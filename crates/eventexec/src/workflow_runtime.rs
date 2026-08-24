//! Assembly-owned workflow runtime closure.
//!
//! The repository-wide generated catalogs describe definitions only. This module is the sole
//! production join from a sealed [`assembly_schema::RuntimePlan`] to runtime-visible Projection and
//! Saga views. Fields stay private so callers cannot manufacture activation independently.
//!
//! INVARIANT: PROJECTION-ACTIVE-SERVING-BIND-01 { level = "Hard", exec = "native-compile", source = "code", native = "active selection can enter WorkflowRuntimePlan only by consuming the private plan-issued ProjectionActivationPermit together with an exact runtime target and exact-definition ProjectionServingEvidence; the assembly must separately consume the same concrete serving capability into its typed domain composition" }

use std::collections::BTreeMap;
use std::sync::Arc;

use assembly_schema::{ProjectionActivation, RuntimePlan, SagaActivation, WorkflowActivation};
use diport::{
    DynManagedResource, SagaDurableStoreError, SagaOperatorAuthorization, SagaOperatorCasOutcome,
    SagaOperatorStatusOutcome, SagaWorkerIdentity, saga_operator_action,
};
use tokio_util::sync::CancellationToken;
use vocab::{ContractBinding, ProjectionInputBinding, SagaContractBinding};

use crate::{ProjectionMetricActivation, ProjectionMetricScope, ProjectionTarget, WorkerHealth};

/// Saga-internal retention telemetry owner. The fixed target label cannot enter the generic L2
/// [`crate::RetentionTarget`] vocabulary.
pub struct SagaTerminalRetentionMetrics;

impl SagaTerminalRetentionMetrics {
    const TARGET_LABEL: &'static str = "saga_terminal";

    /// Record one Saga terminal retention sweep without widening the L2 target vocabulary.
    pub fn record_sweep(outcome: crate::RetentionOutcome, deleted: u64, duration_seconds: f64) {
        metrics::counter!(
            "retention_sweep_deleted_total",
            "target" => Self::TARGET_LABEL,
        )
        .increment(deleted);
        metrics::counter!(
            "retention_sweep_ticks_total",
            "target" => Self::TARGET_LABEL,
            "outcome" => outcome.as_label(),
        )
        .increment(1);
        metrics::histogram!(
            "retention_sweep_duration_seconds",
            "target" => Self::TARGET_LABEL,
            "outcome" => outcome.as_label(),
        )
        .record(duration_seconds);
    }

    /// Record the Saga terminal expired backlog, preserving unavailable-as-NaN semantics.
    pub fn record_backlog(observation: crate::RetentionBacklogObservation) {
        let (depth, oldest_age_seconds) = match observation {
            crate::RetentionBacklogObservation::Available(backlog) => {
                (backlog.depth() as f64, backlog.oldest_age_seconds() as f64)
            }
            crate::RetentionBacklogObservation::Unavailable => (f64::NAN, f64::NAN),
        };
        metrics::gauge!(
            "retention_expired_backlog_depth",
            "target" => Self::TARGET_LABEL,
        )
        .set(depth);
        metrics::gauge!(
            "retention_expired_oldest_age_seconds",
            "target" => Self::TARGET_LABEL,
        )
        .set(oldest_age_seconds);
    }
}

mod sealed {
    pub trait SagaRuntimeFactory {}
}

type ProjectionSpawn = dyn Fn(
        CancellationToken,
        Arc<WorkerHealth>,
        primitives::WriteAdmission,
    ) -> Box<DynManagedResource<'static>>
    + Send
    + Sync;

/// One immutable, plan-issued Projection runtime.
///
/// Its fields are private and it can only be minted by consuming a
/// [`ProjectionRuntimeBinding`]. The replay target and worker launcher therefore share the same
/// captured target allocation; adapters cannot implement a second `target()` selection path.
pub struct ProjectionRuntime {
    target: Arc<dyn ProjectionTarget>,
    spawn: Arc<ProjectionSpawn>,
    target_generation: crate::ProjectionVersion,
    observation: crate::ProjectionObservationReader,
}

impl ProjectionRuntime {
    fn target(&self) -> Arc<dyn ProjectionTarget> {
        Arc::clone(&self.target)
    }

    fn execution_observation(&self) -> ProjectionExecutionObservation {
        ProjectionExecutionObservation {
            target_generation: self.target_generation.clone(),
            reader: self.observation.clone(),
        }
    }

    pub fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        admission: primitives::WriteAdmission,
    ) -> Box<DynManagedResource<'static>> {
        (self.spawn)(token, health, admission)
    }
}

fn target_matches_identity(
    target: &dyn ProjectionTarget,
    definition: ContractBinding,
    inputs: &[ProjectionInputBinding],
    input_generation: &str,
) -> bool {
    let target_definition = target.definition();
    target_definition.contract() == definition
        && target.bindings() == inputs
        && target_definition.input_generation().as_str() == input_generation
}

/// Identity evidence carried by the concrete serving capability for one exact Projection.
///
/// This is deliberately not named a port: eventexec verifies plan identity but does not erase or
/// own the callable domain API. The active assembly must retain the same concrete `Arc` and consume
/// it into its long-lived typed domain composition.
pub trait ProjectionServingEvidence: Send + Sync {
    fn definition(&self) -> ContractBinding;
}

/// Complete active Saga runtime factory. Stores, typed actions, fencing and worker configuration
/// are captured by the factory before it enters the catalog; assembly wiring can only spawn this
/// exact selected implementation.
trait SagaRuntimeFactory: sealed::SagaRuntimeFactory + Send + Sync {
    fn identity(&self) -> &SagaWorkerIdentity;
    /// Exact generated definition owned by this runtime factory.
    fn definition(&self) -> &consistency::SagaDefinitionIdentity;
    fn start_target(&self) -> SagaRuntimeStartTarget;
    fn operator_target(&self) -> SagaRuntimeOperatorTarget;
    fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        admission: primitives::WriteAdmission,
    ) -> Box<DynManagedResource<'static>>;
}

trait SagaRuntimeStartControl: Send + Sync {
    fn start(
        &self,
        authorization: diport::SagaStartAuthorization,
        request: crate::SagaStartRequest,
    ) -> futures::future::BoxFuture<
        'static,
        Result<consistency::SagaInstanceRecord, crate::SagaStartError>,
    >;
}

impl<T> SagaRuntimeStartControl for T
where
    T: crate::SagaStartPort + Send + Sync + 'static,
{
    fn start(
        &self,
        authorization: diport::SagaStartAuthorization,
        request: crate::SagaStartRequest,
    ) -> futures::future::BoxFuture<
        'static,
        Result<consistency::SagaInstanceRecord, crate::SagaStartError>,
    > {
        crate::SagaStartPort::start(self, authorization, request)
    }
}

trait SagaRuntimeOperatorControl: Send + Sync {
    fn status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorStatusOutcome, SagaDurableStoreError>>;
    fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorCasOutcome, SagaDurableStoreError>>;
    fn repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
    ) -> futures::future::BoxFuture<'static, crate::SagaOperatorRecoveryOutcome>;
}

impl<S> SagaRuntimeOperatorControl for crate::SagaOperatorService<S>
where
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
{
    fn status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorStatusOutcome, SagaDurableStoreError>>
    {
        crate::SagaOperatorService::status(self, authorization)
    }

    fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorCasOutcome, SagaDurableStoreError>>
    {
        crate::SagaOperatorService::retry_compensation(self, authorization)
    }

    fn repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
    ) -> futures::future::BoxFuture<'static, crate::SagaOperatorRecoveryOutcome> {
        crate::SagaOperatorService::repair(self, authorization)
    }
}

#[derive(Clone)]
struct ProjectionCapabilityBundle {
    definition: ContractBinding,
    runtime: Option<Arc<ProjectionRuntime>>,
    serving_evidence: Option<Arc<dyn ProjectionServingEvidence>>,
}

impl ProjectionCapabilityBundle {
    #[cfg(test)]
    fn capture_only(definition: ContractBinding) -> Self {
        Self {
            definition,
            runtime: None,
            serving_evidence: None,
        }
    }

    #[cfg(test)]
    fn shadow(definition: ContractBinding, runtime: Arc<ProjectionRuntime>) -> Self {
        Self {
            definition,
            runtime: Some(runtime),
            serving_evidence: None,
        }
    }

    #[cfg(test)]
    fn active(
        definition: ContractBinding,
        runtime: Arc<ProjectionRuntime>,
        serving_evidence: Arc<dyn ProjectionServingEvidence>,
    ) -> Self {
        Self {
            definition,
            runtime: Some(runtime),
            serving_evidence: Some(serving_evidence),
        }
    }
}

#[derive(Clone)]
struct SagaCapabilityBundle {
    definition: SagaContractBinding,
    runtime: Arc<dyn SagaRuntimeFactory>,
}

#[derive(Clone, Default)]
struct SelectedWorkflowCapabilities {
    projection: BTreeMap<String, ProjectionCapabilityBundle>,
    saga: BTreeMap<String, SagaCapabilityBundle>,
}

impl SelectedWorkflowCapabilities {
    /// Empty production capability catalog. It is the exact catalog for today's all-disabled
    /// assemblies; changing an assembly to active before real typed bindings land fails closed.
    #[cfg(test)]
    fn empty() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn insert_projection(
        &mut self,
        bundle: ProjectionCapabilityBundle,
    ) -> Result<(), WorkflowRuntimeError> {
        let id = bundle.definition.contract_id().to_owned();
        match self.projection.entry(id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(bundle);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { workflow: id })
            }
        }
    }
}

/// Move-only proof for one exact selected Projection runtime.
///
/// INVARIANT: PROJECTION-ACTIVATION-PERMIT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, no Clone, plan-only mint and consuming bind" }
pub struct ProjectionActivationPermit {
    definition: ContractBinding,
    inputs: Vec<ProjectionInputBinding>,
    input_generation: &'static str,
    target_generation: crate::ProjectionVersion,
    activation: ProjectionActivation,
    source_runtime_plan_fingerprint: String,
}

/// Exact definition and fixed system identity handed to the adapter by the consuming bind.
/// Move-only construction prevents one permit from issuing multiple runtime objects.
///
/// The sealed [`ProjectionMetricScope`] is minted only by
/// [`ProjectionRuntimeCapability::bind_active`] / [`ProjectionRuntimeCapability::bind_shadow`]
/// after the activation permit is verified. Adapters hold it via [`Self::metric_scope`].
pub struct ProjectionRuntimeBinding {
    definition: ContractBinding,
    inputs: Vec<ProjectionInputBinding>,
    input_generation: &'static str,
    target_generation: crate::ProjectionVersion,
    metric_scope: ProjectionMetricScope,
}

impl ProjectionRuntimeBinding {
    pub const fn definition(&self) -> ContractBinding {
        self.definition
    }

    pub fn inputs(&self) -> &[ProjectionInputBinding] {
        &self.inputs
    }

    pub const fn input_generation(&self) -> &'static str {
        self.input_generation
    }

    pub fn target_generation(&self) -> &crate::ProjectionVersion {
        &self.target_generation
    }

    /// Return the sealed metric scope minted at Active/Shadow bind time.
    #[must_use]
    pub const fn metric_scope(&self) -> ProjectionMetricScope {
        self.metric_scope
    }

    pub fn background_execution_issuer(&self) -> ProjectionBackgroundExecutionIssuer {
        ProjectionBackgroundExecutionIssuer { _private: () }
    }

    /// Consume this plan binding into the sole runtime object used by replay and lifecycle.
    ///
    /// The launcher receives the target captured here; there is no adapter-owned target accessor
    /// that can make a second, drifting selection later.
    pub fn issue_runtime<S>(
        self,
        target: Arc<dyn ProjectionTarget>,
        spawn: S,
    ) -> Result<ProjectionRuntime, WorkflowRuntimeError>
    where
        S: Fn(
                Arc<dyn ProjectionTarget>,
                CancellationToken,
                Arc<WorkerHealth>,
                primitives::WriteAdmission,
                crate::ProjectionObservationPublisher,
            ) -> Box<DynManagedResource<'static>>
            + Send
            + Sync
            + 'static,
    {
        if !target_matches_identity(
            target.as_ref(),
            self.definition,
            &self.inputs,
            self.input_generation,
        ) {
            return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
                workflow: self.definition.contract_id().to_owned(),
            });
        }
        let worker_target = Arc::clone(&target);
        let target_generation = self.target_generation;
        let (publisher, observation) =
            crate::projection_observation::projection_observation_channel();
        Ok(ProjectionRuntime {
            target,
            spawn: Arc::new(move |token, health, admission| {
                spawn(
                    Arc::clone(&worker_target),
                    token,
                    health,
                    admission,
                    publisher.clone(),
                )
            }),
            target_generation,
            observation,
        })
    }
}

/// Exact target identity handed to an offline maintenance adapter by a consumed active-plan
/// permit. It cannot spawn a worker or mint serving evidence.
pub struct ProjectionMaintenanceBinding {
    definition: ContractBinding,
    inputs: Vec<ProjectionInputBinding>,
    input_generation: &'static str,
}

impl ProjectionMaintenanceBinding {
    pub const fn definition(&self) -> ContractBinding {
        self.definition
    }

    pub fn inputs(&self) -> &[ProjectionInputBinding] {
        &self.inputs
    }

    pub const fn input_generation(&self) -> &'static str {
        self.input_generation
    }
}

/// Move-only proof that one exact active assembly target was bound for offline maintenance.
///
/// Unlike [`ProjectionRuntimeCapability`], this capability has no worker factory and no serving
/// evidence. It exists solely so an operator can replay/status/swap the target selected by the
/// same sealed assembly manifest without activating a second serving topology.
pub struct ProjectionMaintenanceCapability {
    pub(crate) definition: ContractBinding,
    pub(crate) inputs: Vec<ProjectionInputBinding>,
    pub(crate) input_generation: &'static str,
    pub(crate) target: Arc<dyn ProjectionTarget>,
    pub(crate) source_runtime_plan_fingerprint: String,
}

impl ProjectionMaintenanceCapability {
    pub fn bind<B>(
        permit: ProjectionActivationPermit,
        build: B,
    ) -> Result<Self, WorkflowRuntimeError>
    where
        B: FnOnce(
            ProjectionMaintenanceBinding,
        ) -> Result<Arc<dyn ProjectionTarget>, WorkflowRuntimeError>,
    {
        if permit.activation != ProjectionActivation::Active {
            return Err(WorkflowRuntimeError::CapabilityBindingRejected {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        let binding = ProjectionMaintenanceBinding {
            definition: permit.definition,
            inputs: permit.inputs.clone(),
            input_generation: permit.input_generation,
        };
        let target = build(binding)?;
        if !target_matches_identity(
            target.as_ref(),
            permit.definition,
            &permit.inputs,
            permit.input_generation,
        ) {
            return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        Ok(Self {
            definition: permit.definition,
            inputs: permit.inputs,
            input_generation: permit.input_generation,
            target,
            source_runtime_plan_fingerprint: permit.source_runtime_plan_fingerprint,
        })
    }
}

/// Cloneable fixed-identity issuer captured by the worker spawned from a plan binding.
/// Private construction keeps background execution authority downstream of the consumed binding.
#[derive(Clone)]
pub struct ProjectionBackgroundExecutionIssuer {
    _private: (),
}

impl ProjectionBackgroundExecutionIssuer {
    pub fn issue(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> crate::ProjectionExecutionContext {
        crate::ProjectionExecutionContext::background_worker(tenant)
    }
}

/// Complete Projection runtime paired with one consumed plan permit.
pub struct ProjectionRuntimeCapability {
    bundle: ProjectionCapabilityBundle,
    source_runtime_plan_fingerprint: String,
}

impl ProjectionRuntimeCapability {
    pub fn bind_shadow<B>(
        permit: ProjectionActivationPermit,
        build: B,
    ) -> Result<Self, WorkflowRuntimeError>
    where
        B: FnOnce(ProjectionRuntimeBinding) -> Result<ProjectionRuntime, WorkflowRuntimeError>,
    {
        if permit.activation != ProjectionActivation::Shadow {
            return Err(WorkflowRuntimeError::CapabilityBindingRejected {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        let binding = ProjectionRuntimeBinding {
            definition: permit.definition,
            inputs: permit.inputs.clone(),
            input_generation: permit.input_generation,
            target_generation: permit.target_generation,
            metric_scope: ProjectionMetricScope::mint(
                permit.definition.contract_id(),
                ProjectionMetricActivation::Shadow,
            ),
        };
        let runtime = Arc::new(build(binding)?);
        let target = runtime.target();
        if !target_matches_identity(
            target.as_ref(),
            permit.definition,
            &permit.inputs,
            permit.input_generation,
        ) {
            return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        Ok(Self {
            bundle: ProjectionCapabilityBundle {
                definition: permit.definition,
                runtime: Some(runtime),
                serving_evidence: None,
            },
            source_runtime_plan_fingerprint: permit.source_runtime_plan_fingerprint,
        })
    }

    pub fn bind_active<B>(
        permit: ProjectionActivationPermit,
        build: B,
        serving_evidence: Arc<dyn ProjectionServingEvidence>,
    ) -> Result<Self, WorkflowRuntimeError>
    where
        B: FnOnce(ProjectionRuntimeBinding) -> Result<ProjectionRuntime, WorkflowRuntimeError>,
    {
        if permit.activation != ProjectionActivation::Active
            || serving_evidence.definition() != permit.definition
        {
            return Err(WorkflowRuntimeError::CapabilityBindingRejected {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        let binding = ProjectionRuntimeBinding {
            definition: permit.definition,
            inputs: permit.inputs.clone(),
            input_generation: permit.input_generation,
            target_generation: permit.target_generation,
            metric_scope: ProjectionMetricScope::mint(
                permit.definition.contract_id(),
                ProjectionMetricActivation::Active,
            ),
        };
        let runtime = Arc::new(build(binding)?);
        let target = runtime.target();
        if !target_matches_identity(
            target.as_ref(),
            permit.definition,
            &permit.inputs,
            permit.input_generation,
        ) {
            return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        Ok(Self {
            bundle: ProjectionCapabilityBundle {
                definition: permit.definition,
                runtime: Some(runtime),
                serving_evidence: Some(serving_evidence),
            },
            source_runtime_plan_fingerprint: permit.source_runtime_plan_fingerprint,
        })
    }
}

/// Move-only proof that one exact Saga is active in the sealed assembly plan.
///
/// INVARIANT: SAGA-ACTIVATION-PERMIT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields, no Clone, plan-only mint and consuming runtime bind" }
pub struct SagaActivationPermit {
    definition: SagaContractBinding,
    source_runtime_plan_fingerprint: String,
}

/// Complete runtime capability paired with one consumed activation permit.
pub struct SagaRuntimeCapability {
    bundle: SagaCapabilityBundle,
    source_runtime_plan_fingerprint: String,
}

impl SagaRuntimeCapability {
    /// Consume one plan-issued permit and bind the complete worker dependency set.
    // Keep every capability explicit at this destructive assembly boundary: grouping the
    // operator service with worker dependencies would make omission possible again.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_worker<T, S, E>(
        permit: SagaActivationPermit,
        identity: SagaWorkerIdentity,
        tenant_source: Arc<T>,
        durable_store: Arc<S>,
        executor: Arc<E>,
        clock: Arc<dyn diport::Clock>,
        config: crate::SagaWorkerConfig,
        operator_service: crate::SagaOperatorService<S>,
    ) -> Result<Self, WorkflowRuntimeError>
    where
        T: diport::SagaTenantSource + Send + Sync + 'static,
        S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
        E: crate::SagaExecutor + crate::SagaStartPort + Send + Sync + 'static,
    {
        if operator_service.identity() != &identity {
            return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
                workflow: permit.definition.contract_id().to_owned(),
            });
        }
        let definition = consistency::SagaDefinitionIdentity::from_binding(permit.definition);
        let runtime: Arc<dyn SagaRuntimeFactory> = Arc::new(BoundSagaRuntimeFactory {
            identity,
            definition,
            tenant_source,
            durable_store,
            executor,
            clock,
            config,
            operator_service,
        });
        let bundle = SagaCapabilityBundle {
            definition: permit.definition,
            runtime,
        };
        validate_saga_bundle(permit.definition.contract_id(), permit.definition, &bundle)?;
        Ok(Self {
            bundle,
            source_runtime_plan_fingerprint: permit.source_runtime_plan_fingerprint,
        })
    }
}

struct BoundSagaRuntimeFactory<T, S, E> {
    identity: SagaWorkerIdentity,
    definition: consistency::SagaDefinitionIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    executor: Arc<E>,
    clock: Arc<dyn diport::Clock>,
    config: crate::SagaWorkerConfig,
    operator_service: crate::SagaOperatorService<S>,
}

impl<T, S, E> sealed::SagaRuntimeFactory for BoundSagaRuntimeFactory<T, S, E> {}

impl<T, S, E> SagaRuntimeFactory for BoundSagaRuntimeFactory<T, S, E>
where
    T: diport::SagaTenantSource + Send + Sync + 'static,
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
    E: crate::SagaExecutor + crate::SagaStartPort + Send + Sync + 'static,
{
    fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    fn definition(&self) -> &consistency::SagaDefinitionIdentity {
        &self.definition
    }

    fn operator_target(&self) -> SagaRuntimeOperatorTarget {
        SagaRuntimeOperatorTarget {
            identity: self.identity.clone(),
            control: Arc::new(self.operator_service.clone()),
        }
    }

    fn start_target(&self) -> SagaRuntimeStartTarget {
        SagaRuntimeStartTarget {
            identity: self.identity.clone(),
            control: Arc::clone(&self.executor) as Arc<dyn SagaRuntimeStartControl>,
        }
    }

    fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        admission: primitives::WriteAdmission,
    ) -> Box<DynManagedResource<'static>> {
        DynManagedResource::new_box(
            crate::SagaWorkerRuntime::new(
                self.identity.clone(),
                Arc::clone(&self.tenant_source),
                Arc::clone(&self.durable_store),
                Arc::clone(&self.executor),
                Arc::clone(&self.clock),
                self.config,
                admission,
            )
            .spawn(token, health),
        )
    }
}

/// Unbound assembly selection. Active Saga permits are taken from the selection map and must return
/// as a complete [`SagaRuntimeCapability`] before the plan can be bound.
#[derive(Clone, Copy)]
enum SagaDefinitionCatalog {
    Production,
    #[cfg(feature = "internal-test-support")]
    Conformance,
}

impl SagaDefinitionCatalog {
    fn specs(self) -> &'static [generated::saga::SagaSpec] {
        match self {
            Self::Production => generated::saga::SPECS,
            #[cfg(feature = "internal-test-support")]
            Self::Conformance => generated::saga::test_support::SPECS,
        }
    }
}

pub struct WorkflowActivationPlan {
    activations: Vec<WorkflowActivation>,
    capabilities: SelectedWorkflowCapabilities,
    projection_preview: WorkflowRuntimePlan,
    source_runtime_plan_fingerprint: String,
    projection_permits: BTreeMap<String, ProjectionActivationPermit>,
    saga_permits: BTreeMap<String, SagaActivationPermit>,
    saga_catalog: SagaDefinitionCatalog,
}

impl WorkflowActivationPlan {
    pub fn select(runtime: &RuntimePlan) -> Result<Self, WorkflowRuntimeError> {
        let activations = runtime
            .workflow_plans()
            .iter()
            .map(|plan| plan.activation().clone())
            .collect();
        Self::select_from_catalog(runtime, activations, SagaDefinitionCatalog::Production)
    }

    /// Select the one closed, generated Saga conformance catalog for integration tests.
    #[cfg(feature = "internal-test-support")]
    pub fn select_saga_conformance_for_test(
        runtime: &RuntimePlan,
    ) -> Result<Self, WorkflowRuntimeError> {
        let mut activations = runtime
            .workflow_plans()
            .iter()
            .map(|plan| plan.activation().clone())
            .collect::<Vec<_>>();
        let definition = generated::saga::test_support::test_v1::primary::SPEC.contract();
        let definition_schema_digest =
            vocab::CanonicalSha256Digest::parse(definition.schema_hash()).map_err(|_| {
                WorkflowRuntimeError::DefinitionMismatch {
                    workflow: definition.contract_id().to_owned(),
                    field: "schema-digest",
                }
            })?;
        activations.push(WorkflowActivation::Saga {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest,
            activation: SagaActivation::Active,
        });
        Self::select_from_catalog(runtime, activations, SagaDefinitionCatalog::Conformance)
    }

    fn select_from_catalog(
        runtime: &RuntimePlan,
        activations: Vec<WorkflowActivation>,
        saga_catalog: SagaDefinitionCatalog,
    ) -> Result<Self, WorkflowRuntimeError> {
        let fingerprint = runtime.runtime_plan_fingerprint().as_str().to_owned();
        let generated_sagas = unique_saga_definitions(saga_catalog.specs())?;
        let generated_projections =
            unique_projection_definitions(generated::event::PROJECTION_DEFINITIONS)?;
        validate_projection_inputs(generated::event::PROJECTION_INPUTS, &generated_projections)?;
        let mut projection_permits = BTreeMap::new();
        let mut saga_permits = BTreeMap::new();
        for activation in &activations {
            if let WorkflowActivation::Projection {
                id,
                definition_version,
                definition_schema_digest,
                target_generation,
                activation: mode @ (ProjectionActivation::Shadow | ProjectionActivation::Active),
            } = activation
            {
                let definition = generated_projections.get(id.as_str()).ok_or_else(|| {
                    WorkflowRuntimeError::MissingDefinition {
                        workflow: id.clone(),
                    }
                })?;
                validate_identity(
                    id,
                    definition_version,
                    definition_schema_digest.as_str(),
                    *definition,
                )?;
                let inputs = generated::event::PROJECTION_INPUTS
                    .iter()
                    .filter(|input| input.projection_id() == id)
                    .copied()
                    .collect::<Vec<_>>();
                if inputs.is_empty() {
                    return Err(WorkflowRuntimeError::MissingProjectionInputs {
                        workflow: id.clone(),
                    });
                }
                let permit = ProjectionActivationPermit {
                    definition: *definition,
                    inputs,
                    input_generation: generated::event::PROJECTION_INPUT_GENERATION,
                    target_generation: crate::ProjectionVersion::parse(target_generation).map_err(
                        |_| WorkflowRuntimeError::ProjectionTargetGenerationInvalid {
                            workflow: id.clone(),
                        },
                    )?,
                    activation: *mode,
                    source_runtime_plan_fingerprint: fingerprint.clone(),
                };
                if projection_permits.insert(id.clone(), permit).is_some() {
                    return Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow {
                        workflow: id.clone(),
                    });
                }
            }
            let WorkflowActivation::Saga {
                id,
                definition_version,
                definition_schema_digest,
                activation: SagaActivation::Active,
            } = activation
            else {
                continue;
            };
            let spec = generated_sagas.get(id.as_str()).ok_or_else(|| {
                WorkflowRuntimeError::MissingDefinition {
                    workflow: id.clone(),
                }
            })?;
            validate_identity(
                id,
                definition_version,
                definition_schema_digest.as_str(),
                spec.contract(),
            )?;
            let permit = SagaActivationPermit {
                definition: **spec,
                source_runtime_plan_fingerprint: fingerprint.clone(),
            };
            if saga_permits.insert(id.clone(), permit).is_some() {
                return Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow {
                    workflow: id.clone(),
                });
            }
        }
        let capabilities = SelectedWorkflowCapabilities::default();
        let projection_activations = activations
            .iter()
            .map(|activation| match activation {
                WorkflowActivation::Saga {
                    id,
                    definition_version,
                    definition_schema_digest,
                    ..
                } => WorkflowActivation::Saga {
                    id: id.clone(),
                    definition_version: definition_version.clone(),
                    definition_schema_digest: definition_schema_digest.clone(),
                    activation: SagaActivation::Disabled,
                },
                WorkflowActivation::Projection {
                    id,
                    definition_version,
                    definition_schema_digest,
                    target_generation,
                    activation,
                } => WorkflowActivation::Projection {
                    id: id.clone(),
                    definition_version: definition_version.clone(),
                    definition_schema_digest: definition_schema_digest.clone(),
                    target_generation: target_generation.clone(),
                    activation: match activation {
                        ProjectionActivation::Disabled => ProjectionActivation::Disabled,
                        _ => ProjectionActivation::CaptureOnly,
                    },
                },
            })
            .collect::<Vec<_>>();
        let projection_refs = projection_activations.iter().collect::<Vec<_>>();
        let projection_preview = compile_activations(
            &projection_refs,
            capabilities.clone(),
            &fingerprint,
            generated::event::PROJECTION_DEFINITIONS,
            generated::event::PROJECTION_INPUTS,
            saga_catalog.specs(),
        )?;
        Ok(Self {
            activations,
            capabilities,
            projection_preview,
            source_runtime_plan_fingerprint: fingerprint,
            projection_permits,
            saga_permits,
            saga_catalog,
        })
    }

    /// Borrow the projection capture closure before active Saga permits are bound.
    pub fn projection_capture(&self) -> ProjectionCaptureView<'_> {
        self.projection_preview.projection_capture()
    }

    pub fn take_saga_permit(
        &mut self,
        contract_id: &str,
    ) -> Result<SagaActivationPermit, WorkflowRuntimeError> {
        self.saga_permits.remove(contract_id).ok_or_else(|| {
            WorkflowRuntimeError::MissingCapability {
                workflow: contract_id.to_owned(),
                capability: "active-saga-permit",
            }
        })
    }

    pub fn take_projection_permit(
        &mut self,
        contract_id: &str,
    ) -> Result<ProjectionActivationPermit, WorkflowRuntimeError> {
        self.projection_permits.remove(contract_id).ok_or_else(|| {
            WorkflowRuntimeError::MissingCapability {
                workflow: contract_id.to_owned(),
                capability: "projection-activation-permit",
            }
        })
    }

    pub fn bind(
        mut self,
        projections: impl IntoIterator<Item = ProjectionRuntimeCapability>,
        sagas: impl IntoIterator<Item = SagaRuntimeCapability>,
    ) -> Result<WorkflowRuntimePlan, WorkflowRuntimeError> {
        for capability in projections {
            if capability.source_runtime_plan_fingerprint != self.source_runtime_plan_fingerprint {
                return Err(WorkflowRuntimeError::CapabilityBindingRejected {
                    workflow: capability.bundle.definition.contract_id().to_owned(),
                });
            }
            let id = capability.bundle.definition.contract_id().to_owned();
            if self
                .capabilities
                .projection
                .insert(id.clone(), capability.bundle)
                .is_some()
            {
                return Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { workflow: id });
            }
        }
        for capability in sagas {
            if capability.source_runtime_plan_fingerprint != self.source_runtime_plan_fingerprint {
                return Err(WorkflowRuntimeError::CapabilityBindingRejected {
                    workflow: capability.bundle.definition.contract_id().to_owned(),
                });
            }
            let id = capability.bundle.definition.contract_id().to_owned();
            if self
                .capabilities
                .saga
                .insert(id.clone(), capability.bundle)
                .is_some()
            {
                return Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { workflow: id });
            }
        }
        if let Some((workflow, _)) = self.projection_permits.first_key_value() {
            return Err(WorkflowRuntimeError::MissingCapability {
                workflow: workflow.clone(),
                capability: "bound-projection-runtime",
            });
        }
        if let Some((workflow, _)) = self.saga_permits.first_key_value() {
            return Err(WorkflowRuntimeError::MissingCapability {
                workflow: workflow.clone(),
                capability: "bound-saga-runtime",
            });
        }
        let activation_refs = self.activations.iter().collect::<Vec<_>>();
        compile_activations(
            &activation_refs,
            self.capabilities,
            &self.source_runtime_plan_fingerprint,
            generated::event::PROJECTION_DEFINITIONS,
            generated::event::PROJECTION_INPUTS,
            self.saga_catalog.specs(),
        )
    }
}

pub struct WorkflowRuntimePlan {
    source_runtime_plan_fingerprint: String,
    projection_inputs: Vec<ProjectionInputBinding>,
    _projection_captures: Vec<SelectedProjectionCapture>,
    projection_targets: Vec<SelectedProjectionTarget>,
    sagas: Vec<ActivatedSaga>,
    activated: Vec<ActivatedWorkflow>,
}

impl WorkflowRuntimePlan {
    /// Empty sealed plan for integration fixtures that exercise assemblies with no activated
    /// workflows. Production callers must compile from the assembly RuntimePlan.
    #[cfg(any(test, feature = "internal-test-support"))]
    pub fn disabled_fixture() -> Self {
        Self {
            source_runtime_plan_fingerprint: String::new(),
            projection_inputs: Vec::new(),
            _projection_captures: Vec::new(),
            projection_targets: Vec::new(),
            sagas: Vec::new(),
            activated: Vec::new(),
        }
    }

    pub fn projection_capture(&self) -> ProjectionCaptureView<'_> {
        ProjectionCaptureView {
            generation: generated::event::PROJECTION_INPUT_GENERATION,
            bindings: &self.projection_inputs,
            captures: &self._projection_captures,
        }
    }

    pub fn projection_targets(&self) -> ProjectionTargetView<'_> {
        ProjectionTargetView {
            generation: generated::event::PROJECTION_INPUT_GENERATION,
            targets: &self.projection_targets,
        }
    }

    /// Mint an exact generated scope through the production registry path for downstream adapter
    /// integration tests. The fixture accepts no definition fields or generation override.
    #[cfg(feature = "internal-test-support")]
    #[doc(hidden)]
    pub fn generated_projection_capture_fixture() -> Self {
        let projection_inputs = generated::event::PROJECTION_INPUTS.to_vec();
        let projection_captures = generated::event::PROJECTION_DEFINITIONS
            .iter()
            .map(|definition| SelectedProjectionCapture {
                definition: ProjectionCaptureDefinition {
                    id: definition.contract_id().to_owned(),
                    definition_version: definition.version().to_owned(),
                    definition_schema_digest: definition.schema_hash().to_owned(),
                },
                inputs: projection_inputs
                    .iter()
                    .filter(|input| input.projection_id() == definition.contract_id())
                    .copied()
                    .collect(),
            })
            .collect::<Vec<_>>();
        let activated = projection_captures
            .iter()
            .map(|capture| ActivatedWorkflow {
                id: capture.definition.id.clone(),
                definition_version: capture.definition.definition_version.clone(),
                definition_schema_digest: capture.definition.definition_schema_digest.clone(),
                shape: ActivatedWorkflowShape::ProjectionCapture,
            })
            .collect();
        Self {
            source_runtime_plan_fingerprint: String::new(),
            projection_inputs,
            _projection_captures: projection_captures,
            projection_targets: Vec::new(),
            sagas: Vec::new(),
            activated,
        }
    }

    #[cfg(feature = "internal-test-support")]
    #[doc(hidden)]
    pub fn generated_projection_source_scope_fixture(
        projection: &crate::ProjectionId,
        tenant: rss_request_context::TenantId,
    ) -> Option<ProjectionSourceScope> {
        let plan = Self::generated_projection_capture_fixture();
        crate::ProjectionTargetRegistry::capture_source_scope_fixture(
            plan.projection_capture(),
            projection,
            tenant,
        )
        .ok()
    }

    /// Mint the fixed replay execution identity for an exact generated projection in adapter
    /// integration tests. The fixture accepts neither actor nor purpose and is absent from
    /// production builds.
    #[cfg(feature = "internal-test-support")]
    #[doc(hidden)]
    pub fn generated_projection_operator_execution_fixture(
        projection: &crate::ProjectionId,
        tenant: rss_request_context::TenantId,
    ) -> Option<crate::ProjectionExecutionContext> {
        generated::event::PROJECTION_DEFINITIONS
            .iter()
            .any(|definition| definition.contract_id() == projection.as_str())
            .then(|| crate::ProjectionExecutionContext::operator_replay(tenant))
    }

    /// Mint one plan-shaped runtime binding for an exact generated projection and target
    /// generation in adapter integration tests. Accepts no definition override and is absent
    /// from production builds.
    #[cfg(feature = "internal-test-support")]
    #[doc(hidden)]
    pub fn generated_projection_runtime_binding_fixture(
        projection: &crate::ProjectionId,
        target_generation: &crate::ProjectionVersion,
    ) -> Option<ProjectionRuntimeBinding> {
        let definition = *generated::event::PROJECTION_DEFINITIONS
            .iter()
            .find(|definition| definition.contract_id() == projection.as_str())?;
        let inputs = generated::event::PROJECTION_INPUTS
            .iter()
            .copied()
            .filter(|binding| binding.projection_id() == projection.as_str())
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            return None;
        }
        Some(ProjectionRuntimeBinding {
            definition,
            inputs,
            input_generation: generated::event::PROJECTION_INPUT_GENERATION,
            target_generation: target_generation.clone(),
            metric_scope: ProjectionMetricScope::mint(
                definition.contract_id(),
                ProjectionMetricActivation::Active,
            ),
        })
    }

    pub fn sagas(&self) -> SagaRuntimeView<'_> {
        SagaRuntimeView { sagas: &self.sagas }
    }

    pub fn activated_workflows(&self) -> ActivatedWorkflowsView<'_> {
        ActivatedWorkflowsView {
            source_runtime_plan_fingerprint: &self.source_runtime_plan_fingerprint,
            workflows: &self.activated,
        }
    }
}

#[derive(Clone, Copy)]
pub struct ProjectionCaptureView<'a> {
    generation: &'static str,
    bindings: &'a [ProjectionInputBinding],
    captures: &'a [SelectedProjectionCapture],
}

impl<'a> ProjectionCaptureView<'a> {
    pub fn is_enabled(self) -> bool {
        !self.bindings.is_empty()
    }

    pub fn generation(self) -> Option<&'static str> {
        self.is_enabled().then_some(self.generation)
    }

    pub fn bindings(self) -> &'a [ProjectionInputBinding] {
        self.bindings
    }

    /// Exact definition identity and source bindings for every capture selected by the sealed
    /// assembly plan, including `CaptureOnly` workflows that intentionally have no runtime target.
    pub fn entries(
        self,
    ) -> impl ExactSizeIterator<
        Item = (
            &'a ProjectionCaptureDefinition,
            &'a [ProjectionInputBinding],
        ),
    > + 'a {
        self.captures
            .iter()
            .map(|capture| (&capture.definition, capture.inputs.as_slice()))
    }
}

#[derive(Clone, Copy)]
pub struct ProjectionTargetView<'a> {
    generation: &'static str,
    targets: &'a [SelectedProjectionTarget],
}

impl<'a> ProjectionTargetView<'a> {
    pub fn entries(self) -> impl ExactSizeIterator<Item = ProjectionTargetEntry<'a>> + 'a {
        self.targets
            .iter()
            .map(move |target| ProjectionTargetEntry {
                generation: self.generation,
                target,
            })
    }
}

#[derive(Clone, Copy)]
pub struct ProjectionTargetEntry<'a> {
    generation: &'static str,
    target: &'a SelectedProjectionTarget,
}

impl ProjectionTargetEntry<'_> {
    pub(crate) fn input_generation(&self) -> &'static str {
        self.generation
    }

    pub fn workflow(&self) -> &ActivatedWorkflow {
        &self.target.workflow
    }
    pub fn definition(&self) -> ContractBinding {
        self.target.definition
    }
    pub fn bindings(&self) -> &[ProjectionInputBinding] {
        &self.target.inputs
    }
    pub fn target(&self) -> Arc<dyn ProjectionTarget> {
        Arc::clone(&self.target.target)
    }
    pub fn runtime_factory(&self) -> &Arc<ProjectionRuntime> {
        &self.target.runtime
    }

    pub fn serving_evidence_definition(&self) -> Option<ContractBinding> {
        self.target
            .serving_evidence
            .as_ref()
            .map(|evidence| evidence.definition())
    }

    /// Mint the fixed replay actor from the sealed selected plan; request principals and source
    /// metadata cannot influence this context.
    pub fn operator_execution_context(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> crate::ProjectionExecutionContext {
        crate::ProjectionExecutionContext::operator_replay(tenant)
    }
}

/// Tenant/projection/definition-bound source authority minted only by
/// [`crate::ProjectionTargetRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSourceScope {
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) projection: crate::ProjectionId,
    pub(crate) definition_version: Box<str>,
    pub(crate) definition_schema_digest: Box<str>,
    pub(crate) input_generation: Box<str>,
}

impl ProjectionSourceScope {
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub fn projection(&self) -> &crate::ProjectionId {
        &self.projection
    }

    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    pub fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }

    pub fn input_generation(&self) -> &str {
        &self.input_generation
    }
}

struct SelectedProjectionCapture {
    definition: ProjectionCaptureDefinition,
    inputs: Vec<ProjectionInputBinding>,
}

struct SelectedProjectionTarget {
    definition: ContractBinding,
    workflow: ActivatedWorkflow,
    inputs: Vec<ProjectionInputBinding>,
    runtime: Arc<ProjectionRuntime>,
    target: Arc<dyn ProjectionTarget>,
    serving_evidence: Option<Arc<dyn ProjectionServingEvidence>>,
}

#[derive(Clone, Copy)]
pub struct SagaRuntimeView<'a> {
    sagas: &'a [ActivatedSaga],
}

impl<'a> SagaRuntimeView<'a> {
    pub fn is_empty(self) -> bool {
        self.sagas.is_empty()
    }

    pub fn specs(self) -> impl ExactSizeIterator<Item = SagaContractBinding> + 'a {
        self.sagas.iter().map(|saga| saga.spec)
    }

    pub fn entries(self) -> impl ExactSizeIterator<Item = SagaRuntimeEntry<'a>> + 'a {
        self.sagas.iter().map(|saga| SagaRuntimeEntry { saga })
    }
}

struct ActivatedSaga {
    spec: SagaContractBinding,
    runtime: Arc<dyn SagaRuntimeFactory>,
}

#[derive(Clone, Copy)]
pub struct SagaRuntimeEntry<'a> {
    saga: &'a ActivatedSaga,
}

/// Opaque spawn handle for one plan-selected Saga runtime.
#[derive(Clone)]
pub struct SagaRuntimeSpawner {
    runtime: Arc<dyn SagaRuntimeFactory>,
}

/// Opaque operator handle for one plan-selected Saga runtime.
///
/// The concrete store and service stay captured behind the private runtime factory/control
/// boundary; callers can only submit an action-specific target-bound authorization.
#[derive(Clone)]
pub struct SagaRuntimeOperatorTarget {
    identity: SagaWorkerIdentity,
    control: Arc<dyn SagaRuntimeOperatorControl>,
}

/// Opaque adopter start handle for one plan-selected Saga runtime.
#[derive(Clone)]
pub struct SagaRuntimeStartTarget {
    identity: SagaWorkerIdentity,
    control: Arc<dyn SagaRuntimeStartControl>,
}

impl SagaRuntimeStartTarget {
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    pub fn start(
        &self,
        authorization: diport::SagaStartAuthorization,
        request: crate::SagaStartRequest,
    ) -> futures::future::BoxFuture<
        'static,
        Result<consistency::SagaInstanceRecord, crate::SagaStartError>,
    > {
        self.control.start(authorization, request)
    }
}

impl SagaRuntimeOperatorTarget {
    pub fn identity(&self) -> &SagaWorkerIdentity {
        &self.identity
    }

    pub fn status(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorStatusOutcome, SagaDurableStoreError>>
    {
        self.control.status(authorization)
    }

    pub fn retry_compensation(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
    ) -> futures::future::BoxFuture<'static, Result<SagaOperatorCasOutcome, SagaDurableStoreError>>
    {
        self.control.retry_compensation(authorization)
    }

    pub fn repair(
        &self,
        authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
    ) -> futures::future::BoxFuture<'static, crate::SagaOperatorRecoveryOutcome> {
        self.control.repair(authorization)
    }
}

impl SagaRuntimeSpawner {
    pub fn identity(&self) -> &SagaWorkerIdentity {
        self.runtime.identity()
    }

    pub fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
        admission: primitives::WriteAdmission,
    ) -> Box<DynManagedResource<'static>> {
        self.runtime.spawn(token, health, admission)
    }
}

impl SagaRuntimeEntry<'_> {
    pub const fn spec(&self) -> SagaContractBinding {
        self.saga.spec
    }
    pub fn spawner(&self) -> SagaRuntimeSpawner {
        SagaRuntimeSpawner {
            runtime: Arc::clone(&self.saga.runtime),
        }
    }
    pub fn operator_target(&self) -> SagaRuntimeOperatorTarget {
        self.saga.runtime.operator_target()
    }
    pub fn start_target(&self) -> SagaRuntimeStartTarget {
        self.saga.runtime.start_target()
    }
}

#[derive(Clone, Copy)]
pub struct ActivatedWorkflowsView<'a> {
    source_runtime_plan_fingerprint: &'a str,
    workflows: &'a [ActivatedWorkflow],
}

impl<'a> ActivatedWorkflowsView<'a> {
    pub fn source_runtime_plan_fingerprint(self) -> &'a str {
        self.source_runtime_plan_fingerprint
    }

    pub fn workflows(self) -> &'a [ActivatedWorkflow] {
        self.workflows
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedWorkflow {
    id: String,
    definition_version: String,
    definition_schema_digest: String,
    shape: ActivatedWorkflowShape,
}

/// Static projection identity used by capture independently of execution capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionCaptureDefinition {
    id: String,
    definition_version: String,
    definition_schema_digest: String,
}

impl ProjectionCaptureDefinition {
    /// Return the generated projection contract identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the generated projection definition version.
    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    /// Return the generated projection definition schema digest.
    pub fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }
}

/// Runtime status capability present only for shadow/active projections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionExecutionObservation {
    target_generation: crate::ProjectionVersion,
    reader: crate::ProjectionObservationReader,
}

impl ProjectionExecutionObservation {
    /// Return the plan-selected target generation paired with this worker observation.
    pub fn target_generation(&self) -> &crate::ProjectionVersion {
        &self.target_generation
    }

    /// Sample the worker's latest bounded process-wide status.
    pub fn status(&self) -> crate::ProjectionWorkerStatus {
        self.reader.read()
    }

    /// Mint a paired observation only for cross-crate integration tests.
    #[cfg(feature = "internal-test-support")]
    #[doc(hidden)]
    pub fn fixture(
        target_generation: crate::ProjectionVersion,
    ) -> (Self, crate::ProjectionObservationPublisher) {
        let (publisher, reader) = crate::projection_observation::projection_observation_channel();
        (
            Self {
                target_generation,
                reader,
            },
            publisher,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatedExecutingProjectionActivation {
    /// Execute without authoritative serving.
    Shadow,
    /// Execute as the authoritative projection.
    Active,
}

/// Closed runtime workflow shape. Executing projections necessarily carry their live reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivatedWorkflowShape {
    /// Capture projection inputs without executing a worker.
    ProjectionCapture,
    /// Execute a projection with the observation capability issued to its worker.
    ProjectionExecuting {
        /// Exact executing posture selected by the sealed runtime plan.
        activation: ActivatedExecutingProjectionActivation,
        /// Live worker observation paired with the executing runtime.
        execution: ProjectionExecutionObservation,
    },
    /// Execute an active saga.
    SagaActive,
}

impl ActivatedWorkflow {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    pub fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }

    pub const fn shape(&self) -> &ActivatedWorkflowShape {
        &self.shape
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkflowRuntimeError {
    #[error("workflow `{workflow}` is missing generated definition")]
    MissingDefinition { workflow: String },
    #[error("workflow `{workflow}` mode differs from generated definition")]
    ModeMismatch { workflow: String },
    #[error("workflow `{workflow}` definition {field} differs from generated definition")]
    DefinitionMismatch {
        workflow: String,
        field: &'static str,
    },
    #[error("workflow `{workflow}` generated definition is duplicated")]
    DuplicateDefinition { workflow: String },
    #[error("workflow `{workflow}` has no generated projection inputs")]
    MissingProjectionInputs { workflow: String },
    #[error("workflow `{workflow}` target generation is invalid")]
    ProjectionTargetGenerationInvalid { workflow: String },
    #[error("generated projection input references unknown workflow `{workflow}`")]
    UnknownProjectionInput { workflow: String },
    #[error("workflow `{workflow}` has a duplicate generated projection input")]
    DuplicateProjectionInput { workflow: String },
    #[error("workflow `{workflow}` is missing runtime capability `{capability}`")]
    MissingCapability {
        workflow: String,
        capability: &'static str,
    },
    #[error("runtime capability catalog contains unknown workflow `{workflow}`")]
    UnknownCapabilityWorkflow { workflow: String },
    #[error("runtime capability catalog contains duplicate workflow `{workflow}`")]
    DuplicateCapabilityWorkflow { workflow: String },
    #[error("workflow `{workflow}` capability identity differs from generated definition")]
    CapabilityIdentityMismatch { workflow: String },
    #[error("workflow `{workflow}` typed capability rejected the selected definition")]
    CapabilityBindingRejected { workflow: String },
}

fn compile_activations(
    activations: &[&WorkflowActivation],
    mut capabilities: SelectedWorkflowCapabilities,
    source_runtime_plan_fingerprint: &str,
    projection_definitions: &[ContractBinding],
    projection_inputs: &[ProjectionInputBinding],
    saga_specs: &[SagaContractBinding],
) -> Result<WorkflowRuntimePlan, WorkflowRuntimeError> {
    let projections = unique_projection_definitions(projection_definitions)?;
    let sagas = unique_saga_definitions(saga_specs)?;
    validate_projection_inputs(projection_inputs, &projections)?;
    validate_capability_catalog(&capabilities, &projections, &sagas)?;

    let mut selected_inputs = Vec::new();
    let mut selected_captures = Vec::new();
    let mut selected_targets = Vec::new();
    let mut selected_sagas = Vec::new();
    let mut activated = Vec::new();

    for activation in activations {
        match activation {
            WorkflowActivation::Projection {
                id,
                definition_version,
                definition_schema_digest,
                target_generation: _,
                activation,
            } => {
                if sagas.contains_key(id.as_str()) {
                    return Err(WorkflowRuntimeError::ModeMismatch {
                        workflow: id.clone(),
                    });
                }
                let definition = projections.get(id.as_str()).ok_or_else(|| {
                    WorkflowRuntimeError::MissingDefinition {
                        workflow: id.clone(),
                    }
                })?;
                validate_identity(
                    id,
                    definition_version,
                    definition_schema_digest.as_str(),
                    *definition,
                )?;
                let inputs = projection_inputs
                    .iter()
                    .filter(|binding| binding.projection_id() == id)
                    .copied()
                    .collect::<Vec<_>>();
                if inputs.is_empty() {
                    return Err(WorkflowRuntimeError::MissingProjectionInputs {
                        workflow: id.clone(),
                    });
                }
                let execution_activation = match activation {
                    ProjectionActivation::Disabled => continue,
                    ProjectionActivation::CaptureOnly => None,
                    ProjectionActivation::Shadow => {
                        Some(ActivatedExecutingProjectionActivation::Shadow)
                    }
                    ProjectionActivation::Active => {
                        Some(ActivatedExecutingProjectionActivation::Active)
                    }
                };
                selected_inputs.extend(inputs.iter().copied());
                let capture_definition = ProjectionCaptureDefinition {
                    id: id.clone(),
                    definition_version: definition_version.clone(),
                    definition_schema_digest: definition_schema_digest.to_string(),
                };
                selected_captures.push(SelectedProjectionCapture {
                    definition: capture_definition.clone(),
                    inputs: inputs.clone(),
                });
                let observation = if let Some(execution_activation) = execution_activation {
                    let bundle = capabilities.projection.remove(id).ok_or_else(|| {
                        WorkflowRuntimeError::MissingCapability {
                            workflow: id.clone(),
                            capability: "typed-projection-bundle",
                        }
                    })?;
                    validate_projection_bundle(id, *activation, *definition, &inputs, &bundle)?;
                    let Some(runtime) = bundle.runtime else {
                        return Err(WorkflowRuntimeError::MissingCapability {
                            workflow: id.clone(),
                            capability: "projection-runtime-factory",
                        });
                    };
                    let observation = ActivatedWorkflow {
                        id: capture_definition.id,
                        definition_version: capture_definition.definition_version,
                        definition_schema_digest: capture_definition.definition_schema_digest,
                        shape: ActivatedWorkflowShape::ProjectionExecuting {
                            activation: execution_activation,
                            execution: runtime.execution_observation(),
                        },
                    };
                    let target = runtime.target();
                    selected_targets.push(SelectedProjectionTarget {
                        definition: bundle.definition,
                        workflow: observation.clone(),
                        inputs,
                        runtime,
                        target,
                        serving_evidence: bundle.serving_evidence,
                    });
                    observation
                } else {
                    ActivatedWorkflow {
                        id: capture_definition.id,
                        definition_version: capture_definition.definition_version,
                        definition_schema_digest: capture_definition.definition_schema_digest,
                        shape: ActivatedWorkflowShape::ProjectionCapture,
                    }
                };
                activated.push(observation);
            }
            WorkflowActivation::Saga {
                id,
                definition_version,
                definition_schema_digest,
                activation,
            } => {
                if projections.contains_key(id.as_str()) {
                    return Err(WorkflowRuntimeError::ModeMismatch {
                        workflow: id.clone(),
                    });
                }
                let spec = sagas.get(id.as_str()).ok_or_else(|| {
                    WorkflowRuntimeError::MissingDefinition {
                        workflow: id.clone(),
                    }
                })?;
                validate_identity(
                    id,
                    definition_version,
                    definition_schema_digest.as_str(),
                    spec.contract(),
                )?;
                if *activation == SagaActivation::Disabled {
                    continue;
                }
                let bundle = capabilities.saga.remove(id).ok_or_else(|| {
                    WorkflowRuntimeError::MissingCapability {
                        workflow: id.clone(),
                        capability: "typed-saga-bundle",
                    }
                })?;
                validate_saga_bundle(id, **spec, &bundle)?;
                selected_sagas.push(ActivatedSaga {
                    spec: **spec,
                    runtime: bundle.runtime,
                });
                activated.push(ActivatedWorkflow {
                    id: id.clone(),
                    definition_version: definition_version.clone(),
                    definition_schema_digest: definition_schema_digest.to_string(),
                    shape: ActivatedWorkflowShape::SagaActive,
                });
            }
        }
    }
    activated.sort_by(|left, right| left.id.cmp(&right.id));
    selected_targets.sort_by(|left, right| left.workflow.id.cmp(&right.workflow.id));
    selected_captures.sort_by(|left, right| left.definition.id.cmp(&right.definition.id));
    selected_inputs.sort_by(|left, right| {
        (
            left.projection_id(),
            left.contract_id(),
            left.version(),
            left.topic(),
        )
            .cmp(&(
                right.projection_id(),
                right.contract_id(),
                right.version(),
                right.topic(),
            ))
    });
    Ok(WorkflowRuntimePlan {
        source_runtime_plan_fingerprint: source_runtime_plan_fingerprint.to_owned(),
        projection_inputs: selected_inputs,
        _projection_captures: selected_captures,
        projection_targets: selected_targets,
        sagas: selected_sagas,
        activated,
    })
}

fn unique_projection_definitions(
    definitions: &[ContractBinding],
) -> Result<BTreeMap<&str, ContractBinding>, WorkflowRuntimeError> {
    let mut by_id = BTreeMap::new();
    for definition in definitions {
        if by_id
            .insert(definition.contract_id(), *definition)
            .is_some()
        {
            return Err(WorkflowRuntimeError::DuplicateDefinition {
                workflow: definition.contract_id().to_owned(),
            });
        }
    }
    Ok(by_id)
}

fn unique_saga_definitions(
    specs: &[SagaContractBinding],
) -> Result<BTreeMap<&str, &SagaContractBinding>, WorkflowRuntimeError> {
    let mut by_id = BTreeMap::new();
    for spec in specs {
        if by_id.insert(spec.contract_id(), spec).is_some() {
            return Err(WorkflowRuntimeError::DuplicateDefinition {
                workflow: spec.contract_id().to_owned(),
            });
        }
    }
    Ok(by_id)
}

fn validate_projection_inputs(
    inputs: &[ProjectionInputBinding],
    projections: &BTreeMap<&str, ContractBinding>,
) -> Result<(), WorkflowRuntimeError> {
    let mut seen = std::collections::BTreeSet::new();
    for input in inputs {
        if !projections.contains_key(input.projection_id()) {
            return Err(WorkflowRuntimeError::UnknownProjectionInput {
                workflow: input.projection_id().to_owned(),
            });
        }
        let key = (
            input.projection_id(),
            input.contract_id(),
            input.version(),
            input.schema_hash(),
            input.topic(),
        );
        if !seen.insert(key) {
            return Err(WorkflowRuntimeError::DuplicateProjectionInput {
                workflow: input.projection_id().to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_capability_catalog(
    catalog: &SelectedWorkflowCapabilities,
    projections: &BTreeMap<&str, ContractBinding>,
    sagas: &BTreeMap<&str, &SagaContractBinding>,
) -> Result<(), WorkflowRuntimeError> {
    for id in catalog.projection.keys() {
        if !projections.contains_key(id.as_str()) {
            return Err(WorkflowRuntimeError::UnknownCapabilityWorkflow {
                workflow: id.clone(),
            });
        }
    }
    for id in catalog.saga.keys() {
        if !sagas.contains_key(id.as_str()) {
            return Err(WorkflowRuntimeError::UnknownCapabilityWorkflow {
                workflow: id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_identity(
    id: &str,
    version: &str,
    digest: &str,
    definition: ContractBinding,
) -> Result<(), WorkflowRuntimeError> {
    if version != definition.version() {
        return Err(WorkflowRuntimeError::DefinitionMismatch {
            workflow: id.to_owned(),
            field: "version",
        });
    }
    if digest != definition.schema_hash() {
        return Err(WorkflowRuntimeError::DefinitionMismatch {
            workflow: id.to_owned(),
            field: "schema-digest",
        });
    }
    Ok(())
}

fn validate_projection_bundle(
    id: &str,
    activation: ProjectionActivation,
    definition: ContractBinding,
    inputs: &[ProjectionInputBinding],
    bundle: &ProjectionCapabilityBundle,
) -> Result<(), WorkflowRuntimeError> {
    if bundle.definition != definition {
        return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
            workflow: id.to_owned(),
        });
    }
    let _ = inputs;
    if matches!(
        activation,
        ProjectionActivation::Shadow | ProjectionActivation::Active
    ) && bundle.runtime.is_none()
    {
        return Err(WorkflowRuntimeError::MissingCapability {
            workflow: id.to_owned(),
            capability: "projection-runtime-factory",
        });
    }
    if activation == ProjectionActivation::Active
        && !bundle
            .serving_evidence
            .as_ref()
            .is_some_and(|evidence| evidence.definition() == definition)
    {
        return Err(WorkflowRuntimeError::MissingCapability {
            workflow: id.to_owned(),
            capability: "serving-evidence",
        });
    }
    Ok(())
}

fn validate_saga_bundle(
    id: &str,
    definition: SagaContractBinding,
    bundle: &SagaCapabilityBundle,
) -> Result<(), WorkflowRuntimeError> {
    let identity = bundle.runtime.identity();
    if bundle.definition != definition
        || identity.owner() != definition.domain()
        || identity.contract_id().as_str() != definition.contract_id()
        || bundle.runtime.definition()
            != &consistency::SagaDefinitionIdentity::from_binding(definition)
    {
        return Err(WorkflowRuntimeError::CapabilityIdentityMismatch {
            workflow: id.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::num::NonZeroUsize;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use futures::future::BoxFuture;

    use super::*;

    fn digest(raw: &str) -> vocab::CanonicalSha256Digest {
        vocab::CanonicalSha256Digest::parse(raw).expect("canonical digest fixture")
    }

    struct NoopProjectionStore;
    impl crate::ProjectionTargetStore for NoopProjectionStore {
        fn apply<'a>(
            &'a self,
            _input: &'a crate::ValidatedProjectionApply,
        ) -> BoxFuture<
            'a,
            Result<crate::ProjectionTargetStoreOutcome, crate::ProjectionTargetStoreError>,
        > {
            Box::pin(async { Ok(crate::ProjectionTargetStoreOutcome::Applied) })
        }
    }

    struct NoopManagedResource;

    impl diport::ManagedResource for NoopManagedResource {
        fn name(&self) -> &str {
            "projection-runtime-test"
        }

        async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
            Ok(())
        }
    }

    fn projection_target_for(definition: ContractBinding) -> Arc<dyn ProjectionTarget> {
        projection_target_for_identity(definition, generated::event::PROJECTION_INPUT_GENERATION)
    }

    fn projection_target_for_identity(
        definition: ContractBinding,
        input_generation: &'static str,
    ) -> Arc<dyn ProjectionTarget> {
        let bindings = generated::event::PROJECTION_INPUTS
            .iter()
            .filter(|input| input.projection_id() == definition.contract_id())
            .cloned()
            .collect();
        Arc::new(
            crate::ConformingProjectionTarget::new(
                crate::ProjectionTargetDefinition::new(definition, input_generation)
                    .expect("generated target definition is canonical"),
                bindings,
                Arc::new(NoopProjectionStore),
            )
            .expect("generated target binding is canonical"),
        )
    }

    fn projection_runtime_for(target: Arc<dyn ProjectionTarget>) -> Arc<ProjectionRuntime> {
        let (_publisher, observation) =
            crate::projection_observation::projection_observation_channel();
        Arc::new(ProjectionRuntime {
            target,
            spawn: Arc::new(|_, _, _| panic!("test runtime must not spawn")),
            target_generation: crate::ProjectionVersion::parse("materialized-v7")
                .expect("test target generation is canonical"),
            observation,
        })
    }

    struct ServingPort(ContractBinding);
    impl ProjectionServingEvidence for ServingPort {
        fn definition(&self) -> ContractBinding {
            self.0
        }
    }

    fn projection_catalog(mode: ProjectionActivation) -> SelectedWorkflowCapabilities {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let runtime = projection_runtime_for(projection_target_for(definition));
        let bundle = match mode {
            ProjectionActivation::Disabled | ProjectionActivation::CaptureOnly => {
                ProjectionCapabilityBundle::capture_only(definition)
            }
            ProjectionActivation::Shadow => ProjectionCapabilityBundle::shadow(definition, runtime),
            ProjectionActivation::Active => ProjectionCapabilityBundle::active(
                definition,
                runtime,
                Arc::new(ServingPort(definition)),
            ),
        };
        let mut catalog = SelectedWorkflowCapabilities::empty();
        catalog
            .insert_projection(bundle)
            .expect("unique test projection");
        catalog
    }

    fn projection_activation(mode: ProjectionActivation) -> WorkflowActivation {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        WorkflowActivation::Projection {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest: digest(definition.schema_hash()),
            target_generation: "materialized-v7".to_owned(),
            activation: mode,
        }
    }

    fn saga_activation(mode: SagaActivation) -> WorkflowActivation {
        let definition = generated::saga::SPECS[0].contract();
        WorkflowActivation::Saga {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest: digest(definition.schema_hash()),
            activation: mode,
        }
    }

    struct RuntimeTenantSource;

    impl diport::SagaTenantSource for RuntimeTenantSource {
        async fn list_runnable_tenants(
            &self,
            _identity: &SagaWorkerIdentity,
            _cursor: Option<diport::SagaTenantCursor>,
            _limit: NonZeroUsize,
        ) -> Result<diport::SagaTenantPage, SagaDurableStoreError> {
            Ok(diport::SagaTenantPage::new(Vec::new(), None))
        }

        async fn observe_unresolved(
            &self,
            _identity: &SagaWorkerIdentity,
        ) -> Result<diport::SagaUnresolvedObservation, SagaDurableStoreError> {
            Ok(diport::SagaUnresolvedObservation::new(0, 0, 0, None))
        }
    }

    struct RuntimeRepairClaim;

    impl diport::SagaOperatorRepairClaim for RuntimeRepairClaim {
        fn instance(&self) -> consistency::SagaInstanceRef {
            panic!("runtime fixture never acquires a repair claim")
        }

        fn expected_reason(&self) -> diport::SagaOperatorRepairReason {
            panic!("runtime fixture never acquires a repair claim")
        }
    }

    #[derive(Default)]
    struct RuntimeStore {
        status_calls: AtomicUsize,
    }

    impl diport::SagaDurableStore for RuntimeStore {
        async fn register(
            &self,
            _authorization: diport::SagaStartAuthorization,
            _registration: diport::SagaInstanceRegistration,
        ) -> Result<consistency::SagaInstanceRecord, SagaDurableStoreError> {
            panic!("runtime fixture does not register")
        }

        async fn get(
            &self,
            _instance: &consistency::SagaInstanceRef,
        ) -> Result<Option<consistency::SagaInstanceRecord>, SagaDurableStoreError> {
            Ok(None)
        }

        async fn list_runnable(
            &self,
            _identity: &SagaWorkerIdentity,
            _tenant: rss_request_context::TenantId,
            _limit: NonZeroUsize,
        ) -> Result<Vec<diport::SagaRunnableInstance>, SagaDurableStoreError> {
            Ok(Vec::new())
        }

        async fn claim(
            &self,
            _request: diport::SagaClaimRequest,
        ) -> Result<diport::SagaClaimOutcome, SagaDurableStoreError> {
            Ok(diport::SagaClaimOutcome::Missing)
        }

        async fn renew(
            &self,
            _lease: &consistency::SagaLease,
            _ttl: diport::SagaLeaseTtl,
        ) -> Result<consistency::SagaLeaseOutcome, SagaDurableStoreError> {
            Ok(consistency::SagaLeaseOutcome::Lost)
        }

        async fn release(
            &self,
            _lease: &consistency::SagaLease,
        ) -> Result<consistency::SagaLeaseOutcome, SagaDurableStoreError> {
            Ok(consistency::SagaLeaseOutcome::Lost)
        }

        async fn recovery_snapshot(
            &self,
            _request: diport::SagaRecoveryRequest,
        ) -> Result<diport::SagaRecoveryOutcome, SagaDurableStoreError> {
            Ok(diport::SagaRecoveryOutcome::LeaseLost)
        }

        async fn terminal_receipt(
            &self,
            _request: diport::SagaTerminalReceiptRequest,
        ) -> Result<diport::SagaTerminalReceiptOutcome, SagaDurableStoreError> {
            Ok(diport::SagaTerminalReceiptOutcome::Missing)
        }

        async fn mutate(
            &self,
            _lease: &consistency::SagaLease,
            _mutation: diport::SagaDurableMutation,
        ) -> Result<diport::SagaDurableMutationOutcome, SagaDurableStoreError> {
            Ok(diport::SagaDurableMutationOutcome::LeaseLost)
        }

        async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
            Ok(())
        }
    }

    impl diport::SagaOperatorStore for RuntimeStore {
        type RepairClaim = RuntimeRepairClaim;

        async fn operator_status(
            &self,
            _authorization: SagaOperatorAuthorization<saga_operator_action::Status>,
        ) -> Result<SagaOperatorStatusOutcome, SagaDurableStoreError> {
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            Ok(SagaOperatorStatusOutcome::Missing)
        }

        async fn retry_compensation(
            &self,
            _authorization: SagaOperatorAuthorization<saga_operator_action::RetryCompensation>,
        ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
            Ok(SagaOperatorCasOutcome::Missing)
        }

        async fn claim_repair(
            &self,
            _authorization: SagaOperatorAuthorization<saga_operator_action::Repair>,
            _holder: diport::SagaLeaseHolder,
            _ttl: diport::SagaLeaseTtl,
        ) -> Result<diport::SagaOperatorClaimOutcome<Self::RepairClaim>, SagaDurableStoreError>
        {
            Ok(diport::SagaOperatorClaimOutcome::Missing)
        }

        async fn repair_snapshot(
            &self,
            _claim: &Self::RepairClaim,
            _scopes: Vec<consistency::SagaReceiptScope>,
        ) -> Result<diport::SagaRecoveryOutcome, SagaDurableStoreError> {
            Ok(diport::SagaRecoveryOutcome::LeaseLost)
        }

        async fn release_repair(
            &self,
            _claim: Self::RepairClaim,
        ) -> Result<consistency::SagaLeaseOutcome, SagaDurableStoreError> {
            Ok(consistency::SagaLeaseOutcome::Lost)
        }

        async fn commit_repair(
            &self,
            _claim: Self::RepairClaim,
            _decision: diport::SagaOperatorRepair,
        ) -> Result<SagaOperatorCasOutcome, SagaDurableStoreError> {
            Ok(SagaOperatorCasOutcome::Missing)
        }
    }

    struct RuntimeExecutor;

    impl crate::SagaExecutor for RuntimeExecutor {
        fn advance_registered(
            &self,
            _instance: consistency::SagaInstanceRef,
            _definition: consistency::SagaDefinitionIdentity,
        ) -> BoxFuture<'static, crate::SagaOutcome> {
            panic!("runtime fixture does not advance instances")
        }
    }

    impl crate::SagaStartPort for RuntimeExecutor {
        fn start(
            &self,
            _authorization: diport::SagaStartAuthorization,
            _request: crate::SagaStartRequest,
        ) -> BoxFuture<'static, Result<consistency::SagaInstanceRecord, crate::SagaStartError>>
        {
            panic!("runtime fixture does not start instances")
        }
    }

    struct RuntimeClock;

    impl diport::Clock for RuntimeClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::UNIX_EPOCH
        }
    }

    fn active_saga_selection(fingerprint: &str) -> WorkflowActivationPlan {
        let activation = saga_activation(SagaActivation::Active);
        let definition = generated::saga::SPECS[0];
        let fingerprint = fingerprint.to_owned();
        let projection_activation = match &activation {
            WorkflowActivation::Saga {
                id,
                definition_version,
                definition_schema_digest,
                ..
            } => WorkflowActivation::Saga {
                id: id.clone(),
                definition_version: definition_version.clone(),
                definition_schema_digest: definition_schema_digest.clone(),
                activation: SagaActivation::Disabled,
            },
            _ => unreachable!("Saga fixture activation"),
        };
        let capabilities = SelectedWorkflowCapabilities::empty();
        let projection_preview = compile_fixture(&[projection_activation], capabilities.clone())
            .expect("disabled Saga projection preview");
        WorkflowActivationPlan {
            activations: vec![activation],
            capabilities,
            projection_preview,
            source_runtime_plan_fingerprint: fingerprint.clone(),
            projection_permits: BTreeMap::new(),
            saga_permits: BTreeMap::from([(
                definition.contract_id().to_owned(),
                SagaActivationPermit {
                    definition,
                    source_runtime_plan_fingerprint: fingerprint,
                },
            )]),
            saga_catalog: SagaDefinitionCatalog::Production,
        }
    }

    fn active_projection_selection(fingerprint: &str) -> WorkflowActivationPlan {
        let activation = projection_activation(ProjectionActivation::Shadow);
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let inputs = generated::event::PROJECTION_INPUTS
            .iter()
            .filter(|input| input.projection_id() == definition.contract_id())
            .copied()
            .collect::<Vec<_>>();
        let preview_activation = WorkflowActivation::Projection {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest: digest(definition.schema_hash()),
            target_generation: "materialized-v7".to_owned(),
            activation: ProjectionActivation::CaptureOnly,
        };
        let capabilities = SelectedWorkflowCapabilities::empty();
        let projection_preview =
            compile_fixture(&[preview_activation], capabilities.clone()).expect("capture preview");
        WorkflowActivationPlan {
            activations: vec![activation],
            capabilities,
            projection_preview,
            source_runtime_plan_fingerprint: fingerprint.to_owned(),
            projection_permits: BTreeMap::from([(
                definition.contract_id().to_owned(),
                ProjectionActivationPermit {
                    definition,
                    inputs,
                    input_generation: generated::event::PROJECTION_INPUT_GENERATION,
                    target_generation: crate::ProjectionVersion::parse("materialized-v7")
                        .expect("test target generation"),
                    activation: ProjectionActivation::Shadow,
                    source_runtime_plan_fingerprint: fingerprint.to_owned(),
                },
            )]),
            saga_permits: BTreeMap::new(),
            saga_catalog: SagaDefinitionCatalog::Production,
        }
    }

    fn active_serving_projection_selection(fingerprint: &str) -> WorkflowActivationPlan {
        let mut selection = active_projection_selection(fingerprint);
        selection.activations = vec![projection_activation(ProjectionActivation::Active)];
        let permit = selection
            .projection_permits
            .values_mut()
            .next()
            .expect("projection permit");
        permit.activation = ProjectionActivation::Active;
        selection
    }

    fn saga_identity() -> SagaWorkerIdentity {
        let definition = generated::saga::SPECS[0];
        SagaWorkerIdentity::new(
            definition.domain(),
            diport::SagaContractId::parse(definition.contract_id())
                .expect("generated Saga contract id"),
        )
        .expect("generated Saga identity")
    }

    fn runtime_operator_service(
        store: Arc<RuntimeStore>,
        identity: SagaWorkerIdentity,
    ) -> crate::SagaOperatorService<RuntimeStore> {
        crate::SagaOperatorService::for_runtime_test(
            store,
            crate::SagaDefinitionRegistry::builder().finish(),
            identity,
            diport::SagaLeaseHolder::parse("runtime-operator-test").expect("holder"),
            diport::SagaLeaseTtl::new(Duration::from_secs(30)).expect("ttl"),
        )
    }

    fn compile_fixture(
        activations: &[WorkflowActivation],
        catalog: SelectedWorkflowCapabilities,
    ) -> Result<WorkflowRuntimePlan, WorkflowRuntimeError> {
        compile_activations(
            &activations.iter().collect::<Vec<_>>(),
            catalog,
            "test-runtime-plan",
            generated::event::PROJECTION_DEFINITIONS,
            generated::event::PROJECTION_INPUTS,
            generated::saga::SPECS,
        )
    }

    #[test]
    fn disabled_and_omitted_definitions_have_zero_runtime_surface()
    -> Result<(), WorkflowRuntimeError> {
        let activation = projection_activation(ProjectionActivation::Disabled);
        let catalog = projection_catalog(ProjectionActivation::Active);
        let plan = compile_fixture(&[activation], catalog)?;
        assert!(!plan.projection_capture().is_enabled());
        assert_eq!(plan.projection_targets().entries().len(), 0);
        assert!(plan.sagas().is_empty());
        assert!(plan.activated_workflows().workflows().is_empty());
        Ok(())
    }

    #[test]
    fn capture_only_selects_exact_projection_inputs_without_target()
    -> Result<(), WorkflowRuntimeError> {
        let activation = projection_activation(ProjectionActivation::CaptureOnly);
        let id = activation.id().to_owned();
        let catalog = projection_catalog(ProjectionActivation::CaptureOnly);
        let plan = compile_fixture(&[activation], catalog)?;
        assert!(plan.projection_capture().is_enabled());
        let captures = plan.projection_capture().entries().collect::<Vec<_>>();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].0.id(), id);
        assert!(
            captures[0]
                .1
                .iter()
                .all(|binding| binding.projection_id() == id)
        );
        assert_eq!(plan.projection_targets().entries().len(), 0);
        assert_eq!(plan.activated_workflows().workflows().len(), 1);
        assert!(matches!(
            plan.activated_workflows().workflows()[0].shape(),
            ActivatedWorkflowShape::ProjectionCapture
        ));
        Ok(())
    }

    #[test]
    fn shadow_and_active_require_complete_typed_projection_bundles() {
        let shadow = projection_activation(ProjectionActivation::Shadow);
        let id = shadow.id().to_owned();
        assert_eq!(
            compile_fixture(
                &[shadow],
                projection_catalog(ProjectionActivation::CaptureOnly)
            )
            .err(),
            Some(WorkflowRuntimeError::MissingCapability {
                workflow: id.clone(),
                capability: "projection-runtime-factory",
            })
        );

        let active = projection_activation(ProjectionActivation::Active);
        assert_eq!(
            compile_fixture(&[active], projection_catalog(ProjectionActivation::Shadow)).err(),
            Some(WorkflowRuntimeError::MissingCapability {
                workflow: id,
                capability: "serving-evidence",
            })
        );
    }

    #[test]
    fn active_saga_requires_bound_runtime_capability_and_disabled_saga_is_empty()
    -> Result<(), WorkflowRuntimeError> {
        let active = saga_activation(SagaActivation::Active);
        let id = active.id().to_owned();
        assert_eq!(
            compile_fixture(
                std::slice::from_ref(&active),
                SelectedWorkflowCapabilities::empty()
            )
            .err(),
            Some(WorkflowRuntimeError::MissingCapability {
                workflow: id,
                capability: "typed-saga-bundle",
            })
        );
        let disabled = saga_activation(SagaActivation::Disabled);
        let plan = compile_fixture(&[disabled], SelectedWorkflowCapabilities::empty())?;
        assert!(plan.sagas().is_empty());
        assert!(plan.activated_workflows().workflows().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn selection_permit_bind_carries_operator_control_into_the_runtime_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_saga_selection("test-runtime-plan");
        let definition = generated::saga::SPECS[0];
        let permit = selection.take_saga_permit(definition.contract_id())?;
        let identity = saga_identity();
        let store = Arc::new(RuntimeStore::default());
        let operator_service = runtime_operator_service(Arc::clone(&store), identity.clone());
        let capability = SagaRuntimeCapability::bind_worker(
            permit,
            identity.clone(),
            Arc::new(RuntimeTenantSource),
            Arc::clone(&store),
            Arc::new(RuntimeExecutor),
            Arc::new(RuntimeClock),
            crate::SagaWorkerConfig::default(),
            operator_service,
        )?;
        let plan = selection.bind(std::iter::empty(), [capability])?;
        let entry = plan.sagas().entries().next().expect("active Saga entry");
        let target = entry.operator_target();
        assert_eq!(target.identity(), &identity);

        let tenant = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000001926")?;
        let instance = consistency::SagaInstanceRef::new(
            tenant,
            consistency::SagaId::new(uuid::Uuid::from_u128(1926)),
        )?;
        let authorization = diport::test_support::saga_operator_authorization(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            identity,
            instance,
            (),
            diport::SagaOperatorStartAuditId::parse("audit-runtime-status")?,
        );
        assert_eq!(
            target.status(authorization).await?,
            SagaOperatorStatusOutcome::Missing
        );
        assert_eq!(store.status_calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[test]
    fn projection_permit_binds_exact_target_and_fixed_execution_identities()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_projection_selection("projection-runtime-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;
        let expected_target = projection_target_for(definition);
        let worker_received_exact_target = Arc::new(AtomicBool::new(false));
        let expected_worker_target = Arc::clone(&expected_target);
        let worker_received_exact_target_for_spawn = Arc::clone(&worker_received_exact_target);
        let capability = ProjectionRuntimeCapability::bind_shadow(permit, |binding| {
            assert_eq!(binding.definition(), definition);
            assert_eq!(
                binding.input_generation(),
                generated::event::PROJECTION_INPUT_GENERATION
            );
            assert!(
                binding
                    .inputs()
                    .iter()
                    .all(|input| input.projection_id() == definition.contract_id())
            );
            assert_eq!(binding.target_generation().as_str(), "materialized-v7");
            binding.issue_runtime(
                Arc::clone(&expected_target),
                move |worker_target, _, _, _, _| {
                    worker_received_exact_target_for_spawn.store(
                        Arc::ptr_eq(&worker_target, &expected_worker_target),
                        Ordering::SeqCst,
                    );
                    DynManagedResource::new_box(NoopManagedResource)
                },
            )
        })?;
        let plan = selection.bind([capability], std::iter::empty())?;
        let entry = plan
            .projection_targets()
            .entries()
            .next()
            .expect("shadow projection target");
        assert!(Arc::ptr_eq(&entry.target(), &expected_target));
        let (admission_control, _, _, write_admission) =
            primitives::prepare_dr_admission_controls().into_parts();
        admission_control
            .start_running()
            .expect("test admission starts running");
        let _resource = entry.runtime_factory().spawn(
            CancellationToken::new(),
            Arc::new(WorkerHealth::starting()),
            write_admission,
        );
        assert!(worker_received_exact_target.load(Ordering::SeqCst));
        let tenant = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000001920")?;
        let replay = entry.operator_execution_context(tenant);
        assert_eq!(replay.identity().actor(), "rss-projection-replay");
        assert_eq!(replay.identity().purpose().as_str(), "operator-replay");
        Ok(())
    }

    #[test]
    fn active_projection_permit_requires_exact_serving_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_serving_projection_selection("projection-active-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;
        let expected_target = projection_target_for(definition);
        let capability = ProjectionRuntimeCapability::bind_active(
            permit,
            |binding| {
                binding.issue_runtime(Arc::clone(&expected_target), |_, _, _, _, _| {
                    DynManagedResource::new_box(NoopManagedResource)
                })
            },
            Arc::new(ServingPort(definition)),
        )?;
        let plan = selection.bind([capability], std::iter::empty())?;
        let entry = plan
            .projection_targets()
            .entries()
            .next()
            .expect("active projection target");
        assert_eq!(entry.serving_evidence_definition(), Some(definition));
        Ok(())
    }

    #[test]
    fn projection_metric_scope_mints_on_active_and_shadow_bind()
    -> Result<(), Box<dyn std::error::Error>> {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let expected_target = projection_target_for(definition);

        let mut shadow_selection = active_projection_selection("projection-metric-shadow-plan");
        let shadow_permit = shadow_selection.take_projection_permit(definition.contract_id())?;
        let mut shadow_scope = None;
        let _shadow = ProjectionRuntimeCapability::bind_shadow(shadow_permit, |binding| {
            shadow_scope = Some(binding.metric_scope());
            assert_eq!(
                binding.metric_scope().projection_id(),
                definition.contract_id()
            );
            assert_eq!(
                binding.metric_scope().activation(),
                crate::ProjectionMetricActivation::Shadow
            );
            assert_eq!(binding.metric_scope().activation().as_label(), "shadow");
            binding.issue_runtime(Arc::clone(&expected_target), |_, _, _, _, _| {
                DynManagedResource::new_box(NoopManagedResource)
            })
        })?;
        assert_eq!(
            shadow_scope
                .expect("shadow bind must mint scope")
                .activation()
                .as_label(),
            "shadow"
        );

        let mut active_selection =
            active_serving_projection_selection("projection-metric-active-plan");
        let active_permit = active_selection.take_projection_permit(definition.contract_id())?;
        let mut active_scope = None;
        let _active = ProjectionRuntimeCapability::bind_active(
            active_permit,
            |binding| {
                active_scope = Some(binding.metric_scope());
                assert_eq!(
                    binding.metric_scope().projection_id(),
                    definition.contract_id()
                );
                assert_eq!(
                    binding.metric_scope().activation(),
                    crate::ProjectionMetricActivation::Active
                );
                assert_eq!(binding.metric_scope().activation().as_label(), "active");
                binding.issue_runtime(Arc::clone(&expected_target), |_, _, _, _, _| {
                    DynManagedResource::new_box(NoopManagedResource)
                })
            },
            Arc::new(ServingPort(definition)),
        )?;
        assert_eq!(
            active_scope
                .expect("active bind must mint scope")
                .activation()
                .as_label(),
            "active"
        );
        Ok(())
    }

    #[test]
    fn active_projection_binding_rejects_non_active_permit_before_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_projection_selection("projection-shadow-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;

        assert!(matches!(
            ProjectionRuntimeCapability::bind_active(
                permit,
                |_| panic!("rejected active binding must not build a runtime"),
                Arc::new(ServingPort(definition)),
            ),
            Err(WorkflowRuntimeError::CapabilityBindingRejected { workflow })
                if workflow == definition.contract_id()
        ));
        Ok(())
    }

    #[test]
    fn active_projection_binding_rejects_serving_definition_drift_before_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_serving_projection_selection("projection-active-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;
        let drifted_definition = ContractBinding::from_static(
            definition.domain(),
            definition.contract_id(),
            "v999",
            definition.schema_hash(),
        );

        assert!(matches!(
            ProjectionRuntimeCapability::bind_active(
                permit,
                |_| panic!("definition drift must be rejected before runtime construction"),
                Arc::new(ServingPort(drifted_definition)),
            ),
            Err(WorkflowRuntimeError::CapabilityBindingRejected { workflow })
                if workflow == definition.contract_id()
        ));
        Ok(())
    }

    #[test]
    fn maintenance_projection_binding_rejects_non_active_permit_before_build()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_projection_selection("projection-shadow-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;

        assert!(matches!(
            ProjectionMaintenanceCapability::bind(permit, |_| {
                panic!("rejected maintenance binding must not build a target")
            }),
            Err(WorkflowRuntimeError::CapabilityBindingRejected { workflow })
                if workflow == definition.contract_id()
        ));
        Ok(())
    }

    #[test]
    fn maintenance_projection_binding_rejects_target_identity_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut selection = active_serving_projection_selection("projection-active-plan");
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let permit = selection.take_projection_permit(definition.contract_id())?;
        let drifted_definition = ContractBinding::from_static(
            definition.domain(),
            definition.contract_id(),
            "v999",
            definition.schema_hash(),
        );

        assert!(matches!(
            ProjectionMaintenanceCapability::bind(permit, |_| {
                Ok(projection_target_for(drifted_definition))
            }),
            Err(WorkflowRuntimeError::CapabilityIdentityMismatch { workflow })
                if workflow == definition.contract_id()
        ));
        Ok(())
    }

    #[cfg(feature = "internal-test-support")]
    #[test]
    fn projection_operator_fixture_accepts_only_generated_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let tenant = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000001920")?;
        let generated =
            crate::ProjectionId::parse(generated::event::PROJECTION_DEFINITIONS[0].contract_id())?;
        let execution = WorkflowRuntimePlan::generated_projection_operator_execution_fixture(
            &generated, tenant,
        )
        .expect("generated projection");
        assert_eq!(execution.identity().actor(), "rss-projection-replay");
        assert_eq!(execution.identity().purpose().as_str(), "operator-replay");
        let unknown = crate::ProjectionId::parse("settings.not-generated")?;
        assert!(
            WorkflowRuntimePlan::generated_projection_operator_execution_fixture(&unknown, tenant)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn capability_from_another_plan_is_rejected_by_its_machine_fingerprint()
    -> Result<(), Box<dyn std::error::Error>> {
        let definition = generated::saga::SPECS[0];
        let mut source = active_saga_selection("source-runtime-plan");
        let permit = source.take_saga_permit(definition.contract_id())?;
        let identity = saga_identity();
        let store = Arc::new(RuntimeStore::default());
        let capability = SagaRuntimeCapability::bind_worker(
            permit,
            identity.clone(),
            Arc::new(RuntimeTenantSource),
            Arc::clone(&store),
            Arc::new(RuntimeExecutor),
            Arc::new(RuntimeClock),
            crate::SagaWorkerConfig::default(),
            runtime_operator_service(store, identity),
        )?;
        let target = active_saga_selection("target-runtime-plan");

        assert!(matches!(
            target.bind(std::iter::empty(), [capability]),
            Err(WorkflowRuntimeError::CapabilityBindingRejected { workflow })
                if workflow == definition.contract_id()
        ));
        Ok(())
    }

    #[test]
    fn definition_identity_and_mode_drift_fail_closed() {
        let mut wrong = projection_activation(ProjectionActivation::Disabled);
        if let WorkflowActivation::Projection {
            definition_version, ..
        } = &mut wrong
        {
            *definition_version = "v999".to_owned();
        }
        assert!(matches!(
            compile_fixture(&[wrong], SelectedWorkflowCapabilities::empty()),
            Err(WorkflowRuntimeError::DefinitionMismatch {
                field: "version",
                ..
            })
        ));

        let saga = generated::saga::SPECS[0].contract();
        let wrong_mode = WorkflowActivation::Projection {
            id: saga.contract_id().to_owned(),
            definition_version: saga.version().to_owned(),
            definition_schema_digest: digest(saga.schema_hash()),
            target_generation: "materialized-v7".to_owned(),
            activation: ProjectionActivation::Disabled,
        };
        assert!(matches!(
            compile_fixture(&[wrong_mode], SelectedWorkflowCapabilities::empty()),
            Err(WorkflowRuntimeError::ModeMismatch { .. })
        ));

        let mut wrong_digest = projection_activation(ProjectionActivation::Disabled);
        if let WorkflowActivation::Projection {
            definition_schema_digest,
            ..
        } = &mut wrong_digest
        {
            *definition_schema_digest =
                digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        }
        assert!(matches!(
            compile_fixture(&[wrong_digest], SelectedWorkflowCapabilities::empty()),
            Err(WorkflowRuntimeError::DefinitionMismatch {
                field: "schema-digest",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_definitions_and_inputs_fail_closed() {
        let activation = projection_activation(ProjectionActivation::Disabled);
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        assert!(matches!(
            compile_activations(
                &[&activation],
                SelectedWorkflowCapabilities::empty(),
                "test-runtime-plan",
                &[definition, definition],
                generated::event::PROJECTION_INPUTS,
                generated::saga::SPECS,
            ),
            Err(WorkflowRuntimeError::DuplicateDefinition { .. })
        ));
        let input = generated::event::PROJECTION_INPUTS[0];
        assert!(matches!(
            compile_activations(
                &[&activation],
                SelectedWorkflowCapabilities::empty(),
                "test-runtime-plan",
                generated::event::PROJECTION_DEFINITIONS,
                &[input, input],
                generated::saga::SPECS,
            ),
            Err(WorkflowRuntimeError::DuplicateProjectionInput { .. })
        ));

        assert!(matches!(
            compile_activations(
                &[&projection_activation(ProjectionActivation::CaptureOnly)],
                projection_catalog(ProjectionActivation::CaptureOnly),
                "test-runtime-plan",
                generated::event::PROJECTION_DEFINITIONS,
                &[],
                generated::saga::SPECS,
            ),
            Err(WorkflowRuntimeError::MissingProjectionInputs { .. })
        ));

        let unknown_input = ProjectionInputBinding::from_static(
            "unknown.projection",
            "identity",
            "identity.session.created",
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "identity.session.created",
        );
        assert!(matches!(
            compile_activations(
                &[&activation],
                SelectedWorkflowCapabilities::empty(),
                "test-runtime-plan",
                generated::event::PROJECTION_DEFINITIONS,
                &[unknown_input],
                generated::saga::SPECS,
            ),
            Err(WorkflowRuntimeError::UnknownProjectionInput { .. })
        ));
    }

    #[test]
    fn catalog_rejects_duplicates_and_unknown_definition_identity() {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let runtime = projection_runtime_for(projection_target_for(definition));
        let mut duplicate = SelectedWorkflowCapabilities::empty();
        duplicate
            .insert_projection(ProjectionCapabilityBundle::shadow(
                definition,
                runtime.clone(),
            ))
            .expect("first capability");
        assert!(matches!(
            duplicate.insert_projection(ProjectionCapabilityBundle::shadow(definition, runtime)),
            Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { .. })
        ));

        let unknown = ContractBinding::from_static(
            "unknown",
            "unknown.projection",
            "v1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let mut catalog = SelectedWorkflowCapabilities::empty();
        let runtime = projection_runtime_for(projection_target_for(definition));
        catalog
            .insert_projection(ProjectionCapabilityBundle::shadow(unknown, runtime))
            .expect("unique unknown capability");
        let disabled = projection_activation(ProjectionActivation::Disabled);
        assert!(matches!(
            compile_fixture(&[disabled], catalog),
            Err(WorkflowRuntimeError::UnknownCapabilityWorkflow { .. })
        ));
    }

    #[test]
    fn target_view_borrows_the_catalog_selected_implementation() -> Result<(), WorkflowRuntimeError>
    {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let target = projection_target_for(definition);
        let runtime = projection_runtime_for(Arc::clone(&target));
        let mut catalog = SelectedWorkflowCapabilities::empty();
        catalog.insert_projection(ProjectionCapabilityBundle::shadow(definition, runtime))?;
        let plan = compile_fixture(
            &[projection_activation(ProjectionActivation::Shadow)],
            catalog,
        )?;
        let selected = plan
            .projection_targets()
            .entries()
            .next()
            .expect("selected target")
            .target();
        assert!(Arc::ptr_eq(&selected, &target));
        Ok(())
    }

    #[test]
    fn registry_rejects_definition_and_input_generation_drift_before_target_io()
    -> Result<(), Box<dyn std::error::Error>> {
        const OTHER_GENERATION: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let selected = generated::event::PROJECTION_DEFINITIONS[0];
        let drifted_definition = ContractBinding::from_static(
            selected.domain(),
            selected.contract_id(),
            selected.version(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );

        for target in [
            projection_target_for_identity(selected, OTHER_GENERATION),
            projection_target_for_identity(
                drifted_definition,
                generated::event::PROJECTION_INPUT_GENERATION,
            ),
        ] {
            let runtime = projection_runtime_for(target);
            let mut catalog = SelectedWorkflowCapabilities::empty();
            catalog.insert_projection(ProjectionCapabilityBundle::shadow(selected, runtime))?;
            let plan = compile_fixture(
                &[projection_activation(ProjectionActivation::Shadow)],
                catalog,
            )?;
            assert!(matches!(
                crate::ProjectionTargetRegistry::from_view(plan.projection_targets()),
                Err(crate::ProjectionRegistryError::TargetIdentityMismatch { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn registry_mints_each_real_projection_identity_without_cross_splicing()
    -> Result<(), Box<dyn std::error::Error>> {
        let definitions = generated::event::PROJECTION_DEFINITIONS;
        assert!(
            definitions.len() >= 2,
            "fixture requires two real definitions"
        );

        let mut catalog = SelectedWorkflowCapabilities::empty();
        let activations = definitions
            .iter()
            .map(|definition| {
                let runtime = projection_runtime_for(projection_target_for(*definition));
                catalog
                    .insert_projection(ProjectionCapabilityBundle::shadow(*definition, runtime))
                    .expect("generated projection ids are unique");
                WorkflowActivation::Projection {
                    id: definition.contract_id().to_owned(),
                    definition_version: definition.version().to_owned(),
                    definition_schema_digest: digest(definition.schema_hash()),
                    target_generation: format!("{}-target", definition.version()),
                    activation: ProjectionActivation::Shadow,
                }
            })
            .collect::<Vec<_>>();
        let plan = compile_fixture(&activations, catalog)?;
        let registry = crate::ProjectionTargetRegistry::from_view(plan.projection_targets())?;
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;

        let first_id = crate::ProjectionId::parse(definitions[0].contract_id())?;
        let second_id = crate::ProjectionId::parse(definitions[1].contract_id())?;
        let first = registry.source_scope(&first_id, tenant)?;
        let second = registry.source_scope(&second_id, tenant)?;
        let replay = registry.operator_execution_context(&first_id, tenant)?;

        assert_eq!(first.projection(), &first_id);
        assert_eq!(first.definition_version(), definitions[0].version());
        assert_eq!(
            first.definition_schema_digest(),
            definitions[0].schema_hash()
        );
        assert_eq!(second.projection(), &second_id);
        assert_eq!(second.definition_version(), definitions[1].version());
        assert_eq!(
            second.definition_schema_digest(),
            definitions[1].schema_hash()
        );
        assert_ne!(first.projection(), second.projection());
        assert_eq!(replay.tenant(), tenant);
        assert_eq!(replay.identity().actor(), "rss-projection-replay");
        assert_eq!(replay.identity().purpose().as_str(), "operator-replay");
        assert_ne!(
            first.definition_schema_digest(),
            second.definition_schema_digest()
        );
        assert!(
            registry
                .bindings_for(&first_id)?
                .iter()
                .all(|binding| binding.projection_id() == first.projection().as_str())
        );
        assert!(
            registry
                .bindings_for(&second_id)?
                .iter()
                .all(|binding| binding.projection_id() == second.projection().as_str())
        );
        Ok(())
    }

    #[test]
    fn typed_capability_identity_drift_fails_closed() {
        let generated_projection = generated::event::PROJECTION_DEFINITIONS[0];
        let wrong_projection = ContractBinding::from_static(
            generated_projection.domain(),
            generated_projection.contract_id(),
            "v999",
            generated_projection.schema_hash(),
        );
        let mut projections = SelectedWorkflowCapabilities::empty();
        let runtime = projection_runtime_for(projection_target_for(generated_projection));
        projections
            .insert_projection(ProjectionCapabilityBundle::shadow(
                wrong_projection,
                runtime,
            ))
            .expect("unique wrong projection capability");
        assert!(matches!(
            compile_fixture(
                &[projection_activation(ProjectionActivation::Shadow)],
                projections,
            ),
            Err(WorkflowRuntimeError::CapabilityIdentityMismatch { .. })
        ));
    }
}
