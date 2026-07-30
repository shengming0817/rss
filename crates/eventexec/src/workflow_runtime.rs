//! Assembly-owned workflow runtime closure.
//!
//! The repository-wide generated catalogs describe definitions only. This module is the sole
//! production join from a sealed [`assembly_schema::RuntimePlan`] to runtime-visible Projection and
//! Saga views. Fields stay private so callers cannot manufacture activation independently.

use std::collections::BTreeMap;
use std::sync::Arc;

use assembly_schema::{ProjectionActivation, RuntimePlan, SagaActivation, WorkflowActivation};
use diport::{DynManagedResource, SagaWorkerIdentity};
use tokio_util::sync::CancellationToken;
use vocab::{ContractBinding, ProjectionInputBinding, SagaContractBinding};

use crate::{ProjectionTarget, WorkerHealth};

mod sealed {
    pub trait ProjectionRuntimeFactory {}
    pub trait SagaRuntimeFactory {}
}

/// Typed capture capability. Implementations validate that the compiled definition and exact input
/// set can be bound to the concrete source/capture store represented by this object.
trait ProjectionCapturePort: Send + Sync {
    fn bind(&self, definition: ContractBinding, inputs: &[ProjectionInputBinding]) -> bool;
}

/// Complete shadow/active Projection runtime factory. The factory owns the checkpoint, dead-letter,
/// worker and probe dependencies and exposes the exact replay target used by the operator.
pub trait ProjectionRuntimeFactory: sealed::ProjectionRuntimeFactory + Send + Sync {
    fn target(&self) -> Arc<dyn ProjectionTarget>;
    fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
    ) -> Box<DynManagedResource<'static>>;
}

/// Typed serving capability for an authoritative Projection.
trait ProjectionServingPort: Send + Sync {
    fn serves(&self, definition: ContractBinding) -> bool;
}

/// Complete active Saga runtime factory. Stores, typed actions, fencing and worker configuration
/// are captured by the factory before it enters the catalog; assembly wiring can only spawn this
/// exact selected implementation.
pub trait SagaRuntimeFactory: sealed::SagaRuntimeFactory + Send + Sync {
    fn identity(&self) -> &SagaWorkerIdentity;
    fn spawn(
        &self,
        token: CancellationToken,
        health: Arc<WorkerHealth>,
    ) -> Box<DynManagedResource<'static>>;
}

struct ProjectionCapabilityBundle {
    definition: ContractBinding,
    capture: Arc<dyn ProjectionCapturePort>,
    runtime: Option<Arc<dyn ProjectionRuntimeFactory>>,
    serving: Option<Arc<dyn ProjectionServingPort>>,
}

impl ProjectionCapabilityBundle {
    #[cfg(test)]
    fn capture_only(definition: ContractBinding, capture: Arc<dyn ProjectionCapturePort>) -> Self {
        Self {
            definition,
            capture,
            runtime: None,
            serving: None,
        }
    }

    #[cfg(test)]
    fn shadow(
        definition: ContractBinding,
        capture: Arc<dyn ProjectionCapturePort>,
        runtime: Arc<dyn ProjectionRuntimeFactory>,
    ) -> Self {
        Self {
            definition,
            capture,
            runtime: Some(runtime),
            serving: None,
        }
    }

    #[cfg(test)]
    fn active(
        definition: ContractBinding,
        capture: Arc<dyn ProjectionCapturePort>,
        runtime: Arc<dyn ProjectionRuntimeFactory>,
        serving: Arc<dyn ProjectionServingPort>,
    ) -> Self {
        Self {
            definition,
            capture,
            runtime: Some(runtime),
            serving: Some(serving),
        }
    }
}

struct SagaCapabilityBundle {
    definition: SagaContractBinding,
    runtime: Arc<dyn SagaRuntimeFactory>,
}

impl SagaCapabilityBundle {
    #[cfg(test)]
    fn active(definition: SagaContractBinding, runtime: Arc<dyn SagaRuntimeFactory>) -> Self {
        Self {
            definition,
            runtime,
        }
    }
}

#[derive(Default)]
pub struct WorkflowCapabilityCatalog {
    projection: BTreeMap<String, ProjectionCapabilityBundle>,
    saga: BTreeMap<String, SagaCapabilityBundle>,
}

impl WorkflowCapabilityCatalog {
    /// Empty production capability catalog. It is the exact catalog for today's all-disabled
    /// assemblies; changing an assembly to active before real typed bindings land fails closed.
    pub fn empty() -> Self {
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

    #[cfg(test)]
    fn insert_saga(&mut self, bundle: SagaCapabilityBundle) -> Result<(), WorkflowRuntimeError> {
        let id = bundle.definition.contract_id().to_owned();
        match self.saga.entry(id.clone()) {
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
    #[cfg(any(test, feature = "test-support"))]
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

    pub fn compile(
        runtime: &RuntimePlan,
        capabilities: WorkflowCapabilityCatalog,
    ) -> Result<Self, WorkflowRuntimeError> {
        let activations = runtime
            .workflow_plans()
            .iter()
            .map(|plan| plan.activation())
            .collect::<Vec<_>>();
        compile_activations(
            &activations,
            capabilities,
            runtime.runtime_plan_fingerprint().as_str(),
            generated::event::PROJECTION_DEFINITIONS,
            generated::event::PROJECTION_INPUTS,
            generated::saga::SPECS,
        )
    }

    pub fn projection_capture(&self) -> ProjectionCaptureView<'_> {
        ProjectionCaptureView {
            generation: generated::event::PROJECTION_INPUT_GENERATION,
            bindings: &self.projection_inputs,
        }
    }

    pub fn projection_targets(&self) -> ProjectionTargetView<'_> {
        ProjectionTargetView {
            targets: &self.projection_targets,
        }
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
}

#[derive(Clone, Copy)]
pub struct ProjectionTargetView<'a> {
    targets: &'a [SelectedProjectionTarget],
}

impl<'a> ProjectionTargetView<'a> {
    pub fn entries(self) -> impl ExactSizeIterator<Item = ProjectionTargetEntry<'a>> + 'a {
        self.targets
            .iter()
            .map(|target| ProjectionTargetEntry { target })
    }
}

#[derive(Clone, Copy)]
pub struct ProjectionTargetEntry<'a> {
    target: &'a SelectedProjectionTarget,
}

impl ProjectionTargetEntry<'_> {
    pub fn workflow(&self) -> &ActivatedWorkflow {
        &self.target.workflow
    }
    pub fn bindings(&self) -> &[ProjectionInputBinding] {
        &self.target.inputs
    }
    pub fn target(&self) -> Arc<dyn ProjectionTarget> {
        Arc::clone(&self.target.target)
    }
    pub fn runtime_factory(&self) -> &Arc<dyn ProjectionRuntimeFactory> {
        &self.target.runtime
    }
}

struct SelectedProjectionCapture {
    _capture: Arc<dyn ProjectionCapturePort>,
}

struct SelectedProjectionTarget {
    workflow: ActivatedWorkflow,
    inputs: Vec<ProjectionInputBinding>,
    runtime: Arc<dyn ProjectionRuntimeFactory>,
    target: Arc<dyn ProjectionTarget>,
    _serving: Option<Arc<dyn ProjectionServingPort>>,
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

impl SagaRuntimeEntry<'_> {
    pub const fn spec(&self) -> SagaContractBinding {
        self.saga.spec
    }
    pub fn runtime_factory(&self) -> &Arc<dyn SagaRuntimeFactory> {
        &self.saga.runtime
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
    activation: ActivatedWorkflowActivation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivatedWorkflowActivation {
    Projection(ProjectionActivation),
    Saga(SagaActivation),
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

    pub const fn activation(&self) -> ActivatedWorkflowActivation {
        self.activation
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
    mut capabilities: WorkflowCapabilityCatalog,
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
                    definition_schema_digest,
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
                if *activation == ProjectionActivation::Disabled {
                    continue;
                }
                let bundle = capabilities.projection.remove(id).ok_or_else(|| {
                    WorkflowRuntimeError::MissingCapability {
                        workflow: id.clone(),
                        capability: "typed-projection-bundle",
                    }
                })?;
                validate_projection_bundle(id, *activation, *definition, &inputs, &bundle)?;
                selected_inputs.extend(inputs.iter().copied());
                let observation = ActivatedWorkflow {
                    id: id.clone(),
                    definition_version: definition_version.clone(),
                    definition_schema_digest: definition_schema_digest.clone(),
                    activation: ActivatedWorkflowActivation::Projection(*activation),
                };
                selected_captures.push(SelectedProjectionCapture {
                    _capture: Arc::clone(&bundle.capture),
                });
                if matches!(
                    activation,
                    ProjectionActivation::Shadow | ProjectionActivation::Active
                ) {
                    let Some(runtime) = bundle.runtime else {
                        return Err(WorkflowRuntimeError::MissingCapability {
                            workflow: id.clone(),
                            capability: "projection-runtime-factory",
                        });
                    };
                    let target = runtime.target();
                    selected_targets.push(SelectedProjectionTarget {
                        workflow: observation.clone(),
                        inputs,
                        runtime,
                        target,
                        _serving: bundle.serving,
                    });
                }
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
                    definition_schema_digest,
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
                    definition_schema_digest: definition_schema_digest.clone(),
                    activation: ActivatedWorkflowActivation::Saga(*activation),
                });
            }
        }
    }
    activated.sort_by(|left, right| left.id.cmp(&right.id));
    selected_targets.sort_by(|left, right| left.workflow.id.cmp(&right.workflow.id));
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
    catalog: &WorkflowCapabilityCatalog,
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
    if !bundle.capture.bind(definition, inputs) {
        return Err(WorkflowRuntimeError::CapabilityBindingRejected {
            workflow: id.to_owned(),
        });
    }
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
            .serving
            .as_ref()
            .is_some_and(|serving| serving.serves(definition))
    {
        return Err(WorkflowRuntimeError::MissingCapability {
            workflow: id.to_owned(),
            capability: "serving-port",
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
    use futures::future::BoxFuture;

    use super::*;

    struct CapturePort;
    impl ProjectionCapturePort for CapturePort {
        fn bind(&self, definition: ContractBinding, inputs: &[ProjectionInputBinding]) -> bool {
            !inputs.is_empty()
                && inputs
                    .iter()
                    .all(|input| input.projection_id() == definition.contract_id())
        }
    }

    struct RejectingCapturePort;
    impl ProjectionCapturePort for RejectingCapturePort {
        fn bind(&self, _definition: ContractBinding, _inputs: &[ProjectionInputBinding]) -> bool {
            false
        }
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

    fn projection_target() -> Arc<dyn ProjectionTarget> {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let projection = crate::ProjectionId::parse(definition.contract_id())
            .expect("generated projection id is canonical");
        let bindings = generated::event::PROJECTION_INPUTS
            .iter()
            .filter(|input| input.projection_id() == definition.contract_id())
            .cloned()
            .collect();
        Arc::new(
            crate::ConformingProjectionTarget::new(
                projection,
                bindings,
                Arc::new(NoopProjectionStore),
            )
            .expect("generated target binding is canonical"),
        )
    }

    struct ProjectionFactory {
        target: Arc<dyn ProjectionTarget>,
    }
    impl sealed::ProjectionRuntimeFactory for ProjectionFactory {}
    impl ProjectionRuntimeFactory for ProjectionFactory {
        fn target(&self) -> Arc<dyn ProjectionTarget> {
            Arc::clone(&self.target)
        }
        fn spawn(
            &self,
            _token: CancellationToken,
            _health: Arc<WorkerHealth>,
        ) -> Box<DynManagedResource<'static>> {
            panic!("test factory must not spawn")
        }
    }

    struct ServingPort;
    impl ProjectionServingPort for ServingPort {
        fn serves(&self, _definition: ContractBinding) -> bool {
            true
        }
    }

    struct SagaFactory {
        identity: SagaWorkerIdentity,
    }
    impl sealed::SagaRuntimeFactory for SagaFactory {}
    impl SagaRuntimeFactory for SagaFactory {
        fn identity(&self) -> &SagaWorkerIdentity {
            &self.identity
        }
        fn spawn(
            &self,
            _token: CancellationToken,
            _health: Arc<WorkerHealth>,
        ) -> Box<DynManagedResource<'static>> {
            panic!("test factory must not spawn")
        }
    }

    fn projection_catalog(mode: ProjectionActivation) -> WorkflowCapabilityCatalog {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        let capture = Arc::new(CapturePort);
        let runtime = Arc::new(ProjectionFactory {
            target: projection_target(),
        });
        let bundle = match mode {
            ProjectionActivation::Disabled | ProjectionActivation::CaptureOnly => {
                ProjectionCapabilityBundle::capture_only(definition, capture)
            }
            ProjectionActivation::Shadow => {
                ProjectionCapabilityBundle::shadow(definition, capture, runtime)
            }
            ProjectionActivation::Active => ProjectionCapabilityBundle::active(
                definition,
                capture,
                runtime,
                Arc::new(ServingPort),
            ),
        };
        let mut catalog = WorkflowCapabilityCatalog::empty();
        catalog
            .insert_projection(bundle)
            .expect("unique test projection");
        catalog
    }

    fn saga_catalog() -> WorkflowCapabilityCatalog {
        use diport::SagaContractId;
        let definition = generated::saga::SPECS[0];
        let identity = SagaWorkerIdentity::new(
            definition.domain(),
            SagaContractId::parse(definition.contract_id()).expect("generated saga id"),
        )
        .expect("generated saga identity");
        let mut catalog = WorkflowCapabilityCatalog::empty();
        catalog
            .insert_saga(SagaCapabilityBundle::active(
                definition,
                Arc::new(SagaFactory { identity }),
            ))
            .expect("unique test saga");
        catalog
    }

    fn projection_activation(mode: ProjectionActivation) -> WorkflowActivation {
        let definition = generated::event::PROJECTION_DEFINITIONS[0];
        WorkflowActivation::Projection {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest: definition.schema_hash().to_owned(),
            activation: mode,
        }
    }

    fn saga_activation(mode: SagaActivation) -> WorkflowActivation {
        let definition = generated::saga::SPECS[0].contract();
        WorkflowActivation::Saga {
            id: definition.contract_id().to_owned(),
            definition_version: definition.version().to_owned(),
            definition_schema_digest: definition.schema_hash().to_owned(),
            activation: mode,
        }
    }

    fn compile_fixture(
        activations: &[WorkflowActivation],
        catalog: WorkflowCapabilityCatalog,
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
        assert!(
            plan.projection_capture()
                .bindings()
                .iter()
                .all(|binding| binding.projection_id() == id)
        );
        assert_eq!(plan.projection_targets().entries().len(), 0);
        assert_eq!(plan.activated_workflows().workflows().len(), 1);
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
                capability: "serving-port",
            })
        );
    }

    #[test]
    fn active_saga_requires_typed_factory_and_disabled_saga_is_empty()
    -> Result<(), WorkflowRuntimeError> {
        let active = saga_activation(SagaActivation::Active);
        let id = active.id().to_owned();
        assert_eq!(
            compile_fixture(
                std::slice::from_ref(&active),
                WorkflowCapabilityCatalog::empty()
            )
            .err(),
            Some(WorkflowRuntimeError::MissingCapability {
                workflow: id,
                capability: "typed-saga-bundle",
            })
        );
        let active_plan = compile_fixture(&[active], saga_catalog())?;
        assert_eq!(active_plan.sagas().entries().len(), 1);

        let disabled = saga_activation(SagaActivation::Disabled);
        let plan = compile_fixture(&[disabled], WorkflowCapabilityCatalog::empty())?;
        assert!(plan.sagas().is_empty());
        assert!(plan.activated_workflows().workflows().is_empty());
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
            compile_fixture(&[wrong], WorkflowCapabilityCatalog::empty()),
            Err(WorkflowRuntimeError::DefinitionMismatch {
                field: "version",
                ..
            })
        ));

        let saga = generated::saga::SPECS[0].contract();
        let wrong_mode = WorkflowActivation::Projection {
            id: saga.contract_id().to_owned(),
            definition_version: saga.version().to_owned(),
            definition_schema_digest: saga.schema_hash().to_owned(),
            activation: ProjectionActivation::Disabled,
        };
        assert!(matches!(
            compile_fixture(&[wrong_mode], WorkflowCapabilityCatalog::empty()),
            Err(WorkflowRuntimeError::ModeMismatch { .. })
        ));

        let mut wrong_digest = projection_activation(ProjectionActivation::Disabled);
        if let WorkflowActivation::Projection {
            definition_schema_digest,
            ..
        } = &mut wrong_digest
        {
            *definition_schema_digest = "sha256:wrong".to_owned();
        }
        assert!(matches!(
            compile_fixture(&[wrong_digest], WorkflowCapabilityCatalog::empty()),
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
                WorkflowCapabilityCatalog::empty(),
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
                WorkflowCapabilityCatalog::empty(),
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
            "sha256:unknown",
            "identity.session.created",
        );
        assert!(matches!(
            compile_activations(
                &[&activation],
                WorkflowCapabilityCatalog::empty(),
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
        let mut duplicate = WorkflowCapabilityCatalog::empty();
        duplicate
            .insert_projection(ProjectionCapabilityBundle::capture_only(
                definition,
                Arc::new(RejectingCapturePort),
            ))
            .expect("first capability");
        assert!(matches!(
            duplicate.insert_projection(ProjectionCapabilityBundle::capture_only(
                definition,
                Arc::new(CapturePort),
            )),
            Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { .. })
        ));
        assert!(matches!(
            compile_fixture(
                &[projection_activation(ProjectionActivation::CaptureOnly)],
                duplicate,
            ),
            Err(WorkflowRuntimeError::CapabilityBindingRejected { .. })
        ));

        let saga_definition = generated::saga::SPECS[0];
        let mut sagas = saga_catalog();
        let wrong_identity = SagaWorkerIdentity::new(
            "wrong-owner",
            diport::SagaContractId::parse(saga_definition.contract_id())
                .expect("generated saga id"),
        )
        .expect("syntactically valid wrong identity");
        assert!(matches!(
            sagas.insert_saga(SagaCapabilityBundle::active(
                saga_definition,
                Arc::new(SagaFactory {
                    identity: wrong_identity,
                }),
            )),
            Err(WorkflowRuntimeError::DuplicateCapabilityWorkflow { .. })
        ));
        assert!(compile_fixture(&[saga_activation(SagaActivation::Active)], sagas,).is_ok());

        let unknown =
            ContractBinding::from_static("unknown", "unknown.projection", "v1", "sha256:unknown");
        let mut catalog = WorkflowCapabilityCatalog::empty();
        catalog
            .insert_projection(ProjectionCapabilityBundle::capture_only(
                unknown,
                Arc::new(CapturePort),
            ))
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
        let target = projection_target();
        let runtime = Arc::new(ProjectionFactory {
            target: Arc::clone(&target),
        });
        let mut catalog = WorkflowCapabilityCatalog::empty();
        catalog.insert_projection(ProjectionCapabilityBundle::shadow(
            definition,
            Arc::new(CapturePort),
            runtime,
        ))?;
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
    fn typed_capability_identity_drift_fails_closed() {
        let generated_projection = generated::event::PROJECTION_DEFINITIONS[0];
        let wrong_projection = ContractBinding::from_static(
            generated_projection.domain(),
            generated_projection.contract_id(),
            "v999",
            generated_projection.schema_hash(),
        );
        let mut projections = WorkflowCapabilityCatalog::empty();
        projections
            .insert_projection(ProjectionCapabilityBundle::capture_only(
                wrong_projection,
                Arc::new(CapturePort),
            ))
            .expect("unique wrong projection capability");
        assert!(matches!(
            compile_fixture(
                &[projection_activation(ProjectionActivation::CaptureOnly)],
                projections,
            ),
            Err(WorkflowRuntimeError::CapabilityIdentityMismatch { .. })
        ));

        let generated_saga = generated::saga::SPECS[0];
        let wrong_identity = SagaWorkerIdentity::new(
            "wrong-owner",
            diport::SagaContractId::parse(generated_saga.contract_id()).expect("generated saga id"),
        )
        .expect("syntactically valid wrong identity");
        let mut sagas = WorkflowCapabilityCatalog::empty();
        sagas
            .insert_saga(SagaCapabilityBundle::active(
                generated_saga,
                Arc::new(SagaFactory {
                    identity: wrong_identity,
                }),
            ))
            .expect("unique wrong saga capability");
        assert!(matches!(
            compile_fixture(&[saga_activation(SagaActivation::Active)], sagas),
            Err(WorkflowRuntimeError::CapabilityIdentityMismatch { .. })
        ));
    }
}
