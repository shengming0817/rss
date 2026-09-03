//! Provider-independent, non-serializable runtime inventory observation model.

use assembly_schema::runtime_inventory as observation;
use assembly_schema::{AssemblyDomain, AssemblyListenerKind, ListenerAuth, RuntimePlan};
use bootstrap::HealthReporter;
use primitives::{HealthStatus, ProbeName};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

/// Build metadata declared to the process by its launch environment.
///
/// The image digest cannot be self-proven by a binary embedded in that image. This value is
/// therefore reportable metadata, not an OCI/SLSA verification receipt, and is deliberately never
/// joined to an external delivery plan or workload identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildMetadata {
    source_revision: String,
    image_digest: observation::CanonicalSha256Digest,
}

impl BuildMetadata {
    pub fn parse(source_revision: &str, image_digest: &str) -> Result<Self, InventoryError> {
        if !matches!(source_revision.len(), 40 | 64) || !is_lower_hex(source_revision) {
            return Err(InventoryError::BuildMetadata);
        }
        let image_digest = observation::CanonicalSha256Digest::parse(image_digest)
            .map_err(|_| InventoryError::BuildMetadata)?;
        Ok(Self {
            source_revision: source_revision.to_owned(),
            image_digest,
        })
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub fn image_digest(&self) -> &str {
        self.image_digest.as_str()
    }

    /// Parse an optional launch assertion. The pair is atomic: a partial claim is rejected.
    pub fn from_optional(
        source_revision: Option<&str>,
        image_digest: Option<&str>,
    ) -> Result<Option<Self>, InventoryError> {
        match (source_revision, image_digest) {
            (None, None) => Ok(None),
            (Some(source_revision), Some(image_digest)) => {
                Self::parse(source_revision, image_digest).map(Some)
            }
            _ => Err(InventoryError::BuildMetadata),
        }
    }
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryEndpointScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEndpoint {
    scheme: InventoryEndpointScheme,
    host: String,
    port: u16,
}

impl InventoryEndpoint {
    fn from_bound(scheme: InventoryEndpointScheme, address: SocketAddr) -> Self {
        Self {
            scheme,
            host: address.ip().to_string(),
            port: address.port(),
        }
    }

    pub const fn scheme(&self) -> InventoryEndpointScheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// A configured peer endpoint. Unlike [`InventoryEndpoint`], this does not
/// claim that a socket was successfully bound by this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementEndpoint {
    scheme: InventoryEndpointScheme,
    host: String,
    port: u16,
}

impl PlacementEndpoint {
    pub fn from_typed_parts(
        scheme: InventoryEndpointScheme,
        host: &str,
        port: u16,
    ) -> Result<Self, InventoryError> {
        if host.is_empty() || port == 0 || host.contains('@') || host.contains('/') {
            return Err(InventoryError::Endpoint);
        }
        Ok(Self {
            scheme,
            host: host.to_owned(),
            port,
        })
    }

    pub const fn scheme(&self) -> InventoryEndpointScheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundListenerObservation {
    id: String,
    kind: AssemblyListenerKind,
    auth: ListenerAuth,
    endpoint: InventoryEndpoint,
}

impl BoundListenerObservation {
    pub fn from_bound(
        id: impl Into<String>,
        kind: AssemblyListenerKind,
        auth: ListenerAuth,
        scheme: InventoryEndpointScheme,
        address: SocketAddr,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            auth,
            endpoint: InventoryEndpoint::from_bound(scheme, address),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn kind(&self) -> AssemblyListenerKind {
        self.kind
    }

    pub const fn auth(&self) -> ListenerAuth {
        self.auth
    }

    pub const fn endpoint(&self) -> &InventoryEndpoint {
        &self.endpoint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProbeBinding {
    provider_id: String,
    evidence: ProviderProbeEvidence,
}

/// Exact provider projection sealed by a completed provider transaction.
pub struct ProviderExecutionReceipt {
    source_runtime_plan_fingerprint: String,
    bindings: Vec<ProviderProbeBinding>,
}

impl ProviderExecutionReceipt {
    /// Seal the complete provider set of a typed RuntimePlan without caller-supplied source facts.
    pub fn from_runtime_plan(
        runtime: &RuntimePlan,
        bindings: Vec<ProviderProbeBinding>,
    ) -> Result<Self, InventoryError> {
        Self::seal(
            runtimeinventorymint::RuntimeInventoryMint::capability(),
            runtime.runtime_plan_fingerprint().as_str(),
            runtime
                .provider_plans()
                .iter()
                .map(|provider| provider.id().to_owned()),
            bindings,
        )
    }

    /// Seal a placement-projected provider transaction. Only the approved runtime inventory
    /// boundary can name the mint capability; normal callers use [`Self::from_runtime_plan`].
    pub fn seal(
        _mint: runtimeinventorymint::RuntimeInventoryMint,
        source_runtime_plan_fingerprint: impl Into<String>,
        expected_provider_ids: impl IntoIterator<Item = String>,
        mut bindings: Vec<ProviderProbeBinding>,
    ) -> Result<Self, InventoryError> {
        let expected = expected_provider_ids.into_iter().collect::<BTreeSet<_>>();
        bindings.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        let actual = bindings
            .iter()
            .map(|binding| binding.provider_id().to_owned())
            .collect::<BTreeSet<_>>();
        if expected.len() != bindings.len() || expected != actual {
            return Err(InventoryError::ProviderBinding);
        }
        Ok(Self {
            source_runtime_plan_fingerprint: source_runtime_plan_fingerprint.into(),
            bindings,
        })
    }

    fn into_bindings(self) -> Vec<ProviderProbeBinding> {
        self.bindings
    }

    pub fn bindings(&self) -> &[ProviderProbeBinding] {
        &self.bindings
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderProbeEvidence {
    ConstructionOnly,
    Observed(NonEmptyProbeSet),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NonEmptyProbeSet(Vec<ProbeName>);

/// A workflow activation copied from the sealed workflow runtime plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedWorkflowObservation {
    id: String,
    definition_version: String,
    definition_schema_digest: observation::CanonicalSha256Digest,
    shape: ActivatedWorkflowObservationShape,
}

impl ActivatedWorkflowObservation {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    pub fn definition_schema_digest(&self) -> &str {
        self.definition_schema_digest.as_str()
    }

    pub const fn shape(&self) -> &ActivatedWorkflowObservationShape {
        &self.shape
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivatedWorkflowObservationShape {
    ProjectionCapture,
    ProjectionExecuting {
        activation: InventoryExecutingProjectionActivation,
        execution: eventexec::ProjectionExecutionObservation,
    },
    SagaActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryExecutingProjectionActivation {
    Shadow,
    Active,
}

impl ProviderProbeBinding {
    pub fn from_probe_receipt(
        provider_id: impl Into<String>,
        probe_names: Vec<ProbeName>,
    ) -> Result<Self, InventoryError> {
        let provider_id = provider_id.into();
        if provider_id.is_empty() {
            return Err(InventoryError::ProviderBinding);
        }
        let unique = probe_names
            .iter()
            .map(ProbeName::as_str)
            .collect::<BTreeSet<_>>();
        if unique.len() != probe_names.len() {
            return Err(InventoryError::ProviderBinding);
        }
        Ok(Self {
            provider_id,
            evidence: if probe_names.is_empty() {
                ProviderProbeEvidence::ConstructionOnly
            } else {
                ProviderProbeEvidence::Observed(NonEmptyProbeSet(probe_names))
            },
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn probe_names(&self) -> &[ProbeName] {
        match &self.evidence {
            ProviderProbeEvidence::ConstructionOnly => &[],
            ProviderProbeEvidence::Observed(probe_names) => &probe_names.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryPlacementMode {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryPlacementReadiness {
    Ready,
    MtlsSourceUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementObservation {
    domain: AssemblyDomain,
    workload: String,
    mode: InventoryPlacementMode,
    endpoint: Option<PlacementEndpoint>,
    spiffe_identity: Option<String>,
    readiness: InventoryPlacementReadiness,
}

impl PlacementObservation {
    pub fn local(domain: AssemblyDomain, workload: impl Into<String>) -> Self {
        Self {
            domain,
            workload: workload.into(),
            mode: InventoryPlacementMode::Local,
            endpoint: None,
            spiffe_identity: None,
            readiness: InventoryPlacementReadiness::Ready,
        }
    }

    pub fn remote(
        domain: AssemblyDomain,
        workload: impl Into<String>,
        endpoint: Option<PlacementEndpoint>,
        spiffe_identity: Option<String>,
        readiness: InventoryPlacementReadiness,
    ) -> Result<Self, InventoryError> {
        if spiffe_identity.as_deref().is_some_and(str::is_empty) {
            return Err(InventoryError::Placement);
        }
        Ok(Self {
            domain,
            workload: workload.into(),
            mode: InventoryPlacementMode::Remote,
            endpoint,
            spiffe_identity,
            readiness,
        })
    }

    pub const fn domain(&self) -> AssemblyDomain {
        self.domain
    }

    pub fn workload(&self) -> &str {
        &self.workload
    }

    pub const fn mode(&self) -> InventoryPlacementMode {
        self.mode
    }

    pub fn endpoint(&self) -> Option<&PlacementEndpoint> {
        self.endpoint.as_ref()
    }

    pub fn spiffe_identity(&self) -> Option<&str> {
        self.spiffe_identity.as_deref()
    }

    pub const fn readiness(&self) -> InventoryPlacementReadiness {
        self.readiness
    }
}

pub struct RuntimeInventorySeed {
    identity: observation::RuntimeInventoryIdentity,
    build_metadata: Option<BuildMetadata>,
    domains: Vec<AssemblyDomain>,
    activated_workflows: Vec<ActivatedWorkflowObservation>,
    listeners: Vec<ExpectedListener>,
    provider_bindings: Vec<ProviderProbeBinding>,
    placements: Vec<PlacementObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedListener {
    id: String,
    kind: AssemblyListenerKind,
    auth: ListenerAuth,
}

impl RuntimeInventorySeed {
    pub fn from_runtime_plan(
        runtime: &RuntimePlan,
        activated_workflows: eventexec::ActivatedWorkflowsView<'_>,
        provider_receipt: ProviderExecutionReceipt,
        mut placements: Vec<PlacementObservation>,
    ) -> Result<Self, InventoryError> {
        if activated_workflows.source_runtime_plan_fingerprint()
            != runtime.runtime_plan_fingerprint().as_str()
        {
            return Err(InventoryError::WorkflowPlanSource);
        }
        if provider_receipt.source_runtime_plan_fingerprint
            != runtime.runtime_plan_fingerprint().as_str()
        {
            return Err(InventoryError::ProviderPlanSource);
        }
        let activated_workflows = activated_workflows
            .workflows()
            .iter()
            .map(|workflow| {
                let shape = match workflow.shape() {
                    eventexec::ActivatedWorkflowShape::ProjectionCapture => {
                        ActivatedWorkflowObservationShape::ProjectionCapture
                    }
                    eventexec::ActivatedWorkflowShape::ProjectionExecuting {
                        activation,
                        execution,
                    } => ActivatedWorkflowObservationShape::ProjectionExecuting {
                        activation: match activation {
                            eventexec::ActivatedExecutingProjectionActivation::Shadow => {
                                InventoryExecutingProjectionActivation::Shadow
                            }
                            eventexec::ActivatedExecutingProjectionActivation::Active => {
                                InventoryExecutingProjectionActivation::Active
                            }
                        },
                        execution: execution.clone(),
                    },
                    eventexec::ActivatedWorkflowShape::SagaActive => {
                        ActivatedWorkflowObservationShape::SagaActive
                    }
                };
                Ok(ActivatedWorkflowObservation {
                    id: workflow.id().to_owned(),
                    definition_version: workflow.definition_version().to_owned(),
                    definition_schema_digest: observation::CanonicalSha256Digest::parse(
                        workflow.definition_schema_digest(),
                    )
                    .map_err(|_| InventoryError::ActivatedWorkflow)?,
                    shape,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let provider_bindings = provider_receipt.into_bindings();

        placements.sort_by(|left, right| {
            (left.domain.as_str(), left.workload.as_str())
                .cmp(&(right.domain.as_str(), right.workload.as_str()))
        });
        let expected_placements = runtime
            .placement_plans()
            .iter()
            .map(|placement| (placement.domain().as_str(), placement.workload()))
            .collect::<BTreeSet<_>>();
        let actual_placements = placements
            .iter()
            .map(|placement| (placement.domain.as_str(), placement.workload.as_str()))
            .collect::<BTreeSet<_>>();
        if expected_placements.len() != placements.len() || expected_placements != actual_placements
        {
            return Err(InventoryError::Placement);
        }

        Ok(Self {
            identity: observation::RuntimeInventoryIdentity::from_runtime_plan(runtime),
            build_metadata: None,
            domains: runtime
                .domain_plans()
                .iter()
                .map(|domain| domain.id())
                .collect(),
            activated_workflows,
            listeners: runtime
                .listener_plans()
                .iter()
                .map(|listener| ExpectedListener {
                    id: listener.id().to_owned(),
                    kind: listener.kind(),
                    auth: listener.auth(),
                })
                .collect(),
            provider_bindings,
            placements,
        })
    }

    /// Attach launch-supplied build metadata without coupling it to runtime/deployment identity.
    pub fn with_build_metadata(mut self, build_metadata: BuildMetadata) -> Self {
        self.build_metadata = Some(build_metadata);
        self
    }
}

struct InventoryState {
    seed: RuntimeInventorySeed,
    health: OnceLock<Arc<HealthReporter>>,
    listeners: OnceLock<Vec<BoundListenerObservation>>,
    placement_readiness: OnceLock<PlacementReadinessSampler>,
}

type LiveInventorySource = dyn Fn() -> Result<observation::RuntimeInventoryParts, observation::RuntimeInventoryReadFailure>
    + Send
    + Sync;

/// Cloneable live runtime-inventory reader.
///
/// Instances are issued only by [`inventory_channel`] or [`deferred_inventory_channel`]; the
/// source constructor is crate-private so assembly roots cannot replace runtime health evidence.
#[derive(Clone)]
pub struct InventoryReader(Arc<LiveInventorySource>);

impl InventoryReader {
    fn new(
        source: impl Fn() -> Result<
            observation::RuntimeInventoryParts,
            observation::RuntimeInventoryReadFailure,
        > + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(Arc::new(source))
    }

    /// Resample live listeners, health, and placement state and mint one opaque observation.
    pub fn read(
        &self,
    ) -> Result<observation::RuntimeInventoryObservation, observation::RuntimeInventoryReadFailure>
    {
        observation::RuntimeInventoryObservation::from_runtimeexec(
            (self.0)()?,
            runtimeinventorymint::RuntimeInventoryMint::capability(),
        )
    }
}

pub type PlacementReadinessSampler = Arc<dyn Fn() -> InventoryPlacementReadiness + Send + Sync>;

pub struct InventoryPublisher(Arc<InventoryState>);

pub struct InventoryHealthPublisher(Arc<InventoryState>);

pub struct InventoryPlacementReadinessPublisher(Arc<InventoryState>);

pub fn inventory_channel(
    seed: RuntimeInventorySeed,
    health: Arc<HealthReporter>,
) -> (InventoryPublisher, InventoryReader) {
    let state = Arc::new(InventoryState {
        seed,
        health: OnceLock::from(health),
        listeners: OnceLock::new(),
        placement_readiness: OnceLock::new(),
    });
    let reader_state = Arc::clone(&state);
    let reader = InventoryReader::new(move || read_parts(&reader_state));
    (InventoryPublisher(state), reader)
}

pub fn deferred_inventory_channel(
    seed: RuntimeInventorySeed,
) -> (
    InventoryPublisher,
    InventoryReader,
    InventoryHealthPublisher,
    InventoryPlacementReadinessPublisher,
) {
    let state = Arc::new(InventoryState {
        seed,
        health: OnceLock::new(),
        listeners: OnceLock::new(),
        placement_readiness: OnceLock::new(),
    });
    let reader_state = Arc::clone(&state);
    let reader = InventoryReader::new(move || read_parts(&reader_state));
    (
        InventoryPublisher(Arc::clone(&state)),
        reader,
        InventoryHealthPublisher(Arc::clone(&state)),
        InventoryPlacementReadinessPublisher(state),
    )
}

impl InventoryHealthPublisher {
    pub fn publish(self, health: Arc<HealthReporter>) -> Result<(), InventoryError> {
        self.0
            .health
            .set(health)
            .map_err(|_| InventoryError::AlreadyPublished)
    }
}

impl InventoryPlacementReadinessPublisher {
    pub fn publish(self, sampler: PlacementReadinessSampler) -> Result<(), InventoryError> {
        self.0
            .placement_readiness
            .set(sampler)
            .map_err(|_| InventoryError::AlreadyPublished)
    }
}

impl InventoryPublisher {
    pub fn publish(
        self,
        mut listeners: Vec<BoundListenerObservation>,
    ) -> Result<(), InventoryError> {
        listeners.sort_by(|left, right| left.id.cmp(&right.id));
        let mut expected = self.0.seed.listeners.iter().collect::<Vec<_>>();
        expected.sort_by(|left, right| left.id.cmp(&right.id));
        let exact = expected.len() == listeners.len()
            && expected.iter().zip(&listeners).all(|(expected, actual)| {
                expected.id == actual.id
                    && expected.kind == actual.kind
                    && expected.auth == actual.auth
            });
        if !exact {
            return Err(InventoryError::ListenerBinding);
        }
        self.0
            .listeners
            .set(listeners)
            .map_err(|_| InventoryError::AlreadyPublished)
    }
}

fn read_parts(
    state: &InventoryState,
) -> Result<observation::RuntimeInventoryParts, observation::RuntimeInventoryReadFailure> {
    let listeners = state
        .listeners
        .get()
        .ok_or(observation::RuntimeInventoryReadFailure::Unavailable)?;
    let health = state
        .health
        .get()
        .ok_or(observation::RuntimeInventoryReadFailure::Unavailable)?;
    let report = health.report();
    let checks = report
        .checks()
        .iter()
        .map(|check| (check.name().as_str(), check.status()))
        .collect::<BTreeMap<_, _>>();
    let provider_posture = state
        .seed
        .provider_bindings
        .iter()
        .map(|binding| {
            observation::RuntimeInventoryProviderPosture::new(
                binding.provider_id.clone(),
                provider_state(binding, &checks),
            )
        })
        .collect();
    let live_placement_readiness = state.placement_readiness.get().map(|sampler| sampler());
    let placements: Vec<PlacementObservation> = state
        .seed
        .placements
        .iter()
        .cloned()
        .map(|mut placement| {
            if placement.mode == InventoryPlacementMode::Remote
                && let Some(readiness) = live_placement_readiness
            {
                placement.readiness = readiness;
            }
            placement
        })
        .collect();
    Ok(observation::RuntimeInventoryParts::new(
        state.seed.identity.clone(),
        state.seed.build_metadata.as_ref().map(|metadata| {
            observation::RuntimeInventoryBuildMetadata::new(
                metadata.source_revision.clone(),
                metadata.image_digest.clone(),
            )
        }),
        state.seed.domains.clone(),
        state
            .seed
            .activated_workflows
            .iter()
            .map(workflow_observation)
            .collect(),
        listeners.iter().map(listener_observation).collect(),
        provider_posture,
        placements.iter().map(placement_observation).collect(),
    ))
}

fn provider_state(
    binding: &ProviderProbeBinding,
    checks: &BTreeMap<&str, HealthStatus>,
) -> observation::RuntimeInventoryProviderState {
    let ProviderProbeEvidence::Observed(probe_names) = &binding.evidence else {
        return observation::RuntimeInventoryProviderState::Unobserved;
    };
    let mut state = observation::RuntimeInventoryProviderState::Ready;
    for probe in &probe_names.0 {
        let Some(status) = checks.get(probe.as_str()) else {
            return observation::RuntimeInventoryProviderState::Unavailable;
        };
        state = match (state, status) {
            (_, HealthStatus::Unhealthy) => observation::RuntimeInventoryProviderState::Unavailable,
            (_, status) if !matches!(status, HealthStatus::Healthy | HealthStatus::Degraded) => {
                observation::RuntimeInventoryProviderState::Unavailable
            }
            (observation::RuntimeInventoryProviderState::Ready, HealthStatus::Degraded) => {
                observation::RuntimeInventoryProviderState::Degraded
            }
            (current, _) => current,
        };
    }
    state
}

fn endpoint_observation(
    scheme: InventoryEndpointScheme,
    host: &str,
    port: u16,
) -> observation::RuntimeInventoryEndpoint {
    observation::RuntimeInventoryEndpoint::new(
        match scheme {
            InventoryEndpointScheme::Http => observation::RuntimeInventoryEndpointScheme::Http,
            InventoryEndpointScheme::Https => observation::RuntimeInventoryEndpointScheme::Https,
        },
        host.to_owned(),
        port,
    )
}

fn workflow_observation(
    workflow: &ActivatedWorkflowObservation,
) -> observation::RuntimeInventoryActivatedWorkflow {
    match &workflow.shape {
        ActivatedWorkflowObservationShape::ProjectionCapture => {
            observation::RuntimeInventoryActivatedWorkflow::capture_only_projection(
                workflow.id.clone(),
                workflow.definition_version.clone(),
                workflow.definition_schema_digest.clone(),
            )
        }
        ActivatedWorkflowObservationShape::ProjectionExecuting {
            activation,
            execution,
        } => {
            let activation = match activation {
                InventoryExecutingProjectionActivation::Shadow => {
                    observation::RuntimeInventoryExecutingProjectionActivation::Shadow
                }
                InventoryExecutingProjectionActivation::Active => {
                    observation::RuntimeInventoryExecutingProjectionActivation::Active
                }
            };
            projection_workflow_observation(workflow, activation, execution)
        }
        ActivatedWorkflowObservationShape::SagaActive => {
            observation::RuntimeInventoryActivatedWorkflow::active_saga(
                workflow.id.clone(),
                workflow.definition_version.clone(),
                workflow.definition_schema_digest.clone(),
            )
        }
    }
}

fn projection_workflow_observation(
    workflow: &ActivatedWorkflowObservation,
    activation: observation::RuntimeInventoryExecutingProjectionActivation,
    execution: &eventexec::ProjectionExecutionObservation,
) -> observation::RuntimeInventoryActivatedWorkflow {
    observation::RuntimeInventoryActivatedWorkflow::executing_projection(
        workflow.id.clone(),
        workflow.definition_version.clone(),
        workflow.definition_schema_digest.clone(),
        activation,
        observation::RuntimeInventoryProjectionExecution::new(
            execution.target_generation().as_str().to_owned(),
            projection_worker_status(execution.status()),
        ),
    )
}

fn projection_worker_status(
    status: eventexec::ProjectionWorkerStatus,
) -> observation::RuntimeInventoryProjectionWorkerStatus {
    use eventexec::ProjectionWorkerStatus as Source;
    use observation::RuntimeInventoryProjectionWorkerStatus as Target;
    match status {
        Source::Starting => Target::Starting,
        Source::Healthy {
            selected_generation,
            max_lag,
        } => Target::Healthy {
            selected_generation: selected_generation_observation(selected_generation),
            max_lag,
        },
        Source::Retryable {
            selected_generation,
            max_lag,
            reasons,
        } => Target::Retryable {
            selected_generation: selected_generation_observation(selected_generation),
            max_lag,
            reasons: retryable_posture_observation(reasons),
        },
        Source::Quarantined {
            selected_generation,
            max_lag,
            reasons,
        } => Target::Quarantined {
            selected_generation: selected_generation_observation(selected_generation),
            max_lag,
            reasons: quarantine_posture_observation(reasons),
        },
        Source::Mixed {
            selected_generation,
            max_lag,
            retryable_reasons,
            quarantine_reasons,
        } => Target::Mixed {
            selected_generation: selected_generation_observation(selected_generation),
            max_lag,
            retryable_reasons: retryable_posture_observation(retryable_reasons),
            quarantine_reasons: quarantine_posture_observation(quarantine_reasons),
        },
        Source::Unavailable(reason) => Target::Unavailable(match reason {
            eventexec::ProjectionUnavailableReason::StartupObservation => {
                observation::RuntimeInventoryUnavailableReason::StartupObservation
            }
            eventexec::ProjectionUnavailableReason::SweepIncomplete => {
                observation::RuntimeInventoryUnavailableReason::SweepIncomplete
            }
            eventexec::ProjectionUnavailableReason::TenantObservation => {
                observation::RuntimeInventoryUnavailableReason::TenantObservation
            }
        }),
        Source::Stopped(reason) => Target::Stopped(stopped_reason_observation(reason)),
    }
}

fn selected_generation_observation(
    value: eventexec::ProjectionSelectedGeneration,
) -> observation::RuntimeInventorySelectedGeneration {
    match value {
        eventexec::ProjectionSelectedGeneration::None => {
            observation::RuntimeInventorySelectedGeneration::None
        }
        eventexec::ProjectionSelectedGeneration::Uniform(generation) => {
            observation::RuntimeInventorySelectedGeneration::Uniform(generation.as_str().to_owned())
        }
        eventexec::ProjectionSelectedGeneration::Mixed => {
            observation::RuntimeInventorySelectedGeneration::Mixed
        }
    }
}

fn retryable_posture_observation(
    value: eventexec::ProjectionReasonPosture<eventexec::ProjectionRetryableReason>,
) -> observation::RuntimeInventoryReasonPosture<observation::RuntimeInventoryRetryableReason> {
    match value {
        eventexec::ProjectionReasonPosture::Mixed => {
            observation::RuntimeInventoryReasonPosture::Mixed
        }
        eventexec::ProjectionReasonPosture::Uniform(reason) => {
            observation::RuntimeInventoryReasonPosture::Uniform(match reason {
                eventexec::ProjectionRetryableReason::CheckpointUnread => {
                    observation::RuntimeInventoryRetryableReason::CheckpointUnread
                }
                eventexec::ProjectionRetryableReason::CheckpointUnsaved => {
                    observation::RuntimeInventoryRetryableReason::CheckpointUnsaved
                }
                eventexec::ProjectionRetryableReason::DeadLetterUnsaved => {
                    observation::RuntimeInventoryRetryableReason::DeadLetterUnsaved
                }
                eventexec::ProjectionRetryableReason::ApplyTransient => {
                    observation::RuntimeInventoryRetryableReason::ApplyTransient
                }
                eventexec::ProjectionRetryableReason::CommitUnknown => {
                    observation::RuntimeInventoryRetryableReason::CommitUnknown
                }
                eventexec::ProjectionRetryableReason::SourceTransient => {
                    observation::RuntimeInventoryRetryableReason::SourceTransient
                }
                eventexec::ProjectionRetryableReason::QuarantinePersistence => {
                    observation::RuntimeInventoryRetryableReason::QuarantinePersistence
                }
            })
        }
    }
}

fn quarantine_posture_observation(
    value: eventexec::ProjectionReasonPosture<eventexec::ProjectionQuarantineReason>,
) -> observation::RuntimeInventoryReasonPosture<observation::RuntimeInventoryQuarantineReason> {
    use eventexec::ProjectionQuarantineReason as Source;
    use observation::RuntimeInventoryQuarantineReason as Target;
    match value {
        eventexec::ProjectionReasonPosture::Mixed => {
            observation::RuntimeInventoryReasonPosture::Mixed
        }
        eventexec::ProjectionReasonPosture::Uniform(reason) => {
            observation::RuntimeInventoryReasonPosture::Uniform(match reason {
                Source::TargetDefinitionDrift => Target::TargetDefinitionDrift,
                Source::InputBindingDrift => Target::InputBindingDrift,
                Source::TenantDrift => Target::TenantDrift,
                Source::PayloadMalformed => Target::PayloadMalformed,
                Source::PayloadValueInvalid => Target::PayloadValueInvalid,
                Source::VersionRegression => Target::VersionRegression,
                Source::ProviderInvariant => Target::ProviderInvariant,
                Source::ProviderPermanent => Target::ProviderPermanent,
                Source::Conflict => Target::Conflict,
                Source::ApplyOutOfOrder => Target::ApplyOutOfOrder,
                Source::RollbackFailed => Target::RollbackFailed,
                Source::SourceOutOfOrder => Target::SourceOutOfOrder,
            })
        }
    }
}

fn stopped_reason_observation(
    reason: eventexec::ProjectionStoppedReason,
) -> observation::RuntimeInventoryStoppedReason {
    use eventexec::ProjectionStoppedReason as Source;
    use observation::RuntimeInventoryStoppedReason as Target;
    match reason {
        Source::RuntimeBuildFailed => Target::RuntimeBuildFailed,
        Source::WorkerPanicked => Target::WorkerPanicked,
        Source::TenantCatalogUnavailable => Target::TenantCatalogUnavailable,
        Source::SelectedGenerationUnavailable => Target::SelectedGenerationUnavailable,
        Source::SelectedGenerationIdentityInvalid => Target::SelectedGenerationIdentityInvalid,
        Source::InvalidTenant => Target::InvalidTenant,
        Source::TenantQuarantineUnavailable => Target::TenantQuarantineUnavailable,
        Source::StartupSourceUnavailable => Target::StartupSourceUnavailable,
        Source::ProjectionOutcomeInvalid => Target::ProjectionOutcomeInvalid,
        Source::CoordinateOverflow => Target::CoordinateOverflow,
        Source::TargetConfigInvalid => Target::TargetConfigInvalid,
    }
}

fn listener_observation(
    listener: &BoundListenerObservation,
) -> observation::RuntimeInventoryListener {
    observation::RuntimeInventoryListener::new(
        listener.id.clone(),
        listener.kind,
        listener.auth,
        endpoint_observation(
            listener.endpoint.scheme,
            &listener.endpoint.host,
            listener.endpoint.port,
        ),
    )
}

fn placement_observation(
    placement: &PlacementObservation,
) -> observation::RuntimeInventoryPlacement {
    observation::RuntimeInventoryPlacement::new(
        placement.domain,
        placement.workload.clone(),
        match placement.mode {
            InventoryPlacementMode::Local => observation::RuntimeInventoryPlacementMode::Local,
            InventoryPlacementMode::Remote => observation::RuntimeInventoryPlacementMode::Remote,
        },
        placement
            .endpoint
            .as_ref()
            .map(|endpoint| endpoint_observation(endpoint.scheme, &endpoint.host, endpoint.port)),
        placement.spiffe_identity.clone(),
        match placement.readiness {
            InventoryPlacementReadiness::Ready => {
                observation::RuntimeInventoryPlacementReadiness::Ready
            }
            InventoryPlacementReadiness::MtlsSourceUnavailable => {
                observation::RuntimeInventoryPlacementReadiness::MtlsSourceUnavailable
            }
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    #[error("runtime inventory build metadata is invalid")]
    BuildMetadata,
    #[error("runtime inventory provider binding is invalid")]
    ProviderBinding,
    #[error("runtime inventory provider receipt came from another runtime plan")]
    ProviderPlanSource,
    #[error("runtime inventory activated workflow is invalid")]
    ActivatedWorkflow,
    #[error("runtime inventory activated workflows came from another runtime plan")]
    WorkflowPlanSource,
    #[error("runtime inventory listener binding is invalid")]
    ListenerBinding,
    #[error("runtime inventory placement is invalid")]
    Placement,
    #[error("runtime inventory endpoint is invalid")]
    Endpoint,
    #[error("runtime inventory was already published")]
    AlreadyPublished,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_metadata_is_closed() {
        assert!(
            BuildMetadata::parse(&"a".repeat(40), &format!("sha256:{}", "b".repeat(64))).is_ok()
        );
        assert!(
            BuildMetadata::parse(&"a".repeat(64), &format!("sha256:{}", "b".repeat(64))).is_ok()
        );
        for (revision, digest) in [
            ("A".repeat(40), format!("sha256:{}", "b".repeat(64))),
            ("a".repeat(39), format!("sha256:{}", "b".repeat(64))),
            ("a".repeat(40), format!("sha256:{}", "B".repeat(64))),
            ("a".repeat(40), "sha256:short".to_owned()),
        ] {
            assert_eq!(
                BuildMetadata::parse(&revision, &digest),
                Err(InventoryError::BuildMetadata)
            );
        }
    }
}
