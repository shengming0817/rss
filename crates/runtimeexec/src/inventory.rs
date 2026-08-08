//! Provider-independent, non-serializable runtime inventory observation model.

use assembly_schema::{AssemblyDomain, AssemblyListenerKind, ListenerAuth, RuntimePlan};
use bootstrap::HealthReporter;
use primitives::{HealthStatus, ProbeName};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

const SCHEMA_VERSION: u32 = 1;

/// Build metadata declared to the process by its launch environment.
///
/// The image digest cannot be self-proven by a binary embedded in that image. This value is
/// therefore reportable metadata, not an OCI/SLSA verification receipt, and is deliberately never
/// joined to an external delivery plan or workload identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildMetadata {
    source_revision: String,
    image_digest: String,
}

impl BuildMetadata {
    pub fn parse(source_revision: &str, image_digest: &str) -> Result<Self, InventoryError> {
        if !matches!(source_revision.len(), 40 | 64) || !is_lower_hex(source_revision) {
            return Err(InventoryError::BuildMetadata);
        }
        if image_digest.len() != 71
            || !image_digest.starts_with("sha256:")
            || !is_lower_hex(&image_digest[7..])
        {
            return Err(InventoryError::BuildMetadata);
        }
        Ok(Self {
            source_revision: source_revision.to_owned(),
            image_digest: image_digest.to_owned(),
        })
    }

    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    pub fn image_digest(&self) -> &str {
        &self.image_digest
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
    probe_names: Vec<ProbeName>,
}

/// A workflow activation copied from the sealed workflow runtime plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedWorkflowObservation {
    id: String,
    definition_version: String,
    definition_schema_digest: String,
    activation: InventoryWorkflowActivation,
}

impl ActivatedWorkflowObservation {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    pub fn definition_schema_digest(&self) -> &str {
        &self.definition_schema_digest
    }

    pub const fn activation(&self) -> InventoryWorkflowActivation {
        self.activation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryWorkflowActivation {
    Projection(InventoryProjectionActivation),
    Saga(InventorySagaActivation),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryProjectionActivation {
    CaptureOnly,
    Shadow,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventorySagaActivation {
    Active,
}

impl ProviderProbeBinding {
    pub fn new(
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
            probe_names,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn probe_names(&self) -> &[ProbeName] {
        &self.probe_names
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
    assembly_fingerprint: String,
    build_metadata: Option<BuildMetadata>,
    runtime_plan_fingerprint: String,
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
        mut provider_bindings: Vec<ProviderProbeBinding>,
        mut placements: Vec<PlacementObservation>,
    ) -> Result<Self, InventoryError> {
        if activated_workflows.source_runtime_plan_fingerprint()
            != runtime.runtime_plan_fingerprint().as_str()
        {
            return Err(InventoryError::WorkflowPlanSource);
        }
        let activated_workflows = activated_workflows
            .workflows()
            .iter()
            .map(|workflow| {
                let activation = match workflow.activation() {
                    eventexec::ActivatedWorkflowActivation::Projection(
                        assembly_schema::ProjectionActivation::CaptureOnly,
                    ) => InventoryWorkflowActivation::Projection(
                        InventoryProjectionActivation::CaptureOnly,
                    ),
                    eventexec::ActivatedWorkflowActivation::Projection(
                        assembly_schema::ProjectionActivation::Shadow,
                    ) => InventoryWorkflowActivation::Projection(
                        InventoryProjectionActivation::Shadow,
                    ),
                    eventexec::ActivatedWorkflowActivation::Projection(
                        assembly_schema::ProjectionActivation::Active,
                    ) => InventoryWorkflowActivation::Projection(
                        InventoryProjectionActivation::Active,
                    ),
                    eventexec::ActivatedWorkflowActivation::Saga(
                        assembly_schema::SagaActivation::Active,
                    ) => InventoryWorkflowActivation::Saga(InventorySagaActivation::Active),
                    eventexec::ActivatedWorkflowActivation::Projection(
                        assembly_schema::ProjectionActivation::Disabled,
                    )
                    | eventexec::ActivatedWorkflowActivation::Saga(
                        assembly_schema::SagaActivation::Disabled,
                    ) => return Err(InventoryError::ActivatedWorkflow),
                };
                Ok(ActivatedWorkflowObservation {
                    id: workflow.id().to_owned(),
                    definition_version: workflow.definition_version().to_owned(),
                    definition_schema_digest: workflow.definition_schema_digest().to_owned(),
                    activation,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        provider_bindings.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
        let expected_providers = runtime
            .provider_plans()
            .iter()
            .map(|provider| provider.id())
            .collect::<BTreeSet<_>>();
        let actual_providers = provider_bindings
            .iter()
            .map(ProviderProbeBinding::provider_id)
            .collect::<BTreeSet<_>>();
        if expected_providers.len() != provider_bindings.len()
            || expected_providers != actual_providers
        {
            return Err(InventoryError::ProviderBinding);
        }

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
            assembly_fingerprint: runtime.assembly_fingerprint().as_str().to_owned(),
            build_metadata: None,
            runtime_plan_fingerprint: runtime.runtime_plan_fingerprint().as_str().to_owned(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InventoryProviderState {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPosture {
    id: String,
    state: InventoryProviderState,
}

impl ProviderPosture {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn state(&self) -> InventoryProviderState {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventorySnapshot {
    schema_version: u32,
    assembly_fingerprint: String,
    build_metadata: Option<BuildMetadata>,
    runtime_plan_fingerprint: String,
    domains: Vec<AssemblyDomain>,
    activated_workflows: Vec<ActivatedWorkflowObservation>,
    listeners: Vec<BoundListenerObservation>,
    provider_posture: Vec<ProviderPosture>,
    placements: Vec<PlacementObservation>,
}

impl RuntimeInventorySnapshot {
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn assembly_fingerprint(&self) -> &str {
        &self.assembly_fingerprint
    }
    pub fn build_metadata(&self) -> Option<&BuildMetadata> {
        self.build_metadata.as_ref()
    }
    pub fn runtime_plan_fingerprint(&self) -> &str {
        &self.runtime_plan_fingerprint
    }
    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.domains
    }
    pub fn activated_workflows(&self) -> &[ActivatedWorkflowObservation] {
        &self.activated_workflows
    }
    pub fn listeners(&self) -> &[BoundListenerObservation] {
        &self.listeners
    }
    pub fn provider_posture(&self) -> &[ProviderPosture] {
        &self.provider_posture
    }
    pub fn placements(&self) -> &[PlacementObservation] {
        &self.placements
    }
}

struct InventoryState {
    seed: RuntimeInventorySeed,
    health: OnceLock<Arc<HealthReporter>>,
    listeners: OnceLock<Vec<BoundListenerObservation>>,
    placement_readiness: OnceLock<PlacementReadinessSampler>,
}

pub type PlacementReadinessSampler = Arc<dyn Fn() -> InventoryPlacementReadiness + Send + Sync>;

pub struct InventoryPublisher(Arc<InventoryState>);

pub struct InventoryHealthPublisher(Arc<InventoryState>);

pub struct InventoryPlacementReadinessPublisher(Arc<InventoryState>);

#[derive(Clone)]
pub struct InventoryReader(Arc<InventoryState>);

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
    (
        InventoryPublisher(Arc::clone(&state)),
        InventoryReader(state),
    )
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
    (
        InventoryPublisher(Arc::clone(&state)),
        InventoryReader(Arc::clone(&state)),
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

impl InventoryReader {
    pub fn read(&self) -> Result<RuntimeInventorySnapshot, InventoryError> {
        let listeners = self.0.listeners.get().ok_or(InventoryError::Unavailable)?;
        let health = self.0.health.get().ok_or(InventoryError::Unavailable)?;
        let report = health.report();
        let checks = report
            .checks()
            .iter()
            .map(|check| (check.name().as_str(), check.status()))
            .collect::<BTreeMap<_, _>>();
        let provider_posture = self
            .0
            .seed
            .provider_bindings
            .iter()
            .map(|binding| ProviderPosture {
                id: binding.provider_id.clone(),
                state: provider_state(binding, &checks),
            })
            .collect();
        let live_placement_readiness = self.0.placement_readiness.get().map(|sampler| sampler());
        let placements = self
            .0
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
        Ok(RuntimeInventorySnapshot {
            schema_version: SCHEMA_VERSION,
            assembly_fingerprint: self.0.seed.assembly_fingerprint.clone(),
            build_metadata: self.0.seed.build_metadata.clone(),
            runtime_plan_fingerprint: self.0.seed.runtime_plan_fingerprint.clone(),
            domains: self.0.seed.domains.clone(),
            activated_workflows: self.0.seed.activated_workflows.clone(),
            listeners: listeners.clone(),
            provider_posture,
            placements,
        })
    }
}

fn provider_state(
    binding: &ProviderProbeBinding,
    checks: &BTreeMap<&str, HealthStatus>,
) -> InventoryProviderState {
    if binding.probe_names.is_empty() {
        return InventoryProviderState::Ready;
    }
    let mut state = InventoryProviderState::Ready;
    for probe in &binding.probe_names {
        let Some(status) = checks.get(probe.as_str()) else {
            return InventoryProviderState::Unavailable;
        };
        state = state.max(match status {
            HealthStatus::Healthy => InventoryProviderState::Ready,
            HealthStatus::Degraded => InventoryProviderState::Degraded,
            HealthStatus::Unhealthy => InventoryProviderState::Unavailable,
            _ => InventoryProviderState::Unavailable,
        });
    }
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    #[error("runtime inventory build metadata is invalid")]
    BuildMetadata,
    #[error("runtime inventory provider binding is invalid")]
    ProviderBinding,
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
    #[error("runtime inventory is unavailable")]
    Unavailable,
    #[error("runtime inventory was already published")]
    AlreadyPublished,
}

#[cfg(test)]
mod tests {
    use super::*;
    use assembly_schema::{ParsedAssemblyLock, ParsedRuntimePlan, RepositoryAssemblyManifestV2};
    use bootstrap::{HealthProbe, Registry};
    use primitives::{HealthCheck, ProbeName};
    use std::error::Error;
    use std::sync::atomic::{AtomicU8, Ordering};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn runtime_plan() -> TestResult<ParsedRuntimePlan> {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("runtimeexec repository root")?;
        let source = RepositoryAssemblyManifestV2::discover_v2(
            repository_root,
            &repository_root.join("assemblies/identityaudit"),
        )?;
        let lock = ParsedAssemblyLock::from_json_slice(include_bytes!(
            "../../../assemblies/identityaudit/assembly.lock.json"
        ))?
        .verify_repository_v2(&source)?
        .into_executable();
        Ok(ParsedRuntimePlan::from_json_slice_bound(
            include_bytes!("../../../assemblies/identityaudit/runtime-plan.json"),
            source.canonical(),
            &lock,
        )?)
    }

    fn workflow_runtime(runtime: &ParsedRuntimePlan) -> TestResult<eventexec::WorkflowRuntimePlan> {
        Ok(
            eventexec::WorkflowActivationPlan::select(runtime.as_plan())?
                .bind(std::iter::empty(), std::iter::empty())?,
        )
    }

    fn alternate_runtime_plan() -> TestResult<ParsedRuntimePlan> {
        let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("runtimeexec repository root")?;
        let source = RepositoryAssemblyManifestV2::discover_v2(
            repository_root,
            &repository_root.join("assemblies/runtime"),
        )?;
        let lock = ParsedAssemblyLock::from_json_slice(include_bytes!(
            "../../../assemblies/runtime/assembly.lock.json"
        ))?
        .verify_repository_v2(&source)?
        .into_executable();
        Ok(ParsedRuntimePlan::from_json_slice_bound(
            include_bytes!("../../../assemblies/runtime/runtime-plan.json"),
            source.canonical(),
            &lock,
        )?)
    }

    struct FixedProbe(ProbeName, HealthStatus);
    impl HealthProbe for FixedProbe {
        fn check(&self) -> HealthCheck {
            HealthCheck::new(self.0.clone(), self.1, "test")
        }
    }

    fn reporter(status: HealthStatus) -> TestResult<Arc<HealthReporter>> {
        let mut registry = Registry::new();
        let name = ProbeName::parse("provider-health")?;
        registry.probe(name.clone(), Box::new(FixedProbe(name, status)))?;
        Ok(Arc::new(registry.take_health_reporter()))
    }

    struct MutableProbe(ProbeName, Arc<AtomicU8>);
    impl HealthProbe for MutableProbe {
        fn check(&self) -> HealthCheck {
            let status = match self.1.load(Ordering::SeqCst) {
                0 => HealthStatus::Healthy,
                1 => HealthStatus::Degraded,
                _ => HealthStatus::Unhealthy,
            };
            HealthCheck::new(self.0.clone(), status, "mutable test")
        }
    }

    fn mutable_reporter() -> TestResult<(Arc<HealthReporter>, Arc<AtomicU8>, ProbeName)> {
        let state = Arc::new(AtomicU8::new(0));
        let name = ProbeName::parse("provider-health")?;
        let mut registry = Registry::new();
        registry.probe(
            name.clone(),
            Box::new(MutableProbe(name.clone(), Arc::clone(&state))),
        )?;
        Ok((Arc::new(registry.take_health_reporter()), state, name))
    }

    fn exact_seed(
        runtime: &ParsedRuntimePlan,
        probe: Option<ProbeName>,
    ) -> TestResult<RuntimeInventorySeed> {
        let providers = runtime
            .provider_plans()
            .iter()
            .enumerate()
            .map(|(index, provider)| {
                ProviderProbeBinding::new(
                    provider.id(),
                    if index == 0 {
                        probe.clone().into_iter().collect()
                    } else {
                        Vec::new()
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let placements = runtime
            .placement_plans()
            .iter()
            .map(|placement| PlacementObservation::local(placement.domain(), placement.workload()))
            .collect();
        let workflow_runtime = workflow_runtime(runtime)?;
        Ok(RuntimeInventorySeed::from_runtime_plan(
            runtime.as_plan(),
            workflow_runtime.activated_workflows(),
            providers,
            placements,
        )?
        .with_build_metadata(BuildMetadata::parse(
            &"a".repeat(40),
            &format!("sha256:{}", "b".repeat(64)),
        )?))
    }

    #[test]
    fn inventory_build_metadata_is_closed_and_reported_without_deployment_join() -> TestResult {
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

        let runtime = runtime_plan()?;
        let seed = exact_seed(&runtime, None)?;
        let (publisher, reader) = inventory_channel(seed, reporter(HealthStatus::Healthy)?);
        publisher.publish(exact_listeners(&runtime)?)?;
        let metadata = reader
            .read()?
            .build_metadata()
            .ok_or("fixture build metadata")?
            .clone();
        assert_eq!(metadata.source_revision(), "a".repeat(40));
        assert_eq!(
            metadata.image_digest(),
            format!("sha256:{}", "b".repeat(64))
        );
        Ok(())
    }

    fn exact_listeners(runtime: &ParsedRuntimePlan) -> TestResult<Vec<BoundListenerObservation>> {
        runtime
            .listener_plans()
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                let port = 10_000 + u16::try_from(index)?;
                Ok(BoundListenerObservation::from_bound(
                    listener.id(),
                    listener.kind(),
                    listener.auth(),
                    InventoryEndpointScheme::Http,
                    format!("127.0.0.1:{port}").parse()?,
                ))
            })
            .collect()
    }

    #[test]
    fn inventory_provider_state_is_dynamic_and_missing_is_unavailable() -> TestResult {
        let binding =
            ProviderProbeBinding::new("provider", vec![ProbeName::parse("provider-health")?])?;
        let healthy = BTreeMap::from([("provider-health", HealthStatus::Healthy)]);
        let degraded = BTreeMap::from([("provider-health", HealthStatus::Degraded)]);
        let unhealthy = BTreeMap::from([("provider-health", HealthStatus::Unhealthy)]);
        assert_eq!(
            provider_state(&binding, &healthy),
            InventoryProviderState::Ready
        );
        assert_eq!(
            provider_state(&binding, &degraded),
            InventoryProviderState::Degraded
        );
        assert_eq!(
            provider_state(&binding, &unhealthy),
            InventoryProviderState::Unavailable
        );
        assert_eq!(
            provider_state(&binding, &BTreeMap::new()),
            InventoryProviderState::Unavailable
        );
        let no_probe = ProviderProbeBinding::new("provider", Vec::new())?;
        assert_eq!(
            provider_state(&no_probe, &BTreeMap::new()),
            InventoryProviderState::Ready
        );
        Ok(())
    }

    #[test]
    fn inventory_listener_publication_requires_exact_runtime_join() -> TestResult {
        let make = || -> TestResult<_> {
            let runtime = runtime_plan()?;
            let seed = exact_seed(&runtime, None)?;
            let listeners = exact_listeners(&runtime)?;
            Ok((runtime, seed, listeners))
        };

        let (_, seed, mut missing) = make()?;
        missing.pop().ok_or("fixture must contain listeners")?;
        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(missing),
            Err(InventoryError::ListenerBinding)
        );

        let (_, seed, mut duplicate) = make()?;
        duplicate.push(duplicate[0].clone());
        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(duplicate),
            Err(InventoryError::ListenerBinding)
        );

        let (_, seed, mut extra) = make()?;
        extra.push(BoundListenerObservation::from_bound(
            "extra-listener",
            AssemblyListenerKind::Admin,
            ListenerAuth::NoAuth,
            InventoryEndpointScheme::Https,
            "127.0.0.1:9999".parse()?,
        ));
        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(extra),
            Err(InventoryError::ListenerBinding)
        );

        let (_, seed, mut wrong_kind) = make()?;
        wrong_kind[0].kind = AssemblyListenerKind::Internal;
        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(wrong_kind),
            Err(InventoryError::ListenerBinding)
        );

        let (_, seed, mut wrong_auth) = make()?;
        wrong_auth[0].auth = ListenerAuth::ServiceToken;
        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(wrong_auth),
            Err(InventoryError::ListenerBinding)
        );

        let (runtime, seed, mut exact) = make()?;
        assert!(exact.len() >= 3, "fixture must exercise an exact set");
        exact.reverse();
        let (publisher, reader) = inventory_channel(seed, reporter(HealthStatus::Healthy)?);
        publisher.publish(exact)?;
        let snapshot = reader.read()?;
        assert_eq!(snapshot.listeners().len(), runtime.listener_plans().len());
        assert!(
            snapshot
                .listeners()
                .windows(2)
                .all(|pair| pair[0].id() < pair[1].id())
        );
        Ok(())
    }

    #[test]
    fn inventory_reader_recomputes_provider_posture_on_each_request() -> TestResult {
        let runtime = runtime_plan()?;
        let (health, state, probe) = mutable_reporter()?;
        let seed = exact_seed(&runtime, Some(probe))?;
        let (publisher, reader) = inventory_channel(seed, health);
        publisher.publish(exact_listeners(&runtime)?)?;

        assert_eq!(
            reader.read()?.provider_posture()[0].state(),
            InventoryProviderState::Ready
        );
        state.store(1, Ordering::SeqCst);
        assert_eq!(
            reader.read()?.provider_posture()[0].state(),
            InventoryProviderState::Degraded
        );
        state.store(2, Ordering::SeqCst);
        assert_eq!(
            reader.read()?.provider_posture()[0].state(),
            InventoryProviderState::Unavailable
        );
        Ok(())
    }

    #[test]
    fn inventory_reader_recomputes_remote_placement_on_each_request() -> TestResult {
        let runtime = runtime_plan()?;
        let mut seed = exact_seed(&runtime, None)?;
        let placement = seed
            .placements
            .first_mut()
            .ok_or("fixture must contain a placement")?;
        placement.mode = InventoryPlacementMode::Remote;
        placement.readiness = InventoryPlacementReadiness::MtlsSourceUnavailable;
        let listeners = exact_listeners(&runtime)?;
        let readiness = Arc::new(AtomicU8::new(0));
        let sampled = Arc::clone(&readiness);
        let (publisher, reader, health_publisher, placement_publisher) =
            deferred_inventory_channel(seed);
        health_publisher.publish(reporter(HealthStatus::Healthy)?)?;
        placement_publisher.publish(Arc::new(move || {
            if sampled.load(Ordering::Acquire) == 0 {
                InventoryPlacementReadiness::MtlsSourceUnavailable
            } else {
                InventoryPlacementReadiness::Ready
            }
        }))?;
        publisher.publish(listeners)?;

        assert_eq!(
            reader.read()?.placements()[0].readiness(),
            InventoryPlacementReadiness::MtlsSourceUnavailable
        );
        readiness.store(1, Ordering::Release);
        assert_eq!(
            reader.read()?.placements()[0].readiness(),
            InventoryPlacementReadiness::Ready
        );
        Ok(())
    }

    #[test]
    fn inventory_provider_bindings_require_exact_ids_and_allow_explicit_shared_probes() -> TestResult
    {
        let runtime = runtime_plan()?;
        let workflow_runtime = workflow_runtime(&runtime)?;
        let placements = || {
            runtime
                .placement_plans()
                .iter()
                .map(|placement| {
                    PlacementObservation::local(placement.domain(), placement.workload())
                })
                .collect::<Vec<_>>()
        };
        let mut bindings = runtime
            .provider_plans()
            .iter()
            .map(|provider| ProviderProbeBinding::new(provider.id(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let missing = bindings.pop().ok_or("fixture must contain a provider")?;
        assert_eq!(
            RuntimeInventorySeed::from_runtime_plan(
                runtime.as_plan(),
                workflow_runtime.activated_workflows(),
                bindings.clone(),
                placements(),
            )
            .err(),
            Some(InventoryError::ProviderBinding)
        );
        let mut duplicate = bindings.clone();
        duplicate.push(missing.clone());
        duplicate.push(missing.clone());
        assert_eq!(
            RuntimeInventorySeed::from_runtime_plan(
                runtime.as_plan(),
                workflow_runtime.activated_workflows(),
                duplicate,
                placements(),
            )
            .err(),
            Some(InventoryError::ProviderBinding)
        );
        bindings.push(ProviderProbeBinding::new("unknown-provider", Vec::new())?);
        assert_eq!(
            RuntimeInventorySeed::from_runtime_plan(
                runtime.as_plan(),
                workflow_runtime.activated_workflows(),
                bindings,
                placements(),
            )
            .err(),
            Some(InventoryError::ProviderBinding)
        );

        let shared = ProbeName::parse("shared-provider-health")?;
        let exact = runtime
            .provider_plans()
            .iter()
            .map(|provider| ProviderProbeBinding::new(provider.id(), vec![shared.clone()]))
            .collect::<Result<Vec<_>, _>>()?;
        RuntimeInventorySeed::from_runtime_plan(
            runtime.as_plan(),
            workflow_runtime.activated_workflows(),
            exact,
            placements(),
        )?;
        Ok(())
    }

    #[test]
    fn inventory_reader_is_unavailable_before_exact_listener_publication() -> TestResult {
        let runtime = runtime_plan()?;
        let workflow_runtime = workflow_runtime(&runtime)?;
        let providers = runtime
            .provider_plans()
            .iter()
            .map(|provider| ProviderProbeBinding::new(provider.id(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let placements = runtime
            .placement_plans()
            .iter()
            .map(|placement| PlacementObservation::local(placement.domain(), placement.workload()))
            .collect();
        let seed = RuntimeInventorySeed::from_runtime_plan(
            runtime.as_plan(),
            workflow_runtime.activated_workflows(),
            providers,
            placements,
        )?;
        let (publisher, reader) = inventory_channel(seed, reporter(HealthStatus::Healthy)?);
        assert!(matches!(reader.read(), Err(InventoryError::Unavailable)));
        let listeners = exact_listeners(&runtime)?;
        publisher.publish(listeners)?;
        let snapshot = reader.read()?;
        assert_eq!(snapshot.schema_version(), 1);
        assert_eq!(snapshot.listeners().len(), runtime.listener_plans().len());
        assert_eq!(
            snapshot.provider_posture().len(),
            runtime.provider_plans().len()
        );
        Ok(())
    }

    #[test]
    fn inventory_copies_the_sealed_activated_workflow_view() -> TestResult {
        let runtime = runtime_plan()?;
        let workflow_runtime = workflow_runtime(&runtime)?;
        let providers = runtime
            .provider_plans()
            .iter()
            .map(|provider| ProviderProbeBinding::new(provider.id(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let placements = runtime
            .placement_plans()
            .iter()
            .map(|placement| PlacementObservation::local(placement.domain(), placement.workload()))
            .collect();
        let seed = RuntimeInventorySeed::from_runtime_plan(
            runtime.as_plan(),
            workflow_runtime.activated_workflows(),
            providers,
            placements,
        )?;
        let (publisher, reader) = inventory_channel(seed, reporter(HealthStatus::Healthy)?);
        publisher.publish(exact_listeners(&runtime)?)?;

        assert!(reader.read()?.activated_workflows().is_empty());
        Ok(())
    }

    #[test]
    fn inventory_rejects_activated_workflows_from_another_runtime_plan() -> TestResult {
        let runtime = runtime_plan()?;
        let other_runtime = alternate_runtime_plan()?;
        let other_workflows = workflow_runtime(&other_runtime)?;
        let providers = runtime
            .provider_plans()
            .iter()
            .map(|provider| ProviderProbeBinding::new(provider.id(), Vec::new()))
            .collect::<Result<Vec<_>, _>>()?;
        let placements = runtime
            .placement_plans()
            .iter()
            .map(|placement| PlacementObservation::local(placement.domain(), placement.workload()))
            .collect();

        assert!(
            RuntimeInventorySeed::from_runtime_plan(
                runtime.as_plan(),
                other_workflows.activated_workflows(),
                providers,
                placements,
            )
            .is_err(),
            "inventory must reject activated workflows compiled from another runtime plan"
        );
        Ok(())
    }
}
