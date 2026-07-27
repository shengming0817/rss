//! Provider-independent, non-serializable runtime inventory observation model.

use assembly_schema::{
    AssemblyDomain, AssemblyListenerKind, ListenerAuth, ParsedDeploymentPlan, RuntimePlan,
};
use bootstrap::HealthReporter;
use primitives::{HealthStatus, ProbeName};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    source_sha: String,
    image_digest: String,
}

impl BuildIdentity {
    pub fn parse(source_sha: &str, image_digest: &str) -> Result<Self, InventoryError> {
        if source_sha.len() != 40 || !is_lower_hex(source_sha) {
            return Err(InventoryError::BuildIdentity);
        }
        if image_digest.len() != 71
            || !image_digest.starts_with("sha256:")
            || !is_lower_hex(&image_digest[7..])
        {
            return Err(InventoryError::BuildIdentity);
        }
        Ok(Self {
            source_sha: source_sha.to_owned(),
            image_digest: image_digest.to_owned(),
        })
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    pub fn image_digest(&self) -> &str {
        &self.image_digest
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
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
    PeerEndpointUnresolved,
    PeerEndpointUnavailable,
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
    runtime_plan_fingerprint: String,
    deployment_fingerprint: String,
    build_identity: BuildIdentity,
    domains: Vec<AssemblyDomain>,
    listeners: Vec<ExpectedListener>,
    service_endpoints: Vec<(AssemblyListenerKind, u16)>,
    probe_endpoints: BTreeSet<u16>,
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
    pub fn from_bound(
        runtime: &RuntimePlan,
        deployment: &ParsedDeploymentPlan,
        workload: &str,
        build_identity: BuildIdentity,
        mut provider_bindings: Vec<ProviderProbeBinding>,
        mut placements: Vec<PlacementObservation>,
    ) -> Result<Self, InventoryError> {
        if deployment.assembly_fingerprint() != runtime.assembly_fingerprint() {
            return Err(InventoryError::AssemblyFingerprintMismatch);
        }
        if deployment.runtime_plan_fingerprint() != runtime.runtime_plan_fingerprint() {
            return Err(InventoryError::RuntimePlanFingerprintMismatch);
        }
        let workload_plan = deployment
            .workloads()
            .iter()
            .find(|candidate| candidate.name() == workload)
            .ok_or(InventoryError::DeploymentWorkload)?;
        let (_, expected_digest) = workload_plan
            .image()
            .rsplit_once('@')
            .ok_or(InventoryError::DeploymentWorkload)?;
        if expected_digest != build_identity.image_digest() {
            return Err(InventoryError::BuildImageMismatch);
        }

        let mut service_endpoints = deployment
            .services()
            .iter()
            .filter(|service| service.workload() == workload)
            .flat_map(|service| service.ports())
            .map(|port| {
                let kind = match port.name() {
                    "http" => AssemblyListenerKind::Primary,
                    "admin" => AssemblyListenerKind::Admin,
                    "health" => AssemblyListenerKind::Health,
                    "internal" => AssemblyListenerKind::Internal,
                    _ => return Err(InventoryError::DeploymentWorkload),
                };
                Ok((kind, port.port()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        service_endpoints.sort_unstable();
        let probe_endpoints = workload_plan
            .probes()
            .iter()
            .map(|probe| probe.port())
            .collect();

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
            runtime_plan_fingerprint: runtime.runtime_plan_fingerprint().as_str().to_owned(),
            deployment_fingerprint: deployment.deployment_fingerprint().as_str().to_owned(),
            build_identity,
            domains: runtime
                .domain_plans()
                .iter()
                .map(|domain| domain.id())
                .collect(),
            listeners: runtime
                .listener_plans()
                .iter()
                .map(|listener| ExpectedListener {
                    id: listener.id().to_owned(),
                    kind: listener.kind(),
                    auth: listener.auth(),
                })
                .collect(),
            service_endpoints,
            probe_endpoints,
            provider_bindings,
            placements,
        })
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
    runtime_plan_fingerprint: String,
    deployment_fingerprint: String,
    build_identity: BuildIdentity,
    domains: Vec<AssemblyDomain>,
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
    pub fn runtime_plan_fingerprint(&self) -> &str {
        &self.runtime_plan_fingerprint
    }
    pub fn deployment_fingerprint(&self) -> &str {
        &self.deployment_fingerprint
    }
    pub const fn build_identity(&self) -> &BuildIdentity {
        &self.build_identity
    }
    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.domains
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
        let mut actual_endpoints = listeners
            .iter()
            .map(|listener| (listener.kind, listener.endpoint.port))
            .collect::<Vec<_>>();
        actual_endpoints.sort_unstable();
        let actual_probe_endpoints = listeners
            .iter()
            .filter(|listener| listener.kind == AssemblyListenerKind::Health)
            .map(|listener| listener.endpoint.port)
            .collect::<BTreeSet<_>>();
        if actual_endpoints != self.0.seed.service_endpoints
            || actual_probe_endpoints != self.0.seed.probe_endpoints
        {
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
            runtime_plan_fingerprint: self.0.seed.runtime_plan_fingerprint.clone(),
            deployment_fingerprint: self.0.seed.deployment_fingerprint.clone(),
            build_identity: self.0.seed.build_identity.clone(),
            domains: self.0.seed.domains.clone(),
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
    #[error("runtime inventory build identity is invalid")]
    BuildIdentity,
    #[error("runtime inventory build image does not match deployment")]
    BuildImageMismatch,
    #[error("runtime inventory deployment assembly fingerprint does not match runtime plan")]
    AssemblyFingerprintMismatch,
    #[error("runtime inventory deployment runtime fingerprint does not match runtime plan")]
    RuntimePlanFingerprintMismatch,
    #[error("runtime inventory deployment workload is invalid")]
    DeploymentWorkload,
    #[error("runtime inventory provider binding is invalid")]
    ProviderBinding,
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
    use assembly_schema::{ParsedRuntimePlan, WorkloadPlan};
    use bootstrap::{HealthProbe, Registry};
    use primitives::{HealthCheck, ProbeName};
    use sha2::{Digest, Sha256};
    use std::error::Error;
    use std::sync::atomic::{AtomicU8, Ordering};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn bound_plans() -> TestResult<(
        ParsedRuntimePlan,
        ParsedDeploymentPlan,
        String,
        BuildIdentity,
    )> {
        let runtime = ParsedRuntimePlan::from_json_slice(include_bytes!(
            "../../../assemblies/settingsonly/runtime-plan.json"
        ))?;
        let deployment = ParsedDeploymentPlan::from_json_slice(
            runtime.as_plan(),
            include_bytes!("../../../deploy/generated/settingsonly.deployment-plan.json"),
        )?;
        let workload = deployment.workloads()[0].name().to_owned();
        let digest = image_digest(&deployment.workloads()[0])?.to_owned();
        let build = BuildIdentity::parse(&"a".repeat(40), &digest)?;
        Ok((runtime, deployment, workload, build))
    }

    fn image_digest(workload: &WorkloadPlan) -> TestResult<&str> {
        Ok(workload
            .image()
            .rsplit_once('@')
            .ok_or("fixture image must be immutable")?
            .1)
    }

    fn fingerprint(tag: &str, value: &serde_json::Value) -> TestResult<String> {
        let canonical = serde_json_canonicalizer::to_vec(value)?;
        let mut hasher = Sha256::new();
        hasher.update(tag.as_bytes());
        hasher.update([0]);
        hasher.update(canonical);
        Ok(format!("sha256:{:x}", hasher.finalize()))
    }

    fn same_assembly_different_runtime() -> TestResult<(ParsedRuntimePlan, ParsedDeploymentPlan)> {
        let mut runtime: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../assemblies/settingsonly/runtime-plan.json"
        ))?;
        runtime["listenerPlans"][0]["auth"] =
            serde_json::Value::String("rssAccessToken".to_owned());
        let mut unsigned_runtime = runtime.clone();
        unsigned_runtime
            .as_object_mut()
            .ok_or("runtime fixture must be an object")?
            .remove("runtimePlanFingerprint");
        let runtime_fingerprint = fingerprint("rss-runtime-plan-v1", &unsigned_runtime)?;
        runtime["runtimePlanFingerprint"] = serde_json::Value::String(runtime_fingerprint.clone());
        let runtime = ParsedRuntimePlan::from_json_slice(&serde_json::to_vec(&runtime)?)?;

        let mut deployment: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../deploy/generated/settingsonly.deployment-plan.json"
        ))?;
        deployment["runtimePlanFingerprint"] = serde_json::Value::String(runtime_fingerprint);
        let mut unsigned_deployment = deployment.clone();
        unsigned_deployment
            .as_object_mut()
            .ok_or("deployment fixture must be an object")?
            .remove("deploymentFingerprint");
        deployment["deploymentFingerprint"] =
            serde_json::Value::String(fingerprint("rss-deployment-plan-v1", &unsigned_deployment)?);
        let deployment = ParsedDeploymentPlan::from_json_slice(
            runtime.as_plan(),
            &serde_json::to_vec(&deployment)?,
        )?;
        Ok((runtime, deployment))
    }

    #[test]
    fn inventory_build_identity_is_closed() {
        assert!(
            BuildIdentity::parse(&"a".repeat(40), &format!("sha256:{}", "b".repeat(64))).is_ok()
        );
        assert_eq!(
            BuildIdentity::parse(&"A".repeat(40), &format!("sha256:{}", "b".repeat(64))),
            Err(InventoryError::BuildIdentity)
        );
        assert_eq!(
            BuildIdentity::parse(&"a".repeat(40), &format!("sha256:{}", "B".repeat(64))),
            Err(InventoryError::BuildIdentity)
        );
    }

    #[test]
    fn inventory_seed_rejects_image_mismatch() -> TestResult {
        let (runtime, deployment, workload, _) = bound_plans()?;
        let build = BuildIdentity::parse(&"a".repeat(40), &format!("sha256:{}", "b".repeat(64)))?;
        let error = RuntimeInventorySeed::from_bound(
            runtime.as_plan(),
            &deployment,
            &workload,
            build,
            Vec::new(),
            Vec::new(),
        )
        .err();
        assert_eq!(error, Some(InventoryError::BuildImageMismatch));
        Ok(())
    }

    #[test]
    fn inventory_seed_exact_joins_deployment_assembly_fingerprint() -> TestResult {
        let (runtime, _, workload, build) = bound_plans()?;
        let other_runtime = ParsedRuntimePlan::from_json_slice(include_bytes!(
            "../../../assemblies/identityaudit/runtime-plan.json"
        ))?;
        let other_deployment = ParsedDeploymentPlan::from_json_slice(
            other_runtime.as_plan(),
            include_bytes!("../../../deploy/generated/identityaudit.deployment-plan.json"),
        )?;
        assert_eq!(
            RuntimeInventorySeed::from_bound(
                runtime.as_plan(),
                &other_deployment,
                &workload,
                build,
                Vec::new(),
                Vec::new(),
            )
            .err(),
            Some(InventoryError::AssemblyFingerprintMismatch)
        );
        Ok(())
    }

    #[test]
    fn inventory_seed_exact_joins_deployment_runtime_fingerprint() -> TestResult {
        let (runtime, _, workload, build) = bound_plans()?;
        let (_, changed_deployment) = same_assembly_different_runtime()?;
        assert_eq!(
            RuntimeInventorySeed::from_bound(
                runtime.as_plan(),
                &changed_deployment,
                &workload,
                build,
                Vec::new(),
                Vec::new(),
            )
            .err(),
            Some(InventoryError::RuntimePlanFingerprintMismatch)
        );
        Ok(())
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
        deployment: &ParsedDeploymentPlan,
        workload: &str,
        build: BuildIdentity,
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
        Ok(RuntimeInventorySeed::from_bound(
            runtime.as_plan(),
            deployment,
            workload,
            build,
            providers,
            placements,
        )?)
    }

    fn exact_listeners(
        runtime: &ParsedRuntimePlan,
        deployment: &ParsedDeploymentPlan,
        workload: &str,
    ) -> TestResult<Vec<BoundListenerObservation>> {
        runtime
            .listener_plans()
            .iter()
            .map(|listener| {
                let port_name = match listener.kind() {
                    AssemblyListenerKind::Primary => "http",
                    AssemblyListenerKind::Admin => "admin",
                    AssemblyListenerKind::Health => "health",
                    AssemblyListenerKind::Internal => "internal",
                };
                let port = deployment
                    .services()
                    .iter()
                    .filter(|service| service.workload() == workload)
                    .flat_map(|service| service.ports())
                    .find(|port| port.name() == port_name)
                    .ok_or("listener port must exist in deployment fixture")?
                    .port();
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
            let (runtime, deployment, workload, build) = bound_plans()?;
            let seed = exact_seed(&runtime, &deployment, &workload, build, None)?;
            let listeners = exact_listeners(&runtime, &deployment, &workload)?;
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
    fn inventory_listener_publication_rejects_deployment_port_drift() -> TestResult {
        let (runtime, deployment, workload, build) = bound_plans()?;
        let seed = exact_seed(&runtime, &deployment, &workload, build, None)?;
        let mut listeners = exact_listeners(&runtime, &deployment, &workload)?;
        listeners[0].endpoint.port += 1;

        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(listeners),
            Err(InventoryError::ListenerBinding)
        );
        Ok(())
    }

    #[test]
    fn inventory_listener_publication_rejects_probe_endpoint_drift() -> TestResult {
        let (runtime, deployment, workload, build) = bound_plans()?;
        let mut seed = exact_seed(&runtime, &deployment, &workload, build, None)?;
        let mut listeners = exact_listeners(&runtime, &deployment, &workload)?;
        let health = listeners
            .iter_mut()
            .find(|listener| listener.kind == AssemblyListenerKind::Health)
            .ok_or("fixture must contain a health listener")?;
        health.endpoint.port += 1;
        let service_health = seed
            .service_endpoints
            .iter_mut()
            .find(|(kind, _)| *kind == AssemblyListenerKind::Health)
            .ok_or("fixture must contain a health service endpoint")?;
        service_health.1 += 1;

        assert_eq!(
            inventory_channel(seed, reporter(HealthStatus::Healthy)?)
                .0
                .publish(listeners),
            Err(InventoryError::ListenerBinding)
        );
        Ok(())
    }

    #[test]
    fn inventory_reader_recomputes_provider_posture_on_each_request() -> TestResult {
        let (runtime, deployment, workload, build) = bound_plans()?;
        let (health, state, probe) = mutable_reporter()?;
        let seed = exact_seed(&runtime, &deployment, &workload, build, Some(probe))?;
        let (publisher, reader) = inventory_channel(seed, health);
        publisher.publish(exact_listeners(&runtime, &deployment, &workload)?)?;

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
        let (runtime, deployment, workload, build) = bound_plans()?;
        let mut seed = exact_seed(&runtime, &deployment, &workload, build, None)?;
        let placement = seed
            .placements
            .first_mut()
            .ok_or("fixture must contain a placement")?;
        placement.mode = InventoryPlacementMode::Remote;
        placement.readiness = InventoryPlacementReadiness::PeerEndpointUnresolved;
        let listeners = exact_listeners(&runtime, &deployment, &workload)?;
        let readiness = Arc::new(AtomicU8::new(0));
        let sampled = Arc::clone(&readiness);
        let (publisher, reader, health_publisher, placement_publisher) =
            deferred_inventory_channel(seed);
        health_publisher.publish(reporter(HealthStatus::Healthy)?)?;
        placement_publisher.publish(Arc::new(move || match sampled.load(Ordering::Acquire) {
            0 => InventoryPlacementReadiness::PeerEndpointUnresolved,
            1 => InventoryPlacementReadiness::Ready,
            _ => InventoryPlacementReadiness::PeerEndpointUnavailable,
        }))?;
        publisher.publish(listeners)?;

        assert_eq!(
            reader.read()?.placements()[0].readiness(),
            InventoryPlacementReadiness::PeerEndpointUnresolved
        );
        readiness.store(1, Ordering::Release);
        assert_eq!(
            reader.read()?.placements()[0].readiness(),
            InventoryPlacementReadiness::Ready
        );
        readiness.store(2, Ordering::Release);
        assert_eq!(
            reader.read()?.placements()[0].readiness(),
            InventoryPlacementReadiness::PeerEndpointUnavailable
        );
        Ok(())
    }

    #[test]
    fn inventory_provider_bindings_require_exact_ids_and_allow_explicit_shared_probes() -> TestResult
    {
        let (runtime, deployment, workload, build) = bound_plans()?;
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
            RuntimeInventorySeed::from_bound(
                runtime.as_plan(),
                &deployment,
                &workload,
                build.clone(),
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
            RuntimeInventorySeed::from_bound(
                runtime.as_plan(),
                &deployment,
                &workload,
                build.clone(),
                duplicate,
                placements(),
            )
            .err(),
            Some(InventoryError::ProviderBinding)
        );
        bindings.push(ProviderProbeBinding::new("unknown-provider", Vec::new())?);
        assert_eq!(
            RuntimeInventorySeed::from_bound(
                runtime.as_plan(),
                &deployment,
                &workload,
                build.clone(),
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
        RuntimeInventorySeed::from_bound(
            runtime.as_plan(),
            &deployment,
            &workload,
            build,
            exact,
            placements(),
        )?;
        Ok(())
    }

    #[test]
    fn inventory_reader_is_unavailable_before_exact_listener_publication() -> TestResult {
        let (runtime, deployment, workload, build) = bound_plans()?;
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
        let seed = RuntimeInventorySeed::from_bound(
            runtime.as_plan(),
            &deployment,
            &workload,
            build,
            providers,
            placements,
        )?;
        let (publisher, reader) = inventory_channel(seed, reporter(HealthStatus::Healthy)?);
        assert!(matches!(reader.read(), Err(InventoryError::Unavailable)));
        let listeners = exact_listeners(&runtime, &deployment, &workload)?;
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
}
