//! Wire-neutral runtime inventory observations.
//!
//! These types deliberately do not implement `Serialize` or `Deserialize`. A live source supplies
//! raw parts to the reader, which alone mints the opaque hand-off consumed by generated wire
//! projection.
#![warn(missing_docs)]

use crate::{
    AssemblyDomain, AssemblyFingerprint, AssemblyListenerKind, ListenerAuth, RuntimePlan,
    RuntimePlanFingerprint,
};
pub use vocab::CanonicalSha256Digest;

fn all_unique<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(index, item)| !items[index + 1..].contains(item))
}

/// Provenance-bearing fingerprints copied from one validated runtime plan.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeInventoryIdentity {
    assembly_fingerprint: AssemblyFingerprint,
    runtime_plan_fingerprint: RuntimePlanFingerprint,
}

impl std::fmt::Debug for RuntimeInventoryIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInventoryIdentity")
            .field("assembly_fingerprint", &self.assembly_fingerprint.as_str())
            .field(
                "runtime_plan_fingerprint",
                &self.runtime_plan_fingerprint.as_str(),
            )
            .finish()
    }
}

impl RuntimeInventoryIdentity {
    /// Preserve both typed identities from the same validated runtime plan.
    pub fn from_runtime_plan(runtime_plan: &RuntimePlan) -> Self {
        Self {
            assembly_fingerprint: runtime_plan.assembly_fingerprint().clone(),
            runtime_plan_fingerprint: runtime_plan.runtime_plan_fingerprint().clone(),
        }
    }

    /// Return the typed assembly fingerprint.
    pub fn assembly_fingerprint(&self) -> &AssemblyFingerprint {
        &self.assembly_fingerprint
    }

    /// Return the typed runtime-plan fingerprint.
    pub fn runtime_plan_fingerprint(&self) -> &RuntimePlanFingerprint {
        &self.runtime_plan_fingerprint
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Construct syntax-valid identities for tests that do not compile an assembly plan.
    pub fn for_test(
        assembly_fingerprint: CanonicalSha256Digest,
        runtime_plan_fingerprint: CanonicalSha256Digest,
    ) -> Self {
        Self {
            assembly_fingerprint: AssemblyFingerprint::from_validated(assembly_fingerprint),
            runtime_plan_fingerprint: RuntimePlanFingerprint::from_validated(
                runtime_plan_fingerprint,
            ),
        }
    }
}

/// Network scheme for an observed listener or declared placement endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryEndpointScheme {
    /// Plain HTTP.
    Http,
    /// HTTP protected by TLS.
    Https,
}

/// Endpoint facts without HTTP DTO or serialization ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryEndpoint {
    scheme: RuntimeInventoryEndpointScheme,
    host: String,
    port: u16,
}

impl RuntimeInventoryEndpoint {
    /// Build endpoint parts; the enclosing observation validates host and port.
    pub fn new(scheme: RuntimeInventoryEndpointScheme, host: String, port: u16) -> Self {
        Self { scheme, host, port }
    }

    /// Return the endpoint scheme.
    pub const fn scheme(&self) -> RuntimeInventoryEndpointScheme {
        self.scheme
    }

    /// Return the endpoint host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the non-zero endpoint port after observation validation.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Launch-supplied build metadata; this is reportable metadata, not provenance proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryBuildMetadata {
    source_revision: String,
    image_digest: CanonicalSha256Digest,
}

impl RuntimeInventoryBuildMetadata {
    /// Build metadata parts; the enclosing observation validates the source revision.
    pub fn new(source_revision: String, image_digest: CanonicalSha256Digest) -> Self {
        Self {
            source_revision,
            image_digest,
        }
    }

    /// Return the source revision.
    pub fn source_revision(&self) -> &str {
        &self.source_revision
    }

    /// Return the syntax-validated image digest.
    pub fn image_digest(&self) -> &CanonicalSha256Digest {
        &self.image_digest
    }
}

/// Activation posture for a projection workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryProjectionActivation {
    /// Capture inputs without executing the projection.
    CaptureOnly,
    /// Execute without making results authoritative.
    Shadow,
    /// Execute as the active projection.
    Active,
}

/// Closed activated-workflow vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryWorkflowActivation {
    /// Projection activation with its exact posture.
    Projection(RuntimeInventoryProjectionActivation),
    /// Active saga; disabled workflows are excluded from inventory.
    SagaActive,
}

/// One activated workflow copied from the sealed runtime plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryActivatedWorkflow {
    id: String,
    definition_version: String,
    definition_schema_digest: CanonicalSha256Digest,
    activation: RuntimeInventoryWorkflowActivation,
}

impl RuntimeInventoryActivatedWorkflow {
    /// Build workflow parts; the enclosing observation validates identifier and version.
    pub fn new(
        id: String,
        definition_version: String,
        definition_schema_digest: CanonicalSha256Digest,
        activation: RuntimeInventoryWorkflowActivation,
    ) -> Self {
        Self {
            id,
            definition_version,
            definition_schema_digest,
            activation,
        }
    }

    /// Return the workflow contract identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the definition version.
    pub fn definition_version(&self) -> &str {
        &self.definition_version
    }

    /// Return the syntax-validated definition schema digest.
    pub fn definition_schema_digest(&self) -> &CanonicalSha256Digest {
        &self.definition_schema_digest
    }

    /// Return the closed activation posture.
    pub const fn activation(&self) -> RuntimeInventoryWorkflowActivation {
        self.activation
    }
}

/// One listener backed by a successful bind receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryListener {
    id: String,
    kind: AssemblyListenerKind,
    auth: ListenerAuth,
    endpoint: RuntimeInventoryEndpoint,
}

impl RuntimeInventoryListener {
    /// Build listener parts; the enclosing observation validates identifier and endpoint.
    pub fn new(
        id: String,
        kind: AssemblyListenerKind,
        auth: ListenerAuth,
        endpoint: RuntimeInventoryEndpoint,
    ) -> Self {
        Self {
            id,
            kind,
            auth,
            endpoint,
        }
    }

    /// Return the listener identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the listener kind.
    pub const fn kind(&self) -> AssemblyListenerKind {
        self.kind
    }

    /// Return the listener authentication scheme.
    pub const fn auth(&self) -> ListenerAuth {
        self.auth
    }

    /// Return the bound endpoint.
    pub const fn endpoint(&self) -> &RuntimeInventoryEndpoint {
        &self.endpoint
    }
}

/// Operator posture derived from one provider's sealed probe evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryProviderState {
    /// The provider has construction evidence but no dynamic health probe evidence.
    Unobserved,
    /// Every expected probe is present and healthy.
    Ready,
    /// At least one probe is degraded and none is worse.
    Degraded,
    /// A probe is unhealthy, missing, or reports an unknown state.
    Unavailable,
}

/// Provider identifier paired with its independently computed live posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryProviderPosture {
    id: String,
    state: RuntimeInventoryProviderState,
}

impl RuntimeInventoryProviderPosture {
    /// Build provider posture parts; the enclosing observation validates the identifier.
    pub fn new(id: String, state: RuntimeInventoryProviderState) -> Self {
        Self { id, state }
    }

    /// Return the provider identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the provider posture.
    pub const fn state(&self) -> RuntimeInventoryProviderState {
        self.state
    }
}

/// Placement execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryPlacementMode {
    /// Workload runs in this process.
    Local,
    /// Workload is reached through a declared remote endpoint.
    Remote,
}

/// Placement readiness vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryPlacementReadiness {
    /// Placement is ready for its declared execution mode.
    Ready,
    /// Remote mTLS client identity material is unavailable.
    MtlsSourceUnavailable,
}

/// One runtime-plan placement with optional live readiness overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryPlacement {
    domain: AssemblyDomain,
    workload: String,
    mode: RuntimeInventoryPlacementMode,
    endpoint: Option<RuntimeInventoryEndpoint>,
    spiffe_identity: Option<String>,
    readiness: RuntimeInventoryPlacementReadiness,
}

impl RuntimeInventoryPlacement {
    /// Build placement parts; the enclosing observation validates textual fields and endpoint.
    pub fn new(
        domain: AssemblyDomain,
        workload: String,
        mode: RuntimeInventoryPlacementMode,
        endpoint: Option<RuntimeInventoryEndpoint>,
        spiffe_identity: Option<String>,
        readiness: RuntimeInventoryPlacementReadiness,
    ) -> Self {
        Self {
            domain,
            workload,
            mode,
            endpoint,
            spiffe_identity,
            readiness,
        }
    }

    /// Return the owned domain.
    pub const fn domain(&self) -> AssemblyDomain {
        self.domain
    }

    /// Return the workload name.
    pub fn workload(&self) -> &str {
        &self.workload
    }

    /// Return the placement mode.
    pub const fn mode(&self) -> RuntimeInventoryPlacementMode {
        self.mode
    }

    /// Return the configured remote endpoint, if any.
    pub fn endpoint(&self) -> Option<&RuntimeInventoryEndpoint> {
        self.endpoint.as_ref()
    }

    /// Return the declared SPIFFE identity, if any.
    pub fn spiffe_identity(&self) -> Option<&str> {
        self.spiffe_identity.as_deref()
    }

    /// Return the current placement readiness.
    pub const fn readiness(&self) -> RuntimeInventoryPlacementReadiness {
        self.readiness
    }
}

/// Closed invariant categories retained for safe runtime-inventory diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryInvariantKind {
    /// The runtime plan contains no domains or repeated domains.
    Domains,
    /// Launch-supplied build metadata violates the contract shape.
    BuildMetadata,
    /// Activated workflow facts are invalid or repeated.
    ActivatedWorkflows,
    /// Bound listener facts are invalid or repeated.
    Listeners,
    /// Provider posture facts are invalid or repeated.
    ProviderPosture,
    /// Placement facts are invalid or repeated.
    Placements,
}

impl RuntimeInventoryInvariantKind {
    /// Return a stable, non-sensitive diagnostic stage.
    pub const fn diagnostic_stage(self) -> &'static str {
        match self {
            Self::Domains => "observation.domains",
            Self::BuildMetadata => "observation.build_metadata",
            Self::ActivatedWorkflows => "observation.activated_workflows",
            Self::Listeners => "observation.listeners",
            Self::ProviderPosture => "observation.provider_posture",
            Self::Placements => "observation.placements",
        }
    }
}

/// Closed failures produced while reading or validating a live inventory observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeInventoryReadFailure {
    /// Required listener or health evidence has not been published yet.
    #[error("runtime inventory observation is unavailable")]
    Unavailable,
    /// Published facts violated one neutral observation invariant.
    #[error("runtime inventory observation invariant failed at {0:?}")]
    Invariant(RuntimeInventoryInvariantKind),
}

/// Complete raw facts returned by one live runtime sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryParts {
    identity: RuntimeInventoryIdentity,
    build_metadata: Option<RuntimeInventoryBuildMetadata>,
    domains: Vec<AssemblyDomain>,
    activated_workflows: Vec<RuntimeInventoryActivatedWorkflow>,
    listeners: Vec<RuntimeInventoryListener>,
    provider_posture: Vec<RuntimeInventoryProviderPosture>,
    placements: Vec<RuntimeInventoryPlacement>,
}

impl RuntimeInventoryParts {
    /// Collect one sample for reader-owned validation and minting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: RuntimeInventoryIdentity,
        build_metadata: Option<RuntimeInventoryBuildMetadata>,
        domains: Vec<AssemblyDomain>,
        activated_workflows: Vec<RuntimeInventoryActivatedWorkflow>,
        listeners: Vec<RuntimeInventoryListener>,
        provider_posture: Vec<RuntimeInventoryProviderPosture>,
        placements: Vec<RuntimeInventoryPlacement>,
    ) -> Self {
        Self {
            identity,
            build_metadata,
            domains,
            activated_workflows,
            listeners,
            provider_posture,
            placements,
        }
    }
}

/// Complete inventory evidence minted only by the `runtimeexec` live reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryObservation {
    parts: RuntimeInventoryParts,
}

impl RuntimeInventoryObservation {
    /// Validate a live runtime sample and mint its projection receipt.
    ///
    /// The unnameable-to-assembly [`runtimeinventorymint::RuntimeInventoryMint`] argument makes
    /// `runtimeexec` the only production caller permitted by the dependency graph.
    pub fn from_runtimeexec(
        parts: RuntimeInventoryParts,
        _mint: runtimeinventorymint::RuntimeInventoryMint,
    ) -> Result<Self, RuntimeInventoryReadFailure> {
        let valid_endpoint = |endpoint: &RuntimeInventoryEndpoint| {
            !endpoint.host().is_empty() && endpoint.host().len() <= 253 && endpoint.port() != 0
        };
        let valid_version = |value: &str| {
            value.strip_prefix('v').is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        };
        let build_valid = parts.build_metadata.as_ref().is_none_or(|metadata| {
            matches!(metadata.source_revision().len(), 40 | 64)
                && metadata
                    .source_revision()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !build_valid {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::BuildMetadata,
            ));
        }
        if parts.domains.is_empty() || !all_unique(&parts.domains) {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::Domains,
            ));
        }
        let workflows_valid = parts.activated_workflows.iter().all(|workflow| {
            !workflow.id().is_empty() && valid_version(workflow.definition_version())
        });
        if !workflows_valid || !all_unique(&parts.activated_workflows) {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::ActivatedWorkflows,
            ));
        }
        let listeners_valid = parts
            .listeners
            .iter()
            .all(|listener| !listener.id().is_empty() && valid_endpoint(listener.endpoint()));
        if !listeners_valid || !all_unique(&parts.listeners) {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::Listeners,
            ));
        }
        let providers_valid = parts
            .provider_posture
            .iter()
            .all(|provider| !provider.id().is_empty());
        if !providers_valid || !all_unique(&parts.provider_posture) {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::ProviderPosture,
            ));
        }
        let placements_valid = parts.placements.iter().all(|placement| {
            !placement.workload().is_empty()
                && placement.endpoint().is_none_or(valid_endpoint)
                && placement
                    .spiffe_identity()
                    .is_none_or(|identity| !identity.is_empty())
        });
        if !placements_valid || !all_unique(&parts.placements) {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::Placements,
            ));
        }
        Ok(Self { parts })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Validate and mint an observation for contract projection tests.
    pub fn for_test(parts: RuntimeInventoryParts) -> Result<Self, RuntimeInventoryReadFailure> {
        Self::from_runtimeexec(
            parts,
            runtimeinventorymint::RuntimeInventoryMint::capability(),
        )
    }

    /// Return the provenance-bearing assembly fingerprint.
    pub fn assembly_fingerprint(&self) -> &AssemblyFingerprint {
        self.parts.identity.assembly_fingerprint()
    }
    /// Return optional launch-supplied build metadata.
    pub fn build_metadata(&self) -> Option<&RuntimeInventoryBuildMetadata> {
        self.parts.build_metadata.as_ref()
    }
    /// Return the provenance-bearing runtime-plan fingerprint.
    pub fn runtime_plan_fingerprint(&self) -> &RuntimePlanFingerprint {
        self.parts.identity.runtime_plan_fingerprint()
    }
    /// Return domains in runtime-plan declaration order.
    pub fn domains(&self) -> &[AssemblyDomain] {
        &self.parts.domains
    }
    /// Return activated workflows in runtime-plan order.
    pub fn activated_workflows(&self) -> &[RuntimeInventoryActivatedWorkflow] {
        &self.parts.activated_workflows
    }
    /// Return listeners in stable listener-id order.
    pub fn listeners(&self) -> &[RuntimeInventoryListener] {
        &self.parts.listeners
    }
    /// Return independently evaluated provider posture in provider-plan order.
    pub fn provider_posture(&self) -> &[RuntimeInventoryProviderPosture] {
        &self.parts.provider_posture
    }
    /// Return placements in stable domain/workload order.
    pub fn placements(&self) -> &[RuntimeInventoryPlacement] {
        &self.parts.placements
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    fn digest(byte: char) -> TestResult<CanonicalSha256Digest> {
        Ok(CanonicalSha256Digest::parse(format!(
            "sha256:{}",
            byte.to_string().repeat(64)
        ))?)
    }

    fn parts() -> TestResult<RuntimeInventoryParts> {
        Ok(RuntimeInventoryParts::new(
            RuntimeInventoryIdentity::for_test(digest('a')?, digest('b')?),
            None,
            vec![AssemblyDomain::Identity],
            vec![RuntimeInventoryActivatedWorkflow::new(
                "identity.rotate".to_owned(),
                "v1".to_owned(),
                digest('c')?,
                RuntimeInventoryWorkflowActivation::SagaActive,
            )],
            vec![RuntimeInventoryListener::new(
                "admin".to_owned(),
                AssemblyListenerKind::Admin,
                ListenerAuth::Mtls,
                RuntimeInventoryEndpoint::new(
                    RuntimeInventoryEndpointScheme::Https,
                    "127.0.0.1".to_owned(),
                    8443,
                ),
            )],
            vec![RuntimeInventoryProviderPosture::new(
                "listener-pdp".to_owned(),
                RuntimeInventoryProviderState::Ready,
            )],
            vec![RuntimeInventoryPlacement::new(
                AssemblyDomain::Identity,
                "identity".to_owned(),
                RuntimeInventoryPlacementMode::Local,
                None,
                None,
                RuntimeInventoryPlacementReadiness::Ready,
            )],
        ))
    }

    #[test]
    fn reader_rejects_each_repeated_collection_with_closed_provenance() -> TestResult {
        for expected in [
            RuntimeInventoryInvariantKind::Domains,
            RuntimeInventoryInvariantKind::ActivatedWorkflows,
            RuntimeInventoryInvariantKind::Listeners,
            RuntimeInventoryInvariantKind::ProviderPosture,
            RuntimeInventoryInvariantKind::Placements,
        ] {
            let mut duplicate = parts()?;
            match expected {
                RuntimeInventoryInvariantKind::Domains => {
                    duplicate.domains.push(duplicate.domains[0]);
                }
                RuntimeInventoryInvariantKind::ActivatedWorkflows => duplicate
                    .activated_workflows
                    .push(duplicate.activated_workflows[0].clone()),
                RuntimeInventoryInvariantKind::Listeners => {
                    duplicate.listeners.push(duplicate.listeners[0].clone());
                }
                RuntimeInventoryInvariantKind::ProviderPosture => duplicate
                    .provider_posture
                    .push(duplicate.provider_posture[0].clone()),
                RuntimeInventoryInvariantKind::Placements => {
                    duplicate.placements.push(duplicate.placements[0].clone());
                }
                RuntimeInventoryInvariantKind::BuildMetadata => {
                    return Err("unexpected invariant fixture".into());
                }
            }
            assert_eq!(
                RuntimeInventoryObservation::for_test(duplicate),
                Err(RuntimeInventoryReadFailure::Invariant(expected))
            );
        }
        Ok(())
    }

    #[test]
    fn observation_retains_build_metadata_invariant_provenance() -> TestResult {
        let mut invalid = parts()?;
        invalid.build_metadata = Some(RuntimeInventoryBuildMetadata::new(
            "not-a-revision".to_owned(),
            digest('d')?,
        ));
        assert_eq!(
            RuntimeInventoryObservation::for_test(invalid),
            Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::BuildMetadata
            ))
        );
        Ok(())
    }
}
