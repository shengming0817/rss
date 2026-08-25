//! Wire-neutral runtime inventory observations.
//!
//! These types deliberately do not implement `Serialize` or `Deserialize`. A live source supplies
//! raw parts to the reader, which alone mints the opaque hand-off consumed by generated wire
//! projection.
#![warn(missing_docs)]

use crate::{
    AssemblyDomain, AssemblyFingerprint, AssemblyListenerKind, CanonicalAssemblyManifestV2,
    ListenerAuth, OfficialAssemblyProfile, RuntimePlan, RuntimePlanFingerprint,
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
    official_profile: Option<OfficialAssemblyProfile>,
    config_digest: Option<CanonicalSha256Digest>,
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
            official_profile: runtime_plan.plan_kind().official_profile(),
            config_digest: runtime_plan.plan_kind().config_digest().cloned(),
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

    /// Return the official profile selected by the RuntimePlan, if any.
    pub const fn official_profile(&self) -> Option<OfficialAssemblyProfile> {
        self.official_profile
    }

    /// Return the manifest-derived official profile configuration digest, if any.
    pub const fn config_digest(&self) -> Option<&CanonicalSha256Digest> {
        self.config_digest.as_ref()
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
            official_profile: None,
            config_digest: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Construct an official-profile identity for inventory contract tests.
    pub fn for_test_official(
        assembly_fingerprint: CanonicalSha256Digest,
        runtime_plan_fingerprint: CanonicalSha256Digest,
        profile: OfficialAssemblyProfile,
        config_digest: CanonicalSha256Digest,
    ) -> Self {
        Self {
            assembly_fingerprint: AssemblyFingerprint::from_validated(assembly_fingerprint),
            runtime_plan_fingerprint: RuntimePlanFingerprint::from_validated(
                runtime_plan_fingerprint,
            ),
            official_profile: Some(profile),
            config_digest: Some(config_digest),
        }
    }
}

/// Manifest-derived exact official-profile topology carried into the protected inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryOfficialProfile {
    profile: OfficialAssemblyProfile,
    config_digest: CanonicalSha256Digest,
    routes: Vec<String>,
    workers: Vec<String>,
    probes: Vec<String>,
}

impl RuntimeInventoryOfficialProfile {
    /// Derive the protected closure only from a canonical manifest and its validated plan.
    pub fn from_manifest_and_plan(
        manifest: &CanonicalAssemblyManifestV2,
        plan: &RuntimePlan,
    ) -> Result<Self, RuntimeInventoryOfficialProfileError> {
        let profile = plan
            .plan_kind()
            .official_profile()
            .ok_or(RuntimeInventoryOfficialProfileError::GenericPlan)?;
        let closure = manifest
            .official_profile(profile)
            .ok_or(RuntimeInventoryOfficialProfileError::MissingManifestProfile)?;
        let expected = manifest
            .official_profile_config_digest(profile)
            .map_err(|_| RuntimeInventoryOfficialProfileError::ConfigDigest)?;
        if plan.plan_kind().config_digest() != Some(&expected) {
            return Err(RuntimeInventoryOfficialProfileError::ConfigDigest);
        }
        Ok(Self {
            profile,
            config_digest: expected,
            routes: closure.required_routes().to_vec(),
            workers: closure.required_workers(),
            probes: closure.required_probes(),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Construct an exact official-profile closure for isolated contract tests.
    pub fn for_test(
        profile: OfficialAssemblyProfile,
        config_digest: CanonicalSha256Digest,
        routes: Vec<String>,
        workers: Vec<String>,
        probes: Vec<String>,
    ) -> Self {
        Self {
            profile,
            config_digest,
            routes,
            workers,
            probes,
        }
    }
    /// Return the closed profile ID.
    pub const fn profile(&self) -> OfficialAssemblyProfile {
        self.profile
    }
    /// Return the canonical config digest.
    pub const fn config_digest(&self) -> &CanonicalSha256Digest {
        &self.config_digest
    }
    /// Return exact route IDs.
    pub fn routes(&self) -> &[String] {
        &self.routes
    }
    /// Return exact worker IDs.
    pub fn workers(&self) -> &[String] {
        &self.workers
    }
    /// Return exact readiness probe IDs.
    pub fn probes(&self) -> &[String] {
        &self.probes
    }
}

/// Closed failures while deriving protected official-profile inventory evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeInventoryOfficialProfileError {
    /// Generic plans cannot produce official-profile evidence.
    #[error("generic RuntimePlan cannot produce official-profile inventory evidence")]
    GenericPlan,
    /// The canonical manifest does not declare the plan's profile.
    #[error("RuntimePlan official profile is absent from the canonical manifest")]
    MissingManifestProfile,
    /// The plan binding and manifest-derived configuration digest differ.
    #[error("RuntimePlan official-profile configuration digest differs from the manifest")]
    ConfigDigest,
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

/// Execution-only projection activation; capture-only cannot enter this constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryExecutingProjectionActivation {
    /// Execute without authoritative serving.
    Shadow,
    /// Execute as the authoritative projection.
    Active,
}

/// Selected-generation posture across one complete tenant sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventorySelectedGeneration {
    /// No tenant selected an executable generation during the complete sweep.
    None,
    /// Every selected tenant used the supplied generation.
    Uniform(String),
    /// Selected generations differed, including selected and uninitialized tenants coexisting.
    Mixed,
}

/// Bounded reason posture without tenant identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryReasonPosture<R> {
    /// Every reported tenant produced the same closed reason.
    Uniform(R),
    /// Multiple closed reasons occurred without exposing tenant-level facts.
    Mixed,
}

/// Closed retryable reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryRetryableReason {
    /// The durable checkpoint could not be read.
    CheckpointUnread,
    /// The durable checkpoint could not be saved after processing.
    CheckpointUnsaved,
    /// A rejected event could not be written to the dead-letter store.
    DeadLetterUnsaved,
    /// Applying an event failed transiently.
    ApplyTransient,
    /// The apply commit outcome is unknown.
    CommitUnknown,
    /// Reading the projection source failed transiently.
    SourceTransient,
    /// Persisting durable quarantine failed transiently.
    QuarantinePersistence,
}

/// Closed durable tenant-quarantine reason vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryQuarantineReason {
    /// Target definition identity drifted.
    TargetDefinitionDrift,
    /// Input binding identity drifted.
    InputBindingDrift,
    /// Provider state belongs to a different tenant.
    TenantDrift,
    /// An input payload could not be decoded.
    PayloadMalformed,
    /// A decoded payload violated value constraints.
    PayloadValueInvalid,
    /// An input attempted to regress the projection version.
    VersionRegression,
    /// The provider violated an invariant.
    ProviderInvariant,
    /// The provider rejected the operation permanently.
    ProviderPermanent,
    /// Applying the event conflicted with durable state.
    Conflict,
    /// The apply store observed an out-of-order write.
    ApplyOutOfOrder,
    /// Compensation could not restore durable state.
    RollbackFailed,
    /// The source delivered an event behind the accepted coordinate.
    SourceOutOfOrder,
}

/// Closed observation-unavailable reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryUnavailableReason {
    /// Initial source/checkpoint observation has not completed successfully.
    StartupObservation,
    /// The tenant sweep ended before every selected tenant was observed.
    SweepIncomplete,
    /// At least one tenant's bounded observation failed.
    TenantObservation,
}

/// Closed process-fatal reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeInventoryStoppedReason {
    /// The dedicated worker runtime could not be constructed.
    RuntimeBuildFailed,
    /// The worker unwound while being polled.
    WorkerPanicked,
    /// The tenant catalog is unavailable.
    TenantCatalogUnavailable,
    /// The selected generation cannot be resolved.
    SelectedGenerationUnavailable,
    /// The selected generation identity is invalid.
    SelectedGenerationIdentityInvalid,
    /// The tenant catalog returned an invalid tenant identity.
    InvalidTenant,
    /// Durable tenant quarantine cannot be read or written.
    TenantQuarantineUnavailable,
    /// The initial projection source is unavailable.
    StartupSourceUnavailable,
    /// A projection run returned an inconsistent outcome.
    ProjectionOutcomeInvalid,
    /// A provider coordinate cannot be represented by the runtime.
    CoordinateOverflow,
    /// The plan-issued target configuration is invalid.
    TargetConfigInvalid,
}

/// Current process-wide worker status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryProjectionWorkerStatus {
    /// The worker has not completed its first reportable observation.
    Starting,
    /// A complete sweep observed neither retryable work nor durable quarantine.
    Healthy {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: RuntimeInventorySelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
    },
    /// A complete sweep observed retryable work but no durable quarantine.
    Retryable {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: RuntimeInventorySelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of retryable reasons.
        reasons: RuntimeInventoryReasonPosture<RuntimeInventoryRetryableReason>,
    },
    /// A complete sweep observed durable quarantine but no retryable work.
    Quarantined {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: RuntimeInventorySelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of durable quarantine reasons.
        reasons: RuntimeInventoryReasonPosture<RuntimeInventoryQuarantineReason>,
    },
    /// A complete sweep observed both retryable work and durable quarantine.
    Mixed {
        /// Aggregated selected-generation posture for the complete sweep.
        selected_generation: RuntimeInventorySelectedGeneration,
        /// Maximum paired per-tenant lag in provider offset units.
        max_lag: u64,
        /// Bounded aggregate of retryable reasons.
        retryable_reasons: RuntimeInventoryReasonPosture<RuntimeInventoryRetryableReason>,
        /// Bounded aggregate of durable quarantine reasons.
        quarantine_reasons: RuntimeInventoryReasonPosture<RuntimeInventoryQuarantineReason>,
    },
    /// No complete current snapshot is available; stale generation and lag are suppressed.
    Unavailable(RuntimeInventoryUnavailableReason),
    /// The worker stopped fatally and the terminal status cannot be overwritten.
    Stopped(RuntimeInventoryStoppedReason),
}

/// Required runtime portion of a shadow/active projection observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryProjectionExecution {
    target_generation: String,
    worker_status: RuntimeInventoryProjectionWorkerStatus,
}

impl RuntimeInventoryProjectionExecution {
    /// Seal the target generation and its live worker sample into one execution observation.
    pub fn new(
        target_generation: String,
        worker_status: RuntimeInventoryProjectionWorkerStatus,
    ) -> Self {
        Self {
            target_generation,
            worker_status,
        }
    }
    /// Return the plan-selected target generation.
    pub fn target_generation(&self) -> &str {
        &self.target_generation
    }
    /// Return the sampled worker status.
    pub fn worker_status(&self) -> &RuntimeInventoryProjectionWorkerStatus {
        &self.worker_status
    }
}

/// One activated workflow copied from the sealed runtime plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInventoryActivatedWorkflow {
    id: String,
    definition_version: String,
    definition_schema_digest: CanonicalSha256Digest,
    shape: RuntimeInventoryActivatedWorkflowShape,
}

/// Closed activated-workflow shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeInventoryActivatedWorkflowShape {
    /// Capture-only projection with no execution capability.
    ProjectionCapture,
    /// Shadow or active projection with its required execution observation.
    ProjectionExecuting {
        /// Exact executing activation posture.
        activation: RuntimeInventoryExecutingProjectionActivation,
        /// Live execution facts sampled by RuntimeExec.
        execution: RuntimeInventoryProjectionExecution,
    },
    /// Active saga; disabled workflows are excluded from inventory.
    SagaActive,
}

impl RuntimeInventoryActivatedWorkflow {
    /// Build workflow parts; the enclosing observation validates identifier and version.
    pub fn capture_only_projection(
        id: String,
        definition_version: String,
        definition_schema_digest: CanonicalSha256Digest,
    ) -> Self {
        Self {
            id,
            definition_version,
            definition_schema_digest,
            shape: RuntimeInventoryActivatedWorkflowShape::ProjectionCapture,
        }
    }

    /// Build a shadow or active projection with its required execution observation.
    pub fn executing_projection(
        id: String,
        definition_version: String,
        definition_schema_digest: CanonicalSha256Digest,
        activation: RuntimeInventoryExecutingProjectionActivation,
        projection_execution: RuntimeInventoryProjectionExecution,
    ) -> Self {
        Self {
            id,
            definition_version,
            definition_schema_digest,
            shape: RuntimeInventoryActivatedWorkflowShape::ProjectionExecuting {
                activation,
                execution: projection_execution,
            },
        }
    }

    /// Build an active saga observation.
    pub fn active_saga(
        id: String,
        definition_version: String,
        definition_schema_digest: CanonicalSha256Digest,
    ) -> Self {
        Self {
            id,
            definition_version,
            definition_schema_digest,
            shape: RuntimeInventoryActivatedWorkflowShape::SagaActive,
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

    /// Return the closed workflow shape.
    pub const fn shape(&self) -> &RuntimeInventoryActivatedWorkflowShape {
        &self.shape
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
    /// Official-profile identity or exact declared closure differs from the RuntimePlan binding.
    OfficialProfile,
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
            Self::OfficialProfile => "observation.official_profile",
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
    official_profile: Option<RuntimeInventoryOfficialProfile>,
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
            official_profile: None,
            build_metadata,
            domains,
            activated_workflows,
            listeners,
            provider_posture,
            placements,
        }
    }

    /// Attach the manifest-derived official closure exactly once before reader validation.
    pub fn with_official_profile(mut self, profile: RuntimeInventoryOfficialProfile) -> Self {
        self.official_profile = Some(profile);
        self
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
        let official_valid = match (
            parts.identity.official_profile(),
            parts.identity.config_digest(),
            parts.official_profile.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(profile), Some(digest), Some(closure)) => {
                let closed = |values: &[String]| {
                    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
                };
                closure.profile() == profile
                    && closure.config_digest() == digest
                    && closed(closure.routes())
                    && closed(closure.workers())
                    && closed(closure.probes())
            }
            _ => false,
        };
        if !official_valid {
            return Err(RuntimeInventoryReadFailure::Invariant(
                RuntimeInventoryInvariantKind::OfficialProfile,
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
    /// Return the AssemblyLock digest that binds this runtime composition.
    pub fn assembly_lock_digest(&self) -> &AssemblyFingerprint {
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
    /// Return the manifest-bound official profile closure, if this is an official RuntimePlan.
    pub fn official_profile(&self) -> Option<&RuntimeInventoryOfficialProfile> {
        self.parts.official_profile.as_ref()
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
            vec![RuntimeInventoryActivatedWorkflow::active_saga(
                "identity.rotate".to_owned(),
                "v1".to_owned(),
                digest('c')?,
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
                RuntimeInventoryInvariantKind::OfficialProfile => {
                    return Err("unexpected official-profile invariant fixture".into());
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

    #[test]
    fn workflow_constructors_mint_only_closed_shapes() -> TestResult {
        let capture = RuntimeInventoryActivatedWorkflow::capture_only_projection(
            "settings.capture".to_owned(),
            "v3".to_owned(),
            digest('e')?,
        );
        assert!(matches!(
            capture.shape(),
            RuntimeInventoryActivatedWorkflowShape::ProjectionCapture
        ));

        let executing = RuntimeInventoryActivatedWorkflow::executing_projection(
            "settings.execute".to_owned(),
            "v3".to_owned(),
            digest('f')?,
            RuntimeInventoryExecutingProjectionActivation::Active,
            RuntimeInventoryProjectionExecution::new(
                "v3".to_owned(),
                RuntimeInventoryProjectionWorkerStatus::Starting,
            ),
        );
        assert!(matches!(
            executing.shape(),
            RuntimeInventoryActivatedWorkflowShape::ProjectionExecuting {
                activation: RuntimeInventoryExecutingProjectionActivation::Active,
                execution,
            } if matches!(execution.worker_status(), RuntimeInventoryProjectionWorkerStatus::Starting)
        ));
        Ok(())
    }
}
