//! Domain-shaped async repository port for device-certificate persistence.

use dynosaur::dynosaur;

use super::{
    AcceptDesiredPolicy, ConditionStateBatch, DesiredPolicyAccepted, DeviceCertificateError,
    DeviceCertificateScope, DeviceCertificateStateSnapshot, ExpectedGeneration,
};
use crate::cert_artifact::{
    ArtifactAppendAuthorization, ArtifactEligibility, PersistedCertificateArtifactSnapshot,
};
use crate::device_certificate::reconcile::CertificateReadyProof;
use deviceloop::FenceEpoch;
use eventexec::reconcile::{ReconcileWake, WakeVersion};

/// Closed desired-policy acceptance result, including exact replay and zero-write conflicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredPolicyAcceptOutcome {
    /// Desired, accepted operation, and durable target wake committed atomically.
    Accepted {
        /// Deterministic accepted result stored for replay.
        result: DesiredPolicyAccepted,
        /// Best-effort post-commit notification hint for the exact durable target/version.
        wake: ReconcileWake,
    },
    /// An identical canonical request returned the append-once result with zero writes.
    Replayed {
        /// Previously accepted deterministic result.
        result: DesiredPolicyAccepted,
    },
    /// Storage observed another current generation; the complete unit of work wrote nothing.
    ExpectedGenerationConflict {
        /// Actual generation; zero denotes row absence.
        actual: ExpectedGeneration,
    },
    /// The idempotency key was already bound to another canonical request; zero writes occurred.
    IdempotencyConflict,
}

/// Closed failure taxonomy at the device-certificate repository boundary.
///
/// Reconcile lifecycle failures remain distinct from provider availability so application owners
/// can choose retry and operator behavior without inspecting strings or downcasting sources.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCertificateRepositoryError {
    /// A validated mutation still cannot be lowered to the configured storage representation.
    #[error("device-certificate mutation cannot be represented by storage")]
    InvalidMutation,
    /// The exact reconcile target and its canonical lease row have not been enrolled.
    #[error("device-certificate reconcile enrollment is missing")]
    ReconcileEnrollmentMissing,
    /// The exact reconcile target is persistently quarantined and cannot accept a new wake.
    #[error("device-certificate reconcile target is quarantined")]
    ReconcileTargetQuarantined,
    /// The storage provider was unavailable or a transaction failed.
    #[error("device-certificate storage is unavailable")]
    StorageUnavailable {
        /// Opaque provider failure retained for diagnostics and retry classification.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// PostgreSQL did not confirm whether the transaction committed or rolled back.
    #[error("device-certificate transaction settlement is unknown")]
    SettlementUnknown {
        /// Opaque provider failure; callers must reconcile by explicit same-key replay.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Persisted rows failed the domain restore funnel.
    #[error("device-certificate storage returned invalid state")]
    CorruptState(#[source] DeviceCertificateError),
}

impl DeviceCertificateRepositoryError {
    /// Preserve an infrastructure provider failure without exposing it as domain state.
    pub fn storage_unavailable(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StorageUnavailable {
            source: Box::new(source),
        }
    }

    /// Preserve an unsafe commit/rollback settlement without claiming rollback or retry safety.
    pub fn settlement_unknown(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::SettlementUnknown {
            source: Box::new(source),
        }
    }
}

/// Identity-owned desired-policy mutation persistence port.
///
/// The desired accept method owns its narrow operation/idempotency and existing-target due join;
/// status inspection, command, receipt, readiness, and current-epoch decisions remain absent by
/// construction.
#[trait_variant::make(DeviceCertificateRepository: Send)]
#[dynosaur(
    pub DynDeviceCertificateRepository = dyn(box) DeviceCertificateRepository,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait DeviceCertificateRepositoryLocal: Send + Sync {
    /// Atomically accept desired state, append idempotency result, and advance durable target wake.
    async fn accept_desired_policy(
        &self,
        input: AcceptDesiredPolicy,
    ) -> Result<DesiredPolicyAcceptOutcome, DeviceCertificateRepositoryError>;
}

/// Exact scheduler lease and desired-generation fence carried by every reconcile mutation.
/// Construction is identity-internal from an active [`eventexec::reconcile::ReconcileAttempt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAttemptFence {
    scope: DeviceCertificateScope,
    attempt_id: String,
    lease_token: String,
    epoch: FenceEpoch,
    wake_version: WakeVersion,
    expected_generation: ExpectedGeneration,
}

/// Attempt authority before storage has selected the current desired generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAttemptAuthority {
    scope: DeviceCertificateScope,
    attempt_id: String,
    target_id: String,
    lease_token: String,
    epoch: FenceEpoch,
    wake_version: WakeVersion,
}

impl CertificateAttemptAuthority {
    /// Validate the eventexec-owned certificate target snapshot.
    pub fn from_snapshot(
        snapshot: &eventexec::reconcile::DeviceCertificateAttemptSnapshot,
    ) -> Result<Self, DeviceCertificateError> {
        let device = ids::DeviceId::parse(&snapshot.device_id().hyphenated().to_string())
            .map_err(|_| DeviceCertificateError::InvalidPersistedValue)?;
        Ok(Self {
            scope: DeviceCertificateScope::from_authorized(snapshot.tenant(), device),
            attempt_id: snapshot.attempt_id().to_owned(),
            target_id: snapshot.target_id().to_owned(),
            lease_token: snapshot.lease_token().to_owned(),
            epoch: FenceEpoch::try_new(snapshot.epoch())?,
            wake_version: snapshot.wake_version(),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only adapter conformance constructor preserving the production target checks.
    pub fn for_test(
        scope: DeviceCertificateScope,
        attempt: &eventexec::reconcile::ReconcileAttempt,
    ) -> Result<Self, DeviceCertificateError> {
        let target = attempt.target();
        let resource_matches =
            ids::DeviceId::parse(target.resource_id()).is_ok_and(|device| device == scope.device());
        if target.tenant() != scope.tenant()
            || target.reconciler_id() != "identity.device-certificate"
            || target.resource_kind() != "device-certificate"
            || !resource_matches
        {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        Ok(Self {
            scope,
            attempt_id: attempt.attempt_id().to_owned(),
            target_id: target.target_id().to_owned(),
            lease_token: target.lease_token().to_owned(),
            epoch: FenceEpoch::try_new(target.epoch())?,
            wake_version: target.wake_version(),
        })
    }

    /// Authorized tenant/device scope.
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }
    /// Attempt identity.
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    /// Durable scheduler target identity.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    /// Provider-issued lease token.
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }
    /// Target-local epoch.
    pub const fn epoch(&self) -> FenceEpoch {
        self.epoch
    }
    /// Captured wake version.
    pub const fn wake_version(&self) -> WakeVersion {
        self.wake_version
    }
}

impl CertificateAttemptFence {
    /// Bind a storage-selected current desired generation to an already validated attempt.
    #[doc(hidden)]
    pub fn restore_current(
        authority: &CertificateAttemptAuthority,
        expected_generation: ExpectedGeneration,
    ) -> Self {
        Self {
            scope: authority.scope,
            attempt_id: authority.attempt_id.clone(),
            lease_token: authority.lease_token.clone(),
            epoch: authority.epoch,
            wake_version: authority.wake_version,
            expected_generation,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn from_attempt(
        scope: DeviceCertificateScope,
        attempt: &eventexec::reconcile::ReconcileAttempt,
        expected_generation: ExpectedGeneration,
    ) -> Result<Self, DeviceCertificateError> {
        let resource_matches = ids::DeviceId::parse(attempt.target().resource_id())
            .is_ok_and(|device| device == scope.device());
        if attempt.target().tenant() != scope.tenant() || !resource_matches {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        Ok(Self {
            scope,
            attempt_id: attempt.attempt_id().to_owned(),
            lease_token: attempt.target().lease_token().to_owned(),
            epoch: FenceEpoch::try_new(attempt.target().epoch())?,
            wake_version: attempt.target().wake_version(),
            expected_generation,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only adapter conformance constructor delegating to the production attempt funnel.
    pub fn for_test(
        scope: DeviceCertificateScope,
        attempt: &eventexec::reconcile::ReconcileAttempt,
        expected_generation: ExpectedGeneration,
    ) -> Result<Self, DeviceCertificateError> {
        Self::from_attempt(scope, attempt, expected_generation)
    }

    /// Authorized tenant/device scope.
    #[must_use]
    pub const fn scope(&self) -> DeviceCertificateScope {
        self.scope
    }
    /// Append-only scheduler attempt identity.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    /// Current provider-issued target lease token.
    #[must_use]
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }
    /// Target-local lease epoch.
    #[must_use]
    pub const fn epoch(&self) -> FenceEpoch {
        self.epoch
    }
    /// Wake version captured by the attempt.
    #[must_use]
    pub const fn wake_version(&self) -> WakeVersion {
        self.wake_version
    }
    /// Desired generation that every mutation must compare.
    #[must_use]
    pub const fn expected_generation(&self) -> ExpectedGeneration {
        self.expected_generation
    }
}

/// Atomic current desired-state read under one scheduler attempt authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateReconcileView {
    fence: CertificateAttemptFence,
    state: DeviceCertificateStateSnapshot,
    deletion_requested: bool,
    transport: CertificateTransportObservation,
}

/// Fenced device transport availability used by command decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateTransportObservation {
    /// The command transport may accept a canonical command.
    Available,
    /// The transport is authoritatively unavailable for this attempt view.
    Unavailable,
}

impl CertificateReconcileView {
    /// Restore a provider view while binding the state generation into every later mutation.
    #[doc(hidden)]
    pub fn restore_current(
        authority: &CertificateAttemptAuthority,
        state: DeviceCertificateStateSnapshot,
        deletion_requested: bool,
        transport: CertificateTransportObservation,
    ) -> Result<Self, DeviceCertificateError> {
        if state.scope() != authority.scope() {
            return Err(DeviceCertificateError::InvalidPersistedValue);
        }
        let generation = ExpectedGeneration::try_new(state.desired().generation().get())?;
        Ok(Self {
            fence: CertificateAttemptFence::restore_current(authority, generation),
            state,
            deletion_requested,
            transport,
        })
    }

    /// Complete mutation fence carrying the storage-selected generation.
    pub const fn fence(&self) -> &CertificateAttemptFence {
        &self.fence
    }
    /// Current validated aggregate snapshot.
    pub const fn state(&self) -> &DeviceCertificateStateSnapshot {
        &self.state
    }
    /// Current internal deletion request state.
    pub const fn deletion_requested(&self) -> bool {
        self.deletion_requested
    }
    /// Fenced transport availability observation.
    pub const fn transport(&self) -> CertificateTransportObservation {
        self.transport
    }
}

/// Fenced condition mutation. `Ready=True` is only available through an unforgeable proof.
#[derive(Debug, PartialEq, Eq)]
pub enum CertificateConditionMutation {
    /// Timestamp-free ordinary condition states.
    States(ConditionStateBatch),
    /// Complete readiness evidence. Providers must atomically write `Ready=True/StateMatches`
    /// and close `Reconciling`, `PendingDevice`, `Degraded`, `Quarantined`, and `Deleting` in the
    /// same fenced transaction; partial lowering violates this variant's contract.
    Ready(Box<CertificateReadyProof>),
}

/// Common append-once artifact persistence result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAppendOutcome {
    /// The receipt was inserted exactly once.
    Appended,
    /// The identical receipt already existed; no row changed.
    Replayed,
    /// The generation was already bound to different immutable evidence; no row changed.
    Conflict,
    /// A lease/wake/generation coordinate was stale; no row changed.
    StaleFence,
}

/// Common result for fenced condition/deletion mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedMutationOutcome {
    /// Mutation committed under the exact fence.
    Applied,
    /// A lease/wake/generation coordinate was stale; no row changed.
    StaleFence,
    /// Desired state was absent; no row changed.
    MissingDesired,
}

/// Exact-one-generation rotation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationOutcome {
    /// Policy was copied to the next generation and the target was woken atomically.
    Rotated {
        /// New desired generation.
        generation: ExpectedGeneration,
        /// Best-effort post-commit notification hint.
        wake: ReconcileWake,
    },
    /// A lease/wake/generation coordinate was stale; no row changed.
    StaleFence,
    /// The current generation cannot advance; no row changed.
    GenerationExhausted,
}

/// Internal deletion request result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionRequestOutcome {
    /// Deletion request and wake committed atomically.
    Requested(ReconcileWake),
    /// An identical deletion request already exists; no row changed.
    Replayed,
    /// A lease/wake/generation coordinate was stale; no row changed.
    StaleFence,
}

/// Closed result of checking the current-generation command's durable overall deadline.
///
/// The repository selects the command, optimistic version, and authoritative transaction time.
/// Callers can supply only the sealed reconcile-attempt fence, so an arbitrary command or clock
/// cannot be used to manufacture expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentCommandExpiryOutcome {
    /// No active or previously timed-out command exists for the current desired generation.
    NoCurrent,
    /// The current active command's durable overall deadline has not elapsed.
    NotDue,
    /// The current active command advanced exactly once to `timed_out`.
    Expired,
    /// The latest command for this generation was already durably timed out.
    AlreadyExpired,
    /// The reconcile attempt lost its lease, epoch, wake version, or desired-generation fence.
    StaleFence,
}

/// Closed failure taxonomy for the reconcile-only repository boundary.
#[derive(Debug, thiserror::Error)]
pub enum CertificateReconcileRepositoryError {
    /// Mutation could not be represented without weakening a domain invariant.
    #[error("certificate reconcile mutation is invalid")]
    InvalidMutation,
    /// Persisted state failed a restore funnel.
    #[error("certificate reconcile storage returned invalid state")]
    CorruptState(#[source] DeviceCertificateError),
    /// The command provider rejected a permanent, corrupt, or invariant-breaking expiry path.
    #[error("certificate reconcile command expiry violated a durable invariant")]
    CommandInvariant(#[source] deviceloop::DeviceCommandStoreError),
    /// Storage or its transaction was unavailable.
    #[error("certificate reconcile storage is unavailable")]
    StorageUnavailable {
        /// Opaque provider failure retained for diagnostics.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl CertificateReconcileRepositoryError {
    /// Preserve provider diagnostics without widening the closed failure taxonomy.
    pub fn storage_unavailable(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::StorageUnavailable {
            source: Box::new(source),
        }
    }
}

/// Reconcile-only persistence port. Every mutation requires the same sealed attempt fence; the
/// reconciler has no access to the older unfenced mutation methods through this dependency slot.
#[trait_variant::make(CertificateReconcileRepository: Send)]
#[allow(async_fn_in_trait)]
pub trait CertificateReconcileRepositoryLocal<E: ArtifactEligibility>: Send + Sync {
    /// Load the desired/reported/condition snapshot under the current attempt coordinates.
    async fn load_current_view(
        &self,
        authority: &CertificateAttemptAuthority,
    ) -> Result<Option<CertificateReconcileView>, CertificateReconcileRepositoryError>;

    /// Load every retained immutable artifact receipt for deletion and current-state decisions.
    async fn load_artifact_receipts(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<Vec<PersistedCertificateArtifactSnapshot<E>>, CertificateReconcileRepositoryError>;

    /// Load the reviewed current canonical command, if one exists for this exact attempt view.
    async fn load_current_command_evidence(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<
        Option<eventexec::reconcile::DeviceCertificateCommandEvidence>,
        CertificateReconcileRepositoryError,
    >;

    /// Expire the selected current-generation command when its provider-owned deadline is due.
    async fn expire_due_current_command(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<CurrentCommandExpiryOutcome, CertificateReconcileRepositoryError>;

    /// Append one current-generation receipt or return a closed zero-write classification.
    async fn append_artifact_receipt(
        &self,
        fence: &CertificateAttemptFence,
        authorization: ArtifactAppendAuthorization<E>,
    ) -> Result<ArtifactAppendOutcome, CertificateReconcileRepositoryError>;

    /// Persist ordinary or proven-ready conditions under the complete attempt fence.
    async fn write_conditions(
        &self,
        fence: &CertificateAttemptFence,
        conditions: CertificateConditionMutation,
    ) -> Result<FencedMutationOutcome, CertificateReconcileRepositoryError>;

    /// Copy current policy, advance exactly one generation, reset conditions, and wake atomically.
    async fn rotate_generation(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<RotationOutcome, CertificateReconcileRepositoryError>;

    /// Set the internal deletion request and wake under expected-generation CAS.
    async fn request_deletion(
        &self,
        fence: &CertificateAttemptFence,
    ) -> Result<DeletionRequestOutcome, CertificateReconcileRepositoryError>;
}
