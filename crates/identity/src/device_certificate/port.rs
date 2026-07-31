//! Domain-shaped async repository port for device-certificate persistence.

use dynosaur::dynosaur;

use super::{
    AcceptDesiredPolicy, ConditionStateBatch, ConditionUpsertOutcome, DesiredPolicyAccepted,
    DeviceCertificateError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    ExpectedGeneration, ReportedStateWrite, ReportedWriteOutcome,
};
use eventexec::reconcile::ReconcileWake;

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
}

/// Identity-owned desired-policy operation and reported/condition persistence port.
///
/// The desired accept method owns its narrow operation/idempotency and existing-target due join;
/// command, receipt, readiness, and current-epoch decisions remain absent by construction.
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

    /// Advance reported storage high-water or return a closed zero-write classification.
    async fn advance_reported(
        &self,
        input: ReportedStateWrite,
    ) -> Result<ReportedWriteOutcome, DeviceCertificateRepositoryError>;

    /// Upsert timestamp-free closed condition states without deleting omitted kinds.
    async fn upsert_condition_states(
        &self,
        scope: DeviceCertificateScope,
        conditions: ConditionStateBatch,
    ) -> Result<ConditionUpsertOutcome, DeviceCertificateRepositoryError>;

    /// Load validated current persistence state, or `None` when desired is absent.
    async fn load_state(
        &self,
        scope: DeviceCertificateScope,
    ) -> Result<Option<DeviceCertificateStateSnapshot>, DeviceCertificateRepositoryError>;
}
