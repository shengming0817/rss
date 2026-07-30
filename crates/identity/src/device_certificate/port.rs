//! Domain-shaped async repository port for device-certificate persistence.

use dynosaur::dynosaur;

use super::{
    ConditionStateBatch, ConditionUpsertOutcome, DesiredStateCas, DesiredStateSnapshot,
    DeviceCertificateError, DeviceCertificateScope, DeviceCertificateStateSnapshot,
    ExpectedGeneration, ReportedStateWrite, ReportedWriteOutcome,
};

/// Closed result of expected-generation desired-state compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredCasOutcome {
    /// The desired row was written and restored through the validated snapshot funnel.
    Applied(DesiredStateSnapshot),
    /// Storage observed another current generation. No row was written.
    Conflict {
        /// Actual generation; zero denotes row absence.
        actual: ExpectedGeneration,
    },
}

/// Infrastructure failure at the device-certificate repository boundary.
#[derive(Debug, thiserror::Error)]
pub enum DeviceCertificateRepositoryError {
    /// A validated mutation still cannot be lowered to the configured storage representation.
    #[error("device-certificate mutation cannot be represented by storage")]
    InvalidMutation,
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

/// Identity-owned desired/reported/condition persistence port.
///
/// Command, receipt, operation, scheduler, readiness, and current-epoch decisions are absent from
/// this API by construction.
#[trait_variant::make(DeviceCertificateRepository: Send)]
#[dynosaur(
    pub DynDeviceCertificateRepository = dyn(box) DeviceCertificateRepository,
    bridge(dyn)
)]
#[allow(async_fn_in_trait)]
pub trait DeviceCertificateRepositoryLocal: Send + Sync {
    /// Atomically compare expected desired generation and write only on exact match.
    async fn compare_and_swap_desired(
        &self,
        input: DesiredStateCas,
    ) -> Result<DesiredCasOutcome, DeviceCertificateRepositoryError>;

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
