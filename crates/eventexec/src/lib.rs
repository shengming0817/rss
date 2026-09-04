//! Provider-neutral orchestration for transactional messaging and retained recovery workflows.

pub mod dead_letter;
pub use dead_letter::{DeadLetterId, DeadLetterIdError};
pub mod tenant_authority;
pub use tenant_authority::{
    TenantAuthority, TenantAuthorityBinding, TenantAuthorityConfigError, TenantAuthorityError,
    TenantAuthoritySignError,
};

mod worker_health;
pub use worker_health::WorkerHealth;

pub mod projection_metrics;
pub use projection_metrics::{
    MetricsProjectionMetrics, ProjectionMetric, ProjectionMetricActivation, ProjectionMetricScope,
    ProjectionMetrics, ProjectionProcessedOutcome,
};

pub mod dlq;
pub use dlq::{
    DlqCursor, DlqEntryKind, DlqEntrySummary, DlqError, DlqInspectRequest, DlqInspectTarget,
    DlqListQuery, DlqListResult, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayOutcome,
    DlqReplayRequest, DlqReplayStoreStage, DlqStore, DurablyAuditedDlqMutation,
    OutboxExpiredResolutionKind, OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest,
    OutboxResolutionChangeTicket, record_dlq_outbox_redrive, record_dlq_outbox_redrive_error,
    record_dlq_replay, record_dlq_replay_error, record_outbox_expired_resolution,
    record_outbox_expired_resolution_error,
};

pub mod dr_admission_runtime;
pub mod dr_recovery;
pub use dr_admission_runtime::{
    DrAdmissionCommand, DrAdmissionCommandPhase, DrAdmissionCommandStore,
    DrAdmissionProcessIdentity, DrAdmissionRuntimeError, run_dr_admission_controller,
};
pub use dr_recovery::{
    AuthorizedL2DrRecoveryPlan, L2DrRecoveryDurableReceipt, L2DrRecoveryDurableStartProof,
    L2DrRecoveryError, L2DrRecoveryOperatorSubject, L2DrRecoveryOutcome, L2DrRecoveryPlan,
    L2DrRecoveryPlanDigest, L2DrRecoveryReceipt, L2DrRecoveryStore, OperatorL2DrRecoveryCapability,
    RecoveryChangeTicket, RecoveryDirection, RecoveryEpochId, RecoveryEventSet,
    RequiredAdmissionFence, UtcEpochMicros,
};

pub mod dlx_lifecycle;
pub use dlx_lifecycle::{
    DLX_HOT_RETENTION_SECONDS, DlxArchiveKeyName, DlxArchiveObjectKey, DlxHotKeyName, DlxLifecycle,
    DlxLifecycleHealth, DlxLifecycleTickReport, ExpiredArchiveReceipt, MissingArchiveProof,
    RetentionBacklog, RetentionBacklogObservation, RetentionOutcome, RetentionTarget,
    VerifiedArchiveReceipt, apply_dlx_lifecycle_health,
};
mod dlx_archive_record;
pub use dlx_archive_record::{
    ArchiveCanonicalRecord, DlxArchiveCandidate, DlxArchiveSafeMetadata,
    DlxArchiveSafeMetadataInput, DlxMetadataDigest,
};
mod dlx_archive_cipher;
pub mod dlx_lifecycle_metrics;
pub use dlx_lifecycle_metrics::{MetricsRetentionMetrics, RetentionMetrics};
