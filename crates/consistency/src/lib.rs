//! consistency — RSS 一致性引擎接缝：outbox / inbox / saga / reconcile / projection / idempotency 纯态机 + 策略 trait（引擎层 L0–L4，依赖基础层）。
//!
//! # 派发范式（ADR-003 §2 / ADR-004 C1）
//!
//! 本 crate 冻结的是**引擎策略 trait**（L0–L4 一致性等级）：`InboxStore`/`OutboxRelay`/
//! `Reconciler`/`Projector` 一律 **native AFIT**（trait 内直接 `async fn`）+ **泛型静态分发**
//! （消费方 `fn run<S: Trait>(s: &S)`，零开销、零 box）——**不引 dynosaur、不引 async-trait**。
//! native AFIT trait 不 object-safe，故全 crate 禁 `Box<dyn Trait>`：消费方一律泛型 `<S: Trait>`。
//! Saga authoring 已收口到 `eventexec::SagaStep<GeneratedStepMarker>`；本 crate 只拥有其 durable
//! identity、journal/replay 纯模型，避免平行 factory/runtime contract。
//!
//! 这些是引擎侧策略接缝，**非** DI 注入 infra port（provider-可换的 Store/Publisher/Clock 走 dynosaur，
//! 归未来 `diport` crate，不在本 crate）。错误用本地 [`EngineError`]（thiserror，message `&'static str`
//! const，ADR-004 C10）。engine 类型**不** derive serde（ADR-004 C6）。
//!
//! ref: kube-rs kube-runtime/src/{controller,watcher}.rs@main（Reconciler 函数式接缝 + 内部 native AFIT）；
//! oxidecomputer/steno src/saga_action_generic.rs@main（saga do/undo + 逆序补偿）。
//!
//! # 模块一致性等级
//!
//! | 模块 | 等级 |
//! |------|------|
//! | idempotency | L0 |
//! | command_journal | L1/L2 |
//! | inbox | L0/L2 |
//! | outbox | L1/L2 |
//! | saga | L3 |
//! | reconcile | L4 |
//! | projection | L3 |

pub mod command_journal;
pub mod error;
pub mod idempotency;
pub mod inbox;
pub mod localtx;
pub mod outbox;
pub mod projection;
pub mod reconcile;
pub mod saga;
pub mod tx_retry;

pub use command_journal::{
    CommandAttempt, CommandAttemptError, CommandErrorSummary, CommandIdempotencyKey,
    CommandJournalOutcome, CommandJournalStatus, CommandJournalTerminalSummary,
    CommandJournalValueError, CommandRequestFingerprint, CommandResultSummary,
};
pub use error::{EngineError, EngineErrorKind};
pub use idempotency::{
    ConsumerGroup, ConsumerGroupError, IdemKey, IdemKeyError, LeaseOutcome, LeaseToken, SeenState,
};
pub use inbox::{
    INBOX_RECEIPT_CORRELATION_MAX_LEN, INBOX_RECEIPT_TRACE_MAX_LEN, InboxBacklog,
    InboxBacklogScope, InboxClaim, InboxLeaseFreshness, InboxReceiptContext,
    InboxReceiptContextError, InboxState, InboxStatus, InboxStatusError, InboxStore,
};
pub use localtx::{
    LocalTxBoundary, LocalTxCommitUnknown, LocalTxDeadlineStage, LocalTxExecutionBudget,
    LocalTxExecutionBudgetError, LocalTxFinalStatus, LocalTxModel, LocalTxRetry,
};
pub use outbox::{
    BacklogMetricSample, BacklogObservation, BacklogSample, Disposition, EventEntry, EventTopic,
    EventTopicError, HandleResult, OutboxAppendOutcome, OutboxBacklog, OutboxContractId,
    OutboxContractIdError, OutboxFactConflict, OutboxFactFingerprint, OutboxFactIdentity,
    OutboxMetricSubject, OutboxPayload, OutboxRelay, PartitionKey, PartitionKeyError,
    PermanentError, PermanentErrorKind, RetentionSweeper, Settled, StoredOutboxEntry,
    StoredOutboxEntryError, StoredOutboxTopic, is_canonical_topic_name,
};
pub use projection::{
    Lsn, PartitionSerialDelivery, ProjectionApplyError, ProjectionApplyErrorKind,
    ProjectionApplyErrorReason, ProjectionApplyOutcome, ProjectionBatchLimit,
    ProjectionBatchLimitError, ProjectionCheckpoint, ProjectionCheckpointError,
    ProjectionDeadLetter, ProjectionDeadLetterReason, ProjectionEvent, ProjectionEventMetadata,
    ProjectionEventRecord, ProjectionEventSource, Projector, SerialInOrder, SerialInOrderGuarantor,
};
pub use reconcile::{
    ActualState, Context, ConvergeAction, DesiredState, DriftKind, EntityId, EntityIdError,
    Outcome, ReconcileDiff, ReconcileError, ReconcileResultLabel, Reconciler, Request,
};
pub use saga::{
    CompensationOutcome, SagaAttempt, SagaAttemptError, SagaCompensationCause, SagaContractId,
    SagaContractIdError, SagaDefinition, SagaDefinitionIdentity, SagaDefinitionIdentityError,
    SagaDurableStatus, SagaEffectPhase, SagaId, SagaIdempotencyKey, SagaInstanceRecord,
    SagaInstanceRecordError, SagaInstanceRef, SagaInstanceRefError, SagaInstanceStatus,
    SagaInterruption, SagaJournalRecord, SagaJournalStatus, SagaLease, SagaLeaseError,
    SagaLeaseOutcome, SagaModelError, SagaOperatorReason, SagaOutcome, SagaReceiptFormatVersion,
    SagaReceiptFormatVersionError, SagaReceiptScope, SagaReceiptScopeError, SagaReplayDecision,
    SagaWorkerIdentity, SagaWorkerIdentityError,
};
pub use tx_retry::{
    TxRetryBackoff, TxRetryClass, TxRetryFinalStatus, TxRetryPolicy, TxRetryPolicyError,
    TxRetryReport, run_tx_retry,
};
