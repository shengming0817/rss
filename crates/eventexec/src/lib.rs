//! eventexec — 事件执行与 saga 编排运行时。
//!
//! 已写实：`consumer`（ConsumerBase + DLX）/ `relay`（outbox relay/sweeper worker）/ `reconcile`
//! （控制环 harness）/ `saga`（[`SagaExecutorImpl`] durable intent/permit + typed recovery + 逆序补偿）/
//! `run_dispatch` / `ConsumerError::new`。少量历史接缝的覆盖率豁免见 ADR-004 C8。
//!
//! ref: watermill message/message.go+pubsub.go+router.go@master
//!      oxidecomputer/steno src/saga_action_generic.rs@main
//!      serverlesstechnology/cqrs（背景 relay 解耦 + 取消安全两阶段关闭）

pub mod consumer;
pub use consumer::{ConsumerMeta, LeaseConfig, run_consumer, run_consumer_ackable};
pub mod tenant_authority;
pub use tenant_authority::{
    TenantAuthority, TenantAuthorityBinding, TenantAuthorityConfigError, TenantAuthorityError,
    TenantAuthoritySignError,
};

pub mod consumer_worker;
pub use consumer_worker::{
    EVENT_CONSUMER_PROBE, run_ackable_subscription_loop, spawn_consumer, spawn_consumer_ackable,
    spawn_consumer_ackable_subscriber, spawn_relay,
};

pub mod managed_blocking_worker;
pub use managed_blocking_worker::{
    ManagedBlockingWorker, spawn_on_dedicated_runtime,
    spawn_on_dedicated_runtime_with_build_failure,
};

// 命令分发 runtime：generated seam → reviewed command capability → provider store，命令不再借事件 emitter。
pub mod command;

// 事件 authoring runtime：generated sealed contract → reviewed event capability；普通 EventEntry
// 无法转换成该能力。
pub mod event;

pub mod relay;
pub use relay::{
    OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE, RelayWorker,
    SWEEPER_WORKER_NAME, SamplerWorker, SweeperWorker, WorkerHealth, WorkerStoppedGuard,
    backlog_sampler_loop, relay_loop, sweeper_loop,
};

// #1209 outbox relay 配置护栏（构造期 fail-fast）+ 可观测性发射端口（注入式）。
pub mod relay_config;
pub use relay_config::{
    RELAY_BUDGET_MAX_MILLIS, RelayBudget, RelayBudgetError, RelayConfig, RelayConfigError,
    SamplerConfig, SamplerConfigError, SweeperConfig, SweeperConfigError,
};
pub mod relay_metrics;
pub use relay_metrics::{MetricsOutboxMetrics, OutboxMetricScope, OutboxMetrics, RelayPhase};

pub mod dlq;
pub use dlq::{
    AuthorizedDlqOperatorReceipt, DeadLetterId, DlqCursor, DlqEntryKind, DlqEntrySummary, DlqError,
    DlqInspectRequest, DlqInspectTarget, DlqListQuery, DlqListResult, DlqMutationKind,
    DlqMutationMetricOutcome, DlqRedriveOutcome, DlqRedriveRequest, DlqReplayOutcome,
    DlqReplayRequest, DlqStore, OperatorDlqCapability, OutboxExpiredResolutionKind,
    OutboxExpiredResolutionOutcome, OutboxExpiredResolutionRequest, OutboxResolutionChangeTicket,
    VerifiedOperatorSubject, record_dlq_mutation_error, record_dlq_outbox_redrive,
    record_dlq_replay, record_outbox_expired_resolution,
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

pub mod reconcile;
pub use reconcile::{
    AttemptErrorKind, AttemptResult, AttemptScope, AttemptTrigger, BackoffError, BackoffPolicy,
    Builder as ReconcileBuilder, ClaimedTarget, DeviceCommandAuditProofRestoreError,
    DurableReconciler, FencedCommandReviewError, OperatorReconcileCapability, RECONCILE_PROBE,
    ReconcileAttempt, ReconcileConfigError, ReconcileLoop, ReconcileMaxInFlight,
    ReconcileOperatorStore, ReconcileQuarantineReason, ReconcileScheduleError,
    ReconcileScheduleErrorKind, ReconcileScheduleStore, ReconcileSchedulerBuilder,
    ReconcileTargetStatus, ReconcileTargetSummary, ReconcileWorker, ReconcileWorkerControl,
    ReviewedFencedCommand, ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleLeaseOutcome,
    Tenancy, Trigger, TriggerError,
};

pub mod projection;
pub use projection::{
    ConformingProjectionTarget, PROJECTION_WORKER_PROBE, ProjectionActivePointer,
    ProjectionDedupeKey, ProjectionHarness, ProjectionId, ProjectionPoisonPolicy,
    ProjectionProjector, ProjectionRegistryError, ProjectionRun, ProjectionRunnerConfig,
    ProjectionRunnerConfigError, ProjectionSelector, ProjectionSelectorError, ProjectionStop,
    ProjectionTarget, ProjectionTargetConfigError, ProjectionTargetRegistry, ProjectionTargetStore,
    ProjectionTargetStoreError, ProjectionTargetStoreErrorKind, ProjectionTargetStoreOutcome,
    ProjectionVersion, ValidatedProjectionApply, projection_runner_loop, projection_runner_once,
    spawn_projection_worker,
};

mod workflow_runtime;
pub use workflow_runtime::{
    ActivatedWorkflow, ActivatedWorkflowActivation, ActivatedWorkflowsView, ProjectionCaptureView,
    ProjectionRuntimeFactory, ProjectionSourceScope, ProjectionTargetEntry, ProjectionTargetView,
    SagaRuntimeEntry, SagaRuntimeFactory, SagaRuntimeView, WorkflowCapabilityCatalog,
    WorkflowRuntimeError, WorkflowRuntimePlan,
};

pub mod saga;
pub use saga::{
    SagaActionError, SagaAttemptOutcome, SagaCompensationContext, SagaDefinitionRegistry,
    SagaDefinitionRegistryBuilder, SagaDefinitionRegistryError, SagaDefinitionRegistryLookupError,
    SagaExecStatus, SagaExecutor, SagaExecutorConfig, SagaExecutorConfigError, SagaExecutorDeps,
    SagaExecutorImpl, SagaForwardContext, SagaId, SagaInterruption, SagaOperatorRecoveryOutcome,
    SagaOutcome, SagaPolicyError, SagaProbeOutcome, SagaStep, SagaSuccessReceiptError,
    SagaSuccessReference, SagaTailer, TypedSagaActionFactory, TypedSagaActionFactoryBuilder,
};

pub mod saga_worker;

/// Generated saga fixtures exposed only to non-shipped integration harnesses.
#[cfg(feature = "test-support")]
pub mod saga_test_support {
    pub use generated::saga::billing_v1;
}
pub use saga_worker::{
    SAGA_EXECUTOR_PROBE, SagaWorker, SagaWorkerConfig, saga_executor_probe_name, spawn_saga_worker,
};

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;

// 消息原语（Message / MessageId / EnvelopeMetadata / MessageStream）随 Subscriber DI port 迁 `diport`
// （issue #1075，ADR-003 DI port 收敛）；本 crate 经 `diport::Message` 消费（HandlerFn/ConsumerFn 入参）。
// 统一 delivery envelope（#1160）：`Message.metadata: diport::EnvelopeMetadata` 从 broker header 透传，
// handler 经 `msg.metadata.get(..)` / `.occurred_at_secs()` 读 transport-safe occurred_at / correlation 等元数据；
// subjectId / actor 是 persisted-only，不从 broker header 回流。
use diport::{Message, RedactedSource};

// ── 处理结论 ─────────────────────────────────────────────────────────────────

/// 处理结论（显式化 watermill 隐式 ack：Nack=不重入队，Requeue=重入队+可退避）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    Ack,
    Nack,
    Requeue { after: Option<Duration> },
}

// ── 处理器类型别名 ────────────────────────────────────────────────────────────

/// 单消息 handler（对齐 watermill HandlerFunc，去掉 `[]*Message` 输出——输出经 Publisher DI port）。
pub type HandlerFn = Arc<dyn Fn(Message) -> BoxFuture<'static, Disposition> + Send + Sync>;

/// 带错误通道的 consumer（区分业务 Nack 与基础设施故障）。
pub type ConsumerFn =
    Arc<dyn Fn(Message) -> BoxFuture<'static, Result<Disposition, ConsumerError>> + Send + Sync>;

// ── Consumer 错误 ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("consumer failed")]
pub struct ConsumerError {
    #[source]
    source: RedactedSource,
}

impl ConsumerError {
    pub fn new<E: std::error::Error + Send + Sync + 'static>(source: E) -> Self {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// 主题初始化接缝（`SubscribeInitializer`）与 Subscriber 内部接缝（`EventSubscriber` → `Subscriber`）
// 及 `MessageStream` / `SubscribeInitError` 随 Subscriber DI port 迁 `diport`（issue #1075，
// ADR-003 DI port 收敛）；消费方经 `diport::{Subscriber, SubscribeInitializer, MessageStream}` 注入。

// ── 单消费者分发驱动（RW-G1 追踪弹）────────────────────────────────────────────

/// 单条消息**含首投**在内的最大消费次数（防 `Requeue` 无限重试挂线程）。
///
/// 语义：首投 1 次 + 至多 `MAX_REDELIVERY - 1` 次重投 = 总计至多 `MAX_REDELIVERY` 次 handler 调用。
/// 真实 broker 退避 / DLX 留 W。
pub const MAX_REDELIVERY: u32 = 3;

/// 单消费者分发驱动：逐条消费订阅流 → [`HandlerFn`] → 按 [`Disposition`] 收口。
///
/// 顺序消费 `stream`（取消即流终止——由 [`diport::Subscriber`] 实现据 `CancellationToken` 收口，
/// 本驱动不持 token）；每条消息按 handler 返回的 disposition 处理：
/// - [`Disposition::Ack`]：完成。
/// - [`Disposition::Nack`]：丢弃（in-mem 无 DLQ；真实 broker DLX 留 W）。
/// - [`Disposition::Requeue`]：重投，上限 [`MAX_REDELIVERY`] 次（in-mem 不 honor backoff `after`，
///   真实 broker 退避留 W）——刻意**不**复制 watermill 无限重试循环（会挂消费线程）。
///
/// 下游事件经 handler 自持的 [`diport::Publisher`] 发布，不经本驱动中转（与 watermill router
/// 内置 publisher 偏离，对齐 RSS DI port 隔离）。
/// ref: watermill message/router.go@fbce4d6cd13c8657c668c7e7990fef90d2471b8a（handleMessage Ack/Nack 决策）
pub async fn run_dispatch(mut stream: diport::MessageStream, handler: HandlerFn) {
    use futures::StreamExt;
    while let Some(msg) = stream.next().await {
        dispatch_one(&handler, msg).await;
    }
}

/// 处理单条消息：按 [`Disposition`] 收口（bounded 重投）。从 [`run_dispatch`] 抽出，
/// 控制各自认知复杂度 ≤15（rust-standards §工程护栏）。
async fn dispatch_one(handler: &HandlerFn, msg: Message) {
    // 含首投在内至多 MAX_REDELIVERY 次（bounded，防 Requeue 无限重试）。日志收口到 helper 控制复杂度。
    for _ in 0..MAX_REDELIVERY {
        match handler(msg.clone()).await {
            Disposition::Ack => return,
            Disposition::Nack => {
                log_dropped_nack(&msg);
                return;
            }
            Disposition::Requeue { .. } => continue,
        }
    }
    log_dropped_exhausted(&msg);
}

/// 静默丢失是审计/合规盲点——Nack 丢弃前结构化记录（in-mem 无 DLQ；真实 broker DLX 留 W）。
fn log_dropped_nack(msg: &Message) {
    tracing::warn!(
        message_id = msg.id.as_str(),
        "dispatch: handler nacked, message dropped (in-mem, no DLQ)"
    );
}

/// Requeue 达上限仍未 Ack/Nack——丢弃前结构化记录。
fn log_dropped_exhausted(msg: &Message) {
    tracing::error!(
        message_id = msg.id.as_str(),
        attempts = MAX_REDELIVERY,
        "dispatch: requeue budget exhausted, message dropped"
    );
}

// ── smoke tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_send_sync<T: Send + Sync + ?Sized>() {}

    #[test]
    fn message_and_handler_fn_are_send_sync() {
        _assert_send_sync::<Message>();
        _assert_send_sync::<HandlerFn>();
    }

    #[test]
    fn disposition_variants_exhaustive_match() {
        let variants: &[Disposition] = &[
            Disposition::Ack,
            Disposition::Nack,
            Disposition::Requeue { after: None },
            Disposition::Requeue {
                after: Some(Duration::from_secs(1)),
            },
        ];
        for d in variants {
            // 同 crate 内 #[non_exhaustive] 不强制 _ 臂；穷尽匹配验证变体可达
            let _ = match d {
                Disposition::Ack => "ack",
                Disposition::Nack => "nack",
                Disposition::Requeue { .. } => "requeue",
            };
        }
    }

    #[test]
    fn disposition_clone_eq() {
        assert_eq!(Disposition::Ack, Disposition::Ack.clone());
        assert_eq!(
            Disposition::Requeue { after: None },
            Disposition::Requeue { after: None },
        );
    }

    #[test]
    fn consumer_fn_is_send_sync() {
        // ConsumerFn 是 Arc<dyn Fn..> 别名，?Sized 断言 object-safe + Send+Sync
        _assert_send_sync::<ConsumerFn>();
    }

    // SubscribeInitializer / EventSubscriber 的 Send+Sync/object-safe smoke 随其迁 `diport`
    // （diport::subscriber::smoke）；此处不再断言（类型已不在本 crate）。

    // ── run_dispatch 分发驱动（RW-G1 已写实）────────────────────────────────────

    use std::sync::atomic::{AtomicU32, Ordering};

    fn stream_of(payloads: &[&[u8]]) -> diport::MessageStream {
        let msgs: Vec<Message> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| Message::new(format!("m-{i}"), p.to_vec()))
            .collect();
        Box::pin(futures::stream::iter(msgs))
    }

    /// 计数 handler：记录调用次数并按 `disp` 返回。
    fn counting_handler(counter: Arc<AtomicU32>, disp: Disposition) -> HandlerFn {
        Arc::new(move |_msg| {
            let counter = counter.clone();
            let disp = disp.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::Relaxed);
                disp
            })
        })
    }

    #[tokio::test]
    async fn dispatch_invokes_handler_per_message_on_ack() {
        let counter = Arc::new(AtomicU32::new(0));
        run_dispatch(
            stream_of(&[b"a", b"b", b"c"]),
            counting_handler(counter.clone(), Disposition::Ack),
        )
        .await;
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn dispatch_nack_drops_without_retry() {
        let counter = Arc::new(AtomicU32::new(0));
        run_dispatch(
            stream_of(&[b"a"]),
            counting_handler(counter.clone(), Disposition::Nack),
        )
        .await;
        // Nack：单次调用即丢弃（无重投）。
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dispatch_requeue_is_bounded() {
        let counter = Arc::new(AtomicU32::new(0));
        run_dispatch(
            stream_of(&[b"a"]),
            counting_handler(counter.clone(), Disposition::Requeue { after: None }),
        )
        .await;
        // Requeue：bounded 重投，恰 MAX_REDELIVERY 次（非无限循环）。
        assert_eq!(counter.load(Ordering::Relaxed), MAX_REDELIVERY);
    }

    #[tokio::test]
    async fn dispatch_requeue_then_ack_stops_early() {
        // 前 2 次 Requeue、第 3 次 Ack：恰 3 次调用（< 上限的提前收敛）。
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let handler: HandlerFn = Arc::new(move |_msg| {
            let c = c.clone();
            Box::pin(async move {
                let n = c.fetch_add(1, Ordering::Relaxed) + 1;
                if n < 3 {
                    Disposition::Requeue { after: None }
                } else {
                    Disposition::Ack
                }
            })
        });
        run_dispatch(stream_of(&[b"a"]), handler).await;
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn consumer_error_redacts_source_debug_and_chain() {
        let err = ConsumerError::new(std::io::Error::other("redis://user:hunter2@cache"));
        assert_eq!(err.to_string(), "consumer failed");
        let dbg = format!("{err:?}");
        assert!(!dbg.contains("hunter2"), "Debug 泄漏 source: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted>: {dbg}");
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "first source is RedactedSource");
        let Some(source) = source else {
            return;
        };
        assert_eq!(source.to_string(), "<redacted>");
        assert!(
            std::error::Error::source(source).is_none(),
            "source chain must stop at RedactedSource"
        );
    }
}
