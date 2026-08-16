//! 受监督的事件消费后台 worker（`ManagedResource` 两阶段关闭）。
//!
//! 把 [`crate::run_consumer`]（at-most-once / MemBus）/ [`crate::run_consumer_ackable`]
//! （at-least-once / AMQP broker settle）接成真实运行的后台 worker：Demo 路径组合根先订阅得
//! `MessageStream` 再 [`spawn_consumer`]；Durable ackable 路径经 [`run_ackable_subscription_loop`]
//! 在 worker 线程内 subscribe（失败/断流 until-cancel 退避重入）再驱动消费。经
//! [`crate::ManagedBlockingWorker`] 专用线程 + `bootstrap::ShutdownStack` 两阶段关闭，
//! [`crate::WorkerHealth`] 供 readyz 聚合。
//!
//! # 为什么用专用 OS 线程而非 `tokio::spawn`（与 `relay.rs` 的关键分岔）
//!
//! `run_consumer` / `run_consumer_ackable` 的 future 是 **`!Send`**：`consume_one` 跨 `.await` 持
//! `&DynDeadLetterStore`（ackable 路径另持 `&DynAcker`），而 `DynDeadLetterStore` / `DynAcker` 是
//! `#[trait_variant::make(_: Send)]` + `#[dynosaur(dyn(box) _)]` 生成的 **Send-但-非-Sync** wrapper
//! （`&T: Send ⟺ T: Sync`）⇒ `&DynX` 跨 await 即 `!Send`。故**不能**像 [`crate::RelayWorker`] 那样
//! `tokio::spawn`（要求 future `Send`）。
//!
//! 解法：在**专用 OS 线程**上建 current-thread runtime `block_on` 驱动 `!Send` future——
//! [`std::thread::spawn`] 只要求**捕获值** `Send`（`MessageStream` / `DeliveryStream` / DLX / `Arc<S>` /
//! handler 全 Send），future 在线程内构建与轮询、**不跨线程**，无需 `Send`。此法**零改** #1142 冻结接缝
//! （`run_consumer*` / `settle` / DLX 签名不动）。bins（HTTP server + consumer 同 multi-thread runtime）本就
//! 无法 `tokio::spawn` 这些 `!Send` future，专用线程是必需形态、非权宜。
//!
//! # 订阅与取消
//!
//! **Demo（compose-first）**：组合根**先**订阅（`subscribe(topic, token)`）得 stream、**再**
//! [`spawn_consumer`] 驱动该 stream——保证订阅在发布之前完成（in-mem MemBus 无重放，订阅须先于
//! 发布），且 stream 与 worker 共用同一 [`CancellationToken`]。worker 关闭时
//! [`diport::ManagedResource::shutdown`] 取消该 token → subscriber 流终止（MemBus `take_until` /
//! AMQP channel close → broker requeue in-flight）→ loop 退出 → `block_on` 返回 → 线程结束。组合根经
//! `ShutdownStack::register_detached` 注册（worker 自持 token、在 `shutdown` 中自取消，不依赖 stack 阶段 1
//! 广播）。
//!
//! **Durable（supervise-until-cancel）**：组合根经 [`spawn_consumer_ackable_subscriber`] /
//! composition `spawn_consumer_ackable_tx_subscriber` 把 `subscribe_ackable` 放进 worker 线程，并由
//! [`run_ackable_subscription_loop`] 监督：subscribe 失败与 delivery stream 非取消终止均指数退避重入，
//! 直到 shutdown token 取消。成功订阅后重置 attempt，并以 CAS 仅在 `starting`|
//! `subscriber-unavailable` → Healthy（[`WorkerHealth::mark_subscription_recovered`]，不洗掉
//! `dlx-write-error`）；失败/断流标 `subscriber-unavailable`（不覆盖 DLX/invariant；与初始
//! `starting` 同为 Unhealthy，但 detail 可区分）。
//!
//! 关闭：[`diport::ManagedResource::shutdown`] 取消 worker token 后等待专用线程发回的 completion；不在
//! Tokio blocking pool 执行 `JoinHandle::join`，因此整体 shutdown 预算取消 future 后 runtime drop 仍然
//! 有界。线程 panic 由 `catch_unwind` 收口成 [`diport::ShutdownError`]，**不**静默吞 panic 误报
//! 关闭成功。健康粒度（v1）：
//! 初始 `starting`（Unhealthy）；监督循环成功订阅 → CAS 恢复 `Healthy`（不洗 DLX）；subscribe/断流 →
//! `subscriber-unavailable`（Unhealthy，不覆盖 DLX/invariant）；loop 退出 → `mark_stopped`
//! （Unhealthy，readyz 翻）。per-message settle/dlx 失败降级需
//! loop 内钩子 = 改 #1142 接缝，留 follow-up（现 `consumer_settle_total{outcome}` metric 已覆盖告警）。
//!
//! ref: ThreeDotsLabs/watermill message/router.go@master（`Router.Run` 每 subscriber 一受监督消费循环 +
//!      context 取消逐个收敛；RSS 偏离：per-worker 独立 ManagedResource + readyz 归因，非单 waitgroup）
//!      serverlesstechnology/cqrs（背景 worker 解耦 + 取消安全两阶段关闭，`relay.rs` 同源）
//!      lapin message::Delivery.acker（Durable 路径 manual-ack 生命周期，settle-once）
//!
//! # NOTE：runctx（`AppCtx` task-local）不跨线程传播
//!
//! Worker 跑在专用 OS 线程的独立 current-thread runtime，`runctx::AppCtx` 是
//! task-local——**不跨线程传播**。Handler 实现**禁止**读 `runctx::try_current()`（会返回 `None`）；
//! 租户上下文须从 message payload 解析（本 PR 各 handler 即如此）。
//!
//! # NOTE：AMQP ManagedBlockingWorker（专用线程驱动的真 broker 验证）
//!
//! 专用线程驱动在 demo（MemBus）+ eventexec 单测验证；真 AMQP broker 下经
//! ManagedBlockingWorker（lapin cross-runtime）覆盖。§6 集成 journey
//! （`amqp_consumer_at_least_once_journey.rs`）用 inline `tokio::join!` 同 runtime 驱动
//! `run_consumer_ackable` 证 broker settlement，覆盖接缝的 at-least-once 终态兑现。

use std::sync::Arc;
use std::time::Duration;

use consistency::InboxStore;
use consistency::{HandleResult, OutboxRelay};
use diport::{
    AckableSubscriber, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DeliveryStream,
    DynAckableSubscriber, DynDeadLetterStore, Message, MessageStream, Topic,
};
use futures::StreamExt as _;
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::ManagedBlockingWorker;
use crate::consumer::{ConsumerMeta, LeaseConfig, run_consumer, run_consumer_ackable};
use crate::managed_blocking_worker::spawn_on_dedicated_runtime;
use crate::reconcile::{BackoffPolicy, wait_or_cancel};
use crate::relay::WorkerHealth;

/// readyz probe 名基（event consumer worker；无 `_ready` 后缀——运行时操作 probe，对齐
/// [`crate::OUTBOX_RELAY_PROBE`]）。组合根据此 + domain/topic 组装 per-worker `primitives::ProbeName`
/// （如 `event_consumer:audit:identity.session-created`）接 readyz 聚合（HTTP endpoint mount 归 #1320 / assemblies/runtime）。
pub const EVENT_CONSUMER_PROBE: &str = "event_consumer";

/// consumer worker 关闭超时：每条在途消息 handle + commit + settle 有界 drain，对齐 relay 的 45s 预算。
const CONSUMER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

// ── spawn（专用线程驱动 !Send 消费 future）─────────────────────────────────────

/// DLX store wrapper：发射闭值集写入指标，并在写失败时把 consumer worker 标为 degraded。
///
/// wrapper 只包 consumer worker 路径；不改变 ConsumerBase 的 commit/release/settle 状态机。
struct HealthReportingDlx {
    inner: tokio::sync::Mutex<Box<DynDeadLetterStore<'static>>>,
    health: Arc<WorkerHealth>,
    domain: String,
}

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): eventexec consumer worker 内部包装已注入的 DLX port，用于 worker health/metrics；
// 不新增 provider，不触碰 adapter 资源构造。
impl DeadLetterStore for HealthReportingDlx {
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        let result = inner.write_dead_letter(record).await;
        let outcome = if result.is_ok() {
            "ok"
        } else {
            self.health.mark_dlx_write_error();
            "error"
        };
        metrics::counter!(
            "consumer_dlx_write_total",
            "domain" => self.domain.clone(),
            "outcome" => outcome,
        )
        .increment(1);
        result
    }

    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        let inner = self.inner.lock().await;
        inner.shutdown().await
    }
}

fn health_reporting_dlx(
    dlx: Box<DynDeadLetterStore<'static>>,
    health: Arc<WorkerHealth>,
    meta: &ConsumerMeta,
) -> Box<DynDeadLetterStore<'static>> {
    DynDeadLetterStore::new_box(HealthReportingDlx {
        inner: tokio::sync::Mutex::new(dlx),
        health,
        domain: meta.domain().to_owned(),
    })
}

/// spawn at-most-once 消费 worker（Demo / MemBus 路径，acker=None、不触 broker settle）。
///
/// 组合根先 `subscribe(topic, token)` 得 `stream`、再调本函数；worker 持同一 `token`，`shutdown` 取消即流终止。
#[allow(clippy::too_many_arguments)]
// reason: 9 参数是消费 worker spawn 的最小必要集（name/stream/idem/dlx/meta/handler/lease_cfg/token/health
// 各自语义独立）；聚合 struct 增间接层且无复用，item-level carve-out（error-handling.md §Carve-out）。
pub fn spawn_consumer<S, H>(
    name: String,
    stream: MessageStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    admission: primitives::ConsumerAdmission,
) -> ManagedBlockingWorker
where
    S: InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    spawn_on_dedicated_runtime(
        name,
        token,
        Arc::clone(&health),
        CONSUMER_SHUTDOWN_TIMEOUT,
        move |token| async move {
            health.mark_healthy();
            let stream = Box::pin(stream.take_until(token.cancelled_owned()));
            run_consumer(
                stream,
                idempotency,
                dlx,
                meta,
                handler,
                lease_cfg,
                admission,
            )
            .await;
            Ok(())
        },
    )
}

/// spawn outbox relay worker（专用 OS 线程 + panic-safety `WorkerStoppedGuard` 守卫，与
/// `spawn_consumer_ackable` 对称）。
///
/// `PgOutbox: Send+!Sync` → `Arc<PgOutbox>: !Send` → relay future `!Send`，不可 `tokio::spawn`；
/// 解法：`store: A`（`A: Send`）跨线程移入，在线程内 `Arc::new(store)` 构建——`Arc<A>`（`!Send`）
/// 始终在单一线程持有，无需 `Send`（与 [`crate::RelayWorker`] / OS 线程模式对称）。
///
/// panic-safety：`WorkerStoppedGuard` Drop 守卫覆盖**所有**退出路径（runtime 构建失败、relay future
/// panic unwind、正常返回），确保 `health.mark_stopped()`（readyz Unhealthy）不被 panic 跳过。
/// `relay_loop` 自身在取消后亦调 `mark_stopped`（幂等：两次 store 同值，正常路径无害）。
///
/// 返回的 [`ManagedBlockingWorker`] 持同一 `health` + `token`，shutdown 取消 token → relay_loop break →
/// 线程退出 → completion → Ok（健康态翻 Unhealthy）。
#[allow(clippy::too_many_arguments)]
// reason: relay spawn 参数是唯一 production relay 所需的完整 dependency set；admission 必填，
// 同 spawn_consumer_ackable item-level carve-out（error-handling.md §Carve-out）。
pub fn spawn_relay<A>(
    name: String,
    store: A,
    config: crate::RelayConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn crate::OutboxMetrics>,
    admission: primitives::RelayAdmission,
) -> ManagedBlockingWorker
where
    A: OutboxRelay + Send + 'static,
{
    spawn_on_dedicated_runtime(
        name,
        token,
        Arc::clone(&health),
        CONSUMER_SHUTDOWN_TIMEOUT,
        move |token| async move {
            // Arc::new(store) 在线程内构建：Arc<A>(!Send) 不跨线程；store: A (Send) 跨线程移入。
            let store = Arc::new(store);
            crate::relay::relay_loop(store, config, clock, token, health, metrics, admission).await;
            Ok(())
        },
    )
}

/// spawn at-least-once 消费 worker（**test / compose-first** 路径：调用方已持有 `DeliveryStream`）。
///
/// 生产 durable 订阅的**唯一监督入口**是 [`run_ackable_subscription_loop`]（经
/// [`spawn_consumer_ackable_subscriber`] / composition `spawn_consumer_ackable_tx_subscriber`）。
/// 本函数**无** subscribe 失败/断流监督——组合根若先 `subscribe_ackable` 再调本函数，仅驱动既有
/// stream 直至取消；subscribe 失败不会退避重入。测试与 compose-first 场景（已有 stream）可用；
/// 长驻 durable 生产路径应走 `*_subscriber` API。
///
/// `DeliveryStream` 每条 `Delivery { message, acker }` 终态恰 settle 一次（ack/requeue/reject）。
/// 崩溃窗口（settle 前线程退出）→ channel close → broker requeue in-flight，经幂等去重 =
/// at-least-once 不丢。
#[allow(clippy::too_many_arguments)]
// reason: 同 spawn_consumer——9 参数语义独立，item-level carve-out。
pub fn spawn_consumer_ackable<S, H>(
    name: String,
    stream: DeliveryStream,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    admission: primitives::ConsumerAdmission,
) -> ManagedBlockingWorker
where
    S: InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    spawn_on_dedicated_runtime(
        name,
        token,
        Arc::clone(&health),
        CONSUMER_SHUTDOWN_TIMEOUT,
        move |token| async move {
            health.mark_healthy();
            let stream = Box::pin(stream.take_until(token.cancelled_owned()));
            run_consumer_ackable(
                stream,
                idempotency,
                dlx.as_ref(),
                &meta,
                &handler,
                lease_cfg,
                admission,
            )
            .await;
            Ok(())
        },
    )
}

/// Ackable 订阅监督循环：subscribe 失败与 delivery stream 非取消终止均指数退避重入，直到
/// shutdown token 取消。成功订阅后 [`WorkerHealth::mark_subscription_recovered`]（CAS：仅
/// starting|subscriber-unavailable→healthy）并重置 attempt；失败/断流标
/// `subscriber-unavailable`（不覆盖 dlx-write-error/invariant）。panic 仍由
/// [`ManagedBlockingWorker`] 收口，本循环不建模 handler fatal。
///
/// `run_once` 由调用方以 [`AsyncFnMut`] 注入（可借用 `!Sync` DLX）；spawn 禁止再手写 one-shot
/// `match subscribe_ackable`。
///
/// 可观测：`consumer_subscribe_retry_total{domain,outcome}`（outcome=`subscribe_error`|
/// `stream_end`；topic 不入 label）；日志带 `domain`/`component`=`event_consumer`。
///
/// ref: ThreeDotsLabs/watermill message/router.go@master（受监督消费循环）
///      kube-rs/kube kube-runtime controller backoff（until-cancel）
#[allow(
    clippy::cognitive_complexity,
    clippy::too_many_arguments,
    reason = "the canonical supervised subscriber loop keeps subscribe, pause, health, retry, and shutdown ordering in one closed state machine"
)]
pub async fn run_ackable_subscription_loop<D>(
    subscriber: Box<DynAckableSubscriber<'static>>,
    topic: Topic,
    domain: String,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    backoff: BackoffPolicy,
    admission: primitives::ConsumerAdmission,
    mut run_once: D,
) where
    D: AsyncFnMut(DeliveryStream, primitives::ConsumerAdmission),
{
    let mut attempts = 0_u32;
    loop {
        if token.is_cancelled() {
            return;
        }
        if admission.wait_open().await.is_err() {
            return;
        }
        let subscribe_permit = match admission.try_enter() {
            Ok(permit) => permit,
            Err(primitives::AdmissionError::Paused) => continue,
            Err(primitives::AdmissionError::Stopped) => return,
            Err(error) => {
                tracing::error!(error = %error, "consumer: subscribe admission invariant failed");
                health.mark_invariant();
                return;
            }
        };
        let subscribe_token = token.child_token();
        let subscribe = tokio::select! {
            biased;
            () = token.cancelled() => return,
            _ = admission.wait_closed() => {
                subscribe_token.cancel();
                None
            }
            result = subscriber.subscribe_ackable(topic.clone(), subscribe_token.clone()) => Some(result),
        };
        drop(subscribe_permit);
        let Some(subscribe) = subscribe else {
            continue;
        };
        match subscribe {
            Ok(stream) => {
                attempts = 0;
                health.mark_subscription_recovered();
                let stream = Box::pin(stream.take_until(token.clone().cancelled_owned()));
                run_once(stream, admission.clone()).await;
                if token.is_cancelled() {
                    return;
                }
                if backoff_after_stream_end(
                    &health,
                    &backoff,
                    &token,
                    &mut attempts,
                    &topic,
                    &domain,
                )
                .await
                {
                    return;
                }
            }
            Err(err) => {
                if backoff_after_subscribe_error(
                    &health,
                    &backoff,
                    &token,
                    &mut attempts,
                    &err,
                    &topic,
                    &domain,
                )
                .await
                {
                    return;
                }
            }
        }
    }
}

/// 监督重试 outcome 闭值（metric label；禁止 topic / error text）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscribeRetryOutcome {
    SubscribeError,
    StreamEnd,
}

impl SubscribeRetryOutcome {
    const fn as_label(self) -> &'static str {
        match self {
            Self::SubscribeError => "subscribe_error",
            Self::StreamEnd => "stream_end",
        }
    }
}

fn record_subscribe_retry(domain: &str, outcome: SubscribeRetryOutcome) {
    metrics::counter!(
        "consumer_subscribe_retry_total",
        "domain" => domain.to_owned(),
        "outcome" => outcome.as_label(),
    )
    .increment(1);
}

/// stream 非取消结束：标 unavailable + 退避；`true` = 已 cancel。
async fn backoff_after_stream_end(
    health: &WorkerHealth,
    backoff: &BackoffPolicy,
    token: &CancellationToken,
    attempts: &mut u32,
    topic: &Topic,
    domain: &str,
) -> bool {
    *attempts = attempts.saturating_add(1);
    health.mark_subscriber_unavailable();
    record_subscribe_retry(domain, SubscribeRetryOutcome::StreamEnd);
    tracing::warn!(
        domain = %domain,
        component = EVENT_CONSUMER_PROBE,
        topic = %topic.as_str(),
        attempts = *attempts,
        outcome = SubscribeRetryOutcome::StreamEnd.as_label(),
        "consumer: ackable delivery stream ended; resubscribing after backoff"
    );
    wait_or_cancel(backoff.delay_for(*attempts), token).await
}

/// subscribe 失败：标 unavailable + 退避；`true` = 已 cancel。
async fn backoff_after_subscribe_error(
    health: &WorkerHealth,
    backoff: &BackoffPolicy,
    token: &CancellationToken,
    attempts: &mut u32,
    err: &diport::SubscriberError,
    topic: &Topic,
    domain: &str,
) -> bool {
    *attempts = attempts.saturating_add(1);
    health.mark_subscriber_unavailable();
    record_subscribe_retry(domain, SubscribeRetryOutcome::SubscribeError);
    tracing::warn!(
        domain = %domain,
        component = EVENT_CONSUMER_PROBE,
        topic = %topic.as_str(),
        error = %err,
        attempts = *attempts,
        outcome = SubscribeRetryOutcome::SubscribeError.as_label(),
        "consumer: subscribe_ackable failed; retrying after backoff"
    );
    wait_or_cancel(backoff.delay_for(*attempts), token).await
}

/// spawn at-least-once 消费 worker，并在 worker 线程内用注入的 stack child token 完成订阅。
///
/// 组合根 `WorkerSpec` 闭包是同步的，但 AMQP `subscribe_ackable` 是 async。该函数把订阅放进
/// managed worker 专用线程的 current-thread runtime 内执行，经 [`run_ackable_subscription_loop`]
/// 监督 subscribe/断流重入，使 `ShutdownStack::register_with_token` 注入的 child token 同时驱动
/// 订阅取消与 worker shutdown，满足 `SHUTDOWN-TOKEN-FUNNEL-01`。
///
/// `backoff`：生产传 [`BackoffPolicy::default`]；测试可注入 tiny / 自定义策略。
#[allow(clippy::too_many_arguments)]
// reason: 与 spawn_consumer_ackable 同形；subscriber/topic/backoff 是把 async subscribe 移入 worker
// 线程并注入退避策略所需的最小新增参数，聚合 struct 只会增加间接层。
pub fn spawn_consumer_ackable_subscriber<S, H>(
    name: String,
    subscriber: Box<DynAckableSubscriber<'static>>,
    topic: Topic,
    idempotency: Arc<S>,
    dlx: Box<DynDeadLetterStore<'static>>,
    meta: ConsumerMeta,
    handler: H,
    lease_cfg: LeaseConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    backoff: BackoffPolicy,
    admission: primitives::ConsumerAdmission,
) -> ManagedBlockingWorker
where
    S: InboxStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let domain = meta.domain().to_owned();
    spawn_on_dedicated_runtime(
        name,
        token,
        Arc::clone(&health),
        CONSUMER_SHUTDOWN_TIMEOUT,
        move |token| async move {
            run_ackable_subscription_loop(
                subscriber,
                topic,
                domain,
                token,
                health,
                backoff,
                admission,
                async |stream, admission| {
                    run_consumer_ackable(
                        stream,
                        Arc::clone(&idempotency),
                        dlx.as_ref(),
                        &meta,
                        &handler,
                        lease_cfg,
                        admission,
                    )
                    .await;
                },
            )
            .await;
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use consistency::InboxReceiptContext;
    use consistency::error::EngineError;
    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use diport::dead_letter_store::{
        DeadLetterProvenance, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError,
        DeadLetterSummary,
    };
    use diport::{
        AckAction, AckError, AckableSubscriber, Acker, Delivery, DynAckableSubscriber, DynAcker,
        ManagedResource, SubscriberError, Topic,
    };
    use diport::{
        EnvelopeMetadata, KEY_SCHEMA_HASH, KEY_SCHEMA_VERSION, KEY_TENANT_AUTHORITY, KEY_TENANT_ID,
    };
    use futures::StreamExt;
    use primitives::healthz::{HealthStatus, ProbeName};
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::{
        BoxFuture, CancellationToken, ConsumerMeta, DeliveryStream, DynDeadLetterStore,
        EVENT_CONSUMER_PROBE, HandleResult, InboxStore, LeaseConfig, Message, MessageStream,
        WorkerHealth, health_reporting_dlx, run_ackable_subscription_loop, spawn_consumer,
        spawn_consumer_ackable, spawn_consumer_ackable_subscriber, spawn_relay,
    };
    use crate::tenant_authority::TenantAuthorityBinding;
    use crate::{BackoffPolicy, ManagedBlockingWorker, TenantAuthority};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const SCHEMA_HASH: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// 测试用 lease 配置（续租间隔大，worker happy-path 测试中续租不触发）。
    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(std::time::Duration::from_secs(60))
    }

    fn consumer_admission() -> primitives::ConsumerAdmission {
        let (control, _, consumer, _) = primitives::prepare_dr_admission_controls().into_parts();
        assert!(control.start_running().is_ok());
        consumer
    }

    fn relay_admission() -> primitives::RelayAdmission {
        let (control, relay, _, _) = primitives::prepare_dr_admission_controls().into_parts();
        assert!(control.start_running().is_ok());
        relay
    }

    // ── fakes / stream factories ───────────────────────────────────────────────

    /// 有限消息流（处理完即终止，确定性 completion）。
    fn finite_stream(msgs: &[(&str, &[u8])]) -> MessageStream {
        let msgs: Vec<Message> = msgs.iter().map(|(id, p)| message(id, p)).collect();
        Box::pin(futures::stream::iter(msgs))
    }

    /// 取消前永不终止的消息流（验运行中 Healthy + cancel 收敛）：有限前缀 + `pending`，仅 `token` 取消才终止。
    fn cancellable_stream(token: CancellationToken) -> MessageStream {
        Box::pin(
            futures::stream::iter(Vec::<Message>::new())
                .chain(futures::stream::pending::<Message>())
                .take_until(async move { token.cancelled().await }),
        )
    }

    fn independently_pending_stream(polled: Arc<std::sync::atomic::AtomicBool>) -> MessageStream {
        Box::pin(futures::stream::poll_fn(move |_cx| {
            polled.store(true, Ordering::Release);
            std::task::Poll::<Option<Message>>::Pending
        }))
    }

    fn independently_pending_delivery_stream(
        polled: Arc<std::sync::atomic::AtomicBool>,
    ) -> DeliveryStream {
        Box::pin(futures::stream::poll_fn(move |_cx| {
            polled.store(true, Ordering::Release);
            std::task::Poll::<Option<Delivery>>::Pending
        }))
    }

    /// 携记录型 acker 的有限投递流（断言终态向 broker settle）。
    fn delivery_stream(
        msgs: &[(&str, &[u8])],
        actions: Arc<Mutex<Vec<AckAction>>>,
    ) -> DeliveryStream {
        let deliveries: Vec<Delivery> = msgs
            .iter()
            .map(|(id, p)| {
                Delivery::new(
                    message(id, p),
                    DynAcker::new_box(RecordingAcker(actions.clone())),
                )
            })
            .collect();
        Box::pin(futures::stream::iter(deliveries))
    }

    /// 记录每次 settle 的 [`AckAction`]（断言 ackable 驱动终态向 broker settle）。
    struct RecordingAcker(Arc<Mutex<Vec<AckAction>>>);
    impl Acker for RecordingAcker {
        async fn settle(&self, action: AckAction) -> Result<(), AckError> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(action);
            Ok(())
        }
    }

    struct CapturingSubscriber {
        seen_token: std::sync::mpsc::Sender<CancellationToken>,
    }

    impl AckableSubscriber for CapturingSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            token: CancellationToken,
        ) -> Result<DeliveryStream, SubscriberError> {
            let _ = self.seen_token.send(token.clone());
            Ok(Box::pin(
                futures::stream::pending::<Delivery>()
                    .take_until(async move { token.cancelled().await }),
            ))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("test subscriber unavailable")]
    struct TestSubscriberUnavailable;

    struct FailingSubscriber;

    impl AckableSubscriber for FailingSubscriber {
        async fn subscribe_ackable(
            &self,
            _topic: Topic,
            _token: CancellationToken,
        ) -> Result<DeliveryStream, SubscriberError> {
            Err(SubscriberError::new(TestSubscriberUnavailable))
        }

        async fn shutdown(&self) -> Result<(), SubscriberError> {
            Ok(())
        }
    }

    fn tiny_backoff() -> BackoffPolicy {
        // 1ms < 8ms：构造失败不可达；避免 clippy::expect_used。
        BackoffPolicy::new(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(8),
        )
        .unwrap_or_default()
    }

    /// 恒 Fresh 幂等 store（计 commit 次数）。
    struct FreshStore {
        commits: AtomicU32,
    }
    impl FreshStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                commits: AtomicU32::new(0),
            })
        }
        fn commits(&self) -> u32 {
            self.commits.load(Ordering::Acquire)
        }
    }
    impl InboxStore for FreshStore {
        async fn try_claim(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, EngineError> {
            Ok(SeenState::Fresh)
        }
        async fn extend(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            // worker happy-path 测试不模拟租约丢失：恒 Held。
            Ok(LeaseOutcome::Held)
        }
        async fn commit(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.commits.fetch_add(1, Ordering::Release);
            Ok(LeaseOutcome::Held)
        }
        async fn release(
            &self,
            _ctx: &InboxReceiptContext,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<(), EngineError> {
            Ok(())
        }
    }

    /// noop DLX（worker 测试 happy-path 不触死信；DLX 三路径由 consumer.rs 单测覆盖）。
    struct NoopDlx;
    impl DeadLetterStore for NoopDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }
    fn noop_dlx() -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(NoopDlx)
    }

    struct ErrorDlx;
    impl DeadLetterStore for ErrorDlx {
        async fn write_dead_letter(
            &self,
            _record: DeadLetterRecord,
        ) -> Result<(), DeadLetterStoreError> {
            Err(DeadLetterStoreError::new(std::io::Error::other(
                "test dlx write failed",
            )))
        }
        async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
            Ok(())
        }
    }

    fn error_dlx() -> Box<DynDeadLetterStore<'static>> {
        DynDeadLetterStore::new_box(ErrorDlx)
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse(TENANT).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn message(id: &str, payload: &[u8]) -> Message {
        let token = tenant_authority()
            .sign(TenantAuthorityBinding::new(
                tenant(),
                "audit",
                "contract-session",
                "session.created",
                id,
            ))
            .expect("tenant authority test signing cannot fail");
        let mut md = EnvelopeMetadata::empty();
        md.insert_wire_pair(KEY_TENANT_ID, TENANT);
        md.insert_wire_pair(KEY_TENANT_AUTHORITY, token);
        md.insert_wire_pair(KEY_SCHEMA_VERSION, "v1");
        md.insert_wire_pair(KEY_SCHEMA_HASH, SCHEMA_HASH);
        Message::new_with_metadata(id, payload.to_vec(), md)
    }

    #[allow(clippy::expect_used)]
    // reason: 测试 tenant literal 合法，失败即测试数据写错。
    fn sample_dead_letter_record(message_id: &str) -> DeadLetterRecord {
        DeadLetterRecord::new(
            rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001")
                .expect("valid tenant id"),
            message_id,
            DeadLetterProvenance::consumer("identity", "audit"),
            "identity.session-created",
            "identity.session-created",
            Some("audit.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("test dead letter"),
            1,
            EnvelopeMetadata::empty(),
        )
    }

    fn handler_ack(
        counter: Arc<AtomicU32>,
    ) -> impl Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static {
        move |_msg| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                HandleResult::ack()
            })
        }
    }

    #[allow(clippy::panic)]
    // reason: 故意 panic，验证 worker 线程 panic 经 completion 包成 ShutdownError 上抛。
    fn handler_panic()
    -> impl Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static {
        move |_msg| Box::pin(async move { panic!("consumer-worker-test-panic") })
    }

    fn health() -> Arc<WorkerHealth> {
        Arc::new(WorkerHealth::healthy())
    }

    #[derive(Debug)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut tag = Vec::from(key.as_bytes());
            tag.extend_from_slice(message);
            Mac::from_bytes(tag)
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            self.sign(key, algorithm, message).as_bytes() == tag.as_bytes()
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant_authority() -> Arc<TenantAuthority> {
        Arc::new(
            TenantAuthority::new(
                Arc::new(TestMac),
                MacKey::from_bytes(vec![0x42; 32]),
                60,
                5,
                Arc::new(|| 1_700_000_000),
            )
            .expect("valid tenant authority"),
        )
    }

    fn meta() -> ConsumerMeta {
        ConsumerMeta::new(
            "audit",
            "audit",
            "contract-session",
            "session.created",
            "audit.session.consumer",
            tenant_authority(),
        )
    }

    // ── tests ───────────────────────────────────────────────────────────────────

    #[allow(clippy::unwrap_used)]
    // reason: 测试 runtime 构造和 wrapper 调用，失败即测试环境错误；item-level carve-out。
    #[test]
    fn health_reporting_dlx_emits_write_metric_and_degrades_on_error() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ok_health = Arc::new(WorkerHealth::starting());
        let err_health = Arc::new(WorkerHealth::starting());

        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let meta = meta();
                let ok = health_reporting_dlx(noop_dlx(), Arc::clone(&ok_health), &meta);
                ok.write_dead_letter(sample_dead_letter_record("dlx-ok"))
                    .await
                    .unwrap();

                let err = health_reporting_dlx(error_dlx(), Arc::clone(&err_health), &meta);
                assert!(
                    err.write_dead_letter(sample_dead_letter_record("dlx-error"))
                        .await
                        .is_err()
                );
            });
        });

        let rendered = handle.render();
        assert!(
            rendered.contains("consumer_dlx_write_total"),
            "缺 metric consumer_dlx_write_total: {rendered}"
        );
        assert!(
            rendered.contains("domain=\"audit\""),
            "缺 domain label: {rendered}"
        );
        assert!(
            rendered.contains("outcome=\"ok\""),
            "缺 outcome=ok label: {rendered}"
        );
        assert!(
            rendered.contains("outcome=\"error\""),
            "缺 outcome=error label: {rendered}"
        );
        assert_eq!(ok_health.status(), HealthStatus::Unhealthy);
        assert_eq!(ok_health.detail(), "starting");
        assert_eq!(err_health.status(), HealthStatus::Degraded);
        assert_eq!(err_health.detail(), "dlx-write-error");
    }

    /// at-most-once 驱动有限流：处理全部消息（handler / commit 各 N 次），shutdown 后 Unhealthy。
    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: timeout makes the finite-stream admission handshake fail-loud without racing shutdown.
    async fn worker_drives_finite_stream_then_joins() {
        let counter = Arc::new(AtomicU32::new(0));
        let idem = FreshStore::new();
        let worker = spawn_consumer(
            "event_consumer:audit:session.created".to_string(),
            finite_stream(&[("evt-1", b"a"), ("evt-2", b"b"), ("evt-3", b"c")]),
            idem.clone(),
            noop_dlx(),
            meta(),
            handler_ack(counter.clone()),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while counter.load(Ordering::Acquire) != 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("finite stream did not drain: {error}"));
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3, "全部 3 条被消费");
        assert_eq!(idem.commits(), 3, "每条 Ack→commit");
        assert_eq!(
            worker.health().status(),
            HealthStatus::Unhealthy,
            "退出后 Unhealthy"
        );
    }

    /// 运行中 Healthy；shutdown 取消 token → take_until 终止流 → loop 退出 → completion → Unhealthy。
    #[tokio::test]
    async fn worker_healthy_while_running_unhealthy_after_cancel() {
        let token = CancellationToken::new();
        let worker = spawn_consumer(
            "event_consumer:audit:session.created".to_string(),
            cancellable_stream(token.clone()),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            token,
            health(),
            consumer_admission(),
        );
        // 运行中：health 初始 Healthy，worker 阻塞在 pending stream 未退出。
        assert_eq!(worker.health().status(), HealthStatus::Healthy);
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(worker.health().status(), HealthStatus::Unhealthy);
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: the poll handshake proves the independently-bound stream entered the worker loop.
    async fn worker_shutdown_cancels_independently_bound_stream() {
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker = spawn_consumer(
            "event_consumer:audit:independent-stream".to_string(),
            independently_pending_stream(Arc::clone(&polled)),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !polled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("independent stream was not polled: {error}"));

        let shutdown = tokio::time::timeout(std::time::Duration::from_secs(1), worker.shutdown())
            .await
            .unwrap_or_else(|error| panic!("canonical token did not stop stream: {error}"));
        assert!(shutdown.is_ok());
    }

    /// shutdown_timeout = consumer 预算（45s）；二次 shutdown（句柄已 take→None）仍 Ok（幂等）。
    #[tokio::test]
    async fn worker_shutdown_timeout_and_idempotent() {
        let worker = spawn_consumer(
            "event_consumer:audit:session.created".to_string(),
            finite_stream(&[]),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        assert_eq!(
            ManagedResource::shutdown_timeout(&worker),
            super::CONSUMER_SHUTDOWN_TIMEOUT
        );
        assert!(worker.shutdown().await.is_ok());
        assert!(worker.shutdown().await.is_ok(), "二次 shutdown 幂等");
    }

    /// Cancelling an in-flight shutdown must not leave a Tokio blocking join behind: otherwise
    /// dropping the runtime waits forever for a handler that ignored cancellation.
    #[test]
    #[allow(clippy::panic)]
    // reason: thread/runtime harness failures must fail this lifecycle regression test.
    fn stalled_consumer_shutdown_does_not_block_runtime_drop() {
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let harness = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("test runtime: {error}"));
            runtime.block_on(async move {
                let handler = move |_message: Message| {
                    let started = Arc::clone(&thread_started);
                    let release = Arc::clone(&thread_release);
                    Box::pin(async move {
                        started.store(true, Ordering::Release);
                        // Stall fixture: ignore WaitTimeout — handler holds until the test
                        // releases or drops the runtime; timeout is not a readiness failure.
                        let _ = testkit::await_notified(
                            release.as_ref(),
                            std::time::Duration::from_secs(60),
                        )
                        .await;
                        HandleResult::ack()
                    }) as BoxFuture<'static, HandleResult>
                };
                let worker = spawn_consumer(
                    "event_consumer:audit:stalled".to_string(),
                    finite_stream(&[("evt-stalled", b"a")]),
                    FreshStore::new(),
                    noop_dlx(),
                    meta(),
                    handler,
                    lease_cfg(),
                    CancellationToken::new(),
                    health(),
                    consumer_admission(),
                );
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while !started.load(Ordering::Acquire) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|error| panic!("handler did not start: {error}"));
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(20), worker.shutdown(),)
                        .await
                        .is_err(),
                    "stalled handler must exercise cancelled shutdown"
                );
            });
            drop(runtime);
            let _ = dropped_tx.send(());
        });

        let dropped_without_release = dropped_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_ok();
        release.notify_one();
        harness
            .join()
            .unwrap_or_else(|_| panic!("runtime-drop harness panicked"));
        assert!(
            dropped_without_release,
            "runtime drop waited for spawn_blocking(thread.join()) after shutdown cancellation"
        );
    }

    /// worker 线程 panic（handler panic）→ shutdown completion 返 Err（ShutdownError），不静默吞；
    /// 且 panic unwind 仍经 [`crate::WorkerStoppedGuard`] 守卫标 Unhealthy（F3：原 `mark_stopped` 在 `block_on`
    /// 后，被 panic 跳过 → readyz 误报 Healthy；守卫修复后此断言成立）。
    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: timeout proves the panic path ran before shutdown observes its typed completion.
    async fn worker_panic_propagates_and_marks_stopped() {
        let worker = spawn_consumer(
            "event_consumer:audit:session.created".to_string(),
            finite_stream(&[("evt-1", b"a")]),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_panic(),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while worker.health().detail() != "stopped" {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("worker panic did not stop runner: {error}"));
        assert!(
            worker.shutdown().await.is_err(),
            "worker 线程 panic 须经 completion 上抛 ShutdownError"
        );
        assert_eq!(
            worker.health().status(),
            HealthStatus::Unhealthy,
            "panic unwind 仍须经退出守卫标 Unhealthy（readyz 翻；F3）"
        );
    }

    /// ackable 驱动：handler Ack + commit ok → 终态向 broker settle `Ack`（证 broker settlement 真发）。
    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: timeout makes the delivery admission handshake fail-loud without racing shutdown.
    async fn ackable_worker_settles_ack_on_success() {
        let actions = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::new(AtomicU32::new(0));
        let worker = spawn_consumer_ackable(
            "event_consumer:audit:session.created".to_string(),
            delivery_stream(&[("evt-1", b"a")], actions.clone()),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(counter.clone()),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while counter.load(Ordering::Acquire) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("delivery stream did not settle: {error}"));
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 1, "1 条被消费");
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack],
            "ackable 驱动终态向 broker settle Ack"
        );
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: the poll handshake proves the independently-bound delivery stream entered the loop.
    async fn ackable_worker_shutdown_cancels_independently_bound_stream() {
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker = spawn_consumer_ackable(
            "event_consumer:audit:independent-delivery-stream".to_string(),
            independently_pending_delivery_stream(Arc::clone(&polled)),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            CancellationToken::new(),
            health(),
            consumer_admission(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !polled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("independent delivery stream was not polled: {error}"));

        let shutdown = tokio::time::timeout(std::time::Duration::from_secs(1), worker.shutdown())
            .await
            .unwrap_or_else(|error| {
                panic!("canonical token did not stop delivery stream: {error}")
            });
        assert!(shutdown.is_ok());
    }

    /// Ackable worker 的订阅必须使用外部注入 token：这是组合根 WorkerSpec child token funnel 的前提。
    #[tokio::test]
    #[allow(clippy::panic)]
    // reason: 测试等待 worker thread 回传 token，超时即测试失败；panic 是断言失败路径。
    async fn ackable_subscriber_worker_passes_injected_token_to_subscribe() {
        let (tx, rx) = std::sync::mpsc::channel();
        let stack_child = CancellationToken::new();
        let worker = spawn_consumer_ackable_subscriber(
            "event_consumer:audit:session.created".to_string(),
            DynAckableSubscriber::new_box(CapturingSubscriber { seen_token: tx }),
            Topic::new("session.created"),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            stack_child.clone(),
            health(),
            tiny_backoff(),
            consumer_admission(),
        );

        let subscribed_token = match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(token) => token,
            Err(err) => panic!("worker must subscribe with injected token: {err}"),
        };
        assert!(!subscribed_token.is_cancelled());

        stack_child.cancel();
        assert!(
            subscribed_token.is_cancelled(),
            "root/stack child cancellation must reach subscriber stream token"
        );
        assert!(worker.shutdown().await.is_ok());
    }

    /// 持续订阅失败时保持 subscriber-unavailable；cancel 后干净退出且 detail 不被盖成 stopped。
    #[tokio::test(start_paused = true)]
    async fn ackable_subscriber_failure_health_remains_subscriber_unavailable() {
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let supervise = run_ackable_subscription_loop(
            DynAckableSubscriber::new_box(FailingSubscriber),
            Topic::new("session.created"),
            "audit".to_owned(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
            async |mut stream, _admission| while stream.next().await.is_some() {},
        );
        let watchdog = async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            assert_eq!(health.status(), HealthStatus::Unhealthy);
            assert_eq!(health.detail(), "subscriber-unavailable");
            token.cancel();
        };
        tokio::join!(supervise, watchdog);
        health.mark_stopped();
        assert_eq!(health.detail(), "subscriber-unavailable");
    }

    #[tokio::test(start_paused = true)]
    async fn ackable_subscriber_retries_then_becomes_healthy() {
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let subscribe_calls = Arc::new(AtomicU32::new(0));
        let subscribe_calls_run = Arc::clone(&subscribe_calls);
        struct FlakyShared {
            fails_remaining: AtomicU32,
            subscribe_calls: Arc<AtomicU32>,
        }
        impl AckableSubscriber for FlakyShared {
            async fn subscribe_ackable(
                &self,
                _topic: Topic,
                token: CancellationToken,
            ) -> Result<DeliveryStream, SubscriberError> {
                self.subscribe_calls.fetch_add(1, Ordering::AcqRel);
                if self.fails_remaining.load(Ordering::Acquire) > 0 {
                    self.fails_remaining.fetch_sub(1, Ordering::AcqRel);
                    return Err(SubscriberError::new(TestSubscriberUnavailable));
                }
                Ok(Box::pin(
                    futures::stream::pending::<Delivery>()
                        .take_until(async move { token.cancelled().await }),
                ))
            }
            async fn shutdown(&self) -> Result<(), SubscriberError> {
                Ok(())
            }
        }
        let supervise = run_ackable_subscription_loop(
            DynAckableSubscriber::new_box(FlakyShared {
                fails_remaining: AtomicU32::new(2),
                subscribe_calls: subscribe_calls_run,
            }),
            Topic::new("session.created"),
            "audit".to_owned(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
            async |mut stream, _admission| while stream.next().await.is_some() {},
        );
        let watchdog = async {
            while health.status() != HealthStatus::Healthy {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            assert!(subscribe_calls.load(Ordering::Acquire) >= 3);
            token.cancel();
        };
        tokio::join!(supervise, watchdog);
    }

    #[tokio::test(start_paused = true)]
    async fn ackable_subscriber_stream_end_resubscribes() {
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let subscribe_calls = Arc::new(AtomicU32::new(0));
        let subscribe_calls_run = Arc::clone(&subscribe_calls);
        struct SeqShared {
            subscribe_calls: Arc<AtomicU32>,
        }
        impl AckableSubscriber for SeqShared {
            async fn subscribe_ackable(
                &self,
                _topic: Topic,
                token: CancellationToken,
            ) -> Result<DeliveryStream, SubscriberError> {
                let n = self.subscribe_calls.fetch_add(1, Ordering::AcqRel);
                if n == 0 {
                    return Ok(Box::pin(futures::stream::iter(Vec::<Delivery>::new())));
                }
                Ok(Box::pin(
                    futures::stream::pending::<Delivery>()
                        .take_until(async move { token.cancelled().await }),
                ))
            }
            async fn shutdown(&self) -> Result<(), SubscriberError> {
                Ok(())
            }
        }
        let supervise = run_ackable_subscription_loop(
            DynAckableSubscriber::new_box(SeqShared {
                subscribe_calls: subscribe_calls_run,
            }),
            Topic::new("session.created"),
            "audit".to_owned(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
            async |mut stream, _admission| while stream.next().await.is_some() {},
        );
        let watchdog = async {
            while subscribe_calls.load(Ordering::Acquire) < 2
                || health.status() != HealthStatus::Healthy
            {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            assert!(subscribe_calls.load(Ordering::Acquire) >= 2);
            token.cancel();
        };
        tokio::join!(supervise, watchdog);
    }

    #[tokio::test(start_paused = true)]
    async fn ackable_subscriber_retry_aborts_on_shutdown_cancel() {
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let supervise = run_ackable_subscription_loop(
            DynAckableSubscriber::new_box(FailingSubscriber),
            Topic::new("session.created"),
            "audit".to_owned(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
            async |mut stream, _admission| while stream.next().await.is_some() {},
        );
        let watchdog = async {
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            token.cancel();
        };
        tokio::join!(supervise, watchdog);
        assert_eq!(health.detail(), "subscriber-unavailable");
    }

    /// dlx-write-error → stream-end → resubscribe：通道恢复不得洗掉已证实 DLX 故障。
    #[tokio::test(start_paused = true)]
    async fn ackable_subscriber_resubscribe_preserves_dlx_write_error() {
        let health = Arc::new(WorkerHealth::starting());
        health.mark_dlx_write_error();
        assert_eq!(health.detail(), "dlx-write-error");
        let token = CancellationToken::new();
        let subscribe_calls = Arc::new(AtomicU32::new(0));
        let subscribe_calls_run = Arc::clone(&subscribe_calls);
        struct SeqPreserveDlx {
            subscribe_calls: Arc<AtomicU32>,
        }
        impl AckableSubscriber for SeqPreserveDlx {
            async fn subscribe_ackable(
                &self,
                _topic: Topic,
                token: CancellationToken,
            ) -> Result<DeliveryStream, SubscriberError> {
                let n = self.subscribe_calls.fetch_add(1, Ordering::AcqRel);
                if n == 0 {
                    return Ok(Box::pin(futures::stream::iter(Vec::<Delivery>::new())));
                }
                Ok(Box::pin(
                    futures::stream::pending::<Delivery>()
                        .take_until(async move { token.cancelled().await }),
                ))
            }
            async fn shutdown(&self) -> Result<(), SubscriberError> {
                Ok(())
            }
        }
        let supervise = run_ackable_subscription_loop(
            DynAckableSubscriber::new_box(SeqPreserveDlx {
                subscribe_calls: subscribe_calls_run,
            }),
            Topic::new("session.created"),
            "audit".to_owned(),
            token.clone(),
            Arc::clone(&health),
            tiny_backoff(),
            consumer_admission(),
            async |mut stream, _admission| while stream.next().await.is_some() {},
        );
        let watchdog = async {
            while subscribe_calls.load(Ordering::Acquire) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
            assert_eq!(health.detail(), "dlx-write-error");
            assert_eq!(health.status(), HealthStatus::Degraded);
            token.cancel();
        };
        tokio::join!(supervise, watchdog);
        assert_eq!(health.detail(), "dlx-write-error");
    }

    /// `ManagedBlockingWorker` 是 `Send + Sync`（经 `Box<DynManagedResource>` 注入 ShutdownStack 的前提）。
    #[test]
    fn managed_blocking_worker_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ManagedBlockingWorker>();
    }

    // ── spawn_relay fakes ──────────────────────────────────────────────────────

    /// noop relay store：`claim_batch` 恒返空批，`relay` 恒返 `Ok(Ack)`（spawn_relay happy-path 用）。
    struct NoopRelayStore {
        domain: vocab::DomainName,
    }

    /// Noop provider 私有的 non-Clone claim；空批测试不会实际铸造它。
    struct NoopRelayClaim {
        subject: consistency::OutboxMetricSubject,
    }

    struct StalledRelayStore {
        domain: vocab::DomainName,
        claimed: std::sync::atomic::AtomicBool,
        started: Arc<std::sync::atomic::AtomicBool>,
        release: Arc<tokio::sync::Notify>,
        subject: consistency::OutboxMetricSubject,
    }

    impl consistency::OutboxRelay for NoopRelayStore {
        type Claim = NoopRelayClaim;

        fn claim_subject(claim: &Self::Claim) -> &consistency::OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &vocab::DomainName {
            &self.domain
        }

        async fn claim_batch(
            &self,
            _limit: usize,
        ) -> Result<Vec<Self::Claim>, consistency::error::EngineError> {
            Ok(vec![])
        }
        async fn relay(
            &self,
            _entry: Self::Claim,
        ) -> Result<consistency::outbox::Disposition, consistency::error::EngineError> {
            Ok(consistency::outbox::Disposition::Ack)
        }
    }

    impl consistency::OutboxRelay for StalledRelayStore {
        type Claim = NoopRelayClaim;

        fn claim_subject(claim: &Self::Claim) -> &consistency::OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &vocab::DomainName {
            &self.domain
        }

        async fn claim_batch(
            &self,
            _limit: usize,
        ) -> Result<Vec<Self::Claim>, consistency::error::EngineError> {
            if self.claimed.swap(true, Ordering::AcqRel) {
                return Ok(Vec::new());
            }
            Ok(vec![NoopRelayClaim {
                subject: self.subject.clone(),
            }])
        }

        async fn relay(
            &self,
            _entry: Self::Claim,
        ) -> Result<consistency::Disposition, consistency::error::EngineError> {
            self.started.store(true, Ordering::Release);
            // Stall fixture: ignore WaitTimeout — relay holds until the test releases the
            // barrier; timeout is intentional hold, not a readiness failure.
            let _ =
                testkit::await_notified(self.release.as_ref(), std::time::Duration::from_secs(60))
                    .await;
            Ok(consistency::Disposition::Ack)
        }
    }

    /// 固定时钟替身（满足 `diport::Clock: Send+Sync` 约束；now() 恒返 UNIX_EPOCH）。
    struct FixedClockRelay;
    impl diport::Clock for FixedClockRelay {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
    }

    /// noop metrics（spawn_relay 测试不断言发射计数）。
    struct NoopRelayMetrics;
    impl crate::OutboxMetrics for NoopRelayMetrics {
        fn record_publish(
            &self,
            _: &crate::OutboxMetricScope<'_>,
            _: consistency::outbox::Disposition,
        ) {
        }
        fn record_backlog(&self, _: &crate::OutboxMetricScope<'_>, _: consistency::BacklogSample) {}
        fn record_backlog_unavailable(&self, _: &crate::OutboxMetricScope<'_>) {}
        fn record_partition_blocked(&self, _: &crate::OutboxMetricScope<'_>, _: u64) {}
        fn record_tick_duration(&self, _: crate::RelayPhase, _: f64) {}
    }

    #[allow(clippy::expect_used)]
    // reason: 测试用合法 RelayConfig，parse 失败即参数写错；item-level carve-out。
    fn relay_cfg_for_test() -> crate::RelayConfig {
        crate::RelayConfig::new(
            std::time::Duration::from_secs(60), // 长轮询间隔：测试期间不触发 tick
            10,
        )
        .expect("valid test relay config")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed test provider domain is valid by construction; item-level carve-out.
    fn noop_relay_store() -> NoopRelayStore {
        NoopRelayStore {
            domain: vocab::DomainName::parse("testdomain").expect("valid test domain"),
        }
    }

    // ── spawn_relay tests ──────────────────────────────────────────────────────

    /// spawn_relay → 运行中 Healthy；cancel + shutdown → Ok；退出后 Unhealthy（panic-safety 路径）。
    #[tokio::test]
    async fn spawn_relay_healthy_then_shutdown_stopped() {
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let worker = spawn_relay(
            "outbox-relay-test".into(),
            noop_relay_store(),
            relay_cfg_for_test(),
            Arc::new(FixedClockRelay),
            token.clone(),
            Arc::clone(&health),
            Arc::new(NoopRelayMetrics),
            relay_admission(),
        );

        // 运行中 Healthy（relay_loop 跑在线程内，未退出）。
        assert_eq!(
            worker.health().status(),
            primitives::healthz::HealthStatus::Healthy,
            "spawn_relay worker must be Healthy while running"
        );

        // shutdown → Ok（cancel → relay_loop break → 线程退出 → completion）。
        token.cancel();
        assert!(
            worker.shutdown().await.is_ok(),
            "spawn_relay worker shutdown must succeed"
        );

        // 退出后 Unhealthy（relay_loop mark_stopped + WorkerStoppedGuard 守卫双重保证）。
        assert_eq!(
            worker.health().status(),
            primitives::healthz::HealthStatus::Unhealthy,
            "relay worker must be Unhealthy after shutdown (WorkerStoppedGuard guard)"
        );
    }

    /// A publish that ignores cancellation must be bounded by the outer shutdown budget without
    /// leaving a blocking join owned by the Tokio runtime.
    #[test]
    #[allow(clippy::panic)]
    // reason: thread/runtime harness failures must fail this lifecycle regression test.
    fn stalled_publish_shutdown_does_not_block_runtime_drop() {
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let thread_started = Arc::clone(&started);
        let thread_release = Arc::clone(&release);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::channel();
        let harness = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|error| panic!("test runtime: {error}"));
            runtime.block_on(async move {
                let worker = spawn_relay(
                    "outbox-relay-stalled-publish".to_owned(),
                    StalledRelayStore {
                        domain: vocab::DomainName::parse("identity")
                            .unwrap_or_else(|error| panic!("test domain: {error}")),
                        claimed: std::sync::atomic::AtomicBool::new(false),
                        started: thread_started,
                        release: thread_release,
                        subject: consistency::OutboxMetricSubject::new(
                            tenant(),
                            consistency::OutboxContractId::parse("identity.session-created")
                                .unwrap_or_else(|error| panic!("test contract: {error}")),
                        ),
                    },
                    relay_cfg_for_test(),
                    Arc::new(FixedClockRelay),
                    CancellationToken::new(),
                    health(),
                    Arc::new(NoopRelayMetrics),
                    relay_admission(),
                );
                tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    while !started.load(Ordering::Acquire) {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap_or_else(|error| panic!("publish did not start: {error}"));
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(20), worker.shutdown(),)
                        .await
                        .is_err(),
                    "stalled publish must exercise cancelled shutdown"
                );
            });
            drop(runtime);
            let _ = dropped_tx.send(());
        });

        let dropped_without_release = dropped_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_ok();
        release.notify_one();
        harness
            .join()
            .unwrap_or_else(|_| panic!("runtime-drop harness panicked"));
        assert!(
            dropped_without_release,
            "runtime drop waited for stalled outbox publish after shutdown cancellation"
        );
    }

    /// EVENT_CONSUMER_PROBE 可通过 ProbeName::parse + 无 `_ready` 后缀（运行时操作 probe，对标
    /// relay.rs T12）。
    #[test]
    fn event_consumer_probe_name_parses_and_no_ready_suffix() {
        assert!(
            ProbeName::parse(EVENT_CONSUMER_PROBE).is_ok(),
            "EVENT_CONSUMER_PROBE must parse as valid ProbeName"
        );
        assert!(
            !EVENT_CONSUMER_PROBE.ends_with("_ready"),
            "EVENT_CONSUMER_PROBE must not end with _ready"
        );
    }
}
