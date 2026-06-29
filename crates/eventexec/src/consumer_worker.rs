//! ConsumerWorker —— 受监督的事件消费后台 worker（`ManagedResource` 两阶段关闭）。
//!
//! 把 [`crate::run_consumer`]（at-most-once / MemBus）/ [`crate::run_consumer_ackable`]
//! （at-least-once / AMQP broker settle）接成真实运行的后台 worker：组合根按 topology resolver 决策
//! 订阅得 stream（Demo→[`diport::Subscriber::subscribe`]→`MessageStream`；Durable→
//! [`diport::AckableSubscriber::subscribe_ackable`]→`DeliveryStream`），再 [`spawn_consumer`] /
//! [`spawn_consumer_ackable`] 在专用线程驱动；worker impl [`diport::ManagedResource`] 交
//! `bootstrap::ShutdownStack` 两阶段关闭，经 [`crate::WorkerHealth`] 供 readyz 聚合。
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
//! # 订阅与取消（subscribe-at-callsite）
//!
//! 组合根**先**订阅（`subscribe(topic, token)`）得 stream、**再** spawn worker 驱动该 stream：保证订阅在发布
//! 之前完成（in-mem MemBus 无重放，订阅须先于发布），且 stream 与 worker 共用同一 [`CancellationToken`]
//! ——worker 关闭时 [`ConsumerWorker::shutdown`] 取消该 token → subscriber 流终止（MemBus `take_until` /
//! AMQP channel close → broker requeue in-flight）→ loop 退出 → `block_on` 返回 → 线程结束。组合根经
//! `ShutdownStack::register_detached` 注册（worker 自持 token、在 `shutdown` 中自取消，不依赖 stack 阶段 1
//! 广播）。
//!
//! 关闭：[`ConsumerWorker::shutdown`] 经 `spawn_blocking` join 专用线程，线程 panic / `JoinError` 包成
//! [`diport::ShutdownError`] 上抛（对齐 `relay.rs` F6，**不**静默吞 panic 误报关闭成功）。健康粒度（v1）：
//! 运行中 `Healthy`（[`WorkerHealth`] 初始态），loop 退出 → `mark_stopped`（Unhealthy，readyz 翻）；per-message
//! settle/dlx 失败降级需 loop 内钩子 = 改 #1142 接缝，留 follow-up（现 `consumer_settle_total{outcome}` metric 已覆盖告警）。
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
//! # NOTE：AMQP-pending-#1017（`ConsumerWorker` 专用线程驱动的真 broker 验证）
//!
//! `ConsumerWorker` 的专用线程驱动在 demo（MemBus）+ eventexec 单测验证；真 AMQP broker 下经
//! `ConsumerWorker` 的 worker 化（lapin cross-runtime）留 #1017。§6 集成 journey
//! （`amqp_consumer_at_least_once_journey.rs`）用 inline `tokio::join!` 同 runtime 驱动
//! `run_consumer_ackable` 证 broker settlement，覆盖接缝的 at-least-once 终态兑现。

use std::sync::{Arc, Mutex};
use std::time::Duration;

use consistency::idempotency::IdempotencyStore;
use consistency::{HandleResult, OutboxRelay, OutboxSource};
use diport::{
    AckableSubscriber, DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DeliveryStream,
    DynAckableSubscriber, DynDeadLetterStore, Message, MessageStream, Topic,
};
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::consumer::{ConsumerMeta, LeaseConfig, run_consumer, run_consumer_ackable};
use crate::relay::WorkerHealth;

/// readyz probe 名基（event consumer worker；无 `_ready` 后缀——运行时操作 probe，对齐
/// [`crate::OUTBOX_RELAY_PROBE`]）。组合根据此 + domain/topic 组装 per-worker `primitives::ProbeName`
/// （如 `event_consumer:audit:identity.session-created`）接 readyz 聚合（HTTP endpoint mount 归 #1017）。
pub const EVENT_CONSUMER_PROBE: &str = "event_consumer";

/// consumer worker 关闭超时：每条在途消息 handle + commit + settle 有界 drain，对齐 relay 的 45s 预算。
const CONSUMER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

// ── ConsumerWorker（adopt 专用消费线程 + ManagedResource）──────────────────────

/// 受监督的事件消费后台 worker（adopt 专用 OS 线程的 [`std::thread::JoinHandle`]）。
///
/// 与 [`crate::RelayWorker`]（adopt `tokio::task::JoinHandle`）对偶但**不共用** `adopt_worker!` 宏——
/// 消费驱动 future `!Send`、跑在专用线程而非 `tokio::spawn`（见模块 rustdoc），关闭需跨线程 join。
pub struct ConsumerWorker {
    name: String,
    // shutdown 时 take 出 join（Mutex<Option<_>>：`shutdown(&self)` 需消费内部句柄；同 relay AdoptedWorker 范式）。
    inner: Mutex<Option<std::thread::JoinHandle<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl ConsumerWorker {
    /// adopt 已 spawn 的消费线程 + 同一 health + 同一 token（由 `spawn_*` 内部构造）。
    fn adopt(
        name: String,
        handle: std::thread::JoinHandle<()>,
        health: Arc<WorkerHealth>,
        token: CancellationToken,
    ) -> Self {
        Self {
            name,
            inner: Mutex::new(Some(handle)),
            health,
            token,
        }
    }

    /// 读 worker health（readyz 聚合用）。
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }
}

/// worker 线程 panic：join 返回 `Err(Box<dyn Any>)` 时的 typed 错误（`Box<dyn Any>` 非 `Error`，无法直接
/// 包进 [`diport::ShutdownError`]；用本 typed 占位，原始 panic payload 不经 wire/日志泄漏，PII-safe）。
#[derive(Debug, thiserror::Error)]
#[error("consumer worker thread panicked")]
struct ConsumerThreadPanicked;

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): consumer 后台 worker 归 eventexec 服务层并 impl `ManagedResource`
// （经组合根 ShutdownStack 注入两阶段关闭），同 RelayWorker（relay.rs:500 同款例外）。`ManagedResource` 是
// 生命周期 trait（非可替换 provider port），worker 是引擎驱动产物而非 adapter provider，不迁 adapter。
// allowlist 外 item-level 例外（DIPORT-IMPL-ALLOWLIST-01 逃生门）；根治（豁免 `ManagedResource` 出 lint 扫描集）
// 见 #1153。unknown_lints 同 allow：dylint 自定义 lint 在 plain clippy 未注册（make verify 跑 plain clippy + dylint 双路）。
impl diport::ManagedResource for ConsumerWorker {
    fn name(&self) -> &str {
        &self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        CONSUMER_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        // 取消本 worker token（subscriber 流据此终止）；幂等，二次 shutdown 安全。
        self.token.cancel();
        // take 出线程句柄（释放 std Mutex guard 后再 await——不跨 await 持锁）。二次 shutdown → None → Ok。
        let handle = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();
        let Some(handle) = handle else {
            return Ok(());
        };
        // !Send future 跑在专用线程，join 是阻塞调用——放 spawn_blocking 避免阻塞组合根 runtime。
        match tokio::task::spawn_blocking(move || handle.join()).await {
            // spawn_blocking 自身 JoinError（极罕见：blocking 任务被 abort）。
            Err(join_err) => Err(diport::ShutdownError::new(join_err)),
            // worker 线程 panic（thread::Result Err）→ typed 上抛（对齐 relay F6，不静默吞 panic 误报成功）。
            Ok(Err(_panic)) => Err(diport::ShutdownError::new(ConsumerThreadPanicked)),
            Ok(Ok(())) => Ok(()),
        }
    }
}

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

/// 在专用 OS 线程建 current-thread runtime `block_on` 跑 `body`：线程退出（正常 / runtime 构建失败 /
/// future panic）由 [`crate::WorkerStoppedGuard`] 守卫统一 `health.mark_stopped()`（readyz Unhealthy）。
///
/// `worker_name` 用于 runtime 构建失败时的结构化日志归因（`worker = worker_name` 字段）。
/// `make_body` **必须** `Send`（捕获值跨线程移入），其返回的 future **无需** `Send`（在线程内构建与轮询）。
fn spawn_consumer_thread<Fut, M>(
    worker_name: &str,
    health: Arc<WorkerHealth>,
    make_body: M,
) -> std::thread::JoinHandle<()>
where
    M: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()>,
{
    let worker_name = worker_name.to_string();
    std::thread::spawn(move || {
        // 退出守卫：正常返回 / runtime 构建失败 / future panic 三条路径均经 Drop 统一 mark_stopped（F3）。
        let _stopped = health.stopped_on_exit();
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(
                    worker = worker_name,
                    error = %e,
                    "consumer: worker runtime build failed; worker unhealthy"
                );
                return;
            }
        };
        rt.block_on(make_body());
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
) -> ConsumerWorker
where
    S: IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let health_run = Arc::clone(&health);
    let handle = spawn_consumer_thread(&name, health.clone(), move || async move {
        health_run.mark_healthy();
        run_consumer(stream, idempotency, dlx, meta, handler, lease_cfg).await;
    });
    ConsumerWorker::adopt(name, handle, health, token)
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
/// 返回的 [`ConsumerWorker`] 持同一 `health` + `token`，shutdown 取消 token → relay_loop break →
/// 线程退出 → join → Ok（健康态翻 Unhealthy）。
#[allow(clippy::too_many_arguments)]
// reason: relay spawn 7 参数是最小必要集（name/store/config/clock/token/health/metrics 各自语义独立），
// 同 spawn_consumer_ackable item-level carve-out（error-handling.md §Carve-out）。
pub fn spawn_relay<A>(
    name: String,
    store: A,
    config: crate::RelayConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn crate::OutboxMetrics>,
) -> ConsumerWorker
where
    A: OutboxSource + OutboxRelay + Send + 'static,
{
    let health_loop = Arc::clone(&health);
    let token_run = token.clone();
    let handle = spawn_consumer_thread(&name, health.clone(), move || async move {
        // Arc::new(store) 在线程内构建：Arc<A>(!Send) 不跨线程；store: A (Send) 跨线程移入。
        let store = Arc::new(store);
        crate::relay::relay_loop(store, config, clock, token_run, health_loop, metrics).await;
    });
    ConsumerWorker::adopt(name, handle, health, token)
}

/// spawn at-least-once 消费 worker（Durable / AMQP 路径，每条终态向 broker settle）。
///
/// 组合根先 `subscribe_ackable(topic, token)` 得 `stream`、再调本函数。`DeliveryStream` 每条
/// `Delivery { message, acker }` 终态恰 settle 一次（ack/requeue/reject）。崩溃窗口（settle 前线程退出）→
/// channel close → broker requeue in-flight，经幂等去重 = at-least-once 不丢。
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
) -> ConsumerWorker
where
    S: IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let health_run = Arc::clone(&health);
    let handle = spawn_consumer_thread(&name, health.clone(), move || async move {
        health_run.mark_healthy();
        run_consumer_ackable(stream, idempotency, dlx, meta, handler, lease_cfg).await;
    });
    ConsumerWorker::adopt(name, handle, health, token)
}

/// spawn at-least-once 消费 worker，并在 worker 线程内用注入的 stack child token 完成订阅。
///
/// 组合根 `WorkerSpec` 闭包是同步的，但 AMQP `subscribe_ackable` 是 async。该函数把订阅放进
/// `ConsumerWorker` 专用线程的 current-thread runtime 内执行，使 `ShutdownStack::register_with_token`
/// 注入的 child token 同时驱动订阅 stream 取消和 worker shutdown，满足 `SHUTDOWN-TOKEN-FUNNEL-01`。
#[allow(clippy::too_many_arguments)]
// reason: 与 spawn_consumer_ackable 同形；subscriber/topic 是把 async subscribe 移入 worker 线程所需的
// 最小新增参数，聚合 struct 只会增加间接层。
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
) -> ConsumerWorker
where
    S: IdempotencyStore + Send + Sync + 'static,
    H: Fn(Message) -> BoxFuture<'static, HandleResult> + Send + Sync + 'static,
{
    let token_run = token.clone();
    let health_run = Arc::clone(&health);
    let dlx = health_reporting_dlx(dlx, Arc::clone(&health), &meta);
    let handle = spawn_consumer_thread(&name, health.clone(), move || async move {
        match subscriber.subscribe_ackable(topic, token_run.clone()).await {
            Ok(stream) => {
                health_run.mark_healthy();
                run_consumer_ackable(stream, idempotency, dlx, meta, handler, lease_cfg).await;
            }
            Err(err) => {
                health_run.mark_subscriber_unavailable();
                tracing::error!(
                    error = %err,
                    "consumer: subscribe_ackable failed; worker exiting"
                );
            }
        }
    });
    ConsumerWorker::adopt(name, handle, health, token)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use consistency::error::EngineError;
    use consistency::idempotency::{IdemKey, LeaseOutcome, LeaseToken, SeenState};
    use diport::EnvelopeMetadata;
    use diport::dead_letter_store::{
        DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, DeadLetterSummary,
        WritableDeadLetterSource,
    };
    use diport::{
        AckAction, AckError, AckableSubscriber, Acker, Delivery, DynAckableSubscriber, DynAcker,
        ManagedResource, SubscriberError, Topic,
    };
    use futures::StreamExt;
    use primitives::healthz::{HealthStatus, ProbeName};
    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier};

    use super::{
        Arc, BoxFuture, CancellationToken, ConsumerMeta, ConsumerWorker, DeliveryStream,
        DynDeadLetterStore, EVENT_CONSUMER_PROBE, HandleResult, IdempotencyStore, LeaseConfig,
        Message, MessageStream, Mutex, WorkerHealth, health_reporting_dlx, spawn_consumer,
        spawn_consumer_ackable, spawn_consumer_ackable_subscriber, spawn_relay,
    };
    use crate::TenantAuthority;

    /// 测试用 lease 配置（续租间隔大，worker happy-path 测试中续租不触发）。
    fn lease_cfg() -> LeaseConfig {
        LeaseConfig::from_ttl(std::time::Duration::from_secs(60))
    }

    // ── fakes / stream factories ───────────────────────────────────────────────

    /// 有限消息流（处理完即终止，确定性 join）。
    fn finite_stream(msgs: &[(&str, &[u8])]) -> MessageStream {
        let msgs: Vec<Message> = msgs
            .iter()
            .map(|(id, p)| Message::new(*id, p.to_vec()))
            .collect();
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

    /// 携记录型 acker 的有限投递流（断言终态向 broker settle）。
    fn delivery_stream(
        msgs: &[(&str, &[u8])],
        actions: Arc<Mutex<Vec<AckAction>>>,
    ) -> DeliveryStream {
        let deliveries: Vec<Delivery> = msgs
            .iter()
            .map(|(id, p)| {
                Delivery::new(
                    Message::new(*id, p.to_vec()),
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
    impl IdempotencyStore for FreshStore {
        async fn try_claim(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<SeenState, EngineError> {
            Ok(SeenState::Fresh)
        }
        async fn extend(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            // worker happy-path 测试不模拟租约丢失：恒 Held。
            Ok(LeaseOutcome::Held)
        }
        async fn commit(
            &self,
            _key: &IdemKey,
            _lease: &LeaseToken,
        ) -> Result<LeaseOutcome, EngineError> {
            self.commits.fetch_add(1, Ordering::Release);
            Ok(LeaseOutcome::Held)
        }
        async fn release(&self, _key: &IdemKey, _lease: &LeaseToken) -> Result<(), EngineError> {
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
    // reason: 测试 tenant literal 合法，失败即测试数据写错。
    fn sample_dead_letter_record(message_id: &str) -> DeadLetterRecord {
        DeadLetterRecord::new(
            vocab::TenantId::parse("00000000-0000-0000-0000-000000000001")
                .expect("valid tenant id"),
            message_id,
            "audit",
            "identity.session-created",
            "identity.session-created",
            Some("audit.session.consumer".to_string()),
            b"payload".to_vec(),
            DeadLetterSummary::new("test dead letter"),
            1,
            WritableDeadLetterSource::Consumer,
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
    // reason: 故意 panic，验证 worker 线程 panic 经 join 包成 ShutdownError 上抛（不静默吞，对齐 relay F6）。
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
        );
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 3, "全部 3 条被消费");
        assert_eq!(idem.commits(), 3, "每条 Ack→commit");
        assert_eq!(
            worker.health().status(),
            HealthStatus::Unhealthy,
            "退出后 Unhealthy"
        );
    }

    /// 运行中 Healthy；shutdown 取消 token → take_until 终止流 → loop 退出 → join → Unhealthy。
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
        );
        // 运行中：health 初始 Healthy，worker 阻塞在 pending stream 未退出。
        assert_eq!(worker.health().status(), HealthStatus::Healthy);
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(worker.health().status(), HealthStatus::Unhealthy);
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
        );
        assert_eq!(
            ManagedResource::shutdown_timeout(&worker),
            super::CONSUMER_SHUTDOWN_TIMEOUT
        );
        assert!(worker.shutdown().await.is_ok());
        assert!(worker.shutdown().await.is_ok(), "二次 shutdown 幂等");
    }

    /// worker 线程 panic（handler panic）→ shutdown join 返 Err（ShutdownError），不静默吞（relay F6 同款）；
    /// 且 panic unwind 仍经 [`crate::WorkerStoppedGuard`] 守卫标 Unhealthy（F3：原 `mark_stopped` 在 `block_on`
    /// 后，被 panic 跳过 → readyz 误报 Healthy；守卫修复后此断言成立）。
    #[tokio::test]
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
        );
        assert!(
            worker.shutdown().await.is_err(),
            "worker 线程 panic 须经 join 上抛 ShutdownError"
        );
        assert_eq!(
            worker.health().status(),
            HealthStatus::Unhealthy,
            "panic unwind 仍须经退出守卫标 Unhealthy（readyz 翻；F3）"
        );
    }

    /// ackable 驱动：handler Ack + commit ok → 终态向 broker settle `Ack`（证 broker settlement 真发）。
    #[tokio::test]
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
        );
        assert!(worker.shutdown().await.is_ok());
        assert_eq!(counter.load(Ordering::SeqCst), 1, "1 条被消费");
        assert_eq!(
            *actions.lock().unwrap_or_else(|e| e.into_inner()),
            vec![AckAction::Ack],
            "ackable 驱动终态向 broker settle Ack"
        );
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

    /// 订阅失败应保留 subscriber-unavailable detail；线程退出守卫不得覆盖成 stopped。
    #[tokio::test]
    async fn ackable_subscriber_failure_health_remains_subscriber_unavailable() {
        let health = Arc::new(WorkerHealth::starting());
        let worker = spawn_consumer_ackable_subscriber(
            "event_consumer:audit:session.created".to_string(),
            DynAckableSubscriber::new_box(FailingSubscriber),
            Topic::new("session.created"),
            FreshStore::new(),
            noop_dlx(),
            meta(),
            handler_ack(Arc::new(AtomicU32::new(0))),
            lease_cfg(),
            CancellationToken::new(),
            Arc::clone(&health),
        );

        assert!(worker.shutdown().await.is_ok());
        assert_eq!(worker.health().status(), HealthStatus::Unhealthy);
        assert_eq!(worker.health().detail(), "subscriber-unavailable");
    }

    /// `ConsumerWorker` 是 `Send + Sync`（经 `Box<DynManagedResource>` 注入 ShutdownStack 的前提）。
    #[test]
    fn consumer_worker_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ConsumerWorker>();
    }

    // ── spawn_relay fakes ──────────────────────────────────────────────────────

    /// noop relay store：`poll_pending` 恒返空批，`relay` 恒返 `Ok(Ack)`（spawn_relay happy-path 用）。
    struct NoopRelayStore;

    impl consistency::OutboxSource for NoopRelayStore {
        async fn poll_pending(
            &self,
            _domain: &str,
            _limit: usize,
        ) -> Result<Vec<consistency::outbox::Entry>, consistency::error::EngineError> {
            Ok(vec![])
        }
    }

    impl consistency::OutboxRelay for NoopRelayStore {
        async fn relay(
            &self,
            _entry: &consistency::outbox::Entry,
        ) -> Result<consistency::outbox::Disposition, consistency::error::EngineError> {
            Ok(consistency::outbox::Disposition::Ack)
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
        fn record_publish(&self, _: &vocab::DomainName, _: consistency::outbox::Disposition) {}
        fn record_backlog(&self, _: &vocab::DomainName, _: consistency::BacklogSample) {}
        fn record_tick_duration(&self, _: crate::RelayPhase, _: f64) {}
    }

    #[allow(clippy::expect_used)]
    // reason: 测试用合法 RelayConfig，parse 失败即参数写错；item-level carve-out。
    fn relay_cfg_for_test() -> crate::RelayConfig {
        crate::RelayConfig::new(
            vec!["testdomain".to_string()],
            std::time::Duration::from_secs(60), // 长轮询间隔：测试期间不触发 tick
            10,
            std::time::Duration::from_secs(60),
        )
        .expect("valid test relay config")
    }

    // ── spawn_relay tests ──────────────────────────────────────────────────────

    /// spawn_relay → 运行中 Healthy；cancel + shutdown → Ok；退出后 Unhealthy（panic-safety 路径）。
    #[tokio::test]
    async fn spawn_relay_healthy_then_shutdown_stopped() {
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let worker = spawn_relay(
            "outbox-relay-test".into(),
            NoopRelayStore,
            relay_cfg_for_test(),
            Arc::new(FixedClockRelay),
            token.clone(),
            Arc::clone(&health),
            Arc::new(NoopRelayMetrics),
        );

        // 运行中 Healthy（relay_loop 跑在线程内，未退出）。
        assert_eq!(
            worker.health().status(),
            primitives::healthz::HealthStatus::Healthy,
            "spawn_relay worker must be Healthy while running"
        );

        // shutdown → Ok（cancel → relay_loop break → 线程退出 → join）。
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
