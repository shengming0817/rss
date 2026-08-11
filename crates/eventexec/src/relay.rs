//! Outbox relay/sweeper worker — L2 两阶段关闭 ManagedResource。
//!
//! # 设计摘要
//!
//! `consistency` 的两个 AFIT trait（`OutboxRelay`/`RetentionSweeper`）是 native AFIT、**无 Send 变体**。
//! `tokio::spawn` 要求 future Send，而泛型 `<A: OutboxRelay>` 下 `A::claim_batch(..)`
//! 的 future 在 stable Rust 上无法证明 Send（RTN 未稳定）。因此：
//! - 泛型 `relay_loop` / `sweeper_loop`：纯 loop 体，**不 spawn**——泛型 async fn 不要求 Send，能编过。
//! - spawn 发生在**具体类型 call site**（生产=组合根 PgOutbox，测试=具体 Fake）——单态化后 future 具体 Send。
//! - `RelayWorker` / `SweeperWorker`：adopt 式，持已 spawn 的 `JoinHandle<()>`，impl `ManagedResource`。
//!
//! ref: serverlesstechnology/cqrs（背景 relay 解耦 + 取消安全两阶段关闭，偏离 event-sourcing 同步派发）。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use consistency::{
    BacklogObservation, BacklogSample, Disposition, OutboxBacklog, OutboxContractId,
    OutboxMetricSubject, OutboxRelay, RetentionSweeper,
};
use primitives::healthz::HealthStatus;
use vocab::DomainName;

use crate::relay_config::{RelayConfig, SamplerConfig, SweeperConfig};
use crate::relay_metrics::{OutboxMetricScope, OutboxMetrics, RelayPhase};
use crate::worker_control::WorkerDrainObservation;
use crate::{MetricsRetentionMetrics, RetentionMetrics, RetentionOutcome, RetentionTarget};

// ── probe 名常量 ────────────────────────────────────────────────────────────

/// readyz probe 名：outbox relay worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_RELAY_PROBE: &str = "outbox_relay";

/// readyz probe 名：outbox sweeper worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_SWEEPER_PROBE: &str = "outbox_sweeper";

/// readyz probe 名：outbox backlog 采样 worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_SAMPLER_PROBE: &str = "outbox_sampler";

// worker 名常量（≥3 处使用抽 const）
const RELAY_WORKER_NAME: &str = "outbox-relay";
/// outbox 保留期 sweeper 的 readyz worker 名（per-target sweeper 默认名；组合根 #1208 可对 inbox_receipts /
/// dead_letter 传各自名，#327 review F2）。`pub`：[`SweeperWorker::adopt`] 的 `name` 参数由组合根/测试传入。
pub const SWEEPER_WORKER_NAME: &str = "outbox-sweeper";
const SAMPLER_WORKER_NAME: &str = "outbox-sampler";

/// worker 关闭超时：重 I/O drain，覆盖默认 30s（relay/sweeper 同值）。
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

// AtomicU8 编码：0=Healthy 1=Degraded 2=Unhealthy 3=Starting 4=SubscriberUnavailable
// 5=DlxWriteError 6=Invariant
const HEALTH_HEALTHY: u8 = 0;
const HEALTH_DEGRADED: u8 = 1;
const HEALTH_UNHEALTHY: u8 = 2;
const HEALTH_STARTING: u8 = 3;
const HEALTH_SUBSCRIBER_UNAVAILABLE: u8 = 4;
const HEALTH_DLX_WRITE_ERROR: u8 = 5;
const HEALTH_INVARIANT: u8 = 6;

// ── WorkerHealth ────────────────────────────────────────────────────────────

/// Worker 运行期健康（原子 u8，Send+Sync；0=Healthy 1=Degraded 2=Unhealthy）。
///
/// claim/relay/sweep 错误 → `mark_degraded`；loop 退出（worker 不再运行）→ `mark_stopped`（Unhealthy）。
/// readyz 聚合经 `health()` 读此状态，据此翻 probe。
pub struct WorkerHealth(AtomicU8);

/// Marks a worker as stopped when the owning thread/task exits.
///
/// This shared guard covers wrappers that can return before reaching their
/// loop-level `mark_stopped` call, for example runtime build failures or panic
/// unwinds in supervised worker threads.
pub struct WorkerStoppedGuard(Arc<WorkerHealth>);

impl Drop for WorkerStoppedGuard {
    fn drop(&mut self) {
        self.0.mark_stopped();
    }
}

impl WorkerHealth {
    /// 构造初始 Healthy 状态（AtomicU8::new(0)）。
    pub fn healthy() -> Self {
        Self(AtomicU8::new(HEALTH_HEALTHY))
    }

    /// 构造初始 Starting 状态（readyz 视为 Unhealthy，直到 worker 明确进入运行态）。
    pub fn starting() -> Self {
        Self(AtomicU8::new(HEALTH_STARTING))
    }

    /// Build a guard that flips the worker to Unhealthy when dropped.
    #[must_use]
    pub fn stopped_on_exit(self: &Arc<Self>) -> WorkerStoppedGuard {
        WorkerStoppedGuard(Arc::clone(self))
    }

    /// 读当前健康状态。
    pub fn status(&self) -> HealthStatus {
        match self.0.load(Ordering::Acquire) {
            HEALTH_HEALTHY => HealthStatus::Healthy,
            HEALTH_DEGRADED | HEALTH_DLX_WRITE_ERROR => HealthStatus::Degraded,
            HEALTH_STARTING | HEALTH_SUBSCRIBER_UNAVAILABLE | HEALTH_INVARIANT => {
                HealthStatus::Unhealthy
            }
            // `_` 兜底 HEALTH_UNHEALTHY + 任何非法编码（AtomicU8 仅由本类型三 const 写入；
            // clippy::wildcard_in_or_patterns 拒 `CONST | _`，故用裸 `_`）。
            _ => HealthStatus::Unhealthy,
        }
    }

    /// 稳定 readyz detail（const literal，无 runtime 错误 / 凭据 / payload）。
    pub fn detail(&self) -> &'static str {
        match self.0.load(Ordering::Acquire) {
            HEALTH_HEALTHY => "worker",
            HEALTH_DEGRADED => "degraded",
            HEALTH_STARTING => "starting",
            HEALTH_SUBSCRIBER_UNAVAILABLE => "subscriber-unavailable",
            HEALTH_DLX_WRITE_ERROR => "dlx-write-error",
            HEALTH_INVARIANT => "invariant",
            _ => "stopped",
        }
    }

    /// 一整轮 claim/relay（或 sweep）干净成功 → 恢复 Healthy（瞬态故障自愈，**非**单向 latch；F5）。
    ///
    /// 与 [`WorkerHealth::mark_degraded`] 同档（无条件 store）；仅在运行期由 tick 调用。
    /// **不得**用于 ackable 订阅恢复——订阅恢复走 [`WorkerHealth::mark_subscription_recovered`]，
    /// 以免洗掉已证实的 `dlx-write-error`。
    #[doc(hidden)]
    pub fn mark_healthy(&self) {
        if self.0.load(Ordering::Acquire) == HEALTH_INVARIANT {
            return;
        }
        self.0.store(HEALTH_HEALTHY, Ordering::Release);
    }

    /// A standby observation proves that the worker loop is live without proving a recovery from
    /// an earlier backend failure. It may therefore open only the initial Starting state.
    #[doc(hidden)]
    pub fn mark_started(&self) {
        let _ = self.0.compare_exchange(
            HEALTH_STARTING,
            HEALTH_HEALTHY,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Ackable 订阅通道恢复：仅 `starting` | `subscriber-unavailable` → Healthy（CAS）。
    ///
    /// 不覆盖 `dlx-write-error` / `invariant` / `degraded`——通道恢复 ≠ 全部故障清除。
    #[doc(hidden)]
    pub fn mark_subscription_recovered(&self) {
        loop {
            let current = self.0.load(Ordering::Acquire);
            if !matches!(current, HEALTH_STARTING | HEALTH_SUBSCRIBER_UNAVAILABLE) {
                return;
            }
            if self
                .0
                .compare_exchange(current, HEALTH_HEALTHY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// claim/relay/sweep 出错，或 relay 业务处置为 Requeue/Reject → Degraded（无条件 store，**非** CAS）。
    ///
    /// 顺序不变式由**构造**保证而非此方法：loop 仅在运行期每轮 tick 据结果二选一调
    /// `mark_healthy`/`mark_degraded`，退出时恰调一次终态 `mark_stopped`（Unhealthy）；cancel 后不再
    /// tick，故 Unhealthy 之后不会被运行期标记回退。
    pub(crate) fn mark_degraded(&self) {
        if self.0.load(Ordering::Acquire) == HEALTH_INVARIANT {
            return;
        }
        self.0.store(HEALTH_DEGRADED, Ordering::Release);
    }

    /// Projection adapter retry loops remain live while their provider is transiently unavailable.
    /// This narrow adapter hook records that state without conflating it with a stopped worker or
    /// an unavailable subscription transport.
    #[doc(hidden)]
    pub fn mark_projection_degraded(&self) {
        self.mark_degraded();
    }

    /// 订阅失败（broker/subscriber 不可用）→ Unhealthy，detail 固定为 subscriber-unavailable。
    ///
    /// 不覆盖已证实的 `dlx-write-error` / `invariant`（通道故障不得洗掉更高优先级故障态）。
    #[doc(hidden)]
    pub fn mark_subscriber_unavailable(&self) {
        if matches!(
            self.0.load(Ordering::Acquire),
            HEALTH_DLX_WRITE_ERROR | HEALTH_INVARIANT
        ) {
            return;
        }
        self.0
            .store(HEALTH_SUBSCRIBER_UNAVAILABLE, Ordering::Release);
    }

    /// DLX 写失败 → Degraded，detail 固定为 dlx-write-error。
    #[doc(hidden)]
    pub fn mark_dlx_write_error(&self) {
        self.0.store(HEALTH_DLX_WRITE_ERROR, Ordering::Release);
    }

    /// A verified safety invariant failed. This state is latched for the worker lifetime.
    pub(crate) fn mark_invariant(&self) {
        self.0.store(HEALTH_INVARIANT, Ordering::Release);
    }

    /// loop 退出（worker 停止运行）→ Unhealthy；readyz 据此翻。
    pub(crate) fn mark_stopped(&self) {
        if matches!(
            self.0.load(Ordering::Acquire),
            HEALTH_SUBSCRIBER_UNAVAILABLE | HEALTH_INVARIANT
        ) {
            return;
        }
        self.0.store(HEALTH_UNHEALTHY, Ordering::Release);
    }
}

// ── relay_loop（泛型，不 spawn）──────────────────────────────────────────────

/// Outbox relay 驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 从 provider 自身绑定的 domain 按 `config.max_in_flight()` 拉取一批 pending entry，立即并发
/// relay，并经
/// `metrics` 发射 `outbox_publish_total{status}` / `outbox_dlx_total` / `outbox_relay_tick_duration_seconds`
/// （#1209）。取消信号（`token.cancelled()`）在每轮循环顶部检查——当前条 relay 跑完再退，在途写不丢；
/// 取消在下一轮 loop 顶部生效（单条有界，尊重 shutdown budget）。`config` 经 [`RelayConfig`] funnel 已
/// 校验（`poll_interval`/`max_in_flight` 越界在构造点即拒，RELAY-CONFIG-01），此处不再防御 0ms 热轮询。
/// loop 退出（无论 cancel 还是 panic 外的正常返回）→ `health.mark_stopped()`。
pub async fn relay_loop<A>(
    store: Arc<A>,
    config: RelayConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn OutboxMetrics>,
) where
    A: OutboxRelay,
{
    let mut ticker = tokio::time::interval(config.poll_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                relay_tick(
                    &store,
                    config.max_in_flight(),
                    clock.as_ref(),
                    &health,
                    metrics.as_ref(),
                )
                .await;
            }
        }
    }
    health.mark_stopped();
}

/// Pause/resume handle plus bounded drain observation for an outbox relay loop.
///
/// Pause is admission-only: an already claimed batch finishes before the loop acknowledges a
/// drained state. Resume immediately closes a prior drained observation. Stopped is terminal.
#[derive(Clone)]
pub struct RelayWorkerControl {
    paused: watch::Sender<bool>,
    drain: WorkerDrainObservation,
}

impl RelayWorkerControl {
    /// Create a control to pass to [`relay_loop_controlled`] and retain at the composition root.
    pub fn new() -> Self {
        let (paused, _receiver) = watch::channel(false);
        Self {
            paused,
            drain: WorkerDrainObservation::new(),
        }
    }

    /// Stop new claims after the current relay batch completes.
    pub fn pause(&self) {
        if self.drain.is_stopped() {
            return;
        }
        self.paused.send_replace(true);
    }

    /// Resume relay claims.
    pub fn resume(&self) {
        if self.drain.is_stopped() {
            return;
        }
        self.drain.mark_running();
        self.paused.send_replace(false);
    }

    /// Current requested pause flag.
    pub fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    /// Number of entries in the currently claimed relay batch.
    pub fn in_flight(&self) -> usize {
        self.drain.in_flight()
    }

    /// Whether pause has taken effect and current relay work is zero, or the loop stopped.
    pub fn is_drained(&self) -> bool {
        self.drain.is_drained()
    }

    /// Whether the relay loop reached its terminal stopped state.
    pub fn is_stopped(&self) -> bool {
        self.drain.is_stopped()
    }

    /// Wait until admission is paused and current work reaches zero, or the loop stops.
    pub async fn wait_drained(&self) {
        self.drain.wait_drained().await;
    }
}

impl Default for RelayWorkerControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Outbox relay loop with explicit admission and drain control.
pub async fn relay_loop_controlled<A>(
    store: Arc<A>,
    config: RelayConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn OutboxMetrics>,
    control: RelayWorkerControl,
) where
    A: OutboxRelay,
{
    let mut ticker = tokio::time::interval(config.poll_interval());
    let mut paused = control.paused.subscribe();
    loop {
        if token.is_cancelled() {
            break;
        }
        if *paused.borrow() {
            control.drain.mark_paused();
            tokio::select! {
                biased;
                () = token.cancelled() => break,
                changed = paused.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
            continue;
        }
        control.drain.mark_running();
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            changed = paused.changed() => {
                if changed.is_err() {
                    break;
                }
            }
            _ = ticker.tick() => {
                relay_tick_controlled(
                    &store,
                    config.max_in_flight(),
                    clock.as_ref(),
                    &health,
                    metrics.as_ref(),
                    &control.drain,
                )
                .await;
            }
        }
    }
    control.drain.mark_stopped();
    health.mark_stopped();
}

/// 单轮 relay 健康结果——驱动 worker health（F4 把业务处置通道并入映射）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum TickOutcome {
    /// 全部 entry Ack（或空批次），无 claim/relay 错误。
    Clean,
    /// 出现 claim/relay 错误，或 relay 处置为 Requeue/Reject（broker 失败 / DLX）。
    Degraded,
}

/// relay 单轮 tick（抽出控制认知复杂度 ≤15）：domain 只由 provider 暴露，避免 config 与 publisher
/// 形成可错插的双输入；本轮结果一次性翻 health。
///
/// 干净（含空轮）→ `mark_healthy`（F5：瞬态故障下一轮自愈）；任一 claim/relay 错误或
/// Requeue/Reject 处置 → `mark_degraded`（F4：health 不再只表达异常通道）。
async fn relay_tick<A>(
    store: &Arc<A>,
    max_in_flight: usize,
    clock: &dyn diport::Clock,
    health: &Arc<WorkerHealth>,
    metrics: &dyn OutboxMetrics,
) where
    A: OutboxRelay,
{
    let tick = relay_domain_once(store, max_in_flight, clock, metrics, None).await;
    match tick {
        TickOutcome::Clean => health.mark_healthy(),
        TickOutcome::Degraded => health.mark_degraded(),
    }
}

async fn relay_tick_controlled<A>(
    store: &Arc<A>,
    max_in_flight: usize,
    clock: &dyn diport::Clock,
    health: &Arc<WorkerHealth>,
    metrics: &dyn OutboxMetrics,
    drain: &WorkerDrainObservation,
) where
    A: OutboxRelay,
{
    let tick = relay_domain_once(store, max_in_flight, clock, metrics, Some(drain)).await;
    match tick {
        TickOutcome::Clean => health.mark_healthy(),
        TickOutcome::Degraded => health.mark_degraded(),
    }
}

/// 注入 Clock 计相对时延（秒）：`now − start`；时钟回拨（end<start）⇒ 0（不发负样本）。
/// 经构造器注入的 [`diport::Clock`] 读时，遵 clock 注入纪律（禁直调 `Instant`/`SystemTime::now`）。
fn secs_since(clock: &dyn diport::Clock, start: SystemTime) -> f64 {
    clock
        .now()
        .duration_since(start)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// 单 domain 一轮：原子 claim 一批（计 claim 相耗时）→ 即时并发中继（计 publish 相耗时 + 发 publish 计数），返回该
/// domain 的 [`TickOutcome`]（早返展平嵌套 + 批中继抽 [`relay_batch`]，认知复杂度 ≤15）。
async fn relay_domain_once<A>(
    store: &Arc<A>,
    batch: usize,
    clock: &dyn diport::Clock,
    metrics: &dyn OutboxMetrics,
    drain: Option<&WorkerDrainObservation>,
) -> TickOutcome
where
    A: OutboxRelay,
{
    let domain = store.claim_domain();
    let claim_start = clock.now();
    let claim_result = store.claim_batch(batch).await;
    metrics.record_tick_duration(RelayPhase::Claim, secs_since(clock, claim_start));
    let entries = match claim_result {
        Ok(entries) => entries,
        Err(e) => {
            log_claim_failed(domain.as_str(), &e);
            return TickOutcome::Degraded;
        }
    };
    if !entries.is_empty() {
        log_claimed(domain.as_str(), entries.len());
    }
    if let Some(drain) = drain {
        drain.set_in_flight(entries.len());
    }
    let publish_start = clock.now();
    let outcome = relay_batch(store, domain, entries, metrics).await;
    if let Some(drain) = drain {
        drain.set_in_flight(0);
    }
    metrics.record_tick_duration(RelayPhase::Publish, secs_since(clock, publish_start));
    outcome
}

/// 并发中继一批 entry：发 `outbox_publish_total{status}`（含 Ack）+ 翻 [`TickOutcome`]（抽出控制
/// [`relay_domain_once`] 认知复杂度 ≤15）。
///
/// # INVARIANT: OUTBOX-RELAY-IMMEDIATE-DISPATCH-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// entries **立即并发**投递；per-partition in-order 由 SQL head-of-partition gating 承载：同一 claim
/// batch 对每个 `(tenant, domain, partition)` 至多返回队头一条，因此本批内不存在同 partition 的并发项。
/// `RelayConfig::max_in_flight` 同时限制 claim 数和并发数，不让已持租 entry 在应用队列中串行等待至过期。
///
/// 不在 relay 外套 select!：当前条 publish+CAS 跑完再退，在途写不丢；取消在下一轮 loop 顶部生效
/// （单条有界，尊重 shutdown budget）。
async fn relay_batch<A>(
    store: &Arc<A>,
    domain: &DomainName,
    entries: Vec<A::Claim>,
    metrics: &dyn OutboxMetrics,
) -> TickOutcome
where
    A: OutboxRelay,
{
    let mut outcome = TickOutcome::Clean;
    let results = futures::future::join_all(entries.into_iter().map(|entry| async move {
        // Claim 按值消费；仅复制低基数 metric subject，绝不复制 lease capability。
        let subject = A::claim_subject(&entry).clone();
        (subject, store.relay(entry).await)
    }))
    .await;
    for (subject, result) in results {
        match result {
            Ok(disposition) => {
                let scope = OutboxMetricScope::new(domain, &subject);
                metrics.record_publish(&scope, disposition);
                if disposition != Disposition::Ack {
                    // Requeue（broker 瞬态失败，退避重投）/ Reject（预算耗尽进 DLX）——业务处置通道映射为
                    // Degraded（F4）。`!= Ack` 兜底 `Disposition` 的 `#[non_exhaustive]` 未来处置（保守降级）。
                    log_relay_disposition(domain.as_str(), disposition);
                    outcome = TickOutcome::Degraded;
                }
            }
            Err(e) => {
                log_relay_failed(domain.as_str(), &e);
                outcome = TickOutcome::Degraded;
            }
        }
    }
    outcome
}

// ── 结构化日志 helper（抽出 tracing 宏展开，控制调用方认知复杂度 ≤15；
//    仿 lib.rs `log_dropped_*` 范式）。勿记 payload/PII。 ─────────────────────────
//
// PII 安全：`error = %e` 记的是 `consistency::EngineError` 的 Display，而 EngineError::Display 仅输出
// `kind().message()`（`&'static str` const，无 runtime 数据/SQL/PII——`engine_error_display_equals_kind_message`
// 测试约束）；adapter 层 sqlx 错误已在落 EngineError 前经 `secure::redact_error` 清洗。**前提**：EngineError
// 若未来新增携 runtime 数据的 variant，本处需复核（同 consumer.rs `log_dead_lettered` 假设）。

/// claim_batch 失败：退避到下一 tick 前结构化记录。
fn log_claim_failed(domain: &str, e: &impl std::fmt::Display) {
    tracing::warn!(
        domain,
        error = %e,
        "relay: claim_batch failed, marking worker degraded; backing off to next tick"
    );
}

/// 单条 entry 中继失败：标记 worker degraded 前结构化记录。
fn log_relay_failed(domain: &str, e: &impl std::fmt::Display) {
    tracing::warn!(
        domain,
        error = %e,
        "relay: entry relay failed, marking worker degraded"
    );
}

/// 单条 entry 业务处置为 Requeue/Reject（broker 失败 / DLX）：标记 worker degraded 前结构化记录（F4）。
fn log_relay_disposition(domain: &str, disposition: Disposition) {
    tracing::warn!(
        domain,
        disposition = disposition.as_label(),
        "relay: entry settled with non-ack disposition, marking worker degraded"
    );
}

/// 单轮捞到非空批次：结构化记录批量（正常路径可观测；空轮不记，减噪）。
fn log_claimed(domain: &str, claimed: usize) {
    tracing::debug!(domain, claimed, "relay: tick claimed");
}

// ── sweeper_loop（泛型，不 spawn）────────────────────────────────────────────

/// 保留期 sweeper 驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 调 `store.sweep(config.retain_seconds())`，删除超保留期已终结行。`config` 经
/// [`SweeperConfig`] funnel 已校验（`sweep_interval`≠0、`retain_seconds`≠0，SWEEPER-CONFIG-01）。
/// 取消/错误处理与 `relay_loop` 同骨架。
///
/// 泛型 `S: RetentionSweeper` ⇒ 可驱动 outbox / inbox receipt 的有界保留清理；
/// dead-letter 使用独立的 archive-before-purge lifecycle，不能接入此 sweeper。
/// 各表的终结谓词 + 时间列由对应 adapter impl 决定，本 loop 只负责 tick 调度与健康/取消骨架。
///
/// `target`（低基数 `&'static str`，如 `outbox` / `inbox_receipts`）= 本 loop 驱动的清理目标——
/// 泛型 store 自身无表身份，故由 spawn 端显式传入并写入每轮成功/失败日志，使多表 sweeper 的日志可归因（#327
/// review F2）。worker 身份见 [`SweeperWorker::adopt`] 的 `name` 参数（per-target readyz 命名）。
pub async fn sweeper_loop<S>(
    store: Arc<S>,
    config: SweeperConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    target: RetentionTarget,
) where
    S: RetentionSweeper,
{
    let mut ticker = tokio::time::interval(config.sweep_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => sweeper_tick(
                &store,
                config.retain_seconds(),
                clock.as_ref(),
                &health,
                target,
            ).await,
        }
    }
    health.mark_stopped();
}

/// sweeper 单轮 tick（抽出控制认知复杂度 ≤15）。`target` 写入日志使清理目标可归因。
async fn sweeper_tick<S>(
    store: &Arc<S>,
    retain_seconds: u64,
    clock: &dyn diport::Clock,
    health: &Arc<WorkerHealth>,
    target: RetentionTarget,
) where
    S: RetentionSweeper,
{
    let started = clock.now();
    let metrics = MetricsRetentionMetrics;
    match store.sweep(retain_seconds).await {
        Ok(deleted) => {
            metrics.record_sweep(
                target,
                RetentionOutcome::Success,
                deleted,
                secs_since(clock, started),
            );
            tracing::debug!(
                target_table = target.as_label(),
                deleted,
                "sweeper: tick completed"
            );
            health.mark_healthy(); // 干净一轮 → 恢复 Healthy（F5：瞬态故障自愈，非单向 latch）。
        }
        Err(e) => {
            metrics.record_sweep(
                target,
                RetentionOutcome::Transient,
                0,
                secs_since(clock, started),
            );
            log_sweep_failed(target.as_label(), &e);
            health.mark_degraded();
        }
    }
}

/// sweep 失败：标记 worker degraded 前结构化记录（抽出 tracing 宏展开）。`target` 标识清理目标表。
fn log_sweep_failed(target: &'static str, e: &impl std::fmt::Display) {
    tracing::warn!(
        target_table = target,
        error = %e,
        "sweeper: sweep failed, marking worker degraded; backing off to next tick"
    );
}

// ── backlog_sampler_loop（泛型，不 spawn）────────────────────────────────────

type BacklogScopeState = HashMap<String, HashSet<ObservedBacklogScope>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservedBacklogScope {
    tenant_id: vocab::TenantId,
    contract_id: OutboxContractId,
}

impl ObservedBacklogScope {
    fn from_subject(subject: &OutboxMetricSubject) -> Self {
        Self {
            tenant_id: subject.tenant_id(),
            contract_id: subject.contract_id().clone(),
        }
    }

    fn to_subject(&self) -> OutboxMetricSubject {
        OutboxMetricSubject::new(self.tenant_id, self.contract_id.clone())
    }
}

/// Outbox backlog 采样驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 逐 `config.domains()` 采样 backlog（pending depth + 最老 pending 龄）→ 经 `metrics`
/// set `outbox_pending_depth{domain,contract_id,tenant_id}` /
/// `outbox_oldest_pending_age_seconds{domain,contract_id,tenant_id}` gauge；同一进程内已观测 scope
/// 后续从成功采样结果消失时显式置 0，避免保留陈旧非零 series（#1209/#1625）。
/// [`BacklogObservation::Standby`] 不是成功空采样：不写 gauge、不清理已观测 scope，也不把 worker
/// health 恢复为 Healthy；只有 active observation 能变更这三类状态。
/// 独立于 relay/sweeper 的专用 worker（独立 [`WorkerHealth`]）：gauge 新鲜度由 `config.sample_interval()`
/// 解耦 relay 吞吐与 retention 周期（默认数十秒，远密于 5min oldest-age SLO 窗口），采样失败只降级
/// `outbox_sampler` probe、不污染 relay readyz。取消/错误骨架同 `sweeper_loop`。
/// `config`（domains / sample_interval）经 [`SamplerConfig`] funnel 已校验（SAMPLER-CONFIG-01），
/// 同 [`relay_loop`]），此处不再防御 0 间隔 / 越界 domain 集。
pub async fn backlog_sampler_loop<B>(
    store: Arc<B>,
    config: SamplerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn OutboxMetrics>,
) where
    B: OutboxBacklog,
{
    let mut ticker = tokio::time::interval(config.sample_interval());
    let mut observed_scopes = BacklogScopeState::default();
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                sampler_tick(
                    &store,
                    config.domains(),
                    &mut observed_scopes,
                    &health,
                    metrics.as_ref(),
                ).await;
            }
        }
    }
    health.mark_stopped();
}

/// sampler 单轮 tick：逐 domain 采样 + 发 gauge；成功采样时补齐“上一轮有、本轮无”的 scope 零值。
/// 任一 domain 采样 Err → 整轮 Degraded 且不清理该 domain 的上一轮状态（其余 domain 仍尝试，不早退）。
/// 存在 standby → 保持 health；全 active 且干净 → Healthy（F5 自愈）。
async fn sampler_tick<B>(
    store: &Arc<B>,
    domains: &[DomainName],
    observed_scopes: &mut BacklogScopeState,
    health: &Arc<WorkerHealth>,
    metrics: &dyn OutboxMetrics,
) where
    B: OutboxBacklog,
{
    let mut degraded = false;
    let mut standby = false;
    for domain in domains {
        match store.sample_backlog(domain.as_str()).await {
            Ok(BacklogObservation::Active(samples)) => {
                let mut current_scopes = HashSet::with_capacity(samples.len());
                for sample in samples {
                    current_scopes.insert(ObservedBacklogScope::from_subject(sample.subject()));
                    let scope = OutboxMetricScope::new(domain, sample.subject());
                    metrics.record_backlog(&scope, sample.sample());
                    metrics.record_partition_blocked(&scope, sample.partition_blocked_depth());
                }
                let stale_scopes = observed_scopes
                    .get(domain.as_str())
                    .map(|previous| {
                        previous
                            .difference(&current_scopes)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                for stale_scope in stale_scopes {
                    let subject = stale_scope.to_subject();
                    let scope = OutboxMetricScope::new(domain, &subject);
                    metrics.record_backlog(&scope, BacklogSample::empty());
                    metrics.record_partition_blocked(&scope, 0);
                }
                if current_scopes.is_empty() {
                    observed_scopes.remove(domain.as_str());
                } else {
                    observed_scopes.insert(domain.as_str().to_owned(), current_scopes);
                }
            }
            Ok(BacklogObservation::Standby) => standby = true,
            Err(e) => {
                log_sample_failed(domain.as_str(), &e);
                degraded = true;
            }
        }
    }
    if degraded {
        health.mark_degraded();
    } else if standby {
        health.mark_started();
    } else {
        health.mark_healthy();
    }
}

/// backlog 采样失败：标记 worker degraded 前结构化记录（抽出 tracing 宏展开）。勿记 payload/PII。
fn log_sample_failed(domain: &str, e: &impl std::fmt::Display) {
    tracing::warn!(
        domain,
        error = %e,
        "sampler: sample_backlog failed, marking worker degraded; backing off to next tick"
    );
}

// ── worker 两阶段关闭共享 helper ─────────────────────────────────────────────

/// adopt 式 worker 关闭收敛（[`RelayWorker`] / [`SweeperWorker`] 共用）：防御性 cancel（幂等）→ await
/// JoinHandle。task panic/abort 的 `JoinError` 包成 typed [`diport::ShutdownError`] 上抛——**不**再
/// `let _ = h.await` 吞掉，使 panic/abort 误报成关闭成功（F6；接 `ManagedResource::shutdown` typed 语义）。
async fn shutdown_worker(
    token: &CancellationToken,
    inner: &tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
) -> Result<(), diport::ShutdownError> {
    // 防御性 cancel（幂等；生产中 ShutdownStack 已先 cancel，此处兜底防 test/误用 hang）。
    token.cancel();
    // await loop 收敛——保证 worker 在 pool 之前停（LIFO 由组合根注册顺序保证）、在途写不丢。
    if let Some(h) = inner.lock().await.take() {
        h.join()
            .await
            .map_err(diport::ShutdownError::from_join_error)?;
    }
    Ok(())
}

// ── adopt 式 worker（共用 AdoptedWorker + newtype 委派）────────────────────────

/// adopt 式后台 worker 通用状态（[`RelayWorker`] / [`SweeperWorker`] / [`SamplerWorker`] 共用）。
///
/// 持已 spawn 的 `JoinHandle<()>` + 同一 health + 同一 token；三个 public worker 各 newtype 包裹一个
/// `AdoptedWorker`、委派 `adopt`/`health`/`shutdown`，消除字段集 + 构造 + 访问器三副本（#1209 review）。
/// public worker 仍是**具体类型**——relay_loop/sweeper_loop/backlog_sampler_loop 是泛型非-Send，spawn 在
/// 具体 call site 单态化后 future 才 Send（见本文件 §设计摘要），故不能合并成单一 generic worker。
struct AdoptedWorker {
    inner: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl AdoptedWorker {
    fn adopt(handle: JoinHandle<()>, health: Arc<WorkerHealth>, token: CancellationToken) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            health,
            token,
        }
    }

    fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        shutdown_worker(&self.token, &self.inner).await
    }
}

/// 由 newtype 包裹 [`AdoptedWorker`] 生成 public worker + 委派 `ManagedResource`（仅 `name()` 各异）。
macro_rules! adopt_worker {
    ($(#[doc = $doc:literal])+ $worker:ident => $name_const:ident) => {
        $(#[doc = $doc])+
        ///
        /// adopt 式：先在具体类型处 `tokio::spawn(<loop>::<ConcreteStore>(...))` 再 `adopt`。
        pub struct $worker(AdoptedWorker);

        impl $worker {
            /// 组合根/测试：先 spawn 对应 loop(具体类型)，再 adopt JoinHandle + 同一 health + 同一 token。
            pub fn adopt(
                handle: JoinHandle<()>,
                health: Arc<WorkerHealth>,
                token: CancellationToken,
            ) -> Self {
                Self(AdoptedWorker::adopt(handle, health, token))
            }

            /// 读 worker health（readyz 聚合用）。
            pub fn health(&self) -> Arc<WorkerHealth> {
                self.0.health()
            }
        }

        impl diport::ManagedResource for $worker {
            fn name(&self) -> &str {
                $name_const
            }

            fn shutdown_timeout(&self) -> Duration {
                WORKER_SHUTDOWN_TIMEOUT
            }

            async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
                self.0.shutdown().await
            }
        }
    };
}

adopt_worker!(
    /// Outbox relay 后台 worker。
    RelayWorker => RELAY_WORKER_NAME
);
adopt_worker!(
    /// Outbox backlog 采样后台 worker（结构与 [`RelayWorker`] 同构）。
    SamplerWorker => SAMPLER_WORKER_NAME
);

/// 保留期 sweeper 后台 worker（结构与 [`RelayWorker`] 同构，但 **readyz name 运行期携带**）。
///
/// 同一泛化 `sweeper_loop` 可服务 outbox / inbox receipt durable 表，故 worker 身份不再是
/// 编译期常量——由 [`SweeperWorker::adopt`] 的 `name` 参数（per-target，如 [`SWEEPER_WORKER_NAME`]）决定，使
/// readyz 聚合能区分各表 sweeper（#327 review F2）。adopt 式：先在具体类型处 `tokio::spawn(sweeper_loop::<S>(..))` 再 `adopt`。
pub struct SweeperWorker {
    inner: AdoptedWorker,
    name: &'static str,
}

impl SweeperWorker {
    /// 组合根/测试：先 spawn `sweeper_loop`(具体类型)，再 adopt JoinHandle + 同一 health/token + per-target `name`
    /// （readyz 命名，如 `outbox-sweeper` / `inbox-dedup-sweeper`）。
    pub fn adopt(
        name: &'static str,
        handle: JoinHandle<()>,
        health: Arc<WorkerHealth>,
        token: CancellationToken,
    ) -> Self {
        Self {
            inner: AdoptedWorker::adopt(handle, health, token),
            name,
        }
    }

    /// 读 worker health（readyz 聚合用）。
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.inner.health()
    }
}

impl diport::ManagedResource for SweeperWorker {
    fn name(&self) -> &str {
        self.name
    }

    fn shutdown_timeout(&self) -> Duration {
        WORKER_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.inner.shutdown().await
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomOrd};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::outbox::{
        BacklogMetricSample, BacklogSample, Disposition, OutboxContractId, OutboxMetricSubject,
    };
    use consistency::{OutboxBacklog, OutboxRelay, RetentionSweeper};
    use diport::ManagedResource;
    use primitives::healthz::{HealthStatus, ProbeName};
    use tokio::sync::{Barrier, Notify};
    use tokio_util::sync::CancellationToken;
    use vocab::DomainName;

    use super::{
        OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE, SWEEPER_WORKER_NAME,
        SamplerWorker, SweeperWorker, WorkerHealth, backlog_sampler_loop, sweeper_loop,
    };
    use crate::RetentionTarget;
    use crate::relay::{RelayWorker, RelayWorkerControl, relay_loop, relay_loop_controlled};
    use crate::relay_config::{RelayConfig, SamplerConfig, SweeperConfig};
    use crate::relay_metrics::{OutboxMetricScope, OutboxMetrics, RelayPhase};
    // ── 测试配置 / metrics 辅助 ───────────────────────────────────────────────

    /// 合法测试 RelayConfig（max_in_flight=10）。
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out（error-handling.md §Carve-out）。
    fn relay_config(poll: Duration) -> RelayConfig {
        RelayConfig::new(poll, 10).expect("valid test relay config")
    }

    /// 合法测试 SamplerConfig。
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out。
    fn sampler_config(domains: &[&str], sample: Duration) -> SamplerConfig {
        SamplerConfig::new(
            domains.iter().map(|domain| (*domain).to_owned()).collect(),
            sample,
        )
        .expect("valid test sampler config")
    }

    /// 合法测试 SweeperConfig。
    #[allow(clippy::expect_used)]
    // reason: 同上。
    fn sweeper_config(retain: u64, sweep: Duration) -> SweeperConfig {
        SweeperConfig::new(retain, sweep).expect("valid test sweeper config")
    }

    /// 丢弃式 metrics（loop 测试不断言发射时用；复用 CountingMetrics fake，不另设 public no-op）。
    fn noop_metrics() -> Arc<dyn OutboxMetrics> {
        CountingMetrics::new()
    }

    /// 固定时钟（test 替身；`duration_since` 恒 0，满足 tick 相记录断言又不触系统时钟纪律）。
    struct FixedClock;
    impl diport::Clock for FixedClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
    }
    fn fixed_clock() -> Arc<dyn diport::Clock> {
        Arc::new(FixedClock)
    }

    /// 解析测试 domain（合法 DomainName，crate-name 形）。
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 已知合法 domain，item-level carve-out（error-handling.md §Carve-out）。
    fn dn(s: &str) -> vocab::DomainName {
        vocab::DomainName::parse(s).expect("valid test domain")
    }

    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 已知合法 tenant / contract。
    fn subject(contract_id: &str) -> OutboxMetricSubject {
        OutboxMetricSubject::new(
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("valid test tenant"),
            OutboxContractId::parse(contract_id).expect("valid test contract"),
        )
    }

    fn backlog_sample(contract_id: &str, sample: BacklogSample) -> BacklogMetricSample {
        BacklogMetricSample::new(subject(contract_id), sample)
    }

    fn blocked_backlog_sample(
        contract_id: &str,
        sample: BacklogSample,
        partition_blocked_depth: u64,
    ) -> BacklogMetricSample {
        BacklogMetricSample::with_partition_blocked_depth(
            subject(contract_id),
            sample,
            partition_blocked_depth,
        )
    }

    /// 记录发射调用的 metrics fake（确定性断言；不碰全局 recorder）。
    #[derive(Default)]
    struct CountingMetrics {
        publishes: Mutex<Vec<(String, String, String, Disposition)>>,
        backlogs: Mutex<Vec<(String, String, String, BacklogSample)>>,
        partition_blocked: Mutex<Vec<(String, String, String, u64)>>,
        tick_phases: Mutex<Vec<RelayPhase>>,
    }

    impl CountingMetrics {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        #[allow(clippy::unwrap_used)]
        // reason: Mutex lock in test，item-level carve-out。
        fn publishes(&self) -> Vec<(String, String, String, Disposition)> {
            self.publishes.lock().unwrap().clone()
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn backlogs(&self) -> Vec<(String, String, String, BacklogSample)> {
            self.backlogs.lock().unwrap().clone()
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn partition_blocked(&self) -> Vec<(String, String, String, u64)> {
            self.partition_blocked.lock().unwrap().clone()
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn tick_phases(&self) -> Vec<RelayPhase> {
            self.tick_phases.lock().unwrap().clone()
        }
    }

    impl OutboxMetrics for CountingMetrics {
        #[allow(clippy::unwrap_used)]
        // reason: Mutex lock in test。
        fn record_publish(&self, scope: &OutboxMetricScope<'_>, disposition: Disposition) {
            self.publishes.lock().unwrap().push((
                scope.domain_label().to_string(),
                scope.contract_id_label().to_string(),
                scope.tenant_id_label(),
                disposition,
            ));
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn record_backlog(&self, scope: &OutboxMetricScope<'_>, sample: BacklogSample) {
            self.backlogs.lock().unwrap().push((
                scope.domain_label().to_string(),
                scope.contract_id_label().to_string(),
                scope.tenant_id_label(),
                sample,
            ));
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn record_partition_blocked(&self, scope: &OutboxMetricScope<'_>, blocked_depth: u64) {
            self.partition_blocked.lock().unwrap().push((
                scope.domain_label().to_string(),
                scope.contract_id_label().to_string(),
                scope.tenant_id_label(),
                blocked_depth,
            ));
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn record_tick_duration(&self, phase: RelayPhase, _seconds: f64) {
            self.tick_phases.lock().unwrap().push(phase);
        }
    }

    /// Fake backlog 采样源：返预置 sample 或 Err。
    struct FakeBacklog {
        samples: Vec<BacklogMetricSample>,
        err: Option<consistency::error::EngineErrorKind>,
    }

    impl FakeBacklog {
        fn new(sample: BacklogSample) -> Arc<Self> {
            Self::with_samples(vec![backlog_sample("identity.session-created", sample)])
        }
        fn with_samples(samples: Vec<BacklogMetricSample>) -> Arc<Self> {
            Arc::new(Self { samples, err: None })
        }
        fn with_err(kind: consistency::error::EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                samples: vec![],
                err: Some(kind),
            })
        }
    }

    impl OutboxBacklog for FakeBacklog {
        async fn sample_backlog(
            &self,
            _domain: &str,
        ) -> Result<consistency::BacklogObservation, consistency::error::EngineError> {
            if let Some(kind) = self.err {
                return Err(consistency::error::EngineError::new(kind));
            }
            Ok(consistency::BacklogObservation::Active(
                self.samples.clone(),
            ))
        }
    }

    struct StandbyBacklog;

    impl OutboxBacklog for StandbyBacklog {
        async fn sample_backlog(
            &self,
            _domain: &str,
        ) -> Result<consistency::BacklogObservation, consistency::error::EngineError> {
            Ok(consistency::BacklogObservation::Standby)
        }
    }

    // ── Fake store（具体类型；Send 友好：用 Arc<Mutex>/Atomic，不跨 await 持有锁）──

    /// Fake provider 私有铸造、按值消费的 non-Clone claim。
    struct FakeClaim {
        subject: OutboxMetricSubject,
    }

    impl FakeClaim {
        fn new(subject: OutboxMetricSubject) -> Self {
            Self { subject }
        }
    }

    fn make_claimed_entry() -> FakeClaim {
        FakeClaim::new(subject("identity.session-created"))
    }

    /// bounded yield：让 spawned worker task 推进，至多 32 次 yield 等到 `want` 状态后返回 true。
    /// `start_paused` 下无真实 I/O、interval 首 tick 立即就绪，目标状态实际 1–2 次 yield 即到达；32 是
    /// 宽裕上限（容调度器交错），非临界值——确定性收敛而非靠时序竞态。超出预算返回 false（断言失败）。
    async fn yield_until(health: &Arc<WorkerHealth>, want: HealthStatus) -> bool {
        for _ in 0..32 {
            if health.status() == want {
                return true;
            }
            tokio::task::yield_now().await;
        }
        health.status() == want
    }

    /// Fake store：统一实现 claim + relay capability。
    /// - claim：按轮次从预置队列吐 entries（每次 claim 返回队列头部至多 batch 条）。
    /// - relay：计数调用，按预置策略返 Ok(Disposition)/Err。
    struct FakeStore {
        /// provider 构造时绑定的唯一发布域。
        domain: DomainName,
        /// 预置 claims（每次 claim 弹出头部 batch 条）。
        claims: Mutex<Vec<FakeClaim>>,
        /// relay 调用计数。
        relay_count: AtomicUsize,
        /// relay 返回错误策略：None=Ok(relay_disposition)，Some(kind)=Err。
        relay_err: Option<consistency::error::EngineErrorKind>,
        /// relay 成功路径返回的处置（默认 Ack；测 F4 时置 Requeue/Reject）。
        relay_disposition: Disposition,
        /// claim 返回错误策略：None=Ok，Some(kind)=Err。
        claim_err: Option<consistency::error::EngineErrorKind>,
    }

    impl FakeStore {
        fn new(entries: Vec<FakeClaim>) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("identity"),
                claims: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: Disposition::Ack,
                claim_err: None,
            })
        }

        fn with_relay_err(
            entries: Vec<FakeClaim>,
            kind: consistency::error::EngineErrorKind,
        ) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("identity"),
                claims: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: Some(kind),
                relay_disposition: Disposition::Ack,
                claim_err: None,
            })
        }

        /// relay 成功但返回非-Ack 处置（Requeue/Reject）——测 F4 health 映射。
        fn with_relay_disposition(entries: Vec<FakeClaim>, disposition: Disposition) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("identity"),
                claims: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: disposition,
                claim_err: None,
            })
        }

        fn with_claim_err(kind: consistency::error::EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("identity"),
                claims: Mutex::new(vec![]),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: Disposition::Ack,
                claim_err: Some(kind),
            })
        }

        fn relay_count(&self) -> usize {
            self.relay_count.load(AtomOrd::Acquire)
        }
    }

    impl OutboxRelay for FakeStore {
        type Claim = FakeClaim;

        fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &DomainName {
            &self.domain
        }

        async fn claim_batch(
            &self,
            limit: usize,
        ) -> Result<Vec<Self::Claim>, consistency::error::EngineError> {
            if let Some(kind) = self.claim_err {
                return Err(consistency::error::EngineError::new(kind));
            }
            #[allow(clippy::unwrap_used)]
            // reason: Mutex lock in test，item-level carve-out
            let mut claims = self.claims.lock().unwrap();
            let drain_end = limit.min(claims.len());
            let batch = claims.drain(..drain_end).collect();
            Ok(batch)
        }
        async fn relay(
            &self,
            _entry: Self::Claim,
        ) -> Result<Disposition, consistency::error::EngineError> {
            if let Some(kind) = self.relay_err {
                return Err(consistency::error::EngineError::new(kind));
            }
            self.relay_count.fetch_add(1, AtomOrd::Release);
            Ok(self.relay_disposition)
        }
    }

    struct ObservedRelayStore {
        domain: DomainName,
        claims: Mutex<Vec<FakeClaim>>,
        claim_count: AtomicUsize,
        started: AtomicUsize,
        changed: Notify,
        finish: Notify,
    }

    impl ObservedRelayStore {
        fn new(entries: Vec<FakeClaim>) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("identity"),
                claims: Mutex::new(entries),
                claim_count: AtomicUsize::new(0),
                started: AtomicUsize::new(0),
                changed: Notify::new(),
                finish: Notify::new(),
            })
        }

        async fn wait_until_started(&self, count: usize) {
            loop {
                let changed = self.changed.notified();
                if self.started.load(AtomOrd::Acquire) >= count {
                    break;
                }
                changed.await;
            }
        }
    }

    impl OutboxRelay for ObservedRelayStore {
        type Claim = FakeClaim;

        fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &DomainName {
            &self.domain
        }

        async fn claim_batch(
            &self,
            limit: usize,
        ) -> Result<Vec<Self::Claim>, consistency::error::EngineError> {
            self.claim_count.fetch_add(1, AtomOrd::Release);
            let mut claims = self
                .claims
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let drain_end = limit.min(claims.len());
            Ok(claims.drain(..drain_end).collect())
        }

        async fn relay(
            &self,
            _entry: Self::Claim,
        ) -> Result<Disposition, consistency::error::EngineError> {
            self.started.fetch_add(1, AtomOrd::Release);
            self.changed.notify_waiters();
            self.finish.notified().await;
            Ok(Disposition::Ack)
        }
    }

    /// 所有 relay future 必须同时开始，才能越过 barrier；串行实现会超时。
    struct ConcurrentRelayStore {
        domain: DomainName,
        barrier: Barrier,
    }

    impl ConcurrentRelayStore {
        fn new(width: usize) -> Arc<Self> {
            Arc::new(Self {
                domain: dn("dom"),
                barrier: Barrier::new(width),
            })
        }
    }

    impl OutboxRelay for ConcurrentRelayStore {
        type Claim = FakeClaim;

        fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject {
            &claim.subject
        }

        fn claim_domain(&self) -> &DomainName {
            &self.domain
        }

        async fn claim_batch(
            &self,
            _limit: usize,
        ) -> Result<Vec<Self::Claim>, consistency::error::EngineError> {
            Ok(Vec::new())
        }
        async fn relay(
            &self,
            _entry: Self::Claim,
        ) -> Result<Disposition, consistency::error::EngineError> {
            self.barrier.wait().await;
            Ok(Disposition::Ack)
        }
    }

    /// F4 复现：一批 claim 必须即时并发 dispatch；串行等待会让批尾在首次 publish 前消耗租约。
    #[tokio::test]
    async fn claimed_batch_is_dispatched_without_serial_tail_wait() {
        let width = 3;
        let store = ConcurrentRelayStore::new(width);
        let entries = (0..width).map(|_| make_claimed_entry()).collect();
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            super::relay_batch(&store, &dn("dom"), entries, &CountingMetrics::default()),
        )
        .await;
        assert!(
            result.is_ok(),
            "all claimed entries must begin relay concurrently within the lease budget"
        );
    }

    /// Fake sweeper：impl RetentionSweeper，计数调用并按策略返结果。
    struct FakeSweeper {
        sweep_count: AtomicUsize,
        sweep_err: Option<consistency::error::EngineErrorKind>,
    }

    impl FakeSweeper {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sweep_count: AtomicUsize::new(0),
                sweep_err: None,
            })
        }

        fn with_err(kind: consistency::error::EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                sweep_count: AtomicUsize::new(0),
                sweep_err: Some(kind),
            })
        }

        #[allow(dead_code)]
        // reason: 保留供未来断言 sweeper 实际执行次数的测试用；当前仅测 health 状态路径，未用到计数。
        fn sweep_count(&self) -> usize {
            self.sweep_count.load(AtomOrd::Acquire)
        }
    }

    impl RetentionSweeper for FakeSweeper {
        async fn sweep(
            &self,
            _retain_seconds: u64,
        ) -> Result<u64, consistency::error::EngineError> {
            if let Some(kind) = self.sweep_err {
                return Err(consistency::error::EngineError::new(kind));
            }
            self.sweep_count.fetch_add(1, AtomOrd::Release);
            Ok(0)
        }
    }

    // ── T8：两阶段逆序 shutdown，在途写不丢 ──────────────────────────────────

    /// T8：cancel → shutdown 后断言已预置的 entries 全部被 relay（无半途丢弃）。
    ///
    /// 使用 `start_paused=true` 控 interval tick：先手动 advance，驱动一轮 poll+relay，
    /// 再 cancel → shutdown → 断言 relay_count == entry 数。
    #[tokio::test(start_paused = true)]
    async fn t8_shutdown_drains_in_flight_entries() {
        let entries: Vec<FakeClaim> = (0..3).map(|_| make_claimed_entry()).collect();
        let entry_count = entries.len();
        let store = FakeStore::new(entries);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        // spawn relay_loop（具体类型 FakeStore，future 具体 Send，tokio::spawn 编得过）。
        let handle = tokio::spawn(relay_loop(
            store.clone(),
            relay_config(Duration::from_millis(100)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));

        let worker = RelayWorker::adopt(handle, health.clone(), token.clone());

        // 推进时间触发 interval tick：relay_loop 会执行一轮 poll+relay。
        tokio::time::advance(std::time::Duration::from_millis(200)).await;
        // 让调度器切换到 relay_loop 任务完成本轮。
        tokio::task::yield_now().await;

        // 取消 + shutdown（两阶段逆序）。
        token.cancel();
        let result = worker.shutdown().await;

        assert!(result.is_ok(), "shutdown must succeed: {result:?}");
        // 所有 entries 均已 relay（在途写不丢）。
        assert_eq!(
            store.relay_count(),
            entry_count,
            "all entries must be relayed before shutdown"
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed positive max-in-flight fixture is part of the relay drain control proof.
    async fn relay_control_observes_pause_drain_resume_and_stop() {
        let store = ObservedRelayStore::new(vec![make_claimed_entry(), make_claimed_entry()]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let control = RelayWorkerControl::new();
        let config = RelayConfig::new(Duration::from_secs(60), 1).expect("valid relay config");
        let handle = tokio::spawn(relay_loop_controlled(
            store.clone(),
            config,
            fixed_clock(),
            token.clone(),
            health,
            noop_metrics(),
            control.clone(),
        ));

        store.wait_until_started(1).await;
        assert_eq!(control.in_flight(), 1);
        assert!(!control.is_drained(), "active relay is not drained");

        control.pause();
        store.finish.notify_one();
        control.wait_drained().await;
        assert_eq!(control.in_flight(), 0);
        assert_eq!(
            store.claim_count.load(AtomOrd::Acquire),
            1,
            "pause must prevent a second claim after current work drains"
        );

        control.resume();
        assert!(
            !control.is_drained(),
            "resume closes the drained observation"
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        store.wait_until_started(2).await;
        store.finish.notify_one();
        tokio::task::yield_now().await;

        token.cancel();
        assert!(handle.await.is_ok(), "controlled relay stops cleanly");
        assert!(control.is_stopped());
        assert!(control.is_drained());
        control.resume();
        assert!(
            control.is_drained(),
            "a stopped relay remains terminally drained"
        );
    }

    // ── T9：shutdown 收敛/幂等；shutdown_timeout == 45s ──────────────────────

    /// T9：cancel 后 shutdown 在 budget 内返回；shutdown_timeout()==45s；
    /// shutdown 后再次（防御调用）不 panic。
    #[tokio::test]
    async fn t9_shutdown_converges_and_timeout_is_45s() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let handle = tokio::spawn(relay_loop(
            store.clone(),
            relay_config(Duration::from_secs(60)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));

        let worker = RelayWorker::adopt(handle, health.clone(), token.clone());

        // 验证 shutdown_timeout
        assert_eq!(
            worker.shutdown_timeout(),
            std::time::Duration::from_secs(45),
            "RelayWorker shutdown_timeout must be 45s"
        );

        // shutdown 应在 budget 内收敛（cancel 后 loop 退出）。
        token.cancel();
        let result = worker.shutdown().await;
        assert!(result.is_ok(), "first shutdown must succeed: {result:?}");

        // 再次调用不 panic（inner 已 take，None 分支直接 Ok）。
        let result2 = worker.shutdown().await;
        assert!(
            result2.is_ok(),
            "second shutdown must not panic: {result2:?}"
        );
    }

    /// T9b：SweeperWorker shutdown_timeout 同为 45s。
    #[tokio::test]
    async fn t9b_sweeper_shutdown_timeout_is_45s() {
        let sweeper = FakeSweeper::new();
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let handle = tokio::spawn(sweeper_loop(
            sweeper.clone(),
            sweeper_config(86400, Duration::from_secs(60)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            RetentionTarget::OutboxPublished,
        ));

        let worker =
            SweeperWorker::adopt(SWEEPER_WORKER_NAME, handle, health.clone(), token.clone());

        assert_eq!(
            worker.shutdown_timeout(),
            std::time::Duration::from_secs(45),
            "SweeperWorker shutdown_timeout must be 45s"
        );

        token.cancel();
        let result = worker.shutdown().await;
        assert!(result.is_ok(), "sweeper shutdown must succeed: {result:?}");
    }

    // ── T10：worker 退出 → health Unhealthy；claim/relay 错误 → Degraded ────────

    /// T10a：cancel → shutdown 后 health 变 Unhealthy（mark_stopped）。
    #[tokio::test]
    async fn t10a_worker_stopped_health_unhealthy() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let handle = tokio::spawn(relay_loop(
            store.clone(),
            relay_config(Duration::from_secs(60)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));

        let worker = RelayWorker::adopt(handle, health.clone(), token.clone());

        // 初始 Healthy。
        assert_eq!(worker.health().status(), HealthStatus::Healthy);

        token.cancel();
        let _ = worker.shutdown().await;

        // loop 退出后 mark_stopped → Unhealthy。
        assert_eq!(
            worker.health().status(),
            HealthStatus::Unhealthy,
            "stopped worker must be Unhealthy"
        );
    }

    /// T10b：一轮 relay 返回 Err → health Degraded（F4 经 relay_tick 聚合）。
    ///
    /// 直接驱动 `relay_tick`（不经 interval loop）——F5 恢复会在后续空轮把状态翻回 Healthy，
    /// 经 loop+advance 断言瞬态 Degraded 会竞态；单轮直驱确定。worker 退出→Unhealthy 由 t10a 覆盖。
    #[tokio::test]
    async fn t10b_relay_error_marks_degraded() {
        let store = FakeStore::with_relay_err(
            vec![make_claimed_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::default();
        super::relay_tick(&store, 10, &FixedClock, &health, &metrics).await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "relay error round must mark worker Degraded"
        );
        assert!(
            metrics.publishes().is_empty(),
            "transient relay errors must not be cross-counted as Ack"
        );
    }

    /// F4：relay 返回 Ok(Requeue)/Ok(Reject)（broker 瞬态失败 / DLX）→ health Degraded
    /// （业务处置通道并入 health 映射，非仅 Err 异常通道）。
    #[tokio::test]
    async fn relay_non_ack_disposition_marks_degraded() {
        for disposition in [Disposition::Requeue, Disposition::Reject] {
            let store = FakeStore::with_relay_disposition(vec![make_claimed_entry()], disposition);
            let health = Arc::new(WorkerHealth::healthy());
            super::relay_tick(
                &store,
                10,
                &FixedClock,
                &health,
                &CountingMetrics::default(),
            )
            .await;
            assert_eq!(
                health.status(),
                HealthStatus::Degraded,
                "non-ack disposition must mark Degraded: {}",
                disposition.as_label()
            );
        }
    }

    /// F5：一轮 relay 错误标 Degraded 后，下一轮干净（空批次 / 全 Ack）恢复 Healthy（非单向 latch）。
    #[tokio::test]
    async fn relay_tick_recovers_to_healthy_after_clean_round() {
        let health = Arc::new(WorkerHealth::healthy());
        // 第一轮：relay Err → Degraded。
        let erroring = FakeStore::with_relay_err(
            vec![make_claimed_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        super::relay_tick(
            &erroring,
            10,
            &FixedClock,
            &health,
            &CountingMetrics::default(),
        )
        .await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "relay error round → Degraded"
        );
        // 第二轮：干净 store（空批次）→ 恢复 Healthy。
        let clean = FakeStore::new(vec![]);
        super::relay_tick(
            &clean,
            10,
            &FixedClock,
            &health,
            &CountingMetrics::default(),
        )
        .await;
        assert_eq!(
            health.status(),
            HealthStatus::Healthy,
            "clean round must recover Healthy"
        );
    }

    /// F5 补：非空批次但全 Ack（relay_batch 执行 + outcome 保持 Clean）也能从 Degraded 恢复 Healthy
    /// （区别于空批次路径——验证 relay_batch 内 Ack 不翻 Degraded）。
    #[tokio::test]
    async fn relay_tick_recovers_to_healthy_after_all_ack_nonempty_round() {
        let health = Arc::new(WorkerHealth::healthy());
        // 第一轮：relay Err → Degraded。
        let erroring = FakeStore::with_relay_err(
            vec![make_claimed_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        super::relay_tick(
            &erroring,
            10,
            &FixedClock,
            &health,
            &CountingMetrics::default(),
        )
        .await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "relay error → Degraded"
        );
        // 第二轮：非空批次、全 Ack（默认 disposition）→ relay_batch 执行但 outcome Clean → Healthy。
        let all_ack = FakeStore::new(vec![make_claimed_entry(), make_claimed_entry()]);
        super::relay_tick(
            &all_ack,
            10,
            &FixedClock,
            &health,
            &CountingMetrics::default(),
        )
        .await;
        assert_eq!(
            health.status(),
            HealthStatus::Healthy,
            "non-empty all-Ack round must recover Healthy"
        );
        assert_eq!(all_ack.relay_count(), 2, "both entries must be relayed");
    }

    /// F6：worker task 异常终止（abort）→ shutdown 把 JoinError 包成 ShutdownError 返回 Err
    /// （不再 `let _ = h.await` 吞掉 panic/abort 致 Ack 假成功）。
    #[tokio::test]
    async fn worker_shutdown_propagates_join_error_on_abort() {
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        // 永不完成的 task，abort 之 → JoinHandle 收敛为 JoinError（cancelled）。
        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let worker = RelayWorker::adopt(handle, health, token);
        let result = worker.shutdown().await;
        assert!(
            result.is_err(),
            "shutdown must propagate JoinError as ShutdownError when worker task aborted"
        );
    }

    /// T10c：claim 返回 Err → health Degraded（claim_batch 路径）。
    #[tokio::test(start_paused = true)]
    async fn t10c_claim_error_marks_degraded() {
        let store = FakeStore::with_claim_err(consistency::error::EngineErrorKind::Transient);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let _handle = tokio::spawn(relay_loop(
            store.clone(),
            relay_config(Duration::from_millis(100)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));

        tokio::time::advance(std::time::Duration::from_millis(200)).await;

        // 精确断言：worker 仍运行时 claim 错误必已触发 mark_degraded（Degraded，未被终态覆盖）。
        assert!(
            yield_until(&health, HealthStatus::Degraded).await,
            "claim error must mark Degraded while worker still running"
        );

        token.cancel();
        tokio::time::advance(std::time::Duration::from_millis(200)).await;
        assert!(
            yield_until(&health, HealthStatus::Unhealthy).await,
            "stopped worker must become Unhealthy after claim error"
        );
    }

    /// T10d：sweeper sweep Err → health Degraded 路径。
    #[tokio::test(start_paused = true)]
    async fn t10d_sweeper_error_marks_degraded() {
        let sweeper = FakeSweeper::with_err(consistency::error::EngineErrorKind::Transient);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let _handle = tokio::spawn(sweeper_loop(
            sweeper.clone(),
            sweeper_config(86400, Duration::from_secs(1)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            RetentionTarget::OutboxPublished,
        ));

        tokio::time::advance(std::time::Duration::from_secs(2)).await;

        // 精确断言：worker 仍运行时 sweep 错误必已触发 mark_degraded（Degraded，未被终态覆盖）。
        assert!(
            yield_until(&health, HealthStatus::Degraded).await,
            "sweep error must mark Degraded while worker still running"
        );

        token.cancel();
        tokio::time::advance(std::time::Duration::from_millis(200)).await;
        assert!(
            yield_until(&health, HealthStatus::Unhealthy).await,
            "stopped worker must become Unhealthy after sweep error"
        );
    }

    // ── T12：probe 名契约 ────────────────────────────────────────────────────

    /// T12：probe 名可通过 ProbeName::parse + 无 `_ready` 后缀（运行时操作 probe）。
    #[test]
    fn t12_probe_names_parse_and_no_ready_suffix() {
        // relay probe
        assert!(
            ProbeName::parse(OUTBOX_RELAY_PROBE).is_ok(),
            "OUTBOX_RELAY_PROBE must parse as valid ProbeName"
        );
        assert!(
            !OUTBOX_RELAY_PROBE.ends_with("_ready"),
            "OUTBOX_RELAY_PROBE must not end with _ready"
        );
        // sweeper probe
        assert!(
            ProbeName::parse(OUTBOX_SWEEPER_PROBE).is_ok(),
            "OUTBOX_SWEEPER_PROBE must parse as valid ProbeName"
        );
        assert!(
            !OUTBOX_SWEEPER_PROBE.ends_with("_ready"),
            "OUTBOX_SWEEPER_PROBE must not end with _ready"
        );
        // sampler probe（#1209）
        assert!(
            ProbeName::parse(OUTBOX_SAMPLER_PROBE).is_ok(),
            "OUTBOX_SAMPLER_PROBE must parse as valid ProbeName"
        );
        assert!(
            !OUTBOX_SAMPLER_PROBE.ends_with("_ready"),
            "OUTBOX_SAMPLER_PROBE must not end with _ready"
        );
    }

    // ── WorkerHealth 状态转换 ────────────────────────────────────────────────

    #[test]
    fn worker_health_initial_healthy() {
        assert_eq!(WorkerHealth::healthy().status(), HealthStatus::Healthy);
    }

    #[test]
    fn worker_health_mark_degraded() {
        let h = WorkerHealth::healthy();
        h.mark_degraded();
        assert_eq!(h.status(), HealthStatus::Degraded);
    }

    #[test]
    fn worker_health_mark_stopped_is_unhealthy() {
        let h = WorkerHealth::healthy();
        h.mark_stopped();
        assert_eq!(h.status(), HealthStatus::Unhealthy);
    }

    #[test]
    fn worker_health_subscription_recovered_cas_only_opens_channel_states() {
        let starting = WorkerHealth::starting();
        starting.mark_subscription_recovered();
        assert_eq!(starting.status(), HealthStatus::Healthy);

        let unavailable = WorkerHealth::starting();
        unavailable.mark_subscriber_unavailable();
        unavailable.mark_subscription_recovered();
        assert_eq!(unavailable.status(), HealthStatus::Healthy);

        let dlx = WorkerHealth::starting();
        dlx.mark_dlx_write_error();
        dlx.mark_subscription_recovered();
        assert_eq!(dlx.detail(), "dlx-write-error");
        assert_eq!(dlx.status(), HealthStatus::Degraded);

        let degraded = WorkerHealth::healthy();
        degraded.mark_degraded();
        degraded.mark_subscription_recovered();
        assert_eq!(degraded.status(), HealthStatus::Degraded);
    }

    #[test]
    fn worker_health_subscriber_unavailable_does_not_cover_dlx_or_invariant() {
        let dlx = WorkerHealth::starting();
        dlx.mark_dlx_write_error();
        dlx.mark_subscriber_unavailable();
        assert_eq!(dlx.detail(), "dlx-write-error");

        let invariant = WorkerHealth::starting();
        invariant.mark_invariant();
        invariant.mark_subscriber_unavailable();
        assert_eq!(invariant.detail(), "invariant");
    }

    // ── RelayWorker/SweeperWorker name ───────────────────────────────────────

    #[tokio::test]
    async fn relay_worker_name_is_outbox_relay() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(relay_loop(
            store,
            relay_config(Duration::from_secs(60)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));
        let worker = RelayWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-relay");
        let _ = worker.shutdown().await; // 收敛 spawned task（防 leak；shutdown 内部防御性 cancel）。
    }

    // #327 review F2：SweeperWorker readyz name 运行期 per-target——adopt 传入名即 `name()` 返回名，使多表
    // sweeper 身份可区分（不再硬编码 outbox）。同时覆盖默认常量 SWEEPER_WORKER_NAME 与自定义 inbox 名两路。
    #[tokio::test]
    async fn sweeper_worker_name_is_per_target() {
        async fn adopt_named(name: &'static str) -> SweeperWorker {
            let health = Arc::new(WorkerHealth::healthy());
            let token = CancellationToken::new();
            let handle = tokio::spawn(sweeper_loop(
                FakeSweeper::new(),
                sweeper_config(86400, Duration::from_secs(60)),
                fixed_clock(),
                token.clone(),
                health.clone(),
                RetentionTarget::OutboxPublished,
            ));
            SweeperWorker::adopt(name, handle, health, token)
        }
        let outbox = adopt_named(SWEEPER_WORKER_NAME).await;
        assert_eq!(outbox.name(), "outbox-sweeper", "默认常量 = outbox-sweeper");
        let inbox = adopt_named("inbox-dedup-sweeper").await;
        assert_eq!(
            inbox.name(),
            "inbox-dedup-sweeper",
            "per-target：adopt 传入名即 readyz name"
        );
        let _ = outbox.shutdown().await; // 收敛 spawned task（防 leak；shutdown 内部防御性 cancel）。
        let _ = inbox.shutdown().await;
    }

    // ── #1209 sampler worker name ────────────────────────────────────────────

    #[tokio::test]
    async fn sampler_worker_name_is_outbox_sampler() {
        let store = FakeBacklog::new(BacklogSample::empty());
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(backlog_sampler_loop(
            store,
            sampler_config(&["dom"], Duration::from_secs(60)),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));
        let worker = SamplerWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-sampler");
        let _ = worker.shutdown().await; // 收敛 spawned task（防 leak；shutdown 内部防御性 cancel）。
    }

    // ── #1209 metrics 发射 + 采样行为（counting fake，确定性断言）────────────

    /// relay 单条结算逐 Disposition 发 `outbox_publish_total{status}`（含 Ack）。
    #[tokio::test]
    async fn relay_records_publish_counter_per_disposition() {
        for disposition in [Disposition::Ack, Disposition::Requeue, Disposition::Reject] {
            let store = FakeStore::with_relay_disposition(vec![make_claimed_entry()], disposition);
            let health = Arc::new(WorkerHealth::healthy());
            let metrics = CountingMetrics::new();
            super::relay_tick(&store, 10, &FixedClock, &health, metrics.as_ref()).await;
            assert_eq!(
                metrics.publishes(),
                vec![(
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    disposition,
                )],
                "publish counter must record disposition {}",
                disposition.as_label()
            );
        }
    }

    /// relay tick 每 domain 各发一次 claim 相 + 一次 publish 相耗时（settle 并入 publish）。
    #[tokio::test]
    async fn relay_records_tick_duration_claim_and_publish() {
        let store = FakeStore::new(vec![make_claimed_entry()]);
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        super::relay_tick(&store, 10, &FixedClock, &health, metrics.as_ref()).await;
        assert_eq!(
            metrics.tick_phases(),
            vec![RelayPhase::Claim, RelayPhase::Publish],
            "tick must observe claim then publish phase"
        );
    }

    /// sampler tick 逐 domain set backlog gauge（record_backlog 携采样值）+ 干净轮 Healthy。
    #[tokio::test]
    async fn sampler_records_backlog_gauge() {
        let sample_a = BacklogSample::new(42, 305);
        let sample_b = BacklogSample::empty();
        let store = FakeBacklog::with_samples(vec![
            blocked_backlog_sample("identity.session-created", sample_a, 2),
            backlog_sample("identity.role-assigned", sample_b),
        ]);
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        let mut observed_scopes = super::BacklogScopeState::default();
        super::sampler_tick(
            &store,
            &[dn("identity")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(
            metrics.backlogs(),
            vec![
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    sample_a,
                ),
                (
                    "identity".to_string(),
                    "identity.role-assigned".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    sample_b,
                ),
            ]
        );
        assert_eq!(
            metrics.partition_blocked(),
            vec![
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    2,
                ),
                (
                    "identity".to_string(),
                    "identity.role-assigned".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    0,
                ),
            ]
        );
        assert_eq!(health.status(), HealthStatus::Healthy);
    }

    /// sampler 进程内已观测 scope 本轮消失时显式置零，避免保留陈旧非零 gauge。
    #[tokio::test]
    async fn sampler_zeroes_previously_observed_scope_when_sample_disappears() {
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        let mut observed_scopes = super::BacklogScopeState::default();

        let first = FakeBacklog::with_samples(vec![backlog_sample(
            "identity.session-created",
            BacklogSample::new(42, 305),
        )]);
        super::sampler_tick(
            &first,
            &[dn("identity")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;

        let second = FakeBacklog::with_samples(vec![]);
        super::sampler_tick(
            &second,
            &[dn("identity")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;

        assert_eq!(
            metrics.backlogs(),
            vec![
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    BacklogSample::new(42, 305),
                ),
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    BacklogSample::empty(),
                ),
            ]
        );
        assert_eq!(
            metrics.partition_blocked(),
            vec![
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    0,
                ),
                (
                    "identity".to_string(),
                    "identity.session-created".to_string(),
                    "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                    0,
                ),
            ]
        );
        assert_eq!(health.status(), HealthStatus::Healthy);
    }

    /// Active -> standby is not a real empty sample: preserve the last gauges and do not report a
    /// successful sampling recovery while this replica does not own the maintenance lease.
    #[tokio::test]
    async fn sampler_standby_preserves_observation_and_health() {
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        let mut observed_scopes = super::BacklogScopeState::default();
        let active = FakeBacklog::with_samples(vec![backlog_sample(
            "identity.session-created",
            BacklogSample::new(42, 305),
        )]);
        super::sampler_tick(
            &active,
            &[dn("identity")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;
        health.mark_degraded();

        super::sampler_tick(
            &Arc::new(StandbyBacklog),
            &[dn("identity")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;

        assert_eq!(
            metrics.backlogs(),
            vec![(
                "identity".to_string(),
                "identity.session-created".to_string(),
                "f47ac10b-58cc-4372-a567-0e02b2c3d479".to_string(),
                BacklogSample::new(42, 305),
            )],
            "standby must not zero the active replica's last observation"
        );
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "standby must not masquerade as a successful sampling tick"
        );
    }

    #[tokio::test]
    async fn sampler_first_standby_opens_only_starting_health() {
        let starting = Arc::new(WorkerHealth::starting());
        let metrics = CountingMetrics::new();
        let mut observed_scopes = super::BacklogScopeState::default();
        super::sampler_tick(
            &Arc::new(StandbyBacklog),
            &[dn("identity")],
            &mut observed_scopes,
            &starting,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(starting.status(), HealthStatus::Healthy);

        let degraded = Arc::new(WorkerHealth::healthy());
        degraded.mark_degraded();
        super::sampler_tick(
            &Arc::new(StandbyBacklog),
            &[dn("identity")],
            &mut observed_scopes,
            &degraded,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(degraded.status(), HealthStatus::Degraded);
    }

    /// sampler 采样 Err → 整轮 Degraded（不发 gauge），干净下一轮自愈（F5）。
    #[tokio::test]
    async fn sampler_error_marks_degraded_then_recovers() {
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        let mut observed_scopes = super::BacklogScopeState::default();
        // 第一轮：采样 Err → Degraded、无 gauge 发射。
        let erroring = FakeBacklog::with_err(consistency::error::EngineErrorKind::Transient);
        super::sampler_tick(
            &erroring,
            &[dn("dom")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert!(
            metrics.backlogs().is_empty(),
            "Err round must not emit gauge"
        );
        // 第二轮：干净采样 → 恢复 Healthy。
        let clean = FakeBacklog::new(BacklogSample::empty());
        super::sampler_tick(
            &clean,
            &[dn("dom")],
            &mut observed_scopes,
            &health,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Healthy);
    }
}
