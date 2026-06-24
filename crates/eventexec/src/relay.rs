//! Outbox relay/sweeper worker — L2 两阶段关闭 ManagedResource。
//!
//! # 设计摘要
//!
//! `consistency` 的三个 AFIT trait（`OutboxSource`/`OutboxRelay`/`OutboxSweeper`）是 native AFIT、
//! **无 Send 变体**。`tokio::spawn` 要求 future Send，而泛型 `<A: OutboxSource>` 下 `A::poll_pending(..)`
//! 的 future 在 stable Rust 上无法证明 Send（RTN 未稳定）。因此：
//! - 泛型 `relay_loop` / `sweeper_loop`：纯 loop 体，**不 spawn**——泛型 async fn 不要求 Send，能编过。
//! - spawn 发生在**具体类型 call site**（生产=组合根 PgOutbox，测试=具体 Fake）——单态化后 future 具体 Send。
//! - `RelayWorker` / `SweeperWorker`：adopt 式，持已 spawn 的 `JoinHandle<()>`，impl `ManagedResource`。
//!
//! ref: serverlesstechnology/cqrs（背景 relay 解耦 + 取消安全两阶段关闭，偏离 event-sourcing 同步派发）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use consistency::{Disposition, OutboxRelay, OutboxSource, OutboxSweeper};
use primitives::healthz::HealthStatus;

// ── probe 名常量 ────────────────────────────────────────────────────────────

/// readyz probe 名：outbox relay worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_RELAY_PROBE: &str = "outbox_relay";

/// readyz probe 名：outbox sweeper worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_SWEEPER_PROBE: &str = "outbox_sweeper";

// worker 名常量（≥3 处使用抽 const）
const RELAY_WORKER_NAME: &str = "outbox-relay";
const SWEEPER_WORKER_NAME: &str = "outbox-sweeper";

/// worker 关闭超时：重 I/O drain，覆盖默认 30s（relay/sweeper 同值）。
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

// AtomicU8 编码：0=Healthy 1=Degraded 2=Unhealthy
const HEALTH_HEALTHY: u8 = 0;
const HEALTH_DEGRADED: u8 = 1;
const HEALTH_UNHEALTHY: u8 = 2;

// ── WorkerHealth ────────────────────────────────────────────────────────────

/// Worker 运行期健康（原子 u8，Send+Sync；0=Healthy 1=Degraded 2=Unhealthy）。
///
/// poll/relay/sweep 错误 → `mark_degraded`；loop 退出（worker 不再运行）→ `mark_stopped`（Unhealthy）。
/// readyz 聚合经 `health()` 读此状态，据此翻 probe。
pub struct WorkerHealth(AtomicU8);

impl WorkerHealth {
    /// 构造初始 Healthy 状态（AtomicU8::new(0)）。
    pub fn healthy() -> Self {
        Self(AtomicU8::new(HEALTH_HEALTHY))
    }

    /// 读当前健康状态。
    pub fn status(&self) -> HealthStatus {
        match self.0.load(Ordering::Acquire) {
            HEALTH_HEALTHY => HealthStatus::Healthy,
            HEALTH_DEGRADED => HealthStatus::Degraded,
            _ => HealthStatus::Unhealthy,
        }
    }

    /// 一整轮 poll/relay（或 sweep）干净成功 → 恢复 Healthy（瞬态故障自愈，**非**单向 latch；F5）。
    ///
    /// 与 [`WorkerHealth::mark_degraded`] 同档（无条件 store）；仅在运行期由 tick 调用。
    pub(crate) fn mark_healthy(&self) {
        self.0.store(HEALTH_HEALTHY, Ordering::Release);
    }

    /// poll/relay/sweep 出错，或 relay 业务处置为 Requeue/Reject → Degraded（无条件 store，**非** CAS）。
    ///
    /// 顺序不变式由**构造**保证而非此方法：loop 仅在运行期每轮 tick 据结果二选一调
    /// `mark_healthy`/`mark_degraded`，退出时恰调一次终态 `mark_stopped`（Unhealthy）；cancel 后不再
    /// tick，故 Unhealthy 之后不会被运行期标记回退。
    pub(crate) fn mark_degraded(&self) {
        self.0.store(HEALTH_DEGRADED, Ordering::Release);
    }

    /// loop 退出（worker 停止运行）→ Unhealthy；readyz 据此翻。
    pub(crate) fn mark_stopped(&self) {
        self.0.store(HEALTH_UNHEALTHY, Ordering::Release);
    }
}

// ── relay_loop（泛型，不 spawn）──────────────────────────────────────────────

/// Outbox relay 驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 遍历 `domains`，按 `batch` 大小拉取 pending entry，逐条 relay。
/// 取消信号（`token.cancelled()`）在每轮循环顶部检查——当前条 relay 跑完再退，在途写不丢；
/// 取消在下一轮 loop 顶部生效（单条有界，尊重 shutdown budget）。
/// loop 退出（无论 cancel 还是 panic 外的正常返回）→ `health.mark_stopped()`。
pub async fn relay_loop<A>(
    store: Arc<A>,
    domains: Vec<String>,
    poll_interval: Duration,
    batch: usize,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    A: OutboxSource + OutboxRelay,
{
    let mut ticker = tokio::time::interval(poll_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                relay_tick(&store, &domains, batch, &health).await;
            }
        }
    }
    health.mark_stopped();
}

/// 单轮（或单 domain）relay 健康结果——驱动 worker health（F4 把业务处置通道并入映射）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum TickOutcome {
    /// 全部 entry Ack（或空批次），无 poll/relay 错误。
    Clean,
    /// 出现 poll/relay 错误，或 relay 处置为 Requeue/Reject（broker 失败 / DLX）。
    Degraded,
}

impl TickOutcome {
    /// 取更差者（Degraded 吸收 Clean）——跨 domain 聚合用。
    fn worse(self, other: TickOutcome) -> TickOutcome {
        if self == TickOutcome::Degraded || other == TickOutcome::Degraded {
            TickOutcome::Degraded
        } else {
            TickOutcome::Clean
        }
    }
}

/// relay 单轮 tick（抽出控制认知复杂度 ≤15）：逐 domain 委派 [`relay_domain_once`]，整轮结果一次性翻 health。
///
/// 全 domain 干净（含空轮）→ `mark_healthy`（F5：瞬态故障下一轮自愈）；任一 poll/relay 错误或
/// Requeue/Reject 处置 → `mark_degraded`（F4：health 不再只表达异常通道）。
async fn relay_tick<A>(store: &Arc<A>, domains: &[String], batch: usize, health: &Arc<WorkerHealth>)
where
    A: OutboxSource + OutboxRelay,
{
    let mut tick = TickOutcome::Clean;
    for domain in domains {
        tick = tick.worse(relay_domain_once(store, domain, batch).await);
    }
    match tick {
        TickOutcome::Clean => health.mark_healthy(),
        TickOutcome::Degraded => health.mark_degraded(),
    }
}

/// 单 domain 一轮：扫一批 → 逐条中继，返回该 domain 的 [`TickOutcome`]（早返展平嵌套，认知复杂度 ≤15）。
async fn relay_domain_once<A>(store: &Arc<A>, domain: &str, batch: usize) -> TickOutcome
where
    A: OutboxSource + OutboxRelay,
{
    let entries = match store.poll_pending(domain, batch).await {
        Ok(entries) => entries,
        Err(e) => {
            log_poll_failed(domain, &e);
            return TickOutcome::Degraded;
        }
    };
    if !entries.is_empty() {
        log_polled(domain, entries.len());
    }
    let mut outcome = TickOutcome::Clean;
    for entry in entries {
        // 不在 relay 外套 select!：当前条 publish+CAS 跑完再退，在途写不丢；
        // 取消在下一轮 loop 顶部生效（单条有界，尊重 shutdown budget）。
        match store.relay(&entry).await {
            Ok(Disposition::Ack) => {}
            Ok(disposition) => {
                // Requeue（broker 瞬态失败，退避重投）/ Reject（预算耗尽进 DLX）——业务处置通道映射为
                // Degraded（F4）。`_` 兜底 `Disposition` 的 `#[non_exhaustive]` 未来处置（保守降级）。
                log_relay_disposition(domain, disposition);
                outcome = TickOutcome::Degraded;
            }
            Err(e) => {
                log_relay_failed(domain, &e);
                outcome = TickOutcome::Degraded;
            }
        }
    }
    outcome
}

// ── 结构化日志 helper（抽出 tracing 宏展开，控制调用方认知复杂度 ≤15；
//    仿 lib.rs `log_dropped_*` 范式）。勿记 payload/PII。 ─────────────────────────

/// poll_pending 失败：退避到下一 tick 前结构化记录。
fn log_poll_failed(domain: &str, e: &impl std::fmt::Display) {
    tracing::warn!(
        domain,
        error = %e,
        "relay: poll_pending failed, marking worker degraded; backing off to next tick"
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
fn log_polled(domain: &str, polled: usize) {
    tracing::debug!(domain, polled, "relay: tick polled");
}

// ── sweeper_loop（泛型，不 spawn）────────────────────────────────────────────

/// Outbox sweeper 驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 调 `store.sweep(retain_seconds)`，删除超保留期已投递行。
/// 取消/错误处理与 `relay_loop` 同骨架。
pub async fn sweeper_loop<S>(
    store: Arc<S>,
    retain_seconds: u64,
    sweep_interval: Duration,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    S: OutboxSweeper,
{
    let mut ticker = tokio::time::interval(sweep_interval);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => sweeper_tick(&store, retain_seconds, &health).await,
        }
    }
    health.mark_stopped();
}

/// sweeper 单轮 tick（抽出控制认知复杂度 ≤15）。
async fn sweeper_tick<S>(store: &Arc<S>, retain_seconds: u64, health: &Arc<WorkerHealth>)
where
    S: OutboxSweeper,
{
    match store.sweep(retain_seconds).await {
        Ok(deleted) => {
            tracing::debug!(deleted, "sweeper: tick completed");
            health.mark_healthy(); // 干净一轮 → 恢复 Healthy（F5：瞬态故障自愈，非单向 latch）。
        }
        Err(e) => {
            log_sweep_failed(&e);
            health.mark_degraded();
        }
    }
}

/// sweep 失败：标记 worker degraded 前结构化记录（抽出 tracing 宏展开）。
fn log_sweep_failed(e: &impl std::fmt::Display) {
    tracing::warn!(
        error = %e,
        "sweeper: sweep failed, marking worker degraded; backing off to next tick"
    );
}

// ── worker 两阶段关闭共享 helper ─────────────────────────────────────────────

/// adopt 式 worker 关闭收敛（[`RelayWorker`] / [`SweeperWorker`] 共用）：防御性 cancel（幂等）→ await
/// JoinHandle。task panic/abort 的 `JoinError` 包成 typed [`diport::ShutdownError`] 上抛——**不**再
/// `let _ = h.await` 吞掉，使 panic/abort 误报成关闭成功（F6；接 `ManagedResource::shutdown` typed 语义）。
async fn shutdown_worker(
    token: &CancellationToken,
    inner: &tokio::sync::Mutex<Option<JoinHandle<()>>>,
) -> Result<(), diport::ShutdownError> {
    // 防御性 cancel（幂等；生产中 ShutdownStack 已先 cancel，此处兜底防 test/误用 hang）。
    token.cancel();
    // await loop 收敛——保证 worker 在 pool 之前停（LIFO 由组合根注册顺序保证）、在途写不丢。
    if let Some(h) = inner.lock().await.take() {
        h.await.map_err(diport::ShutdownError::new)?;
    }
    Ok(())
}

// ── RelayWorker（adopt 式 ManagedResource）──────────────────────────────────

/// Outbox relay 后台 worker（adopt 式）。
///
/// 持已 spawn 的 `JoinHandle<()>`，impl `ManagedResource`。
/// 组合根/测试：先在具体类型处 `tokio::spawn(relay_loop::<ConcreteStore>(...))` 再 `adopt`。
pub struct RelayWorker {
    inner: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl RelayWorker {
    /// 组合根/测试：先 spawn relay_loop(具体类型)，再 adopt JoinHandle + 同一 health + 同一 token。
    pub fn adopt(
        handle: JoinHandle<()>,
        health: Arc<WorkerHealth>,
        token: CancellationToken,
    ) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(handle)),
            health,
            token,
        }
    }

    /// 读 worker health（readyz 聚合用）。
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }
}

// reason(rss_diport_impl_allowlist): spec T004.4 显式将 outbox relay worker 归属 eventexec 服务层并 impl
// ManagedResource（经组合根 ShutdownStack 注入两阶段关闭）。ManagedResource 是生命周期 trait（非可替换
// provider port），worker 持 relay_loop spawn 的 JoinHandle、是引擎驱动产物而非 adapter provider，不迁 adapter。
// allowlist 外 item-level 例外（DIPORT-IMPL-ALLOWLIST-01 逃生门）；根治（豁免 ManagedResource 出 lint 扫描集）见 #1153。
// unknown_lints 同 allow：dylint 自定义 lint 在 plain clippy 未注册（make verify 跑 plain clippy + dylint 双路）。
#[allow(unknown_lints, rss_diport_impl_allowlist)]
impl diport::ManagedResource for RelayWorker {
    fn name(&self) -> &str {
        RELAY_WORKER_NAME
    }

    fn shutdown_timeout(&self) -> Duration {
        WORKER_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        shutdown_worker(&self.token, &self.inner).await
    }
}

// ── SweeperWorker（adopt 式 ManagedResource）────────────────────────────────

/// Outbox sweeper 后台 worker（adopt 式；结构与 [`RelayWorker`] 同构）。
pub struct SweeperWorker {
    inner: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl SweeperWorker {
    /// 组合根/测试：先 spawn sweeper_loop(具体类型)，再 adopt JoinHandle + 同一 health + 同一 token。
    pub fn adopt(
        handle: JoinHandle<()>,
        health: Arc<WorkerHealth>,
        token: CancellationToken,
    ) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(handle)),
            health,
            token,
        }
    }

    /// 读 worker health（readyz 聚合用）。
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }
}

// reason(rss_diport_impl_allowlist): 同 RelayWorker（spec T004.4 服务层 worker impl ManagedResource 生命周期
// trait；非 adapter provider，不迁；DIPORT-IMPL-ALLOWLIST-01 逃生门，根治见 #1153）。
#[allow(unknown_lints, rss_diport_impl_allowlist)]
impl diport::ManagedResource for SweeperWorker {
    fn name(&self) -> &str {
        SWEEPER_WORKER_NAME
    }

    fn shutdown_timeout(&self) -> Duration {
        WORKER_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        shutdown_worker(&self.token, &self.inner).await
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomOrd};
    use std::sync::{Arc, Mutex};

    use consistency::outbox::{Disposition, Entry, Topic};
    use consistency::{OutboxRelay, OutboxSource, OutboxSweeper};
    use diport::ManagedResource;
    use primitives::healthz::{HealthStatus, ProbeName};
    use tokio_util::sync::CancellationToken;

    use super::{
        OUTBOX_RELAY_PROBE, OUTBOX_SWEEPER_PROBE, SweeperWorker, WorkerHealth, sweeper_loop,
    };
    use crate::relay::{RelayWorker, relay_loop};

    // ── Fake store（具体类型；Send 友好：用 Arc<Mutex>/Atomic，不跨 await 持有锁）──

    /// 构造测试 Entry（topic + idem_key + payload）。
    fn make_entry() -> Entry {
        #[allow(clippy::unwrap_used)]
        // reason: 测试 happy-path，item-level carve-out
        Entry::new(
            Topic::parse("session.created").unwrap(),
            consistency::idempotency::IdemKey::parse("evt-001").unwrap(),
            vec![1u8, 2, 3],
        )
    }

    /// bounded yield：让 spawned worker task 推进，至多 N 次 yield 等到 `want` 状态后返回 true。
    /// `start_paused` 下无真实 I/O，目标状态必在数次 poll 内到达；超出预算返回 false（断言失败）。
    async fn yield_until(health: &Arc<WorkerHealth>, want: HealthStatus) -> bool {
        for _ in 0..32 {
            if health.status() == want {
                return true;
            }
            tokio::task::yield_now().await;
        }
        health.status() == want
    }

    /// Fake store：同时 impl OutboxSource + OutboxRelay。
    /// - poll：按轮次从预置队列吐 entries（每次 poll 返回队列头部至多 batch 条）。
    /// - relay：计数调用，按预置策略返 Ok(Disposition)/Err。
    struct FakeStore {
        /// 预置 entries（每次 poll 弹出头部 batch 条）。
        pending: Mutex<Vec<Entry>>,
        /// relay 调用计数。
        relay_count: AtomicUsize,
        /// relay 返回错误策略：None=Ok(relay_disposition)，Some(kind)=Err。
        relay_err: Option<consistency::error::EngineErrorKind>,
        /// relay 成功路径返回的处置（默认 Ack；测 F4 时置 Requeue/Reject）。
        relay_disposition: Disposition,
        /// poll 返回错误策略：None=Ok，Some(kind)=Err。
        poll_err: Option<consistency::error::EngineErrorKind>,
    }

    impl FakeStore {
        fn new(entries: Vec<Entry>) -> Arc<Self> {
            Arc::new(Self {
                pending: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: Disposition::Ack,
                poll_err: None,
            })
        }

        fn with_relay_err(
            entries: Vec<Entry>,
            kind: consistency::error::EngineErrorKind,
        ) -> Arc<Self> {
            Arc::new(Self {
                pending: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: Some(kind),
                relay_disposition: Disposition::Ack,
                poll_err: None,
            })
        }

        /// relay 成功但返回非-Ack 处置（Requeue/Reject）——测 F4 health 映射。
        fn with_relay_disposition(entries: Vec<Entry>, disposition: Disposition) -> Arc<Self> {
            Arc::new(Self {
                pending: Mutex::new(entries),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: disposition,
                poll_err: None,
            })
        }

        fn with_poll_err(kind: consistency::error::EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                pending: Mutex::new(vec![]),
                relay_count: AtomicUsize::new(0),
                relay_err: None,
                relay_disposition: Disposition::Ack,
                poll_err: Some(kind),
            })
        }

        fn relay_count(&self) -> usize {
            self.relay_count.load(AtomOrd::Acquire)
        }
    }

    impl OutboxSource for FakeStore {
        async fn poll_pending(
            &self,
            _domain: &str,
            limit: usize,
        ) -> Result<Vec<Entry>, consistency::error::EngineError> {
            if let Some(kind) = self.poll_err {
                return Err(consistency::error::EngineError::new(kind));
            }
            #[allow(clippy::unwrap_used)]
            // reason: Mutex lock in test，item-level carve-out
            let mut pending = self.pending.lock().unwrap();
            let drain_end = limit.min(pending.len());
            let batch: Vec<Entry> = pending.drain(..drain_end).collect();
            Ok(batch)
        }
    }

    impl OutboxRelay for FakeStore {
        async fn relay(
            &self,
            _entry: &Entry,
        ) -> Result<Disposition, consistency::error::EngineError> {
            if let Some(kind) = self.relay_err {
                return Err(consistency::error::EngineError::new(kind));
            }
            self.relay_count.fetch_add(1, AtomOrd::Release);
            Ok(self.relay_disposition)
        }
    }

    /// Fake sweeper：impl OutboxSweeper，计数调用并按策略返结果。
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

    impl OutboxSweeper for FakeSweeper {
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
        let entries: Vec<Entry> = (0..3).map(|_| make_entry()).collect();
        let entry_count = entries.len();
        let store = FakeStore::new(entries);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        // spawn relay_loop（具体类型 FakeStore，future 具体 Send，tokio::spawn 编得过）。
        let handle = tokio::spawn(relay_loop(
            store.clone(),
            vec!["test-domain".to_string()],
            std::time::Duration::from_millis(100),
            10,
            token.clone(),
            health.clone(),
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
            vec!["test-domain".to_string()],
            std::time::Duration::from_secs(60),
            10,
            token.clone(),
            health.clone(),
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
            86400,
            std::time::Duration::from_secs(60),
            token.clone(),
            health.clone(),
        ));

        let worker = SweeperWorker::adopt(handle, health.clone(), token.clone());

        assert_eq!(
            worker.shutdown_timeout(),
            std::time::Duration::from_secs(45),
            "SweeperWorker shutdown_timeout must be 45s"
        );

        token.cancel();
        let result = worker.shutdown().await;
        assert!(result.is_ok(), "sweeper shutdown must succeed: {result:?}");
    }

    // ── T10：worker 退出 → health Unhealthy；poll/relay 错误 → Degraded ────────

    /// T10a：cancel → shutdown 后 health 变 Unhealthy（mark_stopped）。
    #[tokio::test]
    async fn t10a_worker_stopped_health_unhealthy() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let handle = tokio::spawn(relay_loop(
            store.clone(),
            vec!["dom".to_string()],
            std::time::Duration::from_secs(60),
            10,
            token.clone(),
            health.clone(),
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
            vec![make_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        let health = Arc::new(WorkerHealth::healthy());
        super::relay_tick(&store, &["dom".to_string()], 10, &health).await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "relay error round must mark worker Degraded"
        );
    }

    /// F4：relay 返回 Ok(Requeue)/Ok(Reject)（broker 瞬态失败 / DLX）→ health Degraded
    /// （业务处置通道并入 health 映射，非仅 Err 异常通道）。
    #[tokio::test]
    async fn relay_non_ack_disposition_marks_degraded() {
        for disposition in [Disposition::Requeue, Disposition::Reject] {
            let store = FakeStore::with_relay_disposition(vec![make_entry()], disposition);
            let health = Arc::new(WorkerHealth::healthy());
            super::relay_tick(&store, &["dom".to_string()], 10, &health).await;
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
        let domains = ["dom".to_string()];
        // 第一轮：relay Err → Degraded。
        let erroring = FakeStore::with_relay_err(
            vec![make_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        super::relay_tick(&erroring, &domains, 10, &health).await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "relay error round → Degraded"
        );
        // 第二轮：干净 store（空批次）→ 恢复 Healthy。
        let clean = FakeStore::new(vec![]);
        super::relay_tick(&clean, &domains, 10, &health).await;
        assert_eq!(
            health.status(),
            HealthStatus::Healthy,
            "clean round must recover Healthy"
        );
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

    /// T10c：poll 返回 Err → health Degraded（poll_pending 路径）。
    #[tokio::test(start_paused = true)]
    async fn t10c_poll_error_marks_degraded() {
        let store = FakeStore::with_poll_err(consistency::error::EngineErrorKind::Transient);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let _handle = tokio::spawn(relay_loop(
            store.clone(),
            vec!["dom".to_string()],
            std::time::Duration::from_millis(100),
            10,
            token.clone(),
            health.clone(),
        ));

        tokio::time::advance(std::time::Duration::from_millis(200)).await;

        // 精确断言：worker 仍运行时 poll 错误必已触发 mark_degraded（Degraded，未被终态覆盖）。
        assert!(
            yield_until(&health, HealthStatus::Degraded).await,
            "poll error must mark Degraded while worker still running"
        );

        token.cancel();
        tokio::time::advance(std::time::Duration::from_millis(200)).await;
        assert!(
            yield_until(&health, HealthStatus::Unhealthy).await,
            "stopped worker must become Unhealthy after poll error"
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
            86400,
            std::time::Duration::from_millis(100),
            token.clone(),
            health.clone(),
        ));

        tokio::time::advance(std::time::Duration::from_millis(200)).await;

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

    // ── RelayWorker/SweeperWorker name ───────────────────────────────────────

    #[tokio::test]
    async fn relay_worker_name_is_outbox_relay() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(relay_loop(
            store,
            vec![],
            std::time::Duration::from_secs(60),
            10,
            token.clone(),
            health.clone(),
        ));
        let worker = RelayWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-relay");
    }

    #[tokio::test]
    async fn sweeper_worker_name_is_outbox_sweeper() {
        let sweeper = FakeSweeper::new();
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(sweeper_loop(
            sweeper,
            86400,
            std::time::Duration::from_secs(60),
            token.clone(),
            health.clone(),
        ));
        let worker = SweeperWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-sweeper");
    }
}
