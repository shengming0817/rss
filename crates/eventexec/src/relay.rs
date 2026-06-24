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
use std::time::{Duration, SystemTime};

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use consistency::{Disposition, Entry, OutboxBacklog, OutboxRelay, OutboxSource, OutboxSweeper};
use primitives::healthz::HealthStatus;
use vocab::DomainName;

use crate::relay_config::{RelayConfig, SweeperConfig};
use crate::relay_metrics::{OutboxMetrics, RelayPhase};

// ── probe 名常量 ────────────────────────────────────────────────────────────

/// readyz probe 名：outbox relay worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_RELAY_PROBE: &str = "outbox_relay";

/// readyz probe 名：outbox sweeper worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_SWEEPER_PROBE: &str = "outbox_sweeper";

/// readyz probe 名：outbox backlog 采样 worker（无 `_ready` 后缀——运行时操作 probe）。
pub const OUTBOX_SAMPLER_PROBE: &str = "outbox_sampler";

// worker 名常量（≥3 处使用抽 const）
const RELAY_WORKER_NAME: &str = "outbox-relay";
const SWEEPER_WORKER_NAME: &str = "outbox-sweeper";
const SAMPLER_WORKER_NAME: &str = "outbox-sampler";

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
            // `_` 兜底 HEALTH_UNHEALTHY + 任何非法编码（AtomicU8 仅由本类型三 const 写入；
            // clippy::wildcard_in_or_patterns 拒 `CONST | _`，故用裸 `_`）。
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
/// 每轮 tick 遍历 `config.domains()`，按 `config.batch()` 大小拉取 pending entry，逐条 relay，并经
/// `metrics` 发射 `outbox_publish_total{status}` / `outbox_dlx_total` / `outbox_relay_tick_duration_seconds`
/// （#1209）。取消信号（`token.cancelled()`）在每轮循环顶部检查——当前条 relay 跑完再退，在途写不丢；
/// 取消在下一轮 loop 顶部生效（单条有界，尊重 shutdown budget）。`config` 经 [`RelayConfig`] funnel 已
/// 校验（`poll_interval`/`batch`/domains 越界在构造点即拒，RELAY-CONFIG-01），此处不再防御 0ms 热轮询。
/// loop 退出（无论 cancel 还是 panic 外的正常返回）→ `health.mark_stopped()`。
pub async fn relay_loop<A>(
    store: Arc<A>,
    config: RelayConfig,
    clock: Arc<dyn diport::Clock>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn OutboxMetrics>,
) where
    A: OutboxSource + OutboxRelay,
{
    let mut ticker = tokio::time::interval(config.poll_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                relay_tick(
                    &store,
                    config.domains(),
                    config.batch(),
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
async fn relay_tick<A>(
    store: &Arc<A>,
    domains: &[DomainName],
    batch: usize,
    clock: &dyn diport::Clock,
    health: &Arc<WorkerHealth>,
    metrics: &dyn OutboxMetrics,
) where
    A: OutboxSource + OutboxRelay,
{
    let mut tick = TickOutcome::Clean;
    for domain in domains {
        tick = tick.worse(relay_domain_once(store, domain, batch, clock, metrics).await);
    }
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

/// 单 domain 一轮：扫一批（计 poll 相耗时）→ 逐条中继（计 publish 相耗时 + 发 publish 计数），返回该
/// domain 的 [`TickOutcome`]（早返展平嵌套 + 批中继抽 [`relay_batch`]，认知复杂度 ≤15）。
async fn relay_domain_once<A>(
    store: &Arc<A>,
    domain: &DomainName,
    batch: usize,
    clock: &dyn diport::Clock,
    metrics: &dyn OutboxMetrics,
) -> TickOutcome
where
    A: OutboxSource + OutboxRelay,
{
    let poll_start = clock.now();
    let poll_result = store.poll_pending(domain.as_str(), batch).await;
    metrics.record_tick_duration(RelayPhase::Poll, secs_since(clock, poll_start));
    let entries = match poll_result {
        Ok(entries) => entries,
        Err(e) => {
            log_poll_failed(domain.as_str(), &e);
            return TickOutcome::Degraded;
        }
    };
    if !entries.is_empty() {
        log_polled(domain.as_str(), entries.len());
    }
    let publish_start = clock.now();
    let outcome = relay_batch(store, domain, entries, metrics).await;
    metrics.record_tick_duration(RelayPhase::Publish, secs_since(clock, publish_start));
    outcome
}

/// 逐条中继一批 entry：发 `outbox_publish_total{status}`（含 Ack）+ 翻 [`TickOutcome`]（抽出控制
/// [`relay_domain_once`] 认知复杂度 ≤15）。
///
/// 不在 relay 外套 select!：当前条 publish+CAS 跑完再退，在途写不丢；取消在下一轮 loop 顶部生效
/// （单条有界，尊重 shutdown budget）。
async fn relay_batch<A>(
    store: &Arc<A>,
    domain: &DomainName,
    entries: Vec<Entry>,
    metrics: &dyn OutboxMetrics,
) -> TickOutcome
where
    A: OutboxSource + OutboxRelay,
{
    let mut outcome = TickOutcome::Clean;
    for entry in entries {
        match store.relay(&entry).await {
            Ok(disposition) => {
                metrics.record_publish(domain, disposition);
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
/// 每轮 tick 调 `store.sweep(config.retain_seconds())`，删除超保留期已投递行。`config` 经
/// [`SweeperConfig`] funnel 已校验（`sweep_interval`≠0、`retain_seconds`≠0，SWEEPER-CONFIG-01）。
/// 取消/错误处理与 `relay_loop` 同骨架。
pub async fn sweeper_loop<S>(
    store: Arc<S>,
    config: SweeperConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    S: OutboxSweeper,
{
    let mut ticker = tokio::time::interval(config.sweep_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => sweeper_tick(&store, config.retain_seconds(), &health).await,
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

// ── backlog_sampler_loop（泛型，不 spawn）────────────────────────────────────

/// Outbox backlog 采样驱动循环（泛型，**不** spawn；spawn 在具体类型 call site）。
///
/// 每轮 tick 逐 `config.domains()` 采样 backlog（pending depth + 最老 pending 龄）→ 经 `metrics`
/// set `outbox_pending_depth{domain}` / `outbox_oldest_pending_age_seconds{domain}` gauge（#1209）。
/// 独立于 relay/sweeper 的专用 worker（独立 [`WorkerHealth`]）：gauge 新鲜度由 `config.sample_interval()`
/// 解耦 relay 吞吐与 retention 周期（默认数十秒，远密于 5min oldest-age SLO 窗口），采样失败只降级
/// `outbox_sampler` probe、不污染 relay readyz。取消/错误骨架同 `sweeper_loop`。
/// `config`（domains / sample_interval）经 [`RelayConfig`] funnel 已校验（INVARIANT: RELAY-CONFIG-01，
/// 同 [`relay_loop`]），此处不再防御 0 间隔 / 越界 domain 集。
pub async fn backlog_sampler_loop<B>(
    store: Arc<B>,
    config: RelayConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn OutboxMetrics>,
) where
    B: OutboxBacklog,
{
    let mut ticker = tokio::time::interval(config.sample_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                sampler_tick(&store, config.domains(), &health, metrics.as_ref()).await;
            }
        }
    }
    health.mark_stopped();
}

/// sampler 单轮 tick：逐 domain 采样 + 发 gauge；任一 domain 采样 Err → 整轮 Degraded（其余 domain 仍尝试，
/// 不早退——单 domain 故障不致全停采样）。全干净 → Healthy（F5 自愈）。
async fn sampler_tick<B>(
    store: &Arc<B>,
    domains: &[DomainName],
    health: &Arc<WorkerHealth>,
    metrics: &dyn OutboxMetrics,
) where
    B: OutboxBacklog,
{
    let mut degraded = false;
    for domain in domains {
        match store.sample_backlog(domain.as_str()).await {
            Ok(sample) => metrics.record_backlog(domain, sample),
            Err(e) => {
                log_sample_failed(domain.as_str(), &e);
                degraded = true;
            }
        }
    }
    if degraded {
        health.mark_degraded();
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

// ── adopt 式 worker（共用 AdoptedWorker + newtype 委派）────────────────────────

/// adopt 式后台 worker 通用状态（[`RelayWorker`] / [`SweeperWorker`] / [`SamplerWorker`] 共用）。
///
/// 持已 spawn 的 `JoinHandle<()>` + 同一 health + 同一 token；三个 public worker 各 newtype 包裹一个
/// `AdoptedWorker`、委派 `adopt`/`health`/`shutdown`，消除字段集 + 构造 + 访问器三副本（#1209 review）。
/// public worker 仍是**具体类型**——relay_loop/sweeper_loop/backlog_sampler_loop 是泛型非-Send，spawn 在
/// 具体 call site 单态化后 future 才 Send（见本文件 §设计摘要），故不能合并成单一 generic worker。
struct AdoptedWorker {
    inner: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl AdoptedWorker {
    fn adopt(handle: JoinHandle<()>, health: Arc<WorkerHealth>, token: CancellationToken) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(handle)),
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
///
/// reason(rss_diport_impl_allowlist): spec T004.4 显式将 outbox 后台 worker 归属 eventexec 服务层并 impl
/// `ManagedResource`（经组合根 ShutdownStack 注入两阶段关闭）。`ManagedResource` 是生命周期 trait（非可替换
/// provider port），worker 持 loop spawn 的 JoinHandle、是引擎驱动产物而非 adapter provider，不迁 adapter。
/// allowlist 外 item-level 例外（DIPORT-IMPL-ALLOWLIST-01 逃生门）；根治（豁免 `ManagedResource` 出 lint 扫描集）
/// 见 #1153。unknown_lints 同 allow：dylint 自定义 lint 在 plain clippy 未注册（make verify 跑 plain clippy + dylint 双路）。
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

        #[allow(unknown_lints, rss_diport_impl_allowlist)]
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
    /// Outbox sweeper 后台 worker（结构与 [`RelayWorker`] 同构）。
    SweeperWorker => SWEEPER_WORKER_NAME
);
adopt_worker!(
    /// Outbox backlog 采样后台 worker（结构与 [`RelayWorker`] 同构）。
    SamplerWorker => SAMPLER_WORKER_NAME
);

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering as AtomOrd};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::outbox::{BacklogSample, Disposition, Entry, Topic};
    use consistency::{OutboxBacklog, OutboxRelay, OutboxSource, OutboxSweeper};
    use diport::ManagedResource;
    use primitives::healthz::{HealthStatus, ProbeName};
    use tokio_util::sync::CancellationToken;

    use super::{
        OUTBOX_RELAY_PROBE, OUTBOX_SAMPLER_PROBE, OUTBOX_SWEEPER_PROBE, SamplerWorker,
        SweeperWorker, WorkerHealth, backlog_sampler_loop, sweeper_loop,
    };
    use crate::relay::{RelayWorker, relay_loop};
    use crate::relay_config::{RelayConfig, SweeperConfig};
    use crate::relay_metrics::{OutboxMetrics, RelayPhase};
    use vocab::DomainName;

    // ── 测试配置 / metrics 辅助 ───────────────────────────────────────────────

    /// 合法测试 RelayConfig（batch=10, sample=15s；domains 经 &[&str]）。
    #[allow(clippy::expect_used)]
    // reason: 测试 happy-path 断言已知合法 config，item-level carve-out（error-handling.md §Carve-out）。
    fn relay_config(domains: &[&str], poll: Duration) -> RelayConfig {
        RelayConfig::new(
            domains.iter().map(|d| (*d).to_string()).collect(),
            poll,
            10,
            Duration::from_secs(15),
        )
        .expect("valid test relay config")
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

    /// 记录发射调用的 metrics fake（确定性断言；不碰全局 recorder）。
    #[derive(Default)]
    struct CountingMetrics {
        publishes: Mutex<Vec<(String, Disposition)>>,
        backlogs: Mutex<Vec<(String, BacklogSample)>>,
        tick_phases: Mutex<Vec<RelayPhase>>,
    }

    impl CountingMetrics {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
        #[allow(clippy::unwrap_used)]
        // reason: Mutex lock in test，item-level carve-out。
        fn publishes(&self) -> Vec<(String, Disposition)> {
            self.publishes.lock().unwrap().clone()
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn backlogs(&self) -> Vec<(String, BacklogSample)> {
            self.backlogs.lock().unwrap().clone()
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
        fn record_publish(&self, domain: &DomainName, disposition: Disposition) {
            self.publishes
                .lock()
                .unwrap()
                .push((domain.as_str().to_string(), disposition));
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn record_backlog(&self, domain: &DomainName, sample: BacklogSample) {
            self.backlogs
                .lock()
                .unwrap()
                .push((domain.as_str().to_string(), sample));
        }
        #[allow(clippy::unwrap_used)]
        // reason: 同上。
        fn record_tick_duration(&self, phase: RelayPhase, _seconds: f64) {
            self.tick_phases.lock().unwrap().push(phase);
        }
    }

    /// Fake backlog 采样源：返预置 sample 或 Err。
    struct FakeBacklog {
        sample: BacklogSample,
        err: Option<consistency::error::EngineErrorKind>,
    }

    impl FakeBacklog {
        fn new(sample: BacklogSample) -> Arc<Self> {
            Arc::new(Self { sample, err: None })
        }
        fn with_err(kind: consistency::error::EngineErrorKind) -> Arc<Self> {
            Arc::new(Self {
                sample: BacklogSample::empty(),
                err: Some(kind),
            })
        }
    }

    impl OutboxBacklog for FakeBacklog {
        async fn sample_backlog(
            &self,
            _domain: &str,
        ) -> Result<BacklogSample, consistency::error::EngineError> {
            if let Some(kind) = self.err {
                return Err(consistency::error::EngineError::new(kind));
            }
            Ok(self.sample)
        }
    }

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
            relay_config(&["testdomain"], Duration::from_millis(100)),
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
            relay_config(&["testdomain"], Duration::from_secs(60)),
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
            relay_config(&["dom"], Duration::from_secs(60)),
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
            vec![make_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        let health = Arc::new(WorkerHealth::healthy());
        super::relay_tick(
            &store,
            &[dn("dom")],
            10,
            &FixedClock,
            &health,
            &CountingMetrics::default(),
        )
        .await;
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
            super::relay_tick(
                &store,
                &[dn("dom")],
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
        let domains = [dn("dom")];
        // 第一轮：relay Err → Degraded。
        let erroring = FakeStore::with_relay_err(
            vec![make_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        super::relay_tick(
            &erroring,
            &domains,
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
            &domains,
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
        let domains = [dn("dom")];
        // 第一轮：relay Err → Degraded。
        let erroring = FakeStore::with_relay_err(
            vec![make_entry()],
            consistency::error::EngineErrorKind::Transient,
        );
        super::relay_tick(
            &erroring,
            &domains,
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
        let all_ack = FakeStore::new(vec![make_entry(), make_entry()]);
        super::relay_tick(
            &all_ack,
            &domains,
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

    /// T10c：poll 返回 Err → health Degraded（poll_pending 路径）。
    #[tokio::test(start_paused = true)]
    async fn t10c_poll_error_marks_degraded() {
        let store = FakeStore::with_poll_err(consistency::error::EngineErrorKind::Transient);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();

        let _handle = tokio::spawn(relay_loop(
            store.clone(),
            relay_config(&["dom"], Duration::from_millis(100)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
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
            sweeper_config(86400, Duration::from_secs(1)),
            token.clone(),
            health.clone(),
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

    // ── RelayWorker/SweeperWorker name ───────────────────────────────────────

    #[tokio::test]
    async fn relay_worker_name_is_outbox_relay() {
        let store = FakeStore::new(vec![]);
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(relay_loop(
            store,
            relay_config(&["dom"], Duration::from_secs(60)),
            fixed_clock(),
            token.clone(),
            health.clone(),
            noop_metrics(),
        ));
        let worker = RelayWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-relay");
        let _ = worker.shutdown().await; // 收敛 spawned task（防 leak；shutdown 内部防御性 cancel）。
    }

    #[tokio::test]
    async fn sweeper_worker_name_is_outbox_sweeper() {
        let sweeper = FakeSweeper::new();
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(sweeper_loop(
            sweeper,
            sweeper_config(86400, Duration::from_secs(60)),
            token.clone(),
            health.clone(),
        ));
        let worker = SweeperWorker::adopt(handle, health, token);
        assert_eq!(worker.name(), "outbox-sweeper");
        let _ = worker.shutdown().await; // 收敛 spawned task（防 leak；shutdown 内部防御性 cancel）。
    }

    // ── #1209 sampler worker name ────────────────────────────────────────────

    #[tokio::test]
    async fn sampler_worker_name_is_outbox_sampler() {
        let store = FakeBacklog::new(BacklogSample::empty());
        let health = Arc::new(WorkerHealth::healthy());
        let token = CancellationToken::new();
        let handle = tokio::spawn(backlog_sampler_loop(
            store,
            relay_config(&["dom"], Duration::from_secs(60)),
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
            let store = FakeStore::with_relay_disposition(vec![make_entry()], disposition);
            let health = Arc::new(WorkerHealth::healthy());
            let metrics = CountingMetrics::new();
            super::relay_tick(
                &store,
                &[dn("identity")],
                10,
                &FixedClock,
                &health,
                metrics.as_ref(),
            )
            .await;
            assert_eq!(
                metrics.publishes(),
                vec![("identity".to_string(), disposition)],
                "publish counter must record disposition {}",
                disposition.as_label()
            );
        }
    }

    /// relay tick 每 domain 各发一次 poll 相 + 一次 publish 相耗时（settle 并入 publish）。
    #[tokio::test]
    async fn relay_records_tick_duration_poll_and_publish() {
        let store = FakeStore::new(vec![make_entry()]);
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        super::relay_tick(
            &store,
            &[dn("identity")],
            10,
            &FixedClock,
            &health,
            metrics.as_ref(),
        )
        .await;
        assert_eq!(
            metrics.tick_phases(),
            vec![RelayPhase::Poll, RelayPhase::Publish],
            "tick must observe poll then publish phase"
        );
    }

    /// sampler tick 逐 domain set backlog gauge（record_backlog 携采样值）+ 干净轮 Healthy。
    #[tokio::test]
    async fn sampler_records_backlog_gauge() {
        let sample = BacklogSample::new(42, 305);
        let store = FakeBacklog::new(sample);
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        super::sampler_tick(&store, &[dn("identity")], &health, metrics.as_ref()).await;
        assert_eq!(metrics.backlogs(), vec![("identity".to_string(), sample)]);
        assert_eq!(health.status(), HealthStatus::Healthy);
    }

    /// sampler 采样 Err → 整轮 Degraded（不发 gauge），干净下一轮自愈（F5）。
    #[tokio::test]
    async fn sampler_error_marks_degraded_then_recovers() {
        let health = Arc::new(WorkerHealth::healthy());
        let metrics = CountingMetrics::new();
        // 第一轮：采样 Err → Degraded、无 gauge 发射。
        let erroring = FakeBacklog::with_err(consistency::error::EngineErrorKind::Transient);
        super::sampler_tick(&erroring, &[dn("dom")], &health, metrics.as_ref()).await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert!(
            metrics.backlogs().is_empty(),
            "Err round must not emit gauge"
        );
        // 第二轮：干净采样 → 恢复 Healthy。
        let clean = FakeBacklog::new(BacklogSample::empty());
        super::sampler_tick(&clean, &[dn("dom")], &health, metrics.as_ref()).await;
        assert_eq!(health.status(), HealthStatus::Healthy);
    }
}
