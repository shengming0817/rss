//! DB liveness 采样组件（后台周期探针 + adopt 式 ManagedResource worker）。
//!
//! 镜像 `crates/eventexec/src/relay.rs`（`backlog_sampler_loop` + `AdoptedWorker` + `adopt_worker!`
//! 结构），但 postgres 在 `adapters/` 下不引用 `eventexec` 类型——**结构镜像而非类型复用**。
//!
//! # 组件
//!
//! - [`PgDbReadiness`]：`AtomicU8` 状态持有者，初值 Down（fail-closed：首次成功采样前不报 ready）。
//! - [`pg_readiness_sampling_loop`]：裸 loop，**不 spawn**，spawn 在组合根 call-site。
//! - [`PgReadinessSampler`]：adopt 式 worker，impl `diport::ManagedResource`；
//!   `shutdown` 两阶段关闭：cancel token → await handle。
//!
//! `tokio::time::interval` 被允许——clippy 只禁 `Instant::now`/`elapsed`（Clock 注入约束），
//! 周期定时器不属此约束（relay.rs:371 同款用法）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::PgStore;
use crate::pool::PoolReadiness;

// AtomicU8 编码：0=Ready，1=Saturated，2=Down（三态；初值 Down=2，fail-closed）。
const READINESS_READY: u8 = 0;
const READINESS_SATURATED: u8 = 1;
const READINESS_DOWN: u8 = 2;

/// worker 名常量（`ManagedResource::name` 稳定标识；≥3 处同义使用抽 const）。
const SAMPLER_WORKER_NAME: &str = "pg-readiness-sampler";

// ── PgDbReadiness ──────────────────────────────────────────────────────────────

/// DB liveness 采样状态持有者（`AtomicU8`；初值 Down = fail-closed）。
///
/// 首次成功采样前不报 ready，确保 readyz probe 在 DB 真正可达前不通过。
/// `snapshot()` 供 probe 同步读（无 await，不阻塞 reactor）；`mark()` 仅由后台
/// 采样 loop 调用（`pub(crate)`）。
///
/// 编码：0=Ready，1=Saturated，2=Down（三态；#1309 F4 重引 Saturated——池饱和可服务，DB 不可达不可服务）。
pub struct PgDbReadiness(AtomicU8);

impl PgDbReadiness {
    /// 构造，初值 Down（fail-closed：首次成功采样前不报 ready）。
    ///
    /// 保持 `pub`（#1423）：`PgDbReadiness` 是 provider-agnostic 状态原子（**非** pool/store/repo），
    /// 封闭其构造无 funnel 价值、且破坏 hermetic probe 单测（probe→503 路径不需真 DB）；生产编排路径仍是
    /// [`crate::PgRuntimeDeps::setup`] 建 + [`crate::PgRuntimeHandle::readiness_handle`] 派发。
    pub fn new() -> Self {
        Self(AtomicU8::new(READINESS_DOWN))
    }

    /// 同步读当前 DB liveness 快照（probe 同步接口，不阻塞 reactor）。
    #[must_use]
    pub fn snapshot(&self) -> PoolReadiness {
        match self.0.load(Ordering::Acquire) {
            READINESS_READY => PoolReadiness::Ready,
            READINESS_SATURATED => PoolReadiness::Saturated,
            // 兜底所有其他值为 Down（仅 READINESS_DOWN 正常写入；`_` 兼容
            // clippy::wildcard_in_or_patterns——不能写 `READINESS_DOWN | _`）。
            _ => PoolReadiness::Down,
        }
    }

    /// 后台采样 loop 写入最新 liveness 状态（`Ordering::Release`）。
    ///
    /// `PoolReadiness` 三态（#1309 F4 重引 Saturated）：`Ready`→0，`Saturated`→1，`Down`→2。
    pub(crate) fn mark(&self, r: PoolReadiness) {
        let v = match r {
            PoolReadiness::Ready => READINESS_READY,
            PoolReadiness::Saturated => READINESS_SATURATED,
            PoolReadiness::Down => READINESS_DOWN,
        };
        self.0.store(v, Ordering::Release);
    }
}

impl Default for PgDbReadiness {
    fn default() -> Self {
        Self::new()
    }
}

// ── pg_readiness_sampling_loop ─────────────────────────────────────────────────

/// DB liveness 状态转移时记 warn!/info!（`Down`/`Saturated` 转入 / `Ready` 恢复）；状态未变或首次成功则静默。
// reason: tracing::warn!/info! 宏展开后 clippy cognitive_complexity 计数偏高（实际 4 分支）——item-level carve-out。
#[allow(clippy::cognitive_complexity)]
fn log_readiness_transition(cur: PoolReadiness, last: Option<PoolReadiness>) {
    // reason: 早返回比 else 分支更清晰；状态未变（last==cur）不重复记日志。
    if last == Some(cur) {
        return;
    }
    if cur == PoolReadiness::Down {
        tracing::warn!(target: "postgres", "postgres readiness degraded: db unreachable");
    } else if cur == PoolReadiness::Saturated {
        tracing::warn!(target: "postgres", "postgres pool saturated — degraded, still serving");
    } else if last.is_some() {
        // reason: cur == Ready && last.is_some() = 从 Down/Saturated 恢复；last.is_none() = 首次成功，静默。
        tracing::info!(target: "postgres", "postgres readiness recovered");
    }
}

/// 后台周期 DB liveness 采样 loop（裸 loop，**不 spawn**；spawn 在组合根 call-site）。
///
/// 镜像 `eventexec::relay::backlog_sampler_loop`：`biased` 取消优先，`interval` 周期
/// tick，每 tick 调 `store.probe_db_liveness()` 并原子写 `health`。
///
/// 取消信号经 `CancellationToken` 注入；首 tick 即发（`interval` 语义），
/// 确保 probe 快速更新（`advance` 或实际 period 过后）。
///
/// **状态转移日志**：仅在状态转移时记日志（`Down`/`Saturated` → warn，`Ready` 恢复 → info；由 [`log_readiness_transition`] 负责）。
///
/// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：spawn 仪式收口进
/// [`crate::PgReadinessSamplerFactory::spawn`]。
pub(crate) async fn pg_readiness_sampling_loop(
    store: Arc<PgStore>,
    period: Duration,
    token: CancellationToken,
    health: Arc<PgDbReadiness>,
) {
    let mut ticker = tokio::time::interval(period);
    let mut last: Option<PoolReadiness> = None;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let cur = store.probe_db_liveness().await;
                log_readiness_transition(cur, last);
                last = Some(cur);
                health.mark(cur);
            }
        }
    }
}

// ── PgReadinessSampler ─────────────────────────────────────────────────────────

/// DB liveness 采样 adopt 式 worker（impl `diport::ManagedResource`）。
///
/// 持已 spawn 的 `JoinHandle<()>` + `Arc<PgDbReadiness>` + `CancellationToken`；
/// `shutdown` 两阶段关闭：cancel token（幂等）→ await handle 收敛。
///
/// adopt 式：先在具体类型处 `tokio::spawn(pg_readiness_sampling_loop(...))` 再调
/// [`PgReadinessSampler::adopt`]，与 `relay.rs` 中 `RelayWorker::adopt` 同范式。
///
/// `PgStore` 在 `adapters/postgres` 下 impl `ManagedResource` 无需 `#[allow]`——
/// `PgReadinessSampler` 同理：dylint `rss_diport_impl_allowlist` 按 manifest
/// 父目录 (`adapters/`) 自动放行。
pub struct PgReadinessSampler {
    inner: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    health: Arc<PgDbReadiness>,
    token: CancellationToken,
}

impl PgReadinessSampler {
    /// 先 `tokio::spawn(pg_readiness_sampling_loop(具体 store, ...))` 再 adopt。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：仅由
    /// [`crate::PgReadinessSamplerFactory::spawn`] 收口调用。
    pub(crate) fn adopt(
        handle: JoinHandle<()>,
        health: Arc<PgDbReadiness>,
        token: CancellationToken,
    ) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(handle)),
            health,
            token,
        }
    }

    /// 返回 liveness 状态句柄。
    ///
    /// 当外部已 adopt `PgReadinessSampler` 且需从 sampler 反取 `Arc<PgDbReadiness>` 时用；
    /// 组合根直接持有 `Arc<PgDbReadiness>` 时无需调此方法。
    pub fn readiness_handle(&self) -> Arc<PgDbReadiness> {
        self.health.clone()
    }
}

impl diport::ManagedResource for PgReadinessSampler {
    fn name(&self) -> &str {
        SAMPLER_WORKER_NAME
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        // 防御性 cancel（幂等；生产中 ShutdownStack 已先 cancel，此处兜底防 test/误用 hang）。
        self.token.cancel();
        // await loop 收敛——保证 worker 在 pool 之前停（LIFO 由组合根注册顺序保证）。
        if let Some(h) = self.inner.lock().await.take() {
            h.await.map_err(diport::ShutdownError::new)?;
        }
        Ok(())
    }
}

// ── 单元测试（无 DB）─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use diport::ManagedResource;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tokio_util::sync::CancellationToken;

    use crate::PgStore;
    use crate::pool::PoolReadiness;

    use super::{PgDbReadiness, PgReadinessSampler, pg_readiness_sampling_loop};

    // ── 辅助：构造已关闭 lazy pool 的 PgStore（不连 DB）────────────────────────

    async fn make_closed_store() -> PgStore {
        // reason: connect_lazy_with 不发真实连接（延迟建连）；close() 后 is_closed()=true。
        // 任意本地地址，不建真实连接（pool.rs:399 同套路）。
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        pool.close().await;
        PgStore { pool }
    }

    // ── PgDbReadiness 状态机 ──────────────────────────────────────────────────

    #[test]
    fn initial_snapshot_is_down() {
        let h = PgDbReadiness::new();
        assert_eq!(
            h.snapshot(),
            PoolReadiness::Down,
            "初值必须为 Down（fail-closed）"
        );
    }

    #[test]
    fn default_snapshot_is_down() {
        let h = PgDbReadiness::default();
        assert_eq!(h.snapshot(), PoolReadiness::Down, "Default 初值必须为 Down");
    }

    #[test]
    fn mark_ready_snapshot_is_ready() {
        let h = PgDbReadiness::new();
        h.mark(PoolReadiness::Ready);
        assert_eq!(h.snapshot(), PoolReadiness::Ready);
    }

    #[test]
    fn mark_down_snapshot_is_down() {
        let h = PgDbReadiness::new();
        h.mark(PoolReadiness::Ready);
        h.mark(PoolReadiness::Down);
        assert_eq!(
            h.snapshot(),
            PoolReadiness::Down,
            "mark(Down) 后 snapshot 必须为 Down"
        );
    }

    #[test]
    fn mark_saturated_snapshot_is_saturated() {
        let h = PgDbReadiness::new();
        h.mark(PoolReadiness::Saturated);
        assert_eq!(
            h.snapshot(),
            PoolReadiness::Saturated,
            "mark(Saturated) 后 snapshot 必须为 Saturated（池饱和真态，非 Down）"
        );
    }

    // ── probe_db_liveness（无 DB）────────────────────────────────────────────

    #[tokio::test]
    async fn probe_closed_pool_returns_down() {
        let store = make_closed_store().await;
        assert_eq!(
            store.probe_db_liveness().await,
            PoolReadiness::Down,
            "已关闭的 pool → probe 返回 Down（is_closed 快路径）"
        );
    }

    // ── 采样 loop（start_paused，无 DB）──────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn sampling_loop_marks_down_on_closed_pool() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();

        let handle = tokio::spawn(pg_readiness_sampling_loop(
            Arc::clone(&store),
            Duration::from_millis(100),
            token.clone(),
            Arc::clone(&health),
        ));

        // advance 推进时钟 → 触发首 tick（interval 首 tick 即发）→ 驱动 spawned task 完成首轮。
        tokio::time::advance(Duration::from_millis(150)).await;

        assert_eq!(
            health.snapshot(),
            PoolReadiness::Down,
            "closed pool 首 tick 后 health 应为 Down"
        );

        token.cancel();
        assert!(handle.await.is_ok(), "sampling loop task 应正常退出");
    }

    #[tokio::test(start_paused = true)]
    async fn sampling_loop_exits_on_cancel() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();

        let handle = tokio::spawn(pg_readiness_sampling_loop(
            Arc::clone(&store),
            Duration::from_secs(3600), // 长 period，不会自然 tick（测取消路径）
            token.clone(),
            Arc::clone(&health),
        ));

        token.cancel();
        // biased cancel 优先——loop 应立即 break，task 正常完成。
        assert!(handle.await.is_ok(), "cancel 后 loop 应退出");
    }

    // ── PgReadinessSampler shutdown ──────────────────────────────────────────

    #[tokio::test]
    async fn sampler_shutdown_cancels_and_joins() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();

        let handle = tokio::spawn(pg_readiness_sampling_loop(
            Arc::clone(&store),
            Duration::from_secs(3600),
            token.clone(),
            Arc::clone(&health),
        ));

        let sampler = PgReadinessSampler::adopt(handle, Arc::clone(&health), token);
        assert!(
            sampler.shutdown().await.is_ok(),
            "PgReadinessSampler::shutdown 应返回 Ok"
        );
    }

    #[tokio::test]
    async fn readiness_handle_returns_same_arc() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();
        // 立即取消——loop biased 分支首先触发，task 不等 tick 就退出。
        token.cancel();

        let handle = tokio::spawn(pg_readiness_sampling_loop(
            Arc::clone(&store),
            Duration::from_secs(3600),
            token.clone(),
            Arc::clone(&health),
        ));

        let sampler = PgReadinessSampler::adopt(handle, Arc::clone(&health), token);
        let returned = sampler.readiness_handle();
        assert!(
            Arc::ptr_eq(&health, &returned),
            "readiness_handle 应返回同一 Arc<PgDbReadiness>"
        );
        assert!(sampler.shutdown().await.is_ok());
    }

    #[test]
    fn sampler_name_is_stable() {
        // INVARIANT: SAMPLER-NAME-01 { level = "Medium", exec = "manual/opt-in", source = "code" }— name 常量用于 ShutdownStack 日志，不可随意改变。
        assert_eq!(super::SAMPLER_WORKER_NAME, "pg-readiness-sampler");
    }
}
