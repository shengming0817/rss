//! RLS readiness and expiry sweepers owned by WireDomains/BuildInfra.

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use postgres::PgRuntimeHandle;
use primitives::{HealthCheck, HealthStatus, ProbeName};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// ── Auth-grant expiry sweeper helper ──────────────────────────────────────────────────────────

pub(crate) const AUTH_GRANT_SWEEPER_PROBE_NAME: &str = "auth_grant_sweeper";
pub(crate) const AUTH_GRANT_SWEEPER_WORKER_NAME: &str = "auth-grant-sweeper";
const AUTH_GRANT_SWEEP_TIMEOUT: Duration = Duration::from_secs(25);
pub(crate) const SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME: &str = "service_token_replay_sweeper";
pub(crate) const SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME: &str = "service-token-replay-sweeper";
const SERVICE_TOKEN_REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const SERVICE_TOKEN_REPLAY_SWEEP_TIMEOUT: Duration = Duration::from_secs(25);

// ── RlsReadyProbe ──────────────────────────────────────────────────────────────────────────────

/// RLS 能力门 readyz 兜底探针稳定名（underscore_case，与 prometheus 约定一致）。
pub(crate) const RLS_READY_PROBE_NAME: &str = "rls_ready";

/// RLS 能力门 readyz 兜底探针——读 [`PgRuntimeHandle::rls_ready_handle`] 的启动核验镜像（非 pool）。
///
/// 启动期 `verify_rls_capability` 失败时 `setup` 直接 fail-fast（进程不进入服务态），故进程在跑 ⇒ 此探针
/// 恒 `Healthy`；其价值是把「durable RLS 能力已就绪」这一不变式**显式暴露**到 readyz（运维可见），并为
/// 后续周期性再核验留接线点（届时改为写采样状态即可，探针形态不变）。
///
/// `check`（sync，non-blocking）：读 `AtomicBool`（Acquire），`true → Healthy("ready")` /
/// `false → Unhealthy("not-enforced")`（fail-closed）。`detail` 固定 `&'static str` const（禁夹带 PII）。
pub(crate) struct RlsReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl RlsReadyProbe {
    /// 构造 `RlsReadyProbe`（读 RLS 能力门镜像）。`name` 应使用 [`RLS_READY_PROBE_NAME`] 常量。
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        // reason: RLS_READY_PROBE_NAME 是 underscore_case const literal，ProbeName::parse 仅失败于非法
        // 字符；const 已手工验证，expect 是构造期 programmer error（不可恢复，同 ConfigsReadyProbe）。
        let name = ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RlsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "not-enforced")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

// ── AuthGrant sweeper probe / shared sweeper worker ───────────────────────────────────────────

const SWEEPER_STARTING: u8 = 0;
const SWEEPER_HEALTHY: u8 = 1;
const SWEEPER_DEGRADED: u8 = 2;
const SWEEPER_STOPPED: u8 = 3;

pub(crate) struct SweeperHealth(std::sync::atomic::AtomicU8);

impl SweeperHealth {
    pub(crate) fn starting() -> Self {
        Self(std::sync::atomic::AtomicU8::new(SWEEPER_STARTING))
    }

    fn mark_healthy(&self) {
        self.0
            .store(SWEEPER_HEALTHY, std::sync::atomic::Ordering::Release);
    }

    fn mark_degraded(&self) {
        self.0
            .store(SWEEPER_DEGRADED, std::sync::atomic::Ordering::Release);
    }

    fn mark_stopped(&self) {
        self.0
            .store(SWEEPER_STOPPED, std::sync::atomic::Ordering::Release);
    }

    fn observe_result<T, E>(&self, result: &Result<T, E>) {
        if result.is_ok() {
            self.mark_healthy();
        } else {
            self.mark_degraded();
        }
    }

    pub(crate) fn status_detail(&self) -> (HealthStatus, &'static str) {
        match self.0.load(std::sync::atomic::Ordering::Acquire) {
            SWEEPER_HEALTHY => (HealthStatus::Healthy, "worker"),
            SWEEPER_DEGRADED => (HealthStatus::Degraded, "degraded"),
            SWEEPER_STOPPED => (HealthStatus::Unhealthy, "stopped"),
            _ => (HealthStatus::Unhealthy, "starting"),
        }
    }
}

struct SweeperStoppedGuard(Arc<SweeperHealth>);

impl Drop for SweeperStoppedGuard {
    fn drop(&mut self) {
        self.0.mark_stopped();
    }
}

struct AuthGrantSweeperProbe {
    name: ProbeName,
    health: Arc<SweeperHealth>,
}

impl bootstrap::HealthProbe for AuthGrantSweeperProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = self.health.status_detail();
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct SweeperWorker {
    name: &'static str,
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for SweeperWorker {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "sweeper worker join failed");
        }
        Ok(())
    }
}

pub(crate) type AuthGrantSweepFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<u64, consistency::EngineError>> + Send + 'a>,
>;

pub(crate) trait AuthGrantSweepRunner: Send {
    fn sweep(&mut self, deadline: postgres::AuthGrantSweepDeadline) -> AuthGrantSweepFuture<'_>;
}

impl AuthGrantSweepRunner for postgres::PgAuthGrantSweeper {
    fn sweep(&mut self, deadline: postgres::AuthGrantSweepDeadline) -> AuthGrantSweepFuture<'_> {
        Box::pin(self.sweep_expired(deadline))
    }
}

pub(crate) async fn run_auth_grant_sweeper_loop(
    mut sweeper: impl AuthGrantSweepRunner,
    period: Duration,
    timeout: Duration,
    worker_token: CancellationToken,
    health: Arc<SweeperHealth>,
) {
    let _stopped = SweeperStoppedGuard(Arc::clone(&health));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = worker_token.cancelled() => break,
            _ = ticker.tick() => {
                let Some(deadline) = auth_grant_sweep_deadline(timeout, &health) else {
                    ticker.reset();
                    continue;
                };
                if run_auth_grant_sweep_tick(&mut sweeper, deadline, &worker_token, &health).await {
                    break;
                }
                ticker.reset();
            }
        }
    }
}

fn auth_grant_sweep_deadline(
    timeout: Duration,
    health: &SweeperHealth,
) -> Option<postgres::AuthGrantSweepDeadline> {
    match postgres::AuthGrantSweepDeadline::from_timeout(timeout) {
        Ok(deadline) => Some(deadline),
        Err(error) => {
            tracing::warn!(
                target_table = "auth_grants",
                error = %error,
                "auth-grant sweeper: deadline setup failed"
            );
            health.mark_degraded();
            None
        }
    }
}

async fn run_auth_grant_sweep_tick(
    sweeper: &mut impl AuthGrantSweepRunner,
    deadline: postgres::AuthGrantSweepDeadline,
    worker_token: &CancellationToken,
    health: &SweeperHealth,
) -> bool {
    tokio::select! {
        biased;
        () = worker_token.cancelled() => true,
        result = sweeper.sweep(deadline) => {
            report_auth_grant_sweep_result(result, health);
            false
        }
    }
}

fn report_auth_grant_sweep_result(
    result: Result<u64, consistency::EngineError>,
    health: &SweeperHealth,
) {
    health.observe_result(&result);
    match result {
        Ok(deleted) => log_auth_grant_sweep_success(deleted),
        Err(error) => log_auth_grant_sweep_error(&error),
    }
}

fn log_auth_grant_sweep_success(deleted: u64) {
    tracing::debug!(
        target_table = "auth_grants",
        deleted,
        "auth-grant sweeper: tick completed"
    );
}

fn log_auth_grant_sweep_error(error: &consistency::EngineError) {
    tracing::warn!(
        target_table = "auth_grants",
        error = %error,
        "auth-grant sweeper: sweep failed, marking worker degraded; backing off to next tick"
    );
}

fn spawn_auth_grant_sweeper(
    sweeper: postgres::PgAuthGrantSweeper,
    period: Duration,
    token: CancellationToken,
    health: Arc<SweeperHealth>,
) -> SweeperWorker {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(run_auth_grant_sweeper_loop(
        sweeper,
        period,
        AUTH_GRANT_SWEEP_TIMEOUT,
        worker_token,
        health,
    ));
    SweeperWorker {
        name: AUTH_GRANT_SWEEPER_WORKER_NAME,
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

pub(crate) fn sweeper_module_result(
    worker: bootstrap::WorkerSpec,
    health: Arc<SweeperHealth>,
    probe_name: &'static str,
) -> anyhow::Result<DomainModuleResult> {
    let probe_name = ProbeName::parse(probe_name).context("sweeper probe name is invalid")?;
    Ok(DomainModuleResult {
        probes: vec![(
            probe_name.clone(),
            Box::new(AuthGrantSweeperProbe {
                name: probe_name,
                health,
            }),
        )],
        workers: vec![worker],
        ..Default::default()
    })
}

pub(crate) fn wire_auth_grant_sweeper(
    pg: &PgRuntimeHandle,
    period: Duration,
) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().auth_grant_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_auth_grant_sweeper(
            sweeper,
            period,
            token,
            worker_health,
        ))
    });
    tracing::info!(
        interval_ms = period.as_millis(),
        "auth-grant sweeper interval configured"
    );
    sweeper_module_result(worker, health, AUTH_GRANT_SWEEPER_PROBE_NAME)
}

pub(crate) fn wire_service_token_replay_sweeper(
    pg: &PgRuntimeHandle,
) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().service_token_replay_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        let child = token.child_token();
        let worker_token = child.clone();
        let health = worker_health;
        let handle = tokio::spawn(async move {
            let _stopped = SweeperStoppedGuard(Arc::clone(&health));
            let mut ticker = tokio::time::interval(SERVICE_TOKEN_REPLAY_SWEEP_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    () = worker_token.cancelled() => break,
                    _ = ticker.tick() => {
                        tokio::select! {
                            biased;
                            () = worker_token.cancelled() => break,
                            result = sweeper.sweep_expired(
                                match diport::ServiceTokenReplayDeadline::from_timeout(
                                    SERVICE_TOKEN_REPLAY_SWEEP_TIMEOUT,
                                ) {
                                    Ok(deadline) => deadline,
                                    Err(error) => {
                                        tracing::warn!(
                                            target_table = "service_token_replay_keys",
                                            error = %error,
                                            "replay sweeper: deadline setup failed"
                                        );
                                        health.mark_degraded();
                                        ticker.reset();
                                        continue;
                                    }
                                }
                            ) => {
                                health.observe_result(&result);
                                match result {
                                    Ok(deleted) => {
                                        tracing::debug!(target_table = "service_token_replay_keys", deleted, "replay sweeper: tick completed");
                                    }
                                    Err(error) => {
                                        tracing::warn!(target_table = "service_token_replay_keys", error = %error, "replay sweeper: sweep failed");
                                    }
                                }
                                ticker.reset();
                            }
                        }
                    }
                }
            }
        });
        DynManagedResource::new_box(SweeperWorker {
            name: SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME,
            handle: tokio::sync::Mutex::new(Some(handle)),
            token: child,
        })
    });
    sweeper_module_result(worker, health, SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME)
}
