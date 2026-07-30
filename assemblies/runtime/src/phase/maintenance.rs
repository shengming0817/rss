//! RLS readiness and expiry sweepers owned by WireDomains/BuildInfra.

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use eventexec::{
    MetricsRetentionMetrics, RetentionBacklog, RetentionBacklogObservation, RetentionMetrics,
    RetentionOutcome, RetentionTarget,
};
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
pub(crate) const REVOCATION_SWEEPER_PROBE_NAME: &str = "certificate_revocation_sweeper";
pub(crate) const REVOCATION_SWEEPER_WORKER_NAME: &str = "certificate-revocation-sweeper";
const REVOCATION_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const REVOCATION_SWEEP_TIMEOUT: Duration = Duration::from_secs(25);
const AUTH_GRANT_TARGET_TABLE: &str = "auth_grants";
const SERVICE_TOKEN_REPLAY_TARGET_TABLE: &str = "service_token_replay_keys";
const REVOCATION_TARGET_TABLE: &str = "certificate_revocations";

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

pub(crate) type RevocationSweepFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<RevocationSweepObservation, consistency::EngineError>,
            > + Send
            + 'a,
    >,
>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RevocationSweepObservation {
    deleted: u64,
    backlog: RetentionBacklog,
}

impl RevocationSweepObservation {
    pub(crate) const fn new(deleted: u64, backlog: RetentionBacklog) -> Self {
        Self { deleted, backlog }
    }
}

pub(crate) trait AuthGrantSweepRunner: Send {
    fn sweep(&mut self, deadline: postgres::AuthGrantSweepDeadline) -> AuthGrantSweepFuture<'_>;
}

impl AuthGrantSweepRunner for postgres::PgAuthGrantSweeper {
    fn sweep(&mut self, deadline: postgres::AuthGrantSweepDeadline) -> AuthGrantSweepFuture<'_> {
        Box::pin(self.sweep_expired(deadline))
    }
}

pub(crate) trait RevocationSweepRunner: Send {
    fn sweep(&mut self, deadline: postgres::RevocationSweepDeadline) -> RevocationSweepFuture<'_>;
}

impl RevocationSweepRunner for postgres::PgRevocationSweeper {
    fn sweep(&mut self, deadline: postgres::RevocationSweepDeadline) -> RevocationSweepFuture<'_> {
        Box::pin(async move {
            let report = self.sweep_expired(deadline).await?;
            Ok(RevocationSweepObservation::new(
                report.deleted(),
                RetentionBacklog::new(
                    report.backlog().depth(),
                    report.backlog().oldest_age_seconds(),
                ),
            ))
        })
    }
}

type MaintenanceSweepFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = MaintenanceSweepResult> + Send + 'a>>;

#[derive(Debug)]
enum MaintenanceSweepResult {
    Success {
        deleted: u64,
        backlog: Option<RetentionBacklog>,
    },
    Failure {
        outcome: RetentionOutcome,
        stage: MaintenanceSweepFailureStage,
    },
}

impl MaintenanceSweepResult {
    fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }
}

#[derive(Debug, Clone, Copy)]
enum MaintenanceSweepFailureStage {
    Deadline,
    Sweep,
}

impl MaintenanceSweepFailureStage {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Sweep => "sweep",
        }
    }
}

trait MaintenanceSweepTask: Send {
    fn target_table(&self) -> &'static str;

    fn sweep(&mut self, timeout: Duration) -> MaintenanceSweepFuture<'_>;

    fn observe(&self, _result: &MaintenanceSweepResult, _duration_seconds: f64) {}
}

struct AuthGrantSweepTask<R> {
    runner: R,
}

impl<R: AuthGrantSweepRunner> MaintenanceSweepTask for AuthGrantSweepTask<R> {
    fn target_table(&self) -> &'static str {
        AUTH_GRANT_TARGET_TABLE
    }

    fn sweep(&mut self, timeout: Duration) -> MaintenanceSweepFuture<'_> {
        Box::pin(async move {
            let deadline = match postgres::AuthGrantSweepDeadline::from_timeout(timeout) {
                Ok(deadline) => deadline,
                Err(error) => {
                    return MaintenanceSweepResult::Failure {
                        outcome: retention_outcome(&error),
                        stage: MaintenanceSweepFailureStage::Deadline,
                    };
                }
            };
            match self.runner.sweep(deadline).await {
                Ok(deleted) => MaintenanceSweepResult::Success {
                    deleted,
                    backlog: None,
                },
                Err(error) => MaintenanceSweepResult::Failure {
                    outcome: retention_outcome(&error),
                    stage: MaintenanceSweepFailureStage::Sweep,
                },
            }
        })
    }
}

struct RevocationSweepTask<R> {
    runner: R,
}

impl<R: RevocationSweepRunner> MaintenanceSweepTask for RevocationSweepTask<R> {
    fn target_table(&self) -> &'static str {
        REVOCATION_TARGET_TABLE
    }

    fn sweep(&mut self, timeout: Duration) -> MaintenanceSweepFuture<'_> {
        Box::pin(async move {
            let deadline = match postgres::RevocationSweepDeadline::from_timeout(timeout) {
                Ok(deadline) => deadline,
                Err(error) => {
                    return MaintenanceSweepResult::Failure {
                        outcome: retention_outcome(&error),
                        stage: MaintenanceSweepFailureStage::Deadline,
                    };
                }
            };
            match self.runner.sweep(deadline).await {
                Ok(report) => MaintenanceSweepResult::Success {
                    deleted: report.deleted,
                    backlog: Some(report.backlog),
                },
                Err(error) => MaintenanceSweepResult::Failure {
                    outcome: retention_outcome(&error),
                    stage: MaintenanceSweepFailureStage::Sweep,
                },
            }
        })
    }

    fn observe(&self, result: &MaintenanceSweepResult, duration_seconds: f64) {
        let metrics = MetricsRetentionMetrics;
        match result {
            MaintenanceSweepResult::Success {
                deleted,
                backlog: Some(backlog),
            } => {
                metrics.record_sweep(
                    RetentionTarget::CertificateRevocations,
                    RetentionOutcome::Success,
                    *deleted,
                    duration_seconds,
                );
                metrics.record_retention_backlog(
                    RetentionTarget::CertificateRevocations,
                    RetentionBacklogObservation::Available(*backlog),
                );
            }
            MaintenanceSweepResult::Failure { outcome, .. } => {
                metrics.record_sweep(
                    RetentionTarget::CertificateRevocations,
                    *outcome,
                    0,
                    duration_seconds,
                );
                metrics.record_retention_backlog(
                    RetentionTarget::CertificateRevocations,
                    RetentionBacklogObservation::Unavailable,
                );
            }
            MaintenanceSweepResult::Success { backlog: None, .. } => {
                unreachable!("revocation sweep success must include its atomic backlog sample")
            }
        }
    }
}

struct ServiceTokenReplaySweepTask {
    sweeper: postgres::PgServiceTokenReplaySweeper,
}

impl MaintenanceSweepTask for ServiceTokenReplaySweepTask {
    fn target_table(&self) -> &'static str {
        SERVICE_TOKEN_REPLAY_TARGET_TABLE
    }

    fn sweep(&mut self, timeout: Duration) -> MaintenanceSweepFuture<'_> {
        Box::pin(async move {
            let deadline = match diport::ServiceTokenReplayDeadline::from_timeout(timeout) {
                Ok(deadline) => deadline,
                Err(_) => {
                    return MaintenanceSweepResult::Failure {
                        outcome: RetentionOutcome::Invariant,
                        stage: MaintenanceSweepFailureStage::Deadline,
                    };
                }
            };
            match self.sweeper.sweep_expired(deadline).await {
                Ok(deleted) => MaintenanceSweepResult::Success {
                    deleted,
                    backlog: None,
                },
                Err(_) => MaintenanceSweepResult::Failure {
                    outcome: RetentionOutcome::Transient,
                    stage: MaintenanceSweepFailureStage::Sweep,
                },
            }
        })
    }
}

fn retention_outcome(error: &consistency::EngineError) -> RetentionOutcome {
    match error.kind() {
        consistency::EngineErrorKind::Transient => RetentionOutcome::Transient,
        consistency::EngineErrorKind::Permanent | consistency::EngineErrorKind::Invariant => {
            RetentionOutcome::Invariant
        }
        _ => RetentionOutcome::Invariant,
    }
}

#[allow(
    clippy::cognitive_complexity,
    clippy::disallowed_methods,
    reason = "the closed cancellation loop needs Tokio monotonic elapsed time only for latency telemetry"
)]
async fn run_sweeper_loop(
    mut task: impl MaintenanceSweepTask,
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
                let started = tokio::time::Instant::now();
                let result = tokio::select! {
                    biased;
                    () = worker_token.cancelled() => break,
                    result = task.sweep(timeout) => result,
                };
                if result.is_success() {
                    health.mark_healthy();
                } else {
                    health.mark_degraded();
                }
                match &result {
                    MaintenanceSweepResult::Success { deleted, backlog } => tracing::debug!(
                        target_table = task.target_table(),
                        deleted,
                        backlog_depth = backlog.map(RetentionBacklog::depth),
                        backlog_oldest_age_seconds = backlog.map(RetentionBacklog::oldest_age_seconds),
                        "maintenance sweeper tick completed"
                    ),
                    MaintenanceSweepResult::Failure { outcome, stage } => tracing::warn!(
                        target_table = task.target_table(),
                        outcome = outcome.as_label(),
                        stage = stage.as_label(),
                        "maintenance sweeper tick failed; backing off to next tick"
                    ),
                }
                task.observe(&result, started.elapsed().as_secs_f64());
                ticker.reset();
            }
        }
    }
}

pub(crate) async fn run_auth_grant_sweeper_loop(
    sweeper: impl AuthGrantSweepRunner,
    period: Duration,
    timeout: Duration,
    worker_token: CancellationToken,
    health: Arc<SweeperHealth>,
) {
    run_sweeper_loop(
        AuthGrantSweepTask { runner: sweeper },
        period,
        timeout,
        worker_token,
        health,
    )
    .await;
}

pub(crate) async fn run_revocation_sweeper_loop(
    sweeper: impl RevocationSweepRunner,
    period: Duration,
    timeout: Duration,
    worker_token: CancellationToken,
    health: Arc<SweeperHealth>,
) {
    run_sweeper_loop(
        RevocationSweepTask { runner: sweeper },
        period,
        timeout,
        worker_token,
        health,
    )
    .await;
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
    let worker = bootstrap::WorkerSpec::phase_one(move |token| {
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
    let worker = bootstrap::WorkerSpec::phase_one(move |token| {
        let child = token.child_token();
        let worker_token = child.clone();
        let health = worker_health;
        let handle = tokio::spawn(run_sweeper_loop(
            ServiceTokenReplaySweepTask { sweeper },
            SERVICE_TOKEN_REPLAY_SWEEP_INTERVAL,
            SERVICE_TOKEN_REPLAY_SWEEP_TIMEOUT,
            worker_token,
            health,
        ));
        DynManagedResource::new_box(SweeperWorker {
            name: SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME,
            handle: tokio::sync::Mutex::new(Some(handle)),
            token: child,
        })
    });
    sweeper_module_result(worker, health, SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME)
}

/// Wire the receipt-backed, fixed certificate-revocation retention function into one real probe
/// and one managed worker. There is no runtime batch/grace override: both remain migration-owned.
pub(crate) fn wire_revocation_sweeper(pg: &PgRuntimeHandle) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().revocation_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker = bootstrap::WorkerSpec::phase_one(move |token| {
        let child = token.child_token();
        let worker_token = child.clone();
        let handle = tokio::spawn(run_revocation_sweeper_loop(
            sweeper,
            REVOCATION_SWEEP_INTERVAL,
            REVOCATION_SWEEP_TIMEOUT,
            worker_token,
            worker_health,
        ));
        DynManagedResource::new_box(SweeperWorker {
            name: REVOCATION_SWEEPER_WORKER_NAME,
            handle: tokio::sync::Mutex::new(Some(handle)),
            token: child,
        })
    });
    sweeper_module_result(worker, health, REVOCATION_SWEEPER_PROBE_NAME)
}
