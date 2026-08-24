//! RLS readiness and expiry sweepers owned by WireDomains/BuildInfra.

use anyhow::Context as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ShutdownError};
use eventexec::{
    MetricsRetentionMetrics, RetentionBacklog, RetentionBacklogObservation, RetentionMetrics,
    RetentionOutcome, RetentionTarget, SagaTerminalRetentionMetrics,
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
pub(crate) const SAGA_TERMINAL_SWEEPER_PROBE_NAME: &str = "saga_terminal_sweeper";
pub(crate) const SAGA_TERMINAL_SWEEPER_WORKER_NAME: &str = "saga-terminal-sweeper";
const SAGA_TERMINAL_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const SAGA_TERMINAL_SWEEP_TIMEOUT: Duration = Duration::from_secs(25);
const AUTH_GRANT_TARGET_TABLE: &str = "auth_grants";
const SERVICE_TOKEN_REPLAY_TARGET_TABLE: &str = "service_token_replay_keys";
const REVOCATION_TARGET_TABLE: &str = "certificate_revocations";
const SAGA_TERMINAL_TARGET_TABLE: &str = "saga_instances";

// ── RlsReadyProbe ──────────────────────────────────────────────────────────────────────────────

/// RLS 能力门 readyz 兜底探针稳定名（underscore_case，与 prometheus 约定一致）。
pub(crate) const RLS_READY_PROBE_NAME: &str = "rls_ready";

/// RLS 能力门 readyz 探针——同步读取 writer+reader 周期 attestation 的 typed 状态。
///
/// `check`（sync，non-blocking）：读 typed atomic snapshot，`true → Healthy("ready")` /
/// `false → Unhealthy("attestation-unverified")`（fail-closed）。`detail` 固定 `&'static str` const。
pub(crate) struct RlsReadyProbe {
    ready: Arc<postgres::PgRlsReadiness>,
    name: ProbeName,
}

impl RlsReadyProbe {
    /// 构造 `RlsReadyProbe`（读 RLS 能力门镜像）。`name` 应使用 [`RLS_READY_PROBE_NAME`] 常量。
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<postgres::PgRlsReadiness>) -> Self {
        // reason: RLS_READY_PROBE_NAME 是 underscore_case const literal，ProbeName::parse 仅失败于非法
        // 字符；const 已手工验证，expect 是构造期 programmer error（不可恢复，同 ConfigsReadyProbe）。
        let name = ProbeName::parse(RLS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RlsReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.is_ready() {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "attestation-unverified")
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
    task: diport::ManagedTask,
}

impl SweeperWorker {
    fn spawn<F, Make>(name: &'static str, token: CancellationToken, make: Make) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
        Make: FnOnce(CancellationToken) -> F + Send + 'static,
    {
        let (start, _status) = diport::ManagedTask::prepare(name, diport::DEFAULT_SHUTDOWN_TIMEOUT);
        let task = start.spawn(token, |managed_token| async move {
            make(managed_token).await;
            Ok(())
        });
        Self { name, task }
    }
}

impl ManagedResource for SweeperWorker {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        diport::ManagedResource::shutdown(&self.task).await
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

type SagaTerminalSweepFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<SagaTerminalSweepObservation, consistency::EngineError>,
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

trait SagaTerminalSweepRunner: Send + 'static {
    fn sweep(
        &mut self,
        deadline: postgres::SagaTerminalSweepDeadline,
    ) -> SagaTerminalSweepFuture<'_>;
}

#[derive(Debug, Clone, Copy)]
struct SagaTerminalSweepObservation {
    deleted: u64,
    backlog: RetentionBacklog,
}

impl SagaTerminalSweepRunner for postgres::PgSagaTerminalSweeper {
    fn sweep(
        &mut self,
        deadline: postgres::SagaTerminalSweepDeadline,
    ) -> SagaTerminalSweepFuture<'_> {
        Box::pin(async move {
            let report = self.sweep_expired(deadline).await?;
            Ok(SagaTerminalSweepObservation {
                deleted: report.deleted(),
                backlog: RetentionBacklog::new(
                    report.backlog_depth(),
                    report.oldest_expired_age_seconds(),
                ),
            })
        })
    }
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

struct SagaTerminalSweepTask<R> {
    runner: R,
}

impl<R: SagaTerminalSweepRunner> MaintenanceSweepTask for SagaTerminalSweepTask<R> {
    fn target_table(&self) -> &'static str {
        SAGA_TERMINAL_TARGET_TABLE
    }

    fn sweep(&mut self, timeout: Duration) -> MaintenanceSweepFuture<'_> {
        Box::pin(async move {
            let deadline = match postgres::SagaTerminalSweepDeadline::from_timeout(timeout) {
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
        match result {
            MaintenanceSweepResult::Success {
                deleted,
                backlog: Some(backlog),
            } => {
                SagaTerminalRetentionMetrics::record_sweep(
                    RetentionOutcome::Success,
                    *deleted,
                    duration_seconds,
                );
                SagaTerminalRetentionMetrics::record_backlog(
                    RetentionBacklogObservation::Available(*backlog),
                );
            }
            MaintenanceSweepResult::Failure { outcome, .. } => {
                SagaTerminalRetentionMetrics::record_sweep(*outcome, 0, duration_seconds);
                SagaTerminalRetentionMetrics::record_backlog(
                    RetentionBacklogObservation::Unavailable,
                );
            }
            MaintenanceSweepResult::Success { backlog: None, .. } => {
                unreachable!("Saga terminal sweep success must include its atomic backlog sample")
            }
        }
    }
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
    admission: primitives::WriteAdmission,
) {
    let _stopped = SweeperStoppedGuard(Arc::clone(&health));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = worker_token.cancelled() => break,
            _ = ticker.tick() => {
                let Ok(_permit) = admission.try_enter() else {
                    continue;
                };
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
    admission: primitives::WriteAdmission,
) {
    run_sweeper_loop(
        AuthGrantSweepTask { runner: sweeper },
        period,
        timeout,
        worker_token,
        health,
        admission,
    )
    .await;
}

pub(crate) async fn run_revocation_sweeper_loop(
    sweeper: impl RevocationSweepRunner,
    period: Duration,
    timeout: Duration,
    worker_token: CancellationToken,
    health: Arc<SweeperHealth>,
    admission: primitives::WriteAdmission,
) {
    run_sweeper_loop(
        RevocationSweepTask { runner: sweeper },
        period,
        timeout,
        worker_token,
        health,
        admission,
    )
    .await;
}

fn spawn_auth_grant_sweeper(
    sweeper: postgres::PgAuthGrantSweeper,
    period: Duration,
    token: CancellationToken,
    health: Arc<SweeperHealth>,
    admission: primitives::WriteAdmission,
) -> SweeperWorker {
    let child = token.child_token();
    SweeperWorker::spawn(
        AUTH_GRANT_SWEEPER_WORKER_NAME,
        child,
        move |worker_token| async move {
            run_auth_grant_sweeper_loop(
                sweeper,
                period,
                AUTH_GRANT_SWEEP_TIMEOUT,
                worker_token,
                health,
                admission,
            )
            .await;
        },
    )
}

pub(crate) fn sweeper_module_result(
    worker: bootstrap::WorkerSpec,
    health: Arc<SweeperHealth>,
    probe_name: &'static str,
) -> anyhow::Result<DomainModuleResult> {
    let probe_name = ProbeName::parse(probe_name).context("sweeper probe name is invalid")?;
    let mut output = DomainModuleResult::default();
    output.push_probe((
        probe_name.clone(),
        Box::new(AuthGrantSweeperProbe {
            name: probe_name,
            health,
        }),
    ));
    output.push_worker(worker);
    Ok(output)
}

pub(crate) fn wire_auth_grant_sweeper(
    pg: &PgRuntimeHandle,
    period: Duration,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().auth_grant_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker_admission = write_admission.clone();
    let worker = bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.phase.maintenance.01",
        write_admission,
        move |token, _write_admission| {
            DynManagedResource::new_box(spawn_auth_grant_sweeper(
                sweeper,
                period,
                token,
                worker_health,
                worker_admission,
            ))
        },
    );
    tracing::info!(
        interval_ms = period.as_millis(),
        "auth-grant sweeper interval configured"
    );
    sweeper_module_result(worker, health, AUTH_GRANT_SWEEPER_PROBE_NAME)
}

pub(crate) fn wire_service_token_replay_sweeper(
    pg: &PgRuntimeHandle,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().service_token_replay_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker_admission = write_admission.clone();
    let worker = bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.phase.maintenance.02",
        write_admission,
        move |token, _write_admission| {
            let child = token.child_token();
            let health = worker_health;
            DynManagedResource::new_box(SweeperWorker::spawn(
                SERVICE_TOKEN_REPLAY_SWEEPER_WORKER_NAME,
                child,
                move |worker_token| {
                    run_sweeper_loop(
                        ServiceTokenReplaySweepTask { sweeper },
                        SERVICE_TOKEN_REPLAY_SWEEP_INTERVAL,
                        SERVICE_TOKEN_REPLAY_SWEEP_TIMEOUT,
                        worker_token,
                        health,
                        worker_admission,
                    )
                },
            ))
        },
    );
    sweeper_module_result(worker, health, SERVICE_TOKEN_REPLAY_SWEEPER_PROBE_NAME)
}

/// Wire the receipt-backed, fixed certificate-revocation retention function into one real probe
/// and one managed worker. There is no runtime batch/grace override: both remain migration-owned.
pub(crate) fn wire_revocation_sweeper(
    pg: &PgRuntimeHandle,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    let sweeper = pg.infra().revocation_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker_admission = write_admission.clone();
    let worker = bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.phase.maintenance.03",
        write_admission,
        move |token, _write_admission| {
            let child = token.child_token();
            DynManagedResource::new_box(SweeperWorker::spawn(
                REVOCATION_SWEEPER_WORKER_NAME,
                child,
                move |worker_token| {
                    run_revocation_sweeper_loop(
                        sweeper,
                        REVOCATION_SWEEP_INTERVAL,
                        REVOCATION_SWEEP_TIMEOUT,
                        worker_token,
                        worker_health,
                        worker_admission,
                    )
                },
            ))
        },
    );
    sweeper_module_result(worker, health, REVOCATION_SWEEPER_PROBE_NAME)
}

/// Register one process-global terminal Saga retention worker whenever at least one Saga is active.
/// Retention age and batch size remain frozen inside `rss_sweep_terminal_sagas()`.
pub(crate) fn wire_saga_terminal_sweeper(
    pg: &PgRuntimeHandle,
    active_saga_count: usize,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<DomainModuleResult> {
    if active_saga_count == 0 {
        return Ok(DomainModuleResult::default());
    }
    let sweeper = pg.infra().saga_terminal_sweeper();
    let health = Arc::new(SweeperHealth::starting());
    let worker_health = Arc::clone(&health);
    let worker_admission = write_admission.clone();
    let worker = bootstrap::WorkerSpec::writes_phase_one(
        "assemblies.runtime.src.phase.maintenance.04",
        write_admission,
        move |token, _write_admission| {
            let child = token.child_token();
            DynManagedResource::new_box(SweeperWorker::spawn(
                SAGA_TERMINAL_SWEEPER_WORKER_NAME,
                child,
                move |worker_token| {
                    run_sweeper_loop(
                        SagaTerminalSweepTask { runner: sweeper },
                        SAGA_TERMINAL_SWEEP_INTERVAL,
                        SAGA_TERMINAL_SWEEP_TIMEOUT,
                        worker_token,
                        worker_health,
                        worker_admission,
                    )
                },
            ))
        },
    );
    sweeper_module_result(worker, health, SAGA_TERMINAL_SWEEPER_PROBE_NAME)
}

#[cfg(test)]
mod saga_terminal_tests {
    use super::{
        MaintenanceSweepFailureStage, MaintenanceSweepResult, MaintenanceSweepTask,
        RetentionBacklog, RetentionOutcome, SAGA_TERMINAL_SWEEPER_PROBE_NAME,
        SAGA_TERMINAL_SWEEPER_WORKER_NAME, SagaTerminalSweepTask, wire_saga_terminal_sweeper,
    };

    struct UnusedRunner;

    impl super::SagaTerminalSweepRunner for UnusedRunner {
        fn sweep(
            &mut self,
            _deadline: postgres::SagaTerminalSweepDeadline,
        ) -> super::SagaTerminalSweepFuture<'_> {
            unreachable!("observation tests do not execute a sweep")
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn omitted_or_disabled_sagas_register_no_retention_and_many_register_one() {
        let pg = postgres::PgRuntimeHandle::for_module_test();
        for active_saga_count in [0, 1, 3] {
            let result = wire_saga_terminal_sweeper(
                &pg,
                active_saga_count,
                &primitives::prepare_dr_admission_controls().into_parts().3,
            )
            .expect("terminal Saga retention module result");
            let expected = usize::from(active_saga_count > 0);
            assert_eq!(result.probe_count(), expected);
            assert_eq!(result.worker_count(), expected);
            assert!(result.resource_count() == 0);
            if let Some((name, _)) = result.probes().next() {
                assert_eq!(name.as_str(), SAGA_TERMINAL_SWEEPER_PROBE_NAME);
            }
        }
        assert_eq!(SAGA_TERMINAL_SWEEPER_WORKER_NAME, "saga-terminal-sweeper");
    }

    #[test]
    fn saga_terminal_observer_uses_shared_metrics_and_nan_for_failure() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let task = SagaTerminalSweepTask {
                runner: UnusedRunner,
            };
            task.observe(
                &MaintenanceSweepResult::Success {
                    deleted: 7,
                    backlog: Some(RetentionBacklog::new(3, 2_700_000)),
                },
                0.25,
            );
            task.observe(
                &MaintenanceSweepResult::Failure {
                    outcome: RetentionOutcome::Transient,
                    stage: MaintenanceSweepFailureStage::Sweep,
                },
                0.5,
            );
        });
        let rendered = handle.render();
        assert!(rendered.contains(
            "retention_sweep_ticks_total{target=\"saga_terminal\",outcome=\"success\"} 1"
        ));
        assert!(rendered.contains("retention_expired_backlog_depth{target=\"saga_terminal\"} NaN"));
        assert!(
            rendered.contains("retention_expired_oldest_age_seconds{target=\"saga_terminal\"} NaN")
        );
    }
}
