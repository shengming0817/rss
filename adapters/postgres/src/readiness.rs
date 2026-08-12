//! DB liveness 采样组件（后台周期探针 + adopt 式 ManagedResource worker）。
//!
//! 镜像 `crates/eventexec/src/relay.rs`（`backlog_sampler_loop` + `AdoptedWorker` + `adopt_worker!`
//! 结构），但 postgres 在 `adapters/` 下不引用 `eventexec` 类型——**结构镜像而非类型复用**。
//!
//! # 组件
//!
//! - [`PgDbReadiness`]：`AtomicU8` 状态持有者，初值 Down（fail-closed：首次成功采样前不报 ready）。
//! - [`pg_readiness_sampling_loop`]：裸 loop，**不 spawn**，spawn 在组合根 call-site。
//! - [`PgRuntimeMonitor`]：同时托管 liveness 与 RLS attestation 的 adopt 式 worker；
//!   `shutdown` 两阶段关闭：cancel token → await handle。
//!
//! `tokio::time::interval` 被允许——clippy 只禁 `Instant::now`/`elapsed`（Clock 注入约束），
//! 周期定时器不属此约束（relay.rs:371 同款用法）。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
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
const MONITOR_WORKER_NAME: &str = "pg-runtime-monitor";
const PROJECTION_REGISTRY_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const RLS_ATTESTATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Validated PostgreSQL liveness sampling interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgReadinessInterval(Duration);

impl PgReadinessInterval {
    /// Validate a liveness interval in the supported `1..=300s` range.
    pub fn try_new(value: Duration) -> Result<Self, &'static str> {
        if (Duration::from_secs(1)..=Duration::from_secs(300)).contains(&value) {
            Ok(Self(value))
        } else {
            Err("postgres readiness interval must be between 1s and 300s")
        }
    }

    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn for_test(value: Duration) -> Self {
        Self(value)
    }
}

impl Default for PgReadinessInterval {
    fn default() -> Self {
        Self(Duration::from_secs(5))
    }
}

/// Validated periodic RLS attestation interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgRlsAttestationInterval(Duration);

impl PgRlsAttestationInterval {
    /// Validate a security attestation interval in the supported `10..=300s` range.
    pub fn try_new(value: Duration) -> Result<Self, &'static str> {
        if (Duration::from_secs(10)..=Duration::from_secs(300)).contains(&value) {
            Ok(Self(value))
        } else {
            Err("postgres RLS attestation interval must be between 10s and 300s")
        }
    }

    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn for_test(value: Duration) -> Self {
        Self(value)
    }
}

impl Default for PgRlsAttestationInterval {
    fn default() -> Self {
        Self(Duration::from_secs(60))
    }
}

/// Complete, non-optional schedule for the PostgreSQL runtime monitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgRuntimeMonitorConfig {
    readiness: PgReadinessInterval,
    rls_attestation: PgRlsAttestationInterval,
}

impl PgRuntimeMonitorConfig {
    #[must_use]
    pub const fn new(
        readiness: PgReadinessInterval,
        rls_attestation: PgRlsAttestationInterval,
    ) -> Self {
        Self {
            readiness,
            rls_attestation,
        }
    }

    #[must_use]
    pub const fn readiness(self) -> PgReadinessInterval {
        self.readiness
    }

    #[must_use]
    pub const fn rls_attestation(self) -> PgRlsAttestationInterval {
        self.rls_attestation
    }
}

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
    /// [`crate::PgRuntimeDeps::connect_serving`] 建 + [`crate::PgRuntimeHandle::readiness_handle`] 派发。
    pub fn new() -> Self {
        metrics::gauge!("pg_readiness_up").set(0.0);
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
        metrics::gauge!("pg_readiness_up").set(if r == PoolReadiness::Down { 0.0 } else { 1.0 });
    }
}

/// Read-only runtime RLS attestation state.
///
/// Production construction and mutation remain private to the verified PostgreSQL bundle and its
/// single runtime monitor. Consumers can only take a synchronous snapshot for readyz.
pub struct PgRlsReadiness(AtomicBool);

impl PgRlsReadiness {
    pub(crate) fn verified() -> Self {
        metrics::gauge!("pg_rls_attestation_up").set(1.0);
        Self(AtomicBool::new(true))
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn for_test(ready: bool) -> Self {
        metrics::gauge!("pg_rls_attestation_up").set(if ready { 1.0 } else { 0.0 });
        Self(AtomicBool::new(ready))
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn mark(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
        metrics::gauge!("pg_rls_attestation_up").set(if ready { 1.0 } else { 0.0 });
    }
}

impl Default for PgDbReadiness {
    fn default() -> Self {
        Self::new()
    }
}

// ── pg_readiness_sampling_loop ─────────────────────────────────────────────────

/// DB liveness 二元状态转移时记 warn!/info!（`Down`/`Saturated` 转入 / `Ready` 恢复）；
/// writer/reader 状态对未变或首次双 Ready 则静默。
// reason: tracing::warn!/info! 宏展开后 clippy cognitive_complexity 计数偏高（实际 4 分支）——item-level carve-out。
#[allow(clippy::cognitive_complexity)]
fn log_readiness_transition(
    writer: PoolReadiness,
    reader: PoolReadiness,
    last: Option<(PoolReadiness, PoolReadiness)>,
) -> bool {
    let current = (writer, reader);
    // reason: 以二元状态对去重；即使 worst-of 未变，任一 lane 变化也必须留下诊断证据。
    if last == Some(current) {
        return false;
    }
    let cur = worst_readiness(writer, reader);
    if cur == PoolReadiness::Down {
        tracing::warn!(
            target: "postgres",
            ?writer,
            ?reader,
            "postgres readiness degraded: db unreachable"
        );
    } else if cur == PoolReadiness::Saturated {
        tracing::warn!(
            target: "postgres",
            ?writer,
            ?reader,
            "postgres pool saturated — degraded, still serving"
        );
    } else if last.is_some() {
        // reason: cur == Ready && last.is_some() = 从 Down/Saturated 恢复；last.is_none() = 首次成功，静默。
        tracing::info!(
            target: "postgres",
            ?writer,
            ?reader,
            "postgres readiness recovered"
        );
    }
    true
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
/// [`crate::PgRuntimeMonitorFactory::spawn`]。
pub(crate) async fn pg_readiness_sampling_loop(
    writer_store: Arc<PgStore>,
    reader_store: Arc<PgStore>,
    projection_capture: Option<crate::projection_events::ProjectionCaptureRegistration>,
    period: Duration,
    token: CancellationToken,
    health: Arc<PgDbReadiness>,
) {
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last: Option<(PoolReadiness, PoolReadiness)> = None;
    let mut last_registry: Option<PoolReadiness> = None;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                health.mark(PoolReadiness::Down);
                break;
            },
            _ = ticker.tick() => {
                let (writer, reader) = tokio::join!(
                    writer_store.probe_db_liveness(),
                    reader_store.probe_db_liveness(),
                );
                let registry = match projection_capture.as_ref() {
                    Some(capture) => Some(sample_projection_registry_readiness(
                        writer,
                        &writer_store,
                        capture,
                        last_registry,
                    ).await),
                    None => None,
                };
                let cur = registry.map_or_else(
                    || worst_readiness(writer, reader),
                    |registry| worst_readiness(worst_readiness(writer, reader), registry),
                );
                log_readiness_transition(writer, reader, last);
                if let Some(registry) = registry {
                    if let Some(transition) = projection_registry_transition(registry, last_registry) {
                        log_projection_registry_transition(transition);
                    }
                    last_registry = Some(registry);
                }
                last = Some((writer, reader));
                health.mark(cur);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RlsAttestationLane {
    Writer,
    Reader,
}

impl RlsAttestationLane {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Reader => "reader",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RlsAttestationReason {
    Timeout,
    ProbeError,
    Role,
    Privileges,
    TenantCatalog,
    Guc,
}

impl RlsAttestationReason {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::ProbeError => "probe-error",
            Self::Role => "role",
            Self::Privileges => "privileges",
            Self::TenantCatalog => "tenant-catalog",
            Self::Guc => "guc",
        }
    }
}

#[derive(Debug)]
struct RlsAttestationFailure {
    lane: RlsAttestationLane,
    reason: RlsAttestationReason,
    offender_tables: Option<Vec<String>>,
}

impl RlsAttestationFailure {
    const fn key(&self) -> (RlsAttestationLane, RlsAttestationReason) {
        (self.lane, self.reason)
    }
}

fn classify_rls_error(error: crate::PgError) -> RlsAttestationFailure {
    use crate::PgError;
    let (reason, offender_tables) = match error {
        PgError::RlsCapability(_) | PgError::TenantReadCapability(_) => {
            (RlsAttestationReason::ProbeError, None)
        }
        PgError::RlsUnexpectedServingRole
        | PgError::WriterRoleAttributes
        | PgError::WriterMembership
        | PgError::WriterOwnership
        | PgError::TenantReadUnexpectedRole
        | PgError::TenantReadRoleAttributes
        | PgError::TenantReadMembership
        | PgError::TenantReadOwnership
        | PgError::TenantReadDefaultTransaction
        | PgError::TenantReadSearchPath => (RlsAttestationReason::Role, None),
        PgError::WriterPrivileges { .. }
        | PgError::WriterDefaultPrivileges { .. }
        | PgError::TenantReadDatabasePrivileges
        | PgError::TenantReadRelationPrivileges
        | PgError::TenantReadDefaultPrivileges { .. }
        | PgError::TenantReadSequencePrivileges
        | PgError::TenantReadSchemaPrivileges
        | PgError::TenantReadFunctionPrivileges { .. }
        | PgError::TenantReadFunctionDefinition { .. }
        | PgError::TenantReadLargeObjectMutatorPrivileges
        | PgError::TenantReadLargeObjectPrivileges
        | PgError::TenantReadLargeObjectCompatibility
        | PgError::TenantReadParameterPrivileges => (RlsAttestationReason::Privileges, None),
        PgError::RlsGucRoundtrip => (RlsAttestationReason::Guc, None),
        PgError::RlsNoTenantTables => (RlsAttestationReason::TenantCatalog, None),
        PgError::RlsNotEnforced { offenders } => {
            (RlsAttestationReason::TenantCatalog, Some(offenders))
        }
        _ => (RlsAttestationReason::ProbeError, None),
    };
    RlsAttestationFailure {
        lane: RlsAttestationLane::Writer,
        reason,
        offender_tables,
    }
}

async fn attest_rls_lane(
    lane: RlsAttestationLane,
    store: &PgStore,
    deadline: tokio::time::Instant,
) -> Result<(), RlsAttestationFailure> {
    let probe_deadline = crate::pool::PgCapabilityProbeDeadline::new(deadline);
    let probe = quietly(async {
        match lane {
            RlsAttestationLane::Writer => store.verify_rls_capability_until(probe_deadline).await,
            RlsAttestationLane::Reader => {
                store
                    .verify_tenant_read_capability_until(probe_deadline)
                    .await
            }
        }
    });
    match tokio::time::timeout_at(deadline, probe).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let mut failure = classify_rls_error(error);
            failure.lane = lane;
            Err(failure)
        }
        Err(_) => Err(RlsAttestationFailure {
            lane,
            reason: RlsAttestationReason::Timeout,
            offender_tables: None,
        }),
    }
}

async fn quietly<F: std::future::Future>(future: F) -> F::Output {
    let dispatch = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    tokio::pin!(future);
    std::future::poll_fn(|context| {
        tracing::dispatcher::with_default(&dispatch, || future.as_mut().poll(context))
    })
    .await
}

async fn attest_rls_capabilities(
    writer_store: &PgStore,
    reader_store: &PgStore,
) -> Result<(), RlsAttestationFailure> {
    // This deadline controls Tokio cancellation and the matching PostgreSQL
    // transaction-local timeouts; it is not business time and has no Clock seam.
    #[allow(clippy::disallowed_methods)]
    let deadline = tokio::time::Instant::now() + RLS_ATTESTATION_TIMEOUT;
    let writer = attest_rls_lane(RlsAttestationLane::Writer, writer_store, deadline);
    let reader = attest_rls_lane(RlsAttestationLane::Reader, reader_store, deadline);
    tokio::pin!(writer, reader);
    tokio::select! {
        writer_result = &mut writer => {
            writer_result?;
            reader.await
        }
        reader_result = &mut reader => {
            reader_result?;
            writer.await
        }
    }
}

fn apply_rls_attestation(
    health: &PgRlsReadiness,
    outcome: Result<(), RlsAttestationFailure>,
    last_failure: &mut Option<(RlsAttestationLane, RlsAttestationReason)>,
) {
    match outcome {
        Ok(()) => {
            health.mark(true);
            if last_failure.take().is_some() {
                tracing::info!(target: "postgres", "postgres RLS attestation recovered");
            }
        }
        Err(failure) => {
            health.mark(false);
            let key = failure.key();
            if *last_failure != Some(key) {
                if let Some(offenders) = failure.offender_tables {
                    tracing::error!(
                        target: "postgres",
                        lane = failure.lane.as_label(),
                        reason = failure.reason.as_label(),
                        tables = %offenders.join(","),
                        "postgres RLS attestation degraded"
                    );
                } else {
                    tracing::error!(
                        target: "postgres",
                        lane = failure.lane.as_label(),
                        reason = failure.reason.as_label(),
                        "postgres RLS attestation degraded"
                    );
                }
                *last_failure = Some(key);
            }
        }
    }
}

pub(crate) async fn pg_rls_attestation_loop(
    writer_store: Arc<PgStore>,
    reader_store: Arc<PgStore>,
    period: Duration,
    token: CancellationToken,
    health: Arc<PgRlsReadiness>,
) {
    let mut last_failure = None;
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => {
                health.mark(false);
                break;
            },
            _ = ticker.tick() => {
                let outcome = tokio::select! {
                    biased;
                    () = token.cancelled() => {
                        health.mark(false);
                        break;
                    },
                    outcome = attest_rls_capabilities(&writer_store, &reader_store) => outcome,
                };
                apply_rls_attestation(&health, outcome, &mut last_failure);
            }
        }
    }
}

async fn sample_projection_registry_readiness(
    writer: PoolReadiness,
    writer_store: &PgStore,
    capture: &crate::projection_events::ProjectionCaptureRegistration,
    last_registry: Option<PoolReadiness>,
) -> PoolReadiness {
    if writer != PoolReadiness::Ready {
        // The writer lane already determines the aggregate. Avoid a second acquire while
        // saturated/down and sample the registry on the next Ready tick.
        return retained_projection_registry_readiness(last_registry);
    }
    match tokio::time::timeout(
        PROJECTION_REGISTRY_PROBE_TIMEOUT,
        writer_store.validate_projection_capture_registration(capture),
    )
    .await
    {
        Ok(Ok(())) => PoolReadiness::Ready,
        Ok(Err(_)) | Err(_) => PoolReadiness::Down,
    }
}

fn retained_projection_registry_readiness(last_registry: Option<PoolReadiness>) -> PoolReadiness {
    last_registry.unwrap_or(PoolReadiness::Down)
}

enum ProjectionRegistryTransition {
    Degraded,
    Recovered,
}

fn projection_registry_transition(
    registry: PoolReadiness,
    last: Option<PoolReadiness>,
) -> Option<ProjectionRegistryTransition> {
    match (registry, last) {
        (PoolReadiness::Down, Some(PoolReadiness::Down)) => None,
        (PoolReadiness::Down, _) => Some(ProjectionRegistryTransition::Degraded),
        (PoolReadiness::Ready, Some(PoolReadiness::Down)) => {
            Some(ProjectionRegistryTransition::Recovered)
        }
        _ => None,
    }
}

fn log_projection_registry_transition(transition: ProjectionRegistryTransition) {
    match transition {
        ProjectionRegistryTransition::Degraded => log_projection_registry_degraded(),
        ProjectionRegistryTransition::Recovered => log_projection_registry_recovered(),
    }
}

fn log_projection_registry_degraded() {
    tracing::warn!(
        target: "postgres",
        "postgres readiness degraded: selected projection inputs are absent from the generation"
    );
}

fn log_projection_registry_recovered() {
    tracing::info!(
        target: "postgres",
        "postgres readiness recovered: selected projection inputs belong to the generation"
    );
}

fn worst_readiness(writer: PoolReadiness, reader: PoolReadiness) -> PoolReadiness {
    if writer == PoolReadiness::Down || reader == PoolReadiness::Down {
        PoolReadiness::Down
    } else if writer == PoolReadiness::Saturated || reader == PoolReadiness::Saturated {
        PoolReadiness::Saturated
    } else {
        PoolReadiness::Ready
    }
}

// ── PgRuntimeMonitor ───────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[error("postgres runtime monitor lane exited unexpectedly")]
struct MonitorLaneExited;

fn mark_monitor_down(readiness: &PgDbReadiness, rls_readiness: &PgRlsReadiness) {
    readiness.mark(PoolReadiness::Down);
    rls_readiness.mark(false);
}

fn monitor_join_error(error: tokio::task::JoinError) -> diport::ShutdownError {
    let error = diport::ShutdownError::from_join_error(error);
    tracing::error!(
        target: "postgres",
        reason = error.kind().as_str(),
        "postgres runtime monitor lane terminated abnormally"
    );
    error
}

pub(crate) async fn supervise_runtime_monitor(
    mut readiness_task: JoinHandle<()>,
    mut rls_task: JoinHandle<()>,
    token: CancellationToken,
    readiness: Arc<PgDbReadiness>,
    rls_readiness: Arc<PgRlsReadiness>,
) -> Result<(), diport::ShutdownError> {
    tokio::select! {
        biased;
        () = token.cancelled() => {
            mark_monitor_down(&readiness, &rls_readiness);
            let (readiness_result, rls_result) = tokio::join!(readiness_task, rls_task);
            readiness_result.map_err(monitor_join_error)?;
            rls_result.map_err(monitor_join_error)?;
            Ok(())
        }
        readiness_result = &mut readiness_task => {
            mark_monitor_down(&readiness, &rls_readiness);
            token.cancel();
            rls_task.abort();
            let _ = rls_task.await;
            if let Err(error) = readiness_result {
                return Err(monitor_join_error(error));
            }
            tracing::error!(target: "postgres", lane = "readiness", reason = "task-exited", "postgres runtime monitor lane terminated abnormally");
            Err(diport::ShutdownError::new(MonitorLaneExited))
        }
        rls_result = &mut rls_task => {
            mark_monitor_down(&readiness, &rls_readiness);
            token.cancel();
            readiness_task.abort();
            let _ = readiness_task.await;
            if let Err(error) = rls_result {
                return Err(monitor_join_error(error));
            }
            tracing::error!(target: "postgres", lane = "rls", reason = "task-exited", "postgres runtime monitor lane terminated abnormally");
            Err(diport::ShutdownError::new(MonitorLaneExited))
        }
    }
}

/// DB liveness 采样 adopt 式 worker（impl `diport::ManagedResource`）。
///
/// 持已 spawn 的 typed supervisor + `Arc<PgDbReadiness>` + `CancellationToken`；
/// `shutdown` 两阶段关闭：cancel token（幂等）→ await handle 收敛。
///
/// adopt 式：先在具体类型处 `tokio::spawn(pg_readiness_sampling_loop(...))` 再调
/// [`PgRuntimeMonitor::adopt`]，与 `relay.rs` 中 `RelayWorker::adopt` 同范式。
///
/// `PgStore` 在 `adapters/postgres` 下 impl `ManagedResource` 无需 `#[allow]`——
/// `PgRuntimeMonitor` 同理：dylint `rss_diport_impl_allowlist` 按 manifest
/// 父目录 (`adapters/`) 自动放行。
pub struct PgRuntimeMonitor {
    inner: tokio::sync::Mutex<Option<diport::OwnedTask<Result<(), diport::ShutdownError>>>>,
    readiness: Arc<PgDbReadiness>,
    rls_readiness: Arc<PgRlsReadiness>,
    token: CancellationToken,
}

impl PgRuntimeMonitor {
    /// 先 `tokio::spawn(pg_readiness_sampling_loop(具体 store, ...))` 再 adopt。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：仅由
    /// [`crate::PgRuntimeMonitorFactory::spawn`] 收口调用。
    pub(crate) fn adopt(
        handle: JoinHandle<Result<(), diport::ShutdownError>>,
        readiness: Arc<PgDbReadiness>,
        rls_readiness: Arc<PgRlsReadiness>,
        token: CancellationToken,
    ) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            readiness,
            rls_readiness,
            token,
        }
    }

    /// 返回 liveness 状态句柄。
    ///
    /// 当外部已 adopt `PgRuntimeMonitor` 且需从 monitor 反取 `Arc<PgDbReadiness>` 时用；
    /// 组合根直接持有 `Arc<PgDbReadiness>` 时无需调此方法。
    pub fn readiness_handle(&self) -> Arc<PgDbReadiness> {
        self.readiness.clone()
    }
}

impl diport::ManagedResource for PgRuntimeMonitor {
    fn name(&self) -> &str {
        MONITOR_WORKER_NAME
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.readiness.mark(PoolReadiness::Down);
        self.rls_readiness.mark(false);
        // 防御性 cancel（幂等；生产中 ShutdownStack 已先 cancel，此处兜底防 test/误用 hang）。
        self.token.cancel();
        // await loop 收敛——保证 worker 在 pool 之前停（LIFO 由组合根注册顺序保证）。
        if let Some(h) = self.inner.lock().await.take() {
            h.join()
                .await
                .map_err(diport::ShutdownError::from_join_error)??;
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

    use super::{PgDbReadiness, PgRlsReadiness, PgRuntimeMonitor, pg_readiness_sampling_loop};

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

    #[test]
    fn dual_pool_readiness_uses_worst_state() {
        assert_eq!(
            super::worst_readiness(PoolReadiness::Ready, PoolReadiness::Down),
            PoolReadiness::Down
        );
        assert_eq!(
            super::worst_readiness(PoolReadiness::Saturated, PoolReadiness::Ready),
            PoolReadiness::Saturated
        );
        assert_eq!(
            super::worst_readiness(PoolReadiness::Ready, PoolReadiness::Ready),
            PoolReadiness::Ready
        );
    }

    #[test]
    fn readiness_transition_deduplicates_the_lane_pair_not_only_worst_state() {
        let saturated_writer = (PoolReadiness::Saturated, PoolReadiness::Ready);
        assert!(
            super::log_readiness_transition(saturated_writer.0, saturated_writer.1, None,),
            "first degraded pair must be logged"
        );
        assert!(
            !super::log_readiness_transition(
                saturated_writer.0,
                saturated_writer.1,
                Some(saturated_writer),
            ),
            "an unchanged writer/reader pair must be deduplicated"
        );

        let both_saturated = (PoolReadiness::Saturated, PoolReadiness::Saturated);
        assert_eq!(
            super::worst_readiness(saturated_writer.0, saturated_writer.1),
            super::worst_readiness(both_saturated.0, both_saturated.1),
            "the aggregate intentionally remains saturated"
        );
        assert!(
            super::log_readiness_transition(
                both_saturated.0,
                both_saturated.1,
                Some(saturated_writer),
            ),
            "a reader transition must be logged even when the worst state is unchanged"
        );
    }

    #[test]
    fn skipped_projection_probe_preserves_last_known_state_fail_closed() {
        assert_eq!(
            super::retained_projection_registry_readiness(None),
            PoolReadiness::Down,
            "an unprobed registry has no known-good state"
        );
        assert_eq!(
            super::retained_projection_registry_readiness(Some(PoolReadiness::Down)),
            PoolReadiness::Down,
            "a skipped probe must not erase a known registry failure"
        );
        assert_eq!(
            super::retained_projection_registry_readiness(Some(PoolReadiness::Ready)),
            PoolReadiness::Ready,
            "a skipped probe preserves the last successful sample"
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
            Arc::clone(&store),
            None,
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
            Arc::clone(&store),
            None,
            Duration::from_secs(3600), // 长 period，不会自然 tick（测取消路径）
            token.clone(),
            Arc::clone(&health),
        ));

        token.cancel();
        // biased cancel 优先——loop 应立即 break，task 正常完成。
        assert!(handle.await.is_ok(), "cancel 后 loop 应退出");
        assert_eq!(health.snapshot(), PoolReadiness::Down);
    }

    // ── PgRuntimeMonitor shutdown ────────────────────────────────────────────

    #[tokio::test]
    async fn monitor_shutdown_cancels_and_joins() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();

        let task_store = Arc::clone(&store);
        let task_health = Arc::clone(&health);
        let task_token = token.clone();
        let handle = tokio::spawn(async move {
            pg_readiness_sampling_loop(
                Arc::clone(&task_store),
                task_store,
                None,
                Duration::from_secs(3600),
                task_token,
                task_health,
            )
            .await;
            Ok(())
        });

        let rls = Arc::new(PgRlsReadiness::for_test(true));
        let monitor = PgRuntimeMonitor::adopt(handle, Arc::clone(&health), Arc::clone(&rls), token);
        assert!(
            monitor.shutdown().await.is_ok(),
            "PgRuntimeMonitor::shutdown 应返回 Ok"
        );
        assert_eq!(health.snapshot(), PoolReadiness::Down);
        assert!(!rls.is_ready());
    }

    #[tokio::test]
    async fn readiness_handle_returns_same_arc() {
        let store = Arc::new(make_closed_store().await);
        let health = Arc::new(PgDbReadiness::new());
        let token = CancellationToken::new();
        // 立即取消——loop biased 分支首先触发，task 不等 tick 就退出。
        token.cancel();

        let task_store = Arc::clone(&store);
        let task_health = Arc::clone(&health);
        let task_token = token.clone();
        let handle = tokio::spawn(async move {
            pg_readiness_sampling_loop(
                Arc::clone(&task_store),
                task_store,
                None,
                Duration::from_secs(3600),
                task_token,
                task_health,
            )
            .await;
            Ok(())
        });

        let monitor = PgRuntimeMonitor::adopt(
            handle,
            Arc::clone(&health),
            Arc::new(PgRlsReadiness::for_test(true)),
            token,
        );
        let returned = monitor.readiness_handle();
        assert!(
            Arc::ptr_eq(&health, &returned),
            "readiness_handle 应返回同一 Arc<PgDbReadiness>"
        );
        assert!(monitor.shutdown().await.is_ok());
    }

    #[test]
    fn monitor_name_is_stable() {
        // INVARIANT: MONITOR-NAME-01 { level = "Medium", exec = "manual/opt-in", source = "code" }— name 常量用于 ShutdownStack 日志，不可随意改变。
        assert_eq!(super::MONITOR_WORKER_NAME, "pg-runtime-monitor");
    }

    #[test]
    fn typed_intervals_enforce_distinct_ranges() {
        assert!(super::PgReadinessInterval::try_new(Duration::from_secs(1)).is_ok());
        assert!(super::PgReadinessInterval::try_new(Duration::from_secs(301)).is_err());
        assert!(super::PgRlsAttestationInterval::try_new(Duration::from_secs(10)).is_ok());
        assert!(super::PgRlsAttestationInterval::try_new(Duration::from_secs(9)).is_err());
    }

    #[test]
    fn rls_attestation_fails_closed_and_recovers_atomically() {
        let health = PgRlsReadiness::for_test(true);
        let mut last = None;
        let failure = super::RlsAttestationFailure {
            lane: super::RlsAttestationLane::Reader,
            reason: super::RlsAttestationReason::Privileges,
            offender_tables: None,
        };
        super::apply_rls_attestation(&health, Err(failure), &mut last);
        assert!(!health.is_ready());
        let key = (
            super::RlsAttestationLane::Reader,
            super::RlsAttestationReason::Privileges,
        );
        assert_eq!(last, Some(key));
        super::apply_rls_attestation(
            &health,
            Err(super::RlsAttestationFailure {
                lane: key.0,
                reason: key.1,
                offender_tables: None,
            }),
            &mut last,
        );
        assert_eq!(last, Some(key));
        super::apply_rls_attestation(&health, Ok(()), &mut last);
        assert!(health.is_ready());
        assert_eq!(last, None);
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn monitor_supervisor_fails_closed_when_a_lane_panics() {
        let readiness = Arc::new(PgDbReadiness::new());
        readiness.mark(PoolReadiness::Ready);
        let rls = Arc::new(PgRlsReadiness::for_test(true));
        let token = CancellationToken::new();
        let readiness_task = tokio::spawn(async { panic!("synthetic monitor lane panic") });
        let rls_task = tokio::spawn(std::future::pending());

        let result = super::supervise_runtime_monitor(
            readiness_task,
            rls_task,
            token,
            Arc::clone(&readiness),
            Arc::clone(&rls),
        )
        .await;

        assert!(matches!(
            result,
            Err(ref error) if error.kind() == diport::ShutdownErrorKind::TaskPanicked
        ));
        assert_eq!(readiness.snapshot(), PoolReadiness::Down);
        assert!(!rls.is_ready());
    }

    #[test]
    fn readiness_and_rls_gauges_are_unlabelled_and_overwrite_current_state() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let db = PgDbReadiness::new();
            db.mark(PoolReadiness::Ready);
            db.mark(PoolReadiness::Saturated);
            let rls = PgRlsReadiness::for_test(false);
            rls.mark(true);
            assert_eq!(db.snapshot(), PoolReadiness::Saturated);
            assert!(rls.is_ready());
        });
        let rendered = handle.render();
        let data_lines: Vec<_> = rendered
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        assert_eq!(
            data_lines
                .iter()
                .filter(|line| line.starts_with("pg_readiness_up "))
                .count(),
            1,
            "{rendered}"
        );
        assert!(rendered.contains("pg_readiness_up 1"), "{rendered}");
        assert_eq!(
            data_lines
                .iter()
                .filter(|line| line.starts_with("pg_rls_attestation_up "))
                .count(),
            1,
            "{rendered}"
        );
        assert!(rendered.contains("pg_rls_attestation_up 1"), "{rendered}");
        assert!(
            !rendered.contains('{'),
            "gauges must have no labels: {rendered}"
        );
    }
}
