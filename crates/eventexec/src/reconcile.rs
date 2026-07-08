//! reconcile 控制环 Loop harness（L4）—— desired↔actual 收敛运行期（对标 kube-rs controller-runtime）。
//!
//! 引擎策略 trait `consistency::Reconciler` 是函数式接缝（P2 冻结）；本模块是其**运行期 harness**：
//! [`Builder`] 唯一公开构造入口（必填 sealed [`Tenancy`] + [`Trigger`]）、leader-gated dispatch、
//! per-entity 指数退避、panic→transient。决策 1（plan.md）：harness 落 `eventexec` 复用结构化并发
//! （`tokio::select!` + `CancellationToken`）+ leader/lease 接入点，避免第四个 runtime home。
//!
//! ref: kube-rs kube-runtime/src/controller/mod.rs@main（reconcile 调度 + `Action::requeue` 退避）；
//!      kubernetes/client-go tools/leaderelection（leader-gated dispatch + lease 续租）。
//!
//! ## Enforced invariants
//!
//! - **RECONCILE-TENANCY-REQ-01**（Hard，类型系统）：[`Builder::new`] 第二、三参 [`Tenancy`] / [`Trigger`]
//!   是必填位置参——漏传即编译错（E0061），非运行期校验。回归见 `tests/ui/reconcile_missing_{tenancy,trigger}_fail.rs`
//!   （trybuild compile_fail）。`Tenancy` 仿 `Clock` 位置参约定：reconciler 在 tenantless system 身份下跑，
//!   须显式声明命名空间（reconcile.md §Builder 强制）。
//! - **panic→transient**（reconcile.md §Reconciler 实现要点）：捕获的 `reconcile()` panic（`catch_unwind`）
//!   映射 transient 退避，不挂环。
//! - fencing 正确性（RECONCILE-FENCE-MONO-01）落 `diport::FencedWriter` 单调 CAS（域 reconciler 写路径消费），
//!   **不在 harness**：harness 仅经 `Context::for_harness(epoch)` 把当前任期 epoch 注入 reconciler。

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use consistency::outbox::{Entry, OutboxPayload, Topic};
use consistency::{
    Context, ConvergeAction, EntityId, Outcome, ReconcileError, ReconcileResultLabel, Reconciler,
    Request,
};
use diport::{EnvelopeSubjectId, LeaderElector, OutboxActor, OutboxEnvelopeParts, RedactedSource};
use futures::FutureExt;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::WorkerHealth;
use crate::command::{CommandEmitError, DispatchId};

/// readyz probe 名（无 `_ready` 后缀，对齐 relay probe 约定）。
pub const RECONCILE_PROBE: &str = "reconcile";

/// lease TTL：holder 须在此时长内续租，超时未续 ⇒ 他副本可接管（epoch 递增）。
const LEASE_TTL: Duration = Duration::from_secs(15);
/// 续租轮询间隔（< `LEASE_TTL`，留续租裕度）。
const RENEW_INTERVAL: Duration = Duration::from_secs(5);

// ── Durable scheduler API（PG-backed scheduler + command outbox seam）────────

/// Durable reconcile scheduler storage failure.
///
/// Display is intentionally constant; provider errors stay redacted behind [`RedactedSource`].
#[derive(Debug, thiserror::Error)]
#[error("reconcile schedule store operation failed")]
pub struct ReconcileScheduleError {
    #[source]
    source: RedactedSource,
}

impl ReconcileScheduleError {
    /// Wrap a provider/storage error without exposing its Display text to callers.
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// Durable scheduler configuration error.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReconcileConfigError {
    /// Lease TTL must be at least one second because durable providers persist it at second granularity.
    #[error("reconcile lease ttl must be at least one second")]
    LeaseTtlTooShort,
    /// Lease TTL must not contain subsecond precision because durable providers persist it at second granularity.
    #[error("reconcile lease ttl must be whole seconds")]
    LeaseTtlSubsecond,
    /// Lease TTL exceeded the durable provider seconds range.
    #[error("reconcile lease ttl is too large")]
    LeaseTtlTooLarge,
    /// Claim batch size must be positive.
    #[error("reconcile claim batch size must be positive")]
    BatchSizeZero,
}

/// Target-local lease CAS result for durable reconcile writes.
#[must_use = "lease CAS outcomes must be matched so Lost is handled explicitly"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleLeaseOutcome {
    /// The target lease token + epoch still matched.
    Held,
    /// The target lease was reclaimed or expired before the write.
    Lost,
}

/// Attempt append result under the claimed target lease.
#[must_use = "attempt append outcomes must be matched so Lost is handled explicitly"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleAttemptOutcome {
    /// Attempt row was appended and can be reconciled.
    Started(ReconcileAttempt),
    /// The target lease was no longer held before the attempt could start.
    Lost,
}

/// Trigger reason for an append-only reconcile attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptTrigger {
    /// Periodic due-target scheduler tick.
    Resync,
    /// Targeted event dispatch.
    Targeted,
    /// Requeue requested by prior outcome.
    Requeue,
    /// Expired lease was reclaimed.
    LeaseReclaim,
}

impl AttemptTrigger {
    /// Stable DB/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Resync => "resync",
            Self::Targeted => "targeted",
            Self::Requeue => "requeue",
            Self::LeaseReclaim => "lease_reclaim",
        }
    }
}

/// Error classification persisted with an attempt result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptErrorKind {
    /// Retryable failure.
    Transient,
    /// Non-retryable failure.
    Permanent,
    /// Invariant violation.
    Invariant,
}

impl AttemptErrorKind {
    /// Stable DB/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
        }
    }

    fn from_error(error: &ReconcileError) -> Self {
        if error.is_transient() {
            Self::Transient
        } else if error.is_permanent() {
            Self::Permanent
        } else {
            Self::Invariant
        }
    }
}

/// Durable target claimed by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedTarget {
    tenant: vocab::TenantId,
    target_id: String,
    lease_token: String,
    epoch: u64,
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
    trigger: AttemptTrigger,
}

impl ClaimedTarget {
    /// Build a claimed target from a provider claim row.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: vocab::TenantId,
        target_id: impl Into<String>,
        lease_token: impl Into<String>,
        epoch: u64,
        reconciler_id: impl Into<String>,
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        trigger: AttemptTrigger,
    ) -> Self {
        Self {
            tenant,
            target_id: target_id.into(),
            lease_token: lease_token.into(),
            epoch,
            reconciler_id: reconciler_id.into(),
            resource_kind: resource_kind.into(),
            resource_id: resource_id.into(),
            trigger,
        }
    }

    /// Target tenant.
    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    /// Target id as provider UUID text.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Current target lease token.
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }

    /// Target-local lease epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Reconciler namespace.
    pub fn reconciler_id(&self) -> &str {
        &self.reconciler_id
    }

    /// Resource kind within the reconciler.
    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    /// Opaque resource id.
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Attempt trigger associated with the claim.
    pub fn trigger(&self) -> AttemptTrigger {
        self.trigger
    }
}

/// Append-only attempt identity tied to the target lease that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileAttempt {
    attempt_id: String,
    target: ClaimedTarget,
}

impl ReconcileAttempt {
    /// Build an attempt handle from a store-generated id and its claimed target.
    pub fn new(attempt_id: impl Into<String>, target: ClaimedTarget) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            target,
        }
    }

    /// Attempt id as provider UUID text.
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Claimed target protected by this attempt.
    pub fn target(&self) -> &ClaimedTarget {
        &self.target
    }
}

/// Terminal attempt result persisted separately from action ledger rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptResult {
    result: ReconcileResultLabel,
    error_kind: Option<AttemptErrorKind>,
    requeue_after: Option<Duration>,
    next_run_after: Duration,
}

impl AttemptResult {
    /// Successful outcome result.
    pub fn from_outcome(outcome: &Outcome, default_next_run_after: Duration) -> Self {
        let requeue_after = outcome.requeue_interval();
        Self {
            result: ReconcileResultLabel::from_outcome(outcome),
            error_kind: None,
            requeue_after,
            next_run_after: requeue_after.unwrap_or(default_next_run_after),
        }
    }

    /// Error result.
    pub fn from_error(error: &ReconcileError, next_run_after: Duration) -> Self {
        Self {
            result: ReconcileResultLabel::from_error(error),
            error_kind: Some(AttemptErrorKind::from_error(error)),
            requeue_after: None,
            next_run_after,
        }
    }

    /// Panic is mapped to transient by the reconcile harness contract.
    pub fn from_panic(next_run_after: Duration) -> Self {
        Self {
            result: ReconcileResultLabel::from_panic(),
            error_kind: Some(AttemptErrorKind::Transient),
            requeue_after: None,
            next_run_after,
        }
    }

    /// Stable result label.
    pub fn result(&self) -> ReconcileResultLabel {
        self.result
    }

    /// Optional error classification.
    pub fn error_kind(&self) -> Option<AttemptErrorKind> {
        self.error_kind
    }

    /// Optional successful requeue delay.
    pub fn requeue_after(&self) -> Option<Duration> {
        self.requeue_after
    }

    /// Delay before this target is due again.
    pub fn next_run_after(&self) -> Duration {
        self.next_run_after
    }
}

/// Stable dispatch key required for reconcile command outbox writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableDispatchKey(String);

impl StableDispatchKey {
    /// Parse a reviewed stable dispatch key.
    pub fn parse(raw: impl Into<String>) -> Result<Self, CommandEmitError> {
        let raw = raw.into();
        DispatchId::from_idempotency_key(&raw)?;
        Ok(Self(raw))
    }

    /// Borrow the stable key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reviewed command entry that can only be built with a stable dispatch key.
///
/// This is the transactional counterpart of `eventexec::command::emit_async`: it produces the
/// same command outbox primitives but does not call an emitter, so a provider can append action
/// ledger + outbox row in one tenant transaction.
pub struct ReviewedCommand {
    entry: Entry,
    envelope: OutboxEnvelopeParts,
}

impl ReviewedCommand {
    /// Build a reviewed command outbox write.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dispatch_key: StableDispatchKey,
        topic: &str,
        contract: vocab::ContractBinding,
        tenant: vocab::TenantId,
        payload: Vec<u8>,
        subject_id: EnvelopeSubjectId,
        actor: OutboxActor,
    ) -> Result<Self, CommandEmitError> {
        let parsed_topic = Topic::parse(topic).map_err(|_| CommandEmitError::Topic)?;
        let scoped_key = scoped_dispatch_key(tenant, &parsed_topic, &dispatch_key);
        let dispatch_id = DispatchId::from_idempotency_key(&scoped_key)?;
        let entry = Entry::new(
            parsed_topic,
            dispatch_id.into_idem_key(),
            OutboxPayload::from_reviewed_event_bytes(payload),
        );
        let envelope = OutboxEnvelopeParts::new(contract, tenant, subject_id, actor);
        Ok(Self { entry, envelope })
    }

    /// Consume into provider outbox primitives.
    pub fn into_parts(self) -> (Entry, OutboxEnvelopeParts) {
        (self.entry, self.envelope)
    }
}

fn scoped_dispatch_key(
    tenant: vocab::TenantId,
    topic: &Topic,
    dispatch_key: &StableDispatchKey,
) -> String {
    let tenant = tenant.to_string();
    let topic = topic.as_str();
    let key = dispatch_key.as_str();
    format!(
        "reconcile:v1:t{}:{tenant}:p{}:{topic}:k{}:{key}",
        tenant.len(),
        topic.len(),
        key.len()
    )
}

/// Provider-agnostic durable reconcile store.
#[allow(async_fn_in_trait)]
pub trait ReconcileScheduleStore {
    /// Claim due active targets for one tenant and reconciler.
    async fn claim_due_targets(
        &self,
        tenant: vocab::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: u32,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError>;

    /// Append one attempt under the current target lease.
    async fn append_attempt(
        &self,
        target: &ClaimedTarget,
        holder_id: &str,
    ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError>;

    /// Record a terminal attempt result and update target scheduling under lease CAS.
    async fn record_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: AttemptResult,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError>;

    /// Atomically append a converge action and enqueue the reviewed command outbox row.
    async fn record_action_and_enqueue_command(
        &self,
        attempt: &ReconcileAttempt,
        action: ConvergeAction,
        command: ReviewedCommand,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError>;

    /// Extend a held target lease.
    async fn extend_lease(
        &self,
        target: &ClaimedTarget,
        lease_ttl: Duration,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError>;

    /// Release a held target lease.
    async fn release_lease(
        &self,
        target: &ClaimedTarget,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError>;

    /// Disable a target so future due scans skip it.
    async fn pause_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError>;

    /// Re-enable a target and make it immediately due.
    async fn resume_target(
        &self,
        tenant: vocab::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError>;
}

/// Attempt-scoped recorder handed to durable reconcilers.
pub struct AttemptScope<'a, S: ReconcileScheduleStore> {
    store: &'a S,
    attempt: ReconcileAttempt,
}

impl<'a, S: ReconcileScheduleStore> AttemptScope<'a, S> {
    fn new(store: &'a S, attempt: ReconcileAttempt) -> Self {
        Self { store, attempt }
    }

    /// Current attempt id for correlation.
    pub fn attempt_id(&self) -> &str {
        self.attempt.attempt_id()
    }

    /// Record a converge action and enqueue its command in the same provider transaction.
    pub async fn record_action_and_enqueue_command(
        &self,
        action: ConvergeAction,
        command: ReviewedCommand,
    ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
        self.store
            .record_action_and_enqueue_command(&self.attempt, action, command)
            .await
    }
}

/// Durable reconcile strategy.
#[allow(async_fn_in_trait)]
pub trait DurableReconciler<S: ReconcileScheduleStore> {
    /// Reconcile one claimed target.
    async fn reconcile(
        &self,
        ctx: &Context,
        target: &ClaimedTarget,
        attempt: &AttemptScope<'_, S>,
    ) -> Result<Outcome, ReconcileError>;
}

/// Durable scheduler builder.
pub struct ReconcileSchedulerBuilder<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    store: S,
    reconciler: R,
    tenant: vocab::TenantId,
    reconciler_id: String,
    holder_id: String,
    trigger: Trigger,
    backoff: BackoffPolicy,
    lease_ttl: Duration,
    batch_size: u32,
}

impl<S, R> ReconcileSchedulerBuilder<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    /// New durable scheduler builder. Store, tenancy and trigger are required at construction.
    pub fn new(
        store: S,
        reconciler: R,
        tenant: vocab::TenantId,
        reconciler_id: impl Into<String>,
        holder_id: impl Into<String>,
        _tenancy: Tenancy,
        trigger: Trigger,
    ) -> Self {
        Self {
            store,
            reconciler,
            tenant,
            reconciler_id: reconciler_id.into(),
            holder_id: holder_id.into(),
            trigger,
            backoff: BackoffPolicy::default(),
            lease_ttl: LEASE_TTL,
            batch_size: 16,
        }
    }

    /// Override backoff policy.
    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    /// Override target lease TTL.
    pub fn with_lease_ttl(mut self, lease_ttl: Duration) -> Result<Self, ReconcileConfigError> {
        validate_lease_ttl(lease_ttl)?;
        self.lease_ttl = lease_ttl;
        Ok(self)
    }

    /// Override due claim batch size.
    pub fn with_batch_size(mut self, batch_size: u32) -> Result<Self, ReconcileConfigError> {
        if batch_size == 0 {
            return Err(ReconcileConfigError::BatchSizeZero);
        }
        self.batch_size = batch_size;
        Ok(self)
    }

    /// Build a worker and its control handle.
    pub fn build(self) -> ReconcileWorker<S, R> {
        let (paused_tx, paused_rx) = watch::channel(false);
        ReconcileWorker {
            store: self.store,
            reconciler: self.reconciler,
            tenant: self.tenant,
            reconciler_id: self.reconciler_id,
            holder_id: self.holder_id,
            trigger: self.trigger,
            backoff: self.backoff,
            lease_ttl: self.lease_ttl,
            batch_size: self.batch_size,
            health: Arc::new(WorkerHealth::healthy()),
            paused_tx,
            paused_rx,
        }
    }
}

/// Pause/resume handle for a durable reconcile worker.
#[derive(Clone)]
pub struct ReconcileWorkerControl {
    paused: watch::Sender<bool>,
}

impl ReconcileWorkerControl {
    /// Stop new claims after the current in-flight attempt drains.
    pub fn pause(&self) {
        let _ = self.paused.send(true);
    }

    /// Resume due target claims.
    pub fn resume(&self) {
        let _ = self.paused.send(false);
    }

    /// Current local pause flag.
    pub fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }
}

/// Durable reconcile worker.
pub struct ReconcileWorker<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    store: S,
    reconciler: R,
    tenant: vocab::TenantId,
    reconciler_id: String,
    holder_id: String,
    trigger: Trigger,
    backoff: BackoffPolicy,
    lease_ttl: Duration,
    batch_size: u32,
    health: Arc<WorkerHealth>,
    paused_tx: watch::Sender<bool>,
    paused_rx: watch::Receiver<bool>,
}

enum WorkerLoopEvent {
    Cancelled,
    PauseChanged,
    Tick,
}

type DurableReconcileOutcome =
    Result<Result<Outcome, ReconcileError>, Box<dyn std::any::Any + Send>>;

enum TargetRun {
    Finished(DurableReconcileOutcome),
    Cancelled,
    LeaseLost,
}

impl<S, R> ReconcileWorker<S, R>
where
    S: ReconcileScheduleStore + Send + Sync,
    R: DurableReconciler<S> + Send + Sync,
{
    /// Control handle for pausing/resuming new target claims.
    pub fn control(&self) -> ReconcileWorkerControl {
        ReconcileWorkerControl {
            paused: self.paused_tx.clone(),
        }
    }

    /// Health handle for readyz.
    pub fn health(&self) -> Arc<WorkerHealth> {
        Arc::clone(&self.health)
    }

    /// Run the durable scheduler loop until cancellation.
    pub async fn run(mut self, token: CancellationToken) {
        let _stopped = self.health.stopped_on_exit();
        let period = self.trigger.period();
        self.log_durable_start(period);
        self.run_worker_loop(period, &token).await;
        tracing::info!(
            tenant_id = %self.tenant,
            reconciler_id = self.reconciler_id,
            holder_id = self.holder_id,
            "reconcile: durable scheduler stopped"
        );
    }

    fn log_durable_start(&self, period: Duration) {
        tracing::info!(
            tenant_id = %self.tenant,
            reconciler_id = self.reconciler_id,
            ?period,
            "reconcile: durable scheduler starting"
        );
    }

    async fn run_worker_loop(&mut self, period: Duration, token: &CancellationToken) {
        let mut ticker = tokio::time::interval(period);
        let mut attempts: HashMap<String, u32> = HashMap::new();
        while self.wait_for_active_tick(&mut ticker, token).await {
            self.run_due_batch(token, &mut attempts).await;
        }
    }

    async fn wait_for_active_tick(
        &mut self,
        ticker: &mut tokio::time::Interval,
        token: &CancellationToken,
    ) -> bool {
        loop {
            match next_worker_event(&mut self.paused_rx, ticker, token).await {
                WorkerLoopEvent::Cancelled => return false,
                WorkerLoopEvent::PauseChanged => continue,
                WorkerLoopEvent::Tick if *self.paused_rx.borrow() => {
                    self.health.mark_healthy();
                }
                WorkerLoopEvent::Tick => return true,
            }
        }
    }

    async fn run_due_batch(&self, token: &CancellationToken, attempts: &mut HashMap<String, u32>) {
        match self
            .store
            .claim_due_targets(
                self.tenant,
                &self.reconciler_id,
                &self.holder_id,
                self.batch_size,
                self.lease_ttl,
            )
            .await
        {
            Ok(targets) => self.run_claimed_targets(targets, token, attempts).await,
            Err(ref e) => {
                self.health.mark_degraded();
                tracing::warn!(
                    tenant_id = %self.tenant,
                    reconciler_id = self.reconciler_id,
                    holder_id = self.holder_id,
                    batch_size = self.batch_size,
                    error = %e,
                    "reconcile: claim due targets failed"
                );
            }
        }
    }

    async fn run_claimed_targets(
        &self,
        targets: Vec<ClaimedTarget>,
        token: &CancellationToken,
        attempts: &mut HashMap<String, u32>,
    ) {
        self.health.mark_healthy();
        let mut targets = targets.into_iter();
        while let Some(target) = targets.next() {
            if self.should_stop_claimed_batch(token) {
                self.release_target_and_remaining(target, targets).await;
                break;
            }
            self.run_target(target, token, attempts).await;
        }
    }

    fn should_stop_claimed_batch(&self, token: &CancellationToken) -> bool {
        token.is_cancelled() || *self.paused_rx.borrow()
    }

    async fn release_target_and_remaining(
        &self,
        target: ClaimedTarget,
        remaining: impl Iterator<Item = ClaimedTarget>,
    ) {
        self.release_lease_best_effort(&target, "batch_stopped")
            .await;
        for target in remaining {
            self.release_lease_best_effort(&target, "batch_stopped")
                .await;
        }
    }

    async fn run_target(
        &self,
        target: ClaimedTarget,
        token: &CancellationToken,
        attempts: &mut HashMap<String, u32>,
    ) {
        let Some(attempt) = self.append_attempt_or_release(&target).await else {
            return;
        };
        match self
            .run_reconciler_with_lease(&target, &attempt, token)
            .await
        {
            TargetRun::Finished(result) => self.finish_attempt(attempt, result, attempts).await,
            TargetRun::Cancelled => {
                self.release_lease_best_effort(&target, "attempt_cancelled")
                    .await;
            }
            TargetRun::LeaseLost => {
                self.health.mark_degraded();
                tracing::warn!(
                    tenant_id = %target.tenant(),
                    reconciler_id = target.reconciler_id(),
                    resource_kind = target.resource_kind(),
                    resource_id = target.resource_id(),
                    target_id = target.target_id(),
                    epoch = target.epoch(),
                    "reconcile: target lease lost"
                );
            }
        }
    }

    async fn append_attempt_or_release(&self, target: &ClaimedTarget) -> Option<ReconcileAttempt> {
        match self.store.append_attempt(target, &self.holder_id).await {
            Ok(ScheduleAttemptOutcome::Started(attempt)) => Some(attempt),
            Ok(ScheduleAttemptOutcome::Lost) => {
                self.observe_attempt_append_lost(target);
                None
            }
            Err(ref e) => {
                self.observe_attempt_append_error(target, e);
                self.release_lease_best_effort(target, "append_attempt_failed")
                    .await;
                None
            }
        }
    }

    fn observe_attempt_append_lost(&self, target: &ClaimedTarget) {
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %target.tenant(),
            reconciler_id = self.reconciler_id,
            holder_id = self.holder_id,
            target_id = target.target_id(),
            resource_kind = target.resource_kind(),
            resource_id = target.resource_id(),
            trigger = target.trigger().as_label(),
            "reconcile: target lease lost before attempt append"
        );
    }

    fn observe_attempt_append_error(&self, target: &ClaimedTarget, error: &ReconcileScheduleError) {
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %target.tenant(),
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            resource_id = target.resource_id(),
            target_id = target.target_id(),
            epoch = target.epoch(),
            trigger = target.trigger().as_label(),
            error = %error,
            "reconcile: append attempt failed"
        );
    }

    async fn run_reconciler_with_lease(
        &self,
        target: &ClaimedTarget,
        attempt: &ReconcileAttempt,
        token: &CancellationToken,
    ) -> TargetRun {
        let ctx = Context::for_harness(Some(vocab::Epoch::new(target.epoch())));
        let scope = AttemptScope::new(&self.store, attempt.clone());
        tokio::select! {
            biased;
            () = token.cancelled() => {
                TargetRun::Cancelled
            }
            () = self.renew_until_lost(target, token) => {
                TargetRun::LeaseLost
            }
            result = AssertUnwindSafe(self.reconciler.reconcile(&ctx, target, &scope)).catch_unwind() => {
                TargetRun::Finished(result)
            }
        }
    }

    async fn finish_attempt(
        &self,
        attempt: ReconcileAttempt,
        result: DurableReconcileOutcome,
        attempts: &mut HashMap<String, u32>,
    ) {
        let key = attempt.target().target_id().to_string();
        let attempt_result = self.classify_attempt_result(&key, result, attempts);
        emit_reconcile_result(attempt_result.result());
        self.persist_attempt_result(&attempt, attempt_result).await;
        self.release_lease_best_effort(attempt.target(), "attempt_finished")
            .await;
    }

    fn classify_attempt_result(
        &self,
        key: &str,
        result: DurableReconcileOutcome,
        attempts: &mut HashMap<String, u32>,
    ) -> AttemptResult {
        match result {
            Ok(Ok(outcome)) => self.settled_attempt_result(key, &outcome, attempts),
            Ok(Err(ref error)) => self.error_attempt_result(key, error, attempts),
            Err(_panic) => self.panic_attempt_result(key, attempts),
        }
    }

    fn settled_attempt_result(
        &self,
        key: &str,
        outcome: &Outcome,
        attempts: &mut HashMap<String, u32>,
    ) -> AttemptResult {
        attempts.remove(key);
        self.health.mark_healthy();
        AttemptResult::from_outcome(outcome, self.trigger.period())
    }

    fn error_attempt_result(
        &self,
        key: &str,
        error: &ReconcileError,
        attempts: &mut HashMap<String, u32>,
    ) -> AttemptResult {
        self.health.mark_degraded();
        if error.is_transient() {
            let delay = self.backoff.delay_for(bump_target_attempts(attempts, key));
            return AttemptResult::from_error(error, delay);
        }
        attempts.remove(key);
        AttemptResult::from_error(error, self.trigger.period())
    }

    fn panic_attempt_result(
        &self,
        key: &str,
        attempts: &mut HashMap<String, u32>,
    ) -> AttemptResult {
        self.health.mark_degraded();
        let delay = self.backoff.delay_for(bump_target_attempts(attempts, key));
        AttemptResult::from_panic(delay)
    }

    async fn persist_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        attempt_result: AttemptResult,
    ) {
        match self
            .store
            .record_attempt_result(attempt, attempt_result)
            .await
        {
            Ok(outcome) => self.observe_attempt_result_record_outcome(attempt, outcome),
            Err(ref e) => self.observe_attempt_result_record_error(attempt, e),
        }
    }

    fn observe_attempt_result_record_outcome(
        &self,
        attempt: &ReconcileAttempt,
        outcome: ScheduleLeaseOutcome,
    ) {
        if outcome == ScheduleLeaseOutcome::Held {
            return;
        }
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %attempt.target().tenant(),
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            resource_id = attempt.target().resource_id(),
            target_id = attempt.target().target_id(),
            epoch = attempt.target().epoch(),
            attempt_id = attempt.attempt_id(),
            "reconcile: attempt result lost lease"
        );
    }

    fn observe_attempt_result_record_error(
        &self,
        attempt: &ReconcileAttempt,
        error: &ReconcileScheduleError,
    ) {
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %attempt.target().tenant(),
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            resource_id = attempt.target().resource_id(),
            target_id = attempt.target().target_id(),
            epoch = attempt.target().epoch(),
            attempt_id = attempt.attempt_id(),
            error = %error,
            "reconcile: record attempt result failed"
        );
    }

    async fn release_lease_best_effort(&self, target: &ClaimedTarget, operation: &'static str) {
        match self.store.release_lease(target).await {
            Ok(ScheduleLeaseOutcome::Held) => self.observe_lease_release_held(target, operation),
            Ok(ScheduleLeaseOutcome::Lost) => self.observe_lease_release_lost(target, operation),
            Err(ref e) => self.observe_lease_release_error(target, operation, e),
        }
    }

    fn observe_lease_release_held(&self, target: &ClaimedTarget, operation: &'static str) {
        tracing::debug!(
            tenant_id = %target.tenant(),
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            resource_id = target.resource_id(),
            target_id = target.target_id(),
            epoch = target.epoch(),
            operation,
            "reconcile: target lease released"
        );
    }

    fn observe_lease_release_lost(&self, target: &ClaimedTarget, operation: &'static str) {
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %target.tenant(),
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            resource_id = target.resource_id(),
            target_id = target.target_id(),
            epoch = target.epoch(),
            operation,
            "reconcile: target lease release lost lease"
        );
    }

    fn observe_lease_release_error(
        &self,
        target: &ClaimedTarget,
        operation: &'static str,
        error: &ReconcileScheduleError,
    ) {
        self.health.mark_degraded();
        tracing::warn!(
            tenant_id = %target.tenant(),
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            resource_id = target.resource_id(),
            target_id = target.target_id(),
            epoch = target.epoch(),
            operation,
            error = %error,
            "reconcile: target lease release failed"
        );
    }

    async fn renew_until_lost(&self, target: &ClaimedTarget, token: &CancellationToken) {
        let renew_every = (self.lease_ttl / 3).max(Duration::from_millis(1));
        let mut ticker = tokio::time::interval(renew_every);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = token.cancelled() => return,
                _ = ticker.tick() => {}
            }
            match self.store.extend_lease(target, self.lease_ttl).await {
                Ok(ScheduleLeaseOutcome::Held) => {}
                _ => return,
            }
        }
    }
}

fn bump_target_attempts(attempts: &mut HashMap<String, u32>, key: &str) -> u32 {
    let n = attempts.entry(key.to_string()).or_insert(0);
    *n = n.saturating_add(1);
    *n
}

fn validate_lease_ttl(lease_ttl: Duration) -> Result<(), ReconcileConfigError> {
    if lease_ttl.as_secs() == 0 {
        return Err(ReconcileConfigError::LeaseTtlTooShort);
    }
    if lease_ttl.subsec_nanos() != 0 {
        return Err(ReconcileConfigError::LeaseTtlSubsecond);
    }
    if i64::try_from(lease_ttl.as_secs()).is_err() {
        return Err(ReconcileConfigError::LeaseTtlTooLarge);
    }
    Ok(())
}

async fn next_worker_event(
    paused_rx: &mut watch::Receiver<bool>,
    ticker: &mut tokio::time::Interval,
    token: &CancellationToken,
) -> WorkerLoopEvent {
    tokio::select! {
        biased;
        () = token.cancelled() => WorkerLoopEvent::Cancelled,
        changed = paused_rx.changed() => {
            if changed.is_err() {
                WorkerLoopEvent::Cancelled
            } else {
                WorkerLoopEvent::PauseChanged
            }
        }
        _ = ticker.tick() => WorkerLoopEvent::Tick,
    }
}

fn emit_reconcile_result(result: ReconcileResultLabel) {
    metrics::counter!("reconcile_total", "result" => result.as_label()).increment(1);
}

// ── Tenancy（必填 sealed 位置参，RECONCILE-TENANCY-REQ-01）───────────────────

/// 租户命名空间声明（sealed：私有字段，仅经 [`Tenancy::single_tenant`] / [`Tenancy::tenant_scoped`] 构造）。
///
/// reconciler 在 tenantless system 身份下发射命令（Claimer key 落 `_notenant`），故 [`Builder::new`] 强制
/// 显式声明该命名空间是否正确（必填位置参，漏传 = 编译错）。`TenantScoped` reconciler 须自行在 command-id
/// 编码 tenant 维度（框架不验证 body，残留盲区——reconcile.md §Builder 强制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tenancy(TenancyKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenancyKind {
    SingleTenant,
    TenantScoped,
}

impl Tenancy {
    /// 单租户 / 无租户系统：reconciler 不跨租户。
    pub fn single_tenant() -> Self {
        Self(TenancyKind::SingleTenant)
    }

    /// 多租户：reconciler 须自行在 command-id 编码 tenant 维度（框架不验证）。
    pub fn tenant_scoped() -> Self {
        Self(TenancyKind::TenantScoped)
    }
}

// ── Trigger（必填位置参；私有 inner + fail-fast 构造）──────────────────────────

/// 触发策略构造错误（fail-fast，非运行期 panic）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TriggerError {
    /// resync 周期为零（`tokio::time::interval(0)` 会 panic，故构造期拒）。
    #[error("reconcile trigger interval must be non-zero")]
    ZeroInterval,
}

/// 收敛触发策略（必填位置参；决定 dispatch 节奏）。
///
/// **私有 inner**（newtype funnel）：业务不能字面构造非法策略——周期经 [`Trigger::interval`] fail-fast 校验
/// 非零（杜绝零周期 → `tokio::time::interval` 运行期 panic）。`EventDriven`（订阅事件 → 立即
/// `Request::for_entity` targeted dispatch）随事件总线订阅接线后续兑现（见 reconcile follow-up issue）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trigger(TriggerKind);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TriggerKind {
    /// 每 `period` 发一次 `Request::default()`（resync pulse「re-observe 全部」，level-triggered）。
    Interval(Duration),
}

impl Trigger {
    /// 周期 resync 触发（每 `period` 一次 resync pulse）；`period == 0` → [`TriggerError::ZeroInterval`]（fail-fast）。
    pub fn interval(period: Duration) -> Result<Self, TriggerError> {
        if period.is_zero() {
            return Err(TriggerError::ZeroInterval);
        }
        Ok(Self(TriggerKind::Interval(period)))
    }

    /// 解出 resync 周期（harness 内部用）。
    pub(crate) fn period(&self) -> Duration {
        match self.0 {
            TriggerKind::Interval(period) => period,
        }
    }
}

// ── BackoffPolicy（per-entity 指数退避）─────────────────────────────────────

/// reconcile builder 族配置错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackoffError {
    /// 退避 base 超过 cap（非法策略，fail-fast 非静默钳制）。
    ///
    /// `base` / `cap` 是构造时传入的配置值，属公开参数，不含 PII（thiserror 引用字段合法）。
    #[error("reconcile backoff base ({base:?}) exceeds cap ({cap:?})")]
    BaseExceedsCap {
        /// 超出 cap 的 base 值。
        base: Duration,
        /// 策略设定的 cap 值。
        cap: Duration,
    },
}

/// per-entity 指数退避策略：第 n 次失败延迟 `base * 2^(n-1)`，封顶 `cap`。
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    base: Duration,
    cap: Duration,
}

impl BackoffPolicy {
    /// 构造退避策略；`base > cap` → [`BackoffError::BaseExceedsCap`]（fail-fast）。
    pub fn new(base: Duration, cap: Duration) -> Result<Self, BackoffError> {
        if base > cap {
            return Err(BackoffError::BaseExceedsCap { base, cap });
        }
        Ok(Self { base, cap })
    }

    /// 第 `attempts` 次失败（1-based）的退避延迟：`base * 2^(attempts-1)`，封顶 `cap`（饱和不回绕）。
    fn delay_for(&self, attempts: u32) -> Duration {
        // exp ≤ 31：`1u32 << 31` 不溢出；更高次幂经后续 `min(cap)` 收敛，无需精确大数。
        let exp = attempts.saturating_sub(1).min(31);
        let factor = 1_u32 << exp;
        self.base.saturating_mul(factor).min(self.cap)
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        // 默认 1s 起、60s 封顶（保守起点，避免热重试打爆后端）。
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }
}

// ── Builder（唯一公开构造入口）───────────────────────────────────────────────

/// [`ReconcileLoop`] 唯一公开构造入口。`new(reconciler, tenancy, trigger)` 三参必填——漏 tenancy/trigger
/// 即编译错（INVARIANT RECONCILE-TENANCY-REQ-01）。可选 `with_backoff` 调退避；`build()` infallible。
///
/// leader 选举不在 build-time：单进程 / 多副本是**运行期形态**，经 [`ReconcileLoop::run`] /
/// [`ReconcileLoop::run_with_leader`] 二选一表达（typed function choice）——避免「无 leader」需要一个
/// sentinel provider 占位。
///
/// # 与 FencedWriter 的分工
///
/// harness 经 `Context::for_harness(epoch)` 把当前任期 epoch 注入 reconciler；reconciler 自持
/// `Arc<DynFencedWriter>`（构造器注入），在 `reconcile()` 内取 `ctx.epoch()` 构造 `FencedWriteRequest`
/// 调用。**cancellation 语义**：reconcile future 可能在任意 await 点被 drop（丢 lease / shutdown），
/// reconciler 须保证写经 FencedWriter CAS、不依赖跨 panic/cancel 的中间状态。
pub struct Builder<R: Reconciler> {
    reconciler: R,
    tenancy: Tenancy,
    trigger: Trigger,
    backoff: BackoffPolicy,
}

impl<R: Reconciler> Builder<R> {
    /// 新建 builder。`tenancy` / `trigger` 必填位置参（RECONCILE-TENANCY-REQ-01 Hard，漏传即编译错）。
    pub fn new(reconciler: R, tenancy: Tenancy, trigger: Trigger) -> Self {
        Self {
            reconciler,
            tenancy,
            trigger,
            backoff: BackoffPolicy::default(),
        }
    }

    /// 覆盖默认指数退避策略。
    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    /// 构造 [`ReconcileLoop`]（infallible：两必填项已位置参 Hard 保证，backoff 已在 [`BackoffPolicy::new`] fail-fast）。
    ///
    /// 是 `ReconcileLoop` **唯一**构造入口（其无公开构造器、config 字段私有）。
    pub fn build(self) -> ReconcileLoop<R> {
        ReconcileLoop {
            reconciler: self.reconciler,
            tenancy: self.tenancy,
            trigger: self.trigger,
            backoff: self.backoff,
            health: Arc::new(WorkerHealth::healthy()),
        }
    }
}

// ── ReconcileLoop（收敛环）───────────────────────────────────────────────────

/// 单次 dispatch 后的调度结论。
#[derive(Debug, PartialEq, Eq)]
enum NextAction {
    /// 已收敛 / 不可重试分类——等下个 resync tick 或外部事件（level-triggered 重驱动）。
    Idle,
    /// `after` 后主动复检（来自 `Outcome::requeue_after` 或 transient 退避）。
    RequeueAfter(Duration),
}

/// reconcile 收敛环（仅经 [`Builder::build`] 构造）。
///
/// [`ReconcileLoop::run`]（单进程）/ [`ReconcileLoop::run_with_leader`]（多副本）驱动收敛直到 token 取消
/// （**无内部 spawn**：组合根 `tokio::spawn(loop.run(token))`，与 relay 同范式——泛型 future 在具体
/// reconciler + leader 处单态化为 Send）。
///
/// 与 relay 的 `RelayWorker` 不同，reconcile 不分离 Worker——`run`/`run_with_leader` 消费 `self`，
/// 组合根 `tokio::spawn` 直接持 JoinHandle。
pub struct ReconcileLoop<R: Reconciler> {
    reconciler: R,
    tenancy: Tenancy,
    trigger: Trigger,
    backoff: BackoffPolicy,
    health: Arc<WorkerHealth>,
}

impl<R: Reconciler> ReconcileLoop<R> {
    /// 共享健康句柄（readyz 聚合读，[`RECONCILE_PROBE`] 翻该状态）。
    pub fn health(&self) -> Arc<WorkerHealth> {
        Arc::clone(&self.health)
    }

    /// 单进程驱动：always leader、epoch `None`、无 fencing（reconcile.md §Leader-elect）。直到 `token` 取消。
    ///
    /// **生产多副本部署禁止用 `run`**（无 fencing）；多副本必须 `run_with_leader`。
    /// 单进程 = 确认单副本。
    pub async fn run(self, token: CancellationToken) {
        let period = self.trigger.period();
        self.log_start(period, false);
        let mut attempts: HashMap<Option<EntityId>, u32> = HashMap::new();
        Self::dispatch_loop(
            &self.reconciler,
            &self.backoff,
            &self.health,
            period,
            None,
            &token,
            &mut attempts,
        )
        .await;
        self.health.mark_stopped();
        tracing::info!("reconcile: loop stopped");
    }

    /// 多副本驱动：注入 leader 选举 provider（泛型静态分发 + `Arc`，非 `Box<DynLeaderElector>`——dyn 变体
    /// `Send` 非 `Sync`，跨 `tokio::spawn` 的 Send future await 持有不成立，diport DIPORT-ASYNC-ARC-SEND-01）。
    /// 整环 leader-gated：仅 lease holder dispatch、注入任期 epoch；丢 lease 取消在途 reconcile。直到 `token` 取消。
    pub async fn run_with_leader<L>(self, leader: Arc<L>, token: CancellationToken)
    where
        L: LeaderElector + Send + Sync + 'static,
    {
        let period = self.trigger.period();
        self.log_start(period, true);
        let mut attempts: HashMap<Option<EntityId>, u32> = HashMap::new();
        self.leader_gated(period, &*leader, &token, &mut attempts)
            .await;
        self.health.mark_stopped();
        tracing::info!("reconcile: loop stopped");
    }

    /// 启动日志（抽出降 run 认知复杂度）。
    fn log_start(&self, period: Duration, has_leader: bool) {
        tracing::info!(
            tenancy = ?self.tenancy,
            ?period,
            has_leader,
            "reconcile: loop starting"
        );
    }

    /// 多副本 leader-gated 外环：争夺 lease → 持有期间 dispatch（注入任期 epoch）→ 丢 lease 回争夺。
    async fn leader_gated<L: LeaderElector + Send + Sync + 'static>(
        &self,
        period: Duration,
        leader: &L,
        token: &CancellationToken,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) {
        while !token.is_cancelled() {
            match leader.acquire(LEASE_TTL).await {
                // 当选：服务一个任期；根取消（已优雅让出）则退出，否则丢 lease 回 acquire 重选举。
                Ok(Some(lease)) => {
                    if self
                        .serve_term(leader, period, lease, token, attempts)
                        .await
                    {
                        return;
                    }
                }
                // standby（他副本持有）：正常态（mark_healthy；readyz 不区分 standby/active，运维经 leader
                // audit log 区分），等下个 TTL 再争夺。
                Ok(None) => {
                    log_standby();
                    self.health.mark_healthy();
                    if wait_or_cancel(LEASE_TTL, token).await {
                        return;
                    }
                }
                // infra 故障：退避后重试。
                Err(ref e) => {
                    log_acquire_failed(e);
                    self.health.mark_degraded();
                    if wait_or_cancel(RENEW_INTERVAL, token).await {
                        return;
                    }
                }
            }
        }
    }

    /// 服务单个 leadership 任期：以任期 epoch 跑 dispatch（注入 epoch），直到丢 lease 或根取消。
    /// 返回 `true` 表根取消（已优雅让出，调用方应退出外环）；`false` 表丢 lease（回外环重选举）。
    async fn serve_term<L: LeaderElector + Send + Sync + 'static>(
        &self,
        leader: &L,
        period: Duration,
        lease: diport::LeaseToken,
        token: &CancellationToken,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) -> bool {
        log_elected(lease.epoch);
        self.lead_term(leader, period, lease.epoch, token, attempts)
            .await;
        if token.is_cancelled() {
            if let Err(ref e) = leader.release(lease).await {
                log_release_failed(e);
            }
            return true;
        }
        false
    }

    /// 单个 leadership 任期：dispatch 环与 lease 续租**并发**（无 spawn，`select!` 内同任务）。
    ///
    /// 丢 lease（[`Self::renew_until_lost`] 先完成）⇒ `select!` 丢弃 dispatch future ⇒ **取消在途 reconcile**
    /// （reconcile.md §Leader-elect「丢 lease 取消 lease-scoped CancellationToken 中断在途 reconcile」）。
    async fn lead_term<L: LeaderElector + Send + Sync + 'static>(
        &self,
        leader: &L,
        period: Duration,
        epoch: vocab::Epoch,
        token: &CancellationToken,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) {
        let scope = token.child_token();
        tokio::select! {
            biased;
            () = token.cancelled() => scope.cancel(),
            () = Self::renew_until_lost(leader, &scope) => {}
            () = Self::dispatch_loop(
                &self.reconciler, &self.backoff, &self.health, period, Some(epoch), &scope, attempts,
            ) => {}
        }
    }

    /// 续租轮询直到丢 lease：每 [`RENEW_INTERVAL`] 再 `acquire`；丢（`None`）或 renew infra 错（`Err`）⇒
    /// fail-closed `scope.cancel()` 让出（不确定是否仍持有 ⇒ 停写，正确性优先于可用性）。
    async fn renew_until_lost<L: LeaderElector>(leader: &L, scope: &CancellationToken) {
        let mut ticker = tokio::time::interval(RENEW_INTERVAL);
        ticker.tick().await; // 吞掉立即首 tick（刚 acquire 过）
        loop {
            ticker.tick().await;
            match leader.acquire(LEASE_TTL).await {
                Ok(Some(_)) => {} // 续租成功，继续持有
                _ => {
                    log_lease_lost();
                    scope.cancel();
                    return;
                }
            }
        }
    }

    /// dispatch 环：每 tick / 退避到期发一次 resync pulse；`cancel` 取消即返回。
    async fn dispatch_loop(
        reconciler: &R,
        backoff: &BackoffPolicy,
        health: &WorkerHealth,
        period: Duration,
        epoch: Option<vocab::Epoch>,
        cancel: &CancellationToken,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) {
        let mut ticker = tokio::time::interval(period);
        let mut requeue: Option<Duration> = None;
        loop {
            let pending = requeue.take();
            tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                () = sleep_or_pending(pending) => {}
                _ = ticker.tick() => {}
            }
            let ctx = Context::for_harness(epoch);
            // dispatch 与 cancel **同层** select：取消（root / lease-scoped）可丢弃在途 dispatch future、
            // **中断在途 reconcile**（否则 cancel 须等当前 reconcile().await 跑完才生效）。
            tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                action = Self::dispatch_once(reconciler, backoff, health, &ctx, Request::default(), attempts) => {
                    if let NextAction::RequeueAfter(d) = action {
                        requeue = Some(d);
                    }
                }
            }
        }
    }

    /// 单次 dispatch：跑 `reconcile`（panic 经 `catch_unwind` 映射 transient），据结果决定退避 / 调度。
    ///
    /// # catch_unwind 契约
    ///
    /// `AssertUnwindSafe` 是「框架信任 reconciler impl 的 unwind safety」契约——无法验证 impl 实际状态；
    /// reconciler 若在 await 点持 poisoned-able Mutex，捕获后状态可能损坏，故 reconciler 应 panic-tolerant
    /// （写经 CAS、不跨 dispatch 复用可变共享态）。
    async fn dispatch_once(
        reconciler: &R,
        backoff: &BackoffPolicy,
        health: &WorkerHealth,
        ctx: &Context,
        req: Request,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) -> NextAction {
        let key = req.entity().cloned();
        let result = AssertUnwindSafe(reconciler.reconcile(ctx, req))
            .catch_unwind()
            .await;
        match result {
            // 收敛：清退避；按 requeue_after 调度复检 / 等下个 tick。
            Ok(Ok(outcome)) => {
                attempts.remove(&key);
                health.mark_healthy();
                match outcome.requeue_interval() {
                    Some(d) => NextAction::RequeueAfter(d),
                    None => NextAction::Idle,
                }
            }
            // transient：per-entity 指数退避重入队。
            Ok(Err(ref e)) if e.is_transient() => {
                log_transient();
                health.mark_degraded();
                NextAction::RequeueAfter(backoff.delay_for(bump_attempts(attempts, key)))
            }
            // permanent / invariant：仅分类，不自动放弃下一步——清退避、等下个 resync tick 重驱动。
            Ok(Err(_)) => {
                log_permanent();
                attempts.remove(&key);
                health.mark_degraded();
                NextAction::Idle
            }
            // 捕获 panic → 映射 transient（不挂环）。
            Err(_panic) => {
                log_panicked();
                health.mark_degraded();
                NextAction::RequeueAfter(backoff.delay_for(bump_attempts(attempts, key)))
            }
        }
    }
}

// ── 结构化日志 helper（抽出 tracing 宏展开，控制调用方认知复杂度；
//    仿 relay.rs `log_*` 范式）。勿记 payload/PII——error 字段经 `*Error` 脱敏 Display（固定常量摘要）。

/// 当选 leader（任期 epoch 可观测，非 PII）。
fn log_elected(epoch: vocab::Epoch) {
    tracing::info!(?epoch, "reconcile: elected leader");
}

/// 本副本 standby（他副本持 lease，正常态，debug 减噪）。
fn log_standby() {
    tracing::debug!("reconcile: standby, another replica holds lease");
}

/// 争夺 lease infra 故障（退避重试）。
fn log_acquire_failed(error: &diport::LeaderElectorError) {
    tracing::warn!(error = %error, "reconcile: leader acquire failed, backing off");
}

/// 优雅让出失败（他副本须等 TTL 才接管）。
fn log_release_failed(error: &diport::LeaderElectorError) {
    tracing::warn!(error = %error, "reconcile: graceful release failed, peer waits for TTL");
}

/// 丢 lease，取消在途 dispatch（fail-closed 停写）。
fn log_lease_lost() {
    tracing::warn!("reconcile: lease lost, cancelling in-flight dispatch");
}

/// transient 错误，per-entity 退避重入队。
fn log_transient() {
    tracing::warn!("reconcile: transient error, backing off");
}

/// permanent 错误，不退避、等下个 resync tick 重驱动。
fn log_permanent() {
    tracing::warn!("reconcile: permanent error, awaiting next resync");
}

/// 捕获 reconcile panic，映射 transient 退避（环不挂）。
fn log_panicked() {
    tracing::error!("reconcile: dispatch panicked, mapped to transient backoff");
}

// ── 自由 helper ──────────────────────────────────────────────────────────────

/// `Some(d)` ⇒ sleep `d`；`None` ⇒ 永不完成（让 `select!` 仅靠其它分支推进）。
async fn sleep_or_pending(d: Option<Duration>) {
    match d {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// 等 `d` 或 token 取消；返回 `true` 表已取消（调用方据此提前退出）。
async fn wait_or_cancel(d: Duration, token: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = token.cancelled() => true,
        () = tokio::time::sleep(d) => false,
    }
}

/// 对 `key` 的失败计数 `+1` 并返回新值（1-based）；饱和不回绕。
fn bump_attempts(attempts: &mut HashMap<Option<EntityId>, u32>, key: Option<EntityId>) -> u32 {
    let n = attempts.entry(key).or_insert(0);
    *n = n.saturating_add(1);
    *n
}

#[cfg(test)]
mod tests {
    use super::{
        AttemptErrorKind, AttemptResult, AttemptScope, BackoffError, BackoffPolicy, Builder,
        ClaimedTarget, DurableReconciler, NextAction, RECONCILE_PROBE, RENEW_INTERVAL,
        ReconcileAttempt, ReconcileConfigError, ReconcileLoop, ReconcileScheduleError,
        ReconcileScheduleStore, ReconcileSchedulerBuilder, ReviewedCommand, ScheduleAttemptOutcome,
        ScheduleLeaseOutcome, StableDispatchKey, Tenancy, Trigger, TriggerError, bump_attempts,
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use consistency::{
        Context, ConvergeAction, EngineErrorKind, EntityId, Outcome, ReconcileError,
        ReconcileResultLabel, Reconciler, Request,
    };
    use diport::{
        EnvelopeSubjectId, LeaderElector, LeaderElectorError, LeaderId, LeaseToken, OpaqueActorId,
        OutboxActor,
    };
    use primitives::{HealthStatus, ProbeName};
    use tokio_util::sync::CancellationToken;

    use crate::WorkerHealth;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    // ── 测试 Reconciler：按行为脚本返回，记录看到的 epoch + 调用次数 ──────────

    #[derive(Clone, Copy)]
    enum Behavior {
        Settled,
        RequeueAfter(Duration),
        Transient,
        Permanent,
        Panic,
    }

    struct ScriptedReconciler {
        behavior: Behavior,
        calls: Arc<AtomicU32>,
        seen_epoch: Arc<Mutex<Vec<Option<vocab::Epoch>>>>,
        cancel_after: Option<(u32, CancellationToken)>,
    }

    impl ScriptedReconciler {
        fn new(behavior: Behavior) -> Self {
            Self {
                behavior,
                calls: Arc::new(AtomicU32::new(0)),
                seen_epoch: Arc::new(Mutex::new(Vec::new())),
                cancel_after: None,
            }
        }
        /// run 测试用：跑 `n` 次后取消 token，使 loop 退出（避免 start_paused 无限推进）。
        fn cancelling(behavior: Behavior, n: u32, token: CancellationToken) -> Self {
            let mut r = Self::new(behavior);
            r.cancel_after = Some((n, token));
            r
        }
    }

    impl Reconciler for ScriptedReconciler {
        #[allow(clippy::panic)]
        // reason: 测试桩刻意 panic 以验证 harness 的 panic→transient 捕获（dispatch_panic_maps_to_transient_backoff）；
        // item-level carve-out（error-handling.md §Carve-out）。
        async fn reconcile(&self, ctx: &Context, _req: Request) -> Result<Outcome, ReconcileError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            self.seen_epoch
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(ctx.epoch());
            if let Some((limit, token)) = &self.cancel_after
                && n >= *limit
            {
                token.cancel();
            }
            match self.behavior {
                Behavior::Settled => Ok(Outcome::settled()),
                Behavior::RequeueAfter(d) => Ok(Outcome::requeue_after(d)),
                Behavior::Transient => Err(ReconcileError::new(EngineErrorKind::Transient)),
                Behavior::Permanent => Err(ReconcileError::new(EngineErrorKind::Permanent)),
                Behavior::Panic => panic!("scripted reconcile panic"),
            }
        }
    }

    /// 按调用次数切换行为的 Reconciler：前 N 次返回 `first`，此后返回 `rest`；
    /// 可选在第 `cancel_on` 次调用后取消 token（避免裸 sleep 竞态）。
    struct SeqReconciler {
        first: Behavior,
        rest: Behavior,
        switch_after: u32,
        calls: Arc<AtomicU32>,
        cancel_on: Option<(u32, CancellationToken)>,
    }

    impl SeqReconciler {
        fn new(
            first: Behavior,
            rest: Behavior,
            switch_after: u32,
            cancel_on: Option<(u32, CancellationToken)>,
        ) -> Self {
            Self {
                first,
                rest,
                switch_after,
                calls: Arc::new(AtomicU32::new(0)),
                cancel_on,
            }
        }
    }

    impl Reconciler for SeqReconciler {
        async fn reconcile(
            &self,
            _ctx: &Context,
            _req: Request,
        ) -> Result<Outcome, ReconcileError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some((on, token)) = &self.cancel_on
                && n >= *on
            {
                token.cancel();
            }
            let behavior = if n <= self.switch_after {
                self.first
            } else {
                self.rest
            };
            match behavior {
                Behavior::Settled => Ok(Outcome::settled()),
                Behavior::RequeueAfter(d) => Ok(Outcome::requeue_after(d)),
                Behavior::Transient => Err(ReconcileError::new(EngineErrorKind::Transient)),
                Behavior::Permanent => Err(ReconcileError::new(EngineErrorKind::Permanent)),
                Behavior::Panic => unreachable!("SeqReconciler not used for panic tests"),
            }
        }
    }

    // ── 测试 LeaderElector ────────────────────────────────────────────────────

    struct AlwaysLeader(u64);
    impl LeaderElector for AlwaysLeader {
        async fn acquire(
            &self,
            _lease: Duration,
        ) -> Result<Option<LeaseToken>, LeaderElectorError> {
            Ok(Some(LeaseToken {
                holder: tlid(),
                epoch: vocab::Epoch::new(self.0),
            }))
        }
        async fn release(&self, _token: LeaseToken) -> Result<(), LeaderElectorError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), LeaderElectorError> {
            Ok(())
        }
    }

    struct NeverLeader;
    impl LeaderElector for NeverLeader {
        async fn acquire(
            &self,
            _lease: Duration,
        ) -> Result<Option<LeaseToken>, LeaderElectorError> {
            Ok(None)
        }
        async fn release(&self, _token: LeaseToken) -> Result<(), LeaderElectorError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), LeaderElectorError> {
            Ok(())
        }
    }

    /// 第 1 次 acquire 返 Ok(Some(lease))，第 2 次起返 Ok(None)（模拟丢 lease）。
    /// 用于验证「丢 lease → select-drop 取消在途 dispatch」承诺。
    struct RenewOnceLeader {
        acquired: AtomicBool,
    }

    impl RenewOnceLeader {
        fn new() -> Self {
            Self {
                acquired: AtomicBool::new(false),
            }
        }
    }

    impl LeaderElector for RenewOnceLeader {
        async fn acquire(
            &self,
            _lease: Duration,
        ) -> Result<Option<LeaseToken>, LeaderElectorError> {
            let was_acquired = self.acquired.swap(true, Ordering::SeqCst);
            if !was_acquired {
                // 第 1 次：当选
                Ok(Some(LeaseToken {
                    holder: tlid(),
                    epoch: vocab::Epoch::new(0),
                }))
            } else {
                // 第 2 次起：丢 lease（standby）
                Ok(None)
            }
        }
        async fn release(&self, _token: LeaseToken) -> Result<(), LeaderElectorError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), LeaderElectorError> {
            Ok(())
        }
    }

    /// 第 1 次 acquire 返 Ok(Some)，后续返 Err（infra 故障）。
    /// 用于验证「Err 分支与 None 分支同样 fail-closed 取消 scope」承诺。
    struct ErrorOnRenewLeader {
        acquired: AtomicBool,
    }

    impl ErrorOnRenewLeader {
        fn new() -> Self {
            Self {
                acquired: AtomicBool::new(false),
            }
        }
    }

    impl LeaderElector for ErrorOnRenewLeader {
        async fn acquire(
            &self,
            _lease: Duration,
        ) -> Result<Option<LeaseToken>, LeaderElectorError> {
            let was_acquired = self.acquired.swap(true, Ordering::SeqCst);
            if !was_acquired {
                Ok(Some(LeaseToken {
                    holder: tlid(),
                    epoch: vocab::Epoch::new(0),
                }))
            } else {
                Err(LeaderElectorError::new(std::io::Error::other(
                    "renew-infra-fail",
                )))
            }
        }
        async fn release(&self, _token: LeaseToken) -> Result<(), LeaderElectorError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), LeaderElectorError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    // reason: 测试桩用 canonical literal 构造，item-level carve-out（error-handling.md §Carve-out）。
    fn tlid() -> LeaderId {
        LeaderId::parse("test-leader").expect("canonical")
    }

    #[allow(clippy::expect_used)]
    // reason: 测试用非零秒构造 Trigger，item-level carve-out。
    fn trig(secs: u64) -> Trigger {
        Trigger::interval(Duration::from_secs(secs)).expect("nonzero interval")
    }

    #[allow(clippy::expect_used)]
    // reason: fixed canonical UUID for tests.
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant")
    }

    fn claimed_target() -> ClaimedTarget {
        claimed_target_with_ids(
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "device-1",
        )
    }

    fn claimed_target_with_ids(
        target_id: &str,
        lease_token: &str,
        resource_id: &str,
    ) -> ClaimedTarget {
        ClaimedTarget::new(
            tenant(),
            target_id,
            lease_token,
            9,
            "test-reconciler",
            "device",
            resource_id,
            super::AttemptTrigger::Resync,
        )
    }

    #[derive(Clone, Default)]
    struct FakeScheduleStore {
        state: Arc<Mutex<FakeScheduleState>>,
    }

    #[derive(Default)]
    struct FakeScheduleState {
        targets: VecDeque<ClaimedTarget>,
        claims: u32,
        attempts: u32,
        results: Vec<AttemptResult>,
        actions: Vec<ConvergeAction>,
        command_keys: Vec<String>,
        releases: u32,
        cancel_on_record: Option<CancellationToken>,
        cancel_on_extend_lost: Option<CancellationToken>,
        append_attempt_lost: bool,
        extend_outcome: Option<ScheduleLeaseOutcome>,
        release_outcome: Option<ScheduleLeaseOutcome>,
        release_error: bool,
    }

    impl FakeScheduleStore {
        fn with_target(target: ClaimedTarget) -> Self {
            Self::with_targets([target])
        }

        fn with_targets(targets: impl IntoIterator<Item = ClaimedTarget>) -> Self {
            let store = Self::default();
            let mut state = store.state.lock().unwrap_or_else(|e| e.into_inner());
            state.targets.extend(targets);
            drop(state);
            store
        }

        fn cancel_on_record(&self, token: CancellationToken) {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cancel_on_record = Some(token);
        }

        fn lose_append_attempt(&self) {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .append_attempt_lost = true;
        }

        fn lose_extend_and_cancel(&self, token: CancellationToken) {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.extend_outcome = Some(ScheduleLeaseOutcome::Lost);
            state.cancel_on_extend_lost = Some(token);
        }

        fn set_release_outcome(&self, outcome: ScheduleLeaseOutcome) {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .release_outcome = Some(outcome);
        }

        fn fail_release(&self) {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .release_error = true;
        }
    }

    impl ReconcileScheduleStore for FakeScheduleStore {
        async fn claim_due_targets(
            &self,
            _tenant: vocab::TenantId,
            _reconciler_id: &str,
            _holder_id: &str,
            limit: u32,
            _lease_ttl: Duration,
        ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.claims = state.claims.saturating_add(1);
            let mut targets = Vec::new();
            for _ in 0..limit {
                if let Some(target) = state.targets.pop_front() {
                    targets.push(target);
                }
            }
            Ok(targets)
        }

        async fn append_attempt(
            &self,
            target: &ClaimedTarget,
            _holder_id: &str,
        ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.attempts = state.attempts.saturating_add(1);
            if state.append_attempt_lost {
                return Ok(ScheduleAttemptOutcome::Lost);
            }
            Ok(ScheduleAttemptOutcome::Started(ReconcileAttempt::new(
                format!("attempt-{}", state.attempts),
                target.clone(),
            )))
        }

        async fn record_attempt_result(
            &self,
            _attempt: &ReconcileAttempt,
            result: AttemptResult,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let cancel = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.results.push(result);
                state.cancel_on_record.clone()
            };
            if let Some(token) = cancel {
                token.cancel();
            }
            Ok(ScheduleLeaseOutcome::Held)
        }

        async fn record_action_and_enqueue_command(
            &self,
            _attempt: &ReconcileAttempt,
            action: ConvergeAction,
            command: ReviewedCommand,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let (entry, _envelope) = command.into_parts();
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.actions.push(action);
            state
                .command_keys
                .push(entry.idem_key().as_str().to_string());
            Ok(ScheduleLeaseOutcome::Held)
        }

        async fn extend_lease(
            &self,
            _target: &ClaimedTarget,
            _lease_ttl: Duration,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let (outcome, cancel) = {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                (
                    state.extend_outcome.unwrap_or(ScheduleLeaseOutcome::Held),
                    state.cancel_on_extend_lost.clone(),
                )
            };
            if outcome == ScheduleLeaseOutcome::Lost
                && let Some(token) = cancel
            {
                token.cancel();
            }
            Ok(outcome)
        }

        async fn release_lease(
            &self,
            _target: &ClaimedTarget,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.releases = state.releases.saturating_add(1);
            if state.release_error {
                return Err(ReconcileScheduleError::new(std::io::Error::other(
                    "release failed",
                )));
            }
            Ok(state.release_outcome.unwrap_or(ScheduleLeaseOutcome::Held))
        }

        async fn pause_target(
            &self,
            _tenant: vocab::TenantId,
            _target_id: &str,
        ) -> Result<(), ReconcileScheduleError> {
            Ok(())
        }

        async fn resume_target(
            &self,
            _tenant: vocab::TenantId,
            _target_id: &str,
        ) -> Result<(), ReconcileScheduleError> {
            Ok(())
        }
    }

    enum DurableBehavior {
        Settled,
        Transient,
    }

    struct DurableScript {
        behavior: DurableBehavior,
        calls: Arc<AtomicU32>,
    }

    impl DurableScript {
        fn new(behavior: DurableBehavior) -> Self {
            Self {
                behavior,
                calls: Arc::new(AtomicU32::new(0)),
            }
        }
    }

    impl DurableReconciler<FakeScheduleStore> for DurableScript {
        async fn reconcile(
            &self,
            ctx: &Context,
            _target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<Outcome, ReconcileError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(ctx.epoch(), Some(vocab::Epoch::new(9)));
            match self.behavior {
                DurableBehavior::Settled => Ok(Outcome::settled()),
                DurableBehavior::Transient => Err(ReconcileError::new(EngineErrorKind::Transient)),
            }
        }
    }

    #[allow(clippy::expect_used)]
    fn reviewed_command(key: &str) -> ReviewedCommand {
        ReviewedCommand::new(
            StableDispatchKey::parse(key).expect("dispatch key"),
            "test.command",
            vocab::ContractBinding::from_static(
                "test",
                "test.command",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            tenant(),
            b"{}".to_vec(),
            EnvelopeSubjectId::from_opaque("device-1").expect("subject"),
            OutboxActor::service(OpaqueActorId::from_opaque("reconcile-test").expect("actor")),
        )
        .expect("reviewed command")
    }

    #[test]
    fn stable_dispatch_key_rejects_empty_and_reviewed_command_uses_key() -> TestResult {
        assert!(StableDispatchKey::parse("").is_err());

        let command = reviewed_command("reconcile-device-1-create");
        let (entry, envelope) = command.into_parts();
        assert_eq!(
            entry.idem_key().as_str(),
            "reconcile:v1:t36:11111111-1111-1111-1111-111111111111:p12:test.command:k25:reconcile-device-1-create"
        );
        assert_eq!(entry.topic().as_str(), "test.command");
        assert_eq!(envelope.tenant(), tenant());

        let same_raw_other_tenant = ReviewedCommand::new(
            StableDispatchKey::parse("reconcile-device-1-create")?,
            "test.command",
            vocab::ContractBinding::from_static(
                "test",
                "test.command",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            vocab::TenantId::parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")?,
            b"{}".to_vec(),
            EnvelopeSubjectId::from_opaque("device-1")?,
            OutboxActor::service(OpaqueActorId::from_opaque("reconcile-test")?),
        )?;
        let (other_entry, _) = same_raw_other_tenant.into_parts();
        assert_ne!(
            entry.idem_key().as_str(),
            other_entry.idem_key().as_str(),
            "same raw key must not collide across tenants"
        );

        let bad_topic = ReviewedCommand::new(
            StableDispatchKey::parse("reconcile-device-1-update")?,
            "not canonical topic",
            vocab::ContractBinding::from_static(
                "test",
                "test.command",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
            tenant(),
            Vec::new(),
            EnvelopeSubjectId::from_opaque("device-1")?,
            OutboxActor::service(OpaqueActorId::from_opaque("reconcile-test")?),
        );
        assert!(bad_topic.is_err(), "invalid topic must fail closed");
        Ok(())
    }

    #[tokio::test]
    async fn attempt_scope_records_action_and_command_through_single_store_call() -> TestResult {
        let store = FakeScheduleStore::default();
        let attempt = ReconcileAttempt::new("attempt-scope", claimed_target());
        let scope = AttemptScope::new(&store, attempt);

        let outcome = scope
            .record_action_and_enqueue_command(
                ConvergeAction::Create,
                reviewed_command("reconcile-device-1-create"),
            )
            .await?;

        assert_eq!(outcome, ScheduleLeaseOutcome::Held);
        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.actions, vec![ConvergeAction::Create]);
        assert_eq!(
            state.command_keys,
            vec![
                "reconcile:v1:t36:11111111-1111-1111-1111-111111111111:p12:test.command:k25:reconcile-device-1-create"
                    .to_string()
            ]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: spawned worker should exit after fake store records the result.
    async fn reconcile_worker_pause_stops_claims_until_resume() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.cancel_on_record(token.clone());
        let reconciler = DurableScript::new(DurableBehavior::Settled);
        let calls = Arc::clone(&reconciler.calls);
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            reconciler,
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();
        let control = worker.control();
        control.pause();
        let handle = tokio::spawn(worker.run(token));

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            store.state.lock().unwrap_or_else(|e| e.into_inner()).claims,
            0,
            "paused worker must not claim new targets"
        );

        control.resume();
        tokio::time::sleep(Duration::from_secs(10)).await;
        handle.await.expect("worker exits after fake result record");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.claims, 1);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: spawned worker should exit after fake store records the result.
    async fn reconcile_worker_records_transient_attempt_result() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Transient),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token));
        tokio::time::sleep(Duration::from_secs(1)).await;
        handle.await.expect("worker exits after fake result record");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.results.len(), 1);
        let result = state.results[0];
        assert_eq!(result.result(), ReconcileResultLabel::Transient);
        assert_eq!(
            result.error_kind(),
            Some(super::AttemptErrorKind::Transient)
        );
        assert_eq!(result.next_run_after(), Duration::from_secs(1));
        assert_eq!(state.releases, 1);
    }

    #[test]
    fn durable_builder_rejects_zero_lease_ttl() {
        let result = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::ZERO);
        assert!(matches!(
            result,
            Err(ReconcileConfigError::LeaseTtlTooShort)
        ));
    }

    #[test]
    fn durable_builder_rejects_subsecond_lease_ttl() {
        let result = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_millis(500));
        assert!(matches!(
            result,
            Err(ReconcileConfigError::LeaseTtlTooShort)
        ));

        let result = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_millis(1_500));
        assert!(matches!(
            result,
            Err(ReconcileConfigError::LeaseTtlSubsecond)
        ));
    }

    #[test]
    fn durable_builder_rejects_zero_batch_size() {
        let result = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_batch_size(0);
        assert!(matches!(result, Err(ReconcileConfigError::BatchSizeZero)));
    }

    #[test]
    fn durable_attempt_result_classifies_success_labels() {
        let default_next = Duration::from_secs(60);
        let settled = AttemptResult::from_outcome(&Outcome::settled(), default_next);
        assert_eq!(settled.result(), ReconcileResultLabel::Settled);
        assert_eq!(settled.next_run_after(), default_next);
        assert_eq!(settled.requeue_after(), None);
        assert_eq!(settled.error_kind(), None);

        let requeue_after = Duration::from_millis(250);
        let requeue = AttemptResult::from_outcome(
            &Outcome::requeue_after(requeue_after),
            Duration::from_secs(60),
        );
        assert_eq!(requeue.result(), ReconcileResultLabel::RequeueAfter);
        assert_eq!(requeue.next_run_after(), requeue_after);
        assert_eq!(requeue.requeue_after(), Some(requeue_after));
        assert_eq!(requeue.error_kind(), None);
    }

    #[test]
    fn durable_attempt_result_classifies_error_labels() {
        let transient = AttemptResult::from_error(
            &ReconcileError::new(EngineErrorKind::Transient),
            Duration::from_secs(1),
        );
        assert_eq!(transient.result(), ReconcileResultLabel::Transient);
        assert_eq!(transient.error_kind(), Some(AttemptErrorKind::Transient));

        let permanent = AttemptResult::from_error(
            &ReconcileError::new(EngineErrorKind::Permanent),
            Duration::from_secs(60),
        );
        assert_eq!(permanent.result(), ReconcileResultLabel::Permanent);
        assert_eq!(permanent.error_kind(), Some(AttemptErrorKind::Permanent));

        let invariant = AttemptResult::from_error(
            &ReconcileError::new(EngineErrorKind::Invariant),
            Duration::from_secs(60),
        );
        assert_eq!(invariant.result(), ReconcileResultLabel::Invariant);
        assert_eq!(invariant.error_kind(), Some(AttemptErrorKind::Invariant));

        let panic = AttemptResult::from_panic(Duration::from_secs(1));
        assert_eq!(panic.result(), ReconcileResultLabel::Transient);
        assert_eq!(panic.error_kind(), Some(AttemptErrorKind::Transient));
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: spawned worker exits after the test token is cancelled.
    async fn reconcile_worker_lease_lost_before_attempt_does_not_run_or_release() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.lose_append_attempt();
        let reconciler = DurableScript::new(DurableBehavior::Settled);
        let calls = Arc::clone(&reconciler.calls);
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            reconciler,
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token.clone()));
        tokio::time::sleep(Duration::from_secs(1)).await;
        token.cancel();
        handle.await.expect("worker exits after cancellation");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.attempts, 1);
        assert_eq!(
            state.releases, 0,
            "lost append must not release stale lease"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fake store cancels the test token when renew returns Lost.
    async fn reconcile_worker_lease_lost_drops_in_flight_attempt() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.lose_extend_and_cancel(token.clone());
        let reconciler = PendingReconciler {
            entered: Arc::new(AtomicBool::new(false)),
        };
        let entered = Arc::clone(&reconciler.entered);
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            reconciler,
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token));
        tokio::time::sleep(Duration::from_secs(2)).await;
        handle.await.expect("worker exits after lease loss");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(entered.load(Ordering::SeqCst), "reconciler should start");
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 0, "lost lease must not be released again");
    }

    #[tokio::test]
    async fn reconcile_worker_marks_degraded_when_release_lost() {
        let store = FakeScheduleStore::default();
        store.set_release_outcome(ScheduleLeaseOutcome::Lost);
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        let health = worker.health();

        worker
            .release_lease_best_effort(&claimed_target(), "unit_test")
            .await;

        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .releases,
            1
        );
    }

    #[tokio::test]
    async fn reconcile_worker_marks_degraded_when_release_errors() {
        let store = FakeScheduleStore::default();
        store.fail_release();
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        let health = worker.health();

        worker
            .release_lease_best_effort(&claimed_target(), "unit_test")
            .await;

        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .releases,
            1
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: spawned worker should exit after fake store records the first result.
    async fn reconcile_worker_cancel_releases_remaining_claimed_batch_targets() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_targets([
            claimed_target(),
            claimed_target_with_ids(
                "44444444-4444-4444-4444-444444444444",
                "55555555-5555-5555-5555-555555555555",
                "device-2",
            ),
            claimed_target_with_ids(
                "66666666-6666-6666-6666-666666666666",
                "77777777-7777-7777-7777-777777777777",
                "device-3",
            ),
        ]);
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_batch_size(3)
        .expect("positive batch size")
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token));
        tokio::time::sleep(Duration::from_secs(1)).await;
        handle
            .await
            .expect("worker exits after first result cancels token");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.claims, 1);
        assert_eq!(state.attempts, 1);
        assert_eq!(
            state.releases, 3,
            "cancelled worker must release every already claimed target in the batch"
        );
    }

    /// 永不完成的 reconciler（验证取消/丢 lease 能 drop 在途 dispatch future——否则测试挂死）。
    struct PendingReconciler {
        entered: Arc<AtomicBool>,
    }

    impl Reconciler for PendingReconciler {
        async fn reconcile(
            &self,
            _ctx: &Context,
            _req: Request,
        ) -> Result<Outcome, ReconcileError> {
            self.entered.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await; // 永不返回；只能被 drop（取消）打断
            unreachable!("pending reconciler must be cancelled, never completes")
        }
    }

    impl DurableReconciler<FakeScheduleStore> for PendingReconciler {
        async fn reconcile(
            &self,
            _ctx: &Context,
            _target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<Outcome, ReconcileError> {
            self.entered.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
            unreachable!("pending durable reconciler must be cancelled, never completes")
        }
    }

    /// dispatch_once 测试 helper：返回 (NextAction, Arc<WorkerHealth>) 供健康状态断言。
    async fn dispatch_once_for(
        reconciler: &ScriptedReconciler,
        ctx: &Context,
        req: Request,
        attempts: &mut HashMap<Option<EntityId>, u32>,
    ) -> (NextAction, Arc<WorkerHealth>) {
        let backoff = BackoffPolicy::default();
        let health = Arc::new(WorkerHealth::healthy());
        let action = ReconcileLoop::<ScriptedReconciler>::dispatch_once(
            reconciler, &backoff, &health, ctx, req, attempts,
        )
        .await;
        (action, health)
    }

    // ── BackoffPolicy ──────────────────────────────────────────────────────────

    #[test]
    fn backoff_rejects_base_exceeding_cap() {
        assert!(matches!(
            BackoffPolicy::new(Duration::from_secs(2), Duration::from_secs(1)),
            Err(BackoffError::BaseExceedsCap { .. })
        ));
        assert!(BackoffPolicy::new(Duration::from_secs(1), Duration::from_secs(1)).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试断言已通过 new() 构造的合法策略，expect 仅为不应 panic 的固定策略构造。
    fn backoff_grows_exponentially_capped() {
        let p =
            BackoffPolicy::new(Duration::from_secs(1), Duration::from_secs(10)).expect("policy");
        assert_eq!(p.delay_for(0), Duration::from_secs(1)); // 0 次失败 = base（边界）
        assert_eq!(p.delay_for(1), Duration::from_secs(1)); // base
        assert_eq!(p.delay_for(2), Duration::from_secs(2)); // 2*base
        assert_eq!(p.delay_for(3), Duration::from_secs(4)); // 4*base
        assert_eq!(p.delay_for(4), Duration::from_secs(8)); // 8*base
        assert_eq!(p.delay_for(5), Duration::from_secs(10)); // 16*base 封顶 cap
        assert_eq!(p.delay_for(99), Duration::from_secs(10)); // 大 n 仍封顶（饱和不回绕）
    }

    // ── dispatch_once（核心决策，确定性无时钟）─────────────────────────────────

    #[tokio::test]
    async fn dispatch_settled_resets_backoff_and_idles() {
        let reconciler = ScriptedReconciler::new(Behavior::Settled);
        let mut attempts = HashMap::new();
        attempts.insert(None, 3); // 预置退避计数
        let ctx = Context::for_harness(None);
        let (action, health) =
            dispatch_once_for(&reconciler, &ctx, Request::default(), &mut attempts).await;
        assert_eq!(action, NextAction::Idle);
        assert!(!attempts.contains_key(&None), "收敛应清退避计数");
        assert_eq!(
            health.status(),
            HealthStatus::Healthy,
            "settled 应 mark_healthy"
        );
    }

    #[tokio::test]
    async fn dispatch_requeue_after_schedules_recheck() {
        let reconciler = ScriptedReconciler::new(Behavior::RequeueAfter(Duration::from_secs(30)));
        let mut attempts = HashMap::new();
        let ctx = Context::for_harness(None);
        let (action, _health) =
            dispatch_once_for(&reconciler, &ctx, Request::default(), &mut attempts).await;
        assert_eq!(action, NextAction::RequeueAfter(Duration::from_secs(30)));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: 测试断言已 is_ok 的 parse（canonical key），item-level carve-out（error-handling.md §Carve-out）。
    async fn dispatch_transient_backs_off_per_entity() {
        let reconciler = ScriptedReconciler::new(Behavior::Transient);
        let mut attempts = HashMap::new();
        let ctx = Context::for_harness(None);
        let id_a = EntityId::parse("device-a").expect("eid-a");
        let id_b = EntityId::parse("device-b").expect("eid-b");

        // entity-a 连续 2 次 transient → 第 2 次退避 = 2*base（独立计数）。
        let (a1, health_a1) = dispatch_once_for(
            &reconciler,
            &ctx,
            Request::for_entity(id_a.clone()),
            &mut attempts,
        )
        .await;
        let (a2, _) = dispatch_once_for(
            &reconciler,
            &ctx,
            Request::for_entity(id_a.clone()),
            &mut attempts,
        )
        .await;
        // entity-b 首次 transient → 退避 = base（与 a 隔离，证明 per-entity）。
        let (b1, health_b1) = dispatch_once_for(
            &reconciler,
            &ctx,
            Request::for_entity(id_b.clone()),
            &mut attempts,
        )
        .await;

        assert_eq!(a1, NextAction::RequeueAfter(Duration::from_secs(1)));
        assert_eq!(a2, NextAction::RequeueAfter(Duration::from_secs(2)));
        assert_eq!(b1, NextAction::RequeueAfter(Duration::from_secs(1)));
        assert_eq!(attempts.get(&Some(id_a)), Some(&2));
        assert_eq!(attempts.get(&Some(id_b)), Some(&1));
        assert_eq!(
            health_a1.status(),
            HealthStatus::Degraded,
            "transient 应 mark_degraded"
        );
        assert_eq!(
            health_b1.status(),
            HealthStatus::Degraded,
            "transient 应 mark_degraded"
        );
    }

    #[tokio::test]
    async fn dispatch_permanent_idles_without_backoff() {
        let reconciler = ScriptedReconciler::new(Behavior::Permanent);
        let mut attempts = HashMap::new();
        attempts.insert(None, 5);
        let ctx = Context::for_harness(None);
        let (action, health) =
            dispatch_once_for(&reconciler, &ctx, Request::default(), &mut attempts).await;
        // permanent 仅分类，不退避也不放弃下一步（等下个 tick 重驱动）。
        assert_eq!(action, NextAction::Idle);
        assert!(
            !attempts.contains_key(&None),
            "permanent 清退避（非 transient 序列）"
        );
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "permanent 应 mark_degraded"
        );
    }

    #[tokio::test]
    async fn dispatch_panic_maps_to_transient_backoff() {
        let reconciler = ScriptedReconciler::new(Behavior::Panic);
        let mut attempts = HashMap::new();
        let ctx = Context::for_harness(None);
        // 捕获 panic → transient 退避（环不挂；本调用正常返回）。
        let (action, health) =
            dispatch_once_for(&reconciler, &ctx, Request::default(), &mut attempts).await;
        assert_eq!(action, NextAction::RequeueAfter(Duration::from_secs(1)));
        assert_eq!(attempts.get(&None), Some(&1));
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "panic→transient 应 mark_degraded"
        );
    }

    #[tokio::test]
    async fn dispatch_injects_epoch_into_ctx() {
        let reconciler = ScriptedReconciler::new(Behavior::Settled);
        let mut attempts = HashMap::new();
        let ctx = Context::for_harness(Some(vocab::Epoch::new(5)));
        let _ = dispatch_once_for(&reconciler, &ctx, Request::default(), &mut attempts).await;
        let seen = reconciler
            .seen_epoch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(seen, vec![Some(vocab::Epoch::new(5))]);
    }

    // ── bump_attempts ────────────────────────────────────────────────────────

    #[test]
    fn bump_attempts_is_one_based_and_per_key() {
        let mut m = HashMap::new();
        assert_eq!(bump_attempts(&mut m, None), 1);
        assert_eq!(bump_attempts(&mut m, None), 2);
        let k = EntityId::parse("x").ok();
        assert_eq!(bump_attempts(&mut m, k), 1); // 独立 key 独立计数
    }

    // ── RECONCILE_PROBE ──────────────────────────────────────────────────────

    #[test]
    fn reconcile_probe_parses_and_has_no_ready_suffix() {
        assert!(ProbeName::parse(RECONCILE_PROBE).is_ok());
        assert!(!RECONCILE_PROBE.ends_with("_ready"));
    }

    // ── run（集成态，start_paused 控时 + token 取消）────────────────────────────

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: 断言已 is_ok 的构造路径，item-level carve-out。
    async fn run_single_process_dispatches_with_no_epoch_and_stops() {
        let token = CancellationToken::new();
        // 跑 2 次后自取消，epoch 应为 None（单进程无 leader）。
        let reconciler = ScriptedReconciler::cancelling(Behavior::Settled, 2, token.clone());
        let calls = Arc::clone(&reconciler.calls);
        let seen = Arc::clone(&reconciler.seen_epoch);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(10)).build();
        let health = loop_.health();
        loop_.run(token).await;
        assert!(calls.load(Ordering::SeqCst) >= 2, "应至少 dispatch 2 次");
        let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            seen.iter().all(|e| e.is_none()),
            "单进程 epoch 恒 None: {seen:?}"
        );
        assert_eq!(
            health.status(),
            HealthStatus::Unhealthy,
            "停后 mark_stopped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn run_leader_gated_dispatches_with_term_epoch() {
        let token = CancellationToken::new();
        let reconciler = ScriptedReconciler::cancelling(Behavior::Settled, 1, token.clone());
        let seen = Arc::clone(&reconciler.seen_epoch);
        let loop_ = Builder::new(reconciler, Tenancy::tenant_scoped(), trig(10)).build();
        loop_
            .run_with_leader(Arc::new(AlwaysLeader(7)), token)
            .await;
        let seen = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(
            seen.iter().any(|e| *e == Some(vocab::Epoch::new(7))),
            "leader 任期 epoch 应注入 ctx: {seen:?}"
        );
    }

    /// 验证：run_not_leader_never_dispatches
    ///
    /// start_paused 使 tokio 时间不自动推进；sleep(60s) 在单线程 executor 下不引入真实墙钟等待——
    /// advance 仅由此 test 驱动，NeverLeader 返回 Ok(None) 使 leader_gated 做 LEASE_TTL(15s) 的
    /// wait_or_cancel，每次 tick 推进 60s 足以让 loop 经历多轮 standby 而不 dispatch。
    #[tokio::test(start_paused = true)]
    async fn run_not_leader_never_dispatches() {
        let token = CancellationToken::new();
        let reconciler = ScriptedReconciler::new(Behavior::Settled);
        let calls = Arc::clone(&reconciler.calls);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(10)).build();
        // 非 leader：跑一会儿后取消，应零 dispatch（leader-gated）。
        // start_paused 单线程下确定性：sleep 不消耗真实时间，cancel 后 loop 必然在 wait_or_cancel 退出。
        let handle = tokio::spawn(loop_.run_with_leader(Arc::new(NeverLeader), token.clone()));
        tokio::time::sleep(Duration::from_secs(60)).await;
        token.cancel();
        let _ = handle.await;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "非 leader 不得 dispatch");
    }

    // ── leader 任期：丢 lease → select-drop 取消在途 dispatch ──────────────────

    /// 验证 reconcile.md §Leader-elect「丢 lease 取消在途 reconcile」承诺：
    /// RenewOnceLeader 第 2 次续租返 Ok(None)，renew_until_lost 取消 scope，
    /// dispatch_loop 被 select! drop，calls 停止增长。
    #[tokio::test(start_paused = true)]
    async fn lead_term_lease_lost_cancels_dispatch() {
        let token = CancellationToken::new();
        // 使用 SeqReconciler：第 1 次 dispatch 后取消外部 token（驱动测试退出），
        // 同时 RenewOnceLeader 在 RENEW_INTERVAL 后丢 lease → scope cancel。
        // 取消 token 后外层 leader_gated 也结束。
        let reconciler = SeqReconciler::new(
            Behavior::Settled,
            Behavior::Settled,
            1,
            Some((1, token.clone())),
        );
        let calls = Arc::clone(&reconciler.calls);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(5)).build();
        let leader = Arc::new(RenewOnceLeader::new());
        loop_.run_with_leader(leader, token).await;
        // dispatch 至多 1 次（第 1 次 dispatch 后取消，丢 lease 保证不再 dispatch）。
        assert!(
            calls.load(Ordering::SeqCst) <= 1,
            "丢 lease 后不应再 dispatch，calls={}",
            calls.load(Ordering::SeqCst)
        );
    }

    // ── renew_until_lost Err 分支 fail-closed ──────────────────────────────────

    /// 验证：renew 时 Err（infra 故障）与 Ok(None)（丢 lease）同样触发 scope cancel → dispatch 停止。
    #[tokio::test(start_paused = true)]
    async fn lead_term_renew_err_cancels_dispatch() {
        let token = CancellationToken::new();
        let reconciler = SeqReconciler::new(
            Behavior::Settled,
            Behavior::Settled,
            1,
            Some((1, token.clone())),
        );
        let calls = Arc::clone(&reconciler.calls);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(5)).build();
        let leader = Arc::new(ErrorOnRenewLeader::new());
        loop_.run_with_leader(leader, token).await;
        assert!(
            calls.load(Ordering::SeqCst) <= 1,
            "renew Err 应 fail-closed 停止 dispatch，calls={}",
            calls.load(Ordering::SeqCst)
        );
    }

    // ── requeue_after loop 级回归 ────────────────────────────────────────────

    /// 验证 dispatch_loop 的 sleep_or_pending(requeue) 在 d 后真正驱动了二次 dispatch：
    /// 第 1 次返 requeue_after(30s)，第 2 次返 Settled 并取消 token，assertions calls >= 2。
    #[tokio::test(start_paused = true)]
    async fn dispatch_loop_requeue_after_drives_second_dispatch() {
        let token = CancellationToken::new();
        // switch_after=1：第 1 次 RequeueAfter(30s)，第 2 次起 Settled；第 2 次时取消。
        let reconciler = SeqReconciler::new(
            Behavior::RequeueAfter(Duration::from_secs(30)),
            Behavior::Settled,
            1,
            Some((2, token.clone())),
        );
        let calls = Arc::clone(&reconciler.calls);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(60)).build();
        loop_.run(token).await;
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "requeue_after 应在 30s 后触发第二次 dispatch，calls={}",
            calls.load(Ordering::SeqCst)
        );
    }

    // ── F4：Trigger 零周期 fail-fast ──────────────────────────────────────────

    /// `Trigger::interval(0)` → `Err(ZeroInterval)`（构造期拒，杜绝 tokio interval 运行期 panic）；非零 → Ok。
    #[test]
    fn trigger_interval_rejects_zero() {
        assert!(matches!(
            Trigger::interval(Duration::ZERO),
            Err(TriggerError::ZeroInterval)
        ));
        assert!(Trigger::interval(Duration::from_secs(1)).is_ok());
    }

    // ── F3：取消 / 丢 lease 丢弃在途 pending dispatch ──────────────────────────

    /// 单进程 `run`：root cancel 须 drop 在途 reconcile（`dispatch_once` 与 cancel 同层 select）。
    /// PendingReconciler 永挂——F3 未修则 `run` 卡在 `dispatch_once().await`、`handle.await` 永不返回（测试超时）。
    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: 断言 spawn handle join，item-level carve-out。
    async fn run_cancels_in_flight_pending_dispatch() {
        let entered = Arc::new(AtomicBool::new(false));
        let reconciler = PendingReconciler {
            entered: Arc::clone(&entered),
        };
        let token = CancellationToken::new();
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(10)).build();
        let handle = tokio::spawn(loop_.run(token.clone()));
        // 让 spawn 的 loop 跑到首 tick → 进入在途 pending reconcile（start_paused：sleep 推进虚拟时间）。
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(entered.load(Ordering::SeqCst), "应已进入在途 reconcile");
        token.cancel();
        handle
            .await
            .expect("run 应在取消后返回（在途 pending dispatch 被 select-drop）");
    }

    /// 多副本：丢 lease 须 drop 在途 pending dispatch（renew_until_lost cancel scope → lead_term select-drop）。
    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: 断言 spawn handle join，item-level carve-out。
    async fn lease_lost_drops_in_flight_pending_dispatch() {
        let entered = Arc::new(AtomicBool::new(false));
        let reconciler = PendingReconciler {
            entered: Arc::clone(&entered),
        };
        let token = CancellationToken::new();
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(60)).build();
        let leader = Arc::new(RenewOnceLeader::new());
        let handle = tokio::spawn(loop_.run_with_leader(leader, token.clone()));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(entered.load(Ordering::SeqCst), "应已进入在途 reconcile");
        // 推进过 RENEW_INTERVAL：RenewOnceLeader 第 2 次 acquire 返 None → scope cancel → drop 在途 pending dispatch。
        tokio::time::sleep(RENEW_INTERVAL + Duration::from_secs(1)).await;
        token.cancel(); // 丢 lease 后回 standby，cancel root 结束 loop
        handle
            .await
            .expect("丢 lease 应 drop 在途 pending dispatch，loop 取消后返回");
    }
}
