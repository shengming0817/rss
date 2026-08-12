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
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use consistency::{
    Context, ConvergeAction, EntityId, Outcome, ReconcileError, ReconcileResultLabel, Reconciler,
    Request,
};
use diport::{
    EnvelopeCausationId, EnvelopeSubjectId, LeaderElector, OpaqueActorId, OutboxActor,
    OutboxEnvelopeParts, RedactedSource,
};
use futures::FutureExt;
use futures::stream::{FuturesUnordered, StreamExt};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::WorkerHealth;
use crate::command::{
    CommandEmitError, CommandIdempotencyKeyring, ReviewedCommandIntent, reviewed_keyed_intent,
};
use crate::worker_control::WorkerDrainObservation;

/// Exact generated fenced carrier for `identity.apply-device-certificate`.
///
/// The alias lets fault-harness adapters consume the real sealed carrier through the eventexec
/// boundary without adding an Adapter→Generated dependency edge.
pub type ApplyDeviceCertificateReconcileCommand =
    generated::command::identity_v1::FencedReconcileCommand;

const DEVICE_CERTIFICATE_RECONCILER_ID: &str = "identity.device-certificate";
const DEVICE_CERTIFICATE_RESOURCE_KIND: &str = "device-certificate";
const DEVICE_CERTIFICATE_PRODUCER_ACTOR_ID: &str = "rss.reconcile.device-certificate.v1";
const FENCED_COMMAND_KEY_DOMAIN: &str = "rss-device-command-v1";
const FENCED_INTENT_DIGEST_DOMAIN: &str = "rss-fenced-intent-v1";
const MAX_FENCED_DEADLINE_EPOCH_SECONDS: u64 = i64::MAX as u64 / 1_000_000;

/// readyz probe 名（无 `_ready` 后缀，对齐 relay probe 约定）。
pub const RECONCILE_PROBE: &str = "reconcile";

/// lease TTL：holder 须在此时长内续租，超时未续 ⇒ 他副本可接管（epoch 递增）。
const LEASE_TTL: Duration = Duration::from_secs(15);
/// 续租轮询间隔（< `LEASE_TTL`，留续租裕度）。
const RENEW_INTERVAL: Duration = Duration::from_secs(5);
/// Local exact-target notifications are bounded and remain a latency optimization only.
const TARGETED_WAKE_BUFFER: usize = 64;

// ── Durable scheduler API（PG-backed scheduler + command outbox seam）────────

/// Durable reconcile scheduler storage failure.
///
/// Display is intentionally constant; provider errors stay redacted behind [`RedactedSource`].
#[derive(Debug, thiserror::Error)]
#[error("reconcile schedule store operation failed")]
pub struct ReconcileScheduleError {
    kind: ReconcileScheduleErrorKind,
    #[source]
    source: RedactedSource,
}

/// Closed, payload-free scheduler failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileScheduleErrorKind {
    /// Durable scheduler provider failed.
    Infrastructure,
    /// An action event id already names a different durable fact.
    FactConflict,
    /// The generated request carries a permanently invalid semantic fact.
    PermanentFailure,
    /// Runtime/generated authority coordinates violate an internal invariant.
    InvariantViolation,
}

impl ReconcileScheduleError {
    /// Wrap a provider/storage error without exposing its Display text to callers.
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind: ReconcileScheduleErrorKind::Infrastructure,
            source: RedactedSource::new(source),
        }
    }

    /// Preserve a typed outbox fact conflict without exposing fact material.
    pub fn fact_conflict(source: consistency::OutboxFactConflict) -> Self {
        Self {
            kind: ReconcileScheduleErrorKind::FactConflict,
            source: RedactedSource::new(source),
        }
    }

    fn fenced_review(source: FencedCommandReviewError) -> Self {
        let kind = match source {
            FencedCommandReviewError::Digest | FencedCommandReviewError::DeadlineRange => {
                ReconcileScheduleErrorKind::PermanentFailure
            }
            FencedCommandReviewError::Scope
            | FencedCommandReviewError::Fence
            | FencedCommandReviewError::Causation
            | FencedCommandReviewError::RequestEncoding
            | FencedCommandReviewError::ProducerIdentity
            | FencedCommandReviewError::CoordinateRange => {
                ReconcileScheduleErrorKind::InvariantViolation
            }
        };
        Self {
            kind,
            source: RedactedSource::new(source),
        }
    }

    /// Return the closed failure classification.
    pub const fn kind(&self) -> ReconcileScheduleErrorKind {
        self.kind
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
    /// Maximum in-flight attempts must be in the closed range `1..=64`.
    #[error("reconcile max in-flight must be between 1 and 64")]
    MaxInFlightOutOfRange,
}

/// Validated hard bound for concurrently running reconcile attempts; defaults to `16`.
///
/// INVARIANT: RECONCILE-MAX-IN-FLIGHT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private field plus sole validated constructor and typed provider boundary" }: configuration is closed to `1..=64`, and the builder plus [`ReconcileScheduleStore`] carry this type unchanged. The boundary and compile-fail tests prove this Hard half. A provider can still violate its runtime return contract; that blind spot is contained by the scheduler's Medium admission invariant, which degrades and CAS releases excess claims without starting attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileMaxInFlight(u8);

impl ReconcileMaxInFlight {
    /// Construct a concurrency bound in the closed range `1..=64`.
    pub fn try_new(value: usize) -> Result<Self, ReconcileConfigError> {
        if value == 0 || value > 64 {
            return Err(ReconcileConfigError::MaxInFlightOutOfRange);
        }
        let Ok(value) = u8::try_from(value) else {
            return Err(ReconcileConfigError::MaxInFlightOutOfRange);
        };
        Ok(Self(value))
    }

    /// Return the validated concurrency bound.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl Default for ReconcileMaxInFlight {
    fn default() -> Self {
        Self(16)
    }
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

/// Closed operation label for durable DeviceLatent lease observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseOperation {
    /// Acquire one due or targeted lease.
    Claim,
    /// Renew one currently held lease.
    Extend,
    /// Release one lease without mutating reconcile state.
    Release,
}

impl LeaseOperation {
    /// Stable low-cardinality metric/log label.
    const fn as_label(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Extend => "extend",
            Self::Release => "release",
        }
    }
}

/// Closed result label for a durable DeviceLatent lease operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseState {
    /// The exact lease fence is held after the operation.
    Held,
    /// The operation did not hold the exact lease fence.
    Lost,
    /// The provider operation failed without exposing provider error text as a label.
    Error,
}

impl LeaseState {
    /// Stable low-cardinality metric/log label.
    const fn as_label(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::Lost => "lost",
            Self::Error => "error",
        }
    }
}

/// Closed context label for durable DeviceLatent lease observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaseReason {
    /// Periodic due-target scan.
    DueScan,
    /// Exact-target wake optimization.
    TargetedWake,
    /// Periodic renewal while an attempt is running.
    Renewal,
    /// The active attempt was cancelled.
    AttemptCancelled,
    /// Attempt evidence could not be appended.
    AppendAttemptFailed,
    /// Terminal attempt evidence could not be recorded.
    AttemptResultRecordFailed,
    /// A newer replacement displaced an unstarted replacement.
    SupersededReplacement,
    /// A returned claim carried an older fence.
    StaleGeneration,
    /// Admission capacity or worker state rejected a claim.
    ClaimNotAdmitted,
    /// Shutdown prevented a replacement from starting.
    ShutdownBeforeReplacement,
    /// Pause prevented a replacement from starting.
    PauseBeforeReplacement,
    /// A queued replacement was no longer runnable after its predecessor completed.
    ReplacementNotStarted,
}

impl LeaseReason {
    /// Stable low-cardinality metric/log label.
    const fn as_label(self) -> &'static str {
        match self {
            Self::DueScan => "due_scan",
            Self::TargetedWake => "targeted_wake",
            Self::Renewal => "renewal",
            Self::AttemptCancelled => "attempt_cancelled",
            Self::AppendAttemptFailed => "append_attempt_failed",
            Self::AttemptResultRecordFailed => "attempt_result_record_failed",
            Self::SupersededReplacement => "superseded_replacement",
            Self::StaleGeneration => "stale_generation",
            Self::ClaimNotAdmitted => "claim_not_admitted",
            Self::ShutdownBeforeReplacement => "shutdown_before_replacement",
            Self::PauseBeforeReplacement => "pause_before_replacement",
            Self::ReplacementNotStarted => "replacement_not_started",
        }
    }
}

/// Durable terminal-result transaction outcome.
#[must_use = "result outcomes must be matched so superseded wakes and lost leases are observed"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleResultOutcome {
    /// Result, target schedule transition, and lease release committed atomically.
    Recorded,
    /// Result and lease release committed, but a newer durable wake preserved the due target.
    WakeSuperseded,
    /// The attempt lease was no longer held, so no result was recorded.
    Lost,
}

/// Persisted consecutive retryable-failure count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FailureStreak(u32);

impl FailureStreak {
    /// Restore the exact provider value.
    #[must_use]
    pub const fn restore(raw: u32) -> Self {
        Self(raw)
    }

    /// Provider representation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Advance one retryable failure, saturating rather than wrapping.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Invalid durable wake version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WakeVersionError {
    /// Wake versions must fit the nonnegative signed database range.
    #[error("wake version must be in 0..=i64::MAX")]
    OutOfRange,
    /// The monotonic wake version cannot advance beyond the database maximum.
    #[error("wake version cannot advance beyond i64::MAX")]
    Exhausted,
}

/// Monotonic durable exact-target wake version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WakeVersion(u64);

impl WakeVersion {
    /// Validate a provider/domain value.
    pub fn try_new(raw: u64) -> Result<Self, WakeVersionError> {
        (raw <= i64::MAX as u64)
            .then_some(Self(raw))
            .ok_or(WakeVersionError::OutOfRange)
    }

    /// Restore a signed database value.
    pub fn restore(raw: i64) -> Result<Self, WakeVersionError> {
        u64::try_from(raw)
            .map_err(|_| WakeVersionError::OutOfRange)
            .and_then(Self::try_new)
    }

    /// Provider representation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advance the durable wake version.
    pub fn next(self) -> Result<Self, WakeVersionError> {
        self.0
            .checked_add(1)
            .filter(|raw| *raw <= i64::MAX as u64)
            .map(Self)
            .ok_or(WakeVersionError::Exhausted)
    }
}

/// Non-authorizing hint that one exact durable target has a newer due wake.
///
/// The worker/store must re-check tenant, reconciler, target status, version, and lease state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileWake {
    target_id: String,
    version: WakeVersion,
}

impl ReconcileWake {
    /// Build a post-commit latency hint from provider-owned target state.
    #[must_use]
    pub fn new(target_id: impl Into<String>, version: WakeVersion) -> Self {
        Self {
            target_id: target_id.into(),
            version,
        }
    }

    /// Opaque durable target identity. This is not an authorization coordinate.
    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Durable version the notifier observed after commit.
    #[must_use]
    pub const fn version(&self) -> WakeVersion {
        self.version
    }
}

/// Closed, payload-free reason for persistently disabling a reconcile target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileQuarantineReason {
    /// The stable event id is already bound to a different outbox fact.
    FactConflict,
    /// A non-retryable reconcile failure requires operator remediation.
    PermanentFailure,
    /// A reconcile invariant was violated and automatic retries are unsafe.
    InvariantViolation,
}

/// Reviewed capability for tenant-scoped reconcile target inspection and recovery.
///
/// Only an authenticated operator boundary may issue this zero-sized token. Keeping it mandatory
/// on the mutation/read port makes omission fail to compile; `rss_operator_authorization_callsite` limits
/// the public issuing funnel to reviewed admin/PDP wrappers.
#[derive(Debug, Clone, Copy)]
pub struct OperatorReconcileCapability {
    _private: (),
}

impl OperatorReconcileCapability {
    /// Issue the capability after service-principal authentication, tenant authorization and
    /// start-audit recording have all succeeded.
    pub fn issue_for_authorized_operator() -> Self {
        Self { _private: () }
    }
}

/// Durable reconcile target state exposed to the operator control boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileTargetStatus {
    /// The scheduler may claim the target.
    Active,
    /// The scheduler must skip the target until an authorized resume.
    Disabled,
}

impl ReconcileTargetStatus {
    /// Stable wire/log label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// Payload-free reconcile target inspection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileTargetSummary {
    tenant: rss_request_context::TenantId,
    target_id: String,
    reconciler_id: String,
    resource_kind: String,
    status: ReconcileTargetStatus,
    disabled_reason: Option<ReconcileQuarantineReason>,
}

impl ReconcileTargetSummary {
    /// Construct a validated provider result.
    pub fn new(
        tenant: rss_request_context::TenantId,
        target_id: String,
        reconciler_id: String,
        resource_kind: String,
        status: ReconcileTargetStatus,
        disabled_reason: Option<ReconcileQuarantineReason>,
    ) -> Result<Self, ReconcileScheduleError> {
        if status == ReconcileTargetStatus::Active && disabled_reason.is_some() {
            return Err(ReconcileScheduleError::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "active reconcile target has a disabled reason",
            )));
        }
        Ok(Self {
            tenant,
            target_id,
            reconciler_id,
            resource_kind,
            status,
            disabled_reason,
        })
    }

    /// Owning tenant.
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    /// Opaque target UUID.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Reconciler namespace.
    pub fn reconciler_id(&self) -> &str {
        &self.reconciler_id
    }

    /// Resource kind; the resource identifier is intentionally not exposed.
    pub fn resource_kind(&self) -> &str {
        &self.resource_kind
    }

    /// Current scheduler state.
    pub fn status(&self) -> ReconcileTargetStatus {
        self.status
    }

    /// Closed quarantine reason, when the target was disabled by the scheduler.
    pub fn disabled_reason(&self) -> Option<ReconcileQuarantineReason> {
        self.disabled_reason
    }
}

impl ReconcileQuarantineReason {
    /// Stable low-cardinality log/UI label.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::FactConflict => "fact_conflict",
            Self::PermanentFailure => "permanent_failure",
            Self::InvariantViolation => "invariant_violation",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::FactConflict => 1,
            Self::PermanentFailure => 2,
            Self::InvariantViolation => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::FactConflict),
            2 => Some(Self::PermanentFailure),
            3 => Some(Self::InvariantViolation),
            _ => None,
        }
    }
}

/// Atomic action/outbox write result under the target lease.
#[must_use = "action outcomes must be matched so Lost is handled explicitly"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleActionOutcome {
    /// Action and command outbox fact were committed.
    Enqueued,
    /// The exact fenced command fact was already committed.
    Duplicate,
    /// The target lease was no longer held.
    Lost,
}

/// Provider result for the certificate-deletion terminal transaction.
#[must_use = "completion outcomes must be matched so evidence and lost leases fail closed"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleCompletionOutcome {
    /// Terminal evidence, finalizer release, target disable, attempt result, and lease release
    /// committed atomically.
    Completed,
    /// At least one retained authorized artifact was neither revoked nor expired.
    EvidencePending,
    /// The attempt no longer held the exact target lease/wake fence.
    Lost,
}

/// Unforgeable proof that an attempt result was already committed by the provider transaction.
pub struct AttemptCompletionReceipt {
    attempt_id: String,
    target_id: String,
}

impl std::fmt::Debug for AttemptCompletionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttemptCompletionReceipt(<sealed>)")
    }
}

/// Attempt-scoped completion classification returned to a durable reconciler.
#[must_use = "completed receipts must be returned as a durable reconcile outcome"]
#[derive(Debug)]
pub enum AttemptCompletionOutcome {
    /// The complete terminal transaction committed and produced a linear receipt.
    Completed(AttemptCompletionReceipt),
    /// Revocation or authoritative expiry evidence is not yet complete.
    EvidencePending,
    /// The attempt lost its lease before any completion mutation committed.
    Lost,
}

/// Closed result of an eventexec durable reconciler.
#[derive(Debug)]
pub enum DurableReconcileOutcome {
    /// Scheduler still owns terminal attempt-result persistence and the next target schedule.
    Schedule(Outcome),
    /// A specialized attempt-scoped transaction already persisted the terminal result.
    Completed(AttemptCompletionReceipt),
}

impl DurableReconcileOutcome {
    /// Healthy convergence with the normal periodic resync fallback.
    #[must_use]
    pub fn settled() -> Self {
        Self::Schedule(Outcome::settled())
    }

    /// Healthy convergence that requests a bounded earlier recheck.
    #[must_use]
    pub fn requeue_after(after: Duration) -> Self {
        Self::Schedule(Outcome::requeue_after(after))
    }

    /// Consume the only receipt capable of suppressing duplicate attempt-result persistence.
    #[must_use]
    pub fn completed(receipt: AttemptCompletionReceipt) -> Self {
        Self::Completed(receipt)
    }
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
}

/// Durable target claimed by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedTarget {
    tenant: rss_request_context::TenantId,
    target_id: String,
    lease_token: String,
    epoch: u64,
    reconciler_id: String,
    resource_kind: String,
    resource_id: String,
    failure_streak: FailureStreak,
    wake_version: WakeVersion,
    trigger: AttemptTrigger,
}

/// Named provider restore values for one durably claimed target.
///
/// Public fields make identity, lease fence, and schedule coordinates explicit at adapter
/// boundaries so same-typed strings and integers cannot be exchanged positionally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedTargetRestore {
    // Target identity.
    /// Owning authenticated tenant.
    pub tenant: rss_request_context::TenantId,
    /// Opaque durable target identity.
    pub target_id: String,
    /// Reconciler namespace.
    pub reconciler_id: String,
    /// Resource kind within the reconciler.
    pub resource_kind: String,
    /// Opaque resource identity.
    pub resource_id: String,
    // Lease fence.
    /// Current provider-issued lease token.
    pub lease_token: String,
    /// Target-local monotonic lease epoch.
    pub epoch: u64,
    // Durable schedule snapshot.
    /// Consecutive retryable failures observed by the claim.
    pub failure_streak: FailureStreak,
    /// Wake version captured by the claim.
    pub wake_version: WakeVersion,
    /// Auditable reason this target was claimed.
    pub trigger: AttemptTrigger,
}

impl ClaimedTarget {
    /// Restore a claimed target from explicit provider claim-row coordinates.
    #[must_use]
    pub fn restore(input: ClaimedTargetRestore) -> Self {
        Self {
            tenant: input.tenant,
            target_id: input.target_id,
            lease_token: input.lease_token,
            epoch: input.epoch,
            reconciler_id: input.reconciler_id,
            resource_kind: input.resource_kind,
            resource_id: input.resource_id,
            failure_streak: input.failure_streak,
            wake_version: input.wake_version,
            trigger: input.trigger,
        }
    }

    /// Target tenant.
    pub fn tenant(&self) -> rss_request_context::TenantId {
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

    /// Durable consecutive retryable failures observed by this claim.
    #[must_use]
    pub const fn failure_streak(&self) -> FailureStreak {
        self.failure_streak
    }

    /// Durable wake version captured by this claim and its attempt.
    #[must_use]
    pub const fn wake_version(&self) -> WakeVersion {
        self.wake_version
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

/// Closed target transition requested by a terminal attempt result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptSchedule {
    /// Keep the target active and make it due after this delay.
    After(Duration),
    /// Disable the target with one closed operator-visible reason.
    Quarantine(ReconcileQuarantineReason),
}

/// Terminal attempt result persisted separately from action ledger rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptResult {
    result: ReconcileResultLabel,
    error_kind: Option<AttemptErrorKind>,
    requeue_after: Option<Duration>,
    schedule: AttemptSchedule,
}

impl AttemptResult {
    /// Successful outcome result.
    pub fn from_outcome(outcome: &Outcome, default_next_run_after: Duration) -> Self {
        let requeue_after = outcome.requeue_interval();
        Self {
            result: ReconcileResultLabel::from_outcome(outcome),
            error_kind: None,
            requeue_after,
            schedule: AttemptSchedule::After(requeue_after.unwrap_or(default_next_run_after)),
        }
    }

    fn from_transient(transient_after: Duration) -> Self {
        Self {
            result: ReconcileResultLabel::Transient,
            error_kind: Some(AttemptErrorKind::Transient),
            requeue_after: None,
            schedule: AttemptSchedule::After(transient_after),
        }
    }

    fn from_permanent() -> Self {
        Self {
            result: ReconcileResultLabel::Permanent,
            error_kind: Some(AttemptErrorKind::Permanent),
            requeue_after: None,
            schedule: AttemptSchedule::Quarantine(ReconcileQuarantineReason::PermanentFailure),
        }
    }

    fn from_invariant() -> Self {
        Self {
            result: ReconcileResultLabel::Invariant,
            error_kind: Some(AttemptErrorKind::Invariant),
            requeue_after: None,
            schedule: AttemptSchedule::Quarantine(ReconcileQuarantineReason::InvariantViolation),
        }
    }

    /// Panic is mapped to transient by the reconcile harness contract.
    pub fn from_panic(next_run_after: Duration) -> Self {
        Self {
            result: ReconcileResultLabel::from_panic(),
            error_kind: Some(AttemptErrorKind::Transient),
            requeue_after: None,
            schedule: AttemptSchedule::After(next_run_after),
        }
    }

    fn from_quarantine(reason: ReconcileQuarantineReason) -> Self {
        Self {
            result: ReconcileResultLabel::Invariant,
            error_kind: Some(AttemptErrorKind::Invariant),
            requeue_after: None,
            schedule: AttemptSchedule::Quarantine(reason),
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

    /// Closed schedule transition applied atomically with result recording and lease release.
    #[must_use]
    pub const fn schedule(&self) -> AttemptSchedule {
        self.schedule
    }
}

/// Closed installation token for the device-certificate background producer.
///
/// The token is intentionally zero-sized and accepts no actor, subject, tenant, holder, or caller
/// input. Runtime command authoring therefore always derives the same logical service actor.
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceCertificateSystemProducer {
    _seal: (),
}

/// Non-cloneable command draft reviewed against one exact reconcile attempt.
///
/// This value proves only that the command coordinates are well-formed and bound to the captured
/// attempt target and fence. It is deliberately **not** artifact authorization: the persistence
/// provider must exact-check the immutable authorized-artifact receipt in the same transaction
/// that records the command, action, journal claim, and outbox fact.
///
/// Fields and construction are private. A draft can only be obtained from
/// [`AttemptScope::review_device_certificate_command`] and is consumed by
/// [`AttemptScope::record_device_certificate_command`].
pub struct AttemptReviewedDeviceCertificateCommand {
    attempt_id: String,
    command: ApplyDeviceCertificateReconcileCommand,
}

impl std::fmt::Debug for AttemptReviewedDeviceCertificateCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttemptReviewedDeviceCertificateCommand(<redacted>)")
    }
}

/// Invalid validated device-certificate command lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device-certificate command TTL must be positive whole seconds")]
pub struct DeviceCertificateCommandTtlError;

/// Positive whole-second command lifetime used only inside an attempt scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCertificateCommandTtl(std::num::NonZeroU64);

impl DeviceCertificateCommandTtl {
    /// Validate a bounded whole-second TTL.
    pub fn try_new(value: Duration) -> Result<Self, DeviceCertificateCommandTtlError> {
        if value.subsec_nanos() != 0 {
            return Err(DeviceCertificateCommandTtlError);
        }
        let seconds = std::num::NonZeroU64::new(value.as_secs())
            .filter(|seconds| seconds.get() <= i64::MAX as u64)
            .ok_or(DeviceCertificateCommandTtlError)?;
        Ok(Self(seconds))
    }

    /// Validated TTL seconds.
    pub const fn seconds(self) -> u64 {
        self.0.get()
    }
}

struct DeviceCertificateCommand {
    device_id: uuid::Uuid,
    desired_generation: std::num::NonZeroU64,
    artifact_id: generated::command::identity_v1::IdentityApplyDeviceCertificateRequestArtifactId,
    artifact_digest:
        generated::command::identity_v1::IdentityApplyDeviceCertificateRequestArtifactDigest,
    policy_hash: generated::command::identity_v1::IdentityApplyDeviceCertificateRequestPolicyHash,
    deadline_epoch_seconds: std::num::NonZeroU64,
}

impl DeviceCertificateCommand {
    fn from_coordinates(
        device_id: uuid::Uuid,
        desired_generation: std::num::NonZeroU64,
        artifact_id: generated::command::identity_v1::IdentityApplyDeviceCertificateRequestArtifactId,
        artifact_digest: [u8; 32],
        policy_hash: [u8; 32],
        deadline_epoch_seconds: std::num::NonZeroU64,
    ) -> Result<Self, FencedCommandReviewError> {
        Ok(Self {
            device_id,
            desired_generation,
            artifact_id,
            artifact_digest: sha256_label(&artifact_digest)
                .as_str()
                .try_into()
                .map_err(|_| FencedCommandReviewError::RequestEncoding)?,
            policy_hash: sha256_label(&policy_hash)
                .as_str()
                .try_into()
                .map_err(|_| FencedCommandReviewError::RequestEncoding)?,
            deadline_epoch_seconds,
        })
    }

    fn into_fenced_command(
        self,
        fence_epoch: u64,
    ) -> Result<ApplyDeviceCertificateReconcileCommand, FencedCommandReviewError> {
        let fence_epoch = std::num::NonZeroU64::new(fence_epoch)
            .ok_or(FencedCommandReviewError::CoordinateRange)?;
        let mut semantic_value = serde_json::json!({
            "artifactDigest": self.artifact_digest.as_str(),
            "artifactId": self.artifact_id.as_str(),
            "deadlineEpochSeconds": self.deadline_epoch_seconds,
            "desiredGeneration": self.desired_generation,
            "deviceId": self.device_id,
            "fenceEpoch": fence_epoch,
            "intentDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "policyHash": self.policy_hash.as_str(),
        });
        let digest = canonical_fenced_intent_digest_value(
            semantic_value.clone(),
            generated::command::identity_v1::SPEC,
        )?;
        semantic_value["intentDigest"] = serde_json::Value::String(sha256_label(&digest));
        let request = serde_json::from_value(semantic_value)
            .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
        Ok(generated::command::identity_v1::fenced_reconcile_command(
            request,
        ))
    }
}

impl DeviceCertificateSystemProducer {
    /// Install the only producer identity accepted by the fenced scheduler seam.
    #[must_use]
    pub const fn install() -> Self {
        Self { _seal: () }
    }

    fn actor(self) -> Result<OutboxActor, CommandEmitError> {
        OpaqueActorId::from_opaque(DEVICE_CERTIFICATE_PRODUCER_ACTOR_ID)
            .map(OutboxActor::service)
            .map_err(|_| CommandEmitError::Serialization)
    }
}

/// Payload-free audit coordinates carried beside one reviewed fenced command.
///
/// The provider persists these facts through the command aggregate, attempt/action ledger, and
/// outbox metadata. Fields stay private so callers cannot forge a different producer or scope.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceCommandAuditProof {
    tenant: rss_request_context::TenantId,
    device_id: uuid::Uuid,
    desired_generation: PersistableDesiredGeneration,
    fence_epoch: PersistableFenceEpoch,
    intent_digest: [u8; 32],
    producer_actor_id: &'static str,
    attempt_id: String,
}

macro_rules! persistable_positive_i64 {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(i64);

        impl $name {
            fn try_from_u64(raw: u64) -> Option<Self> {
                i64::try_from(raw).ok().filter(|value| *value > 0).map(Self)
            }

            fn try_from_i64(raw: i64) -> Option<Self> {
                (raw > 0).then_some(Self(raw))
            }

            /// Return the signed value already proven safe for persistent integer storage.
            pub const fn get(self) -> i64 {
                self.0
            }
        }
    };
}

persistable_positive_i64!(
    PersistableDesiredGeneration,
    "A positive desired generation proven to fit the persistent signed-integer domain."
);
persistable_positive_i64!(
    PersistableFenceEpoch,
    "A positive fence epoch proven to fit the persistent signed-integer domain."
);

/// Absolute command deadline proven safe for canonical microsecond and PostgreSQL timestamp storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersistableCommandDeadlineEpochSeconds(i64);

impl PersistableCommandDeadlineEpochSeconds {
    fn try_from_u64(raw: u64) -> Option<Self> {
        (1..=MAX_FENCED_DEADLINE_EPOCH_SECONDS)
            .contains(&raw)
            .then_some(raw)
            .and_then(|value| i64::try_from(value).ok())
            .map(Self)
    }

    fn try_from_i64(raw: i64) -> Option<Self> {
        u64::try_from(raw).ok().and_then(Self::try_from_u64)
    }

    /// Return the signed epoch seconds already proven safe for persistent timestamp storage.
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl std::fmt::Debug for DeviceCommandAuditProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceCommandAuditProof(<redacted>)")
    }
}

/// Payload-free rejection while reconstructing a durable command audit proof.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("durable device command audit proof is invalid")]
pub struct DeviceCommandAuditProofRestoreError;

impl DeviceCommandAuditProof {
    /// Restore a proof from provider-owned durable coordinates.
    ///
    /// The producer actor is deliberately not an argument: durable reconstruction binds the same
    /// closed system identity as live command review.
    #[doc(hidden)]
    pub fn restore_durable(
        tenant: rss_request_context::TenantId,
        device_id: uuid::Uuid,
        desired_generation: i64,
        fence_epoch: i64,
        intent_digest: [u8; 32],
        attempt_id: String,
    ) -> Result<Self, DeviceCommandAuditProofRestoreError> {
        let Some(desired_generation) =
            PersistableDesiredGeneration::try_from_i64(desired_generation)
        else {
            return Err(DeviceCommandAuditProofRestoreError);
        };
        let Some(fence_epoch) = PersistableFenceEpoch::try_from_i64(fence_epoch) else {
            return Err(DeviceCommandAuditProofRestoreError);
        };
        if attempt_id.is_empty() {
            return Err(DeviceCommandAuditProofRestoreError);
        }
        Ok(Self {
            tenant,
            device_id,
            desired_generation,
            fence_epoch,
            intent_digest,
            producer_actor_id: DEVICE_CERTIFICATE_PRODUCER_ACTOR_ID,
            attempt_id,
        })
    }

    /// Owning tenant.
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    /// Canonical target device.
    pub const fn device_id(&self) -> uuid::Uuid {
        self.device_id
    }

    /// Desired-state generation carried by the command.
    pub const fn desired_generation(&self) -> PersistableDesiredGeneration {
        self.desired_generation
    }

    /// Target-local lease epoch used as the command fence.
    pub const fn fence_epoch(&self) -> PersistableFenceEpoch {
        self.fence_epoch
    }

    /// Stable semantic intent digest; takeover does not change this value.
    pub const fn intent_digest(&self) -> &[u8; 32] {
        &self.intent_digest
    }

    /// Stable logical service actor.
    pub const fn producer_actor_id(&self) -> &'static str {
        self.producer_actor_id
    }

    /// Attempt causation identity.
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
}

/// Reviewed durable evidence for the one canonical device-certificate command.
///
/// The provider can restore this value only by supplying both the audited command coordinates and
/// the original typed outbox payload. Restoration reparses the generated request and recomputes its
/// canonical intent digest, so a raw command row or payload alone cannot become readiness evidence.
pub struct DeviceCertificateCommandEvidence {
    audit: DeviceCommandAuditProof,
    artifact_id: String,
    artifact_digest: [u8; 32],
    policy_hash: [u8; 32],
    deadline_epoch_seconds: PersistableCommandDeadlineEpochSeconds,
}

impl std::fmt::Debug for DeviceCertificateCommandEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeviceCertificateCommandEvidence(<redacted>)")
    }
}

impl DeviceCertificateCommandEvidence {
    /// Restore and re-review one durable generated command payload against its audited row.
    #[doc(hidden)]
    pub fn restore_durable(
        audit: DeviceCommandAuditProof,
        payload: &[u8],
        deadline_epoch_seconds: i64,
    ) -> Result<Self, FencedCommandReviewError> {
        let request: generated::command::identity_v1::IdentityApplyDeviceCertificateRequest =
            serde_json::from_slice(payload)
                .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
        let artifact_id = request.artifact_id.as_str().to_owned();
        let artifact_digest = parse_sha256_label(request.artifact_digest.as_str())?;
        let policy_hash = parse_sha256_label(request.policy_hash.as_str())?;
        let request_intent = parse_sha256_label(request.intent_digest.as_str())?;
        let deadline_epoch_seconds =
            PersistableCommandDeadlineEpochSeconds::try_from_i64(deadline_epoch_seconds)
                .ok_or(FencedCommandReviewError::DeadlineRange)?;

        if request.device_id != audit.device_id
            || request.desired_generation.get() != audit.desired_generation.get() as u64
            || request.fence_epoch.get() != audit.fence_epoch.get() as u64
            || request.deadline_epoch_seconds.get() != deadline_epoch_seconds.get() as u64
            || request_intent != audit.intent_digest
        {
            return Err(FencedCommandReviewError::Scope);
        }

        let command = generated::command::identity_v1::fenced_reconcile_command(request);
        let canonical =
            canonical_fenced_intent_digest(&command, generated::command::identity_v1::SPEC)?;
        if canonical != audit.intent_digest {
            return Err(FencedCommandReviewError::Digest);
        }

        Ok(Self {
            audit,
            artifact_id,
            artifact_digest,
            policy_hash,
            deadline_epoch_seconds,
        })
    }

    /// Owning tenant.
    #[must_use]
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.audit.tenant()
    }

    /// Canonical target device.
    #[must_use]
    pub const fn device_id(&self) -> uuid::Uuid {
        self.audit.device_id()
    }

    /// Desired generation carried by the reviewed command.
    #[must_use]
    pub const fn desired_generation(&self) -> PersistableDesiredGeneration {
        self.audit.desired_generation()
    }

    /// Command fence epoch.
    #[must_use]
    pub const fn fence_epoch(&self) -> PersistableFenceEpoch {
        self.audit.fence_epoch()
    }

    /// Canonical semantic intent digest.
    #[must_use]
    pub const fn intent_digest(&self) -> &[u8; 32] {
        self.audit.intent_digest()
    }

    /// Authorized artifact reference encoded in the reviewed payload.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Authorized public artifact digest encoded in the reviewed payload.
    #[must_use]
    pub const fn artifact_digest(&self) -> &[u8; 32] {
        &self.artifact_digest
    }

    /// Desired policy digest encoded in the reviewed payload.
    #[must_use]
    pub const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }

    /// Reviewed absolute command deadline.
    #[must_use]
    pub const fn deadline_epoch_seconds(&self) -> PersistableCommandDeadlineEpochSeconds {
        self.deadline_epoch_seconds
    }
}

/// Reviewed fenced reconcile command capability.
///
/// This is the transactional counterpart of `eventexec::command::emit_async`: it produces the
/// same command outbox primitives plus immutable fencing/audit coordinates, without exposing a raw
/// actor, subject, tenant, or idempotency key authoring seam.
pub struct ReviewedFencedCommand {
    intent: ReviewedCommandIntent,
    envelope: OutboxEnvelopeParts,
    audit: DeviceCommandAuditProof,
    deadline_epoch_seconds: PersistableCommandDeadlineEpochSeconds,
}

/// Closed, payload-free rejection of fenced command authoring.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum FencedCommandReviewError {
    /// The attempt target is not the canonical device-certificate scope.
    #[error("fenced command scope is invalid")]
    Scope,
    /// The request epoch does not match the attempt fence.
    #[error("fenced command fence is invalid")]
    Fence,
    /// The semantic intent digest is not canonical.
    #[error("fenced command intent digest is invalid")]
    Digest,
    /// The attempt cannot provide a canonical causation identity.
    #[error("fenced command causation is invalid")]
    Causation,
    /// The generated request could not be encoded.
    #[error("fenced command request encoding failed")]
    RequestEncoding,
    /// The closed producer identity could not be reconstructed.
    #[error("fenced command producer identity is invalid")]
    ProducerIdentity,
    /// Generation or epoch exceeds the persistent signed coordinate domain.
    #[error("fenced command coordinate is outside the persistent range")]
    CoordinateRange,
    /// Deadline exceeds the canonical persistent timestamp domain.
    #[error("fenced command deadline is outside the persistent range")]
    DeadlineRange,
}

impl ReviewedFencedCommand {
    fn from_spec<C>(
        command: C,
        keyring: &CommandIdempotencyKeyring,
        producer: DeviceCertificateSystemProducer,
        attempt: &ReconcileAttempt,
    ) -> Result<Self, FencedCommandReviewError>
    where
        C: generated::command::FencedCommandSpec,
    {
        let target = attempt.target();
        if target.reconciler_id() != DEVICE_CERTIFICATE_RECONCILER_ID
            || target.resource_kind() != DEVICE_CERTIFICATE_RESOURCE_KIND
            || target.resource_id() != command.device_id().hyphenated().to_string()
        {
            return Err(FencedCommandReviewError::Scope);
        }
        if target.epoch() != command.fence_epoch().get() {
            return Err(FencedCommandReviewError::Fence);
        }
        let tenant = target.tenant();
        let payload = serde_json::to_vec(command.request())
            .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
        let spec = <C::Contract as generated::command::CommandContract>::SPEC;
        let desired_generation =
            PersistableDesiredGeneration::try_from_u64(command.desired_generation().get())
                .ok_or(FencedCommandReviewError::CoordinateRange)?;
        let fence_epoch = PersistableFenceEpoch::try_from_u64(command.fence_epoch().get())
            .ok_or(FencedCommandReviewError::CoordinateRange)?;
        let deadline_epoch_seconds = PersistableCommandDeadlineEpochSeconds::try_from_u64(
            command.deadline_epoch_seconds().get(),
        )
        .ok_or(FencedCommandReviewError::DeadlineRange)?;
        let device_id = command.device_id();
        let intent_digest = parse_sha256_label(command.intent_digest())?;
        if canonical_fenced_intent_digest(&command, spec)? != intent_digest {
            return Err(FencedCommandReviewError::Digest);
        }
        let raw_idempotency_key = fenced_idempotency_material(
            spec,
            device_id,
            desired_generation,
            fence_epoch,
            &intent_digest,
        );
        let subject_id = EnvelopeSubjectId::from_uuid(device_id);
        let actor = producer
            .actor()
            .map_err(|_| FencedCommandReviewError::ProducerIdentity)?;
        let (intent, envelope) = reviewed_keyed_intent(
            keyring,
            spec,
            tenant,
            payload,
            subject_id,
            actor,
            &raw_idempotency_key,
        )
        .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
        let causation_id = EnvelopeCausationId::from_opaque(attempt.attempt_id())
            .map_err(|_| FencedCommandReviewError::Causation)?;
        Ok(Self {
            intent,
            envelope: envelope.with_causation_id(causation_id),
            audit: DeviceCommandAuditProof {
                tenant,
                device_id,
                desired_generation,
                fence_epoch,
                intent_digest,
                producer_actor_id: DEVICE_CERTIFICATE_PRODUCER_ACTOR_ID,
                attempt_id: attempt.attempt_id().to_owned(),
            },
            deadline_epoch_seconds,
        })
    }

    /// Borrow sealed keyed alias probes for provider idempotency claim.
    ///
    /// The raw key is never recoverable from this value; command authoring remains sealed behind
    /// generated [`generated::command::FencedCommandSpec`] implementations.
    pub fn aliases(&self) -> &crate::command::CommandAliasProbeSet {
        self.intent.aliases()
    }

    /// Borrow payload-free typed audit coordinates.
    pub const fn audit_proof(&self) -> &DeviceCommandAuditProof {
        &self.audit
    }

    /// Consume into provider outbox primitives.
    pub fn into_parts(
        self,
    ) -> (
        ReviewedCommandIntent,
        OutboxEnvelopeParts,
        DeviceCommandAuditProof,
        PersistableCommandDeadlineEpochSeconds,
    ) {
        (
            self.intent,
            self.envelope,
            self.audit,
            self.deadline_epoch_seconds,
        )
    }
}

fn canonical_fenced_intent_digest<C>(
    command: &C,
    spec: generated::command::CommandSpec,
) -> Result<[u8; 32], FencedCommandReviewError>
where
    C: generated::command::FencedCommandSpec,
{
    let value = serde_json::to_value(command.request())
        .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
    canonical_fenced_intent_digest_value(value, spec)
}

fn canonical_fenced_intent_digest_value(
    mut value: serde_json::Value,
    spec: generated::command::CommandSpec,
) -> Result<[u8; 32], FencedCommandReviewError> {
    let object = value
        .as_object_mut()
        .ok_or(FencedCommandReviewError::RequestEncoding)?;
    for coordinate in [
        "deviceId",
        "desiredGeneration",
        "fenceEpoch",
        "intentDigest",
        "deadlineEpochSeconds",
    ] {
        if object.remove(coordinate).is_none() {
            return Err(FencedCommandReviewError::RequestEncoding);
        }
    }
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| FencedCommandReviewError::RequestEncoding)?;
    let binding = spec.contract();
    let mut hasher = Sha256::new();
    hash_fenced_intent_component(&mut hasher, FENCED_INTENT_DIGEST_DOMAIN.as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.domain().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.contract_id().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.version().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.schema_hash().as_bytes());
    hash_fenced_intent_component(&mut hasher, &canonical);
    Ok(hasher.finalize().into())
}

/// Codegen-owning fixture funnel used by provider conformance graphs.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn device_certificate_command_fixture(
    mut value: serde_json::Value,
) -> Result<ApplyDeviceCertificateReconcileCommand, ReconcileScheduleError> {
    let object = value.as_object_mut().ok_or_else(|| {
        ReconcileScheduleError::new(std::io::Error::other("command fixture must be an object"))
    })?;
    object.insert(
        "intentDigest".to_owned(),
        serde_json::Value::String(sha256_label(&[0; 32])),
    );
    let digest =
        canonical_fenced_intent_digest_value(value.clone(), generated::command::identity_v1::SPEC)
            .map_err(ReconcileScheduleError::fenced_review)?;
    let object = value.as_object_mut().ok_or_else(|| {
        ReconcileScheduleError::new(std::io::Error::other("command fixture must be an object"))
    })?;
    object.insert(
        "intentDigest".to_owned(),
        serde_json::Value::String(sha256_label(&digest)),
    );
    let request = serde_json::from_value(value).map_err(ReconcileScheduleError::new)?;
    Ok(generated::command::identity_v1::fenced_reconcile_command(
        request,
    ))
}

/// Stable semantic view that keeps generated command types inside eventexec.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub struct DeviceCertificateCommandFixtureView<'a> {
    pub device_id: uuid::Uuid,
    pub desired_generation: u64,
    pub artifact_id: &'a str,
    pub artifact_digest: &'a str,
    pub policy_hash: &'a str,
    pub deadline_epoch_seconds: u64,
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn device_certificate_command_fixture_view(
    command: &ApplyDeviceCertificateReconcileCommand,
) -> DeviceCertificateCommandFixtureView<'_> {
    use generated::command::FencedCommandSpec as _;
    let request = command.request();
    DeviceCertificateCommandFixtureView {
        device_id: request.device_id,
        desired_generation: request.desired_generation.get(),
        artifact_id: request.artifact_id.as_str(),
        artifact_digest: request.artifact_digest.as_str(),
        policy_hash: request.policy_hash.as_str(),
        deadline_epoch_seconds: request.deadline_epoch_seconds.get(),
    }
}

fn hash_fenced_intent_component(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value);
    hasher.update(b"\0");
}

fn fenced_idempotency_material(
    spec: generated::command::CommandSpec,
    device_id: uuid::Uuid,
    desired_generation: PersistableDesiredGeneration,
    fence_epoch: PersistableFenceEpoch,
    intent_digest: &[u8; 32],
) -> String {
    let binding = spec.contract();
    let mut hasher = Sha256::new();
    hash_fenced_intent_component(&mut hasher, FENCED_COMMAND_KEY_DOMAIN.as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.domain().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.contract_id().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.version().as_bytes());
    hash_fenced_intent_component(&mut hasher, binding.schema_hash().as_bytes());
    hash_fenced_intent_component(&mut hasher, device_id.as_bytes());
    hash_fenced_intent_component(&mut hasher, &desired_generation.get().to_be_bytes());
    hash_fenced_intent_component(&mut hasher, &fence_epoch.get().to_be_bytes());
    hash_fenced_intent_component(&mut hasher, intent_digest);
    let digest = hasher.finalize();
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn parse_sha256_label(value: &str) -> Result<[u8; 32], FencedCommandReviewError> {
    let hex = value
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64)
        .ok_or(FencedCommandReviewError::Digest)?;
    let mut bytes = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0]).ok_or(FencedCommandReviewError::Digest)?;
        let low = decode_lower_hex(pair[1]).ok_or(FencedCommandReviewError::Digest)?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

fn sha256_label(digest: &[u8; 32]) -> String {
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

const fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Provider-agnostic durable reconcile store.
#[allow(async_fn_in_trait)]
pub trait ReconcileScheduleStore {
    /// Claim due active targets for one tenant and reconciler.
    ///
    /// The provider MUST return at most `limit` targets, with no duplicate target identity. Every
    /// returned target MUST carry the caller holder's currently held, unexpired CAS lease token and
    /// a strictly monotonic target-local epoch. Within the provider-visible unlocked due set,
    /// results MUST be ordered by `(next_run_at, target_id)`; `SKIP LOCKED` providers do not promise
    /// a global order across concurrent holders. Violations are runtime invariants: the worker
    /// degrades and safely discards or CAS releases claims without exceeding its attempt bound.
    async fn claim_due_targets(
        &self,
        tenant: rss_request_context::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        limit: ReconcileMaxInFlight,
        lease_ttl: Duration,
    ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError>;

    /// Revalidate and claim one exact versioned durable wake under the normal lease/epoch fence.
    async fn claim_targeted(
        &self,
        tenant: rss_request_context::TenantId,
        reconciler_id: &str,
        holder_id: &str,
        wake: &ReconcileWake,
        lease_ttl: Duration,
    ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError>;

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
    ) -> Result<ScheduleResultOutcome, ReconcileScheduleError>;

    /// Atomically supersede obsolete commands and append the fenced command, action, and outbox.
    async fn record_fenced_command(
        &self,
        attempt: &ReconcileAttempt,
        action: ConvergeAction,
        command: ReviewedFencedCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError>;

    /// Atomically complete the canonical device-certificate deletion finalizer under attempt CAS.
    async fn complete_device_certificate_deletion(
        &self,
        attempt: &ReconcileAttempt,
    ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError>;

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
        tenant: rss_request_context::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError>;

    /// Re-enable a target and make it immediately due.
    async fn resume_target(
        &self,
        tenant: rss_request_context::TenantId,
        target_id: &str,
    ) -> Result<(), ReconcileScheduleError>;
}

/// Authorized operator port for inspecting and resuming quarantined reconcile targets.
#[allow(async_fn_in_trait)]
pub trait ReconcileOperatorStore {
    /// Read one exact tenant/target without exposing command payloads or fact material.
    async fn inspect_target(
        &self,
        tenant: rss_request_context::TenantId,
        target_id: &str,
        capability: OperatorReconcileCapability,
    ) -> Result<ReconcileTargetSummary, ReconcileScheduleError>;

    /// Clear a reviewed quarantine and make the exact tenant/target immediately due.
    async fn resume_target(
        &self,
        tenant: rss_request_context::TenantId,
        target_id: &str,
        capability: OperatorReconcileCapability,
    ) -> Result<ReconcileTargetSummary, ReconcileScheduleError>;
}

/// Attempt-scoped recorder handed to durable reconcilers.
pub struct AttemptScope<'a, S: ReconcileScheduleStore> {
    store: &'a S,
    keyring: &'a CommandIdempotencyKeyring,
    producer: DeviceCertificateSystemProducer,
    attempt: ReconcileAttempt,
    quarantine_reason: AtomicU8,
}

/// Sealed attempt authority for the one device-certificate target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificateAttemptSnapshot {
    tenant: rss_request_context::TenantId,
    device_id: uuid::Uuid,
    attempt_id: String,
    target_id: String,
    lease_token: String,
    epoch: u64,
    wake_version: WakeVersion,
}

impl DeviceCertificateAttemptSnapshot {
    /// Owning tenant.
    pub const fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }
    /// Canonical device target.
    pub const fn device_id(&self) -> uuid::Uuid {
        self.device_id
    }
    /// Append-only attempt identity.
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }
    /// Durable target identity.
    pub fn target_id(&self) -> &str {
        &self.target_id
    }
    /// Provider-issued lease token.
    pub fn lease_token(&self) -> &str {
        &self.lease_token
    }
    /// Target-local epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Captured wake version.
    pub const fn wake_version(&self) -> WakeVersion {
        self.wake_version
    }
}

impl<'a, S: ReconcileScheduleStore> AttemptScope<'a, S> {
    fn new(
        store: &'a S,
        keyring: &'a CommandIdempotencyKeyring,
        producer: DeviceCertificateSystemProducer,
        attempt: ReconcileAttempt,
    ) -> Self {
        Self {
            store,
            keyring,
            producer,
            attempt,
            quarantine_reason: AtomicU8::new(0),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    /// Test-only component constructor preserving the production attempt scope.
    pub fn for_test(
        store: &'a S,
        keyring: &'a CommandIdempotencyKeyring,
        producer: DeviceCertificateSystemProducer,
        attempt: ReconcileAttempt,
    ) -> Self {
        Self::new(store, keyring, producer, attempt)
    }

    /// Current attempt id for correlation.
    pub fn attempt_id(&self) -> &str {
        self.attempt.attempt_id()
    }

    /// Derive the only device-certificate authority snapshot accepted by the identity repository.
    pub fn device_certificate_snapshot(
        &self,
    ) -> Result<DeviceCertificateAttemptSnapshot, ReconcileScheduleError> {
        let target = self.attempt.target();
        let device_id = uuid::Uuid::parse_str(target.resource_id())
            .map_err(|_| ReconcileScheduleError::fenced_review(FencedCommandReviewError::Scope))?;
        if target.reconciler_id() != DEVICE_CERTIFICATE_RECONCILER_ID
            || target.resource_kind() != DEVICE_CERTIFICATE_RESOURCE_KIND
            || target.epoch() == 0
        {
            return Err(ReconcileScheduleError::fenced_review(
                FencedCommandReviewError::Scope,
            ));
        }
        Ok(DeviceCertificateAttemptSnapshot {
            tenant: target.tenant(),
            device_id,
            attempt_id: self.attempt.attempt_id().to_owned(),
            target_id: target.target_id().to_owned(),
            lease_token: target.lease_token().to_owned(),
            epoch: target.epoch(),
            wake_version: target.wake_version(),
        })
    }

    /// Review one command draft against this attempt's canonical target and fence.
    ///
    /// Artifact coordinates remain evidence claims, not authorization. The provider transaction
    /// consuming the resulting draft must exact-check them against the immutable persisted
    /// artifact receipt while the same lease is held.
    pub fn review_device_certificate_command(
        &self,
        desired_generation: u64,
        artifact_id: &str,
        artifact_digest: [u8; 32],
        policy_hash: [u8; 32],
        authoritative_now: SystemTime,
        ttl: DeviceCertificateCommandTtl,
    ) -> Result<AttemptReviewedDeviceCertificateCommand, ReconcileScheduleError> {
        let snapshot = self.device_certificate_snapshot()?;
        let desired_generation =
            std::num::NonZeroU64::new(desired_generation).ok_or_else(|| {
                ReconcileScheduleError::fenced_review(FencedCommandReviewError::CoordinateRange)
            })?;
        let artifact_id = artifact_id.try_into().map_err(|_| {
            ReconcileScheduleError::fenced_review(FencedCommandReviewError::RequestEncoding)
        })?;
        let deadline = authoritative_now
            .checked_add(Duration::from_secs(ttl.seconds()))
            .and_then(|deadline| deadline.duration_since(SystemTime::UNIX_EPOCH).ok())
            .and_then(|deadline| std::num::NonZeroU64::new(deadline.as_secs()))
            .ok_or_else(|| {
                ReconcileScheduleError::fenced_review(FencedCommandReviewError::DeadlineRange)
            })?;
        let command = DeviceCertificateCommand::from_coordinates(
            snapshot.device_id(),
            desired_generation,
            artifact_id,
            artifact_digest,
            policy_hash,
            deadline,
        )
        .and_then(|command| command.into_fenced_command(snapshot.epoch()))
        .map_err(ReconcileScheduleError::fenced_review)?;
        Ok(AttemptReviewedDeviceCertificateCommand {
            attempt_id: snapshot.attempt_id().to_owned(),
            command,
        })
    }

    /// Consume one attempt-reviewed draft through the sole provider transaction funnel.
    ///
    /// The provider remains responsible for exact artifact-receipt verification in the same
    /// transaction as every durable command side effect.
    pub async fn record_device_certificate_command(
        &self,
        action: ConvergeAction,
        reviewed: AttemptReviewedDeviceCertificateCommand,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
        if reviewed.attempt_id != self.attempt.attempt_id() {
            self.quarantine_reason.store(
                ReconcileQuarantineReason::InvariantViolation.code(),
                Ordering::Release,
            );
            return Err(ReconcileScheduleError::fenced_review(
                FencedCommandReviewError::Causation,
            ));
        }
        self.record_reviewed_fenced_command(action, reviewed.command)
            .await
    }

    /// Complete deletion only after the provider rechecks every retained artifact's terminal
    /// revocation or authoritative-expiry evidence in the same lease-CAS transaction.
    pub async fn complete_device_certificate_deletion(
        &self,
    ) -> Result<AttemptCompletionOutcome, ReconcileScheduleError> {
        match self
            .store
            .complete_device_certificate_deletion(&self.attempt)
            .await?
        {
            ScheduleCompletionOutcome::Completed => Ok(AttemptCompletionOutcome::Completed(
                AttemptCompletionReceipt {
                    attempt_id: self.attempt.attempt_id().to_owned(),
                    target_id: self.attempt.target().target_id().to_owned(),
                },
            )),
            ScheduleCompletionOutcome::EvidencePending => {
                Ok(AttemptCompletionOutcome::EvidencePending)
            }
            ScheduleCompletionOutcome::Lost => Ok(AttemptCompletionOutcome::Lost),
        }
    }

    async fn record_reviewed_fenced_command<C>(
        &self,
        action: ConvergeAction,
        command: C,
    ) -> Result<ScheduleActionOutcome, ReconcileScheduleError>
    where
        C: generated::command::FencedCommandSpec,
    {
        let command = match ReviewedFencedCommand::from_spec(
            command,
            self.keyring,
            self.producer,
            &self.attempt,
        ) {
            Ok(command) => command,
            Err(error) => {
                let reason = match error {
                    FencedCommandReviewError::Digest | FencedCommandReviewError::DeadlineRange => {
                        ReconcileQuarantineReason::PermanentFailure
                    }
                    FencedCommandReviewError::Scope
                    | FencedCommandReviewError::Fence
                    | FencedCommandReviewError::Causation
                    | FencedCommandReviewError::RequestEncoding
                    | FencedCommandReviewError::ProducerIdentity
                    | FencedCommandReviewError::CoordinateRange => {
                        ReconcileQuarantineReason::InvariantViolation
                    }
                };
                self.quarantine_reason
                    .store(reason.code(), Ordering::Release);
                return Err(ReconcileScheduleError::fenced_review(error));
            }
        };
        let outcome = self
            .store
            .record_fenced_command(&self.attempt, action, command)
            .await;
        if let Err(error) = &outcome
            && error.kind() == ReconcileScheduleErrorKind::FactConflict
        {
            self.quarantine_reason.store(
                ReconcileQuarantineReason::FactConflict.code(),
                Ordering::Release,
            );
        }
        outcome
    }

    fn quarantine_reason(&self) -> Option<ReconcileQuarantineReason> {
        ReconcileQuarantineReason::from_code(self.quarantine_reason.load(Ordering::Acquire))
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
    ) -> Result<DurableReconcileOutcome, ReconcileError>;
}

/// Durable scheduler builder.
pub struct ReconcileSchedulerBuilder<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    store: S,
    reconciler: R,
    keyring: Arc<CommandIdempotencyKeyring>,
    producer: DeviceCertificateSystemProducer,
    tenant: rss_request_context::TenantId,
    reconciler_id: String,
    holder_id: String,
    trigger: Trigger,
    backoff: BackoffPolicy,
    lease_ttl: Duration,
    max_in_flight: ReconcileMaxInFlight,
}

impl<S, R> ReconcileSchedulerBuilder<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    /// New durable scheduler builder. Store, tenancy and trigger are required at construction.
    #[allow(clippy::too_many_arguments)]
    // reason: the mandatory idempotency keyring is an independent security dependency; grouping
    // store/reconciler/tenant/identity/tenancy/trigger would only hide required constructor inputs.
    pub fn new(
        store: S,
        reconciler: R,
        keyring: Arc<CommandIdempotencyKeyring>,
        producer: DeviceCertificateSystemProducer,
        tenant: rss_request_context::TenantId,
        reconciler_id: impl Into<String>,
        holder_id: impl Into<String>,
        _tenancy: Tenancy,
        trigger: Trigger,
    ) -> Self {
        Self {
            store,
            reconciler,
            keyring,
            producer,
            tenant,
            reconciler_id: reconciler_id.into(),
            holder_id: holder_id.into(),
            trigger,
            backoff: BackoffPolicy::default(),
            lease_ttl: LEASE_TTL,
            max_in_flight: ReconcileMaxInFlight::default(),
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

    /// Override the validated hard bound for concurrent attempts (default `16`).
    pub fn with_max_in_flight(mut self, max_in_flight: ReconcileMaxInFlight) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Build a worker and its control handle.
    pub fn build(self) -> ReconcileWorker<S, R> {
        let (paused_tx, paused_rx) = watch::channel(false);
        let (wake_tx, wake_rx) = mpsc::channel(TARGETED_WAKE_BUFFER);
        ReconcileWorker {
            driver: Arc::new(ReconcileDriver {
                store: self.store,
                reconciler: self.reconciler,
                keyring: self.keyring,
                producer: self.producer,
                tenant: self.tenant,
                reconciler_id: self.reconciler_id,
                holder_id: self.holder_id,
                trigger: self.trigger,
                backoff: self.backoff,
                lease_ttl: self.lease_ttl,
                health: Arc::new(WorkerHealth::healthy()),
            }),
            max_in_flight: self.max_in_flight,
            paused_tx,
            paused_rx,
            wake_tx,
            wake_rx,
            drain: WorkerDrainObservation::new(),
        }
    }
}

/// Local targeted-wake enqueue failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReconcileWakeError {
    /// The bounded optional-notification queue is full; periodic due scanning remains authoritative.
    #[error("reconcile targeted wake queue is full")]
    QueueFull,
    /// The worker has stopped and cannot receive optional notifications.
    #[error("reconcile targeted wake worker has stopped")]
    WorkerStopped,
}

/// Pause/resume and optional exact-target notification handle for a durable reconcile worker.
#[derive(Clone)]
pub struct ReconcileWorkerControl {
    paused: watch::Sender<bool>,
    wake: mpsc::Sender<ReconcileWake>,
    drain: WorkerDrainObservation,
}

impl ReconcileWorkerControl {
    /// Stop new claims after the current in-flight attempt drains.
    pub fn pause(&self) {
        if self.drain.is_stopped() {
            return;
        }
        self.paused.send_replace(true);
    }

    /// Resume due target claims.
    pub fn resume(&self) {
        if self.drain.is_stopped() {
            return;
        }
        self.drain.mark_running();
        self.paused.send_replace(false);
    }

    /// Current local pause flag.
    pub fn is_paused(&self) -> bool {
        *self.paused.borrow()
    }

    /// Current worker-owned jobs, including claims, attempts and lease releases.
    pub fn in_flight(&self) -> usize {
        self.drain.in_flight()
    }

    /// Whether pause has taken effect and all current work is complete, or the worker stopped.
    pub fn is_drained(&self) -> bool {
        self.drain.is_drained()
    }

    /// Whether the worker loop reached its terminal stopped state.
    pub fn is_stopped(&self) -> bool {
        self.drain.is_stopped()
    }

    /// Wait until admission is paused and current work reaches zero, or the worker stops.
    pub async fn wait_drained(&self) {
        self.drain.wait_drained().await;
    }

    /// Best-effort enqueue of a post-commit exact-target wake.
    ///
    /// Full or closed queues do not affect correctness because durable due scanning repairs loss.
    pub fn try_wake(&self, wake: ReconcileWake) -> Result<(), ReconcileWakeError> {
        self.wake.try_send(wake).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ReconcileWakeError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => ReconcileWakeError::WorkerStopped,
        })
    }
}

/// Durable reconcile worker.
pub struct ReconcileWorker<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    driver: Arc<ReconcileDriver<S, R>>,
    max_in_flight: ReconcileMaxInFlight,
    paused_tx: watch::Sender<bool>,
    paused_rx: watch::Receiver<bool>,
    wake_tx: mpsc::Sender<ReconcileWake>,
    wake_rx: mpsc::Receiver<ReconcileWake>,
    drain: WorkerDrainObservation,
}

struct ReconcileDriver<S, R>
where
    S: ReconcileScheduleStore,
    R: DurableReconciler<S>,
{
    store: S,
    reconciler: R,
    keyring: Arc<CommandIdempotencyKeyring>,
    producer: DeviceCertificateSystemProducer,
    tenant: rss_request_context::TenantId,
    reconciler_id: String,
    holder_id: String,
    trigger: Trigger,
    backoff: BackoffPolicy,
    lease_ttl: Duration,
    health: Arc<WorkerHealth>,
}

enum WorkerLoopEvent {
    Cancelled,
    PauseChanged,
    Tick,
    Targeted(ReconcileWake),
}

type DurableRunResult =
    Result<Result<DurableReconcileOutcome, ReconcileError>, Box<dyn std::any::Any + Send>>;

#[derive(Clone, Copy)]
enum DurableAttemptFailureKind {
    Transient,
    Permanent,
    Invariant,
    Panic,
}

impl DurableAttemptFailureKind {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Invariant => "invariant",
            Self::Panic => "panic",
        }
    }

    const fn is_retryable(self) -> bool {
        matches!(self, Self::Transient | Self::Panic)
    }
}

enum TargetRun {
    Finished(DurableRunResult, Option<ReconcileQuarantineReason>),
    Cancelled,
    LeaseLost(LeaseState),
}

enum WorkerJob {
    DueClaimed {
        limit: ReconcileMaxInFlight,
        result: Result<Vec<ClaimedTarget>, ReconcileScheduleError>,
    },
    TargetedClaimed {
        wake: ReconcileWake,
        result: Result<Option<ClaimedTarget>, ReconcileScheduleError>,
    },
    AttemptFinished {
        target_id: String,
        fence: ActiveLeaseFence,
    },
    LeaseReleased,
}

enum WorkerJobRequest {
    ClaimDue(ReconcileMaxInFlight),
    ClaimTargeted(ReconcileWake),
    RunAttempt {
        target: ClaimedTarget,
        cancel: CancellationToken,
    },
    Release(ClaimedTarget, LeaseReason),
}

/// INVARIANT: RECONCILE-BOUNDED-ADMISSION-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "reconcile_worker_due_new_epoch_cancels_then_replaces_active_generation", anti_vacuity = "reconcile_worker_replacement_accepts_only_strictly_newer_epoch" }: the worker-owned future set starts only available capacity, and each active target owns its fence, cancellation token and at most one latest-generation handoff. Peak, overflow, generation, pause and shutdown tests prove the runtime half that the type system cannot see.
struct SchedulerState {
    attempts_in_flight: usize,
    active_targets: HashMap<String, ActiveAttempt>,
    claim_in_flight: bool,
    due_ready: bool,
    paused: bool,
    shutting_down: bool,
}

impl SchedulerState {
    fn new(paused: bool) -> Self {
        Self {
            attempts_in_flight: 0,
            active_targets: HashMap::new(),
            claim_in_flight: false,
            due_ready: true,
            paused,
            shutting_down: false,
        }
    }

    fn available(&self, max_in_flight: ReconcileMaxInFlight) -> usize {
        usize::from(max_in_flight.get()) - self.attempts_in_flight
    }

    fn can_claim(&self, max_in_flight: ReconcileMaxInFlight) -> bool {
        !self.paused
            && !self.shutting_down
            && !self.claim_in_flight
            && self.available(max_in_flight) > 0
    }

    fn take_due_claim(&mut self, max_in_flight: ReconcileMaxInFlight) -> Option<WorkerJobRequest> {
        if !self.can_claim(max_in_flight) || !self.due_ready {
            return None;
        }
        let Ok(limit) = ReconcileMaxInFlight::try_new(self.available(max_in_flight)) else {
            self.shutting_down = true;
            return None;
        };
        self.claim_in_flight = true;
        self.due_ready = false;
        Some(WorkerJobRequest::ClaimDue(limit))
    }

    fn classify_target(
        &self,
        target: &ClaimedTarget,
        max_in_flight: ReconcileMaxInFlight,
    ) -> TargetAdmission {
        let Some(active) = self.active_targets.get(target.target_id()) else {
            return if self.paused || self.shutting_down || self.available(max_in_flight) == 0 {
                TargetAdmission::NoCapacity
            } else {
                TargetAdmission::Start
            };
        };
        if active.fence.matches(target)
            || active
                .replacement
                .as_ref()
                .is_some_and(|replacement| same_lease_fence(replacement, target))
        {
            return TargetAdmission::DuplicateSameFence;
        }
        if self.paused || self.shutting_down {
            return TargetAdmission::NoCapacity;
        }
        let latest_epoch = active
            .replacement
            .as_ref()
            .map_or(active.fence.epoch, ClaimedTarget::epoch);
        if target.epoch() > latest_epoch {
            TargetAdmission::NewerFence
        } else {
            TargetAdmission::StaleFence
        }
    }

    fn start_target(
        &mut self,
        target: &ClaimedTarget,
        root: &CancellationToken,
    ) -> CancellationToken {
        let cancel = root.child_token();
        self.active_targets.insert(
            target.target_id().to_owned(),
            ActiveAttempt {
                fence: ActiveLeaseFence::from_target(target),
                cancel: cancel.clone(),
                replacement: None,
            },
        );
        self.attempts_in_flight += 1;
        cancel
    }

    fn queue_replacement(&mut self, target: ClaimedTarget) -> Option<ClaimedTarget> {
        let Some(active) = self.active_targets.get_mut(target.target_id()) else {
            return Some(target);
        };
        active.cancel.cancel();
        active.replacement.replace(target)
    }

    fn take_replacements(&mut self, reason: LeaseReason) -> Vec<WorkerJobRequest> {
        self.active_targets
            .values_mut()
            .filter_map(|active| {
                active
                    .replacement
                    .take()
                    .map(|target| WorkerJobRequest::Release(target, reason))
            })
            .collect()
    }

    fn begin_shutdown(&mut self, cancelled: bool) -> Vec<WorkerJobRequest> {
        if !cancelled || self.shutting_down {
            return Vec::new();
        }
        self.shutting_down = true;
        self.take_replacements(LeaseReason::ShutdownBeforeReplacement)
    }
}

struct ActiveAttempt {
    fence: ActiveLeaseFence,
    cancel: CancellationToken,
    replacement: Option<ClaimedTarget>,
}

#[derive(Clone, PartialEq, Eq)]
struct ActiveLeaseFence {
    lease_token: String,
    epoch: u64,
}

impl ActiveLeaseFence {
    fn from_target(target: &ClaimedTarget) -> Self {
        Self {
            lease_token: target.lease_token().to_owned(),
            epoch: target.epoch(),
        }
    }

    fn matches(&self, target: &ClaimedTarget) -> bool {
        self.lease_token == target.lease_token() && self.epoch == target.epoch()
    }
}

fn same_lease_fence(left: &ClaimedTarget, right: &ClaimedTarget) -> bool {
    left.lease_token() == right.lease_token() && left.epoch() == right.epoch()
}

enum TargetAdmission {
    Start,
    DuplicateSameFence,
    NewerFence,
    StaleFence,
    NoCapacity,
}

impl<S, R> ReconcileWorker<S, R>
where
    S: ReconcileScheduleStore + Send + Sync + 'static,
    R: DurableReconciler<S> + Send + Sync + 'static,
{
    /// Control handle for pausing/resuming new target claims.
    pub fn control(&self) -> ReconcileWorkerControl {
        ReconcileWorkerControl {
            paused: self.paused_tx.clone(),
            wake: self.wake_tx.clone(),
            drain: self.drain.clone(),
        }
    }

    /// Health handle for readyz.
    pub fn health(&self) -> Arc<WorkerHealth> {
        Arc::clone(&self.driver.health)
    }

    fn observe_initial_admission(&self, paused: bool) {
        if paused {
            self.drain.mark_paused();
        } else {
            self.drain.mark_running();
        }
    }

    /// Run the durable scheduler loop until cancellation.
    pub async fn run(mut self, token: CancellationToken) {
        let _stopped = self.driver.health.stopped_on_exit();
        let period = self.driver.trigger.period();
        self.driver.log_durable_start(period);
        let mut ticker = tokio::time::interval(period);
        let mut jobs = FuturesUnordered::new();
        let mut state = SchedulerState::new(*self.paused_rx.borrow());
        self.observe_initial_admission(state.paused);

        while !state.shutting_down || !jobs.is_empty() {
            let driver = Arc::clone(&self.driver);
            jobs.extend(
                state
                    .begin_shutdown(token.is_cancelled())
                    .into_iter()
                    .map(|request| execute_worker_job(Arc::clone(&driver), request)),
            );

            let driver = Arc::clone(&self.driver);
            jobs.extend(
                state
                    .take_due_claim(self.max_in_flight)
                    .map(|request| execute_worker_job(driver, request)),
            );
            self.drain.set_in_flight(jobs.len());

            let requests = if state.shutting_down {
                jobs.next()
                    .await
                    .map(|job| self.handle_worker_job(job, &mut state, &token))
                    .unwrap_or_default()
            } else {
                tokio::select! {
                    biased;
                    event = next_worker_event(
                        &mut self.paused_rx,
                        &mut self.wake_rx,
                        &mut ticker,
                        &token,
                        !state.due_ready,
                        state.can_claim(self.max_in_flight) && !state.due_ready,
                    ) => self.handle_worker_event(event, &mut state),
                    Some(job) = jobs.next(), if !jobs.is_empty() => {
                        self.handle_worker_job(job, &mut state, &token)
                    }
                }
            };
            let driver = Arc::clone(&self.driver);
            jobs.extend(
                requests
                    .into_iter()
                    .map(|request| execute_worker_job(Arc::clone(&driver), request)),
            );
            self.drain.set_in_flight(jobs.len());
        }

        self.drain.mark_stopped();

        tracing::info!(
            reconciler_id = self.driver.reconciler_id,
            "reconcile: durable scheduler stopped"
        );
    }

    fn handle_worker_event(
        &self,
        event: WorkerLoopEvent,
        state: &mut SchedulerState,
    ) -> Vec<WorkerJobRequest> {
        match event {
            WorkerLoopEvent::Cancelled => {
                state.shutting_down = true;
                state.take_replacements(LeaseReason::ShutdownBeforeReplacement)
            }
            WorkerLoopEvent::PauseChanged => {
                state.paused = *self.paused_rx.borrow();
                if !state.paused {
                    self.drain.mark_running();
                    state.due_ready = true;
                    Vec::new()
                } else {
                    self.drain.mark_paused();
                    state.take_replacements(LeaseReason::PauseBeforeReplacement)
                }
            }
            WorkerLoopEvent::Tick => {
                if !state.paused {
                    state.due_ready = true;
                }
                Vec::new()
            }
            WorkerLoopEvent::Targeted(wake) => {
                if state.can_claim(self.max_in_flight) && !state.due_ready {
                    state.claim_in_flight = true;
                    vec![WorkerJobRequest::ClaimTargeted(wake)]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn handle_worker_job(
        &self,
        job: WorkerJob,
        state: &mut SchedulerState,
        root: &CancellationToken,
    ) -> Vec<WorkerJobRequest> {
        match job {
            WorkerJob::DueClaimed { limit, result } => {
                state.claim_in_flight = false;
                match result {
                    Ok(targets) => self.accept_due_claims(targets, limit, state, root),
                    Err(ref error) => {
                        self.driver.observe_due_claim_error(limit, error);
                        Vec::new()
                    }
                }
            }
            WorkerJob::TargetedClaimed { wake, result } => {
                state.claim_in_flight = false;
                match result {
                    Ok(Some(target)) => self.accept_target(target, state, root),
                    Ok(None) => {
                        self.driver.observe_targeted_claim_skipped(&wake);
                        Vec::new()
                    }
                    Err(ref error) => {
                        self.driver.observe_targeted_claim_error(&wake, error);
                        Vec::new()
                    }
                }
            }
            WorkerJob::AttemptFinished { target_id, fence } => {
                let Some(active) = state.active_targets.get_mut(&target_id) else {
                    self.driver
                        .observe_stale_attempt_completion(&target_id, &fence);
                    return Vec::new();
                };
                if active.fence != fence {
                    self.driver
                        .observe_stale_attempt_completion(&target_id, &fence);
                    return Vec::new();
                }
                if let Some(target) = active.replacement.take() {
                    if state.paused || state.shutting_down {
                        state.active_targets.remove(&target_id);
                        state.attempts_in_flight = state.attempts_in_flight.saturating_sub(1);
                        vec![WorkerJobRequest::Release(
                            target,
                            LeaseReason::ReplacementNotStarted,
                        )]
                    } else {
                        let cancel = root.child_token();
                        active.fence = ActiveLeaseFence::from_target(&target);
                        active.cancel = cancel.clone();
                        vec![WorkerJobRequest::RunAttempt { target, cancel }]
                    }
                } else {
                    state.active_targets.remove(&target_id);
                    state.attempts_in_flight = state.attempts_in_flight.saturating_sub(1);
                    if !state.paused && !state.shutting_down {
                        state.due_ready = true;
                    }
                    Vec::new()
                }
            }
            WorkerJob::LeaseReleased => Vec::new(),
        }
    }

    fn accept_due_claims(
        &self,
        targets: Vec<ClaimedTarget>,
        limit: ReconcileMaxInFlight,
        state: &mut SchedulerState,
        root: &CancellationToken,
    ) -> Vec<WorkerJobRequest> {
        let returned = targets.len();
        let capacity = state.available(self.max_in_flight);
        let mut requests = Vec::with_capacity(returned);
        let overflow = returned > capacity && !state.paused && !state.shutting_down;
        if overflow {
            self.driver.observe_claim_overflow(returned, capacity);
        }
        for target in targets {
            match state.classify_target(&target, self.max_in_flight) {
                TargetAdmission::Start => {
                    let cancel = state.start_target(&target, root);
                    requests.push(WorkerJobRequest::RunAttempt { target, cancel });
                }
                TargetAdmission::DuplicateSameFence => {
                    self.driver.observe_duplicate_claim(&target, true);
                }
                TargetAdmission::NewerFence => {
                    self.driver.observe_duplicate_claim(&target, false);
                    if let Some(superseded) = state.queue_replacement(target) {
                        requests.push(WorkerJobRequest::Release(
                            superseded,
                            LeaseReason::SupersededReplacement,
                        ));
                    }
                }
                TargetAdmission::StaleFence => {
                    self.driver.observe_duplicate_claim(&target, false);
                    requests.push(WorkerJobRequest::Release(
                        target,
                        LeaseReason::StaleGeneration,
                    ));
                }
                TargetAdmission::NoCapacity => {
                    requests.push(WorkerJobRequest::Release(
                        target,
                        LeaseReason::ClaimNotAdmitted,
                    ));
                }
            }
        }
        state.due_ready =
            !state.paused && !state.shutting_down && returned >= usize::from(limit.get());
        if returned == 0 && state.attempts_in_flight == 0 && !state.paused && !state.shutting_down {
            self.driver.health.mark_healthy();
        }
        requests
    }

    fn accept_target(
        &self,
        target: ClaimedTarget,
        state: &mut SchedulerState,
        root: &CancellationToken,
    ) -> Vec<WorkerJobRequest> {
        match state.classify_target(&target, self.max_in_flight) {
            TargetAdmission::Start => {
                let cancel = state.start_target(&target, root);
                vec![WorkerJobRequest::RunAttempt { target, cancel }]
            }
            TargetAdmission::DuplicateSameFence => {
                self.driver.observe_duplicate_claim(&target, true);
                Vec::new()
            }
            TargetAdmission::NewerFence => {
                self.driver.observe_duplicate_claim(&target, false);
                state
                    .queue_replacement(target)
                    .into_iter()
                    .map(|superseded| {
                        WorkerJobRequest::Release(superseded, LeaseReason::SupersededReplacement)
                    })
                    .collect()
            }
            TargetAdmission::StaleFence => {
                self.driver.observe_duplicate_claim(&target, false);
                vec![WorkerJobRequest::Release(
                    target,
                    LeaseReason::StaleGeneration,
                )]
            }
            TargetAdmission::NoCapacity => vec![WorkerJobRequest::Release(
                target,
                LeaseReason::ClaimNotAdmitted,
            )],
        }
    }
}

impl<S, R> ReconcileDriver<S, R>
where
    S: ReconcileScheduleStore + Send + Sync,
    R: DurableReconciler<S> + Send + Sync,
{
    fn log_durable_start(&self, period: Duration) {
        tracing::info!(
            reconciler_id = self.reconciler_id,
            ?period,
            "reconcile: durable scheduler starting"
        );
    }

    fn observe_due_claim_error(&self, limit: ReconcileMaxInFlight, error: &ReconcileScheduleError) {
        self.health.mark_degraded();
        tracing::warn!(
            reconciler_id = self.reconciler_id,
            max_claim = limit.get(),
            operation = LeaseOperation::Claim.as_label(),
            state = LeaseState::Error.as_label(),
            reason = LeaseReason::DueScan.as_label(),
            error = %error,
            "reconcile: claim due targets failed"
        );
    }

    fn observe_targeted_claim_skipped(&self, wake: &ReconcileWake) {
        tracing::debug!(
            reconciler_id = self.reconciler_id,
            wake_version = wake.version().get(),
            operation = LeaseOperation::Claim.as_label(),
            state = LeaseState::Lost.as_label(),
            reason = LeaseReason::TargetedWake.as_label(),
            "reconcile: targeted wake was stale, disabled, not due, or already claimed"
        );
    }

    fn observe_targeted_claim_error(&self, wake: &ReconcileWake, error: &ReconcileScheduleError) {
        self.health.mark_degraded();
        tracing::warn!(
            reconciler_id = self.reconciler_id,
            wake_version = wake.version().get(),
            operation = LeaseOperation::Claim.as_label(),
            state = LeaseState::Error.as_label(),
            reason = LeaseReason::TargetedWake.as_label(),
            error = %error,
            "reconcile: claim targeted wake failed"
        );
    }

    fn observe_claim_overflow(&self, returned: usize, capacity: usize) {
        self.health.mark_degraded();
        tracing::error!(
            reconciler_id = self.reconciler_id,
            returned,
            capacity,
            "reconcile: provider returned more claims than requested capacity"
        );
    }

    fn observe_duplicate_claim(&self, target: &ClaimedTarget, same_fence: bool) {
        self.health.mark_degraded();
        tracing::error!(
            reconciler_id = self.reconciler_id,
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            same_fence,
            "reconcile: provider returned a target that is already active"
        );
    }

    fn observe_stale_attempt_completion(&self, _target_id: &str, fence: &ActiveLeaseFence) {
        self.health.mark_degraded();
        tracing::error!(
            reconciler_id = self.reconciler_id,
            epoch = fence.epoch,
            "reconcile: stale attempt completion did not match active generation"
        );
    }

    async fn run_target(&self, target: ClaimedTarget, token: &CancellationToken) {
        let Some(attempt) = self.append_attempt_or_release(&target).await else {
            return;
        };
        match self
            .run_reconciler_with_lease(&target, &attempt, token)
            .await
        {
            TargetRun::Finished(result, None) => self.finish_attempt(attempt, result).await,
            TargetRun::Finished(_, Some(reason)) => {
                self.finish_quarantined_attempt(attempt, reason).await;
            }
            TargetRun::Cancelled => {
                self.release_lease_best_effort(&target, LeaseReason::AttemptCancelled)
                    .await;
            }
            TargetRun::LeaseLost(state) => {
                self.health.mark_degraded();
                tracing::warn!(
                    reconciler_id = target.reconciler_id(),
                    resource_kind = target.resource_kind(),
                    epoch = target.epoch(),
                    operation = LeaseOperation::Extend.as_label(),
                    state = state.as_label(),
                    reason = LeaseReason::Renewal.as_label(),
                    "reconcile: target lease renewal stopped"
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
                self.release_lease_best_effort(target, LeaseReason::AppendAttemptFailed)
                    .await;
                None
            }
        }
    }

    fn observe_attempt_append_lost(&self, target: &ClaimedTarget) {
        self.health.mark_degraded();
        tracing::warn!(
            reconciler_id = self.reconciler_id,
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            trigger = target.trigger().as_label(),
            "reconcile: target lease lost before attempt append"
        );
    }

    fn observe_attempt_append_error(&self, target: &ClaimedTarget, error: &ReconcileScheduleError) {
        self.health.mark_degraded();
        tracing::warn!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
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
        let scope = AttemptScope::new(&self.store, &self.keyring, self.producer, attempt.clone());
        tokio::select! {
            biased;
            () = token.cancelled() => {
                TargetRun::Cancelled
            }
            state = self.renew_until_lost(target) => {
                TargetRun::LeaseLost(state)
            }
            result = AssertUnwindSafe(self.reconciler.reconcile(&ctx, target, &scope)).catch_unwind() => {
                TargetRun::Finished(result, scope.quarantine_reason())
            }
        }
    }

    async fn finish_attempt(&self, attempt: ReconcileAttempt, result: DurableRunResult) {
        if let Ok(Ok(DurableReconcileOutcome::Completed(receipt))) = &result {
            if receipt.attempt_id != attempt.attempt_id()
                || receipt.target_id != attempt.target().target_id()
            {
                self.health.mark_degraded();
                tracing::error!(
                    reconciler_id = attempt.target().reconciler_id(),
                    resource_kind = attempt.target().resource_kind(),
                    epoch = attempt.target().epoch(),
                    "reconcile: completion receipt did not match the active attempt"
                );
            }
            emit_reconcile_result(ReconcileResultLabel::Settled);
            return;
        }
        let attempt_result = self.classify_attempt_result(&attempt, result);
        emit_reconcile_result(attempt_result.result());
        self.persist_attempt_result(&attempt, attempt_result).await;
    }

    async fn finish_quarantined_attempt(
        &self,
        attempt: ReconcileAttempt,
        reason: ReconcileQuarantineReason,
    ) {
        self.health.mark_degraded();
        emit_reconcile_result(ReconcileResultLabel::Invariant);
        tracing::error!(
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            epoch = attempt.target().epoch(),
            quarantine_reason = reason.as_label(),
            "reconcile: target quarantined; automatic reclaim disabled"
        );
        self.persist_attempt_result(&attempt, AttemptResult::from_quarantine(reason))
            .await;
    }

    fn classify_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        result: DurableRunResult,
    ) -> AttemptResult {
        match result {
            Ok(Ok(DurableReconcileOutcome::Schedule(outcome))) => {
                self.settled_attempt_result(&outcome)
            }
            Ok(Ok(DurableReconcileOutcome::Completed(_))) => {
                unreachable!("completed attempts are handled before classification")
            }
            Ok(Err(ref error)) => self.error_attempt_result(attempt, error),
            Err(_panic) => self.panic_attempt_result(attempt),
        }
    }

    fn settled_attempt_result(&self, outcome: &Outcome) -> AttemptResult {
        AttemptResult::from_outcome(outcome, self.trigger.period())
    }

    fn error_attempt_result(
        &self,
        attempt: &ReconcileAttempt,
        error: &ReconcileError,
    ) -> AttemptResult {
        self.health.mark_degraded();
        let (kind, result) = if error.is_transient() {
            let delay = self
                .backoff
                .delay_for(attempt.target().failure_streak().next().get());
            (
                DurableAttemptFailureKind::Transient,
                AttemptResult::from_transient(delay),
            )
        } else if error.is_permanent() {
            (
                DurableAttemptFailureKind::Permanent,
                AttemptResult::from_permanent(),
            )
        } else {
            (
                DurableAttemptFailureKind::Invariant,
                AttemptResult::from_invariant(),
            )
        };
        self.observe_durable_attempt_failure(attempt, kind, result);
        result
    }

    fn panic_attempt_result(&self, attempt: &ReconcileAttempt) -> AttemptResult {
        self.health.mark_degraded();
        let delay = self
            .backoff
            .delay_for(attempt.target().failure_streak().next().get());
        let result = AttemptResult::from_panic(delay);
        self.observe_durable_attempt_failure(attempt, DurableAttemptFailureKind::Panic, result);
        result
    }

    fn observe_durable_attempt_failure(
        &self,
        attempt: &ReconcileAttempt,
        kind: DurableAttemptFailureKind,
        result: AttemptResult,
    ) {
        let retry_after_ms = result
            .requeue_after()
            .map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        if kind.is_retryable() {
            Self::log_retryable_durable_attempt_failure(attempt, kind, retry_after_ms);
        } else {
            Self::log_terminal_durable_attempt_failure(attempt, kind, retry_after_ms);
        }
    }

    fn log_retryable_durable_attempt_failure(
        attempt: &ReconcileAttempt,
        kind: DurableAttemptFailureKind,
        retry_after_ms: u64,
    ) {
        let target = attempt.target();
        tracing::warn!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            trigger = target.trigger().as_label(),
            failure_kind = kind.as_label(),
            failure_streak = target.failure_streak().get(),
            retry_scheduled = true,
            retry_after_ms,
            "reconcile: durable attempt classified as failure"
        );
    }

    fn log_terminal_durable_attempt_failure(
        attempt: &ReconcileAttempt,
        kind: DurableAttemptFailureKind,
        retry_after_ms: u64,
    ) {
        let target = attempt.target();
        tracing::error!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            trigger = target.trigger().as_label(),
            failure_kind = kind.as_label(),
            failure_streak = target.failure_streak().get(),
            retry_scheduled = false,
            retry_after_ms,
            "reconcile: durable attempt classified as failure"
        );
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
            Err(ref e) => {
                self.observe_attempt_result_record_error(attempt, e);
                self.release_lease_best_effort(
                    attempt.target(),
                    LeaseReason::AttemptResultRecordFailed,
                )
                .await;
            }
        }
    }

    fn observe_attempt_result_record_outcome(
        &self,
        attempt: &ReconcileAttempt,
        outcome: ScheduleResultOutcome,
    ) {
        match outcome {
            ScheduleResultOutcome::Recorded => {}
            ScheduleResultOutcome::WakeSuperseded => self.observe_result_wake_superseded(attempt),
            ScheduleResultOutcome::Lost => self.observe_attempt_result_lost(attempt),
        }
    }

    fn observe_result_wake_superseded(&self, attempt: &ReconcileAttempt) {
        tracing::debug!(
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            epoch = attempt.target().epoch(),
            claimed_wake_version = attempt.target().wake_version().get(),
            "reconcile: attempt result recorded while a newer durable wake remained due"
        );
    }

    fn observe_attempt_result_lost(&self, attempt: &ReconcileAttempt) {
        self.health.mark_degraded();
        tracing::warn!(
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            epoch = attempt.target().epoch(),
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
            reconciler_id = attempt.target().reconciler_id(),
            resource_kind = attempt.target().resource_kind(),
            epoch = attempt.target().epoch(),
            error = %error,
            "reconcile: record attempt result failed"
        );
    }

    async fn release_lease_best_effort(&self, target: &ClaimedTarget, reason: LeaseReason) {
        match self.store.release_lease(target).await {
            Ok(ScheduleLeaseOutcome::Held) => self.observe_lease_release_held(target, reason),
            Ok(ScheduleLeaseOutcome::Lost) => self.observe_lease_release_lost(target, reason),
            Err(ref error) => self.observe_lease_release_error(target, reason, error),
        }
    }

    fn observe_lease_release_held(&self, target: &ClaimedTarget, reason: LeaseReason) {
        emit_lease_churn(LeaseOperation::Release, LeaseState::Held, reason);
        tracing::debug!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            operation = LeaseOperation::Release.as_label(),
            state = LeaseState::Held.as_label(),
            reason = reason.as_label(),
            "reconcile: target lease released"
        );
    }

    fn observe_lease_release_lost(&self, target: &ClaimedTarget, reason: LeaseReason) {
        self.health.mark_degraded();
        emit_lease_churn(LeaseOperation::Release, LeaseState::Lost, reason);
        tracing::warn!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            operation = LeaseOperation::Release.as_label(),
            state = LeaseState::Lost.as_label(),
            reason = reason.as_label(),
            "reconcile: target lease release lost lease"
        );
    }

    fn observe_lease_release_error(
        &self,
        target: &ClaimedTarget,
        reason: LeaseReason,
        error: &ReconcileScheduleError,
    ) {
        self.health.mark_degraded();
        emit_lease_churn(LeaseOperation::Release, LeaseState::Error, reason);
        tracing::warn!(
            reconciler_id = target.reconciler_id(),
            resource_kind = target.resource_kind(),
            epoch = target.epoch(),
            operation = LeaseOperation::Release.as_label(),
            state = LeaseState::Error.as_label(),
            reason = reason.as_label(),
            error = %error,
            "reconcile: target lease release failed"
        );
    }

    async fn renew_until_lost(&self, target: &ClaimedTarget) -> LeaseState {
        let renew_every = (self.lease_ttl / 3).max(Duration::from_millis(1));
        let mut ticker = tokio::time::interval(renew_every);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match self.store.extend_lease(target, self.lease_ttl).await {
                Ok(ScheduleLeaseOutcome::Held) => emit_lease_churn(
                    LeaseOperation::Extend,
                    LeaseState::Held,
                    LeaseReason::Renewal,
                ),
                Ok(ScheduleLeaseOutcome::Lost) => {
                    emit_lease_churn(
                        LeaseOperation::Extend,
                        LeaseState::Lost,
                        LeaseReason::Renewal,
                    );
                    return LeaseState::Lost;
                }
                Err(_) => {
                    emit_lease_churn(
                        LeaseOperation::Extend,
                        LeaseState::Error,
                        LeaseReason::Renewal,
                    );
                    return LeaseState::Error;
                }
            }
        }
    }
}

async fn execute_worker_job<S, R>(
    driver: Arc<ReconcileDriver<S, R>>,
    request: WorkerJobRequest,
) -> WorkerJob
where
    S: ReconcileScheduleStore + Send + Sync + 'static,
    R: DurableReconciler<S> + Send + Sync + 'static,
{
    match request {
        WorkerJobRequest::ClaimDue(limit) => {
            let result = driver
                .store
                .claim_due_targets(
                    driver.tenant,
                    &driver.reconciler_id,
                    &driver.holder_id,
                    limit,
                    driver.lease_ttl,
                )
                .await;
            match &result {
                Ok(targets) => {
                    for _ in targets {
                        emit_lease_churn(
                            LeaseOperation::Claim,
                            LeaseState::Held,
                            LeaseReason::DueScan,
                        );
                    }
                }
                Err(_) => emit_lease_churn(
                    LeaseOperation::Claim,
                    LeaseState::Error,
                    LeaseReason::DueScan,
                ),
            }
            WorkerJob::DueClaimed { limit, result }
        }
        WorkerJobRequest::ClaimTargeted(wake) => {
            let result = driver
                .store
                .claim_targeted(
                    driver.tenant,
                    &driver.reconciler_id,
                    &driver.holder_id,
                    &wake,
                    driver.lease_ttl,
                )
                .await;
            let state = match &result {
                Ok(Some(_)) => LeaseState::Held,
                Ok(None) => LeaseState::Lost,
                Err(_) => LeaseState::Error,
            };
            emit_lease_churn(LeaseOperation::Claim, state, LeaseReason::TargetedWake);
            WorkerJob::TargetedClaimed { wake, result }
        }
        WorkerJobRequest::RunAttempt { target, cancel } => {
            let target_id = target.target_id().to_owned();
            let fence = ActiveLeaseFence::from_target(&target);
            driver.run_target(target, &cancel).await;
            WorkerJob::AttemptFinished { target_id, fence }
        }
        WorkerJobRequest::Release(target, reason) => {
            driver.release_lease_best_effort(&target, reason).await;
            WorkerJob::LeaseReleased
        }
    }
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
    wake_rx: &mut mpsc::Receiver<ReconcileWake>,
    ticker: &mut tokio::time::Interval,
    token: &CancellationToken,
    accept_tick: bool,
    accept_targeted: bool,
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
        // An already-due periodic scan precedes optional wake hints so sustained exact traffic
        // cannot starve the repair path. Cancellation and pause changes remain higher priority.
        _ = ticker.tick(), if accept_tick => WorkerLoopEvent::Tick,
        Some(wake) = wake_rx.recv(), if accept_targeted => WorkerLoopEvent::Targeted(wake),
    }
}

fn emit_reconcile_result(result: ReconcileResultLabel) {
    metrics::counter!("reconcile_total", "result" => result.as_label()).increment(1);
}

fn emit_lease_churn(operation: LeaseOperation, state: LeaseState, reason: LeaseReason) {
    metrics::counter!(
        "device_latent_lease_churn_total",
        "operation" => operation.as_label(),
        "state" => state.as_label(),
        "reason" => reason.as_label(),
    )
    .increment(1);
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
    pub(crate) fn delay_for(&self, attempts: u32) -> Duration {
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
pub(crate) async fn wait_or_cancel(d: Duration, token: &CancellationToken) -> bool {
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
    use super::DeviceCertificateSystemProducer;
    use super::{
        ActiveLeaseFence, AttemptCompletionOutcome, AttemptErrorKind, AttemptResult,
        AttemptSchedule, AttemptScope, BackoffError, BackoffPolicy, Builder, ClaimedTarget,
        ClaimedTargetRestore, DeviceCertificateCommandEvidence, DeviceCertificateCommandTtl,
        DurableReconcileOutcome, DurableReconciler, FailureStreak, FencedCommandReviewError,
        LeaseOperation, LeaseReason, LeaseState, MAX_FENCED_DEADLINE_EPOCH_SECONDS, NextAction,
        PersistableCommandDeadlineEpochSeconds, PersistableDesiredGeneration,
        PersistableFenceEpoch, RECONCILE_PROBE, RENEW_INTERVAL, ReconcileAttempt,
        ReconcileConfigError, ReconcileDriver, ReconcileLoop, ReconcileMaxInFlight,
        ReconcileQuarantineReason, ReconcileScheduleError, ReconcileScheduleErrorKind,
        ReconcileScheduleStore, ReconcileSchedulerBuilder, ReconcileTargetStatus,
        ReconcileTargetSummary, ReconcileWake, ReconcileWakeError, ReviewedFencedCommand,
        ScheduleActionOutcome, ScheduleAttemptOutcome, ScheduleCompletionOutcome,
        ScheduleLeaseOutcome, ScheduleResultOutcome, SchedulerState, TARGETED_WAKE_BUFFER,
        TargetAdmission, Tenancy, Trigger, TriggerError, WakeVersion, WorkerJob, WorkerJobRequest,
        WorkerLoopEvent, bump_attempts, canonical_fenced_intent_digest_value, emit_lease_churn,
        execute_worker_job, next_worker_event, same_lease_fence,
    };
    use std::time::SystemTime;

    /// `start_paused` 下用步进 `advance` 代替裸 sleep：每步先 `yield_now` 让 spawn 登记 timer。
    async fn advance_paused(total: Duration) {
        const STEP: Duration = Duration::from_millis(50);
        let mut left = total;
        while !left.is_zero() {
            tokio::task::yield_now().await;
            let step = STEP.min(left);
            tokio::time::advance(step).await;
            left = left.saturating_sub(step);
        }
    }

    fn max_in_flight(value: usize) -> ReconcileMaxInFlight {
        let result = ReconcileMaxInFlight::try_new(value);
        assert!(result.is_ok(), "fixed test concurrency must be valid");
        result.unwrap_or_default()
    }

    #[test]
    fn schedule_error_classification_is_closed_and_redacted() {
        let infrastructure =
            ReconcileScheduleError::new(std::io::Error::other("SECRET_SCHEDULE_MARKER"));
        assert_eq!(
            infrastructure.kind(),
            ReconcileScheduleErrorKind::Infrastructure
        );
        assert!(!format!("{infrastructure:?}").contains("SECRET_SCHEDULE_MARKER"));

        let conflict = ReconcileScheduleError::fact_conflict(consistency::OutboxFactConflict);
        assert_eq!(conflict.kind(), ReconcileScheduleErrorKind::FactConflict);
        assert_eq!(
            conflict.to_string(),
            "reconcile schedule store operation failed"
        );
        assert!(!format!("{conflict:?}").contains("fingerprint"));
    }

    #[test]
    fn operator_summary_rejects_active_target_with_quarantine_reason() -> TestResult {
        let tenant = rss_request_context::TenantId::parse("018f5d8a-7b6c-7d2e-8a1b-1234567890ab")?;
        assert!(
            ReconcileTargetSummary::new(
                tenant,
                "018f5d8a-7b6c-7d2e-8a1b-1234567890ac".to_owned(),
                "device".to_owned(),
                "device".to_owned(),
                ReconcileTargetStatus::Active,
                Some(ReconcileQuarantineReason::FactConflict),
            )
            .is_err()
        );
        Ok(())
    }
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::Notify;

    use consistency::{
        Context, ConvergeAction, EngineErrorKind, EntityId, Outcome, ReconcileError,
        ReconcileResultLabel, Reconciler, Request,
    };
    use diport::{LeaderElector, LeaderElectorError, LeaderId, LeaseToken};
    use primitives::{HealthStatus, ProbeName};
    use tokio_util::sync::CancellationToken;

    use crate::WorkerHealth;
    use crate::command::{CommandAliasKey, CommandIdempotencyKeyring};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[allow(clippy::expect_used)]
    fn keyring() -> Arc<CommandIdempotencyKeyring> {
        Arc::new(
            CommandIdempotencyKeyring::new(
                CommandAliasKey::new("current", vec![0x42; 32]).expect("key"),
                vec![CommandAliasKey::new("previous", vec![0x24; 32]).expect("key")],
            )
            .expect("keyring"),
        )
    }

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
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111")
            .expect("tenant")
    }

    fn claimed_target() -> ClaimedTarget {
        claimed_target_with_ids(
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "device-1",
        )
    }

    fn claimed_device_target() -> ClaimedTarget {
        claimed_device_target_with(tenant(), 9)
    }

    #[allow(clippy::expect_used)] // reason: fixed non-zero test fixture.
    fn claimed_device_target_with(
        tenant: rss_request_context::TenantId,
        epoch: u64,
    ) -> ClaimedTarget {
        ClaimedTarget::restore(ClaimedTargetRestore {
            tenant,
            target_id: "22222222-2222-2222-2222-222222222222".to_owned(),
            reconciler_id: "identity.device-certificate".to_owned(),
            resource_kind: "device-certificate".to_owned(),
            resource_id: "44444444-4444-4444-4444-444444444444".to_owned(),
            lease_token: "33333333-3333-3333-3333-333333333333".to_owned(),
            epoch,
            failure_streak: FailureStreak::restore(3),
            wake_version: WakeVersion::try_new(7).expect("wake version"),
            trigger: super::AttemptTrigger::Resync,
        })
    }

    #[allow(clippy::expect_used)]
    fn canonical_device_command_value(fence_epoch: u64) -> serde_json::Value {
        let mut value = serde_json::json!({
            "artifactDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifactId": "artifact-device-certificate-v1",
            "deadlineEpochSeconds": 4_000_000_000_u64,
            "desiredGeneration": 7_u64,
            "deviceId": "44444444-4444-4444-4444-444444444444",
            "fenceEpoch": fence_epoch,
            "intentDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "policyHash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        });
        let digest = canonical_fenced_intent_digest_value(
            value.clone(),
            generated::command::identity_v1::SPEC,
        )
        .expect("canonical semantic intent");
        value["intentDigest"] = serde_json::Value::String(format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ));
        value
    }

    #[allow(clippy::expect_used)]
    fn fenced_device_command(
        fence_epoch: u64,
    ) -> generated::command::identity_v1::FencedReconcileCommand {
        let request = serde_json::from_value(canonical_device_command_value(fence_epoch))
            .expect("schema fixture");
        generated::command::identity_v1::fenced_reconcile_command(request)
    }

    #[allow(clippy::expect_used)]
    fn command_time() -> (SystemTime, DeviceCertificateCommandTtl) {
        (
            SystemTime::UNIX_EPOCH + Duration::from_secs(3_999_999_940),
            DeviceCertificateCommandTtl::try_new(Duration::from_secs(60)).expect("ttl"),
        )
    }

    #[allow(clippy::expect_used)]
    // reason: fixed persisted wake coordinates are canonical unit-test fixtures.
    fn claimed_target_with_ids(
        target_id: &str,
        lease_token: &str,
        resource_id: &str,
    ) -> ClaimedTarget {
        claimed_target_with_fence(target_id, lease_token, resource_id, 9)
    }

    #[allow(clippy::expect_used)]
    // reason: fixed persisted wake coordinates are canonical generation-handoff fixtures.
    fn claimed_target_with_fence(
        target_id: &str,
        lease_token: &str,
        resource_id: &str,
        epoch: u64,
    ) -> ClaimedTarget {
        ClaimedTarget::restore(ClaimedTargetRestore {
            tenant: tenant(),
            target_id: target_id.to_owned(),
            reconciler_id: "test-reconciler".to_owned(),
            resource_kind: "device".to_owned(),
            resource_id: resource_id.to_owned(),
            lease_token: lease_token.to_owned(),
            epoch,
            failure_streak: FailureStreak::restore(3),
            wake_version: WakeVersion::try_new(7).expect("wake version"),
            trigger: super::AttemptTrigger::Resync,
        })
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed wake coordinates create two simultaneously-ready scheduler inputs.
    async fn due_tick_precedes_ready_targeted_wake() {
        let (_paused_tx, mut paused_rx) = tokio::sync::watch::channel(false);
        let (wake_tx, mut wake_rx) = tokio::sync::mpsc::channel(2);
        for version in [1, 2] {
            wake_tx
                .try_send(ReconcileWake::new(
                    "22222222-2222-2222-2222-222222222222",
                    WakeVersion::try_new(version).expect("wake version"),
                ))
                .expect("wake queue capacity");
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        let token = CancellationToken::new();

        let first = next_worker_event(
            &mut paused_rx,
            &mut wake_rx,
            &mut ticker,
            &token,
            true,
            true,
        )
        .await;
        let second = next_worker_event(
            &mut paused_rx,
            &mut wake_rx,
            &mut ticker,
            &token,
            true,
            true,
        )
        .await;
        tokio::time::advance(Duration::from_secs(30)).await;
        let third = next_worker_event(
            &mut paused_rx,
            &mut wake_rx,
            &mut ticker,
            &token,
            true,
            true,
        )
        .await;

        assert!(matches!(first, WorkerLoopEvent::Tick));
        assert!(matches!(second, WorkerLoopEvent::Targeted(_)));
        assert!(matches!(third, WorkerLoopEvent::Tick));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed boundary values prove the fallible wake restore/advance funnel.
    fn durable_retry_coordinates_are_closed_and_saturating() {
        let restored = FailureStreak::restore(41);
        assert_eq!(restored.get(), 41);
        assert_eq!(restored.next().get(), 42);
        assert_eq!(FailureStreak::restore(u32::MAX).next().get(), u32::MAX);

        let wake = WakeVersion::try_new(i64::MAX as u64).expect("maximum wake version");
        assert_eq!(wake.get(), i64::MAX as u64);
        assert!(WakeVersion::try_new(i64::MAX as u64 + 1).is_err());
        assert!(wake.next().is_err());
    }

    #[derive(Clone, Default)]
    struct FakeScheduleStore {
        state: Arc<Mutex<FakeScheduleState>>,
        claim_gate: Arc<Mutex<Option<Arc<ClaimGate>>>>,
        claims_changed: Arc<Notify>,
        released: Arc<Notify>,
        results_changed: Arc<Notify>,
    }

    #[derive(Default)]
    struct ClaimGate {
        entered: AtomicBool,
        changed: Notify,
        release: Notify,
    }

    impl ClaimGate {
        async fn wait_until_entered(&self) {
            let entered = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self.entered.load(Ordering::SeqCst) {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(
                entered.is_ok(),
                "claim should enter the controlled provider"
            );
        }
    }

    #[derive(Default)]
    struct FakeScheduleState {
        targets: VecDeque<ClaimedTarget>,
        targeted_targets: VecDeque<ClaimedTarget>,
        claims: u32,
        claim_error_once: bool,
        over_return_claims: bool,
        targeted_claims: u32,
        attempts: u32,
        attempt_triggers: Vec<super::AttemptTrigger>,
        results: Vec<AttemptResult>,
        actions: Vec<ConvergeAction>,
        command_keys: Vec<String>,
        releases: u32,
        released_fences: Vec<(String, u64)>,
        cancel_on_record: Option<CancellationToken>,
        cancel_on_extend_lost: Option<CancellationToken>,
        append_attempt_lost: bool,
        extend_outcome: Option<ScheduleLeaseOutcome>,
        extend_lost_target: Option<String>,
        extend_error_target: Option<String>,
        extensions_lost: u32,
        extension_errors: u32,
        release_outcome: Option<ScheduleLeaseOutcome>,
        release_error: bool,
        fact_conflict_on_action: bool,
        quarantines: u32,
        result_outcome: Option<ScheduleResultOutcome>,
        result_error: bool,
        completion_outcome: Option<ScheduleCompletionOutcome>,
        completions: u32,
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

        fn with_targeted_target(target: ClaimedTarget) -> Self {
            let store = Self::default();
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .targeted_targets
                .push_back(target);
            store
        }

        fn enqueue_target(&self, target: ClaimedTarget) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .targets
                .push_back(target);
        }

        fn block_next_claim(&self) -> Arc<ClaimGate> {
            let gate = Arc::new(ClaimGate::default());
            *self
                .claim_gate
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(Arc::clone(&gate));
            gate
        }

        fn over_return_claims(&self) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .over_return_claims = true;
        }

        fn fail_next_claim(&self) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .claim_error_once = true;
        }

        async fn wait_for_claims(&self, count: u32) {
            let claimed = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.claims_changed.notified();
                    if self
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .claims
                        >= count
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(
                claimed.is_ok(),
                "provider should observe the expected claims"
            );
        }

        async fn wait_for_releases(&self, count: u32) {
            let released = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let released = self.released.notified();
                    if self
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .releases
                        >= count
                    {
                        break;
                    }
                    released.await;
                }
            })
            .await;
            assert!(released.is_ok(), "claimed lease should be released");
        }

        async fn wait_for_results(&self, count: usize) {
            let recorded = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.results_changed.notified();
                    if self
                        .state
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .results
                        .len()
                        >= count
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(recorded.is_ok(), "attempt result should be recorded");
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

        fn lose_extend_for(&self, target_id: &str) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_lost_target = Some(target_id.to_owned());
        }

        fn fail_extend_for(&self, target_id: &str) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_error_target = Some(target_id.to_owned());
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

        fn quarantine_action(&self) {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fact_conflict_on_action = true;
        }

        fn fail_result_record(&self) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .result_error = true;
        }

        fn set_completion_outcome(&self, outcome: ScheduleCompletionOutcome) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .completion_outcome = Some(outcome);
        }
    }

    impl ReconcileScheduleStore for FakeScheduleStore {
        async fn claim_due_targets(
            &self,
            _tenant: rss_request_context::TenantId,
            _reconciler_id: &str,
            _holder_id: &str,
            limit: ReconcileMaxInFlight,
            _lease_ttl: Duration,
        ) -> Result<Vec<ClaimedTarget>, ReconcileScheduleError> {
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.claims = state.claims.saturating_add(1);
                self.claims_changed.notify_waiters();
                if state.claim_error_once {
                    state.claim_error_once = false;
                    return Err(ReconcileScheduleError::new(std::io::Error::other(
                        "claim failed",
                    )));
                }
            }
            let gate = self
                .claim_gate
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take();
            if let Some(gate) = gate {
                gate.entered.store(true, Ordering::SeqCst);
                gate.changed.notify_waiters();
                gate.release.notified().await;
            }
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let mut targets = Vec::new();
            let claim_count = if state.over_return_claims {
                state.targets.len()
            } else {
                usize::from(limit.get())
            };
            for _ in 0..claim_count {
                if let Some(target) = state.targets.pop_front() {
                    targets.push(target);
                }
            }
            Ok(targets)
        }

        async fn claim_targeted(
            &self,
            _tenant: rss_request_context::TenantId,
            _reconciler_id: &str,
            _holder_id: &str,
            wake: &ReconcileWake,
            _lease_ttl: Duration,
        ) -> Result<Option<ClaimedTarget>, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.targeted_claims = state.targeted_claims.saturating_add(1);
            let Some(mut target) = state.targeted_targets.pop_front() else {
                return Ok(None);
            };
            if target.target_id() != wake.target_id() || target.wake_version() != wake.version() {
                return Ok(None);
            }
            target.trigger = super::AttemptTrigger::Targeted;
            Ok(Some(target))
        }

        async fn append_attempt(
            &self,
            target: &ClaimedTarget,
            _holder_id: &str,
        ) -> Result<ScheduleAttemptOutcome, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.attempts = state.attempts.saturating_add(1);
            state.attempt_triggers.push(target.trigger());
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
        ) -> Result<ScheduleResultOutcome, ReconcileScheduleError> {
            let (cancel, outcome, error) = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.results.push(result);
                self.results_changed.notify_waiters();
                (
                    state.cancel_on_record.clone(),
                    state
                        .result_outcome
                        .unwrap_or(ScheduleResultOutcome::Recorded),
                    state.result_error,
                )
            };
            if let Some(token) = cancel {
                token.cancel();
            }
            if error {
                return Err(ReconcileScheduleError::new(std::io::Error::other(
                    "record failed",
                )));
            }
            Ok(outcome)
        }

        #[allow(clippy::expect_used)]
        // reason: the typed reconcile path always derives a current keyed alias before store I/O.
        async fn record_fenced_command(
            &self,
            _attempt: &ReconcileAttempt,
            action: ConvergeAction,
            command: ReviewedFencedCommand,
        ) -> Result<ScheduleActionOutcome, ReconcileScheduleError> {
            let (intent, _envelope, _audit, _deadline) = command.into_parts();
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.fact_conflict_on_action {
                state.quarantines = state.quarantines.saturating_add(1);
                return Err(ReconcileScheduleError::fact_conflict(
                    consistency::OutboxFactConflict,
                ));
            }
            state.actions.push(action);
            let current = intent.aliases().current().expect("keyed reconcile command");
            state
                .command_keys
                .push(format!("{}:{}", current.key_id(), current.digest().len()));
            Ok(ScheduleActionOutcome::Enqueued)
        }

        async fn complete_device_certificate_deletion(
            &self,
            _attempt: &ReconcileAttempt,
        ) -> Result<ScheduleCompletionOutcome, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.completions = state.completions.saturating_add(1);
            Ok(state
                .completion_outcome
                .unwrap_or(ScheduleCompletionOutcome::Completed))
        }

        async fn extend_lease(
            &self,
            target: &ClaimedTarget,
            _lease_ttl: Duration,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let (outcome, cancel) = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.extend_error_target.as_deref() == Some(target.target_id()) {
                    state.extension_errors = state.extension_errors.saturating_add(1);
                    return Err(ReconcileScheduleError::new(std::io::Error::other(
                        "extend failed",
                    )));
                }
                let outcome = if state.extend_lost_target.as_deref() == Some(target.target_id()) {
                    ScheduleLeaseOutcome::Lost
                } else {
                    state.extend_outcome.unwrap_or(ScheduleLeaseOutcome::Held)
                };
                if outcome == ScheduleLeaseOutcome::Lost {
                    state.extensions_lost = state.extensions_lost.saturating_add(1);
                }
                (outcome, state.cancel_on_extend_lost.clone())
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
            target: &ClaimedTarget,
        ) -> Result<ScheduleLeaseOutcome, ReconcileScheduleError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.releases = state.releases.saturating_add(1);
            state
                .released_fences
                .push((target.lease_token().to_owned(), target.epoch()));
            self.released.notify_waiters();
            if state.release_error {
                return Err(ReconcileScheduleError::new(std::io::Error::other(
                    "release failed",
                )));
            }
            Ok(state.release_outcome.unwrap_or(ScheduleLeaseOutcome::Held))
        }

        async fn pause_target(
            &self,
            _tenant: rss_request_context::TenantId,
            _target_id: &str,
        ) -> Result<(), ReconcileScheduleError> {
            Ok(())
        }

        async fn resume_target(
            &self,
            _tenant: rss_request_context::TenantId,
            _target_id: &str,
        ) -> Result<(), ReconcileScheduleError> {
            Ok(())
        }
    }

    enum DurableBehavior {
        Settled,
        Transient,
        Permanent,
        Panic,
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
        #[allow(clippy::panic)]
        // reason: the fake deliberately panics to prove durable panic retry classification.
        async fn reconcile(
            &self,
            ctx: &Context,
            _target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(ctx.epoch(), Some(vocab::Epoch::new(9)));
            match self.behavior {
                DurableBehavior::Settled => Ok(DurableReconcileOutcome::settled()),
                DurableBehavior::Transient => Err(ReconcileError::new(EngineErrorKind::Transient)),
                DurableBehavior::Permanent => Err(ReconcileError::new(EngineErrorKind::Permanent)),
                DurableBehavior::Panic => panic!("durable scripted reconcile panic"),
            }
        }
    }

    struct SlowFirstReconciler {
        active: AtomicUsize,
        peak: AtomicUsize,
        started: Mutex<Vec<String>>,
        changed: Notify,
    }

    impl SlowFirstReconciler {
        fn new() -> Self {
            Self {
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                started: Mutex::new(Vec::new()),
                changed: Notify::new(),
            }
        }

        async fn wait_for_started(&self, count: usize) {
            let filled = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self
                        .started
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .len()
                        >= count
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(
                filled.is_ok(),
                "scheduler should fill freed slots deterministically"
            );
        }
    }

    impl DurableReconciler<FakeScheduleStore> for Arc<SlowFirstReconciler> {
        async fn reconcile(
            &self,
            _ctx: &Context,
            target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(target.resource_id().to_owned());
            self.changed.notify_waiters();
            if target.resource_id() == "device-1" {
                std::future::pending::<()>().await;
            }
            self.active.fetch_sub(1, Ordering::SeqCst);
            Ok(DurableReconcileOutcome::settled())
        }
    }

    struct GenerationHandoffReconciler {
        active: Arc<AtomicUsize>,
        peak: AtomicUsize,
        started: Mutex<Vec<u64>>,
        changed: Notify,
        finish_new: Notify,
    }

    impl GenerationHandoffReconciler {
        fn new() -> Self {
            Self {
                active: Arc::new(AtomicUsize::new(0)),
                peak: AtomicUsize::new(0),
                started: Mutex::new(Vec::new()),
                changed: Notify::new(),
                finish_new: Notify::new(),
            }
        }

        async fn wait_for_started(&self, count: usize) {
            let started = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self
                        .started
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .len()
                        >= count
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(started.is_ok(), "replacement generation should start");
        }

        async fn wait_for_epoch(&self, epoch: u64) {
            let started = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self
                        .started
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .contains(&epoch)
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(
                started.is_ok(),
                "latest replacement generation should start"
            );
        }
    }

    struct ActiveGenerationGuard(Arc<AtomicUsize>);

    impl Drop for ActiveGenerationGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl DurableReconciler<FakeScheduleStore> for Arc<GenerationHandoffReconciler> {
        async fn reconcile(
            &self,
            _ctx: &Context,
            target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            let _guard = ActiveGenerationGuard(Arc::clone(&self.active));
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(target.epoch());
            self.changed.notify_waiters();
            if target.epoch() == 9 {
                std::future::pending::<()>().await;
            }
            self.finish_new.notified().await;
            Ok(DurableReconcileOutcome::settled())
        }
    }

    struct LeaseIsolationReconciler {
        started: AtomicUsize,
        changed: Notify,
        finish_other: Notify,
    }

    impl LeaseIsolationReconciler {
        async fn wait_until_both_started(&self) {
            let started = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self.started.load(Ordering::SeqCst) == 2 {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(started.is_ok(), "both attempts should start");
        }
    }

    impl DurableReconciler<FakeScheduleStore> for Arc<LeaseIsolationReconciler> {
        async fn reconcile(
            &self,
            _ctx: &Context,
            target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            if target.resource_id() == "device-1" {
                std::future::pending::<()>().await;
            }
            self.finish_other.notified().await;
            Ok(DurableReconcileOutcome::settled())
        }
    }

    struct ObservedDrainReconciler {
        started: AtomicUsize,
        changed: Notify,
        finish: Notify,
    }

    impl ObservedDrainReconciler {
        async fn wait_until_started(&self, count: usize) {
            let started = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let changed = self.changed.notified();
                    if self.started.load(Ordering::SeqCst) >= count {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            assert!(started.is_ok(), "expected {count} attempts to start");
        }
    }

    impl DurableReconciler<FakeScheduleStore> for Arc<ObservedDrainReconciler> {
        async fn reconcile(
            &self,
            _ctx: &Context,
            _target: &ClaimedTarget,
            _attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            self.changed.notify_waiters();
            self.finish.notified().await;
            Ok(DurableReconcileOutcome::settled())
        }
    }

    #[allow(clippy::unwrap_used)]
    // reason: tracing capture owns its isolated runtime and mutex; poisoning is a test failure.
    fn capture_durable_reconcile_events<F, Fut>(f: F) -> Vec<HashMap<String, String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        use tracing::field::{Field, Visit};
        use tracing::{Event, Subscriber};
        use tracing_subscriber::layer::{Context as LayerContext, Layer};
        use tracing_subscriber::prelude::*;

        struct CaptureLayer {
            events: Arc<Mutex<Vec<HashMap<String, String>>>>,
        }

        struct CaptureVisitor {
            fields: HashMap<String, String>,
        }

        impl Visit for CaptureVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.fields
                    .insert(field.name().to_owned(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.fields
                    .insert(field.name().to_owned(), value.to_owned());
            }
        }

        impl<S: Subscriber> Layer<S> for CaptureLayer {
            fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
                let mut visitor = CaptureVisitor {
                    fields: HashMap::from([(
                        "level".to_owned(),
                        event.metadata().level().as_str().to_owned(),
                    )]),
                };
                event.record(&mut visitor);
                self.events.lock().unwrap().push(visitor.fields);
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer {
            events: Arc::clone(&events),
        });
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(f());
            tracing::callsite::rebuild_interest_cache();
        });
        events.lock().unwrap().clone()
    }

    struct QuarantiningScript;

    impl DurableReconciler<FakeScheduleStore> for QuarantiningScript {
        #[allow(clippy::expect_used)]
        // reason: fixed unit-test command fixtures and injected fake outcomes are infallible.
        async fn reconcile(
            &self,
            _ctx: &Context,
            _target: &ClaimedTarget,
            attempt: &AttemptScope<'_, FakeScheduleStore>,
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
            let reviewed = attempt
                .review_device_certificate_command(
                    7,
                    "artifact-device-certificate-v1",
                    [0xaa; 32],
                    [0xbb; 32],
                    command_time().0,
                    command_time().1,
                )
                .expect("attempt-reviewed command");
            let error = attempt
                .record_device_certificate_command(ConvergeAction::Create, reviewed)
                .await
                .expect_err("fake fact conflict");
            assert_eq!(error.kind(), ReconcileScheduleErrorKind::FactConflict);
            Err(ReconcileError::new(EngineErrorKind::Invariant))
        }
    }

    #[allow(clippy::expect_used)]
    fn reviewed_command(attempt: &ReconcileAttempt) -> ReviewedFencedCommand {
        ReviewedFencedCommand::from_spec(
            fenced_device_command(attempt.target().epoch()),
            &keyring(),
            DeviceCertificateSystemProducer::install(),
            attempt,
        )
        .expect("reviewed command")
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed keyed reconcile fixtures must contain the current alias probe.
    fn typed_reviewed_command_derives_scope_actor_audit_and_aliases() -> TestResult {
        let attempt = ReconcileAttempt::new("attempt-audit", claimed_device_target());
        let command = reviewed_command(&attempt);
        let (intent, envelope, audit, deadline) = command.into_parts();
        let first_digest = intent.aliases().current().expect("keyed").digest().to_vec();
        assert_eq!(intent.topic(), generated::command::identity_v1::TOPIC);
        assert_eq!(envelope.tenant(), tenant());
        assert_eq!(audit.tenant(), tenant());
        assert_eq!(
            audit.device_id().to_string(),
            "44444444-4444-4444-4444-444444444444"
        );
        assert_eq!(audit.desired_generation().get(), 7);
        assert_eq!(audit.fence_epoch().get(), 9);
        assert_eq!(
            audit.producer_actor_id(),
            "rss.reconcile.device-certificate.v1"
        );
        assert_eq!(audit.attempt_id(), "attempt-audit");
        assert_eq!(deadline.get(), 4_000_000_000);

        let takeover =
            ReconcileAttempt::new("attempt-takeover", claimed_device_target_with(tenant(), 10));
        let (other_intent, _, takeover_audit, _) = reviewed_command(&takeover).into_parts();
        assert_ne!(
            first_digest,
            other_intent.aliases().current().expect("keyed").digest()
        );
        assert_eq!(takeover_audit.intent_digest(), audit.intent_digest());
        assert_eq!(takeover_audit.fence_epoch().get(), 10);

        Ok(())
    }

    #[test]
    fn durable_certificate_command_evidence_revalidates_payload_and_digest() -> TestResult {
        let attempt = ReconcileAttempt::new("attempt-evidence", claimed_device_target());
        let (intent, _, audit, deadline) = reviewed_command(&attempt).into_parts();
        let evidence = DeviceCertificateCommandEvidence::restore_durable(
            audit.clone(),
            intent.payload(),
            deadline.get(),
        )?;
        assert_eq!(evidence.tenant(), tenant());
        assert_eq!(evidence.device_id(), audit.device_id());
        assert_eq!(evidence.desired_generation().get(), 7);
        assert_eq!(evidence.fence_epoch().get(), 9);
        assert_eq!(evidence.intent_digest(), audit.intent_digest());
        assert_eq!(evidence.artifact_id(), "artifact-device-certificate-v1");
        assert_eq!(evidence.deadline_epoch_seconds(), deadline);
        assert_eq!(
            format!("{evidence:?}"),
            "DeviceCertificateCommandEvidence(<redacted>)"
        );

        let mut tampered: serde_json::Value = serde_json::from_slice(intent.payload())?;
        tampered["artifactId"] =
            serde_json::Value::String("artifact-device-certificate-v2".to_owned());
        let error = DeviceCertificateCommandEvidence::restore_durable(
            audit,
            &serde_json::to_vec(&tampered)?,
            deadline.get(),
        );
        assert_eq!(error.err(), Some(FencedCommandReviewError::Digest));
        Ok(())
    }

    #[test]
    fn canonical_fenced_intent_has_known_vector_and_rejects_payload_splicing() -> TestResult {
        let attempt = ReconcileAttempt::new("attempt-intent", claimed_device_target());
        let mut value = canonical_device_command_value(9);
        assert_eq!(
            value["intentDigest"].as_str(),
            Some("sha256:5235fccf9c0cdc3ccb274a3e9447af6d05eb602385287e39f1510caae609ac5c")
        );

        value["artifactId"] = serde_json::Value::String("artifact-device-certificate-v2".into());
        let request = serde_json::from_value(value)?;
        let command = generated::command::identity_v1::fenced_reconcile_command(request);
        let error = match ReviewedFencedCommand::from_spec(
            command,
            &keyring(),
            DeviceCertificateSystemProducer::install(),
            &attempt,
        ) {
            Err(error) => error,
            Ok(_) => return Err("semantic payload reused the prior digest".into()),
        };
        assert_eq!(error, FencedCommandReviewError::Digest);
        Ok(())
    }

    #[test]
    fn persistable_fenced_ranges_are_closed_and_classified() {
        assert!(PersistableDesiredGeneration::try_from_u64(1).is_some());
        assert!(PersistableDesiredGeneration::try_from_u64(i64::MAX as u64).is_some());
        assert!(PersistableDesiredGeneration::try_from_u64(i64::MAX as u64 + 1).is_none());
        assert!(PersistableFenceEpoch::try_from_u64(i64::MAX as u64 + 1).is_none());
        assert!(
            PersistableCommandDeadlineEpochSeconds::try_from_u64(MAX_FENCED_DEADLINE_EPOCH_SECONDS)
                .is_some()
        );
        assert!(
            PersistableCommandDeadlineEpochSeconds::try_from_u64(
                MAX_FENCED_DEADLINE_EPOCH_SECONDS + 1
            )
            .is_none()
        );
    }

    #[test]
    fn fenced_command_debug_surfaces_redact_intent_digest() -> TestResult {
        let value = canonical_device_command_value(9);
        let digest = value["intentDigest"].as_str().ok_or("digest")?.to_owned();
        let request = serde_json::from_value::<
            generated::command::identity_v1::IdentityApplyDeviceCertificateRequest,
        >(value)?;
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains(&digest));

        let carrier = generated::command::identity_v1::fenced_reconcile_command(request);
        let carrier_debug = format!("{carrier:?}");
        assert!(!carrier_debug.contains(&digest));

        let proof = reviewed_command(&ReconcileAttempt::new(
            "attempt-debug",
            claimed_device_target(),
        ))
        .into_parts()
        .2;
        let proof_debug = format!("{proof:?}");
        for forbidden in [
            tenant().to_string(),
            "44444444-4444-4444-4444-444444444444".to_owned(),
            "attempt-debug".to_owned(),
            "cc".repeat(32),
        ] {
            assert!(!proof_debug.contains(&forbidden), "leaked {forbidden}");
        }
        assert!(proof_debug.contains("redacted"));
        Ok(())
    }

    #[test]
    fn device_latent_lease_labels_are_closed_and_exhaustive() {
        let operations = [
            (LeaseOperation::Claim, "claim"),
            (LeaseOperation::Extend, "extend"),
            (LeaseOperation::Release, "release"),
        ];
        for (value, label) in operations {
            assert_eq!(value.as_label(), label);
        }

        let states = [
            (LeaseState::Held, "held"),
            (LeaseState::Lost, "lost"),
            (LeaseState::Error, "error"),
        ];
        for (value, label) in states {
            assert_eq!(value.as_label(), label);
        }

        let reasons = [
            (LeaseReason::DueScan, "due_scan"),
            (LeaseReason::TargetedWake, "targeted_wake"),
            (LeaseReason::Renewal, "renewal"),
            (LeaseReason::AttemptCancelled, "attempt_cancelled"),
            (LeaseReason::AppendAttemptFailed, "append_attempt_failed"),
            (
                LeaseReason::AttemptResultRecordFailed,
                "attempt_result_record_failed",
            ),
            (LeaseReason::SupersededReplacement, "superseded_replacement"),
            (LeaseReason::StaleGeneration, "stale_generation"),
            (LeaseReason::ClaimNotAdmitted, "claim_not_admitted"),
            (
                LeaseReason::ShutdownBeforeReplacement,
                "shutdown_before_replacement",
            ),
            (
                LeaseReason::PauseBeforeReplacement,
                "pause_before_replacement",
            ),
            (
                LeaseReason::ReplacementNotStarted,
                "replacement_not_started",
            ),
        ];
        for (value, label) in reasons {
            assert_eq!(value.as_label(), label);
        }
    }

    #[test]
    fn device_latent_lease_churn_uses_only_exact_closed_labels() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            emit_lease_churn(
                LeaseOperation::Claim,
                LeaseState::Held,
                LeaseReason::DueScan,
            );
            emit_lease_churn(
                LeaseOperation::Extend,
                LeaseState::Lost,
                LeaseReason::Renewal,
            );
            emit_lease_churn(
                LeaseOperation::Release,
                LeaseState::Error,
                LeaseReason::AttemptCancelled,
            );
        });
        let rendered = handle.render();
        let samples = rendered
            .lines()
            .filter(|line| line.starts_with("device_latent_lease_churn_total{"))
            .collect::<Vec<_>>();
        assert_eq!(samples.len(), 3, "unexpected samples: {rendered}");

        for labels in [
            "operation=\"claim\",state=\"held\",reason=\"due_scan\"",
            "operation=\"extend\",state=\"lost\",reason=\"renewal\"",
            "operation=\"release\",state=\"error\",reason=\"attempt_cancelled\"",
        ] {
            let exact = format!("device_latent_lease_churn_total{{{labels}}} 1");
            assert!(
                samples.contains(&exact.as_str()),
                "missing exact {labels}: {rendered}"
            );
        }
        for forbidden in [
            "tenant_id",
            "device_id",
            "command_id",
            "target_id",
            "resource_id",
            "holder_id",
            "attempt_id",
            "duration",
            "error_text",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn lease_release_store_outcomes_emit_behavior_lease_churn() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        #[allow(clippy::unwrap_used)]
        // reason: test runtime construction for local metrics capture.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        metrics::with_local_recorder(&recorder, || {
            rt.block_on(async {
                let target = claimed_target();
                let held = FakeScheduleStore::default();
                let driver = Arc::new(ReconcileDriver {
                    store: held,
                    reconciler: DurableScript::new(DurableBehavior::Settled),
                    keyring: keyring(),
                    producer: DeviceCertificateSystemProducer::install(),
                    tenant: tenant(),
                    reconciler_id: "test-reconciler".to_owned(),
                    holder_id: "holder-a".to_owned(),
                    trigger: trig(10),
                    backoff: BackoffPolicy::default(),
                    lease_ttl: Duration::from_secs(3),
                    health: Arc::new(WorkerHealth::healthy()),
                });
                driver
                    .release_lease_best_effort(&target, LeaseReason::AttemptCancelled)
                    .await;

                let lost = FakeScheduleStore::default();
                lost.set_release_outcome(ScheduleLeaseOutcome::Lost);
                let driver = Arc::new(ReconcileDriver {
                    store: lost,
                    reconciler: DurableScript::new(DurableBehavior::Settled),
                    keyring: keyring(),
                    producer: DeviceCertificateSystemProducer::install(),
                    tenant: tenant(),
                    reconciler_id: "test-reconciler".to_owned(),
                    holder_id: "holder-a".to_owned(),
                    trigger: trig(10),
                    backoff: BackoffPolicy::default(),
                    lease_ttl: Duration::from_secs(3),
                    health: Arc::new(WorkerHealth::healthy()),
                });
                driver
                    .release_lease_best_effort(&target, LeaseReason::DueScan)
                    .await;

                let errored = FakeScheduleStore::default();
                errored.fail_release();
                let driver = Arc::new(ReconcileDriver {
                    store: errored,
                    reconciler: DurableScript::new(DurableBehavior::Settled),
                    keyring: keyring(),
                    producer: DeviceCertificateSystemProducer::install(),
                    tenant: tenant(),
                    reconciler_id: "test-reconciler".to_owned(),
                    holder_id: "holder-a".to_owned(),
                    trigger: trig(10),
                    backoff: BackoffPolicy::default(),
                    lease_ttl: Duration::from_secs(3),
                    health: Arc::new(WorkerHealth::healthy()),
                });
                driver
                    .release_lease_best_effort(&target, LeaseReason::Renewal)
                    .await;

                let claim = FakeScheduleStore::with_target(claimed_target());
                let driver = Arc::new(ReconcileDriver {
                    store: claim,
                    reconciler: DurableScript::new(DurableBehavior::Settled),
                    keyring: keyring(),
                    producer: DeviceCertificateSystemProducer::install(),
                    tenant: tenant(),
                    reconciler_id: "test-reconciler".to_owned(),
                    holder_id: "holder-a".to_owned(),
                    trigger: trig(10),
                    backoff: BackoffPolicy::default(),
                    lease_ttl: Duration::from_secs(3),
                    health: Arc::new(WorkerHealth::healthy()),
                });
                let _ = execute_worker_job(
                    driver,
                    WorkerJobRequest::ClaimDue(ReconcileMaxInFlight::try_new(1).expect("limit")),
                )
                .await;
            });
        });
        let rendered = handle.render();
        for labels in [
            "operation=\"release\",state=\"held\",reason=\"attempt_cancelled\"",
            "operation=\"release\",state=\"lost\",reason=\"due_scan\"",
            "operation=\"release\",state=\"error\",reason=\"renewal\"",
            "operation=\"claim\",state=\"held\",reason=\"due_scan\"",
        ] {
            let exact = format!("device_latent_lease_churn_total{{{labels}}} 1");
            assert!(
                rendered.lines().any(|line| line == exact),
                "missing behavior sample {labels}: {rendered}"
            );
        }
    }

    #[test]
    fn fenced_review_error_classification_is_closed() {
        assert_eq!(
            ReconcileScheduleError::fenced_review(FencedCommandReviewError::Digest).kind(),
            ReconcileScheduleErrorKind::PermanentFailure
        );
        assert_eq!(
            ReconcileScheduleError::fenced_review(FencedCommandReviewError::DeadlineRange).kind(),
            ReconcileScheduleErrorKind::PermanentFailure
        );
        for error in [
            FencedCommandReviewError::Scope,
            FencedCommandReviewError::Fence,
            FencedCommandReviewError::Causation,
            FencedCommandReviewError::RequestEncoding,
            FencedCommandReviewError::ProducerIdentity,
            FencedCommandReviewError::CoordinateRange,
        ] {
            assert_eq!(
                ReconcileScheduleError::fenced_review(error).kind(),
                ReconcileScheduleErrorKind::InvariantViolation
            );
        }
    }

    #[tokio::test]
    async fn attempt_scope_records_action_and_command_through_single_store_call() -> TestResult {
        let store = FakeScheduleStore::default();
        let attempt = ReconcileAttempt::new("attempt-scope", claimed_device_target());
        let keys = keyring();
        let scope = AttemptScope::new(
            &store,
            &keys,
            DeviceCertificateSystemProducer::install(),
            attempt,
        );

        let snapshot = scope.device_certificate_snapshot()?;
        assert_eq!(
            snapshot.device_id(),
            uuid::Uuid::parse_str("44444444-4444-4444-4444-444444444444")?
        );
        assert_eq!(snapshot.epoch(), 9);
        assert_eq!(snapshot.wake_version().get(), 7);

        let (now, ttl) = command_time();
        let reviewed = scope.review_device_certificate_command(
            7,
            "artifact-device-certificate-v1",
            [0xaa; 32],
            [0xbb; 32],
            now,
            ttl,
        )?;
        let outcome = scope
            .record_device_certificate_command(ConvergeAction::Create, reviewed)
            .await?;

        assert_eq!(outcome, ScheduleActionOutcome::Enqueued);
        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.actions, vec![ConvergeAction::Create]);
        assert_eq!(state.command_keys.len(), 1);
        assert_eq!(state.command_keys[0], "current:32");
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn reviewed_certificate_command_cannot_cross_attempts() -> TestResult {
        let store = FakeScheduleStore::default();
        let keys = keyring();
        let source = AttemptScope::new(
            &store,
            &keys,
            DeviceCertificateSystemProducer::install(),
            ReconcileAttempt::new("attempt-source", claimed_device_target()),
        );
        let destination = AttemptScope::new(
            &store,
            &keys,
            DeviceCertificateSystemProducer::install(),
            ReconcileAttempt::new("attempt-destination", claimed_device_target()),
        );
        let (now, ttl) = command_time();
        let reviewed = source.review_device_certificate_command(
            7,
            "artifact-device-certificate-v1",
            [0xaa; 32],
            [0xbb; 32],
            now,
            ttl,
        )?;

        let error = destination
            .record_device_certificate_command(ConvergeAction::Create, reviewed)
            .await
            .expect_err("an attempt-reviewed command must not cross attempt identities");

        assert_eq!(error.kind(), ReconcileScheduleErrorKind::InvariantViolation);
        assert_eq!(
            destination.quarantine_reason(),
            Some(ReconcileQuarantineReason::InvariantViolation)
        );
        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(state.actions.is_empty());
        assert!(state.command_keys.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn certificate_completion_receipt_suppresses_duplicate_attempt_result() -> TestResult {
        let store = FakeScheduleStore::default();
        let attempt = ReconcileAttempt::new("attempt-complete", claimed_device_target());
        let keys = keyring();
        let scope = AttemptScope::new(
            &store,
            &keys,
            DeviceCertificateSystemProducer::install(),
            attempt.clone(),
        );
        let receipt = match scope.complete_device_certificate_deletion().await? {
            AttemptCompletionOutcome::Completed(receipt) => receipt,
            other => return Err(format!("unexpected completion outcome: {other:?}").into()),
        };
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "identity.device-certificate",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        worker
            .driver
            .finish_attempt(attempt, Ok(Ok(DurableReconcileOutcome::completed(receipt))))
            .await;
        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.completions, 1);
        assert!(
            state.results.is_empty(),
            "scheduler must not persist an already committed completion twice"
        );
        Ok(())
    }

    #[tokio::test]
    async fn certificate_completion_pending_evidence_cannot_mint_receipt() -> TestResult {
        let store = FakeScheduleStore::default();
        store.set_completion_outcome(ScheduleCompletionOutcome::EvidencePending);
        let attempt = ReconcileAttempt::new("attempt-pending", claimed_device_target());
        let keys = keyring();
        let scope = AttemptScope::new(
            &store,
            &keys,
            DeviceCertificateSystemProducer::install(),
            attempt,
        );
        assert!(matches!(
            scope.complete_device_certificate_deletion().await?,
            AttemptCompletionOutcome::EvidencePending
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed positive builder fixture is part of the quarantine worker proof.
    async fn reconcile_worker_terminally_records_fact_conflict_quarantine() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_device_target());
        store.quarantine_action();
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            QuarantiningScript,
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "identity.device-certificate",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_max_in_flight(ReconcileMaxInFlight::try_new(1).expect("valid concurrency"))
        .build();
        let health = worker.health();

        worker.run(token).await;

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.quarantines, 1);
        assert!(
            state.actions.is_empty(),
            "quarantined action must roll back"
        );
        assert_eq!(state.results.len(), 1);
        assert_eq!(state.results[0].result(), ReconcileResultLabel::Invariant);
        assert_eq!(
            state.results[0].error_kind(),
            Some(AttemptErrorKind::Invariant)
        );
        assert_eq!(state.releases, 0, "result transaction releases the lease");
        assert_ne!(health.status(), HealthStatus::Healthy);
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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

        advance_paused(Duration::from_secs(1)).await;
        assert_eq!(
            store.state.lock().unwrap_or_else(|e| e.into_inner()).claims,
            0,
            "paused worker must not claim new targets"
        );

        control.resume();
        advance_paused(Duration::from_secs(10)).await;
        handle.await.expect("worker exits after fake result record");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.claims, 1);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 0, "result transaction releases the lease");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reconcile_worker_pause_releases_claim_race_without_starting_attempt() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        let gate = store.block_next_claim();
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .build();
        let control = worker.control();
        let handle = tokio::spawn(worker.run(token.clone()));

        gate.wait_until_entered().await;
        control.pause();
        gate.release.notify_one();
        store.wait_for_releases(1).await;

        token.cancel();
        assert!(
            handle.await.is_ok(),
            "paused worker exits after cancellation"
        );
        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 0);
        assert_eq!(state.releases, 1);
    }

    #[tokio::test]
    async fn reconcile_worker_shutdown_releases_claim_race_without_starting_attempt() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        let gate = store.block_next_claim();
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .build();
        let handle = tokio::spawn(worker.run(token.clone()));

        gate.wait_until_entered().await;
        token.cancel();
        gate.release.notify_one();
        store.wait_for_releases(1).await;
        assert!(handle.await.is_ok(), "shutdown drains claim-race release");

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 0);
        assert_eq!(state.releases, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_worker_pause_drains_active_attempt_without_refill() {
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
        let reconciler = Arc::new(LeaseIsolationReconciler {
            started: AtomicUsize::new(0),
            changed: Notify::new(),
            finish_other: Notify::new(),
        });
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();
        let control = worker.control();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_until_both_started().await;
        control.pause();
        reconciler.finish_other.notify_one();
        store.wait_for_results(1).await;
        assert_eq!(reconciler.started.load(Ordering::SeqCst), 2);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .attempts,
            2,
            "paused drain must not refill the freed slot"
        );

        token.cancel();
        assert!(handle.await.is_ok(), "paused worker drains on shutdown");
    }

    #[tokio::test]
    async fn reconcile_worker_control_observes_pause_drain_resume_and_stop() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_targets([
            claimed_target(),
            claimed_target_with_ids(
                "44444444-4444-4444-4444-444444444444",
                "55555555-5555-5555-5555-555555555555",
                "device-2",
            ),
        ]);
        let reconciler = Arc::new(ObservedDrainReconciler {
            started: AtomicUsize::new(0),
            changed: Notify::new(),
            finish: Notify::new(),
        });
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(1))
        .build();
        let control = worker.control();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_until_started(1).await;
        assert_eq!(control.in_flight(), 1);
        assert!(!control.is_drained(), "active attempt is not drained");

        control.pause();
        reconciler.finish.notify_one();
        control.wait_drained().await;
        assert_eq!(control.in_flight(), 0);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .attempts,
            1,
            "pause must not refill after the active attempt drains"
        );

        control.resume();
        assert!(
            !control.is_drained(),
            "resume closes the drained observation"
        );
        reconciler.wait_until_started(2).await;
        reconciler.finish.notify_one();
        store.wait_for_results(2).await;

        token.cancel();
        assert!(handle.await.is_ok(), "worker stops after cancellation");
        assert!(control.is_stopped());
        assert!(control.is_drained());
        control.resume();
        assert!(
            control.is_drained(),
            "a stopped worker remains terminally drained"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_worker_ready_tick_cannot_starve_completed_claim() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.cancel_on_record(token.clone());
        let gate = store.block_next_claim();
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            Trigger::interval(Duration::from_nanos(1)).unwrap_or_else(|_| unreachable!()),
        )
        .build();
        let handle = tokio::spawn(worker.run(token));

        gate.wait_until_entered().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        gate.release.notify_one();
        assert!(
            handle.await.is_ok(),
            "ready claim must outrun overdue ticks"
        );
        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 1);
        assert_eq!(state.results.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_worker_tick_does_not_mask_claim_failure() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::default();
        store.fail_next_claim();
        let gate = store.block_next_claim();
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(1),
        )
        .build();
        let health = worker.health();
        let handle = tokio::spawn(worker.run(token.clone()));

        store.wait_for_claims(1).await;
        while health.status() != HealthStatus::Degraded {
            tokio::task::yield_now().await;
        }
        assert_eq!(health.status(), HealthStatus::Degraded);
        tokio::time::advance(Duration::from_secs(1)).await;
        gate.wait_until_entered().await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "tick alone must not recover readiness"
        );

        gate.release.notify_one();
        store.wait_for_claims(2).await;
        while health.status() != HealthStatus::Healthy {
            tokio::task::yield_now().await;
        }
        token.cancel();
        assert!(
            handle.await.is_ok(),
            "worker exits after health recovery proof"
        );
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
        advance_paused(Duration::from_secs(1)).await;
        handle.await.expect("worker exits after fake result record");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.results.len(), 1);
        let result = state.results[0];
        assert_eq!(result.result(), ReconcileResultLabel::Transient);
        assert_eq!(
            result.error_kind(),
            Some(super::AttemptErrorKind::Transient)
        );
        assert_eq!(
            result.schedule(),
            AttemptSchedule::After(Duration::from_secs(8)),
            "restored failure streak 3 advances to durable retry 4"
        );
        assert_eq!(state.releases, 0, "result transaction releases the lease");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: the scripted panic is caught and the fake cancels after durable result record.
    async fn reconcile_worker_uses_claimed_failure_streak_for_panic_backoff() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Panic),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();

        worker.run(token).await;

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.results[0].result(), ReconcileResultLabel::Transient);
        assert_eq!(
            state.results[0].schedule(),
            AttemptSchedule::After(Duration::from_secs(8))
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed wake and worker fixtures are valid and the fake cancels on result record.
    async fn reconcile_worker_claims_versioned_targeted_wake_and_audits_trigger() {
        let token = CancellationToken::new();
        let target = claimed_target();
        let wake = ReconcileWake::new(target.target_id(), target.wake_version());
        let store = FakeScheduleStore::with_targeted_target(target);
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
        control.try_wake(wake).expect("bounded wake queue");

        worker.run(token).await;

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            state.claims, 1,
            "initial due tick runs before the queued exact wake"
        );
        assert_eq!(state.targeted_claims, 1);
        assert_eq!(
            state.attempt_triggers,
            vec![super::AttemptTrigger::Targeted]
        );
        assert_eq!(state.results.len(), 1);
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed wake fixtures fill the bounded queue without awaiting a worker.
    fn reconcile_worker_control_has_bounded_non_authoritative_wakes() {
        let worker = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        let control = worker.control();
        let version = WakeVersion::try_new(1).expect("wake version");
        for index in 0..TARGETED_WAKE_BUFFER {
            control
                .try_wake(ReconcileWake::new(format!("target-{index}"), version))
                .expect("within bounded capacity");
        }
        assert_eq!(
            control.try_wake(ReconcileWake::new("overflow", version)),
            Err(ReconcileWakeError::QueueFull)
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: the fake cancels after recording the closed permanent quarantine result.
    async fn reconcile_worker_quarantines_permanent_failure_without_periodic_schedule() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Permanent),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();

        worker.run(token).await;

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            state.results[0].schedule(),
            AttemptSchedule::Quarantine(ReconcileQuarantineReason::PermanentFailure)
        );
        assert_eq!(state.releases, 0, "result transaction releases the lease");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed worker fixture validates the only post-result explicit release path.
    async fn reconcile_worker_releases_best_effort_only_when_result_record_errors() {
        let token = CancellationToken::new();
        let store = FakeScheduleStore::with_target(claimed_target());
        store.fail_result_record();
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();

        worker.run(token).await;

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.releases, 1);
    }

    #[test]
    fn durable_builder_rejects_zero_lease_ttl() {
        let result = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
    fn durable_max_in_flight_has_closed_bounds() {
        assert!(ReconcileMaxInFlight::try_new(0).is_err());
        assert_eq!(
            ReconcileMaxInFlight::try_new(1).map(ReconcileMaxInFlight::get),
            Ok(1)
        );
        assert_eq!(
            ReconcileMaxInFlight::try_new(64).map(ReconcileMaxInFlight::get),
            Ok(64)
        );
        assert!(ReconcileMaxInFlight::try_new(65).is_err());
    }

    #[tokio::test]
    async fn reconcile_worker_refills_slots_without_waiting_for_slow_target() {
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
            claimed_target_with_ids(
                "88888888-8888-8888-8888-888888888888",
                "99999999-9999-9999-9999-999999999999",
                "device-4",
            ),
        ]);
        let reconciler = Arc::new(SlowFirstReconciler::new());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();

        let handle = tokio::spawn(worker.run(token.clone()));
        reconciler.wait_for_started(4).await;

        let started = reconciler
            .started
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        assert_eq!(reconciler.peak.load(Ordering::SeqCst), 2);
        assert!(
            started.iter().position(|id| id == "device-3")
                < started.iter().position(|id| id == "device-4")
        );
        assert_eq!(reconciler.active.load(Ordering::SeqCst), 1);

        token.cancel();
        assert!(handle.await.is_ok(), "worker drains after cancellation");
        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 4);
        assert_eq!(
            state.releases, 1,
            "only the cancelled slow attempt releases"
        );
    }

    #[tokio::test]
    async fn reconcile_worker_discards_same_fence_duplicate_without_release() {
        let token = CancellationToken::new();
        let target = claimed_target();
        let store = FakeScheduleStore::with_targets([target.clone(), target]);
        store.cancel_on_record(token.clone());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();

        worker.run(token).await;

        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: fixed typed scheduler and wake fixtures prove generation handoff deterministically.
    async fn reconcile_worker_due_new_epoch_cancels_then_replaces_active_generation() {
        let token = CancellationToken::new();
        let old = claimed_target();
        let new = claimed_target_with_fence(
            old.target_id(),
            "44444444-4444-4444-4444-444444444444",
            old.resource_id(),
            10,
        );
        let store = FakeScheduleStore::with_target(old.clone());
        let reconciler = Arc::new(GenerationHandoffReconciler::new());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            Trigger::interval(Duration::from_millis(1)).expect("nonzero interval"),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_for_started(1).await;
        store.enqueue_target(new.clone());
        store.wait_for_claims(2).await;
        reconciler.wait_for_started(2).await;

        assert_eq!(reconciler.peak.load(Ordering::SeqCst), 1);
        assert_eq!(
            *reconciler
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            vec![9, 10]
        );
        let released = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .released_fences
            .clone();
        assert!(released.contains(&(old.lease_token().to_owned(), old.epoch())));
        assert!(!released.contains(&(new.lease_token().to_owned(), new.epoch())));

        reconciler.finish_new.notify_one();
        store.wait_for_results(1).await;
        token.cancel();
        assert!(handle.await.is_ok(), "generation-aware worker should drain");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: fixed typed scheduler and wake fixtures prove targeted generation handoff.
    async fn reconcile_worker_targeted_new_epoch_cancels_then_replaces_active_generation() {
        let token = CancellationToken::new();
        let old = claimed_target();
        let new = claimed_target_with_fence(
            old.target_id(),
            "44444444-4444-4444-4444-444444444444",
            old.resource_id(),
            10,
        );
        let store = FakeScheduleStore::with_target(old.clone());
        store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .targeted_targets
            .push_back(new.clone());
        let reconciler = Arc::new(GenerationHandoffReconciler::new());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();
        let control = worker.control();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_for_started(1).await;
        control
            .try_wake(ReconcileWake::new(old.target_id(), new.wake_version()))
            .expect("bounded wake queue");
        reconciler.wait_for_started(2).await;

        assert_eq!(reconciler.peak.load(Ordering::SeqCst), 1);
        let released = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .released_fences
            .clone();
        assert!(released.contains(&(old.lease_token().to_owned(), old.epoch())));
        assert!(!released.contains(&(new.lease_token().to_owned(), new.epoch())));

        reconciler.finish_new.notify_one();
        store.wait_for_results(1).await;
        token.cancel();
        assert!(handle.await.is_ok(), "targeted replacement should drain");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    // reason: fixed lease epochs prove a bounded handoff keeps only the latest generation.
    async fn reconcile_worker_replacement_accepts_only_strictly_newer_epoch() {
        let token = CancellationToken::new();
        let old = claimed_target();
        let middle = claimed_target_with_fence(
            old.target_id(),
            "44444444-4444-4444-4444-444444444444",
            old.resource_id(),
            10,
        );
        let latest = claimed_target_with_fence(
            old.target_id(),
            "55555555-5555-5555-5555-555555555555",
            old.resource_id(),
            11,
        );
        let store = FakeScheduleStore::with_target(old.clone());
        let reconciler = Arc::new(GenerationHandoffReconciler::new());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            Trigger::interval(Duration::from_millis(1)).expect("nonzero interval"),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_for_started(1).await;
        store.enqueue_target(middle.clone());
        store.enqueue_target(latest.clone());
        reconciler.wait_for_epoch(11).await;

        assert_eq!(reconciler.peak.load(Ordering::SeqCst), 1);
        assert_eq!(
            reconciler
                .started
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .last(),
            Some(&11)
        );
        let released = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .released_fences
            .clone();
        assert!(released.contains(&(old.lease_token().to_owned(), old.epoch())));
        assert!(released.contains(&(middle.lease_token().to_owned(), middle.epoch())));
        assert!(!released.contains(&(latest.lease_token().to_owned(), latest.epoch())));

        reconciler.finish_new.notify_one();
        store.wait_for_results(1).await;
        token.cancel();
        assert!(handle.await.is_ok(), "latest generation should drain");
    }

    #[tokio::test]
    async fn reconcile_worker_pause_and_shutdown_release_unstarted_replacements() {
        for cancelled in [false, true] {
            let root = CancellationToken::new();
            let old = claimed_target();
            let replacement = claimed_target_with_fence(
                old.target_id(),
                "44444444-4444-4444-4444-444444444444",
                old.resource_id(),
                10,
            );
            let worker = ReconcileSchedulerBuilder::new(
                FakeScheduleStore::default(),
                DurableScript::new(DurableBehavior::Settled),
                keyring(),
                DeviceCertificateSystemProducer::install(),
                tenant(),
                "test-reconciler",
                "holder-a",
                Tenancy::tenant_scoped(),
                trig(60),
            )
            .build();
            let mut state = SchedulerState::new(false);
            let attempt_cancel = state.start_target(&old, &root);
            assert!(matches!(
                state.classify_target(&replacement, max_in_flight(16)),
                TargetAdmission::NewerFence
            ));
            assert!(state.queue_replacement(replacement.clone()).is_none());
            assert!(attempt_cancel.is_cancelled());

            let requests = if cancelled {
                worker.handle_worker_event(WorkerLoopEvent::Cancelled, &mut state)
            } else {
                worker.control().pause();
                worker.handle_worker_event(WorkerLoopEvent::PauseChanged, &mut state)
            };
            assert_eq!(requests.len(), 1);
            assert!(matches!(
                &requests[0],
                WorkerJobRequest::Release(target, _) if same_lease_fence(target, &replacement)
            ));
            assert!(
                state
                    .active_targets
                    .get(old.target_id())
                    .is_some_and(|active| active.replacement.is_none())
            );
            for request in requests {
                let _ = super::execute_worker_job(Arc::clone(&worker.driver), request).await;
            }
            assert!(
                worker
                    .driver
                    .store
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .released_fences
                    .iter()
                    .any(|released| {
                        released == &(replacement.lease_token().to_owned(), replacement.epoch())
                    }),
                "an unstarted replacement must be CAS released"
            );
        }
    }

    #[test]
    fn reconcile_worker_stale_completion_cannot_remove_replacement_generation() {
        let root = CancellationToken::new();
        let old = claimed_target();
        let replacement = claimed_target_with_fence(
            old.target_id(),
            "44444444-4444-4444-4444-444444444444",
            old.resource_id(),
            10,
        );
        let worker = ReconcileSchedulerBuilder::new(
            FakeScheduleStore::default(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .build();
        let health = worker.health();
        let mut state = SchedulerState::new(false);
        state.start_target(&old, &root);
        assert!(state.queue_replacement(replacement.clone()).is_none());
        let old_fence = ActiveLeaseFence::from_target(&old);

        let replacement_request = worker.handle_worker_job(
            WorkerJob::AttemptFinished {
                target_id: old.target_id().to_owned(),
                fence: old_fence.clone(),
            },
            &mut state,
            &root,
        );
        assert!(matches!(
            replacement_request.first(),
            Some(WorkerJobRequest::RunAttempt { target, .. }) if same_lease_fence(target, &replacement)
        ));

        let stale_request = worker.handle_worker_job(
            WorkerJob::AttemptFinished {
                target_id: old.target_id().to_owned(),
                fence: old_fence,
            },
            &mut state,
            &root,
        );
        assert!(stale_request.is_empty());
        assert_eq!(state.attempts_in_flight, 1);
        assert!(
            state
                .active_targets
                .get(old.target_id())
                .is_some_and(|active| active.fence.matches(&replacement))
        );
        assert_eq!(health.status(), HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn reconcile_worker_releases_provider_overflow_without_exceeding_bound() {
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
        store.over_return_claims();
        let reconciler = Arc::new(SlowFirstReconciler::new());
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .build();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_for_started(2).await;
        store.wait_for_releases(1).await;
        assert_eq!(reconciler.peak.load(Ordering::SeqCst), 2);
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .attempts,
            2
        );

        token.cancel();
        assert!(handle.await.is_ok(), "worker drains bounded attempts");
    }

    #[test]
    fn durable_attempt_result_classifies_success_labels() {
        let default_next = Duration::from_secs(60);
        let settled = AttemptResult::from_outcome(&Outcome::settled(), default_next);
        assert_eq!(settled.result(), ReconcileResultLabel::Settled);
        assert_eq!(settled.schedule(), AttemptSchedule::After(default_next));
        assert_eq!(settled.requeue_after(), None);
        assert_eq!(settled.error_kind(), None);

        let requeue_after = Duration::from_millis(250);
        let requeue = AttemptResult::from_outcome(
            &Outcome::requeue_after(requeue_after),
            Duration::from_secs(60),
        );
        assert_eq!(requeue.result(), ReconcileResultLabel::RequeueAfter);
        assert_eq!(requeue.schedule(), AttemptSchedule::After(requeue_after));
        assert_eq!(requeue.requeue_after(), Some(requeue_after));
        assert_eq!(requeue.error_kind(), None);
    }

    #[test]
    fn durable_attempt_result_classifies_error_labels() {
        let transient = AttemptResult::from_transient(Duration::from_secs(1));
        assert_eq!(transient.result(), ReconcileResultLabel::Transient);
        assert_eq!(transient.error_kind(), Some(AttemptErrorKind::Transient));

        let permanent = AttemptResult::from_permanent();
        assert_eq!(permanent.result(), ReconcileResultLabel::Permanent);
        assert_eq!(permanent.error_kind(), Some(AttemptErrorKind::Permanent));
        assert_eq!(
            permanent.schedule(),
            AttemptSchedule::Quarantine(ReconcileQuarantineReason::PermanentFailure)
        );

        let invariant = AttemptResult::from_invariant();
        assert_eq!(invariant.result(), ReconcileResultLabel::Invariant);
        assert_eq!(invariant.error_kind(), Some(AttemptErrorKind::Invariant));
        assert_eq!(
            invariant.schedule(),
            AttemptSchedule::Quarantine(ReconcileQuarantineReason::InvariantViolation)
        );

        let panic = AttemptResult::from_panic(Duration::from_secs(1));
        assert_eq!(panic.result(), ReconcileResultLabel::Transient);
        assert_eq!(panic.error_kind(), Some(AttemptErrorKind::Transient));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: fixed attempts drive every closed durable failure classification through tracing.
    fn durable_attempt_failures_emit_closed_pii_safe_structured_events() {
        let events = capture_durable_reconcile_events(|| async {
            let worker = ReconcileSchedulerBuilder::new(
                FakeScheduleStore::default(),
                DurableScript::new(DurableBehavior::Settled),
                keyring(),
                DeviceCertificateSystemProducer::install(),
                tenant(),
                "test-reconciler",
                "holder-a",
                Tenancy::tenant_scoped(),
                trig(10),
            )
            .build();
            let results: Vec<(&str, super::DurableRunResult)> = vec![
                (
                    "attempt-transient",
                    Ok(Err(ReconcileError::new(EngineErrorKind::Transient))),
                ),
                (
                    "attempt-permanent",
                    Ok(Err(ReconcileError::new(EngineErrorKind::Permanent))),
                ),
                (
                    "attempt-invariant",
                    Ok(Err(ReconcileError::new(EngineErrorKind::Invariant))),
                ),
                ("attempt-panic", Err(Box::new("SECRET_PANIC_PAYLOAD"))),
            ];
            for (attempt_id, result) in results {
                worker
                    .driver
                    .finish_attempt(ReconcileAttempt::new(attempt_id, claimed_target()), result)
                    .await;
            }
        });

        let failure_events = events
            .iter()
            .filter(|event| {
                event
                    .get("message")
                    .is_some_and(|message| message.contains("durable attempt classified"))
            })
            .collect::<Vec<_>>();
        assert_eq!(failure_events.len(), 4, "events={events:?}");
        let observed = failure_events
            .iter()
            .map(|event| {
                event
                    .get("failure_kind")
                    .expect("closed failure kind")
                    .trim_matches('"')
            })
            .collect::<Vec<_>>();
        assert_eq!(observed, ["transient", "permanent", "invariant", "panic"]);
        for event in failure_events {
            for required in [
                "reconciler_id",
                "resource_kind",
                "trigger",
                "failure_kind",
                "failure_streak",
                "retry_scheduled",
                "retry_after_ms",
            ] {
                assert!(
                    event.contains_key(required),
                    "missing {required}: {event:?}"
                );
            }
            for forbidden in [
                "tenant_id",
                "resource_id",
                "target_id",
                "holder_id",
                "attempt_id",
                "error",
                "panic_payload",
            ] {
                assert!(
                    !event.contains_key(forbidden),
                    "leaked {forbidden}: {event:?}"
                );
            }
            assert!(!format!("{event:?}").contains("SECRET_PANIC_PAYLOAD"));
        }
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
        advance_paused(Duration::from_secs(1)).await;
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
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
        advance_paused(Duration::from_secs(2)).await;
        handle.await.expect("worker exits after lease loss");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(entered.load(Ordering::SeqCst), "reconciler should start");
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 0, "lost lease must not be released again");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed whole-second lease fixture is validated before the isolation proof runs.
    async fn reconcile_worker_lease_loss_isolated_to_one_attempt() {
        let token = CancellationToken::new();
        let first = claimed_target();
        let second = claimed_target_with_ids(
            "44444444-4444-4444-4444-444444444444",
            "55555555-5555-5555-5555-555555555555",
            "device-2",
        );
        let store = FakeScheduleStore::with_targets([first.clone(), second]);
        store.lose_extend_for(first.target_id());
        store.cancel_on_record(token.clone());
        let reconciler = Arc::new(LeaseIsolationReconciler {
            started: AtomicUsize::new(0),
            changed: Notify::new(),
            finish_other: Notify::new(),
        });
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token.clone()));
        reconciler.wait_until_both_started().await;
        advance_paused(Duration::from_secs(2)).await;
        assert!(
            !token.is_cancelled(),
            "target-local lease loss must not cancel root"
        );
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extensions_lost,
            1
        );

        reconciler.finish_other.notify_one();
        assert!(
            handle.await.is_ok(),
            "unaffected attempt records and stops worker"
        );
        let state = store
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.attempts, 2);
        assert_eq!(
            state.results.len(),
            1,
            "the unaffected attempt must complete"
        );
        assert_eq!(state.releases, 0, "lost lease is not released again");
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)]
    // reason: fixed whole-second lease fixture proves provider errors remain target-local.
    async fn reconcile_worker_lease_extend_error_isolated_and_not_masked_by_other_success() {
        let token = CancellationToken::new();
        let first = claimed_target();
        let second = claimed_target_with_ids(
            "44444444-4444-4444-4444-444444444444",
            "55555555-5555-5555-5555-555555555555",
            "device-2",
        );
        let store = FakeScheduleStore::with_targets([first.clone(), second]);
        store.fail_extend_for(first.target_id());
        let reconciler = Arc::new(LeaseIsolationReconciler {
            started: AtomicUsize::new(0),
            changed: Notify::new(),
            finish_other: Notify::new(),
        });
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            Arc::clone(&reconciler),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(60),
        )
        .with_max_in_flight(max_in_flight(2))
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();
        let health = worker.health();
        let handle = tokio::spawn(worker.run(token.clone()));

        reconciler.wait_until_both_started().await;
        let recovery_claim = store.block_next_claim();
        advance_paused(Duration::from_secs(2)).await;
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extension_errors,
            1
        );
        assert!(!token.is_cancelled(), "provider error must not cancel root");
        assert_eq!(health.status(), HealthStatus::Degraded);

        reconciler.finish_other.notify_one();
        store.wait_for_results(1).await;
        recovery_claim.wait_until_entered().await;
        assert_eq!(
            health.status(),
            HealthStatus::Degraded,
            "an unrelated target success must not wash out the provider error"
        );
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .releases,
            0,
            "an errored extend must not release a potentially stale fence"
        );

        recovery_claim.release.notify_one();
        store.wait_for_claims(2).await;
        let recovered = tokio::time::timeout(Duration::from_secs(2), async {
            while health.status() != HealthStatus::Healthy {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(recovered.is_ok(), "a clean due scan must recover health");
        token.cancel();
        assert!(handle.await.is_ok(), "worker exits after clean receipt");
    }

    #[tokio::test]
    async fn reconcile_worker_marks_degraded_when_release_lost() {
        let store = FakeScheduleStore::default();
        store.set_release_outcome(ScheduleLeaseOutcome::Lost);
        let worker = ReconcileSchedulerBuilder::new(
            store.clone(),
            DurableScript::new(DurableBehavior::Settled),
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        let health = worker.health();

        worker
            .driver
            .release_lease_best_effort(&claimed_target(), LeaseReason::AttemptCancelled)
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .build();
        let health = worker.health();

        worker
            .driver
            .release_lease_best_effort(&claimed_target(), LeaseReason::AttemptCancelled)
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
    async fn reconcile_worker_shutdown_cancels_and_releases_concurrent_attempts() {
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
            keyring(),
            DeviceCertificateSystemProducer::install(),
            tenant(),
            "test-reconciler",
            "holder-a",
            Tenancy::tenant_scoped(),
            trig(10),
        )
        .with_max_in_flight(ReconcileMaxInFlight::try_new(3).expect("valid concurrency"))
        .with_lease_ttl(Duration::from_secs(3))
        .expect("whole-second lease ttl")
        .build();

        let handle = tokio::spawn(worker.run(token));
        advance_paused(Duration::from_secs(1)).await;
        handle
            .await
            .expect("worker exits after first result cancels token");

        let state = store.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.claims, 1);
        assert_eq!(state.attempts, 3);
        assert_eq!(
            state.releases, 2,
            "shutdown must release every concurrent attempt that did not record a result"
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
        ) -> Result<DurableReconcileOutcome, ReconcileError> {
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
    /// start_paused 使 tokio 时间不自动推进；`advance(60s)` 由本 test 显式驱动虚拟时间——
    /// NeverLeader 返回 Ok(None) 使 leader_gated 做 LEASE_TTL(15s) 的 wait_or_cancel，
    /// 每次 tick 推进 60s 足以让 loop 经历多轮 standby 而不 dispatch。
    #[tokio::test(start_paused = true)]
    async fn run_not_leader_never_dispatches() {
        let token = CancellationToken::new();
        let reconciler = ScriptedReconciler::new(Behavior::Settled);
        let calls = Arc::clone(&reconciler.calls);
        let loop_ = Builder::new(reconciler, Tenancy::single_tenant(), trig(10)).build();
        // 非 leader：跑一会儿后取消，应零 dispatch（leader-gated）。
        // start_paused 单线程下确定性：advance 推进虚拟时间，cancel 后 loop 必然在 wait_or_cancel 退出。
        let handle = tokio::spawn(loop_.run_with_leader(Arc::new(NeverLeader), token.clone()));
        advance_paused(Duration::from_secs(60)).await;
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
        // 让 spawn 的 loop 跑到首 tick → 进入在途 pending reconcile（start_paused：advance 推进虚拟时间）。
        advance_paused(Duration::from_secs(1)).await;
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
        advance_paused(Duration::from_secs(1)).await;
        assert!(entered.load(Ordering::SeqCst), "应已进入在途 reconcile");
        // 推进过 RENEW_INTERVAL：RenewOnceLeader 第 2 次 acquire 返 None → scope cancel → drop 在途 pending dispatch。
        advance_paused(RENEW_INTERVAL + Duration::from_secs(1)).await;
        token.cancel(); // 丢 lease 后回 standby，cancel root 结束 loop
        handle
            .await
            .expect("丢 lease 应 drop 在途 pending dispatch，loop 取消后返回");
    }
}
