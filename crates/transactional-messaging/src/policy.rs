//! Budgets measured in one monotonic time domain.
//!
//! Mint [`ExecutionDeadlines`] once per delivery and reuse its operation cutoff through retries
//! and backoff. The later settlement cutoff protects cleanup time. See [`within`] for the shared
//! provider watchdog, caller timeout, and cancellation contract.
//!
//! A provider can pair the caller's cutoff with its own I/O watchdog. This Tokio example uses
//! one origin for both clock observations and sleep; the immediate operation stands in for I/O.
//!
//! ```rust
//! use rss_transactional_messaging::policy::{
//!     AbsoluteDeadline, Clock, ExecutionBudget, ExecutionDeadlines, ExecutionTimer,
//!     MonotonicInstant, within,
//! };
//!
//! struct Timer(tokio::time::Instant);
//! impl Clock for Timer {
//!     fn now(&self) -> MonotonicInstant {
//!         MonotonicInstant::from_elapsed(self.0.elapsed())
//!     }
//! }
//! impl ExecutionTimer for Timer {
//!     async fn sleep_until(&self, deadline: AbsoluteDeadline) {
//!         tokio::time::sleep_until(self.0 + deadline.instant().elapsed()).await;
//!     }
//! }
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let timer = Timer(tokio::time::Instant::now());
//!     let deadlines = ExecutionDeadlines::from_budget(&timer, ExecutionBudget::STANDARD)?;
//!     let value = within(&timer, deadlines.operation(), |io_deadline| async move {
//!         tokio::time::timeout(io_deadline.timeout(), async { 42 }).await
//!     }).await??;
//!     assert_eq!(value, 42);
//!     Ok(())
//! }
//! ```

use std::future::{Future, poll_fn};
use std::num::NonZeroU32;
use std::task::Poll;
use std::time::Duration;

use crate::error::{MessagingError, MessagingErrorKind};

/// Maximum total attempts accepted by [`RetryPolicy`], including the initial attempt.
pub const RETRY_ATTEMPTS_MAX: NonZeroU32 = NonZeroU32::MIN.saturating_add(127);
/// Upper bound for each component of [`DeliveryBudget`].
pub const DELIVERY_BUDGET_MAX: Duration = Duration::from_secs(24 * 60 * 60);
/// Upper bound for a [`ShutdownBudget`].
pub const SHUTDOWN_BUDGET_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Minimum supported periodic lease-renewal interval.
#[cfg(feature = "consumer")]
pub const LEASE_RENEWAL_INTERVAL_MIN: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid attempt count or backoff relationship.
pub enum RetryPolicyError {
    #[error("retry attempts exceed operational maximum {max}")]
    /// The requested attempt count exceeds [`RETRY_ATTEMPTS_MAX`].
    AttemptsExceeded {
        /// Maximum number of attempts accepted by the policy.
        max: NonZeroU32,
    },
    #[error("retry backoff base must be non-zero")]
    /// Backoff would allow a busy retry loop.
    ZeroBackoff,
    #[error("retry backoff base exceeds cap")]
    /// Initial delay exceeds the requested maximum delay.
    BaseExceedsCap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Bounded attempt count and capped exponential backoff; does not itself schedule retries.
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    base: Duration,
    cap: Duration,
}

impl RetryPolicy {
    /// Three total attempts, with a one-second initial delay and a sixty-second cap.
    pub const STANDARD: Self = Self {
        max_attempts: NonZeroU32::MIN.saturating_add(2),
        base: Duration::from_secs(1),
        cap: Duration::from_secs(60),
    };

    /// Validate the attempt limit and `0 < base <= cap`; otherwise return [`RetryPolicyError`].
    pub fn new(
        max_attempts: NonZeroU32,
        base: Duration,
        cap: Duration,
    ) -> Result<Self, RetryPolicyError> {
        if max_attempts > RETRY_ATTEMPTS_MAX {
            return Err(RetryPolicyError::AttemptsExceeded {
                max: RETRY_ATTEMPTS_MAX,
            });
        }
        if base.is_zero() {
            return Err(RetryPolicyError::ZeroBackoff);
        }
        if base > cap {
            return Err(RetryPolicyError::BaseExceedsCap);
        }
        Ok(Self {
            max_attempts,
            base,
            cap,
        })
    }

    #[must_use]
    /// Total allowed attempts, including the initial attempt.
    pub const fn max_attempts(&self) -> NonZeroU32 {
        self.max_attempts
    }
    #[must_use]
    /// Whether this one-based attempt fits the count limit; time-budget admission is separate.
    pub const fn allows_attempt(&self, attempt: NonZeroU32) -> bool {
        attempt.get() <= self.max_attempts.get()
    }
    #[must_use]
    /// Capped exponential delay after a one-based failure; does not check whether another attempt
    /// is allowed.
    pub fn delay_after(&self, failed_attempt: NonZeroU32) -> Duration {
        let mut delay = self.base.min(self.cap);
        for _ in 0..failed_attempt.get().saturating_sub(1).min(128) {
            delay = delay.saturating_mul(2).min(self.cap);
            if delay == self.cap {
                break;
            }
        }
        delay
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid delivery timing components or insufficient lease headroom.
pub enum DeliveryBudgetError {
    #[error("delivery budget component must be non-zero")]
    /// At least one component is zero.
    Zero,
    #[error("delivery budget component must use integral milliseconds")]
    /// A component contains sub-millisecond precision.
    NonIntegralMilliseconds,
    #[error("delivery budget component exceeds operational maximum")]
    /// A component exceeds [`DELIVERY_BUDGET_MAX`].
    OperationalRangeExceeded,
    #[error("delivery required budget overflows Duration")]
    /// The sum of publication, settlement, and margin durations cannot be represented.
    RequiredBudgetOverflow,
    #[error("delivery required budget must be strictly below lease")]
    /// The required work budget is not strictly shorter than the lease TTL.
    RequiredBudgetNotBelowLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Publication, settlement, and safety headroom that must fit inside an outbox lease.
pub struct DeliveryBudget {
    lease_ttl: Duration,
    publish_timeout: Duration,
    settle_timeout: Duration,
    safety_margin: Duration,
}

impl DeliveryBudget {
    /// Require positive whole-millisecond components within [`DELIVERY_BUDGET_MAX`] and work
    /// strictly below TTL; otherwise return [`DeliveryBudgetError`].
    pub fn new(
        lease_ttl: Duration,
        publish_timeout: Duration,
        settle_timeout: Duration,
        safety_margin: Duration,
    ) -> Result<Self, DeliveryBudgetError> {
        for duration in [lease_ttl, publish_timeout, settle_timeout, safety_margin] {
            if duration.is_zero() {
                return Err(DeliveryBudgetError::Zero);
            }
            if !duration.subsec_nanos().is_multiple_of(1_000_000) {
                return Err(DeliveryBudgetError::NonIntegralMilliseconds);
            }
            if duration > DELIVERY_BUDGET_MAX {
                return Err(DeliveryBudgetError::OperationalRangeExceeded);
            }
        }
        let required = publish_timeout
            .checked_add(settle_timeout)
            .and_then(|value| value.checked_add(safety_margin))
            .ok_or(DeliveryBudgetError::RequiredBudgetOverflow)?;
        if required >= lease_ttl {
            return Err(DeliveryBudgetError::RequiredBudgetNotBelowLease);
        }
        Ok(Self {
            lease_ttl,
            publish_timeout,
            settle_timeout,
            safety_margin,
        })
    }

    #[must_use]
    /// Provider lease duration against which the work budget was validated.
    pub const fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }
    #[must_use]
    /// Maximum time allotted to one publication attempt.
    pub const fn publish_timeout(&self) -> Duration {
        self.publish_timeout
    }
    #[must_use]
    /// Time reserved for persisting the publication outcome.
    pub const fn settle_timeout(&self) -> Duration {
        self.settle_timeout
    }
    #[must_use]
    /// Extra headroom beyond publication and settlement.
    pub const fn safety_margin(&self) -> Duration {
        self.safety_margin
    }
    #[must_use]
    /// Sum of publication timeout, settlement timeout, and safety margin.
    pub fn required_budget(&self) -> Duration {
        self.publish_timeout
            .saturating_add(self.settle_timeout)
            .saturating_add(self.safety_margin)
    }
    #[must_use]
    /// Whether remaining provider-authoritative time is strictly greater than the required budget.
    pub fn can_start_attempt(&self, remaining: Duration) -> bool {
        remaining > self.required_budget()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid bounded-drain duration.
pub enum ShutdownBudgetError {
    #[error("shutdown budget must be non-zero")]
    /// No drain time was allowed.
    Zero,
    #[error("shutdown budget exceeds operational maximum")]
    /// The duration exceeds [`SHUTDOWN_BUDGET_MAX`].
    OperationalRangeExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Maximum duration a runtime may spend draining admitted work during shutdown.
pub struct ShutdownBudget(Duration);

impl ShutdownBudget {
    /// Allow up to forty-five seconds for drain.
    pub const STANDARD: Self = Self(Duration::from_secs(45));
    /// Require a positive duration no greater than [`SHUTDOWN_BUDGET_MAX`]; otherwise return
    /// [`ShutdownBudgetError`].
    pub fn new(timeout: Duration) -> Result<Self, ShutdownBudgetError> {
        if timeout.is_zero() {
            return Err(ShutdownBudgetError::Zero);
        }
        if timeout > SHUTDOWN_BUDGET_MAX {
            return Err(ShutdownBudgetError::OperationalRangeExceeded);
        }
        Ok(Self(timeout))
    }
    #[must_use]
    /// Configured maximum drain duration.
    pub const fn timeout(self) -> Duration {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Elapsed duration in one clock's monotonic time domain, not a wall-clock timestamp.
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    #[must_use]
    /// Wrap elapsed time from the same origin used by the execution timer.
    pub const fn from_elapsed(elapsed: Duration) -> Self {
        Self(elapsed)
    }
    #[must_use]
    /// Duration since this clock's origin.
    pub const fn elapsed(self) -> Duration {
        self.0
    }
    #[must_use]
    /// Add a duration, returning `None` on representational overflow.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
    #[must_use]
    /// Elapsed time since `earlier`, clamped to zero if it lies later.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// Monotonic time source; observations must not go backwards or change origin.
pub trait Clock: Send + Sync {
    /// Observe elapsed time in this clock's fixed monotonic domain.
    fn now(&self) -> MonotonicInstant;
}

/// Monotonic timer used by provider-neutral execution orchestration.
///
/// The timer and its [`Clock`] implementation must share one monotonic time domain. Provider
/// operations are raced by [`within`]; implementations only supply the sleep primitive and cannot
/// replace the core-owned arbitration.
pub trait ExecutionTimer: Clock {
    /// Complete at or after the cutoff, waking the waiting task when it is reached.
    /// An elapsed deadline must be immediately ready. Dropping the sleep must cancel its wait
    /// without blocking; use the same origin as [`Clock::now`].
    fn sleep_until(&self, deadline: AbsoluteDeadline) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Total consumer execution time with a protected settlement interval.
pub struct ExecutionBudget {
    total: Duration,
    settlement_reserve: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Invalid execution budget or unrepresentable absolute cutoff.
pub enum ExecutionBudgetError {
    #[error("execution budget total must be non-zero")]
    /// No execution time was allowed.
    ZeroTotal,
    #[error("settlement reserve must be non-zero and strictly below total")]
    /// Settlement reserve is zero or is not strictly below total time.
    InvalidSettlementReserve,
    #[error("execution deadline exceeds monotonic time range")]
    /// Adding a duration to the observed clock value overflows.
    DeadlineOverflow,
}

impl ExecutionBudget {
    /// Ten seconds total, reserving the final two seconds for settlement and cleanup.
    pub const STANDARD: Self = Self {
        total: Duration::from_secs(10),
        settlement_reserve: Duration::from_secs(2),
    };

    /// Require `0 < settlement_reserve < total`; otherwise return [`ExecutionBudgetError`].
    pub fn new(
        total: Duration,
        settlement_reserve: Duration,
    ) -> Result<Self, ExecutionBudgetError> {
        if total.is_zero() {
            return Err(ExecutionBudgetError::ZeroTotal);
        }
        if settlement_reserve.is_zero() || settlement_reserve >= total {
            return Err(ExecutionBudgetError::InvalidSettlementReserve);
        }
        Ok(Self {
            total,
            settlement_reserve,
        })
    }

    #[must_use]
    /// Whole delivery budget, including settlement and cleanup.
    pub const fn total(self) -> Duration {
        self.total
    }
    #[must_use]
    /// Final interval unavailable to claim, transaction, or retry work.
    pub const fn settlement_reserve(self) -> Duration {
        self.settlement_reserve
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Operation and settlement cutoffs minted from one monotonic clock observation.
///
/// Reuse the pair for one delivery; constructing a new pair would start a new budget.
pub struct ExecutionDeadlines {
    operation: AbsoluteDeadline,
    settlement: AbsoluteDeadline,
}

impl ExecutionDeadlines {
    /// Freeze both execution phases from one clock read and one validated budget.
    /// Return [`ExecutionBudgetError::DeadlineOverflow`] if either cutoff cannot be represented.
    pub fn from_budget(
        clock: &impl Clock,
        budget: ExecutionBudget,
    ) -> Result<Self, ExecutionBudgetError> {
        let now = clock.now();
        let operation = now
            .checked_add(budget.total - budget.settlement_reserve)
            .map(AbsoluteDeadline)
            .ok_or(ExecutionBudgetError::DeadlineOverflow)?;
        let settlement = now
            .checked_add(budget.total)
            .map(AbsoluteDeadline)
            .ok_or(ExecutionBudgetError::DeadlineOverflow)?;
        Ok(Self {
            operation,
            settlement,
        })
    }

    /// Return the cutoff for claim, lease, transaction, and retry work.
    #[must_use]
    pub const fn operation(self) -> AbsoluteDeadline {
        self.operation
    }

    /// Return the later cutoff reserved for release, settlement, and abandon work.
    #[must_use]
    pub const fn settlement(self) -> AbsoluteDeadline {
        self.settlement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fixed cutoff in the execution timer's monotonic domain.
pub struct AbsoluteDeadline(MonotonicInstant);

/// Remaining time to the core-owned absolute deadline at one provider call boundary.
///
/// Start the provider watchdog with this duration immediately on entry. This is a snapshot, not
/// a ticking clock; retaining and reusing it later would extend the effective I/O budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationDeadline(Duration);

impl OperationDeadline {
    /// Maximum duration this provider future may remain pending.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.0
    }
}

impl AbsoluteDeadline {
    /// Freeze a relative timeout against the caller's clock; zero means already elapsed.
    /// Return [`ExecutionBudgetError::DeadlineOverflow`] if the cutoff cannot be represented.
    pub fn from_timeout(
        clock: &impl Clock,
        timeout: Duration,
    ) -> Result<Self, ExecutionBudgetError> {
        clock
            .now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(ExecutionBudgetError::DeadlineOverflow)
    }

    #[must_use]
    /// The monotonic cutoff, suitable for the paired timer's sleep primitive.
    pub const fn instant(self) -> MonotonicInstant {
        self.0
    }
    #[must_use]
    /// Time until the cutoff, clamped to zero once elapsed.
    pub fn remaining(self, clock: &impl Clock) -> Duration {
        self.0.saturating_duration_since(clock.now())
    }

    /// Project this absolute deadline into the remaining provider-operation duration.
    #[must_use]
    pub fn operation(self, clock: &impl Clock) -> OperationDeadline {
        OperationDeadline(self.remaining(clock))
    }

    /// Derive an absolute phase deadline that can only shorten this deadline.
    #[must_use]
    pub fn capped(self, clock: &impl Clock, cap: Duration) -> Self {
        let capped = clock.now().checked_add(cap).map(Self);
        capped.map_or(self, |capped| self.min(capped))
    }
}

impl AbsoluteDeadline {
    fn min(self, other: Self) -> Self {
        if self.0.elapsed() <= other.0.elapsed() {
            self
        } else {
            other
        }
    }
}

/// Race one provider future against a core-owned absolute deadline.
///
/// The deadline branch is always polled first. An already elapsed deadline does not invoke
/// `start`; after a timeout, dropping the provider future requests cancellation but does not prove
/// that an external effect did not occur. The [`OperationDeadline`] passed to `start` is the
/// adapter's second-layer I/O watchdog for the exact same cutoff. Providers must enforce that
/// duration for their I/O, even though this function independently bounds the caller's wait.
///
/// # Errors
///
/// Return [`MessagingErrorKind::DeadlineElapsed`] when time expires, including when both futures
/// are ready. Otherwise return `Ok` containing the provider's output unchanged, including any
/// provider error. Uncertain commit or publication must remain uncertain in the caller's outcome.
pub async fn within<'a, T, S, F>(
    timer: &'a T,
    deadline: AbsoluteDeadline,
    start: S,
) -> Result<F::Output, MessagingError>
where
    T: ExecutionTimer + 'a,
    S: FnOnce(OperationDeadline) -> F + 'a,
    F: Future + Send + 'a,
    F::Output: Send + 'a,
{
    let operation_deadline = deadline.operation(timer);
    if operation_deadline.timeout().is_zero() {
        return Err(deadline_elapsed());
    }

    let delay = timer.sleep_until(deadline);
    let operation = start(operation_deadline);
    let mut delay = std::pin::pin!(delay);
    let mut operation = std::pin::pin!(operation);
    poll_fn(|context| {
        if delay.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(deadline_elapsed()));
        }
        operation.as_mut().poll(context).map(Ok)
    })
    .await
}

fn deadline_elapsed() -> MessagingError {
    MessagingError::new(
        MessagingErrorKind::DeadlineElapsed,
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "core-owned operation deadline elapsed",
        ),
    )
}

#[cfg(feature = "consumer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed validation error for consumer lease renewal.
pub enum LeaseRenewalPolicyError {
    /// A provider lease must have positive duration.
    #[error("consumer lease ttl must be non-zero")]
    ZeroTtl,
    /// The lease cannot accommodate the minimum renewal interval.
    #[error("consumer lease ttl must exceed the minimum renewal interval")]
    TooShort,
}

#[cfg(feature = "consumer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Periodic renewal schedule derived from the provider-authoritative claim TTL.
pub struct LeaseRenewalPolicy {
    ttl: Duration,
    interval: Duration,
}

#[cfg(feature = "consumer")]
impl LeaseRenewalPolicy {
    /// Derive one third of TTL with a one-millisecond floor.
    /// Return [`LeaseRenewalPolicyError`] when TTL is zero or at most one millisecond.
    pub fn from_ttl(ttl: Duration) -> Result<Self, LeaseRenewalPolicyError> {
        if ttl.is_zero() {
            return Err(LeaseRenewalPolicyError::ZeroTtl);
        }
        if ttl <= LEASE_RENEWAL_INTERVAL_MIN {
            return Err(LeaseRenewalPolicyError::TooShort);
        }
        Ok(Self {
            ttl,
            interval: (ttl / 3).max(LEASE_RENEWAL_INTERVAL_MIN),
        })
    }

    /// Return the authoritative TTL used by both the provider and renewal scheduler.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        self.ttl
    }

    /// Return the fixed renewal interval.
    #[must_use]
    pub const fn interval(self) -> Duration {
        self.interval
    }

    /// Verify this schedule against provider-authoritative remaining lease evidence.
    #[must_use]
    pub fn fits(self, remaining: Duration) -> bool {
        self.interval < remaining
    }
}

/// Consumer execution budget and bounded retry. Renewal policy belongs to the inbox provider.
#[cfg(feature = "consumer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerExecutionPolicy {
    retry: RetryPolicy,
    budget: ExecutionBudget,
}

#[cfg(feature = "consumer")]
impl ConsumerExecutionPolicy {
    #[must_use]
    /// Combine validated retry and execution limits without changing the provider's lease policy.
    pub const fn new(retry: RetryPolicy, budget: ExecutionBudget) -> Self {
        Self { retry, budget }
    }

    #[must_use]
    /// Attempt-count and backoff limits.
    pub const fn retry(self) -> RetryPolicy {
        self.retry
    }

    #[must_use]
    /// Total time and protected settlement reserve.
    pub const fn budget(self) -> ExecutionBudget {
        self.budget
    }
}
