//! Monotonic time and bounded execution policies.

use std::num::NonZeroU32;
use std::time::Duration;

/// Canonical operation owned by the transactional messaging core.
pub const RETRY_ATTEMPTS_MAX: NonZeroU32 = NonZeroU32::MIN.saturating_add(127);
/// Canonical operation owned by the transactional messaging core.
pub const DELIVERY_BUDGET_MAX: Duration = Duration::from_secs(24 * 60 * 60);
/// Canonical operation owned by the transactional messaging core.
pub const SHUTDOWN_BUDGET_MAX: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed `RetryPolicyError` protocol type.
pub enum RetryPolicyError {
    #[error("retry attempts exceed operational maximum {max}")]
    /// `AttemptsExceeded` state in the closed protocol.
    AttemptsExceeded {
        /// Maximum number of attempts accepted by the policy.
        max: NonZeroU32,
    },
    #[error("retry backoff base must be non-zero")]
    /// `ZeroBackoff` state in the closed protocol.
    ZeroBackoff,
    #[error("retry backoff base exceeds cap")]
    /// `BaseExceedsCap` state in the closed protocol.
    BaseExceedsCap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `RetryPolicy` protocol type.
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    base: Duration,
    cap: Duration,
}

impl RetryPolicy {
    /// Canonical operation owned by the transactional messaging core.
    pub const STANDARD: Self = Self {
        max_attempts: NonZeroU32::MIN.saturating_add(2),
        base: Duration::from_secs(1),
        cap: Duration::from_secs(60),
    };

    /// `new` operation defined by this protocol type.
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
    /// `max_attempts` operation defined by this protocol type.
    pub const fn max_attempts(&self) -> NonZeroU32 {
        self.max_attempts
    }
    #[must_use]
    /// `allows_attempt` operation defined by this protocol type.
    pub const fn allows_attempt(&self, attempt: NonZeroU32) -> bool {
        attempt.get() <= self.max_attempts.get()
    }
    #[must_use]
    /// `delay_after` operation defined by this protocol type.
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
/// Closed `DeliveryBudgetError` protocol type.
pub enum DeliveryBudgetError {
    #[error("delivery budget component must be non-zero")]
    /// `Zero` state in the closed protocol.
    Zero,
    #[error("delivery budget component must use integral milliseconds")]
    /// `NonIntegralMilliseconds` state in the closed protocol.
    NonIntegralMilliseconds,
    #[error("delivery budget component exceeds operational maximum")]
    /// `OperationalRangeExceeded` state in the closed protocol.
    OperationalRangeExceeded,
    #[error("delivery required budget overflows Duration")]
    /// `RequiredBudgetOverflow` state in the closed protocol.
    RequiredBudgetOverflow,
    #[error("delivery required budget must be strictly below lease")]
    /// `RequiredBudgetNotBelowLease` state in the closed protocol.
    RequiredBudgetNotBelowLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `DeliveryBudget` protocol type.
pub struct DeliveryBudget {
    lease_ttl: Duration,
    publish_timeout: Duration,
    settle_timeout: Duration,
    safety_margin: Duration,
}

impl DeliveryBudget {
    /// `new` operation defined by this protocol type.
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
    /// `lease_ttl` operation defined by this protocol type.
    pub const fn lease_ttl(&self) -> Duration {
        self.lease_ttl
    }
    #[must_use]
    /// `publish_timeout` operation defined by this protocol type.
    pub const fn publish_timeout(&self) -> Duration {
        self.publish_timeout
    }
    #[must_use]
    /// `settle_timeout` operation defined by this protocol type.
    pub const fn settle_timeout(&self) -> Duration {
        self.settle_timeout
    }
    #[must_use]
    /// `safety_margin` operation defined by this protocol type.
    pub const fn safety_margin(&self) -> Duration {
        self.safety_margin
    }
    #[must_use]
    /// `required_budget` operation defined by this protocol type.
    pub fn required_budget(&self) -> Duration {
        self.publish_timeout
            .saturating_add(self.settle_timeout)
            .saturating_add(self.safety_margin)
    }
    #[must_use]
    /// `can_start_attempt` operation defined by this protocol type.
    pub fn can_start_attempt(&self, remaining: Duration) -> bool {
        remaining > self.required_budget()
    }
    #[must_use]
    /// `publisher_watchdog_timeout` operation defined by this protocol type.
    pub fn publisher_watchdog_timeout(&self) -> Duration {
        self.publish_timeout.saturating_add(self.safety_margin)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed `ShutdownBudgetError` protocol type.
pub enum ShutdownBudgetError {
    #[error("shutdown budget must be non-zero")]
    /// `Zero` state in the closed protocol.
    Zero,
    #[error("shutdown budget exceeds operational maximum")]
    /// `OperationalRangeExceeded` state in the closed protocol.
    OperationalRangeExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `ShutdownBudget` protocol type.
pub struct ShutdownBudget(Duration);

impl ShutdownBudget {
    /// Canonical operation owned by the transactional messaging core.
    pub const STANDARD: Self = Self(Duration::from_secs(45));
    /// `new` operation defined by this protocol type.
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
    /// `timeout` operation defined by this protocol type.
    pub const fn timeout(self) -> Duration {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// Closed `MonotonicInstant` protocol type.
pub struct MonotonicInstant(Duration);

impl MonotonicInstant {
    #[must_use]
    /// `from_elapsed` operation defined by this protocol type.
    pub const fn from_elapsed(elapsed: Duration) -> Self {
        Self(elapsed)
    }
    #[must_use]
    /// `elapsed` operation defined by this protocol type.
    pub const fn elapsed(self) -> Duration {
        self.0
    }
    #[must_use]
    /// `checked_add` operation defined by this protocol type.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
    #[must_use]
    /// `saturating_duration_since` operation defined by this protocol type.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }
}

/// Closed `Clock` protocol type.
pub trait Clock: Send + Sync {
    /// Canonical operation owned by the transactional messaging core.
    fn now(&self) -> MonotonicInstant;
}

/// Monotonic timer used by provider-neutral local retry orchestration.
pub trait RetryTimer: Clock {
    /// Delay without exceeding the unchanged delivery execution deadline.
    fn delay(
        &self,
        duration: Duration,
        deadline: OperationDeadline,
    ) -> impl Future<Output = ()> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `ExecutionBudget` protocol type.
pub struct ExecutionBudget {
    total: Duration,
    settlement_reserve: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
/// Closed `ExecutionBudgetError` protocol type.
pub enum ExecutionBudgetError {
    #[error("execution budget total must be non-zero")]
    /// `ZeroTotal` state in the closed protocol.
    ZeroTotal,
    #[error("settlement reserve must be non-zero and strictly below total")]
    /// `InvalidSettlementReserve` state in the closed protocol.
    InvalidSettlementReserve,
    #[error("execution deadline exceeds monotonic time range")]
    /// `DeadlineOverflow` state in the closed protocol.
    DeadlineOverflow,
}

impl ExecutionBudget {
    /// Canonical operation owned by the transactional messaging core.
    pub const STANDARD: Self = Self {
        total: Duration::from_secs(10),
        settlement_reserve: Duration::from_secs(2),
    };

    /// `new` operation defined by this protocol type.
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
    /// `total` operation defined by this protocol type.
    pub const fn total(self) -> Duration {
        self.total
    }
    #[must_use]
    /// `settlement_reserve` operation defined by this protocol type.
    pub const fn settlement_reserve(self) -> Duration {
        self.settlement_reserve
    }
    #[must_use]
    /// `operation` operation defined by this protocol type.
    pub fn operation(self) -> Duration {
        self.total - self.settlement_reserve
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Closed `AbsoluteDeadline` protocol type.
pub struct AbsoluteDeadline(MonotonicInstant);

/// Remaining time to the core-owned absolute deadline at one provider call boundary.
///
/// Providers use this value with their runtime timeout primitive. Its constructor is private so
/// the original execution budget cannot be reset at each stage.
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
    /// Freeze a relative provider-operation timeout against the caller's monotonic clock.
    pub fn from_timeout(
        clock: &impl Clock,
        timeout: Duration,
    ) -> Result<Self, ExecutionBudgetError> {
        if timeout.is_zero() {
            return Err(ExecutionBudgetError::ZeroTotal);
        }
        clock
            .now()
            .checked_add(timeout)
            .map(Self)
            .ok_or(ExecutionBudgetError::DeadlineOverflow)
    }

    /// `from_budget` operation defined by this protocol type.
    pub fn from_budget(
        clock: &impl Clock,
        budget: ExecutionBudget,
    ) -> Result<Self, ExecutionBudgetError> {
        clock
            .now()
            .checked_add(budget.total())
            .map(Self)
            .ok_or(ExecutionBudgetError::DeadlineOverflow)
    }
    #[must_use]
    /// `instant` operation defined by this protocol type.
    pub const fn instant(self) -> MonotonicInstant {
        self.0
    }
    #[must_use]
    /// `remaining` operation defined by this protocol type.
    pub fn remaining(self, clock: &impl Clock) -> Duration {
        self.0.saturating_duration_since(clock.now())
    }

    /// Project this absolute deadline into the remaining provider-operation duration.
    #[must_use]
    pub fn operation(self, clock: &impl Clock) -> OperationDeadline {
        OperationDeadline(self.remaining(clock))
    }

    /// Project this deadline while reserving a smaller phase-specific provider timeout.
    #[must_use]
    pub fn operation_capped(self, clock: &impl Clock, cap: Duration) -> OperationDeadline {
        OperationDeadline(self.remaining(clock).min(cap))
    }
}

/// Complete consumer execution policy: one absolute budget and one bounded local retry schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerExecutionPolicy {
    retry: RetryPolicy,
    budget: ExecutionBudget,
}

impl ConsumerExecutionPolicy {
    #[must_use]
    /// `new` operation defined by this protocol type.
    pub const fn new(retry: RetryPolicy, budget: ExecutionBudget) -> Self {
        Self { retry, budget }
    }

    #[must_use]
    /// `retry` operation defined by this protocol type.
    pub const fn retry(self) -> RetryPolicy {
        self.retry
    }

    #[must_use]
    /// `budget` operation defined by this protocol type.
    pub const fn budget(self) -> ExecutionBudget {
        self.budget
    }
}
