//! Bounded provider-neutral retry and shutdown lifecycle values.

use std::num::NonZeroU32;
use std::time::Duration;

use crate::delivery::{ConsumerTxOutcome, RejectKind};

/// Maximum total attempts accepted by [`RetryPolicy`].
pub const RETRY_ATTEMPTS_MAX: NonZeroU32 = NonZeroU32::MIN.saturating_add(127);
/// Maximum supported timeout for one managed Eventing shutdown lifecycle.
pub const SHUTDOWN_BUDGET_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// Failure while constructing a [`RetryPolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RetryPolicyError {
    /// The total attempt count exceeds the operationally bounded loop limit.
    #[error("retry attempts exceed operational maximum {max}")]
    AttemptsExceeded { max: NonZeroU32 },
    /// A retrying lifecycle must yield before its next attempt.
    #[error("retry backoff base must be non-zero")]
    ZeroBackoff,
    /// The initial delay exceeds its saturation cap.
    #[error("retry backoff base {base:?} exceeds cap {cap:?}")]
    BaseExceedsCap { base: Duration, cap: Duration },
}

/// Total attempt budget and exponential backoff for one bounded retry lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: NonZeroU32,
    base: Duration,
    cap: Duration,
}

impl RetryPolicy {
    /// Existing production policy: three total attempts, 1s base and 60s cap.
    pub const STANDARD: Self = Self {
        max_attempts: NonZeroU32::MIN.saturating_add(2),
        base: Duration::from_secs(1),
        cap: Duration::from_secs(60),
    };

    /// Constructs one complete retry policy.
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
            return Err(RetryPolicyError::BaseExceedsCap { base, cap });
        }
        Ok(Self {
            max_attempts,
            base,
            cap,
        })
    }

    /// Returns the total number of attempts, including the first attempt.
    #[must_use]
    pub const fn max_attempts(&self) -> NonZeroU32 {
        self.max_attempts
    }

    /// Whether a 1-based attempt is inside this policy.
    #[must_use]
    pub const fn allows_attempt(&self, attempt: NonZeroU32) -> bool {
        attempt.get() <= self.max_attempts.get()
    }

    /// Returns the delay after a 1-based failed attempt, saturating at the cap.
    #[must_use]
    pub fn delay_after(&self, failed_attempt: NonZeroU32) -> Duration {
        let mut delay = self.base.min(self.cap);
        if delay.is_zero() {
            return delay;
        }
        // A positive Duration reaches Duration::MAX in fewer than 128 doublings, so this remains
        // constant-bounded even for `NonZeroU32::MAX` attempts.
        for _ in 0..failed_attempt.get().saturating_sub(1).min(128) {
            delay = delay.saturating_mul(2).min(self.cap);
            if delay == self.cap {
                break;
            }
        }
        delay
    }
}

/// Closed action selected for one consumer transaction outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerTxAction {
    /// A provider commit proof authorizes broker acknowledgement.
    Commit,
    /// A terminal handler result enters the dead-letter path.
    Reject(RejectKind),
    /// The exact policy delay has elapsed and the same handler may run again.
    RetryReady {
        /// The 1-based attempt that just failed.
        failed_attempt: NonZeroU32,
        /// The policy-owned delay before the next attempt.
        delay: Duration,
    },
    /// Broker redelivery is required without another local handler call.
    Requeue,
    /// The inbox lease is no longer authoritative.
    Fenced,
    /// The bounded local retry allowance is exhausted.
    Exhausted,
}

/// Error returned when a terminal consumer transaction lifecycle is reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("consumer transaction lifecycle is closed")]
pub struct ConsumerTxLifecycleClosed;

/// Production decision cursor for one bounded consumer transaction lifecycle.
///
/// The cursor owns attempt advancement and terminal closure. Runtime owners execute the returned
/// action, but cannot bypass its real retry wait, obtain a fourth provider attempt from the
/// standard policy, or reuse the cursor after a terminal result.
#[derive(Debug)]
pub struct ConsumerTxLifecycle {
    policy: RetryPolicy,
    current_attempt: Option<NonZeroU32>,
}

impl ConsumerTxLifecycle {
    /// Starts a fresh lifecycle at attempt one.
    #[must_use]
    pub const fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            current_attempt: Some(NonZeroU32::MIN),
        }
    }

    /// Returns the current 1-based provider attempt, or `None` after a terminal decision.
    #[must_use]
    pub const fn current_attempt(&self) -> Option<NonZeroU32> {
        self.current_attempt
    }

    /// Completes one provider attempt and returns its only valid action.
    ///
    /// A retry action becomes observable only after the supplied delay future has completed.
    /// Production and conformance callers supply their runtime's real sleep future; this seam owns
    /// when it is invoked and advances the attempt only after it returns. Dropping this future
    /// cancels the wait and cannot expose a next-attempt permit.
    pub async fn finish_attempt<C, W, F>(
        &mut self,
        outcome: &ConsumerTxOutcome<C>,
        wait: W,
    ) -> Result<ConsumerTxAction, ConsumerTxLifecycleClosed>
    where
        W: FnOnce(Duration) -> F,
        F: Future<Output = ()>,
    {
        let action = self.decide(outcome)?;
        if let ConsumerTxAction::RetryReady {
            failed_attempt,
            delay,
        } = action
        {
            wait(delay).await;
            self.current_attempt = Some(NonZeroU32::MIN.saturating_add(failed_attempt.get()));
        } else {
            self.current_attempt = None;
        }
        Ok(action)
    }

    fn decide<C>(
        &self,
        outcome: &ConsumerTxOutcome<C>,
    ) -> Result<ConsumerTxAction, ConsumerTxLifecycleClosed> {
        let attempt = self.current_attempt.ok_or(ConsumerTxLifecycleClosed)?;
        let action = match outcome {
            ConsumerTxOutcome::Committed(_) => ConsumerTxAction::Commit,
            ConsumerTxOutcome::Rejected(kind) => ConsumerTxAction::Reject(*kind),
            ConsumerTxOutcome::HandlerTransient
                if attempt.get() < self.policy.max_attempts().get() =>
            {
                let delay = self.policy.delay_after(attempt);
                return Ok(ConsumerTxAction::RetryReady {
                    failed_attempt: attempt,
                    delay,
                });
            }
            ConsumerTxOutcome::HandlerTransient => ConsumerTxAction::Exhausted,
            ConsumerTxOutcome::InfrastructureTransient
            | ConsumerTxOutcome::CommitUnknown
            | ConsumerTxOutcome::RollbackFailed => ConsumerTxAction::Requeue,
            ConsumerTxOutcome::Fenced => ConsumerTxAction::Fenced,
        };
        Ok(action)
    }
}

/// Failure while constructing a [`ShutdownBudget`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ShutdownBudgetError {
    /// A shutdown lifecycle must have a positive bound.
    #[error("shutdown budget must be non-zero")]
    Zero,
    /// The shutdown lifecycle exceeds the supported operational bound.
    #[error("shutdown budget exceeds operational maximum of 24 hours")]
    OperationalRangeExceeded,
}

/// Positive bound for one managed Eventing shutdown lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownBudget(Duration);

impl ShutdownBudget {
    /// Existing production shutdown budget.
    pub const STANDARD: Self = Self(Duration::from_secs(45));

    /// Constructs a positive shutdown bound.
    pub const fn new(timeout: Duration) -> Result<Self, ShutdownBudgetError> {
        if timeout.is_zero() {
            return Err(ShutdownBudgetError::Zero);
        }
        if timeout.as_secs() > SHUTDOWN_BUDGET_MAX.as_secs()
            || (timeout.as_secs() == SHUTDOWN_BUDGET_MAX.as_secs()
                && timeout.subsec_nanos() > SHUTDOWN_BUDGET_MAX.subsec_nanos())
        {
            return Err(ShutdownBudgetError::OperationalRangeExceeded);
        }
        Ok(Self(timeout))
    }

    /// Returns the exact internal timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        self.0
    }
}
