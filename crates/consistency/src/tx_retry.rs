//! Transaction retry policy for explicit UoW boundaries.
//!
//! This module owns the closed retry classification and the bounded retry loop. It deliberately
//! does not know about SQLSTATE, repository errors, metrics, or clocks; adapters classify their own
//! errors and emit boundary-specific observability.
//!
//! INVARIANT: TX-RETRY-BOUNDARY-01 { level = "Medium", exec = "manual/opt-in", source = "code" } -
//! retry classification stays closed and `run_tx_retry` only retries a full explicit UoW boundary.

use std::future::Future;
use std::time::Duration;

/// Closed transaction retry classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxRetryClass {
    /// Temporary storage/backend failure; retrying the whole UoW is allowed while budget remains.
    Transient,
    /// CAS/version conflict; callers must refetch/recompute explicitly above the UoW.
    Conflict,
    /// Permanent failure; retrying the same UoW cannot make progress.
    Permanent,
    /// Fencing/lease/ownership was lost; retrying the same side effect risks double execution.
    OwnershipLost,
}

impl TxRetryClass {
    /// Stable low-cardinality metrics/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            TxRetryClass::Transient => "transient",
            TxRetryClass::Conflict => "conflict",
            TxRetryClass::Permanent => "permanent",
            TxRetryClass::OwnershipLost => "ownership_lost",
        }
    }
}

/// Final retry loop status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxRetryFinalStatus {
    /// The UoW completed successfully.
    Success,
    /// Retry budget was exhausted on transient errors.
    Exhausted,
    /// The loop stopped immediately on a non-retryable class.
    NotRetryable(TxRetryClass),
}

impl TxRetryFinalStatus {
    /// Stable low-cardinality metrics/log label.
    pub fn as_label(self) -> &'static str {
        match self {
            TxRetryFinalStatus::Success => "success",
            TxRetryFinalStatus::Exhausted => "exhausted",
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Conflict) => "conflict",
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent) => "permanent",
            TxRetryFinalStatus::NotRetryable(TxRetryClass::OwnershipLost) => "ownership_lost",
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Transient) => "transient_not_retried",
        }
    }
}

/// Bounded retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxRetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl TxRetryPolicy {
    /// Conservative default for storage UoW boundaries.
    pub const DEFAULT: Self = Self {
        max_attempts: 3,
        base_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(50),
    };

    /// Build a validated policy. `max_attempts` is total attempts, including the first try.
    pub fn new(
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
    ) -> Result<Self, TxRetryPolicyError> {
        if max_attempts == 0 {
            return Err(TxRetryPolicyError::ZeroAttempts);
        }
        if base_delay > max_delay {
            return Err(TxRetryPolicyError::DelayRange);
        }
        Ok(Self {
            max_attempts,
            base_delay,
            max_delay,
        })
    }

    /// Total attempts, including the first try.
    pub fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    /// Whether a classified failed attempt may be retried.
    pub fn should_retry(self, class: TxRetryClass, attempt: u32) -> bool {
        class == TxRetryClass::Transient && attempt < self.max_attempts
    }

    /// Exponential backoff delay after a failed attempt.
    pub fn delay_after(self, attempt: u32) -> Duration {
        if self.base_delay.is_zero() {
            return Duration::ZERO;
        }
        let exp = attempt.saturating_sub(1).min(31);
        self.base_delay
            .saturating_mul(1_u32 << exp)
            .min(self.max_delay)
    }
}

impl Default for TxRetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Retry policy construction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TxRetryPolicyError {
    /// Attempt budget must include at least the first try.
    #[error("transaction retry max_attempts must be >= 1")]
    ZeroAttempts,
    /// Delay bounds must be ordered.
    #[error("transaction retry base_delay must be <= max_delay")]
    DelayRange,
}

/// Result metadata from a retry loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxRetryReport {
    attempts: u32,
    final_status: TxRetryFinalStatus,
}

impl TxRetryReport {
    /// Number of attempts actually executed.
    pub fn attempts(self) -> u32 {
        self.attempts
    }

    /// Final loop status.
    pub fn final_status(self) -> TxRetryFinalStatus {
        self.final_status
    }
}

/// Run an operation under a bounded retry policy.
///
/// `op` receives a one-based attempt number and must recreate the full UoW on every call. `sleep`
/// is injected by the caller so this engine crate stays runtime-neutral.
pub async fn run_tx_retry<T, E, Op, OpFut, Classify, Sleep, SleepFut>(
    policy: TxRetryPolicy,
    mut op: Op,
    classify: Classify,
    mut sleep: Sleep,
) -> (Result<T, E>, TxRetryReport)
where
    Op: FnMut(u32) -> OpFut,
    OpFut: Future<Output = Result<T, E>>,
    Classify: Fn(&E) -> TxRetryClass,
    Sleep: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let mut attempt = 1;
    loop {
        match op(attempt).await {
            Ok(value) => {
                return (
                    Ok(value),
                    TxRetryReport {
                        attempts: attempt,
                        final_status: TxRetryFinalStatus::Success,
                    },
                );
            }
            Err(error) => {
                let class = classify(&error);
                if policy.should_retry(class, attempt) {
                    sleep(policy.delay_after(attempt)).await;
                    attempt = attempt.saturating_add(1);
                    continue;
                }
                let status = if class == TxRetryClass::Transient {
                    TxRetryFinalStatus::Exhausted
                } else {
                    TxRetryFinalStatus::NotRetryable(class)
                };
                return (
                    Err(error),
                    TxRetryReport {
                        attempts: attempt,
                        final_status: status,
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::time::Duration;

    use super::{
        TxRetryClass, TxRetryFinalStatus, TxRetryPolicy, TxRetryPolicyError, run_tx_retry,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeError {
        Transient,
        Conflict,
        Permanent,
        OwnershipLost,
    }

    fn classify(error: &FakeError) -> TxRetryClass {
        match error {
            FakeError::Transient => TxRetryClass::Transient,
            FakeError::Conflict => TxRetryClass::Conflict,
            FakeError::Permanent => TxRetryClass::Permanent,
            FakeError::OwnershipLost => TxRetryClass::OwnershipLost,
        }
    }

    async fn no_sleep(_: Duration) {}

    #[test]
    fn retry_class_labels_are_stable_and_distinct() {
        let labels = [
            TxRetryClass::Transient.as_label(),
            TxRetryClass::Conflict.as_label(),
            TxRetryClass::Permanent.as_label(),
            TxRetryClass::OwnershipLost.as_label(),
        ];
        assert_eq!(
            labels,
            ["transient", "conflict", "permanent", "ownership_lost"]
        );
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }

    #[test]
    fn final_status_labels_are_stable() {
        let cases = [
            (TxRetryFinalStatus::Success, "success"),
            (TxRetryFinalStatus::Exhausted, "exhausted"),
            (
                TxRetryFinalStatus::NotRetryable(TxRetryClass::Conflict),
                "conflict",
            ),
            (
                TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent),
                "permanent",
            ),
            (
                TxRetryFinalStatus::NotRetryable(TxRetryClass::OwnershipLost),
                "ownership_lost",
            ),
        ];
        for (status, expected) in cases {
            assert_eq!(status.as_label(), expected);
        }
    }

    #[test]
    fn policy_rejects_invalid_inputs() {
        assert_eq!(
            TxRetryPolicy::new(0, Duration::ZERO, Duration::ZERO),
            Err(TxRetryPolicyError::ZeroAttempts)
        );
        assert_eq!(
            TxRetryPolicy::new(1, Duration::from_millis(2), Duration::from_millis(1)),
            Err(TxRetryPolicyError::DelayRange)
        );
    }

    #[tokio::test]
    async fn transient_retries_until_success() {
        let calls = Cell::new(0);
        let policy = TxRetryPolicy {
            max_attempts: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let (result, report) = run_tx_retry(
            policy,
            |attempt| {
                calls.set(calls.get() + 1);
                async move {
                    if attempt < 3 {
                        Err(FakeError::Transient)
                    } else {
                        Ok("done")
                    }
                }
            },
            classify,
            no_sleep,
        )
        .await;

        assert_eq!(result, Ok("done"));
        assert_eq!(calls.get(), 3);
        assert_eq!(report.attempts(), 3);
        assert_eq!(report.final_status(), TxRetryFinalStatus::Success);
    }

    #[tokio::test]
    async fn transient_exhaustion_returns_final_error() {
        let policy = TxRetryPolicy {
            max_attempts: 2,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let (result, report) = run_tx_retry(
            policy,
            |_attempt| async { Err::<(), _>(FakeError::Transient) },
            classify,
            no_sleep,
        )
        .await;

        assert_eq!(result, Err(FakeError::Transient));
        assert_eq!(report.attempts(), 2);
        assert_eq!(report.final_status(), TxRetryFinalStatus::Exhausted);
    }

    #[tokio::test]
    async fn non_retryable_classes_stop_after_first_attempt() {
        for error in [
            FakeError::Conflict,
            FakeError::Permanent,
            FakeError::OwnershipLost,
        ] {
            let calls = Cell::new(0);
            let (result, report) = run_tx_retry(
                TxRetryPolicy::default(),
                |_attempt| {
                    calls.set(calls.get() + 1);
                    async move { Err::<(), _>(error) }
                },
                classify,
                no_sleep,
            )
            .await;

            assert_eq!(result, Err(error));
            assert_eq!(calls.get(), 1);
            assert_eq!(report.attempts(), 1);
            assert_eq!(
                report.final_status(),
                TxRetryFinalStatus::NotRetryable(classify(&error))
            );
        }
    }
}
