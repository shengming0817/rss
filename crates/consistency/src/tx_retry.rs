//! Transaction retry policy for explicit UoW boundaries.
//!
//! This module owns the closed retry classification and the bounded retry loop. It deliberately
//! does not know about SQLSTATE, repository errors, metrics, or clocks; adapters classify their own
//! errors and emit boundary-specific observability.
//!
//! INVARIANT: TX-RETRY-BOUNDARY-01 { level = "Medium", exec = "manual/opt-in", source = "code" } —
//! [`TxRetryClass`], [`TxRetryPolicy`], and [`run_tx_retry`] keep retry decisions at the UoW
//! boundary as closed, bounded, adapter-classified policy rather than scattered bool/string checks.

use std::future::Future;
use std::time::Duration;

// One repetition owns every class fact and expands both closed sets. Adding a class therefore also
// adds its final-status payload; there is no second list for a maintainer or agent to synchronize.
macro_rules! closed_tx_retry_vocabulary {
    (
        $(
            $(#[$class_meta:meta])*
            $class:ident => ($class_label:literal, $final_label:literal)
        ),+ $(,)?
    ) => {
        /// Closed transaction retry classification.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TxRetryClass {
            $(
                $(#[$class_meta])*
                $class,
            )+
        }

        impl TxRetryClass {
            /// Complete closed retry-class set in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$class),+];

            /// Stable low-cardinality metrics/log label.
            #[must_use]
            pub const fn as_label(self) -> &'static str {
                match self {
                    $(Self::$class => $class_label),+
                }
            }
        }

        /// Final retry loop status.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TxRetryFinalStatus {
            /// The UoW completed successfully.
            Success,
            /// Retry budget was exhausted on transient errors.
            Exhausted,
            /// The loop stopped immediately on a non-retryable class.
            NotRetryable(TxRetryClass),
        }

        impl TxRetryFinalStatus {
            /// Complete closed final-status set: fixed outcomes, then every retry class in
            /// declaration order.
            pub const ALL: &'static [Self] = &[
                Self::Success,
                Self::Exhausted,
                $(Self::NotRetryable(TxRetryClass::$class)),+
            ];

            /// Stable low-cardinality metrics/log label.
            #[must_use]
            pub const fn as_label(self) -> &'static str {
                match self {
                    Self::Success => "success",
                    Self::Exhausted => "exhausted",
                    $(Self::NotRetryable(TxRetryClass::$class) => $final_label),+
                }
            }
        }
    };
}

closed_tx_retry_vocabulary! {
    /// Temporary storage/backend failure; retrying the whole UoW is allowed while budget remains.
    Transient => ("transient", "transient_not_retried"),
    /// CAS/version conflict; callers must refetch/recompute explicitly above the UoW.
    Conflict => ("conflict", "conflict"),
    /// Permanent failure; retrying the same UoW cannot make progress.
    Permanent => ("permanent", "permanent"),
    /// Fencing/lease/ownership was lost; retrying the same side effect risks double execution.
    OwnershipLost => ("ownership_lost", "ownership_lost"),
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
                    drop(error);
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
    use std::rc::Rc;
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
        let labels: Vec<_> = TxRetryClass::ALL
            .iter()
            .map(|class| class.as_label())
            .collect();
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
        let labels: Vec<_> = TxRetryFinalStatus::ALL
            .iter()
            .map(|status| status.as_label())
            .collect();
        assert_eq!(
            labels,
            [
                "success",
                "exhausted",
                "transient_not_retried",
                "conflict",
                "permanent",
                "ownership_lost",
            ]
        );
        for (index, label) in labels.iter().enumerate() {
            assert!(
                !labels[(index + 1)..].contains(label),
                "duplicate final status label: {label}"
            );
        }
    }

    #[test]
    fn final_status_payloads_cover_retry_classes_in_declaration_order() {
        let payloads = &TxRetryFinalStatus::ALL[2..];
        assert_eq!(payloads.len(), TxRetryClass::ALL.len());
        for (status, class) in payloads.iter().zip(TxRetryClass::ALL) {
            assert_eq!(*status, TxRetryFinalStatus::NotRetryable(*class));
        }
    }

    mod synthetic_added_class_compile_proof {
        closed_tx_retry_vocabulary! {
            /// Baseline synthetic class.
            Baseline => ("baseline", "baseline_not_retried"),
            /// A newly added class that must expand into both closed sets.
            Added => ("added", "added_not_retried"),
        }

        // Removing either generated payload makes this native compile-time equality fail.
        const _: [(); TxRetryClass::ALL.len()] = [(); TxRetryFinalStatus::ALL.len() - 2];

        #[test]
        fn added_class_is_present_in_the_generated_final_set() {
            assert_eq!(
                TxRetryFinalStatus::ALL,
                [
                    TxRetryFinalStatus::Success,
                    TxRetryFinalStatus::Exhausted,
                    TxRetryFinalStatus::NotRetryable(TxRetryClass::Baseline),
                    TxRetryFinalStatus::NotRetryable(TxRetryClass::Added),
                ]
            );
            assert_eq!(TxRetryClass::Added.as_label(), "added");
            assert_eq!(
                TxRetryFinalStatus::NotRetryable(TxRetryClass::Added).as_label(),
                "added_not_retried"
            );
        }
    }

    #[test]
    fn default_policy_exposes_expected_attempt_budget() {
        assert_eq!(TxRetryPolicy::DEFAULT.max_attempts(), 3);
        assert_eq!(TxRetryPolicy::default().max_attempts(), 3);
    }

    #[test]
    fn should_retry_only_transient_before_attempt_budget() {
        let policy = TxRetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
        };

        let cases = [
            (TxRetryClass::Transient, 1, true),
            (TxRetryClass::Transient, 2, true),
            (TxRetryClass::Transient, 3, false),
            (TxRetryClass::Conflict, 1, false),
            (TxRetryClass::Permanent, 1, false),
            (TxRetryClass::OwnershipLost, 1, false),
        ];
        for (class, attempt, expected) in cases {
            assert_eq!(
                policy.should_retry(class, attempt),
                expected,
                "class={class:?} attempt={attempt}"
            );
        }
    }

    #[test]
    fn delay_after_uses_exponential_backoff_and_caps_at_max() {
        let policy = TxRetryPolicy {
            max_attempts: 10,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
        };

        let cases = [
            (0, Duration::from_millis(5)),
            (1, Duration::from_millis(5)),
            (2, Duration::from_millis(10)),
            (3, Duration::from_millis(20)),
            (4, Duration::from_millis(20)),
            (40, Duration::from_millis(20)),
        ];
        for (attempt, expected) in cases {
            assert_eq!(policy.delay_after(attempt), expected, "attempt={attempt}");
        }
    }

    #[test]
    fn delay_after_zero_base_stays_zero() {
        let policy = TxRetryPolicy {
            max_attempts: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::from_millis(10),
        };

        for attempt in [0, 1, 2, 40] {
            assert_eq!(policy.delay_after(attempt), Duration::ZERO);
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

        assert!(matches!(result, Ok("done")));
        assert_eq!(calls.get(), 3);
        assert_eq!(report.attempts(), 3);
        assert_eq!(report.final_status(), TxRetryFinalStatus::Success);
    }

    #[tokio::test]
    async fn transient_retry_sleeps_with_policy_delay() {
        let calls = Cell::new(0);
        let slept = Cell::new(Duration::ZERO);
        let policy = TxRetryPolicy {
            max_attempts: 2,
            base_delay: Duration::from_millis(7),
            max_delay: Duration::from_millis(50),
        };

        let (result, report) = run_tx_retry(
            policy,
            |attempt| {
                calls.set(calls.get() + 1);
                async move {
                    if attempt == 1 {
                        Err(FakeError::Transient)
                    } else {
                        Ok("done")
                    }
                }
            },
            classify,
            |delay| {
                slept.set(delay);
                async {}
            },
        )
        .await;

        assert!(matches!(result, Ok("done")));
        assert_eq!(calls.get(), 2);
        assert_eq!(slept.get(), Duration::from_millis(7));
        assert_eq!(report.attempts(), 2);
        assert_eq!(report.final_status(), TxRetryFinalStatus::Success);
    }

    #[tokio::test]
    async fn retry_drops_failed_error_before_backoff_sleep() {
        #[derive(Debug)]
        struct DropSentinel {
            dropped: Rc<Cell<bool>>,
        }

        impl Drop for DropSentinel {
            fn drop(&mut self) {
                self.dropped.set(true);
            }
        }

        let dropped = Rc::new(Cell::new(false));
        let observed_before_sleep = Rc::new(Cell::new(false));
        let policy = TxRetryPolicy {
            max_attempts: 2,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
        };
        let dropped_for_op = Rc::clone(&dropped);
        let observed_for_sleep = Rc::clone(&observed_before_sleep);

        let (result, report) = run_tx_retry(
            policy,
            move |attempt| {
                let dropped_for_op = Rc::clone(&dropped_for_op);
                async move {
                    if attempt == 1 {
                        Err(DropSentinel {
                            dropped: dropped_for_op,
                        })
                    } else {
                        Ok("done")
                    }
                }
            },
            |_error| TxRetryClass::Transient,
            move |_delay| {
                observed_for_sleep.set(dropped.get());
                async {}
            },
        )
        .await;

        assert!(matches!(result, Ok("done")));
        assert!(observed_before_sleep.get());
        assert_eq!(report.attempts(), 2);
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
