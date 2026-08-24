//! Provider-neutral retry policy shared by L2 workers and internal L3/L4 runtimes.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Retry policy construction failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackoffError {
    /// The initial delay exceeds the cap.
    #[error("retry backoff base ({base:?}) exceeds cap ({cap:?})")]
    BaseExceedsCap {
        /// Configured initial delay.
        base: Duration,
        /// Configured maximum delay.
        cap: Duration,
    },
}

/// Exponential retry policy: `base * 2^(attempts-1)`, saturated at `cap`.
#[derive(Debug, Clone, Copy)]
pub struct BackoffPolicy {
    base: Duration,
    cap: Duration,
}

impl BackoffPolicy {
    /// Build a retry policy, rejecting `base > cap` without silently clamping it.
    pub fn new(base: Duration, cap: Duration) -> Result<Self, BackoffError> {
        if base > cap {
            return Err(BackoffError::BaseExceedsCap { base, cap });
        }
        Ok(Self { base, cap })
    }

    /// Return the delay for a 1-based failure count, saturating instead of wrapping.
    pub(crate) fn delay_for(&self, attempts: u32) -> Duration {
        let exp = attempts.saturating_sub(1).min(31);
        let factor = 1_u32 << exp;
        self.base.saturating_mul(factor).min(self.cap)
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            cap: Duration::from_secs(60),
        }
    }
}

/// Wait for the delay or cancellation, giving cancellation deterministic priority.
pub(crate) async fn wait_or_cancel(delay: Duration, token: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = token.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{BackoffError, BackoffPolicy};

    #[test]
    fn rejects_base_exceeding_cap() {
        assert!(matches!(
            BackoffPolicy::new(Duration::from_secs(2), Duration::from_secs(1)),
            Err(BackoffError::BaseExceedsCap { .. })
        ));
        assert!(BackoffPolicy::new(Duration::from_secs(1), Duration::from_secs(1)).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn grows_exponentially_and_saturates_at_cap() {
        let policy =
            BackoffPolicy::new(Duration::from_secs(1), Duration::from_secs(10)).expect("policy");
        assert_eq!(policy.delay_for(0), Duration::from_secs(1));
        assert_eq!(policy.delay_for(1), Duration::from_secs(1));
        assert_eq!(policy.delay_for(2), Duration::from_secs(2));
        assert_eq!(policy.delay_for(3), Duration::from_secs(4));
        assert_eq!(policy.delay_for(4), Duration::from_secs(8));
        assert_eq!(policy.delay_for(5), Duration::from_secs(10));
        assert_eq!(policy.delay_for(99), Duration::from_secs(10));
    }
}
