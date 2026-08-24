//! Internal Tokio wait helpers for the public provider-neutral retry policy.

use std::num::NonZeroU32;
use std::time::Duration;

use eventing::lifecycle::RetryPolicy;
use tokio_util::sync::CancellationToken;

pub(crate) fn delay_after(policy: &RetryPolicy, failed_attempt: u32) -> Duration {
    policy.delay_after(NonZeroU32::new(failed_attempt).unwrap_or(NonZeroU32::MIN))
}

/// Wait for the delay or cancellation, giving cancellation deterministic priority.
pub(crate) async fn wait_or_cancel(delay: Duration, token: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = token.cancelled() => true,
        () = tokio::time::sleep(delay) => false,
    }
}
