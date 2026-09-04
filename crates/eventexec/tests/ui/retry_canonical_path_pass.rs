use std::time::Duration;
use std::num::NonZeroU32;

use rss_transactional_messaging::policy::{RetryPolicy, RetryPolicyError};

fn main() {
    let policy: Result<RetryPolicy, RetryPolicyError> =
        RetryPolicy::new(
            NonZeroU32::MIN,
            Duration::from_millis(1),
            Duration::from_secs(1),
        );
    let _ = policy.expect("valid retry policy");
}
