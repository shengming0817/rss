use std::time::Duration;

use eventexec::retry::{BackoffError, BackoffPolicy};

fn main() {
    let policy: Result<BackoffPolicy, BackoffError> =
        BackoffPolicy::new(Duration::from_millis(1), Duration::from_secs(1));
    let _ = policy.expect("valid retry policy");
}
