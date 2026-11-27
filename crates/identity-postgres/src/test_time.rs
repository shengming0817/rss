//! A fixed observation for exact proof and deadline boundary tests.
use rss_request_context::{Clock, Deadline, ExecutionTimer, SharedExecutionTimer};
use std::time::Instant;

struct Frozen(Instant);
impl Clock for Frozen {
    fn now(&self) -> Instant {
        self.0
    }
}
impl ExecutionTimer for Frozen {
    async fn sleep_until(&self, cutoff: Deadline) {
        if !cutoff.is_expired(self.now()) {
            std::future::pending::<()>().await;
        }
    }
}
pub(super) fn at(now: Instant) -> SharedExecutionTimer {
    SharedExecutionTimer::new(Frozen(now))
}

#[tokio::test]
#[allow(clippy::disallowed_methods, reason = "seed the controlled test clock")]
async fn delayed_handoff_expires_at_the_original_cutoff() -> Result<(), crate::AuthorityError> {
    use std::time::Duration;
    let received = Instant::now();
    let cutoff = Deadline::at(received + Duration::from_secs(5));
    let handed_off = at(received + Duration::from_secs(3));
    let budget = crate::Budget::new(cutoff, &handed_off)?;
    assert_eq!(budget.time_left(), Duration::from_secs(2));
    assert!(crate::Budget::new(budget.cutoff, &at(received + Duration::from_secs(5))).is_err());
    Ok(())
}
