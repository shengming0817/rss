#![allow(clippy::unwrap_used, clippy::disallowed_methods)]
// reason: the injected fixture owns its fixed monotonic origin.
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use std::time::{Duration, Instant};
struct Timer(Instant);
impl Clock for Timer {
    fn now(&self) -> Instant {
        self.0
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, _: Deadline) {
        std::future::pending().await
    }
}
#[test]
fn shared_deadline_is_bounded_and_rejects_overflow() {
    let timer = Timer(Instant::now());
    let deadline = Deadline::from_timeout(&timer, Duration::from_secs(10)).unwrap();
    assert_eq!(
        deadline.remaining(timer.now()),
        Some(Duration::from_secs(10))
    );
    assert_eq!(deadline.capped(&timer, Duration::from_secs(20)), deadline);
    assert_eq!(
        deadline.capped(&timer, Duration::from_secs(2)).instant(),
        timer.now() + Duration::from_secs(2)
    );
    assert!(Deadline::from_timeout(&timer, Duration::MAX).is_err());
    assert!(
        Deadline::from_timeout(&timer, Duration::ZERO)
            .unwrap()
            .is_expired(timer.now())
    );
}
