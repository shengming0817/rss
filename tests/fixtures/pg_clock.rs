//! Real monotonic time for the Audit and Ledger PostgreSQL acceptance suites.
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use std::{future::poll_fn, task::Poll, time::Instant};

pub struct TestClock;
impl Clock for TestClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "the injected fixture owns the monotonic clock"
    )]
    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for TestClock {
    async fn sleep_until(&self, deadline: Deadline) {
        let sleep = tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into()));
        tokio::pin!(sleep);
        // Tokio rounds timer-wheel wakeups. An already elapsed cutoff wins on this poll.
        poll_fn(|cx| {
            if deadline.is_expired(self.now()) {
                Poll::Ready(())
            } else {
                sleep.as_mut().poll(cx)
            }
        })
        .await;
    }
}
