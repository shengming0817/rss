//! One monotonic budget across all provider stages.
use crate::Error;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// Caller-injected monotonic clock and sleeper, sharing one time origin.
pub trait Timer: Send + Sync {
    /// Elapsed monotonic time since the caller's origin.
    fn now(&self) -> Duration;
    /// Sleep until a coordinate in that same origin.
    fn sleep_until(&self, deadline: Duration) -> impl Future<Output = ()> + Send;
}
/// Per-invocation cancellation and absolute deadline. Stages never reset the budget.
pub struct Control<'a, T> {
    timer: &'a T,
    deadline: Duration,
    cancel: &'a CancellationToken,
}
impl<'a, T: Timer> Control<'a, T> {
    /// Bind the explicit timer, deadline and cancellation signal.
    pub const fn new(timer: &'a T, deadline: Duration, cancel: &'a CancellationToken) -> Self {
        Self {
            timer,
            deadline,
            cancel,
        }
    }
    /// Check whether another operation may start.
    pub fn check(&self) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(Error::new(crate::ErrorKind::Cancelled))
        } else if self.timer.now() >= self.deadline {
            Err(Error::new(crate::ErrorKind::Deadline))
        } else {
            Ok(())
        }
    }
    /// Remaining time, for provider lock/statement timeouts.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_sub(self.timer.now())
    }
    /// Bound an operation. Interruption does not prove a mutating operation rolled back.
    pub async fn run<R>(
        &self,
        future: impl Future<Output = Result<R, Error>> + Send,
    ) -> Result<R, Error> {
        self.check()?;
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(Error::new(crate::ErrorKind::Cancelled)),
            () = self.timer.sleep_until(self.deadline) => Err(Error::new(crate::ErrorKind::Deadline)),
            result = future => result,
        }
    }
}
impl<T: Timer> Control<'_, T> {
    pub(crate) async fn wait(&self, duration: Duration) -> Result<(), Error> {
        let until = self.timer.now().saturating_add(duration);
        self.run(async {
            self.timer.sleep_until(until).await;
            Ok(())
        })
        .await
    }
}
/// Operational lease timing, independent of the definition and total execution deadline.
#[derive(Debug, Clone, Copy)]
pub struct LeasePolicy {
    ttl: Duration,
}
impl LeasePolicy {
    /// Choose a lease between 30 milliseconds and 24 hours. Renewals run every third of its TTL.
    /// Prefer the 30-second default; a longer TTL explicitly increases crash recovery latency.
    pub fn new(ttl: Duration) -> Result<Self, Error> {
        if ttl < Duration::from_millis(30) || ttl > Duration::from_secs(86400) {
            return Err(Error::new(crate::ErrorKind::LeaseInput));
        }
        Ok(Self { ttl })
    }
    /// Lease expiry duration passed to the provider.
    pub const fn ttl(self) -> Duration {
        self.ttl
    }
    pub(crate) fn renewal_interval(self) -> Duration {
        self.ttl / 3
    }
}
impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(30),
        }
    }
}
