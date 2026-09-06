//! One monotonic budget across all provider stages.
use crate::{Error, ErrorKind};
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
            Err(Error::new(ErrorKind::Cancelled))
        } else if self.timer.now() >= self.deadline {
            Err(Error::new(ErrorKind::Deadline))
        } else {
            Ok(())
        }
    }
    /// Limit an attempt without resetting the outer budget or cancellation signal.
    pub fn child(&self, timeout: Duration) -> Control<'_, T> {
        Control {
            timer: self.timer,
            deadline: self.timer.now().saturating_add(timeout).min(self.deadline),
            cancel: self.cancel,
        }
    }
    pub(crate) async fn sleep_until(&self, deadline: Duration) {
        self.timer.sleep_until(deadline).await;
    }
    /// Sleep on the explicitly injected monotonic clock.
    pub async fn sleep(&self, duration: Duration) {
        self.timer
            .sleep_until(self.timer.now().saturating_add(duration))
            .await;
    }
    /// Current coordinate of the caller-injected monotonic clock.
    pub fn elapsed(&self) -> Duration {
        self.timer.now()
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
            () = self.cancel.cancelled() => Err(Error::new(ErrorKind::Cancelled)),
            () = self.timer.sleep_until(self.deadline) => Err(Error::new(ErrorKind::Deadline)),
            result = future => result,
        }
    }
}
