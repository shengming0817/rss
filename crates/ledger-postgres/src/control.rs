use crate::Error;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;
/// Caller-injected monotonic clock and sleeper sharing one origin.
pub trait Timer: Send + Sync {
    /// Current monotonic coordinate.
    fn now(&self) -> Duration;
    /// Wait until a coordinate in the same origin.
    fn sleep_until(&self, deadline: Duration) -> impl Future<Output = ()> + Send;
}
/// One absolute budget, including transaction settlement. Never reset between stages.
pub struct Control<'a, T> {
    timer: &'a T,
    deadline: Duration,
    cancel: &'a CancellationToken,
}
impl<'a, T: Timer> Control<'a, T> {
    /// Bind an injected timer, absolute deadline and cancellation signal.
    pub const fn new(timer: &'a T, deadline: Duration, cancel: &'a CancellationToken) -> Self {
        Self {
            timer,
            deadline,
            cancel,
        }
    }
    /// Remaining duration in the caller's clock domain.
    pub fn remaining(&self) -> Duration {
        self.deadline.saturating_sub(self.timer.now())
    }
    pub(crate) fn check(&self, stage: LocalTxDeadlineStage) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled(stage))
        } else if self.remaining().is_zero() {
            Err(Error::Deadline(stage))
        } else {
            Ok(())
        }
    }
    pub(crate) async fn run<R>(
        &self,
        future: impl Future<Output = Result<R, Error>>,
    ) -> Result<R, Error> {
        self.run_stage(LocalTxDeadlineStage::Setup, future).await
    }
    pub(crate) async fn run_stage<R>(
        &self,
        stage: LocalTxDeadlineStage,
        future: impl Future<Output = Result<R, Error>>,
    ) -> Result<R, Error> {
        self.check(stage)?;
        tokio::select! { biased;
            ()=self.cancel.cancelled()=>Err(Error::Cancelled(stage)),
            ()=self.timer.sleep_until(self.deadline)=>Err(Error::Deadline(stage)),
            result=future=>result,
        }
    }
}
