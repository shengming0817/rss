use crate::Error;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// One absolute budget, including transaction settlement. Never reset between stages.
pub struct Control<'a, T> {
    timer: &'a T,
    deadline: Deadline,
    cancel: &'a CancellationToken,
}
impl<'a, T: ExecutionTimer> Control<'a, T> {
    /// Bind an injected timer, absolute deadline and cancellation signal.
    pub const fn new(timer: &'a T, deadline: Deadline, cancel: &'a CancellationToken) -> Self {
        Self {
            timer,
            deadline,
            cancel,
        }
    }
    /// Remaining duration in the caller's clock domain.
    pub fn remaining(&self) -> Duration {
        self.deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    pub(crate) fn check(&self, stage: LocalTxDeadlineStage) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled(stage))
        } else if self.deadline.is_expired(self.timer.now()) {
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
            () = self.cancel.cancelled() => Err(Error::Cancelled(stage)),
            () = self.timer.sleep_until(self.deadline) => Err(Error::Deadline(stage)),
            result = future => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use rss_transactional_messaging_testkit::memory::FakeClock;

    #[tokio::test]
    async fn simultaneous_wakeups_prefer_cancel_then_deadline_over_business() -> anyhow::Result<()>
    {
        for cancelled in [false, true] {
            let timer = FakeClock::new();
            let deadline = Deadline::from_timeout(&timer, Duration::from_secs(1))?;
            let cancel = CancellationToken::new();
            let business_ready = CancellationToken::new();
            let control = Control::new(&timer, deadline, &cancel);
            let stage = LocalTxDeadlineStage::Operation;
            let operation = control.run_stage(stage, async {
                business_ready.cancelled().await;
                Ok(())
            });
            tokio::pin!(operation);
            assert!(operation.as_mut().now_or_never().is_none());

            business_ready.cancel();
            timer.advance(Duration::from_secs(1))?;
            if cancelled {
                cancel.cancel();
            }
            assert_eq!(control.remaining(), Duration::ZERO);
            match operation.await {
                Err(Error::Cancelled(LocalTxDeadlineStage::Operation)) if cancelled => {}
                Err(Error::Deadline(LocalTxDeadlineStage::Operation)) if !cancelled => {}
                result => anyhow::bail!("unexpected simultaneous result: {result:?}"),
            }
        }
        Ok(())
    }
}
