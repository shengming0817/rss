use crate::Error;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// Caller-owned absolute cutoffs for the transaction owner and its operation.
pub struct Control<'a, T> {
    timer: &'a T,
    total_deadline: Deadline,
    operation_deadline: Deadline,
    cancel: &'a CancellationToken,
}
impl<'a, T: ExecutionTimer> Control<'a, T> {
    /// Bind absolute cutoffs without refreshing them. Operation is capped by total.
    pub fn new(
        timer: &'a T,
        total_deadline: Deadline,
        operation_deadline: Deadline,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            timer,
            total_deadline,
            operation_deadline: operation_deadline.shortened_to(total_deadline.instant()),
            cancel,
        }
    }
    /// Remaining owner time for acquisition, setup and acknowledged settlement.
    pub fn total_remaining(&self) -> Duration {
        self.total_deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    /// Remaining time for pre-locking and the business callback.
    pub fn operation_remaining(&self) -> Duration {
        self.operation_deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    fn deadline(&self, stage: LocalTxDeadlineStage) -> Deadline {
        match stage {
            LocalTxDeadlineStage::Operation => self.operation_deadline,
            _ => self.total_deadline,
        }
    }
    #[cfg(feature = "ledger")]
    pub(crate) fn ledger_control(
        &self,
        stage: LocalTxDeadlineStage,
    ) -> rss_ledger_postgres::Control<'a, T> {
        rss_ledger_postgres::Control::new(self.timer, self.deadline(stage), self.cancel)
    }
    /// Check cancellation and the original cutoff before starting synchronous work at a stage.
    pub fn check(&self, stage: LocalTxDeadlineStage) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled(stage))
        } else if self.deadline(stage).is_expired(self.timer.now()) {
            Err(Error::Deadline(stage))
        } else {
            Ok(())
        }
    }
    pub(crate) async fn run<R>(
        &self,
        stage: LocalTxDeadlineStage,
        future: impl Future<Output = Result<R, Error>>,
    ) -> Result<R, Error> {
        self.check(stage)?;
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(Error::Cancelled(stage)),
            () = self.timer.sleep_until(self.deadline(stage)) => Err(Error::Deadline(stage)),
            value = future => value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_request_context::Clock;
    use rss_transactional_messaging_testkit::memory::FakeClock;

    #[test]
    fn operation_expiry_preserves_settlement_and_total_caps_every_stage() {
        let clock = FakeClock::new();
        let cancel = CancellationToken::new();
        let expired = Deadline::at(clock.now());
        let future = Deadline::at(clock.now() + Duration::from_secs(1));
        let control = Control::new(&clock, future, expired, &cancel);
        assert!(matches!(
            control.check(LocalTxDeadlineStage::Operation),
            Err(Error::Deadline(LocalTxDeadlineStage::Operation))
        ));
        for stage in [
            LocalTxDeadlineStage::Acquire,
            LocalTxDeadlineStage::Begin,
            LocalTxDeadlineStage::Setup,
            LocalTxDeadlineStage::Commit,
            LocalTxDeadlineStage::Rollback,
        ] {
            assert!(control.check(stage).is_ok());
            assert!(matches!(
                Control::new(&clock, expired, future, &cancel).check(stage),
                Err(Error::Deadline(_))
            ));
        }
        assert!(
            Control::new(&clock, expired, future, &cancel)
                .operation_remaining()
                .is_zero()
        );
    }

    #[cfg(feature = "ledger")]
    #[test]
    fn ledger_inherits_absolute_stage_cutoffs_after_time_spent_in_audit() -> anyhow::Result<()> {
        let timer = FakeClock::new();
        let cancel = CancellationToken::new();
        let total = Deadline::from_timeout(&timer, Duration::from_secs(8))?;
        let operation = Deadline::from_timeout(&timer, Duration::from_secs(3))?;
        let audit = Control::new(&timer, total, operation, &cancel);

        timer.advance(Duration::from_secs(2))?;
        let setup = audit.ledger_control(LocalTxDeadlineStage::Setup);
        let write = audit.ledger_control(LocalTxDeadlineStage::Operation);
        assert_eq!(setup.remaining(), Duration::from_secs(6));
        assert_eq!(write.remaining(), Duration::from_secs(1));

        timer.advance(Duration::from_secs(1))?;
        assert_eq!(write.remaining(), Duration::ZERO);
        assert_eq!(setup.remaining(), Duration::from_secs(5));
        Ok(())
    }
}
