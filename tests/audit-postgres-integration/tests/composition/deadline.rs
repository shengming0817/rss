use super::*;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
use std::sync::atomic::{AtomicBool, Ordering};

struct AdvancingClock {
    anchor: Instant,
    advanced: AtomicBool,
}
impl Clock for AdvancingClock {
    fn now(&self) -> Instant {
        self.anchor + Duration::from_secs(u64::from(self.advanced.load(Ordering::SeqCst)))
    }
}
impl ExecutionTimer for AdvancingClock {
    async fn sleep_until(&self, deadline: Deadline) {
        futures::future::poll_fn(|_| {
            if deadline.is_expired(self.now()) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
    }
}

pub(super) async fn run(store: &PgAudit) -> anyhow::Result<()> {
    for reject in [false, true] {
        let clock = AdvancingClock {
            anchor: TestClock.now(),
            advanced: AtomicBool::new(false),
        };
        let cancel = CancellationToken::new();
        let control = Control::new(
            &clock,
            Deadline::at(clock.anchor + Duration::from_secs(10)),
            Deadline::at(clock.anchor + Duration::from_millis(500)),
            &cancel,
        );
        let attempt = store
            .read_tx_with_context(tenant()?, &control, &clock, move |clock, _| {
                Box::pin(async move {
                    // Simulate synchronous host work reaching the cutoff in its final poll.
                    clock.advanced.store(true, Ordering::SeqCst);
                    if reject { Err(Error::Conflict) } else { Ok(()) }
                })
            })
            .await;
        let result = attempt.fold(|_| None, |_| None, Some, |_| None, |_| None, |_| None);
        if reject {
            assert!(matches!(
                result,
                Some(TransactionError::Operation(Error::Conflict))
            ));
        } else {
            assert!(matches!(
                result,
                Some(TransactionError::Audit(Error::Deadline(Stage::Operation)))
            ));
        }
    }
    Ok(())
}
