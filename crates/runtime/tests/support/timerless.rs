//! Same source runs as a normal integration test and as an isolated panic=abort consumer.
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_runtime::{
    DrainCompletion, DynManagedResource, LifecycleScope, ManagedResource, ShutdownError,
    ShutdownFailureKind, ShutdownStack, TotalDrainBudget,
};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

struct ManualTimer {
    origin: Instant,
    millis: AtomicU64,
    changed: tokio::sync::Notify,
}
impl ManualTimer {
    #[allow(clippy::disallowed_methods)] // reason: the injected manual clock owns its origin.
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            millis: AtomicU64::new(0),
            changed: tokio::sync::Notify::new(),
        }
    }
    fn advance(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}
impl Clock for ManualTimer {
    fn now(&self) -> Instant {
        self.origin + Duration::from_millis(self.millis.load(Ordering::SeqCst))
    }
}
impl ExecutionTimer for ManualTimer {
    async fn sleep_until(&self, deadline: Deadline) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if deadline.instant() <= self.now() {
                return;
            }
            changed.await;
        }
    }
}

struct Resource {
    budget: Duration,
    started: Arc<tokio::sync::Notify>,
    dropped: Arc<AtomicUsize>,
    pending: bool,
}
impl Drop for Resource {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl ManagedResource for Resource {
    fn name(&self) -> &str {
        "manual-timer-resource"
    }
    fn shutdown_timeout(&self) -> Duration {
        self.budget
    }
    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.started.notify_one();
        if self.pending {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let timer = Arc::new(ManualTimer::new());
        for (total, per_resource, pending) in [(5, 1, false), (5, 1, true), (1, 5, true)] {
            let started = Arc::new(tokio::sync::Notify::new());
            let dropped = Arc::new(AtomicUsize::new(0));
            let mut stack = ShutdownStack::try_new(
                TotalDrainBudget::new(Duration::from_secs(total))?,
                timer.clone(),
            )?;
            let mut startup = stack.startup()?;
            startup.stage_resource(DynManagedResource::new_box(Resource {
                budget: Duration::from_secs(per_resource),
                started: started.clone(),
                dropped: dropped.clone(),
                pending,
            }));
            startup.commit().finish();
            let drain = stack.shutdown();
            started.notified().await;
            timer.advance(1000);
            let receipt = drain.join().await?;
            assert_eq!(
                dropped.load(Ordering::SeqCst),
                1,
                "owner joined resource destruction"
            );
            if !pending {
                assert!(receipt.is_clean());
            } else if total < per_resource {
                assert_eq!(receipt.completion(), DrainCompletion::BudgetExhausted);
                assert!(matches!(
                    receipt.failures()[0].kind,
                    ShutdownFailureKind::BudgetExhausted
                ));
            } else {
                assert_eq!(receipt.completion(), DrainCompletion::Complete);
                assert!(matches!(
                    receipt.failures()[0].kind,
                    ShutdownFailureKind::TimedOut(_)
                ));
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut overflow =
            ShutdownStack::try_new(TotalDrainBudget::new(Duration::MAX)?, timer.clone())?;
        let mut startup = overflow.startup()?;
        startup.stage_resource(DynManagedResource::new_box(Resource {
            budget: Duration::from_secs(1),
            started: Arc::new(tokio::sync::Notify::new()),
            dropped: dropped.clone(),
            pending: true,
        }));
        startup.commit().finish();
        let receipt = overflow.shutdown().join().await?;
        assert_eq!(receipt.completion(), DrainCompletion::BudgetExhausted);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);

        let mut scope = LifecycleScope::<(), (), ()>::try_new(
            TotalDrainBudget::new(Duration::from_secs(1))?,
            timer,
        )?;
        let outcome = scope
            .drive(
                |startup| {
                    Box::pin(async move {
                        startup.commit().finish();
                        Ok(())
                    })
                },
                std::future::pending::<Result<(), ()>>(),
            )
            .await?;
        assert!(
            outcome
                .shutdown()
                .as_ref()
                .is_ok_and(|receipt| receipt.is_clean())
        );
        Ok(())
    })
}
