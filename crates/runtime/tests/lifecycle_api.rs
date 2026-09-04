use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rss_runtime::{
    DrainCompletion, DynManagedResource, ManagedResource, ManagedTask, ShutdownError,
    ShutdownFailureKind, ShutdownStack, ShutdownStackError, TaskState, TotalDrainBudget,
    blocking_worker_registration,
};

struct RecordingResource {
    name: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
}

struct PausingResource {
    starts: Arc<AtomicUsize>,
    finishes: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
}

struct GateResource {
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl ManagedResource for GateResource {
    fn name(&self) -> &str {
        "gate"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.started.notify_one();
        self.release.notified().await;
        Ok(())
    }
}

struct FailingResource;

impl ManagedResource for FailingResource {
    fn name(&self) -> &str {
        "failed"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        Err(ShutdownError::new(std::io::Error::other("private")))
    }
}

struct HangingResource(&'static str);

impl ManagedResource for HangingResource {
    fn name(&self) -> &str {
        self.0
    }

    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(60)
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        std::future::pending().await
    }
}

struct DropObservedHangingResource(Arc<AtomicUsize>);

impl ManagedResource for DropObservedHangingResource {
    fn name(&self) -> &str {
        "drop-budget"
    }

    fn shutdown_timeout(&self) -> Duration {
        Duration::from_secs(60)
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let _guard = Guard(Arc::clone(&self.0));
        std::future::pending().await
    }
}

impl ManagedResource for PausingResource {
    fn name(&self) -> &str {
        "pausing"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.starts.fetch_add(1, Ordering::AcqRel);
        self.release.notified().await;
        self.finishes.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

impl ManagedResource for RecordingResource {
    fn name(&self) -> &str {
        self.name
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(self.name);
        Ok(())
    }
}

#[test]
#[allow(clippy::expect_used)] // reason: invalid construction is asserted by this test.
fn total_drain_budget_rejects_zero() {
    assert!(TotalDrainBudget::new(Duration::ZERO).is_err());
    assert!(TotalDrainBudget::new(Duration::from_secs(1)).is_ok());
}

#[test]
#[allow(clippy::expect_used)] // reason: fixed positive budget is test setup.
fn shutdown_owner_requires_an_active_tokio_runtime() {
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    assert!(matches!(
        ShutdownStack::try_new(budget),
        Err(ShutdownStackError::RuntimeUnavailable)
    ));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: lifecycle setup and clean drain are test assertions.
async fn empty_runtime_finishes_with_a_typed_clean_receipt() {
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let receipt = stack.shutdown().await.expect("driver remains available");
    assert!(receipt.is_clean());
    assert_eq!(receipt.registered_resources(), 0);
    assert_eq!(receipt.completion(), DrainCompletion::Complete);
    assert!(receipt.failures().is_empty());
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: lifecycle setup and clean drain are test assertions.
async fn startup_and_launch_stage_resources_immediately_and_drain_lifo() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let mut startup = stack.startup().expect("registration is open");
    startup.stage_resource(DynManagedResource::new_box(RecordingResource {
        name: "dependency",
        events: Arc::clone(&events),
    }));
    let mut launch = startup.commit();
    launch.stage_resource(DynManagedResource::new_box(RecordingResource {
        name: "dependent",
        events: Arc::clone(&events),
    }));
    launch.finish();

    let receipt = stack.shutdown().await.expect("driver remains available");
    assert!(receipt.is_clean());
    assert_eq!(receipt.registered_resources(), 2);
    assert_eq!(
        *events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec!["dependent", "dependency"]
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: bounded background completion is the test assertion.
async fn dropping_stack_continues_the_owned_drain() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let mut startup = stack.startup().expect("registration is open");
    startup.stage_resource(DynManagedResource::new_box(RecordingResource {
        name: "first",
        events: Arc::clone(&events),
    }));
    startup.stage_resource(DynManagedResource::new_box(RecordingResource {
        name: "owned",
        events: Arc::clone(&events),
    }));
    drop(stack);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
                == 2
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drop-owned drain must complete");
    assert_eq!(
        *events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec!["owned", "first"]
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: bounded background completion is the test assertion.
async fn dropped_stack_keeps_the_total_drain_budget() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let budget = TotalDrainBudget::new(Duration::from_millis(20)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    stack
        .startup()
        .expect("registration is open")
        .stage_resource(DynManagedResource::new_box(DropObservedHangingResource(
            Arc::clone(&dropped),
        )));
    drop(stack);

    tokio::time::timeout(Duration::from_secs(1), async {
        while dropped.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drop-owned drain remains bounded");
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: bounded background completion is the test assertion.
async fn cancelling_shutdown_waiter_continues_exactly_one_owned_drain() {
    let starts = Arc::new(AtomicUsize::new(0));
    let finishes = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    stack
        .startup()
        .expect("registration is open")
        .stage_resource(DynManagedResource::new_box(PausingResource {
            starts: Arc::clone(&starts),
            finishes: Arc::clone(&finishes),
            release: Arc::clone(&release),
        }));

    let waiter = tokio::spawn(stack.shutdown());
    while starts.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
    }
    waiter.abort();
    let _ = waiter.await;
    release.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while finishes.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("background drain must finish");
    assert_eq!(starts.load(Ordering::Acquire), 1);
    assert_eq!(finishes.load(Ordering::Acquire), 1);
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: transaction setup and driver join are test assertions.
async fn transaction_funnels_bind_tokens_and_seal_after_launch() {
    let regular_token = Arc::new(Mutex::new(None));
    let deferred_token = Arc::new(Mutex::new(None));
    let gate_started = Arc::new(tokio::sync::Notify::new());
    let gate_release = Arc::new(tokio::sync::Notify::new());
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let (regular_start, regular_status) = ManagedTask::prepare("regular", Duration::from_secs(1));
    let regular_registration = regular_start.into_registration(|token| async move {
        token.cancelled().await;
        Ok(())
    });
    let (deferred_start, deferred_status) =
        ManagedTask::prepare("deferred", Duration::from_secs(1));
    let deferred_registration = deferred_start.into_registration(|token| async move {
        token.cancelled().await;
        Ok(())
    });

    let mut startup = stack.startup().expect("registration is open");
    startup.stage_with_token({
        let regular_token = Arc::clone(&regular_token);
        move |token| {
            *regular_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token);
            DynManagedResource::new_box(RecordingResource {
                name: "regular-resource",
                events: Arc::new(Mutex::new(Vec::new())),
            })
        }
    });
    let returned_regular = startup.stage_task_with_token(regular_registration);
    let mut launch = startup.commit();
    launch.stage_deferred_with_token({
        let deferred_token = Arc::clone(&deferred_token);
        move |token| {
            *deferred_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token);
            DynManagedResource::new_box(RecordingResource {
                name: "deferred-resource",
                events: Arc::new(Mutex::new(Vec::new())),
            })
        }
    });
    let returned_deferred = launch.stage_deferred_task_with_token(deferred_registration);
    launch.stage_resource(DynManagedResource::new_box(GateResource {
        started: Arc::clone(&gate_started),
        release: Arc::clone(&gate_release),
    }));
    launch.finish();
    assert!(stack.startup().is_err(), "registration cannot be reopened");

    let waiter = tokio::spawn(stack.shutdown());
    gate_started.notified().await;
    assert!(
        regular_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
    );
    assert!(
        !deferred_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
    );
    assert_eq!(returned_regular.current(), regular_status.current());
    assert_eq!(returned_deferred.current(), deferred_status.current());
    gate_release.notify_one();
    let receipt = waiter
        .await
        .expect("waiter joins")
        .expect("driver remains available");
    assert!(receipt.is_clean());
    assert!(matches!(regular_status.current(), TaskState::Stopped(_)));
    assert!(matches!(deferred_status.current(), TaskState::Stopped(_)));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: fallible worker startup and clean join are test assertions.
async fn transaction_starts_and_joins_fallible_blocking_registration() {
    let observed_token = Arc::new(Mutex::new(None));
    let run_observed_token = Arc::clone(&observed_token);
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let registration = blocking_worker_registration(
        "transaction-blocking",
        Duration::from_secs(1),
        move |token| {
            *run_observed_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token.clone());
            while !token.is_cancelled() {
                std::thread::yield_now();
            }
            Ok(())
        },
    );
    let status = stack
        .startup()
        .expect("registration is open")
        .try_stage_blocking_with_token(registration)
        .expect("worker thread starts");

    assert_eq!(status.current(), TaskState::Running);
    let receipt = stack.shutdown().await.expect("driver remains available");
    assert!(receipt.is_clean());
    assert!(matches!(status.current(), TaskState::Stopped(_)));
    assert!(
        observed_token
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: failure receipt construction is the test assertion.
async fn failed_receipt_is_complete_ordered_and_consumable() {
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    stack
        .startup()
        .expect("registration is open")
        .stage_resource(DynManagedResource::new_box(FailingResource));
    let receipt = stack.shutdown().await.expect("driver remains available");
    assert_eq!(receipt.registered_resources(), 1);
    assert_eq!(receipt.completion(), DrainCompletion::Complete);
    assert!(!receipt.is_clean());
    let failures = receipt.into_failures();
    assert_eq!(failures.len(), 1);
    assert!(matches!(failures[0].kind, ShutdownFailureKind::Failed(_)));
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: budget exhaustion receipt is the test assertion.
async fn exhausted_receipt_counts_current_and_remaining_resources() {
    let budget = TotalDrainBudget::new(Duration::from_millis(1)).expect("positive budget");
    let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
    let mut startup = stack.startup().expect("registration is open");
    startup.stage_resource(DynManagedResource::new_box(HangingResource("remaining")));
    startup.stage_resource(DynManagedResource::new_box(HangingResource("current")));
    let receipt = stack.shutdown().await.expect("driver remains available");
    assert_eq!(receipt.registered_resources(), 2);
    assert_eq!(receipt.completion(), DrainCompletion::BudgetExhausted);
    assert!(!receipt.is_clean());
    assert_eq!(receipt.failures().len(), 2);
    assert!(
        receipt
            .failures()
            .iter()
            .all(|failure| matches!(failure.kind, ShutdownFailureKind::BudgetExhausted))
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: runtime construction is test setup.
fn drop_after_originating_runtime_stops_still_broadcasts_cancellation() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime builds");
    let observed = Arc::new(Mutex::new(None));
    let stack = runtime.block_on(async {
        let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
        let mut stack = ShutdownStack::try_new(budget).expect("inside Tokio runtime");
        stack
            .startup()
            .expect("registration is open")
            .stage_with_token({
                let observed = Arc::clone(&observed);
                move |token| {
                    *observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token);
                    DynManagedResource::new_box(RecordingResource {
                        name: "origin-runtime",
                        events: Arc::new(Mutex::new(Vec::new())),
                    })
                }
            });
        stack
    });
    drop(runtime);
    drop(stack);
    assert!(
        observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled)
    );
}

#[test]
#[allow(clippy::expect_used)] // reason: runtime construction is test setup.
fn explicit_shutdown_reports_stopped_originating_runtime() {
    let origin = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("origin runtime builds");
    let stack = origin.block_on(async {
        let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("positive budget");
        ShutdownStack::try_new(budget).expect("inside origin runtime")
    });
    drop(origin);
    let waiter = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("waiter runtime builds");
    let result = waiter.block_on(stack.shutdown());
    assert!(matches!(result, Err(ShutdownStackError::DriverUnavailable)));
}
