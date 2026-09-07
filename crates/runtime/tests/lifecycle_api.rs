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
    let receipt = stack
        .shutdown()
        .join()
        .await
        .expect("driver remains available");
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

    let receipt = stack
        .shutdown()
        .join()
        .await
        .expect("driver remains available");
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

    let waiter = tokio::spawn(async move { stack.shutdown().join().await });
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

    let waiter = tokio::spawn(async move { stack.shutdown().join().await });
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
    let receipt = stack
        .shutdown()
        .join()
        .await
        .expect("driver remains available");
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
    let receipt = stack
        .shutdown()
        .join()
        .await
        .expect("driver remains available");
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
    let receipt = stack
        .shutdown()
        .join()
        .await
        .expect("driver remains available");
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
    let result = waiter.block_on(async { stack.shutdown().join().await });
    assert!(matches!(result, Err(ShutdownStackError::DriverUnavailable)));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: scope setup and retained failures are test assertions.
async fn scope_retains_execution_and_shutdown_failures() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    let mut scope = LifecycleScope::<(), &'static str, &'static str>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    startup.stage_resource(DynManagedResource::new_box(FailingResource));
                    Err("startup failed")
                })
            },
            std::future::pending(),
        )
        .await
        .expect("first drive");
    assert!(matches!(
        outcome.exit(),
        ScopeExit::Completed(Err("startup failed"))
    ));
    assert!(!outcome.shutdown().as_ref().expect("receipt").is_clean());
    assert!(scope.wait().await.expect("retained").shutdown().is_ok());
    assert!(scope.into_outcome().is_some());
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: cancellation recovery is the test assertion.
async fn scope_cancelled_during_startup_recovers_receipt() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    let starts = Arc::new(AtomicUsize::new(0));
    let finishes = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Notify::new());
    let staged = Arc::new(tokio::sync::Notify::new());
    let mut scope = LifecycleScope::<(), (), ()>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    {
        let ready = Arc::clone(&staged);
        let resource = PausingResource {
            starts: Arc::clone(&starts),
            finishes: Arc::clone(&finishes),
            release: Arc::clone(&release),
        };
        let drive = scope.drive(
            move |mut startup| {
                Box::pin(async move {
                    startup.stage_resource(DynManagedResource::new_box(resource));
                    ready.notify_one();
                    std::future::pending().await
                })
            },
            std::future::pending(),
        );
        tokio::pin!(drive);
        tokio::select! { biased; _ = &mut drive => unreachable!(), () = staged.notified() => {} }
    }
    release.notify_one();
    let outcome = scope
        .wait()
        .await
        .expect("cancelled drive remains observable");
    assert!(matches!(outcome.exit(), ScopeExit::DriveCancelled));
    assert!(outcome.shutdown().as_ref().expect("receipt").is_clean());
    assert_eq!(starts.load(Ordering::Acquire), 1);
    assert_eq!(finishes.load(Ordering::Acquire), 1);
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: retained drain result is the assertion.
async fn drain_wait_can_be_cancelled_and_repeated_without_losing_receipt() {
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"))
            .expect("runtime");
    stack
        .startup()
        .expect("startup")
        .stage_resource(DynManagedResource::new_box(GateResource {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        }));
    let mut drain = stack.shutdown();
    {
        let wait = drain.wait();
        tokio::pin!(wait);
        tokio::select! { biased; _ = &mut wait => unreachable!(), () = started.notified() => {} }
    }
    release.notify_one();
    assert!(drain.wait().await.as_ref().expect("receipt").is_clean());
    assert!(
        drain
            .wait()
            .await
            .as_ref()
            .expect("same receipt")
            .is_clean()
    );
    assert!(
        drain
            .into_result()
            .expect("complete")
            .expect("receipt")
            .is_clean()
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: cached failure receipt ownership is the assertion.
async fn join_consumes_a_previously_observed_failure_receipt() {
    let mut stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"))
            .expect("runtime");
    stack
        .startup()
        .expect("registration is open")
        .stage_resource(DynManagedResource::new_box(FailingResource));
    let mut drain = stack.shutdown();
    assert!(!drain.wait().await.as_ref().expect("receipt").is_clean());
    let failures = drain.join().await.expect("cached receipt").into_failures();
    assert_eq!(failures.len(), 1);
    assert!(matches!(failures[0].kind, ShutdownFailureKind::Failed(_)));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: gate lifecycle assertions.
async fn admission_closes_synchronously_and_waits_for_last_permit() {
    let mut stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"))
            .expect("runtime");
    let (control, gate) = stack
        .startup()
        .expect("startup")
        .commit()
        .finish_with_admission("admission", Duration::from_secs(1));
    assert!(gate.try_admit().is_err());
    control.open().expect("first open");
    let permit = gate.try_admit().expect("open");
    let mut drain = stack.shutdown();
    assert!(gate.try_admit().is_err(), "closed before polling the drain");
    assert!(control.open().is_err(), "cannot reopen");
    assert!(futures::poll!(std::pin::pin!(drain.wait())).is_pending());
    drop(permit);
    assert!(drain.wait().await.as_ref().expect("receipt").is_clean());
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: critical and ordinary tasks must have distinct semantics.
async fn critical_completion_during_startup_stops_scope() {
    use rss_runtime::{LifecycleScope, ScopeExit, TaskExit};
    let mut scope = LifecycleScope::<(), (), ()>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    let outcome = scope
        .drive(
            |mut startup| {
                Box::pin(async move {
                    let (start, _) = ManagedTask::prepare("critical", Duration::from_secs(1));
                    startup.stage_task_with_token(
                        start.into_registration(|_| async { Ok(()) }).critical(),
                    );
                    std::future::pending().await
                })
            },
            std::future::pending(),
        )
        .await
        .expect("first drive");
    match outcome.exit() {
        ScopeExit::CriticalTaskExited(exit) => {
            assert_eq!(exit.name(), "critical");
            assert_eq!(exit.reason(), TaskExit::Completed);
        }
        _ => unreachable!("critical completion must stop startup"),
    }
    assert!(outcome.shutdown().as_ref().expect("receipt").is_clean());
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: cancellation after execution must retain both outcomes.
async fn cancelling_scope_cleanup_wait_keeps_original_execution_error() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut scope = LifecycleScope::<(), &'static str, &'static str>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    {
        let resource = GateResource {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        };
        let drive = scope.drive(
            move |mut startup| {
                Box::pin(async move {
                    startup.stage_resource(DynManagedResource::new_box(FailingResource));
                    startup.stage_resource(DynManagedResource::new_box(resource));
                    Err("original")
                })
            },
            std::future::pending(),
        );
        tokio::pin!(drive);
        tokio::select! { biased; _ = &mut drive => unreachable!(), () = started.notified() => {} }
    }
    assert!(futures::poll!(std::pin::pin!(scope.wait())).is_pending());
    release.notify_one();
    let outcome = scope.wait().await.expect("retry");
    assert!(matches!(
        outcome.exit(),
        ScopeExit::Completed(Err("original"))
    ));
    assert_eq!(
        outcome
            .shutdown()
            .as_ref()
            .expect("receipt")
            .failures()
            .len(),
        1
    );
}

#[tokio::test]
#[allow(clippy::expect_used, clippy::panic)] // reason: injecting a callback panic tests its safe projection.
async fn scope_reports_unsealed_execution_panic_and_invalid_reuse() {
    use rss_runtime::{LifecycleScope, ScopeExit, ScopeStateError};
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("budget");
    let mut scope = LifecycleScope::<(), (), ()>::try_new(budget).expect("runtime");
    assert!(matches!(
        scope.wait().await,
        Err(ScopeStateError::NotStarted)
    ));
    assert!(matches!(
        scope
            .drive(|_| Box::pin(async { Ok(()) }), std::future::pending())
            .await
            .expect("drive")
            .exit(),
        ScopeExit::RegistrationIncomplete(())
    ));
    assert!(matches!(
        scope
            .drive(|_| Box::pin(async { Ok(()) }), std::future::pending())
            .await,
        Err(ScopeStateError::AlreadyDriven)
    ));
    let mut scope = LifecycleScope::<(), (), ()>::try_new(budget).expect("runtime");
    assert!(matches!(
        scope
            .drive(|_| panic!("private payload"), std::future::pending())
            .await
            .expect("drive")
            .exit(),
        ScopeExit::ExecutionPanicked
    ));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: ordinary completion is not a service fault.
async fn ordinary_task_and_empty_monitor_do_not_stop_execution() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    for with_task in [false, true] {
        let mut scope = LifecycleScope::<u8, (), ()>::try_new(
            TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
        )
        .expect("runtime");
        let outcome = scope
            .drive(
                move |mut startup| {
                    Box::pin(async move {
                        if with_task {
                            let (start, _) =
                                ManagedTask::prepare("one-shot", Duration::from_secs(1));
                            let status = startup.stage_task_with_token(
                                start.into_registration(|_| async { Ok(()) }),
                            );
                            status.wait_stopped().await;
                        }
                        startup.commit().finish();
                        Ok(7)
                    })
                },
                std::future::pending(),
            )
            .await
            .expect("drive");
        assert!(matches!(outcome.exit(), ScopeExit::Completed(Ok(7))));
        assert!(outcome.shutdown().as_ref().expect("receipt").is_clean());
    }
}

#[tokio::test]
#[allow(clippy::expect_used, clippy::panic)] // reason: injecting task failures tests closed reasons.
async fn critical_terminal_reasons_remain_named_and_trigger_cleanup() {
    use rss_runtime::{LifecycleScope, ScopeExit, ShutdownErrorKind, TaskExit};
    for expected in [
        TaskExit::Cancelled,
        TaskExit::Failed(ShutdownErrorKind::Operation),
        TaskExit::Failed(ShutdownErrorKind::TaskPanicked),
        TaskExit::Failed(ShutdownErrorKind::TaskCancelled),
        TaskExit::Failed(ShutdownErrorKind::TaskUnknown),
        TaskExit::Failed(ShutdownErrorKind::DeadlineExceeded),
    ] {
        let mut scope = LifecycleScope::<(), (), ()>::try_new(
            TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
        )
        .expect("runtime");
        let outcome = scope
            .drive(
                move |mut startup| {
                    Box::pin(async move {
                        let (start, _) =
                            ManagedTask::prepare("named-critical", Duration::from_secs(1));
                        startup.stage_deferred_task_with_token(
                            start
                                .into_registration(move |token| async move {
                                    match expected {
                                        TaskExit::Cancelled => {
                                            token.cancel();
                                            Ok(())
                                        }
                                        TaskExit::Failed(ShutdownErrorKind::Operation) => Err(
                                            ShutdownError::new(std::io::Error::other("private")),
                                        ),
                                        TaskExit::Failed(ShutdownErrorKind::TaskPanicked) => {
                                            panic!("private")
                                        }
                                        TaskExit::Failed(ShutdownErrorKind::TaskCancelled) => {
                                            Err(ShutdownError::task_cancelled(
                                                std::io::Error::other("abnormal cancellation"),
                                            ))
                                        }
                                        TaskExit::Failed(ShutdownErrorKind::TaskUnknown) => {
                                            Err(ShutdownError::task_unknown(std::io::Error::other(
                                                "unknown",
                                            )))
                                        }
                                        TaskExit::Failed(ShutdownErrorKind::DeadlineExceeded) => {
                                            Err(ShutdownError::deadline_exceeded(
                                                std::io::Error::other("deadline"),
                                            ))
                                        }
                                        TaskExit::Completed => {
                                            unreachable!("completion has a separate startup test")
                                        }
                                    }
                                })
                                .critical(),
                        );
                        startup.commit().finish();
                        std::future::pending().await
                    })
                },
                std::future::pending(),
            )
            .await
            .expect("drive");
        match outcome.exit() {
            ScopeExit::CriticalTaskExited(exit) => {
                assert_eq!(exit.name(), "named-critical");
                assert_eq!(exit.reason(), expected);
            }
            _ => unreachable!("critical terminal must trigger shutdown"),
        }
        assert_eq!(
            outcome.shutdown().as_ref().expect("receipt").is_clean(),
            expected == TaskExit::Cancelled
        );
    }
}

#[tokio::test]
#[allow(clippy::expect_used, clippy::panic)] // reason: blocking failures are injected to verify the scope seam.
async fn critical_blocking_terminal_results_are_observed() {
    use rss_runtime::{LifecycleScope, ScopeExit, ShutdownErrorKind, TaskExit};
    for expected in [
        TaskExit::Completed,
        TaskExit::Failed(ShutdownErrorKind::Operation),
        TaskExit::Failed(ShutdownErrorKind::TaskPanicked),
    ] {
        let mut scope = LifecycleScope::<(), (), ()>::try_new(
            TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
        )
        .expect("runtime");
        let outcome = scope
            .drive(
                move |mut startup| {
                    Box::pin(async move {
                        startup
                            .try_stage_blocking_with_token(
                                blocking_worker_registration(
                                    "thread-critical",
                                    Duration::from_secs(1),
                                    move |_| match expected {
                                        TaskExit::Completed => Ok(()),
                                        TaskExit::Failed(ShutdownErrorKind::Operation) => Err(
                                            ShutdownError::new(std::io::Error::other("private")),
                                        ),
                                        _ => panic!("private panic payload"),
                                    },
                                )
                                .critical(),
                            )
                            .expect("thread");
                        std::future::pending().await
                    })
                },
                std::future::pending(),
            )
            .await
            .expect("drive");
        assert!(
            matches!(outcome.exit(), ScopeExit::CriticalTaskExited(exit) if exit.name() == "thread-critical" && exit.reason() == expected)
        );
        assert_eq!(
            outcome.shutdown().as_ref().expect("receipt").is_clean(),
            expected == TaskExit::Completed
        );
    }
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: ready stop wins before any construction is polled.
async fn already_ready_stop_prevents_construction_and_preserves_stop_error() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    let mut scope = LifecycleScope::<(), &'static str, &'static str>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    let outcome = scope
        .drive(|_| unreachable!("stop ready before startup"), async {
            Err("stop source failed")
        })
        .await
        .expect("drive");
    assert!(matches!(
        outcome.exit(),
        ScopeExit::StopRequested(Err("stop source failed"))
    ));
    assert!(outcome.shutdown().as_ref().expect("receipt").is_clean());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::expect_used)] // reason: barriers establish the concurrent admit/close boundary.
async fn concurrent_admit_close_counts_every_successful_lease() {
    let mut stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(2)).expect("budget"))
            .expect("runtime");
    let (control, gate) = stack
        .startup()
        .expect("startup")
        .commit()
        .finish_with_admission("race", Duration::from_secs(1));
    control.open().expect("open");
    let anchor = gate.try_admit().expect("guaranteed in-flight work");
    let barrier = Arc::new(tokio::sync::Barrier::new(17));
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let gate = gate.clone();
        let barrier = Arc::clone(&barrier);
        racers.spawn(async move {
            barrier.wait().await;
            gate.try_admit().ok()
        });
    }
    barrier.wait().await;
    control.close();
    let mut permits = Vec::new();
    while let Some(result) = racers.join_next().await {
        permits.extend(result.expect("racer joins"));
    }
    for _ in 0..16 {
        assert!(gate.try_admit().is_err());
    }
    let mut drain = stack.shutdown();
    assert!(futures::poll!(std::pin::pin!(drain.wait())).is_pending());
    drop(anchor);
    if !permits.is_empty() {
        assert!(futures::poll!(std::pin::pin!(drain.wait())).is_pending());
    }
    drop(permits);
    assert!(drain.wait().await.as_ref().expect("receipt").is_clean());
}

#[tokio::test(start_paused = true)]
#[allow(clippy::expect_used)] // reason: retained permits must report timeout rather than termination.
async fn admission_timeout_does_not_certify_permit_or_task_termination() {
    for total_first in [false, true] {
        let mut stack = ShutdownStack::try_new(
            TotalDrainBudget::new(Duration::from_secs(if total_first { 1 } else { 2 }))
                .expect("budget"),
        )
        .expect("runtime");
        let (control, gate) = stack
            .startup()
            .expect("startup")
            .commit()
            .finish_with_admission(
                "held-permit",
                Duration::from_millis(if total_first { 2000 } else { 100 }),
            );
        control.open().expect("open");
        let permit = gate.try_admit().expect("permit");
        let mut drain = stack.shutdown();
        let receipt = drain.wait().await.as_ref().expect("receipt");
        assert!(!receipt.is_clean());
        assert!(matches!(
            receipt.failures()[0].kind,
            ShutdownFailureKind::TimedOut(_) | ShutdownFailureKind::BudgetExhausted
        ));
        assert!(gate.try_admit().is_err());
        drop(permit);
        assert!(
            !drain
                .wait()
                .await
                .as_ref()
                .expect("sticky failure")
                .is_clean()
        );
    }
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: the event sequence proves real dependency access and task destruction.
async fn scope_admission_and_critical_tasks_preserve_deferred_dependency_order() {
    use rss_runtime::{AdmissionGate, LifecycleScope, ScopeExit};
    let events = Arc::new(Mutex::new(Vec::new()));
    let admitted = Arc::new(tokio::sync::Notify::new());
    let mut scope = LifecycleScope::<(), (), ()>::try_new(
        TotalDrainBudget::new(Duration::from_secs(2)).expect("budget"),
    )
    .expect("runtime");
    let recorded = Arc::clone(&events);
    let ready = Arc::clone(&admitted);
    let outcome = scope
        .drive(
            move |mut startup| {
                Box::pin(async move {
                    startup.stage_resource(DynManagedResource::new_box(RecordingResource {
                        name: "dependency-closed",
                        events: Arc::clone(&recorded),
                    }));
                    let (send_work_gate, work_gate) =
                        tokio::sync::oneshot::channel::<AdmissionGate>();
                    let (send_stop_gate, stop_gate) =
                        tokio::sync::oneshot::channel::<AdmissionGate>();
                    let release = Arc::new(tokio::sync::Notify::new());
                    let worker_release = Arc::clone(&release);
                    let worker_events = Arc::clone(&recorded);
                    let (worker, _) =
                        ManagedTask::prepare("deferred-worker", Duration::from_secs(1));
                    startup.stage_deferred_task_with_token(
                        worker
                            .into_registration(move |token| async move {
                                struct OnDrop(Arc<Mutex<Vec<&'static str>>>);
                                impl Drop for OnDrop {
                                    fn drop(&mut self) {
                                        self.0
                                            .lock()
                                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                                            .push("worker-destroyed");
                                    }
                                }
                                let _drop = OnDrop(Arc::clone(&worker_events));
                                let gate = work_gate.await.expect("gate");
                                let permit = gate.try_admit().expect("open gate");
                                ready.notify_one();
                                worker_release.notified().await;
                                assert!(
                                    !token.is_cancelled(),
                                    "deferred worker stays usable during admission drain"
                                );
                                {
                                    let mut events = worker_events
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    assert!(!events.contains(&"dependency-closed"));
                                    events.push("inflight-used-dependency");
                                }
                                drop(permit);
                                token.cancelled().await;
                                Ok(())
                            })
                            .critical(),
                    );
                    let (stopper, _) = ManagedTask::prepare("ingress", Duration::from_secs(1));
                    startup.stage_task_with_token(
                        stopper
                            .into_registration(move |token| async move {
                                let gate = stop_gate.await.expect("gate");
                                token.cancelled().await;
                                assert!(
                                    gate.try_admit().is_err(),
                                    "pre-close must precede root broadcast"
                                );
                                recorded
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .push("admission-closed");
                                release.notify_one();
                                Ok(())
                            })
                            .critical(),
                    );
                    let (control, gate) = startup
                        .commit()
                        .finish_with_admission("inflight", Duration::from_secs(1));
                    control.open().expect("product decides open");
                    assert!(send_work_gate.send(gate.clone()).is_ok());
                    assert!(send_stop_gate.send(gate).is_ok());
                    // Retain control for the complete running phase.
                    let _control = control;
                    std::future::pending().await
                })
            },
            async {
                admitted.notified().await;
                Ok(())
            },
        )
        .await
        .expect("drive");
    assert!(matches!(outcome.exit(), ScopeExit::StopRequested(Ok(()))));
    assert!(outcome.shutdown().as_ref().expect("receipt").is_clean());
    assert_eq!(
        *events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [
            "admission-closed",
            "inflight-used-dependency",
            "worker-destroyed",
            "dependency-closed"
        ]
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: finite channel release bounds the intentionally non-cooperative thread.
async fn timed_out_blocking_runner_is_not_reported_as_terminated() {
    let (release, wait_release) = std::sync::mpsc::channel::<()>();
    let (started, start_received) = tokio::sync::oneshot::channel();
    let (finished, finish_received) = tokio::sync::oneshot::channel();
    let mut stack =
        ShutdownStack::try_new(TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"))
            .expect("runtime");
    let status = stack
        .startup()
        .expect("startup")
        .try_stage_blocking_with_token(blocking_worker_registration(
            "non-cooperative",
            Duration::from_millis(10),
            move |_| {
                assert!(started.send(()).is_ok());
                // Deliberately ignore lifecycle cancellation. This test itself has a finite bound.
                wait_release
                    .recv_timeout(Duration::from_secs(2))
                    .expect("test releases thread");
                let _ = finished.send(());
                Ok(())
            },
        ))
        .expect("thread starts");
    start_received.await.expect("running");
    let mut drain = stack.shutdown();
    let receipt = drain.wait().await.as_ref().expect("receipt");
    assert!(matches!(
        receipt.failures()[0].kind,
        ShutdownFailureKind::TimedOut(_)
    ));
    assert_eq!(
        status.current(),
        TaskState::Running,
        "timeout did not terminate the runner"
    );
    release.send(()).expect("release thread");
    finish_received.await.expect("finite test thread ends");
    status.wait_stopped().await;
    assert!(
        !drain
            .wait()
            .await
            .as_ref()
            .expect("sticky timeout")
            .is_clean()
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: an unpolled async drive must neither construct resources nor consume the scope.
async fn unpolled_drive_leaves_scope_ready_without_constructing_resources() {
    use rss_runtime::{LifecycleScope, ScopeExit, ScopeStateError};
    let mut scope = LifecycleScope::<(), (), ()>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    drop(scope.drive(
        |_| unreachable!("unpolled callback cannot execute"),
        std::future::pending(),
    ));
    assert!(matches!(
        scope.wait().await,
        Err(ScopeStateError::NotStarted)
    ));
    let outcome = scope
        .drive(
            |startup| {
                Box::pin(async move {
                    startup.commit().finish();
                    Ok(())
                })
            },
            std::future::pending(),
        )
        .await
        .expect("first polled drive");
    assert!(matches!(outcome.exit(), ScopeExit::Completed(Ok(()))));
    assert_eq!(
        outcome
            .shutdown()
            .as_ref()
            .expect("receipt")
            .registered_resources(),
        0
    );
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: successful values must survive registration protocol failures.
async fn incomplete_registration_preserves_non_clone_execution_value() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    struct Value(u8);
    let mut scope = LifecycleScope::<Value, (), ()>::try_new(
        TotalDrainBudget::new(Duration::from_secs(1)).expect("budget"),
    )
    .expect("runtime");
    scope
        .drive(
            |_| Box::pin(async { Ok(Value(73)) }),
            std::future::pending(),
        )
        .await
        .expect("drive");
    let (exit, shutdown) = scope.into_outcome().expect("retained").into_parts();
    assert!(matches!(exit, ScopeExit::RegistrationIncomplete(Value(73))));
    assert!(shutdown.expect("receipt").is_clean());
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: distinct source errors are preserved without merging or erasing them.
async fn execution_and_stop_errors_keep_independent_types() {
    use rss_runtime::{LifecycleScope, ScopeExit};
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("budget");
    let mut scope = LifecycleScope::<(), &'static str, u16>::try_new(budget).expect("runtime");
    assert!(matches!(
        scope
            .drive(
                |_| Box::pin(async { Err("execution") }),
                std::future::pending()
            )
            .await
            .expect("drive")
            .exit(),
        ScopeExit::Completed(Err("execution"))
    ));
    let mut scope = LifecycleScope::<(), &'static str, u16>::try_new(budget).expect("runtime");
    assert!(matches!(
        scope
            .drive(|_| unreachable!("stop ready"), async { Err(403) })
            .await
            .expect("drive")
            .exit(),
        ScopeExit::StopRequested(Err(403))
    ));
}

#[tokio::test]
#[allow(clippy::expect_used)] // reason: the bare stack monitor must observe future same-owner registrations.
async fn bare_stack_critical_monitor_observes_registration_and_empty_closure() {
    use rss_runtime::TaskExit;
    let budget = TotalDrainBudget::new(Duration::from_secs(1)).expect("budget");
    let mut stack = ShutdownStack::try_new(budget).expect("runtime");
    let monitor = stack.critical_tasks();
    assert!(futures::poll!(std::pin::pin!(monitor.wait())).is_pending());
    let (start, _) = ManagedTask::prepare("bare-critical", Duration::from_secs(1));
    stack
        .startup()
        .expect("startup")
        .stage_task_with_token(start.into_registration(|_| async { Ok(()) }).critical());
    let exit = monitor.wait().await.expect("critical exit");
    assert_eq!(exit.name(), "bare-critical");
    assert_eq!(exit.reason(), TaskExit::Completed);
    assert!(stack.shutdown().join().await.expect("receipt").is_clean());
    assert_eq!(monitor.wait().await.expect("sticky terminal"), exit);
    let empty = ShutdownStack::try_new(budget).expect("runtime");
    let monitor = empty.critical_tasks();
    drop(empty);
    assert!(monitor.wait().await.is_none());
}
