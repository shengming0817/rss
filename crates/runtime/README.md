# rss-runtime

`rss-runtime` is the provider-neutral owner of managed tasks, cancellation-safe startup and launch
transactions, dedicated-thread registration, and bounded reverse-order shutdown.

It does not install process signals or panic hooks, bind listeners, parse configuration, own health
registries, or model assemblies and providers.

The stack owns its cancellation root. Resources receive only a short-lived child token while they
are being registered, and every shutdown has one positive total budget. The `timer` below is the
host-provided `Arc<impl rss_request_context::ExecutionTimer>`:

```rust
use std::time::Duration;

use rss_runtime::{ManagedTask, ShutdownStack, TotalDrainBudget};

# async fn example(timer: std::sync::Arc<impl rss_request_context::ExecutionTimer + 'static>) -> Result<(), Box<dyn std::error::Error>> {
let budget = TotalDrainBudget::new(Duration::from_secs(30))?;
let mut stack = ShutdownStack::try_new(budget, timer)?;

let (start, status) = ManagedTask::prepare("relay", Duration::from_secs(5));
let registration = start.into_registration(|token| async move {
    token.cancelled().await;
    Ok(())
});
let mut startup = stack.startup()?;
let same_source_status = startup.stage_task_with_token(registration);
assert_eq!(status.current(), same_source_status.current());
let mut launch = startup.commit();
// Register launch resources immediately with `launch.stage_*`.
launch.finish();

let receipt = stack.shutdown().join().await?;
if !receipt.is_clean() {
    // The receipt is an in-process observation, not persisted evidence.
    for failure in receipt.failures() {
        eprintln!("{failure}");
    }
}
# Ok(())
# }
```

`ShutdownStack::try_new` and `LifecycleScope::try_new` require an active Tokio runtime and an
explicit `Arc<impl rss_request_context::ExecutionTimer + 'static>`. A missing runtime returns
`RuntimeUnavailable` before resource registration; the timer is a mandatory constructor capability.
All total and per-resource shutdown deadlines use that timer's monotonic domain. Unrepresentable
cutoffs fail closed as exhausted budgets. No hidden Tokio timer probe or timer fallback remains.

A timerless Tokio runtime is supported when the host supplies a valid independent timer. The host
owns timer/runtime assembly and must keep both driven through cleanup; RSS owns only the retained
timer capability and its shutdown arbitration. A Tokio-backed host timer requires its own enabled
time driver. Registered resources retain their own timer prerequisites.
Migration: pass the host timer to both constructors; the former one-argument
constructors and `TimeDriverUnavailable` are removed. Timer admission performs no panic probing,
including in `panic = "abort"` builds. Isolation of actual resource/callback panics still depends on
Rust unwinding and the host's panic policy.

Standalone `ManagedTask::shutdown` and `ManagedBlockingWorker::shutdown` retain their join handles
when a waiter is cancelled. Concurrent/repeated calls return the same actual join result, including
errors and panics; thread success includes thread-local destruction. A task status is not a join
receipt. Dropping the task owner aborts its task; dropping a thread owner requests cancellation but
cannot forcibly stop the thread. These standalone shutdown methods do not impose their own timeout.
Migration: a second shutdown no longer clears a failure, and cancelling only a shutdown waiter no
longer aborts an independently retained managed task.

There are no default features. The crate deliberately has no compatibility API for former
lifecycle ownership paths.

Cancellation of a shutdown waiter preserves the submitted drain only while the Tokio runtime that
created the stack remains driven. Dropping the stack always broadcasts cancellation synchronously;
if that runtime has already stopped, asynchronous resource flushing cannot be completed. Likewise,
`join_owned_task` does not make an already-started Tokio blocking closure abortable, so it is only
for one-shot operations that enforce their own finite bound.

Task/resource panic control flow is isolated into closed error kinds, but `catch_unwind` does not
suppress Rust's process-wide panic hook. Applications whose panic payloads may contain sensitive
data remain responsible for installing their process-owned redacting hook before starting work.

Shutdown failure observations publish the closed `ShutdownErrorKind` label and a fixed event message.
They do not format the provider source or include a redundant free-text error field.

## Local scope, critical tasks and admission

`LifecycleScope::drive` lends its startup transaction **by value** to one callback. The callback
constructs resources, immediately stages each completed resource before its next cancellable await,
commits startup, seals launch and runs. The transaction itself does not roll back on Drop. The scope
owns cleanup on callback failure, panic, stop or drive cancellation; cleanup does not undo external
business effects. Successfully returning without sealing registration is `RegistrationIncomplete(T)`, retaining the original value.

```rust
use std::time::Duration;
use rss_runtime::{AdmissionGate, LifecycleScope, ManagedTask, ScopeExit, ShutdownError, TotalDrainBudget};

# async fn example(timer: std::sync::Arc<impl rss_request_context::ExecutionTimer + 'static>) -> Result<(), Box<dyn std::error::Error>> {
let mut scope = LifecycleScope::<(), ShutdownError, tokio::sync::oneshot::error::RecvError>::try_new(
    TotalDrainBudget::new(Duration::from_secs(10))?,
    timer,
)?;
// This example requests stop when one request is in flight. A product supplies its own source.
let (request_stop, stop) = tokio::sync::oneshot::channel();
let outcome = scope.drive(|mut startup| Box::pin(async move {
    let (worker, _) = ManagedTask::prepare("dependency-worker", Duration::from_secs(2));
    let dependency = startup.stage_deferred_task_with_token(worker.into_registration(|token| async move {
        token.cancelled().await;
        Ok(())
    }).critical());
    let (send_gate, receive_gate) = tokio::sync::oneshot::channel::<AdmissionGate>();
    let (ingress, _) = ManagedTask::prepare("inflight-request", Duration::from_secs(2));
    let mut launch = startup.commit();
    launch.stage_task_with_token(ingress.into_registration(move |token| async move {
        let gate = receive_gate.await.map_err(ShutdownError::new)?;
        let permit = gate.try_admit().map_err(ShutdownError::new)?;
        let _ = request_stop.send(());
        token.cancelled().await;
        assert!(gate.try_admit().is_err());
        assert!(dependency.is_running()); // Deferred dependency is still available during drain.
        // Finish current dependency access before releasing the in-flight lease.
        drop(permit);
        Ok(())
    }).critical());
    let (control, gate) = launch.finish_with_admission("inflight", Duration::from_secs(2));
    control.open().map_err(ShutdownError::new)?; // Product prerequisites are satisfied.
    assert!(send_gate.send(gate).is_ok());
    let _control = control; // Keep open authority throughout the running phase.
    std::future::pending().await
}), stop).await?;
assert!(matches!(outcome.exit(), ScopeExit::StopRequested(Ok(()))));
assert!(outcome.shutdown().as_ref().map_err(|error| *error)?.is_clean());
# Ok(())
# }
```

`drive` and `wait` borrow the scope. Cancelling either wait preserves already-observed execution
results and cleanup failures; retain the scope and call `wait` again. `into_outcome` transfers a
completed result without requiring Clone. Dropping the entire scope abandons result delivery, not
cleanup. An unpolled drive has not started; `wait` then reports `NotStarted`. A second drive reports
`AlreadyDriven`. Execution and stop-source errors have independent types. Generic application results/errors are never automatically formatted or logged.

Only registrations explicitly marked `.critical()` participate in a scope's early-exit monitor.
The monitor observes tasks staged during startup as well as launch and running; it spawns no tasks.
It preserves the registration's name and closed `TaskExit`. A ready stop wins over critical exit,
which wins over execution in the same select poll. Ordinary one-shot success, Saga Yielded or paused
compensation must not be marked critical merely because they are managed. Bare `ShutdownStack`
consumers can obtain its read-only `critical_tasks()` monitor before registration and select on
`monitor.wait()`. It observes only same-stack registrations, including later additions, without
spawning tasks. It returns None only when the stack publisher closes with no critical tasks; a live
empty set stays pending. Bare consumers decide whether an observed exit was expected;
`LifecycleScope` applies the early-exit policy automatically using the same monitor.
`TaskStatus` describes the runner's return/panic/cancellation observation, not business readiness or
thread-local destruction. The resource owner still cancels and joins the task/thread at shutdown.

Admission starts unopened. `finish_with_admission` seals registration and installs the drain last;
only then is open authority returned. Closing is permanent, and dropping control closes the gate.
The close lock serializes token minting with closure; Tokio TaskTracker's `close` alone is not an
admission gate. On shutdown, admission closes synchronously before the normal cancellation broadcast.
The last registered admission resource waits for permits before dependent resources close. Work that
must remain usable during this wait uses deferred registration. Hold the move-only permit for the
whole dependency-access lifetime, including any child work; releasing a count cannot terminate a
future. Timeout/BudgetExhausted remains a failure even if a permit is released later. After timeout,
the bounded shutdown driver may proceed to close dependencies while unfinished work still exists.
Non-cooperative synchronous code and a stopped originating runtime cannot be forcibly cleaned up.

A product can implement `rss_platform::HostView` with this gate and a local newtype implementing
`rss_platform::AdmissionPermit`. The runtime crate does not depend on platform. Authentication,
tenant/device authorization, readiness and cross-process DR admission remain product responsibilities;
permit drain is not evidence that a product is stopped.

## API replacement

`ShutdownStack::shutdown` now synchronously returns `ShutdownDrain`; replace `stack.shutdown().await`
with `stack.shutdown().join().await` for an owned result. Cancelling `join` abandons the receipt,
while submitted cleanup continues. To recover the receipt after cancelling a wait, retain the drain
and use `drain.wait().await`; `into_result` moves out its cached completed result. No compatibility
await adapter or alternate shutdown entrypoint is provided. Stack, scope and Drop all use the same internal resource-transfer path.

ref: tokio-rs/tokio tokio-util/src/task/task_tracker.rs@tokio-util-0.7.16
ref: tokio-rs/tokio tokio/src/runtime/task/join.rs@tokio-1.53.1
