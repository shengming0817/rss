# rss-runtime

`rss-runtime` is the provider-neutral owner of managed tasks, cancellation-safe startup and launch
transactions, dedicated-thread registration, and bounded reverse-order shutdown.

It does not install process signals or panic hooks, bind listeners, parse configuration, own health
registries, or model assemblies and providers.

The stack owns its cancellation root. Resources receive only a short-lived child token while they
are being registered, and every shutdown has one positive total budget:

```rust
use std::time::Duration;

use rss_runtime::{ManagedTask, ShutdownStack, TotalDrainBudget};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let budget = TotalDrainBudget::new(Duration::from_secs(30))?;
let mut stack = ShutdownStack::try_new(budget)?;

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

let receipt = stack.shutdown().await?;
if !receipt.is_clean() {
    // The receipt is an in-process observation, not persisted evidence.
    for failure in receipt.failures() {
        eprintln!("{failure}");
    }
}
# Ok(())
# }
```

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
