# rss-diag-context

`rss-diag-context` propagates a validated correlation ID through an asynchronous task scope. Its
API is intentionally small: parse at a trust boundary, bind one `DiagnosticCtx`, and read the
ambient value where diagnostic metadata is emitted.

```rust
use rss_diag_context::{CorrelationId, DiagnosticCtx, correlation, current, scope};

# async fn example() -> Result<(), rss_diag_context::CorrelationIdError> {
assert!(current().is_none());
assert!(correlation().is_none());

let id = CorrelationId::parse("request-42")?;
assert_eq!(id.as_str(), "request-42");
let seen = scope(DiagnosticCtx::new(id), async {
    assert_eq!(current().unwrap().correlation().as_str(), "request-42");
    correlation().unwrap()
}).await;
assert_eq!(seen.as_str(), "request-42");
# Ok(())
# }
```

Ambient context does not cross `tokio::spawn` automatically. Capture it before spawning and bind
the snapshot inside the child task when the diagnostic chain must continue. A `Send` input future
produces a spawnable scoped future; local executors may also scope a non-`Send` future:

```no_run
use rss_diag_context::{current, scope};

# async fn emit_metadata() {}
# async fn example() -> Result<(), tokio::task::JoinError> {
if let Some(snapshot) = current() {
    tokio::spawn(scope(snapshot, async { emit_metadata().await })).await?;
} else {
    tokio::spawn(async { emit_metadata().await }).await?;
}
# Ok(())
# }
```

Correlation context is observability data, not an identity, tenant, authentication, or
authorization source. Missing context returns `None` and must only omit diagnostic enrichment; it
must never change an authorization outcome. RSS enforces that rule for its authorization owners,
but the public type cannot prevent an external application from deliberately misusing a diagnostic
identifier.

Cargo publication eligibility and a passing package proof make this package a release candidate;
they are not an RC, a registry upload, or publication approval.

The async scope shape follows Tokio task-local scoping and tracing's explicit propagation model:
[Tokio task-local source](https://github.com/tokio-rs/tokio/blob/be8ee45b3fc2d107174e586141b1cb12c93e2ddf/tokio/src/task/task_local.rs),
[tracing instrumentation source](https://github.com/tokio-rs/tracing/blob/2d55f6faf9be83e7e4634129fb96813241aac2b8/tracing/src/instrument.rs).

Licensed under the MIT License.
