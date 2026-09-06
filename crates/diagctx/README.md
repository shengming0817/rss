# rss-diag-context

`rss-diag-context` provides validated `CorrelationId` and owned `DiagnosticCtx` values. The default
API has no Tokio dependency: parse at a trust boundary and pass the context explicitly.

```rust
use rss_diag_context::{CorrelationId, DiagnosticCtx};
let ctx = DiagnosticCtx::new(CorrelationId::parse("request-42")?);
assert_eq!(ctx.correlation().as_str(), "request-42");
# Ok::<(), rss_diag_context::CorrelationIdError>(())
```

Opt into ambient asynchronous propagation with the `task-local` feature:

```toml
[dependencies]
rss-diag-context = { version = "0.1", features = ["task-local"] }
```

`scope`, `current`, and `correlation` are available only with this feature. Task scoping uses Tokio's
existing task-local mechanism; it does not create a runtime or spawn tasks on the caller's behalf.

```rust
# #[cfg(feature = "task-local")]
# {
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
# }
```

Ambient context does not cross `tokio::spawn` automatically. Capture it before spawning and bind
the snapshot inside the child task when the diagnostic chain must continue. A `Send` input future
produces a spawnable scoped future; local executors may also scope a non-`Send` future:

```no_run
# #[cfg(feature = "task-local")]
# {
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
# }
```

Correlation context is observability data, not an identity, tenant, authentication, or
authorization source. Missing context returns `None` and must only omit diagnostic enrichment; it
must never change an authorization outcome. RSS enforces that rule for its authorization owners,
but the public type cannot prevent an external application from deliberately misusing a diagnostic
identifier.

Cargo publication eligibility and a passing same-revision package proof establish candidate
eligibility only. RC approval applies to an exact revision and archive digest under the repository's
`RELEASES.md`; it does not publish the package. Versioned notes live in the root `CHANGELOG.md`.

The async scope shape follows Tokio task-local scoping and tracing's explicit propagation model:
[Tokio task-local source](https://github.com/tokio-rs/tokio/blob/be8ee45b3fc2d107174e586141b1cb12c93e2ddf/tokio/src/task/task_local.rs),
[tracing instrumentation source](https://github.com/tokio-rs/tracing/blob/2d55f6faf9be83e7e4634129fb96813241aac2b8/tracing/src/instrument.rs).

Licensed under the MIT License.
