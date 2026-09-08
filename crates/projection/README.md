# rss-projection

Provider-neutral, single-source projection execution and recovery. This package owns the event,
source, execution, bounded runner and explicit cross-system at-least-once contracts. It has no
RSS message-envelope, MessageRoute, global DI or product read-model dependency.

```rust
use rss_projection::{BatchLimit, Event, Position, ProjectionScope, RunLimit, SourceScope};
use rss_request_context::TenantId;
# fn example() -> Result<(), Box<dyn std::error::Error>> {
let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
let source = SourceScope::new(tenant, "orders")?;
let scope = ProjectionScope::new(source.clone(), "totals", "v1")?;
let event = Event::new(source, Position::new(0)?, "fact-1", vec![1])?;
let limit = RunLimit::new(BatchLimit::new(100)?, 10_000)?;
# Ok(())
# }
```

## Execution contracts

- `Source` returns a committed, immutable prefix in strictly increasing source-local position
  order. Positions are not comparable across tenants/sources. The runner validates the complete
  fetched batch before admitting effects. `None` precedes the first event; position zero is legal.
- `Execution` represents a provider-bound generation/session and exposes its verified
  `DefinitionIdentity`. Providers must bind this identity before granting authority and verify
  it on checkpoint reads and writes, before effects. `run` loads its checkpoint, reads
  bounded batches and settles each event. No task is spawned and no implicit retry/takeover occurs.
- `Control` uses a required caller-injected monotonic `Timer`, absolute deadline and cancellation
  token. The total event budget includes duplicates and filtered events; phases never reset time.
- `Report.position` includes only acknowledged progress. `CommitUnknown` and `RollbackFailed`
  require reloading durable state with the same fact identity. Cancellation of a mutating future
  cannot prove the absence of effects.
- `AtLeastOnce` composes `ExternalCheckpoint` and an idempotent `ExternalTarget`. A successful
  remote effect followed by checkpoint failure is replayed. Remote deduplication keys must include
  tenant, source, projection, generation and fact ID, with conflict detection for changed bytes.
  `ExternalTarget::apply` receives the session definition. The target must bind it immutably to
  the generation and reject a different definition, not add it to the deduplication key.
  Remote conditional-write/fencing is the application's responsibility: local checkpoint CAS
  cannot stop an already admitted remote write. This is not an atomic cross-system transaction.

`ReplayBound::Through` is an immutable generation snapshot, including the empty-source case.
A specified initial checkpoint means **after** that position; the application must provide the
matching read-model baseline and its complete processed fact receipt set.
`GenerationStart::after(position, receipts)` rejects missing receipts, future coordinates and
conflicting facts; a provider verifies source binding and persists receipts with initialization.
The snapshot producer is responsible for completeness, including filtered facts. A new generation gets separate read-model keys; product code decides
when to switch readers. There is no in-place reset, cleanup, active/shadow registry or DLQ policy.

`DefinitionIdentity::new([u8; 32])` is an opaque caller-declared definition/schema fingerprint.
It is a generation attribute, not another scope key. The application supplies the same value on
initialization and direct takeover; a mismatch is `Conflict` and grants no new execution right.
There is no default, implicit adoption or automatic hashing of SQL, closures or build artifacts.
The fingerprint checks declaration equality, not the truth of the actual mapping. A changed
mapping uses a new generation. A rebuilt input journal uses a new `SourceScope` identity even
when its encoding is unchanged; worker epoch and position never substitute for source lineage.

Names are 1–128 ASCII alphanumeric/`_.:-` bytes. Payloads are encoded application facts, at most
1 MiB; event type/schema information belongs in those bytes. Fingerprints use the exact bytes,
not position, so retries at later coordinates remain the same fact. Providers must preserve the
source contract, and effects must not silently reinterpret an existing generation's definition.

## Local execution observation

`run` synchronously prepares a `#[must_use] Run`; awaiting it produces the final
`#[must_use] Report`. `report.into_result()` propagates any failure. Preparation captures the
session identity and allocates local state, but provider I/O starts only when the future is polled.
Every invocation has its own read-only handle; even two runs on the same session are distinct.

```rust
use rss_projection::{run, Control, Execution, ObservationStatus, RunLimit, Source, Timer};
# async fn example<S: Source, E: Execution, T: Timer>(
# source: &S, session: &E, control: &Control<'_, T>, limit: RunLimit,
# ) {
let work = run(source, session, control, limit);
let observation = work.observation();
assert_eq!(observation.read(), ObservationStatus::Pending);
// Clone the handle into a caller-owned task to read while this invocation executes.
let report = work.await;
assert_eq!(observation.read(), ObservationStatus::Stopped(report.clone()));
// Export metrics or diagnostics directly from the report under application policy.
# }
```

- `Pending` means no checkpoint has been acknowledged, including before first poll.
  `Running` with `position: None` means a checkpoint *was* acknowledged before the first event.
- `Running` publishes one consistent local snapshot after checkpoint loading and each successful
  settlement: position, applied, duplicates and filtered. Counts describe this invocation only.
  Unknown commits never advance observation. The final `Stopped(Report)` is exactly the returned
  report and remains terminal, including for cancellation, deadline, fencing and other failures.
- Dropping the run or its future (including task abort and panic unwinding) before a report
  latches `Unavailable`, retaining optional last-confirmed progress. This does not prove rollback,
  the absence of effects, or termination of remote work. Destructors cannot observe a leaked
  future or process termination; retained snapshot values are historical, not live references.
- The handle exposes only reads and the bound scope/definition. Equality identifies the same
  invocation, not the same tenant or generation. Handles grant no authentication, control or write
  authority; the application owns their distribution. `Running` is not a lease or readiness check.
- Only the execution future publishes; no user callback, background task, notification queue or
  additional provider query is introduced. Owned snapshot reads cannot retain a lock that blocks
  publication. Each publication has allocation/synchronization cost; this is not hard realtime.
- `Source::high_water` and `Execution::checkpoint` remain separate queries, not an atomic snapshot.
  Source-local coordinate differences are not necessarily counts of pending events.

For APIs requiring `Future`, import `std::future::IntoFuture` and pass `work.into_future()`.
The former post-run `Observer`/`Report::observe` API is removed; consume the report directly.
There is no parallel observed/unobserved execution API or compatibility wrapper.

## Extraction and compatibility

Extracted from baseline `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`:
`crates/consistency/src/projection.rs`, `crates/eventexec/src/projection.rs`, and
`crates/eventexec/tests/projection_worker_restart.rs`. Only ordering, recovery, error and bounded
execution semantics survive. The former separate apply/checkpoint harness and product bindings
are removed. The new public owner has no aliases or legacy schema/data import path.

Version 0.1.0 is experimental. Defaults are empty; there are no alternate consistency features.
See `rss-projection-postgres` for the atomic PostgreSQL implementation and executable example.


最小可运行使用流程及独立源码/候选 artifact 命令见 [rss-examples](../examples/README.md)。
