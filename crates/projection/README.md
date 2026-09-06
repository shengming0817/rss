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
- `Execution` represents a provider-bound generation/session. `run` loads its checkpoint, reads
  bounded batches and settles each event. No task is spawned and no implicit retry/takeover occurs.
- `Control` uses a required caller-injected monotonic `Timer`, absolute deadline and cancellation
  token. The total event budget includes duplicates and filtered events; phases never reset time.
- `Report.position` includes only acknowledged progress. `CommitUnknown` and `RollbackFailed`
  require reloading durable state with the same fact identity. Cancellation of a mutating future
  cannot prove the absence of effects.
- `AtLeastOnce` composes `ExternalCheckpoint` and an idempotent `ExternalTarget`. A successful
  remote effect followed by checkpoint failure is replayed. Remote deduplication keys must include
  tenant, source, projection, generation and fact ID, with conflict detection for changed bytes.
  Remote conditional-write/fencing is the application's responsibility: local checkpoint CAS
  cannot stop an already admitted remote write. This is not an atomic cross-system transaction.

`ReplayBound::Through` is an immutable generation snapshot, including the empty-source case.
A specified initial checkpoint means **after** that position; the application must provide the
matching read-model baseline and its complete processed fact receipt set.
`GenerationStart::after(position, receipts)` rejects missing receipts, future coordinates and
conflicting facts; a provider verifies source binding and persists receipts with initialization.
The snapshot producer is responsible for completeness, including filtered facts. A new generation gets separate read-model keys; product code decides
when to switch readers. There is no in-place reset, cleanup, active/shadow registry or DLQ policy.

Names are 1–128 ASCII alphanumeric/`_.:-` bytes. Payloads are encoded application facts, at most
1 MiB; event type/schema information belongs in those bytes. Fingerprints use the exact bytes,
not position, so retries at later coordinates remain the same fact. Providers must preserve the
source contract, and effects must not silently reinterpret an existing generation's definition.

`run` returns a `#[must_use] Report`; `into_result` propagates any failure. Only after receiving it,
the caller may explicitly use `report.observe(&observer)` to emit aggregate closed outcomes and
stop reasons. This callback is outside the execution budget; even if it fails, the caller already
owns its report. No arbitrary observer executes inside the bounded worker. Tenant IDs and names
are identity values, not authentication evidence.

## Extraction and compatibility

Extracted from baseline `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`:
`crates/consistency/src/projection.rs`, `crates/eventexec/src/projection.rs`, and
`crates/eventexec/tests/projection_worker_restart.rs`. Only ordering, recovery, error and bounded
execution semantics survive. The former separate apply/checkpoint harness and product bindings
are removed. The new public owner has no aliases or legacy schema/data import path.

Version 0.1.0 is experimental. Defaults are empty; there are no alternate consistency features.
See `rss-projection-postgres` for the atomic PostgreSQL implementation and executable example.
