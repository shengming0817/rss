# rss-observation-postgres

PostgreSQL 16 observation persistence, with one atomic batch transaction and one Rust integrity
state machine. Adopt a dedicated, already configured SQLx `PgPool` with `PgStore::new(pool, clock,
deadline)`. The host owns TLS (VerifyFull), credentials and authentication configuration. The store
owns operation settlement and closing the adopted pool; `close` closes its clones too. No pool,
connection or arbitrary SQL callback is exposed by the observation API.

## Installation and privileges

An external migrator executes `MIGRATION_SQL` using a dedicated NOSUPERUSER NOBYPASSRLS schema owner.
Runtime receives schema USAGE, table SELECT, and function EXECUTE, without table DML, TRUNCATE,
owner-role membership, CREATE or RLS bypass. Tables use FORCE RLS and transaction-local tenant
scope. Functions have fixed search paths and revoke PUBLIC execute. The runtime is trusted
companion infrastructure; a tenant GUC is isolation inside that boundary, not authentication of
an attacker who already possesses its database credentials.

```sql
-- Run as the external owner after installing MIGRATION_SQL; provision roles separately.
GRANT USAGE ON SCHEMA rss_observation TO observation_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_observation TO observation_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation TO observation_runtime;
```

Runtime admission accepts only storage revision 2. `MIGRATION_SQL` installs the current schema;
`UPGRADE_SQL` performs the one-way revision 1 → 2 conversion. Stop writers and execute the upgrade
as the dedicated schema owner, outside an enclosing transaction (the SQL owns BEGIN/COMMIT).
It takes exclusive locks, temporarily removes FORCE RLS for owner-only batch backfill, restores it,
and commits the new journal with unchanged raw reports, fingerprints, receipts and decisions.
On any error, the external migrator must ROLLBACK/discard its connection before retrying. Grant
runtime SELECT on the new `rss_observation.journals` table after upgrading.

Historical applicable rows are assigned positions in canonical stream/sequence order; ordering
between streams has no historical fact-authority meaning. There were no prior journal checkpoints:
initialize a fresh projection from its beginning, never reuse an unrelated source's checkpoint.
No revision-1 runtime, dual reads, old API aliases, data deletion or historical device-command
import is provided. Future persisted changes require an explicit upgrade and admission contract.

## Transaction and recovery

`activate` locks the object lifecycle and atomically creates a never-used stream epoch with policy
and initial state. Registration switches prevent old sources from writing; old immutable receipts
remain readable. The expected revision is global to the object's lifecycle, not its producer
sequence. Exact activation replay returns its original revision without reactivating an old epoch.

`receive` first looks up exact scoped batch identity. For a new batch it locks object registration
and stream, rechecks duplicates after waiting, computes the core decision and commits raw canonical
bytes, fingerprint, received time, policy, receipt/decision and the stream update together. One
`batches` row is both the receipt and complete recoverable representation. Its core-computed applicable
flag admits only validated snapshots/deltas. The same transaction assigns an independent positive
`log_position` under a per-tenant allocator row lock. Lock order is object → stream → tenant
journal, held to settlement; no higher position can become visible while a lower position could
still commit. Rollback rolls back allocation, and exact retry never allocates again. Exhaustion
rejects every new report; exact replay still returns the original receipt. The batch itself is the immutable journal entry; there is
no copied event payload, outbox, publication state or background worker. SQL functions enforce expected
revision and atomic writes; only the Rust core owns snapshot/delta decisions.

Only COMMIT acknowledgment or exact durable readback returns success. Missing ACK closes the
connection, then a fresh tenant-scoped transaction validates the immutable batch and recorded
transition, without comparing the current mutable cursor. Read failure or absence preserves
`CommitUnknown`; corrupt evidence is `Invariant`; different authored content is `Conflict`.
Do not switch IDs or automatically retry an unknown attempt. Explicitly retry/read the same
identity. Rollback acknowledgment loss is `RollbackFailed`, never proof of no writes.

Server SQLSTATE `57014` (query cancellation) and `55P03` (lock watchdog) are operation
failures. Only acknowledged rollback exposes them as `Deadline`; unconfirmed rollback remains
`RollbackFailed`, and an unconfirmed commit remains `CommitUnknown`. Receipt lookup and stream
locks precede the first possible write and therefore do not by themselves mark an effect attempt.

All operations use the caller's original absolute deadline, including pool acquisition, lock and
statement watchdogs, settlement and readback. Timeouts before effects return `Deadline`; during potentially mutating execution or commit they
return `CommitUnknown`, and during rollback they return `RollbackFailed`. Cancellation by dropping
a future closes its unconfirmed connection. PostgreSQL watchdogs clamp to its supported millisecond range. The server
clock owns receipt time and baseline expiry; the host-injected clock owns the operation budget.

Core `u64` producer sequence and revision use checked PostgreSQL `numeric(20,0)` without bigint
narrowing. V1 retains all reports/receipts/retired epochs and has no cleanup API. Replay retention
is a minimum guarantee; an existing receipt does not expire. Baseline validity is separate and
only a new higher complete snapshot restores an expired baseline. The independent server journal position uses the signed bigint range supported by Projection.
There is no consumer release acknowledgment or cleanup API.

## Composition and verification

Implement the core `Authority` using verified product context, obtain a `LifecycleGrant` and call
`activate` with explicit `Policy`; then verify each batch and call `receive`. `ReadGrant` permits
`lookup` and historical stream `state`; a never-created stream returns `UnknownStream`. Product code interprets payload bytes and applies coverage
absence semantics. Receipt acceptance never means Inventory or compliance has been updated.

```rust,no_run
use rss_observation::{Clock, Error};
use rss_observation_postgres::PgStore;
use rss_request_context::Deadline;
async fn adopt<C: Clock>(pool: sqlx::PgPool, clock: C, deadline: Deadline)
    -> Result<PgStore<C>, Error> {
    PgStore::new(pool, clock, deadline).await
}
```

`integration` exposes only one-shot settlement faults; default features are empty. Real TLS
PostgreSQL tests live in `postgres-integration --test observation`, including concurrency, RLS,
ACK loss, cursor atomicity and real worker-process kill/recovery. `hack/observation-package-proof.py`
consumes actual extracted package artifacts in separate core, base adapter, Source-only and PostgreSQL-bridge workspaces.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: baseline 5b63e10 adapters/postgres/src/device_command.rs (exact receipt recovery, without command coupling)

## Optional Projection source

Enable `projection` for Source and independent resolution, without loading `rss-projection-postgres`.
Enable the additive `projection-postgres` feature for borrowed PostgreSQL transaction resolution.
Both features use the same journal and reference format. Use `PgSource::new(Arc<PgStore<C>>, JournalReadGrant, SourceScope)`. It implements
`rss_projection::Source` for that exact scope; the constructor rejects a tenant different from
the grant, and reads/resolution reject scope mismatches. The application declares the journal's
source lineage (the example uses `rss.observation.v1`), reuses it across restarts and changes it
after rebuilding the input journal. This does not authenticate database provenance. Source lineage
is independent of Reference v1 encoding, producer epoch and source-local positions.
The flag controls dependencies and APIs only: every installation and every receive uses the same
revision-2 journal, including when this feature is disabled. `high_water` and `read` query visible
immutable batch positions, never producer sequence, wall-clock time or current lifecycle state.
Historical applicable records remain replayable after retirement, expiry or NeedSnapshot.

`read` validates rows one at a time and emits bounded immutable version-1 references containing
Scope, batch ID and the full Observation fingerprint. Event IDs are ASCII hex fingerprints. No
consumer mapping runs in the source. The reference therefore remains stable across projection
generations and fits the Projection 1 MiB event limit even for a legal 4 MiB report or UTF-8 ID.
Reference encoding is private; unknown, changed or misplaced references are rejected by exact
reconstruction from the validated durable record. Debug/error formatting does not expose facts.

`resolve(event, deadline)` returns `ApplicableRecord` under the source's tenant grant.
`resolve_in_transaction(&mut PgTransaction, event)` (requires `projection-postgres`) resolves on the **same borrowed transaction**
as the consumer's `PgEffect`. Provision that projection runtime role with Observation schema USAGE
and table SELECT as well. The resolver does not change session identity, deadlines or settlement. Its static SQL retains
Observation error classification in both entry points; the example maps invalid references,
authorization failures and storage-contract violations to a rejected effect, rather than transient
unavailability. Neither category advances the checkpoint.
The consumer mapping supplies its own `DefinitionIdentity` to Projection `initialize` and
`takeover`; the source does not invent a definition for a business read model. The handoff mapping
owns its declaration next to its effect. A changed definition requires a new generation, and
mismatched takeover must fail before Facts SQL. Use `projection` / `run` for atomic
read-model SQL, write-authority validation, fact receipt and checkpoint. The source's own reads
have a 30-second provider bound; runner Control additionally bounds the whole invocation.

For another system, resolve before sending and compose existing `AtLeastOnce`; destination
idempotency and conditional-write/fencing remain the consumer's responsibility. Local checkpoint
ownership cannot fence an in-flight remote write. All referenced records remain retained.
Tenant journal order is delivery order, never MDM source priority or cross-source fact authority.

## Runnable consumer example

Provision a fresh demo database as its administrator:

```sh
psql "$ADMIN_DATABASE_URL" -f crates/observation-postgres/examples/handoff/setup.sql
# Set handoff_owner and handoff_runtime passwords separately with psql \password.
# PG_CA_FILE contains the trusted server CA. MIGRATION_DATABASE_URL identifies handoff_owner.
cargo run -p rss-observation-postgres --features projection-postgres --example handoff-install
# DATABASE_URL identifies handoff_runtime.
cargo run -p rss-observation-postgres --features projection-postgres --example handoff
```

The example supplies its own authority, clock and read-model mapping. It receives snapshot,
explicit delta deletion, gap and recovery snapshot while projection is stopped, then runs and
resumes a generation. The complete empty recovery snapshot clears only its declared coverage.
`handoff/install.rs` composes both published `MIGRATION_SQL` constants and package-local facts SQL;
it does not depend on workspace sibling paths. `handoff/model.rs`, installer and facts schema are
consumer-owned assets shipped in the package;
no Inventory, source precedence, device authentication or compliance policy enters the component.

Real PostgreSQL T2 in `postgres-integration --test observation_projection` proves ordered
visibility/rollback, large references, multi-source/tenant/registration/epoch separation, one-way
upgrade/rollback, atomic effect/checkpoint recovery and worker-process kill after staged SQL.
Package proof consumes core, base adapter, Source-only and PostgreSQL-bridge compositions from
exact `.crate` files; the Source-only closure rejects the concrete Projection PostgreSQL adapter.

ref: postgres/postgres doc/src/sgml/mvcc.sgml@c13dd7d50f21268dc64b4b3edbce31993985ab12
ref: EventStore/EventStoreDB-Client-Rust kurrentdb/src/types.rs@d76e58ba464b2dc77c196ffefbca330ce9df938d
