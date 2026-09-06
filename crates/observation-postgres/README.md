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

Fresh installation is the only initial migration. There is no historical device-command data
import or dual schema/decoder. Future schema revisions must be explicit and retain the identities
required by their consumers. The adapter validates its storage contract on admission.

## Transaction and recovery

`activate` locks the object lifecycle and atomically creates a never-used stream epoch with policy
and initial state. Registration switches prevent old sources from writing; old immutable receipts
remain readable. The expected revision is global to the object's lifecycle, not its producer
sequence. Exact activation replay returns its original revision without reactivating an old epoch.

`receive` first looks up exact scoped batch identity. For a new batch it locks object registration
and stream, rechecks duplicates after waiting, computes the core decision and commits raw canonical
bytes, fingerprint, received time, policy, receipt/decision and the stream update together. One
`batches` row is both the receipt and complete recoverable representation. Its core-computed applicable
flag and partial index identify only validated snapshots/deltas for future handoff; there is no
second receipt/payload table, background worker or projection log. SQL functions enforce expected
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
only a new higher complete snapshot restores an expired baseline. Projection, server LSN and
consumer release acknowledgment remain outside this package's current API.

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
consumes actual extracted package artifacts in separate core and adapter workspaces.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: baseline 5b63e10 adapters/postgres/src/device_command.rs (exact receipt recovery, without command coupling)
