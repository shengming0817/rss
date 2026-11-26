# rss-observation-postgres

PostgreSQL 16 observation persistence, with one atomic batch transaction and one Rust integrity
state machine. Adopt a dedicated, already configured SQLx `PgPool` with `PgStore::new(pool, clock,
deadline)`. The host owns TLS (VerifyFull), credentials and authentication configuration. The store
owns operation settlement and closing the adopted pool; `close` closes its clones too. No pool,
connection or arbitrary SQL callback is exposed by the observation API.

## Installation and privileges

An external migrator executes `MIGRATION_SQL` using a dedicated NOSUPERUSER NOBYPASSRLS schema owner.
Runtime receives schema USAGE, SELECT on streams, journals and batches, and function EXECUTE, without table DML, TRUNCATE,
owner-role membership, CREATE or RLS bypass. Tables use FORCE RLS and transaction-local tenant
scope. Functions have fixed search paths and revoke PUBLIC execute. The runtime is trusted
companion infrastructure; a tenant GUC is isolation inside that boundary, not authentication of
an attacker who already possesses its database credentials.

```sql
-- Run as the external owner after installing MIGRATION_SQL; provision roles separately.
GRANT USAGE ON SCHEMA rss_observation TO observation_runtime;
GRANT SELECT ON rss_observation.streams, rss_observation.batches, rss_observation.journals TO observation_runtime;
GRANT EXECUTE ON FUNCTION rss_observation.activate(text,numeric,text,text), rss_observation.lock_stream(text), rss_observation.commit_batch(text,text,numeric,bytea,bytea,bigint,text,text,numeric,boolean) TO observation_runtime;
```

Install `MIGRATION_SQL` in a fresh schema as one transaction. Runtime admission verifies storage
revision 4, its catalog definitions and effective privileges, including those on the tenant
admission and journal tables. Both pool constructors check roles the login can assume or administer,
including indirect membership administration grants.

## Transaction and recovery

`activate` locks the object lifecycle and atomically creates a never-used stream epoch with policy
and initial state. Registration switches prevent old sources from writing; retained receipts
remain readable. The expected revision is global to the object's lifecycle, not its producer
sequence. Exact activation replay returns its original revision without reactivating an old epoch.

`receive` first looks up exact scoped batch identity. For a new batch it locks object registration
and stream, rechecks duplicates after waiting, computes the core decision and commits raw canonical
bytes, fingerprint, received time, policy, receipt/decision and the stream update together. One
`batches` row is both the receipt and complete recoverable representation. Its core-computed applicable
flag admits only validated snapshots/deltas. Applicable reports allocate a positive `log_position` under the tenant journal row lock, held
through settlement. Rollback releases the position for reuse. Projection can only see committed
positions in allocation order. Activation creates the tenant admission row once. Inapplicable
reports take a shared lock on that row through settlement and keep a NULL position. Allocating
the last position closes admission in the same transaction, after earlier admitted reports settle.
Later activations preserve closure. Exhaustion rejects every new report and retained exact replay still
returns the original receipt. The batch itself is the immutable journal entry; there is
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
a future closes its unconfirmed connection. Runtime budgets outside PostgreSQL's positive signed-integer millisecond range are rejected before acquisition; watchdogs use the remaining time rounded up to milliseconds. The server
clock owns receipt time and baseline expiry; the host-injected clock owns the operation budget.

## Retired stream maintenance

Provision a separate maintenance login with schema USAGE and EXECUTE on
`rss_observation.reclaim(text,bigint,bigint,numeric,integer)`. Adopt its dedicated pool with
`PgMaintenance::new`. Runtime and maintenance admission both verify the role split, RLS and storage revision.
Each `ObservationMaintenance::reclaim` call requires a freshly verified `MaintenanceGrant`, an absolute
deadline and a `ScanWindow` (1–64 identities). The grant binds exact scope, latest permissible
retention expiry in server Unix seconds and the host-confirmed safe tenant journal position.
The host coordinates consumer checkpoints, fixed replays, baseline recovery and new generation admission.
Zero protects every journal entry while allowing eligible failed or partial reports to expire.

Only retired streams qualify. The page inspects identities by producer sequence, including already
released or ineligible entries. The database clears eligible raw reports, policy and decisions in
the same transaction as the journal floor update. Use `last_examined` after an acknowledged page;
stop on `finished`. Retry the same window after an uncertain commit. Start a fresh sweep when the
host extends either bound. Released bytes count canonical report bytes; PostgreSQL VACUUM owns space reuse.
Scope, batch ID, sequence, fingerprint, log position and activation history continue to fence reuse.
Lookup returns Found, Expired or NotFound. Exact replay of an expired identity returns HistoryExpired.

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
revision-4 journal. `bounds` reads the durable committed high-water and the last released position.
Each page checks this floor in the same statement snapshot. A cursor equal to the floor may continue;
an earlier cursor gets HistoryExpired, including an empty page. Exact references use per-batch evidence,
so a retained active record below the floor can still resolve. Initialize a new generation with `GenerationStart::after`, a host-prepared read model and
complete deduplication receipts at or beyond the floor. The old generation keeps its original start.

`read` validates rows one at a time and emits bounded immutable version-1 references containing
Scope, batch ID and the full Observation fingerprint. Event IDs are ASCII hex fingerprints. No
consumer mapping runs in the source. The reference therefore remains stable across projection
generations and fits the Projection 1 MiB event limit even for a legal 4 MiB report or UTF-8 ID.
Reference encoding is private; unknown, changed or misplaced references are rejected by exact
reconstruction from the validated durable record. Debug/error formatting does not expose facts.

`resolve(event, &control)` returns `ApplicableRecord` under the source's tenant grant.
For a same-database effect, select `source.into_local(page_bytes)?` and implement
`PgEffect<Item = VerifiedObservation>`. Give the source an explicit canonical-byte allowance
of at least 4 MiB. Together with the runner's count limit it selects an ordered prefix;
the returned page is the atomic unit in `run_batched`. For eight maximum-size reports in one
transaction allow 32 MiB. Decoded facts, references, driver buffers and application data consume
additional memory. The page owns the verified inputs through settlement.

Call `resolve_in_transaction(tx, item)` at each callback before consuming facts. It checks the
tenant, current row, exact report digest and receipt fields on the borrowed transaction, then
returns an `Arc<ApplicableRecord>`. Changed evidence is restored from the same statement snapshot.
A concurrent release before a later callback can therefore roll back the entire batch. Provision
the projection runtime with Observation schema USAGE and SELECT on rss_observation.batches.
Known corrupt positions carry `Phase::Restore` and the source position. The example preserves
those diagnostics when it classifies permanent failures as rejected effects.
The consumer mapping supplies its own `DefinitionIdentity` to Projection `initialize` and
`takeover`; the source does not invent a definition for a business read model. The handoff mapping
owns its declaration next to its effect. A changed definition requires a new generation, and
mismatched takeover must fail before Facts SQL. Use `projection` / `run` for atomic
read-model SQL, write-authority validation, fact receipt and checkpoint. Source high-water/read and independent resolve consume the same caller Control as the runner.
There is no provider 30-second deadline, second timeout or conversion between Timer and Clock
origins: the private shared transaction engine asks its entrypoint for current remaining time.
Native Observation operations continue using their own Deadline/Clock; Projection reads use
Projection Control. Both entrypoints retain settlement and connection quarantine responsibility.
The new signatures replace the old ones without compatibility wrappers. Source restore diagnostics
and unconfirmed rollback (RollbackFailed) survive runner composition. Borrowed resolve performs
query and reconstruction inside the enclosing transaction's internally checked callback.

For another system, resolve before sending and compose existing `AtLeastOnce`; destination
idempotency and conditional-write/fencing remain the consumer's responsibility. Local checkpoint
ownership cannot fence an in-flight remote write. The host includes remote consumers in its release decision.
Tenant journal order is delivery order, never MDM source priority or cross-source fact authority.

## Runnable consumer example

Provision a fresh demo database as its administrator:

```sh
psql "$ADMIN_DATABASE_URL" -f crates/examples/src/observation/setup.sql
# Set handoff_owner and handoff_runtime passwords separately with psql \password.
# Supply bounded stdin JSON: host, port, database, username, password, pg_ca, tenant.
# owner-input.json identifies handoff_owner; keep these ephemeral inputs private.
cargo run -p rss-examples --features observation-handoff --bin observation-install < owner-input.json
# runtime-input.json identifies handoff_runtime.
cargo run -p rss-examples --features observation-handoff --bin observation < runtime-input.json
```

The example supplies its own authority, clock and read-model mapping. It receives snapshot,
explicit delta deletion, gap and recovery snapshot while projection is stopped, then runs and
resumes a generation. The complete empty recovery snapshot clears only its declared coverage.
`crates/examples/src/observation/install.rs` composes both published `MIGRATION_SQL` constants and consumer-local facts SQL;
it does not depend on workspace sibling paths. `crates/examples/src/observation/model.rs`, installer and facts schema are
consumer-owned assets maintained in the non-published repository examples and copied from the same revision by the proof runner;
no Inventory, source precedence, device authentication or compliance policy enters the component.

Real PostgreSQL T2 in `postgres-integration --test observation_projection` proves ordered
visibility/rollback, large references, multi-source/tenant/registration/epoch separation, tenant admission at exhaustion, atomic effect/checkpoint recovery and worker-process kill after staged SQL.
Package proof consumes core, base adapter, Source-only and PostgreSQL-bridge compositions from
exact `.crate` files; the Source-only closure rejects the concrete Projection PostgreSQL adapter.

ref: postgres/postgres doc/src/sgml/mvcc.sgml@c13dd7d50f21268dc64b4b3edbce31993985ab12
ref: EventStore/EventStoreDB-Client-Rust kurrentdb/src/types.rs@d76e58ba464b2dc77c196ffefbca330ce9df938d

The source and candidate consumers run the same handoff with real PostgreSQL. Use
`python3 hack/observation-package-proof.py --source`, or `--artifacts DIR --revision SHA`
from the same clean candidate revision. Core and independent adapter/projection capability graphs
remain separate; the handoff asserts durable reception, replay and projection progress.
