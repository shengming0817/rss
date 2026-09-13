# rss-saga-postgres

PostgreSQL 16+ implementation of `rss-saga::Store`. Instance progress, finite history capacity,
journal events and protected receipts settle in one transaction. The core owns actions and
cryptography; the adapter persists protected records and independently validates transitions.

## Installation and upgrade

An external migrator executes `MIGRATION_SQL` as a dedicated NOSUPERUSER NOBYPASSRLS schema owner.
For an existing component V1 installation, stop all writers and execute `UPGRADE_SQL` instead.
The upgrade takes exclusive component table locks, validates and replays the original history,
moves each receipt into its `ForwardApplied` journal row, and removes the old receipt table and
pairing triggers. It preserves definitions, sequences, attempts, effect keys and receipt V1 bytes.
An invalid history or arithmetic overflow aborts the transaction. The product owns the migration
execution deadline, maintenance window, database backup and available temporary disk/WAL space.

Schema V2 has two tables: `instances` and `journal`. The new runtime accepts only V2; it does not
run migrations or maintain an old-schema reader. Original committed migrations remain immutable.
Fresh installation executes the same migration chain as an upgrade.

Provision a separate runtime login with schema USAGE, table SELECT and EXECUTE on the component
functions. Reapply function EXECUTE grants after the upgrade creates the new signatures. Grant
no direct write, REFERENCES or TRIGGER privileges, including column grants, and no owner membership.
Tables remain LOGGED with ENABLE/FORCE RLS. Admission checks every SET ROLE reachable role,
PUBLIC privileges, rewrite rules, exact tenant policies, function signatures/bodies/attributes,
new history CHECK bindings and receipt uniqueness indexes. Unexpected user triggers are rejected.

The application owns role provisioning, TLS, business tables and authorization. The tenant setting
isolates queries made by trusted application code; possession of database credentials is not tenant
authentication. Products must not let callers select arbitrary tenant settings.

## Composition

```rust,no_run
use rss_saga::{Control, Timer};
use rss_saga_postgres::PgStore;
async fn connect<T: Timer>(pool: sqlx::PgPool, control: &Control<'_, T>)
    -> Result<PgStore, rss_saga::Error>
{
    PgStore::new(pool, control).await
}
```

`PgStore::new` verifies and adopts the supplied pool. All clones share it. `close(control)` stops
pool admission and distinguishes draining from interrupted waiting; cancel and join workers first.
The optional `rss-runtime` feature implements the existing managed-resource lifecycle.

The core [README](../saga/README.md) shows typed actions, explicit `HistoryCapacity` and `ReadBudget`,
a timer and authenticated receipt protection. Runtime roles never receive a business transaction
writer, second receipt writer or history bypass.

## Bounded history and atomic commits

`revision` is the event count. V1 accounting charges 256 bytes for each event plus the protected
receipt envelope's conservative JSON size. This includes the expansion of byte arrays to JSON
numbers, key escaping, AAD and authentication metadata; it is not PostgreSQL tuple or TOAST size.
Definitions have a separate 2 MiB encoded bound. Plaintext remains limited to 1 MiB and ciphertext
to 2 MiB; the maximum encoded receipt is larger than the ciphertext limit.

The core derives mandatory settlement and first-compensation reservations from current progress.
SQL checks the same reservation against durable event/byte capacity when committing the event.
Receipts are stored in their completion row, with CHECK and partial UNIQUE constraints enforcing
pairing and uniqueness. Progress and accounting change atomically under tenant, live lease and
revision/capacity CAS. The commit path uses fixed-size progress and a pending-key point lookup;
it does not reload or aggregate the journal.

Recovery still validates the complete bounded history. It locks fixed-size metadata, checks the
caller's read/authentication budgets, withholds oversized definition/receipt payloads in SQL, and
then streams typed events in order. SQLx receives complete rows, so a Rust check after receiving a
row alone cannot provide the payload boundary. Replay checks actual accounting, effect keys and
transitions, and compares the final projection with the locked metadata. Cooperative yields keep
the injected deadline/cancellation and lease renewal observable between rows. Cryptographic
receipt verification remains in the core.

Capacity exhaustion stops a new intent at a safe boundary. Existing pending effects use reserved
space for authoritative probing and settlement. `history_head` reads small metadata even if a
worker cannot load the history; `extend_history` performs monotonic finite growth using the live
lease, expected revision and expected capacity. It does not append a journal event or reset time.
Candidates use the same admission predicate to exclude capacity-blocked new intents while keeping
pending settlements recoverable.

Upgrade initializes each existing capacity to its observed use plus mandatory remaining obligations
(at least one for empty numeric limits). An instance beyond a worker's read budget requires an
explicitly larger finite read budget; further new attempts may also require capacity growth.
All instances then follow the same runtime path. There is no unlimited grandfather mode,
compaction, checkpoint, history reset or automatic compensation on capacity exhaustion.

## Failure and verification

`CommitUnknown`, `RollbackUnknown`, cancellation and deadlines do not prove absence of a write or
remote effect. Interrupted transactions quarantine their connection; recover under a fresh live
claim and locked snapshot. Pending effects use their original idempotency key. Acknowledged
state, original definition and authenticated receipts remain authoritative.

The real TLS PostgreSQL/Redis tests cover lease takeover, process crashes, acknowledgement loss,
compensation pause/resume, tenant isolation, capacity boundaries, schema drift and one-way upgrade
of pending, paused, terminal and long-history instances. Explicit ignored measurement profiles
record 100/1,000/10,000 events and 50/95/100 percent byte occupancy; ordinary CI has no invented
performance SLO. Measurement commands and results are recorded with the #2425 delivery artifact.

Independent consumption runs through `python3 hack/saga-package-proof.py --source`; fixed candidate
archives use `--artifacts DIR --revision SHA`. Core-only, PostgreSQL and runtime selections resolve
independently. These prove library consumption, not product production acceptance or publication.

ref: restatedev/restate crates/worker-api/src/invoker/invocation_reader.rs@7fcc614c75fac74d051b68b118e87421e90467cc
ref: launchbadge/sqlx sqlx-postgres/src/connection/stream.rs@v0.9.0
