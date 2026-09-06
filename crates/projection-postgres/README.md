# rss-projection-postgres

PostgreSQL 16+ committed-order journals and atomic projection execution. In one event transaction the
adapter locks the checkpoint, validates the worker epoch, applies trusted read-model SQL, records
fact identity and advances the checkpoint. An old worker is fenced **before** the effect.

The caller provides a configured SQLx `PgPool`; the adapter adopts its lifecycle. Configure TLS
and authenticated database credentials before `PgStore::new`, which verifies the dedicated runtime
role, component revision and forced RLS. `close` closes this pool and its clones. Stop/join workers
before closing it. The callback is trusted application SQL, not a sandbox: it must not issue
transaction control, change session identity, or write another generation. Only the adapter owns
normal commit/rollback. Unknown settlement closes the connection instead of returning it to reuse.

## Storage installation

`MIGRATION_SQL` is the version-bound fresh schema. An external migrator executes it **as a dedicated
NOSUPERUSER NOBYPASSRLS schema owner**. Every tenant relation has ENABLE/FORCE RLS. Runtime roles get
schema USAGE, table SELECT and function EXECUTE, with no direct INSERT/UPDATE/DELETE/TRUNCATE on
component tables. Do not grant membership in the owner role. Function search paths are fixed and
PUBLIC privileges revoked. Applications own role provisioning, authentication, migration execution
and business-table policies. The tenant setting provides isolation within a trusted application;
it does not authenticate a caller that already holds database credentials.

The schema contains only source allocators, events, generation/checkpoint state and fact receipts.
It does not contain product read models or settings. First release supports fresh installation
only; no historical PostgreSQL migration chain or data adoption is attempted. Future migrations
are append-only and must preserve these persisted identities.

## API and recovery

1. `local_tx` opens a tenant-bound, deadline-bounded transaction. `PgTransaction::append` acquires
   the source allocator row and holds it through commit. Same ID/bytes returns the original
   position; changed bytes conflict. Use this same transaction for the application fact and append,
   or use `append_in_transaction` to borrow an existing caller-owned SQLx transaction.
   That transaction must already have its tenant setting; on error/interruption its caller must
   roll back or discard it. The API installs transaction-local statement/lock watchdogs. After
   client interruption, rollback can itself surface the pending statement error; if settlement
   is unacknowledged, quarantine the caller-owned pool lease with `close_on_drop` rather than
   returning it for reuse. The returned position is staged, never proof of commit.
   Acquire allocator locks before business rows, and multiple allocator locks in sorted source order.
2. `initialize` accepts `GenerationStart::beginning()` or
   `GenerationStart::after(position, complete_baseline_receipts)`. Positioned starts atomically
   import the supplied fact IDs/digests, so a baseline fact redelivered at a later position cannot
   apply twice. The product must prepare the matching read model and complete receipt set,
   including filtered facts. Reinitialization rejects changed start, bound or baseline receipts;
   starting at a bare coordinate without receipts is not supported. `takeover`
   explicitly increments the checkpoint epoch and returns a private `PgClaim`; no lease or timer
   controls authority. Store identity prevents a claim being attached to a different store handle.
3. `projection(claim, effect)` implements core `Execution`. `PgEffect` receives the borrowed SQL
   transaction and exact scope, returning only `PgEffectOutcome::Applied` or `Filtered`.
   Only the adapter can report a receipt-confirmed `Duplicate`. Include tenant, source/projection (when shared), and generation in
   business keys. A successful callback merely stages changes; only acknowledged commit settles.
4. On unknown commit, load the checkpoint or acquire a new epoch and run again. Same fact at a later
   source coordinate is suppressed by its receipt; changed bytes conflict. Receipts are retained for
   the generation's lifetime. No automatic generation deletion or retention policy is provided.
5. For a remote target, use `external_checkpoint(claim)` with core `AtLeastOnce`. Its separate effect
   and checkpoint calls do not offer PostgreSQL atomicity or remote fencing.

A live run stops when caught up. Replay captures `Source::high_water` under the caller's `Control`
and persists `ReplayBound::Through(end)` in a new generation. The source read and high-water share
the same exact tenant/source predicate. The library never merges source positions or switches readers.
Public Source/checkpoint reads have a 30-second provider statement bound; `run` additionally enforces
its caller's total deadline. Public mutating operations require `Control`.

## Source-checkout runnable example

The following commands run from this source repository checkout. Against an empty PostgreSQL demo database, provision the example using psql as an administrator:

```sh
psql "$ADMIN_DATABASE_URL" -f crates/projection-postgres/examples/setup.sql
# Set projection_runtime's password separately, e.g. with psql's \password command.
# DATABASE_URL identifies projection_runtime; PG_CA_FILE is the trusted server CA PEM path.
cargo run -p rss-projection-postgres --example counter
```

The example requires verified TLS, writes two application facts with journal entries in the same
transaction, retries one append, runs/resumes v1, and replays into v2. Both totals must be 2.
All application tables and role provisioning remain in the example, outside component migrations.

## Independent consumers

A standalone application supplies its own runtime, monotonic `Timer` and cancellation token:

```toml
[dependencies]
rss-projection = { version = "=0.1.0", default-features = false }
rss-projection-postgres = { version = "=0.1.0", default-features = false }
rss-request-context = "=0.1.0"
sqlx = { version = "=0.9.0", default-features = false, features = ["postgres", "runtime-tokio", "tls-rustls"] }
tokio = { version = "1", default-features = false, features = ["rt", "macros", "time"] }
tokio-util = { version = "0.7", features = ["rt"] }
```

Use `#[tokio::main(flavor = "current_thread")]` with this manifest; add `rt-multi-thread` only if
the application selects that runtime. The shipped counter additionally uses `anyhow = "1"`.

An external migrator can execute `sqlx::raw_sql(rss_projection_postgres::MIGRATION_SQL)` on its
separately provisioned owner connection; do not pass that connection to `PgStore::new`. Application
code provides an owned `PgEffect`, adopts its runtime pool with `PgStore::new`, then calls
`initialize`, `takeover`, `projection` and core `run`. Compose business SQL and append through
`local_tx`, or use `append_in_transaction` in an existing tenant-bound SQLx transaction. The source
example files are shipped inside the crate archive for copying into an application, not installed
as commands by adding a Cargo dependency.

For example, an independent migrator can consume the version-matched SQL directly:

```rust,no_run
async fn install(owner_connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(rss_projection_postgres::MIGRATION_SQL)
        .execute(owner_connection).await?;
    Ok(())
}
```

The supplied connection must already use the dedicated migration owner described above;
application role grants and read-model migrations remain separate.

## Evidence and sources

T2 lives in `projection-postgres-integration`: concurrent append, stale epoch, duplicate/conflict,
RLS/ACL, replay, commit ACK loss, transaction timeout and real worker-process kill/recovery.
`integration` exposes settlement faults only; defaults are empty. Package artifacts are consumed
outside the workspace by `hack/projection-package-proof.py`.

ref: baseline/pre-community-core-20260902 adapters/postgres/src/projection_worker/checkpoint.rs@5b63e10
ref: baseline/pre-community-core-20260902 adapters/postgres/migrations/0040_projection_events_funnel_and_projection_dlx.sql@5b63e10
ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0

Historical apply and checkpoint used independent transactions. This implementation replaces that
structure; historical tests are scenario sources, not evidence for the new guarantees.

`PgEffect` and `local_tx` callbacks return `PgOperationError`, which exposes only application
rejection and dependency failure constructors. Propagate borrowed SQL/append errors with `?`;
only the adapter classifies fencing and settlement. `Error::kind()` is the recovery decision,
while `diagnostic()` retains a safe phase/SQLSTATE and an opaque original provider source.
Application SQL errors cannot claim component protocol codes even when they raise the same SQLSTATE.

Call `store.close(&control)` after cancelling and joining workers. Admission closes immediately;
`CloseOutcome` distinguishes a drained pool from cancellation/deadline with outstanding borrowers.
All adopted connections must use the same dedicated runtime login without `SET ROLE` masking.
