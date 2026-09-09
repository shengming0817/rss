# rss-projection-postgres

PostgreSQL 16+ committed-order journals and atomic projection execution. In one event transaction the
adapter locks the checkpoint, validates the worker epoch and definition identity, applies trusted read-model SQL, records
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
PUBLIC privileges revoked. Admission rejects PUBLIC schema/table/column/function ACLs (including
default function EXECUTE), and requires exactly the canonical tenant policy on each of the four
component tables: role set, command, permissiveness, USING and WITH CHECK. Restricted group
grants and independent maintenance roles remain supported; component checks do not govern
application-owned read models. Applications own role provisioning, authentication, migration execution
and business-table policies. The tenant setting provides isolation within a trusted application;
it does not authenticate a caller that already holds database credentials.

The schema contains only source allocators, events, generation/checkpoint state and fact receipts.
It does not contain product read models or settings. Revision 3 binds each generation to exactly
one 32-byte `definition_identity`, independent of its primary key. Runtime roles cannot update it.

`UPGRADE_SQL` upgrades revision 2 to 3 only when **all tenants have no existing checkpoints**.
It owns an explicit transaction: stop workers and execute it outside another transaction as the
schema owner. A nullable column is added then immediately made NOT NULL; PostgreSQL validates
all physical rows, including those hidden by FORCE RLS. Any existing generation aborts the
upgrade without adopting or changing its data. Roll back the failed connection before reuse,
or close it. No default identity, backfill or first-takeover adoption is provided. If unexpected
legacy generations exist, stop: their disposition requires a separate product migration decision.

After a successful upgrade, grant runtime EXECUTE on the new component functions before starting
v3 workers. Old initialize/takeover/lock/finish signatures are removed, so old clients cannot
continue through a compatibility path. The provider admits only revision 3 with its required
identity column/constraint and EXECUTE permission on each required new function.
Missing or revoked function permission rejects `PgStore::new` with `StorageContract`. Existing migration files remain append-only.
Fresh `MIGRATION_SQL` also includes this transaction; do not nest it inside a caller transaction.

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
2. `initialize(scope, definition, start, bound, control)` requires an explicit
   `DefinitionIdentity` and accepts `GenerationStart::beginning()` or
   `GenerationStart::after(position, complete_baseline_receipts)`. Positioned starts atomically
   import the supplied fact IDs/digests, so a baseline fact redelivered at a later position cannot
   apply twice. The product must prepare the matching read model and complete receipt set,
   including filtered facts. Reinitialization rejects changed definition, start, bound or baseline receipts;
   starting at a bare coordinate without receipts is not supported. `takeover(scope, definition, control)` locks and verifies the stored definition before it
   explicitly increments the checkpoint epoch and returns a private `PgClaim`; no lease or timer
   controls authority. A different definition returns `Conflict` without changing epoch/token or
   granting a claim, even when initialization was skipped. Claims and sessions expose their
   immutable definition; checkpoint reads, event lock and settlement verify it again. Store identity prevents a claim being attached to a different store handle.
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

The counter scenario and its application fixture have moved to [`rss-examples`](../examples/README.md).
Its owning integration test provisions temporary verified-TLS PostgreSQL, invokes the public consumer,
and verifies model/checkpoint persistence and recovery. The old adapter-local counter/setup entrypoints
are removed; follow the linked launcher command instead.

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
`local_tx`, or use `append_in_transaction` in an existing tenant-bound SQLx transaction. The example source is maintained in the non-publishable rss-examples package and copied into isolated consumers; library archives contain the component implementation.

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

## Definition declaration and API replacement

The application mapping owns its definition value. The counter example declares a stable fingerprint
beside its effect; initialization, replay and restart reuse it. The library does not compute or prove
SQL/binary identity. Change the generation when changing the mapping; change the source when
rebuilding the input stream, even if payload encoding stays the same.

Revision 3 replaces the old Rust initialization/takeover signatures and adds session identity
accessors and the external-target definition parameter. Update consumers together with the schema;
there are no old overloads, aliases, defaults or compatibility features.

ref: serverlesstechnology/cqrs persistence/postgres-es/src/view_repository.rs (version CAS;
this adapter retains effect, receipt and checkpoint in its own single transaction)


执行示例和输入/结果说明见 [rss-examples](../examples/README.md)。独立源码使用
`python3 hack/projection-package-proof.py --source`；固定 artifact 使用
`python3 hack/projection-package-proof.py --artifacts DIR --revision SHA`。
两种模式实际运行公共 API 场景，正式验收绑定同一 clean revision、版本和 archive digest；
完整故障矩阵仍归本组件 T1/T2，不把示例通过解释为生产验收或实际发布。

Admission observes the configured database at construction; it neither repairs drift nor protects
against trusted administrators changing DDL after admission. Restore the version-matched schema
and grants before retrying; there is no permissive compatibility mode.

ref: postgres src/backend/utils/adt/acl.c@REL_16_STABLE
ref: postgres src/backend/utils/adt/ruleutils.c@REL_16_STABLE
