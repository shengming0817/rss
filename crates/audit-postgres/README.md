# rss-audit-postgres

PostgreSQL 16+ Audit persistence. The host supplies a pool, monotonic timer,
absolute total and operation deadlines, cancellation and explicit `Integrity::Plain` or `Integrity::Ledger(auth)`.
No migration execution, pool shutdown, global reads, memory provider or automatic downgrade.
The `ledger` and `messaging` features are independently additive; `integration` is test-only.

## Ownership and retry

`PgAudit::prepare(event, control)` obtains `recorded_at` from PostgreSQL in V1 Unix seconds.
It returns `PreparedAuditV1`, not a write receipt. Preserve these exact canonical bytes durably
in the source's retry/outbox state before an append can become uncertain. Recreating an event
with a new recording time after commit-unknown is a different request and correctly conflicts.
`PreparedAuditV1::from_canonical_bytes` restores structurally valid bytes; it authenticates
neither their source nor the recording-time assertion. Source adapters remain trusted.

`append` returns canonical `LocalTxAttempt<Committed<StagedAppend>, Error>`. Only the private
`Committed` constructor follows an acknowledged database COMMIT. Successful staging, an error,
an absent read, `CommitUnknown` and `RollbackFailed` are not rollback evidence. Retry the
unchanged prepared request to serialize recovery. Database errors remain redacted. `Error::Storage { kind, source }` retains a closed
`StorageFailure::{Transient,Permanent}` classification; permissions/schema failures require
intervention, while connection interruption, contention and cancellation may be retried.
The messaging conversion preserves that classification; neither class grants ACK authority.

`read_tx_with_context(tenant, control, context, callback)` supplies `ReadAuditTransaction`
inside a PostgreSQL read-only transaction. It checks tenant scope before trusted reads,
never reserves Audit/Ledger heads, and exposes no append or lock operation.
`write_tx_with_context` supplies `WriteAuditTransaction` after acquiring the optional Ledger chain lock. It also provides the read methods. Pass `()` when no context is needed.
Both borrow trusted business SQL via `with_connection`. A callback returning `Result<R, E>` produces
`LocalTxAttempt<Committed<R>, TransactionError<E>>`: `Operation(E)` retains the original
host reason/classification, `Audit(Error)` identifies adapter/control failures, and
`Rollback { operation, settlement }` retains both causes when rollback is unconfirmed.
`E` needs no formatting or error trait; diagnostics never render or traverse it. Match it
explicitly to recover its typed value. `with_connection` likewise preserves its callback's
error type. There is no untyped business-rejection sentinel or error side channel.
Errors must propagate. This is not a SQL sandbox:
do not issue transaction control, change role/tenant/session state, or swallow append errors.
Plain takes no tenant-wide Audit lock. In Ledger mode acquire the chain before business/outbox locks.
`Control::new(timer, total_deadline, operation_deadline, cancel)` caps the operation cutoff
by the total cutoff without refreshing either. Acquisition, setup and settlement use total;
pre-locking and callback work use operation, allowing the host to reserve settlement time.
Server statement timeouts also bound outstanding work. Settlement drains pending server
responses before rollback and remains limited by the original total cutoff; it may still fail. `total_remaining` and `operation_remaining` expose each cutoff.
Unconfirmed connections are closed, never reused.
Cancellation after the callback returns an error cannot overwrite that error. If cancellation
prevents rollback from starting, the result is `RollbackFailed` with both causes, not
`CommitUnknown`: this branch never attempted commit. Only a real rollback ACK permits
`RolledBack`. No fresh cleanup budget is minted.
Preparation errors before COMMIT also use this rollback path. `CommitUnknown` requires
that this owner has actually started the COMMIT operation.

With `messaging`, `budget.append_in(&mut PgTransaction, &integrity, &prepared)` borrows the actual message connection,
inherits its tenant and remaining budget, and changes no GUC, isolation level or lifecycle state.
It does not require a `PgAudit` object or any connection pool. Its result is staged; only the original message owner
can settle Inbox/business/Audit/ledger together and mint ACK authority. Return failures through
that owner; original `PgError` classification, including ownership loss, is preserved.

## Facts derived inside a transaction

`write_tx_with_context` acquires the fixed Audit chain only in Ledger mode, before the callback.
For a borrowed messaging transaction, `lock_head_in` similarly pre-locks only the selected chain.
Plain does not serialize callbacks or product receipts. The host owns their business concurrency.

The product determines the stable identity, recording time and exact canonical bytes before
append. Use `rss_audit_core::prepare` with recorder-authoritative time from the existing connection.
Audit accepts prepared records; it does not call back into the product to reconstruct facts.
Replay preserves the original bytes and timestamp. An absent read is not rollback proof, and an
unknown business transaction must not be rerun merely to regenerate its audit input.

The pool-free messaging functions are `validate_in(tx, integrity)`, `lock_head_in(tx, integrity)`,
`budget.append_in(tx, integrity, prepared)` and `budget.append_batch_in(tx, integrity, batch)`.
Single-item calls delegate to the physical batch kernel. The batch retains input order and original
transaction budget; any error must abort the enclosing transaction. No resolver or compatibility
method remains. Native SQLx and Audit-owned transactions use the same persistence kernel.

## Integrity and reads

Stable identity is `(tenant, source_id, event_id)`. Exact bytes and stored integrity mode
must agree on replay. The host may choose another mode for a new event in the same tenant;
there is no permanent tenant-mode pin. Ledger failure aborts; it never retries plain.
HMAC, chain ordering and key admission remain owned by the optional in-workspace Ledger components.

`read_page(Cursor, ReadLimit, control)` uses stable navigation positions allocated by a database
sequence. Positions allow gaps and do not represent commit order or reliable consumer offsets.
Supply 1..=1024 rows and a positive canonical-byte budget. SQL checks the selected page's byte
budget before returning payloads; oversized pages return no partial rows.
The first statement fixes the maximum currently visible position. Continuations select
`after < position <= through` in position order. The upper bound does not freeze membership:
a low position committed after it was passed can require a fresh query to become visible.
Ordinary pagination does not authenticate missing rows. Ledger verified windows retain their
separate contiguous-chain checks. Product incremental projections must choose their own contract.

With `ledger`, `read_verified(tenant, Sequence, ledger::ReadLimit, control)` authenticates a window
and checks its Audit-row association. Its budget charges ledger encoded bytes, including the
predecessor. Ordinary cursors and ledger sequences are not interchangeable. Plain rows are not
in the ledger window. Verification does not prove source truth, complete Audit history, absence
of tail truncation or an external checkpoint.

## Installation and roles

`MIGRATION_SQL` installs the current fresh schema in a single transaction, as its separately
provisioned NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE owner. Audit directly creates the
navigation sequence, records table and batch append function. Source/event IDs accept 255 bytes;
complete canonical records remain bounded to 128 KiB. Optional Ledger is installed separately.
Only fresh installation is supported: existing schemas are rejected, with no upgrade, repair,
import or compatibility path. The host owns installation and runtime grants.
Runtime must not own objects or reach the owner, have CREATE/delegation rights or PUBLIC access.
Grant only:

```sql
GRANT USAGE ON SCHEMA rss_audit TO audit_runtime;
GRANT SELECT ON rss_audit.records TO audit_runtime;
GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[])
    TO audit_runtime;
```

No runtime sequence privileges are required or permitted.

Runtime cannot INSERT/UPDATE/DELETE/TRUNCATE tables. Fixed SECURITY DEFINER functions enforce
tenant scope and append a physical batch. The records table FORCEs RLS, including for
its owner. Ledger and transactional-messaging installations/grants remain separately owned.
The host must configure authenticated TLS; Audit does not accept a URL or replace pool settings.
Admission checks actual role, inherited/switchable access, columns, constraints, RLS, definer
bodies/configuration, durability and privileges. Incompatible configuration fails startup validation. Privileged
operators can still alter storage; Audit provides no WORM, retention/hold, key custody or DR policy.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: sea-ql/sea-orm TransactionError<E>@2.0.2 (typed callback error, not settlement authority)

Tenant-bound operations check the actual tenant without repeating startup catalog validation. The
independent prepare operation only reads database time without binding a transaction tenant.
`Error::is_interrupted()` classifies Audit and Ledger deadline/cancellation causes consistently;
it does not prove rollback or authorize a retry.

## Installation and startup validation

`PgAudit::new` validates the actual Audit pool's role, schema, RLS, ACLs and functions.
Ledger mode validates Ledger storage on the same lease, including for a one-connection pool.
For a different borrowed runtime, call `validate_connection(connection, control)` or
`validate_in(message_transaction, integrity)` during startup using its **actual** credential/connection.
The latter inherits the original message owner's budget; neither method changes settings,
acquires a second connection, repairs permissions or owns settlement. Hosts must bound server
execution and retire unconfirmed connections after cancellation.

Database engines, controlled deployment roles and trusted host infrastructure are inside the
trust boundary. Stop and drain relevant writers before schema/role changes, validate the new
configuration, then resume. Failure keeps service closed. Ordinary operations do not inspect
catalogs or promise to detect arbitrary administrator GRANT/DDL before the next method call.
SQL permissions/RLS, tenant scope, canonical identity and data/Ledger integrity still apply.
Product authorization and revocation remain live at their separately defined business boundary.
This is not protection against a database controller or a WORM guarantee.

Read-only hosts use `PgAuditReader` with a separately provisioned credential that has SELECT but no Audit or Ledger append-function authority, including inherited/SET-role authority. It shares the full structural admission and existing bounded page/verified-window/read-transaction implementations, but exposes no append or writer handle. The host owns the pool, deadlines and re-admission after controlled changes.

## Borrow an existing SQLx transaction

`append_in_transaction(tx, prepared, control)` and `append_batch_in_transaction(tx, batch, control)`
use the same Audit write kernel as owned transactions and the messaging adapter. Batch results
follow input order; repeated identical identities return the same record and only the first newly
inserted occurrence has `inserted=true`. Different bytes conflict. Empty input does no DB work.
New rows return their database-assigned position and reuse the admitted body. Exact replays are checked in a subsequent statement snapshot. Ledger signs new identities in first-occurrence order under one same-chain lock.

The host admits the actual borrowed credential at startup, configures tenant and server timeouts,
and owns isolation, commit/rollback and connection quarantine. The adapter never acquires a second
connection or changes GUCs. Propagate any error and roll back the whole transaction. Under stronger
isolation, competing writes can cause serialization failure; only the host retries the transaction.
Prepare exact bytes with recorder-authoritative time before append and retain them after uncertainty.

### Write capacity

Create `WriteBudget::new(max_rows, max_batch_bytes, in_flight_bytes)` once per host
capacity domain. Pass clones to `PgAudit::new(pool, integrity, budget, control)` and the
pool-free message writers. All sizes are complete Audit V1 bytes, including repeated inputs.
For sizes known before encoding, call `budget.reserve(rows, bytes, control).await` before
preparation or pool checkout. Bind the returned reservation to the final slice with `bind`.
Use Core's `canonical_len` for the exact size. Binding refunds excess bytes.
For existing input or a borrowed connection use `budget.try_admit(records)` immediately.
Both routes produce a single-use batch. Supply it to the SQLx or message batch append.
The owned transaction callback accepts it via `tx.append_admitted(batch)`.
Underestimates and impossible dimensions return `WriteLimit`; temporary exhaustion
returns `WriteBusy`. Propagate either error to the original transaction owner.
Dropping a waiter or grant returns capacity. Borrowed writes release it on return;
owned transactions retain staged grants until settlement. Retained host retry bytes,
receipts, SQLx buffers and allocator overhead are outside the canonical-byte charge.

For an up-front reservation, use the source recorder's authoritative time and keep the
same reservation through Core preparation and binding:

```rust,ignore
let slot = budget.reserve(1, rss_audit_core::canonical_len(&event)?, control).await?;
let rows = [rss_audit_core::prepare(event, recorded_at)?];
let batch = slot.bind(&rows)?;
budget.append_batch_in(message_tx, integrity, batch).await?;
```

When PostgreSQL supplies the recording time via `PgAudit::prepare`, that method obtains
its own preparation capacity, releases the connection after the clock query, and returns
the retry record. Use it without an outstanding reservation for the same input.

The write budget rejects configuration whose row/byte maxima could exceed a PostgreSQL
Bind frame, including repeated source/event strings, array elements and framing. Aggregate
in-flight capacity is configured separately. When an owned transaction already retains
enough bytes to make its next append impossible even in an otherwise idle domain, the
append reports `WriteLimit`. Another writer's temporary occupation reports `WriteBusy`.
