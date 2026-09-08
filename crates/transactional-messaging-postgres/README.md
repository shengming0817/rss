# PostgreSQL transactional messaging

`rss-transactional-messaging-postgres` 0.1 is an experimental, independently packaged adapter.
The core remains provider-neutral. Installation, role provisioning, business tables, deployment,
database operations and operator authorization belong to the consumer. Explicit library recovery is described below.

Trusted companion infrastructure borrows `PgTransaction` through `with_connection`; application
handlers receive typed repositories. The borrow bounds reference lifetimes, not arbitrary SQL:
trusted code must not issue transaction-control SQL or change tenant settings.

Every operation consumes one injected monotonic deadline. Unacknowledged transaction settlement
quarantines the connection. PostgreSQL time, not the application clock, decides durable lease
ownership and same-ID delivery expiry. No legacy schema is read, migrated or adopted.

## Installation and privileges

Use an external migrator to provision a `rss_tmsg_relay` role with
`NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION` and no membership
in any other role, then execute `migrations/0001_create_transactional_messaging.sql`. The migrator must be able to transfer
function ownership to that role. Do not run migrations through the application pool.

Registry consumers obtain the same versioned SQL through
`rss_transactional_messaging_postgres::MIGRATION_SQL`; the `.crate` also contains the migration
file. Pin the adapter version in the external migrator (`rss-transactional-messaging-postgres =
"=0.1.0"`) so its SQL and runtime come from the same release. The constant does not execute DDL.

The runtime login must not own the schema/tables, be superuser, have BYPASSRLS, or belong to the
relay role. Grant it schema USAGE; policy SELECT; Inbox SELECT/INSERT/UPDATE/DELETE; Outbox
SELECT/INSERT; Outbox sequence USAGE; and EXECUTE on the three package functions. Grant no schema
CREATE or policy mutation rights. The migration revokes PUBLIC EXECUTE. RLS remains ENABLE/FORCE,
including for the non-bypass relay function owner through its explicit Outbox-only policy.

The relay definer is a closed component identity: it must not receive any parent role membership,
including grants with INHERIT/SET disabled or an ADMIN option. A direct membership is the first edge
of every indirect permission path, so rejecting those edges closes inherited, SET ROLE and role-grant
authority without a global catalog scan. `INHERIT` or `NOINHERIT` alone is accepted when no membership
exists. Role attributes such as CREATEDB/CREATEROLE are distinct from inherited object privileges;
SET ROLE reachability is separate again. Runtime-to-relay membership remains independently forbidden.

Runtime, Recovery, DR and Archive all check this one relay posture after the shared fencing probe,
before any profile-specific early return. Extra relay attributes/memberships are rejected through
the existing closed storage-contract categories. The relay check reports `RelayRole`; the preceding
shared fencing probe reports `Functions` for relay SUPERUSER or runtime-to-relay membership.
The external operator must correct the role before reconnecting. This is connection admission, not continuous role-drift monitoring; existing runtimes must be stopped/replaced by their
owner when external role provisioning changes. No library operation executes production ALTER ROLE,
REVOKE or migrations, and no permissive compatibility mode is provided.

Role semantics reference: [PostgreSQL 16 acl.c](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/utils/adt/acl.c)
(`pg_has_role` and membership traversal). The PG TLS suite exercises attribute drift and direct/indirect
MEMBER/USAGE/SET capability combinations, then reconnects after restoring each fixture.

Construct `PgRuntime::connect(config, timer, binding)` with the same monotonic `ExecutionTimer` used by the
consumer/relay. `PgInboxStore` takes a core `LeaseRenewalPolicy`; `PgOutboxStore<R>` takes a
`DeliveryBudget`. Each store owns its policy and the runtime reads it through the port: there is
no separate runtime TTL or renewal setting to mismatch. Use `local_tx` to bind repositories and Outbox append to one transaction.
`PgConsumerEffect<P>` returns a core terminal disposition or a redacted handler/infrastructure
failure; only the adapter creates commit evidence. TLS always uses VerifyFull with explicit CA;
plaintext and transport fault seams are opt-in integration test features, not production modes.

Readiness failures expose `PgStorageContractFailure` closed categories (policy, roles, columns,
constraints/defaults, ACL, RLS or definer functions), without object names or credentials. The
external migrator/operator corrects that category and reconnects. Authentication and missing
database errors are permanent configuration failures; permission denial during the catalog probe
is a storage-contract failure, while runtime permission denial remains a non-retryable operation
error. Transaction stages log only the phase, classification and redacted source.

## Resource ownership and shutdown

The default adapter has no `rss-runtime` dependency. A Tokio-based host can connect, use
`local_tx`, and call `runtime.close().await` directly. `PgRuntime` builds and owns its pool;
`PgTransaction` remains the only transaction lifecycle owner. A shared pool cannot substitute
for sharing the same transaction with repositories and Outbox.

Stop admitting work before closing. The first poll of `close()` stops pool admission and wakes
waiting acquisitions with a closed-pool error classified as `Permanent`: the same runtime cannot
reopen, so retrying acquisition is not useful. Already acquired transactions retain their own
operation deadlines and settlement authority. The future waits for pooled connections to be
released and closed; `is_closed()` only reports that admission has stopped. Repeated and
concurrent closes are safe. Cancelling the wait leaves admission closed, and another call can
continue waiting. Dropping handles does not guarantee graceful cleanup.

SQLx 0.9.0 supplies the corrected pool drain implementation; companion repositories must use
that same SQLx version for borrowed connection types.

The host owns the shutdown budget and wraps `close()` in its own timeout. No additional adapter
shutdown timeout is created. For optional RSS lifecycle integration, explicitly enable:

```toml
rss-transactional-messaging-postgres = { version = "=0.1.0", features = ["rss-runtime"] }
```

This implements `rss_runtime::ManagedResource` for `PgRuntime`; its `shutdown()` delegates to
`close()`, with the budget supplied by `ShutdownStack`. The previous default trait implementation
is removed: existing managed consumers must opt in. The `integration` test feature does not
activate this bridge, and neither feature changes transaction or tenant guarantees.

## Typed companion composition

This compile-checked example keeps SQL in trusted companion repositories. The application handler
only receives a typed repository port. `application_receipts` is a consumer-owned business table,
not part of the adapter migration. The caller supplies core-issued operation deadlines and a
shared monotonic timer; the adapter never creates new sub-operation timeouts.

The example's Rust 2024 consumer declares all three direct dependencies:

```toml
[dependencies]
rss-transactional-messaging-postgres = "=0.1.0"
rss-transactional-messaging = "=0.2.0"
sqlx = { version = "=0.9.0", default-features = false, features = ["postgres", "runtime-tokio"] }
```

`compose` borrows the caller's timer and clones its shared time domain into the adapter;
the caller retains that same timer to pass to `consume_once` or `relay_once`.

```rust,no_run
use std::sync::Arc;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::{
    message::{MessageEnvelope, MessageId, MessagingDomain},
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    policy::{DeliveryBudget, OperationDeadline},
    transaction::{LocalTxAttempt, TerminalDisposition},
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgRuntime, PgTransaction, PgError, PgOutboxStore,
    PgConsumerEffect, PgConsumerEffectFailure, PgConsumerTx,
};

trait Receipts {
    fn record(&mut self, id: &MessageId) -> impl Future<Output = Result<(), PgError>> + Send;
}
struct PgReceipts<'a, 'tx>(&'a mut PgTransaction<'tx>);
impl Receipts for PgReceipts<'_, '_> {
    async fn record(&mut self, id: &MessageId) -> Result<(), PgError> {
        let id = id.as_str().to_owned();
        let tenant = self.0.tenant_id().to_string();
        self.0.with_connection(move |connection| Box::pin(async move {
            sqlx::query("INSERT INTO application_receipts(tenant_id, message_id) VALUES ($1::uuid, $2)")
                .bind(tenant).bind(id).execute(connection).await?;
            Ok(())
        })).await
    }
}
async fn application_handler(repo: &mut impl Receipts, id: &MessageId) -> Result<(), PgError> {
    repo.record(id).await
}
struct Effect;
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(&self, tx: &mut PgTransaction<'_>, message: &MessageEnvelope<Vec<u8>>,
        _deadline: OperationDeadline) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        application_handler(&mut PgReceipts(tx), message.id()).await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        Ok(TerminalDisposition::Succeeded)
    }
}
async fn compose<C: ExecutionTimer + Clone + 'static>(config: PgConfig, timer: &C, binding: rss_transactional_messaging::fence::ExecutionBinding,
    domain: MessagingDomain, budget: DeliveryBudget) -> Result<(Arc<PgRuntime>, Arc<PgOutboxStore<()>>, PgConsumerTx<Effect>), PgError> {
    let runtime = Arc::new(PgRuntime::connect(config, timer.clone(), binding).await?);
    let outbox = Arc::new(PgOutboxStore::new(runtime.clone(), domain, budget)?);
    let consumer = PgConsumerTx::receipt_only(runtime.clone(), Effect);
    Ok((runtime, outbox, consumer))
}
async fn close(runtime: &PgRuntime) {
    // The caller applies its remaining shutdown budget around this future.
    runtime.close().await;
}
async fn append(runtime: &PgRuntime, store: Arc<PgOutboxStore<()>>,
    message: MessageEnvelope<Vec<u8>>, deadline: OperationDeadline) -> LocalTxAttempt<AppendOutcome, PgError> {
    runtime.local_tx(message.metadata().tenant_id(), deadline, move |tx| Box::pin(async move {
        // Consumer-owned repository writes can use this same tx before append.
        store.append(tx, PendingMessage::new(message)).await.map_err(Into::into)
    })).await
}
```

## Durable publication readback

Companion repositories may call `PgOutboxStore::is_published(tx, domain, message_id, fingerprint)` on
an already appended message. It uses the transaction tenant, explicit persisted domain and exact
authored fingerprint. Readback may cross the store's relay domain; append/claim remain bound to
the configured domain. Both append and readback require a transaction minted by this same
PgRuntime. Companion stores can use `validate_transaction` to enforce that binding at every
entry point. Private provenance is minted by local/consumer transactions, never supplied by a
caller; the comparison is a runtime enforcement, not proof against malicious trusted SQL. Only durable published settlement returns true; pending, publishing and dead-letter
return false. Missing rows, corrupt state and changed identity fail closed. This is not device
receipt or execution evidence, and the method neither settles an outbox nor changes its schema.

## Historical source ledger

Source: `baseline/pre-community-core-20260902`.

| Source | Disposition and reason |
| --- | --- |
| `cotx/settlement.rs` | Keep borrowed connection lease and ACK-only reuse; use core `LocalTxAttempt`, remove duplicate outcome enums and product metrics. |
| `pool.rs` | Retain pool lifecycle, TLS verification and bounded acquisition; replace product probes with own-schema/effective-permission checks. |
| `inbox.rs`, `cotx/eventing.rs` | Adapt claim/reclaim, lease CAS and receipt to core identities and fingerprint. |
| `outbox.rs`, `outbox/settlement.rs`, migrations 0057/0060/0064/0066 | Retain atomic claim, frozen retry window, partition head gate and closed settlement; dedicated schema and core digest replace product metadata. |
| `consumer_tx.rs` | Retain private commit proof and atomic effect/receipt; remove Audit/Settings handlers in favor of trusted static effect. |
| Product migration execution, CDC, reconcile, fault-matrix product combinations | Exclude: products own deployment and production workflows; component upgrade SQL remains library-owned. |

Receipt retention must strictly exceed the 24-hour automatic window plus safety margin. No
automatic cleanup or CDC is supplied. Explicit recovery supplies application DLQ, redrive and resolve. A dead-letter partition
head continues blocking its successors.

## Explicit message recovery

Enable `recovery` to consume `rss-transactional-messaging-recovery`. `PgConsumerTx::receipt_only`
selects ordinary terminal receipts. `PgConsumerTx::with_recovery(effect, capture)` selects atomic
protected dead letters; obtain `PgRecoveryCapture::new(runtime, protector, deadline)` first.
Both use the same transaction implementation. The former `new` constructor is removed.

Capture occurs only after verified ingress and rollback of a rejected business effect, in the same
transaction as the terminal Inbox receipt. Protection/storage failure prevents terminal commit.
Configure an `rss-data-protection::Aead` implementation with external key ownership; no default key
or identity provider is installed. Capture roles need SELECT/INSERT on `consumer_dead_letter`.
An existing terminal Inbox receipt with no saved payload is not retroactively replayable.

Create the opaque operator store with `PgRecoveryStore::connect(config, timer, binding, protector)` after
provisioning its privileges. The store privately owns the same PG pool/transaction implementation;
it has no runtime, pool, raw SQL, Deref or generic transaction accessor. Ordinary `PgRuntime::connect`
continues to reject operator UPDATE rights. Provision the operator using the single
[maintenance grant contract below](#consumer-archive-schema-and-role-cutover-2302); ordinary consumer
roles do not receive these privileges automatically. Every operation consumes library-bound
product authorization. RLS remains forced; runtime/maintenance logins must not own tables, bypass
RLS or inherit the relay role. Products provision roles and decide authorization.

New installs execute `MIGRATION_SQL`. Existing component installations execute `RECOVERY_UPGRADE_SQL`
once after the original schema. Runtime only accepts the latest schema; no old-schema fallback or
legacy data importer exists. Migration execution and deployment sequencing remain external.

New-ID replay preserves authored facts and appends at the partition tail, using the same canonical
Outbox append logic. Transport authority/trace are omitted; the product's publisher/ingress adapters
supply fresh transport context. Replay follows the original route, not a single consumer group.
Same-ID redrive never resets the original deadline. Expired resolution writes `resolved`, which
unblocks successors but never passes `is_published`. Compensated resolution requires a same-tenant
published message whose authored causation identifies the target; products judge business adequacy.

Successful operation receipts and state changes commit together. Only the same OperationId may
revisit its existing receipt. A new operation that reuses any existing replay MessageId is a conflict;
a unique database constraint also prevents multiple operation receipts claiming that identity.
`Error::Store(StoreFailureKind)` retains transient/permanent/ownership-lost/invariant classification
without provider text; classification never substitutes for transaction certainty.
Call `PgRecoveryStore::close` to stop admission and drain its private pool under the host's shutdown budget. `LocalTxAttempt` distinguishes
confirmed rollback, failed rollback and commit uncertainty. Read the exact operation receipt after
an uncertain commit; absence is not proof of rollback. The library never blindly repeats a mutation.
`rss_transactional_messaging_recovery::execute` accepts core `ExecutionDeadlines`: mutation uses the
operation cutoff, and receipt readback uses the reserved settlement cutoff from the same clock
observation. It performs one mutation and never resets the total budget.

## Consumer archive schema and role cutover (#2302)

Fresh installation uses `MIGRATION_SQL` (0001–0008). Upgrade exactly once from the installed boundary:

| Installed through | Remaining SQL |
|---|---|
| 0001 | `RECOVERY_UPGRADE_SQL` (0002–0008) |
| 0003 | `ARCHIVE_UPGRADE_SQL` (0004–0008) |
| 0004 or 0005 | Apply each remaining numbered migration in order, through 0008 |
| 0006 | `DR_UPGRADE_SQL` (0007/0008) |

Do not rerun aggregate constants containing already applied DDL. Migration 0005 replaces
`archive_fault` with `archive_fault(uuid,uuid,bytea,text)`; grant that signature after upgrading.
The three-argument overload is removed. Every upgrade must complete the DR provisioning and role
cutover below before admitting this version's runtime.
Migration 0006 fixes all seven archive functions (including internal `archive_fence`) to
`search_path=pg_catalog,rss_transactional_messaging,pg_temp`, preventing temporary relation/type
shadowing. The startup probe rejects unsafe paths, including drift of the internal helper.
Current recovery probes require nullable HOT capsule content and reject the previous broad UPDATE
permission. External migrators must revoke UPDATE on `consumer_dead_letter` from the recovery
operator (including inherited grants), then grant only UPDATE(recovery_version) on that table.
The complete additional maintenance grants are UPDATE on `outbox` and SELECT/INSERT on
`recovery_operations`, together with the already declared base SELECT/INSERT and operation
permissions. No old-schema runtime mode exists.

`PgArchiveRepository` uses a separate, private pool and an archive-only role. The external migrator
owns tables/functions and executes upgrades. Give the workload role schema USAGE and SELECT on
`consumer_dead_letter`, `archive_jobs`, `archive_objects`; grant EXECUTE only on `archive_claim`,
`archive_prepare`, `archive_record`, `archive_purge`, `archive_missing`, `archive_fault` with their
migration-defined signatures. Do not grant `archive_fence`, schema CREATE, table writes, role-owner
membership, SUPERUSER or BYPASSRLS. Function ownership must remain with the trusted component
migration owner. The receipt-writer credential is a trusted verifier capability, not a generic
operator credential; products must keep it away from untrusted arbitrary SQL execution.

Claim/replay/purge share source-first locking. Each new exact archive request increments recovery
revision and fences older requests; retries reuse the same OperationId/digest. The lease duration is derived from the current operation budget (up to five minutes)
and may be resumed after expiry. Zero budgets return `Deadline`; larger budgets return `Invalid`
before claim I/O. Longer jobs must be split into bounded attempts with the same exact request. A live competing lease returns `Busy`; a request/version mismatch
returns `Conflict`, while a stale worker produces the distinct `LocalTxAttempt::Fenced` settlement. A hold is persisted even when no object work is performed. Later
hold/release decisions require the current source revision. Policy changes cannot retroactively
restore already-purged HOT content.

Only verified, matching, sufficiently retained objects permit HOT removal. Prepared ciphertext is
removed upon receipt commit or superseding an expired generation. Object coordinates, original source
rows, Inbox/Outbox and recovery operation receipts remain. The product owns lifecycle expiry; the
library has no S3 deletion port and never removes recovery idempotency evidence during reconciliation.

The archive startup probe checks exact column types/nullability, constraints, defaults, RLS policies,
indexes and effective role privileges. The entire component namespace effective EXECUTE set must
match the archive allowlist; direct, inherited, PUBLIC and overloaded grants are checked. Drift returns `StorageContract`. Receipt readback prioritizes
persisted integrity faults over earlier verified/purged progress. Expired generation scans persist
`last_checked` within the claim transaction to rotate their bounded batch fairly.


## Message disaster recovery and execution fencing (#2303)

Every runtime, recovery operator and archive repository requires an immutable `ExecutionBinding`:
`StorageIdentity` identifies the externally selected physical restore unit and lineage, and the
nonempty tenant/`Epoch` map defines its exact execution scope. There is no default epoch, implicit
single-tenant mode, automatic adoption of database values or legacy SQL overload. An epoch change
fences only that tenant; a multi-tenant relay skips fenced tenants while serving its remaining scope.
Reconstruct the affected runtime with a newly authorized binding after cutover.

`DR_UPGRADE_SQL` applies migrations 0007/0008 after 0006, once, with traffic isolated. Fresh installs
use `MIGRATION_SQL`. The external migrator must provision the singleton `storage_lineage` row with
nonzero 16-byte target/lineage identifiers and each `tenant_epoch` row with a positive epoch before
admitting traffic. Supply these values from independently verified restore/deployment evidence.
During physical restore, install the externally selected new lineage before allowing workers back.
An old snapshot plus matching old credentials cannot prove that restore happened: fencing cannot
replace that external isolation and lineage installation step. These identifiers are coordinates,
not authentication secrets; database credentials and the product authorizer remain trusted.

All execution roles require `EXECUTE ON FUNCTION rss_transactional_messaging.check_execution()`.
Replace Outbox grants with the current exact signatures:

```sql
GRANT EXECUTE ON FUNCTION
 rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),
 rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),
 rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid)
TO application_runtime;
```

A separate DR operator role gets schema USAGE and EXECUTE on `check_execution()`,
`apply_dr(uuid,bytea,text,jsonb,jsonb,bigint)` and `read_dr(uuid,bytea)`. Give it no direct table writes,
relay ownership or inherited privileged roles. `PgDrStore::connect(config, timer, binding)` verifies
this contract; ordinary runtime profiles reject DR application authority. Migration owners administer
lineage/epoch provisioning; application roles cannot write the control tables.

For recovery, construct and product-authorize a bounded `recovery::dr::Plan` (1–500 exact members) with target,
lineage, expected tenant epoch, operation identity and both restore-evidence digests. Application
atomically compares the epoch, advances it by one, installs the selected members and writes the
exact receipt. After a crash, a newly constructed operator with the current binding can retry the exact authorized
operation or query its receipt/progress. Storage identity and tenant scope remain mandatory; SQL
checks the plan's expected epoch separately before any first application. Identical retries read the
receipt even after the epoch advances;
conflicting digests fail. The shared transaction fence is acquired before message/archive locks,
so cutover waits for already admitted old transactions; subsequent stale work is fenced.

Database-ahead recovery requires retained Published Outbox facts with matching fingerprints and
recovery versions inside their original delivery window. It retains the Published fact and tracks
DR delivery separately. The existing Outbox relay publishes the same envelope/MessageId; it never
extends the deadline or fabricates a broker acknowledgement. Pending DR members participate in
partition ordering; an expired member blocks its partition. A later epoch supersedes unfinished
members, retaining their historical progress.

Broker-ahead members name the complete tenant/message/group/contract and fingerprint. Ordinary
verified ingress and ConsumerTx remain the only route to terminal receipts; their real effects,
Inbox terminal and matching DR completion commit together. The library does not move broker cursors.
Archive claims and verified object receipts are generation-bound too: an older S3 inspection cannot
permit HOT purge after cutover; a new claim must inspect the immutable object again.

Products own physical database/broker restore, evidence authentication, ingress/cursor control,
worker replacement and orchestration. No Saga, projection or reconcile reset is implied.

Source provenance: historical extraction uses commit
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`; transaction ownership was checked against
[SQLx v0.9.0 transaction.rs](https://github.com/launchbadge/sqlx/blob/v0.9.0/sqlx-core/src/transaction.rs)
and row-lock/trigger behavior against PostgreSQL REL_17_STABLE `heapam.c` and `trigger.c`.

A relay claim call returns at most one tenant's committed batch. Calls rotate the starting tenant
and scan empty or fenced tenants; no further tenant transaction runs after a nonempty commit.
This preserves already acquired claims when another tenant fails, without promising to fill the
requested limit across tenants. Fenced skips emit only closed, low-cardinality diagnostic labels.
The definer role may lock the external storage witness through `UPDATE(singleton)`; the checked
singleton key permits a no-op only, and neither `target` nor `lineage` is writable by that role.


The DR operator also applies the explicit `PlanAction::Terminate` through the same `apply_dr`
transaction. It locks the tenant epoch, checks the exact current recovery operation/digest, inserts
a linked termination receipt and advances the epoch once. It neither rewrites member evidence nor
changes Published rows or their deadlines. Historical queries project Terminated for unfinished
members, preserving Completed and any durable block reason. The `dr_plan_action` constraint and
same-tenant foreign key enforce the recovery/termination row shapes; `dr_member_block_shape` and
`dr_member_reason` forbid a blocked row without a closed reason. Startup probes reject drift.

Use an exact-authorized termination when a blocked plan must stop, including an all-expired plan.
Create new runtime bindings for the committed epoch before resuming work. Normal successors can
then proceed because the old DR partition barrier has lost execution authority. The original
same-ID deadline is never extended; product policy decides whether later new-ID recovery is needed.
