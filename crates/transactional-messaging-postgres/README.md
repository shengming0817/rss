# PostgreSQL transactional messaging

`rss-transactional-messaging-postgres` 0.1 is an experimental, independently packaged adapter.
The core remains provider-neutral. Installation, role provisioning, business tables, deployment,
database operations and operator recovery belong to the consumer.

Trusted companion infrastructure borrows `PgTransaction` through `with_connection`; application
handlers receive typed repositories. The borrow bounds reference lifetimes, not arbitrary SQL:
trusted code must not issue transaction-control SQL or change tenant settings.

Every operation consumes one injected monotonic deadline. Unacknowledged transaction settlement
quarantines the connection. PostgreSQL time, not the application clock, decides durable lease
ownership and same-ID delivery expiry. No legacy schema is read, migrated or adopted.

## Installation and privileges

Use an external migrator to provision a `rss_tmsg_relay` role with `NOLOGIN NOBYPASSRLS`, then
execute `migrations/0001_create_transactional_messaging.sql`. The migrator must be able to transfer
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

Construct `PgRuntime::connect(config, timer)` with the same monotonic `ExecutionTimer` used by the
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
use rss_transactional_messaging::{
    message::{MessageEnvelope, MessageId, MessagingDomain},
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    policy::{DeliveryBudget, ExecutionTimer, OperationDeadline},
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
async fn compose<C: ExecutionTimer + Clone + 'static>(config: PgConfig, timer: &C,
    domain: MessagingDomain, budget: DeliveryBudget) -> Result<(Arc<PgRuntime>, Arc<PgOutboxStore<()>>, PgConsumerTx<Effect>), PgError> {
    let runtime = Arc::new(PgRuntime::connect(config, timer.clone()).await?);
    let outbox = Arc::new(PgOutboxStore::new(runtime.clone(), domain, budget)?);
    let consumer = PgConsumerTx::new(runtime.clone(), Effect);
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

## Historical source ledger

Source: `baseline/pre-community-core-20260902`.

| Source | Disposition and reason |
| --- | --- |
| `cotx/settlement.rs` | Keep borrowed connection lease and ACK-only reuse; use core `LocalTxAttempt`, remove duplicate outcome enums and product metrics. |
| `pool.rs` | Retain pool lifecycle, TLS verification and bounded acquisition; replace product probes with own-schema/effective-permission checks. |
| `inbox.rs`, `cotx/eventing.rs` | Adapt claim/reclaim, lease CAS and receipt to core identities and fingerprint. |
| `outbox.rs`, `outbox/settlement.rs`, migrations 0057/0060/0064/0066 | Retain atomic claim, frozen retry window, partition head gate and closed settlement; dedicated schema and core digest replace product metadata. |
| `consumer_tx.rs` | Retain private commit proof and atomic effect/receipt; remove Audit/Settings handlers in favor of trusted static effect. |
| Product migration chain, CDC, redrive, reconcile, fault-matrix product combinations | Exclude: not v0.1 messaging ownership. Fresh installation only, no compatibility bridge. |

Receipt retention must strictly exceed the 24-hour automatic window plus safety margin. No
automatic cleanup, redrive, resolve, CDC or application DLQ is supplied. A dead-letter partition
head continues blocking its successors.
