# rss-saga-postgres

PostgreSQL 16+ implementation of the `rss-saga::Store` port. Instance state, journal, protected
receipts and lease fencing share one transaction. The core executor owns actions and cryptography;
the adapter only persists protected receipt records.

## Installation and ownership

An external migrator executes the version-matched `MIGRATION_SQL` as a dedicated
NOSUPERUSER NOBYPASSRLS schema owner. The fresh `rss_saga` schema contains only instances, journal
and step_receipts. Provision a separate runtime login with schema USAGE, table SELECT and EXECUTE
on the component functions; grant no direct write, REFERENCES or TRIGGER privileges (including column grants) and no owner membership.
Tables ENABLE and FORCE RLS, functions have fixed search paths, and PUBLIC privileges are revoked.

The application owns role provisioning, TLS configuration, migration execution and business tables.
The tenant setting isolates queries inside trusted application code; it does not authenticate a
holder of database credentials. Runtime SQL must not change identity or disable security policy.

This version supports fresh installation only. It does not adopt historical `public.saga_*` tables,
run an old migration chain, import active instances or retain an alternate schema. Future component
migrations must be append-only and preserve persisted identity. There is no retention sweeper;
instances, definitions and receipts remain retained, including failed compensation.

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

`PgStore::new` checks the component storage/role contract and adopts the supplied pool. Configure
verified TLS and the runtime login before passing it in. All clones refer to the adopted pool.
`close(control)` stops pool admission and waits within the caller's deadline; its outcome
separates a drained pool from interrupted waiting. Cancel/join workers before closing the store.
The optional `rss-runtime` feature implements the existing `ManagedResource` lifecycle contract.

Claiming locks the instance before checking database time and increments its epoch. Every
transition checks tenant, token, epoch, expiry and expected journal revision. SQL enforces legal
forward/compensation transitions and consecutive attempts. Deferred constraints pair each
forward completion with exactly one protected receipt. Duplicate registration accepts only the
same complete definition; contract/version metadata cannot be replaced for later instances.

Commit errors produce `CommitUnknown`; failed rollback produces `RollbackUnknown`. Interrupted
transactions quarantine the pool connection. The executor stops, then recovers with a new claim
and locked consistent snapshot. Lock acquisition serializes with the earlier transaction: a
plain read that sees no row is not proof of rollback. An acknowledged receipt resumes at the next
step; an unfinished intent probes its external effect. Partial/inconsistent state fails closed.
No special blind retry loop, second receipt writer or raw business transaction API exists.

The implementation preserves canonical effect keys and receipt v1 encoding. Cryptographic receipt
verification happens in the core against the expected instance/definition, not against AAD hydrated
from the row. Randomized ciphertext equality is not a deduplication contract.

A complete typed Step, injected timer, cancellation token and authenticated protector composition
is shown in the [core README](../saga/README.md#complete-typed-composition). Declare the direct
`rss-contract`, `rss-data-protection`, `tokio`, `tokio-util` and chosen AEAD dependencies in the
application manifest; pass this adopted `PgStore` as that example's `S`.

## Verification

`saga-postgres-integration` uses real TLS PostgreSQL and Redis fixtures. It covers RLS/direct-write
rejection, lease takeover, compensation pause/resume, commit ACK loss, pending commit interruption,
receipt corruption, and killing an executor process both before and after its remote effect becomes durable. Restart uses the short lease expiry, not an administrator edit.
Settlement loss is injected by a private test protocol proxy, never a production API or feature; defaults remain empty. Actual `.crate`
artifacts are independently consumed by `hack/saga-package-proof.py`. The candidate workflow passes its existing archive directory and exact revision to that script; checksum/revision checks precede consumption. Default, no-default, standalone `rss-runtime`, and all-feature combinations are verified.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: baseline/pre-community-core-20260902 adapters/postgres/src/saga.rs@5b63e10a1
ref: baseline/pre-community-core-20260902 adapters/postgres/migrations/0083_create_saga_step_receipts.sql@5b63e10a1
