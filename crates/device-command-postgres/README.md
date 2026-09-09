# rss-device-command-postgres

Atomic PostgreSQL companion for `rss-device-command` 0.1.0. It shares the existing
`rss-transactional-messaging-postgres::PgTransaction` with command, authority, Inbox and Outbox
writes. It owns neither a second pool nor commit/rollback. PostgreSQL 16+ and the same SQLx 0.9
version as the messaging adapter are required.

## Installation and ownership

An external migrator executes `MIGRATION_SQL` as a dedicated NOSUPERUSER NOBYPASSRLS schema owner.
The fresh `rss_device_command` schema contains only authorities and commands with dispatch
identity. Every tenant table has ENABLE/FORCE RLS. Grant the runtime role schema USAGE, table
SELECT and function EXECUTE; no direct DML, schema CREATE, owner membership or bypass privileges.
Fixed function search paths and revoked PUBLIC execution restrict the SQL seam. The component schema
allows its dedicated migration owner and one runtime database login shared by application
instances. Additional ACL principals, inherited access by other application logins and extra
functions are rejected. Database administrators remain product-owned trusted operators.
Admission checks exact policy predicates, roles and function signatures/ACLs, and rejects
additional permissive policies or changed function search paths. All five function definitions
are derived from the bundled migration: admission verifies their bodies, parameter names/types,
return types, SQL language and execution attributes, including CALLED ON NULL INPUT. Tables must
be ordinary permanent relations with no non-internal triggers or rewrite rules. These checks
run on the supplied transaction connection and never invoke a business function or repair DDL.
Restore the version-matched definitions before retrying; no compatibility bypass is provided.
Trusted administrator DDL after construction remains outside the admission guarantee. The owner must
not be reachable through SET ROLE. Products provision roles and execute migrations.

Install the separately versioned messaging schema with its own documented runtime grants. New
component installations never read, modify, migrate or adopt historical `device_commands` rows.
Future changes to this component's persisted format require append-only upgrades.

`PgStore::new(tx, outbox)` checks its schema revision, RLS and runtime privilege boundary using
an existing tenant-bound transaction. Rejections log structured `phase="probe"` and a closed
`reason` (`revision`, `relations`, `runtime_role`, `runtime_acl`, `rls_policy`, `functions` or fail-closed
`unknown`), without database names, credentials or role names. Every constructor and operation validates the transaction's private runtime provenance against
its Outbox owner. Distinct PgRuntime instances are rejected even for the same database; share
the original Arc or construct a new paired store after reconnecting. `PgRuntime` remains the connection/TLS/deadline/quarantine owner. Companion SQL is
trusted infrastructure, not a sandbox for arbitrary application SQL: do not change the tenant
setting, issue transaction control, or bypass the typed repository operations.

## Use and uncertainty

See the runnable composition in [`rss-examples`](../examples/README.md). The application supplies the configured runtime,
exact command identity, authenticated report, and immutable authored message. The store verifies
scope and persists the complete message domain/identity/fingerprint. Protocol encoding and the mapping
between payload and command intent remain product responsibilities.

- Initialize authority explicitly. Queue multiple commands using the same authority; commands
  are unique by `(tenant, command ID)`, not by device. A dispatch message can belong to only one
  command in its tenant. Same create facts replay; different facts conflict.
- A scope's authority lock serializes mutations; core Rust determines transitions and SQL saves
  them with version CAS. Authority advancement and supersession use the same transaction. Pages
  bound memory, while the original transaction deadline bounds the entire authority change.
- Outbox append and command admission commit together. Broker publish itself is outside this
  transaction and remains at-least-once. Never mint a new message ID for an ambiguous attempt.
- `recover` calls the messaging owner's `is_published` for the persisted domain/message/fingerprint. A scope may contain commands
  from several messaging domains; recovery never substitutes the current relay domain. Pending,
  in-flight and dead-lettered delivery are not device rejection. Missing dispatch or changed
  identity is an error. `published_at` is the database time this component observes durable
  confirmation, not the original broker confirmation timestamp.
- Run bounded recovery pages under `PgRuntime::local_tx`; commit before using their cursor.
  Only `Committed(page)` advances the cursor to `page.after`; all other outcomes retain the
  original cursor. The example accepts that explicit cursor instead of restarting every page.
  After commit ACK loss, reload exact commands/authority before deciding to retry. Preserve
  all `LocalTxAttempt` variants, including CommitUnknown and RollbackFailed. Dropped mutating
  futures quarantine their unresolved connection through the existing transaction owner.
- Device reports are strict. When `Transition.outcome` is OutOfOrder, a `PgConsumerEffect` returns
  a transient handler failure, so `PgConsumerTx` rolls back and no terminal Inbox receipt is
  written. Release the claim and redeliver persistently. The example decoder derives each report from the current envelope; a fixed unrelated report
  cannot be reused for other messages. Known conflict/fenced input becomes terminal rejection
  through the consumer savepoint, while storage corruption/configuration faults remain
  infrastructure failures. All successful state transitions and terminal Inbox receipts share
  that consumer transaction; no second ingress ledger exists.

Cancellation/expiry/supersession do not retract an already admitted outbox message. Old commands
may still be delivered or executed; product device/gateway enforcement must check generation and
epoch. Server-side rejection proves only that this library did not advance its current command.
Selecting an ordered device partition is a product choice: the messaging adapter's dead-letter
head blocks successors, including later commands. This component does not bypass that policy.

## Evidence and independent consumption

`device-command-postgres-integration` exercises real TLS PostgreSQL, minimum runtime grants,
concurrency, transaction rollback, suppressed commit ACK, Inbox early-report redelivery and
process kills before/after commit. The outbox settlement fixture supplies simulated confirmation;
it proves database recovery, not a real broker or device deployment. No new fault-injection
public feature is added; tests reuse the messaging adapter's integration hooks.

`python3 hack/device-command-package-proof.py --source` runs independent core-only and PostgreSQL source consumers. With
`--artifacts DIR --revision SHA` it consumes the exact candidate bundle and checks its identities.
Defaults are empty. Runtime hosting, production migrations and product T3 remain external.

Source: `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`, historical device_command.rs and migrations
0082/0087/0103; they are extraction sources, not proof that this implementation passed.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0


执行示例和输入/结果说明见 [rss-examples](../examples/README.md)。独立源码使用
`python3 hack/device-command-package-proof.py --source`；固定 artifact 使用
`python3 hack/device-command-package-proof.py --artifacts DIR --revision SHA`。
两种模式实际运行公共 API 场景，正式验收绑定同一 clean revision、版本和 archive digest；
完整故障矩阵仍归本组件 T1/T2，不把示例通过解释为生产验收或实际发布。

ref: postgres src/backend/utils/adt/acl.c@REL_16_STABLE
