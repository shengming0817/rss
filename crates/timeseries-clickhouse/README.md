# rss-timeseries-clickhouse

Recoverable, tenant-isolated ClickHouse storage with PostgreSQL admission and shared
installation resources.

The only deployment profile is ClickHouse 25.8.12.129, one node and one fixed HTTPS
origin, shared tables with tenant-specific read-only credentials, PostgreSQL 17 control
storage and synchronous inserts. ClickHouse must reach the PostgreSQL primary over
verified TLS using a dedicated account that can read only the payload-free active
attempt view. Installation and credential provisioning are external owner operations.

The core owns immutable definitions, samples and statistical semantics. This adapter
owns its independent control schema and raw/summary tables. PostgreSQL retains
identity, publication and lifecycle facts and temporary recovery payloads; ClickHouse
is the only long-term raw/summary data store. No legacy schema is read or upgraded.

`Accepted` means the complete logical batch was verified in ClickHouse and its PG
publication transaction acknowledged. Staged/partial writes remain hidden and return
`Unknown`. A missing receipt is not rollback evidence. Recover the original identity
and content after product reauthorization; never retry with a new identity.

ref: ClickHouse/ClickHouse src/Interpreters/executeQuery.cpp@v25.8.12.129-lts
ref: ClickHouse/ClickHouse src/Processors/Sources/PostgreSQLSource.cpp@v25.8.12.129-lts
ref: ClickHouse/ClickHouse src/QueryPipeline/BlockIO.cpp@v25.8.12.129-lts
ref: ClickHouse/clickhouse-rs src/query.rs@v0.15.3
ref: ClickHouse/clickhouse-rs src/lib.rs@v0.15.3

## Installation and authority

The external PG migrator adopts a dedicated NOLOGIN, NOSUPERUSER, NOBYPASSRLS schema
owner and executes `CONTROL_SQL`. Schema version 3 is fresh-install only. During installation the owner sets
`installation.max_pending_batches` to a per-namespace publication window from 1 to 16 (default 1).
All runtime owners consult the same installation row when allocating a revision. Runtime must not be a member of that owner or have
schema CREATE, installation writes, superuser, BYPASSRLS, CREATEROLE or replication.
Grant schema USAGE, installation SELECT and SELECT/INSERT/UPDATE/DELETE on the ten
control tables. All tenant tables FORCE RLS. These are trusted host credentials, not
an arbitrary SQL sandbox; products must not expose them to end users.

Provision a separate `ch_guard` login with only schema USAGE and SELECT on
`active_attempts` and `guard_identity`. Its named collection `rss_ts_ch_guard` resides
in the ClickHouse server configuration and specifies the PG primary host, port,
database and credential. Configure libpq `PGSSLMODE=verify-full` and
`PGSSLROOTCERT` on that server. No replica, dictionary or cached guard is supported.
The ClickHouse service account must have a readable home directory for libpq's
optional client-certificate lookup. The live guard checks PG primary/TLS posture and the installation identity. A guard
failure does not authorize insertion. Products own coordinated backup/restore of
both databases; independently rolled-back control state is not a supported recovery.

Read the PG installation UUID and pass it to `installation_sql`. Execute its returned
statements as the ClickHouse installer. One fixed HTTPS origin hosts `rss_ts_ch`.
Provision per-tenant SELECT-only users for raw/summaries and installation metadata,
with exact tenant row policies on both data tables and no inherited roles. The writer
has installation/guard SELECT, raw/summary INSERT and CREATE TEMPORARY TABLE for
ClickHouse's `input()` function. It has no permanent schema DDL authority. Maintenance has metadata/data
SELECT, scoped ALTER DELETE/SHOW COLUMNS, SHOW ACCESS and KILL QUERY; it cannot install schema or
change policies. `ConnectionConfig` takes separate writer/maintenance credentials; each `bind_tenant`
takes its own reader credentials. All clients verify the explicit CA and server
identity. Drain and reconstruct the affected capabilities after external reader role
changes, or the owner after installation/service-role/DDL/server configuration changes.

Construction never repairs or installs schema. The deployment fixes synchronous
inserts, a 1024-block non-replicated dedup window, fsync of inserted parts/directories,
no dependent materialized views, no automatic TTL and one local read/write server.
The fixture pins image digest
`sha256:356f0bbb1c4bade74ca32637e944d8f42109d18f13c51f991ba334f0f0749d20`.

## Resource ownership and tenant capabilities

Create one `ChOwner::new(pool, config, clock, limits, deadline)` for one installation
and PG permission role. It adopts the pool, validates PG/CH installation identity and
service privileges, and creates one HTTPS transport. Endpoint equality never merges
owners or different pools. Do not share its adopted PG pool with another resource owner;
closing it also closes host-retained pool clones. Construction does not install schema.

Call `owner.bind_tenant(tenant, reader, cursor_key, material_version, deadline)` to
validate each reader's real identity, exact SELECT grants, absent inherited roles and
exact tenant policies before returning a `ChStore`. The store implements the core
ports and `recover`/`progress`, but has no pool constructor or resource-close method.
Reader configurations share the transport, never another tenant's authentication.
`Limits.operation_permits` is the total admission capacity shared across tenants.
Set `Limits.query_threads` explicitly (use 1 for conservative operation). A public query or
aggregate acquires that many permits at once and runs its SELECTs with the corresponding
`max_threads` and `max_final_threads`. Other calls and tenant binding use one permit.
The thread setting must fit the owner capacity. Every operation also occupies one of the owner’s
`Limits.max_in_flight` request slots. `Limits.max_waiters` explicitly caps waiting calls
across tenants; zero permits only immediate admission. A full queue returns `Unavailable`
before provider IO. Immediately eligible calls, including the allowed bypass, do not consume
a waiting place. Cancellation removes its indexed ticket; grant and close notify outside
the owner mutex. When a queued head cannot fit, one fitting successor
may pass it. Subsequent releases accumulate for that head. Reader and maintenance profiles must accept their
query settings and allow the full range of positive execution timeouts, including individual
values, because each caller supplies its own deadline.
Queueing, PG acquisition, HTTP and settlement use one absolute deadline. Scan, output and
memory limits apply per query. The owner bounds admitted local calls; ClickHouse owns
remote query execution.

Materials are immutable. Products admit a new version, switch their references, then
`retire(deadline)` the old capability. Retirement permanently refuses new calls and
waits for admitted calls before releasing materials; it leaves other capabilities and
the pool usable. Versions identify materials, not an epoch registry or automatic
revocation of other capabilities. Cursors retain their existing domain/request/installation
binding: the same key can continue valid cursors, while replacing the key invalidates them.

Keep the owner alive while using stores. Stores hold only a weak resource reference;
dropping the owner stops admission even while an admitted call still holds resources.
Call `owner.close(deadline)` to stop admission, drain calls, close PG and release HTTP
clients. A timed-out or cancelled close/retire stays closed to new calls and can be
awaited again. Retirement still works after owner drop. Completed cleanup is idempotent.
INSERT responses are awaited in the admitted call; there is no detached INSERT response
worker. Releasing clients is not evidence of synchronous Hyper task/socket termination,
remote query termination or rollback. Uncertain external effects still require recovery.

## Recovery, reads and maintenance

Each stream admits one pending batch inside the installation's per-namespace window.
A full window or busy stream returns `Unavailable` for a new batch. Existing identities
remain recoverable. Independent streams may project out of order. `progress` reports
`Verified` when ClickHouse verification finished but an earlier revision still blocks
publication. Such writes return `Unknown` and cannot yet produce a successful receipt.
Verification releases each batch’s recovery payload. PG publishes up to 16 consecutive verified
batches atomically. Affected summaries carry the first revision that invalidates them, so the
publication boundary also switches summary visibility without rewriting summary rows. A stalled head needs explicit
recovery. `recover(scope, authority, deadline)` selects the oldest pending revision and
reauthorizes its original content; retrying the original batch uses the same protocol.
Each raw attempt owns one revision and query ID. Replacement and publication revoke
and drain that attempt before clearing it. Maintenance reports `PendingWrite` until
the namespace has no unpublished batches.

Raw values retain typed canonical JSON, exact integer timestamps/sequences, original
receipt time and digest. Integers never round-trip through float. History and latest
use query-time deduplication, canonical ordering and authenticated keyset cursors.
Raw and aggregate pagination fix their publication ceiling across calls. History and
latest consult the namespace fence generation. Aggregate continuations bind the exact
stream, series, range and predecessor dependencies, including deletion/restoration and
stream lifecycle. Unrelated publication does not interrupt pagination. Summary references
record the maximum revision of their actual inputs, including the predecessor; equivalent
recomputations remain usable at the old ceiling. Otherwise the reader computes from the
same raw prefix within its existing budgets.

A short PG read-only snapshot selects dependencies and references, then releases its
connection before ClickHouse IO. Another short snapshot rechecks control dependencies and
only the summary objects whose reads were attempted, including failed reads. Changed cache
references permit one retry at the same ceiling and absolute deadline. A changed aggregate
continuation dependency or repeatedly unstable reference returns `SnapshotInvalidated`:
restart from the first page. `HistoryExpired` means required history is unavailable;
`InvalidCursor` covers invalid authentication, expiry or installation binding. A repeatedly
unstable first page returns `Unavailable`; stable budget exhaustion stays `BudgetExceeded`.
`Limits.max_fences` bounds namespace frontiers
independently of sample budgets. Scan, output, memory and
time budgets fail explicitly rather than returning a successful truncated result.

Recompute persists bounded core-fold checkpoints and publishes immutable ClickHouse
summary objects through PG references. Compatible adjacent sufficient statistics can
be merged; means are never averaged. Late samples and deletion/restoration invalidate
affected summaries. Pruning protects requested summaries, predecessor/lookback input
and live restore windows. Expired receipts retain identity fences until stream reclaim.
Definition retirement and stream closure are irreversible admission decisions.

Delete immediately hides a range once acknowledged, and Restore matches the exact
fence before its deadline without reopening writes. Physical cleanup first revokes
relevant PG permits, drains their exact ClickHouse query IDs, then deletes bounded
identity sets. Late network requests must reread the revoked permit inside their
INSERT pipeline, so cannot resurrect cleaned rows. Incomplete steps retain durable
progress. Completion concerns active stored data, not backup/media erasure.

Unknown effects never become a confirmed rejection. The caller's one absolute Deadline
covers pool acquisition, locks, transport and settlement. Unsettled PG connections are
quarantined. The product owns process/task termination and recovery scheduling.

## Public consumers and proof

The examples `timeseries-clickhouse-schema` and `timeseries-clickhouse` consume only
public APIs: two tenants share one owner, and retiring one leaves the other usable.
`hack/timeseries-package-proof.py --source --scenario clickhouse` runs the
same behavior with an isolated workspace; `--artifacts DIR --revision SHA` consumes
only fixed archives and their declared closure. PostgreSQL is a required control
service, but `rss-timeseries-postgres`, messaging and runtime crates are not dependencies.
Candidate validation and actual registry publication remain separate release facts.
