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
owner and executes `CONTROL_SQL`. Runtime must not be a member of that owner or have
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
`max_concurrent_operations` limits complete calls and tenant admission across this owner;
all queueing, PG acquisition, HTTP work and settlement use the original absolute deadline.
Per-call scan/output/memory limits remain explicit and do not become process-wide quotas.

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

Each namespace admits at most one unpublished batch. Reauthorization and an explicit
`recover` call advance the same state machine used by `write`; there is no worker,
automatic new-ID retry, queue service or lease controller. `progress` distinguishes
Prepared from Published without redefining immutable receipts. Producer identity,
order and content remain fixed; transport attempts have distinct identities.

Raw values retain typed canonical JSON, exact integer timestamps/sequences, original
receipt time and digest. Integers never round-trip through float. History and latest
use query-time deduplication, canonical ordering and authenticated keyset cursors.
Raw pagination fixes its publication ceiling but does not promise a cross-call
lifecycle snapshot. Queries hold a namespace shared lock while consulting ClickHouse;
publication and lifecycle changes take its exclusive lock. Scan, output, memory and
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

`PendingWrite` means recover the already prepared batch before attempting maintenance.
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
