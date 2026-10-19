# rss-timeseries-postgres

PostgreSQL 16 atomic time series admission, durable receipts, definition snapshots and
bounded raw history/latest, aggregation and lifecycle operations. TimescaleDB is not required. Products own
metric meaning, authentication, resource authority, source/generation activation,
TLS/credentials, migrations, partitions and retention policy.

## Install and admit

Install the current schema once as a dedicated `NOLOGIN NOSUPERUSER NOBYPASSRLS`
owner. Only fresh installations are supported; no legacy schema, data import or
upgrade entrypoint is retained. The installation profile and runtime profile must
match exactly. Producers retain the existing typed definition/sample/batch format.
No migration or repair runs inside `PgStore::new`.

The owner explicitly calls `rss_timeseries.create_partition(lo, hi)` for each
nonnegative half-open microsecond interval. Creation is transactional, creates the
indexes and child RLS policy, and rejects overlaps. There is no default partition,
runtime DDL, scheduler or automatic backfill. Every admitted observation must have
a prepared partition; a missing partition rolls back the entire batch. Arbitrary
nonnegative signed-64-bit observation times are supported when provisioned, including
`i64::MAX - 1`; `i64::MAX` is the exclusive upper bound.

Provision a separate runtime login with no owner membership, superuser, BYPASSRLS,
CREATEROLE, replication, schema CREATE, table/column writes or grant/admin options.
After provisioning partitions, grant:

```sql
GRANT USAGE ON SCHEMA rss_timeseries TO application_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_timeseries TO application_runtime;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_timeseries TO application_runtime;
REVOKE EXECUTE ON FUNCTION rss_timeseries.create_partition(bigint,bigint)
  FROM application_runtime;
```

Runtime can read and execute the restricted mutation functions, but cannot directly
INSERT/UPDATE/DELETE/TRUNCATE or provision partitions. All tables, including children,
force RLS. Functions fix their search path; PUBLIC has no component permissions.
`PgStore::new(profile, connections, clock, limits, cursor_key, deadline)` checks the PostgreSQL 16
catalog, effective reachable-role permissions, functions and child partition policies.
DDL/role changes require drain and re-admission. Unknown schema or unsafe privileges
fail closed; schema comments alone do not prove admission. The database engine,
owner/migrator and credential-holding Rust host are trusted infrastructure, not a SQL
sandbox. Arbitrary holders of runtime credentials can choose session tenant settings;
never expose these credentials or SQL functions to end users.

Every public operation requires an `Authorized<T>` produced by the product's Authority.
The host reauthorizes each request after authentication and checks current revocation
and resource policy. The adapter derives transaction-local tenant settings only from
that authorized request. Claimed tenant/source fields and content digests are not
credentials. Missing tenant context in direct SQL sees no rows and mutations fail.

## Definition and atomic admission

Register exact immutable definitions before writing. Registration serializes on the
key head, verifies CAS for new versions and uses core compatibility checks. Existing
exact-version/content retries return their original state even after newer versions
exist. Retirement is irreversible, preserves historical interpretation, and competes
with new sample admission on the exact definition row.

Definitions, stream locks, receipts, sample identities and time-partitioned raw
samples remain the admission owners. Lifecycle adds namespace coordination, fences,
current maintenance state, requested summary ranges and sufficient statistics.
A namespace lock precedes stream and definition locks, covering resource selections
and streams created concurrently. Queries take a shared namespace lock for a consistent
operation; pagination is still live across calls. Mutation functions remain the sole
runtime DML surface. Numeric values and snapshots retain typed JSON bytes without an
integer-to-float roundtrip. Text ordering uses C collation.

An entire batch commits identities, raw samples and its receipt together. Same batch
ID/content returns `Replay` with the original counts, receipt time and replay horizon;
changed content conflicts. Cross-batch sample replay preserves first receipt time
and contributes to replayed_samples. Any conflict rejects the whole new batch.
Retirement permits already accepted sample replay, including in a new batch, but
rejects new samples. Batch identity is checked before retirement.

`Limits::replay_micros` is the explicit minimum replay guarantee from first admission.
Elapsed time does not expire a retained receipt; ExpireReceipts performs the authorized
bounded transition after that guarantee. Active streams retain identity/digest fences
so expired receipt IDs conflict or return Expired instead of admitting data again.
Admission receipts do not promise permanent raw visibility. Replaying an accepted
sample never reconstructs a physically pruned row.

## Unknown outcomes and lifecycle

Only COMMIT acknowledgment produces confirmed acceptance. Confirmed rollback permits
an error. Unconfirmed commit/rollback or cancellation with possible effects yields
`Outcome::Unknown`; the connection is quarantined and closed, never returned as clean.
Dropping SQLx's transaction is not treated as rollback acknowledgment. There is no
hidden recovery loop or new-ID retry. After reauthorization, read the original
ReceiptQuery or repeat the exact original Batch. A matching durable receipt settles
the result; a digest mismatch conflicts; `NotVisible` is never rollback evidence.
Confirmed receipts contain only immutable admission facts. Query results report
availability independently of acceptance.

The injected monotonic Clock shares the caller Deadline domain. One absolute budget
covers acquire, lock, statements, decoding and settlement, with server statement/lock
watchdogs. PostgreSQL provides persisted UTC receipt timestamps. `close(deadline)`
closes the adopted pool (including its clones) and waits for borrowers within budget;
the host owns worker/task shutdown. The `integration` feature only exposes one-shot
settlement faults and changes no normal storage guarantees.

## Query and cursor contract

History selects `[start,end)` and sorts by `(series digest, source, generation,
observation time, sequence, sample ID)`. Latest chooses the greatest observation tuple
per exact series/stream **inside the requested window**, then orders the groups.
Neither mode chooses the product's authoritative source. Late data enters history
without moving a stream's latest observation backwards.

Pagination is live keyset pagination, not an MVCC snapshot across requests. New rows
can appear ahead of the cursor or be skipped behind it. Already-returned samples do
not repeat; Latest advances by series/stream so updates cannot repeat a visited group.
A cursor binds the full query (including budgets), V1 provider format, installation
identity, last position and original expiry with HMAC-SHA256. The host supplies a
32-byte secret shared only by the same storage deployment. The same configuration
supports restart/multi-instance continuation; changing the key invalidates old cursors.
There is no key registry, old-key fallback or server-side cursor session.

Positive request point/series budgets must fit explicit host Limits. Page byte limits
bound encoded sample payloads; they are not exact heap limits. SQL returns at most
max_points+1 rows; decoding streams rows with a bounded lookahead. Each stored sample
is at most the core 4 MiB ceiling. Point/series boundaries produce a cursor; byte or
time budget failure returns an error rather than a successful partial page. SQL
watchdogs bound scanned work, including Latest selection/sorting; LIMIT alone does
not bound the scan. Receipt reconstruction verifies structural fields; the trusted
provider still owns the truth of durable admission.

## Proof and examples

`timeseries-postgres-integration` uses real PostgreSQL 16 TLS, separate owner/runtime
roles, concurrent writers, cross-partition conflicts, retirement, real process kills,
commit acknowledgment loss, connection quarantine, permission drift and bounded queries.
`crates/examples` provides `timeseries-install` and `timeseries-pg`; fixture input arrives
on stdin and includes the host's cursor secret. `hack/timeseries-package-proof.py`
runs isolated core/PG consumers with explicit `--source` or exact `--artifacts DIR
--revision SHA`, optionally `--scenario core|pg`. Artifact proof is not actual publication.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: PostgreSQL 16 declarative partitioning and row security

## Bounded aggregation and maintenance

Register a summary range with Recompute using an explicit `SummarySpec`. Each core-fold call
processes at most `MaintenanceBudget.rows` input rows and persists the current fold/checkpoint;
no scheduler or per-step journal is created. Input revisions restart interrupted folds
after concurrent changes. A completed bucket is published atomically. New samples
invalidate affected buckets (including the Counter/state lookahead); replays do not.
Queries use compatible current summaries, otherwise the same arithmetic over raw input.
Partial edges cannot be interpolated after raw retirement and return HistoryExpired.
Output counts include nested state segments; byte, scan and deadline caps remain active.

AdvanceCutoff permanently rejects new observations before the chosen boundary. Prune
protects unfinished requested summaries, Counter/state boundary input and unexpired
restore windows. It hides the pruned range before bounded physical removal, while
completed retained summaries remain queryable. The raw frontier may lag the requested
cutoff by the greatest necessary Counter/state lookback. ObservedOnly transitions
also retain their last predecessor, independently of duration coverage. If a newly
requested computation has already lost required boundary input, it returns HistoryExpired. Raw and summary cutoffs use
observation time; ExpireReceipts uses first acceptance time and never shortens replay_until.
Receipt expiry is a stream operation, so a series-scoped grant cannot erase unrelated
series' batch admission records.

Delete immediately hides rows and invalidates summaries; its write barrier survives
Restore. Restore requires the original selection/window/fence before restore_until
(database UTC). Overlapping deletion fences remain independently effective. Expired
windows are physically removed by Prune after its cutoff/dependency checks. CloseStream
prevents new batches, and Reclaim removes identities only after data and replay
obligations end. Stream closure remains durable after reclamation.

A maintenance plan ID binds its complete request. Reusing it with different content
conflicts; retrying an old step returns current progress without repeating its effects.
Resume after token expiry by reauthorizing the identical request and omitting the token.
Aggregate and maintenance tokens have separate authenticated domains. Fence scans filter the relevant selection/window/kind before applying output
budgets; repeated pruning merges the retained frontier. Summary-range scans and
relevant fence output obey host point/byte/time budgets and fail explicitly when
those limits are insufficient. Maintenance Blocked reasons are actionable prerequisites,
not success or automatic policy changes.


## Explicit TimescaleDB profiles

Enable the additive `timescaledb` feature, then choose a `StorageProfile`. All stores
share the same writer, receipt, transaction, query and lifecycle engine. Installation
uses `profile.installation_sql()`; the host runs it once as the schema owner after an
administrator installs the extension. The installer creates a component-owned private
`rss_timeseries_chunks` schema for raw chunks. Runtime must have no direct or inherited
USAGE/CREATE on this schema. Timescale copies parent SELECT ACLs to newly created chunks
without child RLS; private chunk placement therefore protects even future chunks.
The extension's own internal schema remains available for its metadata APIs. Drain
existing pools and prepared statements before role/DDL changes and re-admit afterward.

No existing deployment migration is supported.
The `timeseries-schema` example emits inspectable SQL for a minimal explicit profile.

| Profile | Isolation | Raw storage | Aggregation |
| --- | --- | --- | --- |
| PostgreSQL | shared FORCE RLS | native partitions | core fold |
| TimescaleSharedRls | shared FORCE RLS | rowstore hypertable | core fold |
| TimescaleDedicatedTenant | fixed tenant database/role/pools | hypertable, explicit columnstore conversion | native I64/U64 Gauge at declared resolutions; core for other cases |

The supported extension is exactly **TimescaleDB 2.30.2**, on PostgreSQL 16.6–16.x.
The fixture pins `timescale/timescaledb:2.30.2-pg16` to manifest digest
`sha256:6f139d56042989bd35f50ba5986e492cd32e35cc6778c50be2659add298dc09f`
(PG 16.15 in the inspected image). SQLx remains the only client; its exact version is
owned by Cargo.lock (currently 0.9.0). Other extension versions are rejected pending
explicit validation. Component schema upgrades require a future explicit implementation;
there is no automatic ALTER EXTENSION, repair, old reader or profile switch.

`StoreConnections::Runtime` is required for PG/shared profiles. Dedicated requires
`StoreConnections::Native` with separate runtime and maintenance pools. The maintenance
pool must use the trusted NOLOGIN schema owner via an explicitly authorized login role;
construction verifies both pools point to the same installation. Closing the store closes
both adopted pools. Products own pool routing and per-database credentials. The raw
hypertable has no RLS in this profile, so database isolation is mandatory: immutable
fixed-tenant CHECK constraints, restricted mutation functions and the Rust tenant gate
reject other tenants. Ordinary metadata tables retain RLS. Never expose either pool to
untrusted callers or use these credentials as a SQL sandbox.

For Timescale runtime grants, use the same SELECT/EXECUTE grants as above, but revoke
`rss_timeseries.integer_now()` instead of the absent `create_partition`. Dedicated also
revokes `rss_timeseries.project_gauge()`. No runtime gets table writes, schema CREATE,
owner membership, or maintenance-pool credentials. Chunk creation belongs to the
hypertable owner. Extension objects, schema fingerprints, chunk permissions, native
views and columnstore settings are checked during admission; drain and re-admit after
role or DDL changes. Missing extension/capabilities and unsupported combinations fail
closed. Shared RLS does not support native CAgg or columnstore in this pinned version.

Dedicated installation declares 1–32 distinct positive microsecond resolutions.
Integer Gauge native aggregates retain exact numeric sum/count/min/max and missing
quality, imported through the core's validated `GaugeStatistics` boundary. F64 keeps
canonical ordered arithmetic; Counter/state keep the existing boundary-aware fold.
The native feature does not change those metric semantics or authorize float coercion.

Native Recompute uses the existing plan/checkpoint/token and canonical summaries:
update source visibility under the namespace lock, refresh a whole bucket outside a
transaction block, then verify revision and phase before publication. Native SQL output
is never returned directly. Each step updates at most `MaintenanceBudget.rows` source
rows or refreshes at most one bucket (within `MaintenanceBudget.buckets`); bucket scans
are bounded by statement/lock timeout and the caller deadline, not a row-count claim.
Timescale's internal commits do not prove component publication. Cancellation or lost
acknowledgment leaves the phase retryable and returns Unknown when effects are possible.

Delete/Restore fences hide results immediately; pending source projection and refresh
cannot expose stale cached summaries. Prune saves retained canonical summaries before
raw removal. Recompute rejects pruned input. The same Prune plan subsequently cleans
native materialization caches with bounded bucket refreshes; that cleanup **never imports
or overwrites canonical retained summaries**. Thus native buffers do not indefinitely
retain pruned contributions, while retained query results survive raw retirement.

`convert_raw_chunks(window, max_chunks, StorageFormat, deadline)` is host-owned physical
administration, available only with dedicated owner credentials. It converts at most
32 complete raw chunks in an explicit interval and is idempotent on repetition. Unknown
may mean only a subset converted. Conversion does not alter logical retention or
resource authorization; it must not be exposed as an end-user maintenance endpoint.
CAgg materializations remain rowstore. No background refresh/compression/retention job
is installed, and no whole-chunk deletion bypasses the component's row-level lifecycle.

The hypertable base is Apache-2 functionality; native continuous aggregates and
columnstore use Timescale License (TSL) code. The tested image is Community, not an
Apache-only build. Products own deployment/distribution license compliance and must
review the pinned upstream LICENSE and `tsl/LICENSE-TIMESCALE`; this adapter does not
promise unrestricted DBaaS use. Source and fixed artifact consumers cover core, PG-only,
Timescale shared and Timescale dedicated separately; actual publication remains separate.

ref: timescale/timescaledb b0977bf2d3a5014ee870247be09bc19d3e9f7a5f
ref: tsl/src/continuous_aggs/common.c, tsl/src/continuous_aggs/refresh.c,
tsl/src/compression/create.c, src/compat/compat.h and LICENSE at 2.30.2
