# rss-timeseries-postgres

PostgreSQL 16 atomic time series admission, durable receipts, definition snapshots and
bounded raw history/latest, aggregation and lifecycle operations. TimescaleDB is not required. Products own
metric meaning, authentication, resource authority, source/generation activation,
TLS/credentials, migrations, partitions and retention policy.

## Install and admit

Execute `MIGRATION_SQL` once as a dedicated `NOLOGIN NOSUPERUSER NOBYPASSRLS` owner.
Fresh installation runs `MIGRATION_SQL` (the ordered migration set). Existing V1
installations run only `UPGRADE_V2_SQL`, with old writers drained, then reapply grants
and admit the current adapter. The runtime accepts only V2; there is no dual reader.
Producer V1 definition/sample/batch bytes and hashes remain unchanged.
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
`PgStore::new(pool, clock, limits, cursor_key, deadline)` checks the PostgreSQL 16
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

Register a summary range with Recompute using an explicit `SummarySpec`. Each call
processes at most the request item budget and persists the current fold/checkpoint;
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
