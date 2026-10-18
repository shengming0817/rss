# rss-timeseries

Typed, provider-neutral time series contracts. Custom metric keys and finite state
members are runtime data. Products own authentication, active sources/generations,
metric meaning, retention, coverage policy and scheduling. This crate owns validated
values, immutable definitions/samples/batches, content identity and bounded ports.

## Values and definitions

Gauge supports i64/u64/finite f64; Counter supports the same numeric representations
with nonnegative values and explicit cumulative/delta intervals. Boolean and finite
state values are not numbers. Missing and Failed readings are not zero/false.
Timestamps are nonnegative signed-64-bit Unix microseconds; sub-microsecond conversion
fails rather than truncating. Negative float zero normalizes to positive zero.

A definition pins tenant/namespace/key/version, unit, metric kind and dimension
rules. Same version/content is replay; changed content conflicts. A newer version
may add optional dimension keys or state members and widen budgets. It cannot change
unit, numeric type, temporality, required dimensions or existing state identity.
Use a new key for changed semantics. State IDs are their meaning: no mutable labels
or aliases are part of this contract. Retirement rejects new data but preserves
exact previously accepted replay and historical interpretation. Products must not
remove referenced definitions. There is no latest-version reinterpretation.

Identifiers are exact 1–256 UTF-8 bytes without controls. Definitions allow at most
64 dimension names and 256 state members; each dimension value is at most 256 bytes,
and the declared total dimension budget is at most 32768 bytes. Batches are nonempty,
limited to 4096 samples and 4 MiB encoded JSON. Host budgets may be stricter.

Series pin a complete immutable definition snapshot. Storage adapters can normalize
snapshots by digest; there is no separate core registry. Samples bind that series to
one source/generation, stable ID, source sequence, observation time, interval and
reading. Counter intervals end at observation time; delta intervals must be positive,
while a zero-width cumulative interval can express an initial reset observation.
Gauge/state intervals are collection provenance, not evidence of continuous validity.

## Identity and encoding

Sample IDs are unique within tenant/namespace/source/generation, including across
series and batches. Same identity/content replays; changed series/time/value conflicts.
Batch IDs fix the complete ordered sample list. Duplicate IDs within a batch fail.
Cross-batch sample replay does not double-count or refresh original receipt times.
Tenant/generation are identities, not evidence of authentication or activation.

V1 SHA-256 hashes domain-separated typed serde JSON. Fields have declared order,
dimension maps/state-member sets are sorted, numeric variants are tagged, and integers
never pass through f64 or serde_json::Value. No provider receipt time or progress is
hashed into producer content. The digest is not a signature or durability proof.
This first encoding has no legacy decoder or fallback. Once persisted, its identity
is protected independently of the experimental Rust API.
`Batch::decode` enforces byte limits before parsing; all nested validated values use
the same constructors as authored values. Hosts must bound transport input before
any direct generic serde decode; constructors still enforce semantic invariants.

## Operations

| Kind | Operations | Restrictions |
|---|---|---|
| Gauge | history/latest, min/max/sum/count/mean | no default fill/interpolation |
| Cumulative counter | history/latest, increase/rate | same source/generation/start; never sum readings |
| Delta counter | history/latest, sum/rate | report overlap/gaps, no implicit interval splitting |
| Bool/state | history/latest, timeline/transitions/coverage | no numeric aggregation; duration requires explicit hold limit |

Integer sums retain checked i128/u128; means retain sum/count, rates increase/duration.
Floating results must remain finite. Aggregation execution belongs to adapters, not
this crate. Results report validity, gaps/overlap/reset boundaries, resolution and
refresh progress; empty observations are Missing. No averaging bucket averages.

History/latest accepts exact series or bounded resource/key filters. Each request
includes tenant/namespace, a positive half-open time range, max series/points and an
absolute deadline. Results retain each source/generation/version. Latest is the
maximum (observation time, source sequence, sample ID) within the requested range,
not arrival order. Resource results never select a product's authoritative source.
Aggregation accepts an exact series/stream only; no implicit cross-version mixing.

## Provider and authorization boundary

The product implements Authority. Authorized inputs cannot be constructed unchecked
and must be obtained afresh at each host operation. Storage implementations remain
trusted: they enforce tenant isolation, concurrent identity checks, definition CAS,
retirement, deletion fences and budgets. Types do not prove external effects.

Mutation errors certify rejection with no effects. Unknown means effects may exist;
resolve or retry the same fixed identity/content, never silently generate another ID.
Receipt lookup NotVisible is not rollback evidence. Durable acceptance, raw visibility
and aggregate progress are independent. Original receipts are immutable on replay.

PostgreSQL may atomically commit batch/sample identities and receipts; commit response
loss still needs settlement. TimescaleDB can reuse that admission while aggregation
refresh progresses separately. ClickHouse requires an explicit reliable admission/
recovery configuration; dedup tokens or background merges alone cannot supply content
conflict detection, replay outside a window, or correct prior aggregate contributions.
Adapters declare their atomicity and replay horizon and reject unsupported operations.
This core does not assert those backends are implemented or validated yet.

Maintenance steps are bounded host calls for recomputation, layered pruning, deletion
or explicit fenced restoration. Fixed plan identity and bound continuation prevent
scope changes; providers must also authenticate tokens and persist progress/fences.
Expired receipts alone cannot authorize resurrection. Production policy, database
schema, transactions, scheduling and recovery execution belong to their owners.

## Validation

Public contract tests and the timeseries-core example prove T1 semantics. Independent
source/artifact consumers execute that same example with an isolated dependency graph.
No memory fake stands in for adapter durability, concurrency, restart or transaction
T2 evidence. Database providers are subsequent work items #2810–#2813.
