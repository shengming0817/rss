# rss-observation

Observation V1 receives bounded reports from offline, unreliable, independently ordered producers.
It owns batch identity, byte-exact replay, snapshot/delta integrity and the atomic persistence port.
`rss-observation-postgres` implements that port. The core has no provider, command, telemetry,
collector, Inventory or projection dependency.

## Admission and ownership

The product implements `Authority` using authenticated context. `VerifiedBatch::verify` requires
submission authority for the exact `Scope` and `Coverage`; `ReadGrant` and `LifecycleGrant` require
separate read and lifecycle decisions. These private-field capabilities do not authenticate a
network peer themselves. Reauthorize for each external request; do not cache grants across product
revocation. The provider is trusted infrastructure: `Record::from_durable` verifies transition
semantics but cannot prove that an arbitrary provider really committed a database transaction.

```compile_fail
use rss_observation::VerifiedBatch;
fn forge() -> VerifiedBatch { VerifiedBatch {} }
```

```compile_fail
use rss_observation::{Epoch, Registration};
fn mix(epoch: Epoch) -> Registration { epoch }
```

`Scope` binds tenant, object, registration instance, source, dataset and producer epoch. Registration
and producer epochs are different types and have no relationship to command fencing. A product
lifecycle activation uses an expected object lifecycle revision; receipt submission cannot activate
a stream. Epoch/registration reuse is rejected. A retry of a historical activation can return its
historical revision without changing the active stream. Multiple sources maintain independent
integrity; the product owns source preference and conflict resolution.

## Report contract

`Batch::new` accepts `Body::Snapshot`, `Delta`, `Partial` or `Failed`. Content is opaque bytes under
`Coverage::format`; the coverage ID/version and collection definition reference are product-owned.
All identifiers are nonempty, at most 256 UTF-8 bytes, without control characters. V1 admits at most
1,000 unique keys, 64 KiB per value and 4 MiB of canonical encoded JSON. Binary values are JSON byte
arrays in this durable format, so their encoded size counts toward the 4 MiB bound. Snapshot values
must be upserts; delta deletion uses `Change::delete`. Object order is normalized before hashing.

The domain-separated SHA-256 fingerprint covers the complete trusted scope and normalized report,
including IDs, kind, coverage, definition/format, sequence/predecessor/baseline, observed time and
content bytes. A producer digest is never authoritative. A complete bounded body plus structural
validation proves that the declared batch arrived intact; completeness and truth of the device's
collection are assertions admitted by the product's trusted authority, not inferred from a hash.
Fragments, unknown versions, duplicate keys and unbounded bodies are rejected before persistence.
No network endpoint or multi-version decoder is supplied.

## Synchronization

There is one active coverage/definition baseline per stream, and sequence is a producer-supplied
`u64` local to that stream. A successful complete snapshot (including empty) establishes its batch
ID as the baseline. Absence only replaces facts in the declared coverage; facts outside it remain
untouched. Changing coverage or definition requires a new complete snapshot. Delta references the
exact snapshot ID under this same scope and coverage, with `previous == cursor` and
`sequence == previous + 1`. Missing delta keys never mean deletion. Unsequenced producers cannot
claim an incremental chain; products must supply a real ordering protocol, not timestamp ordering.

Partial/failed collection or a missing/mismatched/expired baseline or gap requires a new snapshot.
The old applicable cursor is retained, while a separate observed high-water prevents a late
snapshot from undoing a known gap. Late lower sequences are recorded as stale without clearing
resynchronization. Only a new complete snapshot above the high-water recovers the stream.
At `u64::MAX`, activate a new epoch and establish a snapshot; wrapping sequence is never accepted.
`observed_at` does not participate in ordering.

`ReceiveOutcome` distinguishes initial acceptance and replay. A `Record` is the immutable receipt
plus complete batch and historical `Decision`; it is not the current stream status, Inventory
update or compliance result. `ObservationStore::state` reads the separately maintained state.
Exact retries return the original record, even after its epoch retires, provided read/submission
authority remains valid. Changed content under the same identity conflicts. Neither retry changes
cursor nor extends the baseline deadline.

`Policy` requires replay-retention seconds, safety seconds and baseline-validity seconds. The first
two are minimum retention guarantees, not a TTL that invalidates an existing receipt. V1 retains
all records and retirement evidence; there is no automatic deletion. Baseline validity uses the
provider's received time. Expired baselines require a new snapshot, even if an old snapshot is
replayed. Pending applicable records remain discoverable for the separate Observation/Projection
handoff work; producer sequence is not a server projection log position.

Policy、State 和 Decision 的持久表示均带必填 `version: 1`；未知版本和不可达状态拒绝恢复。
公开反序列化复用同一校验入口，Decision 必须结合原始批次、接收时间与 Policy 验证。

## Minimal independent use

```rust
use rss_observation::{Batch, Body, Change, Coverage, Id, Policy, State, SyncOutcome};
use rss_contract::Timepoint;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let coverage = Coverage::new(Id::new("installed")?, Id::new("v1")?,
    Id::new("catalog-v1")?, Id::new("application-bytes-v1")?);
let batch = Batch::new(Id::new("snapshot-1")?, 0, Timepoint::try_from(100)?,
    coverage, Body::Snapshot(vec![Change::upsert(Id::new("object-1")?, vec![1,2])]))?;
let decision = State::initial().advance(&batch, 110, &Policy::new(86400,3600,3600)?)?;
assert_eq!(decision.outcome(), &SyncOutcome::Snapshot);
# Ok(()) }
```

The host supplies monotonic `Clock`, absolute `rss_request_context::Deadline` and its own runtime.
Dropping an adapter future is cancellation; unconfirmed transactions must be quarantined. Core
state-machine decisions do not perform I/O or establish durability by themselves. Provider errors
retain only an opaque redacted source and a closed recovery classification.

Historical extraction: `5b63e10a1b396b0ff70b7d1e6e55db296cd7a891` receipt/replay mechanisms only.
No historical generation, fencing, command store, wire or schema compatibility is retained.
ref: kube-rs/kube kube-runtime/src/watcher.rs@2.0.1
