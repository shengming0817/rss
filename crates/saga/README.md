# rss-saga

A provider-neutral library for ordered cross-system actions, durable recovery and reverse
compensation. The application supplies typed actions, receipt protection, a store and an injected
monotonic timer. PostgreSQL support is in `rss-saga-postgres`.

## Define and register

```rust
use rss_saga::{Definition, Identity, StepSpec};
# fn example() -> Result<(), rss_saga::Error> {
let identity = Identity::new(rss_contract::ContractId::from_static("orders.checkout"), rss_contract::ContractVersion::from_static_major(1), rss_contract::SchemaDigest::from_static("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), rss_saga::ActionGeneration::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?);
let definition = Definition::new("orders", identity, vec![
    StepSpec::new("reserve", "reservation.v1", "inventory.reserve", "inventory.release", 3)?,
    StepSpec::new("charge", "payment.v1", "payments.charge", "payments.refund", 1)?,
])?;
# Ok(())
# }
```

Implement `Step` with an associated `Receipt: Serialize + DeserializeOwned + Send` and the four
operations `execute`, `probe`, `compensate`, `probe_compensation`. Each implementation declares its
step name and receipt schema. `DefinitionBuilder::step` checks registration order and schema
before internal type erasure. Core owns canonical JSON encoding; receipts need not implement Debug.

`Registry::builder().register(builder)?.finish()` creates an immutable exact map. The definition
fingerprint covers declared owner, identity, ordered step/effect/schema bindings and retry limits.
Action generation identifies the application's versioned action implementation; the library
cannot infer the semantics of executable code. Changing semantics requires a new definition version.
Neither registry nor PostgreSQL registration silently replaces a contract/version with different
metadata. Missing exact definitions stop recovery before effects. Keep all referenced action
implementations available until their instances and receipt retention commitments end. The
library has no remove, latest, cleanup or automatic definition retirement operation.

## Execute and recover

`Executor::new(store, protection, registry, read_budget)` does not spawn work. Register an instance with a
caller-selected `Scope` (tenant + UUID), then call `run(scope, budget, control)`.
`Control` carries an injected monotonic `Timer`, one absolute deadline and cancellation token.
`budget` bounds driver advances, including probes and retry decisions; phases do not reset time. Budget exhaustion returns `RunStop::Yielded`, not a failure or successful Saga result.
`run_once(tenant, cursor, SweepBudget::new(instance_limit, advance_limit)?, control)` runs one bounded page. Each instance gets at most one advance; errors stay in its result item. Pass the returned cursor to the next sweep so an unresolved first instance cannot starve later work. An empty final page resets the cursor for the next pass.

The driver records an intent before admitting an external effect. `Applied` carries the typed
receipt; `NotApplied` must prove absence and is retried up to the pinned `max_failures` limit. A negative recovery probe does not count as a proven execution failure; attempt numbers still increase monotonically.
`Unknown`, interrupted calls, and unfinished durable intents require probing with the same
idempotency key before retry. A negative probe permits a fresh attempt; a positive probe persists
the recovered receipt. Serialization or protection failure after an effect never becomes proof
that the effect was absent.

Only `Succeeded` and `Compensated` are terminal. Forward retry exhaustion starts reverse
compensation of completed effects. A failed compensation pauses at `CompensationFailed`, retaining
its receipt and cumulative attempts. `resume(scope, expected_revision, budget, control)` uses a CAS
to authorize one new attempt of that compensation. A stale revision is rejected; success continues
backwards and another failure pauses again. The caller owns authorization for this request.

The default lease is 30 seconds, actively renewed every 10 seconds while work runs. `LeasePolicy` may select another explicit TTL; it is independent of the total deadline. A crashed worker becomes recoverable after its short lease expires without an administrator changing rows.

If renewal interrupts an outstanding durable commit, the driver returns `CommitUnknown` with
the original provider diagnostic and leaves the lease to expire. Recovery reads durable state;
a renewal failure does not prove rollback. Outside a commit, the renewal error keeps its original classification.

A lease fences local writes. It cannot cancel an already issued remote operation. Every action
must pass its stable idempotency key to its external provider, reject changed content at the same
key, and implement authoritative probing. This is not a distributed atomic transaction.

`CommitUnknown`, `RollbackUnknown`, cancellation and deadlines do not prove rollback. Reload through
the same recovery path after ownership is available; never substitute a new instance/effect key.
Reports expose their single acknowledged `HistoryHead` through `head()`. Read status, revision, capacity and usage through that observation; for example, pass `head.revision()` and `head.capacity()` from the same head to `extend_history`. Report state has no duplicate public fields, and the stored progress representation is private. Reports include the failed step and closed cause when compensating or paused. `DefinitionBuilder::last_step` returns a typed `Completion<R>` witness; use it with `Report.success` and `Executor::success_receipt` to retrieve the final authenticated receipt. The resolver checks scope, exact definition and the actual registered Rust receipt type before decoding. Application message ACKs must wait for the required
acknowledged durable transition. Saga does not own broker settlement, a DLQ, or a management API.

## Receipt protection

`ReceiptProtection` requires a `SagaReceiptProtector` plus a versioned HMAC keyring. There is no
plaintext/default protector. Protector methods receive a private executor-minted `ReceiptContext`:
use its exact canonical AAD for authenticated encryption. Implementations are trusted cryptography
adapters and must validate key reference, nonce/tag and ciphertext format. Use a maintained AEAD
implementation, not a custom cipher. Key acquisition, key retention and provider resources belong
to the application; no remote KMS port is introduced here.

Before decrypting, the core compares expected scope/attempt/completion coordinates with stored
metadata. It derives AAD independently, authenticates the ciphertext and verifies the keyed content
fingerprint. A stored envelope cannot mint a trusted context. Plaintext uses the shared zeroizing
`rss_data_protection::Plaintext` capsule; ciphertext, effect keys and fingerprints redact Debug.

The only receipt format is v1 canonical JSON. Historical idempotency v1, AAD, content-message and
HMAC encodings are retained as one canonical implementation, with binary golden vectors. The new
fingerprint is not inserted into those historical byte layouts. Rust owner renaming does not rename
application identities or change effect keys.

## Optional lifecycle integration

Default features are empty. `rss-runtime` enables `Executor::into_registration`, accepting a
caller-owned `TaskStart`, timer and bounded run parameters on `Arc<Executor>`. Keep an Arc clone to schedule a yielded instance again or call `resume` after a pause. It returns a managed registration plus
an execution-result receiver. The receiver distinguishes a paused compensation from successful
execution; task termination alone is not a Saga success receipt. No task starts until the caller
adopts the registration. Dropping the result receiver does not transfer task ownership.

Extracted from `baseline/pre-community-core-20260902` at
`5b63e10a1b396b0ff70b7d1e6e55db296cd7a891`, with obsolete generated/operator/global-DI code removed.
Version 0.1.0 is experimental. There are no compatibility aliases or alternate consistency features.

ref: oxidecomputer/steno src/saga_exec.rs@main
ref: oxidecomputer/steno src/saga_log.rs@main
ref: RustCrypto/traits aead/src/lib.rs@master

Provider errors expose `kind()` for recovery and optional `diagnostic()` for safe phase/SQLSTATE labels. Raw SQLx messages and source chains remain redacted. `StorageContract` identifies schema/role rejection; `LeaseInput` identifies a TTL outside the documented range.

## Complete typed composition

This compile-checked example uses a demo action that only produces deterministic sample receipts;
it performs no remote business writes. Replace that Step with the application's idempotent provider
operations. `S` can be the separately configured PostgreSQL store. The example's AEAD uses `ring`
0.17 and declares direct dependencies on `rss-contract`, `rss-data-protection`, `tokio` (time), and `tokio-util`; the application supplies versioned encryption and integrity key material.

```rust,no_run
use rss_saga::*;
use rss_data_protection::Plaintext;
use ring::{aead, rand::{SecureRandom, SystemRandom}};

struct DemoStep(&'static str);
impl Step for DemoStep {
    type Receipt = String;
    fn name(&self) -> &str { self.0 }
    fn receipt_schema(&self) -> &str { "demo.receipt.v1" }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        // This documentation action has no external effect; its receipt is reproducible.
        EffectOutcome::Applied(self.0.into())
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> {
        ProbeOutcome::Applied(self.0.into())
    }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> {
        EffectOutcome::Applied(())
    }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> {
        ProbeOutcome::Applied(())
    }
}
struct LocalAead { key: aead::LessSafeKey, key_id: String }
impl SagaReceiptProtector for LocalAead {
    async fn seal(&self, plain: &[u8], context: &ReceiptContext) -> Result<Ciphertext, Error> {
        let mut nonce = [0_u8; 12];
        SystemRandom::new().fill(&mut nonce).map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut encrypted = plain.to_vec();
        self.key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context.canonical_aad()), &mut encrypted)
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut bytes = nonce.to_vec(); bytes.extend(encrypted);
        Ciphertext::new(self.key_id.clone(), bytes)
    }
    async fn open(&self, cipher: &Ciphertext, context: &ReceiptContext) -> Result<Plaintext, Error> {
        if cipher.key_ref() != self.key_id || cipher.bytes().len() < 28 {
            return Err(Error::new(ErrorKind::Protection));
        }
        let nonce: [u8; 12] = cipher.bytes()[..12].try_into()
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        let mut bytes = cipher.bytes()[12..].to_vec();
        let plain = self.key.open_in_place(aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context.canonical_aad()), &mut bytes)
            .map_err(|_| Error::new(ErrorKind::Protection))?;
        Ok(Plaintext::new(plain.to_vec()))
    }
}
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
struct Clock(Instant);
impl Timer for Clock {
    fn now(&self) -> Duration { self.0.elapsed() }
    async fn sleep_until(&self, deadline: Duration) {
        tokio::time::sleep(deadline.saturating_sub(self.now())).await;
    }
}
async fn checkout<S: Store>(store: S, scope: Scope, encryption_key: aead::UnboundKey,
    integrity_key: VersionedSagaReceiptIntegrityKey)
    -> Result<(Report, Option<String>), Error>
{
    let timer = Clock(Instant::now());
    let cancel = CancellationToken::new();
    let control = &Control::new(&timer, Duration::from_secs(30), &cancel);
    let definition = Definition::new("demo", Identity::new(rss_contract::ContractId::from_static("demo.checkout"), rss_contract::ContractVersion::from_static_major(1), rss_contract::SchemaDigest::from_static("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), rss_saga::ActionGeneration::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?), vec![
        StepSpec::new("reserve", "demo.receipt.v1", "reserve", "release", 3)?,
        StepSpec::new("charge", "demo.receipt.v1", "charge", "refund", 1)?,
    ])?;
    let (builder, completion) = DefinitionBuilder::new(definition.clone())?
        .step(DemoStep("reserve"))?.last_step(DemoStep("charge"))?;
    let registry = Registry::builder().register(builder)?.finish();
    let provider = LocalAead { key: aead::LessSafeKey::new(encryption_key), key_id: "demo-key-v1".into() };
    let keyring = SagaReceiptIntegrityKeyring::new(integrity_key, vec![])
        .map_err(|_| Error::new(ErrorKind::Protection))?;
    let executor = Executor::new(store, ReceiptProtection::new(provider, keyring), registry, ReadBudget::new(HistoryCapacity::new(10_000, 256 * 1024 * 1024)?, 1024 * 1024 * 1024)?);
    executor.register(scope, &definition, HistoryCapacity::new(10_000, 256 * 1024 * 1024)?, control).await?;
    let report = executor.run(scope, 20, control).await?;
    let receipt = match &report.success {
        Some(reference) => Some(executor.success_receipt(reference, &completion, control).await?),
        None => None,
    };
    Ok((report, receipt))
}
```


最小可运行使用流程及独立源码/候选 artifact 命令见 [rss-examples](../examples/README.md)。

## Finite history capacity

Construct `Executor::new(store, protection, registry, read_budget)` with an explicit
`ReadBudget::new(history_capacity, authentication_bytes)?`. Register each scope with
`register(scope, definition, capacity, control)`. Retries must match both the exact definition and current capacity; a different capacity returns `Conflict`, including an outdated value after growth. There is no unbounded default or legacy overload.
The example's 10,000 events and 256 MiB are explicit caller choices, not a production SLO.

`HistoryCapacity` bounds the committed journal plus required reservations in entries and charged
encoded bytes. Receipt-free events cost 256 bytes. A protected receipt additionally costs
`1024 + 6*(key_ref_bytes + integrity_key_id_bytes) + 5*(ciphertext_bytes + aad_bytes + digest_bytes)`.
The conservative V1 charge covers JSON number-array and escaped-string expansion; it does not
change receipt encoding or measure database physical storage. Definitions have a separate encoded
bound in the provider. Authentication work reserves the existing 1 MiB maximum plaintext per
historical receipt before any protector `open` call.

The caller's read budget limits full history replay and authentication. Each receipt open consumes the maximum plaintext size from one invocation-wide allowance, including replay verification and subsequent compensation opens. Running out at a safe boundary returns `HistoryLimited` before another intent or Resume is written; another invocation may continue with a fresh finite allowance. Before admitting an intent,
the executor also verifies that its maximum settlement remains readable under that budget.
`RunStop::HistoryLimited` means the next intent cannot fit. It preserves business status and
reports the acknowledged `HistoryHead`; it is distinct from advance-budget `Yielded`, failed
compensation and an unknown effect. Capacity exhaustion does not automatically abort a Saga.

A forward intent reserves its maximum receipt settlement, required Abort and first compensation
of applied effects. Compensation intents reserve settlement; Resume reserves itself and the next
intent/settlement pair. Pending effects settle from these reservations. A negative probe or failed
compensation is a safe boundary at which another attempt can be refused. Finite capacity cannot
promise unlimited retries or crashes. Serialization/protection contract failures remain separate
from history capacity and never prove that an effect was absent.

`Executor::history_head(scope, control)` remains available without loading journal payloads.
`extend_history(scope, expected_revision, expected_capacity, larger_capacity, control)` performs
explicit monotonic growth under a live lease and both CAS coordinates. Products own authorization
and resource sizing. To recover beyond a worker's read budget, supply an explicitly larger finite
budget to the same executor type, then use ordinary run/resume. No special bypass worker is needed.

`Snapshot::empty(definition, capacity, read_budget)?` starts bounded replay; `replay(event)` checks
stored sequence, receipt coordinates, actual use and transitions without retroactively applying
new-intent admission to historical events. Providers compare the resulting `head()` with locked
metadata. Live transitions prepare a fixed-size result before persistence and accept it only after
ACK; they do not copy the complete history. Each protected receipt is retained once, with sequence
references for compensation and successful result lookup.
