# rss-transactional-messaging

Provider-neutral transactional messaging core. The crate has one authored message model, one
transaction outcome model, and narrow inbox, outbox, publisher, ingress, settlement, policy, and
observability ports. It contains no worker lifecycle, broker topology, SQL implementation,
dependency-injection registry, dynamic compatibility wrapper, or provider handle. The default
feature set enables both `consumer` and `producer`; disabling either removes that side's ports and
state machines from the public API.

The authored fingerprint covers message identity, tenant, occurrence time, correlation, domain,
route, contract/version/schema, partition, causation, business metadata, and payload. Trace and
tenant-authority evidence live in `TransportContext` and cannot change authored identity.

Consumer effects, terminal receipts, and settlement intents commit in one provider transaction.
Only a committed terminal receipt may acknowledge or reject a delivery. A transaction that did
not start or rolled back can only requeue; fencing and uncertain commit/rollback abandon the
provider session without ACK/NACK. Every provider future receives an `OperationDeadline` projected
from one core-owned absolute deadline; adapters enforce it with their runtime timeout. The managed
delivery stream is move-only, and runtime owners stop admission, finish or cancel the single
in-flight delivery, and bound that drain with `ShutdownBudget`.

Publisher ambiguity is a distinct outcome and the borrowed envelope forces retries to reuse the
persisted `MessageId`. Failures retain only closed stage/reason diagnostics; provider text,
endpoint, message identity and payload never cross the port. Ingress validation consumes a
core-issued challenge and returns opaque evidence bound to the exact subscription, tenant, message
and fingerprint. Only the pipeline can project a durable terminal receipt into broker settlement.

```rust
use rss_transactional_messaging::message::MessageId;
let id = MessageId::parse("message-42")?;
assert_eq!(id.as_str(), "message-42");

# #[cfg(feature = "consumer")]
# {
use rss_transactional_messaging::transaction::{FailureClass, TransactionOutcome};

let outcome = TransactionOutcome::<()>::commit_unknown();
assert!(!outcome.may_retry());
assert!(TransactionOutcome::<()>::rolled_back(FailureClass::Transient).may_retry());
# }

# #[cfg(feature = "producer")]
# {
use rss_transactional_messaging::transport::{
    PublishFailure, PublishFailureKind, PublishFailureReason, PublishFailureStage, PublishOutcome,
};

let publish = PublishOutcome::<()>::DefinitelyNotPublished(PublishFailure::new(
    PublishFailureKind::Transient,
    PublishFailureStage::Admission,
    PublishFailureReason::TransportUnavailable,
));
assert!(matches!(publish, PublishOutcome::DefinitelyNotPublished(_)));
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```
