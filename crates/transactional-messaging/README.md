# rss-transactional-messaging

Provider-neutral transactional messaging semantics for RSS. The crate owns one authored message
model, one transaction outcome model, and narrow inbox, outbox, publisher, ingress, settlement,
policy, and observability ports. It contains no relay or consumer execution algorithm, worker loop,
runtime task, broker topology, SQL implementation, provider handle, health registry, or assembly.

The default feature set enables both `consumer` and `producer`; disabling either removes that
side's ports and state machines from the public API.

Consumer authority is represented by opaque, move-only phases. `verify_ingress` is the only
constructor for `VerifiedConsumerBinding`; exact subscription, tenant, message, contract, and
fingerprint evidence is checked before an inbox identity or `ReceiptIntent` can be produced.
`ReceiptIntent::committed` creates an opaque `CommittedTransaction`, while a provider-rehydrated
terminal receipt must be checked through the verified binding. Only those paths can produce a
`TerminalSettlement`. Core ingress verification can additionally return a move-only
`IngressRejection`; trusted transport decode boundaries receive the separate move-only
`DecodeRejection`. Only these opaque authorities can produce ACK or Reject. Callers may construct
only the conservative Requeue decision directly. Inbox renewal returns provider-authoritative
remaining lease evidence for the runtime to check before continuing execution.

`InboxStore` and `ConsumerTx` implementations are trusted durable semantic boundaries. In
particular, a provider may rehydrate `TerminalReceipt`, and must return `Succeeded` only for state
committed atomically with the handler effect. Private receipt fields and settlement projection keep
that authority out of business callers; they cannot prove that a provider told the truth.

`TransactionOutcome::fold` exposes every closed outcome without exposing or making its private
state forgeable. Commit-unknown, rollback-failed, and fenced outcomes remain distinct. Every
delivery or relay execution provider future is raced by the core-owned `within` funnel against one
monotonic absolute deadline. Subscription establishment and `stream.next()` are intentionally
long-lived admission waits controlled by cancellation and shutdown, not by a per-delivery budget.
The same execution cutoff is projected as `OperationDeadline` for the adapter's second-layer I/O
watchdog. Timeout drops the future as a cancellation request; it does not prove that an external
effect did not occur. `ExecutionDeadlines` mints the operation cutoff and settlement reserve from
one clock observation, so retry stages cannot reset the budget.

The companion `rss-transactional-messaging-runtime` package is the sole owner of `relay_once`,
`consume_once`, periodic claim renewal, retry, settlement ordering, long-lived loops, and
`rss-runtime` task registration.

```rust
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::transaction::{FailureClass, TransactionOutcome};

let id = MessageId::parse("message-42")?;
assert_eq!(id.as_str(), "message-42");

let outcome = TransactionOutcome::<()>::commit_unknown();
assert!(!outcome.may_retry());
assert!(TransactionOutcome::<()>::rolled_back(FailureClass::Transient).may_retry());

# Ok::<(), Box<dyn std::error::Error>>(())
```
