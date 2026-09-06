# rss-transactional-messaging

Provider-neutral message identities, transaction outcomes, inbox/outbox ports, and settlement
contracts. Start with [message] for authored facts, [transaction] for effect outcomes, and
[policy] for deadlines. [error] and [observability] define safe diagnostics.

`consumer` enables inbox, ingress, and consumer settlement APIs; `producer` enables outbox and
publication APIs. Both are enabled by default. Message types, local transaction outcomes, and
budget primitives remain available with `default-features = false`.

Providers own durable truth, fencing, and transport evidence. Opaque capabilities bind that
reported evidence to a message; they cannot prove a provider or validator is truthful. Consumer
ACK requires verified successful terminal evidence committed atomically with handler effects.
Uncertain commit must not be treated as rollback; ambiguous publication preserves the original
message ID and authored content for retry.

The companion [runtime crate](https://docs.rs/rss-transactional-messaging-runtime) owns consumer
and relay execution, renewal, retry, and settlement ordering. Its loops use the core's
[policy::within] deadline and cancellation contract. Provider-specific storage and transport
implementations live in adapters.

[message]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/message/index.html
[transaction]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/transaction/index.html
[policy]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/policy/index.html
[error]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/error/index.html
[observability]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/observability/index.html
[policy::within]: https://docs.rs/rss-transactional-messaging/latest/rss_transactional_messaging/policy/fn.within.html

```rust
use rss_transactional_messaging::message::MessageId;
use rss_transactional_messaging::transaction::LocalTxAttempt;

let id = MessageId::parse("message-42")?;
assert_eq!(id.as_str(), "message-42");

let attempt = LocalTxAttempt::<(), &str>::commit_unknown("confirmation lost");
let status = attempt.fold(
    |_| "committed",
    |_| "not started",
    |_| "rolled back",
    |_| "rollback failed",
    |_| "commit unknown",
    |_| "fenced",
);
assert_eq!(status, "commit unknown");
# Ok::<(), Box<dyn std::error::Error>>(())
```
