# rss-transactional-messaging-runtime

Provider-neutral execution algorithms and managed worker integration for
`rss-transactional-messaging`.

The producer side owns `relay_once`, bounded concurrent claim dispatch, publish-before-settlement,
same-ID ambiguous retry, and a polling worker with skipped missed ticks. Every already claimed entry
is drained before a batch error is returned. Cancellation stops new claims; the active batch may
finish within the explicit worker `ShutdownBudget`. `RelayConfig` accepts polling intervals from
100ms through 300s and a validated `RelayBatchLimit` no greater than 64; the same limit bounds both
durable claims and concurrent publication work in the public batch API.

The consumer side owns `consume_once`: validate, claim, periodic lease renewal, bounded handler
retry, transaction outcome, release/abandon, and commit-before-ACK settlement. Renewal runs across
handler execution and retry backoff. Explicit lease loss cancels the in-flight transaction and
abandons the provider session without settlement. Renewal errors, rollback failure, commit unknown,
and fencing never ACK. Every renewal is checked against the provider-reported remaining lease, so
an unsafe configured interval hard-fences execution. A matching durable terminal receipt bypasses
the handler.
Provider-decoding failures carry a core-minted, move-only rejection capability and are rejected
without exposing a general-purpose Reject constructor.

`ConsumerWorker` supervises subscription establishment, unexpected stream termination, and
transient delivery-processing failures with a distinct unbounded, saturating exponential backoff.
Transient delivery failures retire the current provider stream before resubscription. It processes
exactly one delivery at a time, so the next delivery is not polled until the current settlement
completes. Graceful shutdown stops admission and lets the current delivery finish; if the
managed-task deadline expires, `rss-runtime` drops the task and stream so the provider can
redeliver.

Both worker types expose only `into_registration`, returning an opaque
`ManagedTaskRegistration` and its same-source `TaskStatus`. Raw worker loops and cancellation
tokens are private. Applications stage registrations through `rss-runtime::StartupTransaction`
or `LaunchTransaction`.

```rust,no_run
use rss_runtime::{ManagedTaskRegistration, TaskStatus};
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxStore;
use rss_transactional_messaging::policy::{Clock, ShutdownBudget};
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;
use std::time::Duration;

fn prepare_relay<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
) -> (ManagedTaskRegistration, TaskStatus)
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: Clock + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let shutdown = ShutdownBudget::new(Duration::from_secs(30)).expect("valid budget");
    worker.into_registration("transactional-relay", shutdown)
}
```

The returned registration is then staged once through the application's existing
`rss-runtime` startup transaction; `TaskStatus` is retained for lifecycle observation.

The crate has no provider implementation, process signal handling, listener, configuration loader,
health/readiness registry, probe, deployment lifecycle, product handler, Saga, Projection,
Reconcile, DLQ operator, retention worker, or disaster-recovery controller. Those concerns remain
with providers or external consumers.

Features:

- `consumer`: consumer execution and managed consumer worker.
- `producer`: relay execution and managed relay worker.
- default: both features.
