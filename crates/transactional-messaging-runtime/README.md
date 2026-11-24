# rss-transactional-messaging-runtime

Provider-neutral execution algorithms and managed worker integration for
`rss-transactional-messaging`.

The producer side owns `relay_once(binding, ...)`, which claims one bounded batch, drains it,
and returns the first error in claim order. Each publication starts with one fenced lease
extension that returns both remaining windows. The long-running worker refills free slots
as individual claims finish settlement, polling active work even while a claim request is pending.
`RelayConfig::new(claim_limit, max_in_flight, idle_scan_interval, error_backoff)` controls each
request size, total admitted work, empty-scan interval and recoverable-error delay. Both delays
must be at least 100ms. A completion can wake an idle scan. A recoverable infrastructure failure
holds further requests until the error delay elapses. A durably settled Retry follows the store's
per-record eligibility delay so other due partitions can progress. Cancellation or a fatal error stops new
requests. An outstanding claim request runs to its original deadline. The worker drains every
handle it receives. If the database committed the claim but the reply timed out, the store's
lease expiry and fencing govern when the original message can be claimed again.
Every relay store/publisher future passes through the core-owned absolute-deadline race. Publish
timeout is conservatively ambiguous and is settled as a same-`MessageId` retry; claim, lease and
settlement timeout stop downstream work without inventing durable state.
The store's `delivery_budget()` is the single lease/admission budget source; relay callers do not
supply a second budget that could disagree with durable lease TTL.


Each relay call explicitly selects one `ExecutionBinding` (storage, tenant, expected epoch).
`RelayWorker::run(binding, token)` and its managed registration retain that host-assigned task
identity; hosts select changing tenants through separate single-call operations on shared stores.
An ownership-lost result stops the task without refreshing its epoch. Consumer workers obtain each
delivery's execution identity from the existing trusted ingress validator via
`challenge.verified(binding)`. Once claimed, execution and renewal retain the claim's original identity.

The consumer side owns `consume_once`: validate, claim, periodic lease renewal, bounded handler
retry, transaction outcome, release/abandon, and commit-before-ACK settlement. Renewal runs across
handler execution and retry backoff. Explicit lease loss cancels the in-flight transaction and
abandons the provider session without settlement. Renewal errors, rollback failure, commit unknown,
and fencing never ACK. Every renewal is checked against the provider-reported remaining lease, so
an unsafe provider report hard-fences execution. The inbox supplies `lease_policy()` for both its
durable TTL and the runtime renewal schedule; `ConsumerExecutionPolicy` only controls execution
and retry budgets. A matching durable terminal receipt bypasses
the handler.
Claim, lease, transaction, release, settlement and abandon futures share one pair of operation and
settlement cutoffs minted from one clock observation. A transaction timeout maps to commit outcome
unknown and never ACKs; the reserved cutoff remains available for bounded cleanup. A settlement
timeout means its transport outcome is unknown, so the runtime never issues a second or
contradictory action.
Provider-decoding failures carry a core-minted, move-only rejection capability and are rejected
without exposing a general-purpose Reject constructor.

`ConsumerWorker` supervises subscription establishment, unexpected stream termination, and
transient delivery-processing failures with a distinct unbounded, saturating exponential backoff.
Opening a stream does not reset backoff: consecutive subscribe errors, empty streams and
recoverable processing errors share the failure cursor. A committed result, verified terminal duplicate, or settled rejection resets it to the base.
Busy and deferred deliveries preserve the failure cursor.
Transient delivery failures retire the current provider stream before resubscription. Pass a nonzero delivery window explicitly. One selects serial processing. AMQP applies
the window as per-subscription prefetch. MQTT accepts one. Independent deliveries refill on
completion; one subscription serializes verified tenant/domain/partition keys through settlement.
A rejected terminal head retires that subscription before starting queued successors. PostgreSQL serializes ordinary keyed effects in their transaction. A committed rejection blocks
subsequent effects until authorized gap acceptance. A blocked delivery briefly waits within its existing budget
before requeue. Delivery order and retention across retries depend on the transport: a single-credit subscription
can receive the same blocked message again. The broker envelope supplies no source ordinal.
Queued and busy deliveries count toward the same window and keep their original deadlines.
A live claim or unstarted capacity wait keeps the handle unacknowledged and rechecks at one quarter of the operation budget, clamped to 1–250 ms, until the original cutoff.
The runtime reports cumulative capacity wait once per blocked delivery. Graceful cancellation seals admission before draining.
The same loop
runs on an application's Tokio host or through the optional RSS lifecycle bridge.

## Caller-driven Tokio workers

`ConsumerWorker::run` and `RelayWorker::run` consume the worker and return a future. They do not
spawn tasks or catch provider panics. Constructors and directly awaited loops can borrow ports;
only spawning or RSS registration requires owned, `'static` dependencies. The crate remains
Tokio-based: `consume_once` uses Tokio selection and cooperative yielding, and the relay loop
uses Tokio selection and the injected execution timer for admission delays.

A cancellation token stops new work; it does not discard an active delivery or batch. Keep driving
the future so renewal, transaction outcome, and settlement can finish. The operation and settlement
deadlines still belong to the message algorithm. The host owns the final shutdown budget; constructors and `run` do not enforce an implicit
shutdown timeout. Hosts can use `ShutdownBudget` (standard value: 45 seconds) and project it at
their shutdown boundary. After that budget expires it can drop the future, or abort **and join** its spawned task. Forced
termination cannot promise asynchronous cleanup and never invents an ACK or durable outcome.
Dropping a Tokio `JoinHandle` alone detaches its task and does not stop it.

For a directly awaited relay (the consumer follows the same pattern):

```rust,no_run
# #[cfg(feature = "producer")]
# mod direct_example {
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxRelayStore;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;
use tokio_util::sync::CancellationToken;

async fn drive<P, S, U, C, E>(worker: RelayWorker<P, S, U, C, E>, binding: rss_transactional_messaging::fence::ExecutionBinding, stop: CancellationToken)
where
    P: Send + Sync,
    S: OutboxRelayStore<P>,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    // The host cancels a clone of `stop` and continues polling this future to drain.
    worker.run(binding, stop).await.expect("relay completes");
}
# }
```

A host that spawns the worker must retain its task handle through shutdown:

```rust,no_run
# #[cfg(feature = "producer")]
# mod spawned_example {
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxRelayStore;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::policy::ShutdownBudget;
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;
use tokio_util::sync::CancellationToken;

async fn host<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    stop: impl std::future::Future<Output = ()>,
    budget: ShutdownBudget,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Send + Sync + 'static,
    S: OutboxRelayStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let cancellation = CancellationToken::new();
    let mut task = tokio::spawn(worker.run(binding, cancellation.clone()));
    tokio::select! {
        result = &mut task => return result?.map_err(Into::into),
        () = stop => cancellation.cancel(),
    }
    match tokio::time::timeout(budget.timeout(), &mut task).await {
        Ok(result) => result?.map_err(Into::into),
        Err(timeout) => {
            task.abort();
            let _ = task.await; // Observe termination before releasing provider resources.
            Err(timeout.into())
        }
    }
}
# }
```

## Optional RSS lifecycle bridge

Enable `managed-runtime` explicitly to use `into_registration`. It delegates to `run` and returns
an opaque `ManagedTaskRegistration` and its same-source `TaskStatus`. Stage the registration once
through `rss-runtime::StartupTransaction` or `LaunchTransaction`; the RSS host owns task supervision,
panic reporting and the final shutdown timeout. `into_registration` explicitly requires
`ShutdownBudget` and projects it to `Duration` at this bridge. The worker algorithm retains its
operation/settlement deadlines independently. Its private lifecycle token is not exposed.

```rust,no_run
# #[cfg(all(feature = "producer", feature = "managed-runtime"))]
# mod managed_example {
use rss_runtime::{ManagedTaskRegistration, TaskStatus};
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxRelayStore;
use rss_request_context::ExecutionTimer;
use rss_transactional_messaging::policy::ShutdownBudget;
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;

fn prepare<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
    binding: rss_transactional_messaging::fence::ExecutionBinding,
    shutdown: ShutdownBudget,
) -> (ManagedTaskRegistration, TaskStatus)
where
    P: Send + Sync + 'static,
    S: OutboxRelayStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    worker.into_registration(binding, "transactional-relay", shutdown)
}
# }
```

Migration: existing RSS-hosted consumers must add `features = ["managed-runtime"]` to this
package dependency. Default features now provide only the two caller-driven algorithms.
There is no legacy default mode or compatibility alias. Message identities, tenant checks,
fingerprints, fencing, commit ambiguity and settlement ordering are identical in both hosts.

The crate has no provider implementation, process signal handling, listener, configuration loader,
health/readiness registry, probe, deployment lifecycle, product handler, Saga, Projection,
Reconcile, DLQ operator, retention worker, or disaster-recovery controller. Those concerns remain
with providers or external consumers.

Features:

- `consumer`: consumer execution and caller-driven worker.
- `producer`: relay execution and caller-driven worker.
- `managed-runtime`: optional RSS registration methods; does not enable either message side.
- default: `consumer` and `producer`, without `rss-runtime`.
