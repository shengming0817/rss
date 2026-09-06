# rss-transactional-messaging-runtime

Provider-neutral execution algorithms and managed worker integration for
`rss-transactional-messaging`.

The producer side owns `relay_once`, bounded concurrent claim dispatch, publish-before-settlement,
same-ID ambiguous retry, and a polling worker with skipped missed ticks. Every already claimed entry
is drained before a batch error is returned. Cancellation stops new claims; the active batch may
finish within the host's explicit shutdown budget. `RelayConfig` accepts polling intervals from
100ms through 300s and a validated `RelayBatchLimit` no greater than 64; the same limit bounds both
durable claims and concurrent publication work in the public batch API.
Every relay store/publisher future passes through the core-owned absolute-deadline race. Publish
timeout is conservatively ambiguous and is settled as a same-`MessageId` retry; claim, lease and
settlement timeout stop downstream work without inventing durable state.
The store's `delivery_budget()` is the single lease/admission budget source; relay callers do not
supply a second budget that could disagree with durable lease TTL.

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
Transient delivery failures retire the current provider stream before resubscription. It processes
exactly one delivery at a time, so the next delivery is not polled until the current settlement
completes. Graceful shutdown stops admission and lets the current delivery finish. The same loop
runs on an application's Tokio host or through the optional RSS lifecycle bridge.

## Caller-driven Tokio workers

`ConsumerWorker::run` and `RelayWorker::run` consume the worker and return a future. They do not
spawn tasks or catch provider panics. Constructors and directly awaited loops can borrow ports;
only spawning or RSS registration requires owned, `'static` dependencies. The crate remains
Tokio-based: `consume_once` uses Tokio selection and cooperative yielding, and the relay loop
uses a Tokio interval with skipped missed ticks.

A cancellation token stops new work; it does not discard an active delivery or batch. Keep driving
the future so renewal, transaction outcome, and settlement can finish. The operation and settlement
deadlines still belong to the message algorithm. The host owns the final shutdown budget; after
that budget expires it can drop the future, or abort **and join** its spawned task. Forced
termination cannot promise asynchronous cleanup and never invents an ACK or durable outcome.
Dropping a Tokio `JoinHandle` alone detaches its task and does not stop it.

For a directly awaited relay (the consumer follows the same pattern):

```rust,no_run
# #[cfg(feature = "producer")]
# mod direct_example {
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxStore;
use rss_transactional_messaging::policy::ExecutionTimer;
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;
use tokio_util::sync::CancellationToken;

async fn drive<P, S, U, C, E>(worker: RelayWorker<P, S, U, C, E>, stop: CancellationToken)
where
    P: Send + Sync,
    S: OutboxStore<P>,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt>,
    C: ExecutionTimer,
    E: TransactionalMessagingEmitter,
{
    // The host cancels a clone of `stop` and continues polling this future to drain.
    worker.run(stop).await.expect("relay completes");
}
# }
```

A host that spawns the worker must retain its task handle through shutdown:

```rust,no_run
# #[cfg(feature = "producer")]
# mod spawned_example {
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxStore;
use rss_transactional_messaging::policy::{ExecutionTimer, ShutdownBudget};
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;
use tokio_util::sync::CancellationToken;

async fn host<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
    stop: impl std::future::Future<Output = ()>,
    budget: ShutdownBudget,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    let cancellation = CancellationToken::new();
    let mut task = tokio::spawn(worker.run(cancellation.clone()));
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
panic reporting and the final shutdown timeout. Its private lifecycle token is not exposed.

```rust,no_run
# #[cfg(all(feature = "producer", feature = "managed-runtime"))]
# mod managed_example {
use rss_runtime::{ManagedTaskRegistration, TaskStatus};
use rss_transactional_messaging::observability::TransactionalMessagingEmitter;
use rss_transactional_messaging::outbox::OutboxStore;
use rss_transactional_messaging::policy::{ExecutionTimer, ShutdownBudget};
use rss_transactional_messaging::transport::Publisher;
use rss_transactional_messaging_runtime::relay::RelayWorker;

fn prepare<P, S, U, C, E>(
    worker: RelayWorker<P, S, U, C, E>,
    shutdown: ShutdownBudget,
) -> (ManagedTaskRegistration, TaskStatus)
where
    P: Send + Sync + 'static,
    S: OutboxStore<P> + 'static,
    S::Claim: Sync,
    U: Publisher<P, Receipt = S::PublishReceipt> + 'static,
    C: ExecutionTimer + 'static,
    E: TransactionalMessagingEmitter + 'static,
{
    worker.into_registration("transactional-relay", shutdown)
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
