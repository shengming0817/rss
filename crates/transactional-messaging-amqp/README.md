# rss-transactional-messaging-amqp

An independently consumable AMQP 0-9-1 adapter for `rss-transactional-messaging`. The normal build
contains the real lapin transport. There is no disabled backend, fallback publisher, platform
bundle, readiness registry, provider selection, or PostgreSQL dependency.

## Connect and own the resource

Publisher and subscriber each have one production `connect` constructor. The returned handle is
cloneable and implements only its messaging port; the resource is the unique, move-only owner.
A Tokio host retains the owner and drains its relay/consumer workers before closing the transport.

```rust,no_run
use std::time::Duration;
use rss_transactional_messaging_amqp::{AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint};

async fn use_publisher(
    endpoint: &AmqpPublisherEndpoint,
    ca: &AmqpPrivateCa,
) -> Result<(), Box<dyn std::error::Error>> {
    let (publisher, resource) = AmqpPublisher::connect(
        endpoint, "outbox-publisher", ca, Duration::from_secs(10),
    ).await?;
    // Pass publisher clones to workers; stop and drain those workers before this await.
    resource.shutdown(Duration::from_secs(5)).await?;
    Ok(())
}
```

`AmqpSubscriber::connect(endpoint, name, ca, recovery_timeout)` returns the corresponding pair.
Its handle implements `DeliverySource<Vec<u8>>`. Both resources expose consuming
`shutdown(self, timeout)`: one total budget covers cancellation, connection close, and task joins.
Success means the registered tasks have finished. Zero budget requests forced retirement and
returns `DeadlineExceeded`; an unrepresentable deadline returns `InvalidBudget` and retires the owner.
Completed task failures are harvested with a closed diagnostic kind before pruning; retained tasks
are joined and classified by shutdown. Every failed close/join stage emits its actual phase, task
kind and safe error kind. When multiple stages fail, shutdown returns `TaskPanicked` before
`TaskCancelled` before `Operation`; equal kinds retain the first failure. The total-budget timeout
still returns `DeadlineExceeded`, and failures observed before that timeout remain in diagnostics. Timeout or dropping the close future aborts remaining tasks and requests protocol close; it does
not claim their asynchronous destruction or broker CloseOk has already completed. Cleanup requires
the host's Tokio runtime to continue running. Error kinds are public; provider/panic payloads stay redacted.

Shutdown atomically seals subscription/task registration and retires the exact active transport.
Surviving handles fail closed and cannot resurrect the resource. Resource Drop requests retirement,
including when its consuming close future is dropped before its first poll. Recovery and cancel
workers use Tokio cancellation and abort-on-drop handles inside the adapter. The library does not
install signal handlers or own an application process.

### Optional RSS lifecycle integration

Enable `managed-runtime` explicitly to implement `rss_runtime::ManagedResource` on the same owners.
Register resources immediately, then workers, so the stack's LIFO shutdown drains workers first.
The bridge calls the same private cleanup and leaves its single timeout to the RSS shutdown stack
(default 30 seconds). A repeated trait shutdown is classified as RSS `Operation` (internal AMQP `AlreadyStarted`);
it does not start another cleanup.

```rust,no_run
# #[cfg(feature = "managed-runtime")]
# async fn attach(startup: &mut rss_runtime::StartupTransaction<'_>, endpoint: &rss_transactional_messaging_amqp::AmqpPublisherEndpoint, ca: &rss_transactional_messaging_amqp::AmqpPrivateCa) -> Result<(), rss_transactional_messaging_amqp::AmqpConnectError> {
use rss_runtime::DynManagedResource;
use rss_transactional_messaging_amqp::AmqpPublisher;
let (publisher, resource) = AmqpPublisher::connect(
    endpoint, "outbox-publisher", ca, std::time::Duration::from_secs(10),
).await?;
startup.stage_resource(DynManagedResource::new_box(resource));
# Ok(())
# }
```

This is an intentional pre-publication API replacement: previous default trait consumers must
select this feature or migrate to consuming shutdown. There is no legacy task implementation.
Partial connection failures clean their local connection; multi-resource startup rollback belongs
to the host (or its explicitly selected RSS startup transaction).

## TLS and credentials

`AmqpPublisherEndpoint::parse` and `AmqpSubscriberEndpoint::parse` accept only `amqps://` URLs with
explicit non-empty username/password, host and vhost (`/%2f` explicitly selects the default vhost). The distinct types prevent
credential-slot swaps; actual authority is enforced by RabbitMQ vhost and topic permissions.
Provision credentials, vhosts and broker authorization outside this library. Query parameters and
fragments are rejected, including SASL mechanism overrides.

`AmqpPrivateCa::from_pem` requires a non-empty usable certificate bundle. Connection failures use a redacted source chain; `AmqpConnectError::InvalidRecoveryTimeout` distinguishes
local configuration failures from `Transport` setup failures. Production connections
verify the broker against only those roots; WebPKI/platform roots are not appended. Endpoint
Debug/Display removes credentials, query and fragment. Recovery events contain only closed
stage/reason labels and generation, never endpoint coordinates or provider error text.

## Publication, delivery and deadlines

- A publisher generation owns one connection plus its confirm channel. `mandatory` publication
  and broker confirms distinguish confirmed, definitely-not-published and ambiguous outcomes.
  Unroutable publication is transient. An attempted send whose confirmation is lost or whose
  future is cancelled retires its generation; the caller retries using the same `MessageId`.
- Per-call `OperationDeadline` from the messaging core covers the complete send/confirm or
  settlement operation. Constructor `recovery_timeout` must be an integral number of milliseconds in `1ms..=24h` and bounds publisher background replacement:
  confirm drain, connection close and new confirmed transport share one recovery deadline.
  Resource shutdown has its own total budget, independently of that recovery operation.
- Subscriber retries lazily replace a disconnected connection under a single recovery lock. The
  constructor budget covers lock acquisition, connection setup and installation; shutdown seals
  installation. Existing streams terminate on connection loss and the runtime resubscribes.
  Permission/configuration failures are permanent; topology conflicts remain conflicts.
- Each subscription uses its own channel, `prefetch=1`, and manual ACK/NACK. Its move-only
  settlement stays bound to the original channel. `Requeue` uses NACK with requeue; `Reject`
  uses NACK without requeue. Abandon, failed settlement and dropped unsettled receipts retire
  that channel so the broker can redeliver. An expired deadline must not send a settlement.
- Dropping a delivery stream stops only that subscription's admission. Cancel and settlement
  RPCs are serialized: a previously requested cancel waits for cancel-ok before the in-flight
  settlement can reopen the prefetch window. Subscriber resource shutdown owns cancellation
  tasks and closes all remaining channels.

The adapter publishes to `amq.topic` with the exact message route as routing key, and consumes an
externally provisioned queue whose name equals that route. It never declares queues, bindings or
broker policies. Missing queues fail subscription establishment. Provision the queue and binding
before publishing or starting consumers; subscriber credentials need only read permission on that
queue. Queue type/durability and broker DLX, overflow, capacity and retention policies belong to the
external provisioning/operations owner. A `Reject` sends NACK without requeue; whether RabbitMQ
routes it to a DLX or discards it depends on that external configuration.

RabbitMQ policies allow mutable queue arguments to evolve without shipping new adapter code.
Production retention management and application replay remain external. See
[RabbitMQ policies](https://www.rabbitmq.com/docs/policies) and
[dead-letter configuration](https://www.rabbitmq.com/docs/dlx).

## Verification and features

Default and no-default dependency closures do not contain `rss-runtime`. The additive
`managed-runtime` feature supplies the explicit RSS bridge. `test-support` enables explicit loopback plaintext/default-root fixture
constructors and deterministic fault barriers; it never supplies queue provisioning or broker management.
Do not enable it for production credentials. Default and no-default builds expose the same real
production transport.

T1 checks capabilities, redaction, confirm classification, deadlines and generation fencing.
The separate `amqp-integration` package owns RabbitMQ fixtures and implements the public publisher
and delivery transport suites from `rss-transactional-messaging-testkit`. It proves real confirms,
refusals, ambiguity, settlement, cancellation, redelivery and private-CA authorization. Its fixtures
provision test queues independently, including an identity with only queue read authority.
Three suites each share a 110-second deadline, including fixture startup; nextest retains its
120-second termination limit. They own four temporary brokers: publisher/security (plain + TLS),
settlement/runtime, and subscriber lifecycle. Scenario helpers borrow the suite fixture and
use separate vhosts; none starts a nested broker. Fixture management only acts on owned containers.
Production endpoints are always explicit; integration fixtures do not read endpoint environment overrides.

Pure successful-consumer and commit-unknown outcome decisions belong to the runtime T1 tests
(`long_handler_is_periodically_renewed_then_commits_before_ack` and
`consume_once_fault_matrix_is_bounded_and_never_acks_uncertain_outcomes`). Broker ACK and abandon
remain in delivery conformance. Real publish cancellation/confirmation timeout, settlement Drop,
registration/shutdown, recovery installation, standalone close cancellation and forced runtime cancellation remain T2 because
in-memory generation or decision tests cannot prove their connection and channel cleanup.
The integration package defaults to the standalone host and all three real-broker suites. Its
`managed-runtime` feature additionally exercises RSS startup rollback, repeated trait close and
forced cancellation. Both combinations are verified independently; fixtures are shared within each suite.
These suites make no PostgreSQL or durable application-transaction guarantee.

Historical implementation: `baseline/pre-community-core-20260902`.
Upstream reference: lapin v4.10.0 `src/generated/channel.rs`, `src/publisher_confirm.rs`,
`src/consumer.rs`, and `src/connection_properties.rs`. RSS retains ownership of replacement
and deliberately leaves lapin automatic recovery disabled.
Task ownership reference: tokio-util 0.7.18 `src/task/abort_on_drop.rs` at
`9cc02cc88d083113cd9889a74b382e39e430e180`; drop requests abort, while normal await observes completion.

Licensed under the Apache License, Version 2.0.
