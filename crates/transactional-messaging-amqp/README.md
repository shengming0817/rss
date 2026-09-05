# rss-transactional-messaging-amqp

An independently consumable AMQP 0-9-1 adapter for `rss-transactional-messaging`. The normal build
contains the real lapin transport. There is no disabled backend, fallback publisher, platform
bundle, readiness registry, provider selection, or PostgreSQL dependency.

## Connect and own the resource

Publisher and subscriber each have one production `connect` constructor. The returned handle is
cloneable and implements only its messaging port; the returned resource is move-only and implements
`rss_runtime::ManagedResource`. Register each resource immediately, before the next await. Register
relay/consumer workers afterwards, so LIFO shutdown drains workers before closing their transport.

```rust,no_run
use std::time::Duration;
use rss_runtime::{DynManagedResource, StartupTransaction};
use rss_transactional_messaging_amqp::{
    AmqpConnectError, AmqpPrivateCa, AmqpPublisher, AmqpPublisherEndpoint,
};

async fn attach_publisher(
    startup: &mut StartupTransaction<'_>,
    endpoint: &AmqpPublisherEndpoint,
    ca: &AmqpPrivateCa,
) -> Result<AmqpPublisher, AmqpConnectError> {
    let (publisher, resource) = AmqpPublisher::connect(
        endpoint, "outbox-publisher", ca, Duration::from_secs(10),
    ).await?;
    startup.stage_resource(DynManagedResource::new_box(resource));
    Ok(publisher)
}
```

`AmqpSubscriber::connect(endpoint, name, ca, recovery_timeout)` returns the corresponding subscriber/resource pair.
Its handle implements `DeliverySource<Vec<u8>>`. The application supplies subscriptions and
transaction handlers through the core/runtime APIs. Partial single-role connection failures clean
up their local connection; multi-resource startup rollback is owned by `rss-runtime`.

Resource shutdown atomically seals subscription/task registration and retires the exact active transport. Surviving handles fail
closed and cannot resurrect the resource. Dropping an unregistered owner also requests retirement;
use the runtime shutdown stack to await and bound cleanup. The library does not install signal
handlers or own an application process.

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
  Resource shutdown is bounded by `rss-runtime`, independently of that recovery operation.
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

Only `test-support` is optional. It enables explicit loopback plaintext/default-root fixture
constructors and deterministic fault barriers; it never supplies queue provisioning or broker management.
Do not enable it for production credentials. Default and no-default builds expose the same real
production transport.

T1 checks capabilities, redaction, confirm classification, deadlines and generation fencing.
The separate `amqp-integration` package owns RabbitMQ fixtures and implements the public publisher
and delivery transport suites from `rss-transactional-messaging-testkit`. It proves real confirms,
refusals, ambiguity, settlement, cancellation, redelivery and private-CA authorization. Its fixtures
provision test queues independently, including an identity with only queue read authority.
`RSS_AMQP_TEST_URL` selects a dedicated test broker whose credentials allow fixture provisioning;
this is separate from the production subscriber credential. Management-only fault observations
use owned temporary brokers. It makes
no PostgreSQL or durable application-transaction guarantee.

Historical implementation: `baseline/pre-community-core-20260902`.
Upstream reference: lapin v4.10.0 `src/generated/channel.rs`, `src/publisher_confirm.rs`,
`src/consumer.rs`, and `src/connection_properties.rs`. RSS retains ownership of replacement
and deliberately leaves lapin automatic recovery disabled.

Licensed under the Apache License, Version 2.0.
