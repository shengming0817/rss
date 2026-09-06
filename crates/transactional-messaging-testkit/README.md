# rss-transactional-messaging-testkit

Provider-neutral T1/T2 conformance drivers and deterministic memory test doubles for
`rss-transactional-messaging` and `rss-transactional-messaging-runtime`.

The package owns no provider, connection, container, topology, product journey, or evidence
runner. Provider errors are consumed and discarded; conformance diagnostics contain only closed
scenario stages, provider phases, expected/actual closed labels, and aggregate counts.

Every runner accepts a core-owned `ExecutionBudget` and an injected `ExecutionTimer`. One absolute
deadline covers the complete suite, so a provider cannot reset the budget between scenarios.

## Features and API

| Feature | Modules and doubles |
| --- | --- |
| no default features | `localtx`, `ConformanceError`, `FakeClock` |
| `consumer` | `inbox`, `consumer`, `MemoryInboxStore`, `RecordingSettlement`, delivery transport conformance |
| `producer` | `outbox`, `MemoryOutboxStore`, `MemoryPublisher`, publisher transport conformance |

Both features are enabled by default. Memory stores are non-durable test doubles and make no
production guarantee.

```rust
use rss_transactional_messaging::policy::ExecutionBudget;
use rss_transactional_messaging_testkit::localtx::{
    LocalTxDriver, run_localtx_conformance,
};
use rss_transactional_messaging_testkit::{ConformanceError, memory::FakeClock};

async fn verify_provider<D: LocalTxDriver>(driver: &D) -> Result<(), ConformanceError> {
    run_localtx_conformance(driver, &FakeClock::new(), ExecutionBudget::STANDARD).await
}
```

Provider fixtures remain caller-owned. Drivers return production protocol types. Consumer drivers
map failures directly to the sole safe `ConformanceError` through its closed `fixture`, `connect`,
`publish`, `delivery`, `settlement`, or `shutdown` constructors, so the public runner retains the
operation phase without retaining provider text. Other opaque provider errors are consumed without
requiring `Debug`, `Display`, or `source()`.

## Migration from removed owners

| Removed path | Replacement |
| --- | --- |
| `rss_conformance::localtx` | `rss_transactional_messaging_testkit::localtx` |
| messaging helpers under `rss_conformance` | `outbox`, `inbox`, and `consumer` drivers |
| `memory::MemPublisher` | `memory::MemoryPublisher` |
| `memory::MemSettlement` | `memory::RecordingSettlement` |
| memory message stores | `memory::MemoryOutboxStore` and `memory::MemoryInboxStore` |

There are no aliases, re-exports, shims, or fallback paths for the removed APIs.

Licensed under the Apache License, Version 2.0.

## Transport and store proof ownership

`transport::run_publisher_transport_conformance` checks confirmation, definitive failure and
same-message retry after ambiguity. `run_delivery_transport_conformance` checks ACK, Requeue,
Reject, abandonment, settlement failure and cancellation while draining an in-flight delivery.
Every scenario returns its own core-owned outcomes and message identities. There are no
cross-scenario observation getters, provider handles, container dependencies or mirrored outcomes.

AMQP implements these transport drivers against RabbitMQ. PostgreSQL instead implements the
outbox/inbox/transaction suites against PostgreSQL. The outbox runner verifies append identity,
partition and lease rules, Retry/reclaim, and reclaim after publication without settlement;
it does not require a provider to implement or simulate publication. Its `ReclaimEvidence`
contains the observed claim identities and durable disposition. Retry, DeadLetter and Published
transitions retain independent real-database proofs.

The old OutboxDriver publication scenarios and observation getters have been removed. Callers
implement the appropriate capability driver directly; no old-API adapter is supplied.

Transport driver failures retain their provider phase and identify the exact scenario through
`ConformanceError::stage()` (for example `publisher.confirmed` or `delivery.requeue`).
Budget failures retain the corresponding `.budget` stage.
