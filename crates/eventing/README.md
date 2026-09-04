# rss-eventing

`rss-eventing` is the canonical package identity for the provider-neutral Eventing L2 public
waist. It exposes five modules and no crate-root shortcuts:

- `metadata`: tenant, occurred-at and optional audit correlation.
- `envelope`: opaque event identity and a contract-bound generic payload envelope.
- `delivery`: closed transaction/publication outcomes and validated delivery budgets.
- `lifecycle`: one atomic retry policy and an explicit positive shutdown budget.
- `observability`: closed low-cardinality metric/event vocabulary and an emit contract.

The package does not expose topics, provider SPI, broker administration, AMQP or PostgreSQL
implementation details, generated bindings, dependency injection, runtime drivers, composition,
consumer-owned runtime plans, L3/L4 behavior, or a test platform. Consumers own production routing
and any generated bindings used to derive it; adapters project provider-specific values only after
the public boundary.

The package is selected as an immutable release candidate. Candidate selection does not mean that
the package has been published, promoted to an RC, attached to an official profile, proven by an
external broker consumer, activated, or registered as a T3 capability. Provider-neutral LocalTx
assertions remain owned by `rss-conformance` and are consumed here only as a development
dependency.

```rust
use rss_contract::{ContractDescriptor, Timepoint};
use rss_diag_context::CorrelationId;
use rss_eventing::delivery::{ConsumerTxOutcome, PublishErrorKind};
use rss_eventing::envelope::{EventEnvelope, EventId};
use rss_eventing::lifecycle::{RetryPolicy, ShutdownBudget};
use rss_eventing::metadata::EventMetadata;
use rss_eventing::observability::eventing_observability_descriptor;
use rss_request_context::TenantId;

let tenant = TenantId::parse("2f1c5f2a-39d8-4c3b-a872-f6f724313a39")?;
let occurred_at = Timepoint::try_from(1_700_000_000_i64)?;
let correlation = CorrelationId::parse("audit-42")?;
let metadata = EventMetadata::new(tenant, occurred_at, Some(correlation));
let contract = ContractDescriptor::from_static(
    "example.event-authored",
    1,
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
);
let envelope = EventEnvelope::new(contract, EventId::parse("event-42")?, metadata, "payload");

assert_eq!(envelope.contract().id(), "example.event-authored");
assert_eq!(envelope.event_id().as_str(), "event-42");
assert_eq!(ConsumerTxOutcome::<()>::CommitUnknown.as_label(), "commit_unknown");
assert!(PublishErrorKind::Ambiguous.is_ambiguous());
assert_eq!(RetryPolicy::STANDARD.max_attempts().get(), 3);
assert!(ShutdownBudget::STANDARD.timeout().as_secs() > 0);
assert!(!eventing_observability_descriptor().metrics().is_empty());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The private fake-clock T2 carrier in `testkit` awaits the same closed
`ConsumerTxLifecycle::finish_attempt` control flow used by production; both pass a real Tokio sleep
future into the seam, which owns wait invocation and attempt advancement. The carrier also consumes
the same strict `DeliveryBudget` gate used by the PostgreSQL adapter. Its controlled tasks prove
bounded fixture cancellation, timeout, abort-and-await, and drop cleanup.
Provider settlement remains composition-owned; AMQP wire routing, broker confirms, real
generation replacement, duplicate delivery, and real connection cleanup remain adapter T2
residuals. The carrier is not an official driver, provider SPI, reusable broker fixture, T3 proof,
or a trigger for #1992.
