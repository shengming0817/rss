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
`RuntimePlan`, L3/L4 behavior, or a test platform. Production routing remains derived from the
generated `EventFactBinding`; adapters project provider-specific values only after the public
boundary.

The package is not yet a release candidate, profile or activation surface, external first-green
claim, artifact, or T3 capability. Those states require their own positive governance selection.
Provider-neutral LocalTx assertions remain owned by `rss-conformance` and are consumed here only
as a development dependency.

The private fake-clock T2 carrier in `testkit` awaits the same closed
`ConsumerTxLifecycle::finish_attempt` control flow used by production; both pass a real Tokio sleep
future into the seam, which owns wait invocation and attempt advancement. The carrier also consumes
the same strict `DeliveryBudget` gate used by the PostgreSQL adapter. Its controlled tasks prove
bounded fixture cancellation, timeout, abort-and-await, and drop cleanup.
Provider settlement remains composition-owned; AMQP wire routing, broker confirms, real
generation replacement, duplicate delivery, and real connection cleanup remain adapter T2
residuals. The carrier is not an official driver, provider SPI, reusable broker fixture, T3 proof,
or a trigger for #1992.
