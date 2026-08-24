# rss-eventing

`rss-eventing` is the canonical package identity for the provider-neutral Eventing L2 public
waist. It exposes four modules and no crate-root shortcuts:

- `metadata`: tenant, occurred-at and optional audit correlation.
- `envelope`: opaque event identity and a contract-bound generic payload envelope.
- `delivery`: closed transaction/publication outcomes and validated delivery budgets.
- `lifecycle`: one atomic retry policy and an explicit positive shutdown budget.

The package does not expose topics, provider SPI, broker administration, AMQP or PostgreSQL
implementation details, generated bindings, dependency injection, runtime drivers, composition,
`RuntimePlan`, L3/L4 behavior, or a test platform. Production routing remains derived from the
generated `EventFactBinding`; adapters project provider-specific values only after the public
boundary.

The package is not yet a release candidate, profile or activation surface, external first-green
claim, artifact, or T3 capability. Those states require their own positive governance selection.
Provider-neutral LocalTx assertions remain owned by `rss-conformance` and are consumed here only
as a development dependency.
