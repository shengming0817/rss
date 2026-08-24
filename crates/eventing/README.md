# rss-eventing

`rss-eventing` is the canonical package identity for the provider-neutral eventing public seam.

This skeleton intentionally exports no runtime API and has no production dependencies. It does
not expose provider SPI, broker administration, AMQP or PostgreSQL implementation details,
generated types, dependency injection, composition, `RuntimePlan`, constructors, L3/L4 behavior,
or a test platform.

The package is not yet a release candidate, profile or activation surface, external first-green
claim, artifact, or T3 capability. Those states require their own positive governance selection.
Provider-neutral LocalTx assertions remain owned by `rss-conformance` and are consumed here only
as a development dependency.
