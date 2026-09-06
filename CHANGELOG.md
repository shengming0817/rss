# Changelog

This changelog records notable changes to packages selected by the positive RSS Release Surface.
Package versions are independent. An `Unreleased` entry does not declare a Release Candidate or a
registry release; exact-artifact RC approval and publication follow [RELEASES.md](RELEASES.md).

## Unreleased

### rss-projection / rss-projection-postgres 0.1.0

- Extract ordered projection execution and recovery from baseline `5b63e10` into independent
  core and PostgreSQL packages (#2292). Events no longer require RSS envelopes or MessageRoute.
- Commit read-model effects, fact receipts, epoch validation and checkpoints in one PostgreSQL
  transaction. Append positions follow commit order; replay uses immutable new generations.
- Expose bounded cancellation/deadline execution and an explicitly at-least-once external target path.
  External mutations receive the same Control; caller-owned Report observations run after execution.
- Require complete fact receipts for positioned generation baselines and initialize them atomically;
  only adapter receipts may classify PostgreSQL effects as duplicate.
- Remove legacy Projection models, metrics, conformance and generated input binding exports without
  aliases or compatibility schemas. Generic diport checkpoints now own `CheckpointOffset`.
- Provide a fresh-install schema only; external migrators own installation/grants, and products own
  read-model schema, authentication and generation cutover. No legacy data adoption is supported.

### rss-transactional-messaging-amqp 0.1.0

- Publish the historical lapin transport as an independent adapter with generation-scoped confirms,
  cancellation-safe retirement, manual settlement and separate port handles/resource owners.
- Remove the internal amqp package, bundle/readiness/fallback and secure endpoint owner; the adapter
  owns role-specific endpoints/private CA trust and exposes only test-support fixture seams.
- Redact recursive connection error chains, classify invalid recovery timeouts, and reject subscription
  registration once resource shutdown has sealed admission.

- Consume externally provisioned queues without declaring topology or owning broker retention,
  capacity, overflow or dead-letter policy; remove the route preparation and queue-management API.
- Require explicit production credentials, reject SASL URL overrides, recover subscriber connections
  within an explicit budget, and preserve permanent/conflict error classifications.

### rss-transactional-messaging-testkit 0.1.0

- Close the `none`/`producer`/`consumer` feature graph so each mode activates only its matching core
  capability; keep LocalTx/FakeClock feature-neutral and gate inbox/settlement doubles as consumer API.
- Separate publisher/delivery transport conformance from OutboxDriver storage proof. PostgreSQL retains
  real Retry/DeadLetter/Published and lease/reclaim evidence without a simulated publisher.
- Establish the sole provider-neutral owner for transactional messaging conformance drivers and
  deterministic in-memory outbox, inbox, publisher, settlement, and clock test doubles.
- Preserve the historical local transaction, outbox, inbox, consumer transaction, and nine-case
  crash matrix invariants while consuming core/runtime production outcomes directly.
- Remove the former `rss-conformance` package and messaging doubles from the memory adapter without
  aliases, re-exports, shims, provider catalogs, discovery DSLs, or compatibility features.

### rss-transactional-messaging-runtime 0.1.0

- Bound every consumer and relay provider future through the core-owned absolute-deadline race;
  preserve settlement reserve, map transaction timeout to commit-unknown, and retain same-ID
  ambiguous publish recovery.
- Establish the sole provider-neutral owner for bounded relay and consumer execution, periodic
  lease renewal, subscription recovery, backpressure, and managed worker registration.
- Preserve publish-before-settlement, commit-before-ACK, same-ID ambiguous retry, lease-loss
  fencing, and bounded graceful shutdown without provider or product dependencies.
- Enforce one validated relay batch/claim bound, cancellation-first admission, closed runtime
  failure phases, and feature-specific dependency/test surfaces.
- Replace delivery-processing failures by reconnecting the provider session, use a distinct
  unbounded subscription backoff policy, and expose relay lease-loss observations.

### rss-transactional-messaging 0.2.0

- Keep provider-neutral LocalTx outcomes available without producer or consumer features while
  compiling receipt, ingress, settlement, and `ConsumerTx` capabilities only for consumers.
- Replace `RetryTimer` and relative phase projections with one `ExecutionTimer`, typed
  operation/settlement deadlines, and a deadline-first `within` funnel; distinguish elapsed budget
  from retryable provider failures without compatibility aliases.
  Migrate `RetryTimer::delay` to `ExecutionTimer::sleep_until`, budget projection to
  `ExecutionDeadlines::from_budget`, and phase caps to `AbsoluteDeadline::capped` followed by
  `within`. Runtime worker payloads and relay claim capabilities used by spawned concurrent work
  must also be `Sync`.
- Document inbox/transaction providers as the trusted durable receipt boundary while keeping direct
  settlement authority unavailable to business callers.
- Narrow the core to message, transaction, receipt, policy, port, and opaque transition semantics;
  move every relay and consumer execution entry point to `rss-transactional-messaging-runtime`.
- Add a lease renewal schedule checked against provider-authoritative remaining-time evidence and
  opaque verified binding/terminal settlement phases without aliases, re-exports, shims, or
  compatibility features.
- Make ingress rejection and bounded provider claim batches opaque core transitions so callers
  cannot forge Reject authority or over-admit durable relay work.
- Mint a move-only decode rejection at the trusted transport boundary so malformed provider
  deliveries terminate without exposing a general Reject constructor.

### rss-runtime 0.1.0

- Establish the sole provider-neutral owner for managed resources and tasks, phase-typed startup
  and launch registration, fallible dedicated-thread workers, and bounded LIFO
  shutdown.
- Require one positive total drain budget and preserve exactly-once background draining when the
  stack, or a caller waiting for shutdown, is cancelled.
- Remove every former lifecycle owner path and the obsolete composition crates without aliases,
  deprecated re-exports, shims, conversions, or compatibility features.

### rss-redact 0.1.0

- Establish the sole public owner for diagnostic-output redaction, `SecretText`, `RedactedSource`,
  and `RedactedBytes`. The `Redact` trait and built-in zeroizing secret types work by default;
  the derive re-export now requires explicit `features = ["derive"]`, with no compatibility default.
- Remove the former `secure` and `diport` owner paths without aliases, shims, deprecated re-exports,
  or compatibility features.

### rss-redact-derive 0.1.0

- Establish the dedicated procedural-macro implementation package for `rss-redact`; workspace
  consumers do not depend on it directly.
- Resolve the consumer's actual `rss-redact` dependency name during expansion and remove the former
  `securederive` package identity.

### rss-data-protection 0.1.0

- Establish the sole public owner for AEAD plaintext capsules, ciphertext envelopes, derived AAD,
  protection contexts, Saga receipt protection coordinates, and blind indexes.
- Reject schema version zero at the field AAD construction funnel for request and maintenance
  contexts, matching the existing positive-version invariant for Saga receipt AAD.
- Keep diagnostic redaction and Saga receipt workflow integrity outside the package, with no legacy
  `secure` re-export or compatibility path.

### rss-device-security-contracts 0.1.0

- Export generated authority-free HTTP operation descriptors for the policy PUT and status GET
  Draft contracts, binding canonical contract identity, closed method, and origin-relative path
  template without adding a client or activating routes.

### rss-contract 0.1.0

- Establish the sole public owner for canonical contract IDs, versions, SHA-256 schema digests and descriptors.
- Add authority-free `Timepoint` values with non-negative Unix-second ordering and fallible or
  saturating `SystemTime` conversions, without clock, `now`, deadline, or scheduling authority.
- Add opaque `PageCursor` values with a 4096-byte canonical unpadded base64url bound, closed
  malformed/too-long/stale rejection, and redacted diagnostics that expose neither tokens nor
  provider-owned pagination state.
- Establish the sole public owner for the closed `DataClass`, `SafeErrorCode`, and
  `SafeErrorCategory` vocabularies and the code-only `SafeError` projection.
- Remove `secure::Sensitivity` without an alias, shim, conversion, or dual API; redaction
  mechanisms remain owned by `secure`.
- Keep registries, generated catalogs, runtime bindings and admission authority outside the package.
- Set MSRV to Rust 1.96 with no default features. This is the initial 0.1 public API;
  there is no Foundation facade, compatibility re-export, alias, shim, or alternate owner path.

### rss-request-context 0.1.0

- Establish authority-free tenant/request values, redacted principals, deadlines, cancellation observation and closed obligation views.
- Keep trusted mint, cancellation trigger, deadline extension and cross-tenant authority internal.

### rss-platform 0.3.0

- Replace the v0.2 crypto/lifecycle/synchronous surface with a typed asynchronous application waist and read-only host projection.
- This is an intentional breaking cutover with no alias, shim, conversion, feature-gated fallback or dual baseline.

### rss-diag-context 0.1.0

- Establish the initial root-only diagnostic-context API: validated `CorrelationId`, owned
  `DiagnosticCtx`, and optional task-local `scope`, `current`, and `correlation` accessors.
- Require explicit `features = ["task-local"]` for ambient propagation. Default value consumers,
  including transactional messaging core, no longer acquire Tokio through diagnostics.
- Keep missing ambient context fail-open while preventing diagnostic correlation from becoming an
  identity, tenant, authentication, or authorization source.
- Set MSRV to Rust 1.96 with no default features. The normal direct dependencies are limited to
  `thiserror`, plus Tokio task-local runtime support only when explicitly selected.
- This is the initial public API; there is no earlier published version, compatibility
  shim, or migration path.

### rss-trace-context 0.1.0

- Establish the initial W3C Trace Context API with validated `TraceParent`, owned
  `W3cTraceContext`, closed parse errors, and closed restore outcomes.
- Keep malformed or unavailable trace propagation fail-open without exposing raw input,
  OpenTelemetry SDK errors, or SDK types through the public API.
- Set MSRV to Rust 1.96 with no default features and keep exporter, subscriber, and test helpers out
  of the published dependency and feature surface.
- This is the initial public API; there is no earlier published version, compatibility
  shim, or migration path.
