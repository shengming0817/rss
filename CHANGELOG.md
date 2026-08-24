# Changelog

This changelog records notable changes to packages selected by the positive RSS Release Surface.
Package versions are independent. An `Unreleased` entry does not declare a Release Candidate or a
registry release; exact-artifact RC approval and publication follow [RELEASES.md](RELEASES.md).

## Unreleased

### rss-device-security-contracts 0.1.0

- Export generated authority-free HTTP operation descriptors for the policy PUT and status GET
  Draft contracts, binding canonical contract identity, closed method, and origin-relative path
  template without adding a client or activating routes.

### rss-contract 0.1.0

- Establish the sole public owner for canonical contract IDs, versions, SHA-256 schema digests and descriptors.
- Establish the sole public owner for the closed `DataClass`, `SafeErrorCode`, and
  `SafeErrorCategory` vocabularies and the code-only `SafeError` projection.
- Remove `secure::Sensitivity` without an alias, shim, conversion, or dual API; redaction
  mechanisms remain owned by `secure`.
- Keep registries, generated catalogs, runtime bindings and admission authority outside the package.

### rss-request-context 0.1.0

- Establish authority-free tenant/request values, redacted principals, deadlines, cancellation observation and closed obligation views.
- Keep trusted mint, cancellation trigger, deadline extension and cross-tenant authority internal.

### rss-platform 0.3.0

- Replace the v0.2 crypto/lifecycle/synchronous surface with a typed asynchronous application waist and read-only host projection.
- This is an intentional breaking cutover with no alias, shim, conversion, feature-gated fallback or dual baseline.

### rss-diag-context 0.1.0

- Establish the initial root-only diagnostic-context API: validated `CorrelationId`, owned
  `DiagnosticCtx`, and task-local `scope`, `current`, and `correlation` accessors.
- Keep missing ambient context fail-open while preventing diagnostic correlation from becoming an
  identity, tenant, authentication, or authorization source.
- Set MSRV to Rust 1.96 with no default features. The normal direct dependencies are limited to
  Tokio task-local runtime support and `thiserror`.
- This is the initial Release API baseline; there is no earlier published version, compatibility
  shim, or migration path.

### rss-trace-context 0.1.0

- Establish the initial W3C Trace Context API with validated `TraceParent`, owned
  `W3cTraceContext`, closed parse errors, and closed restore outcomes.
- Keep malformed or unavailable trace propagation fail-open without exposing raw input,
  OpenTelemetry SDK errors, or SDK types through the public API.
- Set MSRV to Rust 1.96 with no default features and keep exporter, subscriber, and test helpers out
  of the published dependency and feature surface.
- This is the initial Release API baseline; there is no earlier published version, compatibility
  shim, or migration path.
