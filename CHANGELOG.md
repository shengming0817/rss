# Changelog

This changelog records notable changes to packages selected by the positive RSS Release Surface.
Package versions are independent. An `Unreleased` entry does not declare a Release Candidate or a
registry release; exact-artifact RC approval and publication follow [RELEASES.md](RELEASES.md).

## Unreleased

### rss-redact 0.1.0

- Establish the sole public owner for diagnostic-output redaction, `SecretText`, `RedactedSource`,
  and `RedactedBytes`, with the `Redact` derive re-exported from the same user-facing package.
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
  `DiagnosticCtx`, and task-local `scope`, `current`, and `correlation` accessors.
- Keep missing ambient context fail-open while preventing diagnostic correlation from becoming an
  identity, tenant, authentication, or authorization source.
- Set MSRV to Rust 1.96 with no default features. The normal direct dependencies are limited to
  Tokio task-local runtime support and `thiserror`.
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
