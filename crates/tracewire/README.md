# rss-trace-context

`rss-trace-context` is a standalone-component candidate for validating and propagating W3C Trace
Context through Rust `tracing` spans. It owns the wire-level `TraceParent` boundary while keeping
OpenTelemetry SDK types private.

Parse untrusted input before attempting to attach it:

```rust
use rss_trace_context::{RestoreOutcome, TraceParent, TraceParentError, restore_remote_parent};

let parent = TraceParent::parse(
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
)?;
assert_eq!(
    parent.as_str(),
    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
);

assert!(matches!(
    TraceParent::parse("not-a-traceparent"),
    Err(TraceParentError::Malformed)
));

// No tracing-opentelemetry layer is installed in this example, so propagation degrades without
// changing application behavior.
let span = tracing::info_span!(parent: None, "request");
assert_eq!(
    restore_remote_parent(&span, &parent, None),
    RestoreOutcome::Unavailable
);
# Ok::<(), TraceParentError>(())
```

`TraceParent::parse` does not trim or normalize input. Version `00` uses the strict four-field W3C
form; versions `01..fe` preserve an optional opaque future suffix; version `ff` is rejected. Inputs
over 512 bytes are rejected before content classification. Errors and restore outcomes are closed
and never contain the original value or an SDK error.

`capture_current` returns `None` when no valid OpenTelemetry context is available. A malformed or
oversized `tracestate` is discarded without rejecting an otherwise valid parent. Trace propagation
is observability data: it must never mint identity or tenant authority, change authentication or
authorization, or block an HTTP request, message, or transaction.

The package has no default features. OpenTelemetry exporter/subscriber helpers are intentionally
absent from its feature graph and public API; RSS keeps its multi-consumer harness in the
publish-disabled `tracewiretest` workspace crate.

Cargo publication eligibility and a passing same-revision package proof make this package a
candidate only. RC approval applies to an exact revision and archive digest under the repository's
`RELEASES.md`; it does not publish the package. Versioned notes live in the root `CHANGELOG.md`.

The private bridge follows the W3C Trace Context 1.1 wire rules and the lifecycle of
`tracing-opentelemetry::OpenTelemetrySpanExt::set_parent`:
[W3C Trace Context](https://www.w3.org/TR/trace-context/),
[tracing-opentelemetry source](https://github.com/tokio-rs/tracing-opentelemetry/blob/1d5422f1f37932fd65e434da618b305d4c94ee9c/src/span_ext.rs),
[OpenTelemetry Rust propagator](https://github.com/open-telemetry/opentelemetry-rust/blob/284a37d93b3856e1975c2807ba3af1421ebd9b52/opentelemetry-sdk/src/propagation/trace_context.rs).

Licensed under the MIT License.
