# Research decisions

- W3C Trace Context defines parent/state parsing and fail-open diagnostic behavior.
- OpenTelemetry HTTP semantic conventions define SERVER naming and attributes.
- `tracing-opentelemetry` recognizes `otel.name`, `otel.kind`, and `otel.status_code` fields.
- axum `MatchedPath` is the only permitted route-name source; raw URI fallback is forbidden.
- `tracewire` remains the repository bridge to OpenTelemetry APIs, so HTTP service code does not
  import those APIs directly.

References:

- https://www.w3.org/TR/trace-context/
- https://opentelemetry.io/docs/specs/semconv/http/http-spans/
