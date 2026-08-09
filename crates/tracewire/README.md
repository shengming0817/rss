# rss-trace-context

`rss-trace-context` is an unpublished standalone-component candidate for W3C Trace Context capture
and remote-parent restoration with Rust `tracing` spans.

Trace propagation is best-effort observability data: unavailable or invalid context must not block
application, authentication, or tenant flows. OpenTelemetry SDK details and test helpers are not part
of the intended public component surface.

The package remains internal until its final API and same-revision package proof are completed.
Packaging metadata or a successful workspace build is not a release or publication approval.

Licensed under the MIT License.
