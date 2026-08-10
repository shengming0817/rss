use opentelemetry::trace::TracerProvider as _;
use release_package::{
    RestoreOutcome, TraceParent, TraceParentError, capture_current, restore_remote_parent,
};
use tracing_subscriber::prelude::*;

const V00: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn trace_id(traceparent: &str) -> Option<&str> {
    traceparent.split('-').nth(1)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parent = TraceParent::parse(V00)?;
    let v00_roundtrip = parent.as_str() == V00;
    let future = V00.replacen("00-", "01-", 1) + "-opaque";
    let future_version_accepted = TraceParent::parse(&future)?.as_str() == future;
    let malformed_rejected = matches!(
        TraceParent::parse("not-a-traceparent"),
        Err(TraceParentError::Malformed)
    );
    let oversized = "a".repeat(513);
    let oversized_rejected = matches!(
        TraceParent::parse(&oversized),
        Err(TraceParentError::Oversized)
    );
    let unsupported = V00.replacen("00-", "ff-", 1);
    let unsupported_error = TraceParent::parse(&unsupported)
        .err()
        .ok_or_else(|| std::io::Error::other("reserved version accepted"))?;
    let unsupported_rejected = unsupported_error == TraceParentError::UnsupportedVersion
        && !unsupported_error.to_string().contains(&unsupported);

    let unavailable_span = tracing::info_span!(parent: None, "unavailable");
    let restore_unavailable = restore_remote_parent(&unavailable_span, &parent, None)
        == RestoreOutcome::Unavailable;

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("package-proof"));
    let subscriber = tracing_subscriber::registry().with(layer);
    let (restore_restored, invalid_state_dropped) =
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(parent: None, "restored");
            let outcome = restore_remote_parent(&span, &parent, Some("INVALID KEY=value"));
            let captured = span.in_scope(capture_current);
            (
                outcome == RestoreOutcome::Restored
                    && captured.as_ref().and_then(|context| {
                        trace_id(context.traceparent().as_str())
                    }) == trace_id(parent.as_str()),
                captured.is_some_and(|context| context.tracestate().is_none()),
            )
        });
    let fail_open_no_panic = capture_current().is_none() && malformed_rejected;

    println!(
        "{}",
        serde_json::json!({
            "package": "rss-trace-context",
            "v00Roundtrip": v00_roundtrip,
            "futureVersionAccepted": future_version_accepted,
            "malformedRejected": malformed_rejected,
            "oversizedRejected": oversized_rejected,
            "unsupportedRejected": unsupported_rejected,
            "restoreRestored": restore_restored,
            "restoreUnavailable": restore_unavailable,
            "invalidStateDropped": invalid_state_dropped,
            "failOpenNoPanic": fail_open_no_panic
        })
    );
    Ok(())
}
