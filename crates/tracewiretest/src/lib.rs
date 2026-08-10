//! Internal, publish-disabled OpenTelemetry test harness for trace-context consumers.
//!
//! This crate has no RSS workspace production dependency and is only consumed through
//! `[dev-dependencies]`. It keeps exporter and subscriber types outside the
//! `rss-trace-context` candidate's feature graph and Release API.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::prelude::*;

/// Captured structured event for cross-crate trace-context diagnostics tests.
pub struct TestEvent {
    pub target: String,
    pub level: String,
    pub fields: std::collections::BTreeMap<String, String>,
}

#[derive(Default)]
struct EventVisitor {
    fields: std::collections::BTreeMap<String, String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }
}

#[derive(Clone)]
struct EventCaptureLayer {
    events: std::sync::Arc<std::sync::Mutex<Vec<TestEvent>>>,
}

impl<S> tracing_subscriber::Layer<S> for EventCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(TestEvent {
                target: event.metadata().target().to_owned(),
                level: event.metadata().level().to_string(),
                fields: visitor.fields,
            });
    }
}

/// Run `f` with a deterministic tracing/OpenTelemetry subscriber.
pub fn with_test_subscriber<R>(f: impl FnOnce() -> R) -> R {
    let provider = SdkTracerProvider::builder().build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("tracewire-test"));
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, f)
}

/// Exported span snapshot for cross-crate conformance tests.
pub struct TestSpan {
    pub name: String,
    pub kind: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
    pub tracestate: String,
    pub status: String,
    pub attributes: std::collections::BTreeMap<String, String>,
}

static TEST_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static TEST_GLOBAL_SUBSCRIBER: std::sync::Once = std::sync::Once::new();

/// Run `f` under a structured-event capture subscriber.
///
/// Capture sessions are process-serialized because tracing callsite interest is process-global.
pub fn with_test_event_capture<R>(f: impl FnOnce() -> R) -> (R, Vec<TestEvent>) {
    let _serial = TEST_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    TEST_GLOBAL_SUBSCRIBER.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: events.clone(),
    });
    let dispatch = tracing::Dispatch::new(subscriber);
    let result = tracing::dispatcher::with_default(&dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    drop(dispatch);
    let mut guard = events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let captured = std::mem::take(&mut *guard);
    drop(guard);
    (result, captured)
}

/// Run `future` under an isolated in-memory exporter and return deterministic span snapshots.
///
/// Capture sessions are process-serialized because tracing callsite interest is process-global.
#[allow(clippy::expect_used)]
pub fn with_test_span_capture<F>(future: F) -> (F::Output, Vec<TestSpan>)
where
    F: std::future::Future,
{
    let _serial = TEST_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    TEST_GLOBAL_SUBSCRIBER.call_once(|| {
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("tracewire-test"));
    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = tracing::Dispatch::new(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test span capture runtime");
    let result = tracing::dispatcher::with_default(&dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        runtime.block_on(future.with_subscriber(dispatch.clone()))
    });
    provider.force_flush().expect("flush captured spans");
    let spans = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .map(|span| TestSpan {
            name: span.name.into_owned(),
            kind: format!("{:?}", span.span_kind).to_ascii_lowercase(),
            trace_id: span.span_context.trace_id().to_string(),
            span_id: span.span_context.span_id().to_string(),
            parent_span_id: span.parent_span_id.to_string(),
            tracestate: span.span_context.trace_state().header(),
            status: format!("{:?}", span.status).to_ascii_lowercase(),
            attributes: span
                .attributes
                .into_iter()
                .map(|kv| (kv.key.as_str().to_owned(), kv.value.to_string()))
                .collect(),
        })
        .collect();
    (result, spans)
}

#[cfg(test)]
mod tests {
    fn shared_test_callsite() {
        let span = tracing::info_span!("tracewiretest.shared.test.callsite");
        let _entered = span.enter();
    }

    #[test]
    fn span_capture_survives_parallel_preregistration_and_spawn() {
        assert!(
            std::thread::spawn(shared_test_callsite).join().is_ok(),
            "pre-register callsite thread completes"
        );

        let (_, spans) = super::with_test_span_capture(async {
            assert!(
                tokio::spawn(async { shared_test_callsite() }).await.is_ok(),
                "captured task completes"
            );
        });

        assert_eq!(
            spans
                .iter()
                .filter(|span| span.name == "tracewiretest.shared.test.callsite")
                .count(),
            1
        );
    }
}
