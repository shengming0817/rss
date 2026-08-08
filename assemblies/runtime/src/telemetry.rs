use anyhow::Context as _;
use observ::TelemetryResource;
use serde::Serialize;
use serde_json::{Number, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::field::{Field, Visit};
use tracing::{Dispatch, Event, Id, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime as _, SystemTime};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

pub(crate) const OTEL_ENDPOINT_ENV: &str = "RSS_OTEL_ENDPOINT";
static JSON_SUBSCRIBER_INSTALLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn build_trace_export(
    config: crate::config::SnapshotConfig<'_>,
    resource: &TelemetryResource,
) -> anyhow::Result<Option<otel::OtelExporter>> {
    build_trace_export_from_value(config.value(OTEL_ENDPOINT_ENV), resource)
}

pub(crate) fn build_trace_export_from_value(
    raw: Option<&str>,
    resource: &TelemetryResource,
) -> anyhow::Result<Option<otel::OtelExporter>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let endpoint = if raw.starts_with("https://") {
        otel::OtelEndpoint::tls(raw).context("RSS_OTEL_ENDPOINT https (TLS) endpoint")?
    } else if raw.starts_with("http://") {
        otel::OtelEndpoint::insecure_localhost(raw)
            .context("RSS_OTEL_ENDPOINT http endpoint must target a loopback host")?
    } else {
        anyhow::bail!("{OTEL_ENDPOINT_ENV} must be https:// (TLS) or http:// to a loopback host");
    };
    let provider =
        otel::build_otlp_provider(endpoint, resource).context("build OTLP/gRPC trace provider")?;
    Ok(Some(otel::OtelExporter::new(provider)))
}

pub(crate) fn prepare_local_before_external<Local, External>(
    config: crate::config::SnapshotConfig<'_>,
    prepare_local: impl FnOnce(crate::config::SnapshotConfig<'_>) -> anyhow::Result<Local>,
    build_external: impl FnOnce() -> anyhow::Result<External>,
) -> anyhow::Result<(Local, External)> {
    let local = prepare_local(config)?;
    let external = build_external()?;
    Ok((local, external))
}

pub(crate) fn install_runtime_subscriber(
    filter: EnvFilter,
    resource: TelemetryResource,
    trace_export: Option<&otel::OtelExporter>,
) -> anyhow::Result<()> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let otel_layer = trace_export.map(|exporter| exporter.layer());
    tracing_subscriber::registry()
        .with(filter)
        .with(otel_layer)
        .with(StructuredJsonLayer::new(std::io::stderr, resource))
        .try_init()
        .context("install runtime-managed tracing subscriber")?;
    JSON_SUBSCRIBER_INSTALLED.store(true, Ordering::Release);
    Ok(())
}

const SCHEMA_VERSION: u8 = 1;
const UNKNOWN_TARGET: &str = "unknown";

/// Safe startup error for a present but invalid `RUST_LOG` directive.
#[derive(thiserror::Error)]
pub(crate) enum TelemetryInitError {
    #[error("invalid RUST_LOG directive")]
    InvalidRustLog,
}

impl fmt::Debug for TelemetryInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid RUST_LOG directive")
    }
}

/// Parse the snapshot-backed filter. Absence alone selects `info`; present invalid input fails.
pub(crate) fn parse_log_filter(raw: Option<&str>) -> Result<EnvFilter, TelemetryInitError> {
    match raw {
        None => Ok(EnvFilter::new("info")),
        Some(raw)
            if raw.trim().is_empty()
                || raw.split(',').any(|directive| directive.trim().is_empty()) =>
        {
            Err(TelemetryInitError::InvalidRustLog)
        }
        Some(raw) => EnvFilter::try_new(raw).map_err(|_| TelemetryInitError::InvalidRustLog),
    }
}

pub(crate) fn emit_process_error(error: &anyhow::Error) {
    tracing::error!(error = %error, "runtime process failed");
}

pub(crate) fn report_process_error(error: &anyhow::Error) -> bool {
    if JSON_SUBSCRIBER_INSTALLED.load(Ordering::Acquire) {
        emit_process_error(error);
        true
    } else {
        false
    }
}

/// Versioned JSON stderr sink with span inheritance and a closed top-level envelope.
///
/// INVARIANT: RUNTIME-JSON-ENVELOPE-V1-01 { level = "Hard", exec = "native-compile", source = "code", native = "concrete serializer with no flatten field plus private layer construction" } -- runtime-managed diagnostic events can only be serialized through the fixed v1 envelope; arbitrary tracing fields remain nested under attributes.
pub(crate) struct StructuredJsonLayer<W> {
    writer: W,
    resource: TelemetryResource,
    dispatch: OnceLock<tracing::dispatcher::WeakDispatch>,
}

impl<W> StructuredJsonLayer<W> {
    pub(crate) fn new(writer: W, resource: TelemetryResource) -> Self {
        Self {
            writer,
            resource,
            dispatch: OnceLock::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct SpanAttributes(BTreeMap<String, Value>);

#[derive(Default)]
struct JsonVisitor {
    fields: BTreeMap<String, Value>,
}

impl JsonVisitor {
    fn record_text(&mut self, field: &Field, value: &str) {
        self.fields.insert(
            field.name().to_owned(),
            Value::String(
                secure::redact_observation_field(field.name(), value)
                    .as_str()
                    .to_owned(),
            ),
        );
    }
}

impl Visit for JsonVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), Value::Bool(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        let value = Number::from_f64(value)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(value.to_string()));
        self.fields.insert(field.name().to_owned(), value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_text(field, value);
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_text(field, &value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_text(field, &format!("{value:?}"));
    }
}

#[derive(Serialize)]
struct StructuredResourceV1 {
    #[serde(rename = "service.name")]
    service_name: String,
    #[serde(rename = "rss.assembly.fingerprint")]
    assembly_fingerprint: String,
    #[serde(rename = "rss.runtime_plan.fingerprint")]
    runtime_plan_fingerprint: String,
}

impl From<&TelemetryResource> for StructuredResourceV1 {
    fn from(resource: &TelemetryResource) -> Self {
        Self {
            service_name: resource.service_name().to_owned(),
            assembly_fingerprint: resource.assembly_fingerprint().to_owned(),
            runtime_plan_fingerprint: resource.runtime_plan_fingerprint().to_owned(),
        }
    }
}

#[derive(Serialize)]
struct StructuredLogV1 {
    schema_version: u8,
    timestamp: String,
    level: String,
    target: String,
    message: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    request_id: Option<String>,
    correlation: Option<String>,
    resource: StructuredResourceV1,
    attributes: BTreeMap<String, Value>,
}

fn current_timestamp() -> String {
    let mut timestamp = String::new();
    let mut writer = Writer::new(&mut timestamp);
    let _ = SystemTime.format_time(&mut writer);
    timestamp
}

fn take_string(fields: &mut BTreeMap<String, Value>, key: &str) -> Option<String> {
    fields.remove(key).map(|value| match value {
        Value::String(value) => value,
        other => other.to_string(),
    })
}

impl<S, W> Layer<S> for StructuredJsonLayer<W>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    fn on_register_dispatch(&self, subscriber: &Dispatch) {
        let _ = self.dispatch.set(subscriber.downgrade());
    }

    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        id: &Id,
        context: Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        attributes.record(&mut visitor);
        if let Some(span) = context.span(id) {
            span.extensions_mut().insert(SpanAttributes(visitor.fields));
        }
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, context: Context<'_, S>) {
        let mut visitor = JsonVisitor::default();
        values.record(&mut visitor);
        if let Some(span) = context.span(id) {
            let mut extensions = span.extensions_mut();
            if let Some(stored) = extensions.get_mut::<SpanAttributes>() {
                stored.0.extend(visitor.fields);
            } else {
                extensions.insert(SpanAttributes(visitor.fields));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let mut attributes = BTreeMap::new();
        let mut parent_span_id = None;
        if let Some(scope) = context.event_scope(event) {
            for span in scope.from_root() {
                parent_span_id = Some(span.id().clone());
                if let Some(stored) = span.extensions().get::<SpanAttributes>() {
                    attributes.extend(stored.0.clone());
                }
            }
        }
        let mut event_fields = JsonVisitor::default();
        event.record(&mut event_fields);
        let message = take_string(&mut event_fields.fields, "message");
        attributes.extend(event_fields.fields);

        let request_id = take_string(&mut attributes, "request_id");
        let correlation = take_string(&mut attributes, "correlation");
        let trace_ids = parent_span_id
            .as_ref()
            .and_then(|span_id| {
                self.dispatch
                    .get()
                    .and_then(tracing::dispatcher::WeakDispatch::upgrade)
                    .as_ref()
                    .and_then(|dispatch| otel::trace_ids_for_span(span_id, dispatch))
            })
            .or_else(otel::current_trace_ids);
        let log = StructuredLogV1 {
            schema_version: SCHEMA_VERSION,
            timestamp: current_timestamp(),
            level: event.metadata().level().as_str().to_owned(),
            target: match event.metadata().target() {
                "" => UNKNOWN_TARGET.to_owned(),
                target => target.to_owned(),
            },
            message,
            trace_id: trace_ids.as_ref().map(|ids| ids.trace_id().to_owned()),
            span_id: trace_ids.as_ref().map(|ids| ids.span_id().to_owned()),
            request_id,
            correlation,
            resource: StructuredResourceV1::from(&self.resource),
            attributes,
        };

        if let Ok(mut line) = serde_json::to_vec(&log) {
            line.push(b'\n');
            let mut writer = self.writer.make_writer();
            let _ = writer.write_all(&line);
        }
    }
}
