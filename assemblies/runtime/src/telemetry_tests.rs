use super::telemetry::{StructuredJsonLayer, parse_log_filter};
use otel::TelemetryResource;
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

struct BufferWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for BufferWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("buffer lock poisoned"))?
            .write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for Buffer {
    type Writer = BufferWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        BufferWriter(Arc::clone(&self.0))
    }
}

impl Buffer {
    #[allow(clippy::expect_used)]
    fn lines(&self) -> Vec<Value> {
        let bytes = self.0.lock().expect("buffer lock").clone();
        String::from_utf8(bytes)
            .expect("utf8 log buffer")
            .lines()
            .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
            .collect()
    }
}

#[allow(clippy::expect_used)] // reason: fixed non-empty fixture literals must construct.
fn resource() -> TelemetryResource {
    TelemetryResource::try_new("runtime", "assembly-fp", "plan-fp")
        .expect("non-empty telemetry resource")
}

const ENVELOPE_KEYS: &[&str] = &[
    "attributes",
    "correlation",
    "level",
    "message",
    "request_id",
    "resource",
    "schema_version",
    "span_id",
    "target",
    "timestamp",
    "trace_id",
];
const RESOURCE_KEYS: &[&str] = &[
    "rss.assembly.fingerprint",
    "rss.runtime_plan.fingerprint",
    "service.name",
];

fn has_exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn is_rfc3339(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

fn is_optional_string(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

fn is_optional_lower_hex_id(value: &Value, width: usize) -> bool {
    value.is_null()
        || value.as_str().is_some_and(|value| {
            value.len() == width
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn structured_envelope_is_valid(value: &Value) -> bool {
    let Some(log) = value.as_object() else {
        return false;
    };
    let Some(resource) = log["resource"].as_object() else {
        return false;
    };
    let Some(attributes) = log["attributes"].as_object() else {
        return false;
    };
    has_exact_keys(log, ENVELOPE_KEYS)
        && log["schema_version"] == 1
        && log["timestamp"].as_str().is_some_and(is_rfc3339)
        && matches!(
            log["level"].as_str(),
            Some("TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR")
        )
        && log["target"]
            .as_str()
            .is_some_and(|target| !target.is_empty())
        && is_optional_string(&log["message"])
        && is_optional_lower_hex_id(&log["trace_id"], 32)
        && is_optional_lower_hex_id(&log["span_id"], 16)
        && is_optional_string(&log["request_id"])
        && is_optional_string(&log["correlation"])
        && has_exact_keys(resource, RESOURCE_KEYS)
        && resource
            .values()
            .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
        && attributes.values().all(|value| {
            value.is_null() || value.is_string() || value.is_number() || value.is_boolean()
        })
}

#[test]
fn structured_json_rejects_non_rfc3339_timestamps() {
    assert!(!is_rfc3339("not-a-dateTZ"));
}

#[test]
#[allow(clippy::expect_used)] // reason: parser success/failure is the direct assertion subject.
fn rust_log_filter_is_fail_fast_and_never_echoes_the_raw_directive() {
    assert_eq!(
        parse_log_filter(None).expect("default filter").to_string(),
        "info"
    );
    assert_eq!(
        parse_log_filter(Some("runtime=debug"))
            .expect("valid filter")
            .to_string(),
        "runtime=debug"
    );
    for raw in [
        "",
        " ",
        ",",
        ",,",
        "runtime=debug,",
        ",runtime=debug",
        "runtime=debug,,otel=info",
        "runtime=[SECRET_BAIT",
    ] {
        let error = parse_log_filter(Some(raw)).expect_err("invalid filter must fail");
        for rendered in [error.to_string(), format!("{error:?}")] {
            assert!(rendered.contains("RUST_LOG"));
            if raw.contains("SECRET_BAIT") {
                assert!(!rendered.contains(raw));
            }
            assert!(!rendered.contains("SECRET_BAIT"));
        }
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
#[allow(clippy::cognitive_complexity, clippy::expect_used)] // reason: one envelope contract matrix is easier to audit atomically.
// INVARIANT: RUNTIME-JSON-ENVELOPE-01 { level = "Medium", exec = "test", source = "code", native = "exact envelope key and value assertions" }
fn structured_json_has_a_closed_v1_envelope_and_null_context_without_otel() {
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(parse_log_filter(Some("info")).expect("filter"))
        .with(StructuredJsonLayer::new(buffer.clone(), resource()));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(attempt = 7_u64, ready = true, "runtime ready");
    });

    let lines = buffer.lines();
    assert_eq!(lines.len(), 1);
    let log = lines[0].as_object().expect("JSON object");
    assert!(has_exact_keys(log, ENVELOPE_KEYS));
    assert_eq!(log["schema_version"], 1);
    assert_eq!(log["level"], "INFO");
    assert_eq!(log["message"], "runtime ready");
    assert!(log["trace_id"].is_null());
    assert!(log["span_id"].is_null());
    assert!(log["request_id"].is_null());
    assert!(log["correlation"].is_null());
    assert_eq!(log["attributes"]["attempt"], 7);
    assert_eq!(log["attributes"]["ready"], true);
    assert_eq!(log["resource"]["service.name"], "runtime");
    assert_eq!(log["resource"]["rss.assembly.fingerprint"], "assembly-fp");
    assert_eq!(log["resource"]["rss.runtime_plan.fingerprint"], "plan-fp");
    assert!(structured_envelope_is_valid(&lines[0]));

    for (field, invalid) in [
        ("timestamp", Value::String("not-a-dateTZ".to_owned())),
        ("trace_id", Value::String("A".repeat(32))),
        ("span_id", Value::String("0".repeat(15))),
        (
            "attributes",
            serde_json::json!({"nested": {"forbidden": true}}),
        ),
    ] {
        let mut invalid_log = lines[0].clone();
        invalid_log[field] = invalid;
        assert!(
            !structured_envelope_is_valid(&invalid_log),
            "invalid {field} must be rejected"
        );
    }
    let mut unknown = lines[0].clone();
    unknown["legacy_text"] = Value::String("forbidden".to_owned());
    assert!(!structured_envelope_is_valid(&unknown));

    let mut unknown_resource = lines[0].clone();
    unknown_resource["resource"]["legacy"] = Value::String("forbidden".to_owned());
    assert!(!structured_envelope_is_valid(&unknown_resource));
}

#[test]
#[allow(clippy::expect_used)] // reason: fixed fixture capture is a test prerequisite.
fn structured_json_normalizes_an_empty_target() {
    let buffer = Buffer::default();
    let subscriber =
        tracing_subscriber::registry().with(StructuredJsonLayer::new(buffer.clone(), resource()));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "", "empty target");
    });

    let lines = buffer.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["target"], "unknown");
    assert!(structured_envelope_is_valid(&lines[0]));
}

#[test]
#[allow(clippy::cognitive_complexity, clippy::expect_used)] // reason: inheritance/redaction precedence is asserted as one matrix.
fn structured_json_inherits_span_context_and_redacts_span_and_event_fields() {
    let buffer = Buffer::default();
    let subscriber =
        tracing_subscriber::registry().with(StructuredJsonLayer::new(buffer.clone(), resource()));
    tracing::subscriber::with_default(subscriber, || {
        let root = tracing::info_span!(
            "request",
            request_id = "req-1",
            correlation = "corr-root",
            authorization = "Bearer SECRET_BAIT",
            inherited = "root"
        );
        let _root = root.enter();
        let child = tracing::info_span!(
            "handler",
            correlation = "corr-child",
            dsn = "postgres://user:SECRET_BAIT@db.internal/rss"
        );
        let _child = child.enter();
        tracing::warn!(
            inherited = "event",
            access_token = "SECRET_BAIT",
            "request failed at postgres://user:SECRET_BAIT@db.internal/rss"
        );
    });

    let lines = buffer.lines();
    assert_eq!(lines.len(), 1);
    let log = &lines[0];
    assert_eq!(log["request_id"], "req-1");
    assert_eq!(log["correlation"], "corr-child");
    assert_eq!(log["attributes"]["inherited"], "event");
    assert_eq!(log["attributes"]["authorization"], "<redacted>");
    assert_eq!(log["attributes"]["access_token"], "<redacted>");
    assert_eq!(
        log["attributes"]["dsn"],
        "postgres://<redacted>@db.internal/rss"
    );
    assert_eq!(
        log["message"],
        "request failed at postgres://<redacted>@db.internal/rss"
    );
    assert!(
        !serde_json::to_string(log)
            .expect("serialize log")
            .contains("SECRET_BAIT")
    );
}

#[test]
#[allow(clippy::cognitive_complexity)] // reason: three event variants intentionally share one captured span scope.
fn only_event_message_is_promoted_and_process_errors_use_the_json_funnel() {
    let buffer = Buffer::default();
    let subscriber =
        tracing_subscriber::registry().with(StructuredJsonLayer::new(buffer.clone(), resource()));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("message_owner", message = "span message");
        let _entered = span.enter();
        tracing::event!(tracing::Level::INFO, source = "span-only");
        tracing::info!(source = "event", "event message");
        super::telemetry::emit_process_error(&anyhow::anyhow!(
            "postgres://user:SECRET_BAIT@db.internal/rss"
        ));
    });

    let logs = buffer.lines();
    assert_eq!(logs.len(), 3);
    assert!(logs[0]["message"].is_null());
    assert_eq!(logs[0]["attributes"]["message"], "span message");
    assert_eq!(logs[1]["message"], "event message");
    assert_eq!(logs[1]["attributes"]["message"], "span message");
    assert_eq!(
        logs[2]["attributes"]["error"],
        "postgres://<redacted>@db.internal/rss"
    );
    assert!(!format!("{logs:?}").contains("SECRET_BAIT"));
}

#[test]
#[allow(clippy::expect_used)] // reason: missing exported fixture span is the assertion failure.
fn explicit_unentered_parent_keeps_json_and_otel_ids_identical() {
    let resource = resource();
    let (exporter, recorder) = otel::test_support::recording_exporter(&resource);
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(exporter.layer())
        .with(StructuredJsonLayer::new(buffer.clone(), resource));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "explicit_parent",
            request_id = "req-explicit",
            correlation = "corr-explicit"
        );
        tracing::error!(parent: &span, outcome = "failed", "explicit parent event");
    });

    let logs = buffer.lines();
    let spans = recorder.spans();
    let span = spans
        .iter()
        .find(|span| span.name() == "explicit_parent")
        .expect("explicit parent span exported");
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["trace_id"], span.trace_id());
    assert_eq!(logs[0]["span_id"], span.span_id());
    assert_eq!(logs[0]["request_id"], "req-explicit");
    assert_eq!(logs[0]["correlation"], "corr-explicit");
    assert!(structured_envelope_is_valid(&logs[0]));
}

#[test]
#[allow(clippy::cognitive_complexity, clippy::expect_used)] // reason: cross-sink parity is a single atomic contract matrix.
// INVARIANT: OBSERVATION-SINK-PARITY-01 { level = "Medium", exec = "test", source = "code", native = "hermetic composed subscriber asserts JSON and OTel identifier, Resource, and redaction parity" }
fn structured_json_and_otel_share_ids_resource_and_redaction() {
    #[derive(secure::Redact)]
    #[allow(dead_code)]
    struct DeclaredPii {
        #[redact(sensitivity = pii_email)]
        email: String,
    }

    let resource = resource();
    let (exporter, recorder) = otel::test_support::recording_exporter(&resource);
    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::registry()
        .with(exporter.layer())
        .with(StructuredJsonLayer::new(buffer.clone(), resource.clone()));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!(
            "composed",
            request_id = "req-otel",
            correlation = "corr-otel",
            authorization = "Bearer SECRET_BAIT",
            password = "SECRET_BAIT",
            private_key = "SECRET_BAIT",
            declared_pii = %secure::safe(
                &DeclaredPii { email: "SECRET_BAIT@example.com".to_owned() },
                secure::RedactScope::Wire,
            )
        );
        let _entered = span.enter();
        tracing::error!(
            access_token = "SECRET_BAIT",
            apiKey = "SECRET_BAIT",
            cookie = "SECRET_BAIT",
            session_id = "SECRET_BAIT",
            jwt = "SECRET_BAIT",
            bearer_value = "SECRET_BAIT",
            salt = "SECRET_BAIT",
            dsn = "postgres://user:SECRET_BAIT@db.internal/rss",
            detail = "probe http://safe/x then postgres://user:SECRET_BAIT@db.internal/rss and amqp://u:SECRET_BAIT@mq/v",
            "provider failed"
        );
    });

    let logs = buffer.lines();
    assert_eq!(logs.len(), 1);
    let spans = recorder.spans();
    let span = spans
        .iter()
        .find(|span| span.name() == "composed")
        .expect("composed span exported");
    assert_eq!(logs[0]["trace_id"], span.trace_id());
    assert_eq!(logs[0]["span_id"], span.span_id());
    assert_eq!(logs[0]["request_id"], "req-otel");
    assert_eq!(logs[0]["correlation"], "corr-otel");
    assert!(structured_envelope_is_valid(&logs[0]));
    assert_eq!(
        span.attributes().get("request_id").map(String::as_str),
        Some("req-otel")
    );
    assert_eq!(
        span.attributes().get("correlation").map(String::as_str),
        Some("corr-otel")
    );
    for key in ["authorization", "password", "private_key"] {
        assert_eq!(
            span.attributes().get(key).map(String::as_str),
            Some("<redacted>"),
            "span field {key} must be redacted"
        );
        assert_eq!(logs[0]["attributes"][key], "<redacted>");
    }
    assert_eq!(
        span.attributes().get("declared_pii").map(String::as_str),
        Some("DeclaredPii { email: <redacted> }")
    );
    assert_eq!(
        logs[0]["attributes"]["declared_pii"],
        "DeclaredPii { email: <redacted> }"
    );
    for key in [
        "access_token",
        "apiKey",
        "cookie",
        "session_id",
        "jwt",
        "bearer_value",
        "salt",
    ] {
        assert_eq!(
            span.events()[0].get(key).map(String::as_str),
            Some("<redacted>"),
            "event field {key} must be redacted"
        );
        assert_eq!(logs[0]["attributes"][key], "<redacted>");
    }
    assert_eq!(
        span.events()[0].get("dsn").map(String::as_str),
        Some("postgres://<redacted>@db.internal/rss")
    );
    assert_eq!(
        span.events()[0].get("detail").map(String::as_str),
        Some(
            "probe http://safe/x then postgres://<redacted>@db.internal/rss and amqp://<redacted>@mq/v"
        )
    );
    assert_eq!(
        logs[0]["attributes"]["detail"],
        "probe http://safe/x then postgres://<redacted>@db.internal/rss and amqp://<redacted>@mq/v"
    );
    let exported_resource = recorder.resource();
    assert_eq!(
        exported_resource,
        std::collections::BTreeMap::from([
            (
                "rss.assembly.fingerprint".to_owned(),
                "assembly-fp".to_owned()
            ),
            (
                "rss.runtime_plan.fingerprint".to_owned(),
                "plan-fp".to_owned()
            ),
            ("service.name".to_owned(), "runtime".to_owned()),
        ])
    );
    let json_resource = logs[0]["resource"]
        .as_object()
        .expect("JSON resource")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("string resource value").to_owned(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(json_resource, exported_resource);
    let json = serde_json::to_string(&logs).expect("serialize logs");
    let exported = format!("{spans:?}");
    for output in [&json, &exported] {
        assert!(!output.contains("SECRET_BAIT"));
        assert!(output.contains("<redacted>"));
    }
}
