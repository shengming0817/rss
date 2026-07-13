#![allow(clippy::expect_used)]

use consistency::{LocalTxBoundary, LocalTxFinalStatus, TxRetryClass, TxRetryFinalStatus};
use metrics_exporter_prometheus::PrometheusBuilder;
use observ::LocalTxObservation;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tracing::{Event, Id, Metadata, Subscriber, field::Visit};
use vocab::{
    ContractBinding, HttpContractOwner, HttpEffectKind, HttpEffectProfile, HttpIdempotency,
    HttpRouteAuth, HttpRouteBinding, HttpSuccessStatus, http::LocalTx,
};

struct TestRoute;

fn route() -> HttpRouteBinding<TestRoute, LocalTx> {
    HttpRouteBinding::from_static(
        HttpContractOwner::domain("identity"),
        ContractBinding::from_static("identity", "identity.password-change", "v1", "test"),
        "/test",
        "POST",
        HttpSuccessStatus::new(204),
        HttpIdempotency::NonIdempotent,
        HttpRouteAuth::ServiceOwned,
        None,
        false,
        HttpEffectProfile::new(&[HttpEffectKind::Write]),
    )
}

#[test]
fn observation_retains_the_route_marker_type() {
    let observation: LocalTxObservation<TestRoute> =
        LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);

    observation.finish(
        1,
        TxRetryFinalStatus::Success,
        Some(LocalTxFinalStatus::Committed),
    );
}

#[test]
fn emits_closed_retry_and_final_metrics() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        let observation = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
        observation.record_failed_attempt(
            1,
            TxRetryClass::Transient,
            Some(LocalTxFinalStatus::RolledBack),
        );
        observation.finish(
            2,
            TxRetryFinalStatus::Success,
            Some(LocalTxFinalStatus::Committed),
        );
    });

    let rendered = handle.render();
    assert!(rendered.contains(
        "localtx_retry_attempts_total{domain=\"identity\",contract_id=\"identity.password-change\",boundary=\"single_domain\",retry_class=\"transient\"} 1"
    ));
    assert!(rendered.contains(
        "localtx_final_total{domain=\"identity\",contract_id=\"identity.password-change\",boundary=\"single_domain\",final_status=\"committed\"} 1"
    ));
    assert!(rendered.contains(
        "localtx_attempts_sum{domain=\"identity\",contract_id=\"identity.password-change\",boundary=\"single_domain\",final_status=\"committed\"} 2"
    ));
}

#[test]
fn unsettled_does_not_forge_final_status_metrics() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        let observation = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
        observation.record_failed_attempt(1, TxRetryClass::Transient, None);
        observation.finish(1, TxRetryFinalStatus::Exhausted, None);
    });

    let rendered = handle.render();
    assert!(rendered.contains("localtx_retry_attempts_total"));
    assert!(!rendered.contains("localtx_final_total"));
    assert!(!rendered.contains("localtx_attempts"));
}

#[derive(Default)]
struct FieldVisitor(BTreeMap<String, String>);

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Clone, Default)]
struct Capture {
    records: Arc<Mutex<CapturedRecords>>,
    event_levels: Arc<Mutex<Vec<tracing::Level>>>,
    warn_only: bool,
}

type CapturedRecords = Vec<(String, BTreeMap<String, String>)>;

impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        !self.warn_only
            || matches!(
                *metadata.level(),
                tracing::Level::ERROR | tracing::Level::WARN
            )
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> Id {
        let mut fields = FieldVisitor::default();
        attrs.record(&mut fields);
        self.records
            .lock()
            .expect("capture lock")
            .push((attrs.metadata().name().to_owned(), fields.0));
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, values: &tracing::span::Record<'_>) {
        let mut fields = FieldVisitor::default();
        values.record(&mut fields);
        if let Some((_, recorded)) = self.records.lock().expect("capture lock").first_mut() {
            recorded.extend(fields.0);
        }
    }

    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = FieldVisitor::default();
        event.record(&mut fields);
        self.records
            .lock()
            .expect("capture lock")
            .push((event.metadata().name().to_owned(), fields.0));
        self.event_levels
            .lock()
            .expect("capture lock")
            .push(*event.metadata().level());
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

impl Capture {
    fn warn_only() -> Self {
        Self {
            warn_only: true,
            ..Self::default()
        }
    }
}

#[test]
fn trace_carries_contract_attempt_and_real_settlement_without_sensitive_fields() {
    let capture = Capture::default();
    let records = Arc::clone(&capture.records);
    let event_levels = Arc::clone(&capture.event_levels);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        let observation = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
        observation.record_failed_attempt(
            1,
            TxRetryClass::Permanent,
            Some(LocalTxFinalStatus::CommitUnknown),
        );
        observation.finish(
            1,
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent),
            Some(LocalTxFinalStatus::CommitUnknown),
        );
    });

    let records = records.lock().expect("capture lock");
    let (_, span) = &records[0];
    assert_eq!(span.get("domain").map(String::as_str), Some("identity"));
    assert_eq!(
        span.get("contract_id").map(String::as_str),
        Some("identity.password-change")
    );
    assert_eq!(
        span.get("boundary").map(String::as_str),
        Some("single_domain")
    );
    assert_eq!(span.get("attempts").map(String::as_str), Some("1"));
    assert_eq!(
        span.get("retry_status").map(String::as_str),
        Some("permanent")
    );
    assert_eq!(
        span.get("final_status").map(String::as_str),
        Some("commit_unknown")
    );
    assert!(records.iter().any(|(_, fields)| {
        fields.get("attempt").map(String::as_str) == Some("1")
            && fields.get("retry_class").map(String::as_str) == Some("permanent")
            && fields.get("final_status").map(String::as_str) == Some("commit_unknown")
    }));
    assert!(
        event_levels
            .lock()
            .expect("capture lock")
            .contains(&tracing::Level::WARN)
    );
    for forbidden in ["tenant_id", "business_key", "sql", "payload", "error"] {
        assert!(
            records
                .iter()
                .all(|(_, fields)| !fields.contains_key(forbidden))
        );
    }
}

#[test]
fn routine_localtx_events_are_debug_only() {
    let capture = Capture::default();
    let event_levels = Arc::clone(&capture.event_levels);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        let observation = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
        observation.record_failed_attempt(
            1,
            TxRetryClass::Transient,
            Some(LocalTxFinalStatus::RolledBack),
        );
        observation.finish(
            2,
            TxRetryFinalStatus::Success,
            Some(LocalTxFinalStatus::Committed),
        );
    });

    let levels = event_levels.lock().expect("capture lock");
    assert!(!levels.is_empty());
    assert!(levels.iter().all(|level| *level == tracing::Level::DEBUG));
}

#[test]
fn exhausted_retry_warns_and_records_closed_status_on_contract_span() {
    let capture = Capture::default();
    let records = Arc::clone(&capture.records);
    let event_levels = Arc::clone(&capture.event_levels);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain).finish(
            3,
            TxRetryFinalStatus::Exhausted,
            Some(LocalTxFinalStatus::RolledBack),
        );
    });

    let records = records.lock().expect("capture lock");
    let (_, span) = &records[0];
    for (key, value) in [
        ("domain", "identity"),
        ("contract_id", "identity.password-change"),
        ("boundary", "single_domain"),
        ("attempts", "3"),
        ("retry_status", "exhausted"),
    ] {
        assert_eq!(span.get(key).map(String::as_str), Some(value));
    }
    assert!(records.iter().any(|(_, fields)| {
        fields.get("attempts").map(String::as_str) == Some("3")
            && fields.get("retry_status").map(String::as_str) == Some("exhausted")
    }));
    assert!(
        event_levels
            .lock()
            .expect("capture lock")
            .contains(&tracing::Level::WARN)
    );
}

#[test]
fn rollback_failed_is_a_warning_signal() {
    let capture = Capture::default();
    let event_levels = Arc::clone(&capture.event_levels);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain).finish(
            1,
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent),
            Some(LocalTxFinalStatus::RollbackFailed),
        );
    });

    assert!(
        event_levels
            .lock()
            .expect("capture lock")
            .contains(&tracing::Level::WARN)
    );
}

fn assert_contract_scope(fields: &BTreeMap<String, String>) {
    for (key, value) in [
        ("domain", "identity"),
        ("contract_id", "identity.password-change"),
        ("boundary", "single_domain"),
    ] {
        assert_eq!(fields.get(key).map(String::as_str), Some(value));
    }
}

#[test]
fn unsafe_warnings_are_self_contained_when_info_span_is_disabled() {
    let capture = Capture::warn_only();
    let records = Arc::clone(&capture.records);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        let observation = LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain);
        observation.record_failed_attempt(
            1,
            TxRetryClass::Permanent,
            Some(LocalTxFinalStatus::CommitUnknown),
        );
        observation.finish(
            1,
            TxRetryFinalStatus::NotRetryable(TxRetryClass::Permanent),
            Some(LocalTxFinalStatus::CommitUnknown),
        );
    });

    let records = records.lock().expect("capture lock");
    assert_eq!(records.len(), 2, "only the two unsafe WARN events survive");
    assert!(records.iter().all(|(_, fields)| {
        assert_contract_scope(fields);
        fields.get("final_status").map(String::as_str) == Some("commit_unknown")
    }));
    assert!(
        records
            .iter()
            .any(|(_, fields)| fields.contains_key("attempt"))
    );
    assert!(
        records
            .iter()
            .any(|(_, fields)| fields.contains_key("attempts"))
    );
}

#[test]
fn exhausted_warning_carries_real_settlement_without_info_span() {
    let capture = Capture::warn_only();
    let records = Arc::clone(&capture.records);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain).finish(
            3,
            TxRetryFinalStatus::Exhausted,
            Some(LocalTxFinalStatus::RolledBack),
        );
    });

    let records = records.lock().expect("capture lock");
    assert_eq!(records.len(), 1, "routine completion DEBUG is filtered");
    let fields = &records[0].1;
    assert_contract_scope(fields);
    for (key, value) in [
        ("attempts", "3"),
        ("retry_status", "exhausted"),
        ("final_status", "rolled_back"),
    ] {
        assert_eq!(fields.get(key).map(String::as_str), Some(value));
    }
}

#[test]
fn exhausted_unsettled_warning_does_not_forge_final_status() {
    let capture = Capture::warn_only();
    let records = Arc::clone(&capture.records);
    let dispatch = tracing::Dispatch::new(capture);

    tracing::dispatcher::with_default(&dispatch, || {
        LocalTxObservation::new(route(), LocalTxBoundary::SingleDomain).finish(
            3,
            TxRetryFinalStatus::Exhausted,
            None,
        );
    });

    let records = records.lock().expect("capture lock");
    assert_eq!(records.len(), 1);
    assert_contract_scope(&records[0].1);
    assert!(!records[0].1.contains_key("final_status"));
}
