use std::time::Duration;

use release_package::delivery::{
    ConsumerTxOutcome, DeliveryBudget, PublishErrorKind, RejectKind,
};
use release_package::envelope::{EventEnvelope, EventId};
use release_package::lifecycle::{
    ConsumerTxAction, ConsumerTxLifecycle, RetryPolicy, ShutdownBudget,
};
use release_package::metadata::EventMetadata;
use release_package::observability::{
    EventingEvent, EventingMetric, eventing_observability_descriptor,
};
use rss_contract::{ContractDescriptor, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;

type ProofResult = Result<(), Box<dyn std::error::Error>>;

fn ensure(condition: bool, failure: &'static str) -> Result<(), std::io::Error> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::other(failure))
    }
}

fn check_metadata_envelope_roundtrip() -> ProofResult {
    let tenant = TenantId::parse("2f1c5f2a-39d8-4c3b-a872-f6f724313a39")?;
    let occurred_at = Timepoint::try_from(1_700_000_000_i64)?;
    let correlation = CorrelationId::parse("package-proof-42")?;
    let metadata = EventMetadata::new(tenant, occurred_at, Some(correlation));
    let contract = ContractDescriptor::from_static(
        "example.event-authored",
        1,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    let envelope = EventEnvelope::new(
        contract,
        EventId::parse("event-42")?,
        metadata,
        "payload",
    )
    .map_payload(str::len);
    let (actual_contract, actual_event_id, actual_metadata, payload_len) = envelope.into_parts();
    ensure(actual_contract == contract, "event contract did not round-trip")?;
    ensure(
        actual_event_id.as_str() == "event-42",
        "event identity did not round-trip",
    )?;
    ensure(
        actual_metadata.tenant_id() == tenant,
        "event tenant did not round-trip",
    )?;
    ensure(
        actual_metadata.occurred_at() == occurred_at,
        "event timepoint did not round-trip",
    )?;
    ensure(
        actual_metadata
            .correlation()
            .is_some_and(|value| value.as_str() == "package-proof-42"),
        "event correlation did not round-trip",
    )?;
    ensure(payload_len == 7, "mapped event payload was incorrect")?;
    ensure(EventId::parse("").is_err(), "empty event identity was accepted")?;
    ensure(
        EventId::parse(&"x".repeat(256)).is_err(),
        "oversized event identity was accepted",
    )?;
    ensure(
        EventId::parse("event\ninjected").is_err(),
        "control character in event identity was accepted",
    )?;
    Ok(())
}

fn check_delivery_closed() -> ProofResult {
    let invalid_budget = DeliveryBudget::new(
        Duration::from_millis(30),
        Duration::from_millis(10),
        Duration::from_millis(10),
        Duration::from_millis(10),
    );
    ensure(
        ConsumerTxOutcome::<()>::Rejected(RejectKind::Invariant).as_label()
            == "rejected_invariant",
        "rejected invariant label changed",
    )?;
    ensure(
        ConsumerTxOutcome::<()>::CommitUnknown.as_label() == "commit_unknown",
        "commit unknown label changed",
    )?;
    ensure(
        PublishErrorKind::Ambiguous.is_ambiguous(),
        "ambiguous publish outcome lost ambiguity",
    )?;
    ensure(
        PublishErrorKind::Ambiguous.is_retryable(),
        "ambiguous publish outcome lost retryability",
    )?;
    ensure(invalid_budget.is_err(), "invalid delivery budget was accepted")?;
    Ok(())
}

async fn check_lifecycle_bounded() -> ProofResult {
    let mut lifecycle = ConsumerTxLifecycle::new(RetryPolicy::STANDARD);
    let first = lifecycle
        .finish_attempt(&ConsumerTxOutcome::<()>::HandlerTransient, |_| async {})
        .await?;
    let second = lifecycle
        .finish_attempt(&ConsumerTxOutcome::<()>::HandlerTransient, |_| async {})
        .await?;
    let exhausted = lifecycle
        .finish_attempt(&ConsumerTxOutcome::<()>::HandlerTransient, |_| async {})
        .await?;
    ensure(
        matches!(
            first,
            ConsumerTxAction::RetryReady { failed_attempt, delay }
                if failed_attempt.get() == 1 && delay == Duration::from_secs(1)
        ),
        "transient lifecycle outcome did not enter the bounded retry state",
    )?;
    ensure(
        matches!(
            second,
            ConsumerTxAction::RetryReady { failed_attempt, delay }
                if failed_attempt.get() == 2 && delay == Duration::from_secs(2)
        ),
        "second transient outcome did not enter the final bounded retry state",
    )?;
    ensure(
        exhausted == ConsumerTxAction::Exhausted,
        "third transient outcome did not exhaust the retry policy",
    )?;
    ensure(
        lifecycle.current_attempt().is_none(),
        "terminal lifecycle retained an active attempt",
    )?;
    ensure(
        lifecycle
            .finish_attempt(&ConsumerTxOutcome::<()>::HandlerTransient, |_| async {})
            .await
            .is_err(),
        "exhausted lifecycle accepted another attempt",
    )?;
    ensure(
        ShutdownBudget::STANDARD.timeout() == Duration::from_secs(45),
        "standard shutdown budget changed",
    )?;
    ensure(
        ShutdownBudget::new(Duration::ZERO).is_err(),
        "zero shutdown budget was accepted",
    )?;
    Ok(())
}

fn check_observability_descriptor() -> ProofResult {
    let descriptor = eventing_observability_descriptor();
    let forbidden = [
        "tenant_id",
        "event_id",
        "topic",
        "provider_address",
        "payload",
        "error_text",
    ];
    ensure(
        descriptor.metrics() == EventingMetric::ALL,
        "metric descriptor inventory changed",
    )?;
    ensure(
        descriptor.events() == EventingEvent::ALL,
        "event descriptor inventory changed",
    )?;
    ensure(
        descriptor.metrics().iter().all(|metric| {
            metric
                .label_keys()
                .iter()
                .all(|key| !forbidden.contains(key))
        }),
        "metric descriptor exposed a forbidden high-cardinality label",
    )?;
    ensure(
        descriptor.events().iter().all(|event| {
            event
                .field_keys()
                .iter()
                .all(|key| !forbidden.contains(key))
        }),
        "event descriptor exposed a forbidden high-cardinality field",
    )?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    check_metadata_envelope_roundtrip()?;
    check_delivery_closed()?;
    check_lifecycle_bounded().await?;
    check_observability_descriptor()?;

    println!(
        "{}",
        serde_json::json!({
            "package": "rss-eventing",
            "metadataEnvelopeRoundtrip": true,
            "deliveryClosed": true,
            "lifecycleBounded": true,
            "observabilityDescriptorReachable": true
        })
    );
    Ok(())
}
