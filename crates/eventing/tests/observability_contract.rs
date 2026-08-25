use rss_eventing::delivery::{ConsumerTxOutcome, RejectKind};
use rss_eventing::observability::{
    EventingEvent, EventingMetric, EventingObservation, EventingTransactionStatus,
    eventing_observability_descriptor,
};

#[test]
fn descriptor_closes_metric_and_event_exact_sets() {
    let descriptor = eventing_observability_descriptor();
    assert_eq!(descriptor.metrics(), &EventingMetric::ALL);
    assert_eq!(descriptor.events(), &EventingEvent::ALL);
    assert_eq!(EventingMetric::ALL.len(), 16);
    assert_eq!(EventingEvent::ALL.len(), 15);

    assert_eq!(
        EventingMetric::ALL.map(EventingMetric::name),
        [
            "outbox_publish_total",
            "outbox_pending_depth",
            "outbox_oldest_pending_age_seconds",
            "outbox_partition_blocked_depth",
            "outbox_relay_tick_duration_seconds",
            "inbox_stale_claim_depth",
            "inbox_oldest_stale_claim_age_seconds",
            "consumer_claim_in_progress_total",
            "consumer_tx_outcome_total",
            "consumer_settle_total",
            "consumer_dlx_skip_total",
            "consumer_dlx_write_total",
            "consumer_subscribe_retry_total",
            "consumer_lease_lost_total",
            "consumer_release_failed_total",
            "dlq_redrive_total",
        ]
    );
    assert_eq!(EventingMetric::OutboxPublishTotal.label_keys(), &["status"]);
    assert_eq!(
        EventingMetric::OutboxRelayTickDurationSeconds.label_keys(),
        &["phase"]
    );
    assert_eq!(
        EventingMetric::ConsumerSettlementTotal.label_keys(),
        &["action", "outcome"]
    );
    assert_eq!(
        EventingMetric::DlqRedriveTotal.label_keys(),
        &["kind", "outcome"]
    );
    for metric in EventingMetric::ALL {
        assert!(!metric.label_keys().iter().any(|key| matches!(
            *key,
            "tenant_id" | "domain" | "contract_id" | "topic" | "handler" | "event_id"
        )));
    }

    assert_eq!(
        EventingEvent::ALL.map(EventingEvent::name),
        [
            "eventing.outbox.publish",
            "eventing.outbox.backlog",
            "eventing.outbox.backlog_unavailable",
            "eventing.outbox.relay_tick",
            "eventing.inbox.backlog",
            "eventing.inbox.backlog_unavailable",
            "eventing.consumer.claim_in_progress",
            "eventing.consumer.transaction",
            "eventing.consumer.settlement",
            "eventing.consumer.dead_letter_skip",
            "eventing.consumer.dead_letter_write",
            "eventing.consumer.subscribe_retry",
            "eventing.consumer.lease_lost",
            "eventing.consumer.release_failed",
            "eventing.dlq.mutation",
        ]
    );
    assert_eq!(
        EventingEvent::OutboxBacklog.field_keys(),
        &[
            "pending_depth",
            "oldest_pending_age_seconds",
            "partition_blocked_depth"
        ]
    );
}

#[test]
fn transaction_outcome_projects_without_commit_proof() {
    let cases = [
        (
            ConsumerTxOutcome::Committed(()),
            EventingTransactionStatus::Committed,
        ),
        (
            ConsumerTxOutcome::HandlerTransient,
            EventingTransactionStatus::HandlerTransient,
        ),
        (
            ConsumerTxOutcome::InfrastructureTransient,
            EventingTransactionStatus::InfrastructureTransient,
        ),
        (
            ConsumerTxOutcome::Rejected(RejectKind::Permanent),
            EventingTransactionStatus::RejectedPermanent,
        ),
        (
            ConsumerTxOutcome::Rejected(RejectKind::Invariant),
            EventingTransactionStatus::RejectedInvariant,
        ),
        (
            ConsumerTxOutcome::CommitUnknown,
            EventingTransactionStatus::CommitUnknown,
        ),
        (
            ConsumerTxOutcome::RollbackFailed,
            EventingTransactionStatus::RollbackFailed,
        ),
        (ConsumerTxOutcome::Fenced, EventingTransactionStatus::Fenced),
    ];
    for (outcome, expected) in cases {
        assert_eq!(outcome.observability_status(), expected);
        let observation = EventingObservation::ConsumerTransaction { status: expected };
        assert_eq!(observation.event(), EventingEvent::ConsumerTransaction);
    }
}
