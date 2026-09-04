use rss_transactional_messaging::observability::{
    TransactionalMessagingEvent, TransactionalMessagingMetric,
    transactional_messaging_observability_descriptor,
};

#[test]
fn descriptor_closes_metric_and_event_exact_sets() {
    let descriptor = transactional_messaging_observability_descriptor();
    assert_eq!(descriptor.metrics(), &TransactionalMessagingMetric::ALL);
    assert_eq!(descriptor.events(), &TransactionalMessagingEvent::ALL);
    assert_eq!(TransactionalMessagingMetric::ALL.len(), 20);
    assert_eq!(TransactionalMessagingEvent::ALL.len(), 19);

    assert_eq!(
        TransactionalMessagingMetric::ALL.map(TransactionalMessagingMetric::name),
        [
            "transactional_messaging_runtime_failure_total",
            "outbox_publish_total",
            "outbox_publish_failure_total",
            "outbox_pending_depth",
            "outbox_oldest_pending_age_seconds",
            "outbox_partition_blocked_depth",
            "outbox_relay_tick_duration_seconds",
            "inbox_stale_claim_depth",
            "inbox_oldest_stale_claim_age_seconds",
            "consumer_claim_in_progress_total",
            "transactional_messaging_ingress_rejected_total",
            "consumer_tx_outcome_total",
            "consumer_settle_total",
            "consumer_dlx_skip_total",
            "consumer_dlx_write_total",
            "consumer_subscribe_retry_total",
            "consumer_lease_lost_total",
            "outbox_relay_lease_lost_total",
            "consumer_release_failed_total",
            "dlq_redrive_total",
        ]
    );
    assert_eq!(
        TransactionalMessagingMetric::OutboxPublishTotal.label_keys(),
        &["status"]
    );
    assert_eq!(
        TransactionalMessagingMetric::OutboxRelayTickDurationSeconds.label_keys(),
        &["phase"]
    );
    assert_eq!(
        TransactionalMessagingMetric::ConsumerSettlementTotal.label_keys(),
        &["action", "outcome"]
    );
    assert_eq!(
        TransactionalMessagingMetric::DlqRedriveTotal.label_keys(),
        &["kind", "outcome"]
    );
    for metric in TransactionalMessagingMetric::ALL {
        assert!(!metric.label_keys().iter().any(|key| matches!(
            *key,
            "tenant_id" | "domain" | "contract_id" | "topic" | "handler" | "event_id"
        )));
    }

    assert_eq!(
        TransactionalMessagingEvent::ALL.map(TransactionalMessagingEvent::name),
        [
            "transactional_messaging.runtime.failure",
            "transactional_messaging.outbox.publish",
            "transactional_messaging.outbox.publish_failure",
            "transactional_messaging.outbox.backlog",
            "transactional_messaging.outbox.backlog_unavailable",
            "transactional_messaging.outbox.relay_tick",
            "transactional_messaging.inbox.backlog",
            "transactional_messaging.inbox.backlog_unavailable",
            "transactional_messaging.consumer.claim_in_progress",
            "transactional_messaging.consumer.ingress_rejected",
            "transactional_messaging.consumer.transaction",
            "transactional_messaging.consumer.settlement",
            "transactional_messaging.consumer.dead_letter_skip",
            "transactional_messaging.consumer.dead_letter_write",
            "transactional_messaging.consumer.subscribe_retry",
            "transactional_messaging.consumer.lease_lost",
            "transactional_messaging.outbox.relay_lease_lost",
            "transactional_messaging.consumer.release_failed",
            "transactional_messaging.dlq.mutation",
        ]
    );
    assert_eq!(
        TransactionalMessagingEvent::OutboxBacklog.field_keys(),
        &[
            "pending_depth",
            "oldest_pending_age_seconds",
            "partition_blocked_depth"
        ]
    );
}
