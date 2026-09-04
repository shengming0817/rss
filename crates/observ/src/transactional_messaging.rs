//! Production metrics/tracing projection for the public TransactionalMessaging observation seam.

use rss_transactional_messaging::observability::{
    TransactionalMessagingEmitter, TransactionalMessagingObservation,
};

/// The unique production projection from closed TransactionalMessaging observations to process telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransactionalMessagingTelemetryEmitter;

impl TransactionalMessagingEmitter for TransactionalMessagingTelemetryEmitter {
    #[allow(
        clippy::cognitive_complexity,
        reason = "one exhaustive match is the auditable projection boundary for the closed observation sum type"
    )]
    fn emit(&self, observation: TransactionalMessagingObservation) {
        match observation {
            TransactionalMessagingObservation::RuntimeFailure { phase, kind } => {
                metrics::counter!(
                    "transactional_messaging_runtime_failure_total",
                    "phase" => phase.as_label(),
                    "kind" => kind.as_label(),
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.runtime.failure",
                    target: "rss.transactional_messaging",
                    tracing::Level::ERROR,
                    phase = phase.as_label(),
                    kind = kind.as_label(),
                );
            }
            TransactionalMessagingObservation::OutboxPublish { status } => {
                metrics::counter!(
                    "outbox_publish_total",
                    "status" => status.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.outbox.publish",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    status = status.as_label()
                );
            }
            TransactionalMessagingObservation::OutboxPublishFailure {
                stage,
                reason,
                ambiguous,
            } => {
                metrics::counter!(
                    "outbox_publish_failure_total",
                    "stage" => stage.as_label(),
                    "reason" => reason.as_label(),
                    "ambiguous" => if ambiguous { "true" } else { "false" },
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.outbox.publish_failure",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    stage = stage.as_label(),
                    reason = reason.as_label(),
                    ambiguous,
                );
            }
            TransactionalMessagingObservation::OutboxBacklog {
                pending_depth,
                oldest_pending_age,
                partition_blocked_depth,
            } => {
                metrics::gauge!("outbox_pending_depth").set(pending_depth as f64);
                metrics::gauge!("outbox_oldest_pending_age_seconds")
                    .set(oldest_pending_age.as_secs_f64());
                metrics::gauge!("outbox_partition_blocked_depth")
                    .set(partition_blocked_depth as f64);
                tracing::event!(
                    name: "transactional_messaging.outbox.backlog",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    pending_depth,
                    oldest_pending_age_seconds = oldest_pending_age.as_secs_f64(),
                    partition_blocked_depth
                );
            }
            TransactionalMessagingObservation::OutboxBacklogUnavailable => {
                metrics::gauge!("outbox_pending_depth").set(f64::NAN);
                metrics::gauge!("outbox_oldest_pending_age_seconds").set(f64::NAN);
                metrics::gauge!("outbox_partition_blocked_depth").set(f64::NAN);
                tracing::event!(
                    name: "transactional_messaging.outbox.backlog_unavailable",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::RelayTick { phase, duration } => {
                metrics::histogram!(
                    "outbox_relay_tick_duration_seconds",
                    "phase" => phase.as_label()
                )
                .record(duration.as_secs_f64());
                tracing::event!(
                    name: "transactional_messaging.outbox.relay_tick",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    phase = phase.as_label(),
                    duration_seconds = duration.as_secs_f64()
                );
            }
            TransactionalMessagingObservation::InboxBacklog {
                stale_claim_depth,
                oldest_stale_claim_age,
            } => {
                metrics::gauge!("inbox_stale_claim_depth").set(stale_claim_depth as f64);
                metrics::gauge!("inbox_oldest_stale_claim_age_seconds")
                    .set(oldest_stale_claim_age.as_secs_f64());
                tracing::event!(
                    name: "transactional_messaging.inbox.backlog",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    stale_claim_depth,
                    oldest_stale_claim_age_seconds = oldest_stale_claim_age.as_secs_f64()
                );
            }
            TransactionalMessagingObservation::InboxBacklogUnavailable => {
                metrics::gauge!("inbox_stale_claim_depth").set(f64::NAN);
                metrics::gauge!("inbox_oldest_stale_claim_age_seconds").set(f64::NAN);
                tracing::event!(
                    name: "transactional_messaging.inbox.backlog_unavailable",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::ConsumerIngressRejected { reason } => {
                metrics::counter!(
                    "transactional_messaging_ingress_rejected_total",
                    "reason" => reason.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.ingress_rejected",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    reason = reason.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerClaimInProgress => {
                metrics::counter!("consumer_claim_in_progress_total").increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.claim_in_progress",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::ConsumerTransaction { status } => {
                metrics::counter!(
                    "consumer_tx_outcome_total",
                    "outcome" => status.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.transaction",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    outcome = status.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerSettlement { action, outcome } => {
                metrics::counter!(
                    "consumer_settle_total",
                    "action" => action.as_label(),
                    "outcome" => outcome.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.settlement",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    action = action.as_label(),
                    outcome = outcome.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerDeadLetterSkip { reason } => {
                metrics::counter!(
                    "consumer_dlx_skip_total",
                    "reason" => reason.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.dead_letter_skip",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    reason = reason.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerDeadLetterWrite { outcome } => {
                metrics::counter!("consumer_dlx_write_total", "outcome" => outcome.as_label())
                    .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.dead_letter_write",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    outcome = outcome.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerSubscribeRetry { outcome } => {
                metrics::counter!("consumer_subscribe_retry_total", "outcome" => outcome.as_label())
                    .increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.subscribe_retry",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    outcome = outcome.as_label()
                );
            }
            TransactionalMessagingObservation::ConsumerLeaseLost => {
                metrics::counter!("consumer_lease_lost_total").increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.lease_lost",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::RelayLeaseLost => {
                metrics::counter!("outbox_relay_lease_lost_total").increment(1);
                tracing::event!(
                    name: "transactional_messaging.outbox.relay_lease_lost",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::ConsumerReleaseFailed => {
                metrics::counter!("consumer_release_failed_total").increment(1);
                tracing::event!(
                    name: "transactional_messaging.consumer.release_failed",
                    target: "rss.transactional_messaging",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            TransactionalMessagingObservation::DeadLetterReplay { result } => {
                emit_dlq_mutation("dead_letter_replay", result.as_label());
            }
            TransactionalMessagingObservation::OutboxDlxRedrive { result } => {
                emit_dlq_mutation("outbox_dlx_redrive", result.as_label());
            }
            TransactionalMessagingObservation::OutboxDlxResolveExpired { result } => {
                emit_dlq_mutation("outbox_dlx_resolve_expired", result.as_label());
            }
        }
    }
}

fn emit_dlq_mutation(kind: &'static str, outcome: &'static str) {
    metrics::counter!(
        "dlq_redrive_total",
        "kind" => kind,
        "outcome" => outcome
    )
    .increment(1);
    tracing::event!(
        name: "transactional_messaging.dlq.mutation",
        target: "rss.transactional_messaging",
        tracing::Level::DEBUG,
        kind,
        outcome
    );
}
