//! Production metrics/tracing projection for the public Eventing observation seam.

use eventing::observability::{EventingEmitter, EventingObservation};

/// The unique production projection from closed Eventing observations to process telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventingTelemetryEmitter;

impl EventingEmitter for EventingTelemetryEmitter {
    #[allow(
        clippy::cognitive_complexity,
        reason = "one exhaustive match is the auditable projection boundary for the closed observation sum type"
    )]
    fn emit(&self, observation: EventingObservation) {
        match observation {
            EventingObservation::OutboxPublish { status } => {
                metrics::counter!(
                    "outbox_publish_total",
                    "status" => status.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "eventing.outbox.publish",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    status = status.as_label()
                );
            }
            EventingObservation::OutboxBacklog {
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
                    name: "eventing.outbox.backlog",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    pending_depth,
                    oldest_pending_age_seconds = oldest_pending_age.as_secs_f64(),
                    partition_blocked_depth
                );
            }
            EventingObservation::OutboxBacklogUnavailable => {
                metrics::gauge!("outbox_pending_depth").set(f64::NAN);
                metrics::gauge!("outbox_oldest_pending_age_seconds").set(f64::NAN);
                metrics::gauge!("outbox_partition_blocked_depth").set(f64::NAN);
                tracing::event!(
                    name: "eventing.outbox.backlog_unavailable",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            EventingObservation::RelayTick { phase, duration } => {
                metrics::histogram!(
                    "outbox_relay_tick_duration_seconds",
                    "phase" => phase.as_label()
                )
                .record(duration.as_secs_f64());
                tracing::event!(
                    name: "eventing.outbox.relay_tick",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    phase = phase.as_label(),
                    duration_seconds = duration.as_secs_f64()
                );
            }
            EventingObservation::InboxBacklog {
                stale_claim_depth,
                oldest_stale_claim_age,
            } => {
                metrics::gauge!("inbox_stale_claim_depth").set(stale_claim_depth as f64);
                metrics::gauge!("inbox_oldest_stale_claim_age_seconds")
                    .set(oldest_stale_claim_age.as_secs_f64());
                tracing::event!(
                    name: "eventing.inbox.backlog",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    stale_claim_depth,
                    oldest_stale_claim_age_seconds = oldest_stale_claim_age.as_secs_f64()
                );
            }
            EventingObservation::InboxBacklogUnavailable => {
                metrics::gauge!("inbox_stale_claim_depth").set(f64::NAN);
                metrics::gauge!("inbox_oldest_stale_claim_age_seconds").set(f64::NAN);
                tracing::event!(
                    name: "eventing.inbox.backlog_unavailable",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            EventingObservation::ConsumerClaimInProgress => {
                metrics::counter!("consumer_claim_in_progress_total").increment(1);
                tracing::event!(
                    name: "eventing.consumer.claim_in_progress",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            EventingObservation::ConsumerTransaction { status } => {
                metrics::counter!(
                    "consumer_tx_outcome_total",
                    "outcome" => status.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "eventing.consumer.transaction",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    outcome = status.as_label()
                );
            }
            EventingObservation::ConsumerSettlement { action, outcome } => {
                metrics::counter!(
                    "consumer_settle_total",
                    "action" => action.as_label(),
                    "outcome" => outcome.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "eventing.consumer.settlement",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    action = action.as_label(),
                    outcome = outcome.as_label()
                );
            }
            EventingObservation::ConsumerDeadLetterSkip { reason } => {
                metrics::counter!(
                    "consumer_dlx_skip_total",
                    "reason" => reason.as_label()
                )
                .increment(1);
                tracing::event!(
                    name: "eventing.consumer.dead_letter_skip",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    reason = reason.as_label()
                );
            }
            EventingObservation::ConsumerDeadLetterWrite { outcome } => {
                metrics::counter!("consumer_dlx_write_total", "outcome" => outcome.as_label())
                    .increment(1);
                tracing::event!(
                    name: "eventing.consumer.dead_letter_write",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    outcome = outcome.as_label()
                );
            }
            EventingObservation::ConsumerSubscribeRetry { outcome } => {
                metrics::counter!("consumer_subscribe_retry_total", "outcome" => outcome.as_label())
                    .increment(1);
                tracing::event!(
                    name: "eventing.consumer.subscribe_retry",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    outcome = outcome.as_label()
                );
            }
            EventingObservation::ConsumerLeaseLost => {
                metrics::counter!("consumer_lease_lost_total").increment(1);
                tracing::event!(
                    name: "eventing.consumer.lease_lost",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            EventingObservation::ConsumerReleaseFailed => {
                metrics::counter!("consumer_release_failed_total").increment(1);
                tracing::event!(
                    name: "eventing.consumer.release_failed",
                    target: "rss.eventing",
                    tracing::Level::DEBUG,
                    {}
                );
            }
            EventingObservation::DeadLetterReplay { result } => {
                emit_dlq_mutation("dead_letter_replay", result.as_label());
            }
            EventingObservation::OutboxDlxRedrive { result } => {
                emit_dlq_mutation("outbox_dlx_redrive", result.as_label());
            }
            EventingObservation::OutboxDlxResolveExpired { result } => {
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
        name: "eventing.dlq.mutation",
        target: "rss.eventing",
        tracing::Level::DEBUG,
        kind,
        outcome
    );
}
