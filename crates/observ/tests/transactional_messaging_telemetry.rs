use observ::TransactionalMessagingTelemetryEmitter;
use rss_transactional_messaging::observability::{
    TransactionalMessagingDeadLetterReplayResult, TransactionalMessagingDeadLetterSkipReason,
    TransactionalMessagingDisposition, TransactionalMessagingEmitter, TransactionalMessagingEvent,
    TransactionalMessagingIoOutcome, TransactionalMessagingMetric,
    TransactionalMessagingObservation, TransactionalMessagingOutboxDlxRedriveResult,
    TransactionalMessagingOutboxDlxResolveResult, TransactionalMessagingRelayPhase,
    TransactionalMessagingSubscribeOutcome, TransactionalMessagingTransactionStatus,
};
use rss_transactional_messaging::transport::{PublishFailureReason, PublishFailureStage};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

static TELEMETRY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn emitter_uses_canonical_metric_names_and_exact_labels() {
    let _guard = TELEMETRY_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        let emitter = TransactionalMessagingTelemetryEmitter;
        emitter.emit(TransactionalMessagingObservation::OutboxPublish {
            status: TransactionalMessagingDisposition::Reject,
        });
        emitter.emit(TransactionalMessagingObservation::RelayTick {
            phase: TransactionalMessagingRelayPhase::Publish,
            duration: Duration::from_millis(1250),
        });
        emitter.emit(TransactionalMessagingObservation::OutboxBacklog {
            pending_depth: 11,
            oldest_pending_age: Duration::from_secs(17),
            partition_blocked_depth: 3,
        });
    });

    let rendered = handle.render();
    assert!(
        rendered.contains("outbox_publish_total{status=\"reject\"} 1"),
        "{rendered}"
    );
    assert!(rendered.contains("outbox_relay_tick_duration_seconds_count{phase=\"publish\"} 1"));
    assert!(rendered.contains("outbox_pending_depth 11"), "{rendered}");
    assert!(
        rendered.contains("outbox_oldest_pending_age_seconds 17"),
        "{rendered}"
    );
    assert!(
        rendered.contains("outbox_partition_blocked_depth 3"),
        "{rendered}"
    );
    for forbidden in [
        "tenant_id=",
        "domain=",
        "contract_id=",
        "topic=",
        "event_id=",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "forbidden `{forbidden}`: {rendered}"
        );
    }
    assert!(!rendered.contains("outbox_dlx_total"), "{rendered}");
}

#[test]
fn unavailable_backlog_retires_every_global_gauge_with_nan() {
    let _guard = TELEMETRY_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::with_local_recorder(&recorder, || {
        let emitter = TransactionalMessagingTelemetryEmitter;
        emitter.emit(TransactionalMessagingObservation::OutboxBacklogUnavailable);
        emitter.emit(TransactionalMessagingObservation::InboxBacklogUnavailable);
    });
    let rendered = handle.render();
    for metric in [
        "outbox_pending_depth",
        "outbox_oldest_pending_age_seconds",
        "outbox_partition_blocked_depth",
        "inbox_stale_claim_depth",
        "inbox_oldest_stale_claim_age_seconds",
    ] {
        assert!(rendered.contains(&format!("{metric} NaN")), "{rendered}");
    }
}

fn every_observation_branch() -> Vec<TransactionalMessagingObservation> {
    vec![
        TransactionalMessagingObservation::OutboxPublish {
            status: TransactionalMessagingDisposition::Ack,
        },
        TransactionalMessagingObservation::OutboxPublishFailure {
            stage: PublishFailureStage::Confirm,
            reason: PublishFailureReason::DeadlineElapsed,
            ambiguous: true,
        },
        TransactionalMessagingObservation::OutboxBacklog {
            pending_depth: 1,
            oldest_pending_age: Duration::from_secs(2),
            partition_blocked_depth: 3,
        },
        TransactionalMessagingObservation::OutboxBacklogUnavailable,
        TransactionalMessagingObservation::RelayTick {
            phase: TransactionalMessagingRelayPhase::Claim,
            duration: Duration::from_secs(1),
        },
        TransactionalMessagingObservation::InboxBacklog {
            stale_claim_depth: 4,
            oldest_stale_claim_age: Duration::from_secs(5),
        },
        TransactionalMessagingObservation::InboxBacklogUnavailable,
        TransactionalMessagingObservation::ConsumerClaimInProgress,
        TransactionalMessagingObservation::ConsumerIngressRejected {
            reason: rss_transactional_messaging::transaction::EnvelopeValidationFailure::MalformedIdentity,
        },
        TransactionalMessagingObservation::ConsumerTransaction {
            status: TransactionalMessagingTransactionStatus::Committed,
        },
        TransactionalMessagingObservation::ConsumerSettlement {
            action: TransactionalMessagingDisposition::Reject,
            outcome: TransactionalMessagingIoOutcome::Error,
        },
        TransactionalMessagingObservation::ConsumerDeadLetterSkip {
            reason: TransactionalMessagingDeadLetterSkipReason::MalformedId,
        },
        TransactionalMessagingObservation::ConsumerDeadLetterWrite {
            outcome: TransactionalMessagingIoOutcome::Ok,
        },
        TransactionalMessagingObservation::ConsumerSubscribeRetry {
            outcome: TransactionalMessagingSubscribeOutcome::SubscribeError,
        },
        TransactionalMessagingObservation::ConsumerLeaseLost,
        TransactionalMessagingObservation::ConsumerReleaseFailed,
        TransactionalMessagingObservation::DeadLetterReplay {
            result: TransactionalMessagingDeadLetterReplayResult::Inserted,
        },
        TransactionalMessagingObservation::OutboxDlxRedrive {
            result: TransactionalMessagingOutboxDlxRedriveResult::Redriven,
        },
        TransactionalMessagingObservation::OutboxDlxResolveExpired {
            result: TransactionalMessagingOutboxDlxResolveResult::Resolved,
        },
    ]
}

fn expected_metrics(
    observation: TransactionalMessagingObservation,
) -> Vec<(&'static str, &'static [&'static str])> {
    match observation {
        TransactionalMessagingObservation::OutboxPublish { .. } => {
            vec![("outbox_publish_total", &["status=\"ack\""])]
        }
        TransactionalMessagingObservation::OutboxPublishFailure { .. } => vec![(
            "outbox_publish_failure_total",
            &[
                "ambiguous=\"true\"",
                "reason=\"deadline_elapsed\"",
                "stage=\"confirm\"",
            ],
        )],
        TransactionalMessagingObservation::OutboxBacklog { .. }
        | TransactionalMessagingObservation::OutboxBacklogUnavailable => vec![
            ("outbox_pending_depth", &[]),
            ("outbox_oldest_pending_age_seconds", &[]),
            ("outbox_partition_blocked_depth", &[]),
        ],
        TransactionalMessagingObservation::RelayTick { .. } => {
            vec![("outbox_relay_tick_duration_seconds", &["phase=\"claim\""])]
        }
        TransactionalMessagingObservation::InboxBacklog { .. }
        | TransactionalMessagingObservation::InboxBacklogUnavailable => {
            vec![
                ("inbox_stale_claim_depth", &[]),
                ("inbox_oldest_stale_claim_age_seconds", &[]),
            ]
        }
        TransactionalMessagingObservation::ConsumerClaimInProgress => {
            vec![("consumer_claim_in_progress_total", &[])]
        }
        TransactionalMessagingObservation::ConsumerIngressRejected { .. } => vec![(
            "transactional_messaging_ingress_rejected_total",
            &["reason=\"malformed_identity\""],
        )],
        TransactionalMessagingObservation::ConsumerTransaction { .. } => {
            vec![("consumer_tx_outcome_total", &["outcome=\"committed\""])]
        }
        TransactionalMessagingObservation::ConsumerSettlement { .. } => vec![(
            "consumer_settle_total",
            &["action=\"reject\"", "outcome=\"error\""],
        )],
        TransactionalMessagingObservation::ConsumerDeadLetterSkip { .. } => {
            vec![("consumer_dlx_skip_total", &["reason=\"malformed_id\""])]
        }
        TransactionalMessagingObservation::ConsumerDeadLetterWrite { .. } => {
            vec![("consumer_dlx_write_total", &["outcome=\"ok\""])]
        }
        TransactionalMessagingObservation::ConsumerSubscribeRetry { .. } => vec![(
            "consumer_subscribe_retry_total",
            &["outcome=\"subscribe_error\""],
        )],
        TransactionalMessagingObservation::ConsumerLeaseLost => {
            vec![("consumer_lease_lost_total", &[])]
        }
        TransactionalMessagingObservation::ConsumerReleaseFailed => {
            vec![("consumer_release_failed_total", &[])]
        }
        TransactionalMessagingObservation::DeadLetterReplay { .. } => vec![(
            "dlq_redrive_total",
            &["kind=\"dead_letter_replay\"", "outcome=\"inserted\""],
        )],
        TransactionalMessagingObservation::OutboxDlxRedrive { .. } => vec![(
            "dlq_redrive_total",
            &["kind=\"outbox_dlx_redrive\"", "outcome=\"redriven\""],
        )],
        TransactionalMessagingObservation::OutboxDlxResolveExpired { .. } => vec![(
            "dlq_redrive_total",
            &[
                "kind=\"outbox_dlx_resolve_expired\"",
                "outcome=\"resolved\"",
            ],
        )],
    }
}

fn metric_sample_labels(rendered: &str, metric: &str) -> Option<BTreeSet<String>> {
    let count_name = format!("{metric}_count");
    [count_name.as_str(), metric].into_iter().find_map(|name| {
        rendered.lines().find_map(|line| {
            let sample = line.split_whitespace().next()?;
            if sample != name && !sample.starts_with(&format!("{name}{{")) {
                return None;
            }
            let Some((_, labels)) = sample.split_once('{') else {
                return Some(BTreeSet::new());
            };
            Some(
                labels
                    .trim_end_matches('}')
                    .split(',')
                    .filter(|label| !label.is_empty())
                    .map(str::to_owned)
                    .collect(),
            )
        })
    })
}

#[test]
fn every_observation_has_exact_metric_identity_and_label_values() {
    let _guard = TELEMETRY_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for observation in every_observation_branch() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            TransactionalMessagingTelemetryEmitter.emit(observation)
        });
        let rendered = handle.render();
        let expected = expected_metrics(observation);
        let actual_names = TransactionalMessagingMetric::ALL
            .into_iter()
            .filter(|metric| metric_sample_labels(&rendered, metric.name()).is_some())
            .map(TransactionalMessagingMetric::name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual_names,
            expected.iter().map(|(name, _)| *name).collect(),
            "metric identity drift for {observation:?}: {rendered}"
        );
        for (name, labels) in expected {
            assert_eq!(
                metric_sample_labels(&rendered, name),
                Some(labels.iter().map(|label| (*label).to_owned()).collect()),
                "metric labels drift for {observation:?}: {rendered}"
            );
        }
    }
}

type CapturedEvent = (String, String, String, BTreeSet<String>);

#[derive(Default)]
struct CaptureLayer(Arc<Mutex<Vec<CapturedEvent>>>);

impl<S> Layer<S> for CaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Fields(BTreeSet<String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(
                &mut self,
                field: &tracing::field::Field,
                _value: &dyn std::fmt::Debug,
            ) {
                self.0.insert(field.name().to_owned());
            }
        }
        let metadata = event.metadata();
        let mut fields = Fields(BTreeSet::new());
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push((
                metadata.name().to_owned(),
                metadata.target().to_owned(),
                metadata.level().to_string(),
                fields.0,
            ));
    }
}

#[test]
fn every_branch_emits_the_exact_static_event_descriptor() {
    let _guard = TELEMETRY_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let layer = CaptureLayer::default();
    let captured = Arc::clone(&layer.0);
    let subscriber = tracing_subscriber::registry().with(layer);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    tracing::subscriber::with_default(subscriber, || {
        metrics::with_local_recorder(&recorder, || {
            let emitter = TransactionalMessagingTelemetryEmitter;
            for observation in every_observation_branch() {
                emitter.emit(observation);
            }
        });
    });

    let captured = captured.lock().unwrap_or_else(|error| error.into_inner());
    assert_eq!(captured.len(), 19, "captured events: {captured:?}");
    let actual = captured
        .iter()
        .map(|(name, target, level, fields)| {
            assert_eq!(target, "rss.transactional_messaging");
            assert_eq!(level, "DEBUG");
            (name.as_str(), fields.clone())
        })
        .collect::<Vec<_>>();
    for event in TransactionalMessagingEvent::ALL {
        let matches = actual
            .iter()
            .filter(|(name, fields)| {
                *name == event.name()
                    && *fields
                        == event
                            .field_keys()
                            .iter()
                            .map(|field| (*field).to_owned())
                            .collect()
            })
            .count();
        let expected = if event == TransactionalMessagingEvent::DlqMutation {
            3
        } else {
            1
        };
        assert_eq!(matches, expected, "descriptor drift for {}", event.name());
    }
    let rendered = handle.render();
    for metric in TransactionalMessagingMetric::ALL {
        assert!(
            rendered.contains(metric.name()),
            "missing {}: {rendered}",
            metric.name()
        );
    }
}
