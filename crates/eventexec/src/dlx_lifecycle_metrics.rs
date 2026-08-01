//! Low-cardinality DLX lifecycle metric emission.

use diport::DlxArchiveBacklog;

use crate::{RetentionBacklogObservation, RetentionOutcome, RetentionTarget};

/// Lifecycle metrics port. Every label is a closed enum owned by eventexec.
pub trait RetentionMetrics: Send + Sync {
    fn record_sweep(
        &self,
        target: RetentionTarget,
        outcome: RetentionOutcome,
        deleted: u64,
        duration_seconds: f64,
    );

    fn record_archive_backlog(&self, backlog: DlxArchiveBacklog);

    fn record_retention_backlog(
        &self,
        target: RetentionTarget,
        observation: RetentionBacklogObservation,
    );
}

/// `metrics` facade-backed production emitter.
pub struct MetricsRetentionMetrics;

impl RetentionMetrics for MetricsRetentionMetrics {
    fn record_sweep(
        &self,
        target: RetentionTarget,
        outcome: RetentionOutcome,
        deleted: u64,
        duration_seconds: f64,
    ) {
        metrics::counter!(
            "retention_sweep_deleted_total",
            "target" => target.as_label()
        )
        .increment(deleted);
        metrics::counter!(
            "retention_sweep_ticks_total",
            "target" => target.as_label(),
            "outcome" => outcome.as_label()
        )
        .increment(1);
        metrics::histogram!(
            "retention_sweep_duration_seconds",
            "target" => target.as_label(),
            "outcome" => outcome.as_label()
        )
        .record(duration_seconds);
    }

    fn record_archive_backlog(&self, backlog: DlxArchiveBacklog) {
        metrics::gauge!("dead_letter_archive_pending_depth").set(backlog.depth() as f64);
        metrics::gauge!("dead_letter_archive_oldest_pending_age_seconds")
            .set(backlog.oldest_age_seconds() as f64);
    }

    fn record_retention_backlog(
        &self,
        target: RetentionTarget,
        observation: RetentionBacklogObservation,
    ) {
        let (depth, oldest_age_seconds) = match observation {
            RetentionBacklogObservation::Available(backlog) => {
                (backlog.depth() as f64, backlog.oldest_age_seconds() as f64)
            }
            RetentionBacklogObservation::Unavailable => (f64::NAN, f64::NAN),
        };
        metrics::gauge!(
            "retention_expired_backlog_depth",
            "target" => target.as_label()
        )
        .set(depth);
        metrics::gauge!(
            "retention_expired_oldest_age_seconds",
            "target" => target.as_label()
        )
        .set(oldest_age_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::{MetricsRetentionMetrics, RetentionMetrics};
    use crate::{RetentionBacklog, RetentionBacklogObservation, RetentionOutcome, RetentionTarget};
    use diport::DlxArchiveBacklog;

    #[test]
    fn backlog_is_value_only_without_label_strings() {
        let sample = DlxArchiveBacklog::new(17, 31);
        assert_eq!(sample.depth(), 17);
        assert_eq!(sample.oldest_age_seconds(), 31);
    }

    #[test]
    fn production_emitter_uses_only_closed_low_cardinality_labels() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let metrics = MetricsRetentionMetrics;
            metrics.record_sweep(
                RetentionTarget::DeadLetter,
                RetentionOutcome::Success,
                7,
                0.25,
            );
            metrics.record_archive_backlog(DlxArchiveBacklog::new(11, 37));
            metrics.record_retention_backlog(
                RetentionTarget::CertificateRevocations,
                RetentionBacklogObservation::Available(RetentionBacklog::new(13, 41)),
            );
            metrics.record_sweep(
                RetentionTarget::CertificateRevocations,
                RetentionOutcome::Transient,
                0,
                0.5,
            );
            metrics.record_retention_backlog(
                RetentionTarget::SagaTerminal,
                RetentionBacklogObservation::Available(RetentionBacklog::new(5, 43)),
            );
        });
        let rendered = handle.render();
        for metric in [
            "retention_sweep_deleted_total",
            "retention_sweep_ticks_total",
            "retention_sweep_duration_seconds_count",
            "dead_letter_archive_pending_depth",
            "dead_letter_archive_oldest_pending_age_seconds",
            "retention_expired_backlog_depth",
            "retention_expired_oldest_age_seconds",
        ] {
            assert!(rendered.contains(metric), "missing {metric}: {rendered}");
        }
        for label in [
            "target=\"dead_letter\"",
            "target=\"certificate_revocations\"",
            "target=\"saga_terminal\"",
            "outcome=\"success\"",
        ] {
            assert!(rendered.contains(label), "missing {label}: {rendered}");
        }
        for forbidden in ["tenant_id=", "dead_letter_id=", "payload=", "error="] {
            assert!(
                !rendered.contains(forbidden),
                "high-cardinality label {forbidden} leaked: {rendered}"
            );
        }
        assert!(
            rendered.contains(
                "retention_sweep_ticks_total{target=\"certificate_revocations\",outcome=\"transient\"} 1"
            ),
            "revocation failure outcome must use the shared typed family: {rendered}"
        );
    }

    #[test]
    fn unavailable_retention_backlog_is_nan_instead_of_zero() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            MetricsRetentionMetrics.record_retention_backlog(
                RetentionTarget::CertificateRevocations,
                RetentionBacklogObservation::Unavailable,
            );
        });
        let rendered = handle.render();
        assert!(
            rendered.contains(
                "retention_expired_backlog_depth{target=\"certificate_revocations\"} NaN"
            ),
            "unavailable backlog must not be rendered as zero: {rendered}"
        );
        assert!(
            rendered.contains(
                "retention_expired_oldest_age_seconds{target=\"certificate_revocations\"} NaN"
            ),
            "unavailable backlog age must not be rendered as zero: {rendered}"
        );
    }
}
