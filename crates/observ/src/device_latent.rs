//! Closed, identifier-free numeric observations for DeviceLatent convergence.
//!
//! The four histograms deliberately carry an empty label set. Their identity is a closed enum,
//! while tenant, device, command, payload, certificate, artifact and provider text cannot enter
//! the metric API.
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/metrics/instruments/histogram.rs@main

use std::time::Duration;

/// Exact metric families owned by DeviceLatent status observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLatentMetric {
    /// Desired generation minus the reported high-water generation.
    GenerationLag,
    /// Age of the current typed `StateDrift` condition.
    DriftAge,
    /// Time from durable command queueing until publish, or until the authoritative observation.
    QueueAge,
    /// Time from durable publish until receipt, or until the authoritative observation.
    AckLatency,
}

impl DeviceLatentMetric {
    /// Complete exact family set; additions are intentional API changes.
    pub const ALL: [Self; 4] = [
        Self::GenerationLag,
        Self::DriftAge,
        Self::QueueAge,
        Self::AckLatency,
    ];

    /// Stable Prometheus family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::GenerationLag => "device_latent_generation_lag",
            Self::DriftAge => "device_latent_drift_age_seconds",
            Self::QueueAge => "device_latent_queue_age_seconds",
            Self::AckLatency => "device_latent_ack_latency_seconds",
        }
    }
}

/// One authoritative, payload-free DeviceLatent status observation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DeviceLatentObservation {
    generation_lag: u64,
    drift_age: Option<Duration>,
    queue_age: Option<Duration>,
    ack_latency: Option<Duration>,
}

impl DeviceLatentObservation {
    /// Bind validated numeric samples without accepting any label or identifier input.
    #[must_use]
    pub const fn new(
        generation_lag: u64,
        drift_age: Option<Duration>,
        queue_age: Option<Duration>,
        ack_latency: Option<Duration>,
    ) -> Self {
        Self {
            generation_lag,
            drift_age,
            queue_age,
            ack_latency,
        }
    }

    /// Desired-minus-reported generation lag captured at the authoritative instant.
    #[must_use]
    pub const fn generation_lag(self) -> u64 {
        self.generation_lag
    }

    /// Age of the current Ready/StateDrift transition, when present.
    #[must_use]
    pub const fn drift_age(self) -> Option<Duration> {
        self.drift_age
    }

    /// Active-command queue age at the authoritative instant, when present.
    #[must_use]
    pub const fn queue_age(self) -> Option<Duration> {
        self.queue_age
    }

    /// Active-command publish-to-receive latency, when present.
    #[must_use]
    pub const fn ack_latency(self) -> Option<Duration> {
        self.ack_latency
    }

    /// Emit only present samples into the exact unlabelled histogram families.
    pub fn record(self) {
        metrics::histogram!(DeviceLatentMetric::GenerationLag.name())
            .record(self.generation_lag as f64);
        if let Some(age) = self.drift_age {
            metrics::histogram!(DeviceLatentMetric::DriftAge.name()).record(age.as_secs_f64());
        }
        if let Some(age) = self.queue_age {
            metrics::histogram!(DeviceLatentMetric::QueueAge.name()).record(age.as_secs_f64());
        }
        if let Some(latency) = self.ack_latency {
            metrics::histogram!(DeviceLatentMetric::AckLatency.name())
                .record(latency.as_secs_f64());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DeviceLatentMetric, DeviceLatentObservation};

    #[test]
    fn metric_families_are_exact_and_unlabelled() {
        assert_eq!(
            DeviceLatentMetric::ALL.map(DeviceLatentMetric::name),
            [
                "device_latent_generation_lag",
                "device_latent_drift_age_seconds",
                "device_latent_queue_age_seconds",
                "device_latent_ack_latency_seconds",
            ]
        );

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            DeviceLatentObservation::new(
                3,
                Some(Duration::from_secs(11)),
                Some(Duration::from_secs(7)),
                Some(Duration::from_millis(250)),
            )
            .record();
        });
        let rendered = handle.render();
        for family in DeviceLatentMetric::ALL {
            assert!(
                rendered.contains(family.name()),
                "missing {family:?}: {rendered}"
            );
        }
        for forbidden in [
            "tenant_id=",
            "device_id=",
            "command_id=",
            "payload=",
            "certificate=",
            "artifact=",
            "error=",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
        assert!(
            rendered
                .lines()
                .filter(|line| line.starts_with("device_latent_"))
                .all(|line| line
                    .split_once('{')
                    .is_none_or(|(_, labels)| labels.starts_with("quantile=\""))),
            "only the exporter's closed quantile label is allowed: {rendered}"
        );
    }

    #[test]
    fn absent_optional_durations_do_not_forge_samples() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            DeviceLatentObservation::new(0, None, None, None).record();
        });
        let rendered = handle.render();
        assert!(rendered.contains("device_latent_generation_lag"));
        for absent in [
            "device_latent_drift_age_seconds",
            "device_latent_queue_age_seconds",
            "device_latent_ack_latency_seconds",
        ] {
            assert!(
                !rendered.contains(absent),
                "unexpected {absent}: {rendered}"
            );
        }
    }
}
