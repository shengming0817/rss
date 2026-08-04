//! Projection worker metrics emit seam (FR-021 / #2010).
//!
//! Low-cardinality families for long-lived active/shadow workers. Labels are closed:
//! `projection_id` + `activation`, with counters allowed to add closed `outcome` / `reason`.
//! Tenant / selector / event / DLQ id / error text / payload / timestamp / PII must never enter
//! labels.
//!
//! [`ProjectionMetricScope`] is sealed: private fields, no public constructor, minted only after
//! [`crate::ProjectionRuntimeCapability::bind_active`] / [`crate::ProjectionRuntimeCapability::bind_shadow`]
//! verify the activation permit. `ContractBinding` itself is not a Hard seal — production callers
//! cannot forge a scope from a bare string.
//!
//! ref: serverlesstechnology/cqrs src/lib.rs
//! ref: vectordotdev/vector src/internal_events/mod.rs

use consistency::ProjectionApplyErrorReason;

/// Closed activation label set for projection worker metrics (`active` | `shadow`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMetricActivation {
    /// Authoritative active worker.
    Active,
    /// Non-authoritative shadow worker.
    Shadow,
}

impl ProjectionMetricActivation {
    /// Stable low-cardinality label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Shadow => "shadow",
        }
    }
}

/// Closed processed-event outcome for the throughput counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionProcessedOutcome {
    /// Successfully applied to the target.
    Applied,
    /// Confirmed duplicate of an already-committed fact.
    Duplicate,
    /// Filtered by the current projection selector.
    Filtered,
    /// Skipped (baseline / poison skip).
    Skipped,
    /// Written to the projection-origin DLQ.
    DeadLettered,
}

impl ProjectionProcessedOutcome {
    /// Complete exact outcome set; additions are intentional API changes.
    pub const ALL: [Self; 5] = [
        Self::Applied,
        Self::Duplicate,
        Self::Filtered,
        Self::Skipped,
        Self::DeadLettered,
    ];

    /// Stable low-cardinality label.
    #[must_use]
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Duplicate => "duplicate",
            Self::Filtered => "filtered",
            Self::Skipped => "skipped",
            Self::DeadLettered => "dead_lettered",
        }
    }
}

/// Exact metric families owned by the projection worker emit seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMetric {
    /// Source high-water minus checkpoint lag.
    Lag,
    /// Seconds since the last successful checkpoint advance.
    CheckpointFreshness,
    /// Apply failures by closed reason.
    ApplyFailure,
    /// Projection-origin DLQ backlog depth.
    DlqBacklog,
    /// Processed events by closed outcome.
    ProcessedEvents,
}

impl ProjectionMetric {
    /// Complete exact family set; additions are intentional API changes.
    pub const ALL: [Self; 5] = [
        Self::Lag,
        Self::CheckpointFreshness,
        Self::ApplyFailure,
        Self::DlqBacklog,
        Self::ProcessedEvents,
    ];

    /// Stable Prometheus family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lag => "projection_lag",
            Self::CheckpointFreshness => "projection_checkpoint_freshness_seconds",
            Self::ApplyFailure => "projection_apply_failure_total",
            Self::DlqBacklog => "projection_dlq_backlog",
            Self::ProcessedEvents => "projection_processed_events_total",
        }
    }
}

/// Sealed metric scope minted only after verified Active/Shadow permit bind.
///
/// Fields are private and there is no public constructor or string parser. Production callers
/// outside this crate cannot forge a scope from a bare `projection_id` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionMetricScope {
    projection_id: &'static str,
    activation: ProjectionMetricActivation,
}

impl ProjectionMetricScope {
    /// Mint a scope after the bind path has verified Active/Shadow activation.
    ///
    /// `pub(crate)` keeps construction inside `eventexec` (bind + same-crate fixtures). External
    /// crates have no constructor.
    pub(crate) const fn mint(
        projection_id: &'static str,
        activation: ProjectionMetricActivation,
    ) -> Self {
        Self {
            projection_id,
            activation,
        }
    }

    /// Generated definition `projection_id` captured at bind time.
    #[must_use]
    pub const fn projection_id(self) -> &'static str {
        self.projection_id
    }

    /// Closed activation captured at bind time.
    #[must_use]
    pub const fn activation(self) -> ProjectionMetricActivation {
        self.activation
    }
}

/// Projection worker metrics port (injectable; `Send + Sync` for spawned workers).
pub trait ProjectionMetrics: Send + Sync {
    /// Set `projection_lag{projection_id,activation}`. Pass `NaN` when observation fails.
    fn record_lag(&self, scope: &ProjectionMetricScope, lag: f64);

    /// Set `projection_checkpoint_freshness_seconds{projection_id,activation}`. Pass `NaN` when
    /// observation fails.
    fn record_checkpoint_freshness(&self, scope: &ProjectionMetricScope, age_seconds: f64);

    /// Increment `projection_apply_failure_total{projection_id,activation,reason}`.
    fn record_apply_failure(
        &self,
        scope: &ProjectionMetricScope,
        reason: ProjectionApplyErrorReason,
    );

    /// Set `projection_dlq_backlog{projection_id,activation}`. Pass `NaN` when observation fails.
    fn record_dlq_backlog(&self, scope: &ProjectionMetricScope, depth: f64);

    /// Increment `projection_processed_events_total{projection_id,activation,outcome}` by `count`.
    fn record_processed_events(
        &self,
        scope: &ProjectionMetricScope,
        outcome: ProjectionProcessedOutcome,
        count: u64,
    );
}

/// `metrics` facade-backed production emitter. No public no-op implementation.
pub struct MetricsProjectionMetrics;

impl ProjectionMetrics for MetricsProjectionMetrics {
    fn record_lag(&self, scope: &ProjectionMetricScope, lag: f64) {
        metrics::gauge!(
            ProjectionMetric::Lag.name(),
            "projection_id" => scope.projection_id(),
            "activation" => scope.activation().as_label(),
        )
        .set(lag);
    }

    fn record_checkpoint_freshness(&self, scope: &ProjectionMetricScope, age_seconds: f64) {
        metrics::gauge!(
            ProjectionMetric::CheckpointFreshness.name(),
            "projection_id" => scope.projection_id(),
            "activation" => scope.activation().as_label(),
        )
        .set(age_seconds);
    }

    fn record_apply_failure(
        &self,
        scope: &ProjectionMetricScope,
        reason: ProjectionApplyErrorReason,
    ) {
        metrics::counter!(
            ProjectionMetric::ApplyFailure.name(),
            "projection_id" => scope.projection_id(),
            "activation" => scope.activation().as_label(),
            "reason" => reason.as_label(),
        )
        .increment(1);
    }

    fn record_dlq_backlog(&self, scope: &ProjectionMetricScope, depth: f64) {
        metrics::gauge!(
            ProjectionMetric::DlqBacklog.name(),
            "projection_id" => scope.projection_id(),
            "activation" => scope.activation().as_label(),
        )
        .set(depth);
    }

    fn record_processed_events(
        &self,
        scope: &ProjectionMetricScope,
        outcome: ProjectionProcessedOutcome,
        count: u64,
    ) {
        if count == 0 {
            return;
        }
        metrics::counter!(
            ProjectionMetric::ProcessedEvents.name(),
            "projection_id" => scope.projection_id(),
            "activation" => scope.activation().as_label(),
            "outcome" => outcome.as_label(),
        )
        .increment(count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_metric_families_are_exact() {
        assert_eq!(
            ProjectionMetric::ALL.map(ProjectionMetric::name),
            [
                "projection_lag",
                "projection_checkpoint_freshness_seconds",
                "projection_apply_failure_total",
                "projection_dlq_backlog",
                "projection_processed_events_total",
            ]
        );
    }

    #[test]
    fn projection_metric_activation_and_outcome_labels_are_closed() {
        assert_eq!(ProjectionMetricActivation::Active.as_label(), "active");
        assert_eq!(ProjectionMetricActivation::Shadow.as_label(), "shadow");
        assert_eq!(
            ProjectionProcessedOutcome::ALL.map(ProjectionProcessedOutcome::as_label),
            [
                "applied",
                "duplicate",
                "filtered",
                "skipped",
                "dead_lettered"
            ]
        );
    }

    #[test]
    fn projection_metric_apply_failure_reasons_use_closed_labels() {
        let reasons = [
            ProjectionApplyErrorReason::Transient,
            ProjectionApplyErrorReason::TargetDefinitionDrift,
            ProjectionApplyErrorReason::InputBindingDrift,
            ProjectionApplyErrorReason::TenantDrift,
            ProjectionApplyErrorReason::PayloadMalformed,
            ProjectionApplyErrorReason::PayloadValueInvalid,
            ProjectionApplyErrorReason::VersionRegression,
            ProjectionApplyErrorReason::ProviderInvariant,
            ProjectionApplyErrorReason::ProviderPermanent,
            ProjectionApplyErrorReason::Conflict,
            ProjectionApplyErrorReason::OutOfOrder,
            ProjectionApplyErrorReason::CommitUnknown,
            ProjectionApplyErrorReason::RollbackFailed,
        ];
        for reason in reasons {
            assert!(
                !reason.as_label().is_empty(),
                "reason label must be non-empty"
            );
            assert!(
                !reason.as_label().contains(' '),
                "reason label must stay closed: {}",
                reason.as_label()
            );
        }
    }

    #[test]
    fn projection_metric_facade_emits_exact_labels_without_forbidden_keys() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let metrics = MetricsProjectionMetrics;
            let scope = ProjectionMetricScope::mint(
                "settings.config-projection",
                ProjectionMetricActivation::Active,
            );
            metrics.record_lag(&scope, 3.0);
            metrics.record_checkpoint_freshness(&scope, 11.0);
            metrics.record_dlq_backlog(&scope, 2.0);
            metrics.record_apply_failure(&scope, ProjectionApplyErrorReason::PayloadMalformed);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Applied, 4);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Duplicate, 1);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Filtered, 1);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Skipped, 1);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::DeadLettered, 1);

            let shadow = ProjectionMetricScope::mint(
                "settings.config-projection",
                ProjectionMetricActivation::Shadow,
            );
            metrics.record_lag(&shadow, f64::NAN);
            metrics.record_checkpoint_freshness(&shadow, f64::NAN);
            metrics.record_dlq_backlog(&shadow, f64::NAN);
            for reason in [
                ProjectionApplyErrorReason::Transient,
                ProjectionApplyErrorReason::TargetDefinitionDrift,
                ProjectionApplyErrorReason::InputBindingDrift,
                ProjectionApplyErrorReason::TenantDrift,
                ProjectionApplyErrorReason::PayloadValueInvalid,
                ProjectionApplyErrorReason::VersionRegression,
                ProjectionApplyErrorReason::ProviderInvariant,
                ProjectionApplyErrorReason::ProviderPermanent,
                ProjectionApplyErrorReason::Conflict,
                ProjectionApplyErrorReason::OutOfOrder,
                ProjectionApplyErrorReason::CommitUnknown,
                ProjectionApplyErrorReason::RollbackFailed,
            ] {
                metrics.record_apply_failure(&shadow, reason);
            }
        });
        let rendered = handle.render();
        for family in ProjectionMetric::ALL {
            assert!(
                rendered.contains(family.name()),
                "missing family {}: {rendered}",
                family.name()
            );
        }
        for label in [
            "projection_id=\"settings.config-projection\"",
            "activation=\"active\"",
            "activation=\"shadow\"",
            "outcome=\"applied\"",
            "outcome=\"duplicate\"",
            "outcome=\"filtered\"",
            "outcome=\"skipped\"",
            "outcome=\"dead_lettered\"",
            "reason=\"payload_malformed\"",
            "reason=\"transient\"",
            "reason=\"target_definition_drift\"",
            "reason=\"input_binding_drift\"",
            "reason=\"tenant_drift\"",
            "reason=\"payload_value_invalid\"",
            "reason=\"version_regression\"",
            "reason=\"provider_invariant\"",
            "reason=\"provider_permanent\"",
            "reason=\"conflict\"",
            "reason=\"out_of_order\"",
            "reason=\"commit_unknown\"",
            "reason=\"rollback_failed\"",
        ] {
            assert!(
                rendered.contains(label),
                "missing closed label {label}: {rendered}"
            );
        }
        for forbidden in [
            "tenant_id=",
            "selector=",
            "event_id=",
            "dead_letter_id=",
            "error=",
            "payload=",
            "timestamp=",
            "pii=",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "forbidden high-cardinality label {forbidden} leaked: {rendered}"
            );
        }
        assert!(
            rendered.contains("projection_lag{") && rendered.contains("NaN"),
            "gauge NaN must remain expressible for observe failure: {rendered}"
        );
    }

    #[test]
    fn projection_metric_facade_skips_zero_processed_event_counts() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let metrics = MetricsProjectionMetrics;
            let scope = ProjectionMetricScope::mint(
                "settings.config-projection",
                ProjectionMetricActivation::Active,
            );
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Applied, 0);
            metrics.record_processed_events(&scope, ProjectionProcessedOutcome::Duplicate, 1);
        });
        let rendered = handle.render();
        assert!(
            !rendered.contains("outcome=\"applied\""),
            "count=0 must not emit outcome series via MetricsProjectionMetrics: {rendered}"
        );
        assert!(
            rendered.contains("outcome=\"duplicate\""),
            "positive count must still emit outcome series: {rendered}"
        );
    }
}
