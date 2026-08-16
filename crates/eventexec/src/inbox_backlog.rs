//! Runtime inbox backlog sampling and Prometheus emission.
//!
//! The selection is derived only from generated subscription specifications. Providers may return
//! typed tenant/group samples, but the sampler validates every group against that sealed selection
//! before a metric scope can be minted.
//!
//! ref: prometheus/client_golang prometheus/gauge.go@main

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use consistency::{BacklogSample, ConsumerGroup, EngineError};
use generated::event::SubscriptionSpec;
use rss_request_context::TenantId;
use tokio_util::sync::CancellationToken;

use crate::WorkerHealth;

/// Stable readyz probe name for the runtime inbox backlog sampler.
pub const INBOX_SAMPLER_PROBE: &str = "inbox_sampler";

/// Generated-topology allow-set for one runtime's inbox backlog sampling.
#[derive(Debug, Clone)]
pub struct InboxBacklogSelection {
    groups: Vec<ConsumerGroup>,
}

impl InboxBacklogSelection {
    /// Derive a canonical, deduplicated allow-set from generated subscription specifications.
    pub fn from_generated(specs: &[SubscriptionSpec]) -> Result<Self, InboxBacklogSelectionError> {
        let mut groups = specs
            .iter()
            .map(|spec| {
                ConsumerGroup::parse(spec.group())
                    .map_err(|_| InboxBacklogSelectionError::InvalidGeneratedGroup)
            })
            .collect::<Result<Vec<_>, _>>()?;
        groups.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
        groups.dedup();
        Ok(Self { groups })
    }

    /// Whether this runtime has any generated consumer group to observe.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Canonical generated group allow-set for the provider query.
    #[must_use]
    pub fn groups(&self) -> &[ConsumerGroup] {
        &self.groups
    }

    fn contains(&self, group: &ConsumerGroup) -> bool {
        self.groups
            .binary_search_by(|candidate| candidate.as_str().cmp(group.as_str()))
            .is_ok()
    }
}

/// Generated subscription selection could not be constructed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InboxBacklogSelectionError {
    /// Generated code contained an invalid consumer group.
    #[error("generated inbox backlog consumer group is invalid")]
    InvalidGeneratedGroup,
}

/// One provider-returned inbox backlog sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxBacklogSample {
    tenant_id: TenantId,
    consumer_group: ConsumerGroup,
    sample: BacklogSample,
}

impl InboxBacklogSample {
    /// Construct a typed provider sample. Selection membership is verified by the sampler.
    #[must_use]
    pub fn new(tenant_id: TenantId, consumer_group: ConsumerGroup, sample: BacklogSample) -> Self {
        Self {
            tenant_id,
            consumer_group,
            sample,
        }
    }

    /// Tenant returned by the provider.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Consumer group returned by the provider.
    #[must_use]
    pub fn consumer_group(&self) -> &ConsumerGroup {
        &self.consumer_group
    }

    /// Backlog scalars returned by the provider.
    #[must_use]
    pub fn sample(&self) -> BacklogSample {
        self.sample
    }
}

/// Ownership-aware result of one inbox backlog observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "standby must not be interpreted as an active empty inbox backlog sample"]
pub enum InboxBacklogObservation {
    /// This process held the maintenance lease and completed a real provider sample.
    Active(Vec<InboxBacklogSample>),
    /// This process did not hold, or lost, the maintenance lease.
    Standby,
}

/// Batch inbox backlog source. Native AFIT keeps the provider statically dispatched.
#[allow(async_fn_in_trait)]
pub trait InboxBacklogSource {
    /// Sample every stale inbox scope admitted by the generated selection in one provider call.
    async fn sample_backlog(
        &self,
        selection: &InboxBacklogSelection,
    ) -> Result<InboxBacklogObservation, EngineError>;
}

/// Validated sampler configuration.
#[derive(Debug, Clone)]
pub struct InboxSamplerConfig {
    selection: InboxBacklogSelection,
    sample_interval: Duration,
}

impl InboxSamplerConfig {
    /// Bind a non-empty generated selection to a non-zero interval.
    pub fn new(
        selection: InboxBacklogSelection,
        sample_interval: Duration,
    ) -> Result<Self, InboxSamplerConfigError> {
        if selection.is_empty() {
            return Err(InboxSamplerConfigError::EmptySelection);
        }
        if sample_interval.is_zero() {
            return Err(InboxSamplerConfigError::ZeroInterval);
        }
        Ok(Self {
            selection,
            sample_interval,
        })
    }

    /// Generated selection bound to this worker.
    #[must_use]
    pub fn selection(&self) -> &InboxBacklogSelection {
        &self.selection
    }

    /// Sampling period.
    #[must_use]
    pub fn sample_interval(&self) -> Duration {
        self.sample_interval
    }
}

/// Inbox sampler configuration failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InboxSamplerConfigError {
    /// A worker without generated groups would create a meaningless maintenance lane.
    #[error("inbox sampler selection must not be empty")]
    EmptySelection,
    /// A zero interval would busy-loop.
    #[error("inbox sampler interval must be greater than zero")]
    ZeroInterval,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ObservedInboxScope {
    tenant_id: TenantId,
    consumer_group: ConsumerGroup,
}

impl ObservedInboxScope {
    fn from_sample(sample: &InboxBacklogSample) -> Self {
        Self {
            tenant_id: sample.tenant_id(),
            consumer_group: sample.consumer_group().clone(),
        }
    }

    fn metric_scope(&self) -> InboxMetricScope<'_> {
        InboxMetricScope { observed: self }
    }
}

/// Validated metric label scope. It has no public constructor.
pub struct InboxMetricScope<'a> {
    observed: &'a ObservedInboxScope,
}

impl InboxMetricScope<'_> {
    /// Canonical tenant label.
    #[must_use]
    pub fn tenant_id_label(&self) -> String {
        self.observed.tenant_id.to_string()
    }

    /// Generated consumer-group label.
    #[must_use]
    pub fn consumer_group_label(&self) -> &str {
        self.observed.consumer_group.as_str()
    }
}

/// Inbox backlog metric emission seam.
pub trait InboxMetrics: Send + Sync {
    /// Set both backlog gauges to a real sample.
    fn record_backlog(&self, scope: &InboxMetricScope<'_>, sample: BacklogSample);
    /// Mark both gauges unavailable without forging zero.
    fn record_unavailable(&self, scope: &InboxMetricScope<'_>);
}

/// `metrics` facade-backed production emitter.
pub struct MetricsInboxMetrics;

impl InboxMetrics for MetricsInboxMetrics {
    fn record_backlog(&self, scope: &InboxMetricScope<'_>, sample: BacklogSample) {
        let tenant_id = scope.tenant_id_label();
        let consumer_group = scope.consumer_group_label().to_owned();
        metrics::gauge!(
            "inbox_stale_claim_depth",
            "tenant_id" => tenant_id.clone(),
            "consumer_group" => consumer_group.clone(),
        )
        .set(sample.depth() as f64);
        metrics::gauge!(
            "inbox_oldest_stale_claim_age_seconds",
            "tenant_id" => tenant_id,
            "consumer_group" => consumer_group,
        )
        .set(sample.oldest_age_seconds() as f64);
    }

    fn record_unavailable(&self, scope: &InboxMetricScope<'_>) {
        let tenant_id = scope.tenant_id_label();
        let consumer_group = scope.consumer_group_label().to_owned();
        metrics::gauge!(
            "inbox_stale_claim_depth",
            "tenant_id" => tenant_id.clone(),
            "consumer_group" => consumer_group.clone(),
        )
        .set(f64::NAN);
        metrics::gauge!(
            "inbox_oldest_stale_claim_age_seconds",
            "tenant_id" => tenant_id,
            "consumer_group" => consumer_group,
        )
        .set(f64::NAN);
    }
}

/// Process-local metric state retained for one ownership session.
#[derive(Default)]
pub struct InboxSamplerState {
    observed: HashSet<ObservedInboxScope>,
    was_active: bool,
}

/// Run an inbox sampling session while the caller retains distributed ownership.
pub async fn inbox_backlog_sampler_session<S>(
    source: Arc<S>,
    config: &InboxSamplerConfig,
    state: &mut InboxSamplerState,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn InboxMetrics>,
) where
    S: InboxBacklogSource,
{
    let mut ticker = tokio::time::interval(config.sample_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                sampler_tick(
                    source.as_ref(),
                    config.selection(),
                    &mut state.observed,
                    &mut state.was_active,
                    health.as_ref(),
                    metrics.as_ref(),
                ).await;
            }
        }
    }
}

/// Retire every series minted by the local owner after ownership is lost or shutdown begins.
pub fn retire_inbox_backlog_metrics(state: &mut InboxSamplerState, metrics: &dyn InboxMetrics) {
    mark_all_unavailable(&state.observed, metrics);
    state.observed.clear();
    state.was_active = false;
}

/// Run an uncoordinated long-lived inbox sampler on the caller-owned runtime.
pub async fn inbox_backlog_sampler_loop<S>(
    source: Arc<S>,
    config: InboxSamplerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    metrics: Arc<dyn InboxMetrics>,
) where
    S: InboxBacklogSource,
{
    let mut state = InboxSamplerState::default();
    inbox_backlog_sampler_session(
        source,
        &config,
        &mut state,
        token,
        Arc::clone(&health),
        Arc::clone(&metrics),
    )
    .await;
    retire_inbox_backlog_metrics(&mut state, metrics.as_ref());
    health.mark_stopped();
}

async fn sampler_tick<S: InboxBacklogSource>(
    source: &S,
    selection: &InboxBacklogSelection,
    observed: &mut HashSet<ObservedInboxScope>,
    was_active: &mut bool,
    health: &WorkerHealth,
    metrics: &dyn InboxMetrics,
) {
    match source.sample_backlog(selection).await {
        Ok(InboxBacklogObservation::Active(samples)) => {
            let mut current = HashSet::with_capacity(samples.len());
            let mut by_scope = HashMap::with_capacity(samples.len());
            for sample in samples {
                if !selection.contains(sample.consumer_group()) {
                    mark_all_unavailable(observed, metrics);
                    health.mark_invariant();
                    return;
                }
                let scope = ObservedInboxScope::from_sample(&sample);
                if by_scope.insert(scope.clone(), sample.sample()).is_some() {
                    mark_all_unavailable(observed, metrics);
                    health.mark_invariant();
                    return;
                }
                current.insert(scope);
            }
            for (scope, sample) in by_scope {
                metrics.record_backlog(&scope.metric_scope(), sample);
            }
            for stale in observed.difference(&current) {
                metrics.record_backlog(&stale.metric_scope(), BacklogSample::empty());
            }
            observed.extend(current);
            *was_active = true;
            health.mark_healthy();
        }
        Ok(InboxBacklogObservation::Standby) => {
            if *was_active {
                mark_all_unavailable(observed, metrics);
                observed.clear();
                *was_active = false;
            }
            health.mark_started();
        }
        Err(error) => {
            tracing::warn!(
                operation = "inbox_sample_backlog",
                error = %error,
                "inbox backlog sampler failed"
            );
            mark_all_unavailable(observed, metrics);
            health.mark_degraded();
        }
    }
}

fn mark_all_unavailable(observed: &HashSet<ObservedInboxScope>, metrics: &dyn InboxMetrics) {
    for scope in observed {
        metrics.record_unavailable(&scope.metric_scope());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use consistency::{EngineError, EngineErrorKind};
    use primitives::HealthStatus;

    fn selection() -> InboxBacklogSelection {
        let result = InboxBacklogSelection::from_generated(&[
            generated::event::settings_v1::SETTINGS_SUBSCRIPTION,
        ]);
        let Ok(selection) = result else {
            unreachable!("static generated selection is valid")
        };
        selection
    }

    fn tenant() -> TenantId {
        let result = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        let Ok(tenant) = result else {
            unreachable!("static tenant fixture is valid")
        };
        tenant
    }

    fn sample(group: &str, depth: u64) -> InboxBacklogSample {
        let result = ConsumerGroup::parse(group);
        let Ok(group) = result else {
            unreachable!("test group fixture is valid")
        };
        InboxBacklogSample::new(tenant(), group, BacklogSample::new(depth, 71))
    }

    struct FakeSource {
        observations: Mutex<VecDeque<Result<InboxBacklogObservation, EngineError>>>,
    }

    impl FakeSource {
        fn new(observations: Vec<Result<InboxBacklogObservation, EngineError>>) -> Self {
            Self {
                observations: Mutex::new(observations.into()),
            }
        }
    }

    impl InboxBacklogSource for FakeSource {
        async fn sample_backlog(
            &self,
            _selection: &InboxBacklogSelection,
        ) -> Result<InboxBacklogObservation, EngineError> {
            self.observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .pop_front()
                .unwrap_or_else(|| Err(EngineError::new(EngineErrorKind::Invariant)))
        }
    }

    #[derive(Default)]
    struct CountingMetrics {
        backlogs: Mutex<Vec<(String, String, BacklogSample)>>,
        unavailable: Mutex<Vec<(String, String)>>,
    }

    impl InboxMetrics for CountingMetrics {
        fn record_backlog(&self, scope: &InboxMetricScope<'_>, sample: BacklogSample) {
            self.backlogs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push((
                    scope.tenant_id_label(),
                    scope.consumer_group_label().to_owned(),
                    sample,
                ));
        }

        fn record_unavailable(&self, scope: &InboxMetricScope<'_>) {
            self.unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push((
                    scope.tenant_id_label(),
                    scope.consumer_group_label().to_owned(),
                ));
        }
    }

    #[test]
    fn config_rejects_empty_selection_and_zero_interval() {
        let Ok(empty) = InboxBacklogSelection::from_generated(&[]) else {
            unreachable!("empty generated selection is structurally valid")
        };
        assert!(matches!(
            InboxSamplerConfig::new(empty, Duration::from_secs(1)),
            Err(InboxSamplerConfigError::EmptySelection)
        ));
        assert!(matches!(
            InboxSamplerConfig::new(selection(), Duration::ZERO),
            Err(InboxSamplerConfigError::ZeroInterval)
        ));
    }

    fn render_sample(value: BacklogSample, unavailable: bool) -> String {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            let metrics = MetricsInboxMetrics;
            let observed =
                ObservedInboxScope::from_sample(&sample("settings.config-version-changed", 9));
            let scope = observed.metric_scope();
            metrics.record_backlog(&scope, value);
            if unavailable {
                metrics.record_unavailable(&scope);
            }
        });
        handle.render()
    }

    #[test]
    fn metrics_facade_emits_exact_backlog_series_and_labels() {
        let rendered = render_sample(BacklogSample::new(9, 71), false);
        for metric in [
            "inbox_stale_claim_depth",
            "inbox_oldest_stale_claim_age_seconds",
        ] {
            let line = rendered
                .lines()
                .find(|line| line.starts_with(metric) && !line.starts_with('#'));
            let Some(line) = line else {
                unreachable!("metric facade emitted the requested series")
            };
            assert!(line.contains("consumer_group=\"settings.config-version-changed\""));
            assert!(line.contains("tenant_id=\"f47ac10b-58cc-4372-a567-0e02b2c3d479\""));
            let labels = line
                .split_once('{')
                .and_then(|(_, rest)| rest.split_once('}'))
                .map(|(labels, _)| labels.split(',').count());
            let Some(labels) = labels else {
                unreachable!("rendered metric contains a label set")
            };
            assert_eq!(labels, 2, "inbox metric label set must be exact");
            let expected = if metric == "inbox_stale_claim_depth" {
                " 9"
            } else {
                " 71"
            };
            assert!(line.ends_with(expected), "unexpected sample: {line}");
        }
    }

    #[test]
    fn metrics_facade_emits_zero_after_clear() {
        let rendered = render_sample(BacklogSample::empty(), false);
        assert!(
            rendered
                .lines()
                .filter(|line| line.starts_with("inbox_"))
                .all(|line| line.ends_with(" 0"))
        );
    }

    #[test]
    fn metrics_facade_marks_failed_scope_nan() {
        let rendered = render_sample(BacklogSample::new(9, 71), true);
        assert!(
            rendered
                .lines()
                .filter(|line| line.starts_with("inbox_"))
                .all(|line| line.ends_with(" NaN"))
        );
    }

    #[tokio::test]
    async fn active_clear_failure_standby_and_recovery_have_closed_semantics() {
        let selection = selection();
        let source = FakeSource::new(vec![
            Ok(InboxBacklogObservation::Active(vec![sample(
                "settings.config-version-changed",
                4,
            )])),
            Err(EngineError::new(EngineErrorKind::Transient)),
            Ok(InboxBacklogObservation::Active(Vec::new())),
            Err(EngineError::new(EngineErrorKind::Transient)),
            Ok(InboxBacklogObservation::Active(vec![sample(
                "settings.config-version-changed",
                2,
            )])),
            Ok(InboxBacklogObservation::Standby),
        ]);
        let metrics = CountingMetrics::default();
        let health = WorkerHealth::starting();
        let mut observed = HashSet::new();
        let mut was_active = false;

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert_eq!(observed.len(), 1);

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            metrics
                .unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            1
        );

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert_eq!(
            observed.len(),
            1,
            "zeroed series remains known until retirement"
        );
        assert!(
            metrics
                .backlogs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .any(|(_, _, sample)| *sample == BacklogSample::empty())
        );

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            metrics
                .unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            2,
            "failure after zero must overwrite the exposed zero with NaN"
        );

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert!(observed.is_empty(), "standby retires process-local series");
        assert_eq!(
            metrics
                .unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn provider_group_outside_generated_selection_latches_invariant() {
        let selection = selection();
        let source = FakeSource::new(vec![Ok(InboxBacklogObservation::Active(vec![sample(
            "forged.group",
            1,
        )]))]);
        let metrics = CountingMetrics::default();
        let health = WorkerHealth::starting();
        let mut observed = HashSet::new();
        let mut was_active = false;
        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert!(
            metrics
                .backlogs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn duplicate_scope_fails_closed_without_rejecting_distinct_tenants() {
        let selection = selection();
        let group = "settings.config-version-changed";
        let first = sample(group, 1);
        let duplicate = sample(group, 2);
        let other_tenant = {
            let result = TenantId::parse("00000000-0000-4000-8000-000000000002");
            let Ok(tenant) = result else {
                unreachable!("static tenant fixture is valid")
            };
            let result = ConsumerGroup::parse(group);
            let Ok(group) = result else {
                unreachable!("static group fixture is valid")
            };
            InboxBacklogSample::new(tenant, group, BacklogSample::new(3, 71))
        };
        let source = FakeSource::new(vec![
            Ok(InboxBacklogObservation::Active(vec![
                first.clone(),
                other_tenant.clone(),
            ])),
            Ok(InboxBacklogObservation::Active(vec![first, duplicate])),
        ]);
        let metrics = CountingMetrics::default();
        let health = WorkerHealth::starting();
        let mut observed = HashSet::new();
        let mut was_active = false;

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert_eq!(observed.len(), 2, "tenant is part of provider uniqueness");

        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert_eq!(
            metrics
                .unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            2,
            "duplicate provider scope retires every previously exposed series"
        );
    }

    #[tokio::test]
    async fn standby_opens_starting_but_does_not_recover_degraded() {
        let selection = selection();
        let source = FakeSource::new(vec![
            Ok(InboxBacklogObservation::Standby),
            Err(EngineError::new(EngineErrorKind::Transient)),
            Ok(InboxBacklogObservation::Standby),
        ]);
        let metrics = CountingMetrics::default();
        let health = WorkerHealth::starting();
        let mut observed = HashSet::new();
        let mut was_active = false;
        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        sampler_tick(
            &source,
            &selection,
            &mut observed,
            &mut was_active,
            &health,
            &metrics,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert!(
            metrics
                .backlogs
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
        assert!(
            metrics
                .unavailable
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cancelled_sampler_marks_stopped_without_querying() {
        let source = Arc::new(FakeSource::new(Vec::new()));
        let result = InboxSamplerConfig::new(selection(), Duration::from_secs(1));
        let Ok(config) = result else {
            unreachable!("non-empty selection and positive interval are valid")
        };
        let token = CancellationToken::new();
        token.cancel();
        let health = Arc::new(WorkerHealth::starting());
        inbox_backlog_sampler_loop(
            source,
            config,
            token,
            Arc::clone(&health),
            Arc::new(CountingMetrics::default()),
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert_eq!(health.detail(), "stopped");
    }
}
