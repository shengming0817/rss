//! Runtime inbox backlog sampling through the closed Eventing observation seam.
//!
//! The selection is derived only from generated subscription specifications. Providers may return
//! typed tenant/group samples, but the sampler validates every group against that sealed selection
//! before contributing to the single process-level sum/max observation.
//!
//! ref: prometheus/client_golang prometheus/gauge.go@main

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use consistency::{BacklogSample, ConsumerGroup, EngineError};
use eventing::observability::{EventingEmitter, EventingObservation};
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
}

/// Process-local observation state retained for one ownership session.
#[derive(Default)]
pub struct InboxSamplerState {
    was_active: bool,
}

/// Run an inbox sampling session while the caller retains distributed ownership.
pub async fn inbox_backlog_sampler_session<S>(
    source: Arc<S>,
    config: &InboxSamplerConfig,
    state: &mut InboxSamplerState,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    emitter: Arc<dyn EventingEmitter>,
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
                    &mut state.was_active,
                    health.as_ref(),
                    emitter.as_ref(),
                ).await;
            }
        }
    }
}

/// Mark the complete global gauge group unavailable after ownership is lost or shutdown begins.
pub fn retire_inbox_backlog_metrics(state: &mut InboxSamplerState, emitter: &dyn EventingEmitter) {
    emitter.emit(EventingObservation::InboxBacklogUnavailable);
    state.was_active = false;
}

/// Run an uncoordinated long-lived inbox sampler on the caller-owned runtime.
pub async fn inbox_backlog_sampler_loop<S>(
    source: Arc<S>,
    config: InboxSamplerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
    emitter: Arc<dyn EventingEmitter>,
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
        Arc::clone(&emitter),
    )
    .await;
    retire_inbox_backlog_metrics(&mut state, emitter.as_ref());
    health.mark_stopped();
}

async fn sampler_tick<S: InboxBacklogSource>(
    source: &S,
    selection: &InboxBacklogSelection,
    was_active: &mut bool,
    health: &WorkerHealth,
    emitter: &dyn EventingEmitter,
) {
    match source.sample_backlog(selection).await {
        Ok(InboxBacklogObservation::Active(samples)) => {
            let mut current = HashSet::with_capacity(samples.len());
            let mut stale_claim_depth = 0_u64;
            let mut oldest_stale_claim_age = Duration::ZERO;
            for sample in samples {
                if !selection.contains(sample.consumer_group()) {
                    emitter.emit(EventingObservation::InboxBacklogUnavailable);
                    *was_active = false;
                    health.mark_invariant();
                    return;
                }
                let scope = ObservedInboxScope::from_sample(&sample);
                if !current.insert(scope) {
                    emitter.emit(EventingObservation::InboxBacklogUnavailable);
                    *was_active = false;
                    health.mark_invariant();
                    return;
                }
                let scalars = sample.sample();
                let Some(next_depth) = stale_claim_depth.checked_add(scalars.depth()) else {
                    emitter.emit(EventingObservation::InboxBacklogUnavailable);
                    *was_active = false;
                    health.mark_invariant();
                    return;
                };
                stale_claim_depth = next_depth;
                oldest_stale_claim_age =
                    oldest_stale_claim_age.max(Duration::from_secs(scalars.oldest_age_seconds()));
            }
            emitter.emit(EventingObservation::InboxBacklog {
                stale_claim_depth,
                oldest_stale_claim_age,
            });
            *was_active = true;
            health.mark_healthy();
        }
        Ok(InboxBacklogObservation::Standby) => {
            emitter.emit(EventingObservation::InboxBacklogUnavailable);
            *was_active = false;
            health.mark_started();
        }
        Err(error) => {
            tracing::warn!(
                operation = "inbox_sample_backlog",
                error = %error,
                "inbox backlog sampler failed"
            );
            emitter.emit(EventingObservation::InboxBacklogUnavailable);
            *was_active = false;
            health.mark_degraded();
        }
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
        observations: Mutex<Vec<EventingObservation>>,
    }

    impl EventingEmitter for CountingMetrics {
        fn emit(&self, observation: EventingObservation) {
            self.observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(observation);
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
        let mut was_active = false;

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert!(was_active);

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|observation| matches!(
                    observation,
                    EventingObservation::InboxBacklogUnavailable
                ))
                .count(),
            1
        );

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .any(|observation| *observation
                    == EventingObservation::InboxBacklog {
                        stale_claim_depth: 0,
                        oldest_stale_claim_age: Duration::ZERO,
                    })
        );

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|observation| matches!(
                    observation,
                    EventingObservation::InboxBacklogUnavailable
                ))
                .count(),
            2,
            "failure after zero must overwrite the exposed zero with NaN"
        );

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert!(!was_active, "standby retires process-local aggregate");
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|observation| matches!(
                    observation,
                    EventingObservation::InboxBacklogUnavailable
                ))
                .count(),
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
        let mut was_active = false;
        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice()
                == [EventingObservation::InboxBacklogUnavailable]
        );
    }

    #[tokio::test]
    async fn depth_overflow_emits_only_unavailable_and_latches_invariant() {
        let selection = selection();
        let source = FakeSource::new(vec![Ok(InboxBacklogObservation::Active(vec![
            sample("identity.session-created", u64::MAX),
            sample("settings.config-version-changed", 1),
        ]))]);
        let metrics = CountingMetrics::default();
        let health = WorkerHealth::healthy();
        let mut was_active = true;

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;

        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            [EventingObservation::InboxBacklogUnavailable]
        );
        assert!(!was_active);
        assert_eq!(health.status(), HealthStatus::Unhealthy);
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
            InboxBacklogSample::new(tenant, group, BacklogSample::new(3, 99))
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
        let mut was_active = false;

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        assert!(was_active);
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .first(),
            Some(&EventingObservation::InboxBacklog {
                stale_claim_depth: 4,
                oldest_stale_claim_age: Duration::from_secs(99),
            })
        );

        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|observation| matches!(
                    observation,
                    EventingObservation::InboxBacklogUnavailable
                ))
                .count(),
            1,
            "duplicate provider scope makes the single aggregate unavailable"
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
        let mut was_active = false;
        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        sampler_tick(&source, &selection, &mut was_active, &health, &metrics).await;
        assert_eq!(health.status(), HealthStatus::Degraded);
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            3
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
        let metrics = Arc::new(CountingMetrics::default());
        inbox_backlog_sampler_loop(
            source,
            config,
            token,
            Arc::clone(&health),
            Arc::clone(&metrics) as Arc<dyn EventingEmitter>,
        )
        .await;
        assert_eq!(health.status(), HealthStatus::Unhealthy);
        assert_eq!(health.detail(), "stopped");
        assert_eq!(
            metrics
                .observations
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_slice(),
            [EventingObservation::InboxBacklogUnavailable]
        );
    }
}
