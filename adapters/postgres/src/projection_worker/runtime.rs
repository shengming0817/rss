//! Runtime orchestration for the Settings-owned Projection worker capability.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::Arc;
#[cfg(test)]
use std::time::SystemTime;
use std::time::{Duration, UNIX_EPOCH};

use diport::{Clock, DynManagedResource, ManagedResource};
use tokio_util::sync::CancellationToken;

use super::{
    PgProjectionWorkerCheckpointStore, PgProjectionWorkerDeadLetterStore, PgProjectionWorkerSource,
    ProjectionWorkerTarget, VerifiedPgProjectionWorkerStore,
};
use crate::dead_letter_payload::DlxPayloadProtector;
use crate::{
    PgProjectionWorkerConfig, PgProjectionWorkerError, PgSettingsProjectionApplyStore, PgStore,
};

/// Dedicated background Projection worker capability owner.
#[cfg(feature = "domain-settings")]
pub struct PgProjectionWorkerDeps {
    worker: VerifiedPgProjectionWorkerStore,
    payload_protector: DlxPayloadProtector,
    clock: Arc<dyn Clock>,
}

#[cfg(feature = "domain-settings")]
impl PgProjectionWorkerDeps {
    pub async fn connect(
        config: &PgProjectionWorkerConfig,
        payload_protector: DlxPayloadProtector,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, PgProjectionWorkerError> {
        let worker = PgStore::connect_verified_projection_worker(config).await?;
        Ok(Self {
            worker,
            payload_protector,
            clock,
        })
    }

    /// Consume the verified worker capability into one plan-issued Settings runtime.
    pub fn into_settings_worker_runtime(
        self,
        binding: eventexec::ProjectionRuntimeBinding,
        runner: eventexec::ProjectionRunnerConfig,
        metrics: Arc<dyn eventexec::ProjectionMetrics>,
    ) -> Result<eventexec::ProjectionRuntime, eventexec::WorkflowRuntimeError> {
        let definition = binding.definition();
        let Ok(target_definition) =
            eventexec::ProjectionTargetDefinition::new(definition, binding.input_generation())
        else {
            unreachable!("plan-issued Settings projection definition is valid")
        };
        let target_scope = ProjectionWorkerTarget::from_binding(&binding);
        let store = Arc::new(PgSettingsProjectionApplyStore::new_projection_worker(
            &self.worker,
            &target_scope,
        ));
        let Ok(target) = eventexec::ConformingProjectionTarget::new(
            target_definition,
            binding.inputs().to_vec(),
            store,
        ) else {
            unreachable!("plan-issued Settings projection bindings are exact")
        };
        let metric_scope = binding.metric_scope();
        let worker = self.worker;
        let payload_protector = self.payload_protector;
        let clock = self.clock;
        binding.issue_runtime(Arc::new(target), move |target, token, health| {
            spawn_settings_projection_worker(
                SettingsProjectionWorkerLaunch {
                    worker_store: worker.clone(),
                    target_scope: target_scope.clone(),
                    target,
                    payload_protector: payload_protector.clone(),
                    runner,
                    metrics: Arc::clone(&metrics),
                    metric_scope,
                    clock: Arc::clone(&clock),
                },
                token,
                health,
            )
        })
    }
}

#[cfg(feature = "domain-settings")]
const PROJECTION_WORKER_TENANT_PAGE_SIZE: i32 = 100;
#[cfg(feature = "domain-settings")]
const PROJECTION_WORKER_JOIN_TIMEOUT: Duration = Duration::from_secs(45);
#[cfg(feature = "domain-settings")]
const PROJECTION_WORKER_POOL_FENCE_BUDGET: Duration = Duration::from_secs(1);
#[cfg(feature = "domain-settings")]
const PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(50);
#[cfg(feature = "domain-settings")]
pub(crate) const PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(feature = "domain-settings")]
pub(crate) const PROJECTION_WORKER_APPLY_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(feature = "domain-settings")]
const PROJECTION_WORKER_BATCH_BUDGET: Duration = Duration::from_secs(40);
/// Shared observe-tenant SQL (six binds: tenant, projection_id, target_generation,
/// definition_version, definition_schema_digest, input_generation).
#[cfg(feature = "domain-settings")]
pub(crate) const PROJECTION_WORKER_OBSERVE_TENANT_SQL: &str = "SELECT source_high_water, checkpoint_offset_lsn, \
     checkpoint_updated_at_epoch_micros, projection_dlq_backlog \
     FROM public.rss_projection_worker_observe_tenant(\
         $1::uuid, $2, $3, $4, $5, $6)";
#[cfg(feature = "domain-settings")]
const _: () = assert!(
    PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT.as_secs() * 5
        + PROJECTION_WORKER_APPLY_TIMEOUT.as_secs()
        <= PROJECTION_WORKER_BATCH_BUDGET.as_secs()
);
#[cfg(feature = "domain-settings")]
const _: () =
    assert!(PROJECTION_WORKER_BATCH_BUDGET.as_secs() < PROJECTION_WORKER_JOIN_TIMEOUT.as_secs());
#[cfg(feature = "domain-settings")]
const _: () = assert!(
    PROJECTION_WORKER_JOIN_TIMEOUT.as_secs() + PROJECTION_WORKER_POOL_FENCE_BUDGET.as_secs()
        < PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT.as_secs()
);
#[cfg(feature = "domain-settings")]
const _: () = assert!(PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT.as_secs() < 60);

#[cfg(feature = "domain-settings")]
#[derive(Debug, thiserror::Error)]
enum PgProjectionWorkerRuntimeError {
    #[error("projection worker tenant catalog is unavailable")]
    TenantCatalog(#[source] sqlx::Error),
    #[error("projection worker tenant catalog timed out")]
    TenantCatalogTimeout,
    #[error("projection worker active generation resolver is unavailable")]
    ActiveGeneration(#[source] sqlx::Error),
    #[error("projection worker active generation resolver timed out")]
    ActiveGenerationTimeout,
    #[error("projection worker active generation identity is invalid")]
    ActiveGenerationIdentity,
    #[error("projection worker tenant catalog returned an invalid tenant")]
    InvalidTenant,
    #[error("projection worker stopped on a fatal projection outcome")]
    FatalProjection,
    #[error("projection worker could not persist tenant quarantine")]
    TenantQuarantine(#[source] sqlx::Error),
    #[error("projection worker tenant quarantine timed out")]
    TenantQuarantineTimeout,
    #[error("projection worker tenant observation is unavailable")]
    TenantObservation(#[source] sqlx::Error),
    #[error("projection worker tenant observation timed out")]
    TenantObservationTimeout,
    #[error("projection worker fatal lsn is outside the postgres coordinate range")]
    FailedLsnOverflow,
    #[error("projection worker target execution binding is invalid")]
    TargetConfig(#[source] eventexec::ProjectionTargetConfigError),
    #[error("projection worker startup checkpoint observation failed")]
    StartupCheckpoint(#[source] diport::CheckpointStoreError),
    #[error("projection worker startup source observation failed")]
    StartupSource(#[source] consistency::EngineError),
}

#[cfg(feature = "domain-settings")]
struct PgProjectionWorkerRuntime {
    worker: eventexec::ManagedBlockingWorker,
    store: VerifiedPgProjectionWorkerStore,
}

#[cfg(feature = "domain-settings")]
impl ManagedResource for PgProjectionWorkerRuntime {
    fn name(&self) -> &str {
        self.worker.name()
    }

    fn shutdown_timeout(&self) -> Duration {
        PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        let worker = self.worker.shutdown().await;
        let store = self.store.shutdown().await;
        worker.and(store)
    }
}

#[cfg(feature = "domain-settings")]
struct SettingsProjectionWorkerLaunch {
    worker_store: VerifiedPgProjectionWorkerStore,
    target_scope: ProjectionWorkerTarget,
    target: Arc<dyn eventexec::ProjectionTarget>,
    payload_protector: DlxPayloadProtector,
    runner: eventexec::ProjectionRunnerConfig,
    metrics: Arc<dyn eventexec::ProjectionMetrics>,
    metric_scope: eventexec::ProjectionMetricScope,
    clock: Arc<dyn Clock>,
}

#[cfg(feature = "domain-settings")]
fn spawn_settings_projection_worker(
    launch: SettingsProjectionWorkerLaunch,
    token: CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
) -> Box<DynManagedResource<'static>> {
    let store = launch.worker_store.clone();
    let worker_health = Arc::clone(&health);
    let worker = eventexec::spawn_on_dedicated_runtime(
        "postgres-settings-projection-worker",
        token,
        health,
        PROJECTION_WORKER_JOIN_TIMEOUT,
        move |token| async move {
            projection_worker_loop(launch, token, worker_health)
                .await
                .map_err(diport::ShutdownError::new)
        },
    );
    DynManagedResource::new_box(PgProjectionWorkerRuntime { worker, store })
}

#[cfg(feature = "domain-settings")]
async fn projection_worker_loop(
    launch: SettingsProjectionWorkerLaunch,
    token: CancellationToken,
    health: Arc<eventexec::WorkerHealth>,
) -> Result<(), PgProjectionWorkerRuntimeError> {
    let SettingsProjectionWorkerLaunch {
        worker_store: worker,
        target_scope,
        target,
        payload_protector,
        runner,
        metrics,
        metric_scope,
        clock,
    } = launch;
    let mut ticker = tokio::time::interval(runner.poll_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut startup_observed = false;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => return Ok(()),
            _ = ticker.tick() => {}
        }

        if !startup_observed {
            match observe_projection_worker_startup(&worker, &target_scope, runner).await {
                Ok(degraded) => {
                    startup_observed = true;
                    record_projection_worker_health(&health, degraded);
                }
                Err(error) if projection_startup_observation_is_retryable(&error) => {
                    log_projection_worker_retry(&error, "startup observation");
                    record_projection_worker_health(&health, true);
                }
                Err(error) => return Err(error),
            }
            continue;
        }

        let retryable_failure = run_projection_sweep(
            &worker,
            &target_scope,
            Arc::clone(&target),
            payload_protector.clone(),
            runner,
            &token,
            &ProjectionWorkerMetricCtx {
                metrics: metrics.as_ref(),
                scope: &metric_scope,
                clock: clock.as_ref(),
            },
        )
        .await?;
        record_projection_worker_health(&health, retryable_failure);
    }
}

#[cfg(feature = "domain-settings")]
fn log_projection_worker_retry(error: &PgProjectionWorkerRuntimeError, operation: &'static str) {
    tracing::warn!(
        error = %error,
        operation,
        "settings projection worker operation will retry"
    );
}

#[cfg(feature = "domain-settings")]
fn record_projection_worker_health(health: &eventexec::WorkerHealth, retryable_failure: bool) {
    if retryable_failure {
        health.mark_projection_degraded();
    } else {
        health.mark_healthy();
    }
}

#[cfg(feature = "domain-settings")]
fn projection_startup_observation_is_retryable(error: &PgProjectionWorkerRuntimeError) -> bool {
    match error {
        PgProjectionWorkerRuntimeError::TenantCatalog(error)
        | PgProjectionWorkerRuntimeError::TenantQuarantine(error)
        | PgProjectionWorkerRuntimeError::TenantObservation(error)
        | PgProjectionWorkerRuntimeError::ActiveGeneration(error) => {
            crate::tx_retry::classify_sqlx_error(error) == consistency::TxRetryClass::Transient
        }
        PgProjectionWorkerRuntimeError::TenantCatalogTimeout
        | PgProjectionWorkerRuntimeError::ActiveGenerationTimeout
        | PgProjectionWorkerRuntimeError::TenantQuarantineTimeout
        | PgProjectionWorkerRuntimeError::TenantObservationTimeout
        | PgProjectionWorkerRuntimeError::StartupCheckpoint(_) => true,
        PgProjectionWorkerRuntimeError::StartupSource(error) => {
            error.kind() == consistency::EngineErrorKind::Transient
        }
        PgProjectionWorkerRuntimeError::InvalidTenant
        | PgProjectionWorkerRuntimeError::ActiveGenerationIdentity
        | PgProjectionWorkerRuntimeError::FatalProjection
        | PgProjectionWorkerRuntimeError::FailedLsnOverflow
        | PgProjectionWorkerRuntimeError::TargetConfig(_) => false,
    }
}

#[cfg(feature = "domain-settings")]
async fn observe_projection_worker_startup(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    runner: eventexec::ProjectionRunnerConfig,
) -> Result<bool, PgProjectionWorkerRuntimeError> {
    let tenants = projection_worker_tenants(worker, target, None).await?;
    let Some(tenant) = tenants.first().copied() else {
        return Ok(false);
    };
    let selected = resolve_projection_worker_generation(worker, target, tenant).await?;
    let Some(selected_target) = selected.bind(target) else {
        return Ok(false);
    };
    if projection_worker_tenant_is_quarantined(worker, &selected_target, tenant).await? {
        return Ok(true);
    }
    let selector = selected_target.selector(tenant);
    let checkpoint = PgProjectionWorkerCheckpointStore::new(worker, &selected_target, tenant);
    let baseline = diport::OwnerCheckpointStore::get_checkpoint(
        &checkpoint,
        &selector.shadow_checkpoint_owner(),
        &selector.shadow_checkpoint_id(),
    )
    .await
    .map_err(PgProjectionWorkerRuntimeError::StartupCheckpoint)?
    .map(|checkpoint| checkpoint.offset);
    let source = PgProjectionWorkerSource::new(worker, &selected_target, tenant);
    let _ = consistency::ProjectionEventSource::read_from(&source, baseline, runner.batch_limit())
        .await
        .map_err(PgProjectionWorkerRuntimeError::StartupSource)?;
    Ok(false)
}

#[cfg(feature = "domain-settings")]
#[allow(
    clippy::disallowed_methods,
    reason = "Tokio Instant is the monotonic source for one bounded worker sweep; no domain timestamp or persisted fact is derived from it"
)]
async fn run_projection_sweep(
    worker: &VerifiedPgProjectionWorkerStore,
    target_scope: &ProjectionWorkerTarget,
    target: Arc<dyn eventexec::ProjectionTarget>,
    payload_protector: DlxPayloadProtector,
    runner: eventexec::ProjectionRunnerConfig,
    token: &CancellationToken,
    metric_ctx: &ProjectionWorkerMetricCtx<'_>,
) -> Result<bool, PgProjectionWorkerRuntimeError> {
    let deadline = tokio::time::Instant::now() + PROJECTION_WORKER_BATCH_BUDGET;
    let mut after = None;
    let mut retryable_failure = false;
    let mut more_work = VecDeque::new();
    // Fail-closed: only a fully completed observation sweep may emit finite gauges.
    let mut sweep = ProjectionSweepGaugeEmit {
        metric_ctx,
        gauges: ProjectionSweepGaugeAcc::default(),
        complete: false,
    };
    loop {
        let tenants = match tokio::select! {
            biased;
            () = token.cancelled() => return Ok(retryable_failure),
            () = tokio::time::sleep_until(deadline) => return Ok(retryable_failure),
            tenants = projection_worker_tenants(worker, target_scope, after) => tenants,
        } {
            Ok(tenants) => tenants,
            Err(error) if projection_startup_observation_is_retryable(&error) => {
                log_projection_worker_retry(&error, "tenant discovery");
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        if tenants.is_empty() {
            sweep.complete = true;
            return Ok(retryable_failure);
        }
        for tenant in tenants.iter().copied() {
            let outcome = tokio::select! {
                () = tokio::time::sleep_until(deadline) => return Ok(retryable_failure),
                outcome = run_and_settle_projection_tenant(
                    worker,
                    target_scope,
                    Arc::clone(&target),
                    payload_protector.clone(),
                    runner,
                    tenant,
                    ProjectionTenantQuantum {
                        metric_ctx,
                        gauges: Some(&mut sweep.gauges),
                    },
                ) => match outcome {
                    Ok(outcome) => outcome,
                    Err(error) => return Err(error),
                },
            };
            retryable_failure |= projection_tenant_run_health(outcome, tenant, &mut more_work);
        }
        after = tenants.last().copied();
        if tenants.len() < usize::try_from(PROJECTION_WORKER_TENANT_PAGE_SIZE).unwrap_or(usize::MAX)
        {
            break;
        }
    }
    match drive_projection_round_robin(more_work, deadline, token, |tenant| {
        run_and_settle_projection_tenant(
            worker,
            target_scope,
            Arc::clone(&target),
            payload_protector.clone(),
            runner,
            tenant,
            ProjectionTenantQuantum {
                metric_ctx,
                gauges: None,
            },
        )
    })
    .await
    {
        Ok(more_retryable) => {
            retryable_failure |= more_retryable;
            sweep.complete = true;
            Ok(retryable_failure)
        }
        Err(error) => Err(error),
    }
}

#[cfg(feature = "domain-settings")]
struct ProjectionWorkerMetricCtx<'a> {
    metrics: &'a dyn eventexec::ProjectionMetrics,
    scope: &'a eventexec::ProjectionMetricScope,
    clock: &'a dyn Clock,
}

/// Always emits sweep gauges on drop. Incomplete sweeps force the NaN triple (never 0 or stale).
#[cfg(feature = "domain-settings")]
struct ProjectionSweepGaugeEmit<'a> {
    metric_ctx: &'a ProjectionWorkerMetricCtx<'a>,
    gauges: ProjectionSweepGaugeAcc,
    complete: bool,
}

#[cfg(feature = "domain-settings")]
impl Drop for ProjectionSweepGaugeEmit<'_> {
    fn drop(&mut self) {
        seal_projection_sweep_completeness(self.complete, &mut self.gauges);
        emit_projection_sweep_gauges(self.metric_ctx, &self.gauges);
    }
}

#[cfg(feature = "domain-settings")]
struct ProjectionTenantQuantum<'a> {
    metric_ctx: &'a ProjectionWorkerMetricCtx<'a>,
    gauges: Option<&'a mut ProjectionSweepGaugeAcc>,
}

#[cfg(feature = "domain-settings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionTenantRun {
    Clean,
    MoreWork,
    Fenced,
    Retryable,
    Quarantined(ProjectionTenantFatal),
}

#[cfg(feature = "domain-settings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionTenantFatal {
    reason: ProjectionTenantFatalReason,
    failed_lsn: consistency::Lsn,
}

#[cfg(feature = "domain-settings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectionTenantFatalReason {
    TargetDefinitionDrift,
    InputBindingDrift,
    TenantDrift,
    PayloadMalformed,
    PayloadValueInvalid,
    VersionRegression,
    ProviderInvariant,
    ProviderPermanent,
    Conflict,
    ApplyOutOfOrder,
    RollbackFailed,
    SourceOutOfOrder,
}

#[cfg(feature = "domain-settings")]
impl ProjectionTenantFatalReason {
    const fn from_apply(reason: consistency::ProjectionApplyErrorReason) -> Option<Self> {
        match reason {
            consistency::ProjectionApplyErrorReason::TargetDefinitionDrift => {
                Some(Self::TargetDefinitionDrift)
            }
            consistency::ProjectionApplyErrorReason::InputBindingDrift => {
                Some(Self::InputBindingDrift)
            }
            consistency::ProjectionApplyErrorReason::TenantDrift => Some(Self::TenantDrift),
            consistency::ProjectionApplyErrorReason::PayloadMalformed => {
                Some(Self::PayloadMalformed)
            }
            consistency::ProjectionApplyErrorReason::PayloadValueInvalid => {
                Some(Self::PayloadValueInvalid)
            }
            consistency::ProjectionApplyErrorReason::VersionRegression => {
                Some(Self::VersionRegression)
            }
            consistency::ProjectionApplyErrorReason::ProviderInvariant => {
                Some(Self::ProviderInvariant)
            }
            consistency::ProjectionApplyErrorReason::ProviderPermanent => {
                Some(Self::ProviderPermanent)
            }
            consistency::ProjectionApplyErrorReason::Conflict => Some(Self::Conflict),
            consistency::ProjectionApplyErrorReason::OutOfOrder => Some(Self::ApplyOutOfOrder),
            consistency::ProjectionApplyErrorReason::RollbackFailed => Some(Self::RollbackFailed),
            consistency::ProjectionApplyErrorReason::Transient
            | consistency::ProjectionApplyErrorReason::CommitUnknown => None,
        }
    }

    const fn as_label(self) -> &'static str {
        match self {
            Self::TargetDefinitionDrift => "target_definition_drift",
            Self::InputBindingDrift => "input_binding_drift",
            Self::TenantDrift => "tenant_drift",
            Self::PayloadMalformed => "payload_malformed",
            Self::PayloadValueInvalid => "payload_value_invalid",
            Self::VersionRegression => "version_regression",
            Self::ProviderInvariant => "provider_invariant",
            Self::ProviderPermanent => "provider_permanent",
            Self::Conflict => "conflict",
            Self::ApplyOutOfOrder => "apply_out_of_order",
            Self::RollbackFailed => "rollback_failed",
            Self::SourceOutOfOrder => "source_out_of_order",
        }
    }
}

#[cfg(feature = "domain-settings")]
fn projection_tenant_run_health(
    outcome: ProjectionTenantRun,
    tenant: vocab::TenantId,
    more_work: &mut VecDeque<vocab::TenantId>,
) -> bool {
    match outcome {
        ProjectionTenantRun::Clean | ProjectionTenantRun::Fenced => false,
        ProjectionTenantRun::MoreWork => {
            more_work.push_back(tenant);
            false
        }
        ProjectionTenantRun::Retryable | ProjectionTenantRun::Quarantined(_) => true,
    }
}

#[cfg(feature = "domain-settings")]
#[allow(
    clippy::disallowed_methods,
    reason = "Tokio Instant compares the same monotonic worker-sweep deadline; no domain timestamp or persisted fact is derived from it"
)]
async fn drive_projection_round_robin<F, Fut>(
    mut tenants: VecDeque<vocab::TenantId>,
    deadline: tokio::time::Instant,
    token: &CancellationToken,
    mut run: F,
) -> Result<bool, PgProjectionWorkerRuntimeError>
where
    F: FnMut(vocab::TenantId) -> Fut,
    Fut: Future<Output = Result<ProjectionTenantRun, PgProjectionWorkerRuntimeError>>,
{
    let mut degraded = false;
    while let Some(tenant) = tenants.pop_front() {
        if token.is_cancelled() || tokio::time::Instant::now() >= deadline {
            break;
        }
        let outcome = tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            outcome = run(tenant) => outcome?,
        };
        degraded |= projection_tenant_run_health(outcome, tenant, &mut tenants);
    }
    Ok(degraded)
}

#[cfg(feature = "domain-settings")]
async fn projection_worker_tenants(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    after: Option<vocab::TenantId>,
) -> Result<Vec<vocab::TenantId>, PgProjectionWorkerRuntimeError> {
    let tenants: Vec<String> = tokio::time::timeout(
        PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT,
        sqlx::query_scalar(
            "SELECT tenant_id::text FROM public.rss_projection_worker_list_tenants(\
             $1, $2, $3, $4, $5::uuid, $6::integer)",
        )
        .bind(target.projection_id())
        .bind(target.definition_version())
        .bind(target.definition_schema_digest())
        .bind(target.input_generation())
        .bind(after.map(|tenant| tenant.to_string()))
        .bind(PROJECTION_WORKER_TENANT_PAGE_SIZE)
        .fetch_all(&worker.0.pool),
    )
    .await
    .map_err(|_| PgProjectionWorkerRuntimeError::TenantCatalogTimeout)?
    .map_err(PgProjectionWorkerRuntimeError::TenantCatalog)?;
    tenants
        .into_iter()
        .map(|tenant| {
            vocab::TenantId::parse(&tenant)
                .map_err(|_| PgProjectionWorkerRuntimeError::InvalidTenant)
        })
        .collect()
}

#[cfg(feature = "domain-settings")]
async fn projection_worker_tenant_is_quarantined(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: vocab::TenantId,
) -> Result<bool, PgProjectionWorkerRuntimeError> {
    tokio::time::timeout(PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
        let mut tx = worker.0.pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        let quarantined = sqlx::query_scalar(
            "SELECT public.rss_projection_worker_tenant_is_quarantined(\
                 $1::uuid, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.to_string())
        .bind(target.projection_id())
        .bind(target.target_generation())
        .bind(target.definition_version())
        .bind(target.definition_schema_digest())
        .bind(target.input_generation())
        .fetch_one(&mut *tx)
        .await?;
        tx.rollback().await?;
        Ok::<_, sqlx::Error>(quarantined)
    })
    .await
    .map_err(|_| PgProjectionWorkerRuntimeError::TenantQuarantineTimeout)?
    .map_err(PgProjectionWorkerRuntimeError::TenantQuarantine)
}

#[cfg(feature = "domain-settings")]
struct ActiveProjectionWorkerSnapshot {
    generation: eventexec::ProjectionVersion,
    _promoted_high_water_lsn: consistency::Lsn,
    _token: vocab::Epoch,
}

#[cfg(feature = "domain-settings")]
enum ProjectionWorkerGeneration {
    Uninitialized,
    Active(ActiveProjectionWorkerSnapshot),
}

#[cfg(feature = "domain-settings")]
impl ProjectionWorkerGeneration {
    fn bind(self, plan: &ProjectionWorkerTarget) -> Option<ProjectionWorkerTarget> {
        match self {
            Self::Uninitialized => None,
            Self::Active(snapshot) => Some(plan.for_generation(snapshot.generation)),
        }
    }
}

#[cfg(feature = "domain-settings")]
async fn resolve_projection_worker_generation(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: vocab::TenantId,
) -> Result<ProjectionWorkerGeneration, PgProjectionWorkerRuntimeError> {
    let row: Option<(String, String, String, String, i64, i64)> =
        tokio::time::timeout(PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
            let mut tx = worker.0.pool.begin().await?;
            crate::cotx::set_local_tenant(&mut tx, tenant).await?;
            let row = sqlx::query_as(
                "SELECT generation, definition_version, definition_schema_digest, \
                        input_generation, promoted_high_water_lsn, token \
                 FROM public.rss_settings_projection_resolve_active()",
            )
            .fetch_optional(&mut *tx)
            .await?;
            tx.rollback().await?;
            Ok::<_, sqlx::Error>(row)
        })
        .await
        .map_err(|_| PgProjectionWorkerRuntimeError::ActiveGenerationTimeout)?
        .map_err(PgProjectionWorkerRuntimeError::ActiveGeneration)?;
    let Some((
        generation,
        definition_version,
        definition_digest,
        input_generation,
        high_water,
        token,
    )) = row
    else {
        return Ok(ProjectionWorkerGeneration::Uninitialized);
    };
    if definition_version != target.definition_version()
        || definition_digest != target.definition_schema_digest()
        || input_generation != target.input_generation()
    {
        return Err(PgProjectionWorkerRuntimeError::ActiveGenerationIdentity);
    }
    let generation = eventexec::ProjectionVersion::parse(&generation)
        .map_err(|_| PgProjectionWorkerRuntimeError::ActiveGenerationIdentity)?;
    let high_water = u64::try_from(high_water)
        .map(consistency::Lsn::new)
        .map_err(|_| PgProjectionWorkerRuntimeError::ActiveGenerationIdentity)?;
    let token = u64::try_from(token)
        .map(vocab::Epoch::new)
        .map_err(|_| PgProjectionWorkerRuntimeError::ActiveGenerationIdentity)?;
    if token.get() == 0 {
        return Err(PgProjectionWorkerRuntimeError::ActiveGenerationIdentity);
    }
    Ok(ProjectionWorkerGeneration::Active(
        ActiveProjectionWorkerSnapshot {
            generation,
            _promoted_high_water_lsn: high_water,
            _token: token,
        },
    ))
}

#[cfg(feature = "domain-settings")]
async fn run_and_settle_projection_tenant(
    worker: &VerifiedPgProjectionWorkerStore,
    target_scope: &ProjectionWorkerTarget,
    target: Arc<dyn eventexec::ProjectionTarget>,
    payload_protector: DlxPayloadProtector,
    runner: eventexec::ProjectionRunnerConfig,
    tenant: vocab::TenantId,
    quantum: ProjectionTenantQuantum<'_>,
) -> Result<ProjectionTenantRun, PgProjectionWorkerRuntimeError> {
    // Resolve/bind first: observe SQL requires the selected active generation. Uninitialized /
    // fenced tenants skip observation; observe the exact selected scope before quarantine so
    // backlog remains visible.
    let selected = resolve_projection_worker_generation(worker, target_scope, tenant).await?;
    let Some(selected_scope) = selected.bind(target_scope) else {
        return Ok(ProjectionTenantRun::Fenced);
    };
    if let Some(gauges) = quantum.gauges {
        observe_projection_tenant_gauges(
            worker,
            &selected_scope,
            tenant,
            quantum.metric_ctx.clock,
            gauges,
        )
        .await;
    }
    if projection_worker_tenant_is_quarantined(worker, &selected_scope, tenant).await? {
        return Ok(ProjectionTenantRun::Retryable);
    }
    let outcome = run_projection_tenant(
        worker,
        &selected_scope,
        target,
        payload_protector,
        runner,
        tenant,
        quantum.metric_ctx,
    )
    .await?;
    let ProjectionTenantRun::Quarantined(fatal) = outcome else {
        return Ok(outcome);
    };
    match quarantine_projection_tenant(worker, &selected_scope, tenant, fatal).await {
        Ok(()) => Ok(outcome),
        Err(error) if projection_startup_observation_is_retryable(&error) => {
            log_projection_worker_retry(&error, "tenant quarantine");
            Ok(ProjectionTenantRun::Retryable)
        }
        Err(error) => Err(error),
    }
}

#[cfg(feature = "domain-settings")]
async fn quarantine_projection_tenant(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: vocab::TenantId,
    fatal: ProjectionTenantFatal,
) -> Result<(), PgProjectionWorkerRuntimeError> {
    let failed_lsn = i64::try_from(fatal.failed_lsn.get())
        .map_err(|_| PgProjectionWorkerRuntimeError::FailedLsnOverflow)?;
    tokio::time::timeout(PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
        let mut tx = worker.0.pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        sqlx::query(
            "SELECT public.rss_projection_worker_quarantine_tenant(\
                 $1::uuid, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant.to_string())
        .bind(target.projection_id())
        .bind(target.target_generation())
        .bind(target.definition_version())
        .bind(target.definition_schema_digest())
        .bind(target.input_generation())
        .bind(fatal.reason.as_label())
        .bind(failed_lsn)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok::<_, sqlx::Error>(())
    })
    .await
    .map_err(|_| PgProjectionWorkerRuntimeError::TenantQuarantineTimeout)?
    .map_err(PgProjectionWorkerRuntimeError::TenantQuarantine)
}

#[cfg(feature = "domain-settings")]
async fn run_projection_tenant(
    worker: &VerifiedPgProjectionWorkerStore,
    target_scope: &ProjectionWorkerTarget,
    target: Arc<dyn eventexec::ProjectionTarget>,
    payload_protector: DlxPayloadProtector,
    runner: eventexec::ProjectionRunnerConfig,
    tenant: vocab::TenantId,
    metric_ctx: &ProjectionWorkerMetricCtx<'_>,
) -> Result<ProjectionTenantRun, PgProjectionWorkerRuntimeError> {
    let source = PgProjectionWorkerSource::new(worker, target_scope, tenant);
    let selector = target_scope.selector(tenant);
    let checkpoint = PgProjectionWorkerCheckpointStore::new(worker, target_scope, tenant);
    let dead_letter =
        PgProjectionWorkerDeadLetterStore::new(worker, target_scope, tenant, payload_protector);
    let witness = consistency::SerialInOrder::from_source(&source);
    let projector = eventexec::ProjectionProjector::with_execution(
        target_scope.background_execution(tenant),
        selector.clone(),
        target,
    )
    .map_err(PgProjectionWorkerRuntimeError::TargetConfig)?;
    let harness = eventexec::ProjectionHarness::new(
        Arc::new(projector),
        Arc::new(checkpoint),
        selector.shadow_checkpoint_owner(),
        selector.shadow_checkpoint_id(),
        Arc::new(dead_letter),
        witness,
    );
    let run = eventexec::projection_runner_once(&source, &harness, runner).await;
    record_projection_run_metrics(metric_ctx, &run);
    classify_projection_tenant_quantum(&run, runner.batch_limit())
}

#[cfg(feature = "domain-settings")]
#[derive(Debug, Default)]
struct ProjectionSweepGaugeAcc {
    observe_failed: bool,
    max_lag: f64,
    max_freshness_secs: Option<f64>,
    sum_dlq: f64,
    observed_tenants: HashSet<vocab::TenantId>,
}

#[cfg(feature = "domain-settings")]
#[derive(Debug, Clone, Copy)]
struct ProjectionTenantObservation {
    source_high_water: Option<i64>,
    checkpoint_offset_lsn: Option<i64>,
    checkpoint_updated_at_epoch_micros: Option<i64>,
    projection_dlq_backlog: i64,
}

#[cfg(feature = "domain-settings")]
async fn observe_projection_tenant_gauges(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: vocab::TenantId,
    clock: &dyn Clock,
    gauges: &mut ProjectionSweepGaugeAcc,
) {
    if gauges.observe_failed || !gauges.observed_tenants.insert(tenant) {
        return;
    }
    match load_projection_tenant_observation(worker, target, tenant).await {
        Ok(observation) => accumulate_projection_tenant_observation(gauges, clock, observation),
        Err(error) => {
            tracing::warn!(
                error = %error,
                tenant = %tenant,
                projection_id = target.projection_id(),
                target_generation = target.target_generation(),
                "projection worker tenant observation failed"
            );
            gauges.observe_failed = true;
        }
    }
}

#[cfg(feature = "domain-settings")]
async fn load_projection_tenant_observation(
    worker: &VerifiedPgProjectionWorkerStore,
    target: &ProjectionWorkerTarget,
    tenant: vocab::TenantId,
) -> Result<ProjectionTenantObservation, PgProjectionWorkerRuntimeError> {
    tokio::time::timeout(PROJECTION_WORKER_SHORT_OPERATION_TIMEOUT, async {
        let mut tx = worker.0.pool.begin().await?;
        crate::cotx::set_local_tenant(&mut tx, tenant).await?;
        let row: (Option<i64>, Option<i64>, Option<i64>, i64) =
            sqlx::query_as(PROJECTION_WORKER_OBSERVE_TENANT_SQL)
                .bind(tenant.to_string())
                .bind(target.projection_id())
                .bind(target.target_generation())
                .bind(target.definition_version())
                .bind(target.definition_schema_digest())
                .bind(target.input_generation())
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(ProjectionTenantObservation {
            source_high_water: row.0,
            checkpoint_offset_lsn: row.1,
            checkpoint_updated_at_epoch_micros: row.2,
            projection_dlq_backlog: row.3,
        })
    })
    .await
    .map_err(|_| PgProjectionWorkerRuntimeError::TenantObservationTimeout)?
    .map_err(PgProjectionWorkerRuntimeError::TenantObservation)
}

#[cfg(feature = "domain-settings")]
fn accumulate_projection_tenant_observation(
    gauges: &mut ProjectionSweepGaugeAcc,
    clock: &dyn Clock,
    observation: ProjectionTenantObservation,
) {
    // Mirror worker source/checkpoint: missing high-water (no events) and missing checkpoint
    // (never saved) both behave as offset 0 for lag math.
    let high_water = observation.source_high_water.unwrap_or(0);
    let checkpoint = observation.checkpoint_offset_lsn.unwrap_or(0);
    let lag = i64::max(high_water - checkpoint, 0) as f64;
    gauges.max_lag = gauges.max_lag.max(lag);
    gauges.sum_dlq += observation.projection_dlq_backlog.max(0) as f64;
    // Missing/invalid updated_at stays absent — emit path exports NaN, never freshness=0.
    if let Some(age) = observation
        .checkpoint_updated_at_epoch_micros
        .and_then(|updated| checkpoint_freshness_seconds(clock, updated))
    {
        gauges.max_freshness_secs = Some(gauges.max_freshness_secs.map_or(age, |max| max.max(age)));
    }
}

#[cfg(feature = "domain-settings")]
fn checkpoint_freshness_seconds(clock: &dyn Clock, updated_at_epoch_micros: i64) -> Option<f64> {
    let updated_at_epoch_micros = u64::try_from(updated_at_epoch_micros).ok()?;
    let updated_at = UNIX_EPOCH + Duration::from_micros(updated_at_epoch_micros);
    clock
        .now()
        .duration_since(updated_at)
        .ok()
        .map(|age| age.as_secs_f64())
}

#[cfg(feature = "domain-settings")]
fn emit_projection_sweep_gauges(
    metric_ctx: &ProjectionWorkerMetricCtx<'_>,
    gauges: &ProjectionSweepGaugeAcc,
) {
    let (lag, freshness, dlq) = projection_sweep_gauge_values(gauges);
    metric_ctx.metrics.record_lag(metric_ctx.scope, lag);
    metric_ctx
        .metrics
        .record_checkpoint_freshness(metric_ctx.scope, freshness);
    metric_ctx.metrics.record_dlq_backlog(metric_ctx.scope, dlq);
}

/// Incomplete sweeps force the NaN triple; complete sweeps keep accumulated finite values.
#[cfg(feature = "domain-settings")]
fn seal_projection_sweep_completeness(complete: bool, gauges: &mut ProjectionSweepGaugeAcc) {
    if !complete {
        gauges.observe_failed = true;
    }
}

/// Shared emit decision for lag / freshness / dlq (NaN when observation failed or incomplete).
#[cfg(feature = "domain-settings")]
fn projection_sweep_gauge_values(gauges: &ProjectionSweepGaugeAcc) -> (f64, f64, f64) {
    if gauges.observe_failed {
        (f64::NAN, f64::NAN, f64::NAN)
    } else {
        (
            gauges.max_lag,
            gauges.max_freshness_secs.unwrap_or(f64::NAN),
            gauges.sum_dlq,
        )
    }
}

#[cfg(feature = "domain-settings")]
fn record_projection_run_metrics(
    metric_ctx: &ProjectionWorkerMetricCtx<'_>,
    run: &eventexec::ProjectionRun,
) {
    use eventexec::ProjectionProcessedOutcome::{
        Applied, DeadLettered, Duplicate, Filtered, Skipped,
    };

    metric_ctx
        .metrics
        .record_processed_events(metric_ctx.scope, Applied, run.applied as u64);
    metric_ctx
        .metrics
        .record_processed_events(metric_ctx.scope, Duplicate, run.duplicates as u64);
    metric_ctx
        .metrics
        .record_processed_events(metric_ctx.scope, Filtered, run.filtered as u64);
    metric_ctx
        .metrics
        .record_processed_events(metric_ctx.scope, Skipped, run.skipped as u64);
    metric_ctx.metrics.record_processed_events(
        metric_ctx.scope,
        DeadLettered,
        run.dead_lettered as u64,
    );

    if let Some(reason) = projection_stop_apply_failure_reason(&run.stop) {
        metric_ctx
            .metrics
            .record_apply_failure(metric_ctx.scope, reason);
    }
}

#[cfg(feature = "domain-settings")]
const fn projection_stop_apply_failure_reason(
    stop: &eventexec::ProjectionStop,
) -> Option<consistency::ProjectionApplyErrorReason> {
    match *stop {
        eventexec::ProjectionStop::ApplyFailed { reason, .. }
        | eventexec::ProjectionStop::PoisonSkipped { reason, .. } => Some(reason),
        eventexec::ProjectionStop::OutOfOrder { .. } => {
            Some(consistency::ProjectionApplyErrorReason::OutOfOrder)
        }
        _ => None,
    }
}

#[cfg(feature = "domain-settings")]
fn classify_projection_tenant_quantum(
    run: &eventexec::ProjectionRun,
    batch_limit: consistency::ProjectionBatchLimit,
) -> Result<ProjectionTenantRun, PgProjectionWorkerRuntimeError> {
    match run.stop {
        eventexec::ProjectionStop::Completed | eventexec::ProjectionStop::PoisonSkipped { .. } => {
            Ok(completed_projection_quantum(run.scanned, batch_limit))
        }
        eventexec::ProjectionStop::Fenced => Ok(ProjectionTenantRun::Fenced),
        eventexec::ProjectionStop::CheckpointUnsaved
        | eventexec::ProjectionStop::CheckpointUnread
        | eventexec::ProjectionStop::DeadLetterUnsaved { .. }
        | eventexec::ProjectionStop::ApplyFailed {
            kind:
                consistency::ProjectionApplyErrorKind::Transient
                | consistency::ProjectionApplyErrorKind::CommitUnknown,
            ..
        }
        | eventexec::ProjectionStop::SourceReadFailed {
            kind: consistency::EngineErrorKind::Transient,
        } => {
            log_projection_tenant_retry(&run.stop);
            Ok(ProjectionTenantRun::Retryable)
        }
        eventexec::ProjectionStop::ApplyFailed {
            failed_at,
            kind,
            reason,
        } => {
            log_projection_tenant_fatal(&run.stop);
            if reason.kind() != kind {
                return Err(PgProjectionWorkerRuntimeError::FatalProjection);
            }
            let reason = ProjectionTenantFatalReason::from_apply(reason)
                .ok_or(PgProjectionWorkerRuntimeError::FatalProjection)?;
            Ok(ProjectionTenantRun::Quarantined(ProjectionTenantFatal {
                reason,
                failed_lsn: failed_at,
            }))
        }
        eventexec::ProjectionStop::OutOfOrder { failed_at } => {
            log_projection_tenant_fatal(&run.stop);
            Ok(ProjectionTenantRun::Quarantined(ProjectionTenantFatal {
                reason: ProjectionTenantFatalReason::SourceOutOfOrder,
                failed_lsn: failed_at,
            }))
        }
        eventexec::ProjectionStop::SourceReadFailed { .. } => {
            log_projection_tenant_fatal(&run.stop);
            Err(PgProjectionWorkerRuntimeError::FatalProjection)
        }
    }
}

#[cfg(feature = "domain-settings")]
fn completed_projection_quantum(
    scanned: usize,
    batch_limit: consistency::ProjectionBatchLimit,
) -> ProjectionTenantRun {
    if scanned >= usize::try_from(batch_limit.get()).unwrap_or(usize::MAX) {
        ProjectionTenantRun::MoreWork
    } else {
        ProjectionTenantRun::Clean
    }
}

#[cfg(feature = "domain-settings")]
fn log_projection_tenant_retry(stop: &eventexec::ProjectionStop) {
    tracing::warn!(stop = ?stop, "settings projection worker tenant batch will retry");
}

#[cfg(feature = "domain-settings")]
fn log_projection_tenant_fatal(stop: &eventexec::ProjectionStop) {
    tracing::error!(stop = ?stop, "settings projection worker tenant batch stopped fatally");
}

#[cfg(all(test, feature = "domain-settings"))]
mod projection_worker_tests {
    use super::*;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use std::collections::{HashMap, VecDeque};

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn lazy_projection_store() -> Arc<PgStore> {
        let pool = PgPoolOptions::new().max_connections(1).connect_lazy_with(
            PgConnectOptions::new()
                .host("127.0.0.1")
                .port(5999)
                .database("rss_test")
                .username("u")
                .password("p"),
        );
        Arc::new(PgStore { pool })
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::expect_used)]
    fn test_projection_metric_scope() -> eventexec::ProjectionMetricScope {
        let projection = eventexec::ProjectionId::parse(crate::SETTINGS_PROJECTION_ID)
            .expect("settings projection id");
        let generation =
            eventexec::ProjectionVersion::parse("v3").expect("settings target generation");
        eventexec::WorkflowRuntimePlan::generated_projection_runtime_binding_fixture(
            &projection,
            &generation,
        )
        .expect("generated projection runtime binding fixture")
        .metric_scope()
    }

    #[test]
    fn projection_worker_observe_tenant_sql_binds_six_parameters() {
        let sql = PROJECTION_WORKER_OBSERVE_TENANT_SQL;
        for n in 1..=6 {
            assert!(
                sql.contains(&format!("${n}")),
                "observe SQL must bind ${n}: {sql}"
            );
        }
        assert!(
            sql.contains("rss_projection_worker_observe_tenant"),
            "observe SQL must call the worker observe function"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn full_quantum_yields_to_the_next_tenant() {
        let run = eventexec::ProjectionRun {
            scanned: 1,
            applied: 1,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: eventexec::ProjectionStop::Completed,
        };
        assert!(matches!(
            classify_projection_tenant_quantum(
                &run,
                consistency::ProjectionBatchLimit::new(1).expect("one event quantum")
            ),
            Ok(ProjectionTenantRun::MoreWork)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn tenant_quantum_preserves_retryable_and_fatal_stop_policy() {
        let run = |kind, reason| eventexec::ProjectionRun {
            scanned: 1,
            applied: 0,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: eventexec::ProjectionStop::ApplyFailed {
                failed_at: consistency::Lsn::new(1),
                kind,
                reason,
            },
        };
        let limit = consistency::ProjectionBatchLimit::new(1).expect("one event quantum");
        assert!(matches!(
            classify_projection_tenant_quantum(
                &run(
                    consistency::ProjectionApplyErrorKind::Transient,
                    consistency::ProjectionApplyErrorReason::Transient,
                ),
                limit,
            ),
            Ok(ProjectionTenantRun::Retryable)
        ));
        assert!(matches!(
            classify_projection_tenant_quantum(
                &run(
                    consistency::ProjectionApplyErrorKind::Permanent,
                    consistency::ProjectionApplyErrorReason::ProviderPermanent,
                ),
                limit,
            ),
            Ok(ProjectionTenantRun::Quarantined(ProjectionTenantFatal {
                reason: ProjectionTenantFatalReason::ProviderPermanent,
                failed_lsn,
            })) if failed_lsn == consistency::Lsn::new(1)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn fencing_is_normal_contention_not_retryable_degradation() {
        let run = eventexec::ProjectionRun {
            scanned: 1,
            applied: 1,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: eventexec::ProjectionStop::Fenced,
        };
        let outcome = classify_projection_tenant_quantum(
            &run,
            consistency::ProjectionBatchLimit::new(1).expect("one event quantum"),
        );
        assert!(matches!(outcome, Ok(ProjectionTenantRun::Fenced)));
    }

    #[test]
    fn projection_stop_apply_failure_reason_is_closed_and_skips_completed() {
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::Completed),
            None
        );
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::Fenced),
            None
        );
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::CheckpointUnsaved),
            None
        );
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::OutOfOrder {
                failed_at: consistency::Lsn::new(3),
            }),
            Some(consistency::ProjectionApplyErrorReason::OutOfOrder)
        );
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::ApplyFailed {
                failed_at: consistency::Lsn::new(3),
                kind: consistency::ProjectionApplyErrorKind::Permanent,
                reason: consistency::ProjectionApplyErrorReason::PayloadMalformed,
            }),
            Some(consistency::ProjectionApplyErrorReason::PayloadMalformed)
        );
        assert_eq!(
            projection_stop_apply_failure_reason(&eventexec::ProjectionStop::PoisonSkipped {
                skipped_at: consistency::Lsn::new(3),
                kind: consistency::ProjectionApplyErrorKind::Permanent,
                reason: consistency::ProjectionApplyErrorReason::PayloadMalformed,
            }),
            Some(consistency::ProjectionApplyErrorReason::PayloadMalformed)
        );
    }

    #[test]
    fn observation_accumulates_max_lag_freshness_and_sum_dlq() {
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1_700_000_100));
        let mut gauges = ProjectionSweepGaugeAcc::default();
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: Some(100),
                checkpoint_offset_lsn: Some(40),
                checkpoint_updated_at_epoch_micros: Some(1_700_000_000_i64 * 1_000_000),
                projection_dlq_backlog: 2,
            },
        );
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: Some(50),
                checkpoint_offset_lsn: Some(45),
                checkpoint_updated_at_epoch_micros: Some(1_700_000_050_i64 * 1_000_000),
                projection_dlq_backlog: 3,
            },
        );
        assert_eq!(gauges.max_lag, 60.0);
        assert_eq!(gauges.max_freshness_secs, Some(100.0));
        assert_eq!(gauges.sum_dlq, 5.0);
    }

    #[test]
    fn observation_hw_behind_checkpoint_is_zero_lag_and_negative_dlq_ignored() {
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1_700_000_100));
        let mut gauges = ProjectionSweepGaugeAcc::default();
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: Some(10),
                checkpoint_offset_lsn: Some(40),
                checkpoint_updated_at_epoch_micros: Some(1_700_000_000_i64 * 1_000_000),
                projection_dlq_backlog: -5,
            },
        );
        assert_eq!(gauges.max_lag, 0.0);
        assert_eq!(gauges.sum_dlq, 0.0);
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: Some(50),
                checkpoint_offset_lsn: Some(40),
                checkpoint_updated_at_epoch_micros: None,
                projection_dlq_backlog: 4,
            },
        );
        assert_eq!(gauges.max_lag, 10.0);
        assert_eq!(gauges.sum_dlq, 4.0, "negative dlq must not reduce the sum");
        assert_eq!(gauges.max_freshness_secs, Some(100.0));
    }

    #[test]
    fn observation_empty_high_water_and_checkpoint_lag_is_zero_without_fake_freshness() {
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1_700_000_100));
        let mut gauges = ProjectionSweepGaugeAcc::default();
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: None,
                checkpoint_offset_lsn: None,
                checkpoint_updated_at_epoch_micros: None,
                projection_dlq_backlog: 0,
            },
        );
        assert_eq!(gauges.max_lag, 0.0);
        assert_eq!(gauges.max_freshness_secs, None);
        assert!(!gauges.observe_failed);
        accumulate_projection_tenant_observation(
            &mut gauges,
            &clock,
            ProjectionTenantObservation {
                source_high_water: Some(80),
                checkpoint_offset_lsn: None,
                checkpoint_updated_at_epoch_micros: None,
                projection_dlq_backlog: 1,
            },
        );
        assert_eq!(gauges.max_lag, 80.0);
        assert_eq!(gauges.max_freshness_secs, None);
        assert_eq!(gauges.sum_dlq, 1.0);
    }

    #[derive(Default)]
    struct RecordingProjectionMetrics {
        lag: std::sync::Mutex<Option<f64>>,
        freshness: std::sync::Mutex<Option<f64>>,
        dlq: std::sync::Mutex<Option<f64>>,
        processed: std::sync::Mutex<Vec<(eventexec::ProjectionProcessedOutcome, u64)>>,
        apply_failures: std::sync::Mutex<Vec<consistency::ProjectionApplyErrorReason>>,
    }

    impl RecordingProjectionMetrics {
        fn record_sample(&self, gauges: &ProjectionSweepGaugeAcc) {
            let (lag, freshness, dlq) = projection_sweep_gauge_values(gauges);
            *self
                .lag
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lag);
            *self
                .freshness
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(freshness);
            *self
                .dlq
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(dlq);
        }

        fn lag(&self) -> Option<f64> {
            *self
                .lag
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn freshness(&self) -> Option<f64> {
            *self
                .freshness
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn dlq(&self) -> Option<f64> {
            *self
                .dlq
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        #[cfg(feature = "test-support")]
        fn processed(&self) -> Vec<(eventexec::ProjectionProcessedOutcome, u64)> {
            self.processed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        #[cfg(feature = "test-support")]
        fn apply_failures(&self) -> Vec<consistency::ProjectionApplyErrorReason> {
            self.apply_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl eventexec::ProjectionMetrics for RecordingProjectionMetrics {
        fn record_lag(&self, _scope: &eventexec::ProjectionMetricScope, lag: f64) {
            *self
                .lag
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lag);
        }

        fn record_checkpoint_freshness(
            &self,
            _scope: &eventexec::ProjectionMetricScope,
            age_seconds: f64,
        ) {
            *self
                .freshness
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(age_seconds);
        }

        fn record_apply_failure(
            &self,
            _scope: &eventexec::ProjectionMetricScope,
            reason: consistency::ProjectionApplyErrorReason,
        ) {
            self.apply_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(reason);
        }

        fn record_dlq_backlog(&self, _scope: &eventexec::ProjectionMetricScope, depth: f64) {
            *self
                .dlq
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(depth);
        }

        fn record_processed_events(
            &self,
            _scope: &eventexec::ProjectionMetricScope,
            outcome: eventexec::ProjectionProcessedOutcome,
            count: u64,
        ) {
            self.processed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((outcome, count));
        }
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn record_projection_run_metrics_records_outcomes_and_apply_failure() {
        use eventexec::ProjectionProcessedOutcome::{
            Applied, DeadLettered, Duplicate, Filtered, Skipped,
        };

        let metrics = RecordingProjectionMetrics::default();
        let scope = test_projection_metric_scope();
        let clock = FixedClock(UNIX_EPOCH);
        let metric_ctx = ProjectionWorkerMetricCtx {
            metrics: &metrics,
            scope: &scope,
            clock: &clock,
        };
        let failed = eventexec::ProjectionRun {
            scanned: 15,
            applied: 5,
            duplicates: 4,
            filtered: 3,
            skipped: 2,
            dead_lettered: 1,
            stop: eventexec::ProjectionStop::ApplyFailed {
                failed_at: consistency::Lsn::new(9),
                kind: consistency::ProjectionApplyErrorKind::Permanent,
                reason: consistency::ProjectionApplyErrorReason::PayloadMalformed,
            },
        };
        record_projection_run_metrics(&metric_ctx, &failed);
        assert_eq!(
            metrics.processed(),
            vec![
                (Applied, 5),
                (Duplicate, 4),
                (Filtered, 3),
                (Skipped, 2),
                (DeadLettered, 1),
            ]
        );
        assert_eq!(
            metrics.apply_failures(),
            vec![consistency::ProjectionApplyErrorReason::PayloadMalformed]
        );

        let completed_metrics = RecordingProjectionMetrics::default();
        let completed_ctx = ProjectionWorkerMetricCtx {
            metrics: &completed_metrics,
            scope: &scope,
            clock: &clock,
        };
        let completed = eventexec::ProjectionRun {
            scanned: 5,
            applied: 5,
            duplicates: 0,
            filtered: 0,
            skipped: 0,
            dead_lettered: 0,
            stop: eventexec::ProjectionStop::Completed,
        };
        record_projection_run_metrics(&completed_ctx, &completed);
        assert!(
            completed_metrics.apply_failures().is_empty(),
            "Completed must not record apply failure"
        );
        assert_eq!(
            completed_metrics.processed(),
            vec![
                (Applied, 5),
                (Duplicate, 0),
                (Filtered, 0),
                (Skipped, 0),
                (DeadLettered, 0),
            ]
        );
    }

    #[test]
    fn projection_sweep_gauge_observe_failed_emits_nan_triple() {
        let metrics = RecordingProjectionMetrics::default();
        let gauges = ProjectionSweepGaugeAcc {
            observe_failed: true,
            max_lag: 9.0,
            max_freshness_secs: Some(3.0),
            sum_dlq: 4.0,
            observed_tenants: HashSet::new(),
        };
        metrics.record_sample(&gauges);
        assert!(metrics.lag().expect("lag").is_nan());
        assert!(metrics.freshness().expect("freshness").is_nan());
        assert!(metrics.dlq().expect("dlq").is_nan());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn projection_sweep_gauge_incomplete_drop_emits_nan_not_zero_or_stale() {
        let metrics = RecordingProjectionMetrics::default();
        let scope = test_projection_metric_scope();
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1));
        let metric_ctx = ProjectionWorkerMetricCtx {
            metrics: &metrics,
            scope: &scope,
            clock: &clock,
        };
        {
            let _sweep = ProjectionSweepGaugeEmit {
                metric_ctx: &metric_ctx,
                gauges: ProjectionSweepGaugeAcc {
                    observe_failed: false,
                    max_lag: 12.0,
                    max_freshness_secs: Some(5.0),
                    sum_dlq: 7.0,
                    observed_tenants: HashSet::new(),
                },
                complete: false,
            };
        }
        assert!(metrics.lag().expect("lag").is_nan());
        assert!(metrics.freshness().expect("freshness").is_nan());
        assert!(metrics.dlq().expect("dlq").is_nan());
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn projection_sweep_gauge_complete_emits_finite_with_freshness_nan_when_absent() {
        let metrics = RecordingProjectionMetrics::default();
        let scope = test_projection_metric_scope();
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1));
        let metric_ctx = ProjectionWorkerMetricCtx {
            metrics: &metrics,
            scope: &scope,
            clock: &clock,
        };
        {
            let mut sweep = ProjectionSweepGaugeEmit {
                metric_ctx: &metric_ctx,
                gauges: ProjectionSweepGaugeAcc::default(),
                complete: true,
            };
            accumulate_projection_tenant_observation(
                &mut sweep.gauges,
                &clock,
                ProjectionTenantObservation {
                    source_high_water: Some(100),
                    checkpoint_offset_lsn: Some(40),
                    checkpoint_updated_at_epoch_micros: None,
                    projection_dlq_backlog: 2,
                },
            );
            accumulate_projection_tenant_observation(
                &mut sweep.gauges,
                &clock,
                ProjectionTenantObservation {
                    source_high_water: Some(50),
                    checkpoint_offset_lsn: Some(45),
                    checkpoint_updated_at_epoch_micros: None,
                    projection_dlq_backlog: -3,
                },
            );
        }
        assert_eq!(metrics.lag().expect("lag"), 60.0);
        assert!(metrics.freshness().expect("freshness").is_nan());
        assert_eq!(metrics.dlq().expect("dlq"), 2.0);
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn projection_sweep_gauge_complete_aggregates_max_max_sum() {
        let metrics = RecordingProjectionMetrics::default();
        let scope = test_projection_metric_scope();
        let clock = FixedClock(UNIX_EPOCH + Duration::from_secs(1_700_000_100));
        let metric_ctx = ProjectionWorkerMetricCtx {
            metrics: &metrics,
            scope: &scope,
            clock: &clock,
        };
        {
            let mut sweep = ProjectionSweepGaugeEmit {
                metric_ctx: &metric_ctx,
                gauges: ProjectionSweepGaugeAcc::default(),
                complete: true,
            };
            accumulate_projection_tenant_observation(
                &mut sweep.gauges,
                &clock,
                ProjectionTenantObservation {
                    source_high_water: Some(100),
                    checkpoint_offset_lsn: Some(40),
                    checkpoint_updated_at_epoch_micros: Some(1_700_000_000_i64 * 1_000_000),
                    projection_dlq_backlog: 2,
                },
            );
            accumulate_projection_tenant_observation(
                &mut sweep.gauges,
                &clock,
                ProjectionTenantObservation {
                    source_high_water: Some(50),
                    checkpoint_offset_lsn: Some(45),
                    checkpoint_updated_at_epoch_micros: Some(1_700_000_050_i64 * 1_000_000),
                    projection_dlq_backlog: 3,
                },
            );
        }
        assert_eq!(metrics.lag().expect("lag"), 60.0);
        assert_eq!(metrics.freshness().expect("freshness"), 100.0);
        assert_eq!(metrics.dlq().expect("dlq"), 5.0);
    }

    #[test]
    fn permanent_catalog_failure_is_global_fatal() {
        assert_eq!(
            crate::tx_retry::classify_sqlstate(Some("42501")),
            consistency::TxRetryClass::Permanent
        );
        assert!(!projection_startup_observation_is_retryable(
            &PgProjectionWorkerRuntimeError::TenantCatalog(sqlx::Error::PoolClosed)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn more_work_round_robin_is_fair_and_deadline_bounded() {
        let first =
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("first tenant");
        let second =
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000002").expect("second tenant");
        let mut visits = Vec::new();
        let mut counts = HashMap::new();
        let degraded = drive_projection_round_robin(
            VecDeque::from([first, second]),
            tokio::time::Instant::now() + PROJECTION_WORKER_BATCH_BUDGET,
            &CancellationToken::new(),
            |tenant| {
                visits.push(tenant);
                let count = counts.entry(tenant).or_insert(0_u8);
                *count += 1;
                std::future::ready(Ok(if *count == 1 {
                    ProjectionTenantRun::MoreWork
                } else {
                    ProjectionTenantRun::Clean
                }))
            },
        )
        .await
        .expect("round robin sweep");
        assert!(!degraded);
        assert_eq!(visits, vec![first, second, first, second]);

        let mut overdue_visits = 0_u8;
        let degraded = drive_projection_round_robin(
            VecDeque::from([first]),
            tokio::time::Instant::now(),
            &CancellationToken::new(),
            |_| {
                overdue_visits += 1;
                std::future::ready(Ok(ProjectionTenantRun::MoreWork))
            },
        )
        .await
        .expect("expired sweep");
        assert!(!degraded);
        assert_eq!(overdue_visits, 0, "expired budget must not start a quantum");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn round_robin_observes_cancellation_before_next_quantum() {
        let tenant =
            vocab::TenantId::parse("00000000-0000-4000-8000-000000000001").expect("tenant");
        let token = CancellationToken::new();
        token.cancel();
        let mut visits = 0_u8;
        drive_projection_round_robin(
            VecDeque::from([tenant]),
            tokio::time::Instant::now() + PROJECTION_WORKER_BATCH_BUDGET,
            &token,
            |_| {
                visits += 1;
                std::future::ready(Ok(ProjectionTenantRun::MoreWork))
            },
        )
        .await
        .expect("cancelled sweep");
        assert_eq!(visits, 0);

        let token = CancellationToken::new();
        let mut visits = 0_u8;
        drive_projection_round_robin(
            VecDeque::from([tenant]),
            tokio::time::Instant::now() + PROJECTION_WORKER_BATCH_BUDGET,
            &token,
            |_| {
                visits += 1;
                token.cancel();
                std::future::ready(Ok(ProjectionTenantRun::MoreWork))
            },
        )
        .await
        .expect("cancel after admitted quantum");
        assert_eq!(visits, 1, "admitted quantum completes but is not requeued");
    }

    #[test]
    fn health_distinguishes_startup_observation_from_runtime_failure() {
        let health = eventexec::WorkerHealth::starting();
        record_projection_worker_health(&health, false);
        assert_eq!(health.status(), primitives::HealthStatus::Healthy);
        record_projection_worker_health(&health, true);
        assert_eq!(health.status(), primitives::HealthStatus::Degraded);
    }

    #[test]
    fn shutdown_budgets_reserve_pool_fence_before_total_drain() {
        assert!(PROJECTION_WORKER_BATCH_BUDGET < PROJECTION_WORKER_JOIN_TIMEOUT);
        assert!(
            PROJECTION_WORKER_JOIN_TIMEOUT + PROJECTION_WORKER_POOL_FENCE_BUDGET
                < PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT
        );
        assert!(PROJECTION_WORKER_RESOURCE_SHUTDOWN_TIMEOUT < Duration::from_secs(60));
    }

    #[tokio::test]
    async fn shutdown_fences_pool_after_join() {
        let store = lazy_projection_store();
        let worker = eventexec::ManagedBlockingWorker::spawn(
            "projection-worker-shutdown-test",
            CancellationToken::new(),
            Arc::new(eventexec::WorkerHealth::starting()),
            Duration::from_secs(1),
            |token| {
                while !token.is_cancelled() {
                    std::thread::yield_now();
                }
                Ok(())
            },
        );
        let resource = PgProjectionWorkerRuntime {
            worker,
            store: VerifiedPgProjectionWorkerStore(Arc::clone(&store)),
        };
        resource
            .shutdown()
            .await
            .expect("projection worker shutdown");
        assert!(store.pool.is_closed(), "worker pool must be fenced closed");
    }
}
