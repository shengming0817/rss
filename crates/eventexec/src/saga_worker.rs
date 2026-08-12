//! Saga background worker + readyz health state.
//!
//! The worker is intentionally a thin poll/orchestrate layer. Work discovery is advisory and all
//! correctness remains in [`crate::SagaExecutor`] plus the single fenced durable store.

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use consistency::SagaInstanceStatus;
use diport::{
    ManagedResource, SagaDurableStore, SagaDurableStoreError, SagaRunnableInstance,
    SagaTenantCursor, SagaTenantSource, SagaWorkerIdentity,
};
use primitives::ProbeName;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::relay::WorkerHealth;
use crate::{SagaExecutor, SagaInterruption, SagaOutcome};

/// readyz probe base name for saga executor workers.
pub const SAGA_EXECUTOR_PROBE: &str = "saga_executor";

const SAGA_WORKER_NAME: &str = "saga-executor";
const SAGA_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_TENANT_BATCH_SIZE: usize = 128;
const DEFAULT_BATCH_SIZE: usize = 16;

/// Saga worker polling configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaWorkerConfig {
    poll_interval_ms: NonZeroU64,
    tenant_batch_size: NonZeroUsize,
    batch_size: NonZeroUsize,
}

impl SagaWorkerConfig {
    /// Build a config from non-zero values.
    pub fn new(
        poll_interval_ms: NonZeroU64,
        tenant_batch_size: NonZeroUsize,
        batch_size: NonZeroUsize,
    ) -> Self {
        Self {
            poll_interval_ms,
            tenant_batch_size,
            batch_size,
        }
    }

    /// Poll interval.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms.get())
    }

    /// Tenant source batch size.
    pub fn tenant_batch_size(&self) -> NonZeroUsize {
        self.tenant_batch_size
    }

    /// Per-tenant runnable instance batch size.
    pub fn batch_size(&self) -> NonZeroUsize {
        self.batch_size
    }
}

impl Default for SagaWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: nonzero_u64(DEFAULT_POLL_INTERVAL_MS),
            tenant_batch_size: nonzero_usize(DEFAULT_TENANT_BATCH_SIZE),
            batch_size: nonzero_usize(DEFAULT_BATCH_SIZE),
        }
    }
}

/// Worker handle adopted by bootstrap shutdown.
pub struct SagaWorker {
    name: String,
    inner: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    health: Arc<WorkerHealth>,
    token: CancellationToken,
}

impl SagaWorker {
    fn adopt(
        name: String,
        handle: JoinHandle<()>,
        health: Arc<WorkerHealth>,
        token: CancellationToken,
    ) -> Self {
        Self {
            name,
            inner: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
            health,
            token,
        }
    }

    /// Worker health shared with readyz probes.
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }
}

impl ManagedResource for SagaWorker {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        if let Some(handle) = self.inner.lock().await.take() {
            handle
                .join()
                .await
                .map_err(diport::ShutdownError::from_join_error)?;
        }
        Ok(())
    }

    fn shutdown_timeout(&self) -> Duration {
        SAGA_WORKER_SHUTDOWN_TIMEOUT
    }
}

/// Complete, non-optional dependency set for one activated Saga worker.
pub struct SagaWorkerRuntime<T, S, E> {
    identity: SagaWorkerIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    executor: Arc<E>,
    clock: Arc<dyn diport::Clock>,
    config: SagaWorkerConfig,
    admission: primitives::WriteAdmission,
}

impl<T, S, E> SagaWorkerRuntime<T, S, E>
where
    T: SagaTenantSource + Send + Sync + 'static,
    S: SagaDurableStore + Send + Sync + 'static,
    E: SagaExecutor + Send + Sync + 'static,
{
    /// Bind every runtime dependency before the worker can enter lifecycle ownership.
    pub fn new(
        identity: SagaWorkerIdentity,
        tenant_source: Arc<T>,
        durable_store: Arc<S>,
        executor: Arc<E>,
        clock: Arc<dyn diport::Clock>,
        config: SagaWorkerConfig,
        admission: primitives::WriteAdmission,
    ) -> Self {
        Self {
            identity,
            tenant_source,
            durable_store,
            executor,
            clock,
            config,
            admission,
        }
    }

    /// Spawn the bound Saga worker on the current Tokio runtime.
    pub fn spawn(self, token: CancellationToken, health: Arc<WorkerHealth>) -> SagaWorker {
        let Self {
            identity,
            tenant_source,
            durable_store,
            executor,
            clock,
            config,
            admission,
        } = self;
        let worker_name = saga_worker_name(&identity);
        let task_token = token.clone();
        let task_health = health.clone();
        let handle = tokio::spawn(async move {
            saga_worker_loop(
                SagaWorkerRuntime::new(
                    identity,
                    tenant_source,
                    durable_store,
                    executor,
                    clock,
                    config,
                    admission,
                ),
                task_token,
                task_health,
            )
            .await;
        });
        SagaWorker::adopt(worker_name, handle, health, token)
    }
}

async fn saga_worker_loop<T, S, E>(
    runtime: SagaWorkerRuntime<T, S, E>,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    T: SagaTenantSource + Send + Sync + 'static,
    S: SagaDurableStore + Send + Sync + 'static,
    E: SagaExecutor + Send + Sync + 'static,
{
    let SagaWorkerRuntime {
        identity,
        tenant_source,
        durable_store,
        executor,
        clock,
        config,
        admission,
    } = runtime;
    let _stopped_guard = health.stopped_on_exit();
    let mut ticker = tokio::time::interval(config.poll_interval());
    let mut health_projection = SagaWorkerHealthProjection::default();
    let mut tenant_cursor = None;
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                let Ok(_permit) = admission.try_enter() else {
                    continue;
                };
                let tick = saga_worker_tick(
                    &identity,
                    tenant_source.as_ref(),
                    durable_store.as_ref(),
                    executor.as_ref(),
                    clock.as_ref(),
                    config,
                    &mut tenant_cursor,
                )
                .await;
                health_projection.apply(tick, &health);
            }
        }
    }
}

/// Build the per-contract readyz probe name.
pub fn saga_executor_probe_name(
    identity: &SagaWorkerIdentity,
) -> Result<ProbeName, primitives::ProbeNameError> {
    ProbeName::parse(&format!(
        "{SAGA_EXECUTOR_PROBE}:{}__{}",
        identity.owner(),
        contract_slug(identity.contract_id().as_str())
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SagaWorkerTick {
    Clean,
    TransientDegraded,
    PermanentDegraded,
}

impl SagaWorkerTick {
    fn worse(self, other: Self) -> Self {
        match (self, other) {
            (Self::PermanentDegraded, _) | (_, Self::PermanentDegraded) => Self::PermanentDegraded,
            (Self::TransientDegraded, _) | (_, Self::TransientDegraded) => Self::TransientDegraded,
            (Self::Clean, Self::Clean) => Self::Clean,
        }
    }
}

#[derive(Default)]
struct SagaWorkerHealthProjection {
    permanently_degraded: bool,
}

impl SagaWorkerHealthProjection {
    fn apply(&mut self, tick: SagaWorkerTick, health: &WorkerHealth) {
        if tick == SagaWorkerTick::PermanentDegraded {
            self.permanently_degraded = true;
        }
        if self.permanently_degraded || tick == SagaWorkerTick::TransientDegraded {
            health.mark_degraded();
        } else {
            health.mark_healthy();
        }
    }
}

pub(crate) async fn saga_worker_tick<T, S, E>(
    identity: &SagaWorkerIdentity,
    tenant_source: &T,
    durable_store: &S,
    executor: &E,
    clock: &dyn diport::Clock,
    config: SagaWorkerConfig,
    tenant_cursor: &mut Option<SagaTenantCursor>,
) -> SagaWorkerTick
where
    T: SagaTenantSource + Send + Sync,
    S: SagaDurableStore + Send + Sync,
    E: SagaExecutor + Send + Sync,
{
    let page = match tenant_source
        .list_runnable_tenants(identity, *tenant_cursor, config.tenant_batch_size())
        .await
    {
        Ok(tenants) => tenants,
        Err(error) => {
            warn_worker_source_error(identity, "tenant_source", &error);
            return SagaWorkerTick::TransientDegraded;
        }
    };
    let (tenants, next) = page.into_parts();
    *tenant_cursor = next;
    let mut tick = match tenant_source.observe_unresolved(identity).await {
        Ok(observation) => {
            record_unresolved_metrics(identity, clock, Some(&observation));
            if observation.is_clear() {
                SagaWorkerTick::Clean
            } else {
                SagaWorkerTick::TransientDegraded
            }
        }
        Err(error) => {
            record_unresolved_metrics(identity, clock, None);
            warn_worker_source_error(identity, "tenant_source_unresolved", &error);
            SagaWorkerTick::TransientDegraded
        }
    };
    for tenant in tenants {
        tick = tick.worse(
            run_tenant_batch(
                identity,
                tenant,
                durable_store,
                executor,
                config.batch_size(),
            )
            .await,
        );
    }
    tick
}

fn record_unresolved_metrics(
    identity: &SagaWorkerIdentity,
    clock: &dyn diport::Clock,
    observation: Option<&diport::SagaUnresolvedObservation>,
) {
    let owner = identity.owner().to_owned();
    let contract = identity.contract_id().as_str().to_owned();
    let (operator_required, degraded, compensation_failed, oldest_age) = match observation {
        Some(observation) => (
            observation.operator_required() as f64,
            observation.degraded() as f64,
            observation.compensation_failed() as f64,
            observation
                .oldest_unresolved_at()
                .and_then(|oldest| clock.now().duration_since(oldest).ok())
                .map_or(0.0, |age| age.as_secs_f64()),
        ),
        None => (f64::NAN, f64::NAN, f64::NAN, f64::NAN),
    };
    for (state, value) in [
        ("operator_required", operator_required),
        ("degraded", degraded),
        ("compensation_failed", compensation_failed),
    ] {
        metrics::gauge!(
            "saga_unresolved_instances",
            "owner" => owner.clone(),
            "contract_id" => contract.clone(),
            "state" => state,
        )
        .set(value);
    }
    metrics::gauge!(
        "saga_unresolved_oldest_age_seconds",
        "owner" => owner,
        "contract_id" => contract,
    )
    .set(oldest_age);
}

async fn run_tenant_batch<S, E>(
    identity: &SagaWorkerIdentity,
    tenant: rss_request_context::TenantId,
    durable_store: &S,
    executor: &E,
    batch_size: NonZeroUsize,
) -> SagaWorkerTick
where
    S: SagaDurableStore + Send + Sync,
    E: SagaExecutor + Send + Sync,
{
    let rows = match durable_store
        .list_runnable(identity, tenant, batch_size)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warn_worker_source_error(identity, "durable_store", &error);
            return SagaWorkerTick::TransientDegraded;
        }
    };
    let mut tick = SagaWorkerTick::Clean;
    for row in rows {
        tick = tick.worse(run_one(identity, row, executor).await);
    }
    tick
}

async fn run_one<E>(
    expected_identity: &SagaWorkerIdentity,
    row: SagaRunnableInstance,
    executor: &E,
) -> SagaWorkerTick
where
    E: SagaExecutor + Send + Sync,
{
    if row.identity() != expected_identity {
        return SagaWorkerTick::PermanentDegraded;
    }
    let instance = row.instance();
    let definition = row.definition().clone();
    let outcome = match row.status() {
        SagaInstanceStatus::Ready
        | SagaInstanceStatus::Running
        | SagaInstanceStatus::Compensating => {
            executor
                .advance_registered(instance, definition.clone())
                .await
        }
        _ => return SagaWorkerTick::PermanentDegraded,
    };
    let tick = classify_outcome(outcome);
    if tick != SagaWorkerTick::Clean {
        tracing::warn!(
            tenant_id = %instance.tenant(),
            saga_id = %instance.saga_id().as_uuid(),
            contract_id = definition.contract_id(),
            definition_version = definition.version(),
            schema_digest = definition.schema_digest(),
            action_generation = definition.action_registry_generation(),
            degradation = ?tick,
            "saga worker instance degraded"
        );
    }
    tick
}

fn classify_outcome(outcome: SagaOutcome) -> SagaWorkerTick {
    match outcome {
        SagaOutcome::Failed { error, .. } if error.degrades_worker_permanently() => {
            SagaWorkerTick::PermanentDegraded
        }
        SagaOutcome::Interrupted { reason } if interruption_permanently_degrades(reason) => {
            SagaWorkerTick::PermanentDegraded
        }
        SagaOutcome::Interrupted { reason } if interruption_transiently_degrades(reason) => {
            SagaWorkerTick::TransientDegraded
        }
        _ => SagaWorkerTick::Clean,
    }
}

fn interruption_permanently_degrades(reason: SagaInterruption) -> bool {
    matches!(
        reason,
        SagaInterruption::JournalConflict
            | SagaInterruption::InstanceDegraded
            | SagaInterruption::UnsupportedDefinition
            | SagaInterruption::ReceiptUnavailable
    )
}

fn interruption_transiently_degrades(reason: SagaInterruption) -> bool {
    matches!(reason, SagaInterruption::StoreUnavailable)
}

fn warn_worker_source_error(
    identity: &SagaWorkerIdentity,
    source: &'static str,
    error: &SagaDurableStoreError,
) {
    tracing::warn!(
        owner = identity.owner(),
        contract_id = identity.contract_id().as_str(),
        source,
        error = %error,
        "saga worker source error"
    );
}

fn saga_worker_name(identity: &SagaWorkerIdentity) -> String {
    format!(
        "{SAGA_WORKER_NAME}-{}-{}",
        identity.owner(),
        contract_slug(identity.contract_id().as_str())
    )
}

fn contract_slug(contract_id: &str) -> String {
    contract_id.replace('.', "_")
}

fn nonzero_u64(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN)
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use consistency::{SagaId, SagaInstanceRecord, SagaInstanceRef, SagaLease, SagaLeaseOutcome};
    use diport::{
        SagaClaimOutcome, SagaClaimRequest, SagaContractId, SagaDurableMutation,
        SagaDurableMutationOutcome, SagaDurableStoreErrorKind, SagaInstanceRegistration,
        SagaLeaseTtl, SagaRecoveryOutcome, SagaRecoveryRequest, SagaTerminalReceiptOutcome,
        SagaTerminalReceiptRequest, SagaUnresolvedObservation,
    };
    use futures::future::BoxFuture;
    use primitives::healthz::HealthStatus;

    use super::*;

    fn clear_unresolved() -> SagaUnresolvedObservation {
        SagaUnresolvedObservation::new(0, 0, 0, None)
    }

    struct FakeTenantSource {
        tenants: Mutex<Result<Vec<rss_request_context::TenantId>, SagaDurableStoreError>>,
        unresolved: SagaUnresolvedObservation,
    }

    impl FakeTenantSource {
        fn with_tenants(tenants: Vec<rss_request_context::TenantId>) -> Self {
            Self {
                tenants: Mutex::new(Ok(tenants)),
                unresolved: clear_unresolved(),
            }
        }

        fn failing() -> Self {
            Self {
                tenants: Mutex::new(Err(store_error())),
                unresolved: clear_unresolved(),
            }
        }

        fn with_unresolved(unresolved: bool) -> Self {
            Self {
                tenants: Mutex::new(Ok(Vec::new())),
                unresolved: if unresolved {
                    SagaUnresolvedObservation::new(1, 0, 0, Some(std::time::UNIX_EPOCH))
                } else {
                    clear_unresolved()
                },
            }
        }
    }

    impl SagaTenantSource for FakeTenantSource {
        async fn list_runnable_tenants(
            &self,
            _identity: &SagaWorkerIdentity,
            cursor: Option<SagaTenantCursor>,
            limit: NonZeroUsize,
        ) -> Result<diport::SagaTenantPage, SagaDurableStoreError> {
            let mut tenants = self
                .tenants
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(Clone::clone)
                .map_err(|_| store_error())?;
            tenants.sort_by_key(|tenant| tenant.to_string());
            if let Some(cursor) = cursor {
                let after = cursor.tenant().to_string();
                tenants.retain(|tenant| tenant.to_string() > after);
            }
            let has_more = tenants.len() > limit.get();
            tenants.truncate(limit.get());
            let next = has_more
                .then(|| tenants.last().copied().map(SagaTenantCursor::new))
                .flatten();
            Ok(diport::SagaTenantPage::new(tenants, next))
        }

        async fn observe_unresolved(
            &self,
            _identity: &SagaWorkerIdentity,
        ) -> Result<SagaUnresolvedObservation, SagaDurableStoreError> {
            Ok(self.unresolved)
        }
    }

    struct FakeInstanceStore {
        rows: Mutex<Result<Vec<SagaRunnableInstance>, SagaDurableStoreError>>,
    }

    impl FakeInstanceStore {
        fn with_rows(rows: Vec<SagaRunnableInstance>) -> Self {
            Self {
                rows: Mutex::new(Ok(rows)),
            }
        }
    }

    impl SagaDurableStore for FakeInstanceStore {
        async fn register(
            &self,
            _authorization: diport::SagaStartAuthorization,
            registration: SagaInstanceRegistration,
        ) -> Result<SagaInstanceRecord, SagaDurableStoreError> {
            SagaInstanceRecord::new(
                registration.instance(),
                SagaInstanceStatus::Ready,
                registration.identity().clone(),
                registration.definition().clone(),
            )
            .map_err(|_| store_error())
        }

        async fn get(
            &self,
            _instance: &SagaInstanceRef,
        ) -> Result<Option<SagaInstanceRecord>, SagaDurableStoreError> {
            Ok(None)
        }

        async fn claim(
            &self,
            _request: SagaClaimRequest,
        ) -> Result<SagaClaimOutcome, SagaDurableStoreError> {
            Ok(SagaClaimOutcome::Busy)
        }

        async fn renew(
            &self,
            _lease: &SagaLease,
            _ttl: SagaLeaseTtl,
        ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn release(
            &self,
            _lease: &SagaLease,
        ) -> Result<SagaLeaseOutcome, SagaDurableStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn recovery_snapshot(
            &self,
            _request: SagaRecoveryRequest,
        ) -> Result<SagaRecoveryOutcome, SagaDurableStoreError> {
            Ok(SagaRecoveryOutcome::LeaseLost)
        }

        async fn terminal_receipt(
            &self,
            _request: SagaTerminalReceiptRequest,
        ) -> Result<SagaTerminalReceiptOutcome, SagaDurableStoreError> {
            Ok(SagaTerminalReceiptOutcome::Missing)
        }

        async fn mutate(
            &self,
            _lease: &SagaLease,
            _mutation: SagaDurableMutation,
        ) -> Result<SagaDurableMutationOutcome, SagaDurableStoreError> {
            Ok(SagaDurableMutationOutcome::LeaseLost)
        }

        async fn list_runnable(
            &self,
            _identity: &SagaWorkerIdentity,
            tenant: rss_request_context::TenantId,
            _limit: NonZeroUsize,
        ) -> Result<Vec<SagaRunnableInstance>, SagaDurableStoreError> {
            self.rows
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|rows| {
                    rows.iter()
                        .filter(|row| row.instance().tenant() == tenant)
                        .cloned()
                        .collect()
                })
                .map_err(|_| store_error())
        }

        async fn shutdown(&self) -> Result<(), SagaDurableStoreError> {
            Ok(())
        }
    }

    fn store_error() -> SagaDurableStoreError {
        SagaDurableStoreError::new(SagaDurableStoreErrorKind::Storage, FakeWorkerError)
    }

    struct FakeExecutor {
        outcomes: Mutex<VecDeque<SagaOutcome>>,
        calls: Mutex<
            Vec<(
                &'static str,
                SagaInstanceRef,
                Option<consistency::SagaDefinitionIdentity>,
            )>,
        >,
    }

    impl FakeExecutor {
        fn new(outcomes: Vec<SagaOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(
            &self,
        ) -> Vec<(
            &'static str,
            SagaInstanceRef,
            Option<consistency::SagaDefinitionIdentity>,
        )> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl SagaExecutor for FakeExecutor {
        fn advance_registered(
            &self,
            instance: SagaInstanceRef,
            definition: consistency::SagaDefinitionIdentity,
        ) -> BoxFuture<'static, SagaOutcome> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((
                "advance_registered",
                instance,
                Some(definition),
            ));
            let outcome = self
                .outcomes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
                .unwrap_or_else(succeeded_outcome);
            Box::pin(async move { outcome })
        }
    }

    #[derive(Debug)]
    struct FakeWorkerError;

    impl std::fmt::Display for FakeWorkerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake worker error")
        }
    }

    impl std::error::Error for FakeWorkerError {}

    struct FixedClock;

    impl diport::Clock for FixedClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::UNIX_EPOCH + Duration::from_secs(60)
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn probe_name_uses_identity_and_no_ready_suffix() {
        let name = saga_executor_probe_name(&identity()).unwrap();
        assert_eq!(name.as_str(), "saga_executor:billing__billing_checkout");
        assert!(!name.as_str().contains("_ready"));
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn tick_runs_ready_and_resumes_running_instances() {
        let tenant = tenant();
        let ready = runnable(tenant, 1, SagaInstanceStatus::Ready);
        let old_definition = consistency::SagaDefinitionIdentity::new(
            "billing.checkout",
            "v2",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let running =
            runnable_with_definition(tenant, 2, SagaInstanceStatus::Running, old_definition);
        let source = FakeTenantSource::with_tenants(vec![tenant]);
        let store = FakeInstanceStore::with_rows(vec![ready.clone(), running.clone()]);
        let executor = FakeExecutor::new(vec![
            succeeded_outcome(),
            SagaOutcome::Interrupted {
                reason: SagaInterruption::LeaseBusy,
            },
        ]);

        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                SagaWorkerConfig::default(),
                &mut None,
            )
            .await,
            SagaWorkerTick::Clean
        );
        assert_eq!(
            executor.calls(),
            vec![
                (
                    "advance_registered",
                    ready.instance(),
                    Some(ready.definition().clone())
                ),
                (
                    "advance_registered",
                    running.instance(),
                    Some(running.definition().clone()),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn unresolved_operator_backlog_is_current_degradation() {
        let source = FakeTenantSource::with_unresolved(true);
        let store = FakeInstanceStore::with_rows(Vec::new());
        let executor = FakeExecutor::new(Vec::new());

        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                SagaWorkerConfig::default(),
                &mut None,
            )
            .await,
            SagaWorkerTick::TransientDegraded
        );
    }

    #[test]
    fn blocked_instance_status_health_and_metric_matrix_is_closed() {
        let matrix = [
            (
                SagaInstanceStatus::OperatorRequired,
                crate::SagaExecStatus::Blocked,
                "operator_required",
            ),
            (
                SagaInstanceStatus::Degraded,
                crate::SagaExecStatus::Blocked,
                "degraded",
            ),
            (
                SagaInstanceStatus::CompensationFailed,
                crate::SagaExecStatus::Blocked,
                "compensation_failed",
            ),
        ];
        for (instance_status, expected_exec_status, _) in &matrix {
            let projected = match instance_status {
                SagaInstanceStatus::OperatorRequired
                | SagaInstanceStatus::Degraded
                | SagaInstanceStatus::CompensationFailed => crate::SagaExecStatus::Blocked,
                _ => unreachable!("matrix contains only blocked durable states"),
            };
            assert_eq!(projected, *expected_exec_status);
        }

        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let observation = SagaUnresolvedObservation::new(11, 13, 17, Some(std::time::UNIX_EPOCH));
        metrics::with_local_recorder(&recorder, || {
            record_unresolved_metrics(&identity(), &FixedClock, Some(&observation));
        });
        let rendered = handle.render();
        for (_, _, metric_state) in matrix {
            assert!(
                rendered.contains(&format!("state=\"{metric_state}\"")),
                "missing blocked metric state {metric_state}: {rendered}"
            );
        }

        let health = WorkerHealth::starting();
        SagaWorkerHealthProjection::default().apply(SagaWorkerTick::TransientDegraded, &health);
        assert_eq!(health.status(), HealthStatus::Degraded);
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn poison_first_page_does_not_starve_later_runnable_tenants() {
        let tenants = (1_u128..=3)
            .map(|value| {
                rss_request_context::TenantId::parse(&uuid::Uuid::from_u128(value).to_string())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let rows = tenants
            .iter()
            .enumerate()
            .map(|(index, tenant)| runnable(*tenant, index as u128 + 1, SagaInstanceStatus::Ready))
            .collect::<Vec<_>>();
        let source = FakeTenantSource::with_tenants(tenants);
        let store = FakeInstanceStore::with_rows(rows.clone());
        let executor = FakeExecutor::new(vec![
            SagaOutcome::Interrupted {
                reason: SagaInterruption::InstanceDegraded,
            },
            succeeded_outcome(),
            succeeded_outcome(),
        ]);
        let config = SagaWorkerConfig::new(
            NonZeroU64::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );
        let mut cursor = None;

        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                config,
                &mut cursor,
            )
            .await,
            SagaWorkerTick::PermanentDegraded,
        );
        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                config,
                &mut cursor,
            )
            .await,
            SagaWorkerTick::Clean,
        );
        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                config,
                &mut cursor,
            )
            .await,
            SagaWorkerTick::Clean,
        );
        assert_eq!(
            executor
                .calls()
                .into_iter()
                .map(|(_, instance, _)| instance)
                .collect::<Vec<_>>(),
            rows.into_iter()
                .map(|row| row.instance())
                .collect::<Vec<_>>(),
        );
        assert_eq!(cursor, None);
    }

    #[tokio::test]
    async fn source_error_degrades_tick() {
        let store = FakeInstanceStore::with_rows(Vec::new());
        let executor = FakeExecutor::new(Vec::new());
        assert_eq!(
            saga_worker_tick(
                &identity(),
                &FakeTenantSource::failing(),
                &store,
                &executor,
                &FixedClock,
                SagaWorkerConfig::default(),
                &mut None,
            )
            .await,
            SagaWorkerTick::TransientDegraded
        );
    }

    #[tokio::test]
    async fn infrastructure_interruption_degrades_tick() {
        let tenant = tenant();
        let source = FakeTenantSource::with_tenants(vec![tenant]);
        let store =
            FakeInstanceStore::with_rows(vec![runnable(tenant, 1, SagaInstanceStatus::Ready)]);
        let executor = FakeExecutor::new(vec![SagaOutcome::Interrupted {
            reason: SagaInterruption::StoreUnavailable,
        }]);

        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                SagaWorkerConfig::default(),
                &mut None,
            )
            .await,
            SagaWorkerTick::TransientDegraded
        );
    }

    #[test]
    fn compensated_receipt_precommit_failure_is_transiently_degraded() {
        assert_eq!(
            classify_outcome(SagaOutcome::Interrupted {
                reason: SagaInterruption::StoreUnavailable,
            }),
            SagaWorkerTick::TransientDegraded
        );
    }

    #[tokio::test]
    #[allow(clippy::unwrap_used)]
    async fn foreign_owner_runnable_is_rejected_before_executor_dispatch() {
        let tenant = tenant();
        let foreign = SagaWorkerIdentity::new(
            "foreign-owner",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap();
        let instance = SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(9))).unwrap();
        let row = SagaRunnableInstance::new(
            instance,
            SagaInstanceStatus::Ready,
            foreign,
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC),
        )
        .unwrap();
        let source = FakeTenantSource::with_tenants(vec![tenant]);
        let store = FakeInstanceStore::with_rows(vec![row]);
        let executor = FakeExecutor::new(Vec::new());

        assert_eq!(
            saga_worker_tick(
                &identity(),
                &source,
                &store,
                &executor,
                &FixedClock,
                SagaWorkerConfig::default(),
                &mut None,
            )
            .await,
            SagaWorkerTick::PermanentDegraded
        );
        assert!(executor.calls().is_empty());
    }

    #[test]
    fn unknown_outcome_and_ownership_loss_are_permanent_degradation() {
        for error in [
            crate::SagaActionError::OutcomeUnknown,
            crate::SagaActionError::OwnershipLost,
        ] {
            assert_eq!(
                classify_outcome(SagaOutcome::Failed {
                    failed_node: "reserve_funds".to_string(),
                    error,
                }),
                SagaWorkerTick::PermanentDegraded
            );
        }
    }

    #[test]
    fn permanent_degradation_survives_a_later_empty_clean_tick() {
        let health = WorkerHealth::starting();
        let mut projection = SagaWorkerHealthProjection::default();

        projection.apply(SagaWorkerTick::PermanentDegraded, &health);
        assert_eq!(health.status(), HealthStatus::Degraded);
        projection.apply(SagaWorkerTick::Clean, &health);
        assert_eq!(health.status(), HealthStatus::Degraded);
    }

    #[test]
    fn repaired_current_backlog_recovers_on_the_next_clean_tick() {
        let health = WorkerHealth::starting();
        let mut projection = SagaWorkerHealthProjection::default();

        projection.apply(SagaWorkerTick::TransientDegraded, &health);
        assert_eq!(health.status(), HealthStatus::Degraded);
        projection.apply(SagaWorkerTick::Clean, &health);
        assert_eq!(health.status(), HealthStatus::Healthy);
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)] // reason: shutdown failure should fail this lifecycle test
    async fn worker_shutdown_marks_health_unhealthy() {
        let tenant = tenant();
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let (admission_control, _, _, write_admission) =
            primitives::prepare_dr_admission_controls().into_parts();
        admission_control
            .start_running()
            .expect("test admission starts running");
        let worker = SagaWorkerRuntime::new(
            identity(),
            Arc::new(FakeTenantSource::with_tenants(vec![tenant])),
            Arc::new(FakeInstanceStore::with_rows(Vec::new())),
            Arc::new(FakeExecutor::new(Vec::new())),
            Arc::new(FixedClock),
            SagaWorkerConfig::default(),
            write_admission,
        )
        .spawn(token, health.clone());
        tokio::task::yield_now().await;
        assert_eq!(health.status(), HealthStatus::Healthy);
        worker.shutdown().await.expect("worker shutdown");
        assert_eq!(health.status(), HealthStatus::Unhealthy);
    }

    #[allow(clippy::unwrap_used)]
    fn identity() -> SagaWorkerIdentity {
        SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn succeeded_outcome() -> SagaOutcome {
        let instance =
            SagaInstanceRef::new(tenant(), SagaId::new(uuid::Uuid::from_u128(u128::MAX))).unwrap();
        let definition =
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC);
        SagaOutcome::Succeeded {
            reference: Box::new(crate::SagaSuccessReference::for_test(
                instance,
                identity(),
                definition,
                <generated::saga::billing_v1::CaptureStep as generated::saga::StepMarker>::BINDING,
            )),
        }
    }

    #[allow(clippy::unwrap_used)]
    fn tenant() -> rss_request_context::TenantId {
        rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn runnable(
        tenant: rss_request_context::TenantId,
        id: u128,
        status: SagaInstanceStatus,
    ) -> SagaRunnableInstance {
        runnable_with_definition(
            tenant,
            id,
            status,
            consistency::SagaDefinitionIdentity::from_binding(generated::saga::billing_v1::SPEC),
        )
    }

    #[allow(clippy::unwrap_used)]
    fn runnable_with_definition(
        tenant: rss_request_context::TenantId,
        id: u128,
        status: SagaInstanceStatus,
        definition: consistency::SagaDefinitionIdentity,
    ) -> SagaRunnableInstance {
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(id))).unwrap();
        SagaRunnableInstance::new(instance, status, identity(), definition).unwrap()
    }
}
