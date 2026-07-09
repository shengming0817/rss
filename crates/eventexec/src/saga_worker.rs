//! Saga background worker + readyz health state.
//!
//! The worker is intentionally a thin poll/orchestrate layer. Work discovery is advisory and all
//! correctness remains in [`crate::SagaExecutor`] plus durable lease/runtime-lock CAS.

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use consistency::SagaInstanceStatus;
use diport::{
    ManagedResource, SagaInstanceStore, SagaInstanceStoreError, SagaRunnableInstance,
    SagaTenantSource, SagaWorkerIdentity,
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
    inner: tokio::sync::Mutex<Option<JoinHandle<()>>>,
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
            inner: tokio::sync::Mutex::new(Some(handle)),
            health,
            token,
        }
    }

    /// Worker health shared with readyz probes.
    pub fn health(&self) -> Arc<WorkerHealth> {
        self.health.clone()
    }
}

#[allow(unknown_lints, rss_diport_impl_allowlist)]
// reason(rss_diport_impl_allowlist): saga background worker is an eventexec runtime resource,
// matching RelayWorker/ProjectionWorker ManagedResource ownership.
impl ManagedResource for SagaWorker {
    fn name(&self) -> &str {
        &self.name
    }

    async fn shutdown(&self) -> Result<(), diport::ShutdownError> {
        self.token.cancel();
        if let Some(handle) = self.inner.lock().await.take() {
            handle.await.map_err(diport::ShutdownError::new)?;
        }
        Ok(())
    }

    fn shutdown_timeout(&self) -> Duration {
        SAGA_WORKER_SHUTDOWN_TIMEOUT
    }
}

/// Spawn a saga worker on the current Tokio runtime.
pub fn spawn_saga_worker<T, S, E>(
    identity: SagaWorkerIdentity,
    tenant_source: Arc<T>,
    instance_store: Arc<S>,
    executor: Arc<E>,
    config: SagaWorkerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) -> SagaWorker
where
    T: SagaTenantSource + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
    E: SagaExecutor + Send + Sync + 'static,
{
    let worker_name = saga_worker_name(&identity);
    let task_token = token.clone();
    let task_health = health.clone();
    let handle = tokio::spawn(async move {
        saga_worker_loop(
            identity,
            tenant_source,
            instance_store,
            executor,
            config,
            task_token,
            task_health,
        )
        .await;
    });
    SagaWorker::adopt(worker_name, handle, health, token)
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

async fn saga_worker_loop<T, S, E>(
    identity: SagaWorkerIdentity,
    tenant_source: Arc<T>,
    instance_store: Arc<S>,
    executor: Arc<E>,
    config: SagaWorkerConfig,
    token: CancellationToken,
    health: Arc<WorkerHealth>,
) where
    T: SagaTenantSource + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
    E: SagaExecutor + Send + Sync + 'static,
{
    let _stopped_guard = health.stopped_on_exit();
    let mut ticker = tokio::time::interval(config.poll_interval());
    loop {
        tokio::select! {
            biased;
            () = token.cancelled() => break,
            _ = ticker.tick() => {
                match saga_worker_tick(
                    &identity,
                    tenant_source.as_ref(),
                    instance_store.as_ref(),
                    executor.as_ref(),
                    config,
                )
                .await
                {
                    SagaWorkerTick::Clean => health.mark_healthy(),
                    SagaWorkerTick::Degraded => health.mark_degraded(),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SagaWorkerTick {
    Clean,
    Degraded,
}

impl SagaWorkerTick {
    fn worse(self, other: Self) -> Self {
        if self == Self::Degraded || other == Self::Degraded {
            Self::Degraded
        } else {
            Self::Clean
        }
    }
}

pub(crate) async fn saga_worker_tick<T, S, E>(
    identity: &SagaWorkerIdentity,
    tenant_source: &T,
    instance_store: &S,
    executor: &E,
    config: SagaWorkerConfig,
) -> SagaWorkerTick
where
    T: SagaTenantSource + Send + Sync,
    S: SagaInstanceStore + Send + Sync,
    E: SagaExecutor + Send + Sync,
{
    let tenants = match tenant_source
        .list_candidate_tenants(identity, config.tenant_batch_size())
        .await
    {
        Ok(tenants) => tenants,
        Err(error) => {
            warn_worker_source_error(identity, "tenant_source", &error);
            return SagaWorkerTick::Degraded;
        }
    };
    let mut tick = SagaWorkerTick::Clean;
    for tenant in tenants {
        tick = tick.worse(
            run_tenant_batch(
                identity,
                tenant,
                instance_store,
                executor,
                config.batch_size(),
            )
            .await,
        );
    }
    tick
}

async fn run_tenant_batch<S, E>(
    identity: &SagaWorkerIdentity,
    tenant: vocab::TenantId,
    instance_store: &S,
    executor: &E,
    batch_size: NonZeroUsize,
) -> SagaWorkerTick
where
    S: SagaInstanceStore + Send + Sync,
    E: SagaExecutor + Send + Sync,
{
    let rows = match instance_store
        .list_runnable(identity, tenant, batch_size)
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            warn_worker_source_error(identity, "instance_store", &error);
            return SagaWorkerTick::Degraded;
        }
    };
    let mut tick = SagaWorkerTick::Clean;
    for row in rows {
        tick = tick.worse(run_one(row, executor).await);
    }
    tick
}

async fn run_one<E>(row: SagaRunnableInstance, executor: &E) -> SagaWorkerTick
where
    E: SagaExecutor + Send + Sync,
{
    let outcome = match row.status() {
        SagaInstanceStatus::Ready => executor.run(row.instance()).await,
        SagaInstanceStatus::Running | SagaInstanceStatus::Compensating => {
            executor.resume(row.instance()).await
        }
        _ => return SagaWorkerTick::Degraded,
    };
    classify_outcome(outcome)
}

fn classify_outcome(outcome: SagaOutcome) -> SagaWorkerTick {
    match outcome {
        SagaOutcome::Interrupted { reason } if interruption_degrades(reason) => {
            SagaWorkerTick::Degraded
        }
        _ => SagaWorkerTick::Clean,
    }
}

fn interruption_degrades(reason: SagaInterruption) -> bool {
    matches!(
        reason,
        SagaInterruption::RuntimeLockUnavailable
            | SagaInterruption::StoreUnavailable
            | SagaInterruption::JournalConflict
            | SagaInterruption::InstanceDegraded
    )
}

fn warn_worker_source_error(
    identity: &SagaWorkerIdentity,
    source: &'static str,
    error: &SagaInstanceStoreError,
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
    use diport::{SagaContractId, SagaInstanceRegistration};
    use futures::future::BoxFuture;
    use primitives::healthz::HealthStatus;

    use super::*;

    struct FakeTenantSource {
        tenants: Mutex<Result<Vec<vocab::TenantId>, SagaInstanceStoreError>>,
    }

    impl FakeTenantSource {
        fn with_tenants(tenants: Vec<vocab::TenantId>) -> Self {
            Self {
                tenants: Mutex::new(Ok(tenants)),
            }
        }

        fn failing() -> Self {
            Self {
                tenants: Mutex::new(Err(SagaInstanceStoreError::new(FakeWorkerError))),
            }
        }
    }

    impl SagaTenantSource for FakeTenantSource {
        async fn list_candidate_tenants(
            &self,
            _identity: &SagaWorkerIdentity,
            _limit: NonZeroUsize,
        ) -> Result<Vec<vocab::TenantId>, SagaInstanceStoreError> {
            self.tenants
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(Clone::clone)
                .map_err(|_| SagaInstanceStoreError::new(FakeWorkerError))
        }
    }

    struct FakeInstanceStore {
        rows: Mutex<Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError>>,
    }

    impl FakeInstanceStore {
        fn with_rows(rows: Vec<SagaRunnableInstance>) -> Self {
            Self {
                rows: Mutex::new(Ok(rows)),
            }
        }
    }

    impl SagaInstanceStore for FakeInstanceStore {
        async fn register(
            &self,
            registration: SagaInstanceRegistration,
        ) -> Result<SagaInstanceRecord, SagaInstanceStoreError> {
            Ok(SagaInstanceRecord::new(
                registration.instance(),
                SagaInstanceStatus::Ready,
            ))
        }

        async fn get(
            &self,
            _instance: &SagaInstanceRef,
        ) -> Result<Option<SagaInstanceRecord>, SagaInstanceStoreError> {
            Ok(None)
        }

        async fn acquire_lease(
            &self,
            _instance: &SagaInstanceRef,
            _holder_id: &str,
            _ttl: Duration,
        ) -> Result<Option<SagaLease>, SagaInstanceStoreError> {
            Ok(None)
        }

        async fn extend_lease(
            &self,
            _lease: &SagaLease,
            _ttl: Duration,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn release_lease(
            &self,
            _lease: &SagaLease,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn mark_status(
            &self,
            _lease: &SagaLease,
            _status: SagaInstanceStatus,
        ) -> Result<SagaLeaseOutcome, SagaInstanceStoreError> {
            Ok(SagaLeaseOutcome::Lost)
        }

        async fn list_runnable(
            &self,
            _identity: &SagaWorkerIdentity,
            _tenant: vocab::TenantId,
            _limit: NonZeroUsize,
        ) -> Result<Vec<SagaRunnableInstance>, SagaInstanceStoreError> {
            self.rows
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(Clone::clone)
                .map_err(|_| SagaInstanceStoreError::new(FakeWorkerError))
        }

        async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
            Ok(())
        }
    }

    struct FakeExecutor {
        outcomes: Mutex<VecDeque<SagaOutcome>>,
        calls: Mutex<Vec<(&'static str, SagaInstanceRef)>>,
    }

    impl FakeExecutor {
        fn new(outcomes: Vec<SagaOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(&'static str, SagaInstanceRef)> {
            self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl SagaExecutor for FakeExecutor {
        fn run(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(("run", instance));
            let outcome = self
                .outcomes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
                .unwrap_or(SagaOutcome::Succeeded { output: Vec::new() });
            Box::pin(async move { outcome })
        }

        fn resume(&self, instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
            self.calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(("resume", instance));
            let outcome = self
                .outcomes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front()
                .unwrap_or(SagaOutcome::Succeeded { output: Vec::new() });
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
        let running = runnable(tenant, 2, SagaInstanceStatus::Running);
        let source = FakeTenantSource::with_tenants(vec![tenant]);
        let store = FakeInstanceStore::with_rows(vec![ready, running]);
        let executor = FakeExecutor::new(vec![
            SagaOutcome::Succeeded { output: Vec::new() },
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
                SagaWorkerConfig::default(),
            )
            .await,
            SagaWorkerTick::Clean
        );
        assert_eq!(
            executor.calls(),
            vec![("run", ready.instance()), ("resume", running.instance())]
        );
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
                SagaWorkerConfig::default(),
            )
            .await,
            SagaWorkerTick::Degraded
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
                SagaWorkerConfig::default(),
            )
            .await,
            SagaWorkerTick::Degraded
        );
    }

    #[tokio::test(start_paused = true)]
    #[allow(clippy::expect_used)] // reason: shutdown failure should fail this lifecycle test
    async fn worker_shutdown_marks_health_unhealthy() {
        let tenant = tenant();
        let health = Arc::new(WorkerHealth::starting());
        let token = CancellationToken::new();
        let worker = spawn_saga_worker(
            identity(),
            Arc::new(FakeTenantSource::with_tenants(vec![tenant])),
            Arc::new(FakeInstanceStore::with_rows(Vec::new())),
            Arc::new(FakeExecutor::new(Vec::new())),
            SagaWorkerConfig::default(),
            token,
            health.clone(),
        );
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
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap()
    }

    #[allow(clippy::unwrap_used)]
    fn runnable(
        tenant: vocab::TenantId,
        id: u128,
        status: SagaInstanceStatus,
    ) -> SagaRunnableInstance {
        let instance =
            SagaInstanceRef::new(tenant, SagaId::new(uuid::Uuid::from_u128(id))).unwrap();
        SagaRunnableInstance::new(instance, status).unwrap()
    }
}
