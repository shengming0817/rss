//! distributed runtime wiring and the first production consumer.
//!
//! The composition root owns provider construction: Redis supplies the distributed lock provider
//! and Postgres supplies state-CAS. Consumers receive [`DistributedRuntimeDeps`] as a required type,
//! so removing the distributed wiring is a compile-time failure.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use consistency::{
    BacklogMetricSample, EngineError, EngineErrorKind, OutboxBacklog, RetentionSweeper,
};
use distributed::{
    CasKey, CasOutcome, CasRequest, DistError, DomainTransport, FencingToken, LockGrant, LockKey,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time;

use crate::SharedRuntimeDeps;

const OUTBOX_MAINTENANCE_LOCK: &str = "runtime/event/outbox-maintenance";
const OUTBOX_MAINTENANCE_CAS: &str = "runtime/event/outbox-maintenance";
const DEFAULT_OUTBOX_MAINTENANCE_TTL: Duration = Duration::from_secs(30);
#[cfg(test)]
const OUTBOX_MAINTENANCE_RENEW_INTERVAL: Duration = Duration::from_millis(5);

/// Exact, non-optional timing owned by the process configuration snapshot.
#[derive(Clone, Copy)]
pub(crate) struct DistributedWorkerConfig {
    outbox_maintenance_ttl: Duration,
}

impl DistributedWorkerConfig {
    /// Preserve the existing non-configurable distributed maintenance timing.
    pub(crate) const fn canonical() -> Self {
        Self {
            outbox_maintenance_ttl: DEFAULT_OUTBOX_MAINTENANCE_TTL,
        }
    }
}

/// Hard-wired distributed runtime dependencies.
#[derive(Clone)]
pub struct DistributedRuntimeDeps {
    locker: Arc<Mutex<distributed::Locker>>,
    state_cas: Arc<Mutex<distributed::StateCas>>,
    domain_transport: Arc<dyn DomainTransport>,
    outbox_maintenance_ttl: Duration,
}

impl DistributedRuntimeDeps {
    /// Coordinator for the durable event outbox maintenance workers.
    #[must_use]
    pub fn outbox_maintenance_coordinator(&self) -> OutboxMaintenanceCoordinator {
        OutboxMaintenanceCoordinator {
            locker: Arc::clone(&self.locker),
            state_cas: Arc::clone(&self.state_cas),
            cas_state: Arc::new(Mutex::new(None)),
            ttl: self.outbox_maintenance_ttl,
        }
    }

    /// Shared outbound domain transport dispatch seam.
    #[must_use]
    pub fn domain_transport(&self) -> Arc<dyn DomainTransport> {
        Arc::clone(&self.domain_transport)
    }
}

/// Composition-root distributed wiring.
///
/// Provider source is intentionally narrow:
/// - lock provider: `SharedRuntimeDeps.redis.infra().lock_store()`
/// - state-CAS provider: `SharedRuntimeDeps.pg.infra().cas_store()`
pub(crate) fn wire_distributed(
    deps: &SharedRuntimeDeps,
    worker: DistributedWorkerConfig,
) -> anyhow::Result<DistributedRuntimeDeps> {
    Ok(DistributedRuntimeDeps {
        locker: Arc::new(Mutex::new(distributed::Locker::new(
            deps.redis.infra().lock_store(),
        ))),
        state_cas: Arc::new(Mutex::new(distributed::StateCas::new(
            deps.pg.infra().cas_store(),
        ))),
        domain_transport: Arc::clone(&deps.domain_transport),
        outbox_maintenance_ttl: worker.outbox_maintenance_ttl,
    })
}

#[derive(Clone)]
pub struct OutboxMaintenanceCoordinator {
    locker: Arc<Mutex<distributed::Locker>>,
    state_cas: Arc<Mutex<distributed::StateCas>>,
    cas_state: Arc<Mutex<Option<CasState>>>,
    ttl: Duration,
}

#[derive(Clone, Copy, Debug)]
struct CasState {
    value: MaintenanceEpoch,
    token: Option<FencingToken>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct MaintenanceEpoch {
    lock_token: u64,
}

impl OutboxMaintenanceCoordinator {
    #[allow(clippy::cognitive_complexity)]
    // reason: 单次 acquire 必须按 lock acquire → CAS Applied/Conflict/Fenced → release 的顺序处理；
    // 拆成多个函数会隐藏 grant ownership/release 路径，降低 fencing 控制流可审计性。
    async fn try_acquire(&self) -> Result<MaintenanceLease, DistError> {
        let key = LockKey::parse(OUTBOX_MAINTENANCE_LOCK).map_err(|e| {
            tracing::warn!(error = %e, "outbox maintenance lock key invalid");
            DistError::Fatal
        })?;
        let grant = {
            let locker = self.locker.lock().await;
            locker.acquire(key, self.ttl).await?
        };
        let Some(grant) = grant else {
            tracing::debug!("outbox maintenance standby: distributed lock held by peer");
            return Ok(MaintenanceLease::Standby);
        };

        let new_epoch = MaintenanceEpoch {
            lock_token: grant.token().value(),
        };
        let expected_state = *self.cas_state.lock().await;
        let request = CasRequest {
            key: CasKey::new(OUTBOX_MAINTENANCE_CAS),
            expected: expected_state.map(|s| s.value),
            new_value: new_epoch,
            token: expected_state.and_then(|s| s.token),
        };
        let outcome = {
            let state_cas = self.state_cas.lock().await;
            state_cas.compare_and_swap(request).await?
        };

        match outcome {
            CasOutcome::Applied { token } => {
                *self.cas_state.lock().await = Some(CasState {
                    value: new_epoch,
                    token: Some(token),
                });
                Ok(MaintenanceLease::Active { grant })
            }
            CasOutcome::Conflict { current } => {
                let Some(current) = current else {
                    *self.cas_state.lock().await = None;
                    self.release_best_effort(grant).await;
                    tracing::debug!("outbox maintenance standby: CAS key absent under contention");
                    return Ok(MaintenanceLease::Standby);
                };
                *self.cas_state.lock().await = Some(CasState {
                    value: current,
                    token: None,
                });
                self.release_best_effort(grant).await;
                tracing::debug!("outbox maintenance standby: CAS conflict");
                Ok(MaintenanceLease::Standby)
            }
            CasOutcome::Fenced { token } => {
                *self.cas_state.lock().await = None;
                self.release_best_effort(grant).await;
                tracing::debug!(token = token.value(), "outbox maintenance fenced");
                Ok(MaintenanceLease::Standby)
            }
            _ => {
                self.release_best_effort(grant).await;
                Err(DistError::Fatal)
            }
        }
    }

    async fn release_best_effort(&self, grant: LockGrant) {
        let locker = self.locker.lock().await;
        if let Err(err) = locker.release(grant).await {
            tracing::warn!(error = %err, "outbox maintenance lock release failed");
        }
    }

    async fn renew_or_stop(&self, grant: &LockGrant) -> Result<Option<LockGrant>, EngineError> {
        let renewed = {
            let locker = self.locker.lock().await;
            locker.renew(grant).await
        };
        Self::map_renew_result(renewed)
    }

    fn map_renew_result(
        renewed: Result<Option<LockGrant>, DistError>,
    ) -> Result<Option<LockGrant>, EngineError> {
        let Some(grant) = renewed.map_err(Self::renew_error_to_engine)? else {
            tracing::debug!("outbox maintenance lease lost; cancelling current tick");
            return Ok(None);
        };
        Ok(Some(grant))
    }

    fn renew_error_to_engine(err: DistError) -> EngineError {
        tracing::warn!(error = %err, "outbox maintenance lock renew failed");
        EngineError::new(EngineErrorKind::Transient)
    }

    fn renew_interval(ttl: Duration) -> Duration {
        #[cfg(test)]
        {
            let _ = ttl;
            OUTBOX_MAINTENANCE_RENEW_INTERVAL
        }
        #[cfg(not(test))]
        {
            ttl.checked_div(3).unwrap_or(Duration::from_secs(1))
        }
    }

    async fn try_run_active(&self) -> Result<Option<LockGrant>, EngineError> {
        match self.try_acquire().await {
            Ok(MaintenanceLease::Standby) => Ok(None),
            Ok(MaintenanceLease::Active { grant }) => Ok(Some(grant)),
            Err(err) => {
                tracing::warn!(error = %err, "outbox maintenance distributed coordinator failed");
                Err(EngineError::new(EngineErrorKind::Transient))
            }
        }
    }

    async fn run_active<T, F>(&self, operation: F) -> Result<Option<T>, EngineError>
    where
        F: Future<Output = Result<T, EngineError>>,
    {
        let Some(mut grant) = self.try_run_active().await? else {
            return Ok(None);
        };

        let interval = Self::renew_interval(grant.ttl());
        let mut renew_sleep = Box::pin(time::sleep(interval));
        tokio::pin!(operation);

        loop {
            tokio::select! {
                result = &mut operation => {
                    self.release_best_effort(grant).await;
                    return result.map(Some);
                }
                () = &mut renew_sleep => {
                    match self.renew_or_stop(&grant).await? {
                        Some(renewed) => {
                            grant = renewed;
                            renew_sleep = Box::pin(time::sleep(interval));
                        }
                        None => {
                            self.release_best_effort(grant).await;
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }
}

enum MaintenanceLease {
    Active { grant: LockGrant },
    Standby,
}

/// Distributed active/standby wrapper for outbox backlog sampling.
pub struct CoordinatedOutboxBacklog<B> {
    inner: B,
    coordinator: OutboxMaintenanceCoordinator,
}

impl<B> CoordinatedOutboxBacklog<B> {
    #[must_use]
    pub fn new(inner: B, coordinator: OutboxMaintenanceCoordinator) -> Self {
        Self { inner, coordinator }
    }
}

impl<B> OutboxBacklog for CoordinatedOutboxBacklog<B>
where
    B: OutboxBacklog + Send + Sync,
{
    async fn sample_backlog(&self, domain: &str) -> Result<Vec<BacklogMetricSample>, EngineError> {
        self.coordinator
            .run_active(self.inner.sample_backlog(domain))
            .await
            .map(|samples| samples.unwrap_or_default())
    }
}

/// Distributed active/standby wrapper for outbox retention sweeping.
pub struct CoordinatedRetentionSweeper<S> {
    inner: S,
    coordinator: OutboxMaintenanceCoordinator,
}

impl<S> CoordinatedRetentionSweeper<S> {
    #[must_use]
    pub fn new(inner: S, coordinator: OutboxMaintenanceCoordinator) -> Self {
        Self { inner, coordinator }
    }
}

impl<S> RetentionSweeper for CoordinatedRetentionSweeper<S>
where
    S: RetentionSweeper + Send + Sync,
{
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        self.coordinator
            .run_active(self.inner.sweep(retain_seconds))
            .await
            .map(|deleted| deleted.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Notify;

    use consistency::{BacklogSample, OutboxContractId, OutboxMetricSubject};
    use diport::{CasStore, CasStoreOutcome, LockAcquireOutcome, LockRenewOutcome, LockStore};

    type LockMap = HashMap<String, (Option<vocab::Epoch>, u64)>;
    type CasMap = HashMap<String, (Vec<u8>, vocab::Epoch)>;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    struct NoopDomainTransport;

    impl distributed::DomainTransport for NoopDomainTransport {
        fn dispatch(
            &self,
            _request: distributed::DomainRequest,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            distributed::DomainResponse,
                            distributed::DomainTransportError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(distributed::DomainResponse::new(
                    204,
                    Vec::new(),
                    Vec::new(),
                ))
            })
        }
    }

    #[allow(clippy::expect_used)]
    // reason: runtime wrapper tests use fixed known-valid tenant/contract fixtures.
    fn backlog_metric_sample(depth: u64, oldest_age_seconds: u64) -> BacklogMetricSample {
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")
            .expect("valid tenant fixture");
        let contract =
            OutboxContractId::parse("identity.session-created").expect("valid contract fixture");
        BacklogMetricSample::new(
            OutboxMetricSubject::new(tenant, contract),
            BacklogSample::new(depth, oldest_age_seconds),
        )
    }

    #[derive(Clone, Default)]
    struct FakeDistributedStore {
        locks: Arc<StdMutex<LockMap>>,
        cas: Arc<StdMutex<CasMap>>,
        renew_calls: Arc<StdMutex<u64>>,
        lose_after_renewals: Arc<StdMutex<Option<u64>>>,
    }

    impl FakeDistributedStore {
        fn losing_on_first_renew() -> Self {
            Self {
                lose_after_renewals: Arc::new(StdMutex::new(Some(0))),
                ..Self::default()
            }
        }

        fn deps(&self) -> DistributedRuntimeDeps {
            DistributedRuntimeDeps {
                locker: Arc::new(Mutex::new(distributed::Locker::new(
                    diport::DynLockStore::new_box(self.clone()),
                ))),
                state_cas: Arc::new(Mutex::new(distributed::StateCas::new(
                    diport::DynCasStore::new_box(self.clone()),
                ))),
                domain_transport: Arc::new(NoopDomainTransport),
                outbox_maintenance_ttl: DEFAULT_OUTBOX_MAINTENANCE_TTL,
            }
        }

        fn renew_calls(&self) -> u64 {
            *self.renew_calls.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl LockStore for FakeDistributedStore {
        async fn acquire(
            &self,
            key: diport::LockStoreKey,
            _ttl: Duration,
        ) -> Result<LockAcquireOutcome, diport::LockStoreError> {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            let entry = locks.entry(key.as_str().to_owned()).or_insert((None, 0));
            if entry.0.is_some() {
                Ok(LockAcquireOutcome::Held)
            } else {
                let token = vocab::Epoch::new(entry.1.saturating_add(1));
                entry.0 = Some(token);
                entry.1 = token.get();
                Ok(LockAcquireOutcome::Acquired { token })
            }
        }

        async fn renew(
            &self,
            key: diport::LockStoreKey,
            token: vocab::Epoch,
            _ttl: Duration,
        ) -> Result<LockRenewOutcome, diport::LockStoreError> {
            let call = {
                let mut calls = self.renew_calls.lock().unwrap_or_else(|e| e.into_inner());
                let call = *calls;
                *calls = calls.saturating_add(1);
                call
            };
            let should_lose = {
                let lose_after = self
                    .lose_after_renewals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                matches!(*lose_after, Some(max_renewals) if call >= max_renewals)
            };
            if should_lose {
                let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
                if let Some((held, _)) = locks.get_mut(key.as_str())
                    && *held == Some(token)
                {
                    *held = None;
                }
                return Ok(LockRenewOutcome::Lost);
            }
            let locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            match locks.get(key.as_str()) {
                Some((Some(held), _)) if *held == token => Ok(LockRenewOutcome::Renewed { token }),
                _ => Ok(LockRenewOutcome::Lost),
            }
        }

        async fn release(
            &self,
            key: diport::LockStoreKey,
            token: vocab::Epoch,
        ) -> Result<(), diport::LockStoreError> {
            let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((held, _)) = locks.get_mut(key.as_str())
                && *held == Some(token)
            {
                *held = None;
            }
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), diport::LockStoreError> {
            Ok(())
        }
    }

    impl CasStore for FakeDistributedStore {
        async fn compare_and_swap(
            &self,
            request: diport::CasStoreRequest,
        ) -> Result<CasStoreOutcome, diport::CasStoreError> {
            let mut cas = self.cas.lock().unwrap_or_else(|e| e.into_inner());
            match cas.get(request.key.as_str()) {
                None => {
                    if request.expected.is_none() {
                        let token = vocab::Epoch::new(1);
                        cas.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(CasStoreOutcome::Applied { token })
                    } else {
                        Ok(CasStoreOutcome::Conflict { current: None })
                    }
                }
                Some((current, current_token)) => {
                    if matches!(request.expected_token, Some(t) if t < *current_token) {
                        return Ok(CasStoreOutcome::Fenced {
                            current_token: *current_token,
                        });
                    }
                    if request.expected.as_ref().map(|v| v.as_bytes()) == Some(current.as_slice()) {
                        let token = current_token.next();
                        cas.insert(
                            request.key.as_str().to_owned(),
                            (request.new_value.into_bytes(), token),
                        );
                        Ok(CasStoreOutcome::Applied { token })
                    } else {
                        Ok(CasStoreOutcome::Conflict {
                            current: Some(current.clone().into()),
                        })
                    }
                }
            }
        }

        async fn shutdown(&self) -> Result<(), diport::CasStoreError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct CountingBacklog {
        calls: Arc<StdMutex<u64>>,
    }

    impl CountingBacklog {
        fn calls(&self) -> u64 {
            *self.calls.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl OutboxBacklog for CountingBacklog {
        async fn sample_backlog(
            &self,
            _domain: &str,
        ) -> Result<Vec<BacklogMetricSample>, EngineError> {
            *self.calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            Ok(vec![backlog_metric_sample(7, 11)])
        }
    }

    #[derive(Clone, Default)]
    struct SlowBacklog {
        started: Arc<Notify>,
        completed: Arc<AtomicBool>,
    }

    impl SlowBacklog {
        fn completed(&self) -> bool {
            self.completed.load(Ordering::SeqCst)
        }
    }

    impl OutboxBacklog for SlowBacklog {
        async fn sample_backlog(
            &self,
            _domain: &str,
        ) -> Result<Vec<BacklogMetricSample>, EngineError> {
            self.started.notify_waiters();
            time::sleep(Duration::from_secs(1)).await;
            self.completed.store(true, Ordering::SeqCst);
            Ok(vec![backlog_metric_sample(13, 17)])
        }
    }

    #[test]
    fn distributed_runtime_deps_exposes_domain_transport_handle() {
        let deps = FakeDistributedStore::default().deps();
        let first = deps.domain_transport();
        let second = deps.domain_transport();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn outbox_backlog_runs_when_coordinator_is_active() -> TestResult {
        let store = FakeDistributedStore::default();
        let coordinator = store.deps().outbox_maintenance_coordinator();
        let backlog = CountingBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), coordinator);

        let sample = wrapped.sample_backlog("identity").await?;

        assert_eq!(sample, vec![backlog_metric_sample(7, 11)]);
        assert_eq!(backlog.calls(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn outbox_backlog_standby_returns_empty_without_calling_inner() -> TestResult {
        let store = FakeDistributedStore::default();
        let first = store.deps().outbox_maintenance_coordinator();
        let _lease = first.try_acquire().await?;
        let second = store.deps().outbox_maintenance_coordinator();
        let backlog = CountingBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), second);

        let sample = wrapped.sample_backlog("identity").await?;

        assert!(sample.is_empty());
        assert_eq!(backlog.calls(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn outbox_backlog_cancels_current_tick_when_lock_renew_is_lost() -> TestResult {
        let store = FakeDistributedStore::losing_on_first_renew();
        let coordinator = store.deps().outbox_maintenance_coordinator();
        let backlog = SlowBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), coordinator);

        let sample = wrapped.sample_backlog("identity").await?;

        assert!(sample.is_empty());
        assert_eq!(store.renew_calls(), 1);
        assert!(
            !backlog.completed(),
            "lost lease must cancel the active tick"
        );
        Ok(())
    }
}
