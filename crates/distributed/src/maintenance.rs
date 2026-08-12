//! Distributed active/standby coordination for durable outbox maintenance.
//!
//! The coordinator owns only provider-independent lock/CAS facades and the fixed outbox
//! maintenance namespace. Assemblies inject the selected provider ports once through
//! [`OutboxMaintenanceCoordinator::from_ports`], then wrap backlog and retention workers with the
//! move-only typed adapters in this module.
//!
//! ref: kubernetes/client-go tools/leaderelection/leaderelection.go@master

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use consistency::{
    BacklogObservation, EngineError, EngineErrorKind, OutboxBacklog, RetentionSweeper,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time;

use crate::{
    CasKey, CasOutcome, CasRequest, DistError, FencingToken, LockGrant, LockKey, Locker, StateCas,
};

const OUTBOX_MAINTENANCE_LOCK: &str = "runtime/event/outbox-maintenance";
const OUTBOX_MAINTENANCE_CAS: &str = "runtime/event/outbox-maintenance";
#[cfg(test)]
const OUTBOX_MAINTENANCE_RENEW_INTERVAL: Duration = Duration::from_millis(5);

/// Shared active/standby coordinator for outbox backlog and retention work.
///
/// Construction consumes both provider ports, so a caller cannot produce a coordinator with only
/// locking or only fencing. Clones share the same typed CAS observation and provider facades.
#[derive(Clone)]
pub struct OutboxMaintenanceCoordinator {
    locker: Arc<Mutex<Locker>>,
    state_cas: Arc<Mutex<StateCas>>,
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
    /// Consume the exact lock and CAS provider ports required for coordinated maintenance.
    #[must_use]
    pub fn from_ports(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
    ) -> Self {
        Self {
            locker: Arc::new(Mutex::new(Locker::new(lock_store))),
            state_cas: Arc::new(Mutex::new(StateCas::new(cas_store))),
            cas_state: Arc::new(Mutex::new(None)),
            ttl,
        }
    }

    #[allow(clippy::cognitive_complexity)]
    // reason: one acquire must visibly retain lock ownership across CAS Applied/Conflict/Fenced
    // and every release path; splitting it obscures the fencing audit trail.
    async fn try_acquire(&self) -> Result<MaintenanceLease, DistError> {
        let key = LockKey::parse(OUTBOX_MAINTENANCE_LOCK).map_err(|error| {
            tracing::warn!(error = %error, "outbox maintenance lock key invalid");
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
            expected: expected_state.map(|state| state.value),
            new_value: new_epoch,
            token: expected_state.and_then(|state| state.token),
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
        }
    }

    async fn release_best_effort(&self, grant: LockGrant) {
        let locker = self.locker.lock().await;
        if let Err(error) = locker.release(grant).await {
            tracing::warn!(error = %error, "outbox maintenance lock release failed");
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

    fn renew_error_to_engine(error: DistError) -> EngineError {
        tracing::warn!(error = %error, "outbox maintenance lock renew failed");
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
            Err(error) => {
                tracing::warn!(error = %error, "outbox maintenance distributed coordinator failed");
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
    /// Bind one backlog implementation to the shared coordinator.
    #[must_use]
    pub fn new(inner: B, coordinator: OutboxMaintenanceCoordinator) -> Self {
        Self { inner, coordinator }
    }
}

impl<B> OutboxBacklog for CoordinatedOutboxBacklog<B>
where
    B: OutboxBacklog + Send + Sync,
{
    async fn sample_backlog(&self, domain: &str) -> Result<BacklogObservation, EngineError> {
        match self
            .coordinator
            .run_active(self.inner.sample_backlog(domain))
            .await?
        {
            Some(BacklogObservation::Active(samples)) => Ok(BacklogObservation::Active(samples)),
            Some(BacklogObservation::Standby) | None => Ok(BacklogObservation::Standby),
        }
    }
}

/// Distributed active/standby wrapper for outbox retention sweeping.
pub struct CoordinatedRetentionSweeper<S> {
    inner: S,
    coordinator: OutboxMaintenanceCoordinator,
}

impl<S> CoordinatedRetentionSweeper<S> {
    /// Bind one retention implementation to the shared coordinator.
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

    use consistency::{
        BacklogMetricSample, BacklogObservation, BacklogSample, OutboxContractId,
        OutboxMetricSubject,
    };
    use diport::{CasStore, CasStoreOutcome, LockAcquireOutcome, LockRenewOutcome, LockStore};
    use testkit::await_delay;
    use tokio::sync::Notify;

    type LockMap = HashMap<String, (Option<vocab::Epoch>, u64)>;
    type CasMap = HashMap<String, (Vec<u8>, vocab::Epoch)>;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[allow(clippy::expect_used)]
    // reason: coordinator tests use fixed known-valid tenant/contract fixtures.
    fn backlog_metric_sample(depth: u64, oldest_age_seconds: u64) -> BacklogMetricSample {
        let tenant = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000001")
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

        fn coordinator(&self) -> OutboxMaintenanceCoordinator {
            OutboxMaintenanceCoordinator::from_ports(
                diport::DynLockStore::new_box(self.clone()),
                diport::DynCasStore::new_box(self.clone()),
                Duration::from_secs(30),
            )
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
            let mut locks = self.locks.lock().unwrap_or_else(|error| error.into_inner());
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
                let mut calls = self
                    .renew_calls
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let call = *calls;
                *calls = calls.saturating_add(1);
                call
            };
            let should_lose = {
                let lose_after = self
                    .lose_after_renewals
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                matches!(*lose_after, Some(max_renewals) if call >= max_renewals)
            };
            if should_lose {
                let mut locks = self.locks.lock().unwrap_or_else(|error| error.into_inner());
                if let Some((held, _)) = locks.get_mut(key.as_str())
                    && *held == Some(token)
                {
                    *held = None;
                }
                return Ok(LockRenewOutcome::Lost);
            }
            let locks = self.locks.lock().unwrap_or_else(|error| error.into_inner());
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
            let mut locks = self.locks.lock().unwrap_or_else(|error| error.into_inner());
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
            let mut cas = self.cas.lock().unwrap_or_else(|error| error.into_inner());
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
                    if matches!(request.expected_token, Some(token) if token < *current_token) {
                        return Ok(CasStoreOutcome::Fenced {
                            current_token: *current_token,
                        });
                    }
                    if request.expected.as_ref().map(|value| value.as_bytes())
                        == Some(current.as_slice())
                    {
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
            *self.calls.lock().unwrap_or_else(|error| error.into_inner())
        }
    }

    impl OutboxBacklog for CountingBacklog {
        async fn sample_backlog(&self, _domain: &str) -> Result<BacklogObservation, EngineError> {
            *self.calls.lock().unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(BacklogObservation::Active(vec![backlog_metric_sample(
                7, 11,
            )]))
        }
    }

    #[derive(Clone, Default)]
    struct CountingSweeper {
        calls: Arc<StdMutex<u64>>,
    }

    impl CountingSweeper {
        fn calls(&self) -> u64 {
            *self.calls.lock().unwrap_or_else(|error| error.into_inner())
        }
    }

    impl RetentionSweeper for CountingSweeper {
        async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
            *self.calls.lock().unwrap_or_else(|error| error.into_inner()) += 1;
            Ok(retain_seconds)
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
        async fn sample_backlog(&self, _domain: &str) -> Result<BacklogObservation, EngineError> {
            self.started.notify_waiters();
            await_delay(Duration::from_secs(1)).await;
            self.completed.store(true, Ordering::SeqCst);
            Ok(BacklogObservation::Active(vec![backlog_metric_sample(
                13, 17,
            )]))
        }
    }

    #[tokio::test]
    async fn outbox_backlog_runs_when_coordinator_is_active() -> TestResult {
        let store = FakeDistributedStore::default();
        let backlog = CountingBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), store.coordinator());

        let sample = wrapped.sample_backlog("identity").await?;

        assert_eq!(
            sample,
            BacklogObservation::Active(vec![backlog_metric_sample(7, 11)])
        );
        assert_eq!(backlog.calls(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn retention_sweeper_runs_when_coordinator_is_active() -> TestResult {
        let store = FakeDistributedStore::default();
        let sweeper = CountingSweeper::default();
        let wrapped = CoordinatedRetentionSweeper::new(sweeper.clone(), store.coordinator());

        let deleted = wrapped.sweep(42).await?;

        assert_eq!(deleted, 42);
        assert_eq!(sweeper.calls(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn outbox_backlog_standby_is_explicit_without_calling_inner() -> TestResult {
        let store = FakeDistributedStore::default();
        let first = store.coordinator();
        let _lease = first.try_acquire().await?;
        let backlog = CountingBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), store.coordinator());

        let sample = wrapped.sample_backlog("identity").await?;

        assert_eq!(sample, BacklogObservation::Standby);
        assert_eq!(backlog.calls(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn outbox_backlog_cancels_current_tick_when_lock_renew_is_lost() -> TestResult {
        let store = FakeDistributedStore::losing_on_first_renew();
        let backlog = SlowBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(backlog.clone(), store.coordinator());

        let sample = wrapped.sample_backlog("identity").await?;

        assert_eq!(sample, BacklogObservation::Standby);
        assert_eq!(store.renew_calls(), 1);
        assert!(
            !backlog.completed(),
            "lost lease must cancel the active tick"
        );
        Ok(())
    }
}
