//! Distributed active/standby coordination for durable maintenance lanes.
//!
//! The coordinator owns only provider-independent lock/CAS facades and one sealed typed
//! maintenance namespace. Assemblies inject the selected provider ports once through
//! typed [`MaintenanceCoordinator`] constructors, then wrap backlog and retention workers with the
//! move-only typed adapters in this module.
//!
//! ref: kubernetes/client-go tools/leaderelection/leaderelection.go@master

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use consistency::{EngineError, EngineErrorKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio::time;

use crate::cas::{CasOutcome, CasRequest, StateCas};
use crate::{DistError, FencingToken, LockGrant, LockKey, Locker};

#[cfg(test)]
const MAINTENANCE_RENEW_INTERVAL: Duration = Duration::from_millis(5);

mod sealed {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait MaintenanceLane: sealed::Sealed {
    /// Single typed identity owner for lock, CAS, and observability projections.
    const RESOURCE: diport::GlobalCasResource;
}

/// Typed outbox backlog observation lane.
pub struct OutboxBacklogMaintenance;

impl sealed::Sealed for OutboxBacklogMaintenance {}
impl MaintenanceLane for OutboxBacklogMaintenance {
    const RESOURCE: diport::GlobalCasResource = diport::GlobalCasResource::OutboxBacklog;
}

/// Typed outbox retention lane, isolated from the continuously held backlog-observation lease.
pub struct OutboxRetentionMaintenance;

impl sealed::Sealed for OutboxRetentionMaintenance {}
impl MaintenanceLane for OutboxRetentionMaintenance {
    const RESOURCE: diport::GlobalCasResource = diport::GlobalCasResource::OutboxRetention;
}

/// Typed inbox backlog maintenance lane.
pub struct InboxBacklogMaintenance;

impl sealed::Sealed for InboxBacklogMaintenance {}
impl MaintenanceLane for InboxBacklogMaintenance {
    const RESOURCE: diport::GlobalCasResource = diport::GlobalCasResource::InboxBacklog;
}

/// Opaque global CAS key minted only by this sealed maintenance module.
///
/// INVARIANT: CAS-GLOBAL-KEY-SCOPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "sealed MaintenanceLane + private GlobalCasKey field and for_lane mint + MaintenanceCoordinator-owned typed key" }
/// （private mint owner + closed maintenance resource constructors）。
#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct GlobalCasKey(diport::GlobalCasStoreKey);

impl GlobalCasKey {
    fn for_lane<L: MaintenanceLane>(topology_scope_sha256: [u8; 32]) -> Self {
        Self(diport::GlobalCasStoreKey::for_resource(
            L::RESOURCE,
            topology_scope_sha256,
        ))
    }

    pub(crate) fn into_store_key(self) -> diport::GlobalCasStoreKey {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(id: u8) -> Self {
        let mut digest = [0_u8; 32];
        digest[31] = id;
        Self(diport::GlobalCasStoreKey::for_resource(
            diport::GlobalCasResource::OutboxBacklog,
            digest,
        ))
    }
}

impl std::fmt::Debug for GlobalCasKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("GlobalCasKey").field(&"<redacted>").finish()
    }
}

/// Ownership-aware result of one coordinated operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "standby must not be interpreted as an active empty maintenance result"]
pub enum MaintenanceObservation<T> {
    /// This process held the lease and completed the operation.
    Active(T),
    /// This process did not hold, or lost, the lease.
    Standby,
}

/// Maintenance coordinator construction failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MaintenanceCoordinatorError {
    /// An empty scope would collapse unrelated topology owners into one global lane.
    #[error("maintenance topology scope must not be empty")]
    EmptyScope,
}

/// Shared active/standby coordinator for one sealed maintenance lane.
///
/// Construction consumes both provider ports, so a caller cannot produce a coordinator with only
/// locking or only fencing. Clones share the same typed CAS observation and provider facades.
pub struct MaintenanceCoordinator<L> {
    locker: Arc<Mutex<Locker>>,
    state_cas: Arc<Mutex<StateCas>>,
    cas_state: Arc<Mutex<Option<CasState>>>,
    ttl: Duration,
    lock_key: String,
    cas_key: GlobalCasKey,
    lane: PhantomData<fn() -> L>,
}

impl<L> Clone for MaintenanceCoordinator<L> {
    fn clone(&self) -> Self {
        Self {
            locker: Arc::clone(&self.locker),
            state_cas: Arc::clone(&self.state_cas),
            cas_state: Arc::clone(&self.cas_state),
            ttl: self.ttl,
            lock_key: self.lock_key.clone(),
            cas_key: self.cas_key.clone(),
            lane: PhantomData,
        }
    }
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

impl<L: MaintenanceLane> MaintenanceCoordinator<L> {
    fn from_scope_labels(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
        scope_labels: &[&str],
    ) -> Result<Self, MaintenanceCoordinatorError> {
        if scope_labels.is_empty() {
            return Err(MaintenanceCoordinatorError::EmptyScope);
        }
        Ok(Self::from_nonempty_scope_labels(
            lock_store,
            cas_store,
            ttl,
            scope_labels,
        ))
    }

    fn from_nonempty_scope_labels(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
        scope_labels: &[&str],
    ) -> Self {
        let mut labels = scope_labels.to_vec();
        labels.sort_unstable();
        labels.dedup();
        let mut digest = Sha256::new();
        for label in labels {
            digest.update(label.len().to_be_bytes());
            digest.update(label.as_bytes());
        }
        let topology_scope_sha256 = digest.finalize();
        let suffix = format!("{topology_scope_sha256:x}");
        let topology_scope_sha256: [u8; 32] = topology_scope_sha256.into();
        Self {
            locker: Arc::new(Mutex::new(Locker::new(lock_store))),
            state_cas: Arc::new(Mutex::new(StateCas::new(cas_store))),
            cas_state: Arc::new(Mutex::new(None)),
            ttl,
            lock_key: format!("{}/{}", L::RESOURCE.as_str(), suffix),
            cas_key: GlobalCasKey::for_lane::<L>(topology_scope_sha256),
            lane: PhantomData,
        }
    }

    #[allow(clippy::cognitive_complexity)]
    // reason: one acquire must visibly retain lock ownership across CAS Applied/Conflict/Fenced
    // and every release path; splitting it obscures the fencing audit trail.
    async fn try_acquire(&self) -> Result<MaintenanceLease, DistError> {
        let key = LockKey::parse(&self.lock_key).map_err(|error| {
            tracing::warn!(lane = L::RESOURCE.label(), error = %error, "maintenance lock key invalid");
            DistError::Fatal
        })?;
        let grant = {
            let locker = self.locker.lock().await;
            locker.acquire(key, self.ttl).await?
        };
        let Some(grant) = grant else {
            tracing::debug!(
                lane = L::RESOURCE.label(),
                "maintenance standby: distributed lock held by peer"
            );
            return Ok(MaintenanceLease::Standby);
        };

        let new_epoch = MaintenanceEpoch {
            lock_token: grant.token().value(),
        };
        let expected_state = *self.cas_state.lock().await;
        let request = CasRequest {
            key: self.cas_key.clone(),
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
                    tracing::debug!(
                        lane = L::RESOURCE.label(),
                        "maintenance standby: CAS key absent under contention"
                    );
                    return Ok(MaintenanceLease::Standby);
                };
                *self.cas_state.lock().await = Some(CasState {
                    value: current,
                    token: None,
                });
                self.release_best_effort(grant).await;
                tracing::debug!(
                    lane = L::RESOURCE.label(),
                    "maintenance standby: CAS conflict"
                );
                Ok(MaintenanceLease::Standby)
            }
            CasOutcome::Fenced { token } => {
                *self.cas_state.lock().await = None;
                self.release_best_effort(grant).await;
                tracing::debug!(
                    lane = L::RESOURCE.label(),
                    token = token.value(),
                    "maintenance fenced"
                );
                Ok(MaintenanceLease::Standby)
            }
        }
    }

    async fn release_best_effort(&self, grant: LockGrant) {
        let locker = self.locker.lock().await;
        if let Err(error) = locker.release(grant).await {
            tracing::warn!(lane = L::RESOURCE.label(), error = %error, "maintenance lock release failed");
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
            tracing::debug!(
                lane = L::RESOURCE.label(),
                "maintenance lease lost; cancelling current operation"
            );
            return Ok(None);
        };
        Ok(Some(grant))
    }

    fn renew_error_to_engine(error: DistError) -> EngineError {
        tracing::warn!(lane = L::RESOURCE.label(), error = %error, "maintenance lock renew failed");
        EngineError::new(EngineErrorKind::Transient)
    }

    fn renew_interval(ttl: Duration) -> Duration {
        #[cfg(test)]
        {
            let _ = ttl;
            MAINTENANCE_RENEW_INTERVAL
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
                tracing::warn!(lane = L::RESOURCE.label(), error = %error, "distributed maintenance coordinator failed");
                Err(EngineError::new(EngineErrorKind::Transient))
            }
        }
    }

    /// Run an operation only while this process owns the typed maintenance lease.
    pub async fn run_active<T, F>(
        &self,
        operation: F,
    ) -> Result<MaintenanceObservation<T>, EngineError>
    where
        F: Future<Output = Result<T, EngineError>>,
    {
        let Some(mut grant) = self.try_run_active().await? else {
            return Ok(MaintenanceObservation::Standby);
        };

        let interval = Self::renew_interval(grant.ttl());
        let mut renew_sleep = Box::pin(time::sleep(interval));
        tokio::pin!(operation);

        loop {
            tokio::select! {
                result = &mut operation => {
                    self.release_best_effort(grant).await;
                    return result.map(MaintenanceObservation::Active);
                }
                () = &mut renew_sleep => {
                    let renewed = match self.renew_or_stop(&grant).await {
                        Ok(renewed) => renewed,
                        Err(error) => {
                            self.release_best_effort(grant).await;
                            return Err(error);
                        }
                    };
                    match renewed {
                        Some(renewed) => {
                            grant = renewed;
                            renew_sleep = Box::pin(time::sleep(interval));
                        }
                        None => {
                            self.release_best_effort(grant).await;
                            return Ok(MaintenanceObservation::Standby);
                        }
                    }
                }
            }
        }
    }
}

impl MaintenanceCoordinator<OutboxBacklogMaintenance> {
    /// Bind ownership to the exact canonical domain selection consumed by the sampler.
    pub fn for_domains(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
        domains: &[vocab::DomainName],
    ) -> Result<Self, MaintenanceCoordinatorError> {
        let labels = domains
            .iter()
            .map(vocab::DomainName::as_str)
            .collect::<Vec<_>>();
        Self::from_scope_labels(lock_store, cas_store, ttl, &labels)
    }
}

impl MaintenanceCoordinator<InboxBacklogMaintenance> {
    /// Bind ownership to the exact canonical consumer-group selection consumed by the sampler.
    pub fn for_consumer_groups(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
        groups: &[rss_transactional_messaging::inbox::ConsumerGroup],
    ) -> Result<Self, MaintenanceCoordinatorError> {
        let labels = groups
            .iter()
            .map(rss_transactional_messaging::inbox::ConsumerGroup::as_str)
            .collect::<Vec<_>>();
        Self::from_scope_labels(lock_store, cas_store, ttl, &labels)
    }
}

impl MaintenanceCoordinator<OutboxRetentionMaintenance> {
    /// Retention has one fixed typed scope and exposes no caller-provided namespace material.
    #[must_use]
    pub fn for_retention(
        lock_store: Box<diport::DynLockStore<'static>>,
        cas_store: Box<diport::DynCasStore<'static>>,
        ttl: Duration,
    ) -> Self {
        Self::from_nonempty_scope_labels(lock_store, cas_store, ttl, &["outbox-retention"])
    }
}

enum MaintenanceLease {
    Active { grant: LockGrant },
    Standby,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use diport::{CasStore, CasStoreOutcome, LockAcquireOutcome, LockRenewOutcome, LockStore};
    use tokio::sync::Notify;

    type LockMap = HashMap<String, (Option<vocab::Epoch>, u64)>;
    type CasMap = HashMap<String, (Vec<u8>, vocab::Epoch)>;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[derive(Clone, Default)]
    struct FakeDistributedStore {
        locks: Arc<StdMutex<LockMap>>,
        cas: Arc<StdMutex<CasMap>>,
        renew_calls: Arc<StdMutex<u64>>,
        lose_after_renewals: Arc<StdMutex<Option<u64>>>,
        error_after_renewals: Arc<StdMutex<Option<u64>>>,
    }

    impl FakeDistributedStore {
        fn coordinator_for<L: MaintenanceLane>(&self) -> MaintenanceCoordinator<L> {
            MaintenanceCoordinator::from_nonempty_scope_labels(
                diport::DynLockStore::new_box(self.clone()),
                diport::DynCasStore::new_box(self.clone()),
                Duration::from_secs(30),
                &["test"],
            )
        }
    }

    #[tokio::test]
    async fn typed_maintenance_lanes_use_distinct_lock_and_cas_namespaces() -> TestResult {
        let store = FakeDistributedStore::default();
        let outbox: MaintenanceCoordinator<OutboxBacklogMaintenance> = store.coordinator_for();
        let retention: MaintenanceCoordinator<OutboxRetentionMaintenance> = store.coordinator_for();
        let inbox: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        assert_eq!(
            outbox
                .run_active(async { Ok::<_, EngineError>(()) })
                .await?,
            MaintenanceObservation::Active(())
        );
        assert_eq!(
            retention
                .run_active(async { Ok::<_, EngineError>(()) })
                .await?,
            MaintenanceObservation::Active(())
        );
        assert_eq!(
            inbox.run_active(async { Ok::<_, EngineError>(()) }).await?,
            MaintenanceObservation::Active(())
        );
        let locks = store
            .locks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        const TEST_SCOPE_SHA256: &str =
            "09a7d352412717c7e0b93286eb544f83ddf6da4260b795e90aa44e8e58f5dadd";
        let expected_keys = [
            format!("runtime/event/outbox-backlog/{TEST_SCOPE_SHA256}"),
            format!("runtime/event/outbox-retention/{TEST_SCOPE_SHA256}"),
            format!("runtime/event/inbox-backlog/{TEST_SCOPE_SHA256}"),
        ];
        assert_eq!(locks.len(), expected_keys.len());
        for key in &expected_keys {
            assert!(locks.contains_key(key), "missing physical lock key {key}");
        }
        drop(locks);
        let cas = store.cas.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(cas.len(), expected_keys.len());
        for key in &expected_keys {
            assert!(cas.contains_key(key), "missing physical CAS key {key}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn distinct_topology_scopes_do_not_block_each_other() -> TestResult {
        let store = FakeDistributedStore::default();
        let identity_group =
            rss_transactional_messaging::inbox::ConsumerGroup::parse("audit.session-created")?;
        let settings_group = rss_transactional_messaging::inbox::ConsumerGroup::parse(
            "settings.config-version-changed",
        )?;
        let identity = MaintenanceCoordinator::<InboxBacklogMaintenance>::for_consumer_groups(
            diport::DynLockStore::new_box(store.clone()),
            diport::DynCasStore::new_box(store.clone()),
            Duration::from_secs(30),
            std::slice::from_ref(&identity_group),
        )?;
        let settings = MaintenanceCoordinator::<InboxBacklogMaintenance>::for_consumer_groups(
            diport::DynLockStore::new_box(store.clone()),
            diport::DynCasStore::new_box(store),
            Duration::from_secs(30),
            std::slice::from_ref(&settings_group),
        )?;
        let (left, right) = tokio::join!(
            identity.run_active(async { Ok::<_, EngineError>(()) }),
            settings.run_active(async { Ok::<_, EngineError>(()) })
        );
        assert_eq!(left?, MaintenanceObservation::Active(()));
        assert_eq!(right?, MaintenanceObservation::Active(()));
        Ok(())
    }

    #[test]
    fn empty_topology_scope_is_rejected() {
        let store = FakeDistributedStore::default();
        let result = MaintenanceCoordinator::<InboxBacklogMaintenance>::for_consumer_groups(
            diport::DynLockStore::new_box(store.clone()),
            diport::DynCasStore::new_box(store),
            Duration::from_secs(30),
            &[],
        );
        assert!(matches!(
            result,
            Err(MaintenanceCoordinatorError::EmptyScope)
        ));
    }

    #[tokio::test]
    async fn lease_covers_long_lived_session_and_peer_takes_over_after_release() -> TestResult {
        let store = FakeDistributedStore::default();
        let owner: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        let peer: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let owner_run = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            async move {
                owner
                    .run_active(async move {
                        entered.notify_one();
                        release.notified().await;
                        Ok::<_, EngineError>(())
                    })
                    .await
            }
        };
        let peer_attempt = async {
            entered.notified().await;
            let observation = peer.run_active(async { Ok::<_, EngineError>(()) }).await;
            release.notify_one();
            observation
        };
        let (owner_result, peer_result) = tokio::join!(owner_run, peer_attempt);
        assert_eq!(owner_result?, MaintenanceObservation::Active(()));
        assert_eq!(
            peer_result?,
            MaintenanceObservation::Standby,
            "peer must remain standby while the full sampling session owns the lease"
        );
        assert_eq!(
            peer.run_active(async { Ok::<_, EngineError>(()) }).await?,
            MaintenanceObservation::Standby,
            "first post-release CAS observation synchronizes the peer epoch"
        );
        assert_eq!(
            peer.run_active(async { Ok::<_, EngineError>(()) }).await?,
            MaintenanceObservation::Active(()),
            "peer becomes the sole active owner after synchronization"
        );
        Ok(())
    }

    struct DropWitness(Arc<AtomicBool>);

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn first_renewal_loss_cancels_operation_releases_lock_and_allows_takeover() -> TestResult
    {
        let store = FakeDistributedStore::default();
        *store
            .lose_after_renewals
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(0);
        let owner: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        let cancelled = Arc::new(AtomicBool::new(false));

        let observation = owner
            .run_active({
                let cancelled = Arc::clone(&cancelled);
                async move {
                    let _witness = DropWitness(cancelled);
                    std::future::pending::<Result<(), EngineError>>().await
                }
            })
            .await?;

        assert_eq!(observation, MaintenanceObservation::Standby);
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(
            *store
                .renew_calls
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
            1
        );
        assert!(
            store
                .locks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .values()
                .all(|(held, _)| held.is_none()),
            "lost owner must not retain a process-local lease witness"
        );

        *store
            .lose_after_renewals
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        let peer: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        assert_eq!(
            peer.run_active(async { Ok::<_, EngineError>(()) }).await?,
            MaintenanceObservation::Standby
        );
        assert_eq!(
            peer.run_active(async { Ok::<_, EngineError>(()) }).await?,
            MaintenanceObservation::Active(())
        );
        Ok(())
    }

    #[tokio::test]
    async fn first_renewal_error_cancels_operation_and_returns_transient() -> TestResult {
        let store = FakeDistributedStore::default();
        *store
            .error_after_renewals
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(0);
        let owner: MaintenanceCoordinator<InboxBacklogMaintenance> = store.coordinator_for();
        let cancelled = Arc::new(AtomicBool::new(false));

        let result = owner
            .run_active({
                let cancelled = Arc::clone(&cancelled);
                async move {
                    let _witness = DropWitness(cancelled);
                    std::future::pending::<Result<(), EngineError>>().await
                }
            })
            .await;

        assert!(matches!(
            result,
            Err(error) if error.kind() == EngineErrorKind::Transient
        ));
        assert!(cancelled.load(Ordering::Acquire));
        assert!(
            store
                .locks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .values()
                .all(|(held, _)| held.is_none())
        );
        Ok(())
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
            let should_error = {
                let error_after = self
                    .error_after_renewals
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                matches!(*error_after, Some(max_renewals) if call >= max_renewals)
            };
            if should_error {
                return Err(diport::LockStoreError::new(std::io::Error::other(
                    "synthetic renewal failure",
                )));
            }
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
}
