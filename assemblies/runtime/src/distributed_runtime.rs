//! distributed runtime wiring and the first production consumer.
//!
//! The composition root owns provider construction: Redis supplies the distributed lock provider
//! and Postgres supplies state-CAS. Consumers receive [`DistributedRuntimeDeps`] as a required type,
//! so removing the distributed wiring is a compile-time failure.

use std::sync::Arc;
use std::time::Duration;

use distributed::HttpContractTransport;

pub use distributed::{
    CoordinatedRetentionSweeper, InboxBacklogMaintenance, MaintenanceCoordinator,
    MaintenanceObservation, OutboxBacklogMaintenance, OutboxRetentionMaintenance,
};

use crate::SharedRuntimeDeps;

const DEFAULT_MAINTENANCE_TTL: Duration = Duration::from_secs(30);

/// Exact, non-optional timing owned by the process configuration snapshot.
#[derive(Clone, Copy)]
pub(crate) struct DistributedWorkerConfig {
    maintenance_ttl: Duration,
}

impl DistributedWorkerConfig {
    /// Preserve the existing non-configurable distributed maintenance timing.
    pub(crate) const fn canonical() -> Self {
        Self {
            maintenance_ttl: DEFAULT_MAINTENANCE_TTL,
        }
    }
}

/// Hard-wired distributed runtime dependencies.
#[derive(Clone)]
pub struct DistributedRuntimeDeps {
    lock_store: Arc<dyn Fn() -> Box<diport::DynLockStore<'static>> + Send + Sync>,
    cas_store: Arc<dyn Fn() -> Box<diport::DynCasStore<'static>> + Send + Sync>,
    maintenance_ttl: Duration,
    domain_transport: Arc<dyn HttpContractTransport>,
}

impl DistributedRuntimeDeps {
    /// Coordinator for the durable event outbox maintenance workers.
    #[must_use]
    pub fn outbox_maintenance_coordinator(
        &self,
        domains: &[vocab::DomainName],
    ) -> Result<
        MaintenanceCoordinator<OutboxBacklogMaintenance>,
        distributed::MaintenanceCoordinatorError,
    > {
        MaintenanceCoordinator::for_domains(
            (self.lock_store)(),
            (self.cas_store)(),
            self.maintenance_ttl,
            domains,
        )
    }

    /// Coordinator for outbox retention, isolated from the continuously owned sampler lane.
    #[must_use]
    pub fn outbox_retention_coordinator(
        &self,
    ) -> MaintenanceCoordinator<OutboxRetentionMaintenance> {
        MaintenanceCoordinator::for_retention(
            (self.lock_store)(),
            (self.cas_store)(),
            self.maintenance_ttl,
        )
    }

    /// Coordinator for the inbox backlog sampler.
    #[must_use]
    pub fn inbox_backlog_maintenance_coordinator(
        &self,
        groups: &[consistency::ConsumerGroup],
    ) -> Result<
        MaintenanceCoordinator<InboxBacklogMaintenance>,
        distributed::MaintenanceCoordinatorError,
    > {
        MaintenanceCoordinator::for_consumer_groups(
            (self.lock_store)(),
            (self.cas_store)(),
            self.maintenance_ttl,
            groups,
        )
    }

    /// Shared outbound domain transport dispatch seam.
    #[must_use]
    pub fn domain_transport(&self) -> Arc<dyn HttpContractTransport> {
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
    let redis = deps.redis.clone();
    let pg = deps.pg.clone();
    Ok(DistributedRuntimeDeps {
        lock_store: Arc::new(move || redis.infra().lock_store()),
        cas_store: Arc::new(move || pg.infra().cas_store()),
        maintenance_ttl: worker.maintenance_ttl,
        domain_transport: Arc::clone(&deps.domain_transport),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use diport::{CasStore, CasStoreOutcome, LockAcquireOutcome, LockRenewOutcome, LockStore};
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::{Arc, Mutex as StdMutex};

    type LockMap = HashMap<String, (Option<vocab::Epoch>, u64)>;
    type CasMap = HashMap<String, (Vec<u8>, vocab::Epoch)>;

    struct NoopDomainTransport;

    impl distributed::HttpContractTransport for NoopDomainTransport {
        fn dispatch(
            &self,
            _request: distributed::HttpContractRequest,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            distributed::HttpContractResponse,
                            distributed::HttpContractTransportError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async { distributed::HttpContractResponse::try_new(204, Vec::new()) })
        }
    }

    #[derive(Clone, Default)]
    struct FakeDistributedStore {
        locks: Arc<StdMutex<LockMap>>,
        cas: Arc<StdMutex<CasMap>>,
        renew_calls: Arc<StdMutex<u64>>,
        lose_after_renewals: Arc<StdMutex<Option<u64>>>,
    }

    impl FakeDistributedStore {
        fn deps(&self) -> DistributedRuntimeDeps {
            let lock_store = self.clone();
            let cas_store = self.clone();
            DistributedRuntimeDeps {
                lock_store: Arc::new(move || diport::DynLockStore::new_box(lock_store.clone())),
                cas_store: Arc::new(move || diport::DynCasStore::new_box(cas_store.clone())),
                maintenance_ttl: Duration::from_millis(15),
                domain_transport: Arc::new(NoopDomainTransport),
            }
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

    #[test]
    fn distributed_runtime_deps_exposes_domain_transport_handle() {
        let deps = FakeDistributedStore::default().deps();
        let first = deps.domain_transport();
        let second = deps.domain_transport();

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn inbox_coordinator_namespace_is_derived_from_typed_local_selection()
    -> anyhow::Result<()> {
        let store = FakeDistributedStore::default();
        let deps = store.deps();
        let audit = consistency::ConsumerGroup::parse("audit.session-created")?;
        let settings = consistency::ConsumerGroup::parse("settings.config-version-changed")?;
        let first = deps.inbox_backlog_maintenance_coordinator(std::slice::from_ref(&audit))?;
        let same = deps.inbox_backlog_maintenance_coordinator(std::slice::from_ref(&audit))?;
        let distinct =
            deps.inbox_backlog_maintenance_coordinator(std::slice::from_ref(&settings))?;

        assert_eq!(
            first
                .run_active(async { Ok::<_, consistency::EngineError>(()) })
                .await?,
            MaintenanceObservation::Active(())
        );
        let key_count_after_first = store
            .locks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        assert_eq!(
            same.run_active(async { Ok::<_, consistency::EngineError>(()) })
                .await?,
            MaintenanceObservation::Standby,
            "a fresh peer first synchronizes the existing CAS epoch"
        );
        assert_eq!(
            store
                .locks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            key_count_after_first,
            "the same typed selection must reuse the exact namespace"
        );
        assert_eq!(
            same.run_active(async { Ok::<_, consistency::EngineError>(()) })
                .await?,
            MaintenanceObservation::Active(()),
            "the synchronized peer can take over the same namespace"
        );
        assert_eq!(
            distinct
                .run_active(async { Ok::<_, consistency::EngineError>(()) })
                .await?,
            MaintenanceObservation::Active(())
        );
        assert_eq!(
            store
                .locks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .len(),
            key_count_after_first + 1,
            "a distinct typed local selection must use a distinct namespace"
        );
        Ok(())
    }
}
