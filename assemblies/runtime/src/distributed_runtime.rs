//! distributed runtime wiring and the first production consumer.
//!
//! The composition root owns provider construction: Redis supplies the distributed lock provider
//! and Postgres supplies state-CAS. Consumers receive [`DistributedRuntimeDeps`] as a required type,
//! so removing the distributed wiring is a compile-time failure.

use std::sync::Arc;
use std::time::Duration;

use distributed::HttpContractTransport;

pub use distributed::{
    CoordinatedOutboxBacklog, CoordinatedRetentionSweeper, OutboxMaintenanceCoordinator,
};

use crate::SharedRuntimeDeps;

const DEFAULT_OUTBOX_MAINTENANCE_TTL: Duration = Duration::from_secs(30);

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
    outbox_maintenance: OutboxMaintenanceCoordinator,
    domain_transport: Arc<dyn HttpContractTransport>,
}

impl DistributedRuntimeDeps {
    /// Coordinator for the durable event outbox maintenance workers.
    #[must_use]
    pub fn outbox_maintenance_coordinator(&self) -> OutboxMaintenanceCoordinator {
        self.outbox_maintenance.clone()
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
    Ok(DistributedRuntimeDeps {
        outbox_maintenance: OutboxMaintenanceCoordinator::from_ports(
            deps.redis.infra().lock_store(),
            deps.pg.infra().cas_store(),
            worker.outbox_maintenance_ttl,
        ),
        domain_transport: Arc::clone(&deps.domain_transport),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Notify;

    use consistency::{
        BacklogMetricSample, BacklogObservation, BacklogSample, EngineError, OutboxBacklog,
        OutboxContractId, OutboxMetricSubject,
    };
    use diport::{CasStore, CasStoreOutcome, LockAcquireOutcome, LockRenewOutcome, LockStore};
    use testkit::await_delay;

    type LockMap = HashMap<String, (Option<vocab::Epoch>, u64)>;
    type CasMap = HashMap<String, (Vec<u8>, vocab::Epoch)>;
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

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
                outbox_maintenance: OutboxMaintenanceCoordinator::from_ports(
                    diport::DynLockStore::new_box(self.clone()),
                    diport::DynCasStore::new_box(self.clone()),
                    Duration::from_millis(15),
                ),
                domain_transport: Arc::new(NoopDomainTransport),
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
        async fn sample_backlog(&self, _domain: &str) -> Result<BacklogObservation, EngineError> {
            *self.calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            Ok(BacklogObservation::Active(vec![backlog_metric_sample(
                7, 11,
            )]))
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
            self.started.notify_one();
            await_delay(Duration::from_secs(1)).await;
            self.completed.store(true, Ordering::SeqCst);
            Ok(BacklogObservation::Active(vec![backlog_metric_sample(
                13, 17,
            )]))
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

        assert_eq!(
            sample,
            BacklogObservation::Active(vec![backlog_metric_sample(7, 11)])
        );
        assert_eq!(backlog.calls(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn outbox_backlog_standby_is_explicit_without_calling_inner() -> TestResult {
        let store = FakeDistributedStore::default();
        let active = SlowBacklog::default();
        let active_started = Arc::clone(&active.started);
        let first =
            CoordinatedOutboxBacklog::new(active, store.deps().outbox_maintenance_coordinator());
        let backlog = CountingBacklog::default();
        let wrapped = CoordinatedOutboxBacklog::new(
            backlog.clone(),
            store.deps().outbox_maintenance_coordinator(),
        );

        let (active_result, standby_result) =
            tokio::join!(first.sample_backlog("identity"), async {
                active_started.notified().await;
                wrapped.sample_backlog("identity").await
            });
        let _active = active_result?;
        let sample = standby_result?;

        assert_eq!(sample, BacklogObservation::Standby);
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

        assert_eq!(sample, BacklogObservation::Standby);
        assert_eq!(store.renew_calls(), 1);
        assert!(
            !backlog.completed(),
            "lost lease must cancel the active tick"
        );
        Ok(())
    }
}
