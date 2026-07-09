//! Saga worker runtime assembly helpers.

use std::sync::Arc;

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
use diport::{DynManagedResource, SagaInstanceStore, SagaTenantSource, SagaWorkerIdentity};
use eventexec::{
    SagaExecutor, SagaWorkerConfig, WorkerHealth, saga_executor_probe_name, spawn_saga_worker,
};

use crate::event_transport::WorkerHealthProbe;

/// Register one saga worker and its readyz probe as an inseparable pair.
pub fn wire_saga_worker<T, S, E>(
    module: &mut DomainModuleResult,
    identity: SagaWorkerIdentity,
    tenant_source: Arc<T>,
    instance_store: Arc<S>,
    executor: Arc<E>,
    config: SagaWorkerConfig,
) -> anyhow::Result<()>
where
    T: SagaTenantSource + Send + Sync + 'static,
    S: SagaInstanceStore + Send + Sync + 'static,
    E: SagaExecutor + Send + Sync + 'static,
{
    let health = Arc::new(WorkerHealth::starting());
    let probe_name = saga_executor_probe_name(&identity).context("parse saga worker probe name")?;
    let worker_health = health.clone();
    let worker: WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_saga_worker(
            identity,
            tenant_source,
            instance_store,
            executor,
            config,
            token,
            worker_health,
        ))
    });
    module.workers.push(worker);
    module.probes.push((
        probe_name.clone(),
        Box::new(WorkerHealthProbe::new(probe_name, health)),
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;
    use std::time::Duration;

    use consistency::{
        SagaInstanceRecord, SagaInstanceRef, SagaInstanceStatus, SagaLease, SagaLeaseOutcome,
    };
    use diport::{
        SagaContractId, SagaInstanceRegistration, SagaInstanceStoreError, SagaRunnableInstance,
    };
    use eventexec::SagaOutcome;
    use futures::future::BoxFuture;
    use primitives::healthz::HealthStatus;

    use super::*;

    struct NoopTenantSource;

    impl SagaTenantSource for NoopTenantSource {
        async fn list_candidate_tenants(
            &self,
            _identity: &SagaWorkerIdentity,
            _limit: NonZeroUsize,
        ) -> Result<Vec<vocab::TenantId>, SagaInstanceStoreError> {
            Ok(Vec::new())
        }
    }

    struct NoopStore;

    impl SagaInstanceStore for NoopStore {
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
            Ok(Vec::new())
        }

        async fn shutdown(&self) -> Result<(), SagaInstanceStoreError> {
            Ok(())
        }
    }

    struct NoopExecutor;

    impl SagaExecutor for NoopExecutor {
        fn run(&self, _instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
            Box::pin(async { SagaOutcome::Succeeded { output: Vec::new() } })
        }

        fn resume(&self, _instance: SagaInstanceRef) -> BoxFuture<'static, SagaOutcome> {
            Box::pin(async { SagaOutcome::Succeeded { output: Vec::new() } })
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn saga_worker_registration_pushes_worker_and_probe_together() {
        let mut module = DomainModuleResult::default();
        wire_saga_worker(
            &mut module,
            identity(),
            Arc::new(NoopTenantSource),
            Arc::new(NoopStore),
            Arc::new(NoopExecutor),
            SagaWorkerConfig::default(),
        )
        .unwrap();

        assert_eq!(module.workers.len(), 1);
        assert_eq!(module.probes.len(), 1);
        assert_eq!(
            module.probes[0].0.as_str(),
            "saga_executor:billing__billing_checkout"
        );
        assert_eq!(module.probes[0].1.check().status(), HealthStatus::Unhealthy);
    }

    #[test]
    fn empty_module_has_no_saga_probe() {
        let module = DomainModuleResult::default();
        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
    }

    #[allow(clippy::unwrap_used)]
    fn identity() -> SagaWorkerIdentity {
        SagaWorkerIdentity::new(
            "billing",
            SagaContractId::parse("billing.checkout").unwrap(),
        )
        .unwrap()
    }
}
