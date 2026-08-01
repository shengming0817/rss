use std::sync::Arc;

fn bind_without_store<T, S, E>(
    permit: eventexec::SagaActivationPermit,
    identity: diport::SagaWorkerIdentity,
    tenant_source: Arc<T>,
    executor: Arc<E>,
    clock: Arc<dyn diport::Clock>,
    config: eventexec::SagaWorkerConfig,
    operator_service: eventexec::SagaOperatorService<S>,
) where
    T: diport::SagaTenantSource + Send + Sync + 'static,
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
    E: eventexec::SagaExecutor + eventexec::SagaStartPort + Send + Sync + 'static,
{
    let _ = eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        tenant_source,
        executor,
        clock,
        config,
        operator_service,
    );
}

fn main() {}
