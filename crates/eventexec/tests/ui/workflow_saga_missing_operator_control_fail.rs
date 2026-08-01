use std::sync::Arc;

fn bind_without_operator_control<T, S, E>(
    permit: eventexec::SagaActivationPermit,
    identity: diport::SagaWorkerIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    executor: Arc<E>,
    clock: Arc<dyn diport::Clock>,
    config: eventexec::SagaWorkerConfig,
) where
    T: diport::SagaTenantSource + Send + Sync + 'static,
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
    E: eventexec::SagaExecutor + eventexec::SagaStartPort + Send + Sync + 'static,
{
    let _ = eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        tenant_source,
        durable_store,
        executor,
        clock,
        config,
    );
}

fn main() {}
