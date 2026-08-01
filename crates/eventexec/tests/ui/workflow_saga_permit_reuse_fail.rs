use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
fn bind_twice<T, S, E>(
    permit: eventexec::SagaActivationPermit,
    identity: diport::SagaWorkerIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    executor: Arc<E>,
    clock: Arc<dyn diport::Clock>,
    config: eventexec::SagaWorkerConfig,
    operator_service: eventexec::SagaOperatorService<S>,
) where
    T: diport::SagaTenantSource + Send + Sync + 'static,
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
    E: eventexec::SagaExecutor + eventexec::SagaStartPort + Send + Sync + 'static,
{
    let _first = eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity.clone(),
        Arc::clone(&tenant_source),
        Arc::clone(&durable_store),
        Arc::clone(&executor),
        Arc::clone(&clock),
        config,
        operator_service.clone(),
    );
    let _second = eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        tenant_source,
        durable_store,
        executor,
        clock,
        config,
        operator_service,
    );
}

fn main() {}
