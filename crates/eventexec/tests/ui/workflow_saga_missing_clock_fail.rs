use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
fn bind_without_clock<T, S, E>(
    permit: eventexec::SagaActivationPermit,
    identity: diport::SagaWorkerIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    executor: Arc<E>,
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
        durable_store,
        executor,
        config,
        operator_service,
    );
}

fn main() {}
