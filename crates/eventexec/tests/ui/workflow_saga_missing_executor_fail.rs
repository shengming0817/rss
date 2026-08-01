use std::sync::Arc;

fn bind_without_executor<T, S>(
    permit: eventexec::SagaActivationPermit,
    identity: diport::SagaWorkerIdentity,
    tenant_source: Arc<T>,
    durable_store: Arc<S>,
    clock: Arc<dyn diport::Clock>,
    config: eventexec::SagaWorkerConfig,
    operator_service: eventexec::SagaOperatorService<S>,
) where
    T: diport::SagaTenantSource + Send + Sync + 'static,
    S: diport::SagaDurableStore + diport::SagaOperatorStore + Send + Sync + 'static,
{
    let _ = eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        tenant_source,
        durable_store,
        clock,
        config,
        operator_service,
    );
}

fn main() {}
