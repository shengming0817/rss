//! Saga worker runtime assembly helpers.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
use eventexec::{
    SagaDefinitionRegistry, SagaExecutorConfig, SagaExecutorDeps, SagaExecutorImpl,
    SagaRuntimeView, WorkerHealth, saga_executor_probe_name,
};

use crate::event_transport::WorkerHealthProbe;

pub(crate) const SAGA_RECEIPT_INTEGRITY_KEY_ENV: &str = "RSS_SAGA_RECEIPT_INTEGRITY_KEY_B64URL";

/// Secret/provider half needed only when the plan actually selects an active Saga.
pub(crate) struct SagaProviderDependencies {
    pub(crate) receipt_key_provider: Box<diport::DynKeyProvider<'static>>,
    pub(crate) receipt_integrity_key_b64url: String,
    pub(crate) dead_letter_protector: postgres::DlxPayloadProtector,
    pub(crate) worker_config: eventexec::SagaWorkerConfig,
}

/// Bind all assembly-selected, domain-owned Saga providers and emit their lifecycle output.
/// Unknown active definitions remain unconsumed and make the final bind fail closed.
pub(crate) fn bind_and_wire_selected_sagas(
    plan: &mut crate::plan::RuntimePlan,
    pg: &postgres::PgRuntimeHandle,
    dependencies: impl FnOnce() -> anyhow::Result<SagaProviderDependencies>,
) -> anyhow::Result<(DomainModuleResult, usize)> {
    let mut capabilities = Vec::new();
    if let Some(permit) = plan
        .take_saga_activation_permit(generated::saga::audit_v1::CONTRACT_ID)
        .context("select audit-owned synthetic Saga permit")?
    {
        let dependencies = dependencies()?;
        capabilities.push(bind_audit_provider(permit, pg, dependencies)?);
    }
    plan.bind_workflow_runtime(capabilities)
        .context("bind exact plan-selected Saga provider closure")?;
    let mut module = DomainModuleResult::default();
    let sagas = plan.workflow_runtime().sagas();
    let active_count = sagas.entries().len();
    wire_saga_worker(sagas, &mut module)?;
    Ok((module, active_count))
}

fn bind_audit_provider(
    permit: eventexec::SagaActivationPermit,
    pg: &postgres::PgRuntimeHandle,
    dependencies: SagaProviderDependencies,
) -> anyhow::Result<eventexec::SagaRuntimeCapability> {
    let integrity_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(dependencies.receipt_integrity_key_b64url.as_bytes())
        .with_context(|| format!("{SAGA_RECEIPT_INTEGRITY_KEY_ENV} must be base64url"))?;
    let integrity = secure::SagaReceiptIntegrityKeyring::new(
        secure::VersionedSagaReceiptIntegrityKey::new(
            secure::SagaReceiptIntegrityKeyId::parse("saga-receipt-v1")?,
            secure::RedactionHashKey::from_bytes(integrity_bytes).with_context(|| {
                format!("{SAGA_RECEIPT_INTEGRITY_KEY_ENV} must decode to at least 32 bytes")
            })?,
        ),
        Vec::new(),
    )?;
    let infra = pg.infra();
    let store = Arc::new(
        infra.saga_durable_store(postgres::PgSagaReceiptProtection::new(
            dependencies.receipt_key_provider,
            integrity,
        )),
    );
    let dead_letter = Arc::new(infra.dead_letter(dependencies.dead_letter_protector));
    let factory = audit::saga::synthetic_activation_factory();
    let config = SagaExecutorConfig::from_typed_factory(
        diport::CheckpointOwner::new("audit"),
        "runtime-audit-synthetic-activation",
        Duration::from_secs(30),
        &factory,
    )?;
    let identity = config.identity().clone();
    let registry = SagaDefinitionRegistry::builder()
        .register(factory)?
        .finish();
    let executor = Arc::new(SagaExecutorImpl::new(
        SagaExecutorDeps::new(Arc::clone(&store), dead_letter, registry),
        config,
    )?);
    let operator = executor.operator_service();
    eventexec::SagaRuntimeCapability::bind_worker(
        permit,
        identity,
        Arc::clone(&store),
        store,
        executor,
        Arc::new(crate::support::SystemClock),
        dependencies.worker_config,
        operator,
    )
    .map_err(Into::into)
}

/// Register only the Saga factories selected and owned by the sealed workflow plan.
/// Factories are invoked inside the worker closure, after activation has been established, so an
/// omitted workflow cannot construct stores, actions, workers or probes.
pub fn wire_saga_worker(
    runtime: SagaRuntimeView<'_>,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    for entry in runtime.entries() {
        let factory = entry.spawner();
        let probe_name =
            saga_executor_probe_name(factory.identity()).context("parse saga worker probe name")?;
        let health = Arc::new(WorkerHealth::starting());
        let worker_health = Arc::clone(&health);
        let worker = WorkerSpec::deferred(move |token| factory.spawn(token, worker_health));
        module.workers.push(worker);
        module.probes.push((
            probe_name.clone(),
            Box::new(WorkerHealthProbe::new(probe_name, health)),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn omitted_saga_cannot_construct_worker_or_probe() {
        let snapshot = crate::config::test_snapshot(&[
            ("RSS_PRIMARY_TOKEN_PROFILE", "rss-access"),
            ("RSS_ADMIN_TOKEN_PROFILE", "rss-access"),
            ("RSS_INTERNAL_AUTH_SCHEME", "mtls"),
        ])
        .unwrap();
        let mut plan = crate::plan::RuntimePlan::bundled(snapshot.view()).unwrap();
        plan.bind_workflow_runtime(std::iter::empty()).unwrap();
        let mut module = DomainModuleResult::default();

        wire_saga_worker(plan.workflow_runtime().sagas(), &mut module).unwrap();

        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
    }
}
