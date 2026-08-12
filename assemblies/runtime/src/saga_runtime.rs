//! Saga worker runtime assembly helpers.

use std::sync::Arc;

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
use eventexec::{SagaRuntimeView, WorkerHealth, saga_executor_probe_name};

use crate::event_transport::WorkerHealthProbe;

/// Bind all assembly-selected, domain-owned Saga providers and emit their lifecycle output.
/// Unknown active definitions remain unconsumed and make the final bind fail closed.
pub(crate) fn bind_and_wire_selected_sagas(
    plan: &mut crate::plan::RuntimePlan,
    write_admission: &primitives::WriteAdmission,
) -> anyhow::Result<(DomainModuleResult, usize)> {
    plan.bind_workflow_runtime(std::iter::empty())
        .context("bind exact plan-selected Saga provider closure")?;
    let mut module = DomainModuleResult::default();
    let sagas = plan.workflow_runtime().sagas();
    let active_count = sagas.entries().len();
    wire_saga_worker(sagas, write_admission, &mut module)?;
    Ok((module, active_count))
}

/// Register only the Saga factories selected and owned by the sealed workflow plan.
/// Factories are invoked inside the worker closure, after activation has been established, so an
/// omitted workflow cannot construct stores, actions, workers or probes.
pub fn wire_saga_worker(
    runtime: SagaRuntimeView<'_>,
    write_admission: &primitives::WriteAdmission,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    for entry in runtime.entries() {
        let factory = entry.spawner();
        let probe_name =
            saga_executor_probe_name(factory.identity()).context("parse saga worker probe name")?;
        let health = Arc::new(WorkerHealth::starting());
        let worker_health = Arc::clone(&health);
        let worker_admission = write_admission.clone();
        let worker_identity = format!(
            "saga:{}:{}",
            factory.identity().owner(),
            factory.identity().contract_id().as_str()
        );
        let worker = WorkerSpec::writes_deferred(
            worker_identity,
            write_admission,
            move |token, _write_admission| factory.spawn(token, worker_health, worker_admission),
        );
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
        let (module, active_count) = bind_and_wire_selected_sagas(
            &mut plan,
            &primitives::prepare_dr_admission_controls().into_parts().3,
        )
        .unwrap();

        assert_eq!(active_count, 0);
        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
    }
}
