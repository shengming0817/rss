//! Saga worker runtime assembly helpers.

use std::sync::Arc;

use anyhow::Context as _;
use bootstrap::{DomainModuleResult, WorkerSpec};
use eventexec::{SagaRuntimeView, WorkerHealth, saga_executor_probe_name};

use crate::event_transport::WorkerHealthProbe;

/// Register only the Saga factories selected and owned by the sealed workflow plan.
/// Factories are invoked inside the worker closure, after activation has been established, so an
/// omitted workflow cannot construct stores, actions, workers or probes.
pub fn wire_saga_worker(
    runtime: SagaRuntimeView<'_>,
    module: &mut DomainModuleResult,
) -> anyhow::Result<()> {
    for entry in runtime.entries() {
        let factory = Arc::clone(entry.runtime_factory());
        let probe_name =
            saga_executor_probe_name(factory.identity()).context("parse saga worker probe name")?;
        let health = Arc::new(WorkerHealth::starting());
        let worker_health = Arc::clone(&health);
        let worker: WorkerSpec = Box::new(move |token| factory.spawn(token, worker_health));
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
        let plan = crate::plan::RuntimePlan::bundled(snapshot.view()).unwrap();
        let mut module = DomainModuleResult::default();

        wire_saga_worker(plan.workflow_runtime().sagas(), &mut module).unwrap();

        assert!(module.probes.is_empty());
        assert!(module.workers.is_empty());
    }
}
