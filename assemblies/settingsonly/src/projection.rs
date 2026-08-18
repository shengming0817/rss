//! Assembly-owned lifecycle batch for the selected Settings active projection.

use std::sync::Arc;

use anyhow::Context as _;

const SETTINGS_PROJECTION_ID: &str = generated::projection::settings_v3::CONTRACT_ID;

/// Opaque exact batch: callers can stage it only as one worker/probe lifecycle unit.
pub(crate) struct ProjectionLifecycleBatch(bootstrap::DomainModuleResult);

impl ProjectionLifecycleBatch {
    pub(crate) fn from_runtime_plan(
        plan: &eventexec::WorkflowRuntimePlan,
        write_admission: &primitives::WriteAdmission,
    ) -> anyhow::Result<Self> {
        let mut targets = plan.projection_targets().entries();
        anyhow::ensure!(
            targets.len() == 1,
            "settingsonly requires exactly one bound projection target"
        );
        let target = targets
            .next()
            .context("settingsonly projection target is missing")?;
        anyhow::ensure!(
            target.workflow().id() == SETTINGS_PROJECTION_ID,
            "settingsonly projection target identity drift"
        );

        let name = primitives::ProbeName::parse(crate::readiness::SETTINGS_PROJECTION_WORKER)
            .context("build settings projection worker probe name")?;
        let health = Arc::new(eventexec::WorkerHealth::starting());
        let runtime = Arc::clone(target.runtime_factory());
        let worker_health = Arc::clone(&health);
        let worker_admission = write_admission.clone();
        let worker = bootstrap::WorkerSpec::writes_deferred(
            "assemblies.settingsonly.src.projection.01",
            write_admission,
            move |token, _write_admission| runtime.spawn(token, worker_health, worker_admission),
        );
        let probe = ProjectionWorkerProbe {
            name: name.clone(),
            health,
        };
        let mut output = bootstrap::DomainModuleResult::default();
        output.push_probe((name, Box::new(probe)));
        output.push_worker(worker);
        Ok(Self(output))
    }

    pub(crate) fn into_output(self) -> bootstrap::DomainModuleResult {
        self.0
    }
}

struct ProjectionWorkerProbe {
    name: primitives::ProbeName,
    health: Arc<eventexec::WorkerHealth>,
}

impl bootstrap::HealthProbe for ProjectionWorkerProbe {
    fn check(&self) -> primitives::HealthCheck {
        primitives::HealthCheck::new(
            self.name.clone(),
            required_health_status(self.health.status()),
            self.health.detail(),
        )
    }
}

fn required_health_status(status: primitives::HealthStatus) -> primitives::HealthStatus {
    match status {
        primitives::HealthStatus::Healthy => primitives::HealthStatus::Healthy,
        primitives::HealthStatus::Degraded => primitives::HealthStatus::Degraded,
        primitives::HealthStatus::Unhealthy => primitives::HealthStatus::Unhealthy,
        _ => primitives::HealthStatus::Unhealthy,
    }
}

const PROJECTION_JOIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);
const _: () =
    assert!(PROJECTION_JOIN_BUDGET.as_secs() < crate::runtime::total_drain_duration().as_secs());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_projection_probe_preserves_degraded_as_ready() {
        assert_eq!(
            required_health_status(primitives::HealthStatus::Degraded),
            primitives::HealthStatus::Degraded
        );
        assert_eq!(
            required_health_status(primitives::HealthStatus::Unhealthy),
            primitives::HealthStatus::Unhealthy
        );
    }

    #[test]
    fn active_projection_emits_one_deferred_worker_and_matching_probe() -> anyhow::Result<()> {
        let plan = crate::plan::SettingsOnlyPlan::bundled()?.bind_fixture_projection()?;
        let (_control, _relay, _consumer, write_admission) =
            primitives::prepare_dr_admission_controls().into_parts();
        let output =
            ProjectionLifecycleBatch::from_runtime_plan(plan.workflow_runtime(), &write_admission)?
                .into_output();
        assert!(output.resource_count() == 0);
        assert!(matches!(
            output.workers().next(),
            Some(bootstrap::WorkerSpec::Deferred(_))
        ));
        assert_eq!(output.worker_count(), 1);
        let (probe_name, _probe) = output
            .probes()
            .next()
            .ok_or_else(|| anyhow::anyhow!("settings active projection must emit one probe"))?;
        assert_eq!(output.probe_count(), 1);
        assert!(
            probe_name
                .as_str()
                .starts_with(eventexec::PROJECTION_WORKER_PROBE)
        );
        assert!(probe_name.as_str().contains(SETTINGS_PROJECTION_ID));
        Ok(())
    }
}
