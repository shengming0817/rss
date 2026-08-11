//! Process lifecycle owner behind the declarative runtime crate façade.

use anyhow::Context as _;
use diport::ManagedResource as _;

use crate::config::{RuntimeConfigSnapshot, SnapshotConfig};
use crate::phase::{self, PreparedRuntimeInputs, ServingRuntimeInputs};
use crate::telemetry;

pub(crate) fn prepare_operator_local(_: SnapshotConfig<'_>) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(super) fn prepare_serving_local(config: SnapshotConfig<'_>) -> anyhow::Result<()> {
    prepare_operator_local(config)
}

/// Capture one process snapshot, run profile-local preparation, then build external tracing.
///
/// The local closure always runs before the OTLP builder. Serving keeps this step process-only;
/// placement-selected domain configuration is parsed later from the same closed snapshot.
pub(crate) fn prepare_runtime_kernel<Local>(
    prepare_local: impl FnOnce(SnapshotConfig<'_>) -> anyhow::Result<Local>,
) -> anyhow::Result<(PreparedRuntimeInputs, Local, phase::PreparedTelemetryPlan)> {
    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot()
        .context("capture process runtime configuration")?;
    let config = runtime_config.view();
    let telemetry_plan = phase::PreparedTelemetryPlan::prepare(config)?;
    let (local, trace_export) =
        telemetry::prepare_local_before_external(config, prepare_local, || {
            telemetry::build_trace_export(config, telemetry_plan.resource())
        })?;
    telemetry::install_runtime_subscriber(
        telemetry_plan.filter(),
        telemetry_plan.resource().clone(),
        trace_export.as_ref(),
    )?;
    Ok((
        PreparedRuntimeInputs::new(runtime_config, trace_export),
        local,
        telemetry_plan,
    ))
}

/// Prepare serving inputs and the placement-first runtime plan before provider construction.
///
/// The binary calls this before [`run`], so tracing and all later consumers share one closed
/// process snapshot. Only the resulting [`ServingRuntimeInputs`] can enter [`run`] or
/// [`shutdown_runtime`].
pub fn prepare_runtime() -> anyhow::Result<ServingRuntimeInputs> {
    let (prepared, (), telemetry_plan) = prepare_runtime_kernel(prepare_operator_local)?;
    ServingRuntimeInputs::new(prepared, telemetry_plan)
}

/// Emit a process-terminal failure through the installed JSON subscriber.
///
/// Preparation failures before subscriber installation use one redacted CLI line; a process
/// therefore emits either pre-runtime CLI text or the versioned JSON stream, never both.
pub fn report_process_error(error: &anyhow::Error) {
    if !telemetry::report_process_error(error) {
        eprintln!("{}", safe_process_error_line(error));
    }
}

pub(super) fn safe_process_error_line(error: &anyhow::Error) -> String {
    let single_line: String = error
        .to_string()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    secure::redact_observation_field("process_error", &single_line).to_string()
}

/// Flush the trace exporter when a prepared runtime exits before serving launch.
pub async fn shutdown_runtime(mut runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {
    shutdown_prepared_runtime(runtime_inputs.prepared_mut()).await
}

pub(crate) async fn shutdown_prepared_runtime(
    runtime_inputs: &mut PreparedRuntimeInputs,
) -> anyhow::Result<()> {
    if let Some(trace_export) = runtime_inputs.take_trace_export() {
        trace_export
            .shutdown()
            .await
            .context("shutdown trace exporter")?;
    }
    Ok(())
}

/// Owns resources prepared before startup until the inner startup body moves them into launch.
pub(super) struct RuntimeLifecycleOwner {
    inputs: ServingRuntimeInputs,
}

impl RuntimeLifecycleOwner {
    pub(super) fn new(inputs: ServingRuntimeInputs) -> Self {
        Self { inputs }
    }

    #[cfg(test)]
    pub(super) fn take_trace_export_for_test(&mut self) -> Option<otel::OtelExporter> {
        self.inputs.take_trace_export()
    }

    pub(super) async fn finish(mut self, startup_result: anyhow::Result<()>) -> anyhow::Result<()> {
        let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;
        match (startup_result, cleanup_result) {
            (Ok(()), cleanup_result) => cleanup_result,
            (Err(startup_error), Ok(())) => Err(startup_error),
            (Err(startup_error), Err(cleanup_error)) => {
                tracing::error!(
                    cleanup_error = %cleanup_error,
                    "runtime startup failed and trace cleanup also failed; preserving startup error"
                );
                Err(startup_error)
            }
        }
    }
}

/// Production composition-root lifecycle entrypoint.
///
/// Provider setup, generated domain wiring, listener finalization, serving, and graceful shutdown
/// remain delegated to the typed phase owner. Missing configuration and failed infrastructure
/// remain fail-fast rather than becoming a false-ready process.
pub async fn run(runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {
    let mut owner = RuntimeLifecycleOwner::new(runtime_inputs);
    let startup_result = crate::phase::execute(&mut owner.inputs).await.map(|_| ());
    owner.finish(startup_result).await
}
