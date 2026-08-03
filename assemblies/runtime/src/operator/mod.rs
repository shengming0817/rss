//! Closed operator command surface for the `rss` binary.

mod audit_ledger;
mod device_latent;
mod dlq;
mod dr_recovery;
mod jwks;
mod projection;
mod reconcile;
mod saga;
mod service_token;
mod settings;
mod vault_allowlist;

pub use audit_ledger::{is_audit_ledger_verify_command, run_audit_ledger_verify_command};
pub use device_latent::{
    DeviceLatentCommandPreparation, is_device_latent_inspection_command,
    prepare_device_latent_command, prepare_device_latent_runtime,
    run_device_latent_inspection_command, shutdown_device_latent_runtime,
};
pub use dlq::{is_dlq_command, run_dlq_control_command};
pub use dr_recovery::{
    L2DrRecoveryCommandPreparation, PreparedL2DrRecoveryCommand, is_l2_dr_recovery_command,
    prepare_l2_dr_recovery_command, run_l2_dr_recovery_command,
};
pub use jwks::{is_rss_access_jwks_export_command, run_rss_access_jwks_export_command};
pub use projection::is_projection_command;
pub use reconcile::{is_reconcile_target_command, run_reconcile_target_command};
pub use saga::{SagaCommandPreparation, is_saga_command, prepare_saga_command, run_saga_command};
pub use settings::{
    is_settings_config_value_maintenance_command, run_settings_config_value_maintenance,
};
pub use vault_allowlist::{
    is_vault_allowlist_validation_command, run_vault_allowlist_validation_command,
};

pub use crate::phase::{OperatorRuntimeInputs, ProjectionOperatorRuntimeInputs};

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::config::{
    ProjectionOperatorTokenConfig, RuntimeConfigSnapshot, ServiceTokenConfig, SnapshotConfig,
};
use crate::infra::oidc::ServiceTokenReplayOwner;
use crate::phase::{OperatorRuntimeCapability, PreparedRuntimeInputs};
use crate::{build_trace_export, prepare_local_before_external, prepare_operator_local};

const SERVICE_TOKEN_REPLAY_STORE_TIMEOUT: Duration = Duration::from_secs(5);

fn build_operator_service_token_provider(
    config: SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
    replay_owner: &impl ServiceTokenReplayOwner,
) -> anyhow::Result<Arc<oidc::OidcProvider<diport::ServiceTokenProfile>>> {
    let config =
        ServiceTokenConfig::from_snapshot(config).context("parse service-token configuration")?;
    crate::infra::oidc::build_service_token_provider(
        &config,
        replay_owner,
        SERVICE_TOKEN_REPLAY_STORE_TIMEOUT,
    )
    .map(|runtime| runtime.provider())
}

fn build_projection_operator_token_provider(
    config: SnapshotConfig<'_>,
    _operator: OperatorRuntimeCapability<'_>,
    replay_owner: &impl ServiceTokenReplayOwner,
) -> anyhow::Result<crate::infra::oidc::RuntimeProjectionOperatorTokenProvider> {
    let config = ProjectionOperatorTokenConfig::from_snapshot(config)
        .context("parse Projection operator token configuration")?;
    crate::infra::oidc::build_projection_operator_token_provider(
        &config,
        replay_owner,
        SERVICE_TOKEN_REPLAY_STORE_TIMEOUT,
    )
}

fn parse_positive_usize(raw: &str, flag: &str) -> anyhow::Result<usize> {
    let value = raw
        .parse::<usize>()
        .with_context(|| format!("{flag} must be a positive integer"))?;
    anyhow::ensure!(value > 0, "{flag} must be greater than zero");
    Ok(value)
}

/// Prepare operator inputs without loading serving-only password policy data.
pub fn prepare_runtime() -> anyhow::Result<OperatorRuntimeInputs> {
    let (prepared, ()) = crate::prepare_runtime_kernel(crate::prepare_operator_local)?;
    OperatorRuntimeInputs::new(prepared)
}

/// Prepare Projection-only inputs from its dedicated closed snapshot and secret carrier.
pub fn prepare_projection_runtime() -> anyhow::Result<ProjectionOperatorRuntimeInputs> {
    ProjectionOperatorRuntimeInputs::new(prepare_projection_operator_runtime_kernel()?)
}

/// Capture and initialize the Projection CLI's dedicated configuration generation.
///
/// This deliberately does not call the serving runtime kernel: that kernel owns the serving
/// snapshot factory and therefore opens the serving secret bundle. The Projection path has its
/// own closed factory and returns a distinct input type at the public operator boundary.
fn prepare_projection_operator_runtime_kernel() -> anyhow::Result<PreparedRuntimeInputs> {
    let runtime_config = RuntimeConfigSnapshot::capture_projection_operator_process_snapshot()
        .context("capture projection operator runtime configuration")?;
    let config = runtime_config.view();
    let ((), trace_export) = prepare_local_before_external(config, prepare_operator_local, || {
        build_trace_export(config)
    })?;
    let filter = config
        .value("RUST_LOG")
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let otel_layer = trace_export.as_ref().map(|exporter| exporter.layer());
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(otel_layer)
        .init();
    Ok(PreparedRuntimeInputs::new(runtime_config, trace_export))
}

/// Execute Projection control through the typed Projection-only input boundary.
pub async fn run_projection_control_command(
    args: &[String],
    runtime_inputs: &ProjectionOperatorRuntimeInputs,
) -> anyhow::Result<()> {
    projection::run_projection_control_command(args, runtime_inputs.operator_inputs()).await
}

/// Flush the trace exporter after an operator command completes.
pub async fn shutdown_runtime(mut runtime_inputs: OperatorRuntimeInputs) -> anyhow::Result<()> {
    crate::shutdown_prepared_runtime(runtime_inputs.prepared_mut()).await
}

/// Flush the trace exporter owned by a prepared Projection command.
pub async fn shutdown_projection_runtime(
    mut runtime_inputs: ProjectionOperatorRuntimeInputs,
) -> anyhow::Result<()> {
    crate::shutdown_prepared_runtime(runtime_inputs.prepared_mut()).await
}

#[cfg(test)]
mod tests;
