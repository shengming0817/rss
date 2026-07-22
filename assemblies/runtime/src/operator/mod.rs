//! Closed operator command surface for the `rss` binary.

mod audit_ledger;
mod dlq;
mod jwks;
mod postgres;
mod projection;
mod reconcile;
mod settings;

pub use audit_ledger::{is_audit_ledger_verify_command, run_audit_ledger_verify_command};
pub use dlq::{is_dlq_command, run_dlq_control_command};
pub use jwks::{is_rss_access_jwks_export_command, run_rss_access_jwks_export_command};
pub use postgres::{is_postgres_command, run_postgres_reader_migration_command};
pub use projection::{is_projection_command, run_projection_control_command};
pub use reconcile::{is_reconcile_target_command, run_reconcile_target_command};
pub use settings::{
    is_settings_config_value_maintenance_command, run_settings_config_value_maintenance,
};

pub use crate::phase::OperatorRuntimeInputs;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;

use crate::config::{ServiceTokenConfig, SnapshotConfig};
use crate::infra::oidc::ServiceTokenReplayOwner;
use crate::phase::OperatorRuntimeCapability;

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
    Ok(OperatorRuntimeInputs::new(prepared))
}

/// Flush the trace exporter after an operator command completes.
pub async fn shutdown_runtime(mut runtime_inputs: OperatorRuntimeInputs) -> anyhow::Result<()> {
    crate::shutdown_prepared_runtime(runtime_inputs.prepared_mut()).await
}

#[cfg(test)]
mod tests;
