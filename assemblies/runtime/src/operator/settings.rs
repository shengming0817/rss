#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use anyhow::Context as _;
use diport::DynKeyProvider;
use postgres::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueProtection, MaintenanceAuditOutcome,
    PgMaintenanceDeps, PgRuntimeDeps,
};

use super::projection::verified_service_maintenance_operator_subject;
use super::{build_operator_service_token_provider, parse_positive_usize};
use crate::config::SnapshotConfig;
use crate::infra::pg::build_pg_migrator_config;
use crate::infra::vault::VaultRuntimeConfigError;
use crate::phase::{OperatorRuntimeCapability, OperatorRuntimeInputs};

/// `rss` binary 是否请求 settings ConfigValue 维护命令。
#[must_use]
pub fn is_settings_config_value_maintenance_command(args: &[String]) -> bool {
    matches!(
        args,
        [cmd, sub, ..] if cmd == "settings-config-values" && sub == "maintenance"
    )
}

pub(super) fn parse_config_value_maintenance_operation(
    raw: &str,
) -> anyhow::Result<ConfigValueMaintenanceOperation> {
    match raw {
        "backfill" => Ok(ConfigValueMaintenanceOperation::Backfill),
        "rewrap" => Ok(ConfigValueMaintenanceOperation::Rewrap),
        "both" => Ok(ConfigValueMaintenanceOperation::Both),
        other => anyhow::bail!(
            "unknown settings config value maintenance operation: {other}; expected backfill|rewrap|both"
        ),
    }
}

#[derive(Debug, Clone)]
pub(super) struct SettingsConfigValueMaintenanceArgs {
    pub(super) options: ConfigValueMaintenanceOptions,
    pub(super) operator_service_token: String,
    pub(super) operator_tenant: vocab::TenantId,
}

pub(super) fn parse_settings_config_value_maintenance_args(
    args: &[String],
) -> anyhow::Result<SettingsConfigValueMaintenanceArgs> {
    anyhow::ensure!(
        is_settings_config_value_maintenance_command(args),
        "usage: rss settings-config-values maintenance --operator-service-token <token> --operator-tenant <uuid> [--operation backfill|rewrap|both] [--tenant <uuid>] [--batch-size <n>] [--max-rows <n>] [--dry-run]"
    );
    let mut options = ConfigValueMaintenanceOptions::default();
    let mut operator_service_token = None;
    let mut operator_tenant = None;
    let mut it = args[2..].iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--operator-service-token" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-service-token requires a value"))?;
                let trimmed = raw.trim();
                anyhow::ensure!(
                    !trimmed.is_empty(),
                    "--operator-service-token must be non-empty"
                );
                operator_service_token = Some(trimmed.to_owned());
            }
            "--operator-tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operator-tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--operator-tenant must be a tenant UUID: {raw}"))?;
                operator_tenant = Some(tenant);
            }
            "--operation" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--operation requires a value"))?;
                options = ConfigValueMaintenanceOptions::new(
                    parse_config_value_maintenance_operation(raw)?,
                )
                .with_tenant_opt(options.tenant_opt())
                .with_batch_size(options.batch_size())
                .with_max_rows(options.max_rows())
                .with_dry_run(options.dry_run());
            }
            "--tenant" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--tenant requires a value"))?;
                let tenant = vocab::TenantId::parse(raw)
                    .with_context(|| format!("--tenant must be a tenant UUID: {raw}"))?;
                options = options.with_tenant(tenant);
            }
            "--batch-size" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--batch-size requires a value"))?;
                options = options.with_batch_size(parse_positive_usize(raw, "--batch-size")?);
            }
            "--max-rows" => {
                let raw = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--max-rows requires a value"))?;
                options = options.with_max_rows(Some(parse_positive_usize(raw, "--max-rows")?));
            }
            "--dry-run" => {
                options = options.with_dry_run(true);
            }
            other => {
                anyhow::bail!("unknown settings config value maintenance argument: {other}");
            }
        }
    }
    let operator_service_token = operator_service_token
        .ok_or_else(|| anyhow::anyhow!("--operator-service-token is required"))?;
    let operator_tenant =
        operator_tenant.ok_or_else(|| anyhow::anyhow!("--operator-tenant is required"))?;
    Ok(SettingsConfigValueMaintenanceArgs {
        options,
        operator_service_token,
        operator_tenant,
    })
}

pub(super) fn settings_config_value_maintenance_resource_id(
    options: &ConfigValueMaintenanceOptions,
) -> String {
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "operation={} scope={} dry_run={} batch_size={} max_rows={}",
        options.operation().as_str(),
        scope,
        options.dry_run(),
        options.batch_size(),
        max_rows
    )
}

pub(super) const UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR: &str = "unverified-service-token";

pub(super) async fn verified_config_value_maintenance_operator_subject(
    service_token: &str,
    operator_tenant: vocab::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<String> {
    verified_service_maintenance_operator_subject(
        service_token,
        operator_tenant,
        pdp,
        "settings config value maintenance",
    )
    .await
}

pub(super) async fn record_config_value_maintenance_finish_audit(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    outcome: MaintenanceAuditOutcome<'_>,
) -> anyhow::Result<()> {
    pg.record_config_value_maintenance_audit(
        operator_subject,
        "settings.config-values.maintenance.finish",
        outcome,
        resource_id,
    )
    .await
    .context("record settings config value maintenance finish audit")
}

pub(super) async fn settings_config_value_maintenance_operator_subject(
    pg: &PgMaintenanceDeps,
    config: SnapshotConfig<'_>,
    operator: OperatorRuntimeCapability<'_>,
    parsed: &SettingsConfigValueMaintenanceArgs,
    resource_id: &str,
) -> anyhow::Result<String> {
    let operator_provider = match build_operator_service_token_provider(config, operator, pg) {
        Ok(provider) => provider,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_provider_config",
                },
            )
            .await?;
            return Err(err).context("settings config value maintenance operator verifier");
        }
    };
    let operator_pdp = diport::DynPdp::from_ref(operator_provider.as_ref());
    match verified_config_value_maintenance_operator_subject(
        &parsed.operator_service_token,
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(subject) => Ok(subject),
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                pg,
                UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
                resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "operator_auth",
                },
            )
            .await?;
            Err(err)
        }
    }
}

pub(super) fn settings_config_value_maintenance_vault_failure(
    error: &VaultRuntimeConfigError,
) -> (&'static str, &'static str) {
    match error {
        VaultRuntimeConfigError::SettingsKeyNameConfig(_) => {
            ("key_name_config", "settings config value key name")
        }
        VaultRuntimeConfigError::VaultClientConfig(_) => (
            "key_provider_config",
            "settings config value maintenance key provider",
        ),
    }
}

pub(super) async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    config: SnapshotConfig<'_>,
) -> anyhow::Result<ConfigValueProtection> {
    let vault_config = match crate::infra::vault::VaultRuntimeConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(err) => {
            let (reason, context) = settings_config_value_maintenance_vault_failure(&err);
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure { reason },
            )
            .await?;
            return Err(err).context(context);
        }
    };
    let (key_provider, key_name) = match vault_config.into_settings_key_provider() {
        Ok(parts) => parts,
        Err(err) => {
            let (reason, context) = settings_config_value_maintenance_vault_failure(&err);
            record_config_value_maintenance_finish_audit(
                pg,
                operator_subject,
                resource_id,
                MaintenanceAuditOutcome::Failure { reason },
            )
            .await?;
            return Err(err).context(context);
        }
    };
    Ok(ConfigValueProtection::new(
        DynKeyProvider::new_box(key_provider),
        key_name,
    ))
}

/// 执行 `rss settings-config-values maintenance`。
pub async fn run_settings_config_value_maintenance(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let config = runtime_inputs.config();
    let parsed = parse_settings_config_value_maintenance_args(args)?;
    let options = parsed.options.clone();
    let resource_id = settings_config_value_maintenance_resource_id(&options);
    let pg = PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(config)?)
        .await
        .context("setup postgres maintenance deps")?;
    pg.record_config_value_maintenance_audit(
        UNVERIFIED_CONFIG_MAINTENANCE_OPERATOR,
        "settings.config-values.maintenance.start",
        MaintenanceAuditOutcome::Success,
        &resource_id,
    )
    .await
    .context("record settings config value maintenance start audit")?;
    let operator_subject = match settings_config_value_maintenance_operator_subject(
        &pg,
        config,
        runtime_inputs.operator_capability(),
        &parsed,
        &resource_id,
    )
    .await
    {
        Ok(subject) => subject,
        Err(err) => {
            pg.shutdown().await.ok();
            return Err(err);
        }
    };
    let capability = ConfigValueMaintenanceCapability::from_verified_service_caller(
        vocab::ServiceCallerDomain::MaintenanceOperator,
    );
    let protection = match settings_config_value_maintenance_protection(
        &pg,
        &operator_subject,
        &resource_id,
        runtime_inputs.config(),
    )
    .await
    {
        Ok(protection) => protection,
        Err(err) => {
            pg.shutdown().await.ok();
            return Err(err);
        }
    };
    let maintenance = pg.config_value_maintenance(protection, capability);
    let report = match maintenance.run(&options).await {
        Ok(report) => report,
        Err(err) => {
            record_config_value_maintenance_finish_audit(
                &pg,
                &operator_subject,
                &resource_id,
                MaintenanceAuditOutcome::Failure {
                    reason: "run_error",
                },
            )
            .await
            .context("record settings config value maintenance failure audit")?;
            pg.shutdown().await.ok();
            return Err(err).context("settings config value maintenance");
        }
    };
    let audit_outcome = if report.failed == 0 {
        MaintenanceAuditOutcome::Success
    } else {
        MaintenanceAuditOutcome::Failure {
            reason: "failed_rows",
        }
    };
    record_config_value_maintenance_finish_audit(
        &pg,
        &operator_subject,
        &resource_id,
        audit_outcome,
    )
    .await?;
    let scope = options
        .tenant_opt()
        .map(|tenant| format!("tenant:{tenant}"))
        .unwrap_or_else(|| "all".to_owned());
    let max_rows = options
        .max_rows()
        .map(|max_rows| max_rows.to_string())
        .unwrap_or_else(|| "none".to_owned());
    println!(
        "operation={} dry_run={} scope={} batch_size={} max_rows={} selected={} backfilled={} rewrapped={} unchanged={} failed={} remaining_plaintext={}",
        options.operation().as_str(),
        options.dry_run(),
        scope,
        options.batch_size(),
        max_rows,
        report.selected,
        report.backfilled,
        report.rewrapped,
        report.unchanged,
        report.failed,
        report.remaining_plaintext
    );
    pg.shutdown().await.ok();
    anyhow::ensure!(
        report.failed == 0,
        "settings config value maintenance completed with failed rows"
    );
    Ok(())
}
