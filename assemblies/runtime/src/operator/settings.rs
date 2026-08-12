// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![forbid(unused_imports)]
#![deny(clippy::wildcard_imports)]

use anyhow::Context as _;
use diport::DynKeyProvider;
#[cfg(feature = "operator-cli")]
use postgres::{ConfigValueMaintenanceCapability, PgRuntimeDeps};
use postgres::{
    ConfigValueMaintenanceOperation, ConfigValueMaintenanceOptions, ConfigValueProtection,
    MaintenanceAuditOutcome, PgMaintenanceDeps,
};

use super::build_operator_service_token_provider;
#[cfg(feature = "operator-cli")]
use super::parse_positive_usize;
#[cfg(feature = "operator-cli")]
use super::projection::service_maintenance_operator_audit_subject;
use super::projection::verified_service_maintenance_operator;
use super::service_token::OperatorServiceToken;
use crate::config::SnapshotConfig;
#[cfg(feature = "operator-cli")]
use crate::infra::pg::build_pg_migrator_config;
use crate::infra::vault::VaultKeyProviderConfigError;
use crate::phase::OperatorRuntimeCapability;
#[cfg(feature = "operator-cli")]
use crate::phase::OperatorRuntimeInputs;

const COMMAND_NAMESPACE: &str = "settings-config-values";

/// Whether the rss binary was invoked for settings ConfigValue maintenance.
///
/// Namespace probe only — not a second argv parser.
#[must_use]
pub fn is_settings_config_value_maintenance_command(args: &[String]) -> bool {
    matches!(args, [namespace, ..] if namespace == COMMAND_NAMESPACE)
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

#[derive(Debug)]
pub(super) struct SettingsConfigValueMaintenanceArgs {
    pub(super) options: ConfigValueMaintenanceOptions,
    pub(super) operator_service_token: OperatorServiceToken,
    pub(super) operator_tenant: rss_request_context::TenantId,
}

/// Opaque command whose argv and stdin token were validated before runtime setup.
#[cfg(feature = "operator-cli")]
pub struct PreparedSettingsConfigValueMaintenanceCommand(SettingsConfigValueMaintenanceArgs);

/// Pure CLI preparation result. Help performs no stdin / environment / provider access beyond
/// clap's own help/version render (already printed when this variant is returned).
#[cfg(feature = "operator-cli")]
pub enum SettingsConfigValueMaintenanceCommandPreparation {
    /// Help or version text was already written; caller returns `Ok(())` without runtime.
    Help,
    Execute(PreparedSettingsConfigValueMaintenanceCommand),
}

#[cfg(feature = "operator-cli")]
mod clap_cli {
    use super::{
        COMMAND_NAMESPACE, PreparedSettingsConfigValueMaintenanceCommand,
        SettingsConfigValueMaintenanceArgs, SettingsConfigValueMaintenanceCommandPreparation,
    };
    use crate::operator::cli_clap::{
        ClapHelpPrinted, OperatorServiceTokenStdinArg, map_clap_parse_error,
        parse_operator_tenant_cli, parse_tenant_cli,
    };
    use crate::operator::service_token::read_operator_service_token_stdin;
    use clap::{Args, Parser, Subcommand};
    use postgres::{ConfigValueMaintenanceOperation, ConfigValueMaintenanceOptions};

    const FAMILY: &str = COMMAND_NAMESPACE;

    // Token material is never accepted on argv: `--operator-service-token-stdin` is presence-only;
    // the opaque token is read from stdin after parse succeeds. Help/version → Help (exit 0);
    // other syntax errors → fixed family-bucketed diagnostic (never echo argv).
    //
    // Tenant scope is fail-closed: exactly one of `--tenant` or `--all-tenants` (mutually exclusive).
    // Flatten only [`OperatorServiceTokenStdinArg`], not required [`OperatorAuthSharedArgs::tenant`].
    #[derive(Debug, Parser)]
    #[command(
        name = COMMAND_NAMESPACE,
        bin_name = "rss settings-config-values",
        about = "Maintain settings ConfigValue encryption state",
        long_about = "Operator commands for settings ConfigValue backfill/rewrap maintenance. \
The operator service token is read from stdin after argv validation \
(--operator-service-token-stdin). The help subcommand is disabled; use --help. \
Tenant scope requires exactly one of --tenant <uuid> or --all-tenants.",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct SettingsConfigValueCli {
        #[command(subcommand)]
        action: SettingsConfigValueSubcommand,
    }

    #[derive(Debug, Subcommand)]
    enum SettingsConfigValueSubcommand {
        /// Backfill and/or rewrap ConfigValue ciphertext rows.
        Maintenance(SettingsConfigValueMaintenanceCliArgs),
    }

    #[derive(Debug, Args)]
    #[command(group(
        clap::ArgGroup::new("tenant_scope")
            .required(true)
            .args(["tenant", "all_tenants"])
    ))]
    struct SettingsConfigValueMaintenanceCliArgs {
        #[command(flatten)]
        token_stdin: OperatorServiceTokenStdinArg,

        /// Operator tenant that minted the operator service token (UUID).
        #[arg(long, value_parser = parse_operator_tenant_cli)]
        operator_tenant: rss_request_context::TenantId,

        /// Target one tenant (UUID). Mutually exclusive with `--all-tenants`.
        #[arg(long, value_parser = parse_tenant_cli)]
        tenant: Option<rss_request_context::TenantId>,

        /// Explicitly scan all tenants. Required when `--tenant` is omitted; mutually exclusive
        /// with `--tenant`.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        all_tenants: bool,

        /// Maintenance operation (backfill|rewrap|both; default both).
        #[arg(
            long = "operation",
            default_value = "both",
            value_parser = parse_operation_cli
        )]
        operation: ConfigValueMaintenanceOperation,

        /// Rows scanned per batch (default 500).
        #[arg(
            long = "batch-size",
            default_value = "500",
            value_parser = parse_batch_size_cli
        )]
        batch_size: usize,

        /// Optional cap on matching rows processed this run.
        #[arg(long = "max-rows", value_parser = parse_max_rows_cli)]
        max_rows: Option<usize>,

        /// Count only; do not write or call the key provider.
        #[arg(long, action = clap::ArgAction::SetTrue)]
        dry_run: bool,
    }

    fn parse_operation_cli(raw: &str) -> Result<ConfigValueMaintenanceOperation, String> {
        super::parse_config_value_maintenance_operation(raw).map_err(|err| err.to_string())
    }

    fn parse_batch_size_cli(raw: &str) -> Result<usize, String> {
        super::parse_positive_usize(raw, "--batch-size").map_err(|err| err.to_string())
    }

    fn parse_max_rows_cli(raw: &str) -> Result<usize, String> {
        super::parse_positive_usize(raw, "--max-rows").map_err(|err| err.to_string())
    }

    #[cfg(test)]
    pub(in crate::operator) fn parse_settings_config_value_maintenance_args(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<SettingsConfigValueMaintenanceArgs> {
        match prepare_settings_config_value_maintenance_command_with_stdin(args, stdin)? {
            SettingsConfigValueMaintenanceCommandPreparation::Execute(
                PreparedSettingsConfigValueMaintenanceCommand(parsed),
            ) => Ok(parsed),
            SettingsConfigValueMaintenanceCommandPreparation::Help => {
                anyhow::bail!("test expected executable settings-config-values command, got help")
            }
        }
    }

    pub(in crate::operator) fn prepare_settings_config_value_maintenance_command_with_stdin(
        args: &[String],
        stdin: &mut impl std::io::BufRead,
    ) -> anyhow::Result<SettingsConfigValueMaintenanceCommandPreparation> {
        let cli = match SettingsConfigValueCli::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => {
                let ClapHelpPrinted = map_clap_parse_error(err, FAMILY)?;
                return Ok(SettingsConfigValueMaintenanceCommandPreparation::Help);
            }
        };
        let SettingsConfigValueSubcommand::Maintenance(shared) = cli.action;
        // Presence is enforced by clap (`required = true`); token never enters argv.
        debug_assert!(shared.token_stdin.operator_service_token_stdin);
        // Tenant scope: clap ArgGroup requires exactly one of --tenant / --all-tenants.
        debug_assert!(
            shared.tenant.is_some() ^ shared.all_tenants,
            "tenant_scope group must admit exactly one of --tenant or --all-tenants"
        );
        let operator_service_token = read_operator_service_token_stdin(stdin)?;
        let mut options = ConfigValueMaintenanceOptions::new(shared.operation)
            .with_batch_size(shared.batch_size)
            .with_max_rows(shared.max_rows)
            .with_dry_run(shared.dry_run);
        if let Some(tenant) = shared.tenant {
            options = options.with_tenant(tenant);
        }
        Ok(SettingsConfigValueMaintenanceCommandPreparation::Execute(
            PreparedSettingsConfigValueMaintenanceCommand(SettingsConfigValueMaintenanceArgs {
                options,
                operator_service_token,
                operator_tenant: shared.operator_tenant,
            }),
        ))
    }
}

#[cfg(all(test, feature = "operator-cli"))]
pub(super) use clap_cli::parse_settings_config_value_maintenance_args;

/// Validate settings-config-values argv and consume stdin before any runtime / environment /
/// provider prep.
#[cfg(feature = "operator-cli")]
pub fn prepare_settings_config_value_maintenance_command(
    args: &[String],
) -> anyhow::Result<SettingsConfigValueMaintenanceCommandPreparation> {
    let stdin = std::io::stdin();
    clap_cli::prepare_settings_config_value_maintenance_command_with_stdin(args, &mut stdin.lock())
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

pub(super) async fn verified_config_value_maintenance_operator(
    service_token: &str,
    operator_tenant: rss_request_context::TenantId,
    pdp: &diport::DynPdp<'_>,
) -> anyhow::Result<authn::VerifiedMaintenanceServiceOperator> {
    verified_service_maintenance_operator(
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

pub(super) async fn settings_config_value_maintenance_operator(
    pg: &PgMaintenanceDeps,
    config: SnapshotConfig<'_>,
    operator: OperatorRuntimeCapability<'_>,
    parsed: &SettingsConfigValueMaintenanceArgs,
    resource_id: &str,
) -> anyhow::Result<authn::VerifiedMaintenanceServiceOperator> {
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
    match verified_config_value_maintenance_operator(
        parsed.operator_service_token.as_str(),
        parsed.operator_tenant,
        operator_pdp,
    )
    .await
    {
        Ok(proof) => Ok(proof),
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
    error: &VaultKeyProviderConfigError,
) -> (&'static str, &'static str) {
    match error {
        VaultKeyProviderConfigError::SettingsKeyName(_) => {
            ("key_name_config", "settings config value key name")
        }
        VaultKeyProviderConfigError::VaultClient(_) => (
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
    let vault_config = match crate::infra::vault::VaultKeyProviderConfig::from_snapshot(config) {
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
    let (key_provider, key_name) = match vault_config.into_key_provider() {
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

/// Execute an authenticated, audited settings ConfigValue maintenance command.
///
/// Callers must finish [`prepare_settings_config_value_maintenance_command`] before opening
/// runtime inputs.
#[cfg(feature = "operator-cli")]
pub async fn run_settings_config_value_maintenance(
    prepared: PreparedSettingsConfigValueMaintenanceCommand,
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    let parsed = prepared.0;
    let config = runtime_inputs.config();
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
    let operator_proof = match settings_config_value_maintenance_operator(
        &pg,
        config,
        runtime_inputs.operator_capability(),
        &parsed,
        &resource_id,
    )
    .await
    {
        Ok(proof) => proof,
        Err(err) => {
            pg.shutdown().await.ok();
            return Err(err);
        }
    };
    let operator_subject = service_maintenance_operator_audit_subject(&operator_proof).to_owned();
    let capability = ConfigValueMaintenanceCapability::from_verified_maintenance_service_operator(
        &operator_proof,
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
