#![recursion_limit = "256"]

//! rss — RSS 组合根 binary（薄 entry）。serving 运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `rss` 先 dispatch 不需要 runtime 配置的 Vault allowlist 离线校验，再 dispatch 显式 operator CLI
//!（forward-only migrate-all、audit ledger verify、settings ConfigValue maintenance、projection
//! replay/shadow-swap、reconcile target inspect/resume）；未知参数 fail-closed，未命中 CLI 时才委托
//! 同一份 `runtime::run()` serving 组合根。`server` 保持 serving-only entry。
enum CommandFamily {
    Serving,
    VaultAllowlistValidation,
    Operator(OperatorCommand),
}

enum OperatorCommand {
    Postgres,
    Projection,
    AuditLedgerVerify,
    Dlq,
    ReconcileTarget,
    SettingsConfigValueMaintenance,
    RssAccessJwksExport,
}

fn init_migration_tracing() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|_| anyhow::anyhow!("initialize postgres migration tracing subscriber"))
}

fn classify_command(args: &[String]) -> anyhow::Result<CommandFamily> {
    if runtime::operator::is_vault_allowlist_validation_command(args) {
        return Ok(CommandFamily::VaultAllowlistValidation);
    }
    if matches!(args, [namespace, command] if namespace == "postgres" && command == "migrate-all") {
        return Ok(CommandFamily::Operator(OperatorCommand::Postgres));
    }
    if runtime::operator::is_projection_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Projection));
    }
    if runtime::operator::is_audit_ledger_verify_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::AuditLedgerVerify));
    }
    if runtime::operator::is_dlq_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Dlq));
    }
    if runtime::operator::is_reconcile_target_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::ReconcileTarget));
    }
    if runtime::operator::is_settings_config_value_maintenance_command(args) {
        return Ok(CommandFamily::Operator(
            OperatorCommand::SettingsConfigValueMaintenance,
        ));
    }
    if runtime::operator::is_rss_access_jwks_export_command(args) {
        return Ok(CommandFamily::Operator(
            OperatorCommand::RssAccessJwksExport,
        ));
    }
    anyhow::ensure!(args.is_empty(), "unknown rss command: {args:?}");
    Ok(CommandFamily::Serving)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = classify_command(&args)?;
    if let CommandFamily::VaultAllowlistValidation = command {
        return runtime::operator::run_vault_allowlist_validation_command(&args);
    }
    let CommandFamily::Operator(command) = command else {
        return runtime::run(runtime::prepare_runtime()?).await;
    };
    if let OperatorCommand::Postgres = command {
        init_migration_tracing()?;
        anyhow::ensure!(
            matches!(args.as_slice(), [namespace, command] if namespace == "postgres" && command == "migrate-all"),
            "usage: rss postgres migrate-all"
        );
        return postgres_migration::migrate_all_from_process_environment()
            .await
            .map_err(anyhow::Error::from);
    }
    if let OperatorCommand::Projection = command {
        let runtime_inputs = runtime::operator::prepare_projection_runtime()?;
        let operator_result =
            runtime::operator::run_projection_control_command(&args, &runtime_inputs).await;
        runtime::operator::shutdown_projection_runtime(runtime_inputs).await?;
        return operator_result;
    }
    let runtime_inputs = runtime::operator::prepare_runtime()?;
    let operator_result = match command {
        OperatorCommand::Postgres => {
            unreachable!("postgres migration returns before runtime setup")
        }
        OperatorCommand::Projection => unreachable!("projection uses dedicated runtime inputs"),
        OperatorCommand::AuditLedgerVerify => {
            runtime::operator::run_audit_ledger_verify_command(&args, &runtime_inputs).await
        }
        OperatorCommand::Dlq => {
            runtime::operator::run_dlq_control_command(&args, &runtime_inputs).await
        }
        OperatorCommand::ReconcileTarget => {
            runtime::operator::run_reconcile_target_command(&args, &runtime_inputs).await
        }
        OperatorCommand::SettingsConfigValueMaintenance => {
            runtime::operator::run_settings_config_value_maintenance(&args, &runtime_inputs).await
        }
        OperatorCommand::RssAccessJwksExport => {
            runtime::operator::run_rss_access_jwks_export_command(&args, &runtime_inputs).await
        }
    };
    runtime::operator::shutdown_runtime(runtime_inputs).await?;
    operator_result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    #[test]
    fn postgres_namespace_is_reserved_for_migrate_all() {
        assert!(matches!(
            classify_command(&args(&["postgres", "migrate-all"])),
            Ok(CommandFamily::Operator(OperatorCommand::Postgres))
        ));
        assert!(classify_command(&args(&["postgres", "migrate-reader-lane"])).is_err());
        assert!(!matches!(
            classify_command(&args(&["migrate-all"])),
            Ok(CommandFamily::Operator(OperatorCommand::Postgres))
        ));
    }
}
