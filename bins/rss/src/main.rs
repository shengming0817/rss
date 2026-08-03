#![recursion_limit = "256"]

//! rss — RSS 组合根 binary（薄 entry）。serving 运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `rss` 先 dispatch 不需要 runtime 配置的 Vault allowlist 离线校验，再 dispatch 显式 operator CLI
//!（forward-only migrate-all、audit ledger verify、settings ConfigValue maintenance、projection
//! replay/shadow-swap、reconcile target inspect/resume、saga、dlq、device-latent inspect、l2-dr-recovery）；未知参数
//! fail-closed，未命中 CLI 时才委托同一份 `runtime::run()` serving 组合根。`server` 保持 serving-only
//! entry。
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
    DeviceLatentInspection,
    ReconcileTarget,
    Saga,
    L2DrRecovery,
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
    if runtime::operator::is_device_latent_inspection_command(args) {
        return Ok(CommandFamily::Operator(
            OperatorCommand::DeviceLatentInspection,
        ));
    }
    if runtime::operator::is_reconcile_target_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::ReconcileTarget));
    }
    if runtime::operator::is_saga_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Saga));
    }
    if runtime::operator::is_l2_dr_recovery_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::L2DrRecovery));
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
    if let OperatorCommand::Saga = command {
        let prepared = match runtime::operator::prepare_saga_command(&args)? {
            runtime::operator::SagaCommandPreparation::Help(help) => {
                println!("{help}");
                return Ok(());
            }
            runtime::operator::SagaCommandPreparation::Execute(command) => command,
        };
        let runtime_inputs = runtime::operator::prepare_runtime()?;
        return runtime::operator::run_saga_command(prepared, runtime_inputs).await;
    }
    if let OperatorCommand::DeviceLatentInspection = command {
        let prepared = match runtime::operator::prepare_device_latent_command(&args)? {
            runtime::operator::DeviceLatentCommandPreparation::Help(help) => {
                println!("{help}");
                return Ok(());
            }
            runtime::operator::DeviceLatentCommandPreparation::Execute(command) => command,
        };
        let runtime_inputs = runtime::operator::prepare_device_latent_runtime()?;
        let operator_result =
            runtime::operator::run_device_latent_inspection_command(prepared, &runtime_inputs)
                .await;
        runtime::operator::shutdown_device_latent_runtime(runtime_inputs).await?;
        return operator_result;
    }
    if let OperatorCommand::L2DrRecovery = command {
        let prepared = match runtime::operator::prepare_l2_dr_recovery_command(&args)? {
            runtime::operator::L2DrRecoveryCommandPreparation::Help(help) => {
                println!("{help}");
                return Ok(());
            }
            runtime::operator::L2DrRecoveryCommandPreparation::Execute(command) => command,
        };
        let runtime_inputs = runtime::operator::prepare_runtime()?;
        return runtime::operator::run_l2_dr_recovery_command(prepared, runtime_inputs).await;
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
        OperatorCommand::DeviceLatentInspection => {
            unreachable!("DeviceLatent preparation returns before runtime setup")
        }
        OperatorCommand::ReconcileTarget => {
            runtime::operator::run_reconcile_target_command(&args, &runtime_inputs).await
        }
        OperatorCommand::Saga => unreachable!("Saga preparation returns before runtime setup"),
        OperatorCommand::L2DrRecovery => {
            unreachable!("L2 DR recovery preparation returns before runtime setup")
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

    #[test]
    fn sagas_namespace_is_reserved_for_closed_operator_dispatch() {
        assert!(matches!(
            classify_command(&args(&["sagas", "status"])),
            Ok(CommandFamily::Operator(OperatorCommand::Saga))
        ));
        assert!(classify_command(&args(&["saga", "status"])).is_err());
    }

    #[test]
    fn device_latent_namespace_dispatches_only_to_the_read_only_operator() {
        assert!(matches!(
            classify_command(&args(&["device-latent", "inspect"])),
            Ok(CommandFamily::Operator(
                OperatorCommand::DeviceLatentInspection
            ))
        ));
        assert!(classify_command(&args(&["device-latent", "resume"])).is_err());
        assert!(matches!(
            classify_command(&args(&["device-latent", "--help"])),
            Ok(CommandFamily::Operator(
                OperatorCommand::DeviceLatentInspection
            ))
        ));
        assert!(classify_command(&args(&["device-latency", "inspect"])).is_err());
    }

    #[test]
    fn l2_dr_recovery_namespace_is_reserved_for_apply_and_runtime_free_help_dispatch() {
        for command in [
            args(&["l2-dr-recovery", "apply"]),
            args(&["l2-dr-recovery", "--help"]),
            args(&["l2-dr-recovery", "apply", "--help"]),
            args(&["l2-dr-recovery", "status"]),
        ] {
            assert!(matches!(
                classify_command(&command),
                Ok(CommandFamily::Operator(OperatorCommand::L2DrRecovery))
            ));
        }
        assert!(classify_command(&args(&["dr-recovery", "apply"])).is_err());
    }
}
