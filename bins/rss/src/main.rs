//! rss — RSS 组合根 binary（薄 entry）。serving 运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `rss` 先 dispatch 显式 operator CLI（0067 reader-lane migration、audit ledger verify、settings
//! ConfigValue maintenance、projection replay/shadow-swap、reconcile target inspect/resume），未知参数 fail-closed；未命中 CLI 时才委托同一份 `runtime::run()` serving
//! 组合根。`server` 保持 serving-only entry。
enum CommandFamily {
    Serving,
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

fn classify_command(args: &[String]) -> anyhow::Result<CommandFamily> {
    if runtime::is_postgres_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Postgres));
    }
    if runtime::is_projection_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Projection));
    }
    if runtime::is_audit_ledger_verify_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::AuditLedgerVerify));
    }
    if runtime::is_dlq_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Dlq));
    }
    if runtime::is_reconcile_target_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::ReconcileTarget));
    }
    if runtime::is_settings_config_value_maintenance_command(args) {
        return Ok(CommandFamily::Operator(
            OperatorCommand::SettingsConfigValueMaintenance,
        ));
    }
    if runtime::is_rss_access_jwks_export_command(args) {
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
    let CommandFamily::Operator(command) = command else {
        return runtime::run(runtime::prepare_runtime()?).await;
    };
    let runtime_inputs = runtime::prepare_operator_runtime()?;
    let operator_result = match command {
        OperatorCommand::Postgres => {
            runtime::run_postgres_reader_migration_command(&args, &runtime_inputs).await
        }
        OperatorCommand::Projection => {
            runtime::run_projection_control_command(&args, &runtime_inputs).await
        }
        OperatorCommand::AuditLedgerVerify => {
            runtime::run_audit_ledger_verify_command(&args, &runtime_inputs).await
        }
        OperatorCommand::Dlq => runtime::run_dlq_control_command(&args, &runtime_inputs).await,
        OperatorCommand::ReconcileTarget => {
            runtime::run_reconcile_target_command(&args, &runtime_inputs).await
        }
        OperatorCommand::SettingsConfigValueMaintenance => {
            runtime::run_settings_config_value_maintenance(&args, &runtime_inputs).await
        }
        OperatorCommand::RssAccessJwksExport => {
            runtime::run_rss_access_jwks_export_command(&args, &runtime_inputs).await
        }
    };
    runtime::shutdown_operator_runtime(runtime_inputs).await?;
    operator_result
}
