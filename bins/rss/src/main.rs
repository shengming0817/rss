#![recursion_limit = "256"]

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
    if runtime::operator::is_postgres_command(args) {
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
    let CommandFamily::Operator(command) = command else {
        return runtime::run(runtime::prepare_runtime()?).await;
    };
    let runtime_inputs = runtime::operator::prepare_runtime()?;
    let operator_result = match command {
        OperatorCommand::Postgres => {
            runtime::operator::run_postgres_reader_migration_command(&args, &runtime_inputs).await
        }
        OperatorCommand::Projection => {
            runtime::operator::run_projection_control_command(&args, &runtime_inputs).await
        }
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
