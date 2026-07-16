//! rss — RSS 组合根 binary（薄 entry）。serving 运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `rss` 先 dispatch 显式 operator CLI（0067 reader-lane migration、audit ledger verify、settings
//! ConfigValue maintenance、projection replay/shadow-swap、reconcile target inspect/resume），未知参数 fail-closed；未命中 CLI 时才委托同一份 `runtime::run()` serving
//! 组合根。`server` 保持 serving-only entry。
enum CommandFamily {
    Serving,
    Postgres,
    Projection,
    AuditLedgerVerify,
    Dlq,
    ReconcileTarget,
    SettingsConfigValueMaintenance,
    OidcJwksExport,
}

fn classify_command(args: &[String]) -> anyhow::Result<CommandFamily> {
    if runtime::is_postgres_command(args) {
        return Ok(CommandFamily::Postgres);
    }
    if runtime::is_projection_command(args) {
        return Ok(CommandFamily::Projection);
    }
    if runtime::is_audit_ledger_verify_command(args) {
        return Ok(CommandFamily::AuditLedgerVerify);
    }
    if runtime::is_dlq_command(args) {
        return Ok(CommandFamily::Dlq);
    }
    if runtime::is_reconcile_target_command(args) {
        return Ok(CommandFamily::ReconcileTarget);
    }
    if runtime::is_settings_config_value_maintenance_command(args) {
        return Ok(CommandFamily::SettingsConfigValueMaintenance);
    }
    if runtime::is_oidc_jwks_export_command(args) {
        return Ok(CommandFamily::OidcJwksExport);
    }
    anyhow::ensure!(args.is_empty(), "unknown rss command: {args:?}");
    Ok(CommandFamily::Serving)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = classify_command(&args)?;
    let runtime_inputs = runtime::prepare_runtime()?;
    let operator_result = match command {
        CommandFamily::Serving => return runtime::run(runtime_inputs).await,
        CommandFamily::Postgres => {
            runtime::run_postgres_reader_migration_command(&args, &runtime_inputs).await
        }
        CommandFamily::Projection => {
            runtime::run_projection_control_command(&args, &runtime_inputs).await
        }
        CommandFamily::AuditLedgerVerify => {
            runtime::run_audit_ledger_verify_command(&args, &runtime_inputs).await
        }
        CommandFamily::Dlq => runtime::run_dlq_control_command(&args, &runtime_inputs).await,
        CommandFamily::ReconcileTarget => {
            runtime::run_reconcile_target_command(&args, &runtime_inputs).await
        }
        CommandFamily::SettingsConfigValueMaintenance => {
            runtime::run_settings_config_value_maintenance(&args, &runtime_inputs).await
        }
        CommandFamily::OidcJwksExport => runtime::run_oidc_jwks_export_command(&args).await,
    };
    runtime::shutdown_runtime(runtime_inputs).await?;
    operator_result
}
