//! rss — RSS 组合根 binary（薄 entry）。serving 运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `rss` 先 dispatch 显式 operator CLI（settings ConfigValue maintenance、projection replay/shadow-swap），
//! 未知参数 fail-closed；未命中 CLI 时才委托同一份 `runtime::run()` serving 组合根。`server` 保持 serving-only entry。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let trace_export = runtime::init_tracing()?;
    if runtime::is_projection_command(&args) {
        let result = runtime::run_projection_control_command(&args).await;
        runtime::shutdown_trace_export(trace_export).await?;
        return result;
    }
    if runtime::is_settings_config_value_maintenance_command(&args) {
        let result = runtime::run_settings_config_value_maintenance(&args).await;
        runtime::shutdown_trace_export(trace_export).await?;
        return result;
    }
    anyhow::ensure!(args.is_empty(), "unknown rss command: {args:?}");
    runtime::run(trace_export).await
}
