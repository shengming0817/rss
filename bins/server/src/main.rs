#![recursion_limit = "256"]

//! server — RSS 组合根 binary（薄 entry）。运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! `server` 是 serving-only entry，始终委托 `runtime::run()`；operator CLI 由 `rss` binary 在进入 serving 前
//! 显式 dispatch。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime_inputs = runtime::prepare_runtime()?;
    runtime::run(runtime_inputs).await
}
