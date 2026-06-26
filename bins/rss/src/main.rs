//! rss — RSS 组合根 binary（薄 entry）。运行时编排在 `runtime::run`（#1309 抽 assemblies/runtime 去 bins 双写）。
//!
//! 当前两个 binary（`rss`/`server`）功能等价，均委托 `runtime::run()`；进程名不同供部署/监控区分。
//! 勿误删其一——两个 binary 的差异在进程名，不在代码逻辑。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    runtime::init_tracing();
    runtime::run().await
}
