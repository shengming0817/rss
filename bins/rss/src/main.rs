//! rss — RSS 组合根 binary（薄 entry）。运行时入口（tokio 运行时 + bind + serve + 信号优雅关停 +
//! wire_X call-site）在 lib crate `rss::run`（#1320）。`#[tokio::main]` 起多线程运行时驱动 async 编排。
//! `init_tracing` 在 `run` 前装配生产 tracing subscriber（否则 bind/serve/shutdown 日志全 no-op）。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rss::init_tracing();
    rss::run().await
}
