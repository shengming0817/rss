//! server — RSS 组合根 binary（薄 entry）。生产认证接线逻辑在 lib crate `server::*`；
//! socket bind / serve / 信号优雅关停 / 全量域注册 = Join #1017。
fn main() -> anyhow::Result<()> {
    server::run()
}
