//! 集成测试共享辅助（`tests/common/mod.rs`：子目录形态，不被当作独立 test 二进制编译）。

use std::sync::Arc;

/// `/metrics` 渲染替身（固定 exposition）——e2e 不装进程级 Prometheus global recorder（避免 `install` 单例争用）。
///
/// `#[allow(dead_code)]`：并非每个 `mod common;` 的测试二进制都用到全部条目（Rust 按 test 文件分别编译 common）。
#[derive(Clone)]
#[allow(dead_code)]
pub struct FixedMetrics(pub &'static str);

impl diport::MetricsExporter for FixedMetrics {
    fn render(&self) -> String {
        self.0.to_owned()
    }
}

/// 固定空 exposition 替身（健康/serve 测试只验路由组装与 bind，不验真实指标内容）。
#[allow(dead_code)]
pub fn noop_metrics() -> Arc<dyn diport::MetricsExporter> {
    Arc::new(FixedMetrics("# noop\n"))
}
