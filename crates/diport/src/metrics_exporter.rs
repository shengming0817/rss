//! `MetricsExporter` —— 指标 scrape 导出 DI port（可替换 provider：prod Prometheus / test 替身）。

/// 指标 scrape 导出 DI port（pull / exposition 接缝）。
///
/// **sync trait** → 天然 dyn-compatible，经 `Box<dyn MetricsExporter>` / `Arc<dyn MetricsExporter>`
/// 注入即可，**不需** dynosaur（dynosaur 仅为 async fn in trait 的 dyn 派发；sync trait 无此问题——
/// 同 `clock.rs`）。
///
/// 语义是 **pull / scrape**：把进程当前指标快照渲染为导出文本（Prometheus exposition format）。
/// push 型 provider（如 otel push exporter）不 impl 本端口——如 s3 不 impl `Publisher`，按需而非全覆盖。
/// 未来 `/metrics`（HealthListener）handler 经 `Arc<dyn MetricsExporter>` 跨并发请求共享渲染句柄。
///
/// `Send + Sync` supertrait：渲染句柄注入进多线程 runtime 持有的 HTTP handler，erased
/// `dyn MetricsExporter` 须 `Send + Sync`。
///
/// **消费方约束**：`/metrics` scrape handler 应挂在 `HealthListener`（health / ready / metrics 面）、仅内部
/// 网络可达，**不** opt-out 走 `Public`——组合根注入 `Arc<dyn MetricsExporter>` 跨并发请求共享，handler 内
/// `exporter.render()` 取 exposition body（content-type `text/plain; version=0.0.4` 由 handler 设置）。
/// 该 `/metrics` 路由挂载 + emit-site 插桩归组合根 / httpserve / observ，不在本 port，亦不在 provider adapter。
pub trait MetricsExporter: Send + Sync {
    /// 渲染当前指标快照为 scrape 导出文本（Prometheus exposition format）。
    ///
    /// infallible（与 `metrics_exporter_prometheus::PrometheusHandle::render` 同形）：渲染只读内存中
    /// 已聚合的指标，无 I/O、无失败路径，故不包 `Result`。
    fn render(&self) -> String;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 sync DI port 可 impl + 经 `Box<dyn _>` / `Arc<dyn _>` 动态注入（无 dynosaur）。
    use super::*;
    use std::sync::Arc;

    struct FixedExporter;
    impl MetricsExporter for FixedExporter {
        fn render(&self) -> String {
            // 固定值：test 替身确定性。
            "# fixed\n".to_owned()
        }
    }

    #[test]
    fn exporter_is_box_injectable() {
        let exporter: Box<dyn MetricsExporter> = Box::new(FixedExporter);
        assert_eq!(exporter.render(), "# fixed\n");
    }

    #[test]
    fn exporter_is_arc_shareable() {
        // /metrics handler 跨并发请求经 Arc<dyn MetricsExporter> 共享（须 Send + Sync）。
        let exporter: Arc<dyn MetricsExporter> = Arc::new(FixedExporter);
        let clone = Arc::clone(&exporter);
        assert_eq!(clone.render(), "# fixed\n");
    }
}
