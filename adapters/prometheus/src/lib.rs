//! prometheus adapter —— RSS workspace（W 阶段真身，#1011 指标导出切片）。
//!
//! 单一 `PromExporter`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-07）。
//! - `backend` feature 开时增补 `impl diport::MetricsExporter`（Prometheus exposition 渲染）。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入 metrics 后端依赖。
//! feature-on（`--features backend`）：`install()` 装进程级 `metrics` facade global recorder（`metrics::counter!`
//! 等发射点经此写入）并持 `PrometheusHandle`；`render()` 输出 Prometheus exposition 文本供 `/metrics` scrape
//! （HTTP 暴露在组合根 / httpserve，不在 adapter）。`default-features=false` 关 http-listener / push-gateway
//! （不拉 hyper / rustls / TLS crypto，见 Cargo.toml；tokio 经 diport 已在树，与本 adapter 无关）。crate
//! 保持 `forbid(unsafe_code)`（继承 workspace lints）。
//! ref: metrics-rs/metrics metrics-exporter-prometheus/src/exporter/builder.rs@metrics-exporter-prometheus-v0.18.3

use diport::{ManagedResource, ShutdownError};

/// Prometheus 指标导出 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有装好的 `PrometheusHandle`（render 句柄）。
pub struct PromExporter {
    #[cfg(feature = "backend")]
    handle: metrics_exporter_prometheus::PrometheusHandle,
}

/// 装载 Prometheus recorder 失败（构造期 fail-fast，不静默 noop）。
///
/// 唯一现实失败模式 = 进程级 `metrics` global recorder 已被装过（重复 install）：默认 `PrometheusBuilder`
/// 无自定义 bucket / quantile，build 不会失败，只剩 set-global 冲突。**不内嵌上游 `BuildError` 作 source**
/// ——本错误是 adapter-local 构造错误（无 provider PII，同 s3 `EmptyBucket`），非 diport **port** error；
/// `rss_diport_error_debug_redacted`（脱敏 dylint）仅扫 `diport` crate、不覆盖 adapter，内嵌 raw source 反
/// 成 Debug 脱敏盲区。故只留 curated 静态消息，fail-fast 返回 `Err`、不丢失失败语义。
#[cfg(feature = "backend")]
#[derive(Debug, thiserror::Error)]
#[error("prometheus recorder already installed (global metrics recorder is set once per process)")]
pub struct InstallError;

#[cfg(feature = "backend")]
impl PromExporter {
    /// 装进程级 `metrics` facade global recorder（`metrics::counter!` 等发射点经此写入）并持有 render 句柄。
    ///
    /// **fail-fast**：global recorder 已装载（重复 install）即 `Err`——误配在组合根接线期即暴露，不静默 noop。
    pub fn install() -> Result<Self, InstallError> {
        let handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .map_err(|_| InstallError)?;
        Ok(Self { handle })
    }
}

/// INVARIANT: ADAPTER-PORT-FREEZE-07 { level = "Hard", exec = "native-compile", source = "code", native = "sealed ManagedResource implementation on the production provider" }.
impl ManagedResource for PromExporter {
    fn name(&self) -> &str {
        "prometheus"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        // reason: Prometheus pull exporter 无后台任务 / 连接需释放——render 句柄随 drop 回收，且
        // default-features=false 关 push-gateway / http-listener（无 spawn 的 upkeep / socket）；关闭无显式动作。
        // 前提 guard：若日后开 push-gateway / http-listener feature（带后台 push / socket），此 noop 失效，须换真实 shutdown。
        Ok(())
    }
}

#[cfg(feature = "backend")]
impl diport::MetricsExporter for PromExporter {
    fn render(&self) -> String {
        self.handle.render()
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! ADAPTER-PORT-FREEZE-07 support：sealed-marker impl 冻结的 diport DI port trait（ManagedResource
    //! 始终；MetricsExporter 于 backend）；去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::PromExporter>);
    }

    #[cfg(feature = "backend")]
    fn assert_metrics_exporter<T: diport::MetricsExporter>(_: PhantomData<T>) {}

    #[cfg(feature = "backend")]
    #[test]
    fn impls_metrics_exporter() {
        assert_metrics_exporter(PhantomData::<super::PromExporter>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    //! Prometheus 导出行为矩阵（确定性，非全局）：本地 `PrometheusRecorder` + `with_local_recorder` 发射
    //! counter / gauge，断言 render exposition 含指标名 + 值；`install()` 全局装载 + 生命周期（name / shutdown）。
    use super::PromExporter;
    use diport::{ManagedResource, MetricsExporter};
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

    impl PromExporter {
        /// test-only 构造（不暴露到 production API——本 impl 块在 `#[cfg(all(test, feature = "backend"))]` 内）：
        /// 包一个本地（非全局）`PrometheusHandle`，确定性断言 render，不污染进程 global recorder。
        fn from_handle(handle: PrometheusHandle) -> Self {
            Self { handle }
        }
    }

    #[test]
    fn render_reflects_emitted_counter() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::counter!("rss_prometheus_smoke_total").increment(3);
        });
        let out = PromExporter::from_handle(handle).render();
        assert!(out.contains("rss_prometheus_smoke_total"), "render: {out}");
        assert!(out.contains('3'), "render missing counter value: {out}");
    }

    #[test]
    fn render_reflects_emitted_gauge() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::gauge!("rss_prometheus_smoke_ratio").set(0.5);
        });
        let out = PromExporter::from_handle(handle).render();
        assert!(out.contains("rss_prometheus_smoke_ratio"), "render: {out}");
        assert!(out.contains("0.5"), "render missing gauge value: {out}");
    }

    #[test]
    fn render_empty_registry_is_wellformed() {
        let recorder = PrometheusBuilder::new().build_recorder();
        // 无发射：空 registry 的 render 是合法 exposition、不 panic。
        let out = PromExporter::from_handle(recorder.handle()).render();
        // 空 registry 渲染为空串（exposition 无 metric 行）。
        assert!(out.is_empty(), "empty registry should render empty: {out}");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)] // reason: 测试断言失败路径用 expect 直观定位（error-handling §Carve-out item-level）
    async fn install_is_fail_fast_singleton_lifecycle() {
        // 唯一触达进程级 global recorder 的测试（global recorder 进程内单例——本模块只此一处 install()，
        // 在 nextest 进程隔离与 `cargo test` 单进程多线程下均确定：无第二个测试争用全局 recorder）。
        let exporter = PromExporter::install().expect("first install installs global recorder");
        assert_eq!(exporter.name(), "prometheus");
        // fail-fast：global recorder 已装载，重复 install 必返回 Err（不静默 noop）。
        assert!(
            PromExporter::install().is_err(),
            "second install must fail-fast (global recorder already set)"
        );
        exporter.shutdown().await.expect("shutdown ok");
        // 装好后 render 是合法 ASCII exposition（不 panic、不含非 ASCII 字符）。
        assert!(exporter.render().is_ascii(), "exposition must be ascii");
    }
}
