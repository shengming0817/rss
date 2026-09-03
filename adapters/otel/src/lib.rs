//! otel adapter —— RSS workspace（W 阶段真身，#1011 可观测性导出切片）。
//!
//! 单一 `OtelExporter`：
//! - 始终 `impl diport::ManagedResource`（已冻结，ADAPTER-PORT-FREEZE-05）。
//! - `backend` feature 开时增补 OTLP/gRPC trace 导出 pipeline（持有 `SdkTracerProvider`）+
//!   `tracing-opentelemetry` 桥接 [`OtelExporter::layer`] + `observ::MetricLabel` → otel `KeyValue` 映射。
//!
//! feature-off（default build）：空壳编译、freeze smoke 类型断言仍有效；不引入 otel 依赖。
//! feature-on（`--features backend`）：[`build_otlp_provider`] 建 OTLP/gRPC exporter（tls-ring + webpki-roots，
//! **禁** aws-lc，见 Cargo.toml）→ [`OtelExporter::new`] 包装 provider；组合根
//! `tracing_subscriber::registry().with(exporter.layer())` 注册桥接 Layer，业务 `tracing` span 即经 OTLP 导出。
//! endpoint / 凭据在组合根决定（adapter 不内建配置，对齐 s3「`new` 收已建后端句柄」范式）。
//! 测试用 `InMemorySpanExporter` 确定性捕获导出 span（无 live collector）；live collector 集成 = follow-up。
//! crate 保持 `forbid(unsafe_code)`（继承 workspace lints；只 import diport/otel trait，不 invoke dynosaur 宏）。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry-sdk/src/trace/provider.rs@0.32.1
//! ref: tokio-rs/tracing-opentelemetry src/layer.rs@0.33.0

#[cfg(feature = "backend")]
mod pipeline;

#[cfg(feature = "backend")]
pub use observ::TelemetryResource;
#[cfg(feature = "test-support")]
pub use pipeline::test_support;
#[cfg(feature = "backend")]
pub use pipeline::{OtelEndpoint, OtelEndpointError, OtelError, build_otlp_provider};

/// Valid trace/span identifiers projected from the currently entered tracing span.
#[cfg(feature = "backend")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceIds {
    trace_id: String,
    span_id: String,
}

#[cfg(feature = "backend")]
impl TraceIds {
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    pub fn span_id(&self) -> &str {
        &self.span_id
    }
}

/// Return identifiers from the active OpenTelemetry context, if one is installed and valid.
#[cfg(feature = "backend")]
pub fn current_trace_ids() -> Option<TraceIds> {
    use opentelemetry::trace::TraceContextExt as _;

    // The bridge layer enables OpenTelemetry context activation by default. Reading the activated
    // context works inside sibling subscriber callbacks, where recursively querying
    // `tracing::Span::current()` is intentionally suppressed by tracing's dispatcher guard.
    let context = opentelemetry::Context::current();
    let span = context.span();
    let span_context = span.span_context();
    span_context.is_valid().then(|| TraceIds {
        trace_id: span_context.trace_id().to_string(),
        span_id: span_context.span_id().to_string(),
    })
}

/// Return identifiers for a resolved tracing span, including an explicit event parent that is not
/// currently entered.
#[cfg(feature = "backend")]
pub fn trace_ids_for_span(
    span_id: &tracing::span::Id,
    dispatch: &tracing::Dispatch,
) -> Option<TraceIds> {
    use opentelemetry::trace::TraceContextExt as _;

    let context = tracing_opentelemetry::get_otel_context(span_id, dispatch)?;
    let span = context.span();
    let span_context = span.span_context();
    span_context.is_valid().then(|| TraceIds {
        trace_id: span_context.trace_id().to_string(),
        span_id: span_context.span_id().to_string(),
    })
}

use diport::{ManagedResource, ShutdownError};

/// OpenTelemetry 导出 adapter（sealed-marker）。
///
/// `backend` feature 关时为空壳（仅供 freeze smoke 类型断言）；开时持有 OTLP/gRPC trace 导出
/// `SdkTracerProvider`，经 [`OtelExporter::layer`] 暴露 tracing 桥接 Layer，关闭时 flush + 关 exporter pipeline。
pub struct OtelExporter {
    #[cfg(feature = "backend")]
    provider: opentelemetry_sdk::trace::SdkTracerProvider,
}

#[cfg(feature = "backend")]
impl OtelExporter {
    /// 由已建 [`SdkTracerProvider`](opentelemetry_sdk::trace::SdkTracerProvider) 构造（provider 经
    /// [`build_otlp_provider`] 或测试注入构建——endpoint / 凭据 / exporter 在构造侧决定，对齐 s3 adapter
    /// 「`new` 收已建后端句柄」范式）。
    pub fn new(provider: opentelemetry_sdk::trace::SdkTracerProvider) -> Self {
        Self { provider }
    }

    /// 取本 provider 的 `tracing-opentelemetry` 桥接 Layer，供组合根
    /// `tracing_subscriber::registry().with(exporter.layer())` 注册——业务 `tracing` span 即经 OTLP 导出。
    ///
    /// 返回的 Layer owned 自带 tracer（不借 `&self`），可独立于本 exporter 的借用注册进 subscriber。
    pub fn layer<S>(&self) -> impl tracing_subscriber::Layer<S> + use<S>
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        use opentelemetry::trace::TracerProvider as _;
        // tracer name = instrumentation scope（OTel 语义）：用本 crate 名标识桥接来源，对齐 OTel 规范
        // （非硬编码短名）。span 的具体来源仍由各 tracing target/metadata 携带，本 scope 标识 otel 桥接层。
        tracing_opentelemetry::layer().with_tracer(self.provider.tracer(env!("CARGO_PKG_NAME")))
    }
}

/// 把 [`observ::MetricLabel`] 闭值集映射为 otel [`KeyValue`](opentelemetry::KeyValue)。
///
/// observ #1006 在其 W 阶段把该映射显式委派给消费 adapter（observ 本身不引 otel）；本 adapter 闭环该契约。
/// value 仅 `LabelValue::Static(&'static str)`——runtime 高基数串无法进入 label value（observ F10）。
#[cfg(feature = "backend")]
pub fn to_key_value(label: &impl observ::MetricLabel) -> opentelemetry::KeyValue {
    // INVARIANT: 此 irrefutable let 是 observ F10 闭值集的编译期守卫——`LabelValue` 一旦新增变体
    // （如 runtime `Dynamic(String)`），本行即编译失败，强制本 adapter 显式决策如何映射，不静默放行高基数串。
    let observ::LabelValue::Static(value) = label.value();
    opentelemetry::KeyValue::new(label.key(), value)
}

/// INVARIANT: ADAPTER-PORT-FREEZE-05 { level = "Hard", exec = "native-compile", source = "code", native = "sealed ManagedResource implementation on the production provider" }.
impl ManagedResource for OtelExporter {
    fn name(&self) -> &str {
        "otel"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        #[cfg(feature = "backend")]
        {
            // 关 exporter pipeline：SdkTracerProvider::shutdown 内部先 flush 未导出 span 再关传输。
            // 它是**同步阻塞**调用（等 batch worker thread flush+ack，自带 5s 内部超时，见 opentelemetry_sdk
            // 0.32 provider.rs）。直接在 async fn 内调用会占住 tokio worker，且 bootstrap 的 per-resource
            // tokio::time::timeout 无法在同步阻塞点取消——故 spawn_blocking 移出 executor，`.await` 提供可被
            // 外层 timeout 作用的让出点。错误（JoinError / OTelSdkError）经 rss_redact::RedactedSource 脱敏。
            let provider = self.provider.clone();
            diport::join_owned_task(move || provider.shutdown())
                .await
                .map_err(ShutdownError::from_join_error)?
                .map_err(ShutdownError::new)?;
        }
        // reason: feature-off 空壳无 provider 可关——无 infra 句柄需释放，关闭无需动作。
        Ok(())
    }
}

#[cfg(test)]
mod smoke {
    #![allow(clippy::expect_used)]

    //! build smoke：编译期断言 sealed-marker 已 impl 冻结的 diport DI port trait（PhantomData 绑定检查，
    //! 不构造、不执行 body）。
    //! ADAPTER-PORT-FREEZE-05 support：sealed-marker `OtelExporter` impl 冻结的 diport DI port trait
    //! （ManagedResource 始终）；去掉该 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    fn assert_managed_resource<T: diport::ManagedResource>(_: PhantomData<T>) {}

    #[test]
    fn impls_managed_resource() {
        assert_managed_resource(PhantomData::<super::OtelExporter>);
    }
}

#[cfg(all(test, feature = "backend"))]
mod backend_tests {
    #![allow(clippy::expect_used)]

    //! 导出行为矩阵（InMemorySpanExporter 确定性捕获，无 live collector）：
    //! tracing span → 桥接 Layer → OTLP 导出 round-trip / observ::MetricLabel→KeyValue 映射 /
    //! OTLP/gRPC provider 构建 + 生命周期（name + shutdown）。
    use super::{OtelEndpoint, OtelExporter, TelemetryResource, build_otlp_provider, to_key_value};
    use diport::ManagedResource;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
    use rstest::rstest;
    use tracing_subscriber::layer::SubscriberExt as _;

    // unwrap/expect 的 item-level carve-out 集中于 helper，测试体不散落。
    #[allow(clippy::unwrap_used)]
    fn finished_spans(exporter: &InMemorySpanExporter) -> Vec<SpanData> {
        exporter.get_finished_spans().unwrap()
    }

    #[allow(clippy::expect_used)]
    fn tls(endpoint: &str) -> OtelEndpoint {
        OtelEndpoint::tls(endpoint).expect("valid https endpoint")
    }

    #[allow(clippy::expect_used)]
    fn local(endpoint: &str) -> OtelEndpoint {
        OtelEndpoint::insecure_localhost(endpoint).expect("valid loopback http endpoint")
    }

    fn resource() -> TelemetryResource {
        TelemetryResource::try_new("runtime", "assembly-fp", "plan-fp")
            .expect("non-empty telemetry resource")
    }

    #[allow(clippy::expect_used)]
    fn build_ok(endpoint: OtelEndpoint) -> SdkTracerProvider {
        build_otlp_provider(endpoint, &resource())
            .expect("valid endpoint builds provider (connect_lazy)")
    }

    #[allow(clippy::expect_used)]
    fn build_err(endpoint: OtelEndpoint) -> super::OtelError {
        build_otlp_provider(endpoint, &resource())
            .expect_err("invalid endpoint must yield OtelError")
    }

    #[test]
    fn round_trip_exports_span_via_layer() {
        let exporter = InMemorySpanExporter::default();
        // SimpleSpanProcessor：span 关闭即同步导出，确定性捕获（无需 force_flush / runtime）。
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let otel = OtelExporter::new(provider);
        let subscriber = tracing_subscriber::registry().with(otel.layer());
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("otel-unit-span");
            let _enter = span.enter();
        });
        // 桥接 Layer 在 tracing span 关闭时结束 otel span → InMemory 捕获到该 span。
        let spans = finished_spans(&exporter);
        assert!(
            spans.iter().any(|s| s.name == "otel-unit-span"),
            "导出 span 缺失：{:?}",
            spans.iter().map(|s| s.name.clone()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_span_exports_nothing() {
        // anti-vacuity：未发 span 时 InMemory 为空——证明上面的捕获非恒真。
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let _otel = OtelExporter::new(provider);
        assert!(finished_spans(&exporter).is_empty());
    }

    #[rstest]
    #[case(observ::HttpLabel::Method(observ::HttpMethod::Get), "method", "GET")]
    #[case(
        observ::HttpLabel::StatusClass(observ::StatusClass::Class5xx),
        "status_class",
        "5xx"
    )]
    #[case(observ::HttpLabel::Domain("identity"), "domain", "identity")]
    #[case(
        observ::HttpLabel::RouteTemplate("/api/v1/devices/{id}"),
        "route_template",
        "/api/v1/devices/{id}"
    )]
    fn to_key_value_maps_http_label(
        #[case] label: observ::HttpLabel,
        #[case] key: &str,
        #[case] value: &str,
    ) {
        let kv = to_key_value(&label);
        assert_eq!(kv.key.as_str(), key);
        assert_eq!(kv.value.as_str(), value);
    }

    #[rstest]
    #[case(
        observ::CertLabel::Outcome(observ::CertOutcomeLabel::Renewed),
        "outcome",
        "renewed"
    )]
    fn to_key_value_maps_cert_label(
        #[case] label: observ::CertLabel,
        #[case] key: &str,
        #[case] value: &str,
    ) {
        let kv = to_key_value(&label);
        assert_eq!(kv.key.as_str(), key);
        assert_eq!(kv.value.as_str(), value);
    }

    #[tokio::test]
    async fn build_otlp_provider_and_lifecycle() {
        // OTLP/gRPC provider 构建（connect_lazy，不连真实 collector，明文 loopback / TLS 两种 transport 分支）
        // → 生命周期 name + shutdown（经 spawn_blocking）。
        for endpoint in [
            local("http://localhost:4317"),
            tls("https://collector.example.com:4317"),
        ] {
            let provider = build_ok(endpoint);
            let otel = OtelExporter::new(provider);
            assert_eq!(ManagedResource::name(&otel), "otel");
            assert!(ManagedResource::shutdown(&otel).await.is_ok());
        }
    }

    #[test]
    fn build_otlp_provider_invalid_endpoint_errs_and_redacts() {
        // typed https endpoint 但 URI 非法（含空格）→ Endpoint::from_shared 失败 → 真实链路返回 OtelError。
        // 同时锁脱敏闭环：endpoint（可携 host/凭据）不经 OtelError 的 Error 接口暴露（OTEL-ERR-SOURCE-REDACT-01）。
        let err = build_err(tls("https://user:hunter2@exa mple:4317"));
        assert_eq!(err.to_string(), "otel exporter pipeline build failed");
        let dbg = format!("{err:?}");
        assert!(
            !dbg.contains("hunter2") && !dbg.contains("exa mple"),
            "OtelError 经真实构建链路泄漏 endpoint: {dbg}"
        );
    }
}
