//! OTLP/gRPC trace 导出 pipeline 构建 + typed endpoint 安全策略 + 导出边界脱敏（仅 `backend` feature）。
//!
//! 拆离自 `lib.rs` 控制认知复杂度（对标 `adapters/s3/src/store.rs`）。提供：
//! - [`OtelEndpoint`]：传输安全 typed opt-in（TLS 默认；明文仅本地 loopback 显式 opt-in，fail-closed）。
//! - [`RedactingSpanExporter`]：导出边界 key-sweep + free-form URL-scrub 脱敏（**defense-in-depth 兜底**，#1361）；
//!   首要防线是 call-site 字段策略（`secure::safe(&v, scope)` / 派生 `Debug`），在值变成 span 属性字符串前按声明
//!   策略脱敏；兜底只见类型擦除后的 `String`：DSN 内联凭据经 URL-scrub 剥除，但非 URL 的 `email`/`subject` 原值仍透传。
//! - [`build_otlp_provider`]：endpoint → 已建脱敏 `SdkTracerProvider` 的 fail-fast typed 构建步骤。

use diport::RedactedSource;
use opentelemetry::{KeyValue, Value};
use opentelemetry_otlp::{SpanExporter as OtlpSpanExporter, WithExportConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use secure::{redact_field, redact_url_credentials};

/// OTLP exporter pipeline 构建失败（endpoint 非法 / 传输初始化失败）。
///
/// **PII 边界**：`Display` 仅输出资源无关安全摘要常量；内部 `opentelemetry-otlp` 构建错误经
/// [`RedactedSource`] 脱敏（endpoint URL / 传输细节不经任何 `Error` 接口暴露），对齐 diport
/// provider-error 范式（`diport::ObjectStoreError` / `ShutdownError`）。
#[derive(Debug, thiserror::Error)]
#[error("otel exporter pipeline build failed")]
pub struct OtelError {
    #[source]
    source: RedactedSource,
}

impl OtelError {
    fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// OTLP 导出端点的传输安全策略（fail-closed typed opt-in）。
///
/// 生产只接受 [`OtelEndpoint::tls`]（`https://`）；明文导出（`http://`）必须经
/// [`OtelEndpoint::insecure_localhost`] 显式 opt-in 且 host 限 loopback——把「非 TLS endpoint」从
/// 「裸字符串约定 + warn 的隐式成功路径」收成**类型层显式选择**（零信任，`docs/rules/observability.md`
/// 「生产禁 localhost fallback / 明文」；plaintext-prod-endpoint 不可表达）。
#[derive(Debug, Clone)]
pub enum OtelEndpoint {
    /// TLS（`https://`）导出端点。
    Tls(String),
    /// 明文（`http://`）本地 collector 端点（host 已校验为 loopback）。
    InsecureLocalhost(String),
}

/// [`OtelEndpoint`] 构造校验失败（fail-fast：误配在组合根接线期即暴露）。
#[derive(Debug, thiserror::Error)]
pub enum OtelEndpointError {
    /// TLS 端点不是 `https://`。
    #[error("otel TLS endpoint must use https:// transport")]
    NotHttps,
    /// 明文端点不是指向 loopback host 的 `http://`。
    #[error(
        "insecure otel endpoint must be plaintext http:// to a loopback host (localhost/127.0.0.1/[::1])"
    )]
    NotLoopbackPlaintext,
}

impl OtelEndpoint {
    /// 构造 TLS 端点（必须 `https://`）——生产默认路径。
    pub fn tls(endpoint: impl Into<String>) -> Result<Self, OtelEndpointError> {
        let endpoint = endpoint.into();
        if endpoint.starts_with("https://") {
            Ok(Self::Tls(endpoint))
        } else {
            Err(OtelEndpointError::NotHttps)
        }
    }

    /// 构造明文本地端点（必须 `http://` 且 host 为 loopback）——明文导出的**唯一**显式 opt-in。
    pub fn insecure_localhost(endpoint: impl Into<String>) -> Result<Self, OtelEndpointError> {
        let endpoint = endpoint.into();
        if is_loopback_http(&endpoint) {
            Ok(Self::InsecureLocalhost(endpoint))
        } else {
            Err(OtelEndpointError::NotLoopbackPlaintext)
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Tls(endpoint) | Self::InsecureLocalhost(endpoint) => endpoint,
        }
    }
}

/// `http://` 且 host 为 loopback，且**无 userinfo**——用 canonical [`url::Url`] parser 解析，不手写
/// authority split（手写解析会把 `http://localhost:4317@evil.example:4317` 的 userinfo `localhost:4317@`
/// 误判成 host=localhost 而放行非 loopback 明文 endpoint，绕过 fail-closed 边界）。
///
/// fail-closed：解析失败 / 非 http / 带 userinfo（`user[:pass]@`，可伪装真实 host）/ host 非 loopback → false。
/// loopback 判定走 `is_loopback()`（覆盖 `127.0.0.0/8` + `::1`，host 大小写经 url 归一）。
fn is_loopback_http(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    if url.scheme() != "http" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
        Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
        _ => false,
    }
}

/// 导出边界脱敏 exporter wrapper（**defense-in-depth 兜底**，#1361）。
///
/// 首要脱敏防线是 call-site 字段策略：调用方经 `secure::safe(&v, scope)` 或派生 `Debug` 在值变成 span
/// 属性字符串前按声明策略脱敏；本 exporter 的导出边界做 key-sweep + free-form URL-scrub 兜底——它只见
/// 类型擦除后的 `String`：DSN 内联凭据经 URL-scrub 剥除（不依赖 key），但非 URL 的自由文本 PII（如
/// `email`/`subject` 原值）仍透传，须由 call-site 字段策略覆盖（#1361）。
///
/// key-sweep 按 [`secure::redact_field`] 单源 funnel 清洗 span/event/link 属性中已知敏感 key
/// （`authorization`/`access_token`/`session`/`cookie`/`jwt`… → `<redacted>`），防凭据经 tracing→OTLP
/// 裸传（`observability.md` §redaction；脱敏落在导出最外边界，fail-closed）。
#[derive(Debug)]
pub(crate) struct RedactingSpanExporter<E> {
    inner: E,
}

impl<E> RedactingSpanExporter<E> {
    /// 包装一个下游 [`SpanExporter`]，在其 `export` 前统一脱敏。
    pub(crate) fn new(inner: E) -> Self {
        Self { inner }
    }
}

/// 就地清洗一组属性的 string 值（非 string 值无自由文本 PII，跳过——避免把计数 / 布尔等 typed 值误改成字符串）。
///
/// 两步（`observability.md` §redaction：「先按 key 判敏感，再做 free-form scrub」）：
/// 1. **key-sweep**：[`secure::redact_field`] 按敏感 key（`authorization`/`session`/`cookie`/`jwt`… → `<redacted>`）；
/// 2. **free-form scrub**：对结果再经 [`secure::redact_url_credentials`] 剥 URL 内联凭据——**不依赖 key 名**，
///    故 `dsn`/`url` 等非敏感 key 携内联 DSN（`postgres://u:p@h/db`）也剥成 `postgres://<redacted>@h/db`。
///
/// **defense-in-depth 兜底**（#1361）：仍有 key-sweep + URL-scrub 都不覆盖的盲区——非 URL 且非敏感 key 的
/// 自由文本 PII（如 `email`/`subject` 原值），须由 call-site 字段策略（`secure::safe(&v, scope)` / 派生 `Debug`）覆盖。
fn redact_attributes(attributes: &mut [KeyValue]) {
    for kv in attributes {
        if !matches!(kv.value, Value::String(_)) {
            continue;
        }
        let replacement = {
            let current = kv.value.as_str();
            let keyed = redact_field(kv.key.as_str(), current.as_ref());
            // free-form scrub：key-sweep 结果再剥 URL 凭据（DSN userinfo 不依赖 key 名）。
            let scrubbed = redact_url_credentials(keyed.as_str());
            (scrubbed.as_str() != current.as_ref()).then(|| scrubbed.as_str().to_owned())
        };
        if let Some(value) = replacement {
            kv.value = Value::from(value);
        }
    }
}

impl<E: SpanExporter> SpanExporter for RedactingSpanExporter<E> {
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        for span in &mut batch {
            redact_attributes(&mut span.attributes);
            for event in &mut span.events.events {
                redact_attributes(&mut event.attributes);
            }
            for link in &mut span.links.links {
                redact_attributes(&mut link.attributes);
            }
        }
        self.inner.export(batch).await
    }

    fn shutdown(&self) -> OTelSdkResult {
        self.inner.shutdown()
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        // 资源属性（service.name 等）须传给下游 exporter，否则导出 span 缺 resource。
        self.inner.set_resource(resource);
    }
}

/// 构建 OTLP/gRPC trace 导出 [`SdkTracerProvider`]：tonic exporter（tls-ring + webpki-roots，见 Cargo.toml）
/// 经 [`RedactingSpanExporter`] 导出边界脱敏 → `BatchSpanProcessor`（后台线程批量导出，不要求调用方 runtime）。
///
/// `endpoint` 是 typed [`OtelEndpoint`]：TLS（`https://`）或显式 opt-in 的本地明文——非 TLS 不再是隐式
/// 成功路径（fail-closed）。tonic channel 惰性连接（`connect_lazy`），构建不连真实 collector（连接发生在首次导出）。
pub fn build_otlp_provider(endpoint: OtelEndpoint) -> Result<SdkTracerProvider, OtelError> {
    let exporter = OtlpSpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.as_str())
        .build()
        .map_err(OtelError::new)?;
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(RedactingSpanExporter::new(exporter))
        .build())
}

#[cfg(test)]
mod tests {
    //! pipeline 行为：OtelError 脱敏 / OtelEndpoint typed 安全边界 / RedactingSpanExporter 导出脱敏。
    //! 确定性，不依赖外部 collector。
    use super::{OtelEndpoint, OtelError, RedactingSpanExporter, redact_attributes};
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry::{KeyValue, Value};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
    use rstest::rstest;
    use tracing_subscriber::layer::SubscriberExt as _;

    // unwrap/expect item-level carve-out 集中于 helper（error-handling.md §Carve-out）。
    #[allow(clippy::unwrap_used)]
    fn finished(mem: &InMemorySpanExporter) -> Vec<SpanData> {
        mem.get_finished_spans().unwrap()
    }

    // ── OtelError 脱敏（INVARIANT: OTEL-ERR-SOURCE-REDACT-01） ──────────────
    #[test]
    fn otel_error_redacts_source() {
        let err = OtelError::new(std::io::Error::other(
            "endpoint=https://user:hunter2@collector.internal:4317",
        ));
        assert_eq!(err.to_string(), "otel exporter pipeline build failed");
        // anti-vacuity：内层 Debug 确实携密，否则回归空转。
        assert!(
            format!("{:?}", std::io::Error::other("hunter2-marker")).contains("hunter2-marker"),
            "前提失效：内层 Debug 未携 marker"
        );
        let dbg = format!("{err:?}");
        assert!(
            !dbg.contains("hunter2") && !dbg.contains("user:"),
            "OtelError Debug 泄漏内层 source: {dbg}"
        );
    }

    // ── OtelEndpoint typed 安全边界（fail-closed） ──────────────────────────
    #[rstest]
    #[case("https://collector.internal:4317", true)]
    #[case("http://collector.internal:4317", false)] // 明文不准走 tls 构造
    #[case("grpc://collector.internal:4317", false)]
    fn otel_endpoint_tls_requires_https(#[case] endpoint: &str, #[case] ok: bool) {
        assert_eq!(OtelEndpoint::tls(endpoint).is_ok(), ok);
    }

    #[rstest]
    #[case("http://localhost:4317", true)]
    #[case("http://127.0.0.1:4317", true)]
    #[case("http://127.0.0.2:4317", true)] // 127.0.0.0/8 全段 loopback（is_loopback）
    #[case("http://[::1]:4317", true)]
    #[case("http://localhost:4317/v1/traces", true)] // 带 path 仍判 host
    #[case("http://LOCALHOST:4317", true)] // host 大小写经 url 归一
    #[case("http://collector.internal:4317", false)] // 非 loopback host
    #[case("https://localhost:4317", false)]
    // 非明文（应走 tls）
    // ── anti-regression（codex F2 回归）：userinfo 伪装 host 必须被拒（fail-closed） ──
    #[case("http://localhost:4317@collector.internal:4317", false)] // userinfo=localhost，真实 host=collector.internal
    #[case("http://user@localhost:4317", false)] // 任何 userinfo（即便 host 真是 localhost）一律拒
    #[case("http://user:pass@localhost:4317", false)]
    #[case("not-a-url", false)] // 解析失败 → 拒
    fn otel_endpoint_insecure_localhost_requires_loopback(
        #[case] endpoint: &str,
        #[case] ok: bool,
    ) {
        assert_eq!(OtelEndpoint::insecure_localhost(endpoint).is_ok(), ok);
    }

    // ── RedactingSpanExporter 导出边界脱敏 ─────────────────────────────────
    #[test]
    fn redact_attributes_scrubs_sensitive_string_keys_only() {
        let mut attrs = vec![
            KeyValue::new("authorization", "Bearer s3cr3t"),
            KeyValue::new("user_id", "u-42"),
            KeyValue::new("session_count", Value::I64(7)), // 敏感 key 但非 string → 不动（不误改 typed 值）
        ];
        redact_attributes(&mut attrs);
        assert_eq!(attrs[0].value.as_str(), "<redacted>");
        assert_eq!(attrs[1].value.as_str(), "u-42"); // 非敏感 key 原样（anti-vacuity）
        assert_eq!(attrs[2].value, Value::I64(7)); // 非 string 值不被脱敏改写
    }

    #[test]
    fn redacting_exporter_scrubs_exported_span_attributes() {
        // 端到端：tracing span 字段 → 桥接 Layer → RedactingSpanExporter → InMemory 捕获已脱敏属性。
        let mem = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(RedactingSpanExporter::new(mem.clone()))
            .build();
        let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "exported",
                authorization = "Bearer s3cr3t",
                access_token = "tok-123",
                session_id = "sess-xyz",
                user_id = "u-42"
            );
            let _enter = span.enter();
        });
        let spans = finished(&mem);
        let exported: Vec<_> = spans.iter().filter(|s| s.name == "exported").collect();
        assert_eq!(exported.len(), 1, "应有 1 条导出 span");
        let attr = |k: &str| {
            exported[0]
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == k)
                .map(|kv| kv.value.as_str().into_owned())
        };
        assert_eq!(attr("authorization").as_deref(), Some("<redacted>"));
        assert_eq!(attr("access_token").as_deref(), Some("<redacted>"));
        assert_eq!(attr("session_id").as_deref(), Some("<redacted>"));
        // 非敏感 key 原样保留——证明脱敏非全量恒抹（anti-vacuity）。
        assert_eq!(attr("user_id").as_deref(), Some("u-42"));
    }

    // ── key-sweep + free-form URL-scrub + 剩余盲区（#1361 review F1）──────────
    /// 敏感 key → `<redacted>`；DSN 内联凭据经 free-form URL-scrub 剥（不依赖 key 名）；
    /// 非 URL 自由文本 PII（email/subject）仍透传（call-site 字段策略覆盖的盲区）。
    #[test]
    fn redact_attributes_sink_redacts_keyed_secrets_and_dsn() {
        let mut attrs = vec![
            KeyValue::new("authorization", "Bearer x"),
            KeyValue::new("session_id", "s"),
            KeyValue::new("email", "alice@example.com"),
            KeyValue::new("subject", "sub-123"),
            KeyValue::new("dsn", "postgres://u:p@h/db"),
            KeyValue::new("user_id", "u-42"),
        ];
        redact_attributes(&mut attrs);
        // 命中敏感 key 模式 → <redacted>（anti-vacuity：函数非 noop）。
        assert_eq!(
            attrs[0].value.as_str(),
            "<redacted>",
            "authorization 应被脱敏"
        );
        assert_eq!(attrs[1].value.as_str(), "<redacted>", "session_id 应被脱敏");
        // 非 URL 自由文本 PII：key-sweep + URL-scrub 都不覆盖 → 透传（须 call-site secure::safe）。
        assert_eq!(
            attrs[2].value.as_str(),
            "alice@example.com",
            "email 非 URL 非敏感 key → 透传（盲区文档化）",
        );
        assert_eq!(attrs[3].value.as_str(), "sub-123", "subject 同上透传");
        // F1：dsn 非敏感 key，但内联凭据经 free-form URL-scrub 剥（observability.md §redaction）。
        assert_eq!(
            attrs[4].value.as_str(),
            "postgres://<redacted>@h/db",
            "dsn 内联凭据应被 URL-scrub 剥",
        );
        // 普通非 URL 非敏感值原样透传（不误伤）。
        assert_eq!(attrs[5].value.as_str(), "u-42", "普通值不应被改");
    }

    #[test]
    fn redacting_exporter_scrubs_event_attributes() {
        // 端到端：OTel span event 属性 → RedactingSpanExporter event.attributes 脱敏循环。
        // 覆盖 export 内 `for event in &mut span.events.events` 分支（现有测试仅覆盖 span.attributes）。
        use opentelemetry::trace::{Span as _, Tracer as _};
        let mem = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(RedactingSpanExporter::new(mem.clone()))
            .build();
        let tracer = provider.tracer("test");
        let mut span = tracer.start("span-with-event");
        span.add_event(
            "auth-event",
            vec![
                KeyValue::new("authorization", "Bearer secret"),
                KeyValue::new("session_id", "sess-abc"),
            ],
        );
        drop(span); // end span → SimpleSpanProcessor 同步导出
        let spans = finished(&mem);
        let matching: Vec<_> = spans
            .iter()
            .filter(|s| s.name == "span-with-event")
            .collect();
        assert_eq!(matching.len(), 1, "span-with-event 应存在");
        let events = &matching[0].events.events;
        assert_eq!(events.len(), 1, "span 应有一个 event");
        let event_attr = |k: &str| {
            events[0]
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == k)
                .map(|kv| kv.value.as_str().into_owned())
        };
        // 事件属性中的敏感 key 同样被 exporter 脱敏。
        assert_eq!(event_attr("authorization").as_deref(), Some("<redacted>"));
        assert_eq!(event_attr("session_id").as_deref(), Some("<redacted>"));
    }

    #[test]
    fn redacting_exporter_scrubs_link_attributes() {
        // 端到端（#1361 review F2）：OTel span link 属性 → RedactingSpanExporter link.attributes 脱敏循环。
        // 覆盖 export 内 `for link in &mut span.links.links` 分支（此前仅 span/event 属性有覆盖）。
        use opentelemetry::trace::{
            Span as _, SpanContext, SpanId, TraceFlags, TraceId, TraceState, Tracer as _,
        };
        let mem = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(RedactingSpanExporter::new(mem.clone()))
            .build();
        let tracer = provider.tracer("test");
        let mut span = tracer.start("span-with-link");
        span.add_link(
            SpanContext::new(
                TraceId::from_bytes([1; 16]),
                SpanId::from_bytes([1; 8]),
                TraceFlags::SAMPLED,
                false,
                TraceState::default(),
            ),
            vec![
                KeyValue::new("authorization", "Bearer secret"),
                KeyValue::new("session_id", "sess-xyz"),
                KeyValue::new("dsn", "postgres://u:p@h/db"),
            ],
        );
        drop(span); // end span → SimpleSpanProcessor 同步导出
        let spans = finished(&mem);
        let matching: Vec<_> = spans
            .iter()
            .filter(|s| s.name == "span-with-link")
            .collect();
        assert_eq!(matching.len(), 1, "span-with-link 应存在");
        let links = &matching[0].links.links;
        assert_eq!(links.len(), 1, "span 应有一个 link");
        let link_attr = |k: &str| {
            links[0]
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == k)
                .map(|kv| kv.value.as_str().into_owned())
        };
        // 敏感 key 脱敏；DSN 内联凭据经 free-form URL-scrub 剥。
        assert_eq!(link_attr("authorization").as_deref(), Some("<redacted>"));
        assert_eq!(link_attr("session_id").as_deref(), Some("<redacted>"));
        assert_eq!(
            link_attr("dsn").as_deref(),
            Some("postgres://<redacted>@h/db"),
            "link 属性的 DSN 凭据应被剥",
        );
    }

    #[test]
    fn field_policy_value_already_redacted_before_sink() {
        // call-site 字段策略（secure::safe + Wire）在值变成 span 属性字符串前已脱敏——
        // `email` 不在 key-sweep 白名单，但 #[derive(Redact)] + Wire scope 保证原邮箱从未进 sink。
        #[derive(secure::Redact)]
        #[allow(dead_code)]
        struct WithEmail {
            #[redact(sensitivity = pii_email)]
            email: String,
        }
        let mem = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(RedactingSpanExporter::new(mem.clone()))
            .build();
        let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("test"));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "field-policy-span",
                who = %secure::safe(
                    &WithEmail { email: "alice@example.com".into() },
                    secure::RedactScope::Wire,
                )
            );
            let _enter = span.enter();
        });
        let spans = finished(&mem);
        let exported: Vec<_> = spans
            .iter()
            .filter(|s| s.name == "field-policy-span")
            .collect();
        assert_eq!(exported.len(), 1, "应有 1 条导出 span");
        let attr = |k: &str| {
            exported[0]
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == k)
                .map(|kv| kv.value.as_str().into_owned())
        };
        // Wire scope：pii("email") 的 EmailMask 塌缩 Fixed → <redacted>。
        // call-site 字段策略在进 sink 前已脱敏，原邮箱从未出现在 span 属性中。
        assert!(attr("who").is_some(), "who 属性应存在");
        if let Some(who) = attr("who") {
            assert!(
                !who.contains("alice@example.com"),
                "原始邮箱不应出现: {who}"
            );
            assert!(
                who.contains("<redacted>"),
                "Wire scope 应产出 <redacted>: {who}"
            );
        }
    }
}
