//! `tracewire` —— W3C Trace Context capture / remote-parent restore 单源。
//!
//! trace 在 `业务请求 → outbox → relay → broker → consumer` 跨 async 边界断链：emit 侧不捕获当前 trace、
//! consumer 侧无法还原 ⇒ 端到端被 relay 切两段。本 crate 是**唯一碰 `opentelemetry` 的新落点**（#1224 决策 2）——
//! producer 经 [`capture_current`] 把当前 `tracing` span 的 OTel 上下文导出为 W3C carrier（落 outbox
//! `metadata` 保留键 `trace`），consumer 经 [`restore_remote_parent`] 还原成 remote parent 挂到消费 span，使 handler
//! 与 producer **同一 `trace_id`**。HTTP server 入口也经同一 API 恢复 `traceparent` + `tracestate`。
//! `adapters/postgres`（emit）、`crates/eventexec`（consume）与 `crates/httpserve`（HTTP server）只依赖本 crate、
//! **不直接 import otel**，延续 RSS「otel 收口」治理（`adapters/otel` / `diagctx` / `observ` 同思路）。
//!
//! **fail-open**：诊断信道缺失从不阻塞投递——未装 otel 层 / span context 无效 ⇒ [`capture_current`] 返
//! `None`（不写 trace 键）；有效但未采样的 context 仍以 flags `00` 传播。`traceparent` 畸形 ⇒
//! [`restore_remote_parent`] 建立的新 span 保持 root，不 panic。
//!
//! W3C 线格式 `00-<32hex traceid>-<16hex spanid>-<2hex flags>`（W3C Trace Context；OTel messaging producer
//! inject / consumer extract 约定）。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry-sdk/src/propagation/trace_context.rs@0.32
//! ref: tokio-rs/tracing-opentelemetry src/span_ext.rs@0.33

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// W3C Trace Context 透传 header 名（producer inject / consumer extract 的 carrier 键）。
const TRACEPARENT: &str = "traceparent";
const TRACESTATE: &str = "tracestate";
const MAX_TRACE_CONTEXT_BYTES: usize = 512;

/// 当前 span mint 的 W3C Trace Context carrier。
///
/// 字段与构造器均私有，且刻意不实现 `Debug`、`Display` 或序列化 trait；下游只能读取标准字段，
/// 不能伪造传播 authority。
///
/// INVARIANT: HTTP-CLIENT-CONTEXT-AUTHORITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields and sole mint funnel" }
pub struct W3cTraceContext {
    traceparent: String,
    tracestate: Option<String>,
}

impl W3cTraceContext {
    /// W3C `traceparent` header value.
    #[must_use]
    pub fn traceparent(&self) -> &str {
        &self.traceparent
    }

    /// W3C `tracestate` header value when the current context carries one.
    #[must_use]
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
    }

    /// Consume the carrier and return its `traceparent` value.
    #[must_use]
    pub fn into_traceparent(self) -> String {
        self.traceparent
    }
}

/// 捕获当前 `tracing` span 的有效 OTel 上下文为不可伪造的 W3C carrier。
///
/// **fail-open**：无 subscriber / 未装 `tracing-opentelemetry` 层 / span context 无效
/// (`is_valid()==false`) ⇒ propagator 不写 `traceparent` ⇒ 返 `None`。未采样不是无效 context，
/// 因此仍传播 flags `00`。
///
/// 生产 caller：`adapters/postgres` 的 `metadata_with_ambient`（emit 与 handler 同 task 同步执行 ⇒
/// `Span::current()` 即请求 span），把结果写入 outbox `metadata` 保留键 `trace`。
#[must_use]
pub fn capture_current() -> Option<W3cTraceContext> {
    // 当前 span 的 OTel 上下文（无 tracing-opentelemetry 层时为 default Context，span context 无效）。
    let cx = tracing::Span::current().context();
    // W3C propagator 仅在 span context `is_valid()` 时写 `traceparent`（含采样判定）；无效则 carrier 空 → None。
    let mut carrier = std::collections::HashMap::<String, String>::new();
    TraceContextPropagator::new().inject_context(&cx, &mut carrier);
    let traceparent = carrier.remove(TRACEPARENT).filter(|s| !s.is_empty())?;
    let tracestate = carrier.remove(TRACESTATE).filter(|s| !s.is_empty());
    Some(W3cTraceContext {
        traceparent,
        tracestate,
    })
}

/// 把 W3C `traceparent` / `tracestate` 还原成 remote parent 挂到 `span`。
///
/// **fail-open**：`traceparent` 畸形 / 空 ⇒ 解析出无效 SpanContext，`set_parent` 不改 trace 归属（span 保持
/// 自身 root），**不 panic**——迟到 / 损坏的诊断信道不影响消费正确性。
///
/// caller 必须在 span 首次 enter/instrument 前调用。畸形 `tracestate` 只丢 state，不使合法 parent 失效。
/// 生产 caller：`crates/httpserve` HTTP 入口与 `crates/eventexec` consumer Fresh 路径。
pub fn restore_remote_parent(span: &tracing::Span, traceparent: &str, tracestate: Option<&str>) {
    if traceparent.len() > MAX_TRACE_CONTEXT_BYTES {
        return;
    }
    let mut carrier = std::collections::HashMap::<String, String>::new();
    carrier.insert(TRACEPARENT.to_owned(), traceparent.to_owned());
    if let Some(tracestate) = tracestate.filter(|value| value.len() <= MAX_TRACE_CONTEXT_BYTES) {
        carrier.insert(TRACESTATE.to_owned(), tracestate.to_owned());
    }
    let cx = TraceContextPropagator::new().extract(&carrier);
    if let Err(e) = span.set_parent(cx) {
        // reason: fail-open——set_parent 仅在 span 已 disabled/closed 或 layer 不可 downcast 时 Err（罕见）；
        // trace 续传是 best-effort 诊断，降级为 debug、消费 span 保持 root，绝不阻断消费。
        tracing::debug!(target: "tracewire", error = %e, "restore_remote_parent: set_parent failed; span stays root");
    }
}

/// **测试脚手架**（`test-util` feature / 本 crate 单测）：在装好 `tracing-opentelemetry` 层
/// （确定性 `SdkTracerProvider`，默认 `ParentBased(AlwaysOn)` 采样根 span）的 subscriber 内同步跑 `f`，
/// 使 [`capture_current`] 在活跃 span 内产出有效 W3C carrier。
///
/// 下游 crate（`adapters/postgres` emit 测试 / `crates/eventexec` consume 测试）经
/// `tracewire = { features = ["test-util"] }` 复用本 helper——**otel 收口在本 crate，下游测试不直接 import otel**。
/// 异步用例传 `|| rt.block_on(async { .. })`：current-thread runtime 在本线程驱动 ⇒ subscriber 全程有效。
#[cfg(any(test, feature = "test-util"))]
pub fn with_test_subscriber<R>(f: impl FnOnce() -> R) -> R {
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::prelude::*;
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let tracer = provider.tracer("tracewire-test");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, f)
}

/// Exported span snapshot for cross-crate conformance tests.
#[cfg(any(test, feature = "test-util"))]
pub struct TestSpan {
    pub name: String,
    pub kind: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
    pub tracestate: String,
    pub status: String,
    pub attributes: std::collections::BTreeMap<String, String>,
}

#[cfg(any(test, feature = "test-util"))]
static TEST_SPAN_CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(any(test, feature = "test-util"))]
static TEST_GLOBAL_SUBSCRIBER: std::sync::Once = std::sync::Once::new();

/// Run `future` to completion under an isolated in-memory OTel exporter and return deterministic
/// span snapshots.
///
/// The helper owns the current-thread runtime and binds every poll to one explicit dispatcher.
/// Capture sessions are process-serialized because tracing callsite interest is process-global.
#[cfg(any(test, feature = "test-util"))]
#[allow(clippy::expect_used)]
pub fn with_test_span_capture<F>(future: F) -> (F::Output, Vec<TestSpan>)
where
    F: std::future::Future,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::prelude::*;

    let _serial = TEST_SPAN_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    TEST_GLOBAL_SUBSCRIBER.call_once(|| {
        // A process-wide registry prevents parallel no-subscriber test threads from caching newly
        // registered production callsites as permanently disabled. Captured spans still route to
        // the session-local dispatcher below; this baseline has no exporting layer.
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry());
    });
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("tracewire-test"));
    let subscriber = tracing_subscriber::registry().with(layer);
    let dispatch = tracing::Dispatch::new(subscriber);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test span capture runtime");
    let result = tracing::dispatcher::with_default(&dispatch, || {
        tracing::callsite::rebuild_interest_cache();
        runtime.block_on(future.with_subscriber(dispatch.clone()))
    });
    provider.force_flush().expect("flush captured spans");
    let spans: Vec<TestSpan> = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .map(|span| TestSpan {
            name: span.name.into_owned(),
            kind: format!("{:?}", span.span_kind).to_ascii_lowercase(),
            trace_id: span.span_context.trace_id().to_string(),
            span_id: span.span_context.span_id().to_string(),
            parent_span_id: span.parent_span_id.to_string(),
            tracestate: span.span_context.trace_state().header(),
            status: format!("{:?}", span.status).to_ascii_lowercase(),
            attributes: span
                .attributes
                .into_iter()
                .map(|kv| (kv.key.as_str().to_owned(), kv.value.to_string()))
                .collect(),
        })
        .collect();
    (result, spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(W3cTraceContext: std::fmt::Debug, std::fmt::Display);

    /// `00-<32hex traceid>-<16hex spanid>-<2hex flags>` → trace_id 段（dash 间第 2 字段）。
    fn trace_id_of(traceparent: &str) -> &str {
        traceparent.split('-').nth(1).unwrap_or("")
    }

    fn shared_test_callsite() {
        let span = tracing::info_span!("tracewire.shared.test.callsite");
        let _entered = span.enter();
    }

    #[test]
    fn span_capture_survives_parallel_preregistration_and_spawn() {
        assert!(
            std::thread::spawn(shared_test_callsite).join().is_ok(),
            "pre-register callsite thread completes"
        );

        let (_, spans) = with_test_span_capture(async {
            assert!(
                tokio::spawn(async { shared_test_callsite() }).await.is_ok(),
                "captured task completes"
            );
        });

        assert_eq!(
            spans
                .iter()
                .filter(|span| span.name == "tracewire.shared.test.callsite")
                .count(),
            1
        );
    }

    // 活跃采样 span 内 capture → 合法 W3C traceparent（版本 00 + 32/16/2 hex）。
    // reason: 测试断言——`with_test_subscriber` 内采样根 span 的 capture 恒 Some，expect 即断言失败信息。
    #[allow(clippy::expect_used)]
    #[test]
    fn capture_inside_otel_span_yields_w3c() {
        let context =
            with_test_subscriber(|| tracing::info_span!("producer").in_scope(capture_current))
                .expect("capture inside sampled otel span yields trace context");
        let tp = context.traceparent();
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(parts.len(), 4, "traceparent 四段: {tp}");
        assert_eq!(parts[0], "00", "version");
        assert_eq!(parts[1].len(), 32, "trace-id 32 hex");
        assert_eq!(parts[2].len(), 16, "span-id 16 hex");
        assert_eq!(parts[3].len(), 2, "flags 2 hex");
        assert!(
            tp.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "全 hex/dash: {tp}"
        );
    }

    // 无 otel 层 → span context 无效 → None（fail-open 核心不变式）。
    #[test]
    fn capture_without_otel_layer_is_none() {
        assert!(capture_current().is_none());
    }

    // round-trip：capture → restore_remote_parent 后 consumer span 与 producer 同 trace_id（issue 验收）。
    // reason: 测试断言——producer/child span 在 `with_test_subscriber` 内恒采样，capture 恒 Some。
    #[allow(clippy::expect_used)]
    #[test]
    fn roundtrip_capture_restore_same_trace_id() {
        let (producer_tp, child_tp) = with_test_subscriber(|| {
            let producer_tp = tracing::info_span!("producer")
                .in_scope(capture_current)
                .expect("producer traceparent")
                .into_traceparent();
            let child = tracing::info_span!("consume");
            restore_remote_parent(&child, &producer_tp, None);
            let child_tp = child
                .in_scope(capture_current)
                .expect("child traceparent after restore")
                .into_traceparent();
            (producer_tp, child_tp)
        });
        assert_eq!(
            trace_id_of(&producer_tp),
            trace_id_of(&child_tp),
            "restore_remote_parent 后 consumer span 与 producer 同 trace_id"
        );
    }

    // 畸形 traceparent → no-op、不 panic（graceful degradation）。
    #[test]
    fn restore_malformed_is_noop_no_panic() {
        with_test_subscriber(|| {
            let span = tracing::info_span!("consume");
            restore_remote_parent(&span, "not-a-valid-traceparent", None);
            let _ = span.in_scope(capture_current); // 不 panic 即通过
        });
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn capture_preserves_tracestate() {
        let context = with_test_subscriber(|| {
            let span = tracing::info_span!(parent: None, "remote-child");
            restore_remote_parent(
                &span,
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                Some("vendor=value"),
            );
            span.in_scope(capture_current)
                .expect("remote child trace context")
        });
        assert_eq!(context.tracestate(), Some("vendor=value"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn capture_valid_unsampled_context_uses_zero_flags() {
        let context = with_test_subscriber(|| {
            let span = tracing::info_span!(parent: None, "remote-child");
            restore_remote_parent(
                &span,
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
                None,
            );
            span.in_scope(capture_current)
                .expect("valid unsampled context is propagated")
        });
        assert!(context.traceparent().ends_with("-00"));
    }

    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn exported_remote_child(
        traceparent: &str,
        tracestate: Option<&str>,
    ) -> opentelemetry_sdk::trace::SpanData {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        use tracing_subscriber::prelude::*;

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("tracewire-test"));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(parent: None, "remote-child");
            restore_remote_parent(&span, traceparent, tracestate);
            let _entered = span.enter();
        });
        exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "remote-child")
            .expect("remote child exported")
    }

    #[test]
    fn remote_parent_sets_exact_parent_and_inherits_tracestate() {
        let span = exported_remote_child(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            Some("vendor=value"),
        );
        assert_eq!(
            span.span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(span.span_context.trace_state().header(), "vendor=value");
    }

    #[test]
    fn remote_parent_malformed_value_starts_new_root() {
        let span = exported_remote_child("not-a-valid-traceparent", None);
        assert_eq!(span.parent_span_id, opentelemetry::trace::SpanId::INVALID);
    }

    #[test]
    fn remote_parent_malformed_state_is_dropped_without_losing_parent() {
        let span = exported_remote_child(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            Some("INVALID KEY=value"),
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(span.span_context.trace_state().header(), "");
    }

    #[test]
    fn remote_parent_oversized_value_starts_new_root() {
        let span = exported_remote_child(&"a".repeat(MAX_TRACE_CONTEXT_BYTES + 1), None);
        assert_eq!(span.parent_span_id, opentelemetry::trace::SpanId::INVALID);
    }

    #[test]
    fn remote_parent_oversized_state_is_dropped_without_losing_parent() {
        let state = "a".repeat(MAX_TRACE_CONTEXT_BYTES + 1);
        let span = exported_remote_child(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            Some(&state),
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(span.span_context.trace_state().header(), "");
    }
}
