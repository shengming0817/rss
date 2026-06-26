//! `tracewire` —— outbox 异步边界的 W3C `traceparent` capture / restore 单源（#1224）。
//!
//! trace 在 `业务请求 → outbox → relay → broker → consumer` 跨 async 边界断链：emit 侧不捕获当前 trace、
//! consumer 侧无法还原 ⇒ 端到端被 relay 切两段。本 crate 是**唯一碰 `opentelemetry` 的新落点**（#1224 决策 2）——
//! producer 经 [`capture`] 把当前 `tracing` span 的 OTel 上下文导出为 W3C `traceparent` 串（落 outbox
//! `metadata` 保留键 `trace`），consumer 经 [`restore_parent`] 还原成 remote parent 挂到消费 span，使 handler
//! 与 producer **同一 `trace_id`**。`adapters/postgres`（emit）与 `crates/eventexec`（consume）只依赖本 crate、
//! **不直接 import otel**，延续 RSS「otel 收口」治理（`adapters/otel` / `diagctx` / `observ` 同思路）。
//!
//! **fail-open**：诊断信道缺失从不阻塞投递——未装 otel 层 / span context 无效 / 未采样 ⇒ [`capture`] 返
//! `None`（不写 trace 键）；`traceparent` 畸形 ⇒ [`restore_parent`] no-op（span 保持 root，不 panic）。
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

/// 捕获当前 `tracing` span 的 OTel 上下文为 W3C `traceparent` 串。
///
/// **fail-open**：无 subscriber / 未装 `tracing-opentelemetry` 层 / span context 无效（`is_valid()==false`，
/// 含未采样）⇒ propagator 不写 `traceparent` ⇒ 返 `None`（caller 据此「有则盖章、无则省略」，绝不阻投递）。
///
/// 生产 caller：`adapters/postgres` 的 `metadata_with_ambient`（emit 与 handler 同 task 同步执行 ⇒
/// `Span::current()` 即请求 span），把结果写入 outbox `metadata` 保留键 `trace`。
#[must_use]
pub fn capture() -> Option<String> {
    // 当前 span 的 OTel 上下文（无 tracing-opentelemetry 层时为 default Context，span context 无效）。
    let cx = tracing::Span::current().context();
    // W3C propagator 仅在 span context `is_valid()` 时写 `traceparent`（含采样判定）；无效则 carrier 空 → None。
    let mut carrier = std::collections::HashMap::<String, String>::new();
    TraceContextPropagator::new().inject_context(&cx, &mut carrier);
    carrier.remove(TRACEPARENT).filter(|s| !s.is_empty())
}

/// 把 W3C `traceparent` 还原成 remote parent 挂到 `span`（使其与 producer 同 `trace_id`）。
///
/// **fail-open**：`traceparent` 畸形 / 空 ⇒ 解析出无效 SpanContext，`set_parent` 不改 trace 归属（span 保持
/// 自身 root），**不 panic**——迟到 / 损坏的诊断信道不影响消费正确性。
///
/// 生产 caller：`crates/eventexec` 的 consumer Fresh 路径（读 `Message.metadata` 的 `trace` 键，挂到消费 span，
/// 再 `instrument` handler）。
pub fn restore_parent(span: &tracing::Span, traceparent: &str) {
    // 单键 carrier 经 W3C propagator extract 成 remote-parent Context；畸形 → 无效 SpanContext（set_parent no-op）。
    let mut carrier = std::collections::HashMap::<String, String>::new();
    carrier.insert(TRACEPARENT.to_owned(), traceparent.to_owned());
    let cx = TraceContextPropagator::new().extract(&carrier);
    if let Err(e) = span.set_parent(cx) {
        // reason: fail-open——set_parent 仅在 span 已 disabled/closed 或 layer 不可 downcast 时 Err（罕见）；
        // trace 续传是 best-effort 诊断，降级为 debug、消费 span 保持 root，绝不阻断消费。
        tracing::debug!(target: "tracewire", error = %e, "restore_parent: set_parent failed; consume span stays root");
    }
}

/// **测试脚手架**（`test-util` feature / 本 crate 单测）：在装好 `tracing-opentelemetry` 层
/// （确定性 `SdkTracerProvider`，默认 `ParentBased(AlwaysOn)` 采样根 span）的 subscriber 内同步跑 `f`，
/// 使 [`capture`] 在活跃 span 内产出有效 `traceparent`。
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `00-<32hex traceid>-<16hex spanid>-<2hex flags>` → trace_id 段（dash 间第 2 字段）。
    fn trace_id_of(traceparent: &str) -> &str {
        traceparent.split('-').nth(1).unwrap_or("")
    }

    // 活跃采样 span 内 capture → 合法 W3C traceparent（版本 00 + 32/16/2 hex）。
    // reason: 测试断言——`with_test_subscriber` 内采样根 span 的 capture 恒 Some，expect 即断言失败信息。
    #[allow(clippy::expect_used)]
    #[test]
    fn capture_inside_otel_span_yields_w3c() {
        let tp = with_test_subscriber(|| tracing::info_span!("producer").in_scope(capture))
            .expect("capture inside sampled otel span yields traceparent");
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
        assert_eq!(capture(), None);
    }

    // round-trip：capture → restore_parent 后 consumer span 与 producer 同 trace_id（issue 验收）。
    // reason: 测试断言——producer/child span 在 `with_test_subscriber` 内恒采样，capture 恒 Some。
    #[allow(clippy::expect_used)]
    #[test]
    fn roundtrip_capture_restore_same_trace_id() {
        let (producer_tp, child_tp) = with_test_subscriber(|| {
            let producer_tp = tracing::info_span!("producer")
                .in_scope(capture)
                .expect("producer traceparent");
            let child = tracing::info_span!("consume");
            restore_parent(&child, &producer_tp);
            let child_tp = child
                .in_scope(capture)
                .expect("child traceparent after restore");
            (producer_tp, child_tp)
        });
        assert_eq!(
            trace_id_of(&producer_tp),
            trace_id_of(&child_tp),
            "restore_parent 后 consumer span 与 producer 同 trace_id"
        );
    }

    // 畸形 traceparent → no-op、不 panic（graceful degradation）。
    #[test]
    fn restore_malformed_is_noop_no_panic() {
        with_test_subscriber(|| {
            let span = tracing::info_span!("consume");
            restore_parent(&span, "not-a-valid-traceparent");
            let _ = span.in_scope(capture); // 不 panic 即通过
        });
    }
}
