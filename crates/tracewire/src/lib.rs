#![doc = include_str!("../README.md")]

//! W3C Trace Context capture / remote-parent restore candidate.
//!
//! trace 在 `业务请求 → outbox → relay → broker → consumer` 跨 async 边界断链：emit 侧不捕获当前 trace、
//! consumer 侧无法还原 ⇒ 端到端被 relay 切两段。本 crate 是 W3C propagation 的**唯一生产 OpenTelemetry bridge**（#1224 决策 2）——
//! producer 经 [`capture_current`] 把当前 `tracing` span 的 OTel 上下文导出为 W3C carrier（落 outbox
//! `metadata` 保留键 `trace`），consumer 经 [`restore_remote_parent`] 还原成 remote parent 挂到消费 span，使 handler
//! 与 producer **同一 `trace_id`**。HTTP server 入口也经同一 API 恢复 `traceparent` + `tracestate`。
//! emit、consume 与 HTTP server 的传播调用方只依赖本 crate、
//! 无需直接依赖 OTel 的传播类型；产品 host 自行安装 exporter。
//!
//! **fail-open**：诊断信道缺失从不阻塞投递——未装 otel 层 / span context 无效 ⇒ [`capture_current`] 返
//! `None`（不写 trace 键）；有效但未采样的 context 仍以 flags `00` 传播。入站值必须先经
//! [`TraceParent::parse`] 验证；attach 不可用由闭值 [`RestoreOutcome::Unavailable`] 表达。
//!
//! W3C 线格式 `00-<32hex traceid>-<16hex spanid>-<2hex flags>`（W3C Trace Context；OTel messaging producer
//! inject / consumer extract 约定）。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry-sdk/src/propagation/trace_context.rs@284a37d93b3856e1975c2807ba3af1421ebd9b52
//! ref: tokio-rs/tracing-opentelemetry src/span_ext.rs@1d5422f1f37932fd65e434da618b305d4c94ee9c

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::fmt;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// W3C Trace Context 透传 header 名（producer inject / consumer extract 的 carrier 键）。
const TRACEPARENT: &str = "traceparent";
const TRACESTATE: &str = "tracestate";
const MAX_TRACE_CONTEXT_BYTES: usize = 512;

/// A validated W3C `traceparent` header value.
///
/// The owned wire value deliberately has private fields and implements neither [`Debug`](fmt::Debug)
/// nor [`Display`](fmt::Display). Callers can only create it through [`TraceParent::parse`] and can
/// only expose the validated wire value explicitly through [`TraceParent::as_str`].
pub struct TraceParent(String);

impl TraceParent {
    /// Parse and validate a W3C Trace Context 1.1 `traceparent` value.
    ///
    /// Version `00` is the strict four-field form. Versions `01..fe` preserve an optional opaque
    /// suffix after the known 55-byte prefix. Version `ff` is reserved. Input is never trimmed or
    /// normalized.
    pub fn parse(value: &str) -> Result<Self, TraceParentError> {
        let bytes = value.as_bytes();
        if bytes.len() > MAX_TRACE_CONTEXT_BYTES {
            return Err(TraceParentError::Oversized);
        }
        if bytes.len() < 55
            || !bytes.is_ascii()
            || bytes[2] != b'-'
            || bytes[35] != b'-'
            || bytes[52] != b'-'
            || !bytes[..2].iter().copied().all(is_lower_hex)
        {
            return Err(TraceParentError::Malformed);
        }
        if bytes[..2] == *b"ff" {
            return Err(TraceParentError::UnsupportedVersion);
        }
        if !bytes[3..35].iter().copied().all(is_lower_hex)
            || bytes[3..35].iter().all(|byte| *byte == b'0')
            || !bytes[36..52].iter().copied().all(is_lower_hex)
            || bytes[36..52].iter().all(|byte| *byte == b'0')
            || !bytes[53..55].iter().copied().all(is_lower_hex)
        {
            return Err(TraceParentError::Malformed);
        }
        let version_zero = bytes[..2] == *b"00";
        if (version_zero && bytes.len() != 55)
            || (!version_zero && bytes.len() > 55 && bytes[55] != b'-')
        {
            return Err(TraceParentError::Malformed);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed, input-free `traceparent` rejection classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceParentError {
    /// The value does not satisfy the W3C Trace Context shape or identifier invariants.
    Malformed,
    /// The value exceeds the candidate's 512-byte defensive bound.
    Oversized,
    /// W3C version `ff` is reserved and cannot be propagated.
    UnsupportedVersion,
}

impl fmt::Display for TraceParentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed traceparent",
            Self::Oversized => "traceparent exceeds 512 bytes",
            Self::UnsupportedVersion => "unsupported traceparent version",
        })
    }
}

impl std::error::Error for TraceParentError {}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (byte >= b'a' && byte <= b'f')
}

/// 当前 span mint 的 W3C Trace Context carrier。
///
/// 字段与构造器均私有，且刻意不实现 `Debug`、`Display` 或序列化 trait；下游只能读取标准字段，
/// 不能伪造传播 authority。
///
/// INVARIANT: HTTP-CLIENT-CONTEXT-AUTHORITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "private fields and sole mint funnel" }
pub struct W3cTraceContext {
    traceparent: TraceParent,
    tracestate: Option<String>,
}

impl W3cTraceContext {
    /// W3C `traceparent` header value.
    #[must_use]
    pub fn traceparent(&self) -> &TraceParent {
        &self.traceparent
    }

    /// W3C `tracestate` header value when the current context carries one.
    #[must_use]
    pub fn tracestate(&self) -> Option<&str> {
        self.tracestate.as_deref()
    }

    /// Consume the carrier and return its `traceparent` value.
    #[must_use]
    pub fn into_traceparent(self) -> TraceParent {
        self.traceparent
    }
}

/// 捕获当前 `tracing` span 的有效 OTel 上下文为不可伪造的 W3C carrier。
///
/// **fail-open**：无 subscriber / 未装 `tracing-opentelemetry` 层 / span context 无效
/// (`is_valid()==false`) ⇒ propagator 不写 `traceparent` ⇒ 返 `None`。未采样不是无效 context，
/// 因此仍传播 flags `00`。
///
/// emit 调用方应在请求 span 所在的 task 中捕获，再将返回 carrier 放入消息的 trace context；
/// 数据库存储本身不负责读取 ambient tracing 状态。
#[must_use]
pub fn capture_current() -> Option<W3cTraceContext> {
    // 当前 span 的 OTel 上下文（无 tracing-opentelemetry 层时为 default Context，span context 无效）。
    let cx = tracing::Span::current().context();
    // W3C propagator 仅在 span context `is_valid()` 时写 `traceparent`（含采样判定）；无效则 carrier 空 → None。
    let mut carrier = std::collections::HashMap::<String, String>::new();
    TraceContextPropagator::new().inject_context(&cx, &mut carrier);
    let traceparent = TraceParent::parse(carrier.remove(TRACEPARENT)?.as_str()).ok()?;
    let tracestate = carrier
        .remove(TRACESTATE)
        .filter(|value| !value.is_empty() && value.len() <= MAX_TRACE_CONTEXT_BYTES);
    Some(W3cTraceContext {
        traceparent,
        tracestate,
    })
}

/// 把 W3C `traceparent` / `tracestate` 还原成 remote parent 挂到 `span`。
///
/// **fail-open**：parent 已在 trust boundary 完成验证；若 SDK 无法提取它，或 span 的 OTel layer / 可变
/// 状态不可用，则返回 [`RestoreOutcome::Unavailable`]，不 panic、不泄漏 SDK error，也不改变业务结果。
///
/// caller 必须在 span 首次 enter/instrument 前调用。畸形 `tracestate` 只丢 state，不使合法 parent 失效。
/// 产品 HTTP 入口或消息消费方在构造处理 span 时调用。
pub fn restore_remote_parent(
    span: &tracing::Span,
    traceparent: &TraceParent,
    tracestate: Option<&str>,
) -> RestoreOutcome {
    let mut carrier = std::collections::HashMap::<String, String>::new();
    carrier.insert(TRACEPARENT.to_owned(), traceparent.as_str().to_owned());
    if let Some(tracestate) = tracestate.filter(|value| value.len() <= MAX_TRACE_CONTEXT_BYTES) {
        carrier.insert(TRACESTATE.to_owned(), tracestate.to_owned());
    }
    let cx = TraceContextPropagator::new().extract(&carrier);
    if !cx.span().span_context().is_valid() {
        return RestoreOutcome::Unavailable;
    }
    span.set_parent(cx)
        .map(|()| RestoreOutcome::Restored)
        .unwrap_or(RestoreOutcome::Unavailable)
}

/// Closed result of attempting to attach a validated remote parent.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The remote context was attached before the span started.
    Restored,
    /// The tracing/OpenTelemetry layer or mutable span state was unavailable.
    Unavailable,
}

/// **私有单测脚手架**：在装好 `tracing-opentelemetry` 层
/// （确定性 `SdkTracerProvider`，默认 `ParentBased(AlwaysOn)` 采样根 span）的 subscriber 内同步跑 `f`，
/// 使 [`capture_current`] 在活跃 span 内产出有效 W3C carrier。
///
/// 仅本 crate 单测使用；本 helper 不进入 Release API，消费方自行安装测试 subscriber。
#[cfg(test)]
fn with_test_subscriber<R>(f: impl FnOnce() -> R) -> R {
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
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn trace_parent_parser_classifies_closed_errors_without_raw_input() {
        const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        for malformed in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4BF92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ] {
            assert!(matches!(
                TraceParent::parse(malformed),
                Err(TraceParentError::Malformed)
            ));
        }

        let oversized = "a".repeat(MAX_TRACE_CONTEXT_BYTES + 1);
        assert!(matches!(
            TraceParent::parse(&oversized),
            Err(TraceParentError::Oversized)
        ));
        let unsupported = VALID.replacen("00-", "ff-", 1);
        let error = TraceParent::parse(&unsupported)
            .err()
            .expect("ff is reserved");
        assert_eq!(error, TraceParentError::UnsupportedVersion);
        assert!(!error.to_string().contains(&unsupported));
    }

    #[test]
    fn trace_parent_version_zero_and_future_boundaries() {
        const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(TraceParent::parse(VALID).expect("v00").as_str(), VALID);

        let future = VALID.replacen("00-", "01-", 1);
        assert_eq!(
            TraceParent::parse(&future).expect("future base").as_str(),
            future
        );
        let future_with_opaque_suffix = format!("{future}-vendor-opaque");
        assert_eq!(
            TraceParent::parse(&future_with_opaque_suffix)
                .expect("future suffix")
                .as_str(),
            future_with_opaque_suffix
        );
        let future_with_empty_opaque_suffix = format!("{future}-");
        assert_eq!(
            TraceParent::parse(&future_with_empty_opaque_suffix)
                .expect("future delimiter")
                .as_str(),
            future_with_empty_opaque_suffix
        );
        let all_flags = VALID
            .strip_suffix("01")
            .expect("fixed flags prefix")
            .to_owned()
            + "ff";
        assert_eq!(
            TraceParent::parse(&all_flags)
                .expect("flags are a bitfield")
                .as_str(),
            all_flags
        );
        assert!(matches!(
            TraceParent::parse(&format!("{future}x")),
            Err(TraceParentError::Malformed)
        ));

        let mut at_limit = future;
        at_limit.push('-');
        at_limit.push_str(&"x".repeat(MAX_TRACE_CONTEXT_BYTES - at_limit.len()));
        assert_eq!(
            TraceParent::parse(&at_limit).expect("512 bytes").as_str(),
            at_limit
        );
        at_limit.push('x');
        assert!(matches!(
            TraceParent::parse(&at_limit),
            Err(TraceParentError::Oversized)
        ));
    }

    static_assertions::assert_not_impl_any!(TraceParent: std::fmt::Debug, std::fmt::Display);
    static_assertions::assert_not_impl_any!(W3cTraceContext: std::fmt::Debug, std::fmt::Display);

    /// `00-<32hex traceid>-<16hex spanid>-<2hex flags>` → trace_id 段（dash 间第 2 字段）。
    fn trace_id_of(traceparent: &str) -> &str {
        traceparent.split('-').nth(1).unwrap_or("")
    }

    // 活跃采样 span 内 capture → 合法 W3C traceparent（版本 00 + 32/16/2 hex）。
    // reason: 测试断言——`with_test_subscriber` 内采样根 span 的 capture 恒 Some，expect 即断言失败信息。
    #[allow(clippy::expect_used)]
    #[test]
    fn capture_inside_otel_span_yields_w3c() {
        let context =
            with_test_subscriber(|| tracing::info_span!("producer").in_scope(capture_current))
                .expect("capture inside sampled otel span yields trace context");
        let tp = context.traceparent().as_str();
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
            assert_eq!(
                restore_remote_parent(&child, &producer_tp, None),
                RestoreOutcome::Restored
            );
            let child_tp = child
                .in_scope(capture_current)
                .expect("child traceparent after restore")
                .into_traceparent();
            (producer_tp, child_tp)
        });
        assert_eq!(
            trace_id_of(producer_tp.as_str()),
            trace_id_of(child_tp.as_str()),
            "restore_remote_parent 后 consumer span 与 producer 同 trace_id"
        );
    }

    #[test]
    fn restore_without_otel_layer_is_unavailable() {
        let parent = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("fixed parent");
        let span = tracing::info_span!("consume");
        assert_eq!(
            restore_remote_parent(&span, &parent, None),
            RestoreOutcome::Unavailable
        );
    }

    #[test]
    fn restore_after_span_start_is_unavailable() {
        let parent = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("fixed parent");
        with_test_subscriber(|| {
            let span = tracing::info_span!(parent: None, "started");
            let _started_context = span.context();
            assert_eq!(
                restore_remote_parent(&span, &parent, None),
                RestoreOutcome::Unavailable
            );
        });
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn capture_preserves_tracestate() {
        let context = with_test_subscriber(|| {
            let span = tracing::info_span!(parent: None, "remote-child");
            let parent =
                TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                    .expect("fixed parent");
            assert_eq!(
                restore_remote_parent(&span, &parent, Some("vendor=value"),),
                RestoreOutcome::Restored
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
            let parent =
                TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")
                    .expect("fixed parent");
            assert_eq!(
                restore_remote_parent(&span, &parent, None,),
                RestoreOutcome::Restored
            );
            span.in_scope(capture_current)
                .expect("valid unsampled context is propagated")
        });
        assert!(context.traceparent().as_str().ends_with("-00"));
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
            let traceparent = TraceParent::parse(traceparent).expect("fixed valid traceparent");
            assert_eq!(
                restore_remote_parent(&span, &traceparent, tracestate),
                RestoreOutcome::Restored
            );
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
    fn remote_parent_malformed_state_is_dropped_without_losing_parent() {
        let span = exported_remote_child(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            Some("INVALID KEY=value"),
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(span.span_context.trace_state().header(), "");
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
