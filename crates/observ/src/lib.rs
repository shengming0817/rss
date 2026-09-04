//! observ — RSS 可观测性服务 crate。
//!
//! 提供：
//! - metrics label 闭值集（HttpLabel / CertLabel），编译期防高基数扩散
//! - provider-agnostic MetricLabel 出口（adapters/otel 负责映射 KeyValue；本 crate 不引 otel）
//! - sink-neutral [`TelemetryResource`]（消费方一次性提供部署身份，JSON/OTLP 只做具名映射）
//!
//! 注：审计 sink（`AuditEvent` / `AuditOutcome` / `AuditSink`）是可替换-provider DI 注入端口，
//! 已迁 `diport`（issue #1075，ADR-003 DI port 收敛）——消费方经 `diport::AuditSink` 注入。
//!
//! 层级：服务层（依赖基础 + 引擎；不依赖域 / adapters）。
//! Eventing telemetry 经 `rss_eventing::observability` 的闭合 observation seam 注入；本 crate 的
//! [`EventingTelemetryEmitter`] 是唯一 production metrics/tracing 投影，不接收 domain/tenant/contract
//! 等动态 label，也不向 eventexec 反向暴露 runtime implementation。
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/metrics/instruments/counter.rs@main

mod eventing;
mod localtx;
mod telemetry;

pub use eventing::EventingTelemetryEmitter;
pub use localtx::{LocalTxMetric, LocalTxObservation};
pub use telemetry::{TelemetryResource, TelemetryResourceError};

// ─── metrics label 闭值集 ───────────────────────────────────────────────────

/// HTTP method 闭值集。
///
/// otel Counter::add 接受开放 key-value；RSS 用 enum 编译期闭合，防高基数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Other,
}

/// HTTP 状态码大类闭值集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusClass {
    Class2xx,
    Class4xx,
    Class5xx,
}

/// HTTP metrics label 集合（non_exhaustive：adapters 层可扩展 otel 映射，不影响 match 调用方）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpLabel {
    Method(HttpMethod),
    StatusClass(StatusClass),
    RouteTemplate(&'static str),
    Domain(&'static str),
}

/// 证书操作结果闭值集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOutcomeLabel {
    Issued,
    Renewed,
    Failed,
    Revoked,
}

/// 证书 metrics label 集合。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertLabel {
    Outcome(CertOutcomeLabel),
}

// ─── provider-agnostic MetricLabel 出口 ─────────────────────────────────────

/// label value 类型（adapters/otel 将其映射到 otel KeyValue；本 crate 不引 otel）。
///
/// 只保留 `Static(&'static str)`（compile-time literal），防止 runtime 动态字符串
/// 进入 label value 导致高基数扩散（F10，Medium）。
///
/// `RouteTemplate` / `Domain` 接受 `&'static str`，因此 runtime 动态身份不能进入
/// [`LabelValue`]；这不声明仓内拥有 route/domain catalog 或 assembly-derived closed set。
/// 外部消费者负责把自身 routing/domain facts 映射为稳定的低基数 literal，本 crate 只保留
/// sink-neutral 的具名投影边界。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelValue {
    Static(&'static str),
}

/// provider-agnostic metric label 接口。
///
/// `key()` 返回低基数 label 键（Prometheus 风格短 snake_case）；`value()` 返回
/// `LabelValue::Static`——只承编译期 literal，runtime 高基数串无法进入（F10）。
/// 携 `&'static str` 字段的变体（`RouteTemplate` / `Domain`）透传
/// 内串，调用方只许传 compile-time 类别字面量，不许传 runtime 标识（如租户 ID）。
///
/// value 大小写约定：HTTP method 用大写（对齐 OTel `http.request.method`），
/// 其余枚举派生值用小写（`2xx` / `ack` / `issued` …）。
///
/// 消费方（`adapters/otel` / `adapters/prometheus`）在各自 W 阶段声明 `observ`
/// 依赖并实现 `fn to_key_value(l: &impl MetricLabel) -> KeyValue` 完成映射；本 crate 不引 otel。
pub trait MetricLabel {
    fn key(&self) -> &'static str;
    fn value(&self) -> LabelValue;
}

impl MetricLabel for HttpLabel {
    fn key(&self) -> &'static str {
        match self {
            HttpLabel::Method(_) => "method",
            HttpLabel::StatusClass(_) => "status_class",
            HttpLabel::RouteTemplate(_) => "route_template",
            HttpLabel::Domain(_) => "domain",
        }
    }

    fn value(&self) -> LabelValue {
        match self {
            HttpLabel::Method(method) => LabelValue::Static(match method {
                HttpMethod::Get => "GET",
                HttpMethod::Post => "POST",
                HttpMethod::Put => "PUT",
                HttpMethod::Delete => "DELETE",
                HttpMethod::Patch => "PATCH",
                HttpMethod::Other => "OTHER",
            }),
            HttpLabel::StatusClass(class) => LabelValue::Static(match class {
                StatusClass::Class2xx => "2xx",
                StatusClass::Class4xx => "4xx",
                StatusClass::Class5xx => "5xx",
            }),
            // RouteTemplate / Domain 已是 compile-time literal，透传内串。
            HttpLabel::RouteTemplate(s) | HttpLabel::Domain(s) => LabelValue::Static(s),
        }
    }
}

impl MetricLabel for CertLabel {
    fn key(&self) -> &'static str {
        match self {
            CertLabel::Outcome(_) => "outcome",
        }
    }

    fn value(&self) -> LabelValue {
        match self {
            CertLabel::Outcome(outcome) => LabelValue::Static(match outcome {
                CertOutcomeLabel::Issued => "issued",
                CertOutcomeLabel::Renewed => "renewed",
                CertOutcomeLabel::Failed => "failed",
                CertOutcomeLabel::Revoked => "revoked",
            }),
        }
    }
}

// ─── 行为测试（W 阶段：穷举 MetricLabel::key()/value() 全分支） ──────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn telemetry_resource_rejects_empty_identity_and_has_named_accessors() {
        for values in [
            ("", "assembly-fp", "plan-fp"),
            ("runtime", "", "plan-fp"),
            ("runtime", "assembly-fp", ""),
        ] {
            assert!(TelemetryResource::try_new(values.0, values.1, values.2).is_err());
        }
        let resource = TelemetryResource::try_new("runtime", "assembly-fp", "plan-fp")
            .expect("non-empty resource");
        assert_eq!(resource.service_name(), "runtime");
        assert_eq!(resource.assembly_fingerprint(), "assembly-fp");
        assert_eq!(resource.runtime_plan_fingerprint(), "plan-fp");
    }

    // ── HttpLabel ────────────────────────────────────────────────────────
    #[test]
    fn http_label_method_key_value() {
        let cases = [
            (HttpMethod::Get, "GET"),
            (HttpMethod::Post, "POST"),
            (HttpMethod::Put, "PUT"),
            (HttpMethod::Delete, "DELETE"),
            (HttpMethod::Patch, "PATCH"),
            (HttpMethod::Other, "OTHER"),
        ];
        for (method, want) in cases {
            let label = HttpLabel::Method(method);
            assert_eq!(label.key(), "method");
            assert_eq!(label.value(), LabelValue::Static(want));
        }
    }

    #[test]
    fn http_label_status_class_key_value() {
        let cases = [
            (StatusClass::Class2xx, "2xx"),
            (StatusClass::Class4xx, "4xx"),
            (StatusClass::Class5xx, "5xx"),
        ];
        for (class, want) in cases {
            let label = HttpLabel::StatusClass(class);
            assert_eq!(label.key(), "status_class");
            assert_eq!(label.value(), LabelValue::Static(want));
        }
    }

    #[test]
    fn http_label_static_fields_pass_through() {
        let route = HttpLabel::RouteTemplate("/api/v1/example");
        assert_eq!(route.key(), "route_template");
        assert_eq!(route.value(), LabelValue::Static("/api/v1/example"));

        let domain = HttpLabel::Domain("identity");
        assert_eq!(domain.key(), "domain");
        assert_eq!(domain.value(), LabelValue::Static("identity"));
    }

    // ── CertLabel ────────────────────────────────────────────────────────
    #[test]
    fn cert_label_outcome_key_value() {
        let cases = [
            (CertOutcomeLabel::Issued, "issued"),
            (CertOutcomeLabel::Renewed, "renewed"),
            (CertOutcomeLabel::Failed, "failed"),
            (CertOutcomeLabel::Revoked, "revoked"),
        ];
        for (outcome, want) in cases {
            let label = CertLabel::Outcome(outcome);
            assert_eq!(label.key(), "outcome");
            assert_eq!(label.value(), LabelValue::Static(want));
        }
    }

    // F10：Owned 已移除，只保留 Static compile-time literal
    #[test]
    fn label_value_static_eq() {
        assert_eq!(
            LabelValue::Static("http.method"),
            LabelValue::Static("http.method")
        );
        // anti-vacuity：不同 literal 必须不等（双向验证 PartialEq）
        assert_ne!(LabelValue::Static("a"), LabelValue::Static("b"));
    }

    // 通用 HTTP/cert label 仍保持 static-only；Eventing 使用独立闭合 observation seam。
    #[test]
    fn label_value_remains_static_only() {
        let labels = [
            HttpLabel::Domain("identity").value(),
            CertLabel::Outcome(CertOutcomeLabel::Issued).value(),
        ];

        assert_eq!(
            labels,
            [LabelValue::Static("identity"), LabelValue::Static("issued"),]
        );
    }
}
