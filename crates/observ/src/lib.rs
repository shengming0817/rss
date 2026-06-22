//! observ — RSS 可观测性服务 crate。
//!
//! 提供：
//! - metrics label 闭值集（HttpLabel / EventLabel / CertLabel），编译期防高基数扩散
//! - provider-agnostic MetricLabel 出口（adapters/otel 负责映射 KeyValue；本 crate 不引 otel）
//! - AuditEvent 值类型 + AuditSink 接缝（impl 由 adapter 提供）
//! - SpanField 结构化日志字段闭值集
//!
//! 层级：服务层（依赖基础 + 引擎；不依赖域 / adapters）。
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/metrics/instruments/counter.rs@main
//! ADR-004 C8：签名冻结阶段覆盖率豁免，所有函数体 = todo!()。

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

/// EventBus Disposition 闭值集。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispositionLabel {
    Ack,
    Nack,
    Requeue,
}

/// EventBus metrics label 集合。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventLabel {
    Topic(&'static str),
    Disposition(DispositionLabel),
    Handler(&'static str),
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
    TenantClass(&'static str),
}

// ─── provider-agnostic MetricLabel 出口 ─────────────────────────────────────

/// label value 类型（adapters/otel 将其映射到 otel KeyValue；本 crate 不引 otel）。
///
/// 只保留 `Static(&'static str)`（compile-time literal），防止 runtime 动态字符串
/// 进入 label value 导致高基数扩散（F10，Medium）。
/// 进一步 sealed resolver 收紧（RouteTemplate/Domain/Topic/Handler/TenantClass）
/// 留待 W 阶段（#1076）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelValue {
    Static(&'static str),
}

/// provider-agnostic metric label 接口。
///
/// adapters/otel 实现：`fn to_key_value(l: &impl MetricLabel) -> KeyValue`。
pub trait MetricLabel {
    fn key(&self) -> &'static str;
    fn value(&self) -> LabelValue;
}

impl MetricLabel for HttpLabel {
    fn key(&self) -> &'static str {
        todo!()
    }

    fn value(&self) -> LabelValue {
        todo!()
    }
}

impl MetricLabel for EventLabel {
    fn key(&self) -> &'static str {
        todo!()
    }

    fn value(&self) -> LabelValue {
        todo!()
    }
}

impl MetricLabel for CertLabel {
    fn key(&self) -> &'static str {
        todo!()
    }

    fn value(&self) -> LabelValue {
        todo!()
    }
}

// ─── 审计事件 ────────────────────────────────────────────────────────────────

/// 审计操作结果。
///
/// `reason` 使用 `&'static str` const literal，遵循 error-handling const-literal 规范，
/// 防止 runtime 数据泄漏进 wire。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOutcome {
    Success,
    Failure { reason: &'static str },
}

/// 审计事件值类型。
///
/// `occurred_at` 由 Clock DI port 注入（见 diport::Clock），不得在本 crate 内直接调用
/// `SystemTime::now()`——本字段持有注入结果，非直接取系统时钟。
/// `action` 使用 `&'static str` const literal，遵循 error-handling const-literal 规范。
///
/// `tenant_id` 使用 `vocab::TenantId` 强类型，保证非空 + canonical UUID 校验（tenancy.md）。
/// `principal_id` / `resource_id` 待 typed id（W 阶段）。
/// `correlation_id` 为跨服务关联 ID，由 outbox envelope correlation 注入，与 `request_id` 不同语义：
/// `request_id` 跟踪单次 HTTP 请求，`correlation_id` 跟踪跨服务调用链。
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub occurred_at: std::time::SystemTime,
    /// 操作主体标识。待 typed id（W 阶段）。
    pub principal_id: String,
    /// 租户标识（非空 canonical UUID，tenancy.md fail-closed）。
    pub tenant_id: vocab::TenantId,
    pub resource_kind: &'static str,
    /// 资源标识。待 typed id（W 阶段）。
    pub resource_id: String,
    pub action: &'static str,
    pub outcome: AuditOutcome,
    /// 单次 HTTP 请求追踪 ID。
    pub request_id: Option<String>,
    /// 跨服务关联 ID，由 outbox envelope correlation 注入，与 request_id 不同语义。
    pub correlation_id: Option<String>,
}

// SAFETY note: AuditEvent 所有字段均 Send + Sync（SystemTime: Send+Sync, String: Send+Sync）。

/// 审计 sink 错误。
#[derive(Debug, thiserror::Error)]
#[error("audit sink failed")]
pub struct AuditSinkError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl AuditSinkError {
    pub fn new<E: std::error::Error + Send + Sync + 'static>(_source: E) -> Self {
        todo!()
    }
}

/// 审计 sink 接缝（impl 由 adapters 提供，注入 domain 消费）。
pub trait AuditSink: Send + Sync {
    fn record(
        &self,
        event: AuditEvent,
    ) -> futures::future::BoxFuture<'static, Result<(), AuditSinkError>>;
}

// ─── 结构化日志字段闭值集 ────────────────────────────────────────────────────

/// tracing span 结构化字段闭值集（限制 high-cardinality key 扩散）。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SpanField {
    Domain(&'static str),
    RequestId(String),
    TenantId(String),
    EntityId { kind: &'static str, id: String },
}

// ─── smoke tests（ADR-004 C8 覆盖率豁免；绝不调用 todo!() 体） ──────────────

#[cfg(test)]
mod tests {
    use super::*;

    // 构造各 label 变体，验证 enum 可达性
    #[test]
    fn http_label_variants_constructible() {
        let _m = HttpLabel::Method(HttpMethod::Get);
        let _m = HttpLabel::Method(HttpMethod::Post);
        let _m = HttpLabel::Method(HttpMethod::Put);
        let _m = HttpLabel::Method(HttpMethod::Delete);
        let _m = HttpLabel::Method(HttpMethod::Patch);
        let _m = HttpLabel::Method(HttpMethod::Other);
        let _s = HttpLabel::StatusClass(StatusClass::Class2xx);
        let _s = HttpLabel::StatusClass(StatusClass::Class4xx);
        let _s = HttpLabel::StatusClass(StatusClass::Class5xx);
        let _r = HttpLabel::RouteTemplate("/api/v1/example");
        let _d = HttpLabel::Domain("identity");
    }

    #[test]
    fn event_label_variants_constructible() {
        let _t = EventLabel::Topic("session.created");
        let _d = EventLabel::Disposition(DispositionLabel::Ack);
        let _d = EventLabel::Disposition(DispositionLabel::Nack);
        let _d = EventLabel::Disposition(DispositionLabel::Requeue);
        let _h = EventLabel::Handler("session_handler");
    }

    #[test]
    fn cert_label_variants_constructible() {
        let _i = CertLabel::Outcome(CertOutcomeLabel::Issued);
        let _r = CertLabel::Outcome(CertOutcomeLabel::Renewed);
        let _f = CertLabel::Outcome(CertOutcomeLabel::Failed);
        let _v = CertLabel::Outcome(CertOutcomeLabel::Revoked);
        let _tc = CertLabel::TenantClass("enterprise");
    }

    // 穷尽 match HttpLabel（同 crate 内 non_exhaustive 不强制 wildcard；列全变体即可）
    #[test]
    fn http_label_exhaustive_match() {
        let labels = vec![
            HttpLabel::Method(HttpMethod::Get),
            HttpLabel::StatusClass(StatusClass::Class2xx),
            HttpLabel::RouteTemplate("/test"),
            HttpLabel::Domain("audit"),
        ];
        for label in &labels {
            let _ = match label {
                HttpLabel::Method(_) => "method",
                HttpLabel::StatusClass(_) => "status_class",
                HttpLabel::RouteTemplate(_) => "route_template",
                HttpLabel::Domain(_) => "domain",
            };
        }
    }

    // 穷尽 match AuditOutcome（同 crate 内 non_exhaustive 不强制 wildcard；列全变体即可）
    #[test]
    fn audit_outcome_exhaustive_match() {
        let outcomes = vec![
            AuditOutcome::Success,
            AuditOutcome::Failure {
                reason: "unauthorized",
            },
        ];
        for outcome in &outcomes {
            let _ = match outcome {
                AuditOutcome::Success => "success",
                AuditOutcome::Failure { reason: _ } => "failure",
            };
        }
    }

    // 证明 AuditEvent: Send + Sync（fn 指针，编译即证明）
    fn _assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn audit_event_is_send_sync() {
        _assert_send_sync::<AuditEvent>();
    }

    // F9：通过不执行的闭包直接访问 AuditEvent 真实字段，
    // 让字段身份（名称 + 类型）进入编译期检查——字段改名/删除即编译失败（Hard）。
    #[test]
    fn audit_event_new_fields_type_shape() {
        // 不调用（仅类型检查）：字段改名/删除即编译失败
        let _assert_fields = |e: AuditEvent| {
            let _ = &e.tenant_id; // vocab::TenantId
            let _ = &e.correlation_id; // Option<String>
            let _ = &e.principal_id;
            let _ = &e.resource_kind;
            let _ = &e.resource_id;
            let _ = &e.action;
            let _ = &e.outcome;
            let _ = &e.occurred_at;
            let _ = &e.request_id;
        };
        let _ = &_assert_fields; // 绑定不调用
    }

    // 绑定 AuditSinkError::new fn 指针（不调用；只验证签名存在）
    #[test]
    fn audit_sink_error_new_fn_pointer_bindable() {
        // 绑定 fn 指针：验证 AuditSinkError::new 存在且签名正确
        // 不调用，避免触发 todo!()
        let _fn_ptr: fn(std::io::Error) -> AuditSinkError = AuditSinkError::new;
        let _ = _fn_ptr; // suppress unused warning
    }

    // 构造 SpanField 各变体
    #[test]
    fn span_field_variants_constructible() {
        let _d = SpanField::Domain("identity");
        let _r = SpanField::RequestId("req-123".to_owned());
        let _t = SpanField::TenantId("tenant-456".to_owned());
        let _e = SpanField::EntityId {
            kind: "session",
            id: "sess-789".to_owned(),
        };
    }

    // LabelValue 变体（F10：Owned 已移除，只保留 Static compile-time literal）
    #[test]
    fn label_value_variants_constructible() {
        let _s = LabelValue::Static("http.method");
    }
}
