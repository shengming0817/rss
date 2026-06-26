//! `AuditSink` —— 审计事件接收 provider DI port（可替换：prod syslog/db / test in-mem）。
//!
//! 自 `observ`（服务层）迁入（issue #1075，ADR-003 DI port 收敛）：审计 sink 是可替换-provider 的
//! DI 注入接缝，归属 DI-infra 单源；端口数据类型（[`AuditEvent`] / [`AuditOutcome`]）随端口一并落本层。
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main

use dynosaur::dynosaur;

use crate::redacted::RedactedSource;

/// 审计 sink 失败。
///
/// PII 边界（与 [`crate::ShutdownError`] / [`crate::SignerError`] 同范式）：`Display` 仅安全摘要常量；
/// source 经 [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`——
/// 原始错误不经任何 `Error` 接口暴露，fail-closed），见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01。
#[derive(Debug, thiserror::Error)]
#[error("audit sink failed")]
pub struct AuditSinkError {
    #[source]
    source: RedactedSource,
}

impl AuditSinkError {
    /// 把 adapter 内部错误包成审计失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

/// 审计操作结果。
///
/// `reason` 使用 `&'static str` const literal，遵循 error-handling const-literal 规范，
/// 防止 runtime 数据泄漏进 wire。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditOutcome {
    /// 操作成功。
    Success,
    /// 操作失败，`reason` 为 const-literal 安全摘要。
    Failure {
        /// 失败原因（const literal，非 runtime 数据）。
        reason: &'static str,
    },
}

/// 审计事件值类型（[`AuditSink::record`] 的入参 DTO）。
///
/// `occurred_at` 由 [`crate::Clock`] DI port 注入结果填入（caller 取注入时钟，本类型不直接取系统时钟）。
/// `action` / `resource_kind` 使用 `&'static str` const literal，遵循 error-handling const-literal 规范。
///
/// `tenant_id` 使用 [`vocab::TenantId`] 强类型，保证非空 + canonical UUID 校验（tenancy.md fail-closed）。
/// `principal_id` / `resource_id` 待 typed id（W 阶段）。
/// `correlation_id` 为跨服务关联 ID（由 outbox envelope correlation 注入），与 `request_id`（单次 HTTP
/// 请求追踪）不同语义。
#[derive(Clone, secure::Redact)]
pub struct AuditEvent {
    /// 事件发生时刻（由注入 [`crate::Clock`] 取得，非本类型直取系统时钟）。
    /// Clock 纪律由 caller 侧 `clippy.toml` `disallowed-methods`（`SystemTime::now`）在调用点静态拦截
    /// （Medium）；DI-infra 本类型不带构造强制（pub 字段，typed ctor 留 W 阶段）。
    #[redact(public)]
    pub occurred_at: std::time::SystemTime,
    /// 操作主体标识。待 typed id（W 阶段）。
    #[redact(pii = "generic")]
    pub principal_id: String,
    /// 租户标识（非空 canonical UUID，tenancy.md fail-closed）。
    #[redact(public)]
    pub tenant_id: vocab::TenantId,
    /// 资源类别（const literal）。
    #[redact(public)]
    pub resource_kind: &'static str,
    /// 资源标识。待 typed id（W 阶段）。
    #[redact(pii = "generic")]
    pub resource_id: String,
    /// 操作动作（const literal）。
    #[redact(public)]
    pub action: &'static str,
    /// 操作结果。
    #[redact(public)]
    pub outcome: AuditOutcome,
    /// 单次 HTTP 请求追踪 ID。
    #[redact(internal)]
    pub request_id: Option<String>,
    /// 跨服务关联 ID，由 outbox envelope correlation 注入，与 request_id 不同语义。
    #[redact(internal)]
    pub correlation_id: Option<String>,
}

/// 审计事件接收 provider DI port（async）。
///
/// 公开 [`AuditSink`] 是 **Send 变体**（adapters `impl AuditSink for ...`），[`DynAuditSink`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynAuditSink>` / `Arc<DynAuditSink>` 注入）。非 Send 基 trait
/// `AuditSinkLocal` 仅供静态分发窄场景，不在 crate 根 re-export（见 crate rustdoc）。
///
/// dyn-safe 约束（ADR-003 §4.6）：方法 `&self`、参数 / 返回为具体类型、supertrait 仅 Send、
/// 带 `async fn shutdown`（无 async Drop）。
#[trait_variant::make(AuditSink: Send)]
#[dynosaur(pub DynAuditSink = dyn(box) AuditSink, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `AuditSink` 变体 +
// dynosaur `DynAuditSink` 承载（DI 注入走 Send wrapper）。这是 ADR-003 既定 dyn-port 范式。
pub trait AuditSinkLocal {
    /// 记录一条审计事件（provider 据 ctx 租户 fail-closed 落 sink）。
    async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError>;

    /// 异步释放 provider 资源（无 async Drop）。有 infra 资源（连接 / 句柄）的 adapter 应同时
    /// `impl ManagedResource` 由 `bootstrap::ShutdownStack` 统一编排；本方法是 port-local 关闭路径
    /// （参 [`crate::Signer::shutdown`]）。
    async fn shutdown(&self) -> Result<(), AuditSinkError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 async DI port 可 native AFIT impl + 经 `Box<DynAuditSink>` 动态注入。
    use super::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError, DynAuditSink};

    fn _assert_send_sync<T: Send + Sync>() {}

    struct NoopAuditSink;
    impl AuditSink for NoopAuditSink {
        async fn record(&self, _event: AuditEvent) -> Result<(), AuditSinkError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), AuditSinkError> {
            Ok(())
        }
    }

    // multi_thread + spawn：验证 boxed future Send（trait_variant Send 变体），与真实 spawn 场景对齐。
    // `record` 入参 `AuditEvent` 含 `vocab::TenantId`（fail-closed，无 infallible 构造、`parse` 仍冻结），
    // 当前不可构造，故注入路径经无参 `shutdown()` 验证；`record` 的签名/可达性由上方 native AFIT impl
    // 编译期保证（impl 必须匹配 trait）。
    #[tokio::test(flavor = "multi_thread")]
    async fn audit_sink_is_dyn_injectable() {
        let sink: Box<DynAuditSink> = DynAuditSink::new_box(NoopAuditSink);
        let joined = tokio::spawn(async move { sink.shutdown().await.is_ok() }).await;
        assert!(matches!(joined, Ok(true)));
    }

    // AuditEvent 字段身份（名称 + 类型）进入编译期检查——字段改名/删除即编译失败（Hard）。
    // 非执行闭包（AuditEvent 当前不可构造）。
    #[test]
    fn audit_event_field_shape() {
        let _assert_fields = |e: AuditEvent| {
            let _ = &e.occurred_at;
            let _ = &e.principal_id;
            let _ = &e.tenant_id; // vocab::TenantId
            let _ = &e.resource_kind;
            let _ = &e.resource_id;
            let _ = &e.action;
            let _ = &e.outcome;
            let _ = &e.request_id;
            let _ = &e.correlation_id; // Option<String>
        };
        let _ = &_assert_fields;
    }

    #[test]
    fn audit_event_is_send_sync() {
        _assert_send_sync::<AuditEvent>();
    }

    // 穷尽 match AuditOutcome（同 crate 内 non_exhaustive 不强制 wildcard；列全变体即可）。
    #[test]
    fn audit_outcome_exhaustive_match() {
        for outcome in &[
            AuditOutcome::Success,
            AuditOutcome::Failure {
                reason: "unauthorized",
            },
        ] {
            let _ = match outcome {
                AuditOutcome::Success => "success",
                AuditOutcome::Failure { reason: _ } => "failure",
            };
        }
    }

    // AuditSinkError::new 在 diport 写实（非冻结 todo!()）：Display 仅安全摘要常量，原始错误进 source。
    #[test]
    fn audit_sink_error_wraps_source() {
        let err = AuditSinkError::new(std::io::Error::other("leak-marker-audit"));
        assert_eq!(err.to_string(), "audit sink failed");
        assert!(std::error::Error::source(&err).is_some());
        // 端到端：derive(Debug) 经 RedactedSource 脱敏、不展开内层 source（anti-vacuity 前置）。
        assert!(
            format!("{:?}", std::io::Error::other("leak-marker-audit"))
                .contains("leak-marker-audit"),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !format!("{err:?}").contains("leak-marker-audit"),
            "wrapper Debug 泄漏 source: {err:?}"
        );
    }
}

#[cfg(test)]
mod pii_debug {
    //! `AuditEvent` Debug 脱敏回归：`principal_id`（subject=PII）/ `resource_id` + 裸 `Option<String>`
    //! 追踪 ID（`request_id` / `correlation_id`，无 typed funnel）不进 Debug/tracing。
    //! INVARIANT: DIPORT-DTO-PII-DEBUG-REDACT-01（derive Redact 脱敏 PII；对标 `RateLimitError` /
    //! `identity::RoleBinding` / `audit::ResourceRef`）。
    use super::{AuditEvent, AuditOutcome};

    // item-level carve-out（同 vocab tenant 测试）：canonical 常量 UUID 解析必成功，测试期 unwrap 受控。
    #[allow(clippy::unwrap_used)]
    fn sample() -> AuditEvent {
        AuditEvent {
            occurred_at: std::time::SystemTime::UNIX_EPOCH,
            principal_id: "alice@corp.example".to_string(),
            tenant_id: vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap(),
            resource_kind: "session",
            resource_id: "device-7f3a".to_string(),
            action: "login",
            outcome: AuditOutcome::Success,
            request_id: Some("req-sensitive-1".to_string()),
            correlation_id: Some("corr-sensitive-7".to_string()),
        }
    }

    #[test]
    fn debug_redacts_pii_and_untyped_tracing_ids() {
        let dbg = format!("{:?}", sample());
        // PII 脱敏
        assert!(
            !dbg.contains("alice@corp.example"),
            "principal_id 泄漏: {dbg}"
        );
        assert!(!dbg.contains("device-7f3a"), "resource_id 泄漏: {dbg}");
        // 裸 Option<String> 追踪 ID 值脱敏（零信任：类型无 PII 保证）
        assert!(!dbg.contains("req-sensitive-1"), "request_id 值泄漏: {dbg}");
        assert!(
            !dbg.contains("corr-sensitive-7"),
            "correlation_id 值泄漏: {dbg}"
        );
        assert!(dbg.contains("<redacted>"), "缺 <redacted> 占位: {dbg}");
        // internal 字段固定脱敏，不暴露 Option 的 Some/None 存在性。
        assert!(
            dbg.contains("request_id: <redacted>"),
            "request_id 应固定脱敏: {dbg}"
        );
        assert!(
            dbg.contains("correlation_id: <redacted>"),
            "correlation_id 应固定脱敏: {dbg}"
        );
        // 非 PII 字段仍可观测（诊断价值）
        assert!(dbg.contains("login"), "action 应可见: {dbg}");
        assert!(dbg.contains("session"), "resource_kind 应可见: {dbg}");
        assert!(dbg.contains("f47ac10b"), "tenant_id 应可见: {dbg}");
    }
}
