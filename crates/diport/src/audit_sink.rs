//! `AuditSink` —— 审计事件接收 provider DI port（可替换：prod syslog/db / test in-mem）。
//!
//! 自 `observ`（服务层）迁入（issue #1075，ADR-003 DI port 收敛）：审计 sink 是可替换-provider 的
//! DI 注入接缝，归属 DI-infra 单源；端口数据类型（[`AuditEvent`] / [`AuditOutcome`]）随端口一并落本层。
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main

use dynosaur::dynosaur;

/// 审计 sink 失败。
///
/// PII 边界（与 [`crate::ShutdownError`] / [`crate::SignerError`] 同范式）：`Display` 仅安全摘要常量；
/// adapter 原始错误经 [`AuditSinkError::new`] 包成 [`std::error::Error::source`] 内部保留，**不进默认日志**。
#[derive(Debug, thiserror::Error)]
#[error("audit sink failed")]
pub struct AuditSinkError {
    #[source]
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl AuditSinkError {
    /// 把 adapter 内部错误包成审计失败。原始错误仅作 internal source 保留，不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: Box::new(source),
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
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// 事件发生时刻（由注入 [`crate::Clock`] 取得，非本类型直取系统时钟）。
    /// Clock 纪律由 caller 侧 `clippy.toml` `disallowed-methods`（`SystemTime::now`）在调用点静态拦截
    /// （Medium）；DI-infra 本类型不带构造强制（pub 字段，typed ctor 留 W 阶段）。
    pub occurred_at: std::time::SystemTime,
    /// 操作主体标识。待 typed id（W 阶段）。
    pub principal_id: String,
    /// 租户标识（非空 canonical UUID，tenancy.md fail-closed）。
    pub tenant_id: vocab::TenantId,
    /// 资源类别（const literal）。
    pub resource_kind: &'static str,
    /// 资源标识。待 typed id（W 阶段）。
    pub resource_id: String,
    /// 操作动作（const literal）。
    pub action: &'static str,
    /// 操作结果。
    pub outcome: AuditOutcome,
    /// 单次 HTTP 请求追踪 ID。
    pub request_id: Option<String>,
    /// 跨服务关联 ID，由 outbox envelope correlation 注入，与 request_id 不同语义。
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
        let err = AuditSinkError::new(std::fmt::Error);
        assert_eq!(err.to_string(), "audit sink failed");
        assert!(std::error::Error::source(&err).is_some());
    }
}
