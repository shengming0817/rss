//! 跨域错误词汇（ADR-004 C10）。
//!
//! `kind` 的 message 是 `&'static str` const literal（禁 `format!` 拼 runtime 数据）；
//! runtime 数据只经两条 typed 通道：[`CoreError::with_details`]（4xx 可下发、5xx 由 wire mapper
//! 强制 strip）与 [`CoreError::with_internal`]（只进服务端日志、永不进 wire）。`CoreError`
//! 私有字段冻结 typed 通道——「把 runtime PII 拼进 message」从类型层不可表达。

use std::time::{Duration, SystemTime};

/// 跨域错误种类。每个 variant 的稳定 message 为 `&'static str` const literal。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreErrorKind {
    NotFound,
    Unauthenticated,
    Forbidden,
    /// 同一 outbox event id 已绑定到不同稳定事实；重试不会改变既有事实。
    OutboxFactConflict,
    /// 乐观并发版本已变化；重新读取后可安全重试。
    VersionConflict,
    Conflict,
    Validation,
    PayloadTooLarge,
    TooManyRequests,
    /// 服务端在显式请求预算内无法完成处理；请求 outcome 未知，不宣告可安全重试。
    Unavailable,
    /// 必需的下游 provider 暂时不可用；当前请求未产生业务事实，可安全重试。
    ProviderUnavailable,
    NotImplemented,
    Internal,
}

impl CoreErrorKind {
    /// 稳定 message（`&'static str` const literal；无 runtime 数据）。
    pub fn message(self) -> &'static str {
        match self {
            CoreErrorKind::NotFound => "not found",
            CoreErrorKind::Unauthenticated => "unauthenticated",
            CoreErrorKind::Forbidden => "forbidden",
            CoreErrorKind::OutboxFactConflict => "outbox fact conflict",
            CoreErrorKind::VersionConflict => "version conflict",
            CoreErrorKind::Conflict => "conflict",
            CoreErrorKind::Validation => "validation error",
            CoreErrorKind::PayloadTooLarge => "payload too large",
            CoreErrorKind::TooManyRequests => "too many requests",
            CoreErrorKind::Unavailable => "service unavailable",
            CoreErrorKind::ProviderUnavailable => "provider unavailable",
            CoreErrorKind::NotImplemented => "not implemented",
            CoreErrorKind::Internal => "internal error",
        }
    }

    /// 稳定错误码（`&'static str` const literal）；统一 wire 错误响应 `error.code` 的单源
    /// `ERR_CORE_*` 前缀由 `vocab` 持有，golden 测试锁全集防漂移。
    ///
    /// 注：跨 crate `ERR_<SEG>_` 前缀所有权注册表（多 crate mint 时）是独立治理子系统（见 #1099）；
    /// 本 PR `vocab` 是 `ERR_CORE_` 唯一 minter，golden 即所有权锁。
    pub fn code(self) -> &'static str {
        match self {
            CoreErrorKind::NotFound => "ERR_CORE_NOT_FOUND",
            CoreErrorKind::Unauthenticated => "ERR_CORE_UNAUTHENTICATED",
            CoreErrorKind::Forbidden => "ERR_CORE_FORBIDDEN",
            CoreErrorKind::OutboxFactConflict => "ERR_CORE_OUTBOX_FACT_CONFLICT",
            CoreErrorKind::VersionConflict => "ERR_CORE_VERSION_CONFLICT",
            CoreErrorKind::Conflict => "ERR_CORE_CONFLICT",
            CoreErrorKind::Validation => "ERR_CORE_VALIDATION",
            CoreErrorKind::PayloadTooLarge => "ERR_CORE_PAYLOAD_TOO_LARGE",
            CoreErrorKind::TooManyRequests => "ERR_CORE_TOO_MANY_REQUESTS",
            CoreErrorKind::Unavailable => "ERR_CORE_UNAVAILABLE",
            CoreErrorKind::ProviderUnavailable => "ERR_CORE_PROVIDER_UNAVAILABLE",
            CoreErrorKind::NotImplemented => "ERR_CORE_NOT_IMPLEMENTED",
            CoreErrorKind::Internal => "ERR_CORE_INTERNAL",
        }
    }

    /// 客户端可否在请求事实不变时安全重试。
    ///
    /// 默认 fail-closed：仅明确的乐观并发、节流与未产生事实的 provider outage 可重试；
    /// 事实冲突和 outcome 未知的请求预算耗尽始终不可重试。
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            CoreErrorKind::VersionConflict
                | CoreErrorKind::TooManyRequests
                | CoreErrorKind::ProviderUnavailable
        )
    }
}

/// 公开错误明细（4xx 可下发；5xx 由 wire mapper 强制 strip）。typed 闭值集——
/// 每条带 `&'static str` key + typed 安全值，禁裸 `String` message 夹带 PII。
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PublicDetail {
    Str(&'static str, String),
    Int(&'static str, i64),
    Bool(&'static str, bool),
    Duration(&'static str, Duration),
    Time(&'static str, SystemTime),
}

/// 内部错误属性（只进服务端日志，永不进 wire）。typed 闭值集。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InternalAttr {
    Str(&'static str, String),
    Int(&'static str, i64),
}

/// 跨域核心错误（私有字段 record；runtime 数据经 `with_details` / `with_internal` typed 通道）。
///
/// `Display` 只输出 `kind` 的 const message——绝不拼 public/internal 明细，避免 PII 误入日志/wire。
///
/// `Debug` 手写实现：只输出 kind 与 public/internal 条目**数量**，永不渲染任何属性键或值
/// （`tracing::error!(?err)` 等 `?` 展开路径与 HTTP wire 路径同等安全）。
#[derive(thiserror::Error)]
#[error("{}", .kind.message())]
pub struct CoreError {
    kind: CoreErrorKind,
    public: Vec<PublicDetail>,
    internal: Vec<InternalAttr>,
}

impl std::fmt::Debug for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 只输出 kind 与条目数量，永不渲染键或值——防止内部属性经 `?err` span 路径泄露。
        f.debug_struct("CoreError")
            .field("kind", &self.kind)
            .field("public", &self.public.len())
            .field("internal", &self.internal.len())
            .finish()
    }
}

impl CoreError {
    /// 由 kind 构造（无 runtime 数据）。
    pub fn new(kind: CoreErrorKind) -> Self {
        Self {
            kind,
            public: Vec::new(),
            internal: Vec::new(),
        }
    }

    /// 追加可下发公开明细（4xx 下发；5xx 由 wire mapper strip）。
    pub fn with_details(mut self, detail: PublicDetail) -> Self {
        self.public.push(detail);
        self
    }

    /// 追加仅日志内部属性（永不进 wire）。
    pub fn with_internal(mut self, attr: InternalAttr) -> Self {
        self.internal.push(attr);
        self
    }

    /// 错误种类。
    pub fn kind(&self) -> CoreErrorKind {
        self.kind
    }

    /// 公开明细（wire mapper 只读这些；5xx strip）。
    pub fn public_details(&self) -> &[PublicDetail] {
        &self.public
    }

    /// 内部属性（只进日志）。
    pub fn internal_attrs(&self) -> &[InternalAttr] {
        &self.internal
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreError, CoreErrorKind, InternalAttr, PublicDetail};
    use std::time::{Duration, SystemTime};

    #[test]
    fn kind_messages_are_stable_literals() {
        let cases: &[(CoreErrorKind, &str)] = &[
            (CoreErrorKind::NotFound, "not found"),
            (CoreErrorKind::Unauthenticated, "unauthenticated"),
            (CoreErrorKind::Forbidden, "forbidden"),
            (CoreErrorKind::OutboxFactConflict, "outbox fact conflict"),
            (CoreErrorKind::VersionConflict, "version conflict"),
            (CoreErrorKind::Conflict, "conflict"),
            (CoreErrorKind::Validation, "validation error"),
            (CoreErrorKind::PayloadTooLarge, "payload too large"),
            (CoreErrorKind::TooManyRequests, "too many requests"),
            (CoreErrorKind::Unavailable, "service unavailable"),
            (CoreErrorKind::ProviderUnavailable, "provider unavailable"),
            (CoreErrorKind::NotImplemented, "not implemented"),
            (CoreErrorKind::Internal, "internal error"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.message(), *expected, "kind={kind:?}");
        }
    }

    #[test]
    fn kind_codes_are_stable_golden() {
        // golden：错误码是 wire 契约（`error.code`），漂移即破坏消费方——精确锁全集。
        let cases: &[(CoreErrorKind, &str)] = &[
            (CoreErrorKind::NotFound, "ERR_CORE_NOT_FOUND"),
            (CoreErrorKind::Unauthenticated, "ERR_CORE_UNAUTHENTICATED"),
            (CoreErrorKind::Forbidden, "ERR_CORE_FORBIDDEN"),
            (CoreErrorKind::Conflict, "ERR_CORE_CONFLICT"),
            (
                CoreErrorKind::OutboxFactConflict,
                "ERR_CORE_OUTBOX_FACT_CONFLICT",
            ),
            (CoreErrorKind::VersionConflict, "ERR_CORE_VERSION_CONFLICT"),
            (CoreErrorKind::Validation, "ERR_CORE_VALIDATION"),
            (CoreErrorKind::PayloadTooLarge, "ERR_CORE_PAYLOAD_TOO_LARGE"),
            (CoreErrorKind::TooManyRequests, "ERR_CORE_TOO_MANY_REQUESTS"),
            (CoreErrorKind::Unavailable, "ERR_CORE_UNAVAILABLE"),
            (
                CoreErrorKind::ProviderUnavailable,
                "ERR_CORE_PROVIDER_UNAVAILABLE",
            ),
            (CoreErrorKind::NotImplemented, "ERR_CORE_NOT_IMPLEMENTED"),
            (CoreErrorKind::Internal, "ERR_CORE_INTERNAL"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.code(), *expected, "kind={kind:?}");
            // 错误码命名空间前缀不变式：全集均 `ERR_CORE_` 前缀。
            assert!(kind.code().starts_with("ERR_CORE_"), "kind={kind:?}");
        }
    }

    #[test]
    fn retryability_is_explicit_and_fact_conflict_is_terminal() {
        assert!(
            CoreErrorKind::VersionConflict.retryable(),
            "CAS conflict is retryable"
        );
        assert!(!CoreErrorKind::Conflict.retryable());
        assert!(
            !CoreErrorKind::Unavailable.retryable(),
            "request timeout has an unknown outcome and is not blanket-retryable"
        );
        assert!(
            CoreErrorKind::ProviderUnavailable.retryable(),
            "a serving dependency outage before business handling is retryable"
        );
        assert!(
            !CoreErrorKind::OutboxFactConflict.retryable(),
            "an event id bound to another fact is terminal"
        );
    }

    #[test]
    fn new_constructs_with_empty_detail_vecs() {
        let err = CoreError::new(CoreErrorKind::NotFound);
        assert_eq!(err.kind(), CoreErrorKind::NotFound);
        assert!(err.public_details().is_empty());
        assert!(err.internal_attrs().is_empty());
    }

    #[test]
    fn with_details_appends_and_is_chainable() {
        let err = CoreError::new(CoreErrorKind::Validation)
            .with_details(PublicDetail::Str("field", "name".to_string()))
            .with_details(PublicDetail::Int("code", 42));
        assert_eq!(err.kind(), CoreErrorKind::Validation);
        assert_eq!(err.public_details().len(), 2);
        assert!(err.internal_attrs().is_empty());
        assert_eq!(
            err.public_details()[0],
            PublicDetail::Str("field", "name".to_string())
        );
        assert_eq!(err.public_details()[1], PublicDetail::Int("code", 42));
    }

    #[test]
    fn with_internal_appends_and_is_chainable() {
        let err = CoreError::new(CoreErrorKind::Internal)
            .with_internal(InternalAttr::Str("trace", "abc".to_string()))
            .with_internal(InternalAttr::Int("errno", 13));
        assert_eq!(err.kind(), CoreErrorKind::Internal);
        assert!(err.public_details().is_empty());
        assert_eq!(err.internal_attrs().len(), 2);
    }

    #[test]
    fn display_outputs_kind_message_only() {
        let err = CoreError::new(CoreErrorKind::Forbidden)
            .with_details(PublicDetail::Bool("active", false))
            .with_internal(InternalAttr::Str("secret", "s3cr3t".to_string()));
        // Display 只输出 kind message，不拼 runtime 明细（PII 安全）
        assert_eq!(err.to_string(), "forbidden");
    }

    #[test]
    fn public_detail_variants_are_constructible() {
        let _str = PublicDetail::Str("k", "v".to_string());
        let _int = PublicDetail::Int("k", -1_i64);
        let _bool = PublicDetail::Bool("k", true);
        let _dur = PublicDetail::Duration("k", Duration::from_secs(5));
        let _time = PublicDetail::Time("k", SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn debug_never_renders_internal_or_public_values() {
        // INVARIANT: DEBUG-NO-ATTR-VALUES-01 { level = "Medium", exec = "manual/opt-in", source = "code" }        // `tracing::error!(?err)` 展开为 Debug；手写 impl 确保内部属性和公开明细的键/值
        // 永不出现在 Debug 输出中，与 HTTP wire strip 路径等价安全。
        let err = CoreError::new(CoreErrorKind::Forbidden)
            .with_internal(InternalAttr::Str(
                "authorization",
                "Bearer s3cr3t".to_string(),
            ))
            .with_details(PublicDetail::Str("field", "name".to_string()));
        let debug_str = format!("{err:?}");
        assert!(
            !debug_str.contains("s3cr3t"),
            "internal value leaked in Debug: {debug_str}"
        );
        assert!(
            !debug_str.contains("name"),
            "public value leaked in Debug: {debug_str}"
        );
        assert!(
            !debug_str.contains("authorization"),
            "internal key leaked in Debug: {debug_str}"
        );
        assert!(
            !debug_str.contains("field"),
            "public key leaked in Debug: {debug_str}"
        );
        // 只输出 kind 与数量
        assert!(debug_str.contains("Forbidden"), "kind missing: {debug_str}");
        assert!(
            debug_str.contains("public: 1"),
            "public count wrong: {debug_str}"
        );
        assert!(
            debug_str.contains("internal: 1"),
            "internal count wrong: {debug_str}"
        );
    }
}
