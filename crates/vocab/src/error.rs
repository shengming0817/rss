//! 跨域错误词汇 —— ADR-004 C10 + `docs/rules/error-handling.md` §Message 与 PII。
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
    Conflict,
    Validation,
    Internal,
}

impl CoreErrorKind {
    /// 稳定 message（`&'static str` const literal；无 runtime 数据）。
    pub fn message(self) -> &'static str {
        todo!()
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
#[derive(Debug, thiserror::Error)]
#[error("{}", .kind.message())]
pub struct CoreError {
    kind: CoreErrorKind,
    public: Vec<PublicDetail>,
    internal: Vec<InternalAttr>,
}

impl CoreError {
    /// 由 kind 构造（无 runtime 数据）。
    pub fn new(_kind: CoreErrorKind) -> Self {
        todo!()
    }

    /// 追加可下发公开明细（4xx 下发；5xx 由 wire mapper strip）。
    pub fn with_details(self, _detail: PublicDetail) -> Self {
        todo!()
    }

    /// 追加仅日志内部属性（永不进 wire）。
    pub fn with_internal(self, _attr: InternalAttr) -> Self {
        todo!()
    }

    /// 错误种类。
    pub fn kind(&self) -> CoreErrorKind {
        todo!()
    }

    /// 公开明细（wire mapper 只读这些；5xx strip）。
    pub fn public_details(&self) -> &[PublicDetail] {
        todo!()
    }

    /// 内部属性（只进日志）。
    pub fn internal_attrs(&self) -> &[InternalAttr] {
        todo!()
    }
}
