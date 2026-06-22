//! 引擎层错误词汇 —— ADR-004 C10 + `docs/rules/error-handling.md`。
//!
//! 引擎策略 trait（`IdempotencyStore`/`OutboxRelay`/`Reconciler`/`SagaStep`/`Projector`）的失败通道。
//! `kind` 的 message 是 `&'static str` const literal（禁 `format!` 拼 runtime 数据，遵 ADR-004 C10）。
//! runtime 因由经 `vocab::CoreError` typed 通道（with_internal）落日志，引擎错误本身只携 kind。

/// 引擎错误种类。每个 variant 的稳定 message 为 `&'static str` const literal。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineErrorKind {
    /// 后端暂时不可用 / 冲突，可重试（reconcile/outbox 退避）。
    Transient,
    /// 永久失败，重试无意义（→ DLX / saga 补偿）。
    Permanent,
    /// 引擎前置不变量被破坏（编程错误，非外部输入）。
    Invariant,
}

impl EngineErrorKind {
    /// 稳定 message（`&'static str` const literal；无 runtime 数据）。
    pub fn message(self) -> &'static str {
        todo!()
    }
}

/// 引擎策略 trait 的统一错误（私有字段；kind + 可选 source 链经 typed 通道）。
///
/// `Display` 只输出 `kind` 的 const message——不拼 runtime 数据，避免 PII 误入日志（同 `vocab::CoreError`）。
/// `is_transient` / `is_permanent` 是重试分类查询；**不**自动改写控制流（reconcile.md：分类 ≠ 放弃）。
#[derive(Debug, thiserror::Error)]
#[error("{}", .kind.message())]
pub struct EngineError {
    kind: EngineErrorKind,
}

impl EngineError {
    /// 由 kind 构造（无 runtime 数据）。
    pub fn new(_kind: EngineErrorKind) -> Self {
        todo!()
    }

    /// 错误种类。
    pub fn kind(&self) -> EngineErrorKind {
        todo!()
    }

    /// 是否可重试（`Transient`）。Loop / relay 据此决定退避重试 vs 放行下一步。
    pub fn is_transient(&self) -> bool {
        todo!()
    }

    /// 是否永久失败（`Permanent`）。仅分类，不自动把重试改放弃（reconcile.md）。
    pub fn is_permanent(&self) -> bool {
        todo!()
    }
}
