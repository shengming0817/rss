//! 引擎层错误词汇 —— ADR-004 C10 + `docs/rules/error-handling.md`。
//!
//! 引擎策略 trait（`InboxStore`/`OutboxRelay`/`Reconciler`/`SagaStep`/`Projector`）的失败通道。
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
        match self {
            EngineErrorKind::Transient => "transient engine error",
            EngineErrorKind::Permanent => "permanent engine error",
            EngineErrorKind::Invariant => "engine invariant violated",
        }
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
    pub fn new(kind: EngineErrorKind) -> Self {
        Self { kind }
    }

    /// 错误种类。
    pub fn kind(&self) -> EngineErrorKind {
        self.kind
    }

    /// 是否可重试（`Transient`）。Loop / relay 据此决定退避重试 vs 放行下一步。
    pub fn is_transient(&self) -> bool {
        self.kind == EngineErrorKind::Transient
    }

    /// 是否永久失败（`Permanent`）。仅分类，不自动把重试改放弃（reconcile.md）。
    pub fn is_permanent(&self) -> bool {
        self.kind == EngineErrorKind::Permanent
    }
}

#[cfg(test)]
mod tests {
    use super::{EngineError, EngineErrorKind};

    const KINDS: [EngineErrorKind; 3] = [
        EngineErrorKind::Transient,
        EngineErrorKind::Permanent,
        EngineErrorKind::Invariant,
    ];

    // 三 variant 的稳定 message 为非空 `&'static str` const literal（C10）且互异。
    #[test]
    fn engine_error_kind_message_distinct() {
        let cases: &[(EngineErrorKind, &str)] = &[
            (EngineErrorKind::Transient, "transient engine error"),
            (EngineErrorKind::Permanent, "permanent engine error"),
            (EngineErrorKind::Invariant, "engine invariant violated"),
        ];
        for &(kind, expected) in cases {
            assert_eq!(kind.message(), expected, "kind={kind:?}");
            assert!(
                !kind.message().is_empty(),
                "empty message for kind={kind:?}"
            );
        }
        assert_ne!(
            EngineErrorKind::Transient.message(),
            EngineErrorKind::Permanent.message()
        );
        assert_ne!(
            EngineErrorKind::Permanent.message(),
            EngineErrorKind::Invariant.message()
        );
        assert_ne!(
            EngineErrorKind::Transient.message(),
            EngineErrorKind::Invariant.message()
        );
    }

    // new → kind 往返。
    #[test]
    fn engine_error_new_round_trips_kind() {
        for kind in KINDS {
            assert_eq!(EngineError::new(kind).kind(), kind, "kind={kind:?}");
        }
    }

    // is_transient / is_permanent 真值表（含 Invariant arm，保覆盖）。
    #[test]
    fn engine_error_transient_permanent_truth_table() {
        let cases: &[(EngineErrorKind, bool, bool)] = &[
            (EngineErrorKind::Transient, true, false),
            (EngineErrorKind::Permanent, false, true),
            (EngineErrorKind::Invariant, false, false),
        ];
        for &(kind, transient, permanent) in cases {
            let e = EngineError::new(kind);
            assert_eq!(e.is_transient(), transient, "is_transient kind={kind:?}");
            assert_eq!(e.is_permanent(), permanent, "is_permanent kind={kind:?}");
        }
    }

    // Display 输出 == kind.message()（不拼 runtime 数据，避免 PII）。
    #[test]
    fn engine_error_display_equals_kind_message() {
        for kind in KINDS {
            assert_eq!(
                EngineError::new(kind).to_string(),
                kind.message(),
                "kind={kind:?}"
            );
        }
    }
}
