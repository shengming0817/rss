//! Saga 编排接缝（L3）—— do/undo 前向动作 + 逆序补偿。
//!
//! `SagaStep` 是 L3 引擎策略 trait（native AFIT：`execute` 前向 + `compensate` 补偿）；step name /
//! outcome 是纯类型。**compensation order 只能 reverse**（saga.md §Governance）——逆序由执行器
//! （eventexec saga executor）持栈驱动，consistency 只冻接缝形态。
//! ref: oxidecomputer/steno src/saga_action_generic.rs@main（`Action::do_it`/`undo_it`/`name` 对标；
//! RSS 拒其 `ActionData: Serialize+DeserializeOwned` bound（ADR-004 C6）、用 native AFIT 替 BoxFuture）。

/// saga step 名 newtype（私有字段；可生成 Rust 标识符且唯一 —— saga.md §Governance）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StepName(String);

/// `StepName` 解析错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StepNameError {
    #[error("saga step name is empty")]
    Empty,
    #[error("saga step name is not a valid identifier")]
    NotIdent,
}

impl StepName {
    /// 解析；要求非空且为合法 Rust 标识符（codegen 生成 step 函数名，fail-closed）。
    pub fn parse(raw: &str) -> Result<Self, StepNameError> {
        if raw.is_empty() {
            return Err(StepNameError::Empty);
        }
        if !is_rust_ident(raw) {
            return Err(StepNameError::NotIdent);
        }
        Ok(Self(raw.to_string()))
    }

    /// 借出底层字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// ASCII Rust 标识符文法：首字节 `[A-Za-z_]`、其余 `[A-Za-z0-9_]`，且**非** Rust 关键字、**非**裸 `_`
/// （空串 → false）。
///
/// **对齐 xtask R10 契约面校验** `name.starts_with("r#") || syn::parse_str::<syn::Ident>(name).is_err()`
/// （`xtask/src/contract/validate.rs:484`）——step name 是 codegen 生成的 step 函数符号，契约声明面与运行期
/// `StepName` 构造面文法须同形：funnel 弱于治理规则会把非法 step name（关键字 / `_`）冻进 consistency 公共 API。
/// 本谓词在 ASCII 内与 R10 **同拒集**：拒 Rust 关键字（[`is_rust_keyword`]，对标 `syn::Ident` 拒关键字）、拒裸 `_`
/// （syn 视其为 `Underscore` token 非 ident）、拒 `r#` raw ident（`#` 不在 `[A-Za-z0-9_]`，文法天然拒，R10 亦显式拒）。
/// 唯一残留分歧：R10 / `syn::Ident` 接受 non-ASCII unicode XID 标识符，本谓词只收 ASCII（runtime 偏严方向——
/// unicode saga step 名非真实用例，codegen 生成 unicode 符号亦不干净）。统一单源（runtime 与 xtask 共用单一
/// 标识符语法 + 关键字源、含 unicode）见 #1175（同 outbox `is_canonical_dotted` ↔ `is_dotted_id` #1126 范式）。
fn is_rust_ident(s: &str) -> bool {
    if s == "_" || is_rust_keyword(s) {
        return false;
    }
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b) if b == b'_' || b.is_ascii_alphabetic())
        && bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}

/// Rust strict 关键字（2015 + 2018）——对标 `syn::Ident` 拒关键字语义。
const RUST_STRICT_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "async", "await",
];

/// Rust reserved 关键字（未来保留，`syn::Ident` 亦拒）。
const RUST_RESERVED_KEYWORDS: &[&str] = &[
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try",
];

/// step name 流入 codegen 须能作裸 fn 名——拒 strict + reserved 关键字（对标 `syn::Ident`）。
fn is_rust_keyword(s: &str) -> bool {
    RUST_STRICT_KEYWORDS.contains(&s) || RUST_RESERVED_KEYWORDS.contains(&s)
}

/// 单 step 前向结果（穷尽闭值集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SagaOutcome {
    /// step 完成，推进下一步。
    Completed,
    /// step 失败，触发**逆序**补偿（saga.md：order 只能 reverse）。
    Failed,
}

/// 补偿结果（穷尽闭值集）。补偿失败需人工/DLX 介入，不静默吞。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompensationOutcome {
    /// 补偿完成。
    Compensated,
    /// 补偿失败（需上报，进入 saga dead-letter）。
    Failed,
}

/// Saga step 策略（L3 引擎策略 trait，native AFIT）。
///
/// `execute` 前向动作；`compensate` 其逆操作（对标 steno do_it/undo_it）。执行器持已完成 step 栈，
/// 失败时**逆序** `compensate`（saga.md）。native AFIT ⇒ 非 object-safe，执行器泛型 `<S: SagaStep>` 消费。
#[allow(async_fn_in_trait)]
// reason: native AFIT 引擎策略 trait 仅泛型静态分发消费，无 Send-bound 跨 await 持有问题；这是 ADR-003 既定范式。
pub trait SagaStep {
    /// 稳定 step 名（codegen 派生唯一标识；saga.md governance）。
    fn name(&self) -> &StepName;

    /// 前向执行此 step。
    async fn execute(&self) -> Result<SagaOutcome, crate::error::EngineError>;

    /// 补偿此 step（逆操作）。仅对已 `Completed` 的 step 由执行器逆序调用。
    async fn compensate(&self) -> Result<CompensationOutcome, crate::error::EngineError>;
}

#[cfg(test)]
mod tests {
    use super::{StepName, StepNameError};

    // parse 接受合法 Rust 标识符（首字符 [A-Za-z_]、其余 [A-Za-z0-9_]，非关键字、非裸 `_`）+ as_str 往返。
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 断言已 is_ok 的 parse 结果，item-level carve-out（error-handling.md §Carve-out）。
    fn step_name_parse_accepts_idents_and_round_trips() {
        let cases: &[&str] = &["a", "A", "_x", "step_one", "A1", "create_session", "x9_y8"];
        for &raw in cases {
            assert!(StepName::parse(raw).is_ok(), "expected Ok for raw={raw:?}");
            assert_eq!(StepName::parse(raw).unwrap().as_str(), raw, "raw={raw:?}");
        }
    }

    // 空 → Empty（fail-closed；codegen 生成 step 函数名，空名不可表达）。
    #[test]
    fn step_name_parse_rejects_empty() {
        assert!(matches!(StepName::parse(""), Err(StepNameError::Empty)));
    }

    // 非标识符 → NotIdent（段首数字 / 连字符 / 点 / 空格 / 非法字符 / 非 ASCII / 制表符 / r# raw ident）。
    #[test]
    fn step_name_parse_rejects_non_ident() {
        let cases: &[&str] = &[
            "1a", "9", "a-b", "a.b", "a b", "a$", " a", "a ", "föö", "a\tb", "r#fn",
        ];
        for &raw in cases {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "expected NotIdent for raw={raw:?}"
            );
        }
    }

    // 关键字 / 裸 `_` → NotIdent（对齐 xtask R10：codegen step 函数名不可为关键字 / `_`）。
    #[test]
    fn step_name_parse_rejects_keywords_and_underscore() {
        for raw in [
            "fn", "if", "let", "pub", "match", "self", "Self", "async", "yield", "_",
        ] {
            assert!(
                matches!(StepName::parse(raw), Err(StepNameError::NotIdent)),
                "expected NotIdent for raw={raw:?}"
            );
        }
    }

    // 私有 is_rust_ident 谓词独立语义（空串短路 false 分支，文法分支全覆盖；
    // parse 已前置拒空，此处守 helper 独立调用时空串 false，仿 outbox is_canonical_dotted_standalone）。
    #[test]
    fn is_rust_ident_standalone() {
        assert!(!super::is_rust_ident(""));
        assert!(super::is_rust_ident("a"));
        assert!(!super::is_rust_ident("_")); // 裸 `_` 现拒（对齐 syn::Ident Underscore token）
        assert!(super::is_rust_ident("_x")); // 含后缀的下划线名仍合法
        assert!(super::is_rust_ident("A1_b"));
        assert!(!super::is_rust_ident("1a"));
        assert!(!super::is_rust_ident("a-b"));
    }

    // 对齐 R10（anti-regression）：runtime 与 xtask R10 契约面 `syn::Ident` 在 ASCII 内**同拒** Rust 关键字
    // 与裸 `_`（codegen step 函数名不可为关键字 / `_`）。固定该对齐：若未来放松接受关键字，本测试触发回归复审。
    // 残留 unicode 分歧 + 单一标识符/关键字源统一见 #1175。
    #[test]
    fn is_rust_ident_rejects_keywords_and_underscore_matching_r10() {
        for raw in [
            "fn", "if", "let", "pub", "match", "self", "Self", "async", "yield", "_",
        ] {
            assert!(
                !super::is_rust_ident(raw),
                "runtime 应与 R10 同拒 {raw:?}（关键字 / 裸 `_` 不可作 codegen step 函数名）"
            );
        }
        // 含 keyword 子串但非关键字、单 `r`（非 r# raw）仍接受。
        assert!(super::is_rust_ident("function"));
        assert!(super::is_rust_ident("r"));
        assert!(!super::is_rust_ident("r#fn"));
    }
}
