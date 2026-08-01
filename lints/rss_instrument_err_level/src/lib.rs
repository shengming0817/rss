#![feature(rustc_private)]
//! `rss_instrument_err_level` — RSS 治理 dylint lint：禁止
//! `#[instrument(..., err)]` / `#[tracing::instrument(..., err)]` 中的裸 `err`。
//!
//! INVARIANT: INSTRUMENT-ERR-LEVEL-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! tracing-attributes 的裸 `err` 默认以 ERROR 级发出返回值事件；业务 4xx（`InvalidKey` /
//! `NotFound` / `InvalidCredentials` 等）会被打进 ERROR 告警面。须显式
//! `err(level = "warn")`（或 `"error"` 等）声明级别。
//!
//! ## Gate budget（`docs/rules/README.md` 红线二）
//!
//! **只加不减，理由（现有 owner 不可表达本失效模式）**：
//! - **不替换**任何既有 Medium/Hard 门：此前无机器门守「`instrument` 的 `err` 缺 `level`」；
//!   Soft 文档/review 约定不是 enforcement 门（ai-robust 禁 Soft 新增），本 lint 是该失效模式的
//!   **首个** Medium carrier，不是「多一道保险」。
//! - **不可并入**唯一其它 pre-expansion owner `rss_runtime_env_funnel`：对方守 `runtime` crate 的
//!   `MacCall`（`env!` / `option_env!` / `include!`）与 HIR env reader；本 lint 守全 workspace
//!   Attribute path 末段 `instrument` 的 `err`/`level` token。AST 节点、激活范围、失效模式均不同，
//!   合并会把无关约束绑进同一 pass，破坏 owner 边界。
//! - **不存在**既有 tracing-attribute / instrument-meta lint 可 merge；统一 tracing attribute policy
//!   lint 属未来重构种子，不在本 INVARIANT 范围。
//!
//! 检测面：`declare_pre_expansion_lint!`（EarlyLintPass / `check_attribute`）——
//! `#[tracing::instrument]` 是 attribute proc-macro，展开后属性消失，必须在 expansion
//! 前扫 AST token。path 末段为 `instrument`（含 `tracing::instrument`）；只扫顶层
//! delimited token（不进 `skip(...)` / `fields(...)`），避免参数名 `err` 误报。
//!
//! 判定：
//! - 裸 `err` / `err,` / `, err` / `err)` → 触发
//! - `err(...)` 且括号内顶层 token 含 Ident `level`（如 `err(level = "warn")`）→ 放行
//! - `err(Debug)` / `err(Display)` / `err()` 等无 `level` → 仍触发（tracing 仍默认 ERROR）
//! - `ret` / 其它 meta 不报
//!
//! 逃生：item-level `#[allow(rss_instrument_err_level)] // reason: ...`。
//! anti-vacuity：UI 红（裸 err / 无 level 的 `err(...)`）+ 绿（带 level / allow）；生产零诊断由
//! verify 内 `cargo dylint --all`（`-D warnings` fail-closed）承载。
//!
//! ref: tokio-rs/tracing tracing-attributes/src/lib.rs

extern crate rustc_ast;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_then;
use rustc_ast::token::TokenKind;
use rustc_ast::tokenstream::TokenTree;
use rustc_ast::{AttrArgs, AttrItemKind, AttrKind, Attribute};
use rustc_lint::{EarlyContext, EarlyLintPass};
use rustc_span::Span;

dylint_linting::declare_pre_expansion_lint! {
    /// ### What it does
    /// 标记 `#[instrument]` / `#[tracing::instrument]` 中未显式声明 `level` 的 `err`
    ///（裸 `err`，或 `err(Debug)` / `err(Display)` / `err()` 等）。
    ///
    /// ### Why is this bad?
    /// 未带 `level = …` 的 `err` 默认 ERROR 级，会把业务 4xx 打进告警面。须显式
    /// `err(level = "warn")`（或 `"error"` 等）。INVARIANT: INSTRUMENT-ERR-LEVEL-01。
    ///
    /// ### Known problems
    /// 只扫顶层 token；`err(...)` 须括号内顶层出现 Ident `level` 才放行（`err(Debug)` /
    /// `err(Display)` / `err()` 仍诊断）。不校验 `level` 取值是否合法。仅 pre-expansion 拦；
    /// 宏生成的 instrument 文本若经另一层 attribute macro 注入，可能漏报。
    ///
    /// ### Example
    /// ```ignore
    /// #[tracing::instrument(err)] // 触发
    /// fn bad() -> Result<(), ()> { Ok(()) }
    ///
    /// #[tracing::instrument(err(Debug))] // 触发（仍默认 ERROR）
    /// fn still_bad() -> Result<(), ()> { Ok(()) }
    ///
    /// #[tracing::instrument(err(level = "warn"))] // OK
    /// fn good() -> Result<(), ()> { Ok(()) }
    /// ```
    pub RSS_INSTRUMENT_ERR_LEVEL,
    Warn,
    "#[instrument(err)] 禁止裸 err：须 err(level = …)（INVARIANT INSTRUMENT-ERR-LEVEL-01）"
}

impl EarlyLintPass for RssInstrumentErrLevel {
    fn check_attribute(&mut self, cx: &EarlyContext<'_>, attr: &Attribute) {
        let AttrKind::Normal(normal) = &attr.kind else {
            return;
        };
        if !is_instrument_attr_path(&normal.item.path) {
            return;
        }
        let AttrItemKind::Unparsed(AttrArgs::Delimited(args)) = &normal.item.args else {
            return;
        };
        for err_span in bare_err_spans(args.tokens.iter()) {
            span_lint_and_then(
                cx,
                RSS_INSTRUMENT_ERR_LEVEL,
                err_span,
                "#[instrument] 禁止裸 `err`：须显式 `err(level = …)`",
                |diag| {
                    diag.help(
                        "业务 4xx 路径用 `err(level = \"warn\")`；确需 ERROR 级用 \
                         `err(level = \"error\")`；确需豁免加 item-level \
                         `#[allow(rss_instrument_err_level)] // reason: ...`",
                    );
                },
            );
        }
    }
}

fn is_instrument_attr_path(path: &rustc_ast::Path) -> bool {
    path.segments
        .last()
        .is_some_and(|seg| seg.ident.name.as_str() == "instrument")
}

/// 顶层 token 流中未声明 `level` 的 `err` span。
///
/// `err(...)` 仅当括号内顶层出现 Ident `level` 时放行；否则（裸 `err` /
/// `err(Debug)` / `err(Display)` / `err()`）仍诊断。
fn bare_err_spans<'a>(
    tokens: impl IntoIterator<Item = &'a TokenTree>,
) -> Vec<Span> {
    let mut out = Vec::new();
    let mut iter = tokens.into_iter().peekable();
    while let Some(tt) = iter.next() {
        let TokenTree::Token(tok, _) = tt else {
            // 顶层 Delimited（如 `skip(...)`）不递归——参数名 `err` 不是 instrument meta。
            continue;
        };
        let TokenKind::Ident(sym, _) = tok.kind else {
            continue;
        };
        if sym.as_str() != "err" {
            continue;
        }
        if let Some(TokenTree::Delimited(..)) = iter.peek() {
            let Some(TokenTree::Delimited(_, _, _, stream)) = iter.next() else {
                unreachable!("peeked Delimited");
            };
            // `err(level = …)` → 放行；`err(Debug)` / `err()` 等无 `level` → 仍诊断。
            if delimited_contains_level_ident(stream.iter()) {
                continue;
            }
        }
        out.push(tok.span);
    }
    out
}

/// `err(...)` Delimited 内顶层是否出现 Ident `level`（不递归嵌套括号）。
fn delimited_contains_level_ident<'a>(
    tokens: impl IntoIterator<Item = &'a TokenTree>,
) -> bool {
    tokens.into_iter().any(|tt| {
        let TokenTree::Token(tok, _) = tt else {
            return false;
        };
        matches!(
            &tok.kind,
            TokenKind::Ident(sym, _) if sym.as_str() == "level"
        )
    })
}

#[test]
fn gate_budget_declared_in_module_docs() {
    // GATE-BUDGET-01 anti-vacuity：carrier rustdoc 必须可审查声明「只加不减」与不可并入理由
    // （docs/rules/README.md 红线二）；缺声明则本测失败。
    let src = include_str!("lib.rs");
    assert!(
        src.contains("## Gate budget"),
        "module docs must declare Gate budget section"
    );
    assert!(
        src.contains("rss_runtime_env_funnel"),
        "must name the only other pre-expansion owner and why it cannot absorb this failure mode"
    );
    assert!(
        src.contains("只加不减") || src.contains("只加不减，理由"),
        "must state add-only gate-budget posture with reason"
    );
    assert!(
        src.contains("首个") && src.contains("Medium"),
        "must state this is the first Medium carrier for the failure mode"
    );
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_instrument_err_level_ui");
}
