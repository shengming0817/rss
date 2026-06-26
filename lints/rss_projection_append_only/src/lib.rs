#![feature(rustc_private)]
//! `rss_projection_append_only` — RSS 治理 dylint lint：projection_events append-only
//! （AST 拒 DELETE/TRUNCATE 字符串字面量）。
//!
//! INVARIANT: PROJECTION-APPEND-ONLY-01
//!
//! `projection_events` 是 append-only CQRS 投影事件日志。禁 DELETE/TRUNCATE——DB 引擎
//! REVOKE 是 Hard 主守卫（migration 层），本 lint 是 Medium 辅助早拦（编译期 AST 字面量扫描）。
//!
//! 强度现状（勿过度宣称）：仅字符串字面量、大小写归一粗匹配；动态拼接 SQL、变量 SQL 不检测。
//! 已接入 `cargo dylint --all`（`cargo xtask verify` 一步，`DYLINT_RUSTFLAGS=-D warnings`
//! fail-closed）；azure 无 CI ⇒ verify 是唯一实际 gate（Medium）。

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_ast::LitKind;
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 拦截对 `projection_events` 表执行 DELETE 或 TRUNCATE 的 SQL 字符串字面量。
    ///
    /// ### Why is this bad?
    /// `projection_events` 是 CQRS 投影事件日志——append-only 语义是投影重建正确性的前提。
    /// DELETE/TRUNCATE 会破坏事件完整性，使投影重建产生错误或丢失历史数据。DB 引擎 REVOKE
    /// 是 Hard 主守卫；本 lint 是 Medium 辅助守卫，在编译期（AST 字符串字面量阶段）早拦。
    /// INVARIANT: PROJECTION-APPEND-ONLY-01。
    ///
    /// ### Known problems
    /// 仅检测字符串字面量，粗匹配（大小写归一 `contains`）：
    /// - 动态 SQL（`format!` 拼接、变量传入）不检测。
    /// - 关键字跨行或注释夹杂的字面量可能漏报。
    /// - 大小写归一匹配 `PROJECTION_EVENTS` / `projection_events` 均可命中，但
    ///   绕过写法（如别名、动态表名）不检测。
    /// - 检测使用 `contains`（关键字与表名顺序无关、不解析 SQL 结构）；含 DELETE/TRUNCATE
    ///   关键字的注释或无关子句夹杂在同一字面量中可能误报（false positive）。
    /// 确需对 `projection_events` 执行 DELETE/TRUNCATE（如 e2e 测试清理）时，
    /// 用 `#[allow(rss_projection_append_only)] // reason: ...` 显式豁免并说明理由。
    ///
    /// ### Example
    /// ```rust
    /// // 触发：DELETE/TRUNCATE projection_events
    /// const SQL: &str = "DELETE FROM projection_events WHERE id = $1";
    /// ```
    /// Use instead:
    /// ```rust
    /// // 放行：仅 INSERT / SELECT 操作
    /// const SQL: &str = "INSERT INTO projection_events (domain, payload) VALUES ($1, $2)";
    /// ```
    pub RSS_PROJECTION_APPEND_ONLY,
    Warn,
    "projection_events 表是 append-only：不得对其 DELETE 或 TRUNCATE（INVARIANT PROJECTION-APPEND-ONLY-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssProjectionAppendOnly {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 仅关注字符串字面量表达式。
        let ExprKind::Lit(lit) = &expr.kind else {
            return;
        };
        // rustc_hir::Lit.node 类型是 rustc_ast::LitKind；Str 变体携 (Symbol, StrStyle)。
        let LitKind::Str(sym, _) = lit.node else {
            return;
        };
        if is_projection_events_delete_or_truncate(sym.as_str()) {
            span_lint_hir_and_then(
                cx,
                RSS_PROJECTION_APPEND_ONLY,
                expr.hir_id,
                expr.span,
                "projection_events 表是 append-only：不得对其 DELETE 或 TRUNCATE",
                |diag| {
                    diag.help(
                        "projection_events 仅 INSERT；逆转须经 maintainer 审核新前向迁移 GRANT；\
                        临时绕过加 `#[allow(rss_projection_append_only)] // reason: ...`",
                    );
                },
            );
        }
    }
}

/// SQL 字符串是否对 `projection_events` 执行 DELETE/TRUNCATE
/// （大写归一粗匹配启发式；动态 SQL 不在检测范围内）。
fn is_projection_events_delete_or_truncate(sql: &str) -> bool {
    let up = sql.to_uppercase();
    (up.contains("DELETE") || up.contains("TRUNCATE")) && up.contains("PROJECTION_EVENTS")
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
