#![feature(rustc_private)]
//! `rss_dlq_operator_callsite` — RSS eventbus 治理 dylint lint：限定 DLQ mutation capability 签发入口。
//!
//! INVARIANT: EVENTBUS-DLQ-OPERATOR-CAP-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! `OperatorDlqCapability` 的私有字段让构造只能经 `issue_for_authorized_operator()` funnel（上游 Hard），
//! 但“谁可以调用该 funnel”是跨 crate callsite 约束，类型系统不能表达；本 lint 复用
//! `rss_crosstenant_callsite` 的下游治理模式，只允许 admin/PDP 边界 crate 或最小 runtime CLI wrapper
//! 调用该签发函数。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅 admin/PDP 边界可签发 DLQ mutation capability；runtime 只允许精确 wrapper。
const ALLOWED_CALLER_CRATES: &[&str] = &["httpserve"];
const ALLOWED_RUNTIME_FUNCTION: &str = "issue_authorized_dlq_capability";

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 allowlist 外 crate 对
    /// `eventexec::OperatorDlqCapability::issue_for_authorized_operator` 的任意 path 引用。
    ///
    /// ### Why is this bad?
    /// DLQ replay/redrive 会恢复 durable payload 或修改 outbox 状态，必须在 admin/PDP 已授权后才可签发
    /// witness。public zero-arg mint 若无 callsite guard，会退化成调用方约定。
    /// INVARIANT: EVENTBUS-DLQ-OPERATOR-CAP-01 { level = "Medium", exec = "verify", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍是 intraprocedural callsite lint；allowlist crate 内 wrapper 若公开给外部调用，需由边界 API 可见性
    /// 和 review 守。`#[cfg(test)]` 子树默认不扫，测试 fixtures 可直接 mint capability。
    pub RSS_DLQ_OPERATOR_CALLSITE,
    Warn,
    "DLQ mutation capability 签发仅限 admin/PDP 边界（callsite-allowlist，INVARIANT EVENTBUS-DLQ-OPERATOR-CAP-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssDlqOperatorCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_dlq_operator_funnel_did(cx, did) && !caller_is_allowed(cx, expr.hir_id) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

fn is_dlq_operator_funnel_did(cx: &LateContext<'_>, did: DefId) -> bool {
    cx.tcx.crate_name(did.krate).as_str() == "eventexec"
        && cx.tcx.item_name(did).as_str() == "issue_for_authorized_operator"
        && matches!(cx.tcx.def_kind(cx.tcx.parent(did)), DefKind::Impl { .. })
}

fn caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    if ALLOWED_CALLER_CRATES.contains(&crate_name.as_str()) {
        return true;
    }
    if crate_name.as_str() != "runtime" {
        return false;
    }
    let parent = cx.tcx.hir_get_parent_item(hir_id);
    let parent_def_id = parent.to_def_id();
    if cx.tcx.item_name(parent_def_id).as_str() != ALLOWED_RUNTIME_FUNCTION {
        return false;
    }
    let def_path = cx.tcx.def_path_str(parent_def_id);
    def_path == ALLOWED_RUNTIME_FUNCTION
}

fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_DLQ_OPERATOR_CALLSITE,
        hir_id,
        span,
        "DLQ mutation capability 仅 admin/PDP 边界可签发：`OperatorDlqCapability::issue_for_authorized_operator` 不得在此 crate 调用",
        |diag| {
            diag.help(
                "在 allowlist 的 admin/PDP 授权路径中签发 capability；runtime CLI 仅允许 `issue_authorized_dlq_capability` wrapper，其它 crate 经请求 DTO 接收",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "dlq_operator_callsite_ui");
}

#[test]
fn ui_httpserve_allowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "httpserve");
}

#[test]
fn ui_runtime_non_boundary_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "runtime");
}
