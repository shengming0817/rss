#![feature(rustc_private)]
//! `rss_dlq_operator_callsite` — RSS operator capability 签发入口治理 dylint。
//!
//! INVARIANT: EVENTBUS-DLQ-OPERATOR-CAP-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! Operator capability 的私有字段让构造只能经 `issue_for_authorized_operator()` funnel（上游 Hard），
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
const ALLOWED_RUNTIME_FUNCTIONS: &[&str] = &[
    "issue_authorized_dlq_capability",
    "issue_authorized_reconcile_capability",
];
const ALLOWED_RUNTIME_RECEIPT_FUNCTION: &str = "dlq_operator_receipt";

#[derive(Clone, Copy)]
enum Funnel {
    Capability,
    AuthorizedReceipt,
}

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
        let Some(funnel) = guarded_funnel(cx, did) else {
            return;
        };
        if !caller_is_allowed(cx, expr.hir_id, funnel) {
            emit(cx, expr.hir_id, expr.span, funnel);
        }
    }
}

fn guarded_funnel(cx: &LateContext<'_>, did: DefId) -> Option<Funnel> {
    if cx.tcx.crate_name(did.krate).as_str() != "eventexec"
        || !matches!(cx.tcx.def_kind(cx.tcx.parent(did)), DefKind::Impl { .. })
    {
        return None;
    }
    match cx.tcx.item_name(did).as_str() {
        "issue_for_authorized_operator" => Some(Funnel::Capability),
        "from_authenticated_and_authorized"
            if impl_self_type_named(cx, did, "AuthorizedDlqOperatorReceipt") =>
        {
            Some(Funnel::AuthorizedReceipt)
        }
        _ => None,
    }
}

fn impl_self_type_named(cx: &LateContext<'_>, did: DefId, expected: &str) -> bool {
    cx.tcx
        .type_of(cx.tcx.parent(did))
        .instantiate_identity()
        .ty_adt_def()
        .is_some_and(|adt| cx.tcx.item_name(adt.did()).as_str() == expected)
}

fn caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId, funnel: Funnel) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    if matches!(funnel, Funnel::Capability)
        && ALLOWED_CALLER_CRATES.contains(&crate_name.as_str())
    {
        return true;
    }
    if crate_name.as_str() != "runtime" {
        return false;
    }
    let parent = cx.tcx.hir_get_parent_item(hir_id);
    let parent_def_id = parent.to_def_id();
    let item_name = cx.tcx.item_name(parent_def_id);
    let def_path = cx.tcx.def_path_str(parent_def_id);
    match funnel {
        Funnel::Capability => {
            ALLOWED_RUNTIME_FUNCTIONS.contains(&item_name.as_str())
                && ALLOWED_RUNTIME_FUNCTIONS.contains(&def_path.as_str())
        }
        Funnel::AuthorizedReceipt => {
            item_name.as_str() == ALLOWED_RUNTIME_RECEIPT_FUNCTION
                && def_path == ALLOWED_RUNTIME_RECEIPT_FUNCTION
        }
    }
}

fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span, funnel: Funnel) {
    let (message, help) = match funnel {
        Funnel::Capability => (
            "operator capability 仅 admin/PDP 边界可签发：`issue_for_authorized_operator` 不得在此 crate 调用",
            "在 allowlist 的 admin/PDP 授权路径中签发 capability；runtime CLI 仅允许精确的 authenticated+authorized wrapper，其它 crate 经请求 DTO 接收",
        ),
        Funnel::AuthorizedReceipt => (
            "authorized DLQ operator receipt 仅认证/PDP 边界可构造：`from_authenticated_and_authorized` 不得在此调用",
            "仅 runtime 可在完成 service-token 验证与精确 action/tenant grant 授权后，经 top-level `dlq_operator_receipt` wrapper 构造 private-field typed receipt",
        ),
    };
    span_lint_hir_and_then(
        cx,
        RSS_DLQ_OPERATOR_CALLSITE,
        hir_id,
        span,
        message,
        |diag| {
            diag.help(help);
        },
    );
}

#[test]
fn ui_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "dlq_operator_callsite_ui");
}

#[test]
fn ui_httpserve_capability_allowed_but_verified_subject_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "httpserve");
}

#[test]
fn ui_runtime_non_boundary_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "runtime");
}
