#![feature(rustc_private)]
//! `rss_crosstenant_callsite` — RSS G0.4 治理 dylint lint：限定跨租户 All-scope mint 三步
//! `CrossTenantCapability::issue_for_verified_super_admin()` / `CrossTenantVisibility::authorize()` /
//! `RowVisibility::new_cross_tenant()` 仅 audit durable-receipt scope mint 函数可调用。
//!
//! INVARIANT: TENANCY-CROSSTENANT-CAP-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! 跨租户可见性是 super-admin 越权面：`CrossTenantCapability` 私有字段（`_seal: ()`）已让**构造**只能经
//! funnel（type-layer Hard，上游）；但「funnel 只许 audit 在 durable append receipt 后调用」无法跨 crate
//! 真 seal。本 lint 承载该 **下游** 约束（精确函数 allowlist，Medium）：其它函数调用即报。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（mint）：私有 `_seal` 字段 ⇒ struct-literal 不可表达，编译错误（Hard，在 vocab）。
//! - 下游（callsite）：哪个 crate 可调 ⇒ 本 lint（Medium）。
//!
//! 检测面：捕获对该 assoc fn 的**任意 path 引用**——直接 `Type::fn()` call 的 callee、`let f = Type::fn`
//! 函数项别名、fn-pointer 强转都解析到同一 `DefId`，杜绝「先别名再调用」绕过。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，azure 无 CI
//! ⇒ verify 是唯一实际 gate；② **跨函数**洗白仍未覆盖（intraprocedural），但唯一放行函数为
//! `audit::ports::CrossTenantReadScope::from_durable_append`，且其入参 receipt 由 application 模块私有字段 Hard
//! seal。注：vocab 自身 smoke 测试引用该
//! fn-item 会命中，但属 `#[cfg(test)]`，`cargo dylint --all` 不扫测试子树 ⇒ 实际 gate 无误报。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::TyKind;
use rustc_span::Span;

const ALLOWED_CALLER_CRATE: &str = "audit";
const ALLOWED_CALLER_FUNCTION: &str = "from_durable_append";
const ALLOWED_CALLER_TYPE: &str = "ports::CrossTenantReadScope";

const FORBIDDEN_ASSOC_FNS: &[&str] = &[
    "issue_for_verified_super_admin",
    "authorize",
    "new_cross_tenant",
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记非 audit durable-receipt scope mint 函数对 vocab 跨租户 All-scope mint 三步的
    /// **任意 path 引用**（直接 call、`let f = Type::fn` 别名、fn-pointer 强转——凡解析到该 assoc fn DefId）。
    ///
    /// ### Why is this bad?
    /// 跨租户可见性是 super-admin 越权面。capability 的**构造**已由 vocab 私有字段封到 funnel（Hard），但
    /// 「funnel 只许 durable receipt 消费点调用」跨 crate 不可真 seal，故由本 exact-function lint承载。
    /// INVARIANT: TENANCY-CROSSTENANT-CAP-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍 intraprocedural；确需在 allowlist 外引用须显式 `#[allow(rss_crosstenant_callsite)]` 并评审。
    ///
    /// ### Example
    /// ```ignore
    /// // 非 durable receipt scope mint：
    /// let cap = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin(); // 触发
    /// ```
    /// Use instead: 先完成 typed durable append，再由 `CrossTenantReadScope::from_durable_append` mint。
    pub RSS_CROSSTENANT_CALLSITE,
    Warn,
    "跨租户 capability 签发仅限 audit durable-receipt scope mint（exact-function allowlist，INVARIANT TENANCY-CROSSTENANT-CAP-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssCrosstenantCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 捕获对 funnel fn-item 的**任意** path 引用——直接 call 的 callee、`let f = Type::fn` 别名、
        // fn-pointer 强转都是 `ExprKind::Path` 解析到该 assoc fn `DefId`；只拦表面 call 会被「先别名再调用」绕过。
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_cross_tenant_funnel_did(cx, did) && !caller_is_allowed(cx, expr.hir_id) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

/// `did` 是 `vocab` 中跨租户 All-scope mint 三步之一。按 crate 名 + item 名 + parent 为 impl 判定。
fn is_cross_tenant_funnel_did(cx: &LateContext<'_>, did: DefId) -> bool {
    cx.tcx.crate_name(did.krate).as_str() == "vocab"
        && FORBIDDEN_ASSOC_FNS.contains(&cx.tcx.item_name(did).as_str())
        && matches!(cx.tcx.def_kind(cx.tcx.parent(did)), DefKind::Impl { .. })
}

/// 只放行 audit crate 内 `CrossTenantReadScope` 的 durable-receipt scope mint 方法。
fn caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() != ALLOWED_CALLER_CRATE {
        return false;
    }
    let owner = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    if cx.tcx.item_name(owner).as_str() != ALLOWED_CALLER_FUNCTION {
        return false;
    }
    let impl_def_id = cx.tcx.parent(owner);
    if !matches!(cx.tcx.def_kind(impl_def_id), DefKind::Impl { .. }) {
        return false;
    }
    let self_ty = cx.tcx.type_of(impl_def_id).instantiate_identity();
    matches!(
        self_ty.kind(),
        TyKind::Adt(def, _) if cx.tcx.def_path_str(def.did()) == ALLOWED_CALLER_TYPE
    )
}

/// 在调用处报告；用调用 expr 的 `HirId` 解析 lint 级别，使 item/expr 级
/// `#[allow(rss_crosstenant_callsite)]` 逃生门生效（同 rss_spawn_missing_scope）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_CROSSTENANT_CALLSITE,
        hir_id,
        span,
        "跨租户 All-scope mint 仅 audit durable-receipt scope mint 可执行：vocab 跨租户 mint 函数不得在此调用",
        |diag| {
            diag.help(
                "先完成 typed durable append，再由 `CrossTenantReadScope::from_durable_append` mint；其它调用须经治理评审并显式 allow",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    // example target 名 `crosstenant_callsite_ui`（非 allowlist）→ 调 funnel 触发；含 anti-vacuity 绿控。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "crosstenant_callsite_ui");
}

#[test]
fn ui_audit_exact_receipt_mint_only() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "audit");
}
