#![feature(rustc_private)]
//! `rss_crosstenant_callsite` — RSS G0.4 治理 dylint lint：限定跨租户 All-scope mint 三步
//! `CrossTenantCapability::issue_for_verified_super_admin()` / `CrossTenantVisibility::authorize()` /
//! `RowVisibility::new_cross_tenant()` 仅 `authn` crate 可调用。
//!
//! INVARIANT: TENANCY-CROSSTENANT-CAP-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! 跨租户可见性是 super-admin 越权面：`CrossTenantCapability` 私有字段（`_seal: ()`）已让**构造**只能经
//! funnel（type-layer Hard，上游）；但「funnel 只许 `authn` 已校验 super-admin 路径调用」无法跨 crate 真
//! seal（domain-patterns.md：sealed-trait 仅定义-crate 内封闭，vocab 无法对 authn sealing）。本 lint 承载
//! 该 **下游** 约束（callsite-allowlist，Medium，AST 级最强可用载体）：非 allowlist crate 调用该 funnel 即报。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（mint）：私有 `_seal` 字段 ⇒ struct-literal 不可表达，编译错误（Hard，在 vocab）。
//! - 下游（callsite）：哪个 crate 可调 ⇒ 本 lint（Medium）。
//!
//! 检测面：捕获对该 assoc fn 的**任意 path 引用**——直接 `Type::fn()` call 的 callee、`let f = Type::fn`
//! 函数项别名、fn-pointer 强转都解析到同一 `DefId`，杜绝「先别名再调用」绕过。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，azure 无 CI
//! ⇒ verify 是唯一实际 gate；② `ALLOWED_CALLER_CRATES` 扩项无机器复核，靠 greppable + 治理评审；③ **跨函数**
//! 洗白仍未覆盖（intraprocedural）：allowlist crate 内 `pub fn wrap() -> Cap { …issue…() }` 被外部调用 `wrap()`，
//! lint 只见各自直接引用、不跨函数追（收紧待 authn 模块可见性，跟踪 #1085）。注：vocab 自身 smoke 测试引用该
//! fn-item 会命中，但属 `#[cfg(test)]`，`cargo dylint --all` 不扫测试子树 ⇒ 实际 gate 无误报。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅这些 crate 可调用跨租户 All-scope mint 三步——单一 greppable 真源，扩项须治理评审
/// （等同对 funnel 本身的审视）。`authn` 持有「已校验 super-admin → 签发 capability」的派生路径。
const ALLOWED_CALLER_CRATES: &[&str] = &["authn"];

const FORBIDDEN_ASSOC_FNS: &[&str] = &[
    "issue_for_verified_super_admin",
    "authorize",
    "new_cross_tenant",
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记非 `authn` crate 对 vocab 跨租户 All-scope mint 三步的
    /// **任意 path 引用**（直接 call、`let f = Type::fn` 别名、fn-pointer 强转——凡解析到该 assoc fn DefId）。
    ///
    /// ### Why is this bad?
    /// 跨租户可见性是 super-admin 越权面。capability 的**构造**已由 vocab 私有字段封到 funnel（Hard），但
    /// 「funnel 只许 authn 已校验 super-admin 路径调用」跨 crate 不可真 seal，故由本 callsite-allowlist lint
    /// 承载（Medium）。非 authn crate 取得该 fn-item（直接调或别名后调）⇒ 绕过 super-admin 校验、跨租户越权。
    /// INVARIANT: TENANCY-CROSSTENANT-CAP-01 { level = "Medium", exec = "verify", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍 intraprocedural：allowlist crate 内 wrapper fn（`pub fn wrap() -> Cap { …issue…() }`）被外部 `wrap()`
    /// 调用会**跨函数**洗白（lint 只见各自直接引用，跟踪 #1085）。`ALLOWED_CALLER_CRATES` 扩项无机器复核（靠
    /// greppable + 治理）。确需在 allowlist 外引用加 `#[allow(rss_crosstenant_callsite)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // 非 authn crate：
    /// let cap = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin(); // 触发
    /// ```
    /// Use instead: 在 `authn` 的已校验 super-admin 派生路径里完成 issue→authorize→new_cross_tenant。
    pub RSS_CROSSTENANT_CALLSITE,
    Warn,
    "跨租户 capability 签发仅限 authn 已校验 super-admin 路径（callsite-allowlist，INVARIANT TENANCY-CROSSTENANT-CAP-01）"
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
        if is_cross_tenant_funnel_did(cx, did) && !caller_is_allowed(cx) {
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

/// 当前被编译 crate（caller）在 allowlist 内。`LOCAL_CRATE` 是 caller，区别于 callee 的 `did.krate`；
/// 按 crate 名判定不可被「在别的 crate 里 `mod authn`」伪造。
fn caller_is_allowed(cx: &LateContext<'_>) -> bool {
    ALLOWED_CALLER_CRATES.contains(&cx.tcx.crate_name(LOCAL_CRATE).as_str())
}

/// 在调用处报告；用调用 expr 的 `HirId` 解析 lint 级别，使 item/expr 级
/// `#[allow(rss_crosstenant_callsite)]` 逃生门生效（同 rss_spawn_missing_scope）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_CROSSTENANT_CALLSITE,
        hir_id,
        span,
        "跨租户 All-scope mint 仅 `authn` 已校验 super-admin 路径可执行：vocab 跨租户 mint 函数不得在此 crate 调用",
        |diag| {
            diag.help(
                "在 `authn` 的已校验 super-admin 派生路径里完成 issue→authorize→new_cross_tenant；确需在 allowlist 外调用须经治理评审扩 `ALLOWED_CALLER_CRATES`，或 item-level `#[allow(rss_crosstenant_callsite)] // reason: ...`",
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
fn ui_authn_allowed() {
    // example target 名 `authn`（= 生产 allowlist 项）⇒ crate_name(LOCAL_CRATE)=="authn" ⇒ 调 funnel 不触发，
    // 验证 allowlist 分支（anti-vacuity：lint 非恒报）。golden ui/authn.stderr 为空。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authn");
}
