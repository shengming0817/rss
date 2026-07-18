#![feature(rustc_private)]
//! `rss_authplan_callsite` — RSS G0.4 治理 dylint lint：限定 AuthPlan 构造入口仅组合根可调用。
//! `primitives::authplan::AuthPlan::new` 与 `AuthPlan::none` 仅 assembly / bin crate（组合根）可调用。
//!
//! INVARIANT: AUTH-PLAN-MINT-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! `AuthPlan` 是 listener 级认证计划，语义上必须由组合根（assembly / bin）装配后通过 bootstrap option
//! 注入；域 crate 直接 mint AuthPlan 绕过组合根注入语义，可能导致认证方案错配。
//!
//! `runtime-api.md` 明文：「域 crate 禁止构造 AuthPlan；组合根经 bootstrap option 注入」——当前仅 Soft
//! 文档约束，本 lint 升为 Medium callsite-allowlist 守卫。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（构造守卫）：`AuthPlan` 字段均私有，外部 crate 可通过 `new` / `none` 合法构造——类型层无
//!   私有字段封闭，必须经 callsite lint 约束；故此 lint 同时承载上游与下游（callsite-allowlist，Medium）。
//! - 下游（使用守卫）：`AuthPlan` 本身可 Copy 传递，使用侧无需 mint——mint 点即是唯一约束面。
//!
//! 关键差异（vs `rss_crosstenant_callsite`）：`new` / `none` 是极常见 fn 名，必须额外验证
//! 关联 fn 的 parent impl 的 self 类型确实是 `AuthPlan`，否则 `Vec::new` / `Option::none` 等会误报。
//! 判定四步：① callee crate 名 == "primitives"；② item 名 ∈ {"new","none"}；③ parent 是 Impl；
//! ④ impl self 类型的 adt 名 == "AuthPlan"（self-ty 检查，本 lint 与 crosstenant 的唯一实质差异）。
//!
//! 检测面：捕获对两个 funnel assoc fn 的**任意 path 引用**——直接 call callee、`let f = AuthPlan::new`
//! 函数项别名、fn-pointer 强转都解析到同一 `DefId`，杜绝「先别名再调用」绕过。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② `ALLOWED_CALLER_CRATES` 扩项无机器复核，靠 greppable + 治理评审；③ **跨函数**洗白仍未覆盖
//! （intraprocedural）：allowlist crate 内 `pub fn wrap() -> AuthPlan { …new()… }` 被外部 `wrap()`
//! 调用，lint 只见各自直接引用、不跨函数追（跟踪 #1085）；④ `#[cfg(test)]` 树不扫，primitives
//! 内自测调用不命中（与 crosstenant 同）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅这些 crate 可调用 `AuthPlan::new` / `AuthPlan::none`——单一 greppable 真源，扩项须治理评审。
/// 组合根（assembly / bin）装配 AuthPlan 后经 bootstrap option 注入，是唯一合法构造点。
/// 当前生产代码无 AuthPlan callsite（组合根未建 body），allowlist 为前瞻守卫。
/// assemblies/runtime → package name "runtime"（#1309 单一组合根；薄 bin bins/server、bins/rss 已移出）。
/// `primitives` 本身定义 `AuthPlan`，在 `none()` 内调 `Self::new()` 是内部实现，合法豁免。
const ALLOWED_CALLER_CRATES: &[&str] = &["primitives", "runtime"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记非组合根 crate 对 `primitives::authplan::AuthPlan::new` 或 `AuthPlan::none` 的
    /// **任意 path 引用**（直接 call、`let f = AuthPlan::new` 别名、fn-pointer 强转——凡解析到该 assoc fn DefId）。
    ///
    /// ### Why is this bad?
    /// `AuthPlan` 是 listener 级认证计划，必须由组合根（assembly / bin crate）装配后经 bootstrap option 注入。
    /// 域 crate 直接 mint AuthPlan 绕过组合根注入语义，可能导致认证方案错配。
    /// runtime-api.md：「域 crate 禁止构造 AuthPlan；组合根经 bootstrap option 注入」。
    /// INVARIANT: AUTH-PLAN-MINT-01 { level = "Medium", exec = "verify", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍 intraprocedural：allowlist crate 内 wrapper fn（`pub fn wrap() -> AuthPlan { …new()… }`）被外部
    /// `wrap()` 调用会**跨函数**洗白（lint 只见各自直接引用，跟踪 #1085）。`ALLOWED_CALLER_CRATES` 扩项
    /// 无机器复核（靠 greppable + 治理）。确需在 allowlist 外引用加
    /// `#[allow(rss_authplan_callsite)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // 域 crate（非组合根）：
    /// let plan = primitives::authplan::AuthPlan::new(ListenerKind::Primary, AuthScheme::RssAccessToken); // 触发
    /// ```
    /// Use instead: 在 assembly / bin crate 的组合根中构造 AuthPlan，经 bootstrap option 注入其它 crate。
    pub RSS_AUTHPLAN_CALLSITE,
    Warn,
    "AuthPlan 构造仅限组合根 crate（assembly / bin）（callsite-allowlist，INVARIANT AUTH-PLAN-MINT-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssAuthplanCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 捕获对 funnel fn-item 的**任意** path 引用——直接 call 的 callee、`let f = AuthPlan::new` 别名、
        // fn-pointer 强转都是 `ExprKind::Path` 解析到该 assoc fn `DefId`；只拦表面 call 会被「先别名再调用」绕过。
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_authplan_mint_did(cx, did) && !caller_is_allowed(cx) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

/// `did` 是 `primitives::authplan::AuthPlan` 的关联 fn `new` 或 `none`。
/// 四步判定——缺第 4 步会误命中所有 `X::new` / `X::none`：
/// 1. callee crate 名 == "primitives"
/// 2. item 名 ∈ {"new", "none"}
/// 3. parent def_kind 是 Impl（assoc fn）
/// 4. impl self 类型的 adt 名 == "AuthPlan"（关键：区分 Vec::new、Option::none 等同名 fn）
fn is_authplan_mint_did(cx: &LateContext<'_>, did: DefId) -> bool {
    // 步骤 1：callee 属于 primitives crate
    if cx.tcx.crate_name(did.krate).as_str() != "primitives" {
        return false;
    }
    // 步骤 2：item 名是 "new" 或 "none"
    let item_name = cx.tcx.item_name(did);
    if item_name.as_str() != "new" && item_name.as_str() != "none" {
        return false;
    }
    // 步骤 3：parent 是 Impl（assoc fn，非自由 fn）
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    // 步骤 4：impl self 类型的 adt 名 == "AuthPlan"（杜绝 Vec::new / Option::none 误报）
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    if let Some(adt_def) = self_ty.ty_adt_def() {
        cx.tcx.item_name(adt_def.did()).as_str() == "AuthPlan"
    } else {
        false
    }
}

/// 当前被编译 crate（caller）在 allowlist 内。`LOCAL_CRATE` 是 caller，区别于 callee 的 `did.krate`；
/// 按 crate 名判定不可被「在别的 crate 里 `mod server`」伪造。
fn caller_is_allowed(cx: &LateContext<'_>) -> bool {
    ALLOWED_CALLER_CRATES.contains(&cx.tcx.crate_name(LOCAL_CRATE).as_str())
}

/// 在调用处报告；用调用 expr 的 `HirId` 解析 lint 级别，使 item/expr 级
/// `#[allow(rss_authplan_callsite)]` 逃生门生效（同 rss_crosstenant_callsite）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_AUTHPLAN_CALLSITE,
        hir_id,
        span,
        "AuthPlan 仅组合根（assembly / bin crate）可构造：`AuthPlan::new` / `AuthPlan::none` 不得在此 crate 调用",
        |diag| {
            diag.help(
                "在 assembly / bin crate 的组合根中构造 AuthPlan，经 bootstrap option 注入；确需在 allowlist 外调用须经治理评审扩 `ALLOWED_CALLER_CRATES`，或 item-level `#[allow(rss_authplan_callsite)] // reason: ...`",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    // example target 名 `authplan_callsite_ui`（非 allowlist）→ 调 AuthPlan::new / AuthPlan::none 触发；
    // 含 anti-vacuity（Vec::new 不触发，证明 lint 非「任意 ::new 调用」）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authplan_callsite_ui");
}

#[test]
fn ui_primitives_allowed() {
    // example target 名 `primitives`（= allowlist 项，定义 crate 内部豁免）⇒ crate_name(LOCAL_CRATE)=="primitives"
    // ⇒ 调 funnel 不触发，验证 allowlist 分支（anti-vacuity：lint 非恒报）。golden ui/primitives.stderr 为空。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "primitives");
}
