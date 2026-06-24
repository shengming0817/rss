#![feature(rustc_private)]
//! `rss_authenticated_callsite` — RSS 治理 dylint lint：限定 `Authenticated` 证据构造入口仅组合根可调用。
//! `httpserve::Authenticated::new` 仅 assembly / bin crate（组合根）可调用。
//!
//! INVARIANT: AUTH-EVIDENCE-MINT-01
//!
//! `Authenticated` 是 enforce 层放行 `Require` 路由的认证证据（INVARIANT AUTH-EVIDENCE-REQUIRE-01）：
//! 请求携该 extension 即放行。它必须由组合根（assembly / bin）的验签桥在凭据校验通过后经外层 `.layer()`
//! 注入；域 crate 若直接 `Authenticated::new(..)` 并 `.layer(Extension(..))` 即可伪造证据绕过鉴权。
//!
//! 与 `rss_authplan_callsite`（AUTH-PLAN-MINT-01）同治理姿态：`AuthPlan` 是 listener 级认证计划、
//! `Authenticated` 是 per-request 认证证据，二者均为安全敏感 mint，均限组合根构造。`Authenticated` 字段私有
//! （外部无法 struct-literal 伪造），`new` 是唯一构造入口 ⇒ 守住 `new` callsite 即闭合 funnel。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（构造守卫）：`Authenticated` 字段私有，外部 crate 仅能经 `new` 合法构造——类型层私有字段已封 struct
//!   literal，但 `new` 为 `pub`（验签桥在 httpserve 外的组合根，无法 `pub(crate)` 收口），故经 callsite lint 约束。
//! - 下游（使用守卫）：`Authenticated` 可 Copy 传递，使用侧无需 mint——mint 点即唯一约束面。
//!
//! 判定四步：① callee crate 名 == "httpserve"；② item 名 == "new"；③ parent 是 Impl；
//! ④ impl self 类型的 adt 名 == "Authenticated"（self-ty 检查，杜绝 `Vec::new` 等同名 fn 误报）。
//!
//! 检测面：捕获对 funnel assoc fn 的**任意 path 引用**——直接 call callee、`let f = Authenticated::new`
//! 函数项别名、fn-pointer 强转都解析到同一 `DefId`，杜绝「先别名再调用」绕过。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；
//! ② `ALLOWED_CALLER_CRATES` 扩项无机器复核，靠 greppable + 治理评审；③ **跨函数**洗白仍未覆盖
//! （intraprocedural，跟踪 #1085）；④ `#[cfg(test)]` 树不扫，httpserve 内自测调用不命中（与 authplan 同）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// 仅这些 crate 可调用 `Authenticated::new`——单一 greppable 真源，扩项须治理评审。
/// 组合根（assembly / bin）的验签桥在凭据校验通过后构造 `Authenticated` 并经外层 `.layer()` 注入，是唯一合法构造点。
/// 当前生产代码无 `Authenticated` callsite（验签桥 = #1109 后续），allowlist 为前瞻守卫。
/// bins/server → package name "server"，bins/rss → package name "rss"（见根 Cargo.toml）。
/// 定义 crate `httpserve` 不入 allowlist：其生产代码不构造 `Authenticated`（仅 `#[cfg(test)]` 调，不被扫）。
const ALLOWED_CALLER_CRATES: &[&str] = &["server", "rss"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记非组合根 crate 对 `httpserve::Authenticated::new` 的**任意 path 引用**（直接 call、
    /// `let f = Authenticated::new` 别名、fn-pointer 强转——凡解析到该 assoc fn DefId）。
    ///
    /// ### Why is this bad?
    /// `Authenticated` 是 enforce 层放行 `Require` 路由的认证证据，必须由组合根（assembly / bin crate）的验签桥
    /// 在凭据校验通过后构造并经外层 `.layer()` 注入。域 crate 直接 mint `Authenticated` 可伪造证据绕过鉴权。
    /// INVARIANT: AUTH-EVIDENCE-MINT-01（与 AUTH-PLAN-MINT-01 同治理姿态）。
    ///
    /// ### Known problems
    /// 仍 intraprocedural：allowlist crate 内 wrapper fn 被外部调用会**跨函数**洗白（跟踪 #1085）。
    /// `ALLOWED_CALLER_CRATES` 扩项无机器复核（靠 greppable + 治理）。确需在 allowlist 外引用加
    /// `#[allow(rss_authenticated_callsite)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // 域 crate（非组合根）：
    /// let ev = httpserve::Authenticated::new(vocab::PrincipalKind::User); // 触发
    /// ```
    /// Use instead: 在 assembly / bin crate 的组合根验签桥中构造 `Authenticated`，经外层 `.layer()` 注入。
    pub RSS_AUTHENTICATED_CALLSITE,
    Warn,
    "Authenticated 证据构造仅限组合根 crate（assembly / bin）（callsite-allowlist，INVARIANT AUTH-EVIDENCE-MINT-01)"
}

impl<'tcx> LateLintPass<'tcx> for RssAuthenticatedCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        // 捕获对 funnel fn-item 的**任意** path 引用——直接 call 的 callee、`let f = Authenticated::new` 别名、
        // fn-pointer 强转都是 `ExprKind::Path` 解析到该 assoc fn `DefId`；只拦表面 call 会被「先别名再调用」绕过。
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_authenticated_mint_did(cx, did) && !caller_is_allowed(cx) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

/// `did` 是 `httpserve::Authenticated` 的关联 fn `new`。
/// 四步判定——缺第 4 步会误命中所有 `X::new`：
/// 1. callee crate 名 == "httpserve"
/// 2. item 名 == "new"
/// 3. parent def_kind 是 Impl（assoc fn）
/// 4. impl self 类型的 adt 名 == "Authenticated"（关键：区分 Vec::new 等同名 fn）
fn is_authenticated_mint_did(cx: &LateContext<'_>, did: DefId) -> bool {
    // 步骤 1：callee 属于 httpserve crate
    if cx.tcx.crate_name(did.krate).as_str() != "httpserve" {
        return false;
    }
    // 步骤 2：item 名是 "new"
    if cx.tcx.item_name(did).as_str() != "new" {
        return false;
    }
    // 步骤 3：parent 是 Impl（assoc fn，非自由 fn）
    let parent_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent_did), DefKind::Impl { .. }) {
        return false;
    }
    // 步骤 4：impl self 类型的 adt 名 == "Authenticated"（杜绝 Vec::new 等误报）
    let self_ty = cx.tcx.type_of(parent_did).skip_binder();
    if let Some(adt_def) = self_ty.ty_adt_def() {
        cx.tcx.item_name(adt_def.did()).as_str() == "Authenticated"
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
/// `#[allow(rss_authenticated_callsite)]` 逃生门生效（同 rss_authplan_callsite）。
fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_AUTHENTICATED_CALLSITE,
        hir_id,
        span,
        "Authenticated 证据仅组合根（assembly / bin crate）可构造：`Authenticated::new` 不得在此 crate 调用",
        |diag| {
            diag.help(
                "在 assembly / bin crate 的组合根验签桥中构造 Authenticated，经外层 `.layer()` 注入；确需在 allowlist 外调用须经治理评审扩 `ALLOWED_CALLER_CRATES`，或 item-level `#[allow(rss_authenticated_callsite)] // reason: ...`",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    // example target 名 `authenticated_callsite_ui`（非 allowlist）→ 调 Authenticated::new 触发；
    // 含 anti-vacuity（Vec::new / httpserve 非-new fn 不触发，证明 lint 非「任意 ::new / 任意 httpserve 调用」）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authenticated_callsite_ui");
}

#[test]
fn ui_server_allowed() {
    // example target 名 `server`（= 生产 allowlist 项）⇒ crate_name(LOCAL_CRATE)=="server" ⇒ 调 funnel 不触发，
    // 验证 allowlist 分支（anti-vacuity：lint 非恒报）。golden ui/server.stderr 为空。
    // 用 "server"（非 "rss"）避与 rss_authplan_callsite 的 example "rss" 在共享 lints workspace 撞 target 名。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "server");
}
