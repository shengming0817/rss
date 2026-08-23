#![feature(rustc_private)]
//! `rss_principal_facet_impl_allowlist` — RSS 治理 dylint lint：`runctx::PrincipalFacet` 仅
//! `authn`（+ 定义 crate `runctx` 的 test facet）可 impl（impl-site caller-crate allowlist）。
//!
//! INVARIANT: PRINCIPAL-FACET-IMPL-AUTHN-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `runctx::AppCtx` 的 principal payload 是 `Arc<dyn PrincipalFacet>`——authn 的已验证 `Principal` 经
//! trait 擦除注入。「只有 authn 能 impl `PrincipalFacet`」是 `AppCtx` 生产**伪造门**：外部 crate impl 不了
//! facet，就拿不到合法 principal payload，也就构造不出 `AppCtx`（伪造任意 tenant/principal 越权）。
//!
//! 但跨 crate「只有 authn 能 impl」**类型层不可表达**——sealed-trait 只能封闭到定义 crate（runctx），
//! 无法选择性放行下游 authn（ADR-003 §4.2 / ADR-006 / ADR-005 §6 已确立：跨 crate sealed-trait 不可行，
//! dylint 为最强可用载体 Medium）。故 `PrincipalFacet` 是 open `pub trait`，impl 面由本 lint 承载。
//!
//! 上下游强度（`cargo xtask archrules verify`）：
//! - 上游（定义面）：`PrincipalFacet` 只在 `runctx` 定义——crate 依赖图（runctx 是基础层、无人能在别处
//!   重定义同名 trait 并让 `AppCtx` 接受）天然成立。
//! - 下游（impl 面）：只有 `authn`（+ `runctx` test facet）可 impl——本 lint（Medium）。
//!
//! 判定面：
//! - trait 归属：被 impl 的 trait 其 `DefId` 的 crate 名 == `runctx` **且** item 名 == `PrincipalFacet`
//!   （runctx 还导出 `RequestCtx`/`MissingCtx` struct 等非-trait，故按 crate+name 精确判，不按 crate 身份泛取）。
//! - caller 放行：impl 所在被编译 crate（`LOCAL_CRATE`）名 ∈ [`ALLOWED_IMPL_CRATES`]（`runctx` = 定义 crate
//!   的 test facet；`authn` = 生产唯一 impl-er）。按 crate 名判定不可被「在别处 `mod authn`」伪造。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，azure 无 CI ⇒
//! verify 是唯一实际 gate；② **`--all-targets` 默认不传** ⇒ `#[cfg(test)]` 子树不被扫（服务 / 域 crate 的
//! `#[cfg(test)]` mock facet impl 不报）；注意 `#[cfg(feature = "test-support")]` 下的 impl（如
//! `runctx::TestPrincipalFacet`）**与 `#[cfg(test)]` 不等价**——它在显式启用该 feature 时即编译进扫描范围，
//! 但因 `runctx` 在 [`ALLOWED_IMPL_CRATES`] 故仍不误报（test 替身 + 定义 crate 均合法，不进默认生产构建）；
//! ③ [`ALLOWED_IMPL_CRATES`] 扩项无机器复核（单一 greppable 真源，靠治理评审——等同对伪造门本身的审视）；
//! ④ **`runctx::test_support::app_ctx[_with_kind]` 旁路不被本 lint 覆盖**——该 fn 在 `runctx/test-support`
//! feature 下是 `pub`，可不经 `impl PrincipalFacet` 直接造 `AppCtx`；若某生产 crate 在**非-dev** shipped 依赖表
//! 启用该 feature 即可伪造任意 tenant/principal 的 ctx，绕过本 lint。此旁路 #1105 前已存在（`PrincipalSlot`
//! 时代同款）。**该旁路已另由 xtask `layer-deps` 的 INVARIANT LAYER-DEPS-09 守**（扫所有 shipped 依赖表，
//! 启用 `runctx/test-support` 即报，Medium）——本 lint（impl 面）+ LAYER-DEPS-09（feature 启用面）共同闭合伪造门。
//!
//! anti-vacuity（守卫非恒真 / 恒假）：红向由 `ui/main.stderr` golden 锁（example crate 名 ∉ allowlist，
//! impl PrincipalFacet **必报**）；绿向由 `authn` example（crate 名 = allowlist 项，impl **不报**，golden
//! `ui/authn.stderr` 为空）+ 真 workspace `cargo dylint --all`（authn 真实 facet impl 0 诊断）双锁。
//! golden 字节随**钉版 nightly**（`lints/rust-toolchain.toml`）；toolchain bump 后须重跑本 crate UI 测试
//! 校验（必要时重 bless `ui/main.stderr`，与其它 dylint UI golden 同纪律）。
//!
//! Hard 化评估（cargo xtask archrules verify）：无低成本 Hard 路径——跨 crate sealed-trait 不可行（ADR-003 §4.2），
//! AST lint 是最强可用载体。与 `rss_crosstenant_callsite`（authn-only callsite）/ `rss_diport_impl_allowlist`
//! （impl-site allowlist）同源评级（Medium）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};

/// 仅这些 crate 可 impl `runctx::PrincipalFacet`——单一 greppable 真源，扩项须治理评审（等同审视伪造门）。
/// `authn` 持有「已验证 `Principal` → facet」的唯一生产派生；`runctx` 是定义 crate（test facet，`#[cfg]` 隔离）。
const ALLOWED_IMPL_CRATES: &[&str] = &["runctx", "authn"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记**非** allowlist crate（不在 `runctx` / `authn`）里对 `runctx::PrincipalFacet` 的 `impl`。
    ///
    /// ### Why is this bad?
    /// `runctx::AppCtx` 的 principal payload 是 `Arc<dyn PrincipalFacet>`——只有能 impl facet 的 crate 才能
    /// 造出合法 principal payload、进而构造 `AppCtx`。若域 / 服务 / adapter crate 也能 impl facet，就能伪造
    /// 任意 tenant/principal 的 `AppCtx`、绕过 RLS / ABAC 越权。跨 crate「只有 authn 能 impl」类型层不可表达
    /// （sealed-trait 跨 crate 不可行，ADR-003 §4.2），故由本 AST lint 承载（Medium，最强可用载体）。
    /// INVARIANT: PRINCIPAL-FACET-IMPL-AUTHN-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]` 子树
    /// 默认不被扫（test mock facet impl 放行）；`ALLOWED_IMPL_CRATES` 扩项无机器复核（靠 greppable + 治理）。
    /// 确需在 allowlist 外 impl 加 `#[allow(rss_principal_facet_impl_allowlist)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // crates/identity（域 crate，非 allowlist）：
    /// impl runctx::PrincipalFacet for MyThing { /* ... */ } // 触发
    /// ```
    /// Use instead: principal facet 只在 `authn` 经已验证 `Principal` 派生；其它 crate 经 `runctx::AppCtx`
    /// 不透明持有、经访问器借用 facet。
    pub RSS_PRINCIPAL_FACET_IMPL_ALLOWLIST,
    Warn,
    "runctx::PrincipalFacet 仅 authn 可 impl（impl-site allowlist，INVARIANT PRINCIPAL-FACET-IMPL-AUTHN-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssPrincipalFacetImplAllowlist {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        // inherent impl（无 of_trait）放行。
        let Some(of_trait) = impl_.of_trait else {
            return;
        };
        let Some(trait_did) = of_trait.trait_ref.trait_def_id() else {
            return;
        };
        // 被 impl 的 trait 是 runctx::PrincipalFacet。
        if !trait_is_principal_facet(cx, trait_did) {
            return;
        }
        // impl 站点 crate ∈ allowlist（runctx 定义 crate / authn 生产）⇒ 放行。
        if caller_is_allowed(cx) {
            return;
        }
        // 在 impl item 处报告；用 item.hir_id() 解析级别 ⇒ impl 块上 #[allow(...)] 生效。
        span_lint_hir_and_then(
            cx,
            RSS_PRINCIPAL_FACET_IMPL_ALLOWLIST,
            item.hir_id(),
            item.span,
            "`runctx::PrincipalFacet` 仅 `authn` 可 impl：此 crate 不在 impl-site allowlist（伪造门，PRINCIPAL-FACET-IMPL-AUTHN-01）",
            |diag| {
                diag.help(
                    "principal facet 只在 `authn` 经已验证 `Principal` 派生；其它 crate 经 `runctx::AppCtx` 不透明持有、经访问器借用 facet；确需在 allowlist 外 impl，在该 impl 块加 `#[allow(rss_principal_facet_impl_allowlist)] // reason: ...`（item-level 逃生门），并在 PR review 说明理由",
                );
            },
        );
    }
}

/// 被 impl 的 trait 是 `runctx::PrincipalFacet`（按 crate 名 + item 名精确判——runctx 还导出非-trait
/// `RequestCtx`/`MissingCtx`，故不按 crate 身份泛取；trait 名在 runctx 唯一，不可被别处 `mod runctx` 伪造）。
fn trait_is_principal_facet(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    cx.tcx.crate_name(trait_did.krate).as_str() == "runctx"
        && cx.tcx.item_name(trait_did).as_str() == "PrincipalFacet"
}

/// 当前被编译 crate（impl 站点）在 allowlist 内。`LOCAL_CRATE` 是 impl 所在 crate，按 crate 名判定不可被
/// 「在别的 crate 里 `mod authn`」伪造。
fn caller_is_allowed(cx: &LateContext<'_>) -> bool {
    ALLOWED_IMPL_CRATES.contains(&cx.tcx.crate_name(LOCAL_CRATE).as_str())
}

#[test]
fn ui_disallowed() {
    // example target 名 `rss_principal_facet_impl_allowlist_ui`（∉ allowlist）→ impl PrincipalFacet 触发；
    // 含 anti-vacuity 绿控（非 runctx trait / inherent / item-level #[allow]）。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_principal_facet_impl_allowlist_ui");
}

#[test]
fn ui_authn_allowed() {
    // example target 名 `authn`（= 生产 allowlist 项）⇒ crate_name(LOCAL_CRATE)=="authn" ⇒ impl 不触发，
    // 验证 allowlist 分支（anti-vacuity：lint 非恒报）。golden ui/authn.stderr 为空。
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authn");
}
