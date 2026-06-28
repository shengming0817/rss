#![feature(rustc_private)]
//! `rss_pdp_impl_adapter_only` — RSS 治理 dylint lint：`diport::Pdp` 验签端口**仅 provider adapter 可
//! impl**；组合根（`bins` / `assemblies`）与域 / 服务 crate 不得内联 `impl diport::Pdp`（信任根锁）。
//!
//! INVARIANT: PDP-IMPL-ADAPTER-ONLY-01 { level = "Medium", exec = "verify", source = "dylint" }（T004.6 / #1198 / ADR-006 §5 安全同批门信任根分线）
//!
//! 背景：`Pdp` 是认证决策的**信任原点**（验签 = 信任原点，`authn::verify_jwt` 经其铸 `VerifiedClaims`）。
//! 既有 `rss_diport_impl_allowlist`（DIPORT-IMPL-ALLOWLIST-01）放行 `adapters` / `bins` / `assemblies` impl
//! **任一** DI port，`deny.toml` oidc/memory wrapper 只拦「依赖 stub adapter crate」——二者都**拦不住**组合根
//! （bins/assemblies，在 allowlist 内）**内联** 一个 always-allow `impl Pdp`（恒返回伪 `VerifiedClaims`）绕过真
//! 验签（`tasks.md:14` stub 防线缺口）。本 lint 把 `Pdp` 收紧到**只准 provider adapter 实现**：组合根只能经
//! 构造器注入真 adapter（如 `oidc::OidcProvider`），不可自造验签判定。
//!
//! 判定面：
//! - trait 归属：被 impl 的 trait `DefId` 的 crate 名 == `diport` **且** trait 名 ∈ {`Pdp`, `PdpLocal`}（Send
//!   变体 + 非 Send 基 trait；二者均能承载验签判定，一并守）。按 crate+名判，不可被别处 `mod diport` 伪造。
//! - impl 站点放行（二选一，键 **package 身份 / 位置**，非源文件路径）：① 被编译 crate 是 `diport` 自身
//!   （dynosaur/trait_variant 宏在 diport 源内生成的 `impl Pdp for DynPdp` bridge，按 `LOCAL_CRATE` 身份判）；
//!   ② 被编译 package 的 `CARGO_MANIFEST_DIR` 父目录名 == `adapters`（provider 实现唯一合法位）。**故意不**放行
//!   `bins` / `assemblies`（≠ `rss_diport_impl_allowlist`）——组合根内联 Pdp 即信任根被旁路，正是本 lint 所拦。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（定义面）：`Pdp` 只定义在 `diport`（`deny.toml` 宏依赖 wrapper，DIPORT-MACRO-CONFINE-01）。
//! - 下游（impl 面）：`Pdp` 只能在 `adapters` 实现——本 lint（Medium，AST 级，最强可用载体）。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，azure 无 CI ⇒
//! verify 是唯一实际 gate；② `#[cfg(test)]` 子树因 `cargo dylint --all` 默认不带 `--all-targets` 不被扫——
//! test stub（如 `authn` 的 `StubPdp`、bins e2e 的测试替身）**合法不报**（test 替身非生产、不进生产构建，无
//! 生产绕过口；这正是「stub Pdp 仅 dev-dep/`#[cfg(test)]`」的要求）；③ allowlist（`adapters` 单目录 + diport）扩
//! 项无机器复核（靠 greppable + 治理评审）。键 `CARGO_MANIFEST_DIR` 父目录 ⇒ 域内 `src/adapters/` 子目录不误放行。
//!
//! anti-vacuity（守卫非恒真 / 恒假）：红向由 UI golden 锁（example crate 父目录非 `adapters` ⇒ `impl Pdp`
//! **必报**；non-Pdp diport trait impl / inherent / item-level `#[allow]` **不报**，证 specificity + 逃生门）；
//! 绿向（adapter impl Pdp **不报**）由 `cargo xtask verify` 的 `cargo dylint --all` 工作区跑承载（`adapters/oidc`
//! 真 `impl diport::Pdp` 0 诊断）——是 verify 机器门（非一次性人工）。adapter 绿分支无法在 UI harness 内单测
//! （harness 控制 example 源路径，无法置于 `adapters/`），故由工作区门承载（同 `rss_diport_impl_allowlist` 范式）。
//!
//! Hard 化评估（ai-robust.md §审查要求）：无低成本 Hard 路径——跨 crate sealed-trait 不可行（ADR-003 §4.2），
//! 「源码位置 / cfg(test) 区分 impl」类型系统 / crate 图无法表达，AST lint 是最强可用载体（Medium）。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::path::Path;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记**非** `adapters` package（且非 `diport` 自身）里对 `diport::Pdp` / `diport::PdpLocal` 验签端口的
    /// `impl`——即组合根（`bins` / `assemblies`）或域 / 服务 crate 内联实现验签判定。
    ///
    /// ### Why is this bad?
    /// `Pdp` 是认证信任原点。组合根（bins/assemblies，在 `rss_diport_impl_allowlist` 放行集内）内联一个
    /// always-allow `impl Pdp`（恒返回伪 `VerifiedClaims`）即可旁路真验签——`deny.toml` stub wrapper 与既有
    /// impl-site allowlist 都拦不住（ADR-006 §5 安全同批门信任根缺口，`tasks.md:14`）。本 lint 把 `Pdp` 收紧到
    /// **只准 provider adapter 实现**，组合根只能经构造器注入真 adapter（如 `oidc::OidcProvider`）。
    /// INVARIANT: PDP-IMPL-ADAPTER-ONLY-01 { level = "Medium", exec = "verify", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]` 子树默认
    /// 不被扫（test stub Pdp 合法不报——正是「stub 仅 dev-dep/cfg(test)」要求）；allowlist（`adapters` + diport）
    /// 扩项无机器复核（靠 greppable + 治理）。键 package 的 `CARGO_MANIFEST_DIR` 父目录，无目录名绕过。
    /// 确需在 allowlist 外 impl 加 `#[allow(rss_pdp_impl_adapter_only)] // reason: ...`（item-level 逃生门）。
    ///
    /// ### Example
    /// ```ignore
    /// // bins/server（组合根，非 adapters）：
    /// struct AllowAll;
    /// impl diport::Pdp for AllowAll { /* 恒返回伪 VerifiedClaims */ } // 触发
    /// ```
    /// Use instead: 把验签实现放到 `adapters/<name>`（provider），组合根经构造器注入 `Box<DynPdp>` 消费。
    pub RSS_PDP_IMPL_ADAPTER_ONLY,
    Warn,
    "diport::Pdp 验签端口仅 provider adapter 可 impl（信任根，INVARIANT PDP-IMPL-ADAPTER-ONLY-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssPdpImplAdapterOnly {
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
        // 仅守 diport::Pdp / PdpLocal（验签端口）；其它 trait（含其它 diport port）不归本 lint。
        if !is_pdp_trait(cx, trait_did) {
            return;
        }
        // diport 自身（dynosaur bridge impl）或 adapters package ⇒ 放行。
        if impl_site_allowed() || is_local_diport(cx) {
            return;
        }
        span_lint_hir_and_then(
            cx,
            RSS_PDP_IMPL_ADAPTER_ONLY,
            item.hir_id(),
            item.span,
            format!(
                "验签端口 `diport::{}` 仅 provider adapter 可 impl：组合根 / 域不得内联验签判定（信任根）",
                cx.tcx.item_name(trait_did)
            ),
            |diag| {
                diag.help(
                    "把验签实现放到 `adapters/<name>`（provider），组合根经构造器注入 `Box<DynPdp>` 消费；确需在 allowlist 外 impl，在该 impl 块加 `#[allow(rss_pdp_impl_adapter_only)] // reason: ...`（item-level 逃生门），并在 PR review 说明理由",
                );
            },
        );
    }
}

/// 被 impl 的 trait 是 `diport::Pdp` 或 `diport::PdpLocal`（验签端口的 Send 变体 + 非 Send 基 trait）。
/// 按 crate 名（diport）+ trait 名判，不可被别处 `mod diport` / 同名 trait 伪造触发或绕过。
fn is_pdp_trait(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    cx.tcx.crate_name(trait_did.krate).as_str() == "diport"
        && matches!(cx.tcx.item_name(trait_did).as_str(), "Pdp" | "PdpLocal")
}

/// 被编译 crate 是 `diport` 自身——dynosaur/trait_variant 宏在 diport 源内生成的 `impl Pdp for DynPdp`
/// bridge 合法（按 `LOCAL_CRATE` 身份判，不可被外部 `mod diport` 伪造）。
fn is_local_diport(cx: &LateContext<'_>) -> bool {
    cx.tcx.crate_name(LOCAL_CRATE).as_str() == "diport"
}

/// impl 站点放行：被编译 package 的 manifest 目录父目录名 == `adapters`（provider 实现唯一合法位）。
/// 键 package 位置（`CARGO_MANIFEST_DIR`，绝对路径、随调用位置不变）非源**文件**位置 ⇒ 域 crate 把 impl
/// 放进 `crates/<domain>/src/adapters/` 子目录无法绕过（manifest dir 仍 `crates/<domain>`，父目录 `crates`）。
/// `CARGO_MANIFEST_DIR` 缺失 fail-closed 视为不允许。**故意不**放行 `bins` / `assemblies`（组合根内联 Pdp 即旁路）。
fn impl_site_allowed() -> bool {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    Path::new(&manifest_dir)
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        == Some("adapters")
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_pdp_impl_adapter_only_ui");
}
