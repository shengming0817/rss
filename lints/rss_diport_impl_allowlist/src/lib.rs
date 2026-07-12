#![feature(rustc_private)]
//! `rss_diport_impl_allowlist` — RSS 治理 dylint lint：`diport` DI port trait 仅 blessed
//! adapter / 组合根可 impl（impl-site allowlist）。
//!
//! INVARIANT: DIPORT-IMPL-ALLOWLIST-01 { level = "Medium", exec = "verify", source = "dylint" }
//!
//! DI port trait（`Signer`/`Publisher`/`Subscriber`/`AuditSink`/`ManagedResource` 的 trait_variant
//! Send 变体 + 基 trait `*Local` + sync `Clock`/`SubscribeInitializer`）集中在 `diport`。ADR-003 §4.2
//! 方案 ②：这些 trait **不带** sealed supertrait——sealed-trait 仅定义 crate 内封闭，无法对**独立**
//! adapter crate sealing。故「谁可 impl port trait」无法用类型系统 Hard 跨 crate 表达，由本 lint 承载
//! （AST 级 impl-site allowlist，Medium，最强可用载体）。
//!
//! 上下游强度（ai-robust.md §审查要求「Funnel 类约束分别说明上游 / 下游」）：
//! - 上游（定义面）：DI port trait 只能**定义**在 diport——`deny.toml` wrapper 限定 dynosaur/trait-variant
//!   宏依赖只准 `diport`（cargo-deny Medium，INVARIANT DIPORT-MACRO-CONFINE-01）。
//! - 下游（impl 面）：DI port trait 只能在 adapter / 组合根**实现**——本 lint（Medium）。cargo-deny 限「依赖」
//!   非「impl 站点」，且域 crate 也合法依赖 diport（消费端口而非 impl），故 impl-site 须由 AST lint 单独守。
//!
//! 判定面：
//! - trait 归属：被 impl 的 trait 其 `DefId` 的 crate 名 == `diport`。diport **只含** port trait + 错误类型
//!   struct（无其它可 impl trait），故按 crate 身份判即覆盖全部 port + 未来新增 port + 基 trait `*Local`，
//!   无名单漂移（≠ 维护显式 trait 名集合，新增 port 会漏守）。
//! - impl 站点放行（二选一，均键 **package 身份 / 位置**，非源**文件**路径）：① 被编译 crate 是 `diport`
//!   自身（定义方 + dynosaur/trait_variant 宏在 diport 源内生成的 bridge impl，按 `LOCAL_CRATE` 身份判）；
//!   ② 被编译 package 的 `CARGO_MANIFEST_DIR`（绝对路径、随调用位置不变）其**父目录名** ∈ workspace 顶层
//!   成员目录 `adapters` / `bins` / `assemblies` / `composition`（对齐 `xtask/src/layers.rs` 顶层成员分层）——新增 adapter
//!   自动覆盖，零 lint 编辑。键 package 位置而非源文件位置 ⇒ 域 crate 把 impl 放进 `crates/<domain>/src/
//!   adapters/` 子目录**无法绕过**（manifest dir 仍 `crates/<domain>`，父目录 `crates`）。`xtask` 父目录是
//!   workspace 根、且系构建工具永不 impl runtime DI port，**故意不**入 allowlist。
//!   **不**用 `span.from_expansion()` 放行宏 impl：那会连**域 / 服务 crate 内 `macro_rules!` / proc-macro
//!   展开的 `impl <port> for ...`** 一并放行（绕过面）；改按 `LOCAL_CRATE` 身份——diport 宏 impl 放行、
//!   域 crate 宏 impl 仍报。
//!
//! 盲区：① 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦，azure 无 CI ⇒
//! verify 是唯一实际 gate；② `#[cfg(test)]` 子树因 `cargo dylint --all` 默认不带 `--all-targets` 不被扫——
//! diport smoke / 服务 crate 的 `#[cfg(test)]` mock impl 不报（test 替身 impl 合法，非生产 impl；`#[cfg(test)]`
//! 不进生产构建，无生产绕过口）；③ allowlist 顶层成员目录集（`adapters`/`bins`/`assemblies`/`composition`）扩项无机器复核
//! （与 `layers.rs` 顶层成员约定同源，靠 greppable + 治理评审）。键 `CARGO_MANIFEST_DIR` 父目录而非源文件
//! 路径，无「祖先目录同名误放行」「域内子目录绕过」隐患。
//!
//! anti-vacuity（守卫非恒真 / 恒假，两向均机器锁）：红向（恒放行）由 UI golden 锁（example crate 路径非
//! allowlist，红例 impl port trait **必报** 2 条）；绿向（恒报 / 误伤 adapter）由 `cargo xtask verify` 的
//! `cargo dylint --all` 工作区跑锁（adapter/组合根真实 impl **0 诊断**）——是 verify 机器门（非一次性人工）。
//! adapter-path 绿分支无法在 UI harness 内单测（harness 控制 example 源路径），故由工作区门承载。
//!
//! Hard 化评估（ai-robust.md §审查要求）：无低成本 Hard 路径——跨 crate sealed-trait 不可行（ADR-003 §4.2），
//! AST lint 是最强可用载体；唯一 Hard 路径是「adapter impl 收回 diport + sealed-trait」（§4.2 方案 ①），代价
//! 是 adapter 逻辑耦合进 diport，ADR-003 已权衡否决，无需另立 Issue。

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
    /// 标记**非** allowlist crate（package manifest 父目录不在 `adapters`/`bins`/`assemblies`/`composition`，即域 / 服务 /
    /// 引擎 / 基础 crate）里对 `diport` 定义的任一 DI port trait 的 `impl`。
    ///
    /// ### Why is this bad?
    /// DI port（`Signer`/`Publisher`/`ManagedResource`…）的正确性要求 provider 可互换、impl 仅限 blessed
    /// adapter（经组合根注入），域 / 服务 crate 只**消费** `Box<DynX>` / `Arc<DynX>`。port trait 集中到独立
    /// `diport` crate 后 sealed-trait 无法跨 crate 封闭（ADR-003 §4.2 方案 ②），故「谁可 impl」由本 AST lint
    /// 承载（Medium，最强可用载体）。域 / 服务 crate 直接 `impl Signer for ...` 会绕过 provider 可替换边界。
    /// INVARIANT: DIPORT-IMPL-ALLOWLIST-01 { level = "Medium", exec = "verify", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings` fail-closed）拦；`#[cfg(test)]` 子树
    /// 默认不被扫（test mock impl 放行）；allowlist 顶层成员目录集（`adapters`/`bins`/`assemblies`/`composition`）扩项无机器
    /// 复核（与 `xtask/src/layers.rs` 顶层成员约定同源，靠 greppable + 治理）。键 package 的 `CARGO_MANIFEST_DIR`
    /// 父目录而非源文件路径，无目录名绕过（域内 `src/adapters/` 子目录、祖先同名目录均不误判）。
    /// 确需在 allowlist 外 impl 加 `#[allow(rss_diport_impl_allowlist)] // reason: ...`。
    ///
    /// ### Example
    /// ```ignore
    /// // crates/identity（域 crate，非 allowlist）：
    /// impl diport::Signer for MyThing { /* ... */ } // 触发
    /// ```
    /// Use instead: 把 provider 实现放到 `adapters/<name>`，域 / 服务 crate 经构造器注入 `Box<DynSigner>` 消费。
    pub RSS_DIPORT_IMPL_ALLOWLIST,
    Warn,
    "diport DI port trait 仅 adapter / 组合根可 impl（impl-site allowlist，INVARIANT DIPORT-IMPL-ALLOWLIST-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssDiportImplAllowlist {
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
        // 被 impl 的 trait 定义在 diport ⇒ DI port trait。
        if !trait_defined_in_diport(cx, trait_did) {
            return;
        }
        // impl 站点是 diport 自身（定义方 + dynosaur 宏 bridge impl）或 adapter / 组合根 package ⇒ 放行。
        if impl_site_allowed(cx) {
            return;
        }
        // 在 impl item 处报告；用 item.hir_id() 解析级别 ⇒ impl 块上 #[allow(rss_diport_impl_allowlist)] 生效。
        span_lint_hir_and_then(
            cx,
            RSS_DIPORT_IMPL_ALLOWLIST,
            item.hir_id(),
            item.span,
            format!(
                "diport DI port trait `{}` 仅 adapter / 组合根可 impl：此 crate 不在 impl-site allowlist",
                cx.tcx.item_name(trait_did)
            ),
            |diag| {
                diag.help(
                    "把 provider 实现放到 `adapters/<name>`（或组合根 `bins/`·`assemblies/`·`composition/`），域 / 服务 crate 经构造器注入 `Box<DynX>` / `Arc<DynX>` 消费；确需在 allowlist 外 impl，在该 impl 块加 `#[allow(rss_diport_impl_allowlist)] // reason: ...`（item-level 逃生门），并在 PR review 说明理由",
                );
            },
        );
    }
}

/// 被 impl 的 trait 定义在 `diport` crate ⇒ DI port trait（diport 只含 port trait + 错误类型 struct，
/// 无其它可 impl trait；trait_variant Send 变体在 diport 源内展开，DefId krate==diport）。按 callee/trait
/// crate 名判定不可被「在别处 `mod diport`」伪造。
fn trait_defined_in_diport(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    cx.tcx.crate_name(trait_did.krate).as_str() == "diport"
}

/// impl 站点放行条件（二选一），均键 **package 身份 / 位置**（非源**文件**路径，杜绝目录名绕过）：
/// 1. 被编译 crate 是 `diport` 自身——port 定义方 + dynosaur/trait_variant 宏在 diport 源内生成的 bridge
///    impl 合法（按 `LOCAL_CRATE` crate 身份判，不可被外部 `mod diport` 伪造）。这同时**关掉宏绕过面**：
///    域 / 服务 crate 用 `macro_rules!` / proc-macro 展开的 `impl <port> for ...` 其 `LOCAL_CRATE` 是该域 /
///    服务 crate（非 diport），不在此分支放行。
/// 2. 被编译 package 的 manifest 目录（cargo 为每个 crate 设 `CARGO_MANIFEST_DIR`，绝对路径、随调用位置
///    不变）其**父目录名** ∈ workspace 顶层成员目录 `adapters` / `bins` / `assemblies` / `composition`。键 package 位置而非
///    源**文件**位置 ⇒ 域 crate 把 impl 放进 `crates/<domain>/src/adapters/` 等子目录**无法绕过**（其
///    manifest dir 仍是 `crates/<domain>`，父目录 `crates`）。`xtask` 父目录是 workspace 根（非这三者）、
///    且系构建工具永不 impl runtime DI port，**故意不**入 allowlist（fail-closed 更严，确需走 item-level
///    `#[allow]`）。
///
/// `CARGO_MANIFEST_DIR` 缺失（理论上 cargo 必设；非 cargo 驱动场景）fail-closed 视为不允许。
fn impl_site_allowed(cx: &LateContext<'_>) -> bool {
    if cx.tcx.crate_name(LOCAL_CRATE).as_str() == "diport" {
        return true;
    }
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    matches!(
        Path::new(&manifest_dir)
            .parent()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str()),
        Some("adapters" | "bins" | "assemblies" | "composition")
    )
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_diport_impl_allowlist_ui");
}
