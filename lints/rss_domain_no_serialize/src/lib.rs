#![feature(rustc_private)]
//! `rss_domain_no_serialize` — RSS G0 治理 dylint lint：domain 实体禁止 derive serde
//! `Serialize`/`Deserialize`（serde derive 冻结）。
//!
//! INVARIANT: SERDE-DOMAIN-FREEZE-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! 「domain 类型不 derive Serialize——只有 contract/DTO/generated 类型可序列化到 wire」
//! （rust-standards.md §DDD 分层、ai-robust.md serde derive 冻结）。serde 的 derive 对任何
//! crate 自由可用、类型系统无法封闭，故以 dylint AST lint 承载（Medium-class 载体）。
//!
//! 强度现状（勿过度宣称）：v1 守的是 **`domain` 模块命名约定**（非完整域 crate 安全边界——实体放
//! `entities`/`aggregate` 等模块不守护，完整覆盖待 #1054）。已接入聚合门（#1023）：`cargo dylint --all` 是
//! `cargo xtask verify` 的一步，经 `DYLINT_RUSTFLAGS=-D warnings` 升为 **fail-closed**（违例即让 verify 非零）；
//! azure 无 CI ⇒ verify 是唯一实际 gate（Medium：靠提交前 / 收尾跑）。覆盖面扩至完整域 crate 边界仍待 #1054。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::DefKind;
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::def_id::DefId;

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 domain 实体类型（本 crate 内、module 级、def-path 含 `domain` 模块段的 ADT）上
    /// `#[derive(serde::Serialize)]` / `#[derive(serde::Deserialize)]`。
    ///
    /// ### Why is this bad?
    /// RSS 约束「domain 类型不 derive Serialize——只有 contract/DTO/generated 类型可序列化到 wire」
    /// （rust-standards.md §DDD 分层、ai-robust.md serde derive 冻结）。直接序列化 entity 会把领域内部
    /// 表示泄漏成 wire 契约。serde 的 derive 对任何 crate 自由可用、类型系统无法封闭，故以 dylint
    /// AST lint 承载（Medium，最强可用载体）。INVARIANT: SERDE-DOMAIN-FREEZE-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// v1 只盯 `#[derive(..)]` 产生的 impl（`#[automatically_derived]`），放行手写 `impl Serialize`
    /// （自定义 wire adapter 合法、罕见）。仅 module 级类型——排除 serde derive 在 fn/const 内生成的
    /// `__Field`/`__Visitor` 等辅助类型。归属靠 `domain` 模块名约定（正向匹配，对齐 rust-standards.md
    /// §DDD 分层「实体/值对象/领域服务落 `domain` 模块」）——故只覆盖放在 `domain` 模块的实体；
    /// `dto`/`wire` 出口、xtask/config 解析 DTO、`generated` 等不在 `domain` 模块的类型不报。
    /// **覆盖边界**：`domain` 按 def-path **段精确匹配**（非子串，`cross_domain` 等不误命中），覆盖嵌套
    /// `*::domain::*`；但实体若放在**非 `domain` 命名**的模块（`entities`/`aggregate`/`models` 等）**不被守护**
    /// ——v2 拟扩为 crate-scoped + 模块黑名单（见 backlog issue）。
    /// 确需序列化的 `domain` 模块类型用 `#[allow(rss_domain_no_serialize)] // reason: ...` 显式豁免。
    ///
    /// ### Example
    /// ```rust
    /// mod domain {
    ///     #[derive(serde::Serialize)] // 触发
    ///     struct UserEntity { id: u64 }
    /// }
    /// ```
    /// Use instead:
    /// ```rust
    /// mod dto {
    ///     #[derive(serde::Serialize)] // dto 模块放行
    ///     struct UserDto { id: u64 }
    /// }
    /// ```
    pub RSS_DOMAIN_NO_SERIALIZE,
    Warn,
    "domain 类型不应 derive serde Serialize/Deserialize（serde derive 冻结）"
}

impl<'tcx> LateLintPass<'tcx> for RssDomainNoSerialize {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        // derive 产物是 trait impl。
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        let Some(header) = impl_.of_trait else {
            return;
        };
        let Some(trait_did) = header.trait_ref.trait_def_id() else {
            return;
        };

        // 1. 该 impl 的 trait 是 serde 的 Serialize / Deserialize。
        if !is_serde_serde_trait(cx, trait_did) {
            return;
        }

        // 2. 该 impl 由 `#[derive(..)]` 产生（携 `#[automatically_derived]`）；手写 impl 放行。
        if !cx.tcx.is_automatically_derived(item.owner_id.to_def_id()) {
            return;
        }

        // 3. Self 类型是本 crate 的域实体。
        let self_ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
        let Some(adt) = self_ty.ty_adt_def() else {
            return;
        };
        let self_did = adt.did();
        // 3a. 外部 crate 类型（含 `generated` 契约派生 wire 类型）天然放行。
        if !self_did.is_local() {
            return;
        }
        // 3b. 仅 module 级类型——排除 serde derive 在 fn/const 体内生成的 __Field/__Visitor 辅助类型
        //     （其父是 AssocFn/Const 而非 Mod）。
        if !matches!(cx.tcx.def_kind(cx.tcx.parent(self_did)), DefKind::Mod) {
            return;
        }
        // 3c. 仅域实体：def-path 含 `domain` 模块段（rust-standards.md §DDD 分层：实体/值对象/
        //     领域服务落 `domain` 模块）。dto/wire 出口、xtask/config 解析 DTO、generated 等放行。
        if !in_domain_module(cx, self_did) {
            return;
        }

        // 在域类型「定义处」报告（而非 derive 生成的 impl span——宏展开会被 rustc 抑制）；并用 self
        // 类型的 HirId 解析 lint 级别，使该类型上的 `#[allow(rss_domain_no_serialize)]` 逃生门生效
        // （impl 是 `#[automatically_derived]`，按 impl 上下文解析级别会忽略 struct 上的 allow）。
        let self_hir = cx.tcx.local_def_id_to_hir_id(self_did.expect_local());
        span_lint_hir_and_then(
            cx,
            RSS_DOMAIN_NO_SERIALIZE,
            self_hir,
            cx.tcx.def_span(self_did),
            "domain 类型不应 derive serde `Serialize`/`Deserialize`（serde derive 冻结）",
            |diag| {
                diag.help(
                    "只在 contract/DTO/generated 类型上序列化；把此类型移到 `dto`/`wire` 模块或经 From/TryFrom 转出 wire DTO。确需序列化时加 `#[allow(rss_domain_no_serialize)] // reason: ...`",
                );
            },
        );
    }
}

/// trait 是 serde 的 `Serialize` / `Deserialize`（按 crate 名 + item 名判定，避开模块路径脆弱性，
/// 且 serde 无 diagnostic item）。serde 1.x 把两 trait 定义移到 `serde_core` 再由 `serde` 导出，两者都认。
fn is_serde_serde_trait(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    matches!(
        cx.tcx.crate_name(trait_did.krate).as_str(),
        "serde" | "serde_core"
    ) && matches!(
        cx.tcx.item_name(trait_did).as_str(),
        "Serialize" | "Deserialize"
    )
}

/// Self 类型的 def-path 含 `domain` 模块段——即 DDD 域层实体（rust-standards.md §DDD 分层）。
/// 正向匹配：避免对 `dto`/`wire` 出口、xtask/config 解析 DTO、`generated` 等非域类型误报。
fn in_domain_module(cx: &LateContext<'_>, self_did: DefId) -> bool {
    cx.tcx.def_path(self_did).data.iter().any(|seg| {
        seg.data
            .get_opt_name()
            .is_some_and(|name| name.as_str() == "domain")
    })
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
