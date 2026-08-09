#![feature(rustc_private)]
//! `rss_diagctx_auth_source` — 诊断上下文不得成为认证或授权决策输入。
//!
//! INVARIANT: DIAGCTX-NOT-AUTH-SOURCE-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `diagctx` 是 attacker-controlled correlation 的 fail-open 观测信道；`runctx`、typed auth evidence
//! 与 PDP/route authorization 才是 fail-closed 授权信道。仅靠 rustdoc 提醒无法阻止未来修改在认证或授权
//! 代码里读取 ambient correlation 并据此分支。本 lint 在 name resolution 后按 `DefId` 识别真实
//! `diagctx` item，并守住以下生产边界：
//!
//! - `authn` crate 的全部模块；
//! - 定义 `diport::Pdp` / `diport::PdpLocal` production impl 的整个 crate；
//! - 定义 `httpserve::RouteAuthorizer` production impl 的整个 crate；
//! - `httpserve::auth` 授权核心模块子树。
//!
//! crate-wide owner 边界不依赖 impl 的源码布局：父模块、sibling module 与任意同 crate helper 都不能先读
//! 诊断值再间接送进决策。HTTP correlation 审计盖章位于独立 `httpserve::auth_audit` 模块，在决策完成后
//! 消费闭值 decision，因此合法不报。
//!
//! ## Gate budget
//!
//! 本规则吸收 #1400，是「诊断信道不得成为授权源」的首个 AST/HIR 机器门，不与既有 lint 重复：
//! `rss_handler_local_principal_authz` 守 handler 不得本地读取 principal/role 做授权，
//! `rss_pdp_impl_adapter_only` 守谁能实现验签 port；二者都不识别 `diagctx` 数据流。跨 crate 类型隔离为
//! Hard 上游，本 lint 是模块/路径约束的最强可用 Medium 下游，接 `cargo dylint --all` 并以
//! `-D warnings` fail-closed。
//!
//! ## 边界
//!
//! lint 按当前 production target 的 HIR 工作；默认 `cargo dylint --all` 不扫描 `#[cfg(test)]` 子树，测试
//! fixture 可使用诊断 helper。跨 crate 任意动态调用图不做数据流推导；授权实现只能消费 typed、无诊断字段的
//! request/evidence，且包含 production impl 的 crate 不得读取 `diagctx`。规则按解析后的 crate identity 匹配，
//! 局部同名 `mod diagctx` 不触发。

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::Res;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{HirId, ItemKind, Path};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 禁止认证/授权 owner 模块引用真实 `diagctx` item，包括 direct path、import alias 与 function item。
    ///
    /// ### Why is this bad?
    /// correlation 是可缺失、attacker-controlled、fail-open 的观测值，不能改变认证、租户或授权结果。
    /// 对应规则 `DIAGCTX-NOT-AUTH-SOURCE-01`。
    ///
    /// ### Known problems
    /// 守生产 HIR 的 crate/module 边界，不做跨模块动态 callgraph 推导；测试 target 默认不扫描。
    pub RSS_DIAGCTX_AUTH_SOURCE,
    Warn,
    "诊断上下文不得成为认证或授权决策输入（INVARIANT DIAGCTX-NOT-AUTH-SOURCE-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssDiagctxAuthSource {
    fn check_path(&mut self, cx: &LateContext<'tcx>, path: &Path<'tcx>, hir_id: HirId) {
        if !is_diagctx_path(cx, path) || !is_guarded_context(cx, hir_id) {
            return;
        }
        span_lint_hir_and_then(
            cx,
            RSS_DIAGCTX_AUTH_SOURCE,
            hir_id,
            path.span,
            "认证/授权决策边界不得读取 `diagctx` 诊断信道",
            |diag| {
                diag.help(
                    "授权只消费 typed auth evidence / runctx / RouteAuthorizationRequest；correlation 仅在决策完成后的独立 audit/observability 模块盖章",
                );
            },
        );
    }
}

fn is_diagctx_path(cx: &LateContext<'_>, path: &Path<'_>) -> bool {
    let Res::Def(_, did) = path.res else {
        return false;
    };
    cx.tcx.crate_name(did.krate).as_str() == "diagctx"
}

fn is_guarded_context(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let local_crate = cx.tcx.crate_name(LOCAL_CRATE);
    if local_crate.as_str() == "authn" {
        return true;
    }

    let current_module = cx
        .tcx
        .def_path_str(cx.tcx.parent_module(hir_id).to_def_id());
    if local_crate.as_str() == "httpserve"
        && (is_same_or_descendant(&current_module, "httpserve::auth")
            || is_same_or_descendant(&current_module, "auth"))
    {
        return true;
    }

    crate_has_guarded_impl(cx)
}

fn crate_has_guarded_impl(cx: &LateContext<'_>) -> bool {
    cx.tcx.hir_free_items().any(|item_id| {
        let item = cx.tcx.hir_item(item_id);
        let ItemKind::Impl(impl_) = item.kind else {
            return false;
        };
        impl_
            .of_trait
            .and_then(|trait_ref| trait_ref.trait_ref.trait_def_id())
            .is_some_and(|trait_did| is_guarded_trait(cx, trait_did))
    })
}

fn is_guarded_trait(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    let owner = cx.tcx.crate_name(trait_did.krate);
    let name = cx.tcx.item_name(trait_did);
    (owner.as_str() == "diport" && matches!(name.as_str(), "Pdp" | "PdpLocal"))
        || (owner.as_str() == "httpserve" && name.as_str() == "RouteAuthorizer")
}

fn is_same_or_descendant(actual: &str, root: &str) -> bool {
    actual == root
        || actual
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with("::"))
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_diagctx_auth_source_ui");
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authn");
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "httpserve");
}
