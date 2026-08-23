#![feature(rustc_private)]
//! `rss_adapter_no_business_fsm` — RSS 治理 dylint lint：`adapters/*` 禁业务 FSM / `statig`。
//!
//! INVARIANT: ADAPTER-NO-BUSINESS-FSM-01 { level = "Medium", exec = "check", source = "dylint" }
//! （ADR-023 / #1494；上游 Medium：`deny.toml` ban `statig` = ADAPTER-THIN-FSM-01）
//!
//! Adapter 必须是薄 SDK / RustCrypto / broker 委托。业务生命周期状态机只属 domain / 引擎。本 lint
//! 在 AST 级拦两类厚实现信号：
//! 1. `use` / path 段含 `statig`（与 deny ban 双保险）；
//! 2. 本地 enum 名匹配 `(?i).*(State|Phase|Lifecycle)$`，且同类型 inherent impl 含
//!    `next` / `transition` / `advance` / `step`（过渡表形态）。
//!
//! 激活条件（键 package 身份，非源文件路径）：
//! - `CARGO_MANIFEST_DIR` 父目录名 == `adapters`；或
//! - `CARGO_PKG_NAME == "rss_adapter_no_business_fsm"`（本 lint 的 UI fixture example）。
//!
//! 上下游强度（cargo xtask archrules verify）：
//! - 上游 Medium：`deny.toml` `{ crate = "statig" }`——依赖图禁 FSM 框架（ADAPTER-THIN-FSM-01；cargo-deny = Medium）。
//! - 下游 Medium：本 lint——禁 path 引用 + 过渡表形态（ADAPTER-NO-BUSINESS-FSM-01）。
//!
//! Hard-化评估：跨 crate「业务 vs 基建」语义无法类型封闭；依赖 ban 只挡具名 crate。AST 形态守卫
//! 是最强可用 Medium 载体。误报以改名 / 上移 domain 消除，禁止批量 `#[allow]`。
//!
//! anti-vacuity：UI golden 锁红（State+transition）与绿（非匹配名 / allow / 无过渡方法的 Phase 标签）；
//! 真 adapters 零诊断由 `cargo dylint --all`（verify）承载。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::path::Path;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::{ImplItemKind, Item, ItemKind, Path as HirPath};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 在 `adapters/*`（及本 lint UI fixture）中标记：
    /// 1. path / `use` 含 `statig`；
    /// 2. 本地 `*State` / `*Phase` / `*Lifecycle` enum 的 inherent impl 含
    ///    `next` / `transition` / `advance` / `step`。
    ///
    /// ### Why is this bad?
    /// Adapter 厚实现（业务 FSM / FSM 框架）是 GoCell S3/OIDC 多轮推倒重建的根因（D3）。业务生命周期
    /// 只属 domain/引擎；adapter 只做薄委托。INVARIANT: ADAPTER-NO-BUSINESS-FSM-01。上游 Medium：
    /// `deny.toml` ban `statig`（ADAPTER-THIN-FSM-01 / ADR-023；cargo-deny = Medium）。
    ///
    /// ### Known problems
    /// 仅启发式：enum 后缀 + 固定方法名；手写 match 推进但不叫这些方法名可能漏报。标签枚举（仅
    /// `as_str` 等）不报。仅 `cargo dylint --all` 拦（接 verify，`-D warnings` fail-closed）。
    /// 确需豁免：`#[allow(rss_adapter_no_business_fsm)] // reason: ...`（禁止批量 allow 债）。
    ///
    /// ### Example
    /// ```rust
    /// enum SessionState { Idle, Active }
    /// impl SessionState {
    ///     fn transition(self) -> Self { Self::Active } // 触发
    /// }
    /// ```
    /// Use instead: 把业务 FSM 上移 domain/引擎；adapter 只保留标签枚举或 SDK 委托。
    pub RSS_ADAPTER_NO_BUSINESS_FSM,
    Warn,
    "adapters 不得承载业务 FSM / 引用 statig（INVARIANT ADAPTER-NO-BUSINESS-FSM-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssAdapterNoBusinessFsm {
    fn check_path(&mut self, cx: &LateContext<'tcx>, path: &HirPath<'tcx>, hir_id: rustc_hir::HirId) {
        if !lint_active() {
            return;
        }
        if !path_mentions_statig(path) {
            return;
        }
        span_lint_hir_and_then(
            cx,
            RSS_ADAPTER_NO_BUSINESS_FSM,
            hir_id,
            path.span,
            "adapters 不得引用 `statig`：业务 FSM 框架禁入薄委托层（上游 Medium：deny.toml ADAPTER-THIN-FSM-01）",
            |diag| {
                diag.help(
                    "业务生命周期状态机放 domain / consistency / deviceloop；adapter 只做 SDK/RustCrypto 薄委托；\
                     确需豁免加 `#[allow(rss_adapter_no_business_fsm)] // reason: ...`",
                );
            },
        );
    }

    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if !lint_active() {
            return;
        }
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        // 只守 inherent impl（过渡表方法挂在类型自身上）。
        if impl_.of_trait.is_some() {
            return;
        }
        let Some(adt_name) = inherent_impl_local_enum_name(cx, item) else {
            return;
        };
        if !is_fsm_enum_name(&adt_name) {
            return;
        }
        for &impl_item_id in impl_.items {
            let impl_item = cx.tcx.hir_impl_item(impl_item_id);
            let ImplItemKind::Fn(..) = impl_item.kind else {
                continue;
            };
            let method = impl_item.ident.name.as_str();
            if !is_transition_method(method) {
                continue;
            }
            span_lint_hir_and_then(
                cx,
                RSS_ADAPTER_NO_BUSINESS_FSM,
                impl_item.hir_id(),
                impl_item.span,
                format!(
                    "adapters 不得定义业务过渡表：`{adt_name}` + 方法 `{method}`（业务 FSM 须上移 domain/引擎）"
                ),
                |diag| {
                    diag.help(
                        "改名避开 `*State`/`*Phase`/`*Lifecycle` 后缀，或删除 `next`/`transition`/`advance`/`step`；\
                         业务推进逻辑放到 domain/引擎；确需豁免加 `#[allow(rss_adapter_no_business_fsm)] // reason: ...`",
                    );
                },
            );
        }
    }
}

/// 激活：`adapters/*` package，或本 lint UI fixture（package 名锁定）。
fn lint_active() -> bool {
    if std::env::var("CARGO_PKG_NAME").ok().as_deref() == Some("rss_adapter_no_business_fsm") {
        return true;
    }
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    Path::new(&manifest_dir)
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        == Some("adapters")
}

fn path_mentions_statig(path: &HirPath<'_>) -> bool {
    path.segments
        .iter()
        .any(|seg| seg.ident.name.as_str() == "statig")
}

fn is_fsm_enum_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with("state") || lower.ends_with("phase") || lower.ends_with("lifecycle")
}

fn is_transition_method(name: &str) -> bool {
    matches!(name, "next" | "transition" | "advance" | "step")
}

/// inherent impl 的 Self 若为本 crate 本地 enum，返回其类型名。
fn inherent_impl_local_enum_name(cx: &LateContext<'_>, item: &Item<'_>) -> Option<String> {
    let self_ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
    let adt = self_ty.ty_adt_def()?;
    let did = adt.did();
    if !did.is_local() || !adt.is_enum() {
        return None;
    }
    Some(cx.tcx.item_name(did).to_string())
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_adapter_no_business_fsm_ui");
}
