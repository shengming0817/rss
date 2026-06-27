#![feature(rustc_private)]
//! `rss_redact_debug_required` — RSS 治理 dylint lint：高风险敏感 DTO 禁止裸
//! `#[derive(Debug)]`，必须改用 `#[derive(secure::Redact)]` 字段级脱敏。
//!
//! INVARIANT: REDACT-DEBUG-REQUIRED-01
//!
//! 守护范围是 issue #1359 本轮迁移的高风险 `(crate, type)`：`diport::AuditEvent`、
//! `identity::RoleBinding`/`Session`/`SessionId`、`runctx::RequestCtx`、
//! `diport::SecretMaterial`/`SecretCoordinate`。这是刻意窄扫：
//! `Debug` 在本仓大量用于安全的 enum/error/配置值，按字段名或字符串全仓启发式扫描会产生治理噪声。
//! 本 lint 只防止已迁移的敏感边界回退到裸 `derive(Debug)`；新增敏感 DTO 应同步把类型名纳入本名单。
//!
//! 检测面：检查 rustc 为 `#[derive(Debug)]` 生成的 `impl Debug for T`（`#[automatically_derived]`），
//! 再把诊断挂回 struct 定义处，使 item-level `#[allow(rss_redact_debug_required)]` 逃生门有效。
//!
//! 盲区：① 手写 `impl Debug` 不在本 lint 范围，仍由类型单测和 review 守；② 仅按 crate + 类型名匹配，
//! 重命名/搬迁敏感 DTO 需同步名单；③ 仅 `cargo dylint --all`（接 `cargo xtask verify`，`-D warnings`
//! fail-closed）拦。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::DefKind;
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记 issue #1359 高风险敏感 DTO 上的裸 `#[derive(Debug)]`，除非同一 item 采用
    /// `#[derive(Redact)]` / `#[derive(secure::Redact)]` 或显式 item-level `#[allow(...)]`。
    ///
    /// ### Why is this bad?
    /// 这些类型承载 subject、session、request context、secret material/coordinate 等敏感值。
    /// 裸 `derive(Debug)` 会按字段递归输出，容易把 PII/secret 带进日志或 tracing。`secure::Redact`
    /// derive 强制每个字段声明 `#[redact(...)]`，缺标注/误配在编译期失败。
    ///
    /// ### Known problems
    /// 只守 issue #1359 的高风险名单，不做全仓启发式敏感字段扫描；手写 `impl Debug` 依赖对应类型单测守护。
    /// 新增敏感 DTO 时，应同步扩展 `SENSITIVE_DEBUG_DTO_NAMES` 与 UI golden。
    pub RSS_REDACT_DEBUG_REQUIRED,
    Warn,
    "高风险敏感 DTO 不得裸 derive(Debug)：改用 #[derive(secure::Redact)] 并逐字段 #[redact(...)]"
}

impl<'tcx> LateLintPass<'tcx> for RssRedactDebugRequired {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        let Some(header) = impl_.of_trait else {
            return;
        };
        let Some(trait_did) = header.trait_ref.trait_def_id() else {
            return;
        };
        if !is_debug_trait(cx, trait_did) {
            return;
        }
        if !cx.tcx.is_automatically_derived(item.owner_id.to_def_id()) {
            return;
        }
        let self_ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
        let Some(adt) = self_ty.ty_adt_def() else {
            return;
        };
        let self_did = adt.did();
        if !self_did.is_local() {
            return;
        }
        if !matches!(cx.tcx.def_kind(cx.tcx.parent(self_did)), DefKind::Mod) {
            return;
        }
        let type_symbol = cx.tcx.item_name(self_did);
        let type_name = type_symbol.as_str();
        if !is_sensitive_debug_dto(cx, type_name) {
            return;
        }
        let self_hir = cx.tcx.local_def_id_to_hir_id(self_did.expect_local());
        span_lint_hir_and_then(
            cx,
            RSS_REDACT_DEBUG_REQUIRED,
            self_hir,
            cx.tcx.def_span(self_did),
            "高风险敏感 DTO 不得裸 derive(Debug)",
            |diag| {
                diag.help(
                    "改用 `#[derive(secure::Redact)]`，并为每个字段声明 `#[redact(public|internal|secret|pii = \"...\")]`；\
                    确需临时豁免时加 item-level `#[allow(rss_redact_debug_required)] // reason: ...`",
                );
            },
        );
    }
}

const UI_FIXTURE_CRATE: &str = "rss_redact_debug_required_ui";

const SENSITIVE_DEBUG_DTO_NAMES: &[&str] = &[
    "AuditEvent",
    "RoleBinding",
    "Session",
    "SessionId",
    "RequestCtx",
    // `PrincipalSlot` 生产类型已于 #1105 删除（runctx principal payload 改 `Arc<dyn PrincipalFacet>`）；
    // 此名仅留作 **UI fixture 通用样例**（`ui/main.rs` 的本地 stub `struct PrincipalSlot`），证明 lint 对
    // 名单内裸 derive(Debug) 类型触发——非生产守护项（生产 `(crate,type)` 匹配见下，已无 runctx PrincipalSlot 臂）。
    "PrincipalSlot",
    "SecretMaterial",
    "SecretCoordinate",
];

fn is_sensitive_debug_dto(cx: &LateContext<'_>, type_name: &str) -> bool {
    let crate_symbol = cx.tcx.crate_name(LOCAL_CRATE);
    let crate_name = crate_symbol.as_str();
    if matches!(crate_name, UI_FIXTURE_CRATE | "main") {
        return SENSITIVE_DEBUG_DTO_NAMES.contains(&type_name);
    }
    matches!(
        (crate_name, type_name),
        (
            "diport",
            "AuditEvent" | "SecretMaterial" | "SecretCoordinate"
        ) | ("identity", "RoleBinding" | "Session" | "SessionId")
            | ("runctx", "RequestCtx")
    )
}

fn is_debug_trait(cx: &LateContext<'_>, trait_did: DefId) -> bool {
    matches!(cx.tcx.crate_name(trait_did.krate).as_str(), "core" | "std")
        && cx.tcx.item_name(trait_did).as_str() == "Debug"
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_redact_debug_required_ui");
}
