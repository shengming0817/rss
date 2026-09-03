#![feature(rustc_private)]
//! `rss_operator_authorization_callsite` — RSS operator authorization 构造入口治理 dylint。
//!
//! INVARIANT: OPERATOR-AUTHORIZATION-CALLSITE-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! Operator capability / authorization plan 的私有字段形成上游 Hard 构造门；“哪个 crate 的哪个精确
//! callsite 可以调用 public constructor”是跨 crate callsite 约束，类型系统不能表达。本 lint 以
//! `diport` / `eventexec` 的 inherent self type + method 做类型感知匹配，再按 caller crate 或精确 crate/module/item
//! 放行。规则目录同时覆盖 DLQ/reconcile funnel、L2 DR move-only plan 与 durable start proof issuer。

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

const ADMIN_PDP_CALLER_CRATES: &[&str] = &["httpserve"];
const NO_CALLER_CRATES: &[&str] = &[];
const NO_EXACT_CALLSITES: &[ExactCallsite] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FunnelKind {
    Capability,
    AuditedRecoveryPlan,
    DurableStartProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactCallsite {
    crate_name: &'static str,
    module_path: &'static str,
    self_type: Option<&'static str>,
    item_name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardedFunnel {
    source_crate: &'static str,
    self_type: &'static str,
    method: &'static str,
    kind: FunnelKind,
    allowed_caller_crates: &'static [&'static str],
    exact_callsites: &'static [ExactCallsite],
}

const L2_DR_START_PROOF_ISSUERS: &[ExactCallsite] = &[ExactCallsite {
    crate_name: "postgres",
    module_path: "bundle",
    self_type: Some("PgL2DrRecoveryDeps"),
    item_name: "record_l2_dr_recovery_start_audit_subject",
}];

const GUARDED_FUNNELS: &[GuardedFunnel] = &[
    GuardedFunnel {
        source_crate: "diport",
        self_type: "DlqOperatorAuthorization",
        method: "issue",
        kind: FunnelKind::Capability,
        allowed_caller_crates: NO_CALLER_CRATES,
        exact_callsites: NO_EXACT_CALLSITES,
    },
    GuardedFunnel {
        source_crate: "eventexec",
        self_type: "OperatorReconcileCapability",
        method: "issue_for_authorized_operator",
        kind: FunnelKind::Capability,
        allowed_caller_crates: ADMIN_PDP_CALLER_CRATES,
        exact_callsites: NO_EXACT_CALLSITES,
    },
    GuardedFunnel {
        source_crate: "eventexec",
        self_type: "OperatorL2DrRecoveryCapability",
        method: "issue_for_authorized_operator",
        kind: FunnelKind::Capability,
        allowed_caller_crates: NO_CALLER_CRATES,
        exact_callsites: NO_EXACT_CALLSITES,
    },
    GuardedFunnel {
        source_crate: "eventexec",
        self_type: "AuthorizedL2DrRecoveryPlan",
        method: "from_authenticated_and_authorized",
        kind: FunnelKind::AuditedRecoveryPlan,
        allowed_caller_crates: NO_CALLER_CRATES,
        exact_callsites: NO_EXACT_CALLSITES,
    },
    GuardedFunnel {
        source_crate: "eventexec",
        self_type: "L2DrRecoveryDurableStartProof",
        method: "from_store",
        kind: FunnelKind::DurableStartProof,
        allowed_caller_crates: NO_CALLER_CRATES,
        exact_callsites: L2_DR_START_PROOF_ISSUERS,
    },
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// 标记规则目录之外的 caller 对受守护 `eventexec` operator constructor 的任意 path 引用。
    ///
    /// ### Why is this bad?
    /// Operator mutation/recovery 必须先完成 service-principal authentication 与精确 action/tenant grant；
    /// 要求 durable start audit 的 workflow 还必须在构造 plan 前持久化该证据。public constructor 若无
    /// type-aware exact-callsite guard，会退化成调用方约定。
    /// INVARIANT: OPERATOR-AUTHORIZATION-CALLSITE-01 { level = "Medium", exec = "check", source = "dylint" }。
    ///
    /// ### Known problems
    /// 仍是 intraprocedural callsite lint；允许 callsite 的可见性与 proof 消费边界仍需类型封装和 review 守。
    /// `#[cfg(test)]` 子树默认不扫，测试 fixtures 可直接构造 capability / plan。
    pub RSS_OPERATOR_AUTHORIZATION_CALLSITE,
    Warn,
    "operator authorization 构造仅限 type-aware 精确边界（callsite-allowlist，INVARIANT OPERATOR-AUTHORIZATION-CALLSITE-01）"
}

impl<'tcx> LateLintPass<'tcx> for RssOperatorAuthorizationCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        let Some(funnel) = guarded_funnel(cx, did) else {
            return;
        };
        if !caller_is_allowed(cx, expr.hir_id, funnel) {
            emit(cx, expr.hir_id, expr.span, funnel);
        }
    }
}

fn guarded_funnel(cx: &LateContext<'_>, did: DefId) -> Option<&'static GuardedFunnel> {
    if !matches!(cx.tcx.def_kind(cx.tcx.parent(did)), DefKind::Impl { .. }) {
        return None;
    }
    let self_type = impl_self_type_name(cx, did)?;
    let method = cx.tcx.item_name(did);
    GUARDED_FUNNELS.iter().find(|funnel| {
        funnel.source_crate == cx.tcx.crate_name(did.krate).as_str()
            && funnel.self_type == self_type.as_str()
            && funnel.method == method.as_str()
    })
}

fn impl_self_type_name(cx: &LateContext<'_>, did: DefId) -> Option<rustc_span::Symbol> {
    cx.tcx
        .type_of(cx.tcx.parent(did))
        .instantiate_identity()
        .ty_adt_def()
        .map(|adt| cx.tcx.item_name(adt.did()))
}

fn caller_is_allowed(cx: &LateContext<'_>, hir_id: HirId, funnel: &GuardedFunnel) -> bool {
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    if funnel.allowed_caller_crates.contains(&crate_name.as_str()) {
        return true;
    }
    let parent = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    let item_name = cx.tcx.item_name(parent);
    funnel.exact_callsites.iter().any(|callsite| {
        crate_name.as_str() == callsite.crate_name
            && item_name.as_str() == callsite.item_name
            && caller_module_path(cx, parent).is_some_and(|path| path == callsite.module_path)
            && callsite.self_type.is_none_or(|expected| {
                impl_self_type_name(cx, parent).is_some_and(|actual| actual.as_str() == expected)
            })
    })
}

fn caller_module_path(cx: &LateContext<'_>, parent: DefId) -> Option<String> {
    let container = if matches!(cx.tcx.def_kind(cx.tcx.parent(parent)), DefKind::Impl { .. }) {
        cx.tcx.parent(cx.tcx.parent(parent))
    } else {
        cx.tcx.parent(parent)
    };
    let crate_name = cx.tcx.crate_name(LOCAL_CRATE);
    let path = cx.tcx.def_path_str(container);
    Some(
        path.strip_prefix(&format!("{crate_name}::"))
            .unwrap_or(&path)
            .to_owned(),
    )
}

fn format_exact_callsites(callsites: &[ExactCallsite]) -> String {
    callsites
        .iter()
        .map(|callsite| {
            let container = callsite.self_type.unwrap_or("");
            let separator = if container.is_empty() { "" } else { "::" };
            format!(
                "{}::{}::{}{}{}",
                callsite.crate_name, callsite.module_path, container, separator, callsite.item_name
            )
        })
        .collect::<Vec<_>>()
        .join("`, `")
}

fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span, funnel: &GuardedFunnel) {
    let constructor = format!("{}::{}", funnel.self_type, funnel.method);
    let no_exact_callsite = funnel.exact_callsites.is_empty();
    let multiple_callsites = funnel.exact_callsites.len() > 1;
    let message = match (funnel.kind, no_exact_callsite, multiple_callsites) {
        (_, true, _) => {
            format!("operator constructor `{constructor}` 当前没有获授权的生产 callsite")
        }
        (FunnelKind::Capability, false, true) => format!(
            "operator capability `{constructor}` 仅可在受信 admin/PDP 或精确受信 wrapper 签发"
        ),
        (FunnelKind::Capability, false, false) => format!(
            "operator capability `{constructor}` 仅可在受信 admin/PDP 或精确生产 owner 签发"
        ),
        (FunnelKind::AuditedRecoveryPlan, false, true) => format!(
            "operator recovery plan `{constructor}` 仅可在认证、精确授权且已消费 durable start proof 的精确受信 callsite 构造"
        ),
        (FunnelKind::AuditedRecoveryPlan, false, false) => format!(
            "operator recovery plan `{constructor}` 仅可在认证、精确授权且已消费 durable start proof 的生产执行函数构造"
        ),
        (FunnelKind::DurableStartProof, false, _) => format!(
            "operator durable start proof `{constructor}` 仅可由已提交精确 start audit 的 Postgres issuer 构造"
        ),
    };
    let expected = format_exact_callsites(funnel.exact_callsites);
    let help = match (funnel.kind, no_exact_callsite, multiple_callsites) {
        (_, true, _) => {
            "不要直接调用或保存 constructor 函数项；生产 owner 必须先建立新的精确授权边界"
                .to_owned()
        }
        (FunnelKind::Capability, false, true) => format!(
            "仅通过以下精确受信 wrapper 之一构造：`{expected}`；不要直接调用或保存 constructor 函数项"
        ),
        (FunnelKind::Capability, false, false) => {
            format!("仅通过 `{expected}` 精确 wrapper 构造；不要直接调用或保存 constructor 函数项")
        }
        (FunnelKind::AuditedRecoveryPlan, false, true) => format!(
            "仅允许以下精确受信 callsite 之一：`{expected}`；不要直接调用、保存 constructor 函数项或创建同名旁路"
        ),
        (FunnelKind::AuditedRecoveryPlan, false, false)
        | (FunnelKind::DurableStartProof, false, _) => format!(
            "仅允许 `{expected}` 精确生产 callsite；不要直接调用、保存 constructor 函数项或创建同名旁路"
        ),
    };
    span_lint_hir_and_then(
        cx,
        RSS_OPERATOR_AUTHORIZATION_CALLSITE,
        hir_id,
        span,
        message,
        |diag| {
            diag.help(help);
        },
    );
}

#[test]
fn guarded_funnel_catalog_is_unique_and_non_vacuous() {
    assert_eq!(GUARDED_FUNNELS.len(), 5);
    for (index, funnel) in GUARDED_FUNNELS.iter().enumerate() {
        assert!(!funnel.self_type.is_empty());
        assert!(!funnel.source_crate.is_empty());
        assert!(!funnel.method.is_empty());
        for (callsite_index, callsite) in funnel.exact_callsites.iter().enumerate() {
            assert!(!callsite.crate_name.is_empty());
            assert!(!callsite.module_path.is_empty());
            assert!(!callsite.item_name.is_empty());
            assert!(
                funnel.exact_callsites[callsite_index + 1..]
                    .iter()
                    .all(|other| callsite != other)
            );
        }
        assert!(GUARDED_FUNNELS[index + 1..].iter().all(|other| {
            (funnel.source_crate, funnel.self_type, funnel.method)
                != (other.source_crate, other.self_type, other.method)
        }));
    }
}

#[test]
fn l2_dr_capability_is_closed_without_a_production_owner() {
    let funnel = GUARDED_FUNNELS
        .iter()
        .find(|funnel| funnel.self_type == "OperatorL2DrRecoveryCapability")
        .expect("L2 DR capability guard must remain registered");
    assert_eq!(funnel.method, "issue_for_authorized_operator");
    assert_eq!(funnel.kind, FunnelKind::Capability);
    assert!(funnel.allowed_caller_crates.is_empty());
    assert!(funnel.exact_callsites.is_empty());
}

#[test]
fn l2_dr_plan_is_closed_without_a_production_owner() {
    let funnel = GUARDED_FUNNELS
        .iter()
        .find(|funnel| funnel.self_type == "AuthorizedL2DrRecoveryPlan")
        .expect("L2 DR plan guard must remain registered");
    assert_eq!(funnel.method, "from_authenticated_and_authorized");
    assert_eq!(funnel.kind, FunnelKind::AuditedRecoveryPlan);
    assert!(funnel.allowed_caller_crates.is_empty());
    assert!(funnel.exact_callsites.is_empty());
}

#[test]
fn l2_dr_start_proof_has_one_exact_postgres_issuer() {
    let funnel = GUARDED_FUNNELS
        .iter()
        .find(|funnel| funnel.self_type == "L2DrRecoveryDurableStartProof")
        .expect("L2 DR start proof guard must remain registered");
    assert_eq!(funnel.method, "from_store");
    assert_eq!(funnel.kind, FunnelKind::DurableStartProof);
    assert_eq!(funnel.exact_callsites, L2_DR_START_PROOF_ISSUERS);
}

#[test]
fn ui_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "operator_authorization_callsite_ui");
}

#[test]
fn ui_httpserve_capability_allowed_but_authorization_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "httpserve");
}

#[test]
fn ui_postgres_non_issuer_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "postgres");
}
