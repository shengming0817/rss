#![feature(rustc_private)]
//! Compiler-resolved runtime environment funnel.
//!
//! INVARIANT: RUNTIME-ENV-FUNNEL-HIR-01 { level = "Medium", exec = "verify", source = "dylint", synthetic_red = "ui_runtime", anti_vacuity = "ui_runtime" }
//!
//! The native boundary keeps the concrete process source and generic capture primitive private.
//! This lint supplies the semantic backstop that source-token scanning cannot provide: it runs
//! after macro expansion and name resolution, so aliases, function items, macro-generated modules,
//! and cross-file macro re-exports resolve to the same governed definition or expansion.
//!
//! Only the `runtime` crate is governed. Direct `std::env` reads are allowed solely in the exact
//! `config::RuntimeConfigSource for config::EnvConfigSource` implementation and four exact nested
//! operator-grant readers. Compile-time `env!`, `option_env!`, and `include!` are forbidden
//! everywhere in production runtime code. The sole process factory may be referenced only by the
//! top-level `prepare_runtime_kernel` owner.

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use std::collections::HashSet;

use clippy_utils::diagnostics::{span_lint_and_then, span_lint_hir_and_then};
use clippy_utils::macros::macro_backtrace;
use rustc_ast::MacCall;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{CRATE_DEF_ID, DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId, Node};
use rustc_lint::{EarlyContext, EarlyLintPass, LateContext, LateLintPass, LintContext, LintStore};
use rustc_session::Session;
use rustc_span::{ExpnId, Span};

const RUNTIME_CRATE: &str = "runtime";
const ENV_READERS: &[&str] = &["var", "var_os", "vars", "vars_os"];
const COMPILE_ENV_MACROS: &[&str] = &["env", "option_env", "include"];
const OPERATOR_GRANT_READERS: &[(&str, &str)] = &[
    (
        "load_projection_maintenance_grants_from_command_env",
        "operator::projection::load_projection_maintenance_grants_from_command_env",
    ),
    (
        "load_audit_ledger_verify_grants_from_command_env",
        "operator::audit_ledger::load_audit_ledger_verify_grants_from_command_env",
    ),
    (
        "load_dlq_operator_grants_from_command_env",
        "operator::dlq::load_dlq_operator_grants_from_command_env",
    ),
    (
        "load_reconcile_operator_grants_from_command_env",
        "operator::reconcile::load_reconcile_operator_grants_from_command_env",
    ),
];

#[derive(Default)]
struct PreExpansionPass;

#[derive(Default)]
struct LatePass {
    reported_expansions: HashSet<ExpnId>,
}

dylint_linting::dylint_library!();

rustc_session::declare_lint! {
    /// ### What it does
    /// Rejects compiler-resolved `std::env::{var,var_os,vars,vars_os}` references outside the
    /// exact runtime funnel owners, rejects `env!`/`option_env!`/`include!` by expansion
    /// provenance, and restricts the process snapshot factory to `prepare_runtime_kernel`.
    ///
    /// ### Why is this bad?
    /// Pre-expansion source scanning can be bypassed with aliases, re-exported macros, generated
    /// modules, or test-only path aliases. Compiler-resolved HIR observes the code that is actually
    /// compiled and makes those syntax rewrites irrelevant.
    ///
    /// ### Known problems
    /// The lint is a compile-time Medium gate and intentionally runs only when the target crate
    /// name is `runtime`. Exact source catalog/cardinality and operator-capability caller wiring
    /// remain independently enforced by xtask inventories.
    pub RSS_RUNTIME_ENV_FUNNEL,
    Warn,
    "runtime ambient environment access must pass through the closed process snapshot or exact operator grant readers"
}

rustc_session::impl_lint_pass!(PreExpansionPass => [RSS_RUNTIME_ENV_FUNNEL]);
rustc_session::impl_lint_pass!(LatePass => [RSS_RUNTIME_ENV_FUNNEL]);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[RSS_RUNTIME_ENV_FUNNEL]);
    lint_store.register_pre_expansion_pass(|| Box::new(PreExpansionPass));
    lint_store.register_late_pass(|_| Box::new(LatePass::default()));
}

impl EarlyLintPass for PreExpansionPass {
    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &MacCall) {
        if cx.sess().opts.crate_name.as_deref() != Some(RUNTIME_CRATE) {
            return;
        }
        let Some(name) = mac.path.segments.last().map(|segment| segment.ident.name) else {
            return;
        };
        if !COMPILE_ENV_MACROS.contains(&name.as_str()) {
            return;
        }
        span_lint_and_then(
            cx,
            RSS_RUNTIME_ENV_FUNNEL,
            mac.span(),
            "runtime 生产代码不得通过 compile-time macro 读取环境或包含外部源码",
            |diag| {
                diag.help(
                    "`env!` / `option_env!` / `include!` 会绕过 process snapshot；把值加入 closed runtime catalog 并从 SnapshotConfig 消费",
                );
            },
        );
    }
}

impl<'tcx> LateLintPass<'tcx> for LatePass {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if !governs_runtime(cx) {
            return;
        }

        self.check_compile_env_expansion(cx, expr);

        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::Fn | DefKind::AssocFn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };

        if let Some(reader) = std_env_reader(cx, did) {
            if !canonical_env_read_is_allowed(cx, expr, reader) {
                emit(
                    cx,
                    expr.hir_id,
                    expr.span.source_callsite(),
                    "runtime 不得在封闭配置入口之外读取进程环境",
                    "把 serving/runtime 配置加入 closed catalog 并从 SnapshotConfig 消费；operator grant 仅保留四个带 typed capability 的精确 reader",
                );
            }
            return;
        }

        if is_process_snapshot_factory(cx, did)
            && !is_top_level_owner(cx, expr.hir_id, "prepare_runtime_kernel")
        {
            emit(
                cx,
                expr.hir_id,
                expr.span.source_callsite(),
                "process runtime snapshot factory 仅可由 `prepare_runtime_kernel` 引用",
                "从 PreparedRuntimeInputs / ServingRuntimeInputs / OperatorRuntimeInputs 传递已有 snapshot capability，不得再次 capture",
            );
        }
    }
}

impl LatePass {
    fn check_compile_env_expansion(&mut self, cx: &LateContext<'_>, expr: &Expr<'_>) {
        let Some(expansion) = macro_backtrace(expr.span).find(|call| {
            let name = cx.tcx.item_name(call.def_id);
            let crate_name = cx.tcx.crate_name(call.def_id.krate);
            COMPILE_ENV_MACROS.contains(&name.as_str())
                && matches!(crate_name.as_str(), "std" | "core")
        }) else {
            return;
        };
        // Direct source invocations were diagnosed by PreExpansionPass. HIR is responsible for
        // nested/re-exported macro expansion, where the governed builtin callsite itself originated
        // in another macro expansion.
        if !expansion.span.from_expansion() {
            return;
        }
        if !self.reported_expansions.insert(expansion.expn) {
            return;
        }
        emit(
            cx,
            expr.hir_id,
            expansion.span.source_callsite(),
            "runtime 生产代码不得通过 compile-time macro 读取环境或包含外部源码",
            "`env!` / `option_env!` / `include!` 会绕过 process snapshot；把值加入 closed runtime catalog 并从 SnapshotConfig 消费",
        );
    }
}

fn governs_runtime(cx: &LateContext<'_>) -> bool {
    cx.tcx.crate_name(LOCAL_CRATE).as_str() == RUNTIME_CRATE
}

fn std_env_reader(cx: &LateContext<'_>, did: DefId) -> Option<&'static str> {
    if cx.tcx.crate_name(did.krate).as_str() != "std" {
        return None;
    }
    let name = cx.tcx.item_name(did);
    let name = ENV_READERS
        .iter()
        .copied()
        .find(|candidate| *candidate == name.as_str())?;
    let path = cx.tcx.def_path_str(did);
    path.ends_with(&format!("::env::{name}")).then_some(name)
}

fn canonical_env_read_is_allowed(cx: &LateContext<'_>, expr: &Expr<'_>, reader: &str) -> bool {
    if expr.span.from_expansion() || !is_direct_call_callee(cx, expr) {
        return false;
    }
    (reader == "var_os" && is_env_config_source_read(cx, expr.hir_id))
        || (reader == "var"
            && OPERATOR_GRANT_READERS
                .iter()
                .any(|(owner, path)| is_exact_local_owner(cx, expr.hir_id, owner, path)))
}

fn is_direct_call_callee(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    matches!(
        cx.tcx.parent_hir_node(expr.hir_id),
        Node::Expr(parent)
            if matches!(
                parent.kind,
                ExprKind::Call(callee, _) if callee.hir_id == expr.hir_id
            )
    )
}

fn is_env_config_source_read(cx: &LateContext<'_>, hir_id: HirId) -> bool {
    let owner = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    if cx.tcx.item_name(owner).as_str() != "read" {
        return false;
    }
    let impl_did = cx.tcx.parent(owner);
    if !matches!(cx.tcx.def_kind(impl_did), DefKind::Impl { .. }) {
        return false;
    }
    let self_ty = cx.tcx.type_of(impl_did).instantiate_identity();
    let Some(self_adt) = self_ty.ty_adt_def() else {
        return false;
    };
    if !is_exact_local_path(
        &cx.tcx.def_path_str(self_adt.did()),
        "config::EnvConfigSource",
    ) {
        return false;
    }
    let trait_ref = cx.tcx.impl_trait_ref(impl_did).instantiate_identity();
    is_exact_local_path(
        &cx.tcx.def_path_str(trait_ref.def_id),
        "config::RuntimeConfigSource",
    )
}

fn is_process_snapshot_factory(cx: &LateContext<'_>, did: DefId) -> bool {
    if did.krate != LOCAL_CRATE || cx.tcx.item_name(did).as_str() != "capture_process_snapshot" {
        return false;
    }
    let impl_did = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(impl_did), DefKind::Impl { .. }) {
        return false;
    }
    cx.tcx
        .type_of(impl_did)
        .instantiate_identity()
        .ty_adt_def()
        .is_some_and(|adt| {
            is_exact_local_path(
                &cx.tcx.def_path_str(adt.did()),
                "config::RuntimeConfigSnapshot",
            )
        })
}

fn is_exact_local_path(actual: &str, expected_without_crate: &str) -> bool {
    actual == expected_without_crate
        || actual
            .strip_prefix("runtime::")
            .is_some_and(|path| path == expected_without_crate)
}

fn is_top_level_owner(cx: &LateContext<'_>, hir_id: HirId, expected: &str) -> bool {
    let owner = cx.tcx.hir_get_parent_item(hir_id).def_id;
    cx.tcx.item_name(owner).as_str() == expected && cx.tcx.local_parent(owner) == CRATE_DEF_ID
}

fn is_exact_local_owner(
    cx: &LateContext<'_>,
    hir_id: HirId,
    expected_name: &str,
    expected_path: &str,
) -> bool {
    let owner = cx.tcx.hir_get_parent_item(hir_id).to_def_id();
    cx.tcx.item_name(owner).as_str() == expected_name
        && is_exact_local_path(&cx.tcx.def_path_str(owner), expected_path)
}

fn emit(
    cx: &LateContext<'_>,
    hir_id: HirId,
    span: Span,
    message: &'static str,
    help: &'static str,
) {
    span_lint_hir_and_then(cx, RSS_RUNTIME_ENV_FUNNEL, hir_id, span, message, |diag| {
        diag.help(help);
    });
}

#[test]
fn ui_runtime() {
    // The compile flag assigns crate name `runtime` and exercises the same crate-identity
    // activation branch as the real assembly.
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
