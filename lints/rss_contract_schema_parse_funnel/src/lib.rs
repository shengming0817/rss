#![feature(rustc_private)]
//! Compiler-resolved backstop for the contract schema parse-once funnel.
//!
//! INVARIANT: CONTRACT-SCHEMA-PARSER-HIR-01 { level = "Medium", exec = "check", source = "dylint", synthetic_red = "ui_xtask", anti_vacuity = "ui_xtask" }

extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use std::collections::{HashMap, HashSet, VecDeque};

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_hir::intravisit::FnKind;
use rustc_hir::{Body, Expr, ExprKind, FnDecl, HirId};
use rustc_lint::{LateContext, LateLintPass, LintStore};
use rustc_middle::ty::Ty;
use rustc_session::Session;
use rustc_span::Span;

const XTASK_CRATE: &str = "xtask";
const GOVERNED_TYPES: &[&str] = &[
    "contract::governance::GovernedContract",
    "repository_contract::RepositoryContract",
    "repository_contract::DeclaredSchema",
    "repository_contract::ResolvedSchema",
];
const ALLOWED_PARSER_OWNERS: &[&str] = &[
    "codegen::tuple_schema",
    "contract::breaking::base_contract_side",
];

#[derive(Default)]
struct ParseFunnelPass {
    roots: HashSet<LocalDefId>,
    edges: HashMap<LocalDefId, HashSet<LocalDefId>>,
    parser_sites: Vec<ParserSite>,
    parser_hir_ids: HashSet<HirId>,
}

#[derive(Clone, Copy)]
struct ParserSite {
    owner: LocalDefId,
    hir_id: HirId,
    span: Span,
}

dylint_linting::dylint_library!();

rustc_session::declare_lint! {
    /// ### What it does
    /// Rejects compiler-resolved serde JSON parsers in the transitive crate-local call graph of a
    /// promoted working-contract/schema consumer.
    ///
    /// ### Why is this bad?
    /// A second parser can bypass the immutable parse-once repository snapshot and make validation,
    /// codegen, breaking checks, and locks observe different source bytes.
    ///
    /// ### Known problems
    /// This Medium backstop follows statically resolved crate-local calls and closures. It does not
    /// claim filesystem capability isolation or prevent deliberately hard-coded external parsing.
    /// The Hard boundary is limited to invalid inspection state being unable to promote.
    pub RSS_CONTRACT_SCHEMA_PARSE_FUNNEL,
    Warn,
    "promoted working-contract consumers must not parse JSON again"
}

rustc_session::impl_lint_pass!(ParseFunnelPass => [RSS_CONTRACT_SCHEMA_PARSE_FUNNEL]);

#[unsafe(no_mangle)]
pub fn register_lints(sess: &Session, lint_store: &mut LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[RSS_CONTRACT_SCHEMA_PARSE_FUNNEL]);
    lint_store.register_late_pass(|_| Box::new(ParseFunnelPass::default()));
}

impl<'tcx> LateLintPass<'tcx> for ParseFunnelPass {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _declaration: &'tcx FnDecl<'tcx>,
        _body: &'tcx Body<'tcx>,
        _span: Span,
        def_id: LocalDefId,
    ) {
        if !governs_xtask(cx) || matches!(kind, FnKind::Closure) {
            return;
        }
        let signature = cx.tcx.fn_sig(def_id).instantiate_identity();
        let signature = cx.tcx.instantiate_bound_regions_with_erased(signature);
        if signature
            .inputs()
            .iter()
            .copied()
            .chain(std::iter::once(signature.output()))
            .any(|ty| type_contains_governed(cx, ty))
        {
            self.roots.insert(def_id);
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        if !governs_xtask(cx) {
            return;
        }

        let owner = expr.hir_id.owner.def_id;
        if type_contains_governed(cx, cx.typeck_results().expr_ty_adjusted(expr)) {
            self.roots.insert(owner);
        }

        match expr.kind {
            ExprKind::Call(callee, _) => {
                if let Some(did) = expression_def_id(cx, callee) {
                    self.record_call_or_parser(cx, owner, callee.hir_id, callee.span, did);
                }
            }
            ExprKind::MethodCall(..) => {
                if let Some(did) = cx.typeck_results().type_dependent_def_id(expr.hir_id) {
                    self.record_call_or_parser(cx, owner, expr.hir_id, expr.span, did);
                }
            }
            ExprKind::Closure(closure) => {
                self.edges.entry(owner).or_default().insert(closure.def_id);
            }
            ExprKind::Path(ref qpath) => {
                if let Res::Def(DefKind::Fn | DefKind::AssocFn, did) =
                    cx.qpath_res(qpath, expr.hir_id)
                    && is_json_parser(cx, did)
                {
                    self.record_parser(owner, expr.hir_id, expr.span);
                }
            }
            _ => {}
        }
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        if !governs_xtask(cx) {
            return;
        }
        let mut reachable = self.roots.clone();
        let mut queue = self.roots.iter().copied().collect::<VecDeque<_>>();
        while let Some(owner) = queue.pop_front() {
            if let Some(targets) = self.edges.get(&owner) {
                for target in targets {
                    if reachable.insert(*target) {
                        queue.push_back(*target);
                    }
                }
            }
        }

        for site in &self.parser_sites {
            if !reachable.contains(&site.owner) || parser_owner_allowed(cx, site.owner) {
                continue;
            }
            span_lint_hir_and_then(
                cx,
                RSS_CONTRACT_SCHEMA_PARSE_FUNNEL,
                site.hir_id,
                site.span.source_callsite(),
                "promoted contract/schema consumer 的调用闭包禁止重新解析 working repository JSON",
                |diag| {
                    diag.help(
                        "消费 DeclaredSchema/ResolvedSchema；working repository bytes 只能由私有 inspection parser 读取一次",
                    );
                },
            );
        }
    }
}

impl ParseFunnelPass {
    fn record_call_or_parser(
        &mut self,
        cx: &LateContext<'_>,
        owner: LocalDefId,
        hir_id: HirId,
        span: Span,
        did: DefId,
    ) {
        if let Some(local) = did.as_local() {
            self.edges.entry(owner).or_default().insert(local);
        }
        if is_json_parser(cx, did) {
            self.record_parser(owner, hir_id, span);
        }
    }

    fn record_parser(&mut self, owner: LocalDefId, hir_id: HirId, span: Span) {
        if self.parser_hir_ids.insert(hir_id) {
            self.parser_sites.push(ParserSite {
                owner,
                hir_id,
                span,
            });
        }
    }
}

fn governs_xtask(cx: &LateContext<'_>) -> bool {
    cx.tcx.crate_name(LOCAL_CRATE).as_str() == XTASK_CRATE
}

fn expression_def_id(cx: &LateContext<'_>, expr: &Expr<'_>) -> Option<DefId> {
    match expr.kind {
        ExprKind::Path(ref qpath) => match cx.qpath_res(qpath, expr.hir_id) {
            Res::Def(DefKind::Fn | DefKind::AssocFn, did) => Some(did),
            _ => None,
        },
        _ => cx.typeck_results().type_dependent_def_id(expr.hir_id),
    }
}

fn type_contains_governed(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    ty.walk().filter_map(|arg| arg.as_type()).any(|nested| {
        nested.ty_adt_def().is_some_and(|adt| {
            let path = cx.tcx.def_path_str(adt.did());
            GOVERNED_TYPES.iter().any(|target| path.ends_with(target))
        })
    })
}

fn is_json_parser(cx: &LateContext<'_>, did: DefId) -> bool {
    let path = cx.tcx.def_path_str(did);
    let canonical_crate = cx.tcx.crate_name(did.krate).as_str() == "serde_json";
    let local_ui_probe = did.krate == LOCAL_CRATE && path.contains("serde_json::de::");
    if !canonical_crate && !local_ui_probe {
        return false;
    }
    matches!(
        cx.tcx.item_name(did).as_str(),
        "from_slice" | "from_str" | "from_reader"
    ) && path.contains("::de::")
}

fn parser_owner_allowed(cx: &LateContext<'_>, owner: LocalDefId) -> bool {
    let path = cx.tcx.def_path_str(owner.to_def_id());
    ALLOWED_PARSER_OWNERS
        .iter()
        .any(|allowed| path.ends_with(allowed))
}

#[test]
fn ui_xtask() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
