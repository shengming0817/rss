#![feature(rustc_private)]
//! `rss_raw_credential_callsite` closes the untrusted-token boxing boundary.
//!
//! INVARIANT: RAW-CREDENTIAL-AUTHN-FUNNEL-01 { level = "Medium", exec = "check", source = "dylint" }
//!
//! `RawCredential` carries the token profile selected by a trusted listener. If arbitrary
//! production crates can call a constructor, an untrusted token can be relabelled before the typed
//! provider sees it. The only production callsite is therefore the public authn verification
//! funnel. Tests must enter through that funnel instead of widening this allowlist.
//!
//! Upstream is Hard: private `RawCredential` fields prevent struct-literal forgery. This Medium
//! callsite allowlist closes the remaining public-constructor path. Constructor discovery is
//! structural: every inherent `diport::RawCredential` associated function whose return type is
//! `RawCredential` is guarded, including function-item aliases and fn-pointer coercions. Adding or
//! renaming a constructor therefore cannot silently escape the lint.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::{DefId, LOCAL_CRATE};
use rustc_hir::{Expr, ExprKind, HirId};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// The sole production funnel allowed to label raw token bytes with a trusted profile.
const ALLOWED_CALLER_CRATES: &[&str] = &["authn"];

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// Rejects any path reference to an inherent `diport::RawCredential` associated function that
    /// returns `RawCredential` outside the `authn` crate.
    ///
    /// ### Why is this bad?
    /// A constructor chooses the trusted token profile before parsing. Calling it outside the
    /// authn funnel permits a caller to relabel untrusted token bytes and weakens the typed
    /// listener/provider trust chain.
    ///
    /// ### Example
    /// ```ignore
    /// let credential = diport::RawCredential::rss_access(untrusted);
    /// ```
    /// Use the profile-specific public authn verification funnel instead.
    pub RSS_RAW_CREDENTIAL_CALLSITE,
    Warn,
    "RawCredential construction is restricted to the typed authn verification funnel"
}

impl<'tcx> LateLintPass<'tcx> for RssRawCredentialCallsite {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Path(ref qpath) = expr.kind else {
            return;
        };
        let Res::Def(DefKind::AssocFn | DefKind::Fn, did) = cx.qpath_res(qpath, expr.hir_id) else {
            return;
        };
        if is_raw_credential_constructor(cx, did) && !caller_is_allowed(cx) {
            emit(cx, expr.hir_id, expr.span);
        }
    }
}

fn is_raw_credential_constructor(cx: &LateContext<'_>, did: DefId) -> bool {
    if cx.tcx.crate_name(did.krate).as_str() != "diport" {
        return false;
    }
    let parent = cx.tcx.parent(did);
    if !matches!(cx.tcx.def_kind(parent), DefKind::Impl { .. })
        || cx.tcx.trait_item_of(did).is_some()
        || !is_raw_credential_type(cx, cx.tcx.type_of(parent).skip_binder())
    {
        return false;
    }

    let signature = cx.tcx.fn_sig(did).instantiate_identity().skip_binder();
    is_raw_credential_type(cx, signature.output())
}

fn is_raw_credential_type(cx: &LateContext<'_>, ty: rustc_middle::ty::Ty<'_>) -> bool {
    ty.ty_adt_def().is_some_and(|adt| {
        cx.tcx.crate_name(adt.did().krate).as_str() == "diport"
            && cx.tcx.item_name(adt.did()).as_str() == "RawCredential"
    })
}

fn caller_is_allowed(cx: &LateContext<'_>) -> bool {
    ALLOWED_CALLER_CRATES.contains(&cx.tcx.crate_name(LOCAL_CRATE).as_str())
}

fn emit(cx: &LateContext<'_>, hir_id: HirId, span: Span) {
    span_lint_hir_and_then(
        cx,
        RSS_RAW_CREDENTIAL_CALLSITE,
        hir_id,
        span,
        "RawCredential constructors may only be referenced by the typed authn verification funnel",
        |diag| {
            diag.help(
                "call `authn::verify_rss_access`, `authn::verify_federated_access`, or `authn::verify_service_token`; do not label raw token bytes in this crate",
            );
        },
    );
}

#[test]
fn ui_disallowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "raw_credential_callsite_ui");
}

#[test]
fn ui_authn_allowed() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "authn");
}
