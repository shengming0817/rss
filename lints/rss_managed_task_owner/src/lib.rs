#![feature(rustc_private)]
//! Type-aware lifecycle ownership guard.
//!
//! INVARIANT: MANAGED-TASK-OWNER-01 { level = "Medium", exec = "check", source = "dylint" }

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::collections::HashSet;

use clippy_utils::diagnostics::span_lint_hir_and_then;
use rustc_hir::{Item, ItemKind};
use rustc_lint::{LateContext, LateLintPass, LintContext as _};
use rustc_middle::ty::{self, Ty};
use rustc_span::def_id::DefId;

dylint_linting::declare_late_lint! {
    /// Rejects a `ManagedResource` whose resolved field graph stores a Tokio `JoinHandle`.
    /// Long-lived tasks must be owned by `diport::ManagedTask`; aliases and newtype wrappers do
    /// not bypass the check.
    pub RSS_MANAGED_TASK_OWNER,
    Warn,
    "ManagedResource stores a raw Tokio JoinHandle instead of diport::ManagedTask"
}

impl<'tcx> LateLintPass<'tcx> for RssManagedTaskOwner {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        let Some(of_trait) = impl_.of_trait else {
            return;
        };
        let Some(trait_did) = of_trait.trait_ref.trait_def_id() else {
            return;
        };
        if !is_managed_resource_trait(cx, trait_did) {
            return;
        }

        let self_ty = cx.tcx.type_of(item.owner_id).instantiate_identity();
        if is_canonical_managed_task(cx, self_ty) {
            return;
        }
        let mut visited = HashSet::new();
        if contains_join_handle(cx, self_ty, &mut visited) {
            span_lint_hir_and_then(
                cx,
                RSS_MANAGED_TASK_OWNER,
                item.hir_id(),
                item.span,
                "ManagedResource owns a raw Tokio JoinHandle",
                |diag| {
                    diag.help("replace the stored handle/token/join state with diport::ManagedTask and expose only TaskStatus");
                },
            );
        }
    }
}

fn is_managed_resource_trait(cx: &LateContext<'_>, did: DefId) -> bool {
    cx.tcx.crate_name(did.krate).as_str() == "diport"
        && matches!(cx.tcx.item_name(did).as_str(), "ManagedResource" | "ManagedResourceLocal")
}

fn is_canonical_managed_task(cx: &LateContext<'_>, ty: Ty<'_>) -> bool {
    let ty::Adt(def, _) = ty.kind() else {
        return false;
    };
    let did = def.did();
    if cx.tcx.crate_name(did.krate).as_str() != "diport"
        || cx.tcx.item_name(did).as_str() != "ManagedTask"
    {
        return false;
    }
    matches!(
        cx.tcx.def_path_str(did).as_str(),
        "diport::ManagedTask"
            | "diport::managed_resource::ManagedTask"
            | "managed_resource::ManagedTask"
    )
}

fn has_local_source(cx: &LateContext<'_>, did: DefId) -> bool {
    if did.is_local() {
        return true;
    }
    let Some(path) = cx
        .sess()
        .source_map()
        .span_to_filename(cx.tcx.def_span(did))
        .into_local_path()
    else {
        return false;
    };
    let source = path.to_string_lossy();
    !source.contains("/.cargo/registry/")
        && !source.contains("/.cargo/git/")
        && !source.contains("/.rustup/toolchains/")
        && !source.starts_with("/rustc/")
        && !source.starts_with('<')
}

fn contains_join_handle<'tcx>(
    cx: &LateContext<'tcx>,
    ty: Ty<'tcx>,
    visited: &mut HashSet<Ty<'tcx>>,
) -> bool {
    let ty = cx.tcx.normalize_erasing_regions(cx.typing_env(), ty);
    if !visited.insert(ty) {
        return false;
    }
    match ty.kind() {
        ty::Adt(def, args) => {
            let did = def.did();
            if cx.tcx.crate_name(did.krate).as_str() == "tokio"
                && cx.tcx.item_name(did).as_str() == "JoinHandle"
            {
                return true;
            }
            if is_canonical_managed_task(cx, ty) {
                return false;
            }
            args.types()
                .any(|argument| contains_join_handle(cx, argument, visited))
                || (has_local_source(cx, did)
                    && def
                        .all_fields()
                        .any(|field| contains_join_handle(cx, field.ty(cx.tcx, args), visited)))
        }
        ty::Tuple(items) => items
            .iter()
            .any(|item| contains_join_handle(cx, item, visited)),
        ty::Array(item, _) | ty::Slice(item) | ty::Ref(_, item, _) | ty::RawPtr(item, _) => {
            contains_join_handle(cx, *item, visited)
        }
        _ => false,
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "rss_managed_task_owner_ui");
}
