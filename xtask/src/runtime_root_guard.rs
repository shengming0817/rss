//! Declarative runtime crate-root guard.
//!
//! INVARIANT: RUNTIME-ROOT-DECLARATIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::rejects_every_production_item_kind", anti_vacuity = "tests::workspace_runtime_root_is_declarative" } -- the runtime crate root contains only external module declarations and imports/re-exports. Executable lifecycle ownership lives in private modules and cannot drift back through functions, types, constants, inline modules, or macro expansion.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result};
use quote::ToTokens as _;
use syn::spanned::Spanned as _;

use crate::diagnostic::{Finding, GovernanceCheck, finding};

const ROOT_PATH: &str = "assemblies/runtime/src/lib.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    ExecutableRootItem,
    InlineRootModule,
    UnsafeDeclarationAttribute,
    PublicRootModule,
    GlobRootReexport,
    MissingLifecycleOwner,
    InvalidLifecycleFacade,
}

const LIFECYCLE_FACADE: [&str; 4] = [
    "prepare_runtime",
    "report_process_error",
    "run",
    "shutdown_runtime",
];

pub(crate) struct RuntimeRootGuard;

impl GovernanceCheck for RuntimeRootGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "runtime-root guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = crate::workspace_root()?;
        let findings = scan_workspace(&root)?;
        Ok((
            "runtime crate root is a declarative facade".to_owned(),
            findings,
        ))
    }
}

fn scan_workspace(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let path = root.join(ROOT_PATH);
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("runtime-root guard reads {}", path.display()))?;
    scan_source(&source)
}

fn scan_source(source: &str) -> Result<Vec<Finding<Rule>>> {
    let file = syn::parse_file(source).context("runtime-root guard parses runtime crate root")?;
    let mut findings = Vec::new();
    let mut lifecycle_owners = 0;
    let mut lifecycle_facade = BTreeSet::new();
    for item in file.items {
        for attribute in item_attrs(&item) {
            if !matches!(
                attribute
                    .path()
                    .get_ident()
                    .map(ToString::to_string)
                    .as_deref(),
                Some("cfg" | "doc" | "path")
            ) {
                findings.push(finding(
                    Rule::UnsafeDeclarationAttribute,
                    format!("{ROOT_PATH}:{}", attribute.span().start().line),
                    format!(
                        "runtime crate-root declarations reject attribute `{}` because it may expand executable items",
                        attribute.path().to_token_stream()
                    ),
                ));
            }
        }
        match &item {
            syn::Item::Use(item) if contains_use_glob(&item.tree) => findings.push(finding(
                Rule::GlobRootReexport,
                format!("{ROOT_PATH}:{}", item.span().start().line),
                "runtime crate root rejects glob imports/re-exports; façade edges must remain explicit",
            )),
            syn::Item::Use(item) => {
                if matches!(item.vis, syn::Visibility::Public(_)) && item.attrs.is_empty() {
                    collect_lifecycle_facade(&item.tree, &mut Vec::new(), &mut lifecycle_facade);
                }
            }
            syn::Item::Mod(module)
                if module.content.is_none()
                    && module.ident == "lifecycle"
                    && !matches!(module.vis, syn::Visibility::Inherited) => {
                        findings.push(finding(
                            Rule::PublicRootModule,
                            format!("{ROOT_PATH}:{}", module.span().start().line),
                            "runtime lifecycle owner must remain private behind explicit re-exports",
                        ));
                    }
            syn::Item::Mod(module)
                if module.content.is_none()
                    && module.ident == "lifecycle"
                    && module.attrs.is_empty() =>
            {
                lifecycle_owners += 1;
            }
            syn::Item::Mod(module) if module.content.is_none() => {}
            syn::Item::Mod(module) => findings.push(finding(
                Rule::InlineRootModule,
                format!("{ROOT_PATH}:{}", module.ident),
                "runtime crate root must not contain inline modules",
            )),
            other => findings.push(finding(
                Rule::ExecutableRootItem,
                format!("{ROOT_PATH}:{}", other.span().start().line),
                format!(
                    "runtime crate root permits only external mod/use declarations; found {}",
                    item_kind(&other)
                ),
            )),
        }
    }
    if lifecycle_owners != 1 {
        findings.push(finding(
            Rule::MissingLifecycleOwner,
            ROOT_PATH,
            "runtime crate root requires one unconditional private `mod lifecycle;` owner",
        ));
    }
    let expected_facade = LIFECYCLE_FACADE
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if lifecycle_facade != expected_facade {
        findings.push(finding(
            Rule::InvalidLifecycleFacade,
            ROOT_PATH,
            format!(
                "runtime lifecycle public façade must re-export the canonical exact set; expected {expected_facade:?}, found {lifecycle_facade:?}"
            ),
        ));
    }
    Ok(findings)
}

fn collect_lifecycle_facade(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    exports: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_lifecycle_facade(&path.tree, prefix, exports);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let lifecycle_owner =
                prefix.as_slice() == ["lifecycle"] || prefix.as_slice() == ["crate", "lifecycle"];
            if lifecycle_owner {
                exports.insert(name.ident.to_string());
            }
        }
        syn::UseTree::Rename(rename) => {
            let lifecycle_owner =
                prefix.as_slice() == ["lifecycle"] || prefix.as_slice() == ["crate", "lifecycle"];
            if lifecycle_owner {
                exports.insert(rename.rename.to_string());
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_lifecycle_facade(item, prefix, exports);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn contains_use_glob(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Path(path) => contains_use_glob(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(contains_use_glob),
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) => false,
    }
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        _ => &[],
    }
}

fn item_kind(item: &syn::Item) -> &'static str {
    match item {
        syn::Item::Const(_) => "const",
        syn::Item::Enum(_) => "enum",
        syn::Item::Fn(_) => "fn",
        syn::Item::Impl(_) => "impl",
        syn::Item::Macro(_) => "macro",
        syn::Item::Static(_) => "static",
        syn::Item::Struct(_) => "struct",
        syn::Item::Trait(_) | syn::Item::TraitAlias(_) => "trait",
        syn::Item::Type(_) => "type",
        syn::Item::Union(_) => "union",
        _ => "unsupported item",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_ROOT: &str = r#"
mod lifecycle;
pub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};
"#;

    #[test]
    fn accepts_external_modules_imports_comments_and_formatting() -> Result<()> {
        let source = r#"
//! docs may grow freely.
#[cfg(test)]
mod tests;
mod lifecycle;
pub use crate::lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};
use lifecycle::prepare_runtime;
"#;
        assert!(scan_source(source)?.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_every_production_item_kind() -> Result<()> {
        let append_cases = [
            "fn run() {}",
            "struct Owner;",
            "enum State { Ready }",
            "trait Start {}",
            "type Alias = ();",
            "const VALUE: usize = 1;",
            "static VALUE: usize = 1;",
            "impl Owner {}",
            "mod inline { fn run() {} }",
            "include!(\"generated.rs\");",
            "extern crate alloc;",
            "#[inject] mod extra;",
            "#[cfg_attr(test, inject)] mod extra;",
            "pub use support::*;",
        ];
        for addition in append_cases {
            let source = format!("{CANONICAL_ROOT}\n{addition}");
            assert!(!scan_source(&source)?.is_empty(), "must reject `{source}`");
        }
        Ok(())
    }

    #[test]
    fn lifecycle_owner_and_facade_are_non_vacuous() -> Result<()> {
        let red_cases = [
            "pub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};",
            "mod lifecycle_owner;\npub use lifecycle_owner::{prepare_runtime, report_process_error, run, shutdown_runtime};",
            "pub mod lifecycle;\npub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};",
            "#[cfg(test)] mod lifecycle;\npub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};",
            "mod lifecycle;\npub use lifecycle::{prepare_runtime, report_process_error, run};",
            "mod lifecycle;\npub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime as shutdown};",
            "mod lifecycle;\n#[cfg(test)] pub use lifecycle::{prepare_runtime, report_process_error, run, shutdown_runtime};",
        ];
        for source in red_cases {
            assert!(!scan_source(source)?.is_empty(), "must reject `{source}`");
        }
        assert!(scan_source(CANONICAL_ROOT)?.is_empty());
        Ok(())
    }

    #[test]
    fn workspace_runtime_root_is_declarative() -> Result<()> {
        assert!(scan_workspace(&crate::workspace_root()?)?.is_empty());
        Ok(())
    }
}
