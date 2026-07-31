//! Contract repository source-funnel structural guard.
//!
//! The governance IR is the sole production owner of repository loading. This guard parses Rust
//! source instead of matching text so test-only fixtures remain free to construct raw repository
//! inputs while production code cannot grow a second loader or retain the deprecated wrapper.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::Visit;

const GOVERNANCE_OWNER: &str = "xtask/src/contract/governance.rs";
const REPOSITORY_OWNER: &str = "crates/assembly-schema/src/repository_contract.rs";
const ASSEMBLY_LOCK_OWNER: &str = "crates/assembly-schema/src/lock.rs";
const CONTRACT_MODULE: &str = "xtask/src/contract/mod.rs";
const WORKSPACE_SOURCE_ROOTS: &[&str] = &[
    "xtask",
    "crates",
    "generated",
    "adapters",
    "assemblies",
    "composition",
    "bins",
    "journeys",
    "examples",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Violation {
    file: String,
    line: usize,
    detail: String,
}

impl Violation {
    fn render(&self) -> String {
        format!("{}:{}: {}", self.file, self.line, self.detail)
    }
}

pub(crate) fn validate_source_funnel(root: &Path) -> Result<()> {
    let violations = workspace_violations(root)?;
    if !violations.is_empty() {
        bail!(
            "contract governance source funnel 存在 production 旁路:\n{}",
            violations
                .iter()
                .map(Violation::render)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(())
}

fn workspace_violations(root: &Path) -> Result<Vec<Violation>> {
    let mut files = Vec::new();
    for source_root in WORKSPACE_SOURCE_ROOTS {
        let source_root = root.join(source_root);
        if source_root.is_dir() {
            collect_rust_sources(&source_root, &mut files)?;
        }
    }
    files.retain(|path| is_production_rust_source(root, path));
    files.sort();

    let owner = root.join(GOVERNANCE_OWNER);
    let repository_owner = root.join(REPOSITORY_OWNER);
    let assembly_lock_owner = root.join(ASSEMBLY_LOCK_OWNER);
    let contract_module = root.join(CONTRACT_MODULE);
    let mut violations = Vec::new();
    for path in files
        .into_iter()
        .filter(|path| path != &owner && path != &repository_owner && path != &assembly_lock_owner)
    {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 contract governance source {} 失败", path.display()))?;
        let label = relative_label(root, &path);
        violations.extend(
            source_violations(&source, path == contract_module)
                .with_context(|| format!("解析 contract governance source {label} 失败"))?
                .into_iter()
                .map(|local| Violation {
                    file: label.clone(),
                    line: local.line,
                    detail: local.detail,
                }),
        );
    }
    violations.sort();
    violations.dedup();
    Ok(violations)
}

fn is_production_rust_source(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let components = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();
    path.file_name().is_some_and(|name| name == "build.rs")
        || components.iter().any(|component| *component == "src")
}

fn collect_rust_sources(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(directory)
        .with_context(|| format!("检查 xtask source 目录 {} 失败", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("xtask source 根必须是无符号链接的真实目录");
    }

    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("读取 xtask source 目录 {} 失败", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("检查 xtask source {} 失败", path.display()))?;
        if file_type.is_symlink() {
            bail!("xtask source tree 禁止符号链接: {}", path.display());
        }
        if file_type.is_dir() {
            collect_rust_sources(&path, output)?;
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            output.push(path);
        }
    }
    Ok(())
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalViolation {
    line: usize,
    detail: String,
}

fn source_violations(source: &str, contract_module: bool) -> Result<Vec<LocalViolation>> {
    let syntax = syn::parse_file(source)?;
    let mut aliases = SourceAliases::default();
    AliasCollector {
        aliases: &mut aliases,
    }
    .visit_file(&syntax);
    aliases.resolve();
    let mut visitor = SourceVisitor {
        aliases: &aliases,
        contract_module,
        violations: Vec::new(),
    };
    visitor.visit_file(&syntax);
    Ok(visitor.violations)
}

#[derive(Default)]
struct SourceAliases {
    paths: BTreeMap<String, Vec<String>>,
    repository_loaders: BTreeSet<String>,
    repository_modules: BTreeSet<String>,
    repository_test_builders: BTreeSet<String>,
    contract_discoverers: BTreeSet<String>,
    contract_modules: BTreeSet<String>,
}

struct AliasCollector<'a> {
    aliases: &'a mut SourceAliases,
}

impl<'ast> Visit<'ast> for AliasCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if attrs_require_test(item_attrs(item)) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if attrs_require_test(impl_item_attrs(item)) {
            return;
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if attrs_require_test(trait_item_attrs(item)) {
            return;
        }
        syn::visit::visit_trait_item(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_aliases(&item.tree, &mut Vec::new(), self.aliases);
    }
}

fn collect_use_aliases(tree: &syn::UseTree, prefix: &mut Vec<String>, aliases: &mut SourceAliases) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut source = prefix.clone();
            source.push(name.ident.to_string());
            record_alias(&source, name.ident.to_string(), aliases);
        }
        syn::UseTree::Rename(rename) => {
            let mut source = prefix.clone();
            source.push(rename.ident.to_string());
            record_alias(&source, rename.rename.to_string(), aliases);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_aliases(tree, prefix, aliases);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn record_alias(source: &[String], alias: String, aliases: &mut SourceAliases) {
    let normalized = source
        .iter()
        .filter(|segment| segment.as_str() != "self")
        .cloned()
        .collect::<Vec<_>>();
    aliases.paths.insert(alias, normalized);
}

impl SourceAliases {
    fn resolve(&mut self) {
        for (alias, source) in self.paths.clone() {
            let normalized = self.expand(&source);
            let names = normalized.iter().map(String::as_str).collect::<Vec<_>>();
            if names.ends_with(&[
                "assembly_schema",
                "repository_contract",
                "load_contract_repository",
            ]) {
                self.repository_loaders.insert(alias.clone());
            } else if names.ends_with(&[
                "assembly_schema",
                "repository_contract",
                "RepositoryContractTestBuilder",
            ]) || names.ends_with(&["assembly_schema", "RepositoryContractTestBuilder"])
            {
                self.repository_test_builders.insert(alias.clone());
            } else if names.ends_with(&["assembly_schema", "repository_contract"]) {
                self.repository_modules.insert(alias.clone());
            }

            if names.ends_with(&["crate", "contract", "discover"]) {
                self.contract_discoverers.insert(alias);
            } else if names.ends_with(&["crate", "contract"]) {
                self.contract_modules.insert(alias);
            }
        }
    }

    fn expand(&self, source: &[String]) -> Vec<String> {
        let mut expanded = source.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(first) = expanded.first().cloned() {
            if !seen.insert(first.clone()) {
                break;
            }
            let Some(prefix) = self.paths.get(&first) else {
                break;
            };
            expanded.splice(0..1, prefix.iter().cloned());
        }
        expanded
    }
}

struct SourceVisitor<'a> {
    aliases: &'a SourceAliases,
    contract_module: bool,
    violations: Vec<LocalViolation>,
}

impl SourceVisitor<'_> {
    fn inspect_path(&mut self, path: &syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if is_repository_loader(&segments, self.aliases) {
            self.violations.push(LocalViolation {
                line: path.span().start().line,
                detail: format!(
                    "禁止绕过 ContractGovernanceIr 直接引用 repository loader `{}`",
                    segments.join("::")
                ),
            });
        }
        if is_contract_discover(&segments, self.aliases) {
            self.violations.push(LocalViolation {
                line: path.span().start().line,
                detail: format!(
                    "禁止调用已废弃的 crate::contract::discover `{}`",
                    segments.join("::")
                ),
            });
        }
        if is_repository_test_builder(&segments, self.aliases) {
            self.violations.push(LocalViolation {
                line: path.span().start().line,
                detail: format!(
                    "RepositoryContract test seam 仅允许 #[cfg(test)] item 使用 `{}`",
                    segments.join("::")
                ),
            });
        }
    }

    fn inspect_macro(&mut self, mac: &syn::Macro) {
        let mut identifiers = Vec::new();
        collect_token_identifiers(mac.tokens.clone(), &mut identifiers);
        if identifiers.iter().any(|identifier| {
            matches!(
                identifier.as_str(),
                "load_contract_repository" | "RepositoryContractTestBuilder"
            ) || self.aliases.repository_loaders.contains(identifier)
                || self.aliases.repository_test_builders.contains(identifier)
                || self.aliases.contract_discoverers.contains(identifier)
        }) {
            self.violations.push(LocalViolation {
                line: mac.span().start().line,
                detail: "macro token stream references a forbidden contract repository source seam"
                    .to_owned(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for SourceVisitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if attrs_require_test(item_attrs(item)) {
            return;
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if attrs_require_test(impl_item_attrs(item)) {
            return;
        }
        syn::visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if attrs_require_test(trait_item_attrs(item)) {
            return;
        }
        syn::visit::visit_trait_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.contract_module && item.sig.ident == "discover" {
            self.violations.push(LocalViolation {
                line: item.sig.ident.span().start().line,
                detail: "禁止保留 crate::contract::discover production wrapper".to_owned(),
            });
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        self.inspect_path(&expression.path);
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut local = SourceAliases::default();
        local.paths.extend(self.aliases.paths.clone());
        collect_use_aliases(&item.tree, &mut Vec::new(), &mut local);
        local.resolve();
        if !local.repository_loaders.is_empty()
            || !local.repository_test_builders.is_empty()
            || !local.contract_discoverers.is_empty()
        {
            self.violations.push(LocalViolation {
                line: item.span().start().line,
                detail:
                    "production use/re-export names a forbidden contract repository source seam"
                        .to_owned(),
            });
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.inspect_macro(mac);
    }
}

fn collect_token_identifiers(tokens: proc_macro2::TokenStream, output: &mut Vec<String>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Ident(identifier) => output.push(identifier.to_string()),
            proc_macro2::TokenTree::Group(group) => {
                collect_token_identifiers(group.stream(), output);
            }
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
        }
    }
}

fn is_repository_loader(segments: &[String], aliases: &SourceAliases) -> bool {
    let names = segments.iter().map(String::as_str).collect::<Vec<_>>();
    names
        .last()
        .is_some_and(|name| name == &"load_contract_repository")
        || matches!(names.as_slice(), [alias] if aliases.repository_loaders.contains(*alias))
        || matches!(names.as_slice(), [module, "load_contract_repository"] if aliases.repository_modules.contains(*module))
}

fn is_contract_discover(segments: &[String], aliases: &SourceAliases) -> bool {
    let names = segments.iter().map(String::as_str).collect::<Vec<_>>();
    matches!(names.as_slice(), [alias] if aliases.contract_discoverers.contains(*alias))
        || matches!(names.as_slice(), [module, "discover"] if aliases.contract_modules.contains(*module))
        || matches!(names.as_slice(), ["crate", "contract", "discover"])
        || (names.ends_with(&["contract", "discover"])
            && names
                .first()
                .is_some_and(|prefix| matches!(*prefix, "crate" | "self" | "super")))
}

fn is_repository_test_builder(segments: &[String], aliases: &SourceAliases) -> bool {
    let names = segments.iter().map(String::as_str).collect::<Vec<_>>();
    names
        .windows(2)
        .any(|window| window == ["RepositoryContractTestBuilder", "new"])
        || matches!(names.as_slice(), [alias, "new"] if aliases.repository_test_builders.contains(*alias))
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn impl_item_attrs(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn trait_item_attrs(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn attrs_require_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(attribute_requires_test)
}

fn attribute_requires_test(attribute: &syn::Attribute) -> bool {
    if attribute.path().is_ident("test") {
        return true;
    }
    let syn::Meta::List(cfg) = &attribute.meta else {
        return false;
    };
    if !cfg.path.is_ident("cfg") {
        return false;
    }
    syn::parse2::<syn::Meta>(cfg.tokens.clone()).is_ok_and(|meta| meta_requires_test(&meta))
}

fn meta_requires_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser as _;

    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let parser = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
            let Ok(nested) = parser.parse2(list.tokens.clone()) else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(meta_requires_test)
            } else {
                !nested.is_empty() && nested.iter().all(meta_requires_test)
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_funnel_rejects_parallel_repository_loaders() -> Result<()> {
        let violations = source_violations(
            r#"
                use assembly_schema::repository_contract::{
                    load_contract_repository as raw_load,
                    RepositoryContractTestBuilder as FixtureBuilder,
                };
                use crate::contract as contracts;

                fn direct(root: &std::path::Path) {
                    let _ = assembly_schema::repository_contract::load_contract_repository(root);
                    let _ = raw_load(root);
                    let _ = crate::contract::discover(root);
                    let _ = contracts::discover(root);
                    let _ = FixtureBuilder::new(manifest, root.to_owned());
                }

                #[cfg(test)]
                mod fixtures {
                    fn allowed(root: &std::path::Path) {
                        let _ = assembly_schema::repository_contract::load_contract_repository(root);
                        let _ = crate::contract::discover(root);
                        let _ = assembly_schema::repository_contract::RepositoryContractTestBuilder::new(manifest, root.to_owned());
                    }
                }
            "#,
            false,
        )?;
        assert_eq!(violations.len(), 7, "synthetic red: {violations:?}");
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.detail.contains("repository loader"))
                .count(),
            2
        );
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.detail.contains("test seam"))
                .count(),
            1
        );
        assert_eq!(
            violations
                .iter()
                .filter(|violation| violation.detail.contains("contract::discover"))
                .count(),
            2
        );

        let wrapper = source_violations(
            "pub(crate) fn discover(root: &std::path::Path) { let _ = root; }",
            true,
        )?;
        assert_eq!(wrapper.len(), 1, "wrapper synthetic red: {wrapper:?}");
        assert!(wrapper[0].detail.contains("production wrapper"));
        Ok(())
    }

    #[test]
    fn transitive_aliases_and_macro_tokens_fail_closed() -> Result<()> {
        let violations = source_violations(
            r#"
                use assembly_schema as schema;
                use schema::repository_contract as repo;
                use repo::load_contract_repository as raw;

                fn transitive(root: &std::path::Path) { let _ = raw(root); }

                macro_rules! hidden {
                    ($root:expr) => { assembly_schema::repository_contract::load_contract_repository($root) };
                }
                fn macro_call(root: &std::path::Path) {
                    let _ = passthrough!(assembly_schema::repository_contract::load_contract_repository(root));
                }
            "#,
            false,
        )?;
        assert!(
            violations
                .iter()
                .any(|violation| violation.detail.contains("`raw`")),
            "transitive alias escaped: {violations:?}"
        );
        assert!(
            violations
                .iter()
                .filter(|violation| violation.detail.contains("macro token"))
                .count()
                >= 2,
            "macro carrier escaped: {violations:?}"
        );
        Ok(())
    }

    #[test]
    fn cfg_test_items_are_allowed_without_hiding_production_bypasses() -> Result<()> {
        let violations = source_violations(
            r#"
                #[cfg(test)]
                fn fixture() {
                    let _ = crate::contract::discover("fixture");
                }

                struct Loader;
                impl Loader {
                    #[cfg(all(test, unix))]
                    fn fixture() {
                        let _ = load_contract_repository("fixture");
                    }

                    #[cfg(any(test, unix))]
                    fn may_compile_in_production() {
                        let _ = load_contract_repository("production");
                    }
                }

                #[cfg(not(test))]
                fn production() {
                    let _ = crate::contract::discover("production");
                }
            "#,
            false,
        )?;
        assert_eq!(violations.len(), 2, "cfg filtering drifted: {violations:?}");
        assert!(
            violations.iter().all(|violation| violation.line >= 14),
            "test-only item leaked into findings: {violations:?}"
        );
        Ok(())
    }

    #[test]
    fn real_workspace_loads_through_governance_ir() -> Result<()> {
        validate_source_funnel(&crate::workspace_root()?)
    }
}
