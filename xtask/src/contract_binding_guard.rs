//! `contract-binding-guard` —— 生产源中禁止裸 mint `vocab::ContractBinding::from_static`。
//!
//! `ContractBinding` 的正确生产来源是 `generated::{http,event,command}::*::CONTRACT`。`from_static`
//! 必须保持 `pub const fn`，否则 codegen 无法跨 crate 发射常量；因此跨 crate sealing 不能做到 Hard。
//! 本 guard 把残余面收口为 Medium：扫描生产 Rust AST，任何非测试代码直接调用
//! `ContractBinding::from_static` 都 fail-fast。测试 fixture 与 generated/xtask 不在本扫描范围内。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" }.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::parse::Parser as _;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprPath, ItemFn, ItemMod, ItemType, ItemUse, Meta, Token, Type,
    TypePath, UseTree,
};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::{member_dirs, rs_files};
use crate::workspace_root;

const SCAN_ROOTS: &[&str] = &["crates", "adapters", "bins", "assemblies"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// 生产代码直接调用 `ContractBinding::from_static`，绕过 generated `CONTRACT` 常量。
    BareFromStatic,
}

pub(crate) struct ContractBindingGuard;

impl GovernanceCheck for ContractBindingGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "contract-binding-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = workspace_root()?;
        let (scanned, findings) = scan_sources(&root)?;
        Ok((
            format!(
                "扫描 {scanned} 个生产 Rust 源文件；ContractBinding 生产 mint 仅允许 generated CONTRACT"
            ),
            findings,
        ))
    }
}

fn scan_sources(root: &Path) -> Result<(usize, Vec<Finding<Rule>>)> {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for top in SCAN_ROOTS {
        for member in member_dirs(&root.join(top))? {
            for path in rs_files(&member.join("src"))? {
                if is_test_file(&path) {
                    continue;
                }
                scanned += 1;
                let content = std::fs::read_to_string(&path)
                    .with_context(|| format!("contract-binding-guard: read {}", path.display()))?;
                findings.extend(scan_file(&root_relative(root, &path), &content)?);
            }
        }
    }
    Ok((scanned, findings))
}

fn scan_file(path: &Path, content: &str) -> Result<Vec<Finding<Rule>>> {
    let ast = syn::parse_file(content)
        .with_context(|| format!("contract-binding-guard: parse {}", path.display()))?;
    let aliases = collect_contract_binding_aliases(&ast);
    let mut visitor = BindingVisitor {
        path,
        aliases,
        in_test: 0,
        findings: Vec::new(),
    };
    visitor.visit_file(&ast);
    Ok(visitor.findings)
}

fn root_relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn is_test_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.contains("test"))
        || path.components().any(|c| c.as_os_str() == "tests")
}

struct BindingVisitor<'a> {
    path: &'a Path,
    aliases: BTreeSet<String>,
    in_test: usize,
    findings: Vec<Finding<Rule>>,
}

impl<'ast> Visit<'ast> for BindingVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        self.with_test_scope(is_test_like(&node.attrs), |this| {
            visit::visit_item_mod(this, node);
        });
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.with_test_scope(is_test_like(&node.attrs), |this| {
            visit::visit_item_fn(this, node);
        });
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.in_test == 0 && is_contract_binding_from_static(&node.func, &self.aliases) {
            self.findings.push(finding(
                Rule::BareFromStatic,
                self.path.display().to_string(),
                "生产代码不得直接调用 `ContractBinding::from_static`；请使用 generated `CONTRACT` 常量",
            ));
        }
        visit::visit_expr_call(self, node);
    }
}

impl BindingVisitor<'_> {
    fn with_test_scope(&mut self, is_test: bool, f: impl FnOnce(&mut Self)) {
        if is_test {
            self.in_test += 1;
        }
        f(self);
        if is_test {
            self.in_test -= 1;
        }
    }
}

struct AliasCollector {
    aliases: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for AliasCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        collect_use_tree_aliases(&node.tree, &mut self.aliases);
        visit::visit_item_use(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        if is_contract_binding_type(&node.ty) {
            self.aliases.insert(node.ident.to_string());
        }
        visit::visit_item_type(self, node);
    }
}

fn collect_contract_binding_aliases(file: &syn::File) -> BTreeSet<String> {
    let mut aliases = BTreeSet::new();
    aliases.insert("ContractBinding".to_string());
    let mut collector = AliasCollector { aliases };
    collector.visit_file(file);
    collector.aliases
}

fn collect_use_tree_aliases(tree: &UseTree, aliases: &mut BTreeSet<String>) {
    match tree {
        UseTree::Path(path) => collect_use_tree_aliases(&path.tree, aliases),
        UseTree::Name(name) if name.ident == "ContractBinding" => {
            aliases.insert("ContractBinding".to_string());
        }
        UseTree::Rename(rename) if rename.ident == "ContractBinding" => {
            aliases.insert(rename.rename.to_string());
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree_aliases(tree, aliases);
            }
        }
        _ => {}
    }
}

fn is_contract_binding_type(ty: &Type) -> bool {
    matches!(ty, Type::Path(TypePath { path, .. }) if path
        .segments
        .last()
        .is_some_and(|seg| seg.ident == "ContractBinding"))
}

fn is_contract_binding_from_static(func: &Expr, aliases: &BTreeSet<String>) -> bool {
    let Expr::Path(ExprPath { path, .. }) = func else {
        return false;
    };
    let mut segments = path.segments.iter().rev();
    let Some(last) = segments.next() else {
        return false;
    };
    let Some(prev) = segments.next() else {
        return false;
    };
    let prev_ident = prev.ident.to_string();
    last.ident == "from_static" && aliases.contains(prev_ident.as_str())
}

fn is_test_like(attrs: &[Attribute]) -> bool {
    attrs.iter().any(is_test_attr)
}

fn is_test_attr(attr: &Attribute) -> bool {
    let path = attr.path();
    if path.is_ident("test") || path.segments.last().is_some_and(|seg| seg.ident == "test") {
        return true;
    }

    match &attr.meta {
        Meta::List(list) if path.is_ident("cfg") => {
            syn::parse2::<Meta>(list.tokens.clone()).is_ok_and(|meta| cfg_meta_is_test_only(&meta))
        }
        Meta::List(_) if path.is_ident("cfg_attr") => false,
        _ => false,
    }
}

fn cfg_meta_is_test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("not") => false,
        Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Some(args) = parse_meta_args(&list.tokens) else {
                return false;
            };
            if args.is_empty() {
                return false;
            }
            if list.path.is_ident("all") {
                args.iter().any(cfg_meta_is_test_only)
            } else {
                args.iter().all(cfg_meta_is_test_only)
            }
        }
        Meta::List(_) | Meta::NameValue(_) => false,
    }
}

fn parse_meta_args(tokens: &proc_macro2::TokenStream) -> Option<Punctuated<Meta, Token![,]>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(tokens.clone())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_prod_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            fn mint() {
                let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_alias_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            use vocab::ContractBinding as Binding;

            fn mint() {
                let _ = Binding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_type_alias_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            type Binding = vocab::ContractBinding;

            fn mint() {
                let _ = Binding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_cfg_not_test_prod_call() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(not(test))]
            fn mint() {
                let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn ignores_cfg_test_module_fixture() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(test)]
            mod tests {
                fn fixture() {
                    let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
                }
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert!(
            findings.is_empty(),
            "test fixtures must be allowed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_mixed_cfg_any_test_or_feature() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(any(test, feature = "prod-fixture"))]
            fn mint() {
                let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1, "mixed cfg is production-reachable");
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_cfg_attr_test_because_item_is_still_prod_reachable() -> anyhow::Result<()> {
        let src = r#"
            #[cfg_attr(test, allow(dead_code))]
            fn mint() {
                let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "cfg_attr(test, ...) does not make the item test-only"
        );
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn ignores_cfg_all_test_and_feature_fixture() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(all(test, feature = "fixture"))]
            fn mint() {
                let _ = vocab::ContractBinding::from_static("identity", "identity.x", "v1", "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert!(
            findings.is_empty(),
            "cfg(all(test, ...)) is only reachable when test cfg is active: {findings:?}"
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn real_sources_have_no_bare_contract_binding_mint() {
        let root = workspace_root().expect("workspace root");
        let (scanned, findings) = scan_sources(&root).expect("scan sources");
        assert!(scanned >= 10, "至少扫到生产 src，实际 {scanned}");
        assert!(
            findings.is_empty(),
            "生产 src 不应裸调用 ContractBinding::from_static: {findings:?}"
        );
    }
}
