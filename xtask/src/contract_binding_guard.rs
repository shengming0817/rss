//! `contract-binding-guard` —— 生产源中禁止裸 mint generated contract/HTTP route/projection/saga binding，并守
//! projection DB fixed function callsite 收口。
//!
//! `ContractBinding` 的正确生产来源是 `generated::{http,event,command}::*::CONTRACT`，HTTP route evidence
//! 的正确来源是 `generated::http::*::SPEC.route`。`from_static`
//! 必须保持 `pub const fn`，否则 codegen 无法跨 crate 发射常量；因此跨 crate provenance 以 AST guard
//! 收口为 Medium，不与 manifest → generated 原子生成的 Hard golden 保证混为一谈。
//! `ProjectionInputBinding` 的正确生产来源是 `generated::event::PROJECTION_INPUTS`；saga binding / policy /
//! output marker 的正确生产来源是 `generated::saga::*::{SPEC,STEPS,STEP_*}` 和 generated output DTO。本 guard 把残余面
//! 收口为 Medium：扫描生产 Rust AST，任何非测试代码直接调用 generated binding constructor 或手写
//! `SagaStepOutputBinding` 都 fail-fast。
//! 测试 fixture 与 generated/xtask 不在本扫描范围内。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" }.
//! INVARIANT: ROUTE-EVIDENCE-PROVENANCE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "contract_binding_guard::tests::scan_sources_covers_nested_examples_and_direct_journey_roots", anti_vacuity = "contract_binding_guard::tests::real_source_roots_cover_examples_and_direct_journeys" }.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use syn::parse::Parser as _;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprPath, ItemFn, ItemImpl, ItemMod, ItemType, ItemUse, Lit, Meta, Token,
    Type, TypePath, UseTree,
};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::{member_dirs, rs_files};
use crate::workspace_root;

const MEMBER_SCAN_ROOTS: &[&str] = &["crates", "adapters", "bins", "assemblies", "examples"];
const DIRECT_SCAN_ROOTS: &[&str] = &["journeys", "journeys-fault-matrix"];
const PROJECTION_EVENTS_WRAPPER: &str = "adapters/postgres/src/projection_events.rs";
const SAGA_BINDING_TEST_SUPPORT_FILES: &[&str] =
    &["adapters/postgres/src/fault_matrix/saga_fixture.rs"];
const PROJECTION_DB_FUNCTIONS: &[&str] =
    &["rss_append_projection_event", "rss_read_projection_events"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// 生产代码引用 generated binding constructor，绕过 generated 常量。
    BareFromStatic,
    /// 生产代码手写 saga output DTO marker，绕过 generated output DTO。
    SagaStepOutputBindingImpl,
    /// 生产代码绕过 sanctioned projection_events wrapper 直接调用 DB fixed function。
    ProjectionDbFunctionCallsite,
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
                "扫描 {scanned} 个生产 Rust 源文件；contract/HTTP route/projection/saga binding 生产 mint 仅允许 generated 常量；projection DB functions 仅允许 sanctioned wrapper"
            ),
            findings,
        ))
    }
}

fn scan_sources(root: &Path) -> Result<(usize, Vec<Finding<Rule>>)> {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for source_root in production_source_roots(root)? {
        for path in rs_files(&source_root.join("src"))? {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("contract-binding-guard: read {}", path.display()))?;
            let relative = root_relative(root, &path);
            if is_test_file(&path) || is_binding_definition_file(&relative) {
                continue;
            }
            scanned += 1;
            findings.extend(scan_file(&relative, &content)?);
        }
    }
    Ok((scanned, findings))
}

fn production_source_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    for top in MEMBER_SCAN_ROOTS {
        roots.extend(member_dirs(&root.join(top))?);
    }
    roots.extend(DIRECT_SCAN_ROOTS.iter().map(|direct| root.join(direct)));
    roots.sort();
    Ok(roots)
}

fn scan_file(path: &Path, content: &str) -> Result<Vec<Finding<Rule>>> {
    let ast = syn::parse_file(content)
        .with_context(|| format!("contract-binding-guard: parse {}", path.display()))?;
    let aliases = collect_contract_binding_aliases(&ast);
    let mut visitor = BindingVisitor {
        path,
        binding_aliases: aliases.binding_constructors,
        saga_output_binding_aliases: aliases.saga_output_binding_traits,
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
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    name == "tests.rs"
        || name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
        || path.components().any(|c| c.as_os_str() == "tests")
}

fn is_binding_definition_file(path: &Path) -> bool {
    path == Path::new("crates/vocab/src/contract/binding.rs")
        || path == Path::new("crates/vocab/src/http.rs")
}

fn is_projection_events_wrapper(path: &Path) -> bool {
    path == Path::new(PROJECTION_EVENTS_WRAPPER)
}

fn expr_contains_projection_db_function(expr: &Expr) -> bool {
    let Expr::Lit(lit) = expr else {
        return false;
    };
    let Lit::Str(value) = &lit.lit else {
        return false;
    };
    let sql = value.value().to_ascii_lowercase();
    PROJECTION_DB_FUNCTIONS
        .iter()
        .any(|function| sql.contains(function))
}

struct BindingVisitor<'a> {
    path: &'a Path,
    binding_aliases: BindingConstructorAliases,
    saga_output_binding_aliases: BTreeSet<String>,
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

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if self.in_test == 0
            && !is_saga_binding_test_support_file(self.path)
            && is_binding_constructor_path(node, &self.binding_aliases)
        {
            self.findings.push(finding(
                Rule::BareFromStatic,
                self.path.display().to_string(),
                "生产代码不得引用 generated binding constructor；请使用 generated `CONTRACT` / HTTP `ROUTE` / `PROJECTION_INPUTS` / saga `SPEC` / `STEPS` 常量",
            ));
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        self.with_test_scope(is_test_like(&node.attrs), |this| {
            if this.in_test == 0
                && !is_saga_binding_test_support_file(this.path)
                && is_saga_step_output_binding_impl(node, &this.saga_output_binding_aliases)
            {
                this.findings.push(finding(
                    Rule::SagaStepOutputBindingImpl,
                    this.path.display().to_string(),
                    "生产代码不得手写 `SagaStepOutputBinding`；请使用 generated saga output DTO",
                ));
            }
            visit::visit_item_impl(this, node);
        });
    }

    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.in_test == 0
            && !is_projection_events_wrapper(self.path)
            && expr_contains_projection_db_function(node)
        {
            self.findings.push(finding(
                Rule::ProjectionDbFunctionCallsite,
                self.path.display().to_string(),
                "生产代码不得直接调用 projection DB fixed function；请经 postgres projection_events wrapper",
            ));
        }
        visit::visit_expr(self, node);
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
    binding_constructors: BindingConstructorAliases,
    saga_output_binding_traits: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for AliasCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        collect_use_tree_aliases(
            &node.tree,
            &mut self.binding_constructors,
            &mut self.saga_output_binding_traits,
        );
        visit::visit_item_use(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast ItemType) {
        if let Some(type_ident) = binding_type_ident(&node.ty) {
            insert_binding_alias(
                &mut self.binding_constructors,
                &node.ident.to_string(),
                &type_ident,
            );
        }
        visit::visit_item_type(self, node);
    }
}

struct SourceAliases {
    binding_constructors: BindingConstructorAliases,
    saga_output_binding_traits: BTreeSet<String>,
}

fn collect_contract_binding_aliases(file: &syn::File) -> SourceAliases {
    let mut binding_constructors = BindingConstructorAliases::new();
    insert_binding_alias(
        &mut binding_constructors,
        "ContractBinding",
        "ContractBinding",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "HttpRouteEvidence",
        "HttpRouteEvidence",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "HttpRouteBinding",
        "HttpRouteBinding",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "ProjectionInputBinding",
        "ProjectionInputBinding",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "SagaStepBinding",
        "SagaStepBinding",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "SagaRuntimePolicySpec",
        "SagaRuntimePolicySpec",
    );
    insert_binding_alias(
        &mut binding_constructors,
        "SagaContractBinding",
        "SagaContractBinding",
    );
    let saga_output_binding_traits = BTreeSet::from(["SagaStepOutputBinding".to_string()]);
    let mut collector = AliasCollector {
        binding_constructors,
        saga_output_binding_traits,
    };
    collector.visit_file(file);
    SourceAliases {
        binding_constructors: collector.binding_constructors,
        saga_output_binding_traits: collector.saga_output_binding_traits,
    }
}

type BindingConstructorAliases = BTreeMap<String, BTreeSet<&'static str>>;

fn collect_use_tree_aliases(
    tree: &UseTree,
    aliases: &mut BindingConstructorAliases,
    output_binding_aliases: &mut BTreeSet<String>,
) {
    match tree {
        UseTree::Path(path) => {
            collect_use_tree_aliases(&path.tree, aliases, output_binding_aliases);
        }
        UseTree::Name(name) => {
            let ident = name.ident.to_string();
            insert_binding_alias(aliases, &ident, &ident);
            if ident == "SagaStepOutputBinding" {
                output_binding_aliases.insert(ident);
            }
        }
        UseTree::Rename(rename) => {
            insert_binding_alias(
                aliases,
                &rename.rename.to_string(),
                &rename.ident.to_string(),
            );
            if rename.ident == "SagaStepOutputBinding" {
                output_binding_aliases.insert(rename.rename.to_string());
            }
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree_aliases(tree, aliases, output_binding_aliases);
            }
        }
        _ => {}
    }
}

fn binding_type_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { path, .. }) => {
            let ident = path.segments.last()?.ident.to_string();
            binding_constructor_methods(&ident).map(|_| ident)
        }
        _ => None,
    }
}

fn insert_binding_alias(aliases: &mut BindingConstructorAliases, alias: &str, type_name: &str) {
    if let Some(methods) = binding_constructor_methods(type_name) {
        aliases.insert(alias.to_string(), methods.iter().copied().collect());
    }
}

fn binding_constructor_methods(type_name: &str) -> Option<&'static [&'static str]> {
    match type_name {
        "ContractBinding"
        | "HttpRouteEvidence"
        | "HttpRouteBinding"
        | "ProjectionInputBinding"
        | "SagaStepBinding" => Some(&["from_static"]),
        "SagaRuntimePolicySpec" => Some(&["from_millis"]),
        "SagaContractBinding" => Some(&["from_parts"]),
        _ => None,
    }
}

fn is_binding_constructor_path(expr: &ExprPath, aliases: &BindingConstructorAliases) -> bool {
    let Some(method) = expr.path.segments.last() else {
        return false;
    };
    let type_alias = if let Some(qself) = &expr.qself {
        type_path_last_ident(&qself.ty)
    } else {
        expr.path
            .segments
            .iter()
            .rev()
            .nth(1)
            .map(|segment| segment.ident.to_string())
    };
    let Some(type_alias) = type_alias else {
        return false;
    };
    let method = method.ident.to_string();
    aliases
        .get(type_alias.as_str())
        .is_some_and(|methods| methods.contains(method.as_str()))
}

fn type_path_last_ident(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(TypePath { path, .. }) => path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Type::Group(group) => type_path_last_ident(&group.elem),
        Type::Paren(paren) => type_path_last_ident(&paren.elem),
        _ => None,
    }
}

fn is_saga_step_output_binding_impl(node: &ItemImpl, aliases: &BTreeSet<String>) -> bool {
    let Some((_, path, _)) = &node.trait_ else {
        return false;
    };
    path.segments
        .last()
        .is_some_and(|seg| aliases.contains(&seg.ident.to_string()))
}

fn is_saga_binding_test_support_file(path: &Path) -> bool {
    SAGA_BINDING_TEST_SUPPORT_FILES
        .iter()
        .any(|allowed| path == Path::new(allowed))
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
        Meta::NameValue(value) if value.path.is_ident("feature") => {
            matches!(
                &value.value,
                Expr::Lit(lit)
                    if matches!(&lit.lit, Lit::Str(feature) if feature.value() == "test-util")
            )
        }
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
    fn scan_sources_covers_nested_examples_and_direct_journey_roots() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-contract-binding-roots-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let source = r#"
            fn mint() {
                let _ = vocab::HttpRouteEvidence::from_static(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/forged",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        for relative in [
            "examples/demo/src/lib.rs",
            "journeys/src/lib.rs",
            "journeys-fault-matrix/src/lib.rs",
        ] {
            let path = root.join(relative);
            let Some(parent) = path.parent() else {
                anyhow::bail!(
                    "synthetic source path must have a parent: {}",
                    path.display()
                );
            };
            std::fs::create_dir_all(parent)?;
            std::fs::write(path, source)?;
        }

        let result = scan_sources(&root);
        std::fs::remove_dir_all(&root)?;
        let (scanned, findings) = result?;
        assert_eq!(scanned, 3, "all production root shapes must be scanned");
        assert_eq!(
            findings.len(),
            3,
            "each synthetic root must trip the provenance guard: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_source_roots_cover_examples_and_direct_journeys() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let roots = production_source_roots(&root)?;
        for relative in [
            "examples/tenancy-consumer",
            "examples/iotdevice",
            "journeys",
            "journeys-fault-matrix",
        ] {
            assert!(
                roots.contains(&root.join(relative)),
                "production provenance scan must include {relative}"
            );
        }
        Ok(())
    }

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
    fn flags_prod_http_route_evidence_mint() -> anyhow::Result<()> {
        let src = r#"
            fn mint() {
                let _ = vocab::HttpRouteEvidence::from_static(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/forged",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_contract_specific_http_route_binding_mint() -> anyhow::Result<()> {
        let src = r#"
            struct RouteMarker;

            fn mint() {
                let _ = vocab::HttpRouteBinding::<RouteMarker>::from_static(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/forged",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1, "typed binding mint must be generated");
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_http_route_evidence_function_item_alias() -> anyhow::Result<()> {
        let src = r#"
            fn mint() {
                let mint = vocab::HttpRouteEvidence::from_static;
                let _ = mint(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/forged",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "constructor function-item aliases must not bypass provenance: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_http_route_evidence_ufcs_constructor() -> anyhow::Result<()> {
        let src = r#"
            type Evidence = vocab::HttpRouteEvidence;

            fn mint() {
                let _ = <Evidence>::from_static(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/forged",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "UFCS constructors must not bypass provenance: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn test_file_filter_is_exact() {
        assert!(!is_test_file(Path::new("crates/x/src/latest.rs")));
        assert!(!is_test_file(Path::new("crates/x/src/contest.rs")));
        assert!(is_test_file(Path::new("crates/x/src/route_test.rs")));
        assert!(is_test_file(Path::new("crates/x/src/route_tests.rs")));
        assert!(is_test_file(Path::new("crates/x/src/tests.rs")));
        assert!(is_test_file(Path::new("crates/x/tests/route.rs")));
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
    fn flags_prod_projection_input_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            use vocab::ProjectionInputBinding;

            fn mint() {
                let _ = ProjectionInputBinding::from_static(
                    "audit.session-projection",
                    "identity",
                    "identity.session-created",
                    "v1",
                    "sha256:0123",
                    "identity.session.created",
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_step_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            use vocab::SagaStepBinding;

            fn mint() {
                let _ = SagaStepBinding::from_static(
                    generated::saga::billing_v1::CONTRACT,
                    "reserve_funds",
                    "reserve.schema.json",
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_policy_from_millis_call() -> anyhow::Result<()> {
        let src = r#"
            use vocab::SagaRuntimePolicySpec as Policy;

            fn mint() {
                let _ = Policy::from_millis(5000, 30000);
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_contract_from_parts_call() -> anyhow::Result<()> {
        let src = r#"
            type Spec = vocab::SagaContractBinding;

            fn mint(
                contract: vocab::ContractBinding,
                policy: vocab::SagaRuntimePolicySpec,
                steps: &'static [vocab::SagaStepBinding],
            ) {
                let _ = Spec::from_parts(contract, policy, steps);
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_output_marker_impl() -> anyhow::Result<()> {
        let src = r#"
            struct Output;

            impl vocab::SagaStepOutputBinding for Output {
                const BINDING: vocab::SagaStepBinding = generated::saga::billing_v1::STEP_0;
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SagaStepOutputBindingImpl);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_output_marker_impl_alias() -> anyhow::Result<()> {
        let src = r#"
            use vocab::SagaStepOutputBinding as Marker;

            struct Output;

            impl Marker for Output {
                const BINDING: vocab::SagaStepBinding = generated::saga::billing_v1::STEP_0;
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SagaStepOutputBindingImpl);
        Ok(())
    }

    #[test]
    fn flags_feature_gated_fault_matrix_binding_mint() -> anyhow::Result<()> {
        let src = r#"
            const STEP: vocab::SagaStepBinding =
                vocab::SagaStepBinding::from_static(
                    generated::saga::billing_v1::CONTRACT,
                    "reserve_funds",
                    "reserve.schema.json",
                );

            struct Output;

            impl vocab::SagaStepOutputBinding for Output {
                const BINDING: vocab::SagaStepBinding = STEP;
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/fault_matrix.rs"), src)?;
        assert_eq!(
            findings.len(),
            2,
            "feature-gated public fault_matrix.rs must still be scanned: {findings:?}"
        );
        assert!(findings.iter().any(|f| f.rule == Rule::BareFromStatic));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SagaStepOutputBindingImpl)
        );
        Ok(())
    }

    #[test]
    fn allows_dedicated_saga_fixture_binding_mint() -> anyhow::Result<()> {
        let src = r#"
            const STEP: vocab::SagaStepBinding =
                vocab::SagaStepBinding::from_static(
                    generated::saga::billing_v1::CONTRACT,
                    "reserve_funds",
                    "reserve.schema.json",
                );

            struct Output;

            impl vocab::SagaStepOutputBinding for Output {
                const BINDING: vocab::SagaStepBinding = STEP;
            }
        "#;
        let findings = scan_file(
            Path::new("adapters/postgres/src/fault_matrix/saga_fixture.rs"),
            src,
        )?;
        assert!(
            findings.is_empty(),
            "only the dedicated fault-matrix saga fixture file may hand-author typed saga bindings: {findings:?}"
        );
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
    fn ignores_explicit_test_util_feature_fixture() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(any(test, feature = "test-util"))]
            fn fixture() {
                let _ = vocab::HttpRouteEvidence::from_static(
                    generated::http::identity_v1::profile::CONTRACT,
                    "/test",
                    "GET",
                    vocab::HttpSuccessStatus::new(200),
                    vocab::HttpIdempotency::Idempotent,
                    vocab::HttpRouteAuth::Public,
                    None,
                    false,
                    vocab::HttpConsistencyLevel::LocalOnly,
                    generated::http::identity_v1::profile::EFFECT_PROFILE,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert!(findings.is_empty(), "test-util fixture must be allowed");
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
    fn flags_projection_db_function_callsite_outside_wrapper() -> anyhow::Result<()> {
        let src = r#"
            fn append() {
                let _sql = "SELECT rss_append_projection_event($1, $2)";
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/outbox.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::ProjectionDbFunctionCallsite);
        Ok(())
    }

    #[test]
    fn flags_projection_db_function_callsite_outside_wrapper_case_insensitive() -> anyhow::Result<()>
    {
        let src = r#"
            fn append() {
                let _sql = "SELECT RSS_APPEND_PROJECTION_EVENT($1, $2)";
                let _read = "SELECT * FROM Rss_Read_Projection_Events($1, $2)";
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/outbox.rs"), src)?;
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ProjectionDbFunctionCallsite),
            "uppercase/mixed-case fixed function calls must be guarded: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn allows_projection_db_function_callsite_in_wrapper() -> anyhow::Result<()> {
        let src = r#"
            fn append() {
                let _append = "SELECT rss_append_projection_event($1, $2)";
                let _read = "SELECT * FROM rss_read_projection_events($1, $2)";
            }
        "#;
        let findings = scan_file(Path::new(PROJECTION_EVENTS_WRAPPER), src)?;
        assert!(
            findings.is_empty(),
            "projection_events wrapper is the sanctioned DB function callsite: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn ignores_projection_db_function_test_fixture() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(test)]
            mod tests {
                fn fixture() {
                    let _sql = "SELECT rss_read_projection_events($1, $2)";
                }
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/lib.rs"), src)?;
        assert!(
            findings.is_empty(),
            "test fixtures must be allowed: {findings:?}"
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
            "生产 src 不应裸调用 binding from_static 或 projection DB function: {findings:?}"
        );
    }
}
