//! `contract-binding-guard` —— 生产源中禁止裸 mint generated contract/HTTP route/projection/saga binding，并守
//! projection DB fixed function callsite 收口。
//!
//! `ContractBinding` / `EventFactBinding` 的正确生产来源是
//! `generated::{http,event,command}::*::{CONTRACT,FACT}`，HTTP route evidence 的正确来源是
//! `generated::http::*::SPEC.route`。`from_static`
//! 必须保持 `pub const fn`，否则 codegen 无法跨 crate 发射常量；因此跨 crate provenance 以 AST guard
//! 收口为 Medium，不与 manifest → generated 原子生成的 Hard golden 保证混为一谈。
//! `GeneratedEventPayload` 同理只允许 codegen owner 实现；生产 crate 手写 impl（含 alias / glob import）
//! 会让任意 payload 自签 contract/topic，故本 guard 一并 fail-fast。
//! `ProjectionInputBinding` 的正确生产来源是 `generated::event::PROJECTION_INPUTS`；saga binding / policy /
//! receipt/typestate marker 的正确生产来源是 `generated::saga::*::{SPEC,STEPS,STEP_*}` 和 sealed generated receipt DTO。本 guard 把残余面
//! 收口为 Medium：扫描生产 Rust AST，任何非测试代码直接调用 generated binding constructor 都
//! fail-fast。
//! 测试 fixture 与 generated/xtask 不在本扫描范围内。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "check", source = "code" }.
//! INVARIANT: ROUTE-EVIDENCE-PROVENANCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "contract_binding_guard::tests::scan_sources_covers_nested_examples_and_direct_journey_roots", anti_vacuity = "contract_binding_guard::tests::real_source_roots_cover_workspace_compositions_and_direct_journeys" }.
//! INVARIANT: PRODUCER-RAW-TRANSPORT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "contract_binding_guard::tests::flags_raw_transport_in_cross_file_reachable_helper", anti_vacuity = "contract_binding_guard::tests::real_active_producer_providers_have_no_raw_transport" }.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use syn::parse::Parser as _;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprMethodCall, ExprPath, ImplItem, Item, ItemFn, ItemImpl, ItemMod,
    ItemType, ItemUse, Lit, Meta, Signature, Token, Type, TypePath, UseTree,
};

use crate::cmd::{CargoSubcommand, cargo_cmd};
use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::rs_files;
use crate::workspace_root;

const DIRECT_SCAN_ROOTS: &[&str] = &["journeys", "journeys-fault-matrix"];
const EXCLUDED_WORKSPACE_PACKAGES: &[&str] = &["generated", "xtask"];
const PROJECTION_EVENTS_WRAPPER: &str = "adapters/postgres/src/projection_events.rs";
const PROJECTION_DB_FUNCTIONS: &[&str] =
    &["rss_append_projection_event", "rss_read_projection_events"];
const ACTIVE_PRODUCER_PROVIDER_FILES: &[&str] = &[
    "adapters/postgres/src/auth_grant_lifecycle.rs",
    "adapters/postgres/src/policy_repo.rs",
    "adapters/postgres/src/role_binding_lifecycle.rs",
    "adapters/postgres/src/config_repo.rs",
];
const RAW_PRODUCER_TRANSPORT_TYPES: &[&str] = &[
    "Publisher",
    "DynPublisher",
    "PublishRequest",
    "OutboxEmitter",
];
const RAW_PRODUCER_TRANSPORT_METHODS: &[&str] = &["publish", "emit"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// 生产代码引用 generated binding constructor，绕过 generated 常量。
    BareFromStatic,
    /// 生产代码手写 generated event payload marker，伪造 codegen provenance。
    GeneratedEventPayloadImpl,
    /// 生产代码绕过 sanctioned projection_events wrapper 直接调用 DB fixed function。
    ProjectionDbFunctionCallsite,
    /// active HTTP producer provider 引用 raw publisher/emitter transport。
    RawProducerTransport,
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
                "扫描 {scanned} 个生产 Rust 源文件；contract/event fact/HTTP route/projection/saga binding 生产 mint 与 GeneratedEventPayload impl 仅允许 generated/codegen owner；projection DB functions 仅允许 sanctioned wrapper；active HTTP producer provider 禁止 raw publisher/emitter"
            ),
            findings,
        ))
    }
}

fn scan_sources(root: &Path) -> Result<(usize, Vec<Finding<Rule>>)> {
    let mut findings = Vec::new();
    let mut sources = BTreeMap::new();
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
            sources.insert(relative, content);
        }
    }
    findings.extend(scan_reachable_raw_transport_helpers(&sources)?);
    Ok((scanned, findings))
}

fn production_source_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let mut roots = workspace_member_roots(root)?;
    roots.extend(DIRECT_SCAN_ROOTS.iter().map(|direct| root.join(direct)));
    roots.sort();
    roots.dedup();
    Ok(roots)
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: BTreeSet<String>,
    workspace_root: PathBuf,
}

#[derive(Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    targets: Vec<CargoTarget>,
}

#[derive(Deserialize)]
struct CargoTarget {
    kind: Vec<String>,
}

fn workspace_member_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let output = cargo_cmd(
        CargoSubcommand::Metadata,
        &["--format-version", "1", "--no-deps"],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| {
        format!(
            "contract-binding-guard: run cargo metadata below {}",
            root.display()
        )
    })?;
    ensure!(
        output.status.success(),
        "contract-binding-guard: cargo metadata failed below {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .context("contract-binding-guard: decode cargo metadata")?;
    let workspace_root = metadata.workspace_root.clone();
    let mut roots = metadata
        .packages
        .into_iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .filter(|package| !EXCLUDED_WORKSPACE_PACKAGES.contains(&package.name.as_str()))
        .filter(|package| {
            package.targets.iter().any(|target| {
                target.kind.iter().any(|kind| {
                    !matches!(kind.as_str(), "test" | "bench" | "example" | "custom-build")
                })
            })
        })
        .map(|package| {
            let manifest_parent = package
                .manifest_path
                .parent()
                .map(Path::to_path_buf)
                .with_context(|| {
                    format!(
                        "contract-binding-guard: workspace member {} manifest has no parent",
                        package.name
                    )
                })?;
            let relative = manifest_parent.strip_prefix(&workspace_root).with_context(|| {
                format!(
                    "contract-binding-guard: workspace member {} escaped metadata workspace root",
                    package.name
                )
            })?;
            Ok(root.join(relative))
        })
        .collect::<Result<Vec<_>>>()?;
    roots.sort();
    roots.dedup();
    ensure!(
        !roots.is_empty(),
        "contract-binding-guard: cargo metadata returned no production workspace members"
    );
    Ok(roots)
}

fn scan_file(path: &Path, content: &str) -> Result<Vec<Finding<Rule>>> {
    let ast = syn::parse_file(content)
        .with_context(|| format!("contract-binding-guard: parse {}", path.display()))?;
    let aliases = collect_contract_binding_aliases(&ast);
    let raw_transport_aliases = collect_raw_transport_aliases(&ast);
    let mut visitor = BindingVisitor {
        path,
        binding_aliases: aliases.binding_constructors,
        generated_event_payload_aliases: aliases.generated_event_payload_traits,
        raw_transport_aliases,
        guard_raw_transport: is_active_producer_provider(path),
        guard_untyped_emit: is_active_producer_provider(path),
        in_test: 0,
        findings: Vec::new(),
        raw_transport_hits: BTreeMap::new(),
    };
    visitor.visit_file(&ast);
    Ok(visitor.into_findings())
}

#[derive(Clone)]
struct ProducerFunctionNode {
    key: String,
    symbol: String,
    path: PathBuf,
    module: Vec<String>,
    owner: Option<String>,
    call_aliases: BTreeMap<String, Vec<String>>,
    signature: Signature,
    block: Block,
    calls: Vec<ProducerCall>,
}

#[derive(Clone)]
enum ProducerCall {
    Function(Vec<String>),
    SelfMethod(String),
}

fn scan_reachable_raw_transport_helpers(
    sources: &BTreeMap<PathBuf, String>,
) -> Result<Vec<Finding<Rule>>> {
    let mut nodes = BTreeMap::new();
    let mut aliases_by_path = BTreeMap::new();
    for (path, source) in sources {
        let Some(module) = postgres_module(path) else {
            continue;
        };
        let file = syn::parse_file(source).with_context(|| {
            format!(
                "contract-binding-guard: parse producer call graph {}",
                path.display()
            )
        })?;
        aliases_by_path.insert(path.clone(), collect_raw_transport_aliases(&file));
        let call_aliases = collect_producer_call_aliases(&file.items);
        collect_producer_function_nodes(path, &module, &call_aliases, &file.items, &mut nodes)?;
    }

    let mut reachable = BTreeSet::new();
    let mut pending = nodes
        .values()
        .filter(|node| is_active_producer_provider(&node.path))
        .map(|node| node.key.clone())
        .collect::<VecDeque<_>>();
    while let Some(key) = pending.pop_front() {
        if !reachable.insert(key.clone()) {
            continue;
        }
        let Some(node) = nodes.get(&key) else {
            continue;
        };
        for call in &node.calls {
            if let Some(callee) = resolve_producer_call(node, call, &nodes) {
                pending.push_back(callee);
            }
        }
    }

    let mut findings = Vec::new();
    let mut reported_sites = BTreeSet::new();
    for key in reachable {
        let Some(node) = nodes.get(&key) else {
            continue;
        };
        if is_active_producer_provider(&node.path) {
            continue;
        }
        let aliases = aliases_by_path
            .get(&node.path)
            .context("reachable producer helper must retain its file aliases")?
            .clone();
        let mut visitor = BindingVisitor {
            path: &node.path,
            binding_aliases: BindingConstructorAliases::new(),
            generated_event_payload_aliases: BTreeSet::new(),
            raw_transport_aliases: aliases,
            guard_raw_transport: true,
            guard_untyped_emit: false,
            in_test: 0,
            findings: Vec::new(),
            raw_transport_hits: BTreeMap::new(),
        };
        visitor.visit_signature(&node.signature);
        visitor.visit_block(&node.block);
        for finding in visitor
            .into_findings()
            .into_iter()
            .filter(|finding| finding.rule == Rule::RawProducerTransport)
        {
            if reported_sites.insert(finding.subject.clone()) {
                findings.push(finding);
            }
        }
    }
    Ok(findings)
}

fn postgres_module(path: &Path) -> Option<Vec<String>> {
    let relative = path.strip_prefix("adapters/postgres/src").ok()?;
    let mut module = relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| component.as_os_str().to_str().map(ToString::to_string))
        .collect::<Vec<_>>();
    let stem = relative.file_stem()?.to_str()?;
    if !matches!(stem, "lib" | "mod") {
        module.push(stem.to_string());
    }
    Some(module)
}

fn collect_producer_function_nodes(
    path: &Path,
    module: &[String],
    call_aliases: &BTreeMap<String, Vec<String>>,
    items: &[Item],
    nodes: &mut BTreeMap<String, ProducerFunctionNode>,
) -> Result<()> {
    for item in items {
        if is_test_like(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Fn(function) => insert_producer_function_node(
                path,
                module,
                None,
                call_aliases,
                &function.sig,
                &function.block,
                nodes,
            )?,
            Item::Impl(item_impl) => {
                let owner = type_path_last_ident(&item_impl.self_ty)
                    .context("producer call graph requires a path-like impl owner")?;
                for item in &item_impl.items {
                    let ImplItem::Fn(method) = item else {
                        continue;
                    };
                    if !is_test_like(&method.attrs) {
                        insert_producer_function_node(
                            path,
                            module,
                            Some(&owner),
                            call_aliases,
                            &method.sig,
                            &method.block,
                            nodes,
                        )?;
                    }
                }
            }
            Item::Mod(item_mod) => {
                if let Some((_, nested)) = &item_mod.content {
                    let mut nested_module = module.to_vec();
                    nested_module.push(item_mod.ident.to_string());
                    collect_producer_function_nodes(
                        path,
                        &nested_module,
                        call_aliases,
                        nested,
                        nodes,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn insert_producer_function_node(
    path: &Path,
    module: &[String],
    owner: Option<&str>,
    call_aliases: &BTreeMap<String, Vec<String>>,
    signature: &Signature,
    block: &Block,
    nodes: &mut BTreeMap<String, ProducerFunctionNode>,
) -> Result<()> {
    let mut symbol = module.to_vec();
    if let Some(owner) = owner {
        symbol.push(owner.to_string());
    }
    symbol.push(signature.ident.to_string());
    let symbol = symbol.join("::");
    let key_prefix = format!("{}::{symbol}", path.display());
    let mut key = key_prefix.clone();
    let mut ordinal = 2usize;
    while nodes.contains_key(&key) {
        key = format!("{key_prefix}#{ordinal}");
        ordinal += 1;
    }
    let calls = collect_producer_calls(block);
    let node = ProducerFunctionNode {
        key: key.clone(),
        symbol,
        path: path.to_path_buf(),
        module: module.to_vec(),
        owner: owner.map(ToString::to_string),
        call_aliases: call_aliases.clone(),
        signature: signature.clone(),
        block: block.clone(),
        calls,
    };
    nodes.insert(key, node);
    Ok(())
}

fn collect_producer_calls(block: &Block) -> Vec<ProducerCall> {
    #[derive(Default)]
    struct CallCollector {
        calls: Vec<ProducerCall>,
    }

    impl<'ast> Visit<'ast> for CallCollector {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(path) = producer_function_path(&node.func) {
                self.calls.push(ProducerCall::Function(path));
            }
            for argument in &node.args {
                self.visit_expr(argument);
            }
        }

        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            if producer_simple_expr_ident(&node.receiver).as_deref() == Some("self") {
                self.calls
                    .push(ProducerCall::SelfMethod(node.method.to_string()));
            }
            self.visit_expr(&node.receiver);
            for argument in &node.args {
                self.visit_expr(argument);
            }
        }

        fn visit_macro(&mut self, _node: &'ast syn::Macro) {}
        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
    }

    let mut collector = CallCollector::default();
    collector.visit_block(block);
    collector.calls
}

fn producer_function_path(expression: &Expr) -> Option<Vec<String>> {
    let Expr::Path(path) = producer_peel_expr(expression) else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

fn producer_simple_expr_ident(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = producer_peel_expr(expression) else {
        return None;
    };
    (path.qself.is_none() && path.path.leading_colon.is_none() && path.path.segments.len() == 1)
        .then(|| path.path.segments[0].ident.to_string())
}

fn producer_peel_expr(expression: &Expr) -> &Expr {
    match expression {
        Expr::Await(value) => producer_peel_expr(&value.base),
        Expr::Group(value) => producer_peel_expr(&value.expr),
        Expr::Paren(value) => producer_peel_expr(&value.expr),
        Expr::Try(value) => producer_peel_expr(&value.expr),
        other => other,
    }
}

fn resolve_producer_call(
    caller: &ProducerFunctionNode,
    call: &ProducerCall,
    nodes: &BTreeMap<String, ProducerFunctionNode>,
) -> Option<String> {
    let candidates = match call {
        ProducerCall::Function(path) => {
            let expanded = path
                .first()
                .and_then(|binding| caller.call_aliases.get(binding))
                .map(|canonical| {
                    canonical
                        .iter()
                        .cloned()
                        .chain(path.iter().skip(1).cloned())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| path.clone());
            let normalized = expanded
                .iter()
                .filter(|segment| !matches!(segment.as_str(), "crate" | "self" | "super"))
                .cloned()
                .collect::<Vec<_>>();
            nodes
                .values()
                .filter(|node| normalized.len() > 1 || node.owner.is_none())
                .filter(|node| symbol_has_suffix(&node.symbol, &normalized))
                .map(|node| node.key.clone())
                .collect::<Vec<_>>()
        }
        ProducerCall::SelfMethod(method) => nodes
            .values()
            .filter(|node| node.module == caller.module && node.owner == caller.owner)
            .filter(|node| node.signature.ident == method)
            .map(|node| node.key.clone())
            .collect::<Vec<_>>(),
    };
    let [candidate] = candidates.as_slice() else {
        return None;
    };
    Some(candidate.clone())
}

fn collect_producer_call_aliases(items: &[Item]) -> BTreeMap<String, Vec<String>> {
    fn collect(
        tree: &UseTree,
        mut prefix: Vec<String>,
        aliases: &mut BTreeMap<String, Vec<String>>,
    ) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, aliases);
            }
            UseTree::Name(name) => {
                prefix.push(name.ident.to_string());
                aliases.insert(name.ident.to_string(), prefix);
            }
            UseTree::Rename(rename) => {
                prefix.push(rename.ident.to_string());
                if rename.rename != "_" {
                    aliases.insert(rename.rename.to_string(), prefix);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    collect(item, prefix.clone(), aliases);
                }
            }
            UseTree::Glob(_) => {}
        }
    }

    let mut aliases = BTreeMap::new();
    for item in items {
        if let Item::Use(item_use) = item
            && !is_test_like(&item_use.attrs)
        {
            collect(&item_use.tree, Vec::new(), &mut aliases);
        }
    }
    aliases
}

fn symbol_has_suffix(symbol: &str, suffix: &[String]) -> bool {
    let symbol = symbol.split("::").collect::<Vec<_>>();
    suffix.len() <= symbol.len()
        && symbol[symbol.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(left, right)| *left == right)
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

fn is_active_producer_provider(path: &Path) -> bool {
    ACTIVE_PRODUCER_PROVIDER_FILES
        .iter()
        .any(|provider| path == Path::new(provider))
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
    generated_event_payload_aliases: BTreeSet<String>,
    raw_transport_aliases: BTreeSet<String>,
    guard_raw_transport: bool,
    guard_untyped_emit: bool,
    in_test: usize,
    findings: Vec<Finding<Rule>>,
    raw_transport_hits: BTreeMap<(usize, usize), BTreeSet<&'static str>>,
}

impl<'ast> Visit<'ast> for BindingVisitor<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        self.with_test_scope(is_test_like(item_attrs(node)), |this| {
            visit::visit_item(this, node);
        });
    }

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
        if self.in_test == 0 && is_binding_constructor_path(node, &self.binding_aliases) {
            self.findings.push(finding(
                Rule::BareFromStatic,
                self.path.display().to_string(),
                "生产代码不得引用 generated binding constructor；请使用 generated `CONTRACT` / HTTP `ROUTE` / `PROJECTION_INPUTS` / saga `SPEC` / `STEPS` 常量",
            ));
        }
        if self.raw_transport_guard_active()
            && node.path.segments.last().is_some_and(|segment| {
                segment.ident == "publish" || (self.guard_untyped_emit && segment.ident == "emit")
            })
        {
            self.flag_raw_transport(node.span(), "raw publish/emitter function path");
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.with_test_scope(is_test_like(&node.attrs), |this| {
            if this.raw_transport_guard_active()
                && use_tree_mentions_raw_transport(&node.tree, &this.raw_transport_aliases)
            {
                this.flag_raw_transport(node.span(), "raw transport import");
            }
            visit::visit_item_use(this, node);
        });
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if self.raw_transport_guard_active()
            && path_mentions_raw_transport(node, &self.raw_transport_aliases)
        {
            self.flag_raw_transport(node.span(), "raw transport type/value path");
        }
        visit::visit_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if self.raw_transport_guard_active()
            && (node.method == "publish" || (self.guard_untyped_emit && node.method == "emit"))
        {
            self.flag_raw_transport(node.span(), "raw publish/emitter method call");
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.raw_transport_guard_active()
            && macro_tokens_mention_raw_transport(&node.tokens, &self.raw_transport_aliases)
        {
            self.flag_raw_transport(node.span(), "macro-hidden raw transport");
        }
        visit::visit_macro(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        self.with_test_scope(is_test_like(&node.attrs), |this| {
            if this.in_test == 0 && is_trait_impl(node, &this.generated_event_payload_aliases) {
                this.findings.push(finding(
                    Rule::GeneratedEventPayloadImpl,
                    this.path.display().to_string(),
                    "生产代码不得手写 `GeneratedEventPayload`；请使用 generated event DTO",
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

    fn raw_transport_guard_active(&self) -> bool {
        self.guard_raw_transport && self.in_test == 0
    }

    fn flag_raw_transport(&mut self, span: proc_macro2::Span, evidence: &'static str) {
        let start = span.start();
        self.raw_transport_hits
            .entry((start.line, start.column))
            .or_default()
            .insert(evidence);
    }

    fn into_findings(mut self) -> Vec<Finding<Rule>> {
        self.findings
            .extend(self.raw_transport_hits.into_iter().map(
                |((line, column), evidence)| {
                    finding(
                        Rule::RawProducerTransport,
                        format!("{}:{line}:{}", self.path.display(), column + 1),
                        format!(
                            "active HTTP producer execution 不得引用 `Publisher` / `DynPublisher` / `PublishRequest` / `OutboxEmitter` 或直接调用 publish/emit；命中 {}",
                            evidence.into_iter().collect::<Vec<_>>().join(", ")
                        ),
                    )
                },
            ));
        self.findings
    }
}

fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

struct AliasCollector {
    binding_constructors: BindingConstructorAliases,
    generated_event_payload_traits: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for AliasCollector {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        collect_use_tree_aliases(
            &node.tree,
            &mut self.binding_constructors,
            &mut self.generated_event_payload_traits,
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
    generated_event_payload_traits: BTreeSet<String>,
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
        "EventFactBinding",
        "EventFactBinding",
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
        "HttpProducerBinding",
        "HttpProducerBinding",
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
    let generated_event_payload_traits = BTreeSet::from(["GeneratedEventPayload".to_string()]);
    let mut collector = AliasCollector {
        binding_constructors,
        generated_event_payload_traits,
    };
    collector.visit_file(file);
    SourceAliases {
        binding_constructors: collector.binding_constructors,
        generated_event_payload_traits: collector.generated_event_payload_traits,
    }
}

fn collect_raw_transport_aliases(file: &syn::File) -> BTreeSet<String> {
    let mut aliases = RAW_PRODUCER_TRANSPORT_TYPES
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();

    // Imports/type aliases may be declared in any order and may form an alias chain. Iterate to a
    // fixed point so `use self::A as B; type A = dyn diport::Publisher;` is still closed.
    loop {
        let before = aliases.len();
        let mut use_collector = RawTransportUseAliasCollector {
            aliases: &mut aliases,
        };
        use_collector.visit_file(file);
        for item in &file.items {
            collect_raw_transport_type_alias(item, &mut aliases);
        }
        if aliases.len() == before {
            break;
        }
    }
    aliases
}

struct RawTransportUseAliasCollector<'a> {
    aliases: &'a mut BTreeSet<String>,
}

impl<'ast> Visit<'ast> for RawTransportUseAliasCollector<'_> {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        collect_raw_transport_use_aliases(&node.tree, self.aliases);
        visit::visit_item_use(self, node);
    }
}

fn collect_raw_transport_use_aliases(tree: &UseTree, aliases: &mut BTreeSet<String>) {
    match tree {
        UseTree::Path(path) => collect_raw_transport_use_aliases(&path.tree, aliases),
        UseTree::Name(name) => {
            let ident = name.ident.to_string();
            if aliases.contains(&ident) {
                aliases.insert(ident);
            }
        }
        UseTree::Rename(rename) => {
            if aliases.contains(rename.ident.to_string().as_str()) {
                aliases.insert(rename.rename.to_string());
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_raw_transport_use_aliases(item, aliases);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn collect_raw_transport_type_alias(item: &Item, aliases: &mut BTreeSet<String>) {
    match item {
        Item::Type(item) if type_mentions_raw_transport(&item.ty, aliases) => {
            aliases.insert(item.ident.to_string());
        }
        Item::Mod(item) => {
            if let Some((_, nested)) = &item.content {
                for nested_item in nested {
                    collect_raw_transport_type_alias(nested_item, aliases);
                }
            }
        }
        _ => {}
    }
}

fn type_mentions_raw_transport(ty: &Type, aliases: &BTreeSet<String>) -> bool {
    struct RawTransportTypeProbe<'a> {
        aliases: &'a BTreeSet<String>,
        found: bool,
    }

    impl<'ast> Visit<'ast> for RawTransportTypeProbe<'_> {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.found |= path_mentions_raw_transport(path, self.aliases);
            if !self.found {
                visit::visit_path(self, path);
            }
        }
    }

    let mut probe = RawTransportTypeProbe {
        aliases,
        found: false,
    };
    probe.visit_type(ty);
    probe.found
}

fn use_tree_mentions_raw_transport(tree: &UseTree, aliases: &BTreeSet<String>) -> bool {
    match tree {
        UseTree::Path(path) => use_tree_mentions_raw_transport(&path.tree, aliases),
        UseTree::Name(name) => aliases.contains(name.ident.to_string().as_str()),
        UseTree::Rename(rename) => {
            aliases.contains(rename.ident.to_string().as_str())
                || aliases.contains(rename.rename.to_string().as_str())
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_mentions_raw_transport(item, aliases)),
        UseTree::Glob(_) => false,
    }
}

fn path_mentions_raw_transport(path: &syn::Path, aliases: &BTreeSet<String>) -> bool {
    path.segments
        .iter()
        .any(|segment| aliases.contains(segment.ident.to_string().as_str()))
}

fn macro_tokens_mention_raw_transport(
    tokens: &proc_macro2::TokenStream,
    aliases: &BTreeSet<String>,
) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => {
            let ident = ident.to_string();
            aliases.contains(&ident)
                || RAW_PRODUCER_TRANSPORT_METHODS
                    .iter()
                    .any(|method| ident == *method)
        }
        proc_macro2::TokenTree::Group(group) => {
            macro_tokens_mention_raw_transport(&group.stream(), aliases)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

type BindingConstructorAliases = BTreeMap<String, BTreeSet<&'static str>>;

fn collect_use_tree_aliases(
    tree: &UseTree,
    aliases: &mut BindingConstructorAliases,
    generated_event_payload_aliases: &mut BTreeSet<String>,
) {
    match tree {
        UseTree::Path(path) => {
            collect_use_tree_aliases(&path.tree, aliases, generated_event_payload_aliases);
        }
        UseTree::Name(name) => {
            let ident = name.ident.to_string();
            insert_binding_alias(aliases, &ident, &ident);
            if ident == "GeneratedEventPayload" {
                generated_event_payload_aliases.insert(ident);
            }
        }
        UseTree::Rename(rename) => {
            insert_binding_alias(
                aliases,
                &rename.rename.to_string(),
                &rename.ident.to_string(),
            );
            if rename.ident == "GeneratedEventPayload" {
                generated_event_payload_aliases.insert(rename.rename.to_string());
            }
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree_aliases(tree, aliases, generated_event_payload_aliases);
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
        | "EventFactBinding"
        | "HttpRouteEvidence"
        | "HttpRouteBinding"
        | "HttpProducerBinding"
        | "ProjectionInputBinding"
        | "SagaStepBinding" => Some(&["from_static"]),
        "SagaRuntimePolicySpec" => Some(&["from_static"]),
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

fn is_trait_impl(node: &ItemImpl, aliases: &BTreeSet<String>) -> bool {
    let Some((_, path, _)) = &node.trait_ else {
        return false;
    };
    path.segments
        .last()
        .is_some_and(|seg| aliases.contains(&seg.ident.to_string()))
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
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"examples/demo\", \"composition/settings\"]\nresolver = \"2\"\n",
        )?;
        for member in ["examples/demo", "composition/settings"] {
            let manifest = root.join(member).join("Cargo.toml");
            std::fs::create_dir_all(
                manifest
                    .parent()
                    .context("synthetic member manifest must have a parent")?,
            )?;
            std::fs::write(
                manifest,
                format!(
                    "[package]\nname = \"{}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
                    member.replace('/', "-")
                ),
            )?;
        }
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
            "composition/settings/src/lib.rs",
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
        assert_eq!(
            scanned, 4,
            "all workspace members and direct production root shapes must be scanned"
        );
        assert_eq!(
            findings.len(),
            4,
            "each synthetic root must trip the provenance guard: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_source_roots_cover_workspace_compositions_and_direct_journeys() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let roots = production_source_roots(&root)?;
        for relative in [
            "examples/tenancy-consumer",
            "examples/iotdevice",
            "composition/identity",
            "composition/settings",
            "composition/audit",
            "journeys",
            "journeys-fault-matrix",
        ] {
            assert!(
                roots.contains(&root.join(relative)),
                "production provenance scan must include {relative}"
            );
        }
        for relative in ["generated", "xtask"] {
            assert!(
                !roots.contains(&root.join(relative)),
                "{relative} is an owner, not a production provenance consumer"
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
    fn flags_prod_http_producer_binding_mint() -> anyhow::Result<()> {
        let src = r#"
            struct RouteMarker;

            fn mint() {
                let _ = vocab::HttpProducerBinding::<RouteMarker>::from_static(
                    generated::http::identity_v1::login::ROUTE,
                    &[generated::event::identity_v1::session_created::CONTRACT],
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "producer binding mint must stay generated-only"
        );
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_event_fact_binding_mint() -> anyhow::Result<()> {
        let src = r#"
            fn mint() {
                let _ = vocab::EventFactBinding::from_static(
                    generated::event::identity_v1::session_created::CONTRACT,
                    "identity.commands.forged",
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "event fact mint must stay generated-only"
        );
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_generated_event_payload_impl() -> anyhow::Result<()> {
        let src = r#"
            struct ForgedPayload;

            impl vocab::GeneratedEventPayload for ForgedPayload {
                const FACT: vocab::EventFactBinding =
                    generated::event::identity_v1::session_created::FACT;
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(
            findings.len(),
            1,
            "generated payload provenance must stay codegen-owned"
        );
        assert_eq!(findings[0].rule, Rule::GeneratedEventPayloadImpl);
        Ok(())
    }

    #[test]
    fn flags_prod_generated_event_payload_alias_and_glob_impls() -> anyhow::Result<()> {
        for src in [
            r#"
                use vocab::GeneratedEventPayload as GeneratedPayload;

                struct ForgedPayload;
                impl GeneratedPayload for ForgedPayload {
                    const FACT: vocab::EventFactBinding =
                        generated::event::identity_v1::session_created::FACT;
                }
            "#,
            r#"
                use vocab::*;

                struct ForgedPayload;
                impl GeneratedEventPayload for ForgedPayload {
                    const FACT: EventFactBinding =
                        generated::event::identity_v1::session_created::FACT;
                }
            "#,
        ] {
            let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
            assert_eq!(
                findings.len(),
                1,
                "aliases and glob imports must not bypass generated payload ownership"
            );
            assert_eq!(findings[0].rule, Rule::GeneratedEventPayloadImpl);
        }
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
                    "billing.reserve",
                    "billing.release",
                    vocab::SagaRetryClass::Transient,
                );
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
        Ok(())
    }

    #[test]
    fn flags_prod_saga_policy_from_static_call() -> anyhow::Result<()> {
        let src = r#"
            use vocab::SagaRuntimePolicySpec as Policy;

            fn mint() {
                let _ = Policy::from_static(
                    3,
                    30000,
                    vocab::SagaBackoff::Exponential,
                    100,
                    5000,
                    vocab::SagaJitter::Full,
                );
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
                let _ = Spec::from_parts(contract, policy, steps, "sha256:0123");
            }
        "#;
        let findings = scan_file(Path::new("crates/x/src/lib.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BareFromStatic);
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

        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/fault_matrix.rs"), src)?;
        assert_eq!(findings.len(), 1);
        assert!(findings.iter().any(|f| f.rule == Rule::BareFromStatic));
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
    fn flags_alias_aware_raw_transport_in_active_producer_provider() -> anyhow::Result<()> {
        let src = r#"
            use diport::{
                DynPublisher as Bus,
                OutboxEmitter as DurableEmitter,
                PublishRequest as Request,
                Publisher as PublisherPort,
            };

            type Transport = Bus<'static>;

            async fn bypass(
                _transport: Transport,
                publisher: &PublisherPort,
                emitter: &DurableEmitter,
                request: Request,
            ) {
                publisher.publish(request).await;
                emitter.emit(parts()).await;
            }
        "#;
        let findings = scan_file(
            Path::new("adapters/postgres/src/auth_grant_lifecycle.rs"),
            src,
        )?;
        let raw_findings = findings
            .iter()
            .filter(|finding| finding.rule == Rule::RawProducerTransport)
            .collect::<Vec<_>>();
        assert!(
            !raw_findings.is_empty(),
            "renamed imports, chained type alias, parameters and calls must remain visible"
        );
        let subjects = raw_findings
            .iter()
            .map(|finding| finding.subject.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            subjects.len(),
            raw_findings.len(),
            "one syntax site must not emit duplicate raw transport diagnostics: {raw_findings:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_raw_transport_in_cross_file_reachable_helper() -> anyhow::Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-producer-raw-transport-call-graph-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let postgres_src = root.join("adapters/postgres/src");
        std::fs::create_dir_all(&postgres_src)?;
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"adapters/postgres\"]\nresolver = \"2\"\n",
        )?;
        std::fs::write(
            root.join("adapters/postgres/Cargo.toml"),
            "[package]\nname = \"postgres\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        std::fs::write(postgres_src.join("lib.rs"), "")?;
        std::fs::write(
            postgres_src.join("auth_grant_lifecycle.rs"),
            r#"
                use crate::producer_transport_helper::publish_raw as dispatch;

                async fn persist() {
                    dispatch().await;
                }
            "#,
        )?;
        std::fs::write(
            postgres_src.join("producer_transport_helper.rs"),
            r#"
                use diport::{DynPublisher, PublishRequest};

                async fn publish_raw(publisher: &DynPublisher<'_>, request: PublishRequest) {
                    publisher.publish(request).await;
                }

                async fn dead_decoy(publisher: &DynPublisher<'_>, request: PublishRequest) {
                    publisher.publish(request).await;
                }
            "#,
        )?;

        let result = scan_sources(&root);
        std::fs::remove_dir_all(&root)?;
        let (_, findings) = result?;
        let raw_findings = findings
            .iter()
            .filter(|finding| finding.rule == Rule::RawProducerTransport)
            .collect::<Vec<_>>();
        assert!(
            !raw_findings.is_empty(),
            "a provider must not hide raw transport behind a cross-file helper"
        );
        assert!(
            raw_findings
                .iter()
                .all(|finding| finding.subject.contains("producer_transport_helper.rs")),
            "the finding must identify the reachable helper rather than a dead sibling: {raw_findings:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_raw_publish_method_without_transport_type_name() -> anyhow::Result<()> {
        let src = r#"
            async fn bypass(transport: &HiddenTransport, request: HiddenRequest) {
                transport.publish(request).await;
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/policy_repo.rs"), src)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RawProducerTransport),
            "method syntax must not hide raw publish from the producer guard: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn flags_macro_hidden_raw_transport_alias() -> anyhow::Result<()> {
        let src = r#"
            use diport::DynPublisher as Bus;

            fn bypass() {
                install_transport!(Bus::new_box(hidden()));
            }
        "#;
        let findings = scan_file(
            Path::new("adapters/postgres/src/role_binding_lifecycle.rs"),
            src,
        )?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RawProducerTransport),
            "macro token trees must not hide an aliased raw transport: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn cfg_test_transport_bait_does_not_hide_production_bypass() -> anyhow::Result<()> {
        let src = r#"
            #[cfg(test)]
            mod bait {
                use diport::OutboxEmitter;

                async fn emit_only_in_tests(emitter: &OutboxEmitter) {
                    emitter.emit(parts()).await;
                }
            }

            async fn production_bypass(transport: &HiddenTransport, request: HiddenRequest) {
                transport.publish(request).await;
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/config_repo.rs"), src)?;
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::RawProducerTransport)
                .count(),
            1,
            "cfg(test) bait is excluded, but the production bypass must still fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn allows_raw_transport_outside_active_producer_providers() -> anyhow::Result<()> {
        let src = r#"
            use diport::{DynPublisher, PublishRequest};

            async fn relay(publisher: &DynPublisher<'_>, request: PublishRequest) {
                publisher.publish(request).await;
            }
        "#;
        let findings = scan_file(Path::new("adapters/postgres/src/outbox.rs"), src)?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::RawProducerTransport),
            "generic relay infrastructure is outside the active HTTP producer closure: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_active_producer_providers_have_no_raw_transport() -> anyhow::Result<()> {
        let root = workspace_root()?;
        for relative in ACTIVE_PRODUCER_PROVIDER_FILES {
            let content = std::fs::read_to_string(root.join(relative))?;
            let findings = scan_file(Path::new(relative), &content)?;
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule != Rule::RawProducerTransport),
                "{relative} must stay behind producer_tx and never import/call raw transport: {findings:?}"
            );
        }
        let (_, findings) = scan_sources(&root)?;
        let raw_findings = findings
            .iter()
            .filter(|finding| finding.rule == Rule::RawProducerTransport)
            .collect::<Vec<_>>();
        assert!(
            raw_findings.is_empty(),
            "active provider execution-reachable helpers must stay behind producer_tx: {raw_findings:?}"
        );
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

    #[test]
    #[allow(clippy::expect_used)]
    fn generated_event_fact_owner_is_non_vacuous() {
        let root = workspace_root().expect("workspace root");
        let generated_sources =
            rs_files(&root.join("generated/src/event")).expect("generated event sources");
        let mut fact_mints = 0usize;
        let mut payload_impls = 0usize;
        for path in generated_sources {
            let source = std::fs::read_to_string(path).expect("generated event source");
            fact_mints += source
                .matches("::vocab::EventFactBinding::from_static")
                .count();
            payload_impls += source
                .matches("impl ::vocab::GeneratedEventPayload for")
                .count();
        }
        assert!(
            fact_mints >= 6 && payload_impls >= 6,
            "codegen owner must retain real event fact mints and payload impls; fact_mints={fact_mints}, payload_impls={payload_impls}"
        );
    }
}
