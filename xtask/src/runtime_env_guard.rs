//! INVARIANT: RUNTIME-ENV-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::synthetic_red_rejects_ambient_env_bypasses", anti_vacuity = "tests::canonical_inventory_is_the_only_accepted_exception_set" } -- production runtime configuration is captured once through the closed process factory; four named operator-grant readers require an operator-only typed capability and exact caller.
//!
//! This fast, no-compile carrier owns the closed catalog, exact capture/grant inventory, and
//! actionable source diagnostics. Macro expansion and resolved call identity are deliberately not
//! reimplemented here: the registered `rss_runtime_env_funnel` late Dylint is the expanded-HIR
//! backstop for generated modules, cross-file macro re-exports, aliases, and compile-env provenance.

use anyhow::{Context, Result};
use proc_macro2::{Span, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const RUNTIME_SRC: &str = "assemblies/runtime/src";
const READERS: &[&str] = &["var", "var_os", "vars", "vars_os"];

const CONFIG_OWNER: &str = "EnvConfigSource::read";
const CONFIG_CAPTURE_OWNER: &str = "prepare_runtime_kernel";
const CONFIG_CAPTURE_METHOD: &str = "capture_process_snapshot";
const CONFIG_PATH: &str = "assemblies/runtime/src/config.rs";
const LIB_PATH: &str = "assemblies/runtime/src/lib.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    AmbientRead,
    NonCanonicalException,
    MissingCapture,
}

#[derive(Clone, Copy)]
struct GrantException {
    path: &'static str,
    owner: &'static str,
    caller: &'static str,
    constant: &'static str,
}

const GRANT_EXCEPTIONS: &[GrantException] = &[
    GrantException {
        path: "assemblies/runtime/src/operator/projection.rs",
        owner: "load_projection_maintenance_grants_from_command_env",
        caller: "projection_maintenance_operator_receipt",
        constant: "PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV",
    },
    GrantException {
        path: "assemblies/runtime/src/operator/audit_ledger.rs",
        owner: "load_audit_ledger_verify_grants_from_command_env",
        caller: "audit_ledger_verify_operator_subject",
        constant: "AUDIT_LEDGER_VERIFY_OPERATOR_GRANTS_ENV",
    },
    GrantException {
        path: "assemblies/runtime/src/operator/dlq.rs",
        owner: "load_dlq_operator_grants_from_command_env",
        caller: "dlq_operator_receipt",
        constant: "DLQ_OPERATOR_GRANTS_ENV",
    },
    GrantException {
        path: "assemblies/runtime/src/operator/reconcile.rs",
        owner: "load_reconcile_operator_grants_from_command_env",
        caller: "run_reconcile_target_command",
        constant: "RECONCILE_OPERATOR_GRANTS_ENV",
    },
];

pub(crate) struct RuntimeEnvGuard;

impl GovernanceCheck for RuntimeEnvGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "runtime-env guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let sources = load_runtime_sources(&root)?;
        let count = sources.len() - test_only_source_paths(&sources)?.len();
        let findings = validate_root(&root)?;
        Ok((
            format!("{count} runtime production source files satisfy RUNTIME-ENV-FUNNEL-01"),
            findings,
        ))
    }
}

pub(crate) fn validate_root(root: &Path) -> Result<Vec<Finding>> {
    scan_sources(&load_runtime_sources(root)?)
}

pub(crate) fn scan_sources(sources: &[(String, String)]) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut expected = ExpectedInventory::default();
    let excluded = test_only_source_paths(sources)?;
    for (path, source) in sources {
        if excluded.contains(path) {
            continue;
        }
        let file = syn::parse_file(source).map_err(|error| {
            anyhow::anyhow!("runtime-env guard cannot parse production Rust {path}: {error}")
        })?;
        let aliases = collect_aliases(&file, path, &mut findings);
        collect_constants(&file, path, &mut expected);
        let mut scanner = FileScanner {
            path,
            aliases,
            findings: &mut findings,
            expected: &mut expected,
            owner: "module".to_owned(),
            module_depth: 0,
            function_depth: 0,
        };
        scanner.visit_file(&file);
    }
    expected.finish(&mut findings);
    Ok(findings)
}

fn test_only_source_paths(sources: &[(String, String)]) -> Result<BTreeSet<String>> {
    let known = sources
        .iter()
        .map(|(path, source)| (path.as_str(), source.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut live = vec![LIB_PATH.to_owned()];
    let mut visited = BTreeSet::new();
    let mut excluded = BTreeSet::new();
    while let Some(path) = live.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        let Some(source) = known.get(path.as_str()) else {
            continue;
        };
        let file = syn::parse_file(source)
            .with_context(|| format!("runtime-env guard parses module graph source {path}"))?;
        walk_module_items(
            &file.items,
            Path::new(&path),
            &module_base(Path::new(&path)),
            true,
            &known,
            &mut live,
            &mut excluded,
        );
    }
    excluded.retain(|path| !visited.contains(path));
    Ok(excluded)
}

fn walk_module_items(
    items: &[syn::Item],
    file: &Path,
    base: &Path,
    parent_live: bool,
    known: &BTreeMap<&str, &str>,
    live: &mut Vec<String>,
    excluded: &mut BTreeSet<String>,
) {
    for module in items.iter().filter_map(|item| match item {
        syn::Item::Mod(module) => Some(module),
        _ => None,
    }) {
        let module_live = parent_live && attrs_may_be_runtime_production(&module.attrs);
        if let Some((_, nested)) = &module.content {
            walk_module_items(
                nested,
                file,
                &base.join(module.ident.to_string()),
                module_live,
                known,
                live,
                excluded,
            );
            continue;
        }
        let paths = module_path_literals(&module.attrs);
        let targets = if paths.is_empty() {
            let target = {
                let stem = base.join(module.ident.to_string());
                [stem.with_extension("rs"), stem.join("mod.rs")]
                    .into_iter()
                    .find(|candidate| known.contains_key(candidate.to_string_lossy().as_ref()))
            };
            target.into_iter().collect::<Vec<_>>()
        } else {
            paths
                .into_iter()
                .map(|path| {
                    lexical_path(&file.parent().unwrap_or_else(|| Path::new("")).join(path))
                })
                .collect()
        };
        for target in targets {
            let target = target.to_string_lossy().replace('\\', "/");
            if module_live {
                live.push(target);
            } else {
                excluded.insert(target.clone());
                let module_dir = target
                    .strip_suffix("/mod.rs")
                    .or_else(|| target.strip_suffix(".rs"))
                    .unwrap_or(&target);
                excluded.extend(
                    known
                        .keys()
                        .filter(|path| path.starts_with(&format!("{module_dir}/")))
                        .map(|path| (*path).to_owned()),
                );
            }
        }
    }
}

fn lexical_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            _ => normalized.push(component),
        }
    }
    normalized
}

fn module_base(file: &Path) -> PathBuf {
    let parent = file.parent().unwrap_or_else(|| Path::new(""));
    if matches!(
        file.file_name().and_then(|name| name.to_str()),
        Some("lib.rs" | "mod.rs")
    ) {
        parent.to_owned()
    } else {
        parent.join(file.file_stem().unwrap_or_default())
    }
}

fn path_literal(meta: &syn::Meta) -> Option<String> {
    match meta {
        syn::Meta::NameValue(value) if value.path.is_ident("path") => match &value.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(path),
                ..
            }) => Some(path.value()),
            _ => None,
        },
        _ => None,
    }
}

fn collect_module_paths(meta: &syn::Meta, paths: &mut Vec<String>) {
    if let Some(path) = path_literal(meta) {
        paths.push(path);
    } else if let syn::Meta::List(list) = meta
        && list.path.is_ident("cfg_attr")
    {
        let nested = list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .unwrap_or_default();
        if nested.first().is_some_and(cfg_can_be_live) {
            for meta in nested.iter().skip(1) {
                collect_module_paths(meta, paths);
            }
        }
    }
}

fn module_path_literals(attrs: &[syn::Attribute]) -> Vec<String> {
    let mut paths = Vec::new();
    for attr in attrs {
        collect_module_paths(&attr.meta, &mut paths);
    }
    paths
}

fn load_runtime_sources(root: &Path) -> Result<Vec<(String, String)>> {
    let src = root.join(RUNTIME_SRC);
    let paths = crate::src_scan::rs_files(&src)?;
    if paths.is_empty() {
        anyhow::bail!("runtime-env guard: {RUNTIME_SRC} contains no Rust sources");
    }
    let mut sources = Vec::with_capacity(paths.len());
    for path in paths {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("runtime-env guard reads {}", path.display()))?;
        sources.push((rel, source));
    }
    Ok(sources)
}

fn attrs_may_be_runtime_production(attrs: &[syn::Attribute]) -> bool {
    !attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| !cfg_can_be_live(&meta))
    })
}

fn cfg_can_be_live(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => false,
        syn::Meta::NameValue(value)
            if value.path.is_ident("feature")
                && matches!(&value.value, syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(feature),
                    ..
                }) if feature.value() == "integration") =>
        {
            false
        }
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let nested = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .unwrap_or_default();
            if list.path.is_ident("all") {
                nested.iter().all(cfg_can_be_live)
            } else {
                nested.iter().any(cfg_can_be_live)
            }
        }
        syn::Meta::List(list) if list.path.is_ident("not") => true,
        _ => true,
    }
}

fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

#[derive(Default, Clone, PartialEq, Eq)]
struct Aliases {
    roots: BTreeSet<String>,
    modules: BTreeSet<String>,
    functions: BTreeSet<String>,
    macros: BTreeSet<String>,
    dynamic_macros: BTreeSet<String>,
    glob: bool,
}

fn collect_aliases(file: &syn::File, path: &str, findings: &mut Vec<Finding>) -> Aliases {
    let mut collector = AliasCollector {
        aliases: Aliases::default(),
        path,
        findings,
    };
    loop {
        let before = collector.aliases.clone();
        collector.visit_file(file);
        if collector.aliases == before {
            break;
        }
    }
    collector.aliases
}

struct AliasCollector<'a> {
    aliases: Aliases,
    path: &'a str,
    findings: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for AliasCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if attrs_may_be_runtime_production(item_attrs(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_use_tree(
            &item.tree,
            &mut Vec::new(),
            &mut self.aliases,
            self.path,
            self.findings,
            item.span(),
        );
    }

    fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
        if item.ident == "std" {
            self.aliases.roots.insert(
                item.rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string()),
            );
        }
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if attrs_may_be_runtime_production(&item.attrs)
            && let Some(name) = &item.ident
            && macro_has_variable_call(&item.mac.tokens)
        {
            self.aliases.dynamic_macros.insert(name.to_string());
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_runtime_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if attrs_may_be_runtime_production(&statement.attrs) {
            syn::visit::visit_stmt_macro(self, statement);
        }
    }
}

fn collect_use_tree(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut Aliases,
    path: &str,
    findings: &mut Vec<Finding>,
    span: Span,
) {
    match tree {
        syn::UseTree::Path(item) => {
            prefix.push(item.ident.to_string());
            collect_use_tree(&item.tree, prefix, aliases, path, findings, span);
            prefix.pop();
        }
        syn::UseTree::Name(item) => {
            let mut full = prefix.clone();
            full.push(item.ident.to_string());
            record_use_alias(&full, item.ident.to_string(), aliases, path, findings, span);
        }
        syn::UseTree::Rename(item) => {
            let mut full = prefix.clone();
            full.push(item.ident.to_string());
            record_use_alias(
                &full,
                item.rename.to_string(),
                aliases,
                path,
                findings,
                span,
            );
        }
        syn::UseTree::Glob(_)
            if prefix.len() == 2
                && (prefix[0] == "std" || aliases.roots.contains(&prefix[0]))
                && prefix[1] == "env" =>
        {
            if !aliases.glob {
                aliases.glob = true;
                push(
                    findings,
                    Rule::AmbientRead,
                    path,
                    span,
                    "module",
                    "ambient std::env glob import bypasses the runtime environment funnel",
                );
            }
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix, aliases, path, findings, span);
            }
        }
    }
}

fn record_use_alias(
    full: &[String],
    local: String,
    aliases: &mut Aliases,
    path: &str,
    findings: &mut Vec<Finding>,
    span: Span,
) {
    let full = &full[full
        .iter()
        .take_while(|segment| matches!(segment.as_str(), "self" | "crate" | "super"))
        .count()..];
    if full
        .last()
        .is_some_and(|name| GRANT_EXCEPTIONS.iter().any(|grant| *name == grant.owner))
    {
        push(
            findings,
            Rule::NonCanonicalException,
            path,
            span,
            "module",
            "named maintenance reader may not be imported, renamed, or re-exported",
        );
    }
    if full.len() == 1 && aliases.macros.contains(&full[0]) {
        aliases.macros.insert(local.clone());
    }
    if full.len() == 1 && aliases.dynamic_macros.contains(&full[0]) {
        aliases.dynamic_macros.insert(local.clone());
    }
    if full.len() == 1 && (full[0] == "std" || aliases.roots.contains(&full[0]))
        || full.len() == 2
            && full[1] == "self"
            && (full[0] == "std" || aliases.roots.contains(&full[0]))
    {
        aliases.roots.insert(local);
        return;
    }
    let std_root = full
        .first()
        .is_some_and(|root| root == "std" || aliases.roots.contains(root));
    if std_root && full.len() == 2 && matches!(full[1].as_str(), "env" | "option_env" | "include") {
        aliases.macros.insert(local.clone());
    }
    if std_root
        && (full.len() == 2 && full[1] == "env"
            || full.len() == 3 && full[1] == "env" && full[2] == "self")
    {
        if aliases.modules.insert(local) {
            push(
                findings,
                Rule::AmbientRead,
                path,
                span,
                "module",
                "ambient std::env module import bypasses the runtime environment funnel",
            );
        }
    } else if full.len() == 3
        && std_root
        && full[1] == "env"
        && READERS.contains(&full[2].as_str())
        && aliases.functions.insert(local)
    {
        push(
            findings,
            Rule::AmbientRead,
            path,
            span,
            "module",
            "ambient std::env reader import/re-export bypasses the runtime environment funnel",
        );
    }
}

#[derive(Debug, Clone)]
struct ObservedSite {
    path: String,
    line: usize,
}

impl ObservedSite {
    fn new(path: &str, span: Span) -> Self {
        Self {
            path: path.to_owned(),
            line: span.start().line,
        }
    }

    fn render(&self) -> String {
        format!("{}:{}", self.path, self.line)
    }
}

#[derive(Debug, Clone, Copy)]
enum InventoryKind {
    ConfigOwner,
    ConfigRead,
    ConfigCapture,
    GrantSignature,
    GrantRead,
    GrantCall,
    GrantConstant,
}

impl InventoryKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ConfigOwner => "config-owner",
            Self::ConfigRead => "config-read",
            Self::ConfigCapture => "config-capture",
            Self::GrantSignature => "grant-signature",
            Self::GrantRead => "grant-read",
            Self::GrantCall => "grant-call",
            Self::GrantConstant => "grant-constant",
        }
    }
}

#[derive(Debug, Clone)]
struct ObservedConstant {
    site: ObservedSite,
    value: String,
}

#[derive(Debug, Default)]
struct GrantInventory {
    owner_sites: Vec<ObservedSite>,
    signature_sites: Vec<ObservedSite>,
    read_sites: Vec<ObservedSite>,
    call_sites: Vec<ObservedSite>,
    constants: Vec<ObservedConstant>,
}

#[derive(Default)]
struct ExpectedInventory {
    config_owner_sites: Vec<ObservedSite>,
    config_read_sites: Vec<ObservedSite>,
    config_capture_sites: Vec<ObservedSite>,
    grants: BTreeMap<&'static str, GrantInventory>,
}

impl ExpectedInventory {
    fn finish(&self, findings: &mut Vec<Finding>) {
        report_exact_inventory(
            findings,
            Rule::MissingCapture,
            InventoryKind::ConfigOwner,
            &self.config_owner_sites,
            CONFIG_PATH,
            CONFIG_OWNER,
            "canonical EnvConfigSource::read must exist exactly once",
        );
        report_exact_inventory(
            findings,
            Rule::MissingCapture,
            InventoryKind::ConfigRead,
            &self.config_read_sites,
            CONFIG_PATH,
            CONFIG_OWNER,
            "canonical EnvConfigSource::read must contain exactly one std::env::var_os(key.as_str())",
        );
        report_exact_inventory(
            findings,
            Rule::MissingCapture,
            InventoryKind::ConfigCapture,
            &self.config_capture_sites,
            LIB_PATH,
            CONFIG_CAPTURE_OWNER,
            "prepare_runtime_kernel must call RuntimeConfigSnapshot::capture_process_snapshot exactly once",
        );
        for grant in GRANT_EXCEPTIONS {
            let inventory = self.grants.get(grant.owner);
            let empty = GrantInventory::default();
            let inventory = inventory.unwrap_or(&empty);
            let fallback = inventory
                .owner_sites
                .first()
                .map_or(grant.path, |site| site.path.as_str());
            for (kind, sites, suffix) in [
                (
                    InventoryKind::GrantSignature,
                    inventory.signature_sites.as_slice(),
                    "top-level canonical owner must accept OperatorRuntimeCapability exactly once",
                ),
                (
                    InventoryKind::GrantRead,
                    inventory.read_sites.as_slice(),
                    "top-level canonical owner must read its exact std::env::var grant key once",
                ),
                (
                    InventoryKind::GrantCall,
                    inventory.call_sites.as_slice(),
                    "top-level canonical owner must be called once by its exact approved caller with the operator-only capability",
                ),
            ] {
                report_exact_inventory(
                    findings,
                    Rule::NonCanonicalException,
                    kind,
                    sites,
                    fallback,
                    grant.owner,
                    suffix,
                );
            }
            let literal = format!("RSS_{}", grant.constant.trim_end_matches("_ENV"));
            if inventory.constants.len() != 1 || inventory.constants[0].value != literal {
                let sites = inventory
                    .constants
                    .iter()
                    .map(|constant| constant.site.clone())
                    .collect::<Vec<_>>();
                let values = inventory
                    .constants
                    .iter()
                    .map(|constant| format!("{:?}", constant.value))
                    .collect::<Vec<_>>()
                    .join(",");
                let subject = inventory.constants.first().map_or_else(
                    || format!("{} ({})", grant.path, grant.constant),
                    |constant| format!("{} ({})", constant.site.render(), grant.constant),
                );
                findings.push(finding(
                    Rule::NonCanonicalException,
                    subject,
                    format!(
                        "inventory={} expected=1 actual={} sites=[{}] expected_value={literal:?} actual_values=[{values}]; constant must be exactly {literal:?}",
                        InventoryKind::GrantConstant.as_str(),
                        sites.len(),
                        render_sites(&sites),
                    ),
                ));
            }
        }
    }
}

fn report_exact_inventory(
    findings: &mut Vec<Finding>,
    rule: Rule,
    kind: InventoryKind,
    sites: &[ObservedSite],
    fallback_path: &str,
    owner: &str,
    suffix: &str,
) {
    if sites.len() == 1 {
        return;
    }
    let subject = sites.first().map_or_else(
        || format!("{fallback_path} ({owner})"),
        |site| format!("{} ({owner})", site.render()),
    );
    findings.push(finding(
        rule,
        subject,
        format!(
            "inventory={} expected=1 actual={} sites=[{}]; {suffix}",
            kind.as_str(),
            sites.len(),
            render_sites(sites),
        ),
    ));
}

fn render_sites(sites: &[ObservedSite]) -> String {
    sites
        .iter()
        .map(ObservedSite::render)
        .collect::<Vec<_>>()
        .join(",")
}

fn collect_constants(file: &syn::File, path: &str, expected: &mut ExpectedInventory) {
    for item in &file.items {
        if let syn::Item::Const(item) = item
            && attrs_may_be_runtime_production(&item.attrs)
            && let Some(grant) = GRANT_EXCEPTIONS
                .iter()
                .find(|grant| path == grant.path && item.ident == grant.constant)
            && let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) = &*item.expr
        {
            expected
                .grants
                .entry(grant.owner)
                .or_default()
                .constants
                .push(ObservedConstant {
                    site: ObservedSite::new(path, item.span()),
                    value: value.value(),
                });
        }
    }
}

struct FileScanner<'a> {
    path: &'a str,
    aliases: Aliases,
    findings: &'a mut Vec<Finding>,
    expected: &'a mut ExpectedInventory,
    owner: String,
    module_depth: usize,
    function_depth: usize,
}

impl FileScanner<'_> {
    fn reader_path(&self, path: &syn::Path) -> Option<(String, bool)> {
        let raw = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let segments = &raw[raw
            .iter()
            .take_while(|segment| matches!(segment.as_str(), "self" | "crate" | "super"))
            .count()..];
        let last = segments.last()?.clone();
        if !READERS.contains(&last.as_str()) {
            return None;
        }
        let recognized = (segments.len() == 3
            && (segments[0] == "std" || self.aliases.roots.contains(&segments[0]))
            && segments[1] == "env")
            || (segments.len() == 2 && self.aliases.modules.contains(&segments[0]))
            || (segments.len() == 1
                && (self.aliases.functions.contains(&segments[0]) || self.aliases.glob));
        recognized.then_some((
            last,
            path.leading_colon.is_none() && raw.len() == 3 && raw[0] == "std" && raw[1] == "env",
        ))
    }

    fn report_read(
        &mut self,
        api: &str,
        canonical_path: bool,
        args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
        span: Span,
    ) {
        let allowed = self.is_allowed(api, canonical_path, args, span);
        match allowed {
            Some(true) => {}
            Some(false) => push(
                self.findings,
                Rule::NonCanonicalException,
                self.path,
                span,
                &self.owner,
                "ambient reader is in a canonical owner but does not use its exact approved API and key",
            ),
            None => push(
                self.findings,
                Rule::AmbientRead,
                self.path,
                span,
                &self.owner,
                "ambient std::env read bypasses the runtime environment funnel",
            ),
        }
    }

    fn is_allowed(
        &mut self,
        api: &str,
        canonical_path: bool,
        args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
        span: Span,
    ) -> Option<bool> {
        if self.module_depth == 0
            && self.function_depth == 1
            && self.path == CONFIG_PATH
            && self.owner == CONFIG_OWNER
        {
            let exact = canonical_path
                && api == "var_os"
                && args.len() == 1
                && args.first().is_some_and(is_key_as_str);
            if exact {
                self.expected
                    .config_read_sites
                    .push(ObservedSite::new(self.path, span));
            }
            return Some(exact);
        }
        let grant = GRANT_EXCEPTIONS.iter().find(|grant| {
            self.module_depth == 0
                && self.function_depth == 1
                && self.path == grant.path
                && self.owner == grant.owner
        })?;
        let exact = canonical_path
            && api == "var"
            && args.len() == 1
            && args
                .first()
                .is_some_and(|argument| is_exact_ident(argument, grant.constant));
        if exact {
            self.expected
                .grants
                .entry(grant.owner)
                .or_default()
                .read_sites
                .push(ObservedSite::new(self.path, span));
        }
        Some(exact)
    }

    fn scan_macro_tokens(&mut self, macro_name: Option<&str>, tokens: &TokenStream, span: Span) {
        let mut flat = Vec::new();
        let mut spans = Vec::new();
        flatten_code_tokens(tokens.clone(), &mut flat, &mut spans);
        let has_literal = |wanted: &str| {
            flat.iter().enumerate().find_map(|(index, token)| {
                (matches!(token, Token::Ident(name) if name == wanted)
                    && !matches!(
                        index.checked_sub(1).and_then(|before| flat.get(before)),
                        Some(Token::Punct('$'))
                    ))
                .then_some(index)
            })
        };
        let direct = flat.windows(4).position(
            |window| matches!(window, [Token::Ident(root), Token::Punct(':'), Token::Punct(':'), Token::Ident(module)] if (root == "std" || self.aliases.roots.contains(root)) && module == "env"),
        );
        let parameter = flat.windows(8).position(
            |window| matches!(window, [Token::Punct('$'), Token::Ident(_), Token::Punct(':'), Token::Punct(':'), Token::Ident(module), Token::Punct(':'), Token::Punct(':'), Token::Ident(reader)] if module == "env" && READERS.contains(&reader.as_str())),
        );
        let split_path = flat.windows(10).position(|window| {
            matches!(
                window,
                [
                    Token::Punct('$'),
                    Token::Ident(_),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Punct('$'),
                    Token::Ident(_),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Punct('$'),
                    Token::Ident(_)
                ]
            )
        });
        let composed_path = flat
            .windows(6)
            .position(|window| {
                matches!(
                    window,
                    [
                        Token::Punct('$'),
                        Token::Ident(_),
                        Token::Punct(':'),
                        Token::Punct(':'),
                        Token::Punct('$'),
                        Token::Ident(_)
                    ]
                )
            })
            .or_else(|| {
                flat.windows(9).position(|window| {
                    matches!(
                        window,
                        [
                            Token::Punct('$'),
                            Token::Ident(_),
                            Token::Punct(':'),
                            Token::Punct(':'),
                            Token::Ident(_),
                            Token::Punct(':'),
                            Token::Punct(':'),
                            Token::Punct('$'),
                            Token::Ident(_)
                        ]
                    )
                })
            });
        let partial_path = flat.windows(8).position(|window| {
            matches!(
                window,
                [
                    Token::Ident(root),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Punct('$'),
                    Token::Ident(_),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Ident(reader)
                ] if (root == "std" || self.aliases.roots.contains(root))
                    && READERS.contains(&reader.as_str())
            ) || matches!(
                window,
                [
                    Token::Ident(root),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Ident(module),
                    Token::Punct(':'),
                    Token::Punct(':'),
                    Token::Punct('$'),
                    Token::Ident(_)
                ] if (root == "std" || self.aliases.roots.contains(root)) && module == "env"
            )
        });
        let compile_macro = flat.windows(2).enumerate().find_map(|(index, window)| {
            (matches!(
                window,
                [Token::Ident(name), Token::Punct('!')]
                    if (matches!(name.as_str(), "env" | "option_env" | "include")
                        || self.aliases.macros.contains(name))
                        && !matches!(
                            index.checked_sub(1).and_then(|before| flat.get(before)),
                            Some(Token::Punct('$'))
                        )
            ))
            .then_some(index)
        });
        let compile_argument = ["env", "option_env", "include"]
            .iter()
            .find_map(|name| has_literal(name))
            .or_else(|| {
                self.aliases
                    .macros
                    .iter()
                    .find_map(|name| has_literal(name))
            });
        let dynamic_macro = compile_argument.filter(|_| {
            macro_name.is_some_and(|name| self.aliases.dynamic_macros.contains(name))
                || flat.windows(2).any(|window| {
                    matches!(
                        window,
                        [Token::Ident(name), Token::Punct('!')]
                            if self.aliases.dynamic_macros.contains(name)
                    )
                })
        });
        let forwarded_values = has_literal("std")
            .or_else(|| self.aliases.roots.iter().find_map(|root| has_literal(root)))
            .filter(|_| has_literal("env").is_some())
            .filter(|_| READERS.iter().any(|reader| has_literal(reader).is_some()));
        let forwarded_structure = flat
            .windows(5)
            .position(|window| {
                matches!(
                    window,
                    [
                        Token::Ident(root),
                        Token::Punct(','),
                        Token::Ident(module),
                        Token::Punct(','),
                        Token::Ident(reader)
                    ] if (root == "std" || self.aliases.roots.contains(root))
                        && module == "env"
                        && READERS.contains(&reader.as_str())
                )
            })
            .or_else(|| {
                flat.windows(3).position(|window| {
                    matches!(
                        window,
                        [Token::Ident(root), Token::Ident(module), Token::Ident(reader)]
                            if (root == "std" || self.aliases.roots.contains(root))
                                && module == "env"
                                && READERS.contains(&reader.as_str())
                    )
                })
            });
        let forwarded = if macro_name != Some("macro_rules") {
            forwarded_values.or(forwarded_structure)
        } else {
            forwarded_structure
        };
        let grant = GRANT_EXCEPTIONS
            .iter()
            .find_map(|grant| has_literal(grant.owner));
        let alias = flat.iter().enumerate().find_map(|(index, token)| {
            let Token::Ident(name) = token else {
                return None;
            };
            (self.aliases.functions.contains(name)
                || self.aliases.glob && READERS.contains(&name.as_str())
                || self.aliases.modules.contains(name)
                    && matches!(
                        flat.get(index + 3),
                        Some(Token::Ident(reader)) if READERS.contains(&reader.as_str())
                    ))
            .then_some(index)
        });
        let mut hits = [
            (MacroBypassKind::DirectPath, direct),
            (MacroBypassKind::ParameterPath, parameter),
            (MacroBypassKind::SplitPath, split_path),
            (MacroBypassKind::ComposedPath, composed_path),
            (MacroBypassKind::PartialPath, partial_path),
            (MacroBypassKind::CompileMacro, compile_macro),
            (MacroBypassKind::DynamicMacro, dynamic_macro),
            (MacroBypassKind::ForwardedPath, forwarded),
            (MacroBypassKind::GrantReader, grant),
            (MacroBypassKind::AliasPath, alias),
        ]
        .into_iter()
        .filter_map(|(kind, index)| {
            index.map(|index| (kind, spans.get(index).copied().unwrap_or(span)))
        })
        .collect::<Vec<_>>();
        hits.sort_by_key(|(kind, span)| (span.start().line, *kind));
        hits.dedup_by_key(|(kind, span)| (span.start().line, *kind));
        for (kind, hit_span) in hits {
            push(
                self.findings,
                Rule::AmbientRead,
                self.path,
                hit_span,
                &self.owner,
                format!(
                    "detector={}: ambient std::env path or alias inside a macro bypasses the runtime environment funnel",
                    kind.as_str()
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for FileScanner<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if attrs_may_be_runtime_production(item_attrs(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let top_level = self.function_depth == 0;
        let prior = std::mem::replace(&mut self.owner, item.sig.ident.to_string());
        if top_level
            && self.module_depth == 0
            && self.path == CONFIG_PATH
            && self.owner == CONFIG_OWNER
        {
            self.expected
                .config_owner_sites
                .push(ObservedSite::new(self.path, item.span()));
        }
        if top_level
            && self.module_depth == 0
            && let Some(grant) = GRANT_EXCEPTIONS
                .iter()
                .find(|grant| self.path == grant.path && self.owner == grant.owner)
        {
            let inventory = self.expected.grants.entry(grant.owner).or_default();
            inventory
                .owner_sites
                .push(ObservedSite::new(self.path, item.span()));
            if grant_owner_visibility_is_canonical(&item.vis)
                && signature_has_operator_capability(&item.sig)
            {
                inventory
                    .signature_sites
                    .push(ObservedSite::new(self.path, item.sig.span()));
            }
        }
        self.function_depth += 1;
        syn::visit::visit_item_fn(self, item);
        self.function_depth -= 1;
        self.owner = prior;
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let self_name = type_last_ident(&item.self_ty).unwrap_or_else(|| "impl".to_owned());
        for entry in &item.items {
            if let syn::ImplItem::Fn(method) = entry
                && attrs_may_be_runtime_production(&method.attrs)
            {
                let prior = std::mem::replace(
                    &mut self.owner,
                    format!("{self_name}::{}", method.sig.ident),
                );
                if self.function_depth == 0
                    && self.module_depth == 0
                    && self.path == CONFIG_PATH
                    && self.owner == CONFIG_OWNER
                {
                    self.expected
                        .config_owner_sites
                        .push(ObservedSite::new(self.path, method.span()));
                }
                self.function_depth += 1;
                syn::visit::visit_impl_item_fn(self, method);
                self.function_depth -= 1;
                self.owner = prior;
            } else if let syn::ImplItem::Const(item) = entry
                && attrs_may_be_runtime_production(&item.attrs)
            {
                syn::visit::visit_impl_item_const(self, item);
            } else if let syn::ImplItem::Macro(item) = entry
                && attrs_may_be_runtime_production(&item.attrs)
            {
                syn::visit::visit_impl_item_macro(self, item);
            }
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        for raw in module_path_literals(&item.attrs) {
            if !module_path_is_protected(&raw) {
                push(
                    self.findings,
                    Rule::AmbientRead,
                    self.path,
                    item.span(),
                    &self.owner,
                    "production path module must stay within the protected Rust source tree",
                );
            }
        }
        if let Some((_, items)) = &item.content {
            self.module_depth += 1;
            for child in items {
                self.visit_item(child);
            }
            self.module_depth -= 1;
        }
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if attrs_may_be_runtime_production(&statement.attrs) {
            syn::visit::visit_stmt_macro(self, statement);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !attrs_may_be_runtime_production(&local.attrs) {
            return;
        }
        if let (Some(name), Some(syn::Expr::Path(path))) = (
            pat_ident(&local.pat),
            local.init.as_ref().map(|init| transparent(&init.expr)),
        ) {
            if let Some((api, _)) = self.reader_path(&path.path) {
                self.aliases.functions.insert(name.clone());
                push(
                    self.findings,
                    Rule::AmbientRead,
                    self.path,
                    local.span(),
                    &self.owner,
                    format!("local alias `{name}` captures ambient std::env::{api}"),
                );
            } else if path.path.segments.len() == 1
                && self
                    .aliases
                    .functions
                    .contains(&path.path.segments[0].ident.to_string())
            {
                self.aliases.functions.insert(name);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = transparent(&call.func)
            && path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == CONFIG_CAPTURE_METHOD)
        {
            let exact_path = path.path.leading_colon.is_none()
                && path.path.segments.len() == 2
                && path.path.segments[0].ident == "RuntimeConfigSnapshot"
                && path.path.segments[1].ident == CONFIG_CAPTURE_METHOD;
            let exact_owner = self.path == LIB_PATH
                && self.module_depth == 0
                && self.function_depth == 1
                && self.owner == CONFIG_CAPTURE_OWNER
                && call.args.is_empty();
            self.expected
                .config_capture_sites
                .push(ObservedSite::new(self.path, call.span()));
            if !exact_path || !exact_owner {
                push(
                    self.findings,
                    Rule::MissingCapture,
                    self.path,
                    call.span(),
                    &self.owner,
                    "process snapshot factory may only be called once by prepare_runtime_kernel through its exact path",
                );
            }
            return;
        }
        if let syn::Expr::Path(path) = transparent(&call.func)
            && let Some((api, canonical_path)) = self.reader_path(&path.path)
        {
            self.report_read(&api, canonical_path, &call.args, call.span());
            for argument in &call.args {
                self.visit_expr(argument);
            }
            return;
        }
        if let syn::Expr::Path(path) = transparent(&call.func)
            && let Some(grant) = grant_for_path(&path.path)
        {
            let exact = path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
                && self.path == grant.path
                && self.module_depth == 0
                && self.function_depth == 1
                && self.owner == grant.caller
                && call.args.len() == 1
                && call.args.first().is_some_and(|argument| {
                    is_exact_ident(argument, "operator")
                        || grant.caller == "run_reconcile_target_command"
                            && is_exact_operator_capability(argument)
                });
            if exact {
                self.expected
                    .grants
                    .entry(grant.owner)
                    .or_default()
                    .call_sites
                    .push(ObservedSite::new(self.path, call.span()));
            } else {
                push(
                    self.findings,
                    Rule::NonCanonicalException,
                    self.path,
                    call.span(),
                    &self.owner,
                    format!(
                        "{} may only be called by {} with its operator-only grant source",
                        grant.owner, grant.caller
                    ),
                );
            }
            for argument in &call.args {
                self.visit_expr(argument);
            }
            return;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if grant_for_path(&path.path).is_some() {
            push(
                self.findings,
                Rule::NonCanonicalException,
                self.path,
                path.span(),
                &self.owner,
                "named maintenance reader may not be qualified, aliased, or used as a value",
            );
            return;
        }
        if self.reader_path(&path.path).is_some() {
            let canonical_owner = self.module_depth == 0
                && self.function_depth == 1
                && self.path == CONFIG_PATH
                && self.owner == CONFIG_OWNER
                || GRANT_EXCEPTIONS.iter().any(|grant| {
                    self.module_depth == 0
                        && self.function_depth == 1
                        && self.path == grant.path
                        && self.owner == grant.owner
                });
            push(
                self.findings,
                if canonical_owner {
                    Rule::NonCanonicalException
                } else {
                    Rule::AmbientRead
                },
                self.path,
                path.span(),
                &self.owner,
                "ambient std::env reader value bypasses the runtime environment funnel",
            );
            return;
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let macro_name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if matches!(
            macro_name.as_deref(),
            Some("env" | "option_env" | "include")
        ) || macro_name
            .as_deref()
            .is_some_and(|name| self.aliases.macros.contains(name))
        {
            push(
                self.findings,
                Rule::AmbientRead,
                self.path,
                mac.path.span(),
                &self.owner,
                "detector=compile-macro: compile-time environment and source include macros are forbidden in runtime production",
            );
        }
        self.scan_macro_tokens(macro_name.as_deref(), &mac.tokens, mac.span());
    }
}

#[derive(Debug)]
enum Token {
    Ident(String),
    Punct(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MacroBypassKind {
    DirectPath,
    ParameterPath,
    SplitPath,
    ComposedPath,
    PartialPath,
    CompileMacro,
    DynamicMacro,
    ForwardedPath,
    GrantReader,
    AliasPath,
}

impl MacroBypassKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectPath => "direct-path",
            Self::ParameterPath => "parameter-path",
            Self::SplitPath => "split-path",
            Self::ComposedPath => "composed-path",
            Self::PartialPath => "partial-path",
            Self::CompileMacro => "compile-macro",
            Self::DynamicMacro => "dynamic-macro",
            Self::ForwardedPath => "forwarded-path",
            Self::GrantReader => "grant-reader",
            Self::AliasPath => "alias-path",
        }
    }
}

fn macro_has_variable_call(tokens: &TokenStream) -> bool {
    let mut flat = Vec::new();
    let mut spans = Vec::new();
    flatten_code_tokens(tokens.clone(), &mut flat, &mut spans);
    flat.windows(3).any(|window| {
        matches!(
            window,
            [Token::Punct('$'), Token::Ident(_), Token::Punct('!')]
        )
    })
}

fn flatten_code_tokens(tokens: TokenStream, out: &mut Vec<Token>, spans: &mut Vec<Span>) {
    for token in tokens {
        match token {
            TokenTree::Ident(ident) => {
                spans.push(ident.span());
                out.push(Token::Ident(ident.to_string()));
            }
            TokenTree::Punct(punct) => {
                spans.push(punct.span());
                out.push(Token::Punct(punct.as_char()));
            }
            TokenTree::Group(group) => flatten_code_tokens(group.stream(), out, spans),
            TokenTree::Literal(_) => {}
        }
    }
}

fn is_key_as_str(expr: &syn::Expr) -> bool {
    matches!(transparent(expr), syn::Expr::MethodCall(call)
        if call.method == "as_str"
            && call.args.is_empty()
            && matches!(transparent(&call.receiver), syn::Expr::Path(path) if is_exact_ident_path(&path.path, "key")))
}

fn signature_has_operator_capability(signature: &syn::Signature) -> bool {
    signature.inputs.len() == 1
        && signature.inputs.first().is_some_and(|input| {
            matches!(input, syn::FnArg::Typed(argument)
                if matches!(&*argument.pat, syn::Pat::Ident(ident) if ident.ident == "_operator")
                    && type_last_ident(&argument.ty)
                        .is_some_and(|ident| ident == "OperatorRuntimeCapability"))
        })
}

fn grant_owner_visibility_is_canonical(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Restricted(restricted)
        if restricted.in_token.is_none()
            && restricted.path.leading_colon.is_none()
            && restricted.path.segments.len() == 1
            && restricted.path.segments[0].ident == "super")
}

fn is_exact_operator_capability(expr: &syn::Expr) -> bool {
    matches!(transparent(expr), syn::Expr::MethodCall(call)
        if call.method == "operator_capability"
            && call.args.is_empty()
            && matches!(transparent(&call.receiver), syn::Expr::Path(path)
                if is_exact_ident_path(&path.path, "runtime_inputs")))
}

fn module_path_is_protected(raw: &str) -> bool {
    !raw.contains('\\')
        && Path::new(raw)
            .extension()
            .is_some_and(|extension| extension == "rs")
        && Path::new(raw)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn grant_for_path(path: &syn::Path) -> Option<&'static GrantException> {
    let owner = path.segments.last()?.ident.to_string();
    GRANT_EXCEPTIONS.iter().find(|grant| owner == grant.owner)
}

fn is_exact_ident(expr: &syn::Expr, expected: &str) -> bool {
    matches!(transparent(expr), syn::Expr::Path(path) if is_exact_ident_path(&path.path, expected))
}

fn is_exact_ident_path(path: &syn::Path, expected: &str) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 1
        && path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == expected)
}

fn type_last_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        _ => None,
    }
}

fn transparent(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Group(group) => transparent(&group.expr),
        syn::Expr::Paren(paren) => transparent(&paren.expr),
        _ => expr,
    }
}

fn push(
    findings: &mut Vec<Finding>,
    rule: Rule,
    path: &str,
    span: Span,
    owner: &str,
    detail: impl Into<String>,
) {
    findings.push(finding(
        rule,
        format!("{path}:{} ({owner})", span.start().line),
        detail,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_sources() -> Vec<(String, String)> {
        let mut sources = vec![
            (
                CONFIG_PATH.to_owned(),
                include_str!("../fixtures/runtime-env-guard/canonical-config.rs").to_owned(),
            ),
            (
                LIB_PATH.to_owned(),
                include_str!("../fixtures/runtime-env-guard/canonical-lib.rs").to_owned(),
            ),
        ];
        for grant in GRANT_EXCEPTIONS {
            let (caller_parameter, caller_argument) =
                if grant.caller == "run_reconcile_target_command" {
                    (
                        "runtime_inputs: &OperatorRuntimeInputs",
                        "runtime_inputs.operator_capability()",
                    )
                } else {
                    ("operator: OperatorRuntimeCapability<'_>", "operator")
                };
            sources.push((
                grant.path.to_owned(),
                format!(
                    "const {constant}: &str = \"RSS_{literal}\";\n\
                     struct OperatorRuntimeCapability<'a>(&'a ());\n\
                     struct OperatorRuntimeInputs;\n\
                     pub(super) fn {owner}(_operator: OperatorRuntimeCapability<'_>) {{ let _ = std::env::var({constant}); }}\n\
                     fn {caller}({caller_parameter}) {{ {owner}({caller_argument}); }}\n",
                    constant = grant.constant,
                    literal = grant.constant.trim_end_matches("_ENV"),
                    owner = grant.owner,
                    caller = grant.caller,
                ),
            ));
        }
        sources
    }

    fn with_source(path: &str, source: impl Into<String>) -> Vec<(String, String)> {
        let mut sources = canonical_sources();
        sources.push((path.to_owned(), source.into()));
        sources
    }

    fn with_mutated(path: &str, needle: &str, replacement: &str) -> Result<Vec<(String, String)>> {
        let mut sources = canonical_sources();
        let (_, source) = sources
            .iter_mut()
            .find(|(candidate, _)| candidate == path)
            .with_context(|| format!("canonical source missing: {path}"))?;
        let mutated = source.replacen(needle, replacement, 1);
        assert_ne!(*source, mutated, "synthetic red must mutate");
        *source = mutated;
        Ok(sources)
    }

    fn assert_rule(sources: &[(String, String)], rule: Rule) -> Result<Vec<Finding>> {
        let findings = scan_sources(sources)?;
        assert!(
            findings.iter().any(|finding| finding.rule == rule),
            "{findings:#?}"
        );
        Ok(findings)
    }

    #[test]
    fn canonical_inventory_is_the_only_accepted_exception_set() -> Result<()> {
        let findings = scan_sources(&canonical_sources())?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn synthetic_red_rejects_ambient_env_bypasses() -> Result<()> {
        for snippet in [
            "let _ = std::env::var(\"RSS_X\");",
            "let _ = std::env::var_os(\"RSS_X\");",
            "let _ = std::env::vars();",
            "let _ = std::env::vars_os();",
            "use std::env as e; let _ = e::var(\"RSS_X\");",
            "use std::env::var as read; let _ = read(\"RSS_X\");",
            "use std::env::*; let _ = var(\"RSS_X\");",
            "use std as a; use a as b; let _ = b::env::var(\"RSS_X\");",
            "use std::{self as root}; let _ = root::env::var(\"RSS_X\");",
            "use std as root; let _ = self::root::env::var(\"RSS_X\");",
            "use std as root; let _ = crate::root::env::var(\"RSS_X\");",
            "use std as root; let _ = super::super::root::env::var(\"RSS_X\");",
            "use std as root; use super::root as r; let _ = r::env::var(\"RSS_X\");",
            "let read = std::env::var; let _ = read(\"RSS_X\");",
            "macro_rules! m { () => { std::env::var(\"X\") } }",
            "macro_rules! m { ($root:ident) => { $root::env::var(\"X\") } } m!(std);",
            "macro_rules! m { ($root:ident,$module:ident,$reader:ident) => { $root::$module::$reader(\"X\") } } m!(std,env,var);",
            "macro_rules! m { ($root:ident,$module:ident) => { $root::$module::var(\"X\") } } m!(std,env);",
            "macro_rules! m { ($root:ident,$reader:ident) => { $root::env::$reader(\"X\") } } m!(std,var);",
            "macro_rules! m { ($module:ident) => { std::$module::var(\"X\") } } m!(env);",
            "macro_rules! m { ($reader:ident) => { std::env::$reader(\"X\") } } m!(var);",
            "macro_rules! m { ($name:ident) => { $name!(\"X\") } } m!(option_env);",
            "use std::option_env as oe; macro_rules! m { ($name:ident) => { $name!(\"X\") } } m!(oe);",
            "macro_rules! m { ($name:ident) => { $name!(\"X\") } } use self::m as x; x!(option_env);",
            "macro_rules! m { ($name:ident) => { $name!(\"X\") } } macro_rules! outer { () => { m!(option_env) } } outer!();",
            "macro_rules! m { () => {{ use std::env as e; e::var(\"X\") }} }",
            "macro_rules! m { () => { env!(\"RSS_X\") } }",
            "use std::option_env as oe; const X: Option<&str> = oe!(\"RSS_X\");",
            "use std::option_env as oe; use self::oe as x; const X: Option<&str> = x!(\"RSS_X\");",
            "const X: &str = env!(\"RSS_X\");",
            "const X: Option<&str> = option_env!(\"RSS_X\");",
            "include!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"));",
            "#[path = \"../ambient.rs\"] mod ambient;",
            "#[cfg_attr(not(test), path = \"../ambient.rs\")] mod ambient;",
        ] {
            let source = format!("fn bypass() {{ {snippet} }}");
            assert_rule(
                &with_source("assemblies/runtime/src/new.rs", source),
                Rule::AmbientRead,
            )?;
        }
        assert_rule(
            &with_source(
                "assemblies/runtime/src/new.rs",
                "struct S; impl S { const X: Option<String> = std::env::var(\"X\").ok(); }",
            ),
            Rule::AmbientRead,
        )?;
        Ok(())
    }

    #[test]
    fn config_capture_rejects_missing_second_and_wrong_reads() -> Result<()> {
        for replacement in [
            "None::<String>",
            "std::env::var_os(key.as_str()); std::env::var_os(key.as_str())",
            "std::env::var_os(\"RSS_WRONG\")",
        ] {
            assert_rule(
                &with_mutated(CONFIG_PATH, "std::env::var_os(key.as_str())", replacement)?,
                Rule::MissingCapture,
            )?;
        }
        Ok(())
    }

    #[test]
    fn production_snapshot_capture_rejects_a_second_mint_site() -> Result<()> {
        assert_rule(
            &with_source(
                "assemblies/runtime/src/duplicate_capture.rs",
                "fn duplicate_capture() { let _ = RuntimeConfigSnapshot::capture_process_snapshot(); }",
            ),
            Rule::MissingCapture,
        )?;
        Ok(())
    }

    #[test]
    fn diagnostics_preserve_inventory_sites_and_macro_detector_kind() -> Result<()> {
        let duplicate = assert_rule(
            &with_mutated(
                CONFIG_PATH,
                "std::env::var_os(key.as_str())",
                "std::env::var_os(key.as_str());\nlet _ = std::env::var_os(key.as_str())",
            )?,
            Rule::MissingCapture,
        )?;
        let inventory = duplicate
            .iter()
            .find(|finding| finding.rule == Rule::MissingCapture)
            .ok_or_else(|| anyhow::anyhow!("missing inventory finding"))?;
        let inventory_cli = diagnostic::format_finding(inventory);
        assert!(
            inventory_cli.contains("[MissingCapture]")
                && inventory_cli.contains("inventory=config-read")
                && inventory_cli.contains("expected=1 actual=2"),
            "{inventory_cli}"
        );
        assert!(
            inventory_cli.contains(&format!("{CONFIG_PATH}:4"))
                && inventory_cli.contains(&format!("{CONFIG_PATH}:5")),
            "{inventory_cli}"
        );

        let macro_findings = assert_rule(
            &with_source(
                "assemblies/runtime/src/macro_diagnostic.rs",
                "macro_rules! hidden {\n\
                 () => {\n\
                 std::env::var(\"RSS_HIDDEN\")\n\
                 }\n\
                 }",
            ),
            Rule::AmbientRead,
        )?;
        let macro_finding = macro_findings
            .iter()
            .find(|finding| {
                finding.rule == Rule::AmbientRead && finding.subject.contains("macro_diagnostic.rs")
            })
            .ok_or_else(|| anyhow::anyhow!("missing macro finding"))?;
        let macro_cli = diagnostic::format_finding(macro_finding);
        assert!(
            macro_cli.contains("[AmbientRead]")
                && macro_cli.contains("macro_diagnostic.rs:3")
                && macro_cli.contains("detector=direct-path"),
            "{macro_cli}"
        );

        let dynamic_findings = assert_rule(
            &with_source(
                "assemblies/runtime/src/dynamic_macro_diagnostic.rs",
                "macro_rules! invoke { ($name:ident) => { $name!(\"RSS_HIDDEN\") } }\n\
                 const HIDDEN: Option<&str> = invoke!(option_env);",
            ),
            Rule::AmbientRead,
        )?;
        let dynamic_cli = dynamic_findings
            .iter()
            .map(diagnostic::format_finding)
            .find(|line| line.contains("detector=dynamic-macro"))
            .ok_or_else(|| anyhow::anyhow!("missing dynamic-macro detector diagnostic"))?;
        assert!(
            dynamic_cli.contains("dynamic_macro_diagnostic.rs:2"),
            "{dynamic_cli}"
        );
        Ok(())
    }

    #[test]
    fn every_named_grant_rejects_wrong_second_missing_and_detached_reads() -> Result<()> {
        for grant in GRANT_EXCEPTIONS {
            let reader = format!("std::env::var({})", grant.constant);
            for (index, replacement) in [
                "std::env::var(\"RSS_WRONG_GRANT\")".to_owned(),
                format!("{reader}; let _ = std::env::var(\"RSS_SECOND_GRANT\")"),
                format!("{{ use std as root; root::env::var({}) }}", grant.constant),
                "let _ = ();".to_owned(),
            ]
            .into_iter()
            .enumerate()
            {
                let findings = assert_rule(
                    &with_mutated(grant.path, &reader, &replacement)?,
                    Rule::NonCanonicalException,
                )?;
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.detail.contains(if index == 3 {
                            "top-level canonical owner"
                        } else {
                            "exact approved API and key"
                        })),
                    "{}: {findings:#?}",
                    grant.owner
                );
            }
        }
        let projection = &GRANT_EXCEPTIONS[0];
        let mut detached = with_mutated(
            projection.path,
            "let _ = std::env::var(PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV);",
            "let _ = ();",
        )?;
        let (_, projection_source) = detached
            .iter_mut()
            .find(|(path, _)| path == projection.path)
            .context("projection canonical source missing")?;
        projection_source.push_str("\nmod bait { fn load_projection_maintenance_grants_from_command_env() { let _ = std::env::var(super::PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV); } }");
        assert_rule(&detached, Rule::NonCanonicalException)?;
        assert_rule(&detached, Rule::AmbientRead)?;
        let extra_call = with_mutated(
            projection.path,
            "fn projection_maintenance_operator_receipt",
            "fn serving(operator: OperatorRuntimeCapability<'_>) { load_projection_maintenance_grants_from_command_env(operator); }\nfn projection_maintenance_operator_receipt",
        )?;
        assert_rule(&extra_call, Rule::NonCanonicalException)?;
        for replacement in [
            "crate::load_projection_maintenance_grants_from_command_env(operator)",
            "{ use self::load_projection_maintenance_grants_from_command_env as hidden; hidden(operator) }",
            "{ let hidden = load_projection_maintenance_grants_from_command_env; hidden(operator) }",
            "{ macro_rules! invoke { ($f:path, $arg:expr) => { $f($arg) } } invoke!(load_projection_maintenance_grants_from_command_env, operator) }",
        ] {
            assert_rule(
                &with_mutated(
                    projection.path,
                    "load_projection_maintenance_grants_from_command_env(operator)",
                    replacement,
                )?,
                Rule::NonCanonicalException,
            )?;
        }
        let nested = with_mutated(
            projection.path,
            "fn load_projection_maintenance_grants_from_command_env(_operator: OperatorRuntimeCapability<'_>) { let _ = std::env::var(PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV); }",
            "fn decoy() { fn load_projection_maintenance_grants_from_command_env(_operator: OperatorRuntimeCapability<'_>) { let _ = std::env::var(PROJECTION_MAINTENANCE_OPERATOR_GRANTS_ENV); } }",
        )?;
        assert_rule(&nested, Rule::NonCanonicalException)?;
        assert_rule(&nested, Rule::AmbientRead)?;
        Ok(())
    }

    #[test]
    fn test_only_sources_and_non_code_bait_are_green() -> Result<()> {
        let mut sources = with_mutated(
            LIB_PATH,
            "struct OperatorRuntimeCapability",
            "#[cfg(test)] mod config_tests;\nstruct OperatorRuntimeCapability",
        )?;
        sources.push((
            "assemblies/runtime/src/config_tests.rs".to_owned(),
            "fn test_only() { let _ = std::env::var(\"RSS_TEST\"); }".to_owned(),
        ));
        sources.push((
            "assemblies/runtime/src/bait.rs".to_owned(),
            "#[cfg(feature = \"integration\")] const TEST_READ: fn(&str) -> _ = std::env::var;\n#[cfg(test)] macro_rules! test_read { () => { std::env::var(\"RSS_TEST\") } }\nmacro_rules! id { ($env:expr) => { std::convert::identity($env) } }\nmacro_rules! wrap { ($value:expr) => {{ let env = std::convert::identity($value); let var = env; var }} }\nmacro_rules! call { ($f:ident) => { $f!(\"X\") } }\nfn live() { #[cfg(test)] let _ = std::env::var(\"RSS_TEST\"); let _ = r#\"std::env::vars_os()\"#; let _ = id!(1); let _ = wrap!(1); call!(println); }".to_owned(),
        ));
        let findings = scan_sources(&sources)?;
        assert!(findings.is_empty(), "{findings:#?}");

        for declaration in [
            "mod shared;",
            "#[cfg_attr(windows, path = \"other.rs\")] #[cfg_attr(unix, path = \"shared.rs\")] mod live;",
            "#[cfg_attr(unix, cfg_attr(feature = \"x\", path = \"shared.rs\"))] mod live;",
        ] {
            let mut shared = with_mutated(
                LIB_PATH,
                "struct OperatorRuntimeCapability",
                &format!(
                    "{declaration}\n#[cfg(test)] #[path = \"./shared.rs\"] mod test_shared;\nstruct OperatorRuntimeCapability"
                ),
            )?;
            shared.push((
                "assemblies/runtime/src/shared.rs".to_owned(),
                "fn live() { let _ = std::env::var(\"RSS_LIVE\"); }".to_owned(),
            ));
            assert_rule(&shared, Rule::AmbientRead)?;
        }
        Ok(())
    }
}
