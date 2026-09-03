//! Runtime assembly cross-file residual gates.
//!
//! Typed and behavioral facts live beside their canonical owners. This module owns only static
//! risks that Rust visibility/ownership cannot close across production files.
//!
//! INVARIANT: RUNTIME-CONFIG-ESCAPE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::risk_residuals_reject_each_cross_file_bypass", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- reachable production consumers cannot open ambient environment readers or introduce demo/no-op/in-memory configuration fallbacks outside the closed config and purpose-bound maintenance grants.
//! INVARIANT: RUNTIME-SECRET-TRANSFER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::risk_residuals_track_secret_bindings_into_diagnostics", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- raw secret extraction/transfer is restricted to purpose-bound extraction sites and typed sinks; bindings, destructuring, helpers, assertions, macros, diagnostics, and parallel handoffs cannot leak it.
//! INVARIANT: RUNTIME-PROVIDER-BYPASS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::provider_protocol_rejects_missing_duplicate_and_wrong_owner_edges", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- production code cannot construct raw/legacy providers or bypass the unique from-plan, event-output receipt, and completed-owner handoff.
//! INVARIANT: RUNTIME-LIFECYCLE-BYPASS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::risk_residuals_resolve_aliases_and_function_values", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- runtimeexec remains the sole launch/signal/drain owner; assembly code cannot mint another lifecycle owner or raw listener handoff.
//! INVARIANT: RUNTIME-PLAN-BINDING-BYPASS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::risk_residuals_reject_each_cross_file_bypass", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- handwritten factories, raw generated workflow catalogs, alternate compose/wire paths, and second workflow activation owners cannot bypass the typed generated binding closure.
//! INVARIANT: RUNTIME-SERVICE-TOKEN-REPLAY-BYPASS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::risk_residuals_reject_each_cross_file_bypass", anti_vacuity = "tests::risk_residuals_accept_workspace" } -- service-token replay evidence must remain PostgreSQL-owned; process-local replay sets and raw verifier/store seams are forbidden in production assembly code.
//! INVARIANT: POSTGRES-SETUP-TRANSACTION-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::postgres_setup_transaction_rejects_missing_live_edges", anti_vacuity = "tests::postgres_setup_transaction_accepts_live_workspace" } -- serving setup registers constructed pools immediately, rolls back partial construction, and commits only after the complete typed owner exists.
//! INVARIANT: AUDIT-SECURITY-FACT-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::audit_security_fact_boundary_rejects_identity_table_reads", anti_vacuity = "tests::audit_security_fact_boundary_accepts_live_workspace" } -- the audit consumer decodes the sealed redacted fact and the entire production PostgreSQL adapter graph never references the identity credential mapping relation.
//! INVARIANT: PROJECTION-TARGET-ENROLLMENT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "projection_target_enrollment::tests::production_store_requires_canonical_enrollment", anti_vacuity = "projection_target_enrollment::tests::workspace_projection_target_guard_is_green" } -- projection enrollment remains owned by its independent module and is aggregated by this gate.

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::localtx_coverage::attrs_may_be_production;
use crate::phase_helper_expand::transparent_expr;
use crate::workspace_root;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::Visit;

const RUNTIME_SRC_PATH: &str = "assemblies/runtime/src";
const POSTGRES_BUNDLE_PATH: &str = "adapters/postgres/src/bundle.rs";
const POSTGRES_MIGRATION_PATH: &str = "adapters/postgres-migration/src/lib.rs";
const POSTGRES_PROJECTION_EVENTS_PATH: &str = "adapters/postgres/src/projection_events.rs";
const POSTGRES_CONSUMER_TX_PATH: &str = "adapters/postgres/src/consumer_tx.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingStructuralEvidence,
    ForbiddenWiring,
}

pub(crate) struct RuntimeAssemblyResidual;

impl GovernanceCheck for RuntimeAssemblyResidual {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "runtime-assembly-residual"
    }
    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        check_root(&workspace_root()?)
    }
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
    let mut findings = runtime_risk_residual_findings(root)?;
    findings.extend(postgres_setup_transaction_live_findings(root)?);
    findings.extend(audit_security_fact_boundary_findings(root)?);
    findings.extend(crate::projection_target_enrollment::findings(root)?);
    Ok((format!("{} residual findings", findings.len()), findings))
}

fn runtime_risk_residual_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    Ok(runtime_risk_residuals(root)?
        .into_iter()
        .map(ResidualFinding::erase)
        .collect())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResidualFinding {
    risk: ResidualRiskKey,
    subject: String,
    detail: String,
}

impl ResidualFinding {
    fn erase(self) -> Finding<Rule> {
        finding(
            Rule::ForbiddenWiring,
            self.subject,
            format!("{}: {}", self.risk.id(), self.detail),
        )
    }
}

fn runtime_risk_residuals(root: &Path) -> Result<Vec<ResidualFinding>> {
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let test_only_modules = test_only_external_modules(&paths)?;
    let mut production_files = Vec::new();
    for path in paths {
        if test_only_modules.contains(&path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
        {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source =
            fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
        let file =
            syn::parse_file(&source).with_context(|| format!("解析 {} 失败", path.display()))?;
        production_files.push((relative, file));
    }
    let mut secret_sources = BTreeSet::new();
    loop {
        let previous_len = secret_sources.len();
        for (relative, file) in &production_files {
            let discovered = SecretSourceCollector::collect(file, relative, &secret_sources);
            secret_sources.extend(discovered);
        }
        if secret_sources.len() == previous_len {
            break;
        }
    }
    let mut findings = Vec::new();
    for (relative, file) in production_files {
        let aliases = ImportAliasCollector::collect(&file);
        let mut visitor = ResidualVisitor {
            relative: &relative,
            violations: BTreeSet::new(),
            aliases,
            secret_sources: &secret_sources,
            tainted_scopes: Vec::new(),
            secret_sink_depth: 0,
            secret_comparison_depth: 0,
            function_stack: Vec::new(),
        };
        visitor.visit_file(&file);
        for (risk, line, detail) in visitor.violations {
            findings.push(ResidualFinding {
                risk,
                subject: format!("{relative}:{line}"),
                detail,
            });
        }
    }
    findings.extend(provider_protocol_residuals(root)?);
    Ok(findings)
}

struct ResidualVisitor<'a> {
    relative: &'a str,
    violations: BTreeSet<(ResidualRiskKey, usize, String)>,
    aliases: BTreeMap<String, String>,
    secret_sources: &'a BTreeSet<SecretSource>,
    tainted_scopes: Vec<BTreeSet<String>>,
    secret_sink_depth: usize,
    secret_comparison_depth: usize,
    function_stack: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ResidualRiskKey {
    Config,
    Secret,
    Provider,
    Lifecycle,
    Plan,
    Replay,
}
impl ResidualRiskKey {
    fn id(self) -> &'static str {
        match self {
            Self::Config => "RUNTIME-CONFIG-ESCAPE-01",
            Self::Secret => "RUNTIME-SECRET-TRANSFER-01",
            Self::Provider => "RUNTIME-PROVIDER-BYPASS-01",
            Self::Lifecycle => "RUNTIME-LIFECYCLE-BYPASS-01",
            Self::Plan => "RUNTIME-PLAN-BINDING-BYPASS-01",
            Self::Replay => "RUNTIME-SERVICE-TOKEN-REPLAY-BYPASS-01",
        }
    }
}

impl ResidualVisitor<'_> {
    fn push<T: Spanned>(&mut self, risk: ResidualRiskKey, site: &T, detail: impl Into<String>) {
        self.violations
            .insert((risk, site.span().start().line, detail.into()));
    }
    fn path(expr: &syn::Expr) -> Option<Vec<String>> {
        let syn::Expr::Path(path) = expr else {
            return None;
        };
        Some(
            path.path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
        )
    }
    fn allows_env(&self) -> bool {
        matches!(
            self.relative,
            "assemblies/runtime/src/config.rs"
                | "assemblies/runtime/src/operator/audit_ledger.rs"
                | "assemblies/runtime/src/operator/dlq.rs"
                | "assemblies/runtime/src/operator/reconcile.rs"
        )
    }
    fn resolve_path(&self, path: &[String]) -> String {
        let Some((first, rest)) = path.split_first() else {
            return String::new();
        };
        let head = self
            .aliases
            .get(first)
            .cloned()
            .unwrap_or_else(|| first.clone());
        if rest.is_empty() {
            head
        } else {
            format!("{head}::{}", rest.join("::"))
        }
    }

    fn secret_method(&self, method: &str) -> bool {
        matches!(
            method,
            "expose" | "expose_secret" | "copy_secret_allocation" | "transfer_secret_allocation"
        ) || (self.relative == "assemblies/runtime/src/secret_config.rs" && method == "into_string")
    }

    fn current_function(&self) -> &str {
        self.function_stack.last().map(String::as_str).unwrap_or("")
    }

    fn is_canonical_secret_extraction_site(&self) -> bool {
        self.secret_sink_depth > 0
            || self.secret_comparison_depth > 0
            || matches!(
                (self.relative, self.current_function()),
                (
                    "assemblies/runtime/src/secret_config.rs",
                    "differs_from" | "copy_secret_allocation" | "transfer_secret_allocation"
                ) | ("assemblies/runtime/src/config.rs", "hs256_secret")
                    | ("assemblies/runtime/src/operator/service_token.rs", "as_str")
            )
    }

    fn expression_is_secret_derived(&self, expr: &syn::Expr) -> bool {
        let tokens = compact_tokens(expr);
        let idents = token_idents(expr);
        let direct = [
            ".expose(",
            ".expose_secret(",
            ".transfer_secret_allocation(",
        ]
        .iter()
        .any(|needle| tokens.contains(needle));
        let source_call = self
            .secret_sources
            .iter()
            .any(|source| source.matches_tokens(&tokens, &idents));
        let propagated = self
            .tainted_scopes
            .last()
            .is_some_and(|tainted| tainted.iter().any(|name| token_idents(expr).contains(name)));
        direct || source_call || propagated
    }
}

struct ImportAliasCollector {
    aliases: BTreeMap<String, String>,
}

impl ImportAliasCollector {
    fn collect(file: &syn::File) -> BTreeMap<String, String> {
        let mut collector = Self {
            aliases: BTreeMap::new(),
        };
        collector.visit_file(file);
        collector.aliases
    }

    fn collect_tree(
        aliases: &mut BTreeMap<String, String>,
        prefix: &mut Vec<String>,
        tree: &syn::UseTree,
    ) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                Self::collect_tree(aliases, prefix, &path.tree);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let mut path = prefix.clone();
                path.push(name.ident.to_string());
                aliases.insert(name.ident.to_string(), path.join("::"));
            }
            syn::UseTree::Rename(rename) => {
                let mut path = prefix.clone();
                path.push(rename.ident.to_string());
                aliases.insert(rename.rename.to_string(), path.join("::"));
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    Self::collect_tree(aliases, prefix, item);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for ImportAliasCollector {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if item_attrs(item).is_none_or(attrs_may_be_production) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        Self::collect_tree(&mut self.aliases, &mut prefix, &item.tree);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SecretSource {
    name: String,
    receiver_type: Option<String>,
}

impl SecretSource {
    fn matches_tokens(&self, tokens: &str, idents: &BTreeSet<String>) -> bool {
        let call = format!("{}(", self.name);
        match &self.receiver_type {
            Some(receiver) => {
                tokens.contains(&format!(".{call}"))
                    && idents.contains(&type_receiver_marker(receiver))
            }
            None => tokens.contains(&call),
        }
    }

    fn matches_return_body(&self, body: &str, signature: &str) -> bool {
        let call = format!("{}(", self.name);
        match &self.receiver_type {
            Some(receiver) => {
                body.contains(&format!(".{call}"))
                    && (body.contains(&type_receiver_marker(receiver))
                        || signature.contains(receiver))
            }
            None => body.contains(&call),
        }
    }
}

struct SecretSourceCollector<'a> {
    sources: BTreeSet<SecretSource>,
    known_sources: &'a BTreeSet<SecretSource>,
    include_into_string: bool,
    receiver_type: Option<String>,
}

impl<'a> SecretSourceCollector<'a> {
    fn collect(
        file: &syn::File,
        relative: &str,
        known_sources: &'a BTreeSet<SecretSource>,
    ) -> BTreeSet<SecretSource> {
        let mut collector = Self {
            sources: BTreeSet::new(),
            known_sources,
            include_into_string: relative == "assemblies/runtime/src/secret_config.rs",
            receiver_type: None,
        };
        collector.visit_file(file);
        collector.sources
    }

    fn body_returns_secret(
        &self,
        block: &syn::Block,
        output: &syn::ReturnType,
        signature: &impl quote::ToTokens,
    ) -> bool {
        let output = compact_tokens(output);
        let raw_output = output.contains("String")
            || output.contains("str")
            || output.contains("[u8]")
            || output.contains("SecretText");
        let body = compact_tokens(block);
        let signature = compact_tokens(signature);
        raw_output
            && (body.contains(".expose(")
                || body.contains(".expose_secret(")
                || body.contains(".transfer_secret_allocation(")
                || (self.include_into_string && body.contains(".into_string("))
                || self
                    .known_sources
                    .iter()
                    .any(|source| source.matches_return_body(&body, &signature)))
    }

    fn record(&mut self, name: String) {
        self.sources.insert(SecretSource {
            name,
            receiver_type: self.receiver_type.clone(),
        });
    }
}

impl<'ast> Visit<'ast> for SecretSourceCollector<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if item_attrs(item).is_none_or(attrs_may_be_production) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs)
            && self.body_returns_secret(&item.block, &item.sig.output, &item.sig)
        {
            self.record(item.sig.ident.to_string());
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let previous = self.receiver_type.take();
        self.receiver_type = type_receiver_name(&item.self_ty);
        syn::visit::visit_item_impl(self, item);
        self.receiver_type = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs)
            && self.body_returns_secret(&item.block, &item.sig.output, &item.sig)
        {
            self.record(item.sig.ident.to_string());
        }
    }
}

fn type_receiver_name(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    Some(path.path.segments.last()?.ident.to_string())
}

fn type_receiver_marker(name: &str) -> String {
    let mut marker = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_uppercase() && index > 0 {
            marker.push('_');
        }
        marker.extend(character.to_lowercase());
    }
    marker
}

fn item_attrs(item: &syn::Item) -> Option<&[syn::Attribute]> {
    Some(match item {
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
        syn::Item::Verbatim(_) => return None,
        _ => return None,
    })
}

fn token_idents<T: quote::ToTokens>(node: &T) -> BTreeSet<String> {
    fn walk(stream: proc_macro2::TokenStream, out: &mut BTreeSet<String>) {
        for token in stream {
            match token {
                proc_macro2::TokenTree::Ident(ident) => {
                    out.insert(ident.to_string());
                }
                proc_macro2::TokenTree::Group(group) => walk(group.stream(), out),
                _ => {}
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(node.to_token_stream(), &mut out);
    out
}

fn collect_pattern_bindings(pattern: &syn::Pat, out: &mut BTreeSet<String>) {
    struct Collector<'a>(&'a mut BTreeSet<String>);
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_pat_ident(&mut self, ident: &'ast syn::PatIdent) {
            self.0.insert(ident.ident.to_string());
            syn::visit::visit_pat_ident(self, ident);
        }
    }
    Collector(out).visit_pat(pattern);
}

fn macro_first_expression(mac: &syn::Macro) -> Option<syn::Expr> {
    let mut first = proc_macro2::TokenStream::new();
    for token in mac.tokens.clone() {
        if matches!(&token, proc_macro2::TokenTree::Punct(punct) if punct.as_char() == ',') {
            break;
        }
        first.extend([token]);
    }
    syn::parse2(first).ok()
}

fn macro_has_safe_secret_comparison(mac: &syn::Macro) -> bool {
    let Some(syn::Expr::Binary(binary)) = macro_first_expression(mac) else {
        return false;
    };
    let protected = |tokens: &str| {
        [
            ".expose(",
            ".expose_secret(",
            ".copy_secret_allocation(",
            ".transfer_secret_allocation(",
        ]
        .iter()
        .map(|needle| tokens.matches(needle).count())
        .sum::<usize>()
    };
    let expression_tokens = compact_tokens(&binary);
    let all_tokens = compact_tokens(&mac.tokens);
    matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
        && protected(&expression_tokens) > 0
        && protected(&all_tokens) == protected(&expression_tokens)
}

impl<'ast> Visit<'ast> for ResidualVisitor<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if item_attrs(item).is_none_or(attrs_may_be_production) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            self.tainted_scopes.push(BTreeSet::new());
            self.function_stack.push(item.sig.ident.to_string());
            syn::visit::visit_item_fn(self, item);
            self.function_stack.pop();
            self.tainted_scopes.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            self.tainted_scopes.push(BTreeSet::new());
            self.function_stack.push(item.sig.ident.to_string());
            syn::visit::visit_impl_item_fn(self, item);
            self.function_stack.pop();
            self.tainted_scopes.pop();
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let tokens = compact_tokens(item);
        if !self.allows_env() && (tokens.contains("std::env") || tokens.contains("std::envas")) {
            self.push(
                ResidualRiskKey::Config,
                item,
                "ambient env import outside a purpose-bound owner",
            );
        }
        if matches!(item.vis, syn::Visibility::Public(_)) && tokens.contains("ShutdownStack") {
            self.push(
                ResidualRiskKey::Lifecycle,
                item,
                "public lifecycle capability re-export",
            );
        }
        if tokens.contains("runtimeexec::*") {
            self.push(
                ResidualRiskKey::Lifecycle,
                item,
                "glob import can hide a second runtime launch owner",
            );
        }
        if tokens.contains("bootstrap::*") || tokens.contains("modules_gen::*") {
            self.push(
                ResidualRiskKey::Plan,
                item,
                "glob import can hide a generated binding bypass",
            );
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let mut purpose_bound_secret_sink = false;
        if let Some(path) = Self::path(&call.func) {
            let joined = self.resolve_path(&path);
            let last = joined.rsplit("::").next().unwrap_or("");
            purpose_bound_secret_sink = [
                "VaultSigner::new_rss_access",
                "VaultSigner::new_rss_access_allow_http",
                "VaultSecretResolver::new",
                "VaultKeyProvider::new",
                "aws_sdk_s3::config::Credentials::new",
                "DomainHttpTargetConfig::new",
            ]
            .iter()
            .any(|sink| joined.ends_with(sink));
            if !self.allows_env()
                && matches!(last, "var" | "var_os")
                && (joined == "std::env::var" || joined == "std::env::var_os")
            {
                self.push(
                    ResidualRiskKey::Config,
                    call,
                    format!("ambient reader `{joined}`"),
                );
            }
            if joined.ends_with("ProviderFactoryDispatch::from_catalog")
                && self.relative != "assemblies/runtime/src/provider_output.rs"
                && self.relative != "assemblies/runtime/src/phase/provider.rs"
            {
                self.push(
                    ResidualRiskKey::Provider,
                    call,
                    "provider catalog claimed outside provider phase",
                );
            }
            if (joined.ends_with("runtimeexec::launch")
                || joined.ends_with("runtimeexec::launch_startup")
                || joined.ends_with("runtimeexec::launch_startup_until"))
                && self.relative != "assemblies/runtime/src/phase/launch.rs"
                && self.relative != "assemblies/runtime/src/test_support.rs"
            {
                self.push(
                    ResidualRiskKey::Lifecycle,
                    call,
                    "second runtime launch owner",
                );
            }
            if joined.ends_with("runtimeexec::launch")
                && call.args.iter().any(|argument| {
                    let tokens = compact_tokens(argument);
                    tokens.contains("vec![") || tokens.contains("Vec::")
                })
            {
                self.push(
                    ResidualRiskKey::Lifecycle,
                    call,
                    "raw listener vector handed directly to runtime launch",
                );
            }
            if matches!(
                joined.as_str(),
                "tokio::signal::ctrl_c"
                    | "tokio::signal::unix::signal"
                    | "tokio::signal::windows::ctrl_c"
                    | "tokio::signal::windows::ctrl_break"
            ) {
                self.push(
                    ResidualRiskKey::Lifecycle,
                    call,
                    "assembly attempted to install a second process signal owner",
                );
            }
            if last == "compose_bindings"
                && self.relative != "assemblies/runtime/src/plan/domain_exec.rs"
            {
                self.push(
                    ResidualRiskKey::Plan,
                    call,
                    "compose_bindings outside validated plan owner",
                );
            }
            if last == "wire_domains" && self.relative != "assemblies/runtime/src/phase/domains.rs"
            {
                self.push(
                    ResidualRiskKey::Plan,
                    call,
                    "generated wire_domains outside phase handoff",
                );
            }
            if joined.ends_with("WorkflowActivationPlan::select")
                && self.relative != "assemblies/runtime/src/plan.rs"
                && self.relative != "assemblies/runtime/src/runtime_inventory.rs"
            {
                self.push(
                    ResidualRiskKey::Plan,
                    call,
                    "second workflow activation owner",
                );
            }
        }
        if purpose_bound_secret_sink {
            self.secret_sink_depth += 1;
        }
        syn::visit::visit_expr_call(self, call);
        if purpose_bound_secret_sink {
            self.secret_sink_depth -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if self.secret_method(&method) && !self.is_canonical_secret_extraction_site() {
            self.push(
                ResidualRiskKey::Secret,
                call,
                format!("raw secret method `{method}` outside a purpose-bound extraction site"),
            );
        }
        if method == "select"
            && compact_tokens(&call.receiver).contains("WorkflowActivationPlan")
            && self.relative != "assemblies/runtime/src/plan.rs"
            && self.relative != "assemblies/runtime/src/runtime_inventory.rs"
        {
            self.push(
                ResidualRiskKey::Plan,
                call,
                "second workflow activation owner",
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        self.secret_comparison_depth += 1;
        syn::visit::visit_expr_binary(self, binary);
        self.secret_comparison_depth -= 1;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        syn::visit::visit_local(self, local);
        let Some(init) = &local.init else {
            return;
        };
        if !self.expression_is_secret_derived(&init.expr) {
            return;
        }
        if let Some(scope) = self.tainted_scopes.last_mut() {
            collect_pattern_bindings(&local.pat, scope);
        }
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, assign);
        if !self.expression_is_secret_derived(&assign.right) {
            return;
        }
        let syn::Expr::Path(target) = assign.left.as_ref() else {
            return;
        };
        let Some(binding) = target.path.get_ident() else {
            return;
        };
        if let Some(scope) = self.tainted_scopes.last_mut() {
            scope.insert(binding.to_string());
        }
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        let path = expr
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let resolved = self.resolve_path(&path);
        let ident = resolved.rsplit("::").next().unwrap_or("");
        if matches!(
            ident,
            "DemoRuntimeConfig" | "NoopRuntimeConfig" | "InMemoryRuntimeConfig"
        ) {
            self.push(
                ResidualRiskKey::Config,
                expr,
                format!("production fallback `{ident}`"),
            );
        }
        if matches!(
            ident,
            "RawProvider" | "LegacyProvider" | "ProviderOutputParts"
        ) {
            self.push(
                ResidualRiskKey::Provider,
                expr,
                format!("raw or legacy provider seam `{ident}`"),
            );
        }
        if ident == "ShutdownStack" && self.relative != "assemblies/runtime/src/provider_output.rs"
        {
            self.push(
                ResidualRiskKey::Lifecycle,
                expr,
                "assembly-owned ShutdownStack",
            );
        }
        if matches!(
            ident,
            "PROJECTION_INPUTS"
                | "PROJECTION_INPUT_GENERATION"
                | "PROJECTION_DEFINITIONS"
                | "UnsupportedProjection"
        ) {
            self.push(
                ResidualRiskKey::Plan,
                expr,
                format!("raw workflow catalog `{ident}`"),
            );
        }
        if matches!(
            ident,
            "ProcessLocalReplay"
                | "InMemoryReplayStore"
                | "RawServiceTokenVerifier"
                | "RawReplayStore"
        ) {
            self.push(
                ResidualRiskKey::Replay,
                expr,
                format!("process-local/raw replay seam `{ident}`"),
            );
        }
        if self.relative.ends_with("operator/service_token.rs")
            && matches!(ident, "HashSet" | "BTreeSet" | "DashMap" | "Mutex")
        {
            self.push(
                ResidualRiskKey::Replay,
                expr,
                format!("process-local replay storage `{ident}`"),
            );
        }
        if (resolved.ends_with("runtimeexec::launch")
            || resolved.ends_with("runtimeexec::launch_startup")
            || resolved.ends_with("runtimeexec::launch_startup_until"))
            && self.relative != "assemblies/runtime/src/phase/launch.rs"
            && self.relative != "assemblies/runtime/src/test_support.rs"
        {
            self.push(
                ResidualRiskKey::Lifecycle,
                expr,
                "runtime launch capability referenced outside its owner",
            );
        }
        if (resolved.ends_with("bootstrap::compose_bindings")
            || resolved.ends_with("modules_gen::wire_domains"))
            && self.relative != "assemblies/runtime/src/plan/domain_exec.rs"
            && self.relative != "assemblies/runtime/src/phase/domains.rs"
        {
            self.push(
                ResidualRiskKey::Plan,
                expr,
                "generated binding capability referenced outside its owner",
            );
        }
        if resolved.ends_with("EnvSecret::transfer_secret_allocation")
            && self.secret_sink_depth == 0
        {
            self.push(
                ResidualRiskKey::Secret,
                expr,
                "secret transfer function referenced outside a purpose-bound sink",
            );
        }
        syn::visit::visit_expr_path(self, expr);
    }

    fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
        let ident = ty
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if ident == "StartupPlan" {
            self.push(
                ResidualRiskKey::Lifecycle,
                ty,
                "assembly attempted to mint a second startup transaction plan",
            );
        }
        if self.relative.ends_with("operator/service_token.rs")
            && matches!(ident.as_str(), "HashSet" | "BTreeSet" | "DashMap" | "Mutex")
        {
            self.push(
                ResidualRiskKey::Replay,
                ty,
                format!("process-local replay storage `{ident}`"),
            );
        }
        if matches!(ident.as_str(), "ProviderBuild" | "CompletedProviderBuild")
            && !matches!(
                self.relative,
                "assemblies/runtime/src/provider_output.rs"
                    | "assemblies/runtime/src/phase.rs"
                    | "assemblies/runtime/src/phase/provider.rs"
                    | "assemblies/runtime/src/phase/infra.rs"
                    | "assemblies/runtime/src/phase/domains.rs"
            )
        {
            self.push(
                ResidualRiskKey::Provider,
                ty,
                format!("provider transaction owner `{ident}` escaped its closed phase graph"),
            );
        }
        syn::visit::visit_type_path(self, ty);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let diagnostic_sink = matches!(
            name.as_str(),
            "trace"
                | "debug"
                | "info"
                | "warn"
                | "error"
                | "event"
                | "println"
                | "eprintln"
                | "format"
                | "format_args"
        );
        let proof_only_macro = matches!(name.as_str(), "assert" | "debug_assert" | "ensure")
            && macro_has_safe_secret_comparison(mac);
        let tokens = compact_tokens(&mac.tokens);
        let idents = token_idents(&mac.tokens);
        let direct_secret = [
            "expose",
            "expose_secret",
            "copy_secret_allocation",
            "transfer_secret_allocation",
        ]
        .iter()
        .any(|ident| idents.contains(*ident));
        let source_call = self
            .secret_sources
            .iter()
            .any(|source| source.matches_tokens(&tokens, &idents));
        let propagated_secret = self
            .tainted_scopes
            .last()
            .is_some_and(|tainted| tainted.iter().any(|binding| idents.contains(binding)));
        if (direct_secret && !proof_only_macro)
            || (diagnostic_sink && (propagated_secret || source_call))
        {
            self.push(
                ResidualRiskKey::Secret,
                mac,
                "unredacted secret in diagnostic macro",
            );
        }
        for ident in &idents {
            let resolved = self
                .aliases
                .get(ident)
                .cloned()
                .unwrap_or_else(|| ident.clone());
            if resolved.ends_with("runtimeexec::launch") {
                self.push(
                    ResidualRiskKey::Lifecycle,
                    mac,
                    "macro can expand a second runtime launch owner",
                );
            }
            if resolved.ends_with("bootstrap::compose_bindings")
                || resolved.ends_with("modules_gen::wire_domains")
            {
                self.push(
                    ResidualRiskKey::Plan,
                    mac,
                    "macro can expand a generated binding bypass",
                );
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn provider_protocol_residuals(root: &Path) -> Result<Vec<ResidualFinding>> {
    if !root
        .join("assemblies/runtime/src/phase/provider.rs")
        .exists()
        && !root
            .join("assemblies/runtime/src/phase/domains.rs")
            .exists()
    {
        return Ok(Vec::new());
    }
    #[derive(Default)]
    struct Inventory {
        from_execution_plan: Vec<(String, usize)>,
        wire_event_transport: Vec<(String, usize)>,
        finish: Vec<(String, usize)>,
    }
    struct Collector<'a> {
        relative: &'a str,
        aliases: BTreeMap<String, String>,
        inventory: &'a mut Inventory,
    }
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            if item_attrs(item).is_none_or(attrs_may_be_production) {
                syn::visit::visit_item(self, item);
            }
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Some(path) = ResidualVisitor::path(&call.func) {
                let first = path.first().cloned().unwrap_or_default();
                let head = self.aliases.get(&first).cloned().unwrap_or(first);
                let joined = if path.len() > 1 {
                    format!("{head}::{}", path[1..].join("::"))
                } else {
                    head
                };
                let site = (self.relative.to_owned(), call.span().start().line);
                if joined.ends_with("ProviderBuild::from_execution_plan") {
                    self.inventory.from_execution_plan.push(site);
                } else if joined.ends_with("wire_event_transport") {
                    self.inventory.wire_event_transport.push(site);
                }
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "finish" && compact_tokens(&call.receiver) == "provider_build" {
                self.inventory
                    .finish
                    .push((self.relative.to_owned(), call.span().start().line));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }

    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let test_only = test_only_external_modules(&paths)?;
    let mut inventory = Inventory::default();
    for path in paths {
        if test_only.contains(&path)
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
        {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "assemblies/runtime/src/test_support.rs" {
            continue;
        }
        let file = parse_rust_file(&path)?;
        let aliases = ImportAliasCollector::collect(&file);
        Collector {
            relative: &relative,
            aliases,
            inventory: &mut inventory,
        }
        .visit_file(&file);
    }

    let expected = [
        (
            "ProviderBuild::from_execution_plan",
            &inventory.from_execution_plan,
            "assemblies/runtime/src/phase/provider.rs",
        ),
        (
            "wire_event_transport",
            &inventory.wire_event_transport,
            "assemblies/runtime/src/phase/domains.rs",
        ),
        (
            "provider_build.finish",
            &inventory.finish,
            "assemblies/runtime/src/phase/domains.rs",
        ),
    ];
    let mut findings = Vec::new();
    for (edge, sites, owner) in expected {
        if sites.len() == 1 && sites[0].0 == owner {
            continue;
        }
        findings.push(ResidualFinding {
            risk: ResidualRiskKey::Provider,
            subject: owner.to_owned(),
            detail: format!(
                "provider receipt/completion edge `{edge}` must have one production call in `{owner}`; sites={sites:?}"
            ),
        });
    }
    Ok(findings)
}

fn collect_rust_sources(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("读目录 {} 失败", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let ty = entry.file_type()?;
        if ty.is_dir() {
            collect_rust_sources(&path, paths)?;
        } else if ty.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(())
}

fn test_only_external_modules(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    struct Collector {
        names: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if item.content.is_none() && !attrs_may_be_production(&item.attrs) {
                self.names.insert(item.ident.to_string());
            } else if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }
    }

    let mut excluded = BTreeSet::new();
    for path in paths {
        let source =
            fs::read_to_string(path).with_context(|| format!("读 {} 失败", path.display()))?;
        let file =
            syn::parse_file(&source).with_context(|| format!("解析 {} 失败", path.display()))?;
        let mut collector = Collector {
            names: BTreeSet::new(),
        };
        collector.visit_file(&file);
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("");
        let module_base = if matches!(stem, "lib" | "main" | "mod") {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        for name in collector.names {
            for candidate in [
                module_base.join(format!("{name}.rs")),
                module_base.join(&name).join("mod.rs"),
            ] {
                if candidate.exists() {
                    excluded.insert(candidate);
                }
            }
        }
    }
    Ok(excluded)
}

fn postgres_setup_transaction_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let path = root.join(POSTGRES_BUNDLE_PATH);
    let migration_path = root.join(POSTGRES_MIGRATION_PATH);
    let projection_path = root.join(POSTGRES_PROJECTION_EVENTS_PATH);
    if !path.exists() || !migration_path.exists() || !projection_path.exists() {
        return Ok(vec![finding(
            Rule::ForbiddenWiring,
            POSTGRES_BUNDLE_PATH,
            "缺少 serving validation 或 migrator registration 的受保护生产 carrier",
        )]);
    }
    let file = parse_rust_file(&path)?;
    let migration = parse_rust_file(&migration_path)?;
    let projection = parse_rust_file(&projection_path)?;
    let setup = unique_production_inherent_method(&file, "PgRuntimeDeps", "connect_serving_inner");
    let serving_canonical =
        setup.is_some_and(|method| postgres_setup_transaction_is_canonical(&method.block));
    let migrator_canonical = migration_projection_registration_is_canonical(&migration);
    let serving_api_closed = projection_registration_is_test_support_only(&projection);
    if serving_canonical && migrator_canonical && serving_api_closed {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        POSTGRES_BUNDLE_PATH,
        format!(
            "serving 必须只校验 plan-selected projection capture 且 disabled 不访问 generation；production migrator 仍登记 definition ledger；serving setup 失败 await rollback，成功 owner 后唯一 commit；serving_canonical={serving_canonical} migrator_canonical={migrator_canonical} serving_api_closed={serving_api_closed}"
        ),
    )])
}

fn migration_projection_registration_is_canonical(file: &syn::File) -> bool {
    let Some(register) = unique_production_function(file, "register_projection_input_bindings")
    else {
        return false;
    };
    let Some(run) = unique_production_function(file, "run_and_verify") else {
        return false;
    };
    let register_tokens = compact_tokens(&register.block);
    let run_tokens = compact_tokens(&run.block);
    register_tokens.contains("postgres_migration_inventory::projection_inputs()")
        && register_tokens.contains("postgres_migration_inventory::projection_input_generation()")
        && register_tokens.contains("public.rss_register_projection_input_binding")
        && register_tokens
            .contains("pool.begin().await.map_err(MigrationError::ProjectionBindings)?")
        && register_tokens.contains("tx.commit().await.map_err(MigrationError::ProjectionBindings)")
        && run_tokens.contains("verify_exact_ledger(pool).await?;")
        && run_tokens.contains("verify_legacy_plaintext_zero_stock(pool).await?;")
        && run_tokens.ends_with("register_projection_input_bindings(pool).await}")
}

fn projection_registration_is_test_support_only(file: &syn::File) -> bool {
    let methods = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) if compact_tokens(&item.self_ty) == "PgStore" => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == "register_projection_input_bindings" =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        return false;
    };
    method
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .map(compact_tokens)
        .collect::<String>()
        == "#[cfg(any(test,feature=\"test-support\",feature=\"fault-matrix-test-support\"))]"
}

fn audit_security_fact_boundary_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let consumer_path = root.join(POSTGRES_CONSUMER_TX_PATH);
    let consumer = parse_rust_file(&consumer_path)?;
    let mut findings = Vec::new();
    if !compact_tokens(&consumer).contains("security_audit_command_from_message") {
        findings.push(finding(
            Rule::ForbiddenWiring,
            POSTGRES_CONSUMER_TX_PATH,
            "audit security-event consumer must decode the sealed redacted fact command",
        ));
    }

    let postgres_src = root.join("adapters/postgres/src");
    let mut paths = Vec::new();
    collect_rust_sources(&postgres_src, &mut paths)?;
    let test_only = test_only_external_modules(&paths)?;
    for path in paths {
        if test_only.contains(&path)
            || path
                .components()
                .any(|component| component.as_os_str() == "integration_tests")
            || path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
        {
            continue;
        }
        let file = parse_rust_file(&path)?;
        let normalized = compact_tokens(&file)
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        if normalized.contains("credential_security_target_mappings") {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative,
                "audit adapter production graph must not reference the identity credential-security target relation",
            ));
        }
    }
    Ok(findings)
}

fn postgres_setup_transaction_is_canonical(block: &syn::Block) -> bool {
    let statements = block.stmts.as_slice();
    if statements.len() != 16 {
        return false;
    }
    let Some(serving_transaction) =
        exact_local_initializer(&statements[0], "serving_transaction", true)
    else {
        return false;
    };
    let Some(writer) = exact_local_initializer(&statements[1], "writer", false) else {
        return false;
    };
    let Some(writer_store) = exact_local_initializer(&statements[3], "writer_store", false) else {
        return false;
    };
    let Some(delivery_policy) = exact_local_initializer(&statements[4], "delivery_policy", false)
    else {
        return false;
    };
    let Some(projection_validation) =
        exact_local_initializer(&statements[5], "projection_validation", false)
    else {
        return false;
    };
    let Some(revocation_receipt) =
        exact_local_initializer(&statements[7], "revocation_receipt", false)
    else {
        return false;
    };
    let Some(saga_receipt) = exact_local_initializer(&statements[8], "saga_receipt", false) else {
        return false;
    };
    let Some(reader) = exact_local_initializer(&statements[9], "reader", false) else {
        return false;
    };
    let Some(stores) = exact_local_initializer(&statements[11], "stores", false) else {
        return false;
    };
    let Some(audit_admin_store) =
        exact_local_initializer(&statements[12], "audit_admin_store", false)
    else {
        return false;
    };
    let Some(owner) = exact_local_initializer(&statements[13], "owner", false) else {
        return false;
    };

    compact_tokens(serving_transaction) == "PgSetupTransaction::new()"
        && compact_tokens(writer) == "PgStore::connect_verified_writer(serving_config).await?"
        && exact_register_statement(
            &statements[2],
            "serving_transaction",
            "writer.store_arc()",
            "postgres-writer",
        )
        && compact_tokens(writer_store) == "writer.store_arc()"
        && preloaded_delivery_policy_match_is_canonical(delivery_policy)
        && projection_validation_is_canonical(projection_validation)
        && projection_binding_failure_is_canonical(&statements[6])
        && revocation_receipt_is_canonical(revocation_receipt)
        && saga_receipt_is_canonical(saga_receipt)
        && reader_connect_is_canonical(reader)
        && exact_register_statement(
            &statements[10],
            "serving_transaction",
            "reader.store_arc()",
            "postgres-reader",
        )
        && compact_tokens(stores) == "Arc::new(PgRuntimeStores::new(writer,reader))"
        && audit_connect_is_canonical(audit_admin_store)
        && postgres_runtime_owner_is_canonical(owner)
        && exact_method_statement(&statements[14], "serving_transaction", "commit", &[])
        && exact_path_call_statement(&statements[15], "Ok", &["owner"])
}

fn preloaded_delivery_policy_match_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == "preloaded_delivery_policy"
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == "Some(policy)"
        && compact_tokens(&match_.arms[0].body) == "policy"
        && compact_tokens(&match_.arms[1].pat) == "None"
        && fallible_serving_match_is_canonical(
            &match_.arms[1].body,
            "writer_store.load_event_delivery_policy().await",
            "policy",
        )
}

fn fallible_serving_match_is_canonical(
    expression: &syn::Expr,
    awaited: &str,
    success: &str,
) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == awaited
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == format!("Ok({success})")
        && compact_tokens(&match_.arms[0].body) == success
        && compact_tokens(&match_.arms[1].pat) == "Err(primary)"
        && returned_failure_close_is_exact(&match_.arms[1].body)
}

fn projection_validation_is_canonical(expression: &syn::Expr) -> bool {
    compact_tokens(expression)
        == "matchprojection_capture.as_ref(){Some(capture)=>writer_store.validate_projection_capture_registration(capture).await.map_err(PgError::ProjectionBindings),None=>Ok(()),}"
}

fn projection_binding_failure_is_canonical(statement: &syn::Stmt) -> bool {
    let Some(expression) = expression_statement(statement) else {
        return false;
    };
    let syn::Expr::If(outer) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&outer.cond) == "letErr(primary)=projection_validation"
        && outer.else_branch.is_none()
        && matches!(outer.then_branch.stmts.as_slice(), [syn::Stmt::Expr(expr, Some(_))]
            if returned_failure_close_is_exact(expr))
}

fn exact_local_initializer<'a>(
    statement: &'a syn::Stmt,
    binding: &str,
    mutable: bool,
) -> Option<&'a syn::Expr> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Ident(pattern) = &local.pat else {
        return None;
    };
    (pattern.ident == binding
        && pattern.by_ref.is_none()
        && pattern.subpat.is_none()
        && pattern.mutability.is_some() == mutable)
        .then(|| local.init.as_ref().map(|init| init.expr.as_ref()))
        .flatten()
}

fn exact_register_statement(
    statement: &syn::Stmt,
    transaction: &str,
    store: &str,
    name: &str,
) -> bool {
    let Some(expression) = expression_statement(statement) else {
        return false;
    };
    let syn::Expr::MethodCall(call) = transparent_expr(expression) else {
        return false;
    };
    call.method == "register"
        && compact_tokens(&call.receiver) == transaction
        && call.args.len() == 1
        && call.args.first().is_some_and(|argument| {
            let syn::Expr::Call(guard) = transparent_expr(argument) else {
                return false;
            };
            is_exact_path(&guard.func, &["PgStoreGuard", "new_named"])
                && guard.args.len() == 2
                && guard
                    .args
                    .first()
                    .is_some_and(|argument| compact_tokens(argument) == store)
                && guard.args.iter().nth(1).is_some_and(|argument| {
                    matches!(argument, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Str(value) if value.value() == name))
                })
        })
}

fn expression_statement(statement: &syn::Stmt) -> Option<&syn::Expr> {
    match statement {
        syn::Stmt::Expr(expression, _) => Some(expression),
        _ => None,
    }
}

fn exact_method_statement(
    statement: &syn::Stmt,
    receiver: &str,
    method: &str,
    arguments: &[&str],
) -> bool {
    expression_statement(statement)
        .is_some_and(|expression| exact_method_call(expression, receiver, method, arguments))
}

fn exact_path_call_statement(statement: &syn::Stmt, path: &str, arguments: &[&str]) -> bool {
    expression_statement(statement).is_some_and(|expression| {
        let syn::Expr::Call(call) = transparent_expr(expression) else {
            return false;
        };
        is_exact_path(&call.func, &[path])
            && call.args.len() == arguments.len()
            && call
                .args
                .iter()
                .zip(arguments)
                .all(|(actual, expected)| compact_tokens(actual) == *expected)
    })
}

fn exact_method_call(
    expression: &syn::Expr,
    receiver: &str,
    method: &str,
    arguments: &[&str],
) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&call.receiver) == receiver
        && call.method == method
        && call.args.len() == arguments.len()
        && call
            .args
            .iter()
            .zip(arguments)
            .all(|(actual, expected)| compact_tokens(actual) == *expected)
}

fn exact_awaited_method_call(
    expression: &syn::Expr,
    fallible: bool,
    receiver: &str,
    method: &str,
    arguments: &[&str],
) -> bool {
    let expression = transparent_expr(expression);
    let expression = if fallible {
        let syn::Expr::Try(try_) = expression else {
            return false;
        };
        transparent_expr(&try_.expr)
    } else {
        expression
    };
    let syn::Expr::Await(await_) = expression else {
        return false;
    };
    exact_method_call(&await_.base, receiver, method, arguments)
}

fn reader_connect_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == "PgStore::connect_verified_read(tenant_read_config).await"
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == "Ok(reader)"
        && compact_tokens(&match_.arms[0].body) == "reader"
        && compact_tokens(&match_.arms[1].pat) == "Err(primary)"
        && returned_failure_close_is_exact(&match_.arms[1].body)
}

fn revocation_receipt_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == "writer.verify_revocation_capability().await"
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == "Ok(receipt)"
        && compact_tokens(&match_.arms[0].body) == "receipt"
        && compact_tokens(&match_.arms[1].pat) == "Err(primary)"
        && returned_failure_close_is_exact(&match_.arms[1].body)
}

fn saga_receipt_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == "writer.verify_saga_receipt_capability().await"
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == "Ok(receipt)"
        && compact_tokens(&match_.arms[0].body) == "receipt"
        && compact_tokens(&match_.arms[1].pat) == "Err(primary)"
        && returned_failure_close_is_exact(&match_.arms[1].body)
}

fn audit_connect_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    if compact_tokens(&match_.expr) != "audit_admin_config" || match_.arms.len() != 2 {
        return false;
    }
    let Some(some_arm) = match_
        .arms
        .iter()
        .find(|arm| compact_tokens(&arm.pat) == "Some(config)")
    else {
        return false;
    };
    let Some(none_arm) = match_
        .arms
        .iter()
        .find(|arm| compact_tokens(&arm.pat) == "None")
    else {
        return false;
    };
    let syn::Expr::Block(some) = transparent_expr(&some_arm.body) else {
        return false;
    };
    let statements = some.block.stmts.as_slice();
    let Some(store) = statements
        .first()
        .and_then(|statement| exact_local_initializer(statement, "store", false))
    else {
        return false;
    };
    statements.len() == 3
        && compact_tokens(&none_arm.body) == "None"
        && audit_store_connect_is_canonical(store)
        && exact_register_statement(
            &statements[1],
            "serving_transaction",
            "store.store_arc()",
            "postgres-audit-admin",
        )
        && exact_path_call_statement(&statements[2], "Some", &["store"])
}

fn audit_store_connect_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(match_) = transparent_expr(expression) else {
        return false;
    };
    compact_tokens(&match_.expr) == "PgStore::connect_verified_audit_admin(config).await"
        && match_.arms.len() == 2
        && compact_tokens(&match_.arms[0].pat) == "Ok(store)"
        && compact_tokens(&match_.arms[0].body) == "store"
        && compact_tokens(&match_.arms[1].pat) == "Err(primary)"
        && returned_failure_close_is_exact(&match_.arms[1].body)
}

fn returned_failure_close_is_exact(expression: &syn::Expr) -> bool {
    let syn::Expr::Return(return_) = transparent_expr(expression) else {
        return false;
    };
    return_.expr.as_deref().is_some_and(|expression| {
        exact_awaited_method_call(
            expression,
            false,
            "serving_transaction",
            "close",
            &["Err(primary)"],
        )
    })
}

fn postgres_runtime_owner_is_canonical(expression: &syn::Expr) -> bool {
    let syn::Expr::Struct(owner) = transparent_expr(expression) else {
        return false;
    };
    if !owner.path.is_ident("Self") || owner.rest.is_some() || owner.fields.len() != 1 {
        return false;
    }
    let Some(handle) = owner
        .fields
        .iter()
        .find(|field| matches!(&field.member, syn::Member::Named(member) if member == "handle"))
    else {
        return false;
    };
    let syn::Expr::Struct(handle) = transparent_expr(&handle.expr) else {
        return false;
    };
    if !handle.path.is_ident("PgRuntimeHandle") || handle.rest.is_some() {
        return false;
    }
    let exact_field = |name: &str, value: &str| {
        handle
            .fields
            .iter()
            .filter(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == name)
                    && compact_tokens(&field.expr) == value
            })
            .count()
            == 1
    };
    let field_names = handle
        .fields
        .iter()
        .filter_map(|field| match &field.member {
            syn::Member::Named(member) => Some(member.to_string()),
            syn::Member::Unnamed(_) => None,
        })
        .collect::<BTreeSet<_>>();
    field_names
        == BTreeSet::from([
            "stores".to_owned(),
            "revocation_receipt".to_owned(),
            "saga_receipt".to_owned(),
            "audit_admin_store".to_owned(),
            "delivery_policy".to_owned(),
            "projection_registry".to_owned(),
            "projection_capture".to_owned(),
            "readiness".to_owned(),
            "rls_readiness".to_owned(),
        ])
        && exact_field("stores", "stores")
        && exact_field("revocation_receipt", "revocation_receipt")
        && exact_field("saga_receipt", "saga_receipt")
        && exact_field("audit_admin_store", "audit_admin_store")
        && exact_field("projection_capture", "projection_capture")
        && exact_field("readiness", "Arc::new(PgDbReadiness::new())")
        && exact_field("rls_readiness", "Arc::new(PgRlsReadiness::verified())")
        && exact_field(
            "projection_registry",
            "projection_capture.as_ref().map_or_else(ProjectionWriteRegistry::empty,|capture|capture.registry())",
        )
}

fn parse_rust_file(path: &Path) -> Result<syn::File> {
    let source = fs::read_to_string(path).with_context(|| format!("读 {} 失败", path.display()))?;
    syn::parse_file(&source).with_context(|| format!("解析 {} 失败", path.display()))
}

#[allow(
    clippy::unreachable,
    reason = "the preceding iterator filter retains only inherent impl items"
)]
fn unique_production_inherent_method<'a>(
    file: &'a syn::File,
    owner: &str,
    method: &str,
) -> Option<&'a syn::ImplItemFn> {
    let methods = file
        .items
        .iter()
        .filter(|item| {
            matches!(item, syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item.trait_.is_none()
                    && type_last_ident(&item.self_ty).is_some_and(|ident| ident == owner))
        })
        .flat_map(|item| {
            let syn::Item::Impl(item) = item else {
                unreachable!("filtered to inherent impls")
            };
            item.items.iter().filter_map(|item| match item {
                syn::ImplItem::Fn(item)
                    if item.sig.ident == method && attrs_may_be_production(&item.attrs) =>
                {
                    Some(item)
                }
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    if methods.len() == 1 {
        Some(methods[0])
    } else {
        None
    }
}

fn unique_production_function<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == name && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    (functions.len() == 1).then(|| functions[0])
}

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

fn is_exact_path(expr: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expr else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn type_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        syn::Type::Reference(reference) => type_last_ident(&reference.elem),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;

    fn write(path: &Path, text: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn replace_nth(
        source: &str,
        needle: &str,
        occurrence: usize,
        replacement: &str,
    ) -> Result<String> {
        let Some((offset, _)) = source.match_indices(needle).nth(occurrence) else {
            anyhow::bail!("missing occurrence {occurrence} of `{needle}`");
        };
        let mut mutated = source.to_owned();
        mutated.replace_range(offset..offset + needle.len(), replacement);
        Ok(mutated)
    }

    #[test]
    fn risk_residuals_accept_workspace() -> Result<()> {
        assert_eq!(
            runtime_risk_residual_findings(&workspace_root()?)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn risk_residuals_reject_each_cross_file_bypass() -> Result<()> {
        let cases = [
            (
                "config",
                "fn bypass(){ let _=std::env::var(\"RSS_BYPASS\"); }",
                "RUNTIME-CONFIG-ESCAPE-01",
            ),
            (
                "secret",
                "fn bypass(secret: secure::SecretText){ tracing::error!(\"{}\", secret.expose()); }",
                "RUNTIME-SECRET-TRANSFER-01",
            ),
            (
                "provider",
                "fn bypass(){ let _=ProviderFactoryDispatch::from_catalog(); }",
                "RUNTIME-PROVIDER-BYPASS-01",
            ),
            (
                "lifecycle",
                "fn bypass(){ runtimeexec::launch(); let _=ShutdownStack::new(); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
            ),
            (
                "plan",
                "fn bypass(){ bootstrap::compose_bindings(); let _=PROJECTION_INPUTS; }",
                "RUNTIME-PLAN-BINDING-BYPASS-01",
            ),
            (
                "replay",
                "fn bypass(){ let _=ProcessLocalReplay; }",
                "RUNTIME-SERVICE-TOKEN-REPLAY-BYPASS-01",
            ),
        ];
        for (name, source, id) in cases {
            let root = unique_tmp(&format!("runtime-residual-{name}"));
            write(&root.join(RUNTIME_SRC_PATH).join("bypass.rs"), source)?;
            let findings = runtime_risk_residual_findings(&root)?;
            assert!(
                findings.iter().any(|finding| finding.detail.contains(id)),
                "{id} did not reject {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn risk_residuals_resolve_aliases_and_function_values() -> Result<()> {
        let cases = [
            (
                "env-alias",
                "use std::env as ambient; fn bypass(){ let _=ambient::var(\"RSS_BYPASS\"); }",
                "RUNTIME-CONFIG-ESCAPE-01",
                "ambient reader `std::env::var`",
            ),
            (
                "launch-alias",
                "use runtimeexec::launch as start; fn bypass(){ start(); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "second runtime launch owner",
            ),
            (
                "launch-value",
                "fn bypass(){ let start = runtimeexec::launch; start(); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "runtime launch capability referenced outside its owner",
            ),
            (
                "launch-macro-alias",
                "use runtimeexec::launch as start; fn bypass(){ expand!(start); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "macro can expand a second runtime launch owner",
            ),
            (
                "startup-owner",
                "fn bypass(plan: runtimeexec::StartupPlan<fn()>){ runtimeexec::launch_startup(plan); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "second runtime launch owner",
            ),
            (
                "signal-owner",
                "fn bypass(){ tokio::signal::ctrl_c(); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "second process signal owner",
            ),
            (
                "raw-listeners",
                "fn bypass(){ runtimeexec::launch(vec![]); }",
                "RUNTIME-LIFECYCLE-BYPASS-01",
                "raw listener vector",
            ),
            (
                "plan-alias",
                "use bootstrap::compose_bindings as compose; fn bypass(){ compose(); }",
                "RUNTIME-PLAN-BINDING-BYPASS-01",
                "compose_bindings outside validated plan owner",
            ),
            (
                "replay-alias",
                "use replay::ProcessLocalReplay as LocalReplay; fn bypass(){ let _=LocalReplay; }",
                "RUNTIME-SERVICE-TOKEN-REPLAY-BYPASS-01",
                "process-local/raw replay seam `ProcessLocalReplay`",
            ),
        ];
        for (name, source, id, expected) in cases {
            let root = unique_tmp(&format!("runtime-residual-{name}"));
            write(&root.join(RUNTIME_SRC_PATH).join("bypass.rs"), source)?;
            let findings = runtime_risk_residual_findings(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding.detail.contains(id) && finding.detail.contains(expected)
                }),
                "{id} did not independently reject {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn risk_residuals_track_secret_bindings_into_diagnostics() -> Result<()> {
        let cases = [
            (
                "binding",
                r#"fn bypass(secret: secure::SecretText){
                    let raw = secret.expose();
                    tracing::error!(%raw);
                }"#,
            ),
            (
                "helper",
                r#"fn reveal(secret: &secure::SecretText) -> &[u8] { secret.expose() }
                fn bypass(secret: secure::SecretText){
                    let raw = reveal(&secret);
                    tracing::event!(tracing::Level::ERROR, %raw);
                }"#,
            ),
            (
                "extra-handoff",
                r#"fn bypass(secret: EnvSecret) -> String {
                    secret.transfer_secret_allocation()
                }"#,
            ),
            (
                "assignment-wrapper",
                r#"struct Wrapped<'a> { raw: &'a [u8] }
                fn bypass(secret: secure::SecretText){
                    let mut raw = &[][..];
                    raw = secret.expose();
                    let wrapped = Wrapped { raw };
                    tracing::error!(?wrapped);
                }"#,
            ),
            (
                "direct-helper-sink",
                r#"fn reveal(secret: &secure::SecretText) -> &[u8] { secret.expose() }
                fn bypass(secret: secure::SecretText){ tracing::error!(?reveal(&secret)); }"#,
            ),
            (
                "custom-macro",
                r#"fn bypass(secret: secure::SecretText){ handoff!(secret.expose()); }"#,
            ),
            (
                "formatting-assertion",
                r#"fn bypass(secret: secure::SecretText){ assert_eq!(secret.expose(), b"expected"); }"#,
            ),
            (
                "proof-message-leak",
                r#"fn bypass(secret: secure::SecretText){ anyhow::ensure!(secret.expose() == b"expected", "actual={:?}", secret.expose()); }"#,
            ),
            (
                "destructured-binding",
                r#"fn bypass(secret: secure::SecretText){
                    let (raw,) = (secret.expose(),);
                    tracing::error!(%raw);
                }"#,
            ),
            (
                "ordinary-call",
                r#"fn send(_: &[u8]) {} fn bypass(secret: secure::SecretText){ send(secret.expose()); }"#,
            ),
        ];
        for (name, source) in cases {
            let root = unique_tmp(&format!("runtime-secret-taint-{name}"));
            write(
                &root.join(RUNTIME_SRC_PATH).join("event_transport.rs"),
                source,
            )?;
            let findings = runtime_risk_residual_findings(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains("RUNTIME-SECRET-TRANSFER-01")),
                "secret taint escaped {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn risk_residuals_track_secret_sources_across_runtime_files() -> Result<()> {
        let root = unique_tmp("runtime-secret-taint-cross-file");
        write(
            &root
                .join(RUNTIME_SRC_PATH)
                .join("operator/service_token.rs"),
            r#"struct OperatorServiceToken(secure::SecretText);
            impl OperatorServiceToken {
                fn as_str(&self) -> &str { self.0.expose() }
            }"#,
        )?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("operator/audit_ledger.rs"),
            r#"fn bypass(parsed: Args) {
                tracing::error!(token = parsed.operator_service_token.as_str());
            }"#,
        )?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("operator/token_helper.rs"),
            r#"fn raw_token(token: &OperatorServiceToken) -> &str { token.as_str() }"#,
        )?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("operator/reconcile.rs"),
            r#"fn bypass(parsed: Args) {
                tracing::error!(token = raw_token(&parsed.operator_service_token));
            }"#,
        )?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("operator/unrelated.rs"),
            r#"fn log(metadata: Metadata) {
                tracing::error!(value = metadata.operator_service_token_metadata.as_str());
            }"#,
        )?;

        let findings = runtime_risk_residual_findings(&root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.subject.ends_with("operator/audit_ledger.rs:2")
                    && finding.detail.contains("RUNTIME-SECRET-TRANSFER-01")
            }),
            "cross-file secret source escaped {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.subject.ends_with("operator/reconcile.rs:2")
                    && finding.detail.contains("RUNTIME-SECRET-TRANSFER-01")
            }),
            "cross-file secret propagator escaped {findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|finding| !finding.subject.contains("operator/unrelated.rs")),
            "receiver marker matched an unrelated as_str call {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn risk_residuals_ignore_test_only_items_modules_and_unrelated_names() -> Result<()> {
        let root = unique_tmp("runtime-residual-production-reachability");
        write(
            &root.join(RUNTIME_SRC_PATH).join("lib.rs"),
            r#"#[cfg(test)] use std::env;
            #[cfg(test)] static START: fn() = runtimeexec::launch;
            #[cfg(test)] const RAW: &str = "ShutdownStack";
            #[cfg(test)] mod checks;
            fn var() {}
            struct Text;
            impl Text { fn into_string(self) -> String { String::new() } }
            fn production(){ var(); let _ = Text.into_string(); }"#,
        )?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("checks.rs"),
            "use std::env; fn test_only(){ runtimeexec::launch(); let _=env::var(\"X\"); }",
        )?;
        assert_eq!(
            runtime_risk_residual_findings(&root)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn risk_residuals_preserve_each_source_location() -> Result<()> {
        let root = unique_tmp("runtime-residual-source-sites");
        write(
            &root.join(RUNTIME_SRC_PATH).join("sites.rs"),
            "fn bypass(){\nlet _=std::env::var(\"A\");\nlet _=std::env::var(\"B\");\n}",
        )?;
        let findings = runtime_risk_residual_findings(&root)?;
        let subjects = findings
            .iter()
            .filter(|finding| finding.detail.contains("RUNTIME-CONFIG-ESCAPE-01"))
            .map(|finding| finding.subject.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            subjects,
            [
                "assemblies/runtime/src/sites.rs:2",
                "assemblies/runtime/src/sites.rs:3"
            ]
        );
        Ok(())
    }

    #[test]
    fn risk_residuals_ignore_private_helper_shape() -> Result<()> {
        let root = unique_tmp("runtime-residual-helper-shape");
        write(
            &root.join(RUNTIME_SRC_PATH).join("renamed.rs"),
            "fn split_owner(){ reordered(); } fn reordered(){}",
        )?;
        assert!(runtime_risk_residual_findings(&root)?.is_empty());
        Ok(())
    }

    fn provider_protocol_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        let workspace = workspace_root()?;
        for relative in [
            "assemblies/runtime/src/phase/provider.rs",
            "assemblies/runtime/src/phase/domains.rs",
        ] {
            write(
                &root.join(relative),
                &fs::read_to_string(workspace.join(relative))?,
            )?;
        }
        Ok(root)
    }

    #[test]
    fn provider_protocol_rejects_missing_duplicate_and_wrong_owner_edges() -> Result<()> {
        let green = provider_protocol_fixture("provider-protocol-green")?;
        assert!(provider_protocol_residuals(&green)?.is_empty());

        for (label, target, needle, replacement) in [
            (
                "missing finish",
                "assemblies/runtime/src/phase/domains.rs",
                "provider_build.finish()",
                "provider_build.abort_for_test()",
            ),
            (
                "missing catalog transaction",
                "assemblies/runtime/src/phase/provider.rs",
                "crate::provider_output::ProviderBuild::from_execution_plan(",
                "crate::provider_output::ProviderBuild::bypass_plan(",
            ),
            (
                "missing event output receipt",
                "assemblies/runtime/src/phase/domains.rs",
                "crate::event_transport::wire_event_transport(",
                "crate::event_transport::bypass_event_transport(",
            ),
        ] {
            let root = provider_protocol_fixture(&format!(
                "provider-protocol-{}",
                label.replace(' ', "-")
            ))?;
            let path = root.join(target);
            let canonical = fs::read_to_string(&path)?;
            let mutated = canonical.replacen(needle, replacement, 1);
            assert_ne!(canonical, mutated, "{label} mutation must be live");
            write(&path, &mutated)?;
            assert!(!provider_protocol_residuals(&root)?.is_empty(), "{label}");
        }

        let duplicate = provider_protocol_fixture("provider-protocol-wrong-owner")?;
        write(
            &duplicate.join("assemblies/runtime/src/bypass.rs"),
            "fn bypass(){ crate::event_transport::wire_event_transport(); }",
        )?;
        assert!(!provider_protocol_residuals(&duplicate)?.is_empty());
        Ok(())
    }

    fn postgres_setup_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        let workspace = workspace_root()?;
        for relative in [
            POSTGRES_BUNDLE_PATH,
            POSTGRES_MIGRATION_PATH,
            POSTGRES_PROJECTION_EVENTS_PATH,
        ] {
            write(
                &root.join(relative),
                &fs::read_to_string(workspace.join(relative))?,
            )?;
        }
        Ok(root)
    }

    #[test]
    fn postgres_setup_transaction_accepts_live_workspace() -> Result<()> {
        assert!(
            postgres_setup_transaction_live_findings(&postgres_setup_fixture("pg-setup-green")?)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn postgres_setup_transaction_rejects_missing_live_edges() -> Result<()> {
        let cases = [
            (
                "verified writer connection",
                "PgStore::connect_verified_writer(serving_config).await?",
                "PgStore::connect(serving_config).await?",
                0,
            ),
            (
                "delivery policy failure close",
                "return serving_transaction.close(Err(primary)).await",
                "return Err(primary)",
                0,
            ),
            (
                "projection validation",
                "validate_projection_capture_registration(capture)",
                "missing_projection_capture_registration(capture)",
                0,
            ),
            (
                "writer immediate register",
                "serving_transaction.register(PgStoreGuard::new_named(",
                "serving_transaction.skip_register(PgStoreGuard::new_named(",
                0,
            ),
            (
                "revocation capability failure close",
                "return serving_transaction.close(Err(primary)).await",
                "return Err(primary)",
                2,
            ),
            (
                "saga receipt capability failure close",
                "return serving_transaction.close(Err(primary)).await",
                "return Err(primary)",
                3,
            ),
            (
                "reader failure close",
                "return serving_transaction.close(Err(primary)).await",
                "return Err(primary)",
                4,
            ),
            (
                "reader immediate register",
                "serving_transaction.register(PgStoreGuard::new_named(",
                "serving_transaction.skip_register(PgStoreGuard::new_named(",
                1,
            ),
            (
                "audit-admin failure close",
                "return serving_transaction.close(Err(primary)).await",
                "return Err(primary)",
                5,
            ),
            (
                "audit-admin immediate register",
                "serving_transaction.register(PgStoreGuard::new_named(",
                "serving_transaction.skip_register(PgStoreGuard::new_named(",
                2,
            ),
            (
                "success commit",
                "serving_transaction.commit();",
                "drop(serving_transaction);",
                0,
            ),
            (
                "complete typed owner",
                "handle: PgRuntimeHandle {\n                stores,\n                revocation_receipt,\n                saga_receipt,\n                audit_admin_store,",
                "handle: PgRuntimeHandle {\n                stores: stores.clone(),\n                revocation_receipt: revocation_receipt.clone(),\n                saga_receipt: saga_receipt.clone(),\n                audit_admin_store: None,",
                0,
            ),
        ];
        for (label, needle, replacement, occurrence) in cases {
            let root =
                postgres_setup_fixture(&format!("pg-setup-red-{}", label.replace(' ', "-")))?;
            let target = root.join(POSTGRES_BUNDLE_PATH);
            let canonical = fs::read_to_string(&target)?;
            let mutated = replace_nth(&canonical, needle, occurrence, replacement)?;
            write(&target, &mutated)?;
            assert!(
                !postgres_setup_transaction_live_findings(&root)?.is_empty(),
                "{label} must fail closed"
            );
        }

        for missing in [
            POSTGRES_BUNDLE_PATH,
            POSTGRES_MIGRATION_PATH,
            POSTGRES_PROJECTION_EVENTS_PATH,
        ] {
            let root =
                postgres_setup_fixture(&format!("pg-setup-missing-{}", missing.replace('/', "-")))?;
            fs::remove_file(root.join(missing))?;
            assert!(
                !postgres_setup_transaction_live_findings(&root)?.is_empty(),
                "missing {missing} must fail closed"
            );
        }
        Ok(())
    }

    #[test]
    fn audit_security_fact_boundary_accepts_live_workspace() -> Result<()> {
        assert!(audit_security_fact_boundary_findings(&workspace_root()?)?.is_empty());
        Ok(())
    }

    #[test]
    fn audit_security_fact_boundary_rejects_identity_table_reads() -> Result<()> {
        let root = unique_tmp("audit-security-red");
        write(
            &root.join(POSTGRES_CONSUMER_TX_PATH),
            "fn consume(){security_audit_command_from_message();credential_security_target_mappings();}",
        )?;
        assert!(!audit_security_fact_boundary_findings(&root)?.is_empty());

        let cross_file = unique_tmp("audit-security-cross-file-red");
        write(
            &cross_file.join(POSTGRES_CONSUMER_TX_PATH),
            "fn consume(){security_audit_command_from_message();}",
        )?;
        write(
            &cross_file.join("adapters/postgres/src/security_lookup.rs"),
            r#"const RELATION: &str = concat!("credential_security_target_", "mappings");"#,
        )?;
        assert!(
            !audit_security_fact_boundary_findings(&cross_file)?.is_empty(),
            "cross-file/macro relation construction must fail closed"
        );
        Ok(())
    }

    #[test]
    fn runtime_assembly_residual_accepts_workspace() -> Result<()> {
        let (_, findings) = check_root(&workspace_root()?)?;
        assert_eq!(findings, Vec::<Finding<Rule>>::new());
        Ok(())
    }
}
