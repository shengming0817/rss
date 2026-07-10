//! runtime event transport source guard.
//!
//! INVARIANT: EVENT-TRANSPORT-PG-INBOX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_missing_pg_bundle_fragment", anti_vacuity = "tests::scan_content_accepts_pg_inbox_bundle" }——
//! `assemblies/runtime/src/event_transport.rs` 的 consumer idempotency must come from PG inbox, not Redis,
//! and production consumer workers must go through the generated-topology bridge.
//! INVARIANT: EVENT-PRODUCER-SPEC-PAIR-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::producer_ast_rejects_swapped_specs_without_partition_key", anti_vacuity = "tests::producer_ast_accepts_generated_spec_alias_and_counts_typed_partition_key" }——
//! every authoring function must use exactly one identical generated SPEC for its EventEntry and
//! envelope before any fact is admitted to the global topology set.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use quote::ToTokens;
use syn::visit::Visit;

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::{is_excluded, member_dirs, rs_files};
use crate::workspace_root;

const TARGET: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_FORBIDDEN: &[&str] = &[
    "RedisInboxStore",
    "RSS_REDIS_CLAIM_TTL_MS",
    "redis_claim_ttl",
    "replaydeps::IdempotencyConfig",
    "redis idempotency",
    "Redis 幂等",
    "adapt_subscriber_handler",
    "spawn_consumer_ackable_subscriber(",
];
const RUNTIME_REDIS_INBOX_FRAGMENT: &str = "redis.infra().inbox(";
const DOMAIN_FORBIDDEN: &[&str] = &[
    "PgInboxStore",
    "RedisInboxStore",
    "ConsumerWorker",
    "spawn_consumer(",
    "spawn_consumer_ackable(",
    "spawn_consumer_ackable_subscriber(",
    "pg.infra().inbox(",
    "pg.infra().dead_letter(",
];
const BYPASS_FORBIDDEN: &[&str] = &[
    "spawn_consumer(",
    "spawn_consumer_ackable(",
    "spawn_consumer_ackable_subscriber(",
    "spawn_consumer_ackable_tx_subscriber(",
    "pg.infra().inbox(",
];
const BYPASS_MEMBER_ROOTS: &[&str] = &["crates", "adapters", "assemblies", "bins"];
const BYPASS_LEAF_CRATES: &[&str] = &["journeys"];
const BYPASS_ALLOWED_PATHS: &[&str] = &[
    TARGET,
    "crates/eventexec/src/consumer_worker.rs",
    "adapters/postgres/src/bundle.rs",
    "adapters/postgres/src/inbox.rs",
    "adapters/redis/src/bundle.rs",
];
const POSTGRES_FAULT_MATRIX_HARNESS: &str = "adapters/postgres/src/fault_matrix.rs";
const POSTGRES_LIB_PATH: &str = "adapters/postgres/src/lib.rs";
const EVENT_CONTRACT_ROOT: &str = "contracts/event";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RedisConsumerClaimer,
    MissingBundleFragment,
    DomainConsumerBundleBypass,
    ProductionConsumerBundleBypass,
    ProducerTopology,
}

pub(crate) struct EventTransportGuard;

impl GovernanceCheck for EventTransportGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "event-transport-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let path = root.join(TARGET);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
        let mut findings = scan_runtime_content(Path::new(TARGET), &content);
        findings.extend(scan_domain_crates(&root)?);
        findings.extend(scan_production_bypasses(&root)?);
        findings.extend(scan_event_producers(&root)?);
        Ok((
            format!(
                "{TARGET} 经 generated topology bridge + ConsumerTx PG inbox bundle 接线，生产 src 无散装 consumer bundle"
            ),
            findings,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionStrategy {
    None,
    Aggregate,
}

#[derive(Debug)]
struct ActiveEvent {
    contract_id: String,
    spec_path: String,
    partition: PartitionStrategy,
}

fn scan_event_producers(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let events = load_active_events(root)?;
    let mut facts = ProducerFacts::default();
    let mut findings = Vec::new();
    for path in producer_source_files(root)? {
        let rel = rel_path(root, &path);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event producer guard: read {}", path.display()))?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("event producer guard: parse {}", path.display()))?;
        let imports = SpecImports::from_file(&file);
        let entry_helpers = event_entry_helpers(&file);
        let mut visitor =
            ProducerVisitor::new(&imports, &entry_helpers, &rel, &mut facts, &mut findings);
        visitor.visit_file(&file);
    }

    for event in &events {
        findings.extend(validate_event_facts(event, &facts));
    }
    Ok(findings)
}

fn producer_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for top in BYPASS_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            if is_excluded(&member) {
                continue;
            }
            let src = member.join("src");
            if !src.is_dir() {
                continue;
            }
            files.extend(
                rust_files_under(&src)?
                    .into_iter()
                    .filter(|path| !is_producer_test_file(path)),
            );
        }
    }
    for leaf in BYPASS_LEAF_CRATES {
        let src = root.join(leaf).join("src");
        if src.is_dir() {
            files.extend(
                rust_files_under(&src)?
                    .into_iter()
                    .filter(|path| !is_producer_test_file(path)),
            );
        }
    }
    Ok(files.into_iter().collect())
}

fn is_producer_test_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    name == "integration_tests.rs"
        || name.ends_with("_test.rs")
        || name.ends_with("_tests.rs")
        || path.components().any(|part| part.as_os_str() == "tests")
}

fn validate_event_facts(event: &ActiveEvent, facts: &ProducerFacts) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    if !facts.entries.contains(&event.spec_path) {
        findings.push(finding(
            Rule::ProducerTopology,
            event.contract_id.clone(),
            format!(
                "active event 缺少使用 generated `{}`.topic() 的真实 EventEntry authoring 调用",
                event.spec_path
            ),
        ));
    }
    if !facts.envelopes.contains(&event.spec_path) {
        findings.push(finding(
            Rule::ProducerTopology,
            event.contract_id.clone(),
            format!(
                "active event 缺少使用 generated `{}`.contract() 的真实 envelope 调用",
                event.spec_path
            ),
        ));
    }
    let partition_sites = facts
        .partition_sites
        .get(&event.spec_path)
        .map(Vec::as_slice)
        .unwrap_or_default();
    match event.partition {
        PartitionStrategy::None if partition_sites.iter().any(|count| *count != 0) => {
            findings.push(finding(
                Rule::ProducerTopology,
                event.contract_id.clone(),
                "partitionKey=none 的 event 每个 authoring site 都禁止设置 typed partition key"
                    .to_string(),
            ));
        }
        PartitionStrategy::Aggregate
            if partition_sites.is_empty() || partition_sites.iter().any(|count| *count != 1) =>
        {
            findings.push(finding(
                Rule::ProducerTopology,
                event.contract_id.clone(),
                format!(
                    "partitionKey=aggregate 的 event 每个 authoring site 必须且只能设置一次 typed partition key，实际 {partition_sites:?}"
                ),
            ));
        }
        PartitionStrategy::None | PartitionStrategy::Aggregate => {}
    }
    findings
}

fn load_active_events(root: &Path) -> Result<Vec<ActiveEvent>> {
    let contract_root = root.join(EVENT_CONTRACT_ROOT);
    let mut events = Vec::new();
    let mut stack = vec![contract_root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("event producer guard: read dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|name| name.to_str()) != Some("contract.toml") {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            let doc: toml::Value = toml::from_str(&content)
                .with_context(|| format!("event producer guard: parse {}", path.display()))?;
            if doc.get("kind").and_then(toml::Value::as_str) != Some("event")
                || doc.get("lifecycle").and_then(toml::Value::as_str) != Some("active")
            {
                continue;
            }
            let contract_id = required_toml_str(&doc, "id", &path)?;
            required_toml_str(&doc, "owner", &path)?;
            let version = required_toml_str(&doc, "version", &path)?;
            let relative = path
                .strip_prefix(root.join(EVENT_CONTRACT_ROOT))
                .unwrap_or(&path);
            let segments: Vec<_> = relative.components().collect();
            let slug = if segments.len() == 4 {
                Some(segments[2].as_os_str().to_string_lossy().replace('-', "_"))
            } else {
                None
            };
            let spec_path = event_spec_path(relative, version, slug.as_deref())?;
            let partition = doc
                .get("subscriptions")
                .and_then(toml::Value::as_array)
                .and_then(|subscriptions| subscriptions.first())
                .and_then(|subscription| subscription.get("topology"))
                .and_then(|topology| topology.get("partitionKey"))
                .and_then(toml::Value::as_str)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} missing subscriptions.topology.partitionKey",
                        path.display()
                    )
                })?;
            let partition = match partition {
                "none" => PartitionStrategy::None,
                "aggregate" => PartitionStrategy::Aggregate,
                other => anyhow::bail!("{} unknown partitionKey `{other}`", path.display()),
            };
            events.push(ActiveEvent {
                contract_id: contract_id.to_string(),
                spec_path,
                partition,
            });
        }
    }
    events.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    Ok(events)
}

fn event_spec_path(relative: &Path, version: &str, slug: Option<&str>) -> Result<String> {
    let segments: Vec<_> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(domain) = segments.first() else {
        anyhow::bail!("event contract path has no domain: {}", relative.display());
    };
    if segments
        .get(1)
        .is_none_or(|path_version| path_version != version)
    {
        anyhow::bail!(
            "event contract path/version mismatch: {} vs {version}",
            relative.display()
        );
    }
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    Ok(match slug {
        Some(slug) => format!("generated::event::{module}::{slug}::SPEC"),
        None => format!("generated::event::{module}::SPEC"),
    })
}

fn required_toml_str<'a>(doc: &'a toml::Value, key: &str, path: &Path) -> Result<&'a str> {
    doc.get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{} missing string `{key}`", path.display()))
}

#[derive(Default)]
struct ProducerFacts {
    entries: BTreeSet<String>,
    envelopes: BTreeSet<String>,
    partition_sites: BTreeMap<String, Vec<usize>>,
}

#[derive(Default)]
struct SpecImports {
    aliases: BTreeMap<String, String>,
    globs: Vec<String>,
}

impl SpecImports {
    fn from_file(file: &syn::File) -> Self {
        let mut imports = Self::default();
        for item in &file.items {
            if let syn::Item::Use(item_use) = item {
                collect_spec_imports(&item_use.tree, Vec::new(), &mut imports);
            }
        }
        imports
    }

    fn resolve(&self, expr: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = peel_expr(expr) else {
            return None;
        };
        let rendered = path.path.to_token_stream().to_string().replace(' ', "");
        if rendered.starts_with("generated::event::") && rendered.ends_with("::SPEC") {
            return Some(rendered);
        }
        if path.path.segments.len() == 1 {
            let ident = path.path.segments[0].ident.to_string();
            if let Some(canonical) = self.aliases.get(&ident) {
                return Some(canonical.clone());
            }
            if ident == "SPEC" && self.globs.len() == 1 {
                return Some(format!("{}::SPEC", self.globs[0]));
            }
        }
        None
    }
}

fn collect_spec_imports(tree: &syn::UseTree, mut prefix: Vec<String>, imports: &mut SpecImports) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_spec_imports(&path.tree, prefix, imports);
        }
        syn::UseTree::Name(name) if name.ident == "SPEC" => {
            prefix.push("SPEC".to_string());
            imports
                .aliases
                .insert("SPEC".to_string(), prefix.join("::"));
        }
        syn::UseTree::Rename(rename) if rename.ident == "SPEC" => {
            prefix.push("SPEC".to_string());
            imports
                .aliases
                .insert(rename.rename.to_string(), prefix.join("::"));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_spec_imports(item, prefix.clone(), imports);
            }
        }
        syn::UseTree::Glob(_) => imports.globs.push(prefix.join("::")),
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) => {}
    }
}

struct ProducerVisitor<'a> {
    imports: &'a SpecImports,
    entry_helpers: &'a BTreeSet<String>,
    path: &'a Path,
    facts: &'a mut ProducerFacts,
    findings: &'a mut Vec<Finding<Rule>>,
}

impl<'a> ProducerVisitor<'a> {
    fn new(
        imports: &'a SpecImports,
        entry_helpers: &'a BTreeSet<String>,
        path: &'a Path,
        facts: &'a mut ProducerFacts,
        findings: &'a mut Vec<Finding<Rule>>,
    ) -> Self {
        Self {
            imports,
            entry_helpers,
            path,
            facts,
            findings,
        }
    }

    fn visit_production_block(&mut self, ident: &syn::Ident, block: &syn::Block) {
        let mut function = FunctionProducerVisitor {
            imports: self.imports,
            entry_helpers: self.entry_helpers,
            entries: BTreeSet::new(),
            envelopes: BTreeSet::new(),
            partition_calls: 0,
        };
        function.visit_block(block);
        let authored: BTreeSet<_> = function
            .entries
            .union(&function.envelopes)
            .filter(|spec| spec.as_str() != UNRESOLVED_SPEC)
            .cloned()
            .collect();
        let complete: BTreeSet<_> = function
            .entries
            .intersection(&function.envelopes)
            .filter(|spec| spec.as_str() != UNRESOLVED_SPEC)
            .cloned()
            .collect();
        let unresolved = function.entries.contains(UNRESOLVED_SPEC)
            || function.envelopes.contains(UNRESOLVED_SPEC);
        if !authored.is_empty()
            && (unresolved
                || function.entries.len() != 1
                || function.envelopes.len() != 1
                || authored.len() != 1
                || complete.len() != 1)
        {
            self.findings.push(finding(
                Rule::ProducerTopology,
                self.path.display().to_string(),
                format!(
                    "函数 `{ident}` 必须且只能用同一个 generated event SPEC 构造 EventEntry 与 envelope"
                ),
            ));
        } else if let Some(spec) = complete.into_iter().next() {
            self.facts.entries.insert(spec.clone());
            self.facts.envelopes.insert(spec.clone());
            self.facts
                .partition_sites
                .entry(spec)
                .or_default()
                .push(function.partition_calls);
        }
        if function.entries.contains(UNRESOLVED_SPEC) {
            self.findings.push(finding(
                Rule::ProducerTopology,
                self.path.display().to_string(),
                format!(
                    "函数 `{ident}` 的 EventEntry topic 必须直接来自 generated event SPEC.topic()"
                ),
            ));
        }
        if function.envelopes.contains(UNRESOLVED_SPEC) {
            self.findings.push(finding(
                Rule::ProducerTopology,
                self.path.display().to_string(),
                format!(
                    "函数 `{ident}` 的 envelope contract 必须直接来自 generated event SPEC.contract()"
                ),
            ));
        }
    }
}

impl<'ast> Visit<'ast> for ProducerVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.ident == "tests" || has_test_attr(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_test_attr(&node.attrs) {
            return;
        }
        if self.entry_helpers.contains(&node.sig.ident.to_string()) {
            return;
        }
        self.visit_production_block(&node.sig.ident, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_test_attr(&node.attrs) {
            return;
        }
        self.visit_production_block(&node.sig.ident, &node.block);
    }
}

const UNRESOLVED_SPEC: &str = "<unresolved>";

struct FunctionProducerVisitor<'a> {
    imports: &'a SpecImports,
    entry_helpers: &'a BTreeSet<String>,
    entries: BTreeSet<String>,
    envelopes: BTreeSet<String>,
    partition_calls: usize,
}

impl<'ast> Visit<'ast> for FunctionProducerVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if call_ends_with(&node.func, "EventEntry", "new") {
            self.entries.insert(
                node.args
                    .first()
                    .and_then(|arg| spec_method_receiver(arg, "topic", self.imports))
                    .unwrap_or_else(|| UNRESOLVED_SPEC.to_string()),
            );
        } else if call_ident(&node.func).is_some_and(|ident| self.entry_helpers.contains(&ident)) {
            self.entries.insert(
                node.args
                    .first()
                    .and_then(|arg| self.imports.resolve(arg))
                    .unwrap_or_else(|| UNRESOLVED_SPEC.to_string()),
            );
        } else if call_ends_with(&node.func, "OutboxEnvelopeParts", "new") {
            self.envelopes.insert(
                node.args
                    .first()
                    .and_then(|arg| spec_method_receiver(arg, "contract", self.imports))
                    .unwrap_or_else(|| UNRESOLVED_SPEC.to_string()),
            );
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "with_partition_key" {
            self.partition_calls += 1;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn spec_method_receiver(expr: &syn::Expr, method: &str, imports: &SpecImports) -> Option<String> {
    match peel_expr(expr) {
        syn::Expr::MethodCall(call) if call.method == method && call.args.is_empty() => {
            imports.resolve(&call.receiver)
        }
        syn::Expr::MethodCall(call) => spec_method_receiver(&call.receiver, method, imports)
            .or_else(|| {
                call.args
                    .iter()
                    .find_map(|arg| spec_method_receiver(arg, method, imports))
            }),
        syn::Expr::Call(call) => call
            .args
            .iter()
            .find_map(|arg| spec_method_receiver(arg, method, imports)),
        _ => None,
    }
}

fn peel_expr(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        expr = match expr {
            syn::Expr::Paren(paren) => &paren.expr,
            syn::Expr::Group(group) => &group.expr,
            syn::Expr::Reference(reference) => &reference.expr,
            syn::Expr::Try(try_expr) => &try_expr.expr,
            syn::Expr::Await(await_expr) => &await_expr.base,
            _ => return expr,
        };
    }
}

fn call_ends_with(expr: &syn::Expr, owner: &str, method: &str) -> bool {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return false;
    };
    let mut segments = path.path.segments.iter().rev();
    matches!(segments.next(), Some(segment) if segment.ident == method)
        && matches!(segments.next(), Some(segment) if segment.ident == owner)
}

fn call_ident(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn event_entry_helpers(file: &syn::File) -> BTreeSet<String> {
    file.items
        .iter()
        .filter_map(|item| {
            let syn::Item::Fn(function) = item else {
                return None;
            };
            let typed_spec_params: BTreeSet<String> = function
                .sig
                .inputs
                .iter()
                .filter_map(|input| {
                    let syn::FnArg::Typed(typed) = input else {
                        return None;
                    };
                    if !normalized_tokens(&typed.ty).ends_with("EventSpec") {
                        return None;
                    }
                    let syn::Pat::Ident(ident) = typed.pat.as_ref() else {
                        return None;
                    };
                    Some(ident.ident.to_string())
                })
                .collect();
            let mut visitor = GenericEntryHelperVisitor {
                typed_spec_params: &typed_spec_params,
                valid: false,
            };
            visitor.visit_block(&function.block);
            visitor.valid.then(|| function.sig.ident.to_string())
        })
        .collect()
}

struct GenericEntryHelperVisitor<'a> {
    typed_spec_params: &'a BTreeSet<String>,
    valid: bool,
}

impl<'ast> Visit<'ast> for GenericEntryHelperVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if call_ends_with(&node.func, "EventEntry", "new")
            && node
                .args
                .first()
                .is_some_and(|arg| expr_has_method_on_ident(arg, "topic", self.typed_spec_params))
        {
            self.valid = true;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn expr_has_method_on_ident(
    expr: &syn::Expr,
    method: &str,
    identifiers: &BTreeSet<String>,
) -> bool {
    match peel_expr(expr) {
        syn::Expr::MethodCall(call) if call.method == method && call.args.is_empty() => {
            matches!(peel_expr(&call.receiver), syn::Expr::Path(path)
                if path.path.segments.len() == 1
                    && identifiers.contains(&path.path.segments[0].ident.to_string()))
        }
        syn::Expr::MethodCall(call) => {
            expr_has_method_on_ident(&call.receiver, method, identifiers)
                || call
                    .args
                    .iter()
                    .any(|arg| expr_has_method_on_ident(arg, method, identifiers))
        }
        syn::Expr::Call(call) => call
            .args
            .iter()
            .any(|arg| expr_has_method_on_ident(arg, method, identifiers)),
        _ => false,
    }
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr.meta.to_token_stream().to_string().contains("test"))
    })
}

fn scan_runtime_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in RUNTIME_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::RedisConsumerClaimer,
                path.display().to_string(),
                format!(
                    "禁止 runtime event consumer 重新接入旧 claimer/handler 路径: `{forbidden}`"
                ),
            ));
        }
    }
    for forbidden in runtime_redis_inbox_fragments(content) {
        findings.push(finding(
            Rule::RedisConsumerClaimer,
            path.display().to_string(),
            format!("禁止 runtime event consumer 重新接入 Redis claimer: `{forbidden}`"),
        ));
    }
    findings.extend(runtime_shape_findings(path, content));
    findings
}

#[derive(Default)]
struct RuntimeShape {
    bridged_private_shape: bool,
    generated_events_bridge: bool,
    bridged_input: bool,
    required_worker_probe_bundle: bool,
    handler_mapping: bool,
}

fn runtime_shape_findings(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            "runtime event transport Rust AST 无法解析".to_string(),
        )];
    };
    let mut shape = RuntimeShape::default();
    for item in &file.items {
        match item {
            syn::Item::Struct(item) if item.ident == "BridgedSubscription" => {
                let fields: BTreeMap<_, _> = item
                    .fields
                    .iter()
                    .filter_map(|field| {
                        field.ident.as_ref().map(|ident| (ident.to_string(), field))
                    })
                    .collect();
                shape.bridged_private_shape =
                    ["event", "subscription", "group"].iter().all(|name| {
                        fields
                            .get(*name)
                            .is_some_and(|field| matches!(field.vis, syn::Visibility::Inherited))
                    }) && !fields.contains_key("handler");
            }
            syn::Item::Fn(item) if item.sig.ident == "bridge_generated_subscriptions" => {
                let body = normalized_tokens(&item.block);
                shape.generated_events_bridge = body.contains(
                    "bridge_subscriptions_with_events(bindings,generated::event::EVENTS)",
                );
            }
            syn::Item::Fn(item) if item.sig.ident == "wire_event_transport" => {
                shape.bridged_input = item.sig.inputs.iter().any(|input| {
                    normalized_tokens(input).contains("subscribers:Vec<BridgedSubscription>")
                });
            }
            syn::Item::Fn(item) if item.sig.ident == "wire_consumer_resource_bundle" => {
                let body = normalized_tokens(&item.block);
                shape.required_worker_probe_bundle = [
                    "pg.infra().inbox()",
                    "LeaseConfig::from_ttl(inbox.lease_ttl())",
                    "dead_letter(security.dlx_payload_protector.clone())",
                    "consumer_tx_handler_for_subscription(pg,&subscription,settings_service)",
                    "spawn_consumer_ackable_tx_subscriber(",
                    "matchsubscription.readiness()",
                    "SubscriberReadiness::Required=>",
                    "module.workers.push(worker)",
                    "module.probes.push(consumer_probe)",
                    "wire_inbox_sweeper(pg,timing,module)?",
                ]
                .iter()
                .all(|required| body.contains(required));
            }
            syn::Item::Fn(item) if item.sig.ident == "consumer_tx_kind_for_subscription" => {
                shape.handler_mapping = true;
            }
            _ => {}
        }
    }

    [
        (
            shape.bridged_private_shape,
            "BridgedSubscription 必须只以私有 event/subscription/group 身份字段封装 generated topology，不得恢复 legacy handler",
        ),
        (
            shape.generated_events_bridge,
            "bridge_generated_subscriptions 必须从 generated::event::EVENTS 单一 registry 桥接",
        ),
        (
            shape.bridged_input,
            "wire_event_transport 必须消费 Vec<BridgedSubscription>",
        ),
        (
            shape.required_worker_probe_bundle,
            "consumer bundle 必须以 Required 穷尽分支成对注册 PG ConsumerTx worker 与 readyz probe",
        ),
        (
            shape.handler_mapping,
            "runtime 必须保留 generated subscription → ConsumerTx handler 的 fail-closed mapping",
        ),
    ]
    .into_iter()
    .filter(|(present, _)| !present)
    .map(|(_, message)| {
        finding(
            Rule::MissingBundleFragment,
            path.display().to_string(),
            message.to_string(),
        )
    })
    .collect()
}

fn normalized_tokens(tokens: &impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn runtime_redis_inbox_fragments(content: &str) -> BTreeSet<&'static str> {
    syn::parse_file(content)
        .map(|file| file_runtime_redis_inbox_fragments(&file))
        .unwrap_or_else(|_| text_runtime_redis_inbox_fragments(content))
}

fn text_runtime_redis_inbox_fragments(content: &str) -> BTreeSet<&'static str> {
    let mut fragments = BTreeSet::new();
    if content.contains(RUNTIME_REDIS_INBOX_FRAGMENT) {
        fragments.insert(RUNTIME_REDIS_INBOX_FRAGMENT);
    }
    fragments
}

fn scan_domain_crates(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for crate_root in domain_crate_roots() {
        let abs_root = root.join(crate_root);
        if !abs_root.exists() {
            continue;
        }
        for path in rust_files_under(&abs_root)? {
            let content = std::fs::read_to_string(&path).with_context(|| {
                format!("event-transport-guard: read domain file {}", path.display())
            })?;
            findings.extend(scan_domain_content(&rel_path(root, &path), &content));
        }
    }
    Ok(findings)
}

fn domain_crate_roots() -> Vec<String> {
    crate::layers::DOMAIN_CRATES
        .iter()
        .map(|crate_name| format!("crates/{crate_name}"))
        .collect()
}

fn scan_production_bypasses(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for top in BYPASS_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            if is_excluded(&member) {
                continue;
            }
            scan_bypass_dir(root, &member.join("src"), &mut findings)?;
        }
    }
    for leaf in BYPASS_LEAF_CRATES {
        let dir = root.join(leaf);
        if !is_excluded(&dir) {
            scan_bypass_dir(root, &dir.join("src"), &mut findings)?;
        }
    }
    Ok(findings)
}

fn scan_bypass_dir(root: &Path, dir: &Path, findings: &mut Vec<Finding<Rule>>) -> Result<()> {
    for path in rs_files(dir)? {
        let rel = rel_path(root, &path);
        if is_bypass_allowed(root, &rel)? {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("event-transport-guard: read {}", path.display()))?;
        findings.extend(scan_bypass_content(&rel, &content));
    }
    Ok(())
}

fn rust_files_under(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path)
            .with_context(|| format!("event-transport-guard: read dir {}", path.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

fn is_bypass_allowed(root: &Path, rel: &Path) -> Result<bool> {
    if BYPASS_ALLOWED_PATHS
        .iter()
        .any(|allowed| rel == Path::new(allowed))
    {
        return Ok(true);
    }
    if rel != Path::new(POSTGRES_FAULT_MATRIX_HARNESS) {
        return Ok(false);
    }
    let lib_path = root.join(POSTGRES_LIB_PATH);
    let lib_content = std::fs::read_to_string(&lib_path)
        .with_context(|| format!("event-transport-guard: read {}", lib_path.display()))?;
    Ok(is_feature_gated_fault_matrix_harness(rel, &lib_content))
}

fn is_feature_gated_fault_matrix_harness(rel: &Path, lib_content: &str) -> bool {
    rel == Path::new(POSTGRES_FAULT_MATRIX_HARNESS)
        && fault_matrix_module_has_feature_gate(lib_content)
}

fn fault_matrix_module_has_feature_gate(lib_content: &str) -> bool {
    let stripped = strip_rust_comment_lines(lib_content);
    let mut pending_attrs = Vec::new();
    for line in stripped.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("#[") {
            pending_attrs.push(line);
            continue;
        }
        if matches!(line, "pub mod fault_matrix;" | "mod fault_matrix;") {
            return pending_attrs.iter().any(|attr| {
                attr.starts_with("#[cfg(")
                    && attr.contains("feature")
                    && attr.contains("\"fault-matrix-test-support\"")
            });
        }
        pending_attrs.clear();
    }
    false
}

fn scan_domain_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in DOMAIN_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::DomainConsumerBundleBypass,
                path.display().to_string(),
                format!("consumer inbox/DLX/worker 只能经 runtime bundle 接线，域 crate 禁止片段: `{forbidden}`"),
            ));
        }
    }
    findings
}

fn scan_bypass_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let forbidden = syn::parse_file(content)
        .map(|file| file_bypass_fragments(&file))
        .unwrap_or_else(|_| text_bypass_fragments(content));
    forbidden
        .into_iter()
        .filter(|fragment| !allowed_bypass_exception(path, content, fragment))
        .map(|fragment| {
            finding(
                Rule::ProductionConsumerBundleBypass,
                path.display().to_string(),
                format!(
                    "consumer inbox/worker 只能经 generated topology bridge + runtime bundle 接线，生产 src 禁止片段: `{fragment}`"
                ),
            )
        })
        .collect()
}

fn allowed_bypass_exception(path: &Path, content: &str, fragment: &str) -> bool {
    path == Path::new("adapters/postgres/src/fault_matrix.rs")
        && fragment == "pg.infra().inbox("
        && content.contains("CONSISTENCY-FAULT-MATRIX-SEAM-01")
        && content.matches("self.deps.infra().inbox()").count() == 3
}

fn text_bypass_fragments(content: &str) -> BTreeSet<&'static str> {
    BYPASS_FORBIDDEN
        .iter()
        .copied()
        .filter(|forbidden| content.contains(forbidden))
        .collect()
}

fn strip_rust_comment_lines(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[derive(Default)]
struct RuntimeVisitor {
    forbidden_infra_aliases: BTreeSet<String>,
    fragments: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for RuntimeVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(pat_ident) = &node.pat
            && let Some(init) = &node.init
            && let Some(InfraReceiver::Forbidden) = classify_runtime_infra_call(&init.expr)
        {
            self.forbidden_infra_aliases
                .insert(pat_ident.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "inbox"
            && expr_is_runtime_forbidden_inbox_receiver(
                &node.receiver,
                &self.forbidden_infra_aliases,
            )
        {
            self.fragments.insert(RUNTIME_REDIS_INBOX_FRAGMENT);
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn file_runtime_redis_inbox_fragments(file: &syn::File) -> BTreeSet<&'static str> {
    let mut visitor = RuntimeVisitor::default();
    visitor.visit_file(file);
    visitor.fragments
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InfraReceiver {
    Pg,
    Forbidden,
}

fn expr_is_runtime_forbidden_inbox_receiver(
    expr: &syn::Expr,
    forbidden_aliases: &BTreeSet<String>,
) -> bool {
    if let Some(receiver) = classify_runtime_infra_call(expr) {
        return receiver == InfraReceiver::Forbidden;
    }
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.path.segments.len() == 1
                && forbidden_aliases.contains(&path.path.segments[0].ident.to_string())
    )
}

fn classify_runtime_infra_call(expr: &syn::Expr) -> Option<InfraReceiver> {
    match expr {
        syn::Expr::MethodCall(call) if call.method == "infra" => {
            if expr_mentions_ident(&call.receiver, "pg") {
                Some(InfraReceiver::Pg)
            } else {
                Some(InfraReceiver::Forbidden)
            }
        }
        syn::Expr::Paren(paren) => classify_runtime_infra_call(&paren.expr),
        syn::Expr::Group(group) => classify_runtime_infra_call(&group.expr),
        syn::Expr::Reference(reference) => classify_runtime_infra_call(&reference.expr),
        _ => None,
    }
}

fn expr_mentions_ident(expr: &syn::Expr, ident: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .iter()
            .any(|segment| segment.ident == ident),
        syn::Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(member) if member == ident)
                || expr_mentions_ident(&field.base, ident)
        }
        syn::Expr::MethodCall(call) => expr_mentions_ident(&call.receiver, ident),
        syn::Expr::Paren(paren) => expr_mentions_ident(&paren.expr, ident),
        syn::Expr::Group(group) => expr_mentions_ident(&group.expr, ident),
        syn::Expr::Reference(reference) => expr_mentions_ident(&reference.expr, ident),
        _ => false,
    }
}

#[derive(Default)]
struct BypassVisitor {
    imported_calls: BTreeMap<String, &'static str>,
    infra_aliases: BTreeSet<String>,
    fragments: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for BypassVisitor {
    fn visit_use_tree(&mut self, node: &'ast syn::UseTree) {
        collect_bypass_imports(node, false, &mut self.imported_calls);
        syn::visit::visit_use_tree(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(pat_ident) = &node.pat
            && let Some(init) = &node.init
            && expr_is_infra_call(&init.expr)
        {
            self.infra_aliases.insert(pat_ident.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref()
            && let Some(fragment) = call_path_bypass_fragment(&path.path, &self.imported_calls)
        {
            self.fragments.insert(fragment);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "inbox" && expr_is_infra_receiver(&node.receiver, &self.infra_aliases) {
            self.fragments.insert("pg.infra().inbox(");
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn file_bypass_fragments(file: &syn::File) -> BTreeSet<&'static str> {
    let mut visitor = BypassVisitor::default();
    visitor.visit_file(file);
    visitor.fragments
}

fn collect_bypass_imports(
    tree: &syn::UseTree,
    seen_eventexec: bool,
    imports: &mut BTreeMap<String, &'static str>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            collect_bypass_imports(
                &path.tree,
                seen_eventexec || path.ident == "eventexec",
                imports,
            );
        }
        syn::UseTree::Name(name) if seen_eventexec => {
            if let Some(fragment) = forbidden_spawn_fragment(&name.ident.to_string()) {
                imports.insert(name.ident.to_string(), fragment);
            }
        }
        syn::UseTree::Rename(rename) if seen_eventexec => {
            if let Some(fragment) = forbidden_spawn_fragment(&rename.ident.to_string()) {
                imports.insert(rename.rename.to_string(), fragment);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_bypass_imports(item, seen_eventexec, imports);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
    }
}

fn call_path_bypass_fragment(
    path: &syn::Path,
    imports: &BTreeMap<String, &'static str>,
) -> Option<&'static str> {
    let ident = path.segments.last()?.ident.to_string();
    forbidden_spawn_fragment(&ident).or_else(|| imports.get(&ident).copied())
}

fn forbidden_spawn_fragment(ident: &str) -> Option<&'static str> {
    match ident {
        "spawn_consumer" => Some("spawn_consumer("),
        "spawn_consumer_ackable" => Some("spawn_consumer_ackable("),
        "spawn_consumer_ackable_subscriber" => Some("spawn_consumer_ackable_subscriber("),
        "spawn_consumer_ackable_tx_subscriber" => Some("spawn_consumer_ackable_tx_subscriber("),
        _ => None,
    }
}

fn expr_is_infra_receiver(expr: &syn::Expr, infra_aliases: &BTreeSet<String>) -> bool {
    if expr_is_infra_call(expr) {
        return true;
    }
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.path.segments.len() == 1
                && infra_aliases.contains(&path.path.segments[0].ident.to_string())
    )
}

fn expr_is_infra_call(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::MethodCall(call) if call.method == "infra")
}

fn rel_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    fn scan_producer_source(content: &str) -> (ProducerFacts, Vec<Finding<Rule>>) {
        let file = syn::parse_file(content).unwrap();
        let imports = SpecImports::from_file(&file);
        let entry_helpers = event_entry_helpers(&file);
        let mut facts = ProducerFacts::default();
        let mut findings = Vec::new();
        let mut visitor = ProducerVisitor::new(
            &imports,
            &entry_helpers,
            Path::new("crates/identity/src/application.rs"),
            &mut facts,
            &mut findings,
        );
        visitor.visit_file(&file);
        (facts, findings)
    }

    #[test]
    fn producer_ast_accepts_generated_spec_alias_and_counts_typed_partition_key() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::identity_v1::session_created::SPEC as SESSION_SPEC;
            fn produce() {
                let entry = EventEntry::new(EventTopic::parse(SESSION_SPEC.topic())?, id, payload);
                let envelope = OutboxEnvelopeParts::new(
                    SESSION_SPEC.contract(), tenant, subject, actor
                ).with_partition_key(key);
            }
            "#,
        );
        let spec = "generated::event::identity_v1::session_created::SPEC";
        assert!(findings.is_empty(), "{findings:?}");
        assert!(facts.entries.contains(spec));
        assert!(facts.envelopes.contains(spec));
        assert_eq!(facts.partition_sites.get(spec), Some(&vec![1]));
    }

    #[test]
    fn producer_ast_resolves_single_generated_spec_glob() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::settings_v1::*;
            fn produce() {
                let entry = EventEntry::new(EventTopic::parse(SPEC.topic())?, id, payload);
                let envelope = OutboxEnvelopeParts::new(SPEC.contract(), tenant, subject, actor);
            }
            "#,
        );
        let spec = "generated::event::settings_v1::SPEC";
        assert!(findings.is_empty(), "{findings:?}");
        assert!(facts.entries.contains(spec));
        assert!(facts.envelopes.contains(spec));
    }

    #[test]
    fn producer_ast_rejects_literals_and_ignores_comment_string_spoofs() {
        let (facts, findings) = scan_producer_source(
            r#"
            use generated::event::settings_v1::SPEC;
            const NOTE: &str = "EventEntry::new(EventTopic::parse(SPEC.topic()), id, payload)";
            // OutboxEnvelopeParts::new(SPEC.contract(), tenant, subject, actor);
            fn produce() {
                let entry = EventEntry::new(EventTopic::parse("settings.changed")?, id, payload);
                let envelope = OutboxEnvelopeParts::new(CONTRACT, tenant, subject, actor);
            }
            "#,
        );
        assert!(!findings.is_empty());
        assert!(
            !facts
                .entries
                .contains("generated::event::settings_v1::SPEC")
        );
        assert!(
            !facts
                .envelopes
                .contains("generated::event::settings_v1::SPEC")
        );
    }

    /// F1 reproduction: two metadata carriers from different generated specs must not be
    /// aggregated into globally-complete facts, even when neither event uses a partition key.
    #[test]
    fn producer_ast_rejects_swapped_specs_without_partition_key() {
        let (facts, findings) = scan_producer_source(
            r#"
            fn produce() {
                let entry = EventEntry::new(
                    EventTopic::parse(generated::event::identity_v1::session_created::SPEC.topic())?,
                    id,
                    payload,
                );
                let envelope = OutboxEnvelopeParts::new(
                    generated::event::settings_v1::SPEC.contract(),
                    tenant,
                    subject,
                    actor,
                );
            }
            "#,
        );

        assert_eq!(
            findings.len(),
            1,
            "swapped SPEC must fail at its authoring function"
        );
        assert!(
            facts.entries.is_empty(),
            "invalid function facts must not be aggregated"
        );
        assert!(
            facts.envelopes.is_empty(),
            "invalid function facts must not be aggregated"
        );
        assert!(facts.partition_sites.is_empty());
    }

    #[test]
    fn aggregate_partition_strategy_requires_exactly_one_typed_key() {
        let spec = "generated::event::inventory_v1::changed::SPEC".to_string();
        let event = ActiveEvent {
            contract_id: "inventory.changed".to_string(),
            spec_path: spec.clone(),
            partition: PartitionStrategy::Aggregate,
        };
        for (count, expected_findings) in [(0, 1), (1, 0), (2, 1)] {
            let mut facts = ProducerFacts::default();
            facts.entries.insert(spec.clone());
            facts.envelopes.insert(spec.clone());
            facts.partition_sites.insert(spec.clone(), vec![count]);
            assert_eq!(
                validate_event_facts(&event, &facts).len(),
                expected_findings,
                "aggregate partition count={count}"
            );
        }

        let mut two_sites = ProducerFacts::default();
        two_sites.entries.insert(spec.clone());
        two_sites.envelopes.insert(spec.clone());
        two_sites.partition_sites.insert(spec, vec![1, 1]);
        assert!(validate_event_facts(&event, &two_sites).is_empty());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn framework_event_spec_path_comes_from_contract_path_not_owner() {
        assert_eq!(
            event_spec_path(Path::new("_seed/v1/contract.toml"), "v1", None).unwrap(),
            "generated::event::_seed_v1::SPEC"
        );
        assert_eq!(
            event_spec_path(
                Path::new("identity/v1/role-revoked/contract.toml"),
                "v1",
                Some("role_revoked")
            )
            .unwrap(),
            "generated::event::identity_v1::role_revoked::SPEC"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn workspace_event_transport_and_active_producers_pass_guard() {
        let (_summary, findings) = EventTransportGuard.check().unwrap();
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn scan_content_rejects_redis_consumer_claimer_needles() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            "let _: RedisInboxStore; let _ = \"RSS_REDIS_CLAIM_TTL_MS\";",
        );
        assert!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::RedisConsumerClaimer)
                .count()
                == 2
        );
    }

    #[test]
    fn scan_content_rejects_runtime_redis_inbox_direct_wire() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            fn wire_consumer_resource_bundle(redis: RedisRuntimeDeps) {
                let group = subscription.group().clone();
                let inbox = redis.infra().inbox(ttl);
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RedisConsumerClaimer)
        );
    }

    #[test]
    fn scan_content_rejects_runtime_redis_inbox_split_wire() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            fn wire_consumer_resource_bundle(redis: RedisRuntimeDeps) {
                let group = subscription.group().clone();
                let infra = redis.infra();
                let inbox = infra.inbox(ttl);
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RedisConsumerClaimer)
        );
    }

    #[test]
    fn scan_content_accepts_pg_inbox_bundle() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            pub struct BridgedSubscription {
                event: EventSpec,
                subscription: SubscriptionSpec,
                group: ConsumerGroup,
            }
            pub fn bridge_generated_subscriptions(bindings: Vec<SubscriberBinding>) {
                bridge_subscriptions_with_events(bindings, generated::event::EVENTS)
            }
            fn wire_event_transport(subscribers: Vec<BridgedSubscription>) {}
            fn wire_consumer_resource_bundle(pg: Pg, module: &mut Module) {
                let group = subscription.group().clone();
                let inbox = pg.infra().inbox();
                let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
                let dlx = DynDeadLetterStore::new_box(
                    pg.infra()
                        .dead_letter(security.dlx_payload_protector.clone()),
                );
                let handler = consumer_tx_handler_for_subscription(
                    pg, &subscription, settings_service
                )?;
                let worker = spawn_consumer_ackable_tx_subscriber();
                let consumer_probe = probe();
                match subscription.readiness() {
                    SubscriberReadiness::Required => {
                        module.workers.push(worker);
                        module.probes.push(consumer_probe);
                    }
                }
                wire_inbox_sweeper(pg, timing, module)?;
            }
            fn consumer_tx_kind_for_subscription() {}
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn scan_content_rejects_missing_pg_bundle_fragment() {
        let findings =
            scan_runtime_content(Path::new(TARGET), "fn wire_consumer_resource_bundle()");
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingBundleFragment)
        );
    }

    #[test]
    fn scan_domain_content_rejects_consumer_bundle_bypass() {
        let findings = scan_domain_content(
            Path::new("crates/identity/src/lib.rs"),
            "let _ = PgInboxStore; spawn_consumer_ackable_subscriber();",
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn fault_matrix_harness_skip_requires_exact_path_and_feature_gate() {
        let gated_lib = r#"
#[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
"#;
        assert!(is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            gated_lib
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new("adapters/postgres/src/nested/fault_matrix.rs"),
            gated_lib
        ));
    }

    #[test]
    fn fault_matrix_harness_skip_rejects_missing_or_wrong_gate() {
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            "pub mod fault_matrix;"
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            r#"
#[cfg(test)]
pub mod fault_matrix;
"#
        ));
        assert!(!is_feature_gated_fault_matrix_harness(
            Path::new(POSTGRES_FAULT_MATRIX_HARNESS),
            r#"
// #[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
"#
        ));
    }

    #[test]
    fn scan_bypass_content_rejects_production_spawn_outside_bridge() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            "spawn_consumer(); spawn_consumer_ackable_subscriber();",
        );
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ProductionConsumerBundleBypass)
        );
    }

    #[test]
    fn scan_bypass_content_rejects_tx_spawn_direct_and_qualified() {
        for content in [
            "fn wire() { spawn_consumer_ackable_tx_subscriber(); }",
            "fn wire() { eventexec::spawn_consumer_ackable_tx_subscriber(); }",
        ] {
            let findings =
                scan_bypass_content(Path::new("assemblies/runtime/src/other.rs"), content);
            assert_eq!(findings.len(), 1, "{content}");
            assert_eq!(findings[0].rule, Rule::ProductionConsumerBundleBypass);
        }
    }

    #[test]
    fn scan_bypass_content_rejects_import_alias_and_split_infra_receiver() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            r#"
            use eventexec::{spawn_consumer_ackable_tx_subscriber as spawn_it};

            fn wire(pg: PgRuntimeDeps) {
                spawn_it();
                let infra = pg.infra();
                infra.inbox();
            }
            "#,
        );
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ProductionConsumerBundleBypass)
        );
    }

    #[test]
    fn scan_bypass_content_ignores_strings_and_comments() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            r#"
            // spawn_consumer();
            const NOTE: &str = "pg.infra().inbox()";
            "#,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn domain_roots_include_all_layer_domain_crates() {
        let roots = domain_crate_roots();
        assert_eq!(
            roots,
            vec![
                "crates/identity",
                "crates/settings",
                "crates/audit",
                "crates/contractreg",
                "crates/syshealth",
            ]
        );
    }

    #[test]
    fn scan_domain_content_rejects_bypass_in_contractreg_and_syshealth() {
        for path in [
            Path::new("crates/contractreg/src/lib.rs"),
            Path::new("crates/syshealth/src/lib.rs"),
        ] {
            let findings = scan_domain_content(path, "let _ = pg.infra().inbox();");
            assert_eq!(findings.len(), 1, "{path:?}");
            assert_eq!(findings[0].rule, Rule::DomainConsumerBundleBypass);
        }
    }

    #[test]
    fn scan_bypass_content_accepts_registered_fault_matrix_inbox_harness() {
        let findings = scan_bypass_content(
            Path::new("adapters/postgres/src/fault_matrix.rs"),
            r#"
            const MARKER: &str = "CONSISTENCY-FAULT-MATRIX-SEAM-01";
            async fn a(&self) { let store = self.deps.infra().inbox(); }
            async fn b(&self) { let store = self.deps.infra().inbox(); }
            async fn c(&self) { let store = self.deps.infra().inbox(); }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn production_bypass_allowlist_does_not_skip_fault_matrix_file() {
        assert!(
            !BYPASS_ALLOWED_PATHS.contains(&"adapters/postgres/src/fault_matrix.rs"),
            "fault_matrix.rs must use site-level exceptions so new bypasses are still scanned"
        );
    }

    #[test]
    fn scan_bypass_content_rejects_extra_fault_matrix_inbox_harness() {
        let findings = scan_bypass_content(
            Path::new("adapters/postgres/src/fault_matrix.rs"),
            r#"
            const MARKER: &str = "CONSISTENCY-FAULT-MATRIX-SEAM-01";
            async fn a(&self) { let store = self.deps.infra().inbox(); }
            async fn b(&self) { let store = self.deps.infra().inbox(); }
            async fn c(&self) { let store = self.deps.infra().inbox(); }
            async fn d(&self) { let store = self.deps.infra().inbox(); }
            "#,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::ProductionConsumerBundleBypass);
    }
}
