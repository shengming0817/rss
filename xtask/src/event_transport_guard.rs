//! runtime event transport source guard.
//!
//! INVARIANT: EVENT-TRANSPORT-PG-INBOX-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_missing_pg_bundle_fragment", anti_vacuity = "tests::scan_content_accepts_pg_inbox_bundle" }——
//! `assemblies/runtime/src/event_transport.rs` 的 consumer idempotency must come from PG inbox, not Redis,
//! and production consumer workers must go through the generated-topology bridge.
//! INVARIANT: EVENT-PRODUCER-SPEC-PAIR-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::producer_ast_rejects_swapped_specs_without_partition_key", anti_vacuity = "tests::producer_ast_accepts_generated_spec_alias_and_counts_typed_partition_key" }——
//! every authoring function must use exactly one identical generated SPEC for its EventEntry and
//! envelope before any fact is admitted to the global topology set.
//! INVARIANT: OUTBOX-RELAY-CLAIM-CUTOVER-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::outbox_claim_cutover_synthetic_red_rejects_legacy_production_paths", anti_vacuity = "tests::outbox_claim_cutover_accepts_canonical_and_non_production_bait" }——
//! production outbox relay providers, runtime wiring, eventexec dispatch, and post-cutover SQL must
//! remain on the single claimed-entry protocol; cross-crate/source-set completeness is enforced by
//! AST/SQL synthetic-red plus a canonical workspace green fixture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use quote::ToTokens;
use syn::spanned::Spanned as _;
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
    OutboxClaimCutover,
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
        let claim_cutover_sources = load_outbox_claim_cutover_sources(&root)?;
        findings.extend(scan_outbox_claim_cutover_sources(&claim_cutover_sources));
        Ok((
            format!(
                "{TARGET} 经 generated topology bridge + ConsumerTx PG inbox bundle 接线，生产 src 无散装 consumer bundle/outbox split claim"
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
                shape.bridged_private_shape = ["event", "subscription", "group", "consumer_tx"]
                    .iter()
                    .all(|name| {
                        fields
                            .get(*name)
                            .is_some_and(|field| matches!(field.vis, syn::Visibility::Inherited))
                    })
                    && !fields.contains_key("handler");
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
                    "consumer_tx_handler_for_subscription(pg,&subscription)",
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
            syn::Item::Fn(item) if item.sig.ident == "resolve_consumer_tx_plan" => {
                shape.handler_mapping = consumer_tx_plan_resolver_is_closed(item);
            }
            _ => {}
        }
    }

    [
        (
            shape.bridged_private_shape,
            "BridgedSubscription 必须以私有 event/subscription/group/consumer_tx 字段封装 generated topology 与已解析闭执行计划，不得恢复 legacy handler",
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
            "runtime 必须以单一 resolver 穷尽匹配 generated typed dispatch key → ConsumerTx plan，且不得使用 wildcard/guard",
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

fn consumer_tx_plan_resolver_is_closed(item: &syn::ItemFn) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Match(mapping), None)) = item.block.stmts.last() else {
        return false;
    };
    normalized_tokens(&mapping.expr) == "spec.dispatch()"
        && !mapping.arms.is_empty()
        && mapping.arms.iter().all(|arm| {
            arm.guard.is_none()
                && matches!(&arm.pat, syn::Pat::Path(path)
                    if path.path.segments.len() == 2
                        && path.path.segments[0].ident == "SubscriptionDispatchKey")
        })
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
    files_with_extension_under(dir, "rs")
}

fn files_with_extension_under(dir: &Path, extension: &str) -> Result<Vec<PathBuf>> {
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
            } else if path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
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

const EVENTEXEC_RELAY_PATH: &str = "crates/eventexec/src/relay.rs";
const POSTGRES_OUTBOX_PATH: &str = "adapters/postgres/src/outbox.rs";
const LEGACY_OUTBOX_MIGRATIONS: &[&str] = &[
    "adapters/postgres/migrations/0031_harden_outbox_tenant_scope.sql",
    "adapters/postgres/migrations/0036_add_outbox_schema_columns.sql",
    "adapters/postgres/migrations/0037_outbox_metric_scope_functions.sql",
];
const RETIRED_OUTBOX_FUNCTIONS: &[&str] = &["RSS_OUTBOX_POLL_PENDING", "RSS_OUTBOX_ACQUIRE_LEASE"];
const ATOMIC_OUTBOX_CLAIM_MIGRATION: &str =
    "adapters/postgres/migrations/0057_atomic_outbox_claim.sql";

#[derive(Debug)]
struct ForbiddenOccurrence {
    token: String,
    line: usize,
}

fn load_outbox_claim_cutover_sources(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut paths = workspace_member_source_files(root)?;
    let migrations = root.join("adapters/postgres/migrations");
    for entry in std::fs::read_dir(&migrations)
        .with_context(|| format!("outbox claim cutover: read dir {}", migrations.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("sql") {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let relative = rel_path(root, &path);
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("outbox claim cutover: read {}", path.display()))?;
            Ok((relative, content))
        })
        .collect()
}

fn workspace_member_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest_path = root.join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("outbox claim cutover: read {}", manifest_path.display()))?;
    let manifest: toml::Value = toml::from_str(&manifest)
        .with_context(|| format!("outbox claim cutover: parse {}", manifest_path.display()))?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .context("outbox claim cutover: workspace.members must be an explicit array")?;
    let mut files = BTreeSet::new();
    for member in members {
        let member = member
            .as_str()
            .context("outbox claim cutover: workspace member must be a string")?;
        let member_root = root.join(member);
        let manifest = member_root.join("Cargo.toml");
        if manifest.is_file() {
            files.insert(manifest);
        }
        let src = member_root.join("src");
        if !src.is_dir() {
            files.extend(files_with_extension_under(&member_root, "sql")?);
        } else {
            files.extend(rust_files_under(&src)?);
            files.extend(files_with_extension_under(&member_root, "sql")?);
        }
    }
    Ok(files.into_iter().collect())
}

fn scan_outbox_claim_cutover_sources(sources: &[(PathBuf, String)]) -> Vec<Finding<Rule>> {
    let test_only_files = external_cfg_test_module_paths(sources);
    let relay_imports = relay_trait_imports_by_source(sources, &test_only_files);
    let mut findings = Vec::new();
    for (path, content) in sources {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("rs") if !test_only_files.contains(path) => {
                findings.extend(scan_outbox_claim_rust(
                    path,
                    content,
                    relay_imports.get(path).cloned().unwrap_or_default(),
                ))
            }
            Some("rs") => {}
            Some("sql") => findings.extend(scan_outbox_claim_sql(path, content)),
            _ => {}
        }
    }
    findings
}

#[derive(Default)]
struct OutboxClaimRustVisitor {
    path: PathBuf,
    relay_trait_names: BTreeMap<Vec<String>, BTreeSet<String>>,
    relay_canonical_roots: BTreeSet<String>,
    relay_crate_exports: BTreeSet<Vec<String>>,
    /// `macro_rules!` name → whether its body generates an `OutboxRelay` impl.
    local_macros: BTreeMap<Vec<String>, BTreeMap<String, bool>>,
    sqlx_query_aliases: BTreeMap<Vec<String>, BTreeSet<String>>,
    sqlx_crate_aliases: BTreeMap<Vec<String>, BTreeSet<String>>,
    module_path: Vec<String>,
    forbidden: Vec<ForbiddenOccurrence>,
    canonical_provider_count: usize,
}

impl OutboxClaimRustVisitor {
    fn new(path: &Path, imports: RelayTraitImports, file: &syn::File) -> Self {
        let forbidden = imports
            .ambiguous_glob_lines
            .iter()
            .map(|line| ForbiddenOccurrence {
                token: "consistency glob import may hide OutboxRelay impl".to_string(),
                line: *line,
            })
            .collect();
        let relay_names = imports
            .names
            .values()
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>();
        Self {
            path: path.to_path_buf(),
            relay_trait_names: imports.names,
            relay_canonical_roots: imports.canonical_roots,
            relay_crate_exports: imports.crate_exports,
            local_macros: collect_local_macro_defs(file, &relay_names, &imports.module_path),
            sqlx_query_aliases: BTreeMap::new(),
            sqlx_crate_aliases: BTreeMap::new(),
            module_path: imports.module_path,
            forbidden,
            canonical_provider_count: 0,
        }
    }

    fn reject_ident(&mut self, ident: &syn::Ident) {
        self.reject_name(&ident.to_string(), ident.span().start().line);
    }

    fn reject_name(&mut self, name: &str, line: usize) {
        if (is_outbox_claim_context(&self.path)
            && matches!(name, "OutboxSource" | "PendingEntry" | "poll_pending"))
            || is_outbox_acquire_helper(&self.path, name)
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: name.to_string(),
                line,
            });
        }
    }

    fn inspect_relay_impl(&mut self, node: &syn::ItemImpl) {
        let Some((_, trait_path, _)) = &node.trait_ else {
            return;
        };
        let trait_segments = trait_path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let canonical = relay_path_is_canonical(&trait_segments, &self.relay_canonical_roots)
            || match trait_segments.as_slice() {
                [relay] => self
                    .relay_trait_names
                    .get(&self.module_path)
                    .is_some_and(|names| names.contains(relay)),
                _ => resolve_relay_symbol(&trait_segments, &self.module_path)
                    .is_some_and(|symbol| self.relay_crate_exports.contains(&symbol)),
            };
        if !canonical {
            return;
        }
        let provider = normalized_tokens(&node.self_ty);
        if self.path == Path::new(POSTGRES_OUTBOX_PATH) && provider == "PgOutbox" {
            self.canonical_provider_count += 1;
        } else {
            self.forbidden.push(ForbiddenOccurrence {
                token: format!("impl OutboxRelay for {provider}"),
                line: node.span().start().line,
            });
        }
    }

    fn reject_sqlx_query(&mut self, sql: &str, line: usize) {
        for statement in direct_sql_statements(sql) {
            if let Some((operation, retired)) = retired_sql_operation(&statement.text) {
                self.forbidden.push(ForbiddenOccurrence {
                    token: format!("sqlx {operation} retired function `{retired}`"),
                    line,
                });
            }
        }
    }

    fn is_sqlx_query_callable(&self, path: &syn::Path) -> bool {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if sqlx_query_path(path) {
            return true;
        }
        match segments.as_slice() {
            [alias]
                if self
                    .scoped_set_contains(&self.sqlx_query_aliases, alias)
                    .is_some() =>
            {
                true
            }
            [crate_alias, rest @ ..]
                if rest.last().is_some_and(|name| name.starts_with("query"))
                    && self
                        .scoped_set_contains(&self.sqlx_crate_aliases, crate_alias)
                        .is_some() =>
            {
                true
            }
            _ => false,
        }
    }

    fn scoped_set_contains<'a>(
        &self,
        table: &'a BTreeMap<Vec<String>, BTreeSet<String>>,
        name: &str,
    ) -> Option<&'a String> {
        let mut scope = self.module_path.clone();
        loop {
            if let Some(names) = table.get(&scope)
                && let Some(found) = names.get(name)
            {
                return Some(found);
            }
            if scope.is_empty() {
                return None;
            }
            scope.pop();
        }
    }

    fn lookup_local_macro(&self, name: &str) -> Option<bool> {
        let mut scope = self.module_path.clone();
        loop {
            if let Some(defs) = self.local_macros.get(&scope)
                && let Some(generates) = defs.get(name)
            {
                return Some(*generates);
            }
            if scope.is_empty() {
                return None;
            }
            scope.pop();
        }
    }

    fn module_imports_relay_trait(&self) -> bool {
        let mut scope = self.module_path.clone();
        loop {
            if self
                .relay_trait_names
                .get(&scope)
                .is_some_and(|names| !names.is_empty())
            {
                return true;
            }
            if scope.is_empty() {
                return false;
            }
            scope.pop();
        }
    }

    fn tokens_mention_relay_impl(&self, tokens: &str) -> bool {
        let mentions_relay = tokens
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|word| {
                word == "OutboxRelay"
                    || self
                        .relay_trait_names
                        .get(&self.module_path)
                        .is_some_and(|names| names.contains(word))
            });
        mentions_relay && tokens.split_whitespace().any(|token| token == "impl")
    }

    fn inspect_relay_macro(&mut self, node: &syn::Macro) {
        if node.path.is_ident("macro_rules") {
            return;
        }
        let Some(macro_name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        let local = self.lookup_local_macro(&macro_name);
        if local == Some(true)
            || self.tokens_mention_relay_impl(&node.tokens.to_string())
            || (local.is_none()
                && macro_name.to_ascii_lowercase().contains("impl")
                && self.module_imports_relay_trait())
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: "macro-generated OutboxRelay impl".to_string(),
                line: node.span().start().line,
            });
        }
    }

    fn record_sqlx_use_bindings(&mut self, tree: &syn::UseTree) {
        let mut bindings = Vec::new();
        collect_relay_use_bindings(tree, Vec::new(), &self.module_path, 0, &mut bindings);
        for binding in bindings {
            if binding.glob {
                continue;
            }
            if binding.path.as_slice() == ["sqlx"] {
                self.sqlx_crate_aliases
                    .entry(binding.scope.clone())
                    .or_default()
                    .insert(binding.local.clone());
            }
            if binding.path.first().is_some_and(|root| root == "sqlx")
                && binding
                    .path
                    .last()
                    .is_some_and(|name| name.starts_with("query"))
                && binding.path.len() >= 2
            {
                self.sqlx_query_aliases
                    .entry(binding.scope)
                    .or_default()
                    .insert(binding.local);
            }
        }
    }
}

impl<'ast> Visit<'ast> for OutboxClaimRustVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let Some((_, items)) = &node.content else {
            return;
        };
        self.module_path.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.module_path.pop();
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_claim_test_only(&node.attrs) {
            self.record_sqlx_use_bindings(&node.tree);
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.sig.ident);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.inspect_relay_impl(node);
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.sig.ident);
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        self.reject_ident(&node.ident);
        syn::visit::visit_item_type(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        for segment in &node.segments {
            self.reject_ident(&segment.ident);
        }
        syn::visit::visit_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "poll_pending"
            && (is_outbox_claim_context(&self.path)
                || normalized_tokens(&node.receiver)
                    .to_ascii_lowercase()
                    .contains("outbox"))
        {
            self.forbidden.push(ForbiddenOccurrence {
                token: node.method.to_string(),
                line: node.method.span().start().line,
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = peel_expr(&node.func)
            && self.is_sqlx_query_callable(&function.path)
            && let Some(sql) = node.args.iter().find_map(expr_string_literal)
        {
            self.reject_sqlx_query(&sql.value(), sql.span().start().line);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.is_sqlx_query_callable(&node.path) {
            if let Some(sql) = first_string_literal(&node.tokens) {
                self.reject_sqlx_query(&sql.value(), sql.span().start().line);
            }
        } else {
            self.inspect_relay_macro(node);
        }
        syn::visit::visit_macro(self, node);
    }
}

fn is_outbox_claim_context(path: &Path) -> bool {
    path == Path::new(EVENTEXEC_RELAY_PATH)
        || path == Path::new(POSTGRES_OUTBOX_PATH)
        || path.components().any(|component| {
            component
                .as_os_str()
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("outbox")
        })
}

fn relay_path_is_canonical(path: &[String], canonical_roots: &BTreeSet<String>) -> bool {
    if !path
        .first()
        .is_some_and(|root| canonical_roots.contains(root))
    {
        return false;
    }
    match path.get(1..) {
        Some([relay]) => relay == "OutboxRelay",
        Some([module, relay]) => module == "outbox" && relay == "OutboxRelay",
        _ => false,
    }
}

fn sqlx_query_path(path: &syn::Path) -> bool {
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    segments.first().is_some_and(|root| root == "sqlx")
        && segments
            .last()
            .is_some_and(|name| name.starts_with("query"))
}

fn expr_string_literal(expr: &syn::Expr) -> Option<&syn::LitStr> {
    let syn::Expr::Lit(literal) = peel_expr(expr) else {
        return None;
    };
    let syn::Lit::Str(string) = &literal.lit else {
        return None;
    };
    Some(string)
}

fn first_string_literal(tokens: &proc_macro2::TokenStream) -> Option<syn::LitStr> {
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(string) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    return Some(string);
                }
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(string) = first_string_literal(&group.stream()) {
                    return Some(string);
                }
            }
            proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => {}
        }
    }
    None
}

#[derive(Clone, Default)]
struct RelayTraitImports {
    names: BTreeMap<Vec<String>, BTreeSet<String>>,
    canonical_roots: BTreeSet<String>,
    crate_exports: BTreeSet<Vec<String>>,
    module_path: Vec<String>,
    ambiguous_glob_lines: Vec<usize>,
}

#[derive(Clone)]
struct RelayUseBinding {
    path: Vec<String>,
    local: String,
    scope: Vec<String>,
    glob: bool,
    line: usize,
}

struct RelaySourceBindings {
    path: PathBuf,
    crate_key: String,
    module_path: Vec<String>,
    bindings: Vec<RelayUseBinding>,
    canonical_roots: BTreeSet<String>,
}

fn relay_trait_imports_by_source(
    sources: &[(PathBuf, String)],
    test_only_files: &BTreeSet<PathBuf>,
) -> BTreeMap<PathBuf, RelayTraitImports> {
    let dependency_aliases = consistency_dependency_aliases(sources);
    let files = sources
        .iter()
        .filter(|(path, _)| {
            path.extension().and_then(|extension| extension.to_str()) == Some("rs")
                && !test_only_files.contains(path)
        })
        .filter_map(|(path, content)| {
            let file = syn::parse_file(content).ok()?;
            if is_claim_test_only(&file.attrs) {
                return None;
            }
            let module_path = source_module_path(path);
            let crate_key = source_crate_key(path);
            let mut collector = RelayUseVisitor::new(module_path.clone());
            collector.visit_file(&file);
            let mut canonical_roots = BTreeSet::from(["consistency".to_string()]);
            canonical_roots.extend(
                dependency_aliases
                    .get(&crate_key)
                    .into_iter()
                    .flatten()
                    .cloned(),
            );
            canonical_roots.extend(
                collector
                    .bindings
                    .iter()
                    .filter(|binding| binding.path.as_slice() == ["consistency"])
                    .map(|binding| binding.local.clone()),
            );
            Some(RelaySourceBindings {
                path: path.clone(),
                crate_key,
                module_path,
                bindings: collector.bindings,
                canonical_roots,
            })
        })
        .collect::<Vec<_>>();

    let mut exports = BTreeMap::<String, BTreeSet<Vec<String>>>::new();
    exports
        .entry("crates/consistency".to_string())
        .or_default()
        .insert(vec!["OutboxRelay".to_string()]);
    exports
        .entry("crates/consistency".to_string())
        .or_default()
        .insert(vec!["outbox".to_string(), "OutboxRelay".to_string()]);
    loop {
        let mut changed = false;
        for file in &files {
            for binding in &file.bindings {
                if relay_binding_is_canonical(binding, file, &exports) {
                    let mut symbol = binding.scope.clone();
                    symbol.push(binding.local.clone());
                    changed |= exports
                        .entry(file.crate_key.clone())
                        .or_default()
                        .insert(symbol);
                }
            }
        }
        if !changed {
            break;
        }
    }

    files
        .into_iter()
        .map(|file| {
            let crate_exports = exports.get(&file.crate_key).cloned().unwrap_or_default();
            let mut imports = RelayTraitImports {
                canonical_roots: file.canonical_roots.clone(),
                crate_exports,
                module_path: file.module_path.clone(),
                ..RelayTraitImports::default()
            };
            for binding in &file.bindings {
                if relay_binding_is_canonical(binding, &file, &exports) {
                    imports
                        .names
                        .entry(binding.scope.clone())
                        .or_default()
                        .insert(binding.local.clone());
                }
                if binding.glob && relay_glob_targets_canonical(binding, &file, &exports) {
                    imports.ambiguous_glob_lines.push(binding.line);
                }
            }
            (file.path, imports)
        })
        .collect()
}

fn relay_binding_is_canonical(
    binding: &RelayUseBinding,
    file: &RelaySourceBindings,
    exports: &BTreeMap<String, BTreeSet<Vec<String>>>,
) -> bool {
    relay_path_is_canonical(&binding.path, &file.canonical_roots)
        || resolve_relay_symbol(&binding.path, &binding.scope).is_some_and(|symbol| {
            exports
                .get(&file.crate_key)
                .is_some_and(|symbols| symbols.contains(&symbol))
        })
}

fn consistency_dependency_aliases(
    sources: &[(PathBuf, String)],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut aliases = BTreeMap::<String, BTreeSet<String>>::new();
    for (path, content) in sources
        .iter()
        .filter(|(path, _)| path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml"))
    {
        let Ok(manifest) = toml::from_str::<toml::Value>(content) else {
            continue;
        };
        let Some(root) = manifest.as_table() else {
            continue;
        };
        let crate_key = path
            .parent()
            .map(|parent| parent.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        collect_consistency_aliases(root, aliases.entry(crate_key).or_default());
    }
    aliases
}

fn collect_consistency_aliases(table: &toml::value::Table, aliases: &mut BTreeSet<String>) {
    for (key, value) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "dev-dependencies" | "build-dependencies"
        ) {
            let Some(dependencies) = value.as_table() else {
                continue;
            };
            for (alias, dependency) in dependencies {
                let canonical = alias == "consistency"
                    || dependency
                        .as_table()
                        .and_then(|entry| entry.get("package"))
                        .and_then(toml::Value::as_str)
                        == Some("consistency");
                if canonical {
                    aliases.insert(alias.replace('-', "_"));
                }
            }
        } else if let Some(nested) = value.as_table() {
            collect_consistency_aliases(nested, aliases);
        }
    }
}

fn relay_glob_targets_canonical(
    binding: &RelayUseBinding,
    file: &RelaySourceBindings,
    exports: &BTreeMap<String, BTreeSet<Vec<String>>>,
) -> bool {
    if binding
        .path
        .first()
        .is_some_and(|root| file.canonical_roots.contains(root))
    {
        return true;
    }
    let Some(module) = resolve_relay_symbol(&binding.path, &binding.scope) else {
        return false;
    };
    exports.get(&file.crate_key).is_some_and(|symbols| {
        symbols
            .iter()
            .any(|symbol| symbol.len() == module.len() + 1 && symbol.starts_with(module.as_slice()))
    })
}

fn resolve_relay_symbol(path: &[String], scope: &[String]) -> Option<Vec<String>> {
    let (mut symbol, cursor) = match path.first().map(String::as_str) {
        Some("crate") => (Vec::new(), 1),
        Some("self") => (scope.to_vec(), 1),
        Some("super") => {
            let mut symbol = scope.to_vec();
            let mut cursor = 0;
            while path.get(cursor).is_some_and(|segment| segment == "super") {
                symbol.pop()?;
                cursor += 1;
            }
            (symbol, cursor)
        }
        Some(_) => (scope.to_vec(), 0),
        None => return None,
    };
    symbol.extend(path[cursor..].iter().cloned());
    Some(symbol)
}

struct RelayUseVisitor {
    bindings: Vec<RelayUseBinding>,
    scope: Vec<String>,
}

impl RelayUseVisitor {
    fn new(scope: Vec<String>) -> Self {
        Self {
            bindings: Vec::new(),
            scope,
        }
    }
}

impl<'ast> Visit<'ast> for RelayUseVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if is_claim_test_only(&node.attrs) {
            return;
        }
        let Some((_, items)) = &node.content else {
            return;
        };
        self.scope.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.scope.pop();
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if !is_claim_test_only(&node.attrs) {
            collect_relay_use_bindings(
                &node.tree,
                Vec::new(),
                &self.scope,
                node.span().start().line,
                &mut self.bindings,
            );
        }
    }
}

fn collect_relay_use_bindings(
    tree: &syn::UseTree,
    mut prefix: Vec<String>,
    scope: &[String],
    line: usize,
    bindings: &mut Vec<RelayUseBinding>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_relay_use_bindings(&path.tree, prefix, scope, line, bindings);
        }
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            bindings.push(RelayUseBinding {
                path: prefix,
                local: name.ident.to_string(),
                scope: scope.to_vec(),
                glob: false,
                line,
            });
        }
        syn::UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            bindings.push(RelayUseBinding {
                path: prefix,
                local: rename.rename.to_string(),
                scope: scope.to_vec(),
                glob: false,
                line,
            });
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_relay_use_bindings(item, prefix.clone(), scope, line, bindings);
            }
        }
        syn::UseTree::Glob(_) => {
            bindings.push(RelayUseBinding {
                path: prefix,
                local: String::new(),
                scope: scope.to_vec(),
                glob: true,
                line,
            });
        }
    }
}

fn source_crate_key(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .take_while(|part| *part != "src")
        .collect::<Vec<_>>()
        .join("/")
}

fn source_module_path(path: &Path) -> Vec<String> {
    let mut segments = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str().map(str::to_string),
            _ => None,
        })
        .skip_while(|part| part != "src")
        .skip(1)
        .collect::<Vec<_>>();
    let Some(file) = segments.pop() else {
        return Vec::new();
    };
    match file.as_str() {
        "lib.rs" | "main.rs" | "mod.rs" => segments,
        _ => {
            segments.push(file.strip_suffix(".rs").unwrap_or(&file).to_string());
            segments
        }
    }
}

fn is_claim_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| cfg_meta_implies_test(&meta)))
    })
}

fn cfg_meta_implies_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let Ok(children) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return false;
            };
            if list.path.is_ident("all") {
                children.iter().any(cfg_meta_implies_test)
            } else {
                !children.is_empty() && children.iter().all(cfg_meta_implies_test)
            }
        }
        syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
    }
}

fn external_cfg_test_module_paths(sources: &[(PathBuf, String)]) -> BTreeSet<PathBuf> {
    let available = sources
        .iter()
        .filter(|(path, _)| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    let mut intrinsic_test_only = BTreeSet::new();
    let mut test_only_refs = BTreeSet::new();
    let mut production_refs = BTreeSet::new();
    for (path, content) in sources {
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Ok(file) = syn::parse_file(content) else {
            continue;
        };
        let file_test_only = is_claim_test_only(&file.attrs);
        if file_test_only {
            intrinsic_test_only.insert(path.clone());
        }
        let base = rust_module_base(path);
        collect_external_module_reachability(
            &file.items,
            &base,
            file_test_only,
            &available,
            &mut test_only_refs,
            &mut production_refs,
        );
    }
    let mut excluded = intrinsic_test_only;
    excluded.extend(test_only_refs.difference(&production_refs).cloned());
    excluded
}

fn rust_module_base(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    match path.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
    }
}

fn collect_external_module_reachability(
    items: &[syn::Item],
    base: &Path,
    inherited_test_only: bool,
    available: &BTreeSet<PathBuf>,
    test_only_refs: &mut BTreeSet<PathBuf>,
    production_refs: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let test_only = inherited_test_only || is_claim_test_only(&module.attrs);
        if let Some((_, nested)) = &module.content {
            collect_external_module_reachability(
                nested,
                &base.join(module.ident.to_string()),
                test_only,
                available,
                test_only_refs,
                production_refs,
            );
            continue;
        }
        for candidate in [
            base.join(format!("{}.rs", module.ident)),
            base.join(module.ident.to_string()).join("mod.rs"),
        ] {
            if available.contains(&candidate) {
                if test_only {
                    test_only_refs.insert(candidate);
                } else {
                    production_refs.insert(candidate);
                }
            }
        }
    }
}

fn is_outbox_acquire_helper(path: &Path, ident: &str) -> bool {
    let explicit_outbox_helper =
        ident.contains("outbox") && ident.contains("acquire") && ident.contains("lease");
    let contextual_helper = ident == "acquire_lease"
        && (path == Path::new(EVENTEXEC_RELAY_PATH)
            || path
                .components()
                .any(|component| component.as_os_str().to_string_lossy().contains("outbox")));
    explicit_outbox_helper || contextual_helper
}

fn collect_local_macro_defs(
    file: &syn::File,
    relay_names: &BTreeSet<String>,
    module_path: &[String],
) -> BTreeMap<Vec<String>, BTreeMap<String, bool>> {
    struct Collector<'a> {
        scope: Vec<String>,
        relay_names: &'a BTreeSet<String>,
        defs: BTreeMap<Vec<String>, BTreeMap<String, bool>>,
    }

    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if is_claim_test_only(&node.attrs) {
                return;
            }
            let Some((_, items)) = &node.content else {
                return;
            };
            self.scope.push(node.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.scope.pop();
        }

        fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
            if is_claim_test_only(&node.attrs) || !node.mac.path.is_ident("macro_rules") {
                return;
            }
            let Some(name) = &node.ident else {
                return;
            };
            let tokens = node.mac.tokens.to_string();
            let mentions_relay = tokens
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|word| word == "OutboxRelay" || self.relay_names.contains(word));
            let generates =
                mentions_relay && tokens.split_whitespace().any(|token| token == "impl");
            self.defs
                .entry(self.scope.clone())
                .or_default()
                .insert(name.to_string(), generates);
        }
    }

    let mut collector = Collector {
        scope: module_path.to_vec(),
        relay_names,
        defs: BTreeMap::new(),
    };
    collector.visit_file(file);
    collector.defs
}

fn scan_outbox_claim_rust(
    path: &Path,
    content: &str,
    imports: RelayTraitImports,
) -> Vec<Finding<Rule>> {
    let Ok(file) = syn::parse_file(content) else {
        return vec![finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "outbox claimed-entry carrier Rust AST 无法解析".to_string(),
        )];
    };
    let mut visitor = OutboxClaimRustVisitor::new(path, imports, &file);
    visitor.visit_file(&file);
    visitor.forbidden.sort_by_key(|occurrence| occurrence.line);
    let mut findings = visitor
        .forbidden
        .into_iter()
        .map(|occurrence| {
            finding(
                Rule::OutboxClaimCutover,
                format!("{}:{}", path.display(), occurrence.line),
                format!(
                    "claimed-entry cutover 禁止生产 legacy/rogue 路径: `{}`",
                    occurrence.token
                ),
            )
        })
        .collect::<Vec<_>>();
    if path == Path::new(POSTGRES_OUTBOX_PATH) && visitor.canonical_provider_count != 1 {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "canonical provider 必须恰有一个 `impl OutboxRelay for PgOutbox`".to_string(),
        ));
    }
    if path == Path::new(EVENTEXEC_RELAY_PATH) && !eventexec_claim_flow_is_connected(&file) {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "eventexec 必须保持 claim_batch → Vec<A::Claim> → relay(claim)".to_string(),
        ));
    }
    if path == Path::new(TARGET) && !runtime_relay_worker_is_connected(&file) {
        findings.push(finding(
            Rule::OutboxClaimCutover,
            path.display().to_string(),
            "runtime wire_domain_relay 必须将 canonical PgOutbox 交给已注册 WorkerSpec 的 spawn_relay"
                .to_string(),
        ));
    }
    findings
}

#[derive(Clone)]
struct RelayBatchContract {
    store_index: usize,
    claim_index: usize,
}

fn eventexec_claim_flow_is_connected(file: &syn::File) -> bool {
    let Some(domain) = unique_top_level_fn(file, "relay_domain_once") else {
        return false;
    };
    let Some(batch) = unique_top_level_fn(file, "relay_batch") else {
        return false;
    };
    let Some(contract) = relay_batch_contract(batch) else {
        return false;
    };
    relay_domain_calls_batch_with_claim(domain, &contract)
}

fn unique_top_level_fn<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    let mut functions = file.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function)
            if function.sig.ident == name && !has_test_attr(&function.attrs) =>
        {
            Some(function)
        }
        _ => None,
    });
    let function = functions.next()?;
    functions.next().is_none().then_some(function)
}

fn relay_batch_contract(function: &syn::ItemFn) -> Option<RelayBatchContract> {
    let parameters = function_parameters(&function.sig);
    let claim_parameters = parameters
        .iter()
        .filter(|(_, _, ty)| {
            let rendered = normalized_tokens(*ty);
            rendered.starts_with("Vec<") && rendered.contains("::Claim>")
        })
        .collect::<Vec<_>>();
    let [claim_parameter] = claim_parameters.as_slice() else {
        return None;
    };
    let claim_index = claim_parameter.0;
    let claim_name = claim_parameter.1.as_str();
    let matching = function
        .block
        .stmts
        .iter()
        .filter_map(statement_expr)
        .filter_map(|expr| awaited_call(expr, "join_all"))
        .filter_map(|call| call.args.first().and_then(relay_map_contract))
        .filter(|(claims, _)| claims == claim_name)
        .collect::<Vec<_>>();
    let [(_, store)] = matching.as_slice() else {
        return None;
    };
    let store_index = parameters
        .iter()
        .find_map(|(index, name, _)| (name == store).then_some(*index))?;
    Some(RelayBatchContract {
        store_index,
        claim_index,
    })
}

fn function_parameters(signature: &syn::Signature) -> Vec<(usize, String, &syn::Type)> {
    signature
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| match input {
            syn::FnArg::Typed(typed) => {
                pat_ident(&typed.pat).map(|name| (index, name, typed.ty.as_ref()))
            }
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn pat_ident(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(typed) => pat_ident(&typed.pat),
        _ => None,
    }
}

fn relay_map_contract(expr: &syn::Expr) -> Option<(String, String)> {
    let syn::Expr::MethodCall(map) = peel_expr(expr) else {
        return None;
    };
    if map.method != "map" || map.args.len() != 1 {
        return None;
    }
    let syn::Expr::MethodCall(iter) = peel_expr(&map.receiver) else {
        return None;
    };
    if iter.method != "into_iter" || !iter.args.is_empty() {
        return None;
    }
    let claims = simple_expr_ident(&iter.receiver)?;
    let syn::Expr::Closure(closure) = peel_expr(map.args.first()?) else {
        return None;
    };
    if closure.inputs.len() != 1 {
        return None;
    }
    let input = closure.inputs.first()?;
    let claim = pat_ident(input)?;
    let syn::Expr::Async(future) = peel_expr(&closure.body) else {
        return None;
    };
    let relay_stores = block_tail_expr(&future.block)
        .into_iter()
        .flat_map(|tail| relay_tail_stores(tail, &claim))
        .collect::<BTreeSet<_>>();
    if relay_stores.len() != 1 {
        return None;
    }
    Some((claims, relay_stores.into_iter().next()?))
}

fn relay_domain_calls_batch_with_claim(
    function: &syn::ItemFn,
    contract: &RelayBatchContract,
) -> bool {
    let parameters = function_parameters(&function.sig)
        .into_iter()
        .map(|(_, name, _)| name)
        .collect::<BTreeSet<_>>();
    let mut derived = BTreeSet::new();
    let mut claim_store = None;
    for statement in &function.block.stmts {
        let Some(expr) = statement_expr(statement) else {
            continue;
        };
        if awaited_call(expr, "relay_batch").is_some_and(|call| {
            let arguments = call.args.iter().cloned().collect::<Vec<_>>();
            call_argument_ident(&arguments, contract.claim_index)
                .is_some_and(|claim| derived.contains(&claim))
                && call_argument_ident(&arguments, contract.store_index) == claim_store
        }) {
            return true;
        }
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let Some(binding) = pat_ident(&local.pat) else {
            continue;
        };
        if let Some(store) = claim_batch_receiver(expr) {
            if parameters.contains(&store) {
                derived.insert(binding);
                claim_store = Some(store);
            }
        } else if expr_derives_from(expr, &derived) {
            derived.insert(binding);
        }
    }
    false
}

fn statement_expr(statement: &syn::Stmt) -> Option<&syn::Expr> {
    match statement {
        syn::Stmt::Local(local) => local.init.as_ref().map(|init| init.expr.as_ref()),
        syn::Stmt::Expr(expr, _) => Some(expr),
        syn::Stmt::Item(_) | syn::Stmt::Macro(_) => None,
    }
}

fn call_argument_ident(arguments: &[syn::Expr], index: usize) -> Option<String> {
    arguments.get(index).and_then(simple_expr_ident)
}

fn simple_expr_ident(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    (path.path.segments.len() == 1).then(|| path.path.segments[0].ident.to_string())
}

fn claim_batch_receiver(expr: &syn::Expr) -> Option<String> {
    awaited_method(expr, "claim_batch").and_then(|call| simple_expr_ident(&call.receiver))
}

fn expr_derives_from(expr: &syn::Expr, names: &BTreeSet<String>) -> bool {
    match peel_expr(expr) {
        syn::Expr::Path(_) => simple_expr_ident(expr).is_some_and(|name| names.contains(&name)),
        syn::Expr::Match(expr) => expr_derives_from(&expr.expr, names),
        _ => false,
    }
}

fn peel_non_await(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        expr = match expr {
            syn::Expr::Paren(paren) => &paren.expr,
            syn::Expr::Group(group) => &group.expr,
            syn::Expr::Reference(reference) => &reference.expr,
            syn::Expr::Try(try_expr) => &try_expr.expr,
            _ => return expr,
        };
    }
}

fn awaited_call<'a>(expr: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprCall> {
    let syn::Expr::Await(awaited) = peel_non_await(expr) else {
        return None;
    };
    let syn::Expr::Call(call) = peel_expr(&awaited.base) else {
        return None;
    };
    (call_ident(&call.func).as_deref() == Some(name)).then_some(call)
}

fn awaited_method<'a>(expr: &'a syn::Expr, name: &str) -> Option<&'a syn::ExprMethodCall> {
    let syn::Expr::Await(awaited) = peel_non_await(expr) else {
        return None;
    };
    let syn::Expr::MethodCall(call) = peel_expr(&awaited.base) else {
        return None;
    };
    (call.method == name).then_some(call)
}

fn block_tail_expr(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.last()? {
        syn::Stmt::Expr(expr, None) => Some(expr),
        _ => None,
    }
}

fn relay_tail_stores(expr: &syn::Expr, claim: &str) -> Vec<String> {
    match peel_non_await(expr) {
        syn::Expr::Await(_) => awaited_method(expr, "relay")
            .filter(|call| {
                call.args.len() == 1
                    && call.args.first().and_then(simple_expr_ident).as_deref() == Some(claim)
            })
            .and_then(|call| simple_expr_ident(&call.receiver))
            .into_iter()
            .collect(),
        syn::Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .flat_map(|element| relay_tail_stores(element, claim))
            .collect(),
        _ => Vec::new(),
    }
}

fn runtime_relay_worker_is_connected(file: &syn::File) -> bool {
    let Some(function) = unique_top_level_fn(file, "wire_domain_relay") else {
        return false;
    };
    let parameters = function_parameters(&function.sig);
    let outboxes = parameters
        .iter()
        .filter(|(_, _, ty)| normalized_tokens(*ty) == "postgres::PgOutbox")
        .collect::<Vec<_>>();
    let modules = parameters
        .iter()
        .filter(|(_, _, ty)| normalized_tokens(*ty) == "&mutDomainModuleResult")
        .collect::<Vec<_>>();
    let ([outbox], [module]) = (outboxes.as_slice(), modules.as_slice()) else {
        return false;
    };
    let workers = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| worker_binding(statement, outbox.1.as_str()))
        .collect::<BTreeSet<_>>();
    if workers.len() != 1 {
        return false;
    }
    function.block.stmts.iter().any(|statement| {
        let Some(expr) = statement_expr(statement) else {
            return false;
        };
        let syn::Expr::MethodCall(push) = peel_expr(expr) else {
            return false;
        };
        push.method == "push"
            && push.args.len() == 1
            && push
                .args
                .first()
                .and_then(simple_expr_ident)
                .is_some_and(|worker| workers.contains(&worker))
            && module_workers_receiver(&push.receiver).as_deref() == Some(module.1.as_str())
    })
}

fn worker_binding(statement: &syn::Stmt, outbox: &str) -> Option<String> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Type(typed) = &local.pat else {
        return None;
    };
    if normalized_tokens(&typed.ty) != "WorkerSpec" {
        return None;
    }
    let worker = pat_ident(&typed.pat)?;
    let init = local.init.as_ref()?.expr.as_ref();
    let syn::Expr::Call(box_new) = peel_expr(init) else {
        return None;
    };
    if !call_ends_with(&box_new.func, "Box", "new") || box_new.args.len() != 1 {
        return None;
    }
    let syn::Expr::Closure(closure) = peel_expr(box_new.args.first()?) else {
        return None;
    };
    let tail = closure_tail_expr(&closure.body)?;
    let syn::Expr::Call(resource) = peel_expr(tail) else {
        return None;
    };
    if !call_ends_with(&resource.func, "DynManagedResource", "new_box") || resource.args.len() != 1
    {
        return None;
    }
    let syn::Expr::Call(spawn) = peel_expr(resource.args.first()?) else {
        return None;
    };
    (call_ident(&spawn.func).as_deref() == Some("spawn_relay")
        && spawn
            .args
            .iter()
            .any(|argument| simple_expr_ident(argument).as_deref() == Some(outbox)))
    .then_some(worker)
}

fn closure_tail_expr(body: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Block(block) = peel_expr(body) else {
        return Some(peel_expr(body));
    };
    match block.block.stmts.last()? {
        syn::Stmt::Expr(expr, None) => Some(expr),
        _ => None,
    }
}

fn module_workers_receiver(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Field(field) = peel_expr(expr) else {
        return None;
    };
    if !matches!(&field.member, syn::Member::Named(name) if name == "workers") {
        return None;
    }
    simple_expr_ident(&field.base)
}

fn scan_outbox_claim_sql(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    if LEGACY_OUTBOX_MIGRATIONS
        .iter()
        .any(|allowed| path == Path::new(allowed))
    {
        return Vec::new();
    }
    let direct = direct_sql_statements(content);
    let mut statements = direct.clone();
    statements.extend(dynamic_execute_literals(content));
    statements.sort_by_key(|statement| statement.line);
    let mut findings = statements
        .into_iter()
        .filter_map(|statement| {
            if statement.text.is_empty() {
                Some(finding(
                    Rule::OutboxClaimCutover,
                    format!("{}:{}", path.display(), statement.line),
                    "atomic claim cutover 后禁止无法静态解析的 dynamic EXECUTE".to_string(),
                ))
            } else {
                retired_sql_operation(&statement.text).map(|(operation, retired)| {
                    finding(
                        Rule::OutboxClaimCutover,
                        format!("{}:{}", path.display(), statement.line),
                        format!(
                            "atomic claim cutover 后禁止 {operation} retired function `{retired}`"
                        ),
                    )
                })
            }
        })
        .collect::<Vec<_>>();
    if path == Path::new(ATOMIC_OUTBOX_CLAIM_MIGRATION) {
        findings.extend(missing_0057_retirement_witnesses(path, &direct));
    }
    findings
}

#[derive(Clone)]
struct LocatedSqlStatement {
    text: String,
    line: usize,
}

fn direct_sql_statements(content: &str) -> Vec<LocatedSqlStatement> {
    let code = sql_code_without_comments_and_literals(content).to_ascii_uppercase();
    let mut line = 1;
    code.split_inclusive(';')
        .filter_map(|statement| {
            let statement_line = line
                + statement
                    .chars()
                    .take_while(|character| character.is_whitespace())
                    .filter(|character| *character == '\n')
                    .count();
            line += statement.bytes().filter(|byte| *byte == b'\n').count();
            (!statement.trim().is_empty()).then(|| LocatedSqlStatement {
                text: statement.to_string(),
                line: statement_line,
            })
        })
        .collect()
}

fn missing_0057_retirement_witnesses(
    path: &Path,
    statements: &[LocatedSqlStatement],
) -> Vec<Finding<Rule>> {
    const REQUIRED: &[(&str, &str)] = &[
        (
            "DROPFUNCTIONIFEXISTSRSS_OUTBOX_POLL_PENDING(TEXT,BIGINT)",
            "rss_outbox_poll_pending(text, bigint)",
        ),
        (
            "DROPFUNCTIONIFEXISTSRSS_OUTBOX_ACQUIRE_LEASE(TEXT)",
            "rss_outbox_acquire_lease(text)",
        ),
    ];
    let drops = statements
        .iter()
        .map(|statement| {
            statement
                .text
                .chars()
                .filter(|character| !character.is_whitespace() && *character != ';')
                .collect::<String>()
        })
        .collect::<BTreeSet<_>>();
    REQUIRED
        .iter()
        .filter(|(signature, _)| !drops.contains(*signature))
        .map(|(_, display)| {
            finding(
                Rule::OutboxClaimCutover,
                format!("{}:1", path.display()),
                format!("0057 必须显式 DROP retired function `{display}`"),
            )
        })
        .collect()
}

fn retired_sql_operation(statement: &str) -> Option<(&'static str, &'static str)> {
    let statement = statement.trim_start().to_ascii_uppercase();
    let operation = statement.split_whitespace().next()?;
    if operation == "DROP" {
        return None;
    }
    let retired = RETIRED_OUTBOX_FUNCTIONS
        .iter()
        .copied()
        .find(|function| statement.contains(function))?;
    match operation {
        "CREATE" => Some(("CREATE", retired)),
        "ALTER" => Some(("ALTER", retired)),
        "GRANT" => Some(("GRANT", retired)),
        _ => Some(("调用", retired)),
    }
}

fn sql_code_without_comments_and_literals(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut output = String::with_capacity(content.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            output.push(' ');
            cursor += 2;
            while cursor < bytes.len() && bytes[cursor] != b'\n' {
                cursor += 1;
            }
        } else if bytes[cursor..].starts_with(b"/*") {
            output.push(' ');
            cursor += 2;
            while cursor < bytes.len() && !bytes[cursor..].starts_with(b"*/") {
                preserve_sql_newline(&mut output, bytes[cursor]);
                cursor += 1;
            }
            cursor = (cursor + 2).min(bytes.len());
        } else if bytes[cursor] == b'\'' {
            output.push(' ');
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\'' {
                    if bytes.get(cursor + 1) == Some(&b'\'') {
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    preserve_sql_newline(&mut output, bytes[cursor]);
                    cursor += 1;
                }
            }
        } else if bytes[cursor] == b'"' {
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'"' {
                    if bytes.get(cursor + 1) == Some(&b'"') {
                        output.push('"');
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    output.push(char::from(bytes[cursor]));
                    cursor += 1;
                }
            }
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            output.push(' ');
            cursor += tag.len();
            let remaining = &bytes[cursor..];
            let skipped = remaining
                .windows(tag.len())
                .position(|window| window == tag)
                .map_or(remaining.len(), |offset| offset + tag.len());
            output.extend(
                remaining[..skipped]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .map(|_| '\n'),
            );
            cursor += skipped;
        } else {
            output.push(char::from(bytes[cursor]));
            cursor += 1;
        }
    }
    output
}

fn preserve_sql_newline(output: &mut String, byte: u8) {
    if byte == b'\n' {
        output.push('\n');
    }
}

fn dynamic_execute_literals(content: &str) -> Vec<LocatedSqlStatement> {
    let bytes = content.as_bytes();
    let mut statements = Vec::new();
    let mut cursor = 0;
    let mut statement_start = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            let Some((body_start, body_end, next)) = sql_dollar_body(bytes, cursor, tag) else {
                break;
            };
            if is_executable_sql_body_prefix(&content[statement_start..cursor]) {
                statements.extend(dynamic_execute_literals_in_body(
                    &content[body_start..body_end],
                    sql_line_at(content, body_start),
                ));
            }
            cursor = next;
        } else if bytes[cursor] == b';' {
            cursor += 1;
            statement_start = cursor;
        } else {
            cursor += 1;
        }
    }
    statements
}

fn dynamic_execute_literals_in_body(
    body: &str,
    body_start_line: usize,
) -> Vec<LocatedSqlStatement> {
    let bytes = body.as_bytes();
    let mut statements = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if sql_word_at(bytes, cursor, b"EXECUTE") {
            let start = cursor + b"EXECUTE".len();
            let end = sql_expression_end(bytes, start);
            let literals = sql_string_literals(&body[start..end]);
            let expression = body[start..end].trim_start();
            let is_sql_grammar_execute = ["ON", "FUNCTION", "PROCEDURE"].into_iter().any(|word| {
                expression.len() >= word.len()
                    && sql_word_at(expression.as_bytes(), 0, word.as_bytes())
            });
            if !is_sql_grammar_execute {
                statements.push(LocatedSqlStatement {
                    text: literals,
                    line: body_start_line
                        + body[..cursor].bytes().filter(|byte| *byte == b'\n').count(),
                });
            }
            cursor = end.saturating_add(1);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            cursor = skip_sql_dollar(bytes, cursor, tag);
        } else {
            cursor += 1;
        }
    }
    statements
}

fn sql_line_at(content: &str, offset: usize) -> usize {
    1 + content.as_bytes()[..offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
}

fn is_executable_sql_body_prefix(prefix: &str) -> bool {
    let code = sql_code_without_comments_and_literals(prefix).to_ascii_uppercase();
    let words = code
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.first() == Some(&"DO")
        || (words.contains(&"CREATE")
            && (words.contains(&"FUNCTION") || words.contains(&"PROCEDURE"))
            && words.last() == Some(&"AS"))
}

fn sql_dollar_body(bytes: &[u8], cursor: usize, tag: &[u8]) -> Option<(usize, usize, usize)> {
    let body_start = cursor + tag.len();
    let remaining = &bytes[body_start..];
    let body_len = remaining
        .windows(tag.len())
        .position(|window| window == tag)?;
    let body_end = body_start + body_len;
    Some((body_start, body_end, body_end + tag.len()))
}

fn skip_sql_line_comment(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && bytes[cursor] != b'\n' {
        cursor += 1;
    }
    cursor
}

fn skip_sql_block_comment(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && !bytes[cursor..].starts_with(b"*/") {
        cursor += 1;
    }
    (cursor + 2).min(bytes.len())
}

fn skip_sql_quote(bytes: &[u8], mut cursor: usize, quote: u8) -> usize {
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == quote {
            if bytes.get(cursor + 1) == Some(&quote) {
                cursor += 2;
            } else {
                return cursor + 1;
            }
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn sql_word_at(bytes: &[u8], cursor: usize, word: &[u8]) -> bool {
    let Some(candidate) = bytes.get(cursor..cursor + word.len()) else {
        return false;
    };
    candidate.eq_ignore_ascii_case(word)
        && cursor
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
        && bytes
            .get(cursor + word.len())
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn sql_expression_end(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() {
        if bytes[cursor..].starts_with(b"--") {
            cursor = skip_sql_line_comment(bytes, cursor + 2);
        } else if bytes[cursor..].starts_with(b"/*") {
            cursor = skip_sql_block_comment(bytes, cursor + 2);
        } else if matches!(bytes[cursor], b'\'' | b'"') {
            cursor = skip_sql_quote(bytes, cursor, bytes[cursor]);
        } else if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            cursor = skip_sql_dollar(bytes, cursor, tag);
        } else if bytes[cursor] == b';' {
            return cursor;
        } else {
            cursor += 1;
        }
    }
    cursor
}

fn sql_string_literals(expression: &str) -> String {
    let bytes = expression.as_bytes();
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if let Some(tag) = sql_dollar_tag(bytes, cursor) {
            output.push(' ');
            let body_start = cursor + tag.len();
            let remaining = &bytes[body_start..];
            let body_len = remaining
                .windows(tag.len())
                .position(|window| window == tag)
                .unwrap_or(remaining.len());
            output.push_str(&String::from_utf8_lossy(&remaining[..body_len]));
            cursor = (body_start + body_len + tag.len()).min(bytes.len());
        } else if bytes[cursor] != b'\'' {
            cursor += 1;
        } else {
            output.push(' ');
            cursor += 1;
            while cursor < bytes.len() {
                if bytes[cursor] == b'\'' {
                    if bytes.get(cursor + 1) == Some(&b'\'') {
                        output.push('\'');
                        cursor += 2;
                    } else {
                        cursor += 1;
                        break;
                    }
                } else {
                    output.push(char::from(bytes[cursor]));
                    cursor += 1;
                }
            }
        }
    }
    output
}

fn sql_dollar_tag(bytes: &[u8], start: usize) -> Option<&[u8]> {
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let end = bytes[start + 1..].iter().position(|byte| *byte == b'$')? + start + 1;
    bytes[start + 1..end]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        .then_some(&bytes[start..=end])
}

fn skip_sql_dollar(bytes: &[u8], cursor: usize, tag: &[u8]) -> usize {
    let body_start = cursor + tag.len();
    let remaining = &bytes[body_start..];
    body_start
        + remaining
            .windows(tag.len())
            .position(|window| window == tag)
            .map_or(remaining.len(), |offset| offset + tag.len())
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
                consumer_tx: ConsumerTxPlan,
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
                let handler = consumer_tx_handler_for_subscription(pg, &subscription)?;
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
            fn resolve_consumer_tx_plan(
                spec: SubscriptionSpec,
                execution: SubscriberExecution,
            ) -> anyhow::Result<ConsumerTxPlan> {
                match spec.dispatch() {
                    SubscriptionDispatchKey::SeedHappenedV1Audit =>
                        adapter_native_plan(spec, execution),
                    SubscriptionDispatchKey::FutureEventV1Audit =>
                        adapter_native_plan(spec, execution),
                }
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn scan_content_rejects_symbol_only_consumer_tx_plan_resolver() {
        let findings = scan_runtime_content(
            Path::new(TARGET),
            r#"
            pub struct BridgedSubscription {
                event: EventSpec,
                subscription: SubscriptionSpec,
                group: ConsumerGroup,
                consumer_tx: ConsumerTxPlan,
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
                    pg.infra().dead_letter(security.dlx_payload_protector.clone()),
                );
                let handler = consumer_tx_handler_for_subscription(pg, &subscription)?;
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
            fn resolve_consumer_tx_plan() {
                if false {
                    SubscriberExecution::AdapterNative;
                    SubscriberExecution::DomainEffect;
                    ConsumerTxPlan::AuditSessionCreated;
                    ConsumerTxPlan::AuditRoleAssigned;
                    ConsumerTxPlan::AuditRoleRevoked;
                    ConsumerTxPlan::AuditPolicyUpdated;
                    ConsumerTxPlan::SettingsConfigVersionChanged;
                }
            }
            "#,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::MissingBundleFragment && finding.detail.contains("单一 resolver")
        }));
    }

    #[allow(clippy::expect_used)]
    fn workspace_consumer_tx_plan_resolver() -> syn::ItemFn {
        syn::parse_file(include_str!(
            "../../assemblies/runtime/src/event_transport.rs"
        ))
        .expect("runtime event transport parses")
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "resolve_consumer_tx_plan" => Some(item),
            _ => None,
        })
        .expect("runtime resolver exists")
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn consumer_tx_plan_resolver_rejects_fail_open_wildcard() {
        let mut resolver = workspace_consumer_tx_plan_resolver();
        let Some(syn::Stmt::Expr(syn::Expr::Match(mapping), None)) =
            resolver.block.stmts.last_mut()
        else {
            panic!("resolver must end in match");
        };
        mapping.arms.last_mut().expect("dispatch arm").pat = syn::parse_quote!(_);
        assert!(!consumer_tx_plan_resolver_is_closed(&resolver));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::panic)]
    fn consumer_tx_plan_resolver_accepts_new_typed_dispatch_without_shadow_registry() {
        let mut resolver = workspace_consumer_tx_plan_resolver();
        let Some(syn::Stmt::Expr(syn::Expr::Match(mapping), None)) =
            resolver.block.stmts.last_mut()
        else {
            panic!("resolver must end in match");
        };
        let mut arm = mapping.arms.last().expect("dispatch arm").clone();
        arm.pat = syn::parse_quote!(SubscriptionDispatchKey::FutureEventV1Audit);
        mapping.arms.push(arm);
        assert!(consumer_tx_plan_resolver_is_closed(&resolver));
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

    #[derive(Clone, Copy)]
    struct ClaimCutoverFixture {
        path: &'static str,
        content: &'static str,
    }

    impl ClaimCutoverFixture {
        const fn new(path: &'static str, content: &'static str) -> Self {
            Self { path, content }
        }
    }

    fn scan_claim_cutover_fixtures(fixtures: &[ClaimCutoverFixture]) -> Vec<Finding<Rule>> {
        let sources = fixtures
            .iter()
            .map(|fixture| (PathBuf::from(fixture.path), fixture.content.to_string()))
            .collect::<Vec<_>>();
        scan_outbox_claim_cutover_sources(&sources)
    }

    fn relay_provider_fixture(imports: &str, relay: &str, provider: &str) -> String {
        format!(
            r#"
            {imports}
            use consistency::{{Disposition, EngineError, OutboxMetricSubject}};
            use vocab::DomainName;
            struct {provider};
            impl {relay} for {provider} {{
                type Claim = ();
                fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject {{ todo!() }}
                fn claim_domain(&self) -> &DomainName {{ todo!() }}
                async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {{
                    todo!()
                }}
                async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {{
                    todo!()
                }}
            }}
            "#,
        )
    }

    #[test]
    fn outbox_claim_cutover_synthetic_red_rejects_legacy_production_paths() {
        let cases = [
            (
                "rogue production relay provider",
                ClaimCutoverFixture::new(
                    "crates/identity/src/rogue_outbox.rs",
                    r#"
                    use consistency::{Disposition, EngineError, OutboxMetricSubject, OutboxRelay};
                    use vocab::DomainName;
                    struct RogueOutbox;
                    impl OutboxRelay for RogueOutbox {
                        type Claim = ();
                        fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject { todo!() }
                        fn claim_domain(&self) -> &DomainName { todo!() }
                        async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {
                            todo!()
                        }
                        async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {
                            todo!()
                        }
                    }
                    "#,
                ),
            ),
            (
                "aliased rogue relay provider in composition",
                ClaimCutoverFixture::new(
                    "composition/identity/src/lib.rs",
                    r#"
                    use consistency::{Disposition, EngineError, OutboxMetricSubject};
                    use consistency::OutboxRelay as ClaimedRelay;
                    use vocab::DomainName;
                    struct RogueOutbox;
                    impl ClaimedRelay for RogueOutbox {
                        type Claim = ();
                        fn claim_subject(_: &Self::Claim) -> &OutboxMetricSubject { todo!() }
                        fn claim_domain(&self) -> &DomainName { todo!() }
                        async fn claim_batch(&self, _: usize) -> Result<Vec<Self::Claim>, EngineError> {
                            todo!()
                        }
                        async fn relay(&self, _: Self::Claim) -> Result<Disposition, EngineError> {
                            todo!()
                        }
                    }
                    "#,
                ),
            ),
            (
                "legacy source trait",
                ClaimCutoverFixture::new(
                    "crates/consistency/src/outbox.rs",
                    r#"
                    pub trait OutboxSource {
                        type Claim;
                        async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError>;
                    }
                    "#,
                ),
            ),
            (
                "eventexec split poll acquire seam",
                ClaimCutoverFixture::new(
                    "crates/eventexec/src/relay.rs",
                    r#"
                    async fn relay_tick<A: OutboxSource + OutboxRelay>(outbox: &A) {
                        let pending = outbox.poll_pending(100).await?;
                        for entry in pending {
                            if outbox.acquire_lease(entry.event_id()).await? {
                                outbox.relay(entry).await?;
                            }
                        }
                    }
                    "#,
                ),
            ),
            (
                "runtime relay wiring bypass",
                ClaimCutoverFixture::new(
                    "assemblies/runtime/src/event_transport.rs",
                    r#"
                    fn wire_domain_relay(
                        outbox: postgres::PgOutbox,
                        module: &mut DomainModuleResult,
                    ) {
                        module.workers.push(Box::new(move |token| {
                            DynManagedResource::new_box(relay_loop(Arc::new(outbox), token))
                        }));
                    }
                    "#,
                ),
            ),
        ];

        for (name, fixture) in cases {
            let findings = scan_claim_cutover_fixtures(&[fixture]);
            assert!(
                !findings.is_empty(),
                "synthetic red `{name}` was not detected"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_resolves_canonical_trait_identity() {
        let crate_alias = relay_provider_fixture(
            "use consistency as c; use c::OutboxRelay as Relay;",
            "Relay",
            "AliasedRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/aliased.rs"),
            crate_alias,
        )]);
        assert!(!findings.is_empty(), "crate alias hid rogue provider");

        let reexported =
            relay_provider_fixture("use crate::RelayPort;", "RelayPort", "ReexportedRogue");
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "pub use consistency::OutboxRelay as RelayPort; mod rogue;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), reexported),
        ]);
        assert!(!findings.is_empty(), "crate re-export hid rogue provider");
    }

    #[test]
    fn outbox_claim_cutover_resolves_native_private_and_cargo_alias_paths() {
        let native =
            relay_provider_fixture("", "consistency::outbox::OutboxRelay", "NativePathRogue");
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/native.rs"),
            native,
        )]);
        assert!(
            !findings.is_empty(),
            "native module path hid rogue provider"
        );

        let private = relay_provider_fixture(
            "use super::OutboxRelay;",
            "OutboxRelay",
            "PrivateImportRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "use consistency::OutboxRelay; mod rogue;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), private),
        ]);
        assert!(
            !findings.is_empty(),
            "private parent import hid rogue provider"
        );

        let cargo_alias = relay_provider_fixture(
            "use relay_engine::OutboxRelay;",
            "OutboxRelay",
            "CargoAliasRogue",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/Cargo.toml"),
                r#"[dependencies]
                relay_engine = { package = "consistency", path = "../consistency" }
                "#
                .to_string(),
            ),
            (PathBuf::from("crates/identity/src/rogue.rs"), cargo_alias),
        ]);
        assert!(
            !findings.is_empty(),
            "Cargo dependency alias hid rogue provider"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_macro_generated_relay_impl() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            macro_rules! impl_relay {
                ($provider:ty) => { impl OutboxRelay for $provider {} };
            }
            struct MacroRogue;
            impl_relay!(MacroRogue);
            "#
            .to_string(),
        )]);
        assert!(
            !findings.is_empty(),
            "macro-generated rogue provider passed"
        );
    }

    #[test]
    fn outbox_claim_cutover_allows_unused_relay_impl_macro_definition() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            macro_rules! impl_relay {
                ($provider:ty) => { impl OutboxRelay for $provider {} };
            }
            struct Unused;
            "#
            .to_string(),
        )]);
        assert!(
            findings.is_empty(),
            "unused macro definition was rejected: {findings:#?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_external_impl_macro_invocation() {
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/rogue.rs"),
            r#"
            use consistency::OutboxRelay;
            struct ExternalRogue;
            external_macros::impl_outbox_relay!(ExternalRogue);
            "#
            .to_string(),
        )]);
        assert!(
            !findings.is_empty(),
            "external impl macro invocation passed"
        );
    }

    #[test]
    fn outbox_claim_cutover_resolves_module_qualified_export_graph() {
        let cases = [
            (
                "nested re-export imported across files",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::ports::RelayPort;",
                    "RelayPort",
                    "ImportedRogue",
                ),
            ),
            (
                "fixed-point nested re-export",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                pub mod api {
                    pub use crate::ports::RelayPort as PublicRelay;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::PublicRelay;",
                    "PublicRelay",
                    "FixedPointRogue",
                ),
            ),
            (
                "self-relative nested re-export",
                r#"
                pub mod api {
                    pub mod ports {
                        pub use consistency::OutboxRelay as RelayPort;
                    }
                    pub use self::ports::RelayPort as SelfRelay;
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::SelfRelay;",
                    "SelfRelay",
                    "SelfRelativeRogue",
                ),
            ),
            (
                "multi-super nested re-export",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                pub mod api {
                    pub mod nested {
                        pub use super::super::ports::RelayPort as DeepRelay;
                    }
                }
                mod rogue;
                "#,
                relay_provider_fixture(
                    "use crate::api::nested::DeepRelay;",
                    "DeepRelay",
                    "SuperRelativeRogue",
                ),
            ),
            (
                "qualified impl path",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture("", "crate::ports::RelayPort", "QualifiedRogue"),
            ),
            (
                "glob from canonical export module",
                r#"
                pub mod ports {
                    pub use consistency::OutboxRelay as RelayPort;
                }
                mod rogue;
                "#,
                relay_provider_fixture("use crate::ports::*;", "RelayPort", "GlobRogue"),
            ),
        ];

        for (name, lib, rogue) in cases {
            let findings = scan_outbox_claim_cutover_sources(&[
                (PathBuf::from("crates/identity/src/lib.rs"), lib.to_string()),
                (PathBuf::from("crates/identity/src/rogue.rs"), rogue),
            ]);
            assert!(!findings.is_empty(), "module export red `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_does_not_confuse_unrelated_same_named_traits() {
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/local.rs"),
                r#"
                trait OutboxRelay {}
                struct LocalRelay;
                impl OutboxRelay for LocalRelay {}
                "#
                .to_string(),
            ),
            (
                PathBuf::from("crates/identity/src/other.rs"),
                r#"
                mod other { pub trait OutboxRelay {} }
                use other::OutboxRelay as OtherRelay;
                struct OtherProvider;
                impl OtherRelay for OtherProvider {}

                mod nested {
                    pub mod ports { pub trait RelayPort {} }
                }
                use nested::ports::RelayPort;
                struct NestedOtherProvider;
                impl RelayPort for NestedOtherProvider {}
                "#
                .to_string(),
            ),
        ]);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn outbox_claim_cutover_scans_modules_named_tests_without_cfg() {
        let content = format!(
            "mod tests {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "ProductionRogue",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            content,
        )]);
        assert!(!findings.is_empty(), "uncfg'd `mod tests` was skipped");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn outbox_claim_source_set_includes_test_named_production_files() {
        static NEXT_TEMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = NEXT_TEMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("rss-outbox-guard-{}-{nonce}", std::process::id()));
        let src = root.join("crates/demo/src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\"]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(src.join("lib.rs"), "pub mod worker_tests;\n").unwrap();
        std::fs::write(src.join("worker_tests.rs"), "pub fn production() {}\n").unwrap();

        let files = workspace_member_source_files(&root).unwrap();
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            files.iter().any(|path| path.ends_with("worker_tests.rs")),
            "production file was excluded by its name: {files:?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_excludes_only_parent_cfg_test_external_modules() {
        let test_provider = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "TestOnlyRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(test)] mod test_support;".to_string(),
            ),
            (
                PathBuf::from("crates/identity/src/test_support.rs"),
                test_provider,
            ),
        ]);
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn outbox_claim_cutover_scans_external_module_with_any_production_reachability() {
        let provider = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ProductionReachableRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                r#"
                #[cfg(test)]
                mod relay;
                #[cfg(not(test))]
                mod relay;
                "#
                .to_string(),
            ),
            (PathBuf::from("crates/identity/src/relay.rs"), provider),
        ]);
        assert!(
            !findings.is_empty(),
            "production-reachable external module was excluded"
        );
    }

    #[test]
    fn outbox_claim_cutover_cfg_test_implication_is_structural() {
        let all_test = format!(
            "#[cfg(all(test, feature = \"fixture\"))] mod support {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "AllTestRelay",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            all_test,
        )]);
        assert!(findings.is_empty(), "cfg(all(test, ..)) must be test-only");

        let any_test = format!(
            "#[cfg(any(test, feature = \"production\"))] mod support {{ {} }}",
            relay_provider_fixture(
                "use consistency::OutboxRelay;",
                "OutboxRelay",
                "AnyTestRelay",
            )
        );
        let findings = scan_outbox_claim_cutover_sources(&[(
            PathBuf::from("crates/identity/src/lib.rs"),
            any_test,
        )]);
        assert!(
            !findings.is_empty(),
            "cfg(any(test, production)) remains production-reachable"
        );

        let external = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ExternalAllTestRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(all(test, feature = \"fixture\"))] mod support;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/support.rs"), external),
        ]);
        assert!(
            findings.is_empty(),
            "external cfg(all(test, ..)) must be test-only: {findings:#?}"
        );

        let external = relay_provider_fixture(
            "use consistency::OutboxRelay;",
            "OutboxRelay",
            "ExternalAnyTestRelay",
        );
        let findings = scan_outbox_claim_cutover_sources(&[
            (
                PathBuf::from("crates/identity/src/lib.rs"),
                "#[cfg(any(test, feature = \"production\"))] mod support;".to_string(),
            ),
            (PathBuf::from("crates/identity/src/support.rs"), external),
        ]);
        assert!(
            !findings.is_empty(),
            "external cfg(any(test, production)) remains production-reachable"
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_disconnected_eventexec_bait() {
        let cases = [
            (
                "relay helper is never called",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claims) = store.claim_batch(batch).await else { return };
                    fn nested_bait<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                        drop(relay_batch(store, claims));
                    }
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "claim result is replaced before relay_batch",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    let unrelated = Vec::new();
                    relay_batch(store, unrelated).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay consumes a different value",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(other).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch call only exists in a dead closure",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    let _dead = || relay_batch(store, claimed);
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch future is dropped",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    drop(relay_batch(store, claimed));
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay_batch exists only in a dead branch",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    if false { relay_batch(store, claimed).await; }
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "relay future is dropped inside the map",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        drop(store.relay(claim));
                    })).await;
                }
                "#,
            ),
            (
                "awaited relay is not the closure tail value",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        let _discarded = store.relay(claim).await;
                    })).await;
                }
                "#,
            ),
            (
                "join_all future is dropped",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    drop(futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })));
                }
                "#,
            ),
            (
                "claim_batch is not awaited",
                r#"
                trait SyncRelay {
                    type Claim;
                    fn claim_batch(&self, limit: usize) -> Vec<Self::Claim>;
                    async fn relay(&self, claim: Self::Claim);
                }
                async fn relay_domain_once<A: SyncRelay>(store: &Arc<A>, batch: usize) {
                    let claimed = store.claim_batch(batch);
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: SyncRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "join_all input is not a map pipeline",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims).await;
                }
                "#,
            ),
            (
                "map has more than one callback argument",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(
                        |claim| async move { store.relay(claim).await },
                        other,
                    )).await;
                }
                "#,
            ),
            (
                "map receiver does not consume the claim vector",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "into_iter call has an argument",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter(other).map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "map closure has multiple inputs",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim, extra| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            (
                "map closure body is not an async future",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let Ok(claimed) = store.claim_batch(batch).await else { return };
                    relay_batch(store, claimed).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(
                        claims.into_iter().map(|claim| store.relay(claim)),
                    ).await;
                }
                "#,
            ),
        ];

        for (name, content) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                EVENTEXEC_RELAY_PATH,
                content,
            )]);
            assert!(!findings.is_empty(), "disconnected bait `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_disconnected_runtime_bait() {
        let cases = [
            (
                "wrong outbox parameter type",
                r#"
                fn wire_domain_relay(outbox: RogueOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
            (
                "spawn call is nested dead bait",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        let _dead = || spawn_relay(name, outbox, token);
                        DynManagedResource::new_box(other_worker(token))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
            (
                "worker is never registered or returned",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    let _discarded = worker;
                }
                "#,
            ),
            (
                "worker registration is conditional",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(name, outbox, token))
                    });
                    if false { module.workers.push(worker); }
                }
                "#,
            ),
            (
                "spawn relay is wrapped by another tail call",
                r#"
                fn wire_domain_relay(outbox: postgres::PgOutbox, module: &mut DomainModuleResult) {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(other(spawn_relay(name, outbox, token)))
                    });
                    module.workers.push(worker);
                }
                "#,
            ),
        ];

        for (name, content) in cases {
            let findings =
                scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(TARGET, content)]);
            assert!(!findings.is_empty(), "runtime bait `{name}` passed");
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn outbox_claim_source_set_includes_composition_members() {
        let root = workspace_root().unwrap();
        let sources = load_outbox_claim_cutover_sources(&root).unwrap();
        let paths = sources
            .iter()
            .map(|(path, _)| path.as_path())
            .collect::<BTreeSet<_>>();
        for path in [
            "composition/settings/src/lib.rs",
            "composition/identity/src/lib.rs",
            "composition/audit/src/lib.rs",
        ] {
            assert!(
                paths.contains(Path::new(path)),
                "missing shipped source {path}"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_synthetic_red_rejects_retired_sql_after_0057() {
        let cases = [
            (
                "CREATE poll_pending",
                "CREATE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint) RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;",
            ),
            (
                "ALTER poll_pending",
                "ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_outbox_maintenance;",
            ),
            (
                "GRANT poll_pending",
                "GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app;",
            ),
            (
                "CREATE acquire_lease",
                "CREATE FUNCTION rss_outbox_acquire_lease(p_event_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;",
            ),
            (
                "ALTER acquire_lease",
                "ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_outbox_maintenance;",
            ),
            (
                "GRANT acquire_lease",
                "GRANT EXECUTE ON FUNCTION rss_outbox_acquire_lease(text) TO rss_app;",
            ),
        ];

        for (name, sql) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_rogue_legacy_outbox_function.sql",
                sql,
            )]);
            assert!(
                !findings.is_empty(),
                "synthetic red `{name}` was not detected"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_whitespace_delimited_retired_ddl() {
        for separator in ["\n", "\t", "\r\n"] {
            let sql = format!(
                "CREATE{separator}FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1';"
            );
            let sources = vec![(
                PathBuf::from("adapters/postgres/migrations/0062_whitespace_legacy.sql"),
                sql,
            )];
            let findings = scan_outbox_claim_cutover_sources(&sources);
            assert!(
                !findings.is_empty(),
                "whitespace-delimited retired DDL passed for {separator:?}"
            );
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_sqlx_retired_function_calls() {
        let cases = [
            r#"fn load() { sqlx::query("SELECT * FROM rss_outbox_poll_pending($1, $2)"); }"#,
            r#"fn load() { sqlx::query_as!(Row, "SELECT rss_outbox_acquire_lease($1)"); }"#,
            r#"use sqlx::query as q; fn load() { q("SELECT * FROM rss_outbox_poll_pending($1, $2)"); }"#,
            r#"use sqlx::query_as as qa; fn load() { qa!(Row, "SELECT rss_outbox_acquire_lease($1)"); }"#,
        ];
        for content in cases {
            let findings = scan_outbox_claim_cutover_sources(&[(
                PathBuf::from("adapters/postgres/src/rogue.rs"),
                content.to_string(),
            )]);
            assert!(!findings.is_empty(), "sqlx retired call passed: {content}");
        }
    }

    #[test]
    fn outbox_claim_cutover_rejects_non_literal_dynamic_execute() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_dynamic_variable.sql",
            r#"
            DO $do$
            DECLARE ddl text := 'CREATE FUNCTION rss_outbox_poll_pending(text, bigint)';
            BEGIN
                EXECUTE ddl;
            END
            $do$;
            "#,
        )]);
        assert!(!findings.is_empty(), "non-literal dynamic EXECUTE passed");
    }

    #[test]
    fn outbox_claim_cutover_allows_unrelated_legacy_identifiers() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "crates/identity/src/local_queue.rs",
            r#"
            struct PendingEntry;
            trait OutboxSource {}
            fn poll_pending() {}
            fn load(source: Queue) { source.poll_pending(); }
            "#,
        )]);
        assert!(
            findings.is_empty(),
            "unrelated names were rejected: {findings:#?}"
        );
    }

    #[test]
    fn outbox_claim_cutover_requires_both_0057_retirement_witnesses() {
        let cases = [
            (
                "missing poll_pending DROP",
                "DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);",
                "rss_outbox_poll_pending",
            ),
            (
                "missing acquire_lease DROP",
                "DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);",
                "rss_outbox_acquire_lease",
            ),
            (
                "ALTER does not witness retirement",
                "ALTER FUNCTION rss_outbox_poll_pending(text, bigint) OWNER TO rss_app;\nDROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);",
                "rss_outbox_poll_pending",
            ),
        ];
        for (name, sql, missing) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
                sql,
            )]);
            assert!(
                findings.iter().any(|finding| {
                    finding.detail.contains("0057 必须显式 DROP")
                        && finding.detail.contains(missing)
                }),
                "0057 witness red `{name}` passed: {findings:#?}"
            );
        }

        let quoted = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
            r#"
            DROP FUNCTION IF EXISTS "rss_outbox_poll_pending" ( text , bigint );
            DROP FUNCTION IF EXISTS "rss_outbox_acquire_lease" ( text );
            "#,
        )]);
        assert!(quoted.is_empty(), "{quoted:#?}");
    }

    #[test]
    fn outbox_claim_cutover_rust_findings_preserve_each_source_line() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "crates/identity/src/rogue_outbox.rs",
            "fn first() {\n    outbox.poll_pending();\n}\nfn second() {\n    outbox.poll_pending();\n}\n",
        )]);
        let poll = findings
            .iter()
            .filter(|finding| finding.detail.contains("`poll_pending`"))
            .collect::<Vec<_>>();
        assert_eq!(poll.len(), 2, "{findings:#?}");
        assert_eq!(poll[0].subject, "crates/identity/src/rogue_outbox.rs:2");
        assert_eq!(poll[1].subject, "crates/identity/src/rogue_outbox.rs:5");
    }

    #[test]
    fn outbox_claim_cutover_sql_findings_preserve_statement_and_execute_lines() {
        let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_located_legacy.sql",
            r#"CREATE FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1';
ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app;
DO $do$
BEGIN
    EXECUTE $ddl$GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app$ddl$;
END
$do$;
"#,
        )]);
        assert_eq!(findings.len(), 3, "{findings:#?}");
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.subject.as_str())
                .collect::<Vec<_>>(),
            [
                "adapters/postgres/migrations/0062_located_legacy.sql:1",
                "adapters/postgres/migrations/0062_located_legacy.sql:2",
                "adapters/postgres/migrations/0062_located_legacy.sql:5",
            ]
        );
    }

    #[test]
    fn outbox_claim_cutover_rejects_quoted_and_dynamic_retired_sql() {
        let cases = [
            (
                "quoted CREATE",
                r#"CREATE FUNCTION "rss_outbox_poll_pending"(text, bigint) RETURNS bigint LANGUAGE sql AS $$ SELECT 1 $$;"#,
            ),
            (
                "schema-qualified quoted ALTER",
                r#"ALTER FUNCTION "public"."rss_outbox_acquire_lease"(text) OWNER TO rss_app;"#,
            ),
            (
                "schema-qualified quoted GRANT",
                r#"GRANT EXECUTE ON FUNCTION public."rss_outbox_poll_pending"(text, bigint) TO rss_app;"#,
            ),
            (
                "DO EXECUTE literal",
                r#"DO $$ BEGIN EXECUTE 'CREATE FUNCTION rss_outbox_acquire_lease(text) RETURNS boolean LANGUAGE sql AS ''SELECT true'''; END $$;"#,
            ),
            (
                "DO EXECUTE format",
                r#"DO $$ BEGIN EXECUTE format('ALTER FUNCTION public.%I(text) OWNER TO rss_app', 'rss_outbox_acquire_lease'); END $$;"#,
            ),
            (
                "DO EXECUTE untagged dollar literal",
                r#"DO $do$ BEGIN EXECUTE $$CREATE FUNCTION rss_outbox_poll_pending(text, bigint) RETURNS bigint LANGUAGE sql AS 'SELECT 1'$$; END $do$;"#,
            ),
            (
                "DO EXECUTE format with tagged dollar literals",
                r#"DO $do$ BEGIN EXECUTE format($fmt$ALTER FUNCTION public.%I(text) OWNER TO rss_app$fmt$, $name$rss_outbox_acquire_lease$name$); END $do$;"#,
            ),
        ];

        for (name, sql) in cases {
            let findings = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_dynamic_legacy_outbox.sql",
                sql,
            )]);
            assert!(!findings.is_empty(), "retired SQL `{name}` passed");
        }
    }

    #[test]
    fn outbox_claim_cutover_dynamic_sql_respects_dollar_literal_state() {
        let inert = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_inert_nested_execute.sql",
            r#"
            DO $do$
            BEGIN
                PERFORM $text$
                    EXECUTE $ddl$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$ddl$;
                $text$;
            END
            $do$;
            "#,
        )]);
        assert!(
            inert.is_empty(),
            "nested dollar literal executed: {inert:#?}"
        );

        let executable = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_real_dollar_execute.sql",
            r#"
            DO $do$
            BEGIN
                EXECUTE $ddl$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$ddl$;
            END
            $do$;
            "#,
        )]);
        assert!(
            !executable.is_empty(),
            "real dollar-quoted EXECUTE was not detected"
        );

        let function_body = scan_claim_cutover_fixtures(&[ClaimCutoverFixture::new(
            "adapters/postgres/migrations/0062_function_dollar_execute.sql",
            r#"
            CREATE FUNCTION rss_outbox_current() RETURNS void AS $body$
            BEGIN
                EXECUTE $ddl$ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app$ddl$;
            END
            $body$ LANGUAGE plpgsql;
            "#,
        )]);
        assert!(
            !function_body.is_empty(),
            "function-body dollar EXECUTE was not detected"
        );
    }

    #[test]
    fn outbox_claim_cutover_accepts_canonical_and_non_production_bait() {
        let fixtures = [
            ClaimCutoverFixture::new(
                "crates/consistency/src/outbox.rs",
                r#"
                pub trait OutboxRelay {
                    type Claim;
                    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject;
                    fn claim_domain(&self) -> &DomainName;
                    async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError>;
                    async fn relay(&self, claim: Self::Claim) -> Result<Disposition, EngineError>;
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/src/outbox.rs",
                r#"
                use consistency::OutboxRelay;
                impl OutboxRelay for PgOutbox {
                    type Claim = PgClaimedOutboxEntry;
                    fn claim_subject(claim: &Self::Claim) -> &OutboxMetricSubject { &claim.subject }
                    fn claim_domain(&self) -> &DomainName { &self.domain }
                    async fn claim_batch(&self, limit: usize) -> Result<Vec<Self::Claim>, EngineError> {
                        claim_batch(&self.pool, &self.domain, limit).await
                    }
                    async fn relay(&self, claim: Self::Claim) -> Result<Disposition, EngineError> {
                        settle_claim(&self.pool, claim).await
                    }
                }

                // Bait only: impl OutboxRelay for RogueOutbox; trait OutboxSource; poll_pending();
                const MIGRATION_NOTE: &str = "CREATE FUNCTION rss_outbox_acquire_lease(text)";
                #[cfg(test)]
                mod tests {
                    struct FakeOutbox;
                    impl OutboxRelay for FakeOutbox { type Claim = FakeClaim; }
                    trait OutboxSource {}
                    fn old_fake_seam() { poll_pending(); acquire_lease(); }
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "crates/eventexec/src/relay.rs",
                r#"
                async fn relay_domain_once<A: OutboxRelay>(store: &Arc<A>, batch: usize) {
                    let claim_result = store.claim_batch(batch).await;
                    let claims = match claim_result {
                        Ok(claims) => claims,
                        Err(error) => return error,
                    };
                    relay_batch(store, claims).await;
                }
                async fn relay_batch<A: OutboxRelay>(store: &Arc<A>, claims: Vec<A::Claim>) {
                    futures::future::join_all(claims.into_iter().map(|claim| async move {
                        store.relay(claim).await
                    })).await;
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "assemblies/runtime/src/event_transport.rs",
                r#"
                fn wire_domain_relay(
                    outbox: postgres::PgOutbox,
                    module: &mut DomainModuleResult,
                ) -> anyhow::Result<()> {
                    let worker: WorkerSpec = Box::new(move |token| {
                        DynManagedResource::new_box(spawn_relay(
                            worker_name,
                            outbox,
                            relay_cfg,
                            clock,
                            token,
                            health,
                            metrics,
                        ))
                    });
                    module.workers.push(worker);
                    Ok(())
                }
                "#,
            ),
            ClaimCutoverFixture::new(
                "crates/saga/src/store.rs",
                "impl SagaStore for PgSagaStore { async fn acquire_lease(&self, saga_id: SagaId) {} }",
            ),
            ClaimCutoverFixture::new(
                "crates/reconcile/src/store.rs",
                "impl ReconcileStore for PgReconcileStore { async fn acquire_lease(&self, action_id: ActionId) {} }",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0031_harden_outbox_tenant_scope.sql",
                "CREATE FUNCTION rss_outbox_poll_pending(p_domain text, p_limit bigint) RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0036_add_outbox_schema_columns.sql",
                "CREATE FUNCTION rss_outbox_acquire_lease(p_event_id text) RETURNS boolean LANGUAGE sql AS $$ SELECT true $$;",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0037_outbox_metric_scope_functions.sql",
                "-- Historical migration intentionally remains immutable.",
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0057_atomic_outbox_claim.sql",
                r#"
                DROP FUNCTION IF EXISTS rss_outbox_poll_pending(text, bigint);
                DROP FUNCTION IF EXISTS rss_outbox_acquire_lease(text);
                CREATE FUNCTION rss_outbox_claim_batch(p_domain text, p_limit bigint)
                RETURNS SETOF outbox LANGUAGE sql AS $$ SELECT * FROM outbox $$;
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0062_comment_bait.sql",
                r#"
                -- CREATE FUNCTION rss_outbox_poll_pending(text, bigint)
                /* ALTER FUNCTION rss_outbox_acquire_lease(text) OWNER TO rss_app; */
                SELECT 'GRANT EXECUTE ON FUNCTION rss_outbox_poll_pending(text, bigint) TO rss_app';
                CREATE FUNCTION rss_outbox_current() RETURNS void LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE NOTICE 'CREATE FUNCTION rss_outbox_acquire_lease(text)';
                    PERFORM format('GRANT EXECUTE ON FUNCTION %I', 'rss_outbox_poll_pending');
                    -- EXECUTE 'ALTER FUNCTION rss_outbox_acquire_lease(text)';
                END
                $$;
                "#,
            ),
            ClaimCutoverFixture::new(
                "adapters/postgres/migrations/0063_inert_dollar_bait.sql",
                r#"
                DO $do$
                BEGIN
                    PERFORM $sql$CREATE FUNCTION rss_outbox_poll_pending(text, bigint)$sql$;
                END
                $do$;
                "#,
            ),
        ];

        let findings = scan_claim_cutover_fixtures(&fixtures);
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
