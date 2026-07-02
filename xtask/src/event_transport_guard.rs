//! runtime event transport source guard.
//!
//! INVARIANT: EVENT-TRANSPORT-PG-INBOX-01 { level = "Medium", exec = "verify", source = "code" }——
//! `assemblies/runtime/src/event_transport.rs` 的 consumer idempotency must come from PG inbox, not Redis,
//! and production consumer workers must go through the generated-topology bridge.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
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
];
const RUNTIME_REDIS_INBOX_FRAGMENT: &str = "redis.infra().inbox(";
const RUNTIME_REQUIRED: &[&str] = &[
    "pub struct BridgedSubscription",
    "pub fn bridge_generated_subscriptions(",
    "bridge_subscriptions_with_specs(bindings, generated::event::SUBSCRIPTIONS)",
    "subscribers: Vec<BridgedSubscription>",
    "fn wire_consumer_resource_bundle(",
    "let inbox = pg.infra().inbox();",
    "let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());",
    "let dlx = DynDeadLetterStore::new_box(",
    ".dead_letter(security.dlx_payload_protector.clone()),",
    "spawn_consumer_ackable_subscriber(",
    "wire_inbox_sweeper(pg, timing, module)?;",
];
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RedisConsumerClaimer,
    MissingBundleFragment,
    DomainConsumerBundleBypass,
    ProductionConsumerBundleBypass,
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
        Ok((
            format!(
                "{TARGET} 经 generated topology bridge + PG inbox consumer bundle 接线，生产 src 无散装 consumer bundle"
            ),
            findings,
        ))
    }
}

fn scan_runtime_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for forbidden in RUNTIME_FORBIDDEN {
        if content.contains(forbidden) {
            findings.push(finding(
                Rule::RedisConsumerClaimer,
                path.display().to_string(),
                format!("禁止 runtime event consumer 重新接入 Redis claimer: `{forbidden}`"),
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
    for required in RUNTIME_REQUIRED {
        if !content.contains(required) {
            findings.push(finding(
                Rule::MissingBundleFragment,
                path.display().to_string(),
                format!("runtime consumer bundle 缺少必备接线片段: `{required}`"),
            ));
        }
    }
    findings
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
        if BYPASS_ALLOWED_PATHS
            .iter()
            .any(|allowed| rel == Path::new(allowed))
        {
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

fn text_bypass_fragments(content: &str) -> BTreeSet<&'static str> {
    BYPASS_FORBIDDEN
        .iter()
        .copied()
        .filter(|forbidden| content.contains(forbidden))
        .collect()
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
            pub struct BridgedSubscription;
            pub fn bridge_generated_subscriptions() {
                bridge_subscriptions_with_specs(bindings, generated::event::SUBSCRIPTIONS)
            }
            fn accepts(subscribers: Vec<BridgedSubscription>) {}
            fn wire_consumer_resource_bundle() {
                let group = subscription.group().clone();
                let inbox = pg.infra().inbox();
                let lease_cfg = LeaseConfig::from_ttl(inbox.lease_ttl());
                let dlx = DynDeadLetterStore::new_box(
                    pg.infra()
                        .dead_letter(security.dlx_payload_protector.clone()),
                );
                spawn_consumer_ackable_subscriber();
                wire_inbox_sweeper(pg, timing, module)?;
            }
            "#,
        );
        assert!(findings.is_empty());
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
    fn scan_bypass_content_rejects_import_alias_and_split_infra_receiver() {
        let findings = scan_bypass_content(
            Path::new("assemblies/runtime/src/other.rs"),
            r#"
            use eventexec::{spawn_consumer_ackable_subscriber as spawn_it};

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
}
