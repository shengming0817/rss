//! Runtime assembly baseline drift gate.
//!
//! The baseline locks static repository facts that later `runtime::run()` split PRs must preserve:
//! runtime Cargo dependencies, assembly DI providers, the shared dependency/result structs, and
//! ordered runtime wiring anchors. It intentionally keeps field-inventory drift separate from
//! `SharedRuntimeDeps` infra-only semantics, which are enforced by `runtime-deps-guard`.
//!
//! INVARIANT: RUNTIME-BASELINE-DRIFT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_baseline_drift_fails", anti_vacuity = "tests::runtime_baseline_accepts_fixture" } -- `cargo xtask runtime-baseline verify`
//! compares the generated runtime assembly baseline with the committed `runtime-baseline/runtime.txt`
//! and fails on missing baseline, content drift, empty dependency/provider inventories, or missing
//! required wiring anchors. Synthetic red/green tests cover every failure class.

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;
use anyhow::{Context, Result};
use assembly_schema::AssemblyManifest;
use std::collections::{BTreeMap, btree_map::Entry};
use std::fs;
use std::path::Path;

const BASELINE_PATH: &str = "runtime-baseline/runtime.txt";
const RUNTIME_CARGO_PATH: &str = "assemblies/runtime/Cargo.toml";
const ASSEMBLY_MANIFEST_PATH: &str = "assemblies/runtime/assembly.toml";
const SHARED_RUNTIME_DEPS_PATH: &str = "assemblies/runtime/src/module.rs";
const BOOTSTRAP_MODULE_PATH: &str = "crates/bootstrap/src/module.rs";
const RUNTIME_LIB_PATH: &str = "assemblies/runtime/src/lib.rs";
const RUNTIME_LAUNCH_PATH: &str = "assemblies/runtime/src/launch.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingBaseline,
    Drift,
    EmptyDependencies,
    EmptyDiportProviders,
    MissingAnchor,
}

pub(crate) struct RuntimeBaseline;

impl GovernanceCheck for RuntimeBaseline {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "runtime-baseline"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        check_root(&workspace_root()?)
    }
}

pub(crate) fn list() -> Result<()> {
    let root = workspace_root()?;
    let report = collect_report(&root)?;
    print!("{}", report.rendered);
    if !report.rendered.ends_with('\n') {
        println!();
    }
    if !report.findings.is_empty() {
        eprintln!(
            "runtime-baseline: {} 项诊断（list 仅展示，verify 会失败）",
            report.findings.len()
        );
        crate::diagnostic::print_findings(&report.findings);
    }
    Ok(())
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
    let report = collect_report(root)?;
    let mut findings = report.findings;
    let baseline = root.join(BASELINE_PATH);
    if !baseline.exists() {
        findings.push(finding(
            Rule::MissingBaseline,
            BASELINE_PATH,
            "缺 committed baseline；运行 `cargo xtask runtime-baseline list > runtime-baseline/runtime.txt`",
        ));
    } else {
        let expected = fs::read_to_string(&baseline)
            .with_context(|| format!("读 {} 失败", baseline.display()))?;
        if normalize_newlines(&expected) != normalize_newlines(&report.rendered) {
            findings.push(finding(
                Rule::Drift,
                BASELINE_PATH,
                "runtime assembly baseline 漂移；运行 `cargo xtask runtime-baseline list > runtime-baseline/runtime.txt` 后复核差异",
            ));
        }
    }
    Ok((
        format!(
            "{} deps, {} providers, {} shared fields, {} result fields, {} anchors",
            report.dependencies,
            report.providers,
            report.shared_fields,
            report.domain_fields,
            report.anchors
        ),
        findings,
    ))
}

fn normalize_newlines(text: &str) -> String {
    let mut normalized = text.replace("\r\n", "\n");
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Report {
    rendered: String,
    findings: Vec<Finding<Rule>>,
    dependencies: usize,
    providers: usize,
    shared_fields: usize,
    domain_fields: usize,
    anchors: usize,
}

fn collect_report(root: &Path) -> Result<Report> {
    let dependencies = runtime_dependencies(root)?;
    let intent = assembly_intent(root)?;
    let providers = assembly_providers(root)?;
    let shared_fields = struct_fields(
        root,
        SHARED_RUNTIME_DEPS_PATH,
        "SharedRuntimeDeps",
        "SharedRuntimeDeps",
    )?;
    let domain = domain_module_result(root)?;
    let anchors = wiring_anchors(root)?;

    let mut findings = Vec::new();
    if dependencies.is_empty() {
        findings.push(finding(
            Rule::EmptyDependencies,
            RUNTIME_CARGO_PATH,
            "[dependencies] 为空，baseline 退化为空转",
        ));
    }
    if providers.is_empty() {
        findings.push(finding(
            Rule::EmptyDiportProviders,
            ASSEMBLY_MANIFEST_PATH,
            "[[diportProviders]] 为空，assembly provider inventory 退化为空转",
        ));
    }
    if !domain.merge_present {
        findings.push(finding(
            Rule::MissingAnchor,
            BOOTSTRAP_MODULE_PATH,
            "缺 `DomainModuleResult::merge` 聚合函数",
        ));
    }
    for field in &domain.fields {
        if !domain.merge_extends.iter().any(|name| name == &field.name) {
            findings.push(finding(
                Rule::MissingAnchor,
                BOOTSTRAP_MODULE_PATH,
                format!("`DomainModuleResult::merge` 未聚合 `{}` 字段", field.name),
            ));
        }
    }
    for anchor in &anchors {
        if anchor.status != AnchorStatus::Ok {
            findings.push(finding(
                Rule::MissingAnchor,
                anchor.path,
                format!(
                    "required runtime wiring anchor `{}` missing or out of order",
                    anchor.id
                ),
            ));
        }
    }

    Ok(Report {
        rendered: render_baseline(
            &dependencies,
            &intent,
            &providers,
            &shared_fields,
            &domain,
            &anchors,
        ),
        dependencies: dependencies.len(),
        providers: providers.len(),
        shared_fields: shared_fields.len(),
        domain_fields: domain.fields.len(),
        anchors: anchors.len(),
        findings,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyEntry {
    name: String,
    spec: String,
}

fn runtime_dependencies(root: &Path) -> Result<Vec<DependencyEntry>> {
    let path = root.join(RUNTIME_CARGO_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let value: toml::Value =
        toml::from_str(&text).with_context(|| format!("解析 {} 失败", path.display()))?;
    let Some(table) = value.get("dependencies").and_then(toml::Value::as_table) else {
        return Ok(Vec::new());
    };
    let mut deps: Vec<_> = table
        .iter()
        .map(|(name, spec)| DependencyEntry {
            name: name.to_string(),
            spec: render_dependency_spec(spec),
        })
        .collect();
    deps.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(deps)
}

fn render_dependency_spec(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => format!("version={s}"),
        toml::Value::Table(table) => {
            let preferred = [
                "package",
                "path",
                "workspace",
                "version",
                "features",
                "default-features",
                "optional",
            ];
            let mut parts = Vec::new();
            for key in preferred {
                if let Some(value) = table.get(key) {
                    parts.push(format!("{key}={}", render_toml_value(value)));
                }
            }
            let mut extras: Vec<_> = table
                .iter()
                .filter(|(key, _)| !preferred.contains(&key.as_str()))
                .collect();
            extras.sort_by_key(|(key, _)| *key);
            for (key, value) in extras {
                parts.push(format!("{key}={}", render_toml_value(value)));
            }
            parts.join("; ")
        }
        other => render_toml_value(other),
    }
}

fn render_toml_value(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.to_string(),
        toml::Value::Integer(i) => i.to_string(),
        toml::Value::Float(f) => f.to_string(),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(dt) => dt.to_string(),
        toml::Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(render_toml_value)
                .collect::<Vec<_>>()
                .join(",")
        ),
        toml::Value::Table(table) => {
            let mut entries: Vec<_> = table.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!("{key}={}", render_toml_value(value)))
                    .collect::<Vec<_>>()
                    .join(";")
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderEntry {
    index: usize,
    port: String,
    provider: String,
    provider_crate: String,
    required_features: Vec<String>,
    consumer: String,
    lifecycle: String,
    durability: String,
    purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssemblyIntentEntry {
    name: String,
    profile: String,
    topology: String,
    domains: Vec<String>,
    listeners: Vec<String>,
}

fn assembly_manifest(root: &Path) -> Result<AssemblyManifest> {
    let path = root.join(ASSEMBLY_MANIFEST_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    AssemblyManifest::from_toml_str(&text).with_context(|| format!("解析 {} 失败", path.display()))
}

fn assembly_intent(root: &Path) -> Result<AssemblyIntentEntry> {
    let manifest = assembly_manifest(root)?;
    Ok(AssemblyIntentEntry {
        name: manifest.name,
        profile: manifest.profile.as_str().to_string(),
        topology: manifest.topology.as_str().to_string(),
        domains: manifest
            .domains
            .iter()
            .map(|domain| domain.as_str().to_string())
            .collect(),
        listeners: manifest
            .listeners
            .iter()
            .map(|listener| listener.kind.as_str().to_string())
            .collect(),
    })
}

fn assembly_providers(root: &Path) -> Result<Vec<ProviderEntry>> {
    let manifest = assembly_manifest(root)?;
    let mut providers = Vec::new();
    for (index, provider) in manifest.diport_providers.iter().enumerate() {
        providers.push(ProviderEntry {
            index: index + 1,
            port: provider.port.to_string(),
            provider: provider.provider.clone(),
            provider_crate: provider.provider_crate.clone(),
            required_features: provider.required_features.clone(),
            consumer: provider.consumer.clone(),
            lifecycle: provider.lifecycle.to_string(),
            durability: provider.durability.to_string(),
            purpose: provider.purpose.clone(),
        });
    }
    Ok(providers)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldEntry {
    name: String,
    ty: String,
}

fn struct_fields(
    root: &Path,
    rel_path: &str,
    struct_name: &str,
    label: &str,
) -> Result<Vec<FieldEntry>> {
    let path = root.join(rel_path);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    parse_struct_fields(&text, struct_name)
        .with_context(|| format!("解析 {label} 字段失败: {}", path.display()))
}

fn parse_struct_fields(src: &str, struct_name: &str) -> Result<Vec<FieldEntry>> {
    let body = extract_struct_body(src, struct_name)
        .with_context(|| format!("未找到 `pub struct {struct_name}`"))?;
    let mut fields = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(line) = line
            .strip_prefix("pub ")
            .or_else(|| line.strip_prefix("pub(crate) "))
        else {
            continue;
        };
        let field = line.split("//").next().unwrap_or(line).trim();
        let Some((name, ty)) = field.split_once(':') else {
            continue;
        };
        fields.push(FieldEntry {
            name: name.trim().to_string(),
            ty: ty.trim().trim_end_matches(',').trim().to_string(),
        });
    }
    Ok(fields)
}

fn extract_struct_body<'a>(src: &'a str, struct_name: &str) -> Option<&'a str> {
    let needle = format!("pub struct {struct_name}");
    let start = src.find(&needle)?;
    let open = src[start..].find('{')? + start;
    let mut depth = 0usize;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&src[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DomainModuleInventory {
    fields: Vec<FieldEntry>,
    merge_present: bool,
    merge_extends: Vec<String>,
}

fn domain_module_result(root: &Path) -> Result<DomainModuleInventory> {
    let path = root.join(BOOTSTRAP_MODULE_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let fields = parse_struct_fields(&text, "DomainModuleResult")
        .with_context(|| format!("解析 DomainModuleResult 字段失败: {}", path.display()))?;
    let merge_body =
        extract_braced_body(&text, "pub fn merge(&mut self, other: DomainModuleResult)");
    let merge_scan = merge_body
        .map(mask_comments_and_strings)
        .unwrap_or_default();
    let merge_present = merge_body.is_some();
    let mut merge_extends = Vec::new();
    if merge_present {
        for field in &fields {
            let pattern = format!("self.{}.extend(other.{})", field.name, field.name);
            if merge_scan.contains(&pattern) {
                merge_extends.push(field.name.clone());
            }
        }
    }
    Ok(DomainModuleInventory {
        fields,
        merge_present,
        merge_extends,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnchorSpec {
    id: &'static str,
    path: &'static str,
    pattern: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorStatus {
    Ok,
    Missing,
    OutOfOrder,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnchorEntry {
    id: &'static str,
    path: &'static str,
    pattern: &'static str,
    status: AnchorStatus,
}

#[derive(Debug, Clone, Copy)]
struct AnchorSearchScope<'a> {
    body: &'a str,
    start: usize,
    end: usize,
}

const RUNTIME_ANCHORS: &[AnchorSpec] = &[
    AnchorSpec {
        id: "run.plan.load",
        path: RUNTIME_LIB_PATH,
        pattern: "plan::RuntimePlan::bundled().context(",
    },
    AnchorSpec {
        id: "run.provider.oidc",
        path: RUNTIME_LIB_PATH,
        pattern: "build_runtime_oidc_provider().context(",
    },
    AnchorSpec {
        id: "run.provider.pg",
        path: RUNTIME_LIB_PATH,
        pattern: "PgRuntimeDeps::setup_with_audit_admin_config",
    },
    AnchorSpec {
        id: "run.provider.vault",
        path: RUNTIME_LIB_PATH,
        pattern: "build_vault_runtime_deps(|name| std::env::var(name).ok())",
    },
    AnchorSpec {
        id: "run.provider.redis",
        path: RUNTIME_LIB_PATH,
        pattern: "build_redis_runtime_deps(|name| std::env::var(name).ok())",
    },
    AnchorSpec {
        id: "run.provider.s3",
        path: RUNTIME_LIB_PATH,
        pattern: "build_s3_runtime_deps_from(|name| std::env::var(name).ok())",
    },
    AnchorSpec {
        id: "run.shared-deps",
        path: RUNTIME_LIB_PATH,
        pattern: "let deps = SharedRuntimeDeps {",
    },
    AnchorSpec {
        id: "run.wire.audit",
        path: RUNTIME_LIB_PATH,
        pattern: "wire_audit(&deps)",
    },
    AnchorSpec {
        id: "run.wire.identity",
        path: RUNTIME_LIB_PATH,
        pattern: "wire_identity(&deps)",
    },
    AnchorSpec {
        id: "run.module.input.settings",
        path: RUNTIME_LIB_PATH,
        pattern: "let (settings_domain, settings_module)",
    },
    AnchorSpec {
        id: "run.wire.settings",
        path: RUNTIME_LIB_PATH,
        pattern: "wire_settings(&deps)",
    },
    AnchorSpec {
        id: "run.compose",
        path: RUNTIME_LIB_PATH,
        pattern: "bootstrap::compose(&[&settings_domain, &identity_domain, &audit_domain])",
    },
    AnchorSpec {
        id: "run.module.input.session-sweeper",
        path: RUNTIME_LIB_PATH,
        pattern: "let session_sweeper_module =",
    },
    AnchorSpec {
        id: "run.module.input.s3-canary",
        path: RUNTIME_LIB_PATH,
        pattern: "let s3_canary_module =",
    },
    AnchorSpec {
        id: "run.resources.redis",
        path: RUNTIME_LIB_PATH,
        pattern: "let redis_resources = deps.redis.runtime_resources()",
    },
    AnchorSpec {
        id: "run.resources.s3",
        path: RUNTIME_LIB_PATH,
        pattern: "let s3_resources = deps.s3.runtime_resources()",
    },
    AnchorSpec {
        id: "run.resources.vault",
        path: RUNTIME_LIB_PATH,
        pattern: "let vault_resources = deps.vault.runtime_resources()",
    },
    AnchorSpec {
        id: "run.resources.oidc",
        path: RUNTIME_LIB_PATH,
        pattern: "let oidc_resource = runtime_oidc.managed_resource()",
    },
    AnchorSpec {
        id: "run.probe.oidc-jwks",
        path: RUNTIME_LIB_PATH,
        pattern: "Box::new(OidcJwksReadyProbe::new(runtime_oidc.jwks_readiness()))",
    },
    AnchorSpec {
        id: "run.module.input.domain-transport",
        path: RUNTIME_LIB_PATH,
        pattern: "let domain_transport_module = domain_transport",
    },
    AnchorSpec {
        id: "run.wire.distributed",
        path: RUNTIME_LIB_PATH,
        pattern: "wire_distributed(&deps)",
    },
    AnchorSpec {
        id: "run.event.bridge",
        path: RUNTIME_LIB_PATH,
        pattern: "event_transport::bridge_generated_subscriptions(registry.drain_subscribers())",
    },
    AnchorSpec {
        id: "run.event.transport",
        path: RUNTIME_LIB_PATH,
        pattern: "event_transport::wire_event_transport(",
    },
    AnchorSpec {
        id: "run.module.assemble",
        path: RUNTIME_LIB_PATH,
        pattern: "assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs",
    },
    AnchorSpec {
        id: "run.probe.drain",
        path: RUNTIME_LIB_PATH,
        pattern: "for (name, probe) in module.probes",
    },
    AnchorSpec {
        id: "run.auth.routers",
        path: RUNTIME_LIB_PATH,
        pattern: "assemble_authed_routers(",
    },
    AnchorSpec {
        id: "run.health.listener",
        path: RUNTIME_LIB_PATH,
        pattern: "health_listener(reporter, metrics_exporter)",
    },
    AnchorSpec {
        id: "run.launch",
        path: RUNTIME_LIB_PATH,
        pattern: "launch::launch(launch_plan)",
    },
    AnchorSpec {
        id: "launch.shutdown.trace",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "if let Some(exporter) = trace_exporter",
    },
    AnchorSpec {
        id: "launch.shutdown.pg-store",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "stack.register_detached(pg_store_guard);",
    },
    AnchorSpec {
        id: "launch.shutdown.pg-audit",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "if let Some(guard) = pg_audit_admin_store_guard",
    },
    AnchorSpec {
        id: "launch.shutdown.pg-sampler",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "stack.register_with_token(pg_readiness_sampler);",
    },
    AnchorSpec {
        id: "launch.shutdown.event-infra",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for guard in event_infra_guards",
    },
    AnchorSpec {
        id: "launch.shutdown.resources",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for resource in domain_resources",
    },
    AnchorSpec {
        id: "launch.shutdown.workers",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for worker in domain_workers",
    },
    AnchorSpec {
        id: "launch.register-plan",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "let listeners = plan.register(&mut stack);",
    },
    AnchorSpec {
        id: "launch.listeners",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "bind_and_register(&mut stack, listener, &addr_resolver).await?;",
    },
];

fn wiring_anchors(root: &Path) -> Result<Vec<AnchorEntry>> {
    let mut file_cache = BTreeMap::<&str, String>::new();
    let mut last_pos = BTreeMap::<(&str, &str), usize>::new();
    let mut entries = Vec::new();

    for spec in RUNTIME_ANCHORS {
        let text = match file_cache.entry(spec.path) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let path = root.join(spec.path);
                let text = fs::read_to_string(&path)
                    .with_context(|| format!("读 {} 失败", path.display()))?;
                entry.insert(text)
            }
        };

        let scope = anchor_search_scope(spec, text);
        let masked_scope = mask_comments_and_strings(scope.body);
        let status = match masked_scope.find(spec.pattern) {
            None => AnchorStatus::Missing,
            Some(pos) => {
                let absolute_pos = scope.start + pos;
                let previous = last_pos.entry(anchor_order_key(spec)).or_insert(0);
                if absolute_pos < *previous {
                    AnchorStatus::OutOfOrder
                } else {
                    *previous = absolute_pos;
                    AnchorStatus::Ok
                }
            }
        };
        entries.push(AnchorEntry {
            id: spec.id,
            path: spec.path,
            pattern: spec.pattern,
            status,
        });
    }
    Ok(entries)
}

fn anchor_search_scope<'a>(spec: &AnchorSpec, text: &'a str) -> AnchorSearchScope<'a> {
    if spec.path == RUNTIME_LIB_PATH {
        return extract_braced_body_at(text, 0, "pub async fn run(")
            .unwrap_or_else(|| empty_scope(text));
    }
    if spec.path == RUNTIME_LAUNCH_PATH {
        if spec.id.starts_with("launch.shutdown.") {
            return launch_plan_register_scope(text).unwrap_or_else(|| empty_scope(text));
        }
        if matches!(spec.id, "launch.register-plan" | "launch.listeners") {
            return extract_braced_body_at(text, 0, "async fn launch_until_observed")
                .unwrap_or_else(|| empty_scope(text));
        }
    }
    AnchorSearchScope {
        body: text,
        start: 0,
        end: text.len(),
    }
}

fn anchor_order_key(spec: &AnchorSpec) -> (&'static str, &'static str) {
    if spec.path == RUNTIME_LIB_PATH {
        return (spec.path, "run");
    }
    if spec.path == RUNTIME_LAUNCH_PATH && spec.id.starts_with("launch.shutdown.") {
        return (spec.path, "register");
    }
    if spec.path == RUNTIME_LAUNCH_PATH
        && matches!(spec.id, "launch.register-plan" | "launch.listeners")
    {
        return (spec.path, "launch_until_observed");
    }
    (spec.path, "file")
}

fn extract_braced_body<'a>(src: &'a str, needle: &str) -> Option<&'a str> {
    extract_braced_body_at(src, 0, needle).map(|scope| scope.body)
}

fn extract_braced_body_at<'a>(
    src: &'a str,
    search_from: usize,
    needle: &str,
) -> Option<AnchorSearchScope<'a>> {
    let start = src.get(search_from..)?.find(needle)? + search_from;
    let open = src[start..].find('{')? + start;
    let scan = mask_comments_and_strings(&src[open..]);
    let mut depth = 0usize;
    for (offset, byte) in scan.as_bytes().iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(AnchorSearchScope {
                        body: &src[open + 1..open + offset],
                        start: open + 1,
                        end: open + offset,
                    });
                }
            }
            _ => {}
        }
    }
    None
}

fn launch_plan_register_scope(text: &str) -> Option<AnchorSearchScope<'_>> {
    let mut cursor = 0usize;
    while cursor < text.len() {
        let impl_scope = extract_braced_body_at(text, cursor, "impl LaunchPlan")?;
        if let Some(method_offset) = impl_scope.body.find("fn register(") {
            let method_start = impl_scope.start + method_offset;
            if let Some(method_scope) = extract_braced_body_at(text, method_start, "fn register(")
                && method_scope.end <= impl_scope.end
            {
                return Some(method_scope);
            }
        }
        cursor = impl_scope.end.saturating_add(1);
    }
    None
}

fn empty_scope(text: &str) -> AnchorSearchScope<'_> {
    AnchorSearchScope {
        body: &text[..0],
        start: 0,
        end: 0,
    }
}

fn mask_comments_and_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if let Some(end) = raw_string_end(bytes, index) {
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if is_prefixed_string_start(bytes, index) {
            let end = quoted_string_end(bytes, index + 2);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'"' {
            let end = quoted_string_end(bytes, index + 1);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            let end = block_comment_end(bytes, index);
            mask_range(bytes, index, end, &mut out);
            index = end;
            continue;
        }

        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn raw_string_end(bytes: &[u8], index: usize) -> Option<usize> {
    let mut cursor = match bytes.get(index) {
        Some(b'r') => index + 1,
        Some(b'b' | b'c') if bytes.get(index + 1) == Some(&b'r') => index + 2,
        _ => return None,
    };
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let hashes = cursor - hashes_start;
    cursor += 1;
    while cursor < bytes.len() {
        if bytes[cursor] == b'"' && has_raw_string_hashes(bytes, cursor + 1, hashes) {
            return Some(cursor + 1 + hashes);
        }
        cursor += 1;
    }
    Some(bytes.len())
}

fn has_raw_string_hashes(bytes: &[u8], start: usize, hashes: usize) -> bool {
    start + hashes <= bytes.len()
        && bytes[start..start + hashes]
            .iter()
            .all(|byte| *byte == b'#')
}

fn is_prefixed_string_start(bytes: &[u8], index: usize) -> bool {
    matches!(bytes.get(index), Some(b'b' | b'c')) && bytes.get(index + 1) == Some(&b'"')
}

fn quoted_string_end(bytes: &[u8], mut index: usize) -> usize {
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return index + 1;
        }
        index += 1;
    }
    bytes.len()
}

fn block_comment_end(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            depth += 1;
            index += 2;
            continue;
        }
        if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
            depth = depth.saturating_sub(1);
            index += 2;
            if depth == 0 {
                return index;
            }
            continue;
        }
        index += 1;
    }
    bytes.len()
}

fn mask_range(bytes: &[u8], start: usize, end: usize, out: &mut Vec<u8>) {
    for byte in &bytes[start..end] {
        match byte {
            b'\n' | b'\r' => out.push(*byte),
            _ => out.push(b' '),
        }
    }
}

fn render_baseline(
    dependencies: &[DependencyEntry],
    intent: &AssemblyIntentEntry,
    providers: &[ProviderEntry],
    shared_fields: &[FieldEntry],
    domain: &DomainModuleInventory,
    anchors: &[AnchorEntry],
) -> String {
    let mut out = String::new();
    out.push_str("# runtime-baseline v1\n");
    out.push_str("# generated-by: cargo xtask runtime-baseline list\n");
    out.push_str("# static-facts-only: dynamic environment/provider state is documented, not enforced here\n\n");

    out.push_str("[sources]\n");
    push_line(&mut out, format_args!("cargo = {RUNTIME_CARGO_PATH}"));
    push_line(
        &mut out,
        format_args!("assembly = {ASSEMBLY_MANIFEST_PATH}"),
    );
    push_line(
        &mut out,
        format_args!("sharedRuntimeDeps = {SHARED_RUNTIME_DEPS_PATH}"),
    );
    push_line(
        &mut out,
        format_args!("domainModuleResult = {BOOTSTRAP_MODULE_PATH}"),
    );
    push_line(&mut out, format_args!("run = {RUNTIME_LIB_PATH}"));
    push_line(&mut out, format_args!("launch = {RUNTIME_LAUNCH_PATH}"));
    out.push('\n');

    out.push_str("[runtime.dependencies]\n");
    for dep in dependencies {
        push_line(&mut out, format_args!("{} = {}", dep.name, dep.spec));
    }
    out.push('\n');

    out.push_str("[assembly.intent]\n");
    push_line(&mut out, format_args!("name = {}", intent.name));
    push_line(&mut out, format_args!("profile = {}", intent.profile));
    push_line(&mut out, format_args!("topology = {}", intent.topology));
    push_line(
        &mut out,
        format_args!("domains = {}", render_string_list(&intent.domains)),
    );
    push_line(
        &mut out,
        format_args!("listeners = {}", render_string_list(&intent.listeners)),
    );
    out.push('\n');

    out.push_str("[assembly.diportProviders]\n");
    for provider in providers {
        push_line(
            &mut out,
            format_args!(
                "{:02} | port={} | provider={} | providerCrate={} | requiredFeatures={} | consumer={} | lifecycle={} | durability={} | purpose={}",
                provider.index,
                provider.port,
                provider.provider,
                provider.provider_crate,
                render_feature_list(&provider.required_features),
                provider.consumer,
                provider.lifecycle,
                provider.durability,
                provider.purpose
            ),
        );
    }
    out.push('\n');

    out.push_str("[sharedRuntimeDeps.fields]\n");
    for field in shared_fields {
        push_line(&mut out, format_args!("{} = {}", field.name, field.ty));
    }
    out.push('\n');

    out.push_str("[domainModuleResult.fields]\n");
    for field in &domain.fields {
        push_line(&mut out, format_args!("{} = {}", field.name, field.ty));
    }
    push_line(
        &mut out,
        format_args!(
            "merge = {}",
            if domain.merge_present {
                "present"
            } else {
                "missing"
            }
        ),
    );
    push_line(
        &mut out,
        format_args!("mergeExtends = {}", domain.merge_extends.join(",")),
    );
    out.push('\n');

    out.push_str("[runtime.run.orderedAnchors]\n");
    for (index, anchor) in anchors.iter().enumerate() {
        push_line(
            &mut out,
            format_args!(
                "{:02} | {} | {} | {} | status={}",
                index + 1,
                anchor.id,
                anchor.path,
                anchor.pattern,
                anchor_status(anchor.status)
            ),
        );
    }
    out
}

fn push_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    out.push_str(&args.to_string());
    out.push('\n');
}

fn render_feature_list(features: &[String]) -> String {
    render_string_list(features)
}

fn render_string_list(items: &[String]) -> String {
    if items.is_empty() {
        "[]".to_string()
    } else {
        format!("[{}]", items.join(","))
    }
}

fn anchor_status(status: AnchorStatus) -> &'static str {
    match status {
        AnchorStatus::Ok => "ok",
        AnchorStatus::Missing => "missing",
        AnchorStatus::OutOfOrder => "out-of-order",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;
    use anyhow::Result;

    fn write(path: &Path, text: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)?;
        Ok(())
    }

    fn fixture_root(name: &str) -> Result<std::path::PathBuf> {
        let root = unique_tmp(name);
        write(
            &root.join(RUNTIME_CARGO_PATH),
            r#"
[package]
name = "runtime"

[dependencies]
bootstrap = { path = "../../crates/bootstrap" }
redis = { package = "redis-adapter", path = "../../adapters/redis", features = ["backend"] }
serde = { workspace = true, features = ["derive"] }
"#,
        )?;
        write(
            &root.join(ASSEMBLY_MANIFEST_PATH),
            r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"

[[listeners]]
kind = "primary"

[[listeners]]
kind = "internal"

[[listeners]]
kind = "admin"

[[listeners]]
kind = "health"

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
"#,
        )?;
        write(
            &root.join(SHARED_RUNTIME_DEPS_PATH),
            r#"
pub struct SharedRuntimeDeps {
    pub pg: PgRuntimeDeps,
    pub redis: RedisRuntimeDeps,
    pub domain_transport: Arc<dyn distributed::DomainTransport>,
}
"#,
        )?;
        write(
            &root.join(BOOTSTRAP_MODULE_PATH),
            r#"
pub struct DomainModuleResult {
    pub probes: Vec<(ProbeName, Box<dyn HealthProbe>)>,
    pub resources: Vec<Box<DynManagedResource<'static>>>,
    pub workers: Vec<WorkerSpec>,
}

impl DomainModuleResult {
    pub fn merge(&mut self, other: DomainModuleResult) {
        self.probes.extend(other.probes);
        self.resources.extend(other.resources);
        self.workers.extend(other.workers);
    }
}
"#,
        )?;
        write(&root.join(RUNTIME_LIB_PATH), &runtime_lib_fixture(None))?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &runtime_launch_fixture(None),
        )?;
        Ok(root)
    }

    fn runtime_lib_fixture(omit: Option<&str>) -> String {
        format!(
            "pub async fn run() {{\n{}\n}}\n",
            runtime_anchor_lines(omit)
        )
    }

    fn runtime_anchor_lines(omit: Option<&str>) -> String {
        let mut lines = Vec::new();
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH)
        {
            if omit == Some(anchor.id) {
                continue;
            }
            lines.push(anchor.pattern);
            if anchor.id == "run.shared-deps" {
                lines.push("}");
            }
        }
        lines.join("\n")
    }

    fn runtime_launch_fixture(omit: Option<&str>) -> String {
        format!(
            "impl LaunchPlan {{ fn register() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\n{}\n}}\n",
            launch_register_anchor_lines(omit),
            launch_until_anchor_lines(omit)
        )
    }

    fn launch_register_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| {
                anchor.path == RUNTIME_LAUNCH_PATH && anchor.id.starts_with("launch.shutdown.")
            })
            .filter(|anchor| omit != Some(anchor.id))
            .map(|anchor| anchor.pattern)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn launch_until_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| {
                anchor.path == RUNTIME_LAUNCH_PATH
                    && matches!(anchor.id, "launch.register-plan" | "launch.listeners")
            })
            .filter(|anchor| omit != Some(anchor.id))
            .map(|anchor| anchor.pattern)
            .collect::<Vec<_>>()
            .join("\n")
    }
    #[test]
    fn runtime_baseline_accepts_fixture() -> Result<()> {
        let root = fixture_root("runtime-baseline-green")?;
        let report = collect_report(&root)?;
        assert_eq!(report.findings, Vec::<Finding<Rule>>::new());
        assert_eq!(report.dependencies, 3);
        assert_eq!(report.providers, 1);
        assert_eq!(report.shared_fields, 3);
        assert_eq!(report.domain_fields, 3);
        assert_eq!(report.anchors, RUNTIME_ANCHORS.len());
        Ok(())
    }

    #[test]
    fn runtime_baseline_rejects_bad_manifest() -> Result<()> {
        let root = fixture_root("runtime-baseline-bad-manifest")?;
        write(
            &root.join(ASSEMBLY_MANIFEST_PATH),
            r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"

[[listeners]]
kind = "primary"

[[listeners]]
kind = "internal"

[[listeners]]
kind = "admin"

[[listeners]]
kind = "health"

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "unknown"
durability = "persistent"
purpose = "jwt-credential-verification"
"#,
        )?;
        assert!(collect_report(&root).is_err());
        Ok(())
    }

    #[test]
    fn runtime_baseline_renderer_snapshot() -> Result<()> {
        let root = fixture_root("runtime-baseline-render")?;
        let report = collect_report(&root)?;
        let expected_prefix = r#"# runtime-baseline v1
# generated-by: cargo xtask runtime-baseline list
# static-facts-only: dynamic environment/provider state is documented, not enforced here

[sources]
cargo = assemblies/runtime/Cargo.toml
assembly = assemblies/runtime/assembly.toml
sharedRuntimeDeps = assemblies/runtime/src/module.rs
domainModuleResult = crates/bootstrap/src/module.rs
run = assemblies/runtime/src/lib.rs
launch = assemblies/runtime/src/launch.rs

[runtime.dependencies]
bootstrap = path=../../crates/bootstrap
redis = package=redis-adapter; path=../../adapters/redis; features=[backend]
serde = workspace=true; features=[derive]
"#;
        assert!(
            report.rendered.starts_with(expected_prefix),
            "{}",
            report.rendered
        );
        assert!(report.rendered.contains("[assembly.intent]"));
        assert!(report.rendered.contains("name = runtime"));
        assert!(report.rendered.contains("profile = demo"));
        assert!(report.rendered.contains("topology = durable-shared"));
        assert!(
            report
                .rendered
                .contains("domains = [identity,settings,audit]")
        );
        assert!(
            report
                .rendered
                .contains("listeners = [primary,internal,admin,health]")
        );
        assert!(report.rendered.contains(
            "01 | port=diport::Pdp | provider=oidc::OidcProvider | providerCrate=oidc | requiredFeatures=[backend] | consumer=httpserve | lifecycle=active | durability=persistent | purpose=jwt-credential-verification"
        ));
        assert!(
            report
                .rendered
                .contains("mergeExtends = probes,resources,workers")
        );
        assert!(report.rendered.contains("36 | launch.register-plan"));
        assert!(report.rendered.contains("37 | launch.listeners"));
        Ok(())
    }

    #[test]
    fn runtime_baseline_missing_baseline_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-missing")?;
        let (_, findings) = check_root(&root)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingBaseline));
        Ok(())
    }

    #[test]
    fn runtime_baseline_drift_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-drift")?;
        write(&root.join(BASELINE_PATH), "stale\n")?;
        let (_, findings) = check_root(&root)?;
        assert!(findings.iter().any(|f| f.rule == Rule::Drift));
        Ok(())
    }

    #[test]
    fn runtime_baseline_empty_dependencies_and_providers_fail() -> Result<()> {
        let root = fixture_root("runtime-baseline-empty")?;
        write(
            &root.join(RUNTIME_CARGO_PATH),
            r#"
[package]
name = "runtime"
[dependencies]
"#,
        )?;
        write(
            &root.join(ASSEMBLY_MANIFEST_PATH),
            r#"
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
diportProviders = []

[[listeners]]
kind = "primary"

[[listeners]]
kind = "internal"

[[listeners]]
kind = "admin"

[[listeners]]
kind = "health"
"#,
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == Rule::EmptyDependencies)
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == Rule::EmptyDiportProviders)
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_missing_required_anchor_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-missing-anchor")?;
        write(
            &root.join(RUNTIME_LIB_PATH),
            &runtime_lib_fixture(Some("run.wire.identity")),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.identity")
            })
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_provider_anchor_requires_real_provider_call() -> Result<()> {
        let root = fixture_root("runtime-baseline-provider-anchor-real-call")?;
        let mut lines = Vec::new();
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH)
        {
            if anchor.id == "run.provider.oidc" {
                lines.push("phase_result(RuntimePhase::BuildProvider, Ok::<_, anyhow::Error>(()))");
            } else {
                lines.push(anchor.pattern);
            }
            if anchor.id == "run.shared-deps" {
                lines.push("}");
            }
        }
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!("pub async fn run() {{\n{}\n}}\n", lines.join("\n")),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.provider.oidc")
            }),
            "provider phase marker alone must not satisfy the real provider construction anchor"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_requires_plan_load_before_provider_construction() -> Result<()> {
        let root = fixture_root("runtime-baseline-plan-load-before-provider")?;
        let mut lines = Vec::new();
        let plan = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.plan.load")
            .context("plan anchor")?;
        let oidc = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.provider.oidc")
            .context("oidc anchor")?;
        lines.push(oidc.pattern);
        lines.push(plan.pattern);
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH)
        {
            if matches!(anchor.id, "run.plan.load" | "run.provider.oidc") {
                continue;
            }
            lines.push(anchor.pattern);
            if anchor.id == "run.shared-deps" {
                lines.push("}");
            }
        }
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!("pub async fn run() {{\n{}\n}}\n", lines.join("\n")),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.provider.oidc")
            }),
            "plan load anchor must precede provider construction"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_missing_launch_anchor_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-missing-launch-anchor")?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &runtime_launch_fixture(Some("launch.shutdown.workers")),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("launch.shutdown.workers")
            }),
            "missing launch register anchor must fail: {:?}",
            report.findings
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_launch_anchor_order_is_checked() -> Result<()> {
        let root = fixture_root("runtime-baseline-launch-out-of-order")?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            r#"
impl LaunchPlan { fn register() {
if let Some(exporter) = trace_exporter
stack.register_detached(pg_store_guard);
if let Some(guard) = pg_audit_admin_store_guard
stack.register_with_token(pg_readiness_sampler);
for guard in event_infra_guards
for worker in domain_workers
for resource in domain_resources
}}
async fn launch_until_observed() {
let listeners = plan.register(&mut stack);
bind_and_register(&mut stack, listener, &addr_resolver).await?;
}
"#,
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("launch.shutdown.workers")
            }),
            "out-of-order launch anchor must fail: {:?}",
            report.findings
        );
        assert!(
            report
                .rendered
                .contains("launch.shutdown.workers | assemblies/runtime/src/launch.rs | for worker in domain_workers | status=out-of-order"),
            "out-of-order launch anchor must be rendered explicitly: {}",
            report.rendered
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_launch_anchor_bait() -> Result<()> {
        let root = fixture_root("runtime-baseline-launch-bait")?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &format!(
                "impl LaunchPlan {{ fn register() {{\n{}\n// {}\nlet _ = {:?};\n}}\n}}\nfn dead_helper() {{ {} }}\nasync fn launch_until_observed() {{\n{}\n}}\n",
                launch_register_anchor_lines(Some("launch.shutdown.resources")),
                "for resource in domain_resources",
                "for resource in domain_resources",
                "for resource in domain_resources",
                launch_until_anchor_lines(None)
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("launch.shutdown.resources")
            }),
            "comment/string/dead helper launch bait must fail: {:?}",
            report.findings
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_same_name_register_bait_before_launch_plan_impl() -> Result<()> {
        let root = fixture_root("runtime-baseline-launch-register-bait")?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &format!(
                "fn register() {{\n{}\n}}\n#[cfg(test)] mod tests {{ fn register() {{\n{}\n}} }}\nimpl LaunchPlan {{ fn register() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\n{}\n}}\n",
                launch_register_anchor_lines(None),
                launch_register_anchor_lines(None),
                launch_register_anchor_lines(Some("launch.shutdown.resources")),
                launch_until_anchor_lines(None)
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("launch.shutdown.resources")
            }),
            "same-name register bait before LaunchPlan impl must not satisfy launch shutdown anchors: {:?}",
            report.findings
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_requires_plan_register_before_listener_bind() -> Result<()> {
        let root = fixture_root("runtime-baseline-launch-plan-before-bind")?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &format!(
                "impl LaunchPlan {{ fn register() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\nbind_and_register(&mut stack, listener, &addr_resolver).await?;\nlet listeners = plan.register(&mut stack);\n}}\n",
                launch_register_anchor_lines(None)
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("launch.listeners")
            }),
            "listener bind before plan.register must be out-of-order: {:?}",
            report.findings
        );
        assert!(
            report
                .rendered
                .contains("launch.listeners | assemblies/runtime/src/launch.rs | bind_and_register(&mut stack, listener, &addr_resolver).await?; | status=out-of-order"),
            "out-of-order listener bind must be rendered explicitly: {}",
            report.rendered
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_anchor_outside_run_body() -> Result<()> {
        let root = fixture_root("runtime-baseline-anchor-outside-run")?;
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!(
                "{}\n#[cfg(test)]\nmod tests {{ fn false_positive() {{ {} }} }}\n",
                runtime_lib_fixture(Some("run.wire.identity")),
                "wire_identity(&deps);"
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.identity")
            }),
            "anchor outside run() body must not satisfy runtime wiring baseline"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_anchor_in_comment_and_string() -> Result<()> {
        let root = fixture_root("runtime-baseline-anchor-comment-string")?;
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!(
                "pub async fn run() {{\n{}\n// {}\nlet _ = {:?};\n}}\n",
                runtime_anchor_lines(Some("run.wire.identity")),
                "wire_identity(&deps);",
                "wire_identity(&deps);"
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.identity")
            }),
            "comment/string anchor must not satisfy runtime wiring baseline"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_merge_extend_in_comment() -> Result<()> {
        let root = fixture_root("runtime-baseline-merge-comment")?;
        write(
            &root.join(BOOTSTRAP_MODULE_PATH),
            r#"
pub struct DomainModuleResult {
    pub probes: Vec<(ProbeName, Box<dyn HealthProbe>)>,
    pub resources: Vec<Box<DynManagedResource<'static>>>,
    pub workers: Vec<WorkerSpec>,
}

impl DomainModuleResult {
    pub fn merge(&mut self, other: DomainModuleResult) {
        self.probes.extend(other.probes);
        // self.resources.extend(other.resources);
        self.workers.extend(other.workers);
    }
}
"#,
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor
                    && f.detail.contains("DomainModuleResult::merge")
                    && f.detail.contains("resources")
            }),
            "commented merge extend must not satisfy DomainModuleResult merge baseline"
        );
        Ok(())
    }
}
