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
//!
//! INVARIANT: RUNTIME-GENERATED-DOMAINS-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_generated_domains_rejects_handwritten_wiring_and_missing_merge", anti_vacuity = "tests::runtime_baseline_accepts_fixture" } -- `run()` must consume the committed generated domain list through `compose_bindings`, must merge its output, and must not restore per-domain handwritten wiring.
//!
//! INVARIANT: RUNTIME-CONFIG-SNAPSHOT-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_config_snapshot_rejects_ambient_provider_readers", anti_vacuity = "tests::runtime_baseline_accepts_fixture" } -- `run()` must capture the process configuration exactly once after loading the plan and before constructing any provider; the same capture binding must flow into `RuntimeInputs`, whose unique snapshot-backed `config_value` reader must feed the unique Vault, Redis, and S3 calls without ambient, discarded-generation, or bait side paths.
//!
//! INVARIANT: SECRET-TEXT-TRANSFER-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff", anti_vacuity = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff" } -- runtime raw secret allocation transfer is a unique named funnel whose four production handoffs are closed and bait-resistant.
//!
//! INVARIANT: RUNTIME-PROVIDER-OUTPUTS-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_provider_outputs_reject_missing_reordered_legacy_and_bait", anti_vacuity = "tests::runtime_provider_outputs_accept_unified_live_path" } -- the sole runtime-local constructor must merge Redis, S3, and Vault in order; postgres must remain outside that trait and cross the launch boundary exactly once as an owned `DomainModuleResult`, without lifecycle primitive bypasses or a parallel output type.
//!
//! INVARIANT: EVENT-TRANSPORT-OUTPUT-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::event_transport_output_funnel_rejects_legacy_and_bypasses", anti_vacuity = "tests::event_transport_output_funnel_accepts_unified_live_path" } -- event transport must return one crate-private `DomainModuleResult`, merge it once into runtime assembly, and register AMQP resources plus workers only through the common lifecycle funnel.

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::localtx_coverage::attrs_may_be_production;
use crate::workspace_root;
use anyhow::{Context, Result};
use assembly_schema::AssemblyManifest;
use quote::ToTokens as _;
use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};
use std::fs;
use std::path::{Path, PathBuf};
use syn::visit::Visit;

const BASELINE_PATH: &str = "runtime-baseline/runtime.txt";
const RUNTIME_CARGO_PATH: &str = "assemblies/runtime/Cargo.toml";
const ASSEMBLY_MANIFEST_PATH: &str = "assemblies/runtime/assembly.toml";
const SHARED_RUNTIME_DEPS_PATH: &str = "assemblies/runtime/src/module.rs";
const BOOTSTRAP_MODULE_PATH: &str = "crates/bootstrap/src/module.rs";
const RUNTIME_LIB_PATH: &str = "assemblies/runtime/src/lib.rs";
const RUNTIME_SRC_PATH: &str = "assemblies/runtime/src";
const PROVIDER_OUTPUT_PATH: &str = "assemblies/runtime/src/provider_output.rs";
const PROVIDER_OUTPUT_FIXTURE_MARKER: &str = ".runtime-provider-output-fixture";
const RUNTIME_CONFIG_FIXTURE_MARKER: &str = ".runtime-config-snapshot-fixture";
const GENERATED_MODULES_PATH: &str = "assemblies/runtime/src/generated/modules_gen.rs";
const RUNTIME_LAUNCH_PATH: &str = "assemblies/runtime/src/launch.rs";
const RUNTIME_EVENT_PATH: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_S3_PATH: &str = "assemblies/runtime/src/infra/s3.rs";
const SECRET_TRANSFER_TOKEN: &str = "transfer_secret_allocation";
const SECRET_TRANSFER_ALLOWLIST: &[(&str, &str)] = &[
    (RUNTIME_LIB_PATH, "fn transfer_secret_allocation"),
    (RUNTIME_EVENT_PATH, "hot_token.transfer_secret_allocation()"),
    (
        RUNTIME_EVENT_PATH,
        "archive_token.transfer_secret_allocation()",
    ),
    (
        RUNTIME_S3_PATH,
        "secret_access_key.transfer_secret_allocation()",
    ),
    (
        RUNTIME_S3_PATH,
        "session_token.map(EnvSecret::transfer_secret_allocation)",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingBaseline,
    Drift,
    EmptyDependencies,
    EmptyDiportProviders,
    MissingAnchor,
    ForbiddenWiring,
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
    findings.extend(runtime_config_snapshot_live_findings(root)?);
    findings.extend(runtime_secret_transfer_live_findings(root)?);
    findings.extend(generated_domains_live_findings(root)?);
    findings.extend(provider_outputs_live_findings(root)?);
    findings.extend(event_transport_output_findings(root)?);

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

#[derive(Default)]
struct RuntimeConfigWiring {
    snapshot_calls: usize,
    canonical_snapshot_calls: usize,
    snapshot_binding: Option<syn::Ident>,
    runtime_inputs_calls: usize,
    canonical_runtime_inputs_bindings: usize,
    runtime_inputs_binding: Option<syn::Ident>,
    config_value_bindings: usize,
    canonical_config_value_bindings: usize,
    vault_calls: usize,
    canonical_vault_calls: usize,
    redis_calls: usize,
    canonical_redis_calls: usize,
    s3_calls: usize,
    canonical_s3_calls: usize,
}

impl RuntimeConfigWiring {
    fn is_canonical(&self) -> bool {
        self.snapshot_calls == 1
            && self.canonical_snapshot_calls == 1
            && self.snapshot_binding.is_some()
            && self.runtime_inputs_calls == 1
            && self.canonical_runtime_inputs_bindings == 1
            && self.runtime_inputs_binding.is_some()
            && self.config_value_bindings == 1
            && self.canonical_config_value_bindings == 1
            && self.vault_calls == 1
            && self.canonical_vault_calls == 1
            && self.redis_calls == 1
            && self.canonical_redis_calls == 1
            && self.s3_calls == 1
            && self.canonical_s3_calls == 1
    }
}

impl<'ast> Visit<'ast> for RuntimeConfigWiring {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let binding = pat_ident(&local.pat);
        let initializer = local.init.as_ref().map(|init| init.expr.as_ref());

        if let (Some(binding), Some(initializer)) = (binding, initializer) {
            if is_env_snapshot_initializer(initializer) && self.snapshot_binding.is_none() {
                self.snapshot_binding = Some(binding.clone());
            }

            if is_runtime_inputs_initializer(initializer, self.snapshot_binding.as_ref()) {
                self.canonical_runtime_inputs_bindings += 1;
                if self.runtime_inputs_binding.is_none() {
                    self.runtime_inputs_binding = Some(binding.clone());
                }
            }
        }

        if binding.is_some_and(|binding| binding == "config_value") {
            self.config_value_bindings += 1;
            if initializer.is_some_and(|initializer| {
                self.runtime_inputs_binding
                    .as_ref()
                    .is_some_and(|runtime_inputs| {
                        is_snapshot_config_value_closure(initializer, runtime_inputs)
                    })
            }) {
                self.canonical_config_value_bindings += 1;
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["RuntimeConfigSnapshot", "capture"]) {
            self.snapshot_calls += 1;
            if call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|arg| is_exact_path(arg, &["EnvConfigSource"]))
            {
                self.canonical_snapshot_calls += 1;
            }
        }
        if path_ends_with(&call.func, &["RuntimeInputs", "new"]) {
            self.runtime_inputs_calls += 1;
        }
        let canonical_reader = call.args.len() == 1
            && call
                .args
                .first()
                .is_some_and(|arg| is_exact_path(arg, &["config_value"]));
        match expr_path_last(&call.func)
            .map(ToString::to_string)
            .as_deref()
        {
            Some("build_vault_runtime_deps") => {
                self.vault_calls += 1;
                self.canonical_vault_calls += usize::from(canonical_reader);
            }
            Some("build_redis_runtime_deps") => {
                self.redis_calls += 1;
                self.canonical_redis_calls += usize::from(canonical_reader);
            }
            Some("build_s3_runtime_deps_from") => {
                self.s3_calls += 1;
                self.canonical_s3_calls += usize::from(canonical_reader);
            }
            _ => {}
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn runtime_config_snapshot_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() && !root.join(RUNTIME_CONFIG_FIXTURE_MARKER).exists() {
        return Ok(Vec::new());
    }
    let path = root.join(RUNTIME_LIB_PATH);
    let source =
        fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let file = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => {
            return Ok(vec![finding(
                Rule::ForbiddenWiring,
                RUNTIME_LIB_PATH,
                format!("runtime configuration snapshot gate 无法解析生产 Rust: {error}"),
            )]);
        }
    };
    Ok(runtime_config_snapshot_findings_for_file(&file))
}

fn runtime_config_snapshot_findings_for_file(file: &syn::File) -> Vec<Finding<Rule>> {
    let runs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "run" && item.sig.asyncness.is_some() => {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if runs.len() != 1 {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "runtime configuration snapshot gate requires exactly one async run()",
        )];
    }
    let mut wiring = RuntimeConfigWiring::default();
    wiring.visit_block(&runs[0].block);
    if wiring.is_canonical() {
        Vec::new()
    } else {
        vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "run() configuration snapshot funnel must bind one EnvConfigSource capture into one RuntimeInputs value, define one config_value closure backed by that input's config().get(), and call Vault/Redis/S3 exactly once with that reader",
        )]
    }
}

fn runtime_secret_transfer_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let require_complete = root.join("Cargo.toml").exists();
    if !require_complete && !root.join(RUNTIME_CONFIG_FIXTURE_MARKER).exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let mut sources = BTreeMap::new();
    for path in paths {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        sources.insert(
            relative,
            mask_comments_and_strings(&fs::read_to_string(path)?),
        );
    }
    let observed = sources
        .values()
        .map(|source| source.matches(SECRET_TRANSFER_TOKEN).count())
        .sum::<usize>();
    let mut allowed = 0;
    let mut findings = Vec::new();
    for (path, pattern) in SECRET_TRANSFER_ALLOWLIST {
        let count = sources
            .get(*path)
            .map_or(0, |source| source.matches(pattern).count());
        allowed += count;
        if count > 1 || (require_complete && count != 1) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                *path,
                format!("secret transfer allowlist requires exactly one `{pattern}`"),
            ));
        }
    }
    if observed != allowed {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_SRC_PATH,
            "secret transfer allowlist rejects an unregistered raw allocation handoff",
        ));
    }
    Ok(findings)
}

fn path_ends_with(expr: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expr else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() >= expected.len()
        && path
            .path
            .segments
            .iter()
            .rev()
            .zip(expected.iter().rev())
            .all(|(segment, expected)| segment.ident == *expected)
}

fn transparent_expr(mut expr: &syn::Expr) -> &syn::Expr {
    loop {
        match expr {
            syn::Expr::Block(block) if block.block.stmts.len() == 1 => {
                let syn::Stmt::Expr(inner, None) = &block.block.stmts[0] else {
                    return expr;
                };
                expr = inner;
            }
            syn::Expr::Group(group) => expr = &group.expr,
            syn::Expr::Paren(paren) => expr = &paren.expr,
            _ => return expr,
        }
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat) if pat.by_ref.is_none() => Some(&pat.ident),
        syn::Pat::Type(pat) => pat_ident(&pat.pat),
        _ => None,
    }
}

fn call_behind_result_context(expr: &syn::Expr) -> Option<&syn::ExprCall> {
    match transparent_expr(expr) {
        syn::Expr::Call(call) => Some(call),
        syn::Expr::Try(expr) => call_behind_result_context(&expr.expr),
        syn::Expr::MethodCall(call)
            if matches!(call.method.to_string().as_str(), "context" | "with_context") =>
        {
            call_behind_result_context(&call.receiver)
        }
        _ => None,
    }
}

fn is_env_snapshot_initializer(expr: &syn::Expr) -> bool {
    call_behind_result_context(expr).is_some_and(|call| {
        path_ends_with(&call.func, &["RuntimeConfigSnapshot", "capture"])
            && call.args.len() == 1
            && call
                .args
                .first()
                .is_some_and(|arg| is_exact_path(arg, &["EnvConfigSource"]))
    })
}

fn is_exact_ident_path(expr: &syn::Expr, expected: &syn::Ident) -> bool {
    let syn::Expr::Path(path) = transparent_expr(expr) else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == *expected)
}

fn is_runtime_inputs_initializer(expr: &syn::Expr, snapshot_binding: Option<&syn::Ident>) -> bool {
    let Some(snapshot_binding) = snapshot_binding else {
        return false;
    };
    call_behind_result_context(expr).is_some_and(|call| {
        path_ends_with(&call.func, &["RuntimeInputs", "new"])
            && call.args.len() == 2
            && call
                .args
                .first()
                .is_some_and(|arg| is_exact_ident_path(arg, snapshot_binding))
    })
}

fn is_snapshot_config_value_closure(expr: &syn::Expr, runtime_inputs_binding: &syn::Ident) -> bool {
    let syn::Expr::Closure(outer) = transparent_expr(expr) else {
        return false;
    };
    let Some(name) = outer.inputs.first().and_then(pat_ident) else {
        return false;
    };
    if outer.inputs.len() != 1 {
        return false;
    }
    let syn::Expr::MethodCall(map) = transparent_expr(&outer.body) else {
        return false;
    };
    let syn::Expr::MethodCall(get) = transparent_expr(&map.receiver) else {
        return false;
    };
    let syn::Expr::MethodCall(config) = transparent_expr(&get.receiver) else {
        return false;
    };
    let Some(syn::Expr::Closure(expose_closure)) = map.args.first().map(transparent_expr) else {
        return false;
    };
    let Some(value) = expose_closure.inputs.first().and_then(pat_ident) else {
        return false;
    };
    let syn::Expr::MethodCall(to_owned) = transparent_expr(&expose_closure.body) else {
        return false;
    };
    let syn::Expr::MethodCall(expose) = transparent_expr(&to_owned.receiver) else {
        return false;
    };

    map.method == "map"
        && map.args.len() == 1
        && get.method == "get"
        && get.args.len() == 1
        && get
            .args
            .first()
            .is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == name))
        && config.method == "config"
        && config.args.is_empty()
        && is_exact_ident_path(&config.receiver, runtime_inputs_binding)
        && expose_closure.inputs.len() == 1
        && to_owned.method == "to_owned"
        && to_owned.args.is_empty()
        && expose.method == "expose"
        && expose.args.is_empty()
        && expr_path_last(&expose.receiver).is_some_and(|ident| ident == value)
}

fn generated_domains_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let path = root.join(RUNTIME_LIB_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let run =
        extract_braced_body_at(&text, 0, "pub async fn run(").unwrap_or_else(|| empty_scope(&text));
    let masked_run = mask_comments_and_strings(run.body);
    let mut findings = Vec::new();
    for forbidden in [
        "wire_audit",
        "wire_identity",
        "wire_settings",
        "bootstrap::compose(&[",
        "domains::audit::module",
        "domains::identity::module",
        "domains::settings::module",
        "let mut domain_bindings = vec!",
        "DomainBinding::new",
    ] {
        if masked_run.contains(forbidden) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_LIB_PATH,
                format!("run() 禁止恢复手写 domain wiring: `{forbidden}`"),
            ));
        }
    }
    if masked_run
        .matches("modules_gen::wire_domains(&deps)")
        .count()
        != 1
        || !masked_run.contains("let mut domain_bindings = modules_gen::wire_domains(&deps)")
        || masked_run
            .matches("bootstrap::compose_bindings(&mut domain_bindings)")
            .count()
            != 1
    {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_LIB_PATH,
            "run() 必须将唯一 generated domain 结果直接交给 compose_bindings",
        ));
    }
    let assembly = extract_braced_body_at(&text, 0, "fn assemble_runtime_module_outputs(")
        .unwrap_or_else(|| empty_scope(&text));
    let masked_assembly = mask_comments_and_strings(assembly.body);
    if !masked_assembly.contains("module.merge(inputs.domains_module)") {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_LIB_PATH,
            "generated domains output 未进入 RuntimeModuleAssemblyInputs merge 路径",
        ));
    }
    let masked_file = mask_comments_and_strings(&text);
    for forbidden_export in [
        "pub use domains::audit::wire_audit",
        "pub use domains::identity::{wire_identity",
        "pub use domains::settings::{CONFIGS_READY_PROBE_NAME, ConfigsReadyProbe, wire_settings",
    ] {
        if masked_file.contains(forbidden_export) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_LIB_PATH,
                format!("生产 runtime root 禁止重新导出 legacy wiring: `{forbidden_export}`"),
            ));
        }
    }
    let mut runtime_sources = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut runtime_sources)?;
    let production_sources = production_module_sources(&runtime_sources)?;
    for source_path in runtime_sources {
        if !production_sources.contains(&normalize_path(&source_path)) {
            continue;
        }
        let relative = source_path.strip_prefix(root).unwrap_or(&source_path);
        if relative == Path::new(GENERATED_MODULES_PATH) {
            continue;
        }
        let source = fs::read_to_string(&source_path)
            .with_context(|| format!("读 {} 失败", source_path.display()))?;
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(_) => {
                // Baseline fixtures intentionally contain isolated, non-compiling anchor
                // fragments. Keep a narrow canonical-path fallback for those fixtures; real
                // workspace syntax is independently compile-gated before verify.
                let masked = mask_comments_and_strings(&source);
                if [
                    "crate::domains::settings::module",
                    "crate::domains::identity::module",
                    "crate::domains::audit::module",
                ]
                .iter()
                .any(|factory| masked.contains(factory))
                {
                    findings.push(finding(
                        Rule::ForbiddenWiring,
                        relative.display().to_string(),
                        "generated artifact 外禁止引用 canonical domain module factory".to_string(),
                    ));
                }
                continue;
            }
        };
        if let Some(factory) =
            forbidden_domain_factory_usage(&file, relative == Path::new(RUNTIME_LIB_PATH))
        {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative.display().to_string(),
                format!("generated artifact 外禁止引用 domain module factory: `{factory}`"),
            ));
        }
    }
    Ok(findings)
}

fn production_module_sources(sources: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    let source_set = sources
        .iter()
        .map(|source| normalize_path(source))
        .collect::<BTreeSet<_>>();
    let mut edges: BTreeMap<PathBuf, Vec<(PathBuf, bool)>> = BTreeMap::new();
    let mut referenced = BTreeSet::new();
    for source in sources {
        let text =
            fs::read_to_string(source).with_context(|| format!("读 {} 失败", source.display()))?;
        let Ok(file) = syn::parse_file(&text) else {
            continue;
        };
        let source = normalize_path(source);
        let base = module_base(&source);
        collect_module_edges(
            &file.items,
            &source,
            &base,
            true,
            &source_set,
            &mut edges,
            &mut referenced,
        );
    }
    let mut production = source_set
        .iter()
        .filter(|source| {
            matches!(
                source.file_stem().and_then(|stem| stem.to_str()),
                Some("lib" | "main")
            ) || !referenced.contains(*source)
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut queue = production.iter().cloned().collect::<VecDeque<_>>();
    while let Some(source) = queue.pop_front() {
        for (target, child_is_production) in edges.get(&source).into_iter().flatten() {
            if *child_is_production && production.insert(target.clone()) {
                queue.push_back(target.clone());
            }
        }
    }
    Ok(production)
}

#[allow(clippy::too_many_arguments)]
fn collect_module_edges(
    items: &[syn::Item],
    source: &Path,
    base: &Path,
    parent_is_production: bool,
    sources: &BTreeSet<PathBuf>,
    edges: &mut BTreeMap<PathBuf, Vec<(PathBuf, bool)>>,
    referenced: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let module_is_production = parent_is_production && attrs_may_be_production(&module.attrs);
        if let Some((_, nested)) = &module.content {
            collect_module_edges(
                nested,
                source,
                &base.join(module.ident.to_string()),
                module_is_production,
                sources,
                edges,
                referenced,
            );
            continue;
        }
        for candidate in out_of_line_module_candidates(base, module) {
            let candidate = normalize_path(&candidate);
            if !sources.contains(&candidate) {
                continue;
            }
            referenced.insert(candidate.clone());
            edges
                .entry(source.to_path_buf())
                .or_default()
                .push((candidate, module_is_production));
        }
    }
}

fn module_base(source: &Path) -> PathBuf {
    let parent = source.parent().unwrap_or_else(|| Path::new(""));
    match source.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") => parent.to_path_buf(),
        Some(stem) => parent.join(stem),
        None => parent.to_path_buf(),
    }
}

fn out_of_line_module_candidates(base: &Path, module: &syn::ItemMod) -> Vec<PathBuf> {
    if let Some(path) = module.attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(meta) = &attr.meta else {
            return None;
        };
        let syn::Expr::Lit(expr) = &meta.value else {
            return None;
        };
        let syn::Lit::Str(path) = &expr.lit else {
            return None;
        };
        Some(path.value())
    }) {
        return vec![base.join(path)];
    }
    let name = module.ident.to_string();
    vec![
        base.join(format!("{name}.rs")),
        base.join(name).join("mod.rs"),
    ]
}

fn event_transport_output_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }
    let event = parse_rust_file(&root.join("assemblies/runtime/src/event_transport.rs"))?;
    let runtime = parse_rust_file(&root.join(RUNTIME_LIB_PATH))?;
    let launch = parse_rust_file(&root.join(RUNTIME_LAUNCH_PATH))?;
    let mut findings = Vec::new();

    let wire = event
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "wire_event_transport" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let canonical_signature = wire.len() == 1
        && matches!(&wire[0].vis, syn::Visibility::Restricted(vis) if vis.path.is_ident("crate"))
        && wire[0].sig.asyncness.is_some()
        && matches!(&wire[0].sig.output, syn::ReturnType::Type(_, ty)
            if compact_tokens(ty.as_ref()) == "anyhow::Result<DomainModuleResult>");
    let legacy_type = event.items.iter().any(|item| match item {
        syn::Item::Struct(item) => item.ident == "EventRuntime",
        syn::Item::Enum(item) => item.ident == "EventRuntime",
        syn::Item::Type(item) => item.ident == "EventRuntime",
        _ => false,
    });
    if !canonical_signature || legacy_type || !has_only_canonical_amqp_runtime_resources(&event) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            "assemblies/runtime/src/event_transport.rs",
            "event transport 必须以 crate-private async fn 直接返回 DomainModuleResult，AMQP resources 只能在 durable 连接循环进入 module.resources",
        ));
    }

    let run = runtime.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "run" => Some(item),
        _ => None,
    });
    let wire_blocks = run.map(wire_domains_blocks).unwrap_or_default();
    let event_binding = wire_blocks
        .first()
        .and_then(|block| event_module_binding(block));
    let canonical_run = wire_blocks.len() == 1
        && wire_blocks.first().is_some_and(|block| {
            event_binding.as_ref().is_some_and(|binding| {
                exact_named_path_call_count(block, &["event_transport", "wire_event_transport"])
                    == 1
                    && runtime_module_field_use_count(block, "event_module", binding) == 1
                    && binding_field_projection_count(block, binding) == 0
            })
        });
    let assembly = runtime.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "assemble_runtime_module_outputs" => Some(item),
        _ => None,
    });
    if !canonical_run
        || assembly.is_none_or(|item| {
            direct_assembly_field_merges(&item.block, "event_module") != 1
                || assembly_input_field_use_count(&item.block, "event_module") != 1
        })
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "run() 必须恰好一次把 wire_event_transport 的 owned output 直接交给 event_module merge，不得投影或平行拆包",
        ));
    }

    if compact_tokens(&launch).contains("event_infra_guards")
        || !has_canonical_pg_runtime_registration(&launch)
        || !launch_plan_fields_are_closed(&launch)
        || !launch_lifecycle_calls_are_canonical(&launch)
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_LAUNCH_PATH,
            "LaunchPlan 必须按 PG module → domain module 两批调用公共 register_module_output，禁止 event 专用字段或生命周期旁路",
        ));
    }
    Ok(findings)
}

fn parse_rust_file(path: &Path) -> Result<syn::File> {
    let source = fs::read_to_string(path).with_context(|| format!("读 {} 失败", path.display()))?;
    syn::parse_file(&source).with_context(|| format!("解析 {} 失败", path.display()))
}

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

fn event_module_binding(block: &syn::Block) -> Option<String> {
    let bindings = block
        .stmts
        .iter()
        .filter_map(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return None;
            };
            let syn::Pat::Ident(binding) = &local.pat else {
                return None;
            };
            let init = local.init.as_ref()?;
            (binding.mutability.is_none()
                && init.diverge.is_none()
                && is_direct_event_transport_binding(&init.expr))
            .then(|| binding.ident.to_string())
        })
        .collect::<Vec<_>>();
    (bindings.len() == 1).then(|| bindings[0].clone())
}

fn is_direct_event_transport_binding(expr: &syn::Expr) -> bool {
    let syn::Expr::Try(try_) = expr else {
        return false;
    };
    let syn::Expr::MethodCall(context) = try_.expr.as_ref() else {
        return false;
    };
    if context.method != "context" || context.args.len() != 1 {
        return false;
    }
    let syn::Expr::Await(await_) = context.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::Call(call) = await_.base.as_ref() else {
        return false;
    };
    is_exact_path(&call.func, &["event_transport", "wire_event_transport"])
}

fn runtime_module_field_use_count(block: &syn::Block, field_name: &str, binding: &str) -> usize {
    struct Counter<'a> {
        field_name: &'a str,
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            if item
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "RuntimeModuleAssemblyInputs")
            {
                self.count += item
                    .fields
                    .iter()
                    .filter(|field| {
                        matches!(&field.member, syn::Member::Named(member) if member == self.field_name)
                            && expr_path_last(&field.expr)
                                .is_some_and(|ident| ident == self.binding)
                    })
                    .count();
            }
            syn::visit::visit_expr_struct(self, item);
        }
    }
    let mut counter = Counter {
        field_name,
        binding,
        count: 0,
    };
    counter.visit_block(block);
    counter.count
}

fn binding_field_projection_count(block: &syn::Block, binding: &str) -> usize {
    struct Counter<'a> {
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if expr_path_last(&field.base).is_some_and(|ident| ident == self.binding) {
                self.count += 1;
            }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut counter = Counter { binding, count: 0 };
    counter.visit_block(block);
    counter.count
}

fn direct_assembly_field_merges(block: &syn::Block, field_name: &str) -> usize {
    block
        .stmts
        .iter()
        .filter(|stmt| {
            let syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)) = stmt else {
                return false;
            };
            call.method == "merge"
                && expr_path_last(&call.receiver).is_some_and(|ident| ident == "module")
                && call.args.first().is_some_and(|arg| {
                    matches!(arg, syn::Expr::Field(field)
                        if expr_path_last(&field.base).is_some_and(|ident| ident == "inputs")
                            && matches!(&field.member, syn::Member::Named(member) if member == field_name))
                })
        })
        .count()
}

fn assembly_input_field_use_count(block: &syn::Block, field_name: &str) -> usize {
    struct Counter<'a> {
        field_name: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if expr_path_last(&field.base).is_some_and(|ident| ident == "inputs")
                && matches!(&field.member, syn::Member::Named(member) if member == self.field_name)
            {
                self.count += 1;
            }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut counter = Counter {
        field_name,
        count: 0,
    };
    counter.visit_block(block);
    counter.count
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn provider_outputs_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() && !root.join(PROVIDER_OUTPUT_FIXTURE_MARKER).exists() {
        // 通用 runtime-baseline fixture 只承载文本 anchor；专属 provider fixture 用显式 marker
        // 启用 AST 门。真实 workspace 总有根 Cargo.toml，不能借此跳过 fail-closed 检查。
        return Ok(Vec::new());
    }
    if !root.join(PROVIDER_OUTPUT_PATH).exists() {
        return Ok(vec![finding(
            Rule::MissingAnchor,
            PROVIDER_OUTPUT_PATH,
            "缺 runtime-local provider output 唯一适配层",
        )]);
    }
    let path = root.join(RUNTIME_LIB_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let mut findings = Vec::new();
    let file = match syn::parse_file(&text) {
        Ok(file) => file,
        Err(error) => {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_LIB_PATH,
                format!("runtime provider gate 无法解析生产 Rust: {error}"),
            ));
            return Ok(findings);
        }
    };
    let run = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "run" && item.sig.asyncness.is_some() => {
            Some(item)
        }
        _ => None,
    });
    if run.is_none_or(|run| !has_canonical_pg_runtime_build(run))
        || exact_path_call_count_in_file(
            &file,
            &["crate", "provider_output", "build_pg_runtime_module"],
        ) != 1
    {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_LIB_PATH,
            "run() 必须恰好一次按值消费 PG owner 构造 DomainModuleResult，并恰好一次交给 LaunchPlanParts",
        ));
    }
    let wire_blocks = run.map(wire_domains_blocks).unwrap_or_default();
    if wire_blocks.len() != 1 {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_LIB_PATH,
            "run() 必须恰好包含一个 RuntimePhase::WireDomains async block",
        ));
    } else if let Some(block) = wire_blocks.first() {
        if direct_provider_constructors(block) != 1
            || direct_provider_declarations(block) != 1
            || exact_named_path_call_count(
                block,
                &["crate", "provider_output", "build_provider_module"],
            ) != 1
            || provider_module_path_uses(block) != 1
        {
            findings.push(finding(
                Rule::MissingAnchor,
                RUNTIME_LIB_PATH,
                "WireDomains 必须恰好一次不可变声明 `let provider_module = crate::provider_output::build_provider_module(&deps)` 并且只消费一次",
            ));
        }
        if direct_provider_registrations(block) != 1
            || exact_named_path_call_count(block, &["crate", "assemble_runtime_module_outputs"])
                != 1
        {
            findings.push(finding(
                Rule::MissingAnchor,
                RUNTIME_LIB_PATH,
                "provider_module 必须恰好一次进入 RuntimeModuleAssemblyInputs",
            ));
        }
    }

    let assembly = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "assemble_runtime_module_outputs" => Some(item),
        _ => None,
    });
    if assembly.is_none_or(|item| direct_assembly_provider_merges(&item.block) != 1) {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_LIB_PATH,
            "assemble_runtime_module_outputs() 必须直接且恰好一次 merge inputs.provider_module",
        ));
    }

    let mut runtime_sources = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut runtime_sources)?;
    let production_sources = production_module_sources(&runtime_sources)?;
    for source_path in runtime_sources {
        if !production_sources.contains(&normalize_path(&source_path)) {
            continue;
        }
        let relative = source_path.strip_prefix(root).unwrap_or(&source_path);
        let source = fs::read_to_string(&source_path)
            .with_context(|| format!("读 {} 失败", source_path.display()))?;
        let Ok(source_file) = syn::parse_file(&source) else {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative.display().to_string(),
                "runtime provider gate 无法解析生产 Rust",
            ));
            continue;
        };
        if relative == Path::new(PROVIDER_OUTPUT_PATH) {
            if !has_only_canonical_provider_output_calls(&source_file) {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    PROVIDER_OUTPUT_PATH,
                    "provider_output.rs 必须保留 Redis/S3/Vault 三个 ProviderOutput impl，并将 owned PG lifecycle 转换为 DomainModuleResult",
                ));
            }
            continue;
        }
        let is_event_transport = relative == Path::new("assemblies/runtime/src/event_transport.rs");
        let provider_calls = provider_primitive_calls(&source_file, is_event_transport);
        let runtime_resources_allowed = if is_event_transport {
            !provider_calls.forbidden
                && provider_calls.amqp_runtime_resources == 1
                && has_only_canonical_amqp_runtime_resources(&source_file)
        } else {
            !provider_calls.forbidden && provider_calls.amqp_runtime_resources == 0
        };
        let pg_lifecycle = pg_lifecycle_calls(&source_file);
        let extra_pg_builder = relative != Path::new(RUNTIME_LIB_PATH)
            && exact_path_call_count_in_file(
                &source_file,
                &["crate", "provider_output", "build_pg_runtime_module"],
            ) != 0;
        let launch_is_canonical = relative != Path::new(RUNTIME_LAUNCH_PATH)
            || has_canonical_pg_runtime_registration(&source_file);
        if !runtime_resources_allowed
            || provider_output_impl_count(&source_file) != 0
            || pg_lifecycle.forbidden
            || extra_pg_builder
            || !launch_is_canonical
        {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative.display().to_string(),
                "provider primitive 只能经 canonical DomainModuleResult seam；PG module 必须在 LaunchPlan 中于 trace 后、domain module 前注册一次",
            ));
        }
    }
    Ok(findings)
}

fn has_only_canonical_provider_output_calls(file: &syn::File) -> bool {
    let mut all_calls = RuntimeResourcesCallCounter::default();
    all_calls.visit_file(file);
    if all_calls.calls != 3 {
        return false;
    }
    let constructors = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "build_provider_module" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if constructors.len() != 1 || !is_canonical_provider_constructor(constructors[0]) {
        return false;
    }
    let mut all_merges = MergeProviderCallCounter::default();
    all_merges.visit_file(file);
    if all_merges.calls != 3 {
        return false;
    }
    if provider_output_impl_count(file) != 3 {
        return false;
    }
    let pg_constructors = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "build_pg_runtime_module" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if pg_constructors.len() != 1 || !is_canonical_pg_runtime_constructor(pg_constructors[0]) {
        return false;
    }
    let mut pg_lifecycle = PgLifecycleCalls::default();
    pg_lifecycle.visit_file(file);
    if pg_lifecycle.into_runtime_parts != 1 || pg_lifecycle.forbidden {
        return false;
    }
    if file
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Struct(item) if item.ident == "PgRuntimeOutput"))
    {
        return false;
    }
    let traits = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Trait(item) if item.ident == "ProviderOutput" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if traits.len() != 1 || !is_canonical_provider_output_trait(traits[0]) {
        return false;
    }
    let mut providers = BTreeMap::new();
    for item in &file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let Some((_, trait_path, _)) = &item.trait_ else {
            continue;
        };
        if trait_path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "ProviderOutput")
        {
            continue;
        }
        let Some(provider) = type_last_ident(&item.self_ty).map(ToString::to_string) else {
            return false;
        };
        if !matches!(
            provider.as_str(),
            "RedisRuntimeDeps" | "S3RuntimeDeps" | "VaultRuntimeDeps"
        ) {
            return false;
        }
        let canonical = item.items.len() == 2
            && item.items.iter().any(|impl_item| {
                matches!(impl_item, syn::ImplItem::Const(binding)
                    if is_canonical_provider_output_binding_impl(binding))
            })
            && item.items.iter().any(|impl_item| {
                matches!(impl_item, syn::ImplItem::Fn(method)
                    if is_canonical_provider_output_method(method))
            });
        if providers.insert(provider, canonical).is_some() {
            return false;
        }
    }
    providers
        == BTreeMap::from([
            ("RedisRuntimeDeps".to_string(), true),
            ("S3RuntimeDeps".to_string(), true),
            ("VaultRuntimeDeps".to_string(), true),
        ])
}

fn provider_output_impl_count(file: &syn::File) -> usize {
    #[derive(Default)]
    struct Counter(usize);
    impl<'ast> Visit<'ast> for Counter {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if !attrs_may_be_production(&item.attrs) {
                return;
            }
            if item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "ProviderOutput")
            }) {
                self.0 += 1;
            }
            syn::visit::visit_item_impl(self, item);
        }
    }
    let mut counter = Counter::default();
    counter.visit_file(file);
    counter.0
}

fn is_canonical_provider_output_trait(item: &syn::ItemTrait) -> bool {
    item.items.len() == 2
        && item.items.iter().any(|trait_item| {
            matches!(trait_item, syn::TraitItem::Const(binding)
                if binding.ident == "OUTPUT_BINDINGS"
                    && compact_tokens(&binding.ty) == "&'static[ProviderOutputBinding]"
                    && binding.default.is_none())
        })
        && item.items.iter().any(|trait_item| {
            matches!(trait_item, syn::TraitItem::Fn(method)
                if method.sig.ident == "provider_output"
                    && method.sig.inputs.len() == 1
                    && matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
                        if receiver.reference.is_some() && receiver.mutability.is_none())
                    && return_type_is(&method.sig.output, "DomainModuleResult")
                    && method.default.is_none())
        })
}

fn is_canonical_provider_output_binding_impl(binding: &syn::ImplItemConst) -> bool {
    if binding.ident != "OUTPUT_BINDINGS"
        || compact_tokens(&binding.ty) != "&'static[ProviderOutputBinding]"
    {
        return false;
    }
    matches!(&binding.expr, syn::Expr::Reference(reference)
        if matches!(reference.expr.as_ref(), syn::Expr::Array(array) if !array.elems.is_empty()))
}

fn is_canonical_provider_output_method(method: &syn::ImplItemFn) -> bool {
    if method.sig.ident != "provider_output"
        || method.sig.inputs.len() != 1
        || !matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_some() && receiver.mutability.is_none())
        || !return_type_is(&method.sig.output, "DomainModuleResult")
        || method.block.stmts.len() != 1
    {
        return false;
    }
    let syn::Stmt::Expr(syn::Expr::Struct(output), None) = &method.block.stmts[0] else {
        return false;
    };
    if path_last_ident(&output.path).is_none_or(|ident| ident != "DomainModuleResult") {
        return false;
    }
    let resource_fields = output
        .fields
        .iter()
        .filter(|field| matches!(&field.member, syn::Member::Named(name) if name == "resources"))
        .collect::<Vec<_>>();
    if resource_fields.len() != 1
        || !matches!(&resource_fields[0].expr, syn::Expr::MethodCall(call)
            if call.method == "runtime_resources"
                && call.args.is_empty()
                && expr_path_last(&call.receiver).is_some_and(|name| name == "self"))
        || output.fields.iter().any(|field| {
            !matches!(&field.member, syn::Member::Named(name)
                if matches!(name.to_string().as_str(), "probes" | "resources" | "workers"))
        })
    {
        return false;
    }
    output.rest.is_none()
        || matches!(&output.rest, Some(rest)
        if matches!(rest.as_ref(), syn::Expr::Call(call)
            if call.args.is_empty() && is_exact_path(&call.func, &["DomainModuleResult", "default"])))
}

fn return_type_is(output: &syn::ReturnType, expected: &str) -> bool {
    match output {
        syn::ReturnType::Type(_, ty) => type_last_ident(ty).is_some_and(|ident| ident == expected),
        syn::ReturnType::Default => false,
    }
}

fn owned_input_ident(input: &syn::FnArg, ty: &str) -> Option<String> {
    let syn::FnArg::Typed(input) = input else {
        return None;
    };
    let syn::Pat::Ident(pat) = input.pat.as_ref() else {
        return None;
    };
    let syn::Type::Path(path) = input.ty.as_ref() else {
        return None;
    };
    if pat.mutability.is_some()
        || pat.by_ref.is_some()
        || path.qself.is_some()
        || path
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != ty)
    {
        return None;
    }
    Some(pat.ident.to_string())
}

#[derive(Default)]
struct PgLifecycleCalls {
    into_runtime_parts: usize,
    factory_spawn: usize,
    forbidden: bool,
}

impl<'ast> Visit<'ast> for PgLifecycleCalls {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        match call.method.to_string().as_str() {
            "into_runtime_parts" => self.into_runtime_parts += 1,
            "spawn"
                if expr_path_last(&call.receiver)
                    .is_some_and(|ident| ident == "sampler_factory") =>
            {
                self.factory_spawn += 1;
            }
            "store_guard" | "audit_admin_store_guard" | "spawn_readiness_sampler" => {
                self.forbidden = true;
            }
            "setup_maintenance"
            | "setup_maintenance_with_audit_admin_config"
            | "run_migrations" => self.forbidden = true,
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(method) = expr_path_last(&call.func).map(ToString::to_string) {
            match method.as_str() {
                "into_runtime_parts" => self.into_runtime_parts += 1,
                "spawn_readiness_sampler" | "store_guard" | "audit_admin_store_guard" => {
                    self.forbidden = true;
                }
                "setup_maintenance"
                | "setup_maintenance_with_audit_admin_config"
                | "run_migrations" => self.forbidden = true,
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn pg_lifecycle_calls(file: &syn::File) -> PgLifecycleCalls {
    let mut calls = PgLifecycleCalls::default();
    calls.visit_file(file);
    if calls.into_runtime_parts != 0 || calls.factory_spawn != 0 {
        calls.forbidden = true;
    }
    calls
}

#[cfg(test)]
#[test]
fn pg_lifecycle_guard_rejects_migrating_maintenance_bypass() {
    let bypass = syn::parse_file(
        "fn bypass() { PgRuntimeDeps::setup_maintenance(); owner.run_migrations(); }",
    )
    .unwrap_or_else(|_| unreachable!());
    assert!(pg_lifecycle_calls(&bypass).forbidden);

    let connect_only =
        syn::parse_file("fn maintenance() { PgRuntimeDeps::connect_maintenance(); }")
            .unwrap_or_else(|_| unreachable!());
    assert!(!pg_lifecycle_calls(&connect_only).forbidden);
}

fn is_canonical_pg_runtime_constructor(item: &syn::ItemFn) -> bool {
    if item.sig.inputs.len() != 2 || !return_type_is(&item.sig.output, "DomainModuleResult") {
        return false;
    }
    let Some(owner) = owned_input_ident(&item.sig.inputs[0], "PgRuntimeDeps") else {
        return false;
    };
    let Some(period) = owned_input_ident(&item.sig.inputs[1], "Duration") else {
        return false;
    };
    let Some((resources, factory)) = pg_runtime_parts_binding(item, &owner, &period) else {
        return false;
    };
    let Some(worker) = pg_worker_binding(item, &factory) else {
        return false;
    };
    pg_returned_module_uses(item, &resources, &worker)
}

fn pg_runtime_parts_binding(
    item: &syn::ItemFn,
    owner: &str,
    period: &str,
) -> Option<(String, String)> {
    let bindings =
        item.block
            .stmts
            .iter()
            .filter_map(|stmt| {
                let syn::Stmt::Local(local) = stmt else {
                    return None;
                };
                let syn::Pat::Tuple(tuple) = &local.pat else {
                    return None;
                };
                let mut bindings = tuple.elems.iter();
                let (Some(syn::Pat::Ident(resources)), Some(syn::Pat::Ident(factory)), None) =
                    (bindings.next(), bindings.next(), bindings.next())
                else {
                    return None;
                };
                let init = local.init.as_ref()?;
                let syn::Expr::MethodCall(call) = init.expr.as_ref() else {
                    return None;
                };
                (resources.by_ref.is_none()
                    && resources.mutability.is_none()
                    && factory.by_ref.is_none()
                    && factory.mutability.is_none()
                    && init.diverge.is_none()
                    && call.method == "into_runtime_parts"
                    && expr_path_last(&call.receiver).is_some_and(|ident| ident == owner)
                    && call.args.len() == 1
                    && call.args.first().is_some_and(|arg| {
                        expr_path_last(arg).is_some_and(|ident| ident == period)
                    }))
                .then(|| (resources.ident.to_string(), factory.ident.to_string()))
            })
            .collect::<Vec<_>>();
    (bindings.len() == 1).then(|| bindings[0].clone())
}

fn pg_worker_binding(item: &syn::ItemFn, factory: &str) -> Option<String> {
    let bindings = item
        .block
        .stmts
        .iter()
        .filter_map(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return None;
            };
            let (pat, typed_as_worker) = match &local.pat {
                syn::Pat::Ident(pat) => (pat, true),
                syn::Pat::Type(typed) => {
                    let syn::Pat::Ident(pat) = typed.pat.as_ref() else {
                        return None;
                    };
                    (
                        pat,
                        type_last_ident(&typed.ty).is_some_and(|ident| ident == "WorkerSpec"),
                    )
                }
                _ => return None,
            };
            let init = local.init.as_ref()?;
            (typed_as_worker
                && pat.by_ref.is_none()
                && pat.mutability.is_none()
                && worker_expr_consumes_factory(&init.expr, factory))
            .then(|| pat.ident.to_string())
        })
        .collect::<Vec<_>>();
    (bindings.len() == 1).then(|| bindings[0].clone())
}

fn worker_expr_consumes_factory(expr: &syn::Expr, factory: &str) -> bool {
    let Some(closure) = returned_worker_closure(expr) else {
        return false;
    };
    let Some(syn::Pat::Ident(token)) = closure.inputs.first() else {
        return false;
    };
    closure.capture.is_some()
        && closure.inputs.len() == 1
        && returned_resource_spawn(&closure.body, factory, &token.ident.to_string())
}

fn returned_worker_closure(expr: &syn::Expr) -> Option<&syn::ExprClosure> {
    match expr {
        syn::Expr::Closure(closure) => Some(closure),
        syn::Expr::Call(call) if call.args.len() == 1 => {
            returned_worker_closure(call.args.first()?)
        }
        syn::Expr::Block(block) => block.block.stmts.last().and_then(|stmt| match stmt {
            syn::Stmt::Expr(expr, _) => returned_worker_closure(expr),
            _ => None,
        }),
        syn::Expr::Group(group) => returned_worker_closure(&group.expr),
        syn::Expr::Paren(paren) => returned_worker_closure(&paren.expr),
        syn::Expr::Try(expr) => returned_worker_closure(&expr.expr),
        _ => None,
    }
}

fn returned_resource_spawn(expr: &syn::Expr, factory: &str, token: &str) -> bool {
    match expr {
        syn::Expr::Call(call)
            if is_exact_path(&call.func, &["DynManagedResource", "new_box"])
                && call.args.len() == 1 =>
        {
            call.args
                .first()
                .is_some_and(|arg| returned_factory_spawn(arg, factory, token))
        }
        syn::Expr::Call(call) if call.args.len() == 1 => {
            call.args
                .first()
                .is_some_and(|arg| returned_resource_spawn(arg, factory, token))
        }
        syn::Expr::Block(block) => block.block.stmts.last().is_some_and(|stmt| {
            matches!(stmt, syn::Stmt::Expr(expr, _) if returned_resource_spawn(expr, factory, token))
        }),
        syn::Expr::Group(group) => returned_resource_spawn(&group.expr, factory, token),
        syn::Expr::Paren(paren) => returned_resource_spawn(&paren.expr, factory, token),
        syn::Expr::Try(expr) => returned_resource_spawn(&expr.expr, factory, token),
        _ => false,
    }
}

fn returned_factory_spawn(expr: &syn::Expr, factory: &str, token: &str) -> bool {
    match expr {
        syn::Expr::MethodCall(call) => {
            call.method == "spawn"
                && expr_path_last(&call.receiver).is_some_and(|ident| ident == factory)
                && call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == token))
        }
        syn::Expr::Call(call) if call.args.len() == 1 => call
            .args
            .first()
            .is_some_and(|arg| returned_factory_spawn(arg, factory, token)),
        syn::Expr::Group(group) => returned_factory_spawn(&group.expr, factory, token),
        syn::Expr::Paren(paren) => returned_factory_spawn(&paren.expr, factory, token),
        syn::Expr::Try(expr) => returned_factory_spawn(&expr.expr, factory, token),
        _ => false,
    }
}

fn pg_returned_module_uses(item: &syn::ItemFn, resources: &str, worker: &str) -> bool {
    let Some(syn::Stmt::Expr(returned, None)) = item.block.stmts.last() else {
        return false;
    };
    struct OutputFlow<'a> {
        resources: &'a str,
        worker: &'a str,
        outputs: usize,
        valid: usize,
    }
    impl<'ast> Visit<'ast> for OutputFlow<'_> {
        fn visit_expr_struct(&mut self, output: &'ast syn::ExprStruct) {
            if path_last_ident(&output.path).is_some_and(|ident| ident == "DomainModuleResult") {
                self.outputs += 1;
                let resources = named_field_expr(output, "resources");
                let workers = named_field_expr(output, "workers");
                if resources.is_some_and(|expr| ident_use_count(expr, self.resources) == 1)
                    && workers.is_some_and(|expr| ident_use_count(expr, self.worker) == 1)
                {
                    self.valid += 1;
                }
            }
            syn::visit::visit_expr_struct(self, output);
        }
    }
    fn named_field_expr<'a>(output: &'a syn::ExprStruct, name: &str) -> Option<&'a syn::Expr> {
        output.fields.iter().find_map(|field| {
            matches!(&field.member, syn::Member::Named(member) if member == name)
                .then_some(&field.expr)
        })
    }
    fn ident_use_count(expr: &syn::Expr, expected: &str) -> usize {
        expr.to_token_stream()
            .to_string()
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .filter(|token| *token == expected)
            .count()
    }
    let mut flow = OutputFlow {
        resources,
        worker,
        outputs: 0,
        valid: 0,
    };
    flow.visit_expr(returned);
    flow.outputs == 1 && flow.valid == 1
}

fn has_canonical_pg_runtime_build(run: &syn::ItemFn) -> bool {
    let declarations = run
        .block
        .stmts
        .iter()
        .filter_map(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return None;
            };
            let syn::Pat::Ident(pat) = &local.pat else {
                return None;
            };
            let Some(init) = &local.init else {
                return None;
            };
            (pat.mutability.is_none()
                && init.diverge.is_none()
                && matches!(init.expr.as_ref(), syn::Expr::Call(call)
                    if is_exact_path(&call.func, &["crate", "provider_output", "build_pg_runtime_module"])
                        && call.args.len() == 2
                        && call.args.iter().all(|arg| matches!(arg, syn::Expr::Path(_)))))
            .then(|| pat.ident.to_string())
        })
        .collect::<Vec<_>>();
    declarations.len() == 1
        && exact_named_path_call_count(
            &run.block,
            &["crate", "provider_output", "build_pg_runtime_module"],
        ) == 1
        && launch_field_use_count(&run.block, "pg_runtime_module", &declarations[0]) == 1
}

fn launch_field_use_count(block: &syn::Block, field_name: &str, binding: &str) -> usize {
    struct Counter<'a> {
        field_name: &'a str,
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            if item
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "LaunchPlanParts")
            {
                self.count += item
                    .fields
                    .iter()
                    .filter(|field| {
                        matches!(&field.member, syn::Member::Named(member) if member == self.field_name)
                            && expr_path_last(&field.expr)
                                .is_some_and(|ident| ident == self.binding)
                    })
                    .count();
            }
            syn::visit::visit_expr_struct(self, item);
        }
    }
    let mut counter = Counter {
        field_name,
        binding,
        count: 0,
    };
    counter.visit_block(block);
    counter.count
}

fn has_canonical_pg_runtime_registration(file: &syn::File) -> bool {
    let methods = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            if type_last_ident(&item.self_ty).is_none_or(|ident| ident != "LaunchPlan") {
                return None;
            }
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "register" => Some(method),
                _ => None,
            })
        })
        .collect::<Vec<_>>();
    if methods.len() != 1 {
        return false;
    }
    let stmts = &methods[0].block.stmts;
    let Some(pg_binding) = launch_destructured_binding(stmts, "pg_runtime_module") else {
        return false;
    };
    let Some(domain_binding) = launch_destructured_binding(stmts, "domain_module") else {
        return false;
    };
    let trace = stmts.iter().position(is_trace_registration_stmt);
    let pg = stmts
        .iter()
        .position(|stmt| is_pg_runtime_registration_stmt(stmt, &pg_binding));
    let domain = stmts
        .iter()
        .position(|stmt| is_pg_runtime_registration_stmt(stmt, &domain_binding));
    matches!((trace, pg, domain), (Some(trace), Some(pg), Some(domain)) if trace < pg && pg < domain)
        && stmts
            .iter()
            .filter(|stmt| is_pg_runtime_registration_stmt(stmt, &pg_binding))
            .count()
            == 1
        && stmts
            .iter()
            .filter(|stmt| is_pg_runtime_registration_stmt(stmt, &domain_binding))
            .count()
            == 1
        && module_registration_call_count(file, &pg_binding) == 1
        && module_registration_call_count(file, &domain_binding) == 1
        && method_call_count_in_block(&methods[0].block, "register_detached") == 1
        && method_call_count_in_block(&methods[0].block, "register_with_token") == 0
}

fn launch_plan_fields_are_closed(file: &syn::File) -> bool {
    const ALLOWED_FIELDS: &[&str] = &[
        "listeners",
        "trace_exporter",
        "pg_runtime_module",
        "domain_module",
    ];
    let plans = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item)
                if item.ident == "LaunchPlanParts" || item.ident == "LaunchPlan" =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    plans.len() == 2
        && plans.iter().all(|plan| {
            plan.fields.iter().all(|field| {
                field
                    .ident
                    .as_ref()
                    .is_some_and(|ident| ALLOWED_FIELDS.contains(&ident.to_string().as_str()))
            })
        })
}

fn launch_lifecycle_calls_are_canonical(file: &syn::File) -> bool {
    fn has_lifecycle_calls(block: &syn::Block) -> bool {
        method_call_count_in_block(block, "register_detached") != 0
            || method_call_count_in_block(block, "register_with_token") != 0
    }

    for item in &file.items {
        match item {
            syn::Item::Fn(function) if attrs_may_be_production(&function.attrs) => {
                let detached = method_call_count_in_block(&function.block, "register_detached");
                let with_token = method_call_count_in_block(&function.block, "register_with_token");
                if function.sig.ident == "bind_and_register" {
                    if detached != 0 || with_token != 2 {
                        return false;
                    }
                } else if detached != 0 || with_token != 0 {
                    return false;
                }
            }
            syn::Item::Impl(item) if attrs_may_be_production(&item.attrs) => {
                let is_launch_plan =
                    type_last_ident(&item.self_ty).is_some_and(|ident| ident == "LaunchPlan");
                for method in item.items.iter().filter_map(|item| match item {
                    syn::ImplItem::Fn(method) if attrs_may_be_production(&method.attrs) => {
                        Some(method)
                    }
                    _ => None,
                }) {
                    let detached = method_call_count_in_block(&method.block, "register_detached");
                    let with_token =
                        method_call_count_in_block(&method.block, "register_with_token");
                    let canonical = is_launch_plan
                        && ((method.sig.ident == "register" && detached == 1 && with_token == 0)
                            || (method.sig.ident == "register_module_output"
                                && detached == 1
                                && with_token == 1));
                    if has_lifecycle_calls(&method.block) && !canonical {
                        return false;
                    }
                }
            }
            _ => {}
        }
    }
    true
}

fn method_call_count_in_block(block: &syn::Block, method: &str) -> usize {
    struct Counter<'a> {
        method: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == self.method {
                self.count += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut counter = Counter { method, count: 0 };
    counter.visit_block(block);
    counter.count
}

fn launch_destructured_binding(stmts: &[syn::Stmt], field_name: &str) -> Option<String> {
    stmts.iter().find_map(|stmt| {
        let syn::Stmt::Local(local) = stmt else {
            return None;
        };
        let syn::Pat::Struct(pat) = &local.pat else {
            return None;
        };
        pat.fields.iter().find_map(|field| {
            if !matches!(&field.member, syn::Member::Named(member) if member == field_name) {
                return None;
            }
            let syn::Pat::Ident(binding) = field.pat.as_ref() else {
                return None;
            };
            Some(binding.ident.to_string())
        })
    })
}

fn module_registration_call_count(file: &syn::File, binding: &str) -> usize {
    struct Counter<'a> {
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if expr_path_last(&call.func).is_some_and(|ident| ident == "register_module_output")
                && call.args.len() == 2
                && call.args.last().is_some_and(|arg| {
                    expr_path_last(arg).is_some_and(|ident| ident == self.binding)
                })
            {
                self.count += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter { binding, count: 0 };
    counter.visit_file(file);
    counter.count
}

fn is_trace_registration_stmt(stmt: &syn::Stmt) -> bool {
    matches!(stmt, syn::Stmt::Expr(syn::Expr::If(expr), None)
        if matches!(expr.cond.as_ref(), syn::Expr::Let(let_)
            if matches!(let_.expr.as_ref(), syn::Expr::Path(path)
                if path.path.is_ident("trace_exporter"))))
}

fn is_pg_runtime_registration_stmt(stmt: &syn::Stmt, binding: &str) -> bool {
    struct Finder<'a> {
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if expr_path_last(&call.func).is_some_and(|ident| ident == "register_module_output")
                && call.args.len() == 2
                && call
                    .args
                    .first()
                    .is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "stack"))
                && call.args.last().is_some_and(|arg| {
                    expr_path_last(arg).is_some_and(|ident| ident == self.binding)
                })
            {
                self.count += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut finder = Finder { binding, count: 0 };
    finder.visit_stmt(stmt);
    finder.count == 1
}

#[derive(Default)]
struct RuntimeResourcesCallCounter {
    calls: usize,
}

impl<'ast> Visit<'ast> for RuntimeResourcesCallCounter {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "runtime_resources" {
            self.calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if expr_path_last(&call.func).is_some_and(|ident| ident == "runtime_resources") {
            self.calls += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[derive(Default)]
struct MergeProviderCallCounter {
    calls: usize,
}

impl<'ast> Visit<'ast> for MergeProviderCallCounter {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "merge_provider" {
            self.calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if expr_path_last(&call.func).is_some_and(|ident| ident == "merge_provider") {
            self.calls += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn wire_domains_blocks(run: &syn::ItemFn) -> Vec<&syn::Block> {
    let mut finder = WireDomainsBlockFinder::default();
    finder.visit_block(&run.block);
    finder.blocks
}

#[derive(Default)]
struct WireDomainsBlockFinder<'ast> {
    blocks: Vec<&'ast syn::Block>,
}

impl<'ast> Visit<'ast> for WireDomainsBlockFinder<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let is_phase_result =
            expr_path_last(&call.func).is_some_and(|ident| ident == "phase_result");
        let is_wire_domains = call
            .args
            .first()
            .and_then(expr_path_last)
            .is_some_and(|ident| ident == "WireDomains");
        if is_phase_result
            && is_wire_domains
            && let Some(block) = call.args.iter().nth(1).and_then(async_expr_block)
        {
            self.blocks.push(block);
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn async_expr_block(expr: &syn::Expr) -> Option<&syn::Block> {
    match expr {
        syn::Expr::Async(expr) => Some(&expr.block),
        syn::Expr::Await(expr) => match expr.base.as_ref() {
            syn::Expr::Async(expr) => Some(&expr.block),
            _ => None,
        },
        _ => None,
    }
}

fn expr_path_last(expr: &syn::Expr) -> Option<&syn::Ident> {
    let syn::Expr::Path(path) = expr else {
        return None;
    };
    path.path.segments.last().map(|segment| &segment.ident)
}

fn path_last_ident(path: &syn::Path) -> Option<&syn::Ident> {
    path.segments.last().map(|segment| &segment.ident)
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

fn is_canonical_provider_constructor(item: &syn::ItemFn) -> bool {
    item.sig.inputs.len() == 1
        && matches!(item.sig.inputs.first(), Some(syn::FnArg::Typed(input))
            if matches!(input.pat.as_ref(), syn::Pat::Ident(pat)
                if pat.ident == "deps" && pat.mutability.is_none() && pat.by_ref.is_none())
                && matches!(input.ty.as_ref(), syn::Type::Reference(reference)
                    if reference.mutability.is_none()
                        && type_last_ident(&reference.elem).is_some_and(|ident| ident == "SharedRuntimeDeps")))
        && return_type_is(&item.sig.output, "DomainModuleResult")
        && item.block.stmts.len() == 5
        && is_provider_module_init(&item.block.stmts[0])
        && is_provider_merge_stmt(&item.block.stmts[1], "redis")
        && is_provider_merge_stmt(&item.block.stmts[2], "s3")
        && is_provider_merge_stmt(&item.block.stmts[3], "vault")
        && matches!(&item.block.stmts[4], syn::Stmt::Expr(expr, None)
            if expr_path_last(expr).is_some_and(|ident| ident == "provider_module"))
}

fn is_provider_module_init(stmt: &syn::Stmt) -> bool {
    let syn::Stmt::Local(local) = stmt else {
        return false;
    };
    let syn::Pat::Ident(pat) = &local.pat else {
        return false;
    };
    let Some(init) = &local.init else {
        return false;
    };
    pat.ident == "provider_module"
        && pat.mutability.is_some()
        && pat.by_ref.is_none()
        && init.diverge.is_none()
        && matches!(init.expr.as_ref(), syn::Expr::Call(call)
            if call.args.is_empty() && is_exact_path(&call.func, &["DomainModuleResult", "default"]))
}

fn is_provider_merge_stmt(stmt: &syn::Stmt, provider: &str) -> bool {
    let syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)) = stmt else {
        return false;
    };
    call.method == "merge_provider"
        && expr_path_last(&call.receiver).is_some_and(|ident| ident == "provider_module")
        && call.args.len() == 1
        && call.args.first().is_some_and(|arg| {
            let syn::Expr::Reference(reference) = arg else {
                return false;
            };
            matches!(reference.expr.as_ref(), syn::Expr::Field(field)
                if expr_path_last(&field.base).is_some_and(|ident| ident == "deps")
                    && matches!(&field.member, syn::Member::Named(member) if member == provider))
        })
}

fn direct_provider_registrations(block: &syn::Block) -> usize {
    block
        .stmts
        .iter()
        .filter(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return false;
            };
            let Some(init) = &local.init else {
                return false;
            };
            is_provider_assembly_call(&init.expr)
        })
        .count()
}

fn direct_provider_constructors(block: &syn::Block) -> usize {
    block
        .stmts
        .iter()
        .filter(|stmt| {
            let syn::Stmt::Local(local) = stmt else {
                return false;
            };
            let syn::Pat::Ident(pat) = &local.pat else {
                return false;
            };
            let Some(init) = &local.init else {
                return false;
            };
            pat.ident == "provider_module"
                && pat.mutability.is_none()
                && pat.by_ref.is_none()
                && init.diverge.is_none()
                && matches!(init.expr.as_ref(), syn::Expr::Call(call)
                    if is_exact_path(&call.func, &["crate", "provider_output", "build_provider_module"])
                        && call.args.len() == 1
                        && call.args.first().is_some_and(|arg| matches!(arg, syn::Expr::Reference(reference)
                            if reference.mutability.is_none()
                                && expr_path_last(&reference.expr).is_some_and(|ident| ident == "deps"))))
        })
        .count()
}

fn direct_provider_declarations(block: &syn::Block) -> usize {
    block
        .stmts
        .iter()
        .filter(|stmt| {
            matches!(stmt, syn::Stmt::Local(local)
                if matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "provider_module"))
        })
        .count()
}

fn provider_module_path_uses(block: &syn::Block) -> usize {
    struct Counter(usize);
    impl<'ast> Visit<'ast> for Counter {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == 1
                && path.path.segments[0].ident == "provider_module"
            {
                self.0 += 1;
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut counter = Counter(0);
    counter.visit_block(block);
    counter.0
}

fn exact_named_path_call_count(block: &syn::Block, path: &[&str]) -> usize {
    struct Counter<'a> {
        path: &'a [&'a str],
        calls: usize,
    }
    impl Visit<'_> for Counter<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if is_exact_path(&call.func, self.path) {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter { path, calls: 0 };
    counter.visit_block(block);
    counter.calls
}

fn exact_path_call_count_in_file(file: &syn::File, path: &[&str]) -> usize {
    struct Counter<'a> {
        path: &'a [&'a str],
        calls: usize,
    }
    impl Visit<'_> for Counter<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if is_exact_path(&call.func, self.path) {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter { path, calls: 0 };
    counter.visit_file(file);
    counter.calls
}

fn is_provider_assembly_call(expr: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expr else {
        return false;
    };
    if !is_exact_path(&call.func, &["crate", "assemble_runtime_module_outputs"]) {
        return false;
    }
    call.args.iter().any(|arg| {
        let syn::Expr::Struct(struct_expr) = arg else {
            return false;
        };
        struct_expr
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "RuntimeModuleAssemblyInputs")
            && struct_expr.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == "provider_module")
                    && expr_path_last(&field.expr).is_some_and(|ident| ident == "provider_module")
            })
    })
}

fn direct_assembly_provider_merges(block: &syn::Block) -> usize {
    block
        .stmts
        .iter()
        .filter(|stmt| {
            let syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)) = stmt else {
                return false;
            };
            call.method == "merge"
                && expr_path_last(&call.receiver).is_some_and(|ident| ident == "module")
                && call.args.first().is_some_and(|arg| {
                    matches!(arg, syn::Expr::Field(field)
                        if expr_path_last(&field.base).is_some_and(|ident| ident == "inputs")
                            && matches!(&field.member, syn::Member::Named(member) if member == "provider_module"))
                })
        })
        .count()
}

#[derive(Default)]
struct ProviderPrimitiveCalls {
    forbidden: bool,
    amqp_runtime_resources: usize,
}

#[derive(Default)]
struct LocalProviderSymbols {
    aliases: BTreeMap<String, String>,
    fields: BTreeMap<(String, String), String>,
    returns: BTreeMap<String, String>,
}

impl LocalProviderSymbols {
    const AMBIGUOUS: &'static str = "__AMBIGUOUS_PROVIDER_TYPE__";

    fn insert_unique(map: &mut BTreeMap<String, String>, name: String, target: String) {
        match map.entry(name) {
            Entry::Vacant(entry) => {
                entry.insert(target);
            }
            Entry::Occupied(mut entry) if entry.get() != &target => {
                entry.insert(Self::AMBIGUOUS.to_string());
            }
            Entry::Occupied(_) => {}
        }
    }

    fn resolve_type(&self, ty: &str) -> String {
        let mut current = ty.to_string();
        let mut seen = BTreeSet::new();
        while seen.insert(current.clone()) {
            let segments = current.split("::").collect::<Vec<_>>();
            let Some((prefix_len, next)) = (1..=segments.len()).rev().find_map(|prefix_len| {
                self.aliases
                    .get(&segments[..prefix_len].join("::"))
                    .map(|next| (prefix_len, next))
            }) else {
                break;
            };
            let suffix = &segments[prefix_len..];
            current = if suffix.is_empty() {
                next.clone()
            } else {
                format!("{next}::{}", suffix.join("::"))
            };
        }
        current
    }

    fn collect(file: &syn::File) -> Self {
        #[derive(Default)]
        struct Collector(LocalProviderSymbols);
        impl Collector {
            fn collect_use(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
                match tree {
                    syn::UseTree::Path(path) => {
                        prefix.push(path.ident.to_string());
                        self.collect_use(&path.tree, prefix);
                        prefix.pop();
                    }
                    syn::UseTree::Rename(rename) => {
                        let is_self = rename.ident == "self";
                        if !is_self {
                            prefix.push(rename.ident.to_string());
                        }
                        LocalProviderSymbols::insert_unique(
                            &mut self.0.aliases,
                            rename.rename.to_string(),
                            prefix.join("::"),
                        );
                        if !is_self {
                            prefix.pop();
                        }
                    }
                    syn::UseTree::Name(name) => {
                        prefix.push(name.ident.to_string());
                        LocalProviderSymbols::insert_unique(
                            &mut self.0.aliases,
                            name.ident.to_string(),
                            prefix.join("::"),
                        );
                        prefix.pop();
                    }
                    syn::UseTree::Group(group) => {
                        for item in &group.items {
                            self.collect_use(item, prefix);
                        }
                    }
                    _ => {}
                }
            }
        }
        impl<'ast> Visit<'ast> for Collector {
            fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
                if attrs_may_be_production(&item.attrs) {
                    syn::visit::visit_item_mod(self, item);
                }
            }

            fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
                if attrs_may_be_production(&item.attrs) {
                    let target = if item.generics.params.is_empty() {
                        type_identity(&item.ty)
                            .unwrap_or_else(|| LocalProviderSymbols::AMBIGUOUS.to_string())
                    } else {
                        LocalProviderSymbols::AMBIGUOUS.to_string()
                    };
                    LocalProviderSymbols::insert_unique(
                        &mut self.0.aliases,
                        item.ident.to_string(),
                        target,
                    );
                }
            }

            fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
                if attrs_may_be_production(&item.attrs) {
                    self.collect_use(&item.tree, &mut Vec::new());
                }
            }

            fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
                if attrs_may_be_production(&item.attrs) {
                    let alias = item
                        .rename
                        .as_ref()
                        .map_or_else(|| item.ident.to_string(), |(_, alias)| alias.to_string());
                    LocalProviderSymbols::insert_unique(
                        &mut self.0.aliases,
                        alias,
                        item.ident.to_string(),
                    );
                }
            }

            fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
                if attrs_may_be_production(&item.attrs) {
                    for field in &item.fields {
                        if let (Some(name), Some(ty)) = (&field.ident, type_identity(&field.ty)) {
                            let target = if item.generics.params.is_empty() {
                                ty
                            } else {
                                LocalProviderSymbols::AMBIGUOUS.to_string()
                            };
                            let key = (item.ident.to_string(), name.to_string());
                            match self.0.fields.entry(key) {
                                Entry::Vacant(entry) => {
                                    entry.insert(target);
                                }
                                Entry::Occupied(mut entry) if entry.get() != &target => {
                                    entry.insert(LocalProviderSymbols::AMBIGUOUS.to_string());
                                }
                                Entry::Occupied(_) => {}
                            }
                        }
                    }
                }
            }

            fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
                if !attrs_may_be_production(&item.attrs) {
                    return;
                }
                if let syn::ReturnType::Type(_, ty) = &item.sig.output
                    && let Some(return_ty) = type_identity(ty)
                    && !item.sig.generics.params.iter().any(|param| {
                        matches!(param, syn::GenericParam::Type(param) if param.ident == return_ty)
                    })
                {
                    LocalProviderSymbols::insert_unique(
                        &mut self.0.returns,
                        item.sig.ident.to_string(),
                        return_ty,
                    );
                }
                syn::visit::visit_item_fn(self, item);
            }
        }
        let mut collector = Collector::default();
        collector.visit_file(file);
        for item in &file.items {
            if let syn::Item::Struct(item) = item
                && is_protected_provider_owner(&item.ident.to_string())
            {
                LocalProviderSymbols::insert_unique(
                    &mut collector.0.aliases,
                    item.ident.to_string(),
                    format!("__LOCAL__::{}", item.ident),
                );
            }
        }
        collector.0
    }
}

struct ProviderPrimitiveVisitor<'a> {
    symbols: &'a LocalProviderSymbols,
    bindings: BTreeMap<String, String>,
    local_shadows: BTreeSet<String>,
    self_type: Option<String>,
    allow_amqp: bool,
    calls: ProviderPrimitiveCalls,
}

impl ProviderPrimitiveVisitor<'_> {
    fn resolve_type(&self, ty: &str) -> String {
        let resolved = self.symbols.resolve_type(ty);
        if !resolved.contains("::") && self.local_shadows.contains(&resolved) {
            format!("__LOCAL__::{resolved}")
        } else {
            resolved
        }
    }

    fn add_item_shadows(&mut self, items: &[syn::Item]) {
        for item in items {
            if let syn::Item::Struct(item) = item
                && is_protected_provider_owner(&item.ident.to_string())
            {
                self.local_shadows.insert(item.ident.to_string());
            }
        }
    }

    fn expr_type(&self, expr: &syn::Expr) -> Option<String> {
        match expr {
            syn::Expr::Path(path) => path
                .path
                .segments
                .last()
                .and_then(|segment| self.bindings.get(&segment.ident.to_string()))
                .map(|ty| self.resolve_type(ty)),
            syn::Expr::Reference(reference) => self.expr_type(&reference.expr),
            syn::Expr::Paren(paren) => self.expr_type(&paren.expr),
            syn::Expr::Field(field) => {
                let base = self.expr_type(&field.base)?;
                let syn::Member::Named(member) = &field.member else {
                    return None;
                };
                if base.rsplit("::").next() == Some("SharedRuntimeDeps") {
                    return match member.to_string().as_str() {
                        "redis" => Some("redis::RedisRuntimeDeps".to_string()),
                        "s3" => Some("s3::S3RuntimeDeps".to_string()),
                        "vault" => Some("vault::VaultRuntimeDeps".to_string()),
                        _ => None,
                    };
                }
                self.symbols
                    .fields
                    .get(&(base, member.to_string()))
                    .map(|ty| self.resolve_type(ty))
            }
            syn::Expr::Call(call) => {
                let syn::Expr::Path(path) = call.func.as_ref() else {
                    return None;
                };
                let segments = path.path.segments.iter().collect::<Vec<_>>();
                if segments.len() >= 2
                    && segments.last().is_some_and(|segment| {
                        matches!(
                            segment.ident.to_string().as_str(),
                            "new" | "default" | "connect"
                        )
                    })
                {
                    Some(
                        self.resolve_type(
                            &segments[..segments.len() - 1]
                                .iter()
                                .map(|segment| segment.ident.to_string())
                                .collect::<Vec<_>>()
                                .join("::"),
                        ),
                    )
                } else {
                    segments
                        .last()
                        .and_then(|segment| self.symbols.returns.get(&segment.ident.to_string()))
                        .map(|ty| self.resolve_type(ty))
                }
            }
            _ => None,
        }
    }

    fn classify(&mut self, method: &str, owner: Option<String>) {
        let owner = owner.map(|ty| self.resolve_type(&ty));
        if method == "runtime_resources"
            && owner.as_deref() == Some("AmqpRuntimeDeps")
            && self.allow_amqp
        {
            self.calls.amqp_runtime_resources += 1;
            return;
        }
        if owner
            .as_deref()
            .is_some_and(|owner| !is_protected_provider_owner(owner))
        {
            return;
        }
        self.calls.forbidden = true;
    }
}

fn is_protected_provider_owner(owner: &str) -> bool {
    if owner == LocalProviderSymbols::AMBIGUOUS {
        return true;
    }
    let segments = owner.split("::").collect::<Vec<_>>();
    matches!(
        segments.as_slice(),
        ["RedisRuntimeDeps"
            | "S3RuntimeDeps"
            | "VaultRuntimeDeps"
            | "AmqpRuntimeDeps"
            | "PgRuntimeDeps"
            | "PgReadinessSamplerFactory"]
            | ["DomainModuleResult" | "DomainModuleResultExt"]
            | ["redis" | "redis_adapter", "RedisRuntimeDeps"]
            | ["s3", "S3RuntimeDeps"]
            | ["vault", "VaultRuntimeDeps"]
            | ["amqp", "AmqpRuntimeDeps"]
            | ["postgres", "PgRuntimeDeps" | "PgReadinessSamplerFactory"]
            | ["bootstrap", "DomainModuleResult"]
            | ["provider_output", "DomainModuleResultExt"]
            | ["crate", "provider_output", "DomainModuleResultExt"]
    )
}

impl<'ast> Visit<'ast> for ProviderPrimitiveVisitor<'_> {
    fn visit_file(&mut self, file: &'ast syn::File) {
        let saved = self.local_shadows.clone();
        self.add_item_shadows(&file.items);
        for item in &file.items {
            self.visit_item(item);
        }
        self.local_shadows = saved;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        if let Some((_, items)) = &item.content {
            let saved = self.local_shadows.clone();
            self.add_item_shadows(items);
            for item in items {
                self.visit_item(item);
            }
            self.local_shadows = saved;
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let saved = self.bindings.clone();
        for input in &item.sig.inputs {
            if let syn::FnArg::Typed(input) = input
                && let syn::Pat::Ident(pat) = input.pat.as_ref()
                && let Some(ty) = type_identity(&input.ty)
            {
                self.bindings
                    .insert(pat.ident.to_string(), self.resolve_type(&ty));
            }
        }
        self.visit_block(&item.block);
        self.bindings = saved;
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let saved = self.self_type.clone();
        self.self_type = type_identity(&item.self_ty);
        syn::visit::visit_item_impl(self, item);
        self.self_type = saved;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let saved = self.bindings.clone();
        if let Some(self_type) = &self.self_type {
            self.bindings
                .insert("self".to_string(), self.resolve_type(self_type));
        }
        for input in &item.sig.inputs {
            if let syn::FnArg::Typed(input) = input
                && let syn::Pat::Ident(pat) = input.pat.as_ref()
                && let Some(ty) = type_identity(&input.ty)
            {
                self.bindings
                    .insert(pat.ident.to_string(), self.resolve_type(&ty));
            }
        }
        self.visit_block(&item.block);
        self.bindings = saved;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let saved = self.bindings.clone();
        let saved_shadows = self.local_shadows.clone();
        for stmt in &block.stmts {
            if let syn::Stmt::Item(syn::Item::Struct(item)) = stmt
                && is_protected_provider_owner(&item.ident.to_string())
            {
                self.local_shadows.insert(item.ident.to_string());
            }
        }
        for stmt in &block.stmts {
            self.visit_stmt(stmt);
        }
        self.bindings = saved;
        self.local_shadows = saved_shadows;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
        }
        let (name, declared_ty) = match &local.pat {
            syn::Pat::Ident(pat) => (Some(pat.ident.to_string()), None),
            syn::Pat::Type(pat) => {
                let name = match pat.pat.as_ref() {
                    syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                    _ => None,
                };
                (name, type_identity(&pat.ty))
            }
            _ => (None, None),
        };
        if let Some(name) = name {
            let inferred = declared_ty
                .or_else(|| {
                    local
                        .init
                        .as_ref()
                        .and_then(|init| self.expr_type(&init.expr))
                })
                .or_else(|| {
                    local.init.as_ref().and_then(|init| {
                        (exact_path_call_count_in_expr(
                            &init.expr,
                            &["amqp", "AmqpRuntimeDeps", "connect"],
                        ) == 1)
                            .then(|| "AmqpRuntimeDeps".to_string())
                    })
                });
            if let Some(ty) = inferred {
                self.bindings.insert(name, self.resolve_type(&ty));
            } else {
                self.bindings.remove(&name);
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        let owner = self.expr_type(&call.receiver);
        if matches!(
            method.as_str(),
            "runtime_resources"
                | "merge_provider"
                | "into_runtime_parts"
                | "store_guard"
                | "audit_admin_store_guard"
                | "spawn_readiness_sampler"
        ) || method == "spawn"
            && owner.as_deref().is_some_and(|owner| {
                self.resolve_type(owner).rsplit("::").next() == Some("PgReadinessSamplerFactory")
            })
        {
            self.classify(&method, owner);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && let Some(method) = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
            && matches!(
                method.as_str(),
                "runtime_resources"
                    | "merge_provider"
                    | "into_runtime_parts"
                    | "store_guard"
                    | "audit_admin_store_guard"
                    | "spawn_readiness_sampler"
                    | "spawn"
            )
        {
            let segments = path.path.segments.iter().collect::<Vec<_>>();
            let owner = path
                .qself
                .as_ref()
                .and_then(|qself| type_identity(&qself.ty))
                .or_else(|| {
                    (segments.len() >= 2).then(|| {
                        segments[..segments.len() - 1]
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect::<Vec<_>>()
                            .join("::")
                    })
                });
            if owner.is_some() {
                self.classify(&method, owner);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn provider_primitive_calls(file: &syn::File, allow_amqp: bool) -> ProviderPrimitiveCalls {
    let symbols = LocalProviderSymbols::collect(file);
    let mut visitor = ProviderPrimitiveVisitor {
        symbols: &symbols,
        bindings: BTreeMap::new(),
        local_shadows: BTreeSet::new(),
        self_type: None,
        allow_amqp,
        calls: ProviderPrimitiveCalls::default(),
    };
    visitor.visit_file(file);
    visitor.calls
}

fn has_only_canonical_amqp_runtime_resources(file: &syn::File) -> bool {
    let wire_durable = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "wire_durable" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if wire_durable.len() != 1 {
        return false;
    }
    let wire_durable = wire_durable[0];
    wire_durable
        .block
        .stmts
        .iter()
        .filter(|stmt| {
            matches!(stmt, syn::Stmt::Expr(syn::Expr::ForLoop(loop_), None)
            if is_canonical_amqp_connection_loop(loop_))
        })
        .count()
        == 1
        && wire_durable_returns_owned_module(wire_durable)
        && !wire_durable_discards_module_output(wire_durable)
}

fn wire_durable_returns_owned_module(wire_durable: &syn::ItemFn) -> bool {
    matches!(wire_durable.block.stmts.last(),
    Some(syn::Stmt::Expr(syn::Expr::Call(call), None))
        if is_exact_path(&call.func, &["Ok"])
            && call.args.len() == 1
            && call.args.first().is_some_and(|arg| {
                expr_path_last(arg).is_some_and(|ident| ident == "module")
            }))
}

fn wire_durable_discards_module_output(wire_durable: &syn::ItemFn) -> bool {
    struct Visitor {
        discards_output: bool,
    }

    impl<'ast> Visit<'ast> for Visitor {
        fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
            if is_module_or_output_channel_expr(&assign.left) {
                self.discards_output = true;
            }
            syn::visit::visit_expr_assign(self, assign);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if is_module_output_channel_expr(&call.receiver)
                && matches!(
                    call.method.to_string().as_str(),
                    "clear" | "drain" | "split_off" | "truncate"
                )
            {
                self.discards_output = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            let destructive_mem_call = is_exact_path(&call.func, &["std", "mem", "take"])
                || is_exact_path(&call.func, &["std", "mem", "replace"])
                || is_exact_path(&call.func, &["mem", "take"])
                || is_exact_path(&call.func, &["mem", "replace"]);
            if destructive_mem_call
                && call.args.first().is_some_and(|arg| {
                    matches!(arg, syn::Expr::Reference(reference)
                        if reference.mutability.is_some()
                            && is_module_or_output_channel_expr(&reference.expr))
                })
            {
                self.discards_output = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }

    let mut visitor = Visitor {
        discards_output: false,
    };
    visitor.visit_block(&wire_durable.block);
    visitor.discards_output
}

fn is_module_or_output_channel_expr(expr: &syn::Expr) -> bool {
    expr_path_last(expr).is_some_and(|ident| ident == "module")
        || is_module_output_channel_expr(expr)
}

fn is_module_output_channel_expr(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Field(field)
        if expr_path_last(&field.base).is_some_and(|ident| ident == "module")
            && matches!(&field.member, syn::Member::Named(member)
                if matches!(member.to_string().as_str(), "probes" | "resources" | "workers")))
}

fn is_canonical_amqp_connection_loop(loop_: &syn::ExprForLoop) -> bool {
    let canonical_pattern = matches!(loop_.pat.as_ref(), syn::Pat::Tuple(tuple)
        if tuple.elems.len() == 2
            && matches!(&tuple.elems[0], syn::Pat::Ident(pat) if pat.ident == "domain_upper")
            && matches!(&tuple.elems[1], syn::Pat::Ident(pat) if pat.ident == "url"));
    let canonical_iter = matches!(loop_.expr.as_ref(), syn::Expr::Reference(reference)
        if reference.mutability.is_none()
            && expr_path_last(&reference.expr).is_some_and(|ident| ident == "per_domain"));
    if !canonical_pattern || !canonical_iter {
        return false;
    }

    let connect = loop_.body.stmts.iter().position(|stmt| {
        let syn::Stmt::Local(local) = stmt else {
            return false;
        };
        matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "amqp_deps")
            && local.init.as_ref().is_some_and(|init| {
                exact_path_call_count_in_expr(&init.expr, &["amqp", "AmqpRuntimeDeps", "connect"])
                    == 1
            })
    });
    let extend = loop_
        .body
        .stmts
        .iter()
        .position(is_canonical_amqp_runtime_resources_stmt);
    let insert = loop_.body.stmts.iter().position(|stmt| {
        matches!(stmt, syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_))
            if call.method == "insert"
                && expr_path_last(&call.receiver).is_some_and(|ident| ident == "amqp_map")
                && call.args.len() == 2
                && call.args.first().is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "domain"))
                && call.args.last().is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "amqp_deps")))
    });
    matches!((connect, extend, insert), (Some(connect), Some(extend), Some(insert))
        if connect < extend && extend < insert)
}

fn exact_path_call_count_in_expr(expr: &syn::Expr, expected: &[&str]) -> usize {
    struct Counter<'a> {
        expected: &'a [&'a str],
        calls: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if is_exact_path(&call.func, self.expected) {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter { expected, calls: 0 };
    counter.visit_expr(expr);
    counter.calls
}

fn is_canonical_amqp_runtime_resources_stmt(stmt: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::MethodCall(extend), Some(_)) = stmt else {
        return false;
    };
    extend.method == "extend"
        && extend.args.len() == 1
        && matches!(extend.receiver.as_ref(), syn::Expr::Field(field)
            if expr_path_last(&field.base).is_some_and(|ident| ident == "module")
                && matches!(&field.member, syn::Member::Named(member) if member == "resources"))
        && extend.args.first().is_some_and(|arg| {
            matches!(arg, syn::Expr::MethodCall(resources)
                if resources.method == "runtime_resources"
                    && resources.args.is_empty()
                    && expr_path_last(&resources.receiver)
                        .is_some_and(|ident| ident == "amqp_deps"))
        })
}

fn type_last_ident(ty: &syn::Type) -> Option<&syn::Ident> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        syn::Type::Reference(reference) => type_last_ident(&reference.elem),
        _ => None,
    }
}

fn type_identity(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) if path.qself.is_none() => Some(
            path.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        ),
        syn::Type::Reference(reference) => type_identity(&reference.elem),
        syn::Type::Paren(paren) => type_identity(&paren.elem),
        _ => None,
    }
}

#[derive(Default)]
struct DomainFactoryImports {
    aliases: BTreeMap<String, Vec<String>>,
    forbidden: Option<String>,
}

impl DomainFactoryImports {
    fn collect_use_tree(
        &mut self,
        tree: &syn::UseTree,
        prefix: &mut Vec<String>,
        crate_root: bool,
    ) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.collect_use_tree(&path.tree, prefix, crate_root);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let mut path = prefix.clone();
                let alias = name.ident.to_string();
                if alias != "self" {
                    path.push(alias.clone());
                }
                self.record_import(alias, path, crate_root);
            }
            syn::UseTree::Rename(rename) => {
                let mut path = prefix.clone();
                if rename.ident != "self" {
                    path.push(rename.ident.to_string());
                }
                self.record_import(rename.rename.to_string(), path, crate_root);
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    self.collect_use_tree(tree, prefix, crate_root);
                }
            }
            syn::UseTree::Glob(_) => {
                if canonical_domain_module_path(prefix, crate_root).is_some() {
                    self.forbidden = Some(format!("{}::*", prefix.join("::")));
                }
            }
        }
    }

    fn record_import(&mut self, alias: String, path: Vec<String>, crate_root: bool) {
        let resolved = resolve_import_alias(&path, &self.aliases);
        if canonical_domain_factory_path(&resolved, crate_root).is_some() {
            self.forbidden = Some(resolved.join("::"));
        }
        self.aliases.insert(alias, resolved);
    }
}

struct DomainFactoryImportVisitor {
    imports: DomainFactoryImports,
    crate_root: bool,
}

impl<'ast> Visit<'ast> for DomainFactoryImportVisitor {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        self.imports
            .collect_use_tree(&item.tree, &mut prefix, self.crate_root);
    }
}

struct DomainFactoryPathVisitor<'a> {
    aliases: &'a BTreeMap<String, Vec<String>>,
    crate_root: bool,
    forbidden: Option<String>,
}

impl<'ast> Visit<'ast> for DomainFactoryPathVisitor<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        let raw = expr
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let resolved = resolve_import_alias(&raw, self.aliases);
        if canonical_domain_factory_path(&resolved, self.crate_root).is_some() {
            self.forbidden = Some(resolved.join("::"));
        }
        syn::visit::visit_expr_path(self, expr);
    }
}

fn forbidden_domain_factory_usage(file: &syn::File, crate_root: bool) -> Option<String> {
    let mut imports = DomainFactoryImportVisitor {
        imports: DomainFactoryImports::default(),
        crate_root,
    };
    imports.visit_file(file);
    if imports.imports.forbidden.is_some() {
        return imports.imports.forbidden;
    }
    let mut paths = DomainFactoryPathVisitor {
        aliases: &imports.imports.aliases,
        crate_root,
        forbidden: None,
    };
    paths.visit_file(file);
    paths.forbidden
}

fn resolve_import_alias(raw: &[String], aliases: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let mut resolved = raw.to_vec();
    for _ in 0..=aliases.len() {
        let Some((first, tail)) = resolved.split_first() else {
            break;
        };
        let Some(prefix) = aliases.get(first) else {
            break;
        };
        let next = prefix
            .iter()
            .cloned()
            .chain(tail.iter().cloned())
            .collect::<Vec<_>>();
        if next == resolved {
            break;
        }
        resolved = next;
    }
    resolved
}

fn canonical_domain_factory_path(path: &[String], crate_root: bool) -> Option<&str> {
    let path = canonical_runtime_path(path, crate_root)?;
    match path {
        [domains, domain, module]
            if domains == "domains"
                && matches!(domain.as_str(), "settings" | "identity" | "audit")
                && module == "module" =>
        {
            Some(domain)
        }
        _ => None,
    }
}

fn canonical_domain_module_path(path: &[String], crate_root: bool) -> Option<&str> {
    let path = canonical_runtime_path(path, crate_root)?;
    match path {
        [domains, domain]
            if domains == "domains"
                && matches!(domain.as_str(), "settings" | "identity" | "audit") =>
        {
            Some(domain)
        }
        _ => None,
    }
}

fn canonical_runtime_path(path: &[String], crate_root: bool) -> Option<&[String]> {
    match path {
        [root, tail @ ..] if root == "crate" => Some(tail),
        _ if crate_root => Some(path),
        _ => None,
    }
}

fn collect_rust_sources(dir: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("读目录 {} 失败", dir.display()))? {
        let entry = entry.with_context(|| format!("读取 {} 目录项失败", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("读取 {} 类型失败", path.display()))?;
        if file_type.is_dir() {
            collect_rust_sources(&path, paths)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(())
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
        id: "run.config.snapshot",
        path: RUNTIME_LIB_PATH,
        pattern: "RuntimeConfigSnapshot::capture(EnvConfigSource)",
    },
    AnchorSpec {
        id: "run.provider.oidc",
        path: RUNTIME_LIB_PATH,
        pattern: "build_runtime_oidc_provider().context(",
    },
    AnchorSpec {
        id: "run.provider.vault",
        path: RUNTIME_LIB_PATH,
        pattern: "build_vault_runtime_deps(config_value)",
    },
    AnchorSpec {
        id: "run.provider.redis",
        path: RUNTIME_LIB_PATH,
        pattern: "build_redis_runtime_deps(config_value)",
    },
    AnchorSpec {
        id: "run.provider.s3",
        path: RUNTIME_LIB_PATH,
        pattern: "build_s3_runtime_deps_from(config_value)",
    },
    AnchorSpec {
        id: "run.provider.pg",
        path: RUNTIME_LIB_PATH,
        pattern: "PgRuntimeDeps::setup_with_audit_admin_config",
    },
    AnchorSpec {
        id: "run.shared-deps",
        path: RUNTIME_LIB_PATH,
        pattern: "let deps = SharedRuntimeDeps {",
    },
    AnchorSpec {
        id: "run.wire.generated-domains",
        path: RUNTIME_LIB_PATH,
        pattern: "modules_gen::wire_domains(&deps)",
    },
    AnchorSpec {
        id: "run.module.input.domains",
        path: RUNTIME_LIB_PATH,
        pattern: "let (mut registry, domains_module) =",
    },
    AnchorSpec {
        id: "run.compose.generated-domains",
        path: RUNTIME_LIB_PATH,
        pattern: "bootstrap::compose_bindings(&mut domain_bindings)",
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
        id: "run.provider-output.module",
        path: RUNTIME_LIB_PATH,
        pattern: "let provider_module = crate::provider_output::build_provider_module(&deps)",
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
        pattern: "crate::assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs",
    },
    AnchorSpec {
        id: "run.probe.drain",
        path: RUNTIME_LIB_PATH,
        pattern: "for (name, probe) in std::mem::take(&mut module.probes)",
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
        id: "run.provider-output.pg",
        path: RUNTIME_LIB_PATH,
        pattern: "crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period)",
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
        id: "launch.shutdown.pg-output",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "Self::register_module_output(stack, pg_runtime_module)?;",
    },
    AnchorSpec {
        id: "launch.shutdown.domain-output",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "Self::register_module_output(stack, domain_module)?;",
    },
    AnchorSpec {
        id: "launch.shutdown.resources",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for resource in output.resources",
    },
    AnchorSpec {
        id: "launch.shutdown.workers",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for worker in output.workers",
    },
    AnchorSpec {
        id: "launch.register-plan",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "let listeners = plan.register(&mut stack)?;",
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
        if matches!(
            spec.id,
            "launch.shutdown.resources" | "launch.shutdown.workers"
        ) {
            return launch_plan_method_scope(text, "fn register_module_output(")
                .unwrap_or_else(|| empty_scope(text));
        }
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
    if spec.path == RUNTIME_LAUNCH_PATH
        && matches!(
            spec.id,
            "launch.shutdown.resources" | "launch.shutdown.workers"
        )
    {
        return (spec.path, "register_module_output");
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
    launch_plan_method_scope(text, "fn register(")
}

fn launch_plan_method_scope<'a>(
    text: &'a str,
    method_needle: &str,
) -> Option<AnchorSearchScope<'a>> {
    let mut cursor = 0usize;
    while cursor < text.len() {
        let impl_scope = extract_braced_body_at(text, cursor, "impl LaunchPlan")?;
        if let Some(method_offset) = impl_scope.body.find(method_needle) {
            let method_start = impl_scope.start + method_offset;
            if let Some(method_scope) = extract_braced_body_at(text, method_start, method_needle)
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
domains = ["settings", "identity", "audit"]
topology = "durable-shared"
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
requiredFeatures = ["backend"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
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
        write(&root.join(PROVIDER_OUTPUT_PATH), provider_adapter_fixture())?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            &runtime_launch_fixture(None),
        )?;
        Ok(root)
    }

    fn runtime_lib_fixture(omit: Option<&str>) -> String {
        format!(
            "pub async fn run() {{\n{}\n}}\nfn assemble_runtime_module_outputs(inputs: RuntimeModuleAssemblyInputs) {{\nlet mut module = DomainModuleResult::default();\nmodule.merge(inputs.domains_module);\nmodule.merge(inputs.provider_module);\n}}\n",
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
            if anchor.id == "run.wire.generated-domains" {
                lines.push("let mut domain_bindings = modules_gen::wire_domains(&deps)");
            } else {
                lines.push(anchor.pattern);
            }
            if anchor.id == "run.shared-deps" {
                lines.push("}");
            }
        }
        lines.join("\n")
    }

    fn runtime_launch_fixture(omit: Option<&str>) -> String {
        format!(
            "impl LaunchPlan {{ fn register() {{\n{}\n}}\nfn register_module_output() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\n{}\n}}\n",
            launch_register_anchor_lines(omit),
            launch_module_registration_anchor_lines(omit),
            launch_until_anchor_lines(omit)
        )
    }

    fn launch_register_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| {
                anchor.path == RUNTIME_LAUNCH_PATH
                    && anchor.id.starts_with("launch.shutdown.")
                    && !matches!(
                        anchor.id,
                        "launch.shutdown.resources" | "launch.shutdown.workers"
                    )
            })
            .filter(|anchor| omit != Some(anchor.id))
            .map(|anchor| anchor.pattern)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn launch_module_registration_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| {
                anchor.path == RUNTIME_LAUNCH_PATH
                    && matches!(
                        anchor.id,
                        "launch.shutdown.resources" | "launch.shutdown.workers"
                    )
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
frameworkContracts = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []

[[diportProviders]]
port = "diport::Pdp"
provider = "oidc::OidcProvider"
providerCrate = "oidc"
consumer = "httpserve"
lifecycle = "unknown"
durability = "persistent"
purpose = "jwt-credential-verification"
outputs = []
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
                .contains("domains = [settings,identity,audit]")
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
        assert!(report.rendered.contains(
            "02 | run.config.snapshot | assemblies/runtime/src/lib.rs | RuntimeConfigSnapshot::capture(EnvConfigSource)"
        ));
        assert!(report.rendered.contains("32 | launch.register-plan"));
        assert!(report.rendered.contains("33 | launch.listeners"));
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
frameworkContracts = []
diportProviders = []

[[listeners]]
kind = "primary"
domains = []

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
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
            &runtime_lib_fixture(Some("run.wire.generated-domains")),
        )?;
        let report = collect_report(&root)?;
        assert!(report.findings.iter().any(|f| {
            f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.generated-domains")
        }));
        Ok(())
    }

    #[test]
    fn runtime_generated_domains_rejects_handwritten_wiring_and_missing_merge() -> Result<()> {
        let root = fixture_root("runtime-generated-domains-red")?;
        let extra_source = root.join("assemblies/runtime/src/handwritten.rs");
        let handwritten = runtime_lib_fixture(None).replace(
            "modules_gen::wire_domains(&deps)",
            "modules_gen::wire_domains(&deps)\nwire_settings(&deps)",
        );
        write(&root.join(RUNTIME_LIB_PATH), &handwritten)?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );

        let qualified = runtime_lib_fixture(None).replace(
            "modules_gen::wire_domains(&deps)",
            "modules_gen::wire_domains(&deps)\ncrate::wire_settings(&deps)",
        );
        write(&root.join(RUNTIME_LIB_PATH), &qualified)?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );

        let helper_bypass = runtime_lib_fixture(None)
            + "\nfn handwritten_helper(deps: &SharedRuntimeDeps) {\ncrate::domains::settings::module(deps);\n}\n";
        write(&root.join(RUNTIME_LIB_PATH), &helper_bypass)?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );

        write(&root.join(RUNTIME_LIB_PATH), &runtime_lib_fixture(None))?;
        write(
            &extra_source,
            "use crate::domains::settings::module as build_settings;\nfn handwritten_alias_helper(deps: &SharedRuntimeDeps) { build_settings(deps); }\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );
        fs::remove_file(&extra_source)?;

        write(
            &extra_source,
            "pub use crate::domains::settings::module as build_settings;\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );
        fs::remove_file(&extra_source)?;

        write(
            &extra_source,
            "use crate::domains::settings as settings_domain;\nfn handwritten_module_alias(deps: &SharedRuntimeDeps) { settings_domain::module(deps); }\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );
        fs::remove_file(&extra_source)?;

        write(
            &extra_source,
            "fn handwritten_local_alias(deps: &SharedRuntimeDeps) { let build = crate::domains::settings::module; build(deps); }\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );
        fs::remove_file(&extra_source)?;

        write(
            &extra_source,
            "mod settings { pub fn module(_: &SharedRuntimeDeps) {} }\nfn local_helper(deps: &SharedRuntimeDeps) { settings::module(deps); }\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != Rule::ForbiddenWiring),
            "local same-name module has no domain factory provenance: {:?}",
            report.findings
        );
        fs::remove_file(&extra_source)?;

        write(
            &extra_source,
            "#[cfg(test)] mod tests { fn generated_test_helper(deps: &SharedRuntimeDeps) { crate::domains::settings::module(deps); } }\n",
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.rule != Rule::ForbiddenWiring),
            "cfg(test) factory seam is outside the production live-path gate: {:?}",
            report.findings
        );
        fs::remove_file(&extra_source)?;

        let missing_merge = runtime_lib_fixture(None).replace(
            "module.merge(inputs.domains_module);",
            "let _ = inputs.domains_module;",
        ) + "\nfn dead_merge_bait(inputs: RuntimeModuleAssemblyInputs) {\nlet mut module = DomainModuleResult::default();\nmodule.merge(inputs.domains_module);\n}\n";
        write(&root.join(RUNTIME_LIB_PATH), &missing_merge)?;
        let report = collect_report(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.rule == Rule::MissingAnchor
                && finding.detail.contains("generated domains output")
        }));
        Ok(())
    }

    fn provider_output_fixture() -> String {
        r#"
pub async fn run() {
    let _wire = phase_result(RuntimePhase::WireDomains, async {
    let provider_module = crate::provider_output::build_provider_module(&deps);
    let _module = crate::assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
        provider_module,
    });
    }.await);
    let pg_runtime_module = crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    let _launch_plan = LaunchPlanParts { pg_runtime_module };
}

fn assemble_runtime_module_outputs(inputs: RuntimeModuleAssemblyInputs) {
    let mut module = DomainModuleResult::default();
    module.merge(inputs.provider_module);
}
"#
        .to_string()
    }

    fn write_event_output_fixture(root: &Path) -> Result<()> {
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        write(
            &root.join("assemblies/runtime/src/event_transport.rs"),
            r#"
pub(crate) async fn wire_event_transport() -> anyhow::Result<DomainModuleResult> { result }
async fn wire_durable() {
    let mut module = DomainModuleResult::default();
    let mut amqp_map = BTreeMap::new();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        let amqp_deps = amqp::AmqpRuntimeDeps::connect(url.as_ref(), &domain, publish_timeout).await?;
        module.resources.extend(amqp_deps.runtime_resources());
        amqp_map.insert(domain, amqp_deps);
    }
    Ok(module)
}
"#,
        )?;
        write(
            &root.join(RUNTIME_LIB_PATH),
            r#"
pub async fn run() {
    let _ = phase_result(RuntimePhase::WireDomains, async {
        let event_module = event_transport::wire_event_transport()
            .await
            .context("wire event transport")?;
        let _module = crate::assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
            event_module,
        });
    });
}
fn assemble_runtime_module_outputs(inputs: RuntimeModuleAssemblyInputs) -> DomainModuleResult {
    let mut module = DomainModuleResult::default();
    module.merge(inputs.event_module);
    module
}
"#,
        )?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            r#"
struct LaunchPlanParts { pg_runtime_module: DomainModuleResult, domain_module: DomainModuleResult }
struct LaunchPlan { pg_runtime_module: DomainModuleResult, domain_module: DomainModuleResult }
impl LaunchPlan {
    fn register(self, stack: &mut ShutdownStack) {
        let Self { trace_exporter, pg_runtime_module, domain_module } = self;
        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }
        Self::register_module_output(stack, pg_runtime_module)?;
        Self::register_module_output(stack, domain_module)?;
    }
    fn register_module_output(stack: &mut ShutdownStack, output: DomainModuleResult) {
        for resource in output.resources { stack.register_detached(resource); }
        for worker in output.workers { stack.register_with_token(worker); }
    }
}
"#,
        )
    }

    #[test]
    fn event_transport_output_funnel_accepts_unified_live_path() -> Result<()> {
        let root = fixture_root("event-transport-output-green")?;
        write_event_output_fixture(&root)?;
        assert_eq!(
            event_transport_output_findings(&root)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn event_transport_output_funnel_rejects_legacy_and_bypasses() -> Result<()> {
        let root = fixture_root("event-transport-output-red")?;
        write_event_output_fixture(&root)?;
        let event_path = root.join("assemblies/runtime/src/event_transport.rs");
        let runtime_path = root.join(RUNTIME_LIB_PATH);
        let launch_path = root.join(RUNTIME_LAUNCH_PATH);
        let event = fs::read_to_string(&event_path)?;
        let runtime = fs::read_to_string(&runtime_path)?;
        let launch = fs::read_to_string(&launch_path)?;

        for (label, path, mutated) in [
            (
                "public output API",
                &event_path,
                event.replacen(
                    "pub(crate) async fn wire_event_transport",
                    "pub async fn wire_event_transport",
                    1,
                ),
            ),
            (
                "legacy wrapper",
                &event_path,
                format!("struct EventRuntime {{ module: DomainModuleResult }}\n{event}"),
            ),
            (
                "dead resource branch",
                &event_path,
                event.replace(
                    "module.resources.extend(amqp_deps.runtime_resources());",
                    "if false { module.resources.extend(amqp_deps.runtime_resources()); }",
                ),
            ),
            (
                "discard unified output",
                &event_path,
                event.replace("Ok(module)", "Ok(DomainModuleResult::default())"),
            ),
            (
                "clear unified resources",
                &event_path,
                event.replace(
                    "Ok(module)",
                    "module.resources.clear();\n    Ok(module)",
                ),
            ),
            (
                "take unified resources",
                &event_path,
                event.replace(
                    "Ok(module)",
                    "let _ = std::mem::take(&mut module.resources);\n    Ok(module)",
                ),
            ),
            (
                "clear unified workers",
                &event_path,
                event.replace("Ok(module)", "module.workers.clear();\n    Ok(module)"),
            ),
            (
                "take unified probes",
                &event_path,
                event.replace(
                    "Ok(module)",
                    "let _ = std::mem::take(&mut module.probes);\n    Ok(module)",
                ),
            ),
            (
                "wrapped event output",
                &runtime_path,
                runtime.replace(
                    "let event_module = event_transport::wire_event_transport()\n            .await\n            .context(\"wire event transport\")?;",
                    "let event_module = discard(event_transport::wire_event_transport()\n            .await\n            .context(\"wire event transport\")?);",
                ),
            ),
            (
                "output field projection",
                &runtime_path,
                runtime.replace(
                    "let _module = crate::assemble_runtime_module_outputs",
                    "let _ = event_module.resources;\n        let _module = crate::assemble_runtime_module_outputs",
                ),
            ),
            (
                "duplicate event merge",
                &runtime_path,
                runtime.replace(
                    "module.merge(inputs.event_module);",
                    "module.merge(inputs.event_module);\n    module.merge(inputs.event_module);",
                ),
            ),
            (
                "preconsume event module",
                &runtime_path,
                runtime.replace(
                    "module.merge(inputs.event_module);",
                    "inputs.event_module.workers.clear();\n    module.merge(inputs.event_module);",
                ),
            ),
            (
                "event launch field",
                &launch_path,
                launch.replacen(
                    "struct LaunchPlanParts {",
                    "struct LaunchPlanParts { event_infra_guards: Vec<Resource>,",
                    1,
                ),
            ),
            (
                "direct lifecycle bypass",
                &launch_path,
                launch.replace(
                    "Self::register_module_output(stack, domain_module)?;",
                    "Self::register_module_output(stack, domain_module)?;\n        stack.register_detached(event_guard);",
                ),
            ),
            (
                "renamed lifecycle carrier helper bypass",
                &launch_path,
                format!(
                    "{}\nfn register_event_lifecycle(stack: &mut ShutdownStack, event_lifecycle: Vec<Resource>) {{\n    for guard in event_lifecycle {{ stack.register_detached(guard); }}\n}}\n",
                    launch
                        .replacen(
                            "struct LaunchPlanParts {",
                            "struct LaunchPlanParts { event_lifecycle: Vec<Resource>,",
                            1,
                        )
                        .replacen(
                            "struct LaunchPlan {",
                            "struct LaunchPlan { event_lifecycle: Vec<Resource>,",
                            1,
                        )
                        .replace(
                            "let Self { trace_exporter, pg_runtime_module, domain_module } = self;",
                            "let Self { trace_exporter, pg_runtime_module, domain_module, event_lifecycle } = self;",
                        )
                        .replace(
                            "Self::register_module_output(stack, domain_module)?;",
                            "Self::register_module_output(stack, domain_module)?;\n        register_event_lifecycle(stack, event_lifecycle);",
                        )
                ),
            ),
        ] {
            write(path, &mutated)?;
            assert!(
                !event_transport_output_findings(&root)?.is_empty(),
                "{label} must fail"
            );
            write(&event_path, &event)?;
            write(&runtime_path, &runtime)?;
            write(&launch_path, &launch)?;
        }
        Ok(())
    }

    fn provider_adapter_fixture() -> &'static str {
        r#"
trait ProviderOutput { const OUTPUT_BINDINGS: &'static [ProviderOutputBinding]; fn provider_output(&self) -> DomainModuleResult; }
impl ProviderOutput for RedisRuntimeDeps { const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[ProviderOutputBinding { port: "redis", provider: "redis", consumer: "runtime", channels: &[LifecycleChannel::Resources] }]; fn provider_output(&self) -> DomainModuleResult { DomainModuleResult { resources: self.runtime_resources(), ..DomainModuleResult::default() } } }
impl ProviderOutput for S3RuntimeDeps { const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[ProviderOutputBinding { port: "s3", provider: "s3", consumer: "runtime", channels: &[LifecycleChannel::Resources] }]; fn provider_output(&self) -> DomainModuleResult { DomainModuleResult { resources: self.runtime_resources(), ..DomainModuleResult::default() } } }
impl ProviderOutput for VaultRuntimeDeps { const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[ProviderOutputBinding { port: "vault", provider: "vault", consumer: "runtime", channels: &[LifecycleChannel::Resources] }]; fn provider_output(&self) -> DomainModuleResult { DomainModuleResult { resources: self.runtime_resources(), ..DomainModuleResult::default() } } }
fn build_provider_module(deps: &SharedRuntimeDeps) -> DomainModuleResult {
    let mut provider_module = DomainModuleResult::default();
    provider_module.merge_provider(&deps.redis);
    provider_module.merge_provider(&deps.s3);
    provider_module.merge_provider(&deps.vault);
    provider_module
}
fn build_pg_runtime_module(owner: PgRuntimeDeps, period: Duration) -> DomainModuleResult {
    let (resources, sampler_factory) = owner.into_runtime_parts(period);
    let readiness_sampler: WorkerSpec =
        Box::new(move |token| DynManagedResource::new_box(sampler_factory.spawn(token)));
    DomainModuleResult { resources, workers: vec![readiness_sampler], ..DomainModuleResult::default() }
}
"#
    }

    fn write_provider_fixture(root: &Path) -> Result<()> {
        write(
            &root.join(PROVIDER_OUTPUT_FIXTURE_MARKER),
            "provider-output\n",
        )?;
        write(&root.join(RUNTIME_LIB_PATH), &provider_output_fixture())?;
        write(&root.join(PROVIDER_OUTPUT_PATH), provider_adapter_fixture())?;
        write(
            &root.join(RUNTIME_LAUNCH_PATH),
            r#"
impl LaunchPlan {
    fn register(self, stack: &mut ShutdownStack) {
        let Self { trace_exporter, pg_runtime_module, domain_module } = self;
        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }
        Self::register_module_output(stack, pg_runtime_module)?;
        Self::register_module_output(stack, domain_module)?;
    }
    fn register_module_output(stack: &mut ShutdownStack, output: DomainModuleResult) {
        for resource in output.resources { stack.register_detached(resource); }
        for worker in output.workers { stack.register_with_token(worker); }
    }
}
"#,
        )
    }

    #[test]
    fn runtime_provider_outputs_accept_unified_live_path() -> Result<()> {
        let root = fixture_root("runtime-provider-outputs-green")?;
        write_provider_fixture(&root)?;

        write(
            &root.join("assemblies/runtime/src/event_transport.rs"),
            r#"
async fn wire_durable() {
    let mut module = DomainModuleResult::default();
    for (domain_upper, url) in &per_domain {
        let domain = domain_upper.to_ascii_lowercase();
        let amqp_deps = amqp::AmqpRuntimeDeps::connect(url.as_ref(), &domain, publish_timeout).await?;
        module.resources.extend(amqp_deps.runtime_resources());
        amqp_map.insert(domain, amqp_deps);
    }
    Ok(module)
}
"#,
        )?;

        assert_eq!(
            provider_outputs_live_findings(&root)?,
            Vec::<Finding<Rule>>::new()
        );

        let provider_output = root.join(PROVIDER_OUTPUT_PATH);
        let canonical_provider = fs::read_to_string(&provider_output)?;
        let three_channel_provider = canonical_provider.replacen(
            "DomainModuleResult { resources: self.runtime_resources(), ..DomainModuleResult::default() }",
            "DomainModuleResult { probes: Vec::new(), resources: self.runtime_resources(), workers: Vec::new(), ..DomainModuleResult::default() }",
            1,
        );
        write(&provider_output, &three_channel_provider)?;
        assert_eq!(
            provider_outputs_live_findings(&root)?,
            Vec::<Finding<Rule>>::new(),
            "ProviderOutput gate 不得把 DomainModuleResult 冻结成 resources-only"
        );
        write(&provider_output, &canonical_provider)?;

        let event_transport = root.join("assemblies/runtime/src/event_transport.rs");
        let canonical = fs::read_to_string(&event_transport)?;
        for (label, mutated) in [
            (
                "dead branch",
                canonical.replace(
                    "        module.resources.extend(amqp_deps.runtime_resources());",
                    "        if false { module.resources.extend(amqp_deps.runtime_resources()); }",
                ),
            ),
            (
                "dead closure",
                canonical.replace(
                    "        module.resources.extend(amqp_deps.runtime_resources());",
                    "        let _dead = || module.resources.extend(amqp_deps.runtime_resources());",
                ),
            ),
            (
                "outside connection loop",
                canonical.replace(
                    "        module.resources.extend(amqp_deps.runtime_resources());",
                    "",
                ) + "\nfn bypass() { module.resources.extend(amqp_deps.runtime_resources()); }\n",
            ),
        ] {
            write(&event_transport, &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&event_transport, &canonical)?;
        Ok(())
    }

    #[test]
    fn runtime_provider_outputs_reject_parallel_pg_output_type() -> Result<()> {
        let root = fixture_root("runtime-provider-outputs-pg-output-red")?;
        write_provider_fixture(&root)?;
        let adapter =
            fs::read_to_string(root.join(PROVIDER_OUTPUT_PATH))? + "\nstruct PgRuntimeOutput;\n";
        write(&root.join(PROVIDER_OUTPUT_PATH), &adapter)?;

        let findings = provider_outputs_live_findings(&root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenWiring
                    && finding.detail.contains("DomainModuleResult")
            }),
            "PgRuntimeOutput parallel seam must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_provider_outputs_allow_pg_local_renames_and_helper_return() -> Result<()> {
        let root = fixture_root("runtime-provider-outputs-pg-semantic-green")?;
        write_provider_fixture(&root)?;
        let adapter = provider_adapter_fixture()
            .replace("resources, sampler_factory", "guards, readiness_factory")
            .replace("readiness_sampler", "sampler_worker")
            .replace("sampler_factory.spawn(token)", "readiness_factory.spawn(cancel)")
            .replace("move |token|", "move |cancel|")
            .replace(
                "DomainModuleResult { resources, workers: vec![sampler_worker], ..DomainModuleResult::default() }",
                "identity(DomainModuleResult { resources: guards, workers: vec![sampler_worker], ..DomainModuleResult::default() })",
            )
            + "\nfn identity(output: DomainModuleResult) -> DomainModuleResult { output }\n";
        write(&root.join(PROVIDER_OUTPUT_PATH), &adapter)?;

        assert_eq!(
            provider_outputs_live_findings(&root)?,
            Vec::<Finding<Rule>>::new(),
            "semantic PG lifecycle gate must not freeze local names or a transparent return helper"
        );
        Ok(())
    }

    #[test]
    fn runtime_provider_outputs_reject_noncanonical_ast_shapes() -> Result<()> {
        let root = fixture_root("runtime-provider-outputs-ast-red")?;
        write_provider_fixture(&root)?;
        fs::remove_file(root.join(PROVIDER_OUTPUT_PATH))?;
        assert_provider_gate_fails(&root, "missing provider_output.rs")?;

        let adapter = provider_adapter_fixture();
        for (label, mutated) in [
            (
                "helper return",
                adapter.replace(
                    "    provider_module\n}",
                    "    identity(provider_module)\n}\nfn identity(output: DomainModuleResult) -> DomainModuleResult { output }",
                ),
            ),
            (
                "builder reset",
                adapter.replace(
                    "    provider_module\n}",
                    "    provider_module = DomainModuleResult::default();\n    provider_module\n}",
                ),
            ),
            (
                "builder clear",
                adapter.replace(
                    "    provider_module\n}",
                    "    provider_module.resources.clear();\n    provider_module\n}",
                ),
            ),
            (
                "wrong constructor return",
                adapter.replace(
                    "    provider_module\n}",
                    "    DomainModuleResult::default()\n}",
                ),
            ),
            (
                "discard runtime resources",
                adapter.replacen(
                    "resources: self.runtime_resources()",
                    "resources: { let _ = self.runtime_resources(); Vec::new() }",
                    1,
                ),
            ),
            (
                "identity wrapped runtime resources",
                adapter.replacen(
                    "resources: self.runtime_resources()",
                    "resources: identity(self.runtime_resources())",
                    1,
                ) + "\nfn identity<T>(value: T) -> T { value }\n",
            ),
            (
                "wrong provider output",
                adapter.replacen(
                    "resources: self.runtime_resources()",
                    "resources: Vec::new()",
                    1,
                ),
            ),
            (
                "default trait method",
                adapter.replace(
                    "fn provider_output(&self) -> DomainModuleResult;",
                    "fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() }",
                ),
            ),
            (
                "missing typed output evidence",
                adapter.replacen(
                    "const OUTPUT_BINDINGS: &'static [ProviderOutputBinding] = &[ProviderOutputBinding { port: \"redis\", provider: \"redis\", consumer: \"runtime\", channels: &[LifecycleChannel::Resources] }]; ",
                    "",
                    1,
                ),
            ),
            (
                "extra provider impl",
                adapter.to_string()
                    + "\nimpl ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } }\n",
            ),
            (
                "nested extra provider impl",
                adapter.to_string()
                    + "\nmod extra { impl ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } } }\n",
            ),
        ] {
            write(&root.join(PROVIDER_OUTPUT_PATH), &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&root.join(PROVIDER_OUTPUT_PATH), adapter)?;

        let runtime = provider_output_fixture();
        for (label, mutated) in [
            (
                "destructured constructor",
                runtime.replace(
                    "let provider_module = crate::provider_output::build_provider_module(&deps);",
                    "let (provider_module,) = (crate::provider_output::build_provider_module(&deps),);",
                ),
            ),
            (
                "mutable run binding",
                runtime.replace("let provider_module =", "let mut provider_module ="),
            ),
            (
                "assigned run binding",
                runtime.replace(
                    "let provider_module = crate::provider_output::build_provider_module(&deps);",
                    "let provider_module = crate::provider_output::build_provider_module(&deps);\nprovider_module = DomainModuleResult::default();",
                ),
            ),
            (
                "local shadow constructor",
                runtime.replace(
                    "let provider_module = crate::provider_output::build_provider_module(&deps);",
                    "fn build_provider_module(_: &SharedRuntimeDeps) -> DomainModuleResult { DomainModuleResult::default() }\nlet provider_module = build_provider_module(&deps);",
                ),
            ),
            (
                "local module shadow constructor",
                runtime.replace(
                    "let provider_module = crate::provider_output::build_provider_module(&deps);",
                    "mod provider_output { pub(super) fn build_provider_module(_: &super::SharedRuntimeDeps) -> super::DomainModuleResult { super::DomainModuleResult::default() } }\nlet provider_module = provider_output::build_provider_module(&deps);",
                ),
            ),
            (
                "local shadow assembler",
                runtime.replace(
                    "let _module = crate::assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {",
                    "fn assemble_runtime_module_outputs(_: RuntimeModuleAssemblyInputs) -> DomainModuleResult { DomainModuleResult::default() }\nlet _module = assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {",
                ),
            ),
        ] {
            write(&root.join(RUNTIME_LIB_PATH), &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        Ok(())
    }

    fn assert_provider_gate_fails(root: &Path, label: &str) -> Result<()> {
        let findings = provider_outputs_live_findings(root)?;
        assert!(!findings.is_empty(), "{label} 必须失败");
        Ok(())
    }

    fn assert_unrelated_provider_method_names_allowed(
        root: &Path,
        source_path: &Path,
    ) -> Result<()> {
        for (source, message) in [
            (
                "fn runtime_resources() {}\nfn unrelated() { runtime_resources(); }\n",
                "无关同名本地函数不得误报",
            ),
            (
                r#"
struct LocalResources;
impl LocalResources {
    fn runtime_resources(&self) {}
    fn delegates(&self) { self.runtime_resources(); }
}
struct LocalModule;
impl LocalModule { fn merge_provider(&mut self) {} }
struct Wrapper { redis: LocalResources }
fn local_resources() -> LocalResources { LocalResources }
fn unrelated(resources: &LocalResources, module: &mut LocalModule, wrapper: &Wrapper) {
    resources.runtime_resources();
    LocalResources::runtime_resources(resources);
    local_resources().runtime_resources();
    wrapper.redis.runtime_resources();
    module.merge_provider();
}
fn external_unrelated(resources: &ExternalResources) { resources.runtime_resources(); }
mod fake { pub struct RedisRuntimeDeps; }
use fake::RedisRuntimeDeps as FakeRedis;
fn qualified_same_name(resources: &fake::RedisRuntimeDeps, alias: &FakeRedis) {
    resources.runtime_resources();
    alias.runtime_resources();
}
"#,
                "有本地类型/方法来源的同名 API 不得误报",
            ),
            (
                "mod fake { pub struct RedisRuntimeDeps; }\nuse fake::RedisRuntimeDeps;\nfn unrelated(resources: &RedisRuntimeDeps) { resources.runtime_resources(); }\n",
                "非 provider 模块的未重命名同名类型不得误报",
            ),
            (
                "struct RedisRuntimeDeps;\nimpl RedisRuntimeDeps { fn runtime_resources(&self) {} }\nfn unrelated(resources: &RedisRuntimeDeps) { resources.runtime_resources(); }\n",
                "本地同名类型声明必须遮蔽 provider 裸名",
            ),
            (
                "mod local { struct RedisRuntimeDeps; impl RedisRuntimeDeps { fn runtime_resources(&self) {} } fn unrelated(resources: &RedisRuntimeDeps) { resources.runtime_resources(); } }\n",
                "inline module 的本地同名类型必须按作用域遮蔽",
            ),
            (
                "fn unrelated() { struct RedisRuntimeDeps; impl RedisRuntimeDeps { fn runtime_resources(&self) {} } let resources: RedisRuntimeDeps = todo!(); resources.runtime_resources(); }\n",
                "block-local 同名类型必须按作用域遮蔽",
            ),
        ] {
            write(source_path, source)?;
            let findings = provider_outputs_live_findings(root)?;
            assert!(
                findings.iter().all(|finding| {
                    finding.subject != "assemblies/runtime/src/legacy_provider.rs"
                }),
                "{message}: {findings:?}"
            );
        }
        Ok(())
    }

    fn assert_test_only_provider_items_allowed(root: &Path, source_path: &Path) -> Result<()> {
        for source in [
            "#[cfg(test)] fn test_only(module: &mut DomainModuleResult, deps: &SharedRuntimeDeps) { module.merge_provider(&deps.redis); }\n",
            "#[cfg(test)] impl crate::provider_output::ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } }\n",
            "#[cfg(all(test, feature = \"fixture\"))] impl crate::provider_output::ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } }\n",
            "#[cfg(test)] mod tests;\n",
        ] {
            write(source_path, source)?;
            let findings = provider_outputs_live_findings(root)?;
            assert!(
                findings.iter().all(|finding| {
                    finding.subject != "assemblies/runtime/src/legacy_provider.rs"
                }),
                "test=false 时恒假的 cfg 必须排除生产扫描: {findings:?}"
            );
        }
        let out_of_line = source_path
            .parent()
            .context("legacy provider fixture parent")?
            .join("legacy_provider/tests.rs");
        write(
            &out_of_line,
            "fn test_only(deps: &SharedRuntimeDeps) { deps.redis.runtime_resources(); }\n",
        )?;
        write(source_path, "#[cfg(test)] mod tests;\n")?;
        let mut sources = Vec::new();
        collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut sources)?;
        let production = production_module_sources(&sources)?;
        assert!(
            !production.contains(&normalize_path(&out_of_line)),
            "out-of-line test module 仍被判为生产可达: source={} child={} production={production:?}",
            source_path.display(),
            out_of_line.display()
        );
        let findings = provider_outputs_live_findings(root)?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.subject != "assemblies/runtime/src/legacy_provider/tests.rs"),
            "test-only out-of-line module 必须排除生产扫描: {findings:?}"
        );
        fs::remove_file(out_of_line)?;

        let inline_test_child = source_path
            .parent()
            .context("legacy provider fixture parent")?
            .join("legacy_provider/tests/helper.rs");
        write(
            &inline_test_child,
            "fn test_only(deps: &SharedRuntimeDeps) { deps.redis.runtime_resources(); }\n",
        )?;
        write(source_path, "#[cfg(test)] mod tests { mod helper; }\n")?;
        let findings = provider_outputs_live_findings(root)?;
        assert!(
            findings.iter().all(|finding| {
                finding.subject != "assemblies/runtime/src/legacy_provider/tests/helper.rs"
            }),
            "inline test module 的 out-of-line child 必须继承 test-only: {findings:?}"
        );
        fs::remove_file(inline_test_child)?;

        let shared = source_path
            .parent()
            .context("legacy provider fixture parent")?
            .join("legacy_provider/prod/shared.rs");
        write(
            &shared,
            "fn bypass(deps: &SharedRuntimeDeps) { deps.redis.runtime_resources(); }\n",
        )?;
        write(
            source_path,
            "mod prod { #[path = \"shared.rs\"] mod helper; }\n#[cfg(test)] #[path = \"prod/shared.rs\"] mod bait;\n",
        )?;
        let findings = provider_outputs_live_findings(root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.subject == "assemblies/runtime/src/legacy_provider/prod/shared.rs"
                    && finding.rule == Rule::ForbiddenWiring
            }),
            "同一文件兼具 production/test 路径时 production 可达必须优先: {findings:?}"
        );
        fs::remove_file(shared)?;
        Ok(())
    }

    #[test]
    fn runtime_provider_outputs_reject_missing_reordered_legacy_and_bait() -> Result<()> {
        let root = fixture_root("runtime-provider-outputs-red")?;
        write_provider_fixture(&root)?;
        let adapter = provider_adapter_fixture();
        let reordered = adapter.replace(
            "    provider_module.merge_provider(&deps.redis);\n    provider_module.merge_provider(&deps.s3);",
            "    provider_module.merge_provider(&deps.s3);\n    provider_module.merge_provider(&deps.redis);",
        );
        write(&root.join(PROVIDER_OUTPUT_PATH), &reordered)?;
        let findings = provider_outputs_live_findings(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring),
            "Redis/S3/Vault 顺序漂移必须失败: {findings:?}"
        );
        write(
            &root.join(PROVIDER_OUTPUT_PATH),
            &(adapter.to_string()
                + "\nfn extra(deps: &RedisRuntimeDeps) { RedisRuntimeDeps::runtime_resources(deps); }\n"),
        )?;
        let findings = provider_outputs_live_findings(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring),
            "provider_output.rs 内 UFCS 额外直连必须失败: {findings:?}"
        );
        write(&root.join(PROVIDER_OUTPUT_PATH), adapter)?;
        for (label, mutated) in [
            (
                "borrowed pg owner",
                adapter.replace(
                    "owner: PgRuntimeDeps, period: Duration",
                    "owner: &PgRuntimeDeps, period: Duration",
                ),
            ),
            (
                "borrowed pg period",
                adapter.replace(
                    "owner: PgRuntimeDeps, period: Duration",
                    "owner: PgRuntimeDeps, period: &Duration",
                ),
            ),
            (
                "missing pg constructor",
                adapter.replace("fn build_pg_runtime_module", "fn removed_pg_runtime_module"),
            ),
            ("duplicate pg constructor", format!("{adapter}\n{adapter}")),
            (
                "legacy pg lifecycle direct call",
                format!(
                    "{adapter}\nfn legacy(owner: &PgRuntimeDeps) {{ owner.spawn_readiness_sampler(); }}\n"
                ),
            ),
            (
                "discard pg resources",
                adapter.replace(
                    "DomainModuleResult { resources, workers: vec![readiness_sampler], ..DomainModuleResult::default() }",
                    "DomainModuleResult { resources: Vec::new(), workers: vec![readiness_sampler], ..DomainModuleResult::default() }",
                ),
            ),
            (
                "discard sampler factory result",
                adapter.replace(
                    "let readiness_sampler: WorkerSpec =\n        Box::new(move |token| DynManagedResource::new_box(sampler_factory.spawn(token)));",
                    "let readiness_sampler: WorkerSpec =\n        Box::new(move |token| { let _ = sampler_factory.spawn(token); DynManagedResource::new_box(fake_worker) });",
                ),
            ),
            (
                "fake readiness worker",
                adapter.replace(
                    "let readiness_sampler: WorkerSpec =\n        Box::new(move |token| DynManagedResource::new_box(sampler_factory.spawn(token)));",
                    "let readiness_sampler: WorkerSpec = { let _bait = Box::new(move |token| DynManagedResource::new_box(sampler_factory.spawn(token))); fake_worker };",
                ),
            ),
            (
                "pg output field substitution",
                adapter.replace(
                    "DomainModuleResult { resources, workers: vec![readiness_sampler], ..DomainModuleResult::default() }",
                    "DomainModuleResult { resources, workers: vec![fake_worker], ..DomainModuleResult::default() }",
                ),
            ),
        ] {
            write(&root.join(PROVIDER_OUTPUT_PATH), &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&root.join(PROVIDER_OUTPUT_PATH), adapter)?;
        let missing_assembly_merge = provider_output_fixture().replace(
            "    module.merge(inputs.provider_module);",
            "    let _ = inputs.provider_module;",
        );
        write(&root.join(RUNTIME_LIB_PATH), &missing_assembly_merge)?;
        let findings = provider_outputs_live_findings(&root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::MissingAnchor && finding.detail.contains("provider_module")
            }),
            "assemble 函数外的 merge bait 不能满足门禁: {findings:?}"
        );

        for extra in [
            "    let provider_module = DomainModuleResult::default();\n",
            "    let provider_alias = crate::provider_output::build_provider_module(&deps);\n",
        ] {
            let reset = provider_output_fixture().replace(
                "    let provider_module = crate::provider_output::build_provider_module(&deps);\n",
                &format!(
                    "    let provider_module = crate::provider_output::build_provider_module(&deps);\n{extra}"
                ),
            );
            write(&root.join(RUNTIME_LIB_PATH), &reset)?;
            let findings = provider_outputs_live_findings(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingAnchor),
                "constructor 后 reset/alias 必须失败: {findings:?}"
            );
        }
        for (label, mutated) in [
            (
                "borrowed pg owner at run",
                provider_output_fixture().replace(
                    "build_pg_runtime_module(pg_owner, pg_readiness_period)",
                    "build_pg_runtime_module(&pg_owner, pg_readiness_period)",
                ),
            ),
            (
                "duplicate pg build outside run",
                provider_output_fixture()
                    + "\nfn bait() { crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period); }\n",
            ),
            (
                "pg output not handed to launch plan",
                provider_output_fixture().replace(
                    "let _launch_plan = LaunchPlanParts { pg_runtime_module };",
                    "let _ = pg_runtime_module;",
                ),
            ),
        ] {
            write(&root.join(RUNTIME_LIB_PATH), &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&root.join(RUNTIME_LIB_PATH), &provider_output_fixture())?;
        let legacy_source = root.join("assemblies/runtime/src/legacy_provider.rs");
        for source in [
            "fn legacy(deps: &SharedRuntimeDeps) { let redis = &deps.redis; redis.runtime_resources(); }\n",
            "fn typed() { let redis: RedisRuntimeDeps = todo!(); redis.runtime_resources(); }\n",
            "fn ufcs(redis: &RedisRuntimeDeps) { RedisRuntimeDeps::runtime_resources(redis); }\n",
            "fn qualified_self_ufcs(redis: &redis_adapter::RedisRuntimeDeps) { <redis_adapter::RedisRuntimeDeps>::runtime_resources(redis); }\n",
            "fn get(deps: &SharedRuntimeDeps) -> &RedisRuntimeDeps { &deps.redis }\nfn helper_return(deps: &SharedRuntimeDeps) { get(deps).runtime_resources(); }\n",
            "fn identity<T>(value: T) -> T { value }\nfn generic_helper(deps: &SharedRuntimeDeps) { identity(&deps.redis).runtime_resources(); }\n",
            "mod helpers { fn get(deps: &SharedRuntimeDeps) -> &RedisRuntimeDeps { &deps.redis } }\nfn qualified_helper(deps: &SharedRuntimeDeps) { helpers::get(deps).runtime_resources(); }\n",
            "type Cache<T> = T;\nfn generic_alias(deps: &SharedRuntimeDeps) { let redis: Cache<&RedisRuntimeDeps> = &deps.redis; redis.runtime_resources(); }\n",
            "fn merge(module: &mut DomainModuleResult, deps: &SharedRuntimeDeps) { module.merge_provider(&deps.redis); }\n",
            "fn merge_ufcs(module: &mut DomainModuleResult, deps: &SharedRuntimeDeps) { DomainModuleResultExt::merge_provider(module, &deps.redis); }\n",
            "fn merge_qualified(module: &mut DomainModuleResult, deps: &SharedRuntimeDeps) { crate::provider_output::DomainModuleResultExt::merge_provider(module, &deps.redis); }\n",
            "impl crate::provider_output::ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } }\n",
            "#[cfg(any(test, unix))] impl crate::provider_output::ProviderOutput for PgRuntimeDeps { fn provider_output(&self) -> DomainModuleResult { DomainModuleResult::default() } }\n",
            concat!(
                "use redis_adapter::RedisRuntimeDeps as CacheDeps;\n",
                "fn legacy_alias(deps: &CacheDeps) { deps.runtime_resources(); }\n",
            ),
            "use redis_adapter as cache;\nfn module_alias(deps: &cache::RedisRuntimeDeps) { deps.runtime_resources(); }\n",
            "use redis_adapter::{self as cache};\nfn grouped_module_alias(deps: &cache::RedisRuntimeDeps) { deps.runtime_resources(); }\n",
            "extern crate redis_adapter as cache;\nfn extern_crate_alias(deps: &cache::RedisRuntimeDeps) { deps.runtime_resources(); }\n",
        ] {
            write(&legacy_source, source)?;
            let findings = provider_outputs_live_findings(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "production helper/alias 中的 runtime_resources 直连必须失败: {findings:?}"
            );
        }
        assert_unrelated_provider_method_names_allowed(&root, &legacy_source)?;
        assert_test_only_provider_items_allowed(&root, &legacy_source)?;
        write(
            &legacy_source,
            "fn spawn(factory: postgres::PgReadinessSamplerFactory, token: CancellationToken) { factory.spawn(token); }\n",
        )?;
        assert_provider_gate_fails(&root, "factory spawn outside canonical helper")?;
        fs::remove_file(&legacy_source)?;

        let launch_path = root.join(RUNTIME_LAUNCH_PATH);
        let canonical_launch = fs::read_to_string(&launch_path)?;
        for (label, mutated) in [
            (
                "pg registration before trace",
                canonical_launch.replace(
                    "        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }\n        Self::register_module_output(stack, pg_runtime_module)?;",
                    "        Self::register_module_output(stack, pg_runtime_module)?;\n        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }",
                ),
            ),
            (
                "duplicate pg registration",
                canonical_launch.replace(
                    "        Self::register_module_output(stack, pg_runtime_module)?;",
                    "        Self::register_module_output(stack, pg_runtime_module)?;\n        Self::register_module_output(stack, pg_runtime_module)?;",
                ),
            ),
            (
                "legacy direct pg registration",
                canonical_launch.replace(
                    "        Self::register_module_output(stack, pg_runtime_module)?;",
                    "        stack.register_detached(pg_store_guard);",
                ),
            ),
        ] {
            write(&launch_path, &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&launch_path, &canonical_launch)?;
        write(&root.join(RUNTIME_LIB_PATH), "pub async fn run( {\n")?;
        assert!(!provider_outputs_live_findings(&root)?.is_empty());
        write(&root.join(RUNTIME_LIB_PATH), &provider_output_fixture())?;
        write(&legacy_source, "fn broken( {\n")?;
        assert!(!provider_outputs_live_findings(&root)?.is_empty());
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
    fn runtime_baseline_requires_config_snapshot_before_provider_construction() -> Result<()> {
        let root = fixture_root("runtime-baseline-config-snapshot-before-provider")?;
        let mut lines = Vec::new();
        let snapshot = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.config.snapshot")
            .context("config snapshot anchor")?;
        let oidc = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.provider.oidc")
            .context("oidc anchor")?;
        lines.push(oidc.pattern);
        lines.push(snapshot.pattern);
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH)
        {
            if matches!(anchor.id, "run.config.snapshot" | "run.provider.oidc") {
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
            report.findings.iter().any(|finding| {
                finding.rule == Rule::MissingAnchor && finding.detail.contains("run.provider.oidc")
            }),
            "configuration snapshot must precede provider construction"
        );
        Ok(())
    }

    #[test]
    fn runtime_config_snapshot_rejects_ambient_provider_readers() -> Result<()> {
        let root = fixture_root("runtime-config-snapshot-rejects-ambient-readers")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let runtime_path = root.join(RUNTIME_LIB_PATH);
        let mut runtime = fs::read_to_string(&runtime_path)?;
        for (snapshot_reader, ambient_reader) in [
            (
                "build_vault_runtime_deps(config_value)",
                "build_vault_runtime_deps(|name| std::env::var(name).ok())",
            ),
            (
                "build_redis_runtime_deps(config_value)",
                "build_redis_runtime_deps(|name| std::env::var(name).ok())",
            ),
            (
                "build_s3_runtime_deps_from(config_value)",
                "build_s3_runtime_deps_from(|name| std::env::var(name).ok())",
            ),
        ] {
            assert!(
                runtime.contains(snapshot_reader),
                "fixture missing {snapshot_reader}"
            );
            runtime = runtime.replace(snapshot_reader, ambient_reader);
        }
        write(&runtime_path, &runtime)?;

        let report = collect_report(&root)?;
        for anchor_id in [
            "run.provider.vault",
            "run.provider.redis",
            "run.provider.s3",
        ] {
            assert!(
                report.findings.iter().any(|finding| {
                    finding.rule == Rule::MissingAnchor && finding.detail.contains(anchor_id)
                }),
                "restoring ambient reader must fail {anchor_id}"
            );
        }

        let canonical = r#"
pub async fn run() {
    let runtime_config = RuntimeConfigSnapshot::capture(EnvConfigSource);
    let runtime_inputs = RuntimeInputs::new(runtime_config, None);
    let config_value = |name: &str| {
        runtime_inputs
            .config()
            .get(name)
            .map(|value| value.expose().to_owned())
    };
    let vault = build_vault_runtime_deps(config_value);
    let redis = build_redis_runtime_deps(config_value);
    let s3 = build_s3_runtime_deps_from(config_value);
}
"#;
        let canonical_file = syn::parse_file(canonical)?;
        assert!(
            runtime_config_snapshot_findings_for_file(&canonical_file).is_empty(),
            "canonical snapshot funnel must pass"
        );
        write(&runtime_path, canonical)?;
        let report = collect_report(&root)?;
        let is_config_finding = |finding: &Finding<Rule>| {
            finding.rule == Rule::ForbiddenWiring
                && finding.subject == RUNTIME_LIB_PATH
                && finding.detail.contains("configuration snapshot")
        };
        assert!(
            !report.findings.iter().any(is_config_finding),
            "canonical fixture must pass the live collect_report entry"
        );

        let ambient_closure = canonical.replace(
            "runtime_inputs\n            .config()\n            .get(name)\n            .map(|value| value.expose().to_owned())",
            "std::env::var(name).ok()",
        );
        write(&runtime_path, &ambient_closure)?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(is_config_finding),
            "live collect_report entry must reject ambient origin without changing provider anchors"
        );
        for (label, mutated) in [
            ("ambient config_value origin", ambient_closure),
            (
                "duplicate snapshot capture",
                canonical.replace(
                    "let runtime_config = RuntimeConfigSnapshot::capture(EnvConfigSource);",
                    "let _snapshot_bait = RuntimeConfigSnapshot::capture(EnvConfigSource);\n    let runtime_config = RuntimeConfigSnapshot::capture(EnvConfigSource);",
                ),
            ),
            (
                "vault ambient call beside compliant bait",
                canonical.replace(
                    "let vault = build_vault_runtime_deps(config_value);",
                    "let _vault_bait = build_vault_runtime_deps(config_value);\n    let vault = build_vault_runtime_deps(|name| std::env::var(name).ok());",
                ),
            ),
            (
                "redis ambient call beside compliant bait",
                canonical.replace(
                    "let redis = build_redis_runtime_deps(config_value);",
                    "let _redis_bait = build_redis_runtime_deps(config_value);\n    let redis = build_redis_runtime_deps(|name| std::env::var(name).ok());",
                ),
            ),
            (
                "s3 ambient call beside compliant bait",
                canonical.replace(
                    "let s3 = build_s3_runtime_deps_from(config_value);",
                    "let _s3_bait = build_s3_runtime_deps_from(config_value);\n    let s3 = build_s3_runtime_deps_from(|name| std::env::var(name).ok());",
                ),
            ),
            (
                "captured snapshot discarded before RuntimeInputs",
                canonical.replace(
                    "let runtime_inputs = RuntimeInputs::new(runtime_config, None);",
                    "let _discarded = runtime_config;\n    let runtime_inputs = RuntimeInputs::new(snapshot_from_helper(), None);",
                ),
            ),
        ] {
            let file = syn::parse_file(&mutated)?;
            assert!(
                runtime_config_snapshot_findings_for_file(&file)
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "snapshot funnel must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_secret_transfer_allowlist_rejects_extra_handoff() -> Result<()> {
        let root = fixture_root("runtime-secret-transfer-allowlist")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let path = root.join("assemblies/runtime/src/event_transport.rs");
        let canonical =
            "fn build_dlx_vault_key_providers_from() { hot_token.transfer_secret_allocation(); }\n";
        write(&path, canonical)?;
        let has_transfer_finding = |report: &Report| {
            report.findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenWiring
                    && finding.detail.contains("secret transfer allowlist")
            })
        };
        assert!(!has_transfer_finding(&collect_report(&root)?));
        write(
            &path,
            &(canonical.to_owned() + "fn leak() { copied_secret.transfer_secret_allocation(); }\n"),
        )?;
        assert!(has_transfer_finding(&collect_report(&root)?));
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
Self::register_module_output(stack, pg_runtime_module)?;
Self::register_module_output(stack, domain_module)?;
}
fn register_module_output() {
for worker in output.workers
for resource in output.resources
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
                .contains("launch.shutdown.workers | assemblies/runtime/src/launch.rs | for worker in output.workers | status=out-of-order"),
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
                "fn register() {{\n{}\n}}\n#[cfg(test)] mod tests {{ fn register() {{\n{}\n}} }}\nimpl LaunchPlan {{ fn register() {{\n{}\n}}\nfn register_module_output() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\n{}\n}}\n",
                launch_register_anchor_lines(None),
                launch_register_anchor_lines(None),
                launch_register_anchor_lines(None),
                launch_module_registration_anchor_lines(Some("launch.shutdown.resources")),
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
                "impl LaunchPlan {{ fn register() {{\n{}\n}}\nfn register_module_output() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\nbind_and_register(&mut stack, listener, &addr_resolver).await?;\nlet listeners = plan.register(&mut stack)?;\n}}\n",
                launch_register_anchor_lines(None),
                launch_module_registration_anchor_lines(None)
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
                runtime_lib_fixture(Some("run.wire.generated-domains")),
                "modules_gen::wire_domains(&deps);"
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.generated-domains")
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
                runtime_anchor_lines(Some("run.wire.generated-domains")),
                "modules_gen::wire_domains(&deps);",
                "modules_gen::wire_domains(&deps);"
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.generated-domains")
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
