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
//! INVARIANT: RUNTIME-CONFIG-SNAPSHOT-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_vault_s3_snapshot_wiring", anti_vacuity = "tests::runtime_vault_s3_snapshot_wiring" } -- the unique production `prepare_runtime()` calls exactly one closed process snapshot factory and seals the password blocklist into `ServingRuntimeInputs`, while `prepare_operator_runtime()` produces an exact `OperatorRuntimeInputs` that cannot carry that serving capability. `run_startup()` maps the serving snapshot view once into the exact serving, PG, Redis, Vault, and S3 generations; the serving aggregate is then consumed by value as event transport, domain transport, worker, and exact domain-module inputs. Redis and Vault are consumed by value, named S3 parts are destructured once, exact general and DLX parts reach their builders, and canonical PG setup is preserved. Settings ConfigValue maintenance receives one exact `SnapshotConfig` view and consumes one typed Vault generation. Discarded/wrong generations, ambient getter revival, duplicate mapping or consumption, aliases, wrappers, macros, compliant bait, and serving/operator type mixing all fail closed. `SnapshotConfig` plus private typed constructors form the native Hard boundary; exact production flow and ambient-reader exclusivity across the conservatively reachable consumer graph remain this explicit Medium AST gate.
//!
//! INVARIANT: RUNTIME-BINARY-SNAPSHOT-LIFECYCLE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_binary_operator_lifecycle_is_proof_aware", anti_vacuity = "tests::runtime_binary_snapshot_wiring_rejects_duplicate_discarded_and_wrong_bindings" } -- `rss` must classify the closed command family from real process arguments before preparation; serving uniquely prepares and transfers `ServingRuntimeInputs` to `run`, while operator commands prepare only `OperatorRuntimeInputs`, every operator arm receives that exact binding, and the sole operator shutdown consumes it. No shared input type, pre-consumption early return, alias, macro, shadow path, or unreachable bait is accepted.
//!
//! INVARIANT: SECRET-TEXT-TRANSFER-LIVE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff", anti_vacuity = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff" } -- runtime raw secret allocation transfer/copy uses two uniquely named funnels whose seven moves plus one required copy into zeroizing Vault/S3 owners are exact, closed, and bait-resistant; both funnel definitions are independently pinned by the same allowlist.
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
use syn::parse::Parser as _;
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
const SERVER_MAIN_PATH: &str = "bins/server/src/main.rs";
const RSS_MAIN_PATH: &str = "bins/rss/src/main.rs";
const GENERATED_MODULES_PATH: &str = "assemblies/runtime/src/generated/modules_gen.rs";
const RUNTIME_LAUNCH_PATH: &str = "assemblies/runtime/src/launch.rs";
const RUNTIME_EVENT_PATH: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_S3_PATH: &str = "assemblies/runtime/src/infra/s3.rs";
const RUNTIME_VAULT_PATH: &str = "assemblies/runtime/src/infra/vault.rs";
const RUNTIME_PHASE_PATH: &str = "assemblies/runtime/src/phase.rs";
const RUNTIME_SECRET_CONFIG_PATH: &str = "assemblies/runtime/src/secret_config.rs";

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
    findings.extend(runtime_binary_config_findings(root)?);
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
struct PrepareRuntimeConfigWiring {
    snapshot_calls: usize,
    canonical_snapshot_calls: usize,
    snapshot_binding: Option<syn::Ident>,
    password_preload_calls: usize,
    canonical_password_preload_calls: usize,
    password_blocklist_binding: Option<syn::Ident>,
    trace_export_binding: Option<syn::Ident>,
    runtime_inputs_calls: usize,
    canonical_runtime_inputs_calls: usize,
    legacy_runtime_inputs_calls: usize,
    snapshot_config_binding: Option<syn::Ident>,
    snapshot_filter_binding: Option<syn::Ident>,
    snapshot_filter_bindings: usize,
    subscriber_filter_uses: usize,
    ambient_rust_log_calls: usize,
}

impl PrepareRuntimeConfigWiring {
    fn is_canonical(&self, require_password_policy: bool) -> bool {
        let password_policy_is_canonical = !require_password_policy
            || (self.password_preload_calls == 1
                && self.canonical_password_preload_calls == 1
                && self.password_blocklist_binding.is_some()
                && self.trace_export_binding.is_some());
        let runtime_inputs_are_canonical = if require_password_policy {
            self.canonical_runtime_inputs_calls == 1
        } else {
            self.canonical_runtime_inputs_calls + self.legacy_runtime_inputs_calls == 1
        };
        self.snapshot_calls == 1
            && self.canonical_snapshot_calls == 1
            && self.snapshot_binding.is_some()
            && password_policy_is_canonical
            && self.runtime_inputs_calls == 1
            && runtime_inputs_are_canonical
            && self.snapshot_config_binding.is_some()
            && self.snapshot_filter_binding.is_some()
            && self.snapshot_filter_bindings == 1
            && self.subscriber_filter_uses == 1
            && self.ambient_rust_log_calls == 0
    }
}

impl<'ast> Visit<'ast> for PrepareRuntimeConfigWiring {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let binding = immutable_pat_ident(&local.pat);
        let initializer = local.init.as_ref().map(|init| init.expr.as_ref());
        if let (Some(binding), Some(initializer)) = (binding, initializer)
            && is_env_snapshot_initializer(initializer)
            && self.snapshot_binding.is_none()
        {
            self.snapshot_binding = Some(binding.clone());
        }
        if let (Some(binding), Some(initializer), Some(snapshot)) =
            (binding, initializer, self.snapshot_binding.as_ref())
            && is_snapshot_view(initializer, snapshot)
            && self.snapshot_config_binding.is_none()
        {
            self.snapshot_config_binding = Some(binding.clone());
        }
        if let (Some(binding), Some(initializer), Some(config)) =
            (binding, initializer, self.snapshot_config_binding.as_ref())
            && is_snapshot_rust_log_filter(initializer, config)
        {
            self.snapshot_filter_bindings += 1;
            if self.snapshot_filter_binding.is_none() {
                self.snapshot_filter_binding = Some(binding.clone());
            }
        }
        if let (Some(initializer), Some(config)) =
            (initializer, self.snapshot_config_binding.as_ref())
            && let Some((password_blocklist, trace_export)) =
                canonical_password_preload_local(&local.pat, initializer, config)
        {
            self.canonical_password_preload_calls += 1;
            if self.password_blocklist_binding.is_none() {
                self.password_blocklist_binding = Some(password_blocklist);
                self.trace_export_binding = Some(trace_export);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(
            &call.func,
            &["RuntimeConfigSnapshot", "capture_process_snapshot"],
        ) {
            self.snapshot_calls += 1;
            if is_process_snapshot_call(call) {
                self.canonical_snapshot_calls += 1;
            }
        }
        if path_ends_with(&call.func, &["seal_password_policy_before_external"]) {
            self.password_preload_calls += 1;
        }
        if path_ends_with(&call.func, &["RuntimeInputs", "new"]) {
            self.runtime_inputs_calls += 1;
            if call.args.len() == 3
                && self.snapshot_binding.as_ref().is_some_and(|snapshot| {
                    call.args
                        .first()
                        .is_some_and(|arg| is_exact_ident_path(arg, snapshot))
                })
                && self
                    .password_blocklist_binding
                    .as_ref()
                    .is_some_and(|password_blocklist| {
                        call.args
                            .iter()
                            .nth(1)
                            .is_some_and(|arg| is_exact_ident_path(arg, password_blocklist))
                    })
                && self
                    .trace_export_binding
                    .as_ref()
                    .is_some_and(|trace_export| {
                        call.args
                            .iter()
                            .nth(2)
                            .is_some_and(|arg| is_exact_ident_path(arg, trace_export))
                    })
            {
                self.canonical_runtime_inputs_calls += 1;
            }
            if call.args.len() == 2
                && self.snapshot_binding.as_ref().is_some_and(|snapshot| {
                    call.args
                        .first()
                        .is_some_and(|arg| is_exact_ident_path(arg, snapshot))
                })
            {
                self.legacy_runtime_inputs_calls += 1;
            }
        }
        if path_ends_with(&call.func, &["EnvFilter", "try_from_default_env"])
            || path_ends_with(&call.func, &["std", "env", "var"])
        {
            self.ambient_rust_log_calls += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "init"
            && call.args.is_empty()
            && let Some(filter) = self.snapshot_filter_binding.as_ref()
        {
            self.subscriber_filter_uses += subscriber_with_binding_count(&call.receiver, filter);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn canonical_password_preload_local(
    pat: &syn::Pat,
    initializer: &syn::Expr,
    config: &syn::Ident,
) -> Option<(syn::Ident, syn::Ident)> {
    let syn::Pat::Tuple(tuple) = pat else {
        return None;
    };
    if tuple.elems.len() != 2 {
        return None;
    }
    let password_blocklist = immutable_pat_ident(tuple.elems.first()?)?.clone();
    let trace_export = immutable_pat_ident(tuple.elems.iter().nth(1)?)?.clone();
    let call = call_behind_result_context(initializer)?;
    if !path_ends_with(&call.func, &["seal_password_policy_before_external"])
        || call.args.len() != 2
        || call
            .args
            .first()
            .is_none_or(|arg| !is_exact_ident_path(arg, config))
    {
        return None;
    }
    let syn::Expr::Closure(external) = transparent_expr(call.args.iter().nth(1)?) else {
        return None;
    };
    let trace_call = call_behind_result_context(&external.body)?;
    (external.inputs.is_empty()
        && path_ends_with(&trace_call.func, &["build_trace_export"])
        && trace_call.args.len() == 1
        && trace_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, config)))
    .then_some((password_blocklist, trace_export))
}

#[derive(Debug, Default)]
struct RunRuntimeConfigWiring {
    runtime_inputs_calls: usize,
    runtime_inputs_config_calls: usize,
    runtime_plan_calls: usize,
    canonical_runtime_plan_calls: usize,
    config_view_bindings: usize,
    canonical_config_view_bindings: usize,
    serving_config_calls: usize,
    canonical_serving_config_calls: usize,
    serving_into_parts_calls: usize,
    canonical_serving_into_parts_calls: usize,
    serving_wiring_inputs_calls: usize,
    canonical_serving_wiring_inputs_calls: usize,
    serving_wiring_destructures: usize,
    canonical_serving_wiring_destructures: usize,
    closure_depth: usize,
    pg_config_calls: usize,
    canonical_pg_config_calls: usize,
    pg_into_parts_calls: usize,
    canonical_pg_into_parts_calls: usize,
    pg_setup_calls: usize,
    canonical_pg_setup_calls: usize,
    pg_setup_after_serving_config: usize,
    redis_config_calls: usize,
    canonical_redis_config_calls: usize,
    vault_config_calls: usize,
    canonical_vault_config_calls: usize,
    vault_into_runtime_calls: usize,
    canonical_vault_into_runtime_calls: usize,
    redis_calls: usize,
    canonical_redis_calls: usize,
    s3_config_calls: usize,
    canonical_s3_config_calls: usize,
    s3_into_parts_calls: usize,
    canonical_s3_into_parts_calls: usize,
    s3_calls: usize,
    canonical_s3_calls: usize,
    s3_dlx_flow_calls: usize,
    canonical_s3_dlx_flow_calls: usize,
    s3_canary_calls: usize,
    canonical_s3_canary_calls: usize,
    s3_canary_assembly_fields: usize,
    canonical_s3_canary_assembly_fields: usize,
    runtime_inputs_binding: Option<syn::Ident>,
    config_binding: Option<syn::Ident>,
    pg_config_binding: Option<syn::Ident>,
    redis_config_binding: Option<syn::Ident>,
    vault_config_binding: Option<syn::Ident>,
    s3_config_binding: Option<syn::Ident>,
    s3_canary_module_binding: Option<syn::Ident>,
    pg_part_bindings: BTreeMap<String, syn::Ident>,
    s3_part_bindings: BTreeMap<String, syn::Ident>,
    serving_part_bindings: BTreeMap<String, syn::Ident>,
    serving_sink_calls: BTreeMap<String, usize>,
    canonical_serving_sink_calls: BTreeMap<String, usize>,
}

impl RunRuntimeConfigWiring {
    fn new(runtime_inputs_binding: syn::Ident) -> Self {
        Self {
            runtime_inputs_binding: Some(runtime_inputs_binding),
            ..Self::default()
        }
    }

    fn is_canonical(&self) -> bool {
        let serving_sinks_are_canonical = SERVING_RUNTIME_SINK_FIELDS.iter().all(|field| {
            self.serving_sink_calls.get(*field) == Some(&1)
                && self.canonical_serving_sink_calls.get(*field) == Some(&1)
        });
        let serving_is_canonical = self.serving_config_calls == 1
            && self.canonical_serving_config_calls == 1
            && self.serving_into_parts_calls == 1
            && self.canonical_serving_into_parts_calls == 1
            && self.serving_part_bindings.len() == SERVING_RUNTIME_PART_FIELDS.len()
            && self.serving_wiring_inputs_calls == 1
            && self.canonical_serving_wiring_inputs_calls == 1
            && self.serving_wiring_destructures == 1
            && self.canonical_serving_wiring_destructures == 1
            && serving_sinks_are_canonical
            && self.pg_setup_after_serving_config == 1;
        self.runtime_inputs_calls == 0
            && self.runtime_inputs_config_calls == 3 + self.runtime_plan_calls
            && self.runtime_plan_calls <= 1
            && self.runtime_plan_calls == self.canonical_runtime_plan_calls
            && self.config_view_bindings == 1
            && self.canonical_config_view_bindings == 1
            && serving_is_canonical
            && self.pg_config_calls == 1
            && self.canonical_pg_config_calls == 1
            && self.pg_into_parts_calls == 1
            && self.canonical_pg_into_parts_calls == 1
            && self.pg_setup_calls == 1
            && self.canonical_pg_setup_calls == 1
            && self.redis_config_calls == 1
            && self.canonical_redis_config_calls == 1
            && self.vault_config_calls == 1
            && self.canonical_vault_config_calls == 1
            && self.vault_into_runtime_calls == 1
            && self.canonical_vault_into_runtime_calls == 1
            && self.redis_calls == 1
            && self.canonical_redis_calls == 1
            && self.s3_config_calls == 1
            && self.canonical_s3_config_calls == 1
            && self.s3_into_parts_calls == 1
            && self.canonical_s3_into_parts_calls == 1
            && self.s3_calls == 1
            && self.canonical_s3_calls == 1
            && self.s3_dlx_flow_calls == 1
            && self.canonical_s3_dlx_flow_calls == 1
            && self.s3_canary_calls == 1
            && self.canonical_s3_canary_calls == 1
            && self.s3_canary_assembly_fields == 1
            && self.canonical_s3_canary_assembly_fields == 1
    }

    fn record_typed_mapping(&mut self, binding: &syn::Ident, call: &syn::ExprCall) {
        let associated = |ty: &str| {
            let syn::Expr::Path(path) = transparent_expr(&call.func) else {
                return false;
            };
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "from_snapshot")
                && path.qself.as_ref().map_or_else(
                    || {
                        path.path
                            .segments
                            .iter()
                            .rev()
                            .nth(1)
                            .is_some_and(|segment| segment.ident == ty)
                    },
                    |qself| type_last_ident(&qself.ty).is_some_and(|ident| ident == ty),
                )
        };
        let kind = if associated("PgRuntimeConfig") {
            "pg"
        } else if associated("RedisRuntimeConfig") {
            "redis"
        } else if associated("VaultRuntimeConfig") {
            "vault"
        } else if associated("S3RuntimeConfig") {
            "s3"
        } else {
            return;
        };
        let canonical = self.config_binding.as_ref().is_some_and(|config| {
            call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|arg| is_exact_ident_path(arg, config))
        });
        match kind {
            "pg" => {
                self.pg_config_calls += 1;
                self.canonical_pg_config_calls += usize::from(canonical);
                if canonical && self.pg_config_binding.is_none() {
                    self.pg_config_binding = Some(binding.clone());
                }
            }
            "redis" => {
                self.redis_config_calls += 1;
                self.canonical_redis_config_calls += usize::from(canonical);
                if canonical && self.redis_config_binding.is_none() {
                    self.redis_config_binding = Some(binding.clone());
                }
            }
            "vault" => {
                self.vault_config_calls += 1;
                self.canonical_vault_config_calls += usize::from(canonical);
                if canonical && self.vault_config_binding.is_none() {
                    self.vault_config_binding = Some(binding.clone());
                }
            }
            "s3" => {
                self.s3_config_calls += 1;
                self.canonical_s3_config_calls += usize::from(canonical);
                if canonical && self.s3_config_binding.is_none() {
                    self.s3_config_binding = Some(binding.clone());
                }
            }
            _ => {}
        }
    }

    fn s3_canary_call_is_canonical(&self, call: &syn::ExprCall) -> bool {
        expr_path_last(&call.func).is_some_and(|ident| ident == "wire_s3_canary")
            && call.args.len() == 2
            && self.s3_part_bindings.get("canary").is_some_and(|canary| {
                call.args
                    .iter()
                    .nth(1)
                    .is_some_and(|argument| is_exact_ident_path(argument, canary))
            })
    }

    fn record_serving_sink(&mut self, field: &str, canonical: bool) {
        *self.serving_sink_calls.entry(field.to_owned()).or_default() += 1;
        if canonical {
            *self
                .canonical_serving_sink_calls
                .entry(field.to_owned())
                .or_default() += 1;
        }
    }

    fn serving_argument_is_canonical(
        &self,
        call: &syn::ExprCall,
        index: usize,
        field: &str,
    ) -> bool {
        self.serving_part_bindings
            .get(field)
            .is_some_and(|binding| {
                call.args
                    .iter()
                    .nth(index)
                    .is_some_and(|argument| is_exact_ident_path(argument, binding))
            })
    }

    fn record_serving_sink_call(&mut self, call: &syn::ExprCall) {
        if self.closure_depth != 0 {
            return;
        }
        let Some(name) = expr_path_last(&call.func).map(ToString::to_string) else {
            return;
        };
        match name.as_str() {
            "wire_domain_transport" => self.record_serving_sink(
                "domain_transport",
                call.args.len() == 1
                    && self.serving_argument_is_canonical(call, 0, "domain_transport"),
            ),
            "wire_domains" => self.record_serving_sink(
                "domain_modules",
                call.args.len() == 2
                    && self.serving_argument_is_canonical(call, 1, "domain_modules"),
            ),
            "wire_session_sweeper" => self.record_serving_sink(
                "session_sweep_interval",
                call.args.len() == 2
                    && self.serving_argument_is_canonical(call, 1, "session_sweep_interval"),
            ),
            "wire_distributed" => self.record_serving_sink(
                "distributed_worker",
                call.args.len() == 2
                    && self.serving_argument_is_canonical(call, 1, "distributed_worker"),
            ),
            "wire_event_transport" => {
                for (field, index) in [
                    ("event_transport", 3),
                    ("event_worker", 4),
                    ("audit_consumer_key", 5),
                ] {
                    self.record_serving_sink(
                        field,
                        call.args.len() == 6
                            && self.serving_argument_is_canonical(call, index, field),
                    );
                }
            }
            "wire_dlx_lifecycle" => self.record_serving_sink(
                "dlx_worker",
                call.args.len() == 2 && self.serving_argument_is_canonical(call, 1, "dlx_worker"),
            ),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for RunRuntimeConfigWiring {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let binding = immutable_pat_ident(&local.pat);
        let initializer = local.init.as_ref().map(|init| init.expr.as_ref());
        if let (Some(binding), Some(initializer), Some(runtime_inputs)) =
            (binding, initializer, self.runtime_inputs_binding.as_ref())
            && is_runtime_inputs_config_view(initializer, runtime_inputs)
        {
            self.config_view_bindings += 1;
            self.canonical_config_view_bindings += 1;
            if self.config_binding.is_none() {
                self.config_binding = Some(binding.clone());
            }
        }
        if let (Some(binding), Some(initializer)) = (binding, initializer)
            && let Some(call) = call_behind_result_context(initializer)
        {
            self.record_typed_mapping(binding, call);
            if self.s3_canary_call_is_canonical(call) && self.s3_canary_module_binding.is_none() {
                self.s3_canary_module_binding = Some(binding.clone());
            }
        }
        if let (Some(initializer), Some(config)) = (initializer, self.config_binding.as_ref())
            && canonical_serving_parts_initializer(initializer, config)
            && let Some(bindings) = serving_parts_pattern_bindings(&local.pat)
            && self.serving_part_bindings.is_empty()
        {
            self.serving_part_bindings = bindings;
        }
        if let Some(bindings) = runtime_wiring_inputs_pattern_bindings(&local.pat) {
            self.serving_wiring_destructures += 1;
            self.canonical_serving_wiring_destructures +=
                usize::from(bindings == serving_wiring_bindings(&self.serving_part_bindings));
        }
        if let (Some(initializer), Some(pg_config)) = (initializer, self.pg_config_binding.as_ref())
            && canonical_pg_parts_initializer(initializer, pg_config)
            && let Some(bindings) = pg_parts_pattern_bindings(&local.pat)
            && self.pg_part_bindings.is_empty()
        {
            self.pg_part_bindings = bindings;
        }
        if let (Some(initializer), Some(s3_config)) = (initializer, self.s3_config_binding.as_ref())
            && canonical_s3_parts_initializer(initializer, s3_config)
            && let Some(bindings) = s3_parts_pattern_bindings(&local.pat)
            && self.s3_part_bindings.is_empty()
        {
            self.s3_part_bindings = bindings;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.record_serving_sink_call(call);
        if path_ends_with(&call.func, &["RuntimeInputs", "new"]) {
            self.runtime_inputs_calls += 1;
        }
        if path_ends_with(&call.func, &["plan", "RuntimePlan", "bundled"]) {
            self.runtime_plan_calls += 1;
            self.canonical_runtime_plan_calls += usize::from(
                call.args.len() == 1
                    && self
                        .runtime_inputs_binding
                        .as_ref()
                        .is_some_and(|runtime_inputs| {
                            call.args.first().is_some_and(|arg| {
                                is_runtime_inputs_config_view(arg, runtime_inputs)
                            })
                        }),
            );
        }
        if path_ends_with(&call.func, &["RuntimeServingConfig", "from_snapshot"]) {
            self.serving_config_calls += 1;
            self.canonical_serving_config_calls +=
                usize::from(self.config_binding.as_ref().is_some_and(|config| {
                    call.args.len() == 1
                        && call
                            .args
                            .first()
                            .is_some_and(|arg| is_exact_ident_path(arg, config))
                }));
        }
        match expr_path_last(&call.func)
            .map(ToString::to_string)
            .as_deref()
        {
            Some("build_redis_runtime_deps") => {
                self.redis_calls += 1;
                self.canonical_redis_calls += usize::from(
                    self.redis_config_binding
                        .as_ref()
                        .is_some_and(|redis_config| {
                            call.args.len() == 1
                                && call
                                    .args
                                    .first()
                                    .is_some_and(|arg| is_exact_ident_path(arg, redis_config))
                        }),
                );
            }
            Some("build_s3_runtime_deps") => {
                self.s3_calls += 1;
                self.canonical_s3_calls +=
                    usize::from(self.s3_part_bindings.get("general").is_some_and(|general| {
                        call.args.len() == 1
                            && call
                                .args
                                .first()
                                .is_some_and(|arg| is_exact_ident_path(arg, general))
                    }));
            }
            Some("build_dlx_lifecycle_bootstrap_config_from") => {
                self.s3_dlx_flow_calls += 1;
                self.canonical_s3_dlx_flow_calls +=
                    usize::from(self.s3_part_bindings.get("dlx_archive").is_some_and(|dlx| {
                        call.args.len() == 6
                            && call
                                .args
                                .iter()
                                .nth(3)
                                .is_some_and(|arg| is_exact_ident_path(arg, dlx))
                    }));
            }
            Some("wire_s3_canary") => {
                self.s3_canary_calls += 1;
                self.canonical_s3_canary_calls +=
                    usize::from(self.s3_canary_call_is_canonical(call));
            }
            _ => {}
        }
        if path_ends_with(
            &call.func,
            &["PgRuntimeDeps", "setup_with_audit_admin_config"],
        ) {
            self.pg_setup_calls += 1;
            let canonical = pg_setup_uses_named_parts(call, &self.pg_part_bindings);
            self.canonical_pg_setup_calls += usize::from(canonical);
            self.pg_setup_after_serving_config +=
                usize::from(canonical && self.canonical_serving_into_parts_calls == 1);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
        if path_last_ident(&item.path).is_some_and(|ident| ident == "RuntimeWiringInputs") {
            self.serving_wiring_inputs_calls += 1;
            self.canonical_serving_wiring_inputs_calls += usize::from(
                runtime_wiring_inputs_struct_is_canonical(item, &self.serving_part_bindings),
            );
        }
        if path_last_ident(&item.path).is_some_and(|ident| ident == "RuntimeModuleAssemblyInputs") {
            for field in &item.fields {
                if matches!(&field.member, syn::Member::Named(member) if member == "s3_canary_module")
                {
                    self.s3_canary_assembly_fields += 1;
                    self.canonical_s3_canary_assembly_fields += usize::from(
                        self.s3_canary_module_binding
                            .as_ref()
                            .is_some_and(|binding| is_exact_ident_path(&field.expr, binding)),
                    );
                }
            }
        }
        syn::visit::visit_expr_struct(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "config"
            && call.args.is_empty()
            && self
                .runtime_inputs_binding
                .as_ref()
                .is_some_and(|runtime_inputs| is_exact_ident_path(&call.receiver, runtime_inputs))
        {
            self.runtime_inputs_config_calls += 1;
        }
        if call.method == "into_parts"
            && call.args.is_empty()
            && let Some(mapping) = call_behind_result_context(&call.receiver)
            && path_ends_with(&mapping.func, &["RuntimeServingConfig", "from_snapshot"])
        {
            self.serving_into_parts_calls += 1;
            self.canonical_serving_into_parts_calls +=
                usize::from(self.config_binding.as_ref().is_some_and(|config| {
                    mapping.args.len() == 1
                        && mapping
                            .args
                            .first()
                            .is_some_and(|arg| is_exact_ident_path(arg, config))
                }));
        }
        if call.method == "into_parts"
            && call.args.is_empty()
            && self
                .pg_config_binding
                .as_ref()
                .is_some_and(|pg_config| is_exact_ident_path(&call.receiver, pg_config))
        {
            self.pg_into_parts_calls += 1;
            self.canonical_pg_into_parts_calls += 1;
        }
        if call.method == "into_parts"
            && call.args.is_empty()
            && self
                .s3_config_binding
                .as_ref()
                .is_some_and(|s3_config| is_exact_ident_path(&call.receiver, s3_config))
        {
            self.s3_into_parts_calls += 1;
            self.canonical_s3_into_parts_calls += 1;
        }
        if call.method == "into_runtime" && call.args.is_empty() {
            self.vault_into_runtime_calls += 1;
            self.canonical_vault_into_runtime_calls += usize::from(
                self.vault_config_binding
                    .as_ref()
                    .is_some_and(|vault_config| is_exact_ident_path(&call.receiver, vault_config)),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit::visit_expr_closure(self, closure);
        self.closure_depth -= 1;
    }
}

const SERVING_RUNTIME_PART_FIELDS: &[&str] = &[
    "token_profiles",
    "event_transport",
    "event_worker",
    "dlx_worker",
    "distributed_worker",
    "domain_transport",
    "domain_modules",
    "audit_consumer_key",
    "session_sweep_interval",
];

const SERVING_RUNTIME_SINK_FIELDS: &[&str] = &[
    "event_transport",
    "event_worker",
    "dlx_worker",
    "distributed_worker",
    "domain_transport",
    "domain_modules",
    "audit_consumer_key",
    "session_sweep_interval",
];

const RUNTIME_WIRING_INPUT_FIELDS: &[&str] = &[
    "event_transport",
    "event_worker",
    "dlx_worker",
    "distributed_worker",
    "domain_modules",
    "audit_consumer_key",
    "session_sweep_interval",
];

fn canonical_serving_parts_initializer(expr: &syn::Expr, config: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    if call.method != "into_parts" || !call.args.is_empty() {
        return false;
    }
    let Some(mapping) = call_behind_result_context(&call.receiver) else {
        return false;
    };
    path_ends_with(&mapping.func, &["RuntimeServingConfig", "from_snapshot"])
        && mapping.args.len() == 1
        && mapping
            .args
            .first()
            .is_some_and(|argument| is_exact_ident_path(argument, config))
}

fn serving_parts_pattern_bindings(pat: &syn::Pat) -> Option<BTreeMap<String, syn::Ident>> {
    exact_struct_pattern_bindings(
        pat,
        "RuntimeServingConfigParts",
        SERVING_RUNTIME_PART_FIELDS,
    )
}

fn runtime_wiring_inputs_pattern_bindings(pat: &syn::Pat) -> Option<BTreeMap<String, syn::Ident>> {
    exact_struct_pattern_bindings(pat, "RuntimeWiringInputs", RUNTIME_WIRING_INPUT_FIELDS)
}

fn exact_struct_pattern_bindings(
    pat: &syn::Pat,
    type_name: &str,
    fields: &[&str],
) -> Option<BTreeMap<String, syn::Ident>> {
    let syn::Pat::Struct(parts) = pat else {
        return None;
    };
    if !is_exact_syn_path(&parts.path, &[type_name])
        || parts.rest.is_some()
        || parts.fields.len() != fields.len()
    {
        return None;
    }
    let mut bindings = BTreeMap::new();
    for field in &parts.fields {
        let syn::Member::Named(member) = &field.member else {
            return None;
        };
        let name = member.to_string();
        if !fields.contains(&name.as_str()) {
            return None;
        }
        let binding = immutable_pat_ident(&field.pat)?.clone();
        if bindings.insert(name, binding).is_some() {
            return None;
        }
    }
    Some(bindings)
}

fn serving_wiring_bindings(serving: &BTreeMap<String, syn::Ident>) -> BTreeMap<String, syn::Ident> {
    serving
        .iter()
        .filter(|(field, _)| RUNTIME_WIRING_INPUT_FIELDS.contains(&field.as_str()))
        .map(|(field, binding)| (field.clone(), binding.clone()))
        .collect()
}

fn runtime_wiring_inputs_struct_is_canonical(
    item: &syn::ExprStruct,
    serving: &BTreeMap<String, syn::Ident>,
) -> bool {
    if !is_exact_syn_path(&item.path, &["RuntimeWiringInputs"])
        || item.rest.is_some()
        || item.fields.len() != RUNTIME_WIRING_INPUT_FIELDS.len()
    {
        return false;
    }
    let mut seen = BTreeSet::new();
    item.fields.iter().all(|field| {
        let syn::Member::Named(member) = &field.member else {
            return false;
        };
        let name = member.to_string();
        RUNTIME_WIRING_INPUT_FIELDS.contains(&name.as_str())
            && seen.insert(name.clone())
            && serving
                .get(&name)
                .is_some_and(|binding| is_exact_ident_path(&field.expr, binding))
    })
}

const PG_RUNTIME_PART_FIELDS: &[&str] = &[
    "serving",
    "tenant_read",
    "migrator",
    "audit_admin",
    "dlx_archiver",
    "dlx_verifier",
    "dlx_purger",
    "legacy_policy",
    "readiness_period",
];

const S3_RUNTIME_PART_FIELDS: &[&str] = &["general", "canary", "dlx_archive"];

fn canonical_pg_parts_initializer(expr: &syn::Expr, pg_config: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == "into_parts"
        && call.args.is_empty()
        && is_exact_ident_path(&call.receiver, pg_config)
}

fn pg_parts_pattern_bindings(pat: &syn::Pat) -> Option<BTreeMap<String, syn::Ident>> {
    let syn::Pat::Struct(parts) = pat else {
        return None;
    };
    if !is_exact_syn_path(&parts.path, &["PgRuntimeConfigParts"])
        || parts.rest.is_some()
        || parts.fields.len() != PG_RUNTIME_PART_FIELDS.len()
    {
        return None;
    }
    let mut bindings = BTreeMap::new();
    for field in &parts.fields {
        let syn::Member::Named(member) = &field.member else {
            return None;
        };
        let name = member.to_string();
        if !PG_RUNTIME_PART_FIELDS.contains(&name.as_str()) {
            return None;
        }
        let binding = immutable_pat_ident(&field.pat)?.clone();
        if bindings.insert(name, binding).is_some() {
            return None;
        }
    }
    Some(bindings)
}

fn canonical_s3_parts_initializer(expr: &syn::Expr, s3_config: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == "into_parts"
        && call.args.is_empty()
        && is_exact_ident_path(&call.receiver, s3_config)
}

fn s3_parts_pattern_bindings(pat: &syn::Pat) -> Option<BTreeMap<String, syn::Ident>> {
    let syn::Pat::Struct(parts) = pat else {
        return None;
    };
    if !is_exact_syn_path(&parts.path, &["S3RuntimeConfigParts"])
        || parts.rest.is_some()
        || parts.fields.len() != S3_RUNTIME_PART_FIELDS.len()
    {
        return None;
    }
    let mut bindings = BTreeMap::new();
    for field in &parts.fields {
        let syn::Member::Named(member) = &field.member else {
            return None;
        };
        let name = member.to_string();
        if !S3_RUNTIME_PART_FIELDS.contains(&name.as_str()) {
            return None;
        }
        let binding = immutable_pat_ident(&field.pat)?.clone();
        if bindings.insert(name, binding).is_some() {
            return None;
        }
    }
    Some(bindings)
}

fn method_on_binding(expr: &syn::Expr, method: &str, binding: &syn::Ident) -> bool {
    matches!(transparent_expr(expr), syn::Expr::MethodCall(call)
        if call.method == method
            && call.args.is_empty()
            && is_exact_ident_path(&call.receiver, binding))
}

fn pg_setup_uses_named_parts(
    call: &syn::ExprCall,
    bindings: &BTreeMap<String, syn::Ident>,
) -> bool {
    let Some(migrator) = bindings.get("migrator") else {
        return false;
    };
    let Some(serving) = bindings.get("serving") else {
        return false;
    };
    let Some(tenant_read) = bindings.get("tenant_read") else {
        return false;
    };
    let Some(audit_admin) = bindings.get("audit_admin") else {
        return false;
    };
    let Some(legacy_policy) = bindings.get("legacy_policy") else {
        return false;
    };
    call.args.len() == 7
        && call
            .args
            .first()
            .is_some_and(|arg| reference_to_binding(arg, migrator))
        && call
            .args
            .iter()
            .nth(1)
            .is_some_and(|arg| reference_to_binding(arg, serving))
        && call
            .args
            .iter()
            .nth(2)
            .is_some_and(|arg| reference_to_binding(arg, tenant_read))
        && call
            .args
            .iter()
            .nth(3)
            .is_some_and(|arg| method_on_binding(arg, "as_ref", audit_admin))
        && call
            .args
            .iter()
            .nth(4)
            .is_some_and(|arg| is_exact_ident_path(arg, legacy_policy))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
struct ProductionRuntimeConfigInventory {
    snapshot_calls: usize,
    runtime_inputs_calls: usize,
    pg_config_calls: usize,
    redis_config_calls: usize,
    vault_config_calls: usize,
    vault_runtime_consumes: usize,
    vault_settings_consumes: usize,
    redis_calls: usize,
    s3_config_calls: usize,
    s3_calls: usize,
    s3_dlx_calls: usize,
    forbidden_indirections: usize,
    symbol_origins: BTreeMap<String, String>,
    vault_config_bindings: BTreeSet<String>,
}

#[derive(Clone, Copy)]
enum RuntimeConfigFact {
    Snapshot,
    Inputs,
    PgMapping,
    RedisMapping,
    VaultMapping,
    VaultRuntimeConsume,
    VaultSettingsConsume,
    RedisBuild,
    S3Mapping,
    S3Build,
    S3DlxBuild,
}

#[derive(Clone, Copy)]
struct RuntimeConfigFactSpec {
    fact: RuntimeConfigFact,
    expected: usize,
    label: &'static str,
}

const RUNTIME_CONFIG_FACT_SPECS: &[RuntimeConfigFactSpec] = &[
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::Snapshot,
        expected: 1,
        label: "snapshot capture",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::Inputs,
        expected: 1,
        label: "runtime inputs",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::PgMapping,
        expected: 1,
        label: "PG typed mapping",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::RedisMapping,
        expected: 1,
        label: "Redis typed mapping",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::VaultMapping,
        expected: 2,
        label: "Vault typed mappings",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::VaultRuntimeConsume,
        expected: 1,
        label: "Vault runtime consume",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::VaultSettingsConsume,
        expected: 1,
        label: "Vault settings consume",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::RedisBuild,
        expected: 1,
        label: "Redis provider builder",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::S3Mapping,
        expected: 1,
        label: "S3 typed mapping",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::S3Build,
        expected: 1,
        label: "S3 provider builder",
    },
    RuntimeConfigFactSpec {
        fact: RuntimeConfigFact::S3DlxBuild,
        expected: 1,
        label: "S3 DLX provider builder",
    },
];

const PROTECTED_CONFIG_SYMBOLS: &[&str] = &[
    "RuntimeConfigSnapshot",
    "PreparedRuntimeInputs",
    "RuntimeServingConfig",
    "RuntimeServingConfigParts",
    "PgRuntimeConfig",
    "PgRuntimeConfigParts",
    "RedisRuntimeConfig",
    "VaultRuntimeConfig",
    "S3RuntimeConfig",
    "S3RuntimeConfigParts",
    "S3GeneralConfig",
    "S3DlxArchiveConfig",
    "build_redis_runtime_deps",
    "build_s3_runtime_deps",
    "build_s3_dlx_archive_store",
];

impl ProductionRuntimeConfigInventory {
    fn canonical_origin(symbol: &str) -> Option<&'static str> {
        match symbol {
            "RuntimeConfigSnapshot" => Some("config::RuntimeConfigSnapshot"),
            "PreparedRuntimeInputs" => Some("phase::PreparedRuntimeInputs"),
            "RuntimeServingConfig" => Some("config::RuntimeServingConfig"),
            "RuntimeServingConfigParts" => Some("config::RuntimeServingConfigParts"),
            "PgRuntimeConfig" => Some("infra::pg::PgRuntimeConfig"),
            "RedisRuntimeConfig" => Some("infra::redis::RedisRuntimeConfig"),
            "VaultRuntimeConfig" => Some("infra::vault::VaultRuntimeConfig"),
            "S3RuntimeConfig" => Some("infra::s3::S3RuntimeConfig"),
            "build_redis_runtime_deps" => Some("infra::redis::build_redis_runtime_deps"),
            "build_s3_runtime_deps" => Some("infra::s3::build_s3_runtime_deps"),
            "build_s3_dlx_archive_store" => Some("infra::s3::build_s3_dlx_archive_store"),
            _ => None,
        }
    }

    fn origin_is_canonical(origin: &str, symbol: &str) -> bool {
        Self::canonical_origin(symbol)
            .is_some_and(|expected| origin == expected || origin == format!("crate::{expected}"))
    }

    fn path_is_canonical(&self, expr: &syn::Expr, symbol: &str) -> bool {
        let syn::Expr::Path(path) = transparent_expr(expr) else {
            return false;
        };
        let rendered = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        if path.qself.is_none() && Self::origin_is_canonical(&rendered, symbol) {
            return true;
        }
        path.qself.is_none()
            && path.path.segments.len() == 1
            && self
                .symbol_origins
                .get(&rendered)
                .is_some_and(|origin| Self::origin_is_canonical(origin, symbol))
    }

    fn associated_call_is_canonical(
        &self,
        call: &syn::ExprCall,
        method: &str,
        symbol: &str,
    ) -> bool {
        let syn::Expr::Path(path) = transparent_expr(&call.func) else {
            return false;
        };
        if path
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != method)
        {
            return false;
        }
        if let Some(qself) = &path.qself {
            let syn::Type::Path(ty) = qself.ty.as_ref() else {
                return false;
            };
            return self.path_is_canonical(
                &syn::Expr::Path(syn::ExprPath {
                    attrs: Vec::new(),
                    qself: None,
                    path: ty.path.clone(),
                }),
                symbol,
            );
        }
        let mut origin = path.clone();
        origin.path.segments.pop();
        self.path_is_canonical(&syn::Expr::Path(origin), symbol)
    }

    fn protected_path_is_unresolved(&self, expr: &syn::Expr) -> bool {
        let syn::Expr::Path(path) = transparent_expr(expr) else {
            return false;
        };
        let Some(symbol) = path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return false;
        };
        Self::canonical_origin(&symbol).is_some() && !self.path_is_canonical(expr, &symbol)
    }

    fn record_use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.record_use_tree(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let mut origin = prefix.clone();
                origin.push(name.ident.to_string());
                self.symbol_origins
                    .insert(name.ident.to_string(), origin.join("::"));
            }
            syn::UseTree::Rename(rename) => {
                let mut origin = prefix.clone();
                origin.push(rename.ident.to_string());
                self.symbol_origins
                    .insert(rename.rename.to_string(), origin.join("::"));
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.record_use_tree(item, prefix);
                }
            }
            syn::UseTree::Glob(_) => {
                if prefix
                    .iter()
                    .any(|part| PROTECTED_CONFIG_SYMBOLS.contains(&part.as_str()))
                {
                    self.forbidden_indirections += 1;
                }
            }
        }
    }

    fn count(&self, fact: RuntimeConfigFact) -> usize {
        match fact {
            RuntimeConfigFact::Snapshot => self.snapshot_calls,
            RuntimeConfigFact::Inputs => self.runtime_inputs_calls,
            RuntimeConfigFact::PgMapping => self.pg_config_calls,
            RuntimeConfigFact::RedisMapping => self.redis_config_calls,
            RuntimeConfigFact::VaultMapping => self.vault_config_calls,
            RuntimeConfigFact::VaultRuntimeConsume => self.vault_runtime_consumes,
            RuntimeConfigFact::VaultSettingsConsume => self.vault_settings_consumes,
            RuntimeConfigFact::RedisBuild => self.redis_calls,
            RuntimeConfigFact::S3Mapping => self.s3_config_calls,
            RuntimeConfigFact::S3Build => self.s3_calls,
            RuntimeConfigFact::S3DlxBuild => self.s3_dlx_calls,
        }
    }

    fn is_exact(&self) -> bool {
        self.forbidden_indirections == 0
            && RUNTIME_CONFIG_FACT_SPECS
                .iter()
                .all(|spec| self.count(spec.fact) == spec.expected)
    }

    fn add(&mut self, other: Self) {
        self.snapshot_calls += other.snapshot_calls;
        self.runtime_inputs_calls += other.runtime_inputs_calls;
        self.pg_config_calls += other.pg_config_calls;
        self.redis_config_calls += other.redis_config_calls;
        self.vault_config_calls += other.vault_config_calls;
        self.vault_runtime_consumes += other.vault_runtime_consumes;
        self.vault_settings_consumes += other.vault_settings_consumes;
        self.redis_calls += other.redis_calls;
        self.s3_config_calls += other.s3_config_calls;
        self.s3_calls += other.s3_calls;
        self.s3_dlx_calls += other.s3_dlx_calls;
        self.forbidden_indirections += other.forbidden_indirections;
    }

    fn diagnostic(&self) -> String {
        let facts = RUNTIME_CONFIG_FACT_SPECS
            .iter()
            .map(|spec| format!("{}={}/{}", spec.label, self.count(spec.fact), spec.expected))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{facts}, forbidden indirections={}",
            self.forbidden_indirections
        )
    }
}

fn compact_type_tokens(value: &impl quote::ToTokens) -> String {
    value
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn cfg_terms(attribute: &syn::Attribute) -> Option<Vec<syn::Meta>> {
    if !attribute.path().is_ident("cfg") {
        return None;
    }
    let syn::Meta::List(cfg) = &attribute.meta else {
        return None;
    };
    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(cfg.tokens.clone())
        .ok()
        .map(|terms| terms.into_iter().collect())
}

fn meta_is_integration_feature(meta: &syn::Meta) -> bool {
    matches!(meta, syn::Meta::NameValue(value)
        if value.path.is_ident("feature")
            && matches!(transparent_expr(&value.value), syn::Expr::Lit(lit)
                if matches!(&lit.lit, syn::Lit::Str(value) if value.value() == "integration")))
}

fn cfg_is_exact_integration(attribute: &syn::Attribute) -> bool {
    cfg_terms(attribute).is_some_and(|terms| {
        terms.len() == 1 && terms.first().is_some_and(meta_is_integration_feature)
    })
}

fn cfg_is_exact_test_or_integration(attribute: &syn::Attribute) -> bool {
    let Some(terms) = cfg_terms(attribute) else {
        return false;
    };
    let [syn::Meta::List(any)] = terms.as_slice() else {
        return false;
    };
    if !any.path.is_ident("any") {
        return false;
    }
    let Ok(items) = syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
        .parse2(any.tokens.clone())
    else {
        return false;
    };
    items.len() == 2
        && items
            .iter()
            .any(|meta| matches!(meta, syn::Meta::Path(path) if path.is_ident("test")))
        && items.iter().any(meta_is_integration_feature)
}

fn has_one_exact_cfg(
    attributes: &[syn::Attribute],
    predicate: impl Fn(&syn::Attribute) -> bool,
) -> bool {
    let cfgs = attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .collect::<Vec<_>>();
    cfgs.len() == 1 && predicate(cfgs[0])
}

fn is_pub_crate(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Restricted(restricted)
        if restricted.in_token.is_none() && restricted.path.is_ident("crate"))
}

fn redis_values_signature_is_exact(signature: &syn::Signature) -> bool {
    let inputs = signature.inputs.iter().collect::<Vec<_>>();
    let exact_input = |input: &&syn::FnArg, name: &str, ty: &str| {
        matches!(input, syn::FnArg::Typed(input)
            if pat_ident(&input.pat).is_some_and(|ident| ident == name)
                && compact_type_tokens(input.ty.as_ref()) == ty)
    };
    signature.ident == "build_redis_runtime_deps_from_values"
        && signature.asyncness.is_some()
        && signature.constness.is_none()
        && signature.unsafety.is_none()
        && signature.generics.params.is_empty()
        && inputs.len() == 2
        && exact_input(&inputs[0], "url", "String")
        && exact_input(&inputs[1], "allow_plaintext", "Option<&str>")
        && matches!(&signature.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == "anyhow::Result<redis::RedisRuntimeDeps>")
}

fn internal_redis_values_seam_is_exact(item: &syn::ItemFn) -> bool {
    redis_values_signature_is_exact(&item.sig)
        && is_pub_crate(&item.vis)
        && has_one_exact_cfg(&item.attrs, cfg_is_exact_test_or_integration)
}

#[derive(Clone, Copy)]
struct ValuesSeamSpec {
    name: &'static str,
    inputs: &'static [(&'static str, &'static str)],
    internal_output: &'static str,
    wrapper_output: &'static str,
    delegate_path: &'static [&'static str],
}

const VAULT_VALUES_INPUTS: &[(&str, &str)] = &[
    ("addr", "String"),
    ("token", "String"),
    ("transit_mount", "String"),
    ("settings_key_name", "String"),
];
const S3_VALUES_INPUTS: &[(&str, &str)] = &[
    ("endpoint_url", "String"),
    ("bucket", "String"),
    ("access_key_id", "String"),
    ("secret_access_key", "String"),
    ("allow_plaintext", "bool"),
    ("force_path_style", "bool"),
];
const VALUES_SEAM_SPECS: &[ValuesSeamSpec] = &[
    ValuesSeamSpec {
        name: "build_vault_runtime_from_values",
        inputs: VAULT_VALUES_INPUTS,
        internal_output: "anyhow::Result<(VaultRuntimeDeps,KeyName)>",
        wrapper_output: "anyhow::Result<(vault::VaultRuntimeDeps,diport::KeyName)>",
        delegate_path: &["crate", "infra", "vault", "build_vault_runtime_from_values"],
    },
    ValuesSeamSpec {
        name: "build_s3_runtime_deps_from_values",
        inputs: S3_VALUES_INPUTS,
        internal_output: "anyhow::Result<S3RuntimeDeps>",
        wrapper_output: "anyhow::Result<s3::S3RuntimeDeps>",
        delegate_path: &["crate", "infra", "s3", "build_s3_runtime_deps_from_values"],
    },
];

fn values_seam_spec(name: &syn::Ident) -> Option<&'static ValuesSeamSpec> {
    VALUES_SEAM_SPECS.iter().find(|spec| name == spec.name)
}

fn values_signature_is_exact(
    signature: &syn::Signature,
    spec: &ValuesSeamSpec,
    output: &str,
) -> bool {
    signature.ident == spec.name
        && signature.asyncness.is_none()
        && signature.constness.is_none()
        && signature.unsafety.is_none()
        && signature.generics.params.is_empty()
        && signature.inputs.len() == spec.inputs.len()
        && signature
            .inputs
            .iter()
            .zip(spec.inputs)
            .all(|(input, (name, ty))| {
                matches!(input, syn::FnArg::Typed(input)
                if pat_ident(&input.pat).is_some_and(|ident| ident == *name)
                    && compact_type_tokens(input.ty.as_ref()) == *ty)
            })
        && matches!(&signature.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == output)
}

fn values_struct_fields_are_exact(
    value: &syn::ExprStruct,
    ty: &str,
    expected: &[(&str, &str)],
) -> bool {
    path_last_ident(&value.path).is_some_and(|ident| ident == ty)
        && value.rest.is_none()
        && value.fields.len() == expected.len()
        && expected.iter().all(|(name, expression)| {
            value.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == name)
                    && compact_tokens(&field.expr) == *expression
            })
        })
}

fn values_mapping_call_is_exact(call: &syn::ExprCall, spec: &ValuesSeamSpec) -> bool {
    let Some(value) = call
        .args
        .first()
        .and_then(|argument| match transparent_expr(argument) {
            syn::Expr::Struct(value) if call.args.len() == 1 => Some(value),
            _ => None,
        })
    else {
        return false;
    };
    match spec.name {
        "build_vault_runtime_from_values" => {
            path_ends_with(&call.func, &["VaultRuntimeConfig", "from_values"])
                && values_struct_fields_are_exact(
                    value,
                    "VaultConfigValues",
                    &[
                        ("addr", "Some(addr)"),
                        ("token", "Some(token.as_str())"),
                        ("transit_mount", "Some(transit_mount)"),
                        ("ca_cert_pem_path", "None"),
                        ("settings_key_name", "Some(settings_key_name.as_str())"),
                    ],
                )
        }
        "build_s3_runtime_deps_from_values" => {
            is_exact_path(&call.func, &["s3_general_config_from_values"])
                && values_struct_fields_are_exact(
                    value,
                    "S3GeneralConfigValues",
                    &[
                        ("endpoint_url", "Some(&endpoint_url)"),
                        ("bucket", "Some(&bucket)"),
                        ("access_key_id", "Some(&access_key_id)"),
                        ("secret_access_key", "Some(&secret_access_key)"),
                        ("session_token", "None"),
                        ("region", "None"),
                        (
                            "force_path_style",
                            "Some(ifforce_path_style{\"true\"}else{\"false\"})",
                        ),
                        (
                            "allow_plaintext",
                            "Some(ifallow_plaintext{\"true\"}else{\"false\"})",
                        ),
                    ],
                )
        }
        _ => false,
    }
}

fn values_seam_body_is_exact(item: &syn::ItemFn, spec: &ValuesSeamSpec) -> bool {
    let [syn::Stmt::Local(local), syn::Stmt::Expr(tail, None)] = item.block.stmts.as_slice() else {
        return false;
    };
    let Some(binding) = immutable_pat_ident(&local.pat) else {
        return false;
    };
    let Some(mapping) = local
        .init
        .as_ref()
        .and_then(|initializer| call_behind_result_context(&initializer.expr))
    else {
        return false;
    };
    if !values_mapping_call_is_exact(mapping, spec) {
        return false;
    }
    fn result_tail(expr: &syn::Expr) -> &syn::Expr {
        match transparent_expr(expr) {
            syn::Expr::Try(expr) => result_tail(&expr.expr),
            syn::Expr::Call(call) if is_exact_path(&call.func, &["Ok"]) && call.args.len() == 1 => {
                result_tail(&call.args[0])
            }
            expr => expr,
        }
    }
    match (spec.name, result_tail(tail)) {
        ("build_vault_runtime_from_values", syn::Expr::MethodCall(call)) => {
            call.method == "into_runtime"
                && call.args.is_empty()
                && is_exact_ident_path(&call.receiver, binding)
        }
        ("build_s3_runtime_deps_from_values", syn::Expr::Call(call)) => {
            is_exact_path(&call.func, &["build_s3_runtime_deps"])
                && call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|argument| is_exact_ident_path(argument, binding))
        }
        _ => false,
    }
}

fn internal_vault_s3_values_seam_is_exact(item: &syn::ItemFn) -> bool {
    let Some(spec) = values_seam_spec(&item.sig.ident) else {
        return false;
    };
    values_signature_is_exact(&item.sig, spec, spec.internal_output)
        && is_pub_crate(&item.vis)
        && has_one_exact_cfg(&item.attrs, cfg_is_exact_test_or_integration)
        && values_seam_body_is_exact(item, spec)
}

fn public_values_wrapper_is_exact(item: &syn::ItemFn, spec: &ValuesSeamSpec) -> bool {
    if !matches!(item.vis, syn::Visibility::Public(_))
        || !values_signature_is_exact(&item.sig, spec, spec.wrapper_output)
        || item.block.stmts.len() != 1
    {
        return false;
    }
    let syn::Stmt::Expr(tail, None) = &item.block.stmts[0] else {
        return false;
    };
    let syn::Expr::Call(call) = transparent_expr(tail) else {
        return false;
    };
    is_exact_path(&call.func, spec.delegate_path)
        && call.args.len() == spec.inputs.len()
        && call
            .args
            .iter()
            .zip(spec.inputs)
            .all(|(argument, (name, _))| is_exact_path(argument, &[*name]))
}

fn vault_s3_test_support_wrappers_are_exact(file: &syn::File) -> bool {
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "test_support" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(module) = (modules.len() == 1).then_some(modules[0]) else {
        return false;
    };
    if !matches!(module.vis, syn::Visibility::Public(_))
        || !has_one_exact_cfg(&module.attrs, cfg_is_exact_integration)
    {
        return false;
    }
    let Some((_, items)) = &module.content else {
        return false;
    };
    VALUES_SEAM_SPECS.iter().all(|spec| {
        let wrappers = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == spec.name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        wrappers.len() == 1 && public_values_wrapper_is_exact(wrappers[0], spec)
    })
}

fn ident_is_protected_config(ident: &syn::Ident) -> bool {
    let ident = ident.to_string();
    PROTECTED_CONFIG_SYMBOLS.contains(&ident.as_str())
}

fn use_tree_has_protected_rename(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(rename) => ident_is_protected_config(&rename.ident),
        syn::UseTree::Path(path) => use_tree_has_protected_rename(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_has_protected_rename),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

fn type_mentions_protected_config(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) => {
            path.path
                .segments
                .iter()
                .any(|segment| ident_is_protected_config(&segment.ident))
                || path
                    .qself
                    .as_ref()
                    .is_some_and(|qself| type_mentions_protected_config(&qself.ty))
        }
        syn::Type::Reference(reference) => type_mentions_protected_config(&reference.elem),
        syn::Type::Paren(paren) => type_mentions_protected_config(&paren.elem),
        syn::Type::Group(group) => type_mentions_protected_config(&group.elem),
        _ => false,
    }
}

fn expr_path_mentions_protected_config(expr: &syn::Expr) -> bool {
    let syn::Expr::Path(path) = transparent_expr(expr) else {
        return false;
    };
    path.path
        .segments
        .iter()
        .any(|segment| ident_is_protected_config(&segment.ident))
        || path
            .qself
            .as_ref()
            .is_some_and(|qself| type_mentions_protected_config(&qself.ty))
}

fn macro_mentions_protected_config(mac: &syn::Macro) -> bool {
    fn contains(tokens: proc_macro2::TokenStream) -> bool {
        tokens.into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => ident_is_protected_config(&ident),
            proc_macro2::TokenTree::Group(group) => contains(group.stream()),
            _ => false,
        })
    }
    contains(mac.tokens.clone())
}

impl<'ast> Visit<'ast> for ProductionRuntimeConfigInventory {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.symbol_origins.clear();
        self.vault_config_bindings.clear();
        for item in &file.items {
            if let syn::Item::Use(item) = item
                && attrs_may_be_production(&item.attrs)
            {
                self.record_use_tree(&item.tree, &mut Vec::new());
            }
        }
        syn::visit::visit_file(self, file);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if internal_redis_values_seam_is_exact(item) || internal_vault_s3_values_seam_is_exact(item)
        {
            return;
        }
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if attrs_may_be_production(&item.attrs) && use_tree_has_protected_rename(&item.tree) {
            self.forbidden_indirections += 1;
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if attrs_may_be_production(&item.attrs) && type_mentions_protected_config(&item.ty) {
            self.forbidden_indirections += 1;
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if local
            .init
            .as_ref()
            .is_some_and(|init| expr_path_mentions_protected_config(&init.expr))
        {
            self.forbidden_indirections += 1;
        }
        if let (Some(binding), Some(initializer)) = (
            immutable_pat_ident(&local.pat),
            local.init.as_ref().map(|init| transparent_expr(&init.expr)),
        ) {
            let mapping = call_behind_result_context(initializer).or_else(|| {
                let syn::Expr::Match(match_) = initializer else {
                    return None;
                };
                let syn::Expr::Call(call) = transparent_expr(&match_.expr) else {
                    return None;
                };
                Some(call)
            });
            if mapping.is_some_and(|call| {
                self.associated_call_is_canonical(call, "from_snapshot", "VaultRuntimeConfig")
            }) {
                self.vault_config_bindings.insert(binding.to_string());
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let snapshot = call.args.is_empty()
            && self.associated_call_is_canonical(
                call,
                "capture_process_snapshot",
                "RuntimeConfigSnapshot",
            );
        let inputs = self.associated_call_is_canonical(call, "new", "PreparedRuntimeInputs");
        let serving_mapping =
            self.associated_call_is_canonical(call, "from_snapshot", "RuntimeServingConfig");
        let pg_mapping =
            self.associated_call_is_canonical(call, "from_snapshot", "PgRuntimeConfig");
        let redis_mapping =
            self.associated_call_is_canonical(call, "from_snapshot", "RedisRuntimeConfig");
        let vault_mapping =
            self.associated_call_is_canonical(call, "from_snapshot", "VaultRuntimeConfig");
        let s3_mapping =
            self.associated_call_is_canonical(call, "from_snapshot", "S3RuntimeConfig");
        if snapshot {
            self.snapshot_calls += 1;
        }
        if inputs {
            self.runtime_inputs_calls += 1;
        }
        if pg_mapping {
            self.pg_config_calls += 1;
        }
        if redis_mapping {
            self.redis_config_calls += 1;
        }
        if vault_mapping {
            self.vault_config_calls += 1;
        }
        if s3_mapping {
            self.s3_config_calls += 1;
        }
        let redis_build = self.path_is_canonical(&call.func, "build_redis_runtime_deps");
        let s3_build = self.path_is_canonical(&call.func, "build_s3_runtime_deps");
        let s3_dlx_build = self.path_is_canonical(&call.func, "build_s3_dlx_archive_store");
        if redis_build {
            self.redis_calls += 1;
        }
        if s3_build {
            self.s3_calls += 1;
        }
        if s3_dlx_build {
            self.s3_dlx_calls += 1;
        }
        if !snapshot
            && !inputs
            && !serving_mapping
            && !pg_mapping
            && !redis_mapping
            && !vault_mapping
            && !s3_mapping
            && !redis_build
            && !s3_build
            && !s3_dlx_build
            && (expr_path_mentions_protected_config(&call.func)
                || self.protected_path_is_unresolved(&call.func))
        {
            self.forbidden_indirections += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let canonical_vault_receiver = matches!(transparent_expr(&call.receiver), syn::Expr::Path(path)
        if path.path.get_ident().is_some_and(|ident| {
            self.vault_config_bindings.contains(&ident.to_string())
        }));
        if canonical_vault_receiver {
            match call.method.to_string().as_str() {
                "into_runtime" => self.vault_runtime_consumes += 1,
                "into_settings_key_provider" => self.vault_settings_consumes += 1,
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if macro_mentions_protected_config(mac) {
            self.forbidden_indirections += 1;
        }
    }
}

fn direct_call_behind_runtime_context(expr: &syn::Expr) -> Option<&syn::ExprCall> {
    match transparent_expr(expr) {
        syn::Expr::Call(call) => Some(call),
        syn::Expr::Try(expr) => direct_call_behind_runtime_context(&expr.expr),
        syn::Expr::Await(expr) => direct_call_behind_runtime_context(&expr.base),
        syn::Expr::MethodCall(call)
            if matches!(call.method.to_string().as_str(), "context" | "with_context") =>
        {
            direct_call_behind_runtime_context(&call.receiver)
        }
        _ => None,
    }
}

#[derive(Default)]
struct BinaryRuntimeWiring {
    prepare_calls: usize,
    run_calls: usize,
    shutdown_calls: usize,
    prepared_binding: Option<syn::Ident>,
    canonical_run_calls: usize,
    canonical_shutdown_calls: usize,
    forbidden_indirections: usize,
}

fn use_tree_has_binary_indirection(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(rename) => {
            matches!(
                rename.ident.to_string().as_str(),
                "runtime" | "prepare_runtime" | "run" | "shutdown_runtime"
            ) || matches!(
                rename.rename.to_string().as_str(),
                "runtime" | "prepare_runtime" | "run" | "shutdown_runtime"
            )
        }
        syn::UseTree::Name(name) => matches!(
            name.ident.to_string().as_str(),
            "runtime" | "prepare_runtime" | "run" | "shutdown_runtime"
        ),
        syn::UseTree::Path(path) => use_tree_has_binary_indirection(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_has_binary_indirection),
        syn::UseTree::Glob(_) => true,
    }
}

fn macro_mentions_binary_runtime(mac: &syn::Macro) -> bool {
    let rendered = mac.tokens.to_string();
    ["prepare_runtime", "shutdown_runtime", "runtime :: run"]
        .iter()
        .any(|symbol| rendered.contains(symbol))
}

impl BinaryRuntimeWiring {
    fn record_exact_binding(&mut self, call: &syn::ExprCall, run: bool) {
        let canonical = self.prepared_binding.as_ref().is_some_and(|binding| {
            call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|arg| is_exact_ident_path(arg, binding))
        });
        if canonical {
            if run {
                self.canonical_run_calls += 1;
            } else {
                self.canonical_shutdown_calls += 1;
            }
        }
    }
}

impl<'ast> Visit<'ast> for BinaryRuntimeWiring {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if attrs_may_be_production(&item.attrs) && use_tree_has_binary_indirection(&item.tree) {
            self.forbidden_indirections += 1;
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (Some(binding), Some(call)) = (
            pat_ident(&local.pat),
            local
                .init
                .as_ref()
                .and_then(|init| direct_call_behind_runtime_context(&init.expr)),
        ) && path_ends_with(&call.func, &["runtime", "prepare_runtime"])
            && self.prepared_binding.is_none()
        {
            self.prepared_binding = Some(binding.clone());
        }
        if local.init.as_ref().is_some_and(|init| {
            let Some(last) = expr_path_last(&init.expr) else {
                return false;
            };
            matches!(
                last.to_string().as_str(),
                "prepare_runtime" | "run" | "shutdown_runtime"
            )
        }) {
            self.forbidden_indirections += 1;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["runtime", "prepare_runtime"]) {
            self.prepare_calls += 1;
        } else if path_ends_with(&call.func, &["runtime", "run"]) {
            self.run_calls += 1;
            self.record_exact_binding(call, true);
        } else if path_ends_with(&call.func, &["runtime", "shutdown_runtime"]) {
            self.shutdown_calls += 1;
            self.record_exact_binding(call, false);
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if macro_mentions_binary_runtime(mac) {
            self.forbidden_indirections += 1;
        }
    }
}

const RSS_COMMAND_FAMILIES: &[(&str, Option<&str>, Option<&str>)] = &[
    ("Serving", None, None),
    (
        "Postgres",
        Some("is_postgres_command"),
        Some("run_postgres_reader_migration_command"),
    ),
    (
        "Projection",
        Some("is_projection_command"),
        Some("run_projection_control_command"),
    ),
    (
        "AuditLedgerVerify",
        Some("is_audit_ledger_verify_command"),
        Some("run_audit_ledger_verify_command"),
    ),
    (
        "Dlq",
        Some("is_dlq_command"),
        Some("run_dlq_control_command"),
    ),
    (
        "ReconcileTarget",
        Some("is_reconcile_target_command"),
        Some("run_reconcile_target_command"),
    ),
    (
        "SettingsConfigValueMaintenance",
        Some("is_settings_config_value_maintenance_command"),
        Some("run_settings_config_value_maintenance"),
    ),
    (
        "RssAccessJwksExport",
        Some("is_rss_access_jwks_export_command"),
        Some("run_rss_access_jwks_export_command"),
    ),
];

fn exact_command_variant(expr: &syn::Expr, expected: &str) -> bool {
    is_exact_path(expr, &["CommandFamily", expected])
}

fn ok_command_variant(expr: &syn::Expr, expected: &str) -> bool {
    let Some(call) = direct_call_behind_runtime_context(expr) else {
        return false;
    };
    is_exact_path(&call.func, &["Ok"])
        && call.args.len() == 1
        && call
            .args
            .first()
            .is_some_and(|arg| exact_command_variant(arg, expected))
}

fn command_variant_pattern<'a>(pattern: &'a syn::Pat, enum_name: &str) -> Option<&'a syn::Ident> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 2 {
        return None;
    }
    let mut segments = path.path.segments.iter();
    if segments
        .next()
        .is_none_or(|segment| segment.ident != enum_name)
    {
        return None;
    }
    segments.next().map(|segment| &segment.ident)
}

fn reference_to_binding(expr: &syn::Expr, binding: &syn::Ident) -> bool {
    matches!(
        transparent_expr(expr),
        syn::Expr::Reference(reference)
            if reference.mutability.is_none() && is_exact_ident_path(&reference.expr, binding)
    )
}

fn direct_awaited_call(expr: &syn::Expr) -> Option<&syn::ExprCall> {
    let syn::Expr::Await(awaited) = transparent_expr(expr) else {
        return None;
    };
    let syn::Expr::Call(call) = transparent_expr(&awaited.base) else {
        return None;
    };
    Some(call)
}

fn is_canonical_process_args(expr: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(collect) = transparent_expr(expr) else {
        return false;
    };
    let syn::Expr::MethodCall(skip) = transparent_expr(&collect.receiver) else {
        return false;
    };
    let Some(args_call) = direct_call_behind_runtime_context(&skip.receiver) else {
        return false;
    };
    collect.method == "collect"
        && collect.args.is_empty()
        && skip.method == "skip"
        && skip.args.len() == 1
        && skip.args.first().is_some_and(|amount| {
            matches!(
                transparent_expr(amount),
                syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_digits() == "1")
            )
        })
        && is_exact_path(&args_call.func, &["std", "env", "args"])
        && args_call.args.is_empty()
}

fn classifier_if_is_canonical(
    statement: &syn::Stmt,
    args: &syn::Ident,
    predicate: &str,
    variant: &str,
) -> bool {
    let syn::Stmt::Expr(expr, None) = statement else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(expr) else {
        return false;
    };
    let Some(condition) = direct_call_behind_runtime_context(&branch.cond) else {
        return false;
    };
    let condition_is_canonical = is_exact_path(&condition.func, &["runtime", predicate])
        && condition.args.len() == 1
        && condition
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, args));
    let return_is_canonical = match branch.then_branch.stmts.as_slice() {
        [syn::Stmt::Expr(expr, Some(_))] | [syn::Stmt::Expr(expr, None)] => {
            let syn::Expr::Return(returned) = transparent_expr(expr) else {
                return false;
            };
            returned.expr.as_deref().is_some_and(|expr| {
                let Some(ok) = direct_call_behind_runtime_context(expr) else {
                    return false;
                };
                let Some(operator) = ok.args.first().and_then(direct_call_behind_runtime_context)
                else {
                    return false;
                };
                is_exact_path(&ok.func, &["Ok"])
                    && ok.args.len() == 1
                    && is_exact_path(&operator.func, &["CommandFamily", "Operator"])
                    && operator.args.len() == 1
                    && operator.args.first().is_some_and(|command| {
                        is_exact_path(command, &["OperatorCommand", variant])
                    })
            })
        }
        _ => false,
    };
    condition_is_canonical && return_is_canonical && branch.else_branch.is_none()
}

fn classifier_is_canonical(file: &syn::File) -> bool {
    let family_enums = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item)
                if item.ident == "CommandFamily" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let classifiers = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "classify_command" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let operator_enums = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item)
                if item.ident == "OperatorCommand" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if family_enums.len() != 1 || operator_enums.len() != 1 || classifiers.len() != 1 {
        return false;
    }
    let family = family_enums[0];
    let family_is_exact = family.variants.len() == 2
        && family.variants.iter().any(|variant| {
            variant.ident == "Serving" && matches!(variant.fields, syn::Fields::Unit)
        })
        && family.variants.iter().any(|variant| {
            variant.ident == "Operator"
                && matches!(&variant.fields, syn::Fields::Unnamed(fields)
                    if fields.unnamed.len() == 1
                        && compact_type_tokens(&fields.unnamed[0].ty) == "OperatorCommand")
        });
    let expected_variants = RSS_COMMAND_FAMILIES
        .iter()
        .filter(|(variant, _, _)| *variant != "Serving")
        .map(|(variant, _, _)| (*variant).to_owned())
        .collect::<BTreeSet<_>>();
    let observed_variants = operator_enums[0]
        .variants
        .iter()
        .filter(|variant| matches!(variant.fields, syn::Fields::Unit))
        .map(|variant| variant.ident.to_string())
        .collect::<BTreeSet<_>>();
    if !family_is_exact
        || operator_enums[0].variants.len() != expected_variants.len()
        || observed_variants != expected_variants
    {
        return false;
    }

    let classifier = classifiers[0];
    if classifier.sig.asyncness.is_some() || classifier.sig.inputs.len() != 1 {
        return false;
    }
    let Some(syn::FnArg::Typed(input)) = classifier.sig.inputs.first() else {
        return false;
    };
    let Some(args) = pat_ident(&input.pat) else {
        return false;
    };
    let operator_families = RSS_COMMAND_FAMILIES
        .iter()
        .filter_map(|(variant, predicate, _)| predicate.map(|predicate| (*variant, predicate)))
        .collect::<Vec<_>>();
    if classifier.block.stmts.len() != operator_families.len() + 2 {
        return false;
    }
    if !operator_families.iter().zip(&classifier.block.stmts).all(
        |((variant, predicate), statement)| {
            classifier_if_is_canonical(statement, args, predicate, variant)
        },
    ) {
        return false;
    }
    let ensure_statement = &classifier.block.stmts[operator_families.len()];
    let ensure_is_canonical = match ensure_statement {
        syn::Stmt::Macro(statement) => {
            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            is_exact_syn_path(&statement.mac.path, &["anyhow", "ensure"])
                && parser
                    .parse2(statement.mac.tokens.clone())
                    .ok()
                    .and_then(|arguments| arguments.into_iter().next())
                    .is_some_and(|condition| {
                        matches!(
                            transparent_expr(&condition),
                            syn::Expr::MethodCall(call)
                                if call.method == "is_empty"
                                    && call.args.is_empty()
                                    && is_exact_ident_path(&call.receiver, args)
                        )
                    })
        }
        _ => false,
    };
    let serving_is_canonical = match classifier.block.stmts.last() {
        Some(syn::Stmt::Expr(expr, None)) => ok_command_variant(expr, "Serving"),
        _ => false,
    };
    ensure_is_canonical && serving_is_canonical
}

fn rss_main_is_canonical(main: &syn::ItemFn) -> bool {
    if main.sig.asyncness.is_none()
        || !matches!(&main.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == "anyhow::Result<()>")
        || main.block.stmts.len() != 7
    {
        return false;
    }
    let [
        args_statement,
        command_statement,
        serving_statement,
        prepare_statement,
        result_statement,
        shutdown_statement,
        tail_statement,
    ] = main.block.stmts.as_slice()
    else {
        return false;
    };
    let syn::Stmt::Local(args_local) = args_statement else {
        return false;
    };
    let Some(args) = pat_ident(&args_local.pat) else {
        return false;
    };
    if !args_local
        .init
        .as_ref()
        .is_some_and(|init| is_canonical_process_args(&init.expr))
    {
        return false;
    }
    let syn::Stmt::Local(command_local) = command_statement else {
        return false;
    };
    let Some(command) = pat_ident(&command_local.pat) else {
        return false;
    };
    let Some(classify_call) = command_local
        .init
        .as_ref()
        .and_then(|init| direct_call_behind_runtime_context(&init.expr))
    else {
        return false;
    };
    if !is_exact_path(&classify_call.func, &["classify_command"])
        || classify_call.args.len() != 1
        || !classify_call
            .args
            .first()
            .is_some_and(|arg| reference_to_binding(arg, args))
    {
        return false;
    }
    let syn::Stmt::Local(serving_local) = serving_statement else {
        return false;
    };
    let syn::Pat::TupleStruct(operator_pattern) = &serving_local.pat else {
        return false;
    };
    let Some(syn::Pat::Ident(operator_command)) = operator_pattern.elems.first() else {
        return false;
    };
    let Some(serving_init) = serving_local.init.as_ref() else {
        return false;
    };
    let serving_is_canonical =
        is_exact_syn_path(&operator_pattern.path, &["CommandFamily", "Operator"])
            && operator_pattern.elems.len() == 1
            && operator_command.by_ref.is_none()
            && operator_command.mutability.is_none()
            && operator_command.subpat.is_none()
            && is_exact_ident_path(&serving_init.expr, command)
            && serving_init.diverge.as_ref().is_some_and(|(_, diverge)| {
                let syn::Expr::Block(block) = transparent_expr(diverge) else {
                    return false;
                };
                let [syn::Stmt::Expr(return_expr, Some(_))] = block.block.stmts.as_slice() else {
                    return false;
                };
                let syn::Expr::Return(returned) = transparent_expr(return_expr) else {
                    return false;
                };
                let Some(run_call) = returned.expr.as_deref().and_then(direct_awaited_call) else {
                    return false;
                };
                let Some(prepare_call) = run_call
                    .args
                    .first()
                    .and_then(direct_call_behind_runtime_context)
                else {
                    return false;
                };
                is_exact_path(&run_call.func, &["runtime", "run"])
                    && run_call.args.len() == 1
                    && is_exact_path(&prepare_call.func, &["runtime", "prepare_runtime"])
                    && prepare_call.args.is_empty()
            });
    if !serving_is_canonical {
        return false;
    }

    let syn::Stmt::Local(prepare_local) = prepare_statement else {
        return false;
    };
    let Some(runtime_inputs) = pat_ident(&prepare_local.pat) else {
        return false;
    };
    let Some(prepare_call) = prepare_local
        .init
        .as_ref()
        .and_then(|init| direct_call_behind_runtime_context(&init.expr))
    else {
        return false;
    };
    if !is_exact_path(&prepare_call.func, &["runtime", "prepare_operator_runtime"])
        || !prepare_call.args.is_empty()
    {
        return false;
    }
    let syn::Stmt::Local(result_local) = result_statement else {
        return false;
    };
    let Some(result) = pat_ident(&result_local.pat) else {
        return false;
    };
    let Some(syn::Expr::Match(dispatch)) = result_local
        .init
        .as_ref()
        .map(|init| transparent_expr(&init.expr))
    else {
        return false;
    };
    if !is_exact_ident_path(&dispatch.expr, &operator_command.ident)
        || dispatch.arms.len() != RSS_COMMAND_FAMILIES.len() - 1
    {
        return false;
    }
    let mut observed = BTreeSet::new();
    for arm in &dispatch.arms {
        if arm.guard.is_some() || !arm.attrs.is_empty() {
            return false;
        }
        let Some(variant) =
            command_variant_pattern(&arm.pat, "OperatorCommand").map(ToString::to_string)
        else {
            return false;
        };
        let Some((_, _, runner)) = RSS_COMMAND_FAMILIES
            .iter()
            .find(|(expected, _, _)| *expected == variant)
        else {
            return false;
        };
        if !observed.insert(variant.clone()) {
            return false;
        }
        let Some(runner) = runner else {
            return false;
        };
        let Some(call) = direct_awaited_call(&arm.body) else {
            return false;
        };
        if !is_exact_path(&call.func, &["runtime", runner])
            || call.args.len() != 2
            || !call
                .args
                .first()
                .is_some_and(|arg| reference_to_binding(arg, args))
            || !call
                .args
                .iter()
                .nth(1)
                .is_some_and(|arg| reference_to_binding(arg, runtime_inputs))
        {
            return false;
        }
    }
    let syn::Stmt::Expr(shutdown, Some(_)) = shutdown_statement else {
        return false;
    };
    let syn::Expr::Try(shutdown) = transparent_expr(shutdown) else {
        return false;
    };
    let Some(shutdown_call) = direct_awaited_call(&shutdown.expr) else {
        return false;
    };
    if !is_exact_path(
        &shutdown_call.func,
        &["runtime", "shutdown_operator_runtime"],
    ) || shutdown_call.args.len() != 1
        || !shutdown_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, runtime_inputs))
    {
        return false;
    }
    matches!(
        tail_statement,
        syn::Stmt::Expr(expr, None) if is_exact_ident_path(expr, result)
    )
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
    let mut findings = production_runtime_config_snapshot_findings(&file);
    if root.join(RSS_MAIN_PATH).exists() && !pg_operator_definitions_are_exact(&file) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "the six PG operator definitions must expose the exact &OperatorRuntimeInputs parameter and flow its .config() view into the typed PG maintenance builder/runtime without ignored, wrong-binding, ambient-wrapper, or compliant-bait paths",
        ));
    }
    findings.extend(runtime_profile_inputs_findings(root)?);
    findings.extend(runtime_config_global_capture_findings(root)?);
    findings.extend(runtime_snapshot_consumer_ambient_findings(root)?);
    findings.extend(redis_snapshot_boundary_findings(root, &file)?);
    findings.extend(vault_s3_values_boundary_findings(root, &file)?);
    Ok(findings)
}

fn runtime_profile_inputs_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let phase_path = root.join(RUNTIME_PHASE_PATH);
    if !phase_path.exists() {
        return Ok(Vec::new());
    }
    let phase_source = fs::read_to_string(&phase_path)
        .with_context(|| format!("读 {} 失败", phase_path.display()))?;
    let phase_file = match syn::parse_file(&phase_source) {
        Ok(file) => file,
        Err(error) => {
            return Ok(vec![finding(
                Rule::ForbiddenWiring,
                RUNTIME_PHASE_PATH,
                format!("runtime profile input gate 无法解析 Rust: {error}"),
            )]);
        }
    };
    let mut findings = Vec::new();
    if !runtime_profile_input_structs_are_exact(&phase_file) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PATH,
            "ServingRuntimeInputs must privately own exactly PreparedRuntimeInputs plus Arc<secure::DigestPasswordBlocklist>; OperatorRuntimeInputs must privately own only PreparedRuntimeInputs, making the password capability unrepresentable",
        ));
    }

    let vault_path = root.join(RUNTIME_VAULT_PATH);
    if vault_path.exists() {
        let vault_source = fs::read_to_string(&vault_path)
            .with_context(|| format!("读 {} 失败", vault_path.display()))?;
        let vault_file = match syn::parse_file(&vault_source) {
            Ok(file) => file,
            Err(error) => {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_VAULT_PATH,
                    format!("RSS access JWKS operator profile gate 无法解析 Rust: {error}"),
                ));
                return Ok(findings);
            }
        };
        if !rss_access_jwks_operator_signature_is_exact(&vault_file) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_VAULT_PATH,
                "run_rss_access_jwks_export_command must accept the exact &[String] and &crate::OperatorRuntimeInputs inputs; serving inputs and ambient configuration are forbidden",
            ));
        }
    }
    Ok(findings)
}

fn runtime_profile_input_structs_are_exact(file: &syn::File) -> bool {
    fn exact_fields(file: &syn::File, name: &str, expected: &[(&str, &str)]) -> bool {
        let structs = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item)
                    if item.ident == name && attrs_may_be_production(&item.attrs) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let Some(item) = (structs.len() == 1).then_some(structs[0]) else {
            return false;
        };
        let syn::Fields::Named(fields) = &item.fields else {
            return false;
        };
        matches!(item.vis, syn::Visibility::Public(_))
            && fields.named.len() == expected.len()
            && fields.named.iter().zip(expected).all(|(field, expected)| {
                matches!(field.vis, syn::Visibility::Inherited)
                    && field
                        .ident
                        .as_ref()
                        .is_some_and(|ident| ident == expected.0)
                    && compact_type_tokens(&field.ty) == expected.1
            })
    }

    exact_fields(
        file,
        "ServingRuntimeInputs",
        &[
            ("prepared", "PreparedRuntimeInputs"),
            (
                "password_blocklist",
                "std::sync::Arc<secure::DigestPasswordBlocklist>",
            ),
        ],
    ) && exact_fields(
        file,
        "OperatorRuntimeInputs",
        &[("prepared", "PreparedRuntimeInputs")],
    )
}

fn rss_access_jwks_operator_signature_is_exact(file: &syn::File) -> bool {
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "run_rss_access_jwks_export_command"
                    && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(function) = (functions.len() == 1).then_some(functions[0]) else {
        return false;
    };
    let inputs = function.sig.inputs.iter().collect::<Vec<_>>();
    function.sig.asyncness.is_some()
        && matches!(function.vis, syn::Visibility::Public(_))
        && inputs.len() == 2
        && matches!(inputs[0], syn::FnArg::Typed(input)
            if compact_type_tokens(input.ty.as_ref()) == "&[String]")
        && matches!(inputs[1], syn::FnArg::Typed(input)
            if compact_type_tokens(input.ty.as_ref()) == "&crate::OperatorRuntimeInputs")
        && matches!(&function.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == "anyhow::Result<()>")
}

fn public_redis_values_wrapper_is_exact(item: &syn::ItemFn) -> bool {
    if !matches!(item.vis, syn::Visibility::Public(_))
        || !redis_values_signature_is_exact(&item.sig)
        || item.block.stmts.len() != 1
    {
        return false;
    }
    let syn::Stmt::Expr(tail, None) = &item.block.stmts[0] else {
        return false;
    };
    let Some(call) = direct_awaited_call(tail) else {
        return false;
    };
    is_exact_path(
        &call.func,
        &[
            "crate",
            "infra",
            "redis",
            "build_redis_runtime_deps_from_values",
        ],
    ) && call.args.len() == 2
        && call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &["url"]))
        && call
            .args
            .iter()
            .nth(1)
            .is_some_and(|arg| is_exact_path(arg, &["allow_plaintext"]))
}

fn redis_test_support_wrapper_is_exact(file: &syn::File) -> bool {
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "test_support" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(module) = (modules.len() == 1).then_some(modules[0]) else {
        return false;
    };
    if !matches!(module.vis, syn::Visibility::Public(_))
        || !has_one_exact_cfg(&module.attrs, cfg_is_exact_integration)
    {
        return false;
    }
    let Some((_, items)) = &module.content else {
        return false;
    };
    let wrappers = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "build_redis_runtime_deps_from_values" =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    wrappers.len() == 1 && public_redis_values_wrapper_is_exact(wrappers[0])
}

fn method_call_count_in_expr(expr: &syn::Expr, method: &str) -> usize {
    struct Counter<'a> {
        method: &'a str,
        calls: usize,
    }
    impl Visit<'_> for Counter<'_> {
        fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
            if call.method == self.method {
                self.calls += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut counter = Counter { method, calls: 0 };
    counter.visit_expr(expr);
    counter.calls
}

#[derive(Default)]
struct ProductionCreatePoolInventory {
    calls: usize,
}

impl<'ast> Visit<'ast> for ProductionCreatePoolInventory {
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
        if call.method == "create_pool" {
            self.calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct RedisPoolUses<'a> {
    pool: Option<&'a syn::Ident>,
    verify_calls: usize,
    canonical_verify_calls: usize,
    setup_calls: usize,
    canonical_setup_calls: usize,
}

impl<'ast> Visit<'ast> for RedisPoolUses<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["verify_redis_pool"]) {
            self.verify_calls += 1;
            self.canonical_verify_calls += usize::from(self.pool.is_some_and(|pool| {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .is_some_and(|arg| reference_to_binding(arg, pool))
            }));
        }
        if path_ends_with(&call.func, &["RedisRuntimeDeps", "setup"]) {
            self.setup_calls += 1;
            self.canonical_setup_calls += usize::from(self.pool.is_some_and(|pool| {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .is_some_and(|arg| is_exact_ident_path(arg, pool))
            }));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn redis_pool_flow_is_exact(file: &syn::File) -> bool {
    let builders = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "build_redis_runtime_deps"
                    && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(builder) = (builders.len() == 1).then_some(builders[0]) else {
        return false;
    };
    let pool_bindings = builder
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local)
                if local.init.as_ref().is_some_and(|init| {
                    method_call_count_in_expr(&init.expr, "create_pool") == 1
                }) =>
            {
                pat_ident(&local.pat)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(pool) = (pool_bindings.len() == 1).then_some(pool_bindings[0]) else {
        return false;
    };
    let mut global = ProductionCreatePoolInventory::default();
    global.visit_file(file);
    let mut uses = RedisPoolUses {
        pool: Some(pool),
        ..RedisPoolUses::default()
    };
    uses.visit_block(&builder.block);
    global.calls == 1
        && method_call_count_in_block(&builder.block, "create_pool") == 1
        && uses.verify_calls == 1
        && uses.canonical_verify_calls == 1
        && uses.setup_calls == 1
        && uses.canonical_setup_calls == 1
}

fn redis_snapshot_boundary_findings(
    root: &Path,
    runtime_file: &syn::File,
) -> Result<Vec<Finding<Rule>>> {
    let path = root.join("assemblies/runtime/src/infra/redis.rs");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let source =
        fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let redis_file = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => {
            return Ok(vec![finding(
                Rule::ForbiddenWiring,
                "assemblies/runtime/src/infra/redis.rs",
                format!("Redis snapshot boundary gate 无法解析 Rust: {error}"),
            )]);
        }
    };
    let internal = redis_file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "build_redis_runtime_deps_from_values" =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if internal.len() == 1
        && internal_redis_values_seam_is_exact(internal[0])
        && redis_test_support_wrapper_is_exact(runtime_file)
        && redis_pool_flow_is_exact(&redis_file)
    {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        "assemblies/runtime/src/infra/redis.rs",
        "Redis explicit-values seam must remain cfg(any(test, feature = \"integration\")) + pub(crate) with its exact signature, the public wrapper must remain cfg(feature = \"integration\"), and the sole production create_pool binding must flow to both verify_redis_pool and RedisRuntimeDeps::setup",
    )])
}

fn vault_s3_values_boundary_findings(
    root: &Path,
    runtime_file: &syn::File,
) -> Result<Vec<Finding<Rule>>> {
    let mut exact_internal = true;
    let mut observed_internal_files = 0;
    for (path, name) in [
        (RUNTIME_VAULT_PATH, "build_vault_runtime_from_values"),
        (RUNTIME_S3_PATH, "build_s3_runtime_deps_from_values"),
    ] {
        let source_path = root.join(path);
        if !source_path.exists() {
            continue;
        }
        observed_internal_files += 1;
        let source = fs::read_to_string(&source_path).with_context(|| format!("读 {path} 失败"))?;
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    path,
                    format!("Vault/S3 explicit-values seam gate 无法解析 Rust: {error}"),
                )]);
            }
        };
        let functions = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        exact_internal &=
            functions.len() == 1 && internal_vault_s3_values_seam_is_exact(functions[0]);
    }
    if observed_internal_files == 0 {
        return Ok(Vec::new());
    }
    exact_internal &= observed_internal_files == VALUES_SEAM_SPECS.len();
    if exact_internal && vault_s3_test_support_wrappers_are_exact(runtime_file) {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        RUNTIME_LIB_PATH,
        "Vault/S3 explicit-values seams must retain their exact cfg(any(test, feature = \"integration\")) internal signatures and typed bodies; public test_support wrappers must retain exact cfg(feature = \"integration\") signatures and single direct delegation",
    )])
}

fn pg_operator_signature_bindings(
    item: &syn::ItemFn,
    name: &str,
) -> Option<(syn::Ident, syn::Ident)> {
    let inputs = item.sig.inputs.iter().collect::<Vec<_>>();
    if item.sig.ident != name
        || !matches!(item.vis, syn::Visibility::Public(_))
        || item.sig.asyncness.is_none()
        || item.sig.constness.is_some()
        || item.sig.unsafety.is_some()
        || !item.sig.generics.params.is_empty()
        || inputs.len() != 2
        || !matches!(&item.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == "anyhow::Result<()>")
    {
        return None;
    }
    let syn::FnArg::Typed(args) = inputs[0] else {
        return None;
    };
    let syn::FnArg::Typed(runtime_inputs) = inputs[1] else {
        return None;
    };
    let runtime_inputs_type = compact_type_tokens(runtime_inputs.ty.as_ref());
    if compact_type_tokens(args.ty.as_ref()) != "&[String]"
        || runtime_inputs_type != "&OperatorRuntimeInputs"
    {
        return None;
    }
    Some((
        pat_ident(&args.pat)?.clone(),
        pat_ident(&runtime_inputs.pat)?.clone(),
    ))
}

fn self_config_field(expr: &syn::Expr) -> bool {
    matches!(transparent_expr(expr), syn::Expr::Field(field)
        if is_exact_path(&field.base, &["self"])
            && matches!(&field.member, syn::Member::Named(member) if member == "config"))
}

#[derive(Clone, Copy)]
enum PgBuilderOrigin<'a> {
    SelfConfig,
    RuntimeInputs(&'a syn::Ident),
}

fn pg_source_expr_is_canonical(
    expr: &syn::Expr,
    origin: PgBuilderOrigin<'_>,
    aliases: &BTreeSet<String>,
) -> bool {
    let expr = transparent_expr(expr);
    if let syn::Expr::Path(path) = expr
        && let Some(ident) = path.path.get_ident()
        && aliases.contains(&ident.to_string())
    {
        return true;
    }
    match origin {
        PgBuilderOrigin::SelfConfig => self_config_field(expr),
        PgBuilderOrigin::RuntimeInputs(runtime_inputs) => {
            is_runtime_inputs_config_view(expr, runtime_inputs)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PgConfigProvenance {
    Migrator,
    AuditMigrator,
    AuditAdmin,
}

struct PgBuilderFlow<'a> {
    expected_builder: &'a str,
    origin: PgBuilderOrigin<'a>,
    source_aliases: BTreeSet<String>,
    config_aliases: BTreeMap<String, PgConfigProvenance>,
    builder_like_calls: usize,
    exact_calls: usize,
    config_calls: usize,
    canonical_config_calls: usize,
    sink_calls: usize,
    canonical_sink_calls: usize,
}

impl PgBuilderFlow<'_> {
    fn expected_builder_kind(&self) -> PgConfigProvenance {
        if self.expected_builder == "build_pg_audit_maintenance_config" {
            PgConfigProvenance::AuditMigrator
        } else {
            PgConfigProvenance::Migrator
        }
    }

    fn builder_call<'a>(&self, expr: &'a syn::Expr) -> Option<&'a syn::ExprCall> {
        let expr = match transparent_expr(expr) {
            syn::Expr::Reference(reference) => reference.expr.as_ref(),
            expr => expr,
        };
        call_behind_result_context(expr)
    }

    fn builder_is_canonical(&self, call: &syn::ExprCall) -> bool {
        expr_path_last(&call.func).is_some_and(|name| name == self.expected_builder)
            && call.args.len() == 1
            && call.args.first().is_some_and(|argument| {
                pg_source_expr_is_canonical(argument, self.origin, &self.source_aliases)
            })
    }

    fn config_provenance(&self, expr: &syn::Expr) -> Option<PgConfigProvenance> {
        let expr = transparent_expr(expr);
        match expr {
            syn::Expr::Reference(reference) => self.config_provenance(&reference.expr),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| self.config_aliases.get(&ident.to_string()).copied()),
            syn::Expr::MethodCall(call) if call.method == "as_ref" && call.args.is_empty() => {
                let kind = self.config_provenance(&call.receiver)?;
                (kind == PgConfigProvenance::AuditAdmin).then_some(kind)
            }
            _ => {
                let call = self.builder_call(expr)?;
                self.builder_is_canonical(call)
                    .then(|| self.expected_builder_kind())
            }
        }
    }

    fn record_sink(&mut self, call: &syn::ExprCall) {
        let name = expr_path_last(&call.func).map(ToString::to_string);
        let expected_kind = self.expected_builder_kind();
        let canonical = match (self.expected_builder, name.as_deref()) {
            ("build_pg_audit_maintenance_config", Some("connect_maintenance")) => {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .and_then(|arg| self.config_provenance(arg))
                        == Some(PgConfigProvenance::AuditMigrator)
            }
            (
                "build_pg_audit_maintenance_config",
                Some("connect_maintenance_with_audit_admin_config"),
            ) => {
                call.args.len() == 2
                    && call
                        .args
                        .first()
                        .and_then(|arg| self.config_provenance(arg))
                        == Some(PgConfigProvenance::AuditMigrator)
                    && call
                        .args
                        .iter()
                        .nth(1)
                        .and_then(|arg| self.config_provenance(arg))
                        == Some(PgConfigProvenance::AuditAdmin)
            }
            (_, Some("connect_maintenance" | "migrate_reader_lane_only")) => {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .and_then(|arg| self.config_provenance(arg))
                        == Some(expected_kind)
            }
            _ => return,
        };
        self.sink_calls += 1;
        self.canonical_sink_calls += usize::from(canonical);
    }

    fn is_exact(&self) -> bool {
        self.is_exact_with_runtime_config_calls(usize::from(matches!(
            self.origin,
            PgBuilderOrigin::RuntimeInputs(_)
        )))
    }

    fn is_exact_with_runtime_config_calls(&self, expected_config_calls: usize) -> bool {
        let expected_sinks = if self.expected_builder == "build_pg_audit_maintenance_config" {
            2
        } else {
            1
        };
        self.builder_like_calls == 1
            && self.exact_calls == 1
            && self.config_calls == expected_config_calls
            && self.canonical_config_calls == expected_config_calls
            && self.sink_calls == expected_sinks
            && self.canonical_sink_calls == expected_sinks
    }
}

impl<'ast> Visit<'ast> for PgBuilderFlow<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let Some(initializer) = local.init.as_ref().map(|init| init.expr.as_ref()) else {
            syn::visit::visit_local(self, local);
            return;
        };
        if let Some(binding) = immutable_pat_ident(&local.pat)
            && pg_source_expr_is_canonical(initializer, self.origin, &self.source_aliases)
        {
            self.source_aliases.insert(binding.to_string());
        }
        if let Some(call) = self.builder_call(initializer)
            && self.builder_is_canonical(call)
        {
            if self.expected_builder == "build_pg_audit_maintenance_config" {
                if let syn::Pat::Tuple(tuple) = &local.pat
                    && tuple.elems.len() == 2
                    && let (Some(migrator), Some(admin)) = (
                        tuple.elems.first().and_then(immutable_pat_ident),
                        tuple.elems.last().and_then(immutable_pat_ident),
                    )
                {
                    self.config_aliases
                        .insert(migrator.to_string(), PgConfigProvenance::AuditMigrator);
                    self.config_aliases
                        .insert(admin.to_string(), PgConfigProvenance::AuditAdmin);
                }
            } else if let Some(binding) = immutable_pat_ident(&local.pat) {
                self.config_aliases
                    .insert(binding.to_string(), PgConfigProvenance::Migrator);
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &syn::ExprCall) {
        let name = expr_path_last(&call.func).map(ToString::to_string);
        if name
            .as_deref()
            .is_some_and(|name| name.starts_with("build_pg_") && name.contains("config"))
        {
            self.builder_like_calls += 1;
        }
        if name.as_deref() == Some(self.expected_builder) && call.args.len() == 1 {
            let canonical = self.builder_is_canonical(call);
            self.exact_calls += usize::from(canonical);
        }
        self.record_sink(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
        if call.method == "config" && call.args.is_empty() {
            self.config_calls += 1;
            self.canonical_config_calls += usize::from(
                matches!(self.origin, PgBuilderOrigin::RuntimeInputs(runtime_inputs)
                    if is_exact_ident_path(&call.receiver, runtime_inputs)),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_match(&mut self, match_: &'ast syn::ExprMatch) {
        syn::visit::visit_expr(self, &match_.expr);
        let matched = self.config_provenance(&match_.expr);
        for arm in &match_.arms {
            for attribute in &arm.attrs {
                self.visit_attribute(attribute);
            }
            let introduced = if matched == Some(PgConfigProvenance::AuditAdmin)
                && let syn::Pat::TupleStruct(some) = &arm.pat
                && is_exact_syn_path(&some.path, &["Some"])
                && some.elems.len() == 1
                && let Some(binding) = some.elems.first().and_then(immutable_pat_ident)
            {
                self.config_aliases
                    .insert(binding.to_string(), PgConfigProvenance::AuditAdmin);
                Some(binding.to_string())
            } else {
                None
            };
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            if let Some(binding) = introduced {
                self.config_aliases.remove(&binding);
            }
        }
    }
}

fn pg_operator_runtime_struct_is_exact(file: &syn::File, name: &str) -> bool {
    let structures = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == name => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(item) = (structures.len() == 1).then_some(structures[0]) else {
        return false;
    };
    let syn::Fields::Named(fields) = &item.fields else {
        return false;
    };
    fields.named.len() == 2
        && fields.named.iter().any(|field| {
            field.ident.as_ref().is_some_and(|ident| ident == "config")
                && type_last_ident(&field.ty).is_some_and(|ident| ident == "SnapshotConfig")
                && matches!(field.vis, syn::Visibility::Inherited)
        })
        && fields.named.iter().any(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "operator")
                && type_last_ident(&field.ty)
                    .is_some_and(|ident| ident == "OperatorRuntimeCapability")
                && matches!(field.vis, syn::Visibility::Inherited)
        })
}

struct PgOperatorWrapperFlow<'a> {
    args: &'a syn::Ident,
    runtime_inputs: &'a syn::Ident,
    runtime_type: &'a str,
    with_runtime: &'a str,
    source_aliases: BTreeSet<String>,
    runtime_bindings: BTreeSet<String>,
    result_bindings: BTreeSet<String>,
    config_calls: usize,
    canonical_config_calls: usize,
    operator_capability_calls: usize,
    runtime_structs: usize,
    canonical_runtime_structs: usize,
    with_runtime_calls: usize,
    canonical_with_runtime_calls: usize,
}

impl<'a> PgOperatorWrapperFlow<'a> {
    fn new(
        args: &'a syn::Ident,
        runtime_inputs: &'a syn::Ident,
        runtime_type: &'a str,
        with_runtime: &'a str,
    ) -> Self {
        Self {
            args,
            runtime_inputs,
            runtime_type,
            with_runtime,
            source_aliases: BTreeSet::new(),
            runtime_bindings: BTreeSet::new(),
            result_bindings: BTreeSet::new(),
            config_calls: 0,
            canonical_config_calls: 0,
            operator_capability_calls: 0,
            runtime_structs: 0,
            canonical_runtime_structs: 0,
            with_runtime_calls: 0,
            canonical_with_runtime_calls: 0,
        }
    }

    fn runtime_struct_is_canonical(&self, runtime: &syn::ExprStruct) -> bool {
        is_exact_syn_path(&runtime.path, &[self.runtime_type])
            && runtime.rest.is_none()
            && runtime.fields.len() == 2
            && runtime.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == "config")
                    && pg_source_expr_is_canonical(
                        &field.expr,
                        PgBuilderOrigin::RuntimeInputs(self.runtime_inputs),
                        &self.source_aliases,
                    )
            })
            && runtime.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == "operator")
                    && matches!(transparent_expr(&field.expr), syn::Expr::MethodCall(call)
                        if call.method == "operator_capability"
                            && call.args.is_empty()
                            && is_exact_ident_path(&call.receiver, self.runtime_inputs))
            })
    }

    fn call_is_canonical(&self, call: &syn::ExprCall) -> bool {
        is_exact_path(&call.func, &[self.with_runtime])
            && call.args.len() == 2
            && call
                .args
                .first()
                .is_some_and(|argument| is_exact_ident_path(argument, self.args))
            && call.args.iter().nth(1).is_some_and(|argument| {
                matches!(transparent_expr(argument), syn::Expr::Reference(reference)
                if reference.mutability.is_none()
                    && matches!(transparent_expr(&reference.expr), syn::Expr::Path(path)
                        if path.path.get_ident().is_some_and(|ident| {
                            self.runtime_bindings.contains(&ident.to_string())
                        })))
            })
    }

    fn expr_call_is_canonical(&self, expr: &syn::Expr) -> bool {
        direct_call_behind_runtime_context(expr).is_some_and(|call| self.call_is_canonical(call))
    }

    fn return_expr_is_canonical(&self, expr: &syn::Expr) -> bool {
        self.expr_call_is_canonical(expr)
            || matches!(transparent_expr(expr), syn::Expr::Path(path)
            if path.path.get_ident().is_some_and(|ident| {
                self.result_bindings.contains(&ident.to_string())
            }))
    }

    fn is_exact(&self) -> bool {
        self.config_calls == 1
            && self.canonical_config_calls == 1
            && self.operator_capability_calls == 1
            && self.runtime_structs == 1
            && self.canonical_runtime_structs == 1
            && self.with_runtime_calls == 1
            && self.canonical_with_runtime_calls == 1
    }
}

impl<'ast> Visit<'ast> for PgOperatorWrapperFlow<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let binding = immutable_pat_ident(&local.pat);
        let initializer = local.init.as_ref().map(|init| init.expr.as_ref());
        if let (Some(binding), Some(initializer)) = (binding, initializer)
            && pg_source_expr_is_canonical(
                initializer,
                PgBuilderOrigin::RuntimeInputs(self.runtime_inputs),
                &self.source_aliases,
            )
        {
            self.source_aliases.insert(binding.to_string());
        }
        if let (Some(binding), Some(syn::Expr::Struct(runtime))) =
            (binding, initializer.map(transparent_expr))
            && is_exact_syn_path(&runtime.path, &[self.runtime_type])
        {
            self.runtime_structs += 1;
            if self.runtime_struct_is_canonical(runtime) {
                self.canonical_runtime_structs += 1;
                self.runtime_bindings.insert(binding.to_string());
            }
        }
        if let (Some(binding), Some(initializer)) = (binding, initializer)
            && self.expr_call_is_canonical(initializer)
        {
            self.result_bindings.insert(binding.to_string());
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if is_exact_path(&call.func, &[self.with_runtime]) {
            self.with_runtime_calls += 1;
            self.canonical_with_runtime_calls += usize::from(self.call_is_canonical(call));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "config" && call.args.is_empty() {
            self.config_calls += 1;
            self.canonical_config_calls +=
                usize::from(is_exact_ident_path(&call.receiver, self.runtime_inputs));
        } else if call.method == "operator_capability" && call.args.is_empty() {
            self.operator_capability_calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn pg_operator_wrapper_is_exact(
    file: &syn::File,
    function: &syn::ItemFn,
    runtime_inputs: &syn::Ident,
    runtime_type: &str,
    runtime_trait: &str,
    builder: &str,
    with_runtime: &str,
) -> bool {
    if !pg_operator_runtime_struct_is_exact(file, runtime_type) {
        return false;
    }
    let Some((args, _)) = pg_operator_signature_bindings(function, &function.sig.ident.to_string())
    else {
        return false;
    };
    let mut wrapper_flow =
        PgOperatorWrapperFlow::new(&args, runtime_inputs, runtime_type, with_runtime);
    wrapper_flow.visit_block(&function.block);
    let tail_is_exact = function
        .block
        .stmts
        .last()
        .and_then(|statement| match statement {
            syn::Stmt::Expr(expr, None) => Some(expr),
            _ => None,
        })
        .is_some_and(|tail| wrapper_flow.return_expr_is_canonical(tail));
    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && type_last_ident(&item.self_ty)
                        .is_some_and(|ident| ident == runtime_type)
                    && item
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path.segments.last())
                        .is_some_and(|segment| segment.ident == runtime_trait) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(implementation) = (implementations.len() == 1).then_some(implementations[0]) else {
        return false;
    };
    let connects = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "connect_maintenance" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(connect) = (connects.len() == 1).then_some(connects[0]) else {
        return false;
    };
    let mut flow = PgBuilderFlow {
        expected_builder: builder,
        origin: PgBuilderOrigin::SelfConfig,
        source_aliases: BTreeSet::new(),
        config_aliases: BTreeMap::new(),
        builder_like_calls: 0,
        exact_calls: 0,
        config_calls: 0,
        canonical_config_calls: 0,
        sink_calls: 0,
        canonical_sink_calls: 0,
    };
    flow.visit_block(&connect.block);
    wrapper_flow.is_exact() && tail_is_exact && flow.is_exact()
}

fn direct_pg_operator_is_exact(
    function: &syn::ItemFn,
    runtime_inputs: &syn::Ident,
    expected_config_calls: usize,
) -> bool {
    let mut flow = PgBuilderFlow {
        expected_builder: "build_pg_migrator_config",
        origin: PgBuilderOrigin::RuntimeInputs(runtime_inputs),
        source_aliases: BTreeSet::new(),
        config_aliases: BTreeMap::new(),
        builder_like_calls: 0,
        exact_calls: 0,
        config_calls: 0,
        canonical_config_calls: 0,
        sink_calls: 0,
        canonical_sink_calls: 0,
    };
    flow.visit_block(&function.block);
    flow.is_exact_with_runtime_config_calls(expected_config_calls)
}

#[derive(Debug, Default)]
struct SettingsVaultFlow<'a> {
    runtime_inputs: Option<&'a syn::Ident>,
    config: Option<&'a syn::Ident>,
    mapped_binding: Option<syn::Ident>,
    mapped_binding_definitions: usize,
    mapping_calls: usize,
    canonical_mapping_calls: usize,
    consume_calls: usize,
    canonical_consume_calls: usize,
    protection_calls: usize,
    canonical_protection_calls: usize,
}

impl<'ast> Visit<'ast> for SettingsVaultFlow<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let binding = immutable_pat_ident(&local.pat);
        if let (Some(binding), Some(mapped)) = (binding, self.mapped_binding.as_ref())
            && binding == mapped
        {
            self.mapped_binding_definitions += 1;
        }
        if let (Some(binding), Some(initializer), Some(config)) =
            (binding, local.init.as_ref(), self.config)
            && let syn::Expr::Match(mapped) = transparent_expr(&initializer.expr)
            && let syn::Expr::Call(call) = transparent_expr(&mapped.expr)
            && path_ends_with(&call.func, &["VaultRuntimeConfig", "from_snapshot"])
            && call.args.len() == 1
            && call
                .args
                .first()
                .is_some_and(|argument| is_exact_ident_path(argument, config))
            && self.mapped_binding.is_none()
        {
            self.mapped_binding = Some(binding.clone());
            self.mapped_binding_definitions = 1;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["VaultRuntimeConfig", "from_snapshot"]) {
            self.mapping_calls += 1;
            self.canonical_mapping_calls += usize::from(self.config.is_some_and(|config| {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .is_some_and(|arg| is_exact_ident_path(arg, config))
            }));
        }
        if expr_path_last(&call.func)
            .is_some_and(|ident| ident == "settings_config_value_maintenance_protection")
        {
            self.protection_calls += 1;
            self.canonical_protection_calls +=
                usize::from(self.runtime_inputs.is_some_and(|runtime_inputs| {
                    call.args.len() == 4
                        && call.args.iter().nth(3).is_some_and(|arg| {
                            matches!(transparent_expr(arg), syn::Expr::MethodCall(config_call)
                                if config_call.method == "config"
                                    && config_call.args.is_empty()
                                    && is_exact_ident_path(&config_call.receiver, runtime_inputs))
                        })
                }));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "into_settings_key_provider" {
            self.consume_calls += 1;
            self.canonical_consume_calls += usize::from(
                call.args.is_empty()
                    && matches!(transparent_expr(&call.receiver), syn::Expr::Path(path)
                    if path.path.get_ident().is_some_and(|ident| {
                        self.mapped_binding.as_ref().is_some_and(|mapped| ident == mapped)
                    })),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn settings_config_value_maintenance_is_exact(
    file: &syn::File,
    run: &syn::ItemFn,
    runtime_inputs: &syn::Ident,
) -> bool {
    if !direct_pg_operator_is_exact(run, runtime_inputs, 2) {
        return false;
    }
    settings_vault_snapshot_flow_is_exact(file, run, runtime_inputs)
}

fn settings_vault_snapshot_flow_is_exact(
    file: &syn::File,
    run: &syn::ItemFn,
    runtime_inputs: &syn::Ident,
) -> bool {
    let protections = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "settings_config_value_maintenance_protection"
                    && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(protection) = (protections.len() == 1).then_some(protections[0]) else {
        return false;
    };
    let inputs = protection.sig.inputs.iter().collect::<Vec<_>>();
    let Some(config) = inputs.get(3).and_then(|input| match input {
        syn::FnArg::Typed(input)
            if type_last_ident(&input.ty).is_some_and(|ident| ident == "SnapshotConfig") =>
        {
            immutable_pat_ident(&input.pat)
        }
        _ => None,
    }) else {
        return false;
    };
    let mut protection_flow = SettingsVaultFlow {
        config: Some(config),
        ..SettingsVaultFlow::default()
    };
    protection_flow.visit_block(&protection.block);
    let mut run_flow = SettingsVaultFlow {
        runtime_inputs: Some(runtime_inputs),
        ..SettingsVaultFlow::default()
    };
    run_flow.visit_block(&run.block);
    protection_flow.mapping_calls == 1
        && protection_flow.canonical_mapping_calls == 1
        && protection_flow.mapped_binding.is_some()
        && protection_flow.mapped_binding_definitions == 1
        && protection_flow.consume_calls == 1
        && protection_flow.canonical_consume_calls == 1
        && run_flow.protection_calls == 1
        && run_flow.canonical_protection_calls == 1
}

fn settings_vault_snapshot_definition_is_exact(file: &syn::File) -> bool {
    let runs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "run_settings_config_value_maintenance"
                    && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(run) = (runs.len() == 1).then_some(runs[0]) else {
        return false;
    };
    let Some((_, runtime_inputs)) =
        pg_operator_signature_bindings(run, "run_settings_config_value_maintenance")
    else {
        return false;
    };
    settings_vault_snapshot_flow_is_exact(file, run, &runtime_inputs)
}

fn pg_operator_definitions_are_exact(file: &syn::File) -> bool {
    let specs = [
        ("run_postgres_reader_migration_command", None),
        (
            "run_projection_control_command",
            Some((
                "ProductionProjectionControlRuntime",
                "ProjectionControlRuntime",
                "build_pg_migrator_config",
                "run_projection_control_command_with_runtime",
            )),
        ),
        (
            "run_audit_ledger_verify_command",
            Some((
                "ProductionAuditLedgerVerifyRuntime",
                "AuditLedgerVerifyRuntime",
                "build_pg_audit_maintenance_config",
                "run_audit_ledger_verify_command_with_runtime",
            )),
        ),
        (
            "run_dlq_control_command",
            Some((
                "ProductionDlqControlRuntime",
                "DlqControlRuntime",
                "build_pg_migrator_config",
                "run_dlq_control_command_with_runtime",
            )),
        ),
        ("run_reconcile_target_command", None),
        ("run_settings_config_value_maintenance", None),
    ];
    specs.iter().all(|(name, wrapper)| {
        let functions = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function)
                    if function.sig.ident == *name && attrs_may_be_production(&function.attrs) =>
                {
                    Some(function)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let Some(function) = (functions.len() == 1).then_some(functions[0]) else {
            return false;
        };
        let Some((_, runtime_inputs)) = pg_operator_signature_bindings(function, name) else {
            return false;
        };
        match wrapper {
            Some((runtime_type, runtime_trait, builder, with_runtime)) => {
                pg_operator_wrapper_is_exact(
                    file,
                    function,
                    &runtime_inputs,
                    runtime_type,
                    runtime_trait,
                    builder,
                    with_runtime,
                )
            }
            None if *name == "run_settings_config_value_maintenance" => {
                settings_config_value_maintenance_is_exact(file, function, &runtime_inputs)
            }
            None => direct_pg_operator_is_exact(function, &runtime_inputs, 1),
        }
    })
}

fn runtime_config_global_capture_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let production_sources = production_module_sources(&paths)?;
    let mut inventory = ProductionRuntimeConfigInventory::default();
    for path in paths {
        if !production_sources.contains(&normalize_path(&path)) {
            continue;
        }
        let source =
            fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
        // Baseline fixtures intentionally keep unrelated production files as isolated,
        // non-compiling anchor fragments. Protected aliases must still name or import at least
        // one governed symbol, so this token prefilter skips only files outside this invariant.
        let masked = mask_comments_and_strings(&source);
        if !PROTECTED_CONFIG_SYMBOLS
            .iter()
            .copied()
            .any(|symbol| masked.contains(symbol))
        {
            continue;
        }
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_SRC_PATH,
                    format!(
                        "runtime configuration global capture gate 无法解析 {}: {error}",
                        path.display()
                    ),
                )]);
            }
        };
        let mut observed = ProductionRuntimeConfigInventory::default();
        observed.visit_file(&file);
        inventory.add(observed);
    }
    if inventory.is_exact() {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        RUNTIME_SRC_PATH,
        format!(
            "runtime production module graph cardinality mismatch; protected aliases, UFCS, local function aliases, and macro indirection fail closed: {}",
            inventory.diagnostic()
        ),
    )])
}

const AMBIENT_ENV_READERS: &[&str] = &["var", "var_os", "vars", "vars_os"];

#[derive(Clone, Default)]
struct AmbientEnvAliases {
    modules: BTreeSet<String>,
    readers: BTreeSet<String>,
    glob: bool,
}

impl AmbientEnvAliases {
    fn add_use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.add_use_tree(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let mut full = prefix.clone();
                full.push(name.ident.to_string());
                self.record_import(&full, name.ident.to_string());
            }
            syn::UseTree::Rename(rename) => {
                let mut full = prefix.clone();
                full.push(rename.ident.to_string());
                self.record_import(&full, rename.rename.to_string());
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.add_use_tree(item, prefix);
                }
            }
            syn::UseTree::Glob(_) => {
                if prefix.as_slice() == ["std", "env"] {
                    self.glob = true;
                }
            }
        }
    }

    fn record_import(&mut self, full: &[String], local: String) {
        if full == ["std", "env"] || full == ["std", "env", "self"] {
            self.modules.insert(local);
        } else if full.len() == 3
            && full[0] == "std"
            && full[1] == "env"
            && AMBIENT_ENV_READERS.contains(&full[2].as_str())
        {
            self.readers.insert(local);
        }
    }

    fn path_is_reader(&self, path: &syn::Path) -> bool {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        (segments.len() == 3
            && segments[0] == "std"
            && segments[1] == "env"
            && AMBIENT_ENV_READERS.contains(&segments[2].as_str()))
            || (segments.len() == 2
                && self.modules.contains(&segments[0])
                && AMBIENT_ENV_READERS.contains(&segments[1].as_str()))
            || (segments.len() == 1
                && (self.readers.contains(&segments[0])
                    || (self.glob && AMBIENT_ENV_READERS.contains(&segments[0].as_str()))))
    }

    fn tokens_mention_reader(&self, tokens: &proc_macro2::TokenStream) -> bool {
        let rendered = tokens.to_string();
        AMBIENT_ENV_READERS.iter().any(|reader| {
            rendered.contains(&format!("std :: env :: {reader}"))
                || self
                    .modules
                    .iter()
                    .any(|module| rendered.contains(&format!("{module} :: {reader}")))
                || self
                    .readers
                    .iter()
                    .any(|alias| rendered.split_whitespace().any(|token| token == alias))
        })
    }
}

struct AmbientContext {
    aliases: AmbientEnvAliases,
    macros: BTreeSet<String>,
    callable_aliases: BTreeMap<String, String>,
    import_origins: BTreeMap<String, String>,
    snapshot_types: BTreeSet<String>,
}

impl Default for AmbientContext {
    fn default() -> Self {
        Self {
            aliases: AmbientEnvAliases::default(),
            macros: BTreeSet::new(),
            callable_aliases: BTreeMap::new(),
            import_origins: BTreeMap::new(),
            snapshot_types: BTreeSet::from(["SnapshotConfig".to_owned()]),
        }
    }
}

impl AmbientContext {
    fn add_callable_use_tree(&mut self, tree: &syn::UseTree) {
        self.add_callable_use_tree_with_prefix(tree, &mut Vec::new());
    }

    fn add_callable_use_tree_with_prefix(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.add_callable_use_tree_with_prefix(&path.tree, prefix);
                prefix.pop();
            }
            syn::UseTree::Rename(rename) => {
                let original = rename.ident.to_string();
                let local = rename.rename.to_string();
                let mut origin = prefix.clone();
                origin.push(original.clone());
                self.import_origins.insert(local.clone(), origin.join("::"));
                self.callable_aliases
                    .insert(local.clone(), original.clone());
                if self.snapshot_types.contains(&original) {
                    self.snapshot_types.insert(local);
                }
            }
            syn::UseTree::Name(name) => {
                let mut origin = prefix.clone();
                origin.push(name.ident.to_string());
                self.import_origins
                    .insert(name.ident.to_string(), origin.join("::"));
                if name.ident == "SnapshotConfig" {
                    self.snapshot_types.insert(name.ident.to_string());
                }
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.add_callable_use_tree_with_prefix(item, prefix);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn tokens_mention_ambient_macro(&self, tokens: &proc_macro2::TokenStream) -> bool {
        fn collect(tokens: proc_macro2::TokenStream, names: &mut BTreeSet<String>) {
            for token in tokens {
                match token {
                    proc_macro2::TokenTree::Ident(ident) => {
                        names.insert(ident.to_string());
                    }
                    proc_macro2::TokenTree::Group(group) => collect(group.stream(), names),
                    _ => {}
                }
            }
        }
        let mut names = BTreeSet::new();
        collect(tokens.clone(), &mut names);
        names.into_iter().any(|name| {
            self.macros
                .contains(&resolve_callable_alias(&self.callable_aliases, &name))
        })
    }

    fn close_macro_aliases(&mut self) {
        let aliases = self
            .callable_aliases
            .keys()
            .filter(|alias| {
                self.macros
                    .contains(&resolve_callable_alias(&self.callable_aliases, alias))
            })
            .cloned()
            .collect::<Vec<_>>();
        self.macros.extend(aliases);
    }
}

fn resolve_callable_alias(aliases: &BTreeMap<String, String>, name: &str) -> String {
    let mut current = name.to_owned();
    let mut visited = BTreeSet::new();
    while visited.insert(current.clone()) {
        let Some(next) = aliases.get(&current) else {
            break;
        };
        current = next.clone();
    }
    current
}

impl<'ast> Visit<'ast> for AmbientContext {
    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if attrs_may_be_production(&item.attrs) {
            self.aliases.add_use_tree(&item.tree, &mut Vec::new());
            self.add_callable_use_tree(&item.tree);
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if attrs_may_be_production(&item.attrs)
            && type_mentions_named_types(&item.ty, &self.snapshot_types)
        {
            self.snapshot_types.insert(item.ident.to_string());
        }
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if attrs_may_be_production(&item.attrs)
            && (self.aliases.tokens_mention_reader(&item.mac.tokens)
                || self.tokens_mention_ambient_macro(&item.mac.tokens))
            && let Some(ident) = &item.ident
        {
            self.macros.insert(ident.to_string());
        }
    }
}

#[derive(Default)]
struct AmbientFunctionFact {
    snapshot_consumer: bool,
    reads_ambient: bool,
    callees: BTreeSet<String>,
}

impl AmbientFunctionFact {
    fn merge(&mut self, other: Self) {
        self.snapshot_consumer |= other.snapshot_consumer;
        self.reads_ambient |= other.reads_ambient;
        self.callees.extend(other.callees);
    }
}

struct AmbientFunctionScanner {
    aliases: AmbientEnvAliases,
    ambient_macros: BTreeSet<String>,
    function_aliases: BTreeMap<String, String>,
    fact: AmbientFunctionFact,
}

impl AmbientFunctionScanner {
    fn new(context: &AmbientContext, snapshot_consumer: bool) -> Self {
        Self {
            aliases: context.aliases.clone(),
            ambient_macros: context.macros.clone(),
            function_aliases: context.callable_aliases.clone(),
            fact: AmbientFunctionFact {
                snapshot_consumer,
                ..AmbientFunctionFact::default()
            },
        }
    }
}

impl<'ast> Visit<'ast> for AmbientFunctionScanner {
    fn visit_item_fn(&mut self, _item: &'ast syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _item: &'ast syn::ImplItemFn) {}

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if attrs_may_be_production(&item.attrs) {
            self.aliases.add_use_tree(&item.tree, &mut Vec::new());
            let mut context = AmbientContext::default();
            context.add_callable_use_tree(&item.tree);
            self.function_aliases.extend(context.callable_aliases);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (Some(binding), Some(syn::Expr::Path(path))) = (
            pat_ident(&local.pat),
            local.init.as_ref().map(|init| transparent_expr(&init.expr)),
        ) {
            if self.aliases.path_is_reader(&path.path) {
                self.aliases.readers.insert(binding.to_string());
            } else if let Some(target) = path.path.segments.last() {
                self.function_aliases
                    .insert(binding.to_string(), target.ident.to_string());
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = transparent_expr(&call.func) {
            if self.aliases.path_is_reader(&path.path) {
                self.fact.reads_ambient = true;
            } else if (path.qself.is_some()
                || path.path.segments.len() == 1
                || path.path.segments.first().is_some_and(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "crate" | "self" | "super"
                    )
                }))
                && let Some(callee) = path.path.segments.last()
            {
                let callee =
                    resolve_callable_alias(&self.function_aliases, &callee.ident.to_string());
                self.fact.callees.insert(callee);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.fact.callees.insert(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let macro_name = path_last_ident(&mac.path).map(ToString::to_string);
        let resolved_macro = macro_name
            .as_ref()
            .map(|name| resolve_callable_alias(&self.function_aliases, name));
        if resolved_macro
            .as_ref()
            .is_some_and(|ident| self.ambient_macros.contains(ident))
            || self.aliases.tokens_mention_reader(&mac.tokens)
        {
            self.fact.reads_ambient = true;
        }
    }
}

#[derive(Default)]
struct AmbientFunctionGraph {
    context: AmbientContext,
    facts: BTreeMap<String, AmbientFunctionFact>,
}

impl AmbientFunctionGraph {
    fn record(
        &mut self,
        signature: &syn::Signature,
        block: &syn::Block,
        self_is_snapshot_config: bool,
    ) {
        let mut scanner = AmbientFunctionScanner::new(
            &self.context,
            self_is_snapshot_config
                || signature_accepts_snapshot_config(signature, &self.context.snapshot_types),
        );
        scanner.visit_block(block);
        self.facts
            .entry(signature.ident.to_string())
            .or_default()
            .merge(scanner.fact);
    }

    fn reachable_ambient_chain(&self) -> Option<Vec<String>> {
        let mut queue = self
            .facts
            .iter()
            .filter(|(_, fact)| fact.snapshot_consumer)
            .map(|(name, _)| (name.clone(), vec![name.clone()]))
            .collect::<VecDeque<_>>();
        let mut visited = BTreeSet::new();
        while let Some((name, chain)) = queue.pop_front() {
            if !visited.insert(name.clone()) {
                continue;
            }
            let Some(fact) = self.facts.get(&name) else {
                continue;
            };
            if fact.reads_ambient {
                return Some(chain);
            }
            queue.extend(
                fact.callees
                    .iter()
                    .filter(|callee| self.facts.contains_key(*callee))
                    .map(|callee| {
                        let mut next = chain.clone();
                        next.push(callee.clone());
                        (callee.clone(), next)
                    }),
            );
        }
        None
    }
}

impl<'ast> Visit<'ast> for AmbientFunctionGraph {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            self.record(&item.sig, &item.block, false);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let self_is_snapshot_config =
            type_mentions_named_types(&item.self_ty, &self.context.snapshot_types);
        for implementation in &item.items {
            if let syn::ImplItem::Fn(method) = implementation
                && attrs_may_be_production(&method.attrs)
            {
                self.record(&method.sig, &method.block, self_is_snapshot_config);
            }
        }
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        for trait_item in &item.items {
            if let syn::TraitItem::Fn(method) = trait_item
                && attrs_may_be_production(&method.attrs)
                && let Some(block) = &method.default
            {
                self.record(&method.sig, block, false);
            }
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs)
            && let Some((_, nested)) = &item.content
        {
            for item in nested {
                self.visit_item(item);
            }
        }
    }
}

fn signature_accepts_snapshot_config(
    signature: &syn::Signature,
    snapshot_types: &BTreeSet<String>,
) -> bool {
    signature.inputs.iter().any(|input| match input {
        syn::FnArg::Receiver(_) => false,
        syn::FnArg::Typed(input) => type_mentions_named_types(&input.ty, snapshot_types),
    })
}

fn type_mentions_named_types(ty: &syn::Type, expected: &BTreeSet<String>) -> bool {
    match ty {
        syn::Type::Path(path) => {
            path.path
                .segments
                .iter()
                .any(|segment| expected.contains(&segment.ident.to_string()))
                || path
                    .qself
                    .as_ref()
                    .is_some_and(|qself| type_mentions_named_types(&qself.ty, expected))
        }
        syn::Type::Reference(reference) => type_mentions_named_types(&reference.elem, expected),
        syn::Type::Paren(paren) => type_mentions_named_types(&paren.elem, expected),
        syn::Type::Group(group) => type_mentions_named_types(&group.elem, expected),
        syn::Type::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|element| type_mentions_named_types(element, expected)),
        _ => false,
    }
}

fn ambient_context_measure<'a>(
    contexts: impl Iterator<Item = &'a AmbientContext>,
) -> (usize, usize, usize, usize) {
    contexts.fold((0, 0, 0, 0), |observed, context| {
        (
            observed.0
                + context.aliases.modules.len()
                + context.aliases.readers.len()
                + usize::from(context.aliases.glob),
            observed.1 + context.macros.len(),
            observed.2 + context.snapshot_types.len(),
            observed.3 + context.callable_aliases.len(),
        )
    })
}

fn runtime_snapshot_consumer_ambient_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let production_sources = production_module_sources(&paths)?;
    let mut findings = Vec::new();
    let require_complete = root.join("Cargo.toml").exists();
    let mut parsed = Vec::new();
    for path in paths {
        if !production_sources.contains(&normalize_path(&path)) {
            continue;
        }
        let source =
            fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error)
                if require_complete
                    || ["SnapshotConfig", "std::env", "std :: env"]
                        .iter()
                        .any(|token| mask_comments_and_strings(&source).contains(token)) =>
            {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    relative,
                    format!("SnapshotConfig consumer ambient-env gate 无法解析生产 Rust: {error}"),
                ));
                continue;
            }
            Err(_) => continue,
        };
        let module = path
            .strip_prefix(root.join(RUNTIME_SRC_PATH))
            .unwrap_or(&path)
            .with_extension("")
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .filter(|component| !matches!(*component, "lib" | "mod"))
            .collect::<Vec<_>>()
            .join("::");
        parsed.push((module, file, AmbientContext::default()));
    }

    loop {
        let before = ambient_context_measure(parsed.iter().map(|(_, _, context)| context));
        let ambient_macros = parsed
            .iter()
            .flat_map(|(_, _, context)| context.macros.iter().cloned())
            .collect::<BTreeSet<_>>();
        let snapshot_types = parsed
            .iter()
            .flat_map(|(_, _, context)| context.snapshot_types.iter().cloned())
            .collect::<BTreeSet<_>>();
        let ambient_module_exports = parsed
            .iter()
            .flat_map(|(module, _, context)| {
                context
                    .aliases
                    .modules
                    .iter()
                    .map(move |alias| format!("{module}::{alias}"))
            })
            .collect::<BTreeSet<_>>();
        for (_, file, context) in &mut parsed {
            context.macros.extend(ambient_macros.iter().cloned());
            context
                .snapshot_types
                .extend(snapshot_types.iter().cloned());
            let imported_ambient_modules = context
                .import_origins
                .iter()
                .filter_map(|(local, origin)| {
                    let normalized = origin.strip_prefix("crate::").unwrap_or(origin);
                    ambient_module_exports
                        .contains(normalized)
                        .then_some(local.clone())
                })
                .collect::<Vec<_>>();
            context.aliases.modules.extend(imported_ambient_modules);
            context.close_macro_aliases();
            context.visit_file(file);
            context.close_macro_aliases();
        }
        let after = ambient_context_measure(parsed.iter().map(|(_, _, context)| context));
        if before == after {
            break;
        }
    }
    let mut graph = AmbientFunctionGraph::default();
    for (_, file, context) in parsed {
        for reader in &context.aliases.readers {
            graph.facts.entry(reader.clone()).or_default().reads_ambient = true;
        }
        if context.aliases.glob || !context.aliases.modules.is_empty() {
            for reader in AMBIENT_ENV_READERS {
                graph
                    .facts
                    .entry((*reader).to_owned())
                    .or_default()
                    .reads_ambient = true;
            }
        }
        for (alias, target) in &context.callable_aliases {
            graph
                .facts
                .entry(alias.clone())
                .or_default()
                .callees
                .insert(target.clone());
        }
        graph.context = context;
        graph.visit_file(&file);
    }
    if let Some(chain) = graph.reachable_ambient_chain() {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_SRC_PATH,
            format!(
                "every production SnapshotConfig consumer and its crate-wide conservatively reachable call chain must reject ambient std::env var/var_os/vars/vars_os reads, including import/function aliases, wrappers, macros, and trait UFCS; reachable chain: {}",
                chain.join(" -> ")
            ),
        ));
    }
    Ok(findings)
}

fn runtime_inputs_mut_parameter(item: &syn::ItemFn) -> Option<&syn::Ident> {
    if item.sig.inputs.len() != 1 {
        return None;
    }
    let syn::FnArg::Typed(input) = item.sig.inputs.first()? else {
        return None;
    };
    let syn::Type::Reference(reference) = input.ty.as_ref() else {
        return None;
    };
    let syn::Type::Path(ty) = reference.elem.as_ref() else {
        return None;
    };
    if reference.mutability.is_none()
        || ty.qself.is_some()
        || ty
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "ServingRuntimeInputs")
    {
        return None;
    }
    pat_ident(&input.pat)
}

fn mutable_reference_to_self_field(expr: &syn::Expr, field_name: &str) -> bool {
    matches!(
        transparent_expr(expr),
        syn::Expr::Reference(reference)
            if reference.mutability.is_some()
                && matches!(transparent_expr(&reference.expr), syn::Expr::Field(field)
                    if is_exact_path(&field.base, &["self"])
                        && matches!(&field.member, syn::Member::Named(member) if member == field_name))
    )
}

fn owner_receiver_is_mut_value(receiver: &syn::Receiver) -> bool {
    receiver.reference.is_none() && receiver.mutability.is_some() && receiver.colon_token.is_none()
}

fn owner_method<'a>(item: &'a syn::ItemImpl, name: &str) -> Option<&'a syn::ImplItemFn> {
    let methods = item
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == name && attrs_may_be_production(&method.attrs) =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    (methods.len() == 1).then_some(methods[0])
}

fn runtime_lifecycle_owner_struct_is_canonical(file: &syn::File) -> bool {
    let owners = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item)
                if item.ident == "RuntimeLifecycleOwner"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(owner) = (owners.len() == 1).then_some(owners[0]) else {
        return false;
    };
    let syn::Fields::Named(fields) = &owner.fields else {
        return false;
    };
    fields.named.len() == 1
        && fields.named.first().is_some_and(|field| {
            field.ident.as_ref().is_some_and(|ident| ident == "inputs")
                && matches!(field.vis, syn::Visibility::Inherited)
                && type_last_ident(&field.ty).is_some_and(|ident| ident == "ServingRuntimeInputs")
        })
}

fn runtime_lifecycle_new_is_canonical(method: &syn::ImplItemFn) -> bool {
    if method.sig.asyncness.is_some() || method.sig.inputs.len() != 1 {
        return false;
    }
    let Some(syn::FnArg::Typed(input)) = method.sig.inputs.first() else {
        return false;
    };
    let Some(inputs) = pat_ident(&input.pat) else {
        return false;
    };
    if type_last_ident(&input.ty).is_none_or(|ident| ident != "ServingRuntimeInputs") {
        return false;
    }
    let [syn::Stmt::Expr(expr, None)] = method.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Struct(owner) = transparent_expr(expr) else {
        return false;
    };
    is_exact_syn_path(&owner.path, &["Self"])
        && owner.rest.is_none()
        && owner.fields.len() == 1
        && owner.fields.first().is_some_and(|field| {
            matches!(&field.member, syn::Member::Named(member) if member == "inputs")
                && is_exact_ident_path(&field.expr, inputs)
        })
}

fn runtime_lifecycle_run_is_canonical(method: &syn::ImplItemFn) -> bool {
    if method.sig.inputs.len() != 1 {
        return false;
    }
    let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
        return false;
    };
    if method.sig.asyncness.is_none()
        || !owner_receiver_is_mut_value(receiver)
        || method.block.stmts.len() != 2
    {
        return false;
    }
    let syn::Stmt::Local(startup_local) = &method.block.stmts[0] else {
        return false;
    };
    let Some(startup_result) = pat_ident(&startup_local.pat) else {
        return false;
    };
    let Some(startup_call) = startup_local
        .init
        .as_ref()
        .and_then(|init| direct_awaited_call(&init.expr))
    else {
        return false;
    };
    let startup_is_canonical = is_exact_path(&startup_call.func, &["run_startup"])
        && startup_call.args.len() == 1
        && startup_call
            .args
            .first()
            .is_some_and(|arg| mutable_reference_to_self_field(arg, "inputs"));
    let syn::Stmt::Expr(tail, None) = &method.block.stmts[1] else {
        return false;
    };
    let syn::Expr::Await(awaited) = transparent_expr(tail) else {
        return false;
    };
    let syn::Expr::MethodCall(finish) = transparent_expr(&awaited.base) else {
        return false;
    };
    startup_is_canonical
        && finish.method == "finish"
        && finish.args.len() == 1
        && is_exact_path(&finish.receiver, &["self"])
        && finish
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, startup_result))
}

fn err_of_binding(expr: &syn::Expr, binding: &str) -> bool {
    let expr = match transparent_expr(expr) {
        syn::Expr::Block(block) => match block.block.stmts.last() {
            Some(syn::Stmt::Expr(expr, None)) => transparent_expr(expr),
            _ => return false,
        },
        expr => expr,
    };
    let Some(call) = direct_call_behind_runtime_context(expr) else {
        return false;
    };
    is_exact_path(&call.func, &["Err"])
        && call.args.len() == 1
        && call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &[binding]))
}

fn awaited_method_behind_result_context(expr: &syn::Expr) -> Option<&syn::ExprMethodCall> {
    match transparent_expr(expr) {
        syn::Expr::Try(try_) => awaited_method_behind_result_context(&try_.expr),
        syn::Expr::MethodCall(call)
            if matches!(call.method.to_string().as_str(), "context" | "with_context") =>
        {
            awaited_method_behind_result_context(&call.receiver)
        }
        syn::Expr::Await(awaited) => match transparent_expr(&awaited.base) {
            syn::Expr::MethodCall(call) => Some(call),
            _ => None,
        },
        _ => None,
    }
}

fn ok_unit_expr(expr: &syn::Expr) -> bool {
    let Some(call) = direct_call_behind_runtime_context(expr) else {
        return false;
    };
    is_exact_path(&call.func, &["Ok"])
        && call.args.len() == 1
        && matches!(call.args.first().map(transparent_expr), Some(syn::Expr::Tuple(unit)) if unit.elems.is_empty())
}

fn shutdown_prepared_runtime_is_canonical(file: &syn::File) -> bool {
    let helpers = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "shutdown_prepared_runtime"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(helper) = helpers.first().filter(|_| helpers.len() == 1).copied() else {
        return false;
    };
    let Some(syn::FnArg::Typed(input)) = helper.sig.inputs.first() else {
        return false;
    };
    let syn::Type::Reference(reference) = input.ty.as_ref() else {
        return false;
    };
    let Some(runtime_inputs) = pat_ident(&input.pat) else {
        return false;
    };
    if helper.sig.asyncness.is_none()
        || !matches!(helper.vis, syn::Visibility::Inherited)
        || helper.sig.inputs.len() != 1
        || reference.mutability.is_none()
        || compact_type_tokens(reference.elem.as_ref()) != "PreparedRuntimeInputs"
        || helper.block.stmts.len() != 2
    {
        return false;
    }
    let syn::Stmt::Expr(branch, None) = &helper.block.stmts[0] else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(branch) else {
        return false;
    };
    let syn::Expr::Let(condition) = transparent_expr(&branch.cond) else {
        return false;
    };
    let syn::Pat::TupleStruct(some) = condition.pat.as_ref() else {
        return false;
    };
    let Some(syn::Pat::Ident(exporter)) = some.elems.first() else {
        return false;
    };
    let syn::Expr::MethodCall(take) = transparent_expr(&condition.expr) else {
        return false;
    };
    let take_is_canonical = is_exact_syn_path(&some.path, &["Some"])
        && some.elems.len() == 1
        && take.method == "take_trace_export"
        && take.args.is_empty()
        && is_exact_ident_path(&take.receiver, runtime_inputs);
    let shutdown_is_canonical = match branch.then_branch.stmts.as_slice() {
        [syn::Stmt::Expr(expr, Some(_))] | [syn::Stmt::Expr(expr, None)] => {
            matches!(transparent_expr(expr), syn::Expr::Try(_))
                && awaited_method_behind_result_context(expr).is_some_and(|shutdown| {
                    shutdown.method == "shutdown"
                        && shutdown.args.is_empty()
                        && is_exact_ident_path(&shutdown.receiver, &exporter.ident)
                })
        }
        _ => false,
    };
    let tail_is_canonical = matches!(
        &helper.block.stmts[1],
        syn::Stmt::Expr(expr, None) if ok_unit_expr(expr)
    );
    take_is_canonical && shutdown_is_canonical && tail_is_canonical && branch.else_branch.is_none()
}

fn reports_cleanup_error_then_returns_primary(expr: &syn::Expr) -> bool {
    let syn::Expr::Block(block) = transparent_expr(expr) else {
        return false;
    };
    let [syn::Stmt::Macro(report), syn::Stmt::Expr(tail, None)] = block.block.stmts.as_slice()
    else {
        return false;
    };
    is_exact_syn_path(&report.mac.path, &["tracing", "error"])
        && report
            .mac
            .tokens
            .to_string()
            .contains("cleanup_error = % cleanup_error")
        && err_of_binding(tail, "startup_error")
}

fn runtime_lifecycle_finish_is_canonical(method: &syn::ImplItemFn) -> bool {
    if method.sig.asyncness.is_none()
        || method.sig.inputs.len() != 2
        || method.block.stmts.len() != 2
    {
        return false;
    }
    let Some(syn::FnArg::Receiver(receiver)) = method.sig.inputs.first() else {
        return false;
    };
    let Some(syn::FnArg::Typed(startup_input)) = method.sig.inputs.iter().nth(1) else {
        return false;
    };
    let Some(startup_result) = pat_ident(&startup_input.pat) else {
        return false;
    };
    if !owner_receiver_is_mut_value(receiver)
        || compact_tokens(&startup_input.ty) != "anyhow::Result<()>"
    {
        return false;
    }
    let syn::Stmt::Local(cleanup_local) = &method.block.stmts[0] else {
        return false;
    };
    let Some(cleanup_result) = pat_ident(&cleanup_local.pat) else {
        return false;
    };
    let Some(cleanup_call) = cleanup_local
        .init
        .as_ref()
        .and_then(|init| direct_awaited_call(&init.expr))
    else {
        return false;
    };
    if !is_exact_path(&cleanup_call.func, &["shutdown_prepared_runtime"])
        || cleanup_call.args.len() != 1
        || !cleanup_call.args.first().is_some_and(|arg| {
            matches!(transparent_expr(arg), syn::Expr::MethodCall(call)
                    if call.method == "prepared_mut"
                        && call.args.is_empty()
                        && matches!(transparent_expr(&call.receiver), syn::Expr::Field(field)
                            if is_exact_path(&field.base, &["self"])
                                && matches!(&field.member, syn::Member::Named(member)
                                    if member == "inputs")))
        })
    {
        return false;
    }
    let syn::Stmt::Expr(tail, None) = &method.block.stmts[1] else {
        return false;
    };
    let syn::Expr::Match(outcome) = transparent_expr(tail) else {
        return false;
    };
    let syn::Expr::Tuple(pair) = transparent_expr(&outcome.expr) else {
        return false;
    };
    if pair.elems.len() != 2
        || !pair
            .elems
            .first()
            .is_some_and(|expr| is_exact_ident_path(expr, startup_result))
        || !pair
            .elems
            .last()
            .is_some_and(|expr| is_exact_ident_path(expr, cleanup_result))
        || outcome.arms.len() != 3
    {
        return false;
    }
    let mut ok_cleanup = false;
    let mut primary_only = false;
    let mut primary_over_cleanup = false;
    for arm in &outcome.arms {
        if arm.guard.is_some() || !arm.attrs.is_empty() {
            return false;
        }
        match compact_tokens(&arm.pat).as_str() {
            "(Ok(()),cleanup_result)" => {
                ok_cleanup = is_exact_path(&arm.body, &["cleanup_result"]);
            }
            "(Err(startup_error),Ok(()))" => {
                primary_only = err_of_binding(&arm.body, "startup_error");
            }
            "(Err(startup_error),Err(cleanup_error))" => {
                primary_over_cleanup = reports_cleanup_error_then_returns_primary(&arm.body);
            }
            _ => return false,
        }
    }
    ok_cleanup && primary_only && primary_over_cleanup
}

fn runtime_lifecycle_outer_is_canonical(file: &syn::File, run: &syn::ItemFn) -> bool {
    if !matches!(run.vis, syn::Visibility::Public(_)) || run.block.stmts.len() != 1 {
        return false;
    }
    let Some(runtime_inputs) = runtime_inputs_parameter(run) else {
        return false;
    };
    let [syn::Stmt::Expr(tail, None)] = run.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Await(awaited) = transparent_expr(tail) else {
        return false;
    };
    let syn::Expr::MethodCall(owner_run) = transparent_expr(&awaited.base) else {
        return false;
    };
    let Some(owner_new) = direct_call_behind_runtime_context(&owner_run.receiver) else {
        return false;
    };
    if owner_run.method != "run"
        || !owner_run.args.is_empty()
        || !is_exact_path(&owner_new.func, &["RuntimeLifecycleOwner", "new"])
        || owner_new.args.len() != 1
        || !owner_new
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, runtime_inputs))
    {
        return false;
    }
    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.is_none()
                    && type_last_ident(&item.self_ty)
                        .is_some_and(|ident| ident == "RuntimeLifecycleOwner")
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(owner_impl) = (implementations.len() == 1).then_some(implementations[0]) else {
        return false;
    };
    runtime_lifecycle_owner_struct_is_canonical(file)
        && shutdown_prepared_runtime_is_canonical(file)
        && owner_method(owner_impl, "new").is_some_and(runtime_lifecycle_new_is_canonical)
        && owner_method(owner_impl, "run").is_some_and(runtime_lifecycle_run_is_canonical)
        && owner_method(owner_impl, "finish").is_some_and(runtime_lifecycle_finish_is_canonical)
        && exact_path_call_count_in_file(file, &["run_startup"]) == 1
}

fn production_named_function<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
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
    functions.first().filter(|_| functions.len() == 1).copied()
}

fn password_policy_preload_helper_is_canonical(file: &syn::File) -> bool {
    let Some(helper) = production_named_function(file, "prepare_local_before_external") else {
        return false;
    };
    if helper.sig.asyncness.is_some() || helper.sig.inputs.len() != 3 {
        return false;
    }
    let mut inputs = helper.sig.inputs.iter();
    let (
        Some(syn::FnArg::Typed(config)),
        Some(syn::FnArg::Typed(prepare_local)),
        Some(syn::FnArg::Typed(build_external)),
    ) = (inputs.next(), inputs.next(), inputs.next())
    else {
        return false;
    };
    let (Some(config), Some(prepare_local), Some(build_external)) = (
        pat_ident(&config.pat),
        pat_ident(&prepare_local.pat),
        pat_ident(&build_external.pat),
    ) else {
        return false;
    };
    let [
        syn::Stmt::Local(local),
        syn::Stmt::Local(external),
        syn::Stmt::Expr(result, None),
    ] = helper.block.stmts.as_slice()
    else {
        return false;
    };
    let (Some(local_binding), Some(local_init)) =
        (immutable_pat_ident(&local.pat), local.init.as_ref())
    else {
        return false;
    };
    let (Some(external_binding), Some(external_init)) =
        (immutable_pat_ident(&external.pat), external.init.as_ref())
    else {
        return false;
    };
    let Some(local_call) = call_behind_result_context(&local_init.expr) else {
        return false;
    };
    let Some(external_call) = call_behind_result_context(&external_init.expr) else {
        return false;
    };
    let syn::Expr::Call(ok) = transparent_expr(result) else {
        return false;
    };
    let Some(syn::Expr::Tuple(tuple)) = ok.args.first().map(transparent_expr) else {
        return false;
    };

    local
        .init
        .as_ref()
        .is_some_and(|init| init.diverge.is_none())
        && external
            .init
            .as_ref()
            .is_some_and(|init| init.diverge.is_none())
        && is_exact_ident_path(&local_call.func, prepare_local)
        && local_call.args.len() == 1
        && local_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, config))
        && is_exact_ident_path(&external_call.func, build_external)
        && external_call.args.is_empty()
        && is_exact_path(&ok.func, &["Ok"])
        && ok.args.len() == 1
        && tuple.elems.len() == 2
        && tuple
            .elems
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, local_binding))
        && tuple
            .elems
            .iter()
            .nth(1)
            .is_some_and(|arg| is_exact_ident_path(arg, external_binding))
}

fn profile_local_functions_are_canonical(file: &syn::File) -> bool {
    let Some(serving) = production_named_function(file, "prepare_serving_local") else {
        return false;
    };
    let Some(operator) = production_named_function(file, "prepare_operator_local") else {
        return false;
    };
    if serving.sig.inputs.len() != 1 {
        return false;
    }
    let Some(syn::FnArg::Typed(serving_config)) = serving.sig.inputs.first() else {
        return false;
    };
    let Some(serving_config) = pat_ident(&serving_config.pat) else {
        return false;
    };
    let [syn::Stmt::Expr(serving_result, None)] = serving.block.stmts.as_slice() else {
        return false;
    };
    let Some(serving_call) = direct_call_behind_runtime_context(serving_result) else {
        return false;
    };
    if operator.sig.inputs.len() != 1
        || !matches!(operator.sig.inputs.first(), Some(syn::FnArg::Typed(_)))
    {
        return false;
    }
    let [syn::Stmt::Expr(operator_result, None)] = operator.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Call(operator_ok) = transparent_expr(operator_result) else {
        return false;
    };
    let operator_unit = operator_ok.args.first().is_some_and(
        |arg| matches!(transparent_expr(arg), syn::Expr::Tuple(tuple) if tuple.elems.is_empty()),
    );

    serving.sig.asyncness.is_none()
        && operator.sig.asyncness.is_none()
        && is_exact_path(
            &serving_call.func,
            &["domains", "identity", "load_password_blocklist"],
        )
        && serving_call.args.len() == 1
        && serving_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, serving_config))
        && is_exact_path(&operator_ok.func, &["Ok"])
        && operator_ok.args.len() == 1
        && operator_unit
}

fn profile_prepare_function_is_canonical(
    file: &syn::File,
    function_name: &str,
    local_function: &str,
    output_type: &str,
    carries_password_blocklist: bool,
) -> bool {
    let Some(function) = production_named_function(file, function_name) else {
        return false;
    };
    if function.sig.asyncness.is_some()
        || !function.sig.inputs.is_empty()
        || !matches!(function.vis, syn::Visibility::Public(_))
    {
        return false;
    }
    let [syn::Stmt::Local(prepared), syn::Stmt::Expr(result, None)] =
        function.block.stmts.as_slice()
    else {
        return false;
    };
    let syn::Pat::Tuple(bindings) = &prepared.pat else {
        return false;
    };
    if bindings.elems.len() != 2 {
        return false;
    }
    let Some(first_binding) = bindings.elems.first() else {
        return false;
    };
    let Some(prepared_binding) = immutable_pat_ident(first_binding) else {
        return false;
    };
    let password_binding = bindings.elems.iter().nth(1).and_then(immutable_pat_ident);
    if carries_password_blocklist != password_binding.is_some() {
        return false;
    }
    let Some(kernel_call) = prepared
        .init
        .as_ref()
        .and_then(|init| call_behind_result_context(&init.expr))
    else {
        return false;
    };
    let syn::Expr::Call(ok) = transparent_expr(result) else {
        return false;
    };
    let Some(syn::Expr::Call(constructor)) = ok.args.first().map(transparent_expr) else {
        return false;
    };
    let constructor_arguments_are_canonical = constructor.args.len()
        == if carries_password_blocklist { 2 } else { 1 }
        && constructor
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, prepared_binding))
        && (!carries_password_blocklist
            || password_binding.is_some_and(|password| {
                constructor
                    .args
                    .iter()
                    .nth(1)
                    .is_some_and(|arg| is_exact_ident_path(arg, password))
            }));

    is_exact_path(&kernel_call.func, &["prepare_runtime_kernel"])
        && kernel_call.args.len() == 1
        && kernel_call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &[local_function]))
        && is_exact_path(&ok.func, &["Ok"])
        && ok.args.len() == 1
        && is_exact_path(&constructor.func, &[output_type, "new"])
        && constructor_arguments_are_canonical
}

fn runtime_kernel_uses_ordered_helper(file: &syn::File) -> bool {
    let Some(kernel) = production_named_function(file, "prepare_runtime_kernel") else {
        return false;
    };
    let calls = kernel
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => local.init.as_ref(),
            _ => None,
        })
        .filter_map(|init| call_behind_result_context(&init.expr))
        .filter(|call| is_exact_path(&call.func, &["prepare_local_before_external"]))
        .collect::<Vec<_>>();
    let Some(call) = (calls.len() == 1).then_some(calls[0]) else {
        return false;
    };
    let Some(syn::Expr::Closure(external)) = call.args.iter().nth(2).map(transparent_expr) else {
        return false;
    };
    let Some(external_call) = direct_call_behind_runtime_context(&external.body) else {
        return false;
    };
    call.args.len() == 3
        && call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &["config"]))
        && call
            .args
            .iter()
            .nth(1)
            .is_some_and(|arg| is_exact_path(arg, &["prepare_local"]))
        && external.inputs.is_empty()
        && is_exact_path(&external_call.func, &["build_trace_export"])
        && external_call.args.len() == 1
        && external_call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &["config"]))
}

#[derive(Debug, Clone, Copy)]
struct PasswordPreloadStatus {
    prepare_wiring: bool,
    helper_shape: bool,
    calls: usize,
}

impl PasswordPreloadStatus {
    fn inspect(file: &syn::File) -> Self {
        Self {
            prepare_wiring: profile_local_functions_are_canonical(file)
                && profile_prepare_function_is_canonical(
                    file,
                    "prepare_runtime",
                    "prepare_serving_local",
                    "ServingRuntimeInputs",
                    true,
                )
                && profile_prepare_function_is_canonical(
                    file,
                    "prepare_operator_runtime",
                    "prepare_operator_local",
                    "OperatorRuntimeInputs",
                    false,
                ),
            helper_shape: password_policy_preload_helper_is_canonical(file)
                && runtime_kernel_uses_ordered_helper(file),
            calls: production_exact_path_call_count_in_file(
                file,
                &["prepare_local_before_external"],
            ),
        }
    }

    fn is_canonical(self) -> bool {
        self.prepare_wiring && self.helper_shape && self.calls == 1
    }

    fn diagnostic(self) -> String {
        format!(
            "password preload: prepare_wiring={}, helper_shape={}, calls={}/1",
            self.prepare_wiring, self.helper_shape, self.calls
        )
    }
}

#[cfg(test)]
fn runtime_config_snapshot_findings_for_file(file: &syn::File) -> Vec<Finding<Rule>> {
    runtime_config_snapshot_findings(file, false)
}

fn production_runtime_config_snapshot_findings(file: &syn::File) -> Vec<Finding<Rule>> {
    runtime_config_snapshot_findings(file, true)
}

fn runtime_config_snapshot_findings(
    file: &syn::File,
    require_password_policy: bool,
) -> Vec<Finding<Rule>> {
    let prepares = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "prepare_runtime" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let runs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "run" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let startups = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "run_startup" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if prepares.len() != 1
        || prepares[0].sig.asyncness.is_some()
        || runs.len() != 1
        || runs[0].sig.asyncness.is_none()
        || startups.len() != 1
        || startups[0].sig.asyncness.is_none()
    {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "runtime configuration snapshot gate requires exactly one production prepare_runtime(), one public async run(), and one private async run_startup()",
        )];
    }

    let Some(runtime_inputs_binding) = runtime_inputs_mut_parameter(startups[0]) else {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "production run_startup() must accept exactly one named &mut ServingRuntimeInputs parameter",
        )];
    };
    let mut prepare_wiring = PrepareRuntimeConfigWiring::default();
    prepare_wiring.visit_block(&prepares[0].block);
    let mut run_wiring = RunRuntimeConfigWiring::new(runtime_inputs_binding.clone());
    run_wiring.visit_block(&startups[0].block);
    let mut inventory = ProductionRuntimeConfigInventory::default();
    inventory.visit_file(file);

    let password_preload = PasswordPreloadStatus::inspect(file);
    let prepare_wiring_is_canonical = if require_password_policy {
        password_preload.prepare_wiring
    } else {
        prepare_wiring.is_canonical(false)
    };
    let password_preload_helper_is_canonical =
        !require_password_policy || password_preload.helper_shape;
    let password_preload_calls_are_canonical =
        !require_password_policy || password_preload.is_canonical();

    if prepare_wiring_is_canonical
        && password_preload_helper_is_canonical
        && password_preload_calls_are_canonical
        && run_wiring.is_canonical()
        && settings_vault_snapshot_definition_is_exact(file)
        && runtime_lifecycle_outer_is_canonical(file, runs[0])
        && inventory.is_exact()
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            format!(
                "prepare_runtime() must seal its sole process snapshot and password blocklist into ServingRuntimeInputs while prepare_operator_runtime() constructs capability-free OperatorRuntimeInputs; the exact serving lifecycle owner must finish one run_startup result; run_startup must map exact PG/Redis/Vault/S3 generations, consume Vault/Redis and named S3 parts by value, preserve canonical PG setup, and route the DLX S3 part without aliases or bait; {}; run={run_wiring:?}, inventory={} ",
                password_preload.diagnostic(),
                inventory.diagnostic()
            ),
        )]
    }
}

fn runtime_binary_config_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for (relative, rss) in [(SERVER_MAIN_PATH, false), (RSS_MAIN_PATH, true)] {
        let path = root.join(relative);
        if !path.exists() {
            continue;
        }
        let source =
            fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    relative,
                    format!("runtime binary snapshot gate 无法解析 Rust: {error}"),
                ));
                continue;
            }
        };
        let mains = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(item)
                    if item.sig.ident == "main" && attrs_may_be_production(&item.attrs) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut inventory = BinaryRuntimeWiring::default();
        inventory.visit_file(&file);
        let shared_wiring_is_canonical = mains.len() == 1
            && inventory.prepare_calls == 1
            && inventory.prepared_binding.is_some()
            && inventory.run_calls == 1
            && inventory.canonical_run_calls == 1
            && inventory.forbidden_indirections == 0;
        let canonical = if rss {
            mains.len() == 1
                && classifier_is_canonical(&file)
                && rss_main_is_canonical(mains[0])
                && inventory.forbidden_indirections == 0
        } else {
            shared_wiring_is_canonical
                && mains[0].sig.asyncness.is_some()
                && inventory.shutdown_calls == 0
        };
        if !canonical {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative,
                if rss {
                    "rss main must classify the closed command family before preparation; serving must inline the sole prepare_runtime -> run path, while operators must acquire exact OperatorRuntimeInputs once, pass it to every closed operator arm, and consume it in the sole shutdown_operator_runtime call without aliases, macros, or bait"
                } else {
                    "server main must bind its sole runtime::prepare_runtime result and pass that exact binding exactly once to runtime::run, with no shutdown or alias side path"
                },
            ));
        }
    }
    Ok(findings)
}

const ENV_SECRET_METHODS: &[(&str, &[&str], &str)] = &[
    (
        "required_value",
        &["value:Option<&str>", "name:&'staticstr"],
        "anyhow::Result<Self>",
    ),
    (
        "optional_value",
        &["value:Option<&str>", "name:&'staticstr"],
        "anyhow::Result<Option<Self>>",
    ),
    (
        "required",
        &["get:&implFn(&str)->Option<String>", "name:&'staticstr"],
        "anyhow::Result<Self>",
    ),
    (
        "optional",
        &["get:&implFn(&str)->Option<String>", "name:&'staticstr"],
        "anyhow::Result<Option<Self>>",
    ),
    ("differs_from", &["&self", "other:&Self"], "bool"),
    ("copy_secret_allocation", &["&self"], "String"),
    ("transfer_secret_allocation", &["self"], "String"),
];

fn env_secret_method_signature_is_exact(method: &syn::ImplItemFn) -> bool {
    let Some((_, inputs, output)) = ENV_SECRET_METHODS
        .iter()
        .find(|(name, _, _)| method.sig.ident == *name)
    else {
        return false;
    };
    is_pub_crate(&method.vis)
        && method.sig.asyncness.is_none()
        && method.sig.constness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.inputs.len() == inputs.len()
        && method
            .sig
            .inputs
            .iter()
            .zip(*inputs)
            .all(|(actual, expected)| compact_tokens(actual) == *expected)
        && matches!(&method.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == *output)
}

fn method_call_on_field(expr: &syn::Expr, base: &str, method: &str) -> bool {
    matches!(transparent_expr(expr), syn::Expr::MethodCall(call)
        if call.method == method
            && call.args.is_empty()
            && matches!(transparent_expr(&call.receiver), syn::Expr::Field(field)
                if is_exact_path(&field.base, &[base])
                    && matches!(&field.member, syn::Member::Unnamed(index) if index.index == 0)))
}

fn local_binding_for(
    block: &syn::Block,
    predicate: impl Fn(&syn::Expr) -> bool,
) -> Option<&syn::Ident> {
    let mut bindings = block.stmts.iter().filter_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        let initializer = local.init.as_ref()?;
        predicate(&initializer.expr).then(|| immutable_pat_ident(&local.pat))?
    });
    let binding = bindings.next()?;
    bindings.next().is_none().then_some(binding)
}

fn expr_is_direct_or_binding(
    expr: &syn::Expr,
    direct: impl Fn(&syn::Expr) -> bool,
    binding: Option<&syn::Ident>,
) -> bool {
    direct(expr) || binding.is_some_and(|binding| is_exact_ident_path(expr, binding))
}

fn env_secret_differs_body_is_safe(block: &syn::Block) -> bool {
    let left = local_binding_for(block, |expr| method_call_on_field(expr, "self", "expose"));
    let right = local_binding_for(block, |expr| method_call_on_field(expr, "other", "expose"));
    let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() else {
        return false;
    };
    matches!(transparent_expr(tail), syn::Expr::Binary(binary)
    if matches!(binary.op, syn::BinOp::Ne(_))
        && expr_is_direct_or_binding(
            &binary.left,
            |expr| method_call_on_field(expr, "self", "expose"),
            left,
        )
        && expr_is_direct_or_binding(
            &binary.right,
            |expr| method_call_on_field(expr, "other", "expose"),
            right,
        ))
}

fn env_secret_copy_body_is_safe(block: &syn::Block) -> bool {
    let exposed = local_binding_for(block, |expr| method_call_on_field(expr, "self", "expose"));
    let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() else {
        return false;
    };
    matches!(transparent_expr(tail), syn::Expr::MethodCall(call)
    if call.method == "to_owned"
        && call.args.is_empty()
        && expr_is_direct_or_binding(
            &call.receiver,
            |expr| method_call_on_field(expr, "self", "expose"),
            exposed,
        ))
}

fn env_secret_transfer_body_is_safe(block: &syn::Block) -> bool {
    let transferred = local_binding_for(block, |expr| {
        method_call_on_field(expr, "self", "into_string")
    });
    let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() else {
        return false;
    };
    expr_is_direct_or_binding(
        tail,
        |expr| method_call_on_field(expr, "self", "into_string"),
        transferred,
    )
}

fn env_secret_method_body_is_safe(method: &syn::ImplItemFn) -> bool {
    let body = compact_tokens(&method.block);
    match method.sig.ident.to_string().as_str() {
        "required_value" => {
            body.matches("secure::SecretText::from_string").count() == 1
                && body.matches("value.to_owned()").count() == 1
                && body.contains("Self(secure::SecretText::from_string")
        }
        "optional_value" => {
            body.matches("Self::required_value").count() == 1 && body.contains(".transpose()")
        }
        "required" => {
            body.matches("get(name)").count() == 1
                && body.matches("Self::required_value").count() == 1
                && body.contains("value.as_deref()")
        }
        "optional" => {
            body.matches("get(name)").count() == 1
                && body.matches("Self::optional_value").count() == 1
                && body.contains("value.as_deref()")
        }
        "differs_from" => env_secret_differs_body_is_safe(&method.block),
        "copy_secret_allocation" => env_secret_copy_body_is_safe(&method.block),
        "transfer_secret_allocation" => env_secret_transfer_body_is_safe(&method.block),
        _ => false,
    }
}

#[derive(Default)]
struct RawSecretExtractorInventory {
    allowed_expose: usize,
    allowed_into_string: usize,
    forbidden: usize,
    method: Option<String>,
}

impl<'ast> Visit<'ast> for RawSecretExtractorInventory {
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        let previous = self.method.replace(item.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, item);
        self.method = previous;
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if matches!(call.method.to_string().as_str(), "expose" | "into_string") {
            let receiver = compact_tokens(&call.receiver);
            match (self.method.as_deref(), call.method.to_string().as_str()) {
                (Some("differs_from"), "expose")
                    if matches!(receiver.as_str(), "self.0" | "other.0") =>
                {
                    self.allowed_expose += 1;
                }
                (Some("copy_secret_allocation"), "expose") if receiver == "self.0" => {
                    self.allowed_expose += 1;
                }
                (Some("transfer_secret_allocation"), "into_string") if receiver == "self.0" => {
                    self.allowed_into_string += 1;
                }
                _ => self.forbidden += 1,
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tokens = compact_tokens(&mac.tokens);
        self.forbidden += usize::from(tokens.contains("expose") || tokens.contains("into_string"));
    }
}

fn exact_env_secret_shape(secret_file: &syn::File, runtime_file: &syn::File) -> bool {
    let actual_structs = secret_file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "EnvSecret" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let actual_impls = secret_file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if type_last_ident(&item.self_ty).is_some_and(|ident| ident == "EnvSecret") =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let methods_are_exact = actual_impls.len() == 1
        && actual_impls[0].items.len() == ENV_SECRET_METHODS.len()
        && actual_impls[0].items.iter().all(|item| match item {
            syn::ImplItem::Fn(method) => {
                env_secret_method_signature_is_exact(method)
                    && env_secret_method_body_is_safe(method)
            }
            _ => false,
        });
    let mut extractors = RawSecretExtractorInventory::default();
    extractors.visit_file(secret_file);
    let private_module = runtime_file
        .items
        .iter()
        .filter(|item| {
            matches!(item,
        syn::Item::Mod(module)
            if module.ident == "secret_config"
                && matches!(module.vis, syn::Visibility::Inherited))
        })
        .count()
        == 1;
    let opaque_reexport = runtime_file
        .items
        .iter()
        .filter(|item| {
            matches!(item,
        syn::Item::Use(use_)
            if is_pub_crate(&use_.vis)
                && compact_tokens(&use_.tree) == "secret_config::EnvSecret")
        })
        .count()
        == 1;
    let carrier_is_exact = actual_structs.len() == 1
        && is_pub_crate(&actual_structs[0].vis)
        && actual_structs[0].generics.params.is_empty()
        && matches!(&actual_structs[0].fields, syn::Fields::Unnamed(fields)
        if fields.unnamed.len() == 1
            && fields.unnamed.first().is_some_and(|field| {
                compact_type_tokens(&field.ty) == "secure::SecretText"
                    && field.attrs.iter().any(|attribute| {
                        attribute.path().is_ident("redact")
                            && compact_tokens(&attribute.meta).contains("sensitivity=secret")
                    })
            }))
        && actual_structs[0].attrs.iter().any(|attribute| {
            attribute.path().is_ident("derive")
                && compact_tokens(&attribute.meta).contains("secure::Redact")
        });
    carrier_is_exact
        && methods_are_exact
        && extractors.allowed_expose == 3
        && extractors.allowed_into_string == 1
        && extractors.forbidden == 0
        && private_module
        && opaque_reexport
}

#[derive(Default)]
struct SecretFlowViolation {
    path: String,
    callable: String,
    context: String,
}

#[derive(Default)]
struct SecretFlowInventory {
    callable: Option<String>,
    current_path: String,
    transfer_total: usize,
    transfer_sinks: usize,
    copy_total: usize,
    copy_sinks: usize,
    comparison_total: usize,
    comparison_sinks: usize,
    sensitive_reads: usize,
    sensitive_mappings: usize,
    sensitive_conversions: usize,
    forbidden_indirections: Vec<SecretFlowViolation>,
    exact_sinks: BTreeMap<&'static str, usize>,
    sensitive_aliases: BTreeMap<String, &'static str>,
    sensitive_read_labels: BTreeMap<&'static str, usize>,
    sensitive_mapping_labels: BTreeMap<&'static str, usize>,
    sensitive_conversion_labels: BTreeMap<&'static str, usize>,
    comparison_labels: BTreeMap<&'static str, usize>,
}

impl SecretFlowInventory {
    fn record_forbidden(&mut self, context: impl Into<String>) {
        self.forbidden_indirections.push(SecretFlowViolation {
            path: self.current_path.clone(),
            callable: self
                .callable
                .clone()
                .unwrap_or_else(|| "module scope".to_owned()),
            context: context.into(),
        });
    }

    fn method_arg(expr: &syn::Expr, receiver: &str, method: &str) -> bool {
        matches!(transparent_expr(expr), syn::Expr::MethodCall(call)
            if call.method == method
                && call.args.is_empty()
                && is_exact_path(&call.receiver, &[receiver]))
    }

    fn canonical_sensitive_key(raw: &str) -> Option<&'static str> {
        match raw {
            "VAULT_TOKEN_ENV" | "RSS_VAULT_TOKEN" => Some("VAULT_TOKEN_ENV"),
            "S3_ACCESS_KEY_ID_ENV" | "RSS_S3_ACCESS_KEY_ID" => Some("S3_ACCESS_KEY_ID_ENV"),
            "S3_SECRET_ACCESS_KEY_ENV" | "RSS_S3_SECRET_ACCESS_KEY" => {
                Some("S3_SECRET_ACCESS_KEY_ENV")
            }
            "S3_SESSION_TOKEN_ENV" | "RSS_S3_SESSION_TOKEN" => Some("S3_SESSION_TOKEN_ENV"),
            _ => None,
        }
    }

    fn sensitive_key(&self, expr: &syn::Expr) -> Option<&'static str> {
        match transparent_expr(expr) {
            syn::Expr::Path(path) => {
                let ident = path.path.segments.last()?.ident.to_string();
                Self::canonical_sensitive_key(&ident)
                    .or_else(|| self.sensitive_aliases.get(&ident).copied())
            }
            syn::Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Str(value) => Self::canonical_sensitive_key(&value.value()),
                _ => None,
            },
            _ => None,
        }
    }

    fn direct_snapshot_read(&self, expr: &syn::Expr, key: &str) -> bool {
        matches!(transparent_expr(expr), syn::Expr::MethodCall(call)
            if call.method == "value"
                && call.args.len() == 1
                && is_exact_path(&call.receiver, &["config"])
                && call.args.first().and_then(|argument| self.sensitive_key(argument)) == Some(key))
    }

    fn record_sensitive_use_tree(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => self.record_sensitive_use_tree(&path.tree),
            syn::UseTree::Rename(rename) => {
                if let Some(key) = Self::canonical_sensitive_key(&rename.ident.to_string()) {
                    self.sensitive_aliases
                        .insert(rename.rename.to_string(), key);
                }
            }
            syn::UseTree::Name(name) => {
                if let Some(key) = Self::canonical_sensitive_key(&name.ident.to_string()) {
                    self.sensitive_aliases.insert(name.ident.to_string(), key);
                }
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.record_sensitive_use_tree(item);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn record_vault_sink(&mut self, call: &syn::ExprCall, sink: &str) {
        let callable = self.callable.as_deref();
        let approved = match (callable, sink) {
            (Some("build_dlx_vault_key_providers_from"), sink)
                if sink.ends_with("VaultKeyProvider::new") =>
            {
                let argument = call.args.iter().nth(2);
                for (receiver, label) in [
                    ("hot_token", "event.hot"),
                    ("archive_token", "event.archive"),
                ] {
                    if argument.is_some_and(|arg| {
                        Self::method_arg(arg, receiver, "transfer_secret_allocation")
                    }) {
                        *self.exact_sinks.entry(label).or_default() += 1;
                    }
                }
                argument.is_some_and(|arg| {
                    Self::method_arg(arg, "hot_token", "transfer_secret_allocation")
                        || Self::method_arg(arg, "archive_token", "transfer_secret_allocation")
                })
            }
            (Some("into_runtime" | "into_settings_key_provider"), sink)
                if sink.ends_with("VaultKeyProvider::new") =>
            {
                let approved = call.args.iter().nth(2).is_some_and(|arg| {
                    Self::method_arg(arg, "token", "transfer_secret_allocation")
                });
                if approved {
                    let label = if callable == Some("into_runtime") {
                        "vault.runtime"
                    } else {
                        "vault.settings"
                    };
                    *self.exact_sinks.entry(label).or_default() += 1;
                }
                approved
            }
            (Some("into_runtime"), sink) if sink.ends_with("VaultSecretResolver::new") => {
                let approved =
                    call.args.iter().nth(2).is_some_and(|arg| {
                        Self::method_arg(arg, "token", "copy_secret_allocation")
                    });
                if approved {
                    *self.exact_sinks.entry("vault.copy").or_default() += 1;
                }
                approved
            }
            _ => false,
        };
        if approved {
            if call.args.iter().nth(2).is_some_and(|arg| matches!(transparent_expr(arg), syn::Expr::MethodCall(method) if method.method == "copy_secret_allocation")) {
                self.copy_sinks += 1;
            } else {
                self.transfer_sinks += 1;
            }
        }
    }

    fn record_s3_sink(&mut self, call: &syn::ExprCall, sink: &str) {
        if self.callable.as_deref() != Some("s3_general_config_from_values")
            || !sink.ends_with("Credentials::new")
        {
            return;
        }
        let access = call.args.first().is_some_and(|arg| {
            Self::method_arg(arg, "access_key_id", "transfer_secret_allocation")
        });
        let secret = call.args.iter().nth(1).is_some_and(|arg| {
            Self::method_arg(arg, "secret_access_key", "transfer_secret_allocation")
        });
        let session = call.args.iter().nth(2).is_some_and(|arg| matches!(transparent_expr(arg), syn::Expr::MethodCall(map)
            if map.method == "map"
                && is_exact_path(&map.receiver, &["session_token"])
                && map.args.len() == 1
                && map.args.first().is_some_and(|arg| is_exact_path(arg, &["EnvSecret", "transfer_secret_allocation"]))));
        for (approved, label) in [
            (access, "s3.access"),
            (secret, "s3.secret"),
            (session, "s3.session"),
        ] {
            self.transfer_sinks += usize::from(approved);
            if approved {
                *self.exact_sinks.entry(label).or_default() += 1;
            }
        }
    }

    fn record_sensitive_conversion(&mut self, call: &syn::ExprCall) {
        let key = call
            .args
            .iter()
            .nth(1)
            .and_then(|argument| self.sensitive_key(argument));
        if matches!(
            expr_path_last(&call.func)
                .map(ToString::to_string)
                .as_deref(),
            Some("required_value" | "optional_value")
        ) && call.args.len() == 2
            && key.is_some()
            && matches!(call.args.first().map(transparent_expr), Some(syn::Expr::Field(field))
                if is_exact_path(&field.base, &["values"]))
        {
            self.sensitive_conversions += 1;
            *self
                .sensitive_conversion_labels
                .entry(key.unwrap_or("unknown"))
                .or_default() += 1;
        }
    }
}

impl<'ast> Visit<'ast> for SecretFlowInventory {
    fn visit_file(&mut self, file: &'ast syn::File) {
        self.sensitive_aliases.clear();
        for item in &file.items {
            if let syn::Item::Use(use_) = item {
                self.record_sensitive_use_tree(&use_.tree);
            }
        }
        syn::visit::visit_file(self, file);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_production(&item.attrs) {
            let previous = self.callable.replace(item.sig.ident.to_string());
            let aliases = self.sensitive_aliases.clone();
            syn::visit::visit_item_fn(self, item);
            self.sensitive_aliases = aliases;
            self.callable = previous;
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_production(&item.attrs) {
            let previous = self.callable.replace(item.sig.ident.to_string());
            let aliases = self.sensitive_aliases.clone();
            syn::visit::visit_impl_item_fn(self, item);
            self.sensitive_aliases = aliases;
            self.callable = previous;
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.record_sensitive_use_tree(&item.tree);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (Some(binding), Some(initializer)) = (
            immutable_pat_ident(&local.pat),
            local
                .init
                .as_ref()
                .map(|initializer| initializer.expr.as_ref()),
        ) && let Some(key) = self.sensitive_key(initializer)
        {
            self.sensitive_aliases.insert(binding.to_string(), key);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
        let expected = match path_last_ident(&item.path)
            .map(ToString::to_string)
            .as_deref()
        {
            Some("VaultConfigValues") => &[("token", "VAULT_TOKEN_ENV")][..],
            Some("S3GeneralConfigValues") => &[
                ("access_key_id", "S3_ACCESS_KEY_ID_ENV"),
                ("secret_access_key", "S3_SECRET_ACCESS_KEY_ENV"),
                ("session_token", "S3_SESSION_TOKEN_ENV"),
            ][..],
            _ => &[][..],
        };
        for (field, key) in expected {
            let mapped = item.fields.iter().any(|candidate| {
                matches!(&candidate.member, syn::Member::Named(member) if member == field)
                    && self.direct_snapshot_read(&candidate.expr, key)
            });
            self.sensitive_mappings += usize::from(mapped);
            if mapped {
                *self.sensitive_mapping_labels.entry(key).or_default() += 1;
            }
        }
        syn::visit::visit_expr_struct(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if expr_path_last(&call.func).is_some_and(|callee| callee == "new") {
            let sink = compact_tokens(&call.func);
            self.record_vault_sink(call, &sink);
            self.record_s3_sink(call, &sink);
        }
        self.record_sensitive_conversion(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        match call.method.to_string().as_str() {
            "transfer_secret_allocation" => self.transfer_total += 1,
            "copy_secret_allocation" => self.copy_total += 1,
            "differs_from" => {
                self.comparison_total += 1;
                let pair = (
                    compact_tokens(&call.receiver),
                    call.args.first().map(compact_tokens),
                );
                let label = if self.callable.as_deref()
                    == Some("build_dlx_vault_key_providers_from")
                {
                    match (pair.0.as_str(), pair.1.as_deref()) {
                        ("hot_token", Some("&archive_token")) => Some("event.compare.hot_archive"),
                        ("hot_token", Some("&general_token")) => Some("event.compare.hot_general"),
                        ("archive_token", Some("&general_token")) => {
                            Some("event.compare.archive_general")
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                self.comparison_sinks += usize::from(label.is_some());
                if let Some(label) = label {
                    *self.comparison_labels.entry(label).or_default() += 1;
                }
            }
            "value" => {
                if let Some(key) = call
                    .args
                    .first()
                    .and_then(|argument| self.sensitive_key(argument))
                {
                    self.sensitive_reads += 1;
                    *self.sensitive_read_labels.entry(key).or_default() += 1;
                }
            }
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if compact_tokens(path) == "EnvSecret::transfer_secret_allocation" {
            self.transfer_total += 1;
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tokens = compact_tokens(&mac.tokens);
        let sensitive_key = [
            ("VAULT_TOKEN_ENV", "VAULT_TOKEN_ENV"),
            ("S3_ACCESS_KEY_ID_ENV", "S3_ACCESS_KEY_ID_ENV"),
            ("S3_SECRET_ACCESS_KEY_ENV", "S3_SECRET_ACCESS_KEY_ENV"),
            ("S3_SESSION_TOKEN_ENV", "S3_SESSION_TOKEN_ENV"),
        ]
        .iter()
        .find_map(|(token, key)| tokens.contains(token).then_some(*key))
        .or_else(|| {
            self.sensitive_aliases
                .iter()
                .find_map(|(alias, key)| tokens.contains(alias).then_some(*key))
        });
        let macro_name = compact_tokens(&mac.path);
        let snapshot_callable = matches!(
            self.callable.as_deref(),
            Some("from_snapshot" | "from_values")
        );
        let snapshot_reader = tokens.contains("config.value(")
            || tokens.contains("snapshot.value(")
            || (tokens.contains('$') && tokens.contains(".value("));
        if snapshot_reader || (snapshot_callable && sensitive_key.is_some()) {
            self.record_forbidden(format!(
                "source macro {macro_name} contains snapshot value reader or sensitive key {}; fail-closed macro provenance",
                sensitive_key.unwrap_or("unknown-sensitive-key")
            ));
        }
        if tokens.contains("differs_from") {
            self.comparison_total += 1;
            let comparison = [
                (
                    "hot_token.differs_from(&archive_token),",
                    "event.compare.hot_archive",
                ),
                (
                    "hot_token.differs_from(&general_token),",
                    "event.compare.hot_general",
                ),
                (
                    "archive_token.differs_from(&general_token),",
                    "event.compare.archive_general",
                ),
            ]
            .iter()
            .find(|(expected, _)| tokens.starts_with(expected));
            let approved = comparison.is_some();
            self.comparison_sinks += usize::from(approved);
            if let Some((_, label)) = comparison {
                *self.comparison_labels.entry(label).or_default() += 1;
            }
            if !approved {
                self.record_forbidden(format!(
                    "sink macro {macro_name} contains an unapproved secret comparison"
                ));
            }
        }
        if ["transfer_secret_allocation", "copy_secret_allocation"]
            .iter()
            .any(|method| tokens.contains(method))
        {
            self.record_forbidden(format!(
                "sink macro {macro_name} contains a secret transfer/copy helper"
            ));
        }
    }
}

fn runtime_secret_transfer_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let require_complete = root.join("Cargo.toml").exists();
    if !require_complete && !root.join(RUNTIME_CONFIG_FIXTURE_MARKER).exists() {
        return Ok(Vec::new());
    }
    let secret_path = root.join(RUNTIME_SECRET_CONFIG_PATH);
    let runtime_path = root.join(RUNTIME_LIB_PATH);
    if !secret_path.exists() || !runtime_path.exists() {
        return Ok(vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_SECRET_CONFIG_PATH,
            "secret carrier gate requires the sibling private secret_config module",
        )]);
    }
    let secret_file = syn::parse_file(&fs::read_to_string(&secret_path)?)?;
    let runtime_file = syn::parse_file(&fs::read_to_string(&runtime_path)?)?;
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let production_sources = production_module_sources(&paths)?;
    let mut inventory = SecretFlowInventory::default();
    let mut env_secret_structs = 0;
    for path in paths {
        if !production_sources.contains(&normalize_path(&path)) {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(_) if !require_complete => continue,
            Err(error) => return Err(error.into()),
        };
        env_secret_structs += file
            .items
            .iter()
            .filter(|item| {
                matches!(item,
            syn::Item::Struct(item) if item.ident == "EnvSecret")
            })
            .count();
        inventory.current_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        inventory.visit_file(&file);
    }
    let mut findings = Vec::new();
    if !exact_env_secret_shape(&secret_file, &runtime_file) || env_secret_structs != 1 {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_SECRET_CONFIG_PATH,
            format!(
                "carrier EnvSecret in runtime::secret_config is missing or has extra/non-opaque structure; expected one private zeroizing carrier and observed {env_secret_structs} EnvSecret definitions"
            ),
        ));
    }

    for (label, path, function) in [
        (
            "VAULT_TOKEN_ENV",
            RUNTIME_VAULT_PATH,
            "VaultRuntimeConfig::from_snapshot/from_values",
        ),
        (
            "S3_ACCESS_KEY_ID_ENV",
            RUNTIME_S3_PATH,
            "S3RuntimeConfig::from_snapshot/s3_general_config_from_values",
        ),
        (
            "S3_SECRET_ACCESS_KEY_ENV",
            RUNTIME_S3_PATH,
            "S3RuntimeConfig::from_snapshot/s3_general_config_from_values",
        ),
        (
            "S3_SESSION_TOKEN_ENV",
            RUNTIME_S3_PATH,
            "S3RuntimeConfig::from_snapshot/s3_general_config_from_values",
        ),
    ] {
        let reads = inventory
            .sensitive_read_labels
            .get(label)
            .copied()
            .unwrap_or(0);
        let mappings = inventory
            .sensitive_mapping_labels
            .get(label)
            .copied()
            .unwrap_or(0);
        let conversions = inventory
            .sensitive_conversion_labels
            .get(label)
            .copied()
            .unwrap_or(0);
        if (reads, mappings, conversions) != (1, 1, 1) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "source {label} in {function} has missing/extra stages; expected read=1, mapping=1, conversion=1, observed read={reads}, mapping={mappings}, conversion={conversions}"
                ),
            ));
        }
    }

    for (label, path, function) in [
        (
            "event.hot",
            RUNTIME_EVENT_PATH,
            "build_dlx_vault_key_providers_from",
        ),
        (
            "event.archive",
            RUNTIME_EVENT_PATH,
            "build_dlx_vault_key_providers_from",
        ),
        (
            "s3.access",
            RUNTIME_S3_PATH,
            "s3_general_config_from_values",
        ),
        (
            "s3.secret",
            RUNTIME_S3_PATH,
            "s3_general_config_from_values",
        ),
        (
            "s3.session",
            RUNTIME_S3_PATH,
            "s3_general_config_from_values",
        ),
        (
            "vault.runtime",
            RUNTIME_VAULT_PATH,
            "VaultRuntimeConfig::into_runtime",
        ),
        (
            "vault.settings",
            RUNTIME_VAULT_PATH,
            "VaultRuntimeConfig::into_settings_key_provider",
        ),
        (
            "vault.copy",
            RUNTIME_VAULT_PATH,
            "VaultRuntimeConfig::into_runtime",
        ),
    ] {
        let observed = inventory.exact_sinks.get(label).copied().unwrap_or(0);
        if observed != 1 {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "sink {label} in {function} is missing/extra; expected exactly 1 approved handoff, observed {observed}"
                ),
            ));
        }
    }

    for label in [
        "event.compare.hot_archive",
        "event.compare.hot_general",
        "event.compare.archive_general",
    ] {
        let observed = inventory.comparison_labels.get(label).copied().unwrap_or(0);
        if observed != 1 {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_EVENT_PATH,
                format!(
                    "sink {label} in build_dlx_vault_key_providers_from is missing/extra; expected exactly 1 comparison, observed {observed}"
                ),
            ));
        }
    }

    if inventory.transfer_total != inventory.transfer_sinks {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_SRC_PATH,
            format!(
                "secret transfer sink inventory has missing/extra unregistered handoffs; approved={}, observed={}",
                inventory.transfer_sinks, inventory.transfer_total
            ),
        ));
    }
    if inventory.copy_total != inventory.copy_sinks {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_VAULT_PATH,
            format!(
                "secret copy sink VaultRuntimeConfig::into_runtime has missing/extra handoffs; approved={}, observed={}",
                inventory.copy_sinks, inventory.copy_total
            ),
        ));
    }
    if inventory.comparison_total != inventory.comparison_sinks {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_EVENT_PATH,
            format!(
                "secret comparison sink build_dlx_vault_key_providers_from has missing/extra calls; approved={}, observed={}",
                inventory.comparison_sinks, inventory.comparison_total
            ),
        ));
    }
    for violation in &inventory.forbidden_indirections {
        findings.push(finding(
            Rule::ForbiddenWiring,
            &violation.path,
            format!(
                "forbidden secret macro/helper provenance in {}: {}",
                violation.callable, violation.context
            ),
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

fn is_exact_syn_path(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
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

fn immutable_pat_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat)
            if pat.by_ref.is_none() && pat.mutability.is_none() && pat.subpat.is_none() =>
        {
            Some(&pat.ident)
        }
        syn::Pat::Type(pat) => immutable_pat_ident(&pat.pat),
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
    call_behind_result_context(expr).is_some_and(is_process_snapshot_call)
}

fn is_process_snapshot_call(call: &syn::ExprCall) -> bool {
    path_ends_with(
        &call.func,
        &["RuntimeConfigSnapshot", "capture_process_snapshot"],
    ) && call.args.is_empty()
}

fn is_snapshot_view(expr: &syn::Expr, snapshot: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == "view" && call.args.is_empty() && is_exact_ident_path(&call.receiver, snapshot)
}

fn is_runtime_inputs_config_view(expr: &syn::Expr, runtime_inputs: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == "config"
        && call.args.is_empty()
        && is_exact_ident_path(&call.receiver, runtime_inputs)
}

fn is_snapshot_rust_log_filter(expr: &syn::Expr, config: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(fallback) = transparent_expr(expr) else {
        return false;
    };
    if fallback.method != "unwrap_or_else" || fallback.args.len() != 1 {
        return false;
    }
    let Some(syn::Expr::Closure(default)) = fallback.args.first().map(transparent_expr) else {
        return false;
    };
    if !default.inputs.is_empty() {
        return false;
    }
    let Some(default_call) = direct_call_behind_runtime_context(&default.body) else {
        return false;
    };
    let default_is_info = path_ends_with(&default_call.func, &["EnvFilter", "new"])
        && default_call.args.len() == 1
        && default_call.args.first().is_some_and(|arg| {
            matches!(transparent_expr(arg), syn::Expr::Lit(lit)
                if matches!(&lit.lit, syn::Lit::Str(value) if value.value() == "info"))
        });
    let syn::Expr::MethodCall(and_then) = transparent_expr(&fallback.receiver) else {
        return false;
    };
    if and_then.method != "and_then" || and_then.args.len() != 1 {
        return false;
    }
    let Some(syn::Expr::Closure(parse)) = and_then.args.first().map(transparent_expr) else {
        return false;
    };
    let Some(raw) = parse.inputs.first().and_then(pat_ident) else {
        return false;
    };
    if parse.inputs.len() != 1 {
        return false;
    }
    let syn::Expr::MethodCall(ok) = transparent_expr(&parse.body) else {
        return false;
    };
    let Some(parse_call) = direct_call_behind_runtime_context(&ok.receiver) else {
        return false;
    };
    let parser_is_canonical = ok.method == "ok"
        && ok.args.is_empty()
        && path_ends_with(&parse_call.func, &["EnvFilter", "try_new"])
        && parse_call.args.len() == 1
        && parse_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, raw));
    let syn::Expr::MethodCall(value) = transparent_expr(&and_then.receiver) else {
        return false;
    };
    let value_is_snapshot = value.method == "value"
        && value.args.len() == 1
        && is_exact_ident_path(&value.receiver, config)
        && value.args.first().is_some_and(|arg| {
            matches!(transparent_expr(arg), syn::Expr::Lit(lit)
                if matches!(&lit.lit, syn::Lit::Str(value) if value.value() == "RUST_LOG"))
        });
    default_is_info && parser_is_canonical && value_is_snapshot
}

fn subscriber_with_binding_count(expr: &syn::Expr, binding: &syn::Ident) -> usize {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return 0;
    };
    usize::from(
        call.method == "with"
            && call.args.len() == 1
            && call
                .args
                .first()
                .is_some_and(|arg| is_exact_ident_path(arg, binding)),
    ) + subscriber_with_binding_count(&call.receiver, binding)
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

fn runtime_inputs_parameter(item: &syn::ItemFn) -> Option<&syn::Ident> {
    if item.sig.inputs.len() != 1 {
        return None;
    }
    let syn::FnArg::Typed(input) = item.sig.inputs.first()? else {
        return None;
    };
    let syn::Type::Path(ty) = input.ty.as_ref() else {
        return None;
    };
    if ty.qself.is_some()
        || ty
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "ServingRuntimeInputs")
    {
        return None;
    }
    pat_ident(&input.pat)
}

fn generated_domains_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let path = root.join(RUNTIME_LIB_PATH);
    let text = fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    let run = production_async_function_scope(&text, "run_startup", "async fn run_startup(");
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
        .matches("modules_gen::wire_domains(&deps, domain_modules)")
        .count()
        != 1
        || !masked_run
            .contains("let mut domain_bindings = modules_gen::wire_domains(&deps, domain_modules)")
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

    let run = unique_production_async_function(&runtime, "run_startup");
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

fn unique_production_async_function<'a>(
    file: &'a syn::File,
    name: &str,
) -> Option<&'a syn::ItemFn> {
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == name
                    && item.sig.asyncness.is_some()
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    (functions.len() == 1).then_some(functions[0])
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
    let run = unique_production_async_function(&file, "run_startup");
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
        .position(|stmt| is_module_registration_result_stmt(stmt, &pg_binding, "pg_result"));
    let domain = stmts.iter().position(|stmt| {
        is_module_registration_result_stmt(stmt, &domain_binding, "domain_result")
    });
    let pg_propagation = stmts
        .iter()
        .position(|stmt| is_result_propagation_stmt(stmt, "pg_result"));
    let domain_propagation = stmts
        .iter()
        .position(|stmt| is_result_propagation_stmt(stmt, "domain_result"));
    matches!(
        (trace, pg, domain, pg_propagation, domain_propagation),
        (
            Some(trace),
            Some(pg),
            Some(domain),
            Some(pg_propagation),
            Some(domain_propagation)
        ) if trace < pg
            && pg < domain
            && domain < pg_propagation
            && pg_propagation < domain_propagation
    ) && stmts
        .iter()
        .filter(|stmt| is_module_registration_result_stmt(stmt, &pg_binding, "pg_result"))
        .count()
        == 1
        && stmts
            .iter()
            .filter(|stmt| {
                is_module_registration_result_stmt(stmt, &domain_binding, "domain_result")
            })
            .count()
            == 1
        && stmts
            .iter()
            .filter(|stmt| is_result_propagation_stmt(stmt, "pg_result"))
            .count()
            == 1
        && stmts
            .iter()
            .filter(|stmt| is_result_propagation_stmt(stmt, "domain_result"))
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

    let mtls_helpers = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "register_mtls_server"
                    && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let split_mtls_registration = mtls_helpers.len() == 1
        && method_call_count_in_block(&mtls_helpers[0].block, "register_detached") == 0
        && method_call_count_in_block(&mtls_helpers[0].block, "register_with_token") == 1;

    for item in &file.items {
        match item {
            syn::Item::Fn(function) if attrs_may_be_production(&function.attrs) => {
                let detached = method_call_count_in_block(&function.block, "register_detached");
                let with_token = method_call_count_in_block(&function.block, "register_with_token");
                if function.sig.ident == "bind_and_register" {
                    let inline = mtls_helpers.is_empty() && with_token == 2;
                    let split = split_mtls_registration
                        && with_token == 1
                        && exact_named_path_call_count(&function.block, &["register_mtls_server"])
                            == 1;
                    if detached != 0 || (!inline && !split) {
                        return false;
                    }
                } else if function.sig.ident == "register_mtls_server" {
                    if !split_mtls_registration {
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

fn is_module_registration_result_stmt(
    stmt: &syn::Stmt,
    module_binding: &str,
    result_binding: &str,
) -> bool {
    let syn::Stmt::Local(local) = stmt else {
        return false;
    };
    let syn::Pat::Ident(result) = &local.pat else {
        return false;
    };
    let Some(init) = &local.init else {
        return false;
    };
    let Some(call) = direct_call_behind_runtime_context(&init.expr) else {
        return false;
    };
    result.ident == result_binding
        && result.by_ref.is_none()
        && result.mutability.is_none()
        && init.diverge.is_none()
        && is_exact_path(&call.func, &["Self", "register_module_output"])
        && call.args.len() == 2
        && call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, &["stack"]))
        && call
            .args
            .last()
            .is_some_and(|arg| is_exact_path(arg, &[module_binding]))
}

fn is_result_propagation_stmt(stmt: &syn::Stmt, result_binding: &str) -> bool {
    matches!(
        stmt,
        syn::Stmt::Expr(syn::Expr::Try(propagation), Some(_))
            if is_exact_path(&propagation.expr, &[result_binding])
    )
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

fn production_exact_path_call_count_in_file(file: &syn::File, path: &[&str]) -> usize {
    struct Counter<'a> {
        path: &'a [&'a str],
        calls: usize,
    }
    impl Visit<'_> for Counter<'_> {
        fn visit_item_mod(&mut self, item: &syn::ItemMod) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_fn(&mut self, item: &syn::ItemFn) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_fn(self, item);
            }
        }

        fn visit_item_impl(&mut self, item: &syn::ItemImpl) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_impl(self, item);
            }
        }

        fn visit_impl_item_fn(&mut self, item: &syn::ImplItemFn) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_impl_item_fn(self, item);
            }
        }

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
    id: String,
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
            id: provider.id.clone(),
            port: provider.port.to_string(),
            provider: provider.provider.to_string(),
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
        id: "prepare.config.snapshot",
        path: RUNTIME_LIB_PATH,
        pattern: "RuntimeConfigSnapshot::capture_process_snapshot()",
    },
    AnchorSpec {
        id: "prepare.password-policy.preload",
        path: RUNTIME_LIB_PATH,
        pattern: "prepare_runtime_kernel(prepare_serving_local)?",
    },
    AnchorSpec {
        id: "prepare.tracing.otel",
        path: RUNTIME_LIB_PATH,
        pattern: "prepare_local_before_external(config, prepare_local, || build_trace_export(config))?",
    },
    AnchorSpec {
        id: "prepare.tracing.filter",
        path: RUNTIME_LIB_PATH,
        pattern: "let filter = config",
    },
    AnchorSpec {
        id: "prepare.inputs",
        path: RUNTIME_LIB_PATH,
        pattern: "PreparedRuntimeInputs::new(runtime_config, trace_export)",
    },
    AnchorSpec {
        id: "run.plan.load",
        path: RUNTIME_LIB_PATH,
        pattern: "plan::RuntimePlan::bundled(runtime_inputs.config()).context(",
    },
    AnchorSpec {
        id: "run.config.serving",
        path: RUNTIME_LIB_PATH,
        pattern: "RuntimeServingConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.provider.rss-access",
        path: RUNTIME_LIB_PATH,
        pattern: "build_rss_access_provider(",
    },
    AnchorSpec {
        id: "run.provider.federated-access",
        path: RUNTIME_LIB_PATH,
        pattern: "build_federated_access_provider(",
    },
    AnchorSpec {
        id: "run.config.s3",
        path: RUNTIME_LIB_PATH,
        pattern: "S3RuntimeConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.config.vault",
        path: RUNTIME_LIB_PATH,
        pattern: "VaultRuntimeConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.provider.vault",
        path: RUNTIME_LIB_PATH,
        pattern: "vault_config.into_runtime()",
    },
    AnchorSpec {
        id: "run.provider.redis",
        path: RUNTIME_LIB_PATH,
        pattern: "build_redis_runtime_deps(redis_config)",
    },
    AnchorSpec {
        id: "run.provider.s3",
        path: RUNTIME_LIB_PATH,
        pattern: "build_s3_runtime_deps(s3_general_config)",
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
        id: "run.provider.service-token",
        path: RUNTIME_LIB_PATH,
        pattern: "build_service_token_provider(",
    },
    AnchorSpec {
        id: "run.wire.generated-domains",
        path: RUNTIME_LIB_PATH,
        pattern: "modules_gen::wire_domains(&deps, domain_modules)",
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
        id: "run.resources.rss-access-token",
        path: RUNTIME_LIB_PATH,
        pattern: "if let Some(provider) = runtime_rss_access.as_ref() {\n                token_verifier_resources.push(provider.managed_resource());\n            }",
    },
    AnchorSpec {
        id: "run.resources.federated-access-token",
        path: RUNTIME_LIB_PATH,
        pattern: "if let Some(provider) = runtime_federated_access.as_ref() {\n                token_verifier_resources.push(provider.managed_resource());\n            }",
    },
    AnchorSpec {
        id: "run.resources.service-token",
        path: RUNTIME_LIB_PATH,
        pattern: "if let Some(provider) = runtime_service_token.as_ref() {\n                token_verifier_resources.push(provider.managed_resource());\n            }",
    },
    AnchorSpec {
        id: "run.probe.rss-access-token-jwks-name",
        path: RUNTIME_LIB_PATH,
        pattern: "ProbeName::parse(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)",
    },
    AnchorSpec {
        id: "run.probe.rss-access-token-jwks",
        path: RUNTIME_LIB_PATH,
        pattern: "Box::new(AccessTokenJwksReadyProbe::rss_access(",
    },
    AnchorSpec {
        id: "run.probe.federated-access-token-jwks-name",
        path: RUNTIME_LIB_PATH,
        pattern: "ProbeName::parse(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)",
    },
    AnchorSpec {
        id: "run.probe.federated-access-token-jwks",
        path: RUNTIME_LIB_PATH,
        pattern: "Box::new(AccessTokenJwksReadyProbe::federated_access(",
    },
    AnchorSpec {
        id: "run.module.input.domain-transport",
        path: RUNTIME_LIB_PATH,
        pattern: "let domain_transport_module = domain_transport",
    },
    AnchorSpec {
        id: "run.wire.distributed",
        path: RUNTIME_LIB_PATH,
        pattern: "distributed_runtime::wire_distributed(&deps, distributed_worker)",
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
        id: "run.auth.routers-capability",
        path: RUNTIME_LIB_PATH,
        pattern: "assemble_authed_routers(\n                runtime_inputs.config(),",
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
        id: "run.launch-capability",
        path: RUNTIME_LIB_PATH,
        pattern: "launch::launch(runtime_inputs.config(), launch_plan)",
    },
    AnchorSpec {
        id: "launch.shutdown.trace",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "if let Some(exporter) = trace_exporter",
    },
    AnchorSpec {
        id: "launch.shutdown.pg-output",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "let pg_result = Self::register_module_output(stack, pg_runtime_module);",
    },
    AnchorSpec {
        id: "launch.shutdown.domain-output",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "let domain_result = Self::register_module_output(stack, domain_module);",
    },
    AnchorSpec {
        id: "launch.shutdown.pg-result",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "pg_result?;",
    },
    AnchorSpec {
        id: "launch.shutdown.domain-result",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "domain_result?;",
    },
    AnchorSpec {
        id: "launch.shutdown.resources",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for resource in resources",
    },
    AnchorSpec {
        id: "launch.shutdown.workers",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "for worker in workers",
    },
    AnchorSpec {
        id: "launch.register-plan",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "let listeners = plan.register(&mut stack)?;",
    },
    AnchorSpec {
        id: "launch.listeners",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "bind_and_register(&mut stack, listener, budget, &addr_resolver).await?;",
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
        if spec.id.starts_with("prepare.") {
            let function = if spec.id == "prepare.password-policy.preload" {
                "pub fn prepare_runtime("
            } else {
                "fn prepare_runtime_kernel<"
            };
            return extract_braced_body_at(text, 0, function).unwrap_or_else(|| empty_scope(text));
        }
        return production_async_function_scope(text, "run_startup", "async fn run_startup(");
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
        if spec.id.starts_with("prepare.") {
            return if spec.id == "prepare.password-policy.preload" {
                (spec.path, "prepare-serving")
            } else {
                (spec.path, "prepare-kernel")
            };
        }
        return (spec.path, "run_startup");
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

fn production_async_function_scope<'a>(
    text: &'a str,
    name: &str,
    needle: &str,
) -> AnchorSearchScope<'a> {
    let Ok(file) = syn::parse_file(text) else {
        return extract_braced_body_at(text, 0, needle).unwrap_or_else(|| empty_scope(text));
    };
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == name
                    && item.sig.asyncness.is_some()
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(function) = (functions.len() == 1).then_some(functions[0]) else {
        return empty_scope(text);
    };
    let line = function.sig.ident.span().start().line;
    let search_from = if line <= 1 {
        0
    } else {
        text.match_indices('\n')
            .nth(line - 2)
            .map_or(0, |(offset, _)| offset + 1)
    };
    extract_braced_body_at(text, search_from, needle).unwrap_or_else(|| empty_scope(text))
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
                "{:02} | id={} | port={} | provider={} | providerCrate={} | requiredFeatures={} | consumer={} | lifecycle={} | durability={} | purpose={}",
                provider.index,
                provider.id,
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

    #[test]
    fn password_policy_preload_helper_gate_is_ordered_and_non_vacuous() -> Result<()> {
        let canonical = r#"
fn prepare_local_before_external<Local, External>(
    config: SnapshotConfig<'_>,
    prepare_local: impl FnOnce(SnapshotConfig<'_>) -> anyhow::Result<Local>,
    build_external: impl FnOnce() -> anyhow::Result<External>,
) -> anyhow::Result<(Local, External)> {
    let local = prepare_local(config)?;
    let external = build_external()?;
    Ok((local, external))
}
fn prepare_serving_local(config: SnapshotConfig<'_>) -> anyhow::Result<Blocklist> {
    domains::identity::load_password_blocklist(config)
}
fn prepare_operator_local(_: SnapshotConfig<'_>) -> anyhow::Result<()> { Ok(()) }
fn prepare_runtime_kernel<Local>(prepare_local: impl FnOnce() -> Local) {
    let (local, trace_export) =
        prepare_local_before_external(config, prepare_local, || build_trace_export(config))?;
}
pub fn prepare_runtime() -> anyhow::Result<ServingRuntimeInputs> {
    let (prepared, password_blocklist) = prepare_runtime_kernel(prepare_serving_local)?;
    Ok(ServingRuntimeInputs::new(prepared, password_blocklist))
}
pub fn prepare_operator_runtime() -> anyhow::Result<OperatorRuntimeInputs> {
    let (prepared, ()) = prepare_runtime_kernel(prepare_operator_local)?;
    Ok(OperatorRuntimeInputs::new(prepared))
}
"#;
        let status = PasswordPreloadStatus::inspect(&syn::parse_file(canonical)?);
        assert!(status.is_canonical(), "canonical profile split: {status:?}");

        let cases = [
            (
                "prepare wiring",
                canonical.replacen(
                    "prepare_runtime_kernel(prepare_serving_local)?",
                    "prepare_runtime_kernel(prepare_operator_local)?",
                    1,
                ),
                "password preload: prepare_wiring=false, helper_shape=true, calls=1/1",
            ),
            (
                "helper order",
                canonical.replacen(
                    "let local = prepare_local(config)?;\n    let external = build_external()?;",
                    "let external = build_external()?;\n    let local = prepare_local(config)?;",
                    1,
                ),
                "password preload: prepare_wiring=true, helper_shape=false, calls=1/1",
            ),
            (
                "production helper call count",
                format!(
                    "{canonical}\nfn duplicate() {{ prepare_local_before_external(config, local, external); }}\n"
                ),
                "password preload: prepare_wiring=true, helper_shape=true, calls=2/1",
            ),
        ];
        for (case, source, expected) in cases {
            let status = PasswordPreloadStatus::inspect(&syn::parse_file(&source)?);
            assert!(!status.is_canonical(), "{case} must be rejected");
            assert_eq!(status.diagnostic(), expected, "{case}");
        }
        Ok(())
    }

    #[test]
    fn runtime_profile_input_gate_rejects_password_capability_leaks() -> Result<()> {
        let canonical = r#"
pub struct PreparedRuntimeInputs;
pub struct ServingRuntimeInputs {
    prepared: PreparedRuntimeInputs,
    password_blocklist: std::sync::Arc<secure::DigestPasswordBlocklist>,
}
pub struct OperatorRuntimeInputs {
    prepared: PreparedRuntimeInputs,
}
"#;
        assert!(runtime_profile_input_structs_are_exact(&syn::parse_file(
            canonical
        )?));
        for (case, source) in [
            (
                "adapter-owned blocklist alias",
                canonical.replace(
                    "secure::DigestPasswordBlocklist",
                    "crypto::DigestPasswordBlocklist",
                ),
            ),
            (
                "operator carries password capability",
                canonical.replace(
                    "pub struct OperatorRuntimeInputs {\n    prepared: PreparedRuntimeInputs,\n}",
                    "pub struct OperatorRuntimeInputs {\n    prepared: PreparedRuntimeInputs,\n    password_blocklist: std::sync::Arc<secure::DigestPasswordBlocklist>,\n}",
                ),
            ),
        ] {
            assert!(
                !runtime_profile_input_structs_are_exact(&syn::parse_file(&source)?),
                "{case} must be rejected"
            );
        }

        let rss_access_jwks = r#"
pub async fn run_rss_access_jwks_export_command(
    args: &[String],
    runtime_inputs: &crate::OperatorRuntimeInputs,
) -> anyhow::Result<()> { todo!() }
"#;
        assert!(rss_access_jwks_operator_signature_is_exact(
            &syn::parse_file(rss_access_jwks)?
        ));
        assert!(!rss_access_jwks_operator_signature_is_exact(
            &syn::parse_file(
                &rss_access_jwks.replace("OperatorRuntimeInputs", "ServingRuntimeInputs")
            )?
        ));
        Ok(())
    }

    fn snapshot_program_with_lifecycle(legacy: &str) -> String {
        let startup = legacy.replace(
            "pub async fn run(mut runtime_inputs: RuntimeInputs)",
            "async fn run_startup(runtime_inputs: &mut ServingRuntimeInputs)",
        );
        assert_ne!(
            startup, legacy,
            "fixture must contain the legacy run signature"
        );
        let startup = startup.replace(
            "    let config = runtime_inputs.config();",
            "    finish(pg_owner.service_token_replay_store());\n    assemble_authed_routers(runtime_inputs.config());\n    launch(runtime_inputs.config());\n    let config = runtime_inputs.config();",
        );
        format!(
            r#"{startup}

async fn shutdown_prepared_runtime(inputs: &mut PreparedRuntimeInputs) -> anyhow::Result<()> {{
    if let Some(exporter) = inputs.take_trace_export() {{ exporter.shutdown().await?; }}
    Ok(())
}}
struct RuntimeLifecycleOwner {{ inputs: ServingRuntimeInputs }}
impl RuntimeLifecycleOwner {{
    fn new(inputs: ServingRuntimeInputs) -> Self {{ Self {{ inputs }} }}
    async fn run(mut self) -> anyhow::Result<()> {{
        let startup_result = run_startup(&mut self.inputs).await;
        self.finish(startup_result).await
    }}
    async fn finish(mut self, startup_result: anyhow::Result<()>) -> anyhow::Result<()> {{
        let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;
        match (startup_result, cleanup_result) {{
            (Ok(()), cleanup_result) => cleanup_result,
            (Err(startup_error), Ok(())) => Err(startup_error),
            (Err(startup_error), Err(cleanup_error)) => {{
                tracing::error!(cleanup_error = %cleanup_error, "cleanup failed");
                Err(startup_error)
            }}
        }}
    }}
}}
pub async fn run(runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {{
    RuntimeLifecycleOwner::new(runtime_inputs).run().await
}}
"#
        )
    }

    fn with_password_policy_preload(source: String) -> String {
        let source = source.replacen(
            "let trace_export = build_trace_export(config)?;",
            "let (password_blocklist, trace_export) =\n        seal_password_policy_before_external(config, || build_trace_export(config))?;",
            1,
        );
        let source = source.replacen(
            "Ok(RuntimeInputs::new(runtime_config, trace_export))",
            "Ok(RuntimeInputs::new(runtime_config, password_blocklist, trace_export))",
            1,
        );
        let source = source.replacen(
            "Ok(RuntimeInputs::new(runtime_config, password_blocklist, trace_export))",
            "let _prepared_inputs = PreparedRuntimeInputs::new(runtime_config, trace_export);\n    Ok(RuntimeInputs::new(runtime_config, password_blocklist, trace_export))",
            1,
        );
        format!(
            r#"
use phase::PreparedRuntimeInputs;
fn seal_password_policy_before_external<External>(
    config: SnapshotConfig<'_>,
    build_external: impl FnOnce() -> anyhow::Result<External>,
) -> anyhow::Result<(Arc<secure::DigestPasswordBlocklist>, External)> {{
    let password_blocklist = domains::identity::load_password_blocklist(config)?;
    let external = build_external()?;
    Ok((password_blocklist, external))
}}
{source}"#
        )
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
id = "listener-pdp"
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
            "use config::RuntimeConfigSnapshot;\nuse phase::ServingRuntimeInputs;\nuse infra::vault::VaultRuntimeConfig;\nuse infra::redis::{{build_redis_runtime_deps, RedisRuntimeConfig}};\nuse infra::s3::{{build_s3_dlx_archive_store, build_s3_runtime_deps, S3RuntimeConfig}};\n\npub fn prepare_runtime() {{\n{}\n}}\nfn prepare_runtime_kernel<Local>() {{\n{}\n}}\nasync fn run_startup(runtime_inputs: &mut ServingRuntimeInputs) {{\n{}\n}}\nfn assemble_runtime_module_outputs(inputs: RuntimeModuleAssemblyInputs) {{\nlet mut module = DomainModuleResult::default();\nmodule.merge(inputs.domains_module);\nmodule.merge(inputs.provider_module);\n}}\n",
            prepare_profile_anchor_lines(omit),
            prepare_kernel_anchor_lines(omit),
            run_anchor_lines(omit)
        )
    }

    fn prepare_profile_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.id == "prepare.password-policy.preload")
            .filter(|anchor| omit != Some(anchor.id))
            .map(|anchor| anchor.pattern)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn prepare_kernel_anchor_lines(omit: Option<&str>) -> String {
        RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| {
                anchor.path == RUNTIME_LIB_PATH
                    && anchor.id.starts_with("prepare.")
                    && anchor.id != "prepare.password-policy.preload"
            })
            .filter(|anchor| omit != Some(anchor.id))
            .map(|anchor| anchor.pattern)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn run_anchor_lines(omit: Option<&str>) -> String {
        let mut lines = Vec::new();
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH && anchor.id.starts_with("run."))
        {
            if omit == Some(anchor.id) {
                continue;
            }
            if anchor.id == "run.wire.generated-domains" {
                lines.push(
                    "let mut domain_bindings = modules_gen::wire_domains(&deps, domain_modules)",
                );
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
id = "listener-pdp"
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
            "01 | id=listener-pdp | port=diport::Pdp | provider=oidc::OidcProvider | providerCrate=oidc | requiredFeatures=[backend] | consumer=httpserve | lifecycle=active | durability=persistent | purpose=jwt-credential-verification"
        ));
        assert!(
            report
                .rendered
                .contains("mergeExtends = probes,resources,workers")
        );
        assert!(report.rendered.contains(
            "01 | prepare.config.snapshot | assemblies/runtime/src/lib.rs | RuntimeConfigSnapshot::capture_process_snapshot()"
        ));
        assert!(report.rendered.contains("| launch.register-plan |"));
        assert!(report.rendered.contains("| launch.listeners |"));
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
            "modules_gen::wire_domains(&deps, domain_modules)",
            "modules_gen::wire_domains(&deps, domain_modules)\nwire_settings(&deps)",
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
            "modules_gen::wire_domains(&deps, domain_modules)",
            "modules_gen::wire_domains(&deps, domain_modules)\ncrate::wire_settings(&deps)",
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
async fn run_startup() {
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
async fn run_startup() {
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
        let pg_result = Self::register_module_output(stack, pg_runtime_module);
        let domain_result = Self::register_module_output(stack, domain_module);
        pg_result?;
        domain_result?;
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
                    "let domain_result = Self::register_module_output(stack, domain_module);",
                    "let domain_result = Self::register_module_output(stack, domain_module);\n        stack.register_detached(event_guard);",
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
                            "let domain_result = Self::register_module_output(stack, domain_module);",
                            "let domain_result = Self::register_module_output(stack, domain_module);\n        register_event_lifecycle(stack, event_lifecycle);",
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
        let pg_result = Self::register_module_output(stack, pg_runtime_module);
        let domain_result = Self::register_module_output(stack, domain_module);
        pg_result?;
        domain_result?;
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
                    "        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }\n        let pg_result = Self::register_module_output(stack, pg_runtime_module);",
                    "        let pg_result = Self::register_module_output(stack, pg_runtime_module);\n        if let Some(exporter) = trace_exporter { stack.register_detached(exporter); }",
                ),
            ),
            (
                "duplicate pg registration",
                canonical_launch.replace(
                    "        let pg_result = Self::register_module_output(stack, pg_runtime_module);",
                    "        let pg_result = Self::register_module_output(stack, pg_runtime_module);\n        let _duplicate_pg_result = Self::register_module_output(stack, pg_runtime_module);",
                ),
            ),
            (
                "legacy direct pg registration",
                canonical_launch.replace(
                    "        let pg_result = Self::register_module_output(stack, pg_runtime_module);",
                    "        stack.register_detached(pg_store_guard);\n        let pg_result = Ok(());",
                ),
            ),
        ] {
            write(&launch_path, &mutated)?;
            assert_provider_gate_fails(&root, label)?;
        }
        write(&launch_path, &canonical_launch)?;
        write(&root.join(RUNTIME_LIB_PATH), "async fn run_startup( {\n")?;
        assert!(!provider_outputs_live_findings(&root)?.is_empty());
        write(&root.join(RUNTIME_LIB_PATH), &provider_output_fixture())?;
        write(&legacy_source, "fn broken( {\n")?;
        assert!(!provider_outputs_live_findings(&root)?.is_empty());
        Ok(())
    }

    #[test]
    fn runtime_baseline_provider_anchor_requires_real_provider_call() -> Result<()> {
        for provider_id in [
            "run.provider.rss-access",
            "run.provider.federated-access",
            "run.provider.service-token",
        ] {
            let root = fixture_root(&format!(
                "runtime-baseline-provider-anchor-real-call-{}",
                provider_id.replace('.', "-")
            ))?;
            let mut lines = Vec::new();
            for anchor in RUNTIME_ANCHORS
                .iter()
                .filter(|anchor| anchor.path == RUNTIME_LIB_PATH && anchor.id.starts_with("run."))
            {
                if anchor.id == provider_id {
                    lines.push(
                        "phase_result(RuntimePhase::BuildProvider, Ok::<_, anyhow::Error>(()))",
                    );
                } else {
                    lines.push(anchor.pattern);
                }
                if anchor.id == "run.shared-deps" {
                    lines.push("}");
                }
            }
            write(
                &root.join(RUNTIME_LIB_PATH),
                &format!("async fn run_startup() {{\n{}\n}}\n", lines.join("\n")),
            )?;
            let report = collect_report(&root)?;
            assert!(
                report.findings.iter().any(|finding| {
                    finding.rule == Rule::MissingAnchor && finding.detail.contains(provider_id)
                }),
                "provider phase marker alone must not satisfy {provider_id}: {:?}",
                report.findings
            );
        }
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
        let rss_access = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.provider.rss-access")
            .context("RSS access provider anchor")?;
        lines.push(rss_access.pattern);
        lines.push(plan.pattern);
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH && anchor.id.starts_with("run."))
        {
            if matches!(anchor.id, "run.plan.load" | "run.provider.rss-access") {
                continue;
            }
            lines.push(anchor.pattern);
            if anchor.id == "run.shared-deps" {
                lines.push("}");
            }
        }
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!("async fn run_startup() {{\n{}\n}}\n", lines.join("\n")),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.provider.rss-access")
            }),
            "plan load anchor must precede provider construction"
        );
        Ok(())
    }

    #[test]
    fn runtime_token_profile_anchors_reject_missing_and_bait_only_evidence() -> Result<()> {
        for anchor_id in [
            "run.provider.rss-access",
            "run.provider.federated-access",
            "run.provider.service-token",
            "run.resources.rss-access-token",
            "run.resources.federated-access-token",
            "run.resources.service-token",
            "run.probe.rss-access-token-jwks-name",
            "run.probe.rss-access-token-jwks",
            "run.probe.federated-access-token-jwks-name",
            "run.probe.federated-access-token-jwks",
        ] {
            let root = fixture_root(&format!(
                "runtime-token-profile-anchor-{}",
                anchor_id.replace('.', "-")
            ))?;
            let anchor = RUNTIME_ANCHORS
                .iter()
                .find(|anchor| anchor.id == anchor_id)
                .with_context(|| format!("missing test anchor {anchor_id}"))?;
            let source = format!(
                "{}\n// bait-only: {}\nconst TOKEN_PROFILE_BAIT: &str = {:?};\n",
                runtime_lib_fixture(Some(anchor_id)),
                anchor.pattern.replace('\n', " "),
                anchor.pattern,
            );
            write(&root.join(RUNTIME_LIB_PATH), &source)?;
            let report = collect_report(&root)?;
            assert!(
                report.findings.iter().any(|finding| {
                    finding.rule == Rule::MissingAnchor && finding.detail.contains(anchor_id)
                }),
                "comment/string bait must not satisfy {anchor_id}: {:?}",
                report.findings
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_baseline_requires_config_snapshot_before_runtime_inputs() -> Result<()> {
        let root = fixture_root("runtime-baseline-config-snapshot-before-inputs")?;
        let mut prepare_lines = Vec::new();
        let snapshot = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "prepare.config.snapshot")
            .context("config snapshot anchor")?;
        let inputs = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "prepare.inputs")
            .context("runtime inputs anchor")?;
        prepare_lines.push(inputs.pattern);
        prepare_lines.push(snapshot.pattern);
        for anchor in RUNTIME_ANCHORS
            .iter()
            .filter(|anchor| anchor.path == RUNTIME_LIB_PATH && anchor.id.starts_with("prepare."))
        {
            if matches!(anchor.id, "prepare.config.snapshot" | "prepare.inputs") {
                continue;
            }
            prepare_lines.push(anchor.pattern);
        }
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!(
                "pub fn prepare_runtime() {{\n{}\n}}\nasync fn run_startup(runtime_inputs: &mut RuntimeInputs) {{\n{}\n}}\n",
                prepare_lines.join("\n"),
                run_anchor_lines(None)
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|finding| {
                finding.rule == Rule::MissingAnchor && finding.detail.contains("prepare.inputs")
            }),
            "configuration snapshot must precede RuntimeInputs construction"
        );
        Ok(())
    }

    #[test]
    fn runtime_vault_s3_snapshot_wiring() -> Result<()> {
        let canonical = with_password_policy_preload(snapshot_program_with_lifecycle(
            r#"
use config::{RuntimeConfigSnapshot, RuntimeServingConfig, SnapshotConfig};
use phase::{OperatorRuntimeInputs, PreparedRuntimeInputs, RuntimeInputs, ServingRuntimeInputs};
use infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use infra::redis::{build_redis_runtime_deps, RedisRuntimeConfig};
use infra::s3::{
    build_s3_dlx_archive_store, build_s3_runtime_deps, S3DlxArchiveConfig,
    S3RuntimeConfig, S3RuntimeConfigParts,
};
use infra::vault::VaultRuntimeConfig;

pub fn prepare_runtime() -> anyhow::Result<RuntimeInputs> {
    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot();
    let config = runtime_config.view();
    let filter = config.value("RUST_LOG")
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let trace_export = build_trace_export(config)?;
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();
    Ok(RuntimeInputs::new(runtime_config, trace_export))
}

async fn build_dlx_lifecycle_bootstrap_config_from(
    archiver: PgConfig,
    verifier: PgConfig,
    purger: PgConfig,
    s3_archive: S3DlxArchiveConfig,
    get: Reader,
    clock: Clock,
) {
    let _archive = build_s3_dlx_archive_store(s3_archive, clock).await;
}

async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    config: SnapshotConfig<'_>,
) {
    let vault_config = match VaultRuntimeConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_settings_key_provider();
}

pub async fn run_settings_config_value_maintenance(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    settings_config_value_maintenance_protection(
        &pg,
        operator_subject,
        resource_id,
        runtime_inputs.config(),
    ).await;
    Ok(())
}

pub async fn run(mut runtime_inputs: RuntimeInputs) {
    let config = runtime_inputs.config();
    let RuntimeServingConfigParts {
        token_profiles,
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_transport,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    } = RuntimeServingConfig::from_snapshot(config)?
        .into_parts();
    let pg_config = PgRuntimeConfig::from_snapshot(config)?;
    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;
    let s3_config = S3RuntimeConfig::from_snapshot(config)?;
    let PgRuntimeConfigParts {
        serving: serving_config,
        tenant_read: tenant_read_config,
        migrator: migrator_config,
        audit_admin: audit_admin_config,
        dlx_archiver: dlx_archiver_config,
        dlx_verifier: dlx_verifier_config,
        dlx_purger: dlx_purger_config,
        legacy_policy: plaintext_policy,
        readiness_period: pg_readiness_period,
    } = pg_config.into_parts();
    let S3RuntimeConfigParts {
        general: s3_general_config,
        canary: s3_canary_config,
        dlx_archive: s3_dlx_archive_config,
    } = s3_config.into_parts();
    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
    let (vault, settings_key_name) = vault_config.into_runtime()?;
    let redis = build_redis_runtime_deps(redis_config);
    let s3 = build_s3_runtime_deps(s3_general_config);
    wire_domain_transport(domain_transport);
    let wiring_inputs = RuntimeWiringInputs {
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    };
    let RuntimeWiringInputs {
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    } = wiring_inputs;
    modules_gen::wire_domains(&deps, domain_modules);
    wire_session_sweeper(&pg, session_sweep_interval);
    let distributed = wire_distributed(&deps, distributed_worker);
    wire_event_transport(
        &pg,
        distributed,
        subscribers,
        event_transport,
        event_worker,
        audit_consumer_key,
    );
    wire_dlx_lifecycle(dlx_lifecycle, dlx_worker);
    let s3_canary_module = wire_s3_canary(&deps, s3_canary_config)?;
    let module = assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
        s3_canary_module,
        ..assembly_inputs
    });
    PgRuntimeDeps::setup_with_audit_admin_config(
        &migrator_config, &serving_config, &tenant_read_config,
        audit_admin_config.as_ref(), plaintext_policy, generation, inputs,
    );
    let config_value = |name: &str| config.value(name).map(str::to_owned);
    build_dlx_lifecycle_bootstrap_config_from(
        dlx_archiver_config,
        dlx_verifier_config,
        dlx_purger_config,
        s3_dlx_archive_config,
        config_value,
        clock,
    );
}
"#,
        ));
        let canonical_file = syn::parse_file(&canonical)?;
        assert!(
            settings_vault_snapshot_definition_is_exact(&canonical_file),
            "settings maintenance Vault snapshot fixture must be canonical"
        );
        let canonical_findings = runtime_config_snapshot_findings_for_file(&canonical_file);
        assert!(
            canonical_findings.is_empty(),
            "typed Vault/S3 snapshot funnel is the anti-vacuity green: {canonical_findings:?}"
        );

        let qualified = canonical
            .replace(
                "PgRuntimeConfig::from_snapshot",
                "infra::pg::PgRuntimeConfig::from_snapshot",
            )
            .replace(
                "RedisRuntimeConfig::from_snapshot",
                "infra::redis::RedisRuntimeConfig::from_snapshot",
            )
            .replace(
                "VaultRuntimeConfig::from_snapshot",
                "infra::vault::VaultRuntimeConfig::from_snapshot",
            )
            .replace(
                "S3RuntimeConfig::from_snapshot",
                "<infra::s3::S3RuntimeConfig>::from_snapshot",
            )
            .replace(
                "build_redis_runtime_deps(redis_config)",
                "infra::redis::build_redis_runtime_deps(redis_config)",
            )
            .replace(
                "build_s3_runtime_deps(s3_general_config)",
                "infra::s3::build_s3_runtime_deps(s3_general_config)",
            )
            .replace(
                "build_s3_dlx_archive_store(s3_archive, clock)",
                "infra::s3::build_s3_dlx_archive_store(s3_archive, clock)",
            );
        let qualified_file = syn::parse_file(&qualified)?;
        let qualified_findings = runtime_config_snapshot_findings_for_file(&qualified_file);
        assert!(
            qualified_findings.is_empty(),
            "relative module and inherent associated paths must preserve canonical origin: {qualified_findings:?}"
        );

        let serving_mapping = r#"    let RuntimeServingConfigParts {
        token_profiles,
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_transport,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    } = RuntimeServingConfig::from_snapshot(config)?
        .into_parts();
"#;
        let late_serving_mapping = canonical.replace(serving_mapping, "").replace(
            "    let config_value = |name: &str|",
            &format!("{serving_mapping}    let config_value = |name: &str|"),
        );
        for (label, mutated) in [
            (
                "missing serving mapping",
                canonical.replace(serving_mapping, ""),
            ),
            ("serving mapping after migration setup", late_serving_mapping),
            (
                "serving wrong generation",
                canonical.replace(
                    "RuntimeServingConfig::from_snapshot(config)?",
                    "RuntimeServingConfig::from_snapshot(other_inputs.config())?",
                ),
            ),
            (
                "duplicate serving mapping",
                canonical.replace(
                    serving_mapping,
                    &format!(
                        "    let _serving_bait = RuntimeServingConfig::from_snapshot(config)?\n        .into_parts();\n{serving_mapping}"
                    ),
                ),
            ),
            (
                "discarded serving parts",
                canonical.replace(
                    serving_mapping,
                    "    let _serving_parts = RuntimeServingConfig::from_snapshot(config)?\n        .into_parts();\n",
                ),
            ),
            (
                "serving field replaced before transfer",
                canonical.replace(
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport,\n        event_worker,",
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport,\n        event_worker: other_event_worker,",
                ),
            ),
            (
                "serving fields swapped before transfer",
                canonical.replace(
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport,\n        event_worker,\n        dlx_worker,",
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport,\n        event_worker: dlx_worker,\n        dlx_worker: event_worker,",
                ),
            ),
            (
                "serving sink hidden in dead closure",
                canonical.replace(
                    "    wire_session_sweeper(&pg, session_sweep_interval);",
                    "    let _dead = || wire_session_sweeper(&pg, session_sweep_interval);",
                ),
            ),
            (
                "legacy Vault getter revival",
                canonical.replace(
                    "let vault_config = VaultRuntimeConfig::from_snapshot(config)?;",
                    "let vault_config = build_vault_runtime_deps(|name| std::env::var(name).ok())?;",
                ),
            ),
            (
                "legacy S3 getter revival",
                canonical.replace(
                    "let s3_config = S3RuntimeConfig::from_snapshot(config)?;",
                    "let s3_config = build_s3_runtime_deps_from(|name| std::env::var(name).ok())?;",
                ),
            ),
            (
                "Vault wrong generation",
                canonical.replace(
                    "let vault_config = VaultRuntimeConfig::from_snapshot(config)?;",
                    "let vault_config = VaultRuntimeConfig::from_snapshot(other_inputs.config())?;",
                ),
            ),
            (
                "S3 wrong generation",
                canonical.replace(
                    "let s3_config = S3RuntimeConfig::from_snapshot(config)?;",
                    "let s3_config = S3RuntimeConfig::from_snapshot(other_inputs.config())?;",
                ),
            ),
            (
                "duplicate Vault mapping",
                canonical.replace(
                    "let vault_config = VaultRuntimeConfig::from_snapshot(config)?;",
                    "let _vault_bait = VaultRuntimeConfig::from_snapshot(config)?;\n    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;",
                ),
            ),
            (
                "duplicate S3 mapping",
                canonical.replace(
                    "let s3_config = S3RuntimeConfig::from_snapshot(config)?;",
                    "let _s3_bait = S3RuntimeConfig::from_snapshot(config)?;\n    let s3_config = S3RuntimeConfig::from_snapshot(config)?;",
                ),
            ),
            (
                "duplicate Vault consume",
                canonical.replace(
                    "let (vault, settings_key_name) = vault_config.into_runtime()?;",
                    "let _vault_bait = vault_config.into_runtime()?;\n    let (vault, settings_key_name) = vault_config.into_runtime()?;",
                ),
            ),
            (
                "wrong S3 general part",
                canonical.replace(
                    "let s3 = build_s3_runtime_deps(s3_general_config);",
                    "let s3 = build_s3_runtime_deps(other_general_config);",
                ),
            ),
            (
                "wrong S3 DLX part",
                canonical.replace(
                    "        s3_dlx_archive_config,",
                    "        other_s3_dlx_archive_config,",
                ),
            ),
            (
                "wrong S3 canary part",
                canonical.replace(
                    "wire_s3_canary(&deps, s3_canary_config)?",
                    "wire_s3_canary(&deps, other_s3_canary_config)?",
                ),
            ),
            (
                "discarded S3 canary result",
                canonical.replace(
                    "let s3_canary_module = wire_s3_canary(&deps, s3_canary_config)?;",
                    "let _ = wire_s3_canary(&deps, s3_canary_config)?;\n    let s3_canary_module = DomainModuleResult::default();",
                ),
            ),
            (
                "empty S3 canary module",
                canonical.replace(
                    "let s3_canary_module = wire_s3_canary(&deps, s3_canary_config)?;",
                    "let s3_canary_module = DomainModuleResult::default();",
                ),
            ),
            (
                "wrong assembled S3 canary module",
                canonical.replace(
                    "        s3_canary_module,\n        ..assembly_inputs",
                    "        s3_canary_module: other_module,\n        ..assembly_inputs",
                ),
            ),
            (
                "maintenance ambient snapshot wrapper",
                canonical.replace(
                    "let vault_config = match VaultRuntimeConfig::from_snapshot(config) {",
                    "let vault_config = match VaultRuntimeConfig::from_snapshot(snapshot_from_ambient(|| std::env::var(\"RSS_VAULT_TOKEN\"))) {",
                ),
            ),
            (
                "maintenance Vault consume alias",
                canonical.replace(
                    "let _parts = vault_config.into_settings_key_provider();",
                    "let provider_config = vault_config;\n    let _parts = provider_config.into_settings_key_provider();",
                ),
            ),
            (
                "maintenance Vault binding shadow",
                canonical.replace(
                    "let _parts = vault_config.into_settings_key_provider();",
                    "let vault_config = other_vault_config;\n    let _parts = vault_config.into_settings_key_provider();",
                ),
            ),
            (
                "maintenance unrelated consume bait",
                canonical.replace(
                    "let _parts = vault_config.into_settings_key_provider();",
                    "let _bait = other_vault_config.into_settings_key_provider();\n    let _parts = vault_config.into_settings_key_provider();",
                ),
            ),
            (
                "protected import alias",
                format!("{canonical}\nuse infra::vault::VaultRuntimeConfig as HiddenVaultConfig;\n"),
            ),
            (
                "protected local function alias",
                format!(
                    "{canonical}\nfn hidden(config: SnapshotConfig<'_>) {{ let map = VaultRuntimeConfig::from_snapshot; let _ = map(config); }}\n"
                ),
            ),
            (
                "protected macro indirection",
                format!(
                    "{canonical}\nfn hidden(config: SnapshotConfig<'_>) {{ passthrough!(S3RuntimeConfig::from_snapshot(config)); }}\n"
                ),
            ),
            (
                "wrong-origin same-name typed config",
                canonical.replacen(
                    "VaultRuntimeConfig::from_snapshot(config)?",
                    "other::VaultRuntimeConfig::from_snapshot(config)?",
                    1,
                ),
            ),
            (
                "wrong-origin same-name builder",
                canonical.replace(
                    "build_s3_runtime_deps(s3_general_config)",
                    "other::build_s3_runtime_deps(s3_general_config)",
                ),
            ),
        ] {
            let file = syn::parse_file(&mutated)?;
            assert!(
                !runtime_config_snapshot_findings_for_file(&file).is_empty(),
                "typed Vault/S3 snapshot gate must reject {label}"
            );
        }

        Ok(())
    }

    #[test]
    fn runtime_vault_s3_values_seams_and_test_support_wrappers_are_exact() -> Result<()> {
        let vault_internal = r#"
#[cfg(any(test, feature = "integration"))]
pub(crate) fn build_vault_runtime_from_values(
    addr: String,
    token: String,
    transit_mount: String,
    settings_key_name: String,
) -> anyhow::Result<(VaultRuntimeDeps, KeyName)> {
    let config = VaultRuntimeConfig::from_values(VaultConfigValues {
        addr: Some(addr),
        token: Some(token.as_str()),
        transit_mount: Some(transit_mount),
        ca_cert_pem_path: None,
        settings_key_name: Some(settings_key_name.as_str()),
    })?;
    config.into_runtime()
}
"#;
        let s3_internal = r#"
#[cfg(any(test, feature = "integration"))]
pub(crate) fn build_s3_runtime_deps_from_values(
    endpoint_url: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    allow_plaintext: bool,
    force_path_style: bool,
) -> anyhow::Result<S3RuntimeDeps> {
    let config = s3_general_config_from_values(S3GeneralConfigValues {
        endpoint_url: Some(&endpoint_url),
        bucket: Some(&bucket),
        access_key_id: Some(&access_key_id),
        secret_access_key: Some(&secret_access_key),
        session_token: None,
        region: None,
        force_path_style: Some(if force_path_style { "true" } else { "false" }),
        allow_plaintext: Some(if allow_plaintext { "true" } else { "false" }),
    })?;
    build_s3_runtime_deps(config)
}
"#;
        let wrappers = r#"
#[cfg(feature = "integration")]
pub mod test_support {
    pub fn build_vault_runtime_from_values(
        addr: String,
        token: String,
        transit_mount: String,
        settings_key_name: String,
    ) -> anyhow::Result<(vault::VaultRuntimeDeps, diport::KeyName)> {
        crate::infra::vault::build_vault_runtime_from_values(
            addr, token, transit_mount, settings_key_name,
        )
    }

    pub fn build_s3_runtime_deps_from_values(
        endpoint_url: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        allow_plaintext: bool,
        force_path_style: bool,
    ) -> anyhow::Result<s3::S3RuntimeDeps> {
        crate::infra::s3::build_s3_runtime_deps_from_values(
            endpoint_url, bucket, access_key_id, secret_access_key,
            allow_plaintext, force_path_style,
        )
    }
}
"#;

        let internal_is_exact = |source: &str, name: &str| -> Result<bool> {
            let file = syn::parse_file(source)?;
            Ok(file.items.iter().any(|item| {
                matches!(item,
                syn::Item::Fn(function)
                    if function.sig.ident == name
                        && internal_vault_s3_values_seam_is_exact(function))
            }))
        };
        assert!(internal_is_exact(
            vault_internal,
            "build_vault_runtime_from_values"
        )?);
        assert!(internal_is_exact(
            s3_internal,
            "build_s3_runtime_deps_from_values"
        )?);
        assert!(vault_s3_test_support_wrappers_are_exact(&syn::parse_file(
            wrappers
        )?));
        let vault_equivalent = vault_internal
            .replace(
                "let config = VaultRuntimeConfig::from_values",
                "let mapped = VaultRuntimeConfig::from_values",
            )
            .replace("    config.into_runtime()", "    mapped.into_runtime()");
        let s3_equivalent = s3_internal
            .replace(
                "let config = s3_general_config_from_values",
                "let mapped = s3_general_config_from_values",
            )
            .replace(
                "    build_s3_runtime_deps(config)",
                "    build_s3_runtime_deps(mapped)",
            );
        assert!(internal_is_exact(
            &vault_equivalent,
            "build_vault_runtime_from_values"
        )?);
        assert!(internal_is_exact(
            &s3_equivalent,
            "build_s3_runtime_deps_from_values"
        )?);

        for (label, source, name) in [
            (
                "Vault zero args",
                vault_internal.replace(
                    "    addr: String,\n    token: String,\n    transit_mount: String,\n    settings_key_name: String,\n",
                    "",
                ),
                "build_vault_runtime_from_values",
            ),
            (
                "Vault wrong arg type",
                vault_internal.replace("token: String", "token: &str"),
                "build_vault_runtime_from_values",
            ),
            (
                "Vault ambient getter",
                vault_internal.replace(
                    "addr: Some(addr)",
                    "addr: std::env::var(\"RSS_VAULT_ADDR\").ok()",
                ),
                "build_vault_runtime_from_values",
            ),
            (
                "Vault wrong callee",
                vault_internal.replace("VaultRuntimeConfig::from_values", "VaultRuntimeConfig::from_snapshot"),
                "build_vault_runtime_from_values",
            ),
            (
                "Vault extra statement",
                vault_internal.replace(
                    "    config.into_runtime()",
                    "    audit_values();\n    config.into_runtime()",
                ),
                "build_vault_runtime_from_values",
            ),
            (
                "S3 zero args",
                s3_internal.replace(
                    "    endpoint_url: String,\n    bucket: String,\n    access_key_id: String,\n    secret_access_key: String,\n    allow_plaintext: bool,\n    force_path_style: bool,\n",
                    "",
                ),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 wrong arg type",
                s3_internal.replace("force_path_style: bool", "force_path_style: String"),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 ambient getter",
                s3_internal.replace(
                    "endpoint_url: Some(&endpoint_url)",
                    "endpoint_url: std::env::var(\"RSS_S3_ENDPOINT_URL\").ok().as_deref()",
                ),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 wrong callee",
                s3_internal.replace(
                    "s3_general_config_from_values",
                    "s3_general_config_from_snapshot",
                ),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 extra statement",
                s3_internal.replace(
                    "    build_s3_runtime_deps(config)",
                    "    audit_values();\n    build_s3_runtime_deps(config)",
                ),
                "build_s3_runtime_deps_from_values",
            ),
        ] {
            assert!(
                !internal_is_exact(&source, name)?,
                "internal values seam must reject {label}"
            );
        }

        for (label, mutated) in [
            (
                "wrapper zero args",
                wrappers.replace(
                    "            addr, token, transit_mount, settings_key_name,",
                    "",
                ),
            ),
            (
                "wrapper wrong args",
                wrappers.replace(
                    "            endpoint_url, bucket, access_key_id, secret_access_key,",
                    "            endpoint_url, bucket, secret_access_key, access_key_id,",
                ),
            ),
            (
                "wrapper ambient getter",
                wrappers.replace(
                    "            addr, token, transit_mount, settings_key_name,",
                    "            std::env::var(\"RSS_VAULT_ADDR\")?, token, transit_mount, settings_key_name,",
                ),
            ),
            (
                "wrapper wrong callee",
                wrappers.replace(
                    "crate::infra::s3::build_s3_runtime_deps_from_values",
                    "crate::infra::s3::build_s3_runtime_deps",
                ),
            ),
            (
                "wrapper extra statement",
                wrappers.replace(
                    "        crate::infra::vault::build_vault_runtime_from_values(",
                    "        audit_values();\n        crate::infra::vault::build_vault_runtime_from_values(",
                ),
            ),
        ] {
            assert!(
                !vault_s3_test_support_wrappers_are_exact(&syn::parse_file(&mutated)?),
                "public values wrappers must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_config_inventory_rejects_aliases_and_reserves_protected_type_names() -> Result<()> {
        let root = fixture_root("runtime-config-snapshot-alias-resistant")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let runtime_path = root.join(RUNTIME_LIB_PATH);
        let canonical = r#"
mod config {}
mod phase {}
mod infra { pub mod vault {} pub mod redis {} pub mod s3 {} }
use config::{
    RuntimeConfigSnapshot, RuntimeServingConfig, RuntimeServingConfigParts, SnapshotConfig,
};
use phase::{OperatorRuntimeInputs, PreparedRuntimeInputs, ServingRuntimeInputs};
use infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use infra::vault::VaultRuntimeConfig;
use infra::redis::{build_redis_runtime_deps, RedisRuntimeConfig};
use infra::s3::{
    build_s3_dlx_archive_store, build_s3_runtime_deps, S3DlxArchiveConfig,
    S3RuntimeConfig, S3RuntimeConfigParts,
};

pub fn prepare_runtime() -> anyhow::Result<PreparedRuntimeInputs> {
    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot();
    let config = runtime_config.view();
    let filter = config.value("RUST_LOG");
    let trace_export = build_trace_export(config)?;
    Ok(PreparedRuntimeInputs::new(runtime_config, trace_export))
}

async fn build_dlx_lifecycle_bootstrap_config_from(
    archiver: PgConfig,
    verifier: PgConfig,
    purger: PgConfig,
    s3_archive: S3DlxArchiveConfig,
    get: Reader,
    clock: Clock,
) {
    let _archive = build_s3_dlx_archive_store(s3_archive, clock).await;
}

async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    config: SnapshotConfig<'_>,
) {
    let vault_config = match VaultRuntimeConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_settings_key_provider();
}

pub async fn run_settings_config_value_maintenance(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    settings_config_value_maintenance_protection(
        &pg,
        operator_subject,
        resource_id,
        runtime_inputs.config(),
    ).await;
    Ok(())
}

pub async fn run(mut runtime_inputs: ServingRuntimeInputs) {
    let config = runtime_inputs.config();
    let _pg_config = PgRuntimeConfig::from_snapshot(config);
    let redis_config = RedisRuntimeConfig::from_snapshot(config);
    let s3_config = S3RuntimeConfig::from_snapshot(config);
    let S3RuntimeConfigParts {
        general: s3_general_config,
        canary: s3_canary_config,
        dlx_archive: s3_dlx_archive_config,
    } = s3_config.into_parts();
    let vault_config = VaultRuntimeConfig::from_snapshot(config);
    let (vault, settings_key_name) = vault_config.into_runtime();
    let redis = build_redis_runtime_deps(redis_config);
    let s3 = build_s3_runtime_deps(s3_general_config);
    build_dlx_lifecycle_bootstrap_config_from(
        dlx_archiver_config,
        dlx_verifier_config,
        dlx_purger_config,
        s3_dlx_archive_config,
        config_value,
        clock,
    );
}
"#;
        write(&runtime_path, canonical)?;
        assert!(
            runtime_config_global_capture_findings(&root)?.is_empty(),
            "canonical inventory must pass"
        );

        let side_path = root.join(RUNTIME_SRC_PATH).join("alias_sidepath.rs");
        for (label, source) in [
            (
                "renamed use plus local function alias",
                r#"use crate::config::RuntimeConfigSnapshot as Snapshot;
fn hidden() { let take = Snapshot::capture_process_snapshot; let _ = take(); }
"#,
            ),
            (
                "grouped module alias plus type alias and UFCS",
                r#"use crate::{phase as runtime_phase};
type Inputs = runtime_phase::PreparedRuntimeInputs;
fn hidden() { let _ = <Inputs>::new(snapshot(), trace()); }
"#,
            ),
            (
                "provider module aliases and local aliases",
                r#"use crate::infra::{vault as v, redis as r, s3 as object_store};
fn hidden() {
    let vault = v::build_vault_runtime_deps;
    let redis = r::build_redis_runtime_deps;
    let s3 = object_store::build_s3_runtime_deps_from;
    let _ = vault(reader); let _ = redis(reader); let _ = s3(reader);
}
"#,
            ),
            (
                "protected invocation hidden in a macro",
                r#"use crate::config::RuntimeConfigSnapshot as Snapshot;
fn hidden() { passthrough!(Snapshot::capture_process_snapshot()); }
"#,
            ),
        ] {
            write(&side_path, source)?;
            assert!(
                !runtime_config_global_capture_findings(&root)?.is_empty(),
                "global inventory must reject {label}"
            );
        }

        write(
            &side_path,
            r#"
mod local {
    pub struct RuntimeConfigSnapshot;
    impl RuntimeConfigSnapshot { pub fn capture_process_snapshot() {} }
    pub struct PreparedRuntimeInputs;
    impl PreparedRuntimeInputs { pub fn new(_: LocalSnapshot, _: LocalTrace) {} }
    pub fn build_vault_runtime_deps(_: LocalReader) {}
    pub fn build_redis_runtime_deps(_: LocalReader) {}
    pub fn build_s3_runtime_deps_from(_: LocalReader) {}
}
use local::{PreparedRuntimeInputs, RuntimeConfigSnapshot};
use local::{build_vault_runtime_deps, build_redis_runtime_deps, build_s3_runtime_deps_from};
fn harmless() {
    RuntimeConfigSnapshot::capture_process_snapshot();
    PreparedRuntimeInputs::new(LocalSnapshot, LocalTrace);
    build_vault_runtime_deps(LocalReader);
    build_redis_runtime_deps(LocalReader);
    build_s3_runtime_deps_from(LocalReader);
}
"#,
        )?;
        assert!(
            !runtime_config_global_capture_findings(&root)?.is_empty(),
            "production source must reserve protected type/builder names instead of allowing ambiguous local shadows"
        );

        write(
            &side_path,
            "fn capture_process_snapshot() {}\nfn harmless() { capture_process_snapshot(); }\n",
        )?;
        assert!(
            runtime_config_global_capture_findings(&root)?.is_empty(),
            "an unrelated local function with a generic call name must remain a compliant bait"
        );

        write(
            &side_path,
            r#"
mod unrelated { pub fn into_runtime() {} }
use unrelated::into_runtime as launch;
struct LocalRuntime;
impl LocalRuntime { fn into_runtime(&self) {} }
fn harmless(local: &LocalRuntime) { local.into_runtime(); launch(); }
"#,
        )?;
        assert!(
            runtime_config_global_capture_findings(&root)?.is_empty(),
            "unrelated into_runtime methods and import aliases must not be protected Vault facts"
        );
        Ok(())
    }

    #[test]
    fn runtime_config_inventory_follows_the_real_production_module_graph() -> Result<()> {
        let root = fixture_root("runtime-config-snapshot-module-graph")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let runtime_path = root.join(RUNTIME_LIB_PATH);
        let canonical = runtime_lifecycle_snapshot_fixture();
        write(
            &runtime_path,
            &format!("{canonical}\n#[cfg(test)] mod detached_snapshot_tests;\n"),
        )?;
        let detached = root
            .join(RUNTIME_SRC_PATH)
            .join("detached_snapshot_tests.rs");
        write(
            &detached,
            r#"use crate::config::RuntimeConfigSnapshot;
use crate::phase::RuntimeInputs;
fn fixture_only() {
    let snapshot = RuntimeConfigSnapshot::capture_process_snapshot();
    let _ = RuntimeInputs::new(snapshot, trace());
}
"#,
        )?;
        assert!(
            runtime_config_global_capture_findings(&root)?.is_empty(),
            "a detached module reachable only through cfg(test) must be excluded"
        );

        write(
            &runtime_path,
            &format!("{canonical}\nmod detached_snapshot_tests;\n"),
        )?;
        assert!(
            !runtime_config_global_capture_findings(&root)?.is_empty(),
            "removing the parent cfg(test) must expose the second snapshot/input generation"
        );
        Ok(())
    }

    fn runtime_lifecycle_snapshot_fixture() -> String {
        with_password_policy_preload(
            r#"
use config::{
    RuntimeConfigSnapshot, RuntimeServingConfig, RuntimeServingConfigParts, SnapshotConfig,
};
use phase::{OperatorRuntimeInputs, PreparedRuntimeInputs, RuntimeInputs, ServingRuntimeInputs};
use infra::pg::{PgRuntimeConfig, PgRuntimeConfigParts};
use infra::vault::VaultRuntimeConfig;
use infra::redis::{build_redis_runtime_deps, RedisRuntimeConfig};
use infra::s3::{
    build_s3_dlx_archive_store, build_s3_runtime_deps, S3DlxArchiveConfig,
    S3RuntimeConfig, S3RuntimeConfigParts,
};

pub fn prepare_runtime() -> anyhow::Result<RuntimeInputs> {
    let runtime_config = RuntimeConfigSnapshot::capture_process_snapshot();
    let config = runtime_config.view();
    let filter = config.value("RUST_LOG")
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let trace_export = build_trace_export(config)?;
    tracing_subscriber::registry().with(filter).init();
    Ok(RuntimeInputs::new(runtime_config, trace_export))
}

async fn build_dlx_lifecycle_bootstrap_config_from(
    archiver: PgConfig,
    verifier: PgConfig,
    purger: PgConfig,
    s3_archive: S3DlxArchiveConfig,
    get: Reader,
    clock: Clock,
) {
    let _archive = build_s3_dlx_archive_store(s3_archive, clock).await;
}

async fn settings_config_value_maintenance_protection(
    pg: &PgMaintenanceDeps,
    operator_subject: &str,
    resource_id: &str,
    config: SnapshotConfig<'_>,
) {
    let vault_config = match VaultRuntimeConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_settings_key_provider();
}

pub async fn run_settings_config_value_maintenance(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    settings_config_value_maintenance_protection(
        &pg,
        operator_subject,
        resource_id,
        runtime_inputs.config(),
    ).await;
    Ok(())
}

async fn shutdown_prepared_runtime(inputs: &mut PreparedRuntimeInputs) -> anyhow::Result<()> {
    if let Some(exporter) = inputs.take_trace_export() { exporter.shutdown().await?; }
    Ok(())
}

struct RuntimeLifecycleOwner { inputs: ServingRuntimeInputs }
impl RuntimeLifecycleOwner {
    fn new(inputs: ServingRuntimeInputs) -> Self { Self { inputs } }
    async fn run(mut self) -> anyhow::Result<()> {
        let startup_result = run_startup(&mut self.inputs).await;
        self.finish(startup_result).await
    }
    async fn finish(mut self, startup_result: anyhow::Result<()>) -> anyhow::Result<()> {
        let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;
        match (startup_result, cleanup_result) {
            (Ok(()), cleanup_result) => cleanup_result,
            (Err(startup_error), Ok(())) => Err(startup_error),
            (Err(startup_error), Err(cleanup_error)) => {
                tracing::error!(cleanup_error = %cleanup_error, "cleanup failed");
                Err(startup_error)
            }
        }
    }
}

pub async fn run(runtime_inputs: ServingRuntimeInputs) -> anyhow::Result<()> {
    RuntimeLifecycleOwner::new(runtime_inputs).run().await
}

async fn run_startup(runtime_inputs: &mut ServingRuntimeInputs) -> anyhow::Result<()> {
    assemble_authed_routers(runtime_inputs.config());
    launch(runtime_inputs.config());
    let config = runtime_inputs.config();
    let RuntimeServingConfigParts {
        token_profiles,
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_transport,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    } = RuntimeServingConfig::from_snapshot(config)?
        .into_parts();
    let pg_config = PgRuntimeConfig::from_snapshot(config)?;
    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;
    let s3_config = S3RuntimeConfig::from_snapshot(config)?;
    let PgRuntimeConfigParts {
        serving: serving_config,
        tenant_read: tenant_read_config,
        migrator: migrator_config,
        audit_admin: audit_admin_config,
        dlx_archiver: dlx_archiver_config,
        dlx_verifier: dlx_verifier_config,
        dlx_purger: dlx_purger_config,
        legacy_policy: plaintext_policy,
        readiness_period: pg_readiness_period,
    } = pg_config.into_parts();
    let S3RuntimeConfigParts {
        general: s3_general_config,
        canary: s3_canary_config,
        dlx_archive: s3_dlx_archive_config,
    } = s3_config.into_parts();
    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
    let (vault, settings_key_name) = vault_config.into_runtime()?;
    let redis = build_redis_runtime_deps(redis_config);
    let s3 = build_s3_runtime_deps(s3_general_config);
    wire_domain_transport(domain_transport);
    let wiring_inputs = RuntimeWiringInputs {
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    };
    let RuntimeWiringInputs {
        event_transport,
        event_worker,
        dlx_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        session_sweep_interval,
    } = wiring_inputs;
    modules_gen::wire_domains(&deps, domain_modules);
    wire_session_sweeper(&pg, session_sweep_interval);
    let distributed = wire_distributed(&deps, distributed_worker);
    wire_event_transport(
        &pg,
        distributed,
        subscribers,
        event_transport,
        event_worker,
        audit_consumer_key,
    );
    wire_dlx_lifecycle(dlx_lifecycle, dlx_worker);
    let s3_canary_module = wire_s3_canary(&deps, s3_canary_config)?;
    let module = assemble_runtime_module_outputs(RuntimeModuleAssemblyInputs {
        s3_canary_module,
        ..assembly_inputs
    });
    PgRuntimeDeps::setup_with_audit_admin_config(
        &migrator_config,
        &serving_config,
        &tenant_read_config,
        audit_admin_config.as_ref(),
        plaintext_policy,
        generation,
        inputs,
    );
    let config_value = |name: &str| config.value(name).map(str::to_owned);
    build_dlx_lifecycle_bootstrap_config_from(
        dlx_archiver_config,
        dlx_verifier_config,
        dlx_purger_config,
        s3_dlx_archive_config,
        config_value,
        clock,
    );
    Ok(())
}
"#
            .to_owned(),
        )
    }

    #[test]
    fn runtime_lifecycle_owner_rejects_terminal_cleanup_bypasses() -> Result<()> {
        let canonical = runtime_lifecycle_snapshot_fixture();
        let canonical_file = syn::parse_file(&canonical)?;
        let canonical_findings = runtime_config_snapshot_findings_for_file(&canonical_file);
        assert!(
            canonical_findings.is_empty(),
            "outer lifecycle owner plus inner startup is the anti-vacuity green: owner={}, shutdown={}, outer={}, findings={canonical_findings:?}",
            runtime_lifecycle_owner_struct_is_canonical(&canonical_file),
            shutdown_prepared_runtime_is_canonical(&canonical_file),
            production_named_function(&canonical_file, "run")
                .is_some_and(|run| runtime_lifecycle_outer_is_canonical(&canonical_file, run)),
        );
        for (label, mutated) in [
            (
                "outer direct startup return",
                canonical.replace(
                    "RuntimeLifecycleOwner::new(runtime_inputs).run().await",
                    "run_startup(&mut runtime_inputs).await",
                ),
            ),
            (
                "outer wrong owner binding",
                canonical.replace(
                    "RuntimeLifecycleOwner::new(runtime_inputs).run().await",
                    "RuntimeLifecycleOwner::new(other_inputs).run().await",
                ),
            ),
            (
                "owner skips finish",
                canonical.replace(
                    "let startup_result = run_startup(&mut self.inputs).await;\n        self.finish(startup_result).await",
                    "return run_startup(&mut self.inputs).await;",
                ),
            ),
            (
                "finish receives wrong result binding",
                canonical.replace(
                    "self.finish(startup_result).await",
                    "self.finish(other_result).await",
                ),
            ),
            (
                "duplicate terminal cleanup",
                canonical.replace(
                    "let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;",
                    "let _duplicate = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;\n        let cleanup_result = shutdown_prepared_runtime(self.inputs.prepared_mut()).await;",
                ),
            ),
            (
                "pending exporter cleanup is a noop",
                canonical.replace(
                    "if let Some(exporter) = inputs.take_trace_export() { exporter.shutdown().await?; }",
                    "let _ = inputs;",
                ),
            ),
            (
                "pending exporter takes from wrong binding",
                canonical.replace(
                    "inputs.take_trace_export()",
                    "other_inputs.take_trace_export()",
                ),
            ),
            (
                "pending exporter function alias",
                canonical.replace(
                    "if let Some(exporter) = inputs.take_trace_export() { exporter.shutdown().await?; }",
                    "let take = PreparedRuntimeInputs::take_trace_export;\n    if let Some(exporter) = take(inputs) { exporter.shutdown().await?; }",
                ),
            ),
            (
                "inner alias plus direct-call bait",
                canonical.replace(
                    "let startup_result = run_startup(&mut self.inputs).await;",
                    "let startup = run_startup;\n        if false { let _bait = run_startup(&mut self.inputs).await; }\n        let startup_result = startup(&mut self.inputs).await;",
                ),
            ),
            (
                "cleanup error compliant bait without reporting",
                canonical.replace(
                    "tracing::error!(cleanup_error = %cleanup_error, \"cleanup failed\");",
                    "let _compliant_bait = &cleanup_error;",
                ),
            ),
            (
                "finish returns cleanup over primary failure",
                canonical.replace(
                    "(Err(startup_error), Err(cleanup_error)) => {\n                tracing::error!(cleanup_error = %cleanup_error, \"cleanup failed\");\n                Err(startup_error)\n            }",
                    "(Err(_startup_error), Err(cleanup_error)) => Err(cleanup_error)",
                ),
            ),
        ] {
            let file = syn::parse_file(&mutated)?;
            assert!(
                !runtime_config_snapshot_findings_for_file(&file).is_empty(),
                "runtime lifecycle gate must reject {label}"
            );
        }
        Ok(())
    }

    fn canonical_rss_binary_fixture() -> &'static str {
        r#"
enum CommandFamily {
    Serving,
    Operator(OperatorCommand),
}

enum OperatorCommand {
    Postgres,
    Projection,
    AuditLedgerVerify,
    Dlq,
    ReconcileTarget,
    SettingsConfigValueMaintenance,
    RssAccessJwksExport,
}

fn classify_command(args: &[String]) -> anyhow::Result<CommandFamily> {
    if runtime::is_postgres_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Postgres));
    }
    if runtime::is_projection_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Projection));
    }
    if runtime::is_audit_ledger_verify_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::AuditLedgerVerify));
    }
    if runtime::is_dlq_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::Dlq));
    }
    if runtime::is_reconcile_target_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::ReconcileTarget));
    }
    if runtime::is_settings_config_value_maintenance_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::SettingsConfigValueMaintenance));
    }
    if runtime::is_rss_access_jwks_export_command(args) {
        return Ok(CommandFamily::Operator(OperatorCommand::RssAccessJwksExport));
    }
    anyhow::ensure!(args.is_empty(), "unknown rss command: {args:?}");
    Ok(CommandFamily::Serving)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = classify_command(&args)?;
    let CommandFamily::Operator(command) = command else {
        return runtime::run(runtime::prepare_runtime()?).await;
    };
    let runtime_inputs = runtime::prepare_operator_runtime()?;
    let operator_result = match command {
        OperatorCommand::Postgres => runtime::run_postgres_reader_migration_command(&args, &runtime_inputs).await,
        OperatorCommand::Projection => runtime::run_projection_control_command(&args, &runtime_inputs).await,
        OperatorCommand::AuditLedgerVerify => runtime::run_audit_ledger_verify_command(&args, &runtime_inputs).await,
        OperatorCommand::Dlq => runtime::run_dlq_control_command(&args, &runtime_inputs).await,
        OperatorCommand::ReconcileTarget => runtime::run_reconcile_target_command(&args, &runtime_inputs).await,
        OperatorCommand::SettingsConfigValueMaintenance => runtime::run_settings_config_value_maintenance(&args, &runtime_inputs).await,
        OperatorCommand::RssAccessJwksExport => runtime::run_rss_access_jwks_export_command(&args, &runtime_inputs).await,
    };
    runtime::shutdown_operator_runtime(runtime_inputs).await?;
    operator_result
}
"#
    }

    #[test]
    fn runtime_binary_snapshot_wiring_rejects_duplicate_discarded_and_wrong_bindings() -> Result<()>
    {
        let root = fixture_root("runtime-binary-snapshot-wiring")?;
        let server_path = root.join("bins/server/src/main.rs");
        let rss_path = root.join("bins/rss/src/main.rs");
        let canonical_server = r#"#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let runtime_inputs = runtime::prepare_runtime()?;
    runtime::run(runtime_inputs).await
}
"#;
        let canonical_rss = canonical_rss_binary_fixture();
        write(&server_path, canonical_server)?;
        write(&rss_path, canonical_rss)?;
        assert!(runtime_binary_config_findings(&root)?.is_empty());

        for (label, mutated) in [
            (
                "server duplicate prepare",
                canonical_server.replace(
                    "let runtime_inputs = runtime::prepare_runtime()?;",
                    "let _bait = runtime::prepare_runtime()?;\n    let runtime_inputs = runtime::prepare_runtime()?;",
                ),
            ),
            (
                "server discarded prepare through alias",
                canonical_server.replace(
                    "let runtime_inputs = runtime::prepare_runtime()?;",
                    "use runtime::prepare_runtime as prepare;\n    prepare()?;\n    let runtime_inputs = other_inputs();",
                ),
            ),
            (
                "server wrong run binding",
                canonical_server.replace("runtime::run(runtime_inputs)", "runtime::run(other_inputs)"),
            ),
        ] {
            write(&server_path, &mutated)?;
            assert!(
                !runtime_binary_config_findings(&root)?.is_empty(),
                "binary gate must reject {label}"
            );
        }
        write(&server_path, canonical_server)?;

        for (label, mutated) in [
            (
                "rss duplicate prepare through module alias",
                canonical_rss.replace(
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;",
                    "use runtime as rt;\n    let _bait = rt::prepare_operator_runtime()?;\n    let runtime_inputs = runtime::prepare_operator_runtime()?;",
                ),
            ),
            (
                "rss wrong shutdown binding",
                canonical_rss.replace(
                    "runtime::shutdown_operator_runtime(runtime_inputs)",
                    "runtime::shutdown_operator_runtime(other_inputs)",
                ),
            ),
            (
                "rss ambient local alias",
                canonical_rss.replace(
                    "runtime::run(runtime::prepare_runtime()?)",
                    "{ let serving = runtime::run; serving(other_inputs) }",
                ),
            ),
        ] {
            write(&rss_path, &mutated)?;
            assert!(
                !runtime_binary_config_findings(&root)?.is_empty(),
                "binary gate must reject {label}"
            );
        }
        write(&rss_path, canonical_rss)?;
        assert!(runtime_binary_config_findings(&root)?.is_empty());
        Ok(())
    }

    #[test]
    fn runtime_pg_redis_snapshot_wiring() -> Result<()> {
        let canonical = runtime_lifecycle_snapshot_fixture().to_owned();
        let canonical_file = syn::parse_file(&canonical)?;
        assert!(
            runtime_config_snapshot_findings_for_file(&canonical_file).is_empty(),
            "one runtime_inputs.config() view must construct the PG and Redis typed configs; the Redis builder consumes its config by value"
        );

        let renamed = canonical
            .replace(
                "let config = runtime_inputs.config();",
                "let snapshot_view = runtime_inputs.config();",
            )
            .replace("from_snapshot(config)?", "from_snapshot(snapshot_view)?")
            .replace(
                "let config_value = |name: &str| config.value(name).map(str::to_owned);",
                "let read_snapshot = |name: &str| snapshot_view.value(name).map(str::to_owned);",
            )
            .replace(
                "        config_value,\n        clock,",
                "        read_snapshot,\n        clock,",
            );
        assert_ne!(
            renamed, canonical,
            "renamed fixture must change identifiers"
        );
        let renamed_file = syn::parse_file(&renamed)?;
        assert!(
            runtime_config_snapshot_findings_for_file(&renamed_file).is_empty(),
            "equivalent local renames must preserve snapshot provenance"
        );

        for (label, mutated) in [
            (
                "wrong RuntimeInputs generation",
                canonical.replace(
                    "let config = runtime_inputs.config();",
                    "let config = other_runtime_inputs.config();",
                ),
            ),
            (
                "duplicate snapshot view",
                canonical.replace(
                    "let config = runtime_inputs.config();",
                    "let _discarded_config = runtime_inputs.config();\n    let config = runtime_inputs.config();",
                ),
            ),
            (
                "discarded wildcard snapshot view",
                canonical.replace(
                    "let config = runtime_inputs.config();",
                    "let _ = runtime_inputs.config();\n    let config = runtime_inputs.config();",
                ),
            ),
            (
                "discarded bare snapshot view",
                canonical.replace(
                    "let config = runtime_inputs.config();",
                    "runtime_inputs.config();\n    let config = runtime_inputs.config();",
                ),
            ),
            (
                "discarded PG typed mapping",
                canonical.replace(
                    "let pg_config = PgRuntimeConfig::from_snapshot(config)?;",
                    "let _discarded = PgRuntimeConfig::from_snapshot(config)?;\n    let pg_config = build_pg_config()?;",
                ),
            ),
            (
                "duplicate Redis typed mapping",
                canonical.replace(
                    "let redis_config = RedisRuntimeConfig::from_snapshot(config)?;",
                    "let _bait = RedisRuntimeConfig::from_snapshot(config)?;\n    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;",
                ),
            ),
            (
                "borrowed Redis config",
                canonical.replace(
                    "build_redis_runtime_deps(redis_config)",
                    "build_redis_runtime_deps(&redis_config)",
                ),
            ),
            (
                "typed parts do not feed postgres setup",
                canonical.replace("&migrator_config,", "&wrong_migrator_config,"),
            ),
            (
                "discarded typed parts are compliant bait",
                canonical.replace(
                    "} = pg_config.into_parts();",
                    "} = pg_config.into_parts();\n    let _ = (serving_config, tenant_read_config, migrator_config, audit_admin_config, plaintext_policy);",
                )
                .replace("&migrator_config,", "&wrong_migrator_config,"),
            ),
            (
                "ambient std env PG getter",
                canonical.replace(
                    "PgRuntimeConfig::from_snapshot(config)?",
                    "build_pg_config_from(|name| std::env::var(name).ok())?",
                ),
            ),
            (
                "ambient Redis getter beside compliant bait",
                canonical.replace(
                    "let redis_config = RedisRuntimeConfig::from_snapshot(config)?;",
                    "let _compliant_bait = RedisRuntimeConfig::from_snapshot(config)?;\n    let redis_config = build_redis_config_from(|name| std::env::var(name).ok())?;",
                ),
            ),
            (
                "typed config import alias",
                canonical
                    .replace(
                        "use infra::pg::PgRuntimeConfig;",
                        "use infra::pg::PgRuntimeConfig as DatabaseConfig;",
                    )
                    .replace(
                        "PgRuntimeConfig::from_snapshot(config)?",
                        "DatabaseConfig::from_snapshot(config)?",
                    ),
            ),
            (
                "typed mapping wrapper",
                canonical
                    .replace(
                        "PgRuntimeConfig::from_snapshot(config)?",
                        "map_pg(config)?",
                    )
                    .replace(
                        "pub fn prepare_runtime()",
                        "fn map_pg(config: SnapshotConfig<'_>) -> anyhow::Result<PgRuntimeConfig> { PgRuntimeConfig::from_snapshot(config) }\n\npub fn prepare_runtime()",
                    ),
            ),
        ] {
            assert_ne!(mutated, canonical, "synthetic red must mutate {label}");
            let file = syn::parse_file(&mutated)?;
            assert!(
                !runtime_config_snapshot_findings_for_file(&file).is_empty(),
                "PG/Redis snapshot gate must reject {label}"
            );
        }

        let root = fixture_root("runtime-pg-operator-snapshot-wiring")?;
        let rss_path = root.join(RSS_MAIN_PATH);
        let canonical_rss = canonical_rss_binary_fixture();
        write(&rss_path, canonical_rss)?;
        assert!(
            runtime_binary_config_findings(&root)?.is_empty(),
            "six PG operator calls must receive the exact prepared &runtime_inputs binding"
        );
        for operator_call in [
            "run_postgres_reader_migration_command(&args, &runtime_inputs)",
            "run_projection_control_command(&args, &runtime_inputs)",
            "run_audit_ledger_verify_command(&args, &runtime_inputs)",
            "run_dlq_control_command(&args, &runtime_inputs)",
            "run_reconcile_target_command(&args, &runtime_inputs)",
            "run_settings_config_value_maintenance(&args, &runtime_inputs)",
        ] {
            let wrong_inputs = canonical_rss.replace(
                operator_call,
                &operator_call.replace("runtime_inputs", "other_inputs"),
            );
            assert_ne!(wrong_inputs, canonical_rss);
            write(&rss_path, &wrong_inputs)?;
            assert!(
                !runtime_binary_config_findings(&root)?.is_empty(),
                "binary gate must reject wrong RuntimeInputs for {operator_call}"
            );
            let missing_inputs = canonical_rss.replace(
                operator_call,
                &operator_call.replace(", &runtime_inputs", ""),
            );
            assert_ne!(missing_inputs, canonical_rss);
            write(&rss_path, &missing_inputs)?;
            assert!(
                !runtime_binary_config_findings(&root)?.is_empty(),
                "binary gate must reject missing RuntimeInputs for {operator_call}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_pg_redis_snapshot_wiring_rejects_operator_definition_bypasses() -> Result<()> {
        let source = fs::read_to_string(workspace_root()?.join(RUNTIME_LIB_PATH))?;
        let canonical = syn::parse_file(&source)?;
        assert!(
            pg_operator_definitions_are_exact(&canonical),
            "the six production operator definitions are the anti-vacuity green"
        );

        let mutations = [
            (
                "ignored exact parameter",
                source.replacen(
                    "runtime_inputs: &OperatorRuntimeInputs,",
                    "_runtime_inputs: &OperatorRuntimeInputs,",
                    1,
                ),
            ),
            (
                "wrapper reads the wrong binding",
                source.replacen(
                    "config: runtime_inputs.config(),",
                    "config: other_inputs.config(),",
                    1,
                ),
            ),
            (
                "wrapper mints the operator capability from the wrong binding",
                source.replacen(
                    "operator: runtime_inputs.operator_capability(),",
                    "operator: other_inputs.operator_capability(),",
                    1,
                ),
            ),
            (
                "typed runtime reads the wrong snapshot field",
                source.replacen(
                    "build_pg_migrator_config(self.config)?",
                    "build_pg_migrator_config(other.config)?",
                    1,
                ),
            ),
            (
                "direct operator reads the wrong RuntimeInputs",
                source.replacen(
                    "build_pg_migrator_config(runtime_inputs.config())?",
                    "build_pg_migrator_config(other_inputs.config())?",
                    1,
                ),
            ),
            (
                "ambient wrapper beside compliant typed bait",
                source.replacen(
                    "build_pg_migrator_config(runtime_inputs.config())?",
                    "{ let _compliant_bait = build_pg_migrator_config(runtime_inputs.config())?; build_pg_migrator_config_from(|name| std::env::var(name).ok())? }",
                    1,
                ),
            ),
            (
                "discarded compliant builder beside wrong maintenance config",
                source.replacen(
                    "PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(self.config)?)",
                    "{ let _compliant_bait = build_pg_migrator_config(self.config)?; PgRuntimeDeps::connect_maintenance(&wrong_config) }",
                    1,
                ),
            ),
            (
                "mutable config local is reassigned before maintenance sink",
                source.replacen(
                    "PgRuntimeDeps::connect_maintenance(&build_pg_migrator_config(self.config)?)",
                    "{ let mut config = build_pg_migrator_config(self.config)?; config = wrong_config; PgRuntimeDeps::connect_maintenance(&config) }",
                    1,
                ),
            ),
            (
                "audit tuple does not feed audit maintenance sink",
                source.replacen(
                    "PgRuntimeDeps::connect_maintenance_with_audit_admin_config(&migrator_config, config)",
                    "PgRuntimeDeps::connect_maintenance_with_audit_admin_config(&wrong_migrator_config, config)",
                    1,
                ),
            ),
        ];
        for (label, mutated) in mutations {
            assert_ne!(mutated, source, "synthetic red must mutate {label}");
            let file = syn::parse_file(&mutated)?;
            assert!(
                !pg_operator_definitions_are_exact(&file),
                "PG operator definition gate must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_pg_operator_provenance_allows_equivalent_local_structure() -> Result<()> {
        let source = fs::read_to_string(workspace_root()?.join(RUNTIME_LIB_PATH))?;
        let renamed_and_split = source
            .replacen(
                "pub async fn run_projection_control_command(\n    args: &[String],\n    runtime_inputs: &OperatorRuntimeInputs,\n) -> anyhow::Result<()> {\n    let runtime = ProductionProjectionControlRuntime {\n        config: runtime_inputs.config(),\n        operator: runtime_inputs.operator_capability(),\n    };\n    run_projection_control_command_with_runtime(args, &runtime).await\n}",
                "pub async fn run_projection_control_command(\n    command_args: &[String],\n    inputs: &OperatorRuntimeInputs,\n) -> anyhow::Result<()> {\n    let snapshot = inputs.config();\n    let runtime = ProductionProjectionControlRuntime {\n        config: snapshot,\n        operator: inputs.operator_capability(),\n    };\n    let outcome = run_projection_control_command_with_runtime(command_args, &runtime)\n        .await\n        .context(\"run projection operator\");\n    outcome\n}",
                1,
            );
        assert_ne!(
            renamed_and_split, source,
            "green fixture must change structure"
        );
        assert!(
            pg_operator_definitions_are_exact(&syn::parse_file(&renamed_and_split)?),
            "equivalent parameter/local renames, config split, context, and result local must preserve provenance"
        );
        Ok(())
    }

    #[test]
    fn runtime_pg_redis_snapshot_wiring_locks_integration_seam_and_single_pool() -> Result<()> {
        let internal = r#"
#[cfg(any(test, feature = "integration"))]
pub(crate) async fn build_redis_runtime_deps_from_values(
    url: String,
    allow_plaintext: Option<&str>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    build_redis_runtime_deps(config).await.map(|(deps, _)| deps)
}
"#;
        let wrapper = r#"
#[cfg(feature = "integration")]
pub mod test_support {
    pub async fn build_redis_runtime_deps_from_values(
        url: String,
        allow_plaintext: Option<&str>,
    ) -> anyhow::Result<redis::RedisRuntimeDeps> {
        crate::infra::redis::build_redis_runtime_deps_from_values(url, allow_plaintext).await
    }
}
"#;
        let pool = r#"
pub(crate) async fn build_redis_runtime_deps(config: RedisRuntimeConfig) -> anyhow::Result<(redis::RedisRuntimeDeps, Duration)> {
    let pool = deadpool_redis::Config::from_url(raw_url)
        .create_pool(Some(Runtime::Tokio1))
        .context("create redis pool")?;
    verify_redis_pool(&pool).await?;
    Ok((redis::RedisRuntimeDeps::setup(pool), readiness_interval))
}
"#;
        let internal_is_exact = |source: &str| -> Result<bool> {
            let file = syn::parse_file(source)?;
            let functions = file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Fn(function)
                        if function.sig.ident == "build_redis_runtime_deps_from_values" =>
                    {
                        Some(function)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            Ok(functions.len() == 1 && internal_redis_values_seam_is_exact(functions[0]))
        };
        assert!(internal_is_exact(internal)?);
        assert!(redis_test_support_wrapper_is_exact(&syn::parse_file(
            wrapper
        )?));
        assert!(redis_pool_flow_is_exact(&syn::parse_file(pool)?));

        for (label, mutated) in [
            (
                "internal cfg deleted",
                internal.replace("#[cfg(any(test, feature = \"integration\"))]\n", ""),
            ),
            (
                "internal cfg narrowed",
                internal.replace("cfg(any(test, feature = \"integration\"))", "cfg(test)"),
            ),
            (
                "internal visibility widened",
                internal.replace("pub(crate) async fn", "pub async fn"),
            ),
            (
                "internal name bait",
                internal.replace(
                    "build_redis_runtime_deps_from_values",
                    "build_redis_runtime_deps_from_value_bait",
                ),
            ),
        ] {
            assert_ne!(mutated, internal, "synthetic red must mutate {label}");
            assert!(
                !internal_is_exact(&mutated)?,
                "internal integration seam must reject {label}"
            );
        }

        for (label, mutated) in [
            (
                "public wrapper cfg deleted",
                wrapper.replace("#[cfg(feature = \"integration\")]\n", ""),
            ),
            (
                "public wrapper name bait",
                wrapper.replace(
                    "pub async fn build_redis_runtime_deps_from_values",
                    "pub async fn build_redis_runtime_deps_from_value_bait",
                ),
            ),
            (
                "public wrapper replaced by re-export bait",
                wrapper.replace(
                    "pub async fn build_redis_runtime_deps_from_values",
                    "pub use crate::infra::redis::build_redis_runtime_deps_from_values;\n    pub async fn redis_values_bait",
                ),
            ),
        ] {
            assert_ne!(mutated, wrapper, "synthetic red must mutate {label}");
            assert!(
                !redis_test_support_wrapper_is_exact(&syn::parse_file(&mutated)?),
                "public integration wrapper must reject {label}"
            );
        }

        for (label, mutated) in [
            (
                "second startup pool",
                pool.replace(
                    "let pool = deadpool_redis::Config::from_url(raw_url)",
                    "let _second = deadpool_redis::Config::from_url(other_url).create_pool(Some(Runtime::Tokio1))?;\n    let pool = deadpool_redis::Config::from_url(raw_url)",
                ),
            ),
            (
                "verify uses a different pool",
                pool.replace("verify_redis_pool(&pool)", "verify_redis_pool(&other_pool)"),
            ),
            (
                "business deps use a different pool",
                pool.replace("RedisRuntimeDeps::setup(pool)", "RedisRuntimeDeps::setup(other_pool)"),
            ),
            (
                "wrong verify beside compliant bait",
                pool.replace(
                    "verify_redis_pool(&pool).await?;",
                    "verify_redis_pool(&pool).await?;\n    verify_redis_pool(&other_pool).await?;",
                ),
            ),
            (
                "readiness sampler creates a second pool",
                format!(
                    "{pool}\nfn readiness_sampler() {{ deadpool_redis::Config::from_url(other_url).create_pool(Some(Runtime::Tokio1)); }}\n"
                ),
            ),
        ] {
            assert_ne!(mutated, pool, "synthetic red must mutate {label}");
            assert!(
                !redis_pool_flow_is_exact(&syn::parse_file(&mutated)?),
                "Redis single-pool provenance must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_binary_operator_lifecycle_is_proof_aware() -> Result<()> {
        let root = fixture_root("runtime-binary-operator-lifecycle")?;
        let rss_path = root.join(RSS_MAIN_PATH);
        let canonical = canonical_rss_binary_fixture();
        write(&rss_path, canonical)?;
        assert!(
            runtime_binary_config_findings(&root)?.is_empty(),
            "closed classification plus single shutdown must be the anti-vacuity green"
        );

        for (label, mutated) in [
            (
                "unknown command check after acquisition",
                canonical.replace(
                    "let command = classify_command(&args)?;",
                    "let _early = runtime::prepare_operator_runtime()?;\n    let command = classify_command(&args)?;",
                ),
            ),
            (
                "shadow ensure macro",
                canonical.replace("anyhow::ensure!", "fake::ensure!"),
            ),
            (
                "vacuous unknown condition",
                canonical.replace(
                    "args.is_empty(), \"unknown rss command: {args:?}\"",
                    "args.is_empty() || true, \"unknown rss command: {args:?}\"",
                ),
            ),
            (
                "shadow runtime acquisition path",
                canonical.replace(
                    "runtime::prepare_runtime()?",
                    "shadow::runtime::prepare_runtime()?",
                ),
            ),
            (
                "shadow runtime runner path",
                canonical.replace(
                    "runtime::run_projection_control_command(&args, &runtime_inputs).await",
                    "shadow::runtime::run_projection_control_command(&args, &runtime_inputs).await",
                ),
            ),
            (
                "shadow runtime import",
                canonical.replacen(
                    "enum CommandFamily",
                    "use shadow::runtime;\nenum CommandFamily",
                    1,
                ),
            ),
            (
                "synthetic process arguments",
                canonical.replace(
                    "std::env::args().skip(1).collect()",
                    "Vec::new()",
                ),
            ),
            (
                "fallible pre-consumption side path",
                canonical.replace(
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;",
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;\n    preflight()?;",
                ),
            ),
            (
                "ensure pre-consumption side path",
                canonical.replace(
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;",
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;\n    anyhow::ensure!(ready(), \"not ready\");",
                ),
            ),
            (
                "bail pre-consumption side path",
                canonical.replace(
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;",
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;\n    if !ready() { anyhow::bail!(\"not ready\"); }",
                ),
            ),
            (
                "operator arm returns before shared shutdown",
                canonical.replace(
                    "OperatorCommand::Projection => runtime::run_projection_control_command(&args, &runtime_inputs).await,",
                    "OperatorCommand::Projection => return runtime::run_projection_control_command(&args, &runtime_inputs).await,",
                ),
            ),
            (
                "duplicate operator arm is unreachable bait",
                canonical.replace(
                    "OperatorCommand::AuditLedgerVerify => runtime::run_audit_ledger_verify_command(&args, &runtime_inputs).await,",
                    "OperatorCommand::AuditLedgerVerify => runtime::run_audit_ledger_verify_command(&args, &runtime_inputs).await,\n        OperatorCommand::AuditLedgerVerify => command_bait().await,",
                ),
            ),
            (
                "wrong shutdown binding",
                canonical.replace(
                    "runtime::shutdown_operator_runtime(runtime_inputs)",
                    "runtime::shutdown_operator_runtime(other_inputs)",
                ),
            ),
            (
                "runtime macro bait",
                canonical.replace(
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;",
                    "let runtime_inputs = runtime::prepare_operator_runtime()?;\n    passthrough!(runtime::run(other_inputs));",
                ),
            ),
        ] {
            write(&rss_path, &mutated)?;
            assert!(
                !runtime_binary_config_findings(&root)?.is_empty(),
                "proof-aware binary gate must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn snapshot_consumers_reject_reachable_ambient_env_variants() -> Result<()> {
        let root = fixture_root("runtime-snapshot-consumer-ambient")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let runtime_path = root.join(RUNTIME_LIB_PATH);
        let live_runtime = fs::read_to_string(workspace_root()?.join(RUNTIME_LIB_PATH))?;
        let canonical_runtime = format!("{live_runtime}\nmod ambient;\nmod wrapper;\n");
        write(&runtime_path, &canonical_runtime)?;
        let routes_path = root.join(RUNTIME_SRC_PATH).join("routes.rs");
        let ambient_path = root.join(RUNTIME_SRC_PATH).join("ambient.rs");
        let wrapper_path = root.join(RUNTIME_SRC_PATH).join("wrapper.rs");
        write(&ambient_path, "")?;
        write(&wrapper_path, "")?;
        let compliant = r#"
use crate::config::SnapshotConfig;
fn assemble(config: SnapshotConfig<'_>) { let _ = config.value("SAFE"); }
fn unreachable_bait() { let _ = std::env::var("UNREACHABLE"); }
"#;
        write(&routes_path, compliant)?;
        let compliant_findings = runtime_config_snapshot_live_findings(&root)?;
        assert!(
            compliant_findings.is_empty(),
            "an unreachable ambient helper is compliant bait: {compliant_findings:?}"
        );

        for (label, mutation) in [
            ("direct var", "let _ = std::env::var(\"X\");"),
            ("direct var_os", "let _ = std::env::var_os(\"X\");"),
            ("direct vars", "let _ = std::env::vars();"),
            ("direct vars_os", "let _ = std::env::vars_os();"),
            (
                "import alias",
                "use std::env as ambient; let _ = ambient::var(\"X\");",
            ),
            (
                "imported function alias",
                "use std::env::var as read; let _ = read(\"X\");",
            ),
            (
                "local function alias",
                "let read = std::env::var_os; let _ = read(\"X\");",
            ),
            ("reachable local wrapper", "read_ambient();"),
            ("reachable ambient macro", "ambient_read!();"),
            (
                "reachable trait UFCS",
                "<AmbientReader as ReadAmbient>::read();",
            ),
        ] {
            let support = match label {
                "reachable local wrapper" => "fn read_ambient() { let _ = std::env::vars(); }",
                "reachable ambient macro" => {
                    "macro_rules! ambient_read { () => { std::env::vars_os() }; }"
                }
                "reachable trait UFCS" => {
                    "trait ReadAmbient { fn read(); } struct AmbientReader; impl ReadAmbient for AmbientReader { fn read() { let _ = std::env::var(\"X\"); } }"
                }
                _ => "",
            };
            write(
                &routes_path,
                &format!(
                    "use crate::config::SnapshotConfig;\n{support}\nfn assemble(config: SnapshotConfig<'_>) {{ let _ = config.value(\"SAFE\"); {mutation} }}\n"
                ),
            )?;
            assert!(
                !runtime_config_snapshot_live_findings(&root)?.is_empty(),
                "SnapshotConfig consumer guard must reject {label}"
            );
        }

        for (label, ambient, consumer) in [
            (
                "cross-file wrapper",
                "pub fn read_env() { let _ = std::env::var(\"X\"); }",
                "use crate::config::SnapshotConfig; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); crate::ambient::read_env(); }",
            ),
            (
                "cross-file imported function rename",
                "pub fn read_env() { let _ = std::env::var_os(\"X\"); }",
                "use crate::ambient::read_env as read; use crate::config::SnapshotConfig; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); read(); }",
            ),
            (
                "cross-file trait UFCS",
                "pub trait ReadAmbient { fn read(); } pub struct AmbientReader; impl ReadAmbient for AmbientReader { fn read() { let _ = std::env::vars(); } }",
                "use crate::ambient::{AmbientReader, ReadAmbient}; use crate::config::SnapshotConfig; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); <AmbientReader as ReadAmbient>::read(); }",
            ),
            (
                "cross-file macro",
                "macro_rules! ambient_read { () => { std::env::vars_os() }; } pub(crate) use ambient_read;",
                "use crate::ambient::ambient_read; use crate::config::SnapshotConfig; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); ambient_read!(); }",
            ),
        ] {
            write(&ambient_path, ambient)?;
            write(&routes_path, consumer)?;
            assert!(
                !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
                "crate-wide SnapshotConfig consumer guard must reject {label}"
            );
        }

        write(&ambient_path, "")?;
        write(
            &routes_path,
            "use crate::config::SnapshotConfig as Config; fn assemble(config: Config<'_>) { let _ = config.value(\"SAFE\"); let _ = std::env::var(\"X\"); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "SnapshotConfig import alias must remain a consumer seed"
        );

        write(
            &routes_path,
            "use crate::config::SnapshotConfig; type C<'a> = B<'a>; type B<'a> = A<'a>; type A<'a> = SnapshotConfig<'a>; fn assemble(config: C<'_>) { let _ = config.value(\"SAFE\"); let _ = std::env::var(\"X\"); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "three-layer reverse-ordered SnapshotConfig type aliases must reach a fixpoint"
        );

        write(
            &ambient_path,
            "macro_rules! ambient_base { () => { std::env::var(\"X\") }; } pub(crate) use ambient_base;",
        )?;
        write(
            &wrapper_path,
            "use crate::ambient::ambient_base; macro_rules! wrapped { () => { ambient_base!() }; } pub(crate) use wrapped;",
        )?;
        write(
            &routes_path,
            "use crate::config::SnapshotConfig; use crate::wrapper::wrapped; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); wrapped!(); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "two-hop cross-file ambient macro chain must reach a fixpoint"
        );

        write(
            &ambient_path,
            "pub fn read_env() { let _ = std::env::var_os(\"X\"); }",
        )?;
        write(
            &wrapper_path,
            "pub(crate) use crate::ambient::read_env as read; pub(crate) use read as hidden;",
        )?;
        write(
            &routes_path,
            "use crate::config::SnapshotConfig; use crate::wrapper::hidden; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); hidden(); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "two-hop callable re-export alias must conservatively reach the ambient wrapper"
        );

        write(&ambient_path, "pub(crate) use std::env::var as read_env;")?;
        write(
            &wrapper_path,
            "pub(crate) use crate::ambient::read_env as hidden;",
        )?;
        write(
            &routes_path,
            "use crate::config::SnapshotConfig; use crate::wrapper::hidden; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); let _ = hidden(\"X\"); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "direct ambient reader re-export alias must remain an ambient graph seed"
        );

        write(&ambient_path, "pub(crate) use std::env as ambient_env;")?;
        write(&wrapper_path, "")?;
        write(
            &routes_path,
            "use crate::ambient::ambient_env; use crate::config::SnapshotConfig; fn assemble(config: SnapshotConfig<'_>) { let _ = config.value(\"SAFE\"); let _ = ambient_env::var(\"X\"); }",
        )?;
        assert!(
            !runtime_snapshot_consumer_ambient_findings(&root)?.is_empty(),
            "ambient module re-export must seed all governed reader names"
        );
        Ok(())
    }

    #[test]
    fn runtime_tracing_filter_must_flow_from_snapshot_into_the_subscriber() -> Result<()> {
        let canonical = runtime_lifecycle_snapshot_fixture().to_owned();
        let canonical_file = syn::parse_file(&canonical)?;
        assert!(runtime_config_snapshot_findings_for_file(&canonical_file).is_empty());

        let ambient = canonical.replace(
            "let filter = config.value(\"RUST_LOG\")\n        .and_then(|raw| EnvFilter::try_new(raw).ok())\n        .unwrap_or_else(|| EnvFilter::new(\"info\"));",
            "let _compliant_bait = config.value(\"RUST_LOG\")\n        .and_then(|raw| EnvFilter::try_new(raw).ok())\n        .unwrap_or_else(|| EnvFilter::new(\"info\"));\n    let filter = EnvFilter::try_from_default_env()\n        .unwrap_or_else(|_| EnvFilter::new(\"info\"));",
        );
        let ambient_file = syn::parse_file(&ambient)?;
        assert!(
            !runtime_config_snapshot_findings_for_file(&ambient_file).is_empty(),
            "an unused snapshot-derived bait must not hide an ambient subscriber filter"
        );
        Ok(())
    }

    #[test]
    fn runtime_secret_transfer_allowlist_rejects_extra_handoff() -> Result<()> {
        let root = fixture_root("runtime-secret-transfer-allowlist")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        let workspace = workspace_root()?;
        let governed = [
            RUNTIME_LIB_PATH,
            RUNTIME_SECRET_CONFIG_PATH,
            RUNTIME_EVENT_PATH,
            RUNTIME_VAULT_PATH,
            RUNTIME_S3_PATH,
        ];
        let mut canonical = BTreeMap::new();
        for relative in governed {
            let source = fs::read_to_string(workspace.join(relative))?;
            write(&root.join(relative), &source)?;
            canonical.insert(relative, source);
        }
        let canonical_findings = runtime_secret_transfer_live_findings(&root)?;
        assert!(canonical_findings.is_empty(), "{canonical_findings:?}");

        let event = canonical.get(RUNTIME_EVENT_PATH).context("event source")?;
        let vault = canonical.get(RUNTIME_VAULT_PATH).context("vault source")?;
        let secret = canonical
            .get(RUNTIME_SECRET_CONFIG_PATH)
            .context("secret carrier source")?;
        let equivalent_secret = secret.replace(
            "        Ok(Self(secure::SecretText::from_string(value.to_owned())))",
            "        let owned = value.to_owned();\n        Ok(Self(secure::SecretText::from_string(owned)))",
        )
        .replace(
            "        self.0.expose() != other.0.expose()",
            "        let left = self.0.expose();\n        let right = other.0.expose();\n        left != right",
        )
        .replace(
            "        self.0.expose().to_owned()",
            "        let exposed = self.0.expose();\n        exposed.to_owned()",
        )
        .replace(
            "        self.0.into_string()",
            "        { self.0.into_string() }",
        );
        write(&root.join(RUNTIME_SECRET_CONFIG_PATH), &equivalent_secret)?;
        assert!(runtime_secret_transfer_live_findings(&root)?.is_empty());
        write(&root.join(RUNTIME_SECRET_CONFIG_PATH), secret)?;
        for (label, relative, mutated) in [
            (
                "extra move",
                RUNTIME_EVENT_PATH,
                format!("{event}\nfn leak(secret: EnvSecret) {{ secret.transfer_secret_allocation(); }}\n"),
            ),
            (
                "detached String",
                RUNTIME_EVENT_PATH,
                event.replace(
                    "hot_token.transfer_secret_allocation(),",
                    "{ let detached: String = hot_token.transfer_secret_allocation(); detached },",
                ),
            ),
            (
                "wrong receiver",
                RUNTIME_EVENT_PATH,
                event.replacen(
                    "hot_token.transfer_secret_allocation(),",
                    "archive_token.transfer_secret_allocation(),",
                    1,
                ),
            ),
            (
                "direct sensitive snapshot copy",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "let _leak = config.value(VAULT_TOKEN_ENV).map(str::to_owned);\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "literal sensitive snapshot key",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "let _leak = config.value(\"RSS_VAULT_TOKEN\");\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "qualified sensitive snapshot key",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "let _leak = config.value(crate::infra::vault::VAULT_TOKEN_ENV);\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "local sensitive snapshot key alias",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "let token_key = VAULT_TOKEN_ENV;\n        let _leak = config.value(token_key);\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "imported sensitive snapshot key alias",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "use crate::infra::vault::VAULT_TOKEN_ENV as TOKEN_KEY;\n        let _leak = config.value(TOKEN_KEY);\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "macro sensitive snapshot key",
                RUNTIME_VAULT_PATH,
                vault.replace(
                    "Self::from_values(VaultConfigValues {",
                    "passthrough!(config.value(VAULT_TOKEN_ENV));\n        Self::from_values(VaultConfigValues {",
                ),
            ),
            (
                "split macro sensitive snapshot key",
                RUNTIME_VAULT_PATH,
                format!(
                    "macro_rules! read {{ ($cfg:expr, $key:expr) => {{ $cfg.value($key) }} }}\n{}",
                    vault.replace(
                        "Self::from_values(VaultConfigValues {",
                        "let _leak = read!(config, VAULT_TOKEN_ENV);\n        Self::from_values(VaultConfigValues {",
                    )
                ),
            ),
            (
                "function alias",
                RUNTIME_EVENT_PATH,
                format!("{event}\nfn alias() {{ let move_secret = EnvSecret::transfer_secret_allocation; }}\n"),
            ),
            (
                "macro bait",
                RUNTIME_EVENT_PATH,
                format!("{event}\nfn bait() {{ passthrough!(hot_token.transfer_secret_allocation()); }}\n"),
            ),
            (
                "string bait replacing sink",
                RUNTIME_EVENT_PATH,
                event.replacen(
                    "hot_token.transfer_secret_allocation(),",
                    "{ let _bait = \"hot_token.transfer_secret_allocation()\"; String::new() },",
                    1,
                ),
            ),
            (
                "extra raw extractor",
                RUNTIME_SECRET_CONFIG_PATH,
                secret.replace(
                    "    pub(crate) fn transfer_secret_allocation(self) -> String {\n        self.0.into_string()\n    }\n}",
                    "    pub(crate) fn transfer_secret_allocation(self) -> String {\n        self.0.into_string()\n    }\n\n    pub(crate) fn leaked_copy(&self) -> String {\n        self.0.expose().to_owned()\n    }\n}",
                ),
            ),
        ] {
            assert_ne!(
                mutated,
                canonical.get(relative).context("canonical source")?.as_str()
            );
            let path = root.join(relative);
            write(&path, &mutated)?;
            let findings = runtime_secret_transfer_live_findings(&root)?;
            assert!(
                !findings.is_empty(),
                "secret source-to-sink gate must reject {label}"
            );
            match label {
                "wrong receiver" => assert!(findings.iter().any(|finding| {
                    finding.subject == RUNTIME_EVENT_PATH
                        && finding.detail.contains("event.hot")
                        && finding
                            .detail
                            .contains("build_dlx_vault_key_providers_from")
                        && finding.detail.contains("missing/extra")
                })),
                "literal sensitive snapshot key" => assert!(findings.iter().any(|finding| {
                    finding.subject == RUNTIME_VAULT_PATH
                        && finding.detail.contains("VAULT_TOKEN_ENV")
                        && finding.detail.contains("VaultRuntimeConfig::from_snapshot")
                        && finding.detail.contains("missing/extra")
                })),
                "extra raw extractor" => assert!(findings.iter().any(|finding| {
                    finding.subject == RUNTIME_SECRET_CONFIG_PATH
                        && finding.detail.contains("carrier EnvSecret")
                        && finding.detail.contains("missing or has extra")
                })),
                "split macro sensitive snapshot key" => {
                    assert!(findings.iter().any(|finding| {
                        finding.subject == RUNTIME_VAULT_PATH
                            && finding.detail.contains("macro")
                            && finding.detail.contains("VAULT_TOKEN_ENV")
                            && finding.detail.contains("from_snapshot")
                    }))
                }
                _ => {}
            }
            write(&path, canonical.get(relative).context("canonical source")?)?;
        }
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
let pg_result = Self::register_module_output(stack, pg_runtime_module);
let domain_result = Self::register_module_output(stack, domain_module);
pg_result?;
domain_result?;
}
fn register_module_output() {
for worker in workers
for resource in resources
}}
async fn launch_until_observed() {
let listeners = plan.register(&mut stack)?;
bind_and_register(&mut stack, listener, budget, &addr_resolver).await?;
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
                .contains("launch.shutdown.workers | assemblies/runtime/src/launch.rs | for worker in workers | status=out-of-order"),
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
                "impl LaunchPlan {{ fn register() {{\n{}\n}}\nfn register_module_output() {{\n{}\n}}\n}}\nasync fn launch_until_observed() {{\nbind_and_register(&mut stack, listener, budget, &addr_resolver).await?;\nlet listeners = plan.register(&mut stack)?;\n}}\n",
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
                .contains("launch.listeners | assemblies/runtime/src/launch.rs | bind_and_register(&mut stack, listener, budget, &addr_resolver).await?; | status=out-of-order"),
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
                "#[cfg(test)] async fn run_startup() {{ {} }}\nasync fn run_startup() {{}}\n",
                "modules_gen::wire_domains(&deps, domain_modules);",
            ),
        )?;
        let report = collect_report(&root)?;
        assert!(
            report.findings.iter().any(|f| {
                f.rule == Rule::MissingAnchor && f.detail.contains("run.wire.generated-domains")
            }),
            "test-only same-name startup bait must not satisfy runtime wiring baseline"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_ignores_anchor_in_comment_and_string() -> Result<()> {
        let root = fixture_root("runtime-baseline-anchor-comment-string")?;
        write(
            &root.join(RUNTIME_LIB_PATH),
            &format!(
                "async fn run_startup() {{\n{}\n// {}\nlet _ = {:?};\n}}\n",
                run_anchor_lines(Some("run.wire.generated-domains")),
                "modules_gen::wire_domains(&deps, domain_modules);",
                "modules_gen::wire_domains(&deps, domain_modules);"
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
