//! Runtime assembly baseline drift gate.
//!
//! The baseline locks static repository facts that later `runtime::run()` split PRs must preserve:
//! runtime Cargo dependencies, the shared dependency/result structs, and
//! ordered runtime wiring anchors. It intentionally keeps field-inventory drift separate from
//! `SharedRuntimeDeps` infra-only semantics, which are enforced by `runtime-deps-guard`.
//!
//! INVARIANT: RUNTIME-BASELINE-DRIFT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_baseline_drift_fails", anti_vacuity = "tests::runtime_baseline_accepts_fixture" } -- `cargo xtask runtime-baseline verify`
//! compares the generated runtime assembly baseline with the committed `runtime-baseline/runtime.txt`
//! and fails on missing baseline, content drift, an empty dependency inventory, or missing
//! required wiring anchors. Synthetic red/green tests cover every failure class.
//!
//! INVARIANT: RUNTIME-GENERATED-DOMAINS-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_generated_domains_rejects_handwritten_wiring_and_missing_merge", anti_vacuity = "tests::runtime_baseline_accepts_fixture" } -- the runtime phase must consume the committed generated domain list through the plan-owned validator and private `ValidatedDomainBindings` handoff into `compose_bindings`, retain partial bindings on constructor/validation/compose failure, record every output in `ProviderBuild`'s startup transaction, and must not restore per-domain handwritten wiring.
//!
//! INVARIANT: RUNTIME-CONFIG-SNAPSHOT-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_vault_s3_snapshot_wiring + tests::runtime_vault_allowlist_typed_funnel_rejects_bypasses + tests::runtime_jwks_export_requires_snapshot_and_operator_capability", anti_vacuity = "tests::runtime_vault_s3_snapshot_wiring + tests::runtime_vault_allowlist_typed_funnel_rejects_bypasses + tests::runtime_jwks_export_requires_snapshot_and_operator_capability" } -- the unique serving `prepare_runtime()` calls exactly one closed process snapshot factory and seals the password blocklist plus strict build identity into `ServingRuntimeInputs`, while `runtime::operator::prepare_runtime()` produces an exact `OperatorRuntimeInputs` that cannot carry those serving capabilities. `run_startup()` delegates once to the typed phase executor; `ProvidersBuilt::build_infra` maps the serving snapshot view into the exact serving, PG, Redis, Vault, and S3 generations, and `InfraBuilt::wire_domains` consumes the serving aggregate by value as event transport, domain transport, worker, and exact domain-module inputs. Redis and Vault are consumed by value, named S3 parts are destructured once, exact general and DLX parts reach their builders, and canonical PG setup is preserved. The Vault tenant/store allowlist key occurs exactly once in the closed snapshot catalog and flows through the sole typed JSON parser into the private, non-optional `VaultRuntimeConfig::stores` field, then by-value into the sole resolver constructor; the one closed file/stdin validator calls that same parser before operator runtime preparation and cannot read ambient configuration, construct providers, or emit input-derived output. Empty reconstruction, alternate parsers/sources, output leaks, and maintenance reads fail closed. Settings ConfigValue maintenance receives one exact `SnapshotConfig` view and consumes the distinct allowlist-free `VaultKeyProviderConfig` generation. The JWKS operator has one direct production call into a crate-private Vault exporter that requires both the snapshot view and `OperatorRuntimeCapability`, with no getter, HTTP boolean, alias, wrapper, or legacy raw seam. Discarded/wrong generations, ambient getter revival, duplicate mapping or consumption, aliases, wrappers, macros, compliant bait, and serving/operator type mixing all fail closed. Ordered phase-method anchors and the phase snapshot visitor share one syn expander (`expand_inherent_phase_method`) that recursively inlines same-impl private `Self::helper` / `self.helper` calls in call order into a virtual buffer (monotonic virtual offsets): anchors rewrite helper body text with param→arg idents from call remaps, while the visitor remaps tracked bindings arg→param; helper-definition absolute file offsets are never compared in a phase lane, and helper cycles fail closed on both expand and visitor paths. `SnapshotConfig` plus private typed constructors form the native Hard boundary; exact production flow and ambient-reader exclusivity across the conservatively reachable consumer graph remain this explicit Medium AST gate.
//!
//! INVARIANT: RUNTIME-BINARY-SNAPSHOT-LIFECYCLE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_binary_operator_lifecycle_is_proof_aware", anti_vacuity = "tests::runtime_binary_snapshot_wiring_rejects_duplicate_discarded_and_wrong_bindings" } -- `rss` must classify the closed command family from real process arguments before preparation; the Vault allowlist validator returns through its sole file/stdin runner before any runtime preparation, serving uniquely prepares and transfers `ServingRuntimeInputs` to `run`, while stateful operator commands prepare only `OperatorRuntimeInputs`, every stateful operator arm receives that exact binding, and the sole operator shutdown consumes it. No shared input type, pre-consumption early return, validator preparation, alias, macro, shadow path, or unreachable bait is accepted.
//!
//! INVARIANT: SECRET-TEXT-TRANSFER-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff", anti_vacuity = "tests::runtime_secret_transfer_allowlist_rejects_extra_handoff" } -- runtime raw secret allocation transfer/copy uses two uniquely named funnels whose seven moves plus two required copies into zeroizing Vault signer/resolver and S3 owners are exact, closed, and bait-resistant; both funnel definitions are independently pinned by the same allowlist.
//!
//! INVARIANT: RUNTIME-PROVIDER-BIJECTION-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_provider_bijection_gate_rejects_drift_and_bypasses", anti_vacuity = "tests::runtime_provider_bijection_gate_accepts_live_workspace" } -- the generated active catalog must join RuntimePlan exactly once, every closed typed permit must be consumed exactly once into the transactional provider owner, every failure path must roll back, and only a completed provider module may cross into Launch.
//!
//! INVARIANT: EVENT-TRANSPORT-OUTPUT-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::event_transport_output_funnel_rejects_legacy_and_bypasses", anti_vacuity = "tests::event_transport_output_funnel_accepts_unified_live_path" } -- event transport must return one crate-private `DomainModuleResult`, consume the sealed publisher/subscriber receipt batch in `ProviderBuild`, locally roll back partial AMQP connections, and register resources plus workers only through the common lifecycle funnel.
//!
//! INVARIANT: RUNTIME-PHASE-TRANSITION-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_phase_transition_rejects_missing_reordered_drop_plan_and_bait", anti_vacuity = "tests::runtime_phase_transition_accepts_canonical_live_path" } -- the unique production `run_startup()` delegates only to `phase::execute`; that executor consumes the exact five associated-`Next` transitions in order, every transition uses its associated `RuntimePhaseState::PHASE` through the directly redacting private `phase_result` funnel, the runtime plan stays owned by `PhaseContext` while its single listener execution projection is carried as a mandatory phase-state field into Finalize, state trait impls are closed across the complete production module graph, and launch inputs validate before the sole launch phase constructs `LaunchPlan`. Tuple/drop/skip/reorder paths, direct or aliased `LaunchPlan`/`ShutdownStack` access, legacy root phase bodies, cross-file impls, macros, dead branches, comments, strings, and test-only bait fail closed.
//!
//! INVARIANT: RUNTIMEEXEC-LAUNCH-OWNERSHIP-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_launch_kernel_owner_rejects_assembly_executor_and_bait + tests::runtime_launch_kernel_owner_rejects_lifecycle_mutations + tests::runtime_launch_kernel_owner_rejects_semantic_carrier_mutations", anti_vacuity = "tests::runtime_launch_kernel_owner_accepts_workspace" } -- `crates/runtimeexec/src/lib.rs` is the sole launch/signal/drain owner. Its private-field transaction, registrar, activated-inventory, typed provider/domain batch, and launch-plan carriers keep prepare-created resources inside the shutdown owner, require non-empty listener registration before readiness, and preserve provider-before-domain transfer. The runtime launch phase must consume the finalized probe receipt and typed lifecycle batches into exactly one `runtimeexec::LaunchPlan::new` and call exactly one `runtimeexec::launch`; assembly launch owns only adapter prepare/preflight/activation and non-health-before-health ordering. Old assembly LaunchPlan/LaunchPlanParts/RuntimeOutputs aliases, executor wrappers, production ShutdownStack access, parallel calls, macros, dead helpers, comments, and strings fail closed.
//!
//! INVARIANT: RUNTIME-LISTENER-PLAN-EXECUTION-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_listener_plan_execution_rejects_legacy_and_structural_bypasses + tests::runtime_placement_plan_execution_rejects_missing_anchors", anti_vacuity = "tests::runtime_listener_plan_execution_accepts_workspace" } -- across the complete production module graph, AST must expose exactly one RuntimePlan listener projection call, one consuming finalizer and phase call, and one `FinalizedListenerSet` construction expression in their canonical owners with no constructor/trait seam; `ListenerExecutionPlan`, `ListenerExecutionSpec`, `AssembledListener`, and `FinalizedListenerSet` remain exact `pub(crate)` types with inherited-private fields and no public re-export; launch accepts only that set, while raw-value auth assemblers, manual Health append, legacy config auth accessors, public listener/routes modules, and ordinary `Vec<AssembledListener>` launch inputs remain forbidden. PlacementExecutionPlan must mint once and reach outbound transport only through `reject_remote_on_local_listeners` + `from_placement`.
//!
//! INVARIANT: RUNTIME-PLAN-LIVE-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_plan_live_closure_rejects_missing_consumption_and_bait", anti_vacuity = "tests::runtime_plan_live_closure_accepts_workspace" } -- the sole production BuildProvider phase must mint the private, consuming DomainExecutionPlan from RuntimePlan plus PlacementExecutionPlan and carry it linearly through ProvidersBuilt/InfraBuilt. Across the complete production module graph, bootstrap::compose_bindings may appear only as the exact call owned by ValidatedDomainBindings::compose, and crate::modules_gen::wire_domains only as the exact call owned by InfraBuilt::wire_domains; imports, aliases, function-item references, dead helpers, and macro bait fail closed. WireDomains must consume generated bindings through exact validation and the private wrapper, and each generated/validation/composition failure arm must structurally execute failure.into_parts -> drain_binding_outputs -> ProviderBuild::record_domain -> return Err. The runtime-owned test executes the real generated wire -> validate -> compose path and compares typed provider, listener, domain, and placement relations as exact sets; no parallel text inventory exists.
//!
//! INVARIANT: RUNTIME-SERVICE-TOKEN-REPLAY-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_service_token_replay_live_rejects_bait_parallel_paths_and_process_local_guards", anti_vacuity = "tests::runtime_service_token_replay_live_accepts_typed_pg_composition" } -- the only production service-token constructor accepts the closed PostgreSQL replay-owner trait, whose implementation set is exactly `PgRuntimeDeps` plus `PgMaintenanceDeps`. Serving and the five operator paths call that typed constructor directly at their run-reachable sites. Missing calls, extra/dead helpers, macro indirection, test-only evidence, process-local guards, comments, and strings cannot satisfy the inventory.
//!
//! INVARIANT: POSTGRES-SETUP-TRANSACTION-LIVE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::postgres_setup_transaction_rejects_missing_live_edges", anti_vacuity = "tests::postgres_setup_transaction_accepts_live_workspace" } -- the unique production `PgRuntimeDeps::connect_serving` must register each constructed pool immediately, validate only the optional plan-selected projection capture registration, mint the revocation and Saga receipt capability receipts before constructing the reader, roll back writer/reader partial construction on either capability, reader, or audit-admin failure, and commit only after the typed owner holds all serving pools, immutable capture selection, and both receipts. Disabled capture performs no generation validation. The AST gate pins the live statement/branch structure; helper-only tests, comments, strings, and dead bait cannot satisfy it.
//! INVARIANT: WORKFLOW-RUNTIME-PLAN-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::workflow_runtime_plan_funnel_rejects_missing_views_raw_catalog_and_unsupported", anti_vacuity = "tests::workflow_runtime_plan_funnel_accepts_live_workspace" } -- all three assemblies compile one private `WorkflowRuntimePlan` before provider construction. PostgreSQL capture, Projection target/operator/DLQ, Saga worker, and runtime inventory accept only the corresponding borrowed plan view; inventory also rejects an activated-workflow view whose sealed source RuntimePlan fingerprint differs from the inventory RuntimePlan. Production assembly/runtime sources cannot consume raw generated workflow catalogs or revive blanket unsupported state; missing carriers and compliant-looking comments/strings fail closed.
//! INVARIANT: AUDIT-SECURITY-FACT-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::audit_security_fact_boundary_rejects_identity_table_reads", anti_vacuity = "tests::audit_security_fact_boundary_accepts_live_workspace" } -- the transactional audit security-event consumer must decode the generated redacted fact into the audit-owned sealed command and must never query the identity-owned credential-security target mapping relation.
//! INVARIANT: PROJECTION-TARGET-ENROLLMENT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "projection_target_enrollment::tests::production_store_requires_canonical_enrollment + projection_target_enrollment::tests::every_concrete_store_requires_its_own_enrollment + projection_target_enrollment::tests::enrollments_cannot_share_or_evade_concrete_store_edges + projection_target_enrollment::tests::exact_set_is_read_from_testkit_catalog_owner + projection_target_enrollment::tests::enrollment_rejects_wrong_set_unreachable_and_noop + projection_target_enrollment::tests::live_behavior_rejects_dead_branch_and_canned_observation + projection_target_enrollment::tests::enrollment_requires_enabled_tokio_test_runners + projection_target_enrollment::tests::cargo_globs_and_custom_production_targets_remain_scanned + projection_target_enrollment::tests::opaque_external_item_macro_attribute_and_derive_are_rejected + projection_target_enrollment::tests::runtime_funnel_rejects_bypasses + projection_target_enrollment::tests::empty_store_inventory_requires_disabled_projection_activations", anti_vacuity = "projection_target_enrollment::tests::canonical_store_enrollment_is_accepted + projection_target_enrollment::tests::opaque_codegen_in_unrelated_eventexec_consumer_is_not_scanned + projection_target_enrollment::tests::workspace_projection_target_guard_is_green" } -- `runtime-baseline verify` discovers every production `ProjectionTargetStore` implementation from the canonical Cargo target inventory. Every concrete implementation must map one-to-one to an independently selectable `#[tokio::test]` conformance enrollment; the exact ordered case set is read from testkit's `ProjectionCase::ALL` owner rather than duplicated in xtask. Behaviors must carry real wrapper→projector→harness→checkpoint observations; dead/canned evidence is rejected. Only concrete store-owner modules reject non-allowlisted opaque item macros, proc attributes, or custom derives, so unrelated eventexec consumers remain outside this fence. The runtime façade remains sealed to `ConformingProjectionTarget`, raw validated input can only be constructed inside that wrapper, legacy target seams are absent, and an empty production store inventory requires every canonically discovered assembly projection activation to remain disabled.

use crate::assembly_governance::{AssemblyGovernanceIr, Core};
use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::localtx_coverage::attrs_may_be_production;
use crate::phase_helper_expand::{
    PhaseExpandError, binding_remaps_for_call, expand_inherent_phase_method, inherent_entry_method,
    mask_comments_and_strings, private_production_methods, production_inherent_impl,
    self_or_owner_call, self_receiver_helper_call,
};
use crate::workspace_root;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};
use std::fs;
use std::path::{Path, PathBuf};
use syn::parse::Parser as _;
use syn::visit::Visit;

fn attrs_may_be_default_runtime_production(attrs: &[syn::Attribute]) -> bool {
    attrs_may_be_production(attrs)
        && !attrs.iter().any(|attribute| {
            attribute.path().is_ident("cfg")
                && compact_tokens(&attribute.meta).contains("feature=\"integration\"")
        })
}

const BASELINE_PATH: &str = "runtime-baseline/runtime.txt";
const RUNTIME_CARGO_PATH: &str = "assemblies/runtime/Cargo.toml";
const SHARED_RUNTIME_DEPS_PATH: &str = "assemblies/runtime/src/module.rs";
const BOOTSTRAP_MODULE_PATH: &str = "crates/bootstrap/src/module.rs";
const RUNTIME_LIB_PATH: &str = "assemblies/runtime/src/lib.rs";
const RUNTIME_SRC_PATH: &str = "assemblies/runtime/src";
const PROVIDER_OUTPUT_PATH: &str = "assemblies/runtime/src/provider_output.rs";
const GENERATED_PROVIDERS_PATH: &str = "assemblies/runtime/src/generated/providers_gen.rs";
const RUNTIME_CONFIG_FIXTURE_MARKER: &str = ".runtime-config-snapshot-fixture";
const SERVER_MAIN_PATH: &str = "bins/server/src/main.rs";
const RSS_MAIN_PATH: &str = "bins/rss/src/main.rs";
const GENERATED_MODULES_PATH: &str = "assemblies/runtime/src/generated/modules_gen.rs";
const RUNTIME_LAUNCH_PATH: &str = "assemblies/runtime/src/launch.rs";
const RUNTIMEEXEC_PATH: &str = "crates/runtimeexec/src/lib.rs";
const RUNTIME_EVENT_PATH: &str = "assemblies/runtime/src/event_transport.rs";
const RUNTIME_S3_PATH: &str = "assemblies/runtime/src/infra/s3.rs";
const RUNTIME_VAULT_PATH: &str = "assemblies/runtime/src/infra/vault.rs";
const RUNTIME_OIDC_PATH: &str = "assemblies/runtime/src/infra/oidc.rs";
const RUNTIME_PHASE_PATH: &str = "assemblies/runtime/src/phase.rs";
const RUNTIME_PHASE_PROVIDER_PATH: &str = "assemblies/runtime/src/phase/provider.rs";
const RUNTIME_PHASE_INFRA_PATH: &str = "assemblies/runtime/src/phase/infra.rs";
const RUNTIME_PHASE_DOMAIN_TRANSPORT_PATH: &str =
    "assemblies/runtime/src/phase/infra/domain_transport.rs";
const RUNTIME_PHASE_DOMAINS_PATH: &str = "assemblies/runtime/src/phase/domains.rs";
const RUNTIME_PHASE_FINALIZE_PATH: &str = "assemblies/runtime/src/phase/finalize.rs";
const RUNTIME_PHASE_LAUNCH_PATH: &str = "assemblies/runtime/src/phase/launch.rs";
const RUNTIME_SECRET_CONFIG_PATH: &str = "assemblies/runtime/src/secret_config.rs";
const RUNTIME_PLAN_PATH: &str = "assemblies/runtime/src/plan.rs";
const RUNTIME_DOMAIN_EXEC_PATH: &str = "assemblies/runtime/src/plan/domain_exec.rs";
const RUNTIME_PLACEMENT_EXEC_PATH: &str = "assemblies/runtime/src/plan/placement_exec.rs";
const RUNTIME_OPERATOR_PATH: &str = "assemblies/runtime/src/operator/mod.rs";
const RUNTIME_OPERATOR_JWKS_PATH: &str = "assemblies/runtime/src/operator/jwks.rs";
const RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH: &str =
    "assemblies/runtime/src/operator/vault_allowlist.rs";
const RUNTIME_OPERATOR_PROJECTION_PATH: &str = "assemblies/runtime/src/operator/projection.rs";
const RUNTIME_OPERATOR_AUDIT_PATH: &str = "assemblies/runtime/src/operator/audit_ledger.rs";
const RUNTIME_OPERATOR_DLQ_PATH: &str = "assemblies/runtime/src/operator/dlq.rs";
const RUNTIME_OPERATOR_RECONCILE_PATH: &str = "assemblies/runtime/src/operator/reconcile.rs";
const RUNTIME_OPERATOR_SETTINGS_PATH: &str = "assemblies/runtime/src/operator/settings.rs";
const RUNTIME_TEST_SUPPORT_PATH: &str = "assemblies/runtime/src/test_support.rs";
const RUNTIME_PHASE_DLX_PATH: &str = "assemblies/runtime/src/phase/infra/dlx.rs";
const RUNTIME_ROUTES_PATH: &str = "assemblies/runtime/src/routes.rs";
#[cfg(test)]
const RUNTIME_LISTENERS_PATH: &str = "assemblies/runtime/src/listeners.rs";
const RUNTIME_CONFIG_PATH: &str = "assemblies/runtime/src/config.rs";
const POSTGRES_BUNDLE_PATH: &str = "adapters/postgres/src/bundle.rs";
const POSTGRES_MIGRATION_PATH: &str = "adapters/postgres-migration/src/lib.rs";
const POSTGRES_PROJECTION_EVENTS_PATH: &str = "adapters/postgres/src/projection_events.rs";
const POSTGRES_CONSUMER_TX_PATH: &str = "adapters/postgres/src/consumer_tx.rs";
const EVENTEXEC_WORKFLOW_RUNTIME_PATH: &str = "crates/eventexec/src/workflow_runtime.rs";
const RUNTIMEEXEC_INVENTORY_PATH: &str = "crates/runtimeexec/src/inventory.rs";
const IDENTITYAUDIT_PLAN_PATH: &str = "assemblies/identityaudit/src/plan.rs";
const IDENTITYAUDIT_PROVIDERS_PATH: &str = "assemblies/identityaudit/src/providers.rs";
const IDENTITYAUDIT_RUNTIME_PATH: &str = "assemblies/identityaudit/src/runtime.rs";
const SETTINGSONLY_PLAN_PATH: &str = "assemblies/settingsonly/src/plan.rs";
const SETTINGSONLY_PROVIDERS_PATH: &str = "assemblies/settingsonly/src/providers.rs";
const SETTINGSONLY_RUNTIME_PATH: &str = "assemblies/settingsonly/src/runtime.rs";
const RUNTIME_SAGA_PATH: &str = "assemblies/runtime/src/saga_runtime.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingBaseline,
    Drift,
    EmptyDependencies,
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
    let governance = AssemblyGovernanceIr::<Core>::load(root)?;
    let runtime = governance
        .assembly("runtime")
        .context("runtime assembly missing from governance IR")?;
    collect_report_with_projection(root, runtime.manifest().diport_providers().len())
}

fn collect_report_with_projection(root: &Path, provider_count: usize) -> Result<Report> {
    let dependencies = runtime_dependencies(root)?;
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
        match &anchor.status {
            AnchorStatus::Ok => {}
            AnchorStatus::ExpansionFailed(detail) => findings.push(finding(
                Rule::MissingAnchor,
                anchor.path,
                format!(
                    "required runtime wiring anchor `{}` helper expansion failed: {detail}",
                    anchor.id
                ),
            )),
            AnchorStatus::Missing | AnchorStatus::OutOfOrder => findings.push(finding(
                Rule::MissingAnchor,
                anchor.path,
                format!(
                    "required runtime wiring anchor `{}` missing or out of order",
                    anchor.id
                ),
            )),
        }
    }
    findings.extend(runtime_config_snapshot_live_findings(root)?);
    findings.extend(runtime_binary_config_findings(root)?);
    findings.extend(runtime_secret_transfer_live_findings(root)?);
    findings.extend(runtime_phase_transition_findings(root)?);
    findings.extend(runtime_launch_kernel_owner_findings(root)?);
    findings.extend(runtime_service_token_replay_live_findings(root)?);
    findings.extend(postgres_setup_transaction_live_findings(root)?);
    findings.extend(workflow_runtime_plan_funnel_findings(root)?);
    findings.extend(audit_security_fact_boundary_findings(root)?);
    findings.extend(generated_domains_live_findings(root)?);
    findings.extend(provider_outputs_live_findings(root)?);
    findings.extend(event_transport_output_findings(root)?);
    findings.extend(runtime_plan_live_closure_findings(root)?);
    findings.extend(listener_plan_execution_findings(root)?);
    findings.extend(crate::projection_target_enrollment::findings(root)?);

    Ok(Report {
        rendered: render_baseline(&dependencies, &shared_fields, &domain, &anchors),
        dependencies: dependencies.len(),
        providers: provider_count,
        shared_fields: shared_fields.len(),
        domain_fields: domain.fields.len(),
        anchors: anchors.len(),
        findings,
    })
}

fn runtime_plan_live_closure_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join(RUNTIME_PLAN_PATH).exists() {
        return Ok(Vec::new());
    }
    let required = [
        RUNTIME_DOMAIN_EXEC_PATH,
        RUNTIME_PHASE_PATH,
        RUNTIME_PHASE_PROVIDER_PATH,
        RUNTIME_PHASE_DOMAINS_PATH,
    ];
    for path in required {
        if !root.join(path).exists() {
            return Ok(vec![finding(
                Rule::MissingAnchor,
                path,
                "RuntimePlan live closure owner is missing",
            )]);
        }
    }

    let domain_exec = parse_rust_file(&root.join(RUNTIME_DOMAIN_EXEC_PATH))?;
    let phase = parse_rust_file(&root.join(RUNTIME_PHASE_PATH))?;
    let provider = parse_rust_file(&root.join(RUNTIME_PHASE_PROVIDER_PATH))?;
    let domains = parse_rust_file(&root.join(RUNTIME_PHASE_DOMAINS_PATH))?;
    let build_providers =
        unique_production_inherent_method(&provider, "Planned", "build_providers");
    let wire_domains = unique_production_inherent_method(&domains, "InfraBuilt", "wire_domains");
    let validate =
        unique_production_inherent_method(&domain_exec, "DomainExecutionPlan", "validate");
    let compose =
        unique_production_inherent_method(&domain_exec, "ValidatedDomainBindings", "compose");
    let mint = production_functions_named(&domain_exec, "mint");

    let phase_shape = compact_tokens(&phase);
    let provider_shape = build_providers.map(compact_tokens).unwrap_or_default();
    let domains_shape = wire_domains.map(compact_tokens).unwrap_or_default();
    let validate_is_consuming = validate.is_some_and(|method| {
        matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none())
            && compact_tokens(&method.block).contains("bindings.iter().map(DomainBinding::name)")
    });
    let compose_is_consuming = compose.is_some_and(|method| {
        matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none())
            && exact_named_path_call_count(&method.block, &["bootstrap", "compose_bindings"]) == 1
    });
    let capability_shapes_are_closed = ["DomainExecutionPlan", "ValidatedDomainBindings"]
        .into_iter()
        .all(|name| {
            let declarations = domain_exec
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
            declarations.len() == 1
                && is_exact_pub_crate(&declarations[0].vis)
                && declarations[0]
                    .fields
                    .iter()
                    .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        });
    let mint_is_closed = mint.len() == 1
        && matches!(&mint[0].vis, syn::Visibility::Restricted(restricted)
            if restricted.path.is_ident("super"))
        && method_call_count_in_block(&mint[0].block, "domain_plans") == 1
        && method_call_count_in_block(&mint[0].block, "is_local") == 1;

    let production_files = runtime_production_source_files(root)?;
    let mut calls = RuntimePlanClosureCalls::default();
    let mut exclusive_calls = RuntimePlanExclusiveCallInventory::default();
    for file in production_files.values() {
        calls.visit_file(file);
        exclusive_calls.visit_file(file);
    }

    let mut findings = Vec::new();
    let wire_validate_calls = wire_domains
        .map(|method| method_call_count_in_block(&method.block, "validate"))
        .unwrap_or_default();
    let wire_compose_calls = wire_domains
        .map(|method| method_call_count_in_block(&method.block, "compose"))
        .unwrap_or_default();
    let wire_direct_compose_calls = wire_domains
        .map(|method| {
            exact_named_path_call_count(&method.block, &["bootstrap", "compose_bindings"])
        })
        .unwrap_or_default();
    let failure_proof = wire_domains
        .map(|method| wire_domain_failure_proof(&method.block))
        .unwrap_or_default();
    let checks = [
        (
            capability_shapes_are_closed && validate_is_consuming && compose_is_consuming,
            RUNTIME_DOMAIN_EXEC_PATH,
            "DomainExecutionPlan/ValidatedDomainBindings must remain private-field, consuming capabilities and the latter must own the sole canonical compose handoff",
        ),
        (
            mint_is_closed,
            RUNTIME_DOMAIN_EXEC_PATH,
            "only the plan module may mint DomainExecutionPlan from domain declarations and PlacementExecutionPlan local projection",
        ),
        (
            compose_is_consuming
                && exclusive_calls.compose_bindings.is_exact_single_call()
                && compose.is_some_and(|method| {
                    exact_named_path_call_count(
                        &method.block,
                        &["bootstrap", "compose_bindings"],
                    ) == 1
                }),
            RUNTIME_DOMAIN_EXEC_PATH,
            "the complete production graph must contain exactly one bootstrap::compose_bindings function reference/call, owned by consuming ValidatedDomainBindings::compose, with no import, alias, dead helper, or macro seam",
        ),
        (
            exclusive_calls.generated_wire_domains.is_exact_single_call()
                && wire_domains.is_some_and(|method| {
                    exact_named_path_call_count(
                        &method.block,
                        &["crate", "modules_gen", "wire_domains"],
                    ) == 1
                }),
            RUNTIME_PHASE_DOMAINS_PATH,
            "the complete production graph must contain exactly one crate::modules_gen::wire_domains function reference/call, owned by InfraBuilt::wire_domains, with no import, alias, dead helper, or macro seam",
        ),
        (
            calls.domain_execution_plan == 1
                && calls.listener_execution_plan == 1
                && calls.placement_execution_plan == 1,
            RUNTIME_PHASE_PROVIDER_PATH,
            "the production module graph must contain exactly one domain/listener/placement RuntimePlan execution projection",
        ),
        (
            build_providers.is_some()
                && provider_shape.contains(
                    "runtime_plan.domain_execution_plan(&placement_execution_plan)",
                )
                && provider_shape.contains("DomainPhaseContext::new(self.runtime_inputs,runtime_plan,domain_execution_plan)"),
            RUNTIME_PHASE_PROVIDER_PATH,
            "BuildProvider must mint and linearly seal DomainExecutionPlan into DomainPhaseContext",
        ),
        (
            phase_shape.contains("structDomainPhaseContext<'a>")
                && phase_shape.contains("domain_execution_plan:crate::plan::DomainExecutionPlan")
                && phase_shape.contains("pub(crate)structProvidersBuilt<'a>{context:DomainPhaseContext<'a>")
                && phase_shape.contains("pub(crate)structInfraBuilt<'a>{context:DomainPhaseContext<'a>"),
            RUNTIME_PHASE_PATH,
            "ProvidersBuilt and InfraBuilt must carry the mandatory domain execution capability",
        ),
        (
            wire_domains.is_some()
                && wire_validate_calls == 1
                && wire_compose_calls == 1
                && wire_direct_compose_calls == 0
                && domains_shape.contains("domain_execution_plan.validate(domain_bindings)")
                && domains_shape.contains("validated_domain_bindings.compose()")
                && failure_proof.is_exact(),
            RUNTIME_PHASE_DOMAINS_PATH,
            "WireDomains must validate once, compose only the private wrapper, and structurally preserve generated/validation/composition failure bindings through into_parts -> drain_binding_outputs -> record_domain -> return Err",
        ),
        (
            calls.public_domain_capability_reexports == 0,
            RUNTIME_SRC_PATH,
            "domain execution capabilities must not have a public re-export",
        ),
    ];
    for (accepted, path, detail) in checks {
        if !accepted {
            findings.push(finding(Rule::ForbiddenWiring, path, detail));
        }
    }
    Ok(findings)
}

#[derive(Default)]
struct ExclusiveFunctionUse {
    expression_references: usize,
    exact_calls: usize,
    imports: usize,
    macro_mentions: usize,
}

impl ExclusiveFunctionUse {
    fn is_exact_single_call(&self) -> bool {
        self.expression_references == 1
            && self.exact_calls == 1
            && self.imports == 0
            && self.macro_mentions == 0
    }
}

#[derive(Default)]
struct RuntimePlanExclusiveCallInventory {
    compose_bindings: ExclusiveFunctionUse,
    generated_wire_domains: ExclusiveFunctionUse,
}

impl RuntimePlanExclusiveCallInventory {
    fn record_expr_path(&mut self, path: &syn::Path) {
        match path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        {
            Some(name) if name == "compose_bindings" => {
                self.compose_bindings.expression_references += 1;
            }
            Some(name) if name == "wire_domains" => {
                self.generated_wire_domains.expression_references += 1;
            }
            _ => {}
        }
    }

    fn record_use(&mut self, tree: &syn::UseTree) {
        let tokens = compact_tokens(tree);
        self.compose_bindings.imports += usize::from(tokens.contains("compose_bindings"));
        self.generated_wire_domains.imports += usize::from(tokens.contains("wire_domains"));
    }

    fn record_macro(&mut self, mac: &syn::Macro) {
        fn contains_ident(tokens: proc_macro2::TokenStream, expected: &str) -> bool {
            tokens.into_iter().any(|token| match token {
                proc_macro2::TokenTree::Ident(ident) => ident == expected,
                proc_macro2::TokenTree::Group(group) => contains_ident(group.stream(), expected),
                _ => false,
            })
        }
        self.compose_bindings.macro_mentions +=
            usize::from(contains_ident(mac.tokens.clone(), "compose_bindings"));
        self.generated_wire_domains.macro_mentions +=
            usize::from(contains_ident(mac.tokens.clone(), "wire_domains"));
    }
}

impl<'ast> Visit<'ast> for RuntimePlanExclusiveCallInventory {
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

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.compose_bindings.exact_calls += usize::from(is_exact_path(
            &call.func,
            &["bootstrap", "compose_bindings"],
        ));
        self.generated_wire_domains.exact_calls += usize::from(is_exact_path(
            &call.func,
            &["crate", "modules_gen", "wire_domains"],
        ));
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.record_expr_path(&path.path);
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if attrs_may_be_production(&item.attrs) {
            self.record_use(&item.tree);
        }
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if attrs_may_be_production(&item.attrs) {
            self.record_macro(&item.mac);
        }
    }

    fn visit_expr_macro(&mut self, item: &'ast syn::ExprMacro) {
        if attrs_may_be_production(&item.attrs) {
            self.record_macro(&item.mac);
        }
    }

    fn visit_stmt_macro(&mut self, item: &'ast syn::StmtMacro) {
        if attrs_may_be_production(&item.attrs) {
            self.record_macro(&item.mac);
        }
    }
}

#[derive(Default)]
struct WireDomainFailureProof {
    generated_matches: usize,
    generated_rollbacks: usize,
    validation_matches: usize,
    validation_rollbacks: usize,
    composition_matches: usize,
    composition_rollbacks: usize,
}

impl WireDomainFailureProof {
    fn is_exact(&self) -> bool {
        self.generated_matches == 1
            && self.generated_rollbacks == 1
            && self.validation_matches == 1
            && self.validation_rollbacks == 1
            && self.composition_matches == 1
            && self.composition_rollbacks == 1
    }
}

fn wire_domain_failure_proof(block: &syn::Block) -> WireDomainFailureProof {
    struct Visitor {
        proof: WireDomainFailureProof,
    }
    impl Visit<'_> for Visitor {
        fn visit_expr_match(&mut self, match_: &syn::ExprMatch) {
            let rollback = match_
                .arms
                .iter()
                .find(|arm| pat_is_single_tuple_variant(&arm.pat, "Err", "failure"))
                .is_some_and(|arm| domain_failure_arm_is_exact(&arm.body));
            if generated_domain_match_scrutinee(&match_.expr) {
                self.proof.generated_matches += 1;
                self.proof.generated_rollbacks += usize::from(rollback);
            } else if method_match_scrutinee(
                &match_.expr,
                "domain_execution_plan",
                "validate",
                Some("domain_bindings"),
            ) {
                self.proof.validation_matches += 1;
                self.proof.validation_rollbacks += usize::from(rollback);
            } else if method_match_scrutinee(
                &match_.expr,
                "validated_domain_bindings",
                "compose",
                None,
            ) {
                self.proof.composition_matches += 1;
                self.proof.composition_rollbacks += usize::from(rollback);
            }
            syn::visit::visit_expr_match(self, match_);
        }
    }
    let mut visitor = Visitor {
        proof: WireDomainFailureProof::default(),
    };
    visitor.visit_block(block);
    visitor.proof
}

fn generated_domain_match_scrutinee(expr: &syn::Expr) -> bool {
    let syn::Expr::Await(await_) = transparent_expr(expr) else {
        return false;
    };
    let syn::Expr::Call(call) = transparent_expr(&await_.base) else {
        return false;
    };
    is_exact_path(&call.func, &["crate", "modules_gen", "wire_domains"])
}

fn method_match_scrutinee(
    expr: &syn::Expr,
    receiver: &str,
    method: &str,
    argument: Option<&str>,
) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == method
        && expr_is_ident(&call.receiver, receiver)
        && match argument {
            Some(argument) => {
                call.args.len() == 1
                    && call
                        .args
                        .first()
                        .is_some_and(|arg| expr_is_ident(arg, argument))
            }
            None => call.args.is_empty(),
        }
}

fn pat_is_single_tuple_variant(pat: &syn::Pat, variant: &str, binding: &str) -> bool {
    let syn::Pat::TupleStruct(tuple) = pat else {
        return false;
    };
    is_exact_syn_path(&tuple.path, &[variant])
        && tuple.elems.len() == 1
        && tuple
            .elems
            .first()
            .and_then(pat_ident)
            .is_some_and(|ident| ident == binding)
}

fn domain_failure_arm_is_exact(expr: &syn::Expr) -> bool {
    let syn::Expr::Block(block) = transparent_expr(expr) else {
        return false;
    };
    let [syn::Stmt::Local(parts), record, returned] = block.block.stmts.as_slice() else {
        return false;
    };
    failure_parts_local_is_exact(parts)
        && stmt_expr(record).is_some_and(record_failed_domain_bindings_is_exact)
        && stmt_expr(returned).is_some_and(return_failed_domain_source_is_exact)
}

fn failure_parts_local_is_exact(local: &syn::Local) -> bool {
    let syn::Pat::Tuple(tuple) = &local.pat else {
        return false;
    };
    let Some(source) = tuple.elems.first().and_then(pat_ident) else {
        return false;
    };
    let Some(syn::Pat::Ident(bindings)) = tuple.elems.iter().nth(1) else {
        return false;
    };
    let Some(init) = &local.init else {
        return false;
    };
    let syn::Expr::MethodCall(call) = transparent_expr(&init.expr) else {
        return false;
    };
    tuple.elems.len() == 2
        && source == "source"
        && bindings.ident == "bindings"
        && bindings.by_ref.is_none()
        && bindings.mutability.is_some()
        && call.method == "into_parts"
        && call.args.is_empty()
        && expr_is_ident(&call.receiver, "failure")
        && init.diverge.is_none()
}

fn record_failed_domain_bindings_is_exact(expr: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(record) = transparent_expr(expr) else {
        return false;
    };
    let Some(argument) = record.args.first() else {
        return false;
    };
    let syn::Expr::Call(drain) = transparent_expr(argument) else {
        return false;
    };
    let Some(syn::Expr::Reference(bindings)) = drain.args.first().map(transparent_expr) else {
        return false;
    };
    record.method == "record_domain"
        && record.args.len() == 1
        && expr_is_ident(&record.receiver, "provider_build")
        && is_exact_path(&drain.func, &["bootstrap", "drain_binding_outputs"])
        && drain.args.len() == 1
        && bindings.mutability.is_some()
        && expr_is_ident(&bindings.expr, "bindings")
}

fn return_failed_domain_source_is_exact(expr: &syn::Expr) -> bool {
    let syn::Expr::Return(return_) = transparent_expr(expr) else {
        return false;
    };
    let Some(returned) = &return_.expr else {
        return false;
    };
    let syn::Expr::MethodCall(context) = transparent_expr(returned) else {
        return false;
    };
    let syn::Expr::Call(error) = transparent_expr(&context.receiver) else {
        return false;
    };
    context.method == "context"
        && context.args.len() == 1
        && context
            .args
            .first()
            .is_some_and(|argument| matches!(transparent_expr(argument), syn::Expr::Lit(lit) if matches!(lit.lit, syn::Lit::Str(_))))
        && is_exact_path(&error.func, &["Err"])
        && error.args.len() == 1
        && error
            .args
            .first()
            .is_some_and(|argument| expr_is_ident(argument, "source"))
}

fn stmt_expr(stmt: &syn::Stmt) -> Option<&syn::Expr> {
    match stmt {
        syn::Stmt::Expr(expr, _) => Some(expr),
        _ => None,
    }
}

fn expr_is_ident(expr: &syn::Expr, expected: &str) -> bool {
    let syn::Expr::Path(path) = transparent_expr(expr) else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == expected)
}

#[derive(Default)]
struct RuntimePlanClosureCalls {
    domain_execution_plan: usize,
    listener_execution_plan: usize,
    placement_execution_plan: usize,
    public_domain_capability_reexports: usize,
}

impl<'ast> Visit<'ast> for RuntimePlanClosureCalls {
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

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        match call.method.to_string().as_str() {
            "domain_execution_plan" => self.domain_execution_plan += 1,
            "listener_execution_plan" => self.listener_execution_plan += 1,
            "placement_execution_plan" => self.placement_execution_plan += 1,
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !attrs_may_be_production(&item.attrs) || !matches!(item.vis, syn::Visibility::Public(_))
        {
            return;
        }
        let tokens = compact_tokens(&item.tree);
        self.public_domain_capability_reexports += usize::from(
            tokens.contains("DomainExecutionPlan") || tokens.contains("ValidatedDomainBindings"),
        );
    }

    fn visit_macro(&mut self, _item: &'ast syn::Macro) {
        // Macro tokens are deliberately never accepted as live closure evidence.
    }
}

/// Focused live launch/listener evidence shared with the assembly artifact inventory.
pub(crate) fn artifact_launch_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = runtime_launch_kernel_owner_findings(root)?;
    findings.extend(listener_plan_execution_findings(root)?);
    Ok(findings)
}

fn listener_plan_execution_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    // Historical unit fixtures exercise unrelated baseline rules and intentionally do not model
    // the listener-plan source graph. A real runtime tree always contains plan.rs.
    if !root.join(RUNTIME_PLAN_PATH).exists() {
        return Ok(Vec::new());
    }
    let production_files = runtime_production_source_files(root)?;
    let sources = production_files
        .keys()
        .map(|path| {
            fs::read_to_string(root.join(path))
                .with_context(|| format!("读 listener-plan gate source {path} 失败"))
                .map(|source| (path.clone(), source))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let source = |path: &str| sources.get(path).map(String::as_str).unwrap_or_default();
    let plan = source(RUNTIME_PLAN_PATH);
    let placement_exec = source(RUNTIME_PLACEMENT_EXEC_PATH);
    let routes = source(RUNTIME_ROUTES_PATH);
    let finalize = source(RUNTIME_PHASE_FINALIZE_PATH);
    let phase = source(RUNTIME_PHASE_PATH);
    let launch = source(RUNTIME_LAUNCH_PATH);
    let lib = source(RUNTIME_LIB_PATH);
    let provider = source(RUNTIME_PHASE_PROVIDER_PATH);
    let infra = source(RUNTIME_PHASE_INFRA_PATH);
    let domain_transport = source(RUNTIME_PHASE_DOMAIN_TRANSPORT_PATH);
    let inventories = production_files
        .iter()
        .map(|(path, file)| (path.clone(), listener_plan_execution_inventory(file)))
        .collect::<BTreeMap<_, _>>();
    let total_inventory = inventories.values().fold(
        ListenerPlanExecutionInventory::default(),
        |mut total, inventory| {
            total.absorb(inventory);
            total
        },
    );
    let inventory_count = |path: &str, field: fn(&ListenerPlanExecutionInventory) -> usize| {
        inventories.get(path).map(field).unwrap_or_default()
    };

    let mut findings = Vec::new();
    let checks = [
        (
            plan.matches("fn listener_execution_plan(&self)").count() == 1
                && plan.contains("pub(crate) struct ListenerExecutionPlan")
                && plan.contains("pub(crate) struct ListenerExecutionSpec")
                && plan.contains("RUNTIME-LISTENER-PLAN-EXECUTION-01"),
            RUNTIME_PLAN_PATH,
            "RuntimePlan 必须唯一 mint 私有 listener execution capability",
        ),
        (
            routes
                .matches("pub(crate) fn finalize_listener_plan(")
                .count()
                == 1
                && routes.contains("execution_plan.into_listeners()")
                && routes.contains("pub(crate) struct FinalizedListenerSet")
                && routes.contains("providers.validate_exact_presence(&execution_plan)"),
            RUNTIME_ROUTES_PATH,
            "必须只有一个消费 ListenerExecutionPlan 的 finalizer，并产出 FinalizedListenerSet",
        ),
        (
            total_inventory.projection_calls == 1
                && inventory_count(RUNTIME_PHASE_PROVIDER_PATH, |item| item.projection_calls) == 1
                && total_inventory.set_returning_functions == 1
                && total_inventory.canonical_finalizers == 1
                && total_inventory.finalizer_calls == 1
                && total_inventory.canonical_finalizer_calls == 1
                && inventory_count(RUNTIME_PHASE_FINALIZE_PATH, |item| item.finalizer_calls) == 1
                && inventory_count(RUNTIME_PHASE_FINALIZE_PATH, |item| {
                    item.canonical_finalizer_calls
                }) == 1
                && total_inventory.finalizer_input_structs == 1
                && total_inventory.canonical_finalizer_input_structs == 1
                && inventory_count(RUNTIME_ROUTES_PATH, |item| {
                    item.canonical_finalizer_input_structs
                }) == 1
                && total_inventory.set_literals == 1
                && inventory_count(RUNTIME_ROUTES_PATH, |item| item.set_literals) == 1
                && total_inventory.set_constructor_methods == 0
                && total_inventory.set_trait_impls == 0,
            RUNTIME_ROUTES_PATH,
            "production AST 必须精确锁定唯一 plan projection、单 finalizer/call/set literal，且无额外 constructor/From seam",
        ),
        (
            finalize.contains("listener_execution_plan,")
                && finalize.contains("let finalized_listeners = finalize_listener_plan(")
                && finalize.contains("let (listeners, probe_receipt, health_reporter) = finalized_listeners.into_parts();")
                && finalize.contains("Ok(((listeners, probe_receipt), inventory_publisher))")
                && finalize.contains("listeners,")
                && finalize.contains("probe_receipt,")
                && finalize.contains("inventory_publisher,"),
            RUNTIME_PHASE_FINALIZE_PATH,
            "Finalize phase 必须消费 plan capability 后调用唯一 listener finalizer",
        ),
        (
            phase.contains("listeners: crate::routes::FinalizedListenerSet")
                && !phase.contains("listeners: Vec<crate::routes::AssembledListener>"),
            RUNTIME_PHASE_PATH,
            "Finalized phase state 只能持有 FinalizedListenerSet",
        ),
        (
            launch
                .matches("listeners: routes::FinalizedListenerSet")
                .count()
                == 2
                && !launch.contains("\n    listeners: Vec<routes::AssembledListener>"),
            RUNTIME_LAUNCH_PATH,
            "RuntimeLaunchAdapter 必须唯一持有并消费 FinalizedListenerSet",
        ),
        (
            lib.contains("\nmod listeners;")
                && lib.contains("\nmod routes;")
                && !lib.contains("\npub mod listeners;")
                && !lib.contains("\npub mod routes;"),
            RUNTIME_LIB_PATH,
            "listeners/routes 必须保持 crate-private",
        ),
        (
            plan.matches("fn placement_execution_plan(").count() == 1
                && placement_exec.contains("RUNTIME-PLACEMENT-PLAN-EXECUTION-01")
                && placement_exec
                    .matches("fn reject_remote_on_local_listeners(")
                    .count()
                    == 1
                && provider.contains("runtime_plan.placement_execution_plan(")
                && provider.contains("reject_remote_on_local_listeners(")
                && domain_transport.matches("fn from_placement(").count() == 1
                && infra.contains("DomainTransportConfig::from_placement("),
            RUNTIME_PLACEMENT_EXEC_PATH,
            "RuntimePlan 必须唯一 mint PlacementExecutionPlan，并经 reject_remote_on_local_listeners + from_placement 进入 outbound transport",
        ),
    ];
    for (ok, path, detail) in checks {
        if !ok {
            findings.push(finding(Rule::ForbiddenWiring, path, detail));
        }
    }
    findings.extend(listener_capability_visibility_findings(&production_files));

    for (path, source) in &sources {
        for forbidden in [
            "assemble_authed_routers_from_values",
            "assemble_authed_routers_with_bindings",
            "health_listener(reporter, metrics_exporter)",
            "health_auth_scheme",
            "pub(crate) const fn admin(&self)",
            "pub(crate) const fn internal(&self)",
            "AssembledListener::plain",
            "pub fn health_listener",
        ] {
            if !source.contains(forbidden) {
                continue;
            }
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!("listener plan production path 禁止 legacy bypass `{forbidden}`"),
            ));
        }
    }
    Ok(findings)
}

#[derive(Default)]
struct ListenerPlanExecutionInventory {
    projection_calls: usize,
    finalizer_calls: usize,
    canonical_finalizer_calls: usize,
    finalizer_input_structs: usize,
    canonical_finalizer_input_structs: usize,
    set_returning_functions: usize,
    canonical_finalizers: usize,
    set_constructor_methods: usize,
    set_trait_impls: usize,
    set_literals: usize,
    inside_set_impl: bool,
}

impl ListenerPlanExecutionInventory {
    fn absorb(&mut self, other: &Self) {
        self.projection_calls += other.projection_calls;
        self.finalizer_calls += other.finalizer_calls;
        self.canonical_finalizer_calls += other.canonical_finalizer_calls;
        self.finalizer_input_structs += other.finalizer_input_structs;
        self.canonical_finalizer_input_structs += other.canonical_finalizer_input_structs;
        self.set_returning_functions += other.set_returning_functions;
        self.canonical_finalizers += other.canonical_finalizers;
        self.set_constructor_methods += other.set_constructor_methods;
        self.set_trait_impls += other.set_trait_impls;
        self.set_literals += other.set_literals;
    }
}

const LISTENER_CAPABILITY_TYPES: &[(&str, &str)] = &[
    ("ListenerExecutionPlan", RUNTIME_PLAN_PATH),
    ("ListenerExecutionSpec", RUNTIME_PLAN_PATH),
    ("AssembledListener", RUNTIME_ROUTES_PATH),
    ("FinalizedListenerSet", RUNTIME_ROUTES_PATH),
    ("FinalizedListenerPlan", RUNTIME_ROUTES_PATH),
    ("FinalizedProbeReceipt", RUNTIME_ROUTES_PATH),
];

#[derive(Default)]
struct ListenerCapabilityInventory {
    declarations: BTreeMap<String, Vec<(bool, bool)>>,
    public_reexports: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ListenerCapabilityInventory {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if !attrs_may_be_production(&item.attrs) {
            return;
        }
        let name = item.ident.to_string();
        if LISTENER_CAPABILITY_TYPES
            .iter()
            .any(|(protected, _)| *protected == name)
        {
            self.declarations.entry(name).or_default().push((
                is_exact_pub_crate(&item.vis),
                item.fields
                    .iter()
                    .all(|field| matches!(field.vis, syn::Visibility::Inherited)),
            ));
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !attrs_may_be_production(&item.attrs) || !matches!(item.vis, syn::Visibility::Public(_))
        {
            return;
        }
        collect_public_listener_capability_reexports(
            &item.tree,
            &mut Vec::new(),
            &mut self.public_reexports,
        );
    }
}

fn is_exact_pub_crate(visibility: &syn::Visibility) -> bool {
    matches!(
        visibility,
        syn::Visibility::Restricted(restricted)
            if restricted.in_token.is_none() && restricted.path.is_ident("crate")
    )
}

fn collect_public_listener_capability_reexports(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    exposed: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_public_listener_capability_reexports(&path.tree, prefix, exposed);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let ident = name.ident.to_string();
            if LISTENER_CAPABILITY_TYPES
                .iter()
                .any(|(protected, _)| *protected == ident)
            {
                exposed.insert(ident);
            }
        }
        syn::UseTree::Rename(rename) => {
            let ident = rename.ident.to_string();
            if LISTENER_CAPABILITY_TYPES
                .iter()
                .any(|(protected, _)| *protected == ident)
            {
                exposed.insert(ident);
            }
        }
        syn::UseTree::Glob(_) => {
            if prefix
                .last()
                .is_some_and(|module| matches!(module.as_str(), "plan" | "routes"))
            {
                exposed.extend(
                    LISTENER_CAPABILITY_TYPES
                        .iter()
                        .map(|(protected, _)| (*protected).to_owned()),
                );
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_public_listener_capability_reexports(item, prefix, exposed);
            }
        }
    }
}

fn listener_capability_visibility_findings(
    production_files: &BTreeMap<String, syn::File>,
) -> Vec<Finding<Rule>> {
    let mut declarations: BTreeMap<String, Vec<(&str, bool, bool)>> = BTreeMap::new();
    let mut public_reexports = Vec::new();
    for (path, file) in production_files {
        let mut inventory = ListenerCapabilityInventory::default();
        inventory.visit_file(file);
        for (name, observed) in inventory.declarations {
            declarations
                .entry(name)
                .or_default()
                .extend(observed.into_iter().map(|(crate_visible, private_fields)| {
                    (path.as_str(), crate_visible, private_fields)
                }));
        }
        public_reexports.extend(
            inventory
                .public_reexports
                .into_iter()
                .map(|name| (path.as_str(), name)),
        );
    }

    let mut findings = Vec::new();
    for (name, owner) in LISTENER_CAPABILITY_TYPES {
        let observed = declarations
            .get(*name)
            .map(Vec::as_slice)
            .unwrap_or_default();
        if !matches!(
            observed,
            [(path, true, true)] if *path == *owner
        ) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                *owner,
                format!(
                    "`{name}` 必须只在 canonical owner 定义一次、精确使用 pub(crate) 且所有字段保持 inherited-private"
                ),
            ));
        }
    }
    for (path, name) in public_reexports {
        findings.push(finding(
            Rule::ForbiddenWiring,
            path,
            format!("listener execution capability `{name}` 禁止 public re-export"),
        ));
    }
    findings
}

fn listener_plan_execution_inventory(file: &syn::File) -> ListenerPlanExecutionInventory {
    let mut inventory = ListenerPlanExecutionInventory::default();
    inventory.visit_file(file);
    inventory
}

fn return_type_mentions(output: &syn::ReturnType, ident: &str) -> bool {
    matches!(output, syn::ReturnType::Type(_, ty) if compact_tokens(ty).contains(ident))
}

fn finalizer_input_struct_is_canonical(item: &syn::ItemStruct) -> bool {
    const FIELDS: &[(&str, &str)] = &[
        ("execution_plan", "ListenerExecutionPlan"),
        ("config", "SnapshotConfig<'config>"),
        ("registry", "&'borrowmutbootstrap::Registry"),
        ("providers", "&'borrowTokenProviderBindings"),
        ("audit_sink", "httpserve::AuditSinkHandle"),
        ("audit_clock", "Arc<dyndiport::Clock>"),
        ("rate_limiter", "Arc<GovernorLimiter>"),
        ("metrics", "Arc<dyndiport::MetricsExporter>"),
        (
            "framework_routes",
            "crate::runtime_inventory::RuntimeInventoryRoutes",
        ),
    ];
    item.ident == "FinalizeListenerPlanInputs"
        && is_exact_pub_crate(&item.vis)
        && compact_tokens(&item.generics) == "<'config,'borrow>"
        && matches!(&item.fields, syn::Fields::Named(fields)
        if fields.named.len() == FIELDS.len()
            && fields.named.iter().zip(FIELDS).all(|(field, (name, ty))| {
                field.ident.as_ref().is_some_and(|ident| ident == name)
                    && is_exact_pub_crate(&field.vis)
                    && compact_tokens(&field.ty) == *ty
            }))
}

fn finalizer_signature_is_canonical(signature: &syn::Signature) -> bool {
    matches!(signature.inputs.first(), Some(syn::FnArg::Typed(argument))
        if signature.inputs.len() == 1
            && matches!(argument.pat.as_ref(), syn::Pat::Ident(binding)
                if binding.ident == "inputs"
                    && binding.by_ref.is_none()
                    && binding.mutability.is_none())
            && compact_tokens(&argument.ty) == "FinalizeListenerPlanInputs<'_,'_>")
        && return_type_mentions(&signature.output, "FinalizedListenerPlan")
}

fn finalizer_call_is_canonical(call: &syn::ExprCall) -> bool {
    const FIELDS: &[(&str, &str)] = &[
        ("execution_plan", "listener_execution_plan"),
        ("config", "context.config()"),
        ("registry", "&mutregistry"),
        ("providers", "&token_provider_bindings"),
        ("audit_sink", "auth_audit_sink"),
        ("audit_clock", "auth_audit_clock"),
        ("rate_limiter", "rate_limiter"),
        ("metrics", "metrics_exporter"),
        (
            "framework_routes",
            "crate::runtime_inventory::RuntimeInventoryRoutes::new(inventory_reader,)",
        ),
    ];
    let Some(syn::Expr::Struct(inputs)) = call.args.first() else {
        return false;
    };
    call.args.len() == 1
        && path_last_ident(&inputs.path).is_some_and(|ident| ident == "FinalizeListenerPlanInputs")
        && inputs.rest.is_none()
        && inputs.fields.len() == FIELDS.len()
        && inputs
            .fields
            .iter()
            .zip(FIELDS)
            .all(|(field, (name, expression))| {
                matches!(&field.member, syn::Member::Named(ident) if ident == name)
                    && compact_tokens(&field.expr) == *expression
            })
}

impl<'ast> Visit<'ast> for ListenerPlanExecutionInventory {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_default_runtime_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !attrs_may_be_default_runtime_production(&item.attrs) {
            return;
        }
        if return_type_mentions(&item.sig.output, "FinalizedListenerPlan") {
            self.set_returning_functions += 1;
            if item.sig.ident == "finalize_listener_plan"
                && finalizer_signature_is_canonical(&item.sig)
            {
                self.canonical_finalizers += 1;
            }
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if !attrs_may_be_default_runtime_production(&item.attrs) {
            return;
        }
        if item.ident == "FinalizeListenerPlanInputs" {
            self.finalizer_input_structs += 1;
            self.canonical_finalizer_input_structs +=
                usize::from(finalizer_input_struct_is_canonical(item));
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !attrs_may_be_default_runtime_production(&item.attrs) {
            return;
        }
        let is_set_impl =
            type_last_ident(&item.self_ty).is_some_and(|ident| ident == "FinalizedListenerSet");
        if is_set_impl && item.trait_.is_some() {
            self.set_trait_impls += 1;
        }
        let previous = self.inside_set_impl;
        self.inside_set_impl = is_set_impl;
        syn::visit::visit_item_impl(self, item);
        self.inside_set_impl = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !attrs_may_be_default_runtime_production(&item.attrs) {
            return;
        }
        if self.inside_set_impl
            && (return_type_mentions(&item.sig.output, "FinalizedListenerSet")
                || return_type_mentions(&item.sig.output, "Self"))
        {
            self.set_constructor_methods += 1;
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "listener_execution_plan" {
            self.projection_calls += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if expr_path_last(&call.func).is_some_and(|ident| ident == "finalize_listener_plan") {
            self.finalizer_calls += 1;
            self.canonical_finalizer_calls += usize::from(finalizer_call_is_canonical(call));
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        if path_last_ident(&expression.path).is_some_and(|ident| ident == "FinalizedListenerSet") {
            self.set_literals += 1;
        }
        syn::visit::visit_expr_struct(self, expression);
    }
}

#[derive(Debug, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingRemapMapKind {
    Pg,
    S3,
    Serving,
}

#[derive(Debug)]
enum BindingRemapUndo {
    Slot {
        slot: usize,
        previous: syn::Ident,
    },
    Map {
        kind: BindingRemapMapKind,
        key: String,
        previous: syn::Ident,
    },
}

const TRACKED_BINDING_SLOT_COUNT: usize = 8;

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
    serving_parts_binding: Option<syn::Ident>,
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

    fn push_binding_remaps(
        &mut self,
        remaps: &[(syn::Ident, syn::Ident)],
    ) -> Vec<BindingRemapUndo> {
        let mut undo = Vec::new();
        // `binding_remaps_for_call` yields `(param, arg)`; remap tracked bindings arg → param.
        for (param, arg) in remaps {
            self.remap_tracked_binding(arg, param, &mut undo);
        }
        undo
    }

    fn pop_binding_remaps(&mut self, undo: Vec<BindingRemapUndo>) {
        for entry in undo.into_iter().rev() {
            match entry {
                BindingRemapUndo::Slot { slot, previous } => {
                    self.set_tracked_binding_slot(slot, Some(previous));
                }
                BindingRemapUndo::Map {
                    kind,
                    key,
                    previous,
                } => match kind {
                    BindingRemapMapKind::Pg => {
                        self.pg_part_bindings.insert(key, previous);
                    }
                    BindingRemapMapKind::S3 => {
                        self.s3_part_bindings.insert(key, previous);
                    }
                    BindingRemapMapKind::Serving => {
                        self.serving_part_bindings.insert(key, previous);
                    }
                },
            }
        }
    }

    fn remap_tracked_binding(
        &mut self,
        from: &syn::Ident,
        to: &syn::Ident,
        undo: &mut Vec<BindingRemapUndo>,
    ) {
        for slot in 0..TRACKED_BINDING_SLOT_COUNT {
            if self.tracked_binding_slot(slot).as_ref() == Some(from) {
                undo.push(BindingRemapUndo::Slot {
                    slot,
                    previous: from.clone(),
                });
                self.set_tracked_binding_slot(slot, Some(to.clone()));
            }
        }
        for (key, binding) in &mut self.pg_part_bindings {
            if binding == from {
                undo.push(BindingRemapUndo::Map {
                    kind: BindingRemapMapKind::Pg,
                    key: key.clone(),
                    previous: from.clone(),
                });
                *binding = to.clone();
            }
        }
        for (key, binding) in &mut self.s3_part_bindings {
            if binding == from {
                undo.push(BindingRemapUndo::Map {
                    kind: BindingRemapMapKind::S3,
                    key: key.clone(),
                    previous: from.clone(),
                });
                *binding = to.clone();
            }
        }
        for (key, binding) in &mut self.serving_part_bindings {
            if binding == from {
                undo.push(BindingRemapUndo::Map {
                    kind: BindingRemapMapKind::Serving,
                    key: key.clone(),
                    previous: from.clone(),
                });
                *binding = to.clone();
            }
        }
    }

    fn tracked_binding_slot(&self, slot: usize) -> &Option<syn::Ident> {
        match slot {
            0 => &self.runtime_inputs_binding,
            1 => &self.config_binding,
            2 => &self.pg_config_binding,
            3 => &self.redis_config_binding,
            4 => &self.vault_config_binding,
            5 => &self.s3_config_binding,
            6 => &self.s3_canary_module_binding,
            7 => &self.serving_parts_binding,
            _ => {
                debug_assert!(
                    false,
                    "tracked binding slot {slot} out of range (expected 0..{TRACKED_BINDING_SLOT_COUNT})"
                );
                unreachable!(
                    "tracked binding slot {slot} out of range (expected 0..{TRACKED_BINDING_SLOT_COUNT})"
                )
            }
        }
    }

    fn set_tracked_binding_slot(&mut self, slot: usize, value: Option<syn::Ident>) {
        match slot {
            0 => self.runtime_inputs_binding = value,
            1 => self.config_binding = value,
            2 => self.pg_config_binding = value,
            3 => self.redis_config_binding = value,
            4 => self.vault_config_binding = value,
            5 => self.s3_config_binding = value,
            6 => self.s3_canary_module_binding = value,
            7 => self.serving_parts_binding = value,
            _ => {
                debug_assert!(
                    false,
                    "tracked binding slot {slot} out of range (expected 0..{TRACKED_BINDING_SLOT_COUNT})"
                );
                unreachable!(
                    "tracked binding slot {slot} out of range (expected 0..{TRACKED_BINDING_SLOT_COUNT})"
                )
            }
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

    fn is_phase_canonical(&self) -> bool {
        let serving_sinks_are_canonical = SERVING_RUNTIME_SINK_FIELDS.iter().all(|field| {
            self.serving_sink_calls.get(*field) == Some(&1)
                && self.canonical_serving_sink_calls.get(*field) == Some(&1)
        });
        self.runtime_inputs_calls == 0
            && self.runtime_inputs_config_calls == 2
            && self.runtime_plan_calls == 1
            && self.canonical_runtime_plan_calls == 1
            && self.config_view_bindings == 2
            && self.canonical_config_view_bindings == 2
            && self.serving_config_calls == 1
            && self.canonical_serving_config_calls == 1
            && self.serving_into_parts_calls == 1
            && self.canonical_serving_into_parts_calls == 1
            && self.serving_part_bindings.len() == SERVING_RUNTIME_PART_FIELDS.len()
            && self.serving_wiring_inputs_calls == 1
            && self.canonical_serving_wiring_inputs_calls == 1
            && self.serving_wiring_destructures == 0
            && self.canonical_serving_wiring_destructures == 0
            && serving_sinks_are_canonical
            && self.pg_setup_after_serving_config == 1
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
            && self.s3_canary_assembly_fields == 0
            && self.canonical_s3_canary_assembly_fields == 0
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
            "wire_domains" => self.record_serving_sink(
                "domain_modules",
                call.args.len() == 3
                    && self.serving_argument_is_canonical(call, 1, "domain_modules"),
            ),
            "wire_auth_grant_sweeper" => self.record_serving_sink(
                "auth_grant_sweep_interval",
                call.args.len() == 2
                    && self.serving_argument_is_canonical(call, 1, "auth_grant_sweep_interval"),
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

impl RunRuntimeConfigWiring {
    fn observe_local(&mut self, local: &syn::Local) {
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
        if let (Some(binding), Some(initializer), Some(config)) =
            (binding, initializer, self.config_binding.as_ref())
            && canonical_serving_parts_initializer(initializer, config)
            && self.serving_parts_binding.is_none()
        {
            self.serving_parts_binding = Some(binding.clone());
        }
        if let (Some(initializer), Some(config)) = (initializer, self.config_binding.as_ref())
            && (canonical_serving_parts_initializer(initializer, config)
                || self
                    .serving_parts_binding
                    .as_ref()
                    .is_some_and(|binding| is_exact_ident_path(initializer, binding)))
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
    }

    fn observe_expr_call(&mut self, call: &syn::ExprCall) {
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
                                    || is_self_runtime_inputs_config_view(arg)
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
        if path_ends_with(&call.func, &["PgRuntimeDeps", "connect_serving"]) {
            self.pg_setup_calls += 1;
            let canonical = pg_setup_uses_named_parts(call, &self.pg_part_bindings);
            self.canonical_pg_setup_calls += usize::from(canonical);
            self.pg_setup_after_serving_config +=
                usize::from(canonical && self.canonical_serving_into_parts_calls == 1);
        }
    }

    fn observe_expr_struct(&mut self, item: &syn::ExprStruct) {
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
    }

    fn observe_expr_method_call(&mut self, call: &syn::ExprMethodCall) {
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
    }
}

impl<'ast> Visit<'ast> for RunRuntimeConfigWiring {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.observe_local(local);
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.observe_expr_call(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
        self.observe_expr_struct(item);
        syn::visit::visit_expr_struct(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.observe_expr_method_call(call);
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit::visit_expr_closure(self, closure);
        self.closure_depth -= 1;
    }
}

struct HelperExpandingVisit<'a, 'ast> {
    inner: &'a mut RunRuntimeConfigWiring,
    owner: &'a str,
    methods: &'a BTreeMap<String, &'ast syn::ImplItemFn>,
    stack: &'a mut Vec<String>,
    error: &'a mut Option<PhaseExpandError>,
}

impl<'a, 'ast> Visit<'ast> for HelperExpandingVisit<'a, 'ast> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.inner.observe_local(local);
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.error.is_some() {
            return;
        }
        if let Some((helper, args)) = self_or_owner_call(call, self.owner, self.methods) {
            if !self.expand_helper(helper, args) {
                return;
            }
            return;
        }
        self.inner.observe_expr_call(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
        self.inner.observe_expr_struct(item);
        syn::visit::visit_expr_struct(self, item);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.error.is_some() {
            return;
        }
        if let Some((helper, args)) = self_receiver_helper_call(call, self.methods) {
            if !self.expand_helper(helper, args) {
                return;
            }
            return;
        }
        self.inner.observe_expr_method_call(call);
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.inner.closure_depth += 1;
        syn::visit::visit_expr_closure(self, closure);
        self.inner.closure_depth -= 1;
    }
}

impl<'a, 'ast> HelperExpandingVisit<'a, 'ast> {
    fn expand_helper(
        &mut self,
        helper: &'ast syn::ImplItemFn,
        args: &'ast syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
    ) -> bool {
        let name = helper.sig.ident.to_string();
        if self.stack.iter().any(|frame| frame == &name) {
            *self.error = Some(PhaseExpandError::Cycle(name));
            return false;
        }
        for arg in args {
            self.visit_expr(arg);
            if self.error.is_some() {
                return false;
            }
        }
        let remaps = binding_remaps_for_call(helper, args);
        let undo = self.inner.push_binding_remaps(&remaps);
        self.stack.push(name);
        self.visit_block(&helper.block);
        self.stack.pop();
        self.inner.pop_binding_remaps(undo);
        self.error.is_none()
    }
}

const SERVING_RUNTIME_PART_FIELDS: &[&str] = &[
    "token_profiles",
    "event_transport",
    "event_worker",
    "dlx_worker",
    "distributed_worker",
    "domain_modules",
    "audit_consumer_key",
    "auth_grant_sweep_interval",
];

const SERVING_RUNTIME_SINK_FIELDS: &[&str] = &[
    "event_transport",
    "event_worker",
    "distributed_worker",
    "domain_modules",
    "audit_consumer_key",
    "auth_grant_sweep_interval",
];

const RUNTIME_WIRING_INPUT_FIELDS: &[&str] = &[
    "event_transport",
    "event_worker",
    "distributed_worker",
    "domain_modules",
    "audit_consumer_key",
    "auth_grant_sweep_interval",
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
    "audit_admin",
    "dlx_archiver",
    "dlx_verifier",
    "dlx_purger",
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
    let Some(serving) = bindings.get("serving") else {
        return false;
    };
    let Some(tenant_read) = bindings.get("tenant_read") else {
        return false;
    };
    let Some(audit_admin) = bindings.get("audit_admin") else {
        return false;
    };
    call.args.len() == 4
        && call
            .args
            .first()
            .is_some_and(|arg| reference_to_binding(arg, serving))
        && call
            .args
            .iter()
            .nth(1)
            .is_some_and(|arg| reference_to_binding(arg, tenant_read))
        && call
            .args
            .iter()
            .nth(2)
            .is_some_and(|arg| method_on_binding(arg, "as_ref", audit_admin))
        && call
            .args
            .iter()
            .nth(3)
            .is_some_and(|arg| compact_tokens(arg) == "projection_capture")
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
    "VaultKeyProviderConfig",
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
            "VaultKeyProviderConfig" => Some("infra::vault::VaultKeyProviderConfig"),
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
        && exact_input(&inputs[1], "ca_cert_pem", "Vec<u8>")
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
    ("tenant_store_allowlist_json", "String"),
];
const S3_VALUES_INPUTS: &[(&str, &str)] = &[
    ("endpoint_url", "String"),
    ("bucket", "String"),
    ("access_key_id", "String"),
    ("secret_access_key", "String"),
    ("force_path_style", "bool"),
    ("ca_cert_pem", "Vec<u8>"),
];
const VALUES_SEAM_SPECS: &[ValuesSeamSpec] = &[
    ValuesSeamSpec {
        name: "build_vault_runtime_from_values",
        inputs: VAULT_VALUES_INPUTS,
        internal_output: "anyhow::Result<(VaultRuntimeDeps,std::sync::Arc<VaultSigner>,KeyName)>",
        wrapper_output: "anyhow::Result<(vault::VaultRuntimeDeps,Arc<vault::VaultSigner>,diport::KeyName,)>",
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
                        (
                            "tenant_store_allowlist_json",
                            "Some(tenant_store_allowlist_json.as_str())",
                        ),
                    ],
                )
        }
        _ => false,
    }
}

const S3_PRIVATE_CA_VALUES_BODY: &str = r#"{
    let endpoint = secure::S3Endpoint::parse(endpoint_url, secure::PlaintextEndpointPolicy::Deny)
        .with_context(|| {
            format!("{S3_ENDPOINT_URL_ENV} must be https:// (plaintext http:// is banned)")
        })?;
    let factory = s3::PrivateCaS3ClientFactory::new(
        endpoint,
        DEFAULT_S3_REGION,
        aws_sdk_s3::config::Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "rss-runtime-integration",
        ),
        force_path_style,
        ca_cert_pem,
    );
    let client = factory
        .build_client()
        .context("build S3 client with private CA")?;
    let store = S3Store::new(client, bucket).context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
}"#;

fn s3_private_ca_values_seam_body_is_exact(item: &syn::ItemFn) -> bool {
    let Ok(expected) = syn::parse_str::<syn::Block>(S3_PRIVATE_CA_VALUES_BODY) else {
        return false;
    };
    compact_tokens(&item.block) == compact_tokens(&expected)
}

fn values_seam_body_is_exact(item: &syn::ItemFn, spec: &ValuesSeamSpec) -> bool {
    if spec.name == "build_s3_runtime_deps_from_values" {
        return s3_private_ca_values_seam_body_is_exact(item);
    }
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

fn vault_s3_test_support_file_is_exact(file: &syn::File) -> bool {
    VALUES_SEAM_SPECS.iter().all(|spec| {
        let wrappers = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == spec.name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        wrappers.len() == 1 && public_values_wrapper_is_exact(wrappers[0], spec)
    })
}

fn integration_test_support_module_is_exact(file: &syn::File) -> bool {
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "test_support" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    matches!(modules.as_slice(), [module]
    if matches!(module.vis, syn::Visibility::Public(_))
        && module.content.is_none()
        && has_one_exact_cfg(&module.attrs, cfg_is_exact_integration)
        && module.attrs.iter().all(|attribute| {
            attribute.path().is_ident("cfg") || attribute.path().is_ident("doc")
        }))
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
                    || self.associated_call_is_canonical(
                        call,
                        "from_snapshot",
                        "VaultKeyProviderConfig",
                    )
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
            self.associated_call_is_canonical(call, "from_snapshot", "VaultRuntimeConfig")
                || self.associated_call_is_canonical(
                    call,
                    "from_snapshot",
                    "VaultKeyProviderConfig",
                );
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
                "into_key_provider" => self.vault_settings_consumes += 1,
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
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

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
const RSS_OFFLINE_COMMAND_FAMILY: (&str, &str, &str) = (
    "VaultAllowlistValidation",
    "is_vault_allowlist_validation_command",
    "run_vault_allowlist_validation_command",
);

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
    let condition_is_canonical =
        is_exact_path(&condition.func, &["runtime", "operator", predicate])
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

fn classifier_offline_if_is_canonical(statement: &syn::Stmt, args: &syn::Ident) -> bool {
    let syn::Stmt::Expr(expr, None) = statement else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(expr) else {
        return false;
    };
    let Some(condition) = direct_call_behind_runtime_context(&branch.cond) else {
        return false;
    };
    let condition_is_canonical = is_exact_path(
        &condition.func,
        &["runtime", "operator", RSS_OFFLINE_COMMAND_FAMILY.1],
    ) && condition.args.len() == 1
        && condition
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, args));
    let return_is_canonical = match branch.then_branch.stmts.as_slice() {
        [syn::Stmt::Expr(expr, Some(_))] | [syn::Stmt::Expr(expr, None)] => {
            let syn::Expr::Return(returned) = transparent_expr(expr) else {
                return false;
            };
            returned
                .expr
                .as_deref()
                .is_some_and(|expr| ok_command_variant(expr, RSS_OFFLINE_COMMAND_FAMILY.0))
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
    let family_is_exact = family.variants.len() == 3
        && family.variants.iter().any(|variant| {
            variant.ident == "Serving" && matches!(variant.fields, syn::Fields::Unit)
        })
        && family.variants.iter().any(|variant| {
            variant.ident == RSS_OFFLINE_COMMAND_FAMILY.0
                && matches!(variant.fields, syn::Fields::Unit)
        })
        && family.variants.iter().any(|variant| {
            variant.ident == "Operator"
                && matches!(&variant.fields, syn::Fields::Unnamed(fields)
                    if fields.unnamed.len() == 1
                        && compact_type_tokens(&fields.unnamed[0].ty) == "OperatorCommand")
        });
    let mut expected_variants = RSS_COMMAND_FAMILIES
        .iter()
        .filter(|(variant, _, _)| *variant != "Serving")
        .map(|(variant, _, _)| (*variant).to_owned())
        .collect::<BTreeSet<_>>();
    expected_variants.insert("Postgres".to_owned());
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
    if classifier.block.stmts.len() != operator_families.len() + 4 {
        return false;
    }
    if !classifier_offline_if_is_canonical(&classifier.block.stmts[0], args)
        || !classifier_migration_if_is_canonical(&classifier.block.stmts[1], args)
        || !operator_families
            .iter()
            .zip(&classifier.block.stmts[2..])
            .all(|((variant, predicate), statement)| {
                classifier_if_is_canonical(statement, args, predicate, variant)
            })
    {
        return false;
    }
    let ensure_statement = &classifier.block.stmts[operator_families.len() + 2];
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

fn classifier_migration_if_is_canonical(statement: &syn::Stmt, args: &syn::Ident) -> bool {
    let syn::Stmt::Expr(expr, None) = statement else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(expr) else {
        return false;
    };
    let condition = compact_tokens(&branch.cond);
    condition.contains("matches!(")
        && condition.contains(&args.to_string())
        && condition.contains("namespace==\"postgres\"")
        && condition.contains("command==\"migrate-all\"")
        && branch.else_branch.is_none()
        && matches!(branch.then_branch.stmts.as_slice(), [syn::Stmt::Expr(expr, Some(_))] | [syn::Stmt::Expr(expr, None)]
            if compact_tokens(expr) == "returnOk(CommandFamily::Operator(OperatorCommand::Postgres))")
}

fn offline_dispatch_is_canonical(
    statement: &syn::Stmt,
    args: &syn::Ident,
    command: &syn::Ident,
) -> bool {
    let syn::Stmt::Expr(expr, None) = statement else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(expr) else {
        return false;
    };
    let syn::Expr::Let(condition) = transparent_expr(&branch.cond) else {
        return false;
    };
    let pattern_is_canonical = matches!(&*condition.pat, syn::Pat::Path(path)
        if is_exact_syn_path(&path.path, &["CommandFamily", RSS_OFFLINE_COMMAND_FAMILY.0]));
    let return_is_canonical = match branch.then_branch.stmts.as_slice() {
        [syn::Stmt::Expr(expr, Some(_))] | [syn::Stmt::Expr(expr, None)] => {
            let syn::Expr::Return(returned) = transparent_expr(expr) else {
                return false;
            };
            let Some(call) = returned
                .expr
                .as_deref()
                .and_then(direct_call_behind_runtime_context)
            else {
                return false;
            };
            is_exact_path(
                &call.func,
                &["runtime", "operator", RSS_OFFLINE_COMMAND_FAMILY.2],
            ) && call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|arg| reference_to_binding(arg, args))
        }
        _ => false,
    };
    pattern_is_canonical
        && is_exact_ident_path(&condition.expr, command)
        && return_is_canonical
        && branch.else_branch.is_none()
}

fn rss_main_is_canonical(main: &syn::ItemFn) -> bool {
    if main.sig.asyncness.is_none()
        || !matches!(&main.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty.as_ref()) == "anyhow::Result<()>")
        || main.block.stmts.len() != 9
    {
        return false;
    }
    let [
        args_statement,
        command_statement,
        offline_statement,
        serving_statement,
        migration_statement,
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
    if !offline_dispatch_is_canonical(offline_statement, args, command) {
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
    if !migration_dispatch_is_canonical(migration_statement, &operator_command.ident, args) {
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
    if !is_exact_path(
        &prepare_call.func,
        &["runtime", "operator", "prepare_runtime"],
    ) || !prepare_call.args.is_empty()
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
        || dispatch.arms.len() != RSS_COMMAND_FAMILIES.len()
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
        if !observed.insert(variant.clone()) {
            return false;
        }
        if variant == "Postgres" {
            if compact_tokens(&arm.body)
                != "{unreachable!(\"postgresmigrationreturnsbeforeruntimesetup\")}"
            {
                return false;
            }
            continue;
        }
        let Some((_, _, runner)) = RSS_COMMAND_FAMILIES
            .iter()
            .find(|(expected, _, _)| *expected == variant)
        else {
            return false;
        };
        let Some(runner) = runner else {
            return false;
        };
        let Some(call) = direct_awaited_call(&arm.body) else {
            return false;
        };
        if !is_exact_path(&call.func, &["runtime", "operator", runner])
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
        &["runtime", "operator", "shutdown_runtime"],
    ) || shutdown_call.args.len() != 1
        || !shutdown_call
            .args
            .first()
            .is_some_and(|arg| is_exact_ident_path(arg, runtime_inputs))
    {
        return false;
    }
    let tail_ok = matches!(
        tail_statement,
        syn::Stmt::Expr(expr, None) if is_exact_ident_path(expr, result)
    );
    tail_ok
}

fn migration_dispatch_is_canonical(
    statement: &syn::Stmt,
    command: &syn::Ident,
    args: &syn::Ident,
) -> bool {
    let syn::Stmt::Expr(expr, None) = statement else {
        return false;
    };
    let syn::Expr::If(branch) = transparent_expr(expr) else {
        return false;
    };
    let condition = compact_tokens(&branch.cond);
    let body = compact_tokens(&branch.then_branch);
    condition == format!("letOperatorCommand::Postgres={command}")
        && branch.else_branch.is_none()
        && branch.then_branch.stmts.len() == 3
        && body.contains("init_migration_tracing()?")
        && body.contains(&format!("matches!({args}.as_slice(),[namespace,command]"))
        && body.contains("namespace==\"postgres\"")
        && body.contains("command==\"migrate-all\"")
        && body.contains("returnpostgres_migration::migrate_all_from_process_environment().await.map_err(anyhow::Error::from)")
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
    let typed_phase_executor = exact_path_call_count_in_file(&file, &["phase", "execute"]) == 1;
    let legacy_fixture = root.join(RUNTIME_CONFIG_FIXTURE_MARKER).exists()
        && !root.join("Cargo.toml").exists()
        && !typed_phase_executor;
    let mut findings = if legacy_fixture {
        production_runtime_config_snapshot_findings(&file)
    } else {
        let provider_path = root.join(RUNTIME_PHASE_PROVIDER_PATH);
        let infra_path = root.join(RUNTIME_PHASE_INFRA_PATH);
        let domains_path = root.join(RUNTIME_PHASE_DOMAINS_PATH);
        let provider_source = fs::read_to_string(&provider_path)
            .with_context(|| format!("读 {} 失败", provider_path.display()))?;
        let infra_source = fs::read_to_string(&infra_path)
            .with_context(|| format!("读 {} 失败", infra_path.display()))?;
        let domains_source = fs::read_to_string(&domains_path)
            .with_context(|| format!("读 {} 失败", domains_path.display()))?;
        let provider = match syn::parse_file(&provider_source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_PHASE_PROVIDER_PATH,
                    format!("runtime configuration snapshot gate 无法解析生产 Rust: {error}"),
                )]);
            }
        };
        let infra = match syn::parse_file(&infra_source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_PHASE_INFRA_PATH,
                    format!("runtime configuration snapshot gate 无法解析生产 Rust: {error}"),
                )]);
            }
        };
        let domains = match syn::parse_file(&domains_source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_PHASE_DOMAINS_PATH,
                    format!("runtime configuration snapshot gate 无法解析生产 Rust: {error}"),
                )]);
            }
        };
        let operator = parse_rust_file(&root.join(RUNTIME_OPERATOR_PATH))?;
        let settings = parse_rust_file(&root.join(RUNTIME_OPERATOR_SETTINGS_PATH))?;
        let dlx = parse_rust_file(&root.join(RUNTIME_PHASE_DLX_PATH))?;
        production_runtime_phase_config_snapshot_findings(
            &file,
            &operator,
            ProductionRuntimePhaseConfig {
                provider_source: &provider_source,
                provider: &provider,
                infra_source: &infra_source,
                infra: &infra,
                domains_source: &domains_source,
                domains: &domains,
                additional_inventory_files: &[&settings, &dlx],
            },
        )
    };
    if root.join(RSS_MAIN_PATH).exists() {
        let production_files = runtime_production_source_files(root)?;
        if !pg_operator_module_graph_is_exact(&production_files) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                "assemblies/runtime/src/operator",
                "the six PG operator definitions must live in their canonical operator modules, expose the exact &OperatorRuntimeInputs parameter, and flow its .config() view into the typed PG maintenance builder/runtime without ignored, wrong-binding, ambient-wrapper, or compliant-bait paths",
            ));
        }
    }
    findings.extend(runtime_profile_inputs_findings(root)?);
    findings.extend(runtime_config_global_capture_findings(root)?);
    findings.extend(runtime_snapshot_consumer_ambient_findings(root)?);
    findings.extend(redis_snapshot_boundary_findings(root, &file)?);
    findings.extend(vault_allowlist_typed_funnel_findings(root)?);
    findings.extend(vault_s3_values_boundary_findings(root, &file)?);
    Ok(findings)
}

struct ProductionRuntimePhaseConfig<'a> {
    provider_source: &'a str,
    provider: &'a syn::File,
    infra_source: &'a str,
    infra: &'a syn::File,
    domains_source: &'a str,
    domains: &'a syn::File,
    additional_inventory_files: &'a [&'a syn::File],
}

fn production_runtime_phase_config_snapshot_findings(
    runtime: &syn::File,
    operator: &syn::File,
    phase: ProductionRuntimePhaseConfig<'_>,
) -> Vec<Finding<Rule>> {
    let prepares = production_functions_named(runtime, "prepare_runtime");
    let runs = production_functions_named(runtime, "run");
    let startups = production_functions_named(runtime, "run_startup");
    let Some(prepare) = (prepares.len() == 1).then_some(prepares[0]) else {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "runtime configuration snapshot gate requires one production prepare_runtime",
        )];
    };
    let Some(run) = (runs.len() == 1).then_some(runs[0]) else {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "runtime configuration snapshot gate requires one production run",
        )];
    };
    let Some(startup) = (startups.len() == 1).then_some(startups[0]) else {
        return vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "runtime configuration snapshot gate requires one production run_startup",
        )];
    };
    if let Err(error) = expand_inherent_phase_method(
        phase.provider_source,
        phase.provider,
        "Planned",
        "build_providers",
    ) {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_PROVIDER_PATH,
            format!("typed BuildProvider helper expansion failed: {error}"),
        )];
    }
    if let Err(error) = expand_inherent_phase_method(
        phase.infra_source,
        phase.infra,
        "ProvidersBuilt",
        "build_infra",
    ) {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_INFRA_PATH,
            format!("typed BuildInfra helper expansion failed: {error}"),
        )];
    }
    if let Err(error) = expand_inherent_phase_method(
        phase.domains_source,
        phase.domains,
        "InfraBuilt",
        "wire_domains",
    ) {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_DOMAINS_PATH,
            format!("typed WireDomains helper expansion failed: {error}"),
        )];
    }

    let mut prepare_wiring = PrepareRuntimeConfigWiring::default();
    prepare_wiring.visit_block(&prepare.block);
    let mut run_wiring =
        RunRuntimeConfigWiring::new(syn::Ident::new("context", proc_macro2::Span::call_site()));
    if let Err(error) = visit_expanded_phase_method(
        &mut run_wiring,
        phase.provider,
        "Planned",
        "build_providers",
    ) {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_PROVIDER_PATH,
            format!("typed BuildProvider helper expansion visitor failed: {error}"),
        )];
    }
    if let Err(error) = visit_expanded_phase_method(
        &mut run_wiring,
        phase.infra,
        "ProvidersBuilt",
        "build_infra",
    ) {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_INFRA_PATH,
            format!("typed BuildInfra helper expansion visitor failed: {error}"),
        )];
    }
    if let Err(error) =
        visit_expanded_phase_method(&mut run_wiring, phase.domains, "InfraBuilt", "wire_domains")
    {
        return vec![finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_DOMAINS_PATH,
            format!("typed WireDomains helper expansion visitor failed: {error}"),
        )];
    }
    let mut inventory = ProductionRuntimeConfigInventory::default();
    inventory.visit_file(runtime);
    inventory.visit_file(phase.provider);
    inventory.visit_file(phase.infra);
    inventory.visit_file(phase.domains);
    for file in phase.additional_inventory_files {
        inventory.visit_file(file);
    }
    let password_preload = PasswordPreloadStatus::inspect_production(runtime, operator);

    if prepare.sig.asyncness.is_none()
        && run.sig.asyncness.is_some()
        && startup.sig.asyncness.is_some()
        && runtime_inputs_mut_parameter(startup).is_some()
        && password_preload.is_canonical()
        && run_wiring.is_phase_canonical()
        && runtime_lifecycle_outer_is_canonical(runtime, run)
        && inventory.is_exact()
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_INFRA_PATH,
            format!(
                "typed phase config flow must map one captured generation through BuildProvider, BuildInfra, and WireDomains without aliases or fallback; {}; run={run_wiring:?}, inventory={}",
                password_preload.diagnostic(),
                inventory.diagnostic()
            ),
        )]
    }
}

fn production_functions_named<'a>(file: &'a syn::File, name: &str) -> Vec<&'a syn::ItemFn> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == name && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect()
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
            "ServingRuntimeInputs must privately own exactly PreparedRuntimeInputs and Arc<secure::DigestPasswordBlocklist>; OperatorRuntimeInputs must privately own only PreparedRuntimeInputs, making serving capabilities unrepresentable",
        ));
    }

    let jwks_path = root.join(RUNTIME_OPERATOR_JWKS_PATH);
    if jwks_path.exists() {
        let jwks_source = fs::read_to_string(&jwks_path)
            .with_context(|| format!("读 {} 失败", jwks_path.display()))?;
        let jwks_file = match syn::parse_file(&jwks_source) {
            Ok(file) => file,
            Err(error) => {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_OPERATOR_JWKS_PATH,
                    format!("RSS access JWKS operator profile gate 无法解析 Rust: {error}"),
                ));
                return Ok(findings);
            }
        };
        if !rss_access_jwks_operator_signature_is_exact(&jwks_file) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_OPERATOR_JWKS_PATH,
                "run_rss_access_jwks_export_command must accept the exact &[String] and &OperatorRuntimeInputs inputs in the canonical operator owner; serving inputs and ambient configuration are forbidden",
            ));
        }
        let vault_path = root.join(RUNTIME_VAULT_PATH);
        if vault_path.is_file() {
            let vault_file = parse_rust_file(&vault_path)?;
            if !rss_access_jwks_capability_flow_is_exact(&vault_file, &jwks_file) {
                findings.push(finding(
                    Rule::ForbiddenWiring,
                    RUNTIME_OPERATOR_JWKS_PATH,
                    "RSS access JWKS production flow must call the sole capability-bound Vault export with exact args + SnapshotConfig + OperatorRuntimeCapability; getter/allow-http/alias/dead-helper seams are forbidden",
                ));
            }
        }
    }
    Ok(findings)
}

fn rss_access_jwks_capability_flow_is_exact(vault: &syn::File, operator: &syn::File) -> bool {
    let exports = production_functions_named(vault, "export_rss_access_jwks");
    let urls = production_functions_named(vault, "vault_transit_key_metadata_url");
    let wrappers = production_functions_named(operator, "run_rss_access_jwks_export_command");
    let [export] = exports.as_slice() else {
        return false;
    };
    let [url] = urls.as_slice() else {
        return false;
    };
    let [wrapper] = wrappers.as_slice() else {
        return false;
    };
    let export_inputs = compact_tokens(&export.sig.inputs);
    let export_shape = compact_tokens(&export.block);
    let url_inputs = compact_tokens(&url.sig.inputs);
    let url_shape = compact_tokens(&url.block);
    let wrapper_shape = compact_tokens(&wrapper.block);
    let production_export_calls = operator
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if attrs_may_be_production(&function.attrs) => Some(function),
            _ => None,
        })
        .map(|function| {
            exact_named_path_call_count(
                &function.block,
                &["crate", "infra", "vault", "export_rss_access_jwks"],
            )
        })
        .sum::<usize>();
    let forbidden_alias = operator.items.iter().any(|item| {
        matches!(item, syn::Item::Use(use_) if attrs_may_be_production(&use_.attrs)
            && compact_tokens(&use_.tree).contains("export_rss_access_jwks"))
    });

    is_exact_pub_crate(&export.vis)
        && export.sig.asyncness.is_some()
        && export_inputs
            == "args:&[String],config:SnapshotConfig<'_>,_operator:OperatorRuntimeCapability<'_>,"
        && compact_tokens(&export.sig.output) == "->anyhow::Result<()>"
        && !export_shape.contains("allow_http")
        && exact_named_path_call_count(&export.block, &["vault_transit_key_metadata_url"]) == 1
        && matches!(url.vis, syn::Visibility::Inherited)
        && url_inputs == "addr:&str,mount:&str,key_id:&str,"
        && !url_shape.contains("allow_http")
        && url_shape.contains("url.scheme()==\"https\"")
        && production_functions_named(vault, "export_rss_access_jwks_from").is_empty()
        && wrapper.sig.asyncness.is_some()
        && compact_tokens(&wrapper.sig.inputs)
            == "args:&[String],runtime_inputs:&OperatorRuntimeInputs,"
        && exact_named_path_call_count(
            &wrapper.block,
            &["crate", "infra", "vault", "export_rss_access_jwks"],
        ) == 1
        && production_export_calls == 1
        && wrapper_shape.contains(
            "crate::infra::vault::export_rss_access_jwks(args,runtime_inputs.config(),runtime_inputs.operator_capability(),).await",
        )
        && !forbidden_alias
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
            if compact_type_tokens(input.ty.as_ref()) == "&OperatorRuntimeInputs")
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
            .is_some_and(|arg| is_exact_path(arg, &["ca_cert_pem"]))
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

fn redis_test_support_file_is_exact(file: &syn::File) -> bool {
    let wrappers = file
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
    wrappers.len() == 1 && public_redis_values_wrapper_is_exact(wrappers[0])
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
struct RedisPrivateCaFlow<'a> {
    deps: Option<&'a syn::Ident>,
    connect_calls: usize,
    canonical_connect_calls: usize,
    ping_calls: usize,
    canonical_ping_calls: usize,
}

impl<'ast> Visit<'ast> for RedisPrivateCaFlow<'ast> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["RedisRuntimeDeps", "connect_with_private_ca"]) {
            self.connect_calls += 1;
            self.canonical_connect_calls += usize::from(
                call.args.len() == 2
                    && call.args.first().is_some_and(|arg| {
                        matches!(arg, syn::Expr::Reference(reference)
                            if reference.mutability.is_none()
                                && is_exact_path(reference.expr.as_ref(), &["endpoint"]))
                    })
                    && call
                        .args
                        .iter()
                        .nth(1)
                        .is_some_and(|arg| is_exact_path(arg, &["ca"])),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "ping" {
            self.ping_calls += 1;
            self.canonical_ping_calls += usize::from(
                self.deps
                    .is_some_and(|deps| is_exact_ident_path(&call.receiver, deps)),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
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
    let deps_bindings = builder
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local)
                if local.init.as_ref().is_some_and(|init| {
                    exact_path_call_count_in_expr(
                        &init.expr,
                        &["redis", "RedisRuntimeDeps", "connect_with_private_ca"],
                    ) == 1
                }) =>
            {
                pat_ident(&local.pat)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(deps) = (deps_bindings.len() == 1).then_some(deps_bindings[0]) else {
        return false;
    };
    let mut global = ProductionCreatePoolInventory::default();
    global.visit_file(file);
    let mut uses = RedisPrivateCaFlow {
        deps: Some(deps),
        ..RedisPrivateCaFlow::default()
    };
    uses.visit_block(&builder.block);
    global.calls == 0
        && uses.connect_calls == 1
        && uses.canonical_connect_calls == 1
        && uses.ping_calls == 1
        && uses.canonical_ping_calls == 1
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
    let support_path = root.join(RUNTIME_TEST_SUPPORT_PATH);
    let wrapper_is_exact = if support_path.exists() {
        redis_test_support_file_is_exact(&parse_rust_file(&support_path)?)
            && (!root.join("Cargo.toml").exists()
                || integration_test_support_module_is_exact(runtime_file))
    } else {
        !root.join("Cargo.toml").exists() && redis_test_support_wrapper_is_exact(runtime_file)
    };
    if internal.len() == 1
        && internal_redis_values_seam_is_exact(internal[0])
        && wrapper_is_exact
        && redis_pool_flow_is_exact(&redis_file)
    {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        "assemblies/runtime/src/infra/redis.rs",
        "Redis explicit-values seam must remain cfg(any(test, feature = \"integration\")) + pub(crate) with its exact signature, the public wrapper must remain cfg(feature = \"integration\"), and the sole production RedisRuntimeDeps::connect_with_private_ca binding must flow to deps.ping",
    )])
}

const VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY: &str = "RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON";

fn production_owner_methods_named<'a>(
    file: &'a syn::File,
    owner: &str,
    method: &str,
) -> Vec<&'a syn::ImplItemFn> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.is_none()
                    && attrs_may_be_production(&item.attrs)
                    && type_last_ident(&item.self_ty).is_some_and(|ident| ident == owner) =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(item)
                if item.sig.ident == method && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect()
}

fn production_struct_is_exact(
    file: &syn::File,
    name: &str,
    expected_fields: &[(&str, &str)],
) -> bool {
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
    let [item] = structs.as_slice() else {
        return false;
    };
    let syn::Fields::Named(fields) = &item.fields else {
        return false;
    };
    fields.named.len() == expected_fields.len()
        && fields
            .named
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        && expected_fields.iter().all(|(name, ty)| {
            fields.named.iter().any(|field| {
                field.ident.as_ref().is_some_and(|ident| ident == name)
                    && compact_type_tokens(&field.ty) == *ty
            })
        })
}

fn production_type_has_default(file: &syn::File, name: &str) -> bool {
    let derives_default = file.items.iter().any(|item| match item {
        syn::Item::Struct(item) if item.ident == name && attrs_may_be_production(&item.attrs) => {
            item.attrs.iter().any(|attribute| {
                attribute.path().is_ident("derive") && compact_tokens(attribute).contains("Default")
            })
        }
        _ => false,
    });
    let implements_default = file.items.iter().any(|item| match item {
        syn::Item::Impl(item)
            if attrs_may_be_production(&item.attrs)
                && type_last_ident(&item.self_ty).is_some_and(|ident| ident == name) =>
        {
            item.trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .is_some_and(|segment| segment.ident == "Default")
        }
        _ => false,
    });
    derives_default || implements_default
}

fn production_enum_excludes_ident(file: &syn::File, name: &str, forbidden: &str) -> bool {
    let enums = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item) if item.ident == name && attrs_may_be_production(&item.attrs) => {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    matches!(enums.as_slice(), [item] if !compact_tokens(*item).contains(forbidden))
}

#[derive(Default)]
struct ExactStringLiteralCount {
    expected: &'static str,
    count: usize,
}

impl<'ast> Visit<'ast> for ExactStringLiteralCount {
    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.count += usize::from(literal.value() == self.expected);
    }
}

fn fixed_serving_allowlist_key_is_exact(config: &syn::File) -> bool {
    let catalogs = config
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item)
                if item.ident == "FIXED_SERVING_KEYS" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [catalog] = catalogs.as_slice() else {
        return false;
    };
    let mut count = ExactStringLiteralCount {
        expected: VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY,
        ..ExactStringLiteralCount::default()
    };
    count.visit_expr(&catalog.expr);
    count.count == 1
}

fn vault_allowlist_key_constant_is_exact(vault: &syn::File) -> bool {
    let constants = vault
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item)
                if item.ident == "VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [constant] = constants.as_slice() else {
        return false;
    };
    compact_type_tokens(&constant.ty) == "&str"
        && matches!(transparent_expr(&constant.expr), syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Str(value)
                if value.value() == VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY))
}

fn is_allowlist_key_expr(expr: &syn::Expr) -> bool {
    match transparent_expr(expr) {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV"),
        syn::Expr::Lit(literal) => matches!(&literal.lit, syn::Lit::Str(value)
            if value.value() == VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY),
        _ => false,
    }
}

fn snapshot_allowlist_read_is_exact(expr: &syn::Expr, config: &syn::Ident) -> bool {
    matches!(transparent_expr(expr), syn::Expr::MethodCall(call)
        if call.method == "value"
            && call.args.len() == 1
            && is_exact_ident_path(&call.receiver, config)
            && call.args.first().is_some_and(is_allowlist_key_expr))
}

#[derive(Default)]
struct VaultAllowlistProductionInventory {
    key_references: usize,
    allowlist_parser_calls: usize,
    allowlist_constructor_calls: usize,
    resolver_constructor_calls: usize,
}

fn path_is_vault_secret_resolver_constructor(path: &syn::Path) -> bool {
    let segments = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    segments.len() >= 2
        && segments[segments.len() - 2] == "VaultSecretResolver"
        && matches!(
            segments.last().map(String::as_str),
            Some("new" | "new_allow_http")
        )
}

impl<'ast> Visit<'ast> for VaultAllowlistProductionInventory {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.key_references += usize::from(
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV"),
        );
        let segments = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.allowlist_parser_calls += usize::from(
            segments
                .last()
                .is_some_and(|segment| segment == "tenant_store_allowlist_from_value"),
        );
        self.allowlist_constructor_calls +=
            usize::from(segments.ends_with(&["TenantStoreAllowlist".to_owned(), "new".to_owned()]));
        self.resolver_constructor_calls +=
            usize::from(path_is_vault_secret_resolver_constructor(&path.path));
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_lit(&mut self, literal: &'ast syn::ExprLit) {
        self.key_references += usize::from(matches!(&literal.lit, syn::Lit::Str(value)
            if value.value() == VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY));
        syn::visit::visit_expr_lit(self, literal);
    }
}

fn vault_allowlist_production_inventory(vault: &syn::File) -> VaultAllowlistProductionInventory {
    let mut inventory = VaultAllowlistProductionInventory::default();
    for item in &vault.items {
        match item {
            syn::Item::Fn(item) if attrs_may_be_production(&item.attrs) => {
                inventory.visit_block(&item.block);
            }
            syn::Item::Impl(item) if attrs_may_be_production(&item.attrs) => {
                for member in &item.items {
                    if let syn::ImplItem::Fn(method) = member
                        && attrs_may_be_production(&method.attrs)
                    {
                        inventory.visit_block(&method.block);
                    }
                }
            }
            _ => {}
        }
    }
    inventory
}

fn use_tree_contains_ident(tree: &syn::UseTree, expected: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            path.ident == expected || use_tree_contains_ident(&path.tree, expected)
        }
        syn::UseTree::Name(name) => name.ident == expected,
        syn::UseTree::Rename(rename) => rename.ident == expected,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_contains_ident(tree, expected)),
        syn::UseTree::Glob(_) => false,
    }
}

fn macro_contains_vault_allowlist_symbol(mac: &syn::Macro) -> bool {
    fn contains_protected_ident(tokens: proc_macro2::TokenStream) -> bool {
        tokens.into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => matches!(
                ident.to_string().as_str(),
                "tenant_store_allowlist_from_value"
                    | "TenantStoreAllowlist"
                    | "VaultSecretResolver"
            ),
            proc_macro2::TokenTree::Group(group) => contains_protected_ident(group.stream()),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
        })
    }

    contains_protected_ident(mac.tokens.clone())
}

#[derive(Default)]
struct VaultAllowlistMacroInventory {
    protected_symbols: usize,
}

impl<'ast> Visit<'ast> for VaultAllowlistMacroInventory {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.protected_symbols += usize::from(macro_contains_vault_allowlist_symbol(mac));
        syn::visit::visit_macro(self, mac);
    }
}

fn vault_allowlist_production_macro_inventory(file: &syn::File) -> VaultAllowlistMacroInventory {
    let mut inventory = VaultAllowlistMacroInventory::default();
    for item in &file.items {
        match item {
            syn::Item::Fn(item) if attrs_may_be_production(&item.attrs) => {
                inventory.visit_block(&item.block);
            }
            syn::Item::Impl(item) if attrs_may_be_production(&item.attrs) => {
                for member in &item.items {
                    if let syn::ImplItem::Fn(method) = member
                        && attrs_may_be_production(&method.attrs)
                    {
                        inventory.visit_block(&method.block);
                    }
                }
            }
            syn::Item::Macro(item) if attrs_may_be_production(&item.attrs) => {
                inventory.visit_macro(&item.mac);
            }
            _ => {}
        }
    }
    inventory
}

fn vault_allowlist_production_graph_violations(root: &Path) -> Result<Vec<String>> {
    let mut sources = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut sources)?;
    let production = production_module_sources(&sources)?;
    let mut observed = BTreeMap::new();
    let mut violations = Vec::new();
    for path in sources {
        if !production.contains(&normalize_path(&path)) {
            continue;
        }
        let file = parse_rust_file(&path)?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let inventory = vault_allowlist_production_inventory(&file);
        if inventory.key_references != 0
            || inventory.allowlist_parser_calls != 0
            || inventory.allowlist_constructor_calls != 0
            || inventory.resolver_constructor_calls != 0
        {
            observed.insert(relative.clone(), inventory);
        }

        for item in &file.items {
            if let syn::Item::Use(use_) = item
                && attrs_may_be_production(&use_.attrs)
                && relative != RUNTIME_VAULT_PATH
                && [
                    "tenant_store_allowlist_from_value",
                    "TenantStoreAllowlist",
                    "VaultSecretResolver",
                ]
                .iter()
                .any(|symbol| use_tree_contains_ident(&use_.tree, symbol))
            {
                violations.push(format!("protected-symbol-import:{relative}"));
            }
        }
        let macros = vault_allowlist_production_macro_inventory(&file);
        if macros.protected_symbols != 0 {
            violations.push(format!(
                "protected-symbol-in-macro:{relative}:{}",
                macros.protected_symbols
            ));
        }
    }

    let expected = BTreeMap::from([
        (
            RUNTIME_VAULT_PATH.to_owned(),
            VaultAllowlistProductionInventory {
                key_references: 1,
                allowlist_parser_calls: 1,
                allowlist_constructor_calls: 1,
                resolver_constructor_calls: 1,
            },
        ),
        (
            RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH.to_owned(),
            VaultAllowlistProductionInventory {
                allowlist_parser_calls: 1,
                ..VaultAllowlistProductionInventory::default()
            },
        ),
    ]);
    if observed.len() != expected.len()
        || expected.iter().any(|(path, expected)| {
            observed.get(path).is_none_or(|actual| {
                actual.key_references != expected.key_references
                    || actual.allowlist_parser_calls != expected.allowlist_parser_calls
                    || actual.allowlist_constructor_calls != expected.allowlist_constructor_calls
                    || actual.resolver_constructor_calls != expected.resolver_constructor_calls
            })
        })
    {
        let summary = observed
            .iter()
            .map(|(path, inventory)| {
                format!(
                    "{path}=key:{}/parser:{}/allowlist-new:{}/resolver-new:{}",
                    inventory.key_references,
                    inventory.allowlist_parser_calls,
                    inventory.allowlist_constructor_calls,
                    inventory.resolver_constructor_calls,
                )
            })
            .collect::<Vec<_>>();
        violations.push(format!("production-graph-exact-set:{summary:?}"));
    }
    Ok(violations)
}

#[derive(Default)]
struct VaultSnapshotAllowlistFlow<'a> {
    config: Option<&'a syn::Ident>,
    key_references: usize,
    key_reads: usize,
    canonical_key_reads: usize,
    values_structs: usize,
    canonical_values_structs: usize,
    from_values_calls: usize,
    canonical_from_values_calls: usize,
}

impl VaultSnapshotAllowlistFlow<'_> {
    fn values_struct_is_canonical(&self, value: &syn::ExprStruct) -> bool {
        path_last_ident(&value.path).is_some_and(|ident| ident == "VaultConfigValues")
            && value.rest.is_none()
            && value
                .fields
                .iter()
                .filter(|field| {
                    matches!(&field.member, syn::Member::Named(member)
                    if member == "tenant_store_allowlist_json")
                })
                .count()
                == 1
            && value.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member)
                    if member == "tenant_store_allowlist_json")
                    && self
                        .config
                        .is_some_and(|config| snapshot_allowlist_read_is_exact(&field.expr, config))
            })
    }
}

impl<'ast> Visit<'ast> for VaultSnapshotAllowlistFlow<'_> {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.key_references += usize::from(
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV"),
        );
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_lit(&mut self, literal: &'ast syn::ExprLit) {
        self.key_references += usize::from(matches!(&literal.lit, syn::Lit::Str(value)
            if value.value() == VAULT_TENANT_STORE_ALLOWLIST_JSON_KEY));
        syn::visit::visit_expr_lit(self, literal);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "value"
            && call.args.len() == 1
            && call.args.first().is_some_and(is_allowlist_key_expr)
        {
            self.key_reads += 1;
            self.canonical_key_reads += usize::from(
                self.config
                    .is_some_and(|config| is_exact_ident_path(&call.receiver, config)),
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
        if path_last_ident(&value.path).is_some_and(|ident| ident == "VaultConfigValues") {
            self.values_structs += 1;
            self.canonical_values_structs += usize::from(self.values_struct_is_canonical(value));
        }
        syn::visit::visit_expr_struct(self, value);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["Self", "from_values"]) {
            self.from_values_calls += 1;
            self.canonical_from_values_calls += usize::from(
                call.args.len() == 1
                    && matches!(call.args.first().map(transparent_expr),
                        Some(syn::Expr::Struct(value)) if self.values_struct_is_canonical(value)),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn vault_runtime_snapshot_allowlist_flow_is_exact(vault: &syn::File) -> bool {
    let methods = production_owner_methods_named(vault, "VaultRuntimeConfig", "from_snapshot");
    let [method] = methods.as_slice() else {
        return false;
    };
    let inputs = method.sig.inputs.iter().collect::<Vec<_>>();
    let Some(config) = inputs.first().and_then(|input| match input {
        syn::FnArg::Typed(input) if compact_type_tokens(&input.ty) == "SnapshotConfig<'_>" => {
            immutable_pat_ident(&input.pat)
        }
        _ => None,
    }) else {
        return false;
    };
    if inputs.len() != 1
        || !matches!(&method.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty) == "Result<Self,VaultRuntimeConfigError>")
    {
        return false;
    }
    let mut flow = VaultSnapshotAllowlistFlow {
        config: Some(config),
        ..VaultSnapshotAllowlistFlow::default()
    };
    flow.visit_block(&method.block);
    flow.key_references == 1
        && flow.key_reads == 1
        && flow.canonical_key_reads == 1
        && flow.values_structs == 1
        && flow.canonical_values_structs == 1
        && flow.from_values_calls == 1
        && flow.canonical_from_values_calls == 1
}

fn values_allowlist_argument_is_exact(expr: &syn::Expr, values: &syn::Ident) -> bool {
    matches!(transparent_expr(expr), syn::Expr::Field(field)
        if matches!(&field.member, syn::Member::Named(member)
            if member == "tenant_store_allowlist_json")
            && is_exact_ident_path(&field.base, values))
}

#[derive(Default)]
struct VaultFromValuesAllowlistFlow {
    values: Option<syn::Ident>,
    parser_calls: usize,
    canonical_parser_calls: usize,
    allowlist_bindings: BTreeSet<String>,
    provider_bindings: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for VaultFromValuesAllowlistFlow {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let Some(binding) = immutable_pat_ident(&local.pat) else {
            syn::visit::visit_local(self, local);
            return;
        };
        if let Some(init) = &local.init {
            let mut calls = VaultFromValuesAllowlistFlow {
                values: self.values.clone(),
                ..VaultFromValuesAllowlistFlow::default()
            };
            calls.visit_expr(&init.expr);
            if calls.parser_calls == 1 && calls.canonical_parser_calls == 1 {
                self.allowlist_bindings.insert(binding.to_string());
            }
            struct ProviderCalls(usize);
            impl<'ast> Visit<'ast> for ProviderCalls {
                fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                    self.0 += usize::from(path_ends_with(
                        &call.func,
                        &["VaultProviderConfig", "from_values"],
                    ));
                    syn::visit::visit_expr_call(self, call);
                }
            }
            let mut providers = ProviderCalls(0);
            providers.visit_expr(&init.expr);
            if providers.0 == 1 {
                self.provider_bindings.insert(binding.to_string());
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if path_ends_with(&call.func, &["tenant_store_allowlist_from_value"]) {
            self.parser_calls += 1;
            self.canonical_parser_calls += usize::from(
                call.args.len() == 1
                    && call.args.first().is_some_and(|argument| {
                        self.values.as_ref().is_some_and(|values| {
                            values_allowlist_argument_is_exact(argument, values)
                        })
                    }),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn tail_returns_canonical_vault_runtime_config(
    block: &syn::Block,
    providers: &BTreeSet<String>,
    allowlists: &BTreeSet<String>,
) -> bool {
    let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() else {
        return false;
    };
    matches!(transparent_expr(tail), syn::Expr::Call(call)
    if path_ends_with(&call.func, &["Ok"])
        && call.args.len() == 1
        && matches!(call.args.first().map(transparent_expr), Some(syn::Expr::Struct(value))
            if path_last_ident(&value.path).is_some_and(|ident| ident == "Self")
                && value.rest.is_none()
                && value.fields.len() == 2
                && value.fields.iter().all(|field| {
                    let syn::Member::Named(member) = &field.member else { return false; };
                    let syn::Expr::Path(path) = transparent_expr(&field.expr) else { return false; };
                    let Some(binding) = path.path.get_ident().map(ToString::to_string) else { return false; };
                    (member == "provider" && providers.contains(&binding))
                        || (member == "stores" && allowlists.contains(&binding))
                })))
}

fn vault_runtime_from_values_allowlist_flow_is_exact(vault: &syn::File) -> bool {
    let methods = production_owner_methods_named(vault, "VaultRuntimeConfig", "from_values");
    let [method] = methods.as_slice() else {
        return false;
    };
    let inputs = method.sig.inputs.iter().collect::<Vec<_>>();
    let Some(values) = inputs.first().and_then(|input| match input {
        syn::FnArg::Typed(input) if compact_type_tokens(&input.ty) == "VaultConfigValues<'_>" => {
            immutable_pat_ident(&input.pat).cloned()
        }
        _ => None,
    }) else {
        return false;
    };
    if inputs.len() != 1
        || !matches!(&method.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty) == "Result<Self,VaultRuntimeConfigError>")
    {
        return false;
    }
    let mut flow = VaultFromValuesAllowlistFlow {
        values: Some(values),
        ..VaultFromValuesAllowlistFlow::default()
    };
    flow.visit_block(&method.block);
    flow.parser_calls == 1
        && flow.canonical_parser_calls == 1
        && flow.allowlist_bindings.len() == 1
        && flow.provider_bindings.len() == 1
        && tail_returns_canonical_vault_runtime_config(
            &method.block,
            &flow.provider_bindings,
            &flow.allowlist_bindings,
        )
}

fn expression_is_field_of(expr: &syn::Expr, binding: &syn::Ident, field_name: &str) -> bool {
    matches!(transparent_expr(expr), syn::Expr::Field(field)
        if matches!(&field.member, syn::Member::Named(member) if member == field_name)
            && is_exact_ident_path(&field.base, binding))
}

fn reference_is_field_of(expr: &syn::Expr, binding: &syn::Ident, field_name: &str) -> bool {
    matches!(transparent_expr(expr), syn::Expr::Reference(reference)
        if reference.mutability.is_none()
            && expression_is_field_of(&reference.expr, binding, field_name))
}

fn error_mapper_is(expr: &syn::Expr, variant: &str) -> bool {
    let syn::Expr::Closure(mapper) = transparent_expr(expr) else {
        return false;
    };
    mapper.inputs.len() == 1
        && matches!(transparent_expr(&mapper.body), syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == variant))
}

fn parsed_field_local_is(
    local: &syn::Local,
    parser: &[&str],
    source: &syn::Ident,
    field_name: &str,
    error_variant: &str,
) -> Option<syn::Ident> {
    let binding = immutable_pat_ident(&local.pat)?.clone();
    let init = local.init.as_ref()?;
    let syn::Expr::Try(try_) = transparent_expr(&init.expr) else {
        return None;
    };
    let syn::Expr::MethodCall(map_err) = transparent_expr(&try_.expr) else {
        return None;
    };
    let syn::Expr::Call(parse) = transparent_expr(&map_err.receiver) else {
        return None;
    };
    (map_err.method == "map_err"
        && map_err.args.len() == 1
        && map_err
            .args
            .first()
            .is_some_and(|mapper| error_mapper_is(mapper, error_variant))
        && path_ends_with(&parse.func, parser)
        && parse.args.len() == 1
        && parse
            .args
            .first()
            .is_some_and(|argument| reference_is_field_of(argument, source, field_name)))
    .then_some(binding)
}

fn store_id_owned_expression_is(expr: &syn::Expr, store: &syn::Ident) -> bool {
    let syn::Expr::MethodCall(to_owned) = transparent_expr(expr) else {
        return false;
    };
    let syn::Expr::MethodCall(as_str) = transparent_expr(&to_owned.receiver) else {
        return false;
    };
    to_owned.method == "to_owned"
        && to_owned.args.is_empty()
        && as_str.method == "as_str"
        && as_str.args.is_empty()
        && is_exact_ident_path(&as_str.receiver, store)
}

fn mapped_binding_tail_is(
    statement: &syn::Stmt,
    source: &syn::Ident,
    tenant: &syn::Ident,
    store: &syn::Ident,
) -> bool {
    let syn::Stmt::Expr(expression, None) = statement else {
        return false;
    };
    let syn::Expr::Call(ok) = transparent_expr(expression) else {
        return false;
    };
    let Some(syn::Expr::Tuple(pair)) = ok.args.first().map(transparent_expr) else {
        return false;
    };
    let Some(syn::Expr::Tuple(key)) = pair.elems.first().map(transparent_expr) else {
        return false;
    };
    let Some(syn::Expr::Struct(binding)) = pair.elems.iter().nth(1).map(transparent_expr) else {
        return false;
    };
    path_ends_with(&ok.func, &["Ok"])
        && ok.args.len() == 1
        && pair.elems.len() == 2
        && key.elems.len() == 2
        && key
            .elems
            .first()
            .is_some_and(|expr| is_exact_ident_path(expr, tenant))
        && key
            .elems
            .iter()
            .nth(1)
            .is_some_and(|expr| store_id_owned_expression_is(expr, store))
        && path_last_ident(&binding.path).is_some_and(|ident| ident == "StoreBinding")
        && binding.rest.is_none()
        && binding.fields.len() == 2
        && binding.fields.iter().all(|field| {
            matches!(&field.member, syn::Member::Named(member)
                if (member == "mount" || member == "kv_path_prefix")
                    && expression_is_field_of(&field.expr, source, &member.to_string()))
        })
}

fn binding_mapper_block_is_exact(block: &syn::Block, source: &syn::Ident) -> bool {
    let tenants = block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => parsed_field_local_is(
                local,
                &["TenantId", "parse"],
                source,
                "tenant_id",
                "InvalidTenantId",
            ),
            _ => None,
        })
        .collect::<Vec<_>>();
    let stores = block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => parsed_field_local_is(
                local,
                &["settings", "ports", "StoreId", "parse"],
                source,
                "store_id",
                "InvalidStoreId",
            ),
            _ => None,
        })
        .collect::<Vec<_>>();
    let ([tenant], [store], Some(tail)) =
        (tenants.as_slice(), stores.as_slice(), block.stmts.last())
    else {
        return false;
    };
    mapped_binding_tail_is(tail, source, tenant, store)
}

fn binding_map_is_exact(call: &syn::ExprMethodCall, wire: &syn::Ident, vault: &syn::File) -> bool {
    let syn::Expr::MethodCall(into_iter) = transparent_expr(&call.receiver) else {
        return false;
    };
    let syn::Expr::Field(bindings) = transparent_expr(&into_iter.receiver) else {
        return false;
    };
    let mapper_is_exact = match call.args.first().map(transparent_expr) {
        Some(syn::Expr::Closure(mapper)) => {
            let Some(source) = mapper.inputs.first().and_then(immutable_pat_ident) else {
                return false;
            };
            matches!(transparent_expr(&mapper.body), syn::Expr::Block(body)
                if mapper.inputs.len() == 1
                    && binding_mapper_block_is_exact(&body.block, source))
        }
        Some(syn::Expr::Path(path)) => {
            let Some(name) = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
            else {
                return false;
            };
            let Some(function) = production_function_named(vault, &name) else {
                return false;
            };
            let inputs = function.sig.inputs.iter().collect::<Vec<_>>();
            let Some(source) = function_typed_input_ident(function, 0) else {
                return false;
            };
            inputs.len() == 1
                && matches!(inputs[0], syn::FnArg::Typed(input)
                    if compact_type_tokens(&input.ty) == "VaultTenantStoreBindingWire")
                && matches!(&function.sig.output, syn::ReturnType::Type(_, output)
                    if compact_type_tokens(output)
                        == "Result<((TenantId,String),StoreBinding),VaultTenantStoreAllowlistConfigError>")
                && binding_mapper_block_is_exact(&function.block, source)
        }
        _ => false,
    };
    call.method == "map"
        && call.args.len() == 1
        && into_iter.method == "into_iter"
        && into_iter.args.is_empty()
        && matches!(&bindings.member, syn::Member::Named(member) if member == "bindings")
        && is_exact_ident_path(&bindings.base, wire)
        && mapper_is_exact
}

fn binding_collection_is_exact(expr: &syn::Expr, wire: &syn::Ident, vault: &syn::File) -> bool {
    let syn::Expr::Try(result) = transparent_expr(expr) else {
        return false;
    };
    let syn::Expr::MethodCall(collect) = transparent_expr(&result.expr) else {
        return false;
    };
    let syn::Expr::MethodCall(map) = transparent_expr(&collect.receiver) else {
        return false;
    };
    collect.method == "collect" && collect.args.is_empty() && binding_map_is_exact(map, wire, vault)
}

fn expression_has_single_call_with_argument(
    expr: &syn::Expr,
    callee: &[&str],
    argument: &syn::Ident,
) -> bool {
    struct Calls<'a> {
        callee: &'a [&'a str],
        argument: &'a syn::Ident,
        total: usize,
        canonical: usize,
    }
    impl<'ast> Visit<'ast> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if path_ends_with(&call.func, self.callee) {
                self.total += 1;
                self.canonical += usize::from(
                    call.args.len() == 1
                        && call
                            .args
                            .first()
                            .is_some_and(|arg| is_exact_ident_path(arg, self.argument)),
                );
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls {
        callee,
        argument,
        total: 0,
        canonical: 0,
    };
    calls.visit_expr(expr);
    calls.total == 1 && calls.canonical == 1
}

fn required_option_local_is(local: &syn::Local, input: &syn::Ident) -> Option<syn::Ident> {
    let binding = immutable_pat_ident(&local.pat)?.clone();
    let init = local.init.as_ref()?;
    let syn::Expr::Try(try_) = transparent_expr(&init.expr) else {
        return None;
    };
    let syn::Expr::MethodCall(ok_or) = transparent_expr(&try_.expr) else {
        return None;
    };
    (ok_or.method == "ok_or"
        && ok_or.args.len() == 1
        && is_exact_ident_path(&ok_or.receiver, input)
        && ok_or.args.first().is_some_and(|error| {
            matches!(transparent_expr(error), syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "Missing"))
        }))
    .then_some(binding)
}

fn tenant_store_allowlist_parser_is_exact(vault: &syn::File) -> bool {
    let functions = production_functions_named(vault, "tenant_store_allowlist_from_value");
    let [function] = functions.as_slice() else {
        return false;
    };
    let inputs = function.sig.inputs.iter().collect::<Vec<_>>();
    let Some(input) = inputs.first().and_then(|argument| match argument {
        syn::FnArg::Typed(input) if compact_type_tokens(&input.ty) == "Option<&str>" => {
            immutable_pat_ident(&input.pat)
        }
        syn::FnArg::Receiver(_) => None,
        _ => None,
    }) else {
        return false;
    };
    if !is_pub_crate(&function.vis)
        || inputs.len() != 1
        || !matches!(&function.sig.output, syn::ReturnType::Type(_, ty)
            if compact_type_tokens(ty)
                == "Result<TenantStoreAllowlist,VaultTenantStoreAllowlistConfigError>")
    {
        return false;
    }
    let required_inputs = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => required_option_local_is(local, input),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [document] = required_inputs.as_slice() else {
        return false;
    };
    let wire_locals = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => match &local.pat {
                syn::Pat::Type(typed)
                    if compact_type_tokens(&typed.ty) == "VaultTenantStoreAllowlistWire" =>
                {
                    Some((immutable_pat_ident(&typed.pat)?, local.init.as_ref()?))
                }
                _ => None,
            },
            _ => None,
        })
        .filter(|(_, init)| {
            expression_has_single_call_with_argument(
                &init.expr,
                &["serde_json", "from_str"],
                document,
            )
        })
        .collect::<Vec<_>>();
    let [(wire, _)] = wire_locals.as_slice() else {
        return false;
    };
    let binding_locals = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => {
                Some((immutable_pat_ident(&local.pat)?, local.init.as_ref()?))
            }
            _ => None,
        })
        .filter(|(_, init)| binding_collection_is_exact(&init.expr, wire, vault))
        .collect::<Vec<_>>();
    let [(bindings, _)] = binding_locals.as_slice() else {
        return false;
    };
    function.block.stmts.last().is_some_and(|statement| {
        let syn::Stmt::Expr(expr, None) = statement else {
            return false;
        };
        expression_has_single_call_with_argument(expr, &["TenantStoreAllowlist", "new"], bindings)
    })
}

fn production_function_named<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    let functions = production_functions_named(file, name);
    matches!(functions.as_slice(), [_]).then_some(functions[0])
}

fn production_string_const(file: &syn::File, name: &str) -> Option<String> {
    let constants = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item)
                if item.ident == name && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [constant] = constants.as_slice() else {
        return None;
    };
    if compact_type_tokens(&constant.ty) != "&str" {
        return None;
    }
    match transparent_expr(&constant.expr) {
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Str(value) => Some(value.value()),
            _ => None,
        },
        _ => None,
    }
}

fn validator_input_enum_is_closed(file: &syn::File) -> bool {
    let enums = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item)
                if item.ident == "VaultAllowlistInput" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [input] = enums.as_slice() else {
        return false;
    };
    input.variants.len() == 2
        && input.variants.iter().any(|variant| {
            variant.ident == "File"
                && matches!(&variant.fields, syn::Fields::Unnamed(fields)
                    if fields.unnamed.len() == 1
                        && compact_type_tokens(&fields.unnamed[0].ty) == "&'astr")
        })
        && input
            .variants
            .iter()
            .any(|variant| variant.ident == "Stdin" && matches!(variant.fields, syn::Fields::Unit))
}

fn validator_error_categories_are_static(file: &syn::File) -> bool {
    let errors = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item)
                if item.ident == "VaultAllowlistValidationCommandError"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [error] = errors.as_slice() else {
        return false;
    };
    !error.variants.is_empty()
        && error.variants.iter().all(|variant| {
            matches!(variant.fields, syn::Fields::Unit)
                && variant
                    .attrs
                    .iter()
                    .filter(|attr| attr.path().is_ident("error"))
                    .count()
                    == 1
                && variant
                    .attrs
                    .iter()
                    .find(|attr| attr.path().is_ident("error"))
                    .is_some_and(|attr| {
                        attr.parse_args::<syn::LitStr>().is_ok_and(|message| {
                            let message = message.value();
                            !message.is_empty() && !message.contains(['{', '}'])
                        })
                    })
        })
}

fn validator_function_signature_is(file: &syn::File, name: &str, expected: syn::Signature) -> bool {
    production_function_named(file, name).is_some_and(|function| {
        let actual = &function.sig;
        actual.ident == expected.ident
            && actual.constness.is_none() == expected.constness.is_none()
            && actual.asyncness.is_none() == expected.asyncness.is_none()
            && actual.unsafety.is_none() == expected.unsafety.is_none()
            && actual.abi.is_none() == expected.abi.is_none()
            && actual.variadic.is_none() == expected.variadic.is_none()
            && compact_tokens(&actual.generics) == compact_tokens(&expected.generics)
            && actual.inputs.len() == expected.inputs.len()
            && actual
                .inputs
                .iter()
                .zip(&expected.inputs)
                .all(|(actual, expected)| match (actual, expected) {
                    (syn::FnArg::Receiver(actual), syn::FnArg::Receiver(expected)) => {
                        compact_tokens(actual) == compact_tokens(expected)
                    }
                    (syn::FnArg::Typed(actual), syn::FnArg::Typed(expected)) => {
                        compact_type_tokens(&actual.ty) == compact_type_tokens(&expected.ty)
                    }
                    _ => false,
                })
            && compact_tokens(&actual.output) == compact_tokens(&expected.output)
    })
}

fn function_typed_input_ident(function: &syn::ItemFn, index: usize) -> Option<&syn::Ident> {
    function
        .sig
        .inputs
        .iter()
        .nth(index)
        .and_then(|input| match input {
            syn::FnArg::Typed(input) => immutable_pat_ident(&input.pat),
            syn::FnArg::Receiver(_) => None,
        })
}

fn validator_match_body<'a>(
    function: &'a syn::ItemFn,
    input: &syn::Ident,
) -> Option<&'a syn::ExprMatch> {
    let Some(syn::Stmt::Expr(expression, None)) = function.block.stmts.last() else {
        return None;
    };
    match transparent_expr(expression) {
        syn::Expr::Match(expression) if is_exact_ident_path(&expression.expr, input) => {
            Some(expression)
        }
        _ => None,
    }
}

#[derive(Default)]
struct ValidatorArmInventory {
    file_outputs: usize,
    stdin_outputs: usize,
    input_selection_errors: usize,
    input_read_errors: usize,
    file_reads: usize,
    stdin_reads: usize,
    flags: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ValidatorArmInventory {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.file_outputs +=
            usize::from(path_ends_with(&call.func, &["VaultAllowlistInput", "File"]));
        self.file_reads +=
            usize::from(path_ends_with(&call.func, &["std", "fs", "read_to_string"]));
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.stdin_reads += usize::from(call.method == "read_to_string");
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.stdin_outputs += usize::from(path_ends_with(
            &syn::Expr::Path(path.clone()),
            &["VaultAllowlistInput", "Stdin"],
        ));
        self.input_selection_errors += usize::from(
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "InputSelection"),
        );
        self.input_read_errors += usize::from(
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "InputRead"),
        );
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_lit_str(&mut self, value: &'ast syn::LitStr) {
        if value.value().starts_with("--") {
            self.flags.insert(value.value());
        }
    }
}

fn validator_arm_inventory(arm: &syn::Arm) -> ValidatorArmInventory {
    let mut inventory = ValidatorArmInventory::default();
    inventory.visit_arm(arm);
    inventory
}

fn validator_input_selection_is_closed(file: &syn::File) -> bool {
    let Some(function) = production_function_named(file, "parse_input") else {
        return false;
    };
    let Some(args) = function_typed_input_ident(function, 0) else {
        return false;
    };
    let Some(selection) = validator_match_body(function, args) else {
        return false;
    };
    let arms = selection
        .arms
        .iter()
        .map(validator_arm_inventory)
        .collect::<Vec<_>>();
    let combined = arms
        .iter()
        .fold(ValidatorArmInventory::default(), |mut all, arm| {
            all.file_outputs += arm.file_outputs;
            all.stdin_outputs += arm.stdin_outputs;
            all.input_selection_errors += arm.input_selection_errors;
            all.input_read_errors += arm.input_read_errors;
            all.file_reads += arm.file_reads;
            all.stdin_reads += arm.stdin_reads;
            all.flags.extend(arm.flags.iter().cloned());
            all
        });
    combined.file_outputs == 1
        && combined.stdin_outputs == 1
        && combined.input_selection_errors == 1
        && combined.flags == BTreeSet::from(["--file".to_owned(), "--stdin".to_owned()])
        && arms
            .iter()
            .all(|arm| arm.file_outputs + arm.stdin_outputs + arm.input_selection_errors == 1)
}

fn validator_input_reader_is_closed(file: &syn::File) -> bool {
    let Some(function) = production_function_named(file, "read_input") else {
        return false;
    };
    let Some(input) = function_typed_input_ident(function, 0) else {
        return false;
    };
    let Some(reader) = validator_match_body(function, input) else {
        return false;
    };
    let arms = reader
        .arms
        .iter()
        .map(validator_arm_inventory)
        .collect::<Vec<_>>();
    let file_arms = arms
        .iter()
        .filter(|arm| arm.file_reads == 1 && arm.input_read_errors == 1)
        .count();
    let stdin_arms = arms
        .iter()
        .filter(|arm| arm.stdin_reads == 1 && arm.input_read_errors == 1)
        .count();
    file_arms == 1
        && stdin_arms == 1
        && arms
            .iter()
            .all(|arm| arm.input_read_errors == 1 && arm.file_reads + arm.stdin_reads == 1)
}

fn reachable_validator_functions<'a>(
    file: &'a syn::File,
    root: &str,
) -> Option<Vec<&'a syn::ItemFn>> {
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if attrs_may_be_production(&function.attrs) => {
                Some((function.sig.ident.to_string(), function))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    functions.get(root)?;
    let known = functions.keys().cloned().collect::<BTreeSet<_>>();
    let mut reachable = BTreeSet::from([root.to_owned()]);
    let mut queue = VecDeque::from([root.to_owned()]);
    while let Some(name) = queue.pop_front() {
        struct Calls<'a> {
            known: &'a BTreeSet<String>,
            calls: BTreeSet<String>,
        }
        impl<'ast> Visit<'ast> for Calls<'_> {
            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                if let Some(name) = path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    && self.known.contains(&name)
                {
                    self.calls.insert(name);
                }
                syn::visit::visit_expr_path(self, path);
            }
        }
        let mut calls = Calls {
            known: &known,
            calls: BTreeSet::new(),
        };
        calls.visit_block(&functions[&name].block);
        for call in calls.calls {
            if reachable.insert(call.clone()) {
                queue.push_back(call);
            }
        }
    }
    Some(
        reachable
            .into_iter()
            .filter_map(|name| functions.get(&name).copied())
            .collect(),
    )
}

#[derive(Default)]
struct ValidatorSemanticInventory {
    parse_input: usize,
    read_input: usize,
    typed_parser: usize,
    process_runner: usize,
    stdin: usize,
    stdout: usize,
    static_writes: usize,
    other_writes: usize,
    output_write_errors: usize,
}

impl<'ast> Visit<'ast> for ValidatorSemanticInventory {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.parse_input += usize::from(path_ends_with(&call.func, &["parse_input"]));
        self.read_input += usize::from(path_ends_with(&call.func, &["read_input"]));
        self.typed_parser += usize::from(path_ends_with(
            &call.func,
            &["tenant_store_allowlist_from_value"],
        ));
        self.process_runner += usize::from(path_ends_with(
            &call.func,
            &["run_vault_allowlist_validation_with_io"],
        ));
        self.stdin += usize::from(path_ends_with(&call.func, &["std", "io", "stdin"]));
        self.stdout += usize::from(path_ends_with(&call.func, &["std", "io", "stdout"]));
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.output_write_errors += usize::from(
            path.path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "OutputWrite"),
        );
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "writeln")
        {
            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            let is_static = parser.parse2(mac.tokens.clone()).is_ok_and(|arguments| {
                arguments.len() == 2
                    && matches!(arguments.iter().nth(1).map(transparent_expr),
                        Some(syn::Expr::Lit(literal))
                            if matches!(&literal.lit, syn::Lit::Str(value)
                                if value.value() == "{VALIDATION_SUCCEEDED}"))
            });
            self.static_writes += usize::from(is_static);
            self.other_writes += usize::from(!is_static);
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn validator_semantic_inventory(
    file: &syn::File,
    root: &str,
) -> Option<ValidatorSemanticInventory> {
    let functions = reachable_validator_functions(file, root)?;
    let mut inventory = ValidatorSemanticInventory::default();
    for function in functions {
        inventory.visit_block(&function.block);
    }
    Some(inventory)
}

fn validator_typed_flow_is_closed(file: &syn::File) -> bool {
    validator_semantic_inventory(file, "run_vault_allowlist_validation_with_io").is_some_and(
        |inventory| {
            inventory.parse_input == 1
                && inventory.read_input == 1
                && inventory.typed_parser == 1
                && inventory.static_writes == 1
                && inventory.other_writes == 0
                && inventory.output_write_errors == 1
        },
    )
}

fn validator_process_runner_is_closed(file: &syn::File) -> bool {
    validator_semantic_inventory(file, "run_vault_allowlist_validation_command").is_some_and(
        |inventory| inventory.process_runner == 1 && inventory.stdin == 1 && inventory.stdout == 1,
    )
}

fn validator_production_surface_has_no_forbidden_capability(file: &syn::File) -> bool {
    let tokens = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item) if attrs_may_be_production(&item.attrs) => {
                Some(compact_tokens(item))
            }
            syn::Item::Enum(item) if attrs_may_be_production(&item.attrs) => {
                Some(compact_tokens(item))
            }
            syn::Item::Fn(item) if attrs_may_be_production(&item.attrs) => {
                Some(compact_tokens(item))
            }
            syn::Item::Impl(item) if attrs_may_be_production(&item.attrs) => {
                Some(compact_tokens(item))
            }
            syn::Item::Use(item) if attrs_may_be_production(&item.attrs) => {
                Some(compact_tokens(item))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");
    [
        "std::env",
        "SnapshotConfig",
        "VaultRuntimeConfig",
        "VaultKeyProviderConfig",
        "VaultSecretResolver::new",
        "reqwest",
        "tokio",
        "RSS_VAULT",
        "println!",
        "eprintln!",
        "dbg!",
    ]
    .iter()
    .all(|forbidden| !tokens.contains(forbidden))
}

fn vault_allowlist_offline_validator_violations(
    vault: &syn::File,
    validator: &syn::File,
) -> Vec<&'static str> {
    let mut violations = Vec::new();
    if !tenant_store_allowlist_parser_is_exact(vault) {
        violations.push("shared-parser-definition");
    }
    if !validator_input_enum_is_closed(validator) {
        violations.push("input-enum-file-stdin-only");
    }
    if !validator_error_categories_are_static(validator) {
        violations.push("static-unit-error-categories");
    }
    for (name, expected, violation) in [
        (
            "is_vault_allowlist_validation_command",
            syn::parse_quote!(fn is_vault_allowlist_validation_command(args: &[String]) -> bool),
            "command-signature",
        ),
        (
            "parse_input",
            syn::parse_quote!(fn parse_input(args: &[String]) -> Result<VaultAllowlistInput<'_>, VaultAllowlistValidationCommandError>),
            "parse-input-signature",
        ),
        (
            "read_input",
            syn::parse_quote!(fn read_input(input: VaultAllowlistInput<'_>, stdin: &mut impl std::io::Read) -> Result<String, VaultAllowlistValidationCommandError>),
            "read-input-signature",
        ),
        (
            "run_vault_allowlist_validation_with_io",
            syn::parse_quote!(fn run_vault_allowlist_validation_with_io(args: &[String], stdin: &mut impl std::io::Read, stdout: &mut impl std::io::Write) -> Result<(), VaultAllowlistValidationCommandError>),
            "typed-flow-signature",
        ),
        (
            "run_vault_allowlist_validation_command",
            syn::parse_quote!(fn run_vault_allowlist_validation_command(args: &[String]) -> anyhow::Result<()>),
            "process-runner-signature",
        ),
    ] {
        if !validator_function_signature_is(validator, name, expected) {
            violations.push(violation);
            break;
        }
    }
    if production_function_named(validator, "is_vault_allowlist_validation_command").is_none_or(
        |function| !compact_tokens(&function.block).contains("command==VAULT_ALLOWLIST_CLI"),
    ) {
        violations.push("command-namespace");
    }
    if !validator_input_selection_is_closed(validator) {
        violations.push("input-selection");
    }
    if !validator_input_reader_is_closed(validator) {
        violations.push("input-reader");
    }
    if !validator_typed_flow_is_closed(validator) {
        violations.push("raw-parser-static-output-flow");
    }
    if !validator_process_runner_is_closed(validator) {
        violations.push("process-io-runner");
    }
    if production_string_const(validator, "VAULT_ALLOWLIST_CLI").as_deref()
        != Some("vault-allowlist")
        || production_string_const(validator, "VAULT_ALLOWLIST_VALIDATE_CLI").as_deref()
            != Some("validate")
        || production_string_const(validator, "VALIDATION_SUCCEEDED").as_deref()
            != Some("vault allowlist validation succeeded")
    {
        violations.push("closed-command-and-success-literals");
    }
    if !validator_production_surface_has_no_forbidden_capability(validator) {
        violations.push("forbidden-ambient-provider-network-output-capability");
    }
    violations
}

#[derive(Default)]
struct VaultIntoRuntimeAllowlistFlow {
    canonical_destructures: usize,
    stores_binding: Option<syn::Ident>,
    resolver_calls: usize,
    canonical_resolver_calls: usize,
    constructor_calls: usize,
}

impl<'ast> Visit<'ast> for VaultIntoRuntimeAllowlistFlow {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Struct(pattern), Some(initializer)) = (
            &local.pat,
            local.init.as_ref().map(|init| transparent_expr(&init.expr)),
        ) && path_last_ident(&pattern.path).is_some_and(|ident| ident == "Self")
            && pattern.rest.is_none()
            && pattern.fields.len() == 2
            && is_exact_path(initializer, &["self"])
        {
            let mut fields = BTreeMap::new();
            for field in &pattern.fields {
                let (syn::Member::Named(member), syn::Pat::Ident(binding)) =
                    (&field.member, &*field.pat)
                else {
                    continue;
                };
                if binding.by_ref.is_none()
                    && binding.mutability.is_none()
                    && binding.subpat.is_none()
                {
                    fields.insert(member.to_string(), binding.ident.clone());
                }
            }
            if fields.len() == 2 && fields.contains_key("provider") && fields.contains_key("stores")
            {
                self.canonical_destructures += 1;
                self.stores_binding = fields.get("stores").cloned();
            }
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let is_resolver_constructor = matches!(transparent_expr(&call.func), syn::Expr::Path(path)
            if path_is_vault_secret_resolver_constructor(&path.path));
        if is_resolver_constructor {
            self.resolver_calls += 1;
            self.canonical_resolver_calls += usize::from(
                path_ends_with(&call.func, &["VaultSecretResolver", "new"])
                    && call.args.len() == 5
                    && call.args.last().is_some_and(|arg| {
                        self.stores_binding
                            .as_ref()
                            .is_some_and(|stores| is_exact_ident_path(arg, stores))
                    }),
            );
        }
        self.constructor_calls +=
            usize::from(path_ends_with(&call.func, &["TenantStoreAllowlist", "new"]));
        syn::visit::visit_expr_call(self, call);
    }
}

fn vault_into_runtime_allowlist_flow_is_exact(vault: &syn::File) -> bool {
    let methods = production_owner_methods_named(vault, "VaultRuntimeConfig", "into_runtime");
    let [method] = methods.as_slice() else {
        return false;
    };
    if !matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
        if receiver.reference.is_none() && receiver.mutability.is_none())
        || method.sig.inputs.len() != 1
    {
        return false;
    }
    let mut flow = VaultIntoRuntimeAllowlistFlow::default();
    flow.visit_block(&method.block);
    flow.canonical_destructures == 1
        && flow.resolver_calls == 1
        && flow.canonical_resolver_calls == 1
        && flow.constructor_calls == 0
}

fn vault_maintenance_config_excludes_allowlist(vault: &syn::File) -> bool {
    if !production_struct_is_exact(
        vault,
        "VaultKeyProviderConfig",
        &[("provider", "VaultProviderConfig")],
    ) || !production_struct_is_exact(
        vault,
        "VaultProviderValues",
        &[
            ("addr", "Option<String>"),
            ("token", "Option<&'astr>"),
            ("transit_mount", "Option<String>"),
            ("ca_cert_pem_path", "Option<&'astr>"),
            ("settings_key_name", "Option<&'astr>"),
        ],
    ) || production_type_has_default(vault, "VaultKeyProviderConfig")
        || !production_enum_excludes_ident(vault, "VaultKeyProviderConfigError", "Allowlist")
    {
        return false;
    }
    let methods = production_owner_methods_named(vault, "VaultKeyProviderConfig", "from_snapshot");
    let [method] = methods.as_slice() else {
        return false;
    };
    let mut inventory = VaultAllowlistProductionInventory::default();
    inventory.visit_block(&method.block);
    inventory.key_references == 0
        && inventory.allowlist_parser_calls == 0
        && inventory.allowlist_constructor_calls == 0
        && inventory.resolver_constructor_calls == 0
}

fn vault_allowlist_typed_funnel_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let config_path = root.join(RUNTIME_CONFIG_PATH);
    let vault_path = root.join(RUNTIME_VAULT_PATH);
    let validator_path = root.join(RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH);
    let missing = [
        (RUNTIME_CONFIG_PATH, &config_path),
        (RUNTIME_VAULT_PATH, &vault_path),
        (RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH, &validator_path),
    ]
    .into_iter()
    .filter_map(|(relative, path)| (!path.exists()).then_some(relative))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Ok(vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_SRC_PATH,
            format!("Vault tenant/store allowlist required carriers are missing: {missing:?}"),
        )]);
    }
    let config = parse_rust_file(&config_path)?;
    let vault = parse_rust_file(&vault_path)?;
    let validator = parse_rust_file(&validator_path)?;
    let validator_violations = vault_allowlist_offline_validator_violations(&vault, &validator);
    let production_graph_violations = vault_allowlist_production_graph_violations(root)?;
    let runtime_type_is_exact = production_struct_is_exact(
        &vault,
        "VaultRuntimeConfig",
        &[
            ("provider", "VaultProviderConfig"),
            ("stores", "TenantStoreAllowlist"),
        ],
    ) && !production_type_has_default(&vault, "VaultRuntimeConfig");
    let values_type_is_exact = production_struct_is_exact(
        &vault,
        "VaultConfigValues",
        &[
            ("addr", "Option<String>"),
            ("token", "Option<&'astr>"),
            ("transit_mount", "Option<String>"),
            ("ca_cert_pem_path", "Option<&'astr>"),
            ("settings_key_name", "Option<&'astr>"),
            ("tenant_store_allowlist_json", "Option<&'astr>"),
        ],
    );
    let canonical = fixed_serving_allowlist_key_is_exact(&config)
        && vault_allowlist_key_constant_is_exact(&vault)
        && runtime_type_is_exact
        && values_type_is_exact
        && vault_runtime_snapshot_allowlist_flow_is_exact(&vault)
        && vault_runtime_from_values_allowlist_flow_is_exact(&vault)
        && tenant_store_allowlist_parser_is_exact(&vault)
        && validator_violations.is_empty()
        && production_graph_violations.is_empty()
        && vault_into_runtime_allowlist_flow_is_exact(&vault)
        && vault_maintenance_config_excludes_allowlist(&vault);
    if canonical {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        RUNTIME_VAULT_PATH,
        format!(
            "Vault tenant/store allowlist must flow exactly once from the closed snapshot key through the typed JSON parser and private non-Optional VaultRuntimeConfig field into the sole resolver constructor; the closed file/stdin validator must reuse that parser before runtime preparation with static output; maintenance must use the allowlist-free VaultKeyProviderConfig; validator violations={validator_violations:?}, production graph violations={production_graph_violations:?}",
        ),
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
    let support_path = root.join(RUNTIME_TEST_SUPPORT_PATH);
    let exact_wrappers = if support_path.exists() {
        vault_s3_test_support_file_is_exact(&parse_rust_file(&support_path)?)
            && (!root.join("Cargo.toml").exists()
                || integration_test_support_module_is_exact(runtime_file))
    } else {
        !root.join("Cargo.toml").exists() && vault_s3_test_support_wrappers_are_exact(runtime_file)
    };
    if exact_internal && exact_wrappers {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        RUNTIME_LIB_PATH,
        format!(
            "Vault/S3 explicit-values seams must retain their exact cfg(any(test, feature = \"integration\")) internal signatures and typed bodies; public test_support wrappers must retain exact cfg(feature = \"integration\") signatures and single direct delegation; internal={exact_internal} wrappers={exact_wrappers}"
        ),
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
            (_, Some("connect_maintenance")) => {
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
    let dlq = name == "ProductionDlqControlRuntime";
    fields.named.len() == if dlq { 3 } else { 2 }
        && fields.named.iter().any(|field| {
            field.ident.as_ref().is_some_and(|ident| ident == "config")
                && type_last_ident(&field.ty).is_some_and(|ident| ident == "SnapshotConfig")
                && matches!(field.vis, syn::Visibility::Inherited)
        })
        && (!dlq
            || fields.named.iter().any(|field| {
                field
                    .ident
                    .as_ref()
                    .is_some_and(|ident| ident == "projection_capture")
                    && type_last_ident(&field.ty)
                        .is_some_and(|ident| ident == "ProjectionCaptureView")
                    && matches!(field.vis, syn::Visibility::Inherited)
            }))
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
        let dlq = self.runtime_type == "ProductionDlqControlRuntime";
        is_exact_syn_path(&runtime.path, &[self.runtime_type])
            && runtime.rest.is_none()
            && runtime.fields.len() == if dlq { 3 } else { 2 }
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
            }) && (!dlq || runtime.fields.iter().any(|field| {
            matches!(&field.member, syn::Member::Named(member) if member == "projection_capture")
                && compact_tokens(&field.expr) == "plan.workflow_runtime().projection_capture()"
        }))
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
        let expected_config_calls = if self.runtime_type == "ProductionDlqControlRuntime" {
            2
        } else {
            1
        };
        self.config_calls == expected_config_calls
            && self.canonical_config_calls == expected_config_calls
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
            && path_ends_with(&call.func, &["VaultKeyProviderConfig", "from_snapshot"])
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
        if path_ends_with(&call.func, &["VaultKeyProviderConfig", "from_snapshot"]) {
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
        if call.method == "into_key_provider" {
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

#[cfg(test)]
fn pg_operator_definitions_are_exact(file: &syn::File) -> bool {
    let specs = [
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
    specs
        .iter()
        .all(|(name, wrapper)| pg_operator_definition_is_exact(file, name, *wrapper))
}

type PgOperatorWrapperSpec = (&'static str, &'static str, &'static str, &'static str);

fn pg_operator_definition_is_exact(
    file: &syn::File,
    name: &str,
    wrapper: Option<PgOperatorWrapperSpec>,
) -> bool {
    let functions = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == name && attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(function) = (functions.len() == 1).then(|| functions.first()).flatten() else {
        return false;
    };
    let Some((_, runtime_inputs)) = pg_operator_signature_bindings(function, name) else {
        return false;
    };
    match wrapper {
        Some((runtime_type, runtime_trait, builder, with_runtime)) => pg_operator_wrapper_is_exact(
            file,
            function,
            &runtime_inputs,
            runtime_type,
            runtime_trait,
            builder,
            with_runtime,
        ),
        None if name == "run_settings_config_value_maintenance" => {
            settings_config_value_maintenance_is_exact(file, function, &runtime_inputs)
        }
        None => direct_pg_operator_is_exact(function, &runtime_inputs, 1),
    }
}

fn pg_operator_module_graph_is_exact(files: &BTreeMap<String, syn::File>) -> bool {
    [
        (
            RUNTIME_OPERATOR_PROJECTION_PATH,
            "run_projection_control_command",
            Some((
                "ProductionProjectionControlRuntime",
                "ProjectionControlRuntime",
                "build_pg_migrator_config",
                "run_projection_control_command_with_runtime",
            )),
        ),
        (
            RUNTIME_OPERATOR_AUDIT_PATH,
            "run_audit_ledger_verify_command",
            Some((
                "ProductionAuditLedgerVerifyRuntime",
                "AuditLedgerVerifyRuntime",
                "build_pg_audit_maintenance_config",
                "run_audit_ledger_verify_command_with_runtime",
            )),
        ),
        (
            RUNTIME_OPERATOR_DLQ_PATH,
            "run_dlq_control_command",
            Some((
                "ProductionDlqControlRuntime",
                "DlqControlRuntime",
                "build_pg_migrator_config",
                "run_dlq_control_command_with_runtime",
            )),
        ),
        (
            RUNTIME_OPERATOR_RECONCILE_PATH,
            "run_reconcile_target_command",
            None,
        ),
        (
            RUNTIME_OPERATOR_SETTINGS_PATH,
            "run_settings_config_value_maintenance",
            None,
        ),
    ]
    .into_iter()
    .all(|(path, name, wrapper)| {
        files
            .get(path)
            .is_some_and(|file| pg_operator_definition_is_exact(file, name, wrapper))
    })
}

fn runtime_config_global_capture_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let production_sources = production_module_sources(&paths)?;
    let mut inventory = ProductionRuntimeConfigInventory::default();
    let mut forbidden_paths = Vec::new();
    let runtime_source = fs::read_to_string(root.join(RUNTIME_LIB_PATH))?;
    let legacy_fixture = root.join(RUNTIME_CONFIG_FIXTURE_MARKER).exists()
        && !root.join("Cargo.toml").exists()
        && !mask_comments_and_strings(&runtime_source).contains("phase::execute(");
    for path in paths {
        if !production_sources.contains(&normalize_path(&path)) {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(&path);
        if legacy_fixture
            && (relative == Path::new(RUNTIME_PHASE_PATH)
                || relative.starts_with(Path::new("assemblies/runtime/src/phase")))
        {
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
        if observed.forbidden_indirections != 0 {
            forbidden_paths.push(relative.display().to_string());
        }
        inventory.add(observed);
    }
    if inventory.is_exact() {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        RUNTIME_SRC_PATH,
        format!(
            "runtime production module graph cardinality mismatch; protected aliases, UFCS, local function aliases, and macro indirection fail closed: {}; forbidden_paths={forbidden_paths:?}",
            inventory.diagnostic(),
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
    if methods.len() == 1 {
        Some(methods[0])
    } else {
        None
    }
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
    kernel_path: &[&str],
    local_path: &[&str],
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
    let statements = function.block.stmts.as_slice();
    let (Some(syn::Stmt::Local(prepared)), Some(syn::Stmt::Expr(result, None))) =
        (statements.first(), statements.last())
    else {
        return false;
    };
    if statements.len() != 2 {
        return false;
    }
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
    let result_is_canonical = if carries_password_blocklist {
        let syn::Expr::Call(ok) = transparent_expr(result) else {
            return false;
        };
        let Some(syn::Expr::Call(constructor)) = ok.args.first().map(transparent_expr) else {
            return false;
        };
        is_exact_path(&ok.func, &["Ok"])
            && ok.args.len() == 1
            && is_exact_path(&constructor.func, &[output_type, "new"])
            && constructor.args.len() == 2
            && constructor
                .args
                .first()
                .is_some_and(|arg| is_exact_ident_path(arg, prepared_binding))
            && password_binding.is_some_and(|password| {
                constructor
                    .args
                    .iter()
                    .nth(1)
                    .is_some_and(|arg| is_exact_ident_path(arg, password))
            })
    } else {
        let syn::Expr::Call(ok) = transparent_expr(result) else {
            return false;
        };
        let Some(syn::Expr::Call(constructor)) = ok.args.first().map(transparent_expr) else {
            return false;
        };
        is_exact_path(&ok.func, &["Ok"])
            && ok.args.len() == 1
            && is_exact_path(&constructor.func, &[output_type, "new"])
            && constructor.args.len() == 1
            && constructor
                .args
                .first()
                .is_some_and(|arg| is_exact_ident_path(arg, prepared_binding))
    };

    is_exact_path(&kernel_call.func, kernel_path)
        && kernel_call.args.len() == 1
        && kernel_call
            .args
            .first()
            .is_some_and(|arg| is_exact_path(arg, local_path))
        && result_is_canonical
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
                    &["prepare_runtime_kernel"],
                    &["prepare_serving_local"],
                    "ServingRuntimeInputs",
                    true,
                )
                && profile_prepare_function_is_canonical(
                    file,
                    "prepare_operator_runtime",
                    &["prepare_runtime_kernel"],
                    &["prepare_operator_local"],
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

    fn inspect_production(runtime: &syn::File, operator: &syn::File) -> Self {
        Self {
            prepare_wiring: profile_local_functions_are_canonical(runtime)
                && profile_prepare_function_is_canonical(
                    runtime,
                    "prepare_runtime",
                    &["prepare_runtime_kernel"],
                    &["prepare_serving_local"],
                    "ServingRuntimeInputs",
                    true,
                )
                && profile_prepare_function_is_canonical(
                    operator,
                    "prepare_runtime",
                    &["crate", "prepare_runtime_kernel"],
                    &["crate", "prepare_operator_local"],
                    "OperatorRuntimeInputs",
                    false,
                ),
            helper_shape: password_policy_preload_helper_is_canonical(runtime)
                && runtime_kernel_uses_ordered_helper(runtime),
            calls: production_exact_path_call_count_in_file(
                runtime,
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
    let run_wiring_is_canonical = run_wiring.is_canonical();
    let settings_wiring_is_canonical = settings_vault_snapshot_definition_is_exact(file);
    let lifecycle_owner_is_canonical = runtime_lifecycle_outer_is_canonical(file, runs[0]);
    let inventory_is_canonical = inventory.is_exact();

    if prepare_wiring_is_canonical
        && password_preload_helper_is_canonical
        && password_preload_calls_are_canonical
        && run_wiring_is_canonical
        && settings_wiring_is_canonical
        && lifecycle_owner_is_canonical
        && inventory_is_canonical
    {
        Vec::new()
    } else {
        vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            format!(
                "prepare_runtime() must seal its sole process snapshot and password blocklist into ServingRuntimeInputs while runtime::operator::prepare_runtime() constructs capability-free OperatorRuntimeInputs; the exact serving lifecycle owner must finish one run_startup result; run_startup must map exact PG/Redis/Vault/S3 generations, consume Vault/Redis and named S3 parts by value, preserve canonical PG setup, and route the DLX S3 part without aliases or bait; {}; prepare_ok={prepare_wiring_is_canonical}, password_helper_ok={password_preload_helper_is_canonical}, password_calls_ok={password_preload_calls_are_canonical}, run_ok={run_wiring_is_canonical}, settings_ok={settings_wiring_is_canonical}, lifecycle_ok={lifecycle_owner_is_canonical}, inventory_ok={inventory_is_canonical}; prepare={prepare_wiring:?}, run={run_wiring:?}, inventory={} ",
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
                    if !classifier_is_canonical(&file) {
                        "rss main must use the closed serving/offline/migrate-all/operator classifier before preparation"
                    } else if !rss_main_is_canonical(mains[0]) {
                        "rss main must isolate migrate-all before operator preparation; serving must inline the sole prepare_runtime -> run path, while stateful operators use the exact prepare/run/shutdown surface once"
                    } else {
                        "rss binary contains a forbidden runtime prepare/run/shutdown indirection outside the exact main funnel"
                    }
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
        let approved =
            match (callable, sink) {
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
                (Some("into_runtime" | "into_key_provider"), sink)
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
                    let approved = call.args.iter().nth(2).is_some_and(|arg| {
                        Self::method_arg(arg, "token", "copy_secret_allocation")
                    });
                    if approved {
                        *self.exact_sinks.entry("vault.copy").or_default() += 1;
                    }
                    approved
                }
                (Some("into_runtime"), sink) if sink.ends_with("VaultSigner::new") => {
                    let approved = call.args.iter().nth(2).is_some_and(|arg| {
                        Self::method_arg(arg, "token", "copy_secret_allocation")
                    });
                    if approved {
                        *self.exact_sinks.entry("vault.signer").or_default() += 1;
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
            Some("VaultConfigValues" | "VaultProviderValues") => {
                &[("token", "VAULT_TOKEN_ENV")][..]
            }
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
    let (inventory, env_secret_structs) =
        collect_runtime_secret_flow_inventory(root, require_complete)?;
    let mut findings = Vec::new();
    push_env_secret_shape_findings(
        &mut findings,
        &secret_file,
        &runtime_file,
        env_secret_structs,
    );
    push_sensitive_stage_count_findings(&mut findings, &inventory);
    push_exact_sink_count_findings(&mut findings, &inventory);
    push_secret_transfer_total_findings(&mut findings, &inventory);
    Ok(findings)
}

fn collect_runtime_secret_flow_inventory(
    root: &Path,
    require_complete: bool,
) -> Result<(SecretFlowInventory, usize)> {
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
    Ok((inventory, env_secret_structs))
}

fn push_env_secret_shape_findings(
    findings: &mut Vec<Finding<Rule>>,
    secret_file: &syn::File,
    runtime_file: &syn::File,
    env_secret_structs: usize,
) {
    if !exact_env_secret_shape(secret_file, runtime_file) || env_secret_structs != 1 {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_SECRET_CONFIG_PATH,
            format!(
                "carrier EnvSecret in runtime::secret_config is missing or has extra/non-opaque structure; expected one private zeroizing carrier and observed {env_secret_structs} EnvSecret definitions"
            ),
        ));
    }
}

fn push_sensitive_stage_count_findings(
    findings: &mut Vec<Finding<Rule>>,
    inventory: &SecretFlowInventory,
) {
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
        let expected = if label == "VAULT_TOKEN_ENV" {
            (2, 2, 1)
        } else {
            (1, 1, 1)
        };
        if (reads, mappings, conversions) != expected {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "source {label} in {function} has missing/extra stages; expected read={}, mapping={}, conversion={}, observed read={reads}, mapping={mappings}, conversion={conversions}",
                    expected.0, expected.1, expected.2,
                ),
            ));
        }
    }
}

fn push_exact_sink_count_findings(
    findings: &mut Vec<Finding<Rule>>,
    inventory: &SecretFlowInventory,
) {
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
            "VaultKeyProviderConfig::into_key_provider",
        ),
        (
            "vault.copy",
            RUNTIME_VAULT_PATH,
            "VaultRuntimeConfig::into_runtime",
        ),
        (
            "vault.signer",
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
}

fn push_secret_transfer_total_findings(
    findings: &mut Vec<Finding<Rule>>,
    inventory: &SecretFlowInventory,
) {
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

fn is_self_runtime_inputs_config_view(expr: &syn::Expr) -> bool {
    let syn::Expr::MethodCall(call) = transparent_expr(expr) else {
        return false;
    };
    call.method == "config"
        && call.args.is_empty()
        && matches!(transparent_expr(&call.receiver), syn::Expr::Field(field)
            if is_exact_path(&field.base, &["self"])
                && matches!(&field.member, syn::Member::Named(member) if member == "runtime_inputs"))
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

fn runtime_production_source_files(root: &Path) -> Result<BTreeMap<String, syn::File>> {
    let mut paths = Vec::new();
    collect_rust_sources(&root.join(RUNTIME_SRC_PATH), &mut paths)?;
    let production_sources = production_module_sources(&paths)?;
    let mut files = BTreeMap::new();
    for path in paths {
        if !production_sources.contains(&normalize_path(&path)) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&path)
            .with_context(|| format!("read typed runtime production owner {relative}"))?;
        let file = syn::parse_file(&source)
            .with_context(|| format!("parse typed runtime production owner {relative}"))?;
        files.insert(relative, file);
    }
    Ok(files)
}

fn runtime_phase_transition_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    // Small baseline text fixtures intentionally omit the compiled runtime module graph. Dedicated
    // phase fixtures and the real workspace carry a root Cargo.toml and therefore fail closed.
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }
    let paths = [
        RUNTIME_LIB_PATH,
        RUNTIME_PHASE_PATH,
        RUNTIME_PHASE_PROVIDER_PATH,
        RUNTIME_PHASE_INFRA_PATH,
        RUNTIME_PHASE_DOMAINS_PATH,
        RUNTIME_PHASE_FINALIZE_PATH,
        RUNTIME_PHASE_LAUNCH_PATH,
    ];
    let mut files = BTreeMap::new();
    for path in paths {
        let source = match fs::read_to_string(root.join(path)) {
            Ok(source) => source,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::MissingAnchor,
                    path,
                    format!("typed runtime phase owner missing: {error}"),
                )]);
            }
        };
        let file = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                return Ok(vec![finding(
                    Rule::ForbiddenWiring,
                    path,
                    format!("typed runtime phase gate 无法解析生产 Rust: {error}"),
                )]);
            }
        };
        files.insert(path, file);
    }

    let runtime = &files[RUNTIME_LIB_PATH];
    let phase = &files[RUNTIME_PHASE_PATH];
    let transition_specs = [
        (
            RUNTIME_PHASE_PROVIDER_PATH,
            "Planned",
            "build_providers",
            "ProvidersBuilt",
        ),
        (
            RUNTIME_PHASE_INFRA_PATH,
            "ProvidersBuilt",
            "build_infra",
            "InfraBuilt",
        ),
        (
            RUNTIME_PHASE_DOMAINS_PATH,
            "InfraBuilt",
            "wire_domains",
            "DomainsWired",
        ),
        (
            RUNTIME_PHASE_FINALIZE_PATH,
            "DomainsWired",
            "finalize",
            "Finalized",
        ),
        (
            RUNTIME_PHASE_LAUNCH_PATH,
            "Finalized",
            "launch",
            "RuntimeOutputs",
        ),
    ];
    let production_files = match runtime_production_source_files(root) {
        Ok(files) => files,
        Err(error) => {
            return Ok(vec![finding(
                Rule::ForbiddenWiring,
                RUNTIME_SRC_PATH,
                format!(
                    "typed runtime phase gate cannot inventory production module graph: {error:#}"
                ),
            )]);
        }
    };
    let mut findings = Vec::new();
    if !startup_phase_delegation_is_canonical(runtime) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_LIB_PATH,
            "predicate=startup_phase_delegation expected=unique run_startup -> phase::execute actual=non-canonical",
        ));
    }
    if !phase_state_definitions_are_canonical(phase) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PATH,
            "predicate=phase_state_definitions expected=private sealed RuntimePhaseState with exact five state/Next/PHASE implementations actual=non-canonical",
        ));
    }
    for (path, actual) in production_phase_state_impl_violations(&production_files) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            path,
            format!(
                "predicate=runtime_phase_state_impl_closure expected=RuntimePhaseState implementations are sealed and owned only by {RUNTIME_PHASE_PATH} actual={actual}"
            ),
        ));
    }
    if !phase_execute_is_canonical(phase) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PATH,
            "predicate=phase_execute expected=exact Planned -> ProvidersBuilt -> InfraBuilt -> DomainsWired -> Finalized -> RuntimeOutputs consuming chain actual=non-canonical",
        ));
    }
    if !phase_context_shape_is_canonical(phase) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PATH,
            "predicate=phase_context_shape expected=private PhaseContext owning exactly runtime_inputs and runtime_plan actual=non-canonical",
        ));
    }
    if !runtime_plan_flow_is_canonical(&files[RUNTIME_PHASE_PROVIDER_PATH]) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PROVIDER_PATH,
            "predicate=runtime_plan_flow expected=RuntimePlan::bundled and DomainExecutionPlan results move exactly once into DomainPhaseContext::new actual=non-canonical",
        ));
    }
    findings.extend(runtime_transition_method_findings(
        &files,
        &transition_specs,
    ));
    if !unique_production_inherent_method(&files[RUNTIME_PHASE_LAUNCH_PATH], "Finalized", "launch")
        .is_some_and(launch_pre_handoff_is_canonical)
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_LAUNCH_PATH,
            "predicate=launch_pre_handoff expected=request budget validation before exact LaunchPlan construction and launch handoff actual=non-canonical",
        ));
    }
    if !phase_result_redaction_is_canonical(phase) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_PATH,
            "predicate=phase_result_redaction expected=private result funnel with direct secure::redact_error failure log actual=non-canonical",
        ));
    }
    findings.extend(runtime_lifecycle_ownership_findings(
        &files,
        &production_files,
    ));
    Ok(findings)
}

fn runtime_transition_method_findings(
    files: &BTreeMap<&str, syn::File>,
    transition_specs: &[(&str, &str, &str, &str)],
) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for &(path, owner, method, _) in transition_specs {
        let transition = unique_production_inherent_method(&files[path], owner, method);
        if !transition.is_some_and(consuming_transition_is_canonical) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "predicate=transition_{method} expected=unique consuming {owner}::{method} returning associated RuntimePhaseState::Next actual=non-canonical"
                ),
            ));
        }
        if !transition.is_some_and(transition_phase_funnel_is_canonical) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "predicate=phase_funnel_{method} expected=single phase_result(<Self as RuntimePhaseState>::PHASE, result) tail call actual=non-canonical"
                ),
            ));
        }
        if production_exact_path_call_count_in_file(&files[path], &["drop"]) != 0
            || production_exact_path_call_count_in_file(&files[path], &["std", "mem", "drop"]) != 0
        {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "predicate=no_drop_{method} expected=no production drop/std::mem::drop call in transition owner actual=forbidden call present"
                ),
            ));
        }
    }
    findings
}

fn runtime_lifecycle_ownership_findings(
    files: &BTreeMap<&str, syn::File>,
    production_files: &BTreeMap<String, syn::File>,
) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    if production_files
        .get(RUNTIME_OPERATOR_PATH)
        .is_none_or(|file| !operator_module_ownership_is_closed(file))
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_OPERATOR_PATH,
            "predicate=operator_module_ownership expected=exact external command modules, no production private prelude, and explicit imports only; unresolved globs fail closed",
        ));
    }
    for (path, file) in production_files {
        let uses = production_lifecycle_primitive_uses(file, &[]);
        let is_canonical = if path == RUNTIME_PHASE_LAUNCH_PATH {
            uses.phase_execute == 0
                && uses.launch_plan == 1
                && uses.launch_plan_parts == 0
                && uses.runtime_outputs == 0
                && uses.shutdown_stack == 0
        } else if path == RUNTIME_PHASE_PATH {
            uses.phase_execute == 0
                && uses.launch_plan == 0
                && uses.launch_plan_parts == 0
                && uses.runtime_outputs == 2
                && uses.shutdown_stack == 0
        } else if path == PROVIDER_OUTPUT_PATH {
            uses.phase_execute == 0
                && uses.launch_plan == 0
                && uses.launch_plan_parts == 0
                && uses.runtime_outputs == 0
                && uses.shutdown_stack == 1
        } else if path == RUNTIME_LAUNCH_PATH {
            uses.phase_execute == 0 && uses.lifecycle_is_empty()
        } else if path == RUNTIME_LIB_PATH {
            uses.phase_execute == 1 && uses.lifecycle_is_empty()
        } else {
            uses.phase_execute == 0 && uses.lifecycle_is_empty()
        };
        if !is_canonical {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                format!(
                    "predicate=lifecycle_primitive_ownership expected=phase::execute only in {RUNTIME_LIB_PATH}; LaunchPlan/LaunchPlanParts only in {RUNTIME_PHASE_LAUNCH_PATH}; one ShutdownStack only in {PROVIDER_OUTPUT_PATH} for transactional abort actual={uses:?}"
                ),
            ));
        }
    }
    let launch_primitive_uses = production_files
        .get(RUNTIME_PHASE_LAUNCH_PATH)
        .map(|file| production_lifecycle_primitive_uses(file, &[]))
        .unwrap_or_default();
    if launch_primitive_uses.launch_plan != 1
        || launch_primitive_uses.launch_plan_parts != 0
        || launch_primitive_uses.shutdown_stack != 0
        || production_exact_path_call_count_in_file(
            &files[RUNTIME_PHASE_LAUNCH_PATH],
            &["runtimeexec", "LaunchPlan", "new"],
        ) != 1
        || production_exact_path_call_count_in_file(
            &files[RUNTIME_PHASE_LAUNCH_PATH],
            &["runtimeexec", "launch"],
        ) != 1
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_LAUNCH_PATH,
            format!(
                "predicate=launch_plan_ownership expected=one exact runtimeexec::LaunchPlan::new + runtimeexec::launch and no legacy LaunchPlanParts in launch phase actual={launch_primitive_uses:?}"
            ),
        ));
    }
    findings
}

fn runtime_launch_kernel_owner_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }
    let production_files = runtime_production_source_files(root)?;
    let kernel = match parse_rust_file(&root.join(RUNTIMEEXEC_PATH)) {
        Ok(file) => file,
        Err(error) => {
            return Ok(vec![finding(
                Rule::MissingAnchor,
                RUNTIMEEXEC_PATH,
                format!("runtimeexec launch kernel owner missing or invalid: {error:#}"),
            )]);
        }
    };
    let phase_launch = parse_rust_file(&root.join(RUNTIME_PHASE_LAUNCH_PATH))?;
    let adapter = parse_rust_file(&root.join(RUNTIME_LAUNCH_PATH))?;
    let mut findings = Vec::new();

    let structs = |name: &str| {
        kernel
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
            .collect::<Vec<_>>()
    };
    let exact_named_carrier = |name: &str, expected: &[&str]| {
        matches!(structs(name).as_slice(), [item]
            if matches!(item.vis, syn::Visibility::Public(_))
                && matches!(&item.fields, syn::Fields::Named(_))
                && item.fields.iter().all(|field| matches!(field.vis, syn::Visibility::Inherited))
                && item.fields.iter()
                    .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
                    .collect::<BTreeSet<_>>()
                    == expected.iter().map(|field| (*field).to_owned()).collect())
    };
    let exact_tuple_carrier = |name: &str, field_type: &str| {
        matches!(structs(name).as_slice(), [item]
            if matches!(item.vis, syn::Visibility::Public(_))
                && matches!(&item.fields, syn::Fields::Unnamed(fields)
                    if fields.unnamed.len() == 1
                        && matches!(fields.unnamed[0].vis, syn::Visibility::Inherited)
                        && compact_tokens(&fields.unnamed[0].ty) == field_type))
    };
    let owner_shape = exact_named_carrier(
        "LaunchPlan",
        &[
            "adapter",
            "probe_receipt",
            "on_ready",
            "trace_exporter",
            "lifecycle_batches",
        ],
    ) && exact_named_carrier("LaunchTransaction", &["stack"])
        && exact_named_carrier("LaunchRegistrar", &["stack", "listener_count"])
        && exact_named_carrier("Activated", &["inventory"])
        && exact_tuple_carrier("ProviderLifecycleBatch", "DomainModuleResult")
        && exact_tuple_carrier("DomainLifecycleBatch", "DomainModuleResult")
        && exact_named_carrier("LaunchLifecycleBatches", &["provider", "domain"])
        && exact_named_carrier("RuntimeOutputs", &["_completed"])
        && structs("LaunchPlanParts").is_empty()
        && unique_production_async_function(&kernel, "launch").is_some()
        && unique_production_async_function(&kernel, "launch_until").is_some()
        && unique_production_async_function(&kernel, "execute_launch").is_some()
        && unique_production_async_function(&kernel, "finish_launch").is_some()
        && unique_production_inherent_method(
            &kernel,
            "ProviderLifecycleBatch",
            "from_provider_output",
        )
        .is_some_and(|method| compact_tokens(&method.block) == "{Self(output)}")
        && unique_production_inherent_method(&kernel, "DomainLifecycleBatch", "from_domain_output")
            .is_some_and(|method| compact_tokens(&method.block) == "{Self(output)}")
        && unique_production_inherent_method(&kernel, "LaunchLifecycleBatches", "new")
            .is_some_and(|method| compact_tokens(&method.block) == "{Self{provider,domain}}");
    if !owner_shape {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIMEEXEC_PATH,
            "predicate=runtimeexec_owner_shape expected=private-field transaction/registrar/activated/typed-batch/plan carriers plus launch/launch_until/execute_launch/finish_launch; no LaunchPlanParts actual=non-canonical",
        ));
    }

    let kernel_tokens = compact_tokens(&kernel);
    let preserves_primary_launch_error = preserve_launch_error_is_canonical(&kernel);
    let lifecycle_checks = [
        (
            "stack-owner",
            production_exact_path_call_count_in_file(&kernel, &["ShutdownStack", "new"]) == 1,
        ),
        (
            "batch-transfer-call",
            production_exact_path_call_count_in_file(&kernel, &["register_lifecycle_outputs"]) == 4,
        ),
        (
            "module-transfer-calls",
            production_exact_path_call_count_in_file(&kernel, &["register_module_output"]) == 2,
        ),
        (
            "signal-call",
            production_exact_path_call_count_in_file(&kernel, &["wait_for_shutdown_signal"]) == 1,
        ),
        (
            "batch-transfer",
            kernel_tokens
                .contains("register_lifecycle_outputs(stack,trace_exporter,lifecycle_batches)?"),
        ),
        (
            "transaction-mint",
            kernel_tokens.contains("letmuttransaction=LaunchTransaction{stack}"),
        ),
        (
            "receipt-prepare",
            kernel_tokens.contains("adapter.prepare(probe_receipt,&muttransaction).await?"),
        ),
        (
            "registrar-activation",
            kernel_tokens.contains("Adapter::activate(prepared,transaction.commit())?"),
        ),
        (
            "activated-ready",
            kernel_tokens.contains("letreadiness=on_ready(activated.into_inventory())"),
        ),
        (
            "ready-signal-race",
            kernel_tokens.contains("result=&mutshutdown=>returnresult"),
        ),
        (
            "drain",
            kernel_tokens.contains("stack.shutdown_within(total_drain_budget.duration()).await"),
        ),
        (
            "staged-resource",
            kernel_tokens.contains("self.stack.register_detached(resource)"),
        ),
        (
            "empty-registrar",
            kernel_tokens.contains("listener_count:0"),
        ),
        (
            "registered-listener",
            kernel_tokens.contains("self.stack.register_with_token(make)"),
        ),
        (
            "closed-worker-admission-policy",
            kernel_tokens.contains(
                "WorkerSpec::PhaseOne(worker)=>stack.register_with_token(worker),WorkerSpec::Deferred(worker)=>stack.register_deferred_with_token(worker)",
            ),
        ),
        (
            "sole-runtime-root-token-mint",
            production_exact_path_call_count_in_file(&kernel, &["CancellationToken", "new"]) == 1,
        ),
        (
            "listener-count",
            kernel_tokens.contains("self.listener_count+=1"),
        ),
        (
            "nonempty-activation",
            kernel_tokens.contains("self.listener_count>0"),
        ),
        (
            "activated-capability",
            kernel_tokens.contains("Ok(Activated{inventory})"),
        ),
        (
            "typed-batch-destructure",
            kernel_tokens.contains("letLaunchLifecycleBatches{provider,domain}=lifecycle_batches"),
        ),
        (
            "provider-role",
            kernel_tokens.contains("register_module_output(stack,provider.0)"),
        ),
        (
            "domain-role",
            kernel_tokens.contains("register_module_output(stack,domain.0)"),
        ),
        (
            "batch-error-order",
            kernel_tokens.contains("provider_result?;domain_result"),
        ),
        (
            "dual-error-arm",
            kernel_tokens.contains("(Err(launch_error),Err(drain_error))"),
        ),
        ("primary-error", preserves_primary_launch_error),
    ];
    let missing_lifecycle = lifecycle_checks
        .iter()
        .filter_map(|(label, accepted)| (!accepted).then_some(*label))
        .collect::<Vec<_>>();
    if !missing_lifecycle.is_empty() {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIMEEXEC_PATH,
            format!(
                "predicate=runtimeexec_lifecycle expected=unique stack, staged prepare ownership, typed provider/domain transfer, non-empty registered activation, ready hook, signal and drain with primary-error preservation actual=missing {}",
                missing_lifecycle.join(",")
            ),
        ));
    }

    let phase_calls = production_exact_path_call_count_in_file(
        &phase_launch,
        &["runtimeexec", "LaunchPlan", "new"],
    ) == 1
        && production_exact_path_call_count_in_file(&phase_launch, &["runtimeexec", "launch"]) == 1;
    let global_launch_calls = production_files
        .values()
        .map(|file| production_exact_path_call_count_in_file(file, &["runtimeexec", "launch"]))
        .sum::<usize>();
    let phase_tokens = compact_tokens(&phase_launch);
    let phase_batches =
        phase_tokens.contains("letlifecycle_batches=provider_build.into_launch_batches()");
    let phase_plan = phase_tokens.contains(
        "runtimeexec::LaunchPlan::new(adapter,probe_receipt,|inventory|asyncmove{crate::launch::log_ready(inventory)},trace_exporter,lifecycle_batches,crate::launch::total_drain_budget()?,)",
    );
    if !phase_calls || global_launch_calls != 1 || !phase_batches || !phase_plan {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_LAUNCH_PATH,
            format!(
                "predicate=runtimeexec_handoff expected=phase owns sole typed-batch LaunchPlan::new + runtimeexec::launch and consumes receipt actual=phase_calls={phase_calls},global_launch_calls={global_launch_calls},phase_batches={phase_batches},phase_plan={phase_plan}"
            ),
        ));
    }

    let adapter_tokens = compact_tokens(&adapter);
    let adapter_is_closed =
        production_exact_path_call_count_in_file(&adapter, &["BoundListenerSet", "prepare"]) == 1
            && adapter_tokens.contains("listeners.preflight_activation()?")
            && adapter_tokens.contains("prepared.listeners.activate(&mutregistrar)")
            && adapter_tokens.contains("registrar.complete(inventory)")
            && adapter_tokens.contains("transaction.stage_resource(lifecycle)")
            && adapter_tokens.contains("self.non_health.into_iter().chain(self.health)");
    if !adapter_is_closed {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_LAUNCH_PATH,
            "predicate=runtime_adapter expected=stage prepare resources, prepare-all then preflight-all, register non-health before health, and complete a non-empty activation actual=non-canonical",
        ));
    }

    for (path, file) in &production_files {
        let lifecycle_uses = production_lifecycle_primitive_uses(file, &[]);
        let owns_forbidden_shutdown_stack =
            path != PROVIDER_OUTPUT_PATH && lifecycle_uses.shutdown_stack != 0;
        if assembly_defines_legacy_lifecycle_item(file)
            || production_macro_mentions_runtimeexec_launch(file)
            || owns_forbidden_shutdown_stack
        {
            findings.push(finding(
                Rule::ForbiddenWiring,
                path,
                "predicate=no_assembly_launch_compat expected=no legacy lifecycle owner/alias/re-export, wrapper macro, parallel executor or direct ShutdownStack outside provider transactional abort actual=forbidden production item",
            ));
        }
    }
    Ok(findings)
}

fn preserve_launch_error_is_canonical(kernel: &syn::File) -> bool {
    let Some(function) = unique_production_function(kernel, "preserve_launch_error") else {
        return false;
    };
    let Some(syn::Stmt::Expr(syn::Expr::Match(outcome), None)) = function.block.stmts.last() else {
        return false;
    };
    if outcome.arms.len() != 4 {
        return false;
    }

    let err_binding = |pattern: &syn::Pat| -> Option<String> {
        let syn::Pat::TupleStruct(result) = pattern else {
            return None;
        };
        if !is_exact_syn_path(&result.path, &["Err"]) || result.elems.len() != 1 {
            return None;
        }
        let syn::Pat::Ident(binding) = result.elems.first()? else {
            return None;
        };
        Some(binding.ident.to_string())
    };

    let matching = outcome
        .arms
        .iter()
        .filter(|arm| {
            let syn::Pat::Tuple(pair) = &arm.pat else {
                return false;
            };
            let Some(primary) = pair.elems.first().and_then(err_binding) else {
                return false;
            };
            let Some(cleanup) = pair.elems.iter().nth(1).and_then(err_binding) else {
                return false;
            };
            let syn::Expr::Block(body) = transparent_expr(&arm.body) else {
                return false;
            };
            let Some(syn::Stmt::Expr(tail, None)) = body.block.stmts.last() else {
                return false;
            };
            let body_tokens = compact_tokens(&body.block);
            let reports_cleanup = body_tokens.contains("preservingprimarylauncherror")
                && body_tokens.contains(&cleanup);
            reports_cleanup && compact_tokens(tail) == format!("Err({primary})")
        })
        .count();
    matching == 1
}

fn assembly_defines_legacy_lifecycle_item(file: &syn::File) -> bool {
    const PROTECTED: &[&str] = &["LaunchPlan", "LaunchPlanParts", "RuntimeOutputs"];
    const EXECUTORS: &[&str] = &[
        "execute_launch",
        "finish_launch",
        "launch_until",
        "launch_until_observed",
        "wait_for_shutdown_signal",
    ];
    file.items.iter().any(|item| match item {
        syn::Item::Struct(item) => PROTECTED.contains(&item.ident.to_string().as_str()),
        syn::Item::Enum(item) => PROTECTED.contains(&item.ident.to_string().as_str()),
        syn::Item::Type(item) => PROTECTED.contains(&item.ident.to_string().as_str()),
        syn::Item::Fn(item) => EXECUTORS.contains(&item.sig.ident.to_string().as_str()),
        syn::Item::Use(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
            let tokens = compact_tokens(&item.tree);
            PROTECTED.iter().any(|name| tokens.contains(name))
        }
        _ => false,
    })
}

fn production_macro_mentions_runtimeexec_launch(file: &syn::File) -> bool {
    struct Visitor {
        found: bool,
    }
    impl<'ast> Visit<'ast> for Visitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if attrs_may_be_production(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }
        fn visit_macro(&mut self, item: &'ast syn::Macro) {
            let tokens = compact_tokens(&item.tokens);
            self.found |= tokens.contains("runtimeexec")
                && (tokens.contains("launch") || tokens.contains("LaunchPlan"));
        }
    }
    let mut visitor = Visitor { found: false };
    visitor.visit_file(file);
    visitor.found
}

fn operator_module_ownership_is_closed(file: &syn::File) -> bool {
    fn contains_glob(tree: &syn::UseTree) -> bool {
        match tree {
            syn::UseTree::Path(path) => contains_glob(&path.tree),
            syn::UseTree::Group(group) => group.items.iter().any(contains_glob),
            syn::UseTree::Glob(_) => true,
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) => false,
        }
    }

    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if attrs_may_be_production(&module.attrs) => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let module_names = modules
        .iter()
        .map(|module| module.ident.to_string())
        .collect::<Vec<_>>();
    module_names
        == [
            "audit_ledger",
            "dlq",
            "jwks",
            "projection",
            "reconcile",
            "settings",
            "vault_allowlist",
        ]
        && modules.iter().all(|module| {
            matches!(module.vis, syn::Visibility::Inherited) && module.content.is_none()
        })
        && file.items.iter().all(|item| {
            !matches!(item, syn::Item::Use(item)
                if attrs_may_be_production(&item.attrs) && contains_glob(&item.tree))
        })
}

fn startup_phase_delegation_is_canonical(file: &syn::File) -> bool {
    let Some(startup) = unique_production_async_function(file, "run_startup") else {
        return false;
    };
    let Some(runtime_inputs) = runtime_inputs_mut_parameter(startup) else {
        return false;
    };
    if !matches!(startup.vis, syn::Visibility::Inherited)
        || compact_tokens(&startup.sig.output) != "->anyhow::Result<()>"
        || startup.block.stmts.len() != 1
        || production_exact_path_call_count_in_file(file, &["phase", "execute"]) != 1
    {
        return false;
    }
    let syn::Stmt::Expr(syn::Expr::MethodCall(map), None) = &startup.block.stmts[0] else {
        return false;
    };
    let syn::Expr::Await(await_) = transparent_expr(&map.receiver) else {
        return false;
    };
    let syn::Expr::Call(execute) = transparent_expr(&await_.base) else {
        return false;
    };
    map.method == "map"
        && map.args.len() == 1
        && compact_tokens(map.args.first().unwrap_or_else(|| unreachable!())) == "|_|()"
        && is_exact_path(&execute.func, &["phase", "execute"])
        && execute.args.len() == 1
        && execute
            .args
            .first()
            .is_some_and(|argument| is_exact_ident_path(argument, runtime_inputs))
}

fn phase_execute_is_canonical(file: &syn::File) -> bool {
    let executes = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "execute" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(execute) = (executes.len() == 1).then_some(executes[0]) else {
        return false;
    };
    let Some(runtime_inputs) = runtime_inputs_mut_parameter(execute) else {
        return false;
    };
    if execute.sig.asyncness.is_none()
        || !matches!(&execute.vis, syn::Visibility::Restricted(vis) if vis.path.is_ident("crate"))
        || !result_return_type_is(&execute.sig.output, "RuntimeOutputs")
        || execute.block.stmts.len() != 6
    {
        return false;
    }
    let Some(planned) = exact_phase_state_init(
        &execute.block.stmts[0],
        "planned",
        "Planned",
        runtime_inputs,
    ) else {
        return false;
    };
    let Some(providers) = exact_consuming_transition_local(
        &execute.block.stmts[1],
        "providers",
        &planned,
        "build_providers",
    ) else {
        return false;
    };
    let Some(infra) = exact_consuming_transition_local(
        &execute.block.stmts[2],
        "infra",
        &providers,
        "build_infra",
    ) else {
        return false;
    };
    let Some(domains) = exact_consuming_transition_local(
        &execute.block.stmts[3],
        "domains",
        &infra,
        "wire_domains",
    ) else {
        return false;
    };
    let Some(finalized) = exact_consuming_transition_local(
        &execute.block.stmts[4],
        "finalized",
        &domains,
        "finalize",
    ) else {
        return false;
    };
    matches!(
        &execute.block.stmts[5],
        syn::Stmt::Expr(syn::Expr::Await(await_), None)
            if matches!(transparent_expr(&await_.base), syn::Expr::MethodCall(call)
                if call.method == "launch"
                    && call.args.is_empty()
                    && is_exact_ident_path(&call.receiver, &finalized))
    )
}

fn exact_phase_state_init(
    statement: &syn::Stmt,
    expected_binding: &str,
    state: &str,
    runtime_inputs: &syn::Ident,
) -> Option<syn::Ident> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let binding = immutable_pat_ident(&local.pat)?;
    let init = local.init.as_ref()?;
    let syn::Expr::Struct(state_init) = transparent_expr(&init.expr) else {
        return None;
    };
    (binding == expected_binding
        && init.diverge.is_none()
        && is_exact_syn_path(&state_init.path, &[state])
        && state_init.rest.is_none()
        && state_init.fields.len() == 1
        && state_init.fields.first().is_some_and(|field| {
            matches!(&field.member, syn::Member::Named(member) if member == "runtime_inputs")
                && is_exact_ident_path(&field.expr, runtime_inputs)
        }))
    .then(|| binding.clone())
}

fn exact_consuming_transition_local(
    statement: &syn::Stmt,
    expected_binding: &str,
    predecessor: &syn::Ident,
    method: &str,
) -> Option<syn::Ident> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let binding = immutable_pat_ident(&local.pat)?;
    let init = local.init.as_ref()?;
    let syn::Expr::Try(try_) = transparent_expr(&init.expr) else {
        return None;
    };
    let syn::Expr::Await(await_) = transparent_expr(&try_.expr) else {
        return None;
    };
    let syn::Expr::MethodCall(call) = transparent_expr(&await_.base) else {
        return None;
    };
    (binding == expected_binding
        && init.diverge.is_none()
        && call.method == method
        && call.args.is_empty()
        && is_exact_ident_path(&call.receiver, predecessor))
    .then(|| binding.clone())
}

fn phase_state_definitions_are_canonical(file: &syn::File) -> bool {
    let states = [
        (
            "Planned",
            "Planned<'a>",
            "ProvidersBuilt<'a>",
            "BuildProvider",
        ),
        (
            "ProvidersBuilt",
            "ProvidersBuilt<'a>",
            "InfraBuilt<'a>",
            "BuildInfra",
        ),
        (
            "InfraBuilt",
            "InfraBuilt<'a>",
            "DomainsWired<'a>",
            "WireDomains",
        ),
        (
            "DomainsWired",
            "DomainsWired<'a>",
            "Finalized<'a>",
            "Finalize",
        ),
        (
            "Finalized",
            "Finalized<'_>",
            "runtimeexec::RuntimeOutputs",
            "Launch",
        ),
    ];
    let contexts = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item)
                if item.ident == "PhaseContext" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let context_is_private = contexts.len() == 1
        && matches!(contexts[0].vis, syn::Visibility::Inherited)
        && contexts[0]
            .fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited));
    let structs_are_private = states.iter().all(|(state, _, _, _)| {
        let structs = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item)
                    if item.ident == *state && attrs_may_be_production(&item.attrs) =>
                {
                    Some(item)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        structs.len() == 1
            && matches!(&structs[0].vis, syn::Visibility::Restricted(vis)
                if vis.path.is_ident("crate"))
            && matches!(&structs[0].fields, syn::Fields::Named(fields)
                if !fields.named.is_empty()
                    && fields.named.iter().all(|field| matches!(field.vis, syn::Visibility::Inherited)))
            && structs[0]
                .attrs
                .iter()
                .any(|attr| attr.path().is_ident("must_use"))
            && !attrs_derive_forbidden_phase_traits(&structs[0].attrs)
            && !has_production_phase_state_trait_impl(file, state, &["Clone", "Copy", "Debug", "Default"])
    });
    let trait_defs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Trait(item)
                if item.ident == "RuntimePhaseState" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let trait_is_exact = trait_defs.len() == 1
        && matches!(&trait_defs[0].vis, syn::Visibility::Inherited)
        && trait_defs[0].generics.params.is_empty()
        && trait_defs[0].supertraits.len() == 1
        && trait_defs[0]
            .supertraits
            .first()
            .is_some_and(|bound| compact_tokens(bound) == "sealed::Sealed")
        && trait_defs[0].items.len() == 2
        && trait_defs[0]
            .items
            .iter()
            .any(|item| compact_tokens(item) == "typeNext;")
        && trait_defs[0]
            .items
            .iter()
            .any(|item| compact_tokens(item) == "constPHASE:RuntimePhase;");
    let sealed_modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(item)
                if item.ident == "sealed" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let sealed_trait_is_exact = sealed_modules.len() == 1
        && matches!(sealed_modules[0].vis, syn::Visibility::Inherited)
        && sealed_modules[0]
            .content
            .as_ref()
            .is_some_and(|(_, items)| {
                matches!(
                    items.as_slice(),
                    [syn::Item::Trait(item)]
                        if item.ident == "Sealed"
                            && matches!(&item.vis, syn::Visibility::Restricted(vis)
                                if vis.path.is_ident("super"))
                            && item.generics.params.is_empty()
                            && item.supertraits.is_empty()
                            && item.items.is_empty()
                )
            });
    let phase_impl_count = file
        .items
        .iter()
        .filter(|item| {
            matches!(item, syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path_last_ident(path))
                        .is_some_and(|ident| ident == "RuntimePhaseState"))
        })
        .count();
    let sealed_impl_count = file
        .items
        .iter()
        .filter(|item| {
            matches!(item, syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item
                        .trait_
                        .as_ref()
                        .is_some_and(|(_, path, _)| is_exact_syn_path(path, &["sealed", "Sealed"])))
        })
        .count();
    let state_trait_impl_count = file
        .items
        .iter()
        .filter(|item| {
            matches!(item, syn::Item::Impl(item)
            if attrs_may_be_production(&item.attrs)
                && item.trait_.is_some()
                && type_last_ident(&item.self_ty).is_some_and(|ident| {
                    states.iter().any(|(state, _, _, _)| ident == *state)
                }))
        })
        .count();
    let production_item_macros = file
        .items
        .iter()
        .filter(
            |item| matches!(item, syn::Item::Macro(item) if attrs_may_be_production(&item.attrs)),
        )
        .count();
    context_is_private
        && structs_are_private
        && trait_is_exact
        && sealed_trait_is_exact
        && phase_impl_count == states.len()
        && sealed_impl_count == states.len()
        && state_trait_impl_count == states.len() * 2
        && production_item_macros == 0
        && states.iter().all(|(state, self_ty, next, phase)| {
            phase_state_impl_is_exact(file, state, self_ty, next, phase)
                && phase_state_sealed_impl_is_exact(file, state)
        })
}

fn attrs_derive_forbidden_phase_traits(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive") && {
            let tokens = compact_tokens(&attr.meta);
            ["Clone", "Copy", "Debug", "Default"]
                .iter()
                .any(|trait_name| tokens.contains(trait_name))
        }
    })
}

fn has_production_phase_state_trait_impl(
    file: &syn::File,
    state: &str,
    forbidden_traits: &[&str],
) -> bool {
    file.items.iter().any(|item| {
        matches!(item, syn::Item::Impl(item)
            if attrs_may_be_production(&item.attrs)
                && type_last_ident(&item.self_ty).is_some_and(|ident| ident == state)
                && item
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path_last_ident(path))
                    .is_some_and(|ident| forbidden_traits.iter().any(|forbidden| ident == *forbidden)))
    })
}

fn phase_state_impl_is_exact(
    file: &syn::File,
    state: &str,
    expected_self: &str,
    next: &str,
    phase: &str,
) -> bool {
    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path_last_ident(path))
                        .is_some_and(|ident| ident == "RuntimePhaseState")
                    && type_last_ident(&item.self_ty).is_some_and(|ident| ident == state) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(implementation) = (implementations.len() == 1).then_some(implementations[0]) else {
        return false;
    };
    if compact_tokens(&implementation.self_ty) != expected_self || implementation.items.len() != 2 {
        return false;
    }
    let next_items = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Type(item) if item.ident == "Next" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let phase_items = implementation
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Const(item) if item.ident == "PHASE" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    next_items.len() == 1
        && compact_tokens(&next_items[0].ty) == next
        && phase_items.len() == 1
        && compact_tokens(&phase_items[0].expr) == format!("RuntimePhase::{phase}")
}

fn phase_state_sealed_impl_is_exact(file: &syn::File, state: &str) -> bool {
    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item.trait_.as_ref().is_some_and(|(_, path, _)| {
                        is_exact_syn_path(path, &["sealed", "Sealed"])
                    })
                    && type_last_ident(&item.self_ty).is_some_and(|ident| ident == state) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    matches!(
        implementations.as_slice(),
        [implementation]
            if compact_tokens(&implementation.self_ty) == format!("{state}<'_>")
                && implementation.items.is_empty()
    )
}

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

fn consuming_transition_is_canonical(method: &syn::ImplItemFn) -> bool {
    method.sig.asyncness.is_some()
        && method.sig.inputs.len() == 1
        && matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
            if receiver.reference.is_none()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        && matches!(&method.vis, syn::Visibility::Restricted(vis) if vis.path.is_ident("super"))
        && compact_tokens(&method.sig.output) == "->anyhow::Result<<SelfasRuntimePhaseState>::Next>"
}

fn result_return_type_is(output: &syn::ReturnType, expected: &str) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    let syn::Type::Path(path) = ty.as_ref() else {
        return false;
    };
    let Some(result) = path.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    result.ident == "Result"
        && arguments.args.first().is_some_and(|argument| {
            matches!(argument, syn::GenericArgument::Type(ty)
                if type_last_ident(ty).is_some_and(|ident| ident == expected))
        })
}

fn transition_phase_funnel_is_canonical(method: &syn::ImplItemFn) -> bool {
    if exact_named_path_call_count(&method.block, &["phase_result"]) != 1 {
        return false;
    }
    let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) = method.block.stmts.last() else {
        return false;
    };
    is_exact_path(&call.func, &["phase_result"])
        && call.args.len() == 2
        && call
            .args
            .first()
            .is_some_and(|phase| compact_tokens(phase) == "<SelfasRuntimePhaseState>::PHASE")
        && call
            .args
            .iter()
            .nth(1)
            .is_some_and(|result| is_exact_path(result, &["result"]))
        && !compact_tokens(&method.block).contains("RuntimePhase::")
}

fn launch_pre_handoff_is_canonical(method: &syn::ImplItemFn) -> bool {
    let block = transition_body(&method.block);
    let tokens = compact_tokens(block);
    let budget = tokens.find("crate::launch::server_request_budget(");
    let plan = tokens.find("runtimeexec::LaunchPlan::new(");
    let launch = tokens.find("runtimeexec::launch(");
    exact_named_path_call_count(block, &["crate", "launch", "server_request_budget"]) == 1
        && exact_named_path_call_count(block, &["runtimeexec", "LaunchPlan", "new"]) == 1
        && exact_named_path_call_count(block, &["runtimeexec", "launch"]) == 1
        && method_call_count_in_block(block, "abort") == 1
        && method_call_count_in_block(block, "into_launch_batches") == 1
        && matches!((budget, plan, launch), (Some(budget), Some(plan), Some(launch))
            if budget < plan && plan < launch)
        && tokens.contains("Err(error)=>Err(provider_build.abort(error).await)")
        && tokens.contains("letlifecycle_batches=provider_build.into_launch_batches();")
        && tokens.contains(
            "adapter,probe_receipt,|inventory|asyncmove{crate::launch::log_ready(inventory)},trace_exporter,lifecycle_batches,crate::launch::total_drain_budget()?,",
        )
}

fn phase_context_shape_is_canonical(phase: &syn::File) -> bool {
    let contexts = phase
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "PhaseContext" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(context) = (contexts.len() == 1).then_some(contexts[0]) else {
        return false;
    };
    let context_fields = context
        .fields
        .iter()
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect::<Vec<_>>();
    context_fields == ["runtime_inputs", "runtime_plan"]
        && context
            .fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited))
}

fn runtime_plan_flow_is_canonical(provider: &syn::File) -> bool {
    let Some(build) = unique_production_inherent_method(provider, "Planned", "build_providers")
    else {
        return false;
    };
    #[derive(Default)]
    struct PlanFlow {
        runtime_plan_bindings: usize,
        placement_plan_bindings: usize,
        domain_plan_bindings: usize,
        context_constructors: usize,
    }
    impl<'ast> Visit<'ast> for PlanFlow {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            let Some(binding) = immutable_pat_ident(&local.pat) else {
                syn::visit::visit_local(self, local);
                return;
            };
            let call = local
                .init
                .as_ref()
                .and_then(|init| call_behind_result_context(&init.expr));
            if binding == "runtime_plan"
                && call.is_some_and(|call| {
                    is_exact_path(&call.func, &["crate", "plan", "RuntimePlan", "bundled"])
                        && call.args.len() == 1
                })
            {
                self.runtime_plan_bindings += 1;
            }
            let method = local.init.as_ref().map(|init| transparent_expr(&init.expr));
            if binding == "placement_execution_plan"
                && matches!(method, Some(syn::Expr::MethodCall(call))
                    if call.method == "placement_execution_plan"
                        && is_exact_path(&call.receiver, &["runtime_plan"]))
            {
                self.placement_plan_bindings += 1;
            }
            if binding == "domain_execution_plan"
                && matches!(method, Some(syn::Expr::MethodCall(call))
                if call.method == "domain_execution_plan"
                    && is_exact_path(&call.receiver, &["runtime_plan"])
                    && call.args.len() == 1
                    && call.args.first().is_some_and(|argument| {
                        reference_to_binding(argument, &syn::Ident::new(
                            "placement_execution_plan",
                            proc_macro2::Span::call_site(),
                        ))
                    }))
            {
                self.domain_plan_bindings += 1;
            }
            let constructor = local
                .init
                .as_ref()
                .and_then(|init| direct_call_behind_runtime_context(&init.expr));
            if binding == "context"
                && constructor.is_some_and(|call| {
                    is_exact_path(&call.func, &["DomainPhaseContext", "new"])
                        && call.args.len() == 3
                        && call.args.first().is_some_and(|argument| {
                            compact_tokens(argument) == "self.runtime_inputs"
                        })
                        && call
                            .args
                            .iter()
                            .nth(1)
                            .is_some_and(|argument| is_exact_path(argument, &["runtime_plan"]))
                        && call.args.iter().nth(2).is_some_and(|argument| {
                            is_exact_path(argument, &["domain_execution_plan"])
                        })
                })
            {
                self.context_constructors += 1;
            }
            syn::visit::visit_local(self, local);
        }
    }
    let mut flow = PlanFlow::default();
    flow.visit_block(&build.block);
    flow.runtime_plan_bindings == 1
        && flow.placement_plan_bindings == 1
        && flow.domain_plan_bindings == 1
        && flow.context_constructors == 1
        && exact_named_path_call_count(&build.block, &["crate", "plan", "RuntimePlan", "bundled"])
            == 1
        && exact_named_path_call_count(&build.block, &["DomainPhaseContext", "new"]) == 1
        && method_call_count_in_block(&build.block, "placement_execution_plan") == 1
        && method_call_count_in_block(&build.block, "domain_execution_plan") == 1
}

fn phase_result_redaction_is_canonical(file: &syn::File) -> bool {
    let phase_results = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "phase_result" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let failed_logs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(item)
                if item.sig.ident == "log_phase_failed" && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let direct_redacting_log = failed_logs.first().is_some_and(|function| {
        let [syn::Stmt::Macro(statement)] = function.block.stmts.as_slice() else {
            return false;
        };
        is_exact_syn_path(&statement.mac.path, &["tracing", "warn"])
            && compact_tokens(&statement.mac.tokens)
                == "runtime.phase=phase.as_str(),error=%secure::redact_error(err),\"runtimephasefailed\""
    });
    phase_results.len() == 1
        && matches!(phase_results[0].vis, syn::Visibility::Inherited)
        && failed_logs.len() == 1
        && exact_named_path_call_count(&phase_results[0].block, &["log_phase_completed"]) == 1
        && exact_named_path_call_count(&phase_results[0].block, &["log_phase_failed"]) == 1
        && direct_redacting_log
}

const PROTECTED_RUNTIME_PHASE_STATES: &[&str] = &[
    "Planned",
    "ProvidersBuilt",
    "InfraBuilt",
    "DomainsWired",
    "Finalized",
];

fn production_phase_state_impl_violations(
    files: &BTreeMap<String, syn::File>,
) -> Vec<(String, &'static str)> {
    files
        .iter()
        .filter_map(|(path, file)| {
            if path == RUNTIME_PHASE_PATH {
                return None;
            }
            let mut aliases = BTreeSet::new();
            let mut trait_aliases = BTreeSet::new();
            for item in &file.items {
                if let syn::Item::Use(item) = item
                    && attrs_may_be_production(&item.attrs)
                {
                    collect_phase_state_use_aliases(&item.tree, &mut Vec::new(), &mut aliases);
                    collect_use_aliases_for_ident(
                        &item.tree,
                        &mut Vec::new(),
                        "RuntimePhaseState",
                        &mut trait_aliases,
                    );
                }
            }
            let mut changed = true;
            while changed {
                changed = false;
                for item in &file.items {
                    let syn::Item::Type(item) = item else {
                        continue;
                    };
                    if !attrs_may_be_production(&item.attrs) {
                        continue;
                    }
                    let Some(target) = type_last_ident(&item.ty) else {
                        continue;
                    };
                    let target = target.to_string();
                    if (PROTECTED_RUNTIME_PHASE_STATES.contains(&target.as_str())
                        || aliases.contains(&target))
                        && aliases.insert(item.ident.to_string())
                    {
                        changed = true;
                    }
                }
            }
            let foreign_runtime_phase_impl = file.items.iter().any(|item| {
                matches!(item, syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path_last_ident(path))
                        .is_some_and(|ident| {
                            ident == "RuntimePhaseState"
                                || trait_aliases.contains(&ident.to_string())
                        }))
            });
            let protected_impl = file.items.iter().any(|item| {
                matches!(item, syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                        && item.trait_.is_some()
                        && type_last_ident(&item.self_ty).is_some_and(|ident| {
                            let ident = ident.to_string();
                            PROTECTED_RUNTIME_PHASE_STATES.contains(&ident.as_str())
                                || aliases.contains(&ident)
                        }))
            });
            let protected_macro = file.items.iter().any(|item| {
                matches!(item, syn::Item::Macro(item)
                if attrs_may_be_production(&item.attrs)
                    && (token_stream_mentions_any_ident(&item.mac.tokens, &aliases)
                        || token_stream_mentions_ident_or_alias(
                            &item.mac.tokens,
                            "RuntimePhaseState",
                            &trait_aliases,
                        )))
            });
            if foreign_runtime_phase_impl {
                Some((path.clone(), "foreign production impl"))
            } else if protected_impl {
                Some((path.clone(), "protected state trait impl outside owner"))
            } else if protected_macro {
                Some((path.clone(), "protected state macro outside owner"))
            } else {
                None
            }
        })
        .collect()
}

fn collect_use_aliases_for_ident(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    target: &str,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_aliases_for_ident(&path.tree, prefix, target, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) if name.ident == target => {
            aliases.insert(target.to_owned());
        }
        syn::UseTree::Rename(rename)
            if rename.ident == target
                || (rename.ident == "self"
                    && prefix.last().is_some_and(|ident| ident == target)) =>
        {
            aliases.insert(rename.rename.to_string());
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_aliases_for_ident(tree, prefix, target, aliases);
            }
        }
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
    }
}

fn collect_phase_state_use_aliases(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_phase_state_use_aliases(&path.tree, prefix, aliases);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            if PROTECTED_RUNTIME_PHASE_STATES.contains(&name.ident.to_string().as_str()) {
                aliases.insert(name.ident.to_string());
            }
        }
        syn::UseTree::Rename(rename) => {
            let is_protected = if rename.ident == "self" {
                prefix
                    .last()
                    .is_some_and(|ident| PROTECTED_RUNTIME_PHASE_STATES.contains(&ident.as_str()))
            } else {
                PROTECTED_RUNTIME_PHASE_STATES.contains(&rename.ident.to_string().as_str())
            };
            if is_protected {
                aliases.insert(rename.rename.to_string());
            }
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_phase_state_use_aliases(tree, prefix, aliases);
            }
        }
        syn::UseTree::Glob(_) => {
            aliases.extend(
                PROTECTED_RUNTIME_PHASE_STATES
                    .iter()
                    .map(|state| (*state).to_owned()),
            );
        }
    }
}

fn token_stream_mentions_any_ident(
    tokens: &proc_macro2::TokenStream,
    aliases: &BTreeSet<String>,
) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => {
            let ident = ident.to_string();
            PROTECTED_RUNTIME_PHASE_STATES.contains(&ident.as_str()) || aliases.contains(&ident)
        }
        proc_macro2::TokenTree::Group(group) => {
            token_stream_mentions_any_ident(&group.stream(), aliases)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

fn token_stream_mentions_ident_or_alias(
    tokens: &proc_macro2::TokenStream,
    target: &str,
    aliases: &BTreeSet<String>,
) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => {
            ident == target || aliases.contains(&ident.to_string())
        }
        proc_macro2::TokenTree::Group(group) => {
            token_stream_mentions_ident_or_alias(&group.stream(), target, aliases)
        }
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

#[derive(Debug, Default)]
struct LifecyclePrimitiveUses {
    launch_plan: usize,
    launch_plan_parts: usize,
    runtime_outputs: usize,
    shutdown_stack: usize,
    phase_execute: usize,
}

impl LifecyclePrimitiveUses {
    fn lifecycle_is_empty(&self) -> bool {
        self.launch_plan == 0
            && self.launch_plan_parts == 0
            && self.runtime_outputs == 0
            && self.shutdown_stack == 0
    }
}

fn production_lifecycle_primitive_uses(
    file: &syn::File,
    allowed_glob_prefixes: &[&[&str]],
) -> LifecyclePrimitiveUses {
    struct Counter<'a> {
        uses: LifecyclePrimitiveUses,
        allowed_glob_prefixes: &'a [&'a [&'a str]],
    }
    impl Counter<'_> {
        fn record_path(&mut self, path: &syn::Path) {
            for segment in &path.segments {
                match segment.ident.to_string().as_str() {
                    "LaunchPlan" => self.uses.launch_plan += 1,
                    "LaunchPlanParts" => self.uses.launch_plan_parts += 1,
                    "RuntimeOutputs" => self.uses.runtime_outputs += 1,
                    "ShutdownStack" => self.uses.shutdown_stack += 1,
                    _ => {}
                }
            }
            if path
                .segments
                .iter()
                .rev()
                .take(2)
                .map(|segment| segment.ident.to_string())
                .eq(["execute", "phase"].into_iter().map(str::to_owned))
            {
                self.uses.phase_execute += 1;
            }
        }

        fn record_use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
            match tree {
                syn::UseTree::Path(path) => {
                    prefix.push(path.ident.to_string());
                    self.record_use_tree(&path.tree, prefix);
                    prefix.pop();
                }
                syn::UseTree::Name(name) => {
                    prefix.push(name.ident.to_string());
                    self.record_use_path(prefix);
                    prefix.pop();
                }
                syn::UseTree::Rename(rename) => {
                    if rename.ident == "self" {
                        self.record_use_path(prefix);
                    } else {
                        prefix.push(rename.ident.to_string());
                        self.record_use_path(prefix);
                        prefix.pop();
                    }
                }
                syn::UseTree::Group(group) => {
                    for tree in &group.items {
                        self.record_use_tree(tree, prefix);
                    }
                }
                syn::UseTree::Glob(_) => {
                    let allowed = self.allowed_glob_prefixes.iter().any(|allowed| {
                        prefix
                            .iter()
                            .map(String::as_str)
                            .eq(allowed.iter().copied())
                    });
                    if !allowed {
                        self.uses.launch_plan += 1;
                        self.uses.launch_plan_parts += 1;
                        self.uses.shutdown_stack += 1;
                        self.uses.phase_execute += 1;
                    }
                }
            }
        }

        fn record_use_path(&mut self, path: &[String]) {
            for segment in path {
                match segment.as_str() {
                    "LaunchPlan" => self.uses.launch_plan += 1,
                    "LaunchPlanParts" => self.uses.launch_plan_parts += 1,
                    "RuntimeOutputs" => self.uses.runtime_outputs += 1,
                    "ShutdownStack" => self.uses.shutdown_stack += 1,
                    _ => {}
                }
            }
            if matches!(path, [.., phase, execute] if phase == "phase" && execute == "execute") {
                self.uses.phase_execute += 1;
            }
            if matches!(path, [root, phase] if root == "crate" && phase == "phase") {
                self.uses.phase_execute += 1;
            }
        }

        fn record_macro_tokens(&mut self, tokens: proc_macro2::TokenStream) {
            let contains_phase_execute = compact_tokens(&tokens).contains("phase::execute");
            for token in tokens {
                match token {
                    proc_macro2::TokenTree::Ident(ident) => match ident.to_string().as_str() {
                        "LaunchPlan" => self.uses.launch_plan += 1,
                        "LaunchPlanParts" => self.uses.launch_plan_parts += 1,
                        "RuntimeOutputs" => self.uses.runtime_outputs += 1,
                        "ShutdownStack" => self.uses.shutdown_stack += 1,
                        _ => {}
                    },
                    proc_macro2::TokenTree::Group(group) => {
                        self.record_macro_tokens(group.stream());
                    }
                    proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
                }
            }
            if contains_phase_execute {
                self.uses.phase_execute += 1;
            }
        }
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if attrs_may_be_default_runtime_production(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if attrs_may_be_default_runtime_production(&item.attrs) {
                syn::visit::visit_item_fn(self, item);
            }
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            if attrs_may_be_default_runtime_production(&item.attrs) {
                syn::visit::visit_item_impl(self, item);
            }
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if attrs_may_be_default_runtime_production(&item.attrs) {
                syn::visit::visit_impl_item_fn(self, item);
            }
        }
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if attrs_may_be_default_runtime_production(&item.attrs) {
                self.record_use_tree(&item.tree, &mut Vec::new());
            }
        }
        fn visit_macro(&mut self, item: &'ast syn::Macro) {
            self.record_macro_tokens(item.tokens.clone());
        }
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.record_path(&path.path);
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
            self.record_path(&item.path);
            syn::visit::visit_expr_struct(self, item);
        }
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.record_path(&path.path);
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut counter = Counter {
        uses: LifecyclePrimitiveUses::default(),
        allowed_glob_prefixes,
    };
    counter.visit_file(file);
    counter.uses
}

fn generated_domains_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let path = root.join(RUNTIME_PHASE_DOMAINS_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let domains = parse_rust_file(&path)?;
    let mut findings = Vec::new();
    let wire = unique_production_inherent_method(&domains, "InfraBuilt", "wire_domains");
    let compact_wire = wire.map(compact_tokens).unwrap_or_default();
    for forbidden in [
        "wire_audit",
        "wire_identity",
        "wire_settings",
        "bootstrap::compose(&[",
        "domains::audit::module",
        "domains::identity::module",
        "domains::settings::module",
        "letmutdomain_bindings=vec!",
        "DomainBinding::new",
    ] {
        if compact_wire.contains(forbidden) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                RUNTIME_PHASE_DOMAINS_PATH,
                format!("WireDomains 禁止恢复手写 domain wiring: `{forbidden}`"),
            ));
        }
    }
    let canonical_wire = wire.is_some_and(|method| {
        exact_named_path_call_count(&method.block, &["crate", "modules_gen", "wire_domains"]) == 1
            && exact_named_path_call_count(&method.block, &["bootstrap", "compose_bindings"]) == 0
            && exact_named_path_call_count(&method.block, &["bootstrap", "drain_binding_outputs"])
                == 3
            && method_call_count_in_block(&method.block, "validate") == 1
            && method_call_count_in_block(&method.block, "compose") == 1
            && compact_tokens(&method.block)
                .contains("domain_execution_plan.validate(domain_bindings)")
            && compact_tokens(&method.block).contains("validated_domain_bindings.compose()")
            && compact_tokens(&method.block)
                .matches(
                    "provider_build.record_domain(bootstrap::drain_binding_outputs(&mutbindings))",
                )
                .count()
                == 3
            && compact_tokens(&method.block)
                .contains("provider_build.record_domain(domains_module)")
    });
    if !canonical_wire {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_DOMAINS_PATH,
            "WireDomains 必须将唯一 generated domain 结果交给 plan-owned validator，并仅通过 ValidatedDomainBindings 进入 compose_bindings",
        ));
    }
    if wire.is_none_or(|method| {
        method_call_count_in_block(&method.block, "record_domain") < 5
            || !compact_tokens(&method.block).contains("record_domain(domains_module)")
    }) {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_DOMAINS_PATH,
            "generated domains output 未进入 ProviderBuild domain transaction",
        ));
    }
    let root_path = root.join(RUNTIME_LIB_PATH);
    let root_text = fs::read_to_string(&root_path)
        .with_context(|| format!("读 {} 失败", root_path.display()))?;
    let masked_file = mask_comments_and_strings(&root_text);
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

fn runtime_service_token_replay_live_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let oidc_path = root.join(RUNTIME_OIDC_PATH);
    let infra_path = root.join(RUNTIME_PHASE_INFRA_PATH);
    if !root.join("Cargo.toml").exists() && (!oidc_path.exists() || !infra_path.exists()) {
        // Generic runtime-baseline fixtures do not model OIDC. The real workspace cannot delete
        // any of these compiled modules without failing native compilation.
        return Ok(Vec::new());
    }
    let production_files = runtime_production_source_files(root)?;
    if service_token_replay_live_is_canonical(&production_files) {
        Ok(Vec::new())
    } else {
        Ok(vec![finding(
            Rule::ForbiddenWiring,
            RUNTIME_OIDC_PATH,
            "service-token verifier 必须只接受闭合 PostgreSQL replay owner；serving 与五条 operator live path 必须直接调用该 typed seam，禁止 process-local guard、平行/死 helper 与 macro 旁路",
        )])
    }
}

fn service_token_replay_live_is_canonical(files: &BTreeMap<String, syn::File>) -> bool {
    let required = [
        RUNTIME_OPERATOR_PATH,
        RUNTIME_OPERATOR_PROJECTION_PATH,
        RUNTIME_OPERATOR_AUDIT_PATH,
        RUNTIME_OPERATOR_DLQ_PATH,
        RUNTIME_OPERATOR_RECONCILE_PATH,
        RUNTIME_OPERATOR_SETTINGS_PATH,
        RUNTIME_OIDC_PATH,
        RUNTIME_PHASE_INFRA_PATH,
    ];
    if !required.iter().all(|path| files.contains_key(*path)) {
        return false;
    }
    let operator = &files[RUNTIME_OPERATOR_PATH];
    let projection = &files[RUNTIME_OPERATOR_PROJECTION_PATH];
    let audit = &files[RUNTIME_OPERATOR_AUDIT_PATH];
    let dlq = &files[RUNTIME_OPERATOR_DLQ_PATH];
    let reconcile = &files[RUNTIME_OPERATOR_RECONCILE_PATH];
    let settings = &files[RUNTIME_OPERATOR_SETTINGS_PATH];
    let oidc = &files[RUNTIME_OIDC_PATH];
    let infra = &files[RUNTIME_PHASE_INFRA_PATH];
    let operator_builders =
        production_functions_named(operator, "build_operator_service_token_provider");
    let service_builders = production_functions_named(oidc, "build_service_token_provider");
    let Some(operator_builder) = (operator_builders.len() == 1).then(|| operator_builders[0])
    else {
        return false;
    };
    let Some(service_builder) = (service_builders.len() == 1).then(|| service_builders[0]) else {
        return false;
    };
    if !replay_owner_trait_is_closed(oidc)
        || !exact_named_typed_input(
            &operator_builder.sig,
            2,
            "replay_owner",
            "&implServiceTokenReplayOwner",
        )
        || !exact_named_typed_input(
            &service_builder.sig,
            1,
            "replay_owner",
            "&implServiceTokenReplayOwner",
        )
        || exact_path_call_argument_count(
            &operator_builder.block,
            &["crate", "infra", "oidc", "build_service_token_provider"],
            1,
            "replay_owner",
        ) != 1
        || !service_builder_consumes_owner_once(&service_builder.block)
    {
        return false;
    }

    let operator_receipts = production_impl_methods_named(projection, "operator_receipt");
    let audit_subjects = production_impl_methods_named(audit, "operator_subject");
    let dlq_subjects = production_impl_methods_named(dlq, "operator_subject");
    if ![projection, audit, dlq, reconcile, settings]
        .iter()
        .all(|file| {
            production_has_exact_super_import(file, "build_operator_service_token_provider")
        })
        || operator_receipts.len() != 1
        || audit_subjects.len() != 1
        || dlq_subjects.len() != 1
        || operator_receipts.iter().any(|method| {
            exact_path_call_argument_count(
                &method.block,
                &["build_operator_service_token_provider"],
                2,
                "session",
            ) != 1
        })
        || audit_subjects.iter().chain(&dlq_subjects).any(|method| {
            exact_path_call_argument_count(
                &method.block,
                &["build_operator_service_token_provider"],
                2,
                "session",
            ) != 1
        })
    {
        return false;
    }
    for (file, function_name, owner) in [
        (reconcile, "run_reconcile_target_command", "&pg"),
        (
            settings,
            "settings_config_value_maintenance_operator_subject",
            "pg",
        ),
    ] {
        let functions = production_functions_named(file, function_name);
        if functions.len() != 1
            || exact_path_call_argument_count(
                &functions[0].block,
                &["build_operator_service_token_provider"],
                2,
                owner,
            ) != 1
        {
            return false;
        }
    }

    let Some(build_infra) =
        unique_production_inherent_method(infra, "ProvidersBuilt", "build_infra")
    else {
        return false;
    };
    let exact_inventory = files
        .values()
        .map(|file| production_call_last_ident_count(file, "build_operator_service_token_provider"))
        .sum::<usize>()
        == 5
        && files
            .values()
            .map(|file| production_call_last_ident_count(file, "build_service_token_provider"))
            .sum::<usize>()
            == 2
        && production_exact_path_call_count_in_file(
            operator,
            &["crate", "infra", "oidc", "build_service_token_provider"],
        ) == 1
        && production_exact_path_call_count_in_file(
            infra,
            &["crate", "infra", "oidc", "build_service_token_provider"],
        ) == 1
        && exact_path_call_argument_count(
            &build_infra.block,
            &["crate", "infra", "oidc", "build_service_token_provider"],
            1,
            "&pg_owner",
        ) == 1;
    let production = files.values().collect::<Vec<_>>();
    exact_inventory && !production_replay_bypass_present(&production)
}

fn production_has_exact_super_import(file: &syn::File, expected: &str) -> bool {
    fn count(tree: &syn::UseTree, prefix: &mut Vec<String>, expected: &str) -> usize {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                let result = count(&path.tree, prefix, expected);
                prefix.pop();
                result
            }
            syn::UseTree::Name(name)
                if name.ident == expected && prefix.as_slice() == ["super"] =>
            {
                1
            }
            syn::UseTree::Group(group) => group
                .items
                .iter()
                .map(|tree| count(tree, prefix, expected))
                .sum(),
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => 0,
        }
    }
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Use(item) if attrs_may_be_production(&item.attrs) => Some(item),
            _ => None,
        })
        .map(|item| count(&item.tree, &mut Vec::new(), expected))
        .sum::<usize>()
        == 1
}

fn production_call_last_ident_count(file: &syn::File, expected: &str) -> usize {
    struct Counter<'a> {
        expected: &'a str,
        calls: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
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

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if expr_path_last(&call.func).is_some_and(|ident| ident == self.expected) {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter { expected, calls: 0 };
    counter.visit_file(file);
    counter.calls
}

fn exact_named_typed_input(
    signature: &syn::Signature,
    index: usize,
    name: &str,
    expected_type: &str,
) -> bool {
    matches!(
        signature.inputs.iter().nth(index),
        Some(syn::FnArg::Typed(input))
            if matches!(input.pat.as_ref(), syn::Pat::Ident(binding)
                if binding.ident == name
                    && binding.by_ref.is_none()
                    && binding.mutability.is_none()
                    && binding.subpat.is_none())
                && compact_tokens(input.ty.as_ref()) == expected_type
    )
}

fn production_impl_methods_named<'a>(file: &'a syn::File, name: &str) -> Vec<&'a syn::ImplItemFn> {
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) if attrs_may_be_production(&item.attrs) => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == name && attrs_may_be_production(&method.attrs) =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect()
}

fn exact_path_call_argument_count(
    block: &syn::Block,
    path: &[&str],
    argument_index: usize,
    expected_argument: &str,
) -> usize {
    struct Counter<'a> {
        path: &'a [&'a str],
        argument_index: usize,
        expected_argument: &'a str,
        count: usize,
    }
    impl Visit<'_> for Counter<'_> {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if is_exact_path(&call.func, self.path)
                && call
                    .args
                    .iter()
                    .nth(self.argument_index)
                    .is_some_and(|argument| compact_tokens(argument) == self.expected_argument)
            {
                self.count += 1;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut counter = Counter {
        path,
        argument_index,
        expected_argument,
        count: 0,
    };
    counter.visit_block(block);
    counter.count
}

fn service_builder_consumes_owner_once(block: &syn::Block) -> bool {
    struct Inventory {
        lower_calls: usize,
        canonical_calls: usize,
    }
    impl Visit<'_> for Inventory {
        fn visit_expr_call(&mut self, call: &syn::ExprCall) {
            if is_exact_path(
                &call.func,
                &["self", "build_service_token_provider_from_values"],
            ) {
                self.lower_calls += 1;
                if call.args.iter().nth(4).is_some_and(|argument| {
                    matches!(argument, syn::Expr::MethodCall(method)
                        if method.method == "service_token_replay_store"
                            && method.args.is_empty()
                            && expr_path_last(&method.receiver)
                                .is_some_and(|ident| ident == "replay_owner"))
                }) {
                    self.canonical_calls += 1;
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut inventory = Inventory {
        lower_calls: 0,
        canonical_calls: 0,
    };
    inventory.visit_block(block);
    inventory.lower_calls == 1 && inventory.canonical_calls == 1
}

fn replay_owner_trait_is_closed(file: &syn::File) -> bool {
    let traits = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Trait(item)
                if item.ident == "ServiceTokenReplayOwner"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(owner_trait) = (traits.len() == 1).then(|| traits[0]) else {
        return false;
    };
    let exact_trait = compact_tokens(&owner_trait.vis) == "pub(crate)"
        && owner_trait.supertraits.len() == 1
        && owner_trait.supertraits.first().is_some_and(|bound| {
            compact_tokens(bound) == "service_token_replay_owner_sealed::Sealed"
        })
        && owner_trait.items.len() == 1
        && matches!(&owner_trait.items[0], syn::TraitItem::Fn(method)
            if method.sig.ident == "service_token_replay_store"
                && method.sig.inputs.len() == 1
                && matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver))
                    if receiver.reference.is_some()
                        && receiver.mutability.is_none())
                && matches!(&method.sig.output, syn::ReturnType::Type(_, ty)
                    if compact_tokens(ty.as_ref())
                        == "Arc<diport::DynServiceTokenReplayStore<'static>>"));
    if !exact_trait {
        return false;
    }
    let sealed_modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(item)
                if item.ident == "service_token_replay_owner_sealed"
                    && attrs_may_be_production(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if sealed_modules.len() != 1 || !sealed_replay_owner_module_is_exact(sealed_modules[0]) {
        return false;
    }

    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if attrs_may_be_production(&item.attrs)
                    && item.trait_.as_ref().is_some_and(|(_, path, _)| {
                        path.segments
                            .last()
                            .is_some_and(|segment| segment.ident == "ServiceTokenReplayOwner")
                    }) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected = BTreeSet::from([
        "postgres::PgMaintenanceDeps".to_owned(),
        "postgres::PgRuntimeDeps".to_owned(),
    ]);
    implementations.len() == 2
        && implementations
            .iter()
            .map(|implementation| compact_tokens(implementation.self_ty.as_ref()))
            .collect::<BTreeSet<_>>()
            == expected
        && implementations.iter().all(|implementation| {
            let owner = compact_tokens(implementation.self_ty.as_ref());
            implementation.items.len() == 1
                && matches!(&implementation.items[0], syn::ImplItem::Fn(method)
                    if method.sig.ident == "service_token_replay_store"
                        && compact_tokens(&method.block)
                            == format!("{{{owner}::service_token_replay_store(self)}}"))
        })
}

fn sealed_replay_owner_module_is_exact(module: &syn::ItemMod) -> bool {
    let Some((_, items)) = &module.content else {
        return false;
    };
    let traits = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Trait(item) if item.ident == "Sealed" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(sealed_trait) = (traits.len() == 1).then(|| traits[0]) else {
        return false;
    };
    let implementations = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if item.trait_.as_ref().is_some_and(|(polarity, path, _)| {
                    polarity.is_none()
                        && path.segments.len() == 1
                        && path.segments[0].ident == "Sealed"
                }) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let expected = BTreeSet::from([
        "postgres::PgMaintenanceDeps".to_owned(),
        "postgres::PgRuntimeDeps".to_owned(),
    ]);
    matches!(module.vis, syn::Visibility::Inherited)
        && items.len() == 3
        && compact_tokens(&sealed_trait.vis) == "pub"
        && sealed_trait.items.is_empty()
        && sealed_trait.supertraits.is_empty()
        && implementations.len() == 2
        && implementations.iter().all(|implementation| {
            implementation.items.is_empty() && implementation.generics.params.is_empty()
        })
        && implementations
            .iter()
            .map(|implementation| compact_tokens(implementation.self_ty.as_ref()))
            .collect::<BTreeSet<_>>()
            == expected
}

#[derive(Default)]
struct ProductionReplayBypass {
    process_local_guard: bool,
    macro_indirection: bool,
}

impl<'ast> Visit<'ast> for ProductionReplayBypass {
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

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        if attrs_may_be_production(&item.attrs) {
            if item.ident == "RuntimeServiceTokenReplayGuard" {
                self.process_local_guard = true;
            }
            syn::visit::visit_item_struct(self, item);
        }
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        if attrs_may_be_production(&item.attrs) {
            if item.ident == "RuntimeServiceTokenReplayGuard" {
                self.process_local_guard = true;
            }
            syn::visit::visit_item_enum(self, item);
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if attrs_may_be_production(&item.attrs) {
            if item.ident == "RuntimeServiceTokenReplayGuard" {
                self.process_local_guard = true;
            }
            syn::visit::visit_item_type(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path
            .segments
            .iter()
            .any(|segment| segment.ident == "RuntimeServiceTokenReplayGuard")
        {
            self.process_local_guard = true;
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if token_stream_contains_ident(
            item.tokens.clone(),
            &[
                "RuntimeServiceTokenReplayGuard",
                "build_service_token_provider",
                "build_operator_service_token_provider",
            ],
        ) {
            self.macro_indirection = true;
        }
        syn::visit::visit_macro(self, item);
    }
}

fn token_stream_contains_ident(stream: proc_macro2::TokenStream, protected: &[&str]) -> bool {
    stream.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => {
            protected.iter().any(|protected| ident == *protected)
        }
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_ident(group.stream(), protected)
        }
        _ => false,
    })
}

fn production_replay_bypass_present(files: &[&syn::File]) -> bool {
    let mut visitor = ProductionReplayBypass::default();
    for file in files {
        visitor.visit_file(file);
    }
    visitor.process_local_guard || visitor.macro_indirection
}

fn event_transport_output_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }
    let event = parse_rust_file(&root.join("assemblies/runtime/src/event_transport.rs"))?;
    let domains = parse_rust_file(&root.join(RUNTIME_PHASE_DOMAINS_PATH))?;
    let launch = parse_rust_file(&root.join(RUNTIMEEXEC_PATH))?;
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

    let wire = unique_production_inherent_method(&domains, "InfraBuilt", "wire_domains")
        .map(|method| transition_body(&method.block));
    let canonical_run = wire.is_some_and(|block| {
        exact_named_path_call_count(block, &["crate", "event_transport", "wire_event_transport"])
            == 1
            && exact_named_path_call_count(
                block,
                &["crate", "provider_output", "ProviderOutput", "event"],
            ) == 1
            && method_call_count_in_block(block, "event_publisher") == 1
            && method_call_count_in_block(block, "event_subscriber") == 1
            && event_output_record_is_canonical(block)
    });
    if !canonical_run {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIME_PHASE_DOMAINS_PATH,
            "WireDomains 必须把唯一 event transport output 包装为 ProviderOutput，同时消费 publisher/subscriber 两个 typed permit 并交给 ProviderBuild；domain module 不得平行持有 event_module",
        ));
    }

    let launch_tokens = compact_tokens(&launch);
    let provider =
        launch_tokens.find("letprovider_result=register_module_output(stack,provider.0);");
    let domain = launch_tokens.find("letdomain_result=register_module_output(stack,domain.0);");
    let owners = launch
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "LaunchPlan" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let launch_plan_fields_are_closed = owners.len() == 1
        && owners[0]
            .fields
            .iter()
            .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "adapter".to_owned(),
                "probe_receipt".to_owned(),
                "on_ready".to_owned(),
                "trace_exporter".to_owned(),
                "lifecycle_batches".to_owned(),
            ]);
    let module_registration_is_closed =
        unique_production_function(&launch, "register_module_output").is_some_and(|function| {
            method_call_count_in_block(&function.block, "register_detached") == 1
                && method_call_count_in_block(&function.block, "register_deferred_with_token") == 1
                && method_call_count_in_block(&function.block, "register_with_token") == 1
                && exact_named_path_call_count(&function.block, &["CancellationToken", "new"]) == 0
        });
    let lifecycle_registration_is_closed =
        unique_production_function(&launch, "register_lifecycle_outputs").is_some_and(|function| {
            method_call_count_in_block(&function.block, "register_detached") == 1
                && method_call_count_in_block(&function.block, "register_with_token") == 0
        });
    if launch_tokens.contains("event_infra_guards")
        || !launch_plan_fields_are_closed
        || !matches!((provider, domain), (Some(provider), Some(domain)) if provider < domain)
        || !launch_tokens.contains("provider_result?;domain_result")
        || production_exact_path_call_count_in_file(&launch, &["register_module_output"]) != 2
        || !module_registration_is_closed
        || !lifecycle_registration_is_closed
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIMEEXEC_PATH,
            "LaunchPlan 必须以 typed lifecycle batches 按 provider → domain 调用公共 register_module_output，禁止角色反转、event 专用字段或生命周期旁路",
        ));
    }
    Ok(findings)
}

fn event_output_record_is_canonical(block: &syn::Block) -> bool {
    #[derive(Default)]
    struct Records {
        canonical: usize,
        bypass: usize,
    }
    impl<'ast> Visit<'ast> for Records {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if expr_path_last(&call.receiver).is_some_and(|ident| ident == "provider_build") {
                if call.method == "record"
                    && call.args.len() == 1
                    && call.args.first().is_some_and(|argument| {
                        matches!(transparent_expr(argument), syn::Expr::Call(output)
                            if is_exact_path(
                                &output.func,
                                &["crate", "provider_output", "ProviderOutput", "event"],
                            )
                                && output.args.len() == 3
                                && output.args.first().is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "event_module"))
                                && output.args.iter().nth(1).is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "event_publisher_permit"))
                                && output.args.iter().nth(2).is_some_and(|arg| expr_path_last(arg).is_some_and(|ident| ident == "event_subscriber_permit")))
                    })
                {
                    self.canonical += 1;
                }
                if call.method == "record_domain"
                    && call.args.first().is_some_and(|argument| {
                        expr_path_last(argument).is_some_and(|ident| ident == "event_module")
                    })
                {
                    self.bypass += 1;
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut records = Records::default();
    records.visit_block(block);
    records.canonical == 1 && records.bypass == 0
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

fn workflow_runtime_plan_funnel_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let workflow_scope_present = [
        EVENTEXEC_WORKFLOW_RUNTIME_PATH,
        IDENTITYAUDIT_PLAN_PATH,
        SETTINGSONLY_PLAN_PATH,
    ]
    .into_iter()
    .any(|path| root.join(path).exists());
    if !workflow_scope_present {
        return Ok(Vec::new());
    }
    let required = [
        EVENTEXEC_WORKFLOW_RUNTIME_PATH,
        RUNTIME_PLAN_PATH,
        IDENTITYAUDIT_PLAN_PATH,
        SETTINGSONLY_PLAN_PATH,
        POSTGRES_BUNDLE_PATH,
        POSTGRES_PROJECTION_EVENTS_PATH,
        RUNTIME_OPERATOR_PROJECTION_PATH,
        RUNTIME_OPERATOR_DLQ_PATH,
        RUNTIME_SAGA_PATH,
        RUNTIMEEXEC_INVENTORY_PATH,
        RUNTIME_PHASE_INFRA_PATH,
        RUNTIME_PHASE_FINALIZE_PATH,
        IDENTITYAUDIT_PROVIDERS_PATH,
        IDENTITYAUDIT_RUNTIME_PATH,
        SETTINGSONLY_PROVIDERS_PATH,
        SETTINGSONLY_RUNTIME_PATH,
    ];
    let mut findings = Vec::new();
    let mut files = BTreeMap::new();
    for path in required {
        let absolute = root.join(path);
        match fs::read_to_string(&absolute) {
            Ok(source) => match syn::parse_file(&source) {
                Ok(file) => {
                    files.insert(path, file);
                }
                Err(error) => findings.push(finding(
                    Rule::ForbiddenWiring,
                    path,
                    format!("workflow runtime funnel carrier is not valid Rust: {error}"),
                )),
            },
            Err(error) => findings.push(finding(
                Rule::MissingAnchor,
                path,
                format!("workflow runtime funnel carrier missing: {error}"),
            )),
        }
    }

    if files.len() == required.len() && !workflow_runtime_carrier_shapes_are_canonical(&files) {
        findings.push(finding(
            Rule::ForbiddenWiring,
            EVENTEXEC_WORKFLOW_RUNTIME_PATH,
            "workflow runtime plan/view fields, protected signatures, or live view consumption drifted",
        ));
    }
    findings.extend(workflow_runtime_production_bypass_findings(root)?);
    Ok(findings)
}

fn workflow_runtime_carrier_shapes_are_canonical(files: &BTreeMap<&str, syn::File>) -> bool {
    let workflow = &files[EVENTEXEC_WORKFLOW_RUNTIME_PATH];
    let projection = &files[RUNTIME_OPERATOR_PROJECTION_PATH];
    let saga = &files[RUNTIME_SAGA_PATH];
    let postgres = &files[POSTGRES_BUNDLE_PATH];
    let inventory = &files[RUNTIMEEXEC_INVENTORY_PATH];
    workflow_runtime_types_are_sealed(workflow)
        && plan_compiles_workflows(
            &files[RUNTIME_PLAN_PATH],
            "RuntimePlan",
            "from_bundled_artifacts",
        )
        && plan_compiles_workflows(
            &files[IDENTITYAUDIT_PLAN_PATH],
            "IdentityAuditPlan",
            "bundled",
        )
        && plan_compiles_workflows(
            &files[SETTINGSONLY_PLAN_PATH],
            "SettingsOnlyPlan",
            "bundled",
        )
        && protected_method_parameter(
            postgres,
            "PgRuntimeDeps",
            "connect_serving",
            3,
            "projection_capture",
            "eventexec::ProjectionCaptureView<'_>",
            "ProjectionCaptureRegistration::from_capture(projection_capture)",
        )
        && protected_function_parameter(
            projection,
            "build_projection_target_registry",
            0,
            "view",
            "ProjectionTargetView<'_>",
            "ProjectionTargetRegistry::from_view(view)",
        )
        && protected_function_parameter(
            saga,
            "wire_saga_worker",
            0,
            "runtime",
            "SagaRuntimeView<'_>",
            "runtime.entries()",
        )
        && protected_method_parameter(
            inventory,
            "RuntimeInventorySeed",
            "from_runtime_plan",
            1,
            "activated_workflows",
            "eventexec::ActivatedWorkflowsView<'_>",
            "activated_workflows.workflows()",
        )
        && production_method_body_contains(
            inventory,
            "from_runtime_plan",
            "activated_workflows.source_runtime_plan_fingerprint()",
        )
        && production_method_body_contains(
            inventory,
            "from_runtime_plan",
            "runtime.runtime_plan_fingerprint().as_str()",
        )
        && private_struct_field(
            &files[RUNTIME_OPERATOR_DLQ_PATH],
            "ProductionDlqControlRuntime",
            "projection_capture",
            "ProjectionCaptureView<'a>",
        )
        && production_method_body_contains(
            &files[IDENTITYAUDIT_RUNTIME_PATH],
            "prepare",
            "plan.workflow_runtime().projection_capture()",
        )
        && production_method_body_contains(
            &files[SETTINGSONLY_RUNTIME_PATH],
            "prepare",
            "compiled_plan.workflow_runtime().projection_capture()",
        )
        && production_method_body_contains(
            &files[RUNTIME_OPERATOR_PROJECTION_PATH],
            "build_registry",
            "plan.workflow_runtime().projection_targets()",
        )
        && production_function_body_contains(
            &files[RUNTIME_OPERATOR_DLQ_PATH],
            "run_dlq_control_command",
            "plan.workflow_runtime().projection_capture()",
        )
        && production_method_body_contains(
            &files[RUNTIME_PHASE_INFRA_PATH],
            "build_infra",
            "context.runtime_plan.workflow_runtime().projection_capture()",
        )
        && production_method_body_contains(
            &files[RUNTIME_PHASE_FINALIZE_PATH],
            "finalize",
            ".workflow_runtime().activated_workflows()",
        )
}

fn workflow_runtime_types_are_sealed(file: &syn::File) -> bool {
    [
        "WorkflowRuntimePlan",
        "ProjectionCaptureView",
        "ProjectionTargetView",
        "SagaRuntimeView",
        "ActivatedWorkflowsView",
    ]
    .into_iter()
    .all(|name| {
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
        matches!(structs.as_slice(), [item]
            if matches!(&item.fields, syn::Fields::Named(fields)
                if !fields.named.is_empty()
                    && fields.named.iter().all(|field| matches!(field.vis, syn::Visibility::Inherited))))
    })
}

fn plan_compiles_workflows(file: &syn::File, owner: &str, method: &str) -> bool {
    unique_production_inherent_method(file, owner, method).is_some_and(|method| {
        live_block_contains(&method.block, "eventexec::WorkflowRuntimePlan::compile")
            && private_struct_field(
                file,
                owner,
                "workflow_runtime",
                "eventexec::WorkflowRuntimePlan",
            )
    })
}

fn private_struct_field(file: &syn::File, owner: &str, field: &str, ty: &str) -> bool {
    file.items.iter().any(|item| {
        let syn::Item::Struct(item) = item else {
            return false;
        };
        item.ident == owner
            && attrs_may_be_production(&item.attrs)
            && matches!(&item.fields, syn::Fields::Named(fields)
            if fields.named.iter().any(|candidate| {
                candidate.ident.as_ref().is_some_and(|ident| ident == field)
                    && matches!(candidate.vis, syn::Visibility::Inherited)
                    && compact_tokens(&candidate.ty) == ty
            }))
    })
}

fn protected_method_parameter(
    file: &syn::File,
    owner: &str,
    method: &str,
    index: usize,
    name: &str,
    ty: &str,
    consumption: &str,
) -> bool {
    unique_production_inherent_method(file, owner, method).is_some_and(|method| {
        exact_named_typed_input(&method.sig, index, name, ty)
            && live_block_contains(&method.block, consumption)
    })
}

fn protected_function_parameter(
    file: &syn::File,
    function: &str,
    index: usize,
    name: &str,
    ty: &str,
    consumption: &str,
) -> bool {
    unique_production_function(file, function).is_some_and(|function| {
        exact_named_typed_input(&function.sig, index, name, ty)
            && live_block_contains(&function.block, consumption)
    })
}

fn production_method_body_contains(file: &syn::File, method: &str, expected: &str) -> bool {
    let methods = production_impl_methods_named(file, method);
    matches!(methods.as_slice(), [method] if live_block_contains(&method.block, expected))
}

fn production_function_body_contains(file: &syn::File, function: &str, expected: &str) -> bool {
    unique_production_function(file, function)
        .is_some_and(|function| live_block_contains(&function.block, expected))
}

fn live_block_contains(block: &syn::Block, expected: &str) -> bool {
    let mut visitor = LiveConsumptionVisitor {
        expected,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

struct LiveConsumptionVisitor<'a> {
    expected: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for LiveConsumptionVisitor<'_> {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        self.found |= live_expression_matches(expression, self.expected);
        if let Some(closure) = invoked_closure(&expression.func) {
            self.visit_expr(&closure.body);
            for argument in &expression.args {
                self.visit_expr(argument);
            }
        } else {
            syn::visit::visit_expr_call(self, expression);
        }
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.found |= live_expression_matches(expression, self.expected);
        syn::visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {}

    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        if let Some(async_expression) = invoked_async(&expression.base) {
            self.visit_block(&async_expression.block);
        } else {
            self.visit_expr(&expression.base);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(initializer) = &local.init
            && matches!(
                &*initializer.expr,
                syn::Expr::Closure(_) | syn::Expr::Async(_)
            )
        {
            return;
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_const(&mut self, _expression: &'ast syn::ExprConst) {}

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.visit_expr(&expression.cond);
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.visit_expr(&expression.expr);
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.visit_expr(&expression.cond);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.visit_expr(&expression.expr);
    }

    fn visit_expr_loop(&mut self, _expression: &'ast syn::ExprLoop) {}
}

fn invoked_closure(expression: &syn::Expr) -> Option<&syn::ExprClosure> {
    match expression {
        syn::Expr::Closure(closure) => Some(closure),
        syn::Expr::Paren(paren) => invoked_closure(&paren.expr),
        syn::Expr::Group(group) => invoked_closure(&group.expr),
        _ => None,
    }
}

fn invoked_async(expression: &syn::Expr) -> Option<&syn::ExprAsync> {
    match expression {
        syn::Expr::Async(expression) => Some(expression),
        syn::Expr::Paren(paren) => invoked_async(&paren.expr),
        syn::Expr::Group(group) => invoked_async(&group.expr),
        _ => None,
    }
}

fn live_expression_matches(expression: impl quote::ToTokens, expected: &str) -> bool {
    let actual = compact_tokens(&expression);
    if expected.starts_with('.') {
        actual.ends_with(expected)
    } else {
        actual.starts_with(expected)
    }
}

fn workflow_runtime_production_bypass_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut sources = Vec::new();
    for directory in [
        "crates/eventexec/src",
        "crates/runtimeexec/src",
        "adapters/postgres/src",
        "assemblies/runtime/src",
        "assemblies/identityaudit/src",
        "assemblies/settingsonly/src",
    ] {
        let absolute = root.join(directory);
        if absolute.exists() {
            collect_rust_sources(&absolute, &mut sources)?;
        }
    }
    let production = production_module_sources(&sources)?;
    let mut findings = Vec::new();
    for source in production {
        let relative = source
            .strip_prefix(root)
            .unwrap_or(&source)
            .to_string_lossy()
            .replace('\\', "/");
        let file = parse_rust_file(&source)?;
        let mut visitor = WorkflowRuntimeBypassVisitor {
            allow_raw_catalog: relative == EVENTEXEC_WORKFLOW_RUNTIME_PATH,
            violations: BTreeSet::new(),
        };
        visitor.visit_file(&file);
        for violation in visitor.violations {
            findings.push(finding(
                Rule::ForbiddenWiring,
                relative.clone(),
                format!("production workflow runtime bypass is forbidden: `{violation}`"),
            ));
        }
    }
    Ok(findings)
}

struct WorkflowRuntimeBypassVisitor {
    allow_raw_catalog: bool,
    violations: BTreeSet<String>,
}

impl WorkflowRuntimeBypassVisitor {
    fn record_path(&mut self, path: &syn::Path) {
        let Some(last) = path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        if (!self.allow_raw_catalog && workflow_raw_catalog_ident(&last))
            || workflow_unsupported_ident(&last)
        {
            self.violations.insert(last);
        }
    }
}

impl<'ast> Visit<'ast> for WorkflowRuntimeBypassVisitor {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if attrs_may_be_default_runtime_production(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if attrs_may_be_default_runtime_production(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if attrs_may_be_default_runtime_production(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if attrs_may_be_default_runtime_production(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !attrs_may_be_default_runtime_production(&item.attrs) {
            return;
        }
        record_workflow_use_tree(&item.tree, self.allow_raw_catalog, &mut self.violations);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.record_path(path);
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if workflow_unsupported_ident(&method) {
            self.violations.insert(method);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn record_workflow_use_tree(
    tree: &syn::UseTree,
    allow_raw_catalog: bool,
    violations: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            record_workflow_use_tree(&path.tree, allow_raw_catalog, violations);
        }
        syn::UseTree::Name(name) => {
            record_workflow_use_ident(&name.ident.to_string(), allow_raw_catalog, violations);
        }
        syn::UseTree::Rename(rename) => {
            record_workflow_use_ident(&rename.ident.to_string(), allow_raw_catalog, violations);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                record_workflow_use_tree(tree, allow_raw_catalog, violations);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn record_workflow_use_ident(
    ident: &str,
    allow_raw_catalog: bool,
    violations: &mut BTreeSet<String>,
) {
    if (!allow_raw_catalog && workflow_raw_catalog_ident(ident))
        || workflow_unsupported_ident(ident)
    {
        violations.insert(ident.to_owned());
    }
}

fn workflow_raw_catalog_ident(ident: &str) -> bool {
    matches!(
        ident,
        "PROJECTION_INPUTS" | "PROJECTION_INPUT_GENERATION" | "PROJECTION_DEFINITIONS"
    )
}

fn workflow_unsupported_ident(ident: &str) -> bool {
    matches!(
        ident,
        "mark_all_generated_unsupported" | "UnsupportedProjection"
    )
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
    let path = root.join(POSTGRES_CONSUMER_TX_PATH);
    let source =
        fs::read_to_string(&path).with_context(|| format!("读 {} 失败", path.display()))?;
    if source.contains("security_audit_command_from_message")
        && !source.contains("credential_security_target_mappings")
    {
        return Ok(Vec::new());
    }
    Ok(vec![finding(
        Rule::ForbiddenWiring,
        POSTGRES_CONSUMER_TX_PATH,
        "audit security-event consumer 必须只消费 sealed redacted fact command，禁止直读 identity credential-security target mapping",
    )])
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
            "rls_ready".to_owned(),
        ])
        && exact_field("stores", "stores")
        && exact_field("revocation_receipt", "revocation_receipt")
        && exact_field("saga_receipt", "saga_receipt")
        && exact_field("audit_admin_store", "audit_admin_store")
        && exact_field("projection_capture", "projection_capture")
        && exact_field(
            "projection_registry",
            "projection_capture.as_ref().map_or_else(ProjectionWriteRegistry::empty,|capture|capture.registry())",
        )
}

fn parse_rust_file(path: &Path) -> Result<syn::File> {
    let source = fs::read_to_string(path).with_context(|| format!("读 {} 失败", path.display()))?;
    syn::parse_file(&source).with_context(|| format!("解析 {} 失败", path.display()))
}

fn transition_body(block: &syn::Block) -> &syn::Block {
    for stmt in &block.stmts {
        let syn::Stmt::Local(local) = stmt else {
            continue;
        };
        if pat_ident(&local.pat).is_none_or(|binding| binding != "result") {
            continue;
        }
        let Some(init) = &local.init else {
            continue;
        };
        match init.expr.as_ref() {
            syn::Expr::Async(async_) => return &async_.block,
            syn::Expr::Await(await_) => {
                if let syn::Expr::Async(async_) = await_.base.as_ref() {
                    return &async_.block;
                }
            }
            _ => {}
        }
    }
    block
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
    (functions.len() == 1).then_some(functions[0])
}

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
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
    provider_plan_output_bijection_findings(root)
}

fn provider_plan_output_bijection_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    if !root.join("Cargo.toml").exists() {
        return Ok(Vec::new());
    }

    const FACTORIES: &[(&str, &str)] = &[
        ("HttpservePostgresAuthAuditSink", "auth_audit_sink"),
        (
            "DeviceloopPostgresRevocationStore",
            "device_revocation_store",
        ),
        ("DistributedPostgresCasStore", "distributed_cas_store"),
        ("DistributedRedisLockStore", "distributed_lock_store"),
        (
            "EventexecVaultArchiveKeyProvider",
            "dlx_archive_key_provider",
        ),
        ("EventexecS3DlxArchiveStore", "dlx_archive_store"),
        (
            "EventexecPostgresDlxLifecycleRepository",
            "dlx_lifecycle_repository",
        ),
        ("EventexecAmqpPublisher", "event_publisher"),
        ("EventexecAmqpSubscriber", "event_subscriber"),
        ("IdentityVaultSigner", "identity_signer"),
        ("HttpserveOidcPdp", "listener_pdp"),
        ("HttpserveGovernorRateLimiter", "listener_rate_limiter"),
        ("RuntimeS3ObjectStore", "runtime_object_store"),
        (
            "OidcPostgresServiceTokenReplayStore",
            "service_token_replay_store",
        ),
        ("SettingsVaultKeyProvider", "settings_key_provider"),
        ("SettingsVaultSecretResolver", "settings_secret_resolver"),
    ];
    const REQUIRED_PATHS: &[&str] = &[
        PROVIDER_OUTPUT_PATH,
        GENERATED_PROVIDERS_PATH,
        RUNTIME_PHASE_PROVIDER_PATH,
        RUNTIME_PHASE_INFRA_PATH,
        RUNTIME_PHASE_DOMAINS_PATH,
        RUNTIME_PHASE_FINALIZE_PATH,
        RUNTIME_PHASE_LAUNCH_PATH,
        RUNTIME_LAUNCH_PATH,
        RUNTIMEEXEC_PATH,
    ];

    let missing = REQUIRED_PATHS
        .iter()
        .copied()
        .filter(|path| !root.join(path).exists())
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Ok(missing
            .into_iter()
            .map(|path| {
                finding(
                    Rule::MissingAnchor,
                    path,
                    "provider plan/output bijection gate 缺生产 owner",
                )
            })
            .collect());
    }

    let parsed = REQUIRED_PATHS
        .iter()
        .map(|path| Ok((*path, parse_rust_file(&root.join(path))?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let provider_output = &parsed[PROVIDER_OUTPUT_PATH];
    let generated = &parsed[GENERATED_PROVIDERS_PATH];
    let provider_phase = &parsed[RUNTIME_PHASE_PROVIDER_PATH];
    let infra_phase = &parsed[RUNTIME_PHASE_INFRA_PATH];
    let domains_phase = &parsed[RUNTIME_PHASE_DOMAINS_PATH];
    let finalize_phase = &parsed[RUNTIME_PHASE_FINALIZE_PATH];
    let phase_launch = &parsed[RUNTIME_PHASE_LAUNCH_PATH];
    let launch = &parsed[RUNTIMEEXEC_PATH];
    let mut findings = Vec::new();

    let struct_count = |file: &syn::File, name: &str| {
        file.items
            .iter()
            .filter(|item| {
                matches!(item, syn::Item::Struct(item)
                    if item.ident == name && attrs_may_be_production(&item.attrs))
            })
            .count()
    };
    let trait_count = |file: &syn::File, name: &str| {
        file.items
            .iter()
            .filter(|item| {
                matches!(item, syn::Item::Trait(item)
                    if item.ident == name && attrs_may_be_production(&item.attrs))
            })
            .count()
    };
    let provider_tokens = compact_tokens(provider_output);
    let owner_shape = [
        ("ProviderOutput", 1),
        ("ProviderBuild", 1),
        ("ProviderFactoryDispatch", 1),
        ("CompletedProviderBuild", 1),
    ]
    .into_iter()
    .all(|(name, expected)| {
        struct_count(provider_output, name) == expected
            // `provider_permits!` may emit ProviderFactoryDispatch inside the macro body; the
            // source still Hard-pins the consuming owner name without restoring a trait seam.
            || (name == "ProviderFactoryDispatch"
                && provider_tokens.contains("structProviderFactoryDispatch"))
    }) && trait_count(provider_output, "ProviderOutput") == 0;
    if !owner_shape {
        findings.push(finding(
            Rule::ForbiddenWiring,
            PROVIDER_OUTPUT_PATH,
            "provider lifecycle 必须由四个 private/consuming transaction owner 承载，禁止恢复 ProviderOutput trait/self-proof",
        ));
    }

    let generated_tokens = compact_tokens(generated);
    let catalog_is_closed =
        exact_path_call_count_in_file(generated, &["ProviderCatalogEntry", "checked"])
            == FACTORIES.len()
            && FACTORIES.iter().all(|(variant, _)| {
                let symbol = format!("ProviderFactorySymbol::{variant}");
                let macro_factory = format!("factory:{variant}");
                generated_tokens.matches(&symbol).count() == 1
                    && (provider_tokens.contains(&symbol)
                        || provider_tokens.contains(&macro_factory))
            })
            && provider_tokens.contains("matchentry.factory()");
    if !catalog_is_closed {
        findings.push(finding(
            Rule::ForbiddenWiring,
            GENERATED_PROVIDERS_PATH,
            format!(
                "generated active catalog 与 exhaustive typed dispatch 必须形成 exact set；expected={} factories",
                FACTORIES.len()
            ),
        ));
    }

    let provider_phase_tokens = compact_tokens(provider_phase);
    let plan_join_is_unique = exact_path_call_count_in_file(
        provider_phase,
        &["crate", "provider_output", "ProviderBuild", "from_plan"],
    ) == 1
        && exact_path_call_count_in_file(
            provider_phase,
            &[
                "crate",
                "provider_output",
                "ProviderFactoryDispatch",
                "from_catalog",
            ],
        ) == 1
        && provider_phase_tokens
            .matches("crate::providers_gen::PROVIDER_CATALOG")
            .count()
            == 2;
    if !plan_join_is_unique {
        findings.push(finding(
            Rule::MissingAnchor,
            RUNTIME_PHASE_PROVIDER_PATH,
            "BuildProvider 必须恰好一次把 RuntimePlan declarations 与 generated PROVIDER_CATALOG join，再生成 typed one-shot dispatch",
        ));
    }

    let construction_files = [provider_phase, infra_phase, domains_phase];
    for (variant, accessor) in FACTORIES {
        let uses = construction_files
            .iter()
            .map(|file| {
                let mut count = 0;
                for item in &file.items {
                    if let syn::Item::Impl(item) = item {
                        for impl_item in &item.items {
                            if let syn::ImplItem::Fn(method) = impl_item {
                                count += method_call_count_in_block(&method.block, accessor);
                            }
                        }
                    }
                }
                count
            })
            .sum::<usize>();
        if uses != 1 {
            findings.push(finding(
                Rule::ForbiddenWiring,
                PROVIDER_OUTPUT_PATH,
                format!(
                    "typed factory permit {variant}/{accessor} 必须在生产 phase 消费且只消费一次；observed={uses}"
                ),
            ));
        }
    }

    let phase_method_calls = |file: &syn::File, method_name: &str| {
        file.items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item) => Some(item),
                _ => None,
            })
            .flat_map(|item| item.items.iter())
            .filter_map(|item| match item {
                syn::ImplItem::Fn(method) if attrs_may_be_production(&method.attrs) => Some(method),
                _ => None,
            })
            .map(|method| method_call_count_in_block(&method.block, method_name))
            .sum::<usize>()
    };
    let record_count = construction_files
        .iter()
        .map(|file| phase_method_calls(file, "record"))
        .sum::<usize>();
    let domains_tokens = compact_tokens(domains_phase);
    let finalize_tokens = compact_tokens(finalize_phase);
    let phase_launch_tokens = compact_tokens(phase_launch);
    let provider_tokens = compact_tokens(provider_phase);
    let infra_tokens = compact_tokens(infra_phase);
    let transaction_is_closed = record_count == 8
        && phase_method_calls(domains_phase, "finish") == 1
        && provider_tokens.contains("provider_build.abort_with(module,error).await")
        && infra_tokens.contains("provider_build.abort_with(module,error).await")
        && domains_tokens.contains("provider_build.abort(error).await")
        && domains_tokens.contains("failure.abort().await")
        && domains_tokens.contains("completed.abort(error).await")
        && finalize_tokens.contains("provider_build.abort(error).await")
        && phase_launch_tokens.contains("provider_build.abort(error).await")
        && phase_method_calls(phase_launch, "into_launch_batches") == 1
        && phase_launch_tokens.contains("provider_build.into_launch_batches()");
    if !transaction_is_closed {
        findings.push(finding(
            Rule::ForbiddenWiring,
            PROVIDER_OUTPUT_PATH,
            format!(
                "provider transaction 必须覆盖 8 个 sealed output batches、唯一 finish、各 fallible phase rollback 与唯一 launch handoff；record_count={record_count}"
            ),
        ));
    }

    let launch_tokens = compact_tokens(launch);
    let pg_build_is_unique = exact_path_call_count_in_file(
        infra_phase,
        &["crate", "provider_output", "build_pg_runtime_module"],
    ) == 1
        && exact_path_call_count_in_file(
            phase_launch,
            &["crate", "provider_output", "build_pg_runtime_module"],
        ) == 0;
    let provider_registration =
        launch_tokens.find("letprovider_result=register_module_output(stack,provider.0);");
    let domain_registration =
        launch_tokens.find("letdomain_result=register_module_output(stack,domain.0);");
    if !pg_build_is_unique
        || !matches!((provider_registration, domain_registration),
            (Some(provider), Some(domain)) if provider < domain)
        || !launch_tokens.contains("provider_result?;domain_result")
    {
        findings.push(finding(
            Rule::ForbiddenWiring,
            RUNTIMEEXEC_PATH,
            "PG owner 必须在 BuildInfra 立即进入 ProviderOutput；Launch 只接受 completed typed lifecycle batches，并在 domain batch 前注册 provider batch",
        ));
    }

    for forbidden in [
        "ProviderOutputBinding",
        "PROVIDER_OUTPUT_BINDINGS",
        "build_provider_module",
        "merge_provider",
        "trait ProviderOutput",
        "let pg_runtime_module",
    ] {
        if REQUIRED_PATHS.iter().any(|path| {
            fs::read_to_string(root.join(path)).is_ok_and(|source| source.contains(forbidden))
        }) {
            findings.push(finding(
                Rule::ForbiddenWiring,
                PROVIDER_OUTPUT_PATH,
                format!("legacy/fallback provider seam 禁止回归: {forbidden}"),
            ));
        }
    }

    Ok(findings)
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
        && wire_durable_returns_owned_or_rolls_back(wire_durable)
        && !wire_durable_discards_module_output(wire_durable)
}

fn wire_durable_returns_owned_or_rolls_back(wire_durable: &syn::ItemFn) -> bool {
    exact_named_path_call_count(
        &wire_durable.block,
        &["crate", "provider_output", "abort_uncommitted"],
    ) == 5
        && matches!(wire_durable.block.stmts.last(),
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
            && expr_path_last(&reference.expr).is_some_and(|ident| ident == "per_domain"))
        || expr_path_last(&loop_.expr).is_some_and(|ident| ident == "per_domain");
    if !canonical_pattern || !canonical_iter {
        return false;
    }

    let connect = loop_.body.stmts.iter().position(|stmt| {
        let syn::Stmt::Local(local) = stmt else {
            return false;
        };
        matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "amqp_deps")
            && local.init.as_ref().is_some_and(|init| {
                exact_path_call_count_in_expr(
                    &init.expr,
                    &["amqp", "AmqpRuntimeDeps", "connect_with_private_ca"],
                ) == 1
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum AnchorStatus {
    Ok,
    Missing,
    OutOfOrder,
    ExpansionFailed(String),
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
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "crate::plan::RuntimePlan::bundled(self.runtime_inputs.config())",
    },
    AnchorSpec {
        id: "run.listener.execution-plan",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "let listener_execution_plan = runtime_plan.listener_execution_plan();",
    },
    AnchorSpec {
        id: "run.placement.execution-plan",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "runtime_plan.placement_execution_plan(self.runtime_inputs.config())",
    },
    AnchorSpec {
        id: "run.placement.reject-remote-on-local-listeners",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: ".reject_remote_on_local_listeners(&listener_execution_plan)",
    },
    AnchorSpec {
        id: "run.domain.execution-plan",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "runtime_plan.domain_execution_plan(&placement_execution_plan)",
    },
    AnchorSpec {
        id: "run.config.serving",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "RuntimeServingConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.provider.rss-access",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "build_rss_access_provider(",
    },
    AnchorSpec {
        id: "run.resources.rss-access-token",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "if let Some(provider) = runtime_rss_access.as_ref() {",
    },
    AnchorSpec {
        id: "run.provider.federated-access",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "build_federated_access_provider(",
    },
    AnchorSpec {
        id: "run.resources.federated-access-token",
        path: RUNTIME_PHASE_PROVIDER_PATH,
        pattern: "if let Some(provider) = runtime_federated_access.as_ref() {",
    },
    AnchorSpec {
        id: "run.config.s3",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "S3RuntimeConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.config.vault",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "VaultRuntimeConfig::from_snapshot(config)",
    },
    AnchorSpec {
        id: "run.provider.vault",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "vault_config.into_runtime()",
    },
    AnchorSpec {
        id: "run.provider.redis",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "build_redis_runtime_deps(redis_config)",
    },
    AnchorSpec {
        id: "run.provider.s3",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "build_s3_runtime_deps(s3_general_config)",
    },
    AnchorSpec {
        id: "run.provider.pg",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "PgRuntimeDeps::connect_serving",
    },
    AnchorSpec {
        id: "run.provider.service-token",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "build_service_token_provider(",
    },
    AnchorSpec {
        id: "run.provider-output.pg",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period)",
    },
    AnchorSpec {
        id: "run.resources.service-token",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "if let Some(provider) = runtime_service_token.as_ref() {",
    },
    AnchorSpec {
        id: "run.domain-transport.from-placement",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "DomainTransportConfig::from_placement(\n                event_transport.topology(),\n                &placement_execution_plan,\n                &crate::config::ServingConfigMapper::new(config),\n            )",
    },
    AnchorSpec {
        id: "run.module.output.domain-transport",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "provider_build.record_domain(domain_transport.module_result());",
    },
    AnchorSpec {
        id: "run.shared-deps",
        path: RUNTIME_PHASE_INFRA_PATH,
        pattern: "let deps = SharedRuntimeDeps::from_built_provider(",
    },
    AnchorSpec {
        id: "run.wire.generated-domains",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "crate::modules_gen::wire_domains(\n                &deps,\n                domain_modules,\n                &placement_execution_plan,\n            )",
    },
    AnchorSpec {
        id: "run.validate.generated-domains",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "domain_execution_plan.validate(domain_bindings)",
    },
    AnchorSpec {
        id: "run.module.input.domains",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "let (mut registry, domains_module) =",
    },
    AnchorSpec {
        id: "run.compose.generated-domains",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "validated_domain_bindings.compose()",
    },
    AnchorSpec {
        id: "run.module.output.domains",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "provider_build.record_domain(domains_module);",
    },
    AnchorSpec {
        id: "run.module.input.auth-grant-sweeper",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "let auth_grant_sweeper_module =",
    },
    AnchorSpec {
        id: "run.module.input.s3-canary",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "let s3_canary_module =",
    },
    AnchorSpec {
        id: "run.probe.rss-access-token-jwks-name",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "ProbeName::parse(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)",
    },
    AnchorSpec {
        id: "run.probe.rss-access-token-jwks",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "Box::new(AccessTokenJwksReadyProbe::rss_access(",
    },
    AnchorSpec {
        id: "run.probe.federated-access-token-jwks-name",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "ProbeName::parse(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME)",
    },
    AnchorSpec {
        id: "run.probe.federated-access-token-jwks",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "Box::new(AccessTokenJwksReadyProbe::federated_access(",
    },
    AnchorSpec {
        id: "run.wire.distributed",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "distributed_runtime::wire_distributed(&deps, distributed_worker)",
    },
    AnchorSpec {
        id: "run.event.bridge",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "event_transport::bridge_generated_subscriptions(",
    },
    AnchorSpec {
        id: "run.event.transport",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "event_transport::wire_event_transport(",
    },
    AnchorSpec {
        id: "run.provider-output.module",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "provider_build.finish()",
    },
    AnchorSpec {
        id: "run.probe.transaction-drain",
        path: RUNTIME_PHASE_DOMAINS_PATH,
        pattern: "completed.register_probes(&mut wired.registry)",
    },
    AnchorSpec {
        id: "run.listener.finalizer",
        path: RUNTIME_PHASE_FINALIZE_PATH,
        pattern: "let finalized_listeners = finalize_listener_plan(",
    },
    AnchorSpec {
        id: "run.launch-capability",
        path: RUNTIME_PHASE_LAUNCH_PATH,
        pattern: "runtimeexec::launch(launch_plan).await",
    },
    AnchorSpec {
        id: "launch.shutdown.trace",
        path: RUNTIMEEXEC_PATH,
        pattern: "if let Some(exporter) = trace_exporter",
    },
    AnchorSpec {
        id: "launch.shutdown.provider-output",
        path: RUNTIMEEXEC_PATH,
        pattern: "let provider_result = register_module_output(stack, provider.0);",
    },
    AnchorSpec {
        id: "launch.shutdown.domain-output",
        path: RUNTIMEEXEC_PATH,
        pattern: "let domain_result = register_module_output(stack, domain.0);",
    },
    AnchorSpec {
        id: "launch.shutdown.provider-result",
        path: RUNTIMEEXEC_PATH,
        pattern: "provider_result?;",
    },
    AnchorSpec {
        id: "launch.shutdown.domain-result",
        path: RUNTIMEEXEC_PATH,
        pattern: "    domain_result",
    },
    AnchorSpec {
        id: "launch.shutdown.resources",
        path: RUNTIMEEXEC_PATH,
        pattern: "for resource in resources",
    },
    AnchorSpec {
        id: "launch.shutdown.workers",
        path: RUNTIMEEXEC_PATH,
        pattern: "for worker in workers",
    },
    AnchorSpec {
        id: "launch.register-lifecycle",
        path: RUNTIMEEXEC_PATH,
        pattern: "register_lifecycle_outputs(stack, trace_exporter, lifecycle_batches)?;",
    },
    AnchorSpec {
        id: "launch.listener-prepare",
        path: RUNTIMEEXEC_PATH,
        pattern: "let prepared = adapter.prepare(probe_receipt, &mut transaction).await?;",
    },
    AnchorSpec {
        id: "launch.listener-activate",
        path: RUNTIMEEXEC_PATH,
        pattern: "Adapter::activate(prepared, transaction.commit())",
    },
    AnchorSpec {
        id: "launch.ready-hook",
        path: RUNTIMEEXEC_PATH,
        pattern: "let readiness = on_ready(activated.into_inventory());",
    },
    AnchorSpec {
        id: "launch.signal-wait",
        path: RUNTIMEEXEC_PATH,
        pattern: "let shutdown = wait_for_shutdown_signal()?;",
    },
    AnchorSpec {
        id: "launch.shutdown.drain",
        path: RUNTIMEEXEC_PATH,
        pattern: "shutdown_within(total_drain_budget.duration())",
    },
    AnchorSpec {
        id: "adapter.listener-prepare",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "BoundListenerSet::prepare(",
    },
    AnchorSpec {
        id: "adapter.listener-preflight",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "listeners.preflight_activation()?;",
    },
    AnchorSpec {
        id: "adapter.listener-activate",
        path: RUNTIME_LAUNCH_PATH,
        pattern: "prepared.listeners.activate(&mut registrar)",
    },
];

fn phase_method_expand_target(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        RUNTIME_PHASE_PROVIDER_PATH => Some(("Planned", "build_providers")),
        RUNTIME_PHASE_INFRA_PATH => Some(("ProvidersBuilt", "build_infra")),
        RUNTIME_PHASE_DOMAINS_PATH => Some(("InfraBuilt", "wire_domains")),
        RUNTIME_PHASE_FINALIZE_PATH => Some(("DomainsWired", "finalize")),
        RUNTIME_PHASE_LAUNCH_PATH => Some(("Finalized", "launch")),
        _ => None,
    }
}

fn visit_expanded_phase_method(
    visitor: &mut RunRuntimeConfigWiring,
    file: &syn::File,
    owner: &str,
    entry: &str,
) -> Result<(), PhaseExpandError> {
    let implementation = production_inherent_impl(file, owner)?;
    let methods = private_production_methods(implementation)?;
    let entry_method = inherent_entry_method(implementation, entry)?;
    let mut stack = Vec::new();
    let mut error = None;
    let mut expanding = HelperExpandingVisit {
        inner: visitor,
        owner,
        methods: &methods,
        stack: &mut stack,
        error: &mut error,
    };
    expanding.visit_block(&entry_method.block);
    if let Some(err) = error {
        return Err(err);
    }
    Ok(())
}

fn wiring_anchors(root: &Path) -> Result<Vec<AnchorEntry>> {
    let mut file_cache = BTreeMap::<&str, String>::new();
    let mut expanded_cache = BTreeMap::<&str, Result<String, PhaseExpandError>>::new();
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

        let (search_body, offset_base, expand_error) =
            if let Some((owner, method)) = phase_method_expand_target(spec.path) {
                let expanded = expanded_cache.entry(spec.path).or_insert_with(|| {
                    match syn::parse_file(text) {
                        Ok(file) => expand_inherent_phase_method(text, &file, owner, method)
                            .map(|expanded| expanded.virtual_source),
                        Err(error) => Err(PhaseExpandError::Parse(error.to_string())),
                    }
                });
                match expanded {
                    Ok(body) => (body.as_str(), 0usize, None),
                    Err(error) => ("", 0usize, Some(error.clone())),
                }
            } else {
                let scope = anchor_search_scope(spec, text);
                (scope.body, scope.start, None)
            };
        let masked_scope = mask_comments_and_strings(search_body);
        let status = if let Some(error) = expand_error {
            AnchorStatus::ExpansionFailed(error.to_string())
        } else {
            match masked_scope.find(spec.pattern) {
                None => AnchorStatus::Missing,
                Some(pos) => {
                    let absolute_pos = offset_base + pos;
                    let previous = last_pos.entry(anchor_order_key(spec)).or_insert(0);
                    if absolute_pos < *previous {
                        AnchorStatus::OutOfOrder
                    } else {
                        *previous = absolute_pos;
                        AnchorStatus::Ok
                    }
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
    if spec.path == RUNTIMEEXEC_PATH {
        if matches!(
            spec.id,
            "launch.shutdown.resources" | "launch.shutdown.workers"
        ) {
            return production_function_scope(
                text,
                "register_module_output",
                "fn register_module_output(",
            )
            .unwrap_or_else(|| empty_scope(text));
        }
        if spec.id.starts_with("launch.shutdown.") {
            return if spec.id == "launch.shutdown.drain" {
                production_function_scope(text, "spawn_drain", "fn spawn_drain(")
            } else {
                production_function_scope(
                    text,
                    "register_lifecycle_outputs",
                    "fn register_lifecycle_outputs(",
                )
            }
            .unwrap_or_else(|| empty_scope(text));
        }
        if matches!(
            spec.id,
            "launch.register-lifecycle"
                | "launch.listener-prepare"
                | "launch.listener-activate"
                | "launch.ready-hook"
        ) {
            return production_function_scope(text, "execute_launch", "async fn execute_launch<")
                .unwrap_or_else(|| empty_scope(text));
        }
        if spec.id == "launch.signal-wait" {
            return production_function_scope(
                text,
                "install_shutdown_signal",
                "fn install_shutdown_signal(",
            )
            .unwrap_or_else(|| empty_scope(text));
        }
    }
    AnchorSearchScope {
        body: text,
        start: 0,
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
    if spec.path == RUNTIME_PHASE_PROVIDER_PATH {
        return (spec.path, "build_providers");
    }
    if spec.path == RUNTIME_PHASE_INFRA_PATH {
        return (spec.path, "build_infra");
    }
    if spec.path == RUNTIME_PHASE_DOMAINS_PATH {
        return (spec.path, "wire_domains");
    }
    if spec.path == RUNTIME_PHASE_FINALIZE_PATH {
        return (spec.path, "finalize");
    }
    if spec.path == RUNTIME_PHASE_LAUNCH_PATH {
        return (spec.path, "phase_launch");
    }
    if spec.path == RUNTIMEEXEC_PATH
        && matches!(
            spec.id,
            "launch.shutdown.resources" | "launch.shutdown.workers"
        )
    {
        return (spec.path, "register_module_output");
    }
    if spec.path == RUNTIMEEXEC_PATH && spec.id.starts_with("launch.shutdown.") {
        return if spec.id == "launch.shutdown.drain" {
            (spec.path, "spawn_drain")
        } else {
            (spec.path, "register_lifecycle_outputs")
        };
    }
    if spec.path == RUNTIMEEXEC_PATH
        && matches!(
            spec.id,
            "launch.register-lifecycle"
                | "launch.listener-prepare"
                | "launch.listener-activate"
                | "launch.ready-hook"
        )
    {
        return (spec.path, "execute_launch");
    }
    if spec.path == RUNTIMEEXEC_PATH && spec.id == "launch.signal-wait" {
        return (spec.path, "install_shutdown_signal");
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

fn production_function_scope<'a>(
    text: &'a str,
    name: &str,
    needle: &str,
) -> Option<AnchorSearchScope<'a>> {
    let file = syn::parse_file(text).ok()?;
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
    let function = (functions.len() == 1).then_some(functions[0])?;
    let line = function.sig.ident.span().start().line;
    let search_from = if line <= 1 {
        0
    } else {
        text.match_indices('\n')
            .nth(line - 2)
            .map_or(0, |(offset, _)| offset + 1)
    };
    extract_braced_body_at(text, search_from, needle)
}

fn empty_scope(text: &str) -> AnchorSearchScope<'_> {
    AnchorSearchScope {
        body: &text[..0],
        start: 0,
    }
}

fn render_baseline(
    dependencies: &[DependencyEntry],
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
        format_args!("sharedRuntimeDeps = {SHARED_RUNTIME_DEPS_PATH}"),
    );
    push_line(
        &mut out,
        format_args!("domainModuleResult = {BOOTSTRAP_MODULE_PATH}"),
    );
    push_line(&mut out, format_args!("run = {RUNTIME_LIB_PATH}"));
    push_line(&mut out, format_args!("launch = {RUNTIME_LAUNCH_PATH}"));
    push_line(&mut out, format_args!("runtimeexec = {RUNTIMEEXEC_PATH}"));
    out.push('\n');

    out.push_str("[runtime.dependencies]\n");
    for dep in dependencies {
        push_line(&mut out, format_args!("{} = {}", dep.name, dep.spec));
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
                anchor_status(&anchor.status)
            ),
        );
    }
    out
}

fn push_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    out.push_str(&args.to_string());
    out.push('\n');
}

fn anchor_status(status: &AnchorStatus) -> &str {
    match status {
        AnchorStatus::Ok => "ok",
        AnchorStatus::Missing => "missing",
        AnchorStatus::OutOfOrder => "out-of-order",
        AnchorStatus::ExpansionFailed(_) => "expansion-failed",
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

    fn copy_runtime_sources(root: &Path) -> Result<()> {
        let workspace = workspace_root()?;
        let mut sources = Vec::new();
        collect_rust_sources(&workspace.join(RUNTIME_SRC_PATH), &mut sources)?;
        for source in sources {
            let relative = source.strip_prefix(&workspace)?;
            write(&root.join(relative), &fs::read_to_string(&source)?)?;
        }
        Ok(())
    }

    fn replay_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        copy_runtime_sources(&root)?;
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        Ok(root)
    }

    fn replay_fixture_is_canonical(root: &Path) -> Result<bool> {
        Ok(service_token_replay_live_is_canonical(
            &runtime_production_source_files(root)?,
        ))
    }

    fn mutate_replay_file(
        root: &Path,
        path: &str,
        needle: &str,
        occurrence: usize,
        replacement: &str,
        append: &str,
    ) -> Result<()> {
        let target = root.join(path);
        let source = fs::read_to_string(&target)?;
        let mutated = format!(
            "{}{}",
            replace_nth(&source, needle, occurrence, replacement)?,
            append
        );
        anyhow::ensure!(source != mutated, "replay mutation must be live for {path}");
        write(&target, &mutated)
    }

    fn replace_nth(
        source: &str,
        needle: &str,
        occurrence: usize,
        replacement: &str,
    ) -> Result<String> {
        let start = source
            .match_indices(needle)
            .nth(occurrence)
            .map(|(start, _)| start)
            .ok_or_else(|| {
                anyhow::anyhow!("missing occurrence {occurrence} of replay test needle `{needle}`")
            })?;
        Ok(format!(
            "{}{}{}",
            &source[..start],
            replacement,
            &source[start + needle.len()..]
        ))
    }

    fn postgres_setup_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        let workspace = workspace_root()?;
        write(
            &root.join(POSTGRES_BUNDLE_PATH),
            &fs::read_to_string(workspace.join(POSTGRES_BUNDLE_PATH))?,
        )?;
        write(
            &root.join(POSTGRES_MIGRATION_PATH),
            &fs::read_to_string(workspace.join(POSTGRES_MIGRATION_PATH))?,
        )?;
        write(
            &root.join(POSTGRES_PROJECTION_EVENTS_PATH),
            &fs::read_to_string(workspace.join(POSTGRES_PROJECTION_EVENTS_PATH))?,
        )?;
        Ok(root)
    }

    fn workflow_runtime_funnel_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        let workspace = workspace_root()?;
        for path in [
            EVENTEXEC_WORKFLOW_RUNTIME_PATH,
            RUNTIME_PLAN_PATH,
            IDENTITYAUDIT_PLAN_PATH,
            SETTINGSONLY_PLAN_PATH,
            POSTGRES_BUNDLE_PATH,
            POSTGRES_PROJECTION_EVENTS_PATH,
            RUNTIME_OPERATOR_PROJECTION_PATH,
            RUNTIME_OPERATOR_DLQ_PATH,
            RUNTIME_SAGA_PATH,
            RUNTIMEEXEC_INVENTORY_PATH,
            RUNTIME_PHASE_INFRA_PATH,
            RUNTIME_PHASE_FINALIZE_PATH,
            IDENTITYAUDIT_PROVIDERS_PATH,
            IDENTITYAUDIT_RUNTIME_PATH,
            SETTINGSONLY_PROVIDERS_PATH,
            SETTINGSONLY_RUNTIME_PATH,
        ] {
            write(&root.join(path), &fs::read_to_string(workspace.join(path))?)?;
        }
        Ok(root)
    }

    #[test]
    fn workflow_runtime_plan_funnel_accepts_live_workspace() -> Result<()> {
        assert_eq!(
            workflow_runtime_plan_funnel_findings(&workspace_root()?)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn workflow_runtime_plan_funnel_rejects_missing_views_raw_catalog_and_unsupported() -> Result<()>
    {
        let missing_core = workflow_runtime_funnel_fixture("workflow-runtime-missing-core")?;
        fs::remove_file(missing_core.join(EVENTEXEC_WORKFLOW_RUNTIME_PATH))?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&missing_core)?.is_empty(),
            "deleting the sole workflow compiler carrier must fail closed"
        );

        let missing = workflow_runtime_funnel_fixture("workflow-runtime-missing-view")?;
        let target = missing.join(RUNTIME_SAGA_PATH);
        let source = fs::read_to_string(&target)?;
        write(
            &target,
            &source.replace("SagaRuntimeView", "LegacySagaRuntime"),
        )?;
        assert!(!workflow_runtime_plan_funnel_findings(&missing)?.is_empty());

        let raw = workflow_runtime_funnel_fixture("workflow-runtime-raw-catalog")?;
        let target = raw.join(RUNTIME_PHASE_INFRA_PATH);
        let source = fs::read_to_string(&target)?;
        write(
            &target,
            &format!("{source}\nfn bypass() {{ let _ = generated::event::PROJECTION_INPUTS; }}\n"),
        )?;
        assert!(!workflow_runtime_plan_funnel_findings(&raw)?.is_empty());

        let aliased_raw = workflow_runtime_funnel_fixture("workflow-runtime-aliased-raw")?;
        let target = aliased_raw.join(POSTGRES_PROJECTION_EVENTS_PATH);
        let source = fs::read_to_string(&target)?;
        write(
            &target,
            &format!(
                "{source}\nfn live_catalog_bypass() {{ use generated::event::PROJECTION_INPUTS as RAW; let _ = RAW; }}\n"
            ),
        )?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&aliased_raw)?.is_empty(),
            "an aliased raw catalog import in a production carrier must fail closed"
        );

        let raw_parameter = workflow_runtime_funnel_fixture("workflow-runtime-raw-parameter")?;
        let target = raw_parameter.join(POSTGRES_BUNDLE_PATH);
        let source = fs::read_to_string(&target)?.replace(
            "pub async fn connect_serving(\n        serving_config: &PgConfig,\n        tenant_read_config: &PgTenantReadConfig,\n        audit_admin_config: Option<&PgConfig>,\n        projection_capture: eventexec::ProjectionCaptureView<'_>,",
            "pub async fn connect_serving(\n        serving_config: &PgConfig,\n        tenant_read_config: &PgTenantReadConfig,\n        audit_admin_config: Option<&PgConfig>,\n        projection_capture: &[vocab::ProjectionInputBinding],",
        );
        write(&target, &source)?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&raw_parameter)?.is_empty(),
            "the serving API must accept only the sealed projection capture view"
        );

        let unsupported = workflow_runtime_funnel_fixture("workflow-runtime-unsupported")?;
        let target = unsupported.join(RUNTIME_OPERATOR_PROJECTION_PATH);
        let source = fs::read_to_string(&target)?;
        write(
            &target,
            &format!(
                "{source}\nfn bypass(registry: &mut Registry) {{ registry.mark_all_generated_unsupported(); }}\n"
            ),
        )?;
        assert!(!workflow_runtime_plan_funnel_findings(&unsupported)?.is_empty());

        let bait = workflow_runtime_funnel_fixture("workflow-runtime-comment-bait")?;
        let target = bait.join(RUNTIME_SAGA_PATH);
        let source = fs::read_to_string(&target)?.replace("SagaRuntimeView", "LegacySagaRuntime");
        write(
            &target,
            &format!("{source}\n// SagaRuntimeView\nconst BAIT: &str = \"SagaRuntimeView\";\n"),
        )?;
        assert!(!workflow_runtime_plan_funnel_findings(&bait)?.is_empty());

        let dead_bait = workflow_runtime_funnel_fixture("workflow-runtime-dead-bait")?;
        let target = dead_bait.join(RUNTIME_SAGA_PATH);
        let source = fs::read_to_string(&target)?.replace(
            "runtime: SagaRuntimeView<'_>,",
            "runtime: LegacySagaRuntime<'_>,",
        );
        write(
            &target,
            &format!(
                "{source}\nfn dead_bait(runtime: SagaRuntimeView<'_>) {{ let _ = runtime; }}\n"
            ),
        )?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&dead_bait)?.is_empty(),
            "an unrelated dead function cannot replace the protected saga signature"
        );

        let dead_branch = workflow_runtime_funnel_fixture("workflow-runtime-dead-branch")?;
        let target = dead_branch.join(RUNTIME_SAGA_PATH);
        let source = fs::read_to_string(&target)?.replace(
            "for entry in runtime.entries() {",
            "if false { let _ = runtime.entries(); }\n    for entry in std::iter::empty::<eventexec::SagaRuntimeEntry<'_>>() {",
        );
        write(&target, &source)?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&dead_branch)?.is_empty(),
            "a dead branch cannot satisfy the protected live view consumption"
        );

        let dead_closure = workflow_runtime_funnel_fixture("workflow-runtime-dead-closure")?;
        let target = dead_closure.join(RUNTIME_SAGA_PATH);
        let source = fs::read_to_string(&target)?.replace(
            "for entry in runtime.entries() {",
            "let _dead = || { runtime.entries() };\n    let _dead_async = async { runtime.entries() };\n    let _nested_async = Some(async { runtime.entries() });\n    drop(async { runtime.entries() });\n    let _dead_if = if false { Some(runtime.entries()) } else { None };\n    while false { let _ = runtime.entries(); }\n    for _never in std::iter::empty::<()>() { let _ = runtime.entries(); }\n    for entry in std::iter::empty::<eventexec::SagaRuntimeEntry<'_>>() {",
        );
        write(&target, &source)?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&dead_closure)?.is_empty(),
            "closure and async-block bait cannot satisfy live view consumption"
        );

        let mismatched_inventory =
            workflow_runtime_funnel_fixture("workflow-runtime-mismatched-inventory")?;
        let target = mismatched_inventory.join(RUNTIMEEXEC_INVENTORY_PATH);
        let source = fs::read_to_string(&target)?.replace(
            "activated_workflows.source_runtime_plan_fingerprint()",
            "runtime.runtime_plan_fingerprint().as_str()",
        );
        write(&target, &source)?;
        assert!(
            !workflow_runtime_plan_funnel_findings(&mismatched_inventory)?.is_empty(),
            "inventory must prove its activated workflow view came from the same RuntimePlan"
        );
        Ok(())
    }

    #[test]
    fn postgres_setup_transaction_accepts_live_workspace() -> Result<()> {
        let root = postgres_setup_fixture("postgres-setup-transaction-live")?;
        assert_eq!(
            postgres_setup_transaction_live_findings(&root)?,
            Vec::<Finding<Rule>>::new(),
            "the real production setup AST is the anti-vacuity green"
        );
        Ok(())
    }

    #[test]
    fn postgres_setup_transaction_uses_plan_selected_projection_validation_guard() -> Result<()> {
        let source = fs::read_to_string(workspace_root()?.join(POSTGRES_BUNDLE_PATH))?;
        assert!(
            source.contains(
                "match projection_capture.as_ref() {\n            Some(capture) => writer_store\n                .validate_projection_capture_registration(capture)"
            ),
            "serving projection validation must be conditional on the plan-selected capture"
        );
        Ok(())
    }

    #[test]
    fn audit_security_fact_boundary_accepts_live_workspace() -> Result<()> {
        assert_eq!(
            audit_security_fact_boundary_findings(&workspace_root()?)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn audit_security_fact_boundary_rejects_identity_table_reads() -> Result<()> {
        let root = unique_tmp("audit-security-side-channel");
        write(
            &root.join(POSTGRES_CONSUMER_TX_PATH),
            "fn handle_security_attempt() { security_audit_command_from_message(); credential_security_target_mappings(); }",
        )?;
        assert!(!audit_security_fact_boundary_findings(&root)?.is_empty());
        Ok(())
    }

    #[test]
    fn postgres_setup_transaction_rejects_missing_live_edges() -> Result<()> {
        let missing_root = postgres_setup_fixture("postgres-setup-transaction-missing-carrier")?;
        fs::remove_file(missing_root.join(POSTGRES_BUNDLE_PATH))?;
        assert!(
            !postgres_setup_transaction_live_findings(&missing_root)?.is_empty(),
            "removing the protected production carrier must fail closed"
        );

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
                "projection validation missing",
                "validate_projection_capture_registration(capture)",
                "missing_projection_capture_registration(capture)",
                0,
            ),
            (
                "projection validation failure close",
                "return serving_transaction.close(Err(primary)).await;",
                "return Err(primary);",
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
                "dummy success owner",
                "handle: PgRuntimeHandle {\n                stores,\n                revocation_receipt,\n                saga_receipt,\n                audit_admin_store,",
                "handle: PgRuntimeHandle {\n                stores: stores.clone(),\n                revocation_receipt: revocation_receipt.clone(),\n                saga_receipt: saga_receipt.clone(),\n                audit_admin_store: None,",
                0,
            ),
        ];
        for (label, needle, replacement, occurrence) in cases {
            let root = postgres_setup_fixture(&format!(
                "postgres-setup-transaction-red-{}",
                label.replace(' ', "-")
            ))?;
            let target = root.join(POSTGRES_BUNDLE_PATH);
            let canonical = fs::read_to_string(&target)?;
            let mutated = replace_nth(&canonical, needle, occurrence, replacement)?;
            assert_ne!(canonical, mutated, "{label} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                !postgres_setup_transaction_live_findings(&root)?.is_empty(),
                "{label} must fail closed"
            );
        }

        for (label, occurrence) in [
            ("revocation capability dead close bait", 1),
            ("saga receipt capability dead close bait", 2),
            ("reader dead close bait", 3),
            ("audit-admin dead close bait", 4),
        ] {
            let root = postgres_setup_fixture(&format!(
                "postgres-setup-transaction-red-{}",
                label.replace(' ', "-")
            ))?;
            let target = root.join(POSTGRES_BUNDLE_PATH);
            let canonical = fs::read_to_string(&target)?;
            let mutated = replace_nth(
                &canonical,
                "Err(primary) => return serving_transaction.close(Err(primary)).await,",
                occurrence,
                "Err(primary) => {\n                        if false {\n                            return serving_transaction.close(Err(primary)).await;\n                        }\n                        return Err(primary);\n                    },",
            )?;
            assert_ne!(canonical, mutated, "{label} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                !postgres_setup_transaction_live_findings(&root)?.is_empty(),
                "{label} must fail closed"
            );
        }

        for missing in [POSTGRES_MIGRATION_PATH, POSTGRES_PROJECTION_EVENTS_PATH] {
            let root = postgres_setup_fixture(&format!(
                "postgres-projection-capability-missing-{}",
                missing.replace('/', "-")
            ))?;
            fs::remove_file(root.join(missing))?;
            assert!(
                !postgres_setup_transaction_live_findings(&root)?.is_empty(),
                "missing {missing} must fail closed"
            );
        }

        let root = postgres_setup_fixture("postgres-projection-migrator-handwritten")?;
        let target = root.join(POSTGRES_MIGRATION_PATH);
        let source = fs::read_to_string(&target)?;
        write(
            &target,
            &source.replace(
                "postgres_migration_inventory::projection_input_generation()",
                "\"handwritten-generation\"",
            ),
        )?;
        assert!(
            !postgres_setup_transaction_live_findings(&root)?.is_empty(),
            "migrator must consume the generated generation"
        );

        let root = postgres_setup_fixture("postgres-projection-serving-registration")?;
        let target = root.join(POSTGRES_PROJECTION_EVENTS_PATH);
        let source = fs::read_to_string(&target)?;
        let production = source.replace(
            "    #[cfg(any(test, feature = \"test-support\", feature = \"fault-matrix-test-support\"))]\n    pub(crate) async fn register_projection_input_bindings",
            "    pub(crate) async fn register_projection_input_bindings",
        );
        assert_ne!(
            source, production,
            "serving capability mutation must be live"
        );
        write(&target, &production)?;
        assert!(
            !postgres_setup_transaction_live_findings(&root)?.is_empty(),
            "production serving registration capability must fail closed"
        );
        Ok(())
    }

    #[test]
    fn runtime_service_token_replay_live_accepts_typed_pg_composition() -> Result<()> {
        let root = workspace_root()?;
        assert!(
            service_token_replay_live_is_canonical(&runtime_production_source_files(&root)?),
            "real runtime service-token composition is the anti-vacuity green"
        );
        Ok(())
    }

    #[test]
    fn runtime_service_token_replay_live_rejects_bait_parallel_paths_and_process_local_guards()
    -> Result<()> {
        let root = replay_fixture("service-token-replay-missing-call")?;
        assert!(replay_fixture_is_canonical(&root)?);
        mutate_replay_file(
            &root,
            RUNTIME_OPERATOR_PROJECTION_PATH,
            "build_operator_service_token_provider(",
            0,
            "missing_operator_service_token_provider(",
            r#"
const REPLAY_STRING_BAIT: &str = "build_operator_service_token_provider(";
// build_operator_service_token_provider(
"#,
        )?;
        assert!(!replay_fixture_is_canonical(&root)?);

        let root = replay_fixture("service-token-replay-dead-helper")?;
        let operator = root.join(RUNTIME_OPERATOR_PATH);
        let source = fs::read_to_string(&operator)?;
        write(
            &operator,
            &format!(
                "{source}\nfn dead_replay_bait(config: Config, operator: Operator, owner: Owner) {{ let _ = build_operator_service_token_provider(config, operator, owner); }}\n"
            ),
        )?;
        assert!(
            !replay_fixture_is_canonical(&root)?,
            "a dead helper must violate the closed production inventory"
        );

        let root = replay_fixture("service-token-replay-test-bait")?;
        let operator = root.join(RUNTIME_OPERATOR_PATH);
        let source = fs::read_to_string(&operator)?;
        write(
            &operator,
            &format!(
                "{source}\n#[cfg(test)] fn test_only_replay_bait(config: Config, operator: Operator, owner: Owner) {{ struct RuntimeServiceTokenReplayGuard; let _ = build_operator_service_token_provider(config, operator, owner); }}\n"
            ),
        )?;
        assert!(
            replay_fixture_is_canonical(&root)?,
            "test-only evidence must be ignored rather than counted as production"
        );

        let root = replay_fixture("service-token-replay-process-local")?;
        let operator = root.join(RUNTIME_OPERATOR_PATH);
        let source = fs::read_to_string(&operator)?;
        write(
            &operator,
            &format!("{source}\nstruct RuntimeServiceTokenReplayGuard;\n"),
        )?;
        assert!(
            !replay_fixture_is_canonical(&root)?,
            "a production process-local replay guard must fail closed"
        );

        let root = replay_fixture("service-token-replay-widened-owner")?;
        mutate_replay_file(
            &root,
            RUNTIME_OIDC_PATH,
            "impl Sealed for postgres::PgMaintenanceDeps {}",
            0,
            "impl Sealed for postgres::PgMaintenanceDeps {}\n\
             impl Sealed for memory::RuntimeServiceTokenReplayGuard {}",
            "",
        )?;
        assert!(
            !replay_fixture_is_canonical(&root)?,
            "the native sealed owner set must remain exactly the two PostgreSQL owners"
        );

        let root = replay_fixture("service-token-replay-macro")?;
        let operator = root.join(RUNTIME_OPERATOR_PATH);
        let source = fs::read_to_string(&operator)?;
        write(
            &operator,
            &format!(
                "{source}\nfn replay_macro_bypass() {{ replay!(build_operator_service_token_provider); }}\n"
            ),
        )?;
        assert!(
            !replay_fixture_is_canonical(&root)?,
            "macro indirection around a protected constructor must fail closed"
        );
        Ok(())
    }

    fn phase_transition_fixture(name: &str) -> Result<std::path::PathBuf> {
        let root = unique_tmp(name);
        copy_runtime_sources(&root)?;
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        Ok(root)
    }

    #[test]
    fn runtime_phase_transition_accepts_canonical_live_path() -> Result<()> {
        let root = phase_transition_fixture("runtime-phase-transition-green")?;
        let findings = runtime_phase_transition_findings(&root)?;
        assert!(
            findings.is_empty(),
            "real typed phase chain is the anti-vacuity green: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_phase_transition_rejects_cross_file_state_impl_with_precise_finding() -> Result<()> {
        let root = phase_transition_fixture("runtime-phase-transition-red-cross-file-state")?;
        let runtime = root.join(RUNTIME_LIB_PATH);
        let source = fs::read_to_string(&runtime)?;
        write(&runtime, &format!("{source}\nmod rogue;\n"))?;
        write(
            &root.join("assemblies/runtime/src/rogue.rs"),
            r#"
struct Skipped;

impl crate::phase::RuntimePhaseState for Skipped {
    type Next = crate::phase::RuntimeOutputs;
    const PHASE: crate::phase::RuntimePhase = crate::phase::RuntimePhase::Launch;
}
"#,
        )?;

        let findings = runtime_phase_transition_findings(&root)?;
        assert_eq!(
            findings
                .iter()
                .filter(|finding| {
                    finding.rule == Rule::ForbiddenWiring
                        && finding.subject == "assemblies/runtime/src/rogue.rs"
                        && finding.detail
                            == "predicate=runtime_phase_state_impl_closure expected=RuntimePhaseState implementations are sealed and owned only by assemblies/runtime/src/phase.rs actual=foreign production impl"
                })
                .count(),
            1,
            "cross-file Skipped impl must produce one precise finding at its real path: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_phase_transition_reports_failed_predicate_path_and_detail() -> Result<()> {
        let root = phase_transition_fixture("runtime-phase-transition-red-precise-finding")?;
        let target = root.join(RUNTIME_LIB_PATH);
        let source = fs::read_to_string(&target)?;
        let mutated = source.replacen(
            "phase::execute(runtime_inputs).await.map(|_| ())",
            "phase::execute_bait(runtime_inputs).await.map(|_| ())",
            1,
        );
        assert_ne!(source, mutated, "startup fixture must mutate");
        write(&target, &mutated)?;

        let findings = runtime_phase_transition_findings(&root)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenWiring
                    && finding.subject == RUNTIME_LIB_PATH
                    && finding.detail
                        == "predicate=startup_phase_delegation expected=unique run_startup -> phase::execute actual=non-canonical"
            }),
            "startup predicate must name its real path and exact failure: {findings:?}"
        );
        assert!(
            findings.iter().all(|finding| !finding
                .detail
                .starts_with("production startup must delegate")),
            "generic conjunction finding must be removed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_phase_transition_rejects_missing_reordered_drop_plan_and_bait() -> Result<()> {
        let cases = [
            (
                "missing sole delegation with comment/test bait",
                RUNTIME_LIB_PATH,
                "phase::execute(runtime_inputs).await.map(|_| ())",
                "phase::execute_bait(runtime_inputs).await.map(|_| ())\n}\n\
                 // phase::execute(runtime_inputs).await.map(|_| ())\n\
                 #[cfg(test)] async fn bait(inputs: &mut ServingRuntimeInputs) {\n\
                     let _ = phase::execute(inputs).await;\n",
            ),
            (
                "reordered consuming chain",
                RUNTIME_PHASE_PATH,
                "    let infra = providers.build_infra().await?;\n\
                 \x20   let domains = infra.wire_domains().await?;",
                "    let domains = infra.wire_domains().await?;\n\
                 \x20   let infra = providers.build_infra().await?;",
            ),
            (
                "early RuntimePlan drop",
                RUNTIME_PHASE_PROVIDER_PATH,
                "        let context =\n            DomainPhaseContext::new(self.runtime_inputs, runtime_plan, domain_execution_plan);",
                "        drop(runtime_plan);\n\
                 \x20       let context =\n            DomainPhaseContext::new(self.runtime_inputs, runtime_plan, domain_execution_plan);",
            ),
            (
                "caller-forgeable phase label",
                RUNTIME_PHASE_PROVIDER_PATH,
                "phase_result(<Self as RuntimePhaseState>::PHASE, result)",
                "phase_result(RuntimePhase::BuildProvider, result)",
            ),
            (
                "copyable lifecycle state",
                RUNTIME_PHASE_PATH,
                "#[must_use]\npub(crate) struct InfraBuilt",
                "#[must_use]\n#[derive(Clone, Copy)]\npub(crate) struct InfraBuilt",
            ),
            (
                "missing must_use state marker",
                RUNTIME_PHASE_PATH,
                "#[must_use]\npub(crate) struct ProvidersBuilt",
                "pub(crate) struct ProvidersBuilt",
            ),
            (
                "public phase context",
                RUNTIME_PHASE_PATH,
                "struct PhaseContext<'a>",
                "pub(crate) struct PhaseContext<'a>",
            ),
            (
                "manual debug lifecycle state",
                RUNTIME_PHASE_PATH,
                "",
                "\nimpl std::fmt::Debug for InfraBuilt<'_> {\n\
                 \x20   fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
                 }\n",
            ),
            (
                "production only aliased debug lifecycle state",
                RUNTIME_PHASE_PATH,
                "",
                "\nuse std::fmt::Debug as Diagnostic;\n\
                 #[cfg(not(test))]\n\
                 impl Diagnostic for Planned<'_> {\n\
                 \x20   fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
                 }\n",
            ),
            (
                "extra phase state implementation",
                RUNTIME_PHASE_PATH,
                "",
                "\nstruct Skipped;\n\
                 impl RuntimePhaseState for Skipped {\n\
                 \x20   type Next = RuntimeOutputs;\n\
                 \x20   const PHASE: RuntimePhase = RuntimePhase::Launch;\n\
                 }\n",
            ),
            (
                "concrete transition return bypass",
                RUNTIME_PHASE_PROVIDER_PATH,
                "anyhow::Result<<Self as RuntimePhaseState>::Next>",
                "anyhow::Result<ProvidersBuilt<'a>>",
            ),
            (
                "cfg test transition impl bait",
                RUNTIME_PHASE_PROVIDER_PATH,
                "impl<'a> Planned<'a> {",
                "#[cfg(test)]\nimpl<'a> Planned<'a> {",
            ),
            (
                "raw error with redaction field bait",
                RUNTIME_PHASE_PATH,
                "error = %secure::redact_error(err),",
                "error = %err,\n        redaction_bait = %secure::redact_error(err),",
            ),
            (
                "direct ShutdownStack bypass outside launch phase",
                RUNTIME_PHASE_DOMAINS_PATH,
                "",
                "\nfn bypass() { let _ = ShutdownStack::new(token); }\n",
            ),
            (
                "legacy tuple before executor",
                RUNTIME_LIB_PATH,
                "    phase::execute(runtime_inputs).await.map(|_| ())",
                "    let _legacy = (runtime_inputs.config(), runtime_inputs.password_blocklist());\n\
                 \x20   phase::execute(runtime_inputs).await.map(|_| ())",
            ),
            (
                "operator glob import",
                RUNTIME_OPERATOR_PATH,
                "",
                "\nuse crate::phase::*;\n",
            ),
            (
                "operator inline private prelude revival",
                RUNTIME_OPERATOR_PATH,
                "",
                "\nmod private { use crate::phase::OperatorRuntimeInputs; }\n",
            ),
        ];

        for (label, path, needle, replacement) in cases {
            let root = phase_transition_fixture(&format!(
                "runtime-phase-transition-red-{}",
                label.replace(' ', "-")
            ))?;
            let target = root.join(path);
            let source = fs::read_to_string(&target)?;
            let mutated = if needle.is_empty() {
                format!("{source}{replacement}")
            } else {
                source.replacen(needle, replacement, 1)
            };
            assert_ne!(source, mutated, "{label} fixture must mutate");
            write(&target, &mutated)?;
            let findings = runtime_phase_transition_findings(&root)?;
            assert!(!findings.is_empty(), "typed phase gate must reject {label}");
        }

        for (label, rogue) in [
            (
                "lifecycle aliases in a new production module",
                "use crate::launch::{LaunchPlan as LP, LaunchPlanParts as Parts};\n\
                 fn bypass() { let _ = LP::new(Parts { todo: () }); }\n",
            ),
            (
                "phase module alias in a new production module",
                "use crate::phase as p;\n\
                 async fn bypass(inputs: &mut ServingRuntimeInputs) {\n\
                 \x20   let _ = p::execute(inputs).await;\n\
                 }\n",
            ),
            (
                "lifecycle macro indirection in a new production module",
                "fn bypass() { lifecycle_bait!(LaunchPlan, LaunchPlanParts, ShutdownStack); }\n",
            ),
            (
                "production only state trait impl in a new module",
                "#[cfg(not(test))]\n\
                 impl std::fmt::Debug for crate::phase::Planned<'_> {\n\
                 \x20   fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
                 }\n",
            ),
            (
                "macro generated state trait impl in a new module",
                "#[cfg(not(test))]\n\
                 macro_rules! add_debug { ($state:ty) => {\n\
                 \x20   impl std::fmt::Debug for $state {\n\
                 \x20       fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }\n\
                 \x20   }\n\
                 } }\n\
                 #[cfg(not(test))]\n\
                 add_debug!(crate::phase::Planned<'_>);\n",
            ),
        ] {
            let root = phase_transition_fixture(&format!(
                "runtime-phase-transition-red-{}",
                label.replace(' ', "-")
            ))?;
            let runtime = root.join(RUNTIME_LIB_PATH);
            let source = fs::read_to_string(&runtime)?;
            write(&runtime, &format!("{source}\nmod rogue;\n"))?;
            write(&root.join("assemblies/runtime/src/rogue.rs"), rogue)?;
            let findings = runtime_phase_transition_findings(&root)?;
            assert!(!findings.is_empty(), "typed phase gate must reject {label}");
        }

        let root = phase_transition_fixture("runtime-phase-transition-red-late-budget-bait")?;
        let target = root.join(RUNTIME_PHASE_LAUNCH_PATH);
        let source = fs::read_to_string(&target)?;
        let canonical = "crate::launch::server_request_budget(context.config())";
        assert!(source.contains(canonical), "late budget mutation anchor");
        let mutated = format!(
            "use crate::launch::server_request_budget as late_budget;\n{}\n\
             fn dead_budget_bait(context: Context) {{\n\
             \x20   if false {{ let _ = crate::launch::server_request_budget(context.config()); }}\n\
             }}\n",
            source.replacen(canonical, "late_budget(context.config())", 1)
        );
        write(&target, &mutated)?;
        let findings = runtime_phase_transition_findings(&root)?;
        assert!(
            !findings.is_empty(),
            "typed phase gate must reject dead exact-call bait plus late aliased budget validation"
        );
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
    runtime_inputs: &OperatorRuntimeInputs,
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
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        for path in [
            PROVIDER_OUTPUT_PATH,
            GENERATED_PROVIDERS_PATH,
            RUNTIME_LAUNCH_PATH,
            RUNTIMEEXEC_PATH,
            RUNTIME_DOMAIN_EXEC_PATH,
            POSTGRES_BUNDLE_PATH,
            POSTGRES_CONSUMER_TX_PATH,
            POSTGRES_MIGRATION_PATH,
            POSTGRES_PROJECTION_EVENTS_PATH,
        ] {
            write(&root.join(path), &fs::read_to_string(workspace.join(path))?)?;
        }
        for phase_path in [
            RUNTIME_PHASE_PATH,
            RUNTIME_PHASE_PROVIDER_PATH,
            RUNTIME_PHASE_INFRA_PATH,
            RUNTIME_PHASE_DOMAINS_PATH,
            RUNTIME_PHASE_FINALIZE_PATH,
            RUNTIME_PHASE_LAUNCH_PATH,
        ] {
            let canonical_path = workspace.join(phase_path);
            write(
                &root.join(phase_path),
                &fs::read_to_string(&canonical_path)
                    .with_context(|| format!("read canonical phase fixture {phase_path}"))?,
            )?;
        }
        Ok(root)
    }

    fn collect_report(root: &Path) -> Result<Report> {
        collect_report_with_projection(root, 1)
    }

    fn check_fixture_root(root: &Path) -> Result<(String, Vec<Finding<Rule>>)> {
        let report = collect_report(root)?;
        let mut findings = report.findings;
        let baseline = root.join(BASELINE_PATH);
        if !baseline.exists() {
            findings.push(finding(
                Rule::MissingBaseline,
                BASELINE_PATH,
                "missing fixture baseline",
            ));
        } else if normalize_newlines(&fs::read_to_string(&baseline)?)
            != normalize_newlines(&report.rendered)
        {
            findings.push(finding(
                Rule::Drift,
                BASELINE_PATH,
                "fixture baseline drift",
            ));
        }
        Ok(("fixture runtime baseline".to_owned(), findings))
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
                    "let mut domain_bindings = modules_gen::wire_domains(&deps, domain_modules, &placement_execution_plan)",
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
    fn runtime_launch_kernel_owner_accepts_workspace() -> Result<()> {
        let root = workspace_root()?;
        assert_eq!(
            runtime_launch_kernel_owner_findings(&root)?,
            Vec::<Finding<Rule>>::new(),
            "the real runtimeexec kernel and assembly adapter are the anti-vacuity green"
        );
        Ok(())
    }

    #[test]
    fn runtime_launch_kernel_owner_rejects_assembly_executor_and_bait() -> Result<()> {
        let cases = [
            (
                "runtime-launch-owner-legacy-alias-red",
                r#"
pub type RuntimeOutputs = runtimeexec::RuntimeOutputs;
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=no_assembly_launch_compat",
            ),
            (
                "runtime-launch-owner-legacy-executor-red",
                r#"
async fn execute_launch() {}
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=no_assembly_launch_compat",
            ),
            (
                "runtime-launch-owner-macro-bait-red",
                r#"
macro_rules! parallel_launch {
    ($plan:expr) => { runtimeexec::launch($plan) };
}
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=no_assembly_launch_compat",
            ),
            (
                "runtime-launch-owner-dead-bait-red",
                r#"
#[allow(dead_code)]
async fn dead_launch_bait(plan: Plan) {
    let _ = runtimeexec::launch(plan).await;
}
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=runtimeexec_handoff",
            ),
            (
                "runtime-launch-owner-second-launch-red",
                r#"
async fn bypass_runtimeexec_owner(plan: Plan) {
    let _ = runtimeexec::launch(plan).await;
}
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=runtimeexec_handoff",
            ),
            (
                "runtime-launch-owner-direct-stack-red",
                r#"
fn bypass_runtimeexec_stack(token: tokio_util::sync::CancellationToken) {
    let _ = bootstrap::shutdown::ShutdownStack::new(token);
}
"#,
                RUNTIME_PHASE_LAUNCH_PATH,
                "predicate=no_assembly_launch_compat",
            ),
        ];

        let workspace = workspace_root()?;
        for (name, mutation, expected_subject, expected_predicate) in cases {
            let root = replay_fixture(name)?;
            write(
                &root.join(RUNTIMEEXEC_PATH),
                &fs::read_to_string(workspace.join(RUNTIMEEXEC_PATH))?,
            )?;
            let path = root.join(RUNTIME_PHASE_LAUNCH_PATH);
            let mut source = fs::read_to_string(&path)?;
            source.push_str(mutation);
            write(&path, &source)?;

            let findings = runtime_launch_kernel_owner_findings(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding.subject == expected_subject
                        && finding.detail.contains(expected_predicate)
                }),
                "{name} must be rejected by the real runtime launch owner gate: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_launch_kernel_owner_rejects_lifecycle_mutations() -> Result<()> {
        let cases = [
            (
                "runtime-launch-lifecycle-module-transfer-red",
                "register_lifecycle_outputs(stack, trace_exporter, lifecycle_batches)?;",
                "register_lifecycle_outputs_bypass(stack, trace_exporter, lifecycle_batches)?;",
            ),
            (
                "runtime-launch-lifecycle-module-order-red",
                "provider_result?;\n    domain_result",
                "domain_result?;\n    provider_result",
            ),
            (
                "runtime-launch-lifecycle-prepare-red",
                "adapter.prepare(probe_receipt, &mut transaction).await?",
                "adapter.prepare_without_receipt(&mut transaction).await?",
            ),
            (
                "runtime-launch-lifecycle-activate-red",
                "Adapter::activate(prepared, transaction.commit())",
                "Adapter::activate_bypass(prepared, transaction.commit())",
            ),
            (
                "runtime-launch-lifecycle-ready-red",
                "let readiness = on_ready(activated.into_inventory());",
                "drop(activated);",
            ),
            (
                "runtime-launch-lifecycle-stage-owner-red",
                "self.stack.register_detached(resource);",
                "drop(resource);",
            ),
            (
                "runtime-launch-lifecycle-worker-token-funnel-red",
                "WorkerSpec::PhaseOne(worker) => stack.register_with_token(worker),",
                "WorkerSpec::PhaseOne(worker) => stack.register_deferred_with_token(worker),",
            ),
            (
                "runtime-launch-lifecycle-empty-activation-red",
                "self.listener_count > 0,",
                "true,",
            ),
            (
                "runtime-launch-lifecycle-provider-role-red",
                "register_module_output(stack, provider.0);",
                "register_module_output(stack, domain.0);",
            ),
            (
                "runtime-launch-lifecycle-signal-red",
                "let shutdown = wait_for_shutdown_signal()?;",
                "let shutdown = wait_for_shutdown_signal_bypass()?;",
            ),
            (
                "runtime-launch-lifecycle-drain-red",
                "report_shutdown_failures(stack.shutdown_within(total_drain_budget.duration()).await)",
                "report_shutdown_failures(Vec::new())",
            ),
            (
                "runtime-launch-lifecycle-primary-error-red",
                "            Err(launch_error)\n        }\n    }\n}\n\n#[cfg(unix)]",
                "            Err(drain_error)\n        }\n    }\n}\n\n#[cfg(unix)]",
            ),
        ];

        let workspace = workspace_root()?;
        let source = fs::read_to_string(workspace.join(RUNTIMEEXEC_PATH))?;
        for (name, before, after) in cases {
            let root = replay_fixture(name)?;
            let mutated = source.replacen(before, after, 1);
            assert_ne!(mutated, source, "{name} mutation must change runtimeexec");
            write(&root.join(RUNTIMEEXEC_PATH), &mutated)?;

            let findings = runtime_launch_kernel_owner_findings(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding.subject == RUNTIMEEXEC_PATH
                        && finding.detail.contains("predicate=runtimeexec_lifecycle")
                }),
                "{name} must be rejected by the lifecycle predicate: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_launch_kernel_owner_rejects_semantic_carrier_mutations() -> Result<()> {
        let cases = [
            (
                "runtime-launch-carrier-transaction-red",
                "pub struct LaunchTransaction<'stack> {\n    stack: &'stack mut ShutdownStack,\n}",
                "pub struct LaunchTransaction<'stack> {\n    pub stack: &'stack mut ShutdownStack,\n}",
            ),
            (
                "runtime-launch-carrier-activated-red",
                "pub struct Activated<Inventory> {\n    inventory: Inventory,\n}",
                "pub struct Activated<Inventory> {\n    pub inventory: Inventory,\n}",
            ),
            (
                "runtime-launch-carrier-provider-batch-red",
                "pub struct ProviderLifecycleBatch(DomainModuleResult);",
                "pub struct ProviderLifecycleBatch(pub DomainModuleResult);",
            ),
            (
                "runtime-launch-carrier-role-constructor-red",
                "Self { provider, domain }",
                "Self {\n            provider: ProviderLifecycleBatch(domain.0),\n            domain: DomainLifecycleBatch(provider.0),\n        }",
            ),
        ];

        let workspace = workspace_root()?;
        let source = fs::read_to_string(workspace.join(RUNTIMEEXEC_PATH))?;
        for (name, before, after) in cases {
            let root = replay_fixture(name)?;
            let mutated = source.replacen(before, after, 1);
            assert_ne!(mutated, source, "{name} mutation must change runtimeexec");
            write(&root.join(RUNTIMEEXEC_PATH), &mutated)?;

            let findings = runtime_launch_kernel_owner_findings(&root)?;
            assert!(
                findings.iter().any(|finding| {
                    finding.subject == RUNTIMEEXEC_PATH
                        && finding.detail.contains("predicate=runtimeexec_owner_shape")
                }),
                "{name} must be rejected by the semantic carrier predicate: {findings:?}"
            );
        }
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
sharedRuntimeDeps = assemblies/runtime/src/module.rs
domainModuleResult = crates/bootstrap/src/module.rs
run = assemblies/runtime/src/lib.rs
launch = assemblies/runtime/src/launch.rs
runtimeexec = crates/runtimeexec/src/lib.rs

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
        assert!(!report.rendered.contains("[assembly.intent]"));
        assert!(!report.rendered.contains("[assembly.diportProviders]"));
        assert!(
            report
                .rendered
                .contains("mergeExtends = probes,resources,workers")
        );
        assert!(report.rendered.contains(
            "01 | prepare.config.snapshot | assemblies/runtime/src/lib.rs | RuntimeConfigSnapshot::capture_process_snapshot()"
        ));
        assert!(report.rendered.contains("| launch.register-lifecycle |"));
        assert!(report.rendered.contains("| launch.listener-prepare |"));
        assert!(report.rendered.contains("| launch.listener-activate |"));
        Ok(())
    }

    #[test]
    fn runtime_baseline_missing_baseline_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-missing")?;
        let (_, findings) = check_fixture_root(&root)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingBaseline));
        Ok(())
    }

    #[test]
    fn runtime_baseline_drift_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-drift")?;
        write(&root.join(BASELINE_PATH), "stale\n")?;
        let (_, findings) = check_fixture_root(&root)?;
        assert!(findings.iter().any(|f| f.rule == Rule::Drift));
        Ok(())
    }

    #[test]
    fn runtime_baseline_empty_dependencies_fail() -> Result<()> {
        let root = fixture_root("runtime-baseline-empty")?;
        write(
            &root.join(RUNTIME_CARGO_PATH),
            r#"
[package]
name = "runtime"
[dependencies]
"#,
        )?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == Rule::EmptyDependencies)
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_missing_required_anchor_fails() -> Result<()> {
        let root = fixture_root("runtime-baseline-missing-anchor")?;
        let anchor = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.wire.generated-domains")
            .context("generated domains anchor")?;
        let path = root.join(anchor.path);
        let source = fs::read_to_string(&path)?;
        let mutated = source.replacen(anchor.pattern, "removed_generated_domain_wiring", 1);
        anyhow::ensure!(mutated != source, "fixture anchor mutation must be live");
        write(&path, &mutated)?;
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
        let domains_path = root.join(RUNTIME_PHASE_DOMAINS_PATH);
        let canonical_domains = fs::read_to_string(&domains_path)?;
        let handwritten = canonical_domains.replacen(
            "        let result = async {",
            "        let result = async {\n            wire_settings(&deps);",
            1,
        );
        write(&domains_path, &handwritten)?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );

        let qualified = canonical_domains.replacen(
            "        let result = async {",
            "        let result = async {\n            crate::wire_settings(&deps);",
            1,
        );
        write(&domains_path, &qualified)?;
        let report = collect_report(&root)?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring)
        );

        write(&domains_path, &canonical_domains)?;
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
        write(&domains_path, &canonical_domains)?;
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

        let missing_merge = canonical_domains.replace(
            "provider_build.record_domain(domains_module);",
            "drop(domains_module);",
        ) + "\nfn dead_merge_bait(provider_build: &mut ProviderBuild, domains_module: DomainModuleResult) {\nprovider_build.record_domain(domains_module);\n}\n";
        write(&domains_path, &missing_merge)?;
        let report = collect_report(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.rule == Rule::MissingAnchor
                && finding.detail.contains("generated domains output")
        }));
        Ok(())
    }

    fn event_output_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        let workspace = workspace_root()?;
        for path in [
            RUNTIME_EVENT_PATH,
            RUNTIME_PHASE_DOMAINS_PATH,
            RUNTIMEEXEC_PATH,
        ] {
            write(&root.join(path), &fs::read_to_string(workspace.join(path))?)?;
        }
        Ok(root)
    }

    #[test]
    fn event_transport_output_funnel_accepts_unified_live_path() -> Result<()> {
        let root = event_output_fixture("event-transport-output-live")?;
        assert_eq!(
            event_transport_output_findings(&root)?,
            Vec::<Finding<Rule>>::new()
        );
        Ok(())
    }

    #[test]
    fn event_transport_output_funnel_rejects_legacy_and_bypasses() -> Result<()> {
        let root = event_output_fixture("event-transport-output-red")?;
        for (label, path, needle, replacement) in [
            (
                "public event output API",
                RUNTIME_EVENT_PATH,
                "pub(crate) async fn wire_event_transport",
                "pub async fn wire_event_transport",
            ),
            (
                "missing publisher receipt",
                RUNTIME_PHASE_DOMAINS_PATH,
                "provider_factories.event_publisher()?",
                "provider_factories.event_subscriber()?",
            ),
            (
                "parallel receiptless event output",
                RUNTIME_PHASE_DOMAINS_PATH,
                "provider_build\n                .record(crate::provider_output::ProviderOutput::event(",
                "provider_build.record_domain(event_module);\n            provider_build\n                .record(crate::provider_output::ProviderOutput::event(",
            ),
            (
                "direct lifecycle bypass",
                RUNTIMEEXEC_PATH,
                "let domain_result = register_module_output(stack, domain.0);",
                "let domain_result = register_module_output(stack, domain.0);\n    stack.register_detached(event_guard);",
            ),
            (
                "event-specific launch field",
                RUNTIMEEXEC_PATH,
                "pub struct LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {",
                "pub struct LaunchPlan<Adapter, ProbeReceipt, ReadyHook> {\n    event_infra_guards: Vec<Resource>,",
            ),
        ] {
            let target = root.join(path);
            let canonical = fs::read_to_string(&target)?;
            let mutated = canonical.replacen(needle, replacement, 1);
            assert_ne!(canonical, mutated, "{label} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                !event_transport_output_findings(&root)?.is_empty(),
                "{label} must fail closed"
            );
            write(&target, &canonical)?;
        }
        Ok(())
    }

    fn provider_bijection_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        write(&root.join("Cargo.toml"), "[workspace]\n")?;
        let workspace = workspace_root()?;
        for path in [
            PROVIDER_OUTPUT_PATH,
            GENERATED_PROVIDERS_PATH,
            RUNTIME_PHASE_PROVIDER_PATH,
            RUNTIME_PHASE_INFRA_PATH,
            RUNTIME_PHASE_DOMAINS_PATH,
            RUNTIME_PHASE_FINALIZE_PATH,
            RUNTIME_PHASE_LAUNCH_PATH,
            RUNTIME_LAUNCH_PATH,
            RUNTIMEEXEC_PATH,
        ] {
            write(&root.join(path), &fs::read_to_string(workspace.join(path))?)?;
        }
        Ok(root)
    }

    #[test]
    fn runtime_provider_bijection_gate_accepts_live_workspace() -> Result<()> {
        let root = provider_bijection_fixture("runtime-provider-bijection-live")?;
        assert_eq!(
            provider_plan_output_bijection_findings(&root)?,
            Vec::<Finding<Rule>>::new(),
            "real generated catalog → typed permits → transaction → launch path is the green proof"
        );
        Ok(())
    }

    #[test]
    fn runtime_provider_bijection_gate_rejects_drift_and_bypasses() -> Result<()> {
        let root = provider_bijection_fixture("runtime-provider-bijection-red")?;
        for (label, path, needle, replacement) in [
            (
                "generated factory drift",
                GENERATED_PROVIDERS_PATH,
                "ProviderFactorySymbol::HttpservePostgresAuthAuditSink",
                "ProviderFactorySymbol::SettingsVaultKeyProvider",
            ),
            (
                "duplicate typed permit consumption",
                RUNTIME_PHASE_PROVIDER_PATH,
                "provider_factories.listener_pdp()?",
                "provider_factories.listener_rate_limiter()?",
            ),
            (
                "missing transaction finish",
                RUNTIME_PHASE_DOMAINS_PATH,
                "provider_build.finish()",
                "provider_build.finish_bypass()",
            ),
            (
                "missing finish-failure abort",
                RUNTIME_PHASE_DOMAINS_PATH,
                "failure.abort().await",
                "failure.drop_without_abort().await",
            ),
            (
                "missing completed-probe abort",
                RUNTIME_PHASE_DOMAINS_PATH,
                "completed.abort(error).await",
                "completed.drop_without_abort(error).await",
            ),
            (
                "missing domains rollback abort",
                RUNTIME_PHASE_DOMAINS_PATH,
                "provider_build.abort(error).await",
                "provider_build.drop_without_abort(error).await",
            ),
            (
                "missing late rollback",
                RUNTIME_PHASE_FINALIZE_PATH,
                "provider_build.abort(error).await",
                "provider_build.drop_without_abort(error).await",
            ),
        ] {
            let target = root.join(path);
            let canonical = fs::read_to_string(&target)?;
            let mutated = canonical.replacen(needle, replacement, 1);
            assert_ne!(canonical, mutated, "{label} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                !provider_plan_output_bijection_findings(&root)?.is_empty(),
                "{label} must fail closed"
            );
            write(&target, &canonical)?;
        }

        let provider_output = root.join(PROVIDER_OUTPUT_PATH);
        let canonical = fs::read_to_string(&provider_output)?;
        write(
            &provider_output,
            &format!("{canonical}\ntrait ProviderOutput {{}}\n"),
        )?;
        assert!(
            !provider_plan_output_bijection_findings(&root)?.is_empty(),
            "legacy self-proof trait bait must fail closed"
        );
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
            let provider = RUNTIME_ANCHORS
                .iter()
                .find(|anchor| anchor.id == provider_id)
                .with_context(|| format!("missing provider anchor {provider_id}"))?;
            let path = root.join(provider.path);
            let source = fs::read_to_string(&path)?;
            let mutated = source.replacen(
                provider.pattern,
                "phase_result(RuntimePhase::BuildProvider, Ok::<_, anyhow::Error>(()))",
                1,
            );
            anyhow::ensure!(
                mutated != source,
                "provider fixture mutation must be live for {provider_id}"
            );
            write(&path, &mutated)?;
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
        let plan = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.plan.load")
            .context("plan anchor")?;
        let rss_access = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.provider.rss-access")
            .context("RSS access provider anchor")?;
        anyhow::ensure!(
            plan.path == rss_access.path,
            "provider anchors must share one owner"
        );
        let path = root.join(plan.path);
        let source = fs::read_to_string(&path)?;
        let sentinel = "__runtime_plan_anchor_sentinel__";
        let mutated = source
            .replacen(plan.pattern, sentinel, 1)
            .replacen(rss_access.pattern, plan.pattern, 1)
            .replacen(sentinel, rss_access.pattern, 1);
        anyhow::ensure!(mutated != source, "provider order mutation must be live");
        write(&path, &mutated)?;
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
            let path = root.join(anchor.path);
            let canonical = fs::read_to_string(&path)?;
            let replacement = if anchor_id.starts_with("run.resources.") {
                "{ removed_token_profile_anchor(); }"
            } else if anchor_id.ends_with("-jwks-name") {
                "removed_token_profile_anchor()"
            } else if anchor_id.ends_with("-jwks") {
                "Box::new(removed_token_profile_anchor("
            } else {
                "removed_token_profile_anchor("
            };
            let source = canonical.replacen(anchor.pattern, replacement, 1);
            anyhow::ensure!(
                source != canonical,
                "token-profile fixture mutation must be live for {anchor_id}"
            );
            let source = format!(
                "{source}\n// bait-only: {}\nconst TOKEN_PROFILE_BAIT: &str = {:?};\n",
                anchor.pattern.replace('\n', " "),
                anchor.pattern,
            );
            write(&path, &source)?;
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
use infra::vault::{VaultKeyProviderConfig, VaultRuntimeConfig};

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
    let vault_config = match VaultKeyProviderConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_key_provider();
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
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    } = RuntimeServingConfig::from_snapshot(config)?
        .into_parts();
    let pg_config = PgRuntimeConfig::from_snapshot(config)?;
    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;
    let s3_config = S3RuntimeConfig::from_snapshot(config)?;
    let PgRuntimeConfigParts {
        serving: serving_config,
        tenant_read: tenant_read_config,
        audit_admin: audit_admin_config,
        dlx_archiver: dlx_archiver_config,
        dlx_verifier: dlx_verifier_config,
        dlx_purger: dlx_purger_config,
        readiness_period: pg_readiness_period,
    } = pg_config.into_parts();
    let S3RuntimeConfigParts {
        general: s3_general_config,
        canary: s3_canary_config,
        dlx_archive: s3_dlx_archive_config,
    } = s3_config.into_parts();
    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
    let (vault, identity_signer, settings_key_name) = vault_config.into_runtime()?;
    let redis = build_redis_runtime_deps(redis_config);
    let s3 = build_s3_runtime_deps(s3_general_config);
    let wiring_inputs = RuntimeWiringInputs {
        event_transport,
        event_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    };
    let RuntimeWiringInputs {
        event_transport,
        event_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    } = wiring_inputs;
    modules_gen::wire_domains(&deps, domain_modules, &placement_execution_plan);
    wire_auth_grant_sweeper(&pg, auth_grant_sweep_interval);
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
    PgRuntimeDeps::connect_serving(
        &serving_config, &tenant_read_config, audit_admin_config.as_ref(), projection_capture,
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
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
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
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport,\n        event_worker,\n        distributed_worker,",
                    "    let wiring_inputs = RuntimeWiringInputs {\n        event_transport: distributed_worker,\n        event_worker,\n        distributed_worker: event_transport,",
                ),
            ),
            (
                "serving sink hidden in dead closure",
                canonical.replace(
                    "    wire_auth_grant_sweeper(&pg, auth_grant_sweep_interval);",
                    "    let _dead = || wire_auth_grant_sweeper(&pg, auth_grant_sweep_interval);",
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
                    "let (vault, identity_signer, settings_key_name) = vault_config.into_runtime()?;",
                    "let _vault_bait = vault_config.into_runtime()?;\n    let (vault, identity_signer, settings_key_name) = vault_config.into_runtime()?;",
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
                    "let vault_config = match VaultKeyProviderConfig::from_snapshot(config) {",
                    "let vault_config = match VaultKeyProviderConfig::from_snapshot(snapshot_from_ambient(|| std::env::var(\"RSS_VAULT_TOKEN\"))) {",
                ),
            ),
            (
                "maintenance Vault consume alias",
                canonical.replace(
                    "let _parts = vault_config.into_key_provider();",
                    "let provider_config = vault_config;\n    let _parts = provider_config.into_key_provider();",
                ),
            ),
            (
                "maintenance Vault binding shadow",
                canonical.replace(
                    "let _parts = vault_config.into_key_provider();",
                    "let vault_config = other_vault_config;\n    let _parts = vault_config.into_key_provider();",
                ),
            ),
            (
                "maintenance unrelated consume bait",
                canonical.replace(
                    "let _parts = vault_config.into_key_provider();",
                    "let _bait = other_vault_config.into_key_provider();\n    let _parts = vault_config.into_key_provider();",
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
    tenant_store_allowlist_json: String,
) -> anyhow::Result<(VaultRuntimeDeps, std::sync::Arc<VaultSigner>, KeyName)> {
    let config = VaultRuntimeConfig::from_values(VaultConfigValues {
        addr: Some(addr),
        token: Some(token.as_str()),
        transit_mount: Some(transit_mount),
        ca_cert_pem_path: None,
        settings_key_name: Some(settings_key_name.as_str()),
        tenant_store_allowlist_json: Some(tenant_store_allowlist_json.as_str()),
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
    force_path_style: bool,
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<S3RuntimeDeps> {
    let endpoint = secure::S3Endpoint::parse(endpoint_url, secure::PlaintextEndpointPolicy::Deny)
        .with_context(|| {
            format!("{S3_ENDPOINT_URL_ENV} must be https:// (plaintext http:// is banned)")
        })?;
    let factory = s3::PrivateCaS3ClientFactory::new(
        endpoint,
        DEFAULT_S3_REGION,
        aws_sdk_s3::config::Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "rss-runtime-integration",
        ),
        force_path_style,
        ca_cert_pem,
    );
    let client = factory
        .build_client()
        .context("build S3 client with private CA")?;
    let store = S3Store::new(client, bucket).context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
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
        tenant_store_allowlist_json: String,
    ) -> anyhow::Result<(
        vault::VaultRuntimeDeps,
        Arc<vault::VaultSigner>,
        diport::KeyName,
    )> {
        crate::infra::vault::build_vault_runtime_from_values(
            addr, token, transit_mount, settings_key_name, tenant_store_allowlist_json,
        )
    }

    pub fn build_s3_runtime_deps_from_values(
        endpoint_url: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        force_path_style: bool,
        ca_cert_pem: Vec<u8>,
    ) -> anyhow::Result<s3::S3RuntimeDeps> {
        crate::infra::s3::build_s3_runtime_deps_from_values(
            endpoint_url, bucket, access_key_id, secret_access_key,
            force_path_style, ca_cert_pem,
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
        assert!(internal_is_exact(
            &vault_equivalent,
            "build_vault_runtime_from_values"
        )?);

        for (label, source, name) in [
            (
                "Vault zero args",
                vault_internal.replace(
                    "    addr: String,\n    token: String,\n    transit_mount: String,\n    settings_key_name: String,\n    tenant_store_allowlist_json: String,\n",
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
                    "    endpoint_url: String,\n    bucket: String,\n    access_key_id: String,\n    secret_access_key: String,\n    force_path_style: bool,\n    ca_cert_pem: Vec<u8>,\n",
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
                "S3 plaintext policy bait",
                s3_internal.replace(
                    "secure::PlaintextEndpointPolicy::Deny",
                    "secure::PlaintextEndpointPolicy::Allow",
                ),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 wrong callee",
                s3_internal.replace(
                    "s3::PrivateCaS3ClientFactory::new",
                    "s3::PlaintextS3ClientFactory::new",
                ),
                "build_s3_runtime_deps_from_values",
            ),
            (
                "S3 extra statement",
                s3_internal.replace(
                    "    Ok(S3RuntimeDeps::new(store))",
                    "    audit_values();\n    Ok(S3RuntimeDeps::new(store))",
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
                    "            addr, token, transit_mount, settings_key_name, tenant_store_allowlist_json,",
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
                    "            addr, token, transit_mount, settings_key_name, tenant_store_allowlist_json,",
                    "            std::env::var(\"RSS_VAULT_ADDR\")?, token, transit_mount, settings_key_name, tenant_store_allowlist_json,",
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

    fn vault_allowlist_typed_funnel_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        write(&root.join(RUNTIME_CONFIG_FIXTURE_MARKER), "enabled\n")?;
        for relative in [
            RUNTIME_CONFIG_PATH,
            RUNTIME_VAULT_PATH,
            RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
        ] {
            write(
                &root.join(relative),
                &fs::read_to_string(workspace.join(relative))?,
            )?;
        }
        Ok(root)
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_rejects_bypasses() -> Result<()> {
        let root = vault_allowlist_typed_funnel_fixture("vault-allowlist-typed-funnel")?;
        let canonical_findings = vault_allowlist_typed_funnel_findings(&root)?;
        assert!(
            canonical_findings.is_empty(),
            "canonical snapshot -> typed allowlist -> resolver funnel must pass: {canonical_findings:?}"
        );

        let config_path = root.join(RUNTIME_CONFIG_PATH);
        let canonical_config = fs::read_to_string(&config_path)?;
        let vault_path = root.join(RUNTIME_VAULT_PATH);
        let canonical_vault = fs::read_to_string(&vault_path)?;
        let validator_path = root.join(RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH);
        let canonical_validator = fs::read_to_string(&validator_path)?;
        for (label, relative, source) in [
            (
                "missing catalog key",
                RUNTIME_CONFIG_PATH,
                canonical_config.replacen(
                    "    \"RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON\",\n",
                    "",
                    1,
                ),
            ),
            (
                "missing snapshot read",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "tenant_store_allowlist_json: config.value(VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV),",
                    "tenant_store_allowlist_json: None,",
                    1,
                ),
            ),
            (
                "optional serving field",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "stores: TenantStoreAllowlist,",
                    "stores: Option<TenantStoreAllowlist>,",
                    1,
                ),
            ),
            (
                "runtime empty reconstruction",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "let Self { provider, stores } = self;",
                    "let Self { provider, stores: _ } = self;\n        let stores = TenantStoreAllowlist::new(std::iter::empty())?;",
                    1,
                ),
            ),
            (
                "alternate ambient source",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "tenant_store_allowlist_json: config.value(VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV),",
                    "tenant_store_allowlist_json: std::env::var(VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV).ok().as_deref(),",
                    1,
                ),
            ),
            (
                "tenant field substitution",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "TenantId::parse(&binding.tenant_id)",
                    "TenantId::parse(&binding.store_id)",
                    1,
                ),
            ),
            (
                "store field substitution",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "settings::ports::StoreId::parse(&binding.store_id)",
                    "settings::ports::StoreId::parse(&binding.tenant_id)",
                    1,
                ),
            ),
            (
                "mount field rewrite",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "mount: binding.mount,",
                    "mount: binding.kv_path_prefix.clone(),",
                    1,
                ),
            ),
            (
                "prefix field rewrite",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "kv_path_prefix: binding.kv_path_prefix,",
                    "kv_path_prefix: format!(\"shadow/{}\", binding.kv_path_prefix),",
                    1,
                ),
            ),
            (
                "disconnected canonical mapper proof",
                RUNTIME_VAULT_PATH,
                canonical_vault
                    .replacen("let bindings = wire", "let _proof = wire", 1)
                    .replacen(
                        "TenantStoreAllowlist::new(bindings)",
                        "let bindings = Vec::new();\n    TenantStoreAllowlist::new(bindings)",
                        1,
                    ),
            ),
            (
                "maintenance allowlist read",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "impl VaultKeyProviderConfig {\n    pub(crate) fn from_snapshot(\n        config: SnapshotConfig<'_>,\n    ) -> Result<Self, VaultKeyProviderConfigError> {\n        let provider = VaultProviderConfig::from_values(VaultProviderValues {",
                    "impl VaultKeyProviderConfig {\n    pub(crate) fn from_snapshot(\n        config: SnapshotConfig<'_>,\n    ) -> Result<Self, VaultKeyProviderConfigError> {\n        let _allowlist = config.value(VAULT_TENANT_STORE_ALLOWLIST_JSON_ENV);\n        let provider = VaultProviderConfig::from_values(VaultProviderValues {",
                    1,
                ),
            ),
            (
                "maintenance allowlist error branch",
                RUNTIME_VAULT_PATH,
                canonical_vault.replacen(
                    "pub(crate) enum VaultKeyProviderConfigError {\n",
                    "pub(crate) enum VaultKeyProviderConfigError {\n    #[error(\"unreachable allowlist error\")]\n    TenantStoreAllowlist(#[source] VaultTenantStoreAllowlistConfigError),\n",
                    1,
                ),
            ),
            (
                "offline validator missing typed parser",
                RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
                canonical_validator.replacen(
                    "crate::infra::vault::tenant_store_allowlist_from_value(Some(&raw))?;",
                    "let _ = raw;",
                    1,
                ),
            ),
            (
                "offline validator alternate JSON parser",
                RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
                canonical_validator.replacen(
                    "crate::infra::vault::tenant_store_allowlist_from_value(Some(&raw))?;",
                    "let _: serde_json::Value = serde_json::from_str(&raw).map_err(|_| VaultAllowlistValidationCommandError::InvalidJson)?;",
                    1,
                ),
            ),
            (
                "offline validator ambient allowlist reader",
                RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
                canonical_validator.replacen(
                    "let raw = read_input(parse_input(args)?, stdin)?;",
                    "let raw = std::env::var(\"RSS_VAULT_TENANT_STORE_ALLOWLIST_JSON\").map_err(|_| VaultAllowlistValidationCommandError::InputRead)?;",
                    1,
                ),
            ),
            (
                "offline validator output leak",
                RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
                canonical_validator.replacen(
                    "writeln!(stdout, \"{VALIDATION_SUCCEEDED}\")",
                    "writeln!(stdout, \"{raw}\")",
                    1,
                ),
            ),
        ] {
            let target = root.join(relative);
            let canonical = if relative == RUNTIME_CONFIG_PATH {
                &canonical_config
            } else if relative == RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH {
                &canonical_validator
            } else {
                &canonical_vault
            };
            anyhow::ensure!(source != *canonical, "{label} mutation must be live");
            write(&target, &source)?;
            assert!(
                !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
                "Vault allowlist typed funnel must reject {label}"
            );
            write(&target, canonical)?;
        }

        let unexpected_owner_path = root.join(RUNTIME_OPERATOR_SETTINGS_PATH);
        for (label, source) in [
            (
                "third-owner direct parser call",
                r#"fn extra_allowlist_parse(raw: &str) {
    let _ = crate::infra::vault::tenant_store_allowlist_from_value(Some(raw));
}
"#,
            ),
            (
                "third-owner parser import alias",
                r#"use crate::infra::vault::tenant_store_allowlist_from_value as parse_allowlist;
fn extra_allowlist_parse(raw: &str) { let _ = parse_allowlist(Some(raw)); }
"#,
            ),
            (
                "third-owner parser helper",
                r#"fn hidden_allowlist_helper(raw: &str) {
    let _ = crate::infra::vault::tenant_store_allowlist_from_value(Some(raw));
}
fn extra_allowlist_parse(raw: &str) { hidden_allowlist_helper(raw); }
"#,
            ),
            (
                "third-owner parser re-export",
                r#"pub(crate) use crate::infra::vault::tenant_store_allowlist_from_value;
"#,
            ),
        ] {
            write(&unexpected_owner_path, source)?;
            assert!(
                !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
                "Vault allowlist parser callsite exact-set must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_fails_closed_without_carriers() -> Result<()> {
        for relative in [
            RUNTIME_CONFIG_PATH,
            RUNTIME_VAULT_PATH,
            RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH,
        ] {
            let root = vault_allowlist_typed_funnel_fixture("vault-allowlist-missing-carrier")?;
            fs::remove_file(root.join(relative))?;
            assert!(
                !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
                "missing Vault allowlist carrier must fail closed: {relative}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_rejects_constructor_bypass_without_parser_token()
    -> Result<()> {
        let root = vault_allowlist_typed_funnel_fixture("vault-allowlist-constructor-bypass")?;
        write(
            &root.join(RUNTIME_SRC_PATH).join("bypass.rs"),
            r#"
fn bypass(
    raw: &str,
    entries: Vec<((vocab::tenant::TenantId, String), vault::StoreBinding)>,
    client: reqwest::Client,
    addr: String,
    token: String,
) {
    let _: serde_json::Value = serde_json::from_str(raw).unwrap();
    let allowlist = vault::TenantStoreAllowlist::new(entries).unwrap();
    let _ = vault::VaultSecretResolver::new(
        client,
        addr,
        token,
        std::time::Duration::from_secs(1),
        allowlist,
    );
}
"#,
        )?;
        assert!(
            !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
            "alternate parse -> allowlist constructor -> resolver constructor must fail closed"
        );
        Ok(())
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_rejects_semantic_constructor_aliases() -> Result<()> {
        for (label, source) in [
            (
                "function item",
                r#"fn bypass() {
    let make_allowlist = vault::TenantStoreAllowlist::new;
    let make_resolver = vault::VaultSecretResolver::new;
    let _ = (make_allowlist, make_resolver);
}
"#,
            ),
            (
                "import alias",
                r#"use vault::{TenantStoreAllowlist as Allowlist, VaultSecretResolver as Resolver};
fn bypass() { let _ = (Allowlist::new, Resolver::new); }
"#,
            ),
            (
                "re-export",
                r#"pub(crate) use vault::{TenantStoreAllowlist, VaultSecretResolver};
"#,
            ),
            (
                "macro generated bypass",
                r#"macro_rules! bypass {
    () => {{
        let make_allowlist = vault::TenantStoreAllowlist::new;
        let make_resolver = vault::VaultSecretResolver::new;
        (make_allowlist, make_resolver)
    }};
}
"#,
            ),
        ] {
            let root = vault_allowlist_typed_funnel_fixture("vault-allowlist-semantic-alias")?;
            write(&root.join(RUNTIME_SRC_PATH).join("bypass.rs"), source)?;
            assert!(
                !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
                "Vault allowlist constructor inventory must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_closes_http_opt_in_constructor_sink() -> Result<()> {
        for (label, source) in [
            (
                "direct call",
                r#"fn bypass(
    client: reqwest::Client,
    allowlist: vault::TenantStoreAllowlist,
) {
    let _ = vault::VaultSecretResolver::new_allow_http(
        client,
        "http://vault.invalid",
        "token",
        std::time::Duration::from_secs(1),
        allowlist,
    );
}
"#,
            ),
            (
                "function item",
                r#"fn bypass() {
    let make_resolver = vault::VaultSecretResolver::new_allow_http;
    let _ = make_resolver;
}
"#,
            ),
            (
                "import alias",
                r#"use vault::VaultSecretResolver as Resolver;
fn bypass() { let _ = Resolver::new_allow_http; }
"#,
            ),
            (
                "re-export",
                r#"pub(crate) use vault::VaultSecretResolver;
fn bypass() { let _ = VaultSecretResolver::new_allow_http; }
"#,
            ),
            (
                "macro generated",
                r#"macro_rules! bypass {
    () => { vault::VaultSecretResolver::new_allow_http };
}
"#,
            ),
        ] {
            let root = vault_allowlist_typed_funnel_fixture("vault-http-constructor-sink")?;
            write(&root.join(RUNTIME_SRC_PATH).join("bypass.rs"), source)?;
            assert!(
                !vault_allowlist_typed_funnel_findings(&root)?.is_empty(),
                "all resolver construction capabilities must be closed: {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_vault_allowlist_typed_funnel_accepts_equivalent_refactors() -> Result<()> {
        let root = vault_allowlist_typed_funnel_fixture("vault-allowlist-equivalent-refactors")?;
        let vault_path = root.join(RUNTIME_VAULT_PATH);
        let vault = fs::read_to_string(&vault_path)?
            .replacen("raw: Option<&str>", "input: Option<&str>", 1)
            .replacen(
                "let raw = raw.ok_or(VaultTenantStoreAllowlistConfigError::Missing)?;",
                "let document = input.ok_or(VaultTenantStoreAllowlistConfigError::Missing)?;",
                1,
            )
            .replacen("raw.trim().is_empty()", "document.trim().is_empty()", 1)
            .replacen(
                "serde_json::from_str(raw)",
                "serde_json::from_str(document)",
                1,
            )
            .replacen(
                "fn from_values(values: VaultConfigValues<'_>) -> Result<Self, VaultRuntimeConfigError> {",
                "fn from_values(input_values: VaultConfigValues<'_>) -> Result<Self, VaultRuntimeConfigError> {",
                1,
            )
            .replacen("addr: values.addr,", "addr: input_values.addr,", 1)
            .replacen("token: values.token,", "token: input_values.token,", 1)
            .replacen(
                "transit_mount: values.transit_mount,",
                "transit_mount: input_values.transit_mount,",
                1,
            )
            .replacen(
                "ca_cert_pem_path: values.ca_cert_pem_path,",
                "ca_cert_pem_path: input_values.ca_cert_pem_path,",
                1,
            )
            .replacen(
                "settings_key_name: values.settings_key_name,",
                "settings_key_name: input_values.settings_key_name,",
                1,
            )
            .replacen(
                "let stores = tenant_store_allowlist_from_value(values.tenant_store_allowlist_json)",
                "let allowlist = tenant_store_allowlist_from_value(input_values.tenant_store_allowlist_json)",
                1,
            )
            .replacen(
                "Ok(Self { provider, stores })",
                "let _benign = ();\n        Ok(Self { provider, stores: allowlist })",
                1,
            )
            .replacen(
                "let Self { provider, stores } = self;",
                "let Self { provider, stores: allowlist } = self;",
                1,
            )
            .replacen(
                "            stores,\n        )\n        .map_err(|e| {\n            VaultRuntimeConfigError::VaultClient(anyhow::anyhow!(\n                \"vault resolver config error: {e}\"",
                "            allowlist,\n        )\n        .map_err(|e| {\n            VaultRuntimeConfigError::VaultClient(anyhow::anyhow!(\n                \"vault resolver config error: {e}\"",
                1,
            )
            .replacen(
                "pub(crate) fn tenant_store_allowlist_from_value(",
                "fn parse_allowlist_binding(\n    input_binding: VaultTenantStoreBindingWire,\n) -> Result<((TenantId, String), StoreBinding), VaultTenantStoreAllowlistConfigError> {\n    let parsed_tenant = TenantId::parse(&input_binding.tenant_id)\n        .map_err(|_| VaultTenantStoreAllowlistConfigError::InvalidTenantId)?;\n    let parsed_store = settings::ports::StoreId::parse(&input_binding.store_id)\n        .map_err(|_| VaultTenantStoreAllowlistConfigError::InvalidStoreId)?;\n    Ok((\n        (parsed_tenant, parsed_store.as_str().to_owned()),\n        StoreBinding {\n            mount: input_binding.mount,\n            kv_path_prefix: input_binding.kv_path_prefix,\n        },\n    ))\n}\n\npub(crate) fn tenant_store_allowlist_from_value(",
                1,
            )
            .replacen(
                ".map(|binding| {\n            let tenant = TenantId::parse(&binding.tenant_id)\n                .map_err(|_| VaultTenantStoreAllowlistConfigError::InvalidTenantId)?;\n            let store = settings::ports::StoreId::parse(&binding.store_id)\n                .map_err(|_| VaultTenantStoreAllowlistConfigError::InvalidStoreId)?;\n            Ok((\n                (tenant, store.as_str().to_owned()),\n                StoreBinding {\n                    mount: binding.mount,\n                    kv_path_prefix: binding.kv_path_prefix,\n                },\n            ))\n        })",
                ".map(parse_allowlist_binding)",
                1,
            );
        write(&vault_path, &vault)?;

        let validator_path = root.join(RUNTIME_OPERATOR_VAULT_ALLOWLIST_PATH);
        let validator = fs::read_to_string(&validator_path)?
            .replacen(
                "fn parse_input(\n    args: &[String],\n) -> Result<VaultAllowlistInput<'_>, VaultAllowlistValidationCommandError> {\n    match args {",
                "fn parse_input(\n    command_args: &[String],\n) -> Result<VaultAllowlistInput<'_>, VaultAllowlistValidationCommandError> {\n    let _benign = ();\n    match command_args {",
                1,
            )
            .replacen(
                "fn read_input(\n    input: VaultAllowlistInput<'_>,\n    stdin: &mut impl std::io::Read,\n) -> Result<String, VaultAllowlistValidationCommandError> {\n    match input {",
                "fn read_input(\n    selected_input: VaultAllowlistInput<'_>,\n    stdin: &mut impl std::io::Read,\n) -> Result<String, VaultAllowlistValidationCommandError> {\n    let _benign = ();\n    match selected_input {",
                1,
            )
            .replacen(
            r#"fn run_vault_allowlist_validation_with_io(
    args: &[String],
    stdin: &mut impl std::io::Read,
    stdout: &mut impl std::io::Write,
) -> Result<(), VaultAllowlistValidationCommandError> {
    let raw = read_input(parse_input(args)?, stdin)?;
    crate::infra::vault::tenant_store_allowlist_from_value(Some(&raw))?;
    writeln!(stdout, "{VALIDATION_SUCCEEDED}")
        .map_err(|_| VaultAllowlistValidationCommandError::OutputWrite)
}"#,
            r#"fn validate_document(raw: &str) -> Result<(), VaultAllowlistValidationCommandError> {
    crate::infra::vault::tenant_store_allowlist_from_value(Some(raw))?;
    Ok(())
}

fn run_vault_allowlist_validation_with_io(
    args: &[String],
    stdin: &mut impl std::io::Read,
    stdout: &mut impl std::io::Write,
) -> Result<(), VaultAllowlistValidationCommandError> {
    let document = read_input(parse_input(args)?, stdin)?;
    validate_document(&document)?;
    writeln!(stdout, "{VALIDATION_SUCCEEDED}")
        .map_err(|_| VaultAllowlistValidationCommandError::OutputWrite)
}"#,
            1,
        );
        write(&validator_path, &validator)?;

        let findings = vault_allowlist_typed_funnel_findings(&root)?;
        assert!(
            findings.is_empty(),
            "alpha-renaming and helper extraction must preserve the semantic proof: {findings:?}"
        );
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
use infra::vault::{VaultKeyProviderConfig, VaultRuntimeConfig};
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
    let vault_config = match VaultKeyProviderConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_key_provider();
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
    let (vault, identity_signer, settings_key_name) = vault_config.into_runtime();
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
use infra::vault::{VaultKeyProviderConfig, VaultRuntimeConfig};
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
    let vault_config = match VaultKeyProviderConfig::from_snapshot(config) {
        Ok(config) => config,
        Err(error) => return,
    };
    let _parts = vault_config.into_key_provider();
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
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    } = RuntimeServingConfig::from_snapshot(config)?
        .into_parts();
    let pg_config = PgRuntimeConfig::from_snapshot(config)?;
    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;
    let s3_config = S3RuntimeConfig::from_snapshot(config)?;
    let PgRuntimeConfigParts {
        serving: serving_config,
        tenant_read: tenant_read_config,
        audit_admin: audit_admin_config,
        dlx_archiver: dlx_archiver_config,
        dlx_verifier: dlx_verifier_config,
        dlx_purger: dlx_purger_config,
        readiness_period: pg_readiness_period,
    } = pg_config.into_parts();
    let S3RuntimeConfigParts {
        general: s3_general_config,
        canary: s3_canary_config,
        dlx_archive: s3_dlx_archive_config,
    } = s3_config.into_parts();
    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
    let (vault, identity_signer, settings_key_name) = vault_config.into_runtime()?;
    let redis = build_redis_runtime_deps(redis_config);
    let s3 = build_s3_runtime_deps(s3_general_config);
    let wiring_inputs = RuntimeWiringInputs {
        event_transport,
        event_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    };
    let RuntimeWiringInputs {
        event_transport,
        event_worker,
        distributed_worker,
        domain_modules,
        audit_consumer_key,
        auth_grant_sweep_interval,
    } = wiring_inputs;
    modules_gen::wire_domains(&deps, domain_modules, &placement_execution_plan);
    wire_auth_grant_sweeper(&pg, auth_grant_sweep_interval);
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
    PgRuntimeDeps::connect_serving(
        &serving_config,
        &tenant_read_config,
        audit_admin_config.as_ref(),
        projection_capture,
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
        include_str!("../../bins/rss/src/main.rs")
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
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;",
                    "use runtime::operator as operator;\n    let _bait = operator::prepare_runtime()?;\n    let runtime_inputs = runtime::operator::prepare_runtime()?;",
                ),
            ),
            (
                "rss wrong shutdown binding",
                canonical_rss.replace(
                    "runtime::operator::shutdown_runtime(runtime_inputs)",
                    "runtime::operator::shutdown_runtime(other_inputs)",
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
        let canonical_findings = runtime_config_snapshot_findings_for_file(&canonical_file);
        assert!(
            canonical_findings.is_empty(),
            "one runtime_inputs.config() view must construct the PG and Redis typed configs; the Redis builder consumes its config by value: {canonical_findings:?}"
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
                canonical.replace("&serving_config,", "&wrong_serving_config,"),
            ),
            (
                "discarded typed parts are compliant bait",
                canonical.replace(
                    "} = pg_config.into_parts();",
                    "} = pg_config.into_parts();\n    let _ = (serving_config, tenant_read_config, audit_admin_config);",
                )
                .replace("&serving_config,", "&wrong_serving_config,"),
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
            "stateful operator calls must receive the exact prepared &runtime_inputs binding"
        );
        for operator_call in [
            "run_projection_control_command(&args, &runtime_inputs)",
            "run_audit_ledger_verify_command(&args, &runtime_inputs)",
            "run_dlq_control_command(&args, &runtime_inputs)",
            "run_reconcile_target_command(&args, &runtime_inputs)",
            "run_settings_config_value_maintenance(&args, &runtime_inputs)",
            "run_rss_access_jwks_export_command(&args, &runtime_inputs)",
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

    fn workspace_operator_source() -> Result<String> {
        let root = workspace_root()?;
        [
            RUNTIME_OPERATOR_PROJECTION_PATH,
            RUNTIME_OPERATOR_AUDIT_PATH,
            RUNTIME_OPERATOR_DLQ_PATH,
            RUNTIME_OPERATOR_RECONCILE_PATH,
            RUNTIME_OPERATOR_SETTINGS_PATH,
        ]
        .into_iter()
        .map(|path| {
            fs::read_to_string(root.join(path))
                .with_context(|| format!("read operator baseline source {path}"))
        })
        .collect::<Result<Vec<_>>>()
        .map(|sources| {
            sources
                .into_iter()
                .map(|source| {
                    source
                        .lines()
                        .filter(|line| !line.trim_start().starts_with("#!["))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
    }

    #[test]
    fn runtime_pg_redis_snapshot_wiring_rejects_operator_definition_bypasses() -> Result<()> {
        let source = workspace_operator_source()?;
        let canonical = syn::parse_file(&source)?;
        assert!(
            pg_operator_definitions_are_exact(&canonical),
            "the five PG-backed operator definitions are the anti-vacuity green"
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
    fn runtime_jwks_export_requires_snapshot_and_operator_capability() -> Result<()> {
        let root = workspace_root()?;
        let vault_source = fs::read_to_string(root.join(RUNTIME_VAULT_PATH))?;
        let operator_source = fs::read_to_string(root.join(RUNTIME_OPERATOR_JWKS_PATH))?;
        let vault = syn::parse_file(&vault_source)?;
        let operator = syn::parse_file(&operator_source)?;
        assert!(
            rss_access_jwks_capability_flow_is_exact(&vault, &operator),
            "workspace JWKS export is the capability-bound anti-vacuity green"
        );

        for (label, mutated_vault, mutated_operator) in [
            (
                "production bool seam",
                vault_source.replacen(
                    "_operator: OperatorRuntimeCapability<'_>,",
                    "allow_http: bool,",
                    1,
                ),
                operator_source.clone(),
            ),
            (
                "operator getter closure",
                vault_source.clone(),
                operator_source.replacen(
                    "runtime_inputs.config(),\n        runtime_inputs.operator_capability(),",
                    "|name| runtime_inputs.config().value(name).map(str::to_owned),\n        false,",
                    1,
                ),
            ),
            (
                "aliased export",
                vault_source.clone(),
                operator_source
                    .replacen(
                        "use crate::phase::OperatorRuntimeInputs;",
                        "use crate::infra::vault::export_rss_access_jwks as hidden_export;\nuse crate::phase::OperatorRuntimeInputs;",
                        1,
                    )
                    .replace(
                        "crate::infra::vault::export_rss_access_jwks(",
                        "hidden_export(",
                    ),
            ),
            (
                "dead production helper",
                vault_source.clone(),
                format!(
                    "{operator_source}\nasync fn dead(args: &[String], inputs: &OperatorRuntimeInputs) {{ let _ = crate::infra::vault::export_rss_access_jwks(args, inputs.config(), inputs.operator_capability()).await; }}\n"
                ),
            ),
            (
                "legacy raw getter seam",
                format!(
                    "{vault_source}\npub(crate) async fn export_rss_access_jwks_from(args: &[String], get: impl Fn(&str) -> Option<String>, allow_http: bool) -> anyhow::Result<()> {{ let _ = (args, get, allow_http); Ok(()) }}\n"
                ),
                operator_source.clone(),
            ),
        ] {
            assert!(
                mutated_vault != vault_source || mutated_operator != operator_source,
                "{label} must mutate Vault or operator source"
            );
            let mutated_vault = syn::parse_file(&mutated_vault)
                .with_context(|| format!("parse {label} Vault mutation"))?;
            let mutated_operator = syn::parse_file(&mutated_operator)
                .with_context(|| format!("parse {label} operator mutation"))?;
            assert!(
                !rss_access_jwks_capability_flow_is_exact(&mutated_vault, &mutated_operator),
                "JWKS capability gate must reject {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_pg_operator_provenance_allows_equivalent_local_structure() -> Result<()> {
        let source = workspace_operator_source()?;
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
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    build_redis_runtime_deps(config).await.map(|(deps, _)| deps)
}
"#;
        let wrapper = r#"
#[cfg(feature = "integration")]
pub mod test_support {
    pub async fn build_redis_runtime_deps_from_values(
        url: String,
        ca_cert_pem: Vec<u8>,
    ) -> anyhow::Result<redis::RedisRuntimeDeps> {
        crate::infra::redis::build_redis_runtime_deps_from_values(url, ca_cert_pem).await
    }
}
"#;
        let pool = r#"
pub(crate) async fn build_redis_runtime_deps(config: RedisRuntimeConfig) -> anyhow::Result<(redis::RedisRuntimeDeps, Duration)> {
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build redis TLS pool with private CA")?;
    deps.ping()
        .await
        .with_context(|| format!("verify redis connectivity"))?;
    Ok((deps, readiness_interval))
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
                "second private-CA connect",
                pool.replace(
                    "let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)",
                    "let _second = redis::RedisRuntimeDeps::connect_with_private_ca(&other, ca)?;\n    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)",
                ),
            ),
            (
                "ping uses a different binding",
                pool.replace("deps.ping()", "other.ping()"),
            ),
            (
                "create_pool revival bait",
                format!(
                    "{pool}\nfn readiness_sampler() {{ deadpool_redis::Config::from_url(other_url).create_pool(Some(Runtime::Tokio1)); }}\n"
                ),
            ),
            (
                "connect without ping",
                pool.replace(
                    "deps.ping()\n        .await\n        .with_context(|| format!(\"verify redis connectivity\"))?;\n    ",
                    "",
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
                "offline validator prepares operator runtime",
                canonical.replace(
                    "return runtime::operator::run_vault_allowlist_validation_command(&args);",
                    "let _runtime_inputs = runtime::operator::prepare_runtime()?;\n        return runtime::operator::run_vault_allowlist_validation_command(&args);",
                ),
            ),
            (
                "unknown command check after acquisition",
                canonical.replace(
                    "let command = classify_command(&args)?;",
                    "let _early = runtime::operator::prepare_runtime()?;\n    let command = classify_command(&args)?;",
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
                    "runtime::operator::run_projection_control_command(&args, &runtime_inputs).await",
                    "shadow::runtime::operator::run_projection_control_command(&args, &runtime_inputs).await",
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
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;",
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;\n    preflight()?;",
                ),
            ),
            (
                "ensure pre-consumption side path",
                canonical.replace(
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;",
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;\n    anyhow::ensure!(ready(), \"not ready\");",
                ),
            ),
            (
                "bail pre-consumption side path",
                canonical.replace(
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;",
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;\n    if !ready() { anyhow::bail!(\"not ready\"); }",
                ),
            ),
            (
                "operator arm returns before shared shutdown",
                canonical.replace(
                    "runtime::operator::run_projection_control_command(&args, &runtime_inputs).await",
                    "return runtime::operator::run_projection_control_command(&args, &runtime_inputs).await",
                ),
            ),
            (
                "duplicate operator arm is unreachable bait",
                canonical.replace(
                    "OperatorCommand::AuditLedgerVerify => {\n            runtime::operator::run_audit_ledger_verify_command(&args, &runtime_inputs).await\n        }",
                    "OperatorCommand::AuditLedgerVerify => {\n            runtime::operator::run_audit_ledger_verify_command(&args, &runtime_inputs).await\n        }\n        OperatorCommand::AuditLedgerVerify => command_bait().await,",
                ),
            ),
            (
                "wrong shutdown binding",
                canonical.replace(
                    "runtime::operator::shutdown_runtime(runtime_inputs)",
                    "runtime::operator::shutdown_runtime(other_inputs)",
                ),
            ),
            (
                "runtime macro bait",
                canonical.replace(
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;",
                    "let runtime_inputs = runtime::operator::prepare_runtime()?;\n    passthrough!(runtime::run(other_inputs));",
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
        copy_runtime_sources(&root)?;
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
    fn runtime_baseline_ignores_anchor_outside_run_body() -> Result<()> {
        let root = fixture_root("runtime-baseline-anchor-outside-run")?;
        let anchor = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.wire.generated-domains")
            .context("generated domains anchor")?;
        let path = root.join(anchor.path);
        let source = fs::read_to_string(&path)?;
        let mutated = source.replacen(
            anchor.pattern,
            "crate::removed_modules_gen::wire_domains(&deps, domain_modules)",
            1,
        );
        let bait = format!(
            "#[cfg(test)] impl InfraBuilt<'_> {{ async fn wire_domains(self) {{ let _ = {} ; }} }}\n",
            anchor.pattern
        );
        write(&path, &(bait + &mutated))?;
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
        let anchor = RUNTIME_ANCHORS
            .iter()
            .find(|anchor| anchor.id == "run.wire.generated-domains")
            .context("generated domains anchor")?;
        let path = root.join(anchor.path);
        let source = fs::read_to_string(&path)?;
        let mutated = source
            .replacen(
                anchor.pattern,
                "crate::removed_modules_gen::wire_domains(&deps, domain_modules)",
                1,
            )
            .replacen(
                "        let result = async move {",
                &format!(
                    "        let result = async move {{\n            // {}\n            let _anchor_bait = {:?};",
                    anchor.pattern, anchor.pattern
                ),
                1,
            );
        write(&path, &mutated)?;
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

    fn listener_plan_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        for path in [
            RUNTIME_PLAN_PATH,
            RUNTIME_PLACEMENT_EXEC_PATH,
            RUNTIME_ROUTES_PATH,
            RUNTIME_PHASE_FINALIZE_PATH,
            RUNTIME_PHASE_PATH,
            RUNTIME_PHASE_PROVIDER_PATH,
            RUNTIME_PHASE_INFRA_PATH,
            RUNTIME_PHASE_DOMAIN_TRANSPORT_PATH,
            RUNTIME_PHASE_DOMAINS_PATH,
            RUNTIME_PHASE_LAUNCH_PATH,
            RUNTIME_LAUNCH_PATH,
            RUNTIME_LIB_PATH,
            RUNTIME_CONFIG_PATH,
            RUNTIME_LISTENERS_PATH,
        ] {
            write(&root.join(path), &fs::read_to_string(workspace.join(path))?)?;
        }
        Ok(root)
    }

    fn runtime_plan_live_closure_fixture(name: &str) -> Result<PathBuf> {
        let root = unique_tmp(name);
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        let mut sources = Vec::new();
        collect_rust_sources(&workspace.join(RUNTIME_SRC_PATH), &mut sources)?;
        for source in sources {
            let relative = source.strip_prefix(workspace)?;
            write(&root.join(relative), &fs::read_to_string(&source)?)?;
        }
        Ok(root)
    }

    #[test]
    fn runtime_plan_live_closure_accepts_workspace() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        assert_eq!(runtime_plan_live_closure_findings(root)?, Vec::new());
        Ok(())
    }

    #[test]
    fn runtime_plan_live_closure_rejects_missing_consumption_and_bait() -> Result<()> {
        for (case, path, from, to, bait) in [
            (
                "projection-summary-bait",
                RUNTIME_PHASE_PROVIDER_PATH,
                "runtime_plan.domain_execution_plan(&placement_execution_plan)",
                "runtime_plan.domain_execution_plan_removed(&placement_execution_plan)",
                "\n// runtime_plan.domain_execution_plan(&placement_execution_plan)\n\
                 const DOMAIN_PLAN_BAIT: &str = \"runtime_plan.domain_execution_plan(&placement_execution_plan)\";\n\
                 #[cfg(test)] fn test_bait(plan: RuntimePlan, placement: PlacementExecutionPlan) { let _ = plan.domain_execution_plan(&placement); }\n\
                 macro_rules! domain_plan_bait { () => { runtime_plan.domain_execution_plan(&placement_execution_plan) } }\n",
            ),
            (
                "validation-comment-bait",
                RUNTIME_PHASE_DOMAINS_PATH,
                "domain_execution_plan.validate(domain_bindings)",
                "domain_execution_plan.validate_removed(domain_bindings)",
                "\n// domain_execution_plan.validate(domain_bindings)\n\
                 const VALIDATE_BAIT: &str = \"domain_execution_plan.validate(domain_bindings)\";\n",
            ),
            (
                "non-consuming-capability",
                RUNTIME_DOMAIN_EXEC_PATH,
                "    pub(crate) fn validate(\n        self,",
                "    pub(crate) fn validate(\n        &self,",
                "",
            ),
            (
                "direct-compose-bypass",
                RUNTIME_PHASE_DOMAINS_PATH,
                "validated_domain_bindings.compose()",
                "bootstrap::compose_bindings(&mut Vec::new())",
                "",
            ),
            (
                "missing-infra-carrier",
                RUNTIME_PHASE_PATH,
                "pub(crate) struct InfraBuilt<'a> {\n    context: DomainPhaseContext<'a>,",
                "pub(crate) struct InfraBuilt<'a> {\n    context: PhaseContext<'a>,",
                "",
            ),
        ] {
            let root =
                runtime_plan_live_closure_fixture(&format!("runtime-plan-live-closure-{case}"))?;
            let target = root.join(path);
            let source = fs::read_to_string(&target)?;
            let mutated = format!("{}{}", source.replacen(from, to, 1), bait);
            anyhow::ensure!(mutated != source, "{case} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                runtime_plan_live_closure_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail the RuntimePlan live closure gate"
            );
        }

        let root = runtime_plan_live_closure_fixture(
            "runtime-plan-live-closure-public-capability-reexport",
        )?;
        let lib_path = root.join(RUNTIME_LIB_PATH);
        let source = fs::read_to_string(&lib_path)?;
        write(
            &lib_path,
            &format!("{source}\npub use crate::plan::DomainExecutionPlan;\n"),
        )?;
        assert!(
            runtime_plan_live_closure_findings(&root)?
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring),
            "public capability re-export must fail the RuntimePlan live closure gate"
        );

        for (case, path, bait, expected_detail) in [
            (
                "dead-compose-helper",
                RUNTIME_DOMAIN_EXEC_PATH,
                "\nfn dead_compose_helper(mut bindings: Vec<DomainBinding>) {\n    let _ = bootstrap::compose_bindings(&mut bindings);\n}\n",
                "bootstrap::compose_bindings function reference/call",
            ),
            (
                "compose-use-rename",
                RUNTIME_DOMAIN_EXEC_PATH,
                "\nuse bootstrap::compose_bindings as hidden_compose;\n",
                "bootstrap::compose_bindings function reference/call",
            ),
            (
                "generated-wire-function-item-alias",
                RUNTIME_PHASE_DOMAINS_PATH,
                "\nfn dead_wire_alias() {\n    let hidden_wire = crate::modules_gen::wire_domains;\n    let _ = hidden_wire;\n}\n",
                "crate::modules_gen::wire_domains function reference/call",
            ),
            (
                "generated-wire-dead-helper",
                RUNTIME_PHASE_DOMAINS_PATH,
                "\nasync fn dead_generated_wire() {\n    let _ = crate::modules_gen::wire_domains(&deps, modules, &placement).await;\n}\n",
                "crate::modules_gen::wire_domains function reference/call",
            ),
            (
                "exclusive-call-macro-bait",
                RUNTIME_PHASE_DOMAINS_PATH,
                "\nmacro_rules! hidden_domain_calls {\n    () => {{ bootstrap::compose_bindings(&mut bindings); crate::modules_gen::wire_domains(&deps, modules, &placement) }};\n}\n",
                "complete production graph",
            ),
        ] {
            let root =
                runtime_plan_live_closure_fixture(&format!("runtime-plan-live-closure-{case}"))?;
            let target = root.join(path);
            let source = fs::read_to_string(&target)?;
            write(&target, &format!("{source}{bait}"))?;
            assert!(
                runtime_plan_live_closure_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring
                        && finding.detail.contains(expected_detail)),
                "{case} must fail the exclusive production-call ownership proof"
            );
        }

        fn replace_nth(source: &str, needle: &str, replacement: &str, nth: usize) -> String {
            let Some((offset, _)) = source.match_indices(needle).nth(nth) else {
                return source.to_owned();
            };
            let mut mutated = source.to_owned();
            mutated.replace_range(offset..offset + needle.len(), replacement);
            mutated
        }

        for (case, needle, replacement, nth) in [
            (
                "generated-failure-must-split",
                "failure.into_parts()",
                "failure.into_parts_removed()",
                0,
            ),
            (
                "validation-failure-must-drain",
                "bootstrap::drain_binding_outputs(&mut bindings)",
                "bootstrap::drain_binding_outputs_removed(&mut bindings)",
                1,
            ),
            (
                "composition-failure-must-record",
                "provider_build.record_domain(bootstrap::drain_binding_outputs(&mut bindings))",
                "provider_build.record_domain_removed(bootstrap::drain_binding_outputs(&mut bindings))",
                2,
            ),
            (
                "composition-failure-must-return-err",
                "return Err(source).context(\"compose generated domains\");",
                "return Ok(source).context(\"compose generated domains\");",
                0,
            ),
        ] {
            let root =
                runtime_plan_live_closure_fixture(&format!("runtime-plan-live-closure-{case}"))?;
            let target = root.join(RUNTIME_PHASE_DOMAINS_PATH);
            let source = fs::read_to_string(&target)?;
            let mutated = replace_nth(&source, needle, replacement, nth);
            anyhow::ensure!(mutated != source, "{case} mutation must be live");
            write(&target, &mutated)?;
            assert!(
                runtime_plan_live_closure_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring
                        && finding.detail.contains("structurally preserve")),
                "{case} must fail the structured rollback proof"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_listener_plan_execution_accepts_workspace() -> Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .context("xtask workspace root")?;
        assert_eq!(listener_plan_execution_findings(root)?, Vec::new());
        Ok(())
    }

    #[test]
    fn runtime_placement_plan_execution_rejects_missing_anchors() -> Result<()> {
        for (case, path, from, to) in [
            (
                "reject-remote-fn",
                RUNTIME_PLACEMENT_EXEC_PATH,
                "fn reject_remote_on_local_listeners(",
                "fn reject_remote_on_local_listeners_removed(",
            ),
            (
                "from-placement-fn",
                RUNTIME_PHASE_DOMAIN_TRANSPORT_PATH,
                "fn from_placement(",
                "fn from_placement_removed(",
            ),
            (
                "placement-execution-plan-call",
                RUNTIME_PHASE_PROVIDER_PATH,
                "runtime_plan.placement_execution_plan(",
                "runtime_plan.placement_execution_plan_removed(",
            ),
            (
                "from-placement-consumer",
                RUNTIME_PHASE_INFRA_PATH,
                "DomainTransportConfig::from_placement(",
                "DomainTransportConfig::from_placement_removed(",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-placement-plan-{case}"))?;
            let source = fs::read_to_string(root.join(path))?;
            let mutated = source.replacen(from, to, 1);
            anyhow::ensure!(mutated != source, "{case} mutation must be live");
            write(&root.join(path), &mutated)?;
            assert!(
                listener_plan_execution_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail placement-plan execution gate"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_listener_plan_execution_rejects_legacy_and_structural_bypasses() -> Result<()> {
        for (case, path, mutation) in [
            (
                "raw-value-assembler",
                RUNTIME_ROUTES_PATH,
                "\npub fn assemble_authed_routers_from_values() {}\n",
            ),
            (
                "manual-health",
                RUNTIME_PHASE_FINALIZE_PATH,
                "\nfn bypass() { health_listener(reporter, metrics_exporter); }\n",
            ),
            (
                "legacy-config-decision",
                RUNTIME_CONFIG_PATH,
                "\nfn health_auth_scheme() {}\n",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-listener-plan-{case}"))?;
            let source = fs::read_to_string(root.join(path))?;
            write(&root.join(path), &(source + mutation))?;
            let findings = listener_plan_execution_findings(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail listener-plan execution gate"
            );
        }

        let root = listener_plan_fixture("runtime-listener-plan-vec-launch")?;
        let source = fs::read_to_string(root.join(RUNTIME_LAUNCH_PATH))?;
        let mutated = source.replacen(
            "\n    listeners: routes::FinalizedListenerSet,",
            "\n    listeners: Vec<routes::AssembledListener>,",
            1,
        );
        anyhow::ensure!(mutated != source, "Vec launch mutation must be live");
        write(&root.join(RUNTIME_LAUNCH_PATH), &mutated)?;
        assert!(
            listener_plan_execution_findings(&root)?
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring),
            "ordinary Vec launch input must fail listener-plan execution gate"
        );

        for (case, path, mutation) in [
            (
                "duplicate-projection",
                RUNTIME_PLAN_PATH,
                "\nfn duplicate_projection(plan: &RuntimePlan) { let _ = plan.listener_execution_plan(); }\n",
            ),
            (
                "alternate-finalizer",
                RUNTIME_ROUTES_PATH,
                "\nfn alternate_finalizer(plan: ListenerExecutionPlan) -> anyhow::Result<FinalizedListenerPlan> { let _ = plan; unreachable!() }\n",
            ),
            (
                "alternate-set-constructor",
                RUNTIME_ROUTES_PATH,
                "\nimpl FinalizedListenerSet { fn alternate_constructor(listeners: Vec<AssembledListener>) -> Self { Self { listeners } } }\n",
            ),
            (
                "set-from-conversion",
                RUNTIME_ROUTES_PATH,
                "\nimpl From<Vec<AssembledListener>> for FinalizedListenerSet { fn from(listeners: Vec<AssembledListener>) -> Self { Self { listeners } } }\n",
            ),
            (
                "duplicate-phase-call",
                RUNTIME_PHASE_FINALIZE_PATH,
                "\nfn duplicate_phase_call() { finalize_listener_plan(); }\n",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-listener-plan-{case}"))?;
            let source = fs::read_to_string(root.join(path))?;
            write(&root.join(path), &(source + mutation))?;
            assert!(
                listener_plan_execution_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail listener-plan execution AST gate"
            );
        }

        for (case, path, from, to) in [
            (
                "misbound-finalizer-input",
                RUNTIME_PHASE_FINALIZE_PATH,
                "metrics: metrics_exporter,",
                "metrics: other_metrics,",
            ),
            (
                "drifted-finalizer-input-type",
                RUNTIME_ROUTES_PATH,
                "pub(crate) metrics: Arc<dyn diport::MetricsExporter>,",
                "pub(crate) metrics: Arc<NoopMetrics>,",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-listener-plan-{case}"))?;
            let source = fs::read_to_string(root.join(path))?;
            let mutated = source.replacen(from, to, 1);
            anyhow::ensure!(mutated != source, "{case} mutation must be live");
            write(&root.join(path), &mutated)?;
            assert!(
                listener_plan_execution_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail the exact named-input gate"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_listener_plan_execution_scans_new_production_modules() -> Result<()> {
        let root = listener_plan_fixture("runtime-listener-plan-new-production-module")?;
        let lib_path = root.join(RUNTIME_LIB_PATH);
        let lib = fs::read_to_string(&lib_path)?;
        write(&lib_path, &(lib + "\nmod listener_plan_bypass;\n"))?;
        write(
            &root.join("assemblies/runtime/src/listener_plan_bypass.rs"),
            "fn duplicate_projection(plan: &RuntimePlan) {\n\
                 let _ = plan.listener_execution_plan();\n\
             }\n",
        )?;

        assert!(
            listener_plan_execution_findings(&root)?
                .iter()
                .any(|finding| finding.rule == Rule::ForbiddenWiring),
            "a newly reachable production module must not bypass listener-plan inventory"
        );
        Ok(())
    }

    #[test]
    fn runtime_listener_plan_execution_locks_capability_visibility() -> Result<()> {
        for (case, path, from, to) in [
            (
                "public-assembled-listener",
                RUNTIME_ROUTES_PATH,
                "pub(crate) struct AssembledListener",
                "pub struct AssembledListener",
            ),
            (
                "public-execution-plan-field",
                RUNTIME_PLAN_PATH,
                "    listeners: Vec<ListenerExecutionSpec>,",
                "    pub listeners: Vec<ListenerExecutionSpec>,",
            ),
            (
                "public-execution-spec-field",
                RUNTIME_PLAN_PATH,
                "    auth_scheme: AuthScheme,",
                "    pub auth_scheme: AuthScheme,",
            ),
            (
                "public-assembled-listener-field",
                RUNTIME_ROUTES_PATH,
                "    routes: httpserve::AuthenticatedRoutes,",
                "    pub routes: httpserve::AuthenticatedRoutes,",
            ),
            (
                "public-finalized-listener-set-field",
                RUNTIME_ROUTES_PATH,
                "    listeners: Vec<AssembledListener>,",
                "    pub listeners: Vec<AssembledListener>,",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-listener-plan-{case}"))?;
            let source = fs::read_to_string(root.join(path))?;
            let mutated = source.replacen(from, to, 1);
            anyhow::ensure!(mutated != source, "{case} mutation must be live");
            write(&root.join(path), &mutated)?;
            assert!(
                listener_plan_execution_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail listener-plan visibility gate"
            );
        }

        for (case, export) in [
            (
                "execution-plan-reexport",
                "pub use crate::plan::ListenerExecutionPlan;",
            ),
            (
                "execution-spec-reexport",
                "pub use crate::plan::ListenerExecutionSpec;",
            ),
            (
                "assembled-listener-reexport",
                "pub use crate::routes::AssembledListener;",
            ),
            (
                "finalized-listener-set-reexport",
                "pub use crate::routes::FinalizedListenerSet;",
            ),
        ] {
            let root = listener_plan_fixture(&format!("runtime-listener-plan-{case}"))?;
            let lib_path = root.join(RUNTIME_LIB_PATH);
            let source = fs::read_to_string(&lib_path)?;
            write(&lib_path, &format!("{source}\n{export}\n"))?;
            assert!(
                listener_plan_execution_findings(&root)?
                    .iter()
                    .any(|finding| finding.rule == Rule::ForbiddenWiring),
                "{case} must fail listener-plan public re-export gate"
            );
        }
        Ok(())
    }

    fn infra_anchor_status(root: &Path, id: &str) -> Result<AnchorStatus> {
        let anchors = wiring_anchors(root)?;
        anchors
            .into_iter()
            .find(|anchor| anchor.id == id)
            .map(|anchor| anchor.status)
            .ok_or_else(|| anyhow::anyhow!("missing anchor {id}"))
    }

    fn build_infra_helper_fixture(body: &str) -> String {
        format!("impl<'a> ProvidersBuilt<'a> {{\n{body}\n}}\n")
    }

    #[test]
    fn runtime_baseline_build_infra_helper_nested_ordered_ok() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-nested-ok")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    Self::phase_a_prove_external_capabilities();
    Self::phase_b_setup_postgres();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a_prove_external_capabilities() {
    Self::record_vault_redis_s3();
}
fn record_vault_redis_s3() {
    vault_config.into_runtime();
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
fn phase_b_setup_postgres() {
    PgRuntimeDeps::connect_serving();
}
"#,
            ),
        )?;
        for id in [
            "run.provider.vault",
            "run.provider.redis",
            "run.provider.s3",
            "run.provider.pg",
        ] {
            assert_eq!(
                infra_anchor_status(&root, id)?,
                AnchorStatus::Ok,
                "{id} must remain ordered through nested helper expansion"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_missing_pattern() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-missing")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    Self::phase_a();
    PgRuntimeDeps::connect_serving();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a() {
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
"#,
            ),
        )?;
        assert_eq!(
            infra_anchor_status(&root, "run.provider.vault")?,
            AnchorStatus::Missing,
            "missing helper pattern must fail closed"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_out_of_order() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-ooo")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    Self::phase_a();
    PgRuntimeDeps::connect_serving();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a() {
    build_redis_runtime_deps(redis_config);
    vault_config.into_runtime();
    build_s3_runtime_deps(s3_general_config);
}
"#,
            ),
        )?;
        assert_eq!(
            infra_anchor_status(&root, "run.provider.redis")?,
            AnchorStatus::OutOfOrder,
            "redis before vault inside helper must be out-of-order"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_cycle_fail_closed() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-cycle")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    Self::phase_a();
    PgRuntimeDeps::connect_serving();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a() {
    Self::phase_b();
    vault_config.into_runtime();
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
fn phase_b() {
    Self::phase_a();
}
"#,
            ),
        )?;
        let status = infra_anchor_status(&root, "run.provider.vault")?;
        assert!(
            matches!(
                status,
                AnchorStatus::ExpansionFailed(ref detail)
                    if detail.contains("helper expansion cycle involving `phase_a`")
            ),
            "Self:: helper cycle must fail closed with PhaseExpandError detail, got {status:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_visitor_cycle_fail_closed() -> Result<()> {
        let source = r#"
impl<'a> ProvidersBuilt<'a> {
    async fn build_infra(self) {
        Self::phase_a();
    }
    fn phase_a() {
        Self::phase_b();
    }
    fn phase_b() {
        Self::phase_a();
    }
}
"#;
        let file = syn::parse_file(source)?;
        let err = match expand_inherent_phase_method(source, &file, "ProvidersBuilt", "build_infra")
        {
            Err(err) => err,
            Ok(_) => anyhow::bail!("expand path must fail closed on cycle"),
        };
        assert!(
            matches!(err, PhaseExpandError::Cycle(_)),
            "expand cycle: {err:?}"
        );
        let mut wiring =
            RunRuntimeConfigWiring::new(syn::Ident::new("context", proc_macro2::Span::call_site()));
        let visit_err = match visit_expanded_phase_method(
            &mut wiring,
            &file,
            "ProvidersBuilt",
            "build_infra",
        ) {
            Err(err) => err,
            Ok(()) => anyhow::bail!("visitor path must fail closed on cycle"),
        };
        assert!(
            matches!(visit_err, PhaseExpandError::Cycle(_)),
            "visitor cycle: {visit_err:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_ignores_bait() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-bait")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    PgRuntimeDeps::connect_serving();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn dead_helper() {
    vault_config.into_runtime();
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
#[cfg(test)]
fn phase_a_prove_external_capabilities() {
    vault_config.into_runtime();
}
fn unused() {
    // vault_config.into_runtime()
    let _ = "vault_config.into_runtime()";
}
"#,
            ),
        )?;
        assert_eq!(
            infra_anchor_status(&root, "run.provider.vault")?,
            AnchorStatus::Missing,
            "dead/cfg(test)/comment/string bait must not satisfy vault anchor"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_comment_string_steal_span_fail_closed() -> Result<()> {
        let source = r#"
impl<'a> ProvidersBuilt<'a> {
    async fn build_infra(self) {
        let _ = "Self::phase_a(";
        // Self::phase_a(
        Self :: phase_a();
    }
    fn phase_a() {
        vault_config.into_runtime();
    }
}
"#;
        let file = syn::parse_file(source)?;
        let err = match expand_inherent_phase_method(source, &file, "ProvidersBuilt", "build_infra")
        {
            Err(err) => err,
            Ok(_) => anyhow::bail!("AST/text dual-path miss must fail closed"),
        };
        assert!(
            matches!(err, PhaseExpandError::MissingCallSpan(_)),
            "expected MissingCallSpan, got {err:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_comment_string_masked_ok() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-mask-ok")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    let _ = "Self::phase_a()";
    // Self::phase_a()
    Self::phase_a();
    Self::phase_b_setup_postgres();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a() {
    vault_config.into_runtime();
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
fn phase_b_setup_postgres() {
    PgRuntimeDeps::connect_serving();
}
"#,
            ),
        )?;
        for id in [
            "run.provider.vault",
            "run.provider.redis",
            "run.provider.s3",
            "run.provider.pg",
        ] {
            assert_eq!(
                infra_anchor_status(&root, id)?,
                AnchorStatus::Ok,
                "{id} must survive comment/string bait when real Self:: call remains"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_renamed_param_anchors_and_visitor() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-renamed-param")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    let config = context.config();
    S3RuntimeConfig::from_snapshot(config);
    let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
    let redis_config = RedisRuntimeConfig::from_snapshot(config)?;
    let s3_general_config = s3_general;
    Self::phase_a(vault_config, redis_config, s3_general_config);
    Self::phase_b_setup_postgres();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a(renamed_vault: VaultRuntimeConfig, renamed_redis: RedisRuntimeConfig, renamed_s3: S3GeneralConfig) {
    renamed_vault.into_runtime();
    build_redis_runtime_deps(renamed_redis);
    build_s3_runtime_deps(renamed_s3);
}
fn phase_b_setup_postgres() {
    PgRuntimeDeps::connect_serving();
}
"#,
            ),
        )?;
        for id in [
            "run.provider.vault",
            "run.provider.redis",
            "run.provider.s3",
            "run.provider.pg",
        ] {
            assert_eq!(
                infra_anchor_status(&root, id)?,
                AnchorStatus::Ok,
                "{id} must match after param→arg rewrite in virtual source"
            );
        }

        let source = fs::read_to_string(root.join(RUNTIME_PHASE_INFRA_PATH))?;
        let file = syn::parse_file(&source)?;
        let expanded =
            expand_inherent_phase_method(&source, &file, "ProvidersBuilt", "build_infra")
                .map_err(|error| anyhow::anyhow!("helper expansion: {error}"))?;
        assert!(
            expanded
                .virtual_source
                .contains("vault_config.into_runtime()"),
            "virtual buffer must rewrite renamed params to call args: {}",
            expanded.virtual_source
        );
        let mut wiring =
            RunRuntimeConfigWiring::new(syn::Ident::new("context", proc_macro2::Span::call_site()));
        visit_expanded_phase_method(&mut wiring, &file, "ProvidersBuilt", "build_infra")
            .map_err(|error| anyhow::anyhow!("visitor expansion: {error}"))?;
        assert_eq!(
            wiring.canonical_vault_into_runtime_calls, 1,
            "visitor remaps must keep renamed helper receiver canonical: {wiring:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_method_call_expanded() -> Result<()> {
        let root = fixture_root("runtime-baseline-build-infra-helper-method-call")?;
        write(
            &root.join(RUNTIME_PHASE_INFRA_PATH),
            &build_infra_helper_fixture(
                r#"
async fn build_infra(self) {
    S3RuntimeConfig::from_snapshot(config);
    VaultRuntimeConfig::from_snapshot(config);
    self.phase_a();
    Self::phase_b_setup_postgres();
    build_service_token_provider();
    crate::provider_output::build_pg_runtime_module(pg_owner, pg_readiness_period);
    if let Some(provider) = runtime_service_token.as_ref() {}
    provider_build.record_domain(domain_transport.module_result());
    let deps = SharedRuntimeDeps {};
}
fn phase_a(&self) {
    vault_config.into_runtime();
    build_redis_runtime_deps(redis_config);
    build_s3_runtime_deps(s3_general_config);
}
fn phase_b_setup_postgres() {
    PgRuntimeDeps::connect_serving();
}
"#,
            ),
        )?;
        for id in [
            "run.provider.vault",
            "run.provider.redis",
            "run.provider.s3",
            "run.provider.pg",
        ] {
            assert_eq!(
                infra_anchor_status(&root, id)?,
                AnchorStatus::Ok,
                "{id} must expand through self.helper method-call form"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_ambiguous_private_method_fail_closed() -> Result<()> {
        let source = r#"
impl<'a> ProvidersBuilt<'a> {
    async fn build_infra(self) {
        Self::phase_a();
    }
    fn phase_a() {
        vault_config.into_runtime();
    }
    fn phase_a() {
        vault_config.into_runtime();
    }
}
"#;
        let file = syn::parse_file(source)?;
        let err = match expand_inherent_phase_method(source, &file, "ProvidersBuilt", "build_infra")
        {
            Err(err) => err,
            Ok(_) => anyhow::bail!("duplicate private helpers must fail closed"),
        };
        assert_eq!(err, PhaseExpandError::AmbiguousImpl);
        Ok(())
    }

    #[test]
    fn runtime_baseline_build_infra_helper_visitor_binding_remap() -> Result<()> {
        let source = r#"
impl<'a> ProvidersBuilt<'a> {
    async fn build_infra(self) {
        let config = context.config();
        let vault_config = VaultRuntimeConfig::from_snapshot(config)?;
        Self::phase_a(vault_config);
    }
    fn phase_a(renamed_vault: VaultRuntimeConfig) {
        let _ = renamed_vault.into_runtime()?;
    }
}
"#;
        let file = syn::parse_file(source)?;
        let expanded = expand_inherent_phase_method(source, &file, "ProvidersBuilt", "build_infra")
            .map_err(|error| anyhow::anyhow!("helper expansion: {error}"))?;
        assert!(
            expanded
                .virtual_source
                .contains("vault_config.into_runtime()"),
            "virtual buffer must rewrite param→arg for anchors: {}",
            expanded.virtual_source
        );
        let mut wiring =
            RunRuntimeConfigWiring::new(syn::Ident::new("context", proc_macro2::Span::call_site()));
        visit_expanded_phase_method(&mut wiring, &file, "ProvidersBuilt", "build_infra")
            .map_err(|error| anyhow::anyhow!("visitor expansion: {error}"))?;
        assert_eq!(
            wiring.canonical_vault_into_runtime_calls, 1,
            "arg→param remap must keep renamed helper receiver canonical: {wiring:?}"
        );

        let mut no_expand =
            RunRuntimeConfigWiring::new(syn::Ident::new("context", proc_macro2::Span::call_site()));
        let build_infra = unique_production_inherent_method(&file, "ProvidersBuilt", "build_infra")
            .ok_or_else(|| anyhow::anyhow!("missing ProvidersBuilt::build_infra"))?;
        no_expand.visit_block(&build_infra.block);
        assert_eq!(
            no_expand.canonical_vault_into_runtime_calls, 0,
            "without expansion, helper body must not count as canonical"
        );
        Ok(())
    }
}
