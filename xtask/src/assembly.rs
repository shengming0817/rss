//! `assembly validate` —— assembly-level DI provider 声明治理。
//!
//! DI-infra port（如 `diport::RevocationStore` / `diport::LockStore` / `diport::CasStore`）不是跨域 wire
//! contract，不放进 `contracts/**/contract.toml`。
//! 但 provider 选择属于组合根部署事实：哪个 assembly 注入哪个 provider、是否持久、是否已 active，必须有机器可读
//! 声明和 verify 门，避免生产在 dev/demo provider 上静默运行。

use anyhow::{Context, Result, bail};
#[cfg(test)]
use assembly_schema::AssemblyManifest;
use assembly_schema::{
    AssemblyDomain, AssemblyProfile, AssemblyTopology, CanonicalAssemblyManifestV2, DiportPort,
    DiportProvider, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFailurePosture, ProviderLifecycle, ProviderScope,
};
use quote::ToTokens as _;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use syn::spanned::Spanned as _;

use crate::assembly_governance::{
    AssemblyGovernanceIr, Core, GovernedAssembly, ProductionAssembly,
};
use crate::contract::GovernedContract;
use crate::contract::governance::ContractGovernanceIr;
use crate::contract::governance::validate_workflow_activations;
use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// `assemblies/*/Cargo.toml` 必须有同目录 `assembly.toml`。
    MissingManifest,
    /// manifest 声明的 active domain 必须是 assembly crate 的直接 normal dependency。
    ActiveDomainDependency,
    /// 未声明 domain 不得进入 assembly normal dependency closure。
    InactiveDomainDependencyClosure,
    /// identityaudit 必须保持 #1797 的独立双域 binary/schema/journey/image/production closure。
    ///
    /// INVARIANT: IDENTITYAUDIT-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::identityaudit_executable_boundary_rejects_lib_only_shape", anti_vacuity = "tests::identityaudit_real_executable_artifact_closure_is_complete" } -- #1797 replaces the demo composition proof with one exact executable package and its closed production transport/artifact closure.
    IdentityAuditBoundary,
    /// settingsonly 必须保持 #1796 的独立 binary/schema/精确 journey/image/default-closure 闭包。
    ///
    /// INVARIANT: SETTINGSONLY-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::settingsonly_production_artifact_gate_rejects_incomplete_case_closure", anti_vacuity = "tests::settingsonly_real_executable_boundary_is_complete" } -- this target-specific gate closes the settingsonly package and four-case production evidence carrier; artifact identity, image target, and ENTRYPOINT remain owned by ASSEMBLY-ARTIFACT-MATRIX-01.
    SettingsOnlyExecutableBoundary,
    /// settingsonly 必须保持 #1836 的唯一 L2 production/durable-isolated 组装闭包。
    ///
    /// INVARIANT: SETTINGSONLY-L2-PRODUCTION-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::settingsonly_l2_production_closure_rejects_synthetic_mutations", anti_vacuity = "tests::settingsonly_l2_production_closure_accepts_real_workspace" } -- exact manifest/provider/artifact/config/subscription/auth-funnel facts and the production startup call chain are verified from parsed source; raw JWT reparsing, aliases, function pointers, comments, test-only bait, dead helpers, fallback factories, and nonactivated subscribers are not evidence.
    SettingsOnlyL2ProductionClosure,
    /// Framework contract declarations must exactly cover active framework-owned contracts.
    FrameworkContractServing,
    /// Workflow activation must exactly join one repository definition and valid lifecycle.
    WorkflowActivation,
    /// Provider-to-probe inventory bindings may only be minted by the generated/private
    /// completion receipt funnels.
    ///
    /// INVARIANT: RUNTIME-INVENTORY-PROVIDER-PROVENANCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_inventory_provider_binding_rejects_handwritten_production_callsite", anti_vacuity = "tests::runtime_inventory_provider_binding_real_completion_funnels_are_exact" } -- provider IDs and probe names remain coupled to the move-only completion receipts; production assembly code cannot handwrite or alias the raw binding constructor.
    RuntimeInventoryProviderProvenance,
    /// Listener observations are minted only at the three production launch roots and directly
    /// consume the successfully bound server handle's `local_addr()`.
    ///
    /// INVARIANT: RUNTIME-INVENTORY-LISTENER-PROVENANCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_inventory_listener_provenance_rejects_detached_or_aliased_construction", anti_vacuity = "tests::runtime_inventory_listener_provenance_real_launch_roots_are_exact" } -- copied addresses, helper aliases, macros, and extra production minting sites cannot masquerade as actual listener publication.
    RuntimeInventoryListenerProvenance,
    /// production `diport::RevocationStore` provider 必须持久。
    RevocationDurability,
    /// production provider 必须 active 且持久；仅 exact active GovernorLimiter 可为进程内临时态。
    ProductionProviderPosture,
    /// active provider 必须由 assembly Cargo.toml `[dependencies]` 声明。
    ActiveProviderDependency,
    /// active provider 必须是 xtask 认识的 provider→port 映射。
    ActiveProviderPort,
    /// 声明的 durability 必须与已知 provider 真身一致。
    ProviderDurabilityMismatch,
    /// active provider 必须启用 provider symbol 所需 feature。
    ActiveProviderFeature,
    /// manifest 声明的 providerCrate 与 xtask provider matrix 锁定的实现 crate 不符。
    ///
    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "check", source = "code" }— provider↔providerCrate 绑定由 xtask provider
    /// matrix 单源锁定；manifest 声明错误 crate 名须被机器拒（Medium，red test 反恒真）。
    ProviderCrateMismatch,
    /// active distributed provider 必须有真实 phase owner 的 consumer 接线证据。
    ///
    /// INVARIANT: ASSEMBLY-DISTRIBUTED-CONSUMER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::active_distributed_provider_reordered_comment_or_test_bait_is_rejected", anti_vacuity = "tests::active_distributed_lock_cas_providers_pass" }— only the ordered `InfraBuilt::wire_domains` producer→consumer dataflow in `src/phase/domains.rs` is production evidence.
    ActiveDistributedProviderConsumer,
    /// production security closeout 必须声明 active critical provider。
    ProductionSecurityCriticalProvider,
    /// production security closeout 必须有本地 JWKS 文件源与 readiness 证据。
    ProductionSecurityJwksCloseout,
    /// production security closeout 必须有 SPIFFE/mTLS 证据且不得保留 service-token 迁移口。
    ProductionSecuritySpiffeCloseout,
    /// production runtime 不得把 egress TLS 降级旋钮读回 serving catalog，且 wiring 须走 private CA。
    ///
    /// INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 / egress-tls { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::production_security_closeout_rejects_egress_tls_downgrade_catalog_regressions", anti_vacuity = "tests::real_runtime_egress_tls_closeout_accepts_workspace" } — #1710 bans `RSS_*_ALLOW_PLAINTEXT` (AMQP/Redis/S3) and `RSS_PG_SSL_MODE` from FIXED_SERVING_KEYS; they must remain in FORBIDDEN_SERVING_KEYS. Ingress `RSS_LISTENER_ALLOW_PLAINTEXT` stays allowed. Private-CA funnels (`connect_with_private_ca` / `PrivateCaS3ClientFactory` / `RedisPrivateCa` / `AmqpPrivateCa` / PG `VerifyFull`+`with_ssl_root_cert`) are required when the corresponding runtime wiring sources exist.
    ProductionSecurityEgressTlsCloseout,
    /// production token profiles must each be built and wired on the `run()`-reachable path.
    ///
    /// INVARIANT: TOKEN-PROFILE-ASSEMBLY-01 { level = "Medium", exec = "check", source = "code" } —
    /// RSS/Federated/Service providers, closed listener bindings, and profile-specific JWKS
    /// resources/probes are structural assembly facts. AST reachability plus mutation fixtures
    /// reject missing and bait-only evidence.
    TokenProfileTrustChain,
    /// Generic/legacy token configuration and the old shared JWKS probe are forbidden.
    TokenProfileLegacySurface,
    /// Access and service key sources must not be assembled by one mixed provider.
    TokenProfileKeyIsolation,
    /// Scheme and provider must not be independently supplied to the verification bridge.
    TokenProfileBinding,
    /// runtime 的 active PDP 必须绑定 exact active persistent replay-store provider。
    PdpReplayStoreCapability,
    /// domain/topology required capability 必须有 active persistent provider 或 exact Cargo dependency 事实。
    ///
    /// INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "check", source = "code" } —
    /// domain→capability 静态表由 xtask 单源锁定；assembly 声明 domain/topology 后，缺失能力、draft
    /// provider、ephemeral critical provider 必须被机器拒。anti-vacuity red/green tests 以
    /// `assembly_capabilities_*` 前缀覆盖。
    RequiredCapability,
}

pub(crate) struct AssemblyValidate;

impl GovernanceCheck for AssemblyValidate {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "assembly validate"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        crate::assembly_governance::validate_source_funnel(&root)?;
        let (count, findings) = validate_root(&root)?;
        Ok((format!("{count} assembly 声明全部通过"), findings))
    }
}

pub(crate) fn validate_root(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let contract_governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    contract_governance.read(|contracts| {
        let (assemblies, mut findings) = discover(root)?;
        findings.extend(validate_workflow_activation_contracts(
            &assemblies,
            contracts,
        ));
        findings.extend(validate_framework_contracts(root, &assemblies, contracts));
        validate_discovered_root(root, assemblies, findings)
    })
}

fn validate_discovered_root(
    root: &Path,
    assemblies: Vec<GovernedAssembly>,
    mut findings: Vec<Finding>,
) -> Result<(usize, Vec<Finding>)> {
    findings.extend(validate_runtime_inventory_provider_provenance(
        root,
        &assemblies,
    )?);
    findings.extend(validate_runtime_inventory_listener_provenance(
        root,
        &assemblies,
    )?);
    let metadata = load_workspace_metadata(root)?;
    for assembly in &assemblies {
        findings.extend(validate_assembly(assembly));
        if let Some(metadata) = &metadata {
            findings.extend(validate_target_domain_closure(root, assembly, metadata)?);
        }
    }
    Ok((assemblies.len(), findings))
}

fn validate_workflow_activation_contracts(
    assemblies: &[GovernedAssembly],
    contracts: &[GovernedContract],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for assembly in assemblies {
        if let Err(error) = validate_workflow_activations(assembly.manifest(), contracts) {
            findings.push(finding(
                Rule::WorkflowActivation,
                assembly.manifest_label(),
                error.to_string(),
            ));
        }
    }
    findings
}

fn validate_runtime_inventory_provider_provenance(
    root: &Path,
    assemblies: &[GovernedAssembly],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for assembly in assemblies {
        let source_root = assembly.dir().join("src");
        // Manifest-only fixtures intentionally validate declarations without forging a runtime
        // carrier. Executable-boundary gates own the absence of a production source tree.
        if !source_root.is_dir() {
            continue;
        }
        let mut sources = Vec::new();
        collect_rust_sources(&source_root, &mut sources)?;
        let mut sanctioned = 0_usize;
        for path in sources {
            if external_module_is_explicit_test_only(&source_root, &path)? {
                continue;
            }
            let source = std::fs::read_to_string(&path)?;
            let file = syn::parse_file(&source)
                .with_context(|| format!("parse runtime inventory source {}", path.display()))?;
            let evidence = production_provider_binding_evidence(&file);
            if evidence.calls == 0
                && evidence.imports == 0
                && evidence.constructor_references == 0
                && evidence.type_aliases == 0
                && evidence.macros == 0
            {
                continue;
            }
            let relative = path
                .strip_prefix(assembly.dir())
                .unwrap_or(path.as_path())
                .to_string_lossy();
            let allowed = match assembly.manifest().name() {
                "runtime" => relative == "src/provider_output.rs",
                "settingsonly" | "identityaudit" => relative == "src/generated/providers_gen.rs",
                _ => false,
            };
            if allowed
                && evidence.imports == 0
                && evidence.type_aliases == 0
                && evidence.macros == 0
                && evidence.calls > 0
                && evidence.constructor_references == evidence.calls
            {
                sanctioned += 1;
            } else {
                findings.push(finding(
                    Rule::RuntimeInventoryProviderProvenance,
                    rel_label(root, &path),
                    format!("ProviderProbeBinding construction/import must stay inside the generated or private consuming completion receipt funnel (calls={}, refs={}, imports={}, aliases={}, macros={})", evidence.calls, evidence.constructor_references, evidence.imports, evidence.type_aliases, evidence.macros),
                ));
            }
        }
        if matches!(
            assembly.manifest().name(),
            "runtime" | "settingsonly" | "identityaudit"
        ) && sanctioned != 1
        {
            findings.push(finding(
                Rule::RuntimeInventoryProviderProvenance,
                assembly.manifest_label(),
                format!(
                    "runtime inventory provider binding requires exactly one sanctioned completion funnel, found {sanctioned}"
                ),
            ));
        }
    }
    Ok(findings)
}

#[derive(Default)]
struct ProviderBindingEvidence {
    calls: usize,
    imports: usize,
    constructor_references: usize,
    type_aliases: usize,
    macros: usize,
}

fn production_provider_binding_evidence(file: &syn::File) -> ProviderBindingEvidence {
    use syn::visit::Visit as _;
    let mut visitor = ProviderBindingVisitor::default();
    visitor.visit_file(file);
    visitor.evidence
}

#[derive(Default)]
struct ProviderBindingVisitor {
    evidence: ProviderBindingEvidence,
}

impl<'ast> syn::visit::Visit<'ast> for ProviderBindingVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_test_or_test_support_cfg(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_test_or_test_support_cfg(&node.attrs) || node.attrs.iter().any(is_test_attribute) {
            return;
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_test_or_test_support_cfg(&node.attrs) || node.attrs.iter().any(is_test_attribute) {
            return;
        }
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if node
            .to_token_stream()
            .to_string()
            .contains("ProviderProbeBinding")
        {
            self.evidence.imports += 1;
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if node
            .ty
            .to_token_stream()
            .to_string()
            .contains("ProviderProbeBinding")
        {
            self.evidence.type_aliases += 1;
        }
        syn::visit::visit_item_type(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.tokens.to_string().contains("ProviderProbeBinding") {
            self.evidence.macros += 1;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let segments = path_segments(&node.path);
        if segments.ends_with(&["ProviderProbeBinding".to_owned(), "new".to_owned()]) {
            self.evidence.constructor_references += 1;
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            let segments = path_segments(&path.path);
            if segments.ends_with(&["ProviderProbeBinding".to_owned(), "new".to_owned()]) {
                self.evidence.calls += 1;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn path_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn validate_runtime_inventory_listener_provenance(
    root: &Path,
    assemblies: &[GovernedAssembly],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for assembly in assemblies {
        let source_root = assembly.dir().join("src");
        if !source_root.is_dir() {
            continue;
        }
        let (allowed_file, expected_calls): (Option<&str>, &[ExpectedListenerObservation]) =
            match assembly.manifest().name() {
                "runtime" => (Some("src/launch.rs"), RUNTIME_LISTENER_OBSERVATIONS),
                "settingsonly" | "identityaudit" => (
                    Some("src/listeners.rs"),
                    match assembly.manifest().name() {
                        "settingsonly" => SETTINGSONLY_LISTENER_OBSERVATIONS,
                        _ => IDENTITYAUDIT_LISTENER_OBSERVATIONS,
                    },
                ),
                _ => (None, &[]),
            };
        let expected_call_count = expected_calls.len();
        let mut valid_calls = 0_usize;
        let mut sources = Vec::new();
        collect_rust_sources(&source_root, &mut sources)?;
        for path in sources {
            if external_module_is_explicit_test_only(&source_root, &path)? {
                continue;
            }
            let source = std::fs::read_to_string(&path)?;
            let file = syn::parse_file(&source)
                .with_context(|| format!("parse listener inventory source {}", path.display()))?;
            let evidence = production_listener_observation_evidence(&file);
            if evidence.is_empty() {
                continue;
            }
            let relative = path
                .strip_prefix(assembly.dir())
                .unwrap_or(path.as_path())
                .to_string_lossy();
            let exact_funnel = allowed_file.is_some_and(|allowed| relative == allowed)
                && evidence.imports == 0
                && evidence.type_aliases == 0
                && evidence.macros == 0
                && evidence.constructor_references == evidence.calls
                && evidence.calls == evidence.direct_local_addr_calls
                && evidence.has_exact_observations(expected_calls);
            if exact_funnel {
                valid_calls += evidence.calls;
            } else {
                findings.push(finding(
                    Rule::RuntimeInventoryListenerProvenance,
                    rel_label(root, &path),
                    format!("BoundListenerObservation must be constructed only at the exact launch root with local_addr() passed directly from the bound handle (calls={}, direct={}, refs={}, imports={}, aliases={}, macros={})", evidence.calls, evidence.direct_local_addr_calls, evidence.constructor_references, evidence.imports, evidence.type_aliases, evidence.macros),
                ));
            }
        }
        if allowed_file.is_some() && valid_calls != expected_call_count {
            findings.push(finding(
                Rule::RuntimeInventoryListenerProvenance,
                assembly.manifest_label(),
                format!(
                    "runtime listener inventory requires {expected_call_count} exact id/kind/auth/bound observation constructors, found {valid_calls}"
                ),
            ));
        }
    }
    Ok(findings)
}

#[derive(Clone, Copy)]
struct ExpectedListenerObservation {
    id: &'static str,
    kind: &'static str,
    auth: &'static str,
    receiver: &'static str,
}

const RUNTIME_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] =
    &[ExpectedListenerObservation {
        id: "self.id.clone()",
        kind: "kind",
        auth: "auth",
        receiver: "self.bound",
    }];
const SETTINGSONLY_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] = &[
    ExpectedListenerObservation {
        id: "\"primary-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Primary",
        auth: "assembly_schema::ListenerAuth::FederatedAccessToken",
        receiver: "prepared.primary_front.as_ref().map_or(&prepared.primary.bound,|front|&front.bound)",
    },
    ExpectedListenerObservation {
        id: "\"admin-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Admin",
        auth: "assembly_schema::ListenerAuth::FederatedAccessToken",
        receiver: "prepared.admin_front.as_ref().map_or(&prepared.admin.bound,|front|&front.bound)",
    },
    ExpectedListenerObservation {
        id: "\"health-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Health",
        auth: "assembly_schema::ListenerAuth::NoAuth",
        receiver: "prepared.health_front.as_ref().map_or(&prepared.health.bound,|front|&front.bound)",
    },
];
const IDENTITYAUDIT_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] = &[
    ExpectedListenerObservation {
        id: "\"primary-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Primary",
        auth: "assembly_schema::ListenerAuth::RssAccessToken",
        receiver: "prepared.primary_front.as_ref().map_or(&prepared.primary.bound,|front|&front.bound)",
    },
    ExpectedListenerObservation {
        id: "\"admin-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Admin",
        auth: "assembly_schema::ListenerAuth::RssAccessToken",
        receiver: "prepared.admin_front.as_ref().map_or(&prepared.admin.bound,|front|&front.bound)",
    },
    ExpectedListenerObservation {
        id: "\"health-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Health",
        auth: "assembly_schema::ListenerAuth::NoAuth",
        receiver: "prepared.health_front.as_ref().map_or(&prepared.health.bound,|front|&front.bound)",
    },
];

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ListenerObservationCall {
    id: String,
    kind: String,
    auth: String,
    receiver: String,
}

#[derive(Default)]
struct ListenerObservationEvidence {
    calls: usize,
    direct_local_addr_calls: usize,
    constructor_references: usize,
    imports: usize,
    type_aliases: usize,
    macros: usize,
    direct_observations: Vec<ListenerObservationCall>,
}

impl ListenerObservationEvidence {
    fn is_empty(&self) -> bool {
        self.calls == 0
            && self.constructor_references == 0
            && self.imports == 0
            && self.type_aliases == 0
            && self.macros == 0
    }

    fn has_exact_observations(&self, expected: &[ExpectedListenerObservation]) -> bool {
        let mut actual = self.direct_observations.clone();
        actual.sort();
        let mut expected = expected
            .iter()
            .map(|call| ListenerObservationCall {
                id: call.id.to_owned(),
                kind: call.kind.to_owned(),
                auth: call.auth.to_owned(),
                receiver: call.receiver.to_owned(),
            })
            .collect::<Vec<_>>();
        expected.sort();
        actual == expected
    }
}

fn production_listener_observation_evidence(file: &syn::File) -> ListenerObservationEvidence {
    use syn::visit::Visit as _;
    let mut visitor = ListenerObservationVisitor::default();
    visitor.visit_file(file);
    visitor.evidence
}

#[derive(Default)]
struct ListenerObservationVisitor {
    evidence: ListenerObservationEvidence,
}

impl<'ast> syn::visit::Visit<'ast> for ListenerObservationVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_test_or_test_support_cfg(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_test_or_test_support_cfg(&node.attrs) || node.attrs.iter().any(is_test_attribute) {
            return;
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_test_or_test_support_cfg(&node.attrs) || node.attrs.iter().any(is_test_attribute) {
            return;
        }
        syn::visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if node
            .to_token_stream()
            .to_string()
            .contains("BoundListenerObservation")
        {
            self.evidence.imports += 1;
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if node
            .ty
            .to_token_stream()
            .to_string()
            .contains("BoundListenerObservation")
        {
            self.evidence.type_aliases += 1;
        }
        syn::visit::visit_item_type(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.tokens.to_string().contains("BoundListenerObservation") {
            self.evidence.macros += 1;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        let segments = path_segments(&node.path);
        if segments.ends_with(&[
            "BoundListenerObservation".to_owned(),
            "from_bound".to_owned(),
        ]) {
            self.evidence.constructor_references += 1;
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            let segments = path_segments(&path.path);
            if segments.ends_with(&[
                "BoundListenerObservation".to_owned(),
                "from_bound".to_owned(),
            ]) {
                self.evidence.calls += 1;
                if node.args.iter().nth(4).is_some_and(|argument| {
                    matches!(argument, syn::Expr::MethodCall(call) if call.method == "local_addr" && call.args.is_empty())
                }) {
                    self.evidence.direct_local_addr_calls += 1;
                    if let Some(syn::Expr::MethodCall(call)) = node.args.iter().nth(4) {
                        self.evidence.direct_observations.push(ListenerObservationCall {
                            id: token_key(&node.args[0]),
                            kind: token_key(&node.args[1]),
                            auth: token_key(&node.args[2]),
                            receiver: token_key(call.receiver.as_ref()),
                        });
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn token_key(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

/// Target-specific artifact semantics shared with `assembly artifacts check`.
/// The matrix owns inventory identity; these existing rules remain the single source for the
/// settingsonly/identityaudit behavior witnesses.
pub(crate) fn artifact_boundary_findings(root: &Path) -> Result<Vec<Finding>> {
    let (assemblies, mut findings) = discover(root)?;
    let metadata = load_workspace_metadata(root)?;
    for assembly in assemblies
        .iter()
        .filter(|assembly| matches!(assembly.manifest().name(), "identityaudit" | "settingsonly"))
    {
        if let Some(metadata) = &metadata {
            findings.extend(validate_target_domain_closure(root, assembly, metadata)?);
        }
    }
    Ok(findings
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.rule,
                Rule::IdentityAuditBoundary
                    | Rule::SettingsOnlyExecutableBoundary
                    | Rule::SettingsOnlyL2ProductionClosure
            )
        })
        .collect())
}

fn validate_framework_contracts(
    root: &Path,
    assemblies: &[GovernedAssembly],
    contracts: &[GovernedContract],
) -> Vec<Finding> {
    use crate::contract::manifest::Lifecycle;

    let by_id = contracts
        .iter()
        .map(|contract| (contract.manifest().id.as_str(), contract))
        .collect::<BTreeMap<_, _>>();
    let mut declarations: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut findings = Vec::new();
    for assembly in assemblies {
        for mount in assembly.manifest().framework_contracts() {
            let contract_id = &mount.id;
            declarations
                .entry(contract_id)
                .or_default()
                .push(assembly.manifest_label());
            match by_id.get(contract_id.as_str()) {
                Some(contract)
                    if contract.manifest().lifecycle == Lifecycle::Active
                        && contract.owner().is_framework_owned() => {}
                Some(_) => findings.push(finding(
                    Rule::FrameworkContractServing,
                    assembly.manifest_label(),
                    format!(
                        "frameworkContracts entry `{contract_id}` must reference an active framework-owned contract"
                    ),
                )),
                None => findings.push(finding(
                    Rule::FrameworkContractServing,
                    assembly.manifest_label(),
                    format!("frameworkContracts entry `{contract_id}` is unknown"),
                )),
            }
        }
    }
    for contract in contracts.iter().filter(|contract| {
        contract.manifest().lifecycle == Lifecycle::Active && contract.owner().is_framework_owned()
    }) {
        match declarations
            .get(contract.manifest().id.as_str())
            .map(Vec::as_slice)
        {
            None | Some([]) => findings.push(finding(
                Rule::FrameworkContractServing,
                rel_label(root, contract.manifest_path()),
                format!(
                    "active framework contract `{}` must be declared by at least one assembly",
                    contract.manifest().id
                ),
            )),
            Some(_) => {}
        }
    }
    findings
}

/// 对单个目标执行与 aggregate gate 相同的完整验证，不读取其它 assembly。
#[cfg(test)]
pub(crate) fn validate_target(root: &Path, name: &str) -> Result<Vec<Finding>> {
    let ir = AssemblyGovernanceIr::<Core>::load_target(root, name)?
        .with_context(|| format!("assembly `{name}` 不存在"))?;
    let assembly = ir
        .assembly(name)
        .with_context(|| format!("assembly `{name}` 不存在"))?;
    validate_governed_target(root, assembly)
}

/// Validate an assembly already selected by the governance owner.
///
/// Callers that already hold a Core IR must use this entry point so target-scoped
/// operations do not rediscover the repository or rerun the global production ratchet.
pub(crate) fn validate_governed_target(
    root: &Path,
    assembly: &GovernedAssembly,
) -> Result<Vec<Finding>> {
    let mut findings = validate_assembly(assembly);
    if let Some(metadata) = load_workspace_metadata(root)? {
        findings.extend(validate_target_domain_closure(root, assembly, &metadata)?);
    }
    Ok(findings)
}

fn validate_target_domain_closure(
    root: &Path,
    assembly: &GovernedAssembly,
    metadata: &CargoMetadata,
) -> Result<Vec<Finding>> {
    // INVARIANT: ASSEMBLY-DOMAIN-CLOSURE-01 { level = "Medium", exec = "check", source = "code" } —
    // 每个 assembly.toml 的 active domain 必须是目标 assembly package 当前 target 图中同名、未 rename、
    // 指向同名 workspace domain crate 的直接 normal dependency；inactive domain 不得进入该目标 package 的
    // normal dependency closure。真实 Cargo fixture 覆盖 alias、target cfg、dev/build、optional、
    // direct/transitive red case。
    let package = package_by_manifest(metadata, assembly.cargo_path()).with_context(|| {
        format!(
            "{} 未出现在 cargo metadata packages 中；manifest_path={}",
            assembly.cargo_label(),
            assembly.cargo_path().display()
        )
    })?;
    let declared_direct_domains = direct_normal_domain_deps(root, metadata, package)?;
    let target_direct_domains = cargo_tree_domains(root, assembly, metadata, Some(1))?;
    let direct_domains = declared_direct_domains
        .intersection(&target_direct_domains)
        .cloned()
        .collect();
    let closure_domains = cargo_tree_domains(root, assembly, metadata, None)?;
    let mut findings = validate_domain_sets(assembly, direct_domains, closure_domains)?;
    if assembly.manifest().name() == "identityaudit" {
        let (closure_packages, test_support_enabled) =
            cargo_tree_default_normal_evidence(root, assembly, metadata)?;
        findings.extend(validate_identityaudit_boundary(
            assembly.manifest_label(),
            assembly.cargo_label(),
            &package.targets,
            &closure_packages,
        ));
        let schema_is_closed =
            identityaudit_schema_is_closed(&assembly.dir().join("config.schema.json"))?;
        let sample_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir().join("identityaudit.example.toml"))?;
        let artifact_acceptance = identityaudit_artifact_acceptance_evidence(root)?;
        let (journey_target_declared, required_journey_test_declared) =
            identityaudit_journey_evidence(root)?;
        let dockerfile = std::fs::read_to_string(root.join("Dockerfile"))
            .context("读取 identityaudit image source Dockerfile 失败")?;
        let runtimeexec_launch_is_live = subset_runtimeexec_launch_is_live(root, "identityaudit")?;
        findings.extend(validate_identityaudit_executable_evidence(
            IdentityAuditExecutableEvidence {
                test_support_enabled,
                schema_is_closed,
                sample_is_regular_file,
                artifact_acceptance,
                journey_target_declared,
                required_journey_test_declared,
                runtimeexec_launch_is_live,
                dockerfile: &dockerfile,
            },
        ));
    }
    if assembly.manifest().name() == "settingsonly" {
        let (closure_packages, test_support_enabled) =
            cargo_tree_default_normal_evidence(root, assembly, metadata)?;
        let schema_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir().join("config.schema.json"))?;
        let sample_is_regular_file =
            is_regular_file_without_symlink(&assembly.dir().join("settingsonly.example.toml"))?;
        let (production_artifact_target_declared, production_artifact) =
            settingsonly_production_artifact_evidence(root)?;
        let (journey_target_declared, required_journey_test_declared) =
            settingsonly_journey_evidence(root)?;
        let runtimeexec_launch_is_live = subset_runtimeexec_launch_is_live(root, "settingsonly")?;
        let dockerignore_contracts_included = dockerignore_includes_contracts(root)?;
        findings.extend(validate_settingsonly_executable_evidence(
            SettingsOnlyExecutableEvidence {
                targets: &package.targets,
                closure_packages: &closure_packages,
                test_support_enabled,
                schema_is_regular_file,
                sample_is_regular_file,
                production_artifact_target_declared,
                production_artifact,
                journey_target_declared,
                required_journey_test_declared,
                runtimeexec_launch_is_live,
                dockerignore_contracts_included,
            },
        ));
        findings.extend(validate_settingsonly_l2_production_closure(
            root,
            assembly,
            &closure_packages,
        )?);
    }
    Ok(findings)
}

#[derive(Clone)]
struct SettingsOnlyL2Evidence {
    manifest: CanonicalAssemblyManifestV2,
    cargo_toml: toml::Value,
    closure_packages: BTreeSet<String>,
    providers_gen: String,
    modules_gen: String,
    lock: serde_json::Value,
    runtime_plan: serde_json::Value,
    config_schema: serde_json::Value,
    config_sample: toml::Value,
    lib_rs: String,
    runtime_rs: String,
    eventing_rs: String,
    bridge_rs: String,
    auth_bridge_rs: String,
    providers_rs: String,
    config_rs: String,
    dlx_rs: String,
}

fn load_settingsonly_l2_evidence(
    root: &Path,
    assembly: &GovernedAssembly,
    closure_packages: &BTreeSet<String>,
) -> Result<SettingsOnlyL2Evidence> {
    let read = |path: &Path| -> Result<String> {
        std::fs::read_to_string(path)
            .with_context(|| format!("read settingsonly L2 evidence {}", path.display()))
    };
    let read_json = |path: &Path| -> Result<serde_json::Value> {
        serde_json::from_str(&read(path)?)
            .with_context(|| format!("parse settingsonly L2 evidence {}", path.display()))
    };
    Ok(SettingsOnlyL2Evidence {
        manifest: assembly.manifest().clone(),
        cargo_toml: assembly.cargo_toml().clone(),
        closure_packages: closure_packages.clone(),
        providers_gen: read(&assembly.dir().join("src/generated/providers_gen.rs"))?,
        modules_gen: read(&assembly.dir().join("src/generated/modules_gen.rs"))?,
        lock: read_json(&assembly.dir().join("assembly.lock.json"))?,
        runtime_plan: read_json(&assembly.dir().join("runtime-plan.json"))?,
        config_schema: read_json(&assembly.dir().join("config.schema.json"))?,
        config_sample: toml::from_str(&read(&assembly.dir().join("settingsonly.example.toml"))?)
            .context("parse settingsonly v2 sample")?,
        lib_rs: read(&assembly.dir().join("src/lib.rs"))?,
        runtime_rs: read(&assembly.dir().join("src/runtime.rs"))?,
        eventing_rs: read(&assembly.dir().join("src/eventing.rs"))?,
        bridge_rs: read(&root.join("composition/eventing/src/lib.rs"))?,
        auth_bridge_rs: read(&assembly.dir().join("src/auth_bridge.rs"))?,
        providers_rs: read(&assembly.dir().join("src/providers.rs"))?,
        config_rs: read(&assembly.dir().join("src/config.rs"))?,
        dlx_rs: read(&assembly.dir().join("src/dlx.rs"))?,
    })
}

fn validate_settingsonly_l2_production_closure(
    root: &Path,
    assembly: &GovernedAssembly,
    closure_packages: &BTreeSet<String>,
) -> Result<Vec<Finding>> {
    let evidence = load_settingsonly_l2_evidence(root, assembly, closure_packages)?;
    Ok(validate_settingsonly_l2_evidence(&evidence))
}

fn l2_finding(field: &str, message: impl Into<String>) -> Finding {
    finding(
        Rule::SettingsOnlyL2ProductionClosure,
        "assemblies/settingsonly",
        format!("field={field} {}", message.into()),
    )
}

fn production_item_tokens(source: &str, name: &str) -> Option<String> {
    let file = syn::parse_file(source).ok()?;
    let mut matches = Vec::new();
    for item in file.items {
        match item {
            syn::Item::Fn(item)
                if item.sig.ident == name && !has_test_or_test_support_cfg(&item.attrs) =>
            {
                matches.push(item.to_token_stream().to_string());
            }
            syn::Item::Impl(item) if !has_test_or_test_support_cfg(&item.attrs) => {
                for impl_item in item.items {
                    if let syn::ImplItem::Fn(method) = impl_item
                        && method.sig.ident == name
                        && !has_test_or_test_support_cfg(&method.attrs)
                    {
                        matches.push(method.to_token_stream().to_string());
                    }
                }
            }
            syn::Item::Const(item)
                if item.ident == name && !has_test_or_test_support_cfg(&item.attrs) =>
            {
                matches.push(item.to_token_stream().to_string());
            }
            _ => {}
        }
    }
    (matches.len() == 1).then(|| {
        strip_string_literals(&matches.remove(0))
            .split_whitespace()
            .collect()
    })
}

fn strip_string_literals(tokens: &str) -> String {
    let mut output = String::with_capacity(tokens.len());
    let mut chars = tokens.chars();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            output.push(ch);
            continue;
        }
        output.push('"');
        let mut escaped = false;
        for literal in chars.by_ref() {
            if escaped {
                escaped = false;
            } else if literal == '\\' {
                escaped = true;
            } else if literal == '"' {
                output.push('"');
                break;
            }
        }
    }
    output
}

fn tokens_have_all(source: &str, item: &str, required: &[&str]) -> bool {
    production_item_tokens(source, item)
        .is_some_and(|tokens| required.iter().all(|needle| tokens.contains(needle)))
}

fn function_local_initializer_has_all(
    source: &str,
    function: &str,
    binding: &str,
    required: &[&str],
) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let mut initializers = file.items.into_iter().filter_map(|item| {
        let syn::Item::Fn(item) = item else {
            return None;
        };
        if item.sig.ident != function || has_test_or_test_support_cfg(&item.attrs) {
            return None;
        }
        let matches = item
            .block
            .stmts
            .iter()
            .filter_map(|statement| {
                let syn::Stmt::Local(local) = statement else {
                    return None;
                };
                (local_binding_ident(&local.pat)? == binding)
                    .then_some(local.init.as_ref())
                    .flatten()
                    .map(|init| {
                        strip_string_literals(&init.expr.to_token_stream().to_string())
                            .split_whitespace()
                            .collect::<String>()
                    })
            })
            .collect::<Vec<_>>();
        (matches.len() == 1)
            .then(|| matches.into_iter().next())
            .flatten()
    });
    let Some(tokens) = initializers.next() else {
        return false;
    };
    initializers.next().is_none() && required.iter().all(|needle| tokens.contains(needle))
}

fn impl_method_has_all(source: &str, type_name: &str, method: &str, required: &[&str]) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let mut matches = file.items.into_iter().filter_map(|item| {
        let syn::Item::Impl(item) = item else {
            return None;
        };
        let syn::Type::Path(path) = item.self_ty.as_ref() else {
            return None;
        };
        if path.path.segments.last()?.ident != type_name
            || has_test_or_test_support_cfg(&item.attrs)
        {
            return None;
        }
        item.items.into_iter().find_map(|item| match item {
            syn::ImplItem::Fn(item)
                if item.sig.ident == method && !has_test_or_test_support_cfg(&item.attrs) =>
            {
                Some(
                    strip_string_literals(&item.to_token_stream().to_string())
                        .split_whitespace()
                        .collect::<String>(),
                )
            }
            _ => None,
        })
    });
    let Some(tokens) = matches.next() else {
        return false;
    };
    matches.next().is_none() && required.iter().all(|needle| tokens.contains(needle))
}

fn exact_non_optional_struct_fields(source: &str, name: &str, fields: &[&str]) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let Some(item) = file.items.into_iter().find_map(|item| match item {
        syn::Item::Struct(item)
            if item.ident == name && !has_test_or_test_support_cfg(&item.attrs) =>
        {
            Some(item)
        }
        _ => None,
    }) else {
        return false;
    };
    let syn::Fields::Named(named) = item.fields else {
        return false;
    };
    let actual = named
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect::<BTreeSet<_>>();
    let expected = fields
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<BTreeSet<_>>();
    actual == expected
        && named.named.iter().all(|field| {
            !matches!(&field.ty, syn::Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"))
        })
}

fn schema_objects_are_closed_and_required(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            let own_shape_ok = object.get("properties").is_none_or(|properties| {
                let Some(properties) = properties.as_object() else {
                    return false;
                };
                let property_names = properties
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let required = object
                    .get("required")
                    .and_then(serde_json::Value::as_array)
                    .map(|fields| {
                        fields
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<BTreeSet<_>>()
                    });
                object
                    .get("additionalProperties")
                    .and_then(serde_json::Value::as_bool)
                    == Some(false)
                    && required.as_ref() == Some(&property_names)
            });
            own_shape_ok && object.values().all(schema_objects_are_closed_and_required)
        }
        serde_json::Value::Array(values) => {
            values.iter().all(schema_objects_are_closed_and_required)
        }
        _ => true,
    }
}

fn production_items_forbid_identifier(source: &str, forbidden: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    file.items
        .into_iter()
        .filter(|item| !item_attrs(item).is_some_and(has_test_or_test_support_cfg))
        .all(|item| {
            !item
                .to_token_stream()
                .to_string()
                .to_ascii_lowercase()
                .contains(forbidden)
        })
}

#[derive(Default)]
struct SettingsOnlyAuthBridgeVisitor {
    wrapper_count: usize,
    exact_wrapper_count: usize,
    raw_reparse_found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for SettingsOnlyAuthBridgeVisitor {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.sig.ident == "federated_evidence" {
            self.wrapper_count += 1;
            let signature_is_exact = matches!(item.vis, syn::Visibility::Inherited)
                && !has_test_or_test_support_cfg(&item.attrs)
                && token_key(&item.sig.inputs) == "access:&authn::VerifiedFederatedAccess"
                && token_key(&item.sig.output) == "->Authenticated";
            let body = token_key(&item.block);
            if signature_is_exact
                && body.contains("access.principal()")
                && body.contains("access.permissions()")
                && body.contains("Authenticated::new_federated(")
            {
                self.exact_wrapper_count += 1;
            }
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let path = token_key(expression);
        if path.ends_with("Jwt::parse") || path.ends_with("VerifiedJwt::raw") {
            self.raw_reparse_found = true;
        }
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "raw" || expression.method == "verified_jwt" {
            self.raw_reparse_found = true;
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn settingsonly_auth_bridge_is_closed(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let mut visitor = SettingsOnlyAuthBridgeVisitor::default();
    syn::visit::Visit::visit_file(&mut visitor, &file);
    let request_wrapper = production_item_tokens(source, "verify_request");
    visitor.wrapper_count == 1
        && visitor.exact_wrapper_count == 1
        && !visitor.raw_reparse_found
        && request_wrapper.is_some_and(|tokens| {
            [
                "letaccess=Arc::new(access)",
                "letprincipal=access.principal_arc()",
                "letevidence=federated_evidence(access.as_ref())",
                "PendingScopeCtx::new(ctx)",
                "extensions_mut().insert(evidence)",
                "extensions_mut().insert(principal)",
            ]
            .iter()
            .all(|required| tokens.contains(required))
                && !tokens.contains("extensions_mut().insert(access)")
        })
}

fn item_attrs(item: &syn::Item) -> Option<&[syn::Attribute]> {
    match item {
        syn::Item::Const(item) => Some(&item.attrs),
        syn::Item::Enum(item) => Some(&item.attrs),
        syn::Item::Fn(item) => Some(&item.attrs),
        syn::Item::Impl(item) => Some(&item.attrs),
        syn::Item::Mod(item) => Some(&item.attrs),
        syn::Item::Static(item) => Some(&item.attrs),
        syn::Item::Struct(item) => Some(&item.attrs),
        syn::Item::Trait(item) => Some(&item.attrs),
        syn::Item::Type(item) => Some(&item.attrs),
        syn::Item::Union(item) => Some(&item.attrs),
        _ => None,
    }
}

fn upper_camel_kebab(value: &str) -> String {
    value
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

fn validate_settingsonly_l2_evidence(evidence: &SettingsOnlyL2Evidence) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !settingsonly_auth_bridge_is_closed(&evidence.auth_bridge_rs) {
        findings.push(l2_finding(
            "federated-auth-funnel",
            "requires one private VerifiedFederatedAccess-consuming wrapper and only its minimal evidence/principal/tenant projections; full access extension insertion, raw JWT parse/reparse, aliases, function pointers, and cfg(test) bait are forbidden",
        ));
    }
    if evidence.manifest.profile() != AssemblyProfile::Production
        || evidence.manifest.topology() != AssemblyTopology::DurableIsolated
        || evidence.manifest.domains() != [AssemblyDomain::Settings]
    {
        findings.push(l2_finding(
            "manifest",
            "requires exact production/durable-isolated/settings topology; demo is forbidden",
        ));
    }

    let actual_provider_facts = evidence
        .manifest
        .diport_providers()
        .iter()
        .map(|provider| {
            let mut outputs = provider
                .outputs
                .iter()
                .map(|output| output.as_str())
                .collect::<Vec<_>>();
            outputs.sort_unstable();
            (provider.id.as_str(), provider.durability.as_str(), outputs)
        })
        .collect::<BTreeSet<_>>();
    if evidence.manifest.diport_providers().len() != actual_provider_facts.len()
        || evidence
            .manifest
            .diport_providers()
            .iter()
            .any(|provider| provider.lifecycle != ProviderLifecycle::Active)
    {
        findings.push(l2_finding(
            "providers",
            "settingsonly manifest provider facts must be unique and active; duplicate or draft providers are forbidden",
        ));
    }

    let expected_closure = SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES
        .iter()
        .copied()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let provider_features_ok = [
        ("amqp", &["backend"][..]),
        ("oidc", &["backend"][..]),
        ("postgres", &["auth-audit-sink", "domain-settings"][..]),
        ("redis", &["backend"][..]),
        ("s3", &["backend"][..]),
        ("vault", &["backend"][..]),
        ("eventing-composition", &["settings-consumers"][..]),
    ]
    .iter()
    .all(|(name, required)| {
        dependency_features(&evidence.cargo_toml, name)
            .is_some_and(|features| required.iter().all(|feature| features.contains(*feature)))
    });
    if evidence.closure_packages != expected_closure || !provider_features_ok {
        findings.push(l2_finding("cargo-closure", "normal workspace closure and production backend features must be exact; fallback factories/test-support are forbidden"));
    }

    let provider_catalog = production_item_tokens(&evidence.providers_gen, "PROVIDER_CATALOG");
    let generated_roles_ok = provider_catalog.as_ref().is_some_and(|tokens| {
        actual_provider_facts
            .iter()
            .all(|(id, durability, outputs)| {
                let role = format!("ProviderRole::{}", upper_camel_kebab(id));
                let Some(start) = tokens.find(&role) else {
                    return false;
                };
                if tokens.matches(&role).count() != 1 {
                    return false;
                }
                let tail = &tokens[start..];
                let end = tail
                    .find("),ProviderCatalogEntry::checked")
                    .unwrap_or(tail.len());
                let entry = &tail[..end];
                let durability = format!("ProviderDurability::{}", upper_camel_kebab(durability));
                let outputs = outputs
                    .iter()
                    .map(|output| format!("LifecycleChannel::{}", upper_camel_kebab(output)))
                    .collect::<Vec<_>>();
                entry.contains(&durability)
                    && entry.matches("LifecycleChannel::").count() == outputs.len()
                    && outputs.iter().all(|output| entry.contains(output))
            })
            && tokens.matches("ProviderCatalogEntry::checked").count()
                == actual_provider_facts.len()
    });
    let generated_modules_ok = production_item_tokens(&evidence.modules_gen, "wire_domains")
        .is_some_and(|tokens| {
            tokens.matches("::module(").count() == 1
                && tokens.contains("crate::domains::settings::module(")
                && tokens.contains(".await")
        });
    if !generated_roles_ok || !generated_modules_ok {
        findings.push(l2_finding("generated", "generated provider catalog/modules must contain the exact production execution body; dead or cfg(test) helpers are not evidence"));
    }

    let lock_ok = evidence
        .lock
        .pointer("/identity/name")
        .and_then(serde_json::Value::as_str)
        == Some("settingsonly")
        && evidence
            .lock
            .pointer("/identity/profile")
            .and_then(serde_json::Value::as_str)
            == Some("production")
        && evidence.lock.pointer("/fingerprint")
            == evidence.runtime_plan.pointer("/assemblyFingerprint")
        && evidence
            .lock
            .pointer("/digests/manifest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|digest| {
                evidence
                    .providers_gen
                    .contains(&format!("Source-Manifest-Digest: {digest}"))
                    && evidence
                        .modules_gen
                        .contains(&format!("Source-Manifest-Digest: {digest}"))
            });
    let plan_facts = evidence
        .runtime_plan
        .pointer("/providerPlans")
        .and_then(serde_json::Value::as_array)
        .map(|plans| {
            plans
                .iter()
                .filter_map(|plan| {
                    let id = plan.get("id")?.as_str()?;
                    let mut outputs = plan
                        .get("outputs")?
                        .as_array()?
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .collect::<Vec<_>>();
                    outputs.sort_unstable();
                    Some((id, outputs))
                })
                .collect::<BTreeSet<_>>()
        });
    let plan_count = evidence
        .runtime_plan
        .pointer("/providerPlans")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len);
    let expected_plan = actual_provider_facts
        .iter()
        .map(|(id, _, outputs)| (*id, outputs.clone()))
        .collect::<BTreeSet<_>>();
    if !lock_ok
        || plan_facts.as_ref() != Some(&expected_plan)
        || plan_count != Some(expected_plan.len())
    {
        findings.push(l2_finding(
            "lock-runtime-plan",
            "committed lock and runtime plan must bind the exact manifest provider closure",
        ));
    }

    let expected_config_fields = [
        "dlx",
        "drain",
        "eventing",
        "federated",
        "listeners",
        "postgres",
        "profile",
        "readiness",
        "redis",
        "s3",
        "schemaVersion",
        "tenantAuthority",
        "topology",
        "vault",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let schema_required = evidence
        .config_schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<BTreeSet<_>>()
        });
    let schema_ok = schema_required.as_ref() == Some(&expected_config_fields)
        && evidence
            .config_schema
            .pointer("/properties/schemaVersion/const")
            .and_then(serde_json::Value::as_u64)
            == Some(2)
        && evidence
            .config_schema
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && schema_objects_are_closed_and_required(&evidence.config_schema);
    let sample_fields = evidence
        .config_sample
        .as_table()
        .map(|table| table.keys().map(String::as_str).collect::<BTreeSet<_>>());
    let sample_ok = sample_fields.as_ref() == Some(&expected_config_fields)
        && evidence
            .config_sample
            .get("schemaVersion")
            .and_then(toml::Value::as_integer)
            == Some(2)
        && evidence
            .config_sample
            .get("profile")
            .and_then(toml::Value::as_str)
            == Some("production")
        && evidence
            .config_sample
            .get("topology")
            .and_then(toml::Value::as_str)
            == Some("durable-isolated");
    if !schema_ok || !sample_ok {
        findings.push(l2_finding("config-v2", "closed config schema and sample must be version 2 production/durable-isolated with unknown fields denied"));
    }

    let startup_ok = tokens_have_all(
        &evidence.lib_rs,
        "run",
        &["config::capture(", "runtime::launch_captured("],
    ) && tokens_have_all(
        &evidence.runtime_rs,
        "prepare",
        &[
            "crate::providers::build(",
            "AssemblyStartupInputs::production(",
        ],
    ) && tokens_have_all(
        &evidence.runtime_rs,
        "prepare_assembly",
        &["crate::eventing::wire(", "role_closer.finish("],
    ) && tokens_have_all(
        &evidence.runtime_rs,
        "launch_captured",
        &["launch(", "ProductionStartup::new("],
    );
    if !startup_ok {
        findings.push(l2_finding("run-reachability", "run must reach providers::build, eventing::wire, and role_closer.finish through the production startup funnel; aliases, dead helpers, comments, and cfg(test) bait are rejected"));
    }

    let provider_build_ok =
        tokens_have_all(
            &evidence.providers_rs,
            "build",
            &[
                "build_postgres(",
                "build_vault(",
                "build_federated_access_provider(",
                "build_production_infra(",
            ],
        ) && tokens_have_all(
            &evidence.providers_rs,
            "build_production_infra",
            &[
                "build_s3_archive_store(",
                "build_redis(",
                "RedisReadyProbe{",
                "RedisReadinessWorker::spawn(",
                "AmqpPrivateCa::from_pem(",
                "AmqpPublisherEndpoint::new(",
                "AmqpSubscriberEndpoint::new(",
                "AmqpRuntimeDeps::connect_with_private_ca(",
                "split_startup_resource(",
                "build_tenant_authority(",
                "VaultKeyProvider::new(",
                "PgDlxLifecycleRuntime::preflight_identities(",
                "PgDlxLifecycleRuntime::setup(",
                "crate::dlx::wire(",
                "SettingsOnlyProductionInfra{",
            ],
        ) && tokens_have_all(
            &evidence.providers_rs,
            "build_redis",
            &[
                "RedisPrivateCa::from_pem(",
                "RedisRuntimeDeps::connect_with_private_ca(",
            ],
        ) && function_local_initializer_has_all(
            &evidence.providers_rs,
            "build_production_infra",
            "redis_output",
            &[
                "RedisReadyProbe{",
                "RedisReadinessWorker::spawn(",
                "redis.runtime_resources()",
            ],
        ) && exact_non_optional_struct_fields(
            &evidence.providers_rs,
            "SettingsOnlyProductionInfra",
            &[
                "eventing",
                "distributed_lock_store",
                "dlx_archive_key_provider",
                "dlx_archive_store",
                "dlx_hot_key_provider",
                "dlx_lifecycle_repository",
                "readiness_startup_timeout",
                "amqp_publisher_activation",
                "amqp_subscriber_activation",
                "provider_activations",
            ],
        ) && production_items_forbid_identifier(&evidence.providers_rs, "fallback");
    let secret_fields_ok = exact_non_optional_struct_fields(
        &evidence.config_rs,
        "ServingSecretBundle",
        &[
            "pg_writer_password",
            "pg_reader_password",
            "pg_dlx_archiver_password",
            "pg_dlx_verifier_password",
            "pg_dlx_purger_password",
            "vault_token",
            "settings_amqp_publisher_url",
            "settings_amqp_subscriber_url",
            "redis_url",
            "tenant_authority_key",
            "dlx_hot_vault_token",
            "dlx_archive_vault_token",
            "s3_access_key_id",
            "s3_secret_access_key",
        ],
    );
    let secret_capture_ok = tokens_have_all(
        &evidence.config_rs,
        "capture_from",
        &[
            "SERVING_SECRET_BUNDLE_PATH",
            "FORBIDDEN_SHARED_AMQP_URL_ENV",
            "read_secret_bundle(",
        ],
    );
    let secret_validate_ok = impl_method_has_all(
        &evidence.config_rs,
        "ResolvedSecrets",
        "validate",
        &[
            "validate_tls_endpoint(&self.settings_amqp_publisher_url,\"\",\"\"",
            "validate_tls_endpoint(&self.settings_amqp_subscriber_url,\"\",\"\"",
            "self.settings_amqp_publisher_url==self.settings_amqp_subscriber_url",
            "validate_tls_endpoint(&self.redis_url,\"\",\"\")",
            "self.vault_token==self.dlx_hot_vault_token",
            "self.vault_token==self.dlx_archive_vault_token",
            "self.dlx_hot_vault_token==self.dlx_archive_vault_token",
        ],
    );
    let secret_bundle_ok = secret_fields_ok && secret_capture_ok && secret_validate_ok;
    let dlx_readiness_ok = tokens_have_all(
        &evidence.dlx_rs,
        "wire",
        &[
            "DLX_ARCHIVE_KEY_READINESS_PROBE",
            "DLX_HOT_KEY_READINESS_PROBE",
            "archive_key_readiness_worker(",
            "key_readiness_worker(",
        ],
    ) && tokens_have_all(
        &evidence.dlx_rs,
        "key_readiness_loop",
        &["verify_key_canary(", "apply_key_readiness("],
    ) && tokens_have_all(
        &evidence.dlx_rs,
        "apply_key_readiness",
        &["apply_key_provider_result(", "DlxLifecycleHealth::Degraded"],
    ) && tokens_have_all(
        &evidence.dlx_rs,
        "apply_key_provider_result",
        &[
            "DlxLifecycleHealth::Healthy",
            "DlxLifecycleHealth::Degraded",
        ],
    ) && tokens_have_all(
        &evidence.dlx_rs,
        "required_health_status",
        &["HealthStatus::Degraded", "HealthStatus::Unhealthy"],
    ) && impl_method_has_all(
        &evidence.dlx_rs,
        "WorkerProbe",
        "check",
        &["required_health_status("],
    ) && function_local_initializer_has_all(
        &evidence.dlx_rs,
        "wire",
        "dlx_hot_key_provider",
        &[
            "hot_key_probe_name",
            "key_readiness_worker(",
            "KeyReadinessSpec::hot()",
        ],
    ) && function_local_initializer_has_all(
        &evidence.dlx_rs,
        "wire",
        "dlx_archive_key_provider",
        &["archive_key_probe_name", "archive_key_readiness_worker("],
    ) && tokens_have_all(
        &evidence.providers_rs,
        "build_production_infra",
        &[
            "hot_output.merge(dlx_outputs.dlx_hot_key_provider);",
            "archive_output.merge(dlx_outputs.dlx_archive_key_provider);",
            ".finish(archive_output)",
        ],
    );
    if !provider_build_ok || !secret_bundle_ok || !dlx_readiness_ok {
        findings.push(l2_finding(
            "production-implementation",
            format!("run-reachable typed provider/config/DLX construction must remain mandatory, fallback-free, and readiness-backed (provider={provider_build_ok}, secret-fields={secret_fields_ok}, secret-capture={secret_capture_ok}, secret-validate={secret_validate_ok}, dlx={dlx_readiness_ok})"),
        ));
    }

    let exact_bridge = tokens_have_all(
        &evidence.eventing_rs,
        "wire",
        &[
            "eventing_composition::bridge_generated_settings_subscriptions(",
            "validate_settings_closure(",
            "wire_amqp_readiness(",
        ],
    ) && tokens_have_all(
        &evidence.bridge_rs,
        "bridge_generated_settings_subscriptions",
        &[
            "admitted_settings_dispatch",
            "settings_v1::CONTRACT_ID",
            "settings_v1::TOPIC",
            "schema_version()==\"\"",
            "consumer()==\"\"",
            "group().as_str()==generated::event::settings_v1::TOPIC",
            "SubscriberReadiness::Required",
            "SettingsConfigVersionChangedV1Settings",
            "ExternalEffectPolicy::Reconcile",
        ],
    ) && tokens_have_all(
        &evidence.eventing_rs,
        "wire_amqp_readiness",
        &[
            "publisher_readiness().is_ready()",
            "subscriber_readiness().is_ready()",
            "AmqpReadinessRole::Publisher",
            "AmqpReadinessRole::Subscriber",
        ],
    ) && tokens_have_all(
        &evidence.eventing_rs,
        "required_health_status",
        &["HealthStatus::Degraded", "HealthStatus::Unhealthy"],
    ) && impl_method_has_all(
        &evidence.eventing_rs,
        "WorkerProbe",
        "check",
        &["required_health_status("],
    );
    if !exact_bridge {
        findings.push(l2_finding("subscription", "requires exactly one activated config-version-changed@v1/settings reconcile/readiness-required bridge; generic, fallback, or nonactivated subscribers are forbidden"));
    }
    findings
}

fn discover(root: &Path) -> Result<(Vec<GovernedAssembly>, Vec<Finding>)> {
    let ir = AssemblyGovernanceIr::<Core>::load(root)?;
    let mut findings = Vec::new();
    for target in ir.targets() {
        let cargo_path = target.cargo_path();
        if !target.has_manifest() {
            if target.has_cargo_manifest() {
                let label = target
                    .dir()
                    .strip_prefix(root)
                    .unwrap_or(target.dir())
                    .display()
                    .to_string();
                findings.push(finding(
                    Rule::MissingManifest,
                    &label,
                    format!(
                        "assembly crate 必须声明 {}/assembly.toml；source={}",
                        label,
                        rel_label(root, &cargo_path)
                    ),
                ));
            }
            continue;
        }
    }
    Ok((ir.assemblies().to_vec(), findings))
}

fn validate_assembly(a: &GovernedAssembly) -> Vec<Finding> {
    let mut findings = Vec::new();
    validate_identityaudit_manifest_boundary(a, &mut findings);
    if let Some(production) = a.production() {
        validate_production_provider_posture(production, &mut findings);
        validate_production_security_closeout(production, &mut findings);
    }

    for (index, provider) in a.manifest().diport_providers().iter().enumerate() {
        let source = format!(
            "{}:{}",
            a.manifest_label(),
            provider_table_line(a.source_text(), index)
        );
        let subject = format!("{source} {}", provider.provider);
        if a.manifest().profile() == AssemblyProfile::Production
            && provider.port == DiportPort::RevocationStore
            && provider.durability != ProviderDurability::Persistent
        {
            findings.push(finding(
                Rule::RevocationDurability,
                &subject,
                "field=durability/profile production diport::RevocationStore provider 必须 durability=persistent；ephemeral-memory 只能用于 demo/test assembly",
            ));
        }

        if provider.lifecycle == ProviderLifecycle::Active
            && dependency_features(a.cargo_toml(), &provider.provider_crate).is_none()
        {
            findings.push(finding(
                Rule::ActiveProviderDependency,
                &subject,
                format!(
                    "field=providerCrate active providerCrate `{}` 必须出现在 {} [dependencies]",
                    provider.provider_crate,
                    a.cargo_label()
                ),
            ));
        }

        if provider.lifecycle == ProviderLifecycle::Active {
            let constructor = provider.provider;
            if constructor.port() != provider.port {
                findings.push(finding(
                    Rule::ActiveProviderPort,
                    &subject,
                    format!(
                        "field=provider typed provider `{}` 的真实 port 是 `{}`，manifest 不得声明为 `{}`",
                        constructor,
                        constructor.port(),
                        provider.port
                    ),
                ));
            } else {
                if constructor.durability() != provider.durability {
                    findings.push(finding(
                        Rule::ProviderDurabilityMismatch,
                        &subject,
                        format!(
                            "field=durability provider `{}` 的真实 durability 是 `{}`，manifest 不得声明为 `{}`",
                            constructor,
                            constructor.durability(),
                            provider.durability
                        ),
                    ));
                }
                if constructor.provider_crate() != provider.provider_crate {
                    findings.push(finding(
                        Rule::ProviderCrateMismatch,
                        &subject,
                        format!(
                            "field=providerCrate provider `{}` 的实现 crate 是 `{}`，manifest 不得声明为 `{}`",
                            constructor,
                            constructor.provider_crate(),
                            provider.provider_crate
                        ),
                    ));
                }
            }

            let required_features = required_features(provider);
            if let Some(actual_features) =
                dependency_features(a.cargo_toml(), &provider.provider_crate)
            {
                let missing: Vec<_> = required_features
                    .iter()
                    .filter(|feature| !actual_features.contains(**feature))
                    .cloned()
                    .collect();
                if !missing.is_empty() {
                    findings.push(finding(
                        Rule::ActiveProviderFeature,
                        &subject,
                        format!(
                            "field=requiredFeatures active provider `{}` for port `{}` 需要启用 Cargo feature {:?}；检查 {} [dependencies].{}",
                            provider.provider,
                            provider.port,
                            missing,
                            a.cargo_label(),
                            provider.provider_crate
                        ),
                    ));
                }
            }

            if a.manifest().name() == "runtime"
                && is_active_distributed_provider(provider)
                && !has_distributed_consumer_evidence(a)
            {
                findings.push(finding(
                    Rule::ActiveDistributedProviderConsumer,
                    &subject,
                    "field=consumer active distributed Lock/CAS provider 必须在 src/phase/domains.rs 的唯一 InfraBuilt::wire_domains phase owner 有 consumer 证据：wire_distributed 结果须按序注入 wire_event_transport",
                ));
            }
        }
    }
    validate_required_capabilities(a, &mut findings);
    validate_pdp_replay_store_capability(a, &mut findings);
    findings
}

fn validate_production_provider_posture(a: ProductionAssembly<'_>, findings: &mut Vec<Finding>) {
    // INVARIANT: ASSEMBLY-PRODUCTION-PROVIDER-POSTURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::production_provider_posture_rejects_non_active_and_non_governor_ephemeral", anti_vacuity = "tests::production_provider_posture_allows_exact_governor_exception" } — production is a hard ratchet: every declaration is executable and durable except the exact process-local edge limiter.
    let full_runtime = is_runtime_assembly(&a);
    for provider in a.manifest().diport_providers() {
        let exact_governor = provider.lifecycle == ProviderLifecycle::Active
            && provider.provider == ProviderConstructor::RatelimitGovernorLimiter
            && provider.port == DiportPort::RateLimiter
            && provider.provider_crate == "ratelimit"
            && provider.consumer == ProviderConsumer::Httpserve
            && provider.durability == ProviderDurability::EphemeralMemory;
        if provider.lifecycle != ProviderLifecycle::Active
            || (provider.durability != ProviderDurability::Persistent && !exact_governor)
        {
            findings.push(finding(
                Rule::ProductionProviderPosture,
                a.manifest_label(),
                format!(
                    "field=diportProviders profile=production provider={} 必须 lifecycle=active 且 durability=persistent；仅 exact active ratelimit::GovernorLimiter 可为 ephemeral-memory；actual lifecycle={} durability={}",
                    provider.provider, provider.lifecycle, provider.durability
                ),
            ));
        }
    }

    if full_runtime
        && !has_active_persistent_provider(
            &a,
            ProviderConstructor::PostgresRevocationStore,
            "deviceloop",
        )
    {
        findings.push(finding(
            Rule::ProductionProviderPosture,
            a.manifest_label(),
            "field=diportProviders runtime production requires exact active persistent postgres::PgRevocationStore for deviceloop",
        ));
    }
}

fn is_runtime_assembly(a: &GovernedAssembly) -> bool {
    a.manifest().name() == "runtime"
}

fn validate_pdp_replay_store_capability(a: &GovernedAssembly, findings: &mut Vec<Finding>) {
    let has_active_pdp = a.manifest().diport_providers().iter().any(|provider| {
        provider.port == DiportPort::Pdp && provider.lifecycle == ProviderLifecycle::Active
    });
    if a.manifest().name() != "runtime" || !has_active_pdp {
        return;
    }

    let provider = ProviderConstructor::PostgresServiceTokenReplayStore;
    let consumer = "oidc";
    let has_required_posture = a.manifest().diport_providers().iter().any(|candidate| {
        candidate.provider == provider
            && candidate.consumer.as_str() == consumer
            && candidate.lifecycle == ProviderLifecycle::Active
            && candidate.durability == ProviderDurability::Persistent
            && candidate.scope == Some(ProviderScope::ClusterGlobal)
            && candidate.failure_posture == Some(ProviderFailurePosture::FailClosed)
    });
    if !has_required_posture {
        findings.push(finding(
            Rule::PdpReplayStoreCapability,
            a.manifest_label(),
            format!(
                "field=diportProviders capability=PdpReplayStore expected active persistent cluster-global fail-closed `{provider}` for `{}` providerCrate `{}` consumer `{consumer}`; actual={}",
                provider.port(),
                provider.provider_crate(),
                provider_actual(a, provider, consumer)
            ),
        ));
    }
}

#[derive(Clone, Copy)]
struct DomainCapabilitySpec {
    domain: &'static str,
    capabilities: &'static [RequiredCapabilitySpec],
}

#[derive(Clone, Copy)]
struct RequiredCapabilitySpec {
    capability: &'static str,
    expectation: RequiredCapabilityExpectation,
}

#[derive(Clone, Copy)]
enum RequiredCapabilityExpectation {
    CargoDependency {
        dependency: &'static str,
        required_features: &'static [&'static str],
    },
    ActivePersistentProvider {
        provider: ProviderConstructor,
        consumer: &'static str,
    },
}

const IDENTITY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-identity"],
        },
    },
    RequiredCapabilitySpec {
        capability: "Signer",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::VaultSigner,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "Pdp",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::OidcProvider,
            consumer: "httpserve",
        },
    },
];

const SETTINGS_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-settings"],
        },
    },
    RequiredCapabilitySpec {
        capability: "VaultKeyProvider",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::VaultKeyProvider,
            consumer: "settings",
        },
    },
    RequiredCapabilitySpec {
        capability: "VaultSecretResolver",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::VaultSecretResolver,
            consumer: "settings",
        },
    },
];

const AUDIT_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-audit"],
        },
    },
    RequiredCapabilitySpec {
        capability: "MacVerifier",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "crypto-adapter",
            required_features: &[],
        },
    },
    RequiredCapabilitySpec {
        capability: "AuthAuditSink",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresAuthAuditSink,
            consumer: "httpserve",
        },
    },
];

const EMPTY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[];

const DURABLE_TOPOLOGY_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Publisher",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::AmqpPublisher,
            consumer: "eventexec",
        },
    },
    RequiredCapabilitySpec {
        capability: "AckableSubscriber",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::AmqpSubscriber,
            consumer: "eventexec",
        },
    },
    RequiredCapabilitySpec {
        capability: "LockStore",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::RedisLockStore,
            consumer: "distributed",
        },
    },
    RequiredCapabilitySpec {
        capability: "CasStore",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresCasStore,
            consumer: "distributed",
        },
    },
];

const REQUIRED_CAPABILITY_DOMAINS: &[DomainCapabilitySpec] = &[
    DomainCapabilitySpec {
        domain: "identity",
        capabilities: IDENTITY_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "settings",
        capabilities: SETTINGS_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "audit",
        capabilities: AUDIT_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "contractreg",
        capabilities: EMPTY_REQUIRED_CAPABILITIES,
    },
    DomainCapabilitySpec {
        domain: "syshealth",
        capabilities: EMPTY_REQUIRED_CAPABILITIES,
    },
];

#[cfg(test)]
fn required_capability_domain_specs() -> &'static [DomainCapabilitySpec] {
    REQUIRED_CAPABILITY_DOMAINS
}

fn validate_required_capabilities(a: &GovernedAssembly, findings: &mut Vec<Finding>) {
    // INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "check", source = "code" } —
    // assembly.toml 的 domains/topology 声明必须闭合到最小 provider/Cargo capability 事实。此 guard
    // 不改变 runtime 接线，不新增兼容路径；缺失、draft、ephemeral critical 均 fail-closed。
    for domain in a.manifest().domains() {
        let domain = domain.as_str();
        let Some(spec) = REQUIRED_CAPABILITY_DOMAINS
            .iter()
            .find(|spec| spec.domain == domain)
        else {
            findings.push(finding(
                Rule::RequiredCapability,
                a.manifest_label(),
                format!(
                    "field=domains domain={domain} capability=DomainCapabilityTable expected domain present in xtask required capability table; actual=missing-domain-spec"
                ),
            ));
            continue;
        };
        for capability in spec.capabilities {
            validate_required_capability(a, spec.domain, capability, findings);
        }
    }

    if requires_distributed_capabilities(a) {
        for capability in DURABLE_TOPOLOGY_REQUIRED_CAPABILITIES {
            validate_required_capability(a, "distributed", capability, findings);
        }
    }
}

fn validate_required_capability(
    a: &GovernedAssembly,
    domain: &str,
    spec: &RequiredCapabilitySpec,
    findings: &mut Vec<Finding>,
) {
    match spec.expectation {
        RequiredCapabilityExpectation::CargoDependency {
            dependency,
            required_features,
        } => match dependency_features(a.cargo_toml(), dependency) {
            None => findings.push(finding(
                Rule::RequiredCapability,
                a.cargo_label(),
                format!(
                    "field=dependencies domain={domain} capability={} expected exact [dependencies].{dependency} in {}; actual=missing-dependency",
                    spec.capability, a.cargo_label()
                ),
            )),
            Some(features)
                if required_features
                    .iter()
                    .any(|required| !features.iter().any(|actual| actual == required)) =>
            {
                findings.push(finding(
                    Rule::RequiredCapability,
                    a.cargo_label(),
                    format!(
                        "field=dependencies domain={domain} capability={} expected [dependencies].{dependency} features {:?}; actual={features:?}",
                        spec.capability, required_features
                    ),
                ));
            }
            Some(_) => {}
        }
        RequiredCapabilityExpectation::ActivePersistentProvider {
            provider,
            consumer,
        } => {
            if !has_active_persistent_provider(a, provider, consumer) {
                findings.push(finding(
                    Rule::RequiredCapability,
                    a.manifest_label(),
                    format!(
                        "field=diportProviders domain={domain} capability={} expected active persistent `{provider}` for `{}` providerCrate `{}` consumer `{consumer}`; actual={}",
                        spec.capability,
                        provider.port(),
                        provider.provider_crate(),
                        provider_actual(a, provider, consumer)
                    ),
                ));
            }
        }
    }
}

fn requires_distributed_capabilities(a: &GovernedAssembly) -> bool {
    a.manifest().profile() == AssemblyProfile::Production
        || matches!(
            a.manifest().topology(),
            AssemblyTopology::DurableShared | AssemblyTopology::DurableIsolated
        )
}

fn has_active_persistent_provider(
    a: &GovernedAssembly,
    provider: ProviderConstructor,
    consumer: &str,
) -> bool {
    a.manifest().diport_providers().iter().any(|candidate| {
        candidate.lifecycle == ProviderLifecycle::Active
            && candidate.durability == ProviderDurability::Persistent
            && candidate.port == provider.port()
            && candidate.provider == provider
            && candidate.provider_crate == provider.provider_crate()
            && candidate.consumer.as_str() == consumer
    })
}

fn provider_actual(a: &GovernedAssembly, provider: ProviderConstructor, consumer: &str) -> String {
    let actual = a
        .manifest()
        .diport_providers()
        .iter()
        .filter(|candidate| {
            candidate.port == provider.port()
                || candidate.provider == provider
                || candidate.provider_crate == provider.provider_crate()
                || candidate.consumer.as_str() == consumer
        })
        .map(provider_state)
        .collect::<Vec<_>>()
        .join(", ");
    if actual.is_empty() {
        "missing-provider".to_string()
    } else {
        actual
    }
}

fn provider_state(provider: &DiportProvider) -> String {
    format!(
        "port={} provider={} providerCrate={} consumer={} lifecycle={} durability={}",
        provider.port,
        provider.provider,
        provider.provider_crate,
        provider.consumer,
        provider.lifecycle,
        provider.durability
    )
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    #[serde(default)]
    dependencies: Vec<MetadataDependency>,
    #[serde(default)]
    targets: Vec<MetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    #[serde(default)]
    name: String,
    #[serde(default)]
    kind: Vec<String>,
    #[serde(default)]
    src_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    kind: Option<String>,
    rename: Option<String>,
    path: Option<PathBuf>,
    target: Option<String>,
}

fn load_workspace_metadata(root: &Path) -> Result<Option<CargoMetadata>> {
    let manifest = root.join("Cargo.toml");
    if !manifest.exists() {
        return Ok(None);
    }

    let manifest_arg = manifest.display().to_string();
    let args = cargo_metadata_args(manifest_arg.as_str());
    let mut cmd = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Metadata,
        &args[1..],
        &[],
        Some(root),
    );
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("执行 cargo metadata 失败：{}", manifest.display()))?;
    if !output.status.success() {
        bail!(
            "cargo metadata --locked 失败（{}）：{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let metadata = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("解析 cargo metadata JSON 失败：{}", manifest.display()))?;
    Ok(Some(metadata))
}

/// One private Cargo metadata snapshot shared by artifact checks. Raw metadata DTOs never cross
/// this façade, and every identity query is restricted to workspace packages.
pub(crate) struct CargoTargetCatalog {
    root: PathBuf,
    metadata: Option<CargoMetadata>,
}

impl CargoTargetCatalog {
    pub(crate) fn load(root: &Path) -> Result<Self> {
        Ok(Self {
            root: root.to_path_buf(),
            metadata: load_workspace_metadata(root)?,
        })
    }

    pub(crate) fn target_exists(
        &self,
        package_name: &str,
        target_name: &str,
        target_kind: &str,
    ) -> bool {
        self.package(package_name).is_some_and(|package| {
            package.targets.iter().any(|target| {
                target.name == target_name && target.kind.iter().any(|kind| kind == target_kind)
            })
        })
    }

    pub(crate) fn target_path(
        &self,
        package_name: &str,
        target_name: &str,
        target_kind: &str,
    ) -> Option<PathBuf> {
        self.package(package_name).and_then(|package| {
            package.targets.iter().find_map(|target| {
                (target.name == target_name && target.kind.iter().any(|kind| kind == target_kind))
                    .then(|| target.src_path.clone())
            })
        })
    }

    pub(crate) fn binary_belongs_to_assembly(
        &self,
        assembly: &str,
        package_name: &str,
        target_name: &str,
    ) -> bool {
        let assembly_manifest = self
            .root
            .join("assemblies")
            .join(assembly)
            .join("Cargo.toml");
        let Some(assembly_package) = self.package_by_manifest(&assembly_manifest) else {
            return false;
        };
        let Some(binary_package) = self.package(package_name) else {
            return false;
        };
        if !binary_package.targets.iter().any(|target| {
            target.name == target_name && target.kind.iter().any(|kind| kind == "bin")
        }) {
            return false;
        }
        binary_package.id == assembly_package.id
            || exact_normal_dependency(binary_package, assembly_package)
    }

    pub(crate) fn has_exact_normal_dependency(
        &self,
        package_name: &str,
        dependency_name: &str,
        dependency_manifest: &str,
    ) -> bool {
        let Some(package) = self.package(package_name) else {
            return false;
        };
        let expected_manifest = self.root.join(dependency_manifest);
        let Some(dependency) = self.package_by_manifest(&expected_manifest) else {
            return false;
        };
        dependency.name == dependency_name && exact_normal_dependency(package, dependency)
    }

    fn package(&self, name: &str) -> Option<&MetadataPackage> {
        let metadata = self.metadata.as_ref()?;
        metadata.packages.iter().find(|package| {
            package.name == name && metadata.workspace_members.contains(&package.id)
        })
    }

    fn package_by_manifest(&self, manifest: &Path) -> Option<&MetadataPackage> {
        let metadata = self.metadata.as_ref()?;
        metadata.packages.iter().find(|package| {
            package.manifest_path == manifest && metadata.workspace_members.contains(&package.id)
        })
    }
}

fn exact_normal_dependency(package: &MetadataPackage, dependency: &MetadataPackage) -> bool {
    let Some(dependency_dir) = dependency.manifest_path.parent() else {
        return false;
    };
    package.dependencies.iter().any(|candidate| {
        candidate.kind.is_none()
            && candidate.rename.is_none()
            && candidate.target.is_none()
            && candidate.name == dependency.name
            && candidate.path.as_deref() == Some(dependency_dir)
    })
}

fn cargo_metadata_args(manifest_arg: &str) -> [&str; 6] {
    [
        "metadata",
        "--format-version=1",
        "--locked",
        "--all-features",
        "--manifest-path",
        manifest_arg,
    ]
}

fn cargo_tree_stdout(
    root: &Path,
    assembly: &GovernedAssembly,
    depth: Option<usize>,
    all_features: bool,
) -> Result<String> {
    let manifest = assembly.cargo_path().display().to_string();
    let depth_value = depth.map(|value| value.to_string());
    let mut args = vec![
        "tree",
        "--manifest-path",
        manifest.as_str(),
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}|{f}",
    ];
    if all_features {
        args.insert(5, "--all-features");
    }
    if let Some(value) = depth_value.as_deref() {
        args.extend(["--depth", value]);
    }
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Tree,
        &args[1..],
        &[],
        Some(root),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .with_context(|| format!("执行 cargo tree 失败：{}", assembly.cargo_label()))?;
    if !output.status.success() {
        bail!(
            "cargo tree 失败（{}）：{}",
            assembly.cargo_label(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    String::from_utf8(output.stdout)
        .with_context(|| format!("cargo tree 输出不是 UTF-8：{}", assembly.cargo_label()))
}

fn cargo_tree_domains(
    root: &Path,
    assembly: &GovernedAssembly,
    metadata: &CargoMetadata,
    depth: Option<usize>,
) -> Result<BTreeSet<String>> {
    let stdout = cargo_tree_stdout(root, assembly, depth, true)?;
    let mut domains = BTreeSet::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| package_is_workspace_domain(root, metadata, package))
    {
        let Some(package_dir) = package.manifest_path.parent() else {
            continue;
        };
        let path_marker = format!("({})", package_dir.display());
        if stdout
            .lines()
            .filter_map(|line| line.split_once('|'))
            .any(|(line, _)| {
                line.starts_with(&format!("{} ", package.name)) && line.ends_with(&path_marker)
            })
        {
            domains.insert(package.name.clone());
        }
    }
    Ok(domains)
}

fn cargo_tree_default_normal_evidence(
    root: &Path,
    assembly: &GovernedAssembly,
    metadata: &CargoMetadata,
) -> Result<(BTreeSet<String>, bool)> {
    let stdout = cargo_tree_stdout(root, assembly, None, false)?;
    let mut packages = BTreeSet::new();
    let mut test_support_enabled = false;
    for (package, features) in stdout.lines().filter_map(|line| line.split_once('|')) {
        if let Some(name) = package.split_whitespace().next() {
            packages.insert(name.to_owned());
        }
        test_support_enabled |= features
            .split(',')
            .map(str::trim)
            .any(|feature| feature == "test-support");
    }
    let workspace_packages = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .filter(|package| packages.contains(&package.name))
        .map(|package| package.name.clone())
        .collect();
    Ok((workspace_packages, test_support_enabled))
}

fn package_by_manifest<'a>(
    metadata: &'a CargoMetadata,
    manifest_path: &Path,
) -> Option<&'a MetadataPackage> {
    metadata
        .packages
        .iter()
        .find(|package| package.manifest_path == manifest_path)
}

fn direct_normal_domain_deps(
    root: &Path,
    metadata: &CargoMetadata,
    assembly: &MetadataPackage,
) -> Result<BTreeSet<String>> {
    let mut domains = BTreeSet::new();
    for dependency in assembly
        .dependencies
        .iter()
        .filter(|dep| dep.kind.is_none())
    {
        if dependency.rename.is_some() {
            continue;
        }
        let Some(path) = &dependency.path else {
            continue;
        };
        for package in metadata
            .packages
            .iter()
            .filter(|package| package_is_workspace_domain(root, metadata, package))
        {
            let Some(package_dir) = package.manifest_path.parent() else {
                continue;
            };
            if dependency.name == package.name && path == package_dir {
                domains.insert(package.name.clone());
            }
        }
    }
    Ok(domains)
}

fn validate_domain_sets(
    a: &GovernedAssembly,
    direct_domains: BTreeSet<String>,
    closure_domains: BTreeSet<String>,
) -> Result<Vec<Finding>> {
    let manifest_domains: BTreeSet<&str> = a
        .manifest()
        .domains()
        .iter()
        .map(AssemblyDomain::as_str)
        .collect();
    let mut findings = Vec::new();
    for domain in &manifest_domains {
        if !direct_domains.contains(*domain) {
            findings.push(finding(
                Rule::ActiveDomainDependency,
                a.manifest_label(),
                format!(
                    "field=domains domain `{domain}` 必须在 {} [dependencies] 中以同名 normal dependency 直接依赖同名 workspace domain crate；dev/build/alias/package rename/crates.io 同名包均不满足",
                    a.cargo_label()
                ),
            ));
        }
    }

    for domain in closure_domains {
        if !manifest_domains.contains(domain.as_str()) {
            findings.push(finding(
                Rule::InactiveDomainDependencyClosure,
                a.cargo_label(),
                format!(
                    "field=domains inactive domain `{domain}` 出现在 assembly normal dependency closure；必须加入 {} domains 或移除/拆分该 normal 依赖",
                    a.manifest_label()
                ),
            ));
        }
    }
    Ok(findings)
}

fn validate_identityaudit_boundary(
    manifest_label: &str,
    cargo_label: &str,
    targets: &[MetadataTarget],
    closure_packages: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exact_targets = targets.len() == 4
        && targets.iter().any(|target| {
            target.name == "build-script-build" && target.kind.as_slice() == ["custom-build"]
        })
        && targets
            .iter()
            .any(|target| target.name == "identityaudit" && target.kind.as_slice() == ["lib"])
        && targets.iter().any(|target| {
            target.name == "identityaudit-server" && target.kind.as_slice() == ["bin"]
        })
        && targets.iter().any(|target| {
            target.name == "identityaudit_artifact_acceptance" && target.kind.as_slice() == ["test"]
        });
    if !exact_targets {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=package.targets {cargo_label} expected exactly repository-attestation build script, lib `identityaudit`, bin `identityaudit-server`, and binary+image test `identityaudit_artifact_acceptance`"
            ),
        ));
    }

    let expected = IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    let missing = expected
        .difference(closure_packages)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=default-normal-workspace-closure {cargo_label} missing required identityaudit packages: {}",
                missing.join(", ")
            ),
        ));
    }
    let unexpected = closure_packages
        .difference(&expected)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            manifest_label,
            format!(
                "field=default-normal-workspace-closure {cargo_label} unexpected packages entered identityaudit: {}",
                unexpected.join(", ")
            ),
        ));
    }
    findings
}

fn validate_identityaudit_manifest_boundary(a: &GovernedAssembly, findings: &mut Vec<Finding>) {
    if a.manifest().name() != "identityaudit" {
        return;
    }
    let listeners = a
        .manifest()
        .listeners()
        .iter()
        .map(|listener| {
            (
                listener.kind.as_str(),
                listener
                    .domains
                    .iter()
                    .map(AssemblyDomain::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let expected_listeners = vec![
        ("primary", vec!["identity"]),
        ("admin", vec!["audit"]),
        ("health", Vec::new()),
    ];
    if a.manifest().profile() != AssemblyProfile::Production
        || a.manifest().topology() != AssemblyTopology::DurableIsolated
        || listeners != expected_listeners
    {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            a.manifest_label(),
            format!(
                "field=profile/topology/listeners identityaudit requires profile=production, topology=durable-isolated, and exact Primary(identity)+Admin(audit)+Health(empty); actual profile={} topology={} listeners={listeners:?}",
                a.manifest().profile().as_str(),
                a.manifest().topology().as_str(),
            ),
        ));
    }
}

const IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES: &[&str] = &[
    "amqp",
    "assembly-schema",
    "audit",
    "audit-composition",
    "authmint",
    "authn",
    "bootstrap",
    "consistency",
    "crypto-adapter",
    "deviceloop",
    "diagctx",
    "diport",
    "distributed",
    "eventexec",
    "eventing-composition",
    "generated",
    "httpd",
    "httpserve",
    "identity",
    "identity-composition",
    "identityaudit",
    "ids",
    "observ",
    "oidc",
    "postgres",
    "postgres-migration-inventory",
    "primitives",
    "prometheus-adapter",
    "ratelimit",
    "redis-adapter",
    "runctx",
    "runtimeexec",
    "secure",
    "securederive",
    "support",
    "tracewire",
    "vault",
    "vocab",
];

#[derive(Clone, Copy)]
struct IdentityAuditExecutableEvidence<'a> {
    test_support_enabled: bool,
    schema_is_closed: bool,
    sample_is_regular_file: bool,
    artifact_acceptance: bool,
    journey_target_declared: bool,
    required_journey_test_declared: bool,
    runtimeexec_launch_is_live: bool,
    dockerfile: &'a str,
}

fn validate_identityaudit_executable_evidence(
    evidence: IdentityAuditExecutableEvidence<'_>,
) -> Vec<Finding> {
    let subject = "assemblies/identityaudit";
    let mut findings = Vec::new();
    if evidence.test_support_enabled {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=default-normal-features `test-support` must stay disabled in the production closure",
        ));
    }
    if !evidence.schema_is_closed {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=config-schema expected a non-symlink closed object schema at assemblies/identityaudit/config.schema.json",
        ));
    }
    if !evidence.sample_is_regular_file {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=config-sample expected a non-symlink regular file at assemblies/identityaudit/identityaudit.example.toml",
        ));
    }
    if !evidence.artifact_acceptance {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=artifact-acceptance expected exact binary+image executable assertions in assemblies/identityaudit/tests/artifact_acceptance.rs",
        ));
    }
    if !evidence.journey_target_declared || !evidence.required_journey_test_declared {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=journey expected explicit `identityaudit_runtime` target with non-ignored `identityaudit_login_audit_ready_sigterm_drain`",
        ));
    }
    if !evidence.runtimeexec_launch_is_live {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=health-runtime-wiring run must reach launch_captured, which must construct StartupPlan and call runtimeexec::launch_startup",
        ));
    }
    if !identityaudit_docker_target_is_closed(evidence.dockerfile) {
        findings.push(finding(
            Rule::IdentityAuditBoundary,
            subject,
            "field=Dockerfile expected migration-free serving builder and identityaudit-runtime on the distroless nonroot base, while runtime remains the default final stage",
        ));
    }
    findings
}

const SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES: &[&str] = &[
    "amqp",
    "assembly-schema",
    "authmint",
    "authn",
    "bootstrap",
    "consistency",
    "crypto-adapter",
    "diagctx",
    "diport",
    "distributed",
    "eventexec",
    "eventing-composition",
    "generated",
    "httpd",
    "httpserve",
    "ids",
    "observ",
    "oidc",
    "postgres",
    "postgres-migration-inventory",
    "primitives",
    "prometheus-adapter",
    "ratelimit",
    "redis-adapter",
    "runctx",
    "runtimeexec",
    "secure",
    "securederive",
    "settings",
    "settings-composition",
    "settingsonly",
    "s3",
    "support",
    "tracewire",
    "vault",
    "vocab",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactClosureStage {
    SourceRead,
    Parse,
    EntryLink,
    TestInventory,
    CaseInventory,
    EvidenceId,
    TestName,
    Dispatch,
    Scenario,
    ReceiptProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactClosurePath {
    Entry,
    Support,
}

impl ArtifactClosurePath {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "journeys/tests/settingsonly_production_artifact.rs",
            Self::Support => "journeys/tests/support/settingsonly_production_artifact.rs",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ArtifactClosureSpan {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

impl ArtifactClosureSpan {
    fn from_span(span: proc_macro2::Span) -> Self {
        let start = span.start();
        let end = span.end();
        Self {
            start_line: start.line,
            start_column: start.column,
            end_line: end.line,
            end_column: end.column,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactClosureViolation {
    stage: ArtifactClosureStage,
    case: Option<String>,
    path: ArtifactClosurePath,
    span: Option<ArtifactClosureSpan>,
    expected: String,
    actual: String,
}

impl ArtifactClosureViolation {
    fn new(
        stage: ArtifactClosureStage,
        case: Option<impl Into<String>>,
        path: ArtifactClosurePath,
        span: Option<proc_macro2::Span>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self {
            stage,
            case: case.map(Into::into),
            path,
            span: span.map(ArtifactClosureSpan::from_span),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    fn detail(&self) -> String {
        let case = self.case.as_deref().unwrap_or("<carrier>");
        let span = self.span.map_or_else(
            || "span=<none>".to_owned(),
            |span| {
                format!(
                    "span={}:{}-{}:{}",
                    span.start_line, span.start_column, span.end_line, span.end_column
                )
            },
        );
        format!(
            "stage={:?} case={case} path={} {span} expected={} actual={}",
            self.stage,
            self.path.as_str(),
            self.expected,
            self.actual
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArtifactClosureCertificate {
    cases: BTreeSet<String>,
}

impl ArtifactClosureCertificate {
    #[cfg(test)]
    fn case_count(&self) -> usize {
        self.cases.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArtifactClosureEvidence {
    Certified(ArtifactClosureCertificate),
    Violations(Vec<ArtifactClosureViolation>),
}

impl ArtifactClosureEvidence {
    #[cfg(test)]
    fn certificate(cases: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Certified(ArtifactClosureCertificate {
            cases: cases.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Clone)]
struct SettingsOnlyExecutableEvidence<'a> {
    targets: &'a [MetadataTarget],
    closure_packages: &'a BTreeSet<String>,
    test_support_enabled: bool,
    schema_is_regular_file: bool,
    sample_is_regular_file: bool,
    production_artifact_target_declared: bool,
    production_artifact: ArtifactClosureEvidence,
    journey_target_declared: bool,
    required_journey_test_declared: bool,
    runtimeexec_launch_is_live: bool,
    dockerignore_contracts_included: bool,
}

fn validate_settingsonly_executable_evidence(
    evidence: SettingsOnlyExecutableEvidence<'_>,
) -> Vec<Finding> {
    let subject = "assemblies/settingsonly";
    let mut findings = Vec::new();
    let exact_targets = evidence.targets.len() == 3
        && evidence.targets.iter().any(|target| {
            target.name == "build-script-build" && target.kind.as_slice() == ["custom-build"]
        })
        && evidence
            .targets
            .iter()
            .any(|target| target.name == "settingsonly" && target.kind.as_slice() == ["lib"])
        && evidence.targets.iter().any(|target| {
            target.name == "settingsonly-server" && target.kind.as_slice() == ["bin"]
        });
    if !exact_targets {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=package.targets expected exactly repository-attestation build script, lib `settingsonly`, and bin `settingsonly-server`",
        ));
    }

    let allowed = SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES
        .iter()
        .map(|package| (*package).to_owned())
        .collect::<BTreeSet<_>>();
    let missing = allowed
        .difference(evidence.closure_packages)
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            format!(
                "field=default-normal-workspace-closure missing allowed settingsonly packages: {}",
                missing.join(", ")
            ),
        ));
    }
    let unexpected = evidence
        .closure_packages
        .difference(&allowed)
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            format!(
                "field=default-normal-workspace-closure unexpected packages entered settingsonly: {}",
                unexpected.join(", ")
            ),
        ));
    }
    if evidence.test_support_enabled {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=default-normal-features `test-support` must stay disabled in the production closure",
        ));
    }
    if !evidence.schema_is_regular_file {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=config-schema expected a non-symlink regular file at assemblies/settingsonly/config.schema.json",
        ));
    }
    if !evidence.sample_is_regular_file {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=config-sample expected a non-symlink regular file at assemblies/settingsonly/settingsonly.example.toml",
        ));
    }
    if !evidence.production_artifact_target_declared {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=production-artifact stage=Target path=journeys/Cargo.toml expected one exact integration-only `settingsonly_production_artifact` target",
        ));
    }
    if let ArtifactClosureEvidence::Violations(violations) = evidence.production_artifact {
        findings.extend(violations.into_iter().map(|violation| {
            finding(
                Rule::SettingsOnlyExecutableBoundary,
                violation.path.as_str(),
                format!("field=production-artifact {}", violation.detail()),
            )
        }));
    }
    if !evidence.journey_target_declared || !evidence.required_journey_test_declared {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=journey expected explicit `settingsonly_runtime` target with non-ignored `settingsonly_lifecycle_fixture_ready_request_sigterm_drain`",
        ));
    }
    if !evidence.runtimeexec_launch_is_live {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=health-runtime-wiring run must reach launch_captured, which must construct StartupPlan and call runtimeexec::launch_startup",
        ));
    }
    if !evidence.dockerignore_contracts_included {
        findings.push(finding(
            Rule::SettingsOnlyExecutableBoundary,
            subject,
            "field=.dockerignore contracts/ must remain in the settingsonly-runtime build context",
        ));
    }
    findings
}

fn is_regular_file_without_symlink(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("检查 {} 失败", path.display())),
    }
}

fn identityaudit_schema_is_closed(path: &Path) -> Result<bool> {
    if !is_regular_file_without_symlink(path)? {
        return Ok(false);
    }
    let source =
        std::fs::read_to_string(path).with_context(|| format!("读取 {} 失败", path.display()))?;
    let Ok(schema) = serde_json::from_str::<serde_json::Value>(&source) else {
        return Ok(false);
    };
    Ok(schema_objects_are_closed(&schema))
}

pub(crate) fn schema_objects_are_closed(value: &serde_json::Value) -> bool {
    let Some(schema) = value.as_object() else {
        return value == &serde_json::Value::Bool(false);
    };
    if schema.len() == 1
        && schema
            .get("$ref")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reference| reference.starts_with("#/definitions/"))
    {
        return true;
    }
    let can_accept_object = match schema.get("type") {
        Some(serde_json::Value::String(kind)) => kind == "object",
        Some(serde_json::Value::Array(kinds)) => kinds.iter().any(|kind| kind == "object"),
        Some(_) => true,
        None => true,
    };
    if can_accept_object
        && schema.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
    {
        return false;
    }

    // `not` cannot widen the instance set, so it cannot introduce an open object carrier.
    for keyword in [
        "if",
        "then",
        "else",
        "contains",
        "propertyNames",
        "additionalItems",
    ] {
        if schema
            .get(keyword)
            .is_some_and(|child| !schema_objects_are_closed(child))
        {
            return false;
        }
    }
    if let Some(items) = schema.get("items") {
        let closed = items.as_array().map_or_else(
            || schema_objects_are_closed(items),
            |items| items.iter().all(schema_objects_are_closed),
        );
        if !closed {
            return false;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if schema.get(keyword).is_some_and(|children| {
            children
                .as_array()
                .is_none_or(|children| !children.iter().all(schema_objects_are_closed))
        }) {
            return false;
        }
    }
    for keyword in [
        "properties",
        "patternProperties",
        "definitions",
        "$defs",
        "dependentSchemas",
    ] {
        if schema.get(keyword).is_some_and(|children| {
            children
                .as_object()
                .is_none_or(|children| !children.values().all(schema_objects_are_closed))
        }) {
            return false;
        }
    }
    if let Some(dependencies) = schema.get("dependencies") {
        let Some(dependencies) = dependencies.as_object() else {
            return false;
        };
        if !dependencies
            .values()
            .filter(|dependency| !dependency.is_array())
            .all(schema_objects_are_closed)
        {
            return false;
        }
    }
    true
}

fn identityaudit_journey_evidence(root: &Path) -> Result<(bool, bool)> {
    let manifest_path = root.join("journeys/Cargo.toml");
    let manifest: toml::Value = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?
        .parse()
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let target_declared = manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|target| {
                target.get("name").and_then(toml::Value::as_str) == Some("identityaudit_runtime")
                    && target.get("path").and_then(toml::Value::as_str)
                        == Some("tests/identityaudit_runtime.rs")
            })
        });
    let source_path = root.join("journeys/tests/identityaudit_runtime.rs");
    let required_test_declared = match std::fs::read_to_string(&source_path) {
        Ok(source) => identityaudit_journey_has_required_test(&source)
            .with_context(|| format!("解析 {} 失败", source_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", source_path.display()));
        }
    };
    Ok((target_declared, required_test_declared))
}

fn identityaudit_journey_has_required_test(source: &str) -> Result<bool> {
    const REQUIRED_TEST: &str = "identityaudit_login_audit_ready_sigterm_drain";
    for item in syn::parse_file(source)?.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident != REQUIRED_TEST
            || !function.attrs.iter().any(is_test_attribute)
            || function.attrs.iter().any(is_ignore_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
        {
            continue;
        }
        if function.block.stmts.iter().any(stmt_is_control_flow) {
            return Ok(false);
        }
        let mut visitor = IdentityAuditJourneyVisitor::default();
        syn::visit::Visit::visit_block(&mut visitor, &function.block);
        return Ok(visitor.is_complete());
    }
    Ok(false)
}

fn stmt_is_control_flow(statement: &syn::Stmt) -> bool {
    matches!(
        statement,
        syn::Stmt::Expr(
            syn::Expr::If(_)
                | syn::Expr::Match(_)
                | syn::Expr::Loop(_)
                | syn::Expr::While(_)
                | syn::Expr::ForLoop(_),
            _,
        )
    )
}

macro_rules! skip_opaque_witness_scopes {
    () => {
        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

        fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}

        fn visit_expr_const(&mut self, _node: &'ast syn::ExprConst) {}

        fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}

        fn visit_item_const(&mut self, _node: &'ast syn::ItemConst) {}

        fn visit_item_static(&mut self, _node: &'ast syn::ItemStatic) {}
    };
}

fn subset_runtimeexec_launch_is_live(root: &Path, assembly: &str) -> Result<bool> {
    let base = root.join("assemblies").join(assembly).join("src");
    let lib = std::fs::read_to_string(base.join("lib.rs"))
        .with_context(|| format!("读取 {assembly} lib runtime wiring 失败"))?;
    let runtime = std::fs::read_to_string(base.join("runtime.rs"))
        .with_context(|| format!("读取 {assembly} runtimeexec wiring 失败"))?;
    subset_runtimeexec_launch_sources_are_live(&lib, &runtime)
}

fn subset_runtimeexec_launch_sources_are_live(lib: &str, runtime: &str) -> Result<bool> {
    fn function_calls(source: &str, owner: &str) -> Result<Option<RuntimeLaunchCallVisitor>> {
        let file = syn::parse_file(source)?;
        let Some(function) = file.items.iter().find_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == owner
                    && !function.attrs.iter().any(is_conditional_attribute) =>
            {
                Some(function)
            }
            _ => None,
        }) else {
            return Ok(None);
        };
        if function.block.stmts.iter().any(stmt_is_control_flow) {
            return Ok(None);
        }
        let mut visitor = RuntimeLaunchCallVisitor::default();
        syn::visit::Visit::visit_block(&mut visitor, &function.block);
        Ok(Some(visitor))
    }

    let Some(run) = function_calls(lib, "run")? else {
        return Ok(false);
    };
    let Some(launch) = function_calls(runtime, "launch_captured")? else {
        return Ok(false);
    };
    let direct = launch.startup_plan && launch.launch_startup;
    let delegated = if launch.launch_helper {
        function_calls(runtime, "launch")?
            .is_some_and(|helper| helper.startup_plan && helper.launch_startup)
    } else {
        false
    };
    Ok(run.launch_captured && (direct || delegated))
}

#[derive(Default)]
struct RuntimeLaunchCallVisitor {
    launch_captured: bool,
    startup_plan: bool,
    launch_startup: bool,
    launch_helper: bool,
}

impl<'ast> syn::visit::Visit<'ast> for RuntimeLaunchCallVisitor {
    skip_opaque_witness_scopes!();

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.launch_captured |=
            expression_path_ends_with(node.func.as_ref(), &["runtime", "launch_captured"]);
        self.startup_plan |=
            expression_path_ends_with(node.func.as_ref(), &["runtimeexec", "StartupPlan", "new"]);
        self.launch_startup |=
            expression_path_ends_with(node.func.as_ref(), &["runtimeexec", "launch_startup"]);
        self.launch_helper |= expression_path_ends_with(node.func.as_ref(), &["launch"]);
        syn::visit::visit_expr_call(self, node);
    }
}

#[derive(Default)]
struct IdentityAuditJourneyVisitor {
    runtime_start: bool,
    wait_until_ready: bool,
    login: bool,
    wait_for_auth_audit: bool,
    wait_for_session_created_hash_chain: bool,
    send_sigterm: bool,
    wait_for_drain: bool,
}

impl IdentityAuditJourneyVisitor {
    fn is_complete(&self) -> bool {
        self.runtime_start
            && self.wait_until_ready
            && self.login
            && self.wait_for_auth_audit
            && self.wait_for_session_created_hash_chain
            && self.send_sigterm
            && self.wait_for_drain
    }
}

impl<'ast> syn::visit::Visit<'ast> for IdentityAuditJourneyVisitor {
    skip_opaque_witness_scopes!();

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.runtime_start |= expression_path_ends_with(
            node.func.as_ref(),
            &["RuntimeFixture", "start"],
        ) && matches!(node.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("providers"));
        self.wait_for_auth_audit |= expression_path_ends_with(
            node.func.as_ref(),
            &["wait_for_auth_audit"],
        ) && matches!(node.args.first(), Some(syn::Expr::Reference(pool)) if matches!(pool.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("pool")));
        self.wait_for_session_created_hash_chain |= expression_path_ends_with(
            node.func.as_ref(),
            &["wait_for_session_created_hash_chain"],
        ) && matches!(node.args.first(), Some(syn::Expr::Reference(pool)) if matches!(pool.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("pool")))
            && matches!(node.args.iter().nth(1), Some(syn::Expr::Reference(login)) if matches!(login.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("login")));
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let runtime = matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("runtime"));
        self.wait_until_ready |= runtime && node.method == "wait_until_ready";
        self.login |= runtime && node.method == "login";
        self.send_sigterm |= runtime && node.method == "send_sigterm";
        self.wait_for_drain |= runtime && node.method == "wait_for_drain";
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn identityaudit_artifact_acceptance_evidence(root: &Path) -> Result<bool> {
    let source_path = root.join("assemblies/identityaudit/tests/artifact_acceptance.rs");
    if !is_regular_file_without_symlink(&source_path)? {
        return Ok(false);
    }
    let source = std::fs::read_to_string(&source_path)
        .with_context(|| format!("读取 {} 失败", source_path.display()))?;
    identityaudit_artifact_source_is_closed(&source)
        .with_context(|| format!("解析 {} 失败", source_path.display()))
}

fn identityaudit_artifact_source_is_closed(source: &str) -> Result<bool> {
    let syntax = syn::parse_file(source)?;
    let mut binary = false;
    let mut image = false;
    let mut executable_contract = false;
    for item in syntax.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if function.sig.ident == "assert_executable_contract"
            && !function.attrs.iter().any(is_conditional_attribute)
        {
            let mut visitor = IdentityAuditExecutableContractVisitor::default();
            syn::visit::Visit::visit_block(&mut visitor, &function.block);
            executable_contract = visitor.is_complete();
        }
        if !function.attrs.iter().any(is_test_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
        {
            continue;
        }
        if function.sig.ident == "identityaudit_server_binary_is_an_executable_artifact"
            && !function.attrs.iter().any(is_ignore_attribute)
            && identityaudit_artifact_contract_tail(&function, ArtifactContractKind::Binary)
        {
            binary = true;
        }
        if function.sig.ident == "identityaudit_runtime_image_is_an_executable_artifact"
            && function.attrs.iter().any(is_ignore_attribute)
            && identityaudit_artifact_contract_tail(&function, ArtifactContractKind::Image)
            && image_environment_is_loaded(&function)
        {
            image = true;
        }
    }
    Ok(binary && image && executable_contract)
}

#[derive(Default)]
struct IdentityAuditExecutableContractVisitor {
    help_execution: bool,
    missing_config_execution: bool,
    assertions: usize,
}

impl IdentityAuditExecutableContractVisitor {
    fn is_complete(&self) -> bool {
        self.help_execution && self.missing_config_execution && self.assertions >= 4
    }
}

impl<'ast> syn::visit::Visit<'ast> for IdentityAuditExecutableContractVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "execute"
            && matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("artifact"))
            && let Some(syn::Expr::Reference(arguments)) = node.args.first()
            && let syn::Expr::Array(arguments) = arguments.expr.as_ref()
        {
            match arguments.elems.first() {
                Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(argument),
                    ..
                })) if arguments.elems.len() == 1 && argument.value() == "--help" => {
                    self.help_execution = true;
                }
                None => self.missing_config_execution = true,
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("assert") {
            self.assertions = self.assertions.saturating_add(1);
        }
        syn::visit::visit_macro(self, node);
    }
}

fn identityaudit_artifact_contract_tail(
    function: &syn::ItemFn,
    kind: ArtifactContractKind,
) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(assertion), None)) = function.block.stmts.last()
    else {
        return false;
    };
    if !expression_path_ends_with(assertion.func.as_ref(), &["assert_executable_contract"])
        || assertion.args.len() != 1
    {
        return false;
    }
    let Some(syn::Expr::Call(artifact)) = assertion.args.first() else {
        return false;
    };
    let expected = match kind {
        ArtifactContractKind::Binary => "Binary",
        ArtifactContractKind::Image => "Image",
    };
    if !expression_path_ends_with(artifact.func.as_ref(), &["Artifact", expected])
        || artifact.args.len() != 1
    {
        return false;
    }
    match (kind, artifact.args.first()) {
        (ArtifactContractKind::Binary, Some(syn::Expr::Macro(expression))) => {
            expression.mac.path.is_ident("env")
                && syn::parse2::<syn::LitStr>(expression.mac.tokens.clone())
                    .is_ok_and(|literal| literal.value() == "CARGO_BIN_EXE_identityaudit-server")
        }
        (ArtifactContractKind::Image, Some(syn::Expr::Reference(reference))) => {
            matches!(reference.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("image"))
        }
        _ => false,
    }
}

fn subset_builder_is_closed(builder: &DockerStage<'_>, package: &str, target: &str) -> bool {
    let cook = format!(
        "cargo chef cook --release --locked --recipe-path recipe.json --package {package} --bin {target}"
    );
    let build = format!("cargo build --release --locked --package {package} --bin {target}");
    let strip = format!("strip target/release/{target}");
    let expected = [
        ("COPY", "--from=planner /app/recipe.json recipe.json"),
        ("RUN", cook.as_str()),
        ("COPY", ". ."),
        ("RUN", build.as_str()),
        ("RUN", strip.as_str()),
    ];
    builder.base == "chef"
        && builder.instructions.len() == expected.len()
        && builder
            .instructions
            .iter()
            .zip(expected)
            .all(|(instruction, (keyword, arguments))| {
                docker_instruction_arguments(instruction, keyword) == Some(arguments)
            })
}

fn identityaudit_docker_target_is_closed(source: &str) -> bool {
    let stages = docker_stages(source);
    let builders = stages
        .iter()
        .filter(|stage| stage.name == "identityaudit-builder")
        .collect::<Vec<_>>();
    let runtimes = stages
        .iter()
        .filter(|stage| stage.name == "identityaudit-runtime")
        .collect::<Vec<_>>();
    let ([builder], [runtime]) = (builders.as_slice(), runtimes.as_slice()) else {
        return false;
    };
    let builder_ok = subset_builder_is_closed(builder, "identityaudit", "identityaudit-server");
    const RUNTIME_INSTRUCTIONS: &[(&str, &str)] = &[
        (
            "COPY",
            "--from=identityaudit-builder /app/target/release/identityaudit-server /usr/local/bin/identityaudit-server",
        ),
        (
            "COPY",
            "--from=identityaudit-builder /app/assemblies/identityaudit/config.schema.json /usr/share/rss/identityaudit/config.schema.json",
        ),
        ("ENTRYPOINT", "[\"/usr/local/bin/identityaudit-server\"]"),
    ];
    let runtime_ok = runtime.base == "gcr.io/distroless/cc-debian12:nonroot"
        && runtime.instructions.len() == RUNTIME_INSTRUCTIONS.len()
        && runtime.instructions.iter().zip(RUNTIME_INSTRUCTIONS).all(
            |(instruction, (keyword, arguments))| {
                docker_instruction_arguments(instruction, keyword) == Some(*arguments)
            },
        );
    let default_runtime_unchanged = stages.last().is_some_and(|stage| stage.name == "runtime");
    builder_ok && runtime_ok && default_runtime_unchanged
}

fn settingsonly_journey_evidence(root: &Path) -> Result<(bool, bool)> {
    let manifest_path = root.join("journeys/Cargo.toml");
    let manifest: toml::Value = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?
        .parse()
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let target_declared = manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .is_some_and(|targets| {
            targets.iter().any(|target| {
                target.get("name").and_then(toml::Value::as_str) == Some("settingsonly_runtime")
                    && target.get("path").and_then(toml::Value::as_str)
                        == Some("tests/settingsonly_runtime.rs")
            })
        });
    let source_path = root.join("journeys/tests/settingsonly_runtime.rs");
    let required_test_declared = match std::fs::read_to_string(&source_path) {
        Ok(source) => settingsonly_journey_has_required_test(&source)
            .with_context(|| format!("解析 {} 失败", source_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", source_path.display()));
        }
    };
    Ok((target_declared, required_test_declared))
}

fn settingsonly_journey_has_required_test(source: &str) -> Result<bool> {
    const REQUIRED_TEST: &str = "settingsonly_lifecycle_fixture_ready_request_sigterm_drain";
    let syntax = syn::parse_file(source)?;
    let parent = syntax.items.iter().find(|item| {
        matches!(item, syn::Item::Fn(function)
            if function.sig.ident == REQUIRED_TEST
                && function.attrs.iter().any(is_test_attribute)
                && !function.attrs.iter().any(is_ignore_attribute)
                && !function.attrs.iter().any(is_conditional_attribute))
    });
    let Some(syn::Item::Fn(parent)) = parent else {
        return Ok(false);
    };
    let mut parent_witness = SettingsJourneyVisitor::default();
    for statement in &parent.block.stmts {
        if !stmt_is_control_flow(statement) {
            syn::visit::Visit::visit_stmt(&mut parent_witness, statement);
        }
    }
    let exercise = syntax.items.iter().find(
        |item| matches!(item, syn::Item::Fn(function) if function.sig.ident == "exercise_child"),
    );
    let Some(syn::Item::Fn(exercise)) = exercise else {
        return Ok(false);
    };
    let mut exercise_witness = SettingsJourneyVisitor::default();
    syn::visit::Visit::visit_block(&mut exercise_witness, &exercise.block);
    Ok(parent_witness.parent_is_complete() && exercise_witness.exercise_is_complete())
}

#[derive(Default)]
struct SettingsJourneyVisitor {
    reserve_addresses: bool,
    child_logs: bool,
    spawn_child: bool,
    exercise_child: bool,
    remove_logs: bool,
    activation_accept: bool,
    health_contract: bool,
    primary_contract: bool,
    send_sigterm: bool,
    wait_for_child: bool,
    released_ports: usize,
}

impl SettingsJourneyVisitor {
    fn parent_is_complete(&self) -> bool {
        self.reserve_addresses
            && self.child_logs
            && self.spawn_child
            && self.exercise_child
            && self.remove_logs
    }

    fn exercise_is_complete(&self) -> bool {
        self.activation_accept
            && self.health_contract
            && self.primary_contract
            && self.send_sigterm
            && self.wait_for_child
            && self.released_ports >= 2
    }
}

impl<'ast> syn::visit::Visit<'ast> for SettingsJourneyVisitor {
    skip_opaque_witness_scopes!();

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        for (name, seen) in [
            ("reserve_listener_addresses", &mut self.reserve_addresses),
            ("spawn_child", &mut self.spawn_child),
            ("exercise_child", &mut self.exercise_child),
            ("assert_health_contract", &mut self.health_contract),
            ("assert_primary_fails_closed", &mut self.primary_contract),
            ("send_sigterm", &mut self.send_sigterm),
            ("wait_for_child", &mut self.wait_for_child),
        ] {
            *seen |= expression_path_ends_with(node.func.as_ref(), &[name]);
        }
        self.child_logs |= expression_path_ends_with(node.func.as_ref(), &["ChildLogs", "create"]);
        if expression_path_ends_with(node.func.as_ref(), &["assert_port_released"]) {
            self.released_ports += 1;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.remove_logs |= node.method == "remove"
            && matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("logs"));
        self.activation_accept |= node.method == "accept"
            && matches!(node.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident("activation_gate"));
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn settingsonly_production_artifact_evidence(
    root: &Path,
) -> Result<(bool, ArtifactClosureEvidence)> {
    let manifest_path = root.join("journeys/Cargo.toml");
    let manifest: toml::Value = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读取 {} 失败", manifest_path.display()))?
        .parse()
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let target_declared = settingsonly_production_artifact_target_is_exact(&manifest);
    let entry_path = root.join("journeys/tests/settingsonly_production_artifact.rs");
    let support_path = root.join("journeys/tests/support/settingsonly_production_artifact.rs");
    let entry = match std::fs::read_to_string(&entry_path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                target_declared,
                ArtifactClosureEvidence::Violations(vec![ArtifactClosureViolation::new(
                    ArtifactClosureStage::SourceRead,
                    None::<String>,
                    ArtifactClosurePath::Entry,
                    None,
                    "regular Rust source",
                    "missing",
                )]),
            ));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", entry_path.display()));
        }
    };
    let support = match std::fs::read_to_string(&support_path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                target_declared,
                ArtifactClosureEvidence::Violations(vec![ArtifactClosureViolation::new(
                    ArtifactClosureStage::SourceRead,
                    None::<String>,
                    ArtifactClosurePath::Support,
                    None,
                    "regular Rust source",
                    "missing",
                )]),
            ));
        }
        Err(error) => {
            return Err(error).with_context(|| format!("读取 {} 失败", support_path.display()));
        }
    };
    Ok((
        target_declared,
        settingsonly_production_artifact_sources_are_closed(&entry, &support),
    ))
}

fn settingsonly_production_artifact_target_is_exact(manifest: &toml::Value) -> bool {
    manifest
        .get("test")
        .and_then(toml::Value::as_array)
        .is_some_and(|targets| {
            let matching = targets
                .iter()
                .filter(|target| {
                    target.get("name").and_then(toml::Value::as_str)
                        == Some("settingsonly_production_artifact")
                })
                .collect::<Vec<_>>();
            matches!(matching.as_slice(), [target]
                if target.get("path").and_then(toml::Value::as_str)
                    == Some("tests/settingsonly_production_artifact.rs")
                    && target.get("required-features").and_then(toml::Value::as_array)
                        .is_some_and(|features| matches!(features.as_slice(), [feature]
                            if feature.as_str() == Some("integration"))))
        })
}

fn settingsonly_production_artifact_sources_are_closed(
    entry: &str,
    support: &str,
) -> ArtifactClosureEvidence {
    let entry = match parse_artifact_source(entry, ArtifactClosurePath::Entry) {
        Ok(source) => source,
        Err(violation) => return ArtifactClosureEvidence::Violations(vec![violation]),
    };
    let support = match parse_artifact_source(support, ArtifactClosurePath::Support) {
        Ok(source) => source,
        Err(violation) => return ArtifactClosureEvidence::Violations(vec![violation]),
    };
    let mut violations = Vec::new();
    if !production_entry_links_exact_support(&entry) {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::EntryLink,
            None::<String>,
            ArtifactClosurePath::Entry,
            None,
            "one non-conditional exact support module and import",
            "missing, aliased, duplicated, or conditional link",
        ));
    }

    let evidence_enums = support
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item) if item.ident == "EvidenceCase" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [evidence_enum] = evidence_enums.as_slice() else {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::CaseInventory,
            None::<String>,
            ArtifactClosurePath::Support,
            None,
            "one closed EvidenceCase enum",
            format!("{} EvidenceCase enums", evidence_enums.len()),
        ));
        return ArtifactClosureEvidence::Violations(violations);
    };
    let cases = collect_evidence_cases(evidence_enum, &mut violations);
    let ids = collect_case_string_projection(
        &support,
        "id",
        ArtifactClosureStage::EvidenceId,
        &mut violations,
    );
    let test_names = collect_case_string_projection(
        &support,
        "test_name",
        ArtifactClosureStage::TestName,
        &mut violations,
    );
    let wrappers = collect_case_test_wrappers(&entry, &mut violations);
    let dispatch = collect_case_dispatch(&support, &mut violations);
    reconcile_case_inventory(
        &cases,
        &ids,
        &test_names,
        &wrappers,
        &dispatch,
        &mut violations,
    );
    certify_case_ids(&cases, &ids, &mut violations);
    certify_case_test_names(&cases, &test_names, &wrappers, &mut violations);
    certify_case_dispatch_names(&cases, &dispatch, &mut violations);
    certify_typed_receipt_scenarios(&support, &cases, &dispatch, &mut violations);

    if violations.is_empty() {
        ArtifactClosureEvidence::Certified(ArtifactClosureCertificate { cases })
    } else {
        ArtifactClosureEvidence::Violations(violations)
    }
}

fn parse_artifact_source(
    source: &str,
    path: ArtifactClosurePath,
) -> std::result::Result<syn::File, ArtifactClosureViolation> {
    syn::parse_file(source).map_err(|error| {
        ArtifactClosureViolation::new(
            ArtifactClosureStage::Parse,
            None::<String>,
            path,
            Some(error.span()),
            "valid Rust source",
            error.to_string(),
        )
    })
}

fn collect_evidence_cases(
    evidence_enum: &syn::ItemEnum,
    violations: &mut Vec<ArtifactClosureViolation>,
) -> BTreeSet<String> {
    let mut cases = BTreeSet::new();
    if evidence_enum.attrs.iter().any(is_conditional_attribute) {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::CaseInventory,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(evidence_enum.ident.span()),
            "unconditional closed enum",
            "conditional EvidenceCase enum",
        ));
    }
    for variant in &evidence_enum.variants {
        let case = variant.ident.to_string();
        if !matches!(variant.fields, syn::Fields::Unit)
            || variant.discriminant.is_some()
            || variant.attrs.iter().any(is_conditional_attribute)
        {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::CaseInventory,
                Some(case.clone()),
                ArtifactClosurePath::Support,
                Some(variant.span()),
                "unconditional unit variant without discriminant",
                variant.to_token_stream().to_string(),
            ));
        }
        if !cases.insert(case.clone()) {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::CaseInventory,
                Some(case),
                ArtifactClosurePath::Support,
                Some(variant.ident.span()),
                "unique case variant",
                "duplicate variant",
            ));
        }
    }
    if cases.len() != 4 {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::CaseInventory,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(evidence_enum.ident.span()),
            "four evidence cases",
            format!("{} evidence cases: {cases:?}", cases.len()),
        ));
    }
    cases
}

fn collect_case_string_projection(
    support: &syn::File,
    method_name: &str,
    stage: ArtifactClosureStage,
    violations: &mut Vec<ArtifactClosureViolation>,
) -> BTreeMap<String, String> {
    let methods = support
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(item.self_ty.as_ref(), syn::Type::Path(path)
                if path.path.is_ident("EvidenceCase")) =>
            {
                item.items
                    .iter()
                    .filter_map(|item| match item {
                        syn::ImplItem::Fn(method) if method.sig.ident == method_name => {
                            Some(method)
                        }
                        _ => None,
                    })
                    .next()
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        violations.push(ArtifactClosureViolation::new(
            stage,
            None::<String>,
            ArtifactClosurePath::Support,
            None,
            format!("one exhaustive EvidenceCase::{method_name} projection"),
            format!("{} projection methods", methods.len()),
        ));
        return BTreeMap::new();
    };
    if method.attrs.iter().any(is_conditional_attribute) || method.block.stmts.len() != 1 {
        violations.push(ArtifactClosureViolation::new(
            stage,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(method.sig.ident.span()),
            "unconditional single exhaustive match",
            method.to_token_stream().to_string(),
        ));
        return BTreeMap::new();
    }
    let syn::Stmt::Expr(syn::Expr::Match(case_match), None) = &method.block.stmts[0] else {
        violations.push(ArtifactClosureViolation::new(
            stage,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(method.block.span()),
            "match self without wildcard",
            method.block.to_token_stream().to_string(),
        ));
        return BTreeMap::new();
    };
    if !matches!(case_match.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("self")) {
        violations.push(ArtifactClosureViolation::new(
            stage,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(case_match.expr.span()),
            "self scrutinee",
            case_match.expr.to_token_stream().to_string(),
        ));
    }
    let mut projection = BTreeMap::new();
    for arm in &case_match.arms {
        let Some(case) = case_pattern_name(&arm.pat) else {
            violations.push(ArtifactClosureViolation::new(
                stage,
                None::<String>,
                ArtifactClosurePath::Support,
                Some(arm.pat.span()),
                "explicit Self::<Case> arm without wildcard",
                arm.pat.to_token_stream().to_string(),
            ));
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) = arm.body.as_ref()
        else {
            violations.push(ArtifactClosureViolation::new(
                stage,
                Some(case),
                ArtifactClosurePath::Support,
                Some(arm.body.span()),
                "string literal projection",
                arm.body.to_token_stream().to_string(),
            ));
            continue;
        };
        if arm.guard.is_some() || projection.insert(case.clone(), value.value()).is_some() {
            violations.push(ArtifactClosureViolation::new(
                stage,
                Some(case),
                ArtifactClosurePath::Support,
                Some(arm.span()),
                "one unguarded projection arm",
                "guarded or duplicate arm",
            ));
        }
    }
    projection
}

fn case_pattern_name(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    let segments = path.path.segments.iter().collect::<Vec<_>>();
    matches!(segments.as_slice(), [owner, _] if owner.ident == "Self" || owner.ident == "EvidenceCase")
        .then(|| segments[1].ident.to_string())
}

fn collect_case_test_wrappers(
    entry: &syn::File,
    violations: &mut Vec<ArtifactClosureViolation>,
) -> BTreeMap<String, String> {
    let mut wrappers = BTreeMap::new();
    for item in &entry.items {
        let syn::Item::Fn(function) = item else {
            continue;
        };
        if !function.attrs.iter().any(is_test_attribute) {
            continue;
        }
        let test_name = function.sig.ident.to_string();
        if function.attrs.iter().any(is_ignore_attribute)
            || function.attrs.iter().any(is_conditional_attribute)
            || function
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("should_panic"))
            || function.block.stmts.len() != 1
        {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestInventory,
                None::<String>,
                ArtifactClosurePath::Entry,
                Some(function.sig.ident.span()),
                "one live unconditional non-empty run_case carrier",
                test_name,
            ));
            continue;
        }
        let syn::Stmt::Expr(syn::Expr::Await(awaited), None) = &function.block.stmts[0] else {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestInventory,
                None::<String>,
                ArtifactClosurePath::Entry,
                Some(function.block.span()),
                "tail-awaited run_case(EvidenceCase::<Case>)",
                function.block.to_token_stream().to_string(),
            ));
            continue;
        };
        let syn::Expr::Call(call) = awaited.base.as_ref() else {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestInventory,
                None::<String>,
                ArtifactClosurePath::Entry,
                Some(awaited.span()),
                "run_case call",
                awaited.to_token_stream().to_string(),
            ));
            continue;
        };
        let case = if expression_path_ends_with(call.func.as_ref(), &["run_case"])
            && call.args.len() == 1
        {
            call.args.first().and_then(|argument| match argument {
                syn::Expr::Path(path) => {
                    let segments = path.path.segments.iter().collect::<Vec<_>>();
                    matches!(segments.as_slice(), [owner, _] if owner.ident == "EvidenceCase")
                        .then(|| segments[1].ident.to_string())
                }
                _ => None,
            })
        } else {
            None
        };
        let Some(case) = case else {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestInventory,
                None::<String>,
                ArtifactClosurePath::Entry,
                Some(call.span()),
                "run_case(EvidenceCase::<Case>)",
                call.to_token_stream().to_string(),
            ));
            continue;
        };
        if let Some(previous) = wrappers.insert(case.clone(), test_name.clone()) {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestInventory,
                Some(case),
                ArtifactClosurePath::Entry,
                Some(function.sig.ident.span()),
                "one test carrier per case",
                format!("duplicate carriers {previous} and {test_name}"),
            ));
        }
    }
    wrappers
}

fn collect_case_dispatch(
    support: &syn::File,
    violations: &mut Vec<ArtifactClosureViolation>,
) -> BTreeMap<String, String> {
    let methods = support
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(item.self_ty.as_ref(), syn::Type::Path(path)
                    if path.path.is_ident("EvidenceCase")) =>
            {
                item.items.iter().find_map(|item| match item {
                    syn::ImplItem::Fn(method) if method.sig.ident == "dispatch" => Some(method),
                    _ => None,
                })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        violations.push(dispatch_violation(
            None,
            "one exhaustive EvidenceCase::dispatch method",
            format!("{} dispatch methods", methods.len()),
        ));
        return BTreeMap::new();
    };
    let fixture_ident = method
        .sig
        .inputs
        .iter()
        .find_map(|argument| match argument {
            syn::FnArg::Typed(argument)
                if matches!(argument.ty.as_ref(), syn::Type::Reference(reference)
                if matches!(reference.elem.as_ref(), syn::Type::Path(path)
                    if path.path.is_ident("Fixture"))) =>
            {
                match argument.pat.as_ref() {
                    syn::Pat::Ident(ident) => Some(&ident.ident),
                    _ => None,
                }
            }
            _ => None,
        });
    let Some(fixture_ident) = fixture_ident else {
        violations.push(dispatch_violation(
            Some(method.sig.span()),
            "one mutable Fixture parameter",
            method.sig.to_token_stream().to_string(),
        ));
        return BTreeMap::new();
    };
    let [syn::Stmt::Expr(syn::Expr::Match(case_match), None)] = method.block.stmts.as_slice()
    else {
        violations.push(dispatch_violation(
            Some(method.block.span()),
            "single exhaustive match self",
            method.block.to_token_stream().to_string(),
        ));
        return BTreeMap::new();
    };
    if method.sig.asyncness.is_none()
        || method.attrs.iter().any(is_conditional_attribute)
        || !matches!(case_match.expr.as_ref(), syn::Expr::Path(path) if path.path.is_ident("self"))
    {
        violations.push(dispatch_violation(
            Some(method.sig.span()),
            "unconditional async dispatch matching self",
            method.to_token_stream().to_string(),
        ));
    }
    let mut dispatch = BTreeMap::new();
    for arm in &case_match.arms {
        let Some(case) = case_pattern_name(&arm.pat) else {
            violations.push(dispatch_violation(
                Some(arm.pat.span()),
                "explicit EvidenceCase arm without wildcard",
                arm.pat.to_token_stream().to_string(),
            ));
            continue;
        };
        let scenario = match arm.body.as_ref() {
            syn::Expr::Await(awaited) => match awaited.base.as_ref() {
                syn::Expr::MethodCall(call)
                    if call.args.is_empty()
                        && matches!(call.receiver.as_ref(), syn::Expr::Path(path)
                            if path.path.is_ident(fixture_ident)) =>
                {
                    Some(call.method.to_string())
                }
                _ => None,
            },
            _ => None,
        };
        let Some(scenario) = scenario else {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::Dispatch,
                Some(case),
                ArtifactClosurePath::Support,
                Some(arm.body.span()),
                "awaited zero-argument call on the Fixture parameter",
                arm.body.to_token_stream().to_string(),
            ));
            continue;
        };
        let expected_scenario = snake_case(&case);
        if scenario != expected_scenario {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::Dispatch,
                Some(case.clone()),
                ArtifactClosurePath::Support,
                Some(arm.body.span()),
                expected_scenario,
                scenario.clone(),
            ));
        }
        if arm.guard.is_some() || dispatch.insert(case.clone(), scenario).is_some() {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::Dispatch,
                Some(case),
                ArtifactClosurePath::Support,
                Some(arm.span()),
                "one unguarded dispatch arm",
                arm.to_token_stream().to_string(),
            ));
        }
    }

    validate_production_runner(support, violations);
    dispatch
}

fn validate_production_runner(support: &syn::File, violations: &mut Vec<ArtifactClosureViolation>) {
    let runners = support
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "run_case" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [runner] = runners.as_slice() else {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::Dispatch,
            None::<String>,
            ArtifactClosurePath::Support,
            None,
            "one run_case function",
            format!("{} run_case functions", runners.len()),
        ));
        return;
    };
    let Some((case_ident, _)) = runner
        .sig
        .inputs
        .first()
        .and_then(|argument| match argument {
            syn::FnArg::Typed(argument) => match (argument.pat.as_ref(), argument.ty.as_ref()) {
                (syn::Pat::Ident(ident), syn::Type::Path(path))
                    if path_has_suffix(&path.path, &["EvidenceCase"]) =>
                {
                    Some((&ident.ident, path))
                }
                _ => None,
            },
            _ => None,
        })
    else {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::Dispatch,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(runner.sig.span()),
            "one EvidenceCase parameter",
            runner.sig.to_token_stream().to_string(),
        ));
        return;
    };
    let mut fixture_binding = None;
    let mut result_binding = None;
    let mut start_index = None;
    let mut dispatch_index = None;
    let mut finish_index = None;
    for (index, statement) in runner.block.stmts.iter().enumerate() {
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let syn::Pat::Ident(binding) = &local.pat else {
            continue;
        };
        let Some(init) = &local.init else {
            continue;
        };
        if fixture_start_consumes_case(init.expr.as_ref(), case_ident) {
            if fixture_binding.replace(binding.ident.clone()).is_some() {
                violations.push(dispatch_violation(
                    Some(binding.ident.span()),
                    "one Fixture::start binding",
                    "duplicate Fixture::start",
                ));
            }
            start_index = Some(index);
        }
        if fixture_binding.as_ref().is_some_and(|fixture| {
            expression_contains_case_dispatch(init.expr.as_ref(), case_ident, fixture)
        }) {
            result_binding = Some(binding.ident.clone());
            dispatch_index = Some(index);
        }
    }
    if let (Some(fixture), Some(result)) = (&fixture_binding, &result_binding) {
        for (index, statement) in runner.block.stmts.iter().enumerate() {
            if finish_consumes_bindings(statement, fixture, result)
                && finish_index.replace(index).is_some()
            {
                violations.push(dispatch_violation(
                    Some(statement.span()),
                    "one fixture.finish(result)",
                    "duplicate finish",
                ));
            }
        }
    }
    let mut flow = ProductionRunnerFlow::default();
    syn::visit::Visit::visit_block(&mut flow, &runner.block);
    if runner.sig.asyncness.is_none()
        || runner.attrs.iter().any(is_conditional_attribute)
        || runner.sig.inputs.len() != 1
        || flow.fixture_starts != 1
        || flow.finishes != 1
        || flow.extra_control_flow
        || !matches!((start_index, dispatch_index, finish_index), (Some(start), Some(dispatch), Some(finish)) if start < dispatch && dispatch < finish)
    {
        violations.push(dispatch_violation(
            Some(runner.sig.ident.span()),
            "ordered Fixture::start -> case.dispatch -> fixture.finish(result)",
            runner.block.to_token_stream().to_string(),
        ));
    }
}

fn expression_contains_case_dispatch(
    expression: &syn::Expr,
    case_ident: &syn::Ident,
    fixture_ident: &syn::Ident,
) -> bool {
    struct DispatchCall<'a> {
        case_ident: &'a syn::Ident,
        fixture_ident: &'a syn::Ident,
        count: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for DispatchCall<'_> {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "dispatch"
                && matches!(call.receiver.as_ref(), syn::Expr::Path(path)
                    if path.path.is_ident(self.case_ident))
                && matches!(call.args.first(), Some(syn::Expr::Reference(reference))
                    if reference.mutability.is_some()
                        && matches!(reference.expr.as_ref(), syn::Expr::Path(path)
                            if path.path.is_ident(self.fixture_ident)))
                && call.args.len() == 1
            {
                self.count += 1;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = DispatchCall {
        case_ident,
        fixture_ident,
        count: 0,
    };
    syn::visit::Visit::visit_expr(&mut visitor, expression);
    visitor.count == 1
}

fn fixture_start_consumes_case(expression: &syn::Expr, case_ident: &syn::Ident) -> bool {
    let syn::Expr::Try(tried) = expression else {
        return false;
    };
    let syn::Expr::Await(awaited) = tried.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Call(call) = awaited.base.as_ref() else {
        return false;
    };
    expression_path_ends_with(call.func.as_ref(), &["Fixture", "start"])
        && call.args.len() == 2
        && matches!(call.args.iter().nth(1), Some(syn::Expr::MethodCall(id))
            if id.method == "id" && id.args.is_empty()
                && matches!(id.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident(case_ident)))
}

fn finish_consumes_bindings(
    statement: &syn::Stmt,
    fixture: &syn::Ident,
    result: &syn::Ident,
) -> bool {
    let syn::Stmt::Expr(syn::Expr::Await(awaited), None) = statement else {
        return false;
    };
    matches!(awaited.base.as_ref(), syn::Expr::MethodCall(call)
        if call.method == "finish" && call.args.len() == 1
            && matches!(call.receiver.as_ref(), syn::Expr::Path(path) if path.path.is_ident(fixture))
            && matches!(call.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident(result)))
}

fn dispatch_violation(
    span: Option<proc_macro2::Span>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> ArtifactClosureViolation {
    ArtifactClosureViolation::new(
        ArtifactClosureStage::Dispatch,
        None::<String>,
        ArtifactClosurePath::Support,
        span,
        expected,
        actual,
    )
}

fn reconcile_case_inventory(
    cases: &BTreeSet<String>,
    ids: &BTreeMap<String, String>,
    test_names: &BTreeMap<String, String>,
    wrappers: &BTreeMap<String, String>,
    dispatch: &BTreeMap<String, String>,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    for (stage, path, label, actual) in [
        (
            ArtifactClosureStage::EvidenceId,
            ArtifactClosurePath::Support,
            "EvidenceCase::id arms",
            ids.keys().cloned().collect::<BTreeSet<_>>(),
        ),
        (
            ArtifactClosureStage::TestName,
            ArtifactClosurePath::Support,
            "EvidenceCase::test_name arms",
            test_names.keys().cloned().collect(),
        ),
        (
            ArtifactClosureStage::TestInventory,
            ArtifactClosurePath::Entry,
            "test wrappers",
            wrappers.keys().cloned().collect(),
        ),
        (
            ArtifactClosureStage::Dispatch,
            ArtifactClosurePath::Support,
            "dispatch arms",
            dispatch.keys().cloned().collect(),
        ),
    ] {
        for missing in cases.difference(&actual) {
            violations.push(ArtifactClosureViolation::new(
                stage,
                Some(missing.clone()),
                path,
                None,
                format!("{label} contains the enum case"),
                "missing",
            ));
        }
        for stale in actual.difference(cases) {
            violations.push(ArtifactClosureViolation::new(
                stage,
                Some(stale.clone()),
                path,
                None,
                format!("{label} contains only enum cases"),
                "stale or unknown case",
            ));
        }
    }
}

fn certify_case_ids(
    cases: &BTreeSet<String>,
    ids: &BTreeMap<String, String>,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    let mut seen = BTreeSet::new();
    for case in cases {
        let expected = format!("SETTINGSONLY-T3-{}-01", screaming_kebab_case(case));
        let actual = ids
            .get(case)
            .cloned()
            .unwrap_or_else(|| "missing".to_owned());
        if actual != expected || !seen.insert(actual.clone()) {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::EvidenceId,
                Some(case.clone()),
                ArtifactClosurePath::Support,
                None,
                expected,
                actual,
            ));
        }
    }
}

fn screaming_kebab_case(value: &str) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    let mut result = String::new();
    for (index, ch) in chars.iter().copied().enumerate() {
        let previous = index
            .checked_sub(1)
            .and_then(|index| chars.get(index))
            .copied();
        let next = chars.get(index + 1).copied();
        if index > 0
            && ((ch.is_ascii_uppercase()
                && previous.is_some_and(|previous| previous.is_ascii_lowercase())
                || ch.is_ascii_uppercase()
                    && previous.is_some_and(|previous| previous.is_ascii_uppercase())
                    && next.is_some_and(|next| next.is_ascii_lowercase()))
                || !ch.is_ascii_digit()
                    && previous.is_some_and(|previous| previous.is_ascii_digit()))
        {
            result.push('-');
        }
        result.push(ch.to_ascii_uppercase());
    }
    result
}

fn certify_case_test_names(
    cases: &BTreeSet<String>,
    test_names: &BTreeMap<String, String>,
    wrappers: &BTreeMap<String, String>,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    let mut seen = BTreeSet::new();
    for case in cases {
        let expected = test_names
            .get(case)
            .cloned()
            .unwrap_or_else(|| "missing".to_owned());
        let actual = wrappers
            .get(case)
            .cloned()
            .unwrap_or_else(|| "missing".to_owned());
        if expected != actual || !seen.insert(expected.clone()) {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::TestName,
                Some(case.clone()),
                if actual == "missing" {
                    ArtifactClosurePath::Entry
                } else {
                    ArtifactClosurePath::Support
                },
                None,
                expected,
                actual,
            ));
        }
    }
}

fn certify_case_dispatch_names(
    cases: &BTreeSet<String>,
    dispatch: &BTreeMap<String, String>,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    for case in cases {
        let expected = snake_case(case);
        let actual = dispatch
            .get(case)
            .cloned()
            .unwrap_or_else(|| "missing".to_owned());
        if actual != expected {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::Dispatch,
                Some(case.clone()),
                ArtifactClosurePath::Support,
                None,
                expected,
                actual,
            ));
        }
    }
}

fn snake_case(value: &str) -> String {
    screaming_kebab_case(value)
        .to_ascii_lowercase()
        .replace('-', "_")
}

fn certify_typed_receipt_scenarios(
    support: &syn::File,
    cases: &BTreeSet<String>,
    dispatch: &BTreeMap<String, String>,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    certify_receipt_type_boundaries(support, violations);
    let fixture_methods = support
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(item.self_ty.as_ref(), syn::Type::Path(path)
                    if path.path.is_ident("Fixture")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let async_methods = fixture_methods
        .iter()
        .filter_map(|(name, method)| method.sig.asyncness.is_some().then_some(name.clone()))
        .collect::<BTreeSet<_>>();

    certify_hazard_receipt_minter(
        &fixture_methods,
        "UnackedReceipt",
        &["wait_claimed", "wait_broker_delivery"],
        violations,
    );
    certify_hazard_receipt_minter(
        &fixture_methods,
        "InflightReceipt",
        &["wait_claimed", "wait_for_waiter"],
        violations,
    );

    for case in cases {
        let Some(name) = dispatch.get(case) else {
            continue;
        };
        let Some(method) = fixture_methods.get(name) else {
            violations.push(scenario_violation(
                case,
                None,
                "dispatched Fixture scenario method",
                format!("missing Fixture::{name}"),
            ));
            continue;
        };
        let mut flow = ScenarioFlowVisitor::default();
        syn::visit::Visit::visit_block(&mut flow, &method.block);
        if method.sig.asyncness.is_none()
            || method.attrs.iter().any(is_conditional_attribute)
            || method.block.stmts.is_empty()
            || flow.forbidden
        {
            violations.push(scenario_violation(
                case,
                Some(method.sig.ident.span()),
                "live unconditional transparent async scenario",
                method.to_token_stream().to_string(),
            ));
            continue;
        }
        let mut calls = ScenarioCallFlow::new(&async_methods);
        syn::visit::Visit::visit_block(&mut calls, &method.block);
        for call in calls.invalid {
            violations.push(scenario_violation(
                case,
                Some(call.span),
                "async witness awaited and its Result consumed",
                call.actual,
            ));
        }
        for (name, spans) in calls.consumed {
            if spans.len() > 1 {
                violations.push(scenario_violation(
                    case,
                    spans.first().copied(),
                    format!("one live {name} witness"),
                    format!("{} witnesses", spans.len()),
                ));
            }
        }
        for construction in calls.receipt_constructions {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::ReceiptProvenance,
                Some(case.clone()),
                ArtifactClosurePath::Support,
                Some(construction.1),
                "receipt minted by a typed Fixture method",
                format!("direct {} construction", construction.0),
            ));
        }
    }
}

fn certify_receipt_type_boundaries(
    support: &syn::File,
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    for receipt in support.items.iter().filter_map(|item| match item {
        syn::Item::Struct(receipt) if receipt.ident.to_string().ends_with("Receipt") => {
            Some(receipt)
        }
        _ => None,
    }) {
        let cloneable = receipt.attrs.iter().any(|attribute| {
            attribute.path().is_ident("derive") && {
                let derive = attribute.meta.to_token_stream().to_string();
                derive
                    .split(|ch: char| !ch.is_ascii_alphanumeric())
                    .any(|trait_name| matches!(trait_name, "Clone" | "Copy"))
            }
        });
        let private_fields = receipt
            .fields
            .iter()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited));
        if cloneable || !matches!(receipt.vis, syn::Visibility::Inherited) || !private_fields {
            violations.push(ArtifactClosureViolation::new(
                ArtifactClosureStage::ReceiptProvenance,
                None::<String>,
                ArtifactClosurePath::Support,
                Some(receipt.ident.span()),
                "private non-Clone non-Copy receipt with private fields",
                receipt.to_token_stream().to_string(),
            ));
        }
    }
}

fn certify_hazard_receipt_minter(
    fixture_methods: &BTreeMap<String, &syn::ImplItemFn>,
    receipt: &str,
    ordered_observations: &[&str],
    violations: &mut Vec<ArtifactClosureViolation>,
) {
    let minters = fixture_methods
        .values()
        .filter(|method| method_result_receipt(method).as_deref() == Some(receipt))
        .copied()
        .collect::<Vec<_>>();
    let [minter] = minters.as_slice() else {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::ReceiptProvenance,
            None::<String>,
            ArtifactClosurePath::Support,
            None,
            format!("one typed {receipt} minter"),
            format!("{} minters", minters.len()),
        ));
        return;
    };
    let mut flow = ReceiptMinterFlow::default();
    syn::visit::Visit::visit_block(&mut flow, &minter.block);
    let positions = ordered_observations
        .iter()
        .map(|expected| {
            (flow
                .calls
                .iter()
                .filter(|actual| *actual == expected)
                .count()
                == 1)
                .then(|| {
                    flow.calls
                        .iter()
                        .position(|actual| actual == expected)
                        .map(|position| (expected, position))
                })
                .flatten()
        })
        .collect::<Option<Vec<_>>>();
    let ordered = positions
        .as_ref()
        .is_some_and(|positions| positions.windows(2).all(|pair| pair[0].1 < pair[1].1));
    if minter.sig.asyncness.is_none()
        || minter.attrs.iter().any(is_conditional_attribute)
        || flow
            .constructed
            .iter()
            .filter(|name| *name == receipt)
            .count()
            != 1
        || flow.invalid_consumption
        || !ordered
    {
        violations.push(ArtifactClosureViolation::new(
            ArtifactClosureStage::ReceiptProvenance,
            None::<String>,
            ArtifactClosurePath::Support,
            Some(minter.sig.ident.span()),
            format!(
                "typed {receipt} minter with ordered {}",
                ordered_observations.join(" -> ")
            ),
            format!("calls={:?} constructed={:?}", flow.calls, flow.constructed),
        ));
    }
}

fn method_result_receipt(method: &syn::ImplItemFn) -> Option<String> {
    let syn::ReturnType::Type(_, return_type) = &method.sig.output else {
        return None;
    };
    let syn::Type::Path(result) = return_type.as_ref() else {
        return None;
    };
    let arguments = match &result.path.segments.last()?.arguments {
        syn::PathArguments::AngleBracketed(arguments) => &arguments.args,
        _ => return None,
    };
    arguments.iter().find_map(|argument| match argument {
        syn::GenericArgument::Type(syn::Type::Path(path)) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .filter(|name| name.ends_with("Receipt")),
        _ => None,
    })
}

#[derive(Default)]
struct ReceiptMinterFlow {
    calls: Vec<String>,
    constructed: Vec<String>,
    await_depth: usize,
    try_depth: usize,
    invalid_consumption: bool,
}

impl<'ast> syn::visit::Visit<'ast> for ReceiptMinterFlow {
    fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
        self.await_depth += 1;
        syn::visit::visit_expr_await(self, node);
        self.await_depth -= 1;
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.try_depth += 1;
        syn::visit::visit_expr_try(self, node);
        self.try_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.calls.push(node.method.to_string());
        if matches!(
            node.method.to_string().as_str(),
            "wait_claimed" | "wait_broker_delivery" | "wait_for_waiter"
        ) && (self.await_depth == 0 || self.try_depth == 0)
        {
            self.invalid_consumption = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if let Some(name) = node.path.segments.last() {
            self.constructed.push(name.ident.to_string());
        }
        syn::visit::visit_expr_struct(self, node);
    }
}

fn scenario_violation(
    case: &str,
    span: Option<proc_macro2::Span>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> ArtifactClosureViolation {
    ArtifactClosureViolation::new(
        ArtifactClosureStage::Scenario,
        Some(case.to_owned()),
        ArtifactClosurePath::Support,
        span,
        expected,
        actual,
    )
}

struct InvalidScenarioCall {
    span: proc_macro2::Span,
    actual: String,
}

struct ScenarioCallFlow<'a> {
    async_methods: &'a BTreeSet<String>,
    await_depth: usize,
    try_depth: usize,
    consumed: BTreeMap<String, Vec<proc_macro2::Span>>,
    invalid: Vec<InvalidScenarioCall>,
    receipt_constructions: Vec<(String, proc_macro2::Span)>,
}

impl<'a> ScenarioCallFlow<'a> {
    fn new(async_methods: &'a BTreeSet<String>) -> Self {
        Self {
            async_methods,
            await_depth: 0,
            try_depth: 0,
            consumed: BTreeMap::new(),
            invalid: Vec::new(),
            receipt_constructions: Vec::new(),
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for ScenarioCallFlow<'_> {
    fn visit_expr_await(&mut self, node: &'ast syn::ExprAwait) {
        self.await_depth += 1;
        syn::visit::visit_expr_await(self, node);
        self.await_depth -= 1;
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.try_depth += 1;
        syn::visit::visit_expr_try(self, node);
        self.try_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if self.async_methods.contains(&name) {
            if self.await_depth == 0 || self.try_depth == 0 {
                self.invalid.push(InvalidScenarioCall {
                    span: node.span(),
                    actual: format!(
                        "{name}: await_depth={}, try_depth={}",
                        self.await_depth, self.try_depth
                    ),
                });
            } else {
                self.consumed.entry(name).or_default().push(node.span());
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if let Some(name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            && name.ends_with("Receipt")
        {
            self.receipt_constructions.push((name, node.span()));
        }
        syn::visit::visit_expr_struct(self, node);
    }
}

fn production_entry_links_exact_support(entry: &syn::File) -> bool {
    let modules = entry
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "settingsonly_production_artifact" => {
                Some(module)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [module] = modules.as_slice() else {
        return false;
    };
    let exact_path = module.attrs.iter().filter_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        match &attribute.meta {
            syn::Meta::NameValue(value) => match &value.value {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(path),
                    ..
                }) => Some(path.value()),
                _ => Some(String::new()),
            },
            _ => Some(String::new()),
        }
    });
    if module.content.is_some()
        || module.attrs.iter().any(is_conditional_attribute)
        || exact_path.collect::<Vec<_>>() != ["support/settingsonly_production_artifact.rs"]
    {
        return false;
    }

    let imports = entry
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Use(item)
                if use_tree_root_is(&item.tree, "settingsonly_production_artifact") =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [import] = imports.as_slice() else {
        return false;
    };
    !import.attrs.iter().any(is_conditional_attribute)
        && import.to_token_stream().to_string()
            == "use settingsonly_production_artifact :: { EvidenceCase , run_case } ;"
}

fn use_tree_root_is(tree: &syn::UseTree, expected: &str) -> bool {
    matches!(tree, syn::UseTree::Path(path) if path.ident == expected)
}

#[derive(Default)]
struct ProductionRunnerFlow {
    fixture_starts: usize,
    finishes: usize,
    extra_control_flow: bool,
}

impl<'ast> syn::visit::Visit<'ast> for ProductionRunnerFlow {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.fixture_starts += usize::from(expression_path_ends_with(
            node.func.as_ref(),
            &["Fixture", "start"],
        ));
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.finishes += usize::from(node.method == "finish");
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_if(&mut self, _node: &'ast syn::ExprIf) {
        self.extra_control_flow = true;
    }

    fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {
        self.extra_control_flow = true;
    }

    fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {
        self.extra_control_flow = true;
    }

    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
        self.extra_control_flow = true;
    }

    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.extra_control_flow = true;
    }
}

#[derive(Default)]
struct ScenarioFlowVisitor {
    forbidden: bool,
}

impl<'ast> syn::visit::Visit<'ast> for ScenarioFlowVisitor {
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        self.forbidden |= is_conditional_attribute(node);
        syn::visit::visit_attribute(self, node);
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {
        self.forbidden = true;
    }

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {
        self.forbidden = true;
    }

    fn visit_expr_const(&mut self, _node: &'ast syn::ExprConst) {
        self.forbidden = true;
    }

    fn visit_expr_if(&mut self, _node: &'ast syn::ExprIf) {
        self.forbidden = true;
    }

    fn visit_expr_match(&mut self, _node: &'ast syn::ExprMatch) {
        self.forbidden = true;
    }

    fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {
        self.forbidden = true;
    }

    fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {
        self.forbidden = true;
    }

    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
        self.forbidden = true;
    }

    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.forbidden = true;
    }
}

fn path_has_suffix(path: &syn::Path, expected: &[&str]) -> bool {
    let segments = path.segments.iter().collect::<Vec<_>>();
    segments.len() >= expected.len()
        && segments[segments.len() - expected.len()..]
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn dockerignore_includes_contracts(root: &Path) -> Result<bool> {
    let path = root.join(".dockerignore");
    let source =
        std::fs::read_to_string(&path).with_context(|| format!("读取 {} 失败", path.display()))?;
    Ok(!source.lines().map(str::trim).any(|line| {
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            return false;
        }
        let pattern = line.trim_start_matches('/').trim_end_matches('/');
        pattern == "contracts"
            || pattern.starts_with("contracts/")
            || pattern == "**/contracts"
            || pattern.starts_with("**/contracts/")
    }))
}

#[derive(Clone, Copy)]
enum ArtifactContractKind {
    Binary,
    Image,
}

fn image_environment_is_loaded(function: &syn::ItemFn) -> bool {
    let mut visitor = SettingsOnlyImageEnvironmentVisitor::default();
    syn::visit::Visit::visit_block(&mut visitor, &function.block);
    visitor.image_environment
}

#[derive(Default)]
struct SettingsOnlyImageEnvironmentVisitor {
    image_environment: bool,
}

impl<'ast> syn::visit::Visit<'ast> for SettingsOnlyImageEnvironmentVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if expression_path_ends_with(node.func.as_ref(), &["env", "var"])
            && node.args.len() == 1
            && matches!(node.args.first(), Some(syn::Expr::Path(path)) if path.path.is_ident("IMAGE_ENV"))
        {
            self.image_environment = true;
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn expression_path_ends_with(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    let segments = path.path.segments.iter().collect::<Vec<_>>();
    segments.len() >= expected.len()
        && segments[segments.len() - expected.len()..]
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn is_test_attribute(attribute: &syn::Attribute) -> bool {
    let segments = attribute
        .path()
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    matches!(segments.as_slice(), [test] if test == "test")
        || matches!(segments.as_slice(), [runtime, test] if runtime == "tokio" && test == "test")
}

fn is_ignore_attribute(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("ignore")
}

fn is_conditional_attribute(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr")
}

pub(crate) struct DockerStage<'a> {
    pub(crate) base: &'a str,
    pub(crate) name: &'a str,
    pub(crate) instructions: Vec<&'a str>,
}

pub(crate) fn docker_stages(source: &str) -> Vec<DockerStage<'_>> {
    let mut stages = Vec::new();
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(from) = docker_instruction_arguments(line, "FROM") {
            let mut parts = from.split_whitespace();
            let (Some(base), Some(as_keyword), Some(name), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            if !as_keyword.eq_ignore_ascii_case("AS") {
                continue;
            }
            stages.push(DockerStage {
                base,
                name,
                instructions: Vec::new(),
            });
        } else if let Some(stage) = stages.last_mut() {
            stage.instructions.push(line);
        }
    }
    stages
}

pub(crate) fn docker_instruction_arguments<'a>(
    instruction: &'a str,
    expected: &str,
) -> Option<&'a str> {
    let keyword_end = instruction
        .find(char::is_whitespace)
        .unwrap_or(instruction.len());
    let (keyword, arguments) = instruction.split_at(keyword_end);
    keyword
        .eq_ignore_ascii_case(expected)
        .then(|| arguments.trim_start())
}

fn package_is_workspace_domain(
    root: &Path,
    metadata: &CargoMetadata,
    package: &MetadataPackage,
) -> bool {
    workspace_package_layer(root, metadata, package) == Some(crate::layers::Layer::Domain)
}

fn workspace_package_layer(
    root: &Path,
    metadata: &CargoMetadata,
    package: &MetadataPackage,
) -> Option<crate::layers::Layer> {
    if !metadata.workspace_members.contains(&package.id) {
        return None;
    }
    let package_dir = package.manifest_path.parent()?;
    let member_path = package_dir.strip_prefix(root).ok()?;
    crate::layers::classify(&package.name, &member_path.display().to_string())
}

struct CriticalProviderSpec {
    gate: &'static str,
    provider: ProviderConstructor,
    required: fn(&GovernedAssembly) -> bool,
}

fn validate_production_security_closeout(a: ProductionAssembly<'_>, findings: &mut Vec<Finding>) {
    // INVARIANT: SECURITY-PRODUCTION-CLOSEOUT-01 { level = "Medium", exec = "check", source = "code" } —
    // Production security providers follow capabilities actually consumed by the manifest. An
    // Identity domain needs signing; authenticated listeners need OIDC; Settings and DLX key
    // consumers need Vault KeyProvider. Subset assemblies must not add dummy providers merely to
    // satisfy a full-runtime checklist.
    const CRITICAL_PROVIDERS: &[CriticalProviderSpec] =
        &[
            CriticalProviderSpec {
                gate: "oidc-pdp",
                provider: ProviderConstructor::OidcProvider,
                required: |assembly| {
                    assembly.manifest().listeners().iter().any(|listener| {
                        listener.kind != assembly_schema::AssemblyListenerKind::Health
                    })
                },
            },
            CriticalProviderSpec {
                gate: "vault-signer",
                provider: ProviderConstructor::VaultSigner,
                required: |assembly| {
                    assembly
                        .manifest()
                        .domains()
                        .contains(&assembly_schema::AssemblyDomain::Identity)
                },
            },
            CriticalProviderSpec {
                gate: "vault-keyprovider",
                provider: ProviderConstructor::VaultKeyProvider,
                required: |assembly| {
                    assembly
                        .manifest()
                        .domains()
                        .contains(&assembly_schema::AssemblyDomain::Settings)
                        || assembly
                            .manifest()
                            .diport_providers()
                            .iter()
                            .any(|provider| {
                                provider.port == DiportPort::KeyProvider
                                    || matches!(
                                        provider.port,
                                        DiportPort::DlxArchiveStore
                                            | DiportPort::DlxLifecycleRepository
                                    )
                            })
                },
            },
        ];

    for spec in CRITICAL_PROVIDERS {
        if (spec.required)(&a) && !has_active_persistent_backend_provider(&a, spec) {
            findings.push(finding(
                Rule::ProductionSecurityCriticalProvider,
                a.manifest_label(),
                format!(
                    "field=diportProviders profile=production gate={} 必须声明 active persistent `{}` for `{}`，且 {} [dependencies].{} 必须启用 backend feature",
                    spec.gate,
                    spec.provider,
                    spec.provider.port(),
                    a.cargo_label(),
                    spec.provider.provider_crate()
                ),
            ));
        }
    }

    let evidence = security_closeout_evidence_from_sources(a.dir()).unwrap_or_default();
    if !evidence.has_jwks_closeout() {
        findings.push(finding(
            Rule::ProductionSecurityJwksCloseout,
            a.manifest_label(),
            "source=rust-ast-run-reachable profile=production gate=jwks 必须在 run() 或 typed StartupAdapter::prepare 可达路径有 profile-specific JwksKeySource::load_and_watch + typed VerifierConfigBuilder::keys_jwks + verifier managed resource + profile-specific JWKS readiness probe 注册证据",
        ));
    }
    let owns_internal_listener = a
        .manifest()
        .listeners()
        .iter()
        .any(|listener| listener.kind == assembly_schema::AssemblyListenerKind::Internal);
    if owns_internal_listener && !evidence.has_spiffe_closeout() {
        findings.push(finding(
            Rule::ProductionSecuritySpiffeCloseout,
            a.manifest_label(),
            "source=rust-ast-run-reachable profile=production gate=spiffe-mtls 必须在 run() 可达路径有 MtlsServerConfig::from_spire + DomainHttpTransport::from_spire + domain_transport_ready probe 证据，且不得保留 Internal service-token migration env 常量",
        ));
    }
    if owns_internal_listener {
        validate_token_profile_trust_chain(&a, &evidence, findings);
    }
    if a.manifest().name() == "runtime" {
        validate_runtime_egress_tls_closeout(&a, findings);
    }
}

/// Production egress TLS downgrade knobs that must stay banned from the serving catalog (#1710).
const BANNED_EGRESS_TLS_DOWNGRADE_KEYS: &[&str] = &[
    "RSS_AMQP_ALLOW_PLAINTEXT",
    "RSS_REDIS_ALLOW_PLAINTEXT",
    "RSS_S3_ALLOW_PLAINTEXT",
    "RSS_PG_SSL_MODE",
];

#[derive(Debug, Default)]
struct RuntimeEgressTlsCloseoutEvidence {
    forbidden_has_banned: bool,
    fixed_lacks_banned: bool,
    private_ca_checked: bool,
    private_ca_ok: bool,
}

impl RuntimeEgressTlsCloseoutEvidence {
    fn serving_keys_ok(&self) -> bool {
        self.forbidden_has_banned && self.fixed_lacks_banned
    }
}

fn validate_runtime_egress_tls_closeout(a: &GovernedAssembly, findings: &mut Vec<Finding>) {
    let evidence = runtime_egress_tls_closeout_evidence(a.dir()).unwrap_or_default();
    if !evidence.serving_keys_ok() {
        findings.push(finding(
            Rule::ProductionSecurityEgressTlsCloseout,
            a.manifest_label(),
            format!(
                "source=rust-ast-config profile=production gate=egress-tls-serving-keys banned keys {BANNED_EGRESS_TLS_DOWNGRADE_KEYS:?} must appear in FORBIDDEN_SERVING_KEYS and must not appear in FIXED_SERVING_KEYS (ingress RSS_LISTENER_ALLOW_PLAINTEXT remains allowed)"
            ),
        ));
    }
    if evidence.private_ca_checked && !evidence.private_ca_ok {
        findings.push(finding(
            Rule::ProductionSecurityEgressTlsCloseout,
            a.manifest_label(),
            "source=rust-ast-wiring profile=production gate=egress-tls-private-ca runtime Redis/AMQP/S3/PG wiring must reference RedisPrivateCa / AmqpPrivateCa / PrivateCaS3ClientFactory / connect_with_private_ca / VerifyFull+with_ssl_root_cert; comments, strings, and cfg(test) bait are rejected",
        ));
    }
}

fn runtime_egress_tls_closeout_evidence(dir: &Path) -> Result<RuntimeEgressTlsCloseoutEvidence> {
    let config_path = dir.join("src/config.rs");
    let mut evidence = RuntimeEgressTlsCloseoutEvidence::default();
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("read {}", config_path.display()))?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("parse rust source {}", config_path.display()))?;
        let forbidden = const_string_literals(&file, "FORBIDDEN_SERVING_KEYS").unwrap_or_default();
        let fixed = const_string_literals(&file, "FIXED_SERVING_KEYS").unwrap_or_default();
        evidence.forbidden_has_banned = BANNED_EGRESS_TLS_DOWNGRADE_KEYS
            .iter()
            .all(|key| forbidden.contains(*key));
        evidence.fixed_lacks_banned = BANNED_EGRESS_TLS_DOWNGRADE_KEYS
            .iter()
            .all(|key| !fixed.contains(*key));
    }

    let wiring_checks: &[(&str, &[&str])] = &[
        (
            "src/infra/redis.rs",
            &["RedisPrivateCa", "connect_with_private_ca"],
        ),
        ("src/infra/s3.rs", &["PrivateCaS3ClientFactory"]),
        (
            "src/event_transport.rs",
            &["AmqpPrivateCa", "connect_with_private_ca"],
        ),
        ("src/infra/pg.rs", &["VerifyFull", "with_ssl_root_cert"]),
    ];
    let mut private_ca_ok = true;
    for (rel, required) in wiring_checks {
        let path = dir.join(rel);
        if !path.exists() {
            continue;
        }
        evidence.private_ca_checked = true;
        let content =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if !production_source_has_all(&content, required) {
            private_ca_ok = false;
        }
    }
    evidence.private_ca_ok = private_ca_ok;
    Ok(evidence)
}

fn const_string_literals(file: &syn::File, name: &str) -> Option<BTreeSet<String>> {
    let matches = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Const(item)
                if item.ident == name && !has_test_or_test_support_cfg(&item.attrs) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [item] = matches.as_slice() else {
        return None;
    };
    let mut literals = BTreeSet::new();
    struct LitCollector<'a>(&'a mut BTreeSet<String>);
    impl<'ast> syn::visit::Visit<'ast> for LitCollector<'_> {
        fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
            self.0.insert(lit.value());
        }
    }
    syn::visit::Visit::visit_expr(&mut LitCollector(&mut literals), &item.expr);
    Some(literals)
}

/// Plaintext egress funnel symbols banned alongside private-CA evidence (#1710 / PR #642 F3).
/// Presence of these in non-test production items fails the private-CA closeout even when the
/// required private-CA identifiers also appear (dead-module bait + plaintext coexistence).
const BANNED_EGRESS_PLAINTEXT_FUNNELS: &[&str] = &["connect_allow_plaintext"];

fn production_source_has_all(source: &str, required: &[&str]) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let mut tokens = String::new();
    for item in &file.items {
        if item_attrs(item).is_some_and(has_test_or_test_support_cfg) {
            continue;
        }
        tokens.push_str(&strip_string_literals(&item.to_token_stream().to_string()));
    }
    let compact: String = tokens.split_whitespace().collect();
    if BANNED_EGRESS_PLAINTEXT_FUNNELS
        .iter()
        .any(|banned| compact.contains(banned))
    {
        return false;
    }
    required.iter().all(|needle| compact.contains(needle))
}

fn validate_token_profile_trust_chain(
    a: &GovernedAssembly,
    evidence: &SecurityCloseoutEvidence,
    findings: &mut Vec<Finding>,
) {
    // INVARIANT: TOKEN-PROFILE-ASSEMBLY-01 { level = "Medium", exec = "check", source = "code" } —
    // typed construction alone does not prove that all three exclusive profiles are reachable from
    // the production entrypoint. This gate consumes AST facts only from the free `run()` call graph;
    // comments, strings, dead helpers, and cfg(test) modules cannot satisfy it.
    let mut missing = Vec::new();
    for (present, fact) in [
        (
            evidence.rss_access_provider_build,
            "build_rss_access_provider",
        ),
        (
            evidence.federated_access_provider_build,
            "build_federated_access_provider",
        ),
        (
            evidence.service_token_provider_build,
            "build_service_token_provider",
        ),
        (evidence.rss_access_binding, "ProfileBinding::RssAccess"),
        (
            evidence.federated_access_binding,
            "ProfileBinding::FederatedAccess",
        ),
        (
            evidence.service_token_binding,
            "ProfileBinding::ServiceToken",
        ),
        (
            evidence.rss_access_jwks_probe,
            "AccessTokenJwksReadyProbe::rss_access",
        ),
        (
            evidence.federated_access_jwks_probe,
            "AccessTokenJwksReadyProbe::federated_access",
        ),
        (
            evidence.rss_access_probe_name,
            "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
        ),
        (
            evidence.federated_access_probe_name,
            "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
        ),
        (
            evidence.rss_access_resource_name,
            "RSS_ACCESS_TOKEN_RESOURCE_NAME",
        ),
        (
            evidence.federated_access_resource_name,
            "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME",
        ),
        (
            evidence.profile_managed_resource_calls >= 3,
            "three profile managed_resource registrations",
        ),
        (
            evidence.rss_access_reaches_verify_bridge(),
            "ProfileBinding::RssAccess -> apply_verify_bridge",
        ),
        (
            evidence.federated_access_reaches_verify_bridge(),
            "ProfileBinding::FederatedAccess -> apply_verify_bridge",
        ),
        (
            evidence.service_token_reaches_verify_bridge(),
            "ProfileBinding::ServiceToken -> apply_verify_bridge",
        ),
    ] {
        if !present {
            missing.push(fact);
        }
    }
    if !missing.is_empty() {
        findings.push(finding(
            Rule::TokenProfileTrustChain,
            a.manifest_label(),
            format!(
                "source=rust-ast-run-reachable profile=production token profile trust chain incomplete; missing={missing:?}"
            ),
        ));
    }
    if evidence.legacy_token_surface {
        findings.push(finding(
            Rule::TokenProfileLegacySurface,
            a.manifest_label(),
            "source=production-rust legacy/generic token env, shared OIDC provider/probe, or old collapse helper is forbidden",
        ));
    }
    if evidence.mixed_key_provider {
        findings.push(finding(
            Rule::TokenProfileKeyIsolation,
            a.manifest_label(),
            "source=rust-ast production assembly must not use generic StaticKeySource, `.keys(...)`, or combine ES256 and HS256 key APIs",
        ));
    }
    if evidence.split_scheme_provider_binding {
        findings.push(finding(
            Rule::TokenProfileBinding,
            a.manifest_label(),
            "source=rust-ast provider and scheme/profile must be carried by one ProfileBinding; apply_verify_bridge accepts exactly (routes, binding)",
        ));
    }
}

fn has_active_persistent_backend_provider(
    a: &GovernedAssembly,
    spec: &CriticalProviderSpec,
) -> bool {
    a.manifest().diport_providers().iter().any(|provider| {
        provider.lifecycle == ProviderLifecycle::Active
            && provider.durability == ProviderDurability::Persistent
            && provider.port == spec.provider.port()
            && provider.provider == spec.provider
            && provider.provider_crate == spec.provider.provider_crate()
            && dependency_features(a.cargo_toml(), spec.provider.provider_crate())
                .is_some_and(|features| features.contains("backend"))
    })
}

fn is_active_distributed_provider(provider: &DiportProvider) -> bool {
    provider.lifecycle == ProviderLifecycle::Active
        && provider.consumer == ProviderConsumer::Distributed
        && matches!(provider.port, DiportPort::Lock | DiportPort::Cas)
}

fn has_distributed_consumer_evidence(a: &GovernedAssembly) -> bool {
    distributed_consumer_evidence_from_sources(a.dir()).unwrap_or(false)
}

fn distributed_consumer_evidence_from_sources(dir: &Path) -> Result<bool> {
    let path = dir.join("src/phase/domains.rs");
    if !path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&path)?;
    let file = syn::parse_file(&content)
        .with_context(|| format!("parse rust source {}", path.display()))?;
    Ok(file_has_distributed_consumer_evidence(&file))
}

fn collect_rust_sources(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_sources(&path, files)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn external_module_is_explicit_test_only(source_root: &Path, path: &Path) -> Result<bool> {
    let relative = path.strip_prefix(source_root).unwrap_or(path);
    let Some(module_name) = relative.file_stem().and_then(|stem| stem.to_str()) else {
        return Ok(false);
    };
    if matches!(module_name, "lib" | "main" | "mod") {
        return Ok(false);
    }
    let parent = path.parent().unwrap_or(source_root);
    let mut owners = if parent == source_root {
        vec![source_root.join("lib.rs"), source_root.join("main.rs")]
    } else {
        vec![parent.with_extension("rs"), parent.join("mod.rs")]
    };
    owners.retain(|owner| owner.is_file());
    let mut declarations = Vec::new();
    for owner in owners {
        let source = std::fs::read_to_string(&owner)?;
        let file = syn::parse_file(&source)
            .with_context(|| format!("parse module owner {}", owner.display()))?;
        declarations.extend(file.items.into_iter().filter_map(|item| {
            let syn::Item::Mod(module) = item else {
                return None;
            };
            (module.ident == module_name && module.content.is_none())
                .then(|| has_test_or_test_support_cfg(&module.attrs))
        }));
    }
    Ok(!declarations.is_empty() && declarations.into_iter().all(|test_only| test_only))
}

fn file_has_distributed_consumer_evidence(file: &syn::File) -> bool {
    let methods = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if has_cfg_test(&implementation.attrs)
                || implementation.trait_.is_some()
                || !matches!(
                    implementation.self_ty.as_ref(),
                    syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment| segment.ident == "InfraBuilt")
                )
            {
                return None;
            }
            Some(implementation)
        })
        .flat_map(|implementation| &implementation.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method)
                if method.sig.ident == "wire_domains"
                    && method.sig.asyncness.is_some()
                    && !has_cfg_test(&method.attrs) =>
            {
                Some(method)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        return false;
    };
    let phase_bodies = method
        .block
        .stmts
        .iter()
        .filter_map(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let binding = local_binding_ident(&local.pat)?;
            let init = local.init.as_ref()?;
            let syn::Expr::Await(awaited) = init.expr.as_ref() else {
                return None;
            };
            let syn::Expr::Async(body) = awaited.base.as_ref() else {
                return None;
            };
            (binding == "result").then_some(&body.block)
        })
        .collect::<Vec<_>>();
    let [body] = phase_bodies.as_slice() else {
        return false;
    };

    let producers = body
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let binding = local_binding_ident(&local.pat)?;
            let init = local.init.as_ref()?;
            terminal_path_call(
                &init.expr,
                &["crate", "distributed_runtime", "wire_distributed"],
            )
            .is_some()
            .then_some((index, binding.to_string()))
        })
        .collect::<Vec<_>>();
    let [(producer_index, binding)] = producers.as_slice() else {
        return false;
    };
    let consumers = body
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let init = local.init.as_ref()?;
            let call = terminal_path_call(
                &init.expr,
                &["crate", "event_transport", "wire_event_transport"],
            )?;
            call.args
                .iter()
                .nth(1)
                .is_some_and(|argument| {
                    matches!(
                        argument,
                        syn::Expr::Path(path)
                            if path.path.get_ident().is_some_and(|ident| ident == binding)
                    )
                })
                .then_some(index)
        })
        .collect::<Vec<_>>();
    matches!(consumers.as_slice(), [consumer_index] if consumer_index > producer_index)
}

fn local_binding_ident(pat: &syn::Pat) -> Option<&syn::Ident> {
    match pat {
        syn::Pat::Ident(pat) => Some(&pat.ident),
        syn::Pat::Type(pat) => local_binding_ident(&pat.pat),
        _ => None,
    }
}

fn terminal_path_call<'a>(expr: &'a syn::Expr, expected: &[&str]) -> Option<&'a syn::ExprCall> {
    match expr {
        syn::Expr::Call(call) if expr_path_is_exact(&call.func, expected) => Some(call),
        syn::Expr::Await(awaited) => terminal_path_call(&awaited.base, expected),
        syn::Expr::Try(propagated) => terminal_path_call(&propagated.expr, expected),
        syn::Expr::Paren(paren) => terminal_path_call(&paren.expr, expected),
        syn::Expr::Group(group) => terminal_path_call(&group.expr, expected),
        syn::Expr::MethodCall(method)
            if matches!(
                method.method.to_string().as_str(),
                "context" | "with_context"
            ) && method.args.len() == 1 =>
        {
            terminal_path_call(&method.receiver, expected)
        }
        _ => None,
    }
}

fn expr_path_is_exact(expr: &syn::Expr, expected: &[&str]) -> bool {
    matches!(
        expr,
        syn::Expr::Path(path)
            if path.qself.is_none()
                && path.path.leading_colon.is_none()
                && path.path.segments.len() == expected.len()
                && path.path.segments.iter().zip(expected).all(|(segment, expected)| {
                    segment.ident == *expected
                        && matches!(segment.arguments, syn::PathArguments::None)
                })
    )
}

#[derive(Clone, Default)]
struct SecurityCloseoutEvidence {
    runtime_oidc_provider_build: bool,
    runtime_oidc_provider_handle: bool,
    runtime_oidc_managed_resource: bool,
    jwks_load_and_watch: bool,
    jwks_keys_jwks: bool,
    jwks_ready_probe: bool,
    jwks_probe_registered: bool,
    mtls_server_from_spire: bool,
    domain_transport_from_spire: bool,
    domain_transport_ready_probe: bool,
    legacy_service_token_migration: bool,
    rss_access_provider_build: bool,
    federated_access_provider_build: bool,
    service_token_provider_build: bool,
    rss_access_binding: bool,
    federated_access_binding: bool,
    service_token_binding: bool,
    rss_access_jwks_probe: bool,
    federated_access_jwks_probe: bool,
    rss_access_probe_name: bool,
    federated_access_probe_name: bool,
    rss_access_resource_name: bool,
    federated_access_resource_name: bool,
    service_token_resource_name: bool,
    profile_managed_resource_calls: usize,
    rss_access_bound_to_verify_bridge: bool,
    federated_access_bound_to_verify_bridge: bool,
    service_token_bound_to_verify_bridge: bool,
    rss_access_packed_in_profile_carrier: bool,
    federated_access_packed_in_profile_carrier: bool,
    service_token_packed_in_profile_carrier: bool,
    typed_primary_access_binding_carrier_call: bool,
    typed_admin_access_binding_carrier_call: bool,
    typed_service_binding_carrier_call: bool,
    exact_profile_binding_mapping: bool,
    profile_carrier_bound_to_verify_bridge: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
}

impl SecurityCloseoutEvidence {
    fn merge(&mut self, other: Self) {
        self.runtime_oidc_provider_build |= other.runtime_oidc_provider_build;
        self.runtime_oidc_provider_handle |= other.runtime_oidc_provider_handle;
        self.runtime_oidc_managed_resource |= other.runtime_oidc_managed_resource;
        self.jwks_load_and_watch |= other.jwks_load_and_watch;
        self.jwks_keys_jwks |= other.jwks_keys_jwks;
        self.jwks_ready_probe |= other.jwks_ready_probe;
        self.jwks_probe_registered |= other.jwks_probe_registered;
        self.mtls_server_from_spire |= other.mtls_server_from_spire;
        self.domain_transport_from_spire |= other.domain_transport_from_spire;
        self.domain_transport_ready_probe |= other.domain_transport_ready_probe;
        self.legacy_service_token_migration |= other.legacy_service_token_migration;
        self.rss_access_provider_build |= other.rss_access_provider_build;
        self.federated_access_provider_build |= other.federated_access_provider_build;
        self.service_token_provider_build |= other.service_token_provider_build;
        self.rss_access_binding |= other.rss_access_binding;
        self.federated_access_binding |= other.federated_access_binding;
        self.service_token_binding |= other.service_token_binding;
        self.rss_access_jwks_probe |= other.rss_access_jwks_probe;
        self.federated_access_jwks_probe |= other.federated_access_jwks_probe;
        self.rss_access_probe_name |= other.rss_access_probe_name;
        self.federated_access_probe_name |= other.federated_access_probe_name;
        self.rss_access_resource_name |= other.rss_access_resource_name;
        self.federated_access_resource_name |= other.federated_access_resource_name;
        self.service_token_resource_name |= other.service_token_resource_name;
        self.profile_managed_resource_calls = self
            .profile_managed_resource_calls
            .saturating_add(other.profile_managed_resource_calls);
        self.rss_access_bound_to_verify_bridge |= other.rss_access_bound_to_verify_bridge;
        self.federated_access_bound_to_verify_bridge |=
            other.federated_access_bound_to_verify_bridge;
        self.service_token_bound_to_verify_bridge |= other.service_token_bound_to_verify_bridge;
        self.rss_access_packed_in_profile_carrier |= other.rss_access_packed_in_profile_carrier;
        self.federated_access_packed_in_profile_carrier |=
            other.federated_access_packed_in_profile_carrier;
        self.service_token_packed_in_profile_carrier |=
            other.service_token_packed_in_profile_carrier;
        self.typed_primary_access_binding_carrier_call |=
            other.typed_primary_access_binding_carrier_call;
        self.typed_admin_access_binding_carrier_call |=
            other.typed_admin_access_binding_carrier_call;
        self.typed_service_binding_carrier_call |= other.typed_service_binding_carrier_call;
        self.exact_profile_binding_mapping |= other.exact_profile_binding_mapping;
        self.profile_carrier_bound_to_verify_bridge |= other.profile_carrier_bound_to_verify_bridge;
        self.legacy_token_surface |= other.legacy_token_surface;
        self.mixed_key_provider |= other.mixed_key_provider;
        self.split_scheme_provider_binding |= other.split_scheme_provider_binding;
    }

    fn has_jwks_closeout(&self) -> bool {
        self.runtime_oidc_provider_build
            && self.runtime_oidc_provider_handle
            && self.runtime_oidc_managed_resource
            && self.jwks_load_and_watch
            && self.jwks_keys_jwks
            && self.jwks_ready_probe
            && self.jwks_probe_registered
    }

    fn has_spiffe_closeout(&self) -> bool {
        self.mtls_server_from_spire
            && self.domain_transport_from_spire
            && self.domain_transport_ready_probe
            && !self.legacy_service_token_migration
    }

    fn rss_access_reaches_verify_bridge(&self) -> bool {
        self.rss_access_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.rss_access_packed_in_profile_carrier
                    || (self.typed_primary_access_binding_carrier_call
                        && self.typed_admin_access_binding_carrier_call
                        && self.exact_profile_binding_mapping)))
    }

    fn federated_access_reaches_verify_bridge(&self) -> bool {
        self.federated_access_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.federated_access_packed_in_profile_carrier
                    || (self.typed_primary_access_binding_carrier_call
                        && self.typed_admin_access_binding_carrier_call
                        && self.exact_profile_binding_mapping)))
    }

    fn service_token_reaches_verify_bridge(&self) -> bool {
        self.service_token_bound_to_verify_bridge
            || (self.profile_carrier_bound_to_verify_bridge
                && (self.service_token_packed_in_profile_carrier
                    || (self.typed_service_binding_carrier_call
                        && self.exact_profile_binding_mapping)))
    }
}

fn security_closeout_evidence_from_sources(dir: &Path) -> Result<SecurityCloseoutEvidence> {
    let src_dir = dir.join("src");
    if !src_dir.exists() {
        return Ok(SecurityCloseoutEvidence::default());
    }
    let mut files = Vec::new();
    collect_rust_sources(&src_dir, &mut files)?;
    files.sort();
    let mut program = SecurityCloseoutProgram::default();
    for path in files {
        let content = std::fs::read_to_string(&path)?;
        let file = syn::parse_file(&content)
            .with_context(|| format!("parse rust source {}", path.display()))?;
        let mut file_program = file_security_closeout_program(&file);
        file_program.legacy_token_surface |= source_contains_legacy_token_surface(&content);
        program.merge(file_program);
    }
    Ok(program.reachable_evidence_from_run())
}

fn source_contains_legacy_token_surface(source: &str) -> bool {
    // Intentionally scan raw source rather than string literals alone: the destructive migration
    // requires the old vocabulary to disappear, and comments/cfg(test) must not preserve bait that
    // makes grep-based reviews ambiguous.
    const FORBIDDEN_SUBSTRINGS: &[&str] = &["RSS_JWT_", "RSS_OIDC_", "AssembledListener::plain"];
    const FORBIDDEN_IDENTIFIERS: &[&str] = &[
        "OIDC_JWKS_READY_PROBE_NAME",
        "oidc_jwks_ready",
        "OidcJwksReadyProbe",
        "RuntimeOidcProvider",
        "PreparedRuntimeOidcProvider",
        "build_runtime_oidc_provider",
        "required_scheme_for_auth_scheme",
        "RouteAssemblyContext",
        "assemble_authed_routers_from_values",
        "assemble_authed_routers",
        "health_listener",
        "health_auth_scheme",
    ];
    FORBIDDEN_SUBSTRINGS
        .iter()
        .any(|needle| source.contains(needle))
        || FORBIDDEN_IDENTIFIERS
            .iter()
            .any(|identifier| source_contains_exact_rust_identifier(source, identifier))
}

fn source_contains_exact_rust_identifier(source: &str, identifier: &str) -> bool {
    source.match_indices(identifier).any(|(start, matched)| {
        let before = source[..start].chars().next_back();
        let after = source[start + matched.len()..].chars().next();
        before.is_none_or(|ch| !is_rust_identifier_continue(ch))
            && after.is_none_or(|ch| !is_rust_identifier_continue(ch))
    })
}

fn is_rust_identifier_continue(ch: char) -> bool {
    ch == '_'
        || ch.is_ascii_alphanumeric()
        || (!ch.is_ascii() && syn::parse_str::<syn::Ident>(&format!("a{ch}")).is_ok())
}

#[derive(Default)]
struct SecurityCloseoutProgram {
    functions: BTreeMap<String, SecurityFunctionEvidence>,
    startup_adapter_roots: BTreeSet<String>,
    profile_binding_definitions: usize,
    exact_profile_binding_definitions: usize,
    legacy_service_token_migration: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
}

impl SecurityCloseoutProgram {
    fn merge(&mut self, other: Self) {
        self.profile_binding_definitions = self
            .profile_binding_definitions
            .saturating_add(other.profile_binding_definitions);
        self.exact_profile_binding_definitions = self
            .exact_profile_binding_definitions
            .saturating_add(other.exact_profile_binding_definitions);
        self.legacy_service_token_migration |= other.legacy_service_token_migration;
        self.legacy_token_surface |= other.legacy_token_surface;
        self.mixed_key_provider |= other.mixed_key_provider;
        self.split_scheme_provider_binding |= other.split_scheme_provider_binding;
        self.startup_adapter_roots
            .extend(other.startup_adapter_roots);
        for (name, info) in other.functions {
            self.functions.entry(name).or_default().merge(info);
        }
    }

    fn reachable_evidence_from_run(&self) -> SecurityCloseoutEvidence {
        let mut out = SecurityCloseoutEvidence {
            legacy_service_token_migration: self.legacy_service_token_migration,
            legacy_token_surface: self.legacy_token_surface,
            mixed_key_provider: self.mixed_key_provider,
            split_scheme_provider_binding: self.split_scheme_provider_binding,
            ..SecurityCloseoutEvidence::default()
        };
        let mut seen = BTreeSet::new();
        let mut stack = vec!["free::run".to_string()];
        stack.extend(self.startup_adapter_roots.iter().cloned());
        while let Some(name) = stack.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(info) = self.functions.get(&name) else {
                continue;
            };
            out.merge(info.evidence.clone());
            stack.extend(info.calls.iter().cloned());
        }
        out.exact_profile_binding_mapping =
            self.profile_binding_definitions == 1 && self.exact_profile_binding_definitions == 1;
        out.legacy_service_token_migration = self.legacy_service_token_migration;
        out.legacy_token_surface = self.legacy_token_surface;
        out.mixed_key_provider = self.mixed_key_provider;
        out.split_scheme_provider_binding = self.split_scheme_provider_binding;
        out
    }
}

#[derive(Clone, Default)]
struct SecurityFunctionEvidence {
    evidence: SecurityCloseoutEvidence,
    calls: BTreeSet<String>,
}

impl SecurityFunctionEvidence {
    fn merge(&mut self, other: Self) {
        self.evidence.merge(other.evidence);
        self.calls.extend(other.calls);
    }
}

fn file_security_closeout_program(file: &syn::File) -> SecurityCloseoutProgram {
    let mut visitor = SecurityCloseoutVisitor::default();
    syn::visit::Visit::visit_file(&mut visitor, file);
    visitor.program
}

#[derive(Default)]
struct SecurityCloseoutVisitor {
    program: SecurityCloseoutProgram,
    function_stack: Vec<String>,
    impl_stack: Vec<String>,
    function_key_apis: Vec<(bool, bool)>,
    profile_binding_locals: Vec<BTreeMap<String, TokenProfileBridgeKind>>,
    profile_carrier_bindings: Vec<BTreeSet<String>>,
    typed_token_provider_bindings: Vec<BTreeSet<String>>,
    typed_listener_spec_bindings: Vec<BTreeSet<String>>,
    plan_auth_scheme_locals: Vec<BTreeSet<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TokenProfileBridgeKind {
    RssAccess,
    FederatedAccess,
    ServiceToken,
}

impl<'ast> syn::visit::Visit<'ast> for SecurityCloseoutVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        self.function_stack
            .push(format!("free::{}", node.sig.ident));
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        syn::visit::visit_item_fn(self, node);
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.function_stack.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        let owner = match node.self_ty.as_ref() {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        };
        if let Some(owner) = owner {
            let is_startup_adapter = node.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments.last().is_some_and(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "StartupAdapter" | "LaunchAdapter"
                    )
                })
            });
            if is_startup_adapter
                && node.items.iter().any(|item| {
                    matches!(item, syn::ImplItem::Fn(function) if function.sig.ident == "prepare")
                })
            {
                self.program
                    .startup_adapter_roots
                    .insert(format!("{owner}::prepare"));
            }
            self.impl_stack.push(owner);
            syn::visit::visit_item_impl(self, node);
            self.impl_stack.pop();
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        let Some(owner) = self.impl_stack.last().cloned() else {
            return;
        };
        if owner == "TokenProviderBindings" {
            match node.sig.ident.to_string().as_str() {
                "profile_binding" => {
                    self.program.profile_binding_definitions =
                        self.program.profile_binding_definitions.saturating_add(1);
                    if exact_profile_binding_definition(node) {
                        self.program.exact_profile_binding_definitions = self
                            .program
                            .exact_profile_binding_definitions
                            .saturating_add(1);
                    }
                }
                "access_binding" => {
                    self.program.legacy_token_surface = true;
                }
                "service_binding" => {
                    self.program.legacy_token_surface = true;
                }
                _ => {}
            }
        }
        self.function_stack
            .push(format!("{owner}::{}", node.sig.ident));
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        syn::visit::visit_impl_item_fn(self, node);
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.function_stack.pop();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        if ident_contains(&node.ident, "INTERNAL_SERVICE_TOKEN_MIGRATION") {
            self.program.legacy_service_token_migration = true;
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(call) = call_path_last_segment(node.func.as_ref()) {
            if let Some(identity) = self.path_call_identity(node.func.as_ref()) {
                self.record_call(&identity);
            }
            if call == "Token"
                && call_path_contains_segment(node.func.as_ref(), "ListenerAuthBinding")
                && node.args.len() == 1
                && let Some(binding) = node.args.first()
            {
                self.record_profile_carrier_input(binding);
            }
            if call == "build_runtime_oidc_provider" {
                self.record_evidence(|e| e.runtime_oidc_provider_build = true);
            }
            match call.as_str() {
                "build_rss_access_provider" => {
                    self.record_evidence(|e| {
                        e.runtime_oidc_provider_build = true;
                        e.rss_access_provider_build = true;
                    });
                }
                "build_federated_access_provider" => {
                    self.record_evidence(|e| {
                        e.runtime_oidc_provider_build = true;
                        e.federated_access_provider_build = true;
                    });
                }
                "build_service_token_provider" => {
                    self.record_evidence(|e| e.service_token_provider_build = true);
                }
                "apply_verify_bridge" => {
                    if node.args.len() == 2 {
                        if let Some(binding) = node.args.iter().nth(1) {
                            self.record_profile_bridge(binding);
                        }
                    } else {
                        self.program.split_scheme_provider_binding = true;
                    }
                }
                _ => {}
            }
        }
        if call_path_ends_with(node.func.as_ref(), "load_and_watch")
            && call_path_contains_segment(node.func.as_ref(), "JwksKeySource")
        {
            self.record_evidence(|e| e.jwks_load_and_watch = true);
        }
        if call_path_ends_with(node.func.as_ref(), "new")
            && call_path_contains_segment(node.func.as_ref(), "OidcJwksReadyProbe")
        {
            self.record_evidence(|e| e.jwks_ready_probe = true);
        }
        if call_path_ends_with(node.func.as_ref(), "rss_access")
            && call_path_contains_segment(node.func.as_ref(), "AccessTokenJwksReadyProbe")
        {
            self.record_evidence(|e| {
                e.jwks_ready_probe = true;
                e.rss_access_jwks_probe = true;
            });
        }
        if call_path_ends_with(node.func.as_ref(), "federated_access")
            && call_path_contains_segment(node.func.as_ref(), "AccessTokenJwksReadyProbe")
        {
            self.record_evidence(|e| {
                e.jwks_ready_probe = true;
                e.federated_access_jwks_probe = true;
            });
        }
        if call_path_ends_with(node.func.as_ref(), "from_spire")
            && call_path_contains_segment(node.func.as_ref(), "MtlsServerConfig")
        {
            self.record_evidence(|e| e.mtls_server_from_spire = true);
        }
        if call_path_ends_with(node.func.as_ref(), "from_spire")
            && call_path_contains_segment(node.func.as_ref(), "DomainHttpTransport")
        {
            self.record_evidence(|e| e.domain_transport_from_spire = true);
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        let local_binding = match (&node.pat, &node.init) {
            (syn::Pat::Ident(pattern), Some(init)) => self
                .profile_binding_kind(init.expr.as_ref())
                .map(|kind| (pattern.ident.to_string(), kind)),
            _ => None,
        };
        if let (Some(locals), Some((name, kind))) =
            (self.profile_binding_locals.last_mut(), local_binding)
        {
            locals.insert(name, kind);
        }
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init)
            && let syn::Expr::MethodCall(call) = ungroup_profile_expression(init.expr.as_ref())
            && call.method == "auth_scheme"
            && call.args.is_empty()
            && let Some(receiver) =
                simple_path_ident(ungroup_profile_expression(call.receiver.as_ref()))
            && self
                .typed_listener_spec_bindings
                .last()
                .is_some_and(|bindings| bindings.contains(&receiver))
            && let Some(locals) = self.plan_auth_scheme_locals.last_mut()
        {
            locals.insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let carrier = profile_carrier_binding(&node.pat);
        if let Some(binding) = carrier.as_ref() {
            self.profile_carrier_bindings
                .push(BTreeSet::from([binding.clone()]));
        }
        syn::visit::visit_arm(self, node);
        if carrier.is_some() {
            self.profile_carrier_bindings.pop();
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let phase_owner = match method.as_str() {
            "build_providers" => Some("Planned"),
            "build_infra" => Some("ProvidersBuilt"),
            "wire_domains" => Some("InfraBuilt"),
            "finalize" => Some("DomainsWired"),
            "launch" => Some("Finalized"),
            _ => None,
        };
        if let Some(owner) = phase_owner {
            self.record_call(&format!("{owner}::{method}"));
        } else if let Some(owner) = self.method_receiver_owner(&node.receiver) {
            self.record_call(&format!("{owner}::{method}"));
        }
        if node.method == "keys_jwks" {
            self.record_evidence(|e| e.jwks_keys_jwks = true);
            self.record_key_api(true, false);
        }
        if node.method == "keys_static" || node.method == "add_es256_sec1" {
            self.record_key_api(true, false);
        }
        if node.method == "keys_hs256" || node.method == "add_hs256_secret" {
            self.record_key_api(false, true);
        }
        if node.method == "keys" && !node.args.is_empty() {
            self.program.mixed_key_provider = true;
        }
        if node.method == "provider" {
            self.record_evidence(|e| e.runtime_oidc_provider_handle = true);
        }
        if node.method == "managed_resource" {
            self.record_evidence(|e| {
                e.runtime_oidc_managed_resource = true;
                e.profile_managed_resource_calls =
                    e.profile_managed_resource_calls.saturating_add(1);
            });
        }
        if node.method == "probe" {
            self.record_evidence(|e| e.jwks_probe_registered = true);
        }
        if node.method == "profile_binding"
            && self.receiver_is_typed_token_provider(node.receiver.as_ref())
        {
            self.record_call("TokenProviderBindings::profile_binding");
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if path_contains_segment(&node.path, "DOMAIN_TRANSPORT_READY_PROBE_NAME") {
            self.record_evidence(|e| e.domain_transport_ready_probe = true);
        }
        if path_contains_segment(&node.path, "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME") {
            self.record_evidence(|e| e.rss_access_probe_name = true);
        }
        if path_contains_segment(&node.path, "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME") {
            self.record_evidence(|e| e.federated_access_probe_name = true);
        }
        if path_contains_segment(&node.path, "RSS_ACCESS_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.rss_access_resource_name = true);
        }
        if path_contains_segment(&node.path, "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.federated_access_resource_name = true);
        }
        if path_contains_segment(&node.path, "SERVICE_TOKEN_RESOURCE_NAME") {
            self.record_evidence(|e| e.service_token_resource_name = true);
        }
        if path_ends_with(&node.path, "RssAccess")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.rss_access_binding = true);
        }
        if path_ends_with(&node.path, "FederatedAccess")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.federated_access_binding = true);
        }
        if path_ends_with(&node.path, "ServiceToken")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.service_token_binding = true);
        }
        if path_contains_segment(&node.path, "StaticKeySource") {
            self.program.mixed_key_provider = true;
        }
        if path_contains_segment_matching(&node.path, |segment| {
            segment.contains("INTERNAL_SERVICE_TOKEN_MIGRATION")
        }) {
            self.program.legacy_service_token_migration = true;
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if path_ends_with(&node.path, "RssAccess")
            && path_contains_segment(&node.path, "ProfileBinding")
        {
            self.record_evidence(|e| e.rss_access_binding = true);
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
        for segment in &node.path.segments {
            if segment.ident == "RouteAssemblyContext" {
                self.program.legacy_token_surface = true;
            }
            if segment.ident == "StaticKeySource" {
                self.program.mixed_key_provider = true;
            }
            if segment.ident == "OidcProvider"
                && matches!(segment.arguments, syn::PathArguments::None)
            {
                self.program.split_scheme_provider_binding = true;
            }
        }
        syn::visit::visit_type_path(self, node);
    }
}

impl SecurityCloseoutVisitor {
    fn current_function(&self) -> Option<&str> {
        self.function_stack.last().map(String::as_str)
    }

    fn current_info_mut(&mut self) -> Option<&mut SecurityFunctionEvidence> {
        let name = self.current_function()?.to_owned();
        Some(self.program.functions.entry(name).or_default())
    }

    fn record_call(&mut self, call: &str) {
        if let Some(info) = self.current_info_mut() {
            info.calls.insert(call.to_owned());
        }
    }

    fn record_evidence(&mut self, f: impl FnOnce(&mut SecurityCloseoutEvidence)) {
        if let Some(info) = self.current_info_mut() {
            f(&mut info.evidence);
        }
    }

    fn record_profile_bridge(&mut self, binding: &syn::Expr) {
        if let Some(kind) = self.profile_binding_kind(binding) {
            self.record_evidence(|evidence| match kind {
                TokenProfileBridgeKind::RssAccess => {
                    evidence.rss_access_bound_to_verify_bridge = true;
                }
                TokenProfileBridgeKind::FederatedAccess => {
                    evidence.federated_access_bound_to_verify_bridge = true;
                }
                TokenProfileBridgeKind::ServiceToken => {
                    evidence.service_token_bound_to_verify_bridge = true;
                }
            });
            return;
        }

        let Some(name) = simple_path_ident(binding) else {
            return;
        };
        if self
            .profile_carrier_bindings
            .iter()
            .rev()
            .any(|bindings| bindings.contains(&name))
        {
            // `ListenerAuthBinding::Token(profile)` is a closed carrier whose payload type is
            // `ProfileBinding`. The match arm moves that exact payload into the only token verify
            // bridge, so every exhaustive ProfileBinding variant that reaches the carrier has a
            // binding→bridge path.
            self.record_evidence(|evidence| {
                evidence.profile_carrier_bound_to_verify_bridge = true;
            });
        }
    }

    fn record_profile_carrier_input(&mut self, binding: &syn::Expr) {
        let binding = ungroup_profile_expression(binding);
        if let Some(kind) = self.profile_binding_kind(binding) {
            self.record_evidence(|evidence| match kind {
                TokenProfileBridgeKind::RssAccess => {
                    evidence.rss_access_packed_in_profile_carrier = true;
                }
                TokenProfileBridgeKind::FederatedAccess => {
                    evidence.federated_access_packed_in_profile_carrier = true;
                }
                TokenProfileBridgeKind::ServiceToken => {
                    evidence.service_token_packed_in_profile_carrier = true;
                }
            });
            return;
        }
        let syn::Expr::MethodCall(call) = binding else {
            return;
        };
        if !self.receiver_is_typed_token_provider(call.receiver.as_ref()) {
            return;
        }
        match call.method.to_string().as_str() {
            "profile_binding" if call.args.len() == 1 => {
                let plan_auth = call
                    .args
                    .first()
                    .and_then(|argument| simple_path_ident(ungroup_profile_expression(argument)))
                    .is_some_and(|name| {
                        self.plan_auth_scheme_locals
                            .last()
                            .is_some_and(|locals| locals.contains(&name))
                    });
                self.record_evidence(|evidence| {
                    evidence.typed_primary_access_binding_carrier_call |= plan_auth;
                    evidence.typed_admin_access_binding_carrier_call |= plan_auth;
                    evidence.typed_service_binding_carrier_call |= plan_auth;
                });
            }
            "access_binding" | "service_binding" => self.program.legacy_token_surface = true,
            _ => {}
        }
    }

    fn profile_binding_kind(&self, expression: &syn::Expr) -> Option<TokenProfileBridgeKind> {
        let expression = ungroup_profile_expression(expression);
        if let syn::Expr::Struct(value) = expression
            && path_contains_segment(&value.path, "ProfileBinding")
            && path_ends_with(&value.path, "RssAccess")
        {
            return Some(TokenProfileBridgeKind::RssAccess);
        }
        if let syn::Expr::Call(call) = expression
            && let syn::Expr::Path(path) = call.func.as_ref()
            && path_contains_segment(&path.path, "ProfileBinding")
        {
            return match path.path.segments.last()?.ident.to_string().as_str() {
                "RssAccess" => Some(TokenProfileBridgeKind::RssAccess),
                "FederatedAccess" => Some(TokenProfileBridgeKind::FederatedAccess),
                "ServiceToken" => Some(TokenProfileBridgeKind::ServiceToken),
                _ => None,
            };
        }
        let name = simple_path_ident(expression)?;
        self.profile_binding_locals
            .last()
            .and_then(|locals| locals.get(&name))
            .copied()
    }

    fn record_key_api(&mut self, es256: bool, hs256: bool) {
        if let Some((used_es256, used_hs256)) = self.function_key_apis.last_mut() {
            *used_es256 |= es256;
            *used_hs256 |= hs256;
        }
    }

    fn receiver_is_typed_token_provider(&self, receiver: &syn::Expr) -> bool {
        let Some(name) = simple_path_ident(ungroup_profile_expression(receiver)) else {
            return false;
        };
        self.typed_token_provider_bindings
            .last()
            .is_some_and(|bindings| bindings.contains(&name))
    }

    fn finish_function_key_apis(&mut self) {
        if let Some((used_es256, used_hs256)) = self.function_key_apis.pop() {
            self.program.mixed_key_provider |= used_es256 && used_hs256;
        }
    }

    fn method_receiver_owner(&self, receiver: &syn::Expr) -> Option<String> {
        let receiver = match receiver {
            syn::Expr::Paren(paren) => paren.expr.as_ref(),
            syn::Expr::Group(group) => group.expr.as_ref(),
            _ => receiver,
        };
        if matches!(receiver, syn::Expr::Path(path) if path.path.is_ident("self")) {
            return self.impl_stack.last().cloned();
        }
        let syn::Expr::Call(call) = receiver else {
            return None;
        };
        let syn::Expr::Path(path) = call.func.as_ref() else {
            return None;
        };
        let segments = path.path.segments.iter().collect::<Vec<_>>();
        (segments.len() >= 2).then(|| segments[segments.len() - 2].ident.to_string())
    }

    fn path_call_identity(&self, function: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = function else {
            return None;
        };
        let segments = path.path.segments.iter().collect::<Vec<_>>();
        let method = segments.last()?.ident.to_string();
        let Some(owner) = segments
            .iter()
            .rev()
            .nth(1)
            .map(|segment| segment.ident.to_string())
        else {
            return Some(format!("free::{method}"));
        };
        if owner == "Self" {
            return self
                .impl_stack
                .last()
                .map(|owner| format!("{owner}::{method}"));
        }
        if owner.chars().next().is_some_and(char::is_uppercase) {
            Some(format!("{owner}::{method}"))
        } else {
            // Module-qualified free functions retain their free-function identity. This is
            // conservative across source files while preventing Type::method name collisions.
            Some(format!("free::{method}"))
        }
    }
}

fn token_provider_binding_parameters(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            if !type_contains_ident(argument.ty.as_ref(), "TokenProviderBindings") {
                return None;
            }
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            Some(pattern.ident.to_string())
        })
        .collect()
}

fn listener_execution_spec_parameters(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            if !type_contains_ident(argument.ty.as_ref(), "ListenerExecutionSpec") {
                return None;
            }
            let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
                return None;
            };
            Some(pattern.ident.to_string())
        })
        .collect()
}

fn exact_profile_binding_definition(function: &syn::ImplItemFn) -> bool {
    if function.sig.receiver().is_none()
        || !return_type_contains_ident(&function.sig.output, "ProfileBinding")
    {
        return false;
    }
    let mut scheme_names = function.sig.inputs.iter().filter_map(|input| {
        let syn::FnArg::Typed(argument) = input else {
            return None;
        };
        if !type_contains_ident(argument.ty.as_ref(), "AuthScheme") {
            return None;
        }
        let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
            return None;
        };
        Some(pattern.ident.to_string())
    });
    let Some(scheme) = scheme_names.next() else {
        return false;
    };
    if scheme_names.next().is_some() {
        return false;
    }
    let Some(syn::Expr::Match(mapping)) = sole_block_expression(&function.block) else {
        return false;
    };
    if simple_path_ident(ungroup_profile_expression(mapping.expr.as_ref())).as_deref()
        != Some(scheme.as_str())
    {
        return false;
    }
    let mut observed = BTreeSet::new();
    for arm in &mapping.arms {
        if arm.guard.is_some() {
            return false;
        }
        let kind = match auth_scheme_profile_pattern_kind(&arm.pat) {
            Some(kind) => kind,
            None => {
                let mut evidence = ProfileMappingExpressionEvidence::default();
                syn::visit::Visit::visit_expr(&mut evidence, arm.body.as_ref());
                if evidence.rss_variants + evidence.federated_variants + evidence.service_variants
                    != 0
                {
                    return false;
                }
                continue;
            }
        };
        if matches!(arm.body.as_ref(), syn::Expr::Block(_)) {
            return false;
        }
        if !profile_mapping_expression_is_exact(arm.body.as_ref(), kind) {
            return false;
        }
        observed.insert(kind);
    }
    observed
        == BTreeSet::from([
            TokenProfileBridgeKind::RssAccess,
            TokenProfileBridgeKind::FederatedAccess,
            TokenProfileBridgeKind::ServiceToken,
        ])
}

fn auth_scheme_profile_pattern_kind(pattern: &syn::Pat) -> Option<TokenProfileBridgeKind> {
    let syn::Pat::Path(path) = pattern else {
        return None;
    };
    if !path_contains_segment(&path.path, "AuthScheme") {
        return None;
    }
    match path.path.segments.last()?.ident.to_string().as_str() {
        "RssAccessToken" => Some(TokenProfileBridgeKind::RssAccess),
        "FederatedAccessToken" => Some(TokenProfileBridgeKind::FederatedAccess),
        "ServiceToken" => Some(TokenProfileBridgeKind::ServiceToken),
        _ => None,
    }
}

fn sole_block_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.as_slice() {
        [syn::Stmt::Expr(expression, None)] => Some(expression),
        _ => None,
    }
}

#[derive(Default)]
struct ProfileMappingExpressionEvidence {
    rss_fields: usize,
    federated_fields: usize,
    service_fields: usize,
    rss_variants: usize,
    federated_variants: usize,
    service_variants: usize,
}

impl ProfileMappingExpressionEvidence {
    fn is_exact(&self, expected: TokenProfileBridgeKind) -> bool {
        let fields = [self.rss_fields, self.federated_fields, self.service_fields];
        let variants = [
            self.rss_variants,
            self.federated_variants,
            self.service_variants,
        ];
        let index = match expected {
            TokenProfileBridgeKind::RssAccess => 0,
            TokenProfileBridgeKind::FederatedAccess => 1,
            TokenProfileBridgeKind::ServiceToken => 2,
        };
        fields[index] == 1
            && variants[index] == 1
            && fields.iter().sum::<usize>() == 1
            && variants.iter().sum::<usize>() == 1
    }
}

impl<'ast> syn::visit::Visit<'ast> for ProfileMappingExpressionEvidence {
    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if path_contains_segment(&node.path, "ProfileBinding")
            && path_ends_with(&node.path, "RssAccess")
        {
            self.rss_variants = self.rss_variants.saturating_add(1);
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if matches!(node.base.as_ref(), syn::Expr::Path(path) if path.path.is_ident("self")) {
            let name = match &node.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(_) => String::new(),
            };
            match name.as_str() {
                "rss_access" => self.rss_fields = self.rss_fields.saturating_add(1),
                "federated_access" => {
                    self.federated_fields = self.federated_fields.saturating_add(1);
                }
                "service_token" => {
                    self.service_fields = self.service_fields.saturating_add(1);
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_field(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if path_contains_segment(&node.path, "ProfileBinding") {
            match node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
            {
                Some(name) if name == "RssAccess" => {
                    self.rss_variants = self.rss_variants.saturating_add(1);
                }
                Some(name) if name == "FederatedAccess" => {
                    self.federated_variants = self.federated_variants.saturating_add(1);
                }
                Some(name) if name == "ServiceToken" => {
                    self.service_variants = self.service_variants.saturating_add(1);
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_path(self, node);
    }
}

fn profile_mapping_expression_is_exact(
    expression: &syn::Expr,
    expected: TokenProfileBridgeKind,
) -> bool {
    let mut evidence = ProfileMappingExpressionEvidence::default();
    syn::visit::Visit::visit_expr(&mut evidence, expression);
    evidence.is_exact(expected)
}

fn return_type_contains_ident(output: &syn::ReturnType, expected: &str) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    type_contains_ident(ty.as_ref(), expected)
}

fn type_contains_ident(ty: &syn::Type, expected: &str) -> bool {
    struct TypeIdentVisitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for TypeIdentVisitor<'_> {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            self.found |= node
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == self.expected);
            if !self.found {
                syn::visit::visit_type_path(self, node);
            }
        }
    }
    let mut visitor = TypeIdentVisitor {
        expected,
        found: false,
    };
    syn::visit::Visit::visit_type(&mut visitor, ty);
    visitor.found
}

fn ungroup_profile_expression(expression: &syn::Expr) -> &syn::Expr {
    match expression {
        syn::Expr::Group(group) => ungroup_profile_expression(group.expr.as_ref()),
        syn::Expr::Paren(paren) => ungroup_profile_expression(paren.expr.as_ref()),
        syn::Expr::Try(try_expression) => ungroup_profile_expression(try_expression.expr.as_ref()),
        _ => expression,
    }
}

fn simple_path_ident(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

fn profile_carrier_binding(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::TupleStruct(tuple) = pattern else {
        return None;
    };
    if !path_ends_with(&tuple.path, "Token")
        || !path_contains_segment(&tuple.path, "ListenerAuthBinding")
        || tuple.elems.len() != 1
    {
        return None;
    }
    let syn::Pat::Ident(binding) = tuple.elems.first()? else {
        return None;
    };
    Some(binding.ident.to_string())
}

fn call_path_ends_with(func: &syn::Expr, segment: &str) -> bool {
    matches!(
        func,
        syn::Expr::Path(path)
            if path
                .path
                .segments
                .last()
                .is_some_and(|last| last.ident == segment)
    )
}

fn call_path_last_segment(func: &syn::Expr) -> Option<String> {
    match func {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

fn call_path_contains_segment(func: &syn::Expr, segment: &str) -> bool {
    matches!(func, syn::Expr::Path(path) if path_contains_segment(&path.path, segment))
}

fn path_contains_segment(path: &syn::Path, segment: &str) -> bool {
    path_contains_segment_matching(path, |actual| actual == segment)
}

fn path_ends_with(path: &syn::Path, segment: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|actual| actual.ident == segment)
}

fn path_contains_segment_matching(path: &syn::Path, f: impl Fn(&str) -> bool) -> bool {
    path.segments
        .iter()
        .any(|segment| f(&segment.ident.to_string()))
}

fn ident_contains(ident: &syn::Ident, needle: &str) -> bool {
    ident.to_string().contains(needle)
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let mut found = false;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("test") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn has_test_or_test_support_cfg(attrs: &[syn::Attribute]) -> bool {
    const TEST_FEATURES: &[&str] = &[
        "test-support",
        "test_support",
        "integration",
        "integration-tests",
        "integration_tests",
        "test-utils",
        "test_utils",
    ];
    fn is_test_cfg(meta: &syn::Meta, test_features: &[&str]) -> bool {
        use syn::parse::Parser as _;
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::NameValue(value) if value.path.is_ident("feature") => {
                matches!(&value.value, syn::Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Str(feature) if test_features.contains(&feature.value().as_str())))
            }
            syn::Meta::List(list) if list.path.is_ident("all") => {
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .is_ok_and(|nested| nested.iter().any(|meta| is_test_cfg(meta, test_features)))
            }
            syn::Meta::List(list) if list.path.is_ident("any") => {
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .is_ok_and(|nested| {
                        !nested.is_empty()
                            && nested.iter().all(|meta| is_test_cfg(meta, test_features))
                    })
            }
            _ => false,
        }
    }

    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| is_test_cfg(&meta, TEST_FEATURES))
    })
}

fn required_features(provider: &DiportProvider) -> &'static [&'static str] {
    provider.provider.required_features()
}

fn dependency_features(cargo_toml: &toml::Value, dependency: &str) -> Option<BTreeSet<String>> {
    let dep = cargo_toml
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .and_then(|deps| deps.get(dependency))?;
    let features = dep
        .as_table()
        .and_then(|table| table.get("features"))
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(features)
}

fn provider_table_line(src: &str, provider_index: usize) -> usize {
    let mut seen = 0;
    for (line_index, line) in src.lines().enumerate() {
        if line.trim() == "[[diportProviders]]" {
            if seen == provider_index {
                return line_index + 1;
            }
            seen += 1;
        }
    }
    1
}

fn rel_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::testutil::unique_tmp;
    use std::fs;
    use std::path::Path;

    fn load_fixture_contracts(root: &Path) -> anyhow::Result<Vec<GovernedContract>> {
        let governance = ContractGovernanceIr::load_test_fixture_root(&root.join("contracts"))?;
        governance.read(|contracts| Ok(contracts.to_vec()))
    }

    fn validate_test_fixture_root_without_contracts(
        root: &Path,
    ) -> anyhow::Result<(usize, Vec<Finding>)> {
        anyhow::ensure!(
            !root.join("contracts").exists(),
            "contract-bearing fixtures must use the governed contract fixture loader"
        );
        let (assemblies, findings) = discover(root)?;
        validate_discovered_root(root, assemblies, findings)
    }

    #[test]
    fn assembly_validate_contract_root_gate_rejects_missing_and_non_directory() -> anyhow::Result<()>
    {
        for shape in ["missing", "file"] {
            let root = unique_tmp(&format!("assembly-contract-root-{shape}"));
            fs::create_dir_all(&root)?;
            if shape == "file" {
                write(&root.join("contracts"), "not a directory")?;
            }

            let error = super::validate_root(&root)
                .expect_err("production assembly validation must require a contracts directory");
            let message = format!("{error:#}");
            assert!(
                message.contains("contracts")
                    && (message.contains("missing") || message.contains("directory")),
                "contracts/{shape} failure lost actionable context: {message}"
            );
            let _ = fs::remove_dir_all(&root);
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn assembly_lock_discovery_rejects_non_utf8_name() -> anyhow::Result<()> {
        use std::os::unix::ffi::OsStringExt;

        let root = unique_tmp("assembly-non-utf8-name");
        fs::create_dir_all(root.join("assemblies"))?;
        let invalid = std::ffi::OsString::from_vec(vec![b'n', b'a', b'm', b'e', 0xff]);
        let invalid_dir = root.join("assemblies").join(&invalid);
        match fs::create_dir(&invalid_dir) {
            // macOS/APFS may reject non-UTF8 path components at create time — still fail-closed.
            Err(_) => {}
            Ok(()) => {
                assert!(
                    crate::assembly_governance::discover_targets(&root).is_err(),
                    "non-UTF8 assembly directory names must be rejected"
                );
            }
        }
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    fn write(path: &Path, text: &str) -> anyhow::Result<()> {
        fs::write(path, text)?;
        Ok(())
    }

    /// Synthetic fixtures historically left `[[listeners]].primary.domains = []` while still
    /// declaring top-level `domains`. Manifest graph validation now rejects unbound domains, so
    /// test writers bind every declared domain onto the primary listener before disk write.
    fn bind_declared_domains_to_primary_listener(manifest: &str) -> anyhow::Result<String> {
        let doc: toml::Value = toml::from_str(manifest)?;
        let Some(domains) = doc.get("domains").and_then(|value| value.as_array()) else {
            return Ok(manifest.to_owned());
        };
        if domains.is_empty() {
            return Ok(manifest.to_owned());
        }
        let rendered = domains
            .iter()
            .filter_map(|value| value.as_str())
            .map(|domain| format!(r#""{domain}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let needle = "[[listeners]]\nkind = \"primary\"\ndomains = []";
        let replacement = format!("[[listeners]]\nkind = \"primary\"\ndomains = [{rendered}]");
        if !manifest.contains(needle) {
            return Ok(manifest.to_owned());
        }
        Ok(manifest.replacen(needle, &replacement, 1))
    }

    fn write_assembly(root: &Path, manifest: &str, cargo: &str) -> anyhow::Result<()> {
        let manifest = bind_declared_domains_to_primary_listener(manifest)?;
        let parsed: toml::Value = toml::from_str(&manifest)?;
        let name = parsed
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("runtime");
        let dir = root.join("assemblies").join(name);
        fs::create_dir_all(&dir)?;
        write(&dir.join("assembly.toml"), &manifest)?;
        write(&dir.join("Cargo.toml"), cargo)?;
        Ok(())
    }

    fn assert_pdp_replay_or_canonical_mismatch(root: &Path) -> anyhow::Result<()> {
        match validate_test_fixture_root_without_contracts(root) {
            Ok((_count, findings)) => {
                anyhow::ensure!(
                    findings
                        .iter()
                        .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
                    "expected PdpReplayStoreCapability finding, got {findings:?}"
                );
            }
            Err(err) => {
                let msg = format!("{err:#}");
                anyhow::ensure!(
                    msg.contains("does not match canonical registry")
                        || msg.contains("service-token-replay-store"),
                    "expected replay-store canonicalize mismatch, got {msg}"
                );
            }
        }
        Ok(())
    }

    /// Intentional provider-field reds may fail closed either as soft Findings (post-load
    /// validate_assembly) or as hard canonicalize registry mismatches during discover.
    fn assert_rule_or_canonical_registry_mismatch(
        root: &Path,
        rule: Rule,
        registry_field: &str,
    ) -> anyhow::Result<()> {
        match validate_test_fixture_root_without_contracts(root) {
            Ok((_count, findings)) => {
                anyhow::ensure!(
                    findings.iter().any(|finding| finding.rule == rule),
                    "expected soft finding {rule:?}, got {findings:?}"
                );
            }
            Err(err) => {
                let msg = format!("{err:#}");
                anyhow::ensure!(
                    msg.contains("does not match canonical registry")
                        && msg.contains(registry_field),
                    "expected canonicalize registry mismatch for field={registry_field}, got {msg}"
                );
            }
        }
        Ok(())
    }

    fn assert_no_provider_validation_findings(findings: &[Finding]) {
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::ActiveProviderDependency
                    | Rule::ActiveProviderPort
                    | Rule::ProviderDurabilityMismatch
                    | Rule::ActiveProviderFeature
                    | Rule::ProviderCrateMismatch
                    | Rule::ActiveDistributedProviderConsumer
            )),
            "provider validation emitted findings: {findings:?}"
        );
    }

    fn write_runtime_src(root: &Path, path: &str, text: &str) -> anyhow::Result<()> {
        let file = root.join("assemblies/runtime/src").join(path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        write(&file, text)
    }

    /// Minimal serving-key catalogs that satisfy the #1710 egress TLS closeout gate.
    const EGRESS_TLS_CLOSEOUT_CONFIG_SOURCE: &str = r#"
const FORBIDDEN_SERVING_KEYS: &[&str] = &[
    "RSS_AMQP_ALLOW_PLAINTEXT",
    "RSS_REDIS_ALLOW_PLAINTEXT",
    "RSS_S3_ALLOW_PLAINTEXT",
    "RSS_PG_SSL_MODE",
];

const FIXED_SERVING_KEYS: &[&str] = &[
    "RSS_LISTENER_ALLOW_PLAINTEXT",
    "RSS_AMQP_URL",
];
"#;

    fn write_runtime_egress_tls_closeout_config(root: &Path) -> anyhow::Result<()> {
        write_runtime_src(root, "config.rs", EGRESS_TLS_CLOSEOUT_CONFIG_SOURCE)
    }

    fn write_distributed_consumer_fixture(root: &Path) -> anyhow::Result<()> {
        write_runtime_src(
            root,
            "phase/domains.rs",
            r#"
pub struct InfraBuilt;

impl InfraBuilt {
    pub async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            )
            .await
            .context("wire event transport")?;
            Ok::<_, anyhow::Error>(event_module)
        }
        .await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#,
        )
    }

    fn valid_manifest_with_profile(profile: &str, provider_extra: &str) -> String {
        format!(
            r#"
schemaVersion = 2
name = "runtime"
profile = "{profile}"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
{provider_extra}
"#
        )
    }

    fn valid_manifest(provider_extra: &str) -> String {
        valid_manifest_with_profile("production", provider_extra)
    }

    fn manifest_with_intent() -> String {
        r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["identity", "settings", "audit"]
topology = "durable-shared"
frameworkContracts = []
workflowActivations = []

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
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
"#
        .to_string()
    }

    fn manifest_with_domains(domains: &[&str]) -> String {
        let rendered = domains
            .iter()
            .map(|domain| format!(r#""{domain}""#))
            .collect::<Vec<_>>()
            .join(", ");
        manifest_with_intent().replace(
            r#"domains = ["identity", "settings", "audit"]"#,
            &format!("domains = [{rendered}]"),
        )
    }

    fn domain_findings(
        root: &Path,
        manifest: &str,
        runtime_dependency_tables: &str,
        postgres_dependencies: &str,
    ) -> anyhow::Result<Vec<Finding>> {
        fs::create_dir_all(root)?;
        write(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = [
  "assemblies/runtime",
  "crates/identity",
  "crates/settings",
  "crates/audit",
  "adapters/postgres",
]
resolver = "2"
"#,
        )?;
        write_assembly(
            root,
            manifest,
            &format!(
                r#"[package]
name = "runtime"
version = "0.0.0"
edition = "2024"

{runtime_dependency_tables}
"#
            ),
        )?;
        write_runtime_src(root, "lib.rs", "pub fn fixture() {}")?;

        for domain in ["identity", "settings", "audit"] {
            let dir = root.join("crates").join(domain);
            fs::create_dir_all(dir.join("src"))?;
            write(
                &dir.join("Cargo.toml"),
                &format!(
                    r#"[package]
name = "{domain}"
version = "0.0.0"
edition = "2024"
"#
                ),
            )?;
            write(&dir.join("src/lib.rs"), "pub fn fixture() {}")?;
        }

        let postgres_dir = root.join("adapters/postgres");
        fs::create_dir_all(postgres_dir.join("src"))?;
        write(
            &postgres_dir.join("Cargo.toml"),
            &format!(
                r#"[package]
name = "postgres"
version = "0.0.0"
edition = "2024"

{postgres_dependencies}
"#
            ),
        )?;
        write(&postgres_dir.join("src/lib.rs"), "pub fn fixture() {}")?;

        let manifest_path = root.join("Cargo.toml");
        let manifest_arg = manifest_path.display().to_string();
        let output = crate::cmd::cargo_cmd(
            crate::cmd::CargoSubcommand::GenerateLockfile,
            &["--manifest-path", manifest_arg.as_str()],
            &[],
            Some(root),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
        anyhow::ensure!(
            output.status.success(),
            "generate fixture Cargo.lock failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let (_count, findings) = validate_test_fixture_root_without_contracts(root)?;
        Ok(findings
            .into_iter()
            .filter(|finding| {
                matches!(
                    finding.rule,
                    Rule::ActiveDomainDependency | Rule::InactiveDomainDependencyClosure
                )
            })
            .collect())
    }

    #[test]
    fn assembly_domain_metadata_indexes_all_workspace_features() {
        let args = cargo_metadata_args("/tmp/rss/Cargo.toml");
        assert!(
            args.contains(&"--all-features"),
            "workspace package classification must see the full compile surface: {args:?}"
        );
    }

    fn production_security_manifest(
        profile: &str,
        include_oidc: bool,
        include_vault_signer: bool,
        include_vault_keyprovider: bool,
    ) -> String {
        let topology = if profile == "production" {
            "durable-shared"
        } else {
            "demo"
        };
        let mut manifest = format!(
            r#"
schemaVersion = 2
name = "runtime"
profile = "{profile}"
domains = ["identity", "settings", "audit"]
topology = "{topology}"
frameworkContracts = []
workflowActivations = []

[[listeners]]
kind = "primary"
domains = ["settings", "identity"]

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = ["audit"]

[[listeners]]
kind = "health"
domains = []
"#
        );
        if include_oidc {
            manifest.push_str(
                r#"
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
outputs = ["resources"]

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
            );
        }
        if include_vault_signer {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = ["probes", "resources", "workers"]
"#,
            );
        }
        if include_vault_keyprovider {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "settings-secret-resolver"
port = "diport::SecretResolver"
provider = "vault::VaultSecretResolver"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-secret-material-resolution"
outputs = ["probes", "resources", "workers"]
"#,
            );
        }
        manifest.push_str(
            r#"
[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
requiredFeatures = ["auth-audit-sink"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = ["probes", "resources", "workers"]
"#,
        );
        if profile == "production" {
            manifest.push_str(
                r#"
[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]

[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox event publishing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "event-subscriber"
port = "diport::AckableSubscriber"
provider = "amqp::AmqpSubscriber"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "manual-ack event subscriber workers"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = ["probes", "resources", "workers"]
"#,
            );
        }
        manifest
    }

    const CARGO_SECURITY_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
oidc = { path = "../../adapters/oidc", features = ["backend"] }
vault = { path = "../../adapters/vault", features = ["backend"] }
postgres = { path = "../../adapters/postgres", features = ["domain-identity", "domain-settings", "domain-audit", "auth-audit-sink"] }
crypto-adapter = { path = "../../adapters/crypto" }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    fn capability_manifest(
        profile: &str,
        topology: &str,
        domains: &[&str],
        providers: &str,
    ) -> String {
        let rendered_domains = domains
            .iter()
            .map(|domain| format!(r#""{domain}""#))
            .collect::<Vec<_>>()
            .join(", ");
        let empty_providers = if providers.trim().is_empty() {
            "diportProviders = []\n"
        } else {
            ""
        };
        format!(
            r#"
schemaVersion = 2
name = "runtime"
profile = "{profile}"
domains = [{rendered_domains}]
topology = "{topology}"
frameworkContracts = []
workflowActivations = []
{empty_providers}

[[listeners]]
kind = "primary"
domains = [{rendered_domains}]

[[listeners]]
kind = "internal"
domains = []

[[listeners]]
kind = "admin"
domains = []

[[listeners]]
kind = "health"
domains = []
{providers}
"#
        )
    }

    const CAPABILITY_CARGO_FULL: &str = r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres", features = ["domain-identity", "domain-settings", "domain-audit", "auth-audit-sink"] }
crypto-adapter = { path = "../../adapters/crypto" }
vault = { path = "../../adapters/vault", features = ["backend"] }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    const CAPABILITY_DOMAIN_PROVIDERS: &str = r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "settings-secret-resolver"
port = "diport::SecretResolver"
provider = "vault::VaultSecretResolver"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-secret-material-resolution"
outputs = ["probes", "resources", "workers"]

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
outputs = ["resources"]

[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
requiredFeatures = ["auth-audit-sink"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = ["probes", "resources", "workers"]
"#;

    /// Registry-valid stub that does not satisfy domain required capabilities (Vault/Signer/...).
    const CAPABILITY_STUB_RATE_LIMITER: &str = r#"
[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
outputs = []
"#;

    const CAPABILITY_REPLAY_STORE_PROVIDER: &str = r#"
[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#;

    const IDENTITYAUDIT_MANIFEST: &str =
        include_str!("../../assemblies/identityaudit/assembly.toml");
    const IDENTITYAUDIT_CARGO: &str = include_str!("../../assemblies/identityaudit/Cargo.toml");
    const SETTINGSONLY_MANIFEST: &str = include_str!("../../assemblies/settingsonly/assembly.toml");
    const SETTINGSONLY_CARGO: &str = include_str!("../../assemblies/settingsonly/Cargo.toml");

    const CAPABILITY_EVENT_TRANSPORT_PROVIDERS: &str = r#"
[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox event publishing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "event-subscriber"
port = "diport::AckableSubscriber"
provider = "amqp::AmqpSubscriber"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "manual-ack event subscriber workers"
outputs = ["probes", "resources", "workers"]
"#;

    const CAPABILITY_DISTRIBUTED_PROVIDERS: &str = r#"
[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = ["probes", "resources", "workers"]
"#;

    fn required_capability_findings(manifest: &str, cargo: &str) -> anyhow::Result<Vec<Finding>> {
        let root = unique_tmp("assembly-capabilities");
        write_assembly(&root, manifest, cargo)?;
        match validate_test_fixture_root_without_contracts(&root) {
            Ok((_count, findings)) => Ok(findings
                .into_iter()
                .filter(|finding| finding.rule == Rule::RequiredCapability)
                .collect()),
            // Intentional registry-invalid reds fail closed at canonicalize before soft
            // RequiredCapability findings; keep the error text inspectable by assertions.
            Err(err) => Ok(vec![finding(
                Rule::RequiredCapability,
                "assembly.toml",
                format!("{err:#}"),
            )]),
        }
    }

    fn assert_required_capability(findings: &[Finding], domain: &str, capability: &str) {
        assert!(
            findings.iter().any(|finding| {
                let soft = finding.detail.contains(&format!("domain={domain}"))
                    && finding.detail.contains(&format!("capability={capability}"));
                // canonicalize hard-fail path: detail is the raw error chain
                let hard = finding.detail.contains(capability)
                    || finding.detail.contains(domain)
                    || finding.detail.contains("does not match canonical registry")
                    || finding.detail.contains("empty declaration");
                soft || hard
            }),
            "missing RequiredCapability finding for domain={domain} capability={capability}: {findings:?}"
        );
    }

    /// INVARIANT: ASSEMBLY-REQUIRED-CAPABILITY-01 { level = "Medium", exec = "check", source = "code" } —
    /// required capability 表必须显式覆盖每个 workspace domain；新增 domain 不得静默漏管。
    #[test]
    fn assembly_capabilities_table_covers_all_domain_crates() {
        let domains: Vec<_> = required_capability_domain_specs()
            .iter()
            .map(|spec| spec.domain)
            .collect();
        assert_eq!(domains, crate::layers::DOMAIN_CRATES);
    }

    #[test]
    fn assembly_capabilities_runtime_like_manifest_passes() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["identity", "settings", "audit"],
            &format!(
                "{CAPABILITY_DOMAIN_PROVIDERS}{CAPABILITY_REPLAY_STORE_PROVIDER}{CAPABILITY_EVENT_TRANSPORT_PROVIDERS}{CAPABILITY_DISTRIBUTED_PROVIDERS}"
            ),
        );
        let findings = required_capability_findings(&manifest, CAPABILITY_CARGO_FULL)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn runtime_pdp_requires_durable_replay_store_provider() -> anyhow::Result<()> {
        let manifest =
            capability_manifest("demo", "demo", &["identity"], CAPABILITY_DOMAIN_PROVIDERS);
        let root = unique_tmp("assembly-runtime-pdp-missing-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::PdpReplayStoreCapability),
            "runtime Pdp without durable replay provider must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_wrong_replay_store_provider() -> anyhow::Result<()> {
        let wrong_provider = CAPABILITY_REPLAY_STORE_PROVIDER.replace(
            "postgres::PgServiceTokenReplayStore",
            "postgres::PgCasStore",
        );
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{wrong_provider}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-wrong-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        assert_pdp_replay_or_canonical_mismatch(&root)?;
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_ephemeral_replay_store_provider() -> anyhow::Result<()> {
        let ephemeral = CAPABILITY_REPLAY_STORE_PROVIDER.replace("persistent", "ephemeral-memory");
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{ephemeral}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-ephemeral-replay-store");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        assert_pdp_replay_or_canonical_mismatch(&root)?;
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_replay_store_without_cluster_global_fail_closed_posture()
    -> anyhow::Result<()> {
        let replay_without_posture = CAPABILITY_REPLAY_STORE_PROVIDER
            .replace("scope = \"cluster-global\"\n", "")
            .replace("failurePosture = \"fail-closed\"\n", "");
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["identity"],
            &format!("{CAPABILITY_DOMAIN_PROVIDERS}{replay_without_posture}"),
        );
        let root = unique_tmp("assembly-runtime-pdp-replay-posture-missing");
        write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
        assert_pdp_replay_or_canonical_mismatch(&root)?;
        Ok(())
    }

    #[test]
    fn runtime_pdp_rejects_process_local_or_fail_open_replay_posture() -> anyhow::Result<()> {
        for (name, replay_provider) in [
            (
                "assembly-runtime-pdp-process-local-replay",
                CAPABILITY_REPLAY_STORE_PROVIDER.replace("cluster-global", "process-local"),
            ),
            (
                "assembly-runtime-pdp-fail-open-replay",
                CAPABILITY_REPLAY_STORE_PROVIDER.replace("fail-closed", "fail-open"),
            ),
        ] {
            let manifest = capability_manifest(
                "demo",
                "durable-shared",
                &["identity"],
                &format!("{CAPABILITY_DOMAIN_PROVIDERS}{replay_provider}"),
            );
            let root = unique_tmp(name);
            write_assembly(&root, &manifest, CAPABILITY_CARGO_FULL)?;
            assert_pdp_replay_or_canonical_mismatch(&root)?;
        }
        Ok(())
    }

    #[test]
    fn assembly_capabilities_identityaudit_closure_is_non_vacuous() -> anyhow::Result<()> {
        let findings = required_capability_findings(IDENTITYAUDIT_MANIFEST, IDENTITYAUDIT_CARGO)?;
        assert!(
            findings.is_empty(),
            "green identityaudit closure: {findings:?}"
        );

        for (cargo, manifest, domain, capability) in [
            (
                IDENTITYAUDIT_CARGO.replace(
                    "postgres = { path = \"../../adapters/postgres\", features = [\"domain-identity\", \"domain-audit\", \"auth-audit-sink\"] }\n",
                    "",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "identity",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "[\"domain-identity\", \"domain-audit\", \"auth-audit-sink\"]",
                    "[\"domain-audit\", \"auth-audit-sink\"]",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "identity",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "[\"domain-identity\", \"domain-audit\", \"auth-audit-sink\"]",
                    "[\"domain-identity\", \"auth-audit-sink\"]",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "audit",
                "Pg",
            ),
            (
                IDENTITYAUDIT_CARGO.replace(
                    "crypto-adapter = { path = \"../../adapters/crypto\" }\n",
                    "",
                ),
                IDENTITYAUDIT_MANIFEST.to_owned(),
                "audit",
                "MacVerifier",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"vault::VaultSigner\"",
                    "provider = \"vault::VaultKeyProvider\"",
                ),
                "identity",
                "Signer",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"oidc::OidcProvider\"",
                    "provider = \"vault::VaultSigner\"",
                ),
                "identity",
                "Pdp",
            ),
            (
                IDENTITYAUDIT_CARGO.to_owned(),
                IDENTITYAUDIT_MANIFEST.replace(
                    "provider = \"postgres::PgAuthAuditSink\"",
                    "provider = \"postgres::PgCasStore\"",
                ),
                "audit",
                "AuthAuditSink",
            ),
        ] {
            let findings = required_capability_findings(&manifest, &cargo)?;
            assert_required_capability(&findings, domain, capability);
        }
        Ok(())
    }

    #[test]
    fn assembly_capabilities_settings_requires_vault_keyprovider() -> anyhow::Result<()> {
        let manifest =
            capability_manifest("demo", "demo", &["settings"], CAPABILITY_STUB_RATE_LIMITER);
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;
        assert_required_capability(&findings, "settings", "VaultKeyProvider");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_settings_requires_vault_secret_resolver() -> anyhow::Result<()> {
        let manifest =
            capability_manifest("demo", "demo", &["settings"], CAPABILITY_STUB_RATE_LIMITER);
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
postgres = { path = "../../adapters/postgres" }
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "settings", "VaultSecretResolver");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_settings_requires_domain_feature() -> anyhow::Result<()> {
        let findings = required_capability_findings(
            SETTINGSONLY_MANIFEST,
            &SETTINGSONLY_CARGO.replace(
                "features = [\"domain-settings\", \"auth-audit-sink\"]",
                "features = [\"auth-audit-sink\"]",
            ),
        )?;
        assert_required_capability(&findings, "settings", "Pg");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("domain-settings")),
            "missing domain-settings feature must be explicit: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_identity_requires_signer() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            r#"
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
outputs = ["resources"]

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "identity", "Signer");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_audit_requires_crypto_adapter_dependency() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["audit"],
            r#"
[[diportProviders]]
id = "auth-audit-sink"
port = "diport::AuditSink"
provider = "postgres::PgAuthAuditSink"
providerCrate = "postgres"
requiredFeatures = ["auth-audit-sink"]
consumer = "httpserve"
lifecycle = "active"
durability = "persistent"
purpose = "http-auth-decision-audit"
outputs = ["probes", "resources", "workers"]
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres", features = ["auth-audit-sink"] }
"#,
        )?;
        assert_required_capability(&findings, "audit", "MacVerifier");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_audit_requires_pg_auth_audit_sink() -> anyhow::Result<()> {
        let manifest =
            capability_manifest("demo", "demo", &["audit"], CAPABILITY_STUB_RATE_LIMITER);
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
postgres = { path = "../../adapters/postgres" }
crypto-adapter = { path = "../../adapters/crypto" }
"#,
        )?;
        assert_required_capability(&findings, "audit", "AuthAuditSink");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_required_provider_consumer_must_match() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "demo",
            &["identity"],
            r#"
[[diportProviders]]
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = ["probes", "resources", "workers"]

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
outputs = ["resources"]
"#,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
vault = { path = "../../adapters/vault", features = ["backend"] }
oidc = { path = "../../adapters/oidc", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "identity", "Signer");
        assert!(
            findings.iter().any(|finding| {
                finding.detail.contains("consumer=settings")
                    || finding.detail.contains("expected=identity actual=settings")
            }),
            "wrong consumer detail must be present: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_distributed_lock_and_cas()
    -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["contractreg"],
            CAPABILITY_STUB_RATE_LIMITER,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;
        assert_required_capability(&findings, "distributed", "LockStore");
        assert_required_capability(&findings, "distributed", "CasStore");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_event_transport() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["contractreg"],
            CAPABILITY_DISTRIBUTED_PROVIDERS,
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "distributed", "Publisher");
        assert_required_capability(&findings, "distributed", "AckableSubscriber");
        Ok(())
    }

    #[test]
    fn assembly_capabilities_durable_topology_requires_exact_pg_cas() -> anyhow::Result<()> {
        let manifest = capability_manifest(
            "demo",
            "durable-shared",
            &["contractreg"],
            &format!(
                r#"{CAPABILITY_EVENT_TRANSPORT_PROVIDERS}
[[diportProviders]]
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-cas-store-alternative"
port = "diport::CasStore"
provider = "redis::RedisCasStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "draft"
durability = "persistent"
purpose = "distributed-state-cas-redis-alternative"
outputs = ["resources"]
"#
            ),
        );
        let findings = required_capability_findings(
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
redis = { path = "../../adapters/redis", features = ["backend"] }
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#,
        )?;
        assert_required_capability(&findings, "distributed", "CasStore");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("redis::RedisCasStore")),
            "wrong CAS provider detail must be present: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_capabilities_required_provider_must_be_active_persistent() -> anyhow::Result<()> {
        for (case, lifecycle, durability) in [
            ("draft", "draft", "persistent"),
            ("ephemeral", "active", "ephemeral-memory"),
        ] {
            let manifest = capability_manifest(
                "demo",
                "demo",
                &["settings"],
                &format!(
                    r#"
[[diportProviders]]
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "settings-configvalue-at-rest-encryption"
outputs = ["probes", "resources", "workers"]
"#
                ),
            );
            let findings = required_capability_findings(
                &manifest,
                r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
            )?;
            assert_required_capability(&findings, "settings", "VaultKeyProvider");
            assert!(
                findings.iter().any(|finding| {
                    finding.detail.contains(case)
                        || finding.detail.contains("does not match canonical registry")
                }),
                "{case} detail must be present: {findings:?}"
            );
        }
        Ok(())
    }

    const SECURITY_CLOSEOUT_FULL_SOURCE: &str = r#"
fn build_runtime_oidc_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "primary-idp",
        "/etc/rss/oidc-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let readiness = jwks.readiness_handle();
    let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
        .keys_jwks(jwks);
    let _probe = OidcJwksReadyProbe::new(readiness);
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
}
"#;

    const SECURITY_CLOSEOUT_JWKS_ONLY_SOURCE: &str = r#"
fn build_runtime_oidc_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "primary-idp",
        "/etc/rss/oidc-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let readiness = jwks.readiness_handle();
    let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
        .keys_jwks(jwks);
    let _probe = OidcJwksReadyProbe::new(readiness);
}
"#;

    const SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE: &str = r#"
fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
}
"#;

    const SECURITY_CLOSEOUT_RUN_PATH_SOURCE: &str = r#"
fn build_rss_access_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "rss-access",
        "/etc/rss/rss-access-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let _config = oidc::VerifierConfigBuilder::<RssAccessProfile>::new("https://rss", "rss")
        .keys_jwks(jwks);
    RuntimeAccessProvider { resource_name: RSS_ACCESS_TOKEN_RESOURCE_NAME }
}

fn build_federated_access_provider() {
    let jwks = oidc::JwksKeySource::load_and_watch(
        "federated-access",
        "/etc/rss/federated-access-jwks.json",
        std::time::Duration::from_secs(60),
        tokio_util::sync::CancellationToken::new(),
    ).unwrap();
    let _config = oidc::VerifierConfigBuilder::<FederatedAccessProfile>::new("https://federated", "federated")
        .keys_jwks(jwks);
    RuntimeAccessProvider { resource_name: FEDERATED_ACCESS_TOKEN_RESOURCE_NAME }
}

fn build_service_token_provider() {
    let _config = oidc::VerifierConfigBuilder::<ServiceTokenProfile>::new("https://service", "service")
        .keys_hs256(service_keys);
    RuntimeServiceTokenProvider { resource_name: SERVICE_TOKEN_RESOURCE_NAME }
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}

fn wire_domain_transport_from() {
    let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
    let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
    transport
}

fn run_startup() {
    let rss_access = build_rss_access_provider();
    let federated_access = build_federated_access_provider();
    let service_token = build_service_token_provider();
    let rss_provider = rss_access.provider();
    let federated_provider = federated_access.provider();
    let service_provider = service_token.provider();
    module.resources.push(rss_access.managed_resource());
    module.resources.push(federated_access.managed_resource());
    module.resources.push(service_token.managed_resource());
    registry.probe(
        RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
        Box::new(AccessTokenJwksReadyProbe::rss_access(rss_access.jwks_readiness())),
    ).unwrap();
    registry.probe(
        FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME,
        Box::new(AccessTokenJwksReadyProbe::federated_access(federated_access.jwks_readiness())),
    ).unwrap();
    let rss_binding = ProfileBinding::RssAccess(rss_provider);
    let federated_binding = ProfileBinding::FederatedAccess(federated_provider);
    let service_binding = ProfileBinding::ServiceToken(service_provider);
    let _ = apply_verify_bridge(routes, rss_binding);
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);
    let domain_transport = wire_domain_transport_from();
    module.merge(domain_transport.module_result().unwrap());
    let _ = mtls_config_from_env();
    let pg = ();
    let subscribers = Vec::new();
    let cfg = ();
    let distributed = wire_distributed(deps);
    let _ = wire_event_transport(&pg, distributed, subscribers, cfg);
    let _ = finalize_listener_plan();
}

fn run() {
    run_startup();
}
"#;

    const PROFILE_BINDING_MAPPING_SOURCE: &str = r#"
struct TokenProviderBindings {
    rss_access: Provider,
    federated_access: Provider,
    service_token: Provider,
}

impl TokenProviderBindings {
    fn profile_binding(
        &self,
        scheme: AuthScheme,
    ) -> ProfileBinding {
        match scheme {
            AuthScheme::RssAccessToken => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),
            AuthScheme::FederatedAccessToken => self
                .federated_access
                .map(|provider| ProfileBinding::FederatedAccess(provider)),
            AuthScheme::ServiceToken => self
                .service_token
                .map(|provider| ProfileBinding::ServiceToken(provider)),
            AuthScheme::Mtls | AuthScheme::NoAuth => fail(),
            _ => fail(),
        }
    }
}

fn apply_verify_bridge(routes: Routes, binding: ProfileBinding) {
    match binding {
        ProfileBinding::RssAccess(provider) => verify_rss(routes, provider),
        ProfileBinding::FederatedAccess(provider) => verify_federated(routes, provider),
        ProfileBinding::ServiceToken(provider) => verify_service(routes, provider),
    }
}

fn assemble(
    providers: &TokenProviderBindings,
    spec: ListenerExecutionSpec,
) {
    let scheme = spec.auth_scheme();
    let binding = ListenerAuthBinding::Token(providers.profile_binding(scheme));
    match binding {
        ListenerAuthBinding::Token(profile) => apply_verify_bridge(routes, profile),
        ListenerAuthBinding::Mtls => apply_mtls_verify_bridge(routes),
    }
}

fn run() {
    assemble(&providers, spec);
}
"#;

    fn security_closeout_run_to_launch_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "    let _ = finalize_listener_plan();",
            "    let _ = finalize_listener_plan();\n    launch();",
        )
    }

    fn security_closeout_only_rss_carrier_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            r#"    let _ = apply_verify_bridge(routes, rss_binding);
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);"#,
            r#"    let binding = ListenerAuthBinding::Token(rss_binding);
    let _ = match binding {
        ListenerAuthBinding::Token(profile) => apply_verify_bridge(routes, profile),
        ListenerAuthBinding::Mtls => apply_mtls_verify_bridge(routes),
    };
    drop(federated_binding);
    drop(service_binding);"#,
        )
    }

    fn security_closeout_lifecycle_owner_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "fn run() {\n    run_startup();\n}",
            r#"struct RuntimeLifecycleOwner;

impl RuntimeLifecycleOwner {
    fn new() -> Self { Self }

    async fn run(self) {
        run_startup();
    }
}

pub async fn run() {
    RuntimeLifecycleOwner::new().run().await;
}"#,
        )
    }

    fn security_closeout_disconnected_free_run_source() -> String {
        SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "fn run() {\n    run_startup();\n}",
            r#"struct DeadOwner;

impl DeadOwner {
    fn run(self) {
        run_startup();
    }
}

pub fn run() {}"#,
        )
    }

    const SECURITY_CLOSEOUT_LAUNCH_SOURCE: &str = r#"
fn launch() {
    launch_until();
}

fn launch_until() {
    bind_and_register();
}

fn bind_and_register() {
    let _ = mtls_config_from_env();
}

fn mtls_config_from_env() {
    let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
}
"#;

    #[test]
    fn manifest_rejects_unknown_fields() {
        let raw = manifest_with_intent().replace(
            "topology = \"durable-shared\"",
            "topology = \"durable-shared\"\nunknown = true",
        );
        assert!(AssemblyManifest::from_toml_str(&raw).is_err());
    }

    #[test]
    fn manifest_rejects_invalid_enums() {
        assert!(
            AssemblyManifest::from_toml_str(&valid_manifest(
                r#"lifecycle = "preview"
durability = "ephemeral-memory""#
            ))
            .is_err()
        );
        assert!(
            AssemblyManifest::from_toml_str(&valid_manifest(
                r#"lifecycle = "draft"
durability = "memory""#
            ))
            .is_err()
        );
    }

    #[test]
    fn manifest_rejects_unknown_diport_port() {
        assert!(
            AssemblyManifest::from_toml_str(
                &valid_manifest(
                    r#"lifecycle = "draft"
durability = "ephemeral-memory""#
                )
                .replace("diport::RevocationStore", "diport::RevocationStore ")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_accepts_domains_topology_and_listeners() -> anyhow::Result<()> {
        let manifest = AssemblyManifest::from_toml_str(&manifest_with_intent())?;
        let domains: Vec<_> = manifest
            .domains
            .iter()
            .map(AssemblyDomain::as_str)
            .collect();
        assert_eq!(domains, vec!["identity", "settings", "audit"]);
        assert_eq!(manifest.topology.as_str(), "durable-shared");
        let listeners: Vec<_> = manifest
            .listeners
            .iter()
            .map(|listener| listener.kind.as_str())
            .collect();
        assert_eq!(listeners, vec!["primary", "internal", "admin", "health"]);
        Ok(())
    }

    #[test]
    fn workflow_activation_gate_joins_definition_and_rejects_invalid_lifecycle()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-workflow-activation");
        let contract_dir = root.join("contracts/http/settings/v3");
        fs::create_dir_all(&contract_dir)?;
        write(
            &contract_dir.join("contract.toml"),
            include_str!("../../contracts/http/settings/v3/contract.toml"),
        )?;
        write(
            &contract_dir.join("request.schema.json"),
            include_str!("../../contracts/http/settings/v3/request.schema.json"),
        )?;
        write(
            &contract_dir.join("response.schema.json"),
            include_str!("../../contracts/http/settings/v3/response.schema.json"),
        )?;
        let activation = r#"workflowActivations = [{ mode = "projection", id = "settings.config-projection", definitionVersion = "v3", definitionSchemaDigest = "sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa", activation = "disabled" }]"#;
        let disabled = manifest_with_intent()
            .replace("workflowActivations = []", activation)
            .replacen(
                "kind = \"primary\"\ndomains = []",
                "kind = \"primary\"\ndomains = [\"identity\", \"settings\", \"audit\"]",
                1,
            );
        write_assembly(
            &root,
            &disabled,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let contracts = load_fixture_contracts(&root)?;
        let (assemblies, _) = discover(&root)?;
        assert!(validate_workflow_activation_contracts(&assemblies, &contracts).is_empty());

        let shadow = disabled.replace("activation = \"disabled\"", "activation = \"shadow\"");
        assert_ne!(shadow, disabled);
        write_assembly(
            &root,
            &shadow,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover(&root)?;
        assert!(matches!(
            assemblies[0].manifest().workflow_activations(),
            [assembly_schema::WorkflowActivation::Projection {
                activation: assembly_schema::ProjectionActivation::Shadow,
                ..
            }]
        ));
        let findings = validate_workflow_activation_contracts(&assemblies, &contracts);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WorkflowActivation);
        Ok(())
    }

    #[test]
    fn active_framework_contract_requires_explicit_assembly_declarations() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-framework-contract");
        let contract_dir = root.join("contracts/http/_seed/v1");
        fs::create_dir_all(&contract_dir)?;
        write(
            &contract_dir.join("contract.toml"),
            &include_str!("../../contracts/http/_seed/v1/contract.toml")
                .replace("lifecycle = \"draft\"", "lifecycle = \"active\""),
        )?;
        write(&contract_dir.join("request.schema.json"), "{}")?;
        write(&contract_dir.join("response.schema.json"), "{}")?;
        write_assembly(
            &root,
            &manifest_with_intent(),
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;

        let contracts = load_fixture_contracts(&root)?;
        let (assemblies, _) = discover(&root)?;
        let missing = validate_framework_contracts(&root, &assemblies, &contracts);
        assert!(
            missing
                .iter()
                .any(|finding| finding.rule == Rule::FrameworkContractServing)
        );

        let declared = manifest_with_intent().replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"seed.echo\", listener = \"primary\" }]",
        );
        write_assembly(
            &root,
            &declared,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover(&root)?;
        assert!(validate_framework_contracts(&root, &assemblies, &contracts).is_empty());

        let second = root.join("assemblies/second");
        fs::create_dir_all(second.join("src"))?;
        write(
            &second.join("assembly.toml"),
            &bind_declared_domains_to_primary_listener(
                &declared.replace("name = \"runtime\"", "name = \"second\""),
            )?,
        )?;
        write(
            &second.join("Cargo.toml"),
            "[package]\nname = \"second\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover(&root)?;
        assert!(validate_framework_contracts(&root, &assemblies, &contracts).is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn runtime_inventory_provider_binding_rejects_handwritten_production_callsite()
    -> anyhow::Result<()> {
        let handwritten = syn::parse_file(
            r#"
fn build() {
    let _ = runtimeexec::inventory::ProviderProbeBinding::new("provider", Vec::new());
}
"#,
        )
        .expect("synthetic production source");
        assert_eq!(production_provider_binding_evidence(&handwritten).calls, 1);

        let aliased = syn::parse_file(
            r#"
use runtimeexec::inventory::ProviderProbeBinding as Binding;
fn build() { let _ = Binding::new("provider", Vec::new()); }
"#,
        )
        .expect("synthetic alias source");
        assert_eq!(production_provider_binding_evidence(&aliased).imports, 1);

        let module_aliased_impl = syn::parse_file(
            r#"
use runtimeexec::inventory as model;
struct Receipt;
impl Receipt {
    fn consume(self) {
        let _ = model::ProviderProbeBinding::new("provider", Vec::new());
    }
}
"#,
        )
        .expect("synthetic module alias source");
        let evidence = production_provider_binding_evidence(&module_aliased_impl);
        assert_eq!(evidence.calls, 1);
        assert_eq!(evidence.constructor_references, 1);

        let type_aliased = syn::parse_file(
            r#"
type Binding = runtimeexec::inventory::ProviderProbeBinding;
fn build() { let _ = Binding::new("provider", Vec::new()); }
"#,
        )
        .expect("synthetic type alias source");
        assert_eq!(
            production_provider_binding_evidence(&type_aliased).type_aliases,
            1
        );

        let macro_wrapped = syn::parse_file(
            r#"
macro_rules! mint {
    () => { runtimeexec::inventory::ProviderProbeBinding::new("provider", Vec::new()) };
}
fn build() { let _ = mint!(); }
"#,
        )
        .expect("synthetic macro source");
        assert!(production_provider_binding_evidence(&macro_wrapped).macros > 0);

        let test_only = syn::parse_file(
            r#"
#[cfg(test)]
mod tests {
    use runtimeexec::inventory::ProviderProbeBinding;
    fn fixture() { let _ = ProviderProbeBinding::new("provider", Vec::new()); }
}
"#,
        )
        .expect("synthetic test source");
        assert_eq!(
            production_provider_binding_evidence(&test_only).calls
                + production_provider_binding_evidence(&test_only).imports,
            0
        );

        let root = unique_tmp("inventory-provider-production-validator");
        write_assembly(
            &root,
            &manifest_with_intent(),
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let source_dir = root.join("assemblies/runtime/src");
        fs::create_dir_all(&source_dir)?;
        write(
            &source_dir.join("provider_output.rs"),
            "fn consume() { let _ = runtimeexec::inventory::ProviderProbeBinding::new(\"provider\", Vec::new()); }",
        )?;
        // A production file/module named `test_support` is not a test boundary.
        write(
            &source_dir.join("test_support.rs"),
            "mod test_support { fn mint() { let _ = runtimeexec::inventory::ProviderProbeBinding::new(\"forged\", Vec::new()); } }",
        )?;
        let (assemblies, _) = discover(&root)?;
        let findings = validate_runtime_inventory_provider_provenance(&root, &assemblies)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RuntimeInventoryProviderProvenance),
            "production validator accepted an unguarded test_support callsite: {findings:#?}"
        );

        write(
            &source_dir.join("test_support.rs"),
            "#[cfg(feature = \"test-support\")] mod test_support { fn mint() { let _ = runtimeexec::inventory::ProviderProbeBinding::new(\"fixture\", Vec::new()); } }",
        )?;
        let (assemblies, _) = discover(&root)?;
        assert!(
            validate_runtime_inventory_provider_provenance(&root, &assemblies)?.is_empty(),
            "an explicit test-only cfg must remain outside production evidence"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn runtime_inventory_provider_binding_real_completion_funnels_are_exact() -> anyhow::Result<()>
    {
        let root = crate::workspace_root()?;
        let (assemblies, _) = discover(&root)?;
        let findings = validate_runtime_inventory_provider_provenance(&root, &assemblies)?;
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
        Ok(())
    }

    #[test]
    fn runtime_inventory_listener_provenance_rejects_detached_or_aliased_construction()
    -> anyhow::Result<()> {
        let direct = syn::parse_file(
            r#"
fn publish(bound: Server) {
    let _ = runtimeexec::inventory::BoundListenerObservation::from_bound(
        "admin", kind(), auth(), scheme(), bound.local_addr(),
    );
}
"#,
        )
        .expect("direct bound construction");
        let evidence = production_listener_observation_evidence(&direct);
        assert_eq!(evidence.calls, 1);
        assert_eq!(evidence.direct_local_addr_calls, 1);
        assert_eq!(evidence.constructor_references, 1);
        assert_eq!(evidence.direct_observations[0].receiver, "bound");

        let detached = syn::parse_file(
            r#"
fn publish(bound: Server) {
    let address = bound.local_addr();
    let _ = runtimeexec::inventory::BoundListenerObservation::from_bound(
        "admin", kind(), auth(), scheme(), address,
    );
}
"#,
        )
        .expect("detached address construction");
        let evidence = production_listener_observation_evidence(&detached);
        assert_eq!(evidence.calls, 1);
        assert_eq!(evidence.direct_local_addr_calls, 0);

        let aliased = syn::parse_file(
            r#"
use runtimeexec::inventory::BoundListenerObservation as Observation;
type CopyableObservation = runtimeexec::inventory::BoundListenerObservation;
macro_rules! mint {
    ($bound:expr) => { runtimeexec::inventory::BoundListenerObservation::from_bound(
        "admin", kind(), auth(), scheme(), $bound.local_addr(),
    ) };
}
"#,
        )
        .expect("listener escape source");
        let evidence = production_listener_observation_evidence(&aliased);
        assert_eq!(evidence.imports, 1);
        assert_eq!(evidence.type_aliases, 1);
        assert!(evidence.macros > 0);

        let test_only = syn::parse_file(
            r#"
#[cfg(test)]
mod tests {
    fn fixture(bound: Server) {
        let address = bound.local_addr();
        let _ = runtimeexec::inventory::BoundListenerObservation::from_bound(
            "admin", kind(), auth(), scheme(), address,
        );
    }
}
"#,
        )
        .expect("test-only listener source");
        assert!(production_listener_observation_evidence(&test_only).is_empty());

        let root = unique_tmp("inventory-listener-production-validator");
        write_assembly(
            &root,
            &manifest_with_intent(),
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let source_dir = root.join("assemblies/runtime/src");
        fs::create_dir_all(&source_dir)?;
        write(
            &source_dir.join("listeners.rs"),
            r#"
fn observations(prepared: Prepared) {
    runtimeexec::inventory::BoundListenerObservation::from_bound("primary-main", assembly_schema::AssemblyListenerKind::Primary, assembly_schema::ListenerAuth::FederatedAccessToken, scheme(), prepared.admin.bound.local_addr());
    runtimeexec::inventory::BoundListenerObservation::from_bound("admin-main", assembly_schema::AssemblyListenerKind::Admin, assembly_schema::ListenerAuth::FederatedAccessToken, scheme(), prepared.primary.bound.local_addr());
    runtimeexec::inventory::BoundListenerObservation::from_bound("health-main", assembly_schema::AssemblyListenerKind::Health, assembly_schema::ListenerAuth::NoAuth, scheme(), prepared.health.bound.local_addr());
}
"#,
        )?;
        let (assemblies, _) = discover(&root)?;
        let findings = validate_runtime_inventory_listener_provenance(&root, &assemblies)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RuntimeInventoryListenerProvenance),
            "production validator accepted swapped primary/admin bound receivers: {findings:#?}"
        );

        write(
            &source_dir.join("test_support.rs"),
            "mod test_support { fn forge(bound: Server) { runtimeexec::inventory::BoundListenerObservation::from_bound(\"x\", kind(), auth(), scheme(), bound.local_addr()); } }",
        )?;
        let findings = validate_runtime_inventory_listener_provenance(&root, &assemblies)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::RuntimeInventoryListenerProvenance
                    && finding.subject.ends_with("test_support.rs")
            }),
            "unguarded test_support source must be production evidence: {findings:#?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn runtime_inventory_listener_provenance_real_launch_roots_are_exact() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let (assemblies, _) = discover(&root)?;
        let findings = validate_runtime_inventory_listener_provenance(&root, &assemblies)?;
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
        Ok(())
    }

    #[test]
    fn assembly_manifest_accepts_all_registered_domains() -> anyhow::Result<()> {
        let manifest =
            AssemblyManifest::from_toml_str(&manifest_with_domains(crate::layers::DOMAIN_CRATES))?;
        let domains: Vec<_> = manifest
            .domains
            .iter()
            .map(AssemblyDomain::as_str)
            .collect();
        assert_eq!(domains, crate::layers::DOMAIN_CRATES);
        Ok(())
    }

    #[test]
    fn assembly_manifest_requires_domains_topology_and_listeners() {
        assert!(
            AssemblyManifest::from_toml_str(
                r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
workflowActivations = []

[[diportProviders]]
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]
"#
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_rejects_unknown_domain() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("\"identity\"", "\"billing\"")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_domain_active_manifest_domain_requires_direct_normal_dependency()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-missing-active");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity", "settings"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "manifest domain missing from direct normal dependencies must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_dev_or_build_dependency_does_not_satisfy_active_domain() -> anyhow::Result<()>
    {
        for (case, dependency_table) in [
            (
                "dev",
                r#"[dev-dependencies]
identity = { path = "../../crates/identity" }
"#,
            ),
            (
                "build",
                r#"[build-dependencies]
identity = { path = "../../crates/identity" }
"#,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-domain-{case}"));
            let findings = domain_findings(
                &root,
                &manifest_with_domains(&["identity"]),
                dependency_table,
                "",
            )?;
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule == Rule::ActiveDomainDependency),
                "{case} domain dependency must not satisfy active domain closure: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn assembly_domain_alias_or_package_rename_mismatch_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-alias");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
id = { package = "identity", path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "alias/package rename must not satisfy active domain dependency: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_target_dependency_does_not_satisfy_active_domain()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-target");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[target.'cfg(any())'.dependencies]
identity = { path = "../../crates/identity" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDomainDependency),
            "current-target-inactive domain dependency must not satisfy active domain closure: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_direct_dependency_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-direct");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings" }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive direct domain dependency must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_all_features_optional_inactive_dependency_is_rejected() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-domain-feature-optional");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings", optional = true }
"#,
            "",
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive domain resolved through an all-features optional edge must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_inactive_transitive_normal_dependency_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-inactive-transitive");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
postgres = { path = "../../adapters/postgres" }
"#,
            r#"[dependencies]
settings = { path = "../../crates/settings" }
"#,
        )?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::InactiveDomainDependencyClosure),
            "inactive transitive normal domain dependency must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn assembly_domain_declared_domains_with_normal_closure_pass() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-green");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&["identity", "settings", "audit"]),
            r#"[dependencies]
identity = { path = "../../crates/identity" }
settings = { path = "../../crates/settings" }
audit = { path = "../../crates/audit" }
"#,
            "",
        )?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn assembly_domain_real_workspace_closures_match_manifests() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let (assemblies, discovery_findings) = discover(&root)?;
        assert!(
            discovery_findings.is_empty(),
            "real workspace discovery should be clean: {discovery_findings:?}"
        );
        let metadata = load_workspace_metadata(&root)?.context("real workspace has Cargo.toml")?;
        assert!(
            !assemblies.is_empty(),
            "real workspace must govern assemblies"
        );
        for assembly in &assemblies {
            let findings = validate_target_domain_closure(&root, assembly, &metadata)?;
            assert!(
                findings.is_empty(),
                "{} target closure findings: {findings:?}",
                assembly.manifest().name()
            );
        }
        Ok(())
    }

    fn identityaudit_executable_targets() -> [MetadataTarget; 4] {
        [
            MetadataTarget {
                name: "build-script-build".to_owned(),
                kind: vec!["custom-build".to_owned()],
                src_path: PathBuf::new(),
            },
            MetadataTarget {
                name: "identityaudit".to_owned(),
                kind: vec!["lib".to_owned()],
                src_path: PathBuf::new(),
            },
            MetadataTarget {
                name: "identityaudit-server".to_owned(),
                kind: vec!["bin".to_owned()],
                src_path: PathBuf::new(),
            },
            MetadataTarget {
                name: "identityaudit_artifact_acceptance".to_owned(),
                kind: vec!["test".to_owned()],
                src_path: PathBuf::new(),
            },
        ]
    }

    fn identityaudit_production_closure() -> BTreeSet<String> {
        IDENTITYAUDIT_ALLOWED_NORMAL_WORKSPACE_PACKAGES
            .iter()
            .map(|package| (*package).to_owned())
            .collect()
    }

    /// INVARIANT: IDENTITYAUDIT-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::identityaudit_executable_boundary_rejects_lib_only_shape", anti_vacuity = "tests::identityaudit_real_executable_artifact_closure_is_complete" } -- #1797 replaces the demo composition proof with one exact executable package and its closed production transport/artifact closure.
    #[test]
    fn identityaudit_executable_boundary_accepts_exact_targets_and_production_closure() {
        let findings = validate_identityaudit_boundary(
            "assemblies/identityaudit/assembly.toml",
            "assemblies/identityaudit/Cargo.toml",
            &identityaudit_executable_targets(),
            &identityaudit_production_closure(),
        );
        assert!(
            findings.is_empty(),
            "identityaudit executable + production transport closure must pass: {findings:?}"
        );
    }

    #[test]
    fn identityaudit_executable_boundary_rejects_lib_only_shape() {
        let lib_only = [MetadataTarget {
            name: "identityaudit".to_owned(),
            kind: vec!["lib".to_owned()],
            src_path: PathBuf::new(),
        }];
        let findings = validate_identityaudit_boundary(
            "assemblies/identityaudit/assembly.toml",
            "assemblies/identityaudit/Cargo.toml",
            &lib_only,
            &identityaudit_production_closure(),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditBoundary
                    && finding.detail.contains("package.targets")
            }),
            "lib-only identityaudit must fail the executable boundary: {findings:?}"
        );
    }

    #[test]
    fn identityaudit_manifest_boundary_rejects_demo_profile_and_topology() -> anyhow::Result<()> {
        let demo_manifest = IDENTITYAUDIT_MANIFEST
            .replace("profile = \"production\"", "profile = \"demo\"")
            .replace("topology = \"durable-isolated\"", "topology = \"demo\"");
        let root = unique_tmp("identityaudit-demo-boundary");
        let dir = root.join("assemblies/identityaudit");
        fs::create_dir_all(&dir)?;
        write(&dir.join("assembly.toml"), &demo_manifest)?;
        write(&dir.join("Cargo.toml"), IDENTITYAUDIT_CARGO)?;
        let assembly = GovernedAssembly::fixture(&root, &dir)?;
        let findings = validate_assembly(&assembly);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditBoundary
                    && finding.detail.contains("profile")
                    && finding.detail.contains("topology")
            }),
            "demo identityaudit must fail the production executable boundary: {findings:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    /// identityaudit participates in production provider/JWKS closeout, but has no Internal mTLS
    /// listener or federated/service token profiles and therefore must not inherit those gates.
    #[test]
    fn identityaudit_production_boundary_does_not_inherit_full_runtime_only_gates()
    -> anyhow::Result<()> {
        let production_manifest = IDENTITYAUDIT_MANIFEST
            .replace("profile = \"demo\"", "profile = \"production\"")
            .replace("topology = \"demo\"", "topology = \"durable-isolated\"");
        let root = unique_tmp("identityaudit-production-boundary");
        let dir = root.join("assemblies/identityaudit");
        fs::create_dir_all(&dir)?;
        write(&dir.join("assembly.toml"), &production_manifest)?;
        write(&dir.join("Cargo.toml"), IDENTITYAUDIT_CARGO)?;
        let assembly = GovernedAssembly::fixture(&root, &dir)?;
        let findings = validate_assembly(&assembly);
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::ProductionSecuritySpiffeCloseout
                    | Rule::TokenProfileTrustChain
                    | Rule::ActiveDistributedProviderConsumer
            )),
            "identityaudit must use semantic production gates without full-runtime closeout: {findings:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn identityaudit_real_executable_artifact_closure_is_complete() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let manifest = AssemblyManifest::from_toml_str(IDENTITYAUDIT_MANIFEST)?;
        assert_eq!(manifest.profile, AssemblyProfile::Production);
        assert_eq!(manifest.topology, AssemblyTopology::DurableIsolated);

        let metadata = load_workspace_metadata(&root)?.context("real workspace has Cargo.toml")?;
        let package = metadata
            .packages
            .iter()
            .find(|package| package.name == "identityaudit")
            .context("identityaudit package missing from cargo metadata")?;
        assert_eq!(
            package
                .targets
                .iter()
                .map(|target| (target.name.as_str(), target.kind.as_slice()))
                .collect::<BTreeSet<_>>(),
            identityaudit_executable_targets()
                .iter()
                .map(|target| (target.name.as_str(), target.kind.as_slice()))
                .collect::<BTreeSet<_>>()
        );

        let schema_path = root.join("assemblies/identityaudit/config.schema.json");
        let schema: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&schema_path)?)?;
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&serde_json::json!(false))
        );
        for path in [
            schema_path,
            root.join("assemblies/identityaudit/identityaudit.example.toml"),
        ] {
            assert!(
                is_regular_file_without_symlink(&path)?,
                "required identityaudit artifact is missing or symlinked: {}",
                path.display()
            );
        }

        let journeys_manifest: toml::Value =
            std::fs::read_to_string(root.join("journeys/Cargo.toml"))?.parse()?;
        assert!(
            journeys_manifest
                .get("test")
                .and_then(toml::Value::as_array)
                .is_some_and(|tests| tests.iter().any(|test| {
                    test.get("name").and_then(toml::Value::as_str) == Some("identityaudit_runtime")
                        && test.get("path").and_then(toml::Value::as_str)
                            == Some("tests/identityaudit_runtime.rs")
                }))
        );
        let journey =
            std::fs::read_to_string(root.join("journeys/tests/identityaudit_runtime.rs"))?;
        assert!(identityaudit_journey_has_required_test(&journey)?);

        let dockerfile = std::fs::read_to_string(root.join("Dockerfile"))?;
        assert!(
            identityaudit_docker_target_is_closed(&dockerfile),
            "identityaudit-runtime must be one closed distroless target while runtime remains default"
        );

        let findings = validate_target(&root, "identityaudit")?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::IdentityAuditBoundary),
            "real identityaudit executable closure must be complete: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn identityaudit_artifact_gate_rejects_noop_contracts() -> anyhow::Result<()> {
        let source = include_str!("../../assemblies/identityaudit/tests/artifact_acceptance.rs");
        assert!(identityaudit_artifact_source_is_closed(source)?);
        for broken in [
            source.replace(
                "assert_executable_contract(Artifact::Binary(env!(\"CARGO_BIN_EXE_identityaudit-server\")))",
                "Ok(())",
            ),
            source.replace(
                "assert_executable_contract(Artifact::Image(&image))",
                "Ok(())",
            ),
        ] {
            assert!(
                !identityaudit_artifact_source_is_closed(&broken)?,
                "identityaudit artifact gate accepted a no-op contract"
            );
        }
        assert!(!identityaudit_artifact_source_is_closed(
            r#"
            fn assert_executable_contract(_artifact: Artifact<'_>) -> anyhow::Result<()> { Ok(()) }
            #[test]
            fn identityaudit_server_binary_is_an_executable_artifact() -> anyhow::Result<()> {
                assert_executable_contract(Artifact::Binary(env!("CARGO_BIN_EXE_identityaudit-server")))
            }
            #[test]
            #[ignore]
            fn identityaudit_runtime_image_is_an_executable_artifact() -> anyhow::Result<()> {
                let image = std::env::var(IMAGE_ENV)?;
                assert_executable_contract(Artifact::Image(&image))
            }
            "#
        )?);
        Ok(())
    }

    #[test]
    fn identityaudit_docker_boundary_rejects_third_binary_and_arbitrary_copy() -> anyhow::Result<()>
    {
        let source = std::fs::read_to_string(crate::workspace_root()?.join("Dockerfile"))?;
        for (label, mutated) in [
            (
                "identityaudit third binary",
                source.replace(
                    "--package identityaudit --bin identityaudit-server",
                    "--package identityaudit --bin identityaudit-server --package third --bin third",
                ),
            ),
            (
                "identityaudit arbitrary copy",
                source.replace(
                    "ENTRYPOINT [\"/usr/local/bin/identityaudit-server\"]",
                    "COPY --from=identityaudit-builder /app/target/release/third /usr/local/bin/third\nENTRYPOINT [\"/usr/local/bin/identityaudit-server\"]",
                ),
            ),
        ] {
            assert_ne!(mutated, source, "{label} mutation was vacuous");
            assert!(
                !identityaudit_docker_target_is_closed(&mutated),
                "identityaudit Docker boundary accepted {label}"
            );
        }
        Ok(())
    }

    #[test]
    fn identityaudit_journey_gate_requires_runtime_witness_chain() -> anyhow::Result<()> {
        let source = include_str!("../../journeys/tests/identityaudit_runtime.rs");
        assert!(identityaudit_journey_has_required_test(source)?);
        for required_call in [
            "RuntimeFixture::start",
            "wait_until_ready",
            "login",
            "wait_for_auth_audit",
            "wait_for_session_created_hash_chain",
            "send_sigterm",
            "wait_for_drain",
        ] {
            let broken = source.replace(required_call, "noop_witness");
            assert!(
                !identityaudit_journey_has_required_test(&broken)?,
                "identityaudit journey gate accepted missing witness {required_call}"
            );
        }
        assert!(!identityaudit_journey_has_required_test(
            "#[tokio::test]\nasync fn identityaudit_login_audit_ready_sigterm_drain() -> anyhow::Result<()> { Ok(()) }"
        )?);
        assert!(!identityaudit_journey_has_required_test(
            "#[tokio::test]\nasync fn identityaudit_login_audit_ready_sigterm_drain() -> anyhow::Result<()> { if false { let mut runtime = RuntimeFixture::start(providers).await?; runtime.wait_until_ready().await?; let login = runtime.login().await?; wait_for_auth_audit(&pool).await?; wait_for_session_created_hash_chain(&pool, &login).await?; runtime.send_sigterm()?; runtime.wait_for_drain().await?; } Ok(()) }"
        )?);
        assert!(!identityaudit_journey_has_required_test(
            "#[tokio::test]\nasync fn identityaudit_login_audit_ready_sigterm_drain() -> anyhow::Result<()> { let dead = || { let mut runtime = RuntimeFixture::start(providers); runtime.wait_until_ready(); let login = runtime.login(); wait_for_auth_audit(&pool); wait_for_session_created_hash_chain(&pool, &login); runtime.send_sigterm(); runtime.wait_for_drain(); }; Ok(()) }"
        )?);
        Ok(())
    }

    fn settingsonly_boundary_evidence<'a>(
        targets: &'a [MetadataTarget],
        closure_packages: &'a BTreeSet<String>,
    ) -> SettingsOnlyExecutableEvidence<'a> {
        SettingsOnlyExecutableEvidence {
            targets,
            closure_packages,
            test_support_enabled: false,
            schema_is_regular_file: true,
            sample_is_regular_file: true,
            production_artifact_target_declared: true,
            production_artifact: ArtifactClosureEvidence::certificate([
                "InputReady",
                "L2Join",
                "Sigkill",
                "Sigterm",
            ]),
            journey_target_declared: true,
            required_journey_test_declared: true,
            runtimeexec_launch_is_live: true,
            dockerignore_contracts_included: true,
        }
    }

    /// INVARIANT: SETTINGSONLY-EXECUTABLE-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::settingsonly_production_artifact_gate_rejects_incomplete_case_closure", anti_vacuity = "tests::settingsonly_real_executable_boundary_is_complete" } -- settingsonly remains one build-script+lib+bin package; its integration-only production artifact target is a closed four-case AST bijection, contracts remain in the image build context, and artifact identity/ENTRYPOINT stay owned by ASSEMBLY-ARTIFACT-MATRIX-01.
    #[test]
    fn settingsonly_executable_boundary_rejects_each_incomplete_artifact_fact() {
        let targets = [
            MetadataTarget {
                name: "build-script-build".to_owned(),
                kind: vec!["custom-build".to_owned()],
                src_path: PathBuf::new(),
            },
            MetadataTarget {
                name: "settingsonly".to_owned(),
                kind: vec!["lib".to_owned()],
                src_path: PathBuf::new(),
            },
            MetadataTarget {
                name: "settingsonly-server".to_owned(),
                kind: vec!["bin".to_owned()],
                src_path: PathBuf::new(),
            },
        ];
        let required = SETTINGSONLY_ALLOWED_NORMAL_WORKSPACE_PACKAGES
            .iter()
            .map(|package| (*package).to_owned())
            .collect::<BTreeSet<_>>();
        assert!(
            validate_settingsonly_executable_evidence(settingsonly_boundary_evidence(
                &targets, &required,
            ))
            .is_empty()
        );

        let mut unexpected_closure = required.clone();
        unexpected_closure.insert("mqtt".to_owned());
        assert!(
            validate_settingsonly_executable_evidence(settingsonly_boundary_evidence(
                &targets,
                &unexpected_closure,
            ))
            .iter()
            .any(|finding| finding.detail.contains("unexpected packages")),
            "positive dependency closure accepted an unlisted package"
        );

        let mut incomplete_closure = required
            .iter()
            .filter(|package| package.as_str() != "runtimeexec")
            .cloned()
            .collect::<BTreeSet<_>>();
        incomplete_closure.insert("identity".to_owned());
        let mut incomplete = settingsonly_boundary_evidence(&targets[..1], &incomplete_closure);
        incomplete.test_support_enabled = true;
        incomplete.schema_is_regular_file = false;
        incomplete.sample_is_regular_file = false;
        incomplete.production_artifact_target_declared = false;
        incomplete.production_artifact =
            ArtifactClosureEvidence::Violations(vec![ArtifactClosureViolation::new(
                ArtifactClosureStage::CaseInventory,
                Some("InputReady"),
                ArtifactClosurePath::Support,
                None,
                "closed case inventory",
                "missing",
            )]);
        incomplete.journey_target_declared = false;
        incomplete.required_journey_test_declared = false;
        incomplete.dockerignore_contracts_included = false;
        let details = validate_settingsonly_executable_evidence(incomplete)
            .into_iter()
            .map(|finding| finding.detail)
            .collect::<Vec<_>>()
            .join("\n");
        for field in [
            "package.targets",
            "missing allowed",
            "unexpected packages",
            "default-normal-features",
            "config-schema",
            "config-sample",
            "production-artifact",
            "journey",
            ".dockerignore",
        ] {
            assert!(details.contains(field), "missing red evidence for {field}");
        }
    }

    #[test]
    fn settingsonly_journey_gate_requires_exact_non_ignored_parent() -> anyhow::Result<()> {
        let cases = [
            ("missing parent", "#[test]\nfn unrelated_journey() {}"),
            (
                "only ignored child",
                "#[tokio::test]\n#[ignore]\nasync fn settingsonly_lifecycle_fixture_child() {}",
            ),
            (
                "name bait",
                "#[test]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain_decoy() {}",
            ),
            (
                "ignored parent",
                "#[tokio::test]\n#[ignore]\nasync fn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() {}",
            ),
            (
                "conditionally compiled parent",
                "#[test]\n#[cfg(any())]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { run(); }",
            ),
            (
                "conditionally ignored parent",
                "#[test]\n#[cfg_attr(all(), ignore)]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { run(); }",
            ),
            (
                "empty parent",
                "#[test]\nfn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() {}",
            ),
        ];
        for (case, source) in cases {
            assert!(
                !settingsonly_journey_has_required_test(source)?,
                "settingsonly journey gate accepted {case}"
            );
        }

        assert!(!settingsonly_journey_has_required_test(
            "#[tokio::test]\nasync fn settingsonly_lifecycle_fixture_ready_request_sigterm_drain() { return; }"
        )?);
        assert!(settingsonly_journey_has_required_test(include_str!(
            "../../journeys/tests/settingsonly_runtime.rs"
        ))?);
        Ok(())
    }

    #[test]
    fn subset_health_inventory_requires_live_runtimeexec_launch_chain() -> anyhow::Result<()> {
        let lib = "fn run() { runtime.block_on(runtime::launch_captured(captured)); }";
        let direct = "async fn launch_captured() { let plan = runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan).await; }";
        assert!(subset_runtimeexec_launch_sources_are_live(lib, direct)?);

        let delegated = "async fn launch(startup: S) { let plan = runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan).await; } async fn launch_captured() { launch(startup).await; }";
        assert!(subset_runtimeexec_launch_sources_are_live(lib, delegated)?);

        let dead = "async fn launch_captured() { if false { let plan = runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan).await; } }";
        assert!(!subset_runtimeexec_launch_sources_are_live(lib, dead)?);
        assert!(!subset_runtimeexec_launch_sources_are_live(
            "fn run() {}",
            direct
        )?);
        for opaque in [
            "async fn launch_captured() { let dead = || { let plan = runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan); }; }",
            "async fn launch_captured() { let dead = async { let plan = runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan).await; }; }",
            "async fn launch_captured() { const _: () = { runtimeexec::StartupPlan::new(startup, budget); runtimeexec::launch_startup(plan); }; }",
        ] {
            assert!(
                !subset_runtimeexec_launch_sources_are_live(lib, opaque)?,
                "opaque scope satisfied live launch chain: {opaque}"
            );
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)] // reason: test fixture asserts ArtifactClosureEvidence::Certified via explicit panic path.
    fn settingsonly_production_artifact_gate_rejects_incomplete_case_closure() -> anyhow::Result<()>
    {
        let entry = include_str!("../../journeys/tests/settingsonly_production_artifact.rs");
        let support =
            include_str!("../../journeys/tests/support/settingsonly_production_artifact.rs");
        let manifest: toml::Value = include_str!("../../journeys/Cargo.toml").parse()?;
        assert!(settingsonly_production_artifact_target_is_exact(&manifest));
        let evidence = settingsonly_production_artifact_sources_are_closed(entry, support);
        let ArtifactClosureEvidence::Certified(certificate) = evidence else {
            panic!("real source did not produce a closure certificate: {evidence:?}");
        };
        assert_eq!(certificate.case_count(), 4);

        for (case, broken) in [
            (
                "wrong Cargo target path",
                include_str!("../../journeys/Cargo.toml").replace(
                    "path = \"tests/settingsonly_production_artifact.rs\"",
                    "path = \"tests/decoy.rs\"",
                ),
            ),
            (
                "duplicate Cargo target",
                format!(
                    "{}\n[[test]]\nname = \"settingsonly_production_artifact\"\npath = \"tests/settingsonly_production_artifact.rs\"\nrequired-features = [\"integration\"]\n",
                    include_str!("../../journeys/Cargo.toml")
                ),
            ),
        ] {
            let broken: toml::Value = broken.parse()?;
            assert!(
                !settingsonly_production_artifact_target_is_exact(&broken),
                "production artifact target gate accepted {case}"
            );
        }

        for (case, broken) in [
            (
                "support path replacement",
                entry.replacen(
                    "support/settingsonly_production_artifact.rs",
                    "support/decoy.rs",
                    1,
                ),
            ),
            (
                "support path decoy",
                entry.replacen(
                    "#[path = \"support/settingsonly_production_artifact.rs\"]",
                    "#[path = \"support/decoy.rs\"]\n#[doc = \"support/settingsonly_production_artifact.rs\"]",
                    1,
                ),
            ),
            (
                "aliased support import",
                entry.replacen(
                    "use settingsonly_production_artifact::{EvidenceCase, run_case};",
                    "use settingsonly_production_artifact::{EvidenceCase, run_case as execute};",
                    1,
                ),
            ),
            (
                "missing test",
                entry.replacen(
                    "async fn settingsonly_image_mount_spiffe_readiness_join",
                    "async fn unrelated_test",
                    1,
                ),
            ),
            (
                "extra test",
                format!("{entry}\n#[test]\nfn extra_test() {{}}\n"),
            ),
            (
                "ignored test",
                entry.replacen("#[tokio::test", "#[ignore]\n#[tokio::test", 1),
            ),
            (
                "cfg test",
                entry.replacen("#[tokio::test", "#[cfg(any())]\n#[tokio::test", 1),
            ),
            (
                "should panic test",
                entry.replacen("#[tokio::test", "#[should_panic]\n#[tokio::test", 1),
            ),
            (
                "empty test",
                entry.replacen("run_case(EvidenceCase::InputReady).await", "Ok(())", 1),
            ),
            (
                "wrong case",
                entry.replacen("EvidenceCase::InputReady", "EvidenceCase::Unknown", 1),
            ),
            (
                "duplicate case",
                entry.replacen("EvidenceCase::Sigterm", "EvidenceCase::Sigkill", 1),
            ),
        ] {
            assert_ne!(broken, entry, "{case} mutation was vacuous");
            assert!(
                matches!(
                    settingsonly_production_artifact_sources_are_closed(&broken, support),
                    ArtifactClosureEvidence::Violations(_)
                ),
                "production artifact gate accepted {case}"
            );
        }

        for (case, broken) in [
            (
                "missing EvidenceCase",
                support.replacen("    InputReady,", "    Unknown,", 1),
            ),
            (
                "extra EvidenceCase",
                support.replacen("    InputReady,", "    InputReady,\n    Extra,", 1),
            ),
            (
                "default match arm",
                support.replacen(
                    "            Self::Sigterm => fixture.sigterm().await,",
                    "            Self::Sigterm => fixture.sigterm().await,\n            _ => fixture.sigterm().await,",
                    1,
                ),
            ),
            (
                "string selector",
                support.replacen(
                    "    async fn dispatch(self, fixture: &mut Fixture) -> anyhow::Result<CaseCompletion> {\n        match self {",
                    "    async fn dispatch(self, fixture: &mut Fixture) -> anyhow::Result<CaseCompletion> {\n        match self.id() {",
                    1,
                ),
            ),
            (
                "wrong match case",
                support.replacen(
                    "Self::InputReady => fixture.input_ready().await",
                    "Self::InputReady => fixture.sigterm().await",
                    1,
                ),
            ),
            (
                "swallowed result",
                support.replacen("fixture.finish(result).await", "result", 1),
            ),
            (
                "replaced finish result",
                support.replacen("fixture.finish(result).await", "fixture.finish(Ok(())).await", 1),
            ),
            (
                "early return",
                support.replacen(
                    "    let mut fixture = Fixture::start(repository, case.id()).await?;",
                    "    return Ok(());\n    let mut fixture = Fixture::start(repository, case.id()).await?;",
                    1,
                ),
            ),
            (
                "extra runner branch",
                support.replacen(
                    "    let mut fixture = Fixture::start(repository, case.id()).await?;",
                    "    if false { return Ok(()); }\n    let mut fixture = Fixture::start(repository, case.id()).await?;",
                    1,
                ),
            ),
            (
                "empty scenario",
                support.replacen(
                    "    async fn input_ready(&mut self) -> anyhow::Result<CaseCompletion> {",
                    "    async fn input_ready(&mut self) -> anyhow::Result<CaseCompletion> { return Err(anyhow::anyhow!(\"empty\"));",
                    1,
                ),
            ),
            (
                "opaque-only scenario",
                support.replacen(
                    "        self.workload.wait_request().await?;",
                    "        let _dead = || self.workload.wait_request();",
                    1,
                ),
            ),
            (
                "cfg-elided local witness",
                support.replacen(
                    "        let _ready = self.wait_ready().await?;",
                    "        #[cfg(any())]\n        let _ready = self.wait_ready().await?;",
                    1,
                ),
            ),
            (
                "cfg_attr-elided expression witness",
                support.replacen(
                    "        self.workload.wait_request().await?;",
                    "        #[cfg_attr(all(), cfg(any()))]\n        self.workload.wait_request().await?;",
                    1,
                ),
            ),
            (
                "missing SIGTERM waiter",
                support.replacen("        barrier.wait_for_waiter(&self.pool).await?;\n", "", 1),
            ),
            (
                "non-awaited witness future",
                support.replacen(
                    "        self.wait_claimed(&event_id).await?;",
                    "        self.wait_claimed(&event_id);",
                    1,
                ),
            ),
            (
                "dropped awaited witness result",
                support.replacen(
                    "        self.wait_claimed(&event_id).await?;",
                    "        self.wait_claimed(&event_id).await;",
                    1,
                ),
            ),
            (
                "duplicate witness",
                support.replacen(
                    "        self.wait_claimed(&event_id).await?;",
                    "        self.wait_claimed(&event_id).await?;\n        self.wait_claimed(&event_id).await?;",
                    1,
                ),
            ),
            (
                "out-of-order SIGTERM waiter",
                support.replacen(
                    "        self.wait_claimed(&event_id).await?;\n        barrier.wait_for_waiter(&self.pool).await?;",
                    "        barrier.wait_for_waiter(&self.pool).await?;\n        self.wait_claimed(&event_id).await?;",
                    1,
                ),
            ),
            (
                "wrong Evidence ID",
                support.replacen(
                    "SETTINGSONLY-T3-INPUT-READY-01",
                    "SETTINGSONLY-T3-INPUT-READY-XX",
                    1,
                ),
            ),
            (
                "duplicate Evidence ID",
                support.replacen(
                    "SETTINGSONLY-T3-SIGTERM-01",
                    "SETTINGSONLY-T3-SIGKILL-01",
                    1,
                ),
            ),
        ] {
            assert_ne!(broken, support, "{case} mutation was vacuous");
            assert!(
                matches!(
                    settingsonly_production_artifact_sources_are_closed(entry, &broken),
                    ArtifactClosureEvidence::Violations(_)
                ),
                "production artifact gate accepted {case}"
            );
        }
        Ok(())
    }

    #[test]
    fn settingsonly_production_artifact_gate_emits_precise_typed_diagnostics() {
        let entry = include_str!("../../journeys/tests/settingsonly_production_artifact.rs");
        let support =
            include_str!("../../journeys/tests/support/settingsonly_production_artifact.rs");

        let ignored = entry.replacen("#[tokio::test", "#[ignore]\n#[tokio::test", 1);
        assert_artifact_violation(
            settingsonly_production_artifact_sources_are_closed(&ignored, support),
            ArtifactClosureStage::TestInventory,
            None,
            ArtifactClosurePath::Entry,
            "one live unconditional non-empty run_case carrier",
            "settingsonly_image_mount_spiffe_readiness_join",
        );

        let wrong_dispatch = support.replacen(
            "Self::InputReady => fixture.input_ready().await",
            "Self::InputReady => fixture.sigterm().await",
            1,
        );
        assert_artifact_violation(
            settingsonly_production_artifact_sources_are_closed(entry, &wrong_dispatch),
            ArtifactClosureStage::Dispatch,
            Some("InputReady"),
            ArtifactClosurePath::Support,
            "input_ready",
            "sigterm",
        );

        let direct_receipt = support.replacen(
            "let receipt = self.observe_unacked(event_id, barrier).await?;",
            "let receipt = UnackedReceipt { event_id, barrier };",
            1,
        );
        assert_artifact_violation(
            settingsonly_production_artifact_sources_are_closed(entry, &direct_receipt),
            ArtifactClosureStage::ReceiptProvenance,
            Some("Sigkill"),
            ArtifactClosurePath::Support,
            "receipt minted by a typed Fixture method",
            "direct UnackedReceipt construction",
        );

        let cloneable_receipt = support.replacen(
            "struct UnackedReceipt {",
            "#[derive(Clone)]\nstruct UnackedReceipt {",
            1,
        );
        assert_artifact_violation(
            settingsonly_production_artifact_sources_are_closed(entry, &cloneable_receipt),
            ArtifactClosureStage::ReceiptProvenance,
            None,
            ArtifactClosurePath::Support,
            "private non-Clone non-Copy receipt with private fields",
            "# [derive (Clone)] struct UnackedReceipt { event_id : String , barrier : InboxBarrier , }",
        );

        let alpha_renamed = support
            .replacen(
                "run_case(case: EvidenceCase)",
                "run_case(selected: EvidenceCase)",
                1,
            )
            .replacen("case.id()", "selected.id()", 1)
            .replacen("let mut fixture =", "let mut runtime_fixture =", 1)
            .replacen(
                "case.dispatch(&mut fixture)",
                "selected.dispatch(&mut runtime_fixture)",
                1,
            )
            .replacen("completion.case == case", "completion.case == selected", 1)
            .replacen("let result =", "let outcome =", 1)
            .replacen(
                "fixture.finish(result)",
                "runtime_fixture.finish(outcome)",
                1,
            );
        assert!(matches!(
            settingsonly_production_artifact_sources_are_closed(entry, &alpha_renamed),
            ArtifactClosureEvidence::Certified(_)
        ));

        let unrelated = support.replacen(
            "    async fn l2_join(&mut self) -> anyhow::Result<CaseCompletion> {",
            "    async fn l2_join(&mut self) -> anyhow::Result<CaseCompletion> {\n        let _diagnostic = self.evidence_id;",
            1,
        );
        assert!(matches!(
            settingsonly_production_artifact_sources_are_closed(entry, &unrelated),
            ArtifactClosureEvidence::Certified(_)
        ));
    }

    #[allow(clippy::panic)] // reason: test helper panics with exact violation diagnostics on mismatch.
    fn assert_artifact_violation(
        evidence: ArtifactClosureEvidence,
        stage: ArtifactClosureStage,
        case: Option<&str>,
        path: ArtifactClosurePath,
        expected: &str,
        actual: &str,
    ) {
        let ArtifactClosureEvidence::Violations(violations) = evidence else {
            panic!("mutation unexpectedly produced a certificate");
        };
        let violation = violations
            .iter()
            .find(|violation| {
                violation.stage == stage
                    && violation.case.as_deref() == case
                    && violation.path == path
                    && violation.expected == expected
                    && violation.actual == actual
            })
            .unwrap_or_else(|| {
                panic!(
                    "missing exact violation stage={stage:?} case={case:?} path={path:?} expected={expected:?} actual={actual:?}; actual violations={violations:?}"
                )
            });
        assert!(
            violation.span.is_some(),
            "exact diagnostic omitted its source span: {violation:?}"
        );
    }

    #[test]
    fn settingsonly_real_executable_boundary_is_complete() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let findings = validate_target(&root, "settingsonly")?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::SettingsOnlyExecutableBoundary),
            "real settingsonly artifact closure must be complete: {findings:?}"
        );
        Ok(())
    }

    fn real_settingsonly_l2_evidence() -> anyhow::Result<SettingsOnlyL2Evidence> {
        let root = crate::workspace_root()?;
        let ir = AssemblyGovernanceIr::<Core>::load(&root)?;
        let assembly = ir
            .assembly("settingsonly")
            .context("settingsonly governance projection")?;
        let metadata = load_workspace_metadata(&root)?.context("workspace cargo metadata")?;
        let (closure_packages, _) = cargo_tree_default_normal_evidence(&root, assembly, &metadata)?;
        load_settingsonly_l2_evidence(&root, assembly, &closure_packages)
    }

    #[test]
    fn settingsonly_l2_production_closure_accepts_real_workspace() -> anyhow::Result<()> {
        let evidence = real_settingsonly_l2_evidence()?;
        let findings = validate_settingsonly_l2_evidence(&evidence);
        assert!(
            findings.is_empty(),
            "real L2 production closure must be green: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn settingsonly_l2_production_closure_rejects_synthetic_mutations() -> anyhow::Result<()> {
        let baseline = real_settingsonly_l2_evidence()?;
        assert!(validate_settingsonly_l2_evidence(&baseline).is_empty());

        let mut cases: Vec<(&str, SettingsOnlyL2Evidence)> = Vec::new();

        let mut missing = baseline.clone();
        missing
            .runtime_plan
            .get_mut("providerPlans")
            .and_then(serde_json::Value::as_array_mut)
            .context("providerPlans fixture")?
            .pop();
        cases.push(("missing provider", missing));

        let mut extra = baseline.clone();
        let plans = extra
            .runtime_plan
            .get_mut("providerPlans")
            .and_then(serde_json::Value::as_array_mut)
            .context("providerPlans fixture")?;
        plans.push(plans[0].clone());
        cases.push(("extra provider", extra));

        let mut equal_count_substitution = baseline.clone();
        let substituted = equal_count_substitution
            .runtime_plan
            .get_mut("providerPlans")
            .and_then(serde_json::Value::as_array_mut)
            .context("providerPlans fixture")?
            .iter_mut()
            .find(|provider| {
                provider.get("id").and_then(serde_json::Value::as_str)
                    == Some("distributed-cas-store")
            })
            .context("distributed CAS fixture")?;
        substituted["id"] = serde_json::json!("distributed-cas-store-alternative");
        cases.push((
            "equal-count provider substitution",
            equal_count_substitution,
        ));

        let mut ephemeral = baseline.clone();
        ephemeral.providers_gen = ephemeral.providers_gen.replacen(
            "ProviderDurability::Persistent",
            "ProviderDurability::EphemeralMemory",
            1,
        );
        cases.push(("ephemeral durable provider", ephemeral));

        let mut cargo_fallback = baseline.clone();
        cargo_fallback
            .closure_packages
            .insert("demo-fallback".to_owned());
        cases.push(("fallback Cargo closure", cargo_fallback));

        let mut generated_comment = baseline.clone();
        generated_comment.providers_gen = generated_comment.providers_gen.replace(
            "ProviderCatalogEntry::checked(",
            "/* ProviderCatalogEntry::checked( */ ProviderCatalogEntry::unchecked(",
        );
        cases.push(("generated comment bait", generated_comment));

        let mut generated_test = baseline.clone();
        generated_test.modules_gen = generated_test.modules_gen.replace(
            "pub async fn wire_domains",
            "#[cfg(test)] pub async fn wire_domains",
        );
        cases.push(("generated cfg(test) bait", generated_test));

        let mut lock_drift = baseline.clone();
        lock_drift.runtime_plan["assemblyFingerprint"] = serde_json::json!("sha256:synthetic-red");
        cases.push(("runtime plan drift", lock_drift));

        let mut lock_digest = baseline.clone();
        lock_digest.lock["digests"]["manifest"] = serde_json::json!("sha256:synthetic-red");
        cases.push(("assembly lock drift", lock_digest));

        let mut v1 = baseline.clone();
        v1.config_schema["properties"]["schemaVersion"]["const"] = serde_json::json!(1);
        cases.push(("config v1", v1));

        let mut dead_helper = baseline.clone();
        dead_helper.runtime_rs = dead_helper.runtime_rs.replace(
            "let completed = crate::providers::build(",
            "if false { let _ = crate::providers::build; } let completed = fallback::build(",
        );
        cases.push(("dead helper and fallback", dead_helper));

        let mut nonactivated = baseline.clone();
        nonactivated.eventing_rs = nonactivated.eventing_rs.replace(
            "eventing_composition::bridge_generated_settings_subscriptions(bindings)",
            "eventing_composition::validate_nonactivated_settings_subscriber(bindings)",
        );
        cases.push(("nonactivated subscriber", nonactivated));

        let mut unready_amqp = baseline.clone();
        unready_amqp.eventing_rs = unready_amqp
            .eventing_rs
            .replace("wire_amqp_readiness(", "dead_amqp_readiness(");
        cases.push(("unready AMQP provider roles", unready_amqp));

        let mut degraded_required_probe = baseline.clone();
        degraded_required_probe.eventing_rs = degraded_required_probe.eventing_rs.replace(
            "required_health_status(self.health.status())",
            "self.health.status()",
        );
        cases.push((
            "degraded required probe remains ready",
            degraded_required_probe,
        ));

        let mut generic_bridge = baseline.clone();
        generic_bridge.bridge_rs = generic_bridge
            .bridge_rs
            .replace("admitted_settings_dispatch,", "admitted_dispatch,");
        cases.push(("generic subscription fallback", generic_bridge));

        let mut raw_jwt_parse = baseline.clone();
        raw_jwt_parse
            .auth_bridge_rs
            .push_str("\nfn raw_parse(raw: &str) { let _ = authn::Jwt::parse(raw); }\n");
        cases.push(("raw JWT parse", raw_jwt_parse));

        let mut raw_jwt_alias = baseline.clone();
        raw_jwt_alias.auth_bridge_rs.push_str(
            "\nfn raw_alias(raw: &str) { let parse = authn::Jwt::parse; let _ = parse(raw); }\n",
        );
        cases.push(("raw JWT parse alias", raw_jwt_alias));

        let mut raw_jwt_function_pointer = baseline.clone();
        raw_jwt_function_pointer.auth_bridge_rs.push_str(
            "\nfn raw_pointer(raw: &str) { let parse: fn(&str) -> Result<authn::Jwt, authn::AuthnError> = authn::Jwt::parse; let _ = parse(raw); }\n",
        );
        cases.push(("raw JWT parse function pointer", raw_jwt_function_pointer));

        let mut raw_jwt_test_bait = baseline.clone();
        raw_jwt_test_bait.auth_bridge_rs.push_str(
            "\n#[cfg(test)] mod bait { fn raw_parse(raw: &str) { let _ = authn::Jwt::parse(raw); } }\n",
        );
        cases.push(("cfg(test) raw JWT parse bait", raw_jwt_test_bait));

        let mut full_access_extension = baseline.clone();
        full_access_extension.auth_bridge_rs = full_access_extension.auth_bridge_rs.replace(
            "request.extensions_mut().insert(principal);",
            "request.extensions_mut().insert(principal); request.extensions_mut().insert(access);",
        );
        cases.push(("full verified access extension", full_access_extension));

        let mut provider_fallback = baseline.clone();
        provider_fallback.providers_rs = provider_fallback.providers_rs.replace(
            "build_s3_archive_store(s3, &secrets)",
            "fallback_archive_store(s3, &secrets)",
        );
        cases.push(("production provider fallback", provider_fallback));

        let mut provider_string_bait = baseline.clone();
        provider_string_bait.providers_rs = provider_string_bait.providers_rs.replace(
            "build_s3_archive_store(s3, &secrets)",
            "{ let _bait = \"build_s3_archive_store(s3, &secrets)\"; fallback_archive_store(s3, &secrets) }",
        );
        cases.push(("production provider string bait", provider_string_bait));

        let mut optional_receipt = baseline.clone();
        optional_receipt.providers_rs = optional_receipt.providers_rs.replace(
            "distributed_lock_store: crate::providers_gen::DistributedLockStoreReceipt",
            "distributed_lock_store: Option<crate::providers_gen::DistributedLockStoreReceipt>",
        );
        cases.push(("optional production receipt", optional_receipt));

        let mut unready_redis = baseline.clone();
        unready_redis.providers_rs = unready_redis
            .providers_rs
            .replace("RedisReadinessWorker::spawn(", "dead_redis_sampler(");
        cases.push(("unready Redis provider", unready_redis));

        let mut open_nested_config = baseline.clone();
        open_nested_config.config_schema["definitions"]["ListenersConfig"]["additionalProperties"] =
            serde_json::json!(true);
        cases.push(("open nested config", open_nested_config));

        let mut incomplete_secret_bundle = baseline.clone();
        incomplete_secret_bundle.config_rs = incomplete_secret_bundle
            .config_rs
            .replace("    s3_secret_access_key: SecretValue,\n", "");
        cases.push(("incomplete secret bundle", incomplete_secret_bundle));

        let mut unready_dlx_key = baseline.clone();
        unready_dlx_key.dlx_rs = unready_dlx_key
            .dlx_rs
            .replace("DLX_HOT_KEY_READINESS_PROBE", "DLX_HOT_KEY_UNOBSERVED");
        cases.push(("unready DLX key provider", unready_dlx_key));

        let mut misattributed_dlx_key = baseline.clone();
        misattributed_dlx_key.dlx_rs = misattributed_dlx_key.dlx_rs.replace(
            "let dlx_hot_key_provider = DomainModuleResult {",
            "let lifecycle_hot_key_bait = DomainModuleResult {",
        );
        cases.push(("misattributed DLX key probe", misattributed_dlx_key));

        let mut detached_dlx_receipt = baseline.clone();
        detached_dlx_receipt.providers_rs = detached_dlx_receipt.providers_rs.replace(
            "hot_output.merge(dlx_outputs.dlx_hot_key_provider);",
            "hot_output.merge(dlx_outputs.dlx_lifecycle_repository);",
        );
        cases.push(("detached DLX key receipt", detached_dlx_receipt));

        for (name, evidence) in cases {
            let findings = validate_settingsonly_l2_evidence(&evidence);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SettingsOnlyL2ProductionClosure),
                "synthetic mutation `{name}` escaped the L2 closure gate: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn identityaudit_wire_domains_is_private() -> anyhow::Result<()> {
        let path = crate::workspace_root()?.join("assemblies/identityaudit/src/lib.rs");
        let syntax = syn::parse_file(&std::fs::read_to_string(path)?)?;
        assert!(syntax.items.iter().any(|item| matches!(
            item,
            syn::Item::Fn(function)
                if function.sig.ident == "wire_domains"
                    && matches!(function.vis, syn::Visibility::Inherited)
        )));
        Ok(())
    }

    #[test]
    fn assembly_manifest_rejects_unknown_topology() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("durable-shared", "single-node")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_manifest_rejects_unknown_listener() {
        assert!(
            AssemblyManifest::from_toml_str(
                &manifest_with_intent().replace("kind = \"primary\"", "kind = \"public\"")
            )
            .is_err()
        );
    }

    #[test]
    fn assembly_crate_without_manifest_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-manifest");
        let dir = root.join("assemblies/runtime");
        fs::create_dir_all(&dir)?;
        write(
            &dir.join("Cargo.toml"),
            r#"[package]
name = "runtime"
"#,
        )?;

        let (count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_eq!(count, 0);
        assert!(
            findings.iter().any(|f| f.rule == Rule::MissingManifest),
            "assembly crate without assembly.toml must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_revocation_store_requires_persistent_durability() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-ephemeral");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "active"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        assert_rule_or_canonical_registry_mismatch(
            &root,
            Rule::RevocationDurability,
            "diportProviders.durability",
        )?;
        Ok(())
    }

    #[test]
    fn production_revocation_store_requires_persistent_durability_even_when_draft()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-draft-ephemeral");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "draft"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"
"#,
        )?;

        assert_rule_or_canonical_registry_mismatch(
            &root,
            Rule::RevocationDurability,
            "diportProviders.durability",
        )?;
        Ok(())
    }

    #[test]
    fn production_provider_posture_rejects_non_active_and_non_governor_ephemeral()
    -> anyhow::Result<()> {
        for (name, provider_extra) in [
            (
                "draft",
                r#"lifecycle = "draft"
durability = "persistent""#,
            ),
            (
                "ephemeral",
                r#"lifecycle = "active"
durability = "ephemeral-memory""#,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-production-provider-{name}"));
            write_assembly(
                &root,
                &valid_manifest(provider_extra),
                r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
            )?;
            match validate_test_fixture_root_without_contracts(&root) {
                Ok((_count, findings)) => {
                    assert!(
                        findings
                            .iter()
                            .any(|finding| finding.rule == Rule::ProductionProviderPosture),
                        "production {name} provider must fail closed: {findings:?}"
                    );
                }
                Err(err) => {
                    let msg = format!("{err:#}");
                    assert!(
                        msg.contains("does not match canonical registry"),
                        "production {name} provider must fail closed: {msg}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn runtime_production_ratchet_does_not_depend_on_domain_membership() -> anyhow::Result<()> {
        for (name, domains) in [
            ("reduced", "contractreg"),
            ("expanded", "settings, identity, audit, contractreg"),
        ] {
            let root = unique_tmp(&format!("assembly-runtime-ratchet-{name}"));
            let manifest = valid_manifest_with_profile(
                "demo",
                r#"lifecycle = "active"
durability = "persistent""#,
            )
            .replace(
                "domains = [\"contractreg\"]",
                &format!(
                    "domains = [{}]",
                    domains
                        .split(", ")
                        .map(|domain| format!("\"{domain}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            write_assembly(
                &root,
                &manifest,
                r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
            )?;

            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            // Synthetic temp roots skip production_ratchet_applies; demo profile therefore
            // never enters production() posture. Guard that production security closeout
            // stays dark — workspace load still enforces production identities.
            assert!(
                findings.iter().all(|finding| {
                    !matches!(
                        finding.rule,
                        Rule::ProductionSecurityCriticalProvider
                            | Rule::ProductionSecurityJwksCloseout
                            | Rule::ProductionSecuritySpiffeCloseout
                            | Rule::ProductionSecurityEgressTlsCloseout
                    )
                }),
                "runtime demo fixtures must not collect production security evidence: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn production_provider_posture_allows_exact_governor_exception() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-provider-governor");
        let manifest = format!(
            "{}{}",
            valid_manifest(
                r#"lifecycle = "active"
durability = "persistent""#,
            ),
            r#"

[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "edge-rate-limit"
outputs = []
"#,
        );
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::ProductionProviderPosture),
            "exact active GovernorLimiter is the sole production ephemeral exception: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_profile_cannot_downgrade() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-runtime-demo-profile");
        write_assembly(
            &root,
            &production_security_manifest("demo", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings.iter().all(|finding| {
                !matches!(
                    finding.rule,
                    Rule::ProductionSecurityCriticalProvider
                        | Rule::ProductionSecurityJwksCloseout
                        | Rule::ProductionSecuritySpiffeCloseout
                        | Rule::ProductionSecurityEgressTlsCloseout
                )
            }),
            "runtime demo profile must not collect production security evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_critical_providers() -> anyhow::Result<()> {
        for (name, manifest, gate) in [
            (
                "assembly-production-security-missing-oidc",
                production_security_manifest("production", false, true, true),
                "gate=oidc-pdp",
            ),
            (
                "assembly-production-security-missing-vault-signer",
                production_security_manifest("production", true, false, true),
                "gate=vault-signer",
            ),
            (
                "assembly-production-security-missing-vault-keyprovider",
                production_security_manifest("production", true, true, false),
                "gate=vault-keyprovider",
            ),
        ] {
            let root = unique_tmp(name);
            write_assembly(&root, &manifest, CARGO_SECURITY_BACKEND)?;
            write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;

            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            assert!(
                findings.iter().any(|f| {
                    f.rule == Rule::ProductionSecurityCriticalProvider && f.detail.contains(gate)
                }),
                "{gate} must be required for production security closeout: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn production_security_closeout_does_not_require_signer_for_settings_subset()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-settings-subset");
        let manifest = production_security_manifest("production", true, false, true)
            .replace(
                "domains = [\"identity\", \"settings\", \"audit\"]",
                "domains = [\"settings\"]",
            )
            .replace(
                "domains = [\"settings\", \"identity\"]",
                "domains = [\"settings\"]",
            )
            .replace("domains = [\"audit\"]", "domains = []")
            .replace("\n[[listeners]]\nkind = \"internal\"\ndomains = []\n", "\n");
        write_assembly(&root, &manifest, CARGO_SECURITY_BACKEND)?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;
        write_runtime_egress_tls_closeout_config(&root)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings.iter().all(|finding| {
                finding.rule != Rule::ProductionSecurityCriticalProvider
                    || !finding.detail.contains("gate=vault-signer")
            }),
            "settings-only production must not require a dummy signer: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_jwks_runtime_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-missing-jwks");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "production assembly without JWKS runtime evidence must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_requires_spiffe_mtls_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-missing-spiffe");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_JWKS_ONLY_SOURCE)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "production assembly without SPIFFE/mTLS evidence must fail: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_ignores_comment_and_string_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
// oidc::JwksKeySource::load_and_watch(...).keys_jwks(...) OidcJwksReadyProbe::new(...)
// httpd::MtlsServerConfig::from_spire(...) httpd::DomainHttpTransport::from_spire(...)
const BAIT: &str = "JwksKeySource::load_and_watch keys_jwks OidcJwksReadyProbe::new DOMAIN_TRANSPORT_READY_PROBE_NAME MtlsServerConfig::from_spire DomainHttpTransport::from_spire";

#[cfg(test)]
mod tests {
    fn test_bait() {
        let jwks = oidc::JwksKeySource::load_and_watch("id", "path", interval, token).unwrap();
        let _ = oidc::VerifierConfigBuilder::new("iss", "aud").keys_jwks(jwks);
        let _ = OidcJwksReadyProbe::new(handle);
        let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
        let _ = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
        let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
    }
}
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "comment/string/cfg(test) JWKS bait must not satisfy production evidence: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "comment/string/cfg(test) SPIFFE bait must not satisfy production evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_ignores_cfg_test_run_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-cfg-test-run-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            r#"
#[cfg(test)]
mod tests {
    fn build_runtime_oidc_provider() {
        let jwks = oidc::JwksKeySource::load_and_watch(
            "primary-idp",
            "/etc/rss/oidc-jwks.json",
            std::time::Duration::from_secs(60),
            tokio_util::sync::CancellationToken::new(),
        ).unwrap();
        let readiness = jwks.readiness_handle();
        let _config = oidc::VerifierConfigBuilder::new("https://issuer", "rss")
            .keys_jwks(jwks);
        RuntimeOidcProvider { readiness }
    }

    fn mtls_config_from_env() {
        let _ = httpd::MtlsServerConfig::from_spire(allow_set, endpoint.as_deref());
    }

    fn wire_domain_transport_from() {
        let transport = httpd::DomainHttpTransport::from_spire(targets, endpoint.as_deref());
        let _ = DOMAIN_TRANSPORT_READY_PROBE_NAME;
        transport
    }

    fn run() {
        let runtime_oidc = build_runtime_oidc_provider();
        let provider = runtime_oidc.provider();
        module.resources.push(runtime_oidc.managed_resource());
        registry.probe(
            oidc_jwks_probe_name,
            Box::new(OidcJwksReadyProbe::new(runtime_oidc.jwks_readiness())),
        ).unwrap();
        let domain_transport = wire_domain_transport_from();
        module.merge(domain_transport.module_result().unwrap());
        let _ = mtls_config_from_env();
        let _ = finalize_listener_plan(provider);
    }
}
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "cfg(test) run() JWKS bait must not satisfy production evidence: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "cfg(test) run() SPIFFE bait must not satisfy production evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_rejects_dead_helper_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-dead-helper");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "dead helper JWKS evidence must not satisfy production closeout: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "dead helper SPIFFE evidence must not satisfy production closeout: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_rejects_each_missing_runtime_fact() -> anyhow::Result<()> {
        for (case, mutated) in [
            (
                "rss-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_rss_access_provider()",
                    "missing_rss_provider()",
                    2,
                ),
            ),
            (
                "federated-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_federated_access_provider()",
                    "missing_federated_provider()",
                    2,
                ),
            ),
            (
                "service-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "build_service_token_provider()",
                    "missing_service_provider()",
                    2,
                ),
            ),
            (
                "rss-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("ProfileBinding::RssAccess", "WrongBinding::RssAccess"),
            ),
            (
                "federated-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "ProfileBinding::FederatedAccess",
                    "WrongBinding::FederatedAccess",
                ),
            ),
            (
                "service-binding",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("ProfileBinding::ServiceToken", "WrongBinding::ServiceToken"),
            ),
            (
                "rss-probe",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "AccessTokenJwksReadyProbe::rss_access",
                    "WrongProbe::rss_access",
                ),
            ),
            (
                "federated-probe",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "AccessTokenJwksReadyProbe::federated_access",
                    "WrongProbe::federated_access",
                ),
            ),
            (
                "rss-probe-name",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
                    "WRONG_RSS_PROBE_NAME",
                ),
            ),
            (
                "federated-probe-name",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME",
                    "WRONG_FEDERATED_PROBE_NAME",
                ),
            ),
            (
                "rss-resource",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace("RSS_ACCESS_TOKEN_RESOURCE_NAME", "WRONG_RSS_RESOURCE_NAME"),
            ),
            (
                "federated-resource",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "FEDERATED_ACCESS_TOKEN_RESOURCE_NAME",
                    "WRONG_FEDERATED_RESOURCE_NAME",
                ),
            ),
            (
                "resource-registration",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "module.resources.push(rss_access.managed_resource());",
                    "",
                    1,
                ),
            ),
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-{case}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(&root, "lib.rs", &mutated)?;
            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
                "missing {case} must fail token-profile trust-chain validation: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn token_profile_gate_rejects_legacy_mixed_and_split_surfaces() -> anyhow::Result<()> {
        for (case, mutation, expected) in [
            (
                "legacy-env",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nconst LEGACY: &str = \"RSS_OIDC_ISSUER\";"
                ),
                Rule::TokenProfileLegacySurface,
            ),
            (
                "old-probe-comment",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\n// OIDC_JWKS_READY_PROBE_NAME = oidc_jwks_ready"
                ),
                Rule::TokenProfileLegacySurface,
            ),
            (
                "legacy-listener-config-decision",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn legacy(context: RouteAssemblyContext) {{ drop(context); }}"
                ),
                Rule::TokenProfileLegacySurface,
            ),
            (
                "mixed-key-provider",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE
                    .replace(".keys_hs256(service_keys)", ".keys(service_keys)"),
                Rule::TokenProfileKeyIsolation,
            ),
            (
                "split-provider-scheme",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "apply_verify_bridge(routes, rss_binding)",
                    "apply_verify_bridge(routes, rss_provider, RequiredScheme::RssAccessToken)",
                    1,
                ),
                Rule::TokenProfileBinding,
            ),
            (
                "generic-provider-type",
                format!(
                    "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn bad(provider: Arc<OidcProvider>) {{ drop(provider); }}"
                ),
                Rule::TokenProfileBinding,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-{case}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(&root, "lib.rs", &mutation)?;
            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            assert!(
                findings.iter().any(|finding| finding.rule == expected),
                "{case} must fail with {expected:?}: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn token_profile_legacy_surface_uses_exact_identifier_boundaries() -> anyhow::Result<()> {
        for collision in [
            "finalize_health_listener",
            "health_listener_v2",
            "my_health_listener",
            "éhealth_listener",
        ] {
            let root = unique_tmp(&format!("assembly-token-profile-collision-{collision}"));
            write_assembly(
                &root,
                &production_security_manifest("production", true, true, true),
                CARGO_SECURITY_BACKEND,
            )?;
            write_runtime_src(
                &root,
                "lib.rs",
                &format!("{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\nfn {collision}() {{}}"),
            )?;
            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule != Rule::TokenProfileLegacySurface),
                "identifier collision `{collision}` must not be treated as legacy: {findings:?}"
            );
        }

        let root = unique_tmp("assembly-token-profile-exact-health-listener");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            &format!(
                "{SECURITY_CLOSEOUT_RUN_PATH_SOURCE}\n\
                 #[cfg(test)] fn health_listener() {{}}\n\
                 // health_listener remains forbidden even in comments"
            ),
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileLegacySurface),
            "the exact legacy identifier must remain forbidden in cfg(test) and comments"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_rejects_bindings_discarded_before_bridge() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-discarded-bindings");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let source = security_closeout_only_rss_carrier_source();
        write_runtime_src(&root, "lib.rs", &source)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "three constructors with only RSS entering the bridge must fail: {findings:?}"
        );
        Ok(())
    }

    fn profile_binding_mapping_evidence(
        case: &str,
        source: &str,
    ) -> anyhow::Result<SecurityCloseoutEvidence> {
        let root = unique_tmp(&format!("assembly-profile-binding-mapping-{case}"));
        write_runtime_src(&root, "lib.rs", source)?;
        security_closeout_evidence_from_sources(&root.join("assemblies/runtime"))
    }

    #[test]
    fn token_profile_carrier_requires_exact_typed_mapping() -> anyhow::Result<()> {
        let green = profile_binding_mapping_evidence("green", PROFILE_BINDING_MAPPING_SOURCE)?;
        assert!(green.rss_access_reaches_verify_bridge());
        assert!(green.federated_access_reaches_verify_bridge());
        assert!(green.service_token_reaches_verify_bridge());

        let swapped = PROFILE_BINDING_MAPPING_SOURCE
            .replacen(
                "ProfileBinding::RssAccess(provider)),",
                "ProfileBinding::__SwapPlaceholder(provider)),",
                1,
            )
            .replacen(
                "ProfileBinding::FederatedAccess(provider)),",
                "ProfileBinding::RssAccess(provider)),",
                1,
            )
            .replacen(
                "ProfileBinding::__SwapPlaceholder(provider)),",
                "ProfileBinding::FederatedAccess(provider)),",
                1,
            );
        let wildcard = PROFILE_BINDING_MAPPING_SOURCE
            .replace("AuthScheme::FederatedAccessToken => self", "_ => self");
        let alias = PROFILE_BINDING_MAPPING_SOURCE.replace(
            r#"AuthScheme::RssAccessToken => self
                .rss_access
                .map(|provider| ProfileBinding::RssAccess(provider)),"#,
            r#"AuthScheme::RssAccessToken => {
                let alias = self
                    .rss_access
                    .map(|provider| ProfileBinding::RssAccess(provider));
                alias
            },"#,
        );
        let wrong_receiver = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.profile_binding(scheme)",
            "decoy.profile_binding(scheme)",
        );
        let hardcoded = PROFILE_BINDING_MAPPING_SOURCE.replace(
            "providers.profile_binding(scheme)",
            "providers.profile_binding(AuthScheme::RssAccessToken)",
        );
        let selection_alias = PROFILE_BINDING_MAPPING_SOURCE
            .replace(
                "let scheme = spec.auth_scheme();",
                "let scheme = spec.auth_scheme();\n    let selected = scheme;",
            )
            .replace(
                "providers.profile_binding(scheme)",
                "providers.profile_binding(selected)",
            );
        let service_mismatch = PROFILE_BINDING_MAPPING_SOURCE.replacen(
            "ProfileBinding::ServiceToken(provider))",
            "ProfileBinding::RssAccess(provider))",
            1,
        );

        for (case, source) in [
            ("swapped", swapped),
            ("wildcard", wildcard),
            ("alias", alias),
            ("wrong-receiver", wrong_receiver),
            ("hardcoded-selection", hardcoded),
            ("selection-alias", selection_alias),
        ] {
            let evidence = profile_binding_mapping_evidence(case, &source)?;
            assert!(
                !evidence.rss_access_reaches_verify_bridge()
                    || !evidence.federated_access_reaches_verify_bridge(),
                "{case} must not certify both access-profile mappings"
            );
        }
        let service = profile_binding_mapping_evidence("service-mismatch", &service_mismatch)?;
        assert!(
            !service.service_token_reaches_verify_bridge(),
            "service binding must map the service provider field to ServiceToken"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_ignores_dead_profile_bridge_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-dead-bridge-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let source = security_closeout_only_rss_carrier_source();
        let source = format!(
            r#"{source}
fn dead_bridge_bait(federated_binding: ProfileBinding, service_binding: ProfileBinding) {{
    let _ = apply_verify_bridge(routes, federated_binding);
    let _ = apply_verify_bridge(routes, service_binding);
}}
"#
        );
        write_runtime_src(&root, "lib.rs", &source)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "dead helper bridge calls must not associate discarded production bindings: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn token_profile_trust_chain_ignores_comment_string_and_cfg_test_bait() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-token-profile-bait");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        let bait = format!(
            r#"
{SECURITY_CLOSEOUT_SPIFFE_ONLY_SOURCE}
// build_rss_access_provider build_federated_access_provider build_service_token_provider
const BAIT: &str = "ProfileBinding::RssAccess ProfileBinding::FederatedAccess ProfileBinding::ServiceToken AccessTokenJwksReadyProbe::rss_access AccessTokenJwksReadyProbe::federated_access";
#[cfg(test)]
fn run() {{
    let rss = build_rss_access_provider();
    let fed = build_federated_access_provider();
    let service = build_service_token_provider();
    module.resources.push(rss.managed_resource());
    module.resources.push(fed.managed_resource());
    module.resources.push(service.managed_resource());
    registry.probe(RSS_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, AccessTokenJwksReadyProbe::rss_access(rss.jwks_readiness()));
    registry.probe(FEDERATED_ACCESS_TOKEN_JWKS_READY_PROBE_NAME, AccessTokenJwksReadyProbe::federated_access(fed.jwks_readiness()));
    let _ = RSS_ACCESS_TOKEN_RESOURCE_NAME;
    let _ = FEDERATED_ACCESS_TOKEN_RESOURCE_NAME;
    let _ = SERVICE_TOKEN_RESOURCE_NAME;
    let _ = apply_verify_bridge(routes, ProfileBinding::RssAccess(rss.provider()));
    let _ = apply_verify_bridge(routes, ProfileBinding::FederatedAccess(fed.provider()));
    let _ = apply_verify_bridge(routes, ProfileBinding::ServiceToken(service.provider()));
}}
"#
        );
        write_runtime_src(&root, "lib.rs", &bait)?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::TokenProfileTrustChain),
            "comment/string/cfg(test) facts must not satisfy token-profile trust chain: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_runtime_token_profile_bridge_is_reachable_through_typed_phases() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let evidence = security_closeout_evidence_from_sources(&root.join("assemblies/runtime"))?;
        assert!(
            evidence.rss_access_reaches_verify_bridge()
                && evidence.federated_access_reaches_verify_bridge()
                && evidence.service_token_reaches_verify_bridge(),
            "real runtime typed bridge closure drifted: mapping={} carrier={} rss_typed={} admin_typed={} service_typed={} rss_packed={} federated_packed={} service_packed={}",
            evidence.exact_profile_binding_mapping,
            evidence.profile_carrier_bound_to_verify_bridge,
            evidence.typed_primary_access_binding_carrier_call,
            evidence.typed_admin_access_binding_carrier_call,
            evidence.typed_service_binding_carrier_call,
            evidence.rss_access_packed_in_profile_carrier,
            evidence.federated_access_packed_in_profile_carrier,
            evidence.service_token_packed_in_profile_carrier,
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_full_fixture_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_RUN_PATH_SOURCE)?;
        write_runtime_egress_tls_closeout_config(&root)?;
        write_distributed_consumer_fixture(&root)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings.iter().all(|finding| matches!(
                finding.rule,
                Rule::RuntimeInventoryProviderProvenance | Rule::RuntimeInventoryListenerProvenance
            )),
            "security closeout fixture emitted unrelated findings: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_run_to_launch_fixture_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-run-launch-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", &security_closeout_run_to_launch_source())?;
        write_runtime_src(&root, "launch.rs", SECURITY_CLOSEOUT_LAUNCH_SOURCE)?;
        write_runtime_egress_tls_closeout_config(&root)?;
        write_distributed_consumer_fixture(&root)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings.iter().all(|finding| matches!(
                finding.rule,
                Rule::RuntimeInventoryProviderProvenance | Rule::RuntimeInventoryListenerProvenance
            )),
            "security closeout fixture emitted unrelated findings: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_follows_qualified_lifecycle_owner_run() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-lifecycle-owner-green");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", &security_closeout_lifecycle_owner_source())?;
        write_runtime_egress_tls_closeout_config(&root)?;
        write_distributed_consumer_fixture(&root)?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings.iter().all(|finding| matches!(
                finding.rule,
                Rule::RuntimeInventoryProviderProvenance | Rule::RuntimeInventoryListenerProvenance
            )),
            "security closeout fixture emitted unrelated findings: {findings:?}"
        );
        Ok(())
    }

    fn egress_tls_closeout_fixture_root(label: &str) -> anyhow::Result<std::path::PathBuf> {
        let root = unique_tmp(label);
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(&root, "lib.rs", SECURITY_CLOSEOUT_RUN_PATH_SOURCE)?;
        write_distributed_consumer_fixture(&root)?;
        Ok(root)
    }

    fn assert_egress_tls_finding(findings: &[Finding], gate: &str, message: &str) {
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ProductionSecurityEgressTlsCloseout && f.detail.contains(gate)
            }),
            "{message}: {findings:?}"
        );
    }

    #[test]
    fn production_security_closeout_rejects_egress_tls_downgrade_catalog_regressions()
    -> anyhow::Result<()> {
        let root = egress_tls_closeout_fixture_root("assembly-production-security-egress-tls-red")?;

        // Missing config catalogs → fail closed.
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-serving-keys",
            "missing FORBIDDEN/FIXED serving-key catalogs must fail",
        );

        // Banned key only in FIXED (and absent from FORBIDDEN) → fail.
        write_runtime_src(
            &root,
            "config.rs",
            r#"
const FORBIDDEN_SERVING_KEYS: &[&str] = &["RSS_ACCESS_TOKEN_TRUSTED_KINDS"];
const FIXED_SERVING_KEYS: &[&str] = &[
    "RSS_LISTENER_ALLOW_PLAINTEXT",
    "RSS_AMQP_ALLOW_PLAINTEXT",
    "RSS_REDIS_ALLOW_PLAINTEXT",
    "RSS_S3_ALLOW_PLAINTEXT",
    "RSS_PG_SSL_MODE",
];
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-serving-keys",
            "reintroducing banned keys into FIXED_SERVING_KEYS must fail",
        );

        // Comment / cfg(test) string bait must not satisfy the forbidden catalog.
        write_runtime_src(
            &root,
            "config.rs",
            r#"
// FORBIDDEN_SERVING_KEYS: RSS_AMQP_ALLOW_PLAINTEXT RSS_REDIS_ALLOW_PLAINTEXT RSS_S3_ALLOW_PLAINTEXT RSS_PG_SSL_MODE
const FORBIDDEN_SERVING_KEYS: &[&str] = &["RSS_ACCESS_TOKEN_TRUSTED_KINDS"];
const FIXED_SERVING_KEYS: &[&str] = &["RSS_LISTENER_ALLOW_PLAINTEXT"];

#[cfg(test)]
mod tests {
    const FORBIDDEN_SERVING_KEYS: &[&str] = &[
        "RSS_AMQP_ALLOW_PLAINTEXT",
        "RSS_REDIS_ALLOW_PLAINTEXT",
        "RSS_S3_ALLOW_PLAINTEXT",
        "RSS_PG_SSL_MODE",
    ];
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-serving-keys",
            "comment/cfg(test) bait must not satisfy egress TLS ban catalog",
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_rejects_egress_tls_private_ca_regressions() -> anyhow::Result<()>
    {
        let root =
            egress_tls_closeout_fixture_root("assembly-production-security-egress-tls-private-ca")?;
        write_runtime_egress_tls_closeout_config(&root)?;

        // Good catalogs but plaintext Redis wiring → private-CA gate fails.
        write_runtime_src(
            &root,
            "infra/redis.rs",
            r#"
pub async fn build_redis_runtime_deps() {
    let _ = redis::RedisRuntimeDeps::connect_allow_plaintext(&endpoint);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "Redis wiring without private CA must fail",
        );

        // cfg(test) private-CA bait must not satisfy production wiring evidence.
        write_runtime_src(
            &root,
            "infra/redis.rs",
            r#"
pub async fn build_redis_runtime_deps() {
    let _ = redis::RedisRuntimeDeps::connect_allow_plaintext(&endpoint);
}

#[cfg(test)]
mod tests {
    fn bait() {
        let _ = redis::RedisPrivateCa::from_pem(b"");
        let _ = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca);
    }
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "cfg(test) private-CA bait must not satisfy production wiring",
        );

        // Dead non-test module private-CA bait + production plaintext path must fail.
        write_runtime_src(
            &root,
            "infra/redis.rs",
            r#"
mod unused_private_ca_bait {
    pub fn bait() {
        let _ = redis::RedisPrivateCa::from_pem(b"");
        let _ = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca);
    }
}

pub async fn build_redis_runtime_deps() {
    let _ = redis::RedisRuntimeDeps::connect_allow_plaintext(&endpoint);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "dead-module private-CA bait with plaintext production path must fail",
        );

        // private-CA identifiers coexisting with connect_allow_plaintext must fail.
        write_runtime_src(
            &root,
            "infra/redis.rs",
            r#"
pub async fn build_redis_runtime_deps() {
    let ca = redis::RedisPrivateCa::from_pem(pem).unwrap();
    let _ = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca);
    let _ = redis::RedisRuntimeDeps::connect_allow_plaintext(&endpoint);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "private-CA coexistence with connect_allow_plaintext must fail",
        );

        // Redis OK but S3 lacks PrivateCaS3ClientFactory → fail.
        write_runtime_src(
            &root,
            "infra/redis.rs",
            r#"
pub async fn build_redis_runtime_deps() {
    let ca = redis::RedisPrivateCa::from_pem(pem).unwrap();
    let _ = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca);
}
"#,
        )?;
        write_runtime_src(
            &root,
            "infra/s3.rs",
            r#"
pub fn build_s3_runtime_deps() {
    let _ = aws_sdk_s3::Client::from_conf(config);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "S3 wiring without PrivateCaS3ClientFactory must fail",
        );

        // Redis+S3 OK but AMQP plaintext → fail.
        write_runtime_src(
            &root,
            "infra/s3.rs",
            r#"
pub fn build_s3_runtime_deps() {
    let _ = s3::PrivateCaS3ClientFactory::new(endpoint, ca);
}
"#,
        )?;
        write_runtime_src(
            &root,
            "event_transport.rs",
            r#"
pub async fn wire_amqp() {
    let _ = amqp::AmqpRuntimeDeps::connect_allow_plaintext(endpoint, name);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "AMQP wiring without private CA must fail",
        );

        // Redis+S3+AMQP OK but PG lacks VerifyFull/root cert → fail.
        write_runtime_src(
            &root,
            "event_transport.rs",
            r#"
pub async fn wire_amqp() {
    let ca = amqp::AmqpPrivateCa::from_pem(pem).unwrap();
    let _ = amqp::AmqpRuntimeDeps::connect_with_private_ca(endpoint, name, ca);
}
"#,
        )?;
        write_runtime_src(
            &root,
            "infra/pg.rs",
            r#"
pub fn build_pg() {
    let _ = PgConfig::new(host, port, database, username, password);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_egress_tls_finding(
            &findings,
            "gate=egress-tls-private-ca",
            "PG wiring without VerifyFull+with_ssl_root_cert must fail",
        );

        // Green catalogs + private-CA wiring (Redis/AMQP/S3/PG) → no egress TLS findings.
        write_runtime_src(
            &root,
            "infra/pg.rs",
            r#"
pub fn build_pg() {
    let _ = PgConfig::new(host, port, database, username, password)
        .with_ssl_mode(PgSslMode::VerifyFull)
        .with_ssl_root_cert(path);
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .all(|f| f.rule != Rule::ProductionSecurityEgressTlsCloseout),
            "closed catalogs + private-CA wiring must pass egress TLS gate: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_runtime_egress_tls_closeout_accepts_workspace() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let dir = root.join("assemblies/runtime");
        let evidence = runtime_egress_tls_closeout_evidence(&dir)?;
        assert!(
            evidence.serving_keys_ok(),
            "real runtime must keep banned egress TLS keys in FORBIDDEN_SERVING_KEYS and out of FIXED_SERVING_KEYS"
        );
        assert!(
            evidence.private_ca_checked && evidence.private_ca_ok,
            "real runtime must wire Redis/AMQP/S3/PG through private-CA funnels"
        );
        Ok(())
    }

    #[test]
    fn production_security_closeout_rejects_disconnected_free_run() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-production-security-disconnected-free-run");
        write_assembly(
            &root,
            &production_security_manifest("production", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;
        write_runtime_src(
            &root,
            "lib.rs",
            &security_closeout_disconnected_free_run_source(),
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "disconnected impl method named run must not lend JWKS evidence to free run: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "disconnected impl method named run must not lend SPIFFE evidence to free run: {findings:?}"
        );

        let associated_call_bait = security_closeout_disconnected_free_run_source()
            .replace("fn run_startup()", "fn decoy()")
            .replace("        run_startup();\n", "")
            .replace("pub fn run() {}", "pub fn run() { DeadOwner::decoy(); }");
        write_runtime_src(&root, "lib.rs", &associated_call_bait)?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecurityJwksCloseout),
            "Type::method must not resolve to an evidence-bearing free function with the same name: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ProductionSecuritySpiffeCloseout),
            "associated/free function identities must remain disjoint for SPIFFE evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn full_runtime_demo_profile_is_rejected_before_security_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-demo-security-no-evidence");
        write_assembly(
            &root,
            &production_security_manifest("demo", true, true, true),
            CARGO_SECURITY_BACKEND,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        // Synthetic fixtures skip production identity ratchet; demo profile must still
        // stay outside production security evidence collection.
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::ProductionSecurityCriticalProvider
                    | Rule::ProductionSecurityJwksCloseout
                    | Rule::ProductionSecuritySpiffeCloseout
                    | Rule::ProductionSecurityEgressTlsCloseout
            )),
            "full runtime demo profile must not collect production security evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_crate_must_be_declared_in_assembly_cargo_toml() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-provider-dep");
        write_assembly(
            &root,
            &valid_manifest(
                r#"lifecycle = "active"
durability = "persistent""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
deviceloop = { path = "../../crates/deviceloop" }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderDependency),
            "active provider missing from Cargo.toml must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_required_feature_must_be_enabled() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-missing-provider-feature");
        let manifest = format!(
            "{}\n{}",
            manifest_with_intent(),
            r#"[[diportProviders]]
id = "event-publisher"
port = "diport::Publisher"
provider = "amqp::AmqpPublisher"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "active"
durability = "persistent"
purpose = "outbox-relay-amqp-publish"
outputs = ["probes", "resources", "workers"]
"#,
        );
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
amqp = { path = "../../adapters/amqp" }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active AMQP provider without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn unknown_provider_is_rejected_by_typed_manifest() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-unknown-active-provider");
        let manifest = manifest_with_intent()
            .replace("postgres::PgRevocationStore", "postgres::MissingProvider");
        write_assembly(
            &root,
            &manifest,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let Err(error) = validate_test_fixture_root_without_contracts(&root) else {
            bail!("unknown typed provider must fail to parse");
        };
        assert!(
            format!("{error:#}").contains("postgres::MissingProvider"),
            "typed provider diagnostic lost the rejected constructor: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn active_provider_declared_durability_must_match_known_provider() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-durability-mismatch");
        write_assembly(
            &root,
            &valid_manifest_with_profile(
                "demo",
                r#"lifecycle = "active"
durability = "ephemeral-memory""#,
            ),
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        assert_rule_or_canonical_registry_mismatch(
            &root,
            Rule::ProviderDurabilityMismatch,
            "diportProviders.durability",
        )?;
        Ok(())
    }

    #[test]
    fn active_rate_limiter_provider_passes() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-rate-limiter-active");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "device-revocation-store"
port = "diport::RevocationStore"
provider = "postgres::PgRevocationStore"
providerCrate = "postgres"
requiredFeatures = []
consumer = "deviceloop"
lifecycle = "active"
durability = "persistent"
purpose = "device-certificate-revocation"
outputs = ["probes", "workers"]

[[diportProviders]]
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting (pre-auth, DoS/brute-force 防护)"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres" }
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    /// distributed Lock（redis, backend feature）+ Cas（postgres）provider 矩阵识别 + feature/crate 绑定绿测。
    /// 实 assembly.toml 现声明为 draft（#332 F4 无 consumer），本测以合成 active manifest 验证 validator 对
    /// Lock/CasStore active provider 的识别路径（go-live 翻转 active 时复用）。
    #[test]
    fn active_distributed_lock_cas_providers_pass() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-distributed-lock-cas-active");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]

[[diportProviders]]
id = "distributed-cas-store"
port = "diport::CasStore"
provider = "postgres::PgCasStore"
providerCrate = "postgres"
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-state-cas"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;
        write_runtime_src(
            &root,
            "phase/domains.rs",
            r#"
pub struct InfraBuilt;

impl InfraBuilt {
    pub async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)
                    .context("wire distributed")?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            )
            .await
            .context("wire event transport")?;
            Ok::<_, anyhow::Error>(event_module)
        }
        .await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn distributed_consumer_evidence_rejects_same_name_and_alias_decoys() -> anyhow::Result<()> {
        let canonical = r#"
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let distributed =
                crate::distributed_runtime::wire_distributed(&deps, distributed_worker)?;
            let event_module = crate::event_transport::wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#;
        assert!(
            file_has_distributed_consumer_evidence(&syn::parse_file(canonical)?),
            "canonical fully-qualified producer and consumer paths must pass"
        );

        let same_name_decoy = canonical.replace(
            "crate::distributed_runtime::wire_distributed",
            "crate::decoy::wire_distributed",
        );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&same_name_decoy)?),
            "same-name producer in a non-canonical module must be rejected"
        );

        let alias_decoy = canonical
            .replace(
                "impl InfraBuilt {",
                "use crate::distributed_runtime::wire_distributed as build_distributed;\n\nimpl InfraBuilt {",
            )
            .replace(
                "crate::distributed_runtime::wire_distributed",
                "build_distributed",
            );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&alias_decoy)?),
            "aliases are intentionally unsupported and must be rejected"
        );

        let consumer_decoy = canonical.replace(
            "crate::event_transport::wire_event_transport",
            "crate::decoy::wire_event_transport",
        );
        assert!(
            !file_has_distributed_consumer_evidence(&syn::parse_file(&consumer_decoy)?),
            "same-name consumer in a non-canonical module must be rejected"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_reordered_comment_or_test_bait_is_rejected() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-distributed-string-evidence");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;
        write_runtime_src(
            &root,
            "phase/domains.rs",
            r#"
#[cfg(test)]
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let distributed = wire_distributed(&deps, distributed_worker)?;
            let event_module = wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}

impl InfraBuilt {
    async fn wire_domains(self) {
        // wire_distributed(&deps, distributed_worker)
        let result = async move {
            let _bait = "wire_event_transport(&deps.pg, distributed)";
            Ok::<_, anyhow::Error>(())
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}

fn outer_bait() {
    let distributed = wire_distributed(&deps, distributed_worker);
    let _ = wire_event_transport(&deps.pg, distributed);
}
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "comment/string/cfg(test)/outer-function bait must not satisfy the phase-owner consumer guard: {findings:?}"
        );

        write_runtime_src(
            &root,
            "phase/domains.rs",
            r#"
impl InfraBuilt {
    async fn wire_domains(self) {
        let result = async move {
            let event_module = wire_event_transport(
                &deps.pg,
                distributed,
                event_subscribers,
                event_transport,
                event_worker,
                audit_consumer_key,
            ).await?;
            let distributed = wire_distributed(&deps, distributed_worker)?;
            Ok::<_, anyhow::Error>(event_module)
        }.await;
        phase_result(<Self as RuntimePhaseState>::PHASE, result)
    }
}
"#,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "a consumer ordered before its distributed producer must fail closed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn active_distributed_provider_without_domains_phase_consumer_is_rejected() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-distributed-no-consumer");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "distributed-lock-store"
port = "diport::LockStore"
provider = "redis::RedisLockStore"
providerCrate = "redis"
requiredFeatures = ["backend"]
consumer = "distributed"
lifecycle = "active"
durability = "persistent"
purpose = "distributed-lock-fencing"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
redis = { path = "../../adapters/redis", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveDistributedProviderConsumer),
            "active distributed provider without consumer evidence must be rejected: {findings:?}"
        );
        Ok(())
    }

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "check", source = "code" }— provider↔providerCrate 绑定 red test（anti-vacuity）。
    /// `ratelimit::GovernorLimiter` 与 `providerCrate = "softca"` 不匹配，active 声明必须被拒。
    #[test]
    fn active_provider_with_wrong_provider_crate_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-mismatch");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "softca"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
softca = { path = "../../adapters/softca" }
"#,
        )?;

        assert_rule_or_canonical_registry_mismatch(
            &root,
            Rule::ProviderCrateMismatch,
            "diportProviders.providerCrate",
        )?;
        Ok(())
    }

    /// INVARIANT: ASSEMBLY-PROVIDER-CRATE-01 { level = "Medium", exec = "check", source = "code" }— provider↔providerCrate 绑定正例（non-vacuous green path）。
    /// `ratelimit::GovernorLimiter` + `providerCrate = "ratelimit"` 正确绑定，不应产生 ProviderCrateMismatch。
    #[test]
    fn active_provider_with_correct_provider_crate_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-provider-crate-correct");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "listener-rate-limiter"
port = "diport::RateLimiter"
provider = "ratelimit::GovernorLimiter"
providerCrate = "ratelimit"
consumer = "httpserve"
lifecycle = "active"
durability = "ephemeral-memory"
purpose = "per-peer-IP request rate limiting"
outputs = []
"#,
            r#"[package]
name = "runtime"

[dependencies]
ratelimit = { path = "../../adapters/ratelimit" }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .all(|f| f.rule != Rule::ProviderCrateMismatch),
            "correct providerCrate must not produce ProviderCrateMismatch: {findings:?}"
        );
        Ok(())
    }

    // ---- #1251 eventbus typed transport providers ----

    #[allow(clippy::panic)]
    fn amqp_manifest(provider: &str, port: &str, lifecycle: &str, durability: &str) -> String {
        let role = match provider {
            "amqp::AmqpPublisher" => "event-publisher",
            "amqp::AmqpSubscriber" => "event-subscriber",
            _ => panic!("test helper only admits closed AMQP providers"),
        };
        format!(
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "{role}"
port = "{port}"
provider = "{provider}"
providerCrate = "amqp"
requiredFeatures = ["backend"]
consumer = "eventexec"
lifecycle = "{lifecycle}"
durability = "{durability}"
purpose = "eventbus-transport"
outputs = ["probes", "resources", "workers"]
"#,
        )
    }

    const CARGO_AMQP_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#;

    const CARGO_AMQP_NO_BACKEND: &str = r#"[package]
name = "runtime"

[dependencies]
amqp = { path = "../../adapters/amqp" }
"#;

    #[test]
    fn amqp_publisher_active_persistent_with_backend_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-publisher-green");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::Publisher",
                "active",
                "persistent",
            ),
            CARGO_AMQP_BACKEND,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn amqp_subscriber_active_persistent_with_backend_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-subscriber-green");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpSubscriber",
                "diport::AckableSubscriber",
                "active",
                "persistent",
            ),
            CARGO_AMQP_BACKEND,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn active_vault_signer_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-vault-signer");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "identity-signer"
port = "diport::Signer"
provider = "vault::VaultSigner"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "jwt-access-token-signing"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn active_vault_keyprovider_with_dependency_and_required_feature_is_allowed()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-vault-keyprovider");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "settings-key-provider"
port = "diport::KeyProvider"
provider = "vault::VaultKeyProvider"
providerCrate = "vault"
requiredFeatures = ["backend"]
consumer = "settings"
lifecycle = "active"
durability = "persistent"
purpose = "settings-configvalue-at-rest-encryption"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
vault = { path = "../../adapters/vault", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn active_oidc_pdp_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-active-oidc-pdp");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
outputs = ["resources"]

[[diportProviders]]
id = "service-token-replay-store"
port = "diport::ServiceTokenReplayStore"
provider = "postgres::PgServiceTokenReplayStore"
providerCrate = "postgres"
consumer = "oidc"
lifecycle = "active"
durability = "persistent"
scope = "cluster-global"
failurePosture = "fail-closed"
purpose = "service-token-atomic-replay-consume"
outputs = ["probes", "resources", "workers"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
oidc = { path = "../../adapters/oidc", features = ["backend"] }
postgres = { path = "../../adapters/postgres" }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn active_s3_object_store_with_dependency_and_required_feature_is_allowed() -> anyhow::Result<()>
    {
        let root = unique_tmp("assembly-active-s3-object-store");
        write_assembly(
            &root,
            r#"
schemaVersion = 2
name = "runtime"
profile = "demo"
domains = ["contractreg"]
topology = "demo"
frameworkContracts = []
workflowActivations = []

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
id = "runtime-object-store"
port = "diport::ObjectStore"
provider = "s3::S3Store"
providerCrate = "s3"
requiredFeatures = ["backend"]
consumer = "runtime"
lifecycle = "active"
durability = "persistent"
purpose = "runtime-s3-readiness-canary"
outputs = ["resources"]
"#,
            r#"[package]
name = "runtime"

[dependencies]
s3 = { path = "../../adapters/s3", features = ["backend"] }
"#,
        )?;

        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert_no_provider_validation_findings(&findings);
        Ok(())
    }

    #[test]
    fn amqp_subscriber_active_without_backend_feature_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-subscriber-no-backend");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpSubscriber",
                "diport::AckableSubscriber",
                "active",
                "persistent",
            ),
            CARGO_AMQP_NO_BACKEND,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active amqp subscriber without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn amqp_publisher_active_without_backend_feature_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-amqp-publisher-no-backend");
        write_assembly(
            &root,
            &amqp_manifest(
                "amqp::AmqpPublisher",
                "diport::Publisher",
                "active",
                "persistent",
            ),
            CARGO_AMQP_NO_BACKEND,
        )?;
        let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::ActiveProviderFeature),
            "active amqp publisher without backend feature must be rejected: {findings:?}"
        );
        Ok(())
    }
}
