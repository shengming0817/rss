//! `assembly validate` —— assembly-level DI provider 声明治理。
//!
//! DI-infra port（如 `diport::RevocationStore` / `diport::LockStore` / `diport::CasStore`）不是跨域 wire
//! contract，不放进 `contracts/**/contract.toml`。
//! 但 provider 选择属于组合根部署事实：哪个 assembly 注入哪个 provider、是否持久、是否已 active，必须有机器可读
//! 声明和 verify 门，避免生产在 dev/demo provider 上静默运行。

use anyhow::{Context, Result};
#[cfg(test)]
use assembly_schema::AssemblyManifest;
use assembly_schema::{
    AssemblyDomain, AssemblyProfile, AssemblyTopology, CanonicalAssemblyManifestV2, DiportPort,
    DiportProvider, LifecycleChannel, ProviderConstructor, ProviderConsumer, ProviderDurability,
    ProviderFailurePosture, ProviderLifecycle, ProviderRole, ProviderScope,
};
use quote::ToTokens as _;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Stdio;
use workspacefacts::{
    BuildFacts, BuildPlatforms, BuildSelection, BuildSide, CargoPlatform, DependencyKind,
    DependencySource, FeatureSelection, PackageKey, ResolverVersion, WorkspaceFacts,
};

#[cfg(test)]
use crate::assembly_governance::AssemblyFixtureBuilder;
use crate::assembly_governance::{
    AssemblyGovernanceIr, Core, GovernedAssembly, ProductionAssembly, load_artifact_declaration,
};
use crate::contract::GovernedContract;
use crate::contract::governance::ContractGovernanceIr;
use crate::contract::governance::validate_workflow_activations;
use crate::diagnostic::{self, GovernanceCheck, finding};

#[derive(Debug)]
pub(crate) enum AssemblyCargoFactsError {
    UnresolvedDependency {
        assembly: String,
        dependency: String,
    },
}

impl std::fmt::Display for AssemblyCargoFactsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnresolvedDependency {
                assembly,
                dependency,
            } => write!(
                formatter,
                "assembly `{assembly}` direct normal dependency `{dependency}` is unresolved"
            ),
        }
    }
}

impl std::error::Error for AssemblyCargoFactsError {}

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    /// Root workspace must carry the strict positive Release Surface declaration.
    ReleaseSurfaceDeclaration,
    /// Cargo publishable packages and selected release packages must be an exact set.
    ReleaseSurfaceExactSet,
    /// Selected package/API facts must resolve and remain internally consistent.
    ReleaseSurfacePackage,
    /// Candidate packages must carry complete Cargo publish metadata and an explicit empty default feature.
    ReleasePackageMetadata,
    /// Candidate normal/build workspace path dependencies must form an exact, versioned publish closure.
    ReleasePublishClosure,
    /// Official profile selection must explicitly join the designated supported artifact.
    ReleaseSurfaceProfile,
    /// `assemblies/*/Cargo.toml` 必须有同目录 `assembly.toml`。
    MissingManifest,
    /// manifest 声明的 active domain 必须是 assembly crate 的直接 normal dependency。
    ActiveDomainDependency,
    /// 未声明 domain 不得进入 assembly normal dependency closure。
    InactiveDomainDependencyClosure,
    /// production default Cargo graph不得启用 test-support。
    ///
    /// INVARIANT: ASSEMBLY-PRODUCTION-TEST-SUPPORT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::assembly_default_test_support_is_rejected", anti_vacuity = "tests::assembly_domain_real_workspace_closures_match_manifests" }.
    ProductionTestSupport,
    /// identityaudit 必须保持独立的 production manifest profile/topology/listener语义。
    ///
    /// INVARIANT: IDENTITYAUDIT-MANIFEST-BOUNDARY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::identityaudit_manifest_boundary_rejects_profile_topology_and_listener_drift", anti_vacuity = "tests::identityaudit_real_manifest_boundary_is_exact" }.
    IdentityAuditManifestBoundary,
    /// Framework contract declarations must exactly cover active framework-owned contracts.
    FrameworkContractServing,
    /// Workflow activation must exactly join one repository definition and valid lifecycle.
    WorkflowActivation,
    /// Listener observations are minted only at the three production launch roots and directly
    /// consume the successfully bound server handle's `local_addr()`.
    ///
    /// INVARIANT: RUNTIME-INVENTORY-LISTENER-PROVENANCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtime_inventory_listener_provenance_rejects_detached_dead_or_swapped_flow", anti_vacuity = "tests::runtime_inventory_listener_provenance_real_launch_roots_are_exact" } -- only run/activate-reachable observations minted from the matching successful bound handle may flow into the typed inventory publisher.
    RuntimeInventoryListenerProvenance,
    /// Production run/prepare reachability must consume generated provider selection through the
    /// typed finish/transfer path and inventory publication.
    ///
    /// INVARIANT: PROVIDER-CONSTRUCTION-LIVE-JOIN-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::provider_construction_live_join_rejects_bypassed_or_dead_stages", anti_vacuity = "tests::provider_construction_live_join_real_assemblies_are_exact" }.
    ProviderConstructionLiveJoin,
    /// Dylint does not compile `#[cfg(test)]` trees, so settingsonly's complete source AST must
    /// independently reject raw JWT reparse APIs in every cfg branch.
    ///
    /// INVARIANT: SETTINGSONLY-RAW-JWT-REPARSE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::settingsonly_raw_jwt_reparse_rejects_cfg_test_alias_and_pointer_bait", anti_vacuity = "tests::settingsonly_raw_jwt_reparse_real_workspace_is_clean" }.
    SettingsOnlyRawJwtReparse,
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

pub(crate) struct AssemblyValidate<'a> {
    root: &'a Path,
    facts: &'a WorkspaceFacts,
}

impl<'a> AssemblyValidate<'a> {
    pub(crate) fn new(root: &'a Path, facts: &'a WorkspaceFacts) -> Self {
        Self { root, facts }
    }
}

impl GovernanceCheck for AssemblyValidate<'_> {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "assembly validate"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        crate::workspace_facts::validate_command_funnel(self.root)?;
        crate::assembly_governance::validate_source_funnel(self.root)?;
        let ir = AssemblyGovernanceIr::<Core>::load(self.root)?;
        let (count, mut findings) = validate_governed_root(self.root, self.facts, &ir)?;
        let artifact_projections = if crate::release_surface::requires_artifact_join(self.facts) {
            let joined = ir.join_artifacts(load_artifact_declaration(self.root)?)?;
            crate::release_surface::project_artifacts(&joined)
        } else {
            Vec::new()
        };
        let (surface, release_findings) =
            crate::release_surface::validate(self.facts, &artifact_projections);
        findings.extend(release_findings);
        let (release_package_count, profile_artifact_count, observed_summary) = surface
            .as_ref()
            .map(|surface| {
                (
                    surface.packages().len(),
                    surface.profile_artifacts().len(),
                    surface.observed_summary(),
                )
            })
            .unwrap_or_else(|| (0, 0, "release surface rejected".to_owned()));
        Ok((
            format!(
                "{count} assembly 声明、{} release package 与 {} profile artifact 全部通过；{}",
                release_package_count, profile_artifact_count, observed_summary
            ),
            findings,
        ))
    }
}

#[cfg(test)]
pub(crate) fn validate_root(root: &Path, facts: &WorkspaceFacts) -> Result<(usize, Vec<Finding>)> {
    let contract_governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    let ir = AssemblyGovernanceIr::<Core>::load(root)?;
    validate_governed_root_with_contracts(root, facts, &ir, &contract_governance)
}

pub(crate) fn validate_governed_root(
    root: &Path,
    facts: &WorkspaceFacts,
    ir: &AssemblyGovernanceIr<Core>,
) -> Result<(usize, Vec<Finding>)> {
    let contract_governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    validate_governed_root_with_contracts(root, facts, ir, &contract_governance)
}

fn validate_governed_root_with_contracts(
    root: &Path,
    facts: &WorkspaceFacts,
    ir: &AssemblyGovernanceIr<Core>,
    contract_governance: &ContractGovernanceIr,
) -> Result<(usize, Vec<Finding>)> {
    contract_governance.read(|contracts| {
        let mut findings = discovery_findings(root, ir);
        findings.extend(validate_workflow_activation_contracts(
            ir.assemblies(),
            contracts,
        ));
        findings.extend(validate_framework_contracts(
            root,
            ir.assemblies(),
            contracts,
        ));
        validate_discovered_root(root, facts, ir, findings)
    })
}

fn validate_discovered_root(
    root: &Path,
    facts: &WorkspaceFacts,
    ir: &AssemblyGovernanceIr<Core>,
    mut findings: Vec<Finding>,
) -> Result<(usize, Vec<Finding>)> {
    findings.extend(validate_runtime_inventory_listener_provenance(
        root,
        ir.assemblies(),
    )?);
    for assembly in ir.assemblies() {
        findings.extend(settingsonly_raw_jwt_reparse_findings(assembly)?);
        findings.extend(validate_assembly(assembly));
        findings.extend(validate_assembly_cargo_facts(root, facts, assembly)?);
        findings.extend(validate_target_domain_closure(root, facts, assembly)?);
    }
    Ok((ir.assemblies().len(), findings))
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

fn validate_runtime_inventory_listener_provenance(
    _root: &Path,
    assemblies: &[GovernedAssembly],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    for assembly in assemblies {
        let expected_calls = match assembly.manifest().name() {
            "runtime" => RUNTIME_LISTENER_OBSERVATIONS,
            "settingsonly" => SETTINGSONLY_LISTENER_OBSERVATIONS,
            "identityaudit" => IDENTITYAUDIT_LISTENER_OBSERVATIONS,
            _ => continue,
        };
        let evidence = security_closeout_evidence_from_sources(assembly.dir())?;
        if !evidence.listener_publish_flow
            || !listener_observations_match(&evidence.listener_observations, expected_calls)
        {
            let (missing, unexpected) =
                listener_observation_drift(&evidence.listener_observations, expected_calls);
            let flow_stage = if evidence.listener_observations.is_empty() {
                "bound-local-addr-observation"
            } else if !evidence.listener_publish_sink_seen {
                "inventory-publish-sink"
            } else if !evidence.listener_publish_flow {
                "observation-to-publish-argument"
            } else {
                "listener-identity-role-join"
            };
            findings.push(finding(
                Rule::RuntimeInventoryListenerProvenance,
                assembly.manifest_label(),
                format!(
                    "runtime listener inventory requires run/activate-reachable bound local_addr observations to flow into a typed inventory publish (flow_stage={flow_stage}, expected={}, observed={}, publish_sink_seen={}, publish_flow={}, missing=[{}], unexpected=[{}])",
                    expected_calls.len(),
                    evidence.listener_observations.len(),
                    evidence.listener_publish_sink_seen,
                    evidence.listener_publish_flow,
                    missing.join(", "),
                    unexpected.join(", "),
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
}

const RUNTIME_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] =
    &[ExpectedListenerObservation {
        id: "self.id.clone()",
        kind: "kind",
        auth: "auth",
    }];
const SETTINGSONLY_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] = &[
    ExpectedListenerObservation {
        id: "\"primary-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Primary",
        auth: "assembly_schema::ListenerAuth::FederatedAccessToken",
    },
    ExpectedListenerObservation {
        id: "\"admin-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Admin",
        auth: "assembly_schema::ListenerAuth::FederatedAccessToken",
    },
    ExpectedListenerObservation {
        id: "\"health-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Health",
        auth: "assembly_schema::ListenerAuth::NoAuth",
    },
];
const IDENTITYAUDIT_LISTENER_OBSERVATIONS: &[ExpectedListenerObservation] = &[
    ExpectedListenerObservation {
        id: "\"primary-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Primary",
        auth: "assembly_schema::ListenerAuth::RssAccessToken",
    },
    ExpectedListenerObservation {
        id: "\"admin-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Admin",
        auth: "assembly_schema::ListenerAuth::RssAccessToken",
    },
    ExpectedListenerObservation {
        id: "\"health-main\"",
        kind: "assembly_schema::AssemblyListenerKind::Health",
        auth: "assembly_schema::ListenerAuth::NoAuth",
    },
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ListenerObservationCall {
    id: String,
    kind: String,
    auth: String,
    receiver: String,
}

fn listener_observations_match(
    actual: &[ListenerObservationCall],
    expected: &[ExpectedListenerObservation],
) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    expected.iter().all(|expected| {
        actual.iter().any(|actual| {
            actual.id == expected.id
                && actual.kind == expected.kind
                && actual.auth == expected.auth
                && listener_receiver_matches_role(&actual.receiver, expected.id)
        })
    })
}

fn listener_observation_drift(
    actual: &[ListenerObservationCall],
    expected: &[ExpectedListenerObservation],
) -> (Vec<String>, Vec<String>) {
    let matches = |actual: &ListenerObservationCall, expected: &ExpectedListenerObservation| {
        actual.id == expected.id
            && actual.kind == expected.kind
            && actual.auth == expected.auth
            && listener_receiver_matches_role(&actual.receiver, expected.id)
    };
    let mut missing = expected
        .iter()
        .filter(|expected| !actual.iter().any(|actual| matches(actual, expected)))
        .map(|expected| format!("{}:{}:{}", expected.id, expected.kind, expected.auth))
        .collect::<Vec<_>>();
    let mut unexpected = actual
        .iter()
        .filter(|actual| !expected.iter().any(|expected| matches(actual, expected)))
        .map(|actual| {
            format!(
                "{}:{}:{}@{}",
                actual.id, actual.kind, actual.auth, actual.receiver
            )
        })
        .collect::<Vec<_>>();
    missing.sort();
    unexpected.sort();
    (missing, unexpected)
}

fn listener_receiver_matches_role(receiver: &str, id: &str) -> bool {
    if id == "self.id.clone()" {
        return receiver.starts_with("self.") || receiver == "self";
    }
    ["primary", "admin", "health"]
        .into_iter()
        .find(|role| id.contains(role))
        .is_some_and(|role| receiver.contains(role))
}

fn listener_observation_call(node: &syn::ExprCall) -> Option<ListenerObservationCall> {
    if !call_path_ends_with(node.func.as_ref(), "from_bound") || node.args.len() != 5 {
        return None;
    }
    let syn::Expr::MethodCall(address) = ungroup_profile_expression(&node.args[4]) else {
        return None;
    };
    if address.method != "local_addr" || !address.args.is_empty() {
        return None;
    }
    Some(ListenerObservationCall {
        id: token_key(&node.args[0]),
        kind: token_key(&node.args[1]),
        auth: token_key(&node.args[2]),
        receiver: token_key(address.receiver.as_ref()),
    })
}

fn expression_contains_listener_observation(expression: &syn::Expr) -> bool {
    struct Detector(bool);
    impl<'ast> syn::visit::Visit<'ast> for Detector {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            self.0 |= listener_observation_call(node).is_some();
            if !self.0 {
                syn::visit::visit_expr_call(self, node);
            }
        }
    }
    let mut detector = Detector(false);
    syn::visit::Visit::visit_expr(&mut detector, expression);
    detector.0
}

fn token_key(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[derive(Clone, Default)]
struct StandardPathAliases {
    aliases: BTreeMap<String, String>,
    shadowed_values: BTreeSet<String>,
}

impl StandardPathAliases {
    fn from_items<'a>(items: impl IntoIterator<Item = &'a syn::Item>) -> Self {
        let mut aliases = Self::default();
        for item in items {
            if let syn::Item::Use(item_use) = item {
                aliases.collect_use_tree(&[], &item_use.tree);
            }
        }
        aliases
    }

    fn with_block_imports(&self, block: &syn::Block) -> Self {
        let mut aliases = self.clone();
        for statement in &block.stmts {
            if let syn::Stmt::Item(syn::Item::Use(item_use)) = statement {
                aliases.collect_use_tree(&[], &item_use.tree);
            }
        }
        aliases
    }

    fn shadow_pattern(&mut self, pattern: &syn::Pat) {
        self.shadowed_values.extend(pattern_binding_names(pattern));
    }

    fn with_signature_inputs(&self, signature: &syn::Signature) -> Self {
        let mut aliases = self.clone();
        for input in &signature.inputs {
            if let syn::FnArg::Typed(argument) = input {
                aliases.shadow_pattern(argument.pat.as_ref());
            }
        }
        aliases
    }

    fn collect_use_tree(&mut self, prefix: &[String], tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => {
                let mut nested = prefix.to_vec();
                nested.push(path.ident.to_string());
                self.collect_use_tree(&nested, path.tree.as_ref());
            }
            syn::UseTree::Name(name) => {
                let ident = name.ident.to_string();
                let (local, target) = if ident == "self" {
                    (prefix.last().cloned(), prefix.join("::"))
                } else {
                    let mut target = prefix.to_vec();
                    target.push(ident.clone());
                    (Some(ident), target.join("::"))
                };
                if let Some(local) = local {
                    self.aliases.insert(local, target);
                }
            }
            syn::UseTree::Rename(rename) => {
                let mut target = prefix.to_vec();
                target.push(rename.ident.to_string());
                self.aliases
                    .insert(rename.rename.to_string(), target.join("::"));
            }
            syn::UseTree::Glob(_) => {
                let target = prefix.join("::");
                let imported = match target.as_str() {
                    "std" | "core" => &["iter", "process"][..],
                    "std::iter" | "core::iter" => &["repeat", "repeat_with"][..],
                    "std::process" | "core::process" => &["exit", "abort"][..],
                    _ => &[],
                };
                for name in imported {
                    self.aliases
                        .insert(name.to_string(), format!("{target}::{name}"));
                }
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use_tree(prefix, item);
                }
            }
        }
    }

    fn resolve_key(&self, key: String) -> String {
        if key
            .split("::")
            .next()
            .is_some_and(|name| self.shadowed_values.contains(name))
        {
            return key;
        }
        if let Some(target) = self.aliases.get(&key) {
            return target.clone();
        }
        let Some((first, rest)) = key.split_once("::") else {
            return key;
        };
        self.aliases
            .get(first)
            .map_or(key.clone(), |target| format!("{target}::{rest}"))
    }

    fn value_is_shadowed(&self, name: &str) -> bool {
        self.shadowed_values.contains(name)
    }

    fn resolve_expression_path(&self, expression: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = expression else {
            return None;
        };
        (path.qself.is_none()).then(|| {
            self.resolve_key(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            )
        })
    }

    fn is_infinite_iterator_root(&self, expression: &syn::Expr) -> bool {
        matches!(
            self.resolve_expression_path(expression).as_deref(),
            Some(
                "std::iter::repeat"
                    | "core::iter::repeat"
                    | "iter::repeat"
                    | "std::iter::repeat_with"
                    | "core::iter::repeat_with"
                    | "iter::repeat_with"
            )
        )
    }

    fn is_process_terminator(&self, expression: &syn::Expr) -> bool {
        matches!(
            self.resolve_expression_path(expression).as_deref(),
            Some(
                "std::process::exit"
                    | "std::process::abort"
                    | "core::process::exit"
                    | "core::process::abort"
                    | "process::exit"
                    | "process::abort"
            )
        )
    }

    fn is_explicit_process_terminator(expression: &syn::Expr) -> bool {
        let syn::Expr::Path(path) = expression else {
            return false;
        };
        let segments = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        matches!(
            segments.as_slice(),
            [root, process, function]
                if matches!(root.as_str(), "std" | "core")
                    && process == "process"
                    && matches!(function.as_str(), "exit" | "abort")
        )
    }
}

#[derive(Default)]
struct PatternBindingNameVisitor {
    names: BTreeSet<String>,
}

impl<'ast> syn::visit::Visit<'ast> for PatternBindingNameVisitor {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.names.insert(pattern.ident.to_string());
        syn::visit::visit_pat_ident(self, pattern);
    }
}

fn pattern_binding_names(pattern: &syn::Pat) -> BTreeSet<String> {
    let mut bindings = PatternBindingNameVisitor::default();
    syn::visit::Visit::visit_pat(&mut bindings, pattern);
    bindings.names
}

fn signature_binding_names(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(argument) => Some(pattern_binding_names(argument.pat.as_ref())),
            syn::FnArg::Receiver(_) => None,
        })
        .flatten()
        .collect()
}

/// Validate the bidirectional lifecycle and ownership join between governed assemblies and
/// framework contract declarations.
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

/// Validate an assembly already selected by the governance owner.
///
/// Callers that already hold a Core IR must use this entry point so target-scoped
/// operations do not rediscover the repository or rerun the global production ratchet.
pub(crate) fn validate_governed_target(
    root: &Path,
    assembly: &GovernedAssembly,
    facts: &WorkspaceFacts,
) -> Result<Vec<Finding>> {
    let mut findings = validate_assembly(assembly);
    findings.extend(settingsonly_raw_jwt_reparse_findings(assembly)?);
    findings.extend(validate_assembly_cargo_facts(root, facts, assembly)?);
    findings.extend(validate_target_domain_closure(root, facts, assembly)?);
    Ok(findings)
}

fn validate_target_domain_closure(
    root: &Path,
    facts: &WorkspaceFacts,
    assembly: &GovernedAssembly,
) -> Result<Vec<Finding>> {
    // INVARIANT: ASSEMBLY-DOMAIN-CLOSURE-01 { level = "Medium", exec = "check", source = "code" } —
    // AssemblyGovernanceIr owns the declared domains; WorkspaceFacts/CargoSet owns the current
    // root-specific selected normal graph. Direct edges keep manifest rename/path provenance.
    let package = assembly_package_key(root, facts, assembly)?;
    let all_build = resolve_assembly_build(facts, &package, FeatureSelection::All)?;
    let default_build = resolve_assembly_build(facts, &package, FeatureSelection::Default)?;
    let domains = workspace_domain_packages(facts)?;

    let mut direct_domains = BTreeSet::new();
    for dependency in facts.direct_dependencies_for(&package)? {
        if dependency.kind() != DependencyKind::Normal {
            continue;
        }
        let source_root = match dependency.source() {
            DependencySource::Workspace { repo_relative_root }
            | DependencySource::Path { repo_relative_root } => Some(repo_relative_root.as_path()),
            _ => None,
        };
        let domain_candidate = domains.iter().find(|(domain, name)| {
            dependency.name() == name.as_str()
                || source_root.is_some_and(|root| {
                    facts
                        .repo_relative_root_for(domain)
                        .is_ok_and(|expected| expected == root)
                })
        });
        let Some((domain, name)) = domain_candidate else {
            continue;
        };
        let resolved =
            dependency
                .resolved()
                .ok_or_else(|| AssemblyCargoFactsError::UnresolvedDependency {
                    assembly: assembly.cargo_label().to_owned(),
                    dependency: dependency.name().to_owned(),
                })?;
        let source_matches = source_root.is_some_and(|root| {
            facts
                .repo_relative_root_for(domain)
                .is_ok_and(|expected| expected == root)
        });
        if resolved == domain
            && dependency.name() == name
            && source_matches
            && all_build.is_dependency_selected(
                BuildSide::Target,
                &package,
                dependency.name(),
                domain,
            )
        {
            direct_domains.insert(name.clone());
        }
    }

    let closure_domains = all_build
        .workspace_packages(BuildSide::Target)
        .iter()
        .filter_map(|package| domains.get(package).cloned())
        .collect();
    let mut findings = validate_domain_sets(assembly, direct_domains, closure_domains)?;

    if assembly.production().is_some() {
        let enabled_test_support = default_build
            .enabled_features(BuildSide::Target)
            .iter()
            .filter(|feature| feature.name() == "test-support")
            .map(|feature| feature.package().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if !enabled_test_support.is_empty() {
            findings.push(finding(
                Rule::ProductionTestSupport,
                assembly.cargo_label(),
                format!(
                    "production default Cargo graph enables test-support in {enabled_test_support:?}"
                ),
            ));
        }
    }
    Ok(findings)
}

fn assembly_package_key(
    root: &Path,
    facts: &WorkspaceFacts,
    assembly: &GovernedAssembly,
) -> Result<PackageKey> {
    let cargo_path = assembly.cargo_path().strip_prefix(root).with_context(|| {
        format!(
            "{} Cargo manifest escaped workspace root: {}",
            assembly.manifest_label(),
            assembly.cargo_path().display(),
        )
    })?;
    facts.package_for_repo_path(cargo_path)?.with_context(|| {
        format!(
            "{} is not owned by a workspace package; manifest_path={}",
            assembly.cargo_label(),
            assembly.cargo_path().display(),
        )
    })
}

fn resolve_assembly_build(
    facts: &WorkspaceFacts,
    package: &PackageKey,
    features: FeatureSelection,
) -> Result<BuildFacts> {
    let platform =
        CargoPlatform::build_target().context("resolve assembly Cargo build target platform")?;
    facts
        .resolve_build(BuildSelection::new(
            package.clone(),
            ResolverVersion::V2,
            features,
            BuildPlatforms::new(platform.clone(), platform),
            BTreeSet::new(),
        ))
        .with_context(|| {
            format!(
                "resolve {:?} normal Cargo build for workspace package `{}`",
                features,
                package.as_str(),
            )
        })
}

fn workspace_domain_packages(facts: &WorkspaceFacts) -> Result<BTreeMap<PackageKey, String>> {
    Ok(facts
        .workspace_packages()
        .into_iter()
        .filter(|package| {
            crate::layers::classify(
                package.key().as_str(),
                &package.repo_relative_root().display().to_string(),
            ) == Some(crate::layers::Layer::Domain)
        })
        .map(|package| (package.key().clone(), package.key().as_str().to_owned()))
        .collect())
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

fn discovery_findings(root: &Path, ir: &AssemblyGovernanceIr<Core>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for target in ir.targets() {
        let cargo_path = target.cargo_path();
        if !target.has_manifest() && target.has_cargo_manifest() {
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
                    "assembly crate 必须声明 {label}/assembly.toml；source={}",
                    rel_label(root, &cargo_path),
                ),
            ));
        }
    }
    findings
}

#[cfg(test)]
fn discover(root: &Path) -> Result<(Vec<GovernedAssembly>, Vec<Finding>)> {
    let ir = AssemblyGovernanceIr::<Core>::load(root)?;
    let findings = discovery_findings(root, &ir);
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

const DEVICEIDENTITY_PILOT_REQUIRED_CAPABILITIES: &[RequiredCapabilitySpec] = &[
    RequiredCapabilitySpec {
        capability: "Pg",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "postgres",
            required_features: &["domain-identity"],
        },
    },
    RequiredCapabilitySpec {
        capability: "identity-composition",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "identity-composition",
            required_features: &[],
        },
    },
    RequiredCapabilitySpec {
        capability: "mqtt",
        expectation: RequiredCapabilityExpectation::CargoDependency {
            dependency: "mqtt",
            required_features: &[],
        },
    },
    RequiredCapabilitySpec {
        capability: "device-certificate-store",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresDeviceCertificateRepository,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "device-command-store",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresDeviceCommandStore,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "device-draft-artifact-source",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::IdentityDraftArtifactSimulator,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "device-mqtt-session",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::MqttSession,
            consumer: "identity",
        },
    },
    RequiredCapabilitySpec {
        capability: "device-revocation-store",
        expectation: RequiredCapabilityExpectation::ActivePersistentProvider {
            provider: ProviderConstructor::PostgresRevocationStore,
            consumer: "deviceloop",
        },
    },
];

const DEVICEIDENTITY_PILOT_ROLES: &[ProviderRole] = &[
    ProviderRole::DeviceCertificateStore,
    ProviderRole::DeviceCommandStore,
    ProviderRole::DeviceDraftArtifactSource,
    ProviderRole::DeviceMqttSession,
    ProviderRole::DeviceRevocationStore,
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
    if is_deviceidentity_pilot_shape(a) {
        for capability in DEVICEIDENTITY_PILOT_REQUIRED_CAPABILITIES {
            validate_required_capability(a, "deviceidentity", capability, findings);
        }
        validate_deviceidentity_pilot_exact_roles(a, findings);
        return;
    }

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

fn is_deviceidentity_pilot_shape(a: &GovernedAssembly) -> bool {
    is_deviceidentity_pilot_manifest_shape(a.manifest())
}

fn is_deviceidentity_pilot_manifest_shape(manifest: &CanonicalAssemblyManifestV2) -> bool {
    manifest.profile() == AssemblyProfile::Demo
        && manifest.topology() == AssemblyTopology::Demo
        && manifest.domains() == [AssemblyDomain::Identity]
        && manifest.framework_contracts().is_empty()
        && manifest.workflow_activations().is_empty()
        && manifest.listeners().is_empty()
}

fn validate_deviceidentity_pilot_exact_roles(a: &GovernedAssembly, findings: &mut Vec<Finding>) {
    let actual = a
        .manifest()
        .diport_providers()
        .iter()
        .map(|provider| provider.id)
        .collect::<BTreeSet<_>>();
    let expected = DEVICEIDENTITY_PILOT_ROLES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();

    for missing in expected.difference(&actual) {
        findings.push(finding(
            Rule::RequiredCapability,
            a.manifest_label(),
            format!(
                "field=diportProviders domain=deviceidentity capability={} expected exact pilot provider role; actual=missing-role",
                missing.as_str()
            ),
        ));
    }
    for extra in actual.difference(&expected) {
        findings.push(finding(
            Rule::RequiredCapability,
            a.manifest_label(),
            format!(
                "field=diportProviders domain=deviceidentity capability={} expected exact pilot provider role set; actual=extra-role",
                extra.as_str()
            ),
        ));
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
            dependency: _,
            required_features: _,
        } => {}
        RequiredCapabilityExpectation::ActivePersistentProvider { provider, consumer } => {
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
            Rule::IdentityAuditManifestBoundary,
            a.manifest_label(),
            format!(
                "field=profile/topology/listeners identityaudit requires profile=production, topology=durable-isolated, and exact Primary(identity)+Admin(audit)+Health(empty); actual profile={} topology={} listeners={listeners:?}",
                a.manifest().profile().as_str(),
                a.manifest().topology().as_str(),
            ),
        ));
    }
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
        if (spec.required)(&a) && !has_active_persistent_critical_provider(&a, spec) {
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
    if !evidence.has_provider_construction_live_join() {
        findings.push(finding(
            Rule::ProviderConstructionLiveJoin,
            a.manifest_label(),
            format!(
                "source=rust-ast-run-reachable profile=production gate=provider-live-join requires typed plan selection followed by a typed provider finish and the same finished output's transfer or runtime inventory publication; present selection={} typed_finish={} finish_transfer={} runtime_finish={} publish={}",
                evidence.provider_selection,
                evidence.provider_typed_finish,
                evidence.provider_finish_transfer,
                evidence.runtime_provider_finish,
                evidence.inventory_publish,
            ),
        ));
    }
    let listener_pdp_owns_jwks_lifecycle = a.manifest().diport_providers().iter().any(|provider| {
        provider.id == ProviderRole::ListenerPdp
            && provider.outputs.as_slice()
                == [LifecycleChannel::Probes, LifecycleChannel::Resources]
    });
    if !evidence.has_jwks_closeout() || !listener_pdp_owns_jwks_lifecycle {
        let missing = evidence.jwks_closeout_missing(listener_pdp_owns_jwks_lifecycle);
        findings.push(finding(
            Rule::ProductionSecurityJwksCloseout,
            a.manifest_label(),
            format!(
                "source=rust-ast-run-reachable+typed-provider-receipt profile=production gate=jwks 必须在 run() 或 typed StartupAdapter::prepare 可达路径有 profile-specific JwksKeySource::load_and_watch + typed VerifierConfigBuilder::keys_jwks + verifier managed resource + profile-specific JWKS readiness probe，并经签名闭合的 typed builder→aggregate→commit provenance 消费 listener-pdp lifecycle；manifest 闭值输出必须为 probes+resources；missing=[{}]",
                missing.join(", ")
            ),
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

fn has_active_persistent_critical_provider(
    a: &GovernedAssembly,
    spec: &CriticalProviderSpec,
) -> bool {
    a.manifest().diport_providers().iter().any(|provider| {
        provider.lifecycle == ProviderLifecycle::Active
            && provider.durability == ProviderDurability::Persistent
            && provider.port == spec.provider.port()
            && provider.provider == spec.provider
            && provider.provider_crate == spec.provider.provider_crate()
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

struct RawJwtReparseVisitor {
    forbidden_calls: usize,
    jwt_types: BTreeSet<String>,
    verified_jwt_types: BTreeSet<String>,
}

impl RawJwtReparseVisitor {
    fn bind_type_alias(&mut self, bound: String, target: &str) {
        self.jwt_types.remove(&bound);
        self.verified_jwt_types.remove(&bound);
        if target == "Jwt" {
            self.jwt_types.insert(bound);
        } else if target == "VerifiedJwt" {
            self.verified_jwt_types.insert(bound);
        }
    }

    fn collect_use_tree(&mut self, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(path) => self.collect_use_tree(&path.tree),
            syn::UseTree::Name(name) => {
                self.bind_type_alias(name.ident.to_string(), &name.ident.to_string());
            }
            syn::UseTree::Rename(rename) => {
                self.bind_type_alias(rename.rename.to_string(), &rename.ident.to_string());
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    self.collect_use_tree(item);
                }
            }
            _ => {}
        }
    }

    fn collect_scope_items<'a>(&mut self, items: impl Iterator<Item = &'a syn::Item>) {
        for item in items {
            match item {
                syn::Item::Use(item) => self.collect_use_tree(&item.tree),
                syn::Item::Type(item) => {
                    if let syn::Type::Path(path) = item.ty.as_ref()
                        && let Some(target) = path.path.segments.last()
                    {
                        self.bind_type_alias(item.ident.to_string(), &target.ident.to_string());
                    }
                }
                _ => {}
            }
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for RawJwtReparseVisitor {
    fn visit_file(&mut self, file: &'ast syn::File) {
        let saved_jwt = self.jwt_types.clone();
        let saved_verified = self.verified_jwt_types.clone();
        self.collect_scope_items(file.items.iter());
        for item in &file.items {
            syn::visit::visit_item(self, item);
        }
        self.jwt_types = saved_jwt;
        self.verified_jwt_types = saved_verified;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let Some((_, items)) = &item.content else {
            return;
        };
        let saved_jwt = self.jwt_types.clone();
        let saved_verified = self.verified_jwt_types.clone();
        self.collect_scope_items(items.iter());
        for item in items {
            syn::visit::visit_item(self, item);
        }
        self.jwt_types = saved_jwt;
        self.verified_jwt_types = saved_verified;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let saved_jwt = self.jwt_types.clone();
        let saved_verified = self.verified_jwt_types.clone();
        self.collect_scope_items(block.stmts.iter().filter_map(|statement| match statement {
            syn::Stmt::Item(item) => Some(item),
            _ => None,
        }));
        for statement in &block.stmts {
            syn::visit::visit_stmt(self, statement);
        }
        self.jwt_types = saved_jwt;
        self.verified_jwt_types = saved_verified;
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let mut segments = expression.path.segments.iter().rev();
        let method = segments.next().map(|segment| segment.ident.to_string());
        let owner = segments.next().map(|segment| segment.ident.to_string());
        if (matches!(method.as_deref(), Some("parse"))
            && owner
                .as_ref()
                .is_some_and(|owner| self.jwt_types.contains(owner)))
            || (matches!(method.as_deref(), Some("raw"))
                && owner
                    .as_ref()
                    .is_some_and(|owner| self.verified_jwt_types.contains(owner)))
        {
            self.forbidden_calls = self.forbidden_calls.saturating_add(1);
        }
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if expression.method == "raw" || expression.method == "verified_jwt" {
            self.forbidden_calls = self.forbidden_calls.saturating_add(1);
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn file_raw_jwt_reparse_count(file: &syn::File) -> usize {
    let mut visitor = RawJwtReparseVisitor {
        forbidden_calls: 0,
        jwt_types: BTreeSet::from(["Jwt".to_owned()]),
        verified_jwt_types: BTreeSet::from(["VerifiedJwt".to_owned()]),
    };
    syn::visit::Visit::visit_file(&mut visitor, file);
    visitor.forbidden_calls
}

fn settingsonly_raw_jwt_reparse_findings(assembly: &GovernedAssembly) -> Result<Vec<Finding>> {
    if assembly.manifest().name() != "settingsonly" {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    collect_rust_sources(&assembly.dir().join("src"), &mut files)?;
    files.sort();
    let mut findings = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path)?;
        let syntax = syn::parse_file(&source)
            .with_context(|| format!("parse settingsonly source {}", path.display()))?;
        let count = file_raw_jwt_reparse_count(&syntax);
        if count != 0 {
            findings.push(finding(
                Rule::SettingsOnlyRawJwtReparse,
                assembly.manifest_label(),
                format!(
                    "settingsonly source {} contains {count} raw JWT reparse path(s); cfg(test), aliases and function pointers are not exempt because dylint does not compile that tree",
                    path.strip_prefix(assembly.dir()).unwrap_or(&path).display()
                ),
            ));
        }
    }
    Ok(findings)
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

#[derive(Clone, Debug, Default)]
struct SecurityCloseoutEvidence {
    provider_selection: bool,
    provider_typed_finish: bool,
    provider_finish_transfer: bool,
    runtime_provider_finish: bool,
    inventory_publish: bool,
    listener_publish_flow: bool,
    listener_publish_sink_seen: bool,
    listener_observations: Vec<ListenerObservationCall>,
    runtime_oidc_provider_build: bool,
    runtime_oidc_provider_handle: bool,
    runtime_oidc_managed_resource: bool,
    jwks_load_and_watch: bool,
    jwks_keys_jwks: bool,
    jwks_ready_probe: bool,
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
        self.provider_selection |= other.provider_selection;
        self.provider_typed_finish |= other.provider_typed_finish;
        self.provider_finish_transfer |= other.provider_finish_transfer;
        self.runtime_provider_finish |= other.runtime_provider_finish;
        self.inventory_publish |= other.inventory_publish;
        self.listener_publish_flow |= other.listener_publish_flow;
        self.listener_publish_sink_seen |= other.listener_publish_sink_seen;
        self.listener_observations
            .extend(other.listener_observations);
        self.runtime_oidc_provider_build |= other.runtime_oidc_provider_build;
        self.runtime_oidc_provider_handle |= other.runtime_oidc_provider_handle;
        self.runtime_oidc_managed_resource |= other.runtime_oidc_managed_resource;
        self.jwks_load_and_watch |= other.jwks_load_and_watch;
        self.jwks_keys_jwks |= other.jwks_keys_jwks;
        self.jwks_ready_probe |= other.jwks_ready_probe;
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

    fn has_provider_construction_live_join(&self) -> bool {
        self.provider_selection
            && self.provider_typed_finish
            && (self.provider_finish_transfer || self.runtime_provider_finish)
    }

    fn has_jwks_closeout(&self) -> bool {
        self.runtime_oidc_provider_build
            && self.runtime_oidc_provider_handle
            && self.runtime_oidc_managed_resource
            && self.jwks_load_and_watch
            && self.jwks_keys_jwks
            && self.jwks_ready_probe
    }

    fn jwks_closeout_missing(&self, listener_pdp_owns_jwks_lifecycle: bool) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.runtime_oidc_provider_build {
            missing.push("runtimeOidcProviderBuild");
        }
        if !self.runtime_oidc_provider_handle {
            missing.push("runtimeOidcProviderHandle");
        }
        if !self.runtime_oidc_managed_resource {
            missing.push("runtimeOidcManagedResource");
        }
        if !self.jwks_load_and_watch {
            missing.push("jwksLoadAndWatch");
        }
        if !self.jwks_keys_jwks {
            missing.push("jwksKeysJwks");
        }
        if !self.jwks_ready_probe {
            missing.push("jwksReadyProbe");
        }
        if !listener_pdp_owns_jwks_lifecycle {
            missing.push("manifestListenerPdpOutputs=probes+resources");
        }
        missing
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
    let sources = files
        .into_iter()
        .map(|path| {
            let content = std::fs::read_to_string(&path)?;
            let file = syn::parse_file(&content)
                .with_context(|| format!("parse rust source {}", path.display()))?;
            Ok((path, content, file))
        })
        .collect::<Result<Vec<_>>>()?;
    let diverging_function_names =
        collect_diverging_function_names(sources.iter().map(|(_, _, file)| file));
    let mut program = SecurityCloseoutProgram::default();
    for (path, content, file) in sources {
        let relative = path
            .strip_prefix(&src_dir)
            .with_context(|| format!("rust source escaped src root: {}", path.display()))?;
        let file_identity = relative.to_string_lossy().replace('\\', "/");
        let module_identity = rust_source_module_identity(relative);
        let mut file_program = file_security_closeout_program_at(
            &file,
            file_identity,
            module_identity,
            diverging_function_names.clone(),
        );
        file_program.legacy_token_surface |= source_contains_legacy_token_surface(&content);
        program.merge(file_program);
    }
    Ok(program.reachable_evidence_from_run())
}

#[derive(Default)]
struct DivergingFunctionNameVisitor {
    definitions: Vec<DivergingFunctionDefinition>,
    aliases: Vec<StandardPathAliases>,
    impl_owners: Vec<String>,
    free_returns: BTreeMap<String, String>,
    method_returns: BTreeMap<(String, String), String>,
    struct_fields: BTreeMap<(String, String), String>,
}

struct DivergingFunctionDefinition {
    name: String,
    method_owner: Option<String>,
    explicit_never: bool,
    body: Option<syn::Block>,
    aliases: StandardPathAliases,
    value_types: BTreeMap<String, String>,
}

#[derive(Clone, Default)]
struct DivergingCallTargets {
    free_functions: BTreeSet<String>,
    methods: BTreeSet<(String, String)>,
    free_returns: BTreeMap<String, String>,
    method_returns: BTreeMap<(String, String), String>,
    struct_fields: BTreeMap<(String, String), String>,
}

impl DivergingCallTargets {
    fn contains(&self, name: &str) -> bool {
        self.free_functions.contains(name)
    }

    fn contains_definition(&self, definition: &DivergingFunctionDefinition) -> bool {
        match &definition.method_owner {
            Some(owner) => self
                .methods
                .contains(&(owner.clone(), definition.name.clone())),
            None => self.free_functions.contains(&definition.name),
        }
    }

    fn insert_definition(&mut self, definition: &DivergingFunctionDefinition) {
        match &definition.method_owner {
            Some(owner) => {
                self.methods
                    .insert((owner.clone(), definition.name.clone()));
            }
            None => {
                self.free_functions.insert(definition.name.clone());
            }
        }
    }

    fn method_is_diverging(
        &self,
        receiver: &syn::Expr,
        method: &syn::Ident,
        aliases: &StandardPathAliases,
        value_types: &BTreeMap<String, String>,
    ) -> bool {
        expression_method_owner(
            ungroup_profile_expression(receiver),
            aliases,
            self,
            value_types,
        )
        .is_some_and(|owner| self.owner_method_is_diverging(&owner, method))
    }

    fn owner_method_is_diverging(&self, owner: &str, method: &syn::Ident) -> bool {
        self.methods
            .contains(&(owner.to_string(), method.to_string()))
    }

    fn knows_method_owner(&self, owner: &str) -> bool {
        self.methods
            .iter()
            .any(|(candidate, _)| type_identity_matches(candidate, owner))
    }

    fn knows_struct(&self, owner: &str) -> bool {
        self.struct_fields
            .keys()
            .any(|(candidate, _)| type_identity_matches(candidate, owner))
    }

    fn knows_method_return_owner(&self, owner: &str) -> bool {
        self.method_returns
            .keys()
            .any(|(candidate, _)| candidate == owner)
    }

    fn knows_catalog_type(&self, owner: &str) -> bool {
        self.knows_method_return_owner(owner)
            || self
                .method_returns
                .values()
                .any(|candidate| candidate == owner)
            || self
                .free_returns
                .values()
                .any(|candidate| candidate == owner)
    }

    fn knows_tracked_type(&self, owner: &str) -> bool {
        self.knows_method_owner(owner) || self.knows_struct(owner) || self.knows_catalog_type(owner)
    }

    fn associated_function_is_diverging(
        &self,
        function: &syn::Expr,
        aliases: &StandardPathAliases,
    ) -> bool {
        let Some(path) = aliases.resolve_expression_path(function) else {
            return false;
        };
        let Some((owner, method)) = path.rsplit_once("::") else {
            return false;
        };
        self.methods
            .contains(&(owner.to_string(), method.to_string()))
    }
}

fn type_identity_matches(left: &str, right: &str) -> bool {
    left == right || left.ends_with(&format!("::{right}")) || right.ends_with(&format!("::{left}"))
}

fn type_path_name(
    ty: &syn::Type,
    aliases: &StandardPathAliases,
    self_owner: Option<&str>,
) -> Option<String> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let key = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    if key == "Self" {
        return self_owner.map(str::to_owned);
    }
    Some(aliases.resolve_key(key))
}

fn type_path_owner(
    ty: &syn::Type,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
) -> Option<String> {
    type_path_name(ty, aliases, None).filter(|owner| targets.knows_tracked_type(owner))
}

fn expression_type_name(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
    value_types: &BTreeMap<String, String>,
) -> Option<String> {
    let expression = ungroup_profile_expression(expression);
    match expression {
        syn::Expr::Reference(reference) => {
            expression_type_name(reference.expr.as_ref(), aliases, targets, value_types)
        }
        syn::Expr::Try(value) => {
            expression_type_name(value.expr.as_ref(), aliases, targets, value_types)
        }
        syn::Expr::Await(value) => {
            expression_type_name(value.base.as_ref(), aliases, targets, value_types)
        }
        syn::Expr::Cast(cast) => type_path_owner(cast.ty.as_ref(), aliases, targets),
        syn::Expr::Path(_) => {
            if let Some(path) = aliases.resolve_expression_path(expression) {
                let receiver_name = path.split("::").next().unwrap_or(path.as_str());
                if !aliases.value_is_shadowed(receiver_name) && targets.knows_tracked_type(&path) {
                    return Some(path);
                }
            }
            let name = simple_path_ident(expression)?;
            value_types
                .get(&name)
                .filter(|owner| targets.knows_tracked_type(owner))
                .cloned()
        }
        syn::Expr::Struct(value) => {
            let owner = aliases.resolve_key(
                value
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
            targets.knows_tracked_type(&owner).then_some(owner)
        }
        syn::Expr::Call(call) => {
            let path = aliases.resolve_expression_path(call.func.as_ref())?;
            if let Some((owner, method)) = path.rsplit_once("::") {
                if let Some(returned) = targets
                    .method_returns
                    .get(&(owner.to_string(), method.to_string()))
                    .filter(|returned| targets.knows_tracked_type(returned))
                {
                    return Some(returned.clone());
                }
                if targets.knows_tracked_type(owner) {
                    return Some(owner.to_string());
                }
            }
            let name = path.rsplit("::").next().unwrap_or(path.as_str());
            if aliases.value_is_shadowed(name) {
                return None;
            }
            targets
                .free_returns
                .get(name)
                .filter(|returned| targets.knows_tracked_type(returned))
                .cloned()
        }
        syn::Expr::MethodCall(call) => {
            let receiver_ty =
                expression_type_name(call.receiver.as_ref(), aliases, targets, value_types)?;
            targets
                .method_returns
                .get(&(receiver_ty, call.method.to_string()))
                .filter(|returned| targets.knows_tracked_type(returned))
                .cloned()
        }
        syn::Expr::Field(field) => {
            let syn::Member::Named(name) = &field.member else {
                return None;
            };
            let base_ty = expression_type_name(field.base.as_ref(), aliases, targets, value_types)?;
            targets
                .struct_fields
                .get(&(base_ty.clone(), name.to_string()))
                .filter(|returned| targets.knows_tracked_type(returned))
                .cloned()
                .or_else(|| {
                    let mut matches = targets
                        .struct_fields
                        .iter()
                        .filter(|((owner, field_name), returned)| {
                            field_name == &name.to_string()
                                && (owner.ends_with(&base_ty) || base_ty.ends_with(owner))
                                && targets.knows_tracked_type(returned)
                        })
                        .map(|(_, returned)| returned.clone());
                    let first = matches.next()?;
                    matches.next().is_none().then_some(first)
                })
        }
        _ => None,
    }
}

fn expression_method_owner(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
    value_types: &BTreeMap<String, String>,
) -> Option<String> {
    expression_type_name(expression, aliases, targets, value_types)
        .filter(|owner| targets.knows_method_owner(owner))
}

fn is_provider_finish_owner(owner: &str) -> bool {
    owner.ends_with("ProviderBuild") || owner.ends_with("ProviderRoleBatches")
}

fn in_provider_role_closer_finish(visitor: &SecurityCloseoutVisitor) -> bool {
    visitor
        .impl_stack
        .last()
        .is_some_and(|owner| owner == "ProviderRoleCloser")
        && visitor
            .current_function()
            .is_some_and(|function| function.ends_with("::finish"))
}

fn provider_role_closer_field_has_type(
    expression: &syn::Expr,
    targets: &DivergingCallTargets,
    expected_suffix: &str,
) -> bool {
    let syn::Expr::Field(field) = ungroup_profile_expression(expression) else {
        return false;
    };
    let syn::Member::Named(name) = &field.member else {
        return false;
    };
    targets.struct_fields.iter().any(|((owner, field), ty)| {
        owner.ends_with("ProviderRoleCloser")
            && field == &name.to_string()
            && ty.ends_with(expected_suffix)
    })
}

fn direct_type_receiver_name(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = ungroup_profile_expression(expression) else {
        return None;
    };
    let name = path.path.segments.last()?.ident.to_string();
    name.chars()
        .next()
        .is_some_and(char::is_uppercase)
        .then_some(name)
}

fn field_receiver_owner(expression: &syn::Expr, targets: &DivergingCallTargets) -> Option<String> {
    let syn::Expr::Field(field) = ungroup_profile_expression(expression) else {
        return None;
    };
    let syn::Member::Named(name) = &field.member else {
        return None;
    };
    let mut owners = targets
        .struct_fields
        .iter()
        .filter(|((_, field), _)| field == &name.to_string())
        .map(|(_, owner)| owner.clone());
    let first = owners.next()?;
    owners.all(|owner| owner == first).then_some(first)
}

fn method_is_provider_build(call: &syn::ExprMethodCall) -> bool {
    call.method == "provider_build" && call.args.is_empty()
}

fn provider_finish_expression(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
    value_types: &BTreeMap<String, String>,
) -> bool {
    let syn::Expr::MethodCall(finish) = ungroup_profile_expression(expression) else {
        return false;
    };
    finish.method == "finish"
        && (expression_method_owner(
            ungroup_profile_expression(finish.receiver.as_ref()),
            aliases,
            targets,
            value_types,
        )
        .or_else(|| direct_type_receiver_name(finish.receiver.as_ref()))
        .is_some_and(|owner| owner.ends_with("Constructor"))
            || provider_role_closer_field_has_type(
                finish.receiver.as_ref(),
                targets,
                "Constructor",
            ))
}

fn provider_transfer_expression(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
    value_types: &BTreeMap<String, String>,
) -> bool {
    let syn::Expr::MethodCall(transfer) = ungroup_profile_expression(expression) else {
        return false;
    };
    transfer.method == "transfer"
        && provider_finish_expression(transfer.receiver.as_ref(), aliases, targets, value_types)
}

fn local_method_owner(
    pattern: &syn::Pat,
    initializer: &syn::Expr,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
    value_types: &BTreeMap<String, String>,
) -> Option<String> {
    if let syn::Pat::Type(typed) = pattern
        && let Some(owner) = type_path_owner(typed.ty.as_ref(), aliases, targets)
    {
        return Some(owner);
    }
    expression_type_name(initializer, aliases, targets, value_types)
        .or_else(|| expression_constructor_owner(initializer, aliases))
}

fn expression_constructor_owner(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
) -> Option<String> {
    let expression = ungroup_profile_expression(expression);
    let syn::Expr::Call(call) = expression else {
        return None;
    };
    let path = aliases.resolve_expression_path(call.func.as_ref())?;
    path.rsplit_once("::").map(|(owner, _)| owner.to_string())
}

fn signature_method_owners(
    signature: &syn::Signature,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
) -> BTreeMap<String, String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            let binding = local_binding_ident(argument.pat.as_ref())?.to_string();
            let owner = type_path_owner(argument.ty.as_ref(), aliases, targets)
                .or_else(|| type_path_name(argument.ty.as_ref(), aliases, None))?;
            Some((binding, owner))
        })
        .collect()
}

fn pattern_method_owners(
    pattern: &syn::Pat,
    aliases: &StandardPathAliases,
    targets: &DivergingCallTargets,
) -> BTreeMap<String, String> {
    let syn::Pat::Type(typed) = pattern else {
        return BTreeMap::new();
    };
    let Some(binding) = local_binding_ident(typed.pat.as_ref()) else {
        return BTreeMap::new();
    };
    type_path_owner(typed.ty.as_ref(), aliases, targets)
        .or_else(|| type_path_name(typed.ty.as_ref(), aliases, None))
        .map(|owner| BTreeMap::from([(binding.to_string(), owner)]))
        .unwrap_or_default()
}

fn struct_pattern_method_owners(
    pattern: &syn::Pat,
    targets: &DivergingCallTargets,
) -> BTreeMap<String, String> {
    let syn::Pat::Struct(pattern) = pattern else {
        return BTreeMap::new();
    };
    let owner = pattern
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string());
    pattern
        .fields
        .iter()
        .filter_map(|field| {
            let syn::Member::Named(member) = &field.member else {
                return None;
            };
            let binding = local_binding_ident(&field.pat)?.to_string();
            let returned =
                targets
                    .struct_fields
                    .iter()
                    .find_map(|((receiver, name), returned)| {
                        (name == &member.to_string()
                            && owner
                                .as_ref()
                                .is_some_and(|owner| receiver.ends_with(owner)))
                        .then(|| returned.clone())
                    })?;
            Some((binding, returned))
        })
        .collect()
}

fn signature_value_types(
    signature: &syn::Signature,
    aliases: &StandardPathAliases,
    self_owner: Option<&str>,
) -> BTreeMap<String, String> {
    let mut value_types = BTreeMap::new();
    for input in &signature.inputs {
        match input {
            syn::FnArg::Receiver(_) => {
                if let Some(owner) = self_owner {
                    value_types.insert("self".to_string(), owner.to_string());
                }
            }
            syn::FnArg::Typed(argument) => {
                let Some(binding) = local_binding_ident(argument.pat.as_ref()) else {
                    continue;
                };
                if let Some(ty) = type_path_name(argument.ty.as_ref(), aliases, self_owner) {
                    value_types.insert(binding.to_string(), ty);
                }
            }
        }
    }
    value_types
}

impl DivergingFunctionNameVisitor {
    fn current_aliases(&self) -> StandardPathAliases {
        self.aliases.last().cloned().unwrap_or_default()
    }
}

impl<'ast> syn::visit::Visit<'ast> for DivergingFunctionNameVisitor {
    fn visit_file(&mut self, node: &'ast syn::File) {
        self.aliases
            .push(StandardPathAliases::from_items(&node.items));
        syn::visit::visit_file(self, node);
        self.aliases.pop();
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        self.aliases.push(StandardPathAliases::from_items(items));
        for item in items {
            self.visit_item(item);
        }
        self.aliases.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let aliases = self
            .current_aliases()
            .with_block_imports(&node.block)
            .with_signature_inputs(&node.sig);
        let value_types = signature_value_types(&node.sig, &aliases, None);
        if let syn::ReturnType::Type(_, ty) = &node.sig.output
            && let Some(returned) = type_path_name(ty.as_ref(), &aliases, None)
        {
            self.free_returns
                .insert(node.sig.ident.to_string(), returned);
        }
        self.definitions.push(DivergingFunctionDefinition {
            name: node.sig.ident.to_string(),
            method_owner: None,
            explicit_never: node.sig.asyncness.is_none() && token_key(&node.sig.output) == "->!",
            body: node.sig.asyncness.is_none().then(|| (*node.block).clone()),
            aliases: aliases.clone(),
            value_types,
        });
        self.aliases.push(aliases);
        syn::visit::visit_item_fn(self, node);
        self.aliases.pop();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let method_owner = self.impl_owners.last().cloned();
        let mut aliases = self
            .current_aliases()
            .with_block_imports(&node.block)
            .with_signature_inputs(&node.sig);
        if let Some(owner) = method_owner.as_deref() {
            aliases
                .aliases
                .insert("self".to_string(), owner.to_string());
            aliases
                .aliases
                .insert("Self".to_string(), owner.to_string());
        }
        let value_types = signature_value_types(&node.sig, &aliases, method_owner.as_deref());
        if let syn::ReturnType::Type(_, ty) = &node.sig.output
            && let Some(owner) = method_owner.as_deref()
            && let Some(returned) = type_path_name(ty.as_ref(), &aliases, Some(owner))
        {
            self.method_returns
                .insert((owner.to_string(), node.sig.ident.to_string()), returned);
        }
        self.definitions.push(DivergingFunctionDefinition {
            name: node.sig.ident.to_string(),
            method_owner: method_owner.clone(),
            explicit_never: node.sig.asyncness.is_none() && token_key(&node.sig.output) == "->!",
            body: node.sig.asyncness.is_none().then(|| node.block.clone()),
            aliases: aliases.clone(),
            value_types,
        });
        self.aliases.push(aliases);
        syn::visit::visit_impl_item_fn(self, node);
        self.aliases.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.impl_owners.push(token_key(node.self_ty.as_ref()));
        syn::visit::visit_item_impl(self, node);
        self.impl_owners.pop();
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let aliases = self.current_aliases();
        let owner = aliases.resolve_key(node.ident.to_string());
        for field in &node.fields {
            let Some(name) = field.ident.as_ref() else {
                continue;
            };
            let Some(field_ty) = type_path_name(&field.ty, &aliases, None) else {
                continue;
            };
            self.struct_fields
                .insert((owner.clone(), name.to_string()), field_ty);
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let aliases = self.current_aliases();
        for variant in &node.variants {
            let owner = variant.ident.to_string();
            for field in &variant.fields {
                let (Some(name), Some(field_ty)) = (
                    field.ident.as_ref(),
                    type_path_name(&field.ty, &aliases, None),
                ) else {
                    continue;
                };
                self.struct_fields
                    .insert((owner.clone(), name.to_string()), field_ty);
            }
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_trait_item_fn(&mut self, _node: &'ast syn::TraitItemFn) {}
}

struct LoopBreakVisitor {
    target_label: Option<String>,
    nested_loop_depth: usize,
    target_shadow_depth: usize,
    found: bool,
}

impl LoopBreakVisitor {
    fn label_name(label: Option<&syn::Label>) -> Option<String> {
        label.map(|label| label.name.ident.to_string())
    }

    fn visit_nested_scope(&mut self, label: Option<&syn::Label>, block: &syn::Block) {
        let shadows_target = self.target_label.is_some()
            && Self::label_name(label).as_ref() == self.target_label.as_ref();
        self.nested_loop_depth = self.nested_loop_depth.saturating_add(1);
        if shadows_target {
            self.target_shadow_depth = self.target_shadow_depth.saturating_add(1);
        }
        syn::visit::Visit::visit_block(self, block);
        if shadows_target {
            self.target_shadow_depth = self.target_shadow_depth.saturating_sub(1);
        }
        self.nested_loop_depth = self.nested_loop_depth.saturating_sub(1);
    }
}

impl<'ast> syn::visit::Visit<'ast> for LoopBreakVisitor {
    fn visit_expr_break(&mut self, node: &'ast syn::ExprBreak) {
        let exits_target = match &node.label {
            Some(label) => {
                self.target_shadow_depth == 0
                    && self
                        .target_label
                        .as_ref()
                        .is_some_and(|target| target == &label.ident.to_string())
            }
            None => self.nested_loop_depth == 0,
        };
        self.found |= exits_target;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.visit_nested_scope(node.label.as_ref(), &node.body);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.visit_nested_scope(node.label.as_ref(), &node.body);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.visit_nested_scope(node.label.as_ref(), &node.body);
    }

    fn visit_expr_block(&mut self, node: &'ast syn::ExprBlock) {
        let shadows_target = self.target_label.is_some()
            && Self::label_name(node.label.as_ref()).as_ref() == self.target_label.as_ref();
        if shadows_target {
            self.target_shadow_depth = self.target_shadow_depth.saturating_add(1);
        }
        syn::visit::visit_block(self, &node.block);
        if shadows_target {
            self.target_shadow_depth = self.target_shadow_depth.saturating_sub(1);
        }
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
}

fn block_contains_target_break(block: &syn::Block, label: Option<&syn::Label>) -> bool {
    let mut visitor = LoopBreakVisitor {
        target_label: LoopBreakVisitor::label_name(label),
        nested_loop_depth: 0,
        target_shadow_depth: 0,
        found: false,
    };
    syn::visit::Visit::visit_block(&mut visitor, block);
    visitor.found
}

fn iterator_expression_is_obviously_infinite(
    expression: &syn::Expr,
    aliases: &StandardPathAliases,
) -> bool {
    match expression {
        syn::Expr::Group(group) => {
            iterator_expression_is_obviously_infinite(group.expr.as_ref(), aliases)
        }
        syn::Expr::Paren(paren) => {
            iterator_expression_is_obviously_infinite(paren.expr.as_ref(), aliases)
        }
        syn::Expr::Call(call) => aliases.is_infinite_iterator_root(call.func.as_ref()),
        syn::Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "by_ref"
                    | "chain"
                    | "cloned"
                    | "copied"
                    | "cycle"
                    | "enumerate"
                    | "filter"
                    | "filter_map"
                    | "flat_map"
                    | "flatten"
                    | "fuse"
                    | "inspect"
                    | "map"
                    | "peekable"
                    | "rev"
                    | "skip"
                    | "skip_while"
                    | "step_by"
            ) =>
        {
            iterator_expression_is_obviously_infinite(call.receiver.as_ref(), aliases)
        }
        _ => false,
    }
}

fn for_loop_is_obviously_diverging(
    loop_expression: &syn::ExprForLoop,
    aliases: &StandardPathAliases,
) -> bool {
    iterator_expression_is_obviously_infinite(loop_expression.expr.as_ref(), aliases)
        && !block_contains_target_break(&loop_expression.body, loop_expression.label.as_ref())
}

#[derive(Default)]
struct DivergenceEscapeVisitor {
    found: bool,
}

impl DivergenceEscapeVisitor {
    fn macro_is_known_diverging(macro_path: &syn::Path) -> bool {
        macro_path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "panic" | "unreachable" | "todo" | "unimplemented" | "bail"
            )
        })
    }
}

fn static_bool(expression: &syn::Expr) -> Option<bool> {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Bool(value),
            ..
        }) => Some(value.value),
        syn::Expr::Group(group) => static_bool(&group.expr),
        syn::Expr::Paren(paren) => static_bool(&paren.expr),
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => {
            static_bool(&unary.expr).map(|value| !value)
        }
        syn::Expr::Binary(binary) => match binary.op {
            syn::BinOp::And(_) => Some(static_bool(&binary.left)? && static_bool(&binary.right)?),
            syn::BinOp::Or(_) => Some(static_bool(&binary.left)? || static_bool(&binary.right)?),
            syn::BinOp::Eq(_) => {
                Some(static_literal(&binary.left)? == static_literal(&binary.right)?)
            }
            syn::BinOp::Ne(_) => {
                Some(static_literal(&binary.left)? != static_literal(&binary.right)?)
            }
            _ => None,
        },
        _ => None,
    }
}

fn static_literal(expression: &syn::Expr) -> Option<String> {
    match expression {
        syn::Expr::Lit(literal) => Some(token_key(&literal.lit)),
        syn::Expr::Group(group) => static_literal(&group.expr),
        syn::Expr::Paren(paren) => static_literal(&paren.expr),
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Neg(_)) => {
            Some(format!("-{}", static_literal(&unary.expr)?))
        }
        _ => None,
    }
}

fn pattern_matches_literal(pattern: &syn::Pat, literal: &str) -> Option<bool> {
    match pattern {
        syn::Pat::Lit(pattern) => Some(token_key(&pattern.lit) == literal),
        syn::Pat::Wild(_) | syn::Pat::Rest(_) => Some(true),
        syn::Pat::Paren(paren) => pattern_matches_literal(&paren.pat, literal),
        syn::Pat::Reference(reference) => pattern_matches_literal(&reference.pat, literal),
        syn::Pat::Or(or) => {
            let matches = or
                .cases
                .iter()
                .map(|case| pattern_matches_literal(case, literal))
                .collect::<Option<Vec<_>>>()?;
            Some(matches.into_iter().any(|matched| matched))
        }
        _ => None,
    }
}

impl<'ast> syn::visit::Visit<'ast> for DivergenceEscapeVisitor {
    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.found = true;
    }

    fn visit_expr_try(&mut self, _node: &'ast syn::ExprTry) {
        self.found = true;
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        self.found |= !Self::macro_is_known_diverging(&node.mac.path);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        self.found |= !Self::macro_is_known_diverging(&node.mac.path);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if let Some(condition) = static_bool(&node.cond) {
            if condition {
                syn::visit::Visit::visit_block(self, &node.then_branch);
            } else if let Some((_, otherwise)) = &node.else_branch {
                self.visit_expr(otherwise.as_ref());
            }
            return;
        }
        syn::visit::visit_expr_if(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let Some(literal) = static_literal(&node.expr) else {
            syn::visit::visit_expr_match(self, node);
            return;
        };
        for arm in &node.arms {
            let pattern_match = pattern_matches_literal(&arm.pat, &literal);
            if pattern_match == Some(false) {
                continue;
            }
            let guard = arm.guard.as_ref().and_then(|(_, guard)| static_bool(guard));
            if guard == Some(false) {
                continue;
            }
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard.as_ref());
            }
            self.visit_expr(arm.body.as_ref());
            if pattern_match == Some(true) && (arm.guard.is_none() || guard == Some(true)) {
                break;
            }
        }
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if static_bool(&node.cond) == Some(false) {
            return;
        }
        syn::visit::visit_expr_while(self, node);
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
}

fn block_is_safe_for_divergence_inference(block: &syn::Block) -> bool {
    let mut visitor = DivergenceEscapeVisitor::default();
    syn::visit::Visit::visit_block(&mut visitor, block);
    !visitor.found
}

fn expression_is_obviously_diverging(
    expression: &syn::Expr,
    diverging_names: &DivergingCallTargets,
    aliases: &StandardPathAliases,
    value_types: &BTreeMap<String, String>,
) -> bool {
    match expression {
        syn::Expr::Group(group) => expression_is_obviously_diverging(
            group.expr.as_ref(),
            diverging_names,
            aliases,
            value_types,
        ),
        syn::Expr::Paren(paren) => expression_is_obviously_diverging(
            paren.expr.as_ref(),
            diverging_names,
            aliases,
            value_types,
        ),
        syn::Expr::Block(block) => {
            block_is_obviously_diverging(&block.block, diverging_names, aliases, value_types)
        }
        syn::Expr::Const(block) => {
            block_is_obviously_diverging(&block.block, diverging_names, aliases, value_types)
        }
        syn::Expr::TryBlock(block) => {
            block_is_obviously_diverging(&block.block, diverging_names, aliases, value_types)
        }
        syn::Expr::Unsafe(block) => {
            block_is_obviously_diverging(&block.block, diverging_names, aliases, value_types)
        }
        syn::Expr::Loop(loop_expression) => {
            !block_contains_target_break(&loop_expression.body, loop_expression.label.as_ref())
        }
        syn::Expr::While(while_expression) => {
            matches!(while_expression.cond.as_ref(), syn::Expr::Lit(literal) if matches!(&literal.lit, syn::Lit::Bool(value) if value.value))
                && !block_contains_target_break(
                    &while_expression.body,
                    while_expression.label.as_ref(),
                )
        }
        syn::Expr::ForLoop(loop_expression) => {
            for_loop_is_obviously_diverging(loop_expression, aliases)
        }
        syn::Expr::Call(call) => {
            let name = match call.func.as_ref() {
                syn::Expr::Path(path) if path.path.segments.len() == 1 => path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string()),
                _ => None,
            };
            name.is_some_and(|name| {
                !aliases.value_is_shadowed(&name) && diverging_names.contains(&name)
            }) || diverging_names.associated_function_is_diverging(call.func.as_ref(), aliases)
                || aliases.is_process_terminator(call.func.as_ref())
                || call.args.iter().any(|argument| {
                    expression_is_obviously_diverging(
                        argument,
                        diverging_names,
                        aliases,
                        value_types,
                    )
                })
        }
        syn::Expr::MethodCall(call) => {
            diverging_names.method_is_diverging(
                call.receiver.as_ref(),
                &call.method,
                aliases,
                value_types,
            ) || expression_is_obviously_diverging(
                call.receiver.as_ref(),
                diverging_names,
                aliases,
                value_types,
            ) || call.args.iter().any(|argument| {
                expression_is_obviously_diverging(argument, diverging_names, aliases, value_types)
            })
        }
        syn::Expr::If(branch) => {
            let mut then_aliases = aliases.clone();
            let mut then_types = value_types.clone();
            if let syn::Expr::Let(binding) = branch.cond.as_ref() {
                then_aliases.shadow_pattern(binding.pat.as_ref());
                for name in pattern_binding_names(binding.pat.as_ref()) {
                    then_types.remove(&name);
                }
            }
            let then_diverges = block_is_obviously_diverging(
                &branch.then_branch,
                diverging_names,
                &then_aliases,
                &then_types,
            );
            match &branch.else_branch {
                Some((_, otherwise)) => {
                    then_diverges
                        && expression_is_obviously_diverging(
                            otherwise.as_ref(),
                            diverging_names,
                            aliases,
                            value_types,
                        )
                }
                None => false,
            }
        }
        syn::Expr::Match(branch) => {
            !branch.arms.is_empty()
                && branch.arms.iter().all(|arm| {
                    let mut arm_aliases = aliases.clone();
                    let mut arm_types = value_types.clone();
                    arm_aliases.shadow_pattern(&arm.pat);
                    for name in pattern_binding_names(&arm.pat) {
                        arm_types.remove(&name);
                    }
                    arm.guard.is_none()
                        && expression_is_obviously_diverging(
                            arm.body.as_ref(),
                            diverging_names,
                            &arm_aliases,
                            &arm_types,
                        )
                })
        }
        syn::Expr::Macro(macro_expression) => {
            DivergenceEscapeVisitor::macro_is_known_diverging(&macro_expression.mac.path)
        }
        syn::Expr::Await(awaited) => match awaited.base.as_ref() {
            syn::Expr::Async(block) => {
                block_is_obviously_diverging(&block.block, diverging_names, aliases, value_types)
            }
            expression => {
                expression_is_obviously_diverging(expression, diverging_names, aliases, value_types)
            }
        },
        syn::Expr::Try(expression) => expression_is_obviously_diverging(
            expression.expr.as_ref(),
            diverging_names,
            aliases,
            value_types,
        ),
        _ => false,
    }
}

fn block_is_obviously_diverging(
    block: &syn::Block,
    diverging_names: &DivergingCallTargets,
    aliases: &StandardPathAliases,
    value_types: &BTreeMap<String, String>,
) -> bool {
    let mut aliases = aliases.with_block_imports(block);
    let mut value_types = value_types.clone();
    for statement in &block.stmts {
        match statement {
            syn::Stmt::Local(local) => {
                if local.init.as_ref().is_some_and(|init| {
                    expression_is_obviously_diverging(
                        init.expr.as_ref(),
                        diverging_names,
                        &aliases,
                        &value_types,
                    )
                }) {
                    return true;
                }
                if let Some(binding) = local_binding_ident(&local.pat) {
                    let inferred = local.init.as_ref().and_then(|init| {
                        local_method_owner(
                            &local.pat,
                            init.expr.as_ref(),
                            &aliases,
                            diverging_names,
                            &value_types,
                        )
                    });
                    match inferred {
                        Some(owner) => {
                            value_types.insert(binding.to_string(), owner);
                        }
                        None => {
                            value_types.remove(&binding.to_string());
                        }
                    }
                } else {
                    for name in pattern_binding_names(&local.pat) {
                        value_types.remove(&name);
                    }
                }
                aliases.shadow_pattern(&local.pat);
            }
            syn::Stmt::Expr(expression, _)
                if expression_is_obviously_diverging(
                    expression,
                    diverging_names,
                    &aliases,
                    &value_types,
                ) =>
            {
                return true;
            }
            syn::Stmt::Macro(statement)
                if DivergenceEscapeVisitor::macro_is_known_diverging(&statement.mac.path) =>
            {
                return true;
            }
            syn::Stmt::Item(_) | syn::Stmt::Expr(_, _) | syn::Stmt::Macro(_) => {}
        }
    }
    false
}

fn collect_diverging_function_names<'a>(
    files: impl IntoIterator<Item = &'a syn::File>,
) -> DivergingCallTargets {
    let mut visitor = DivergingFunctionNameVisitor::default();
    for file in files {
        syn::visit::Visit::visit_file(&mut visitor, file);
    }
    let mut targets = DivergingCallTargets {
        free_returns: visitor.free_returns.clone(),
        method_returns: visitor.method_returns.clone(),
        struct_fields: visitor.struct_fields.clone(),
        ..DivergingCallTargets::default()
    };
    for definition in visitor
        .definitions
        .iter()
        .filter(|definition| definition.explicit_never)
    {
        targets.insert_definition(definition);
    }
    loop {
        let newly_diverging = visitor
            .definitions
            .iter()
            .filter(|definition| !targets.contains_definition(definition))
            .filter(|definition| {
                definition.body.as_ref().is_some_and(|body| {
                    block_is_safe_for_divergence_inference(body)
                        && block_is_obviously_diverging(
                            body,
                            &targets,
                            &definition.aliases,
                            &definition.value_types,
                        )
                })
            })
            .collect::<Vec<_>>();
        if newly_diverging.is_empty() {
            break;
        }
        for definition in newly_diverging {
            targets.insert_definition(definition);
        }
    }
    targets
}

fn rust_source_module_identity(relative: &Path) -> Vec<String> {
    let mut components = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let file = components.pop().unwrap_or_default();
    if file == "lib.rs" {
        return vec!["crate".to_string()];
    }
    if file == "main.rs" {
        return vec!["binary".to_string()];
    }
    if components
        .first()
        .is_some_and(|component| component == "bin")
    {
        let mut module = vec!["binary".to_string()];
        module.extend(components.into_iter().skip(1));
        if file != "mod.rs" {
            module.push(file.trim_end_matches(".rs").to_string());
        }
        return module;
    }
    let mut module = vec!["crate".to_string()];
    module.extend(components);
    if file != "mod.rs" {
        module.push(file.trim_end_matches(".rs").to_string());
    }
    module
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
    function_symbols: BTreeMap<String, BTreeSet<String>>,
    invalid_functions: BTreeSet<String>,
    startup_adapter_roots: BTreeSet<String>,
    profile_binding_definitions: usize,
    exact_profile_binding_definitions: usize,
    legacy_service_token_migration: bool,
    legacy_token_surface: bool,
    mixed_key_provider: bool,
    split_scheme_provider_binding: bool,
    listener_observation_producers: BTreeSet<String>,
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
        self.listener_observation_producers
            .extend(other.listener_observation_producers);
        self.startup_adapter_roots
            .extend(other.startup_adapter_roots);
        self.invalid_functions.extend(other.invalid_functions);
        for (symbol, definitions) in other.function_symbols {
            self.function_symbols
                .entry(symbol)
                .or_default()
                .extend(definitions);
        }
        for (name, info) in other.functions {
            self.functions.entry(name).or_default().merge(info);
        }
    }

    fn register_function(&mut self, identity: String, symbols: impl IntoIterator<Item = String>) {
        self.functions.entry(identity.clone()).or_default();
        for symbol in symbols {
            self.function_symbols
                .entry(symbol)
                .or_default()
                .insert(identity.clone());
        }
    }

    fn resolve_function(&self, symbol: &str) -> Option<String> {
        if let Some(unqualified) = symbol.strip_prefix("unqualified::")
            && let Some((module, function)) = unqualified.rsplit_once("::")
        {
            let local = format!("free::{module}::{function}");
            if let Some(definition) = self.resolve_exact_symbol(&local) {
                return Some(definition);
            }
            return self.resolve_exact_symbol(&format!("free::*::{function}"));
        }
        self.resolve_exact_symbol(symbol)
    }

    fn resolve_exact_symbol(&self, symbol: &str) -> Option<String> {
        let definitions = self.function_symbols.get(symbol)?;
        let mut definitions = definitions.iter();
        let definition = definitions.next()?.clone();
        definitions.next().is_none().then_some(definition)
    }

    fn resolve_listener_producer(&self, symbol: &str) -> Option<String> {
        if let Some(name) = symbol.strip_prefix("listener-producer-name::") {
            let suffix = format!("::{name}");
            let mut matches = self
                .listener_observation_producers
                .iter()
                .filter(|identity| identity.ends_with(&suffix));
            let first = matches.next()?.clone();
            return matches.next().is_none().then_some(first);
        }
        self.resolve_function(symbol)
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
        let mut listener_publish_sources = BTreeSet::new();
        let mut stack = self
            .resolve_function("free::crate::run")
            .into_iter()
            .collect::<Vec<_>>();
        stack.extend(self.startup_adapter_roots.iter().cloned());
        while let Some(name) = stack.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            if self.invalid_functions.contains(&name) {
                continue;
            }
            let Some(info) = self.functions.get(&name) else {
                continue;
            };
            out.merge(info.evidence.clone());
            listener_publish_sources.extend(info.listener_publish_sources.iter().cloned());
            stack.extend(
                info.calls
                    .iter()
                    .filter_map(|call| self.resolve_function(call)),
            );
            stack.extend(
                info.listener_publish_sources
                    .iter()
                    .filter_map(|call| self.resolve_listener_producer(call)),
            );
        }
        out.exact_profile_binding_mapping =
            self.profile_binding_definitions == 1 && self.exact_profile_binding_definitions == 1;
        out.legacy_service_token_migration = self.legacy_service_token_migration;
        out.legacy_token_surface = self.legacy_token_surface;
        out.mixed_key_provider = self.mixed_key_provider;
        out.split_scheme_provider_binding = self.split_scheme_provider_binding;
        out.listener_publish_flow |= listener_publish_sources.into_iter().any(|source| {
            self.resolve_listener_producer(&source)
                .is_some_and(|producer| self.listener_observation_producers.contains(&producer))
        });
        out.inventory_publish |= out.listener_publish_flow;
        out
    }
}

#[derive(Clone, Default)]
struct SecurityFunctionEvidence {
    evidence: SecurityCloseoutEvidence,
    calls: BTreeSet<String>,
    listener_publish_sources: BTreeSet<String>,
}

impl SecurityFunctionEvidence {
    fn merge(&mut self, other: Self) {
        self.evidence.merge(other.evidence);
        self.calls.extend(other.calls);
        self.listener_publish_sources
            .extend(other.listener_publish_sources);
    }
}

#[cfg(test)]
fn file_security_closeout_program(file: &syn::File) -> SecurityCloseoutProgram {
    file_security_closeout_program_at(
        file,
        "lib.rs".to_string(),
        vec!["crate".to_string()],
        collect_diverging_function_names(std::iter::once(file)),
    )
}

fn file_security_closeout_program_at(
    file: &syn::File,
    file_identity: String,
    module_identity: Vec<String>,
    diverging_function_names: DivergingCallTargets,
) -> SecurityCloseoutProgram {
    let path_aliases = StandardPathAliases::from_items(&file.items);
    let mut visitor = SecurityCloseoutVisitor {
        file_identity,
        module_stack: module_identity,
        diverging_function_names,
        path_aliases,
        ..SecurityCloseoutVisitor::default()
    };
    syn::visit::Visit::visit_file(&mut visitor, file);
    visitor.program
}

#[derive(Default)]
struct SecurityCloseoutVisitor {
    program: SecurityCloseoutProgram,
    file_identity: String,
    module_stack: Vec<String>,
    function_stack: Vec<String>,
    impl_stack: Vec<String>,
    impl_identity_stack: Vec<String>,
    impl_method_owner_stack: Vec<String>,
    function_key_apis: Vec<(bool, bool)>,
    profile_binding_locals: Vec<BTreeMap<String, TokenProfileBridgeKind>>,
    profile_carrier_bindings: Vec<BTreeSet<String>>,
    typed_token_provider_bindings: Vec<BTreeSet<String>>,
    typed_listener_spec_bindings: Vec<BTreeSet<String>>,
    plan_auth_scheme_locals: Vec<BTreeSet<String>>,
    diverging_function_names: DivergingCallTargets,
    path_aliases: StandardPathAliases,
    value_binding_scopes: Vec<BTreeSet<String>>,
    value_binding_method_owners: Vec<BTreeMap<String, String>>,
    listener_observation_locals: Vec<BTreeSet<String>>,
    inventory_publication_type_params: Vec<BTreeSet<String>>,
    provider_transferred_receipt_locals: Vec<BTreeSet<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TokenProfileBridgeKind {
    RssAccess,
    FederatedAccess,
    ServiceToken,
}

impl<'ast> syn::visit::Visit<'ast> for SecurityCloseoutVisitor {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.push_value_binding_scope(BTreeSet::new(), BTreeMap::new());
        syn::visit::visit_block(self, node);
        self.pop_value_binding_scope();
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if matches!(node, syn::Stmt::Item(_)) && self.current_function().is_some() {
            self.invalidate_current_function();
            return;
        }
        syn::visit::visit_stmt(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        if node.content.is_some() {
            self.module_stack.push(node.ident.to_string());
            syn::visit::visit_item_mod(self, node);
            self.module_stack.pop();
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let symbol = self.free_function_symbol(&node.sig.ident.to_string());
        let identity = self.definition_identity(&symbol);
        self.program.register_function(
            identity.clone(),
            [
                symbol,
                Self::short_free_function_symbol(&node.sig.ident.to_string()),
            ],
        );
        if signature_returns_listener_observations(&node.sig) {
            self.program
                .listener_observation_producers
                .insert(identity.clone());
        }
        self.function_stack.push(identity);
        self.push_value_binding_scope(
            signature_binding_names(&node.sig),
            signature_method_owners(
                &node.sig,
                &self.path_aliases,
                &self.diverging_function_names,
            ),
        );
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        self.listener_observation_locals.push(BTreeSet::new());
        syn::visit::visit_item_fn(self, node);
        self.listener_observation_locals.pop();
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.pop_value_binding_scope();
        self.function_stack.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if has_non_production_attributes(&node.attrs) {
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
        let owner_identity = self.impl_owner_identity(node);
        if let (Some(owner), Some(owner_identity)) = (owner, owner_identity) {
            let is_startup_adapter = node.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments.last().is_some_and(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "StartupAdapter" | "LaunchAdapter"
                    )
                })
            });
            if is_startup_adapter {
                for method in ["prepare", "activate"] {
                    if node.items.iter().any(|item| {
                        matches!(item, syn::ImplItem::Fn(function) if function.sig.ident == method)
                    }) {
                        let symbol = Self::qualified_method_symbol(&owner_identity, method);
                        self.program
                            .startup_adapter_roots
                            .insert(self.definition_identity(&symbol));
                    }
                }
            }
            self.impl_stack.push(owner);
            self.impl_identity_stack.push(owner_identity);
            self.impl_method_owner_stack
                .push(token_key(node.self_ty.as_ref()));
            let inventory_params = node
                .generics
                .where_clause
                .iter()
                .flat_map(|clause| &clause.predicates)
                .filter_map(|predicate| {
                    let syn::WherePredicate::Type(predicate) = predicate else {
                        return None;
                    };
                    let syn::Type::Path(ty) = &predicate.bounded_ty else {
                        return None;
                    };
                    let has_inventory_bound = predicate.bounds.iter().any(|bound| {
                        matches!(bound, syn::TypeParamBound::Trait(bound)
                            if bound.path.segments.last().is_some_and(|segment| segment.ident == "InventoryPublication"))
                    });
                    has_inventory_bound
                        .then(|| ty.path.segments.last().map(|segment| segment.ident.to_string()))
                        .flatten()
                })
                .collect();
            self.inventory_publication_type_params
                .push(inventory_params);
            syn::visit::visit_item_impl(self, node);
            self.inventory_publication_type_params.pop();
            self.impl_method_owner_stack.pop();
            self.impl_identity_stack.pop();
            self.impl_stack.pop();
        }
    }

    #[allow(clippy::cognitive_complexity)]
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        let Some(owner) = self.impl_stack.last().cloned() else {
            return;
        };
        let Some(owner_identity) = self.impl_identity_stack.last().cloned() else {
            return;
        };
        let Some(method_owner) = self.impl_method_owner_stack.last().cloned() else {
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
        let method = node.sig.ident.to_string();
        let symbol = Self::qualified_method_symbol(&owner_identity, &method);
        let identity = self.definition_identity(&symbol);
        self.program.register_function(
            identity.clone(),
            [symbol, Self::short_method_symbol(&owner, &method)],
        );
        if signature_returns_listener_observations(&node.sig) {
            self.program
                .listener_observation_producers
                .insert(identity.clone());
        }
        self.function_stack.push(identity);
        let mut method_owners = signature_method_owners(
            &node.sig,
            &self.path_aliases,
            &self.diverging_function_names,
        );
        if node
            .sig
            .inputs
            .iter()
            .any(|input| matches!(input, syn::FnArg::Receiver(_)))
        {
            method_owners.insert("self".to_string(), method_owner);
        }
        self.push_value_binding_scope(signature_binding_names(&node.sig), method_owners);
        self.function_key_apis.push((false, false));
        self.profile_binding_locals.push(BTreeMap::new());
        self.typed_token_provider_bindings
            .push(token_provider_binding_parameters(&node.sig));
        self.typed_listener_spec_bindings
            .push(listener_execution_spec_parameters(&node.sig));
        self.plan_auth_scheme_locals.push(BTreeSet::new());
        self.listener_observation_locals.push(BTreeSet::new());
        self.provider_transferred_receipt_locals
            .push(BTreeSet::new());
        syn::visit::visit_impl_item_fn(self, node);
        self.provider_transferred_receipt_locals.pop();
        self.listener_observation_locals.pop();
        self.plan_auth_scheme_locals.pop();
        self.typed_listener_spec_bindings.pop();
        self.typed_token_provider_bindings.pop();
        self.profile_binding_locals.pop();
        self.finish_function_key_apis();
        self.pop_value_binding_scope();
        self.function_stack.pop();
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if has_non_production_attributes(&node.attrs) {
            return;
        }
        if ident_contains(&node.ident, "INTERNAL_SERVICE_TOKEN_MIGRATION") {
            self.program.legacy_service_token_migration = true;
        }
        syn::visit::visit_item_const(self, node);
    }

    #[allow(clippy::cognitive_complexity)]
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Closure(closure) = ungroup_profile_expression(node.func.as_ref()) {
            for argument in &node.args {
                self.visit_expr(argument);
            }
            let mut bindings = BTreeSet::new();
            let mut method_owners = BTreeMap::new();
            for input in &closure.inputs {
                bindings.extend(pattern_binding_names(input));
                method_owners.extend(pattern_method_owners(
                    input,
                    &self.path_aliases,
                    &self.diverging_function_names,
                ));
            }
            self.push_value_binding_scope(bindings, method_owners);
            self.visit_expr(closure.body.as_ref());
            self.pop_value_binding_scope();
            return;
        }
        let bare_diverging_call = match node.func.as_ref() {
            syn::Expr::Path(path) if path.path.segments.len() == 1 => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .is_some_and(|name| {
                    !self.value_binding_is_shadowed(&name)
                        && self.diverging_function_names.contains(&name)
                }),
            _ => false,
        };
        if bare_diverging_call
            || self
                .diverging_function_names
                .associated_function_is_diverging(node.func.as_ref(), &self.path_aliases)
            || StandardPathAliases::is_explicit_process_terminator(node.func.as_ref())
        {
            self.invalidate_current_function();
        }
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
        if call_path_ends_with(node.func.as_ref(), "boxed")
            && call_path_contains_segment(node.func.as_ref(), "SharedManagedResource")
        {
            self.record_evidence(|e| {
                e.runtime_oidc_managed_resource = true;
                e.profile_managed_resource_calls =
                    e.profile_managed_resource_calls.saturating_add(1);
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
        if (call_path_ends_with(node.func.as_ref(), "exact_join")
            && call_path_contains_segment(node.func.as_ref(), "ProviderRoleBatches"))
            || (call_path_ends_with(node.func.as_ref(), "from_plan")
                && call_path_contains_segment(node.func.as_ref(), "ProviderBuild"))
        {
            self.record_evidence(|e| e.provider_selection = true);
        }
        if let Some(observation) = listener_observation_call(node) {
            self.record_evidence(|e| e.listener_observations.push(observation));
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        let destructured_method_owners =
            struct_pattern_method_owners(&node.pat, &self.diverging_function_names);
        let method_owner = node.init.as_ref().and_then(|init| {
            local_method_owner(
                &node.pat,
                init.expr.as_ref(),
                &self.path_aliases,
                &self.diverging_function_names,
                &self.value_binding_type_map(),
            )
        });
        if let (Some(binding), Some(init), Some(locals)) = (
            local_binding_ident(&node.pat),
            node.init.as_ref(),
            self.listener_observation_locals.last_mut(),
        ) && expression_contains_listener_observation(init.expr.as_ref())
        {
            locals.insert(binding.to_string());
        }
        if in_provider_role_closer_finish(self)
            && let (Some(binding), Some(init)) =
                (local_binding_ident(&node.pat), node.init.as_ref())
        {
            let value_types = self.value_binding_type_map();
            let is_transferred = provider_transfer_expression(
                init.expr.as_ref(),
                &self.path_aliases,
                &self.diverging_function_names,
                &value_types,
            );
            if is_transferred
                && let Some(locals) = self.provider_transferred_receipt_locals.last_mut()
            {
                locals.insert(binding.to_string());
            }
        }
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
        if let Some(scope) = self.value_binding_scopes.last_mut() {
            scope.extend(pattern_binding_names(&node.pat));
        }
        if let Some(scope) = self.value_binding_method_owners.last_mut() {
            scope.extend(destructured_method_owners);
        }
        if let (Some(owner), Some(binding), Some(scope)) = (
            method_owner,
            local_binding_ident(&node.pat),
            self.value_binding_method_owners.last_mut(),
        ) {
            scope.insert(binding.to_string(), owner);
        }
    }

    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let carrier = profile_carrier_binding(&node.pat);
        self.push_value_binding_scope(
            pattern_binding_names(&node.pat),
            struct_pattern_method_owners(&node.pat, &self.diverging_function_names),
        );
        if let Some(binding) = carrier.as_ref() {
            self.profile_carrier_bindings
                .push(BTreeSet::from([binding.clone()]));
        }
        syn::visit::visit_arm(self, node);
        if carrier.is_some() {
            self.profile_carrier_bindings.pop();
        }
        self.pop_value_binding_scope();
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_expr(node.cond.as_ref());
        let mut bindings = BTreeSet::new();
        if let syn::Expr::Let(binding) = node.cond.as_ref() {
            bindings.extend(pattern_binding_names(binding.pat.as_ref()));
        }
        self.push_value_binding_scope(bindings, BTreeMap::new());
        self.visit_block(&node.then_branch);
        self.pop_value_binding_scope();
        if let Some((_, otherwise)) = &node.else_branch {
            self.visit_expr(otherwise.as_ref());
        }
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.visit_expr(node.expr.as_ref());
        self.push_value_binding_scope(pattern_binding_names(&node.pat), BTreeMap::new());
        self.visit_block(&node.body);
        self.pop_value_binding_scope();
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let mut bindings = BTreeSet::new();
        let mut method_owners = BTreeMap::new();
        for input in &node.inputs {
            bindings.extend(pattern_binding_names(input));
            method_owners.extend(pattern_method_owners(
                input,
                &self.path_aliases,
                &self.diverging_function_names,
            ));
        }
        self.push_value_binding_scope(bindings, method_owners);
        self.visit_expr(node.body.as_ref());
        self.pop_value_binding_scope();
    }

    #[allow(
        clippy::cognitive_complexity,
        reason = "one typed call visitor records the closed security and lifecycle evidence vocabulary"
    )]
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let receiver_name = simple_path_ident(ungroup_profile_expression(node.receiver.as_ref()));
        let bound_owner = receiver_name
            .as_deref()
            .and_then(|name| self.value_binding_method_owner(name))
            .map(str::to_owned);
        let receiver_is_shadowed = receiver_name
            .as_deref()
            .is_some_and(|name| self.value_binding_is_shadowed(name));
        let value_types = self.value_binding_type_map();
        let receiver_owner = bound_owner
            .clone()
            .or_else(|| {
                expression_method_owner(
                    ungroup_profile_expression(node.receiver.as_ref()),
                    &self.path_aliases,
                    &self.diverging_function_names,
                    &value_types,
                )
            })
            .or_else(|| {
                field_receiver_owner(node.receiver.as_ref(), &self.diverging_function_names)
            })
            .or_else(|| direct_type_receiver_name(node.receiver.as_ref()));
        if method_is_provider_build(node)
            && receiver_owner
                .as_deref()
                .is_some_and(|owner| owner.ends_with("Plan"))
        {
            self.record_evidence(|e| e.provider_selection = true);
        }
        let diverges = bound_owner.as_deref().is_some_and(|owner| {
            self.diverging_function_names
                .owner_method_is_diverging(owner, &node.method)
        }) || (!receiver_is_shadowed
            && self.diverging_function_names.method_is_diverging(
                node.receiver.as_ref(),
                &node.method,
                &self.path_aliases,
                &value_types,
            ));
        if diverges {
            self.invalidate_current_function();
        }
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
            self.record_call(&Self::short_method_symbol(owner, &method));
        } else if let Some(owner) = bound_owner.as_deref() {
            let owner = owner.rsplit("::").next().unwrap_or(owner);
            self.record_call(&Self::short_method_symbol(owner, &method));
        } else if let Some(identity) = self.method_receiver_identity(&node.receiver, &method) {
            self.record_call(&identity);
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
        match node.method.to_string().as_str() {
            "finish"
                if receiver_owner
                    .as_deref()
                    .is_some_and(is_provider_finish_owner)
                    || (in_provider_role_closer_finish(self)
                        && provider_role_closer_field_has_type(
                            node.receiver.as_ref(),
                            &self.diverging_function_names,
                            "ProviderRoleBatches",
                        )) =>
            {
                let runtime = receiver_owner
                    .as_deref()
                    .is_some_and(|owner| owner.ends_with("ProviderBuild"));
                let transferred_receipt_flow = !runtime
                    && node.args.iter().any(|argument| {
                        provider_transfer_expression(
                            argument,
                            &self.path_aliases,
                            &self.diverging_function_names,
                            &value_types,
                        ) || simple_path_ident(ungroup_profile_expression(argument)).is_some_and(
                            |binding| {
                                self.provider_transferred_receipt_locals
                                    .last()
                                    .is_some_and(|locals| locals.contains(&binding))
                            },
                        )
                    });
                self.record_evidence(|e| {
                    e.provider_typed_finish = true;
                    e.provider_finish_transfer |= transferred_receipt_flow;
                    e.runtime_provider_finish |= runtime;
                });
            }
            "publish" => {
                let inventory_params = self
                    .inventory_publication_type_params
                    .iter()
                    .flatten()
                    .collect::<BTreeSet<_>>();
                let receiver_field = receiver_name.clone().or_else(|| {
                    let syn::Expr::Field(field) =
                        ungroup_profile_expression(node.receiver.as_ref())
                    else {
                        return None;
                    };
                    let syn::Member::Named(name) = &field.member else {
                        return None;
                    };
                    Some(name.to_string())
                });
                let typed_inventory_sink = receiver_owner.as_deref().is_some_and(|owner| {
                    owner == "runtimeexec::inventory::InventoryPublisher"
                        || inventory_params
                            .contains(&owner.rsplit("::").next().unwrap_or(owner).to_string())
                }) || receiver_field.as_deref().is_some_and(|field| {
                    self.diverging_function_names
                        .struct_fields
                        .iter()
                        .any(|((_, name), ty)| name == field && inventory_params.contains(ty))
                });
                self.record_evidence(|e| {
                    e.listener_publish_sink_seen |= typed_inventory_sink;
                    e.inventory_publish |= typed_inventory_sink;
                });
                let direct_or_bound = node.args.iter().any(|argument| {
                    expression_contains_listener_observation(argument)
                        || simple_path_ident(ungroup_profile_expression(argument)).is_some_and(
                            |binding| {
                                self.listener_observation_locals
                                    .last()
                                    .is_some_and(|locals| locals.contains(&binding))
                            },
                        )
                });
                if typed_inventory_sink && direct_or_bound {
                    self.record_evidence(|e| e.listener_publish_flow = true);
                }
                if typed_inventory_sink {
                    for argument in &node.args {
                        let source = match ungroup_profile_expression(argument) {
                            syn::Expr::MethodCall(call) => {
                                let name = simple_path_ident(ungroup_profile_expression(
                                    call.receiver.as_ref(),
                                ));
                                name.as_deref()
                                    .and_then(|name| self.value_binding_method_owner(name))
                                    .map(|owner| {
                                        let owner = owner.rsplit("::").next().unwrap_or(owner);
                                        Self::short_method_symbol(owner, &call.method.to_string())
                                    })
                                    .or_else(|| {
                                        self.method_receiver_identity(
                                            call.receiver.as_ref(),
                                            &call.method.to_string(),
                                        )
                                    })
                                    .or_else(|| {
                                        Some(format!("listener-producer-name::{}", call.method))
                                    })
                            }
                            syn::Expr::Call(call) => self.path_call_identity(call.func.as_ref()),
                            _ => None,
                        };
                        if let (Some(function), Some(source)) =
                            (self.current_function().map(str::to_owned), source)
                            && let Some(info) = self.program.functions.get_mut(&function)
                        {
                            info.listener_publish_sources.insert(source);
                            if let syn::Expr::MethodCall(call) =
                                ungroup_profile_expression(argument)
                            {
                                info.listener_publish_sources
                                    .insert(format!("listener-producer-name::{}", call.method));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        if node.method == "profile_binding"
            && self.receiver_is_typed_token_provider(node.receiver.as_ref())
        {
            self.record_call(&Self::short_method_symbol(
                "TokenProviderBindings",
                "profile_binding",
            ));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.len() >= 2 {
            let expression = syn::Expr::Path(node.clone());
            if let Some(identity) = self.path_call_identity(&expression) {
                self.record_call(&identity);
            }
        }
        if path_contains_segment(&node.path, "DOMAIN_TRANSPORT_READY_PROBE_NAME") {
            self.record_evidence(|e| e.domain_transport_ready_probe = true);
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
    fn push_value_binding_scope(
        &mut self,
        bindings: BTreeSet<String>,
        method_owners: BTreeMap<String, String>,
    ) {
        self.value_binding_scopes.push(bindings);
        self.value_binding_method_owners.push(method_owners);
    }

    fn pop_value_binding_scope(&mut self) {
        self.value_binding_scopes.pop();
        self.value_binding_method_owners.pop();
    }

    fn value_binding_is_shadowed(&self, name: &str) -> bool {
        self.value_binding_scopes
            .iter()
            .rev()
            .any(|scope| scope.contains(name))
    }

    fn value_binding_method_owner(&self, name: &str) -> Option<&str> {
        self.value_binding_method_owners
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).map(String::as_str))
    }

    fn value_binding_type_map(&self) -> BTreeMap<String, String> {
        let mut value_types = BTreeMap::new();
        for scope in &self.value_binding_method_owners {
            for (name, owner) in scope {
                value_types.insert(name.clone(), owner.clone());
            }
        }
        value_types
    }

    fn current_function(&self) -> Option<&str> {
        self.function_stack.last().map(String::as_str)
    }

    fn current_info_mut(&mut self) -> Option<&mut SecurityFunctionEvidence> {
        let name = self.current_function()?.to_owned();
        Some(self.program.functions.entry(name).or_default())
    }

    fn invalidate_current_function(&mut self) {
        if let Some(function) = self.current_function().map(str::to_owned) {
            self.program.invalid_functions.insert(function);
        }
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

    fn current_module(&self) -> String {
        self.module_stack.join("::")
    }

    fn definition_identity(&self, symbol: &str) -> String {
        format!("{}::{symbol}", self.file_identity)
    }

    fn free_function_symbol(&self, function: &str) -> String {
        format!("free::{}::{function}", self.current_module())
    }

    fn short_free_function_symbol(function: &str) -> String {
        format!("free::*::{function}")
    }

    fn unqualified_free_function_symbol(&self, function: &str) -> String {
        format!("unqualified::{}::{function}", self.current_module())
    }

    fn qualified_method_symbol(owner_identity: &str, method: &str) -> String {
        format!("method::{owner_identity}::{method}")
    }

    fn short_method_symbol(owner: &str, method: &str) -> String {
        format!("method::*::{owner}::{method}")
    }

    fn impl_owner_identity(&self, implementation: &syn::ItemImpl) -> Option<String> {
        let syn::Type::Path(owner) = implementation.self_ty.as_ref() else {
            return None;
        };
        let owner = self.type_path_identity(owner)?;
        implementation
            .trait_
            .as_ref()
            .map_or(Some(owner.clone()), |(_, trait_path, _)| {
                self.path_identity(trait_path)
                    .map(|trait_identity| format!("{owner}::as::{trait_identity}"))
            })
    }

    fn type_path_identity(&self, path: &syn::TypePath) -> Option<String> {
        if path.qself.is_some() {
            return None;
        }
        self.path_identity(&path.path)
    }

    fn path_identity(&self, path: &syn::Path) -> Option<String> {
        if path.leading_colon.is_some() {
            return None;
        }
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let owner = segments.last()?.clone();
        let module = self.resolve_module_path(&segments[..segments.len() - 1]);
        (!module.is_empty()).then(|| format!("{}::{owner}", module.join("::")))
    }

    fn method_receiver_identity(&self, receiver: &syn::Expr, method: &str) -> Option<String> {
        let receiver = match receiver {
            syn::Expr::Paren(paren) => paren.expr.as_ref(),
            syn::Expr::Group(group) => group.expr.as_ref(),
            _ => receiver,
        };
        if matches!(receiver, syn::Expr::Path(path) if path.path.is_ident("self")) {
            return self
                .impl_identity_stack
                .last()
                .map(|owner| Self::qualified_method_symbol(owner, method));
        }
        let syn::Expr::Call(call) = receiver else {
            return None;
        };
        let syn::Expr::Path(path) = call.func.as_ref() else {
            return None;
        };
        let segments = path.path.segments.iter().collect::<Vec<_>>();
        (segments.len() >= 2).then(|| {
            Self::short_method_symbol(&segments[segments.len() - 2].ident.to_string(), method)
        })
    }

    fn path_call_identity(&self, function: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path) = function else {
            return None;
        };
        if path.path.leading_colon.is_some() {
            return None;
        }
        let segments = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        let function = segments.last()?.clone();
        let Some(owner) = segments.iter().rev().nth(1) else {
            return Some(self.unqualified_free_function_symbol(&function));
        };
        if owner == "Self" {
            return self
                .impl_identity_stack
                .last()
                .map(|owner| Self::qualified_method_symbol(owner, &function));
        }
        if owner.chars().next().is_some_and(char::is_uppercase) {
            if segments.len() == 2 {
                return Some(Self::short_method_symbol(owner, &function));
            }
            let module = self.resolve_module_path(&segments[..segments.len() - 2]);
            return (!module.is_empty())
                .then(|| format!("method::{}::{owner}::{function}", module.join("::")));
        }
        let module = self.resolve_module_path(&segments[..segments.len() - 1]);
        (!module.is_empty()).then(|| format!("free::{}::{function}", module.join("::")))
    }

    fn resolve_module_path(&self, path: &[String]) -> Vec<String> {
        let Some(first) = path.first().map(String::as_str) else {
            return self.module_stack.clone();
        };
        match first {
            "crate" => {
                let mut module = vec!["crate".to_string()];
                module.extend(path.iter().skip(1).cloned());
                module
            }
            "self" => {
                let mut module = self.module_stack.clone();
                module.extend(path.iter().skip(1).cloned());
                module
            }
            "super" => {
                let mut module = self.module_stack.clone();
                let mut index = 0;
                while path.get(index).is_some_and(|segment| segment == "super") {
                    if module.len() <= 1 {
                        return Vec::new();
                    }
                    module.pop();
                    index += 1;
                }
                module.extend(path.iter().skip(index).cloned());
                module
            }
            _ => {
                let mut module = self.module_stack.clone();
                module.extend(path.iter().cloned());
                module
            }
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

fn signature_returns_listener_observations(signature: &syn::Signature) -> bool {
    matches!(&signature.output, syn::ReturnType::Type(_, ty) if type_contains_ident(ty, "BoundListenerObservation"))
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

fn has_non_production_attributes(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attribute| is_conditional_attribute(attribute) || is_test_attribute(attribute))
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

fn selected_direct_normal_dependency_features(
    facts: &WorkspaceFacts,
    build: &BuildFacts,
    package: &PackageKey,
    assembly: &GovernedAssembly,
    dependency_name: &str,
) -> Result<Option<BTreeSet<String>>> {
    for dependency in facts.direct_dependencies_for(package)? {
        if dependency.name() != dependency_name || dependency.kind() != DependencyKind::Normal {
            continue;
        }
        let Some(resolved) = dependency.resolved() else {
            return Err(AssemblyCargoFactsError::UnresolvedDependency {
                assembly: assembly.manifest().name().to_owned(),
                dependency: dependency_name.to_owned(),
            }
            .into());
        };
        if build.is_dependency_selected(BuildSide::Target, package, dependency.name(), resolved) {
            return Ok(Some(dependency.requested_features().clone()));
        }
    }
    Ok(None)
}

fn validate_cargo_capability_specs(
    facts: &WorkspaceFacts,
    build: &BuildFacts,
    package: &PackageKey,
    assembly: &GovernedAssembly,
    domain: &str,
    specs: &[RequiredCapabilitySpec],
    findings: &mut Vec<Finding>,
) -> Result<()> {
    for spec in specs {
        let RequiredCapabilityExpectation::CargoDependency {
            dependency,
            required_features,
        } = spec.expectation
        else {
            continue;
        };
        match selected_direct_normal_dependency_features(
            facts,
            build,
            package,
            assembly,
            dependency,
        )? {
            None => findings.push(finding(
                Rule::RequiredCapability,
                assembly.cargo_label(),
                format!(
                    "field=dependencies domain={domain} capability={} expected selected direct normal [dependencies].{dependency} resolving to package `{dependency}` in {}; actual=missing-or-inactive-dependency",
                    spec.capability,
                    assembly.cargo_label()
                ),
            )),
            Some(features)
                if required_features
                    .iter()
                    .any(|required| !features.contains(*required)) =>
            {
                findings.push(finding(
                    Rule::RequiredCapability,
                    assembly.cargo_label(),
                    format!(
                        "field=dependencies domain={domain} capability={} expected [dependencies].{dependency} features {:?}; actual={features:?}",
                        spec.capability, required_features
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_assembly_cargo_facts(
    root: &Path,
    facts: &WorkspaceFacts,
    assembly: &GovernedAssembly,
) -> Result<Vec<Finding>> {
    let package = assembly_package_key(root, facts, assembly)?;
    let build = resolve_assembly_build(facts, &package, FeatureSelection::All)?;
    let mut findings = Vec::new();

    for (index, provider) in assembly.manifest().diport_providers().iter().enumerate() {
        if provider.lifecycle != ProviderLifecycle::Active {
            continue;
        }
        let source = format!(
            "{}:{}",
            assembly.manifest_label(),
            provider_table_line(assembly.source_text(), index)
        );
        let subject = format!("{source} {}", provider.provider);
        match selected_direct_normal_dependency_features(
            facts,
            &build,
            &package,
            assembly,
            &provider.provider_crate,
        )? {
            None => findings.push(finding(
                Rule::ActiveProviderDependency,
                &subject,
                format!(
                    "field=providerCrate active providerCrate `{}` must be a selected direct normal dependency with the same resolved package identity in {}",
                    provider.provider_crate,
                    assembly.cargo_label()
                ),
            )),
            Some(actual_features) => {
                let missing = required_features(provider)
                    .iter()
                    .filter(|feature| !actual_features.contains(**feature))
                    .copied()
                    .collect::<Vec<_>>();
                if !missing.is_empty() {
                    findings.push(finding(
                        Rule::ActiveProviderFeature,
                        &subject,
                        format!(
                            "field=requiredFeatures active provider `{}` for port `{}` requires Cargo feature {:?}; check {} [dependencies].{}",
                            provider.provider,
                            provider.port,
                            missing,
                            assembly.cargo_label(),
                            provider.provider_crate
                        ),
                    ));
                }
            }
        }
    }

    if is_deviceidentity_pilot_shape(assembly) {
        validate_cargo_capability_specs(
            facts,
            &build,
            &package,
            assembly,
            "deviceidentity",
            DEVICEIDENTITY_PILOT_REQUIRED_CAPABILITIES,
            &mut findings,
        )?;
    } else {
        for domain in assembly.manifest().domains() {
            if let Some(spec) = REQUIRED_CAPABILITY_DOMAINS
                .iter()
                .find(|spec| spec.domain == domain.as_str())
            {
                validate_cargo_capability_specs(
                    facts,
                    &build,
                    &package,
                    assembly,
                    spec.domain,
                    spec.capabilities,
                    &mut findings,
                )?;
            }
        }
        if requires_distributed_capabilities(assembly) {
            validate_cargo_capability_specs(
                facts,
                &build,
                &package,
                assembly,
                "distributed",
                DURABLE_TOPOLOGY_REQUIRED_CAPABILITIES,
                &mut findings,
            )?;
        }
    }
    Ok(findings)
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

    #[test]
    fn assembly_validate_canonical_executor_reports_release_surface() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let check = AssemblyValidate::new(&root, command_facts.get()?);
        let (summary, findings) = GovernanceCheck::check(&check)?;

        assert!(
            findings.is_empty(),
            "canonical assembly executor must accept the real workspace: {findings:?}"
        );
        assert!(
            summary.contains("release package")
                && summary.contains("profile artifact")
                && summary.contains("release packages=[")
                && summary.contains("profile artifacts=["),
            "canonical assembly executor lost its Release Surface carrier: {summary}"
        );
        Ok(())
    }

    fn validate_test_fixture_root_without_contracts(
        root: &Path,
    ) -> anyhow::Result<(usize, Vec<Finding>)> {
        anyhow::ensure!(
            !root.join("contracts").exists(),
            "contract-bearing fixtures must use the governed contract fixture loader"
        );
        let (assemblies, mut findings) = discover_test_targets(root)?;
        findings.extend(validate_runtime_inventory_listener_provenance(
            root,
            &assemblies,
        )?);
        if root.join("Cargo.toml").is_file() {
            let command_facts =
                crate::workspace_facts::CommandWorkspaceFacts::for_test_fixture(root);
            let facts = command_facts.get()?;
            for assembly in &assemblies {
                findings.extend(validate_assembly(assembly));
                findings.extend(validate_assembly_cargo_facts(root, facts, assembly)?);
                findings.extend(validate_target_domain_closure(root, facts, assembly)?);
            }
        } else {
            for assembly in &assemblies {
                findings.extend(validate_assembly(assembly));
            }
        }
        Ok((assemblies.len(), findings))
    }

    /// Partial fixture roots intentionally opt into target-scoped governance loading.
    /// Production aggregate discovery remains on the repository-global identity ratchet.
    fn discover_test_targets(root: &Path) -> anyhow::Result<(Vec<GovernedAssembly>, Vec<Finding>)> {
        let targets = crate::assembly_governance::discover_targets(root)?;
        let mut assemblies = Vec::new();
        let mut findings = Vec::new();
        for target in targets {
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
                            "assembly crate 必须声明 {label}/assembly.toml；source={}",
                            rel_label(root, &target.cargo_path())
                        ),
                    ));
                }
                continue;
            }
            let ir = AssemblyGovernanceIr::<Core>::load_target(root, target.name())?
                .with_context(|| format!("fixture assembly `{}` disappeared", target.name()))?;
            assemblies.extend(ir.assemblies().iter().cloned());
        }
        Ok((assemblies, findings))
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

            let workspace_root = crate::workspace_root()?;
            let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&workspace_root);
            let error = super::validate_root(&root, command_facts.get()?)
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

    /// Normalize legacy raw fixtures through the typed schema before writing them. This keeps the
    /// remaining domain/Cargo closure fixtures focused on their assembly-specific facts without a
    /// second text-position mutation language for listener bindings.
    fn bind_declared_domains_to_primary_listener(manifest: &str) -> anyhow::Result<String> {
        let mut manifest = AssemblyManifest::from_toml_str(manifest)?;
        if !manifest.domains.is_empty()
            && let Some(primary) = manifest
                .listeners
                .iter_mut()
                .find(|listener| listener.kind == assembly_schema::AssemblyListenerKind::Primary)
            && primary.domains.is_empty()
        {
            primary.domains.clone_from(&manifest.domains);
        }
        Ok(toml::to_string_pretty(&manifest)?)
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

    fn enable_fixture_cargo_workspace(root: &Path) -> anyhow::Result<()> {
        let assemblies_root = root.join("assemblies");
        let mut members = Vec::new();
        let mut dependency_packages = BTreeMap::<PathBuf, (String, BTreeSet<String>)>::new();
        for entry in fs::read_dir(&assemblies_root)? {
            let assembly_dir = entry?.path();
            if !assembly_dir.is_dir() || !assembly_dir.join("Cargo.toml").is_file() {
                continue;
            }
            let cargo_path = assembly_dir.join("Cargo.toml");
            let mut cargo: toml::Value = toml::from_str(&fs::read_to_string(&cargo_path)?)?;
            if let Some(table) = cargo.as_table_mut() {
                table.remove("lints");
                table.remove("bin");
                table.insert(
                    "features".to_owned(),
                    toml::Value::Table(toml::Table::from_iter([(
                        "default".to_owned(),
                        toml::Value::Array(Vec::new()),
                    )])),
                );
            }
            let package = cargo
                .get_mut("package")
                .and_then(toml::Value::as_table_mut)
                .context("fixture Cargo.toml [package]")?;
            package.insert(
                "version".to_owned(),
                toml::Value::String("0.0.0".to_owned()),
            );
            package.insert("edition".to_owned(), toml::Value::String("2024".to_owned()));
            package.insert(
                "rust-version".to_owned(),
                toml::Value::String("1.86".to_owned()),
            );
            package.remove("build");

            fn retain_path_dependencies(value: &mut toml::Value) {
                let Some(table) = value.as_table_mut() else {
                    return;
                };
                for (key, value) in table.iter_mut() {
                    if matches!(
                        key.as_str(),
                        "dependencies" | "dev-dependencies" | "build-dependencies"
                    ) {
                        if let Some(dependencies) = value.as_table_mut() {
                            dependencies.retain(|_, declaration| {
                                declaration
                                    .as_table()
                                    .is_some_and(|table| table.contains_key("path"))
                            });
                        }
                    } else {
                        retain_path_dependencies(value);
                    }
                }
            }
            retain_path_dependencies(&mut cargo);

            fn collect_dependency_tables<'a>(
                value: &'a toml::Value,
                output: &mut Vec<(&'a str, &'a toml::Value)>,
            ) {
                let Some(table) = value.as_table() else {
                    return;
                };
                for (key, value) in table {
                    if matches!(
                        key.as_str(),
                        "dependencies" | "dev-dependencies" | "build-dependencies"
                    ) {
                        if let Some(dependencies) = value.as_table() {
                            output.extend(
                                dependencies
                                    .iter()
                                    .map(|(name, declaration)| (name.as_str(), declaration)),
                            );
                        }
                    } else {
                        collect_dependency_tables(value, output);
                    }
                }
            }

            let mut declarations = Vec::new();
            collect_dependency_tables(&cargo, &mut declarations);
            for (name, declaration) in declarations {
                let Some(table) = declaration.as_table() else {
                    continue;
                };
                let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
                    continue;
                };
                let absolute = assembly_dir.join(path);
                let package = table
                    .get("package")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(name)
                    .to_owned();
                let features = table
                    .get("features")
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                dependency_packages
                    .entry(absolute)
                    .and_modify(|(_, known)| known.extend(features.clone()))
                    .or_insert((package, features));
            }
            write(&cargo_path, &toml::to_string(&cargo)?)?;
            fs::create_dir_all(assembly_dir.join("src"))?;
            if !assembly_dir.join("src/lib.rs").exists() {
                write(&assembly_dir.join("src/lib.rs"), "pub fn fixture() {}")?;
            }
            members.push(
                assembly_dir
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .into_owned(),
            );
        }

        for (path, (package, requested_features)) in dependency_packages {
            fs::create_dir_all(path.join("src"))?;
            let mut features = requested_features;
            features.extend(
                [
                    "auth-audit-sink",
                    "backend",
                    "domain-settings",
                    "sign",
                    "verify",
                ]
                .into_iter()
                .map(ToOwned::to_owned),
            );
            let feature_table = features
                .into_iter()
                .map(|feature| format!("{feature} = []"))
                .collect::<Vec<_>>()
                .join("\n");
            write(
                &path.join("Cargo.toml"),
                &format!(
                    "[package]\nname = {package:?}\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[features]\n{feature_table}\n"
                ),
            )?;
            write(&path.join("src/lib.rs"), "pub fn fixture() {}")?;
            members.push(path.strip_prefix(root)?.to_string_lossy().into_owned());
        }
        members.sort();
        members.dedup();
        let member_lines = members
            .iter()
            .map(|member| format!("  {member:?},"))
            .collect::<Vec<_>>()
            .join("\n");
        write(
            &root.join("Cargo.toml"),
            &format!(
                "[workspace]\nresolver = \"2\"\nmembers = [\n{member_lines}\n]\n\n[workspace.package]\nversion = \"0.0.0\"\nedition = \"2024\"\n"
            ),
        )?;
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

    fn manifest_with_domains(domains: &[AssemblyDomain]) -> anyhow::Result<String> {
        let mut manifest = AssemblyManifest::from_toml_str(&manifest_with_intent())?;
        manifest.domains = domains.to_vec();
        manifest
            .listeners
            .iter_mut()
            .find(|listener| listener.kind == assembly_schema::AssemblyListenerKind::Primary)
            .context("runtime fixture primary listener")?
            .domains = domains.to_vec();
        Ok(toml::to_string_pretty(&manifest)?)
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

[features]
test-support = []
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
                    Rule::ActiveDomainDependency
                        | Rule::InactiveDomainDependencyClosure
                        | Rule::ProductionTestSupport
                )
            })
            .collect())
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
outputs = ["probes", "resources"]

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

    fn deviceidentity_pilot_manifest(name: &str, providers: &str) -> String {
        format!(
            r#"
schemaVersion = 2
name = "{name}"
profile = "demo"
domains = ["identity"]
topology = "demo"
frameworkContracts = []
workflowActivations = []
listeners = []
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
outputs = ["probes", "resources"]

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

    const DEVICEIDENTITY_PILOT_PROVIDERS: &str = r#"
[[diportProviders]]
id = "device-certificate-store"
port = "identity::CertificateReconcileRepository"
provider = "postgres::PgDeviceCertificateRepository"
providerCrate = "postgres"
requiredFeatures = ["domain-identity"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "draft-device-certificate-persistence"
outputs = ["probes"]

[[diportProviders]]
id = "device-command-store"
port = "identity::DeviceCommandStore"
provider = "postgres::PgDeviceCommandStore"
providerCrate = "postgres"
requiredFeatures = ["domain-identity"]
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "draft-device-command-and-outbox-persistence"
outputs = ["probes", "workers"]

[[diportProviders]]
id = "device-draft-artifact-source"
port = "identity::CertificateArtifactSource"
provider = "identity_composition::DraftArtifactSimulator"
providerCrate = "identity-composition"
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "production-ineligible-deterministic-artifacts"
outputs = []

[[diportProviders]]
id = "device-mqtt-session"
port = "mqtt::MqttSession"
provider = "mqtt::MqttSession"
providerCrate = "mqtt"
consumer = "identity"
lifecycle = "active"
durability = "persistent"
purpose = "authenticated-persistent-device-transport"
outputs = ["probes", "resources", "workers"]

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
"#;

    const DEVICEIDENTITY_PILOT_CARGO: &str = r#"[package]
name = "deviceidentity"

[dependencies]
identity = { path = "../../crates/identity" }
postgres = { path = "../../adapters/postgres", features = ["domain-identity"] }
identity-composition = { path = "../../composition/identity" }
mqtt = { path = "../../adapters/mqtt" }
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
        enable_fixture_cargo_workspace(&root)?;
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
    fn deviceidentity_pilot_capability_closure_is_exact_and_non_vacuous() -> anyhow::Result<()> {
        let manifest =
            deviceidentity_pilot_manifest("deviceidentity", DEVICEIDENTITY_PILOT_PROVIDERS);
        let findings = required_capability_findings(&manifest, DEVICEIDENTITY_PILOT_CARGO)?;
        assert!(findings.is_empty(), "green pilot closure: {findings:?}");

        for role in [
            "device-certificate-store",
            "device-command-store",
            "device-draft-artifact-source",
            "device-mqtt-session",
            "device-revocation-store",
        ] {
            let needle = format!("[[diportProviders]]\nid = \"{role}\"");
            let start = DEVICEIDENTITY_PILOT_PROVIDERS
                .find(&needle)
                .expect("pilot role fixture");
            let remainder = &DEVICEIDENTITY_PILOT_PROVIDERS[start + needle.len()..];
            let end = remainder
                .find("\n[[diportProviders]]")
                .map_or(DEVICEIDENTITY_PILOT_PROVIDERS.len(), |offset| {
                    start + needle.len() + offset
                });
            let mut providers = DEVICEIDENTITY_PILOT_PROVIDERS.to_owned();
            providers.replace_range(start..end, "");
            let manifest = deviceidentity_pilot_manifest("deviceidentity", &providers);
            let findings = required_capability_findings(&manifest, DEVICEIDENTITY_PILOT_CARGO)?;
            assert_required_capability(&findings, "deviceidentity", role);
        }
        Ok(())
    }

    #[test]
    fn deviceidentity_pilot_shape_rejects_listener_framework_and_workflow_drift_but_not_name()
    -> anyhow::Result<()> {
        let wrong_name =
            deviceidentity_pilot_manifest("identity-pilot-alias", DEVICEIDENTITY_PILOT_PROVIDERS);
        let wrong_name_cargo = DEVICEIDENTITY_PILOT_CARGO.replace(
            "name = \"deviceidentity\"",
            "name = \"identity-pilot-alias\"",
        );
        let findings = required_capability_findings(&wrong_name, &wrong_name_cargo)?;
        assert!(
            findings.is_empty(),
            "pilot shape must not depend on the assembly name: {findings:?}"
        );

        let listener = r#"
[[listeners]]
kind = "primary"
domains = ["identity"]
"#;
        let wrong_listener = wrong_name.replace("listeners = []", listener);
        let wrong_framework = wrong_listener.replace(
            "frameworkContracts = []",
            "frameworkContracts = [{ id = \"seed.echo\", listener = \"primary\" }]",
        );
        let wrong_workflow = wrong_listener.replace(
            "workflowActivations = []",
            r#"workflowActivations = [{ mode = "projection", id = "settings.config-projection", definitionVersion = "v3", definitionSchemaDigest = "sha256:3504a1f33b4e2765fff012fd263ed9a317d24cbe200382c364e4220d7bf05baa", targetGeneration = "v3", activation = "capture-only" }]"#,
        );
        for (drift, manifest) in [
            ("listener", wrong_listener),
            ("framework contract", wrong_framework),
            ("workflow activation", wrong_workflow),
        ] {
            let manifest = AssemblyManifest::from_toml_str(&manifest)?.canonicalize_v2()?;
            assert!(
                !is_deviceidentity_pilot_manifest_shape(&manifest),
                "{drift} drift must leave the listenerless pilot shape"
            );
        }
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
outputs = ["probes", "resources"]

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
outputs = ["probes", "resources"]
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

fn build_rss_listener_pdp_jwks_lifecycle(
    provider: &RuntimeAccessProvider<RssAccessProfile>,
) -> ListenerPdpJwksLifecycle {
    ListenerPdpJwksLifecycle::single(
        AccessTokenJwksReadyProbe::rss_access(provider.jwks_readiness()).into_registration(),
        provider.managed_resource(),
    )
}

fn build_federated_listener_pdp_jwks_lifecycle(
    provider: &RuntimeAccessProvider<FederatedAccessProfile>,
) -> ListenerPdpJwksLifecycle {
    ListenerPdpJwksLifecycle::single(
        AccessTokenJwksReadyProbe::federated_access(provider.jwks_readiness()).into_registration(),
        provider.managed_resource(),
    )
}

impl ListenerPdpJwksLifecycle {
    pub(crate) fn merge(mut self, other: Self) -> Self {
        self.tail.push(other.head);
        self.tail.extend(other.tail);
        self
    }

    pub(crate) fn into_output(self) -> bootstrap::DomainModuleResult {
        bootstrap::DomainModuleResult {
            probes,
            resources,
            workers: Vec::new(),
        }
    }
}

impl ProviderOutput {
    fn new(
        module: DomainModuleResult,
        receipts: Vec<ProviderReceipt>,
        batch: &'static str,
        expected_channels: &'static [LifecycleChannel],
    ) -> Self {
        Self {
            batches: vec![ProviderBatch {
                module,
                receipts,
                batch,
                expected_channels,
            }],
        }
    }

    fn listener_pdp(
        constructor: ListenerPdpConstructor,
        lifecycle: ListenerPdpJwksLifecycle,
    ) -> Self {
        Self::new(
            lifecycle.into_output(),
            vec![ProviderReceipt::ListenerPdp(constructor.0)],
            "listener-pdp",
            CHANNELS_PROBES_RESOURCES,
        )
    }
}

mod provider_output {
fn commit_listener_pdp_jwks_lifecycle(
    constructor: ListenerPdpConstructor,
    lifecycle: ListenerPdpJwksLifecycle,
) -> ProviderOutput {
    ProviderOutput::listener_pdp(constructor, lifecycle)
}
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
    let mut provider_build = crate::provider_output::ProviderBuild::from_plan(
        runtime_plan,
        provider_catalog,
    ).context("join runtime provider plan")?;
    let rss_access = build_rss_access_provider();
    let federated_access = build_federated_access_provider();
    let service_token = build_service_token_provider();
    let rss_provider = rss_access.provider();
    let federated_provider = federated_access.provider();
    let service_provider = service_token.provider();
    let rss_lifecycle = self::build_rss_listener_pdp_jwks_lifecycle(&rss_access);
    let federated_lifecycle =
        self::build_federated_listener_pdp_jwks_lifecycle(&federated_access);
    let listener_pdp_lifecycle = rss_lifecycle.merge(federated_lifecycle);
    provider_build.record(
        crate::provider_output::commit_listener_pdp_jwks_lifecycle(
            listener_pdp_constructor,
            listener_pdp_lifecycle,
        ),
    );
    module.resources.push(service_token.managed_resource());
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
        let source = SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
            "    let _ = finalize_listener_plan();",
            "    let _ = finalize_listener_plan();\n    crate::launch::launch();",
        );
        format!("mod launch;\n{source}")
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
pub(crate) fn launch() {
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
    fn workflow_activation_gate_joins_projection_definition_and_rejects_draft_shadow()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-workflow-activation");
        let settings_dir = root.join("contracts/projection/settings/v3");
        fs::create_dir_all(&settings_dir)?;
        write(
            &settings_dir.join("contract.toml"),
            include_str!("../../contracts/projection/settings/v3/contract.toml"),
        )?;
        write(
            &settings_dir.join("projection.schema.json"),
            include_str!("../../contracts/projection/settings/v3/projection.schema.json"),
        )?;

        let audit_dir = root.join("contracts/projection/audit/v2");
        fs::create_dir_all(&audit_dir)?;
        write(
            &audit_dir.join("contract.toml"),
            include_str!("../../contracts/projection/audit/v2/contract.toml"),
        )?;
        write(
            &audit_dir.join("projection.schema.json"),
            include_str!("../../contracts/projection/audit/v2/projection.schema.json"),
        )?;

        let contracts = load_fixture_contracts(&root)?;
        let settings_digest = contracts
            .iter()
            .find(|contract| contract.manifest().id == "settings.config-projection")
            .ok_or_else(|| anyhow::anyhow!("settings projection fixture missing"))?
            .schema_hash()?;
        let activation = format!(
            r#"workflowActivations = [{{ mode = "projection", id = "settings.config-projection", definitionVersion = "v3", definitionSchemaDigest = "{settings_digest}", targetGeneration = "v3", activation = "disabled" }}]"#
        );
        let disabled = manifest_with_intent()
            .replace("workflowActivations = []", &activation)
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
        let (assemblies, _) = discover_test_targets(&root)?;
        assert!(validate_workflow_activation_contracts(&assemblies, &contracts).is_empty());

        let shadow = disabled.replace("activation = \"disabled\"", "activation = \"shadow\"");
        assert_ne!(shadow, disabled);
        write_assembly(
            &root,
            &shadow,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover_test_targets(&root)?;
        assert!(matches!(
            assemblies[0].manifest().workflow_activations(),
            [assembly_schema::WorkflowActivation::Projection {
                activation: assembly_schema::ProjectionActivation::Shadow,
                ..
            }]
        ));
        let findings = validate_workflow_activation_contracts(&assemblies, &contracts);
        assert!(
            findings.is_empty(),
            "active settings projection permits shadow"
        );

        let audit_digest = contracts
            .iter()
            .find(|contract| contract.manifest().id == "audit.session-projection")
            .ok_or_else(|| anyhow::anyhow!("audit projection fixture missing"))?
            .schema_hash()?;
        let invalid_audit = shadow.replace(
            &format!(
                r#"id = "settings.config-projection", definitionVersion = "v3", definitionSchemaDigest = "{settings_digest}""#
            ),
            &format!(
                r#"id = "audit.session-projection", definitionVersion = "v2", definitionSchemaDigest = "{audit_digest}""#
            ),
        );
        assert_ne!(invalid_audit, shadow);
        write_assembly(
            &root,
            &invalid_audit,
            "[package]\nname = \"runtime\"\nversion = \"0.0.0\"\n",
        )?;
        let (assemblies, _) = discover_test_targets(&root)?;
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
        let (assemblies, _) = discover_test_targets(&root)?;
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
        let (assemblies, _) = discover_test_targets(&root)?;
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
        let (assemblies, _) = discover_test_targets(&root)?;
        assert!(validate_framework_contracts(&root, &assemblies, &contracts).is_empty());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn runtime_inventory_listener_provenance_rejects_detached_dead_or_swapped_flow() {
        const PREFIX: &str = r#"
struct Server;
struct UnrelatedPublisher;
struct FakeInventoryPublisher;
use runtimeexec::inventory::InventoryPublisher;
impl InventoryPublisher { fn publish(&self, _observations: Vec<Observation>) {} }
impl UnrelatedPublisher { fn publish(&self, _observations: Vec<Observation>) {} }
impl FakeInventoryPublisher { fn publish(&self, _observations: Vec<Observation>) {} }
use runtimeexec::inventory::BoundListenerObservation as Observation;
struct Adapter { publisher: InventoryPublisher, primary: Server, admin: Server }
"#;
        let expected = [ExpectedListenerObservation {
            id: "\"admin-main\"",
            kind: "Kind::Admin",
            auth: "Auth::Token",
        }];
        let accepts = |body: &str| {
            let file = syn::parse_file(&format!(
                "{PREFIX} impl LaunchAdapter for Adapter {{ fn activate(self) {{ {body} }} }}"
            ))
            .expect("listener flow fixture parses");
            let evidence = file_security_closeout_program(&file).reachable_evidence_from_run();
            evidence.listener_publish_flow
                && listener_observations_match(&evidence.listener_observations, &expected)
        };

        assert!(accepts(
            "self.publisher.publish(Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), self.admin.local_addr())]));"
        ));
        assert!(!accepts(
            "let address = self.admin.local_addr(); self.publisher.publish(Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), address)]));"
        ));
        assert!(!accepts(
            "let _ = Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), self.admin.local_addr()); self.publisher.publish(Vec::new());"
        ));
        assert!(!accepts(
            "self.publisher.publish(Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), self.primary.local_addr())]));"
        ));

        let unrelated = syn::parse_file(&format!(
            "{PREFIX} struct WrongAdapter {{ publisher: UnrelatedPublisher, admin: Server }} impl LaunchAdapter for WrongAdapter {{ fn activate(self) {{ self.publisher.publish(Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), self.admin.local_addr())])); }} }}"
        ))
        .expect("unrelated publish fixture parses");
        let evidence = file_security_closeout_program(&unrelated).reachable_evidence_from_run();
        assert!(!evidence.listener_publish_sink_seen);
        assert!(!evidence.listener_publish_flow);

        let suffix_bait = syn::parse_file(&format!(
            "{PREFIX} struct SuffixBaitAdapter {{ publisher: FakeInventoryPublisher, admin: Server }} impl LaunchAdapter for SuffixBaitAdapter {{ fn activate(self) {{ self.publisher.publish(Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), self.admin.local_addr())])); }} }}"
        ))
        .expect("inventory publisher suffix bait parses");
        let evidence = file_security_closeout_program(&suffix_bait).reachable_evidence_from_run();
        assert!(!evidence.listener_publish_sink_seen);
        assert!(!evidence.listener_publish_flow);

        let dead = syn::parse_file(&format!(
            "{PREFIX} fn dead(server: Server) -> Vec<Observation> {{ Vec::from([Observation::from_bound(\"admin-main\", Kind::Admin, Auth::Token, scheme(), server.local_addr())]) }} impl LaunchAdapter for Adapter {{ fn activate(self) {{ self.publisher.publish(Vec::new()); }} }}"
        ))
        .expect("dead listener fixture parses");
        let evidence = file_security_closeout_program(&dead).reachable_evidence_from_run();
        assert!(!evidence.listener_publish_flow);
        assert!(evidence.listener_observations.is_empty());
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
    fn settingsonly_raw_jwt_reparse_rejects_cfg_test_alias_and_pointer_bait() {
        for source in [
            "#[cfg(test)] mod bait { fn raw(raw: &str) { let _ = authn::Jwt::parse(raw); } }",
            "fn raw(raw: &str) { let parse = authn::Jwt::parse; let _ = parse(raw); }",
            "fn raw(raw: &str) { let parse: fn(&str) -> _ = authn::Jwt::parse; let _ = parse(raw); }",
            "#[cfg(test)] mod bait { use authn::Jwt as J; fn raw(raw: &str) { let _ = J::parse(raw); } }",
            "use authn::{Jwt as J, VerifiedJwt as V}; fn raw(raw: &str) { let _ = J::parse(raw); let _ = V::raw; }",
            "type J = authn::Jwt; fn raw(raw: &str) { let _ = J::parse(raw); }",
            "fn raw(jwt: authn::VerifiedJwt) { let _ = jwt.raw(); }",
        ] {
            let syntax = syn::parse_file(source).expect("raw JWT mutation fixture parses");
            assert_ne!(
                file_raw_jwt_reparse_count(&syntax),
                0,
                "raw JWT mutation must fail closed: {source}"
            );
        }
    }

    #[test]
    fn settingsonly_raw_jwt_aliases_are_lexically_scoped() {
        for (source, expected) in [
            (
                "mod jwt { use authn::Jwt as J; fn no_call() {} } mod other { use other::Parser as J; fn parse(raw: &str) { let _ = J::parse(raw); } }",
                0,
            ),
            (
                "mod jwt { use authn::Jwt as J; fn raw(raw: &str) { let _ = J::parse(raw); } } mod other { use other::Parser as J; fn parse(raw: &str) { let _ = J::parse(raw); } }",
                1,
            ),
            (
                "fn outer() { { use authn::Jwt as J; let _ = J::parse(\"raw\"); } { use other::Parser as J; let _ = J::parse(\"value\"); } }",
                1,
            ),
        ] {
            let syntax = syn::parse_file(source).expect("scoped JWT alias fixture parses");
            assert_eq!(
                file_raw_jwt_reparse_count(&syntax),
                expected,
                "JWT alias evidence must not leak into a sibling lexical scope: {source}"
            );
        }
    }

    #[test]
    fn settingsonly_raw_jwt_reparse_real_workspace_is_clean() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let ir = AssemblyGovernanceIr::<Core>::load_target(&root, "settingsonly")?
            .context("load real settingsonly target")?;
        let assembly = ir.assembly("settingsonly").context("settingsonly target")?;
        assert!(settingsonly_raw_jwt_reparse_findings(assembly)?.is_empty());
        Ok(())
    }

    #[test]
    fn assembly_domain_active_manifest_domain_requires_direct_normal_dependency()
    -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-missing-active");
        let findings = domain_findings(
            &root,
            &manifest_with_domains(&[AssemblyDomain::Identity, AssemblyDomain::Settings])?,
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
                &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[AssemblyDomain::Identity])?,
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
            &manifest_with_domains(&[
                AssemblyDomain::Identity,
                AssemblyDomain::Settings,
                AssemblyDomain::Audit,
            ])?,
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
    fn assembly_default_test_support_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("assembly-domain-default-test-support");
        let manifest = manifest_with_domains(&[AssemblyDomain::Identity])?
            .replace("profile = \"demo\"", "profile = \"production\"")
            .replace("topology = \"demo\"", "topology = \"durable-shared\"");
        let findings = domain_findings(
            &root,
            &manifest,
            r#"[dependencies]
identity = { path = "../../crates/identity", features = ["test-support"] }
"#,
            "",
        )?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::ProductionTestSupport && finding.detail.contains("identity")
        }));
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
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        assert!(
            !assemblies.is_empty(),
            "real workspace must govern assemblies"
        );
        for assembly in &assemblies {
            let findings = validate_target_domain_closure(&root, facts, assembly)?;
            assert!(
                findings.is_empty(),
                "{} target closure findings: {findings:?}",
                assembly.manifest().name()
            );
        }
        Ok(())
    }

    #[test]
    fn identityaudit_manifest_boundary_rejects_profile_topology_and_listener_drift()
    -> anyhow::Result<()> {
        let repository = AssemblyFixtureBuilder::production_universe()?
            .profile("identityaudit", AssemblyProfile::Demo)?
            .topology("identityaudit", AssemblyTopology::Demo)?
            .build()?;
        let ir = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "identityaudit")?
            .context("identityaudit fixture target")?;
        let assembly = ir
            .assembly("identityaudit")
            .context("identityaudit fixture")?;
        let findings = validate_assembly(assembly);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::IdentityAuditManifestBoundary
                    && finding.detail.contains("profile")
                    && finding.detail.contains("topology")
            }),
            "demo identityaudit must fail the production executable boundary: {findings:?}"
        );
        let repository = AssemblyFixtureBuilder::production_universe()?
            .listener_domains(
                "identityaudit",
                assembly_schema::AssemblyListenerKind::Admin,
                vec![AssemblyDomain::Audit, AssemblyDomain::Identity],
            )?
            .build()?;
        let ir = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "identityaudit")?
            .context("identityaudit listener fixture target")?;
        let findings = validate_assembly(
            ir.assembly("identityaudit")
                .context("identityaudit listener fixture")?,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::IdentityAuditManifestBoundary)
        );
        Ok(())
    }

    /// identityaudit participates in production provider/JWKS closeout, but has no Internal mTLS
    /// listener or federated/service token profiles and therefore must not inherit those gates.
    #[test]
    fn identityaudit_real_manifest_boundary_is_exact() -> anyhow::Result<()> {
        let repository = AssemblyFixtureBuilder::production_universe()?.build()?;
        let ir = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "identityaudit")?
            .context("identityaudit fixture target")?;
        let assembly = ir
            .assembly("identityaudit")
            .context("identityaudit fixture")?;
        let findings = validate_assembly(assembly);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::IdentityAuditManifestBoundary)
        );
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::ProductionSecuritySpiffeCloseout
                    | Rule::TokenProfileTrustChain
                    | Rule::ActiveDistributedProviderConsumer
            )),
            "identityaudit must use semantic production gates without full-runtime closeout: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn provider_construction_live_join_rejects_bypassed_or_dead_stages() {
        for source in [
            r#"
struct ProviderRoleBatches; struct RoleConstructor; struct RoleReceipt;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } }
impl RoleConstructor { fn finish(self) -> RoleReceipt { RoleReceipt } }
impl RoleReceipt { fn transfer(self) {} }
fn run() { let _roles = ProviderRoleBatches::exact_join(); RoleConstructor.finish(); }
"#,
            r#"
struct ProviderRoleBatches; struct RoleConstructor; struct RoleReceipt;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } }
impl RoleConstructor { fn finish(self) -> RoleReceipt { RoleReceipt } }
impl RoleReceipt { fn transfer(self) {} }
fn run() { let _roles = ProviderRoleBatches::exact_join(); }
fn dead() { RoleConstructor.finish().transfer(); }
"#,
            r#"
struct ProviderRoleBatches; struct Unrelated; struct UnrelatedReceipt;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } }
impl Unrelated { fn finish(self) -> UnrelatedReceipt { UnrelatedReceipt } }
impl UnrelatedReceipt { fn transfer(self) {} }
fn run() { let _roles = ProviderRoleBatches::exact_join(); Unrelated.finish().transfer(); }
"#,
            r#"
struct ProviderRoleBatches; struct DummyConstructor; struct DummyReceipt;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } }
impl DummyConstructor { fn finish(self) -> DummyReceipt { DummyReceipt } }
impl DummyReceipt { fn transfer(self) {} }
fn run() { let _roles = ProviderRoleBatches::exact_join(); DummyConstructor.finish().transfer(); }
"#,
            r#"
struct ProviderRoleBatches;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } fn finish(self) {} }
fn run() { ProviderRoleBatches::exact_join().finish(); }
"#,
        ] {
            let file = syn::parse_file(source).expect("provider live-join fixture parses");
            let evidence = file_security_closeout_program(&file).reachable_evidence_from_run();
            assert!(!evidence.has_provider_construction_live_join());
        }
        let file = syn::parse_file(
            r#"
struct ProviderRoleBatches; struct ProviderRoleCloser { roles: ProviderRoleBatches, constructor: EventConstructor }
struct EventConstructor; struct EventReceipt;
impl ProviderRoleBatches { fn exact_join() -> Self { Self } }
impl ProviderRoleBatches { fn finish(self, _receipt: EventReceipt) {} }
impl EventConstructor { fn finish(self) -> EventReceipt { EventReceipt } }
impl EventReceipt { fn transfer(self) -> EventReceipt { self } }
impl ProviderRoleCloser {
    fn finish(self) {
        let receipt = self.constructor.finish().transfer();
        self.roles.finish(receipt);
    }
}
fn run() {
    let roles = ProviderRoleBatches::exact_join();
    let closer: ProviderRoleCloser = ProviderRoleCloser { roles, constructor: EventConstructor };
    closer.finish();
}
"#,
        )
        .expect("provider live-join green fixture parses");
        let evidence = file_security_closeout_program(&file).reachable_evidence_from_run();
        assert!(
            evidence.has_provider_construction_live_join(),
            "typed generated carrier fixture must close the selected batch: {evidence:?}"
        );
    }

    #[test]
    fn provider_construction_live_join_real_assemblies_are_exact() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        for name in ["runtime", "settingsonly", "identityaudit"] {
            let evidence =
                security_closeout_evidence_from_sources(&root.join("assemblies").join(name))?;
            assert!(
                evidence.has_provider_construction_live_join(),
                "{name} must retain a production-reachable provider construction handoff: {evidence:?}"
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
    fn production_security_closeout_requires_critical_providers() -> anyhow::Result<()> {
        for (name, constructor, gate) in [
            (
                "assembly-production-security-missing-oidc",
                ProviderConstructor::OidcProvider,
                "gate=oidc-pdp",
            ),
            (
                "assembly-production-security-missing-vault-signer",
                ProviderConstructor::VaultSigner,
                "gate=vault-signer",
            ),
            (
                "assembly-production-security-missing-vault-keyprovider",
                ProviderConstructor::VaultKeyProvider,
                "gate=vault-keyprovider",
            ),
        ] {
            let builder = AssemblyFixtureBuilder::production_universe()?
                .remove_provider("runtime", |provider| provider.provider == constructor)?;
            let builder = if constructor == ProviderConstructor::VaultKeyProvider {
                builder.remove_provider("runtime", |provider| provider.provider == constructor)?
            } else {
                builder
            };
            let repository = builder.build()?;
            write_runtime_src(repository.path(), "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;
            let ir = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "runtime")?
                .with_context(|| format!("{name} fixture target"))?;
            let assembly = ir.assembly("runtime").context("runtime fixture")?;

            let findings = validate_assembly(assembly);
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
        use assembly_schema::AssemblyListenerKind;

        let repository = AssemblyFixtureBuilder::production_universe()?
            .domains("runtime", vec![AssemblyDomain::Settings])?
            .listener_domains(
                "runtime",
                AssemblyListenerKind::Primary,
                vec![AssemblyDomain::Settings],
            )?
            .listener_domains("runtime", AssemblyListenerKind::Internal, vec![])?
            .listener_domains("runtime", AssemblyListenerKind::Admin, vec![])?
            .listener_domains("runtime", AssemblyListenerKind::Health, vec![])?
            .remove_provider("runtime", |provider| {
                provider.provider == ProviderConstructor::VaultSigner
            })?
            .build()?;
        write_runtime_src(repository.path(), "lib.rs", SECURITY_CLOSEOUT_FULL_SOURCE)?;
        write_runtime_egress_tls_closeout_config(repository.path())?;
        let ir = AssemblyGovernanceIr::<Core>::load_target(repository.path(), "runtime")?
            .context("settings-only runtime fixture target")?;
        let assembly = ir
            .assembly("runtime")
            .context("settings-only runtime fixture")?;

        let findings = validate_assembly(assembly);
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
        let jwks = findings
            .iter()
            .find(|f| f.rule == Rule::ProductionSecurityJwksCloseout)
            .with_context(|| format!("missing JWKS closeout finding: {findings:?}"))?;
        assert!(
            jwks.detail.contains("missing=["),
            "JWKS closeout diagnosis must list only missing gate parts: {}",
            jwks.detail
        );
        assert!(
            !jwks.detail.contains("builders=runtime-rss:"),
            "JWKS closeout diagnosis must not dump cross-assembly boolean matrix: {}",
            jwks.detail
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
                "rss-resource-registration",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replacen(
                    "provider.managed_resource(),",
                    "missing_managed_resource(),",
                    1,
                ),
            ),
            (
                "federated-lifecycle-replaced-by-rss",
                SECURITY_CLOSEOUT_RUN_PATH_SOURCE.replace(
                    "self::build_federated_listener_pdp_jwks_lifecycle(&federated_access)",
                    "self::build_rss_listener_pdp_jwks_lifecycle(&rss_access)",
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
                Rule::RuntimeInventoryListenerProvenance | Rule::ProviderConstructionLiveJoin
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
                Rule::RuntimeInventoryListenerProvenance | Rule::ProviderConstructionLiveJoin
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
                Rule::RuntimeInventoryListenerProvenance | Rule::ProviderConstructionLiveJoin
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

        enable_fixture_cargo_workspace(&root)?;

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

        enable_fixture_cargo_workspace(&root)?;

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
    fn active_provider_dependency_requires_exact_selected_normal_identity() -> anyhow::Result<()> {
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
        for (case, dependencies) in [
            (
                "renamed-key",
                r#"[dependencies]
postgres = { path = "../../adapters/postgres" }
amqp_alias = { package = "amqp", path = "../../adapters/amqp", features = ["backend"] }
"#,
            ),
            (
                "inactive-target",
                r#"[dependencies]
postgres = { path = "../../adapters/postgres" }

[target.'cfg(any())'.dependencies]
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#,
            ),
            (
                "dev-kind",
                r#"[dependencies]
postgres = { path = "../../adapters/postgres" }

[dev-dependencies]
amqp = { path = "../../adapters/amqp", features = ["backend"] }
"#,
            ),
        ] {
            let root = unique_tmp(&format!("assembly-provider-selected-{case}"));
            write_assembly(
                &root,
                &manifest,
                &format!("[package]\nname = \"runtime\"\n\n{dependencies}"),
            )?;
            enable_fixture_cargo_workspace(&root)?;
            let (_count, findings) = validate_test_fixture_root_without_contracts(&root)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::ActiveProviderDependency),
                "{case} must not satisfy selected direct normal provider identity: {findings:?}"
            );
        }
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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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
outputs = ["probes", "resources"]

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

        enable_fixture_cargo_workspace(&root)?;
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

        enable_fixture_cargo_workspace(&root)?;
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
        enable_fixture_cargo_workspace(&root)?;
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
        enable_fixture_cargo_workspace(&root)?;
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
