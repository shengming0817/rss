//! Static LocalOnly route/state/port effect closure gate.
//!
//! INVARIANT: LOCAL-ONLY-EFFECTS-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "forged_observation_provenance_is_rejected", anti_vacuity = "governed_observation_provenance_is_accepted" }.
//! INVARIANT: LOCAL-ONLY-RECEIPT-COVERAGE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "local_only_receipt_coverage_is_blocking_and_reportable", anti_vacuity = "real_workspace_local_only_receipt_coverage_is_non_vacuous" }.

use crate::ReportFormat;
use crate::contract::DiscoveredContract;
use crate::contract::manifest::{
    ConsistencyLevel, ContractKind, ContractOwner, EffectKind, HttpMethod, Lifecycle,
};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Expr, GenericArgument, ImplItem, Item, ItemImpl, ItemStruct, ItemType, PathArguments, Type,
    TypeParamBound,
};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const CONSISTENCY_REPORT_SCHEMA_VERSION: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    MissingRouteBinding,
    UnclassifiedState,
    ForbiddenStateEffect,
    CrossTenantPrivilege,
    OpaqueSourceScope,
    ForgedObservationEvidence,
    MissingLocalOnlyReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
enum ReportStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum MountStatus {
    Mounted,
    Missing,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ProofKind {
    LocalOnlyStatic,
    DeclarationOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ProofStatus {
    Passed,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum StateKind {
    Stateless,
    Ordinary,
    Classified,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum SourceReceiptRegistrationStatus {
    Registered,
    Missing,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ReceiptCoverageEnforcement {
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ReceiptCoverageEvidence {
    SourceRegistered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum ReceiptCoverageStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceReceiptRegistration {
    enforcement: ReceiptCoverageEnforcement,
    evidence: ReceiptCoverageEvidence,
    status: SourceReceiptRegistrationStatus,
}

impl SourceReceiptRegistration {
    const fn fail_closed(status: SourceReceiptRegistrationStatus) -> Self {
        Self {
            enforcement: ReceiptCoverageEnforcement::FailClosed,
            evidence: ReceiptCoverageEvidence::SourceRegistered,
            status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalOnlyReceiptCoverage {
    enforcement: ReceiptCoverageEnforcement,
    evidence: ReceiptCoverageEvidence,
    status: ReceiptCoverageStatus,
    active_count: usize,
    registered_count: usize,
    missing_count: usize,
    missing_contracts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportFinding {
    rule: String,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutePosture {
    mount_status: MountStatus,
    mount_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EffectProof {
    kind: ProofKind,
    status: ProofStatus,
    state_kind: Option<StateKind>,
    effect_class: Option<String>,
    privilege_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractPosture {
    contract_id: String,
    owner: String,
    method: String,
    path: String,
    consistency_level: String,
    effects: Vec<String>,
    route: RoutePosture,
    effect_proof: EffectProof,
    source_receipt_registration: SourceReceiptRegistration,
    findings: Vec<ReportFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsistencyReport {
    schema_version: u8,
    status: ReportStatus,
    active_http_contract_count: usize,
    local_only_receipt_coverage: LocalOnlyReceiptCoverage,
    findings: Vec<ReportFinding>,
    contracts: Vec<ContractPosture>,
}

pub(crate) struct LocalOnlyEffects;

impl GovernanceCheck for LocalOnlyEffects {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "consistency local-only-effects"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        check_root(&crate::workspace_root()?)
    }
}

#[derive(Debug, Clone)]
struct Contract {
    id: String,
    serving_scope: ServingScope,
    key: String,
    method: String,
    path: String,
    subject: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LocalOnlyReceiptTarget {
    contract_id: String,
    module_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptRegistration {
    active_contracts: BTreeSet<String>,
    registered_contracts: BTreeSet<String>,
    missing_contracts: Vec<String>,
}

/// Canonical executable identity derived from the same AST site that satisfies the static
/// LocalOnly source-receipt gate. No caller-maintained test list exists outside this inventory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalOnlyExecutionTest {
    pub(crate) contract_id: String,
    pub(crate) package: String,
    pub(crate) test_target: String,
    pub(crate) test_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalOnlyExecutionInventory {
    pub(crate) active_contract_ids: BTreeSet<String>,
    pub(crate) source_receipt_contract_ids: BTreeSet<String>,
    pub(crate) tests: Vec<LocalOnlyExecutionTest>,
}

impl ReceiptRegistration {
    fn reconcile(
        active_contracts: BTreeSet<String>,
        registered_contracts: BTreeSet<String>,
    ) -> Result<Self> {
        if !registered_contracts.is_subset(&active_contracts) {
            bail!("registered LocalOnly receipt is not an active LocalOnly target");
        }
        let missing_contracts = active_contracts
            .difference(&registered_contracts)
            .cloned()
            .collect();
        Ok(Self {
            active_contracts,
            registered_contracts,
            missing_contracts,
        })
    }

    fn report(&self) -> LocalOnlyReceiptCoverage {
        let missing_count = self.missing_contracts.len();
        LocalOnlyReceiptCoverage {
            enforcement: ReceiptCoverageEnforcement::FailClosed,
            evidence: ReceiptCoverageEvidence::SourceRegistered,
            status: if missing_count == 0 {
                ReceiptCoverageStatus::Complete
            } else {
                ReceiptCoverageStatus::Partial
            },
            active_count: self.active_contracts.len(),
            registered_count: self.registered_contracts.len(),
            missing_count,
            missing_contracts: self.missing_contracts.clone(),
        }
    }

    fn blocking_findings(&self) -> Vec<Finding> {
        self.missing_contracts
            .iter()
            .map(|contract_id| missing_receipt_finding(contract_id))
            .collect()
    }
}

fn missing_receipt_finding(contract_id: &str) -> Finding {
    finding(
        Rule::MissingLocalOnlyReceipt,
        contract_id.to_string(),
        format!(
            "active LocalOnly contract `{contract_id}` has no canonical source receipt registration"
        ),
    )
}

fn check_root(root: &Path) -> Result<(String, Vec<Finding>)> {
    let discovered = discover_without_absolute_paths(root)?;
    let (contracts, mut findings) = contracts_and_profile_findings(root, &discovered)?;
    let targets = contracts
        .iter()
        .map(|contract| LocalOnlyReceiptTarget {
            contract_id: contract.id.clone(),
            module_path: module_path_from_mount_key(&contract.key),
        })
        .collect::<Vec<_>>();
    let active_contracts = targets
        .iter()
        .map(|target| target.contract_id.clone())
        .collect();
    let mut receipt_registration =
        ReceiptRegistration::reconcile(active_contracts, BTreeSet::new())?;
    // Contract-only fixtures are intentionally supported by the cross-field unit tests. A real
    // workspace always has Cargo.toml and therefore must close generated/source evidence.
    if root.join("Cargo.toml").is_file() {
        let inventory = local_only_source_inventory(root)?;
        let generated = generated_localonly_routes(root)?;
        verify_manifest_generated_local_only_exact_set(&contracts, &generated)?;
        if root.canonicalize().ok() == crate::workspace_root()?.canonicalize().ok() {
            verify_manifest_compiled_local_only_exact_set(
                &contracts,
                generated::http::LOCAL_ONLY_SPECS,
            )?;
        }
        findings.extend(source_findings(root, &contracts)?);
        findings.extend(observation_provenance_findings(&inventory));
        receipt_registration = local_only_receipt_registration_in_inventory(&inventory, &targets)?;
    }
    findings.extend(receipt_registration.blocking_findings());
    findings
        .sort_by(|a, b| (&a.rule, &a.subject, &a.detail).cmp(&(&b.rule, &b.subject, &b.detail)));
    findings.dedup();
    Ok((
        format!(
            "{} active LocalOnly HTTP contract(s) checked; source receipts registered {}/{}; missing: {}",
            contracts.len(),
            receipt_registration.registered_contracts.len(),
            contracts.len(),
            if receipt_registration.missing_contracts.is_empty() {
                "none".to_string()
            } else {
                receipt_registration.missing_contracts.join(", ")
            }
        ),
        findings,
    ))
}

/// Collect and render the complete report before the sole stdout write. Collection or
/// serialization errors therefore cannot leave a plausible partial artifact behind.
pub(crate) fn run_report(format: ReportFormat) -> Result<()> {
    let root = crate::workspace_root()?;
    let stdout = std::io::stdout();
    run_report_with(format, || collect_report(&root), &mut stdout.lock())
}

fn run_report_with<W, C>(format: ReportFormat, collect: C, writer: &mut W) -> Result<()>
where
    W: Write,
    C: FnOnce() -> Result<ConsistencyReport>,
{
    let report = collect()?;
    let rendered = render_report(&report, format)?;
    writer
        .write_all(rendered.as_bytes())
        .context("write consistency posture report")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ServingScope {
    Domain(String),
    Framework(Vec<String>),
}

impl ServingScope {
    fn matches_owner(&self, owner: vocab::HttpContractOwner) -> bool {
        match self {
            Self::Domain(domain) => owner.domain_name() == Some(domain.as_str()),
            Self::Framework(_) => owner.is_framework(),
        }
    }
}

fn serving_scope(root: &Path, route: vocab::HttpRouteEvidence) -> Result<ServingScope> {
    match route.owner().domain_name() {
        Some(domain) => Ok(ServingScope::Domain(domain.to_string())),
        None if route.owner().is_framework() => Ok(ServingScope::Framework(
            framework_serving_assemblies(root, route.contract_id())?,
        )),
        None => bail!("generated HTTP route has an unrecognized owner"),
    }
}

fn canonical_evidence_for_scope(
    root: &Path,
    scope: &ServingScope,
) -> Result<crate::localtx_coverage::CanonicalServingEvidence> {
    let source = match scope {
        ServingScope::Domain(owner) => {
            crate::localtx_coverage::ServingEvidenceSource::Domain(owner)
        }
        ServingScope::Framework(assemblies) => {
            let mut evidence_by_assembly = Vec::new();
            for assembly in assemblies {
                let evidence = crate::localtx_coverage::canonical_serving_evidence(
                    root,
                    crate::localtx_coverage::ServingEvidenceSource::Framework(assembly),
                )
                .map_err(|error| sanitized(root, error))?;
                evidence_by_assembly.push(evidence);
            }
            let mut evidence_by_assembly = evidence_by_assembly.into_iter();
            let mut canonical = evidence_by_assembly
                .next()
                .ok_or_else(|| anyhow!("framework serving scope has no assembly"))?;
            // One framework contract may intentionally be mounted by several assemblies. The
            // assembly/codegen exact-set guard proves every declared mount independently; this
            // effect posture uses one deterministic carrier only when every declaring assembly
            // exposes exactly one canonical mount for the same contract, avoiding false
            // ambiguity from assembly-local adapter state type names.
            let remaining = evidence_by_assembly.collect::<Vec<_>>();
            canonical.mounts.retain(|contract, mounts| {
                mounts.len() == 1
                    && remaining.iter().all(|evidence| {
                        evidence
                            .mounts
                            .get(contract)
                            .is_some_and(|candidate| candidate.len() == 1)
                    })
            });
            return Ok(canonical);
        }
    };
    crate::localtx_coverage::canonical_serving_evidence(root, source)
        .map_err(|error| sanitized(root, error))
}

fn collect_report(root: &Path) -> Result<ConsistencyReport> {
    ensure_exact_contract_ids(
        "generated LOCAL_ONLY_SPECS/active HTTP registry",
        generated::http::LOCAL_ONLY_SPECS
            .iter()
            .map(|spec| spec.route.contract_id()),
        generated::http::SPECS
            .iter()
            .filter(|spec| spec.route.consistency_level() == vocab::HttpConsistencyLevel::LocalOnly)
            .map(|spec| spec.route.contract_id()),
    )?;
    collect_report_with_specs(root, generated::http::SPECS)
}

fn ensure_exact_contract_ids<'a>(
    label: &str,
    expected: impl IntoIterator<Item = &'a str>,
    actual: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let expected = expected.into_iter().collect::<Vec<_>>();
    let actual = actual.into_iter().collect::<Vec<_>>();
    let expected_ids = expected.iter().copied().collect::<BTreeSet<_>>();
    let actual_ids = actual.iter().copied().collect::<BTreeSet<_>>();
    let mut expected_seen = BTreeSet::new();
    let expected_duplicates = expected
        .iter()
        .copied()
        .filter(|id| !expected_seen.insert(*id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut actual_seen = BTreeSet::new();
    let actual_duplicates = actual
        .iter()
        .copied()
        .filter(|id| !actual_seen.insert(*id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !expected_duplicates.is_empty() {
        bail!("{label} expected IDs contain duplicates={expected_duplicates:?}");
    }
    if !actual_duplicates.is_empty() {
        bail!("{label} actual IDs contain duplicates={actual_duplicates:?}");
    }
    let missing = expected_ids
        .difference(&actual_ids)
        .copied()
        .collect::<Vec<_>>();
    let extra = actual_ids
        .difference(&expected_ids)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() || !extra.is_empty() {
        bail!("{label} identity mismatch: missing={missing:?} extra={extra:?}");
    }
    Ok(())
}

fn collect_report_with_specs(
    root: &Path,
    specs: &[generated::http::HttpSpec],
) -> Result<ConsistencyReport> {
    let receipt_targets = specs
        .iter()
        .filter(|spec| spec.route.consistency_level() == vocab::HttpConsistencyLevel::LocalOnly)
        .map(|spec| LocalOnlyReceiptTarget {
            contract_id: spec.route.contract_id().to_string(),
            module_path: module_path_from_mount_key(spec.mount_key),
        })
        .collect::<Vec<_>>();
    let receipt_registration = local_only_receipt_registration(root, &receipt_targets)?;
    let mut serving_scopes = BTreeSet::new();
    let mut scopes_by_contract = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for spec in specs {
        let route = spec.route;
        if !identities.insert(route.contract_id()) {
            bail!(
                "duplicate generated active HTTP contract `{}`",
                route.contract_id()
            );
        }
        let scope = serving_scope(root, route)?;
        serving_scopes.insert(scope.clone());
        scopes_by_contract.insert(route.contract_id(), scope);
    }

    let mut serving_evidence = BTreeMap::new();
    let mut proof_sources = BTreeMap::new();
    for scope in serving_scopes {
        let evidence = canonical_evidence_for_scope(root, &scope)?;
        if specs.iter().any(|spec| {
            scopes_by_contract.get(spec.route.contract_id()) == Some(&scope)
                && spec.route.consistency_level() == vocab::HttpConsistencyLevel::LocalOnly
                && mount_requires_source(evidence.mounts.get(spec.mount_key))
        }) {
            proof_sources.insert(
                scope.clone(),
                ProofSource::load(root, &scope, &evidence.reachable_production_sources)?,
            );
        }
        serving_evidence.insert(scope, evidence);
    }

    let mut contracts = Vec::new();
    for spec in specs {
        let route = spec.route;
        let scope = scopes_by_contract
            .get(route.contract_id())
            .ok_or_else(|| anyhow!("missing canonical serving scope"))?;
        let evidence = serving_evidence
            .get(scope)
            .ok_or_else(|| anyhow!("missing canonical serving evidence"))?;
        contracts.push(build_contract_posture(
            spec,
            scope,
            evidence.mounts.get(spec.mount_key),
            proof_sources.get(scope),
        )?);
    }
    finalize_report(contracts, &receipt_registration)
}

fn module_path_from_mount_key(mount_key: &str) -> Vec<String> {
    mount_key.split("::").map(ToString::to_string).collect()
}

fn framework_serving_assemblies(root: &Path, contract_id: &str) -> Result<Vec<String>> {
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(root.join("assemblies")).context("read assemblies")? {
        let entry = entry.context("read assembly entry")?;
        if !entry
            .file_type()
            .context("read assembly entry type")?
            .is_dir()
        {
            continue;
        }
        let path = entry.path().join("assembly.toml");
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path).context("read assembly manifest")?;
        let manifest = assembly_schema::AssemblyManifest::from_toml_str(&text)
            .context("parse assembly manifest")?;
        if manifest
            .framework_contracts
            .iter()
            .any(|declared| declared.id == contract_id)
        {
            matches.push(manifest.name);
        }
    }
    matches.sort();
    if matches.is_empty() {
        bail!("framework contract `{contract_id}` has no serving assembly");
    }
    Ok(matches)
}

fn finalize_report(
    mut contracts: Vec<ContractPosture>,
    receipt_registration: &ReceiptRegistration,
) -> Result<ConsistencyReport> {
    contracts.sort_by(|a, b| {
        (&a.contract_id, &a.method, &a.path).cmp(&(&b.contract_id, &b.method, &b.path))
    });
    let active_local_only = contracts
        .iter()
        .filter(|contract| contract.consistency_level == "LocalOnly")
        .map(|contract| contract.contract_id.clone())
        .collect::<BTreeSet<_>>();
    if receipt_registration.active_contracts != active_local_only {
        bail!("LocalOnly receipt assessment does not match active LocalOnly report rows");
    }
    for contract in &mut contracts {
        contract.source_receipt_registration =
            SourceReceiptRegistration::fail_closed(if contract.consistency_level != "LocalOnly" {
                SourceReceiptRegistrationStatus::NotApplicable
            } else if receipt_registration
                .registered_contracts
                .contains(&contract.contract_id)
            {
                SourceReceiptRegistrationStatus::Registered
            } else {
                SourceReceiptRegistrationStatus::Missing
            });
        if contract.source_receipt_registration.status == SourceReceiptRegistrationStatus::Missing {
            contract
                .findings
                .push(report_finding(&missing_receipt_finding(
                    &contract.contract_id,
                )));
            contract.findings.sort();
            contract.findings.dedup();
        }
    }
    let mut findings: Vec<_> = contracts
        .iter()
        .flat_map(|contract| contract.findings.iter().cloned())
        .collect();
    findings.sort();
    findings.dedup();
    Ok(ConsistencyReport {
        schema_version: CONSISTENCY_REPORT_SCHEMA_VERSION,
        status: if findings.is_empty() {
            ReportStatus::Passed
        } else {
            ReportStatus::Failed
        },
        active_http_contract_count: contracts.len(),
        local_only_receipt_coverage: receipt_registration.report(),
        findings,
        contracts,
    })
}

fn build_contract_posture(
    spec: &generated::http::HttpSpec,
    serving_scope: &ServingScope,
    mounts: Option<&BTreeSet<crate::localtx_coverage::CanonicalRouteMount>>,
    source: Option<&ProofSource>,
) -> Result<ContractPosture> {
    let route = spec.route;
    if !serving_scope.matches_owner(route.owner()) {
        bail!("serving scope disagrees with generated HTTP contract owner");
    }
    let owner = route.owner().domain_name().unwrap_or("_framework");
    let (mount_status, mount_sources) = mount_posture(mounts);
    let mut findings: Vec<ReportFinding> = mount_finding(route.contract_id(), mount_status)
        .into_iter()
        .collect();
    let local_only = route.consistency_level() == vocab::HttpConsistencyLevel::LocalOnly;
    let effect_proof = if local_only {
        findings.extend(
            route
                .effect_profile()
                .effects()
                .iter()
                .copied()
                .filter_map(forbidden_generated_effect_wire)
                .map(|effect| ReportFinding {
                    rule: "forbiddenStateEffect".to_string(),
                    subject: route.contract_id().to_string(),
                    detail: format!("LocalOnly declaration contains forbidden effect `{effect}`"),
                }),
        );
        let mut proof = LocalOnlyProofEvaluation {
            state_kind: None,
            effect_class: None,
            privilege_class: None,
            findings: Vec::new(),
        };
        if let Some(mounts) = mounts {
            let contract = Contract {
                id: route.contract_id().to_string(),
                serving_scope: serving_scope.clone(),
                key: spec.mount_key.to_string(),
                method: route.method().to_string(),
                path: route.path().to_string(),
                subject: route.contract_id().to_string(),
            };
            proof = evaluate_localonly_mount(&contract, mounts, source)?;
            findings.extend(proof.findings.iter().map(report_finding));
        }
        EffectProof {
            kind: ProofKind::LocalOnlyStatic,
            status: if findings.is_empty() {
                ProofStatus::Passed
            } else {
                ProofStatus::Failed
            },
            state_kind: proof.state_kind,
            effect_class: proof.effect_class,
            privilege_class: proof.privilege_class,
        }
    } else {
        EffectProof {
            kind: ProofKind::DeclarationOnly,
            status: ProofStatus::NotApplicable,
            state_kind: None,
            effect_class: None,
            privilege_class: None,
        }
    };
    findings.sort();
    findings.dedup();
    Ok(ContractPosture {
        contract_id: route.contract_id().to_string(),
        owner: owner.to_string(),
        method: route.method().to_string(),
        path: route.path().to_string(),
        consistency_level: consistency_wire(route.consistency_level()).to_string(),
        effects: canonical_effects(route.effect_profile().effects()),
        route: RoutePosture {
            mount_status,
            mount_sources,
        },
        effect_proof,
        source_receipt_registration: SourceReceiptRegistration::fail_closed(if local_only {
            SourceReceiptRegistrationStatus::Missing
        } else {
            SourceReceiptRegistrationStatus::NotApplicable
        }),
        findings,
    })
}

fn mount_finding(contract_id: &str, status: MountStatus) -> Option<ReportFinding> {
    let (rule, detail) = match status {
        MountStatus::Mounted => return None,
        MountStatus::Missing => (
            "missingRouteBinding",
            "canonical production Domain::init mount is missing",
        ),
        MountStatus::Ambiguous => (
            "opaqueSourceScope",
            "canonical production route has conflicting mount evidence",
        ),
    };
    Some(ReportFinding {
        rule: rule.to_string(),
        subject: contract_id.to_string(),
        detail: detail.to_string(),
    })
}

fn render_report(report: &ConsistencyReport, format: ReportFormat) -> Result<String> {
    validate_report(report)?;
    match format {
        ReportFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(report)?)),
        ReportFormat::Markdown => Ok(render_markdown(report)),
    }
}

fn validate_report(report: &ConsistencyReport) -> Result<()> {
    if report.schema_version != CONSISTENCY_REPORT_SCHEMA_VERSION {
        bail!("unsupported consistency report schema version");
    }
    if report.active_http_contract_count != report.contracts.len() {
        bail!("activeHttpContractCount does not match contracts");
    }
    let active_local_only = report
        .contracts
        .iter()
        .filter(|contract| contract.consistency_level == "LocalOnly")
        .collect::<Vec<_>>();
    let registered = active_local_only
        .iter()
        .filter(|contract| {
            contract.source_receipt_registration.status
                == SourceReceiptRegistrationStatus::Registered
        })
        .count();
    let missing_contracts = active_local_only
        .iter()
        .filter(|contract| {
            contract.source_receipt_registration.status == SourceReceiptRegistrationStatus::Missing
        })
        .map(|contract| contract.contract_id.clone())
        .collect::<Vec<_>>();
    if report.local_only_receipt_coverage.active_count != active_local_only.len()
        || report.local_only_receipt_coverage.enforcement != ReceiptCoverageEnforcement::FailClosed
        || report.local_only_receipt_coverage.evidence != ReceiptCoverageEvidence::SourceRegistered
        || report.local_only_receipt_coverage.registered_count != registered
        || report.local_only_receipt_coverage.missing_count != missing_contracts.len()
        || report.local_only_receipt_coverage.registered_count
            + report.local_only_receipt_coverage.missing_count
            != report.local_only_receipt_coverage.active_count
        || report.local_only_receipt_coverage.missing_contracts != missing_contracts
        || report.local_only_receipt_coverage.status
            != if missing_contracts.is_empty() {
                ReceiptCoverageStatus::Complete
            } else {
                ReceiptCoverageStatus::Partial
            }
        || report.contracts.iter().any(|contract| {
            contract.source_receipt_registration.enforcement
                != ReceiptCoverageEnforcement::FailClosed
                || contract.source_receipt_registration.evidence
                    != ReceiptCoverageEvidence::SourceRegistered
                || if contract.consistency_level == "LocalOnly" {
                    contract.source_receipt_registration.status
                        == SourceReceiptRegistrationStatus::NotApplicable
                } else {
                    contract.source_receipt_registration.status
                        != SourceReceiptRegistrationStatus::NotApplicable
                }
        })
    {
        bail!("LocalOnly receipt coverage does not match contract rows");
    }
    for contract in &active_local_only {
        let expected = report_finding(&missing_receipt_finding(&contract.contract_id));
        if (contract.source_receipt_registration.status == SourceReceiptRegistrationStatus::Missing)
            != contract.findings.contains(&expected)
        {
            bail!("LocalOnly receipt finding does not match contract registration");
        }
    }
    let mut expected_findings = report
        .contracts
        .iter()
        .flat_map(|contract| contract.findings.iter().cloned())
        .collect::<Vec<_>>();
    expected_findings.sort();
    expected_findings.dedup();
    if report.findings != expected_findings {
        bail!("top-level findings do not match contract findings");
    }
    if (report.status == ReportStatus::Passed) != report.findings.is_empty() {
        bail!("consistency report status does not match findings");
    }
    Ok(())
}

fn render_markdown(report: &ConsistencyReport) -> String {
    let mut output = format!(
        "# Consistency / Effect Posture\n\nStatic status: **{}** · Active HTTP contracts: **{}** · Findings: **{}**\n\nSource receipt registration (fail-closed; tests not executed): **{}/{} registered** · Missing: **{}**{}\n\n| Contract | Owner | Method | Path | Consistency | Effects | Mount | LocalOnly Proof | Source Receipt Registration | Findings |\n|---|---|---|---|---|---|---|---|---|---|\n",
        match report.status {
            ReportStatus::Passed => "passed",
            ReportStatus::Failed => "failed",
        },
        report.active_http_contract_count,
        report.findings.len(),
        report.local_only_receipt_coverage.registered_count,
        report.local_only_receipt_coverage.active_count,
        report.local_only_receipt_coverage.missing_count,
        if report
            .local_only_receipt_coverage
            .missing_contracts
            .is_empty()
        {
            String::new()
        } else {
            format!(
                " · Contracts: {}",
                report
                    .local_only_receipt_coverage
                    .missing_contracts
                    .join(", ")
            )
        }
    );
    for contract in &report.contracts {
        let proof = match contract.effect_proof.kind {
            ProofKind::DeclarationOnly => "declarationOnly/notApplicable".to_string(),
            ProofKind::LocalOnlyStatic => format!(
                "localOnlyStatic/{}; state={}; effect={}; privilege={}",
                proof_status_wire(contract.effect_proof.status),
                option_state_wire(contract.effect_proof.state_kind),
                contract
                    .effect_proof
                    .effect_class
                    .as_deref()
                    .unwrap_or("null"),
                contract
                    .effect_proof
                    .privilege_class
                    .as_deref()
                    .unwrap_or("null")
            ),
        };
        let mount = format!(
            "{}{}",
            mount_status_wire(contract.route.mount_status),
            if contract.route.mount_sources.is_empty() {
                String::new()
            } else {
                format!(": {}", contract.route.mount_sources.join(", "))
            }
        );
        let findings = if contract.findings.is_empty() {
            "—".to_string()
        } else {
            contract
                .findings
                .iter()
                .map(|finding| {
                    format!("{} @ {}: {}", finding.rule, finding.subject, finding.detail)
                })
                .collect::<Vec<_>>()
                .join("; ")
        };
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            literal_cell(&contract.contract_id),
            literal_cell(&contract.owner),
            literal_cell(&contract.method),
            literal_cell(&contract.path),
            literal_cell(&contract.consistency_level),
            literal_cell(&contract.effects.join(", ")),
            literal_cell(&mount),
            literal_cell(&proof),
            literal_cell(source_receipt_registration_status_wire(
                contract.source_receipt_registration.status,
            )),
            literal_cell(&findings),
        ));
    }
    output
}

fn discover_without_absolute_paths(root: &Path) -> Result<Vec<DiscoveredContract>> {
    crate::contract::discover(&root.join("contracts")).map_err(|error| {
        let root_text = root.to_string_lossy();
        anyhow!(format!("{error:#}").replace(root_text.as_ref(), "."))
    })
}

fn contracts_and_profile_findings(
    root: &Path,
    discovered: &[DiscoveredContract],
) -> Result<(Vec<Contract>, Vec<Finding>)> {
    let mut contracts = Vec::new();
    let mut findings = Vec::new();
    for item in discovered {
        let manifest = &item.manifest;
        if manifest.lifecycle != Lifecycle::Active
            || manifest.kind != ContractKind::Http
            || manifest.consistency_level != ConsistencyLevel::LocalOnly
        {
            continue;
        }
        let subject = relative_manifest_path(root, item)?;
        let path = required_path(manifest.path.as_deref(), &subject, &manifest.id)?.to_string();
        let method = required_method(manifest.method, &subject, &manifest.id)?
            .as_wire()
            .to_string();
        let serving_scope = match &manifest.owner {
            ContractOwner::Domain(owner) if owner == &manifest.domain => {
                ServingScope::Domain(owner.clone())
            }
            ContractOwner::Framework => {
                ServingScope::Framework(framework_serving_assemblies(root, &manifest.id)?)
            }
            ContractOwner::Domain(_) => bail!(
                "{subject}: LocalOnly contract `{}` must have its domain as owner",
                manifest.id
            ),
        };
        let profile = manifest.effect_profile.as_ref().ok_or_else(|| {
            anyhow!(
                "{subject}: active LocalOnly HTTP contract `{}` missing `effectProfile`",
                manifest.id
            )
        })?;
        for effect in profile
            .effects
            .iter()
            .copied()
            .filter_map(forbidden_effect_wire)
        {
            findings.push(contract_finding(
                Rule::ForbiddenStateEffect,
                &manifest.id,
                &method,
                &path,
                &subject,
                effect,
                "unknown",
                "manifest effectProfile",
            ));
        }
        contracts.push(Contract {
            id: manifest.id.clone(),
            serving_scope,
            key: generated_key(&manifest.domain, &manifest.version, item.slug.as_deref()),
            method,
            path,
            subject,
        });
    }
    contracts.sort_by(|a, b| (&a.id, &a.subject).cmp(&(&b.id, &b.subject)));
    Ok((contracts, findings))
}

fn source_findings(root: &Path, contracts: &[Contract]) -> Result<Vec<Finding>> {
    let generated = generated_localonly_routes(root)?;
    let mut by_scope: BTreeMap<&ServingScope, Vec<&Contract>> = BTreeMap::new();
    for contract in contracts {
        by_scope
            .entry(&contract.serving_scope)
            .or_default()
            .push(contract);
    }
    let mut findings = Vec::new();
    for (scope, owned) in by_scope {
        let evidence = canonical_evidence_for_scope(root, scope)?;
        let source = owned
            .iter()
            .any(|contract| mount_requires_source(evidence.mounts.get(&contract.key)))
            .then(|| ProofSource::load(root, scope, &evidence.reachable_production_sources))
            .transpose()?;
        for contract in owned {
            if !generated.contains(&contract.key) || !evidence.mounts.contains_key(&contract.key) {
                findings.push(contract_finding(
                    Rule::MissingRouteBinding,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &contract.subject,
                    "unknown",
                    "unknown",
                    "generated typed ROUTE or canonical serving mount is missing",
                ));
                continue;
            }
            let mounts = evidence
                .mounts
                .get(&contract.key)
                .ok_or_else(|| anyhow!("canonical mount disappeared during evaluation"))?;
            findings.extend(evaluate_localonly_mount(contract, mounts, source.as_ref())?.findings);
        }
    }
    Ok(findings)
}

#[derive(Debug)]
struct LocalOnlyProofEvaluation {
    state_kind: Option<StateKind>,
    effect_class: Option<String>,
    privilege_class: Option<String>,
    findings: Vec<Finding>,
}

fn evaluate_localonly_mount(
    contract: &Contract,
    mounts: &BTreeSet<crate::localtx_coverage::CanonicalRouteMount>,
    source: Option<&ProofSource>,
) -> Result<LocalOnlyProofEvaluation> {
    let mut evaluation = LocalOnlyProofEvaluation {
        state_kind: None,
        effect_class: None,
        privilege_class: None,
        findings: Vec::new(),
    };
    if mounts.len() != 1 {
        evaluation.findings.push(contract_finding(
            Rule::OpaqueSourceScope,
            &contract.id,
            &contract.method,
            &contract.path,
            &contract.subject,
            "unknown",
            "unknown",
            "route has conflicting endpoint/state evidence (dead or unmounted spoof included)",
        ));
        return Ok(evaluation);
    }
    let mount = mounts
        .iter()
        .next()
        .ok_or_else(|| anyhow!("one canonical mount expected"))?;
    use crate::localtx_coverage::CanonicalMountedState;
    match &mount.state {
        CanonicalMountedState::Stateless => evaluation.state_kind = Some(StateKind::Stateless),
        CanonicalMountedState::Ordinary => {
            evaluation.state_kind = Some(StateKind::Ordinary);
            evaluation.findings.push(contract_finding(
                Rule::UnclassifiedState,
                &contract.id,
                &contract.method,
                &contract.path,
                &contract.subject,
                "unknown",
                "unknown",
                "LocalOnly endpoint uses ordinary with_state",
            ));
        }
        CanonicalMountedState::Opaque => {
            evaluation.state_kind = Some(StateKind::Opaque);
            evaluation.findings.push(contract_finding(
                Rule::OpaqueSourceScope,
                &contract.id,
                &contract.method,
                &contract.path,
                &mount.source,
                "unknown",
                "unknown",
                "classified state expression is opaque",
            ));
        }
        CanonicalMountedState::Classified(expression) => {
            evaluation.state_kind = Some(StateKind::Classified);
            let source = source.context("classified LocalOnly source evidence is missing")?;
            let Some(state) = source.state_name(&mount.source, expression) else {
                evaluation.findings.push(contract_finding(
                    Rule::OpaqueSourceScope,
                    &contract.id,
                    &contract.method,
                    &contract.path,
                    &mount.source,
                    "unknown",
                    "unknown",
                    "classified state expression is not a canonical named struct",
                ));
                return Ok(evaluation);
            };
            match source.classify_state(&state) {
                Ok(classification) => {
                    evaluation.effect_class = Some(classification.effect.clone());
                    evaluation.privilege_class = Some(classification.privilege.clone());
                    if classification.privilege == "CrossTenantPrivilege" {
                        evaluation.findings.push(classified_finding(
                            Rule::CrossTenantPrivilege,
                            contract,
                            &state,
                            &classification,
                        ));
                    }
                    if !matches!(classification.effect.as_str(), "ReadEffect" | "AuthEffect") {
                        evaluation.findings.push(classified_finding(
                            Rule::ForbiddenStateEffect,
                            contract,
                            &state,
                            &classification,
                        ));
                    }
                }
                Err(error) => {
                    let error = format!("state `{state}`: {error}");
                    let subject =
                        diagnostic_source(&error).unwrap_or_else(|| contract.subject.clone());
                    evaluation.findings.push(contract_finding(
                        if source.states.contains_key(&state) {
                            Rule::OpaqueSourceScope
                        } else {
                            Rule::UnclassifiedState
                        },
                        &contract.id,
                        &contract.method,
                        &contract.path,
                        &subject,
                        "unknown",
                        "unknown",
                        &error,
                    ));
                }
            }
        }
    }
    Ok(evaluation)
}

fn mount_requires_source(
    mounts: Option<&BTreeSet<crate::localtx_coverage::CanonicalRouteMount>>,
) -> bool {
    use crate::localtx_coverage::CanonicalMountedState;
    matches!(
        mounts.and_then(|mounts| {
            let mut mounts = mounts.iter();
            let only = mounts.next()?;
            mounts.next().is_none().then_some(&only.state)
        }),
        Some(CanonicalMountedState::Classified(_))
    )
}

/// Closes the runtime-observation provenance seam left deliberately open by `testkit`'s zero
/// workspace-dependency boundary. The native types make dimensions and proof values
/// non-interchangeable; this source gate binds those values back to the canonical owner-side
/// provider/route evidence. Only direct, mechanically auditable shapes are accepted. Wrappers and
/// aliases that the scanner cannot prove are rejected instead of guessed through.
struct ParsedLocalOnlySource {
    subject: String,
    package: String,
    test_module_prefix: Option<Vec<String>>,
    syntax: syn::File,
    scoped_recorded_provider_fields: BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    canonical_test_repo_fields: BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    receipt_namespace_error: Option<String>,
}

fn local_only_source_inventory(root: &Path) -> Result<Vec<ParsedLocalOnlySource>> {
    let mut files = Vec::new();
    for member in workspace_member_paths(root)? {
        if member == Path::new("crates/testkit") {
            continue;
        }
        for source_root in [
            root.join(&member).join("src"),
            root.join(&member).join("tests"),
        ] {
            if source_root.is_dir() {
                files.extend(
                    rust_files(&source_root)?
                        .into_iter()
                        .map(|file| (member.clone(), file)),
                );
            }
        }
    }
    files.sort();

    let mut parsed = Vec::new();
    for (member, file) in files {
        let subject = relative(root, &file)?;
        let package = workspace_package_name(root, &member)?;
        let test_module_prefix = library_test_module_prefix(root, &member, &file)?;
        let syntax = syn::parse_file(
            &std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?,
        )
        .with_context(|| format!("parse `{subject}`"))?;
        let scoped_recorded_provider_fields =
            collect_scoped_recorded_provider_fields(&syntax.items);
        let canonical_test_repo_fields = collect_canonical_test_repo_fields(&syntax.items);
        let receipt_namespace_error = validate_receipt_namespace(root, &member).err();
        parsed.push(ParsedLocalOnlySource {
            subject,
            package,
            test_module_prefix,
            syntax,
            scoped_recorded_provider_fields,
            canonical_test_repo_fields,
            receipt_namespace_error,
        });
    }
    Ok(parsed)
}

fn workspace_package_name(root: &Path, member: &Path) -> Result<String> {
    let manifest = root.join(member).join("Cargo.toml");
    let value: toml::Value = toml::from_str(
        &std::fs::read_to_string(&manifest)
            .with_context(|| format!("read workspace member manifest `{}`", manifest.display()))?,
    )
    .with_context(|| format!("parse workspace member manifest `{}`", manifest.display()))?;
    value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .context("workspace member package.name must be a string")
}

fn library_test_module_prefix(
    root: &Path,
    member: &Path,
    file: &Path,
) -> Result<Option<Vec<String>>> {
    let src = root.join(member).join("src");
    let Ok(relative) = file.strip_prefix(&src) else {
        return Ok(None);
    };
    let mut components = relative
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(ToOwned::to_owned)
                .context("LocalOnly source module path must be UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    let file_name = components.pop().context("LocalOnly source path is empty")?;
    match file_name.as_str() {
        "lib.rs" => {}
        "mod.rs" => {}
        "main.rs" => return Ok(None),
        _ if file_name.ends_with(".rs") => {
            components.push(file_name.trim_end_matches(".rs").to_owned());
        }
        _ => return Ok(None),
    }
    Ok(Some(components))
}

fn observation_provenance_findings(inventory: &[ParsedLocalOnlySource]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for source in inventory {
        provenance_findings_in_items(
            &source.syntax.items,
            &source.subject,
            &source.scoped_recorded_provider_fields,
            &mut Vec::new(),
            &mut findings,
        );
    }
    findings
}

fn workspace_member_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let manifest = root.join("Cargo.toml");
    let value: toml::Value = toml::from_str(
        &std::fs::read_to_string(&manifest).with_context(|| "read workspace Cargo.toml")?,
    )
    .context("parse workspace Cargo.toml")?;
    let members = value
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| anyhow!("workspace.members must be an explicit array"))?;
    let mut paths = Vec::new();
    for member in members {
        let member = member
            .as_str()
            .ok_or_else(|| anyhow!("workspace member must be a string"))?;
        if member.contains(['*', '?', '[', ']']) {
            bail!("workspace member globs are opaque to LocalOnly provenance: `{member}`");
        }
        let path = PathBuf::from(member);
        if path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            bail!("workspace member escapes the repository: `{member}`");
        }
        paths.push(path);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn validate_receipt_namespace(root: &Path, member: &Path) -> std::result::Result<(), String> {
    let manifest_text = std::fs::read_to_string(root.join(member).join("Cargo.toml"))
        .map_err(|_| "receipt owner manifest is unreadable".to_string())?;
    let manifest: toml::Value = toml::from_str(&manifest_text)
        .map_err(|_| "receipt owner manifest is malformed".to_string())?;
    let expected = [
        ("testkit", Path::new("crates/testkit")),
        ("generated", Path::new("generated")),
        ("httpserve", Path::new("crates/httpserve")),
    ];
    for (name, target) in expected {
        let target_manifest = std::fs::read_to_string(root.join(target).join("Cargo.toml"))
            .map_err(|_| format!("canonical `{name}` workspace package is missing"))?;
        let target_value: toml::Value = toml::from_str(&target_manifest)
            .map_err(|_| format!("canonical `{name}` workspace package manifest is malformed"))?;
        if target_value
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            != Some(name)
        {
            return Err(format!("canonical `{name}` path names another package"));
        }
        let mut found = false;
        for section in ["dependencies", "dev-dependencies"] {
            let Some(dependencies) = manifest.get(section).and_then(toml::Value::as_table) else {
                continue;
            };
            for (key, value) in dependencies {
                let Some(table) = value.as_table() else {
                    if key == name {
                        return Err(format!(
                            "canonical `{name}` dependency must use an exact path"
                        ));
                    }
                    continue;
                };
                if table.get("package").and_then(toml::Value::as_str) == Some(name) && key != name {
                    return Err(format!("canonical `{name}` dependency may not be renamed"));
                }
                if key != name {
                    continue;
                }
                if table.contains_key("package") {
                    return Err(format!(
                        "canonical `{name}` dependency may not override package"
                    ));
                }
                let path = table
                    .get("path")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        format!("canonical `{name}` dependency must use an exact path")
                    })?;
                let actual = root
                    .join(member)
                    .join(path)
                    .canonicalize()
                    .map_err(|_| format!("canonical `{name}` dependency path is invalid"))?;
                let expected = root
                    .join(target)
                    .canonicalize()
                    .map_err(|_| format!("canonical `{name}` workspace path is invalid"))?;
                if actual != expected {
                    return Err(format!(
                        "canonical `{name}` dependency points outside its workspace package"
                    ));
                }
                found = true;
            }
        }
        if !found {
            return Err(format!("canonical `{name}` dependency is missing"));
        }
    }
    Ok(())
}

/// Reconciles canonical source receipt sites with the generated active LocalOnly target set.
/// Missing sites are blocking policy findings; every malformed or stale site is a structural error.
fn local_only_receipt_registration(
    root: &Path,
    targets: &[LocalOnlyReceiptTarget],
) -> Result<ReceiptRegistration> {
    let inventory = local_only_source_inventory(root)?;
    local_only_receipt_registration_in_inventory(&inventory, targets)
}

fn local_only_receipt_registration_in_inventory(
    inventory: &[ParsedLocalOnlySource],
    targets: &[LocalOnlyReceiptTarget],
) -> Result<ReceiptRegistration> {
    collect_local_only_receipt_inventory(inventory, targets).map(|(registration, _)| registration)
}

fn collect_local_only_receipt_inventory(
    inventory: &[ParsedLocalOnlySource],
    targets: &[LocalOnlyReceiptTarget],
) -> Result<(ReceiptRegistration, Vec<LocalOnlyExecutionTest>)> {
    let mut by_module = BTreeMap::new();
    let mut active_ids = BTreeSet::new();
    for target in targets {
        if target.module_path.is_empty() {
            bail!("LocalOnly receipt target has an empty generated module path");
        }
        if !active_ids.insert(target.contract_id.clone()) {
            bail!(
                "duplicate active LocalOnly receipt target `{}`",
                target.contract_id
            );
        }
        if by_module
            .insert(target.module_path.clone(), target.contract_id.clone())
            .is_some()
        {
            bail!("duplicate generated LocalOnly receipt target module");
        }
    }

    let mut registered = BTreeMap::<String, String>::new();
    let mut tests = Vec::new();
    let settings_composition = collect_settings_production_composition_certificate(inventory);
    for source in inventory {
        let factories =
            verified_router_factories(&source.syntax.items, settings_composition.clone());
        let sites = receipt_sites_in_file(
            &source.syntax,
            &source.subject,
            &source.scoped_recorded_provider_fields,
            &source.canonical_test_repo_fields,
            source.receipt_namespace_error.as_deref(),
            &factories,
        )?;
        for site in sites {
            let contract_id = by_module.get(&site.module_path).ok_or_else(|| {
                anyhow!(
                    "{}: receipt marker does not name an active LocalOnly generated target",
                    site.subject
                )
            })?;
            if let Some(previous) = registered.insert(contract_id.clone(), site.subject.clone()) {
                bail!(
                    "{}: duplicate LocalOnly receipt registration for `{contract_id}` (first at {previous})",
                    site.subject
                );
            }
            let mut test_name = source.test_module_prefix.clone().ok_or_else(|| {
                anyhow!(
                    "{}: canonical LocalOnly execution receipt must live in a library unit test",
                    site.subject
                )
            })?;
            test_name.extend(site.test_name);
            if test_name.is_empty() {
                bail!(
                    "{}: canonical LocalOnly execution test name is empty",
                    site.subject
                );
            }
            tests.push(LocalOnlyExecutionTest {
                contract_id: contract_id.clone(),
                package: source.package.clone(),
                test_target: "lib".to_owned(),
                test_name: test_name.join("::"),
            });
        }
    }

    tests.sort();
    let registration =
        ReceiptRegistration::reconcile(active_ids, registered.into_keys().collect())?;
    Ok((registration, tests))
}

/// Returns the executable LocalOnly receipt inventory for the current generated active registry.
pub(crate) fn local_only_execution_inventory(root: &Path) -> Result<LocalOnlyExecutionInventory> {
    let targets = generated::http::LOCAL_ONLY_SPECS
        .iter()
        .map(|spec| LocalOnlyReceiptTarget {
            contract_id: spec.route.contract_id().to_owned(),
            module_path: module_path_from_mount_key(spec.mount_key),
        })
        .collect::<Vec<_>>();
    let parsed = local_only_source_inventory(root)?;
    let (registration, tests) = collect_local_only_receipt_inventory(&parsed, &targets)?;
    if !registration.missing_contracts.is_empty() {
        bail!("active LocalOnly execution inventory has missing source receipts");
    }
    if tests.len() != registration.active_contracts.len() || tests.is_empty() {
        bail!("LocalOnly execution inventory must contain one non-empty test per active contract");
    }
    let source_receipt_contract_ids = tests
        .iter()
        .map(|test| test.contract_id.clone())
        .collect::<BTreeSet<_>>();
    if source_receipt_contract_ids != registration.registered_contracts {
        bail!("LocalOnly execution tests disagree with canonical source receipts");
    }
    Ok(LocalOnlyExecutionInventory {
        active_contract_ids: registration.active_contracts,
        source_receipt_contract_ids,
        tests,
    })
}

#[derive(Debug)]
struct CanonicalReceiptSite {
    module_path: Vec<String>,
    test_name: Vec<String>,
    subject: String,
}

#[derive(Default)]
struct ReceiptCallScan<'ast> {
    calls: BTreeMap<(usize, usize), &'ast syn::ExprCall>,
    proven_statement_calls: BTreeSet<(usize, usize)>,
    canonical_call_blocks: BTreeMap<(usize, usize), &'ast syn::Block>,
    canonical_call_modules: BTreeMap<(usize, usize), Vec<String>>,
    canonical_call_test_names: BTreeMap<(usize, usize), Vec<String>>,
    assertion_path_locations: BTreeSet<(usize, usize)>,
    called_assertion_locations: BTreeSet<(usize, usize)>,
    forbidden_locations: Vec<(usize, &'static str)>,
    module_path: Vec<String>,
    function_depth: usize,
}

impl<'ast> Visit<'ast> for ReceiptCallScan<'ast> {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "assert_local_only_with_receipt")
        {
            let start = node.span().start();
            self.assertion_path_locations
                .insert((start.line, start.column));
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if use_tree_contains_receipt_api(&node.tree) {
            self.forbidden_locations.push((
                node.span().start().line,
                "LocalOnly receipt APIs and markers may not be imported or renamed",
            ));
        }
        visit::visit_item_use(self, node);
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if type_contains_receipt_api(&node.ty) {
            self.forbidden_locations.push((
                node.span().start().line,
                "LocalOnly receipt API type aliases are forbidden",
            ));
        }
        visit::visit_item_type(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if self.function_depth == 0 && attrs_mark_canonical_test(&node.attrs) {
            for location in proven_receipt_statements(&node.block) {
                self.proven_statement_calls.insert(location);
                self.canonical_call_blocks.insert(location, &node.block);
                self.canonical_call_modules
                    .insert(location, self.module_path.clone());
                let mut test_name = self.module_path.clone();
                test_name.push(node.sig.ident.to_string());
                self.canonical_call_test_names.insert(location, test_name);
            }
        }
        self.function_depth += 1;
        visit::visit_item_fn(self, node);
        self.function_depth -= 1;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.function_depth += 1;
        visit::visit_impl_item_fn(self, node);
        self.function_depth -= 1;
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        let exposed = node
            .rename
            .as_ref()
            .map_or(&node.ident, |(_, rename)| rename);
        if matches!(
            exposed.to_string().as_str(),
            "axum" | "testkit" | "generated" | "httpserve"
        ) {
            self.forbidden_locations.push((
                node.span().start().line,
                "canonical receipt crate roots may not be shadowed with `extern crate`",
            ));
        }
        visit::visit_item_extern_crate(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.module_path.push(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.module_path.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_receipt_assertion_call(node) {
            let location = expr_location(&node.func);
            self.calls.insert(location, node);
            self.called_assertion_locations.insert(location);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if token_stream_contains_ident(&node.tokens, "assert_local_only_with_receipt") {
            self.forbidden_locations.push((
                node.span().start().line,
                "LocalOnly receipt assertions may not be hidden in macro tokens",
            ));
        }
        visit::visit_macro(self, node);
    }

    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node
            .segments
            .iter()
            .any(|segment| segment.ident == "LocalOnlyConformanceReceipt")
        {
            self.forbidden_locations.push((
                node.span().start().line,
                "LocalOnlyConformanceReceipt may only be produced by the canonical assertion",
            ));
        }
        visit::visit_path(self, node);
    }
}

fn token_stream_contains_ident(tokens: &proc_macro2::TokenStream, expected: &str) -> bool {
    tokens.clone().into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(ident) => ident == expected,
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_ident(&group.stream(), expected)
        }
        _ => false,
    })
}

fn receipt_sites_in_file(
    syntax: &syn::File,
    subject: &str,
    recorded_provider_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    canonical_test_repo_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    receipt_namespace_error: Option<&str>,
    factories: &VerifiedRouterFactories,
) -> Result<Vec<CanonicalReceiptSite>> {
    let mut scan = ReceiptCallScan::default();
    scan.visit_file(syntax);
    scan.forbidden_locations.sort();
    if let Some((line, detail)) = scan.forbidden_locations.first() {
        bail!("{subject}:{line}: {detail}");
    }
    if !scan.calls.is_empty()
        && let Some(detail) = receipt_namespace_error
    {
        bail!("{subject}: {detail}");
    }
    if let Some((line, _)) = scan
        .assertion_path_locations
        .difference(&scan.called_assertion_locations)
        .next()
    {
        bail!(
            "{subject}:{line}: LocalOnly receipt assertion function aliases and wrappers are forbidden"
        );
    }

    let mut sites = Vec::new();
    for (location, call) in scan.calls {
        let call_subject = format!("{subject}:{}", call.span().start().line);
        if !scan.proven_statement_calls.contains(&location) {
            bail!(
                "{call_subject}: LocalOnly receipt assertion must be a top-level `let (output, receipt) = ...await.expect(...)` statement in a canonical, enabled test and the receipt must be asserted"
            );
        }
        let marker_module = canonical_receipt_marker_module(call).ok_or_else(|| {
            anyhow!(
                "{call_subject}: LocalOnly receipt assertion must use the exact absolute testkit path and generated marker"
            )
        })?;
        let spec_module = canonical_receipt_contract_module(call).ok_or_else(|| {
            anyhow!(
                "{call_subject}: first argument must be the same generated module's SPEC.route.contract_id()"
            )
        })?;
        if marker_module != spec_module {
            bail!("{call_subject}: LocalOnly receipt marker and SPEC contract identity disagree");
        }
        let block = scan.canonical_call_blocks.get(&location).ok_or_else(|| {
            anyhow!("{call_subject}: receipt assertion has no canonical test block")
        })?;
        let lexical_module = scan.canonical_call_modules.get(&location).ok_or_else(|| {
            anyhow!("{call_subject}: receipt assertion has no lexical module certificate")
        })?;
        let test_name = scan
            .canonical_call_test_names
            .get(&location)
            .cloned()
            .ok_or_else(|| anyhow!("{call_subject}: receipt assertion has no test identity"))?;
        certify_receipt_source(
            call,
            block,
            lexical_module,
            &marker_module,
            ReceiptSourceEvidence {
                recorded_provider_fields,
                canonical_test_repo_fields,
                factories,
            },
            &call_subject,
        )?;
        sites.push(CanonicalReceiptSite {
            module_path: marker_module,
            test_name,
            subject: call_subject,
        });
    }
    Ok(sites)
}

struct ReceiptSourceEvidence<'a> {
    recorded_provider_fields: &'a BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    canonical_test_repo_fields: &'a BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    factories: &'a VerifiedRouterFactories,
}

fn attrs_mark_canonical_test(attrs: &[syn::Attribute]) -> bool {
    let test_attributes = attrs
        .iter()
        .filter(|attribute| {
            path_is(attribute.path(), &["test"])
                || path_is(attribute.path(), &["tokio", "test"])
                || path_is(attribute.path(), &["rstest"])
        })
        .count();
    test_attributes == 1 && attrs.iter().all(canonical_test_attribute)
}

fn canonical_test_attribute(attribute: &syn::Attribute) -> bool {
    if path_is(attribute.path(), &["test"])
        || path_is(attribute.path(), &["tokio", "test"])
        || path_is(attribute.path(), &["rstest"])
    {
        return true;
    }
    if !path_is(attribute.path(), &["allow"]) {
        return false;
    }
    attribute
        .meta
        .require_list()
        .is_ok_and(|list| list.tokens.to_string() == "clippy :: expect_used")
}

fn path_is(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.ident == *expected)
}

fn absolute_path_is(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_some()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| {
                actual.ident == *expected && matches!(actual.arguments, PathArguments::None)
            })
}

fn proven_receipt_statements(block: &syn::Block) -> BTreeSet<(usize, usize)> {
    let mut proven = BTreeSet::new();
    for (index, statement) in block.stmts.iter().enumerate() {
        let Some((location, receipt)) = receipt_binding_statement(statement) else {
            continue;
        };
        if block.stmts[..index]
            .iter()
            .any(statement_may_skip_following_receipt)
        {
            continue;
        }
        let following = &block.stmts[index + 1..];
        let assertion = following
            .iter()
            .position(|statement| statement_asserts_receipt(statement, &receipt));
        if assertion.is_some_and(|assertion| {
            !following[..assertion]
                .iter()
                .any(statement_may_skip_following_receipt)
        }) {
            proven.insert(location);
        }
    }
    proven
}

fn statement_may_skip_following_receipt(statement: &syn::Stmt) -> bool {
    #[derive(Default)]
    struct SkipFlow(bool);
    impl<'ast> Visit<'ast> for SkipFlow {
        fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
            self.0 = true;
        }

        fn visit_expr_try(&mut self, _node: &'ast syn::ExprTry) {
            self.0 = true;
        }

        fn visit_expr_if(&mut self, _node: &'ast syn::ExprIf) {
            self.0 = true;
        }

        fn visit_expr_match(&mut self, _node: &'ast syn::ExprMatch) {
            self.0 = true;
        }

        fn visit_expr_loop(&mut self, _node: &'ast syn::ExprLoop) {
            self.0 = true;
        }

        fn visit_expr_while(&mut self, _node: &'ast syn::ExprWhile) {
            self.0 = true;
        }

        fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
            self.0 = true;
        }
    }
    let mut scan = SkipFlow::default();
    scan.visit_stmt(statement);
    scan.0
}

fn receipt_binding_statement(statement: &syn::Stmt) -> Option<((usize, usize), String)> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Tuple(tuple) = &local.pat else {
        return None;
    };
    if tuple.elems.len() != 2 {
        return None;
    }
    let syn::Pat::Ident(receipt) = &tuple.elems[1] else {
        return None;
    };
    if receipt.by_ref.is_some() || receipt.mutability.is_some() || receipt.subpat.is_some() {
        return None;
    }
    let initializer = local.init.as_ref()?;
    let Expr::MethodCall(expect) = peel_expr(&initializer.expr) else {
        return None;
    };
    if expect.method != "expect" || expect.args.len() != 1 {
        return None;
    }
    let Expr::Await(awaited) = peel_expr(&expect.receiver) else {
        return None;
    };
    let Expr::Call(call) = peel_expr(&awaited.base) else {
        return None;
    };
    is_receipt_assertion_call(call).then(|| (expr_location(&call.func), receipt.ident.to_string()))
}

fn statement_asserts_receipt(statement: &syn::Stmt, receipt: &str) -> bool {
    let mac = match statement {
        syn::Stmt::Macro(statement) => &statement.mac,
        syn::Stmt::Expr(Expr::Macro(expression), _) => &expression.mac,
        _ => return false,
    };
    if !absolute_path_is(&mac.path, &["core", "assert_eq"]) {
        return false;
    }
    use syn::parse::Parser as _;
    let Ok(arguments) = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
        .parse2(mac.tokens.clone())
    else {
        return false;
    };
    arguments
        .iter()
        .take(2)
        .any(|argument| expression_is_receipt_read(argument, receipt))
}

fn expression_is_receipt_read(expression: &Expr, receipt: &str) -> bool {
    let Expr::MethodCall(call) = peel_expr(expression) else {
        return false;
    };
    call.method == "contract_id"
        && call.args.is_empty()
        && matches!(peel_expr(&call.receiver), Expr::Path(path) if path.path.is_ident(receipt))
}

fn asserted_receipt_contract_module(
    block: &syn::Block,
    call_location: (usize, usize),
) -> Option<Vec<String>> {
    for (index, statement) in block.stmts.iter().enumerate() {
        let Some((location, receipt)) = receipt_binding_statement(statement) else {
            continue;
        };
        if location != call_location {
            continue;
        }
        let mut assertions = block.stmts[index + 1..]
            .iter()
            .filter(|statement| statement_asserts_receipt(statement, &receipt));
        let statement = assertions.next()?;
        if assertions.next().is_some() {
            return None;
        }
        let mac = match statement {
            syn::Stmt::Macro(statement) => &statement.mac,
            syn::Stmt::Expr(Expr::Macro(expression), _) => &expression.mac,
            _ => return None,
        };
        if !absolute_path_is(&mac.path, &["core", "assert_eq"]) {
            return None;
        }
        use syn::parse::Parser as _;
        let arguments = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated
            .parse2(mac.tokens.clone())
            .ok()?;
        if arguments.len() != 2 {
            return None;
        }
        return arguments
            .iter()
            .find(|argument| !expression_is_receipt_read(argument, &receipt))
            .and_then(generated_contract_id_expression_module);
    }
    None
}

fn generated_contract_id_expression_module(expression: &Expr) -> Option<Vec<String>> {
    let Expr::MethodCall(contract_id) = peel_expr(expression) else {
        return None;
    };
    if contract_id.method != "contract_id" || !contract_id.args.is_empty() {
        return None;
    }
    let Expr::Field(route) = peel_expr(&contract_id.receiver) else {
        return None;
    };
    if !matches!(&route.member, syn::Member::Named(member) if member == "route") {
        return None;
    }
    let Expr::Path(spec) = peel_expr(&route.base) else {
        return None;
    };
    generated_terminal_module(&spec.path, "SPEC")
}

fn expr_location(expression: &Expr) -> (usize, usize) {
    let start = expression.span().start();
    (start.line, start.column)
}

fn is_receipt_assertion_call(call: &syn::ExprCall) -> bool {
    let Expr::Path(function) = peel_expr(&call.func) else {
        return false;
    };
    function
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "assert_local_only_with_receipt")
}

fn canonical_receipt_marker_module(call: &syn::ExprCall) -> Option<Vec<String>> {
    let Expr::Path(function) = peel_expr(&call.func) else {
        return None;
    };
    let path = &function.path;
    if path.leading_colon.is_none()
        || path.segments.len() != 3
        || path.segments[0].ident != "testkit"
        || path.segments[1].ident != "local_only"
        || path.segments[2].ident != "assert_local_only_with_receipt"
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &path.segments[2].arguments else {
        return None;
    };
    if arguments.args.len() != 4
        || !arguments
            .args
            .iter()
            .skip(1)
            .all(|argument| matches!(argument, GenericArgument::Type(Type::Infer(_))))
        || call.args.len() != 3
    {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    generated_marker_module(&marker.path)
}

fn generated_marker_module(path: &syn::Path) -> Option<Vec<String>> {
    if path.leading_colon.is_none()
        || path.segments.len() < 4
        || path.segments[0].ident != "generated"
        || path.segments[1].ident != "http"
        || path.segments.last()?.ident != "LocalOnlyConformanceMarker"
        || path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return None;
    }
    Some(
        path.segments
            .iter()
            .skip(2)
            .take(path.segments.len() - 3)
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

fn canonical_receipt_contract_module(call: &syn::ExprCall) -> Option<Vec<String>> {
    let argument = call.args.first()?;
    let Expr::MethodCall(contract_id) = peel_expr(argument) else {
        return None;
    };
    if contract_id.method != "contract_id" || !contract_id.args.is_empty() {
        return None;
    }
    let Expr::Field(route) = peel_expr(&contract_id.receiver) else {
        return None;
    };
    if !matches!(&route.member, syn::Member::Named(member) if member == "route") {
        return None;
    }
    let Expr::Path(spec) = peel_expr(&route.base) else {
        return None;
    };
    let path = &spec.path;
    if path.leading_colon.is_none()
        || path.segments.len() < 4
        || path.segments[0].ident != "generated"
        || path.segments[1].ident != "http"
        || path.segments.last()?.ident != "SPEC"
        || path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return None;
    }
    Some(
        path.segments
            .iter()
            .skip(2)
            .take(path.segments.len() - 3)
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

fn certify_receipt_source(
    call: &syn::ExprCall,
    block: &syn::Block,
    lexical_module: &[String],
    module: &[String],
    evidence: ReceiptSourceEvidence<'_>,
    subject: &str,
) -> Result<()> {
    let Some(observers_argument) = call.args.iter().nth(1) else {
        bail!("{subject}: receipt assertion requires three canonical arguments");
    };
    let observers_ident = simple_ident(observers_argument)
        .ok_or_else(|| anyhow!("{subject}: receipt observers must be one direct local binding"))?;
    let observers = unique_direct_initializer(block, &observers_ident).ok_or_else(|| {
        anyhow!("{subject}: receipt observers binding must be unique and direct in the test block")
    })?;
    let Expr::Call(observer_call) = peel_expr(observers) else {
        bail!("{subject}: observers must be initialized directly with LocalOnlyObservers::new");
    };
    if !absolute_call_path_is(
        &observer_call.func,
        &["testkit", "local_only", "LocalOnlyObservers", "new"],
    ) || observer_call.args.len() != 3
    {
        bail!("{subject}: observers must use the exact three-dimension absolute initializer");
    }

    let expected_dimensions = ["BusinessWrite", "Outbox", "Publish"];
    let mut proof_ident: Option<String> = None;
    let mut runtime_observers = Vec::new();
    for (argument, dimension) in observer_call.args.iter().zip(expected_dimensions) {
        if let Some(proof) = canonical_static_exclusion_proof(argument, dimension) {
            if proof_ident.as_ref().is_some_and(|known| known != &proof) {
                bail!("{subject}: all static exclusions must share one route-bound proof");
            }
            proof_ident = Some(proof);
        } else if let Some((provider, field)) = canonical_provider_handle(argument) {
            runtime_observers.push((provider, field));
        } else {
            bail!(
                "{subject}: {dimension} observer must be a direct governed exclusion or provider-owned handle"
            );
        }
    }

    let proof = proof_ident.as_ref().ok_or_else(|| {
        anyhow!("{subject}: receipt observers require one route-bound governed proof")
    })?;
    if asserted_receipt_contract_module(block, expr_location(&call.func)).as_deref() != Some(module)
    {
        bail!("{subject}: receipt assertion must compare against the same generated SPEC ID");
    }

    let Some(operation) = call.args.iter().nth(2) else {
        bail!("{subject}: receipt assertion requires a canonical operation argument");
    };
    let (router, operation_module) = canonical_receipt_operation(operation).ok_or_else(|| {
        anyhow!(
            "{subject}: operation must be a zero-argument move closure containing only the direct generated GET testkit call"
        )
    })?;
    if operation_module != module {
        bail!("{subject}: receipt operation path must use the same generated SPEC");
    }
    let (factory_name, factory_call) = mounted_factory_call(block, &router, proof).ok_or_else(|| {
        anyhow!(
            "{subject}: router and governed proof must be the direct tuple returned by `self::factory(...)`"
        )
    })?;
    let factory = evidence
        .factories
        .get(&(lexical_module.to_vec(), factory_name.clone()))
        .ok_or_else(|| {
            if module == ["settings_v4"] {
                if let Some(detail) = evidence.factories.settings_failure() {
                    return anyhow!("{subject}: Settings receipt {detail}");
                }
                anyhow!(
                    "{subject}: Settings receipt provider→TestRepo→service→Domain→classified-state factory failed route/proof/finalizer certification"
                )
            } else {
                anyhow!(
                    "{subject}: `self::{factory_name}` is not a cfg-valid mounted route factory in the receipt's lexical module"
                )
            }
        })?;
    if factory.route_module.as_slice() != module {
        bail!("{subject}: mounted factory proof names a different generated ROUTE");
    }
    if factory_call.args.len() != factory.parameters.len() {
        bail!("{subject}: mounted factory call does not match its certified parameter list");
    }

    for (provider, field) in runtime_observers {
        if unique_direct_initializer(block, &provider).is_none() {
            bail!("{subject}: runtime observer provider must have one direct test binding");
        }
        let matching_parameters = factory_call
            .args
            .iter()
            .enumerate()
            .filter_map(|(index, argument)| {
                canonical_test_repo_provider(argument)
                    .filter(|actual| actual == &provider)
                    .and_then(|_| factory.parameters.get(index))
            })
            .collect::<Vec<_>>();
        let owner = unique_direct_initializer(block, &provider).and_then(unique_constructor_owner);
        let repo_fields = owner.as_ref().and_then(|owner| {
            evidence
                .canonical_test_repo_fields
                .get(&(lexical_module.to_vec(), owner.clone()))
        });
        if matching_parameters.len() != 1
            || !factory
                .constructor_parameters
                .contains(matching_parameters[0])
            || factory
                .constructor_repo_fields
                .get(matching_parameters[0])
                .is_none_or(|fields| {
                    repo_fields.is_none_or(|provided| {
                        if identity_local_only_receipt_module(module) {
                            fields != provided
                        } else {
                            fields.is_disjoint(provided)
                        }
                    })
                })
            || factory_call
                .args
                .iter()
                .filter_map(canonical_test_repo_provider)
                .any(|actual| actual != provider)
        {
            if module == ["settings_v4"] {
                bail!(
                    "{subject}: Settings receipt provider→TestRepo→service→Domain→classified-state lineage does not match the runtime observer"
                );
            }
            bail!(
                "{subject}: runtime observer provider must map through `test_repo()` to the factory parameter used by the mounted Domain/state constructor"
            );
        }
        if repo_fields.is_none() {
            bail!(
                "{subject}: runtime observer provider must expose the canonical `test_repo()` provider bridge"
            );
        }
        if owner.as_ref().is_none_or(|owner| {
            evidence
                .recorded_provider_fields
                .get(&(lexical_module.to_vec(), owner.clone()))
                .is_none_or(|fields| !fields.contains(&field))
        }) {
            bail!("{subject}: runtime observer field has no provider-owned record mutation path");
        }
    }

    let counts = certificate_api_counts(block);
    let expected_static = observer_call.args.len() - counts.runtime_handles;
    if counts.receipt_calls != 1
        || counts.observer_initializers != 1
        || counts.testkit_calls != 1
        || counts.route_proofs != 0
        || counts.static_exclusions != expected_static
        || counts.runtime_handles != observer_call.args.len() - expected_static
    {
        bail!("{subject}: receipt test contains duplicate, shadow, helper, or bait evidence calls");
    }
    Ok(())
}

fn simple_ident(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = peel_expr(expression) else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

fn unique_direct_initializer<'a>(block: &'a syn::Block, expected: &str) -> Option<&'a Expr> {
    struct Count<'name> {
        expected: &'name str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Count<'_> {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            if node.ident == self.expected {
                self.count += 1;
            }
            visit::visit_pat_ident(self, node);
        }
    }
    let mut count = Count { expected, count: 0 };
    count.visit_block(block);
    if count.count != 1 {
        return None;
    }
    block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        let syn::Pat::Ident(pattern) = &local.pat else {
            return None;
        };
        (pattern.ident == expected && pattern.subpat.is_none())
            .then(|| local.init.as_ref().map(|init| &*init.expr))
            .flatten()
    })
}

fn canonical_static_exclusion_proof(expression: &Expr, dimension: &str) -> Option<String> {
    let Expr::Call(call) = peel_expr(expression) else {
        return None;
    };
    let Expr::Path(function) = peel_expr(&call.func) else {
        return None;
    };
    let path = &function.path;
    if path.leading_colon.is_none() || path.segments.len() != 4 || call.args.len() != 1 {
        return None;
    }
    let expected = ["testkit", "local_only", "StaticExclusion", "from_governed"];
    if path
        .segments
        .iter()
        .zip(expected)
        .any(|(actual, expected)| actual.ident != expected)
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &path.segments[2].arguments else {
        return None;
    };
    if arguments.args.len() != 1
        || !matches!(arguments.args.first(), Some(GenericArgument::Type(Type::Path(ty))) if ty.path.leading_colon.is_some() && ty.path.segments.len() == 3 && ty.path.segments[0].ident == "testkit" && ty.path.segments[1].ident == "local_only" && ty.path.segments[2].ident == dimension)
        || !matches!(path.segments[0].arguments, PathArguments::None)
        || !matches!(path.segments[1].arguments, PathArguments::None)
        || !matches!(path.segments[3].arguments, PathArguments::None)
    {
        return None;
    }
    referenced_ident(call.args.first()?)
}

fn canonical_provider_handle(expression: &Expr) -> Option<(String, String)> {
    let Expr::MethodCall(call) = peel_expr(expression) else {
        return None;
    };
    if call.method != "handle" || !call.args.is_empty() || call.turbofish.is_some() {
        return None;
    }
    let Expr::Field(field) = peel_expr(&call.receiver) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    let provider = simple_ident(&field.base)?;
    Some((provider, member.to_string()))
}

fn generated_route_reference_module(expression: &Expr) -> Option<Vec<String>> {
    let expression = match expression {
        Expr::Reference(reference) if reference.mutability.is_none() => peel_expr(&reference.expr),
        _ => return None,
    };
    let Expr::Path(path) = expression else {
        return None;
    };
    generated_terminal_module(&path.path, "ROUTE")
}

fn generated_terminal_module(path: &syn::Path, terminal: &str) -> Option<Vec<String>> {
    if path.leading_colon.is_none()
        || path.segments.len() < 4
        || path.segments[0].ident != "generated"
        || path.segments[1].ident != "http"
        || path.segments.last()?.ident != terminal
        || path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, PathArguments::None))
    {
        return None;
    }
    Some(
        path.segments
            .iter()
            .skip(2)
            .take(path.segments.len() - 3)
            .map(|segment| segment.ident.to_string())
            .collect(),
    )
}

fn canonical_receipt_operation(expression: &Expr) -> Option<(String, Vec<String>)> {
    enum PathReplacement {
        IdentityAccount,
        IdentityPolicy,
        SettingsKey,
    }

    let Expr::Closure(closure) = peel_expr(expression) else {
        return None;
    };
    if closure.capture.is_none()
        || closure.asyncness.is_some()
        || closure.constness.is_some()
        || !closure.inputs.is_empty()
    {
        return None;
    }
    let body = match peel_expr(&closure.body) {
        Expr::Block(block) if block.label.is_none() && block.block.stmts.len() == 1 => {
            block.block.stmts.first().and_then(tail_expression)?
        }
        body => body,
    };
    let Expr::Call(call) = peel_expr(body) else {
        return None;
    };
    if !absolute_call_path_is(&call.func, &["testkit", "call"]) || call.args.len() != 2 {
        return None;
    }
    let router = simple_ident(call.args.first()?)?;
    let Expr::Call(request) = peel_expr(call.args.iter().nth(1)?) else {
        return None;
    };
    if !absolute_call_path_is(&request.func, &["testkit", "ContractRequest", "get"])
        || request.args.len() != 1
    {
        return None;
    }
    let request_path = request.args.first()?;
    let (request_path, replacement) = match peel_expr(request_path) {
        Expr::MethodCall(replace)
            if replace.method == "replace"
                && replace.args.len() == 2
                && replace.turbofish.is_none()
                && string_literal_is(replace.args.first(), "{userId}")
                && string_literal_is(
                    replace.args.iter().nth(1),
                    "11111111-2222-4333-8444-555555555555",
                ) =>
        {
            (&*replace.receiver, Some(PathReplacement::IdentityAccount))
        }
        Expr::MethodCall(replace)
            if replace.method == "replace"
                && replace.args.len() == 2
                && replace.turbofish.is_none()
                && string_literal_is(replace.args.first(), "{policyId}")
                && string_literal_is(replace.args.iter().nth(1), "policy-a") =>
        {
            (&*replace.receiver, Some(PathReplacement::IdentityPolicy))
        }
        Expr::MethodCall(replace)
            if replace.method == "replace"
                && replace.args.len() == 2
                && replace.turbofish.is_none()
                && string_literal_is(replace.args.first(), "{key}")
                && string_literal_is(replace.args.iter().nth(1), "app.k") =>
        {
            (&*replace.receiver, Some(PathReplacement::SettingsKey))
        }
        other => (other, None),
    };
    let Expr::MethodCall(path) = peel_expr(request_path) else {
        return None;
    };
    if path.method != "path" || !path.args.is_empty() {
        return None;
    }
    let Expr::Field(route) = peel_expr(&path.receiver) else {
        return None;
    };
    if !matches!(&route.member, syn::Member::Named(member) if member == "route") {
        return None;
    }
    let Expr::Path(spec) = peel_expr(&route.base) else {
        return None;
    };
    let module = generated_terminal_module(&spec.path, "SPEC")?;
    match replacement {
        Some(PathReplacement::IdentityAccount)
            if module != ["identity_v1", "account_status_get"] =>
        {
            return None;
        }
        Some(PathReplacement::IdentityPolicy) if module != ["identity_v1", "policies_get"] => {
            return None;
        }
        Some(PathReplacement::SettingsKey)
            if module != ["settings_v4"] && module != ["settings_v7"] =>
        {
            return None;
        }
        None if module == ["settings_v4"] || module == ["settings_v7"] => return None,
        _ => {}
    }
    Some((router, module))
}

fn string_literal_is(expression: Option<&Expr>, expected: &str) -> bool {
    matches!(
        expression.map(peel_expr),
        Some(Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        })) if value.value() == expected
    )
}

#[derive(Debug, Clone)]
struct VerifiedRouterFactory {
    route_module: Vec<String>,
    parameters: Vec<String>,
    constructor_parameters: BTreeSet<String>,
    constructor_repo_fields: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug)]
struct VerifiedRouterFactories {
    entries: BTreeMap<(Vec<String>, String), VerifiedRouterFactory>,
    settings_provider: SettingsProviderCertification,
    settings_composition: SettingsCompositionCertification,
}

impl VerifiedRouterFactories {
    fn get(&self, key: &(Vec<String>, String)) -> Option<&VerifiedRouterFactory> {
        self.entries.get(key)
    }

    fn settings_failure(&self) -> Option<String> {
        match &self.settings_provider {
            SettingsProviderCertification::NotApplicable => Some(format_settings_failure(
                SettingsCertificationStage::RootTypes,
                "root production ConfigQueryService + SettingsService + SettingsDomain",
                "Settings provider model is not present in the receipt source",
            )),
            SettingsProviderCertification::Invalid {
                stage,
                expected,
                actual,
            } => Some(format_settings_failure(*stage, expected, actual)),
            SettingsProviderCertification::Valid(_) => match &self.settings_composition {
                SettingsCompositionCertification::NotApplicable => Some(format_settings_failure(
                    SettingsCertificationStage::ProductionComposition,
                    "composition/settings/src/lib.rs production wire",
                    "production composition source is not present",
                )),
                SettingsCompositionCertification::Invalid {
                    stage,
                    expected,
                    actual,
                } => Some(format_settings_failure(*stage, expected, actual)),
                SettingsCompositionCertification::Valid => None,
            },
        }
    }
}

fn mounted_factory_call<'a>(
    block: &'a syn::Block,
    router: &str,
    proof: &str,
) -> Option<(String, &'a syn::ExprCall)> {
    let mut tuple_call = None;
    let mut router_bindings = 0usize;
    let mut proof_bindings = 0usize;
    for statement in &block.stmts {
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        match &local.pat {
            syn::Pat::Tuple(tuple) if tuple.elems.len() == 2 => {
                let (syn::Pat::Ident(router_pat), syn::Pat::Ident(proof_pat)) =
                    (&tuple.elems[0], &tuple.elems[1])
                else {
                    continue;
                };
                if router_pat.ident != router || proof_pat.ident != proof {
                    continue;
                }
                if !immutable_plain_binding(router_pat) || !immutable_plain_binding(proof_pat) {
                    return None;
                }
                router_bindings += 1;
                proof_bindings += 1;
                let Expr::Call(call) = peel_expr(&local.init.as_ref()?.expr) else {
                    return None;
                };
                let Expr::Path(path) = peel_expr(&call.func) else {
                    return None;
                };
                if path.path.leading_colon.is_some()
                    || path.path.segments.len() != 2
                    || path.path.segments[0].ident != "self"
                    || !matches!(path.path.segments[0].arguments, PathArguments::None)
                    || !matches!(path.path.segments[1].arguments, PathArguments::None)
                {
                    return None;
                }
                tuple_call = Some((path.path.segments[1].ident.to_string(), call));
            }
            syn::Pat::Ident(pattern) if pattern.ident == router => {
                if !immutable_plain_binding(pattern) {
                    return None;
                }
                router_bindings += 1;
                if !canonical_identity_router_layer(local, router) {
                    return None;
                }
            }
            syn::Pat::Ident(pattern) if pattern.ident == proof => {
                if !immutable_plain_binding(pattern) {
                    return None;
                }
                proof_bindings += 1;
            }
            _ => {}
        }
    }
    if block_reassigns_any(block, &[router, proof]) {
        return None;
    }
    (tuple_call.is_some() && matches!(router_bindings, 1 | 2) && proof_bindings == 1)
        .then_some(tuple_call?)
}

fn immutable_plain_binding(pattern: &syn::PatIdent) -> bool {
    pattern.by_ref.is_none() && pattern.mutability.is_none() && pattern.subpat.is_none()
}

fn canonical_identity_router_layer(local: &syn::Local, router: &str) -> bool {
    let Some(initializer) = &local.init else {
        return false;
    };
    let Expr::MethodCall(layer) = peel_expr(&initializer.expr) else {
        return false;
    };
    if layer.method != "layer"
        || layer.args.len() != 1
        || layer.turbofish.is_some()
        || simple_ident(&layer.receiver).as_deref() != Some(router)
    {
        return false;
    }
    let Some(Expr::Call(extension)) = layer.args.first().map(peel_expr) else {
        return false;
    };
    if !absolute_call_path_is(&extension.func, &["axum", "Extension"]) || extension.args.len() != 1
    {
        return false;
    }
    let Some(Expr::Call(authenticated)) = extension.args.first().map(peel_expr) else {
        return false;
    };
    if !relative_call_path_is(&authenticated.func, &["httpserve", "Authenticated", "new"])
        || authenticated.args.len() != 4
    {
        return false;
    }
    let rss_access = expression_path_is(
        authenticated.args.first(),
        &["primitives", "RequiredScheme", "RssAccessToken"],
    ) || expression_path_is(
        authenticated.args.first(),
        &["primitives", "RequiredScheme", "FederatedAccessToken"],
    );
    let identity = authenticated.args.iter().nth(1).is_some_and(|principal| {
        expression_path_is(Some(principal), &["vocab", "PrincipalKind", "User"])
            || expression_path_is(Some(principal), &["vocab", "PrincipalKind", "Admin"])
    }) && authenticated
        .args
        .iter()
        .nth(2)
        .is_some_and(|argument| simple_ident(argument).as_deref() == Some("CANON_USER"))
        && authenticated
            .args
            .iter()
            .nth(3)
            .is_some_and(canonical_identity_tenant);
    let settings = authenticated.args.iter().nth(1).is_some_and(|principal| {
        expression_path_is(Some(principal), &["vocab", "PrincipalKind", "Admin"])
    }) && (string_literal_is(
        authenticated.args.iter().nth(2),
        "settings-config-get-subject",
    ) || string_literal_is(
        authenticated.args.iter().nth(2),
        "settings-secret-resolve-subject",
    )) && authenticated
        .args
        .iter()
        .nth(3)
        .is_some_and(canonical_settings_tenant);
    rss_access && (identity || settings)
}

fn canonical_identity_tenant(expression: &Expr) -> bool {
    let Expr::Call(some) = peel_expr(expression) else {
        return false;
    };
    if !relative_call_path_is(&some.func, &["Some"]) || some.args.len() != 1 {
        return false;
    }
    let Some(Expr::Call(tid)) = some.args.first().map(peel_expr) else {
        return false;
    };
    relative_call_path_is(&tid.func, &["tid"])
        && tid.args.len() == 1
        && tid
            .args
            .first()
            .is_some_and(|argument| simple_ident(argument).as_deref() == Some("CANON_TENANT"))
}

fn canonical_settings_tenant(expression: &Expr) -> bool {
    let Expr::Call(some) = peel_expr(expression) else {
        return false;
    };
    if !relative_call_path_is(&some.func, &["Some"]) || some.args.len() != 1 {
        return false;
    }
    let Some(Expr::Call(tenant)) = some.args.first().map(peel_expr) else {
        return false;
    };
    relative_call_path_is(&tenant.func, &["tenant"]) && tenant.args.is_empty()
}

fn relative_call_path_is(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = peel_expr(expression) else {
        return false;
    };
    path_is(&path.path, expected)
        && path
            .path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

fn expression_path_is(expression: Option<&Expr>, expected: &[&str]) -> bool {
    let Some(Expr::Path(path)) = expression.map(peel_expr) else {
        return false;
    };
    path_is(&path.path, expected)
        && path
            .path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

#[derive(Default)]
struct DomainProviderCertificate {
    constructor_fields: Vec<Option<String>>,
    aggregate_constructor: Option<AggregateConstructorCertificate>,
    field_states: BTreeMap<String, BTreeSet<String>>,
}

struct AggregateConstructorCertificate {
    parameter_index: usize,
    type_name: String,
    fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy)]
struct SettingsProviderCertificate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettingsCertificationStage {
    RootTypes,
    QueryFields,
    QueryConstructor,
    GetConfigRead,
    ServiceConstructor,
    QueryGetter,
    DomainConstructor,
    DomainMount,
    ProductionComposition,
}

impl SettingsCertificationStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RootTypes => "root-types",
            Self::QueryFields => "query-fields",
            Self::QueryConstructor => "query-constructor",
            Self::GetConfigRead => "get-config-read",
            Self::ServiceConstructor => "service-constructor",
            Self::QueryGetter => "query-getter",
            Self::DomainConstructor => "domain-constructor",
            Self::DomainMount => "domain-mount",
            Self::ProductionComposition => "production-composition",
        }
    }
}

#[derive(Debug, Clone)]
enum SettingsProviderCertification {
    NotApplicable,
    Invalid {
        stage: SettingsCertificationStage,
        expected: String,
        actual: String,
    },
    Valid(SettingsProviderCertificate),
}

impl SettingsProviderCertification {
    fn invalid(
        stage: SettingsCertificationStage,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self::Invalid {
            stage,
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

#[derive(Debug, Clone)]
enum SettingsCompositionCertification {
    NotApplicable,
    Invalid {
        stage: SettingsCertificationStage,
        expected: String,
        actual: String,
    },
    Valid,
}

impl SettingsCompositionCertification {
    fn invalid(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::Invalid {
            stage: SettingsCertificationStage::ProductionComposition,
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

fn format_settings_failure(
    stage: SettingsCertificationStage,
    expected: &str,
    actual: &str,
) -> String {
    format!(
        "certificate invalid at stage={}; expected={expected}; actual={actual}",
        stage.as_str()
    )
}

const IDENTITY_LOCAL_ONLY_PROVIDER_FIELDS: [&str; 4] = [
    "roles",
    "binding_reads",
    "policies",
    "resource_attribute_reads",
];

fn identity_local_only_receipt_module(module: &[String]) -> bool {
    matches!(
        module,
        [api, route]
            if api == "identity_v1"
                && matches!(
                    route.as_str(),
                    "account_status_get" | "roles_list" | "policies_get" | "policies_list"
                )
    )
}

fn identity_provider_fields_are_exact(value: &syn::ExprStruct, parameter: &str) -> bool {
    let provided = value
        .fields
        .iter()
        .filter_map(|field| {
            let syn::Member::Named(aggregate_field) = &field.member else {
                return None;
            };
            let field_name = aggregate_field.to_string();
            if !IDENTITY_LOCAL_ONLY_PROVIDER_FIELDS.contains(&field_name.as_str()) {
                return None;
            }
            let (provider, repo_field) = direct_provider_field(&field.expr)?;
            (provider == parameter && repo_field == field_name).then_some(field_name)
        })
        .collect::<BTreeSet<_>>();
    provided
        == IDENTITY_LOCAL_ONLY_PROVIDER_FIELDS
            .into_iter()
            .map(ToString::to_string)
            .collect()
}

fn canonical_identity_common_field_states(
    items: &[Item],
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    if !root_production_struct_exists(items, "IdentityCommonDomain")
        || !root_production_struct_exists(items, "CommonIdentityRouteState")
    {
        return None;
    }
    let mut matching = items.iter().filter_map(|item| {
        let Item::Impl(item) = item else {
            return None;
        };
        (item.trait_.is_none()
            && !cfg_gated(&item.attrs)
            && outer_type_ident(&item.self_ty).as_deref() == Some("IdentityCommonDomain"))
        .then_some(item)
    });
    let implementation = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    let method = |name: &str| {
        let mut methods = implementation.items.iter().filter_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name && !cfg_gated(&function.attrs) => {
                Some(function)
            }
            _ => None,
        });
        let only = methods.next()?;
        methods.next().is_none().then_some(only)
    };
    let constructor = method("new")?;
    let route_state = method("route_state")?;
    let parameters = constructor
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                syn::Pat::Ident(pattern) if immutable_plain_binding(pattern) => {
                    Some(pattern.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    if parameters.len() != constructor.sig.inputs.len()
        || !parameters.iter().any(|parameter| parameter == "roles")
        || !parameters.iter().any(|parameter| parameter == "policies")
    {
        return None;
    }
    let Some(Expr::Struct(returned)) = constructor
        .block
        .stmts
        .last()
        .and_then(tail_expression)
        .map(peel_expr)
    else {
        return None;
    };
    if !returned.path.is_ident("Self")
        || returned.rest.is_some()
        || !["roles", "policies"].into_iter().all(|expected| {
            returned.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == expected)
                    && simple_ident(&field.expr).as_deref() == Some(expected)
            })
        })
        || block_reassigns_any(&constructor.block, &["roles", "policies"])
    {
        return None;
    }
    let Some(Expr::Struct(state)) = route_state
        .block
        .stmts
        .last()
        .and_then(tail_expression)
        .map(peel_expr)
    else {
        return None;
    };
    if !state.path.is_ident("CommonIdentityRouteState") || state.rest.is_some() {
        return None;
    }
    let canonical_state = |outer: &str, state_type: &str, state_field: &str, source: &str| {
        state.fields.iter().any(|field| {
            if !matches!(&field.member, syn::Member::Named(member) if member == outer) {
                return false;
            }
            let Expr::Struct(value) = peel_expr(&field.expr) else {
                return false;
            };
            value.path.is_ident(state_type)
                && value.rest.is_none()
                && value.fields.iter().any(|field| {
                    matches!(&field.member, syn::Member::Named(member) if member == state_field)
                        && canonical_identity_state_field(&field.expr).as_deref() == Some(source)
                })
        })
    };
    if !canonical_state("roles_list", "RolesListHandlerState", "roles", "roles")
        || !canonical_state("policies_get", "PolicyQueryService", "policies", "policies")
    {
        return None;
    }
    Some(BTreeMap::from([
        (
            "roles".to_string(),
            BTreeSet::from(["RolesListHandlerState".to_string()]),
        ),
        (
            "policies".to_string(),
            BTreeSet::from(["PolicyQueryService".to_string()]),
        ),
    ]))
}

fn identity_init_mounts_common_route_state(block: &syn::Block) -> bool {
    let common_initializer = unique_direct_initializer(block, "common");
    let canonical_initializer = common_initializer.is_some_and(|initializer| {
        let Expr::MethodCall(call) = peel_expr(initializer) else {
            return false;
        };
        if call.method != "route_state" || !call.args.is_empty() || call.turbofish.is_some() {
            return false;
        }
        let Expr::Field(field) = peel_expr(&call.receiver) else {
            return false;
        };
        matches!(&field.member, syn::Member::Named(member) if member == "common")
            && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
    });
    if !canonical_initializer || block_reassigns_any(block, &["common"]) {
        return false;
    }
    struct CommonMounts {
        count: usize,
    }
    impl<'ast> Visit<'ast> for CommonMounts {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if relative_call_path_is(&node.func, &["mount_common_identity_routes"])
                && node.args.len() == 2
                && node.args.get(1).and_then(simple_ident).as_deref() == Some("common")
            {
                self.count += 1;
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut mounts = CommonMounts { count: 0 };
    mounts.visit_block(block);
    mounts.count == 1
}

fn identity_common_aggregate_fields(
    returned: &syn::ExprStruct,
    destructured: &BTreeMap<String, String>,
    common_states: Option<&BTreeMap<String, BTreeSet<String>>>,
) -> BTreeMap<String, String> {
    let Some(common_states) = common_states else {
        return BTreeMap::new();
    };
    let Some(common) = returned
        .fields
        .iter()
        .find(|field| matches!(&field.member, syn::Member::Named(member) if member == "common"))
    else {
        return BTreeMap::new();
    };
    let Expr::Call(call) = peel_expr(&common.expr) else {
        return BTreeMap::new();
    };
    if !relative_call_path_is(&call.func, &["IdentityCommonDomain", "new"]) {
        return BTreeMap::new();
    }
    call.args
        .iter()
        .filter_map(|argument| {
            let root = simple_ident(argument)?;
            common_states
                .contains_key(&root)
                .then(|| destructured.get(&root).map(|field| (field.clone(), root)))
                .flatten()
        })
        .collect()
}

fn merge_identity_common_states(
    found: &mut BTreeMap<String, BTreeSet<String>>,
    common_states: Option<&BTreeMap<String, BTreeSet<String>>>,
    init: &syn::Block,
) {
    if !identity_init_mounts_common_route_state(init) {
        return;
    }
    let Some(common_states) = common_states else {
        return;
    };
    for (field, states) in common_states {
        found
            .entry(field.clone())
            .or_default()
            .extend(states.iter().cloned());
    }
}

impl DomainProviderCertificate {
    fn direct_parameter_closes_state(&self, index: usize, state: &str) -> bool {
        self.constructor_fields
            .get(index)
            .and_then(Option::as_ref)
            .and_then(|field| self.field_states.get(field))
            .is_some_and(|states| states.contains(state))
    }

    fn aggregate_parameter_closes_state(
        &self,
        index: usize,
        argument: &Expr,
        parameter: &str,
        state: &str,
    ) -> bool {
        let Some(aggregate) = &self.aggregate_constructor else {
            return false;
        };
        if aggregate.parameter_index != index {
            return false;
        }
        let Expr::Struct(value) = peel_expr(argument) else {
            return false;
        };
        let canonical_aggregate = if aggregate.type_name == "IdentityDomainDeps" {
            canonical_identity_deps_path(&value.path)
        } else {
            value.path.leading_colon.is_none()
                && value.path.segments.len() == 1
                && value.path.segments[0].ident == aggregate.type_name
        };
        if value.rest.is_some() || !canonical_aggregate {
            return false;
        }
        if aggregate.type_name == "IdentityDomainDeps"
            && !identity_provider_fields_are_exact(value, parameter)
        {
            return false;
        }
        value.fields.iter().any(|field| {
            let syn::Member::Named(aggregate_field) = &field.member else {
                return false;
            };
            let Some((provider, repo_field)) = direct_provider_field(&field.expr) else {
                return false;
            };
            if provider != parameter || *aggregate_field != repo_field {
                return false;
            }
            aggregate
                .fields
                .get(&repo_field)
                .and_then(|domain_field| self.field_states.get(domain_field))
                .is_some_and(|states| states.contains(state))
        })
    }
}

fn collect_domain_provider_certificates(
    items: &[Item],
) -> BTreeMap<String, DomainProviderCertificate> {
    fn walk<'a>(items: &'a [Item], at_root: bool, impls: &mut Vec<(&'a ItemImpl, bool)>) {
        for item in items {
            match item {
                Item::Impl(item) => impls.push((item, at_root)),
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        walk(nested, false, impls);
                    }
                }
                _ => {}
            }
        }
    }
    let mut impls = Vec::new();
    walk(items, true, &mut impls);
    let canonical_identity_types = ["IdentityDomain", "IdentityDomainDeps"]
        .into_iter()
        .all(|name| root_production_struct_exists(items, name));
    let identity_common_states = canonical_identity_common_field_states(items);
    let mut certificates = BTreeMap::<String, DomainProviderCertificate>::new();
    for (item, at_root) in &impls {
        if item.trait_.is_some() {
            continue;
        }
        let Some(owner) = outer_type_ident(&item.self_ty) else {
            continue;
        };
        if owner == "IdentityDomain"
            && (!at_root || !canonical_identity_types || cfg_gated(&item.attrs))
        {
            continue;
        }
        let Some(function) = item.items.iter().find_map(|child| match child {
            ImplItem::Fn(function)
                if function.sig.ident == "new" && !cfg_gated(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        }) else {
            continue;
        };
        let parameters = function
            .sig
            .inputs
            .iter()
            .filter_map(|input| match input {
                syn::FnArg::Typed(argument) => match &*argument.pat {
                    syn::Pat::Ident(pattern) => Some(pattern.ident.to_string()),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .collect::<Vec<_>>();
        if parameters.len() != function.sig.inputs.len() {
            continue;
        }
        let Some(Expr::Struct(returned)) = function
            .block
            .stmts
            .last()
            .and_then(tail_expression)
            .map(peel_expr)
        else {
            continue;
        };
        if !returned.path.is_ident("Self") || returned.rest.is_some() {
            continue;
        }
        let mut fields = vec![None; parameters.len()];
        for field in &returned.fields {
            let syn::Member::Named(member) = &field.member else {
                continue;
            };
            if let Some(root) = direct_ident_or_field_root(&field.expr)
                && let Some(index) = parameters.iter().position(|parameter| parameter == &root)
            {
                fields[index] = Some(member.to_string());
            }
        }
        let certificate = certificates.entry(owner.clone()).or_default();
        certificate.constructor_fields = fields;
        if owner == "IdentityDomain"
            && parameters.len() == 1
            && function.sig.inputs.iter().next().is_some_and(|input| {
                matches!(
                    input,
                    syn::FnArg::Typed(argument)
                        if outer_type_ident(&argument.ty).as_deref() == Some("IdentityDomainDeps")
                )
            })
            && let Some(destructured) =
                canonical_identity_deps_destructure(&function.block, &parameters[0])
        {
            let aggregate_fields = returned
                .fields
                .iter()
                .filter_map(|field| {
                    let syn::Member::Named(domain_field) = &field.member else {
                        return None;
                    };
                    let root = direct_ident_or_field_root(&field.expr)?;
                    destructured
                        .get(&root)
                        .map(|deps_field| (deps_field.clone(), domain_field.to_string()))
                })
                .collect::<BTreeMap<_, _>>();
            let mut aggregate_fields = aggregate_fields;
            aggregate_fields.extend(identity_common_aggregate_fields(
                returned,
                &destructured,
                identity_common_states.as_ref(),
            ));
            if !aggregate_fields.is_empty()
                && !block_reassigns_any(
                    &function.block,
                    &destructured.keys().map(String::as_str).collect::<Vec<_>>(),
                )
            {
                certificate.aggregate_constructor = Some(AggregateConstructorCertificate {
                    parameter_index: 0,
                    type_name: "IdentityDomainDeps".to_string(),
                    fields: aggregate_fields,
                });
            }
        }
    }
    for (item, at_root) in impls {
        let Some((_, trait_path, _)) = &item.trait_ else {
            continue;
        };
        if trait_path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "Domain")
        {
            continue;
        }
        let Some(owner) = outer_type_ident(&item.self_ty) else {
            continue;
        };
        if owner == "IdentityDomain"
            && (!at_root || !canonical_identity_types || cfg_gated(&item.attrs))
        {
            continue;
        }
        let Some(init) = item.items.iter().find_map(|child| match child {
            ImplItem::Fn(function)
                if function.sig.ident == "init" && !cfg_gated(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        }) else {
            continue;
        };
        let identity = owner == "IdentityDomain";
        let aliases = if identity {
            BTreeMap::new()
        } else {
            init.block
                .stmts
                .iter()
                .filter_map(|statement| {
                    let syn::Stmt::Local(local) = statement else {
                        return None;
                    };
                    let syn::Pat::Ident(alias) = &local.pat else {
                        return None;
                    };
                    let initializer = local.init.as_ref()?;
                    self_field_receiver(&initializer.expr)
                        .map(|field| (alias.ident.to_string(), field))
                })
                .collect::<BTreeMap<_, _>>()
        };
        struct StateFields<'a> {
            identity: bool,
            aliases: &'a BTreeMap<String, String>,
            found: BTreeMap<String, BTreeSet<String>>,
        }
        impl<'ast> Visit<'ast> for StateFields<'_> {
            fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
                let Some(state) = node
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                else {
                    return;
                };
                if state.ends_with("State") || state == "PolicyQueryService" {
                    for field in &node.fields {
                        let direct = if self.identity {
                            canonical_identity_state_field(&field.expr)
                        } else {
                            direct_self_field_lineage(&field.expr)
                        };
                        if let Some(domain_field) = direct {
                            self.found
                                .entry(domain_field)
                                .or_default()
                                .insert(state.clone());
                        } else if !self.identity
                            && let Some(root) = root_receiver_ident(&field.expr)
                            && let Some(domain_field) = self.aliases.get(&root)
                        {
                            self.found
                                .entry(domain_field.clone())
                                .or_default()
                                .insert(state.clone());
                        }
                    }
                }
                visit::visit_expr_struct(self, node);
            }
        }
        let mut scan = StateFields {
            identity,
            aliases: &aliases,
            found: BTreeMap::new(),
        };
        scan.visit_block(&init.block);
        if identity {
            merge_identity_common_states(
                &mut scan.found,
                identity_common_states.as_ref(),
                &init.block,
            );
        }
        certificates.entry(owner).or_default().field_states = scan.found;
    }
    certificates
}

fn collect_settings_provider_certificate(items: &[Item]) -> SettingsProviderCertification {
    let root_types = ["ConfigQueryService", "SettingsService", "SettingsDomain"];
    let present = root_types
        .iter()
        .filter(|name| root_production_struct_exists(items, name))
        .copied()
        .collect::<Vec<_>>();
    if present.is_empty() {
        return SettingsProviderCertification::NotApplicable;
    }
    if present.len() != root_types.len() {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::RootTypes,
            root_types.join(" + "),
            format!("production root types found: {}", present.join(", ")),
        );
    }
    let expected_query_fields = BTreeSet::from(["cache".to_string(), "configs".to_string()]);
    let actual_query_fields = root_named_struct_fields(items, "ConfigQueryService");
    if actual_query_fields.as_ref() != Some(&expected_query_fields) {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::QueryFields,
            format!("exact fields {expected_query_fields:?}"),
            format!("fields {actual_query_fields:?}"),
        );
    }

    let query_new = match settings_production_method(
        items,
        "ConfigQueryService",
        None,
        "new",
        SettingsCertificationStage::QueryConstructor,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    let query_parameters = direct_parameter_names(query_new);
    if query_parameters.as_deref() != Some(&["configs".to_string(), "cache".to_string()])
        || !tail_self_struct_field_is_ident(&query_new.block, "configs", "configs")
        || !tail_self_struct_field_is_ident(&query_new.block, "cache", "cache")
        || local_binding_count(&query_new.block, "configs") != 0
        || block_reassigns_any(&query_new.block, &["configs", "cache"])
    {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::QueryConstructor,
            "ConfigQueryService::new(configs, cache) stores both direct parameters exactly once",
            format!("parameters={query_parameters:?}; constructor body is noncanonical"),
        );
    }

    let get_config = match settings_production_method(
        items,
        "ConfigQueryService",
        None,
        "get_config",
        SettingsCertificationStage::GetConfigRead,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    if !settings_get_config_reads_exact_providers(&get_config.block) {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::GetConfigRead,
            "one configs.head + one configs.find_version(active_version) + one cache.find",
            "get_config provider reads do not match the exact certified set",
        );
    }

    let service_constructor = match settings_production_method(
        items,
        "SettingsService",
        None,
        "with_postgres",
        SettingsCertificationStage::ServiceConstructor,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    let service_parameters = direct_parameter_names(service_constructor);
    if service_parameters.as_deref()
        != Some(&[
            "configs".to_string(),
            "writer".to_string(),
            "flags".to_string(),
            "clock".to_string(),
        ])
        || !canonical_arc_from_parameter_binding(service_constructor, "configs")
    {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::ServiceConstructor,
            "unique production SettingsService::with_postgres(configs, writer, flags, clock)",
            format!("parameters={service_parameters:?}; configs binding is noncanonical"),
        );
    }
    let Some(query_expression) = tail_self_struct_field(&service_constructor.block, "query") else {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::ServiceConstructor,
            "with_postgres stores query from ConfigQueryService::new(configs, cache)",
            "query field initializer is missing or indirect",
        );
    };
    let Expr::Call(query_call) = peel_expr(query_expression) else {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::ServiceConstructor,
            "direct ConfigQueryService::new(configs, cache) call",
            "query field is not initialized by a direct call",
        );
    };
    if !relative_call_path_is(&query_call.func, &["ConfigQueryService", "new"])
        || query_call.args.first().and_then(simple_ident).as_deref() != Some("configs")
        || query_call.args.get(1).and_then(simple_ident).as_deref() != Some("cache")
        || query_call.args.len() != 2
    {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::ServiceConstructor,
            "ConfigQueryService::new(configs, cache)",
            "with_postgres query initializer has a different constructor or argument lineage",
        );
    }

    let query_getter = match settings_production_method(
        items,
        "SettingsService",
        None,
        "config_query_service",
        SettingsCertificationStage::QueryGetter,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    let getter_tail = query_getter.block.stmts.last().and_then(tail_expression);
    if getter_tail.is_none_or(|tail| !self_field_clone(tail, "query")) {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::QueryGetter,
            "config_query_service returns self.query.clone()",
            "getter does not directly clone the certified query field",
        );
    }

    let domain_new = match settings_production_method(
        items,
        "SettingsDomain",
        None,
        "new",
        SettingsCertificationStage::DomainConstructor,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    let Some(config_query) = unique_direct_initializer(&domain_new.block, "config_query") else {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainConstructor,
            "one direct config_query binding from config.config_query_service()",
            "config_query binding is missing or ambiguous",
        );
    };
    let Expr::MethodCall(getter) = peel_expr(config_query) else {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainConstructor,
            "config.config_query_service()",
            "config_query binding is not a method call",
        );
    };
    if getter.method != "config_query_service"
        || !getter.args.is_empty()
        || getter.turbofish.is_some()
        || simple_ident(&getter.receiver).as_deref() != Some("config")
        || !tail_self_struct_field_is_ident(&domain_new.block, "config_query", "config_query")
    {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainConstructor,
            "SettingsDomain stores the direct config.config_query_service() result",
            "Domain constructor query lineage is noncanonical",
        );
    }

    let init = match settings_production_method(
        items,
        "SettingsDomain",
        Some("Domain"),
        "init",
        SettingsCertificationStage::DomainMount,
    ) {
        Ok(function) => function,
        Err(invalid) => return invalid,
    };
    let Some(init_query) = unique_direct_initializer(&init.block, "config_query") else {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainMount,
            "one direct config_query clone in Domain::init",
            "config_query mount binding is missing or ambiguous",
        );
    };
    if !self_field_clone(init_query, "config_query")
        || block_reassigns_any(&init.block, &["config_query"])
    {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainMount,
            "immutable self.config_query.clone() mount binding",
            "Domain::init mount binding has different lineage or is reassigned",
        );
    }
    struct ClassifiedStateCount(usize);
    impl<'ast> Visit<'ast> for ClassifiedStateCount {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node.method == "with_classified_state"
                && node.args.len() == 1
                && node.args.first().and_then(simple_ident).as_deref() == Some("config_query")
            {
                self.0 += 1;
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut mounted = ClassifiedStateCount(0);
    mounted.visit_block(&init.block);
    if mounted.0 != 1 {
        return SettingsProviderCertification::invalid(
            SettingsCertificationStage::DomainMount,
            "exactly one with_classified_state(config_query)",
            format!("found {} matching classified-state mounts", mounted.0),
        );
    }
    SettingsProviderCertification::Valid(SettingsProviderCertificate)
}

fn root_named_struct_fields(items: &[Item], owner: &str) -> Option<BTreeSet<String>> {
    let mut matches = items.iter().filter_map(|item| match item {
        Item::Struct(item) if !cfg_gated(&item.attrs) && item.ident == owner => {
            let syn::Fields::Named(fields) = &item.fields else {
                return None;
            };
            fields
                .named
                .iter()
                .map(|field| field.ident.as_ref().map(ToString::to_string))
                .collect::<Option<BTreeSet<_>>>()
        }
        _ => None,
    });
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}

fn direct_parameter_names(function: &syn::ImplItemFn) -> Option<Vec<String>> {
    function
        .sig
        .inputs
        .iter()
        .map(|input| match input {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                syn::Pat::Ident(pattern)
                    if pattern.by_ref.is_none()
                        && pattern.mutability.is_none()
                        && pattern.subpat.is_none() =>
                {
                    Some(pattern.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn local_binding_count(block: &syn::Block, expected: &str) -> usize {
    struct Bindings<'name> {
        expected: &'name str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Bindings<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if matches!(&node.pat, syn::Pat::Ident(pattern) if pattern.ident == self.expected) {
                self.count += 1;
            }
            visit::visit_local(self, node);
        }
    }
    let mut bindings = Bindings { expected, count: 0 };
    bindings.visit_block(block);
    bindings.count
}

fn canonical_arc_from_parameter_binding(function: &syn::ImplItemFn, parameter: &str) -> bool {
    if direct_parameter_names(function)
        .is_none_or(|parameters| parameters.iter().filter(|name| *name == parameter).count() != 1)
    {
        return false;
    }
    match local_binding_count(&function.block, parameter) {
        0 => true,
        1 => {
            let Some(Expr::Call(call)) =
                unique_direct_initializer(&function.block, parameter).map(peel_expr)
            else {
                return false;
            };
            relative_call_path_is(&call.func, &["Arc", "from"])
                && call.args.len() == 1
                && call.args.first().and_then(simple_ident).as_deref() == Some(parameter)
        }
        _ => false,
    }
}

fn settings_get_config_reads_exact_providers(block: &syn::Block) -> bool {
    #[derive(Default)]
    struct Reads {
        configs_head: usize,
        configs_find_version: usize,
        cache_find: usize,
        unexpected: bool,
    }
    impl<'ast> Visit<'ast> for Reads {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let method = node.method.to_string();
            if matches!(method.as_str(), "head" | "find" | "find_version") {
                match (
                    self_field_receiver(&node.receiver).as_deref(),
                    method.as_str(),
                ) {
                    (Some("configs"), "head") => self.configs_head += 1,
                    (Some("configs"), "find_version")
                        if node.args.len() == 3
                            && node.args.get(2).and_then(simple_ident).as_deref()
                                == Some("active_version") =>
                    {
                        self.configs_find_version += 1;
                    }
                    (Some("cache"), "find") => self.cache_find += 1,
                    _ => self.unexpected = true,
                }
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut reads = Reads::default();
    reads.visit_block(block);
    !reads.unexpected
        && reads.configs_head == 1
        && reads.configs_find_version == 1
        && reads.cache_find == 1
}

enum ProductionMethodSelection<'a> {
    Missing,
    Ambiguous(usize),
    Unique(&'a syn::ImplItemFn),
}

impl ProductionMethodSelection<'_> {
    fn actual(&self) -> String {
        match self {
            Self::Missing => "found 0 production-reachable methods".to_string(),
            Self::Ambiguous(count) => {
                format!("found {count} production-reachable methods (including unknown cfg)")
            }
            Self::Unique(_) => "found one production-reachable method".to_string(),
        }
    }
}

fn root_production_method<'a>(
    items: &'a [Item],
    owner: &str,
    trait_name: Option<&str>,
    method: &str,
) -> ProductionMethodSelection<'a> {
    let matches = items
        .iter()
        .filter_map(|item| {
            let Item::Impl(item) = item else {
                return None;
            };
            if !crate::localtx_coverage::attrs_may_be_production(&item.attrs)
                || outer_type_ident(&item.self_ty).as_deref() != Some(owner)
                || item
                    .trait_
                    .as_ref()
                    .and_then(|(_, path, _)| path.segments.last())
                    .map(|segment| segment.ident.to_string())
                    .as_deref()
                    != trait_name
            {
                return None;
            }
            Some(item.items.iter().filter_map(|child| match child {
                ImplItem::Fn(function)
                    if function.sig.ident == method
                        && crate::localtx_coverage::attrs_may_be_production(&function.attrs) =>
                {
                    Some(function)
                }
                _ => None,
            }))
        })
        .flatten()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => ProductionMethodSelection::Missing,
        [only] => ProductionMethodSelection::Unique(only),
        _ => ProductionMethodSelection::Ambiguous(matches.len()),
    }
}

fn settings_production_method<'a>(
    items: &'a [Item],
    owner: &str,
    trait_name: Option<&str>,
    method: &str,
    stage: SettingsCertificationStage,
) -> Result<&'a syn::ImplItemFn, SettingsProviderCertification> {
    let selection = root_production_method(items, owner, trait_name, method);
    match selection {
        ProductionMethodSelection::Unique(function) => Ok(function),
        other => Err(SettingsProviderCertification::invalid(
            stage,
            format!("exactly one production-reachable {owner}::{method}"),
            other.actual(),
        )),
    }
}

fn tail_self_struct_field<'a>(block: &'a syn::Block, field: &str) -> Option<&'a Expr> {
    let Expr::Struct(returned) = block
        .stmts
        .last()
        .and_then(tail_expression)
        .map(peel_expr)?
    else {
        return None;
    };
    if !returned.path.is_ident("Self") || returned.rest.is_some() {
        return None;
    }
    returned.fields.iter().find_map(|candidate| {
        matches!(&candidate.member, syn::Member::Named(member) if member == field)
            .then_some(&candidate.expr)
    })
}

fn tail_self_struct_field_is_ident(block: &syn::Block, field: &str, expected: &str) -> bool {
    tail_self_struct_field(block, field)
        .and_then(simple_ident)
        .as_deref()
        == Some(expected)
}

fn self_field_clone(expression: &Expr, expected: &str) -> bool {
    let Expr::MethodCall(clone) = peel_expr(expression) else {
        return false;
    };
    if clone.method != "clone" || !clone.args.is_empty() || clone.turbofish.is_some() {
        return false;
    }
    let Expr::Field(field) = peel_expr(&clone.receiver) else {
        return false;
    };
    matches!(&field.member, syn::Member::Named(member) if member == expected)
        && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
}

fn cfg_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        path_is(attribute.path(), &["cfg"]) || path_is(attribute.path(), &["cfg_attr"])
    })
}

fn root_production_struct_exists(items: &[Item], expected: &str) -> bool {
    items.iter().any(|item| {
        matches!(item, Item::Struct(item) if item.ident == expected && !cfg_gated(&item.attrs))
    })
}

fn canonical_identity_deps_destructure(
    block: &syn::Block,
    parameter: &str,
) -> Option<BTreeMap<String, String>> {
    let mut matches = block.stmts.iter().filter_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        if !local.attrs.is_empty()
            || local
                .init
                .as_ref()
                .is_some_and(|initializer| initializer.diverge.is_some())
        {
            return None;
        }
        let syn::Pat::Struct(pattern) = &local.pat else {
            return None;
        };
        if pattern.rest.is_some()
            || pattern.path.leading_colon.is_some()
            || pattern.path.segments.len() != 1
            || pattern.path.segments[0].ident != "IdentityDomainDeps"
            || local
                .init
                .as_ref()
                .and_then(|init| simple_ident(&init.expr))
                .as_deref()
                != Some(parameter)
        {
            return None;
        }
        let fields = pattern
            .fields
            .iter()
            .map(|field| {
                let syn::Member::Named(member) = &field.member else {
                    return None;
                };
                let syn::Pat::Ident(binding) = &*field.pat else {
                    return None;
                };
                if !immutable_plain_binding(binding) || binding.ident != *member {
                    return None;
                }
                Some((binding.ident.to_string(), member.to_string()))
            })
            .collect::<Option<BTreeMap<_, _>>>()?;
        (!fields.is_empty()).then_some(fields)
    });
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}

fn direct_self_field_lineage(expression: &Expr) -> Option<String> {
    match peel_expr(expression) {
        Expr::Field(field) => {
            let syn::Member::Named(member) = &field.member else {
                return None;
            };
            matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
                .then(|| member.to_string())
        }
        Expr::Reference(reference) if reference.mutability.is_none() => {
            direct_self_field_lineage(&reference.expr)
        }
        Expr::Call(call)
            if call.args.len() == 1 && relative_call_path_is(&call.func, &["Arc", "clone"]) =>
        {
            call.args.first().and_then(direct_self_field_lineage)
        }
        _ => None,
    }
}

fn canonical_identity_state_field(expression: &Expr) -> Option<String> {
    let Expr::Call(clone) = peel_expr(expression) else {
        return None;
    };
    if clone.args.len() != 1 || !relative_call_path_is(&clone.func, &["Arc", "clone"]) {
        return None;
    }
    let Expr::Reference(reference) = clone.args.first()? else {
        return None;
    };
    if reference.mutability.is_some() {
        return None;
    }
    let Expr::Field(field) = peel_expr(&reference.expr) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    if !matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self")) {
        return None;
    }
    let field = member.to_string();
    matches!(field.as_str(), "roles" | "policies").then_some(field)
}

fn canonical_identity_deps_path(path: &syn::Path) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 2
        && path.segments[0].ident == "super"
        && path.segments[1].ident == "IdentityDomainDeps"
        && path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

fn canonical_identity_domain_constructor_path(path: &syn::Path) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == 3
        && path.segments[0].ident == "super"
        && path.segments[1].ident == "IdentityDomain"
        && path.segments[2].ident == "new"
        && path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

fn direct_ident_or_field_root(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => direct_ident_or_field_root(&field.base),
        Expr::Paren(parenthesized) => direct_ident_or_field_root(&parenthesized.expr),
        Expr::Group(grouped) => direct_ident_or_field_root(&grouped.expr),
        _ => None,
    }
}

fn self_field_receiver(expression: &Expr) -> Option<String> {
    let mut expression = peel_expr(expression);
    while let Expr::MethodCall(call) = expression {
        expression = peel_expr(&call.receiver);
    }
    let Expr::Field(field) = expression else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
        .then(|| member.to_string())
}

fn outer_type_ident(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn collect_settings_production_composition_certificate(
    inventory: &[ParsedLocalOnlySource],
) -> SettingsCompositionCertification {
    let matching = inventory
        .iter()
        .filter(|source| source.subject == "composition/settings/src/lib.rs")
        .collect::<Vec<_>>();
    let [source] = matching.as_slice() else {
        return if matching.is_empty() {
            SettingsCompositionCertification::NotApplicable
        } else {
            SettingsCompositionCertification::invalid(
                "one canonical composition/settings/src/lib.rs source",
                format!("found {} matching sources", matching.len()),
            )
        };
    };
    certify_settings_production_composition(&source.syntax.items)
}

fn certify_settings_production_composition(items: &[Item]) -> SettingsCompositionCertification {
    let wires = items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function)
                if function.sig.ident == "wire"
                    && crate::localtx_coverage::attrs_may_be_production(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [wire] = wires.as_slice() else {
        return SettingsCompositionCertification::invalid(
            "exactly one production-reachable wire function",
            format!("found {} production-reachable wire functions", wires.len()),
        );
    };
    if !matches!(wire.vis, syn::Visibility::Public(_))
        || wire.sig.asyncness.is_none()
        || wire.sig.unsafety.is_some()
        || !wire.sig.generics.params.is_empty()
        || wire.sig.generics.where_clause.is_some()
        || wire.sig.inputs.len() != 1
        || !matches!(wire.sig.inputs.first(), Some(syn::FnArg::Typed(argument))
            if matches!(&*argument.pat, syn::Pat::Ident(ident)
                if ident.ident == "deps"
                    && ident.by_ref.is_none()
                    && ident.mutability.is_none()
                    && ident.subpat.is_none()))
        || !settings_wire_destructures_pg(&wire.block)
        || local_binding_count(&wire.block, "pg") != 0
        || block_reassigns_any(&wire.block, &["pg"])
    {
        return SettingsCompositionCertification::invalid(
            "pub async wire(deps) with one direct SettingsModuleDeps { pg, .. } destructure",
            "wire signature or production pg capability source is noncanonical",
        );
    }
    let Some(bundle) = unique_tuple_binding_initializer(
        &wire.block,
        &["configs", "writer", "secrets", "secret_writer"],
    ) else {
        return SettingsCompositionCertification::invalid(
            "one settings_bundle(...).into_parts() tuple binding for configs/writer/secrets/secret_writer",
            "canonical provider tuple binding is missing or ambiguous",
        );
    };
    let Expr::MethodCall(into_parts) = peel_expr(bundle) else {
        return SettingsCompositionCertification::invalid(
            "pg.settings_bundle(...).into_parts()",
            "provider tuple initializer is not a method call",
        );
    };
    let Expr::MethodCall(settings_bundle) = peel_expr(&into_parts.receiver) else {
        return SettingsCompositionCertification::invalid(
            "pg.settings_bundle(...).into_parts()",
            "into_parts receiver is not settings_bundle",
        );
    };
    if into_parts.method != "into_parts"
        || !into_parts.args.is_empty()
        || into_parts.turbofish.is_some()
        || settings_bundle.method != "settings_bundle"
        || settings_bundle.args.len() != 2
        || settings_bundle.turbofish.is_some()
        || simple_ident(&settings_bundle.receiver).as_deref() != Some("pg")
    {
        return SettingsCompositionCertification::invalid(
            "direct pg.settings_bundle(arg, arg).into_parts() provider source",
            "provider tuple uses a different source, method, or argument shape",
        );
    }

    let Some(service) = unique_direct_initializer(&wire.block, "config_svc") else {
        return SettingsCompositionCertification::invalid(
            "one direct config_svc binding",
            "config_svc binding is missing or ambiguous",
        );
    };
    let Expr::Call(service_call) = peel_expr(service) else {
        return SettingsCompositionCertification::invalid(
            "SettingsService::with_postgres(configs, writer, empty_flag_store(), clock)",
            "config_svc initializer is not a direct call",
        );
    };
    let canonical_flags = service_call.args.get(2).is_some_and(|flags| {
        matches!(peel_expr(flags), Expr::Call(call) if relative_call_path_is(&call.func, &["empty_flag_store"]) && call.args.is_empty())
    });
    if !relative_call_path_is(&service_call.func, &["SettingsService", "with_postgres"])
        || service_call.args.len() != 4
        || service_call.args.first().and_then(simple_ident).as_deref() != Some("configs")
        || service_call.args.get(1).and_then(simple_ident).as_deref() != Some("writer")
        || !canonical_flags
    {
        return SettingsCompositionCertification::invalid(
            "SettingsService::with_postgres(configs, writer, empty_flag_store(), clock)",
            "production service constructor or provider arguments drifted",
        );
    }

    let Some(domain) = unique_direct_initializer(&wire.block, "domain") else {
        return SettingsCompositionCertification::invalid(
            "one direct SettingsDomain binding",
            "domain binding is missing or ambiguous",
        );
    };
    let Expr::Call(domain_call) = peel_expr(domain) else {
        return SettingsCompositionCertification::invalid(
            "SettingsDomain::new(Arc::new(config_svc), secret_repo, secret_uow, secret_svc)",
            "domain initializer is not a direct call",
        );
    };
    let service_is_wrapped_once = domain_call.args.first().is_some_and(|argument| {
        matches!(peel_expr(argument), Expr::Call(call)
            if relative_call_path_is(&call.func, &["Arc", "new"])
                && call.args.len() == 1
                && call.args.first().and_then(simple_ident).as_deref() == Some("config_svc"))
    });
    if !relative_call_path_is(&domain_call.func, &["SettingsDomain", "new"])
        || domain_call.args.len() != 4
        || !service_is_wrapped_once
        || domain_call.args.get(1).and_then(simple_ident).as_deref() != Some("secret_repo")
        || domain_call.args.get(2).and_then(simple_ident).as_deref() != Some("secret_uow")
        || domain_call.args.get(3).and_then(simple_ident).as_deref() != Some("secret_svc")
        || block_has_mutable_binding(
            &wire.block,
            &["configs", "writer", "config_svc", "secret_svc", "domain"],
        )
        || block_reassigns_any(
            &wire.block,
            &["configs", "writer", "config_svc", "secret_svc", "domain"],
        )
    {
        return SettingsCompositionCertification::invalid(
            "immutable bundle ports → with_postgres → SettingsDomain::new lineage",
            "production Domain construction is wrapped, mutable, reassigned, or uses different bindings",
        );
    }
    SettingsCompositionCertification::Valid
}

fn settings_wire_destructures_pg(block: &syn::Block) -> bool {
    let matching = block.stmts.iter().filter(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        let syn::Pat::Struct(pattern) = &local.pat else {
            return false;
        };
        pattern.path.is_ident("SettingsModuleDeps")
            && local
                .init
                .as_ref()
                .and_then(|init| simple_ident(&init.expr))
                .as_deref()
                == Some("deps")
            && pattern.fields.iter().any(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == "pg")
                    && matches!(&*field.pat, syn::Pat::Ident(ident)
                        if ident.ident == "pg"
                            && ident.by_ref.is_none()
                            && ident.mutability.is_none()
                            && ident.subpat.is_none())
            })
    });
    matching.count() == 1
}

fn unique_tuple_binding_initializer<'a>(
    block: &'a syn::Block,
    expected: &[&str],
) -> Option<&'a Expr> {
    let mut matching = block.stmts.iter().filter_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        let syn::Pat::Tuple(tuple) = &local.pat else {
            return None;
        };
        let names = tuple
            .elems
            .iter()
            .map(|pattern| match pattern {
                syn::Pat::Ident(ident)
                    if ident.by_ref.is_none()
                        && ident.mutability.is_none()
                        && ident.subpat.is_none() =>
                {
                    Some(ident.ident.to_string())
                }
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        (names
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied()))
        .then(|| local.init.as_ref().map(|init| &*init.expr))
        .flatten()
    });
    let only = matching.next()?;
    matching.next().is_none().then_some(only)
}

fn verified_router_factories(
    items: &[Item],
    settings_composition: SettingsCompositionCertification,
) -> VerifiedRouterFactories {
    fn collect(
        items: &[Item],
        module_path: &mut Vec<String>,
        module_cfg_valid: bool,
        declarations: &mut BTreeMap<(Vec<String>, String), usize>,
        verified: &mut BTreeMap<(Vec<String>, String), VerifiedRouterFactory>,
        domain_certificates: &BTreeMap<String, DomainProviderCertificate>,
        settings_certificate: Option<SettingsProviderCertificate>,
    ) {
        for item in items {
            match item {
                Item::Fn(function) => {
                    let key = (module_path.clone(), function.sig.ident.to_string());
                    *declarations.entry(key.clone()).or_default() += 1;
                    if module_cfg_valid
                        && factory_attrs_are_canonical(&function.attrs)
                        && let Some(certificate) = verify_router_factory(
                            function,
                            domain_certificates,
                            settings_certificate,
                        )
                    {
                        verified.insert(key, certificate);
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        module_path.push(module.ident.to_string());
                        collect(
                            nested,
                            module_path,
                            module_cfg_valid && module_cfg_is_canonical(&module.attrs),
                            declarations,
                            verified,
                            domain_certificates,
                            settings_certificate,
                        );
                        module_path.pop();
                    }
                }
                _ => {}
            }
        }
    }

    let mut declarations = BTreeMap::new();
    let mut verified = BTreeMap::new();
    let domain_certificates = collect_domain_provider_certificates(items);
    let settings_provider = collect_settings_provider_certificate(items);
    let settings_certificate = match (&settings_provider, &settings_composition) {
        (
            SettingsProviderCertification::Valid(certificate),
            SettingsCompositionCertification::Valid,
        ) => Some(*certificate),
        _ => None,
    };
    collect(
        items,
        &mut Vec::new(),
        true,
        &mut declarations,
        &mut verified,
        &domain_certificates,
        settings_certificate,
    );
    verified.retain(|key, _| declarations.get(key) == Some(&1));
    VerifiedRouterFactories {
        entries: verified,
        settings_provider,
        settings_composition,
    }
}

fn module_cfg_is_canonical(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|attribute| {
        if path_is(attribute.path(), &["cfg"]) {
            attribute.meta.require_list().is_ok_and(|list| {
                syn::parse2::<syn::Path>(list.tokens.clone())
                    .is_ok_and(|path| path_is(&path, &["test"]))
            })
        } else {
            !path_is(attribute.path(), &["cfg_attr"]) && !path_is(attribute.path(), &["ignore"])
        }
    })
}

fn factory_attrs_are_canonical(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().all(|attribute| {
        path_is(attribute.path(), &["allow"])
            && attribute.meta.require_list().is_ok_and(|list| {
                matches!(
                    list.tokens.to_string().as_str(),
                    "clippy :: expect_used" | "clippy :: too_many_arguments"
                )
            })
    })
}

fn verify_router_factory(
    function: &syn::ItemFn,
    domain_certificates: &BTreeMap<String, DomainProviderCertificate>,
    settings_certificate: Option<SettingsProviderCertificate>,
) -> Option<VerifiedRouterFactory> {
    if function.sig.asyncness.is_some()
        || function.sig.unsafety.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
        || block_contains_return(&function.block)
    {
        return None;
    }
    let route_module_from_type = mounted_proof_return_module(&function.sig.output)?;
    let parameters = function
        .sig
        .inputs
        .iter()
        .map(|argument| match argument {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                syn::Pat::Ident(ident)
                    if ident.by_ref.is_none()
                        && ident.mutability.is_none()
                        && ident.subpat.is_none() =>
                {
                    Some(ident.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Option<Vec<_>>>()?;
    let (tail_router, tail_proof) = factory_tail_tuple(&function.block)?;
    let proof_initializer = unique_direct_initializer(&function.block, &tail_proof)?;
    let (proof_routes, proof_module, proof_state) = mounted_route_proof(proof_initializer)?;
    if proof_module != route_module_from_type {
        return None;
    }
    let router_initializer = unique_direct_initializer(&function.block, &tail_router)?;
    let finalizer_routes = finalized_router_routes(router_initializer)?;
    if proof_routes != finalizer_routes {
        return None;
    }
    let lineage = registry_lineage(&function.block, &proof_routes)?;
    let mut immutable_lineage = vec![
        tail_router.as_str(),
        tail_proof.as_str(),
        proof_routes.as_str(),
        lineage.finalized.as_str(),
        lineage.domain.as_str(),
    ];
    if lineage.framework_registration {
        if mutable_reference_count(&function.block, &lineage.registry) != 1 {
            return None;
        }
    } else {
        immutable_lineage.push(lineage.registry.as_str());
    }
    if block_reassigns_any(&function.block, &immutable_lineage) {
        return None;
    }
    if block_has_mutable_binding(
        &function.block,
        &[&tail_router, &tail_proof, &proof_routes, &finalizer_routes],
    ) {
        return None;
    }
    let mut constructor_parameters = mounted_constructor_parameters(
        &function.block,
        &parameters,
        &lineage.domain,
        proof_state.as_deref(),
        domain_certificates,
    );
    let mut constructor_repo_fields =
        mounted_constructor_repo_fields(&function.block, &parameters, &lineage.domain);
    let settings_lineage = settings_factory_lineage(
        &function.block,
        &parameters,
        &lineage.domain,
        proof_state.as_deref(),
        settings_certificate,
    );
    if proof_state.as_deref() == Some("ConfigQueryService") && settings_lineage.is_none() {
        return None;
    }
    if let Some((provider, field)) = settings_lineage {
        constructor_parameters.insert(provider.clone());
        constructor_repo_fields
            .entry(provider)
            .or_default()
            .insert(field);
    }
    Some(VerifiedRouterFactory {
        route_module: proof_module,
        constructor_parameters,
        constructor_repo_fields,
        parameters,
    })
}

fn mutable_reference_count(block: &syn::Block, binding: &str) -> usize {
    struct Counter<'a> {
        binding: &'a str,
        count: usize,
    }
    impl<'ast> Visit<'ast> for Counter<'_> {
        fn visit_expr_reference(&mut self, reference: &'ast syn::ExprReference) {
            if reference.mutability.is_some()
                && simple_ident(&reference.expr).as_deref() == Some(self.binding)
            {
                self.count += 1;
            }
            visit::visit_expr_reference(self, reference);
        }
    }
    let mut counter = Counter { binding, count: 0 };
    counter.visit_block(block);
    counter.count
}

fn settings_factory_lineage(
    block: &syn::Block,
    parameters: &[String],
    composed_domain: &str,
    proof_state: Option<&str>,
    certificate: Option<SettingsProviderCertificate>,
) -> Option<(String, String)> {
    certificate?;
    if proof_state != Some("ConfigQueryService") {
        return None;
    }
    let domain_initializer = unique_direct_initializer(block, composed_domain)?;
    let Expr::Call(domain_constructor) = peel_expr(domain_initializer) else {
        return None;
    };
    if !relative_call_path_is(
        &domain_constructor.func,
        &["super", "SettingsDomain", "new"],
    ) {
        return None;
    }
    let service = domain_constructor.args.first().and_then(simple_ident)?;
    let service_initializer = unique_direct_initializer(block, &service)?;
    let Expr::Call(arc_new) = peel_expr(service_initializer) else {
        return None;
    };
    if !relative_call_path_is(&arc_new.func, &["Arc", "new"]) || arc_new.args.len() != 1 {
        return None;
    }
    let Expr::Call(service_new) = arc_new.args.first().map(peel_expr)? else {
        return None;
    };
    if !relative_call_path_is(
        &service_new.func,
        &["super", "SettingsService", "with_postgres"],
    ) || service_new.args.len() != 4
    {
        return None;
    }
    let (provider, field) = service_new.args.first().and_then(direct_provider_field)?;
    if field != "configs"
        || !parameters.contains(&provider)
        || block_has_mutable_binding(block, &[&provider, &service])
        || block_reassigns_any(block, &[&provider, &service])
    {
        return None;
    }
    Some((provider, field))
}

fn mounted_proof_return_module(output: &syn::ReturnType) -> Option<Vec<String>> {
    let syn::ReturnType::Type(_, output) = output else {
        return None;
    };
    let Type::Tuple(tuple) = &**output else {
        return None;
    };
    if tuple.elems.len() != 2 || !is_axum_router_type(&tuple.elems[0]) {
        return None;
    }
    let Type::Path(proof) = &tuple.elems[1] else {
        return None;
    };
    let path = &proof.path;
    if path.leading_colon.is_none()
        || path.segments.len() != 2
        || path.segments[0].ident != "httpserve"
    {
        return None;
    }
    let proof_segment = &path.segments[1];
    let PathArguments::AngleBracketed(arguments) = &proof_segment.arguments else {
        return None;
    };
    let expected_arguments = match proof_segment.ident.to_string().as_str() {
        "LocalOnlyMountedRouteProof" => 2,
        "StatelessLocalOnlyMountedRouteProof" => 1,
        _ => return None,
    };
    if arguments.args.len() != expected_arguments {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    generated_terminal_module(&marker.path, "RouteMarker")
}

fn is_axum_router_type(ty: &Type) -> bool {
    let Type::Path(router) = ty else {
        return false;
    };
    let path = &router.path;
    path.leading_colon.is_none()
        && path.segments.len() == 2
        && path.segments[0].ident == "axum"
        && path.segments[1].ident == "Router"
        && path
            .segments
            .iter()
            .all(|segment| matches!(segment.arguments, PathArguments::None))
}

fn factory_tail_tuple(block: &syn::Block) -> Option<(String, String)> {
    let Expr::Tuple(tuple) = peel_expr(block.stmts.last().and_then(tail_expression)?) else {
        return None;
    };
    if tuple.elems.len() != 2 {
        return None;
    }
    Some((
        simple_ident(&tuple.elems[0])?,
        simple_ident(&tuple.elems[1])?,
    ))
}

fn mounted_route_proof(expression: &Expr) -> Option<(String, Vec<String>, Option<String>)> {
    let Expr::MethodCall(expect) = peel_expr(expression) else {
        return None;
    };
    if expect.method != "expect" || expect.args.len() != 1 || expect.turbofish.is_some() {
        return None;
    }
    let Expr::Call(call) = peel_expr(&expect.receiver) else {
        return None;
    };
    let state = match current_mounted_proof_kind(call)? {
        MountedProofKind::Stateful(state) => Some(state),
        MountedProofKind::Stateless => None,
    };
    let routes = referenced_ident(call.args.first()?)?;
    let module = generated_route_reference_module(call.args.iter().nth(1)?)?;
    Some((routes, module, state))
}

enum MountedProofKind {
    Stateful(String),
    Stateless,
}

fn current_mounted_proof_kind(call: &syn::ExprCall) -> Option<MountedProofKind> {
    if call.args.len() != 2 {
        return None;
    }
    let Expr::Path(function) = peel_expr(&call.func) else {
        return None;
    };
    let path = &function.path;
    if path.leading_colon.is_none()
        || path.segments.len() != 2
        || path.segments[0].ident != "httpserve"
    {
        return None;
    }
    let function = &path.segments[1];
    match function.ident.to_string().as_str() {
        "prove_local_only_mounted_route_state" => {
            let PathArguments::AngleBracketed(arguments) = &function.arguments else {
                return None;
            };
            if arguments.args.len() != 2
                || !matches!(
                    arguments.args.iter().nth(1),
                    Some(GenericArgument::Type(Type::Infer(_)))
                )
            {
                return None;
            }
            let Some(GenericArgument::Type(Type::Path(state))) = arguments.args.first() else {
                return None;
            };
            Some(MountedProofKind::Stateful(
                state.path.segments.last()?.ident.to_string(),
            ))
        }
        "prove_stateless_local_only_mounted_route"
            if matches!(function.arguments, PathArguments::None) =>
        {
            Some(MountedProofKind::Stateless)
        }
        _ => None,
    }
}

fn finalized_router_routes(expression: &Expr) -> Option<String> {
    let mut expression = peel_expr(expression);
    loop {
        match expression {
            Expr::MethodCall(call)
                if matches!(
                    call.method.to_string().as_str(),
                    "into_router_for_test" | "layer"
                ) =>
            {
                if call.turbofish.is_some()
                    || (call.method == "into_router_for_test" && !call.args.is_empty())
                    || (call.method == "layer" && !is_transparent_extension_layer(call))
                {
                    return None;
                }
                expression = peel_expr(&call.receiver);
            }
            Expr::MethodCall(call)
                if call.method == "expect" && call.args.len() == 1 && call.turbofish.is_none() =>
            {
                let Expr::Call(finalizer) = peel_expr(&call.receiver) else {
                    return None;
                };
                const FINALIZERS: &[&[&str]] = &[
                    &["httpserve", "finalize_auth"],
                    &["httpserve", "finalize_auth_with_audit"],
                    &["httpserve", "finalize_auth_with_audit_and_authorizer"],
                    &["httpserve", "finalize_primary_auth"],
                    &["httpserve", "finalize_primary_auth_with_audit"],
                ];
                if !FINALIZERS
                    .iter()
                    .any(|expected| absolute_call_path_is(&finalizer.func, expected))
                {
                    return None;
                }
                return simple_ident(finalizer.args.first()?);
            }
            _ => return None,
        }
    }
}

fn is_transparent_extension_layer(call: &syn::ExprMethodCall) -> bool {
    if call.args.len() != 1 {
        return false;
    }
    let Some(Expr::Call(extension)) = call.args.first().map(peel_expr) else {
        return false;
    };
    absolute_call_path_is(&extension.func, &["axum", "Extension"]) && extension.args.len() == 1
}

struct RegistryLineage {
    domain: String,
    registry: String,
    finalized: String,
    framework_registration: bool,
}

fn registry_lineage(block: &syn::Block, routes: &str) -> Option<RegistryLineage> {
    let mut route_source = None;
    let mut route_bindings = 0usize;
    for statement in &block.stmts {
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let binds_routes = match &local.pat {
            syn::Pat::Ident(pattern) => pattern.ident == routes,
            syn::Pat::Tuple(tuple) => tuple.elems.iter().any(
                |pattern| matches!(pattern, syn::Pat::Ident(pattern) if pattern.ident == routes),
            ),
            _ => false,
        };
        if !binds_routes {
            continue;
        }
        route_bindings += 1;
        let Some(initializer) = &local.init else {
            return None;
        };
        route_source = root_receiver_ident(&initializer.expr);
    }
    if route_bindings != 1 {
        return None;
    }
    let finalized = route_source?;
    let finalized_initializer = unique_direct_initializer(block, &finalized)?;
    let Expr::MethodCall(expect) = peel_expr(finalized_initializer) else {
        return None;
    };
    if expect.method != "expect" || expect.args.len() != 1 || expect.turbofish.is_some() {
        return None;
    }
    let Expr::MethodCall(finalize) = peel_expr(&expect.receiver) else {
        return None;
    };
    if finalize.method != "finalize_routes"
        || !finalize.args.is_empty()
        || finalize.turbofish.is_some()
    {
        return None;
    }
    let registry = simple_ident(&finalize.receiver)?;
    let registry_initializer = unique_direct_initializer(block, &registry)?;
    if matches!(peel_expr(registry_initializer), Expr::Call(new)
        if relative_call_path_is(&new.func, &["bootstrap", "Registry", "new"])
            && new.args.is_empty())
    {
        let framework = framework_routes_registered_into(block, &registry)?;
        unique_direct_initializer(block, &framework)?;
        return Some(RegistryLineage {
            domain: framework,
            registry,
            finalized,
            framework_registration: true,
        });
    }
    let Expr::MethodCall(expect) = peel_expr(registry_initializer) else {
        return None;
    };
    if expect.method != "expect" || expect.args.len() != 1 || expect.turbofish.is_some() {
        return None;
    }
    let Expr::Call(compose) = peel_expr(&expect.receiver) else {
        return None;
    };
    if !relative_call_path_is(&compose.func, &["bootstrap", "compose"]) || compose.args.len() != 1 {
        return None;
    }
    let Expr::Reference(reference) = compose.args.first()? else {
        return None;
    };
    if reference.mutability.is_some() {
        return None;
    }
    let Expr::Array(domains) = peel_expr(&reference.expr) else {
        return None;
    };
    if domains.elems.len() != 1 {
        return None;
    }
    let domain = referenced_ident(domains.elems.first()?)?;
    unique_direct_initializer(block, &domain)?;
    Some(RegistryLineage {
        domain,
        registry,
        finalized,
        framework_registration: false,
    })
}

fn framework_routes_registered_into(block: &syn::Block, registry: &str) -> Option<String> {
    let mut matches = block.stmts.iter().filter_map(|statement| {
        let syn::Stmt::Expr(expression, _) = statement else {
            return None;
        };
        let Expr::MethodCall(expect) = peel_expr(expression) else {
            return None;
        };
        if expect.method != "expect" || expect.args.len() != 1 || expect.turbofish.is_some() {
            return None;
        }
        let Expr::Call(register) = peel_expr(&expect.receiver) else {
            return None;
        };
        let Expr::Path(function) = peel_expr(&register.func) else {
            return None;
        };
        let segments = function
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if function.path.leading_colon.is_some()
            || segments != ["crate", "modules_gen", "register_framework_routes"]
            || register.args.len() != 2
        {
            return None;
        }
        let framework = referenced_ident(register.args.first()?)?;
        let Expr::Reference(registry_ref) = register.args.iter().nth(1)? else {
            return None;
        };
        (registry_ref.mutability.is_some()
            && simple_ident(&registry_ref.expr).as_deref() == Some(registry))
        .then_some(framework)
    });
    let only = matches.next()?;
    matches.next().is_none().then_some(only)
}

fn mounted_constructor_parameters(
    block: &syn::Block,
    parameters: &[String],
    composed_domain: &str,
    proof_state: Option<&str>,
    domain_certificates: &BTreeMap<String, DomainProviderCertificate>,
) -> BTreeSet<String> {
    let mut constructed_domains = BTreeMap::<String, BTreeSet<String>>::new();
    for statement in &block.stmts {
        let syn::Stmt::Local(local) = statement else {
            continue;
        };
        let syn::Pat::Ident(binding) = &local.pat else {
            continue;
        };
        let Some(initializer) = &local.init else {
            continue;
        };
        let Expr::Call(call) = peel_expr(&initializer.expr) else {
            continue;
        };
        let Expr::Path(function) = peel_expr(&call.func) else {
            continue;
        };
        let segments = function.path.segments.iter().collect::<Vec<_>>();
        if segments.len() < 2
            || segments.last().is_none_or(|segment| segment.ident != "new")
            || segments.get(segments.len() - 2).is_none_or(|segment| {
                let owner = segment.ident.to_string();
                !owner.ends_with("Domain") && !owner.ends_with("State")
            })
        {
            continue;
        }
        let domain_type = segments[segments.len() - 2].ident.to_string();
        if domain_type == "IdentityDomain"
            && !canonical_identity_domain_constructor_path(&function.path)
        {
            continue;
        }
        let mut referenced = BTreeSet::new();
        for parameter in parameters {
            for (index, argument) in call.args.iter().enumerate() {
                if !expression_references_ident(argument, parameter) {
                    continue;
                }
                let closes_state = proof_state.is_none_or(|state| {
                    domain_certificates
                        .get(&domain_type)
                        .is_some_and(|certificate| {
                            certificate.direct_parameter_closes_state(index, state)
                                || certificate.aggregate_parameter_closes_state(
                                    index, argument, parameter, state,
                                )
                        })
                });
                if closes_state {
                    referenced.insert(parameter.clone());
                }
            }
        }
        constructed_domains.insert(binding.ident.to_string(), referenced);
    }
    constructed_domains
        .remove(composed_domain)
        .unwrap_or_default()
}

fn mounted_constructor_repo_fields(
    block: &syn::Block,
    parameters: &[String],
    composed_domain: &str,
) -> BTreeMap<String, BTreeSet<String>> {
    let Some(initializer) = unique_direct_initializer(block, composed_domain) else {
        return BTreeMap::new();
    };
    let Expr::Call(constructor) = peel_expr(initializer) else {
        return BTreeMap::new();
    };
    let mut fields = BTreeMap::<String, BTreeSet<String>>::new();
    for argument in &constructor.args {
        if let Some((provider, member)) = direct_provider_field(argument)
            && parameters.contains(&provider)
        {
            fields.entry(provider).or_default().insert(member);
            continue;
        }
        let Expr::Struct(aggregate) = peel_expr(argument) else {
            continue;
        };
        if aggregate.rest.is_some() || !canonical_identity_deps_path(&aggregate.path) {
            continue;
        }
        for field in &aggregate.fields {
            let syn::Member::Named(aggregate_field) = &field.member else {
                continue;
            };
            let Some((provider, repo_field)) = direct_provider_field(&field.expr) else {
                continue;
            };
            if parameters.contains(&provider) && *aggregate_field == repo_field {
                fields.entry(provider).or_default().insert(repo_field);
            }
        }
    }
    fields
}

fn direct_provider_field(expression: &Expr) -> Option<(String, String)> {
    let Expr::Field(field) = peel_expr(expression) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    Some((simple_ident(&field.base)?, member.to_string()))
}

fn expression_references_ident(expression: &Expr, expected: &str) -> bool {
    struct References<'name> {
        expected: &'name str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for References<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            self.found |= node.path.is_ident(self.expected);
            visit::visit_expr_path(self, node);
        }
    }
    let mut references = References {
        expected,
        found: false,
    };
    references.visit_expr(expression);
    references.found
}

fn canonical_test_repo_provider(expression: &Expr) -> Option<String> {
    let Expr::MethodCall(call) = peel_expr(expression) else {
        return None;
    };
    if call.method != "test_repo" || !call.args.is_empty() || call.turbofish.is_some() {
        return None;
    }
    simple_ident(&call.receiver)
}

fn block_reassigns_any(block: &syn::Block, names: &[&str]) -> bool {
    struct Assignments<'name> {
        names: &'name [&'name str],
        found: bool,
    }
    impl<'ast> Visit<'ast> for Assignments<'_> {
        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            if self
                .names
                .iter()
                .any(|name| expression_references_ident(&node.left, name))
            {
                self.found = true;
            }
            visit::visit_expr_assign(self, node);
        }

        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if matches!(
                node.op,
                syn::BinOp::AddAssign(_)
                    | syn::BinOp::SubAssign(_)
                    | syn::BinOp::MulAssign(_)
                    | syn::BinOp::DivAssign(_)
                    | syn::BinOp::RemAssign(_)
                    | syn::BinOp::BitXorAssign(_)
                    | syn::BinOp::BitAndAssign(_)
                    | syn::BinOp::BitOrAssign(_)
                    | syn::BinOp::ShlAssign(_)
                    | syn::BinOp::ShrAssign(_)
            ) && self
                .names
                .iter()
                .any(|name| expression_references_ident(&node.left, name))
            {
                self.found = true;
            }
            visit::visit_expr_binary(self, node);
        }

        fn visit_expr_reference(&mut self, node: &'ast syn::ExprReference) {
            if node.mutability.is_some()
                && self
                    .names
                    .iter()
                    .any(|name| expression_references_ident(&node.expr, name))
            {
                self.found = true;
            }
            visit::visit_expr_reference(self, node);
        }
    }
    let mut assignments = Assignments {
        names,
        found: false,
    };
    assignments.visit_block(block);
    assignments.found
}

fn block_has_mutable_binding(block: &syn::Block, names: &[&str]) -> bool {
    struct MutableBindings<'name> {
        names: &'name [&'name str],
        found: bool,
    }
    impl<'ast> Visit<'ast> for MutableBindings<'_> {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            if node.mutability.is_some() && self.names.iter().any(|name| node.ident == *name) {
                self.found = true;
            }
            visit::visit_pat_ident(self, node);
        }
    }
    let mut bindings = MutableBindings {
        names,
        found: false,
    };
    bindings.visit_block(block);
    bindings.found
}

fn block_contains_return(block: &syn::Block) -> bool {
    struct Returns(bool);
    impl<'ast> Visit<'ast> for Returns {
        fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
            self.0 = true;
        }
    }
    let mut returns = Returns(false);
    returns.visit_block(block);
    returns.0
}

fn tail_expression(statement: &syn::Stmt) -> Option<&Expr> {
    match statement {
        syn::Stmt::Expr(expression, None) => Some(expression),
        _ => None,
    }
}

#[derive(Default)]
struct CertificateApiCounts {
    receipt_calls: usize,
    observer_initializers: usize,
    testkit_calls: usize,
    route_proofs: usize,
    static_exclusions: usize,
    runtime_handles: usize,
}

impl<'ast> Visit<'ast> for CertificateApiCounts {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_receipt_assertion_call(node) {
            self.receipt_calls += 1;
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "LocalOnlyObservers", "new"],
        ) {
            self.observer_initializers += 1;
        }
        if absolute_call_path_is(&node.func, &["testkit", "call"]) {
            self.testkit_calls += 1;
        }
        if is_current_mounted_proof_call(node) {
            self.route_proofs += 1;
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "StaticExclusion", "from_governed"],
        ) {
            self.static_exclusions += 1;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "handle"
            && canonical_provider_handle(&Expr::MethodCall(node.clone())).is_some()
        {
            self.runtime_handles += 1;
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn certificate_api_counts(block: &syn::Block) -> CertificateApiCounts {
    let mut counts = CertificateApiCounts::default();
    counts.visit_block(block);
    counts
}

fn use_tree_contains_receipt_api(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            is_receipt_api_ident(&path.ident) || use_tree_contains_receipt_api(&path.tree)
        }
        syn::UseTree::Name(name) => is_receipt_api_ident(&name.ident),
        syn::UseTree::Rename(rename) => {
            is_receipt_api_ident(&rename.ident) || is_receipt_api_ident(&rename.rename)
        }
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_contains_receipt_api),
        syn::UseTree::Glob(_) => false,
    }
}

fn type_contains_receipt_api(ty: &Type) -> bool {
    struct ReceiptType(bool);
    impl<'ast> Visit<'ast> for ReceiptType {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            if node
                .path
                .segments
                .iter()
                .any(|segment| is_receipt_api_ident(&segment.ident))
            {
                self.0 = true;
            }
            visit::visit_type_path(self, node);
        }
    }
    let mut found = ReceiptType(false);
    found.visit_type(ty);
    found.0
}

fn is_receipt_api_ident(ident: &syn::Ident) -> bool {
    matches!(
        ident.to_string().as_str(),
        "assert_local_only_with_receipt"
            | "LocalOnlyConformanceReceipt"
            | "LocalOnlyConformanceMarker"
    )
}

fn collect_canonical_test_repo_fields(
    items: &[Item],
) -> BTreeMap<(Vec<String>, String), BTreeSet<String>> {
    fn collect(
        items: &[Item],
        module_path: &mut Vec<String>,
        module_cfg_valid: bool,
        out: &mut BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    ) {
        for item in items {
            match item {
                Item::Impl(item)
                    if module_cfg_valid
                        && item.trait_.is_none()
                        && factory_attrs_are_canonical(&item.attrs) =>
                {
                    let Some(owner) = terminal_type_ident(&item.self_ty) else {
                        continue;
                    };
                    if item.items.iter().any(|child| {
                        matches!(child, ImplItem::Fn(function) if canonical_test_repo_method(function))
                    }) && let Some(fields) = canonical_from_provider_fields(items, &owner)
                    {
                        out.insert((module_path.clone(), owner), fields);
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        module_path.push(module.ident.to_string());
                        collect(
                            nested,
                            module_path,
                            module_cfg_valid && module_cfg_is_canonical(&module.attrs),
                            out,
                        );
                        module_path.pop();
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = BTreeMap::new();
    collect(items, &mut Vec::new(), true, &mut out);
    out
}

fn canonical_from_provider_fields(items: &[Item], owner: &str) -> Option<BTreeSet<String>> {
    let repo_type = "TestRepo";
    let item = items.iter().find_map(|item| match item {
        Item::Impl(item)
            if item.trait_.is_none()
                && outer_type_ident(&item.self_ty).as_deref() == Some(repo_type) =>
        {
            Some(item)
        }
        _ => None,
    })?;
    let function = item.items.iter().find_map(|child| match child {
        ImplItem::Fn(function) if function.sig.ident == "from_provider" => Some(function),
        _ => None,
    })?;
    let provider = function.sig.inputs.iter().find_map(|input| match input {
        syn::FnArg::Typed(argument) => match &*argument.pat {
            syn::Pat::Ident(pattern) => Some(pattern.ident.to_string()),
            _ => None,
        },
        syn::FnArg::Receiver(_) => None,
    })?;
    if function.block.stmts.len() != 1 {
        return None;
    }
    let Expr::Struct(returned) = function
        .block
        .stmts
        .last()
        .and_then(tail_expression)
        .map(peel_expr)?
    else {
        return None;
    };
    if !returned.path.is_ident("Self") || returned.rest.is_some() {
        return None;
    }
    let fields = returned
        .fields
        .iter()
        .filter_map(|field| {
            let syn::Member::Named(member) = &field.member else {
                return None;
            };
            let member = member.to_string();
            let certified = if member == "configs" {
                settings_config_provider_lineage(&field.expr, &provider)
            } else {
                direct_provider_lineage(&field.expr, &provider)
            };
            certified.then_some(member)
        })
        .collect::<BTreeSet<_>>();
    (!fields.is_empty() && owner != repo_type).then_some(fields)
}

fn settings_config_provider_lineage(expression: &Expr, provider: &str) -> bool {
    let Expr::Call(new_box) = peel_expr(expression) else {
        return false;
    };
    if !relative_call_path_is(&new_box.func, &["DynConfigRepo", "new_box"])
        || new_box.args.len() != 1
    {
        return false;
    }
    let Some(Expr::MethodCall(clone)) = new_box.args.first().map(peel_expr) else {
        return false;
    };
    if clone.method != "clone" || !clone.args.is_empty() || clone.turbofish.is_some() {
        return false;
    }
    let Expr::MethodCall(as_ref) = peel_expr(&clone.receiver) else {
        return false;
    };
    as_ref.method == "as_ref"
        && as_ref.args.is_empty()
        && as_ref.turbofish.is_none()
        && matches!(peel_expr(&as_ref.receiver), Expr::Path(path) if path.path.is_ident(provider))
}

fn direct_provider_lineage(expression: &Expr, provider: &str) -> bool {
    match expression {
        Expr::Path(path) => path.path.is_ident(provider),
        Expr::Reference(reference) => {
            reference.mutability.is_none() && direct_provider_lineage(&reference.expr, provider)
        }
        Expr::Paren(parenthesized) => direct_provider_lineage(&parenthesized.expr, provider),
        Expr::Group(grouped) => direct_provider_lineage(&grouped.expr, provider),
        Expr::Field(field) => direct_provider_lineage(&field.base, provider),
        Expr::Call(call) => {
            call.args.len() == 1
                && canonical_provider_wrapper(&call.func)
                && call
                    .args
                    .first()
                    .is_some_and(|argument| direct_provider_lineage(argument, provider))
        }
        Expr::MethodCall(call) => {
            matches!(call.method.to_string().as_str(), "as_ref" | "clone")
                && call.args.is_empty()
                && call.turbofish.is_none()
                && direct_provider_lineage(&call.receiver, provider)
        }
        _ => false,
    }
}

fn canonical_provider_wrapper(function: &Expr) -> bool {
    let Expr::Path(path) = peel_expr(function) else {
        return false;
    };
    path.path.segments.last().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "consume" | "clone" | "from" | "new_box"
        ) && matches!(segment.arguments, PathArguments::None)
    })
}

fn canonical_test_repo_method(function: &syn::ImplItemFn) -> bool {
    if function.sig.ident != "test_repo"
        || function.sig.asyncness.is_some()
        || function.sig.unsafety.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.inputs.len() != 1
        || !matches!(function.sig.inputs.first(), Some(syn::FnArg::Receiver(receiver)) if receiver.reference.is_some() && receiver.mutability.is_none())
        || !matches!(&function.sig.output, syn::ReturnType::Type(_, ty) if matches!(&**ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "TestRepo")))
        || function.block.stmts.len() != 1
    {
        return false;
    }
    let Some(expression) = function.block.stmts.first().and_then(tail_expression) else {
        return false;
    };
    let Expr::Call(from_provider) = peel_expr(expression) else {
        return false;
    };
    if !relative_call_path_is(&from_provider.func, &["TestRepo", "from_provider"])
        || from_provider.args.len() != 1
    {
        return false;
    }
    let Some(Expr::Call(arc_new)) = from_provider.args.first().map(peel_expr) else {
        return false;
    };
    if !relative_call_path_is(&arc_new.func, &["Arc", "new"]) || arc_new.args.len() != 1 {
        return false;
    }
    let Some(Expr::MethodCall(clone)) = arc_new.args.first().map(peel_expr) else {
        return false;
    };
    clone.method == "clone"
        && clone.args.is_empty()
        && clone.turbofish.is_none()
        && matches!(peel_expr(&clone.receiver), Expr::Path(path) if path.path.is_ident("self"))
}

fn collect_scoped_recorded_provider_fields(
    items: &[Item],
) -> BTreeMap<(Vec<String>, String), BTreeSet<String>> {
    fn collect(
        items: &[Item],
        module_path: &mut Vec<String>,
        module_cfg_valid: bool,
        out: &mut BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    ) {
        for item in items {
            match item {
                Item::Impl(item)
                    if module_cfg_valid
                        && item.trait_.is_some()
                        && factory_attrs_are_canonical(&item.attrs) =>
                {
                    if let Some(owner) = terminal_type_ident(&item.self_ty) {
                        let is_settings_config_repo = owner == "SettingsConfigGetRepoProbe"
                            && item.trait_.as_ref().is_some_and(|(_, path, _)| {
                                path.segments
                                    .last()
                                    .is_some_and(|segment| segment.ident == "ConfigRepo")
                            });
                        let fields = if is_settings_config_repo {
                            settings_config_get_recorded_fields(&item.items)
                        } else {
                            directly_recorded_fields(&item.items)
                        };
                        if !fields.is_empty() {
                            out.entry((module_path.clone(), owner))
                                .or_default()
                                .extend(fields);
                        }
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        module_path.push(module.ident.to_string());
                        collect(
                            nested,
                            module_path,
                            module_cfg_valid && module_cfg_is_canonical(&module.attrs),
                            out,
                        );
                        module_path.pop();
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = BTreeMap::new();
    collect(items, &mut Vec::new(), true, &mut out);
    out
}

fn directly_recorded_fields(items: &[ImplItem]) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for item in items {
        let ImplItem::Fn(function) = item else {
            continue;
        };
        let mut may_skip = false;
        for statement in &function.block.stmts {
            if !may_skip {
                if let Some(field) = direct_recorded_field(statement) {
                    fields.insert(field);
                }
                if let Some(field) = canonical_forbidden_write_record(statement) {
                    fields.insert(field);
                }
            }
            may_skip |= statement_may_skip_following_receipt(statement);
        }
    }
    fields
}

fn settings_config_get_recorded_fields(items: &[ImplItem]) -> BTreeSet<String> {
    let field_for = |method: &str, injection: &str| {
        let mut matches = items.iter().filter_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == method => Some(function),
            _ => None,
        });
        let function = matches.next()?;
        if matches.next().is_some() || !settings_synthetic_write_comes_from_state(&function.block) {
            return None;
        }
        let mut field = None;
        let mut may_skip = false;
        for statement in &function.block.stmts {
            if !may_skip
                && let Some(found) = canonical_settings_forbidden_write_record(statement, injection)
                && field.replace(found).is_some()
            {
                return None;
            }
            may_skip |= statement_may_skip_following_receipt(statement);
        }
        field
    };
    let Some(head) = field_for("head", "Head") else {
        return BTreeSet::new();
    };
    let Some(find_version) = field_for("find_version", "FindVersion") else {
        return BTreeSet::new();
    };
    if head == find_version {
        BTreeSet::from([head])
    } else {
        BTreeSet::new()
    }
}

fn settings_synthetic_write_comes_from_state(block: &syn::Block) -> bool {
    block.stmts.iter().any(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return false;
        };
        let syn::Pat::Tuple(tuple) = &local.pat else {
            return false;
        };
        if tuple.elems.get(1).is_none_or(|pattern| {
            !matches!(pattern, syn::Pat::Ident(ident) if ident.ident == "synthetic_write")
        }) {
            return false;
        }
        let Some(initializer) = &local.init else {
            return false;
        };
        let Expr::Block(source) = peel_expr(&initializer.expr) else {
            return false;
        };
        let state_from_provider = source.block.stmts.iter().any(|statement| {
            let syn::Stmt::Local(state) = statement else {
                return false;
            };
            if !matches!(&state.pat, syn::Pat::Ident(ident) if ident.ident == "state") {
                return false;
            }
            state.init.as_ref().is_some_and(|initializer| {
                expression_is_rooted_at_self_field(&initializer.expr, "state")
            })
        });
        let from_state_field = source
            .block
            .stmts
            .last()
            .and_then(tail_expression)
            .map(peel_expr)
            .and_then(|expression| match expression {
                Expr::Tuple(tuple) => tuple.elems.get(1),
                _ => None,
            })
            .is_some_and(|expression| {
                matches!(peel_expr(expression), Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(member) if member == "synthetic_write")
                        && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("state")))
            });
        state_from_provider && from_state_field
    })
}

fn expression_is_rooted_at_self_field(expression: &Expr, expected: &str) -> bool {
    match peel_expr(expression) {
        Expr::Field(field) => {
            matches!(&field.member, syn::Member::Named(member) if member == expected)
                && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
        }
        Expr::MethodCall(call) => expression_is_rooted_at_self_field(&call.receiver, expected),
        Expr::Await(awaited) => expression_is_rooted_at_self_field(&awaited.base, expected),
        Expr::Try(tried) => expression_is_rooted_at_self_field(&tried.expr, expected),
        Expr::Reference(reference) => {
            reference.mutability.is_none()
                && expression_is_rooted_at_self_field(&reference.expr, expected)
        }
        _ => false,
    }
}

fn canonical_settings_forbidden_write_record(
    statement: &syn::Stmt,
    injection: &str,
) -> Option<String> {
    let syn::Stmt::Expr(Expr::If(branch), _) = statement else {
        return None;
    };
    if branch.else_branch.is_some() || branch.then_branch.stmts.len() != 1 {
        return None;
    }
    let Expr::Binary(condition) = peel_expr(&branch.cond) else {
        return None;
    };
    let exact_guard = matches!(condition.op, syn::BinOp::Eq(_))
        && matches!(peel_expr(&condition.left), Expr::Path(path) if path.path.is_ident("synthetic_write"))
        && matches!(peel_expr(&condition.right), Expr::Path(path)
            if path.path.segments.len() == 2
                && path.path.segments[0].ident == "ConfigGetSyntheticWrite"
                && path.path.segments[1].ident == injection);
    exact_guard
        .then(|| branch.then_branch.stmts.first())
        .flatten()
        .and_then(direct_recorded_field)
}

fn direct_recorded_field(statement: &syn::Stmt) -> Option<String> {
    let syn::Stmt::Expr(expression, _) = statement else {
        return None;
    };
    let Expr::MethodCall(record) = peel_expr(expression) else {
        return None;
    };
    if record.method != "record" || !record.args.is_empty() || record.turbofish.is_some() {
        return None;
    }
    let Expr::Field(field) = peel_expr(&record.receiver) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self"))
        .then(|| member.to_string())
}

fn canonical_forbidden_write_record(statement: &syn::Stmt) -> Option<String> {
    let syn::Stmt::Expr(Expr::If(branch), _) = statement else {
        return None;
    };
    if branch.else_branch.is_some() || branch.then_branch.stmts.len() != 1 {
        return None;
    }
    let Expr::Binary(condition) = peel_expr(&branch.cond) else {
        return None;
    };
    if !matches!(condition.op, syn::BinOp::Eq(_)) {
        return None;
    }
    if !canonical_forbidden_write_guard(condition) {
        return None;
    }
    direct_recorded_field(branch.then_branch.stmts.first()?)
}

fn canonical_forbidden_write_guard(condition: &syn::ExprBinary) -> bool {
    matches!(peel_expr(&condition.left), Expr::Field(field)
        if matches!(&field.member, syn::Member::Named(member) if member == "forbidden_write_on")
            && matches!(peel_expr(&field.base), Expr::Path(path) if path.path.is_ident("self")))
        && matches!(peel_expr(&condition.right), Expr::Call(call)
            if relative_call_path_is(&call.func, &["Some"]) && call.args.len() == 1)
}

fn settings_config_get_helper_calls_are_closed(items: &[Item]) -> bool {
    const HELPER: &str = "call_finalized_config_get_local_only";
    let helpers = items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == HELPER => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [helper] = helpers.as_slice() else {
        return false;
    };
    let owners = parameter_type_owners(&helper.sig.inputs);
    if owners.get("router").map(String::as_str) != Some("Router")
        || owners.get("proof").map(String::as_str) != Some("LocalOnlyMountedRouteProof")
        || owners.get("probe").map(String::as_str) != Some("SettingsConfigGetRepoProbe")
        || owners.get("tenant_id").map(String::as_str) != Some("TenantId")
        || owners.len() != 4
    {
        return false;
    }

    struct Calls<'ast> {
        helper: &'static str,
        calls: Vec<&'ast syn::ExprCall>,
    }
    impl<'ast> Visit<'ast> for Calls<'ast> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if matches!(peel_expr(&node.func), Expr::Path(path)
                if path.path.leading_colon.is_none()
                    && path.path.segments.len() == 1
                    && path.path.segments[0].ident == self.helper)
            {
                self.calls.push(node);
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut count = 0;
    for function in items.iter().filter_map(|item| match item {
        Item::Fn(function) if function.sig.ident != HELPER => Some(function),
        _ => None,
    }) {
        let bindings = direct_initializer_bindings(&function.block);
        let mut calls = Calls {
            helper: HELPER,
            calls: Vec::new(),
        };
        calls.visit_block(&function.block);
        for call in calls.calls {
            count += 1;
            if !settings_config_get_helper_call_is_paired(call, &bindings) {
                return false;
            }
        }
    }
    count > 0
}

fn settings_config_get_helper_call_is_paired(
    call: &syn::ExprCall,
    bindings: &BTreeMap<String, Expr>,
) -> bool {
    if call.args.len() != 4 {
        return false;
    }
    let Some(router) = call.args.first().and_then(referenced_ident) else {
        return false;
    };
    let Some(proof) = call.args.get(1).and_then(referenced_ident) else {
        return false;
    };
    let Some(probe) = call.args.get(2).and_then(referenced_ident) else {
        return false;
    };
    let factory_provider = |binding: &str| {
        let Expr::Call(factory) = bindings.get(binding).map(peel_expr)? else {
            return None;
        };
        if !relative_call_path_is(&factory.func, &["finalized_config_get_router"])
            || factory.args.is_empty()
        {
            return None;
        }
        let Expr::MethodCall(test_repo) = factory.args.first().map(peel_expr)? else {
            return None;
        };
        (test_repo.method == "test_repo"
            && test_repo.args.is_empty()
            && test_repo.turbofish.is_none())
        .then(|| root_receiver_ident(&test_repo.receiver))
        .flatten()
    };
    factory_provider(&router).as_deref() == Some(&probe)
        && factory_provider(&proof).as_deref() == Some(&probe)
}

fn provenance_findings_in_items(
    items: &[Item],
    subject: &str,
    recorded_provider_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    module_path: &mut Vec<String>,
    findings: &mut Vec<Finding>,
) {
    let settings_helper_closed = settings_config_get_helper_calls_are_closed(items);
    for item in items {
        match item {
            Item::Use(item) if use_tree_contains_local_only_api(&item.tree) => {
                push_provenance_finding(
                    findings,
                    subject,
                    item.span().start().line,
                    "LocalOnly evidence APIs may not be imported or renamed; use exact absolute paths",
                );
            }
            Item::Type(item) if type_contains_local_only_api(&item.ty) => {
                push_provenance_finding(
                    findings,
                    subject,
                    item.span().start().line,
                    "LocalOnly evidence API type aliases are forbidden",
                );
            }
            Item::Fn(function) => provenance_findings_in_function(
                function,
                subject,
                recorded_provider_fields,
                module_path,
                settings_helper_closed
                    && function.sig.ident == "call_finalized_config_get_local_only",
                findings,
            ),
            Item::Impl(item) => {
                if item.trait_.as_ref().is_some_and(|(_, path, _)| {
                    path.segments
                        .last()
                        .is_some_and(|segment| segment.ident == "StaticExclusionOwner")
                }) {
                    push_provenance_finding(
                        findings,
                        subject,
                        item.span().start().line,
                        "legacy StaticExclusionOwner impl is forgeable; use an httpserve governed proof",
                    );
                }
                for child in &item.items {
                    if let ImplItem::Fn(function) = child {
                        provenance_findings_in_impl_function(
                            function,
                            subject,
                            recorded_provider_fields,
                            module_path,
                            findings,
                        );
                    }
                }
            }
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    module_path.push(item.ident.to_string());
                    provenance_findings_in_items(
                        nested,
                        subject,
                        recorded_provider_fields,
                        module_path,
                        findings,
                    );
                    module_path.pop();
                }
            }
            _ => {}
        }
    }
}

fn use_tree_contains_local_only_api(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            is_local_only_api_ident(&path.ident) || use_tree_contains_local_only_api(&path.tree)
        }
        syn::UseTree::Name(name) => is_local_only_api_ident(&name.ident),
        syn::UseTree::Rename(rename) => is_local_only_api_ident(&rename.ident),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_contains_local_only_api),
        syn::UseTree::Glob(_) => false,
    }
}

fn type_contains_local_only_api(ty: &Type) -> bool {
    struct ApiType(bool);
    impl<'ast> Visit<'ast> for ApiType {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            if node
                .path
                .segments
                .iter()
                .any(|segment| is_local_only_api_ident(&segment.ident))
            {
                self.0 = true;
            }
            visit::visit_type_path(self, node);
        }
    }
    let mut found = ApiType(false);
    found.visit_type(ty);
    found.0
}

fn is_local_only_api_ident(ident: &syn::Ident) -> bool {
    matches!(
        ident.to_string().as_str(),
        "LocalOnlyObservers" | "StaticExclusion" | "ProviderCounter" | "ProviderCounterHandle"
    )
}

fn provenance_findings_in_function(
    function: &syn::ItemFn,
    subject: &str,
    recorded_provider_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    module_path: &[String],
    allow_settings_parameter_pair: bool,
    findings: &mut Vec<Finding>,
) {
    let parameter_types = parameter_type_owners(&function.sig.inputs);
    provenance_findings_in_block(
        &function.block,
        subject,
        recorded_provider_fields,
        module_path,
        &parameter_types,
        allow_settings_parameter_pair,
        findings,
    );
}

fn provenance_findings_in_impl_function(
    function: &syn::ImplItemFn,
    subject: &str,
    recorded_provider_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    module_path: &[String],
    findings: &mut Vec<Finding>,
) {
    let parameter_types = parameter_type_owners(&function.sig.inputs);
    provenance_findings_in_block(
        &function.block,
        subject,
        recorded_provider_fields,
        module_path,
        &parameter_types,
        false,
        findings,
    );
}

fn parameter_type_owners(
    inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::Token![,]>,
) -> BTreeMap<String, String> {
    inputs
        .iter()
        .filter_map(|input| {
            let syn::FnArg::Typed(argument) = input else {
                return None;
            };
            let syn::Pat::Ident(pattern) = &*argument.pat else {
                return None;
            };
            let ty = match &*argument.ty {
                Type::Reference(reference) => &*reference.elem,
                ty => ty,
            };
            let Type::Path(ty) = ty else {
                return None;
            };
            Some((
                pattern.ident.to_string(),
                ty.path.segments.last()?.ident.to_string(),
            ))
        })
        .collect()
}

fn provenance_findings_in_block(
    block: &syn::Block,
    subject: &str,
    recorded_provider_fields: &BTreeMap<(Vec<String>, String), BTreeSet<String>>,
    module_path: &[String],
    parameter_types: &BTreeMap<String, String>,
    allow_settings_parameter_pair: bool,
    findings: &mut Vec<Finding>,
) {
    let bindings = direct_initializer_bindings(block);
    let provider_routers = canonical_provider_router_bindings(&bindings);
    let mut scan = ProvenanceCallScan::default();
    scan.visit_block(block);

    for line in scan.legacy_evidence_lines {
        findings.push(finding(
            Rule::ForgedObservationEvidence,
            format!("{subject}:{line}"),
            "legacy RuntimeProbe/StaticExclusionOwner evidence is forgeable; use governed proof or provider-owned counter handle",
        ));
    }
    for (line, _) in scan
        .api_expr_locations
        .difference(&scan.allowed_api_locations)
    {
        push_provenance_finding(
            findings,
            subject,
            *line,
            "LocalOnly evidence API must be invoked through its exact absolute canonical path",
        );
    }

    for call in scan.from_governed_calls {
        let Some(argument) = call.args.first() else {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed requires one direct governed proof binding",
            );
            continue;
        };
        let proof = referenced_ident(argument).or_else(|| {
            simple_ident(argument).filter(|proof| {
                parameter_types.get(proof).is_some_and(|owner| {
                    matches!(
                        owner.as_str(),
                        "LocalOnlyMountedRouteProof" | "StatelessLocalOnlyMountedRouteProof"
                    )
                })
            })
        });
        let Some(proof) = proof else {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed argument must be `&proof`, not an inline value or wrapper",
            );
            continue;
        };
        let governed_parameter = parameter_types.get(&proof).is_some_and(|owner| {
            matches!(
                owner.as_str(),
                "LocalOnlyMountedRouteProof" | "StatelessLocalOnlyMountedRouteProof"
            )
        });
        if !governed_parameter
            && bindings
                .get(&proof)
                .is_none_or(|initializer| !is_governed_proof_constructor(initializer))
        {
            push_provenance_finding(
                findings,
                subject,
                call.span().start().line,
                "from_governed proof is not bound directly from a current mounted-route proof constructor",
            );
        }
    }

    for observer in scan.observer_calls {
        for argument in &observer.args {
            let resolved = resolve_direct_binding(argument, &bindings);
            let Some(handle) = find_method_call(resolved, "handle") else {
                if is_from_governed_call(resolved) {
                    continue;
                }
                push_provenance_finding(
                    findings,
                    subject,
                    argument.span().start().line,
                    "LocalOnly observer evidence is neither a direct governed exclusion nor a provider-owned counter handle",
                );
                continue;
            };
            let Some(provider) = root_receiver_ident(&handle.receiver) else {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider counter handle receiver is opaque",
                );
                continue;
            };
            let settings_parameter_pair = allow_settings_parameter_pair
                && provider == "probe"
                && parameter_types.get(&provider).map(String::as_str)
                    == Some("SettingsConfigGetRepoProbe")
                && parameter_types.get("router").map(String::as_str) == Some("Router")
                && scan.oneshot_router_receivers.contains("router");
            if !settings_parameter_pair
                && provider_routers
                    .get(&provider)
                    .is_none_or(|routers| routers.is_disjoint(&scan.oneshot_router_receivers))
            {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider handle is not linked through finalized_scoped_router(receiver.test_repo()) to the router.oneshot operation",
                );
                continue;
            }
            let provider_type = bindings
                .get(&provider)
                .and_then(unique_constructor_owner)
                .or_else(|| parameter_types.get(&provider).cloned());
            let counter_field = direct_receiver_field(&handle.receiver, &provider);
            if provider_type.as_ref().is_none_or(|owner| {
                counter_field.as_ref().is_none_or(|field| {
                    recorded_provider_fields
                        .get(&(module_path.to_vec(), owner.clone()))
                        .is_none_or(|fields| !fields.contains(field))
                })
            }) {
                push_provenance_finding(
                    findings,
                    subject,
                    handle.span().start().line,
                    "provider counter field has no matching `self.<field>.record()` mutation path",
                );
            }
        }
    }
}

fn canonical_provider_router_bindings(
    bindings: &BTreeMap<String, Expr>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (router, initializer) in bindings {
        let Expr::Call(call) = peel_expr(initializer) else {
            continue;
        };
        let Expr::Path(function) = peel_expr(&call.func) else {
            continue;
        };
        if function.path.leading_colon.is_some()
            || !matches!(function.path.segments.len(), 1 | 2)
            || function
                .path
                .segments
                .last()
                .is_none_or(|segment| !segment.ident.to_string().starts_with("finalized_"))
            || (function.path.segments.len() == 2 && function.path.segments[0].ident != "self")
        {
            continue;
        }
        for argument in &call.args {
            let Expr::MethodCall(method) = peel_expr(argument) else {
                continue;
            };
            if method.method == "test_repo"
                && method.args.is_empty()
                && let Some(provider) = root_receiver_ident(&method.receiver)
            {
                out.entry(provider).or_default().insert(router.clone());
            }
        }
    }
    out
}

fn direct_receiver_field(expression: &Expr, provider: &str) -> Option<String> {
    let Expr::Field(field) = peel_expr(expression) else {
        return None;
    };
    let syn::Member::Named(member) = &field.member else {
        return None;
    };
    let Expr::Path(base) = peel_expr(&field.base) else {
        return None;
    };
    (base.path.get_ident().is_some_and(|ident| ident == provider)).then(|| member.to_string())
}

fn push_provenance_finding(
    findings: &mut Vec<Finding>,
    subject: &str,
    line: usize,
    detail: &'static str,
) {
    findings.push(finding(
        Rule::ForgedObservationEvidence,
        format!("{subject}:{line}"),
        detail,
    ));
}

#[derive(Default)]
struct ProvenanceCallScan<'ast> {
    from_governed_calls: Vec<&'ast syn::ExprCall>,
    observer_calls: Vec<&'ast syn::ExprCall>,
    oneshot_router_receivers: BTreeSet<String>,
    legacy_evidence_lines: BTreeSet<usize>,
    api_expr_locations: BTreeSet<(usize, usize)>,
    allowed_api_locations: BTreeSet<(usize, usize)>,
}

impl<'ast> Visit<'ast> for ProvenanceCallScan<'ast> {
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if node.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "StaticExclusionOwner" | "RuntimeProbe"
            )
        }) {
            self.legacy_evidence_lines.insert(node.span().start().line);
        }
        visit::visit_path(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.path.segments.iter().any(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "LocalOnlyObservers"
                    | "StaticExclusion"
                    | "ProviderCounter"
                    | "prove_local_only_mounted_route_state"
                    | "prove_stateless_local_only_mounted_route"
            )
        }) {
            let start = node.span().start();
            self.api_expr_locations.insert((start.line, start.column));
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let start = node.func.span().start();
        let location = (start.line, start.column);
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "StaticExclusion", "from_governed"],
        ) {
            self.from_governed_calls.push(node);
            self.allowed_api_locations.insert(location);
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "LocalOnlyObservers", "new"],
        ) {
            self.observer_calls.push(node);
            self.allowed_api_locations.insert(location);
        }
        if absolute_call_path_is(
            &node.func,
            &["testkit", "local_only", "ProviderCounter", "business_write"],
        ) || is_current_mounted_proof_call(node)
        {
            self.allowed_api_locations.insert(location);
        }
        if absolute_call_path_is(&node.func, &["testkit", "call"])
            && let Some(router) = node.args.first().and_then(root_receiver_ident)
        {
            self.oneshot_router_receivers.insert(router);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "oneshot"
            && let Some(receiver) = root_receiver_ident(&node.receiver)
        {
            self.oneshot_router_receivers.insert(receiver);
        }
        visit::visit_expr_method_call(self, node);
    }
}

fn direct_initializer_bindings(block: &syn::Block) -> BTreeMap<String, Expr> {
    struct Bindings(BTreeMap<String, Expr>);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let syn::Pat::Ident(pattern) = &node.pat
                && pattern.subpat.is_none()
                && let Some(initializer) = &node.init
            {
                self.0
                    .entry(pattern.ident.to_string())
                    .or_insert_with(|| (*initializer.expr).clone());
            } else if let syn::Pat::Tuple(tuple) = &node.pat
                && let Some(initializer) = &node.init
            {
                for pattern in &tuple.elems {
                    if let syn::Pat::Ident(pattern) = pattern
                        && pattern.subpat.is_none()
                    {
                        self.0
                            .entry(pattern.ident.to_string())
                            .or_insert_with(|| (*initializer.expr).clone());
                    }
                }
            }
            visit::visit_local(self, node);
        }
    }
    let mut bindings = Bindings(BTreeMap::new());
    bindings.visit_block(block);
    bindings.0
}

fn resolve_direct_binding<'a>(
    expression: &'a Expr,
    bindings: &'a BTreeMap<String, Expr>,
) -> &'a Expr {
    let Expr::Path(path) = peel_expr(expression) else {
        return expression;
    };
    let Some(ident) = path.path.get_ident() else {
        return expression;
    };
    bindings.get(&ident.to_string()).unwrap_or(expression)
}

fn referenced_ident(expression: &Expr) -> Option<String> {
    let expression = match expression {
        Expr::Paren(value) => &*value.expr,
        Expr::Group(value) => &*value.expr,
        other => other,
    };
    let Expr::Reference(reference) = expression else {
        return None;
    };
    let Expr::Path(path) = peel_expr(&reference.expr) else {
        return None;
    };
    path.path.get_ident().map(ToString::to_string)
}

fn is_governed_proof_constructor(expression: &Expr) -> bool {
    if current_mounted_proof_call(expression).is_some() {
        return true;
    }
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    matches!(
        peel_expr(&call.func),
        Expr::Path(function)
            if function.path.leading_colon.is_none()
                && matches!(function.path.segments.len(), 1 | 2)
                && (function.path.segments.len() == 1
                    || function.path.segments[0].ident == "self")
                && function.path.segments.last().is_some_and(|segment| segment
                    .ident
                    .to_string()
                    .starts_with("finalized_"))
    )
}

fn current_mounted_proof_call(expression: &Expr) -> Option<&syn::ExprCall> {
    let Expr::MethodCall(expect) = peel_expr(expression) else {
        return None;
    };
    if expect.method != "expect" || expect.args.len() != 1 || expect.turbofish.is_some() {
        return None;
    }
    let Expr::Call(call) = peel_expr(&expect.receiver) else {
        return None;
    };
    is_current_mounted_proof_call(call).then_some(call)
}

fn is_current_mounted_proof_call(call: &syn::ExprCall) -> bool {
    current_mounted_proof_kind(call).is_some()
}

fn is_from_governed_call(expression: &Expr) -> bool {
    let Expr::Call(call) = peel_expr(expression) else {
        return false;
    };
    absolute_call_path_is(
        &call.func,
        &["testkit", "local_only", "StaticExclusion", "from_governed"],
    )
}

fn find_method_call<'ast>(
    expression: &'ast Expr,
    method: &str,
) -> Option<&'ast syn::ExprMethodCall> {
    struct Finder<'name, 'ast> {
        method: &'name str,
        found: Option<&'ast syn::ExprMethodCall>,
    }
    impl<'ast> Visit<'ast> for Finder<'_, 'ast> {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if self.found.is_none() && node.method == self.method {
                self.found = Some(node);
                return;
            }
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut finder = Finder {
        method,
        found: None,
    };
    finder.visit_expr(expression);
    finder.found
}

fn root_receiver_ident(expression: &Expr) -> Option<String> {
    match peel_expr(expression) {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => root_receiver_ident(&field.base),
        Expr::MethodCall(call) => root_receiver_ident(&call.receiver),
        Expr::Reference(reference) => root_receiver_ident(&reference.expr),
        _ => None,
    }
}

fn unique_constructor_owner(expression: &Expr) -> Option<String> {
    struct Constructors(BTreeSet<String>);
    impl<'ast> Visit<'ast> for Constructors {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Expr::Path(path) = peel_expr(&node.func)
                && let Some(owner) = path.path.segments.iter().rev().nth(1)
            {
                self.0.insert(owner.ident.to_string());
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut constructors = Constructors(BTreeSet::new());
    constructors.visit_expr(expression);
    (constructors.0.len() == 1)
        .then(|| constructors.0.into_iter().next())
        .flatten()
}

fn absolute_call_path_is(expression: &Expr, expected: &[&str]) -> bool {
    let Expr::Path(path) = peel_expr(expression) else {
        return false;
    };
    path.path.leading_colon.is_some()
        && path.path.segments.len() == expected.len()
        && path
            .path
            .segments
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.ident == *expected)
}

#[derive(Debug, Clone)]
struct StateImpl {
    effect: String,
    privilege: String,
    subject: String,
}

#[derive(Clone)]
struct StructField {
    ty: Type,
    subject: String,
}

#[derive(Clone)]
struct StructInfo {
    fields: Vec<StructField>,
    named_fields: BTreeMap<String, String>,
    subject: String,
}

#[derive(Debug, Clone)]
struct PortClass {
    effect: String,
    privilege: String,
    subject: String,
    port: String,
    privilege_subject: String,
    privilege_port: String,
}

#[derive(Clone)]
struct TypeAlias {
    ty: Type,
    params: Vec<String>,
    subject: String,
}

struct ProofSource {
    states: BTreeMap<String, StateImpl>,
    structs: BTreeMap<String, StructInfo>,
    ports: BTreeMap<String, PortClass>,
    type_aliases: BTreeMap<String, TypeAlias>,
    bindings: BTreeMap<String, BTreeMap<String, String>>,
    trusted_port_macros: BTreeSet<String>,
}

impl ProofSource {
    fn load(root: &Path, scope: &ServingScope, reachable: &BTreeSet<String>) -> Result<Self> {
        let mut this = Self {
            states: BTreeMap::new(),
            structs: BTreeMap::new(),
            ports: BTreeMap::new(),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        for subject in reachable {
            let file = root.join(subject);
            let text =
                std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?;
            let syntax = syn::parse_file(&text).with_context(|| format!("parse `{subject}`"))?;
            if let ServingScope::Domain(owner) = scope {
                collect_trusted_port_macro_definitions(
                    &syntax.items,
                    subject,
                    owner,
                    &mut this.trusted_port_macros,
                )?;
            }
            collect_items(&syntax.items, subject, scope, &mut this)?;
            let bindings = binding_types(&syntax, &this.structs);
            this.bindings.insert(subject.clone(), bindings);
        }
        collect_diport_capabilities(root, &mut this.ports)?;
        if matches!(scope, ServingScope::Domain(_)) && this.trusted_port_macros.is_empty() {
            bail!("owner port classifications lack a canonical owner-sealed macro definition");
        }
        Ok(this)
    }

    fn state_name(&self, source: &str, expression: &str) -> Option<String> {
        let expression = syn::parse_str::<Expr>(expression).ok()?;
        let bindings = self.bindings.get(source)?;
        state_expr_name(&expression, bindings)
    }

    fn classify_state(&self, state: &str) -> Result<PortClass> {
        let declared = self.states.get(state).ok_or_else(|| {
            let subject = self
                .structs
                .get(state)
                .map_or("unknown state", |info| info.subject.as_str());
            anyhow!("{subject}: missing canonical ClassifiedRouteState impl")
        })?;
        let mut visiting = BTreeSet::new();
        let inferred = self
            .infer_struct(state, &mut visiting)?
            .ok_or_else(|| anyhow!("state graph exposes no owner-sealed classified port"))?;
        if declared.effect != inferred.effect || declared.privilege != inferred.privilege {
            bail!(
                "{}: strongest field `{}` {}/{} disagrees with state declaration {}/{} at {}",
                inferred.subject,
                inferred.port,
                inferred.effect,
                inferred.privilege,
                declared.effect,
                declared.privilege,
                declared.subject
            );
        }
        Ok(PortClass {
            effect: declared.effect.clone(),
            privilege: declared.privilege.clone(),
            subject: inferred.subject,
            port: inferred.port,
            privilege_subject: inferred.privilege_subject,
            privilege_port: inferred.privilege_port,
        })
    }

    fn infer_struct(
        &self,
        name: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Option<PortClass>> {
        if !visiting.insert(name.to_string()) {
            bail!("recursive state/service struct graph");
        }
        let info = self
            .structs
            .get(name)
            .ok_or_else(|| anyhow!("state/service struct `{name}` is not uniquely defined"))?;
        let mut classes = Vec::new();
        for field in &info.fields {
            let mut alias_visiting = BTreeSet::new();
            self.infer_type(
                &field.ty,
                &BTreeMap::new(),
                visiting,
                &mut alias_visiting,
                &field.subject,
                &mut classes,
            )?;
        }
        visiting.remove(name);
        let Some(effect) = classes
            .iter()
            .max_by_key(|class| effect_rank(&class.effect))
        else {
            // Non-port local values/caches are outside this static port proof and are covered by
            // the runtime conformance boundary (#1694). They cannot hide a `Dyn*` port: an
            // unclassified dyn capability above is fail-closed.
            if self.states.contains_key(name) {
                bail!(
                    "{}: state graph exposes no owner-sealed classified port",
                    info.subject
                );
            }
            return Ok(None);
        };
        let privilege = classes
            .iter()
            .find(|class| class.privilege == "CrossTenantPrivilege")
            .unwrap_or(effect);
        Ok(Some(PortClass {
            effect: effect.effect.clone(),
            privilege: privilege.privilege.clone(),
            subject: effect.subject.clone(),
            port: effect.port.clone(),
            privilege_subject: privilege.privilege_subject.clone(),
            privilege_port: privilege.privilege_port.clone(),
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn infer_type(
        &self,
        ty: &Type,
        substitutions: &BTreeMap<String, Type>,
        struct_visiting: &mut BTreeSet<String>,
        alias_visiting: &mut BTreeSet<String>,
        field_subject: &str,
        out: &mut Vec<PortClass>,
    ) -> Result<()> {
        match ty {
            Type::Path(path) if path.qself.is_none() => {
                if path.path.leading_colon.is_none()
                    && path.path.segments.len() == 3
                    && path.path.segments[0].ident == "runtimeexec"
                    && path.path.segments[1].ident == "inventory"
                    && path.path.segments[2].ident == "InventoryReader"
                {
                    out.push(PortClass {
                        effect: "ReadEffect".to_owned(),
                        privilege: "LocalPrivilege".to_owned(),
                        subject: field_subject.to_owned(),
                        port: "runtimeexec::inventory::InventoryReader".to_owned(),
                        privilege_subject: field_subject.to_owned(),
                        privilege_port: "runtimeexec::inventory::InventoryReader".to_owned(),
                    });
                    return Ok(());
                }
                let Some(segment) = path.path.segments.last() else {
                    return Ok(());
                };
                let name = segment.ident.to_string();
                if let Some(replacement) = substitutions.get(&name) {
                    return self.infer_type(
                        replacement,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    );
                }
                if let Some(alias) = self.type_aliases.get(&name) {
                    if !alias_visiting.insert(name.clone()) {
                        bail!("{}: recursive type alias `{name}`", alias.subject);
                    }
                    let args = type_arguments(&segment.arguments);
                    if args.len() != alias.params.len() {
                        bail!(
                            "{}: type alias `{name}` expects {} type argument(s), found {}",
                            alias.subject,
                            alias.params.len(),
                            args.len()
                        );
                    }
                    let mut nested = substitutions.clone();
                    nested.extend(alias.params.iter().cloned().zip(args));
                    self.infer_type(
                        &alias.ty,
                        &nested,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                    alias_visiting.remove(&name);
                    return Ok(());
                }
                if let Some(class) = self.ports.get(&name) {
                    out.push(class.at_field(field_subject));
                    return Ok(());
                }
                if self.structs.contains_key(&name) {
                    if let Some(class) = self.infer_struct(&name, struct_visiting)? {
                        out.push(class);
                    }
                    return Ok(());
                }
                if name.starts_with("Dyn") {
                    bail!("{field_subject}: capability `{name}` is not owner-sealed or classified");
                }
                for argument in type_arguments(&segment.arguments) {
                    self.infer_type(
                        &argument,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                }
            }
            Type::TraitObject(object) => {
                let mut principal = Vec::new();
                for bound in &object.bounds {
                    let TypeParamBound::Trait(bound) = bound else {
                        continue;
                    };
                    let Some(segment) = bound.path.segments.last() else {
                        continue;
                    };
                    let name = segment.ident.to_string();
                    if matches!(name.as_str(), "Send" | "Sync" | "Unpin") {
                        continue;
                    }
                    principal.push(name);
                }
                if principal.len() != 1 {
                    bail!("{field_subject}: trait object has no unique classified capability");
                }
                let name = &principal[0];
                let class = self.class_for_trait(name).ok_or_else(|| {
                    anyhow!(
                        "{field_subject}: trait object capability `{name}` is not owner-sealed or classified"
                    )
                })?;
                out.push(class.at_field(field_subject));
            }
            Type::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.infer_type(
                        element,
                        substitutions,
                        struct_visiting,
                        alias_visiting,
                        field_subject,
                        out,
                    )?;
                }
            }
            Type::Array(array) => self.infer_type(
                &array.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Slice(slice) => self.infer_type(
                &slice.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Reference(reference) => self.infer_type(
                &reference.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Ptr(pointer) => self.infer_type(
                &pointer.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Paren(paren) => self.infer_type(
                &paren.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::Group(group) => self.infer_type(
                &group.elem,
                substitutions,
                struct_visiting,
                alias_visiting,
                field_subject,
                out,
            )?,
            Type::ImplTrait(_) => {
                bail!("{field_subject}: opaque impl Trait capability is forbidden")
            }
            _ => {}
        }
        Ok(())
    }

    fn class_for_trait(&self, name: &str) -> Option<&PortClass> {
        self.ports.get(name).or_else(|| {
            self.type_aliases.iter().find_map(|(alias_name, alias)| {
                (trait_object_principal(&alias.ty).as_deref() == Some(name))
                    .then(|| self.ports.get(alias_name))
                    .flatten()
            })
        })
    }
}

impl PortClass {
    fn at_field(&self, subject: &str) -> Self {
        Self {
            effect: self.effect.clone(),
            privilege: self.privilege.clone(),
            subject: subject.to_string(),
            port: format!("{} (classified at {})", self.port, self.subject),
            privilege_subject: subject.to_string(),
            privilege_port: format!(
                "{} (classified at {})",
                self.privilege_port, self.privilege_subject
            ),
        }
    }
}

fn collect_items(
    items: &[Item],
    subject: &str,
    scope: &ServingScope,
    out: &mut ProofSource,
) -> Result<()> {
    for item in items {
        if !attrs_are_production(item_attrs(item)) {
            continue;
        }
        match item {
            Item::Struct(item) => collect_struct(item, subject, &mut out.structs)?,
            Item::Impl(item) => collect_state_impl(item, subject, &mut out.states)?,
            Item::Macro(item) => {
                if let ServingScope::Domain(owner) = scope {
                    collect_port_macro(
                        item,
                        subject,
                        owner,
                        &out.trusted_port_macros,
                        &mut out.ports,
                    )?;
                }
            }
            Item::Type(item) => collect_type_alias(item, subject, &mut out.type_aliases)?,
            Item::Mod(item) => {
                if let Some((_, nested)) = &item.content {
                    collect_items(nested, subject, scope, out)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_type_alias(
    item: &ItemType,
    subject: &str,
    out: &mut BTreeMap<String, TypeAlias>,
) -> Result<()> {
    let name = item.ident.to_string();
    let alias = TypeAlias {
        ty: (*item.ty).clone(),
        params: item
            .generics
            .type_params()
            .map(|param| param.ident.to_string())
            .collect(),
        subject: source_at(subject, item.span()),
    };
    if out.insert(name.clone(), alias).is_some() {
        bail!("duplicate type alias `{name}`");
    }
    Ok(())
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn collect_struct(
    item: &ItemStruct,
    subject: &str,
    out: &mut BTreeMap<String, StructInfo>,
) -> Result<()> {
    let name = item.ident.to_string();
    let named_fields: BTreeMap<_, _> = item
        .fields
        .iter()
        .filter(|field| crate::localtx_coverage::attrs_may_be_production(&field.attrs))
        .filter_map(|field| {
            Some((
                field.ident.as_ref()?.to_string(),
                terminal_type_ident(&field.ty)?,
            ))
        })
        .collect();
    let fields = item
        .fields
        .iter()
        .filter(|field| crate::localtx_coverage::attrs_may_be_production(&field.attrs))
        .map(|field| StructField {
            ty: field.ty.clone(),
            subject: source_at(subject, field.span()),
        })
        .collect();
    if out
        .insert(
            name.clone(),
            StructInfo {
                fields,
                named_fields,
                subject: source_at(subject, item.span()),
            },
        )
        .is_some()
    {
        bail!("duplicate struct identity `{name}` in owner source");
    }
    Ok(())
}

fn collect_state_impl(
    item: &ItemImpl,
    subject: &str,
    out: &mut BTreeMap<String, StateImpl>,
) -> Result<()> {
    let Some((_, trait_path, _)) = &item.trait_ else {
        return Ok(());
    };
    if trait_path
        .segments
        .last()
        .is_none_or(|segment| segment.ident != "ClassifiedRouteState")
    {
        return Ok(());
    }
    let Type::Path(self_ty) = item.self_ty.as_ref() else {
        return Ok(());
    };
    let Some(name) = self_ty
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return Ok(());
    };
    let mut effect = None;
    let mut privilege = None;
    for impl_item in &item.items {
        if let ImplItem::Type(assoc) = impl_item {
            let value = terminal_type_ident(&assoc.ty);
            if assoc.ident == "Effect" {
                effect = value;
            } else if assoc.ident == "Privilege" {
                privilege = value;
            }
        }
    }
    let state = StateImpl {
        effect: effect.ok_or_else(|| anyhow!("{subject}: `{name}` missing Effect"))?,
        privilege: privilege.ok_or_else(|| anyhow!("{subject}: `{name}` missing Privilege"))?,
        subject: source_at(subject, item.span()),
    };
    if out.insert(name.clone(), state).is_some() {
        bail!("duplicate ClassifiedRouteState impl for `{name}`");
    }
    Ok(())
}

fn collect_port_macro(
    item: &syn::ItemMacro,
    subject: &str,
    owner: &str,
    trusted: &BTreeSet<String>,
    out: &mut BTreeMap<String, PortClass>,
) -> Result<()> {
    let canonical_subject = format!("crates/{owner}/src/ports.rs");
    if subject != canonical_subject {
        return Ok(());
    }
    let name = item
        .mac
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    let canonical_plural = format!("classify_{}_ports", owner.replace('-', "_"));
    let canonical_singular = format!("classify_{}_port", owner.replace('-', "_"));
    if name != canonical_plural && name != canonical_singular {
        return Ok(());
    }
    if !trusted.contains(&name) {
        bail!("owner port classification invocation `{name}` is not bound to its canonical macro");
    }
    let text = item.mac.tokens.to_string();
    if name.ends_with("_ports") {
        for entry in text.split([',', ';']) {
            let words = identifiers(entry);
            if let (Some(port), Some(effect)) = (
                words.iter().find(|word| word.starts_with("Dyn")),
                words.iter().find(|word| word.ends_with("Effect")),
            ) {
                insert_port(
                    out,
                    port,
                    effect,
                    "LocalPrivilege",
                    &source_at(subject, item.span()),
                )?;
            }
        }
    } else {
        let words = identifiers(&text);
        if let (Some(port), Some(effect), Some(privilege)) = (
            words.iter().find(|word| word.starts_with("Dyn")),
            words.iter().find(|word| word.ends_with("Effect")),
            words.iter().find(|word| word.ends_with("Privilege")),
        ) {
            insert_port(
                out,
                port,
                effect,
                privilege,
                &source_at(subject, item.span()),
            )?;
        }
    }
    Ok(())
}

fn collect_trusted_port_macro_definitions(
    items: &[Item],
    subject: &str,
    owner: &str,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    if subject != format!("crates/{owner}/src/ports.rs") {
        return Ok(());
    }
    let expected = [
        format!("classify_{}_ports", owner.replace('-', "_")),
        format!("classify_{}_port", owner.replace('-', "_")),
    ];
    for item in items {
        let Item::Macro(item) = item else {
            continue;
        };
        let Some(name) = item.ident.as_ref().map(ToString::to_string) else {
            continue;
        };
        if !expected.contains(&name) {
            continue;
        }
        let words = identifiers(&item.mac.tokens.to_string());
        for required in ["Sealed", "PortEffectClass", "assert_effect"] {
            if !words.iter().any(|word| word == required) {
                bail!("canonical owner port classification macro `{name}` has opaque semantics");
            }
        }
        if !out.insert(name.clone()) {
            bail!("duplicate canonical owner port macro `{name}`");
        }
    }
    Ok(())
}

fn insert_port(
    out: &mut BTreeMap<String, PortClass>,
    port: &str,
    effect: &str,
    privilege: &str,
    subject: &str,
) -> Result<()> {
    let class = PortClass {
        effect: effect.to_string(),
        privilege: privilege.to_string(),
        subject: subject.to_string(),
        port: port.to_string(),
        privilege_subject: subject.to_string(),
        privilege_port: port.to_string(),
    };
    if out.insert(port.to_string(), class).is_some() {
        bail!("duplicate owner port classification `{port}`");
    }
    Ok(())
}

fn collect_diport_capabilities(root: &Path, out: &mut BTreeMap<String, PortClass>) -> Result<()> {
    let effect = root.join("crates/diport/src/effect.rs");
    let file = if effect.is_file() {
        effect
    } else {
        root.join("crates/diport/src/lib.rs")
    };
    let subject = relative(root, &file)?;
    let syntax = syn::parse_file(
        &std::fs::read_to_string(&file).with_context(|| format!("read `{subject}`"))?,
    )
    .with_context(|| format!("parse `{subject}`"))?;
    let mut found = false;
    for item in syntax.items {
        let Item::Macro(item) = item else {
            continue;
        };
        if item
            .mac
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "classify_ports")
        {
            continue;
        }
        found = true;
        let location = source_at(&subject, item.span());
        for entry in item.mac.tokens.to_string().split(';') {
            let words = identifiers(entry);
            let Some(kind) = words.first().map(String::as_str) else {
                continue;
            };
            if !matches!(kind, "dyn" | "sync") {
                bail!("{location}: opaque diport capability classification entry");
            }
            let port = words
                .get(1)
                .ok_or_else(|| anyhow!("{location}: missing diport capability name"))?;
            let effect = words
                .iter()
                .find(|word| word.ends_with("Effect"))
                .ok_or_else(|| anyhow!("{location}: missing diport capability effect"))?;
            insert_port(out, port, effect, "LocalPrivilege", &location)?;
        }
    }
    if !found {
        bail!("{subject}: canonical owner-sealed `classify_ports!` table is missing");
    }
    Ok(())
}

fn type_arguments(arguments: &PathArguments) -> Vec<Type> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return Vec::new();
    };
    arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            GenericArgument::Type(ty) => Some(ty.clone()),
            GenericArgument::AssocType(assoc) => Some(assoc.ty.clone()),
            _ => None,
        })
        .collect()
}

fn trait_object_principal(ty: &Type) -> Option<String> {
    let Type::TraitObject(object) = ty else {
        return None;
    };
    let principals: Vec<_> = object
        .bounds
        .iter()
        .filter_map(|bound| match bound {
            TypeParamBound::Trait(bound) => bound
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        })
        .filter(|name| !matches!(name.as_str(), "Send" | "Sync" | "Unpin"))
        .collect();
    (principals.len() == 1).then(|| principals[0].clone())
}

fn source_at(subject: &str, span: proc_macro2::Span) -> String {
    format!("{subject}:{}", span.start().line)
}

fn diagnostic_source(detail: &str) -> Option<String> {
    let start = detail.find("crates/")?;
    let candidate = &detail[start..];
    let line_separator = candidate.find(':')?;
    let after = &candidate[line_separator + 1..];
    let line_end = after.find(':')?;
    after[..line_end]
        .chars()
        .all(|character| character.is_ascii_digit())
        .then(|| candidate[..line_separator + line_end + 1].to_string())
}

fn state_expr_name(expr: &Expr, bindings: &BTreeMap<String, String>) -> Option<String> {
    match peel_expr(expr) {
        Expr::Struct(value) => value
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::Path(value) => value
            .path
            .segments
            .last()
            .and_then(|segment| bindings.get(&segment.ident.to_string()).cloned()),
        Expr::MethodCall(value) if value.method == "clone" => {
            state_expr_name(&value.receiver, bindings)
        }
        _ => None,
    }
}

fn binding_types(
    file: &syn::File,
    structs: &BTreeMap<String, StructInfo>,
) -> BTreeMap<String, String> {
    struct Locals(Vec<(String, Expr)>);
    impl<'ast> Visit<'ast> for Locals {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if attrs_are_production(&node.attrs)
                && let syn::Pat::Ident(pattern) = &node.pat
                && pattern.subpat.is_none()
                && let Some(init) = &node.init
            {
                self.0
                    .push((pattern.ident.to_string(), (*init.expr).clone()));
            }
            visit::visit_local(self, node);
        }
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if attrs_are_production(&node.attrs) {
                visit::visit_item_mod(self, node);
            }
        }
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if attrs_are_production(&node.attrs) {
                visit::visit_item_fn(self, node);
            }
        }
    }
    let mut locals = Locals(Vec::new());
    locals.visit_file(file);
    let mut fields = BTreeMap::new();
    let mut duplicate_fields = BTreeSet::new();
    for info in structs.values() {
        for (field, ty) in &info.named_fields {
            if fields.insert(field.clone(), ty.clone()).is_some() {
                duplicate_fields.insert(field.clone());
            }
        }
    }
    for field in duplicate_fields {
        fields.remove(&field);
    }
    let mut out = BTreeMap::new();
    for _ in 0..8 {
        let before = out.len();
        for (name, expr) in &locals.0 {
            if let Some(ty) = initializer_type(expr, &out, &fields) {
                out.insert(name.clone(), ty);
            }
        }
        if out.len() == before {
            break;
        }
    }
    out
}

fn initializer_type(
    expr: &Expr,
    bindings: &BTreeMap<String, String>,
    fields: &BTreeMap<String, String>,
) -> Option<String> {
    match peel_expr(expr) {
        Expr::Struct(value) => value
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::Path(value) => value
            .path
            .segments
            .last()
            .and_then(|segment| bindings.get(&segment.ident.to_string()).cloned()),
        Expr::MethodCall(value) if value.method == "clone" => {
            initializer_type(&value.receiver, bindings, fields)
        }
        Expr::Call(value) => {
            if let Expr::Path(function) = peel_expr(&value.func)
                && function
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "new")
                && let Some(owner) = function.path.segments.iter().rev().nth(1)
            {
                Some(owner.ident.to_string())
            } else {
                value
                    .args
                    .first()
                    .and_then(|arg| initializer_type(arg, bindings, fields))
            }
        }
        Expr::Field(value) => match &value.member {
            syn::Member::Named(field) => fields.get(&field.to_string()).cloned(),
            syn::Member::Unnamed(_) => None,
        },
        _ => None,
    }
}

fn generated_localonly_routes(root: &Path) -> Result<BTreeSet<String>> {
    let dir = root.join("generated/src/http");
    let mut routes = BTreeSet::new();
    for file in rust_files(&dir)? {
        if file.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
            continue;
        }
        let module = file
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("generated module filename is not UTF-8"))?;
        let syntax = syn::parse_file(&std::fs::read_to_string(&file)?)?;
        collect_generated_routes(&syntax.items, module, &mut Vec::new(), &mut routes)?;
    }
    Ok(routes)
}

fn verify_manifest_generated_local_only_exact_set(
    contracts: &[Contract],
    generated_routes: &BTreeSet<String>,
) -> Result<()> {
    let manifest_routes = contracts
        .iter()
        .map(|contract| contract.key.clone())
        .collect::<BTreeSet<_>>();
    if manifest_routes != *generated_routes {
        let missing_from_generated = manifest_routes
            .difference(generated_routes)
            .cloned()
            .collect::<Vec<_>>();
        let stale_in_generated = generated_routes
            .difference(&manifest_routes)
            .cloned()
            .collect::<Vec<_>>();
        bail!(
            "generated LocalOnly registry disagrees with active manifests: missing_from_generated={missing_from_generated:?}; stale_in_generated={stale_in_generated:?}"
        );
    }
    Ok(())
}

fn verify_manifest_compiled_local_only_exact_set(
    contracts: &[Contract],
    specs: &[generated::http::HttpSpec],
) -> Result<()> {
    let manifests = contracts
        .iter()
        .map(|contract| (contract.id.as_str(), contract.key.as_str()))
        .collect::<BTreeSet<_>>();
    let compiled = specs
        .iter()
        .map(|spec| (spec.route.contract_id(), spec.mount_key))
        .collect::<BTreeSet<_>>();
    if manifests != compiled || specs.len() != compiled.len() {
        let missing_from_compiled = manifests.difference(&compiled).copied().collect::<Vec<_>>();
        let stale_in_compiled = compiled.difference(&manifests).copied().collect::<Vec<_>>();
        bail!(
            "generated::http::LOCAL_ONLY_SPECS disagrees with active LocalOnly manifests: missing_from_compiled={missing_from_compiled:?}; stale_in_compiled={stale_in_compiled:?}; compiled_duplicates={} ",
            specs.len().saturating_sub(compiled.len())
        );
    }
    Ok(())
}

fn collect_generated_routes(
    items: &[Item],
    module: &str,
    nested: &mut Vec<String>,
    out: &mut BTreeSet<String>,
) -> Result<()> {
    for item in items {
        match item {
            Item::Const(item) if item.ident == "ROUTE" && route_type_is_localonly(&item.ty) => {
                let key = std::iter::once(module.to_string())
                    .chain(nested.iter().cloned())
                    .collect::<Vec<_>>()
                    .join("::");
                if !out.insert(key.clone()) {
                    bail!("duplicate generated LocalOnly ROUTE `{key}`");
                }
            }
            Item::Mod(item) => {
                if let Some((_, children)) = &item.content {
                    nested.push(item.ident.to_string());
                    collect_generated_routes(children, module, nested, out)?;
                    nested.pop();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn route_type_is_localonly(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    let Some(binding) = path.path.segments.last() else {
        return false;
    };
    if binding.ident != "HttpRouteBinding" {
        return false;
    }
    let PathArguments::AngleBracketed(args) = &binding.arguments else {
        return false;
    };
    matches!(args.args.iter().nth(1), Some(GenericArgument::Type(Type::Path(marker))) if marker.path.segments.last().is_some_and(|segment| segment.ident == "LocalOnly"))
}

fn terminal_type_ident(ty: &Type) -> Option<String> {
    struct LastIdent(Vec<String>);
    impl<'ast> Visit<'ast> for LastIdent {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            for segment in &node.path.segments {
                let ident = segment.ident.to_string();
                if !matches!(ident.as_str(), "Arc" | "Box" | "Option" | "Vec") {
                    self.0.push(ident);
                }
                visit::visit_path_arguments(self, &segment.arguments);
            }
        }
    }
    let mut visitor = LastIdent(Vec::new());
    visitor.visit_type(ty);
    visitor
        .0
        .iter()
        .rev()
        .find(|ident| ident.starts_with("Dyn"))
        .cloned()
        .or_else(|| visitor.0.last().cloned())
}

fn identifiers(text: &str) -> Vec<String> {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn effect_rank(effect: &str) -> u8 {
    match effect {
        "AuthEffect" => 0,
        "ReadEffect" => 1,
        "BusinessWriteEffect" => 2,
        "OutboxEffect" => 3,
        "WorkflowEffect" => 4,
        _ => 255,
    }
}

fn attrs_are_production(attrs: &[syn::Attribute]) -> bool {
    !attrs.iter().any(|attr| attr.path().is_ident("test"))
        && crate::localtx_coverage::attrs_may_be_production(attrs)
}

fn peel_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(value) => peel_expr(&value.expr),
        Expr::Paren(value) => peel_expr(&value.expr),
        Expr::Group(value) => peel_expr(&value.expr),
        other => other,
    }
}

fn rust_files(dir: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("read `{}`", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("symlink source evidence is forbidden");
            }
            if kind.is_dir() {
                walk(&path, files)?;
            } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs")
            {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(dir, &mut files)?;
    files.sort();
    Ok(files)
}

#[allow(clippy::too_many_arguments)]
fn contract_finding(
    rule: Rule,
    id: &str,
    method: &str,
    path: &str,
    subject: &str,
    effect: &str,
    privilege: &str,
    source: &str,
) -> Finding {
    finding(
        rule,
        subject.to_string(),
        format!(
            "contract `{id}` {method} {path}: state=`{subject}` port=`{source}` effect=`{effect}` privilege=`{privilege}`"
        ),
    )
}

fn classified_finding(rule: Rule, contract: &Contract, state: &str, class: &PortClass) -> Finding {
    let (subject, port) = if matches!(rule, Rule::CrossTenantPrivilege) {
        (&class.privilege_subject, &class.privilege_port)
    } else {
        (&class.subject, &class.port)
    };
    finding(
        rule,
        subject.clone(),
        format!(
            "contract `{}` {} {}: state=`{state}` port=`{}` effect=`{}` privilege=`{}`",
            contract.id, contract.method, contract.path, port, class.effect, class.privilege
        ),
    )
}

fn relative_manifest_path(root: &Path, contract: &DiscoveredContract) -> Result<String> {
    relative(root, &contract.dir.join("contract.toml"))
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path outside workspace"))?
        .to_str()
        .ok_or_else(|| anyhow!("path is not UTF-8"))?
        .replace('\\', "/"))
}
fn required_path<'a>(path: Option<&'a str>, subject: &str, id: &str) -> Result<&'a str> {
    path.ok_or_else(|| anyhow!("{subject}: active LocalOnly HTTP contract `{id}` missing `path`"))
}
fn required_method(method: Option<HttpMethod>, subject: &str, id: &str) -> Result<HttpMethod> {
    method
        .ok_or_else(|| anyhow!("{subject}: active LocalOnly HTTP contract `{id}` missing `method`"))
}
fn generated_key(domain: &str, version: &str, slug: Option<&str>) -> String {
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    slug.map_or(module.clone(), |slug| {
        format!("{module}::{}", slug.replace('-', "_"))
    })
}
fn forbidden_effect_wire(effect: EffectKind) -> Option<&'static str> {
    match effect {
        EffectKind::Auth | EffectKind::Read | EffectKind::Projection => None,
        other => Some(other.as_wire()),
    }
}

fn forbidden_generated_effect_wire(effect: vocab::HttpEffectKind) -> Option<&'static str> {
    match effect {
        vocab::HttpEffectKind::Read
        | vocab::HttpEffectKind::Auth
        | vocab::HttpEffectKind::Projection => None,
        other => Some(http_effect_wire(other)),
    }
}

fn canonical_effects(effects: &[vocab::HttpEffectKind]) -> Vec<String> {
    let mut effects = effects.to_vec();
    effects.sort_by_key(|effect| *effect as u8);
    effects
        .into_iter()
        .map(http_effect_wire)
        .map(ToString::to_string)
        .collect()
}

fn http_effect_wire(effect: vocab::HttpEffectKind) -> &'static str {
    match effect {
        vocab::HttpEffectKind::Read => "read",
        vocab::HttpEffectKind::Auth => "auth",
        vocab::HttpEffectKind::Projection => "projection",
        vocab::HttpEffectKind::BusinessWrite => "business-write",
        vocab::HttpEffectKind::BusinessTransaction => "business-transaction",
        vocab::HttpEffectKind::Outbox => "outbox",
        vocab::HttpEffectKind::Publish => "publish",
        vocab::HttpEffectKind::Workflow => "workflow",
        vocab::HttpEffectKind::Saga => "saga",
        vocab::HttpEffectKind::Reconcile => "reconcile",
        vocab::HttpEffectKind::Worker => "worker",
        vocab::HttpEffectKind::CrossTenantAudit => "cross-tenant-audit",
    }
}

fn consistency_wire(level: vocab::HttpConsistencyLevel) -> &'static str {
    match level {
        vocab::HttpConsistencyLevel::LocalOnly => "LocalOnly",
        vocab::HttpConsistencyLevel::LocalTx => "LocalTx",
        vocab::HttpConsistencyLevel::OutboxFact => "OutboxFact",
        vocab::HttpConsistencyLevel::WorkflowEventual => "WorkflowEventual",
        vocab::HttpConsistencyLevel::DeviceLatent => "DeviceLatent",
    }
}

fn mount_posture(
    mounts: Option<&BTreeSet<crate::localtx_coverage::CanonicalRouteMount>>,
) -> (MountStatus, Vec<String>) {
    let Some(mounts) = mounts else {
        return (MountStatus::Missing, Vec::new());
    };
    let sources = mounts.iter().map(|mount| mount.source.clone()).collect();
    let status = if mounts.len() == 1 {
        MountStatus::Mounted
    } else if mounts.is_empty() {
        MountStatus::Missing
    } else {
        MountStatus::Ambiguous
    };
    (status, sources)
}

fn report_finding(finding: &Finding) -> ReportFinding {
    ReportFinding {
        rule: match finding.rule {
            Rule::MissingRouteBinding => "missingRouteBinding",
            Rule::UnclassifiedState => "unclassifiedState",
            Rule::ForbiddenStateEffect => "forbiddenStateEffect",
            Rule::CrossTenantPrivilege => "crossTenantPrivilege",
            Rule::OpaqueSourceScope => "opaqueSourceScope",
            Rule::ForgedObservationEvidence => "forgedObservationEvidence",
            Rule::MissingLocalOnlyReceipt => "missingLocalOnlyReceipt",
        }
        .to_string(),
        subject: finding.subject.clone(),
        detail: finding.detail.clone(),
    }
}

fn proof_status_wire(status: ProofStatus) -> &'static str {
    match status {
        ProofStatus::Passed => "passed",
        ProofStatus::Failed => "failed",
        ProofStatus::NotApplicable => "notApplicable",
    }
}

fn source_receipt_registration_status_wire(
    status: SourceReceiptRegistrationStatus,
) -> &'static str {
    match status {
        SourceReceiptRegistrationStatus::Registered => "registered",
        SourceReceiptRegistrationStatus::Missing => "missing",
        SourceReceiptRegistrationStatus::NotApplicable => "notApplicable",
    }
}

fn mount_status_wire(status: MountStatus) -> &'static str {
    match status {
        MountStatus::Mounted => "mounted",
        MountStatus::Missing => "missing",
        MountStatus::Ambiguous => "ambiguous",
    }
}

fn option_state_wire(state: Option<StateKind>) -> &'static str {
    match state {
        Some(StateKind::Stateless) => "stateless",
        Some(StateKind::Ordinary) => "ordinary",
        Some(StateKind::Classified) => "classified",
        Some(StateKind::Opaque) => "opaque",
        None => "null",
    }
}

fn literal_cell(value: &str) -> String {
    let mut encoded = String::from("<code>");
    for character in value.replace("\r\n", "\n").replace('\r', "\n").chars() {
        encoded.push_str(match character {
            '\n' => "<br>",
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '|' => "&#124;",
            '\\' => "&#92;",
            '[' => "&#91;",
            ']' => "&#93;",
            '(' => "&#40;",
            ')' => "&#41;",
            '!' => "&#33;",
            '`' => "&#96;",
            '*' => "&#42;",
            '_' => "&#95;",
            '~' => "&#126;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                encoded.push(character);
                continue;
            }
        });
    }
    encoded.push_str("</code>");
    encoded
}
fn sanitized(root: &Path, error: anyhow::Error) -> anyhow::Error {
    anyhow!(format!("{error:#}").replace(root.to_string_lossy().as_ref(), "."))
}

#[cfg(test)]
fn test_http_spec(
    contract_id: &'static str,
    mount_key: &'static str,
    level: vocab::HttpConsistencyLevel,
    effects: &'static [vocab::HttpEffectKind],
) -> generated::http::HttpSpec {
    test_http_spec_with_owner(
        vocab::HttpContractOwner::domain("seed"),
        contract_id,
        mount_key,
        level,
        effects,
    )
}

#[cfg(test)]
fn test_http_spec_with_owner(
    owner: vocab::HttpContractOwner,
    contract_id: &'static str,
    mount_key: &'static str,
    level: vocab::HttpConsistencyLevel,
    effects: &'static [vocab::HttpEffectKind],
) -> generated::http::HttpSpec {
    generated::http::HttpSpec {
        mount_key,
        route: vocab::HttpRouteEvidence::from_static(
            owner,
            vocab::ContractBinding::from_static(
                "_seed",
                contract_id,
                "v1",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "/seed",
            "GET",
            vocab::HttpSuccessStatus::new(200),
            vocab::HttpIdempotency::Idempotent,
            vocab::HttpRouteAuth::Public,
            None,
            false,
            vocab::http::HttpResourceSharing::TenantScoped,
            level,
            vocab::HttpEffectProfile::new(effects),
        ),
        local_tx: None,
        resource_sharing: generated::http::HttpResourceSharingSpec {
            mode: vocab::http::HttpResourceSharing::TenantScoped,
            reason: None,
        },
        projection_fields: &[],
        headers: &[],
    }
}

#[cfg(test)]
fn empty_proof_source() -> ProofSource {
    ProofSource {
        states: BTreeMap::new(),
        structs: BTreeMap::new(),
        ports: BTreeMap::new(),
        type_aliases: BTreeMap::new(),
        bindings: BTreeMap::new(),
        trusted_port_macros: BTreeSet::new(),
    }
}

#[cfg(test)]
fn synthetic_report_fixture() -> ConsistencyReport {
    let escaped = ReportFinding {
        rule: "forbiddenStateEffect".to_string(),
        subject: "crates/demo/src/lib.rs:7".to_string(),
        detail: "escaped | cell\\path\nline [link](https://example.invalid) ![img](x) <em>raw</em> `tick` *strong* & amp".to_string(),
    };
    let missing = ReportFinding {
        rule: "missingRouteBinding".to_string(),
        subject: "z.remote".to_string(),
        detail: "canonical production Domain::init mount is missing".to_string(),
    };
    let missing_receipt = report_finding(&missing_receipt_finding("a.local"));
    let contracts = vec![
        ContractPosture {
            contract_id: "a.local".to_string(),
            owner: "demo".to_string(),
            method: "GET".to_string(),
            path: "/v1/a".to_string(),
            consistency_level: "LocalOnly".to_string(),
            effects: canonical_effects(&[
                vocab::HttpEffectKind::CrossTenantAudit,
                vocab::HttpEffectKind::Read,
            ]),
            route: RoutePosture {
                mount_status: MountStatus::Mounted,
                mount_sources: vec!["crates/demo/src/lib.rs:7".to_string()],
            },
            effect_proof: EffectProof {
                kind: ProofKind::LocalOnlyStatic,
                status: ProofStatus::Failed,
                state_kind: Some(StateKind::Classified),
                effect_class: Some("ReadEffect".to_string()),
                privilege_class: Some("LocalPrivilege".to_string()),
            },
            source_receipt_registration: SourceReceiptRegistration::fail_closed(
                SourceReceiptRegistrationStatus::Missing,
            ),
            findings: vec![escaped.clone(), missing_receipt.clone()],
        },
        ContractPosture {
            contract_id: "z.remote".to_string(),
            owner: "demo".to_string(),
            method: "POST".to_string(),
            path: "/v1/z".to_string(),
            consistency_level: "LocalTx".to_string(),
            effects: canonical_effects(&[
                vocab::HttpEffectKind::BusinessTransaction,
                vocab::HttpEffectKind::Auth,
            ]),
            route: RoutePosture {
                mount_status: MountStatus::Missing,
                mount_sources: Vec::new(),
            },
            effect_proof: EffectProof {
                kind: ProofKind::DeclarationOnly,
                status: ProofStatus::NotApplicable,
                state_kind: None,
                effect_class: None,
                privilege_class: None,
            },
            source_receipt_registration: SourceReceiptRegistration::fail_closed(
                SourceReceiptRegistrationStatus::NotApplicable,
            ),
            findings: vec![missing.clone()],
        },
    ];
    ConsistencyReport {
        schema_version: CONSISTENCY_REPORT_SCHEMA_VERSION,
        status: ReportStatus::Failed,
        active_http_contract_count: contracts.len(),
        local_only_receipt_coverage: LocalOnlyReceiptCoverage {
            enforcement: ReceiptCoverageEnforcement::FailClosed,
            evidence: ReceiptCoverageEvidence::SourceRegistered,
            status: ReceiptCoverageStatus::Partial,
            active_count: 1,
            registered_count: 0,
            missing_count: 1,
            missing_contracts: vec!["a.local".to_string()],
        },
        findings: vec![escaped, missing_receipt, missing],
        contracts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/consistency_effects")
            .join(name)
    }

    fn domain_scope() -> ServingScope {
        ServingScope::Domain("seed".to_string())
    }

    struct WorkspaceFixture(PathBuf);

    impl WorkspaceFixture {
        fn new() -> Result<Self> {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "rss-consistency-effects-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            copy_tree(&fixture("workspace"), &path)?;
            Ok(Self(path))
        }

        fn source(&self) -> PathBuf {
            self.0.join("crates/demo/src/lib.rs")
        }
        fn ports(&self) -> PathBuf {
            self.0.join("crates/demo/src/ports.rs")
        }
        fn replace(&self, file: &Path, from: &str, to: &str) -> Result<()> {
            let text = fs::read_to_string(file)?;
            if !text.contains(from) {
                bail!("fixture mutation source is missing: {from}");
            }
            fs::write(file, text.replacen(from, to, 1))?;
            Ok(())
        }

        fn cargo_check(&self) -> Result<std::process::Output> {
            let target = self.0.join("target");
            crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Check,
                &["--offline"],
                &[(
                    "CARGO_TARGET_DIR",
                    target
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture target path is not UTF-8"))?,
                )],
                Some(&self.0),
            )
            .arg("--manifest-path")
            .arg(self.0.join("Cargo.toml"))
            .output()
            .map_err(Into::into)
        }

        fn assert_compiles_and_is_rejected(&self) -> Result<Vec<Finding>> {
            let output = self.cargo_check()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let findings = check_root(&self.0)?.1;
            assert!(
                !findings.is_empty(),
                "compiling red fixture unexpectedly passed"
            );
            Ok(findings)
        }

        fn add_write_port(&self) -> Result<()> {
            self.replace(
                &self.ports(),
                "pub type DynReadRepo = dyn ReadRepo;",
                "pub type DynReadRepo = dyn ReadRepo; pub trait WriteRepo: Send + Sync {} pub type DynWriteRepo = dyn WriteRepo;",
            )?;
            self.replace(
                &self.ports(),
                "classify_demo_ports!(DynReadRepo => diport::ReadEffect);",
                "classify_demo_ports!(DynReadRepo => diport::ReadEffect); classify_demo_ports!(DynWriteRepo => diport::BusinessWriteEffect);",
            )
        }

        fn make_framework(&self, stateless: bool, global_read_capability: bool) -> Result<()> {
            let assembly = self.0.join("assemblies/runtime");
            copy_tree(&self.0.join("crates/demo"), &assembly)?;
            fs::remove_dir_all(self.0.join("crates/demo"))?;
            self.replace(
                &self.0.join("Cargo.toml"),
                "\"crates/demo\"",
                "\"assemblies/runtime\"",
            )?;
            self.replace(
                &assembly.join("Cargo.toml"),
                "name = \"demo\"",
                "name = \"runtime\"",
            )?;
            for dependency in ["bootstrap", "diport", "httpserve", "vocab"] {
                self.replace(
                    &assembly.join("Cargo.toml"),
                    &format!("path = \"../{dependency}\""),
                    &format!("path = \"../../crates/{dependency}\""),
                )?;
            }
            self.replace(
                &assembly.join("src/lib.rs"),
                "impl ::bootstrap::Domain for Demo",
                "impl ::bootstrap::FrameworkRoutes for Demo",
            )?;
            self.replace(
                &assembly.join("src/lib.rs"),
                "fn init(&self",
                "fn register(&self",
            )?;
            self.replace(
                &self.0.join("crates/bootstrap/src/lib.rs"),
                "pub trait Domain {",
                "pub trait FrameworkRoutes { fn register(&self, registry: &mut Registry) -> Result<(), httpserve::Error>; }\npub trait Domain {",
            )?;
            if stateless {
                self.replace(
                    &assembly.join("src/lib.rs"),
                    ".with_classified_state(state),",
                    ",",
                )?;
            }
            if global_read_capability {
                self.replace(
                    &self.0.join("crates/diport/src/lib.rs"),
                    "pub trait SubscribeInitializer: Send + Sync {}",
                    "pub trait SubscribeInitializer: Send + Sync {} pub trait ReadInitializer: Send + Sync {}",
                )?;
                self.replace(
                    &self.0.join("crates/diport/src/lib.rs"),
                    "sync SubscribeInitializer => WorkflowEffect;",
                    "sync SubscribeInitializer => WorkflowEffect; sync ReadInitializer => ReadEffect;",
                )?;
                self.replace(
                    &assembly.join("src/lib.rs"),
                    "struct ReadState { repo: Arc<DynReadRepo> }",
                    "struct ReadState { repo: Arc<dyn diport::ReadInitializer> }",
                )?;
            }
            self.replace(
                &self.0.join("contracts/http/demo/v1/safe/contract.toml"),
                "owner = \"demo\"",
                "owner = \"_framework\"",
            )?;
            fs::write(
                assembly.join("assembly.toml"),
                include_str!("../../assemblies/runtime/assembly.toml").replace(
                    "frameworkContracts = [{ id = \"runtime.inventory\", listener = \"admin\" }]",
                    "frameworkContracts = [{ id = \"demo.safe\", listener = \"admin\" }]",
                ),
            )?;
            Ok(())
        }

        fn make_framework_stateless(&self) -> Result<()> {
            self.make_framework(true, false)
        }

        fn make_framework_classified(&self, global_read_capability: bool) -> Result<()> {
            self.make_framework(false, global_read_capability)
        }

        fn make_framework_ordinary(&self) -> Result<()> {
            self.make_framework(false, false)?;
            self.replace(
                &self.0.join("assemblies/runtime/src/lib.rs"),
                ".with_classified_state(state),",
                ".with_state(state),",
            )
        }
    }

    impl Drop for WorkspaceFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn copy_tree(source: &Path, target: &Path) -> Result<()> {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let destination = target.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &destination)?;
            } else {
                fs::copy(entry.path(), destination)?;
            }
        }
        Ok(())
    }

    fn provenance_findings(source: &str) -> Result<Vec<Finding>> {
        let syntax = syn::parse_file(source)?;
        let recorded_provider_fields = collect_scoped_recorded_provider_fields(&syntax.items);
        let mut findings = Vec::new();
        provenance_findings_in_items(
            &syntax.items,
            "crates/demo/src/lib.rs",
            &recorded_provider_fields,
            &mut Vec::new(),
            &mut findings,
        );
        Ok(findings)
    }

    struct ReceiptWorkspace(PathBuf);

    impl std::ops::Deref for ReceiptWorkspace {
        type Target = Path;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for ReceiptWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl ReceiptWorkspace {
        fn cargo_check(&self) -> Result<std::process::Output> {
            let target = self.0.join("target");
            crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Check,
                &["--offline", "--tests"],
                &[(
                    "CARGO_TARGET_DIR",
                    target
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture target path is not UTF-8"))?,
                )],
                Some(&self.0),
            )
            .arg("--manifest-path")
            .arg(self.0.join("Cargo.toml"))
            .output()
            .map_err(Into::into)
        }
    }

    fn receipt_workspace(source: &str) -> Result<ReceiptWorkspace> {
        let root = crate::testutil::unique_tmp("local-only-receipt-source");
        fs::create_dir_all(root.join("crates/demo/src"))?;
        for (path, name) in [
            ("crates/testkit", "testkit"),
            ("crates/httpserve", "httpserve"),
            ("generated", "generated"),
        ] {
            fs::create_dir_all(root.join(path).join("src"))?;
            fs::write(
                root.join(path).join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"),
            )?;
            fs::write(root.join(path).join("src/lib.rs"), "")?;
        }
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/demo\", \"crates/testkit\", \"crates/httpserve\", \"generated\"]\nresolver = \"3\"\n",
        )?;
        fs::write(
            root.join("crates/demo/Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ngenerated = { path = \"../../generated\" }\nhttpserve = { path = \"../httpserve\" }\n\n[dev-dependencies]\ntokio = { version = \"1\", features = [\"macros\", \"rt\"] }\ntestkit = { path = \"../testkit\" }\n",
        )?;
        fs::write(root.join("crates/demo/src/lib.rs"), source)?;
        Ok(ReceiptWorkspace(root))
    }

    fn real_api_provenance_workspace(source: &str) -> Result<ReceiptWorkspace> {
        let fixture = crate::testutil::unique_tmp("local-only-real-proof-api");
        fs::create_dir_all(fixture.join("src"))?;
        let workspace = crate::workspace_root()?;
        fs::write(
            fixture.join("Cargo.toml"),
            format!(
                r#"[package]
name = "local-only-real-proof-api"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
axum = "0.8"
diport = {{ path = "{}" }}
generated = {{ path = "{}" }}
httpserve = {{ path = "{}", features = ["test-util"] }}
testkit = {{ path = "{}" }}
"#,
                workspace.join("crates/diport").display(),
                workspace.join("generated").display(),
                workspace.join("crates/httpserve").display(),
                workspace.join("crates/testkit").display(),
            ),
        )?;
        fs::write(fixture.join("src/lib.rs"), source)?;
        Ok(ReceiptWorkspace(fixture))
    }

    fn receipt_target(id: &str, module: &[&str]) -> LocalOnlyReceiptTarget {
        LocalOnlyReceiptTarget {
            contract_id: id.to_string(),
            module_path: module.iter().map(ToString::to_string).collect(),
        }
    }

    fn canonical_receipt_body(module: &str) -> String {
        let factory = format!("finalized_{}_router", module.replace("::", "_"));
        format!(
            r#"
    let repo_probe = Repo::default();
    let (router, proof) = self::{factory}(repo_probe.test_repo());
    let observers = ::testkit::local_only::LocalOnlyObservers::new(
        repo_probe.counter.handle(),
        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
    );
    let (output, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
        ::generated::http::{module}::LocalOnlyConformanceMarker,
        _,
        _,
        _,
    >(
        ::generated::http::{module}::SPEC.route.contract_id(),
        observers,
        move || ::testkit::call(
            router,
            ::testkit::ContractRequest::get(::generated::http::{module}::SPEC.route.path()),
        ),
    ).await.expect("LocalOnly conformance");
    ::core::assert_eq!(
        receipt.contract_id(),
        ::generated::http::{module}::SPEC.route.contract_id()
    );
    drop(output);
"#,
        )
    }

    fn canonical_receipt(module: &str) -> String {
        let factory = format!("finalized_{}_router", module.replace("::", "_"));
        let test_module = format!("receipt_{}", module.replace("::", "_"));
        format!(
            r#"
#[cfg(test)]
mod {test_module} {{
struct Counter;
impl Counter {{ fn handle(&self) {{}} fn record(&self) {{}} }}
struct Repo {{ counter: Counter }}
impl Repo {{
    fn default() -> Self {{ todo!() }}
    fn test_repo(&self) -> TestRepo {{ TestRepo::from_provider(Arc::new(self.clone())) }}
}}
struct TestRepo {{ read: () }}
impl TestRepo {{ fn from_provider<T>(provider: Arc<T>) -> Self {{ Self {{ read: consume(provider) }} }} }}
trait RecordedMutation {{ fn mutate(&self); }}
impl RecordedMutation for Repo {{ fn mutate(&self) {{ self.counter.record(); }} }}
struct DemoDomain {{ read_repo: () }}
impl DemoDomain {{ fn new(read_repo: ()) -> Self {{ Self {{ read_repo }} }} }}
impl bootstrap::Domain for DemoDomain {{
    fn init(&self, registry: &mut bootstrap::Registry) {{
        let scoped_repo = self.read_repo.clone();
        let state = ReadState {{ repo: scoped_repo.clone() }};
        mount(registry, state);
    }}
}}
fn {factory}(repo: TestRepo) -> (
    axum::Router,
    ::httpserve::LocalOnlyMountedRouteProof<
        ::generated::http::{module}::RouteMarker,
        ReadState,
    >,
) {{
    let domain = DemoDomain::new(repo.read);
    let mut registry = bootstrap::compose(&[&domain]).expect("compose");
    let finalized = registry.finalize_routes().expect("routes");
    let (_, routes) = finalized.into_iter().next().expect("listener");
    let proof = ::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(
        &routes,
        &::generated::http::{module}::ROUTE,
    ).expect("mounted proof");
    let router = ::httpserve::finalize_auth(routes, plan)
        .expect("finalized")
        .into_router_for_test();
    (router, proof)
}}
#[tokio::test]
async fn conforms_{}() {{
{}
}}
}}
"#,
            module.replace("::", "_"),
            canonical_receipt_body(module)
        )
    }

    fn canonical_identity_aggregate_receipt() -> String {
        let production = "struct ContractAuthorizer;\nimpl ContractAuthorizer {\n    fn new(_: (), _: (), _: (), _: ()) -> Self { Self }\n}\nstruct IdentityDomainDeps { roles: (), binding_reads: (), policies: (), resource_attribute_reads: () }\nstruct IdentityDomain { roles: (), policies: (), authorizer: ContractAuthorizer }\nstruct RolesListHandlerState { roles: () }\nimpl IdentityDomain {\n    fn new(deps: IdentityDomainDeps) -> Self {\n        let IdentityDomainDeps { roles, binding_reads, policies, resource_attribute_reads } = deps;\n        let authorizer = ContractAuthorizer::new(roles, binding_reads, policies, resource_attribute_reads);\n        Self { roles, policies, authorizer }\n    }\n}\nimpl bootstrap::Domain for IdentityDomain {\n    fn init(&self, registry: &mut bootstrap::Registry) {\n        let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };\n        mount(registry, roles);\n    }\n}\n";
        let receipt = canonical_receipt("identity_v1::profile")
            .replace(
                "struct TestRepo { read: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { read: consume(provider) } } }",
                "#[derive(Clone)]\nstruct TestRepo { roles: (), binding_reads: (), policies: (), resource_attribute_reads: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { roles: consume(provider.clone()), binding_reads: consume(provider.clone()), policies: consume(provider.clone()), resource_attribute_reads: consume(provider) } } }",
            )
            .replace(
                "struct DemoDomain { read_repo: () }\nimpl DemoDomain { fn new(read_repo: ()) -> Self { Self { read_repo } } }\nimpl bootstrap::Domain for DemoDomain {\n    fn init(&self, registry: &mut bootstrap::Registry) {\n        let scoped_repo = self.read_repo.clone();\n        let state = ReadState { repo: scoped_repo.clone() };\n        mount(registry, state);\n    }\n}",
                "",
            )
            .replace(
                "let domain = DemoDomain::new(repo.read);",
                "let other = repo.clone();\n    let domain = super::IdentityDomain::new(super::IdentityDomainDeps {\n        roles: repo.roles,\n        binding_reads: repo.binding_reads,\n        policies: repo.policies,\n        resource_attribute_reads: repo.resource_attribute_reads,\n    });",
            )
            .replace("ReadState", "RolesListHandlerState");
        format!("{production}{receipt}")
    }

    fn canonical_identity_common_aggregate_receipt() -> String {
        let production = r#"
struct IdentityDomainDeps {
    roles: (),
    binding_reads: (),
    policies: (),
    resource_attribute_reads: (),
}
struct RolesListHandlerState { roles: () }
struct PolicyQueryService { policies: () }
struct CommonIdentityRouteState {
    roles_list: RolesListHandlerState,
    policies_get: PolicyQueryService,
}
struct IdentityCommonDomain { roles: (), policies: () }
impl IdentityCommonDomain {
    fn new(roles: (), binding_reads: (), policies: (), resource_attribute_reads: ()) -> Self {
        consume((binding_reads, resource_attribute_reads));
        Self { roles, policies }
    }
    fn route_state(&self) -> CommonIdentityRouteState {
        CommonIdentityRouteState {
            roles_list: RolesListHandlerState { roles: Arc::clone(&self.roles) },
            policies_get: PolicyQueryService { policies: Arc::clone(&self.policies) },
        }
    }
}
struct IdentityDomain { common: IdentityCommonDomain }
impl IdentityDomain {
    fn new(deps: IdentityDomainDeps) -> Self {
        let IdentityDomainDeps {
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
        } = deps;
        Self {
            common: IdentityCommonDomain::new(
                roles,
                binding_reads,
                policies,
                resource_attribute_reads,
            ),
        }
    }
}
impl bootstrap::Domain for IdentityDomain {
    fn init(&self, registry: &mut bootstrap::Registry) {
        let common = self.common.route_state();
        registry.route_group(move |rb| mount_common_identity_routes(rb, common));
    }
}
"#;
        let receipt = canonical_receipt("identity_v1::profile")
            .replace(
                "struct TestRepo { read: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { read: consume(provider) } } }",
                "#[derive(Clone)]\nstruct TestRepo { roles: (), binding_reads: (), policies: (), resource_attribute_reads: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { roles: consume(provider.clone()), binding_reads: consume(provider.clone()), policies: consume(provider.clone()), resource_attribute_reads: consume(provider) } } }",
            )
            .replace(
                "struct DemoDomain { read_repo: () }\nimpl DemoDomain { fn new(read_repo: ()) -> Self { Self { read_repo } } }\nimpl bootstrap::Domain for DemoDomain {\n    fn init(&self, registry: &mut bootstrap::Registry) {\n        let scoped_repo = self.read_repo.clone();\n        let state = ReadState { repo: scoped_repo.clone() };\n        mount(registry, state);\n    }\n}",
                "",
            )
            .replace(
                "let domain = DemoDomain::new(repo.read);",
                "let domain = super::IdentityDomain::new(super::IdentityDomainDeps {\n        roles: repo.roles,\n        binding_reads: repo.binding_reads,\n        policies: repo.policies,\n        resource_attribute_reads: repo.resource_attribute_reads,\n    });",
            )
            .replace("ReadState", "RolesListHandlerState");
        format!("{production}{receipt}")
    }

    fn canonical_settings_receipt() -> String {
        let production = r#"
#[derive(Clone)]
struct ConfigQueryService { configs: (), cache: () }
impl ConfigQueryService {
    fn new(configs: (), cache: ()) -> Self { Self { configs, cache } }
    async fn get_config(&self) {
        self.configs.head();
        self.cache.find();
        self.configs.find_version(scope, &key, active_version);
    }
}
struct SettingsService { query: ConfigQueryService }
impl SettingsService {
    fn with_postgres(configs: (), writer: (), flags: (), clock: ()) -> Self {
        let configs = Arc::from(configs);
        let cache = make_cache();
        consume((writer, flags, clock));
        Self { query: ConfigQueryService::new(configs, cache) }
    }
    fn config_query_service(&self) -> ConfigQueryService { self.query.clone() }
}
struct SettingsDomain { config: Arc<SettingsService>, config_query: ConfigQueryService }
impl SettingsDomain {
    fn new(config: Arc<SettingsService>) -> Self { let config_query = config.config_query_service(); Self { config, config_query } }
}
impl bootstrap::Domain for SettingsDomain {
    fn init(&self, registry: &mut bootstrap::Registry) { let config_query = self.config_query.clone(); mount(registry, config_query); endpoint.with_classified_state(config_query); }
}
"#;
        let receipt = canonical_receipt("settings_v4")
            .replace(
                "::generated::http::settings_v4::SPEC.route.path()",
                "::generated::http::settings_v4::SPEC.route.path().replace(\"{key}\", \"app.k\")",
            )
            .replace(
                "struct TestRepo { read: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { read: consume(provider) } } }",
                "struct TestRepo { configs: () }\nimpl TestRepo { fn from_provider<T>(provider: Arc<T>) -> Self { Self { configs: DynConfigRepo::new_box(provider.as_ref().clone()) } } }",
            )
            .replace(
                "struct DemoDomain { read_repo: () }\nimpl DemoDomain { fn new(read_repo: ()) -> Self { Self { read_repo } } }\nimpl bootstrap::Domain for DemoDomain {\n    fn init(&self, registry: &mut bootstrap::Registry) {\n        let scoped_repo = self.read_repo.clone();\n        let state = ReadState { repo: scoped_repo.clone() };\n        mount(registry, state);\n    }\n}",
                "",
            )
            .replace(
                "let domain = DemoDomain::new(repo.read);",
                "let config = Arc::new(super::SettingsService::with_postgres(repo.configs, writer(), flags(), clock()));\n    let domain = super::SettingsDomain::new(config, secret_repo(), secret_uow(), secret_svc());",
            )
            .replace("ReadState", "ConfigQueryService");
        format!("{production}{receipt}")
    }

    const CANONICAL_SETTINGS_COMPOSITION: &str = r#"
pub async fn wire(deps: SettingsModuleDeps) {
    let SettingsModuleDeps { pg, clock } = deps;
    let service_clock = Arc::clone(&clock);
    let (configs, writer, secrets, secret_writer) = pg
        .settings_bundle(clock, protections)
        .into_parts();
    let config_svc = SettingsService::with_postgres(
        configs,
        writer,
        empty_flag_store(),
        Box::new(SharedClock(service_clock)),
    );
    let secret_repo = Arc::from(secrets);
    let secret_uow = Arc::from(secret_writer);
    let secret_svc = build_secret_service();
    let domain = SettingsDomain::new(Arc::new(config_svc), secret_repo, secret_uow, secret_svc);
    consume(domain);
}
"#;

    fn settings_receipt_inventory(
        source: &str,
        composition: &str,
    ) -> Result<Vec<ParsedLocalOnlySource>> {
        let workspace = receipt_workspace(source)?;
        let mut inventory = local_only_source_inventory(&workspace)?;
        let syntax = syn::parse_file(composition)?;
        inventory.push(ParsedLocalOnlySource {
            subject: "composition/settings/src/lib.rs".to_string(),
            package: "settings-composition-fixture".to_string(),
            test_module_prefix: None,
            scoped_recorded_provider_fields: collect_scoped_recorded_provider_fields(&syntax.items),
            canonical_test_repo_fields: collect_canonical_test_repo_fields(&syntax.items),
            receipt_namespace_error: None,
            syntax,
        });
        Ok(inventory)
    }

    fn compile_valid_identity_lineage_reds() -> Vec<(&'static str, String)> {
        let production = r#"
use std::sync::Arc;
#[derive(Clone)]
struct Repo { roles: Arc<()>, policies: Arc<()> }
struct IdentityDomainDeps { roles: Arc<()>, policies: Arc<()> }
struct IdentityDomain { roles: Arc<()>, policies: Arc<()> }
struct RolesListHandlerState { roles: Arc<()> }
impl IdentityDomain {
    fn new(deps: IdentityDomainDeps) -> Self {
        let IdentityDomainDeps { roles, policies } = deps;
        Self { roles, policies }
    }
    fn init(&self) {
        let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };
        let _ = roles;
    }
}
"#;
        let nested_same_name = format!(
            r#"{production}
mod receipt {{
    use super::{{Repo, RolesListHandlerState}};
    struct IdentityDomainDeps {{ roles: std::sync::Arc<()>, policies: std::sync::Arc<()> }}
    struct IdentityDomain {{ roles: std::sync::Arc<()>, policies: std::sync::Arc<()> }}
    impl IdentityDomain {{
        fn new(deps: IdentityDomainDeps) -> Self {{
            let IdentityDomainDeps {{ roles, policies }} = deps;
            Self {{ roles, policies }}
        }}
        fn init(&self) {{
            let roles = RolesListHandlerState {{ roles: self.roles.clone() }};
            let _ = roles;
        }}
    }}
    fn factory(repo: Repo) {{
        let domain = IdentityDomain::new(IdentityDomainDeps {{ roles: repo.roles, policies: repo.policies }});
        domain.init();
    }}
}}
"#,
        );
        let type_alias_shadow = format!(
            r#"{production}
mod receipt {{
    type IdentityDomain = super::IdentityDomain;
    type IdentityDomainDeps = super::IdentityDomainDeps;
    fn factory(repo: super::Repo) {{
        let domain = IdentityDomain::new(IdentityDomainDeps {{ roles: repo.roles, policies: repo.policies }});
        domain.init();
    }}
}}
"#,
        );
        let init_mutable_reassigned_alias = production.replace(
            "let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };",
            "let mut roles_repo = self.roles.clone();\n        roles_repo = self.roles.clone();\n        let roles = RolesListHandlerState { roles: roles_repo.clone() };",
        );
        let init_method_wrapper = production.replace(
            "let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };",
            "let roles_repo = self.roles.clone();\n        let roles = RolesListHandlerState { roles: roles_repo };",
        );
        let mut reds = vec![
            ("nested same-name IdentityDomain", nested_same_name),
            ("type alias shadow", type_alias_shadow),
            (
                "init mutable reassigned alias",
                init_mutable_reassigned_alias,
            ),
            ("init method wrapper", init_method_wrapper),
        ];
        let provider_swap_base = r#"
use std::sync::Arc;
#[derive(Clone)]
struct Repo {
    roles: Arc<()>,
    binding_reads: Arc<()>,
    policies: Arc<()>,
    resource_attribute_reads: Arc<()>,
}
struct IdentityDomainDeps {
    roles: Arc<()>,
    binding_reads: Arc<()>,
    policies: Arc<()>,
    resource_attribute_reads: Arc<()>,
}
struct ContractAuthorizer;
impl ContractAuthorizer {
    fn new(_: Arc<()>, _: Arc<()>, _: Arc<()>, _: Arc<()>) -> Self { Self }
}
struct IdentityDomain {
    roles: Arc<()>,
    policies: Arc<()>,
    authorizer: ContractAuthorizer,
}
impl IdentityDomain {
    fn new(deps: IdentityDomainDeps) -> Self {
        let IdentityDomainDeps {
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
        } = deps;
        let authorizer = ContractAuthorizer::new(
            Arc::clone(&roles),
            binding_reads,
            Arc::clone(&policies),
            resource_attribute_reads,
        );
        Self { roles, policies, authorizer }
    }
}
fn factory(repo: Repo) {
    let other = repo.clone();
    let domain = IdentityDomain::new(IdentityDomainDeps {
        roles: repo.roles,
        binding_reads: repo.binding_reads,
        policies: repo.policies,
        resource_attribute_reads: repo.resource_attribute_reads,
    });
    let _ = domain;
}
"#;
        for (name, canonical, swapped) in [
            (
                "roles provider swap",
                "roles: repo.roles",
                "roles: other.roles",
            ),
            (
                "binding reads provider swap",
                "binding_reads: repo.binding_reads",
                "binding_reads: other.binding_reads",
            ),
            (
                "policies provider swap",
                "policies: repo.policies",
                "policies: other.policies",
            ),
            (
                "resource attributes provider swap",
                "resource_attribute_reads: repo.resource_attribute_reads",
                "resource_attribute_reads: other.resource_attribute_reads",
            ),
        ] {
            reds.push((name, provider_swap_base.replace(canonical, swapped)));
        }
        reds
    }

    const COMPILE_VALID_RECEIPT_REDS: &str = r#"
extern crate self as generated;
extern crate self as testkit;

pub mod local_only {
    use core::{future::Future, marker::PhantomData};

    pub struct Receipt<Marker> {
        marker: PhantomData<Marker>,
    }

    impl<Marker> Receipt<Marker> {
        pub fn contract_id(&self) -> &'static str { "identity.profile" }
    }

    pub async fn assert_local_only_with_receipt<Marker, Operation, OperationFuture, T>(
        _: &'static str,
        _: (),
        operation: Operation,
    ) -> Result<(T, Receipt<Marker>), ()>
    where
        Operation: FnOnce() -> OperationFuture,
        OperationFuture: Future<Output = T>,
    {
        Ok((operation().await, Receipt { marker: PhantomData }))
    }
}

pub mod http {
    pub struct Route;
    impl Route { pub const fn contract_id(&self) -> &'static str { "identity.profile" } }
    pub struct Spec { pub route: Route }
    pub mod identity_v1 {
        pub mod profile {
            pub enum LocalOnlyConformanceMarker {}
            pub const SPEC: super::super::Spec = super::super::Spec { route: super::super::Route };
        }
    }
}

#[tokio::test]
async fn ignored_result_is_valid_rust() {
    let _result = ::testkit::local_only::assert_local_only_with_receipt::<
        ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
        _, _, _,
    >(
        ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
        (),
        || async {},
    ).await;
}

#[tokio::test]
async fn branch_is_valid_rust() {
    if true {
        let (output, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
            _, _, _,
        >(
            ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
            (),
            || async {},
        ).await.expect("receipt");
        assert_eq!(receipt.contract_id(), "identity.profile");
        let _ = output;
    }
}

macro_rules! hidden_receipt {
    () => {{
        let (output, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
            _, _, _,
        >(
            ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
            (),
            || async {},
        ).await.expect("receipt");
        assert_eq!(receipt.contract_id(), "identity.profile");
        let _ = output;
    }};
}

#[tokio::test]
async fn macro_is_valid_rust() { hidden_receipt!(); }

#[tokio::test]
async fn async_closure_spawn_are_valid_rust() {
    async { hidden_receipt!(); }.await;
    let proof = || async { hidden_receipt!(); };
    proof().await;
    tokio::spawn(async { hidden_receipt!(); }).await.expect("join");
}

#[tokio::test]
async fn control_flow_blocks_are_valid_rust() {
    if true { hidden_receipt!(); }
    for _ in 0..1 { hidden_receipt!(); }
    match 1 { 1 => hidden_receipt!(), _ => {} }
    unsafe { hidden_receipt!(); }
}

#[tokio::test]
async fn try_is_valid_rust() -> Result<(), ()> {
    async { hidden_receipt!(); Ok(()) }.await?;
    Ok(())
}

#[tokio::test]
async fn const_factory_is_valid_rust() {
    let proof = const { || async { hidden_receipt!(); } };
    proof().await;
}

#[tokio::test]
#[ignore]
async fn ignored_test_is_valid_rust() { hidden_receipt!(); }

#[cfg(any())]
#[tokio::test]
async fn cfg_test_is_valid_rust() { hidden_receipt!(); }
"#;

    const GOVERNED_PROVENANCE: &str = r#"
struct Repo { counter: ::testkit::local_only::ProviderCounter<::testkit::local_only::BusinessWrite> }
impl Repo {
    fn default() -> Self { Self { counter: ::testkit::local_only::ProviderCounter::business_write() } }
    fn test_repo(&self) {}
}
trait RecordedMutation { fn mutate(&self); }
impl RecordedMutation for Repo { fn mutate(&self) { self.counter.record(); } }
#[derive(Clone)]
struct ReadState;
impl ::httpserve::ClassifiedRouteState for ReadState {
    type Effect = ::diport::ReadEffect;
    type Privilege = ::diport::LocalPrivilege;
}
fn finalized_scoped_router(_: ()) -> axum::Router { axum::Router::new() }
fn conforms() {
    let repo_probe = Repo::default();
    let router = finalized_scoped_router(repo_probe.test_repo());
    let routes = ::httpserve::UnfinalizedRoutes::empty();
    let proof = ::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(
        &routes,
        &::generated::http::identity_v1::profile::ROUTE,
    ).expect("mounted proof");
    let outbox = ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof);
    let publish = ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof);
    let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);
    let _response = ::testkit::call(
        router,
        ::testkit::ContractRequest::get(
            ::generated::http::identity_v1::profile::SPEC.route.path(),
        ),
    );
}
"#;

    #[test]
    fn router_factory_rejects_behavioral_layers() -> Result<()> {
        for (name, source) in [
            (
                "short circuit",
                "::httpserve::finalize_auth(routes, plan).expect(\"finalized\").layer(axum::middleware::from_fn(|_request, _next| async { axum::http::StatusCode::NO_CONTENT })).into_router_for_test()",
            ),
            (
                "response replacement",
                "::httpserve::finalize_auth(routes, plan).expect(\"finalized\").layer(axum::middleware::from_fn(|request, next| async move { let _response = next.run(request).await; axum::http::StatusCode::NO_CONTENT })).into_router_for_test()",
            ),
            (
                "unobserved side effect",
                "::httpserve::finalize_auth(routes, plan).expect(\"finalized\").layer(axum::middleware::from_fn(|request, next| async move { SIDE_EFFECT.fetch_add(1, Ordering::SeqCst); next.run(request).await })).into_router_for_test()",
            ),
            (
                "relative Extension path is shadowable",
                "::httpserve::finalize_auth(routes, plan).expect(\"finalized\").layer(axum::Extension(value)).into_router_for_test()",
            ),
        ] {
            let expression = syn::parse_str::<Expr>(source)?;
            assert!(
                finalized_router_routes(&expression).is_none(),
                "{name} layer unexpectedly certified"
            );
        }
        Ok(())
    }

    #[test]
    fn router_factory_accepts_absolute_axum_extensions() -> Result<()> {
        let expression = syn::parse_str::<Expr>(
            "::httpserve::finalize_auth(routes, plan).expect(\"finalized\").layer(::axum::Extension(first)).layer(::axum::Extension(second)).into_router_for_test()",
        )?;
        assert_eq!(
            finalized_router_routes(&expression).as_deref(),
            Some("routes")
        );
        Ok(())
    }

    #[test]
    fn governed_proof_constructor_uses_current_mounted_api() -> Result<()> {
        let current = syn::parse_str::<Expr>(
            "::httpserve::prove_stateless_local_only_mounted_route(&routes, &::generated::http::identity_v1::profile::ROUTE).expect(\"mounted\")",
        )?;
        assert!(is_governed_proof_constructor(&current));
        Ok(())
    }

    #[test]
    fn receipt_execution_shape_reds_are_rust_compile_valid() -> Result<()> {
        let workspace = receipt_workspace(COMPILE_VALID_RECEIPT_REDS)?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            local_only_receipt_registration(
                &workspace,
                &[receipt_target(
                    "identity.profile",
                    &["identity_v1", "profile"]
                )]
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn identity_aggregate_lineage_accepts_only_canonical_direct_fields() -> Result<()> {
        let canonical = canonical_identity_aggregate_receipt();
        let targets = [receipt_target(
            "identity.profile",
            &["identity_v1", "profile"],
        )];
        let workspace = receipt_workspace(&canonical)?;
        let registration = local_only_receipt_registration(&workspace, &targets)?;
        assert_eq!(
            registration.registered_contracts,
            BTreeSet::from(["identity.profile".to_string()])
        );

        for (name, source) in compile_valid_identity_lineage_reds() {
            let workspace = receipt_workspace(&source)?;
            let output = workspace.cargo_check()?;
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let wrong_field = canonical
            .replace("roles: repo.roles,", "roles: repo.policies,")
            .replace("policies: repo.policies,", "policies: repo.roles,");
        let provider_swap_roles = canonical.replace("roles: repo.roles,", "roles: other.roles,");
        let provider_swap_bindings = canonical.replace(
            "binding_reads: repo.binding_reads,",
            "binding_reads: other.binding_reads,",
        );
        let provider_swap_policies =
            canonical.replace("policies: repo.policies,", "policies: other.policies,");
        let provider_swap_resource_attributes = canonical.replace(
            "resource_attribute_reads: repo.resource_attribute_reads,",
            "resource_attribute_reads: other.resource_attribute_reads,",
        );
        let mutable_alias = canonical.replace(
            "let domain = super::IdentityDomain::new(super::IdentityDomainDeps {\n        roles: repo.roles,\n        binding_reads: repo.binding_reads,\n        policies: repo.policies,\n        resource_attribute_reads: repo.resource_attribute_reads,\n    });",
            "let mut deps = IdentityDomainDeps {\n        roles: repo.roles,\n        binding_reads: repo.binding_reads,\n        policies: repo.policies,\n        resource_attribute_reads: repo.resource_attribute_reads,\n    };\n    let deps_alias = deps;\n    let domain = IdentityDomain::new(deps_alias);",
        );
        let test_domain = canonical
            .replace("struct IdentityDomain {", "struct TestIdentityDomain {")
            .replace("impl IdentityDomain {", "impl TestIdentityDomain {")
            .replace(
                "impl bootstrap::Domain for IdentityDomain {",
                "impl bootstrap::Domain for TestIdentityDomain {",
            )
            .replace(
                "let domain = IdentityDomain::new(IdentityDomainDeps {",
                "let domain = TestIdentityDomain::new(IdentityDomainDeps {",
            );
        let nested_same_name = canonical
            .replace(
                "struct Counter;",
                "struct IdentityDomainDeps { roles: (), policies: () }\nstruct IdentityDomain { roles: (), policies: () }\nimpl IdentityDomain {\n    fn new(deps: IdentityDomainDeps) -> Self {\n        let IdentityDomainDeps { roles, policies } = deps;\n        Self { roles, policies }\n    }\n}\nimpl bootstrap::Domain for IdentityDomain {\n    fn init(&self, registry: &mut bootstrap::Registry) {\n        let roles = super::RolesListHandlerState { roles: self.roles.clone() };\n        mount(registry, roles);\n    }\n}\nstruct Counter;",
            )
            .replace(
                "super::IdentityDomain::new(super::IdentityDomainDeps {",
                "IdentityDomain::new(IdentityDomainDeps {",
            );
        let type_alias_shadow = canonical
            .replace(
                "struct Counter;",
                "type IdentityDomain = super::IdentityDomain;\ntype IdentityDomainDeps = super::IdentityDomainDeps;\nstruct Counter;",
            )
            .replace(
                "super::IdentityDomain::new(super::IdentityDomainDeps {",
                "IdentityDomain::new(IdentityDomainDeps {",
            );
        let init_mutable_reassigned_alias = canonical.replace(
            "let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };",
            "let mut roles_repo = self.roles.clone();\n        roles_repo = self.roles.clone();\n        let roles = RolesListHandlerState { roles: roles_repo.clone() };",
        );
        let init_method_wrapper = canonical.replace(
            "let roles = RolesListHandlerState { roles: Arc::clone(&self.roles) };",
            "let roles_repo = self.roles.clone();\n        let roles = RolesListHandlerState { roles: roles_repo };",
        );
        for (name, source) in [
            ("wrong aggregate field", wrong_field),
            ("mutable alias wrapper", mutable_alias),
            ("test-only Domain", test_domain),
            ("nested same-name IdentityDomain", nested_same_name),
            ("type alias shadow", type_alias_shadow),
            (
                "init mutable reassigned alias",
                init_mutable_reassigned_alias,
            ),
            ("init method wrapper", init_method_wrapper),
        ] {
            let workspace = receipt_workspace(&source)?;
            assert!(
                local_only_receipt_registration(&workspace, &targets).is_err(),
                "{name} unexpectedly certified"
            );
        }
        for (name, source) in [
            ("roles provider swap", provider_swap_roles),
            ("binding reads provider swap", provider_swap_bindings),
            ("policies provider swap", provider_swap_policies),
            (
                "resource attributes provider swap",
                provider_swap_resource_attributes,
            ),
        ] {
            let workspace = receipt_workspace(&source)?;
            assert!(
                local_only_receipt_registration(&workspace, &targets).is_err(),
                "{name} unexpectedly certified"
            );
        }
        Ok(())
    }

    #[test]
    fn identity_common_domain_lineage_is_live_and_fail_closed() -> Result<()> {
        let canonical = canonical_identity_common_aggregate_receipt();
        let targets = [receipt_target(
            "identity.profile",
            &["identity_v1", "profile"],
        )];
        let workspace = receipt_workspace(&canonical)?;
        let registration = local_only_receipt_registration(&workspace, &targets)?;
        assert_eq!(
            registration.registered_contracts,
            BTreeSet::from(["identity.profile".to_string()])
        );

        for (name, source) in [
            (
                "route state reads a different common field",
                canonical.replace(
                    "roles: Arc::clone(&self.roles)",
                    "roles: Arc::clone(&self.policies)",
                ),
            ),
            (
                "aggregate drops the roles provider",
                canonical.replacen(
                    "                roles,\n                binding_reads,",
                    "                policies,\n                binding_reads,",
                    1,
                ),
            ),
            (
                "common state is not mounted",
                canonical.replace(
                    "registry.route_group(move |rb| mount_common_identity_routes(rb, common));",
                    "consume((registry, common));",
                ),
            ),
            (
                "common implementation is cfg gated",
                canonical.replace(
                    "impl IdentityCommonDomain {",
                    "#[cfg(test)]\nimpl IdentityCommonDomain {",
                ),
            ),
        ] {
            let workspace = receipt_workspace(&source)?;
            assert!(
                local_only_receipt_registration(&workspace, &targets).is_err(),
                "{name} must be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn local_only_receipt_coverage_rejects_noncanonical_sources() -> Result<()> {
        let canonical = canonical_receipt("identity_v1::profile");
        let targets = [receipt_target(
            "identity.profile",
            &["identity_v1", "profile"],
        )];
        let workspace = receipt_workspace(&canonical)?;
        let registration = local_only_receipt_registration(&workspace, &targets)?;
        assert_eq!(
            registration.registered_contracts,
            BTreeSet::from(["identity.profile".to_string()])
        );

        let stateless = canonical
            .replace(
                "::httpserve::LocalOnlyMountedRouteProof<\n        ::generated::http::identity_v1::profile::RouteMarker,\n        ReadState,\n    >",
                "::httpserve::StatelessLocalOnlyMountedRouteProof<\n        ::generated::http::identity_v1::profile::RouteMarker,\n    >",
            )
            .replace(
                "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
                "::httpserve::prove_stateless_local_only_mounted_route(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
            )
            .replace(
                "repo_probe.counter.handle()",
                "::testkit::local_only::StaticExclusion::<::testkit::local_only::BusinessWrite>::from_governed(&proof)",
            );
        let stateless_workspace = receipt_workspace(&stateless)?;
        let stateless_registration =
            local_only_receipt_registration(&stateless_workspace, &targets)?;
        assert_eq!(
            stateless_registration.registered_contracts,
            BTreeSet::from(["identity.profile".to_string()])
        );

        let body = canonical_receipt_body("identity_v1::profile");
        let cases = [
            (
                "use alias shadows axum Extension",
                format!(
                    "use evil as axum;\n{}",
                    canonical.replace(
                        ".expect(\"finalized\")\n        .into_router_for_test()",
                        ".expect(\"finalized\")\n        .layer(axum::Extension(value))\n        .into_router_for_test()",
                    )
                ),
            ),
            (
                "local module shadows axum Extension",
                format!(
                    "mod axum {{ fn Extension<T>(value: T) -> T {{ value }} }}\n{}",
                    canonical.replace(
                        ".expect(\"finalized\")\n        .into_router_for_test()",
                        ".expect(\"finalized\")\n        .layer(axum::Extension(value))\n        .into_router_for_test()",
                    )
                ),
            ),
            (
                "extern crate alias shadows absolute axum root",
                format!("extern crate evil as axum;\n{canonical}"),
            ),
            (
                "custom assertion",
                canonical.replace(
                    "::testkit::local_only::assert_local_only_with_receipt",
                    "::custom::assert_local_only_with_receipt",
                ),
            ),
            (
                "marker/spec mismatch",
                canonical.replace(
                    "::generated::http::identity_v1::profile::SPEC.route.contract_id()",
                    "::generated::http::identity_v1::roles_list::SPEC.route.contract_id()",
                ),
            ),
            (
                "bare contract id",
                canonical.replace(
                    "::generated::http::identity_v1::profile::SPEC.route.contract_id()",
                    "\"identity.profile\"",
                ),
            ),
            (
                "not awaited",
                r#"
#[tokio::test]
async fn not_awaited() {
    let future = ::testkit::local_only::assert_local_only_with_receipt::<
        ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
        _, _, _,
    >(
        ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
        observers,
        operation,
    );
    drop(future);
}
"#
                .to_string(),
            ),
            (
                "ignored Result",
                r#"
#[tokio::test]
async fn ignored_result() {
    let _result = ::testkit::local_only::assert_local_only_with_receipt::<
        ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
        _, _, _,
    >(
        ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
        observers,
        operation,
    ).await;
}
"#
                .to_string(),
            ),
            (
                "bare await",
                r#"
#[tokio::test]
async fn bare_await() {
    ::testkit::local_only::assert_local_only_with_receipt::<
        ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
        _, _, _,
    >(
        ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
        observers,
        operation,
    ).await;
}
"#
                .to_string(),
            ),
            (
                "receipt not asserted",
                format!(
                    "#[tokio::test]\nasync fn unread_receipt() {{ {} }}",
                    body.replace(
                        "    ::core::assert_eq!(\n        receipt.contract_id(),\n        ::generated::http::identity_v1::profile::SPEC.route.contract_id()\n    );",
                        "    drop(receipt);",
                    )
                ),
            ),
            (
                "receipt asserted against wrong contract",
                canonical.replace(
                    "receipt.contract_id(),\n        ::generated::http::identity_v1::profile::SPEC.route.contract_id()",
                    "receipt.contract_id(),\n        ::generated::http::identity_v1::roles_list::SPEC.route.contract_id()",
                ),
            ),
            (
                "import alias",
                format!(
                    "use testkit::local_only::assert_local_only_with_receipt as receipt;\n{canonical}"
                ),
            ),
            (
                "function item alias",
                r#"
#[tokio::test]
async fn alias_call() {
    let receipt = ::testkit::local_only::assert_local_only_with_receipt;
    let _result = receipt::<
        ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
        _,
        _,
        _,
    >(
        ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
        observers,
        operation,
    ).await;
}
"#
                .to_string(),
            ),
            (
                "nested helper inherits no test authority",
                r#"
#[tokio::test]
async fn outer() {
    async fn helper() {
        let _result = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::profile::SPEC.route.contract_id(),
            observers,
            operation,
        ).await;
    }
    helper().await;
}
"#
                .to_string(),
            ),
            (
                "async block",
                format!(
                    "#[tokio::test]\nasync fn hidden_async() {{ async move {{ {body} }}.await; }}"
                ),
            ),
            (
                "closure",
                format!(
                    "#[tokio::test]\nasync fn hidden_closure() {{ let proof = || async {{ {body} }}; proof().await; }}"
                ),
            ),
            (
                "spawn",
                format!(
                    "#[tokio::test]\nasync fn hidden_spawn() {{ let task = tokio::spawn(async move {{ {body} }}); task.await.expect(\"join\"); }}"
                ),
            ),
            (
                "if branch",
                format!("#[tokio::test]\nasync fn hidden_if() {{ if true {{ {body} }} }}"),
            ),
            (
                "loop",
                format!("#[tokio::test]\nasync fn hidden_loop() {{ for _ in 0..1 {{ {body} }} }}"),
            ),
            (
                "match",
                format!("#[tokio::test]\nasync fn hidden_match() {{ match 1 {{ 1 => {{ {body} }}, _ => {{}} }} }}"),
            ),
            (
                "try operator",
                format!(
                    "#[tokio::test]\nasync fn hidden_try() -> Result<(), Error> {{ async move {{ {body} Ok(()) }}.await?; Ok(()) }}"
                ),
            ),
            (
                "unsafe block",
                format!("#[tokio::test]\nasync fn hidden_unsafe() {{ unsafe {{ {body} }} }}"),
            ),
            (
                "const block",
                format!(
                    "#[tokio::test]\nasync fn hidden_const() {{ let _proof = const {{ || async {{ {body} }} }}; }}"
                ),
            ),
            (
                "macro",
                format!(
                    "macro_rules! hidden_receipt {{ () => {{ {body} }} }}\n#[tokio::test]\nasync fn hidden_macro() {{ hidden_receipt!(); }}"
                ),
            ),
            (
                "cfg test",
                canonical.replacen("#[tokio::test]", "#[cfg(any())]\n#[tokio::test]", 1),
            ),
            (
                "ignored test",
                canonical.replacen("#[tokio::test]", "#[tokio::test]\n#[ignore]", 1),
            ),
            (
                "custom terminal test attribute",
                canonical.replacen("#[tokio::test]", "#[custom::test]", 1),
            ),
            (
                "wrapper",
                canonical.replace("#[tokio::test]", "#[allow(dead_code)]"),
            ),
            (
                "forged receipt",
                format!(
                    "fn forge(value: ::testkit::local_only::LocalOnlyConformanceReceipt<Fake>) {{ drop(value); }}\n{canonical}"
                ),
            ),
            (
                "no-op operation",
                canonical.replace(
                    "move || ::testkit::call(\n            router,\n            ::testkit::ContractRequest::get(::generated::http::identity_v1::profile::SPEC.route.path()),\n        )",
                    "move || async {}",
                ),
            ),
            (
                "wrong operation path",
                canonical.replacen(
                    "::generated::http::identity_v1::profile::SPEC.route.path()",
                    "::generated::http::identity_v1::roles_list::SPEC.route.path()",
                    1,
                ),
            ),
            (
                "wrong operation method",
                canonical.replace("::testkit::ContractRequest::get", "::testkit::ContractRequest::post"),
            ),
            (
                "wrong route proof",
                canonical.replace(
                    "&::generated::http::identity_v1::profile::ROUTE",
                    "&::generated::http::identity_v1::roles_list::ROUTE",
                ),
            ),
            (
                "wrong-but-finalized router",
                canonical
                    .replace(
                        "let (_, routes) = finalized.into_iter().next().expect(\"listener\");",
                        "let (_, routes) = finalized.into_iter().next().expect(\"listener\");\n    let wrong_finalized = registry.finalize_routes().expect(\"wrong routes\");\n    let (_, wrong_routes) = wrong_finalized.into_iter().next().expect(\"wrong listener\");",
                    )
                    .replace(
                        "::httpserve::finalize_auth(routes, plan)",
                        "::httpserve::finalize_auth(wrong_routes, plan)",
                    ),
            ),
            (
                "observer alias",
                canonical
                    .replace(
                        "    let (output, receipt)",
                        "    let observer_alias = observers;\n    let (output, receipt)",
                    )
                    .replace("        observers,\n        move ||", "        observer_alias,\n        move ||"),
            ),
            (
                "observer helper",
                canonical.replace(
                    "::testkit::local_only::LocalOnlyObservers::new(\n        repo_probe.counter.handle(),\n        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),\n        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),\n    )",
                    "make_observers()",
                ),
            ),
            (
                "observer macro",
                canonical.replace(
                    "::testkit::local_only::LocalOnlyObservers::new(\n        repo_probe.counter.handle(),\n        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),\n        ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),\n    )",
                    "make_observers!()",
                ),
            ),
            (
                "decoy observers",
                canonical.replace(
                    "    let (output, receipt)",
                    "    let _decoy = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof), ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof));\n    let (output, receipt)",
                ),
            ),
            (
                "proof alias",
                canonical
                    .replace(
                        "    let observers =",
                        "    let proof_alias = &proof;\n    let observers =",
                    )
                    .replace("from_governed(&proof)", "from_governed(proof_alias)"),
            ),
            (
                "proof helper",
                canonical.replace(
                    "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
                    "make_proof(&routes)",
                ),
            ),
            (
                "proof macro",
                canonical.replace(
                    "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
                    "make_proof!(&routes)",
                ),
            ),
            (
                "decoy proof",
                canonical.replace(
                    "    let observers =",
                    "    let _decoy_proof = ::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(&other_routes, &::generated::http::identity_v1::profile::ROUTE).expect(\"decoy mounted proof\");\n    let observers =",
                ),
            ),
            (
                "provider router mismatch",
                canonical.replace(
                    "    let (router, proof) = self::finalized_identity_v1_profile_router(repo_probe.test_repo());",
                    "    let other_probe = Repo::default();\n    let (router, proof) = self::finalized_identity_v1_profile_router(other_probe.test_repo());",
                ),
            ),
            (
                "mutable receipt router binding",
                canonical.replace("let (router, proof) = self::", "let (mut router, proof) = self::"),
            ),
            (
                "mutable receipt proof binding",
                canonical.replace("let (router, proof) = self::", "let (router, mut proof) = self::"),
            ),
            (
                "receipt router mutable reference",
                canonical.replace(
                    "    let observers =",
                    "    let mut replacement_router = axum::Router::new();\n    ::core::mem::swap(&mut router, &mut replacement_router);\n    let observers =",
                ),
            ),
            (
                "bait call",
                canonical.replace(
                    "    let (output, receipt)",
                    "    let _bait = ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::identity_v1::profile::SPEC.route.path()));\n    let (output, receipt)",
                ),
            ),
            (
                "non-finalized router",
                canonical.replace(
                    "self::finalized_identity_v1_profile_router(repo_probe.test_repo())",
                    "self::fake_router(repo_probe.test_repo())",
                ),
            ),
            (
                "bait finalizer with fake tail",
                canonical.replace(
                    "::httpserve::finalize_auth(routes, plan)\n        .expect(\"finalized\")\n        .into_router_for_test()",
                    "{ let _bait = ::httpserve::finalize_auth(routes, plan); axum::Router::new() }",
                ),
            ),
            (
                "finalizer factory early return",
                canonical.replace(
                    ") {\n    let domain = DemoDomain::new(repo.read);",
                    ") {\n    if opaque() { return fallback(); }\n    let domain = DemoDomain::new(repo.read);",
                ),
            ),
            (
                "factory unknown body attribute",
                canonical.replace(
                    "fn finalized_identity_v1_profile_router(repo: TestRepo)",
                    "#[erase_body]\nfn finalized_identity_v1_profile_router(repo: TestRepo)",
                ),
            ),
            (
                "mutable finalized routes binding",
                canonical.replace(
                    "let (_, routes) = finalized.into_iter().next().expect(\"listener\");",
                    "let (_, mut routes) = finalized.into_iter().next().expect(\"listener\");\n    let mut replacement_routes = Vec::new();\n    ::core::mem::swap(&mut routes, &mut replacement_routes);",
                ),
            ),
            (
                "mutable mounted proof binding",
                canonical.replace(
                    "let proof = ::httpserve::prove_local_only_mounted_route_state",
                    "let mut proof = ::httpserve::prove_local_only_mounted_route_state",
                ),
            ),
            (
                "non-self factory qualifier",
                canonical.replace(
                    "self::finalized_identity_v1_profile_router(repo_probe.test_repo())",
                    "super::finalized_identity_v1_profile_router(repo_probe.test_repo())",
                ),
            ),
            (
                "empty routes",
                canonical.replace(
                    "let (_, routes) = finalized.into_iter().next().expect(\"listener\");",
                    "let routes = Vec::new();",
                ),
            ),
            (
                "arbitrary routes",
                canonical.replace(
                    "let (_, routes) = finalized.into_iter().next().expect(\"listener\");",
                    "let (_, routes) = arbitrary_routes();",
                ),
            ),
            (
                "cfg-disabled factory bait",
                canonical.replace(
                    "fn finalized_identity_v1_profile_router(repo: TestRepo)",
                    "#[cfg(any())]\nfn finalized_identity_v1_profile_router(repo: TestRepo)",
                ),
            ),
            (
                "ignored parent module",
                canonical.replacen(
                    "#[cfg(test)]\nmod receipt_identity_v1_profile",
                    "#[cfg(test)]\n#[ignore]\nmod receipt_identity_v1_profile",
                    1,
                ),
            ),
            (
                "sibling factory bait",
                canonical
                    .replace(
                        "fn finalized_identity_v1_profile_router(repo: TestRepo)",
                        "mod sibling { use super::*; fn finalized_identity_v1_profile_router(repo: TestRepo)",
                    )
                    .replacen("\n#[tokio::test]", "\n}\n#[tokio::test]", 1),
            ),
            (
                "ignored factory bait",
                canonical.replace(
                    "fn finalized_identity_v1_profile_router(repo: TestRepo)",
                    "#[ignore]\nfn finalized_identity_v1_profile_router(repo: TestRepo)",
                ),
            ),
            (
                "provider ignored by Domain constructor",
                canonical.replace(
                    "let domain = DemoDomain::new(repo.read);",
                    "let domain = DemoDomain::new(());",
                ),
            ),
            (
                "test_repo early return before provider bridge",
                canonical.replace(
                    "fn test_repo(&self) -> TestRepo { TestRepo::from_provider(Arc::new(self.clone())) }",
                    "fn test_repo(&self) -> TestRepo { if opaque() { return unrelated_repo(); } TestRepo::from_provider(Arc::new(self.clone())) }",
                ),
            ),
            (
                "Domain constructor dead provider branch",
                canonical.replace(
                    "Self { read_repo }",
                    "Self { read_repo: if false { consume(read_repo) } else { () } }",
                ),
            ),
            (
                "TestRepo dead provider reference",
                canonical.replace(
                    "Self { read: consume(provider) }",
                    "Self { read: { if false { consume(provider); } unrelated_read() } }",
                ),
            ),
            (
                "decoy counter provider",
                canonical
                    .replace(
                        "    let (router, proof)",
                        "    let decoy = Repo::default();\n    let (router, proof)",
                    )
                    .replace("repo_probe.counter.handle()", "decoy.counter.handle()"),
            ),
            (
                "sibling record impl bait",
                canonical
                    .replace(
                        "impl RecordedMutation for Repo { fn mutate(&self) { self.counter.record(); } }",
                        "impl RecordedMutation for Repo { fn mutate(&self) {} }\nmod sibling { impl super::Repo { fn bait(&self) { self.counter.record(); } } }",
                    ),
            ),
            (
                "cfg-disabled record impl bait",
                canonical.replace(
                    "impl RecordedMutation for Repo {",
                    "#[cfg(any())]\nimpl RecordedMutation for Repo {",
                ),
            ),
            (
                "same-module dead inherent record helper",
                canonical.replace("impl RecordedMutation for Repo {", "impl Repo {"),
            ),
            (
                "unqualified receipt assertion",
                canonical.replace("::core::assert_eq!(", "assert_eq!("),
            ),
            (
                "shadowed observers",
                canonical.replace(
                    "    let (output, receipt)",
                    "    let observers = observers;\n    let (output, receipt)",
                ),
            ),
            (
                "malformed receipt generics",
                canonical.replacen("        _,\n        _,\n        _,", "        _,\n        _,", 1),
            ),
            (
                "malformed receipt arguments",
                canonical.replacen("        observers,", "        observers,\n        extra,", 1),
            ),
        ];
        for (name, source) in cases {
            let workspace = receipt_workspace(&source)?;
            let Err(error) = local_only_receipt_registration(&workspace, &targets) else {
                bail!("{name}: noncanonical receipt source unexpectedly passed");
            };
            assert!(!format!("{error:#}").contains(workspace.to_string_lossy().as_ref()));
            assert!(!format!("{error:#}").is_empty(), "{name}");
        }

        for (name, source) in [
            ("non-L0 marker", canonical_receipt("identity_v1::login")),
            ("inactive marker", canonical_receipt("identity_v2::profile")),
            ("stale marker", canonical_receipt("identity_v1::removed")),
        ] {
            let unknown = receipt_workspace(&source)?;
            let Err(error) = local_only_receipt_registration(&unknown, &targets) else {
                bail!("{name}: marker outside the active LocalOnly registry unexpectedly passed");
            };
            assert!(
                format!("{error:#}").contains("does not name an active LocalOnly"),
                "{name}: {error:#}"
            );
        }

        let duplicate = receipt_workspace(&format!("{canonical}\n{canonical}"))?;
        assert!(local_only_receipt_registration(&duplicate, &targets).is_err());

        let malformed = receipt_workspace(&canonical.replace(
            "::testkit::local_only::assert_local_only_with_receipt",
            "::custom::assert_local_only_with_receipt",
        ))?;
        let mut stdout = Vec::new();
        let result = run_report_with(
            ReportFormat::Json,
            || {
                local_only_receipt_registration(&malformed, &targets)?;
                Ok(synthetic_report_fixture())
            },
            &mut stdout,
        );
        assert!(result.is_err());
        assert!(stdout.is_empty());
        Ok(())
    }

    #[test]
    fn local_only_receipt_reconciliation_covers_zero_two_and_six_sites() -> Result<()> {
        let targets = (0..6)
            .map(|index| {
                receipt_target(&format!("demo.route-{index}"), &[&format!("route_{index}")])
            })
            .collect::<Vec<_>>();
        for registered_count in [0, 2, 6] {
            let source = (0..registered_count)
                .map(|index| canonical_receipt(&format!("route_{index}")))
                .collect::<String>();
            let workspace = receipt_workspace(&source)?;
            let registration = local_only_receipt_registration(&workspace, &targets)?;
            assert_eq!(registration.registered_contracts.len(), registered_count);
            assert_eq!(registration.missing_contracts.len(), 6 - registered_count);
            assert_eq!(
                registration.report().status,
                if registered_count == 6 {
                    ReceiptCoverageStatus::Complete
                } else {
                    ReceiptCoverageStatus::Partial
                }
            );
        }
        Ok(())
    }

    #[test]
    fn local_only_receipt_coverage_is_blocking_when_any_active_target_is_missing() -> Result<()> {
        let (_, findings) = check_root(&fixture("green"))?;
        assert_eq!(findings.len(), 1, "missing receipt must block the gate");
        assert_eq!(format!("{:?}", findings[0].rule), "MissingLocalOnlyReceipt");
        assert!(findings[0].detail.contains("demo.safe"));
        Ok(())
    }

    #[test]
    fn missing_receipt_finding_has_one_typed_source_for_gate_and_report() -> Result<()> {
        let registration = ReceiptRegistration::reconcile(
            BTreeSet::from(["demo.safe".to_string()]),
            BTreeSet::new(),
        )?;
        let source = missing_receipt_finding("demo.safe");
        assert_eq!(registration.blocking_findings(), vec![source.clone()]);
        assert_eq!(
            report_finding(&source),
            report_finding(&missing_receipt_finding("demo.safe"))
        );
        Ok(())
    }

    #[test]
    fn standalone_gate_rejects_manifest_generated_registry_drift() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let generated = workspace.0.join("generated/src/http/demo_v1.rs");
        fs::OpenOptions::new()
            .append(true)
            .open(&generated)?
            .write_all(
                br#"
pub mod decoy {
    pub struct RouteMarker;
    pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, ::vocab::http::LocalOnly> =
        ::vocab::HttpRouteBinding::new();
}
"#,
            )?;
        let Err(error) = check_root(&workspace.0) else {
            bail!("registry drift unexpectedly passed");
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("stale_in_generated"), "{detail}");
        assert!(detail.contains("demo_v1::decoy"), "{detail}");
        Ok(())
    }

    #[test]
    fn settings_provider_business_write_observer_is_method_variant_and_state_bound() -> Result<()> {
        let canonical = r#"
struct SettingsConfigGetRepoProbe { state: State, business_write_effects: Counter }
impl ConfigRepo for SettingsConfigGetRepoProbe {
    fn find_version(&self) {
        let (_, synthetic_write, _) = {
            let mut state = self.state.lock();
            ((), state.synthetic_write, ())
        };
        if synthetic_write == ConfigGetSyntheticWrite::FindVersion {
            self.business_write_effects.record();
        }
    }
    fn head(&self) {
        let (_, synthetic_write, _) = {
            let mut state = self.state.lock();
            ((), state.synthetic_write, ())
        };
        if synthetic_write == ConfigGetSyntheticWrite::Head {
            self.business_write_effects.record();
        }
    }
}
"#;
        let recorded = |source: &str| -> Result<BTreeSet<String>> {
            let syntax = syn::parse_file(source)?;
            Ok(collect_scoped_recorded_provider_fields(&syntax.items)
                .remove(&(Vec::new(), "SettingsConfigGetRepoProbe".to_string()))
                .unwrap_or_default())
        };
        assert_eq!(
            recorded(canonical)?,
            BTreeSet::from(["business_write_effects".to_string()])
        );
        for (name, red) in [
            (
                "wrong method",
                canonical.replacen("fn find_version(", "fn find(", 1),
            ),
            (
                "local constant",
                canonical.replace("state.synthetic_write", "ConfigGetSyntheticWrite::Head"),
            ),
            (
                "wrong injection variant",
                canonical.replacen(
                    "ConfigGetSyntheticWrite::FindVersion",
                    "ConfigGetSyntheticWrite::Head",
                    1,
                ),
            ),
            (
                "dead record",
                canonical.replace(
                    "        if synthetic_write",
                    "        return;\n        if synthetic_write",
                ),
            ),
        ] {
            assert!(recorded(&red)?.is_empty(), "{name} unexpectedly certified");
        }
        Ok(())
    }

    #[test]
    fn settings_config_get_receipt_operation_is_narrow() -> Result<()> {
        let canonical = syn::parse_str::<Expr>(
            "move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::settings_v4::SPEC.route.path().replace(\"{key}\", \"app.k\")))",
        )?;
        assert_eq!(
            canonical_receipt_operation(&canonical),
            Some(("router".to_string(), vec!["settings_v4".to_string()]))
        );
        for (name, source) in [
            (
                "wrong placeholder",
                "move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::settings_v4::SPEC.route.path().replace(\"{configKey}\", \"app.k\")))",
            ),
            (
                "wrong value",
                "move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::settings_v4::SPEC.route.path().replace(\"{key}\", \"other.k\")))",
            ),
            (
                "wrong module",
                "move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::identity_v1::profile::SPEC.route.path().replace(\"{key}\", \"app.k\")))",
            ),
        ] {
            let expression = syn::parse_str::<Expr>(source)?;
            assert!(
                canonical_receipt_operation(&expression).is_none(),
                "{name} unexpectedly certified"
            );
        }
        Ok(())
    }

    #[rustfmt::skip]
    const SETTINGS_LINEAGE_REDS: [(&str, &str, &str); 12] = [
        ("fake Domain", "SettingsDomain", "FakeSettingsDomain"),
        ("cfg-hidden production Domain", "struct SettingsDomain {", "#[cfg(any())]\nstruct SettingsDomain {"),
        ("decoy provider field", "repo.configs", "repo.decoy"),
        ("decoy provider wrapper", "DynConfigRepo::new_box(provider.as_ref().clone())", "Decoy::new_box(provider.as_ref().clone())"),
        ("extra query repo field", "cache: () }", "cache: (), decoy: () }"),
        ("wrong read receiver", "self.configs.head()", "self.decoy.head()"),
        ("shadowed service provider", "Arc::from(configs)", "Arc::from(decoy)"),
        ("service wrapper", "Arc::new(super::SettingsService::with_postgres(repo.configs, writer(), flags(), clock()))", "build_settings_service(repo.configs)"),
        ("mutable alias", "let config = Arc::new(super::SettingsService::with_postgres(repo.configs, writer(), flags(), clock()));", "let mut configs = repo.configs;\n    let config = Arc::new(super::SettingsService::with_postgres(configs, writer(), flags(), clock()));"),
        ("wrong classified state", "prove_local_only_mounted_route_state::<ConfigQueryService, _>", "prove_local_only_mounted_route_state::<ReadState, _>"),
        ("wrong generated ROUTE", "&::generated::http::settings_v4::ROUTE", "&::generated::http::identity_v1::profile::ROUTE"),
        ("different finalized routes", "&routes,\n        &::generated::http::settings_v4::ROUTE", "&other_routes,\n        &::generated::http::settings_v4::ROUTE"),
    ];

    #[test]
    fn settings_config_get_receipt_accepts_only_real_service_domain_lineage() -> Result<()> {
        let canonical = canonical_settings_receipt();
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        let inventory = settings_receipt_inventory(&canonical, CANONICAL_SETTINGS_COMPOSITION)?;
        let registration = local_only_receipt_registration_in_inventory(&inventory, &targets)?;
        assert_eq!(
            registration.registered_contracts,
            BTreeSet::from(["settings.config-get".to_string()])
        );

        for (name, from, to) in SETTINGS_LINEAGE_REDS {
            let source = canonical.replace(from, to);
            let inventory = settings_receipt_inventory(&source, CANONICAL_SETTINGS_COMPOSITION)?;
            let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets)
            else {
                bail!("{name} unexpectedly certified");
            };
            let detail = format!("{error:#}");
            assert!(detail.contains("Settings receipt"), "{name}: {detail}");
            if name == "wrong classified state" {
                assert!(detail.contains("classified-state"), "{name}: {detail}");
            }
            if name == "decoy provider field" {
                assert!(
                    detail.contains("provider→TestRepo→service→Domain"),
                    "{name}: {detail}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn settings_receipt_rejects_cfg_test_method_decoy() -> Result<()> {
        let canonical = canonical_settings_receipt();
        let cfg_split = canonical.replace(
            "    async fn get_config(&self) {\n        self.configs.head();\n        self.cache.find();\n        self.configs.find_version(scope, &key, active_version);\n    }",
            "    #[cfg(test)]\n    async fn get_config(&self) {\n        self.configs.head();\n        self.cache.find();\n        self.configs.find_version(scope, &key, active_version);\n    }\n    #[cfg(not(test))]\n    async fn get_config(&self) {}",
        );
        assert_ne!(
            cfg_split, canonical,
            "cfg-split fixture mutation must apply"
        );
        let inventory = settings_receipt_inventory(&cfg_split, CANONICAL_SETTINGS_COMPOSITION)?;
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets) else {
            bail!("test-only canonical method masked the production implementation");
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("get-config-read"), "{detail}");
        Ok(())
    }

    #[test]
    fn settings_receipt_rejects_ambiguous_unknown_cfg_methods() -> Result<()> {
        let canonical = canonical_settings_receipt();
        let ambiguous = canonical.replace(
            "    async fn get_config(&self) {\n        self.configs.head();\n        self.cache.find();\n        self.configs.find_version(scope, &key, active_version);\n    }",
            "    #[cfg(feature = \"one\")]\n    async fn get_config(&self) {\n        self.configs.head();\n        self.cache.find();\n        self.configs.find_version(scope, &key, active_version);\n    }\n    #[cfg(feature = \"two\")]\n    async fn get_config(&self) {\n        self.configs.head();\n        self.cache.find();\n        self.configs.find_version(scope, &key, active_version);\n    }",
        );
        assert_ne!(ambiguous, canonical, "ambiguous cfg mutation must apply");
        let inventory = settings_receipt_inventory(&ambiguous, CANONICAL_SETTINGS_COMPOSITION)?;
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets) else {
            bail!("unknown cfg methods did not remain production-possible and ambiguous");
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("get-config-read"), "{detail}");
        assert!(detail.contains("found 2 production-reachable"), "{detail}");
        Ok(())
    }

    #[test]
    fn settings_receipt_rejects_test_constructor_when_production_funnel_drifts() -> Result<()> {
        let canonical = canonical_settings_receipt();
        let drifted = canonical.replace(
            "    fn with_postgres(configs: (), writer: (), flags: (), clock: ()) -> Self {\n        let configs = Arc::from(configs);\n        let cache = make_cache();\n        consume((writer, flags, clock));\n        Self { query: ConfigQueryService::new(configs, cache) }\n    }",
            "    fn with_postgres(configs: (), writer: (), flags: (), clock: ()) -> Self {\n        let configs = Arc::from(decoy);\n        let cache = make_cache();\n        consume((writer, flags, clock));\n        Self { query: ConfigQueryService::new(configs, cache) }\n    }\n    #[cfg(test)]\n    fn new(configs: ()) -> Self {\n        let configs = Arc::from(configs);\n        let cache = make_cache();\n        Self { query: ConfigQueryService::new(configs, cache) }\n    }",
        ).replace(
            "super::SettingsService::with_postgres(repo.configs, writer(), flags(), clock())",
            "super::SettingsService::new(repo.configs)",
        );
        assert_ne!(drifted, canonical, "constructor drift mutation must apply");
        let inventory = settings_receipt_inventory(&drifted, CANONICAL_SETTINGS_COMPOSITION)?;
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets) else {
            bail!("test constructor certified a drifted production funnel");
        };
        let detail = format!("{error:#}");
        assert!(detail.contains("service-constructor"), "{detail}");
        Ok(())
    }

    #[test]
    fn settings_receipt_rejects_production_composition_drift() -> Result<()> {
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        for (name, from, to) in [
            (
                "composition deps",
                "let SettingsModuleDeps { pg, clock } = deps;",
                "let pg = decoy; let clock = other;",
            ),
            (
                "provider bundle",
                ".settings_bundle(clock, protections)",
                ".decoy_bundle(clock, protections)",
            ),
            (
                "service constructor",
                "SettingsService::with_postgres(",
                "SettingsService::new(",
            ),
            (
                "Domain constructor",
                "SettingsDomain::new(",
                "build_settings_domain(",
            ),
        ] {
            let composition = CANONICAL_SETTINGS_COMPOSITION.replace(from, to);
            assert_ne!(composition, CANONICAL_SETTINGS_COMPOSITION, "{name}");
            let inventory =
                settings_receipt_inventory(&canonical_settings_receipt(), &composition)?;
            let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets)
            else {
                bail!("{name}: production composition lineage drift unexpectedly passed");
            };
            let detail = format!("{error:#}");
            assert!(
                detail.contains("production-composition"),
                "{name}: {detail}"
            );
            assert!(detail.contains("expected="), "{name}: {detail}");
            assert!(detail.contains("actual="), "{name}: {detail}");
        }
        Ok(())
    }

    #[test]
    fn settings_certificate_reports_the_exact_invalid_stage() -> Result<()> {
        let canonical = canonical_settings_receipt();
        let targets = [receipt_target("settings.config-get", &["settings_v4"])];
        for (stage, from, to) in [
            (
                "root-types",
                "struct SettingsDomain {",
                "struct MissingSettingsDomain {",
            ),
            ("query-fields", "cache: () }", "cache: (), decoy: () }"),
            (
                "query-constructor",
                "Self { configs, cache }",
                "Self { configs: decoy, cache }",
            ),
            (
                "get-config-read",
                "self.configs.head()",
                "self.cache.head()",
            ),
            (
                "service-constructor",
                "Arc::from(configs)",
                "Arc::from(decoy)",
            ),
            ("query-getter", "self.query.clone()", "self.decoy.clone()"),
            (
                "domain-constructor",
                "config.config_query_service()",
                "decoy.config_query_service()",
            ),
            (
                "domain-mount",
                "endpoint.with_classified_state(config_query)",
                "endpoint.with_classified_state(decoy)",
            ),
        ] {
            let source = canonical.replacen(from, to, 1);
            assert_ne!(source, canonical, "{stage}: fixture mutation must apply");
            let inventory = settings_receipt_inventory(&source, CANONICAL_SETTINGS_COMPOSITION)?;
            let Err(error) = local_only_receipt_registration_in_inventory(&inventory, &targets)
            else {
                bail!("{stage}: invalid Settings certificate unexpectedly passed");
            };
            let detail = format!("{error:#}");
            assert!(detail.contains(stage), "{stage}: {detail}");
            assert!(detail.contains("expected="), "{stage}: {detail}");
            assert!(detail.contains("actual="), "{stage}: {detail}");
        }
        Ok(())
    }

    #[test]
    fn receipt_target_module_path_preserves_flat_and_nested_codegen_modules() {
        assert_eq!(module_path_from_mount_key("settings_v4"), ["settings_v4"]);
        assert_eq!(
            module_path_from_mount_key("identity_v1::profile"),
            ["identity_v1", "profile"]
        );
    }

    #[test]
    fn governed_observation_provenance_is_accepted() -> Result<()> {
        let findings = provenance_findings(GOVERNED_PROVENANCE)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let workspace = real_api_provenance_workspace(GOVERNED_PROVENANCE)?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "green provenance fixture must compile against the real mounted proof API: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stateless = GOVERNED_PROVENANCE.replace(
            "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
            "::httpserve::prove_stateless_local_only_mounted_route(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    )",
        );
        let findings = provenance_findings(&stateless)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn forged_observation_provenance_is_rejected() -> Result<()> {
        let cases = [
            (
                "legacy owner trait",
                GOVERNED_PROVENANCE.replace(
                    "struct Repo { counter: ::testkit::local_only::ProviderCounter<::testkit::local_only::BusinessWrite> }",
                    "impl StaticExclusionOwner<BusinessWrite> for Fake {}\nstruct Repo { counter: ::testkit::local_only::ProviderCounter<::testkit::local_only::BusinessWrite> }",
                ),
            ),
            (
                "legacy runtime closure",
                GOVERNED_PROVENANCE.replace(
                    "repo_probe.counter.handle()",
                    "RuntimeProbe::write(|| 0)",
                ),
            ),
            (
                "inline proof",
                GOVERNED_PROVENANCE.replace(
                    "::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof)",
                    "::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(&routes, &::generated::http::identity_v1::profile::ROUTE).expect(\"mounted proof\"))",
                ),
            ),
            (
                "forged proof binding",
                GOVERNED_PROVENANCE.replace(
                    "let proof = ::httpserve::prove_local_only_mounted_route_state::<ReadState, _>(\n        &routes,\n        &::generated::http::identity_v1::profile::ROUTE,\n    ).expect(\"mounted proof\");",
                    "let proof = FakeProof::new();",
                ),
            ),
            (
                "lookalike proof constructor",
                GOVERNED_PROVENANCE.replace(
                    "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>",
                    "::lookalike::prove_local_only_mounted_route_state::<ReadState, _>",
                ),
            ),
            (
                "decoy provider",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let decoy = Repo::default();\n    let _observers = ::testkit::local_only::LocalOnlyObservers::new(decoy.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "provider misses mutation record",
                GOVERNED_PROVENANCE.replace("self.counter.record();", "drop(&self.counter);"),
            ),
            (
                "decoy field records instead of observed field",
                GOVERNED_PROVENANCE.replace("self.counter.record();", "self.decoy.record();"),
            ),
            (
                "provider alias hides origin",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let provider_alias = &repo_probe;\n    let _observers = ::testkit::local_only::LocalOnlyObservers::new(provider_alias.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "opaque handle parameter",
                GOVERNED_PROVENANCE
                    .replace(
                        "fn conforms()",
                        "fn conforms(input_handle: ProviderCounterHandle<BusinessWrite>)",
                    )
                    .replace("repo_probe.counter.handle()", "input_handle"),
            ),
            (
                "import-style observer alias",
                GOVERNED_PROVENANCE.replace(
                    "::testkit::local_only::LocalOnlyObservers::new",
                    "LocalOnlyObservers::new",
                ),
            ),
            (
                "observer function item constructor",
                GOVERNED_PROVENANCE.replace(
                    "let _observers = ::testkit::local_only::LocalOnlyObservers::new(repo_probe.counter.handle(), outbox, publish);",
                    "let ctor = ::testkit::local_only::LocalOnlyObservers::new;\n    let _observers = ctor(repo_probe.counter.handle(), outbox, publish);",
                ),
            ),
            (
                "shadowed absolute-looking proof namespace",
                GOVERNED_PROVENANCE.replace(
                    "::httpserve::prove_local_only_mounted_route_state::<ReadState, _>",
                    "::evil::httpserve::prove_local_only_mounted_route_state::<ReadState, _>",
                ),
            ),
            (
                "bait test repo call",
                GOVERNED_PROVENANCE.replace(
                    "let router = finalized_scoped_router(repo_probe.test_repo());",
                    "let _bait = repo_probe.test_repo();\n    let router = finalized_scoped_router(other_probe.test_repo());",
                ),
            ),
            (
                "bait oneshot call",
                GOVERNED_PROVENANCE.replace(
                    "let _response = ::testkit::call(\n        router,",
                    "let _response = ::testkit::call(\n        bait_router,",
                ),
            ),
        ];
        for (name, source) in cases {
            let findings = provenance_findings(&source)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| matches!(finding.rule, Rule::ForgedObservationEvidence)),
                "{name} unexpectedly passed: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn provenance_inventory_includes_non_crates_workspace_members() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let manifest = workspace.0.join("Cargo.toml");
        workspace.replace(
            &manifest,
            ", \"generated\"]",
            ", \"generated\", \"tools/consumer\"]",
        )?;
        let consumer = workspace.0.join("tools/consumer");
        fs::create_dir_all(consumer.join("src"))?;
        fs::write(
            consumer.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        fs::write(
            consumer.join("src/lib.rs"),
            "struct RuntimeProbe; impl RuntimeProbe { fn write(_: impl Fn() -> u64) {} } fn bait() { RuntimeProbe::write(|| 0); }\n",
        )?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let findings = check_root(&workspace.0)?.1;
        assert!(findings.iter().any(|finding| {
            matches!(finding.rule, Rule::ForgedObservationEvidence)
                && finding.subject.starts_with("tools/consumer/src/lib.rs:")
        }));
        Ok(())
    }

    #[test]
    fn safe_profiles_pass_and_inactive_or_non_localonly_are_ignored() -> Result<()> {
        let (summary, findings) = check_root(&fixture("green"))?;
        assert_eq!(
            summary,
            "1 active LocalOnly HTTP contract(s) checked; source receipts registered 0/1; missing: demo.safe"
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(matches!(findings[0].rule, Rule::MissingLocalOnlyReceipt));
        Ok(())
    }

    #[test]
    fn business_effect_profiles_are_stable_and_closed() -> Result<()> {
        let (_, findings) = check_root(&fixture("all_forbidden"))?;
        assert_eq!(findings.len(), 10);
        assert!(
            findings
                .iter()
                .filter(|finding| matches!(finding.rule, Rule::ForbiddenStateEffect))
                .count()
                == 9
        );
        let details: Vec<_> = findings
            .iter()
            .filter(|finding| matches!(finding.rule, Rule::ForbiddenStateEffect))
            .map(|finding| finding.detail.as_str())
            .collect();
        assert!(details.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("business-write"))
        );
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("business-transaction"))
        );
        Ok(())
    }

    #[test]
    fn synthetic_report_renderers_match_exact_golden() -> Result<()> {
        let report = synthetic_report_fixture();
        assert_eq!(
            render_report(&report, ReportFormat::Json)?,
            include_str!("../tests/golden/consistency-posture.json")
        );
        assert_eq!(
            render_report(&report, ReportFormat::Markdown)?,
            include_str!("../tests/golden/consistency-posture.md")
        );
        Ok(())
    }

    #[test]
    fn consistency_report_schema_is_v4_and_receipt_coverage_is_fail_closed() -> Result<()> {
        let report = synthetic_report_fixture();
        let json = serde_json::to_value(&report)?;
        assert_eq!(json["schemaVersion"], 4);
        assert_eq!(
            json["localOnlyReceiptCoverage"]["enforcement"],
            "failClosed"
        );
        assert_eq!(json["status"], "failed");
        assert!(json["findings"].as_array().is_some_and(|findings| {
            findings.iter().any(|finding| {
                finding["rule"] == "missingLocalOnlyReceipt" && finding["subject"] == "a.local"
            })
        }));
        assert!(
            json["contracts"][0]["findings"]
                .as_array()
                .is_some_and(|findings| findings
                    .iter()
                    .any(|finding| finding["rule"] == "missingLocalOnlyReceipt"))
        );
        Ok(())
    }

    #[test]
    fn report_canonicalizes_rows_findings_effects_and_markdown_cells() -> Result<()> {
        let report = synthetic_report_fixture();
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.active_http_contract_count, 2);
        assert_eq!(
            report.contracts[0].effects,
            vec!["read".to_string(), "cross-tenant-audit".to_string()]
        );
        let markdown = render_report(&report, ReportFormat::Markdown)?;
        assert!(markdown.contains("forbiddenStateEffect @ crates/demo/src/lib.rs:7: escaped &#124; cell&#92;path<br>line &#91;link&#93;&#40;https://example.invalid&#41; &#33;&#91;img&#93;&#40;x&#41; &lt;em&gt;raw&lt;/em&gt; &#96;tick&#96; &#42;strong&#42; &amp; amp"));
        assert!(markdown.ends_with('\n'));
        assert!(!markdown.ends_with("\n\n"));
        for forbidden in [
            "timestamp",
            "hostname",
            "gitSha",
            env!("CARGO_MANIFEST_DIR"),
        ] {
            assert!(!markdown.contains(forbidden), "leaked {forbidden}");
        }
        Ok(())
    }

    #[test]
    fn report_policy_failure_is_renderable_but_structural_failure_is_error() -> Result<()> {
        let failed = synthetic_report_fixture();
        assert_eq!(failed.status, ReportStatus::Failed);
        assert!(render_report(&failed, ReportFormat::Json)?.contains("\"status\": \"failed\""));

        let mut malformed = failed;
        malformed.active_http_contract_count += 1;
        assert!(render_report(&malformed, ReportFormat::Json).is_err());

        let mut invalid_receipt_partition = synthetic_report_fixture();
        invalid_receipt_partition.contracts[0]
            .source_receipt_registration
            .status = SourceReceiptRegistrationStatus::NotApplicable;
        invalid_receipt_partition.contracts[0]
            .findings
            .retain(|finding| finding.rule != "missingLocalOnlyReceipt");
        invalid_receipt_partition
            .findings
            .retain(|finding| finding.rule != "missingLocalOnlyReceipt");
        invalid_receipt_partition
            .local_only_receipt_coverage
            .registered_count = 0;
        invalid_receipt_partition
            .local_only_receipt_coverage
            .missing_count = 0;
        invalid_receipt_partition
            .local_only_receipt_coverage
            .missing_contracts
            .clear();
        invalid_receipt_partition.local_only_receipt_coverage.status =
            ReceiptCoverageStatus::Complete;
        assert!(render_report(&invalid_receipt_partition, ReportFormat::Json).is_err());

        let mut legacy = synthetic_report_fixture();
        legacy.schema_version = 2;
        assert!(render_report(&legacy, ReportFormat::Json).is_err());
        Ok(())
    }

    #[test]
    fn report_command_seam_preserves_stdout_and_result_contract() -> Result<()> {
        let mut failed_output = Vec::new();
        run_report_with(
            ReportFormat::Json,
            || Ok(synthetic_report_fixture()),
            &mut failed_output,
        )?;
        let failed: serde_json::Value = serde_json::from_slice(&failed_output)?;
        assert_eq!(failed["status"], "failed");
        assert_eq!(failed["activeHttpContractCount"], 2);
        assert_eq!(failed["contracts"].as_array().map(Vec::len), Some(2));

        let mut structural_output = Vec::new();
        let structural = run_report_with(
            ReportFormat::Json,
            || Err(anyhow!("synthetic structural collection failure")),
            &mut structural_output,
        );
        assert!(structural.is_err());
        assert!(structural_output.is_empty());
        Ok(())
    }

    #[test]
    fn real_workspace_report_consumes_the_generated_active_registry() -> Result<()> {
        let report = collect_report(&crate::workspace_root()?)?;
        assert!(!generated::http::SPECS.is_empty());
        ensure_exact_contract_ids(
            "real workspace consistency report",
            generated::http::SPECS
                .iter()
                .map(|spec| spec.route.contract_id()),
            report
                .contracts
                .iter()
                .map(|contract| contract.contract_id.as_str()),
        )?;
        assert_eq!(
            report.active_http_contract_count,
            generated::http::SPECS.len()
        );
        assert!(
            report
                .contracts
                .windows(2)
                .all(|rows| rows[0].contract_id <= rows[1].contract_id)
        );
        for format in [ReportFormat::Json, ReportFormat::Markdown] {
            let first = render_report(&report, format)?;
            let second = render_report(&report, format)?;
            assert_eq!(first, second);
            assert!(first.ends_with('\n'));
            assert!(!first.contains(env!("CARGO_MANIFEST_DIR")));
        }
        Ok(())
    }

    #[test]
    fn real_workspace_local_only_receipt_coverage_is_non_vacuous() -> Result<()> {
        let root = crate::workspace_root()?;
        let report = collect_report(&root)?;
        assert!(!generated::http::LOCAL_ONLY_SPECS.is_empty());
        let registered_ids = report
            .contracts
            .iter()
            .filter(|contract| {
                contract.source_receipt_registration.status
                    == SourceReceiptRegistrationStatus::Registered
            })
            .map(|contract| contract.contract_id.as_str())
            .collect::<Vec<_>>();
        ensure_exact_contract_ids(
            "real workspace LocalOnly receipt coverage",
            generated::http::LOCAL_ONLY_SPECS
                .iter()
                .map(|spec| spec.route.contract_id()),
            registered_ids.iter().copied(),
        )?;
        assert_eq!(
            report.local_only_receipt_coverage.active_count,
            generated::http::LOCAL_ONLY_SPECS.len()
        );
        assert_eq!(
            report.local_only_receipt_coverage.registered_count,
            generated::http::LOCAL_ONLY_SPECS.len()
        );
        assert_eq!(report.local_only_receipt_coverage.missing_count, 0);
        assert!(
            report
                .local_only_receipt_coverage
                .missing_contracts
                .is_empty()
        );
        assert_eq!(report.status, ReportStatus::Passed);
        let (summary, findings) = check_root(&root)?;
        assert!(findings.is_empty(), "{findings:#?}");
        assert!(summary.contains("active LocalOnly HTTP contract(s) checked"));
        assert!(summary.ends_with("missing: none"));
        Ok(())
    }

    #[test]
    fn exact_contract_id_projection_rejects_missing_extra_duplicate_and_equal_count_wrong_set()
    -> Result<()> {
        let canonical = ["audit.list-entries", "identity.profile"];
        assert!(
            ensure_exact_contract_ids("synthetic", canonical, canonical).is_ok(),
            "canonical exact set must pass"
        );
        for (label, actual, expected_detail) in [
            (
                "missing",
                vec!["audit.list-entries"],
                "missing=[\"identity.profile\"] extra=[]",
            ),
            (
                "extra",
                vec![
                    "audit.list-entries",
                    "identity.profile",
                    "settings.config-get",
                ],
                "missing=[] extra=[\"settings.config-get\"]",
            ),
            (
                "equal-count-wrong-set",
                vec!["audit.list-entries", "settings.config-get"],
                "missing=[\"identity.profile\"] extra=[\"settings.config-get\"]",
            ),
        ] {
            let error = ensure_exact_contract_ids("synthetic", canonical, actual)
                .err()
                .with_context(|| format!("{label}: synthetic identity drift must fail"))?;
            assert!(
                error.to_string().contains(expected_detail),
                "{label}: {error:#}"
            );
        }
        let duplicate_actual = ensure_exact_contract_ids(
            "synthetic",
            canonical,
            [
                "identity.profile",
                "audit.list-entries",
                "identity.profile",
                "audit.list-entries",
            ],
        )
        .err()
        .context("duplicate actual identity must fail")?;
        assert_eq!(
            duplicate_actual.to_string(),
            "synthetic actual IDs contain duplicates=[\"audit.list-entries\", \"identity.profile\"]"
        );
        let duplicate_expected = ensure_exact_contract_ids(
            "synthetic",
            [
                "identity.profile",
                "audit.list-entries",
                "identity.profile",
                "audit.list-entries",
            ],
            canonical,
        )
        .err()
        .context("duplicate expected identity must fail")?;
        assert_eq!(
            duplicate_expected.to_string(),
            "synthetic expected IDs contain duplicates=[\"audit.list-entries\", \"identity.profile\"]"
        );
        Ok(())
    }

    #[test]
    fn framework_owner_is_not_inferred_from_contract_domain() -> Result<()> {
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let spec = test_http_spec_with_owner(
            vocab::HttpContractOwner::framework(),
            "framework.status",
            "framework_v1::status",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        );
        let posture = build_contract_posture(
            &spec,
            &ServingScope::Framework(vec!["runtime".to_string()]),
            None,
            None,
        )?;
        assert_eq!(posture.owner, "_framework");
        assert_eq!(posture.route.mount_status, MountStatus::Missing);
        assert_eq!(posture.effect_proof.status, ProofStatus::Failed);
        assert!(
            build_contract_posture(&spec, &ServingScope::Domain("demo".to_string()), None, None)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn framework_localonly_stateless_closes_gate_and_report_collection() -> Result<()> {
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let workspace = WorkspaceFixture::new()?;
        workspace.make_framework_stateless()?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let specs = [test_http_spec_with_owner(
            vocab::HttpContractOwner::framework(),
            "demo.safe",
            "demo_v1::safe",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        )];

        let report = collect_report_with_specs(&workspace.0, &specs)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.contracts[0].effect_proof.status, ProofStatus::Passed);
        assert_eq!(report.contracts[0].owner, "_framework");
        assert_eq!(
            report.contracts[0].effect_proof.state_kind,
            Some(StateKind::Stateless)
        );
        let (summary, findings) = check_root(&workspace.0)?;
        assert_eq!(
            summary,
            "1 active LocalOnly HTTP contract(s) checked; source receipts registered 0/1; missing: demo.safe"
        );
        assert!(
            findings
                .iter()
                .all(|finding| matches!(finding.rule, Rule::MissingLocalOnlyReceipt))
        );
        Ok(())
    }

    #[test]
    fn framework_localonly_classified_uses_only_global_sealed_capabilities() -> Result<()> {
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let workspace = WorkspaceFixture::new()?;
        workspace.make_framework_classified(true)?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let specs = [test_http_spec_with_owner(
            vocab::HttpContractOwner::framework(),
            "demo.safe",
            "demo_v1::safe",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        )];

        let report = collect_report_with_specs(&workspace.0, &specs)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.contracts[0].effect_proof.status, ProofStatus::Passed);
        assert_eq!(
            report.contracts[0].effect_proof.state_kind,
            Some(StateKind::Classified)
        );
        assert_eq!(
            report.contracts[0].effect_proof.effect_class.as_deref(),
            Some("ReadEffect")
        );
        assert!(
            check_root(&workspace.0)?
                .1
                .iter()
                .all(|finding| { matches!(finding.rule, Rule::MissingLocalOnlyReceipt) })
        );
        Ok(())
    }

    #[test]
    fn framework_localonly_cannot_claim_domain_private_capabilities() -> Result<()> {
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let workspace = WorkspaceFixture::new()?;
        workspace.make_framework_classified(false)?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let specs = [test_http_spec_with_owner(
            vocab::HttpContractOwner::framework(),
            "demo.safe",
            "demo_v1::safe",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        )];

        let report = collect_report_with_specs(&workspace.0, &specs)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert!(!report.contracts[0].findings.is_empty());
        assert!(!check_root(&workspace.0)?.1.is_empty());
        Ok(())
    }

    #[test]
    fn framework_localonly_ordinary_state_renders_a_complete_failed_posture() -> Result<()> {
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let workspace = WorkspaceFixture::new()?;
        workspace.make_framework_ordinary()?;
        let specs = [test_http_spec_with_owner(
            vocab::HttpContractOwner::framework(),
            "demo.safe",
            "demo_v1::safe",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        )];

        let report = collect_report_with_specs(&workspace.0, &specs)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(
            report.contracts[0].effect_proof.state_kind,
            Some(StateKind::Ordinary)
        );
        assert!(
            report.contracts[0]
                .findings
                .iter()
                .any(|finding| finding.rule == "unclassifiedState")
        );
        assert!(!check_root(&workspace.0)?.1.is_empty());
        Ok(())
    }

    #[test]
    fn framework_serving_assemblies_are_manifest_backed() -> Result<()> {
        let root = crate::testutil::unique_tmp("framework-serving-assembly");
        let runtime = root.join("assemblies/runtime");
        std::fs::create_dir_all(&runtime)?;
        std::fs::write(
            runtime.join("assembly.toml"),
            include_str!("../../assemblies/runtime/assembly.toml").replace(
                "frameworkContracts = [{ id = \"runtime.inventory\", listener = \"admin\" }]",
                "frameworkContracts = [{ id = \"framework.status\", listener = \"admin\" }]",
            ),
        )?;
        assert_eq!(
            framework_serving_assemblies(&root, "framework.status")?,
            vec!["runtime"]
        );

        let duplicate = root.join("assemblies/duplicate");
        std::fs::create_dir_all(&duplicate)?;
        std::fs::write(
            duplicate.join("assembly.toml"),
            std::fs::read_to_string(runtime.join("assembly.toml"))?
                .replace("name = \"runtime\"", "name = \"duplicate\""),
        )?;
        assert_eq!(
            framework_serving_assemblies(&root, "framework.status")?,
            vec!["duplicate", "runtime"]
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn framework_receipt_factory_registry_lineage_is_canonical() -> Result<()> {
        fn find(items: &[syn::Item]) -> Option<&syn::ItemFn> {
            for item in items {
                match item {
                    syn::Item::Fn(function)
                        if function.sig.ident == "finalized_runtime_inventory_router" =>
                    {
                        return Some(function);
                    }
                    syn::Item::Mod(module) => {
                        if let Some((_, nested)) = &module.content
                            && let Some(function) = find(nested)
                        {
                            return Some(function);
                        }
                    }
                    _ => {}
                }
            }
            None
        }

        let syntax = syn::parse_file(include_str!(
            "../../assemblies/settingsonly/src/inventory.rs"
        ))?;
        let factory = find(&syntax.items).context("runtime inventory receipt factory")?;
        assert_eq!(
            framework_routes_registered_into(&factory.block, "registry").as_deref(),
            Some("framework_routes"),
            "generated framework registration must bind the same Registry"
        );
        assert!(
            registry_lineage(&factory.block, "routes").is_some(),
            "framework Registry::new + generated registration must be canonical"
        );
        let (router, proof) = factory_tail_tuple(&factory.block).context("factory tail tuple")?;
        let proof_initializer =
            unique_direct_initializer(&factory.block, &proof).context("proof initializer")?;
        assert!(
            mounted_route_proof(proof_initializer).is_some(),
            "mounted framework proof must be canonical"
        );
        let router_initializer =
            unique_direct_initializer(&factory.block, &router).context("router initializer")?;
        assert_eq!(
            finalized_router_routes(router_initializer).as_deref(),
            Some("routes"),
            "framework router must pass the auth finalizer"
        );
        assert!(
            mounted_proof_return_module(&factory.sig.output).is_some(),
            "factory return type must name the generated marker"
        );
        let lineage = registry_lineage(&factory.block, "routes").context("registry lineage")?;
        assert!(
            !block_reassigns_any(
                &factory.block,
                &[
                    &router,
                    &proof,
                    "routes",
                    &lineage.finalized,
                    &lineage.domain,
                ],
            ),
            "factory lineage must not be reassigned"
        );
        assert_eq!(
            mutable_reference_count(&factory.block, &lineage.registry),
            1,
            "framework Registry has one exact generated registration mutation"
        );
        assert!(
            !block_has_mutable_binding(&factory.block, &[&router, &proof, "routes", "routes"],),
            "router, proof, and routes must be immutable"
        );
        assert!(
            verify_router_factory(factory, &BTreeMap::new(), None).is_some(),
            "framework receipt factory must close route, proof, and finalizer lineage"
        );
        Ok(())
    }

    #[test]
    fn mount_posture_distinguishes_missing_mounted_and_ambiguous() {
        use crate::localtx_coverage::{CanonicalMountedState, CanonicalRouteMount};
        let one = BTreeSet::from([CanonicalRouteMount {
            source: "crates/demo/src/lib.rs:1".to_string(),
            handler: "demo_handler".to_string(),
            state: CanonicalMountedState::Stateless,
        }]);
        let two = BTreeSet::from([
            CanonicalRouteMount {
                source: "crates/demo/src/lib.rs:1".to_string(),
                handler: "first_handler".to_string(),
                state: CanonicalMountedState::Stateless,
            },
            CanonicalRouteMount {
                source: "crates/demo/src/lib.rs:2".to_string(),
                handler: "second_handler".to_string(),
                state: CanonicalMountedState::Opaque,
            },
        ]);
        assert_eq!(mount_posture(None).0, MountStatus::Missing);
        assert_eq!(mount_posture(Some(&one)).0, MountStatus::Mounted);
        assert_eq!(mount_posture(Some(&two)).0, MountStatus::Ambiguous);
    }

    #[test]
    fn generated_mount_identity_does_not_guess_from_contract_id_suffix() -> Result<()> {
        use crate::localtx_coverage::{CanonicalMountedState, CanonicalRouteMount};
        const EFFECTS: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let spec = test_http_spec(
            "seed.semantic-name",
            "_seed_v1::filesystem_slug",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        );
        let mounts = BTreeMap::from([
            (
                "_seed_v1::filesystem_slug".to_string(),
                BTreeSet::from([CanonicalRouteMount {
                    source: "crates/_seed/src/lib.rs".to_string(),
                    handler: "filesystem_slug_handler".to_string(),
                    state: CanonicalMountedState::Stateless,
                }]),
            ),
            (
                "_seed_v1::semantic_name".to_string(),
                BTreeSet::from([CanonicalRouteMount {
                    source: "crates/_seed/src/other.rs".to_string(),
                    handler: "semantic_name_handler".to_string(),
                    state: CanonicalMountedState::Stateless,
                }]),
            ),
        ]);
        let row = build_contract_posture(
            &spec,
            &domain_scope(),
            mounts.get(spec.mount_key),
            Some(&empty_proof_source()),
        )?;
        assert_eq!(spec.mount_key, "_seed_v1::filesystem_slug");
        assert_eq!(row.route.mount_status, MountStatus::Mounted);

        let swapped = test_http_spec(
            "seed.filesystem-slug",
            "_seed_v1::semantic_name",
            vocab::HttpConsistencyLevel::LocalOnly,
            EFFECTS,
        );
        let swapped_row = build_contract_posture(
            &swapped,
            &domain_scope(),
            mounts.get(swapped.mount_key),
            Some(&empty_proof_source()),
        )?;
        assert_eq!(
            swapped_row.route.mount_sources,
            ["crates/_seed/src/other.rs"]
        );
        Ok(())
    }

    #[test]
    fn report_row_red_matrix_preserves_status_classes_sources_and_sorted_findings() -> Result<()> {
        use crate::localtx_coverage::{CanonicalMountedState, CanonicalRouteMount};
        const READ: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        const READ_WRITE: &[vocab::HttpEffectKind] = &[
            vocab::HttpEffectKind::BusinessWrite,
            vocab::HttpEffectKind::Read,
        ];
        let source_path = "crates/_seed/src/lib.rs";
        let empty = empty_proof_source();

        let missing_spec = test_http_spec(
            "seed.missing",
            "_seed_v1::missing",
            vocab::HttpConsistencyLevel::LocalOnly,
            READ_WRITE,
        );
        let missing = build_contract_posture(&missing_spec, &domain_scope(), None, None)?;
        assert_eq!(missing.route.mount_status, MountStatus::Missing);
        assert_eq!(missing.effect_proof.status, ProofStatus::Failed);
        assert_eq!(
            missing
                .findings
                .iter()
                .map(|finding| finding.rule.as_str())
                .collect::<Vec<_>>(),
            ["forbiddenStateEffect", "missingRouteBinding"]
        );

        let ambiguous_mounts = BTreeSet::from([
            CanonicalRouteMount {
                source: format!("{source_path}:2"),
                handler: "second_handler".to_string(),
                state: CanonicalMountedState::Opaque,
            },
            CanonicalRouteMount {
                source: format!("{source_path}:1"),
                handler: "first_handler".to_string(),
                state: CanonicalMountedState::Ordinary,
            },
        ]);
        let ambiguous_spec = test_http_spec(
            "seed.ambiguous",
            "_seed_v1::ambiguous",
            vocab::HttpConsistencyLevel::LocalOnly,
            READ,
        );
        let ambiguous = build_contract_posture(
            &ambiguous_spec,
            &domain_scope(),
            Some(&ambiguous_mounts),
            Some(&empty),
        )?;
        assert_eq!(ambiguous.route.mount_status, MountStatus::Ambiguous);
        assert_eq!(
            ambiguous.route.mount_sources,
            [format!("{source_path}:1"), format!("{source_path}:2")]
        );

        let receipt_registration = ReceiptRegistration::reconcile(
            BTreeSet::from(["seed.missing".to_string(), "seed.ambiguous".to_string()]),
            BTreeSet::new(),
        )?;
        let report = finalize_report(vec![missing, ambiguous], &receipt_registration)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.active_http_contract_count, 2);
        assert!(report.findings.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(report.contracts[0].contract_id, "seed.ambiguous");
        Ok(())
    }

    #[test]
    fn report_row_state_red_matrix_preserves_proof_classes() -> Result<()> {
        use crate::localtx_coverage::{CanonicalMountedState, CanonicalRouteMount};
        const READ: &[vocab::HttpEffectKind] = &[vocab::HttpEffectKind::Read];
        let source_path = "crates/_seed/src/lib.rs";
        let empty = empty_proof_source();
        let mut rows = Vec::new();

        for (id, state, expected) in [
            (
                "seed.ordinary",
                CanonicalMountedState::Ordinary,
                StateKind::Ordinary,
            ),
            (
                "seed.opaque",
                CanonicalMountedState::Opaque,
                StateKind::Opaque,
            ),
        ] {
            let spec = test_http_spec(
                id,
                "_seed_v1::state",
                vocab::HttpConsistencyLevel::LocalOnly,
                READ,
            );
            let mounts = BTreeSet::from([CanonicalRouteMount {
                source: source_path.to_string(),
                handler: "state_handler".to_string(),
                state,
            }]);
            let row = build_contract_posture(&spec, &domain_scope(), Some(&mounts), Some(&empty))?;
            assert_eq!(row.effect_proof.state_kind, Some(expected));
            assert_eq!(row.effect_proof.status, ProofStatus::Failed);
            rows.push(row);
        }

        let mut classified_source = empty_proof_source();
        classified_source.states.insert(
            "State".to_string(),
            StateImpl {
                effect: "BusinessWriteEffect".to_string(),
                privilege: "CrossTenantPrivilege".to_string(),
                subject: format!("{source_path}:1"),
            },
        );
        classified_source.structs.insert(
            "State".to_string(),
            StructInfo {
                fields: vec![StructField {
                    ty: syn::parse_quote!(DynAdmin),
                    subject: format!("{source_path}:2"),
                }],
                named_fields: BTreeMap::new(),
                subject: format!("{source_path}:1"),
            },
        );
        classified_source.ports.insert(
            "DynAdmin".to_string(),
            PortClass {
                effect: "BusinessWriteEffect".to_string(),
                privilege: "CrossTenantPrivilege".to_string(),
                subject: format!("{source_path}:3"),
                port: "DynAdmin".to_string(),
                privilege_subject: format!("{source_path}:3"),
                privilege_port: "DynAdmin".to_string(),
            },
        );
        classified_source
            .bindings
            .insert(source_path.to_string(), BTreeMap::new());
        let classified_spec = test_http_spec(
            "seed.classified",
            "_seed_v1::classified",
            vocab::HttpConsistencyLevel::LocalOnly,
            READ,
        );
        let classified_mounts = BTreeSet::from([CanonicalRouteMount {
            source: source_path.to_string(),
            handler: "classified_handler".to_string(),
            state: CanonicalMountedState::Classified(
                "State { admin: unimplemented!() }".to_string(),
            ),
        }]);
        let classified = build_contract_posture(
            &classified_spec,
            &domain_scope(),
            Some(&classified_mounts),
            Some(&classified_source),
        )?;
        assert_eq!(
            classified.effect_proof.state_kind,
            Some(StateKind::Classified)
        );
        assert_eq!(
            classified.effect_proof.effect_class.as_deref(),
            Some("BusinessWriteEffect")
        );
        assert_eq!(
            classified.effect_proof.privilege_class.as_deref(),
            Some("CrossTenantPrivilege")
        );
        assert_eq!(classified.findings.len(), 2);

        rows.push(classified);
        let receipt_registration = ReceiptRegistration::reconcile(
            BTreeSet::from([
                "seed.ordinary".to_string(),
                "seed.opaque".to_string(),
                "seed.classified".to_string(),
            ]),
            BTreeSet::new(),
        )?;
        let report = finalize_report(rows, &receipt_registration)?;
        assert_eq!(report.status, ReportStatus::Failed);
        assert_eq!(report.active_http_contract_count, 3);
        assert!(report.findings.windows(2).all(|pair| pair[0] <= pair[1]));
        assert_eq!(report.contracts[0].contract_id, "seed.classified");
        Ok(())
    }

    #[test]
    fn report_closed_vocabularies_are_exhaustively_wired() {
        use crate::contract::manifest::EffectKind as ManifestEffect;
        use vocab::HttpConsistencyLevel as Level;
        use vocab::HttpEffectKind as Effect;
        let effects = [
            Effect::Read,
            Effect::Auth,
            Effect::Projection,
            Effect::BusinessWrite,
            Effect::BusinessTransaction,
            Effect::Outbox,
            Effect::Publish,
            Effect::Workflow,
            Effect::Saga,
            Effect::Reconcile,
            Effect::Worker,
            Effect::CrossTenantAudit,
        ];
        assert_eq!(canonical_effects(&effects).len(), effects.len());
        assert_eq!(
            effects
                .iter()
                .copied()
                .filter_map(forbidden_generated_effect_wire)
                .count(),
            9
        );
        let manifest_effects = [
            ManifestEffect::Read,
            ManifestEffect::Auth,
            ManifestEffect::Projection,
            ManifestEffect::BusinessWrite,
            ManifestEffect::BusinessTransaction,
            ManifestEffect::Outbox,
            ManifestEffect::Publish,
            ManifestEffect::Workflow,
            ManifestEffect::Saga,
            ManifestEffect::Reconcile,
            ManifestEffect::Worker,
            ManifestEffect::CrossTenantAudit,
        ];
        assert_eq!(
            manifest_effects
                .into_iter()
                .filter_map(forbidden_effect_wire)
                .count(),
            9
        );
        assert_eq!(
            [
                Level::LocalOnly,
                Level::LocalTx,
                Level::OutboxFact,
                Level::WorkflowEventual,
                Level::DeviceLatent,
            ]
            .map(consistency_wire),
            [
                "LocalOnly",
                "LocalTx",
                "OutboxFact",
                "WorkflowEventual",
                "DeviceLatent"
            ]
        );
        assert_eq!(
            [
                ProofStatus::Passed,
                ProofStatus::Failed,
                ProofStatus::NotApplicable
            ]
            .map(proof_status_wire),
            ["passed", "failed", "notApplicable"]
        );
        assert_eq!(
            [
                MountStatus::Mounted,
                MountStatus::Missing,
                MountStatus::Ambiguous
            ]
            .map(mount_status_wire),
            ["mounted", "missing", "ambiguous"]
        );
        assert_eq!(
            [
                Some(StateKind::Stateless),
                Some(StateKind::Ordinary),
                Some(StateKind::Classified),
                Some(StateKind::Opaque),
                None,
            ]
            .map(option_state_wire),
            ["stateless", "ordinary", "classified", "opaque", "null"]
        );
        for rule in [
            Rule::MissingRouteBinding,
            Rule::UnclassifiedState,
            Rule::ForbiddenStateEffect,
            Rule::CrossTenantPrivilege,
            Rule::OpaqueSourceScope,
        ] {
            assert!(
                !report_finding(&finding(rule, "subject", "detail"))
                    .rule
                    .is_empty()
            );
        }
    }

    #[test]
    fn incomplete_metadata_is_a_hard_error() {
        for fixture_name in [
            "missing_profile",
            "missing_kind",
            "missing_path",
            "missing_method",
        ] {
            assert!(
                check_root(&fixture(fixture_name)).is_err(),
                "{fixture_name}"
            );
        }
    }

    #[test]
    fn strongest_effect_ranking_is_fail_closed() {
        assert!(effect_rank("BogusEffect") > effect_rank("WorkflowEffect"));
        assert!(effect_rank("WorkflowEffect") > effect_rank("BusinessWriteEffect"));
    }

    #[test]
    fn same_named_fake_classification_macro_is_not_canonical() -> Result<()> {
        let syntax: syn::File =
            syn::parse_str("macro_rules! classify_demo_ports { ($($tokens:tt)*) => {}; }")?;
        let mut trusted = BTreeSet::new();
        assert!(
            collect_trusted_port_macro_definitions(
                &syntax.items,
                "crates/demo/src/ports.rs",
                "demo",
                &mut trusted,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn state_classification_rejects_strongest_effect_lies() {
        let source = ProofSource {
            states: BTreeMap::from([(
                "ReadState".to_string(),
                StateImpl {
                    effect: "ReadEffect".to_string(),
                    privilege: "LocalPrivilege".to_string(),
                    subject: "crates/demo/src/lib.rs:2".to_string(),
                },
            )]),
            structs: BTreeMap::from([(
                "ReadState".to_string(),
                StructInfo {
                    fields: vec![StructField {
                        ty: syn::parse_quote!(DynWriter),
                        subject: "crates/demo/src/lib.rs:1".to_string(),
                    }],
                    named_fields: BTreeMap::from([("repo".to_string(), "DynWriter".to_string())]),
                    subject: "crates/demo/src/lib.rs:1".to_string(),
                },
            )]),
            ports: BTreeMap::from([(
                "DynWriter".to_string(),
                PortClass {
                    effect: "BusinessWriteEffect".to_string(),
                    privilege: "LocalPrivilege".to_string(),
                    subject: "crates/demo/src/ports.rs".to_string(),
                    port: "DynWriter".to_string(),
                    privilege_subject: "crates/demo/src/ports.rs".to_string(),
                    privilege_port: "DynWriter".to_string(),
                },
            )]),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        assert!(source.classify_state("ReadState").is_err());
    }

    #[test]
    fn composite_state_aggregates_strongest_effect_and_cross_tenant_privilege() -> Result<()> {
        let source = ProofSource {
            states: BTreeMap::from([(
                "State".to_string(),
                StateImpl {
                    effect: "BusinessWriteEffect".to_string(),
                    privilege: "CrossTenantPrivilege".to_string(),
                    subject: "crates/demo/src/lib.rs:4".to_string(),
                },
            )]),
            structs: BTreeMap::from([(
                "State".to_string(),
                StructInfo {
                    fields: vec![StructField {
                        ty: syn::parse_quote!((DynWriter, DynAdmin)),
                        subject: "crates/demo/src/lib.rs:2".to_string(),
                    }],
                    named_fields: BTreeMap::new(),
                    subject: "crates/demo/src/lib.rs:1".to_string(),
                },
            )]),
            ports: BTreeMap::from([
                (
                    "DynWriter".to_string(),
                    PortClass {
                        effect: "BusinessWriteEffect".to_string(),
                        privilege: "LocalPrivilege".to_string(),
                        subject: "crates/demo/src/ports.rs:10".to_string(),
                        port: "DynWriter".to_string(),
                        privilege_subject: "crates/demo/src/ports.rs:10".to_string(),
                        privilege_port: "DynWriter".to_string(),
                    },
                ),
                (
                    "DynAdmin".to_string(),
                    PortClass {
                        effect: "ReadEffect".to_string(),
                        privilege: "CrossTenantPrivilege".to_string(),
                        subject: "crates/demo/src/ports.rs:11".to_string(),
                        port: "DynAdmin".to_string(),
                        privilege_subject: "crates/demo/src/ports.rs:11".to_string(),
                        privilege_port: "DynAdmin".to_string(),
                    },
                ),
            ]),
            type_aliases: BTreeMap::new(),
            bindings: BTreeMap::new(),
            trusted_port_macros: BTreeSet::new(),
        };
        let class = source.classify_state("State")?;
        assert_eq!(class.effect, "BusinessWriteEffect");
        assert_eq!(class.privilege, "CrossTenantPrivilege");
        Ok(())
    }

    #[test]
    fn cfg_feature_named_contest_is_not_mistaken_for_cfg_test() -> Result<()> {
        let syntax: syn::File = syn::parse_str("#[cfg(feature = \"contest\")] fn live() {}")?;
        let Item::Fn(function) = &syntax.items[0] else {
            bail!("fixture must be a function");
        };
        assert!(attrs_are_production(&function.attrs));
        Ok(())
    }

    #[test]
    fn complete_green_workspace_compiles_and_closes_the_canonical_mount() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let output = workspace.cargo_check()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (summary, findings) = check_root(&workspace.0)?;
        assert_eq!(
            summary,
            "1 active LocalOnly HTTP contract(s) checked; source receipts registered 0/1; missing: demo.safe"
        );
        assert!(
            findings
                .iter()
                .all(|finding| matches!(finding.rule, Rule::MissingLocalOnlyReceipt))
        );
        Ok(())
    }

    #[test]
    fn canonical_mount_and_state_red_matrix_is_fail_closed() -> Result<()> {
        let cases = [
            (
                "ordinary",
                ".with_classified_state(state)",
                ".with_state(state)",
            ),
            (
                "unclassified",
                "impl ::httpserve::ClassifiedRouteState for ReadState",
                "impl Unrelated for ReadState",
            ),
            (
                "non-domain",
                "impl ::bootstrap::Domain for Demo",
                "impl Demo",
            ),
            (
                "cfg-disabled",
                "impl ::bootstrap::Domain for Demo",
                "#[cfg(test)] impl ::bootstrap::Domain for Demo",
            ),
            ("unmounted", "Ok(router.mount(", "Ok(router.fake_mount("),
        ];
        for (name, from, to) in cases {
            let workspace = WorkspaceFixture::new()?;
            workspace.replace(&workspace.source(), from, to)?;
            assert!(
                !check_root(&workspace.0)?.1.is_empty(),
                "{name} unexpectedly passed"
            );
        }
        Ok(())
    }

    #[test]
    fn alias_strongest_effect_and_fake_macro_are_rejected() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        workspace.replace(
            &workspace.ports(),
            "pub type DynReadRepo = dyn ReadRepo;",
            "pub type DynReadRepo = dyn ReadRepo; pub trait WriteRepo: Send + Sync {} pub type DynWriteRepo = dyn WriteRepo;",
        )?;
        workspace.replace(
            &workspace.ports(),
            "classify_demo_ports!(DynReadRepo => diport::ReadEffect);",
            "classify_demo_ports!(DynReadRepo => diport::ReadEffect); classify_demo_ports!(DynWriteRepo => diport::BusinessWriteEffect);",
        )?;
        workspace.replace(
            &workspace.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type HiddenWriter = Arc<ports::DynWriteRepo>; struct ReadState { repo: Arc<DynReadRepo>, hidden: HiddenWriter }",
        )?;
        workspace.replace(
            &workspace.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        let findings = check_root(&workspace.0)?.1;
        assert!(
            findings
                .iter()
                .any(|item| matches!(item.rule, Rule::OpaqueSourceScope))
        );

        let fake = WorkspaceFixture::new()?;
        fake.replace(
            &fake.ports(),
            "macro_rules! classify_demo_ports {",
            "macro_rules! classify_demo_ports_fake {",
        )?;
        assert!(
            check_root(&fake.0).is_err(),
            "same-shaped fake macro must fail closed"
        );
        Ok(())
    }

    #[test]
    fn composite_capability_leaves_are_order_independent_and_fail_closed() -> Result<()> {
        for field_ty in [
            "(Arc<DynReadRepo>, Arc<ports::DynWriteRepo>)",
            "(Arc<ports::DynWriteRepo>, Arc<DynReadRepo>)",
            "Option<Vec<[Arc<ports::DynWriteRepo>; 1]>>",
            "&'static Arc<ports::DynWriteRepo>",
        ] {
            let workspace = WorkspaceFixture::new()?;
            workspace.add_write_port()?;
            workspace.replace(
                &workspace.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!("struct ReadState {{ repo: Arc<DynReadRepo>, hidden: {field_ty} }}"),
            )?;
            workspace.replace(
                &workspace.source(),
                "ReadState { repo: unimplemented!() }",
                "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
            )?;
            workspace.assert_compiles_and_is_rejected()?;
        }

        let alias = WorkspaceFixture::new()?;
        alias.add_write_port()?;
        alias.replace(
            &alias.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type Hidden = (Arc<DynReadRepo>, Arc<ports::DynWriteRepo>); struct ReadState { repo: Arc<DynReadRepo>, hidden: Hidden }",
        )?;
        alias.replace(
            &alias.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        alias.assert_compiles_and_is_rejected()?;

        let generic_alias = WorkspaceFixture::new()?;
        generic_alias.add_write_port()?;
        generic_alias.replace(
            &generic_alias.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "type Hidden<T> = (T, Option<Arc<ports::DynWriteRepo>>); struct ReadState { repo: Arc<DynReadRepo>, hidden: Hidden<Arc<DynReadRepo>> }",
        )?;
        generic_alias.replace(
            &generic_alias.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        generic_alias.assert_compiles_and_is_rejected()?;
        Ok(())
    }

    #[test]
    fn sync_diport_and_unknown_trait_objects_are_fail_closed() -> Result<()> {
        for capability in [
            "Arc<dyn diport::SubscribeInitializer>",
            "Arc<diport::DynSubscriber<'static>>",
        ] {
            let workflow = WorkspaceFixture::new()?;
            workflow.replace(
                &workflow.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!(
                    "struct ReadState {{ repo: Arc<DynReadRepo>, subscription: {capability} }}"
                ),
            )?;
            workflow.replace(
                &workflow.source(),
                "ReadState { repo: unimplemented!() }",
                "ReadState { repo: unimplemented!(), subscription: unimplemented!() }",
            )?;
            workflow.assert_compiles_and_is_rejected()?;
        }

        let unknown = WorkspaceFixture::new()?;
        unknown.replace(
            &unknown.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "trait UnknownCapability: Send + Sync {} struct ReadState { repo: Arc<DynReadRepo>, unknown: Arc<dyn UnknownCapability> }",
        )?;
        unknown.replace(
            &unknown.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), unknown: unimplemented!() }",
        )?;
        unknown.assert_compiles_and_is_rejected()?;
        Ok(())
    }

    #[test]
    fn production_cfg_boolean_semantics_cannot_hide_capabilities() -> Result<()> {
        for cfg in [
            "not(test)",
            "any(test, not(test))",
            "all(not(test), any())",
            "feature = \"production_possible\"",
        ] {
            let workspace = WorkspaceFixture::new()?;
            workspace.add_write_port()?;
            workspace.replace(
                &workspace.source(),
                "struct ReadState { repo: Arc<DynReadRepo> }",
                &format!(
                    "struct ReadState {{ repo: Arc<DynReadRepo>, #[cfg({cfg})] hidden: Arc<ports::DynWriteRepo> }}"
                ),
            )?;
            workspace.replace(
                &workspace.source(),
                "ReadState { repo: unimplemented!() }",
                &format!(
                    "ReadState {{ repo: unimplemented!(), #[cfg({cfg})] hidden: unimplemented!() }}"
                ),
            )?;
            let output = workspace.cargo_check()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let findings = check_root(&workspace.0)?.1;
            if cfg != "all(not(test), any())" {
                assert!(!findings.is_empty(), "cfg({cfg}) unexpectedly hid a writer");
            } else {
                assert!(
                    findings
                        .iter()
                        .all(|finding| matches!(finding.rule, Rule::MissingLocalOnlyReceipt)),
                    "cfg({cfg}) is constantly false"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn forbidden_diagnostic_preserves_contract_and_field_provenance() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        workspace.add_write_port()?;
        workspace.replace(
            &workspace.source(),
            "struct ReadState { repo: Arc<DynReadRepo> }",
            "struct ReadState { repo: Arc<DynReadRepo>, hidden: Arc<ports::DynWriteRepo> }",
        )?;
        workspace.replace(
            &workspace.source(),
            "ReadState { repo: unimplemented!() }",
            "ReadState { repo: unimplemented!(), hidden: unimplemented!() }",
        )?;
        let findings = workspace.assert_compiles_and_is_rejected()?;
        let finding = findings
            .iter()
            .find(|finding| matches!(finding.rule, Rule::OpaqueSourceScope))
            .ok_or_else(|| anyhow!("expected strongest-effect mismatch"))?;
        assert!(finding.detail.contains("contract `demo.safe` GET /demo"));
        assert!(finding.detail.contains("crates/demo/src/lib.rs:"));
        assert!(finding.detail.contains("crates/demo/src/ports.rs:"));
        Ok(())
    }

    #[test]
    fn generated_non_localonly_marker_is_rejected() -> Result<()> {
        let workspace = WorkspaceFixture::new()?;
        let generated = workspace.0.join("generated/src/http/demo_v1.rs");
        workspace.replace(&generated, "http::LocalOnly", "http::LocalTx")?;
        assert!(check_root(&workspace.0).is_err());
        Ok(())
    }

    #[test]
    fn dead_helper_cannot_supply_evidence_and_endpoint_wrapper_is_opaque() -> Result<()> {
        let dead = WorkspaceFixture::new()?;
        dead.replace(
            &dead.source(),
            "struct Demo;",
            r#"fn dead_helper(state: ReadState) {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::safe::ROUTE,
        handler,
    ).unwrap().with_classified_state(state);
}
struct Demo;"#,
        )?;
        assert!(
            check_root(&dead.0)?
                .1
                .iter()
                .all(|finding| { matches!(finding.rule, Rule::MissingLocalOnlyReceipt) }),
            "dead helper polluted mount evidence"
        );

        let wrapper = WorkspaceFixture::new()?;
        wrapper.replace(
            &wrapper.source(),
            "struct Demo;",
            "fn identity(value: ::httpserve::GeneratedPrimaryEndpoint) -> ::httpserve::GeneratedPrimaryEndpoint { value }\nstruct Demo;",
        )?;
        wrapper.replace(
            &wrapper.source(),
            "Ok(router.mount(",
            "Ok(router.mount(identity(",
        )?;
        wrapper.replace(&wrapper.source(), "            )?)", "            ))?)")?;
        assert!(
            !check_root(&wrapper.0)?.1.is_empty(),
            "opaque endpoint wrapper passed"
        );
        Ok(())
    }

    #[test]
    fn every_forbidden_effect_and_cross_tenant_privilege_is_red() -> Result<()> {
        for effect in ["BusinessWriteEffect", "OutboxEffect", "WorkflowEffect"] {
            let workspace = WorkspaceFixture::new()?;
            workspace.replace(&workspace.ports(), "ReadEffect);", &format!("{effect});"))?;
            assert!(
                !check_root(&workspace.0)?.1.is_empty(),
                "{effect} unexpectedly passed"
            );
        }
        let workspace = WorkspaceFixture::new()?;
        workspace.replace(
            &workspace.source(),
            "type Privilege = ::diport::LocalPrivilege;",
            "type Privilege = ::diport::CrossTenantPrivilege;",
        )?;
        assert!(
            !check_root(&workspace.0)?.1.is_empty(),
            "cross-tenant unexpectedly passed"
        );
        Ok(())
    }
}
