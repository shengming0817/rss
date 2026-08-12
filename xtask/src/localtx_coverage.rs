//! LocalTx static coverage closure gate.
//!
//! INVARIANT: LOCALTX-COVERAGE-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "missing_route_and_duplicate_marker_are_rejected|invalid_domain_owner_is_rejected|path_dependency_source_is_rejected_even_when_root_matches", anti_vacuity = "green_fixture_closes_every_active_localtx_contract" }.
//! INVARIANT: LOCALTX-BACKEND-PROFILE-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "active_contract_without_backend_profile_is_rejected|backend_profile_missing_required_probe_is_rejected|unawaited_backend_probe_does_not_count|tenant_contract_cannot_enroll_repo_atomic_probe_set|multiple_backend_profiles_in_one_test_function_are_rejected|backend_profile_non_executable_test_attributes_are_rejected|backend_profile_shadow_constructor_is_rejected|backend_profile_nested_constructor_bait_is_rejected|backend_profile_synthetic_action_is_rejected|backend_profile_observer_binding_does_not_count|backend_profile_bare_provider_reference_is_rejected|backend_profile_free_function_provider_argument_is_rejected|backend_profile_discarded_provider_call_is_rejected|backend_profile_unpolled_provider_future_is_rejected", anti_vacuity = "single_backend_profile_in_test_function_is_accepted|actual_workspace_has_non_empty_complete_localtx_closure" }.
//! INVARIANT: LOCALTX-JOURNEY-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "fixture_mutation_requires_exactly_one_match|journey_missing_entry_is_rejected|journey_extra_entry_is_rejected|journey_duplicate_entry_is_rejected|journey_legacy_scope_is_rejected|journey_wrong_tx_model_is_rejected|journey_missing_scenario_is_rejected|journey_non_commit_unknown_case_requires_commits|journey_fake_logout_conflict_is_rejected|journey_missing_board_is_rejected|journey_unknown_board_field_is_rejected|journey_unknown_spec_field_is_rejected|journey_unknown_fixture_field_is_rejected|journey_dangling_spec_is_rejected|journey_spec_metadata_drift_identifies_field_and_values|journey_fixture_metadata_drift_identifies_field_and_values|journey_missing_typed_marker_is_rejected|journey_marker_without_test_attribute_is_rejected|journey_marker_in_unused_closure_is_rejected|journey_ignored_test_is_rejected|journey_cfg_disabled_test_is_rejected|journey_cfg_disabled_ancestor_is_rejected|journey_should_panic_test_is_rejected|journey_wrong_route_marker_is_rejected|journey_missing_case_consumption_is_rejected|journey_duplicate_case_consumption_is_rejected|journey_dynamic_case_consumption_is_rejected|journey_unobserved_case_values_are_rejected|journey_target_must_require_integration|journey_runner_extra_marker_is_rejected|journey_runner_duplicate_marker_is_rejected", anti_vacuity = "journey_green_fixture_closes_active_matrix|journey_markers_may_span_real_tests|journey_entries_may_use_distinct_runners|journey_commit_unknown_case_may_omit_commits|actual_workspace_closes_active_localtx_journeys" }.
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-EXACTSET-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "required_evidence_counts_reject_wrong_carrier_and_distinct_profile_gap|required_evidence_exact_set_rejects_equal_count_wrong_set|required_evidence_backend_profiles_reject_noncanonical_execution_carriers", anti_vacuity = "actual_workspace_has_verified_localtx_evidence_exact_set" }.

use crate::contract::governance::ContractGovernanceIr;
use crate::contract::manifest::{
    ConsistencyLevel, ContractKind, Lifecycle, LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel,
    LocalTxRetry,
};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use syn::spanned::Spanned as _;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprMethodCall, File, FnArg, GenericArgument, Item, ItemConst,
    ItemFn, Meta, PathArguments, Stmt, Type, UseTree,
};
use workspacefacts::{
    DependencyKind as FactsDependencyKind, DependencySource, TargetKind as FactsTargetKind,
    WorkspaceFacts,
};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    InvalidDomainOwner,
    MissingOwnerCrate,
    MissingGeneratedSpec,
    UnexpectedGeneratedSpec,
    MissingRouteBinding,
    MissingTestMarker,
    DuplicateTestMarker,
    UnexpectedTestMarker,
    MissingBackendProfile,
    MissingBackendProviderBinding,
    ForbiddenBackendProfileEvidence,
    MissingBackendProbe,
    MultipleBackendProfilesInTest,
    UnexpectedBackendProfile,
    OpaqueSourceScope,
}

impl Rule {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 15] = [
        Self::InvalidDomainOwner,
        Self::MissingOwnerCrate,
        Self::MissingGeneratedSpec,
        Self::UnexpectedGeneratedSpec,
        Self::MissingRouteBinding,
        Self::MissingTestMarker,
        Self::DuplicateTestMarker,
        Self::UnexpectedTestMarker,
        Self::MissingBackendProfile,
        Self::MissingBackendProviderBinding,
        Self::ForbiddenBackendProfileEvidence,
        Self::MissingBackendProbe,
        Self::MultipleBackendProfilesInTest,
        Self::UnexpectedBackendProfile,
        Self::OpaqueSourceScope,
    ];

    pub(crate) const fn report_wire(self) -> &'static str {
        match self {
            Self::InvalidDomainOwner => "InvalidDomainOwner",
            Self::MissingOwnerCrate => "MissingOwnerCrate",
            Self::MissingGeneratedSpec => "MissingGeneratedSpec",
            Self::UnexpectedGeneratedSpec => "UnexpectedGeneratedSpec",
            Self::MissingRouteBinding => "MissingRouteBinding",
            Self::MissingTestMarker => "MissingTestMarker",
            Self::DuplicateTestMarker => "DuplicateTestMarker",
            Self::UnexpectedTestMarker => "UnexpectedTestMarker",
            Self::MissingBackendProfile => "MissingBackendProfile",
            Self::MissingBackendProviderBinding => "MissingBackendProviderBinding",
            Self::ForbiddenBackendProfileEvidence => "ForbiddenBackendProfileEvidence",
            Self::MissingBackendProbe => "MissingBackendProbe",
            Self::MultipleBackendProfilesInTest => "MultipleBackendProfilesInTest",
            Self::UnexpectedBackendProfile => "UnexpectedBackendProfile",
            Self::OpaqueSourceScope => "OpaqueSourceScope",
        }
    }
}

pub(crate) struct LocalTxCoverage<'a> {
    root: &'a Path,
    facts: &'a WorkspaceFacts,
}

impl<'a> LocalTxCoverage<'a> {
    pub(crate) fn new(root: &'a Path, facts: &'a WorkspaceFacts) -> Self {
        Self { root, facts }
    }
}

impl GovernanceCheck for LocalTxCoverage<'_> {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "localtx-coverage"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        collect_workspace_inventory(self.root, self.facts).map(LocalTxProofInventory::into_gate)
    }
}

#[derive(Debug)]
struct Contract {
    id: String,
    owner: String,
    key: String,
    subject: String,
    valid_owner: bool,
    tx_model: LocalTxModel,
    boundary: LocalTxBoundary,
    retry: LocalTxRetry,
    commit_unknown: LocalTxCommitUnknown,
}

/// Canonical LocalTx proof input. Fields and construction stay private so the gate and report can
/// only consume one fully collected, structurally validated inventory.
pub(crate) struct LocalTxProofInventory {
    summary: String,
    contracts: Vec<LocalTxProofContract>,
    backend_profile_violations: Vec<BackendProfileViolation>,
    unexpected_test_markers: Vec<MarkerOccurrence>,
    unexpected_backend_profiles: Vec<BackendEnrollmentOccurrence>,
    unexpected_generated: Vec<String>,
    cargo_targets: Vec<BackendCarrierIdentity>,
}

/// Private exact-set proof that active LocalTx contracts, journeys, and backend profiles close the
/// same sorted contract-id set. Construction is confined to required-evidence verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedLocalTxContractSet {
    active_contract_ids: Vec<String>,
    journey_contract_ids: Vec<String>,
    backend_profile_contract_ids: Vec<String>,
}

impl VerifiedLocalTxContractSet {
    pub(crate) fn active_contract_ids(&self) -> &[String] {
        &self.active_contract_ids
    }

    #[cfg(test)]
    pub(crate) fn journey_contract_ids(&self) -> &[String] {
        &self.journey_contract_ids
    }

    #[cfg(test)]
    pub(crate) fn backend_profile_contract_ids(&self) -> &[String] {
        &self.backend_profile_contract_ids
    }

    #[cfg(test)]
    pub(crate) fn contract_count(&self) -> usize {
        self.active_contract_ids.len()
    }
}

impl LocalTxProofInventory {
    fn new(
        summary: String,
        contracts: Vec<LocalTxProofContract>,
        backend_profile_violations: Vec<BackendProfileViolation>,
        unexpected_test_markers: Vec<MarkerOccurrence>,
        unexpected_backend_profiles: Vec<BackendEnrollmentOccurrence>,
        unexpected_generated: Vec<String>,
        cargo_targets: Vec<BackendCarrierIdentity>,
    ) -> Self {
        Self {
            summary,
            contracts,
            backend_profile_violations,
            unexpected_test_markers,
            unexpected_backend_profiles,
            unexpected_generated,
            cargo_targets,
        }
    }

    fn into_gate(self) -> (String, Vec<Finding>) {
        let findings = evaluate_inventory(&self);
        (self.summary, findings)
    }

    pub(crate) fn findings(&self) -> Vec<Finding> {
        evaluate_inventory(self)
    }

    pub(crate) fn contracts(&self) -> &[LocalTxProofContract] {
        &self.contracts
    }
}

pub(crate) struct LocalTxProofContract {
    contract_id: String,
    owner: String,
    key: String,
    subject: String,
    valid_owner: bool,
    owner_present: bool,
    test_markers: Vec<MarkerOccurrence>,
    opaque_triggers: Vec<OpaqueTrigger>,
    boundary: LocalTxBoundary,
    tx_model: LocalTxModel,
    retry: LocalTxRetry,
    commit_unknown: LocalTxCommitUnknown,
    manifest: LocalTxProofEvidence,
    generated: LocalTxProofEvidence,
    route: LocalTxProofEvidence,
    test: LocalTxProofEvidence,
    backend_profiles: Vec<LocalTxProofBackendProfile>,
    journey: LocalTxProofJourney,
}

impl LocalTxProofContract {
    pub(crate) fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) fn boundary(&self) -> LocalTxBoundary {
        self.boundary
    }

    pub(crate) fn tx_model(&self) -> LocalTxModel {
        self.tx_model
    }

    pub(crate) fn retry(&self) -> LocalTxRetry {
        self.retry
    }

    pub(crate) fn commit_unknown(&self) -> LocalTxCommitUnknown {
        self.commit_unknown
    }

    pub(crate) fn manifest(&self) -> &LocalTxProofEvidence {
        &self.manifest
    }

    pub(crate) fn generated(&self) -> &LocalTxProofEvidence {
        &self.generated
    }

    pub(crate) fn route(&self) -> &LocalTxProofEvidence {
        &self.route
    }

    pub(crate) fn test(&self) -> &LocalTxProofEvidence {
        &self.test
    }

    pub(crate) fn backend_profiles(&self) -> &[LocalTxProofBackendProfile] {
        &self.backend_profiles
    }

    pub(crate) fn journey(&self) -> &LocalTxProofJourney {
        &self.journey
    }
}

pub(crate) struct LocalTxProofEvidence {
    complete: bool,
    sources: Vec<String>,
}

impl LocalTxProofEvidence {
    fn new(complete: bool, mut sources: Vec<String>) -> Self {
        sources.sort();
        sources.dedup();
        Self { complete, sources }
    }

    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn sources(&self) -> &[String] {
        &self.sources
    }
}

pub(crate) struct LocalTxProofBackendProfile {
    provider: String,
    fixture: String,
    valid_provider: bool,
    sources: Vec<String>,
    required_probes: Vec<(BackendProbe, usize)>,
    observed_probes: Vec<(BackendProbe, usize)>,
    missing_probes: Vec<(BackendProbe, usize, usize)>,
    carrier: Option<BackendCarrierIdentity>,
}

impl LocalTxProofBackendProfile {
    pub(crate) fn provider(&self) -> &str {
        &self.provider
    }

    pub(crate) fn fixture(&self) -> &str {
        &self.fixture
    }

    pub(crate) fn valid_provider(&self) -> bool {
        self.valid_provider
    }

    pub(crate) fn complete(&self) -> bool {
        self.valid_provider && self.missing_probes.is_empty()
    }

    pub(crate) fn sources(&self) -> &[String] {
        &self.sources
    }

    pub(crate) fn required_probes(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.required_probes.iter().map(|(probe, _)| probe.label())
    }

    pub(crate) fn observed_probes(&self) -> impl Iterator<Item = (&'static str, usize)> + '_ {
        self.observed_probes
            .iter()
            .map(|(probe, count)| (probe.label(), *count))
    }

    pub(crate) fn missing_probes(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.missing_probes
            .iter()
            .map(|(probe, _, _)| probe.label())
    }
}

pub(crate) struct LocalTxProofJourney {
    spec: String,
    fixture: String,
    runner: String,
    scenarios: Vec<LocalTxProofJourneyScenario>,
}

impl LocalTxProofJourney {
    pub(crate) fn spec(&self) -> &str {
        &self.spec
    }

    pub(crate) fn fixture(&self) -> &str {
        &self.fixture
    }

    pub(crate) fn runner(&self) -> &str {
        &self.runner
    }

    pub(crate) fn scenarios(&self) -> &[LocalTxProofJourneyScenario] {
        &self.scenarios
    }
}

#[derive(Debug)]
pub(crate) struct LocalTxProofJourneyScenario {
    kind: JourneyScenarioKind,
    applicable: bool,
    reason: Option<String>,
}

impl LocalTxProofJourneyScenario {
    pub(crate) fn kind(&self) -> &'static str {
        self.kind.label()
    }

    pub(crate) fn applicable(&self) -> bool {
        self.applicable
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

#[derive(Debug, Clone)]
struct WorkspaceCrate {
    name: String,
    relative: PathBuf,
    root: PathBuf,
    targets: Vec<CargoTarget>,
    normal_dependencies: BTreeMap<String, DependencyRef>,
    dev_dependencies: BTreeMap<String, DependencyRef>,
    normal_test_dependencies: BTreeMap<String, DependencyRef>,
    dev_test_dependencies: BTreeMap<String, DependencyRef>,
}

#[derive(Debug, Clone)]
struct CargoTarget {
    name: String,
    path: PathBuf,
    kind: CargoTargetKind,
    required_features: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CargoTargetKind {
    Lib,
    Test,
    Other,
}

impl CargoTargetKind {
    const fn matches(self, expected: crate::integration_shards::TargetKind) -> bool {
        matches!(
            (self, expected),
            (Self::Lib, crate::integration_shards::TargetKind::Lib)
                | (Self::Test, crate::integration_shards::TargetKind::Test)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BackendCarrierIdentity {
    package: String,
    target: String,
    kind: CargoTargetKind,
    target_root: String,
    required_features: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct DependencyRef {
    package: String,
    path: Option<PathBuf>,
    source: DependencySource,
    unconditional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MarkerOccurrence {
    key: String,
    owner: String,
    path: String,
    ordinal: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BackendProbe {
    Commit,
    Rollback,
    RejectedNoWrite,
    TenantIsolation,
    RetryBoundary,
    CommitUnknownNoReplay,
    RollbackFailedNoReplay,
}

impl BackendProbe {
    const fn label(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Rollback => "rollback",
            Self::RejectedNoWrite => "rejected-no-write",
            Self::TenantIsolation => "tenant-isolation",
            Self::RetryBoundary => "retry-boundary",
            Self::CommitUnknownNoReplay => "commit-unknown-no-replay",
            Self::RollbackFailedNoReplay => "rollback-failed-no-replay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendEnrollmentOccurrence {
    key: String,
    provider: String,
    provider_fixture: String,
    path: String,
    probes: BTreeMap<BackendProbe, usize>,
    carrier: Option<BackendCarrierIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendProfileMarker {
    name: String,
    key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendProviderBinding {
    name: String,
    key: String,
    provider_path: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendProfileViolation {
    rule: Rule,
    provider: String,
    path: String,
    function: String,
    detail: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct BackendTestEvidence {
    enrollments: Vec<BackendEnrollmentOccurrence>,
    violation: Option<BackendProfileViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OpaqueTrigger {
    subject: String,
    attribute: String,
}

const JOURNEY_BOARD_PATH: &str = "journeys/status-board.toml";
#[cfg(test)]
const GREEN_JOURNEY_RUNNER_PATH: &str = "journeys/tests/localtx_validation_journey.rs";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyBoard {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    scope: String,
    journeys: Vec<JourneyBoardEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyBoardEntry {
    id: String,
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "txModel")]
    tx_model: LocalTxModel,
    spec: String,
    fixture: String,
    runner: String,
    marker: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneySpec {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    id: String,
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "txModel")]
    tx_model: LocalTxModel,
    fixture: String,
    runner: String,
    marker: String,
    scenarios: Vec<JourneyScenario>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyFixture {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    id: String,
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "txModel")]
    tx_model: LocalTxModel,
    spec: String,
    runner: String,
    marker: String,
    cases: Vec<JourneyCase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JourneyScenarioKind {
    Happy,
    AuthFailure,
    ValidationFailure,
    Conflict,
    Contention,
    CommitUnknown,
}

impl JourneyScenarioKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Happy => "happy",
            Self::AuthFailure => "auth-failure",
            Self::ValidationFailure => "validation-failure",
            Self::Conflict => "conflict",
            Self::Contention => "contention",
            Self::CommitUnknown => "commit-unknown",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyScenario {
    kind: JourneyScenarioKind,
    applicable: bool,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JourneyCase {
    id: String,
    scenario: JourneyScenarioKind,
    #[serde(rename = "httpStatus")]
    http_status: u16,
    #[serde(rename = "errorCode")]
    error_code: String,
    retryable: bool,
    attempts: u16,
    commits: Option<u16>,
    #[serde(rename = "redactSentinels")]
    redact_sentinels: Vec<String>,
}

#[derive(Debug)]
struct JourneyClosureEntry {
    contract_id: String,
    tx_model: LocalTxModel,
    spec: String,
    fixture: String,
    runner: String,
    marker: String,
    marker_key: String,
    case_ids: BTreeSet<String>,
    scenarios: Vec<LocalTxProofJourneyScenario>,
}

#[derive(Debug)]
struct JourneyClosure {
    entries: Vec<JourneyClosureEntry>,
    runners: BTreeSet<String>,
}

#[derive(Debug)]
struct JourneyRunnerEvidence {
    markers: BTreeMap<String, String>,
    marker_tests: BTreeMap<String, usize>,
    case_ids: BTreeSet<String>,
    case_tests: BTreeMap<String, usize>,
    observation_error: Option<String>,
}

#[derive(Debug, Default)]
struct JourneyRunnerExpectation {
    markers: BTreeSet<String>,
    cases: BTreeSet<String>,
}

#[derive(Debug)]
struct JourneyCaseCallEvidence {
    parsed: Result<(String, String), String>,
    test: Option<usize>,
}

pub(crate) fn collect_workspace_inventory(
    root: &Path,
    facts: &WorkspaceFacts,
) -> Result<LocalTxProofInventory> {
    collect_inventory(root, facts, &compiled_local_tx_keys()?)
}

#[derive(Debug)]
struct RequiredEvidenceContractSets {
    active: BTreeSet<String>,
    journeys: BTreeSet<String>,
    backend_profiles: BTreeSet<String>,
}

fn required_evidence_contract_sets(
    inventory: &LocalTxProofInventory,
    backend_execution: &crate::integration_shards::IntegrationUnitSpec,
) -> Result<RequiredEvidenceContractSets> {
    let matching_targets = inventory
        .cargo_targets
        .iter()
        .filter(|target| {
            target.package == backend_execution.package
                && target.target == backend_execution.target
                && target.kind.matches(backend_execution.kind)
        })
        .collect::<Vec<_>>();
    let [backend_carrier] = matching_targets.as_slice() else {
        bail!(
            "LocalTx backend execution unit must resolve to exactly one Cargo target; package={} target={} kind={:?}; found {}",
            backend_execution.package,
            backend_execution.target,
            backend_execution.kind,
            matching_targets.len()
        );
    };
    if backend_execution.scheduling != crate::integration_shards::Scheduling::Serial {
        bail!("LocalTx backend execution carrier must remain Serial");
    }
    if !backend_carrier.required_features.is_empty() {
        bail!(
            "LocalTx backend execution carrier `{}` has target-level required-features {:?}; the typed shard does not model target feature activation",
            backend_carrier.target_root,
            backend_carrier.required_features
        );
    }
    let mut sets = RequiredEvidenceContractSets {
        active: BTreeSet::new(),
        journeys: BTreeSet::new(),
        backend_profiles: BTreeSet::new(),
    };
    for contract in &inventory.contracts {
        sets.active.insert(contract.contract_id.clone());
        if !contract.journey.spec.is_empty()
            && !contract.journey.fixture.is_empty()
            && !contract.journey.runner.is_empty()
        {
            sets.journeys.insert(contract.contract_id.clone());
        }
        for profile in &contract.backend_profiles {
            if profile.provider != backend_carrier.package
                || profile.carrier.as_ref() != Some(*backend_carrier)
            {
                bail!(
                    "LocalTx contract `{}` backend profile carrier is provider=`{}` target={:?}; expected typed postgres-domain carrier {:?}",
                    contract.contract_id,
                    profile.provider,
                    profile.carrier,
                    backend_carrier,
                );
            }
        }
        if contract
            .backend_profiles
            .iter()
            .any(LocalTxProofBackendProfile::complete)
        {
            sets.backend_profiles.insert(contract.contract_id.clone());
        }
    }
    Ok(sets)
}

pub(crate) fn localtx_exact_set_difference_summary(
    active: &[String],
    journeys: &[String],
    backend_profiles: &[String],
) -> String {
    let active = active.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let journeys = journeys.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let backend_profiles = backend_profiles
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_from_journeys = active.difference(&journeys).copied().collect::<Vec<_>>();
    let extra_in_journeys = journeys.difference(&active).copied().collect::<Vec<_>>();
    let missing_from_backend = active
        .difference(&backend_profiles)
        .copied()
        .collect::<Vec<_>>();
    let extra_in_backend = backend_profiles
        .difference(&active)
        .copied()
        .collect::<Vec<_>>();
    format!(
        "missing_from_journeys={missing_from_journeys:?} extra_in_journeys={extra_in_journeys:?} missing_from_backend={missing_from_backend:?} extra_in_backend={extra_in_backend:?}"
    )
}

fn verify_required_evidence_sets(
    sets: RequiredEvidenceContractSets,
) -> Result<VerifiedLocalTxContractSet> {
    let active = sets.active.into_iter().collect::<Vec<_>>();
    let journeys = sets.journeys.into_iter().collect::<Vec<_>>();
    let backend_profiles = sets.backend_profiles.into_iter().collect::<Vec<_>>();
    if active.is_empty() || active != journeys || active != backend_profiles {
        bail!(
            "LocalTx required evidence active/journey/backend sets are not exact: {}",
            localtx_exact_set_difference_summary(&active, &journeys, &backend_profiles)
        );
    }
    Ok(VerifiedLocalTxContractSet {
        active_contract_ids: active,
        journey_contract_ids: journeys,
        backend_profile_contract_ids: backend_profiles,
    })
}

fn verify_required_evidence_inventory(
    inventory: &LocalTxProofInventory,
    backend_execution: &crate::integration_shards::IntegrationUnitSpec,
) -> Result<VerifiedLocalTxContractSet> {
    let sets = required_evidence_contract_sets(inventory, backend_execution)?;
    verify_required_evidence_sets(sets)
}

fn release_check_integration_selection() -> Result<crate::integration_shards::IntegrationSelection>
{
    crate::integration_shards::IntegrationSelection::for_profile(
        crate::execution_profiles::ExecutionProfile::ReleaseCheck,
    )
}

pub(crate) fn verify_required_evidence_set(
    root: &Path,
    facts: &WorkspaceFacts,
) -> Result<VerifiedLocalTxContractSet> {
    let inventory = collect_workspace_inventory(root, facts)?;
    let findings = inventory.findings();
    if let Some(first) = findings.first() {
        bail!(
            "LocalTx required evidence inventory has {} finding(s); first={} {}: {}",
            findings.len(),
            first.rule.report_wire(),
            first.subject,
            first.detail
        );
    }
    let selection = release_check_integration_selection()?;
    let carrier = crate::integration_shards::localtx_backend_execution_unit(&selection)?;
    verify_required_evidence_inventory(&inventory, &carrier)
}

fn collect_inventory(
    root: &Path,
    facts: &WorkspaceFacts,
    local_tx_keys: &BTreeSet<String>,
) -> Result<LocalTxProofInventory> {
    collect_inventory_inner(root, facts, local_tx_keys).map_err(|error| sanitized(root, error))
}

#[cfg(test)]
pub(crate) fn collect_fixture_inventory(
    root: &Path,
    facts: &WorkspaceFacts,
) -> Result<LocalTxProofInventory> {
    collect_fixture_inventory_with_keys(root, facts, &fixture_compiled_local_tx_keys()?)
}

#[cfg(test)]
pub(crate) fn collect_fixture_inventory_with_keys(
    root: &Path,
    facts: &WorkspaceFacts,
    local_tx_keys: &BTreeSet<String>,
) -> Result<LocalTxProofInventory> {
    let governance = ContractGovernanceIr::load_test_fixture_root(&root.join("contracts"))
        .map_err(|error| sanitized(root, error))?;
    governance
        .read(|discovered| collect_inventory_from_contracts(root, discovered, facts, local_tx_keys))
        .map_err(|error| sanitized(root, error))
}

fn collect_inventory_inner(
    root: &Path,
    facts: &WorkspaceFacts,
    local_tx_keys: &BTreeSet<String>,
) -> Result<LocalTxProofInventory> {
    let governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    governance
        .read(|discovered| collect_inventory_from_contracts(root, discovered, facts, local_tx_keys))
}

fn collect_inventory_from_contracts(
    root: &Path,
    discovered: &[crate::contract::GovernedContract],
    facts: &WorkspaceFacts,
    local_tx_keys: &BTreeSet<String>,
) -> Result<LocalTxProofInventory> {
    reject_symlinks(root, &root.join("contracts"))?;
    let contracts = discover_from_contracts(root, discovered)?;
    if contracts.is_empty() {
        bail!("localtx-coverage: no active LocalTx HTTP contracts discovered");
    }
    let expected: BTreeMap<_, _> = contracts.iter().map(|c| (c.key.clone(), c)).collect();
    if expected.len() != contracts.len() {
        bail!("localtx-coverage: duplicate generated identity among active LocalTx contracts");
    }
    let journey_closure = load_journey_closure(root)?;
    validate_journey_contracts(&journey_closure, &contracts)?;

    let generated_root = root.join("generated/src/http");
    reject_symlinks(root, &generated_root)?;
    let workspace_crates = workspace_crates_from_facts(root, facts)?;
    validate_journey_cargo_targets(root, &workspace_crates, &journey_closure.runners)?;
    let cargo_targets = workspace_crates
        .iter()
        .flat_map(|member| {
            member
                .targets
                .iter()
                .map(move |target| backend_carrier_identity(root, member, target))
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_packages: BTreeMap<_, _> = workspace_crates
        .iter()
        .map(|member| (member.name.clone(), member.relative.clone()))
        .collect();
    let mut owner_evidence = BTreeMap::new();
    let mut all_markers = Vec::new();
    let mut all_backend_enrollments = Vec::new();
    let mut all_backend_profile_violations = Vec::new();
    let adapter_providers: BTreeSet<_> = workspace_crates
        .iter()
        .filter(|member| member.relative == Path::new("adapters").join(&member.name))
        .map(|member| member.name.clone())
        .collect();
    for member in &workspace_crates {
        let evidence = scan_owner(root, member, &expected_packages)?;
        all_markers.extend(evidence.markers.iter().cloned());
        all_backend_enrollments.extend(evidence.backend_enrollments.iter().cloned());
        all_backend_profile_violations.extend(evidence.backend_profile_violations.iter().cloned());
        if member.relative == Path::new("crates").join(&member.name) {
            owner_evidence.insert(member.name.clone(), evidence);
        }
    }
    all_markers.sort_by(|a, b| {
        (&a.key, &a.owner, &a.path, a.ordinal).cmp(&(&b.key, &b.owner, &b.path, b.ordinal))
    });
    all_markers.dedup();
    let unexpected_test_markers = all_markers
        .iter()
        .filter(|occurrence| !expected.contains_key(&occurrence.key))
        .cloned()
        .collect();
    let unexpected_backend_profiles = all_backend_enrollments
        .iter()
        .filter(|occurrence| !expected.contains_key(&occurrence.key))
        .cloned()
        .collect();
    let unexpected_generated = local_tx_keys
        .iter()
        .filter(|key| !expected.contains_key(*key))
        .cloned()
        .collect();
    let proof_contracts = build_proof_contracts(
        &contracts,
        LocalTxProofInputs {
            local_tx_keys,
            owner_evidence: &owner_evidence,
            markers: &all_markers,
            backend_enrollments: &all_backend_enrollments,
            adapter_providers: &adapter_providers,
            journey_closure: &journey_closure,
        },
    )?;
    Ok(LocalTxProofInventory::new(
        format!(
            "{} active LocalTx HTTP contract(s) covered",
            contracts.len()
        ),
        proof_contracts,
        all_backend_profile_violations,
        unexpected_test_markers,
        unexpected_backend_profiles,
        unexpected_generated,
        cargo_targets,
    ))
}

fn sort_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        (a.rule.report_wire(), &a.subject, &a.detail).cmp(&(
            b.rule.report_wire(),
            &b.subject,
            &b.detail,
        ))
    });
    findings.dedup();
}

fn evaluate_inventory(inventory: &LocalTxProofInventory) -> Vec<Finding> {
    let mut findings = inventory
        .backend_profile_violations
        .iter()
        .map(|violation| {
            finding(
                violation.rule,
                violation.path.clone(),
                format!(
                    "test function `{}` in provider `{}`: {}",
                    violation.function, violation.provider, violation.detail
                ),
            )
        })
        .collect::<Vec<_>>();
    for contract in &inventory.contracts {
        if !contract.valid_owner {
            findings.push(proof_contract_finding(
                Rule::InvalidDomainOwner,
                contract,
                "owner must be a safe Domain owner equal to domain",
            ));
            continue;
        }
        if !contract.generated.complete() {
            findings.push(proof_contract_finding(
                Rule::MissingGeneratedSpec,
                contract,
                "missing from generated::http::LOCAL_TX_SPECS",
            ));
        }
        if !contract.owner_present {
            findings.push(proof_contract_finding(
                Rule::MissingOwnerCrate,
                contract,
                "owner is not a WorkspaceFacts crates/* workspace member",
            ));
            continue;
        }
        let route_missing = !contract.route.complete;
        if route_missing {
            findings.push(proof_contract_finding(
                Rule::MissingRouteBinding,
                contract,
                "production GeneratedEndpoint binding with matching ContractMarker<RouteMarker> is missing",
            ));
        }
        let marker_invalid = !contract.test.complete;
        if route_missing || marker_invalid {
            findings.extend(contract.opaque_triggers.iter().map(|trigger| {
                finding(
                    Rule::OpaqueSourceScope,
                    trigger.subject.clone(),
                    format!(
                        "unsupported attribute `{}` makes LocalTx evidence in this lexical scope opaque",
                        trigger.attribute
                    ),
                )
            }));
        }
        match contract.test_markers.as_slice() {
            [] => findings.push(proof_contract_finding(
                Rule::MissingTestMarker,
                contract,
                "typed marker is missing from a real test function",
            )),
            [only] if only.owner == contract.owner => {}
            [only] => findings.push(finding(
                Rule::UnexpectedTestMarker,
                only.path.clone(),
                format!(
                    "typed marker `{}` is in owner `{}`; expected `{}`",
                    contract.key, only.owner, contract.owner
                ),
            )),
            many => findings.push(finding(
                Rule::DuplicateTestMarker,
                many.iter()
                    .find(|occurrence| occurrence.owner != contract.owner)
                    .unwrap_or(&many[0])
                    .path
                    .clone(),
                format!(
                    "typed marker `{}` occurs {} times at {}; expected exactly one in owner `{}`",
                    contract.key,
                    many.len(),
                    many.iter()
                        .map(|occurrence| occurrence.path.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    contract.owner
                ),
            )),
        }
        if contract.backend_profiles.is_empty() {
            findings.push(proof_contract_finding(
                Rule::MissingBackendProfile,
                contract,
                "no typed real-backend profile enrollment",
            ));
        }
        for profile in &contract.backend_profiles {
            if !profile.valid_provider {
                findings.push(finding(
                    Rule::UnexpectedBackendProfile,
                    profile
                        .sources
                        .first()
                        .cloned()
                        .unwrap_or_else(|| contract.subject.clone()),
                    format!(
                        "backend profile `{}` must be enrolled by an adapters/* provider, got `{}`",
                        contract.key, profile.provider
                    ),
                ));
                continue;
            }
            for (probe, minimum, actual) in &profile.missing_probes {
                findings.push(finding(
                    Rule::MissingBackendProbe,
                    profile.sources.first().cloned().unwrap_or_else(|| contract.subject.clone()),
                    format!(
                        "contract `{}` provider `{}` fixture `{}` txModel `{}` requires probe `{}` at least {minimum} time(s), found {actual}",
                        contract.contract_id,
                        profile.provider,
                        profile.fixture,
                        localtx_model_label(contract.tx_model),
                        probe.label(),
                    ),
                ));
            }
        }
    }
    findings.extend(inventory.unexpected_test_markers.iter().map(|occurrence| {
        finding(
            Rule::UnexpectedTestMarker,
            occurrence.path.clone(),
            format!(
                "typed marker `{}` in owner `{}` has no active LocalTx manifest",
                occurrence.key, occurrence.owner
            ),
        )
    }));
    findings.extend(
        inventory
            .unexpected_backend_profiles
            .iter()
            .map(|occurrence| {
                finding(
                    Rule::UnexpectedBackendProfile,
                    occurrence.path.clone(),
                    format!(
                        "backend profile `{}` in provider `{}` has no active LocalTx manifest",
                        occurrence.key, occurrence.provider
                    ),
                )
            }),
    );
    findings.extend(inventory.unexpected_generated.iter().map(|key| {
        finding(
            Rule::UnexpectedGeneratedSpec,
            "generated/src/http",
            format!("generated LocalTx evidence `{key}` has no active LocalTx manifest"),
        )
    }));
    sort_findings(&mut findings);
    findings
}

fn proof_contract_finding(
    rule: Rule,
    contract: &LocalTxProofContract,
    detail: impl Into<String>,
) -> Finding {
    finding(
        rule,
        contract.subject.clone(),
        format!("contract `{}`: {}", contract.contract_id, detail.into()),
    )
}

struct LocalTxProofInputs<'a> {
    local_tx_keys: &'a BTreeSet<String>,
    owner_evidence: &'a BTreeMap<String, OwnerEvidence>,
    markers: &'a [MarkerOccurrence],
    backend_enrollments: &'a [BackendEnrollmentOccurrence],
    adapter_providers: &'a BTreeSet<String>,
    journey_closure: &'a JourneyClosure,
}

fn build_proof_contracts(
    contracts: &[Contract],
    inputs: LocalTxProofInputs<'_>,
) -> Result<Vec<LocalTxProofContract>> {
    let mut proof_contracts = Vec::with_capacity(contracts.len());
    for contract in contracts {
        let evidence = inputs.owner_evidence.get(&contract.owner);
        let route_sources = evidence
            .and_then(|owner| owner.canonical_mounts.get(&contract.key))
            .into_iter()
            .flatten()
            .map(|mount| mount.source.clone())
            .collect();
        let marker_occurrences = inputs
            .markers
            .iter()
            .filter(|occurrence| occurrence.key == contract.key)
            .cloned()
            .collect::<Vec<_>>();
        let test_complete =
            matches!(marker_occurrences.as_slice(), [only] if only.owner == contract.owner);
        let test_sources = marker_occurrences
            .iter()
            .map(|occurrence| occurrence.path.clone())
            .collect();
        let generated_complete = inputs.local_tx_keys.contains(&contract.key);
        let generated_module = contract
            .key
            .split("::")
            .next()
            .ok_or_else(|| anyhow!("empty generated LocalTx identity"))?;
        let journey = inputs
            .journey_closure
            .entries
            .iter()
            .find(|entry| entry.contract_id == contract.id)
            .ok_or_else(|| anyhow!("missing validated LocalTx journey"))?;

        let backend_profiles = normalize_backend_profiles(
            contract,
            inputs.backend_enrollments,
            inputs.adapter_providers,
        );
        proof_contracts.push(LocalTxProofContract {
            contract_id: contract.id.clone(),
            owner: contract.owner.clone(),
            key: contract.key.clone(),
            subject: contract.subject.clone(),
            valid_owner: contract.valid_owner,
            owner_present: evidence.is_some(),
            test_markers: marker_occurrences,
            opaque_triggers: evidence
                .into_iter()
                .flat_map(|owner| owner.opaque_triggers.iter().cloned())
                .collect(),
            boundary: contract.boundary,
            tx_model: contract.tx_model,
            retry: contract.retry,
            commit_unknown: contract.commit_unknown,
            manifest: LocalTxProofEvidence::new(true, vec![contract.subject.clone()]),
            generated: LocalTxProofEvidence::new(
                generated_complete,
                vec![format!("generated/src/http/{generated_module}.rs")],
            ),
            route: LocalTxProofEvidence::new(
                evidence.is_some_and(|owner| owner.routes.contains(&contract.key)),
                route_sources,
            ),
            test: LocalTxProofEvidence::new(test_complete, test_sources),
            backend_profiles,
            journey: LocalTxProofJourney {
                spec: journey.spec.clone(),
                fixture: journey.fixture.clone(),
                runner: journey.runner.clone(),
                scenarios: journey
                    .scenarios
                    .iter()
                    .map(|scenario| LocalTxProofJourneyScenario {
                        kind: scenario.kind,
                        applicable: scenario.applicable,
                        reason: scenario.reason.clone(),
                    })
                    .collect(),
            },
        });
    }
    proof_contracts.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    Ok(proof_contracts)
}

fn normalize_backend_profiles(
    contract: &Contract,
    enrollments: &[BackendEnrollmentOccurrence],
    adapter_providers: &BTreeSet<String>,
) -> Vec<LocalTxProofBackendProfile> {
    let mut grouped = BTreeMap::<
        (String, String, Option<BackendCarrierIdentity>),
        Vec<&BackendEnrollmentOccurrence>,
    >::new();
    for enrollment in enrollments
        .iter()
        .filter(|enrollment| enrollment.key == contract.key)
    {
        grouped
            .entry((
                enrollment.provider.clone(),
                enrollment.provider_fixture.clone(),
                enrollment.carrier.clone(),
            ))
            .or_default()
            .push(enrollment);
    }
    let required = required_backend_probes(contract.tx_model);
    grouped
        .into_iter()
        .map(|((provider, fixture, carrier), enrollments)| {
            let mut observed = BTreeMap::<BackendProbe, usize>::new();
            let mut sources = Vec::new();
            for enrollment in enrollments {
                sources.push(enrollment.path.clone());
                for (probe, count) in &enrollment.probes {
                    *observed.entry(*probe).or_default() += count;
                }
            }
            sources.sort();
            sources.dedup();
            let missing_probes = required
                .iter()
                .filter_map(|(probe, minimum)| {
                    let actual = observed.get(probe).copied().unwrap_or_default();
                    (actual < *minimum).then_some((*probe, *minimum, actual))
                })
                .collect();
            LocalTxProofBackendProfile {
                valid_provider: adapter_providers.contains(&provider),
                provider,
                fixture,
                sources,
                required_probes: required.clone(),
                observed_probes: observed.into_iter().collect(),
                missing_probes,
                carrier,
            }
        })
        .collect()
}

fn load_journey_closure(root: &Path) -> Result<JourneyClosure> {
    let board_path = root.join(JOURNEY_BOARD_PATH);
    let board: JourneyBoard = parse_journey_toml(root, &board_path)?;
    if board.schema_version != 1 {
        bail!("{JOURNEY_BOARD_PATH}: schemaVersion must be 1");
    }
    if board.scope != "active-localtx" {
        bail!("{JOURNEY_BOARD_PATH}: scope must be `active-localtx`");
    }
    if board.journeys.is_empty() {
        bail!("{JOURNEY_BOARD_PATH}: journeys must not be empty");
    }

    let mut ids = BTreeSet::new();
    let mut contract_ids = BTreeSet::new();
    let mut specs = BTreeSet::new();
    let mut fixtures = BTreeSet::new();
    let mut markers = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    let mut runner_expectations = BTreeMap::<String, JourneyRunnerExpectation>::new();
    let mut entries = Vec::new();
    for entry in board.journeys {
        validate_board_entry(&entry)?;
        require_unique(&mut ids, &entry.id, "journey id")?;
        require_unique(&mut contract_ids, &entry.contract_id, "journey contractId")?;
        require_unique(&mut specs, &entry.spec, "journey spec path")?;
        require_unique(&mut fixtures, &entry.fixture, "journey fixture path")?;
        require_unique(&mut markers, &entry.marker, "journey marker")?;

        let spec_path = scoped_artifact(root, &entry.spec, "journeys", "-localtx-journey.toml")?;
        let fixture_path = scoped_artifact(root, &entry.fixture, "fixtures", "-localtx.toml")?;
        scoped_artifact(root, &entry.runner, "journeys/tests", "_journey.rs")?;
        let spec: JourneySpec = parse_journey_toml(root, &spec_path)?;
        let fixture: JourneyFixture = parse_journey_toml(root, &fixture_path)?;
        validate_spec(&entry, &spec)?;
        validate_fixture(&entry, &fixture, &mut case_ids)?;
        validate_scenario_matrix(entry.tx_model, &spec.scenarios, &fixture.cases, &entry.id)?;
        let expected = runner_expectations.entry(entry.runner.clone()).or_default();
        expected.markers.insert(entry.marker.clone());
        expected
            .cases
            .extend(fixture.cases.iter().map(|case| case.id.clone()));

        entries.push(JourneyClosureEntry {
            contract_id: entry.contract_id,
            tx_model: entry.tx_model,
            spec: entry.spec,
            fixture: entry.fixture,
            runner: entry.runner,
            marker: entry.marker,
            marker_key: String::new(),
            case_ids: fixture.cases.iter().map(|case| case.id.clone()).collect(),
            scenarios: spec
                .scenarios
                .into_iter()
                .map(|scenario| LocalTxProofJourneyScenario {
                    kind: scenario.kind,
                    applicable: scenario.applicable,
                    reason: scenario.reason,
                })
                .collect(),
        });
    }
    for (runner_path, expected) in &runner_expectations {
        let runner = scan_journey_runner(root, &root.join(runner_path))?;
        let actual_markers: BTreeSet<_> = runner.markers.keys().cloned().collect();
        if actual_markers != expected.markers {
            bail!(
                "{runner_path}: LOCALTX_JOURNEY markers differ from its status-board entries; expected {:?}, found {actual_markers:?}",
                expected.markers
            );
        }
        if runner.case_ids != expected.cases {
            bail!(
                "{runner_path}: literal `take_case` calls differ from its fixture cases; expected {:?}, found {:?}",
                expected.cases,
                runner.case_ids
            );
        }
        if let Some(error) = runner.observation_error {
            bail!("{runner_path}: {error}");
        }
        for entry in entries
            .iter_mut()
            .filter(|entry| entry.runner == *runner_path)
        {
            entry.marker_key = runner
                .markers
                .get(&entry.marker)
                .cloned()
                .ok_or_else(|| anyhow!("journey marker accounting failed"))?;
            let marker_test = runner
                .marker_tests
                .get(&entry.marker)
                .ok_or_else(|| anyhow!("journey marker test accounting failed"))?;
            for case_id in &entry.case_ids {
                if runner.case_tests.get(case_id) != Some(marker_test) {
                    bail!(
                        "{runner_path}: fixture case `{case_id}` must be consumed in the same real test as `LOCALTX_JOURNEY_{}`",
                        entry.marker
                    );
                }
            }
        }
    }
    entries.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    Ok(JourneyClosure {
        entries,
        runners: runner_expectations.into_keys().collect(),
    })
}

fn validate_journey_contracts(closure: &JourneyClosure, contracts: &[Contract]) -> Result<()> {
    let contracts_by_id: BTreeMap<_, _> = contracts
        .iter()
        .map(|contract| (contract.id.as_str(), contract))
        .collect();
    let expected: BTreeSet<_> = contracts_by_id.keys().copied().collect();
    let actual: BTreeSet<_> = closure
        .entries
        .iter()
        .map(|entry| entry.contract_id.as_str())
        .collect();
    if actual != expected {
        bail!(
            "{JOURNEY_BOARD_PATH}: active-localtx must contain exactly the discovered active LocalTx contracts; expected {expected:?}, found {actual:?}"
        );
    }
    for entry in &closure.entries {
        let contract = contracts_by_id
            .get(entry.contract_id.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "{JOURNEY_BOARD_PATH}: contractId `{}` is not an active LocalTx HTTP contract",
                    entry.contract_id
                )
            })?;
        if entry.tx_model != contract.tx_model {
            bail!(
                "{JOURNEY_BOARD_PATH}: contract `{}` txModel drifts from its manifest",
                entry.contract_id
            );
        }
        if entry.marker_key != contract.key {
            bail!(
                "{}: marker `LOCALTX_JOURNEY_{}` binds `{}`; expected `{}` for contract `{}`",
                entry.runner,
                entry.marker,
                entry.marker_key,
                contract.key,
                entry.contract_id
            );
        }
    }

    Ok(())
}

fn validate_journey_cargo_targets(
    root: &Path,
    workspace_crates: &[WorkspaceCrate],
    runners: &BTreeSet<String>,
) -> Result<()> {
    let member = workspace_crates
        .iter()
        .find(|member| member.relative == Path::new("journeys"))
        .ok_or_else(|| anyhow!("journeys must be a workspace package"))?;
    for runner in runners {
        let expected = std::fs::canonicalize(root.join(runner))
            .with_context(|| format!("canonicalize LocalTx journey runner `{runner}`"))?;
        let matching: Vec<_> = member
            .targets
            .iter()
            .filter_map(|target| {
                std::fs::canonicalize(&target.path)
                    .ok()
                    .filter(|path| path == &expected)
                    .map(|_| target)
            })
            .collect();
        let [target] = matching.as_slice() else {
            bail!("{runner}: must be registered as exactly one Cargo target");
        };
        if target.kind != CargoTargetKind::Test
            || target.required_features != BTreeSet::from(["integration".to_string()])
        {
            bail!(
                "{runner}: Cargo target must be an integration test with required-features = [\"integration\"]"
            );
        }
    }
    let selection = release_check_integration_selection()?;
    let batch =
        crate::integration_shards::postgres_transaction_journey_execution_batch(&selection)?;
    if !crate::nextest::integration_batch_fails_on_empty(&batch) {
        bail!("LocalTx journey runners: postgres-domain Serial execution must use --no-tests=fail");
    }
    Ok(())
}

fn validate_board_entry(entry: &JourneyBoardEntry) -> Result<()> {
    validate_slug(&entry.id, "journey id")?;
    validate_contract_id(&entry.contract_id)?;
    if entry.runner.trim().is_empty() {
        bail!("journey runner must not be empty");
    }
    validate_marker_suffix(&entry.marker)?;
    Ok(())
}

fn validate_spec(entry: &JourneyBoardEntry, spec: &JourneySpec) -> Result<()> {
    if spec.schema_version != 1 {
        bail!("{}: schemaVersion must be 1", entry.spec);
    }
    require_journey_metadata(&entry.spec, "id", &entry.id, &spec.id)?;
    require_journey_metadata(
        &entry.spec,
        "contractId",
        &entry.contract_id,
        &spec.contract_id,
    )?;
    require_journey_metadata(
        &entry.spec,
        "txModel",
        localtx_model_label(entry.tx_model),
        localtx_model_label(spec.tx_model),
    )?;
    require_journey_metadata(&entry.spec, "fixture", &entry.fixture, &spec.fixture)?;
    require_journey_metadata(&entry.spec, "runner", &entry.runner, &spec.runner)?;
    require_journey_metadata(&entry.spec, "marker", &entry.marker, &spec.marker)?;
    Ok(())
}

fn validate_fixture(
    entry: &JourneyBoardEntry,
    fixture: &JourneyFixture,
    global_case_ids: &mut BTreeSet<String>,
) -> Result<()> {
    if fixture.schema_version != 1 {
        bail!("{}: schemaVersion must be 1", entry.fixture);
    }
    require_journey_metadata(&entry.fixture, "id", &entry.id, &fixture.id)?;
    require_journey_metadata(
        &entry.fixture,
        "contractId",
        &entry.contract_id,
        &fixture.contract_id,
    )?;
    require_journey_metadata(
        &entry.fixture,
        "txModel",
        localtx_model_label(entry.tx_model),
        localtx_model_label(fixture.tx_model),
    )?;
    require_journey_metadata(&entry.fixture, "spec", &entry.spec, &fixture.spec)?;
    require_journey_metadata(&entry.fixture, "runner", &entry.runner, &fixture.runner)?;
    require_journey_metadata(&entry.fixture, "marker", &entry.marker, &fixture.marker)?;
    if fixture.cases.is_empty() {
        bail!("{}: cases must not be empty", entry.fixture);
    }
    for case in &fixture.cases {
        validate_slug(&case.id, "journey case id")?;
        require_unique(global_case_ids, &case.id, "journey case id")?;
        if !(100..=599).contains(&case.http_status) {
            bail!(
                "{}: case `{}` has invalid httpStatus",
                entry.fixture,
                case.id
            );
        }
        if case.error_code.trim().is_empty() {
            bail!(
                "{}: case `{}` has an empty errorCode",
                entry.fixture,
                case.id
            );
        }
        if case.scenario != JourneyScenarioKind::CommitUnknown && case.commits.is_none() {
            bail!(
                "{}: case `{}` may omit commits only for the commit-unknown scenario",
                entry.fixture,
                case.id
            );
        }
        if case.commits.is_some_and(|commits| commits > case.attempts) {
            bail!(
                "{}: case `{}` commits exceed attempts",
                entry.fixture,
                case.id
            );
        }
        if case.redact_sentinels.is_empty()
            || case
                .redact_sentinels
                .iter()
                .any(|sentinel| sentinel.trim().is_empty())
        {
            bail!(
                "{}: case `{}` must declare non-empty redactSentinels",
                entry.fixture,
                case.id
            );
        }
        let _ = case.retryable;
    }
    Ok(())
}

fn require_journey_metadata(
    artifact: &str,
    field: &str,
    expected: &str,
    actual: &str,
) -> Result<()> {
    if actual != expected {
        bail!(
            "{artifact}: field `{field}` drifts from {JOURNEY_BOARD_PATH}; expected `{expected}`, actual `{actual}`"
        );
    }
    Ok(())
}

fn validate_scenario_matrix(
    tx_model: LocalTxModel,
    scenarios: &[JourneyScenario],
    cases: &[JourneyCase],
    journey_id: &str,
) -> Result<()> {
    let required: BTreeSet<_> = match tx_model {
        LocalTxModel::RepoAtomicCas => [
            JourneyScenarioKind::Happy,
            JourneyScenarioKind::AuthFailure,
            JourneyScenarioKind::ValidationFailure,
            JourneyScenarioKind::Conflict,
        ]
        .into_iter()
        .collect(),
        LocalTxModel::TenantScopedUow => [
            JourneyScenarioKind::Happy,
            JourneyScenarioKind::AuthFailure,
            JourneyScenarioKind::ValidationFailure,
            JourneyScenarioKind::Conflict,
            JourneyScenarioKind::Contention,
        ]
        .into_iter()
        .collect(),
    };
    let mut allowed = required.clone();
    allowed.insert(JourneyScenarioKind::CommitUnknown);
    let mut declared = BTreeMap::new();
    for scenario in scenarios {
        if declared.insert(scenario.kind, scenario).is_some() {
            bail!(
                "journey `{journey_id}` has duplicate `{}` scenario",
                scenario.kind.label()
            );
        }
        if scenario.applicable && scenario.reason.is_some() {
            bail!(
                "journey `{journey_id}` applicable `{}` scenario must not have a reason",
                scenario.kind.label()
            );
        }
        if !scenario.applicable
            && scenario
                .reason
                .as_deref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            bail!(
                "journey `{journey_id}` non-applicable `{}` scenario needs a reason",
                scenario.kind.label()
            );
        }
    }
    let actual: BTreeSet<_> = declared.keys().copied().collect();
    if !required.is_subset(&actual) || !actual.is_subset(&allowed) {
        bail!(
            "journey `{journey_id}` scenario closure differs for txModel; required {required:?}, allowed {allowed:?}, found {actual:?}"
        );
    }
    if tx_model == LocalTxModel::RepoAtomicCas
        && declared.values().any(|scenario| !scenario.applicable)
    {
        bail!("journey `{journey_id}` repo-atomic-cas scenarios must all be applicable");
    }
    if tx_model == LocalTxModel::TenantScopedUow {
        for required in [
            JourneyScenarioKind::Happy,
            JourneyScenarioKind::AuthFailure,
            JourneyScenarioKind::ValidationFailure,
            JourneyScenarioKind::Contention,
        ] {
            if !declared
                .get(&required)
                .is_some_and(|scenario| scenario.applicable)
            {
                bail!(
                    "journey `{journey_id}` `{}` scenario must be applicable",
                    required.label()
                );
            }
        }
        if declared
            .get(&JourneyScenarioKind::Conflict)
            .is_none_or(|scenario| scenario.applicable)
        {
            bail!(
                "journey `{journey_id}` tenant-scoped-uow conflict must be applicable=false with a reason"
            );
        }
    }
    if declared
        .get(&JourneyScenarioKind::CommitUnknown)
        .is_some_and(|scenario| !scenario.applicable)
    {
        bail!("journey `{journey_id}` declared commit-unknown scenario must be applicable");
    }

    let covered: BTreeSet<_> = cases.iter().map(|case| case.scenario).collect();
    let applicable: BTreeSet<_> = declared
        .values()
        .filter_map(|scenario| scenario.applicable.then_some(scenario.kind))
        .collect();
    if covered != applicable {
        bail!(
            "journey `{journey_id}` fixture cases must cover exactly applicable scenarios; expected {applicable:?}, found {covered:?}"
        );
    }
    Ok(())
}

fn parse_journey_toml<T: DeserializeOwned>(root: &Path, path: &Path) -> Result<T> {
    ensure_contained(root, root, path)?;
    reject_symlinks(root, path)?;
    let subject = relative(root, path)?;
    let source = std::fs::read_to_string(path).with_context(|| format!("read `{subject}`"))?;
    toml::from_str(&source).with_context(|| format!("parse closed v1 TOML `{subject}`"))
}

fn scoped_artifact(root: &Path, value: &str, parent: &str, suffix: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    if relative.is_absolute()
        || relative.parent() != Some(Path::new(parent))
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.ends_with(suffix))
    {
        bail!("journey artifact path `{value}` must be a direct `{parent}/*{suffix}` path");
    }
    let path = root.join(relative);
    ensure_contained(root, root, &path)?;
    reject_symlinks(root, &path)?;
    Ok(path)
}

fn require_unique(set: &mut BTreeSet<String>, value: &str, label: &str) -> Result<()> {
    if !set.insert(value.to_string()) {
        bail!("duplicate {label} `{value}`");
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("{label} `{value}` must be a lowercase kebab-case slug");
    }
    Ok(())
}

fn validate_contract_id(value: &str) -> Result<()> {
    let segments: Vec<_> = value.split('.').collect();
    if segments.len() < 2 {
        bail!("contractId `{value}` must be dotted");
    }
    for segment in segments {
        validate_slug(segment, "contractId segment")?;
    }
    Ok(())
}

fn validate_marker_suffix(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('_')
        || value.ends_with('_')
        || value.contains("__")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("journey marker `{value}` must be an uppercase snake-case suffix");
    }
    Ok(())
}

fn scan_journey_runner(root: &Path, path: &Path) -> Result<JourneyRunnerEvidence> {
    reject_symlinks(root, path)?;
    let syntax = parse_file(root, path)?;
    struct Collector {
        markers: Vec<(String, Option<String>, Option<usize>, bool)>,
        case_calls: Vec<JourneyCaseCallEvidence>,
        case_groups: Vec<(String, BTreeSet<String>, Option<usize>)>,
        observed_groups: Vec<(String, Option<usize>)>,
        test_rejections: BTreeMap<usize, Option<String>>,
        current_test: Option<usize>,
        current_case_binding: Option<String>,
        ancestor_rejection: Option<String>,
        next_test: usize,
        canonical_top_level: bool,
        observation_enabled: bool,
    }
    impl Collector {}
    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, item: &'ast ItemFn) {
            let previous_test = self.current_test;
            let previous_canonical = self.canonical_top_level;
            if is_journey_test(item) {
                let test = self.next_test;
                self.next_test += 1;
                self.current_test = Some(test);
                self.test_rejections.insert(
                    test,
                    forbidden_journey_attribute(&item.attrs)
                        .or_else(|| self.ancestor_rejection.clone()),
                );
                for statement in &item.block.stmts {
                    match statement {
                        Stmt::Item(Item::Const(marker))
                            if marker.ident.to_string().starts_with("LOCALTX_JOURNEY_") =>
                        {
                            self.canonical_top_level = true;
                            self.visit_item_const(marker);
                        }
                        _ => {
                            if let Some((binding, call)) = canonical_journey_case_call(statement) {
                                self.canonical_top_level = true;
                                let previous_binding = self.current_case_binding.replace(binding);
                                self.visit_expr_method_call(call);
                                self.current_case_binding = previous_binding;
                            } else {
                                if let Some((group, cases)) =
                                    canonical_journey_case_group(statement)
                                {
                                    self.case_groups.push((group, cases, self.current_test));
                                }
                                self.canonical_top_level = false;
                                visit::visit_stmt(self, statement);
                            }
                        }
                    }
                }
            } else {
                self.current_test = None;
                self.canonical_top_level = false;
                visit::visit_item_fn(self, item);
            }
            self.current_test = previous_test;
            self.canonical_top_level = previous_canonical;
        }

        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let previous = self.ancestor_rejection.clone();
            if self.ancestor_rejection.is_none()
                && let Some(reason) = forbidden_journey_attribute(&item.attrs)
            {
                self.ancestor_rejection = Some(format!("ancestor {reason}"));
            }
            visit::visit_item_mod(self, item);
            self.ancestor_rejection = previous;
        }

        fn visit_item_const(&mut self, item: &'ast ItemConst) {
            let name = item.ident.to_string();
            if let Some(suffix) = name.strip_prefix("LOCALTX_JOURNEY_") {
                self.markers.push((
                    suffix.to_string(),
                    strict_journey_marker_key(item),
                    self.current_test,
                    self.canonical_top_level,
                ));
            }
            visit::visit_item_const(self, item);
        }

        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if call.method == "take_case" {
                let case_id = match call.args.first() {
                    Some(Expr::Lit(literal)) if call.args.len() == 1 => match &literal.lit {
                        syn::Lit::Str(value) => self
                            .current_case_binding
                            .clone()
                            .map(|binding| (value.value(), binding))
                            .ok_or_else(|| {
                                format!(
                                    "journey runner: canonical `take_case` binding accounting failed for `{}`",
                                    value.value()
                                )
                            }),
                        _ => Err(
                            "journey runner: `take_case` requires a single string literal"
                                .to_string(),
                        ),
                    },
                    _ => Err(
                        "journey runner: `take_case` requires a single string literal"
                            .to_string(),
                    ),
                };
                self.case_calls.push(JourneyCaseCallEvidence {
                    parsed: case_id,
                    test: self.current_test,
                });
            }

            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_call(&mut self, call: &'ast ExprCall) {
            if self.observation_enabled
                && is_journey_observer_call(call)
                && self.current_test.is_some()
            {
                for argument in &call.args {
                    if let Some(binding) = single_identifier(argument) {
                        self.observed_groups.push((binding, self.current_test));
                    }
                }
            }
            visit::visit_expr_call(self, call);
        }

        fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
            let previous = self.observation_enabled;
            self.observation_enabled = false;
            visit::visit_expr_closure(self, expression);
            self.observation_enabled = previous;
        }

        fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
            let previous = self.observation_enabled;
            self.observation_enabled = false;
            visit::visit_expr_async(self, expression);
            self.observation_enabled = previous;
        }

        fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
            if let Expr::Async(block) = expression.base.as_ref() {
                for statement in &block.block.stmts {
                    self.visit_stmt(statement);
                }
            } else {
                self.visit_expr(expression.base.as_ref());
            }
        }
    }
    let mut collector = Collector {
        markers: Vec::new(),
        case_calls: Vec::new(),
        case_groups: Vec::new(),
        observed_groups: Vec::new(),
        test_rejections: BTreeMap::new(),
        current_test: None,
        current_case_binding: None,
        ancestor_rejection: None,
        next_test: 0,
        canonical_top_level: false,
        observation_enabled: true,
    };
    collector.visit_file(&syntax);
    let mut markers = BTreeMap::new();
    let mut keys = BTreeSet::new();
    let mut marker_tests = BTreeSet::new();
    let mut marker_test_by_suffix = BTreeMap::new();
    for (suffix, key, test, canonical_top_level) in collector.markers {
        validate_marker_suffix(&suffix)?;
        let test = test.ok_or_else(|| {
            anyhow!(
                "journey runner: `LOCALTX_JOURNEY_{suffix}` must be inside a real #[test] or #[tokio::test] function"
            )
        })?;
        if !canonical_top_level {
            bail!(
                "journey runner: `LOCALTX_JOURNEY_{suffix}` must be a test-body top-level const item"
            );
        }
        if let Some(reason) = collector
            .test_rejections
            .get(&test)
            .and_then(|reason| reason.as_deref())
        {
            bail!(
                "journey runner: `LOCALTX_JOURNEY_{suffix}` is inside a non-canonical journey test: {reason}"
            );
        }
        marker_tests.insert(test);
        marker_test_by_suffix.insert(suffix.clone(), test);
        let key = key.ok_or_else(|| {
            anyhow!(
                "journey runner: `LOCALTX_JOURNEY_{suffix}` must be an absolute typed HttpRouteBinding<RouteMarker, LocalTx> = generated::ROUTE marker"
            )
        })?;
        if markers.insert(suffix.clone(), key.clone()).is_some() {
            bail!("journey runner: duplicate marker `LOCALTX_JOURNEY_{suffix}`");
        }
        if !keys.insert(key.clone()) {
            bail!("journey runner: generated route `{key}` has duplicate journey markers");
        }
    }
    let mut case_ids = BTreeSet::new();
    let mut case_tests = BTreeMap::new();
    let mut case_bindings = BTreeMap::<usize, BTreeMap<String, String>>::new();
    for evidence in collector.case_calls {
        let JourneyCaseCallEvidence { parsed, test } = evidence;
        let (case_id, binding) = parsed.map_err(anyhow::Error::msg)?;
        let test = test.ok_or_else(|| {
            anyhow!(
                "journey runner: `take_case` for `{case_id}` must be inside a real journey test"
            )
        })?;
        if !marker_tests.contains(&test) {
            bail!(
                "journey runner: `take_case` for `{case_id}` is inside a test without a LOCALTX_JOURNEY marker"
            );
        }
        if !case_ids.insert(case_id.clone()) {
            bail!("journey runner: duplicate `take_case` for `{case_id}`");
        }
        case_tests.insert(case_id.clone(), test);
        if case_bindings
            .entry(test)
            .or_default()
            .insert(binding.clone(), case_id)
            .is_some()
        {
            bail!("journey runner: duplicate journey case binding `{binding}`");
        }
    }

    let mut observation_error = None;
    for marker_test in marker_tests {
        let empty = BTreeMap::new();
        if let Err(error) = validate_journey_observation_closure(
            case_bindings.get(&marker_test).unwrap_or(&empty),
            &collector.case_groups,
            &collector.observed_groups,
            marker_test,
        ) {
            observation_error = Some(format!("{error:#}"));
            break;
        }
    }
    Ok(JourneyRunnerEvidence {
        markers,
        marker_tests: marker_test_by_suffix,
        case_ids,
        case_tests,
        observation_error,
    })
}

fn validate_journey_observation_closure(
    case_bindings: &BTreeMap<String, String>,
    case_groups: &[(String, BTreeSet<String>, Option<usize>)],
    observed_groups: &[(String, Option<usize>)],
    marker_test: usize,
) -> Result<()> {
    let expected_bindings: BTreeSet<_> = case_bindings.keys().cloned().collect();
    let mut grouped_bindings = BTreeSet::new();
    let mut observation_groups = BTreeSet::new();
    for (group, bindings, test) in case_groups {
        if *test != Some(marker_test) {
            continue;
        }
        let relevant: BTreeSet<_> = bindings.intersection(&expected_bindings).cloned().collect();
        if relevant.is_empty() {
            continue;
        }
        if relevant != *bindings {
            bail!(
                "journey runner: journey observation group `{group}` mixes case and non-case bindings"
            );
        }
        for binding in relevant {
            if !grouped_bindings.insert(binding.clone()) {
                bail!(
                    "journey runner: journey case binding `{binding}` enters multiple observation groups"
                );
            }
        }
        observation_groups.insert(group.clone());
    }
    if grouped_bindings != expected_bindings {
        let missing: BTreeSet<_> = expected_bindings
            .difference(&grouped_bindings)
            .cloned()
            .collect();
        bail!(
            "journey runner: journey case bindings missing from an observation closure: {missing:?}"
        );
    }

    let mut observed_counts = BTreeMap::<String, usize>::new();
    for (binding, test) in observed_groups {
        if *test == Some(marker_test) && observation_groups.contains(binding) {
            *observed_counts.entry(binding.clone()).or_default() += 1;
        }
    }
    for group in observation_groups {
        let count = observed_counts.get(&group).copied().unwrap_or_default();
        if count != 1 {
            bail!(
                "journey runner: journey observation closure group `{group}` must enter exactly one executed `drive_*`/`observe_*` consumer; found {count}"
            );
        }
    }
    Ok(())
}

fn is_journey_test(item: &ItemFn) -> bool {
    item.attrs.iter().any(|attribute| {
        let path = raw_segments(attribute.path());
        match path.as_slice() {
            [name] if name == "test" => matches!(attribute.meta, Meta::Path(_)),
            [root, name] if root == "tokio" && name == "test" => item.sig.asyncness.is_some(),
            _ => false,
        }
    })
}

fn forbidden_journey_attribute(attributes: &[Attribute]) -> Option<String> {
    attributes.iter().find_map(|attribute| {
        let segments = raw_segments(attribute.path());
        matches!(segments.as_slice(), [name] if matches!(name.as_str(), "ignore" | "cfg" | "cfg_attr" | "should_panic"))
            .then(|| format!("#[{}] is forbidden", segments[0]))
    })
}

fn canonical_journey_case_call(statement: &Stmt) -> Option<(String, &ExprMethodCall)> {
    let Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return None;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
    {
        return None;
    }
    let initializer = local.init.as_ref()?;
    if initializer.diverge.is_some() {
        return None;
    }
    let Expr::Try(attempt) = initializer.expr.as_ref() else {
        return None;
    };
    if !attempt.attrs.is_empty() {
        return None;
    }
    let Expr::MethodCall(call) = attempt.expr.as_ref() else {
        return None;
    };
    let Expr::Path(receiver) = call.receiver.as_ref() else {
        return None;
    };
    let receiver_is_identifier = receiver.attrs.is_empty()
        && receiver.qself.is_none()
        && receiver.path.leading_colon.is_none()
        && receiver.path.segments.len() == 1
        && matches!(receiver.path.segments[0].arguments, PathArguments::None);
    (call.attrs.is_empty()
        && call.method == "take_case"
        && call.turbofish.is_none()
        && receiver_is_identifier)
        .then(|| (binding.ident.to_string(), call))
}

fn canonical_journey_case_group(statement: &Stmt) -> Option<(String, BTreeSet<String>)> {
    let Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return None;
    };
    if !local.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.subpat.is_some()
        || local.init.as_ref()?.diverge.is_some()
    {
        return None;
    }
    let Expr::Struct(group) = local.init.as_ref()?.expr.as_ref() else {
        return None;
    };
    if !group.attrs.is_empty()
        || group.rest.is_some()
        || !group
            .path
            .segments
            .last()?
            .ident
            .to_string()
            .ends_with("Cases")
        || group.fields.is_empty()
    {
        return None;
    }
    let mut cases = BTreeSet::new();
    for field in &group.fields {
        if !field.attrs.is_empty() || !matches!(field.member, syn::Member::Named(_)) {
            return None;
        }
        let case = single_identifier(&field.expr)?;
        if !cases.insert(case) {
            return None;
        }
    }
    Some((binding.ident.to_string(), cases))
}

fn is_journey_observer_call(call: &ExprCall) -> bool {
    let Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    function.path.segments.last().is_some_and(|segment| {
        let name = segment.ident.to_string();
        name.starts_with("drive_") || name.starts_with("observe_")
    })
}

fn single_identifier(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = expression else {
        return None;
    };
    (path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && matches!(path.path.segments[0].arguments, PathArguments::None))
    .then(|| path.path.segments[0].ident.to_string())
}

fn strict_journey_marker_key(item: &ItemConst) -> Option<String> {
    let Type::Path(binding) = item.ty.as_ref() else {
        return None;
    };
    if binding.qself.is_some()
        || binding.path.leading_colon.is_none()
        || raw_segments(&binding.path).as_slice() != ["vocab", "HttpRouteBinding"]
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &binding.path.segments.last()?.arguments else {
        return None;
    };
    if arguments.args.len() != 2 {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    if marker.qself.is_some() || marker.path.leading_colon.is_none() {
        return None;
    }
    let marker_segments = raw_segments(&marker.path);
    let GenericArgument::Type(Type::Path(consistency)) = arguments.args.iter().nth(1)? else {
        return None;
    };
    if consistency.qself.is_some()
        || consistency.path.leading_colon.is_none()
        || raw_segments(&consistency.path).as_slice() != ["vocab", "http", "LocalTx"]
    {
        return None;
    }
    let key = key_from_segments(&marker_segments, "RouteMarker")?;
    let Expr::Path(route) = item.expr.as_ref() else {
        return None;
    };
    if route.qself.is_some() || route.path.leading_colon.is_none() {
        return None;
    }
    (key_from_segments(&raw_segments(&route.path), "ROUTE").as_deref() == Some(&key)).then_some(key)
}

fn required_backend_probes(model: LocalTxModel) -> Vec<(BackendProbe, usize)> {
    // HTTP validation/authorization are route preconditions and close in the durable journey;
    // retry ownership closes in pg-tenant-tx-guard. If a backend profile nevertheless enrolls
    // either helper, backend_enrollments_in_test still requires every action to use the provider.
    let mut required = vec![
        (BackendProbe::Commit, 1),
        (BackendProbe::TenantIsolation, 1),
        (BackendProbe::CommitUnknownNoReplay, 1),
    ];
    if model == LocalTxModel::TenantScopedUow {
        required.extend([
            (BackendProbe::Rollback, 1),
            (BackendProbe::RollbackFailedNoReplay, 1),
        ]);
    }
    required
}

pub(crate) const fn localtx_boundary_label(boundary: LocalTxBoundary) -> &'static str {
    match boundary {
        LocalTxBoundary::SingleDomain => "single-domain",
    }
}

pub(crate) const fn localtx_model_label(model: LocalTxModel) -> &'static str {
    match model {
        LocalTxModel::TenantScopedUow => "tenant-scoped-uow",
        LocalTxModel::RepoAtomicCas => "repo-atomic-cas",
    }
}

pub(crate) const fn localtx_retry_label(retry: LocalTxRetry) -> &'static str {
    match retry {
        LocalTxRetry::BoundedTransient => "bounded-transient",
    }
}

pub(crate) const fn localtx_commit_unknown_label(
    commit_unknown: LocalTxCommitUnknown,
) -> &'static str {
    match commit_unknown {
        LocalTxCommitUnknown::NotRetryable => "not-retryable",
    }
}

fn compiled_local_tx_keys() -> Result<BTreeSet<String>> {
    compiled_local_tx_keys_from_mount_keys(
        generated::http::LOCAL_TX_SPECS
            .iter()
            .map(|spec| spec.mount_key),
    )
}

fn compiled_local_tx_keys_from_mount_keys(
    mount_keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<BTreeSet<String>> {
    let mut keys = BTreeSet::new();
    for mount_key in mount_keys {
        let key = mount_key.as_ref().to_owned();
        if !keys.insert(key.clone()) {
            bail!("generated LocalTx exact-set duplicate mount_key `{key}`");
        }
    }
    Ok(keys)
}

#[cfg(test)]
const FIXTURE_LOCAL_TX_MOUNT_KEYS: &[&str] = &["demo_v1::write"];

#[cfg(test)]
fn fixture_compiled_local_tx_keys() -> Result<BTreeSet<String>> {
    compiled_local_tx_keys_from_mount_keys(FIXTURE_LOCAL_TX_MOUNT_KEYS.iter().copied())
}

fn workspace_crates_from_facts(root: &Path, facts: &WorkspaceFacts) -> Result<Vec<WorkspaceCrate>> {
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for package in facts.workspace_packages() {
        let name = package.key().as_str().to_owned();
        let relative = package.repo_relative_root().to_path_buf();
        let member_root = root.join(&relative);
        ensure_contained(root, root, &member_root)?;
        reject_symlinks(root, &member_root)?;
        let targets = project_cargo_targets(root, facts, package.key())?;
        let (
            normal_dependencies,
            dev_dependencies,
            normal_test_dependencies,
            dev_test_dependencies,
        ) = project_dependency_maps(root, facts, package.key())?;
        if !names.insert(name.clone()) {
            bail!("duplicate crates/* workspace package name `{name}`");
        }
        out.push(WorkspaceCrate {
            name,
            relative,
            root: member_root,
            targets,
            normal_dependencies,
            dev_dependencies,
            normal_test_dependencies,
            dev_test_dependencies,
        });
    }
    out.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(out)
}

fn project_cargo_targets(
    root: &Path,
    facts: &WorkspaceFacts,
    package: &workspacefacts::PackageKey,
) -> Result<Vec<CargoTarget>> {
    let mut targets = Vec::new();
    for target in facts.targets_for(package)? {
        let kind = match target.kind() {
            FactsTargetKind::Library | FactsTargetKind::ProcMacro => CargoTargetKind::Lib,
            FactsTargetKind::Test => CargoTargetKind::Test,
            FactsTargetKind::Binary => CargoTargetKind::Other,
            FactsTargetKind::Example
            | FactsTargetKind::Benchmark
            | FactsTargetKind::BuildScript
            | FactsTargetKind::Other => continue,
        };
        targets.push(CargoTarget {
            name: target.name().to_owned(),
            path: root.join(target.repo_relative_src_path()),
            kind,
            required_features: target.required_features().iter().cloned().collect(),
        });
    }
    targets.sort_by(|a, b| (&a.name, a.kind, &a.path).cmp(&(&b.name, b.kind, &b.path)));
    targets.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.path == b.path);
    Ok(targets)
}

type DependencyMaps = (
    BTreeMap<String, DependencyRef>,
    BTreeMap<String, DependencyRef>,
    BTreeMap<String, DependencyRef>,
    BTreeMap<String, DependencyRef>,
);

fn project_dependency_maps(
    root: &Path,
    facts: &WorkspaceFacts,
    package: &workspacefacts::PackageKey,
) -> Result<DependencyMaps> {
    let mut normal_dependencies = BTreeMap::<String, Vec<DependencyRef>>::new();
    let mut dev_dependencies = BTreeMap::<String, Vec<DependencyRef>>::new();
    let mut normal_test_dependencies = BTreeMap::<String, Vec<DependencyRef>>::new();
    let mut dev_test_dependencies = BTreeMap::<String, Vec<DependencyRef>>::new();
    for dependency in facts.direct_dependencies(package)? {
        let key = dependency.name().to_owned();
        if !protected_root(&key)
            && !matches!(key.as_str(), "tokio" | "rstest" | "thiserror" | "tracing")
        {
            continue;
        }
        let reference = dependency_ref_from_facts(root, &dependency)?;
        let destination = match (protected_root(&key), dependency.kind()) {
            (true, FactsDependencyKind::Dev) => &mut dev_dependencies,
            (true, FactsDependencyKind::Normal) => &mut normal_dependencies,
            (false, FactsDependencyKind::Dev) => &mut dev_test_dependencies,
            (false, FactsDependencyKind::Normal) => &mut normal_test_dependencies,
            (_, FactsDependencyKind::Build) => continue,
        };
        destination.entry(key).or_default().push(reference);
    }
    Ok((
        aggregate_dependency_map(normal_dependencies)?,
        aggregate_dependency_map(dev_dependencies)?,
        aggregate_dependency_map(normal_test_dependencies)?,
        aggregate_dependency_map(dev_test_dependencies)?,
    ))
}

fn dependency_ref_from_facts(
    root: &Path,
    dependency: &workspacefacts::DirectDependencyFacts,
) -> Result<DependencyRef> {
    let package = dependency
        .resolved()
        .map(|key| key.as_str().to_owned())
        .ok_or_else(|| {
            anyhow!(
                "dependency `{}` is unresolved; LocalTx coverage fail-closes without package identity",
                dependency.name()
            )
        })?;
    let source = dependency.source().clone();
    let path = match &source {
        DependencySource::Workspace { repo_relative_root }
        | DependencySource::Path { repo_relative_root } => Some(root.join(repo_relative_root)),
        DependencySource::Registry { .. }
        | DependencySource::Sparse { .. }
        | DependencySource::Git { .. }
        | DependencySource::UnknownExternal { .. } => None,
    };
    Ok(DependencyRef {
        package,
        path,
        source,
        unconditional: dependency.unconditional(),
    })
}

fn aggregate_dependency_map(
    declarations: BTreeMap<String, Vec<DependencyRef>>,
) -> Result<BTreeMap<String, DependencyRef>> {
    let mut out = BTreeMap::new();
    for (key, refs) in declarations {
        let Some(first) = refs.first() else {
            continue;
        };
        let package = first.package.clone();
        let path = first.path.clone();
        let source = first.source.clone();
        let mut unconditional = false;
        for candidate in &refs {
            if candidate.package != package || candidate.path != path || candidate.source != source
            {
                bail!(
                    "dependency key `{key}` has inconsistent resolved/source declarations; fail-closed"
                );
            }
            unconditional |= candidate.unconditional;
        }
        out.insert(
            key,
            DependencyRef {
                package,
                path,
                source,
                unconditional,
            },
        );
    }
    Ok(out)
}

fn discover_from_contracts(
    root: &Path,
    discovered: &[crate::contract::GovernedContract],
) -> Result<Vec<Contract>> {
    let mut out = Vec::new();
    for item in discovered {
        let m = item.manifest();
        if m.lifecycle != Lifecycle::Active
            || m.kind != ContractKind::Http
            || m.consistency_level != ConsistencyLevel::LocalTx
        {
            continue;
        }
        let owner = match item.owner().domain().map(vocab::DomainName::as_str) {
            Some(owner) if owner == m.domain && safe_segment(owner) => owner.to_owned(),
            _ => {
                let subject = relative(root, item.manifest_path())?;
                // Preserve invalid owners as a finding without ever joining an unsafe segment.
                out.push(Contract {
                    id: m.id.clone(),
                    owner: String::new(),
                    key: generated_key(&m.domain, &m.version, item.slug()),
                    subject,
                    valid_owner: false,
                    tx_model: m
                        .capabilities
                        .local_tx
                        .as_ref()
                        .map(|capability| capability.tx_model)
                        .unwrap_or(LocalTxModel::TenantScopedUow),
                    boundary: LocalTxBoundary::SingleDomain,
                    retry: LocalTxRetry::BoundedTransient,
                    commit_unknown: LocalTxCommitUnknown::NotRetryable,
                });
                continue;
            }
        };
        let capability = m
            .capabilities
            .local_tx
            .as_ref()
            .ok_or_else(|| anyhow!("active LocalTx contract lacks capabilities.localTx"))?;
        out.push(Contract {
            id: m.id.clone(),
            owner,
            key: generated_key(&m.domain, &m.version, item.slug()),
            subject: relative(root, item.manifest_path())?,
            valid_owner: true,
            tx_model: capability.tx_model,
            boundary: capability.boundary,
            retry: capability.retry,
            commit_unknown: capability.commit_unknown,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !value.contains(['/', '\\'])
}

fn generated_key(domain: &str, version: &str, slug: Option<&str>) -> String {
    let module = format!("{}_{}", domain.replace('-', "_"), version.replace('-', "_"));
    slug.map_or(module.clone(), |slug| {
        format!("{module}::{}", slug.replace('-', "_"))
    })
}

fn peel_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => peel_expr(&reference.expr),
        Expr::Paren(paren) => peel_expr(&paren.expr),
        Expr::Group(group) => peel_expr(&group.expr),
        other => other,
    }
}

#[derive(Default)]
struct OwnerEvidence {
    routes: BTreeSet<String>,
    canonical_mounts: BTreeMap<String, BTreeSet<CanonicalRouteMount>>,
    reachable_production_sources: BTreeSet<String>,
    markers: Vec<MarkerOccurrence>,
    backend_enrollments: Vec<BackendEnrollmentOccurrence>,
    backend_profile_violations: Vec<BackendProfileViolation>,
    test_macros: BTreeSet<String>,
    production_macros: BTreeSet<String>,
    opaque_triggers: BTreeSet<OpaqueTrigger>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CanonicalMountedState {
    Stateless,
    Ordinary,
    Classified(String),
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CanonicalRouteMount {
    pub(crate) source: String,
    pub(crate) handler: String,
    pub(crate) state: CanonicalMountedState,
}

pub(crate) struct CanonicalServingEvidence {
    pub(crate) mounts: BTreeMap<String, BTreeSet<CanonicalRouteMount>>,
    pub(crate) reachable_production_sources: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ServingEvidenceSource<'a> {
    Domain(&'a str),
    Framework(&'a str),
}

/// Canonical production routes mounted by one domain crate or framework assembly.
///
/// This is deliberately the same evidence used by the LocalTx closure gate: Cargo targets,
/// reachable modules, cfg state, aliases, handler markers, `Domain::init` /
/// `FrameworkRoutes::register`, `route_group`, and `mount` are resolved once instead of being
/// reimplemented by sibling consistency checks.
pub(crate) fn canonical_serving_evidence(
    root: &Path,
    facts: &WorkspaceFacts,
    source: ServingEvidenceSource<'_>,
) -> Result<CanonicalServingEvidence> {
    let workspace_crates = workspace_crates_from_facts(root, facts)?;
    let expected_packages: BTreeMap<_, _> = workspace_crates
        .iter()
        .map(|member| (member.name.clone(), member.relative.clone()))
        .collect();
    let (package, relative) = match source {
        ServingEvidenceSource::Domain(owner) => (owner, Path::new("crates").join(owner)),
        ServingEvidenceSource::Framework(assembly) => {
            (assembly, Path::new("assemblies").join(assembly))
        }
    };
    let member = workspace_crates
        .iter()
        .find(|member| member.name == package && member.relative == relative)
        .ok_or_else(|| anyhow!("serving source `{package}` is not a canonical workspace member"))?;
    let evidence = scan_owner(root, member, &expected_packages)?;
    Ok(CanonicalServingEvidence {
        mounts: evidence.canonical_mounts,
        reachable_production_sources: evidence.reachable_production_sources,
    })
}

struct FileUnit {
    relative: String,
    module: Vec<String>,
    syntax: File,
    resolvers: BTreeMap<String, Resolver>,
    reachability: Reachability,
    backend_profile_rejection: Option<String>,
}

#[derive(Clone)]
struct RouteMountHelper {
    function: ItemFn,
    module: Vec<String>,
    resolver: Resolver,
    reachability: Reachability,
    attribute_safe: bool,
}

#[derive(Debug, Clone, Copy)]
struct Reachability {
    prod: bool,
    test: bool,
    backend_test: bool,
    unknown: bool,
}

impl Reachability {
    const BOTH: Self = Self {
        prod: true,
        test: true,
        backend_test: true,
        unknown: false,
    };
    const TEST_ONLY: Self = Self {
        prod: false,
        test: true,
        backend_test: true,
        unknown: false,
    };

    fn with_attrs(self, attrs: &[Attribute]) -> Self {
        let mut reach = self;
        for attr in attrs {
            if attr.path().is_ident("cfg_attr") {
                return Self {
                    prod: false,
                    test: false,
                    backend_test: false,
                    unknown: true,
                };
            }
            if !attr.path().is_ident("cfg") {
                continue;
            }
            let Some(meta) = cfg_expression(attr) else {
                return Self {
                    prod: false,
                    test: false,
                    backend_test: false,
                    unknown: true,
                };
            };
            let prod = cfg_truth(&meta, false);
            let test = cfg_truth(&meta, true);
            let backend_test = cfg_truth_env(&meta, true, true);
            reach.unknown |= prod == Truth::Unknown || test == Truth::Unknown;
            reach.prod &= prod == Truth::True;
            reach.test &= test == Truth::True;
            reach.backend_test &= backend_test == Truth::True;
        }
        reach
    }
}

/// Whether an attributed item/field can exist in a production build.
///
/// Unknown cfg predicates are production-possible and therefore retained for fail-closed static
/// analysis. Only an expression proven false when `test = false` is excluded.
pub(crate) fn attrs_may_be_production(attrs: &[Attribute]) -> bool {
    attrs.iter().all(|attr| {
        if attr.path().is_ident("cfg_attr") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return true;
        }
        cfg_expression(attr).is_none_or(|meta| cfg_truth(&meta, false) != Truth::False)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Default)]
struct Resolver {
    aliases: BTreeMap<String, Vec<String>>,
    local_aliases: BTreeMap<String, Vec<String>>,
    shadowed_roots: BTreeSet<String>,
    opaque_empty_item_macro: bool,
    shadowed_test_macros: BTreeSet<String>,
    shadowed_builtin_macros: BTreeSet<String>,
    trusted_macros: BTreeSet<String>,
}

impl Resolver {
    fn inherited_risks(&self) -> Self {
        Self {
            shadowed_roots: self.shadowed_roots.clone(),
            opaque_empty_item_macro: self.opaque_empty_item_macro,
            shadowed_test_macros: self.shadowed_test_macros.clone(),
            shadowed_builtin_macros: self.shadowed_builtin_macros.clone(),
            trusted_macros: self.trusted_macros.clone(),
            ..Self::default()
        }
    }
}

const MAX_MODULE_DEPTH: usize = 64;
const MAX_CANONICAL_FILES: usize = 512;
const MAX_LOGICAL_UNITS: usize = 1024;
const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const CRATES_IO_INDEX_URL: &str = "https://github.com/rust-lang/crates.io-index";

fn backend_carrier_identity(
    root: &Path,
    member: &WorkspaceCrate,
    target: &CargoTarget,
) -> Result<BackendCarrierIdentity> {
    Ok(BackendCarrierIdentity {
        package: member.name.clone(),
        target: target.name.clone(),
        kind: target.kind,
        target_root: relative(root, &target.path)?,
        required_features: target.required_features.clone(),
    })
}

#[derive(Default)]
struct ModuleBudget {
    canonical_files: BTreeSet<PathBuf>,
    logical_units: usize,
    source_bytes: u64,
}

impl ModuleBudget {
    fn enter(&mut self, canonical: &Path, bytes: u64, depth: usize) -> Result<()> {
        if depth > MAX_MODULE_DEPTH {
            bail!("Rust module depth budget exceeded");
        }
        self.logical_units += 1;
        if self.logical_units > MAX_LOGICAL_UNITS {
            bail!("Rust logical module unit budget exceeded");
        }
        if self.canonical_files.insert(canonical.to_path_buf()) {
            if self.canonical_files.len() > MAX_CANONICAL_FILES {
                bail!("Rust canonical module file budget exceeded");
            }
            self.source_bytes = self.source_bytes.saturating_add(bytes);
            if self.source_bytes > MAX_SOURCE_BYTES {
                bail!("Rust module source byte budget exceeded");
            }
        }
        Ok(())
    }

    fn enter_inline(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_MODULE_DEPTH {
            bail!("Rust module depth budget exceeded");
        }
        self.logical_units += 1;
        if self.logical_units > MAX_LOGICAL_UNITS {
            bail!("Rust logical module unit budget exceeded");
        }
        Ok(())
    }
}

fn scan_owner(
    root: &Path,
    member: &WorkspaceCrate,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<OwnerEvidence> {
    let mut evidence = OwnerEvidence::default();
    for target in &member.targets {
        let initial = if target.kind == CargoTargetKind::Test {
            Reachability::TEST_ONLY
        } else {
            Reachability::BOTH
        };
        let target_label = relative(root, &target.path)?;
        let units = load_target_units(root, member, &target.path, initial)
            .with_context(|| format!("load Cargo target `{target_label}`"))?;
        let mut target_evidence = OwnerEvidence::default();
        scan_units(&member.name, &units, &mut target_evidence)?;
        let carrier = backend_carrier_identity(root, member, target)?;
        for enrollment in &mut target_evidence.backend_enrollments {
            enrollment.carrier = Some(carrier.clone());
        }
        validate_evidence_dependencies(member, &target_evidence, expected_packages)?;
        evidence.routes.extend(target_evidence.routes);
        for (key, mounts) in target_evidence.canonical_mounts {
            evidence
                .canonical_mounts
                .entry(key)
                .or_default()
                .extend(mounts);
        }
        evidence
            .reachable_production_sources
            .extend(target_evidence.reachable_production_sources);
        evidence.markers.extend(target_evidence.markers);
        evidence
            .backend_enrollments
            .extend(target_evidence.backend_enrollments);
        evidence
            .backend_profile_violations
            .extend(target_evidence.backend_profile_violations);
        evidence.test_macros.extend(target_evidence.test_macros);
        evidence
            .production_macros
            .extend(target_evidence.production_macros);
        evidence
            .opaque_triggers
            .extend(target_evidence.opaque_triggers);
    }
    Ok(evidence)
}

fn validate_evidence_dependencies(
    member: &WorkspaceCrate,
    evidence: &OwnerEvidence,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    if !evidence.routes.is_empty() {
        for key in ["bootstrap", "generated", "httpserve"] {
            validate_dependency(member, key, false, expected_packages)?;
        }
    }
    if !evidence.markers.is_empty() {
        for key in ["generated", "vocab"] {
            validate_dependency(member, key, true, expected_packages)?;
        }
    }
    if !evidence.backend_enrollments.is_empty() || !evidence.backend_profile_violations.is_empty() {
        for key in ["generated", "rss_conformance", "testkit", "vocab"] {
            validate_dependency(member, key, true, expected_packages)?;
        }
    }
    for macro_name in &evidence.test_macros {
        validate_macro_dependency(member, macro_name, false)?;
    }
    for macro_name in &evidence.production_macros {
        validate_macro_dependency(member, macro_name, true)?;
    }
    Ok(())
}

fn validate_macro_dependency(
    member: &WorkspaceCrate,
    key: &str,
    require_normal: bool,
) -> Result<()> {
    let normal = member.normal_test_dependencies.get(key);
    let dev = member.dev_test_dependencies.get(key);
    let candidates: Vec<_> = if key == "rstest" || require_normal {
        if require_normal {
            normal.into_iter().collect()
        } else {
            dev.into_iter().collect()
        }
    } else {
        normal.into_iter().chain(dev).collect()
    };
    if candidates.is_empty() {
        bail!("typed marker test macro lacks its effective dependency");
    }
    for dependency in candidates {
        let registry_ok = matches!(
            &dependency.source,
            DependencySource::Registry { url } if url == CRATES_IO_INDEX_URL
        );
        if dependency.package != key
            || dependency.path.is_some()
            || !registry_ok
            || !dependency.unconditional
        {
            bail!("typed marker test macro dependency has the wrong package identity");
        }
    }
    Ok(())
}

fn validate_dependency(
    member: &WorkspaceCrate,
    key: &str,
    allow_dev: bool,
    expected_packages: &BTreeMap<String, PathBuf>,
) -> Result<()> {
    let package_name = if key == "rss_conformance" {
        "rss-conformance"
    } else {
        key
    };
    let expected = expected_packages
        .get(package_name)
        .ok_or_else(|| anyhow!("protected dependency package is not a workspace member"))?;
    let normal = member.normal_dependencies.get(key);
    let dev = member.dev_dependencies.get(key);
    let candidates = normal.into_iter().chain(dev);
    let found = normal.is_some() || (allow_dev && dev.is_some());
    for candidate in candidates {
        let DependencySource::Workspace { repo_relative_root } = &candidate.source else {
            bail!("protected dependency is not a workspace package");
        };
        if candidate.package != package_name
            || repo_relative_root != expected
            || !candidate.unconditional
        {
            bail!("protected dependency key does not identify the expected workspace package");
        }
    }
    if !found {
        bail!("evidence-bearing target lacks a required protected dependency");
    }
    Ok(())
}

fn load_target_units(
    root: &Path,
    member: &WorkspaceCrate,
    target: &Path,
    reachability: Reachability,
) -> Result<Vec<FileUnit>> {
    let mut units = Vec::new();
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut budget = ModuleBudget::default();
    load_module_file(
        root,
        member,
        target,
        Vec::new(),
        reachability,
        None,
        Resolver::default(),
        &mut visited,
        &mut active,
        &mut budget,
        &mut units,
    )?;
    Ok(units)
}

#[allow(clippy::too_many_arguments)]
fn load_module_file(
    root: &Path,
    member: &WorkspaceCrate,
    file: &Path,
    module: Vec<String>,
    reachability: Reachability,
    backend_profile_rejection: Option<String>,
    inherited_resolver: Resolver,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    active: &mut BTreeSet<PathBuf>,
    budget: &mut ModuleBudget,
    units: &mut Vec<FileUnit>,
) -> Result<()> {
    ensure_contained(root, &member.root, file)?;
    let canonical = std::fs::canonicalize(file).context("canonicalize reachable Rust module")?;
    if !active.insert(canonical.clone()) {
        bail!("active Rust module inclusion cycle");
    }
    if !visited.insert((canonical.clone(), module.clone())) {
        active.remove(&canonical);
        return Ok(());
    }
    let bytes = std::fs::metadata(&canonical)
        .context("read reachable Rust module metadata")?
        .len();
    budget.enter(&canonical, bytes, module.len() + 1)?;
    let syntax = parse_file_in(root, &member.root, file)?;
    reject_sensitive_item_macros(&syntax)?;
    let mut resolvers = BTreeMap::new();
    collect_resolvers(&syntax.items, &module, &mut resolvers, inherited_resolver);
    let source_dir = file
        .parent()
        .ok_or_else(|| anyhow!("Rust module has no source directory"))?;
    let module_dir = module_child_dir(file, module.is_empty())?;
    load_external_modules(
        root,
        member,
        &syntax.items,
        source_dir,
        &module_dir,
        &module,
        reachability,
        backend_profile_rejection.clone(),
        &resolvers,
        visited,
        active,
        budget,
        units,
    )?;
    units.push(FileUnit {
        relative: relative(root, file)?,
        module,
        syntax,
        resolvers,
        reachability,
        backend_profile_rejection,
    });
    active.remove(&canonical);
    Ok(())
}

fn module_child_dir(file: &Path, target_root: bool) -> Result<PathBuf> {
    let parent = file
        .parent()
        .ok_or_else(|| anyhow!("Rust target has no parent directory"))?;
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| anyhow!("Rust target filename is not UTF-8"))?;
    if target_root || matches!(stem, "lib" | "main" | "mod") {
        Ok(parent.to_path_buf())
    } else {
        Ok(parent.join(stem))
    }
}

#[allow(clippy::too_many_arguments)]
fn load_external_modules(
    root: &Path,
    member: &WorkspaceCrate,
    items: &[Item],
    source_dir: &Path,
    module_dir: &Path,
    module: &[String],
    inherited_reachability: Reachability,
    inherited_backend_profile_rejection: Option<String>,
    resolvers: &BTreeMap<String, Resolver>,
    visited: &mut BTreeSet<(PathBuf, Vec<String>)>,
    active: &mut BTreeSet<PathBuf>,
    budget: &mut ModuleBudget,
    units: &mut Vec<FileUnit>,
) -> Result<()> {
    for item in items {
        let Item::Mod(item) = item else {
            continue;
        };
        let mut child_module = module.to_vec();
        child_module.push(item.ident.to_string());
        let child_reachability = inherited_reachability.with_attrs(&item.attrs);
        let child_backend_profile_rejection = inherited_backend_profile_rejection
            .clone()
            .or_else(|| forbidden_backend_profile_attribute(&item.attrs));
        if !child_reachability.prod && !child_reachability.test && !child_reachability.unknown {
            continue;
        }
        if let Some((_, nested)) = &item.content {
            budget.enter_inline(child_module.len() + 1)?;
            load_external_modules(
                root,
                member,
                nested,
                source_dir,
                &module_dir.join(item.ident.to_string()),
                &child_module,
                child_reachability,
                child_backend_profile_rejection,
                resolvers,
                visited,
                active,
                budget,
                units,
            )?;
            continue;
        }
        let child_file = if let Some(path) = module_path_attribute(&item.attrs)? {
            source_dir.join(path)
        } else {
            let flat = module_dir.join(format!("{}.rs", item.ident));
            let nested = module_dir.join(item.ident.to_string()).join("mod.rs");
            match (flat.is_file(), nested.is_file()) {
                (true, false) => flat,
                (false, true) => nested,
                (true, true) => bail!("external module has two source candidates"),
                (false, false) => bail!(
                    "external module source is missing for `{}`",
                    child_module.join("::")
                ),
            }
        };
        load_module_file(
            root,
            member,
            &child_file,
            child_module,
            child_reachability,
            child_backend_profile_rejection,
            resolver_for(resolvers, module)
                .map(Resolver::inherited_risks)
                .unwrap_or_default(),
            visited,
            active,
            budget,
            units,
        )?;
    }
    Ok(())
}

fn module_path_attribute(attrs: &[Attribute]) -> Result<Option<PathBuf>> {
    let mut found = None;
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("path")) {
        let Meta::NameValue(value) = &attr.meta else {
            bail!("module #[path] must be a string name-value attribute");
        };
        let Expr::Lit(literal) = &value.value else {
            bail!("module #[path] must be a string literal");
        };
        let syn::Lit::Str(path) = &literal.lit else {
            bail!("module #[path] must be a string literal");
        };
        let path = PathBuf::from(path.value());
        if path.is_absolute() {
            bail!("module #[path] must be workspace-relative");
        }
        if found.replace(path).is_some() {
            bail!("module has duplicate #[path] attributes");
        }
    }
    Ok(found)
}

fn collect_route_mount_helpers(
    items: &[Item],
    module: &mut Vec<String>,
    resolvers: &BTreeMap<String, Resolver>,
    reachability: Reachability,
    attribute_safe: bool,
    helpers: &mut BTreeMap<String, RouteMountHelper>,
) -> Result<()> {
    let resolver = resolver_for(resolvers, module).context("route helper resolver is missing")?;
    for item in items {
        match item {
            Item::Fn(function) => {
                let function_reachability = reachability.with_attrs(&function.attrs);
                let function_attribute_safe =
                    attribute_safe && attrs_safe_for_evidence(&function.attrs);
                if function_reachability.prod
                    && !function_reachability.unknown
                    && function_attribute_safe
                    && !is_test_with_resolver(&function.attrs, resolver)
                {
                    let identity = function_identity(module, &function.sig.ident.to_string());
                    ensure!(
                        helpers
                            .insert(
                                identity.clone(),
                                RouteMountHelper {
                                    function: function.clone(),
                                    module: module.clone(),
                                    resolver: resolver.clone(),
                                    reachability: function_reachability,
                                    attribute_safe: function_attribute_safe,
                                },
                            )
                            .is_none(),
                        "duplicate route mount helper identity `{identity}`"
                    );
                }
            }
            Item::Mod(item) => {
                let Some((_, nested)) = &item.content else {
                    continue;
                };
                module.push(item.ident.to_string());
                collect_route_mount_helpers(
                    nested,
                    module,
                    resolvers,
                    reachability.with_attrs(&item.attrs),
                    attribute_safe && attrs_safe_for_evidence(&item.attrs),
                    helpers,
                )?;
                module.pop();
            }
            _ => {}
        }
    }
    Ok(())
}

fn scan_units(owner: &str, units: &[FileUnit], evidence: &mut OwnerEvidence) -> Result<()> {
    let mut handlers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut route_helpers = BTreeMap::new();
    for unit in units {
        if unit.reachability.prod && !unit.reachability.unknown {
            evidence
                .reachable_production_sources
                .insert(unit.relative.clone());
        }
        let mut collector = HandlerCollector {
            module: unit.module.clone(),
            resolvers: &unit.resolvers,
            handlers: &mut handlers,
            reachability: unit.reachability,
            attribute_safe: true,
            item_scope: Vec::new(),
        };
        collector.visit_file(&unit.syntax);
        let mut helper_module = unit.module.clone();
        collect_route_mount_helpers(
            &unit.syntax.items,
            &mut helper_module,
            &unit.resolvers,
            unit.reachability,
            true,
            &mut route_helpers,
        )?;
    }
    for unit in units {
        let resolver = resolver_for(&unit.resolvers, &unit.module)
            .cloned()
            .ok_or_else(|| anyhow!("module resolver is missing"))?;
        let mut scanner = SourceScanner {
            owner,
            source: &unit.relative,
            module: unit.module.clone(),
            resolvers: &unit.resolvers,
            resolver_stack: vec![resolver],
            handlers: &handlers,
            route_helpers: &route_helpers,
            evidence,
            reachability: unit.reachability,
            in_test_function: false,
            marker_ordinal: 0,
            attribute_safe: true,
            backend_profile_rejection: unit.backend_profile_rejection.clone(),
            test_macro: None,
            canonical_domain_impl: None,
            domain_init_router: None,
            domain_init_body_pending: false,
        };
        scanner.visit_file(&unit.syntax);
    }
    Ok(())
}

fn reject_sensitive_item_macros(file: &File) -> Result<()> {
    struct DefinitionVisitor {
        error: Option<String>,
    }
    impl<'ast> Visit<'ast> for DefinitionVisitor {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if item.ident.is_some()
                && let Some(protected) = protected_token(&item.mac.tokens)
            {
                self.error = Some(format!(
                    "local macro definition touches protected LocalTx symbol `{protected}`"
                ));
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut definitions = DefinitionVisitor { error: None };
    definitions.visit_file(file);
    if let Some(error) = definitions.error {
        bail!(error);
    }

    struct InvocationVisitor {
        error: Option<String>,
    }
    impl<'ast> Visit<'ast> for InvocationVisitor {
        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if item.ident.is_none() && self.error.is_none() {
                let name = item
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                if name == "include" {
                    self.error = Some("reachable include! is unsupported".to_string());
                } else if protected_root(&name) {
                    self.error = Some("item macro binds a protected LocalTx root".to_string());
                } else if let Some(protected) = protected_token(&item.mac.tokens) {
                    self.error = Some(format!(
                        "item-position macro invocation touches protected LocalTx symbol `{protected}`"
                    ));
                }
            }
            visit::visit_item_macro(self, item);
        }
    }
    let mut invocations = InvocationVisitor { error: None };
    invocations.visit_file(file);
    if let Some(error) = invocations.error {
        bail!(error);
    }
    Ok(())
}

fn protected_token(tokens: &proc_macro2::TokenStream) -> Option<String> {
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Ident(ident) if protected_root(&ident.to_string()) => {
                return Some(ident.to_string());
            }
            proc_macro2::TokenTree::Group(group) => {
                if let Some(ident) = protected_token(&group.stream()) {
                    return Some(ident);
                }
            }
            _ => {}
        }
    }
    None
}

fn module_key(module: &[String]) -> String {
    module.join("::")
}

fn collect_resolvers(
    items: &[Item],
    module: &[String],
    out: &mut BTreeMap<String, Resolver>,
    inherited: Resolver,
) {
    collect_resolvers_with_risks(items, module, out, inherited);
}

fn collect_resolvers_with_risks(
    items: &[Item],
    module: &[String],
    out: &mut BTreeMap<String, Resolver>,
    inherited: Resolver,
) {
    let resolver = resolver_with_items(inherited, items, module);
    out.insert(module_key(module), resolver);
    for item in items {
        if let Item::Mod(item) = item
            && let Some((_, nested)) = &item.content
        {
            let mut child = module.to_vec();
            child.push(item.ident.to_string());
            let parent = out
                .get(&module_key(module))
                .map(Resolver::inherited_risks)
                .unwrap_or_default();
            collect_resolvers_with_risks(nested, &child, out, parent);
        }
    }
}

fn resolver_with_items(mut resolver: Resolver, items: &[Item], module: &[String]) -> Resolver {
    collect_macro_namespace_pollution(items, &mut resolver);
    for item in items {
        let Some(trusted) =
            trusted_scope_attributes_with_resolver(item_attributes(item), &resolver)
        else {
            resolver.opaque_empty_item_macro = true;
            continue;
        };
        resolver.trusted_macros.extend(trusted);
        if let Item::Mod(item) = item
            && protected_root(&item.ident.to_string())
        {
            resolver.shadowed_roots.insert(item.ident.to_string());
        }
        if let Item::Mod(item) = item
            && matches!(
                item.ident.to_string().as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            )
        {
            resolver.shadowed_test_macros.insert(item.ident.to_string());
        }
        if let Item::ExternCrate(item) = item {
            let binding = item
                .rename
                .as_ref()
                .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string());
            if protected_root(&binding) {
                resolver.shadowed_roots.insert(binding.clone());
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        if let Item::Macro(item) = item
            && item.ident.is_none()
        {
            resolver.opaque_empty_item_macro = true;
        }
    }
    for item in items {
        if let Item::Use(item) = item {
            collect_use(
                &item.tree,
                Vec::new(),
                item.leading_colon.is_some(),
                module,
                &mut resolver,
            );
        }
    }
    if resolver
        .trusted_macros
        .iter()
        .any(|root| resolver.shadowed_test_macros.contains(root))
    {
        resolver.opaque_empty_item_macro = true;
    }
    resolver
}

fn collect_macro_namespace_pollution(items: &[Item], resolver: &mut Resolver) {
    for item in items {
        match item {
            Item::Macro(item) => {
                if let Some(name) = item.ident.as_ref() {
                    mark_builtin_macro_shadow(&name.to_string(), resolver);
                }
            }
            Item::ExternCrate(item) => {
                let binding = item
                    .rename
                    .as_ref()
                    .map_or_else(|| item.ident.to_string(), |(_, rename)| rename.to_string());
                mark_builtin_macro_shadow(&binding, resolver);
            }
            Item::Mod(item) => mark_builtin_macro_shadow(&item.ident.to_string(), resolver),
            Item::Use(item) => collect_use_macro_pollution(&item.tree, Vec::new(), resolver),
            _ => {}
        }
    }
}

fn collect_use_macro_pollution(tree: &UseTree, mut prefix: Vec<String>, resolver: &mut Resolver) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_macro_pollution(&path.tree, prefix, resolver);
        }
        UseTree::Name(name) => mark_builtin_macro_shadow(&name.ident.to_string(), resolver),
        UseTree::Rename(rename) => {
            mark_builtin_macro_shadow(&rename.rename.to_string(), resolver);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_macro_pollution(item, prefix.clone(), resolver);
            }
        }
        UseTree::Glob(_) => {
            if prefix.as_slice() != ["super"] {
                resolver.shadowed_builtin_macros.insert("test".to_string());
                for name in BUILTIN_DERIVES {
                    resolver.shadowed_builtin_macros.insert((*name).to_string());
                }
            }
        }
    }
}

const BUILTIN_DERIVES: &[&str] = &[
    "Clone",
    "Copy",
    "Debug",
    "Default",
    "Eq",
    "Hash",
    "Ord",
    "PartialEq",
    "PartialOrd",
];

fn mark_builtin_macro_shadow(binding: &str, resolver: &mut Resolver) {
    if binding == "test" || builtin_derive(binding) {
        resolver.shadowed_builtin_macros.insert(binding.to_string());
    }
}

fn item_attributes(item: &Item) -> &[Attribute] {
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
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn trusted_scope_attributes(attrs: &[Attribute]) -> Option<BTreeSet<String>> {
    trusted_scope_attributes_with_resolver(attrs, &Resolver::default())
}

fn trusted_scope_attributes_with_resolver(
    attrs: &[Attribute],
    resolver: &Resolver,
) -> Option<BTreeSet<String>> {
    let mut trusted = BTreeSet::new();
    for attr in attrs {
        extend_trusted_attribute(attr, resolver, &mut trusted)?;
    }
    Some(trusted)
}

fn extend_trusted_attribute(
    attr: &Attribute,
    resolver: &Resolver,
    trusted: &mut BTreeSet<String>,
) -> Option<()> {
    let path = raw_segments(attr.path());
    if matches!(
        path.as_slice(),
        [single]
            if matches!(
                single.as_str(),
                "cfg" | "test" | "allow" | "warn" | "deny" | "forbid" | "doc" | "inline"
                    | "cold" | "must_use" | "ignore" | "should_panic" | "non_exhaustive" | "path"
            )
    ) {
        return Some(());
    }
    if path.as_slice() == ["derive"] {
        return extend_trusted_derives(attr, resolver, trusted);
    }
    match path.as_slice() {
        [root, leaf] if root == "tracing" && leaf == "instrument" => {
            trusted.insert("tracing".to_string());
            Some(())
        }
        [root, leaf]
            if (root == "tokio" && leaf == "test") || (root == "rstest" && leaf == "rstest") =>
        {
            Some(())
        }
        _ => None,
    }
}

fn extend_trusted_derives(
    attr: &Attribute,
    resolver: &Resolver,
    trusted: &mut BTreeSet<String>,
) -> Option<()> {
    let derives = attr
        .parse_args_with(syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)
        .ok()?;
    for derive in derives {
        let derive = raw_segments(&derive);
        match derive.as_slice() {
            [single]
                if builtin_derive(single) && !resolver.shadowed_builtin_macros.contains(single) => {
            }
            [root, leaf] if root == "thiserror" && leaf == "Error" => {
                trusted.insert("thiserror".to_string());
            }
            _ => return None,
        }
    }
    Some(())
}

fn builtin_derive(name: &str) -> bool {
    BUILTIN_DERIVES.contains(&name)
}

fn collect_use(
    tree: &UseTree,
    mut prefix: Vec<String>,
    absolute: bool,
    module: &[String],
    resolver: &mut Resolver,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use(&path.tree, prefix, absolute, module, resolver);
        }
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            let binding = name.ident.to_string();
            if import_is_canonical(&prefix, absolute, resolver) {
                resolver.aliases.insert(binding.clone(), prefix.clone());
            } else {
                if let Some(local) = local_import_identity(&prefix, module) {
                    resolver.local_aliases.insert(binding.clone(), local);
                }
                if protected_root(&binding) {
                    resolver.shadowed_roots.insert(binding.clone());
                }
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            let binding = rename.rename.to_string();
            if import_is_canonical(&prefix, absolute, resolver) {
                resolver.aliases.insert(binding.clone(), prefix.clone());
            } else {
                if let Some(local) = local_import_identity(&prefix, module) {
                    resolver.local_aliases.insert(binding.clone(), local);
                }
                if protected_root(&binding) {
                    resolver.shadowed_roots.insert(binding.clone());
                }
            }
            if matches!(
                binding.as_str(),
                "tokio" | "rstest" | "thiserror" | "tracing"
            ) {
                resolver.shadowed_test_macros.insert(binding);
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use(item, prefix.clone(), absolute, module, resolver);
            }
        }
        _ => {}
    }
}

fn protected_root(binding: &str) -> bool {
    matches!(
        binding,
        "bootstrap" | "generated" | "httpserve" | "rss_conformance" | "testkit" | "vocab"
    )
}

fn local_import_identity(segments: &[String], module: &[String]) -> Option<Vec<String>> {
    match segments.first().map(String::as_str) {
        Some("crate") => Some(segments[1..].to_vec()),
        Some("self") => Some(
            module
                .iter()
                .cloned()
                .chain(segments[1..].iter().cloned())
                .collect(),
        ),
        Some("super") => {
            let mut parent = module.to_vec();
            parent.pop()?;
            parent.extend_from_slice(&segments[1..]);
            Some(parent)
        }
        _ => None,
    }
}

fn import_is_canonical(segments: &[String], absolute: bool, _resolver: &Resolver) -> bool {
    let Some(root) = segments.first() else {
        return false;
    };
    protected_root(root) && absolute
}

fn resolver_for<'a>(
    resolvers: &'a BTreeMap<String, Resolver>,
    module: &[String],
) -> Option<&'a Resolver> {
    resolvers.get(&module_key(module))
}

fn canonical_segments(path: &syn::Path, resolver: &Resolver) -> Option<Vec<String>> {
    if resolver.opaque_empty_item_macro {
        return None;
    }
    let raw: Vec<String> = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let first = raw.first()?;
    if resolver.shadowed_roots.contains(first) {
        return None;
    }
    if path.leading_colon.is_some() && protected_root(first) {
        return Some(raw);
    }
    if resolver.local_aliases.contains_key(first) {
        return None;
    }
    if let Some(imported) = resolver.aliases.get(first) {
        return Some(
            imported
                .iter()
                .cloned()
                .chain(raw.into_iter().skip(1))
                .collect(),
        );
    }
    if protected_root(first) && path.leading_colon.is_some() {
        Some(raw)
    } else {
        None
    }
}

struct HandlerCollector<'a> {
    module: Vec<String>,
    resolvers: &'a BTreeMap<String, Resolver>,
    handlers: &'a mut BTreeMap<String, BTreeSet<String>>,
    reachability: Reachability,
    attribute_safe: bool,
    item_scope: Vec<String>,
}

impl<'ast> Visit<'ast> for HandlerCollector<'_> {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        if let Some(segment) = type_last_segment(&node.self_ty) {
            self.item_scope.push(segment);
        }
        visit::visit_item_impl(self, node);
        if type_last_segment(&node.self_ty).is_some() {
            self.item_scope.pop();
        }
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.item_scope.push(node.ident.to_string());
        visit::visit_item_trait(self, node);
        self.item_scope.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.collect_method_signature(&node.attrs, &node.sig);
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        self.collect_method_signature(&node.attrs, &node.sig);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.module.push(node.ident.to_string());
        for item in items {
            self.visit_item(item);
        }
        self.module.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let function_reachability = self.reachability.with_attrs(&node.attrs);
        if let Some(resolver) = resolver_for(self.resolvers, &self.module)
            && self.attribute_safe
            && attrs_safe_for_evidence(&node.attrs)
            && function_reachability.prod
            && !is_test_with_resolver(&node.attrs, resolver)
        {
            let keys = marker_keys_in_signature(&node.sig, resolver);
            if !keys.is_empty() {
                let identity = function_identity(&self.module, &node.sig.ident.to_string());
                self.handlers.entry(identity).or_default().extend(keys);
            }
        }
    }
}

impl HandlerCollector<'_> {
    fn collect_method_signature(&mut self, attrs: &[Attribute], sig: &syn::Signature) {
        let reachability = self.reachability.with_attrs(attrs);
        let Some(resolver) = resolver_for(self.resolvers, &self.module) else {
            return;
        };
        if !self.attribute_safe
            || !attrs_safe_for_evidence(attrs)
            || !reachability.prod
            || reachability.unknown
            || is_test_with_resolver(attrs, resolver)
        {
            return;
        }
        let keys = marker_keys_in_signature(sig, resolver);
        if !keys.is_empty() {
            let mut identity = self.module.clone();
            identity.extend(self.item_scope.iter().cloned());
            identity.push(sig.ident.to_string());
            self.handlers
                .entry(module_key(&identity))
                .or_default()
                .extend(keys);
        }
    }
}

fn type_last_segment(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

struct SourceScanner<'a> {
    owner: &'a str,
    source: &'a str,
    module: Vec<String>,
    resolvers: &'a BTreeMap<String, Resolver>,
    resolver_stack: Vec<Resolver>,
    handlers: &'a BTreeMap<String, BTreeSet<String>>,
    route_helpers: &'a BTreeMap<String, RouteMountHelper>,
    evidence: &'a mut OwnerEvidence,
    reachability: Reachability,
    in_test_function: bool,
    marker_ordinal: usize,
    attribute_safe: bool,
    backend_profile_rejection: Option<String>,
    test_macro: Option<&'static str>,
    canonical_domain_impl: Option<CanonicalServingImpl>,
    domain_init_router: Option<String>,
    domain_init_body_pending: bool,
}

impl<'ast> Visit<'ast> for SourceScanner<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        let old_backend_profile_rejection = self.backend_profile_rejection.clone();
        if self.backend_profile_rejection.is_none() {
            self.backend_profile_rejection =
                forbidden_backend_profile_attribute(item_attributes(node));
        }
        if let Some(resolver) = self.resolver_stack.last() {
            for attr in item_attributes(node) {
                let mut trusted = BTreeSet::new();
                if extend_trusted_attribute(attr, resolver, &mut trusted).is_none() {
                    self.evidence.opaque_triggers.insert(OpaqueTrigger {
                        subject: format!("{}:{}", self.source, attr.span().start().line),
                        attribute: unsupported_attribute_identity(attr, resolver),
                    });
                }
            }
        }
        visit::visit_item(self, node);
        self.backend_profile_rejection = old_backend_profile_rejection;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        let old_domain_impl = self.canonical_domain_impl;
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.canonical_domain_impl = self
            .resolver_stack
            .last()
            .and_then(|resolver| canonical_serving_impl(node, resolver));
        visit::visit_item_impl(self, node);
        self.canonical_domain_impl = old_domain_impl;
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_item_trait(self, node);
        self.restore_attrs(old);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let old = self.enter_attrs(&node.attrs);
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.domain_init_router = self.canonical_domain_impl.and_then(|kind| {
            self.resolver_stack
                .last()
                .and_then(|resolver| canonical_serving_router(&node.sig, resolver, kind))
        });
        self.domain_init_body_pending = self.domain_init_router.is_some();
        visit::visit_impl_item_fn(self, node);
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
        self.restore_attrs(old);
    }
    fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_trait_item_fn(self, node);
        self.restore_attrs(old);
    }
    fn visit_impl_item_const(&mut self, node: &'ast syn::ImplItemConst) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_impl_item_const(self, node);
        self.restore_attrs(old);
    }
    fn visit_trait_item_const(&mut self, node: &'ast syn::TraitItemConst) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_trait_item_const(self, node);
        self.restore_attrs(old);
    }
    fn visit_item_static(&mut self, node: &'ast syn::ItemStatic) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_item_static(self, node);
        self.restore_attrs(old);
    }
    fn visit_arm(&mut self, node: &'ast syn::Arm) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_arm(self, node);
        self.restore_attrs(old);
    }
    // AST audit: FieldValue is the remaining non-Expr runtime-expression carrier with attrs;
    // Variant discriminants are const-only, while all other executable carriers are scoped above.
    fn visit_field_value(&mut self, node: &'ast syn::FieldValue) {
        let old = self.enter_attrs(&node.attrs);
        visit::visit_field_value(self, node);
        self.restore_attrs(old);
    }
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        self.module.push(node.ident.to_string());
        let Some(resolver) = resolver_for(self.resolvers, &self.module).cloned() else {
            self.module.pop();
            self.reachability = old_reachability;
            self.attribute_safe = old_attribute_safe;
            return;
        };
        self.resolver_stack.push(resolver);
        for item in items {
            self.visit_item(item);
        }
        self.resolver_stack.pop();
        self.module.pop();
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let old_reachability = self.reachability;
        let old_test_function = self.in_test_function;
        let old_attribute_safe = self.attribute_safe;
        let old_test_macro = self.test_macro;
        let old_domain_router = self.domain_init_router.take();
        let old_domain_body_pending = self.domain_init_body_pending;
        self.domain_init_body_pending = false;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        let resolver = self.resolver_stack.last();
        let recognized_test =
            resolver.is_some_and(|resolver| is_test_with_resolver(&node.attrs, resolver));
        self.in_test_function = old_test_function
            || (recognized_test && self.reachability.test && !self.reachability.unknown);
        self.test_macro = resolver
            .and_then(|resolver| safe_test_macro_name(&node.attrs, resolver))
            .or(old_test_macro);
        if !old_test_function
            && recognized_test
            && self.reachability.backend_test
            && self.attribute_safe
            && let Some(resolver) = resolver
        {
            let backend_evidence = backend_enrollments_in_test_in_scope(
                &node.block,
                resolver,
                self.owner,
                self.source,
                &node.sig.ident.to_string(),
                self.backend_profile_rejection.as_deref(),
            );
            if !backend_evidence.enrollments.is_empty() || backend_evidence.violation.is_some() {
                if let Some(test_macro) = self.test_macro {
                    self.evidence.test_macros.insert(test_macro.to_string());
                }
                self.evidence
                    .test_macros
                    .extend(resolver.trusted_macros.iter().cloned());
            }
            self.evidence
                .backend_enrollments
                .extend(backend_evidence.enrollments);
            self.evidence
                .backend_profile_violations
                .extend(backend_evidence.violation);
        }
        visit::visit_item_fn(self, node);
        self.in_test_function = old_test_function;
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
        self.test_macro = old_test_macro;
        self.domain_init_router = old_domain_router;
        self.domain_init_body_pending = old_domain_body_pending;
    }
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let Some(parent) = self.resolver_stack.last().cloned() else {
            return;
        };
        let items: Vec<Item> = node
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect();
        let mut resolver = resolver_with_items(parent, &items, &self.module);
        if node
            .stmts
            .iter()
            .any(|statement| matches!(statement, syn::Stmt::Macro(_)))
        {
            resolver.opaque_empty_item_macro = true;
        }
        if self.domain_init_body_pending
            && let Some(registry) = self.domain_init_router.as_deref()
        {
            self.domain_init_body_pending = false;
            let context = ServingMountContext {
                resolver: &resolver,
                module: &self.module,
                handlers: self.handlers,
                route_helpers: self.route_helpers,
                reachability: self.reachability,
                attribute_safe: self.attribute_safe,
            };
            let mounts = direct_serving_route_mounts(node, registry, &context);
            if !mounts.is_empty() {
                self.evidence.routes.extend(mounts.keys().cloned());
                for (key, mounts) in mounts {
                    let destination = self.evidence.canonical_mounts.entry(key).or_default();
                    destination.extend(mounts.into_iter().map(|mount| CanonicalRouteMount {
                        source: self.source.to_string(),
                        handler: mount.handler,
                        state: mount.state,
                    }));
                }
                self.evidence
                    .production_macros
                    .extend(resolver.trusted_macros.iter().cloned());
            }
        }
        self.resolver_stack.push(resolver);
        visit::visit_block(self, node);
        self.resolver_stack.pop();
    }
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&item.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&item.attrs);
        if self.attribute_safe
            && self.in_test_function
            && self.reachability.test
            && !self.reachability.unknown
            && let Some(resolver) = self.resolver_stack.last()
            && let Some(type_key) = strict_test_marker_key(item, resolver)
        {
            self.evidence.markers.push(MarkerOccurrence {
                key: type_key,
                owner: self.owner.to_string(),
                path: self.source.to_string(),
                ordinal: self.marker_ordinal,
            });
            if let Some(test_macro) = self.test_macro {
                self.evidence.test_macros.insert(test_macro.to_string());
            }
            self.evidence
                .test_macros
                .extend(resolver.trusted_macros.iter().cloned());
            self.marker_ordinal += 1;
        }
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_local(&mut self, node: &'ast syn::Local) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        self.reachability = self.reachability.with_attrs(&node.attrs);
        self.attribute_safe &= attrs_safe_for_evidence(&node.attrs);
        visit::visit_local(self, node);
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
    fn visit_expr(&mut self, node: &'ast Expr) {
        let old_reachability = self.reachability;
        let old_attribute_safe = self.attribute_safe;
        let attrs = expression_attributes(node);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        visit::visit_expr(self, node);
        self.reachability = old_reachability;
        self.attribute_safe = old_attribute_safe;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CanonicalServingImpl {
    Domain,
    Framework,
}

fn canonical_serving_impl(
    node: &syn::ItemImpl,
    resolver: &Resolver,
) -> Option<CanonicalServingImpl> {
    let (_, path, _) = node.trait_.as_ref()?;
    path.leading_colon.as_ref()?;
    match canonical_segments(path, resolver).as_deref() {
        Some([root, item]) if root == "bootstrap" && item == "Domain" => {
            Some(CanonicalServingImpl::Domain)
        }
        Some([root, item]) if root == "bootstrap" && item == "FrameworkRoutes" => {
            Some(CanonicalServingImpl::Framework)
        }
        _ => None,
    }
}

fn canonical_serving_router(
    signature: &syn::Signature,
    resolver: &Resolver,
    kind: CanonicalServingImpl,
) -> Option<String> {
    let expected = match kind {
        CanonicalServingImpl::Domain => "init",
        CanonicalServingImpl::Framework => "register",
    };
    if signature.ident != expected || signature.inputs.len() != 2 {
        return None;
    }
    let mut inputs = signature.inputs.iter();
    let syn::FnArg::Receiver(receiver) = inputs.next()? else {
        return None;
    };
    if receiver.reference.is_none() || receiver.mutability.is_some() {
        return None;
    }
    let syn::FnArg::Typed(registry) = inputs.next()? else {
        return None;
    };
    let syn::Pat::Ident(binding) = registry.pat.as_ref() else {
        return None;
    };
    let Type::Reference(reference) = registry.ty.as_ref() else {
        return None;
    };
    let Type::Path(path) = reference.elem.as_ref() else {
        return None;
    };
    (binding.subpat.is_none()
        && reference.mutability.is_some()
        && path.qself.is_none()
        && path.path.leading_colon.is_some()
        && matches!(canonical_segments(&path.path, resolver).as_deref(), Some([root, item]) if root == "bootstrap" && item == "Registry"))
    .then(|| binding.ident.to_string())
}

struct ServingMountContext<'a> {
    resolver: &'a Resolver,
    module: &'a [String],
    handlers: &'a BTreeMap<String, BTreeSet<String>>,
    route_helpers: &'a BTreeMap<String, RouteMountHelper>,
    reachability: Reachability,
    attribute_safe: bool,
}

fn direct_serving_route_mounts(
    block: &syn::Block,
    registry: &str,
    context: &ServingMountContext<'_>,
) -> BTreeMap<String, BTreeSet<ResolvedRouteMount>> {
    let mut routes = BTreeMap::<String, BTreeSet<ResolvedRouteMount>>::new();
    for statement in &block.stmts {
        let Stmt::Expr(expr, _) = statement else {
            continue;
        };
        let Some((call, call_reachability, call_attribute_safe)) =
            direct_method_call(expr, context.reachability, context.attribute_safe)
        else {
            continue;
        };
        if call.method != "route_group" || simple_ident(&call.receiver).as_deref() != Some(registry)
        {
            continue;
        }
        let Some(Expr::Closure(register)) = call.args.last().map(peel_expr) else {
            continue;
        };
        let Some(router) = (register.inputs.len() == 1)
            .then(|| register.inputs.first().and_then(simple_pattern_ident))
            .flatten()
        else {
            continue;
        };
        let Expr::Block(body) = peel_expr(&register.body) else {
            continue;
        };
        let items: Vec<Item> = body
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Item(item) => Some(item.clone()),
                _ => None,
            })
            .collect();
        let mut closure_resolver =
            resolver_with_items(context.resolver.clone(), &items, context.module);
        if body
            .block
            .stmts
            .iter()
            .any(|statement| matches!(statement, Stmt::Macro(_)))
        {
            closure_resolver.opaque_empty_item_macro = true;
        }
        for (key, states) in mounted_route_states(
            &body.block,
            &router,
            &closure_resolver,
            context.module,
            context.handlers,
            call_reachability.with_attrs(&register.attrs),
            call_attribute_safe && attrs_safe_for_evidence(&register.attrs),
        ) {
            routes.entry(key).or_default().extend(states);
        }
        for (key, states) in mounted_route_helper_states(
            &body.block,
            &router,
            &closure_resolver,
            context.module,
            context.handlers,
            context.route_helpers,
        ) {
            routes.entry(key).or_default().extend(states);
        }
    }
    routes
}

fn mounted_route_helper_states(
    closure: &syn::Block,
    router: &str,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
    route_helpers: &BTreeMap<String, RouteMountHelper>,
) -> BTreeMap<String, BTreeSet<ResolvedRouteMount>> {
    let Some(Stmt::Expr(tail, None)) = closure.stmts.last() else {
        return BTreeMap::new();
    };
    let Expr::Call(call) = peel_expr(tail) else {
        return BTreeMap::new();
    };
    if call.args.first().and_then(simple_ident).as_deref() != Some(router) {
        return BTreeMap::new();
    }
    let Some(identity) = handler_identity(&call.func, module, resolver) else {
        return BTreeMap::new();
    };
    let Some(helper) = route_helpers.get(&identity) else {
        return BTreeMap::new();
    };
    if helper.module != module
        || !helper.reachability.prod
        || helper.reachability.unknown
        || !helper.attribute_safe
        || helper.function.sig.inputs.len() != call.args.len()
        || helper
            .function
            .block
            .stmts
            .iter()
            .any(|statement| matches!(statement, Stmt::Item(_) | Stmt::Macro(_)))
    {
        return BTreeMap::new();
    }
    let Some(FnArg::Typed(first)) = helper.function.sig.inputs.first() else {
        return BTreeMap::new();
    };
    let Some(helper_router) = simple_pattern_ident(&first.pat) else {
        return BTreeMap::new();
    };
    let Type::Path(router_type) = first.ty.as_ref() else {
        return BTreeMap::new();
    };
    if !matches!(
        canonical_segments(&router_type.path, &helper.resolver).as_deref(),
        Some([root, listener]) if root == "httpserve" && listener == "ListenerRouter"
    ) {
        return BTreeMap::new();
    }
    mounted_route_states(
        &helper.function.block,
        &helper_router,
        &helper.resolver,
        &helper.module,
        handlers,
        helper.reachability,
        helper.attribute_safe,
    )
}

fn direct_method_call(
    expr: &Expr,
    reachability: Reachability,
    attribute_safe: bool,
) -> Option<(&ExprMethodCall, Reachability, bool)> {
    let attrs = expression_attributes(expr);
    let reachability = reachability.with_attrs(attrs);
    let attribute_safe = attribute_safe && attrs_safe_for_evidence(attrs);
    if !attribute_safe || !reachability.prod || reachability.unknown {
        return None;
    }
    match expr {
        Expr::Try(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::Paren(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::Group(expr) => direct_method_call(&expr.expr, reachability, attribute_safe),
        Expr::MethodCall(call) => Some((call, reachability, attribute_safe)),
        _ => None,
    }
}

fn mounted_route_states(
    block: &syn::Block,
    router: &str,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
    reachability: Reachability,
    attribute_safe: bool,
) -> BTreeMap<String, BTreeSet<ResolvedRouteMount>> {
    let mut binding_counts = BTreeMap::<String, usize>::new();
    let mut endpoint_bindings =
        BTreeMap::<String, (ResolvedEndpoint, CanonicalMountedState)>::new();
    for statement in &block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let syn::Pat::Ident(pattern) = &local.pat else {
            continue;
        };
        let name = pattern.ident.to_string();
        *binding_counts.entry(name.clone()).or_default() += 1;
        if pattern.subpat.is_none()
            && attribute_safe
            && attrs_safe_for_evidence(&local.attrs)
            && reachability.with_attrs(&local.attrs).prod
            && !reachability.with_attrs(&local.attrs).unknown
            && let Some(init) = &local.init
            && let Some(endpoint) = endpoint_mount(&init.expr, resolver, module, handlers)
        {
            endpoint_bindings.insert(name, (endpoint, mounted_state(&init.expr)));
        }
    }

    let mut collector = SameScopeMountCollector {
        router,
        resolver,
        module,
        handlers,
        inline_routes: BTreeMap::new(),
        mounted_bindings: BTreeMap::new(),
        binding_uses: BTreeMap::new(),
        reachability,
        attribute_safe,
    };
    for statement in &block.stmts {
        match statement {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    let old = (collector.reachability, collector.attribute_safe);
                    collector.reachability = collector.reachability.with_attrs(&local.attrs);
                    collector.attribute_safe &= attrs_safe_for_evidence(&local.attrs);
                    collector.visit_expr(&init.expr);
                    if let Some((_, diverge)) = &init.diverge {
                        collector.visit_expr(diverge);
                    }
                    (collector.reachability, collector.attribute_safe) = old;
                }
            }
            Stmt::Expr(expr, _) => collector.visit_expr(expr),
            Stmt::Item(_) | Stmt::Macro(_) => {}
        }
    }

    let mut routes = collector.inline_routes;
    for (binding, (endpoint, state)) in endpoint_bindings {
        if binding_counts.get(&binding) == Some(&1)
            && collector.binding_uses.get(&binding) == Some(&1)
            && collector.mounted_bindings.get(&binding) == Some(&1)
        {
            routes
                .entry(endpoint.route)
                .or_default()
                .insert(ResolvedRouteMount {
                    handler: endpoint.handler,
                    state,
                });
        }
    }
    routes
}

struct SameScopeMountCollector<'a> {
    router: &'a str,
    resolver: &'a Resolver,
    module: &'a [String],
    handlers: &'a BTreeMap<String, BTreeSet<String>>,
    inline_routes: BTreeMap<String, BTreeSet<ResolvedRouteMount>>,
    mounted_bindings: BTreeMap<String, usize>,
    binding_uses: BTreeMap<String, usize>,
    reachability: Reachability,
    attribute_safe: bool,
}

impl<'ast> Visit<'ast> for SameScopeMountCollector<'_> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        let old = (self.reachability, self.attribute_safe);
        let attrs = expression_attributes(node);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        visit::visit_expr(self, node);
        (self.reachability, self.attribute_safe) = old;
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if node.qself.is_none()
            && node.path.leading_colon.is_none()
            && node.path.segments.len() == 1
        {
            *self
                .binding_uses
                .entry(node.path.segments[0].ident.to_string())
                .or_default() += 1;
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if self.attribute_safe
            && self.reachability.prod
            && !self.reachability.unknown
            && node.method == "mount"
            && simple_ident(&node.receiver).as_deref() == Some(self.router)
            && node.args.len() == 1
            && let Some(argument) = node.args.first()
        {
            if let Some(endpoint) =
                endpoint_mount(argument, self.resolver, self.module, self.handlers)
            {
                self.inline_routes
                    .entry(endpoint.route)
                    .or_default()
                    .insert(ResolvedRouteMount {
                        handler: endpoint.handler,
                        state: mounted_state(argument),
                    });
            } else if let Some(binding) = simple_ident(argument) {
                *self.mounted_bindings.entry(binding).or_default() += 1;
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_block(&mut self, _node: &'ast syn::Block) {}

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
}

fn mounted_state(expr: &Expr) -> CanonicalMountedState {
    use quote::ToTokens as _;
    match peel_expr(expr) {
        Expr::Try(value) => mounted_state(&value.expr),
        Expr::MethodCall(call) if call.method == "with_state" && call.args.len() == 1 => {
            CanonicalMountedState::Ordinary
        }
        Expr::MethodCall(call)
            if call.method == "with_classified_state" && call.args.len() == 1 =>
        {
            call.args
                .first()
                .map_or(CanonicalMountedState::Opaque, |state| {
                    CanonicalMountedState::Classified(state.to_token_stream().to_string())
                })
        }
        Expr::Call(_) => CanonicalMountedState::Stateless,
        _ => CanonicalMountedState::Opaque,
    }
}

fn simple_pattern_ident(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::Ident(pattern) = pattern else {
        return None;
    };
    pattern.subpat.is_none().then(|| pattern.ident.to_string())
}

fn simple_ident(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = peel_endpoint_expr(expr) else {
        return None;
    };
    (path.qself.is_none() && path.path.leading_colon.is_none() && path.path.segments.len() == 1)
        .then(|| path.path.segments[0].ident.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedEndpoint {
    route: String,
    handler: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ResolvedRouteMount {
    handler: String,
    state: CanonicalMountedState,
}

fn endpoint_mount(
    expr: &Expr,
    resolver: &Resolver,
    module: &[String],
    handlers: &BTreeMap<String, BTreeSet<String>>,
) -> Option<ResolvedEndpoint> {
    let Expr::Call(call) = peel_endpoint_expr(expr) else {
        return None;
    };
    if !constructor_is_canonical(call, resolver) {
        return None;
    }
    let route = call
        .args
        .first()
        .and_then(|expr| route_key(expr, resolver))?;
    let handler = call.args.iter().nth(1)?;
    if let Some(identity) = handler_identity(handler, module, resolver) {
        return handlers
            .get(&identity)
            .is_some_and(|keys| keys.contains(&route))
            .then_some(ResolvedEndpoint {
                route,
                handler: identity,
            });
    }
    expr_contains_marker(handler, &route, resolver).then(|| {
        let start = handler.span().start();
        ResolvedEndpoint {
            route,
            handler: format!(
                "<inline:{}@{}:{}>",
                module_key(module),
                start.line,
                start.column
            ),
        }
    })
}

fn peel_endpoint_expr(expr: &Expr) -> &Expr {
    match peel_expr(expr) {
        Expr::Try(expr) => peel_endpoint_expr(&expr.expr),
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "with_state" | "with_classified_state"
            ) && call.args.len() == 1 =>
        {
            peel_endpoint_expr(&call.receiver)
        }
        other => other,
    }
}

fn unsupported_attribute_identity(attr: &Attribute, resolver: &Resolver) -> String {
    if attr.path().is_ident("derive")
        && let Ok(derives) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )
    {
        for derive in derives {
            let segments = raw_segments(&derive);
            let supported = matches!(segments.as_slice(), [single] if builtin_derive(single) && !resolver.shadowed_builtin_macros.contains(single))
                || matches!(segments.as_slice(), [root, leaf] if root == "thiserror" && leaf == "Error");
            if !supported {
                return segments.join("::");
            }
        }
    }
    raw_segments(attr.path()).join("::")
}

impl SourceScanner<'_> {
    fn enter_attrs(&mut self, attrs: &[Attribute]) -> (Reachability, bool) {
        let old = (self.reachability, self.attribute_safe);
        self.reachability = self.reachability.with_attrs(attrs);
        self.attribute_safe &= attrs_safe_for_evidence(attrs);
        old
    }

    fn restore_attrs(&mut self, old: (Reachability, bool)) {
        (self.reachability, self.attribute_safe) = old;
    }
}

fn expression_attributes(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(expr) => &expr.attrs,
        Expr::Assign(expr) => &expr.attrs,
        Expr::Async(expr) => &expr.attrs,
        Expr::Await(expr) => &expr.attrs,
        Expr::Binary(expr) => &expr.attrs,
        Expr::Block(expr) => &expr.attrs,
        Expr::Break(expr) => &expr.attrs,
        Expr::Call(expr) => &expr.attrs,
        Expr::Cast(expr) => &expr.attrs,
        Expr::Closure(expr) => &expr.attrs,
        Expr::Const(expr) => &expr.attrs,
        Expr::Continue(expr) => &expr.attrs,
        Expr::Field(expr) => &expr.attrs,
        Expr::ForLoop(expr) => &expr.attrs,
        Expr::Group(expr) => &expr.attrs,
        Expr::If(expr) => &expr.attrs,
        Expr::Index(expr) => &expr.attrs,
        Expr::Infer(expr) => &expr.attrs,
        Expr::Let(expr) => &expr.attrs,
        Expr::Lit(expr) => &expr.attrs,
        Expr::Loop(expr) => &expr.attrs,
        Expr::Macro(expr) => &expr.attrs,
        Expr::Match(expr) => &expr.attrs,
        Expr::MethodCall(expr) => &expr.attrs,
        Expr::Paren(expr) => &expr.attrs,
        Expr::Path(expr) => &expr.attrs,
        Expr::Range(expr) => &expr.attrs,
        Expr::RawAddr(expr) => &expr.attrs,
        Expr::Reference(expr) => &expr.attrs,
        Expr::Repeat(expr) => &expr.attrs,
        Expr::Return(expr) => &expr.attrs,
        Expr::Struct(expr) => &expr.attrs,
        Expr::Try(expr) => &expr.attrs,
        Expr::TryBlock(expr) => &expr.attrs,
        Expr::Tuple(expr) => &expr.attrs,
        Expr::Unary(expr) => &expr.attrs,
        Expr::Unsafe(expr) => &expr.attrs,
        Expr::While(expr) => &expr.attrs,
        Expr::Yield(expr) => &expr.attrs,
        Expr::Verbatim(_) => &[],
        _ => &[],
    }
}

fn safe_test_macro_name(attrs: &[Attribute], resolver: &Resolver) -> Option<&'static str> {
    attrs
        .iter()
        .find_map(|attr| match raw_segments(attr.path()).as_slice() {
            [root, leaf]
                if root == "tokio"
                    && leaf == "test"
                    && !resolver.shadowed_test_macros.contains(root) =>
            {
                Some("tokio")
            }
            [root, leaf]
                if root == "rstest"
                    && leaf == "rstest"
                    && !resolver.shadowed_test_macros.contains(root) =>
            {
                Some("rstest")
            }
            _ => None,
        })
}

fn is_test_with_resolver(attrs: &[Attribute], resolver: &Resolver) -> bool {
    (attrs.iter().any(|attr| attr.path().is_ident("test"))
        && !resolver.shadowed_builtin_macros.contains("test"))
        || safe_test_macro_name(attrs, resolver).is_some()
}

fn attrs_safe_for_evidence(attrs: &[Attribute]) -> bool {
    trusted_scope_attributes(attrs).is_some()
}

fn forbidden_backend_profile_attribute(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|attribute| {
        let segments = raw_segments(attribute.path());
        matches!(
            segments.as_slice(),
            [name] if matches!(name.as_str(), "ignore" | "should_panic")
        )
        .then(|| {
            format!(
                "#[{}] is forbidden for backend profile evidence",
                segments[0]
            )
        })
    })
}

fn strict_test_marker_key(item: &ItemConst, resolver: &Resolver) -> Option<String> {
    if item.ident != "_" {
        return None;
    }
    let Type::Path(binding) = item.ty.as_ref() else {
        return None;
    };
    if binding.qself.is_some()
        || binding.path.leading_colon.is_none()
        || raw_segments(&binding.path).as_slice() != ["vocab", "HttpRouteBinding"]
        || canonical_segments(&binding.path, resolver).as_deref()
            != Some(["vocab".to_string(), "HttpRouteBinding".to_string()].as_slice())
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &binding.path.segments.last()?.arguments else {
        return None;
    };
    if arguments.args.len() != 2 {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    if marker.qself.is_some() || marker.path.leading_colon.is_none() {
        return None;
    }
    let marker_segments = raw_segments(&marker.path);
    if canonical_segments(&marker.path, resolver).as_deref() != Some(marker_segments.as_slice()) {
        return None;
    }
    let GenericArgument::Type(Type::Path(consistency)) = arguments.args.iter().nth(1)? else {
        return None;
    };
    if consistency.qself.is_some()
        || consistency.path.leading_colon.is_none()
        || canonical_segments(&consistency.path, resolver).as_deref()
            != Some(
                [
                    "vocab".to_string(),
                    "http".to_string(),
                    "LocalTx".to_string(),
                ]
                .as_slice(),
            )
    {
        return None;
    }
    let key = key_from_segments(&marker_segments, "RouteMarker")?;
    let Expr::Path(route) = item.expr.as_ref() else {
        return None;
    };
    if route.qself.is_some() || route.path.leading_colon.is_none() {
        return None;
    }
    let route_segments = raw_segments(&route.path);
    if canonical_segments(&route.path, resolver).as_deref() != Some(route_segments.as_slice()) {
        return None;
    }
    (key_from_segments(&route_segments, "ROUTE").as_deref() == Some(&key)).then_some(key)
}

#[cfg(test)]
fn backend_enrollments_in_test(
    block: &syn::Block,
    resolver: &Resolver,
    provider: &str,
    source: &str,
    function: &str,
) -> BackendTestEvidence {
    backend_enrollments_in_test_in_scope(block, resolver, provider, source, function, None)
}

fn backend_enrollments_in_test_in_scope(
    block: &syn::Block,
    resolver: &Resolver,
    provider: &str,
    source: &str,
    function: &str,
    scope_rejection: Option<&str>,
) -> BackendTestEvidence {
    let markers: Vec<_> = block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Item(Item::Const(item)) => {
                strict_backend_profile_key(item, resolver).map(|key| BackendProfileMarker {
                    name: item.ident.to_string(),
                    key,
                })
            }
            _ => None,
        })
        .collect();
    if !markers.is_empty()
        && let Some(detail) = scope_rejection
    {
        return BackendTestEvidence {
            enrollments: Vec::new(),
            violation: Some(BackendProfileViolation {
                rule: Rule::ForbiddenBackendProfileEvidence,
                provider: provider.to_string(),
                path: source.to_string(),
                function: function.to_string(),
                detail: detail.to_string(),
            }),
        };
    }
    if markers.len() > 1 {
        let rendered = markers
            .iter()
            .map(|marker| format!("`{}` (`{}`)", marker.name, marker.key))
            .collect::<Vec<_>>()
            .join(", ");
        return BackendTestEvidence {
            enrollments: Vec::new(),
            violation: Some(BackendProfileViolation {
                rule: Rule::MultipleBackendProfilesInTest,
                provider: provider.to_string(),
                path: source.to_string(),
                function: function.to_string(),
                detail: format!(
                    "declares {} LOCALTX_BACKEND_PROFILE_* markers: {rendered}; expected at most one",
                    markers.len()
                ),
            }),
        };
    }
    let bindings: Vec<_> = block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Item(Item::Const(item)) => strict_backend_provider_binding(item, resolver),
            _ => None,
        })
        .collect();
    let Some(marker) = markers.first() else {
        return BackendTestEvidence::default();
    };
    let expected_binding_name =
        marker
            .name
            .replacen("LOCALTX_BACKEND_PROFILE_", "LOCALTX_BACKEND_PROVIDER_", 1);
    let matching_bindings: Vec<_> = bindings
        .iter()
        .filter(|binding| binding.name == expected_binding_name && binding.key == marker.key)
        .collect();
    let [binding] = matching_bindings.as_slice() else {
        return BackendTestEvidence {
            enrollments: Vec::new(),
            violation: Some(BackendProfileViolation {
                rule: Rule::MissingBackendProviderBinding,
                provider: provider.to_string(),
                path: source.to_string(),
                function: function.to_string(),
                detail: format!(
                    "profile `{}` requires exactly one `{expected_binding_name}` typed as `PhantomData<(RouteMarker, ProviderFixture)>`; found {} matching bindings",
                    marker.name,
                    matching_bindings.len()
                ),
            }),
        };
    };
    let construction = provider_construction_bindings(block, &binding.provider_path, resolver);
    if construction.bindings.is_empty() {
        return BackendTestEvidence {
            enrollments: Vec::new(),
            violation: Some(BackendProfileViolation {
                rule: Rule::MissingBackendProviderBinding,
                provider: provider.to_string(),
                path: source.to_string(),
                function: function.to_string(),
                detail: format!(
                    "typed provider `{}` is not constructed through its canonical `{}::new(...)` or test-only `{}::from_unverified_for_test(...)` path in the enrolled test; observed constructors: {:?}",
                    binding.provider_path.join("::"),
                    binding.provider_path.join("::"),
                    binding.provider_path.join("::"),
                    construction.observed
                ),
            }),
        };
    }
    let mut probes = BTreeMap::new();
    for (probe, call) in block
        .stmts
        .iter()
        .filter_map(|statement| backend_probe_from_statement(statement, resolver))
    {
        let Some(actions) = backend_probe_actions(probe, call) else {
            return BackendTestEvidence {
                enrollments: Vec::new(),
                violation: Some(BackendProfileViolation {
                    rule: Rule::ForbiddenBackendProfileEvidence,
                    provider: provider.to_string(),
                    path: source.to_string(),
                    function: function.to_string(),
                    detail: format!(
                        "probe `{}` does not expose its canonical provider-bound action slots",
                        probe.label()
                    ),
                }),
            };
        };
        if actions.is_empty()
            || actions
                .iter()
                .any(|action| !provider_bound_call_drives_action(action, &construction.bindings))
        {
            return BackendTestEvidence {
                enrollments: Vec::new(),
                violation: Some(BackendProfileViolation {
                    rule: Rule::ForbiddenBackendProfileEvidence,
                    provider: provider.to_string(),
                    path: source.to_string(),
                    function: function.to_string(),
                    detail: format!(
                        "probe `{}` requires every provider-bound action to drive its outcome through a method call whose receiver or argument is a value constructed as `{}`",
                        probe.label(),
                        binding.provider_path.join("::")
                    ),
                }),
            };
        }
        *probes.entry(probe).or_insert(0) += 1;
    }
    let enrollments = markers
        .into_iter()
        .map(|key| BackendEnrollmentOccurrence {
            key: key.key,
            provider: provider.to_string(),
            provider_fixture: binding.provider_path.join("::"),
            path: source.to_string(),
            probes: probes.clone(),
            carrier: None,
        })
        .collect();
    BackendTestEvidence {
        enrollments,
        violation: None,
    }
}

fn backend_probe_from_statement<'a>(
    statement: &'a Stmt,
    resolver: &Resolver,
) -> Option<(BackendProbe, &'a ExprCall)> {
    let Stmt::Expr(expr, _) = statement else {
        return None;
    };
    let Expr::Try(result) = peel_expr(expr) else {
        return None;
    };
    let Expr::Await(awaited) = peel_expr(&result.expr) else {
        return None;
    };
    let Expr::Call(call) = peel_expr(&awaited.base) else {
        return None;
    };
    backend_probe_from_call(call, resolver).map(|probe| (probe, call))
}

fn strict_backend_profile_key(item: &ItemConst, resolver: &Resolver) -> Option<String> {
    if !item
        .ident
        .to_string()
        .starts_with("LOCALTX_BACKEND_PROFILE_")
    {
        return None;
    }
    let Type::Path(binding) = item.ty.as_ref() else {
        return None;
    };
    if binding.qself.is_some()
        || binding.path.leading_colon.is_none()
        || raw_segments(&binding.path).as_slice() != ["vocab", "HttpRouteBinding"]
        || canonical_backend_segments(&binding.path, resolver).as_deref()
            != Some(["vocab".to_string(), "HttpRouteBinding".to_string()].as_slice())
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &binding.path.segments.last()?.arguments else {
        return None;
    };
    if arguments.args.len() != 2 {
        return None;
    }
    let GenericArgument::Type(Type::Path(marker)) = arguments.args.first()? else {
        return None;
    };
    if marker.qself.is_some() || marker.path.leading_colon.is_none() {
        return None;
    }
    let marker_segments = raw_segments(&marker.path);
    if canonical_backend_segments(&marker.path, resolver).as_deref()
        != Some(marker_segments.as_slice())
    {
        return None;
    }
    let GenericArgument::Type(Type::Path(consistency)) = arguments.args.iter().nth(1)? else {
        return None;
    };
    if consistency.qself.is_some()
        || consistency.path.leading_colon.is_none()
        || canonical_backend_segments(&consistency.path, resolver).as_deref()
            != Some(
                [
                    "vocab".to_string(),
                    "http".to_string(),
                    "LocalTx".to_string(),
                ]
                .as_slice(),
            )
    {
        return None;
    }
    let key = key_from_segments(&marker_segments, "RouteMarker")?;
    let Expr::Path(route) = peel_expr(&item.expr) else {
        return None;
    };
    if route.qself.is_some() || route.path.leading_colon.is_none() {
        return None;
    }
    let route_segments = raw_segments(&route.path);
    if canonical_backend_segments(&route.path, resolver).as_deref()
        != Some(route_segments.as_slice())
    {
        return None;
    }
    (key_from_segments(&route_segments, "ROUTE").as_deref() == Some(&key)).then_some(key)
}

fn strict_backend_provider_binding(
    item: &ItemConst,
    resolver: &Resolver,
) -> Option<BackendProviderBinding> {
    let name = item.ident.to_string();
    if !name.starts_with("LOCALTX_BACKEND_PROVIDER_") {
        return None;
    }
    let Type::Path(phantom) = item.ty.as_ref() else {
        return None;
    };
    if phantom.qself.is_some()
        || phantom.path.leading_colon.is_none()
        || raw_segments(&phantom.path).as_slice() != ["std", "marker", "PhantomData"]
    {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &phantom.path.segments.last()?.arguments else {
        return None;
    };
    let GenericArgument::Type(Type::Tuple(binding)) = arguments.args.first()? else {
        return None;
    };
    if binding.elems.len() != 2 {
        return None;
    }
    let Type::Path(marker) = binding.elems.first()? else {
        return None;
    };
    if marker.qself.is_some() || marker.path.leading_colon.is_none() {
        return None;
    }
    let marker_segments = raw_segments(&marker.path);
    if canonical_backend_segments(&marker.path, resolver).as_deref()
        != Some(marker_segments.as_slice())
    {
        return None;
    }
    let key = key_from_segments(&marker_segments, "RouteMarker")?;
    let Type::Path(provider) = binding.elems.iter().nth(1)? else {
        return None;
    };
    if provider.qself.is_some() {
        return None;
    }
    let provider_path = canonical_provider_identity(&provider.path, resolver)?;
    let Expr::Path(value) = peel_expr(&item.expr) else {
        return None;
    };
    if value.qself.is_some()
        || value.path.leading_colon.is_none()
        || raw_segments(&value.path).as_slice() != ["std", "marker", "PhantomData"]
    {
        return None;
    }
    Some(BackendProviderBinding {
        name,
        key,
        provider_path,
    })
}

fn canonical_provider_identity(path: &syn::Path, resolver: &Resolver) -> Option<Vec<String>> {
    let raw = raw_segments(path);
    let first = raw.first()?;
    if first == "crate" {
        return Some(raw);
    }
    if let Some(imported) = resolver.local_aliases.get(first) {
        return Some(
            std::iter::once("crate".to_string())
                .chain(imported.iter().cloned())
                .chain(raw.into_iter().skip(1))
                .collect(),
        );
    }
    if let Some(imported) = resolver.aliases.get(first) {
        return Some(
            imported
                .iter()
                .cloned()
                .chain(raw.into_iter().skip(1))
                .collect(),
        );
    }
    Some(raw)
}

#[derive(Default)]
struct ProviderConstructionEvidence {
    bindings: BTreeSet<String>,
    observed: BTreeSet<String>,
}

struct ProviderConstructorVisitor<'a> {
    resolver: &'a Resolver,
    observed: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ProviderConstructorVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(function) = peel_expr(&node.func) {
            let raw = raw_segments(&function.path);
            if raw.last().is_some_and(|segment| {
                matches!(segment.as_str(), "new" | "from_unverified_for_test")
            }) {
                let mut identity =
                    canonical_provider_identity(&function.path, self.resolver).unwrap_or(raw);
                identity.pop();
                self.observed.insert(identity.join("::"));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

/// Accept only a constructor whose value is the initializer's dataflow root. Method chaining and
/// `Arc::new(provider)` preserve that root; blocks, tuples, branches and other calls do not. This
/// keeps a dead/nested canonical constructor from lending identity to an unrelated action value.
fn provider_initializer_matches(
    expression: &Expr,
    provider_path: &[String],
    resolver: &Resolver,
) -> bool {
    match peel_expr(expression) {
        Expr::MethodCall(call) => {
            provider_initializer_matches(&call.receiver, provider_path, resolver)
        }
        Expr::Call(call) => {
            let Expr::Path(function) = peel_expr(&call.func) else {
                return false;
            };
            let Some(mut identity) = canonical_provider_identity(&function.path, resolver) else {
                return false;
            };
            if identity.last().is_some_and(|segment| {
                matches!(segment.as_str(), "new" | "from_unverified_for_test")
            }) {
                identity.pop();
                if identity == provider_path {
                    return true;
                }
                let is_arc = identity.as_slice()
                    == ["std".to_string(), "sync".to_string(), "Arc".to_string()];
                return is_arc
                    && call.args.len() == 1
                    && provider_initializer_matches(&call.args[0], provider_path, resolver);
            }
            false
        }
        _ => false,
    }
}

fn provider_construction_bindings(
    block: &syn::Block,
    provider_path: &[String],
    resolver: &Resolver,
) -> ProviderConstructionEvidence {
    let mut evidence = ProviderConstructionEvidence::default();
    for statement in &block.stmts {
        let Stmt::Local(local) = statement else {
            continue;
        };
        let Some(binding) = simple_pattern_ident(&local.pat) else {
            continue;
        };
        let Some(initializer) = &local.init else {
            continue;
        };
        let mut visitor = ProviderConstructorVisitor {
            resolver,
            observed: BTreeSet::new(),
        };
        visitor.visit_expr(&initializer.expr);
        evidence.observed.extend(visitor.observed);
        if provider_initializer_matches(&initializer.expr, provider_path, resolver) {
            evidence.bindings.insert(binding);
        }
    }
    evidence
}

fn backend_probe_actions(probe: BackendProbe, call: &ExprCall) -> Option<Vec<&Expr>> {
    match probe {
        BackendProbe::Commit
        | BackendProbe::Rollback
        | BackendProbe::RejectedNoWrite
        | BackendProbe::CommitUnknownNoReplay
        | BackendProbe::RollbackFailedNoReplay => {
            let case = call.args.first()?;
            let Expr::Call(case) = peel_expr(case) else {
                return None;
            };
            case_constructor_action(case).map(|action| vec![action])
        }
        BackendProbe::TenantIsolation => call.args.iter().nth(2).map(|action| vec![action]),
        BackendProbe::RetryBoundary => {
            let policy = call.args.first()?;
            let Expr::Call(policy) = peel_expr(policy) else {
                return None;
            };
            if !call_has_constructor_suffix(policy, "RetryBoundaryCase") {
                return None;
            }
            let mut actions = Vec::new();
            for path in policy.args.iter().take(4) {
                let Expr::Call(path) = peel_expr(path) else {
                    return None;
                };
                if !matches!(
                    constructor_owner(path).as_deref(),
                    Some(
                        "TransientSuccessPath"
                            | "ConflictPath"
                            | "PermanentPath"
                            | "TransientExhaustionPath"
                    )
                ) {
                    return None;
                }
                actions.push(path.args.first()?);
            }
            (actions.len() == 4).then_some(actions)
        }
    }
}

fn case_constructor_action(call: &ExprCall) -> Option<&Expr> {
    matches!(
        constructor_owner(call).as_deref(),
        Some(
            "CommitCase"
                | "RollbackCase"
                | "RejectedNoWriteCase"
                | "CommitUnknownCase"
                | "RollbackFailedCase"
        )
    )
    .then(|| call.args.first())?
}

fn constructor_owner(call: &ExprCall) -> Option<String> {
    let Expr::Path(function) = peel_expr(&call.func) else {
        return None;
    };
    let segments = raw_segments(&function.path);
    let [.., owner, constructor] = segments.as_slice() else {
        return None;
    };
    (constructor == "new").then(|| owner.clone())
}

fn call_has_constructor_suffix(call: &ExprCall, owner: &str) -> bool {
    constructor_owner(call).as_deref() == Some(owner)
}

fn expr_is_provider_binding(expression: &Expr, bindings: &BTreeSet<String>) -> bool {
    let Expr::Path(path) = peel_expr(expression) else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && bindings.contains(&path.path.segments[0].ident.to_string())
}

fn expr_is_provider_bound_call(expression: &Expr, bindings: &BTreeSet<String>) -> bool {
    let Expr::MethodCall(call) = peel_expr(expression) else {
        return false;
    };
    expr_is_provider_binding(&call.receiver, bindings)
        || call
            .args
            .iter()
            .any(|argument| expr_is_provider_binding(argument, bindings))
}

fn expanded_provider_bindings(action: &Expr, roots: &BTreeSet<String>) -> BTreeSet<String> {
    struct AliasVisitor<'a> {
        bindings: &'a BTreeSet<String>,
        aliases: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for AliasVisitor<'_> {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let (Some(alias), Some(initializer)) =
                (simple_pattern_ident(&local.pat), local.init.as_ref())
                && expr_is_provider_binding(&initializer.expr, self.bindings)
            {
                self.aliases.insert(alias);
            }
            visit::visit_local(self, local);
        }
    }

    let mut bindings = roots.clone();
    loop {
        let mut visitor = AliasVisitor {
            bindings: &bindings,
            aliases: BTreeSet::new(),
        };
        visitor.visit_expr(action);
        let previous = bindings.len();
        bindings.extend(visitor.aliases);
        if bindings.len() == previous {
            return bindings;
        }
    }
}

fn block_tail_depends_on<F>(block: &syn::Block, is_signal: &F) -> bool
where
    F: Fn(&Expr) -> bool,
{
    block.stmts.last().is_some_and(
        |statement| matches!(statement, Stmt::Expr(tail, None) if expression_value_depends_on(tail, is_signal)),
    )
}

fn expression_value_depends_on<F>(expression: &Expr, is_signal: &F) -> bool
where
    F: Fn(&Expr) -> bool,
{
    let expression = peel_expr(expression);
    if is_signal(expression) {
        return true;
    }
    match expression {
        Expr::Array(array) => array
            .elems
            .iter()
            .any(|item| expression_value_depends_on(item, is_signal)),
        Expr::Await(awaited) => expression_value_depends_on(&awaited.base, is_signal),
        Expr::Binary(binary) => {
            expression_value_depends_on(&binary.left, is_signal)
                || expression_value_depends_on(&binary.right, is_signal)
        }
        Expr::Block(block) => block_tail_depends_on(&block.block, is_signal),
        Expr::Call(call) => call
            .args
            .iter()
            .any(|argument| expression_value_depends_on(argument, is_signal)),
        Expr::Cast(cast) => expression_value_depends_on(&cast.expr, is_signal),
        // A projection may select an untainted aggregate member. Without type/MIR place
        // information, treating the base as evidence would promote one member to the whole value.
        Expr::Field(_) | Expr::Index(_) => false,
        Expr::MethodCall(call) => {
            expression_value_depends_on(&call.receiver, is_signal)
                || call
                    .args
                    .iter()
                    .any(|argument| expression_value_depends_on(argument, is_signal))
        }
        Expr::Repeat(repeat) => expression_value_depends_on(&repeat.expr, is_signal),
        Expr::Struct(structure) => {
            structure
                .fields
                .iter()
                .any(|field| expression_value_depends_on(&field.expr, is_signal))
                || structure
                    .rest
                    .as_deref()
                    .is_some_and(|rest| expression_value_depends_on(rest, is_signal))
        }
        Expr::Try(result) => expression_value_depends_on(&result.expr, is_signal),
        Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|item| expression_value_depends_on(item, is_signal)),
        Expr::Unary(unary) => expression_value_depends_on(&unary.expr, is_signal),
        _ => false,
    }
}

fn expression_has_control_signal<F>(expression: &Expr, is_signal: &F) -> bool
where
    F: Fn(&Expr) -> bool,
{
    struct ControlVisitor<'a, F> {
        is_signal: &'a F,
        found: bool,
    }

    impl<'ast, F> Visit<'ast> for ControlVisitor<'_, F>
    where
        F: Fn(&Expr) -> bool,
    {
        fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {
            // An async block is inert unless the surrounding value-flow polls it.
        }

        fn visit_expr_closure(&mut self, _expression: &'ast syn::ExprClosure) {
            // A nested closure may never be called; its body cannot prove outer control flow.
        }

        fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
            if expression
                .expr
                .as_deref()
                .is_some_and(|value| expression_value_depends_on(value, self.is_signal))
            {
                self.found = true;
            }
            visit::visit_expr_return(self, expression);
        }

        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            if expression_value_depends_on(&expression.expr, self.is_signal) {
                self.found = true;
            }
            visit::visit_expr_try(self, expression);
        }
    }

    let mut visitor = ControlVisitor {
        is_signal,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

fn block_drives_outcome<F>(block: &syn::Block, is_signal: &F) -> bool
where
    F: Fn(&Expr) -> bool,
{
    block.stmts.iter().any(|statement| match statement {
        Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|initializer| expression_has_control_signal(&initializer.expr, is_signal)),
        Stmt::Expr(expression, Some(_)) => expression_has_control_signal(expression, is_signal),
        Stmt::Expr(expression, None) => expression_drives_outcome(expression, is_signal),
        Stmt::Item(_) | Stmt::Macro(_) => false,
    })
}

fn expression_drives_outcome<F>(expression: &Expr, is_signal: &F) -> bool
where
    F: Fn(&Expr) -> bool,
{
    match peel_expr(expression) {
        Expr::Async(expression) => block_drives_outcome(&expression.block, is_signal),
        Expr::Block(expression) => block_drives_outcome(&expression.block, is_signal),
        Expr::Closure(expression) => expression_drives_outcome(&expression.body, is_signal),
        Expr::Return(expression) => expression
            .expr
            .as_deref()
            .is_some_and(|value| expression_value_depends_on(value, is_signal)),
        Expr::Try(expression) => expression_value_depends_on(&expression.expr, is_signal),
        expression => expression_value_depends_on(expression, is_signal),
    }
}
fn provider_bound_call_is_transparent_value(
    expression: &Expr,
    provider_bindings: &BTreeSet<String>,
) -> bool {
    match expression {
        Expr::Paren(paren) => {
            provider_bound_call_is_transparent_value(&paren.expr, provider_bindings)
        }
        Expr::Group(group) => {
            provider_bound_call_is_transparent_value(&group.expr, provider_bindings)
        }
        Expr::Await(awaited) => {
            provider_bound_call_is_transparent_value(&awaited.base, provider_bindings)
        }
        Expr::Try(result) => {
            provider_bound_call_is_transparent_value(&result.expr, provider_bindings)
        }
        Expr::MethodCall(call) => {
            expr_is_provider_bound_call(expression, provider_bindings)
                || provider_bound_call_is_transparent_value(&call.receiver, provider_bindings)
        }
        _ => false,
    }
}

fn provider_call_result_bindings(
    action: &Expr,
    provider_bindings: &BTreeSet<String>,
) -> BTreeSet<String> {
    struct ResultVisitor<'a> {
        provider_bindings: &'a BTreeSet<String>,
        results: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for ResultVisitor<'_> {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let (Some(result), Some(initializer)) =
                (simple_pattern_ident(&local.pat), local.init.as_ref())
                && provider_bound_call_is_transparent_value(
                    &initializer.expr,
                    self.provider_bindings,
                )
            {
                self.results.insert(result);
            }
            visit::visit_local(self, local);
        }
    }

    let mut visitor = ResultVisitor {
        provider_bindings,
        results: BTreeSet::new(),
    };
    visitor.visit_expr(action);
    visitor.results
}

fn expr_references_any_name(expression: &Expr, names: &BTreeSet<String>) -> bool {
    let Expr::Path(path) = peel_expr(expression) else {
        return false;
    };
    path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && names.contains(&path.path.segments[0].ident.to_string())
}

fn provider_bound_call_drives_action(action: &Expr, bindings: &BTreeSet<String>) -> bool {
    let provider_bindings = expanded_provider_bindings(action, bindings);
    let provider_results = provider_call_result_bindings(action, &provider_bindings);
    expression_drives_outcome(action, &|candidate| {
        expr_is_provider_bound_call(candidate, &provider_bindings)
            || expr_references_any_name(candidate, &provider_results)
    })
}

fn backend_probe_from_call(call: &ExprCall, resolver: &Resolver) -> Option<BackendProbe> {
    let Expr::Path(function) = peel_expr(&call.func) else {
        return None;
    };
    function.path.leading_colon?;
    let segments = raw_segments(&function.path);
    if canonical_backend_segments(&function.path, resolver).as_deref() != Some(segments.as_slice())
    {
        return None;
    }
    match segments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["rss_conformance", "localtx", "assert_commit"] => Some(BackendProbe::Commit),
        ["rss_conformance", "localtx", "assert_rollback"] => Some(BackendProbe::Rollback),
        ["rss_conformance", "localtx", "assert_rejected_no_write"] => {
            Some(BackendProbe::RejectedNoWrite)
        }
        ["testkit", "tenant_conformance", "assert_tenant_isolation"] => {
            Some(BackendProbe::TenantIsolation)
        }
        [
            "testkit",
            "repo_conformance",
            "assert_retry_boundary_policy",
        ] => Some(BackendProbe::RetryBoundary),
        [
            "rss_conformance",
            "localtx",
            "assert_commit_unknown_no_replay",
        ] => Some(BackendProbe::CommitUnknownNoReplay),
        [
            "rss_conformance",
            "localtx",
            "assert_rollback_failed_no_replay",
        ] => Some(BackendProbe::RollbackFailedNoReplay),
        _ => None,
    }
}

/// Backend enrollment lives in large integration-test modules that may contain unrelated item
/// macros. Exact extern-prelude absolute paths remain compiler-checked; explicit root shadows and
/// Cargo dependency identity are rejected separately. Unlike production route evidence, an
/// unrelated opaque macro therefore cannot erase real backend test evidence.
fn canonical_backend_segments(path: &syn::Path, resolver: &Resolver) -> Option<Vec<String>> {
    let raw = raw_segments(path);
    let first = raw.first()?;
    (path.leading_colon.is_some()
        && protected_root(first)
        && !resolver.shadowed_roots.contains(first)
        && !resolver.local_aliases.contains_key(first))
    .then_some(raw)
}

fn raw_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn marker_keys_in_signature(sig: &syn::Signature, resolver: &Resolver) -> BTreeSet<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(arg) => marker_key_from_type(&arg.ty, resolver),
            _ => None,
        })
        .collect()
}

fn marker_key_from_type(ty: &Type, resolver: &Resolver) -> Option<String> {
    let Type::Path(ty) = ty else {
        return None;
    };
    let canonical = canonical_segments(&ty.path, resolver)?;
    if matches!(
        canonical.as_slice(),
        [httpserve, marker]
            if httpserve == "httpserve"
                && matches!(marker.as_str(), "ContractMarker" | "ProducerMarker")
    ) {
        let contract = ty.path.segments.last()?;
        let PathArguments::AngleBracketed(args) = &contract.arguments else {
            return None;
        };
        return args.args.iter().find_map(|arg| match arg {
            GenericArgument::Type(Type::Path(path)) => {
                generated_key_from_path(&path.path, "RouteMarker", resolver)
            }
            _ => None,
        });
    }
    generated_key_from_path(&ty.path, "RouteMarker", resolver)
}

fn route_key(expr: &Expr, resolver: &Resolver) -> Option<String> {
    let Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    generated_key_from_path(&path.path, "ROUTE", resolver)
        .or_else(|| generated_key_from_path(&path.path, "PRODUCER", resolver))
}

fn handler_identity(expr: &Expr, module: &[String], resolver: &Resolver) -> Option<String> {
    let Expr::Path(path) = peel_expr(expr) else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if let Some(first) = segments.first()
        && let Some(imported) = resolver.local_aliases.get(first)
    {
        return Some(module_key(
            &imported
                .iter()
                .cloned()
                .chain(segments.into_iter().skip(1))
                .collect::<Vec<_>>(),
        ));
    }
    let (mut base, rest) = match segments.first().map(String::as_str) {
        Some("crate") => (Vec::new(), &segments[1..]),
        Some("self") => (module.to_vec(), &segments[1..]),
        Some("super") => {
            let mut parent = module.to_vec();
            parent.pop()?;
            (parent, &segments[1..])
        }
        Some(_) => (module.to_vec(), segments.as_slice()),
        None => return None,
    };
    base.extend_from_slice(rest);
    Some(module_key(&base))
}

fn expr_contains_marker(expr: &Expr, key: &str, resolver: &Resolver) -> bool {
    struct MarkerVisitor<'a> {
        key: &'a str,
        resolver: &'a Resolver,
        found: bool,
    }
    impl<'ast> Visit<'ast> for MarkerVisitor<'_> {
        fn visit_type(&mut self, ty: &'ast Type) {
            self.found |= marker_key_from_type(ty, self.resolver).as_deref() == Some(self.key);
            visit::visit_type(self, ty);
        }
    }
    let mut visitor = MarkerVisitor {
        key,
        resolver,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn generated_key_from_path(
    path: &syn::Path,
    terminal: &str,
    resolver: &Resolver,
) -> Option<String> {
    let segments = canonical_segments(path, resolver)?;
    if segments.first().map(String::as_str) != Some("generated") {
        return None;
    }
    key_from_segments(&segments, terminal)
}

fn key_from_segments(segs: &[String], terminal: &str) -> Option<String> {
    if segs.last()? != terminal {
        return None;
    }
    if segs.first().map(String::as_str) != Some("generated")
        || segs.get(1).map(String::as_str) != Some("http")
    {
        return None;
    }
    let http = 1;
    let key = &segs[http + 1..segs.len() - 1];
    if key.is_empty() {
        None
    } else {
        Some(key.join("::"))
    }
}

fn constructor_is_canonical(call: &ExprCall, resolver: &Resolver) -> bool {
    let Expr::Path(path) = peel_expr(&call.func) else {
        return false;
    };
    let Some(segments) = canonical_segments(&path.path, resolver) else {
        return false;
    };
    matches!(
        segments.as_slice(),
        [httpserve, endpoint, constructor]
            if httpserve == "httpserve"
                && matches!(endpoint.as_str(), "GeneratedEndpoint" | "GeneratedPrimaryEndpoint")
                && matches!(
                    constructor.as_str(),
                    "new" | "new_declared" | "new_producer" | "new_declared_producer"
                )
    )
}

fn function_identity(module: &[String], name: &str) -> String {
    let mut identity = module.to_vec();
    identity.push(name.to_string());
    module_key(&identity)
}

fn cfg_expression(attr: &Attribute) -> Option<Meta> {
    use syn::parse::Parser as _;
    let Meta::List(list) = &attr.meta else {
        return None;
    };
    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
        .and_then(|nested| (nested.len() == 1).then(|| nested[0].clone()))
}

fn cfg_truth(meta: &Meta, test: bool) -> Truth {
    cfg_truth_env(meta, test, false)
}

fn cfg_truth_env(meta: &Meta, test: bool, integration: bool) -> Truth {
    use syn::parse::Parser as _;
    match meta {
        Meta::Path(path) if path.is_ident("test") => {
            if test {
                Truth::True
            } else {
                Truth::False
            }
        }
        Meta::NameValue(value) if value.path.is_ident("feature") => {
            let Expr::Lit(literal) = &value.value else {
                return Truth::Unknown;
            };
            let syn::Lit::Str(feature) = &literal.lit else {
                return Truth::Unknown;
            };
            if feature.value() == "integration" {
                if integration {
                    Truth::True
                } else {
                    Truth::Unknown
                }
            } else {
                Truth::Unknown
            }
        }
        Meta::Path(_) | Meta::NameValue(_) => Truth::Unknown,
        syn::Meta::List(list) => {
            let Some(nested) =
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                    .parse2(list.tokens.clone())
                    .ok()
            else {
                return Truth::Unknown;
            };
            if list.path.is_ident("not") && nested.len() == 1 {
                truth_not(cfg_truth_env(&nested[0], test, integration))
            } else if list.path.is_ident("all") {
                nested.iter().fold(Truth::True, |value, item| {
                    truth_and(value, cfg_truth_env(item, test, integration))
                })
            } else if list.path.is_ident("any") {
                nested.iter().fold(Truth::False, |value, item| {
                    truth_or(value, cfg_truth_env(item, test, integration))
                })
            } else {
                Truth::Unknown
            }
        }
    }
}

fn truth_not(value: Truth) -> Truth {
    match value {
        Truth::True => Truth::False,
        Truth::False => Truth::True,
        Truth::Unknown => Truth::Unknown,
    }
}

fn truth_and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn truth_or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

fn parse_file(root: &Path, path: &Path) -> Result<File> {
    parse_file_in(root, root, path)
}

fn parse_file_in(root: &Path, base: &Path, path: &Path) -> Result<File> {
    let relative = relative(root, path)?;
    let text = read_text_contained(root, base, path)?;
    syn::parse_file(&text).with_context(|| format!("parse Rust `{relative}`"))
}

fn read_text_contained(root: &Path, base: &Path, path: &Path) -> Result<String> {
    ensure_contained(root, base, path)?;
    let label = relative(root, path)?;
    std::fs::read_to_string(path).with_context(|| format!("read `{label}`"))
}

fn ensure_contained(root: &Path, base: &Path, path: &Path) -> Result<()> {
    let root = std::fs::canonicalize(root).context("canonicalize workspace root")?;
    let base = std::fs::canonicalize(base).with_context(|| {
        format!(
            "canonicalize `{}`",
            relative(&root, base).unwrap_or_default()
        )
    })?;
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("canonicalize `{}`", path.display()))?;
    if !base.starts_with(&root) || !canonical.starts_with(&base) {
        bail!("path escapes its canonical workspace scope");
    }
    Ok(())
}

fn reject_symlinks(root: &Path, path: &Path) -> Result<()> {
    let relative_path = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path is outside workspace root"))?;
    let mut current = root.to_path_buf();
    let mut metadata = std::fs::symlink_metadata(root).context("inspect workspace root")?;
    for component in relative_path.components() {
        let Component::Normal(segment) = component else {
            bail!("path is outside workspace root");
        };
        current.push(segment);
        metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                let label = relative(root, &current)?;
                return Err(error).with_context(|| format!("inspect `{label}`"));
            }
        };
        if metadata.file_type().is_symlink() {
            bail!(
                "symlink evidence is not allowed at `{}`",
                relative(root, &current)?
            );
        }
    }
    if relative_path.as_os_str().is_empty() || !path.exists() {
        return Ok(());
    }
    ensure_contained(root, root, path)?;
    if metadata.is_dir() {
        let label = relative(root, path)?;
        for entry in std::fs::read_dir(path).with_context(|| format!("read directory `{label}`"))? {
            reject_symlinks(root, &entry?.path())?;
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| anyhow!("path is outside workspace root"))?;
    Ok(rel
        .to_str()
        .ok_or_else(|| anyhow!("workspace-relative path is not UTF-8"))?
        .replace('\\', "/"))
}

fn sanitized(root: &Path, error: anyhow::Error) -> anyhow::Error {
    let mut message = format!("{error:#}").replace(root.to_string_lossy().as_ref(), ".");
    if let Ok(canonical) = std::fs::canonicalize(root) {
        message = message.replace(canonical.to_string_lossy().as_ref(), ".");
    }
    anyhow!(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_facts_projection_keeps_conditional_aggregation_and_rename_parity()
    -> anyhow::Result<()> {
        use workspacefacts::testing::{
            metadata_json, path_dependency, path_package, path_package_id, resolve_node, target,
        };
        let root = crate::testutil::unique_tmp("localtx-facts-projection");
        fs::create_dir_all(root.join("crates/leaf/src"))?;
        fs::create_dir_all(root.join("crates/consumer/src"))?;
        fs::create_dir_all(root.join("crates/consumer/tests"))?;
        fs::write(root.join("crates/leaf/src/lib.rs"), "")?;
        fs::write(root.join("crates/consumer/src/lib.rs"), "")?;
        fs::write(root.join("crates/consumer/tests/integration.rs"), "")?;
        let root_str = root.to_str().expect("utf8 temp root");
        let leaf_path = format!("{root_str}/crates/leaf");
        let consumer_path = format!("{root_str}/crates/consumer");
        let leaf = path_package(
            "leaf",
            &leaf_path,
            vec![target(
                "leaf",
                "lib",
                &format!("{leaf_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![],
            serde_json::json!({}),
        );
        let mut unconditional = path_dependency("leaf", &leaf_path);
        unconditional
            .as_object_mut()
            .unwrap()
            .insert("rename".into(), "vocab".into());
        let mut conditional = path_dependency("leaf", &leaf_path);
        {
            let object = conditional.as_object_mut().unwrap();
            object.insert("rename".into(), "vocab".into());
            object.insert("target".into(), "cfg(unix)".into());
        }
        let consumer = path_package(
            "consumer",
            &consumer_path,
            vec![
                target(
                    "consumer",
                    "lib",
                    &format!("{consumer_path}/src/lib.rs"),
                    true,
                    &[],
                ),
                target(
                    "integration",
                    "test",
                    &format!("{consumer_path}/tests/integration.rs"),
                    true,
                    &["integration"],
                ),
            ],
            vec![unconditional, conditional],
            serde_json::json!({}),
        );
        let leaf_id = path_package_id(&leaf_path);
        let consumer_id = path_package_id(&consumer_path);
        let consumer_resolve = serde_json::json!({
            "id": consumer_id,
            "dependencies": [leaf_id.clone()],
            "deps": [{
                "name": "vocab",
                "pkg": leaf_id,
                "dep_kinds": [
                    {"kind": null, "target": null},
                    {"kind": null, "target": "cfg(unix)"}
                ]
            }],
            "features": []
        });
        let json = metadata_json(
            root_str,
            vec![leaf, consumer],
            vec![leaf_id.clone(), consumer_id.clone()],
            vec![resolve_node(&leaf_id, &[]), consumer_resolve],
        );
        let facts = WorkspaceFacts::from_metadata_json(&root, &json)?;
        let crates = workspace_crates_from_facts(&root, &facts)?;
        let consumer = crates
            .iter()
            .find(|member| member.name == "consumer")
            .expect("consumer");
        assert_eq!(consumer.relative, Path::new("crates/consumer"));
        assert!(
            consumer
                .targets
                .iter()
                .any(|target| target.kind == CargoTargetKind::Lib && target.name == "consumer")
        );
        assert!(consumer.targets.iter().any(|target| {
            target.kind == CargoTargetKind::Test
                && target.name == "integration"
                && target.required_features.contains("integration")
        }));
        let alias = consumer
            .normal_dependencies
            .get("vocab")
            .expect("aggregated protected rename key");
        assert_eq!(alias.package, "leaf");
        assert!(
            alias.unconditional,
            "unconditional+conditional declarations aggregate to unconditional"
        );
        assert_eq!(alias.path.as_deref(), Some(Path::new(&leaf_path).as_ref()));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn producer_mount_uses_the_same_canonical_route_key() -> anyhow::Result<()> {
        let resolver = Resolver::default();
        let marker: Type = syn::parse_str(
            "::httpserve::ProducerMarker<::generated::http::demo_v1::write::RouteMarker>",
        )?;
        let producer: Expr = syn::parse_str("::generated::http::demo_v1::write::PRODUCER")?;
        assert_eq!(
            marker_key_from_type(&marker, &resolver).as_deref(),
            Some("demo_v1::write")
        );
        assert_eq!(
            route_key(&producer, &resolver).as_deref(),
            Some("demo_v1::write")
        );
        for constructor in ["new_producer", "new_declared_producer"] {
            let constructor: ExprCall = syn::parse_str(&format!(
                "::httpserve::GeneratedPrimaryEndpoint::{constructor}(\
                 ::generated::http::demo_v1::write::PRODUCER, handler)"
            ))?;
            assert!(constructor_is_canonical(&constructor, &resolver));
        }
        let declared: ExprCall = syn::parse_str(
            "::httpserve::GeneratedEndpoint::new_declared(\
             ::generated::http::demo_v1::write::ROUTE, handler)",
        )?;
        assert!(constructor_is_canonical(&declared, &resolver));
        Ok(())
    }

    #[test]
    fn command_scoped_localtx_paths_load_metadata_at_most_once() -> anyhow::Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(
            &root,
            move |root| {
                counter.set(counter.get() + 1);
                let output = crate::cmd::cargo_cmd(
                    crate::cmd::CargoSubcommand::Metadata,
                    &["--locked", "--all-features", "--format-version", "1"],
                    &[],
                    Some(root),
                )
                .output()
                .map_err(|error| error.to_string())?;
                if !output.status.success() {
                    return Err(format!(
                        "cargo metadata failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                Ok(output.stdout)
            },
        );
        let facts = command_facts.get()?;
        let _ = collect_workspace_inventory(&root, facts)?;
        let _ = verify_required_evidence_set(&root, facts)?;
        let _ =
            canonical_serving_evidence(&root, facts, ServingEvidenceSource::Domain("identity"))?;
        assert_eq!(calls.get(), 1, "success path must load metadata once");

        let unused_calls = Rc::new(Cell::new(0));
        let unused_counter = Rc::clone(&unused_calls);
        let _unused =
            crate::workspace_facts::CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
                unused_counter.set(unused_counter.get() + 1);
                Err("unused".to_owned())
            });
        assert_eq!(unused_calls.get(), 0, "non-facts path must stay zero-load");
        Ok(())
    }

    #[test]
    fn canonical_mount_preserves_the_exact_mounted_handler_identity() -> anyhow::Result<()> {
        let resolver = Resolver::default();
        let expression: Expr = syn::parse_str(
            "::httpserve::GeneratedPrimaryEndpoint::new_producer(\
             ::generated::http::demo_v1::write::PRODUCER, fake_handler)",
        )?;
        let handlers = BTreeMap::from([
            (
                "correct_handler".to_string(),
                BTreeSet::from(["demo_v1::write".to_string()]),
            ),
            (
                "fake_handler".to_string(),
                BTreeSet::from(["demo_v1::write".to_string()]),
            ),
        ]);

        let mounted = endpoint_mount(&expression, &resolver, &[], &handlers)
            .context("canonical producer endpoint must resolve")?;

        assert_eq!(mounted.route, "demo_v1::write");
        assert_eq!(mounted.handler, "fake_handler");
        assert_ne!(mounted.handler, "correct_handler");
        Ok(())
    }

    fn helper_mount_source(
        helper_attribute: &str,
        helper_router: &str,
        closure_tail: &str,
    ) -> String {
        format!(
            r#"
            use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
            use ::httpserve::{{
                ContractMarker,
                GeneratedPrimaryEndpoint as Endpoint,
            }};
            fn handler(_: ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
            {helper_attribute}
            fn mount_common(
                rb: {helper_router},
            ) -> Result<{helper_router}, ::httpserve::Error> {{
                let endpoint = Endpoint::new(WRITE_ROUTE, handler)?;
                Ok(rb.mount(endpoint)?)
            }}
            struct Demo;
            impl ::bootstrap::Domain for Demo {{
                fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), ::httpserve::Error> {{
                    reg.route_group(|rb| {{ {closure_tail} }})?;
                    Ok(())
                }}
            }}
            #[cfg(test)] mod tests {{
                #[test] fn covered() {{
                    const _: ::vocab::HttpRouteBinding<
                        ::generated::http::demo_v1::write::RouteMarker,
                        ::vocab::http::LocalTx,
                    > = ::generated::http::demo_v1::write::ROUTE;
                }}
            }}
            "#
        )
    }

    #[test]
    fn canonical_mount_helper_is_typed_live_and_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("canonical-route-helper")?;
        let source = temp.path.join("crates/demo/src/lib.rs");
        let router = "::httpserve::ListenerRouter<()>";
        fs::write(&source, helper_mount_source("", router, "mount_common(rb)"))?;
        let evidence = {
            let command_facts = fixture_command_facts(&temp.path);
            let facts = command_facts.get()?;
            canonical_serving_evidence(&temp.path, facts, ServingEvidenceSource::Domain("demo"))
        }?;
        assert!(evidence.mounts.contains_key("demo_v1::write"));

        for (label, mutated) in [
            (
                "test-only helper",
                helper_mount_source("#[cfg(test)]", router, "mount_common(rb)"),
            ),
            (
                "wrong router type",
                helper_mount_source("", "FakeRouter", "mount_common(rb)"),
            ),
            (
                "wrong router argument",
                helper_mount_source("", router, "mount_common(decoy_rb)"),
            ),
            (
                "non-tail helper call",
                helper_mount_source("", router, "let _discarded = mount_common(rb); Ok(rb)"),
            ),
        ] {
            fs::write(&source, mutated)?;
            let evidence = {
                let command_facts = fixture_command_facts(&temp.path);
                let facts = command_facts.get()?;
                canonical_serving_evidence(&temp.path, facts, ServingEvidenceSource::Domain("demo"))
            }?;
            assert!(
                !evidence.mounts.contains_key("demo_v1::write"),
                "{label} must not satisfy canonical mount evidence"
            );
        }
        Ok(())
    }

    use std::fs;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/localtx_coverage")
            .join(name)
    }

    fn fixture_command_facts(root: &Path) -> crate::workspace_facts::CommandWorkspaceFacts {
        crate::workspace_facts::CommandWorkspaceFacts::for_test_fixture(root)
    }

    fn check_fixture_root(root: &Path) -> Result<(String, Vec<Finding>)> {
        let command_facts = fixture_command_facts(root);
        let facts = command_facts
            .get()
            .map_err(|error| sanitized(root, error))?;
        collect_fixture_inventory_with_keys(root, facts, &fixture_compiled_local_tx_keys()?)
            .map(LocalTxProofInventory::into_gate)
    }

    fn collect_fixture_inventory_under(root: &Path) -> Result<LocalTxProofInventory> {
        let command_facts = fixture_command_facts(root);
        let facts = command_facts
            .get()
            .map_err(|error| sanitized(root, error))?;
        collect_fixture_inventory_with_keys(root, facts, &fixture_compiled_local_tx_keys()?)
    }

    fn workspace_command_facts(root: &Path) -> crate::workspace_facts::CommandWorkspaceFacts {
        crate::workspace_facts::CommandWorkspaceFacts::new(root)
    }

    fn required_error<T>(
        result: anyhow::Result<T>,
        message: &str,
    ) -> anyhow::Result<anyhow::Error> {
        match result {
            Ok(_) => bail!("{message}"),
            Err(error) => Ok(error),
        }
    }

    fn replace_exact_once(
        source: &str,
        needle: &str,
        replacement: &str,
        context: &str,
    ) -> anyhow::Result<String> {
        if needle.is_empty() {
            bail!("{context}: mutation needle must not be empty");
        }
        let matches = source.match_indices(needle).take(2).count();
        if matches != 1 {
            bail!("{context}: expected exactly one mutation match, found {matches}");
        }
        Ok(source.replacen(needle, replacement, 1))
    }

    #[test]
    fn fixture_mutation_requires_exactly_one_match() -> anyhow::Result<()> {
        assert!(replace_exact_once("alpha", "missing", "beta", "missing mutation").is_err());
        assert!(replace_exact_once("alpha alpha", "alpha", "beta", "duplicate mutation").is_err());
        assert_eq!(
            replace_exact_once("alpha", "alpha", "beta", "single mutation")?,
            "beta"
        );
        Ok(())
    }

    #[test]
    fn framework_routes_trait_is_a_canonical_serving_root() -> anyhow::Result<()> {
        let item: syn::ItemImpl = syn::parse_str(
            r#"impl ::bootstrap::FrameworkRoutes for Routes {
                fn register(&self, registry: &mut ::bootstrap::Registry) -> Result<(), ::bootstrap::KernelError> {
                    Ok(())
                }
            }"#,
        )?;
        let resolver = Resolver::default();
        assert_eq!(
            canonical_serving_impl(&item, &resolver),
            Some(CanonicalServingImpl::Framework)
        );
        let method = item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) => Some(method),
            _ => None,
        });
        assert_eq!(
            method.and_then(|method| canonical_serving_router(
                &method.sig,
                &resolver,
                CanonicalServingImpl::Framework,
            )),
            Some("registry".to_string())
        );
        Ok(())
    }

    #[test]
    fn framework_assembly_uses_the_same_canonical_mount_scanner() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("framework-serving-evidence")?;
        let assembly = temp.path.join("assemblies/runtime");
        copy_tree(&temp.path.join("crates/demo"), &assembly)?;
        fs::remove_dir_all(temp.path.join("crates/demo"))?;
        fs::write(
            temp.path.join("Cargo.toml"),
            fs::read_to_string(temp.path.join("Cargo.toml"))?
                .replace("\"crates/demo\"", "\"assemblies/runtime\""),
        )?;
        fs::write(
            assembly.join("Cargo.toml"),
            fs::read_to_string(assembly.join("Cargo.toml"))?
                .replace("name = \"demo\"", "name = \"runtime\"")
                .replace(
                    "path = \"../bootstrap\"",
                    "path = \"../../crates/bootstrap\"",
                )
                .replace(
                    "path = \"../httpserve\"",
                    "path = \"../../crates/httpserve\"",
                )
                .replace("path = \"../vocab\"", "path = \"../../crates/vocab\""),
        )?;
        fs::write(
            assembly.join("src/lib.rs"),
            fs::read_to_string(assembly.join("src/lib.rs"))?
                .replace(
                    "impl ::bootstrap::Domain for Demo",
                    "impl ::bootstrap::FrameworkRoutes for Demo",
                )
                .replace("fn init(&self", "fn register(&self"),
        )?;

        let evidence = {
            let command_facts = fixture_command_facts(&temp.path);
            let facts = command_facts.get()?;
            canonical_serving_evidence(
                &temp.path,
                facts,
                ServingEvidenceSource::Framework("runtime"),
            )
        }?;
        assert!(evidence.mounts.contains_key("demo_v1::write"));
        assert!(
            evidence
                .reachable_production_sources
                .contains("assemblies/runtime/src/lib.rs")
        );
        Ok(())
    }

    #[test]
    fn green_fixture_closes_every_active_localtx_contract() -> anyhow::Result<()> {
        let (summary, findings) = check_fixture_root(&fixture("green"))?;
        assert_eq!(summary, "1 active LocalTx HTTP contract(s) covered");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn journey_missing_board_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-missing-board")?;
        let board = temp.path.join("journeys/status-board.toml");
        if board.exists() {
            fs::remove_file(board)?;
        }
        assert!(
            check_fixture_root(&temp.path).is_err(),
            "a scoped journey closure without its status board must fail closed"
        );
        Ok(())
    }

    #[test]
    fn journey_unknown_board_field_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-unknown-board-field")?;
        let board = temp.path.join("journeys/status-board.toml");
        fs::write(
            &board,
            fs::read_to_string(&board)?.replacen(
                "runner = \"journeys/tests/localtx_validation_journey.rs\"\n",
                "runner = \"journeys/tests/localtx_validation_journey.rs\"\nlegacyEntries = []\n",
                1,
            ),
        )?;
        let error = required_error(
            check_fixture_root(&temp.path),
            "unknown board field must fail",
        )?;
        assert!(
            format!("{error:#}").contains("legacyEntries"),
            "diagnostic must identify the unknown board field: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_unknown_spec_field_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-unknown-spec-field")?;
        let spec = temp.path.join("journeys/demo-write-localtx-journey.toml");
        fs::write(
            &spec,
            fs::read_to_string(&spec)?.replacen(
                "\n[[scenarios]]",
                "\nlegacyAlias = true\n\n[[scenarios]]",
                1,
            ),
        )?;
        let error = required_error(
            check_fixture_root(&temp.path),
            "unknown spec field must fail",
        )?;
        assert!(
            format!("{error:#}").contains("legacyAlias"),
            "diagnostic must identify the unknown spec field: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_unknown_fixture_field_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-unknown-fixture-field")?;
        let fixture = temp.path.join("fixtures/demo-write-localtx.toml");
        fs::write(
            &fixture,
            fs::read_to_string(&fixture)?.replacen(
                "\n[[cases]]",
                "\nlegacyCases = []\n\n[[cases]]",
                1,
            ),
        )?;
        let error = required_error(
            check_fixture_root(&temp.path),
            "unknown fixture field must fail",
        )?;
        assert!(
            format!("{error:#}").contains("legacyCases"),
            "diagnostic must identify the unknown fixture field: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_spec_metadata_drift_identifies_field_and_values() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-spec-metadata-drift")?;
        let spec = temp.path.join("journeys/demo-write-localtx-journey.toml");
        fs::write(
            &spec,
            fs::read_to_string(&spec)?.replace(
                "fixture = \"fixtures/demo-write-localtx.toml\"",
                "fixture = \"fixtures/drift-localtx.toml\"",
            ),
        )?;
        let error = required_error(load_journey_closure(&temp.path), "spec drift must fail")?;
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("journeys/demo-write-localtx-journey.toml"));
        assert!(diagnostic.contains("field `fixture`"));
        assert!(diagnostic.contains("expected `fixtures/demo-write-localtx.toml`"));
        assert!(diagnostic.contains("actual `fixtures/drift-localtx.toml`"));
        Ok(())
    }

    #[test]
    fn journey_fixture_metadata_drift_identifies_field_and_values() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-fixture-metadata-drift")?;
        let fixture = temp.path.join("fixtures/demo-write-localtx.toml");
        fs::write(
            &fixture,
            fs::read_to_string(&fixture)?
                .replace("marker = \"DEMO_WRITE\"", "marker = \"DEMO_DRIFT\""),
        )?;
        let error = required_error(load_journey_closure(&temp.path), "fixture drift must fail")?;
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("fixtures/demo-write-localtx.toml"));
        assert!(diagnostic.contains("field `marker`"));
        assert!(diagnostic.contains("expected `DEMO_WRITE`"));
        assert!(diagnostic.contains("actual `DEMO_DRIFT`"));
        Ok(())
    }

    #[test]
    fn journey_dangling_spec_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-dangling-spec")?;
        fs::remove_file(temp.path.join("journeys/demo-write-localtx-journey.toml"))?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_missing_typed_marker_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-missing-marker")?;
        fs::write(temp.path.join(GREEN_JOURNEY_RUNNER_PATH), "")?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_marker_without_test_attribute_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-marker-without-test-attribute")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replacen("#[test]\n", "", 1),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "marker-only runner must fail",
        )?;
        assert!(
            format!("{error:#}").contains("must be inside a real"),
            "diagnostic must reject marker-only runner: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_marker_in_unused_closure_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-marker-in-unused-closure")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        let source = fs::read_to_string(&runner)?;
        fs::write(
            &runner,
            source.replace(
                r#"    const LOCALTX_JOURNEY_DEMO_WRITE: ::vocab::HttpRouteBinding<
        ::generated::http::demo_v1::write::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::demo_v1::write::ROUTE;
"#,
                r#"    let _bait = || {
        const LOCALTX_JOURNEY_DEMO_WRITE: ::vocab::HttpRouteBinding<
            ::generated::http::demo_v1::write::RouteMarker,
            ::vocab::http::LocalTx,
        > = ::generated::http::demo_v1::write::ROUTE;
    };
"#,
            ),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "marker in an unused closure must fail",
        )?;
        assert!(
            format!("{error:#}").contains("top-level const item"),
            "diagnostic must reject a marker hidden in an unused closure: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_ignored_test_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-ignored-test")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replacen("#[test]\n", "#[ignore]\n#[test]\n", 1),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "an ignored marker test must fail",
        )?;
        assert!(
            format!("{error:#}").contains("#[ignore] is forbidden"),
            "diagnostic must reject ignored journey tests: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_cfg_disabled_test_is_rejected() -> anyhow::Result<()> {
        for (name, attribute, diagnostic) in [
            ("cfg", "#[cfg(any())]\n", "#[cfg] is forbidden"),
            (
                "cfg-attr",
                "#[cfg_attr(all(), ignore)]\n",
                "#[cfg_attr] is forbidden",
            ),
        ] {
            let temp = FixtureCopy::new(&format!("localtx-journey-{name}-test"))?;
            let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
            fs::write(
                &runner,
                fs::read_to_string(&runner)?.replacen(
                    "#[test]\n",
                    &format!("{attribute}#[test]\n"),
                    1,
                ),
            )?;
            let error = required_error(
                load_journey_closure(&temp.path),
                "a conditionally disabled marker test must fail",
            )?;
            assert!(
                format!("{error:#}").contains(diagnostic),
                "diagnostic must reject conditionally disabled journey tests: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn journey_cfg_disabled_ancestor_is_rejected() -> anyhow::Result<()> {
        for (name, attribute) in [
            ("cfg-ancestor", "#[cfg(any())]"),
            ("cfg-attr-ancestor", "#[cfg_attr(all(), cfg(any()))]"),
        ] {
            let temp = FixtureCopy::new(&format!("localtx-journey-{name}"))?;
            let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
            fs::write(
                &runner,
                format!(
                    "{attribute}\nmod disabled {{\n{}\n}}\n",
                    fs::read_to_string(&runner)?
                ),
            )?;
            let error = required_error(
                load_journey_closure(&temp.path),
                "a conditionally disabled ancestor must not supply journey evidence",
            )?;
            assert!(
                format!("{error:#}").contains("ancestor"),
                "diagnostic must reject {name}: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn journey_should_panic_test_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-should-panic-test")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replacen("#[test]\n", "#[should_panic]\n#[test]\n", 1),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "a should-panic marker test must fail",
        )?;
        assert!(
            format!("{error:#}").contains("#[should_panic] is forbidden"),
            "diagnostic must reject should-panic journey tests: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_missing_case_consumption_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-missing-case-consumption")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replace(
                "    let contention = fixtures.take_case(\"demo-write-contention\")?;\n",
                "",
            ),
        )?;
        let error = required_error(load_journey_closure(&temp.path), "missing case must fail")?;
        assert!(
            format!("{error:#}").contains("demo-write-contention"),
            "diagnostic must name the unconsumed case: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_duplicate_case_consumption_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-duplicate-case-consumption")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replace(
                "    let contention = fixtures.take_case(\"demo-write-contention\")?;",
                "    let contention = fixtures.take_case(\"demo-write-contention\")?;\n    let contention = fixtures.take_case(\"demo-write-contention\")?;",
            ),
        )?;
        let error = required_error(load_journey_closure(&temp.path), "duplicate case must fail")?;
        assert!(
            format!("{error:#}").contains("duplicate")
                && format!("{error:#}").contains("demo-write-contention"),
            "diagnostic must name the duplicate case: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_dynamic_case_consumption_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-dynamic-case-consumption")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replace(
                "    let contention = fixtures.take_case(\"demo-write-contention\")?;",
                "    let case_id = \"demo-write-contention\";\n    let contention = fixtures.take_case(case_id)?;",
            ),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "dynamic case id must fail",
        )?;
        assert!(
            format!("{error:#}").contains("single string literal"),
            "diagnostic must reject dynamic case ids: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_unobserved_case_values_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-unobserved-cases")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            replace_exact_once(
                &fs::read_to_string(&runner)?,
                "    observe_demo_cases(demo_cases)?;\n",
                "",
                "remove green observation closure",
            )?,
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "take_case values without an observation closure must fail",
        )?;
        assert!(
            format!("{error:#}").contains("observation closure"),
            "diagnostic must reject unobserved fixture values: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn journey_wrong_route_marker_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-wrong-route-marker")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            fs::read_to_string(&runner)?.replace("demo_v1::write", "demo_v1::other"),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_target_must_require_integration() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-target-feature")?;
        let manifest = temp.path.join("journeys/Cargo.toml");
        fs::write(
            &manifest,
            fs::read_to_string(&manifest)?.replace("required-features = [\"integration\"]\n", ""),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_green_fixture_closes_active_matrix() -> anyhow::Result<()> {
        let closure = load_journey_closure(&fixture("green"))?;
        assert_eq!(closure.entries.len(), 1);
        assert_eq!(closure.entries[0].contract_id, "demo.write");
        assert_eq!(closure.entries[0].marker, "DEMO_WRITE");
        Ok(())
    }

    #[test]
    fn journey_markers_may_span_real_tests() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-split-test-runner")?;
        let runner = temp.path.join("split_journey.rs");
        fs::write(
            &runner,
            r#"
            #[test]
            fn first() {
                const LOCALTX_JOURNEY_DEMO_FIRST: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::first::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::first::ROUTE;
                let _ = LOCALTX_JOURNEY_DEMO_FIRST;
            }

            #[test]
            fn second() {
                const LOCALTX_JOURNEY_DEMO_SECOND: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::second::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::second::ROUTE;
                let _ = LOCALTX_JOURNEY_DEMO_SECOND;
            }
            "#,
        )?;
        let evidence = scan_journey_runner(&temp.path, &runner)?;
        assert_eq!(
            evidence.markers.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from(["DEMO_FIRST".to_string(), "DEMO_SECOND".to_string()])
        );
        Ok(())
    }

    #[test]
    fn journey_entries_may_use_distinct_runners() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-distinct-entry-runners")?;
        let old_runner = "journeys/tests/localtx_validation_journey.rs";
        let new_runner = "journeys/tests/demo_read_localtx_journey.rs";
        let board = temp.path.join(JOURNEY_BOARD_PATH);
        fs::write(
            &board,
            format!(
                "{}\n[[journeys]]\nid = \"demo-read-localtx\"\ncontractId = \"demo.read\"\ntxModel = \"tenant-scoped-uow\"\nspec = \"journeys/demo-read-localtx-journey.toml\"\nfixture = \"fixtures/demo-read-localtx.toml\"\nrunner = \"{new_runner}\"\nmarker = \"DEMO_READ\"\n",
                fs::read_to_string(&board)?
            ),
        )?;
        let spec = fs::read_to_string(temp.path.join("journeys/demo-write-localtx-journey.toml"))?
            .replace("demo-write", "demo-read")
            .replace("demo.write", "demo.read")
            .replace(old_runner, new_runner)
            .replace("DEMO_WRITE", "DEMO_READ");
        fs::write(
            temp.path.join("journeys/demo-read-localtx-journey.toml"),
            spec,
        )?;
        let fixture = fs::read_to_string(temp.path.join("fixtures/demo-write-localtx.toml"))?
            .replace("demo-write", "demo-read")
            .replace("demo.write", "demo.read")
            .replace(old_runner, new_runner)
            .replace("DEMO_WRITE", "DEMO_READ");
        fs::write(temp.path.join("fixtures/demo-read-localtx.toml"), fixture)?;
        let old_path = temp.path.join(old_runner);
        let new_path = temp.path.join(new_runner);
        let runner = fs::read_to_string(old_path)?
            .replace("demo-write", "demo-read")
            .replace("demo_v1::write", "demo_v1::read")
            .replace("DEMO_WRITE", "DEMO_READ");
        fs::write(new_path, runner)?;

        let closure = load_journey_closure(&temp.path)?;
        assert_eq!(closure.entries.len(), 2);
        assert_eq!(
            closure.runners,
            BTreeSet::from([old_runner.to_string(), new_runner.to_string()])
        );
        Ok(())
    }

    #[test]
    fn journey_runner_extra_marker_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-runner-extra-marker")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        let source = fs::read_to_string(&runner)?.replace(
            "    let _ = LOCALTX_JOURNEY_DEMO_WRITE;",
            r#"    const LOCALTX_JOURNEY_DEMO_EXTRA: ::vocab::HttpRouteBinding<
        ::generated::http::demo_v1::extra::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::demo_v1::extra::ROUTE;
    let _ = (LOCALTX_JOURNEY_DEMO_WRITE, LOCALTX_JOURNEY_DEMO_EXTRA);"#,
        );
        fs::write(&runner, source)?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "an extra marker in one runner must fail",
        )?;
        assert!(format!("{error:#}").contains("DEMO_EXTRA"));
        Ok(())
    }

    #[test]
    fn journey_runner_duplicate_marker_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-runner-duplicate-marker")?;
        let runner = temp.path.join(GREEN_JOURNEY_RUNNER_PATH);
        fs::write(
            &runner,
            format!(
                "{}\n#[test]\nfn duplicate_marker() {{\n    const LOCALTX_JOURNEY_DEMO_WRITE: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE;\n    let _ = LOCALTX_JOURNEY_DEMO_WRITE;\n}}\n",
                fs::read_to_string(&runner)?
            ),
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "a duplicate marker across tests must fail",
        )?;
        assert!(format!("{error:#}").contains("duplicate marker"));
        Ok(())
    }

    #[test]
    fn journey_legacy_scope_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-legacy-scope")?;
        let board = temp.path.join(JOURNEY_BOARD_PATH);
        fs::write(
            &board,
            replace_exact_once(
                &fs::read_to_string(&board)?,
                "scope = \"active-localtx\"",
                "scope = \"issue-1706\"",
                "replace active journey scope",
            )?,
        )?;
        let error = required_error(load_journey_closure(&temp.path), "legacy scope must fail")?;
        assert!(format!("{error:#}").contains("scope must be `active-localtx`"));
        Ok(())
    }

    #[test]
    fn journey_missing_entry_is_rejected() -> anyhow::Result<()> {
        let closure = load_journey_closure(&fixture("green"))?;
        let contract = |id: &str, key: &str| Contract {
            id: id.to_owned(),
            owner: "demo".to_owned(),
            key: key.to_owned(),
            subject: format!("contracts/demo/v1/{id}/contract.toml"),
            valid_owner: true,
            tx_model: LocalTxModel::TenantScopedUow,
            boundary: LocalTxBoundary::SingleDomain,
            retry: LocalTxRetry::BoundedTransient,
            commit_unknown: LocalTxCommitUnknown::NotRetryable,
        };
        let contracts = [
            contract("demo.write", "demo_v1::write"),
            contract("demo.missing", "demo_v1::missing"),
        ];
        let error = required_error(
            validate_journey_contracts(&closure, &contracts),
            "non-empty board missing one active contract must fail",
        )?;
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("active-localtx must contain exactly"));
        assert!(diagnostic.contains("demo.missing"));
        assert!(diagnostic.contains("demo.write"));
        Ok(())
    }

    #[test]
    fn journey_extra_entry_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-extra-entry")?;
        for path in [
            JOURNEY_BOARD_PATH,
            "journeys/demo-write-localtx-journey.toml",
            "fixtures/demo-write-localtx.toml",
        ] {
            let path = temp.path.join(path);
            fs::write(
                &path,
                fs::read_to_string(&path)?
                    .replace("contractId = \"demo.write\"", "contractId = \"demo.extra\""),
            )?;
        }
        let error = required_error(
            check_fixture_root(&temp.path),
            "extra journey entry must fail",
        )?;
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("active-localtx must contain exactly"));
        assert!(diagnostic.contains("demo.extra"));
        assert!(diagnostic.contains("demo.write"));
        Ok(())
    }

    #[test]
    fn journey_duplicate_entry_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-duplicate-entry")?;
        let board = temp.path.join(JOURNEY_BOARD_PATH);
        let source = fs::read_to_string(&board)?;
        let entry = source
            .split_once("[[journeys]]")
            .map(|(_, entry)| entry)
            .context("green board entry")?;
        fs::write(&board, format!("{source}\n[[journeys]]{entry}"))?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_wrong_tx_model_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-wrong-tx-model")?;
        let board = temp.path.join(JOURNEY_BOARD_PATH);
        fs::write(
            &board,
            fs::read_to_string(&board)?.replace(
                "txModel = \"tenant-scoped-uow\"",
                "txModel = \"repo-atomic-cas\"",
            ),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_missing_scenario_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-missing-scenario")?;
        let spec = temp.path.join("journeys/demo-write-localtx-journey.toml");
        fs::write(
            &spec,
            fs::read_to_string(&spec)?.replace(
                "\n[[scenarios]]\nkind = \"contention\"\napplicable = true\n",
                "",
            ),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn journey_non_commit_unknown_case_requires_commits() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-journey-missing-commits")?;
        let fixture = temp.path.join("fixtures/demo-write-localtx.toml");
        fs::write(
            &fixture,
            replace_exact_once(
                &fs::read_to_string(&fixture)?,
                "attempts = 1\ncommits = 1",
                "attempts = 1",
                "remove happy-path commits",
            )?,
        )?;
        let error = required_error(
            load_journey_closure(&temp.path),
            "missing commits must fail",
        )?;
        assert!(
            format!("{error:#}").contains("may omit commits only for the commit-unknown scenario")
        );
        Ok(())
    }

    #[test]
    fn journey_commit_unknown_case_may_omit_commits() -> anyhow::Result<()> {
        let entry = JourneyBoardEntry {
            id: "demo-write-localtx".to_string(),
            contract_id: "demo.write".to_string(),
            tx_model: LocalTxModel::TenantScopedUow,
            spec: "journeys/demo-write-localtx-journey.toml".to_string(),
            fixture: "fixtures/demo-write-localtx.toml".to_string(),
            runner: GREEN_JOURNEY_RUNNER_PATH.to_string(),
            marker: "DEMO_WRITE".to_string(),
        };
        let fixture = JourneyFixture {
            schema_version: 1,
            id: entry.id.clone(),
            contract_id: entry.contract_id.clone(),
            tx_model: entry.tx_model,
            spec: entry.spec.clone(),
            runner: GREEN_JOURNEY_RUNNER_PATH.to_string(),
            marker: entry.marker.clone(),
            cases: vec![JourneyCase {
                id: "demo-write-commit-unknown".to_string(),
                scenario: JourneyScenarioKind::CommitUnknown,
                http_status: 500,
                error_code: "ERR_CORE_INTERNAL".to_string(),
                retryable: false,
                attempts: 1,
                commits: None,
                redact_sentinels: vec!["demo-secret".to_string()],
            }],
        };
        validate_fixture(&entry, &fixture, &mut BTreeSet::new())
    }

    #[test]
    fn journey_fake_logout_conflict_is_rejected() {
        let scenarios = [
            JourneyScenario {
                kind: JourneyScenarioKind::Happy,
                applicable: true,
                reason: None,
            },
            JourneyScenario {
                kind: JourneyScenarioKind::AuthFailure,
                applicable: true,
                reason: None,
            },
            JourneyScenario {
                kind: JourneyScenarioKind::ValidationFailure,
                applicable: true,
                reason: None,
            },
            JourneyScenario {
                kind: JourneyScenarioKind::Contention,
                applicable: true,
                reason: None,
            },
            JourneyScenario {
                kind: JourneyScenarioKind::Conflict,
                applicable: true,
                reason: None,
            },
        ];
        let cases: Vec<_> = scenarios
            .iter()
            .map(|scenario| JourneyCase {
                id: format!("logout-{}", scenario.kind.label()),
                scenario: scenario.kind,
                http_status: 200,
                error_code: "none".to_string(),
                retryable: false,
                attempts: 1,
                commits: Some(1),
                redact_sentinels: vec!["session-sentinel".to_string()],
            })
            .collect();
        assert!(
            validate_scenario_matrix(
                LocalTxModel::TenantScopedUow,
                &scenarios,
                &cases,
                "synthetic-localtx",
            )
            .is_err()
        );
    }

    #[test]
    fn actual_workspace_closes_active_localtx_journeys() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let closure = load_journey_closure(&root)?;
        let actual: BTreeSet<_> = closure
            .entries
            .iter()
            .map(|entry| entry.contract_id.clone())
            .collect();
        let governance = ContractGovernanceIr::load_consumer_workspace(&root)?;
        let expected = governance.read(|discovered| {
            Ok(discover_from_contracts(&root, discovered)?
                .into_iter()
                .map(|contract| contract.id)
                .collect::<BTreeSet<_>>())
        })?;
        assert_eq!(actual, expected);
        let generated: BTreeSet<_> = generated::http::LOCAL_TX_SPECS
            .iter()
            .map(|spec| spec.route.contract_id().to_owned())
            .collect();
        assert_eq!(
            actual, generated,
            "journeys must close the generated registry"
        );
        assert!(!actual.is_empty(), "LocalTx journey anti-vacuity");
        Ok(())
    }

    #[test]
    fn multiple_backend_profiles_in_one_test_function_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-shared-backend-profile-probes")?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let source = fs::read_to_string(&profile)?;
        fs::write(
            &profile,
            source.replacen(
                "        let _typed_enrollment = LOCALTX_BACKEND_PROFILE_DEMO_WRITE;",
                r#"        const LOCALTX_BACKEND_PROFILE_DEMO_WRITE_ALIAS: ::vocab::HttpRouteBinding<
            ::generated::http::demo_v1::write::RouteMarker,
            ::vocab::http::LocalTx,
        > = ::generated::http::demo_v1::write::ROUTE;
        let _typed_enrollment = LOCALTX_BACKEND_PROFILE_DEMO_WRITE;"#,
                1,
            ),
        )?;

        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::MultipleBackendProfilesInTest
                    && finding.detail.contains("tenant_scoped_uow_profile")
                    && finding
                        .detail
                        .contains("LOCALTX_BACKEND_PROFILE_DEMO_WRITE")
                    && finding
                        .detail
                        .contains("LOCALTX_BACKEND_PROFILE_DEMO_WRITE_ALIAS")
            }),
            "one test function must not lend the same probes to multiple backend profile markers: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn backend_profile_non_executable_test_attributes_are_rejected() -> anyhow::Result<()> {
        let cases = [
            (
                "ignored-test",
                "    #[tokio::test]\n    async fn tenant_scoped_uow_profile",
                "    #[ignore]\n    #[tokio::test]\n    async fn tenant_scoped_uow_profile",
                "#[ignore]",
            ),
            (
                "should-panic-test",
                "    #[tokio::test]\n    async fn tenant_scoped_uow_profile",
                "    #[should_panic]\n    #[tokio::test]\n    async fn tenant_scoped_uow_profile",
                "#[should_panic]",
            ),
            (
                "ignored-ancestor",
                "#[cfg(test)]\nmod tests {",
                "#[cfg(test)]\n#[ignore]\nmod tests {",
                "#[ignore]",
            ),
            (
                "should-panic-ancestor",
                "#[cfg(test)]\nmod tests {",
                "#[cfg(test)]\n#[should_panic]\nmod tests {",
                "#[should_panic]",
            ),
        ];
        let mut missing_rejections = Vec::new();

        for (name, needle, replacement, expected_detail) in cases {
            let temp = FixtureCopy::new(&format!("localtx-backend-profile-{name}"))?;
            let profile = temp.path.join("adapters/pg/src/lib.rs");
            let source = fs::read_to_string(&profile)?;
            fs::write(
                &profile,
                replace_exact_once(&source, needle, replacement, name)?,
            )?;

            let (_, findings) = check_fixture_root(&temp.path)?;
            if !findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenBackendProfileEvidence
                    && finding.detail.contains(expected_detail)
            }) {
                missing_rejections.push(format!("{name}: {findings:#?}"));
            }
        }

        assert!(
            missing_rejections.is_empty(),
            "non-executable backend profile evidence must fail closed:\n{}",
            missing_rejections.join("\n")
        );
        Ok(())
    }

    #[test]
    fn active_contract_without_backend_profile_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-missing-backend-profile")?;
        fs::write(temp.path.join("adapters/pg/src/lib.rs"), "")?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingBackendProfile),
            "an active LocalTx contract without real backend enrollment must fail: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn backend_profile_missing_required_probe_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-missing-backend-probe")?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let source = fs::read_to_string(&profile)?;
        fs::write(
            &profile,
            source.replacen(
                "::rss_conformance::localtx::assert_rollback(",
                "::rss_conformance::localtx::ignored_rollback(",
                1,
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingBackendProbe),
            "a txModel profile missing one required probe must fail: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn tenant_contract_cannot_enroll_repo_atomic_probe_set() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-wrong-backend-profile")?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let source = fs::read_to_string(&profile)?;
        fs::write(
            &profile,
            source
                .replacen(
                    "::rss_conformance::localtx::assert_rollback(",
                    "::rss_conformance::localtx::ignored_rollback(",
                    1,
                )
                .replacen(
                    "::rss_conformance::localtx::assert_rollback_failed_no_replay(",
                    "::rss_conformance::localtx::ignored_rollback_failed_no_replay(",
                    1,
                ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        let missing = findings
            .iter()
            .filter(|finding| finding.rule == Rule::MissingBackendProbe)
            .count();
        assert_eq!(
            missing, 2,
            "tenant-scoped-uow must not accept the smaller repo-atomic-cas probe set: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn repo_atomic_contract_derives_the_smaller_exact_profile() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-repo-atomic-profile")?;
        let manifest = temp.path.join("contracts/http/demo/v1/write/contract.toml");
        let source = fs::read_to_string(&manifest)?;
        fs::write(
            &manifest,
            source.replace(
                "txModel = \"tenant-scoped-uow\"",
                "txModel = \"repo-atomic-cas\"",
            ),
        )?;
        set_green_journey_to_repo_atomic(&temp.path)?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let source = fs::read_to_string(&profile)?;
        fs::write(
            &profile,
            source
                .replacen(
                    "::rss_conformance::localtx::assert_rollback(",
                    "::rss_conformance::localtx::ignored_rollback(",
                    1,
                )
                .replacen(
                    "::rss_conformance::localtx::assert_rollback_failed_no_replay(",
                    "::rss_conformance::localtx::ignored_rollback_failed_no_replay(",
                    1,
                ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    fn set_green_journey_to_repo_atomic(root: &Path) -> anyhow::Result<()> {
        for path in [
            "journeys/status-board.toml",
            "journeys/demo-write-localtx-journey.toml",
            "fixtures/demo-write-localtx.toml",
        ] {
            let path = root.join(path);
            fs::write(
                &path,
                fs::read_to_string(&path)?.replace(
                    "txModel = \"tenant-scoped-uow\"",
                    "txModel = \"repo-atomic-cas\"",
                ),
            )?;
        }
        let spec = root.join("journeys/demo-write-localtx-journey.toml");
        fs::write(
            &spec,
            fs::read_to_string(&spec)?
                .replace(
                    "\n[[scenarios]]\nkind = \"contention\"\napplicable = true\n",
                    "",
                )
                .replace(
                    "applicable = false\nreason = \"tenant-scoped-uow validates concurrent idempotent convergence, not CAS conflict\"",
                    "applicable = true",
                ),
        )?;
        let fixture = root.join("fixtures/demo-write-localtx.toml");
        fs::write(
            &fixture,
            fs::read_to_string(&fixture)?
                .replace("demo-write-contention", "demo-write-conflict")
                .replace("scenario = \"contention\"", "scenario = \"conflict\"")
                .replace(
                    "redactSentinels = [\"demo-contention\"]",
                    "redactSentinels = [\"demo-conflict\"]",
                ),
        )?;
        let runner = root.join(GREEN_JOURNEY_RUNNER_PATH);
        let source = replace_exact_once(
            &fs::read_to_string(&runner)?,
            "fixtures.take_case(\"demo-write-contention\")",
            "fixtures.take_case(\"demo-write-conflict\")",
            "repo-atomic journey runner case",
        )?;
        fs::write(
            &runner,
            replace_exact_once(
                &source,
                "cases.contention.id == \"demo-write-contention\"",
                "cases.contention.id == \"demo-write-conflict\"",
                "repo-atomic green observer case",
            )?,
        )?;
        Ok(())
    }

    #[test]
    fn unawaited_backend_probe_does_not_count() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-unawaited-backend-probe")?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let mut source = fs::read_to_string(&profile)?;
        let probe = source
            .find("::rss_conformance::localtx::assert_rollback(")
            .context("green rollback probe")?;
        let await_suffix = "\n        .await?;";
        let awaited = probe
            + source[probe..]
                .find(await_suffix)
                .context("green rollback await")?;
        source.replace_range(awaited..awaited + await_suffix.len(), ";");
        fs::write(&profile, source)?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::MissingBackendProbe && finding.detail.contains("rollback")
        }));
        Ok(())
    }

    #[test]
    fn backend_profile_must_come_from_an_adapter_provider() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-is-not-provider")?;
        let manifest = temp.path.join("crates/demo/Cargo.toml");
        let source = fs::read_to_string(&manifest)?;
        fs::write(
            &manifest,
            format!(
                "{source}\n[dev-dependencies]\nrss_conformance = {{ package = \"rss-conformance\", path = \"../conformance\" }}\ntestkit = {{ path = \"../testkit\" }}\n"
            ),
        )?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        let source = fs::read_to_string(&owner)?;
        fs::write(
            &owner,
            format!(
                "{source}\n#[cfg(test)] mod invalid_backend {{\n    #[test] fn profile() {{\n        const LOCALTX_BACKEND_PROFILE_INVALID: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE;\n        const LOCALTX_BACKEND_PROVIDER_INVALID: ::std::marker::PhantomData<(::generated::http::demo_v1::write::RouteMarker, InvalidProviderFixture)> = ::std::marker::PhantomData;\n        let _provider = InvalidProviderFixture::new();\n    }}\n}}\n"
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::UnexpectedBackendProfile && finding.detail.contains("adapters/*")
        }));
        let inventory = collect_fixture_inventory_under(&temp.path)?;
        let invalid = inventory.contracts[0]
            .backend_profiles
            .iter()
            .find(|profile| profile.provider() == "demo")
            .context("invalid non-adapter provider profile")?;
        assert!(!invalid.valid_provider());
        assert!(!invalid.complete());
        Ok(())
    }

    #[test]
    fn orphan_backend_profile_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-orphan-backend-profile")?;
        let profile = temp.path.join("adapters/pg/src/lib.rs");
        let source = fs::read_to_string(&profile)?;
        fs::write(
            &profile,
            source.replace("demo_v1::write", "demo_v1::orphan"),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::UnexpectedBackendProfile
                && finding.detail.contains("has no active LocalTx manifest")
        }));
        Ok(())
    }

    #[test]
    fn backend_profile_shards_cannot_aggregate_across_provider_fixtures() {
        let contract = Contract {
            id: "demo.write".to_string(),
            owner: "demo".to_string(),
            key: "demo_v1::write".to_string(),
            subject: "contracts/demo/v1/write/contract.toml".to_string(),
            valid_owner: true,
            tx_model: LocalTxModel::TenantScopedUow,
            boundary: LocalTxBoundary::SingleDomain,
            retry: LocalTxRetry::BoundedTransient,
            commit_unknown: LocalTxCommitUnknown::NotRetryable,
        };
        let enrollments = [
            BackendEnrollmentOccurrence {
                key: contract.key.clone(),
                provider: "pg".to_string(),
                provider_fixture: "FirstProvider".to_string(),
                path: "adapters/pg/src/first.rs".to_string(),
                probes: BTreeMap::from([
                    (BackendProbe::Commit, 1),
                    (BackendProbe::Rollback, 1),
                    (BackendProbe::RejectedNoWrite, 1),
                ]),
                carrier: None,
            },
            BackendEnrollmentOccurrence {
                key: contract.key.clone(),
                provider: "pg".to_string(),
                provider_fixture: "SecondProvider".to_string(),
                path: "adapters/pg/src/second.rs".to_string(),
                probes: BTreeMap::from([
                    (BackendProbe::RejectedNoWrite, 1),
                    (BackendProbe::TenantIsolation, 1),
                    (BackendProbe::RetryBoundary, 1),
                    (BackendProbe::CommitUnknownNoReplay, 1),
                    (BackendProbe::RollbackFailedNoReplay, 1),
                ]),
                carrier: None,
            },
        ];
        let providers = BTreeSet::from(["pg".to_string()]);
        let profiles = normalize_backend_profiles(&contract, &enrollments, &providers);
        assert_eq!(profiles.len(), 2);
        assert!(
            profiles
                .iter()
                .all(|profile| !profile.missing_probes.is_empty())
        );

        let mut same_fixture = enrollments.clone();
        same_fixture[1].provider_fixture = "FirstProvider".to_string();
        let profiles = normalize_backend_profiles(&contract, &same_fixture, &providers);
        assert_eq!(profiles.len(), 1, "same-fixture shards must aggregate");
        assert!(
            profiles[0].missing_probes.is_empty(),
            "same-fixture shards must close the required probe set"
        );
    }

    #[test]
    fn single_backend_profile_in_test_function_is_accepted() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    DemoProviderFixture,
                )> = ::std::marker::PhantomData;
                let fixture = DemoProviderFixture::from_unverified_for_test(&store);
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        let result = fixture.execute().await;
                        result
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        assert!(evidence.violation.is_none());
        let enrollments = evidence.enrollments;
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].key, "demo_v1::write");
        assert_eq!(enrollments[0].probes.get(&BackendProbe::Commit), Some(&1));
        Ok(())
    }

    #[test]
    fn backend_profile_bare_provider_reference_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    DemoProviderFixture,
                )> = ::std::marker::PhantomData;
                let fixture = DemoProviderFixture::new();
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        let _ = &fixture;
                        Ok::<(), ()>(())
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("a bare provider reference must fail closed"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        assert!(
            violation
                .detail
                .contains("drive its outcome through a method call")
        );
        Ok(())
    }

    #[test]
    fn backend_profile_discarded_provider_call_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    DemoProviderFixture,
                )> = ::std::marker::PhantomData;
                let fixture = DemoProviderFixture::new();
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        fixture.execute().await;
                        Ok::<(), ()>(())
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("a discarded provider call must fail closed"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        assert!(
            violation
                .detail
                .contains("drive its outcome through a method call")
        );
        Ok(())
    }

    #[test]
    fn backend_profile_free_function_provider_argument_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    DemoProviderFixture,
                )> = ::std::marker::PhantomData;
                let fixture = DemoProviderFixture::new();
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        execute_provider(&fixture).await
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("a free helper must not prove provider execution"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        Ok(())
    }

    #[test]
    fn backend_profile_unpolled_provider_future_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    DemoProviderFixture,
                )> = ::std::marker::PhantomData;
                let fixture = DemoProviderFixture::new();
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        async { fixture.execute().await };
                        Ok::<(), ()>(())
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("an unpolled provider future must fail closed"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        Ok(())
    }

    #[test]
    fn backend_profile_without_typed_provider_binding_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                ::rss_conformance::localtx::assert_commit().await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        assert!(
            evidence.enrollments.is_empty(),
            "a route marker without a typed provider fixture binding must not enroll"
        );
        Ok(())
    }

    #[test]
    fn backend_profile_shadow_constructor_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    crate::PgAuthAuditSink,
                )> = ::std::marker::PhantomData;
                let sink = fake::PgAuthAuditSink::from_unverified_for_test(&store);
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async { sink.append().await })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "postgres",
            "integration_tests.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("a shadow constructor must fail closed"))?;
        assert_eq!(violation.rule, Rule::MissingBackendProviderBinding);
        assert!(violation.detail.contains("crate::PgAuthAuditSink"));
        assert!(violation.detail.contains("fake::PgAuthAuditSink"));
        Ok(())
    }

    #[test]
    fn backend_profile_nested_constructor_bait_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    crate::PgAuthAuditSink,
                )> = ::std::marker::PhantomData;
                let sink = {
                    let _bait = crate::PgAuthAuditSink::new();
                    fake::PgAuthAuditSink::new()
                };
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async { sink.append().await })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "postgres",
            "integration_tests.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("nested constructor bait must fail closed"))?;
        assert_eq!(violation.rule, Rule::MissingBackendProviderBinding);
        Ok(())
    }

    #[test]
    fn backend_profile_synthetic_action_is_rejected() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_AUDIT_LIST_TENANT_ENTRIES: ::vocab::HttpRouteBinding<
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_AUDIT_LIST_TENANT_ENTRIES: ::std::marker::PhantomData<(
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                    crate::PgAuthAuditSink,
                )> = ::std::marker::PhantomData;
                let _sink = crate::PgAuthAuditSink::new();
                ::rss_conformance::localtx::assert_commit(
                    ::rss_conformance::localtx::CommitCase::new(|| async {
                        Err(AuditLocalTxProfileError::synthetic())
                    })
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "postgres",
            "integration_tests.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("a synthetic provider action must fail closed"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        assert!(violation.detail.contains("provider-bound action"));
        Ok(())
    }

    #[test]
    fn backend_profile_observer_binding_does_not_count() -> anyhow::Result<()> {
        let function: ItemFn = syn::parse_str(
            r#"#[tokio::test]
            async fn profile() -> Result<(), ()> {
                const LOCALTX_BACKEND_PROFILE_DEMO_WRITE: ::vocab::HttpRouteBinding<
                    ::generated::http::demo_v1::write::RouteMarker,
                    ::vocab::http::LocalTx,
                > = ::generated::http::demo_v1::write::ROUTE;
                const LOCALTX_BACKEND_PROVIDER_DEMO_WRITE: ::std::marker::PhantomData<(
                    ::generated::http::demo_v1::write::RouteMarker,
                    crate::DemoProvider,
                )> = ::std::marker::PhantomData;
                let provider = crate::DemoProvider::new();
                ::rss_conformance::localtx::assert_rejected_no_write(
                    ::rss_conformance::localtx::RejectedNoWriteCase::new(
                        || async { Err::<(), ()>(()) },
                        || async { provider.snapshot().await },
                    )
                ).await?;
                Ok(())
            }"#,
        )?;
        let evidence = backend_enrollments_in_test(
            &function.block,
            &Resolver::default(),
            "pg",
            "probe.rs",
            "profile",
        );
        let violation = evidence
            .violation
            .ok_or_else(|| anyhow!("observer-only provider use must fail closed"))?;
        assert_eq!(violation.rule, Rule::ForbiddenBackendProfileEvidence);
        assert!(violation.detail.contains("provider-bound action"));
        Ok(())
    }

    #[test]
    fn green_fixture_is_a_compiling_workspace() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-green-compile")?;
        let output = temp.cargo_check()?;
        assert!(
            output.status.success(),
            "green fixture must compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn endpoint_construction_without_mount_is_rejected() -> anyhow::Result<()> {
        for source in [
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    );
}
"#,
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn dead_helper() {
    let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    );
}
fn init(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| Ok(rb));
}
"#,
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| {
        let _ = ::httpserve::GeneratedPrimaryEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            handler,
        );
        Ok(rb)
    });
}
"#,
            r#"struct FakeMount;
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init(fake: FakeMount) {
    fake.mount(::httpserve::GeneratedPrimaryEndpoint::new(
        ::generated::http::demo_v1::write::ROUTE,
        handler,
    ));
}
"#,
        ] {
            let temp = FixtureCopy::new("localtx-unmounted-endpoint")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                &owner,
                format!(
                    "{source}\n#[test] fn covered() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n"
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "unmounted endpoint construction must not close coverage: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn route_mount_outside_canonical_domain_init_is_rejected() -> anyhow::Result<()> {
        for source in [
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn disconnected(reg: &mut ::httpserve::Registry) {
    reg.route_group(|rb| {
        Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            handler,
        )))
    });
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::httpserve::Registry) {
        reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        let disconnected = || {
            reg.route_group(|rb| {
                Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                    ::generated::http::demo_v1::write::ROUTE,
                    |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
                )))
            });
        };
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        let disconnected = || reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
"#,
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        match true {
            true => reg.route_group(|rb| {
                Ok(rb.mount(::httpserve::GeneratedPrimaryEndpoint::new(
                    ::generated::http::demo_v1::write::ROUTE,
                    |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
                )))
            }),
            false => (),
        };
    }
}
"#,
        ] {
            let temp = FixtureCopy::new("localtx-non-domain-route")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    "{source}\n#[test] fn covered() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n"
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "non-Domain or unreachable mount must not close coverage: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn missing_route_and_duplicate_marker_are_rejected() -> anyhow::Result<()> {
        let missing = FixtureCopy::new("localtx-missing-route")?;
        fs::write(
            missing.path.join("crates/demo/src/lib.rs"),
            "#[test] fn covered() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, route_findings) = check_fixture_root(&missing.path)?;
        assert!(
            route_findings
                .iter()
                .any(|f| f.rule == Rule::MissingRouteBinding)
        );
        let duplicate = FixtureCopy::new("localtx-duplicate-marker")?;
        let owner = duplicate.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[test] fn second() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, marker_findings) = check_fixture_root(&duplicate.path)?;
        assert!(
            marker_findings
                .iter()
                .any(|f| f.rule == Rule::DuplicateTestMarker)
        );
        Ok(())
    }

    #[test]
    fn invalid_domain_owner_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-invalid-domain-owner")?;
        let manifest = temp.path.join("contracts/http/demo/v1/write/contract.toml");
        fs::write(
            &manifest,
            fs::read_to_string(&manifest)?.replace("owner = \"demo\"", "owner = \"_framework\""),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InvalidDomainOwner),
            "framework owner must emit InvalidDomainOwner: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn path_dependency_source_is_rejected_even_when_root_matches() -> anyhow::Result<()> {
        let package_relative = PathBuf::from("crates/generated");
        let member = WorkspaceCrate {
            name: "demo".to_owned(),
            relative: PathBuf::from("crates/demo"),
            root: PathBuf::from("/tmp/unused-demo-root"),
            targets: Vec::new(),
            normal_dependencies: BTreeMap::from([(
                "generated".to_owned(),
                DependencyRef {
                    package: "generated".to_owned(),
                    path: Some(PathBuf::from("/tmp/unused-generated-root")),
                    source: DependencySource::Path {
                        repo_relative_root: package_relative.clone(),
                    },
                    unconditional: true,
                },
            )]),
            dev_dependencies: BTreeMap::new(),
            normal_test_dependencies: BTreeMap::new(),
            dev_test_dependencies: BTreeMap::new(),
        };
        let expected_packages = BTreeMap::from([("generated".to_owned(), package_relative)]);
        let error = validate_dependency(&member, "generated", false, &expected_packages)
            .expect_err("DependencySource::Path must fail-closed even when root matches");
        assert!(
            format!("{error:#}").contains("workspace"),
            "path source rejection must name workspace requirement: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn comments_strings_and_non_test_functions_are_not_markers() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-marker")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?
                .replace("#[cfg(test)] mod tests {", "mod tests {")
                .replace("#[test] fn covered()", "fn covered()"),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn generated_evidence_owner_and_malformed_source_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-closure")?;
        let command_facts = fixture_command_facts(&temp.path);
        let facts = command_facts.get()?;
        // Injecting an empty compiled exact-set reports MissingGeneratedSpec without source registry.
        let (_, findings) =
            collect_fixture_inventory_with_keys(&temp.path, facts, &BTreeSet::new())?.into_gate();
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingGeneratedSpec),
            "{findings:#?}"
        );

        let manifest = temp.path.join("contracts/http/demo/v1/write/contract.toml");
        let valid_manifest = fs::read_to_string(&manifest)?;
        fs::write(
            &manifest,
            valid_manifest.replace("owner = \"demo\"", "owner = \"../demo\""),
        )?;
        let owner_error = check_fixture_root(&temp.path)
            .expect_err("unsafe owner must fail during manifest-backed owner promotion");
        assert!(
            format!("{owner_error:#}").contains("contract owner must be a canonical domain name")
        );

        fs::write(&manifest, valid_manifest)?;
        let generated = temp.path.join("generated/src/http/demo_v1.rs");
        fs::write(&generated, "this is not Rust")?;
        let error = match check_fixture_root(&temp.path) {
            Ok(_) => bail!("malformed Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn missing_and_unexpected_generated_entries_are_reported() -> anyhow::Result<()> {
        let missing = FixtureCopy::new("localtx-missing-generated")?;
        let command_facts = fixture_command_facts(&missing.path);
        let facts = command_facts
            .get()
            .map_err(|error| sanitized(&missing.path, error))?;
        let (_, findings) =
            collect_fixture_inventory_with_keys(&missing.path, facts, &BTreeSet::new())?
                .into_gate();
        assert!(
            findings.iter().any(
                |f| f.rule == Rule::MissingGeneratedSpec && f.detail.contains("LOCAL_TX_SPECS")
            ),
            "{findings:#?}"
        );

        let unexpected = FixtureCopy::new("localtx-unexpected-generated")?;
        let command_facts = fixture_command_facts(&unexpected.path);
        let facts = command_facts
            .get()
            .map_err(|error| sanitized(&unexpected.path, error))?;
        let mut keys = fixture_compiled_local_tx_keys()?;
        keys.insert("demo_v1::orphan".to_owned());
        let (_, findings) =
            collect_fixture_inventory_with_keys(&unexpected.path, facts, &keys)?.into_gate();
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::UnexpectedGeneratedSpec && f.detail.contains("demo_v1::orphan")
            }),
            "{findings:#?}"
        );

        // equal-count-wrong-set: same cardinality, different membership
        let wrong_set = FixtureCopy::new("localtx-equal-count-wrong-set")?;
        let command_facts = fixture_command_facts(&wrong_set.path);
        let facts = command_facts
            .get()
            .map_err(|error| sanitized(&wrong_set.path, error))?;
        let keys = BTreeSet::from(["demo_v1::orphan".to_owned()]);
        let (_, findings) =
            collect_fixture_inventory_with_keys(&wrong_set.path, facts, &keys)?.into_gate();
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingGeneratedSpec),
            "missing real key: {findings:#?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::UnexpectedGeneratedSpec),
            "extra orphan key: {findings:#?}"
        );

        let ignored = FixtureCopy::new("localtx-ignored-draft")?;
        let draft = ignored.path.join("contracts/http/demo/v1/draft");
        fs::create_dir_all(&draft)?;
        fs::write(
            draft.join("contract.toml"),
            fs::read_to_string(
                ignored
                    .path
                    .join("contracts/http/demo/v1/write/contract.toml"),
            )?
            .replace("id = \"demo.write\"", "id = \"demo.draft\"")
            .replace("lifecycle = \"active\"", "lifecycle = \"draft\""),
        )?;
        for schema in ["request.schema.json", "response.schema.json"] {
            fs::copy(
                ignored
                    .path
                    .join("contracts/http/demo/v1/write")
                    .join(schema),
                draft.join(schema),
            )?;
        }
        let (summary, findings) = check_fixture_root(&ignored.path)?;
        assert_eq!(summary, "1 active LocalTx HTTP contract(s) covered");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn compiled_local_tx_keys_reject_duplicate_mount_keys() {
        let err = compiled_local_tx_keys_from_mount_keys(["demo_v1::write", "demo_v1::write"])
            .expect_err("duplicate mount keys must fail closed");
        assert!(
            format!("{err:#}").contains("duplicate mount_key `demo_v1::write`"),
            "{err:#}"
        );
    }
    #[test]
    fn orphan_marker_and_non_utf8_source_fail_closed() -> anyhow::Result<()> {
        let orphan = FixtureCopy::new("localtx-orphan-marker")?;
        let owner = orphan.path.join("crates/demo/src/lib.rs");
        let source = fs::read_to_string(&owner)?;
        fs::write(
            &owner,
            format!(
                "{source}\n#[cfg(test)] mod orphan_marker {{\n    #[test] fn covered() {{\n        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::orphan::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::orphan::ROUTE;\n    }}\n}}\n"
            ),
        )?;
        let (_, findings) = check_fixture_root(&orphan.path)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::UnexpectedTestMarker && finding.detail.contains("demo_v1::orphan")
        }));

        let non_utf8 = FixtureCopy::new("localtx-non-utf8")?;
        let generated = non_utf8.path.join("generated/src/http/demo_v1.rs");
        fs::write(&generated, [0xff, 0xfe])?;
        let error = match check_fixture_root(&non_utf8.path) {
            Ok(_) => bail!("non-UTF-8 Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(non_utf8.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn actual_workspace_has_non_empty_complete_localtx_closure() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = workspace_command_facts(&root);
        let inventory = collect_workspace_inventory(&root, command_facts.get()?)?;
        let (summary, findings) = inventory.into_gate();
        assert!(!summary.starts_with("0 active"), "anti-vacuity: {summary}");
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn actual_workspace_has_verified_localtx_evidence_exact_set() -> anyhow::Result<()> {
        let verified = {
            let root = crate::workspace_root()?;
            let command_facts = workspace_command_facts(&root);
            verify_required_evidence_set(&root, command_facts.get()?)
        }?;
        let expected = ["audit.list-tenant-entries", "settings.secret-publish"];
        assert_eq!(verified.active_contract_ids(), expected);
        assert_eq!(verified.journey_contract_ids(), expected);
        assert_eq!(verified.backend_profile_contract_ids(), expected);
        assert_eq!(verified.contract_count(), expected.len());
        Ok(())
    }

    #[test]
    fn required_evidence_counts_reject_wrong_carrier_and_distinct_profile_gap() -> anyhow::Result<()>
    {
        fn clone_profile(profile: &LocalTxProofBackendProfile) -> LocalTxProofBackendProfile {
            LocalTxProofBackendProfile {
                provider: profile.provider.clone(),
                fixture: profile.fixture.clone(),
                valid_provider: profile.valid_provider,
                sources: profile.sources.clone(),
                required_probes: profile.required_probes.clone(),
                observed_probes: profile.observed_probes.clone(),
                missing_probes: profile.missing_probes.clone(),
                carrier: profile.carrier.clone(),
            }
        }

        let root = crate::workspace_root()?;
        let selection = release_check_integration_selection()?;
        let carrier = crate::integration_shards::localtx_backend_execution_unit(&selection)?;

        let mut wrong_carrier =
            collect_workspace_inventory(&root, workspace_command_facts(&root).get()?)?;
        wrong_carrier.contracts[0].backend_profiles[0].provider = "wrong-carrier".to_string();
        let Err(error) = required_evidence_contract_sets(&wrong_carrier, &carrier) else {
            bail!("a profile outside the typed execution carrier must fail closed");
        };
        assert!(format!("{error:#}").contains("wrong-carrier"));

        let mut profile_gap =
            collect_workspace_inventory(&root, workspace_command_facts(&root).get()?)?;
        let active_len = profile_gap.contracts.len();
        let duplicate = clone_profile(&profile_gap.contracts[0].backend_profiles[0]);
        profile_gap.contracts[0].backend_profiles.push(duplicate);
        profile_gap.contracts[1].backend_profiles.clear();
        let raw_complete_profiles = profile_gap
            .contracts
            .iter()
            .flat_map(|contract| &contract.backend_profiles)
            .filter(|profile| profile.complete())
            .count();
        assert_eq!(
            raw_complete_profiles, active_len,
            "synthetic fixture must preserve a misleading raw profile count equal to active.len()"
        );
        let sets = required_evidence_contract_sets(&profile_gap, &carrier)?;
        assert_ne!(
            sets.backend_profiles, sets.active,
            "distinct-contract profile gap must diverge from the active set"
        );
        assert!(verify_required_evidence_inventory(&profile_gap, &carrier).is_err());
        Ok(())
    }

    #[test]
    fn required_evidence_exact_set_rejects_equal_count_wrong_set() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let selection = release_check_integration_selection()?;
        let carrier = crate::integration_shards::localtx_backend_execution_unit(&selection)?;
        let inventory = collect_workspace_inventory(&root, workspace_command_facts(&root).get()?)?;
        let mut sets = required_evidence_contract_sets(&inventory, &carrier)?;
        let original_count = sets.active.len();
        ensure!(
            original_count > 0,
            "workspace LocalTx set must be non-empty"
        );
        let replaced = sets.journeys.iter().next().context("journey set")?.clone();
        sets.journeys.remove(&replaced);
        sets.journeys
            .insert("forged.equal-count-wrong-set".to_owned());
        assert_eq!(sets.journeys.len(), original_count);
        assert_ne!(sets.journeys, sets.active);
        let Err(error) = verify_required_evidence_sets(sets) else {
            bail!("equal-count wrong journey set must fail closed");
        };
        assert!(
            format!("{error:#}").contains("extra_in_journeys=[\"forged.equal-count-wrong-set\"]"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn required_evidence_exact_set_accepts_synchronized_shrink_without_expected_n()
    -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let selection = release_check_integration_selection()?;
        let carrier = crate::integration_shards::localtx_backend_execution_unit(&selection)?;
        let mut inventory =
            collect_workspace_inventory(&root, workspace_command_facts(&root).get()?)?;
        let original = verify_required_evidence_inventory(&inventory, &carrier)?;
        ensure!(
            original.contract_count() > 1,
            "workspace must have more than one LocalTx contract to shrink"
        );
        inventory.contracts.remove(0);
        let shrunk = verify_required_evidence_inventory(&inventory, &carrier)?;
        assert_eq!(shrunk.contract_count(), original.contract_count() - 1);
        assert_eq!(shrunk.active_contract_ids(), shrunk.journey_contract_ids());
        assert_eq!(
            shrunk.active_contract_ids(),
            shrunk.backend_profile_contract_ids()
        );
        Ok(())
    }

    #[test]
    fn required_evidence_backend_profiles_reject_noncanonical_execution_carriers()
    -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let selection = release_check_integration_selection()?;
        let carrier = crate::integration_shards::localtx_backend_execution_unit(&selection)?;
        let mut inventory =
            collect_workspace_inventory(&root, workspace_command_facts(&root).get()?)?;
        let canonical = inventory.contracts[0].backend_profiles[0]
            .carrier
            .clone()
            .context("workspace backend profile carrier")?;

        let mut cases = Vec::new();

        let mut unregistered_target = canonical.clone();
        unregistered_target.target = "unregistered-localtx-profile".to_string();
        cases.push(("same-package unregistered target", unregistered_target));

        let mut wrong_kind = canonical.clone();
        wrong_kind.kind = CargoTargetKind::Test;
        cases.push(("wrong target kind", wrong_kind));

        let mut wrong_required_feature = canonical.clone();
        wrong_required_feature
            .required_features
            .insert("never-enabled-by-postgres-domain".to_string());
        cases.push(("wrong required feature", wrong_required_feature));

        let mut wrong_target_root = canonical.clone();
        wrong_target_root.target_root =
            "adapters/postgres/tests/unregistered_localtx_profile.rs".to_string();
        cases.push(("wrong target root", wrong_target_root));

        for (name, forged) in cases {
            inventory.contracts[0].backend_profiles[0].carrier = Some(forged);
            assert!(
                required_evidence_contract_sets(&inventory, &carrier).is_err(),
                "{name} must not close required LocalTx backend evidence"
            );
            inventory.contracts[0].backend_profiles[0].carrier = Some(canonical.clone());
        }

        let target_index = inventory
            .cargo_targets
            .iter()
            .position(|target| target == &canonical)
            .context("canonical backend Cargo target")?;
        let mut unmodeled_feature = canonical.clone();
        unmodeled_feature
            .required_features
            .insert("never-enabled-by-postgres-domain".to_string());
        inventory.cargo_targets[target_index] = unmodeled_feature.clone();
        inventory.contracts[0].backend_profiles[0].carrier = Some(unmodeled_feature);
        let Err(error) = required_evidence_contract_sets(&inventory, &carrier) else {
            bail!("unmodeled target feature activation must fail closed");
        };
        assert!(format!("{error:#}").contains("does not model target feature activation"));
        Ok(())
    }

    #[test]
    fn inventory_and_gate_share_route_test_profile_and_probe_findings() -> anyhow::Result<()> {
        type FixtureMutation = fn(&Path) -> anyhow::Result<()>;
        let cases: [(&str, Rule, FixtureMutation); 4] = [
            ("route", Rule::MissingRouteBinding, |root| {
                fs::write(
                    root.join("crates/demo/src/lib.rs"),
                    "#[test] fn covered() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
                )?;
                Ok(())
            }),
            ("test", Rule::MissingTestMarker, |root| {
                let source = fs::read_to_string(root.join("crates/demo/src/lib.rs"))?;
                fs::write(
                    root.join("crates/demo/src/lib.rs"),
                    source.replace("#[test] fn covered()", "fn covered()"),
                )?;
                Ok(())
            }),
            ("profile", Rule::MissingBackendProfile, |root| {
                fs::write(root.join("adapters/pg/src/lib.rs"), "")?;
                Ok(())
            }),
            ("probe", Rule::MissingBackendProbe, |root| {
                let path = root.join("adapters/pg/src/lib.rs");
                let source = fs::read_to_string(&path)?;
                fs::write(
                    path,
                    source.replacen(
                        "::rss_conformance::localtx::assert_rollback(",
                        "::rss_conformance::localtx::ignored_rollback(",
                        1,
                    ),
                )?;
                Ok(())
            }),
        ];
        for (name, expected_rule, mutate) in cases {
            let temp = FixtureCopy::new(&format!("localtx-inventory-parity-{name}"))?;
            mutate(&temp.path)?;
            let inventory = collect_fixture_inventory_under(&temp.path)?;
            let inventory_findings = inventory.findings();
            let (_, gate_findings) = check_fixture_root(&temp.path)?;
            assert_eq!(inventory_findings, gate_findings, "{name} finding parity");
            assert!(
                inventory_findings
                    .iter()
                    .any(|finding| finding.rule == expected_rule),
                "{name} fixture omitted {expected_rule:?}: {inventory_findings:#?}"
            );
            match expected_rule {
                Rule::MissingRouteBinding => assert!(!inventory.contracts[0].route.complete),
                Rule::MissingTestMarker => assert!(!inventory.contracts[0].test.complete),
                Rule::MissingBackendProfile => {
                    assert!(inventory.contracts[0].backend_profiles.is_empty());
                }
                Rule::MissingBackendProbe => assert!(
                    inventory.contracts[0]
                        .backend_profiles
                        .iter()
                        .any(|profile| !profile.missing_probes.is_empty())
                ),
                _ => unreachable!(),
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn dangling_and_intermediate_symlinks_are_structural_errors_without_absolute_paths()
    -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("localtx-component-symlink");
        fs::create_dir_all(root.join("real"))?;
        fs::write(root.join("real/evidence.rs"), "")?;

        let dangling = root.join("dangling.rs");
        symlink(root.join("missing.rs"), &dangling)?;
        let error = required_error(reject_symlinks(&root, &dangling), "dangling symlink")?;
        let diagnostic = format!("{:#}", sanitized(&root, error));
        assert!(diagnostic.contains("symlink evidence is not allowed"));
        assert!(!diagnostic.contains(root.to_string_lossy().as_ref()));

        let intermediate = root.join("alias");
        symlink(root.join("real"), &intermediate)?;
        let nested = intermediate.join("evidence.rs");
        let error = required_error(
            reject_symlinks(&root, &nested),
            "intermediate symlink inside workspace",
        )?;
        let diagnostic = format!("{:#}", sanitized(&root, error));
        assert!(diagnostic.contains("symlink evidence is not allowed"));
        assert!(!diagnostic.contains(root.to_string_lossy().as_ref()));
        assert!(reject_symlinks(&root, &root.join("absent.rs")).is_ok());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn findings_are_stably_sorted_and_workspace_relative() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-sorted-findings")?;
        fs::write(temp.path.join("crates/demo/src/lib.rs"), "")?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        let lines: Vec<_> = findings.iter().map(diagnostic::format_finding).collect();
        let mut sorted = lines.clone();
        sorted.sort();
        assert_eq!(lines, sorted);
        assert!(
            lines
                .iter()
                .all(|line| !line.contains(env!("CARGO_MANIFEST_DIR")))
        );
        Ok(())
    }

    #[test]
    fn report_rule_wire_names_are_exhaustive_unique_and_schema_stable() {
        let expected = [
            "InvalidDomainOwner",
            "MissingOwnerCrate",
            "MissingGeneratedSpec",
            "UnexpectedGeneratedSpec",
            "MissingRouteBinding",
            "MissingTestMarker",
            "DuplicateTestMarker",
            "UnexpectedTestMarker",
            "MissingBackendProfile",
            "MissingBackendProviderBinding",
            "ForbiddenBackendProfileEvidence",
            "MissingBackendProbe",
            "MultipleBackendProfilesInTest",
            "UnexpectedBackendProfile",
            "OpaqueSourceScope",
        ];
        let actual = Rule::ALL.map(Rule::report_wire);
        assert_eq!(
            actual, expected,
            "wire renames require a schema-version review"
        );
        assert_eq!(
            actual.into_iter().collect::<BTreeSet<_>>().len(),
            Rule::ALL.len(),
            "report rule wire names must remain unique"
        );
    }

    #[test]
    fn owner_must_be_a_real_workspace_member_crate() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-member")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?.replace("\"crates/demo\", ", ""),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingOwnerCrate),
            "directory-shaped decoys must not count as owner crates: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn markers_are_global_and_must_belong_to_the_owner() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-wrong-owner-marker")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            replace_exact_once(
                &fs::read_to_string(&workspace)?,
                ", \"generated\", \"journeys\"]",
                ", \"generated\", \"journeys\", \"crates/other\"]",
                "enroll wrong-owner marker fixture",
            )?,
        )?;
        fs::create_dir_all(temp.path.join("crates/other/src"))?;
        fs::write(
            temp.path.join("crates/other/Cargo.toml"),
            "[package]\nname = \"other\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dev-dependencies]\ngenerated = { path = \"../../generated\" }\nvocab = { path = \"../vocab\" }\n",
        )?;
        fs::write(
            temp.path.join("crates/other/src/lib.rs"),
            "#[test] fn wrong_owner() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings.iter().any(|finding| {
                matches!(
                    finding.rule,
                    Rule::DuplicateTestMarker | Rule::UnexpectedTestMarker
                ) && finding.subject.contains("crates/other/src/lib.rs")
            }),
            "wrong-owner duplicate must name its source file: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn local_same_named_types_and_generated_module_are_not_canonical_evidence() -> anyhow::Result<()>
    {
        let temp = FixtureCopy::new("localtx-canonical-symbols")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn external_cfg_test_module_route_is_not_production_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-external-test-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            "#[cfg(test)] mod tests;\n",
        )?;
        fs::write(
            temp.path.join("crates/demo/src/tests.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn cfg_test_only_boolean_semantics_are_fail_closed() {
        let not_test: Attribute = syn::parse_quote!(#[cfg(not(test))]);
        let mixed_any: Attribute = syn::parse_quote!(#[cfg(any(test, feature = "prod"))]);
        let test_all: Attribute = syn::parse_quote!(#[cfg(all(test, feature = "fixture"))]);
        let not_test = Reachability::BOTH.with_attrs(&[not_test]);
        assert!(not_test.prod);
        assert!(!not_test.test);
        let mixed_any = Reachability::BOTH.with_attrs(&[mixed_any]);
        assert!(!mixed_any.prod);
        assert!(mixed_any.test);
        let test_all = Reachability::BOTH.with_attrs(&[test_all]);
        assert!(!test_all.prod);
        assert!(!test_all.test);
    }

    #[test]
    fn same_named_handler_in_another_module_cannot_lend_its_marker() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-handler-identity")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
mod wrong { pub fn handler() {} }
mod right {
    pub fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
}
fn init() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, wrong::handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_source_file_is_rejected_fail_closed() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;

        let temp = FixtureCopy::new("localtx-symlink")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        let outside = crate::testutil::unique_tmp("localtx-outside").with_extension("rs");
        fs::write(&outside, fs::read_to_string(&owner)?)?;
        fs::remove_file(&owner)?;
        symlink(&outside, &owner)?;
        let result = check_fixture_root(&temp.path);
        let _ = fs::remove_file(outside);
        assert!(result.is_err(), "symlinked evidence must fail closed");
        Ok(())
    }

    #[test]
    fn duplicate_marker_diagnostic_names_marker_file() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-duplicate-diagnostic")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[test] fn second() {{ const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }}\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        let duplicate = findings
            .iter()
            .find(|finding| finding.rule == Rule::DuplicateTestMarker)
            .ok_or_else(|| anyhow!("duplicate marker finding is missing"))?;
        assert_eq!(duplicate.subject, "crates/demo/src/lib.rs");
        Ok(())
    }

    #[test]
    fn orphan_rust_file_is_not_reachable_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-orphan-rust")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        fs::write(
            temp.path.join("crates/demo/src/orphan.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn path_attribute_propagates_external_test_scope() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-path-test-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            "#[cfg(test)]\n#[path = \"bait.rs\"]\nmod tests;\n",
        )?;
        fs::write(
            temp.path.join("crates/demo/src/bait.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn bait() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn block_local_canonical_aliases_are_supported() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-block-alias")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        reg.route_group(|rb| {
            use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
            use ::httpserve::GeneratedPrimaryEndpoint as Endpoint;
            let endpoint = Endpoint::new(WRITE_ROUTE, handler);
            let _ = rb.mount(endpoint);
            Ok(rb)
        });
    }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn renamed_fake_canonical_roots_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-renamed-roots")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use crate::fake_generated as generated;
use crate::fake_httpserve as httpserve;
use crate::fake_vocab as vocab;
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn macro_defined_canonical_shadow_is_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-macro-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
macro_rules! fake_roots { () => {
    mod vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
    mod httpserve {
        pub struct ContractMarker<T>(core::marker::PhantomData<T>);
        pub struct GeneratedEndpoint;
        impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
    }
    mod generated { pub mod http { pub mod demo_v1 { pub mod write {
        pub struct RouteMarker;
        pub const ROUTE: () = ();
    } } } }
}; }
fake_roots!();
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn extern_crate_self_canonical_shadows_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-extern-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
extern crate self as generated;
extern crate self as httpserve;
extern crate self as vocab;
pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>);
pub struct ContractMarker<T>(core::marker::PhantomData<T>);
pub struct GeneratedEndpoint;
impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } }
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn block_local_fake_root_shadows_are_rejected() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-block-shadow")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
fn handler(_: fake_httpserve::ContractMarker<fake_generated::http::demo_v1::write::RouteMarker>) {}
fn init() {
    use crate::fake_generated as generated;
    use crate::fake_httpserve as httpserve;
    httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler);
}
#[test] fn covered() {
    use crate::fake_generated as generated;
    use crate::fake_vocab as vocab;
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn markers_in_non_domain_workspace_members_are_global() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-adapter-marker")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            replace_exact_once(
                &fs::read_to_string(&workspace)?,
                ", \"generated\", \"journeys\"]",
                ", \"generated\", \"journeys\", \"adapters/other\"]",
                "enroll non-domain marker fixture",
            )?,
        )?;
        fs::create_dir_all(temp.path.join("adapters/other/src"))?;
        fs::write(
            temp.path.join("adapters/other/Cargo.toml"),
            "[package]\nname = \"other-adapter\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dev-dependencies]\ngenerated = { path = \"../../generated\" }\nvocab = { path = \"../../crates/vocab\" }\n",
        )?;
        fs::write(
            temp.path.join("adapters/other/src/lib.rs"),
            "#[test] fn wrong_owner() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::DuplicateTestMarker
                    && finding.subject == "adapters/other/src/lib.rs"
            }),
            "adapter marker must enter global exactly-one accounting: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn owner_path_basename_must_equal_domain_and_package() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-path")?;
        fs::rename(
            temp.path.join("crates/demo"),
            temp.path.join("crates/decoy"),
        )?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?.replace("crates/demo", "crates/decoy"),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingOwnerCrate));
        Ok(())
    }

    #[test]
    fn nested_handler_cannot_lend_module_level_identity() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-nested-handler")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
use ::generated::http::demo_v1::write::ROUTE as WRITE_ROUTE;
fn handler() {}
fn hidden() {
    fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
    let _ = handler;
}
fn init() { let _ = httpserve::GeneratedEndpoint::new(WRITE_ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn owner_parse_errors_never_leak_absolute_temp_paths() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-owner-parse-redaction")?;
        fs::write(temp.path.join("crates/demo/src/lib.rs"), "not valid Rust")?;
        let error = match check_fixture_root(&temp.path) {
            Ok(_) => bail!("malformed owner Rust must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn bare_noncanonical_renames_shadow_all_protected_roots() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-bare-renames")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
mod fake_vocab { pub struct HttpRouteBinding<T>(core::marker::PhantomData<T>); }
mod fake_httpserve {
    pub struct ContractMarker<T>(core::marker::PhantomData<T>);
    pub struct GeneratedEndpoint;
    impl GeneratedEndpoint { pub fn new<A, B>(_: A, _: B) {} }
}
mod fake_generated { pub mod http { pub mod demo_v1 { pub mod write {
    pub struct RouteMarker;
    pub const ROUTE: () = ();
} } } }
use fake_generated as generated;
use fake_httpserve as httpserve;
use fake_vocab as vocab;
fn handler(_: httpserve::ContractMarker<generated::http::demo_v1::write::RouteMarker>) {}
fn init() { httpserve::GeneratedEndpoint::new(generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker, vocab::http::LocalTx> =
        generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn reachable_include_macro_is_rejected_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-include")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!("{}\ninclude!(\"extra.rs\");\n", fs::read_to_string(&owner)?),
        )?;
        fs::write(
            temp.path.join("crates/demo/src/extra.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn unknown_empty_item_macro_is_rejected_fail_closed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-unknown-macro")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "unknown_external_macro!();\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn disabled_cfg_cannot_supply_route_or_marker_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-disabled-cfg")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[cfg(any())]
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
#[cfg(any())]
fn init() { let _ = httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[cfg(any())]
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn disabled_same_named_handler_cannot_lend_identity() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-disabled-handler")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            r#"
#[cfg(any())]
fn handler(_: httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn handler() {}
fn init() { let _ = httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn aliased_test_marker_is_not_the_canonical_syntax() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-marker-alias")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "const _: ::vocab::HttpRouteBinding<\n            ::generated::http::demo_v1::write::RouteMarker,\n            ::vocab::http::LocalTx,\n        > =\n            ::generated::http::demo_v1::write::ROUTE;",
                "use ::generated::http::demo_v1::write::{ROUTE as R, RouteMarker as M};\n        use ::vocab::HttpRouteBinding as B;\n        const _: B<M, ::vocab::http::LocalTx> = R;",
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn path_attribute_is_relative_to_current_source_directory() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-path-source-dir")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!("{}\nmod outer;\n", fs::read_to_string(&owner)?),
        )?;
        fs::write(
            temp.path.join("crates/demo/src/outer.rs"),
            "#[cfg(test)]\n#[path = \"bait.rs\"]\nmod tests;\n",
        )?;
        fs::write(temp.path.join("crates/demo/src/bait.rs"), "")?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn absolute_workspace_member_error_is_redacted() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-absolute-member")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            format!(
                "[workspace]\nresolver = \"2\"\nmembers = [\"crates/demo\", \"{}\"]\n",
                temp.path.join("outside").display()
            ),
        )?;
        let error = match check_fixture_root(&temp.path) {
            Ok(_) => bail!("absolute workspace member must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn absolute_module_path_error_is_redacted() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-absolute-module")?;
        fs::write(
            temp.path.join("crates/demo/src/lib.rs"),
            format!(
                "#[path = \"{}\"] mod outside;\n",
                temp.path.join("outside.rs").display()
            ),
        )?;
        let error = match check_fixture_root(&temp.path) {
            Ok(_) => bail!("absolute module path must fail closed"),
            Err(error) => error,
        };
        assert!(!format!("{error:#}").contains(temp.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn nonempty_unknown_item_macro_scope_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-nonempty-macro")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "unknown_external_macro!(harmless);\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn fake_dependency_rebinding_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-dependency")?;
        fs::create_dir_all(temp.path.join("fake/generated/src"))?;
        fs::write(
            temp.path.join("fake/generated/Cargo.toml"),
            "[package]\nname = \"fake-generated\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        fs::write(temp.path.join("fake/generated/src/lib.rs"), "")?;
        let workspace = temp.path.join("Cargo.toml");
        fs::write(
            &workspace,
            fs::read_to_string(&workspace)?
                .replace("\"generated\"]", "\"generated\", \"fake/generated\"]"),
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?.replace(
                "generated = { path = \"../../generated\" }",
                "generated = { package = \"fake-generated\", path = \"../../fake/generated\" }",
            ),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn fake_bootstrap_dependency_cannot_supply_domain_route_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-fake-bootstrap-dependency")?;
        let bootstrap = temp.path.join("crates/bootstrap/Cargo.toml");
        fs::write(
            &bootstrap,
            fs::read_to_string(&bootstrap)?
                .replace("name = \"bootstrap\"", "name = \"fake-bootstrap\""),
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?.replace(
                "bootstrap = { path = \"../bootstrap\" }",
                "bootstrap = { package = \"fake-bootstrap\", path = \"../bootstrap\" }",
            ),
        )?;
        assert!(
            check_fixture_root(&temp.path).is_err(),
            "renamed bootstrap package must not authorize Domain/Registry evidence"
        );
        Ok(())
    }

    #[test]
    fn extern_crate_self_bootstrap_cannot_supply_domain_route_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-self-bootstrap")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "extern crate self as bootstrap;\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingRouteBinding),
            "self-alias bootstrap must not authorize Domain/Registry evidence: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn integration_test_marker_enters_global_exactly_one_accounting() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-integration-marker")?;
        fs::create_dir_all(temp.path.join("crates/demo/tests"))?;
        fs::write(
            temp.path.join("crates/demo/tests/duplicate.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[dev-dependencies]\ngenerated = {{ path = \"../../generated\" }}\nvocab = {{ path = \"../vocab\" }}\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateTestMarker));
        Ok(())
    }

    #[test]
    fn proc_attribute_scope_cannot_supply_evidence() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-proc-attr")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace("fn init(", "#[unknown::rewrite]\nfn init("),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn strict_marker_rejects_near_miss_grammar() -> anyhow::Result<()> {
        let resolver = Resolver::default();
        for source in [
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::other::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::WrongMarker> = ::generated::http::demo_v1::write::ROUTE;",
            "const _: vocab::HttpRouteBinding<generated::http::demo_v1::write::RouteMarker, vocab::http::LocalTx> = generated::http::demo_v1::write::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ()> = ::generated::http::demo_v1::write::ROUTE;",
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = (::generated::http::demo_v1::write::ROUTE);",
        ] {
            let item: ItemConst = syn::parse_str(source)?;
            assert!(
                strict_test_marker_key(&item, &resolver).is_none(),
                "accepted near miss: {source}"
            );
        }
        let canonical: ItemConst = syn::parse_str(
            "const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE;",
        )?;
        assert_eq!(
            strict_test_marker_key(&canonical, &resolver).as_deref(),
            Some("demo_v1::write")
        );
        Ok(())
    }

    #[test]
    fn statically_false_external_module_is_not_parsed() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-false-module")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "#[cfg(any())]\nmod absent;\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        fs::write(
            &owner,
            format!(
                "#[cfg(feature = \"unknown\")]\nmod absent;\n{}",
                fs::read_to_string(&owner)?.replace("#[cfg(any())]\nmod absent;\n", "")
            ),
        )?;
        assert!(check_fixture_root(&temp.path).is_err());
        Ok(())
    }

    #[test]
    fn active_module_inclusion_cycles_fail_with_fixed_relative_errors() -> anyhow::Result<()> {
        let self_cycle = FixtureCopy::new("localtx-self-cycle")?;
        fs::write(
            self_cycle.path.join("crates/demo/src/lib.rs"),
            "#[path = \"lib.rs\"] mod again;\n",
        )?;
        let error = match check_fixture_root(&self_cycle.path) {
            Ok(_) => bail!("self inclusion must fail"),
            Err(error) => error,
        };
        let rendered = format!("{error:#}");
        assert!(rendered.contains("active Rust module inclusion cycle"));
        assert!(!rendered.contains(self_cycle.path.to_string_lossy().as_ref()));

        let two_file = FixtureCopy::new("localtx-two-file-cycle")?;
        fs::write(two_file.path.join("crates/demo/src/lib.rs"), "mod a;\n")?;
        fs::write(
            two_file.path.join("crates/demo/src/a.rs"),
            "#[path = \"lib.rs\"] mod root;\n",
        )?;
        let error = match check_fixture_root(&two_file.path) {
            Ok(_) => bail!("two-file inclusion must fail"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("active Rust module inclusion cycle"));
        Ok(())
    }

    #[test]
    fn integration_route_is_test_only_and_cannot_supply_production_evidence() -> anyhow::Result<()>
    {
        let temp = FixtureCopy::new("localtx-integration-route")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            r#"#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        fs::create_dir_all(temp.path.join("crates/demo/tests"))?;
        fs::write(
            temp.path.join("crates/demo/tests/route.rs"),
            r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }
"#,
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        Ok(())
    }

    #[test]
    fn cargo_autotests_and_explicit_test_targets_are_authoritative() -> anyhow::Result<()> {
        let disabled = FixtureCopy::new("localtx-autotests-disabled")?;
        fs::create_dir_all(disabled.path.join("crates/demo/tests"))?;
        fs::write(
            disabled.path.join("crates/demo/tests/orphan.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = disabled.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            fs::read_to_string(&cargo)?
                .replace("name = \"demo\"", "name = \"demo\"\nautotests = false"),
        )?;
        let (_, findings) = check_fixture_root(&disabled.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let explicit = FixtureCopy::new("localtx-explicit-test")?;
        fs::create_dir_all(explicit.path.join("crates/demo/checks"))?;
        fs::write(
            explicit.path.join("crates/demo/checks/contract.rs"),
            "#[test] fn duplicate() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
        )?;
        let cargo = explicit.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[[test]]\nname = \"contract\"\npath = \"checks/contract.rs\"\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&explicit.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateTestMarker));
        Ok(())
    }

    #[test]
    fn fake_tokio_and_rstest_dependencies_cannot_authorize_markers() -> anyhow::Result<()> {
        for (macro_path, dependency, package) in [
            ("tokio::test", "tokio", "fake-tokio"),
            ("rstest::rstest", "rstest", "fake-rstest"),
        ] {
            let temp = FixtureCopy::new("localtx-fake-test-macro")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                &owner,
                fs::read_to_string(&owner)?.replace(
                    "#[test] fn covered()",
                    &format!("#[{macro_path}] fn covered()"),
                ),
            )?;
            let fake = temp.path.join(format!("fake/{dependency}"));
            fs::create_dir_all(fake.join("src"))?;
            fs::write(
                fake.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{package}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"
                ),
            )?;
            fs::write(fake.join("src/lib.rs"), "")?;
            let workspace = temp.path.join("Cargo.toml");
            fs::write(
                &workspace,
                fs::read_to_string(&workspace)?.replace(
                    "\"generated\"]",
                    &format!("\"generated\", \"fake/{dependency}\"]"),
                ),
            )?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            fs::write(
                &cargo,
                format!(
                    "{}\n[dev-dependencies]\n{dependency} = {{ package = \"{package}\", path = \"../../fake/{dependency}\" }}\n",
                    fs::read_to_string(&cargo)?
                ),
            )?;
            assert!(check_fixture_root(&temp.path).is_err());
        }
        Ok(())
    }

    #[test]
    fn local_test_macro_alias_cannot_borrow_a_real_cargo_dependency() -> anyhow::Result<()> {
        let temp = FixtureCopy::new("localtx-test-macro-alias")?;
        let cargo = temp.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!(
                "{}\n[dev-dependencies]\ntokio = \"1\"\n",
                fs::read_to_string(&cargo)?
            ),
        )?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                "use evil_macros as tokio;\n    #[tokio::test] fn covered()",
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));

        let trusted = FixtureCopy::new("localtx-trusted-macro-alias")?;
        let cargo = trusted.path.join("crates/demo/Cargo.toml");
        fs::write(
            &cargo,
            format!("{}\ntracing = \"0.1\"\n", fs::read_to_string(&cargo)?),
        )?;
        let owner = trusted.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "use evil_macros as tracing;\n#[tracing::instrument] fn bait() {{}}\n{}",
                fs::read_to_string(&owner)?
            ),
        )?;
        let (_, findings) = check_fixture_root(&trusted.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn local_item_macro_invocations_make_test_identity_opaque() -> anyhow::Result<()> {
        for (binding, test_attr, dependency, bait) in [
            ("tokio", "tokio::test", Some(("tokio", "1")), ""),
            ("rstest", "rstest::rstest", Some(("rstest", "0.24")), ""),
            ("test", "test", None, ""),
            ("Debug", "test", None, "#[derive(Debug)] struct Bait;"),
        ] {
            let temp = FixtureCopy::new("localtx-local-item-macro")?;
            if let Some((name, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{name} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            let owner = temp.path.join("crates/demo/src/lib.rs");
            let source = fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                &format!("#[{test_attr}] fn covered()"),
            );
            fs::write(
                &owner,
                format!(
                    "macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}\npoison!();\n{bait}\n{source}"
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingRouteBinding),
                "{binding}: {findings:#?}"
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingTestMarker),
                "{binding}: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn block_statement_macro_invocations_make_nested_evidence_opaque() -> anyhow::Result<()> {
        for (binding, test_attr, dependency, bait) in [
            ("tokio", "tokio::test", Some(("tokio", "1")), ""),
            ("rstest", "rstest::rstest", Some(("rstest", "0.24")), ""),
            ("test", "test", None, ""),
            ("Debug", "test", None, "#[derive(Debug)] struct Bait;"),
        ] {
            let temp = FixtureCopy::new("localtx-block-statement-macro")?;
            if let Some((name, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{name} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init() {{
    macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}
    poison!();
    {bait}
    {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
}}
#[{test_attr}] fn covered() {{
    macro_rules! poison {{ () => {{ use evil_macros as {binding}; }}; }}
    poison!();
    {bait}
    {{
        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
            ::generated::http::demo_v1::write::ROUTE;
    }}
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }

        let control = FixtureCopy::new("localtx-block-expression-macros")?;
        let owner = control.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?
                .replace(
                    "fn init() {",
                    "fn init() { { assert!(true); let _formatted = format!(\"route\"); }",
                )
                .replace(
                    "#[test] fn covered() {",
                    "#[test] fn covered() { { assert!(true); let _formatted = format!(\"marker\"); }",
                ),
        )?;
        let (_, findings) = check_fixture_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn unknown_sibling_attribute_or_derive_taints_the_module_scope() -> anyhow::Result<()> {
        for bait in [
            "#[unknown::rewrite] struct Bait;",
            "#[derive(unknown::Rewrite)] struct Bait;",
        ] {
            let temp = FixtureCopy::new("localtx-unknown-sibling-attr")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::OpaqueSourceScope
                        && finding.subject == "crates/demo/src/lib.rs:1"
                        && (finding.detail.contains("unknown::rewrite")
                            || finding.detail.contains("unknown::Rewrite"))
                }),
                "opaque trigger must name its source line and attribute: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn recognized_test_functions_cannot_supply_production_routes() -> anyhow::Result<()> {
        for (attr, dependency) in [
            ("test", None),
            ("tokio::test", Some(("tokio", "1"))),
            ("rstest::rstest", Some(("rstest", "0.24"))),
        ] {
            let temp = FixtureCopy::new("localtx-test-route-bait")?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            if let Some((dependency, version)) = dependency {
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{dependency} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
#[{attr}] fn bait() {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn parent_resolver_risks_propagate_into_external_modules() -> anyhow::Result<()> {
        for (root_source, missing_route, missing_marker) in [
            ("#[unknown::rewrite] mod evidence;\n", true, true),
            (
                "extern crate self as generated;\nmod evidence;\n",
                true,
                true,
            ),
            ("use evil::test;\nmod evidence;\n", false, true),
        ] {
            let temp = FixtureCopy::new("localtx-external-parent-risk")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(
                temp.path.join("crates/demo/src/evidence.rs"),
                fs::read_to_string(&owner)?,
            )?;
            fs::write(&owner, root_source)?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert_eq!(
                findings.iter().any(|f| f.rule == Rule::MissingRouteBinding),
                missing_route
            );
            assert_eq!(
                findings.iter().any(|f| f.rule == Rule::MissingTestMarker),
                missing_marker
            );
        }
        Ok(())
    }

    #[test]
    fn parent_canonical_aliases_do_not_leak_into_child_modules() -> anyhow::Result<()> {
        let evidence = r#"
struct Endpoint;
impl Endpoint { fn new<A, B>(_: A, _: B) {} }
const ROUTE: () = ();
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
fn init() { Endpoint::new(ROUTE, handler); }
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#;
        for external in [false, true] {
            let temp = FixtureCopy::new("localtx-parent-alias")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            let imports = "use ::generated::http::demo_v1::write::ROUTE;\nuse ::httpserve::GeneratedEndpoint as Endpoint;\n";
            if external {
                fs::write(
                    &owner,
                    format!("{imports}#[path = \"evidence.rs\"] mod evidence;\n"),
                )?;
                fs::write(temp.path.join("crates/demo/src/evidence.rs"), evidence)?;
            } else {
                fs::write(&owner, format!("{imports}mod evidence {{ {evidence} }}\n"))?;
            }
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn builtin_derive_names_cannot_be_rebound_or_globbed() -> anyhow::Result<()> {
        for bait in [
            "use evil::Rewrite as Debug;\n#[derive(Debug)] struct Bait;",
            "use evil::*;\n#[derive(Clone)] struct Bait;",
            "macro_rules! Copy { () => {} }\n#[derive(Copy)] struct Bait;",
        ] {
            let temp = FixtureCopy::new("localtx-derive-shadow")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn evidence_respects_const_statement_block_and_call_cfg_attributes() -> anyhow::Result<()> {
        let marker = FixtureCopy::new("localtx-cfg-const")?;
        let owner = marker.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "const _: ::vocab::HttpRouteBinding",
                "#[cfg(any())] const _: ::vocab::HttpRouteBinding",
            ),
        )?;
        let (_, findings) = check_fixture_root(&marker.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));

        for body in [
            "#[cfg(test)] let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler));",
            "#[cfg(test)] rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler));",
            "#[cfg(test)] { let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler)); }",
            "#[cfg(test)] if true { let _ = rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler)); }",
        ] {
            let temp = FixtureCopy::new("localtx-cfg-route-evidence")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init(reg: &mut ::httpserve::Registry) {{ reg.route_group(|rb| {{ {body} Ok(rb) }}); }}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }

        let control = FixtureCopy::new("localtx-production-method-control")?;
        fs::write(
            control.path.join("crates/demo/src/lib.rs"),
            r#"struct Domain;
impl ::bootstrap::Domain for Domain {
    fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {}
    fn init(&self, reg: &mut ::bootstrap::Registry) { reg.route_group(|rb| { Ok(rb.mount(::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, Domain::handler))) }); }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn builtin_test_attribute_rejects_macro_namespace_pollution() -> anyhow::Result<()> {
        for bait in [
            "use evil::test;",
            "use evil::Rewrite as test;",
            "use evil::*;",
            "macro_rules! test { () => {} }",
            "extern crate self as test;",
        ] {
            let temp = FixtureCopy::new("localtx-test-shadow")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn local_globs_pollute_but_super_glob_inherits_known_parent_risks() -> anyhow::Result<()> {
        for bait in ["use crate::*;", "use self::*;"] {
            let temp = FixtureCopy::new("localtx-local-glob")?;
            let owner = temp.path.join("crates/demo/src/lib.rs");
            fs::write(&owner, format!("{bait}\n{}", fs::read_to_string(&owner)?))?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }

        let temp = FixtureCopy::new("localtx-super-glob")?;
        let owner = temp.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            fs::read_to_string(&owner)?.replace(
                "#[test] fn covered()",
                "use super::*;\n    #[test] fn covered()",
            ),
        )?;
        let (_, findings) = check_fixture_root(&temp.path)?;
        assert!(findings.is_empty(), "{findings:#?}");

        let polluted = FixtureCopy::new("localtx-polluted-super-glob")?;
        let owner = polluted.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "use evil::test;\n{}",
                fs::read_to_string(&owner)?.replace(
                    "#[test] fn covered()",
                    "use super::*;\n    #[test] fn covered()",
                )
            ),
        )?;
        let (_, findings) = check_fixture_root(&polluted.path)?;
        assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        Ok(())
    }

    #[test]
    fn cfg_limited_impls_cannot_supply_route_or_inline_handler_evidence() -> anyhow::Result<()> {
        for cfg in ["test", "any()"] {
            let temp = FixtureCopy::new("localtx-cfg-impl")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"struct Domain;
#[cfg({cfg})]
impl Domain {{
    fn init() {{
        let _ = ::httpserve::GeneratedEndpoint::new(
            ::generated::http::demo_v1::write::ROUTE,
            |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
        );
    }}
}}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }
        Ok(())
    }

    #[test]
    fn attributed_methods_traits_arms_and_statics_cannot_supply_routes() -> anyhow::Result<()> {
        for bait in [
            "#[cfg(test)] trait Bait { fn init() { CALL } }",
            "trait Bait { #[cfg(any())] fn init() { CALL } }",
            "struct Bait; impl Bait { #[unknown::rewrite] fn init() { CALL } }",
            "fn init() { match true { #[cfg(test)] true => { CALL }, _ => {} } }",
            "#[cfg(test)] static BAIT: () = { CALL };",
            "struct Bait; impl Bait { #[cfg(test)] const VALUE: () = { CALL }; }",
        ] {
            let temp = FixtureCopy::new("localtx-attributed-ancestor")?;
            let bait = bait.replace(
                "CALL",
                "let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| ());",
            );
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"{bait}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }
        Ok(())
    }

    #[test]
    fn attributed_struct_field_initializers_respect_route_reachability() -> anyhow::Result<()> {
        for attr in ["cfg(test)", "cfg(any())", "unknown::rewrite"] {
            let temp = FixtureCopy::new("localtx-attributed-field-value")?;
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"struct Holder {{ #[{attr}] endpoint: () }}
fn init() {{
    let _ = Holder {{
        #[{attr}]
        endpoint: {{
            let _ = ::httpserve::GeneratedEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            );
        }}
    }};
}}
#[test] fn covered() {{
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
        }

        let control = FixtureCopy::new("localtx-field-value-control")?;
        fs::write(
            control.path.join("crates/demo/src/lib.rs"),
            r#"struct Demo;
impl ::bootstrap::Domain for Demo {
    fn init(&self, reg: &mut ::bootstrap::Registry) {
        reg.route_group(|rb| {
            Ok(rb.mount(::httpserve::GeneratedEndpoint::new(
                ::generated::http::demo_v1::write::ROUTE,
                |_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>| (),
            )))
        });
    }
}
#[test] fn covered() {
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}
"#,
        )?;
        let (_, findings) = check_fixture_root(&control.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn nested_helpers_in_recognized_tests_remain_test_only() -> anyhow::Result<()> {
        for (attr, dependency) in [
            ("test", None),
            ("tokio::test", Some(("tokio", "1"))),
            ("rstest::rstest", Some(("rstest", "0.24"))),
        ] {
            let temp = FixtureCopy::new("localtx-nested-test-route")?;
            if let Some((dependency, version)) = dependency {
                let cargo = temp.path.join("crates/demo/Cargo.toml");
                fs::write(
                    &cargo,
                    format!(
                        "{}\n[dev-dependencies]\n{dependency} = \"{version}\"\n",
                        fs::read_to_string(&cargo)?
                    ),
                )?;
            }
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
#[{attr}] fn covered() {{
    fn helper() {{
        let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler);
    }}
    helper();
    const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
        ::generated::http::demo_v1::write::ROUTE;
}}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingRouteBinding));
            assert!(!findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    fn fake_outer_test_macros_cannot_lend_identity_to_nested_markers() -> anyhow::Result<()> {
        for (root, version) in [("tokio", "1"), ("rstest", "0.24")] {
            let temp = FixtureCopy::new("localtx-fake-outer-test")?;
            let cargo = temp.path.join("crates/demo/Cargo.toml");
            fs::write(
                &cargo,
                format!(
                    "{}\n[dev-dependencies]\n{root} = \"{version}\"\n",
                    fs::read_to_string(&cargo)?
                ),
            )?;
            let attr = if root == "tokio" {
                "tokio::test"
            } else {
                "rstest::rstest"
            };
            fs::write(
                temp.path.join("crates/demo/src/lib.rs"),
                format!(
                    r#"use evil_macros as {root};
#[{attr}] fn outer() {{
    fn nested() {{
        const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> =
            ::generated::http::demo_v1::write::ROUTE;
    }}
    nested();
}}
fn handler(_: ::httpserve::ContractMarker<::generated::http::demo_v1::write::RouteMarker>) {{}}
fn init() {{ let _ = ::httpserve::GeneratedEndpoint::new(::generated::http::demo_v1::write::ROUTE, handler); }}
"#,
                ),
            )?;
            let (_, findings) = check_fixture_root(&temp.path)?;
            assert!(findings.iter().any(|f| f.rule == Rule::MissingTestMarker));
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn module_budget_accepts_boundary_and_rejects_deep_and_fanout() -> anyhow::Result<()> {
        let mut budget = ModuleBudget::default();
        for index in 0..MAX_CANONICAL_FILES {
            budget.enter(Path::new(&format!("file-{index}.rs")), 1, MAX_MODULE_DEPTH)?;
        }
        assert!(budget.enter(Path::new("too-many.rs"), 1, 1).is_err());
        let mut depth = ModuleBudget::default();
        assert!(
            depth
                .enter(Path::new("deep.rs"), 1, MAX_MODULE_DEPTH + 1)
                .is_err()
        );
        let mut bytes = ModuleBudget::default();
        bytes.enter(Path::new("boundary.rs"), MAX_SOURCE_BYTES, 1)?;
        assert!(bytes.enter(Path::new("too-large.rs"), 1, 1).is_err());

        let deep = FixtureCopy::new("localtx-module-depth")?;
        let owner = deep.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[path = \"depth-1.rs\"] mod depth;\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        for index in 1..MAX_MODULE_DEPTH {
            fs::write(
                deep.path.join(format!("crates/demo/src/depth-{index}.rs")),
                if index + 1 == MAX_MODULE_DEPTH {
                    String::new()
                } else {
                    format!("#[path = \"depth-{}.rs\"] mod next;\n", index + 1)
                },
            )?;
        }
        let (_, findings) = check_fixture_root(&deep.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        fs::write(
            deep.path
                .join(format!("crates/demo/src/depth-{}.rs", MAX_MODULE_DEPTH - 1)),
            format!("#[path = \"depth-{MAX_MODULE_DEPTH}.rs\"] mod next;\n"),
        )?;
        fs::write(
            deep.path
                .join(format!("crates/demo/src/depth-{MAX_MODULE_DEPTH}.rs")),
            "",
        )?;
        assert!(check_fixture_root(&deep.path).is_err());

        let fanout = FixtureCopy::new("localtx-module-fanout")?;
        let owner = fanout.path.join("crates/demo/src/lib.rs");
        let mut source = fs::read_to_string(&owner)?;
        for index in 0..(MAX_CANONICAL_FILES - 1) {
            source.push_str(&format!(
                "\n#[path = \"fanout-{index}.rs\"] mod fanout_{index};"
            ));
            fs::write(
                fanout
                    .path
                    .join(format!("crates/demo/src/fanout-{index}.rs")),
                "",
            )?;
        }
        fs::write(&owner, &source)?;
        let (_, findings) = check_fixture_root(&fanout.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        source.push_str(&format!(
            "\n#[path = \"fanout-{}.rs\"] mod fanout_over;",
            MAX_CANONICAL_FILES - 1
        ));
        fs::write(
            fanout.path.join(format!(
                "crates/demo/src/fanout-{}.rs",
                MAX_CANONICAL_FILES - 1
            )),
            "",
        )?;
        fs::write(&owner, source)?;
        assert!(check_fixture_root(&fanout.path).is_err());

        let inline_depth = FixtureCopy::new("localtx-inline-depth")?;
        let owner = inline_depth.path.join("crates/demo/src/lib.rs");
        let base = fs::read_to_string(&owner)?;
        let nested = |count: usize| {
            format!(
                "{base}\n{}{}",
                (0..count)
                    .map(|index| format!("mod inline_{index} {{"))
                    .collect::<String>(),
                "}".repeat(count)
            )
        };
        fs::write(&owner, nested(MAX_MODULE_DEPTH - 1))?;
        let (_, findings) = check_fixture_root(&inline_depth.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        fs::write(&owner, nested(MAX_MODULE_DEPTH))?;
        assert!(check_fixture_root(&inline_depth.path).is_err());

        let inline_wide = FixtureCopy::new("localtx-inline-wide")?;
        let owner = inline_wide.path.join("crates/demo/src/lib.rs");
        let mut source = fs::read_to_string(&owner)?;
        // Root file + the green fixture's inline `tests` module consume two logical units.
        for index in 0..(MAX_LOGICAL_UNITS - 2) {
            source.push_str(&format!("\nmod inline_wide_{index} {{}}"));
        }
        fs::write(&owner, &source)?;
        let (_, findings) = check_fixture_root(&inline_wide.path)?;
        assert!(findings.is_empty(), "{findings:#?}");
        source.push_str("\nmod inline_wide_over {}");
        fs::write(&owner, source)?;
        assert!(check_fixture_root(&inline_wide.path).is_err());
        Ok(())
    }

    struct FixtureCopy {
        path: PathBuf,
    }
    impl FixtureCopy {
        fn new(prefix: &str) -> anyhow::Result<Self> {
            let path = crate::testutil::unique_tmp(prefix);
            copy_tree(&fixture("green"), &path)?;
            Ok(Self { path })
        }

        fn cargo_check(&self) -> anyhow::Result<std::process::Output> {
            let manifest = self.path.join("Cargo.toml");
            let target = self.path.join("target");
            crate::cmd::cargo_cmd(
                crate::cmd::CargoSubcommand::Check,
                &[
                    "--offline",
                    "--manifest-path",
                    manifest
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture manifest path is not UTF-8"))?,
                ],
                &[(
                    "CARGO_TARGET_DIR",
                    target
                        .to_str()
                        .ok_or_else(|| anyhow!("fixture target path is not UTF-8"))?,
                )],
                Some(&self.path),
            )
            .output()
            .map_err(Into::into)
        }
    }
    impl Drop for FixtureCopy {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let target = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_tree(&entry.path(), &target)?;
            } else {
                fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }
}
