//! Consistency crash fixture gate.
//!
//! Scans `fixtures/consistency/**/fixture-*.toml` and keeps the N-028 crash
//! matrix machine-visible. This is a no-compile governance gate: it validates
//! fixture shape, redaction boundaries, ready-case coverage, and journey runner
//! mappings. Real backend recovery is executed by the opt-in
//! `ci-integration --shard consistency-fault` lane.
//!
//! INVARIANT: CONSISTENCY-CRASH-FIXTURE-01 { level = "Medium", exec = "check", source = "code" } -- consistency crash fixture ids must be unique and fixtures must parse as the closed TOML DSL.
//! INVARIANT: CONSISTENCY-FAULT-MATRIX-01 { level = "Medium", exec = "check", source = "code" } -- N-028 ready cases must cover every consistency mechanism with a non-draft contract; each ready DeviceLatent fixture must bind a non-draft contract, and every ready fixture must have a real journey runner mapping.
//! INVARIANT: CONSISTENCY-FAULT-EVIDENCE-01 { level = "Medium", exec = "check", source = "code" } -- ready L2 evidence is exported only after full fixture, contract, generated-binding, runner, filesystem-safety, and anti-vacuity validation succeeds.
//! INVARIANT: CONSISTENCY-FAULT-RUNNER-SYMBOL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_runner_symbol_must_be_canonical_run_function_path", anti_vacuity = "tests::real_critical_l2_ga_cases_bind_exact_specs_contracts_and_runner_symbols" } -- every ready case binds a canonical top-level `run_*` function that becomes its exact assurance carrier.
//! INVARIANT: CONSISTENCY-FAULT-TYPED-SEAM-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_direct_sqlx_dependency_is_rejected + tests::red_package_aliased_sqlx_dependency_is_rejected_in_every_dependency_table + tests::red_critical_runner_fake_receiver_cannot_supply_provider_capability + tests::red_critical_runner_fake_publisher_and_direct_sql_remain_rejected", anti_vacuity = "tests::green_real_tree_has_required_ready_fixtures + tests::real_critical_l2_ga_cases_bind_exact_specs_contracts_and_runner_symbols" } -- critical runner constructors require sealed provider/conformance output types, assurance consumes the same exact typed runner registration, and the verifier rejects direct or aliased sqlx dependencies, raw SQL, and fake publishers.

use crate::contract::DiscoveredContract;
use crate::contract::manifest::{ConsistencyLevel, ContractOwner, Lifecycle};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::{Expr, ExprArray, Item, Lit};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const MIN_READY_CASES: usize = 12;
const MIN_READY_PER_MECHANISM: usize = 2;
const MAX_ALIAS_LEN: usize = 128;
const LONG_MATERIAL_MIN: usize = 32;
const JOURNEY_RUNNER_SOURCE: &str =
    "journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs";
const JOURNEY_MANIFEST: &str = "journeys-fault-matrix/Cargo.toml";
const MAX_RUNNER_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_FIXTURE_BYTES: u64 = 256 * 1024;
const MAX_JOURNEY_MANIFEST_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingDirectory,
    NoFixtures,
    Parse,
    InvalidFixture,
    DuplicateId,
    ReadyCount,
    MechanismCoverage,
    MissingRunnerMapping,
    RunnerMismatch,
    ForbiddenJourneyDependency,
    CriticalCase,
}

pub(crate) struct ConsistencyFixtures;

impl GovernanceCheck for ConsistencyFixtures {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "consistency-fixtures"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        Ok(check_root(&root))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
enum CrashLevel {
    #[serde(rename = "L0")]
    L0,
    #[serde(rename = "L1")]
    L1,
    #[serde(rename = "L2")]
    L2,
    #[serde(rename = "L3")]
    L3,
    #[serde(rename = "L4")]
    L4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CrashMechanism {
    Outbox,
    Inbox,
    Saga,
    Projection,
    Reconcile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CrashStatus {
    Pending,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CrashRunner {
    Postgres,
    Rabbitmq,
    PostgresRabbitmq,
    PostgresRedis,
}

impl CrashRunner {
    fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "Postgres" => Some(Self::Postgres),
            "Rabbitmq" => Some(Self::Rabbitmq),
            "PostgresRabbitmq" => Some(Self::PostgresRabbitmq),
            "PostgresRedis" => Some(Self::PostgresRedis),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashFaultSpec {
    OutboxAfterPublishBeforeSettle,
    OutboxTransientPublishFailure,
    OutboxConfirmLostChannelClose,
    OutboxPermanentPublishFailure,
    OutboxStaleLeaseContender,
    OutboxLeaseDeadlineExpired,
    InboxClaimCrashBeforeCommit,
    InboxCommitBeforeAckCrash,
    InboxLeaseLostBeforeCommit,
    SagaForwardCompletedBeforeCheckpoint,
    SagaCompensationInterrupted,
    ProjectionAfterApplyBeforeCheckpoint,
    ProjectionStaleCheckpointWriter,
    ReconcileDispatchBeforeResultRecord,
    ReconcileLeaseLostBeforeWrite,
}

impl CrashFaultSpec {
    fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "OutboxAfterPublishBeforeSettle" => Some(Self::OutboxAfterPublishBeforeSettle),
            "OutboxTransientPublishFailure" => Some(Self::OutboxTransientPublishFailure),
            "OutboxConfirmLostChannelClose" => Some(Self::OutboxConfirmLostChannelClose),
            "OutboxPermanentPublishFailure" => Some(Self::OutboxPermanentPublishFailure),
            "OutboxStaleLeaseContender" => Some(Self::OutboxStaleLeaseContender),
            "OutboxLeaseDeadlineExpired" => Some(Self::OutboxLeaseDeadlineExpired),
            "InboxClaimCrashBeforeCommit" => Some(Self::InboxClaimCrashBeforeCommit),
            "InboxCommitBeforeAckCrash" => Some(Self::InboxCommitBeforeAckCrash),
            "InboxLeaseLostBeforeCommit" => Some(Self::InboxLeaseLostBeforeCommit),
            "SagaForwardCompletedBeforeCheckpoint" => {
                Some(Self::SagaForwardCompletedBeforeCheckpoint)
            }
            "SagaCompensationInterrupted" => Some(Self::SagaCompensationInterrupted),
            "ProjectionAfterApplyBeforeCheckpoint" => {
                Some(Self::ProjectionAfterApplyBeforeCheckpoint)
            }
            "ProjectionStaleCheckpointWriter" => Some(Self::ProjectionStaleCheckpointWriter),
            "ReconcileDispatchBeforeResultRecord" => {
                Some(Self::ReconcileDispatchBeforeResultRecord)
            }
            "ReconcileLeaseLostBeforeWrite" => Some(Self::ReconcileLeaseLostBeforeWrite),
            _ => None,
        }
    }

    fn from_fixture(fixture: &Fixture) -> Option<Self> {
        match (
            fixture.mechanism,
            fixture.crash_point.as_str(),
            fixture.expected_invariant.as_str(),
        ) {
            (
                CrashMechanism::Outbox,
                "after-publish-before-settle",
                "outbox-publish-settled-once",
            ) => Some(Self::OutboxAfterPublishBeforeSettle),
            (
                CrashMechanism::Outbox,
                "during-transient-publish",
                "outbox-transient-remains-retryable",
            ) => Some(Self::OutboxTransientPublishFailure),
            (
                CrashMechanism::Outbox,
                "post-send-close-before-confirm",
                "outbox-ambiguous-retry-consumer-effect-once",
            ) => Some(Self::OutboxConfirmLostChannelClose),
            (CrashMechanism::Outbox, "during-permanent-publish", "outbox-dlx-summary-redacted") => {
                Some(Self::OutboxPermanentPublishFailure)
            }
            (
                CrashMechanism::Outbox,
                "stale-contender-settle",
                "outbox-stale-lease-settle-rejected",
            ) => Some(Self::OutboxStaleLeaseContender),
            (
                CrashMechanism::Outbox,
                "deadline-expired-settle",
                "outbox-expired-deadline-settle-rejected",
            ) => Some(Self::OutboxLeaseDeadlineExpired),
            (
                CrashMechanism::Inbox,
                "after-claim-before-commit",
                "inbox-stale-claim-reclaimable",
            ) => Some(Self::InboxClaimCrashBeforeCommit),
            (CrashMechanism::Inbox, "after-commit-before-ack", "inbox-redelivery-dedupes-once") => {
                Some(Self::InboxCommitBeforeAckCrash)
            }
            (
                CrashMechanism::Inbox,
                "lease-lost-before-commit",
                "inbox-stale-lease-cannot-commit",
            ) => Some(Self::InboxLeaseLostBeforeCommit),
            (
                CrashMechanism::Saga,
                "after-forward-before-checkpoint",
                "saga-resume-skips-completed-step",
            ) => Some(Self::SagaForwardCompletedBeforeCheckpoint),
            (CrashMechanism::Saga, "during-compensation", "saga-compensation-resumes-once") => {
                Some(Self::SagaCompensationInterrupted)
            }
            (
                CrashMechanism::Projection,
                "after-apply-before-checkpoint",
                "projection-replay-idempotent",
            ) => Some(Self::ProjectionAfterApplyBeforeCheckpoint),
            (
                CrashMechanism::Projection,
                "stale-checkpoint-writer",
                "projection-stale-writer-rejected",
            ) => Some(Self::ProjectionStaleCheckpointWriter),
            (
                CrashMechanism::Reconcile,
                "after-dispatch-before-result-record",
                "reconcile-dispatch-key-stable",
            ) => Some(Self::ReconcileDispatchBeforeResultRecord),
            (
                CrashMechanism::Reconcile,
                "lease-lost-before-write",
                "reconcile-stale-writer-rejected",
            ) => Some(Self::ReconcileLeaseLostBeforeWrite),
            _ => None,
        }
    }

    fn expected_runner(self) -> CrashRunner {
        match self {
            Self::OutboxAfterPublishBeforeSettle
            | Self::OutboxConfirmLostChannelClose
            | Self::InboxCommitBeforeAckCrash => CrashRunner::PostgresRabbitmq,
            Self::SagaForwardCompletedBeforeCheckpoint | Self::SagaCompensationInterrupted => {
                CrashRunner::PostgresRedis
            }
            Self::OutboxTransientPublishFailure
            | Self::OutboxPermanentPublishFailure
            | Self::OutboxStaleLeaseContender
            | Self::OutboxLeaseDeadlineExpired
            | Self::InboxClaimCrashBeforeCommit
            | Self::InboxLeaseLostBeforeCommit
            | Self::ProjectionAfterApplyBeforeCheckpoint
            | Self::ProjectionStaleCheckpointWriter
            | Self::ReconcileDispatchBeforeResultRecord
            | Self::ReconcileLeaseLostBeforeWrite => CrashRunner::Postgres,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TenantAuthorityState {
    Valid,
    Missing,
    Invalid,
    Expired,
    Mismatch,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[serde(rename = "schemaVersion")]
    schema_version: u16,
    id: String,
    title: String,
    level: CrashLevel,
    mechanism: CrashMechanism,
    status: CrashStatus,
    #[serde(rename = "pendingReason")]
    pending_reason: Option<String>,
    domain: String,
    #[serde(rename = "contractId")]
    contract_id: String,
    #[serde(rename = "tenantAlias")]
    tenant_alias: String,
    #[serde(rename = "messageAlias")]
    message_alias: String,
    #[serde(rename = "partitionKeyAlias")]
    partition_key_alias: String,
    #[serde(rename = "tenantAuthority")]
    tenant_authority: TenantAuthorityState,
    #[serde(rename = "crashPoint")]
    crash_point: String,
    #[serde(rename = "expectedInvariant")]
    expected_invariant: String,
    runner: CrashRunner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunnerContract {
    fault_spec: CrashFaultSpec,
    runner: CrashRunner,
    generated_contract: String,
    runner_symbol: String,
    critical_kind: Option<CriticalRunnerBodyKind>,
    forbidden_bypass: bool,
}

#[derive(Debug, Clone)]
struct ContractEntry {
    owner_domain: String,
    consistency_level: ConsistencyLevel,
    lifecycle: Lifecycle,
    generated_contract: String,
}

/// One canonical ready-L2 fault carrier, exported only after complete validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyL2FaultEvidence {
    pub case_id: String,
    pub contract_id: String,
    pub fixture_carrier: String,
    pub runner_carrier: String,
    pub runner_symbol: String,
}

#[derive(Debug, Clone, Copy)]
struct CriticalFaultCase {
    case_id: &'static str,
    contract_id: &'static str,
    fault_spec: CrashFaultSpec,
    runner: CrashRunner,
    generated_contract: &'static str,
    runner_symbol: &'static str,
    body_kind: CriticalRunnerBodyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CriticalRunnerBodyKind {
    ConfirmLost,
    StaleContender,
    DeadlineExpired,
}

const CRITICAL_FAULT_CASES: [CriticalFaultCase; 3] = [
    CriticalFaultCase {
        case_id: "outbox-confirm-lost-channel-close",
        contract_id: "identity.session-created",
        fault_spec: CrashFaultSpec::OutboxConfirmLostChannelClose,
        runner: CrashRunner::PostgresRabbitmq,
        generated_contract: "generated::event::identity_v1::session_created::CONTRACT",
        runner_symbol: "run_outbox_confirm_lost_channel_close",
        body_kind: CriticalRunnerBodyKind::ConfirmLost,
    },
    CriticalFaultCase {
        case_id: "outbox-stale-contender-settle",
        contract_id: "identity.session-created",
        fault_spec: CrashFaultSpec::OutboxStaleLeaseContender,
        runner: CrashRunner::Postgres,
        generated_contract: "generated::event::identity_v1::session_created::CONTRACT",
        runner_symbol: "run_outbox_stale_contender_settle",
        body_kind: CriticalRunnerBodyKind::StaleContender,
    },
    CriticalFaultCase {
        case_id: "outbox-deadline-expired-settle",
        contract_id: "identity.session-created",
        fault_spec: CrashFaultSpec::OutboxLeaseDeadlineExpired,
        runner: CrashRunner::Postgres,
        generated_contract: "generated::event::identity_v1::session_created::CONTRACT",
        runner_symbol: "run_outbox_deadline_expired_settle",
        body_kind: CriticalRunnerBodyKind::DeadlineExpired,
    },
];

#[derive(Debug, Default)]
struct FixtureScan {
    ready_ids: BTreeSet<String>,
    ready_count: usize,
    ready_by_mechanism: BTreeMap<CrashMechanism, usize>,
    ready_l2_evidence: Vec<ReadyL2FaultEvidence>,
    findings: Vec<Finding>,
}

#[derive(Debug, Default)]
struct RootValidation {
    summary: String,
    findings: Vec<Finding>,
    ready_l2_evidence: Vec<ReadyL2FaultEvidence>,
}

fn check_root(root: &Path) -> (String, Vec<Finding>) {
    let validation = validate_root(root);
    (validation.summary, validation.findings)
}

/// Export canonical ready-L2 carriers from an immutable, already validated contract universe.
///
/// The assurance builder uses this API so contract discovery and validation happen exactly once.
pub(crate) fn ready_l2_fault_evidence_from_validated(
    root: &Path,
    contracts: &[DiscoveredContract],
) -> Result<Vec<ReadyL2FaultEvidence>> {
    let mut validation = validate_root_with_contracts(root, contracts);
    if !validation.findings.is_empty() {
        let first = &validation.findings[0];
        anyhow::bail!(
            "consistency fixture validation failed with {} finding(s); first: {}: {}",
            validation.findings.len(),
            first.subject,
            first.detail
        );
    }
    if validation.ready_l2_evidence.is_empty() {
        anyhow::bail!("consistency fixture validation produced no ready L2 evidence");
    }
    validation.ready_l2_evidence.sort_by(|left, right| {
        (&left.contract_id, &left.case_id).cmp(&(&right.contract_id, &right.case_id))
    });
    Ok(validation.ready_l2_evidence)
}

fn validate_root(root: &Path) -> RootValidation {
    match crate::contract::discover(&root.join("contracts")) {
        Ok(contracts) => validate_root_with_contracts(root, &contracts),
        Err(error) => RootValidation {
            findings: vec![finding(
                Rule::InvalidFixture,
                "contracts",
                format!("contract discovery failed: {error}"),
            )],
            ..RootValidation::default()
        },
    }
}

fn validate_root_with_contracts(
    root: &Path,
    discovered_contracts: &[DiscoveredContract],
) -> RootValidation {
    let dir = root.join("fixtures").join("consistency");
    let mut findings = journey_manifest_dependency_findings(root);
    if let Err(detail) = require_real_directory(&dir) {
        findings.push(finding(Rule::MissingDirectory, rel(root, &dir), detail));
        return RootValidation {
            findings,
            ..RootValidation::default()
        };
    }
    let mut files = Vec::new();
    if let Err(e) = collect_fixture_files(&dir, &mut files) {
        findings.push(finding(Rule::InvalidFixture, rel(root, &dir), e));
        return RootValidation {
            findings,
            ..RootValidation::default()
        };
    }
    files.sort();
    if files.is_empty() {
        findings.push(finding(
            Rule::NoFixtures,
            rel(root, &dir),
            "no fixture-*.toml files found",
        ));
        return RootValidation {
            findings,
            ..RootValidation::default()
        };
    }

    let contracts = match contract_index(discovered_contracts) {
        Ok(contracts) => contracts,
        Err(detail) => {
            findings.push(finding(Rule::InvalidFixture, "contracts", detail));
            BTreeMap::new()
        }
    };
    let journey_runners = match journey_runner_mappings(root) {
        Ok(runners) => runners,
        Err(detail) => {
            findings.push(finding(
                Rule::MissingRunnerMapping,
                JOURNEY_RUNNER_SOURCE,
                detail,
            ));
            BTreeMap::new()
        }
    };

    let scan = scan_fixture_corpus(root, &files, &contracts, &journey_runners);
    add_orphan_runner_findings(&mut findings, &scan.ready_ids, &journey_runners);
    add_critical_fault_findings(&mut findings, &scan, &journey_runners);
    findings.extend(scan.findings);
    add_ready_coverage_findings(
        &mut findings,
        root,
        &dir,
        scan.ready_count,
        &scan.ready_by_mechanism,
        &contracts,
    );

    let summary = format!(
        "{} fixture files scanned, {} ready cases",
        files.len(),
        scan.ready_count
    );
    RootValidation {
        summary,
        findings,
        ready_l2_evidence: scan.ready_l2_evidence,
    }
}

fn scan_fixture_corpus(
    root: &Path,
    files: &[PathBuf],
    contracts: &BTreeMap<String, ContractEntry>,
    journey_runners: &BTreeMap<String, RunnerContract>,
) -> FixtureScan {
    let mut scan = FixtureScan::default();
    let mut ids = BTreeSet::new();
    for path in files {
        let rel_path = rel(root, path);
        let src = match crate::generated_file::read_stable_utf8_file(
            path,
            MAX_FIXTURE_BYTES,
            "fixture TOML",
        ) {
            Ok(src) => src,
            Err(e) => {
                scan.findings
                    .push(finding(Rule::Parse, rel_path, e.to_string()));
                continue;
            }
        };
        if let Some(detail) = raw_toml_safety_finding(&src) {
            scan.findings
                .push(finding(Rule::InvalidFixture, rel_path, detail));
            continue;
        }
        let fixture: Fixture = match toml::from_str(&src) {
            Ok(fixture) => fixture,
            Err(_) => {
                scan.findings.push(finding(
                    Rule::Parse,
                    rel_path,
                    "TOML parse failed; check closed fixture fields and enum values",
                ));
                continue;
            }
        };
        if fixture.status == CrashStatus::Ready {
            scan.ready_count += 1;
            scan.ready_ids.insert(fixture.id.clone());
            *scan
                .ready_by_mechanism
                .entry(fixture.mechanism)
                .or_default() += 1;
            if fixture.level == CrashLevel::L2
                && let Some(runner) = journey_runners.get(&fixture.id)
            {
                scan.ready_l2_evidence.push(ReadyL2FaultEvidence {
                    case_id: fixture.id.clone(),
                    contract_id: fixture.contract_id.clone(),
                    fixture_carrier: rel_path.clone(),
                    runner_carrier: JOURNEY_RUNNER_SOURCE.to_string(),
                    runner_symbol: runner.runner_symbol.clone(),
                });
            }
        }
        if !ids.insert(fixture.id.clone()) {
            scan.findings.push(finding(
                Rule::DuplicateId,
                fixture.id.clone(),
                format!("duplicate id in {rel_path}"),
            ));
        }
        scan.findings.extend(validate_fixture(
            &fixture,
            &rel_path,
            contracts,
            journey_runners,
        ));
    }
    scan
}

fn journey_manifest_dependency_findings(root: &Path) -> Vec<Finding> {
    match forbidden_journey_sqlx_dependencies(root) {
        Ok(dependencies) => dependencies
            .into_iter()
            .map(|(section, dependency)| {
                finding(
                    Rule::ForbiddenJourneyDependency,
                    JOURNEY_MANIFEST,
                    format!(
                        "journeys-fault-matrix must not depend on sqlx; `{dependency}` in [{section}] bypasses typed provider fault seams"
                    ),
                )
            })
            .collect(),
        Err(detail) => vec![finding(
            Rule::ForbiddenJourneyDependency,
            JOURNEY_MANIFEST,
            detail,
        )],
    }
}

fn forbidden_journey_sqlx_dependencies(root: &Path) -> Result<Vec<(String, String)>, String> {
    let path = root.join(JOURNEY_MANIFEST);
    let source = crate::generated_file::read_stable_utf8_file(
        &path,
        MAX_JOURNEY_MANIFEST_BYTES,
        "fault-matrix journey manifest",
    )
    .map_err(|error| error.to_string())?;
    let manifest = source
        .parse::<toml::Value>()
        .map_err(|_| "fault-matrix journey manifest TOML parse failed".to_string())?;
    let table = manifest
        .as_table()
        .ok_or_else(|| "fault-matrix journey manifest root must be a TOML table".to_string())?;
    let workspace_sqlx_aliases = workspace_sqlx_dependency_aliases(root)?;
    let mut forbidden = Vec::new();
    for (section, dependencies) in journey_dependency_tables(table)? {
        for (name, declaration) in dependencies {
            if dependency_resolves_to_sqlx(name, declaration, &section, &workspace_sqlx_aliases)? {
                forbidden.push((section.clone(), name.clone()));
            }
        }
    }
    Ok(forbidden)
}

fn journey_dependency_tables(
    manifest: &toml::value::Table,
) -> Result<Vec<(String, &toml::value::Table)>, String> {
    let mut tables = Vec::new();
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(value) = manifest.get(section) {
            let dependencies = value.as_table().ok_or_else(|| {
                format!("fault-matrix journey manifest [{section}] must be a TOML table")
            })?;
            tables.push((section.to_string(), dependencies));
        }
    }
    let Some(targets) = manifest.get("target") else {
        return Ok(tables);
    };
    let targets = targets
        .as_table()
        .ok_or_else(|| "fault-matrix journey manifest [target] must be a TOML table".to_string())?;
    for (target, value) in targets {
        let target_table = value.as_table().ok_or_else(|| {
            format!("fault-matrix journey manifest [target.{target}] must be a TOML table")
        })?;
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let Some(value) = target_table.get(section) else {
                continue;
            };
            let dependencies = value.as_table().ok_or_else(|| {
                format!(
                    "fault-matrix journey manifest [target.{target}.{section}] must be a TOML table"
                )
            })?;
            tables.push((format!("target.{target}.{section}"), dependencies));
        }
    }
    Ok(tables)
}

fn workspace_sqlx_dependency_aliases(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join("Cargo.toml");
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let source = crate::generated_file::read_stable_utf8_file(
        &path,
        MAX_JOURNEY_MANIFEST_BYTES,
        "workspace manifest",
    )
    .map_err(|error| error.to_string())?;
    let manifest = source
        .parse::<toml::Value>()
        .map_err(|_| "workspace manifest TOML parse failed".to_string())?;
    let root_table = manifest
        .as_table()
        .ok_or_else(|| "workspace manifest root must be a TOML table".to_string())?;
    let Some(workspace) = root_table.get("workspace") else {
        return Ok(BTreeSet::new());
    };
    let workspace = workspace
        .as_table()
        .ok_or_else(|| "workspace manifest [workspace] must be a TOML table".to_string())?;
    let Some(dependencies) = workspace.get("dependencies") else {
        return Ok(BTreeSet::new());
    };
    let dependencies = dependencies.as_table().ok_or_else(|| {
        "workspace manifest [workspace.dependencies] must be a TOML table".to_string()
    })?;
    let mut aliases = BTreeSet::new();
    for (name, declaration) in dependencies {
        if dependency_declares_package(name, declaration, "workspace.dependencies")? == "sqlx" {
            aliases.insert(name.clone());
        }
    }
    Ok(aliases)
}

fn dependency_resolves_to_sqlx(
    name: &str,
    declaration: &toml::Value,
    section: &str,
    workspace_sqlx_aliases: &BTreeSet<String>,
) -> Result<bool, String> {
    let package = dependency_declares_package(name, declaration, section)?;
    let inherited = match declaration.as_table().and_then(|table| table.get("workspace")) {
        Some(value) => value.as_bool().ok_or_else(|| {
            format!(
                "fault-matrix journey dependency `{name}` workspace in [{section}] must be a boolean"
            )
        })?,
        None => false,
    };
    Ok(package == "sqlx" || (inherited && workspace_sqlx_aliases.contains(name)))
}

fn dependency_declares_package<'a>(
    name: &'a str,
    declaration: &'a toml::Value,
    section: &str,
) -> Result<&'a str, String> {
    if declaration.is_str() {
        return Ok(name);
    }
    let table = declaration.as_table().ok_or_else(|| {
        format!(
            "fault-matrix journey dependency `{name}` in [{section}] must be a version string or table"
        )
    })?;
    match table.get("package") {
        Some(value) => value.as_str().ok_or_else(|| {
            format!(
                "fault-matrix journey dependency `{name}` package in [{section}] must be a string"
            )
        }),
        None => Ok(name),
    }
}

fn add_critical_fault_findings(
    findings: &mut Vec<Finding>,
    scan: &FixtureScan,
    journey_runners: &BTreeMap<String, RunnerContract>,
) {
    for expected in CRITICAL_FAULT_CASES {
        let evidence = scan
            .ready_l2_evidence
            .iter()
            .find(|evidence| evidence.case_id == expected.case_id);
        let runner = journey_runners.get(expected.case_id);
        let exact = evidence.is_some_and(|evidence| {
            evidence.contract_id == expected.contract_id
                && evidence.runner_symbol == expected.runner_symbol
        }) && runner.is_some_and(|runner| {
            runner.fault_spec == expected.fault_spec
                && runner.runner == expected.runner
                && runner.generated_contract == expected.generated_contract
                && runner.runner_symbol == expected.runner_symbol
                && runner.critical_kind == Some(expected.body_kind)
                && !runner.forbidden_bypass
        });
        if !exact {
            findings.push(finding(
                Rule::CriticalCase,
                expected.case_id,
                format!(
                    "critical fault case must bind contract `{}`, spec {:?}, runner {:?}, generated contract `{}`, runner function `{}`, and its exact real capability/conformance body",
                    expected.contract_id,
                    expected.fault_spec,
                    expected.runner,
                    expected.generated_contract,
                    expected.runner_symbol
                ),
            ));
        }
    }
}

fn add_orphan_runner_findings(
    findings: &mut Vec<Finding>,
    ready_ids: &BTreeSet<String>,
    journey_runners: &BTreeMap<String, RunnerContract>,
) {
    for runner_id in journey_runners.keys() {
        if !ready_ids.contains(runner_id) {
            findings.push(finding(
                Rule::MissingRunnerMapping,
                JOURNEY_RUNNER_SOURCE,
                format!("journey runner mapping `{runner_id}` has no ready fixture"),
            ));
        }
    }
}

fn add_ready_coverage_findings(
    findings: &mut Vec<Finding>,
    root: &Path,
    dir: &Path,
    ready_count: usize,
    ready_by_mechanism: &BTreeMap<CrashMechanism, usize>,
    contracts: &BTreeMap<String, ContractEntry>,
) {
    if ready_count < MIN_READY_CASES {
        findings.push(finding(
            Rule::ReadyCount,
            rel(root, dir),
            format!("expected at least {MIN_READY_CASES} ready fixtures, found {ready_count}"),
        ));
    }
    for mechanism in [
        CrashMechanism::Outbox,
        CrashMechanism::Inbox,
        CrashMechanism::Saga,
        CrashMechanism::Projection,
        CrashMechanism::Reconcile,
    ] {
        let consistency_level = match mechanism {
            CrashMechanism::Outbox | CrashMechanism::Inbox => ConsistencyLevel::OutboxFact,
            CrashMechanism::Saga | CrashMechanism::Projection => ConsistencyLevel::WorkflowEventual,
            CrashMechanism::Reconcile => ConsistencyLevel::DeviceLatent,
        };
        if !contracts.values().any(|contract| {
            contract.lifecycle != Lifecycle::Draft
                && contract.consistency_level == consistency_level
        }) {
            continue;
        }
        let count = ready_by_mechanism.get(&mechanism).copied().unwrap_or(0);
        if count < MIN_READY_PER_MECHANISM {
            findings.push(finding(
                Rule::MechanismCoverage,
                rel(root, dir),
                format!(
                    "expected at least {MIN_READY_PER_MECHANISM} ready {mechanism:?} fixtures, found {count}"
                ),
            ));
        }
    }
}

fn collect_fixture_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    require_real_directory(dir)?;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()).is_none() {
            return Err(format!(
                "fixture discovery rejects non-UTF-8 path under {}",
                dir.display()
            ));
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "fixture discovery rejects symlink: {}",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_fixture_files(&path, out)?;
        } else if metadata.is_file() && is_fixture_toml(&path) {
            out.push(path);
        } else if !metadata.is_file() {
            return Err(format!(
                "fixture discovery rejects non-regular entry: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "required directory {} is unavailable: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "fixture discovery rejects symlink directory: {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(format!("{} must be a real directory", path.display()));
    }
    Ok(())
}

fn is_fixture_toml(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("toml")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("fixture-"))
}

fn contract_index(
    discovered_contracts: &[DiscoveredContract],
) -> Result<BTreeMap<String, ContractEntry>, String> {
    if discovered_contracts.is_empty() {
        return Err("contract discovery found no contract.toml files".to_string());
    }
    let mut contracts = BTreeMap::new();
    for contract in discovered_contracts {
        let generated_contract = crate::codegen::GeneratedCarrier::from_contract(contract)
            .and_then(|carrier| carrier.item(crate::codegen::GeneratedItem::Contract))
            .map_err(|error| {
                format!(
                    "generated carrier projection failed for {}: {error}",
                    contract.manifest.id
                )
            })?
            .symbol;
        let manifest = &contract.manifest;
        let owner_domain = match &manifest.owner {
            ContractOwner::Domain(owner) => owner.clone(),
            ContractOwner::Framework => "_framework".to_string(),
        };
        let consistency_level = manifest.consistency_level;
        if contracts
            .insert(
                manifest.id.clone(),
                ContractEntry {
                    owner_domain,
                    consistency_level,
                    lifecycle: manifest.lifecycle,
                    generated_contract,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate contract id `{}`", manifest.id));
        }
    }

    Ok(contracts)
}

fn validate_fixture(
    fixture: &Fixture,
    rel_path: &str,
    contracts: &BTreeMap<String, ContractEntry>,
    journey_runners: &BTreeMap<String, RunnerContract>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if fixture.schema_version != 1 {
        findings.push(invalid(
            rel_path,
            format!("schemaVersion must be 1, got {}", fixture.schema_version),
        ));
    }
    validate_slug(&mut findings, rel_path, "id", &fixture.id);
    validate_nonempty(&mut findings, rel_path, "title", &fixture.title);
    validate_domain_name(&mut findings, rel_path, "domain", &fixture.domain);
    validate_dotted(&mut findings, rel_path, "contractId", &fixture.contract_id);
    validate_alias(
        &mut findings,
        rel_path,
        "tenantAlias",
        &fixture.tenant_alias,
    );
    validate_alias(
        &mut findings,
        rel_path,
        "messageAlias",
        &fixture.message_alias,
    );
    validate_alias(
        &mut findings,
        rel_path,
        "partitionKeyAlias",
        &fixture.partition_key_alias,
    );
    validate_slug(&mut findings, rel_path, "crashPoint", &fixture.crash_point);
    validate_slug(
        &mut findings,
        rel_path,
        "expectedInvariant",
        &fixture.expected_invariant,
    );
    if fixture.status == CrashStatus::Pending {
        match fixture.pending_reason.as_deref() {
            Some(reason) => validate_nonempty(&mut findings, rel_path, "pendingReason", reason),
            None => findings.push(invalid(rel_path, "pendingReason is required for pending")),
        }
    } else if fixture.pending_reason.is_some() {
        findings.push(invalid(
            rel_path,
            "pendingReason is only allowed when status is pending",
        ));
    }
    if !mechanism_level_ok(fixture.mechanism, fixture.level) {
        findings.push(invalid(
            rel_path,
            "mechanism and level are inconsistent with consistency-runtime rules",
        ));
    }
    if CrashFaultSpec::from_fixture(fixture).is_none() {
        findings.push(invalid(
            rel_path,
            "crashPoint/expectedInvariant must map to a closed CrashFaultSpec",
        ));
    }
    if fixture.status == CrashStatus::Ready {
        match journey_runners.get(&fixture.id) {
            Some(runner) => validate_runner_contract(
                &mut findings,
                rel_path,
                fixture,
                runner,
                contracts.get(&fixture.contract_id),
            ),
            None => findings.push(finding(
                Rule::MissingRunnerMapping,
                rel_path,
                format!(
                    "ready fixture `{}` has no consistency_fault_matrix journey runner mapping",
                    fixture.id
                ),
            )),
        }
    }
    validate_contract_reference(&mut findings, rel_path, fixture, contracts);
    for (field, value) in fixture_strings(fixture) {
        if looks_sensitive(value) {
            findings.push(invalid(
                rel_path,
                format!("{field} contains a secret-like or PII-like value"),
            ));
        }
    }
    let _ = fixture.tenant_authority; // parsed closed enum; validation is structural.
    findings
}

fn validate_runner_contract(
    findings: &mut Vec<Finding>,
    rel_path: &str,
    fixture: &Fixture,
    runner: &RunnerContract,
    contract: Option<&ContractEntry>,
) {
    match CrashFaultSpec::from_fixture(fixture) {
        Some(spec) if spec == runner.fault_spec => {}
        Some(spec) => findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "ready fixture `{}` maps to fault spec {:?}, but journey runner contract is {:?}",
                fixture.id, spec, runner.fault_spec
            ),
        )),
        None => findings.push(finding(
            Rule::InvalidFixture,
            rel_path,
            format!(
                "ready fixture `{}` crashPoint/expectedInvariant does not map to a closed CrashFaultSpec",
                fixture.id
            ),
        )),
    }
    if fixture.runner != runner.runner {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "ready fixture `{}` declares runner {:?}, but journey runner contract is {:?}",
                fixture.id, fixture.runner, runner.runner
            ),
        ));
    }
    if runner.runner != runner.fault_spec.expected_runner() {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "journey runner for `{}` binds runner {:?}, but fault spec {:?} expects {:?}",
                fixture.id,
                runner.runner,
                runner.fault_spec,
                runner.fault_spec.expected_runner()
            ),
        ));
    }
    if let Some(contract) = contract
        && contract.lifecycle == Lifecycle::Draft
        && contract.consistency_level == ConsistencyLevel::DeviceLatent
    {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "ready fixture `{}` cannot bind draft contract `{}`",
                fixture.id, fixture.contract_id
            ),
        ));
    }
    if let Some(contract) = contract
        && runner.generated_contract != contract.generated_contract
    {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "ready fixture `{}` contract `{}` requires generated contract `{}`, but journey runner binds `{}`",
                fixture.id,
                fixture.contract_id,
                contract.generated_contract,
                runner.generated_contract
            ),
        ));
    }
}

fn journey_runner_mappings(root: &Path) -> Result<BTreeMap<String, RunnerContract>, String> {
    journey_runner_mappings_with_hook(root, || {})
}

fn journey_runner_mappings_with_hook(
    root: &Path,
    after_open: impl FnOnce(),
) -> Result<BTreeMap<String, RunnerContract>, String> {
    let path = root.join(JOURNEY_RUNNER_SOURCE);
    let src = crate::generated_file::read_stable_utf8_file_with_hook(
        &path,
        MAX_RUNNER_SOURCE_BYTES,
        "runner source",
        after_open,
    )
    .map_err(|error| error.to_string())?;
    let syntax = syn::parse_file(&src).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries = ready_case_runner_array(&syntax)
        .ok_or_else(|| "READY_CASE_RUNNERS table not found".to_string())?;
    let mut mappings = BTreeMap::new();
    for entry in &entries.elems {
        let (id, mut runner) = parse_journey_runner_entry(entry)?;
        if runner.critical_kind.is_some() {
            runner.forbidden_bypass =
                critical_runner_has_forbidden_bypass(&syntax, &runner.runner_symbol)?;
        }
        if mappings.insert(id.clone(), runner).is_some() {
            return Err(format!("duplicate journey runner mapping `{id}`"));
        }
    }
    if mappings.is_empty() {
        return Err("READY_CASE_RUNNERS table is empty".to_string());
    }
    Ok(mappings)
}

fn ready_case_runner_array(file: &syn::File) -> Option<&ExprArray> {
    file.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == "READY_CASE_RUNNERS" => expr_array(&item.expr),
        _ => None,
    })
}

fn expr_array(expr: &Expr) -> Option<&ExprArray> {
    match expr {
        Expr::Reference(reference) => expr_array(&reference.expr),
        Expr::Array(array) => Some(array),
        _ => None,
    }
}

fn parse_journey_runner_entry(entry: &Expr) -> Result<(String, RunnerContract), String> {
    let Expr::Call(call) = entry else {
        return Err("READY_CASE_RUNNERS entry must be ReadyCaseRunner::new(...)".to_string());
    };
    let critical_kind = ready_case_runner_constructor(&call.func)?;
    if call.args.len() != 5 {
        return Err(format!(
            "ReadyCaseRunner::new must have 5 arguments, got {}",
            call.args.len()
        ));
    }
    let mut args = call.args.iter();
    let id = string_arg(args.next(), "id")?;
    let fault_spec = crash_fault_spec_arg(args.next())?;
    let runner = crash_runner_arg(args.next())?;
    let generated_contract = generated_contract_arg(args.next())?;
    let runner_symbol = runner_function_arg(args.next())?;
    Ok((
        id,
        RunnerContract {
            fault_spec,
            runner,
            generated_contract,
            runner_symbol,
            critical_kind,
            forbidden_bypass: false,
        },
    ))
}

fn ready_case_runner_constructor(expr: &Expr) -> Result<Option<CriticalRunnerBodyKind>, String> {
    let Expr::Path(path) = expr else {
        return Err("READY_CASE_RUNNERS entry must call a ReadyCaseRunner constructor".to_string());
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path.path.segments.len() != 2
        || path
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
        || path.path.segments[0].ident != "ReadyCaseRunner"
    {
        return Err(
            "READY_CASE_RUNNERS entry must call an exact ReadyCaseRunner constructor".to_string(),
        );
    }
    match path.path.segments[1].ident.to_string().as_str() {
        "new" => Ok(None),
        "confirm_lost" => Ok(Some(CriticalRunnerBodyKind::ConfirmLost)),
        "stale_contender" => Ok(Some(CriticalRunnerBodyKind::StaleContender)),
        "deadline_expired" => Ok(Some(CriticalRunnerBodyKind::DeadlineExpired)),
        constructor => Err(format!(
            "unknown READY_CASE_RUNNERS constructor `ReadyCaseRunner::{constructor}`"
        )),
    }
}

fn critical_runner_has_forbidden_bypass(
    syntax: &syn::File,
    runner_symbol: &str,
) -> Result<bool, String> {
    use syn::visit::Visit as _;

    let function = syntax
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == runner_symbol => Some(function),
            _ => None,
        })
        .ok_or_else(|| format!("critical runner function `{runner_symbol}` not found"))?;

    #[derive(Default)]
    struct BypassVisitor {
        forbidden: bool,
    }

    impl BypassVisitor {
        fn inspect_path(&mut self, path: &syn::Path) {
            let segments = path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            self.forbidden |= segments.first().is_some_and(|segment| segment == "sqlx")
                || segments.iter().any(|segment| {
                    matches!(
                        segment.as_str(),
                        "RecordingPublisher" | "FaultMatrixPublishOutcome"
                    )
                });
        }
    }

    impl<'ast> syn::visit::Visit<'ast> for BypassVisitor {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.inspect_path(&path.path);
            syn::visit::visit_expr_path(self, path);
        }

        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            self.inspect_path(&path.path);
            syn::visit::visit_type_path(self, path);
        }

        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            let sql = literal.value().to_ascii_lowercase();
            self.forbidden |= [
                "update outbox",
                "update inbox_receipts",
                "insert into audit_entries",
            ]
            .iter()
            .any(|needle| sql.contains(needle));
        }
    }

    let mut visitor = BypassVisitor::default();
    visitor.visit_block(&function.block);
    Ok(visitor.forbidden)
}

fn string_arg(expr: Option<&Expr>, name: &str) -> Result<String, String> {
    match expr {
        Some(Expr::Lit(lit)) => match &lit.lit {
            Lit::Str(value) => Ok(value.value()),
            _ => Err(format!("ReadyCaseRunner::{name} must be a string literal")),
        },
        _ => Err(format!("ReadyCaseRunner::{name} must be a string literal")),
    }
}

fn crash_runner_arg(expr: Option<&Expr>) -> Result<CrashRunner, String> {
    let Some(Expr::Path(path)) = expr else {
        return Err("ReadyCaseRunner::runner must be a CrashRunner variant".to_string());
    };
    let variant = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    CrashRunner::from_rust_variant(&variant)
        .ok_or_else(|| format!("unknown READY_CASE_RUNNERS runner `{variant}`"))
}

fn crash_fault_spec_arg(expr: Option<&Expr>) -> Result<CrashFaultSpec, String> {
    let Some(Expr::Path(path)) = expr else {
        return Err("ReadyCaseRunner::fault_spec must be a CrashFaultSpec variant".to_string());
    };
    let variant = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    CrashFaultSpec::from_rust_variant(&variant)
        .ok_or_else(|| format!("unknown READY_CASE_RUNNERS fault spec `{variant}`"))
}

fn generated_contract_arg(expr: Option<&Expr>) -> Result<String, String> {
    let Some(Expr::Path(path)) = expr else {
        return Err(
            "ReadyCaseRunner::contract must be a generated::<kind>::<module>::...::CONTRACT path"
                .to_string(),
        );
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
    {
        return Err(
            "ReadyCaseRunner::contract must be a canonical generated CONTRACT path".to_string(),
        );
    }
    let segments = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if segments.len() < 4
        || segments.first().map(String::as_str) != Some("generated")
        || segments.last().map(String::as_str) != Some("CONTRACT")
    {
        return Err(
            "ReadyCaseRunner::contract must be a generated::<kind>::<module>::...::CONTRACT path"
                .to_string(),
        );
    }
    Ok(segments.join("::"))
}

fn runner_function_arg(expr: Option<&Expr>) -> Result<String, String> {
    let Some(Expr::Path(path)) = expr else {
        return Err(
            "ReadyCaseRunner::runner function must be a canonical run_* Rust path".to_string(),
        );
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path.path.segments.is_empty()
        || path
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
    {
        return Err(
            "ReadyCaseRunner::runner function must be a canonical run_* Rust path".to_string(),
        );
    }
    let segments = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    if segments.len() != 1 || !segments[0].starts_with("run_") {
        return Err(
            "ReadyCaseRunner::runner function must be a canonical top-level run_* Rust path"
                .to_string(),
        );
    }
    Ok(segments.join("::"))
}

fn fixture_strings(fixture: &Fixture) -> [(&'static str, &str); 10] {
    [
        ("id", fixture.id.as_str()),
        ("title", fixture.title.as_str()),
        (
            "pendingReason",
            fixture.pending_reason.as_deref().unwrap_or(""),
        ),
        ("domain", fixture.domain.as_str()),
        ("contractId", fixture.contract_id.as_str()),
        ("tenantAlias", fixture.tenant_alias.as_str()),
        ("messageAlias", fixture.message_alias.as_str()),
        ("partitionKeyAlias", fixture.partition_key_alias.as_str()),
        ("crashPoint", fixture.crash_point.as_str()),
        ("expectedInvariant", fixture.expected_invariant.as_str()),
    ]
}

fn invalid(subject: impl Into<String>, detail: impl Into<String>) -> Finding {
    finding(Rule::InvalidFixture, subject, detail)
}

fn validate_nonempty(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    if value.trim().is_empty() {
        findings.push(invalid(subject, format!("{field} must not be empty")));
    }
}

fn validate_slug(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let ok = value.split('-').all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    });
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a lowercase kebab-case slug"),
        ));
    }
}

fn validate_alias(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_slug(findings, subject, field, value);
    if value.len() > MAX_ALIAS_LEN {
        findings.push(invalid(
            subject,
            format!("{field} exceeds {MAX_ALIAS_LEN} bytes"),
        ));
    }
}

fn validate_domain_name(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        findings.push(invalid(subject, format!("{field} must not be empty")));
        return;
    };
    let ok = first.is_ascii_lowercase()
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a lowercase domain name"),
        ));
    }
}

fn validate_dotted(findings: &mut Vec<Finding>, subject: &str, field: &str, value: &str) {
    validate_nonempty(findings, subject, field, value);
    let ok = value.split('.').all(|seg| {
        !seg.is_empty()
            && matches!(seg.bytes().next(), Some(b) if b.is_ascii_lowercase())
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if !ok {
        findings.push(invalid(
            subject,
            format!("{field} must be a canonical dotted id"),
        ));
    }
}

fn validate_contract_reference(
    findings: &mut Vec<Finding>,
    subject: &str,
    fixture: &Fixture,
    contracts: &BTreeMap<String, ContractEntry>,
) {
    match contracts.get(&fixture.contract_id) {
        Some(contract) => {
            if let Some(detail) = contract_reference_finding(fixture, contract) {
                findings.push(invalid(subject, detail));
            }
        }
        None => findings.push(invalid(
            subject,
            format!(
                "contractId `{}` is not declared in contracts/**/contract.toml",
                fixture.contract_id
            ),
        )),
    }
}

fn contract_reference_finding(fixture: &Fixture, contract: &ContractEntry) -> Option<String> {
    if contract.owner_domain != fixture.domain {
        return Some(format!(
            "contractId `{}` is owned by `{}`, not fixture domain `{}`",
            fixture.contract_id, contract.owner_domain, fixture.domain
        ));
    }
    let expected = expected_consistency_level(fixture.level);
    if contract.consistency_level != expected {
        return Some(format!(
            "contractId `{}` has consistencyLevel {:?}, but fixture level {:?} requires {:?}",
            fixture.contract_id, contract.consistency_level, fixture.level, expected
        ));
    }
    None
}

fn expected_consistency_level(level: CrashLevel) -> ConsistencyLevel {
    match level {
        CrashLevel::L0 => ConsistencyLevel::LocalOnly,
        CrashLevel::L1 => ConsistencyLevel::LocalTx,
        CrashLevel::L2 => ConsistencyLevel::OutboxFact,
        CrashLevel::L3 => ConsistencyLevel::WorkflowEventual,
        CrashLevel::L4 => ConsistencyLevel::DeviceLatent,
    }
}

fn mechanism_level_ok(mechanism: CrashMechanism, level: CrashLevel) -> bool {
    matches!(
        (mechanism, level),
        (
            CrashMechanism::Outbox | CrashMechanism::Inbox,
            CrashLevel::L2
        ) | (
            CrashMechanism::Saga | CrashMechanism::Projection,
            CrashLevel::L3
        ) | (CrashMechanism::Reconcile, CrashLevel::L4)
    )
}

fn raw_toml_safety_finding(src: &str) -> Option<String> {
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if looks_sensitive(key) {
            return Some(raw_toml_safety_detail("fixture key"));
        }
        if looks_sensitive(value) {
            return Some(raw_toml_safety_detail(raw_toml_safety_value_subject(key)));
        }
    }

    None
}

fn raw_toml_safety_detail(subject: &str) -> String {
    format!("{subject} contains raw payload, secret-like, or PII-like material")
}

fn raw_toml_safety_value_subject(key: &str) -> &'static str {
    match key {
        "schemaVersion" => "schemaVersion",
        "id" => "id",
        "title" => "title",
        "level" => "level",
        "mechanism" => "mechanism",
        "status" => "status",
        "pendingReason" => "pendingReason",
        "domain" => "domain",
        "contractId" => "contractId",
        "tenantAlias" => "tenantAlias",
        "messageAlias" => "messageAlias",
        "partitionKeyAlias" => "partitionKeyAlias",
        "tenantAuthority" => "tenantAuthority",
        "crashPoint" => "crashPoint",
        "expectedInvariant" => "expectedInvariant",
        "runner" => "runner",
        _ => "fixture value",
    }
}

fn looks_sensitive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("bearer ")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("apikey")
        || lower.contains("api_key")
        || lower.contains("hmac")
        || lower.contains("vault")
        || lower.contains("payload")
        || lower.contains('@')
        || lower.contains("://")
        || lower.contains("error")
        || lower.contains("exception")
        || lower.contains("panic")
        || lower.contains("stacktrace")
        || lower.contains("traceback")
        || lower.contains("handler")
        || looks_like_uuid(&lower)
        || contains_long_hex_material(&lower)
        || contains_long_base64_material(value)
        || looks_name_like_pii(&lower)
}

fn looks_like_uuid(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == '-'))
        .any(is_uuid_token)
}

fn is_uuid_token(token: &str) -> bool {
    if token.len() != 36 {
        return false;
    }

    token.chars().enumerate().all(|(idx, ch)| {
        if matches!(idx, 8 | 13 | 18 | 23) {
            ch == '-'
        } else {
            ch.is_ascii_hexdigit()
        }
    })
}

fn contains_long_hex_material(value: &str) -> bool {
    let mut run = 0;
    for byte in value.bytes() {
        if byte.is_ascii_hexdigit() {
            run += 1;
            if run >= LONG_MATERIAL_MIN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn contains_long_base64_material(value: &str) -> bool {
    let mut run = 0;
    let mut has_base64_marker = false;
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=') {
            run += 1;
            has_base64_marker |= byte.is_ascii_uppercase() || matches!(byte, b'+' | b'/' | b'=');
            if run >= LONG_MATERIAL_MIN && has_base64_marker {
                return true;
            }
        } else {
            run = 0;
            has_base64_marker = false;
        }
    }
    false
}

fn looks_name_like_pii(lower: &str) -> bool {
    [
        "full name",
        "first name",
        "last name",
        "given name",
        "family name",
        "display name",
        "legal name",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TMP: AtomicUsize = AtomicUsize::new(0);

    const VALID: &str = r#"
schemaVersion = 1
id = "outbox-after-publish-before-settle"
title = "publish succeeds before settle crash"
level = "L2"
mechanism = "outbox"
status = "ready"
domain = "identity"
contractId = "identity.session-created"
tenantAlias = "tenant-a"
messageAlias = "message-a"
partitionKeyAlias = "aggregate-a"
tenantAuthority = "valid"
crashPoint = "after-publish-before-settle"
expectedInvariant = "outbox-publish-settled-once"
runner = "postgres-rabbitmq"
"#;

    const VALID_CONTRACT: &str = r#"
id = "identity.session-created"
kind = "event"
domain = "identity"
version = "v1"
owner = "identity"
consistencyLevel = "OutboxFact"
lifecycle = "active"
topic = "identity.session-created"
delivery = "at-least-once"

[schemas]
payload = "payload.schema.json"

[[subscriptions]]
consumer = "identity"
group = "identity.session-created"
execution = "adapter-native"
externalEffectPolicy = "transactional-only"

[subscriptions.topology]
partitionKey = "none"
readiness = "required"
"#;

    const VALID_JOURNEY_RUNNERS: &str = r#"
const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-after-publish-before-settle",
        CrashFaultSpec::OutboxAfterPublishBeforeSettle,
        CrashRunner::PostgresRabbitmq,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_after_publish_before_settle,
    ),
];
"#;

    fn temp_root(name: &str) -> Result<PathBuf> {
        let n = NEXT_TMP.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "rss-consistency-fixtures-{name}-{}-{n}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(root.join("fixtures/consistency/outbox"))?;
        fs::create_dir_all(root.join("contracts/event/identity/v1/session-created"))?;
        fs::write(
            root.join("contracts/event/identity/v1/session-created/contract.toml"),
            VALID_CONTRACT,
        )?;
        fs::create_dir_all(root.join("journeys-fault-matrix/tests"))?;
        fs::write(
            root.join(JOURNEY_MANIFEST),
            "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[dependencies]\n\n[dev-dependencies]\n\n[build-dependencies]\n",
        )?;
        fs::write(root.join(JOURNEY_RUNNER_SOURCE), VALID_JOURNEY_RUNNERS)?;
        Ok(root)
    }

    fn write_fixture(root: &Path, name: &str, src: &str) -> Result<()> {
        fs::write(
            root.join("fixtures/consistency/outbox")
                .join(format!("fixture-{name}.toml")),
            src,
        )?;
        Ok(())
    }

    #[test]
    fn green_real_tree_has_required_ready_fixtures() -> Result<()> {
        let root = crate::workspace_root()?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.is_empty(),
            "real fixtures should pass: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_missing_directory_fails_closed() -> Result<()> {
        let root = temp_root("missing")?;
        fs::remove_dir_all(root.join("fixtures/consistency"))?;
        let (_, findings) = check_root(&root);
        assert_eq!(findings[0].rule, Rule::MissingDirectory);
        Ok(())
    }

    #[test]
    fn red_unknown_field_is_parse_error() -> Result<()> {
        let root = temp_root("unknown")?;
        write_fixture(&root, "bad", &format!("{VALID}\nextraField = \"x\"\n"))?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::Parse));
        Ok(())
    }

    #[test]
    fn red_duplicate_id_is_reported() -> Result<()> {
        let root = temp_root("duplicate")?;
        write_fixture(&root, "a", VALID)?;
        write_fixture(&root, "b", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateId));
        Ok(())
    }

    #[test]
    fn red_ready_count_floor_is_enforced() -> Result<()> {
        let root = temp_root("floor")?;
        write_fixture(&root, "one", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::ReadyCount));
        assert!(findings.iter().any(|f| f.rule == Rule::MechanismCoverage));
        Ok(())
    }

    #[test]
    fn red_ready_fixture_cannot_bind_draft_contract() -> Result<()> {
        let root = temp_root("ready-draft-contract")?;
        let contract = root.join("contracts/event/identity/v1/session-created/contract.toml");
        fs::write(
            &contract,
            fs::read_to_string(&contract)?
                .replace("lifecycle = \"active\"", "lifecycle = \"draft\"")
                .replace(
                    "consistencyLevel = \"OutboxFact\"",
                    "consistencyLevel = \"DeviceLatent\"",
                ),
        )?;
        write_fixture(
            &root,
            "ready-draft-contract",
            &VALID
                .replace("level = \"L2\"", "level = \"L4\"")
                .replace("mechanism = \"outbox\"", "mechanism = \"reconcile\"")
                .replace(
                    "crashPoint = \"after-publish-before-settle\"",
                    "crashPoint = \"after-dispatch-before-result-record\"",
                )
                .replace(
                    "expectedInvariant = \"outbox-publish-settled-once\"",
                    "expectedInvariant = \"reconcile-dispatch-key-stable\"",
                )
                .replace("runner = \"postgres-rabbitmq\"", "runner = \"postgres\""),
        )?;

        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::RunnerMismatch && finding.detail.contains("draft contract")
            }),
            "draft contract supplied ready execution evidence: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_missing_runner_mapping_is_reported() -> Result<()> {
        let root = temp_root("missing-runner")?;
        write_fixture(
            &root,
            "missing-runner",
            &VALID
                .replace(
                    "outbox-after-publish-before-settle",
                    "outbox-unmapped-ready-case",
                )
                .replace(
                    "crashPoint = \"after-publish-before-settle\"",
                    "crashPoint = \"unmapped-ready-case\"",
                )
                .replace(
                    "expectedInvariant = \"outbox-publish-settled-once\"",
                    "expectedInvariant = \"outbox-unmapped-invariant\"",
                ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::MissingRunnerMapping
                    && f.detail.contains("outbox-unmapped-ready-case")
            }),
            "missing runner mapping should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_runner_mismatch_is_reported() -> Result<()> {
        let root = temp_root("runner-mismatch")?;
        write_fixture(
            &root,
            "runner-mismatch",
            &VALID.replace("runner = \"postgres-rabbitmq\"", "runner = \"postgres\""),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| f.rule == Rule::RunnerMismatch),
            "runner mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_runner_generated_contract_binding_mismatch_is_reported() -> Result<()> {
        let root = temp_root("runner-contract-binding-mismatch")?;
        fs::write(
            root.join(JOURNEY_RUNNER_SOURCE),
            VALID_JOURNEY_RUNNERS.replace(
                "generated::event::identity_v1::session_created::CONTRACT",
                "generated::event::identity_v1::role_assigned::CONTRACT",
            ),
        )?;
        write_fixture(&root, "runner-contract-binding", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::RunnerMismatch
                    && f.detail.contains("generated contract")
                    && f.detail.contains("session_created")
            }),
            "generated contract binding mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_runner_raw_contract_binding_is_rejected() -> Result<()> {
        let root = temp_root("runner-raw-contract-binding")?;
        fs::write(
            root.join(JOURNEY_RUNNER_SOURCE),
            VALID_JOURNEY_RUNNERS.replace(
                "generated::event::identity_v1::session_created::CONTRACT",
                "vocab::ContractBinding::from_static(\"identity\", \"identity.session-created\", \"v1\", \"sha256:test\")",
            ),
        )?;
        write_fixture(&root, "runner-raw-contract-binding", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::MissingRunnerMapping
                    && f.detail.contains("generated")
                    && f.detail.contains("CONTRACT")
            }),
            "raw ContractBinding constructor should be rejected: {findings:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn red_symlink_fixture_is_rejected_without_following_it() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = temp_root("symlink-fixture")?;
        let outside = root.join("outside-fixture.toml");
        fs::write(&outside, VALID)?;
        symlink(
            &outside,
            root.join("fixtures/consistency/outbox/fixture-symlink.toml"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("rejects symlink")),
            "symlink fixture should fail closed: {findings:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn red_non_regular_fixture_is_rejected_before_read() -> Result<()> {
        use std::os::unix::net::UnixListener;

        let root = temp_root("non-regular-fixture")?;
        let socket_path = root.join("fixtures/consistency/outbox/fixture-socket.toml");
        let bind_path = std::env::temp_dir().join(format!(
            "rss-fixture-socket-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::SeqCst)
        ));
        let _listener = UnixListener::bind(&bind_path)?;
        fs::rename(bind_path, &socket_path)?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("rejects non-regular")),
            "non-regular fixture should fail closed: {findings:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn red_runner_source_symlink_is_rejected_without_following_it() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = temp_root("runner-source-symlink")?;
        let runner = root.join(JOURNEY_RUNNER_SOURCE);
        let outside = root.join("outside-runner.rs");
        fs::write(&outside, VALID_JOURNEY_RUNNERS)?;
        fs::remove_file(&runner)?;
        symlink(&outside, &runner)?;
        write_fixture(&root, "runner-source-symlink", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::MissingRunnerMapping && finding.detail.contains("symlink")
            }),
            "runner source symlink must fail closed: {findings:?}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn red_runner_source_replacement_after_open_is_rejected() -> Result<()> {
        let root = temp_root("runner-source-replacement")?;
        let runner = root.join(JOURNEY_RUNNER_SOURCE);
        let original = fs::read(&runner)?;
        let replacement = root.join("replacement-runner.rs");
        fs::write(&replacement, &original)?;

        let result = journey_runner_mappings_with_hook(&root, || {
            let opened = root.join("opened-runner.rs");
            assert!(fs::rename(&runner, opened).is_ok());
            assert!(fs::rename(&replacement, &runner).is_ok());
        });
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("runner replacement was accepted"))?;
        assert!(error.contains("replaced during read"), "{error}");
        Ok(())
    }

    #[test]
    fn ready_l2_fault_evidence_is_available_only_after_complete_validation() -> Result<()> {
        let root = temp_root("invalid-evidence")?;
        write_fixture(&root, "one", VALID)?;

        let contracts = crate::contract::discover(&root.join("contracts"))?;
        let error = ready_l2_fault_evidence_from_validated(&root, &contracts)
            .err()
            .ok_or_else(|| anyhow::anyhow!("incomplete fixture corpus exported evidence"))?;
        assert!(
            error.to_string().contains("validation"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn real_ready_l2_evidence_closes_active_fact_projection() -> Result<()> {
        let root = crate::workspace_root()?;
        let contracts = crate::contract::discover(&root.join("contracts"))?;
        let expected = contracts
            .iter()
            .filter(|contract| {
                contract.manifest.lifecycle == crate::contract::manifest::Lifecycle::Active
                    && contract.manifest.consistency_level == ConsistencyLevel::OutboxFact
                    && contract.manifest.kind == crate::contract::manifest::ContractKind::Event
                    && contract
                        .manifest
                        .capabilities
                        .outbox
                        .as_ref()
                        .is_some_and(|outbox| {
                            outbox.role == crate::contract::manifest::OutboxRole::Fact
                        })
            })
            .map(|contract| contract.manifest.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(!expected.is_empty(), "active fact projection is empty");

        let evidence = ready_l2_fault_evidence_from_validated(&root, &contracts)?;
        let actual = evidence
            .iter()
            .map(|item| item.contract_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
        assert!(evidence.iter().all(|item| {
            item.fixture_carrier.starts_with("fixtures/consistency/")
                && item.fixture_carrier.ends_with(".toml")
                && item.runner_carrier == JOURNEY_RUNNER_SOURCE
                && item.runner_symbol.starts_with("run_")
        }));
        Ok(())
    }

    #[test]
    fn red_runner_symbol_must_be_canonical_run_function_path() -> Result<()> {
        for invalid in [
            "\"run_outbox_after_publish_before_settle\"",
            "execute_outbox_after_publish_before_settle",
            "::run_outbox_after_publish_before_settle",
            "nested::run_outbox_after_publish_before_settle",
        ] {
            let root = temp_root("runner-symbol")?;
            fs::write(
                root.join(JOURNEY_RUNNER_SOURCE),
                VALID_JOURNEY_RUNNERS.replace("run_outbox_after_publish_before_settle", invalid),
            )?;
            write_fixture(&root, "one", VALID)?;
            let (_, findings) = check_root(&root);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::MissingRunnerMapping
                        && finding.detail.contains("runner function")
                }),
                "invalid runner function path passed: {invalid}; {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn red_direct_sqlx_dependency_is_rejected() -> Result<()> {
        let root = temp_root("direct-sqlx-dependency")?;
        fs::write(
            root.join(JOURNEY_MANIFEST),
            "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[dev-dependencies]\nsqlx = \"0.8\"\n",
        )?;

        let findings = journey_manifest_dependency_findings(&root);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenJourneyDependency
                    && finding.detail.contains("`sqlx`")
                    && finding.detail.contains("[dev-dependencies]")
            }),
            "direct sqlx dependency passed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_package_aliased_sqlx_dependency_is_rejected_in_every_dependency_table() -> Result<()> {
        for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let root = temp_root("aliased-sqlx-dependency")?;
            fs::write(
                root.join(JOURNEY_MANIFEST),
                format!(
                    "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[{section}]\ndatabase = {{ package = \"sqlx\", version = \"0.8\" }}\n"
                ),
            )?;

            let findings = journey_manifest_dependency_findings(&root);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::ForbiddenJourneyDependency
                        && finding.detail.contains("`database`")
                        && finding.detail.contains(&format!("[{section}]"))
                }),
                "aliased sqlx dependency passed in [{section}]: {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn red_target_specific_direct_and_aliased_sqlx_dependencies_are_rejected() -> Result<()> {
        for declaration in [
            "sqlx = \"0.8\"",
            "database = { package = \"sqlx\", version = \"0.8\" }",
        ] {
            let root = temp_root("target-sqlx-dependency")?;
            fs::write(
                root.join(JOURNEY_MANIFEST),
                format!(
                    "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[target.'cfg(unix)'.dev-dependencies]\n{declaration}\n"
                ),
            )?;
            let findings = journey_manifest_dependency_findings(&root);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::ForbiddenJourneyDependency
                        && finding
                            .detail
                            .contains("[target.cfg(unix).dev-dependencies]")
                }),
                "target-specific sqlx dependency passed: {declaration}; {findings:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn red_workspace_inherited_sqlx_alias_is_rejected_in_target_table() -> Result<()> {
        let root = temp_root("workspace-inherited-sqlx")?;
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\n\n[workspace.dependencies]\ndatabase = { package = \"sqlx\", version = \"0.8\" }\n",
        )?;
        fs::write(
            root.join(JOURNEY_MANIFEST),
            "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[target.'cfg(unix)'.dependencies]\ndatabase = { workspace = true }\n",
        )?;
        let findings = journey_manifest_dependency_findings(&root);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenJourneyDependency
                    && finding.detail.contains("`database`")
                    && finding.detail.contains("[target.cfg(unix).dependencies]")
            }),
            "workspace-inherited sqlx alias passed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_malformed_target_dependency_table_fails_closed() -> Result<()> {
        let root = temp_root("malformed-target-dependencies")?;
        fs::write(
            root.join(JOURNEY_MANIFEST),
            "target = \"cfg(unix)\"\n\n[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n",
        )?;
        let findings = journey_manifest_dependency_findings(&root);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ForbiddenJourneyDependency
                    && finding.detail.contains("[target] must be a TOML table")
            }),
            "malformed target declaration did not fail closed: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_critical_runner_typed_constructor_cannot_be_deleted() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = fs::read_to_string(root.join(JOURNEY_RUNNER_SOURCE))?;
        for (case_id, constructor, expected_kind) in [
            (
                "outbox-confirm-lost-channel-close",
                "confirm_lost",
                CriticalRunnerBodyKind::ConfirmLost,
            ),
            (
                "outbox-stale-contender-settle",
                "stale_contender",
                CriticalRunnerBodyKind::StaleContender,
            ),
            (
                "outbox-deadline-expired-settle",
                "deadline_expired",
                CriticalRunnerBodyKind::DeadlineExpired,
            ),
        ] {
            let mutated = source.replacen(
                &format!("ReadyCaseRunner::{constructor}(\n        \"{case_id}\""),
                &format!("ReadyCaseRunner::new(\n        \"{case_id}\""),
                1,
            );
            assert_ne!(mutated, source, "missing real constructor for {case_id}");
            let syntax = syn::parse_file(&mutated)?;
            let entries = ready_case_runner_array(&syntax)
                .ok_or_else(|| anyhow::anyhow!("missing synthetic runner table"))?;
            let (_, runner) = entries
                .elems
                .iter()
                .map(parse_journey_runner_entry)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?
                .into_iter()
                .find(|(id, _)| id == case_id)
                .ok_or_else(|| anyhow::anyhow!("missing critical case {case_id}"))?;
            assert!(
                runner.critical_kind != Some(expected_kind),
                "critical typed constructor deletion passed: {case_id}"
            );
        }
        Ok(())
    }

    #[test]
    fn red_critical_runner_fake_receiver_cannot_supply_provider_capability() -> Result<()> {
        let syntax = syn::parse_file(
            r#"
struct FakeHarness;

impl FakeHarness {
    async fn stale_outbox_settlement(&self) {}
}

fn run_outbox_stale_contender_settle() {
    let fake = FakeHarness;
    fake.stale_outbox_settlement();
}

const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-stale-contender-settle",
        CrashFaultSpec::OutboxStaleLeaseContender,
        CrashRunner::Postgres,
        generated::event::identity_v1::session_created::CONTRACT,
        run_outbox_stale_contender_settle,
    ),
];
"#,
        )?;
        let entries = ready_case_runner_array(&syntax)
            .ok_or_else(|| anyhow::anyhow!("missing synthetic runner table"))?;
        let (_, runner) = parse_journey_runner_entry(
            entries
                .elems
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing synthetic runner"))?,
        )
        .map_err(anyhow::Error::msg)?;
        assert!(
            runner.critical_kind != Some(CriticalRunnerBodyKind::StaleContender),
            "a same-named method on a fake receiver supplied typed postgres capability"
        );
        Ok(())
    }

    #[test]
    fn red_critical_runner_fake_publisher_and_direct_sql_remain_rejected() -> Result<()> {
        for bypass in [
            "RecordingPublisher::ambiguous();",
            "sqlx::query(\"UPDATE outbox SET status = 'published'\");",
        ] {
            let syntax = syn::parse_file(&format!(
                "fn run_outbox_confirm_lost_channel_close() {{ {bypass} }}"
            ))?;
            assert!(
                critical_runner_has_forbidden_bypass(
                    &syntax,
                    "run_outbox_confirm_lost_channel_close"
                )
                .map_err(anyhow::Error::msg)?,
                "critical bypass passed: {bypass}"
            );
        }
        Ok(())
    }

    #[test]
    fn real_critical_l2_ga_cases_bind_exact_specs_contracts_and_runner_symbols() -> Result<()> {
        let root = crate::workspace_root()?;
        let contracts = crate::contract::discover(&root.join("contracts"))?;
        let evidence = ready_l2_fault_evidence_from_validated(&root, &contracts)?;
        let actual = CRITICAL_FAULT_CASES
            .iter()
            .map(|expected| {
                let item = evidence
                    .iter()
                    .find(|item| item.case_id == expected.case_id)
                    .ok_or_else(|| anyhow::anyhow!("missing {}", expected.case_id))?;
                Ok((
                    item.case_id.as_str(),
                    item.contract_id.as_str(),
                    item.runner_symbol.as_str(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected = CRITICAL_FAULT_CASES
            .iter()
            .map(|item| (item.case_id, item.contract_id, item.runner_symbol))
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn crash_fault_spec_variants_match_testkit() -> Result<()> {
        let root = crate::workspace_root()?;
        let xtask_src = fs::read_to_string(root.join("xtask/src/consistency_fixtures.rs"))?;
        let testkit_src = fs::read_to_string(root.join("crates/testkit/src/crash_matrix.rs"))?;
        let xtask_variants = enum_variants(&xtask_src, "CrashFaultSpec")?;
        let testkit_variants = enum_variants(&testkit_src, "CrashFaultSpec")?;

        assert_eq!(
            xtask_variants, testkit_variants,
            "xtask and testkit CrashFaultSpec variants drifted"
        );
        Ok(())
    }

    #[test]
    fn red_runner_contract_invariant_mismatch_is_reported() -> Result<()> {
        let root = temp_root("runner-invariant")?;
        write_fixture(
            &root,
            "runner-invariant",
            &VALID.replace(
                "expectedInvariant = \"outbox-publish-settled-once\"",
                "expectedInvariant = \"outbox-drifted-invariant\"",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("crashPoint/expectedInvariant must map")
            }),
            "closed fault spec mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    fn enum_variants(src: &str, name: &str) -> Result<Vec<String>> {
        let file = syn::parse_file(src)?;
        for item in file.items {
            if let Item::Enum(item) = item
                && item.ident == name
            {
                return Ok(item
                    .variants
                    .iter()
                    .map(|variant| variant.ident.to_string())
                    .collect());
            }
        }
        anyhow::bail!("enum `{name}` not found")
    }

    #[test]
    fn red_runner_contract_contract_id_mismatch_is_reported() -> Result<()> {
        let root = temp_root("runner-contract-id")?;
        write_fixture(
            &root,
            "runner-contract-id",
            &VALID.replace(
                "contractId = \"identity.session-created\"",
                "contractId = \"identity.role-assigned\"",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("not declared") }),
            "contractId mismatch should be reported by contract validation: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_secret_like_alias_is_rejected() -> Result<()> {
        let root = temp_root("secret")?;
        write_fixture(&root, "secret", &VALID.replace("message-a", "bearer-token"))?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("secret-like") })
        );
        Ok(())
    }

    #[test]
    fn red_unknown_contract_id_is_reported() -> Result<()> {
        let root = temp_root("missing-contract")?;
        write_fixture(
            &root,
            "missing-contract",
            &VALID.replace("identity.session-created", "identity.missing"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("not declared") }),
            "missing contractId should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_contract_owner_domain_mismatch_is_reported() -> Result<()> {
        let root = temp_root("contract-owner")?;
        write_fixture(
            &root,
            "owner",
            &VALID.replace("domain = \"identity\"", "domain = \"settings\""),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("owned by") }),
            "owner/domain mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_contract_consistency_level_mismatch_is_reported() -> Result<()> {
        let root = temp_root("contract-level")?;
        fs::write(
            root.join("contracts/event/identity/v1/session-created/contract.toml"),
            VALID_CONTRACT.replace(
                "consistencyLevel = \"OutboxFact\"",
                "consistencyLevel = \"WorkflowEventual\"",
            ),
        )?;
        write_fixture(&root, "level", VALID)?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture && f.detail.contains("consistencyLevel")
            }),
            "contract consistencyLevel mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_long_alias_is_rejected() -> Result<()> {
        let root = temp_root("long-alias")?;
        let long_alias = "g".repeat(MAX_ALIAS_LEN + 1);
        write_fixture(&root, "long", &VALID.replace("message-a", &long_alias))?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture && f.detail.contains("messageAlias exceeds")
            }),
            "long alias should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_parse_time_secret_value_is_rejected_without_raw_leak() -> Result<()> {
        let root = temp_root("enum-secret")?;
        write_fixture(
            &root,
            "enum-secret",
            &VALID.replace(
                "tenantAuthority = \"valid\"",
                "tenantAuthority = \"Bearer super-secret-token\"",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("tenantAuthority")
                    && !f.detail.contains("super-secret-token")
            }),
            "secret-like enum value should be rejected without echoing raw value: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_parse_time_secret_key_is_rejected_without_raw_leak() -> Result<()> {
        let root = temp_root("key-secret")?;
        write_fixture(
            &root,
            "key-secret",
            &format!("{VALID}\n\"super-secret-token\" = \"x\"\n"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("fixture key")
                    && !f.subject.contains("super-secret-token")
                    && !f.detail.contains("super-secret-token")
            }),
            "secret-like key should be rejected without echoing raw key: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_uuid_like_alias_is_rejected() -> Result<()> {
        let root = temp_root("uuid")?;
        write_fixture(
            &root,
            "uuid",
            &VALID.replace("message-a", "550e8400-e29b-41d4-a716-446655440000"),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("messageAlias") }),
            "UUID-looking alias should be rejected: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_handler_error_text_is_rejected() -> Result<()> {
        let root = temp_root("handler-error")?;
        write_fixture(
            &root,
            "handler-error",
            &VALID.replace(
                "publish succeeds before settle crash",
                "handler error stacktrace",
            ),
        )?;
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("title") }),
            "handler error text should be rejected: {findings:?}"
        );
        Ok(())
    }
}
