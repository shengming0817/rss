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
//! INVARIANT: CONSISTENCY-FAULT-RUNNER-SYMBOL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_runner_symbol_must_be_canonical_run_function_path", anti_vacuity = "tests::green_real_tree_has_required_ready_fixtures" } -- every ready case binds a canonical top-level `run_*` function that becomes its exact assurance carrier.
//! INVARIANT: CONSISTENCY-FAULT-TYPED-SEAM-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_direct_sqlx_dependency_is_rejected + tests::red_package_aliased_sqlx_dependency_is_rejected_in_every_dependency_table + tests::red_critical_runner_typed_constructor_cannot_be_deleted + tests::red_critical_runner_fake_receiver_cannot_supply_provider_capability + tests::red_critical_runner_fake_publisher_and_direct_sql_remain_rejected + tests::red_catalog_closure_rejects_missing_normal_and_equal_count_replacement", anti_vacuity = "tests::green_real_tree_has_required_ready_fixtures + tests::specialized_fault_specs_exactly_match_typed_runner_projection" } -- critical runner constructors require sealed provider/conformance output types, assurance consumes the same exact typed runner registration, and the verifier rejects direct or aliased sqlx dependencies, raw SQL, fake publishers, and catalog/fixture/runner projection drift.

use crate::contract::GovernedContract;
use crate::contract::manifest::{ConsistencyLevel, Lifecycle};
use crate::diagnostic::{self, GovernanceCheck, finding};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::parse::{Parse, ParseStream};
use syn::{Expr, ExprArray, Ident, Item, Lit, Token, braced};

pub(crate) type Finding = diagnostic::Finding<Rule>;

const MIN_READY_CASES: usize = 12;
const MIN_READY_PER_MECHANISM: usize = 2;
const MAX_ALIAS_LEN: usize = 128;
const LONG_MATERIAL_MIN: usize = 32;
const JOURNEY_RUNNER_SOURCE: &str =
    "journeys-fault-matrix/tests/consistency_fault_matrix_journey.rs";
const SAGA_JOURNEY_RUNNER_SOURCE: &str = "journeys-fault-matrix/tests/saga_fault_recovery.rs";
const TESTKIT_FAULT_CATALOG_SOURCE: &str = "crates/testkit/src/crash_matrix.rs";
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
    CatalogClosure,
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

impl CrashMechanism {
    fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "Outbox" => Some(Self::Outbox),
            "Inbox" => Some(Self::Inbox),
            "Saga" => Some(Self::Saga),
            "Projection" => Some(Self::Projection),
            "Reconcile" => Some(Self::Reconcile),
            _ => None,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CrashFaultSpec(String);

impl CrashFaultSpec {
    fn variant(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SagaFaultCatalogEntry {
    fixture_id: String,
    contract_id: String,
    generated_contract: String,
    runner_symbol: String,
    test_symbol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FaultCatalogEntry {
    fault_spec: CrashFaultSpec,
    mechanism: CrashMechanism,
    crash_point: String,
    expected_invariant: String,
    runner: CrashRunner,
    execution: CrashExecutionKind,
    saga: Option<SagaFaultCatalogEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashExecutionKind {
    Normal,
    ConfirmLost,
    StaleContender,
    DeadlineExpired,
}

impl CrashExecutionKind {
    fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "Normal" => Some(Self::Normal),
            "ConfirmLost" => Some(Self::ConfirmLost),
            "StaleContender" => Some(Self::StaleContender),
            "DeadlineExpired" => Some(Self::DeadlineExpired),
            _ => None,
        }
    }

    fn is_specialized(self) -> bool {
        self != Self::Normal
    }
}

#[derive(Debug, Clone, Default)]
struct FaultCatalog {
    by_variant: BTreeMap<String, FaultCatalogEntry>,
}

impl FaultCatalog {
    fn entry_for_fixture(&self, fixture: &Fixture) -> Option<&FaultCatalogEntry> {
        self.by_variant.values().find(|entry| {
            entry.mechanism == fixture.mechanism
                && entry.crash_point == fixture.crash_point
                && entry.expected_invariant == fixture.expected_invariant
        })
    }

    fn by_variant(&self, variant: &str) -> Option<&FaultCatalogEntry> {
        self.by_variant.get(variant)
    }

    fn saga_entries(&self) -> impl Iterator<Item = (&FaultCatalogEntry, &SagaFaultCatalogEntry)> {
        self.by_variant
            .values()
            .filter_map(|entry| entry.saga.as_ref().map(|saga| (entry, saga)))
    }
}

struct FaultCatalogSyntax {
    entries: Vec<FaultCatalogSyntaxEntry>,
}

struct FaultCatalogSyntaxEntry {
    variant: Ident,
    mechanism: Ident,
    crash_point: syn::LitStr,
    expected_invariant: syn::LitStr,
    runner: Ident,
    execution: Ident,
    saga: Expr,
}

impl Parse for FaultCatalogSyntax {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut entries = Vec::new();
        while !input.is_empty() {
            let variant = input.parse()?;
            input.parse::<Token![=>]>()?;
            let content;
            braced!(content in input);
            parse_catalog_label(&content, "mechanism")?;
            let mechanism = content.parse()?;
            content.parse::<Token![,]>()?;
            parse_catalog_label(&content, "crash_point")?;
            let crash_point = content.parse()?;
            content.parse::<Token![,]>()?;
            parse_catalog_label(&content, "expected_invariant")?;
            let expected_invariant = content.parse()?;
            content.parse::<Token![,]>()?;
            parse_catalog_label(&content, "runner")?;
            let runner = content.parse()?;
            content.parse::<Token![,]>()?;
            parse_catalog_label(&content, "execution")?;
            let execution = content.parse()?;
            content.parse::<Token![,]>()?;
            parse_catalog_label(&content, "saga")?;
            let saga = content.parse()?;
            if content.peek(Token![,]) {
                content.parse::<Token![,]>()?;
            }
            if !content.is_empty() {
                return Err(content.error("unexpected fault catalog field"));
            }
            entries.push(FaultCatalogSyntaxEntry {
                variant,
                mechanism,
                crash_point,
                expected_invariant,
                runner,
                execution,
                saga,
            });
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            } else if !input.is_empty() {
                return Err(input.error("fault catalog entries must be comma-separated"));
            }
        }
        Ok(Self { entries })
    }
}

fn parse_catalog_label(input: ParseStream<'_>, expected: &str) -> syn::Result<()> {
    let label: Ident = input.parse()?;
    if label != expected {
        return Err(syn::Error::new(
            label.span(),
            format!("expected fault catalog field `{expected}`"),
        ));
    }
    input.parse::<Token![:]>()?;
    Ok(())
}

fn fault_catalog(root: &Path) -> Result<FaultCatalog, String> {
    let path = root.join(TESTKIT_FAULT_CATALOG_SOURCE);
    let src = crate::generated_file::read_stable_utf8_file(
        &path,
        MAX_RUNNER_SOURCE_BYTES,
        "testkit fault catalog source",
    )
    .map_err(|error| error.to_string())?;
    let syntax = syn::parse_file(&src).map_err(|error| format!("{}: {error}", path.display()))?;
    let invocation = syntax
        .items
        .iter()
        .find_map(|item| match item {
            Item::Macro(item)
                if item
                    .mac
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "define_crash_fault_catalog") =>
            {
                Some(&item.mac)
            }
            _ => None,
        })
        .ok_or_else(|| {
            format!(
                "{TESTKIT_FAULT_CATALOG_SOURCE}: define_crash_fault_catalog invocation not found"
            )
        })?;
    let parsed = syn::parse2::<FaultCatalogSyntax>(invocation.tokens.clone())
        .map_err(|error| format!("{TESTKIT_FAULT_CATALOG_SOURCE}: {error}"))?;
    let mut by_variant = BTreeMap::new();
    let mut saga_ids = BTreeSet::new();
    for entry in parsed.entries {
        let variant = entry.variant.to_string();
        let mechanism = CrashMechanism::from_rust_variant(&entry.mechanism.to_string())
            .ok_or_else(|| format!("unknown fault catalog mechanism `{}`", entry.mechanism))?;
        let runner = CrashRunner::from_rust_variant(&entry.runner.to_string())
            .ok_or_else(|| format!("unknown fault catalog runner `{}`", entry.runner))?;
        let execution = CrashExecutionKind::from_rust_variant(&entry.execution.to_string())
            .ok_or_else(|| format!("unknown fault catalog execution `{}`", entry.execution))?;
        let saga = parse_saga_catalog_expr(&entry.saga)?;
        if mechanism == CrashMechanism::Saga && saga.is_none() {
            return Err(format!(
                "Saga fault catalog variant `{variant}` must carry stable Saga metadata"
            ));
        }
        if mechanism != CrashMechanism::Saga && saga.is_some() {
            return Err(format!(
                "non-Saga fault catalog variant `{variant}` cannot carry Saga metadata"
            ));
        }
        if let Some(saga) = &saga
            && !saga_ids.insert(saga.fixture_id.clone())
        {
            return Err(format!(
                "duplicate Saga fixture id `{}` in fault catalog",
                saga.fixture_id
            ));
        }
        let catalog_entry = FaultCatalogEntry {
            fault_spec: CrashFaultSpec(variant.clone()),
            mechanism,
            crash_point: entry.crash_point.value(),
            expected_invariant: entry.expected_invariant.value(),
            runner,
            execution,
            saga,
        };
        if by_variant.insert(variant.clone(), catalog_entry).is_some() {
            return Err(format!("duplicate fault catalog variant `{variant}`"));
        }
    }
    if by_variant.is_empty() {
        return Err("fault catalog must not be empty".to_string());
    }
    Ok(FaultCatalog { by_variant })
}

fn parse_saga_catalog_expr(expr: &Expr) -> Result<Option<SagaFaultCatalogEntry>, String> {
    if let Expr::Path(path) = expr
        && path.path.is_ident("None")
    {
        return Ok(None);
    }
    let Expr::Call(call) = expr else {
        return Err("fault catalog saga metadata must be None or Some((...))".to_string());
    };
    let Expr::Path(function) = call.func.as_ref() else {
        return Err("fault catalog saga metadata must call Some".to_string());
    };
    if !function.path.is_ident("Some") || call.args.len() != 1 {
        return Err("fault catalog saga metadata must call Some once".to_string());
    }
    let Some(Expr::Tuple(tuple)) = call.args.first() else {
        return Err("fault catalog Saga metadata must be a tuple".to_string());
    };
    if tuple.elems.len() != 5 {
        return Err("fault catalog Saga metadata tuple must have five fields".to_string());
    }
    let mut values = tuple.elems.iter().map(|value| match value {
        Expr::Lit(literal) => match &literal.lit {
            Lit::Str(value) => Ok(value.value()),
            _ => Err("fault catalog Saga metadata fields must be strings".to_string()),
        },
        _ => Err("fault catalog Saga metadata fields must be strings".to_string()),
    });
    Ok(Some(SagaFaultCatalogEntry {
        fixture_id: values.next().transpose()?.unwrap_or_default(),
        contract_id: values.next().transpose()?.unwrap_or_default(),
        generated_contract: values.next().transpose()?.unwrap_or_default(),
        runner_symbol: values.next().transpose()?.unwrap_or_default(),
        test_symbol: values.next().transpose()?.unwrap_or_default(),
    }))
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
    execution: CrashExecutionKind,
    forbidden_bypass: bool,
    registry: RunnerRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerRegistry {
    Standard,
    Saga,
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

#[derive(Debug, Default)]
struct FixtureScan {
    ready_ids: BTreeSet<String>,
    fixture_fault_specs: BTreeSet<CrashFaultSpec>,
    ready_fault_specs: BTreeSet<CrashFaultSpec>,
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
    contracts: &[GovernedContract],
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
    match crate::contract::governance::ContractGovernanceIr::load_consumer_workspace(root) {
        Ok(governance) => governance
            .read(|contracts| Ok(validate_root_with_contracts(root, contracts)))
            .unwrap_or_else(|error| RootValidation {
                findings: vec![finding(
                    Rule::InvalidFixture,
                    "contracts",
                    format!("contract snapshot closeout failed: {error}"),
                )],
                ..RootValidation::default()
            }),
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
    discovered_contracts: &[GovernedContract],
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
    let catalog = match fault_catalog(root) {
        Ok(catalog) => catalog,
        Err(detail) => {
            findings.push(finding(
                Rule::InvalidFixture,
                TESTKIT_FAULT_CATALOG_SOURCE,
                detail,
            ));
            FaultCatalog::default()
        }
    };
    let journey_runners = match journey_runner_mappings_from_catalog(root, &catalog, || {}) {
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

    let scan = scan_fixture_corpus(root, &files, &contracts, &journey_runners, &catalog);
    add_orphan_runner_findings(&mut findings, &scan.ready_ids, &journey_runners);
    add_catalog_closure_findings(
        &mut findings,
        &scan.fixture_fault_specs,
        &scan.ready_fault_specs,
        &journey_runners,
        &catalog,
    );
    add_critical_fault_findings(&mut findings, &journey_runners, &catalog);
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
    catalog: &FaultCatalog,
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
        if let Some(entry) = catalog.entry_for_fixture(&fixture) {
            scan.fixture_fault_specs.insert(entry.fault_spec.clone());
        }
        if fixture.status == CrashStatus::Ready {
            scan.ready_count += 1;
            scan.ready_ids.insert(fixture.id.clone());
            *scan
                .ready_by_mechanism
                .entry(fixture.mechanism)
                .or_default() += 1;
            if let Some(entry) = catalog.entry_for_fixture(&fixture) {
                scan.ready_fault_specs.insert(entry.fault_spec.clone());
            }
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
            catalog,
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
    journey_runners: &BTreeMap<String, RunnerContract>,
    catalog: &FaultCatalog,
) {
    for expected in catalog
        .by_variant
        .values()
        .filter(|entry| entry.execution.is_specialized())
    {
        let matching = journey_runners
            .values()
            .filter(|runner| runner.fault_spec == expected.fault_spec)
            .collect::<Vec<_>>();
        if matching.is_empty()
            || matching
                .iter()
                .any(|runner| runner.execution != expected.execution || runner.forbidden_bypass)
        {
            findings.push(finding(
                Rule::CriticalCase,
                expected.fault_spec.variant(),
                format!(
                    "specialized fault spec must have a matching typed runner and real capability/conformance body: execution={:?}",
                    expected.execution
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

fn add_catalog_closure_findings(
    findings: &mut Vec<Finding>,
    fixture_fault_specs: &BTreeSet<CrashFaultSpec>,
    ready_fault_specs: &BTreeSet<CrashFaultSpec>,
    journey_runners: &BTreeMap<String, RunnerContract>,
    catalog: &FaultCatalog,
) {
    let expected_fixtures = catalog
        .by_variant
        .values()
        .map(|entry| entry.fault_spec.clone())
        .collect::<BTreeSet<_>>();
    add_fault_spec_set_diff(
        findings,
        "fixture projection",
        &expected_fixtures,
        fixture_fault_specs,
    );

    for (registry, label, expects_saga) in [
        (RunnerRegistry::Standard, JOURNEY_RUNNER_SOURCE, false),
        (RunnerRegistry::Saga, SAGA_JOURNEY_RUNNER_SOURCE, true),
    ] {
        let expected = ready_fault_specs
            .iter()
            .filter(|fault_spec| {
                catalog
                    .by_variant(fault_spec.variant())
                    .is_some_and(|entry| entry.saga.is_some() == expects_saga)
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let actual = journey_runners
            .values()
            .filter(|runner| runner.registry == registry)
            .map(|runner| runner.fault_spec.clone())
            .collect::<BTreeSet<_>>();
        add_fault_spec_set_diff(findings, label, &expected, &actual);
    }
}

fn add_fault_spec_set_diff(
    findings: &mut Vec<Finding>,
    carrier: &str,
    expected: &BTreeSet<CrashFaultSpec>,
    actual: &BTreeSet<CrashFaultSpec>,
) {
    let missing = expected
        .difference(actual)
        .map(CrashFaultSpec::variant)
        .collect::<Vec<_>>();
    let extra = actual
        .difference(expected)
        .map(CrashFaultSpec::variant)
        .collect::<Vec<_>>();
    if !missing.is_empty() || !extra.is_empty() {
        findings.push(finding(
            Rule::CatalogClosure,
            carrier,
            format!("fault catalog projection drift: missing={missing:?}, extra={extra:?}"),
        ));
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
    discovered_contracts: &[GovernedContract],
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
                    contract.manifest().id
                )
            })?
            .symbol;
        let manifest = contract.manifest();
        let owner_domain = contract.owner().as_str().to_owned();
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
    catalog: &FaultCatalog,
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
    if catalog.entry_for_fixture(fixture).is_none() {
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
                catalog,
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
    catalog: &FaultCatalog,
) {
    match catalog.entry_for_fixture(fixture) {
        Some(entry) if entry.fault_spec == runner.fault_spec => {}
        Some(entry) => findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "ready fixture `{}` maps to fault spec {:?}, but journey runner contract is {:?}",
                fixture.id, entry.fault_spec, runner.fault_spec
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
    if let Some(entry) = catalog.by_variant(runner.fault_spec.variant())
        && runner.runner != entry.runner
    {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "journey runner for `{}` binds runner {:?}, but fault spec {:?} expects {:?}",
                fixture.id, runner.runner, runner.fault_spec, entry.runner
            ),
        ));
    }
    if let Some(entry) = catalog.by_variant(runner.fault_spec.variant())
        && let Some(saga) = &entry.saga
        && (fixture.id != saga.fixture_id
            || fixture.contract_id != saga.contract_id
            || runner.generated_contract != saga.generated_contract
            || runner.runner_symbol != saga.runner_symbol)
    {
        findings.push(finding(
            Rule::RunnerMismatch,
            rel_path,
            format!(
                "Saga fixture `{}` must exactly match catalog identity `{}`, contract `{}`, generated contract `{}`, and runner symbol `{}`",
                fixture.id,
                saga.fixture_id,
                saga.contract_id,
                saga.generated_contract,
                saga.runner_symbol
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

#[cfg(test)]
fn journey_runner_mappings(root: &Path) -> Result<BTreeMap<String, RunnerContract>, String> {
    let catalog = fault_catalog(root)?;
    journey_runner_mappings_from_catalog(root, &catalog, || {})
}

#[cfg(test)]
fn journey_runner_mappings_with_hook(
    root: &Path,
    after_open: impl FnOnce(),
) -> Result<BTreeMap<String, RunnerContract>, String> {
    let catalog = fault_catalog(root)?;
    journey_runner_mappings_from_catalog(root, &catalog, after_open)
}

fn journey_runner_mappings_from_catalog(
    root: &Path,
    catalog: &FaultCatalog,
    after_open: impl FnOnce(),
) -> Result<BTreeMap<String, RunnerContract>, String> {
    let mut mappings = BTreeMap::new();
    let mut after_open = Some(after_open);
    for source in [JOURNEY_RUNNER_SOURCE, SAGA_JOURNEY_RUNNER_SOURCE] {
        let path = root.join(source);
        let src = crate::generated_file::read_stable_utf8_file_with_hook(
            &path,
            MAX_RUNNER_SOURCE_BYTES,
            "runner source",
            || {
                if let Some(hook) = after_open.take() {
                    hook();
                }
            },
        )
        .map_err(|error| error.to_string())?;
        let syntax = syn::parse_file(&src).map_err(|e| format!("{}: {e}", path.display()))?;
        let entries = ready_case_runner_array(&syntax)
            .ok_or_else(|| format!("{source}: READY_CASE_RUNNERS table not found"))?;
        let mut source_entries = BTreeMap::new();
        for entry in &entries.elems {
            let saga_registry = source == SAGA_JOURNEY_RUNNER_SOURCE;
            let (id, mut runner) = parse_journey_runner_entry(entry, catalog, saga_registry)?;
            if runner.execution.is_specialized() {
                runner.forbidden_bypass =
                    critical_runner_has_forbidden_bypass(&syntax, &runner.runner_symbol)?;
            }
            if source == SAGA_JOURNEY_RUNNER_SOURCE {
                source_entries.insert(id.clone(), runner.clone());
            }
            if mappings.insert(id.clone(), runner).is_some() {
                return Err(format!("duplicate journey runner mapping `{id}`"));
            }
        }
        if source == SAGA_JOURNEY_RUNNER_SOURCE {
            ensure_saga_catalog_registry(&syntax, &source_entries, catalog)?;
        }
    }
    if mappings.is_empty() {
        return Err("READY_CASE_RUNNERS table is empty".to_string());
    }
    Ok(mappings)
}

fn ensure_saga_catalog_registry(
    syntax: &syn::File,
    entries: &BTreeMap<String, RunnerContract>,
    catalog: &FaultCatalog,
) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }
    let expected_ids = catalog
        .saga_entries()
        .map(|(_, saga)| saga.fixture_id.clone())
        .collect::<BTreeSet<_>>();
    let actual_ids = entries.keys().cloned().collect::<BTreeSet<_>>();
    if actual_ids != expected_ids {
        return Err(format!(
            "Saga runner registry must exactly match the stable fault catalog: expected {expected_ids:?}, got {actual_ids:?}"
        ));
    }

    for (entry, saga) in catalog.saga_entries() {
        let runner = entries.get(&saga.fixture_id).ok_or_else(|| {
            format!(
                "Saga runner registry missing fixture `{}` after exact-set check",
                saga.fixture_id
            )
        })?;
        if runner.fault_spec != entry.fault_spec
            || runner.runner != entry.runner
            || runner.generated_contract != saga.generated_contract
            || runner.runner_symbol != saga.runner_symbol
        {
            return Err(format!(
                "Saga runner `{}` must exactly match stable catalog spec, provider, contract, and symbol",
                saga.fixture_id
            ));
        }
        let tests = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(function)
                    if function.sig.ident == saga.test_symbol
                        && function.attrs.iter().any(|attr| {
                            attr.path()
                                .segments
                                .last()
                                .is_some_and(|segment| segment.ident == "test")
                        }) =>
                {
                    Some(function)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if tests.len() != 1 {
            return Err(format!(
                "Saga case `{}` must own exactly one independent test `{}`",
                saga.fixture_id, saga.test_symbol
            ));
        }
    }
    Ok(())
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

fn parse_journey_runner_entry(
    entry: &Expr,
    catalog: &FaultCatalog,
    saga_registry: bool,
) -> Result<(String, RunnerContract), String> {
    let Expr::Call(call) = entry else {
        return Err("READY_CASE_RUNNERS entry must be ReadyCaseRunner::new(...)".to_string());
    };
    let execution = ready_case_runner_constructor(&call.func)?;
    let expected_args = if saga_registry { 3 } else { 5 };
    if call.args.len() != expected_args {
        return Err(format!(
            "ReadyCaseRunner::new must have {expected_args} arguments in this registry, got {}",
            call.args.len()
        ));
    }
    let mut args = call.args.iter();
    if saga_registry && execution.is_specialized() {
        return Err("Saga READY_CASE_RUNNERS entries must use ReadyCaseRunner::new".to_string());
    }
    let (id, fault_spec, runner) = if saga_registry {
        let fault_spec = crash_fault_spec_arg(args.next(), catalog)?;
        let entry = catalog
            .by_variant(fault_spec.variant())
            .ok_or_else(|| format!("unknown Saga fault spec `{}`", fault_spec.variant()))?;
        let saga = entry.saga.as_ref().ok_or_else(|| {
            format!(
                "non-Saga fault spec `{}` cannot appear in the Saga runner registry",
                fault_spec.variant()
            )
        })?;
        (saga.fixture_id.clone(), fault_spec, entry.runner)
    } else {
        (
            string_arg(args.next(), "id")?,
            crash_fault_spec_arg(args.next(), catalog)?,
            crash_runner_arg(args.next())?,
        )
    };
    let generated_contract = generated_contract_arg(args.next())?;
    let runner_symbol = runner_function_arg(args.next())?;
    let expected_execution = catalog
        .by_variant(fault_spec.variant())
        .ok_or_else(|| format!("unknown fault spec `{}`", fault_spec.variant()))?
        .execution;
    if execution != expected_execution {
        return Err(format!(
            "fault spec `{}` requires {expected_execution:?}, got {execution:?}",
            fault_spec.variant()
        ));
    }
    Ok((
        id,
        RunnerContract {
            fault_spec,
            runner,
            generated_contract,
            runner_symbol,
            execution,
            forbidden_bypass: false,
            registry: if saga_registry {
                RunnerRegistry::Saga
            } else {
                RunnerRegistry::Standard
            },
        },
    ))
}

fn ready_case_runner_constructor(expr: &Expr) -> Result<CrashExecutionKind, String> {
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
        "new" => Ok(CrashExecutionKind::Normal),
        "confirm_lost" => Ok(CrashExecutionKind::ConfirmLost),
        "stale_contender" => Ok(CrashExecutionKind::StaleContender),
        "deadline_expired" => Ok(CrashExecutionKind::DeadlineExpired),
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

fn crash_fault_spec_arg(
    expr: Option<&Expr>,
    catalog: &FaultCatalog,
) -> Result<CrashFaultSpec, String> {
    let Some(Expr::Path(path)) = expr else {
        return Err("ReadyCaseRunner::fault_spec must be a CrashFaultSpec variant".to_string());
    };
    let variant = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default();
    catalog
        .by_variant(&variant)
        .map(|entry| entry.fault_spec.clone())
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
    use anyhow::{Context, Result};
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

    const EMPTY_SAGA_JOURNEY_RUNNERS: &str = r#"
const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[];
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
        fs::write(
            root.join("contracts/event/identity/v1/session-created/payload.schema.json"),
            include_str!("../../contracts/event/identity/v1/session-created/payload.schema.json"),
        )?;
        fs::create_dir_all(root.join("journeys-fault-matrix/tests"))?;
        fs::write(
            root.join(JOURNEY_MANIFEST),
            "[package]\nname = \"journeys-fault-matrix\"\nversion = \"0.0.0\"\n\n[dependencies]\n\n[dev-dependencies]\n\n[build-dependencies]\n",
        )?;
        fs::write(root.join(JOURNEY_RUNNER_SOURCE), VALID_JOURNEY_RUNNERS)?;
        fs::write(
            root.join(SAGA_JOURNEY_RUNNER_SOURCE),
            EMPTY_SAGA_JOURNEY_RUNNERS,
        )?;
        let workspace = crate::workspace_root()?;
        let catalog = root.join(TESTKIT_FAULT_CATALOG_SOURCE);
        fs::create_dir_all(catalog.parent().context("testkit catalog parent")?)?;
        fs::copy(workspace.join(TESTKIT_FAULT_CATALOG_SOURCE), catalog)?;
        let relay = root.join("assemblies/runtime/src/event_transport.rs");
        fs::create_dir_all(relay.parent().context("runtime relay parent")?)?;
        fs::copy(
            workspace.join("assemblies/runtime/src/event_transport.rs"),
            relay,
        )?;
        Ok(root)
    }

    fn check_fixture_root(root: &Path) -> (String, Vec<Finding>) {
        match crate::contract::governance::ContractGovernanceIr::load_test_fixture_root(
            &root.join("contracts"),
        ) {
            Ok(governance) => governance
                .read(|contracts| Ok(validate_root_with_contracts(root, contracts)))
                .map(|validation| (validation.summary, validation.findings))
                .unwrap_or_else(|error| {
                    (
                        String::new(),
                        vec![finding(
                            Rule::InvalidFixture,
                            "contracts",
                            format!("contract snapshot closeout failed: {error}"),
                        )],
                    )
                }),
            Err(error) => (
                String::new(),
                vec![finding(
                    Rule::InvalidFixture,
                    "contracts",
                    format!("contract fixture discovery failed: {error}"),
                )],
            ),
        }
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
        let (_, findings) = check_fixture_root(&root);
        assert_eq!(findings[0].rule, Rule::MissingDirectory);
        Ok(())
    }

    #[test]
    fn red_unknown_field_is_parse_error() -> Result<()> {
        let root = temp_root("unknown")?;
        write_fixture(&root, "bad", &format!("{VALID}\nextraField = \"x\"\n"))?;
        let (_, findings) = check_fixture_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::Parse));
        Ok(())
    }

    #[test]
    fn red_duplicate_id_is_reported() -> Result<()> {
        let root = temp_root("duplicate")?;
        write_fixture(&root, "a", VALID)?;
        write_fixture(&root, "b", VALID)?;
        let (_, findings) = check_fixture_root(&root);
        assert!(findings.iter().any(|f| f.rule == Rule::DuplicateId));
        Ok(())
    }

    #[test]
    fn red_ready_count_floor_is_enforced() -> Result<()> {
        let root = temp_root("floor")?;
        write_fixture(&root, "one", VALID)?;
        let (_, findings) = check_fixture_root(&root);
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

        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
        assert!(
            findings.iter().any(|f| f.rule == Rule::RunnerMismatch),
            "runner mismatch should be reported: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn red_duplicate_runner_mapping_across_targets_is_rejected() -> Result<()> {
        let root = temp_root("duplicate-runner-target")?;
        fs::write(
            root.join(SAGA_JOURNEY_RUNNER_SOURCE),
            r#"
const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaForwardEffectBeforeCompletion,
        generated::saga::billing_v1::CONTRACT,
        run_saga_forward_effect_before_completion,
    ),
    ReadyCaseRunner::new(
        CrashFaultSpec::SagaForwardEffectBeforeCompletion,
        generated::saga::billing_v1::CONTRACT,
        run_saga_forward_effect_before_completion,
    ),
];
"#,
        )?;
        let Err(error) = journey_runner_mappings(&root) else {
            anyhow::bail!("duplicate runner identity in a typed target must fail closed")
        };
        assert!(
            error.contains(
                "duplicate journey runner mapping `saga-forward-effect-before-completion`"
            )
        );
        Ok(())
    }

    #[test]
    fn red_runner_string_and_comment_bait_are_not_mappings() -> Result<()> {
        let root = temp_root("runner-string-bait")?;
        fs::write(
            root.join(SAGA_JOURNEY_RUNNER_SOURCE),
            r#"
// ReadyCaseRunner::new("saga-bait", CrashFaultSpec::SagaRetryExhaustion,
// CrashRunner::PostgresRedis, generated::saga::billing_v1::CONTRACT, run_saga_bait)
const BAIT: &str = "ReadyCaseRunner::new(saga-bait)";
const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[];
"#,
        )?;
        let mappings = journey_runner_mappings(&root).map_err(anyhow::Error::msg)?;
        assert_eq!(mappings.len(), 1);
        assert!(!mappings.contains_key("saga-bait"));
        Ok(())
    }

    fn retry_exhaustion_catalog() -> FaultCatalog {
        let entry = FaultCatalogEntry {
            fault_spec: CrashFaultSpec("SagaRetryExhaustion".to_string()),
            mechanism: CrashMechanism::Saga,
            crash_point: "retry-exhaustion".to_string(),
            expected_invariant: "saga-retry-budget-exhausted".to_string(),
            runner: CrashRunner::PostgresRedis,
            execution: CrashExecutionKind::Normal,
            saga: Some(SagaFaultCatalogEntry {
                fixture_id: "saga-retry-exhaustion".to_string(),
                contract_id: "billing.checkout".to_string(),
                generated_contract: "generated::saga::billing_v1::CONTRACT".to_string(),
                runner_symbol: "run_saga_retry_exhaustion".to_string(),
                test_symbol: "saga_retry_exhaustion".to_string(),
            }),
        };
        FaultCatalog {
            by_variant: BTreeMap::from([("SagaRetryExhaustion".to_string(), entry)]),
        }
    }

    fn retry_exhaustion_runner() -> BTreeMap<String, RunnerContract> {
        BTreeMap::from([(
            "saga-retry-exhaustion".to_string(),
            RunnerContract {
                fault_spec: CrashFaultSpec("SagaRetryExhaustion".to_string()),
                runner: CrashRunner::PostgresRedis,
                generated_contract: "generated::saga::billing_v1::CONTRACT".to_string(),
                runner_symbol: "run_saga_retry_exhaustion".to_string(),
                execution: CrashExecutionKind::Normal,
                forbidden_bypass: false,
                registry: RunnerRegistry::Saga,
            },
        )])
    }

    #[test]
    fn saga_catalog_protocol_ignores_private_evidence_and_call_graph_details() -> Result<()> {
        let syntax = syn::parse_file(
            r#"
struct CompletelyDifferentPrivateReceipt;
fn renamed_private_router() { unreachable!() }
#[tokio::test]
async fn saga_retry_exhaustion() { renamed_private_router(); }
"#,
        )?;
        ensure_saga_catalog_registry(
            &syntax,
            &retry_exhaustion_runner(),
            &retry_exhaustion_catalog(),
        )
        .map_err(anyhow::Error::msg)?;
        Ok(())
    }

    #[test]
    fn red_saga_case_without_catalog_test_symbol_is_rejected() -> Result<()> {
        let syntax = syn::parse_file("fn private_implementation() {}")?;
        let Err(error) = ensure_saga_catalog_registry(
            &syntax,
            &retry_exhaustion_runner(),
            &retry_exhaustion_catalog(),
        ) else {
            anyhow::bail!("missing catalog test symbol must fail closed")
        };
        assert!(error.contains("exactly one independent test"));
        Ok(())
    }

    #[test]
    fn red_saga_runner_contract_drift_from_catalog_is_rejected() -> Result<()> {
        let syntax = syn::parse_file("#[test]\nfn saga_retry_exhaustion() {}")?;
        let mut runners = retry_exhaustion_runner();
        runners
            .get_mut("saga-retry-exhaustion")
            .context("fixture runner must exist")?
            .generated_contract = "generated::saga::billing_v2::CONTRACT".to_string();
        let Err(error) =
            ensure_saga_catalog_registry(&syntax, &runners, &retry_exhaustion_catalog())
        else {
            anyhow::bail!("catalog contract drift must fail closed")
        };
        assert!(error.contains("must exactly match stable catalog"));
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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

        let Err(error) =
            crate::contract::governance::ContractGovernanceIr::load_consumer_workspace(&root)
        else {
            anyhow::bail!("incomplete fixture corpus must fail the production validation funnel")
        };
        assert!(
            error.to_string().contains("contract governance rejected"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn real_ready_l2_evidence_closes_active_fact_projection() -> Result<()> {
        let root = crate::workspace_root()?;
        let governance = crate::contract::governance::ContractGovernanceIr::load_contracts_root(
            &root.join("contracts"),
        )?;
        let (expected, evidence) = governance.read(|contracts| {
            let expected = contracts
                .iter()
                .filter(|contract| {
                    contract.manifest().lifecycle == crate::contract::manifest::Lifecycle::Active
                        && contract.manifest().consistency_level == ConsistencyLevel::OutboxFact
                        && contract.manifest().kind
                            == crate::contract::manifest::ContractKind::Event
                        && contract
                            .manifest()
                            .capabilities
                            .outbox
                            .as_ref()
                            .is_some_and(|outbox| {
                                outbox.role == crate::contract::manifest::OutboxRole::Fact
                            })
                })
                .map(|contract| contract.manifest().id.clone())
                .collect::<BTreeSet<_>>();
            let evidence = ready_l2_fault_evidence_from_validated(&root, contracts)?;
            Ok((expected, evidence))
        })?;
        assert!(!expected.is_empty(), "active fact projection is empty");
        let actual = evidence
            .iter()
            .map(|item| item.contract_id.clone())
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
            let (_, findings) = check_fixture_root(&root);
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
        for (case_id, constructor) in [
            ("outbox-confirm-lost-channel-close", "confirm_lost"),
            ("outbox-stale-contender-settle", "stale_contender"),
            ("outbox-deadline-expired-settle", "deadline_expired"),
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
            let catalog = fault_catalog(&root).map_err(anyhow::Error::msg)?;
            let parsed = entries
                .elems
                .iter()
                .map(|entry| parse_journey_runner_entry(entry, &catalog, false))
                .collect::<Result<Vec<_>, _>>();
            assert!(
                parsed.is_err(),
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
        let catalog = fault_catalog(&crate::workspace_root()?).map_err(anyhow::Error::msg)?;
        let parsed = parse_journey_runner_entry(
            entries
                .elems
                .first()
                .ok_or_else(|| anyhow::anyhow!("missing synthetic runner"))?,
            &catalog,
            false,
        );
        assert!(
            parsed.is_err(),
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
    fn specialized_fault_specs_exactly_match_typed_runner_projection() -> Result<()> {
        let root = crate::workspace_root()?;
        let catalog = fault_catalog(&root).map_err(anyhow::Error::msg)?;
        let runners = journey_runner_mappings(&root).map_err(anyhow::Error::msg)?;
        let expected = catalog
            .by_variant
            .values()
            .filter(|entry| entry.execution.is_specialized())
            .map(|entry| entry.fault_spec.clone())
            .collect::<BTreeSet<_>>();
        let actual = runners
            .values()
            .filter(|runner| runner.execution.is_specialized())
            .map(|runner| runner.fault_spec.clone())
            .collect::<BTreeSet<_>>();
        assert!(!expected.is_empty());
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn red_catalog_closure_rejects_missing_normal_and_equal_count_replacement() -> Result<()> {
        let root = crate::workspace_root()?;
        let catalog = fault_catalog(&root).map_err(anyhow::Error::msg)?;
        let runners = journey_runner_mappings(&root).map_err(anyhow::Error::msg)?;
        let ready = runners
            .values()
            .map(|runner| runner.fault_spec.clone())
            .collect::<BTreeSet<_>>();
        let expected = catalog
            .by_variant
            .values()
            .map(|entry| entry.fault_spec.clone())
            .collect::<BTreeSet<_>>();
        let normal = catalog
            .by_variant
            .values()
            .find(|entry| entry.saga.is_none() && !entry.execution.is_specialized())
            .map(|entry| entry.fault_spec.clone())
            .ok_or_else(|| anyhow::anyhow!("normal non-Saga fault catalog must be non-vacuous"))?;

        let mut missing = expected.clone();
        missing.remove(&normal);
        let mut findings = Vec::new();
        add_catalog_closure_findings(&mut findings, &missing, &ready, &runners, &catalog);
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::CatalogClosure && finding.detail.contains(normal.variant())
        }));

        let mut replaced = missing;
        replaced.insert(CrashFaultSpec("EqualCountReplacement".to_string()));
        let mut findings = Vec::new();
        add_catalog_closure_findings(&mut findings, &replaced, &ready, &runners, &catalog);
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::CatalogClosure
                && finding.detail.contains(normal.variant())
                && finding.detail.contains("EqualCountReplacement")
        }));
        Ok(())
    }

    #[test]
    fn stable_fault_catalog_is_the_single_xtask_fault_spec_source() -> Result<()> {
        let root = crate::workspace_root()?;
        let xtask_src = fs::read_to_string(root.join("xtask/src/consistency_fixtures.rs"))?;
        let catalog = fault_catalog(&root).map_err(anyhow::Error::msg)?;
        let syntax = syn::parse_file(&xtask_src)?;

        assert!(!catalog.by_variant.is_empty());
        assert!(
            !syntax
                .items
                .iter()
                .any(|item| matches!(item, Item::Enum(item) if item.ident == "CrashFaultSpec"))
        );
        Ok(())
    }

    #[test]
    fn real_saga_fixtures_and_runner_registry_are_exact_and_non_vacuous() -> Result<()> {
        let root = crate::workspace_root()?;
        let catalog = fault_catalog(&root).map_err(anyhow::Error::msg)?;
        let runners = journey_runner_mappings(&root).map_err(anyhow::Error::msg)?;
        let saga_dir = root.join("fixtures/consistency/saga");
        let mut fixture_ids = BTreeSet::new();
        for entry in fs::read_dir(&saga_dir)? {
            let path = entry?.path();
            if !is_fixture_toml(&path) {
                continue;
            }
            let fixture: Fixture = toml::from_str(&fs::read_to_string(path)?)?;
            if fixture.status == CrashStatus::Ready {
                fixture_ids.insert(fixture.id);
            }
        }
        let expected = catalog
            .saga_entries()
            .map(|(entry, saga)| (saga.fixture_id.clone(), entry, saga))
            .collect::<Vec<_>>();
        let expected_ids = expected
            .iter()
            .map(|(id, _, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let runner_ids = runners
            .keys()
            .filter(|id| expected_ids.contains(*id))
            .cloned()
            .collect::<BTreeSet<_>>();

        assert!(
            !expected_ids.is_empty(),
            "Saga catalog must stay non-vacuous"
        );
        assert_eq!(fixture_ids, expected_ids);
        assert_eq!(runner_ids, expected_ids);
        for (id, entry, saga) in expected {
            let runner = runners
                .get(&id)
                .with_context(|| format!("catalog runner `{id}` must exist"))?;
            assert_eq!(runner.fault_spec, entry.fault_spec);
            assert_eq!(runner.runner, entry.runner);
            assert_eq!(runner.generated_contract, saga.generated_contract);
            assert_eq!(runner.runner_symbol, saga.runner_symbol);
        }
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
        let (_, findings) = check_fixture_root(&root);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::InvalidFixture
                    && f.detail.contains("crashPoint/expectedInvariant must map")
            }),
            "closed fault spec mismatch should be reported: {findings:?}"
        );
        Ok(())
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
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
        let (_, findings) = check_fixture_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::InvalidFixture && f.detail.contains("title") }),
            "handler error text should be rejected: {findings:?}"
        );
        Ok(())
    }
}
