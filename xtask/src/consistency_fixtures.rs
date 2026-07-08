//! Consistency crash fixture gate.
//!
//! Scans `fixtures/consistency/**/fixture-*.toml` and keeps the N-028 crash
//! matrix machine-visible. This is a no-compile governance gate: it validates
//! fixture shape, redaction boundaries, ready-case coverage, and journey runner
//! mappings. Real backend recovery is executed by the opt-in
//! `consistency-fault-matrix` lane.
//!
//! INVARIANT: CONSISTENCY-CRASH-FIXTURE-01 { level = "Medium", exec = "verify", source = "code" } -- consistency crash fixture ids must be unique and fixtures must parse as the closed TOML DSL.
//! INVARIANT: CONSISTENCY-FAULT-MATRIX-01 { level = "Medium", exec = "verify", source = "code" } -- N-028 ready cases must cover all consistency mechanisms and each ready fixture must have a real journey runner mapping.

use crate::contract::manifest::{ConsistencyLevel, ContractManifest, ContractOwner};
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
const JOURNEY_RUNNER_SOURCE: &str = "journeys/tests/consistency_fault_matrix_journey.rs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingDirectory,
    MissingReadme,
    NoFixtures,
    Parse,
    InvalidFixture,
    DuplicateId,
    ReadyCount,
    MechanismCoverage,
    MissingRunnerMapping,
    RunnerMismatch,
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
}

impl CrashRunner {
    fn from_rust_variant(value: &str) -> Option<Self> {
        match value {
            "Postgres" => Some(Self::Postgres),
            "Rabbitmq" => Some(Self::Rabbitmq),
            "PostgresRabbitmq" => Some(Self::PostgresRabbitmq),
            _ => None,
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
    domain: String,
    contract_id: String,
    crash_point: String,
    expected_invariant: String,
    runner: CrashRunner,
}

#[derive(Debug, Clone)]
struct ContractEntry {
    owner_domain: String,
    consistency_level: ConsistencyLevel,
}

#[derive(Debug, Default)]
struct FixtureScan {
    ready_ids: BTreeSet<String>,
    ready_count: usize,
    ready_by_mechanism: BTreeMap<CrashMechanism, usize>,
    findings: Vec<Finding>,
}

fn check_root(root: &Path) -> (String, Vec<Finding>) {
    let dir = root.join("fixtures").join("consistency");
    let mut findings = Vec::new();
    if !dir.is_dir() {
        findings.push(finding(
            Rule::MissingDirectory,
            rel(root, &dir),
            "fixtures/consistency directory is required",
        ));
        return (String::new(), findings);
    }
    if !dir.join("README.md").is_file() {
        findings.push(finding(
            Rule::MissingReadme,
            "fixtures/consistency/README.md",
            "README must describe how to add consistency crash cases",
        ));
    }

    let mut files = Vec::new();
    if let Err(e) = collect_fixture_files(&dir, &mut files) {
        findings.push(finding(Rule::MissingDirectory, rel(root, &dir), e));
        return (String::new(), findings);
    }
    files.sort();
    if files.is_empty() {
        findings.push(finding(
            Rule::NoFixtures,
            rel(root, &dir),
            "no fixture-*.toml files found",
        ));
        return (String::new(), findings);
    }

    let contracts = match contract_index(root) {
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
    findings.extend(scan.findings);
    add_orphan_runner_findings(&mut findings, &scan.ready_ids, &journey_runners);
    add_ready_coverage_findings(
        &mut findings,
        root,
        &dir,
        scan.ready_count,
        &scan.ready_by_mechanism,
    );

    let summary = format!(
        "{} fixture files scanned, {} ready cases",
        files.len(),
        scan.ready_count
    );
    (summary, findings)
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
        let src = match std::fs::read_to_string(path) {
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
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_fixture_files(&path, out)?;
        } else if is_fixture_toml(&path) {
            out.push(path);
        }
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

fn contract_index(root: &Path) -> Result<BTreeMap<String, ContractEntry>, String> {
    let dir = root.join("contracts");
    if !dir.is_dir() {
        return Err("contracts directory is required for contractId validation".to_string());
    }

    let mut files = Vec::new();
    collect_contract_files(&dir, &mut files)?;
    let mut contracts = BTreeMap::new();
    for path in files {
        let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let manifest = ContractManifest::from_toml_str(&src)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let owner_domain = match manifest.owner {
            ContractOwner::Domain(owner) => owner,
            ContractOwner::Framework => "_framework".to_string(),
        };
        let consistency_level = manifest.consistency_level;
        if contracts
            .insert(
                manifest.id.clone(),
                ContractEntry {
                    owner_domain,
                    consistency_level,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate contract id `{}`", manifest.id));
        }
    }

    Ok(contracts)
}

fn collect_contract_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_contract_files(&path, out)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("contract.toml") {
            out.push(path);
        }
    }
    Ok(())
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
    if fixture.status == CrashStatus::Ready {
        match journey_runners.get(&fixture.id) {
            Some(runner) => validate_runner_contract(&mut findings, rel_path, fixture, runner),
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
) {
    for (field, declared, mapped) in [
        ("domain", fixture.domain.as_str(), runner.domain.as_str()),
        (
            "contractId",
            fixture.contract_id.as_str(),
            runner.contract_id.as_str(),
        ),
        (
            "crashPoint",
            fixture.crash_point.as_str(),
            runner.crash_point.as_str(),
        ),
        (
            "expectedInvariant",
            fixture.expected_invariant.as_str(),
            runner.expected_invariant.as_str(),
        ),
    ] {
        if declared != mapped {
            findings.push(finding(
                Rule::RunnerMismatch,
                rel_path,
                format!(
                    "ready fixture `{}` declares {field} `{declared}`, but journey runner contract is `{mapped}`",
                    fixture.id
                ),
            ));
        }
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
}

fn journey_runner_mappings(root: &Path) -> Result<BTreeMap<String, RunnerContract>, String> {
    let path = root.join(JOURNEY_RUNNER_SOURCE);
    let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let syntax = syn::parse_file(&src).map_err(|e| format!("{}: {e}", path.display()))?;
    let entries = ready_case_runner_array(&syntax)
        .ok_or_else(|| "READY_CASE_RUNNERS table not found".to_string())?;
    let mut mappings = BTreeMap::new();
    for entry in &entries.elems {
        let (id, runner) = parse_journey_runner_entry(entry)?;
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
    if !expr_path_ends_with(&call.func, &["ReadyCaseRunner", "new"]) {
        return Err("READY_CASE_RUNNERS entry must call ReadyCaseRunner::new".to_string());
    }
    if call.args.len() != 7 {
        return Err(format!(
            "ReadyCaseRunner::new must have 7 arguments, got {}",
            call.args.len()
        ));
    }
    let mut args = call.args.iter();
    let id = string_arg(args.next(), "id")?;
    let domain = string_arg(args.next(), "domain")?;
    let contract_id = string_arg(args.next(), "contractId")?;
    let crash_point = string_arg(args.next(), "crashPoint")?;
    let expected_invariant = string_arg(args.next(), "expectedInvariant")?;
    let runner = crash_runner_arg(args.next())?;
    Ok((
        id,
        RunnerContract {
            domain,
            contract_id,
            crash_point,
            expected_invariant,
            runner,
        },
    ))
}

fn expr_path_ends_with(expr: &Expr, suffix: &[&str]) -> bool {
    let Expr::Path(path) = expr else {
        return false;
    };
    let segment_count = path.path.segments.len();
    if segment_count < suffix.len() {
        return false;
    }
    path.path
        .segments
        .iter()
        .skip(segment_count - suffix.len())
        .zip(suffix)
        .all(|(segment, expected)| segment.ident == *expected)
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

[subscriptions.topology]
partitionKey = "none"
readiness = "required"
"#;

    const VALID_JOURNEY_RUNNERS: &str = r#"
const READY_CASE_RUNNERS: &[ReadyCaseRunner] = &[
    ReadyCaseRunner::new(
        "outbox-after-publish-before-settle",
        "identity",
        "identity.session-created",
        "after-publish-before-settle",
        "outbox-publish-settled-once",
        CrashRunner::PostgresRabbitmq,
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
        fs::write(root.join("fixtures/consistency/README.md"), "fixture docs")?;
        fs::create_dir_all(root.join("contracts/event/identity/v1/session-created"))?;
        fs::write(
            root.join("contracts/event/identity/v1/session-created/contract.toml"),
            VALID_CONTRACT,
        )?;
        fs::create_dir_all(root.join("journeys/tests"))?;
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
                f.rule == Rule::RunnerMismatch && f.detail.contains("expectedInvariant")
            }),
            "runner expectedInvariant mismatch should be reported: {findings:?}"
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
        let (_, findings) = check_root(&root);
        assert!(
            findings
                .iter()
                .any(|f| { f.rule == Rule::RunnerMismatch && f.detail.contains("contractId") }),
            "runner contractId mismatch should be reported: {findings:?}"
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
