//! Deterministic LocalTx static proof inventory projection.

use crate::ReportFormat;
use crate::localtx_coverage::{
    LocalTxProofEvidence, LocalTxProofInventory, collect_workspace_inventory,
    localtx_boundary_label, localtx_commit_unknown_label, localtx_model_label, localtx_retry_label,
};
use anyhow::{Context, Result, bail};
use observ::{LocalTxActionableAlert, LocalTxOperationsDescriptor, localtx_operations_descriptor};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Component, Path};

const SCHEMA_VERSION: u8 = 1;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ReportStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum EvidenceScope {
    StaticInventory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum EvidenceStatus {
    Complete,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportFinding {
    rule: String,
    subject: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceProjection {
    status: EvidenceStatus,
    sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractEvidence {
    manifest: EvidenceProjection,
    generated: EvidenceProjection,
    route: EvidenceProjection,
    test: EvidenceProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CapabilityProjection {
    boundary: String,
    tx_model: String,
    retry: String,
    commit_unknown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservedProbe {
    probe: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackendProfileProjection {
    provider: String,
    fixture: String,
    provider_status: BackendProviderStatus,
    status: BackendProfileStatus,
    sources: Vec<String>,
    required_probes: Vec<String>,
    observed_probes: Vec<ObservedProbe>,
    missing_probes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum BackendProviderStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum BackendProfileStatus {
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct JourneyScenarioProjection {
    kind: String,
    applicable: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct JourneyProjection {
    spec: String,
    fixture: String,
    runner: String,
    scenarios: Vec<JourneyScenarioProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ContractProjection {
    contract_id: String,
    owner: String,
    capability: CapabilityProjection,
    evidence: ContractEvidence,
    backend_profiles: Vec<BackendProfileProjection>,
    journey: JourneyProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationMetric {
    name: &'static str,
    purpose: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationAlert {
    name: &'static str,
    final_status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RetryPressure {
    classification: &'static str,
    metric: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum OperationsValidation {
    ReferenceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsProjection {
    validation: OperationsValidation,
    included_in_report_status: bool,
    metrics: Vec<OperationMetric>,
    alerts: Vec<OperationAlert>,
    retry_pressure: RetryPressure,
    rules: &'static str,
    runbook: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct LocalTxReport {
    schema_version: u8,
    status: ReportStatus,
    evidence_scope: EvidenceScope,
    active_local_tx_contract_count: usize,
    operations: OperationsProjection,
    findings: Vec<ReportFinding>,
    contracts: Vec<ContractProjection>,
}

/// Collect and render the complete artifact before the sole stdout write. Structural collection,
/// validation, serialization, or writer failures can never leave a plausible partial report.
pub(crate) fn run_report(format: ReportFormat) -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts
        .get()
        .context("localtx report: load command-scoped workspace facts")?;
    let stdout = std::io::stdout();
    run_report_with(format, || collect_report(&root, facts), &mut stdout.lock())
}

fn run_report_with<W, C>(format: ReportFormat, collect: C, writer: &mut W) -> Result<()>
where
    W: Write,
    C: FnOnce() -> Result<LocalTxReport>,
{
    let report = collect()?;
    let rendered = render_report(&report, format)?;
    writer
        .write_all(rendered.as_bytes())
        .context("write LocalTx proof report")
}

fn collect_report(root: &Path, facts: &workspacefacts::WorkspaceFacts) -> Result<LocalTxReport> {
    let inventory = collect_workspace_inventory(root, facts)?;
    let operations = collect_operations(root)?;
    project_inventory(&inventory, operations)
}

fn project_inventory(
    inventory: &LocalTxProofInventory,
    operations: OperationsProjection,
) -> Result<LocalTxReport> {
    let evaluated_findings = inventory.findings();
    let findings = evaluated_findings
        .iter()
        .map(|finding| ReportFinding {
            rule: finding.rule.report_wire().to_string(),
            subject: finding.subject.clone(),
            detail: finding.detail.clone(),
        })
        .collect::<Vec<_>>();
    let mut contracts = Vec::with_capacity(inventory.contracts().len());
    for contract in inventory.contracts() {
        let mut backend_profiles = contract
            .backend_profiles()
            .iter()
            .map(|profile| BackendProfileProjection {
                provider: profile.provider().to_string(),
                fixture: profile.fixture().to_string(),
                provider_status: if profile.valid_provider() {
                    BackendProviderStatus::Valid
                } else {
                    BackendProviderStatus::Invalid
                },
                status: if profile.complete() {
                    BackendProfileStatus::Complete
                } else {
                    BackendProfileStatus::Failed
                },
                sources: profile.sources().to_vec(),
                required_probes: profile.required_probes().map(ToString::to_string).collect(),
                observed_probes: profile
                    .observed_probes()
                    .map(|(probe, count)| ObservedProbe {
                        probe: probe.to_string(),
                        count,
                    })
                    .collect(),
                missing_probes: profile.missing_probes().map(ToString::to_string).collect(),
            })
            .collect::<Vec<_>>();
        backend_profiles.sort_by(|left, right| {
            (&left.provider, &left.fixture).cmp(&(&right.provider, &right.fixture))
        });
        let mut scenarios = contract
            .journey()
            .scenarios()
            .iter()
            .map(|scenario| JourneyScenarioProjection {
                kind: scenario.kind().to_string(),
                applicable: scenario.applicable(),
                reason: scenario.reason().map(ToString::to_string),
            })
            .collect::<Vec<_>>();
        scenarios.sort_by(|left, right| left.kind.cmp(&right.kind));
        contracts.push(ContractProjection {
            contract_id: contract.contract_id().to_string(),
            owner: contract.owner().to_string(),
            capability: CapabilityProjection {
                boundary: localtx_boundary_label(contract.boundary()).to_string(),
                tx_model: localtx_model_label(contract.tx_model()).to_string(),
                retry: localtx_retry_label(contract.retry()).to_string(),
                commit_unknown: localtx_commit_unknown_label(contract.commit_unknown()).to_string(),
            },
            evidence: ContractEvidence {
                manifest: project_evidence(contract.manifest()),
                generated: project_evidence(contract.generated()),
                route: project_evidence(contract.route()),
                test: project_evidence(contract.test()),
            },
            backend_profiles,
            journey: JourneyProjection {
                spec: contract.journey().spec().to_string(),
                fixture: contract.journey().fixture().to_string(),
                runner: contract.journey().runner().to_string(),
                scenarios,
            },
        });
    }
    contracts.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    let mut report = LocalTxReport {
        schema_version: SCHEMA_VERSION,
        status: if findings.is_empty() {
            ReportStatus::Passed
        } else {
            ReportStatus::Failed
        },
        evidence_scope: EvidenceScope::StaticInventory,
        active_local_tx_contract_count: contracts.len(),
        operations,
        findings,
        contracts,
    };
    normalize_report(&mut report);
    validate_report(&report)?;
    Ok(report)
}

fn normalize_report(report: &mut LocalTxReport) {
    report.findings.sort_by(|left, right| {
        (&left.rule, &left.subject, &left.detail).cmp(&(&right.rule, &right.subject, &right.detail))
    });
    for contract in &mut report.contracts {
        for evidence in [
            &mut contract.evidence.manifest,
            &mut contract.evidence.generated,
            &mut contract.evidence.route,
            &mut contract.evidence.test,
        ] {
            evidence.sources.sort();
        }
        contract.backend_profiles.sort_by(|left, right| {
            (&left.provider, &left.fixture).cmp(&(&right.provider, &right.fixture))
        });
        for profile in &mut contract.backend_profiles {
            profile.sources.sort();
            profile.required_probes.sort();
            profile
                .observed_probes
                .sort_by(|left, right| left.probe.cmp(&right.probe));
            profile.missing_probes.sort();
        }
        contract
            .journey
            .scenarios
            .sort_by(|left, right| left.kind.cmp(&right.kind));
    }
    report
        .contracts
        .sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
}

fn project_evidence(evidence: &LocalTxProofEvidence) -> EvidenceProjection {
    EvidenceProjection {
        status: if evidence.complete() {
            EvidenceStatus::Complete
        } else {
            EvidenceStatus::Missing
        },
        sources: evidence.sources().to_vec(),
    }
}

fn operations_projection_from_descriptor() -> OperationsProjection {
    let descriptor = localtx_operations_descriptor();
    OperationsProjection {
        validation: OperationsValidation::ReferenceOnly,
        included_in_report_status: false,
        metrics: descriptor
            .metrics()
            .iter()
            .map(|metric| OperationMetric {
                name: metric.name(),
                purpose: metric.purpose().as_label(),
            })
            .collect(),
        alerts: descriptor
            .alerts()
            .iter()
            .map(|alert| OperationAlert {
                name: alert.name(),
                final_status: alert.final_status().as_label(),
            })
            .collect(),
        retry_pressure: RetryPressure {
            classification: descriptor.retry_classification().as_label(),
            metric: descriptor.retry_metric().name(),
        },
        rules: descriptor.rules_path(),
        runbook: descriptor.runbook_path(),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedAlert {
    name: String,
    expression: String,
    runbook: String,
}

fn collect_operations(root: &Path) -> Result<OperationsProjection> {
    let descriptor = localtx_operations_descriptor();
    if !descriptor.is_consistent() {
        bail!("LocalTx operations descriptor is internally inconsistent");
    }
    validate_relative_source(descriptor.rules_path())?;
    validate_relative_source(descriptor.runbook_path())?;
    let rules = read_carrier(root, descriptor.rules_path())?;
    let runbook = read_carrier(root, descriptor.runbook_path())?;
    validate_alert_rules(&rules, &runbook, descriptor)?;
    Ok(operations_projection_from_descriptor())
}

fn read_carrier(root: &Path, relative: &str) -> Result<String> {
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            bail!("LocalTx operations carrier path is not workspace-relative");
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("read LocalTx operations carrier {relative}"))?;
        if metadata.file_type().is_symlink() {
            bail!("LocalTx operations carrier traverses a symlink: {relative}");
        }
    }
    fs::read_to_string(&current)
        .with_context(|| format!("read LocalTx operations carrier {relative}"))
}

fn validate_alert_rules(
    rules: &str,
    runbook: &str,
    descriptor: &LocalTxOperationsDescriptor,
) -> Result<()> {
    let parsed = parse_localtx_alerts(rules)?;
    let expected_names = descriptor
        .alerts()
        .iter()
        .map(|alert| alert.name())
        .collect::<BTreeSet<_>>();
    let observed_names = parsed
        .iter()
        .map(|alert| alert.name.as_str())
        .collect::<BTreeSet<_>>();
    if parsed.len() != descriptor.alerts().len() || observed_names != expected_names {
        bail!("LocalTx alert rules do not match the typed operations descriptor exactly");
    }
    for alert in descriptor.alerts() {
        let observed = parsed
            .iter()
            .find(|candidate| candidate.name == alert.name())
            .context("typed LocalTx alert is missing from the rules carrier")?;
        if observed.expression != expected_alert_expression(*alert) {
            bail!("LocalTx alert expression drifted from its typed metric/final-status contract");
        }
        let expected_runbook = format!("{}#{}", descriptor.runbook_path(), alert.runbook_anchor());
        if observed.runbook != expected_runbook {
            bail!("LocalTx alert runbook path or anchor drifted");
        }
        if !markdown_has_anchor(runbook, alert.runbook_anchor()) {
            bail!("LocalTx alert runbook anchor is missing");
        }
    }
    Ok(())
}

fn parse_localtx_alerts(rules: &str) -> Result<Vec<ParsedAlert>> {
    #[derive(Default)]
    struct PendingAlert {
        name: String,
        expression: Option<String>,
        runbook: Option<String>,
    }

    fn finish(pending: PendingAlert, parsed: &mut Vec<ParsedAlert>) -> Result<()> {
        if pending.name.starts_with("LocalTx") {
            parsed.push(ParsedAlert {
                name: pending.name,
                expression: pending
                    .expression
                    .context("LocalTx alert is missing expr")?,
                runbook: pending
                    .runbook
                    .context("LocalTx alert is missing runbook")?,
            });
        }
        Ok(())
    }

    fn set_once(slot: &mut Option<String>, value: String, field: &str) -> Result<()> {
        if slot.replace(value).is_some() {
            bail!("LocalTx alert contains duplicate {field} fields");
        }
        Ok(())
    }

    let mut parsed = Vec::new();
    let mut pending = None;
    for line in rules.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("- alert: ") {
            if let Some(previous) = pending.take() {
                finish(previous, &mut parsed)?;
            }
            pending = Some(PendingAlert {
                name: name.trim_matches('"').to_string(),
                ..PendingAlert::default()
            });
        } else if let Some(current) = pending.as_mut() {
            if let Some(expression) = trimmed.strip_prefix("expr: ") {
                set_once(
                    &mut current.expression,
                    expression.trim_matches('"').to_string(),
                    "expr",
                )?;
            } else if let Some(runbook) = trimmed.strip_prefix("runbook: ") {
                set_once(
                    &mut current.runbook,
                    runbook.trim_matches('"').to_string(),
                    "runbook",
                )?;
            }
        }
    }
    if let Some(last) = pending {
        finish(last, &mut parsed)?;
    }
    Ok(parsed)
}

fn expected_alert_expression(alert: LocalTxActionableAlert) -> String {
    format!(
        "sum by (domain, contract_id, boundary) (increase({}{{final_status=\"{}\"}}[5m])) > 0",
        alert.metric().name(),
        alert.final_status().as_label()
    )
}

fn markdown_has_anchor(markdown: &str, expected: &str) -> bool {
    markdown.lines().any(|line| {
        let Some(heading) = line.trim_start().strip_prefix('#') else {
            return false;
        };
        let heading = heading.trim_start_matches('#').trim();
        let mut slug = String::new();
        for character in heading.chars() {
            if character.is_ascii_alphanumeric() {
                slug.push(character.to_ascii_lowercase());
            } else if (character.is_whitespace() || character == '-') && !slug.ends_with('-') {
                slug.push('-');
            }
        }
        slug.trim_matches('-') == expected
    })
}

fn render_report(report: &LocalTxReport, format: ReportFormat) -> Result<String> {
    validate_report(report)?;
    match format {
        ReportFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(report)?)),
        ReportFormat::Markdown => Ok(render_markdown(report)),
    }
}

fn validate_report(report: &LocalTxReport) -> Result<()> {
    if report.schema_version != SCHEMA_VERSION {
        bail!("unsupported LocalTx proof schema version");
    }
    if report.evidence_scope != EvidenceScope::StaticInventory {
        bail!("LocalTx proof evidence scope must be staticInventory");
    }
    if report.active_local_tx_contract_count != report.contracts.len() {
        bail!("activeLocalTxContractCount does not match contracts");
    }
    if (report.status == ReportStatus::Passed) != report.findings.is_empty() {
        bail!("LocalTx proof status does not match findings");
    }
    if report.operations.validation != OperationsValidation::ReferenceOnly
        || report.operations.included_in_report_status
    {
        bail!("operations references must not contribute to LocalTx proof status");
    }
    if report.operations != operations_projection_from_descriptor() {
        bail!("operations projection drifted from the typed owner descriptor");
    }
    if !strictly_sorted_by(&report.findings, |left, right| {
        (&left.rule, &left.subject, &left.detail).cmp(&(&right.rule, &right.subject, &right.detail))
    }) {
        bail!("LocalTx proof findings must be strictly sorted and unique");
    }
    if !strictly_sorted_by(&report.contracts, |left, right| {
        left.contract_id.cmp(&right.contract_id)
    }) {
        bail!("LocalTx proof contracts must be strictly sorted and unique");
    }
    for contract in &report.contracts {
        for evidence in [
            &contract.evidence.manifest,
            &contract.evidence.generated,
            &contract.evidence.route,
            &contract.evidence.test,
        ] {
            if !strictly_sorted_by(&evidence.sources, String::cmp) {
                bail!("LocalTx proof evidence sources must be strictly sorted and unique");
            }
        }
        if !strictly_sorted_by(&contract.backend_profiles, |left, right| {
            (&left.provider, &left.fixture).cmp(&(&right.provider, &right.fixture))
        }) {
            bail!("LocalTx backend profiles must be strictly sorted and unique");
        }
        if !strictly_sorted_by(&contract.journey.scenarios, |left, right| {
            left.kind.cmp(&right.kind)
        }) {
            bail!("LocalTx journey scenarios must be strictly sorted and unique");
        }
        for profile in &contract.backend_profiles {
            if !strictly_sorted_by(&profile.sources, String::cmp)
                || !strictly_sorted_by(&profile.required_probes, String::cmp)
                || !strictly_sorted_by(&profile.observed_probes, |left, right| {
                    left.probe.cmp(&right.probe)
                })
                || !strictly_sorted_by(&profile.missing_probes, String::cmp)
            {
                bail!("LocalTx backend profile evidence must be strictly sorted and unique");
            }
            let expected_status = if profile.provider_status == BackendProviderStatus::Valid
                && profile.missing_probes.is_empty()
            {
                BackendProfileStatus::Complete
            } else {
                BackendProfileStatus::Failed
            };
            if profile.status != expected_status {
                bail!("LocalTx backend profile status does not match normalized evidence");
            }
        }
        for source in contract
            .evidence
            .manifest
            .sources
            .iter()
            .chain(&contract.evidence.generated.sources)
            .chain(&contract.evidence.route.sources)
            .chain(&contract.evidence.test.sources)
            .chain(
                contract
                    .backend_profiles
                    .iter()
                    .flat_map(|profile| profile.sources.iter()),
            )
            .chain([
                &contract.journey.spec,
                &contract.journey.fixture,
                &contract.journey.runner,
            ])
        {
            validate_relative_source(source)?;
        }
    }
    Ok(())
}

fn strictly_sorted_by<T>(items: &[T], compare: impl Fn(&T, &T) -> Ordering) -> bool {
    items
        .windows(2)
        .all(|pair| compare(&pair[0], &pair[1]) == Ordering::Less)
}

fn validate_relative_source(source: &str) -> Result<()> {
    let path = Path::new(source);
    if source.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("LocalTx proof source is not a workspace-relative path");
    }
    Ok(())
}

fn render_markdown(report: &LocalTxReport) -> String {
    let mut output = format!(
        "# LocalTx Proof Report\n\nStatic inventory status: **{}** · Active LocalTx contracts: **{}** · Findings: **{}**\n\nEvidence scope: `staticInventory`. This artifact does not claim real-backend execution or promtool validation.\n\n## Operations\n\n- Validation: `{}`; included in report status: `{}`\n- Metrics: `{}`\n- Actionable alerts: `{}`\n- Retry pressure: `{}` via `{}`\n- Rules: `{}`\n- Runbook: `{}`\n\n## Contracts\n\n| Contract | Owner | Capability | Manifest | Generated | Route | Test | Backend profiles | Journey |\n|---|---|---|---|---|---|---|---|---|\n",
        match report.status {
            ReportStatus::Passed => "passed",
            ReportStatus::Failed => "failed",
        },
        report.active_local_tx_contract_count,
        report.findings.len(),
        operations_validation_wire(report.operations.validation),
        report.operations.included_in_report_status,
        report
            .operations
            .metrics
            .iter()
            .map(|metric| metric.name)
            .collect::<Vec<_>>()
            .join("`, `"),
        report
            .operations
            .alerts
            .iter()
            .map(|alert| alert.name)
            .collect::<Vec<_>>()
            .join("`, `"),
        report.operations.retry_pressure.classification,
        report.operations.retry_pressure.metric,
        report.operations.rules,
        report.operations.runbook,
    );
    for contract in &report.contracts {
        let capability = format!(
            "boundary={}; txModel={}; retry={}; commitUnknown={}",
            contract.capability.boundary,
            contract.capability.tx_model,
            contract.capability.retry,
            contract.capability.commit_unknown
        );
        let backends = if contract.backend_profiles.is_empty() {
            "—".to_string()
        } else {
            contract
                .backend_profiles
                .iter()
                .map(|profile| {
                    format!(
                        "{} / {}: providerStatus={}; status={}; sources=[{}]; required=[{}], observed=[{}], missing=[{}]",
                        profile.provider,
                        profile.fixture,
                        backend_provider_status_wire(profile.provider_status),
                        backend_profile_status_wire(profile.status),
                        profile.sources.join(", "),
                        profile.required_probes.join(", "),
                        profile
                            .observed_probes
                            .iter()
                            .map(|probe| format!("{}={}", probe.probe, probe.count))
                            .collect::<Vec<_>>()
                            .join(", "),
                        profile.missing_probes.join(", "),
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        };
        let journey = format!(
            "spec={}; fixture={}; runner={}; scenarios=[{}]",
            contract.journey.spec,
            contract.journey.fixture,
            contract.journey.runner,
            contract
                .journey
                .scenarios
                .iter()
                .map(|scenario| if scenario.applicable {
                    scenario.kind.clone()
                } else {
                    format!(
                        "{} (not applicable: {})",
                        scenario.kind,
                        scenario.reason.as_deref().unwrap_or("unspecified")
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        );
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            markdown_cell(&contract.contract_id),
            markdown_cell(&contract.owner),
            markdown_cell(&capability),
            evidence_cell(&contract.evidence.manifest),
            evidence_cell(&contract.evidence.generated),
            evidence_cell(&contract.evidence.route),
            evidence_cell(&contract.evidence.test),
            markdown_cell(&backends),
            markdown_cell(&journey),
        ));
    }
    output.push_str("\n## Findings\n\n");
    if report.findings.is_empty() {
        output.push_str("None.\n");
    } else {
        output.push_str("| Rule | Subject | Detail |\n|---|---|---|\n");
        for finding in &report.findings {
            output.push_str(&format!(
                "| {} | {} | {} |\n",
                markdown_cell(&finding.rule),
                markdown_cell(&finding.subject),
                markdown_cell(&finding.detail),
            ));
        }
    }
    output
}

const fn operations_validation_wire(validation: OperationsValidation) -> &'static str {
    match validation {
        OperationsValidation::ReferenceOnly => "referenceOnly",
    }
}

const fn backend_provider_status_wire(status: BackendProviderStatus) -> &'static str {
    match status {
        BackendProviderStatus::Valid => "valid",
        BackendProviderStatus::Invalid => "invalid",
    }
}

const fn backend_profile_status_wire(status: BackendProfileStatus) -> &'static str {
    match status {
        BackendProfileStatus::Complete => "complete",
        BackendProfileStatus::Failed => "failed",
    }
}

fn evidence_cell(evidence: &EvidenceProjection) -> String {
    let status = match evidence.status {
        EvidenceStatus::Complete => "complete",
        EvidenceStatus::Missing => "missing",
    };
    markdown_cell(&format!(
        "{}{}",
        status,
        if evidence.sources.is_empty() {
            String::new()
        } else {
            format!(": {}", evidence.sources.join(", "))
        }
    ))
}

fn markdown_cell(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    struct FixtureCopy {
        path: PathBuf,
    }

    impl FixtureCopy {
        fn new(prefix: &str) -> Result<Self> {
            let path = crate::testutil::unique_tmp(prefix);
            copy_tree(
                &Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/localtx_coverage/green"),
                &path,
            )?;
            let descriptor = localtx_operations_descriptor();
            for relative in [descriptor.rules_path(), descriptor.runbook_path()] {
                let target = path.join(relative);
                fs::create_dir_all(target.parent().context("operations carrier parent")?)?;
                fs::copy(crate::workspace_root()?.join(relative), target)?;
            }
            Ok(Self { path })
        }
    }

    impl Drop for FixtureCopy {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn copy_tree(from: &Path, to: &Path) -> Result<()> {
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

    fn fixture_inventory(root: &Path) -> Result<crate::localtx_coverage::LocalTxProofInventory> {
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::for_test_fixture(root);
        let facts = command_facts.get()?;
        crate::localtx_coverage::collect_fixture_inventory(root, facts)
    }

    fn collect_fixture_report(root: &Path) -> Result<LocalTxReport> {
        let inventory = fixture_inventory(root)?;
        let operations = collect_operations(root)?;
        project_inventory(&inventory, operations)
    }

    fn sample_report() -> LocalTxReport {
        LocalTxReport {
            schema_version: 1,
            status: ReportStatus::Failed,
            evidence_scope: EvidenceScope::StaticInventory,
            active_local_tx_contract_count: 1,
            operations: operations_projection_from_descriptor(),
            findings: vec![ReportFinding {
                rule: "MissingRouteBinding".to_string(),
                subject: "contracts/http/demo/v1/write/contract.toml".to_string(),
                detail: "route | missing\nsynthetic".to_string(),
            }],
            contracts: vec![ContractProjection {
                contract_id: "demo.write".to_string(),
                owner: "demo".to_string(),
                capability: CapabilityProjection {
                    boundary: "single-domain".to_string(),
                    tx_model: "tenant-scoped-uow".to_string(),
                    retry: "bounded-transient".to_string(),
                    commit_unknown: "not-retryable".to_string(),
                },
                evidence: ContractEvidence {
                    manifest: EvidenceProjection {
                        status: EvidenceStatus::Complete,
                        sources: vec!["contracts/http/demo/v1/write/contract.toml".to_string()],
                    },
                    generated: EvidenceProjection {
                        status: EvidenceStatus::Complete,
                        sources: vec!["generated/src/http/demo_v1.rs".to_string()],
                    },
                    route: EvidenceProjection {
                        status: EvidenceStatus::Missing,
                        sources: Vec::new(),
                    },
                    test: EvidenceProjection {
                        status: EvidenceStatus::Complete,
                        sources: vec!["crates/demo/src/lib.rs".to_string()],
                    },
                },
                backend_profiles: vec![BackendProfileProjection {
                    provider: "demo-pg".to_string(),
                    fixture: "postgres".to_string(),
                    provider_status: BackendProviderStatus::Valid,
                    status: BackendProfileStatus::Complete,
                    sources: vec!["adapters/demo-pg/tests/localtx.rs".to_string()],
                    required_probes: vec!["commit".to_string()],
                    observed_probes: vec![ObservedProbe {
                        probe: "commit".to_string(),
                        count: 1,
                    }],
                    missing_probes: Vec::new(),
                }],
                journey: JourneyProjection {
                    spec: "journeys/demo-localtx-journey.toml".to_string(),
                    fixture: "fixtures/demo-localtx.toml".to_string(),
                    runner: "journeys/tests/demo_journey.rs".to_string(),
                    scenarios: vec![JourneyScenarioProjection {
                        kind: "happy".to_string(),
                        applicable: true,
                        reason: None,
                    }],
                },
            }],
        }
    }

    #[test]
    fn exact_golden_formats_and_markdown_escaping() -> Result<()> {
        let report = sample_report();
        assert_eq!(
            render_report(&report, ReportFormat::Json)?,
            include_str!("../tests/golden/localtx-proof.json")
        );
        assert_eq!(
            render_report(&report, ReportFormat::Markdown)?,
            include_str!("../tests/golden/localtx-proof.md")
        );
        Ok(())
    }

    #[test]
    fn markdown_backend_profiles_include_canonically_sorted_sources() {
        let mut report = sample_report();
        report.contracts[0].backend_profiles[0].sources =
            vec!["z/backend.rs".to_string(), "a/backend.rs".to_string()];
        normalize_report(&mut report);
        let markdown = render_markdown(&report);
        assert!(
            markdown.contains(
                "sources=&#91;a/backend.rs, z/backend.rs&#93;; required=&#91;commit&#93;"
            )
        );
    }

    #[test]
    fn alert_rule_drift_is_structural_and_leaves_stdout_empty() -> Result<()> {
        let cases = [
            (
                "missing",
                "      - alert: LocalTxCommitUnknown",
                "      - alert: RemovedCommitUnknown",
            ),
            (
                "extra",
                "      - alert: GenericTxCommitUnknown",
                "      - alert: LocalTxUnexpected\n        expr: sum by (domain, contract_id, boundary) (increase(localtx_final_total{final_status=\"commit_unknown\"}[5m])) > 0\n        annotations:\n          runbook: \"docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md#commit-unknown\"\n\n      - alert: GenericTxCommitUnknown",
            ),
            (
                "duplicate",
                "      - alert: GenericTxCommitUnknown",
                "      - alert: LocalTxCommitUnknown\n        expr: sum by (domain, contract_id, boundary) (increase(localtx_final_total{final_status=\"commit_unknown\"}[5m])) > 0\n        annotations:\n          runbook: \"docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md#commit-unknown\"\n\n      - alert: GenericTxCommitUnknown",
            ),
            (
                "duplicate-expr",
                "        expr: sum by (domain, contract_id, boundary) (increase(localtx_final_total{final_status=\"commit_unknown\"}[5m])) > 0",
                "        expr: sum by (domain, contract_id, boundary) (increase(localtx_final_total{final_status=\"commit_unknown\"}[5m])) > 0\n        expr: sum by (domain, contract_id, boundary) (increase(localtx_final_total{final_status=\"commit_unknown\"}[5m])) > 0",
            ),
            (
                "final-status",
                "final_status=\"commit_unknown\"",
                "final_status=\"rollback_failed\"",
            ),
            (
                "runbook-anchor",
                "localtx-unsafe-settlement.md#commit-unknown",
                "localtx-unsafe-settlement.md#rollback-failed",
            ),
        ];
        for (name, from, to) in cases {
            let fixture = FixtureCopy::new(&format!("localtx-report-alert-{name}"))?;
            let rules = fixture
                .path
                .join(observ::localtx_operations_descriptor().rules_path());
            let current = fs::read_to_string(&rules)?;
            assert!(
                current.contains(from),
                "invalid synthetic-red fixture: {name}"
            );
            fs::write(&rules, current.replacen(from, to, 1))?;
            let mut output = Vec::new();
            assert!(
                run_report_with(
                    ReportFormat::Json,
                    || collect_fixture_report(&fixture.path),
                    &mut output,
                )
                .is_err(),
                "{name} drift unexpectedly rendered"
            );
            assert!(output.is_empty(), "{name} emitted partial stdout");
        }
        Ok(())
    }

    #[test]
    fn schema_status_count_sorting_and_relative_paths_are_fail_closed() {
        let mut report = sample_report();
        report.schema_version = 2;
        assert!(validate_report(&report).is_err());
        report = sample_report();
        report.status = ReportStatus::Passed;
        assert!(validate_report(&report).is_err());
        report = sample_report();
        report.active_local_tx_contract_count = 2;
        assert!(validate_report(&report).is_err());
        report = sample_report();
        report.contracts[0].evidence.manifest.sources[0] = "/tmp/escape".to_string();
        assert!(validate_report(&report).is_err());
        report = sample_report();
        report.operations.retry_pressure.metric = "parallel_registry_metric";
        assert!(validate_report(&report).is_err());
    }

    #[test]
    fn policy_failure_renders_successfully() -> Result<()> {
        let report = sample_report();
        assert!(render_report(&report, ReportFormat::Json)?.contains("\"status\": \"failed\""));
        let mut output = Vec::new();
        run_report_with(ReportFormat::Json, || Ok(report), &mut output)?;
        assert!(String::from_utf8(output)?.contains("\"status\": \"failed\""));
        Ok(())
    }

    #[test]
    fn real_typed_registry_covers_both_closed_tx_models_without_aliases() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let report = collect_report(&root, command_facts.get()?)?;
        let canonical_models = [
            vocab::LocalTxModel::TenantScopedUow,
            vocab::LocalTxModel::RepoAtomicCas,
        ];
        for model in canonical_models {
            assert!(
                generated::http::LOCAL_TX_SPECS.iter().any(|spec| spec
                    .local_tx
                    .is_some_and(|local_tx| local_tx.tx_model == model)),
                "real generated registry must exercise {}",
                model.as_label()
            );
        }
        for spec in generated::http::LOCAL_TX_SPECS {
            let local_tx = spec.local_tx.context("LocalTx registry entry")?;
            let contract = report
                .contracts
                .iter()
                .find(|contract| contract.contract_id == spec.route.contract_id())
                .context("projected LocalTx contract")?;
            assert_eq!(
                contract.capability.boundary,
                local_tx.boundary.as_label().replace('_', "-")
            );
            assert_eq!(
                contract.capability.tx_model,
                local_tx.tx_model.as_label().replace('_', "-")
            );
            assert_eq!(
                contract.capability.retry,
                local_tx.retry.as_label().replace('_', "-")
            );
            assert_eq!(
                contract.capability.commit_unknown,
                local_tx.commit_unknown.as_label().replace('_', "-")
            );
        }
        Ok(())
    }

    #[test]
    fn green_fixture_report_passes_with_empty_findings() -> Result<()> {
        let fixture = FixtureCopy::new("localtx-report-green")?;
        let report = collect_fixture_report(&fixture.path)?;
        assert_eq!(report.status, ReportStatus::Passed);
        assert!(
            report.findings.is_empty(),
            "green fixture must not drift against fixture compiled keys: {findings:#?}",
            findings = report.findings
        );
        assert_eq!(report.active_local_tx_contract_count, 1);
        assert_eq!(report.contracts[0].contract_id, "demo.write");
        Ok(())
    }

    #[test]
    fn report_production_path_matches_gate_findings_and_evidence() -> Result<()> {
        type FixtureMutation = fn(&Path) -> Result<()>;
        let cases: [(&str, &str, FixtureMutation); 4] = [
            ("route", "MissingRouteBinding", |root| {
                fs::write(
                    root.join("crates/demo/src/lib.rs"),
                    "#[test] fn covered() { const _: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE; }\n",
                )?;
                Ok(())
            }),
            ("test", "MissingTestMarker", |root| {
                let path = root.join("crates/demo/src/lib.rs");
                fs::write(
                    &path,
                    fs::read_to_string(&path)?.replace("#[test] fn covered()", "fn covered()"),
                )?;
                Ok(())
            }),
            ("profile", "MissingBackendProfile", |root| {
                fs::write(root.join("adapters/pg/src/lib.rs"), "")?;
                Ok(())
            }),
            ("probe", "MissingBackendProbe", |root| {
                let path = root.join("adapters/pg/src/lib.rs");
                fs::write(
                    &path,
                    fs::read_to_string(&path)?.replacen(
                        "::rss_conformance::localtx::assert_rollback(",
                        "::rss_conformance::localtx::ignored_rollback(",
                        1,
                    ),
                )?;
                Ok(())
            }),
        ];
        for (name, expected_rule, mutate) in cases {
            let fixture = FixtureCopy::new(&format!("localtx-report-parity-{name}"))?;
            mutate(&fixture.path)?;
            let inventory = fixture_inventory(&fixture.path)?;
            let expected = inventory
                .findings()
                .into_iter()
                .map(|finding| ReportFinding {
                    rule: finding.rule.report_wire().to_string(),
                    subject: finding.subject,
                    detail: finding.detail,
                })
                .collect::<Vec<_>>();
            let report = collect_fixture_report(&fixture.path)?;
            assert_eq!(report.status, ReportStatus::Failed, "{name}");
            assert_eq!(report.findings, expected, "{name} gate/report parity");
            let matching = report
                .findings
                .iter()
                .filter(|finding| finding.rule == expected_rule)
                .collect::<Vec<_>>();
            assert_eq!(
                matching.len(),
                1,
                "{name} must emit exactly one {expected_rule}: {findings:#?}",
                findings = report.findings
            );
            let contract = &report.contracts[0];
            match expected_rule {
                "MissingRouteBinding" => {
                    assert_eq!(contract.evidence.route.status, EvidenceStatus::Missing);
                    assert!(contract.evidence.route.sources.is_empty());
                }
                "MissingTestMarker" => {
                    assert_eq!(contract.evidence.test.status, EvidenceStatus::Missing);
                    assert!(contract.evidence.test.sources.is_empty());
                }
                "MissingBackendProfile" => {
                    assert!(
                        contract.backend_profiles.is_empty(),
                        "{name} backend profiles: {:#?}",
                        contract.backend_profiles
                    );
                }
                "MissingBackendProbe" => {
                    let failed = contract
                        .backend_profiles
                        .iter()
                        .filter(|profile| {
                            profile.status == BackendProfileStatus::Failed
                                && !profile.missing_probes.is_empty()
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        failed.len(),
                        1,
                        "{name} must have exactly one failed probe profile: {:#?}",
                        contract.backend_profiles
                    );
                    assert!(
                        failed[0].missing_probes.contains(&"rollback".to_string())
                            || !failed[0].missing_probes.is_empty()
                    );
                }
                _ => bail!("closed localtx report fixture `{name}` escaped"),
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_non_adapter_profile_is_explicitly_failed_in_the_report() -> Result<()> {
        let fixture = FixtureCopy::new("localtx-report-invalid-provider")?;
        let manifest = fixture.path.join("crates/demo/Cargo.toml");
        fs::write(
            &manifest,
            format!(
                "{}\n[dev-dependencies]\nrss_conformance = {{ package = \"rss-conformance\", path = \"../conformance\" }}\ntestkit = {{ path = \"../testkit\" }}\n",
                fs::read_to_string(&manifest)?
            ),
        )?;
        let owner = fixture.path.join("crates/demo/src/lib.rs");
        fs::write(
            &owner,
            format!(
                "{}\n#[cfg(test)] mod invalid_backend {{\n    #[test] fn profile() {{\n        const LOCALTX_BACKEND_PROFILE_INVALID: ::vocab::HttpRouteBinding<::generated::http::demo_v1::write::RouteMarker, ::vocab::http::LocalTx> = ::generated::http::demo_v1::write::ROUTE;\n        const LOCALTX_BACKEND_PROVIDER_INVALID: ::std::marker::PhantomData<(::generated::http::demo_v1::write::RouteMarker, InvalidProviderFixture)> = ::std::marker::PhantomData;\n        let _provider = InvalidProviderFixture::new();\n    }}\n}}\n",
                fs::read_to_string(&owner)?
            ),
        )?;
        let report = collect_fixture_report(&fixture.path)?;
        let invalid = report.contracts[0]
            .backend_profiles
            .iter()
            .find(|profile| profile.provider == "demo")
            .context("non-adapter profile projection")?;
        assert_eq!(invalid.provider_status, BackendProviderStatus::Invalid);
        assert_eq!(invalid.status, BackendProfileStatus::Failed);
        let unexpected = report
            .findings
            .iter()
            .filter(|finding| {
                finding.rule == "UnexpectedBackendProfile" && finding.detail.contains("adapters/*")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            unexpected.len(),
            1,
            "exact UnexpectedBackendProfile finding required: {:#?}",
            report.findings
        );
        Ok(())
    }

    #[test]
    fn structural_collection_failures_leave_stdout_empty() -> Result<()> {
        type FixtureMutation = fn(&Path) -> Result<()>;
        let cases: [(&str, FixtureMutation); 3] = [
            ("malformed-toml", |root| {
                fs::write(
                    root.join("contracts/http/demo/v1/write/contract.toml"),
                    "not = [valid",
                )?;
                Ok(())
            }),
            ("malformed-rust", |root| {
                fs::write(root.join("generated/src/http/demo_v1.rs"), "fn {")?;
                Ok(())
            }),
            ("journey-contradiction", |root| {
                let path = root.join("journeys/status-board.toml");
                fs::write(
                    &path,
                    fs::read_to_string(&path)?.replace(
                        "txModel = \"tenant-scoped-uow\"",
                        "txModel = \"repo-atomic-cas\"",
                    ),
                )?;
                Ok(())
            }),
        ];
        for (name, mutate) in cases {
            let fixture = FixtureCopy::new(&format!("localtx-report-structural-{name}"))?;
            mutate(&fixture.path)?;
            let mut output = Vec::new();
            assert!(
                run_report_with(
                    ReportFormat::Json,
                    || collect_fixture_report(&fixture.path),
                    &mut output,
                )
                .is_err(),
                "{name} unexpectedly rendered"
            );
            assert!(output.is_empty(), "{name} emitted partial stdout");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_collection_failure_leaves_stdout_empty() -> Result<()> {
        let fixture = FixtureCopy::new("localtx-report-structural-symlink")?;
        let contracts = fixture.path.join("contracts");
        fs::remove_dir_all(&contracts)?;
        std::os::unix::fs::symlink(fixture.path.join("missing-contracts"), contracts)?;
        let mut output = Vec::new();
        let error = run_report_with(
            ReportFormat::Json,
            || collect_fixture_report(&fixture.path),
            &mut output,
        );
        let error = match error {
            Ok(()) => bail!("symlink unexpectedly rendered"),
            Err(error) => error,
        };
        assert!(output.is_empty());
        assert!(!format!("{error:#}").contains(fixture.path.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn normalization_is_canonical_and_validation_rejects_duplicates_or_unsorted_vectors() {
        let mut report = sample_report();
        let mut alpha = report.contracts[0].clone();
        alpha.contract_id = "alpha.write".to_string();
        alpha.evidence.route.sources = vec!["z/route.rs".to_string(), "a/route.rs".to_string()];
        let mut earlier = alpha.backend_profiles[0].clone();
        earlier.provider = "alpha-pg".to_string();
        earlier.sources = vec!["z/profile.rs".to_string(), "a/profile.rs".to_string()];
        earlier.required_probes = vec!["rollback".to_string(), "commit".to_string()];
        earlier.observed_probes = vec![
            ObservedProbe {
                probe: "rollback".to_string(),
                count: 1,
            },
            ObservedProbe {
                probe: "commit".to_string(),
                count: 1,
            },
        ];
        alpha.backend_profiles.push(earlier);
        alpha.journey.scenarios.push(JourneyScenarioProjection {
            kind: "abort".to_string(),
            applicable: false,
            reason: Some("synthetic".to_string()),
        });
        report.contracts.push(alpha);
        report.findings.push(ReportFinding {
            rule: "DuplicateTestMarker".to_string(),
            subject: "z".to_string(),
            detail: "z".to_string(),
        });
        report.active_local_tx_contract_count = report.contracts.len();
        normalize_report(&mut report);
        assert!(validate_report(&report).is_ok());
        assert_eq!(report.contracts[0].contract_id, "alpha.write");
        assert_eq!(report.contracts[0].backend_profiles[0].provider, "alpha-pg");
        assert_eq!(report.contracts[0].journey.scenarios[0].kind, "abort");
        assert_eq!(report.findings[0].rule, "DuplicateTestMarker");
        assert_eq!(
            report.contracts[0].evidence.route.sources,
            ["a/route.rs", "z/route.rs"]
        );

        let mut duplicate = sample_report();
        duplicate.findings.push(duplicate.findings[0].clone());
        assert!(validate_report(&duplicate).is_err());
        let mut duplicate = sample_report();
        let duplicate_source = duplicate.contracts[0].evidence.manifest.sources[0].clone();
        duplicate.contracts[0]
            .evidence
            .manifest
            .sources
            .push(duplicate_source);
        assert!(validate_report(&duplicate).is_err());
        let mut duplicate = sample_report();
        let duplicate_profile = duplicate.contracts[0].backend_profiles[0].clone();
        duplicate.contracts[0]
            .backend_profiles
            .push(duplicate_profile);
        assert!(validate_report(&duplicate).is_err());
        let mut duplicate = sample_report();
        let duplicate_scenario = duplicate.contracts[0].journey.scenarios[0].clone();
        duplicate.contracts[0]
            .journey
            .scenarios
            .push(duplicate_scenario);
        assert!(validate_report(&duplicate).is_err());

        let mut unsorted = report;
        unsorted.contracts.reverse();
        assert!(validate_report(&unsorted).is_err());
        let mut unsorted = sample_report();
        unsorted.contracts[0].evidence.route.sources =
            vec!["z/route.rs".to_string(), "a/route.rs".to_string()];
        assert!(validate_report(&unsorted).is_err());
    }

    #[test]
    fn markdown_retry_pressure_is_projected_from_the_typed_operations_model() {
        let mut report = sample_report();
        report.operations.retry_pressure.metric = "synthetic_retry_metric";
        let markdown = render_markdown(&report);
        assert!(markdown.contains("Retry pressure: `diagnosticOnly` via `synthetic_retry_metric`"));
        assert!(!markdown.contains("via `localtx_retry_attempts_total`"));
    }

    #[test]
    fn markdown_cells_literalize_every_active_syntax_character_and_crlf() {
        assert_eq!(
            markdown_cell("&<>|\\[]()!`*_~\"'\r\n<img src=x onerror=alert(1)>"),
            "<code>&amp;&lt;&gt;&#124;&#92;&#91;&#93;&#40;&#41;&#33;&#96;&#42;&#95;&#126;&quot;&#39;<br>&lt;img src=x onerror=alert&#40;1&#41;&gt;</code>"
        );
    }

    #[test]
    fn source_paths_reject_dot_parent_root_and_empty_components() {
        for invalid in ["", ".", "./crates/demo", "../escape", "/absolute"] {
            assert!(
                validate_relative_source(invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
        assert!(validate_relative_source("crates/demo/src/lib.rs").is_ok());
    }

    #[test]
    fn collection_render_and_writer_failures_emit_no_partial_bytes() {
        let mut output = Vec::new();
        let error = run_report_with(
            ReportFormat::Json,
            || bail!("malformed fixture"),
            &mut output,
        );
        assert!(error.is_err());
        assert!(output.is_empty());

        struct RejectWriter;
        impl Write for RejectWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("writer failed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(
            run_report_with(
                ReportFormat::Json,
                || Ok(sample_report()),
                &mut RejectWriter
            )
            .is_err()
        );
    }
}
