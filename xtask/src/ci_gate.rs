//! Stable aggregate gate for a typed CI impact plan.
//!
//! INVARIANT: CI-GATE-RECEIPT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "gate_rejects_missing_duplicate_and_mismatched_receipts_red", anti_vacuity = "gate_accepts_exact_receipt_set_green" }.
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "gate_rejects_complete_generic_receipts_without_localtx_required_evidence_red|localtx_required_evidence_disk_red_matrix", anti_vacuity = "gate_accepts_exact_receipt_set_green|successful_run_persists_the_existing_resource_metrics_in_the_envelope" }.
//! INVARIANT: LOCAL-ONLY-REQUIRED-EVIDENCE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "gate_rejects_complete_generic_receipts_without_localonly_required_evidence_red|localonly_required_evidence_disk_red_matrix", anti_vacuity = "gate_accepts_exact_receipt_set_green|real_workspace_execution_inventory_is_exact_and_non_empty" }.

use crate::ci_evidence::{MAX_JSON_INTEGER, ValidatedEvidence};
use crate::ci_identity::CiIdentityKey;
use crate::ci_impact::{CiImpactPlan, DecisionKind, DecisionReason, PolicyMode};
use crate::ci_lanes::CiJobKey;
use crate::localonly_evidence::{FILE_NAME as LOCALONLY_FILE_NAME, OWNER as LOCALONLY_OWNER};
use crate::localonly_evidence::{ValidatedLocalOnlyReport, exact_set_difference_summary};
use crate::localtx_evidence::ValidatedLocalTxReceipt;
use crate::localtx_evidence::{FILE_NAME as LOCALTX_FILE_NAME, OWNER as LOCALTX_OWNER};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) plan_path: PathBuf,
    pub(crate) receipts_path: PathBuf,
    pub(crate) planner_result: JobResult,
    pub(crate) matrix_result: JobResult,
    pub(crate) metrics_output: PathBuf,
}

pub(crate) fn parse_options(args: &[&str]) -> Result<Options> {
    let mut plan_path = None;
    let mut receipts_path = None;
    let mut planner_result = None;
    let mut matrix_result = None;
    let mut metrics_output = None;
    let mut iter = args.iter().copied();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("ci gate 参数 {flag} 缺少值"))?;
        match flag {
            "--plan" if plan_path.is_none() => plan_path = Some(PathBuf::from(value)),
            "--receipts" if receipts_path.is_none() => receipts_path = Some(PathBuf::from(value)),
            "--planner-result" if planner_result.is_none() => {
                planner_result = Some(value.parse()?);
            }
            "--matrix-result" if matrix_result.is_none() => {
                matrix_result = Some(value.parse()?);
            }
            "--metrics-output" if metrics_output.is_none() => {
                metrics_output = Some(PathBuf::from(value));
            }
            _ => bail!("ci gate 未知或重复参数: {flag}"),
        }
    }
    Ok(Options {
        plan_path: plan_path.context("ci gate 缺少 --plan")?,
        receipts_path: receipts_path.context("ci gate 缺少 --receipts")?,
        planner_result: planner_result.context("ci gate 缺少 --planner-result")?,
        matrix_result: matrix_result.context("ci gate 缺少 --matrix-result")?,
        metrics_output: metrics_output.context("ci gate 缺少 --metrics-output")?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobResult {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

impl JobResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeIdentity {
    run_id: Option<String>,
    run_attempt: Option<String>,
    execution_revision: Option<String>,
    summary_path: Option<PathBuf>,
}

impl RuntimeIdentity {
    fn from_environment() -> Self {
        Self {
            run_id: std::env::var(CiIdentityKey::RunId.env_name()).ok(),
            run_attempt: std::env::var(CiIdentityKey::RunAttempt.env_name()).ok(),
            execution_revision: std::env::var(CiIdentityKey::HeadRevision.env_name()).ok(),
            summary_path: std::env::var_os(CiIdentityKey::StepSummary.env_name())
                .map(PathBuf::from),
        }
    }
}

impl FromStr for JobResult {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "cancelled" => Ok(Self::Cancelled),
            "skipped" => Ok(Self::Skipped),
            _ => bail!("unknown GitHub job result: {value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptIdentity {
    artifact: String,
    job_key: CiJobKey,
    source_revision: String,
    plan_digest: String,
    run_id: String,
    run_attempt: String,
    started_at: String,
    finished_at: String,
    cpu_time_ms: Option<u64>,
    peak_rss_bytes: Option<u64>,
    disk_low_water_bytes: u64,
    compiler_cache_requests: u64,
    compiler_cache_hits: u64,
}

#[derive(Debug)]
struct LocalTxReceiptIdentity {
    artifact: String,
    receipt: ValidatedLocalTxReceipt,
}

#[derive(Debug)]
struct LocalOnlyReportIdentity {
    artifact: String,
    report: ValidatedLocalOnlyReport,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateMetrics {
    schema_version: u8,
    plan_digest: String,
    policy_mode: PolicyMode,
    decision_kind: DecisionKind,
    decision_reason: DecisionReason,
    full_fallback: bool,
    recommended_job_keys: Vec<CiJobKey>,
    executed_job_keys: Vec<CiJobKey>,
    recommended_jobs: usize,
    executed_jobs: usize,
    skipped_runner_jobs: usize,
    started_at: String,
    finished_at: String,
    cpu_time_ms: u64,
    peak_rss_bytes: u64,
    disk_low_water_bytes: u64,
    compiler_cache_requests: u64,
    compiler_cache_hits: u64,
    projected_saved_cpu_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum GateVerdict {
    Success,
    Failure,
}

impl GateVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum GateFailureClass {
    PlannerResult,
    MatrixResult,
    PlanIo,
    PlanInvalid,
    ReceiptLoad,
    RunIdentity,
    ExecutionRevision,
    ReceiptValidation,
    LocaltxEvidence,
    LocalonlyEvidence,
    MetricsBuild,
}

impl GateFailureClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PlannerResult => "planner-result",
            Self::MatrixResult => "matrix-result",
            Self::PlanIo => "plan-io",
            Self::PlanInvalid => "plan-invalid",
            Self::ReceiptLoad => "receipt-load",
            Self::RunIdentity => "run-identity",
            Self::ExecutionRevision => "execution-revision",
            Self::ReceiptValidation => "receipt-validation",
            Self::LocaltxEvidence => "localtx-evidence",
            Self::LocalonlyEvidence => "localonly-evidence",
            Self::MetricsBuild => "metrics-build",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GateEnvelope {
    schema_version: u8,
    verdict: GateVerdict,
    failure_class: Option<GateFailureClass>,
    planner_result: JobResult,
    matrix_result: JobResult,
    error_summary: Option<String>,
    plan_digest: Option<String>,
    policy_mode: Option<PolicyMode>,
    decision_kind: Option<DecisionKind>,
    decision_reason: Option<DecisionReason>,
    full_fallback: Option<bool>,
    observed_receipt_count: usize,
    observed_receipt_keys: Vec<CiJobKey>,
    localtx_active_count: Option<usize>,
    localtx_journey_count: Option<usize>,
    localtx_backend_profile_count: Option<usize>,
    localonly_contract_count: Option<usize>,
    success_metrics: Option<GateMetrics>,
}

struct GateSuccess {
    metrics: GateMetrics,
    localtx_active_count: usize,
    localtx_journey_count: usize,
    localtx_backend_profile_count: usize,
    localonly_contract_count: usize,
}

#[derive(Debug)]
struct GateFailure {
    class: GateFailureClass,
    error: anyhow::Error,
}

impl GateFailure {
    fn new(class: GateFailureClass, error: impl Into<anyhow::Error>) -> Self {
        Self {
            class,
            error: error.into(),
        }
    }
}

struct PlanObservation {
    plan: Option<CiImpactPlan>,
    failure: Option<GateFailure>,
}

struct ReceiptObservation {
    receipts: Vec<ReceiptIdentity>,
    failure: Option<GateFailure>,
}

struct LocalTxReceiptObservation {
    receipts: Vec<LocalTxReceiptIdentity>,
    failure: Option<GateFailure>,
}

struct LocalOnlyReportObservation {
    reports: Vec<LocalOnlyReportIdentity>,
    failure: Option<GateFailure>,
}

struct GateObservations<'a> {
    plan: Option<&'a CiImpactPlan>,
    receipts: &'a [ReceiptIdentity],
    localtx_receipts: &'a [LocalTxReceiptIdentity],
    localonly_reports: &'a [LocalOnlyReportIdentity],
    plan_failure: Option<GateFailure>,
    receipt_failure: Option<GateFailure>,
    localtx_failure: Option<GateFailure>,
    localonly_failure: Option<GateFailure>,
}

pub(crate) fn run(options: &Options) -> Result<()> {
    run_with_runtime(options, &RuntimeIdentity::from_environment())
}

fn run_with_runtime(options: &Options, runtime: &RuntimeIdentity) -> Result<()> {
    let PlanObservation {
        plan,
        failure: plan_failure,
    } = observe_plan(&options.plan_path);
    let ReceiptObservation {
        receipts,
        failure: receipt_failure,
    } = observe_receipts(&options.receipts_path);
    let LocalTxReceiptObservation {
        receipts: localtx_receipts,
        failure: localtx_failure,
    } = observe_localtx_receipts(&options.receipts_path);
    let LocalOnlyReportObservation {
        reports: localonly_reports,
        failure: localonly_failure,
    } = observe_localonly_reports(&options.receipts_path);

    let gate_result = evaluate_observations(
        options,
        runtime,
        GateObservations {
            plan: plan.as_ref(),
            receipts: &receipts,
            localtx_receipts: &localtx_receipts,
            localonly_reports: &localonly_reports,
            plan_failure,
            receipt_failure,
            localtx_failure,
            localonly_failure,
        },
    );
    let (verdict, failure_class, error_summary, success_metrics, evidence_counts, failure) =
        match gate_result {
            Ok(success) => (
                GateVerdict::Success,
                None,
                None,
                Some(success.metrics),
                Some((
                    success.localtx_active_count,
                    success.localtx_journey_count,
                    success.localtx_backend_profile_count,
                    success.localonly_contract_count,
                )),
                None,
            ),
            Err(failure) => {
                let summary = stable_error_summary(&failure.error);
                (
                    GateVerdict::Failure,
                    Some(failure.class),
                    Some(summary),
                    None,
                    None,
                    Some(failure),
                )
            }
        };
    let envelope = GateEnvelope {
        schema_version: 3,
        verdict,
        failure_class,
        planner_result: options.planner_result,
        matrix_result: options.matrix_result,
        error_summary,
        plan_digest: plan.as_ref().map(|value| value.plan_digest().to_owned()),
        policy_mode: plan.as_ref().map(CiImpactPlan::policy_mode),
        decision_kind: plan.as_ref().map(CiImpactPlan::decision_kind),
        decision_reason: plan.as_ref().map(CiImpactPlan::decision_reason),
        full_fallback: plan.as_ref().map(CiImpactPlan::full_fallback),
        observed_receipt_count: receipts.len(),
        observed_receipt_keys: receipts.iter().map(|receipt| receipt.job_key).collect(),
        localtx_active_count: evidence_counts.map(|counts| counts.0),
        localtx_journey_count: evidence_counts.map(|counts| counts.1),
        localtx_backend_profile_count: evidence_counts.map(|counts| counts.2),
        localonly_contract_count: evidence_counts.map(|counts| counts.3),
        success_metrics,
    };
    persist_envelope(
        options,
        runtime,
        &envelope,
        plan.as_ref().map(|value| value.execution_revision()),
    )?;
    if let Some(failure) = failure {
        return Err(failure.error);
    }
    Ok(())
}

fn observe_plan(path: &Path) -> PlanObservation {
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            return PlanObservation {
                plan: None,
                failure: Some(GateFailure::new(
                    GateFailureClass::PlanIo,
                    anyhow::Error::new(error).context(format!("读取 {}", path.display())),
                )),
            };
        }
    };
    match CiImpactPlan::from_json(&source) {
        Ok(plan) => PlanObservation {
            plan: Some(plan),
            failure: None,
        },
        Err(error) => PlanObservation {
            plan: None,
            failure: Some(GateFailure::new(GateFailureClass::PlanInvalid, error)),
        },
    }
}

fn observe_receipts(root: &Path) -> ReceiptObservation {
    let mut evidence_files = Vec::new();
    if let Err(error) = collect_evidence(root, &mut evidence_files) {
        return ReceiptObservation {
            receipts: Vec::new(),
            failure: Some(GateFailure::new(GateFailureClass::ReceiptLoad, error)),
        };
    }
    evidence_files.sort();
    let mut receipts = Vec::with_capacity(evidence_files.len());
    for path in evidence_files {
        match load_receipt(&path, root) {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => {
                return ReceiptObservation {
                    receipts,
                    failure: Some(GateFailure::new(GateFailureClass::ReceiptLoad, error)),
                };
            }
        }
    }
    ReceiptObservation {
        receipts,
        failure: None,
    }
}

fn observe_localtx_receipts(root: &Path) -> LocalTxReceiptObservation {
    let mut evidence_files = Vec::new();
    if let Err(error) = collect_named_evidence(root, LOCALTX_FILE_NAME, &mut evidence_files) {
        return LocalTxReceiptObservation {
            receipts: Vec::new(),
            failure: Some(GateFailure::new(GateFailureClass::LocaltxEvidence, error)),
        };
    }
    evidence_files.sort();
    let mut receipts = Vec::with_capacity(evidence_files.len());
    for path in evidence_files {
        match load_localtx_receipt(&path, root) {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => {
                return LocalTxReceiptObservation {
                    receipts,
                    failure: Some(GateFailure::new(GateFailureClass::LocaltxEvidence, error)),
                };
            }
        }
    }
    LocalTxReceiptObservation {
        receipts,
        failure: None,
    }
}

fn observe_localonly_reports(root: &Path) -> LocalOnlyReportObservation {
    let mut evidence_files = Vec::new();
    if let Err(error) = collect_named_evidence(root, LOCALONLY_FILE_NAME, &mut evidence_files) {
        return LocalOnlyReportObservation {
            reports: Vec::new(),
            failure: Some(GateFailure::new(GateFailureClass::LocalonlyEvidence, error)),
        };
    }
    evidence_files.sort();
    let mut reports = Vec::with_capacity(evidence_files.len());
    for path in evidence_files {
        match load_localonly_report(&path, root) {
            Ok(report) => reports.push(report),
            Err(error) => {
                return LocalOnlyReportObservation {
                    reports,
                    failure: Some(GateFailure::new(GateFailureClass::LocalonlyEvidence, error)),
                };
            }
        }
    }
    LocalOnlyReportObservation {
        reports,
        failure: None,
    }
}

fn evaluate_observations(
    options: &Options,
    runtime: &RuntimeIdentity,
    observations: GateObservations<'_>,
) -> std::result::Result<GateSuccess, GateFailure> {
    let GateObservations {
        plan,
        receipts,
        localtx_receipts,
        localonly_reports,
        plan_failure,
        receipt_failure,
        localtx_failure,
        localonly_failure,
    } = observations;
    if options.planner_result != JobResult::Success {
        return Err(GateFailure::new(
            GateFailureClass::PlannerResult,
            anyhow::anyhow!("planner job did not succeed: {:?}", options.planner_result),
        ));
    }
    if options.matrix_result != JobResult::Success {
        return Err(GateFailure::new(
            GateFailureClass::MatrixResult,
            anyhow::anyhow!(
                "selected CI matrix did not succeed: {:?}",
                options.matrix_result
            ),
        ));
    }
    if let Some(failure) = plan_failure {
        return Err(failure);
    }
    let plan = plan.ok_or_else(|| {
        GateFailure::new(
            GateFailureClass::PlanInvalid,
            anyhow::anyhow!("validated CI impact plan is unavailable"),
        )
    })?;
    if let Some(failure) = localtx_failure {
        return Err(failure);
    }
    if let Some(failure) = localonly_failure {
        return Err(failure);
    }
    if let Some(failure) = receipt_failure {
        return Err(failure);
    }
    let run_id = runtime.run_id.as_deref().ok_or_else(|| {
        GateFailure::new(
            GateFailureClass::RunIdentity,
            anyhow::anyhow!("GITHUB_RUN_ID is missing"),
        )
    })?;
    let run_attempt = runtime.run_attempt.as_deref().ok_or_else(|| {
        GateFailure::new(
            GateFailureClass::RunIdentity,
            anyhow::anyhow!("GITHUB_RUN_ATTEMPT is missing"),
        )
    })?;
    let execution_revision = runtime.execution_revision.as_deref().ok_or_else(|| {
        GateFailure::new(
            GateFailureClass::RunIdentity,
            anyhow::anyhow!("GITHUB_SHA is missing"),
        )
    })?;
    if plan.execution_revision() != execution_revision {
        return Err(GateFailure::new(
            GateFailureClass::ExecutionRevision,
            anyhow::anyhow!(
                "CI impact plan execution revision differs from the current GitHub run"
            ),
        ));
    }
    evaluate(
        plan,
        receipts,
        JobResult::Success,
        JobResult::Success,
        run_id,
        run_attempt,
    )
    .map_err(|error| GateFailure::new(GateFailureClass::ReceiptValidation, error))?;
    let localtx =
        evaluate_localtx_required_evidence(plan, receipts, localtx_receipts, run_id, run_attempt)
            .map_err(|error| GateFailure::new(GateFailureClass::LocaltxEvidence, error))?;
    let localonly = evaluate_localonly_required_evidence(
        plan,
        receipts,
        localonly_reports,
        run_id,
        run_attempt,
    )
    .map_err(|error| GateFailure::new(GateFailureClass::LocalonlyEvidence, error))?;
    let metrics = build_metrics(plan, receipts)
        .map_err(|error| GateFailure::new(GateFailureClass::MetricsBuild, error))?;
    Ok(GateSuccess {
        metrics,
        localtx_active_count: localtx.active_count(),
        localtx_journey_count: localtx.journey_count(),
        localtx_backend_profile_count: localtx.backend_profile_count(),
        localonly_contract_count: localonly.active_contract_ids().len(),
    })
}

fn persist_envelope(
    options: &Options,
    runtime: &RuntimeIdentity,
    envelope: &GateEnvelope,
    execution_revision: Option<&str>,
) -> Result<()> {
    let metrics = serde_json::to_vec_pretty(envelope).context("serialize CI gate envelope")?;
    atomic_write(&options.metrics_output, &metrics).context("write CI gate metrics envelope")?;
    if let Some(path) = &runtime.summary_path {
        atomic_write(
            path,
            render_summary(envelope, execution_revision).as_bytes(),
        )
        .context("write CI gate summary")?;
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .context("atomic output path has no file name")?
        .to_string_lossy();
    let mut temporary = None;
    for nonce in 0..32u8 {
        let candidate = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary_path, mut file) = temporary.context("cannot allocate atomic output file")?;
    let write_result = (|| -> Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

fn stable_error_summary(error: &anyhow::Error) -> String {
    let mut output = String::new();
    let mut previous_space = false;
    for character in format!("{error:#}").chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if character.is_whitespace() {
            if previous_space {
                continue;
            }
            previous_space = true;
            output.push(' ');
        } else {
            previous_space = false;
            output.push(character);
        }
        if output.chars().count() >= 512 {
            break;
        }
    }
    output.trim().to_owned()
}

fn markdown_code(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '`' => '\'',
            '<' => '‹',
            '>' => '›',
            value if value.is_control() => ' ',
            value => value,
        })
        .collect()
}

fn render_summary(envelope: &GateEnvelope, execution_revision: Option<&str>) -> String {
    let observed = envelope
        .observed_receipt_keys
        .iter()
        .map(|key| key.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut summary = format!(
        "## ci-gate\n\n- Result: `{}`\n- Planner/matrix result: `{}` / `{}`\n- Observed receipts (`{}`): `{}`\n",
        envelope.verdict.as_str(),
        envelope.planner_result.as_str(),
        envelope.matrix_result.as_str(),
        envelope.observed_receipt_count,
        observed,
    );
    if let Some(class) = envelope.failure_class {
        summary.push_str(&format!("- Failure class: `{}`\n", class.as_str()));
    }
    if let Some(error) = &envelope.error_summary {
        summary.push_str(&format!("- Error summary: `{}`\n", markdown_code(error)));
    }
    if let Some(plan_digest) = &envelope.plan_digest {
        summary.push_str(&format!("- Plan digest: `{plan_digest}`\n"));
    }
    if let (Some(active), Some(journey), Some(backend)) = (
        envelope.localtx_active_count,
        envelope.localtx_journey_count,
        envelope.localtx_backend_profile_count,
    ) {
        summary.push_str(&format!(
            "- LocalTx required evidence: `{active}/{journey}/{backend}`\n"
        ));
    }
    if let (Some(count), Some(revision)) = (envelope.localonly_contract_count, execution_revision) {
        summary.push_str(&format!(
            "- LocalOnly required evidence: exact-set active/source/executed = `{count}/{count}/{count}` @ `{revision}`\n"
        ));
    }
    if let (Some(mode), Some(kind), Some(reason), Some(fallback)) = (
        envelope.policy_mode,
        envelope.decision_kind,
        envelope.decision_reason,
        envelope.full_fallback,
    ) {
        summary.push_str(&format!(
            "- Policy/decision: `{:?}` / `{:?}` / `{:?}`\n- Full fallback: `{fallback}`\n",
            mode, kind, reason
        ));
    }
    if let Some(metrics) = &envelope.success_metrics {
        let recommended_set = metrics
            .recommended_job_keys
            .iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let executed_set = metrics
            .executed_job_keys
            .iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        summary.push_str(&format!(
            "- Recommended set (`{}`): `{recommended_set}`\n- Executed/verified set (`{}`): `{executed_set}`\n- Potential skipped runners: `{}`\n- CPU time: `{}` ms\n- Projected saved CPU time: `{}` ms\n- Peak RSS: `{}` bytes\n- Disk low water: `{}` bytes\n- Compiler cache: `{}` requests / `{}` hits\n",
            metrics.recommended_jobs,
            metrics.executed_jobs,
            metrics.skipped_runner_jobs,
            metrics.cpu_time_ms,
            metrics.projected_saved_cpu_time_ms,
            metrics.peak_rss_bytes,
            metrics.disk_low_water_bytes,
            metrics.compiler_cache_requests,
            metrics.compiler_cache_hits,
        ));
    }
    summary
}

#[cfg(test)]
fn load_receipts(root: &Path) -> Result<Vec<ReceiptIdentity>> {
    let observation = observe_receipts(root);
    match observation.failure {
        Some(failure) => Err(failure.error),
        None => Ok(observation.receipts),
    }
}

fn load_receipt(path: &Path, root: &Path) -> Result<ReceiptIdentity> {
    let source = fs::read_to_string(path).with_context(|| format!("读取 {}", path.display()))?;
    let evidence = ValidatedEvidence::parse(&source)
        .with_context(|| format!("parse CI evidence {}", path.display()))?;
    let artifact = artifact_parent(path, root)?;
    Ok(ReceiptIdentity {
        artifact,
        job_key: evidence.job_key,
        source_revision: evidence.source_revision,
        plan_digest: evidence.plan_digest,
        run_id: evidence.run_id,
        run_attempt: evidence.run_attempt,
        started_at: evidence.started_at,
        finished_at: evidence.finished_at,
        cpu_time_ms: evidence.resource_usage.cpu_time_ms,
        peak_rss_bytes: evidence.resource_usage.peak_rss_bytes,
        disk_low_water_bytes: evidence.disk_free_bytes,
        compiler_cache_requests: evidence.compiler_cache.requests,
        compiler_cache_hits: evidence.compiler_cache.hits,
    })
}

fn build_metrics(plan: &CiImpactPlan, receipts: &[ReceiptIdentity]) -> Result<GateMetrics> {
    let started_at = receipts
        .iter()
        .map(|receipt| receipt.started_at.as_str())
        .min()
        .context("CI metrics start time is missing")?
        .to_owned();
    let finished_at = receipts
        .iter()
        .map(|receipt| receipt.finished_at.as_str())
        .max()
        .context("CI metrics finish time is missing")?
        .to_owned();
    let recommended_jobs = plan.jobs().iter().filter(|job| job.recommended()).count();
    let executed_jobs = plan.jobs().iter().filter(|job| job.execute()).count();
    let recommended_job_keys = plan
        .jobs()
        .iter()
        .filter(|job| job.recommended())
        .map(|job| job.key())
        .collect::<Vec<_>>();
    let executed_job_keys = plan
        .jobs()
        .iter()
        .filter(|job| job.execute())
        .map(|job| job.key())
        .collect::<Vec<_>>();
    let total_cpu_time_ms = receipts.iter().try_fold(0u64, |total, receipt| {
        checked_metric_total(total, receipt.cpu_time_ms.unwrap_or(0), "CPU total")
    })?;
    let projected_saved_cpu_time_ms = receipts
        .iter()
        .filter(|receipt| !recommended_job_keys.contains(&receipt.job_key))
        .try_fold(0u64, |total, receipt| {
            checked_metric_total(
                total,
                receipt.cpu_time_ms.unwrap_or(0),
                "projected CPU saving",
            )
        })?;
    Ok(GateMetrics {
        schema_version: 1,
        plan_digest: plan.plan_digest().to_owned(),
        policy_mode: plan.policy_mode(),
        decision_kind: plan.decision_kind(),
        decision_reason: plan.decision_reason(),
        full_fallback: plan.full_fallback(),
        recommended_job_keys,
        executed_job_keys,
        recommended_jobs,
        executed_jobs,
        skipped_runner_jobs: CiJobKey::COUNT.saturating_sub(recommended_jobs),
        started_at,
        finished_at,
        cpu_time_ms: total_cpu_time_ms,
        peak_rss_bytes: receipts
            .iter()
            .filter_map(|receipt| receipt.peak_rss_bytes)
            .max()
            .unwrap_or(0),
        disk_low_water_bytes: receipts
            .iter()
            .map(|receipt| receipt.disk_low_water_bytes)
            .min()
            .context("CI metrics disk low water is missing")?,
        compiler_cache_requests: receipts.iter().try_fold(0u64, |total, receipt| {
            checked_metric_total(
                total,
                receipt.compiler_cache_requests,
                "compiler cache request",
            )
        })?,
        compiler_cache_hits: receipts.iter().try_fold(0u64, |total, receipt| {
            checked_metric_total(total, receipt.compiler_cache_hits, "compiler cache hit")
        })?,
        projected_saved_cpu_time_ms,
    })
}

fn checked_metric_total(total: u64, value: u64, label: &str) -> Result<u64> {
    total
        .checked_add(value)
        .filter(|sum| *sum <= MAX_JSON_INTEGER)
        .with_context(|| format!("CI metrics {label} exceeds the JSON safe integer range"))
}

fn collect_evidence(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        bail!("ci-gate refuses symlink: {}", path.display());
    }
    if metadata.is_file() {
        if path.file_name().and_then(|name| name.to_str()) == Some("ci-evidence.json") {
            output.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("读目录 {}", path.display()))? {
        collect_evidence(&entry?.path(), output)?;
    }
    Ok(())
}

fn collect_named_evidence(path: &Path, file_name: &str, output: &mut Vec<PathBuf>) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        if path.file_name().and_then(|name| name.to_str()) == Some(file_name) {
            bail!("ci-gate refuses symlink: {}", path.display());
        }
        return Ok(());
    }
    if metadata.is_file() {
        if path.file_name().and_then(|name| name.to_str()) == Some(file_name) {
            output.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("读目录 {}", path.display()))? {
        collect_named_evidence(&entry?.path(), file_name, output)?;
    }
    Ok(())
}

fn load_localtx_receipt(path: &Path, root: &Path) -> Result<LocalTxReceiptIdentity> {
    let artifact = artifact_parent(path, root)?;
    let canonical = root
        .join(&artifact)
        .join("integration")
        .join(LOCALTX_FILE_NAME);
    if path != canonical {
        bail!(
            "LocalTx evidence is not at its canonical artifact path: {}",
            path.display()
        );
    }
    let receipt = ValidatedLocalTxReceipt::load(path)?;
    Ok(LocalTxReceiptIdentity { artifact, receipt })
}

fn load_localonly_report(path: &Path, root: &Path) -> Result<LocalOnlyReportIdentity> {
    let artifact = artifact_parent(path, root)?;
    let canonical = root
        .join(&artifact)
        .join("local-only")
        .join(LOCALONLY_FILE_NAME);
    if path != canonical {
        bail!(
            "LocalOnly evidence is not at its canonical artifact path: {}",
            path.display()
        );
    }
    let report = ValidatedLocalOnlyReport::load(path)?;
    Ok(LocalOnlyReportIdentity { artifact, report })
}

fn evaluate_localtx_required_evidence<'a>(
    plan: &CiImpactPlan,
    generic_receipts: &[ReceiptIdentity],
    localtx_receipts: &'a [LocalTxReceiptIdentity],
    run_id: &str,
    run_attempt: &str,
) -> Result<&'a ValidatedLocalTxReceipt> {
    let [observed] = localtx_receipts else {
        bail!(
            "expected exactly one LocalTx required evidence receipt, observed {}",
            localtx_receipts.len()
        );
    };
    let owner_decision = plan
        .jobs()
        .iter()
        .find(|job| job.key() == LOCALTX_OWNER)
        .context("CI impact plan is missing the LocalTx evidence owner")?;
    if !owner_decision.execute() {
        bail!("CI impact plan did not execute the LocalTx evidence owner");
    }
    let expected_artifact = LOCALTX_OWNER.expected_artifact(run_id, run_attempt);
    if owner_decision.expected_artifact() != expected_artifact {
        bail!("CI impact plan LocalTx owner artifact identity mismatch");
    }
    let generic_owner = generic_receipts
        .iter()
        .find(|receipt| receipt.job_key == LOCALTX_OWNER)
        .context("LocalTx owner generic evidence receipt is missing")?;
    if observed.artifact != expected_artifact || observed.artifact != generic_owner.artifact {
        bail!("LocalTx evidence is not paired with its owner generic artifact");
    }
    let receipt = &observed.receipt;
    if receipt.job_key() != LOCALTX_OWNER {
        bail!("LocalTx evidence owner mismatch");
    }
    if receipt.source_revision() != plan.execution_revision() {
        bail!("LocalTx evidence source revision mismatch");
    }
    if receipt.plan_digest() != plan.plan_digest() {
        bail!("LocalTx evidence plan digest mismatch");
    }
    if receipt.run_id() != run_id || receipt.run_attempt() != run_attempt {
        bail!("LocalTx evidence run identity mismatch");
    }
    Ok(receipt)
}

fn evaluate_localonly_required_evidence<'a>(
    plan: &CiImpactPlan,
    generic_receipts: &[ReceiptIdentity],
    localonly_reports: &'a [LocalOnlyReportIdentity],
    run_id: &str,
    run_attempt: &str,
) -> Result<&'a ValidatedLocalOnlyReport> {
    if localonly_reports.is_empty() {
        bail!("missing LocalOnly execution report");
    }
    let [observed] = localonly_reports else {
        bail!(
            "expected exactly one LocalOnly execution report, observed {}",
            localonly_reports.len()
        );
    };
    let owner_decision = plan
        .jobs()
        .iter()
        .find(|job| job.key() == LOCALONLY_OWNER)
        .context("CI impact plan is missing the LocalOnly evidence owner")?;
    if !owner_decision.execute() {
        bail!("CI impact plan did not execute the LocalOnly evidence owner");
    }
    let expected_artifact = LOCALONLY_OWNER.expected_artifact(run_id, run_attempt);
    if owner_decision.expected_artifact() != expected_artifact {
        bail!("CI impact plan LocalOnly owner artifact identity mismatch");
    }
    let generic_owner = generic_receipts
        .iter()
        .find(|receipt| receipt.job_key == LOCALONLY_OWNER)
        .context("LocalOnly owner generic evidence receipt is missing")?;
    if observed.artifact != expected_artifact || observed.artifact != generic_owner.artifact {
        bail!("LocalOnly evidence is not paired with its owner generic artifact");
    }
    let report = &observed.report;
    if report.job_key() != LOCALONLY_OWNER {
        bail!("LocalOnly evidence owner mismatch");
    }
    if report.source_revision() != plan.execution_revision() {
        bail!("LocalOnly evidence source revision mismatch");
    }
    let inventory =
        crate::consistency_effects::local_only_execution_inventory(&crate::workspace_root()?)?;
    let active = inventory
        .active_contract_ids
        .into_iter()
        .collect::<Vec<_>>();
    let source = inventory
        .source_receipt_contract_ids
        .into_iter()
        .collect::<Vec<_>>();
    if report.active_contract_ids() != active
        || report.source_receipt_contract_ids() != source
        || report.executed_contract_ids() != active
    {
        bail!(
            "LocalOnly evidence does not match the current active/source inventory: {}",
            exact_set_difference_summary(&active, &source, report.executed_contract_ids())
        );
    }
    Ok(report)
}

fn artifact_parent(path: &Path, root: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("receipt escapes root: {}", path.display()))?;
    let first = relative
        .components()
        .next()
        .context("CI evidence is not nested under its artifact directory")?;
    let std::path::Component::Normal(name) = first else {
        bail!("CI evidence artifact directory is not a normal path component");
    };
    let name = name
        .to_str()
        .context("CI evidence artifact directory is not UTF-8")?;
    if !name.starts_with("ci-evidence-") {
        bail!("CI evidence top-level artifact directory has an invalid identity");
    }
    Ok(name.to_owned())
}

fn evaluate(
    plan: &CiImpactPlan,
    receipts: &[ReceiptIdentity],
    planner_result: JobResult,
    matrix_result: JobResult,
    run_id: &str,
    run_attempt: &str,
) -> Result<()> {
    if planner_result != JobResult::Success {
        bail!("planner job did not succeed: {planner_result:?}");
    }
    if matrix_result != JobResult::Success {
        bail!("selected CI matrix did not succeed: {matrix_result:?}");
    }
    if plan.full_execution_required() && plan.jobs().iter().any(|job| !job.execute()) {
        bail!("full CI plan did not execute the closed catalog");
    }
    let mut expected = BTreeMap::new();
    for job in plan.jobs() {
        let canonical = job.key().expected_artifact(run_id, run_attempt);
        if job.expected_artifact() != canonical {
            bail!(
                "CI impact plan artifact identity mismatch for {}",
                job.key()
            );
        }
        if job.execute() {
            expected.insert(job.key(), canonical);
        }
    }
    let mut seen = BTreeSet::new();
    for receipt in receipts {
        if !seen.insert(receipt.job_key) {
            bail!("duplicate CI evidence receipt for {}", receipt.job_key);
        }
        let expected_artifact = expected
            .get(&receipt.job_key)
            .with_context(|| format!("unexpected CI evidence receipt for {}", receipt.job_key))?;
        if receipt.artifact != *expected_artifact {
            bail!(
                "CI evidence artifact identity mismatch for {}",
                receipt.job_key
            );
        }
        if receipt.source_revision != plan.execution_revision() {
            bail!(
                "CI evidence source revision mismatch for {}",
                receipt.job_key
            );
        }
        if receipt.plan_digest != plan.plan_digest() {
            bail!("CI evidence plan digest mismatch for {}", receipt.job_key);
        }
        if receipt.run_id != run_id || receipt.run_attempt != run_attempt {
            bail!("CI evidence run identity mismatch for {}", receipt.job_key);
        }
    }
    let missing = expected
        .keys()
        .copied()
        .filter(|key| !seen.contains(key))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("missing CI evidence receipts: {missing:?}");
    }
    Ok(())
}

#[cfg(test)]
struct GateFixture {
    plan: CiImpactPlan,
    receipts: Vec<ReceiptIdentity>,
    localtx_receipts: Vec<LocalTxReceiptIdentity>,
    localonly_reports: Vec<LocalOnlyReportIdentity>,
}

#[cfg(test)]
impl GateFixture {
    fn new() -> Result<Self> {
        let plan = crate::ci_impact::test_plan()?;
        let receipts = plan
            .jobs()
            .iter()
            .filter(|job| job.execute())
            .map(|job| ReceiptIdentity {
                artifact: job.expected_artifact().to_owned(),
                job_key: job.key(),
                source_revision: plan.execution_revision().to_owned(),
                plan_digest: plan.plan_digest().to_owned(),
                run_id: "42".to_owned(),
                run_attempt: "3".to_owned(),
                started_at: "2026-07-13T00:00:00Z".to_owned(),
                finished_at: "2026-07-13T00:01:00Z".to_owned(),
                cpu_time_ms: Some(1_000),
                peak_rss_bytes: Some(2_000),
                disk_low_water_bytes: 3_000,
                compiler_cache_requests: 4,
                compiler_cache_hits: 2,
            })
            .collect();
        let localtx_receipts = vec![test_localtx_identity(&plan)?];
        let localonly_reports = vec![test_localonly_identity(&plan)?];
        Ok(Self {
            plan,
            receipts,
            localtx_receipts,
            localonly_reports,
        })
    }

    fn evaluate(&self) -> Result<()> {
        evaluate(
            &self.plan,
            &self.receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )?;
        evaluate_localtx_required_evidence(
            &self.plan,
            &self.receipts,
            &self.localtx_receipts,
            "42",
            "3",
        )?;
        evaluate_localonly_required_evidence(
            &self.plan,
            &self.receipts,
            &self.localonly_reports,
            "42",
            "3",
        )?;
        Ok(())
    }

    fn evaluate_without_localtx_required_evidence(&self) -> Result<()> {
        evaluate(
            &self.plan,
            &self.receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )?;
        evaluate_localtx_required_evidence(&self.plan, &self.receipts, &[], "42", "3")?;
        Ok(())
    }

    fn evaluate_without_localonly_required_evidence(&self) -> Result<()> {
        evaluate(
            &self.plan,
            &self.receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )?;
        evaluate_localonly_required_evidence(&self.plan, &self.receipts, &[], "42", "3")?;
        Ok(())
    }

    fn evaluate_without_first(&self) -> Result<()> {
        evaluate(
            &self.plan,
            &self.receipts[1..],
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )
    }

    fn evaluate_with_duplicate(&self) -> Result<()> {
        let mut receipts = self.receipts.clone();
        receipts.push(receipts[0].clone());
        evaluate(
            &self.plan,
            &receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )
    }

    fn evaluate_with_wrong_revision(&self) -> Result<()> {
        let mut receipts = self.receipts.clone();
        receipts[0].source_revision = "wrong".to_owned();
        evaluate(
            &self.plan,
            &receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )
    }

    fn evaluate_with_wrong_digest_and_run(&self) -> [Result<()>; 2] {
        let mut wrong_digest = self.receipts.clone();
        wrong_digest[0].plan_digest = "c".repeat(64);
        let mut wrong_run = self.receipts.clone();
        wrong_run[0].run_attempt = "4".to_owned();
        [
            evaluate(
                &self.plan,
                &wrong_digest,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3",
            ),
            evaluate(
                &self.plan,
                &wrong_run,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3",
            ),
        ]
    }
}

#[cfg(test)]
fn localtx_receipt_value(plan: &CiImpactPlan) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "evidenceKind": "localtx-required",
        "jobKey": LOCALTX_OWNER,
        "sourceRevision": plan.execution_revision(),
        "planDigest": plan.plan_digest(),
        "runId": "42",
        "runAttempt": "3",
        "outcome": "success",
        "localtxActiveCount": 5,
        "localtxJourneyCount": 5,
        "localtxBackendProfileCount": 5,
    })
}

#[cfg(test)]
fn test_localtx_identity(plan: &CiImpactPlan) -> Result<LocalTxReceiptIdentity> {
    Ok(LocalTxReceiptIdentity {
        artifact: LOCALTX_OWNER.expected_artifact("42", "3"),
        receipt: ValidatedLocalTxReceipt::parse(&serde_json::to_string(&localtx_receipt_value(
            plan,
        ))?)?,
    })
}

#[cfg(test)]
fn localonly_report_value(plan: &CiImpactPlan) -> Result<serde_json::Value> {
    let root = crate::workspace_root()?;
    let inventory = crate::consistency_effects::local_only_execution_inventory(&root)?;
    let active = inventory
        .active_contract_ids
        .into_iter()
        .collect::<Vec<_>>();
    let source = inventory
        .source_receipt_contract_ids
        .into_iter()
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "schemaVersion": 1,
        "jobKey": LOCALONLY_OWNER,
        "sourceRevision": plan.execution_revision(),
        "activeContractIds": active.clone(),
        "sourceReceiptContractIds": source,
        "executedContractIds": active,
    }))
}

#[cfg(test)]
fn test_localonly_identity(plan: &CiImpactPlan) -> Result<LocalOnlyReportIdentity> {
    Ok(LocalOnlyReportIdentity {
        artifact: LOCALONLY_OWNER.expected_artifact("42", "3"),
        report: ValidatedLocalOnlyReport::parse(&serde_json::to_string(&localonly_report_value(
            plan,
        )?)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_receipt(
        root: &Path,
        plan: &CiImpactPlan,
        key: CiJobKey,
        artifact: &str,
        nested: &str,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<()> {
        let mut evidence: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/ci_slo/pass.json"))?;
        evidence["job"]["ciJobKey"] = serde_json::to_value(key)?;
        evidence["job"]["sourceRevision"] = plan.execution_revision().into();
        evidence["job"]["planDigest"] = plan.plan_digest().into();
        evidence["job"]["runId"] = "42".into();
        evidence["job"]["runAttempt"] = "3".into();
        mutate(&mut evidence);
        let directory = root.join(artifact).join(nested);
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join("ci-evidence.json"),
            serde_json::to_string_pretty(&evidence)?,
        )?;
        Ok(())
    }

    fn write_exact_receipts(root: &Path, plan: &CiImpactPlan) -> Result<()> {
        for job in plan.jobs().iter().filter(|job| job.execute()) {
            write_receipt(root, plan, job.key(), job.expected_artifact(), "ci", |_| {})?;
        }
        write_localtx_receipt(
            root,
            plan,
            LOCALTX_OWNER.expected_artifact("42", "3"),
            |_| {},
        )?;
        write_localonly_report(
            root,
            plan,
            LOCALONLY_OWNER.expected_artifact("42", "3"),
            |_| {},
        )?;
        Ok(())
    }

    fn write_localtx_receipt(
        root: &Path,
        plan: &CiImpactPlan,
        artifact: String,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<()> {
        let mut receipt = localtx_receipt_value(plan);
        mutate(&mut receipt);
        let directory = root.join(artifact).join("integration");
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join(LOCALTX_FILE_NAME),
            serde_json::to_vec_pretty(&receipt)?,
        )?;
        Ok(())
    }

    fn localtx_path(root: &Path) -> PathBuf {
        root.join(LOCALTX_OWNER.expected_artifact("42", "3"))
            .join("integration")
            .join(LOCALTX_FILE_NAME)
    }

    fn write_localonly_report(
        root: &Path,
        plan: &CiImpactPlan,
        artifact: String,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> Result<()> {
        let mut report = localonly_report_value(plan)?;
        mutate(&mut report);
        let directory = root.join(artifact).join("local-only");
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join(LOCALONLY_FILE_NAME),
            serde_json::to_vec_pretty(&report)?,
        )?;
        Ok(())
    }

    fn localonly_path(root: &Path) -> PathBuf {
        root.join(LOCALONLY_OWNER.expected_artifact("42", "3"))
            .join("local-only")
            .join(LOCALONLY_FILE_NAME)
    }

    fn evaluate_disk_fixture(root: &Path, fixture: &GateFixture) -> Result<()> {
        let generic = observe_receipts(root);
        if let Some(failure) = generic.failure {
            return Err(failure.error);
        }
        let localtx = observe_localtx_receipts(root);
        if let Some(failure) = localtx.failure {
            return Err(failure.error);
        }
        let localonly = observe_localonly_reports(root);
        if let Some(failure) = localonly.failure {
            return Err(failure.error);
        }
        evaluate(
            &fixture.plan,
            &generic.receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )?;
        evaluate_localtx_required_evidence(
            &fixture.plan,
            &generic.receipts,
            &localtx.receipts,
            "42",
            "3",
        )?;
        evaluate_localonly_required_evidence(
            &fixture.plan,
            &generic.receipts,
            &localonly.reports,
            "42",
            "3",
        )?;
        Ok(())
    }

    #[test]
    fn gate_rejects_missing_duplicate_and_mismatched_receipts_red() -> Result<()> {
        let fixture = GateFixture::new()?;
        assert!(fixture.evaluate_without_first().is_err());
        assert!(fixture.evaluate_with_duplicate().is_err());
        assert!(fixture.evaluate_with_wrong_revision().is_err());
        assert!(
            fixture
                .evaluate_with_wrong_digest_and_run()
                .into_iter()
                .all(|result| result.is_err())
        );
        Ok(())
    }

    #[test]
    fn gate_rejects_complete_generic_receipts_without_localtx_required_evidence_red() -> Result<()>
    {
        let fixture = GateFixture::new()?;
        assert_eq!(
            fixture.receipts.len(),
            fixture
                .plan
                .jobs()
                .iter()
                .filter(|job| job.execute())
                .count(),
            "fixture must remain anti-vacuous: every executed job has generic CI evidence"
        );
        assert!(
            fixture
                .receipts
                .iter()
                .any(|receipt| receipt.job_key == CiJobKey::IntegrationPostgresDomain),
            "fixture must include the LocalTx evidence owner's generic receipt"
        );
        assert!(
            fixture
                .evaluate_without_localtx_required_evidence()
                .is_err(),
            "ci-gate must reject planner/matrix success when LocalTx required evidence is absent"
        );
        Ok(())
    }

    #[test]
    fn gate_rejects_complete_generic_receipts_without_localonly_required_evidence_red() -> Result<()>
    {
        let fixture = GateFixture::new()?;
        assert!(
            fixture
                .receipts
                .iter()
                .any(|receipt| { receipt.job_key == LOCALONLY_OWNER })
        );
        assert!(
            fixture
                .evaluate_without_localonly_required_evidence()
                .is_err(),
            "ci-gate must reject generic success when LocalOnly execution evidence is absent"
        );
        Ok(())
    }

    #[test]
    fn missing_localonly_report_is_explicit_in_the_human_summary_red() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-localonly-summary-missing");
        let plan_path = root.join("plan.json");
        let receipts_path = root.join("receipts");
        fs::create_dir_all(&root)?;
        fs::write(&plan_path, fixture.plan.to_json()?)?;
        write_exact_receipts(&receipts_path, &fixture.plan)?;
        fs::remove_file(localonly_path(&receipts_path))?;
        let options = Options {
            plan_path,
            receipts_path,
            planner_result: JobResult::Success,
            matrix_result: JobResult::Success,
            metrics_output: root.join("metrics.json"),
        };
        let runtime = RuntimeIdentity {
            run_id: Some("42".to_owned()),
            run_attempt: Some("3".to_owned()),
            execution_revision: Some("e".repeat(40)),
            summary_path: Some(root.join("summary.md")),
        };

        assert!(run_with_runtime(&options, &runtime).is_err());
        let summary = fs::read_to_string(
            runtime
                .summary_path
                .as_ref()
                .context("missing LocalOnly summary path")?,
        )?;
        assert!(summary.contains("Failure class: `localonly-evidence`"));
        assert!(summary.contains("missing LocalOnly execution report"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn gate_accepts_exact_receipt_set_green() -> Result<()> {
        let fixture = GateFixture::new()?;
        fixture.evaluate()?;
        let metrics = build_metrics(&fixture.plan, &fixture.receipts)?;
        assert_eq!(metrics.recommended_jobs, 3);
        assert_eq!(metrics.executed_jobs, CiJobKey::COUNT);
        assert_eq!(metrics.skipped_runner_jobs, CiJobKey::COUNT - 3);
        assert_eq!(metrics.cpu_time_ms, 16_000);
        assert_eq!(metrics.projected_saved_cpu_time_ms, 13_000);
        Ok(())
    }

    #[test]
    fn gate_rejects_legacy_evidence_schema() -> Result<()> {
        let root = crate::testutil::unique_tmp("ci-gate-v3");
        let artifact = root.join("ci-evidence-ci-meta-workspace-unpartitioned-42-3/ci");
        fs::create_dir_all(&artifact)?;
        fs::write(
            artifact.join("ci-evidence.json"),
            include_str!("../tests/fixtures/ci_slo/pass.json").replacen(
                "\"schemaVersion\": 4",
                "\"schemaVersion\": 3",
                1,
            ),
        )?;
        assert!(load_receipts(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn gate_rejects_evidence_shape_that_slo_rejects_red() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-shared-evidence-validator");
        let key = CiJobKey::CiMeta;
        write_receipt(
            &root,
            &fixture.plan,
            key,
            key.expected_artifact("42", "3").as_str(),
            "ci",
            |evidence| {
                evidence["snapshots"][0]["stage"] = "after-cache".into();
            },
        )?;
        assert!(
            load_receipts(&root).is_err(),
            "ci-gate must apply the same closed evidence-v4 shape validation as ci-slo"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn artifact_identity_rejects_forged_top_level_with_legitimate_nested_name() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-forged-artifact-parent");
        let key = CiJobKey::CiMeta;
        let expected = key.expected_artifact("42", "3");
        write_receipt(
            &root,
            &fixture.plan,
            key,
            "ci-evidence-forged-workspace-unpartitioned-42-3",
            &format!("nested/{expected}/ci"),
            |_| {},
        )?;
        let receipts = load_receipts(&root)?;
        assert!(
            evaluate(
                &fixture.plan,
                &receipts,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3",
            )
            .is_err(),
            "nested directory names must not impersonate the downloaded artifact identity"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn disk_receipts_cover_green_and_identity_red_matrix() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-disk-receipts");
        write_exact_receipts(&root, &fixture.plan)?;
        let receipts = load_receipts(&root)?;
        evaluate(
            &fixture.plan,
            &receipts,
            JobResult::Success,
            JobResult::Success,
            "42",
            "3",
        )?;

        let first = fixture.plan.jobs()[0].key();
        let first_artifact = fixture.plan.jobs()[0].expected_artifact();
        for (label, mutation) in [
            ("sha", ("sourceRevision", serde_json::json!("f".repeat(40)))),
            ("digest", ("planDigest", serde_json::json!("f".repeat(64)))),
            ("run", ("runAttempt", serde_json::json!("4"))),
        ] {
            let red = crate::testutil::unique_tmp(&format!("ci-gate-disk-{label}"));
            write_exact_receipts(&red, &fixture.plan)?;
            let path = red.join(first_artifact).join("ci/ci-evidence.json");
            let mut evidence: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path)?)?;
            evidence["job"][mutation.0] = mutation.1;
            fs::write(&path, serde_json::to_string_pretty(&evidence)?)?;
            let receipts = load_receipts(&red)?;
            assert!(
                evaluate(
                    &fixture.plan,
                    &receipts,
                    JobResult::Success,
                    JobResult::Success,
                    "42",
                    "3"
                )
                .is_err(),
                "{label} identity drift must fail"
            );
            fs::remove_dir_all(red)?;
        }

        let duplicate = crate::testutil::unique_tmp("ci-gate-disk-duplicate");
        write_exact_receipts(&duplicate, &fixture.plan)?;
        write_receipt(
            &duplicate,
            &fixture.plan,
            first,
            first_artifact,
            "duplicate",
            |_| {},
        )?;
        assert!(
            evaluate(
                &fixture.plan,
                &load_receipts(&duplicate)?,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3"
            )
            .is_err()
        );
        fs::remove_dir_all(duplicate)?;

        let wrong_artifact = crate::testutil::unique_tmp("ci-gate-disk-wrong-artifact");
        write_exact_receipts(&wrong_artifact, &fixture.plan)?;
        fs::rename(
            wrong_artifact.join(first_artifact),
            wrong_artifact.join("ci-evidence-wrong-workspace-unpartitioned-42-3"),
        )?;
        assert!(
            evaluate(
                &fixture.plan,
                &load_receipts(&wrong_artifact)?,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3"
            )
            .is_err()
        );
        fs::remove_dir_all(wrong_artifact)?;

        let schema = crate::testutil::unique_tmp("ci-gate-disk-schema");
        write_exact_receipts(&schema, &fixture.plan)?;
        let path = schema.join(first_artifact).join("ci/ci-evidence.json");
        let mut evidence: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        evidence["schemaVersion"] = 3.into();
        fs::write(path, serde_json::to_string_pretty(&evidence)?)?;
        assert!(load_receipts(&schema).is_err());
        fs::remove_dir_all(schema)?;

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn localtx_required_evidence_disk_red_matrix() -> Result<()> {
        let fixture = GateFixture::new()?;
        let green = crate::testutil::unique_tmp("ci-gate-localtx-green");
        write_exact_receipts(&green, &fixture.plan)?;
        evaluate_disk_fixture(&green, &fixture)?;
        fs::remove_dir_all(green)?;

        let missing = crate::testutil::unique_tmp("ci-gate-localtx-missing");
        write_exact_receipts(&missing, &fixture.plan)?;
        fs::remove_file(localtx_path(&missing))?;
        assert!(evaluate_disk_fixture(&missing, &fixture).is_err());
        fs::remove_dir_all(missing)?;

        let duplicate = crate::testutil::unique_tmp("ci-gate-localtx-duplicate");
        write_exact_receipts(&duplicate, &fixture.plan)?;
        let nested = localtx_path(&duplicate)
            .parent()
            .context("LocalTx fixture parent")?
            .join("nested")
            .join(LOCALTX_FILE_NAME);
        fs::create_dir_all(nested.parent().context("nested fixture parent")?)?;
        fs::copy(localtx_path(&duplicate), nested)?;
        assert!(evaluate_disk_fixture(&duplicate, &fixture).is_err());
        fs::remove_dir_all(duplicate)?;

        let wrong_artifact = crate::testutil::unique_tmp("ci-gate-localtx-wrong-artifact");
        write_exact_receipts(&wrong_artifact, &fixture.plan)?;
        let wrong_path = wrong_artifact
            .join(CiJobKey::CiMeta.expected_artifact("42", "3"))
            .join("integration")
            .join(LOCALTX_FILE_NAME);
        fs::create_dir_all(wrong_path.parent().context("wrong artifact parent")?)?;
        fs::rename(localtx_path(&wrong_artifact), wrong_path)?;
        assert!(evaluate_disk_fixture(&wrong_artifact, &fixture).is_err());
        fs::remove_dir_all(wrong_artifact)?;

        for (label, field, value) in [
            ("schema", "schemaVersion", serde_json::json!(0)),
            ("outcome", "outcome", serde_json::json!("failure")),
            ("active-four", "localtxActiveCount", serde_json::json!(4)),
            ("active-six", "localtxActiveCount", serde_json::json!(6)),
            ("journey-four", "localtxJourneyCount", serde_json::json!(4)),
            ("journey-six", "localtxJourneyCount", serde_json::json!(6)),
            (
                "backend-four",
                "localtxBackendProfileCount",
                serde_json::json!(4),
            ),
            (
                "backend-six",
                "localtxBackendProfileCount",
                serde_json::json!(6),
            ),
            (
                "stale-source",
                "sourceRevision",
                serde_json::json!("f".repeat(40)),
            ),
            (
                "stale-plan",
                "planDigest",
                serde_json::json!("f".repeat(64)),
            ),
            ("stale-run", "runAttempt", serde_json::json!("4")),
        ] {
            let root = crate::testutil::unique_tmp(&format!("ci-gate-localtx-{label}"));
            write_exact_receipts(&root, &fixture.plan)?;
            let path = localtx_path(&root);
            let mut receipt: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
            receipt[field] = value;
            fs::write(path, serde_json::to_vec_pretty(&receipt)?)?;
            assert!(evaluate_disk_fixture(&root, &fixture).is_err(), "{label}");
            fs::remove_dir_all(root)?;
        }

        let unknown = crate::testutil::unique_tmp("ci-gate-localtx-unknown");
        write_exact_receipts(&unknown, &fixture.plan)?;
        let path = localtx_path(&unknown);
        let mut receipt: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        receipt["staticProofInventory"] = serde_json::json!({"active": 5});
        fs::write(path, serde_json::to_vec_pretty(&receipt)?)?;
        assert!(evaluate_disk_fixture(&unknown, &fixture).is_err());
        fs::remove_dir_all(unknown)?;

        let static_bait = crate::testutil::unique_tmp("ci-gate-localtx-static-bait");
        write_exact_receipts(&static_bait, &fixture.plan)?;
        fs::write(
            localtx_path(&static_bait),
            r#"{"schemaVersion":1,"activeContracts":5,"journeys":5,"backendProfiles":5}"#,
        )?;
        assert!(evaluate_disk_fixture(&static_bait, &fixture).is_err());
        fs::remove_dir_all(static_bait)?;
        Ok(())
    }

    #[test]
    fn localonly_required_evidence_disk_red_matrix() -> Result<()> {
        let fixture = GateFixture::new()?;
        let green = crate::testutil::unique_tmp("ci-gate-localonly-green");
        write_exact_receipts(&green, &fixture.plan)?;
        evaluate_disk_fixture(&green, &fixture)?;
        fs::remove_dir_all(green)?;

        let missing = crate::testutil::unique_tmp("ci-gate-localonly-missing");
        write_exact_receipts(&missing, &fixture.plan)?;
        fs::remove_file(localonly_path(&missing))?;
        assert!(evaluate_disk_fixture(&missing, &fixture).is_err());
        fs::remove_dir_all(missing)?;

        let duplicate = crate::testutil::unique_tmp("ci-gate-localonly-duplicate");
        write_exact_receipts(&duplicate, &fixture.plan)?;
        let nested = localonly_path(&duplicate)
            .parent()
            .context("LocalOnly fixture parent")?
            .join("nested")
            .join(LOCALONLY_FILE_NAME);
        fs::create_dir_all(nested.parent().context("nested fixture parent")?)?;
        fs::copy(localonly_path(&duplicate), nested)?;
        assert!(evaluate_disk_fixture(&duplicate, &fixture).is_err());
        fs::remove_dir_all(duplicate)?;

        let wrong_artifact = crate::testutil::unique_tmp("ci-gate-localonly-wrong-artifact");
        write_exact_receipts(&wrong_artifact, &fixture.plan)?;
        let wrong_path = wrong_artifact
            .join(CiJobKey::CiMeta.expected_artifact("42", "3"))
            .join("local-only")
            .join(LOCALONLY_FILE_NAME);
        fs::create_dir_all(wrong_path.parent().context("wrong artifact parent")?)?;
        fs::rename(localonly_path(&wrong_artifact), wrong_path)?;
        assert!(evaluate_disk_fixture(&wrong_artifact, &fixture).is_err());
        fs::remove_dir_all(wrong_artifact)?;

        for (label, mutate) in [
            ("schema", ("schemaVersion", serde_json::json!(0))),
            ("owner", ("jobKey", serde_json::json!("ci-meta"))),
            (
                "source",
                ("sourceRevision", serde_json::json!("f".repeat(40))),
            ),
            (
                "equal-count-wrong-set",
                (
                    "allSets",
                    serde_json::json!([
                        "audit.list-entries",
                        "identity.policies-get",
                        "identity.policies-list",
                        "identity.profile",
                        "identity.roles-list",
                        "settings.config-list",
                        "settings.secret-resolve"
                    ]),
                ),
            ),
        ] {
            let root = crate::testutil::unique_tmp(&format!("ci-gate-localonly-{label}"));
            write_exact_receipts(&root, &fixture.plan)?;
            let path = localonly_path(&root);
            let mut report: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
            if mutate.0 == "allSets" {
                for field in [
                    "activeContractIds",
                    "sourceReceiptContractIds",
                    "executedContractIds",
                ] {
                    report[field] = mutate.1.clone();
                }
            } else {
                report[mutate.0] = mutate.1;
            }
            fs::write(&path, serde_json::to_vec_pretty(&report)?)?;
            if label == "equal-count-wrong-set" {
                let parsed = ValidatedLocalOnlyReport::load(&path)?;
                assert_eq!(parsed.active_contract_ids().len(), 7);
                assert_eq!(parsed.source_receipt_contract_ids().len(), 7);
                assert_eq!(parsed.executed_contract_ids().len(), 7);
            }
            let result = evaluate_disk_fixture(&root, &fixture);
            if label == "equal-count-wrong-set" {
                let Err(error) = result else {
                    bail!("wrong LocalOnly set must fail at the gate");
                };
                assert!(
                    error.to_string().contains(
                        "missing_from_source=[] extra_in_source=[] missing_from_executed=[\"settings.config-get\"] extra_in_executed=[\"settings.config-list\"]"
                    ),
                    "{error:#}"
                );
            } else {
                assert!(result.is_err(), "{label}");
            }
            fs::remove_dir_all(root)?;
        }

        let unknown = crate::testutil::unique_tmp("ci-gate-localonly-unknown");
        write_exact_receipts(&unknown, &fixture.plan)?;
        let path = localonly_path(&unknown);
        let mut report: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        report["legacyCount"] = 6.into();
        fs::write(path, serde_json::to_vec_pretty(&report)?)?;
        assert!(evaluate_disk_fixture(&unknown, &fixture).is_err());
        fs::remove_dir_all(unknown)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn localonly_required_evidence_symlink_is_classified_fail_closed() -> Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-localonly-symlink");
        write_exact_receipts(&root, &fixture.plan)?;
        let path = localonly_path(&root);
        let target = path.with_file_name("target.json");
        fs::rename(&path, &target)?;
        symlink(&target, &path)?;
        let observation = observe_localonly_reports(&root);
        assert!(observation.failure.is_some());
        assert_eq!(
            observation.failure.context("missing failure")?.class,
            GateFailureClass::LocalonlyEvidence
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn localtx_required_evidence_symlink_is_classified_fail_closed() -> Result<()> {
        use std::os::unix::fs::symlink;

        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-localtx-symlink");
        write_exact_receipts(&root, &fixture.plan)?;
        let path = localtx_path(&root);
        let target = path.with_file_name("target.json");
        fs::rename(&path, &target)?;
        symlink(&target, &path)?;
        let observation = observe_localtx_receipts(&root);
        assert!(observation.failure.is_some());
        assert_eq!(
            observation.failure.context("missing failure")?.class,
            GateFailureClass::LocaltxEvidence
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn gate_failure_paths_persist_closed_envelope_and_safe_summary() -> Result<()> {
        let root = crate::testutil::unique_tmp("ci-gate-failure-envelope");
        fs::create_dir_all(&root)?;
        let options = Options {
            plan_path: root.join("missing-plan.json"),
            receipts_path: root.join("missing-receipts"),
            planner_result: JobResult::Failure,
            matrix_result: JobResult::Skipped,
            metrics_output: root.join("metrics.json"),
        };
        let runtime = RuntimeIdentity {
            run_id: Some("42".to_owned()),
            run_attempt: Some("3".to_owned()),
            execution_revision: Some("e".repeat(40)),
            summary_path: Some(root.join("summary.md")),
        };
        assert!(run_with_runtime(&options, &runtime).is_err());
        let serialized = fs::read_to_string(&options.metrics_output)?;
        assert_eq!(
            format!("{serialized}\n"),
            include_str!("../tests/golden/ci-gate-envelope-v3-failure.json"),
            "failure envelope v3 wire drifted"
        );
        let metrics: serde_json::Value = serde_json::from_str(&serialized)?;
        assert_eq!(metrics["schemaVersion"], 3);
        assert_eq!(metrics["verdict"], "failure");
        assert_eq!(metrics["failureClass"], "planner-result");
        assert_eq!(metrics["plannerResult"], "failure");
        assert_eq!(metrics["matrixResult"], "skipped");
        assert_eq!(metrics["observedReceiptCount"], 0);
        assert!(metrics["localtxActiveCount"].is_null());
        assert!(metrics["localtxJourneyCount"].is_null());
        assert!(metrics["localtxBackendProfileCount"].is_null());
        assert!(metrics["localonlyContractCount"].is_null());
        let summary = fs::read_to_string(
            runtime
                .summary_path
                .as_ref()
                .context("failure fixture summary path is missing")?,
        )?;
        assert!(summary.contains("Result: `failure`"));
        assert!(summary.contains("Failure class: `planner-result`"));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn all_failure_stages_persist_a_classified_envelope_before_returning() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-all-failure-envelopes");
        fs::create_dir_all(&root)?;
        let plan_path = root.join("plan.json");
        fs::write(&plan_path, fixture.plan.to_json()?)?;
        let runtime = RuntimeIdentity {
            run_id: Some("42".to_owned()),
            run_attempt: Some("3".to_owned()),
            execution_revision: Some("e".repeat(40)),
            summary_path: Some(root.join("summary.md")),
        };

        let assert_failure = |label: &str,
                              plan_path: PathBuf,
                              receipts_path: PathBuf,
                              planner_result: JobResult,
                              matrix_result: JobResult,
                              runtime: &RuntimeIdentity,
                              expected: &str|
         -> Result<()> {
            let metrics_output = root.join(format!("metrics-{label}.json"));
            let options = Options {
                plan_path,
                receipts_path,
                planner_result,
                matrix_result,
                metrics_output: metrics_output.clone(),
            };
            assert!(run_with_runtime(&options, runtime).is_err(), "{label}");
            let envelope: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(metrics_output)?)?;
            assert_eq!(envelope["verdict"], "failure", "{label}");
            assert_eq!(envelope["failureClass"], expected, "{label}");
            Ok(())
        };

        for planner_result in [JobResult::Failure, JobResult::Cancelled, JobResult::Skipped] {
            assert_failure(
                planner_result.as_str(),
                root.join("absent-plan"),
                root.join("absent-receipts"),
                planner_result,
                JobResult::Skipped,
                &runtime,
                "planner-result",
            )?;
        }
        for matrix_result in [JobResult::Failure, JobResult::Cancelled, JobResult::Skipped] {
            assert_failure(
                &format!("matrix-{}", matrix_result.as_str()),
                plan_path.clone(),
                root.join("absent-receipts"),
                JobResult::Success,
                matrix_result,
                &runtime,
                "matrix-result",
            )?;
        }
        assert_failure(
            "plan-io",
            root.join("absent-plan-io"),
            root.join("absent-receipts"),
            JobResult::Success,
            JobResult::Success,
            &runtime,
            "plan-io",
        )?;
        let invalid_plan = root.join("invalid-plan.json");
        fs::write(&invalid_plan, "{}")?;
        assert_failure(
            "plan-invalid",
            invalid_plan,
            root.join("absent-receipts"),
            JobResult::Success,
            JobResult::Success,
            &runtime,
            "plan-invalid",
        )?;
        let invalid_receipts = root.join("invalid-receipts");
        let injected_artifact = "ci-evidence-invalid`\n# injected-42-3";
        fs::create_dir_all(invalid_receipts.join(injected_artifact).join("ci"))?;
        fs::write(
            invalid_receipts
                .join(injected_artifact)
                .join("ci/ci-evidence.json"),
            "not-json",
        )?;
        assert_failure(
            "receipt-load",
            plan_path.clone(),
            invalid_receipts,
            JobResult::Success,
            JobResult::Success,
            &runtime,
            "receipt-load",
        )?;
        let summary = fs::read_to_string(
            runtime
                .summary_path
                .as_ref()
                .context("classified failure summary path is missing")?,
        )?;
        assert!(!summary.contains("\n# injected"));
        assert!(!summary.contains("invalid`"));
        assert_failure(
            "receipt-validation",
            plan_path.clone(),
            root.join("absent-receipts"),
            JobResult::Success,
            JobResult::Success,
            &runtime,
            "receipt-validation",
        )?;
        let exact = root.join("exact-receipts");
        write_exact_receipts(&exact, &fixture.plan)?;
        let wrong_execution_revision = RuntimeIdentity {
            run_id: Some("42".to_owned()),
            run_attempt: Some("3".to_owned()),
            execution_revision: Some("f".repeat(40)),
            summary_path: Some(root.join("summary-execution-revision.md")),
        };
        assert_failure(
            "execution-revision",
            plan_path.clone(),
            exact.clone(),
            JobResult::Success,
            JobResult::Success,
            &wrong_execution_revision,
            "execution-revision",
        )?;

        let oversized_metrics = root.join("oversized-metrics-receipts");
        write_exact_receipts(&oversized_metrics, &fixture.plan)?;
        for job in fixture.plan.jobs().iter().filter(|job| job.execute()) {
            let path = oversized_metrics
                .join(job.expected_artifact())
                .join("ci/ci-evidence.json");
            let mut evidence: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path)?)?;
            evidence["snapshots"][4]["resourceUsage"]["cpuTimeMs"] = MAX_JSON_INTEGER.into();
            fs::write(path, serde_json::to_vec_pretty(&evidence)?)?;
        }
        assert_failure(
            "metrics-build",
            plan_path.clone(),
            oversized_metrics,
            JobResult::Success,
            JobResult::Success,
            &runtime,
            "metrics-build",
        )?;

        let missing_runtime = RuntimeIdentity {
            run_id: None,
            run_attempt: None,
            execution_revision: None,
            summary_path: Some(root.join("summary-missing-runtime.md")),
        };
        assert_failure(
            "run-identity",
            plan_path.clone(),
            exact,
            JobResult::Success,
            JobResult::Success,
            &missing_runtime,
            "run-identity",
        )?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn successful_run_persists_the_existing_resource_metrics_in_the_envelope() -> Result<()> {
        let fixture = GateFixture::new()?;
        let root = crate::testutil::unique_tmp("ci-gate-success-envelope");
        let plan_path = root.join("plan.json");
        let receipts_path = root.join("receipts");
        fs::create_dir_all(&root)?;
        fs::write(&plan_path, fixture.plan.to_json()?)?;
        write_exact_receipts(&receipts_path, &fixture.plan)?;
        let options = Options {
            plan_path,
            receipts_path,
            planner_result: JobResult::Success,
            matrix_result: JobResult::Success,
            metrics_output: root.join("metrics.json"),
        };
        let runtime = RuntimeIdentity {
            run_id: Some("42".to_owned()),
            run_attempt: Some("3".to_owned()),
            execution_revision: Some("e".repeat(40)),
            summary_path: Some(root.join("summary.md")),
        };
        run_with_runtime(&options, &runtime)?;
        let serialized = fs::read_to_string(&options.metrics_output)?;
        assert_eq!(
            format!("{serialized}\n"),
            include_str!("../tests/golden/ci-gate-envelope-v3-success.json"),
            "success envelope v3 wire drifted"
        );
        let envelope: serde_json::Value = serde_json::from_str(&serialized)?;
        assert_eq!(envelope["schemaVersion"], 3);
        assert_eq!(envelope["verdict"], "success");
        assert!(envelope["failureClass"].is_null());
        assert_eq!(envelope["observedReceiptCount"], CiJobKey::COUNT);
        assert_eq!(envelope["localtxActiveCount"], 5);
        assert_eq!(envelope["localtxJourneyCount"], 5);
        assert_eq!(envelope["localtxBackendProfileCount"], 5);
        assert_eq!(envelope["localonlyContractCount"], 7);
        assert_eq!(envelope["successMetrics"]["executedJobs"], CiJobKey::COUNT);
        assert_eq!(
            envelope["successMetrics"]["recommendedJobs"],
            fixture
                .plan
                .jobs()
                .iter()
                .filter(|job| job.recommended())
                .count()
        );
        let summary = fs::read_to_string(
            runtime
                .summary_path
                .as_ref()
                .context("success fixture summary path is missing")?,
        )?;
        assert!(summary.contains("Result: `success`"));
        assert!(summary.contains("LocalTx required evidence: `5/5/5`"));
        assert!(summary.contains(&format!(
            "LocalOnly required evidence: exact-set active/source/executed = `7/7/7` @ `{}`",
            "e".repeat(40)
        )));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn disk_receipts_reject_missing_and_extra_known_jobs() -> Result<()> {
        let full = GateFixture::new()?;
        let missing = crate::testutil::unique_tmp("ci-gate-disk-missing");
        write_exact_receipts(&missing, &full.plan)?;
        fs::remove_dir_all(missing.join(full.plan.jobs()[0].expected_artifact()))?;
        assert!(
            evaluate(
                &full.plan,
                &load_receipts(&missing)?,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3"
            )
            .is_err()
        );
        fs::remove_dir_all(missing)?;

        let adaptive = crate::ci_impact::test_adaptive_plan()?;
        let extra = crate::testutil::unique_tmp("ci-gate-disk-extra-known");
        write_exact_receipts(&extra, &adaptive)?;
        let extra_key = CiJobKey::CiSecurity;
        write_receipt(
            &extra,
            &adaptive,
            extra_key,
            &extra_key.expected_artifact("42", "3"),
            "ci",
            |_| {},
        )?;
        assert!(
            evaluate(
                &adaptive,
                &load_receipts(&extra)?,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3"
            )
            .is_err()
        );
        fs::remove_dir_all(extra)?;

        let noncanonical = crate::ci_impact::test_plan_with_noncanonical_artifact()?;
        let wrong_plan_artifact =
            crate::testutil::unique_tmp("ci-gate-disk-noncanonical-plan-artifact");
        write_exact_receipts(&wrong_plan_artifact, &noncanonical)?;
        assert!(
            evaluate(
                &noncanonical,
                &load_receipts(&wrong_plan_artifact)?,
                JobResult::Success,
                JobResult::Success,
                "42",
                "3"
            )
            .is_err()
        );
        fs::remove_dir_all(wrong_plan_artifact)?;
        Ok(())
    }

    #[test]
    fn non_success_job_results_fail_closed() -> Result<()> {
        let fixture = GateFixture::new()?;
        for result in [JobResult::Failure, JobResult::Cancelled, JobResult::Skipped] {
            assert!(
                evaluate(
                    &fixture.plan,
                    &fixture.receipts,
                    result,
                    JobResult::Success,
                    "42",
                    "3"
                )
                .is_err()
            );
            assert!(
                evaluate(
                    &fixture.plan,
                    &fixture.receipts,
                    JobResult::Success,
                    result,
                    "42",
                    "3"
                )
                .is_err()
            );
        }
        Ok(())
    }
}
