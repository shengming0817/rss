//! Typed, fail-safe CI impact planning for GitHub Actions.
//!
//! INVARIANT: CI-IMPACT-PLAN-01 { level = "Hard", exec = "native-compile", source = "code", native = "validated plan construction owns the closed 15-job array and matrix derivation" }.
//! INVARIANT: CI-IMPACT-POLICY-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "policy_rejects_unknown_and_rename_red", anti_vacuity = "workspace_policy_catalog_is_non_vacuous" }.
//! INVARIANT: CI-IMPACT-PROJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private ImpactSet construction and exhaustive local/remote projections prevent divergent path maps" }.

use crate::ci_lanes::{CiJobKey, CiLane};
use crate::cmd::{CargoSubcommand, ExternalProgram, cargo_cmd, external_cmd};
use crate::contract::manifest::{ContractManifest, ContractOwner};
use crate::integration_shards::{self, IntegrationShard, LocalFeatureScope};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PLAN_SCHEMA_VERSION: u8 = 1;
const POLICY_SCHEMA_VERSION: u8 = 1;
const UNKNOWN_REVISION: &str = "unknown";
const DOCUMENTATION_PATHS: &[&str] = &["README.md"];
const DOCUMENTATION_PREFIXES: &[&str] = &["docs/"];
const DOCUMENTATION_GOVERNED_PREFIXES: &[&str] = &["docs/rules/", "docs/architecture/"];
const MACHINE_INPUT_PATHS: &[&str] = &[
    "docs/ops/localtx-alerts.rules.yaml",
    "docs/ops/202607082104-1642-consistency-dashboard-checklist.md",
    "docs/runbooks/202607130312-1705-localtx-unsafe-settlement.md",
    "docs/runbooks/202607081921-1633-cdc-outbox.md",
    "docs/ops/localtx-proof-report.md",
    "docs/rules/localtx.md",
];
const POLICY_BEHAVIOR_SPEC: &str = include_str!("../tests/golden/ci-impact-policy.json");
const HIGH_IMPACT_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
    "clippy.toml",
    "Makefile",
    "CLAUDE.md",
];
const HIGH_IMPACT_PREFIXES: &[&str] = &[
    ".github/",
    ".claude/rules/",
    ".config/ci-impact",
    "hack/",
    "xtask/",
    "docs/rules/",
    "docs/architecture/",
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Options {
    pub(crate) event_path: PathBuf,
    pub(crate) policy_path: PathBuf,
    pub(crate) output_path: PathBuf,
    pub(crate) github_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalOptions {
    base: String,
}

pub(crate) fn parse_local_options(args: &[&str]) -> Result<LocalOptions> {
    let mut base = None;
    let mut iter = args.iter().copied();
    while let Some(flag) = iter.next() {
        if flag != "--base" {
            bail!("ci local 未知参数: {flag}");
        }
        let value = iter.next().context("ci local 参数 --base 缺少值")?;
        if value.is_empty() || value.starts_with("--") {
            bail!("ci local 参数 --base 必须是非空 git ref，不能是 flag");
        }
        if base.replace(value.to_owned()).is_some() {
            bail!("ci local 重复参数: --base");
        }
    }
    Ok(LocalOptions {
        base: base.context("ci local 缺少 --base")?,
    })
}

pub(crate) fn parse_options(args: &[&str]) -> Result<Options> {
    let mut event_path = None;
    let mut policy_path = None;
    let mut output_path = None;
    let mut github_output = None;
    let mut iter = args.iter().copied();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| anyhow::anyhow!("ci plan 参数 {flag} 缺少值"))?;
        let slot = match flag {
            "--event-path" => &mut event_path,
            "--policy" => &mut policy_path,
            "--output" => &mut output_path,
            "--github-output" => &mut github_output,
            _ => bail!("ci plan 未知参数: {flag}"),
        };
        if slot.replace(PathBuf::from(value)).is_some() {
            bail!("ci plan 重复参数: {flag}");
        }
    }
    Ok(Options {
        event_path: event_path.context("ci plan 缺少 --event-path")?,
        policy_path: policy_path.context("ci plan 缺少 --policy")?,
        output_path: output_path.context("ci plan 缺少 --output")?,
        github_output: github_output.context("ci plan 缺少 --github-output")?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PolicyMode {
    Shadow,
    Adaptive,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyWire {
    schema_version: u8,
    mode: PolicyMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DecisionKind {
    Adaptive,
    MandatoryFull,
    FallbackFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DecisionReason {
    PullRequestImpact,
    Shadow,
    DevelopPush,
    Schedule,
    WorkflowDispatch,
    FullOverride,
    GlobalImpact,
    PolicyInvalid,
    EventInvalid,
    DiffUnavailable,
    MetadataUnavailable,
    ContractUnavailable,
    RenameOrCopy,
    UnknownPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FallbackStage {
    Policy,
    Event,
    Diff,
    Metadata,
    Contract,
}

impl FallbackStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Event => "event",
            Self::Diff => "diff",
            Self::Metadata => "metadata",
            Self::Contract => "contract",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FallbackCode {
    #[serde(rename = "CI-PLAN-POLICY-INVALID")]
    PolicyInvalid,
    #[serde(rename = "CI-PLAN-FORCE-FULL-INVALID")]
    ForceFullInvalid,
    #[serde(rename = "CI-PLAN-EVENT-INVALID")]
    EventInvalid,
    #[serde(rename = "CI-PLAN-MERGE-BASE-UNAVAILABLE")]
    MergeBaseUnavailable,
    #[serde(rename = "CI-PLAN-SHALLOW-REPOSITORY")]
    ShallowRepository,
    #[serde(rename = "CI-PLAN-DIFF-UNAVAILABLE")]
    DiffUnavailable,
    #[serde(rename = "CI-PLAN-GIT-DIFF-UNAVAILABLE")]
    GitDiffUnavailable,
    #[serde(rename = "CI-PLAN-METADATA-UNAVAILABLE")]
    MetadataUnavailable,
    #[serde(rename = "CI-PLAN-CONTRACT-UNAVAILABLE")]
    ContractUnavailable,
    #[serde(rename = "CI-PLAN-RENAME-OR-COPY")]
    RenameOrCopy,
    #[serde(rename = "CI-PLAN-UNKNOWN-PATH")]
    UnknownPath,
}

impl FallbackCode {
    const fn stage(self) -> FallbackStage {
        match self {
            Self::PolicyInvalid | Self::ForceFullInvalid => FallbackStage::Policy,
            Self::EventInvalid => FallbackStage::Event,
            Self::MergeBaseUnavailable
            | Self::ShallowRepository
            | Self::DiffUnavailable
            | Self::GitDiffUnavailable
            | Self::RenameOrCopy
            | Self::UnknownPath => FallbackStage::Diff,
            Self::MetadataUnavailable => FallbackStage::Metadata,
            Self::ContractUnavailable => FallbackStage::Contract,
        }
    }

    const fn reason(self) -> DecisionReason {
        match self {
            Self::PolicyInvalid | Self::ForceFullInvalid => DecisionReason::PolicyInvalid,
            Self::EventInvalid => DecisionReason::EventInvalid,
            Self::MergeBaseUnavailable
            | Self::ShallowRepository
            | Self::DiffUnavailable
            | Self::GitDiffUnavailable => DecisionReason::DiffUnavailable,
            Self::MetadataUnavailable => DecisionReason::MetadataUnavailable,
            Self::ContractUnavailable => DecisionReason::ContractUnavailable,
            Self::RenameOrCopy => DecisionReason::RenameOrCopy,
            Self::UnknownPath => DecisionReason::UnknownPath,
        }
    }

    const fn action(self) -> &'static str {
        match self {
            Self::PolicyInvalid => "Fix .config/ci-impact.toml and rerun the planner.",
            Self::ForceFullInvalid => "Set RSS_CI_FORCE_FULL to true or false and rerun.",
            Self::EventInvalid => "Inspect the GitHub event payload and rerun the workflow.",
            Self::MergeBaseUnavailable
            | Self::ShallowRepository
            | Self::DiffUnavailable
            | Self::GitDiffUnavailable => {
                "Fetch complete base and head history, then rerun the planner."
            }
            Self::MetadataUnavailable => {
                "Run cargo metadata --locked --all-features and fix the workspace graph."
            }
            Self::ContractUnavailable => {
                "Validate the affected contract manifest and its workspace owners."
            }
            Self::RenameOrCopy => "Review the rename or copy and keep the conservative full run.",
            Self::UnknownPath => "Add the repository-relative path to the typed impact policy.",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyInvalid => "CI-PLAN-POLICY-INVALID",
            Self::ForceFullInvalid => "CI-PLAN-FORCE-FULL-INVALID",
            Self::EventInvalid => "CI-PLAN-EVENT-INVALID",
            Self::MergeBaseUnavailable => "CI-PLAN-MERGE-BASE-UNAVAILABLE",
            Self::ShallowRepository => "CI-PLAN-SHALLOW-REPOSITORY",
            Self::DiffUnavailable => "CI-PLAN-DIFF-UNAVAILABLE",
            Self::GitDiffUnavailable => "CI-PLAN-GIT-DIFF-UNAVAILABLE",
            Self::MetadataUnavailable => "CI-PLAN-METADATA-UNAVAILABLE",
            Self::ContractUnavailable => "CI-PLAN-CONTRACT-UNAVAILABLE",
            Self::RenameOrCopy => "CI-PLAN-RENAME-OR-COPY",
            Self::UnknownPath => "CI-PLAN-UNKNOWN-PATH",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct FallbackContext {
    stage: FallbackStage,
    code: FallbackCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    action: String,
}

impl FallbackContext {
    fn new(code: FallbackCode, subject: Option<String>) -> Self {
        Self {
            stage: code.stage(),
            code,
            subject,
            action: code.action().to_owned(),
        }
    }

    fn validate(&self, reason: DecisionReason) -> Result<()> {
        if self.stage != self.code.stage()
            || self.action != self.code.action()
            || reason != self.code.reason()
        {
            bail!("CI fallback context stage, code, action, and decision reason disagree");
        }
        if let Some(subject) = &self.subject
            && (subject.is_empty()
                || subject.len() > 512
                || Path::new(subject).is_absolute()
                || subject.split('/').any(|component| component == "..")
                || subject.chars().any(char::is_control))
        {
            bail!("CI fallback context subject must be a safe repository-relative path");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobReason {
    MetaAlways,
    Documentation,
    CoreSource,
    CoreTest,
    CoverageSource,
    DependencyManifest,
    ContractOwner,
    ContractSubscriber,
    GeneratedSource,
    IntegrationClosure,
    NotImpacted,
    FullCatalog,
    GlobalImpact,
    UnknownPath,
    RenameOrCopy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RevisionIdentity {
    base_revision: String,
    head_revision: String,
    merge_base_revision: String,
    execution_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct JobDecision {
    key: CiJobKey,
    recommended: bool,
    execute: bool,
    reasons: Vec<JobReason>,
    expected_artifact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CiImpactPlan {
    schema_version: u8,
    policy_version: String,
    plan_digest: String,
    policy_mode: PolicyMode,
    decision_kind: DecisionKind,
    decision_reason: DecisionReason,
    full_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_context: Option<FallbackContext>,
    revisions: RevisionIdentity,
    jobs: Vec<JobDecision>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanWire {
    schema_version: u8,
    policy_version: String,
    plan_digest: String,
    policy_mode: PolicyMode,
    decision_kind: DecisionKind,
    decision_reason: DecisionReason,
    full_fallback: bool,
    fallback_context: Option<FallbackContext>,
    revisions: RevisionIdentity,
    jobs: Vec<JobDecision>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Matrix {
    include: Vec<MatrixRow>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MatrixRow {
    job_key: CiJobKey,
    display_name: String,
    lane: CiLane,
    #[serde(skip_serializing_if = "Option::is_none")]
    shard: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    partition: Option<&'static str>,
    partition_label: &'static str,
    plan_digest: String,
    source_revision: String,
}

impl CiImpactPlan {
    fn new(input: PlanInput) -> Result<Self> {
        let full_execution = input.policy_mode == PolicyMode::Shadow
            || input.decision_kind != DecisionKind::Adaptive;
        let jobs = CiJobKey::ALL
            .into_iter()
            .map(|key| {
                let recommended = input.recommendation.contains(key);
                let reasons = input.recommendation.reasons(key);
                JobDecision {
                    key,
                    recommended,
                    execute: full_execution || recommended,
                    reasons,
                    expected_artifact: key.expected_artifact(&input.run_id, &input.run_attempt),
                }
            })
            .collect();
        let mut plan = Self {
            schema_version: PLAN_SCHEMA_VERSION,
            policy_version: input.policy_version,
            plan_digest: String::new(),
            policy_mode: input.policy_mode,
            decision_kind: input.decision_kind,
            decision_reason: input.decision_reason,
            full_fallback: input.decision_kind == DecisionKind::FallbackFull,
            fallback_context: input.fallback_context,
            revisions: input.revisions,
            jobs,
        };
        plan.validate()?;
        plan.plan_digest = plan.compute_digest()?;
        Ok(plan)
    }

    pub(crate) fn from_json(source: &str) -> Result<Self> {
        let wire: PlanWire = serde_json::from_str(source).context("invalid CI impact plan")?;
        let plan = Self {
            schema_version: wire.schema_version,
            policy_version: wire.policy_version,
            plan_digest: wire.plan_digest,
            policy_mode: wire.policy_mode,
            decision_kind: wire.decision_kind,
            decision_reason: wire.decision_reason,
            full_fallback: wire.full_fallback,
            fallback_context: wire.fallback_context,
            revisions: wire.revisions,
            jobs: wire.jobs,
        };
        plan.validate()?;
        if plan.compute_digest()? != plan.plan_digest {
            bail!("CI impact plan digest mismatch");
        }
        Ok(plan)
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize CI impact plan")
    }

    fn compute_digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.plan_digest.clear();
        let canonical = serde_json::to_vec(&unsigned).context("canonicalize CI impact plan")?;
        Ok(sha256(&canonical))
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != PLAN_SCHEMA_VERSION {
            bail!("unsupported CI impact plan schema");
        }
        validate_hex_digest(&self.policy_version, "policy version")?;
        if !self.plan_digest.is_empty() {
            validate_hex_digest(&self.plan_digest, "plan digest")?;
        }
        validate_revision(&self.revisions.execution_revision, "execution revision")?;
        for (value, label) in [
            (&self.revisions.base_revision, "base revision"),
            (&self.revisions.head_revision, "head revision"),
            (&self.revisions.merge_base_revision, "merge-base revision"),
        ] {
            if value != UNKNOWN_REVISION {
                validate_revision(value, label)?;
            }
        }
        if self.jobs.len() != CiJobKey::COUNT {
            bail!(
                "CI impact plan must contain exactly {} jobs",
                CiJobKey::COUNT
            );
        }
        if !legal_decision(self.policy_mode, self.decision_kind, self.decision_reason) {
            bail!("CI impact plan policy mode, decision kind, and reason are inconsistent");
        }
        for (decision, expected) in self.jobs.iter().zip(CiJobKey::ALL) {
            if decision.key != expected {
                bail!("CI impact plan job catalog is missing, duplicate, or out of order");
            }
            if decision.reasons.is_empty() {
                bail!("CI impact plan job reason is empty");
            }
            let artifact_suffix = decision
                .expected_artifact
                .strip_prefix(&decision.key.artifact_prefix())
                .and_then(|suffix| suffix.rsplit_once('-'));
            if !artifact_suffix.is_some_and(|(run_id, run_attempt)| {
                !run_id.is_empty()
                    && run_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    && !run_attempt.is_empty()
                    && run_attempt.bytes().all(|byte| byte.is_ascii_digit())
            }) {
                bail!("CI impact plan expected artifact identity is not canonical");
            }
            if decision.reasons.windows(2).any(|pair| pair[0] >= pair[1]) {
                bail!("CI impact plan job reasons must be unique and canonically ordered");
            }
            if decision.recommended {
                if decision.reasons.contains(&JobReason::NotImpacted) || !decision.execute {
                    bail!("recommended CI job has an illegal decision state");
                }
            } else if decision.reasons != [JobReason::NotImpacted] {
                bail!("non-recommended CI job must have the not-impacted reason");
            }
        }
        if !self
            .jobs
            .iter()
            .any(|job| job.key == CiJobKey::CiMeta && job.recommended)
        {
            bail!("CI impact plan must always recommend ci-meta");
        }
        if !self
            .jobs
            .iter()
            .any(|job| job.key == CiJobKey::CiMeta && job.execute)
        {
            bail!("CI impact plan matrix must always include ci-meta");
        }
        let must_be_full =
            self.policy_mode == PolicyMode::Shadow || self.decision_kind != DecisionKind::Adaptive;
        if must_be_full && self.jobs.iter().any(|job| !job.execute) {
            bail!("full CI impact plan omitted a closed job");
        }
        if !must_be_full && self.jobs.iter().any(|job| job.execute != job.recommended) {
            bail!("adaptive CI execution must equal the recommended closed set");
        }
        if self.full_fallback != (self.decision_kind == DecisionKind::FallbackFull) {
            bail!("CI impact plan fullFallback disagrees with decisionKind");
        }
        match (&self.fallback_context, self.decision_kind) {
            (Some(context), DecisionKind::FallbackFull) => {
                context.validate(self.decision_reason)?;
            }
            (None, DecisionKind::FallbackFull) => {
                bail!("fallback CI impact plan must contain typed fallback context");
            }
            (None, _) => {}
            (Some(_), _) => bail!("non-fallback CI impact plan cannot contain fallback context"),
        }
        let recommends_full_catalog = self.jobs.iter().all(|job| job.recommended);
        if (matches!(self.decision_kind, DecisionKind::Adaptive)
            || self.decision_reason == DecisionReason::Shadow)
            && recommends_full_catalog
        {
            bail!("selective CI impact state cannot recommend the full catalog");
        }
        if self.decision_kind == DecisionKind::FallbackFull && !recommends_full_catalog {
            bail!("fallback CI impact plan must recommend the closed catalog");
        }
        if self.decision_kind == DecisionKind::MandatoryFull
            && self.decision_reason != DecisionReason::Shadow
            && !recommends_full_catalog
        {
            bail!("non-Shadow mandatory CI impact plan must recommend the closed catalog");
        }
        if recommends_full_catalog {
            let expected_reasons = match self.decision_reason {
                DecisionReason::GlobalImpact => {
                    vec![JobReason::FullCatalog, JobReason::GlobalImpact]
                }
                DecisionReason::RenameOrCopy => {
                    vec![JobReason::FullCatalog, JobReason::RenameOrCopy]
                }
                DecisionReason::UnknownPath => {
                    vec![JobReason::FullCatalog, JobReason::UnknownPath]
                }
                _ => vec![JobReason::FullCatalog],
            };
            if self.jobs.iter().any(|job| job.reasons != expected_reasons) {
                bail!("full CI impact plan reasons disagree with its decision reason");
            }
        }
        Ok(())
    }

    fn matrix(&self) -> Matrix {
        Matrix {
            include: self
                .jobs
                .iter()
                .filter(|job| job.execute)
                .map(|job| MatrixRow {
                    job_key: job.key,
                    display_name: job.key.as_str().to_owned(),
                    lane: job.key.lane_kind(),
                    shard: job.key.shard(),
                    partition: job.key.partition(),
                    partition_label: job.key.partition_label(),
                    plan_digest: self.plan_digest.clone(),
                    source_revision: self.revisions.execution_revision.clone(),
                })
                .collect(),
        }
    }

    pub(crate) fn jobs(&self) -> &[JobDecision] {
        &self.jobs
    }

    pub(crate) fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    pub(crate) fn execution_revision(&self) -> &str {
        &self.revisions.execution_revision
    }

    pub(crate) fn full_execution_required(&self) -> bool {
        self.policy_mode == PolicyMode::Shadow || self.decision_kind != DecisionKind::Adaptive
    }

    pub(crate) const fn policy_mode(&self) -> PolicyMode {
        self.policy_mode
    }

    pub(crate) const fn decision_kind(&self) -> DecisionKind {
        self.decision_kind
    }

    pub(crate) const fn decision_reason(&self) -> DecisionReason {
        self.decision_reason
    }

    pub(crate) const fn full_fallback(&self) -> bool {
        self.full_fallback
    }
}

fn legal_decision(mode: PolicyMode, kind: DecisionKind, reason: DecisionReason) -> bool {
    match reason {
        DecisionReason::PullRequestImpact => {
            mode == PolicyMode::Adaptive && kind == DecisionKind::Adaptive
        }
        DecisionReason::Shadow => mode == PolicyMode::Shadow && kind == DecisionKind::MandatoryFull,
        DecisionReason::DevelopPush
        | DecisionReason::Schedule
        | DecisionReason::WorkflowDispatch
        | DecisionReason::FullOverride
        | DecisionReason::GlobalImpact => kind == DecisionKind::MandatoryFull,
        DecisionReason::PolicyInvalid
        | DecisionReason::EventInvalid
        | DecisionReason::DiffUnavailable
        | DecisionReason::MetadataUnavailable
        | DecisionReason::ContractUnavailable
        | DecisionReason::RenameOrCopy
        | DecisionReason::UnknownPath => kind == DecisionKind::FallbackFull,
    }
}

impl JobDecision {
    pub(crate) const fn key(&self) -> CiJobKey {
        self.key
    }

    pub(crate) const fn execute(&self) -> bool {
        self.execute
    }

    pub(crate) const fn recommended(&self) -> bool {
        self.recommended
    }

    pub(crate) fn expected_artifact(&self) -> &str {
        &self.expected_artifact
    }
}

struct PlanInput {
    policy_version: String,
    policy_mode: PolicyMode,
    decision_kind: DecisionKind,
    decision_reason: DecisionReason,
    fallback_context: Option<FallbackContext>,
    revisions: RevisionIdentity,
    recommendation: Recommendation,
    run_id: String,
    run_attempt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Recommendation {
    Selective(BTreeMap<CiJobKey, BTreeSet<JobReason>>),
    Full(FullCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullCause {
    MandatoryCatalog,
    GlobalImpact,
    RenameOrCopy,
    UnknownPath,
    FallbackUncertainty,
}

/// The only path-to-impact model. Its constructors stay private so callers can only consume a
/// projection produced by this module's closed classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImpactSet {
    Empty,
    Selective(SelectiveImpact),
    Full(FullCause),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectiveImpact {
    documentation: bool,
    packages: BTreeMap<String, BTreeSet<PackageImpact>>,
    reverse_closure: BTreeSet<String>,
    integration_shards: BTreeSet<IntegrationShard>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PackageImpact {
    Source,
    Test,
    Manifest,
    ContractOwner,
    ContractSubscriber,
    Generated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalPackageProjection {
    DirectTestClippy,
}

impl PackageImpact {
    /// Every impact category must make an explicit local-execution decision. A new category that
    /// is only wired into the remote projection cannot compile until this match is extended.
    const fn local_projection(self) -> LocalPackageProjection {
        match self {
            Self::Source
            | Self::Test
            | Self::Manifest
            | Self::ContractOwner
            | Self::ContractSubscriber
            | Self::Generated => LocalPackageProjection::DirectTestClippy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteProjection(Recommendation);

impl From<&ImpactSet> for RemoteProjection {
    fn from(impact: &ImpactSet) -> Self {
        let mut recommendation = Recommendation::empty();
        match impact {
            ImpactSet::Empty => {}
            ImpactSet::Full(cause) => recommendation = Recommendation::Full(*cause),
            ImpactSet::Selective(selective) => {
                if selective.documentation {
                    recommendation.add(CiJobKey::CiMeta, JobReason::Documentation);
                }
                for reasons in selective.packages.values() {
                    for reason in reasons {
                        match reason {
                            PackageImpact::Source => {
                                recommendation.add_core(true, JobReason::CoreSource);
                            }
                            PackageImpact::Test => {
                                recommendation.add_core(false, JobReason::CoreTest);
                            }
                            PackageImpact::Manifest => {
                                recommendation
                                    .add(CiJobKey::CiSecurity, JobReason::DependencyManifest);
                            }
                            PackageImpact::ContractOwner => {
                                recommendation.add_core(true, JobReason::ContractOwner);
                            }
                            PackageImpact::ContractSubscriber => {
                                recommendation.add_core(true, JobReason::ContractSubscriber);
                            }
                            PackageImpact::Generated => {
                                recommendation.add_core(true, JobReason::GeneratedSource);
                            }
                        }
                    }
                }
                for shard in &selective.integration_shards {
                    recommendation.add_shard(*shard);
                }
            }
        }
        Self(recommendation)
    }
}

impl RemoteProjection {
    fn into_recommendation(self) -> Recommendation {
        self.0
    }

    #[cfg(test)]
    fn selected_names(&self) -> Vec<&'static str> {
        self.0.selected_names()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalProjection {
    Empty,
    FastMeta,
    Selective {
        check_packages: Vec<String>,
        test_clippy_packages: Vec<String>,
        feature_gates: Vec<crate::nextest::CoreTestScope>,
        feature_compile_scopes: Vec<LocalFeatureScope>,
    },
    Full,
}

impl From<&ImpactSet> for LocalProjection {
    fn from(impact: &ImpactSet) -> Self {
        match impact {
            ImpactSet::Empty => Self::Empty,
            ImpactSet::Full(_) => Self::Full,
            ImpactSet::Selective(selective) if selective.packages.is_empty() => Self::FastMeta,
            ImpactSet::Selective(selective) => {
                let test_clippy_packages = selective
                    .packages
                    .iter()
                    .filter(|(_, impacts)| {
                        impacts.iter().any(|impact| {
                            matches!(
                                impact.local_projection(),
                                LocalPackageProjection::DirectTestClippy
                            )
                        })
                    })
                    .map(|(package, _)| package.clone())
                    .collect::<Vec<_>>();
                let feature_gates = crate::nextest::CoreTestScope::ALL
                    .into_iter()
                    .filter(|scope| {
                        scope
                            .package()
                            .is_some_and(|package| selective.packages.contains_key(package))
                    })
                    .collect();
                let impacted_packages = selective
                    .packages
                    .keys()
                    .chain(selective.reverse_closure.iter())
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let mut feature_compile_scopes = LocalFeatureScope::ALL
                    .into_iter()
                    .filter(|scope| impacted_packages.contains(scope.package()))
                    .collect::<BTreeSet<_>>();
                feature_compile_scopes.extend(
                    selective
                        .integration_shards
                        .iter()
                        .flat_map(|shard| shard.spec().local_feature_scopes.iter().copied()),
                );
                Self::Selective {
                    check_packages: selective.reverse_closure.iter().cloned().collect(),
                    test_clippy_packages,
                    feature_gates,
                    feature_compile_scopes: feature_compile_scopes.into_iter().collect(),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalCargoOperation {
    Check,
    Test,
    Clippy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalStep {
    FastMeta,
    Packages {
        operation: LocalCargoOperation,
        packages: Vec<String>,
    },
    Feature(crate::nextest::CoreTestScope),
    FeatureCompile(LocalFeatureScope),
    FullVerify,
}

impl LocalProjection {
    fn steps(&self) -> Vec<LocalStep> {
        match self {
            Self::Empty => Vec::new(),
            Self::FastMeta => vec![LocalStep::FastMeta],
            Self::Full => vec![LocalStep::FullVerify],
            Self::Selective {
                check_packages,
                test_clippy_packages,
                feature_gates,
                feature_compile_scopes,
            } => {
                let mut steps = vec![
                    LocalStep::FastMeta,
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Check,
                        packages: check_packages.clone(),
                    },
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Test,
                        packages: test_clippy_packages.clone(),
                    },
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Clippy,
                        packages: test_clippy_packages.clone(),
                    },
                ];
                steps.extend(feature_gates.iter().copied().map(LocalStep::Feature));
                steps.extend(
                    feature_compile_scopes
                        .iter()
                        .copied()
                        .map(LocalStep::FeatureCompile),
                );
                steps
            }
        }
    }
}

impl FullCause {
    const fn job_reason(self) -> JobReason {
        match self {
            Self::MandatoryCatalog | Self::FallbackUncertainty => JobReason::FullCatalog,
            Self::GlobalImpact => JobReason::GlobalImpact,
            Self::RenameOrCopy => JobReason::RenameOrCopy,
            Self::UnknownPath => JobReason::UnknownPath,
        }
    }

    const fn decision(self) -> (DecisionKind, DecisionReason) {
        match self {
            Self::MandatoryCatalog => (DecisionKind::MandatoryFull, DecisionReason::DevelopPush),
            Self::GlobalImpact => (DecisionKind::MandatoryFull, DecisionReason::GlobalImpact),
            Self::RenameOrCopy => (DecisionKind::FallbackFull, DecisionReason::RenameOrCopy),
            Self::UnknownPath => (DecisionKind::FallbackFull, DecisionReason::UnknownPath),
            Self::FallbackUncertainty => {
                (DecisionKind::FallbackFull, DecisionReason::DiffUnavailable)
            }
        }
    }

    fn fallback_context(self) -> Option<FallbackContext> {
        match self {
            Self::RenameOrCopy => Some(FallbackContext::new(FallbackCode::RenameOrCopy, None)),
            Self::UnknownPath => Some(FallbackContext::new(FallbackCode::UnknownPath, None)),
            Self::MandatoryCatalog | Self::GlobalImpact | Self::FallbackUncertainty => None,
        }
    }
}

impl Recommendation {
    fn empty() -> Self {
        let mut selected = BTreeMap::new();
        selected.insert(CiJobKey::CiMeta, BTreeSet::from([JobReason::MetaAlways]));
        Self::Selective(selected)
    }

    fn contains(&self, key: CiJobKey) -> bool {
        match self {
            Self::Selective(selected) => selected.contains_key(&key),
            Self::Full(_) => true,
        }
    }

    fn reasons(&self, key: CiJobKey) -> Vec<JobReason> {
        match self {
            Self::Selective(selected) => selected
                .get(&key)
                .cloned()
                .unwrap_or_else(|| BTreeSet::from([JobReason::NotImpacted]))
                .into_iter()
                .collect(),
            Self::Full(cause) => BTreeSet::from([cause.job_reason(), JobReason::FullCatalog])
                .into_iter()
                .collect(),
        }
    }

    fn add(&mut self, key: CiJobKey, reason: JobReason) {
        if let Self::Selective(selected) = self {
            selected.entry(key).or_default().insert(reason);
        }
    }

    fn add_core(&mut self, coverage: bool, reason: JobReason) {
        self.add(CiJobKey::CiCorePrerequisites, reason);
        self.add(CiJobKey::CiCoreTests1Of2, reason);
        self.add(CiJobKey::CiCoreTests2Of2, reason);
        if coverage {
            self.add(CiJobKey::CiCoverage, JobReason::CoverageSource);
        }
    }

    fn add_shard(&mut self, shard: IntegrationShard) {
        for key in CiJobKey::for_shard(shard) {
            self.add(*key, JobReason::IntegrationClosure);
        }
    }

    #[cfg(test)]
    fn selected_names(&self) -> Vec<&'static str> {
        CiJobKey::ALL
            .into_iter()
            .filter(|key| self.contains(*key))
            .map(CiJobKey::as_str)
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffStatus {
    Added,
    Modified,
    Deleted,
    Renamed,
    Copied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiffEntry {
    status: DiffStatus,
    path: String,
}

impl DiffEntry {
    #[cfg(test)]
    fn modified(path: &str) -> Self {
        Self {
            status: DiffStatus::Modified,
            path: path.to_owned(),
        }
    }

    #[cfg(test)]
    fn rename(path: &str) -> Self {
        Self {
            status: DiffStatus::Renamed,
            path: path.to_owned(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubEvent {
    #[serde(default)]
    pull_request: Option<PullRequest>,
}

#[derive(Debug, Deserialize)]
struct PullRequest {
    base: Revision,
    head: Revision,
}

#[derive(Debug, Deserialize)]
struct Revision {
    sha: String,
}

pub(crate) fn run(root: &Path, options: &Options) -> Result<()> {
    let policy_source = fs::read(&options.policy_path).unwrap_or_default();
    let policy_version = policy_version(&policy_source);
    let policy = std::str::from_utf8(&policy_source)
        .map_err(anyhow::Error::from)
        .and_then(|source| toml::from_str::<PolicyWire>(source).map_err(anyhow::Error::from));
    let event_name = std::env::var("GITHUB_EVENT_NAME").unwrap_or_default();
    let execution_revision =
        std::env::var("GITHUB_SHA").unwrap_or_else(|_| UNKNOWN_REVISION.to_owned());
    validate_revision(&execution_revision, "execution revision")?;
    let run_id = std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".to_owned());
    let run_attempt = std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".to_owned());
    let event_source = fs::read_to_string(&options.event_path)
        .with_context(|| format!("读取 {}", options.event_path.display()));

    let plan = match policy {
        Err(_) => fallback_plan(
            policy_version,
            PolicyMode::Shadow,
            DecisionReason::PolicyInvalid,
            execution_revision,
            run_id,
            run_attempt,
        )?,
        Ok(policy) if policy.schema_version != POLICY_SCHEMA_VERSION => fallback_plan(
            policy_version,
            policy.mode,
            DecisionReason::PolicyInvalid,
            execution_revision,
            run_id,
            run_attempt,
        )?,
        Ok(policy) => plan_event(
            root,
            &event_name,
            event_source.as_deref().unwrap_or("{}"),
            policy_version,
            policy.mode,
            execution_revision,
            run_id,
            run_attempt,
        )?,
    };

    if let Some(parent) = options.output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.output_path, plan.to_json()?)
        .with_context(|| format!("写 {}", options.output_path.display()))?;
    let matrix = serde_json::to_string(&plan.matrix()).context("serialize CI matrix")?;
    let recommended = plan.jobs.iter().filter(|job| job.recommended).count();
    let executed = plan.jobs.iter().filter(|job| job.execute).count();
    let outputs = format!(
        "matrix={matrix}\nplan-digest={}\npolicy-version={}\ndecision-kind={}\nfull-fallback={}\nrecommended-count={recommended}\nexecuted-count={executed}\n",
        plan.plan_digest,
        plan.policy_version,
        decision_kind_name(plan.decision_kind),
        plan.full_fallback,
    );
    fs::write(&options.github_output, outputs)
        .with_context(|| format!("写 {}", options.github_output.display()))?;
    if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
        let summary = render_plan_summary(&plan, recommended, executed);
        fs::write(summary_path, summary)?;
    }
    Ok(())
}

fn render_plan_summary(plan: &CiImpactPlan, recommended: usize, executed: usize) -> String {
    let mut summary = format!(
        "## Typed CI impact plan\n\n- Policy: `{}`\n- Decision: `{}` / `{:?}`\n- Recommended jobs: `{recommended}`\n- Executed jobs: `{executed}`\n- Full fallback: `{}`\n- Plan digest: `{}`\n",
        plan.policy_version,
        decision_kind_name(plan.decision_kind),
        plan.decision_reason,
        plan.full_fallback,
        plan.plan_digest,
    );
    if let Some(context) = &plan.fallback_context {
        summary.push_str(&format!(
            "- Fallback code/stage: `{}` / `{}`\n",
            context.code.as_str(),
            context.stage.as_str(),
        ));
        if let Some(subject) = &context.subject {
            summary.push_str(&format!(
                "- Fallback subject: `{}`\n",
                markdown_code(subject)
            ));
        }
        summary.push_str(&format!("- Action: `{}`\n", markdown_code(&context.action)));
    }
    summary
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

#[allow(clippy::too_many_arguments)]
fn plan_event(
    root: &Path,
    event_name: &str,
    event_source: &str,
    policy_version: String,
    policy_mode: PolicyMode,
    execution_revision: String,
    run_id: String,
    run_attempt: String,
) -> Result<CiImpactPlan> {
    let force_full = match full_override(std::env::var_os("RSS_CI_FORCE_FULL").as_deref()) {
        FullOverride::Disabled => false,
        FullOverride::Enabled => true,
        FullOverride::Invalid => {
            return fallback_plan_with_code(
                policy_version,
                policy_mode,
                FallbackCode::ForceFullInvalid,
                execution_revision,
                run_id,
                run_attempt,
            );
        }
    };
    if force_full {
        return mandatory_plan(
            policy_version,
            policy_mode,
            DecisionReason::FullOverride,
            execution_revision,
            run_id,
            run_attempt,
        );
    }
    match event_name {
        "push" => mandatory_plan(
            policy_version,
            policy_mode,
            DecisionReason::DevelopPush,
            execution_revision,
            run_id,
            run_attempt,
        ),
        "schedule" => mandatory_plan(
            policy_version,
            policy_mode,
            DecisionReason::Schedule,
            execution_revision,
            run_id,
            run_attempt,
        ),
        "workflow_dispatch" => mandatory_plan(
            policy_version,
            policy_mode,
            DecisionReason::WorkflowDispatch,
            execution_revision,
            run_id,
            run_attempt,
        ),
        "pull_request" => {
            let event = serde_json::from_str::<GithubEvent>(event_source);
            let Some(pull_request) = event.ok().and_then(|event| event.pull_request) else {
                return fallback_plan(
                    policy_version,
                    policy_mode,
                    DecisionReason::EventInvalid,
                    execution_revision,
                    run_id,
                    run_attempt,
                );
            };
            if validate_revision(&pull_request.base.sha, "base revision").is_err()
                || validate_revision(&pull_request.head.sha, "head revision").is_err()
            {
                return fallback_plan(
                    policy_version,
                    policy_mode,
                    DecisionReason::EventInvalid,
                    execution_revision,
                    run_id,
                    run_attempt,
                );
            }
            let merge_base = match git_stdout(
                root,
                [
                    "merge-base",
                    pull_request.base.sha.as_str(),
                    pull_request.head.sha.as_str(),
                ],
            ) {
                Ok(value)
                    if value.lines().count() == 1
                        && validate_revision(value.trim(), "merge-base revision").is_ok() =>
                {
                    value.trim().to_owned()
                }
                _ => {
                    return fallback_plan_with_code(
                        policy_version,
                        policy_mode,
                        FallbackCode::MergeBaseUnavailable,
                        execution_revision,
                        run_id,
                        run_attempt,
                    );
                }
            };
            let revisions = RevisionIdentity {
                base_revision: pull_request.base.sha.clone(),
                head_revision: pull_request.head.sha.clone(),
                merge_base_revision: merge_base.clone(),
                execution_revision,
            };
            let recommendation = match pull_request_recommendation(
                root,
                &pull_request.base.sha,
                &pull_request.head.sha,
                &merge_base,
            ) {
                Ok(value) => value,
                Err(failure) => {
                    return fallback_plan_with_revisions(
                        policy_version,
                        policy_mode,
                        failure.context,
                        revisions,
                        run_id,
                        run_attempt,
                    );
                }
            };
            let (decision_kind, decision_reason) = match &recommendation {
                Recommendation::Full(cause) => cause.decision(),
                Recommendation::Selective(_) if policy_mode == PolicyMode::Shadow => {
                    (DecisionKind::MandatoryFull, DecisionReason::Shadow)
                }
                Recommendation::Selective(_) => {
                    (DecisionKind::Adaptive, DecisionReason::PullRequestImpact)
                }
            };
            CiImpactPlan::new(PlanInput {
                policy_version,
                policy_mode,
                decision_kind,
                decision_reason,
                fallback_context: match &recommendation {
                    Recommendation::Full(cause) => cause.fallback_context(),
                    Recommendation::Selective(_) => None,
                },
                revisions,
                recommendation,
                run_id,
                run_attempt,
            })
        }
        _ => fallback_plan(
            policy_version,
            policy_mode,
            DecisionReason::EventInvalid,
            execution_revision,
            run_id,
            run_attempt,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullOverride {
    Disabled,
    Enabled,
    Invalid,
}

fn full_override(value: Option<&OsStr>) -> FullOverride {
    match value.and_then(OsStr::to_str) {
        None if value.is_some() => FullOverride::Invalid,
        None | Some("" | "false") => FullOverride::Disabled,
        Some("true") => FullOverride::Enabled,
        Some(_) => FullOverride::Invalid,
    }
}

fn mandatory_plan(
    policy_version: String,
    policy_mode: PolicyMode,
    reason: DecisionReason,
    execution_revision: String,
    run_id: String,
    run_attempt: String,
) -> Result<CiImpactPlan> {
    CiImpactPlan::new(PlanInput {
        policy_version,
        policy_mode,
        decision_kind: DecisionKind::MandatoryFull,
        decision_reason: reason,
        fallback_context: None,
        revisions: unknown_revisions(execution_revision),
        recommendation: Recommendation::Full(FullCause::MandatoryCatalog),
        run_id,
        run_attempt,
    })
}

fn fallback_plan(
    policy_version: String,
    policy_mode: PolicyMode,
    reason: DecisionReason,
    execution_revision: String,
    run_id: String,
    run_attempt: String,
) -> Result<CiImpactPlan> {
    fallback_plan_with_code(
        policy_version,
        policy_mode,
        fallback_code(reason)?,
        execution_revision,
        run_id,
        run_attempt,
    )
}

fn fallback_plan_with_code(
    policy_version: String,
    policy_mode: PolicyMode,
    code: FallbackCode,
    execution_revision: String,
    run_id: String,
    run_attempt: String,
) -> Result<CiImpactPlan> {
    fallback_plan_with_revisions(
        policy_version,
        policy_mode,
        FallbackContext::new(code, None),
        unknown_revisions(execution_revision),
        run_id,
        run_attempt,
    )
}

fn fallback_plan_with_revisions(
    policy_version: String,
    policy_mode: PolicyMode,
    fallback_context: FallbackContext,
    revisions: RevisionIdentity,
    run_id: String,
    run_attempt: String,
) -> Result<CiImpactPlan> {
    let reason = fallback_context.code.reason();
    CiImpactPlan::new(PlanInput {
        policy_version,
        policy_mode,
        decision_kind: DecisionKind::FallbackFull,
        decision_reason: reason,
        fallback_context: Some(fallback_context),
        revisions,
        recommendation: Recommendation::Full(match reason {
            DecisionReason::RenameOrCopy => FullCause::RenameOrCopy,
            DecisionReason::UnknownPath => FullCause::UnknownPath,
            _ => FullCause::FallbackUncertainty,
        }),
        run_id,
        run_attempt,
    })
}

fn fallback_code(reason: DecisionReason) -> Result<FallbackCode> {
    match reason {
        DecisionReason::PolicyInvalid => Ok(FallbackCode::PolicyInvalid),
        DecisionReason::EventInvalid => Ok(FallbackCode::EventInvalid),
        DecisionReason::DiffUnavailable => Ok(FallbackCode::DiffUnavailable),
        DecisionReason::MetadataUnavailable => Ok(FallbackCode::MetadataUnavailable),
        DecisionReason::ContractUnavailable => Ok(FallbackCode::ContractUnavailable),
        DecisionReason::RenameOrCopy => Ok(FallbackCode::RenameOrCopy),
        DecisionReason::UnknownPath => Ok(FallbackCode::UnknownPath),
        _ => bail!("decision reason is not a fallback state"),
    }
}

fn unknown_revisions(execution_revision: String) -> RevisionIdentity {
    RevisionIdentity {
        base_revision: UNKNOWN_REVISION.to_owned(),
        head_revision: UNKNOWN_REVISION.to_owned(),
        merge_base_revision: UNKNOWN_REVISION.to_owned(),
        execution_revision,
    }
}

#[derive(Debug)]
struct PlannerFailure {
    context: FallbackContext,
}

impl PlannerFailure {
    fn new(code: FallbackCode, subject: Option<String>) -> Self {
        Self {
            context: FallbackContext::new(code, subject),
        }
    }
}

fn pull_request_recommendation(
    root: &Path,
    base: &str,
    head: &str,
    merge_base: &str,
) -> std::result::Result<Recommendation, PlannerFailure> {
    let shallow = git_stdout(root, ["rev-parse", "--is-shallow-repository"])
        .map_err(|_| PlannerFailure::new(FallbackCode::DiffUnavailable, None))?;
    if shallow.trim() != "false" {
        return Err(PlannerFailure::new(FallbackCode::ShallowRepository, None));
    }
    let entries = read_diff(root, base, head)
        .map_err(|_| PlannerFailure::new(FallbackCode::GitDiffUnavailable, None))?;
    if let Some(cause) = immediate_full_cause(&entries, None) {
        return Ok(RemoteProjection::from(&ImpactSet::Full(cause)).into_recommendation());
    }
    let graph = WorkspaceGraph::load(root).map_err(|_| {
        PlannerFailure::new(
            FallbackCode::MetadataUnavailable,
            Some("Cargo.toml".to_owned()),
        )
    })?;
    impact_with_graph(root, &entries, &graph, merge_base)
        .map(|impact| RemoteProjection::from(&impact).into_recommendation())
        .map_err(|_| {
            let subject = entries
                .iter()
                .find(|entry| {
                    entry.path.starts_with("contracts/") || entry.path.starts_with("generated/")
                })
                .map(|entry| entry.path.clone());
            PlannerFailure::new(FallbackCode::ContractUnavailable, subject)
        })
}

pub(crate) fn run_local(root: &Path, options: &LocalOptions) -> Result<()> {
    let context = LocalExecutionContext::new(root, &options.base)?;
    let impact = context.impact_or_full();
    let projection = LocalProjection::from(&impact);
    let steps = projection.steps();
    if steps.is_empty() {
        eprintln!("ci local：<base>...HEAD 无已提交项目差异");
        return Ok(());
    }
    eprintln!("ci local：{} 步", steps.len());
    let mut index = 0;
    execute_local_steps(&steps, |step| {
        index += 1;
        eprintln!("ci local：[{}/{}] {}", index, steps.len(), step.label());
        run_local_step(&context, step)
    })?;
    eprintln!("ci local：全部通过");
    Ok(())
}

fn execute_local_steps(
    steps: &[LocalStep],
    mut execute: impl FnMut(&LocalStep) -> Result<()>,
) -> Result<()> {
    for step in steps {
        execute(step)?;
    }
    Ok(())
}

#[cfg(test)]
fn local_impact(root: &Path, base: &str) -> ImpactSet {
    LocalExecutionContext::new(root, base).map_or_else(
        |error| {
            eprintln!("ci local：影响分析失败，fail-safe 到完整 verify：{error:#}");
            ImpactSet::Full(FullCause::FallbackUncertainty)
        },
        |context| context.impact_or_full(),
    )
}

/// Immutable source identity shared by local impact analysis and every selected gate. The
/// private constructor resolves all revisions before creating a detached committed checkout, so
/// no executor can observe the caller's index, untracked files, or dirty worktree.
struct LocalExecutionContext {
    base: String,
    head: String,
    merge_base: String,
    snapshot: CommittedSnapshot,
}

impl LocalExecutionContext {
    fn new(repository: &Path, base: &str) -> Result<Self> {
        let base = resolve_commit(repository, base)?;
        let head = resolve_commit(repository, "HEAD")?;
        let merge_base = git_stdout(repository, ["merge-base", base.as_str(), head.as_str()])?;
        let merge_base = merge_base.trim();
        validate_revision(merge_base, "local merge-base revision")?;
        let snapshot = CommittedSnapshot::checkout(repository, &head)?;
        Ok(Self {
            base,
            head,
            merge_base: merge_base.to_owned(),
            snapshot,
        })
    }

    fn root(&self) -> &Path {
        self.snapshot.root()
    }

    fn impact(&self) -> Result<ImpactSet> {
        let entries = read_diff(self.root(), &self.base, &self.head)?;
        if entries.is_empty() {
            return Ok(ImpactSet::Empty);
        }
        if let Some(cause) = immediate_full_cause(&entries, None) {
            return Ok(ImpactSet::Full(cause));
        }
        if entries.iter().all(|entry| documentation(&entry.path)) {
            return Ok(impact_entries(
                &entries,
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            ));
        }
        let graph = WorkspaceGraph::load(self.root())?;
        impact_with_graph(self.root(), &entries, &graph, &self.merge_base)
    }

    fn impact_or_full(&self) -> ImpactSet {
        self.impact().unwrap_or_else(|error| {
            eprintln!("ci local：影响分析失败，fail-safe 到完整 verify：{error:#}");
            ImpactSet::Full(FullCause::FallbackUncertainty)
        })
    }
}

static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// An isolated checkout of one committed revision. Local impact classification must not read
/// manifests, contract metadata, generated files, or package topology from the caller's dirty
/// working tree after the diff revisions have been resolved.
struct CommittedSnapshot {
    scratch: PathBuf,
    root: PathBuf,
}

impl CommittedSnapshot {
    fn checkout(repository: &Path, revision: &str) -> Result<Self> {
        let repository = repository
            .to_str()
            .context("workspace path is not valid UTF-8")?;
        let counter = SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let scratch = std::env::temp_dir().join(format!(
            "rss-ci-local-snapshot-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&scratch).context("create committed CI snapshot directory")?;
        let scratch = fs::canonicalize(scratch).context("canonicalize CI snapshot directory")?;
        let root = scratch.join("tree");
        let root_text = root
            .to_str()
            .context("snapshot path is not valid UTF-8")?
            .to_owned();
        let snapshot = Self { scratch, root };
        let clone = external_cmd(
            ExternalProgram::SystemGit,
            &[
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                "--",
                repository,
                &root_text,
            ],
            &[],
            None,
        )
        .status()
        .context("clone committed CI snapshot")?;
        if !clone.success() {
            bail!("clone committed CI snapshot failed");
        }
        let checkout = external_cmd(
            ExternalProgram::SystemGit,
            &["checkout", "--quiet", "--detach", revision, "--"],
            &[],
            Some(snapshot.root()),
        )
        .status()
        .context("checkout committed CI snapshot")?;
        if !checkout.success() {
            bail!("checkout committed CI snapshot failed");
        }
        Ok(snapshot)
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for CommittedSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.scratch);
    }
}

fn resolve_commit(root: &Path, revision: &str) -> Result<String> {
    let commit = format!("{revision}^{{commit}}");
    let output = git_stdout(
        root,
        ["rev-parse", "--verify", "--end-of-options", commit.as_str()],
    )?;
    let value = output.trim();
    if output.lines().count() != 1 {
        bail!("git revision does not resolve to exactly one commit");
    }
    validate_revision(value, "local base revision")?;
    Ok(value.to_owned())
}

impl LocalStep {
    fn label(&self) -> String {
        match self {
            Self::FastMeta => "fast/meta".to_owned(),
            Self::FullVerify => "full verify fallback".to_owned(),
            Self::Packages {
                operation,
                packages,
            } => format!("{} {}", operation.label(), packages.join(",")),
            Self::Feature(gate) => {
                format!(
                    "registered deterministic test scope {}",
                    gate.package().unwrap_or("workspace")
                )
            }
            Self::FeatureCompile(scope) => {
                format!("compile {}[{}] --no-run", scope.package(), scope.feature())
            }
        }
    }
}

impl LocalCargoOperation {
    const fn label(self) -> &'static str {
        match self {
            Self::Check => "check reverse closure",
            Self::Test => "test direct packages",
            Self::Clippy => "clippy direct packages",
        }
    }

    const fn subcommand(self) -> CargoSubcommand {
        match self {
            Self::Check => CargoSubcommand::Check,
            Self::Test => CargoSubcommand::Test,
            Self::Clippy => CargoSubcommand::Clippy,
        }
    }
}

fn run_local_step(context: &LocalExecutionContext, step: &LocalStep) -> Result<()> {
    match step {
        LocalStep::FastMeta => run_snapshot_verify(context, true),
        LocalStep::FullVerify => run_snapshot_verify(context, false),
        LocalStep::Packages {
            operation,
            packages,
        } => run_package_operation(context.root(), *operation, packages),
        LocalStep::Feature(scope) => crate::nextest::NextestInvocation::for_core(
            *scope,
            crate::nextest::NextestLane::Verify,
            None,
        )
        .run(context.root(), &[]),
        LocalStep::FeatureCompile(scope) => run_feature_compile(context.root(), *scope),
    }
}

fn run_snapshot_verify(context: &LocalExecutionContext, fast: bool) -> Result<()> {
    let mut args = vec!["verify"];
    if fast {
        args.push("--fast");
    }
    args.extend(["--against", context.base.as_str()]);
    let status = cargo_cmd(CargoSubcommand::Xtask, &args, &[], Some(context.root())).status()?;
    if !status.success() {
        bail!("ci local snapshot verify failed");
    }
    Ok(())
}

fn run_feature_compile(root: &Path, scope: LocalFeatureScope) -> Result<()> {
    let args = [
        "--locked",
        "-p",
        scope.package(),
        "--features",
        scope.feature(),
        "--no-run",
    ];
    let status = cargo_cmd(CargoSubcommand::Test, &args, &[], Some(root)).status()?;
    if !status.success() {
        bail!(
            "ci local feature compile failed for {}[{}]",
            scope.package(),
            scope.feature()
        );
    }
    Ok(())
}

fn run_package_operation(
    root: &Path,
    operation: LocalCargoOperation,
    packages: &[String],
) -> Result<()> {
    if packages.is_empty() {
        bail!("ci local selective operation has an empty package set");
    }
    let mut owned = vec!["--locked".to_owned()];
    if matches!(
        operation,
        LocalCargoOperation::Check | LocalCargoOperation::Clippy
    ) {
        owned.push("--all-targets".to_owned());
    }
    for package in packages {
        owned.push("-p".to_owned());
        owned.push(package.clone());
    }
    if operation == LocalCargoOperation::Clippy {
        owned.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
    }
    let args = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let status = cargo_cmd(operation.subcommand(), &args, &[], Some(root)).status()?;
    if !status.success() {
        bail!("ci local {} failed", operation.label());
    }
    Ok(())
}

fn read_diff(root: &Path, base: &str, head: &str) -> Result<Vec<DiffEntry>> {
    let range = format!("{base}...{head}");
    let output = external_cmd(
        ExternalProgram::SystemGit,
        &[
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            "--find-copies-harder",
            range.as_str(),
            "--",
        ],
        &[],
        Some(root),
    )
    .output()
    .context("execute git diff")?;
    if !output.status.success() {
        bail!("git diff failed");
    }
    parse_diff(&output.stdout)
}

fn parse_diff(source: &[u8]) -> Result<Vec<DiffEntry>> {
    let mut fields = source.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    if fields.iter().any(|field| field.is_empty()) {
        bail!("empty field in git diff record");
    }
    let mut entries = Vec::new();
    let mut index = 0;
    while index < fields.len() {
        let status = std::str::from_utf8(fields[index]).context("non-UTF-8 diff status")?;
        index += 1;
        let kind = match status {
            "A" => DiffStatus::Added,
            "M" => DiffStatus::Modified,
            "D" => DiffStatus::Deleted,
            value if valid_similarity_status(value, 'R') => DiffStatus::Renamed,
            value if valid_similarity_status(value, 'C') => DiffStatus::Copied,
            _ => bail!("unknown git diff status"),
        };
        let path_count = usize::from(matches!(kind, DiffStatus::Renamed | DiffStatus::Copied)) + 1;
        if index + path_count > fields.len() {
            bail!("truncated git diff record");
        }
        let path = std::str::from_utf8(fields[index + path_count - 1])
            .context("non-UTF-8 diff path")?
            .to_owned();
        index += path_count;
        entries.push(DiffEntry { status: kind, path });
    }
    Ok(entries)
}

fn valid_similarity_status(value: &str, prefix: char) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|score| !score.is_empty() && score.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
fn classify_diff(entries: &[DiffEntry]) -> Recommendation {
    RemoteProjection::from(&impact_entries(
        entries,
        None,
        &BTreeSet::new(),
        &BTreeMap::new(),
    ))
    .into_recommendation()
}

#[cfg(test)]
fn classify_with_graph(
    root: &Path,
    entries: &[DiffEntry],
    graph: &WorkspaceGraph,
    merge_base: &str,
) -> Result<Recommendation> {
    Ok(
        RemoteProjection::from(&impact_with_graph(root, entries, graph, merge_base)?)
            .into_recommendation(),
    )
}

fn impact_with_graph(
    root: &Path,
    entries: &[DiffEntry],
    graph: &WorkspaceGraph,
    merge_base: &str,
) -> Result<ImpactSet> {
    let mut direct = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    for entry in entries {
        if entry.path.starts_with("contracts/") {
            let packages = contract_package_impacts(root, &entry.path, entry.status, merge_base)?;
            if packages.is_empty() || packages.keys().any(|package| !graph.contains(package)) {
                bail!("contract owner or subscriber is outside the workspace catalog");
            }
            for (package, reasons) in packages {
                direct.entry(package).or_default().extend(reasons);
            }
        } else if entry.path.starts_with("generated/src/") && !generated_entrypoint(&entry.path) {
            let domain = generated_domain(&entry.path)
                .context("generated source path has no closed domain identity")?;
            if !graph.contains(&domain) {
                bail!("generated domain is outside the workspace catalog");
            }
            direct
                .entry(domain)
                .or_default()
                .insert(PackageImpact::Generated);
        }
    }
    let mut impacted = direct.keys().cloned().collect::<BTreeSet<_>>();
    impacted.extend(
        entries
            .iter()
            .filter_map(|entry| graph.package_for_path(&entry.path).map(str::to_owned)),
    );
    let closure = graph.reverse_closure(&impacted);
    Ok(impact_entries(entries, Some(graph), &closure, &direct))
}

fn impact_entries(
    entries: &[DiffEntry],
    graph: Option<&WorkspaceGraph>,
    closure: &BTreeSet<String>,
    seeded_packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
) -> ImpactSet {
    if let Some(cause) = immediate_full_cause(entries, graph) {
        return ImpactSet::Full(cause);
    }
    if entries.is_empty() {
        return ImpactSet::Empty;
    }
    let mut documentation_only = false;
    let mut packages = seeded_packages.clone();
    for entry in entries {
        let path = entry.path.as_str();
        if documentation(path) {
            documentation_only = true;
            continue;
        }
        if path.starts_with("contracts/") {
            if graph.is_none() {
                packages
                    .entry("contract-owner".to_owned())
                    .or_default()
                    .insert(PackageImpact::ContractOwner);
            }
            continue;
        }
        if path.starts_with("generated/src/") {
            if graph.is_none() {
                packages
                    .entry("generated-domain".to_owned())
                    .or_default()
                    .insert(PackageImpact::Generated);
            }
            continue;
        }
        let package = match graph {
            Some(graph) => graph.package_for_path(path).map(str::to_owned),
            None => path_package(path),
        };
        let Some(package) = package else {
            return ImpactSet::Full(FullCause::UnknownPath);
        };
        let is_test = path.contains("/tests/")
            || path.contains("/test/")
            || path.ends_with("_test.rs")
            || path.ends_with(".snap");
        let manifest = Path::new(path).file_name() == Some(OsStr::new("Cargo.toml"));
        let reasons = packages.entry(package).or_default();
        reasons.insert(if is_test {
            PackageImpact::Test
        } else {
            PackageImpact::Source
        });
        if manifest {
            reasons.insert(PackageImpact::Manifest);
        }
    }
    let mut selected_shards = BTreeSet::new();
    let mut integration_packages = closure.clone();
    integration_packages.extend(packages.keys().cloned());
    for shard in IntegrationShard::ALL {
        if integration_shards::batches(*shard)
            .iter()
            .any(|batch| integration_packages.contains(batch.package))
        {
            selected_shards.insert(*shard);
        }
    }
    ImpactSet::Selective(SelectiveImpact {
        documentation: documentation_only,
        packages,
        reverse_closure: closure.clone(),
        integration_shards: selected_shards,
    })
}

fn immediate_full_cause(
    entries: &[DiffEntry],
    graph: Option<&WorkspaceGraph>,
) -> Option<FullCause> {
    if entries
        .iter()
        .any(|entry| matches!(entry.status, DiffStatus::Renamed | DiffStatus::Copied))
    {
        return Some(FullCause::RenameOrCopy);
    }
    entries.iter().find_map(|entry| {
        let path = entry.path.as_str();
        if machine_input(path) || high_impact(path) || generated_entrypoint(path) {
            return Some(FullCause::GlobalImpact);
        }
        let package = graph
            .and_then(|graph| graph.package_for_path(path).map(str::to_owned))
            .or_else(|| path_package(path));
        package
            .as_deref()
            .is_some_and(|package| crate::layers::BASIS_CRATES.contains(&package))
            .then_some(FullCause::GlobalImpact)
    })
}

fn documentation(path: &str) -> bool {
    (DOCUMENTATION_PATHS.contains(&path)
        || DOCUMENTATION_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix)))
        && !DOCUMENTATION_GOVERNED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn machine_input(path: &str) -> bool {
    MACHINE_INPUT_PATHS.contains(&path)
}

fn high_impact(path: &str) -> bool {
    HIGH_IMPACT_PATHS.contains(&path)
        || HIGH_IMPACT_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn generated_entrypoint(path: &str) -> bool {
    path.starts_with("generated/")
        && matches!(
            Path::new(path).file_name().and_then(OsStr::to_str),
            Some("lib.rs" | "mod.rs")
        )
}

fn path_package(path: &str) -> Option<String> {
    let parts = path.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        [
            "crates" | "adapters" | "bins" | "assemblies" | "composition" | "examples",
            name,
            ..,
        ] => Some(if *name == "redis" && parts[0] == "adapters" {
            "redis-adapter".to_owned()
        } else {
            (*name).to_owned()
        }),
        ["journeys", ..] => Some("journeys".to_owned()),
        [name, ..] if name.starts_with("journeys-") => Some((*name).to_owned()),
        _ => None,
    }
}

fn generated_domain(path: &str) -> Option<String> {
    if !path.starts_with("generated/src/") || generated_entrypoint(path) {
        return None;
    }
    let stem = Path::new(path).file_stem()?.to_str()?;
    stem.split_once("_v").map(|(domain, _)| domain.to_owned())
}

#[cfg(test)]
fn contract_packages(
    root: &Path,
    changed_path: &str,
    status: DiffStatus,
    merge_base: &str,
) -> Result<BTreeSet<String>> {
    Ok(
        contract_package_impacts(root, changed_path, status, merge_base)?
            .into_keys()
            .collect(),
    )
}

fn contract_package_impacts(
    root: &Path,
    changed_path: &str,
    status: DiffStatus,
    merge_base: &str,
) -> Result<BTreeMap<String, BTreeSet<PackageImpact>>> {
    let manifest_path =
        contract_manifest_path(changed_path).context("contract path has no manifest")?;
    let absolute = root.join(&manifest_path);
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    let mut extend = |source: &str, origin: &str| -> Result<()> {
        for (package, reasons) in
            contract_manifest_impacts(source).with_context(|| origin.to_owned())?
        {
            packages.entry(package).or_default().extend(reasons);
        }
        Ok(())
    };
    let read_current = || {
        fs::read_to_string(&absolute)
            .with_context(|| format!("read current impacted contract {}", absolute.display()))
    };
    let read_base = || {
        git_stdout(root, ["show", &format!("{merge_base}:{manifest_path}")])
            .context("read merge-base impacted contract")
    };
    match status {
        DiffStatus::Added => extend(&read_current()?, "parse current impacted contract")?,
        DiffStatus::Modified => {
            extend(&read_base()?, "parse merge-base impacted contract")?;
            extend(&read_current()?, "parse current impacted contract")?;
        }
        DiffStatus::Deleted => {
            extend(&read_base()?, "parse merge-base impacted contract")?;
            if absolute.is_file() {
                extend(&read_current()?, "parse current impacted contract")?;
            }
        }
        DiffStatus::Renamed | DiffStatus::Copied => {
            bail!("rename/copy contract must be handled by full fallback")
        }
    }
    Ok(packages)
}

fn contract_manifest_impacts(source: &str) -> Result<BTreeMap<String, BTreeSet<PackageImpact>>> {
    let manifest = ContractManifest::from_toml_str(source).context("parse impacted contract")?;
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    match manifest.owner {
        ContractOwner::Domain(owner) => {
            packages
                .entry(owner)
                .or_default()
                .insert(PackageImpact::ContractOwner);
        }
        ContractOwner::Framework => bail!("framework-owned contract has no workspace owner"),
    }
    for subscription in manifest.subscriptions {
        packages
            .entry(subscription.consumer)
            .or_default()
            .insert(PackageImpact::ContractSubscriber);
    }
    Ok(packages)
}

fn contract_manifest_path(path: &str) -> Option<String> {
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.first().copied() != Some("contracts") || parts.len() < 5 {
        return None;
    }
    let depth = if parts.get(4).copied() == Some("contract.toml") || parts.len() == 5 {
        4
    } else {
        5
    };
    let mut manifest = parts[..depth].join("/");
    manifest.push_str("/contract.toml");
    Some(manifest)
}

#[derive(Debug, Deserialize)]
struct MetadataWire {
    packages: Vec<MetadataPackage>,
    resolve: Option<MetadataResolve>,
    workspace_members: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    id: String,
    manifest_path: String,
}

#[derive(Debug, Deserialize)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Deserialize)]
struct MetadataNode {
    id: String,
    deps: Vec<MetadataDependency>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    pkg: String,
}

struct WorkspaceGraph {
    package_paths: Vec<(String, String)>,
    id_to_name: BTreeMap<String, String>,
    reverse: BTreeMap<String, BTreeSet<String>>,
}

impl WorkspaceGraph {
    fn load(root: &Path) -> Result<Self> {
        let output = cargo_cmd(
            CargoSubcommand::Metadata,
            &["--locked", "--all-features", "--format-version", "1"],
            &[],
            Some(root),
        )
        .output()
        .context("execute cargo metadata")?;
        if !output.status.success() {
            bail!("cargo metadata failed");
        }
        let wire: MetadataWire =
            serde_json::from_slice(&output.stdout).context("parse cargo metadata")?;
        Self::from_wire(root, wire)
    }

    fn from_wire(root: &Path, wire: MetadataWire) -> Result<Self> {
        let resolve = wire.resolve.context("cargo metadata resolve is missing")?;
        let id_to_name = wire
            .packages
            .iter()
            .filter(|package| wire.workspace_members.contains(&package.id))
            .map(|package| (package.id.clone(), package.name.clone()))
            .collect::<BTreeMap<_, _>>();
        if id_to_name.len() != wire.workspace_members.len() {
            bail!("cargo metadata workspace member catalog is incomplete");
        }
        let mut package_paths = Vec::new();
        for package in wire
            .packages
            .iter()
            .filter(|package| wire.workspace_members.contains(&package.id))
        {
            let manifest = Path::new(&package.manifest_path);
            let dir = manifest
                .parent()
                .context("metadata manifest has no parent")?;
            let relative = dir
                .strip_prefix(root)
                .with_context(|| format!("metadata path escapes workspace: {}", dir.display()))?;
            package_paths.push((
                relative.to_string_lossy().replace('\\', "/"),
                package.name.clone(),
            ));
        }
        package_paths.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        let mut reverse = BTreeMap::<String, BTreeSet<String>>::new();
        for node in resolve.nodes {
            for dependency in node.deps {
                reverse
                    .entry(dependency.pkg)
                    .or_default()
                    .insert(node.id.clone());
            }
        }
        Ok(Self {
            package_paths,
            id_to_name,
            reverse,
        })
    }

    fn contains(&self, package: &str) -> bool {
        self.id_to_name.values().any(|name| name == package)
    }

    fn package_for_path(&self, path: &str) -> Option<&str> {
        self.package_paths
            .iter()
            .find(|(root, _)| path == root || path.starts_with(&format!("{root}/")))
            .map(|(_, name)| name.as_str())
    }

    fn reverse_closure(&self, names: &BTreeSet<String>) -> BTreeSet<String> {
        let mut ids = self
            .id_to_name
            .iter()
            .filter(|(_, name)| names.contains(*name))
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        let mut queue = ids.iter().cloned().collect::<VecDeque<_>>();
        while let Some(id) = queue.pop_front() {
            if let Some(consumers) = self.reverse.get(&id) {
                for consumer in consumers {
                    if ids.insert(consumer.clone()) {
                        queue.push_back(consumer.clone());
                    }
                }
            }
        }
        ids.into_iter()
            .filter_map(|id| self.id_to_name.get(&id).cloned())
            .collect()
    }
}

fn policy_version(source: &[u8]) -> String {
    policy_version_with_catalog(source, &policy_semantic_catalog())
}

fn policy_version_with_catalog(source: &[u8], catalog: &[String]) -> String {
    let mut material = Vec::new();
    match std::str::from_utf8(source)
        .ok()
        .and_then(|value| toml::from_str::<PolicyWire>(value).ok())
    {
        Some(policy) => {
            push_policy_field(&mut material, b"policy-valid");
            push_policy_field(&mut material, policy.schema_version.to_string().as_bytes());
            push_policy_field(
                &mut material,
                match policy.mode {
                    PolicyMode::Shadow => b"shadow",
                    PolicyMode::Adaptive => b"adaptive",
                },
            );
        }
        None => {
            push_policy_field(&mut material, b"policy-invalid");
            push_policy_field(&mut material, sha256(source).as_bytes());
        }
    }
    for field in catalog {
        push_policy_field(&mut material, field.as_bytes());
    }
    sha256(&material)
}

fn policy_semantic_catalog() -> Vec<String> {
    policy_semantic_catalog_with_behavior(POLICY_BEHAVIOR_SPEC)
}

fn policy_semantic_catalog_with_behavior(behavior_spec: &str) -> Vec<String> {
    let mut catalog = vec![format!("policy-schema={POLICY_SCHEMA_VERSION}")];
    catalog.push(normalized_behavior_spec_identity(behavior_spec));
    catalog.extend(
        DOCUMENTATION_PATHS
            .iter()
            .map(|path| format!("documentation-path={path}")),
    );
    catalog.extend(
        DOCUMENTATION_PREFIXES
            .iter()
            .map(|path| format!("documentation-prefix={path}")),
    );
    catalog.extend(
        DOCUMENTATION_GOVERNED_PREFIXES
            .iter()
            .map(|path| format!("documentation-governed-prefix={path}")),
    );
    catalog.extend(
        MACHINE_INPUT_PATHS
            .iter()
            .map(|path| format!("machine-input-path={path}")),
    );
    catalog.extend(
        HIGH_IMPACT_PATHS
            .iter()
            .map(|path| format!("high-impact-path={path}")),
    );
    catalog.extend(
        HIGH_IMPACT_PREFIXES
            .iter()
            .map(|path| format!("high-impact-prefix={path}")),
    );
    for key in CiJobKey::ALL {
        catalog.push(format!("job-key={}", key.as_str()));
        catalog.push(format!("job-lane={}", key.lane_kind().workflow_name()));
        catalog.push(format!("job-shard={}", key.shard().unwrap_or("")));
        catalog.push(format!("job-partition={}", key.partition().unwrap_or("")));
    }
    for shard in IntegrationShard::ALL {
        catalog.push(format!("integration-shard={}", shard.as_str()));
        catalog.push(format!(
            "integration-partition-policy={}",
            match shard.partition_policy() {
                integration_shards::PartitionPolicy::Unpartitioned => "unpartitioned",
                integration_shards::PartitionPolicy::TwoWayHash => "two-way-hash",
            }
        ));
        for batch in integration_shards::batches(*shard) {
            catalog.push(format!("integration-package={}", batch.package));
            catalog.push(format!("integration-filter={}", batch.filter));
        }
    }
    catalog.extend(
        crate::layers::BASIS_CRATES
            .iter()
            .map(|package| format!("basis-package={package}")),
    );
    catalog.extend(
        crate::layers::DOMAIN_CRATES
            .iter()
            .map(|package| format!("domain-package={package}")),
    );
    catalog
}

fn normalized_behavior_spec_identity(source: &str) -> String {
    let normalized = serde_json::from_str::<serde_json::Value>(source)
        .and_then(|value| serde_json::to_vec(&value));
    match normalized {
        Ok(bytes) => format!("policy-behavior-spec={}", sha256(&bytes)),
        Err(_) => format!("policy-behavior-spec-invalid={}", sha256(source.as_bytes())),
    }
}

fn push_policy_field(material: &mut Vec<u8>, field: &[u8]) {
    material.extend_from_slice(&(field.len() as u64).to_be_bytes());
    material.extend_from_slice(field);
}

fn sha256(source: &[u8]) -> String {
    format!("{:x}", Sha256::digest(source))
}

fn validate_hex_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("CI impact plan {label} must be a SHA-256 digest");
    }
    Ok(())
}

fn validate_revision(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("CI impact plan {label} must be a 40- or 64-hex object ID");
    }
    Ok(())
}

fn decision_kind_name(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Adaptive => "adaptive",
        DecisionKind::MandatoryFull => "mandatory-full",
        DecisionKind::FallbackFull => "fallback-full",
    }
}

fn git_stdout<const N: usize>(root: &Path, args: [&str; N]) -> Result<String> {
    let output = external_cmd(ExternalProgram::SystemGit, &args, &[], Some(root))
        .output()
        .context("execute git")?;
    if !output.status.success() {
        bail!("git command failed");
    }
    String::from_utf8(output.stdout).context("git output is not UTF-8")
}

#[cfg(test)]
pub(crate) fn test_plan() -> Result<CiImpactPlan> {
    CiImpactPlan::new(PlanInput {
        policy_version: "a".repeat(64),
        policy_mode: PolicyMode::Shadow,
        decision_kind: DecisionKind::MandatoryFull,
        decision_reason: DecisionReason::Shadow,
        fallback_context: None,
        revisions: RevisionIdentity {
            base_revision: "b".repeat(40),
            head_revision: "c".repeat(40),
            merge_base_revision: "d".repeat(40),
            execution_revision: "e".repeat(40),
        },
        recommendation: Recommendation::empty(),
        run_id: "42".to_owned(),
        run_attempt: "3".to_owned(),
    })
}

#[cfg(test)]
pub(crate) fn test_adaptive_plan() -> Result<CiImpactPlan> {
    CiImpactPlan::new(PlanInput {
        policy_version: "a".repeat(64),
        policy_mode: PolicyMode::Adaptive,
        decision_kind: DecisionKind::Adaptive,
        decision_reason: DecisionReason::PullRequestImpact,
        fallback_context: None,
        revisions: RevisionIdentity {
            base_revision: "b".repeat(40),
            head_revision: "c".repeat(40),
            merge_base_revision: "d".repeat(40),
            execution_revision: "e".repeat(40),
        },
        recommendation: Recommendation::empty(),
        run_id: "42".to_owned(),
        run_attempt: "3".to_owned(),
    })
}

#[cfg(test)]
pub(crate) fn test_plan_with_noncanonical_artifact() -> Result<CiImpactPlan> {
    let mut plan = test_plan()?;
    plan.jobs[0].expected_artifact = "ci-evidence-noncanonical-42-3".to_owned();
    plan.plan_digest = plan.compute_digest()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::visit::Visit;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct PolicyGolden {
        schema_version: u8,
        machine_inputs: Vec<String>,
        path_cases: Vec<PathCaseGolden>,
        shadow_matrix: serde_json::Value,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct PathCaseGolden {
        status: String,
        path: String,
        full_cause: Option<String>,
        recommended: Vec<String>,
    }

    fn policy_golden() -> Result<PolicyGolden> {
        serde_json::from_str(POLICY_BEHAVIOR_SPEC).context("parse CI impact policy golden")
    }

    fn full_cause_name(cause: FullCause) -> &'static str {
        match cause {
            FullCause::MandatoryCatalog => "mandatory-catalog",
            FullCause::GlobalImpact => "global-impact",
            FullCause::RenameOrCopy => "rename-or-copy",
            FullCause::UnknownPath => "unknown-path",
            FullCause::FallbackUncertainty => "fallback-uncertainty",
        }
    }

    fn rust_sources(root: &Path) -> Result<Vec<PathBuf>> {
        fn visit(path: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    if matches!(name.as_ref(), ".git" | ".cache" | "target" | "worktrees") {
                        continue;
                    }
                    visit(&path, output)?;
                } else if path.extension() == Some(OsStr::new("rs")) {
                    output.push(path);
                }
            }
            Ok(())
        }

        let mut output = Vec::new();
        visit(root, &mut output)?;
        output.sort();
        Ok(output)
    }

    fn machine_consumed_docs(root: &Path) -> Result<BTreeSet<String>> {
        struct IncludeVisitor<'a> {
            root: &'a Path,
            source: &'a Path,
            docs: BTreeSet<String>,
            errors: Vec<String>,
        }

        impl<'ast> Visit<'ast> for IncludeVisitor<'_> {
            fn visit_macro(&mut self, node: &'ast syn::Macro) {
                let is_include = node
                    .path
                    .get_ident()
                    .is_some_and(|name| name == "include_str" || name == "include_bytes");
                if is_include {
                    match node.parse_body::<syn::LitStr>() {
                        Ok(literal) => {
                            let target = self
                                .source
                                .parent()
                                .unwrap_or(self.root)
                                .join(literal.value());
                            match fs::canonicalize(&target).and_then(|target| {
                                target
                                    .strip_prefix(self.root)
                                    .map(Path::to_path_buf)
                                    .map_err(|_| {
                                        std::io::Error::new(
                                            std::io::ErrorKind::InvalidData,
                                            "include target escapes workspace",
                                        )
                                    })
                            }) {
                                Ok(relative) if relative.starts_with("docs") => {
                                    self.docs
                                        .insert(relative.to_string_lossy().replace('\\', "/"));
                                }
                                Ok(_) => {}
                                Err(error) => self.errors.push(format!(
                                    "{}: {} ({error})",
                                    self.source.display(),
                                    target.display()
                                )),
                            }
                        }
                        Err(error) if node.tokens.to_string().contains("docs") => {
                            self.errors.push(format!(
                                "{}: non-literal documentation include ({error})",
                                self.source.display()
                            ));
                        }
                        Err(_) => {}
                    }
                }
                syn::visit::visit_macro(self, node);
            }
        }

        let canonical_root = fs::canonicalize(root)?;
        let mut docs = BTreeSet::new();
        let mut errors = Vec::new();
        for source in rust_sources(&canonical_root)? {
            let text = fs::read_to_string(&source)
                .with_context(|| format!("read Rust source {}", source.display()))?;
            let syntax = syn::parse_file(&text)
                .with_context(|| format!("parse Rust source {}", source.display()))?;
            let mut visitor = IncludeVisitor {
                root: &canonical_root,
                source: &source,
                docs: BTreeSet::new(),
                errors: Vec::new(),
            };
            visitor.visit_file(&syntax);
            docs.append(&mut visitor.docs);
            errors.append(&mut visitor.errors);
        }
        if !errors.is_empty() {
            bail!("invalid machine input includes: {}", errors.join("; "));
        }
        Ok(docs)
    }

    fn machine_input_mapping_is_exact(
        discovered: &BTreeSet<String>,
        configured: &BTreeSet<String>,
        golden: &BTreeSet<String>,
    ) -> bool {
        discovered == configured && configured == golden
    }

    fn git(root: &Path, args: &[&str]) -> Result<()> {
        let status = external_cmd(ExternalProgram::SystemGit, args, &[], Some(root)).status()?;
        if !status.success() {
            bail!("git fixture command failed: {args:?}");
        }
        Ok(())
    }

    fn commit_all(root: &Path, message: &str) -> Result<String> {
        git(root, &["add", "."])?;
        git(
            root,
            &[
                "-c",
                "user.name=CI Impact",
                "-c",
                "user.email=ci-impact@example.invalid",
                "commit",
                "-m",
                message,
            ],
        )?;
        Ok(git_stdout(root, ["rev-parse", "HEAD"])?.trim().to_owned())
    }

    fn pr_event(base: &str, head: &str) -> String {
        serde_json::json!({"pull_request":{"base":{"sha":base},"head":{"sha":head}}}).to_string()
    }

    fn plan_fixture_pr(
        root: &Path,
        base: &str,
        head: &str,
        mode: PolicyMode,
    ) -> Result<CiImpactPlan> {
        plan_event(
            root,
            "pull_request",
            &pr_event(base, head),
            policy_version(
                format!(
                    "schemaVersion=1\nmode='{}'\n",
                    match mode {
                        PolicyMode::Shadow => "shadow",
                        PolicyMode::Adaptive => "adaptive",
                    }
                )
                .as_bytes(),
            ),
            mode,
            head.to_owned(),
            "42".to_owned(),
            "1".to_owned(),
        )
    }

    #[test]
    fn policy_rejects_unknown_and_rename_red() {
        assert!(matches!(
            classify_diff(&[DiffEntry::rename("crates/vocab/src/lib.rs")]),
            Recommendation::Full(_)
        ));
        assert!(matches!(
            classify_diff(&[DiffEntry::modified("unowned/input.bin")]),
            Recommendation::Full(_)
        ));
        assert_eq!(full_override(None), FullOverride::Disabled);
        assert_eq!(
            full_override(Some(OsStr::new("true"))),
            FullOverride::Enabled
        );
        assert_eq!(
            full_override(Some(OsStr::new("TRUE"))),
            FullOverride::Invalid
        );
    }

    #[test]
    fn local_options_are_closed_and_fail_closed() -> Result<()> {
        assert_eq!(
            parse_local_options(&["--base", "origin/develop"])?,
            LocalOptions {
                base: "origin/develop".to_owned(),
            }
        );
        for args in [
            Vec::<&str>::new(),
            vec!["--base"],
            vec!["--base", "main", "--base", "develop"],
            vec!["--base", "--working-tree"],
            vec!["--head", "main"],
            vec!["main"],
        ] {
            assert!(parse_local_options(&args).is_err(), "accepted {args:?}");
        }
        Ok(())
    }

    #[test]
    fn one_impact_set_projects_to_local_and_remote_without_path_remapping() {
        let empty = impact_entries(&[], None, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(LocalProjection::from(&empty), LocalProjection::Empty);
        assert_eq!(
            RemoteProjection::from(&empty).selected_names(),
            vec!["ci-meta"]
        );

        let docs = impact_entries(
            &[DiffEntry::modified("docs/ops/example.md")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(LocalProjection::from(&docs), LocalProjection::FastMeta);

        let mut direct = BTreeMap::new();
        direct.insert("leaf".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let selective = impact_entries(
            &[DiffEntry::modified("crates/leaf/src/lib.rs")],
            None,
            &BTreeSet::from(["consumer".to_owned(), "leaf".to_owned()]),
            &direct,
        );
        assert_eq!(
            LocalProjection::from(&selective),
            LocalProjection::Selective {
                check_packages: vec!["consumer".to_owned(), "leaf".to_owned()],
                test_clippy_packages: vec!["leaf".to_owned()],
                feature_gates: Vec::new(),
                feature_compile_scopes: Vec::new(),
            }
        );
        assert!(
            RemoteProjection::from(&selective)
                .selected_names()
                .contains(&"ci-core-tests/1-of-2")
        );

        let full = impact_entries(
            &[DiffEntry::rename("crates/leaf/src/lib.rs")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(matches!(
            LocalProjection::from(&full),
            LocalProjection::Full
        ));
        assert_eq!(
            RemoteProjection::from(&full).selected_names().len(),
            CiJobKey::COUNT
        );
    }

    #[test]
    fn selective_local_steps_are_ordered_and_feature_gates_are_closed() {
        let projection = LocalProjection::Selective {
            check_packages: vec!["redis-adapter".to_owned(), "runtime".to_owned()],
            test_clippy_packages: vec!["redis-adapter".to_owned()],
            feature_gates: vec![crate::nextest::CoreTestScope::RedisBackend],
            feature_compile_scopes: vec![LocalFeatureScope::RedisAdapter],
        };
        assert_eq!(
            projection.steps(),
            vec![
                LocalStep::FastMeta,
                LocalStep::Packages {
                    operation: LocalCargoOperation::Check,
                    packages: vec!["redis-adapter".to_owned(), "runtime".to_owned()],
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["redis-adapter".to_owned()],
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Clippy,
                    packages: vec!["redis-adapter".to_owned()],
                },
                LocalStep::Feature(crate::nextest::CoreTestScope::RedisBackend),
                LocalStep::FeatureCompile(LocalFeatureScope::RedisAdapter),
            ]
        );
        assert_eq!(
            crate::nextest::CoreTestScope::RedisBackend.package(),
            Some("redis-adapter")
        );
    }

    #[test]
    fn selected_integration_shards_compile_their_feature_scopes_without_running() -> Result<()> {
        let mut direct = BTreeMap::new();
        direct.insert("mqtt".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let impact = impact_entries(
            &[DiffEntry::modified("adapters/mqtt/src/lib.rs")],
            None,
            &BTreeSet::from(["mqtt".to_owned()]),
            &direct,
        );
        let ImpactSet::Selective(mut selective) = impact else {
            bail!("mqtt source change must remain selective");
        };
        selective
            .integration_shards
            .insert(IntegrationShard::EventTransport);

        let labels = LocalProjection::from(&ImpactSet::Selective(selective))
            .steps()
            .iter()
            .map(LocalStep::label)
            .collect::<Vec<_>>();
        for package in ["amqp", "mqtt", "journeys", "runtime"] {
            assert!(
                labels
                    .iter()
                    .any(|label| label == &format!("compile {package}[integration] --no-run")),
                "selected shard omitted {package}[integration]: {labels:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn local_executor_stops_at_the_first_failed_step() {
        let steps = vec![
            LocalStep::FastMeta,
            LocalStep::Packages {
                operation: LocalCargoOperation::Check,
                packages: vec!["leaf".to_owned()],
            },
            LocalStep::Packages {
                operation: LocalCargoOperation::Test,
                packages: vec!["leaf".to_owned()],
            },
        ];
        let mut executed = Vec::new();
        let result = execute_local_steps(&steps, |step| {
            executed.push(step.clone());
            if executed.len() == 2 {
                bail!("synthetic failure");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(executed, steps[..2]);
    }

    #[test]
    fn local_impact_reads_committed_base_range_only_and_fails_safe() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-local-range");
        fs::create_dir_all(temporary_root.join("crates/leaf/src"))?;
        let root = fs::canonicalize(temporary_root)?;
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['crates/leaf']\nresolver='2'\n",
        )?;
        fs::write(
            root.join("crates/leaf/Cargo.toml"),
            "[package]\nname='leaf'\nversion='0.0.0'\nedition='2024'\n",
        )?;
        let source_path = root.join("crates/leaf/src/lib.rs");
        fs::write(&source_path, "pub fn value() -> u8 { 1 }\n")?;
        git(&root, &["init"])?;
        let status =
            cargo_cmd(CargoSubcommand::GenerateLockfile, &[], &[], Some(&root)).status()?;
        if !status.success() {
            bail!("generate-lockfile fixture command failed");
        }
        let base = commit_all(&root, "base")?;

        fs::write(&source_path, "pub fn value() -> u8 { 2 }\n")?;
        fs::write(root.join("untracked.bin"), "not part of committed range")?;
        assert_eq!(local_impact(&root, &base), ImpactSet::Empty);

        fs::write(&source_path, "pub fn value() -> u8 { 1 }\n")?;
        fs::remove_file(root.join("untracked.bin"))?;
        fs::create_dir_all(root.join("docs/ops"))?;
        fs::write(root.join("docs/ops/local.md"), "committed docs\n")?;
        commit_all(&root, "docs")?;
        assert_eq!(
            LocalProjection::from(&local_impact(&root, &base)),
            LocalProjection::FastMeta
        );

        fs::write(&source_path, "pub fn value() -> u8 { 3 }\n")?;
        commit_all(&root, "source")?;
        let committed_projection = LocalProjection::from(&local_impact(&root, &base));
        assert!(matches!(
            committed_projection,
            LocalProjection::Selective { .. }
        ));
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['dirty-untracked-member']\nresolver='2'\n",
        )?;
        fs::create_dir_all(root.join("dirty-untracked-member"))?;
        fs::write(
            root.join("dirty-untracked-member/Cargo.toml"),
            "[package]\nname='dirty-untracked-member'\nversion='0.0.0'\nedition='2024'\n",
        )?;
        assert_eq!(
            LocalProjection::from(&local_impact(&root, &base)),
            committed_projection,
            "dirty and untracked manifests must not affect committed impact classification"
        );
        assert!(matches!(
            local_impact(&root, "refs/heads/does-not-exist"),
            ImpactSet::Full(FullCause::FallbackUncertainty)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn local_execution_context_binds_revisions_and_excludes_caller_dirt() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-local-context");
        fs::create_dir_all(&temporary_root)?;
        let root = fs::canonicalize(temporary_root)?;
        fs::write(root.join("tracked.txt"), "base\n")?;
        git(&root, &["init"])?;
        let base = commit_all(&root, "base")?;
        git(&root, &["branch", "base-ref", &base])?;

        fs::write(root.join("tracked.txt"), "committed head\n")?;
        let head = commit_all(&root, "head")?;
        fs::write(root.join("tracked.txt"), "dirty caller\n")?;
        git(&root, &["add", "tracked.txt"])?;
        fs::write(root.join("untracked.txt"), "caller only\n")?;

        let context = LocalExecutionContext::new(&root, "refs/heads/base-ref")?;
        assert_eq!(context.base, base);
        assert_eq!(context.head, head);
        assert_eq!(context.merge_base, context.base);
        assert_ne!(context.root(), root);
        assert_eq!(
            git_stdout(context.root(), ["rev-parse", "HEAD"])?.trim(),
            context.head
        );
        assert_eq!(
            fs::read_to_string(context.root().join("tracked.txt"))?,
            "committed head\n"
        );
        assert!(!context.root().join("untracked.txt").exists());

        drop(context);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn real_git_pr_plans_preserve_shadow_adaptive_global_and_fallback_semantics() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-real-pr");
        fs::create_dir_all(temporary_root.join("crates/leaf/src"))?;
        let root = fs::canonicalize(temporary_root)?;
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers=['crates/leaf']\nresolver='2'\n",
        )?;
        fs::write(
            root.join("crates/leaf/Cargo.toml"),
            "[package]\nname='leaf'\nversion='0.0.0'\nedition='2024'\n\n[lib]\npath='src/entry.rs'\n",
        )?;
        fs::write(root.join("crates/leaf/src/entry.rs"), "pub mod value;\n")?;
        fs::write(
            root.join("crates/leaf/src/value.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )?;
        fs::write(root.join("Makefile"), "all:\n\t@true\n")?;
        git(&root, &["init"])?;
        let status =
            cargo_cmd(CargoSubcommand::GenerateLockfile, &[], &[], Some(&root)).status()?;
        if !status.success() {
            bail!("generate-lockfile fixture command failed");
        }
        let base = commit_all(&root, "base")?;

        fs::write(
            root.join("crates/leaf/src/value.rs"),
            "pub fn value() -> u8 { 2 }\n",
        )?;
        let ordinary = commit_all(&root, "ordinary")?;
        let shadow = plan_fixture_pr(&root, &base, &ordinary, PolicyMode::Shadow)?;
        assert_eq!(shadow.decision_reason, DecisionReason::Shadow);
        assert_eq!(shadow.decision_kind, DecisionKind::MandatoryFull);
        assert_eq!(shadow.matrix().include.len(), CiJobKey::COUNT);
        assert!(
            shadow
                .jobs
                .iter()
                .any(|job| !job.recommended && job.execute)
        );
        assert_eq!(CiImpactPlan::from_json(&shadow.to_json()?)?, shadow);

        let adaptive = plan_fixture_pr(&root, &base, &ordinary, PolicyMode::Adaptive)?;
        assert_eq!(adaptive.decision_kind, DecisionKind::Adaptive);
        assert_eq!(adaptive.decision_reason, DecisionReason::PullRequestImpact);
        assert_eq!(
            adaptive.matrix().include.len(),
            adaptive.jobs.iter().filter(|job| job.recommended).count()
        );
        assert_ne!(adaptive.plan_digest, shadow.plan_digest);

        fs::write(root.join("Makefile"), "all:\n\t@echo global\n")?;
        let global = commit_all(&root, "global")?;
        let global_plan = plan_fixture_pr(&root, &ordinary, &global, PolicyMode::Shadow)?;
        assert_eq!(global_plan.decision_kind, DecisionKind::MandatoryFull);
        assert_eq!(global_plan.decision_reason, DecisionReason::GlobalImpact);
        assert!(
            global_plan
                .jobs
                .iter()
                .all(|job| job.recommended && job.execute)
        );

        git(
            &root,
            &[
                "mv",
                "crates/leaf/src/value.rs",
                "crates/leaf/src/renamed.rs",
            ],
        )?;
        let renamed = commit_all(&root, "rename")?;
        let rename_plan = plan_fixture_pr(&root, &global, &renamed, PolicyMode::Shadow)?;
        assert_eq!(rename_plan.decision_kind, DecisionKind::FallbackFull);
        assert_eq!(rename_plan.decision_reason, DecisionReason::RenameOrCopy);
        assert!(rename_plan.full_fallback);

        fs::copy(
            root.join("crates/leaf/src/renamed.rs"),
            root.join("crates/leaf/src/copied.rs"),
        )?;
        let copied = commit_all(&root, "copy unchanged source")?;
        let copy_plan = plan_fixture_pr(&root, &renamed, &copied, PolicyMode::Adaptive)?;
        assert_eq!(copy_plan.decision_kind, DecisionKind::FallbackFull);
        assert_eq!(copy_plan.decision_reason, DecisionReason::RenameOrCopy);
        assert!(copy_plan.full_fallback);

        fs::create_dir_all(root.join("unowned"))?;
        fs::write(root.join("unowned/input.bin"), "unknown")?;
        let unknown = commit_all(&root, "unknown")?;
        let unknown_plan = plan_fixture_pr(&root, &copied, &unknown, PolicyMode::Adaptive)?;
        assert_eq!(unknown_plan.decision_kind, DecisionKind::FallbackFull);
        assert_eq!(unknown_plan.decision_reason, DecisionReason::UnknownPath);
        assert!(unknown_plan.full_fallback);
        assert!(unknown_plan.jobs.iter().all(|job| job.execute));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn policy_selects_docs_core_and_integration_green() {
        let docs = classify_diff(&[DiffEntry::modified("docs/ops/example.md")]);
        assert_eq!(docs.selected_names(), vec!["ci-meta"]);

        let core = classify_diff(&[DiffEntry::modified("crates/identity/src/service.rs")]);
        assert!(core.selected_names().contains(&"ci-core-tests/1-of-2"));

        let adapter = classify_diff(&[DiffEntry::modified("adapters/postgres/src/lib.rs")]);
        assert!(
            adapter
                .selected_names()
                .contains(&"integration/postgres-domain")
        );
    }

    #[test]
    fn policy_behavior_and_shadow_matrix_match_independent_golden() -> Result<()> {
        let golden = policy_golden()?;
        assert_eq!(golden.schema_version, 1);
        assert_eq!(
            golden.machine_inputs,
            MACHINE_INPUT_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>()
        );
        for case in golden.path_cases {
            let status = match case.status.as_str() {
                "modified" => DiffStatus::Modified,
                "renamed" => DiffStatus::Renamed,
                other => bail!("unknown golden diff status: {other}"),
            };
            let recommendation = classify_diff(&[DiffEntry {
                status,
                path: case.path.clone(),
            }]);
            assert_eq!(
                recommendation.selected_names(),
                case.recommended
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                "golden recommendation drift for {}",
                case.path
            );
            assert_eq!(
                match recommendation {
                    Recommendation::Full(cause) => Some(full_cause_name(cause)),
                    Recommendation::Selective(_) => None,
                },
                case.full_cause.as_deref(),
                "golden decision drift for {}",
                case.path
            );
        }

        let plan = test_plan()?;
        let mut matrix = serde_json::to_value(plan.matrix())?;
        let rows = matrix["include"]
            .as_array_mut()
            .context("matrix include must be an array")?;
        for row in rows {
            row["planDigest"] = "<plan-digest>".into();
            row["sourceRevision"] = "<source-revision>".into();
        }
        assert_eq!(matrix, golden.shadow_matrix);
        Ok(())
    }

    #[test]
    fn machine_consumed_documents_cannot_take_the_docs_only_fast_path_red() {
        assert!(
            !MACHINE_INPUT_PATHS.is_empty(),
            "machine-input anti-vacuity"
        );
        for path in MACHINE_INPUT_PATHS {
            assert!(
                matches!(
                    classify_diff(&[DiffEntry::modified(path)]),
                    Recommendation::Full(FullCause::GlobalImpact)
                ),
                "machine-consumed input {path} must conservatively execute the full catalog"
            );
        }
    }

    #[test]
    fn workspace_machine_document_inputs_are_exact_and_mutation_hardened() -> Result<()> {
        let root = crate::workspace_root()?;
        let discovered = machine_consumed_docs(&root)?;
        let configured = MACHINE_INPUT_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<BTreeSet<_>>();
        let golden = policy_golden()?
            .machine_inputs
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert!(machine_input_mapping_is_exact(
            &discovered,
            &configured,
            &golden
        ));

        for path in &configured {
            let mut missing = configured.clone();
            assert!(missing.remove(path));
            assert!(
                !machine_input_mapping_is_exact(&discovered, &missing, &golden),
                "removing machine-consumed input `{path}` must fail closed"
            );
        }

        let mut extra = configured;
        extra.insert("docs/runbooks/not-machine-consumed.md".to_owned());
        assert!(!machine_input_mapping_is_exact(
            &discovered,
            &extra,
            &golden
        ));
        Ok(())
    }

    #[test]
    fn plan_roundtrip_rejects_duplicate_catalog_entries() -> Result<()> {
        let plan = test_plan()?;
        let source = plan.to_json()?;
        assert_eq!(CiImpactPlan::from_json(&source)?, plan);

        let mut wire: serde_json::Value = serde_json::from_str(&source)?;
        wire["jobs"][1]["key"] = wire["jobs"][0]["key"].clone();
        assert!(CiImpactPlan::from_json(&wire.to_string()).is_err());

        let mut digest_drift: serde_json::Value = serde_json::from_str(&source)?;
        digest_drift["decisionReason"] = serde_json::json!("full-override");
        assert!(CiImpactPlan::from_json(&digest_drift.to_string()).is_err());

        let mut illegal = plan.clone();
        illegal.decision_reason = DecisionReason::PullRequestImpact;
        illegal.plan_digest = illegal.compute_digest()?;
        assert!(CiImpactPlan::from_json(&illegal.to_json()?).is_err());

        let mut artifact = plan.clone();
        artifact.jobs[0].expected_artifact = "ci-evidence-forged".to_owned();
        artifact.plan_digest = artifact.compute_digest()?;
        assert!(CiImpactPlan::from_json(&artifact.to_json()?).is_err());

        let mut full_reason = fallback_plan(
            "a".repeat(64),
            PolicyMode::Adaptive,
            DecisionReason::UnknownPath,
            "e".repeat(40),
            "42".to_owned(),
            "3".to_owned(),
        )?;
        for job in &mut full_reason.jobs {
            job.reasons = vec![JobReason::FullCatalog];
        }
        full_reason.plan_digest = full_reason.compute_digest()?;
        assert!(CiImpactPlan::from_json(&full_reason.to_json()?).is_err());
        Ok(())
    }

    #[test]
    fn nul_diff_parser_rejects_unknown_and_non_utf8() -> Result<()> {
        assert!(parse_diff(b"X\0path\0").is_err());
        assert!(parse_diff(b"M100\0path\0").is_err());
        assert!(parse_diff(b"Rfoo\0old\0new\0").is_err());
        assert!(parse_diff(b"M\0\0").is_err());
        assert!(parse_diff(b"M\0bad\xff\0").is_err());
        assert!(matches!(
            parse_diff(b"R100\0old\0new\0")?
                .first()
                .map(|entry| entry.status),
            Some(DiffStatus::Renamed)
        ));
        Ok(())
    }

    #[test]
    fn plan_decisions_close_adaptive_mandatory_and_fallback_states() -> Result<()> {
        let input = |policy_mode, decision_kind, recommendation| PlanInput {
            policy_version: "a".repeat(64),
            policy_mode,
            decision_kind,
            decision_reason: match decision_kind {
                DecisionKind::Adaptive => DecisionReason::PullRequestImpact,
                DecisionKind::MandatoryFull => DecisionReason::DevelopPush,
                DecisionKind::FallbackFull => DecisionReason::DiffUnavailable,
            },
            fallback_context: (decision_kind == DecisionKind::FallbackFull)
                .then(|| FallbackContext::new(FallbackCode::DiffUnavailable, None)),
            revisions: RevisionIdentity {
                base_revision: UNKNOWN_REVISION.to_owned(),
                head_revision: UNKNOWN_REVISION.to_owned(),
                merge_base_revision: UNKNOWN_REVISION.to_owned(),
                execution_revision: "e".repeat(40),
            },
            recommendation,
            run_id: "42".to_owned(),
            run_attempt: "3".to_owned(),
        };

        let adaptive = CiImpactPlan::new(input(
            PolicyMode::Adaptive,
            DecisionKind::Adaptive,
            Recommendation::empty(),
        ))?;
        assert_eq!(adaptive.jobs.iter().filter(|job| job.execute).count(), 1);
        assert!(!adaptive.full_fallback);

        let mandatory = CiImpactPlan::new(input(
            PolicyMode::Adaptive,
            DecisionKind::MandatoryFull,
            Recommendation::Full(FullCause::MandatoryCatalog),
        ))?;
        assert!(mandatory.jobs.iter().all(|job| job.execute));
        assert!(!mandatory.full_fallback);

        let fallback = CiImpactPlan::new(input(
            PolicyMode::Adaptive,
            DecisionKind::FallbackFull,
            Recommendation::Full(FullCause::FallbackUncertainty),
        ))?;
        assert!(fallback.jobs.iter().all(|job| job.execute));
        assert!(fallback.full_fallback);

        let mut shadow_input = input(
            PolicyMode::Shadow,
            DecisionKind::MandatoryFull,
            Recommendation::empty(),
        );
        shadow_input.decision_reason = DecisionReason::Shadow;
        let shadow = CiImpactPlan::new(shadow_input)?;
        assert!(shadow.jobs.iter().all(|job| job.execute));
        Ok(())
    }

    #[test]
    fn workspace_graph_ignores_registry_packages_and_closes_reverse_dependencies() -> Result<()> {
        let leaf = "leaf 0.0.0 (path+file:///workspace/crates/leaf)";
        let consumer = "consumer 0.0.0 (path+file:///workspace/crates/consumer)";
        let registry = "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
        let graph = WorkspaceGraph::from_wire(
            Path::new("/workspace"),
            MetadataWire {
                packages: vec![
                    MetadataPackage {
                        name: "leaf".to_owned(),
                        id: leaf.to_owned(),
                        manifest_path: "/workspace/crates/leaf/Cargo.toml".to_owned(),
                    },
                    MetadataPackage {
                        name: "consumer".to_owned(),
                        id: consumer.to_owned(),
                        manifest_path: "/workspace/crates/consumer/Cargo.toml".to_owned(),
                    },
                    MetadataPackage {
                        name: "serde".to_owned(),
                        id: registry.to_owned(),
                        manifest_path: "/registry/serde/Cargo.toml".to_owned(),
                    },
                ],
                workspace_members: BTreeSet::from([leaf.to_owned(), consumer.to_owned()]),
                resolve: Some(MetadataResolve {
                    nodes: vec![
                        MetadataNode {
                            id: leaf.to_owned(),
                            deps: Vec::new(),
                        },
                        MetadataNode {
                            id: consumer.to_owned(),
                            deps: vec![MetadataDependency {
                                pkg: leaf.to_owned(),
                            }],
                        },
                        MetadataNode {
                            id: registry.to_owned(),
                            deps: Vec::new(),
                        },
                    ],
                }),
            },
        )?;
        assert_eq!(
            graph.package_for_path("crates/leaf/src/lib.rs"),
            Some("leaf")
        );
        assert_eq!(
            graph.reverse_closure(&BTreeSet::from(["leaf".to_owned()])),
            BTreeSet::from(["consumer".to_owned(), "leaf".to_owned()])
        );
        assert!(!graph.contains("serde"));
        Ok(())
    }

    fn synthetic_chain_graph(leaves: &[(&str, &str)]) -> WorkspaceGraph {
        let mut package_paths = leaves
            .iter()
            .map(|(path, name)| ((*path).to_owned(), (*name).to_owned()))
            .collect::<Vec<_>>();
        package_paths.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        let mut id_to_name = BTreeMap::from([
            ("adapter".to_owned(), "synthetic-adapter".to_owned()),
            ("runtime".to_owned(), "runtime".to_owned()),
        ]);
        for (_, name) in leaves {
            id_to_name.insert((*name).to_owned(), (*name).to_owned());
        }
        WorkspaceGraph {
            package_paths,
            id_to_name,
            reverse: BTreeMap::new(),
        }
    }

    fn connect_to_runtime(graph: &mut WorkspaceGraph, leaf: &str) {
        graph
            .reverse
            .entry(leaf.to_owned())
            .or_default()
            .insert("adapter".to_owned());
        graph
            .reverse
            .entry("adapter".to_owned())
            .or_default()
            .insert("runtime".to_owned());
    }

    #[test]
    fn multi_hop_reverse_closure_reaches_integration_for_source_contract_consumer_and_generated()
    -> Result<()> {
        let mut source_graph =
            synthetic_chain_graph(&[("generated", "generated"), ("crates/leaf", "leaf")]);
        connect_to_runtime(&mut source_graph, "leaf");
        for path in ["crates/leaf/src/lib.rs", "generated/src/http/leaf_v1.rs"] {
            let recommendation = classify_with_graph(
                Path::new("/workspace"),
                &[DiffEntry::modified(path)],
                &source_graph,
                UNKNOWN_REVISION,
            )?;
            assert!(
                recommendation
                    .selected_names()
                    .contains(&"integration/runtime-http-auth/1-of-2"),
                "{path} must traverse leaf -> adapter -> runtime execution unit"
            );
        }

        let root = crate::testutil::unique_tmp("ci-impact-contract-consumer-chain");
        let contract_dir = root.join("contracts/event/owner/v1/policy-updated");
        fs::create_dir_all(&contract_dir)?;
        let source = fs::read_to_string(
            crate::workspace_root()?
                .join("contracts/event/identity/v1/policy-updated/contract.toml"),
        )?
        .replace("domain = \"identity\"", "domain = \"owner\"")
        .replace("owner = \"identity\"", "owner = \"owner\"")
        .replace("consumer = \"audit\"", "consumer = \"consumer\"");
        fs::write(contract_dir.join("contract.toml"), source)?;
        let mut contract_graph =
            synthetic_chain_graph(&[("crates/owner", "owner"), ("crates/consumer", "consumer")]);
        connect_to_runtime(&mut contract_graph, "consumer");
        let recommendation = classify_with_graph(
            &root,
            &[DiffEntry {
                status: DiffStatus::Added,
                path: "contracts/event/owner/v1/policy-updated/contract.toml".to_owned(),
            }],
            &contract_graph,
            UNKNOWN_REVISION,
        )?;
        assert!(
            recommendation
                .selected_names()
                .contains(&"integration/runtime-http-auth/2-of-2"),
            "contract subscriber must traverse consumer -> adapter -> runtime execution unit"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn contract_owner_subscriber_and_merge_base_deletion_are_preserved() -> Result<()> {
        let workspace = crate::workspace_root()?;
        assert_eq!(
            contract_packages(
                &workspace,
                "contracts/event/identity/v1/policy-updated/payload.schema.json",
                DiffStatus::Added,
                "unused",
            )?,
            BTreeSet::from(["audit".to_owned(), "identity".to_owned()])
        );

        let root = crate::testutil::unique_tmp("ci-impact-contract-delete");
        let contract_dir = root.join("contracts/event/identity/v1/policy-updated");
        fs::create_dir_all(&contract_dir)?;
        fs::copy(
            workspace.join("contracts/event/identity/v1/policy-updated/contract.toml"),
            contract_dir.join("contract.toml"),
        )?;
        fs::write(contract_dir.join("payload.schema.json"), "{}")?;
        for args in [
            vec!["init"],
            vec!["add", "."],
            vec![
                "-c",
                "user.name=CI Impact",
                "-c",
                "user.email=ci-impact@example.invalid",
                "commit",
                "-m",
                "base",
            ],
        ] {
            let status =
                external_cmd(ExternalProgram::SystemGit, &args, &[], Some(&root)).status()?;
            if !status.success() {
                bail!("failed to create contract deletion fixture");
            }
        }
        let base = git_stdout(&root, ["rev-parse", "HEAD"])?;
        let current = fs::read_to_string(contract_dir.join("contract.toml"))?;
        let without_subscriber = current
            .split_once("[[subscriptions]]")
            .map(|(prefix, _)| prefix)
            .context("contract fixture subscription block missing")?;
        fs::write(contract_dir.join("contract.toml"), without_subscriber)?;
        assert_eq!(
            contract_packages(
                &root,
                "contracts/event/identity/v1/policy-updated/contract.toml",
                DiffStatus::Modified,
                base.trim(),
            )?,
            BTreeSet::from(["audit".to_owned(), "identity".to_owned()]),
            "a removed subscriber remains impacted through the merge-base manifest"
        );
        fs::remove_file(contract_dir.join("payload.schema.json"))?;
        assert_eq!(
            contract_packages(
                &root,
                "contracts/event/identity/v1/policy-updated/payload.schema.json",
                DiffStatus::Deleted,
                base.trim(),
            )?,
            BTreeSet::from(["audit".to_owned(), "identity".to_owned()]),
            "a deleted payload unions the old manifest with the surviving current manifest"
        );
        fs::remove_file(contract_dir.join("contract.toml"))?;
        assert_eq!(
            contract_packages(
                &root,
                "contracts/event/identity/v1/policy-updated/contract.toml",
                DiffStatus::Deleted,
                base.trim(),
            )?,
            BTreeSet::from(["audit".to_owned(), "identity".to_owned()])
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn path_policy_covers_full_core_security_and_generated_cases() {
        let cases = [
            ("Cargo.lock", true, "ci-security"),
            (
                "crates/identity/tests/route.rs",
                false,
                "ci-core-tests/2-of-2",
            ),
            ("crates/identity/Cargo.toml", false, "ci-security"),
            ("generated/src/event/mod.rs", true, "ci-meta"),
        ];
        for (path, full, selected) in cases {
            let recommendation = classify_diff(&[DiffEntry::modified(path)]);
            assert_eq!(
                matches!(recommendation, Recommendation::Full(_)),
                full,
                "{path}"
            );
            assert!(
                recommendation.selected_names().contains(&selected),
                "{path}"
            );
        }
    }

    #[test]
    fn policy_digest_is_deterministic_and_binds_config() {
        let compact = b"schemaVersion=1\nmode='shadow'\n";
        let formatted =
            b"# operator comment\nschemaVersion = 1\n\nmode = \"shadow\" # same policy\n";
        assert_eq!(
            policy_version(compact),
            policy_version(formatted),
            "formatting and comments are not policy semantics"
        );
        assert_ne!(
            policy_version(compact),
            policy_version(b"schemaVersion=1\nmode='adaptive'\n")
        );
        let catalog = policy_semantic_catalog();
        let mut changed_catalog = catalog.clone();
        changed_catalog.push("impact-rule=new-semantic-rule".to_owned());
        assert_ne!(
            policy_version_with_catalog(compact, &catalog),
            policy_version_with_catalog(compact, &changed_catalog),
            "an explicit catalog semantic change must rotate policyVersion"
        );
        assert_ne!(
            policy_version_with_catalog(compact, &["ab".to_owned(), "c".to_owned()]),
            policy_version_with_catalog(compact, &["a".to_owned(), "bc".to_owned()]),
            "length-delimited fields must not permit concatenation ambiguity"
        );

        let semantically_same_behavior = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(POLICY_BEHAVIOR_SPEC)
                .unwrap_or(serde_json::Value::Null),
        )
        .unwrap_or_default();
        assert_eq!(
            policy_semantic_catalog(),
            policy_semantic_catalog_with_behavior(&semantically_same_behavior),
            "behavior spec formatting is not policy semantics"
        );
        let mutated_behavior =
            POLICY_BEHAVIOR_SPEC.replacen("docs/guide.md", "docs/changed-policy-input.md", 1);
        assert_ne!(
            policy_version_with_catalog(compact, &policy_semantic_catalog()),
            policy_version_with_catalog(
                compact,
                &policy_semantic_catalog_with_behavior(&mutated_behavior)
            ),
            "behavior truth-table changes must rotate policyVersion"
        );
    }

    #[test]
    fn fallback_plan_exposes_stable_actionable_context_red() -> Result<()> {
        let plan = fallback_plan(
            "a".repeat(64),
            PolicyMode::Adaptive,
            DecisionReason::DiffUnavailable,
            "e".repeat(40),
            "42".to_owned(),
            "3".to_owned(),
        )?;
        let wire: serde_json::Value = serde_json::from_str(&plan.to_json()?)?;
        assert_eq!(wire["fallbackContext"]["code"], "CI-PLAN-DIFF-UNAVAILABLE");
        assert_eq!(wire["fallbackContext"]["stage"], "diff");
        assert!(
            wire["fallbackContext"]["action"]
                .as_str()
                .is_some_and(|action| action.to_ascii_lowercase().contains("fetch")),
            "fallback diagnostic must include a stable remediation without leaking raw errors"
        );
        let summary = render_plan_summary(&plan, CiJobKey::COUNT, CiJobKey::COUNT);
        assert!(summary.contains("CI-PLAN-DIFF-UNAVAILABLE"));
        assert!(summary.contains("Fetch complete base and head history"));

        let typed_failures = [
            PlannerFailure::new(FallbackCode::ShallowRepository, None),
            PlannerFailure::new(FallbackCode::GitDiffUnavailable, None),
            PlannerFailure::new(
                FallbackCode::MetadataUnavailable,
                Some("Cargo.toml".to_owned()),
            ),
            PlannerFailure::new(
                FallbackCode::ContractUnavailable,
                Some("contracts/event/identity/v1/policy-updated/contract.toml".to_owned()),
            ),
        ];
        for failure in typed_failures {
            failure.context.validate(failure.context.code.reason())?;
            assert!(failure.context.code.as_str().starts_with("CI-PLAN-"));
            assert!(!failure.context.action.is_empty());
        }

        let mut forged = plan.clone();
        let context = forged
            .fallback_context
            .as_mut()
            .context("fallback fixture context is missing")?;
        context.subject = Some("/runner/_work/private".to_owned());
        context.action = "`injected`\n# heading".to_owned();
        forged.plan_digest = forged.compute_digest()?;
        assert!(CiImpactPlan::from_json(&forged.to_json()?).is_err());
        Ok(())
    }

    #[test]
    fn workspace_policy_catalog_is_non_vacuous() -> Result<()> {
        let root = crate::workspace_root()?;
        let graph = WorkspaceGraph::load(&root)?;
        assert_eq!(
            graph.package_for_path("xtask/src/ci_impact.rs"),
            Some("xtask")
        );
        for shard in IntegrationShard::ALL {
            let batches = integration_shards::batches(*shard);
            assert!(
                !batches.is_empty(),
                "{} has no execution units",
                shard.as_str()
            );
            assert!(
                batches.iter().all(|batch| graph.contains(batch.package)),
                "{} references a package outside cargo metadata",
                shard.as_str()
            );
        }
        let recommendation = classify_with_graph(
            &root,
            &[DiffEntry::modified("adapters/postgres/src/lib.rs")],
            &graph,
            UNKNOWN_REVISION,
        )?;
        assert!(
            recommendation
                .selected_names()
                .contains(&"integration/postgres-domain")
        );
        Ok(())
    }
}
