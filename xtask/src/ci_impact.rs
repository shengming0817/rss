//! Typed, fail-safe CI impact planning for GitHub Actions.
//!
//! INVARIANT: CI-IMPACT-PLAN-01 { level = "Hard", exec = "native-compile", source = "code", native = "validated plan construction owns the closed typed job array and matrix derivation" }.
//! INVARIANT: CI-IMPACT-POLICY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "policy_rejects_unknown_and_rename_red", anti_vacuity = "workspace_policy_catalog_is_non_vacuous" }.
//! INVARIANT: CI-IMPACT-PROJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private ImpactSet construction and exhaustive local/remote/coverage projections prevent divergent path maps" }.
//! INVARIANT: COVERAGE-SCOPE-PROJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "CoverageDecision Skip|Scope exhaustively projected from private ImpactSet" }.
//! INVARIANT: CI-IMPACT-REQUIRED-EVIDENCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "adaptive_plan_json_cannot_disable_required_evidence_owners_red", anti_vacuity = "adaptive_plan_requires_every_required_evidence_owner" } —— serialized plans cannot bypass any catalog-owned required-evidence executor.

use crate::ci_identity::CiIdentityKey;
use crate::ci_lanes::{CiJobKey, CiLane, GateId, LocalImpactDomain, LocalMetaPolicy, REGISTRY};
use crate::cmd::{CargoSubcommand, ExternalProgram, cargo_cmd, external_cmd};
use crate::integration_shards::{self, IntegrationShard};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const PLAN_SCHEMA_VERSION: u8 = 1;
const POLICY_SCHEMA_VERSION: u8 = 1;
const UNKNOWN_REVISION: &str = "unknown";
const DOCUMENTATION_PATHS: &[&str] = &["README.md"];
const DOCUMENTATION_PREFIXES: &[&str] = &["docs/", ".github/", ".codex/", "hack/"];
const LOCAL_SNAPSHOT_TARGET_SUFFIX: &str = "ci-local-snapshot";

trait LocalClock {
    type Tick: Copy;

    fn now(&self) -> Self::Tick;
    fn elapsed(&self, start: Self::Tick, end: Self::Tick) -> Duration;
}

struct SystemLocalClock;

impl LocalClock for SystemLocalClock {
    type Tick = Instant;

    #[allow(clippy::disallowed_methods)] // system clock adapter boundary for local CLI timing
    fn now(&self) -> Self::Tick {
        Instant::now()
    }

    #[allow(clippy::disallowed_methods)] // system clock adapter boundary for local CLI timing
    fn elapsed(&self, start: Self::Tick, end: Self::Tick) -> Duration {
        end.duration_since(start)
    }
}
/// 被 Rust `include_str!` / `include_bytes!` 消费的受支持机器输入：`docs/` 下的可执行
/// carrier，以及 assembly-schema 的公开 schema 与跨实现 fingerprint fixture。
///
/// 面向人的 runbook / checklist / 报告说明不在此列——测试不得断言散文包含某句话
/// （`docs/rules/README.md` §红线一），因此它们改动时只走 docs-only 快路径。
const MACHINE_INPUT_PATHS: &[&str] = &[
    "docs/ops/0069-account-security-capacity-gate.selftest.sh",
    "docs/ops/0069-account-security-capacity-gate.sh",
    "docs/ops/localtx-alerts.rules.yaml",
    "docs/spec/007-l4-device-latent-production-loop/contracts/application-receipt.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/apply-device-certificate.command.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/device-certificate-reported.event.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/device-command-acked.event.schema.json",
    "crates/assembly-schema/schemas/assembly-lock.schema.json",
    "crates/assembly-schema/schemas/runtime-plan.schema.json",
    "crates/assembly-schema/tests/fixtures/fingerprint-v2-vectors.json",
];
const POLICY_BEHAVIOR_SPEC: &str = include_str!("../tests/golden/ci-impact-policy.json");
const HIGH_IMPACT_PATHS: &[&str] = &[
    ".gitattributes",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "deny.toml",
    "clippy.toml",
];
const HIGH_IMPACT_PREFIXES: &[&str] = &[".config/ci-impact"];
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
    fail_fast: bool,
    fresh: bool,
    only: BTreeSet<LocalStage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LocalStage {
    Meta,
    PythonHooks,
    CargoWrapperSelftest,
    Check,
    Test,
    Clippy,
}

impl LocalStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::PythonHooks => "python-hooks",
            Self::CargoWrapperSelftest => "cargo-wrapper-selftest",
            Self::Check => "check",
            Self::Test => "test",
            Self::Clippy => "clippy",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "meta" => Ok(Self::Meta),
            "python-hooks" => Ok(Self::PythonHooks),
            "cargo-wrapper-selftest" => Ok(Self::CargoWrapperSelftest),
            "check" => Ok(Self::Check),
            "test" => Ok(Self::Test),
            "clippy" => Ok(Self::Clippy),
            _ => bail!("ci local --only 未知 stage: {value}"),
        }
    }
}

pub(crate) fn parse_local_options(args: &[&str]) -> Result<LocalOptions> {
    let mut base = None;
    let mut fail_fast = false;
    let mut fresh = false;
    let mut only = BTreeSet::new();
    let mut iter = args.iter().copied();
    while let Some(flag) = iter.next() {
        match flag {
            "--fail-fast" if !fail_fast => {
                fail_fast = true;
                continue;
            }
            "--fail-fast" => bail!("ci local 重复参数: --fail-fast"),
            "--fresh" if !fresh => {
                fresh = true;
                continue;
            }
            "--fresh" => bail!("ci local 重复参数: --fresh"),
            "--only" => {
                let value = iter.next().context("ci local 参数 --only 缺少值")?;
                if value.is_empty() || value.starts_with("--") {
                    bail!("ci local 参数 --only 必须是非空 stage，不能是 flag");
                }
                let stage = LocalStage::parse(value)?;
                if !only.insert(stage) {
                    bail!("ci local 重复 stage: {value}");
                }
                continue;
            }
            "--base" => {}
            _ => bail!("ci local 未知参数: {flag}"),
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
        fail_fast,
        fresh,
        only,
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
    RequiredEvidence,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    required_evidence_target: Option<&'static str>,
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
        validate_job_catalog(&self.jobs)?;
        let recommends_full_catalog = self.jobs.iter().all(|job| job.recommended);
        if !legal_decision(self.policy_mode, self.decision_kind, self.decision_reason) {
            bail!("CI impact plan policy mode, decision kind, and reason are inconsistent");
        }
        for decision in &self.jobs {
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
        for decision in &self.jobs {
            if decision.key.required_evidence().is_some() {
                if !decision.recommended || !decision.execute {
                    bail!("required-evidence CI owner must be recommended and executed");
                }
                // Full-catalog reasons are already canonical and stronger; selective and Shadow
                // recommendations must retain the explicit required-evidence provenance.
                if !recommends_full_catalog
                    && !decision.reasons.contains(&JobReason::RequiredEvidence)
                {
                    bail!("required-evidence CI owner is missing its typed reason");
                }
            } else if decision.reasons.contains(&JobReason::RequiredEvidence) {
                bail!("non-owner CI job cannot claim the required-evidence reason");
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
                    required_evidence_target: job.key.required_evidence_staged_artifact_path(),
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

fn validate_job_catalog(jobs: &[JobDecision]) -> Result<()> {
    let expected = CiJobKey::ALL.into_iter().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for job in jobs {
        if !actual.insert(job.key) {
            bail!(
                "CI impact plan job catalog contains duplicate ID `{}`",
                job.key.as_str()
            );
        }
    }
    if actual != expected {
        let missing = expected
            .difference(&actual)
            .map(|job| job.as_str())
            .collect::<Vec<_>>();
        let extra = actual
            .difference(&expected)
            .map(|job| job.as_str())
            .collect::<Vec<_>>();
        bail!("CI impact plan job ID closure drift: missing={missing:?}, extra={extra:?}");
    }
    if !jobs.iter().map(|job| job.key).eq(CiJobKey::ALL) {
        bail!("CI impact plan jobs are not in canonical typed catalog order");
    }
    Ok(())
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
    /// Reverse dependency closure of coverage seeds only (Source/Generated/Contract*).
    coverage_closure: BTreeSet<String>,
    /// Workspace members with runnable targets (`lib`/`bin`/`test`/`bench`/`proc-macro`).
    packages_with_tests: BTreeSet<String>,
    /// True when `reverse_closure` contains at least one `lib`/`proc-macro` package.
    /// Drives `cargo check --lib --bins` vs `--bins` for bin-only reverse closures.
    check_includes_lib: bool,
    integration_shards: BTreeSet<IntegrationShard>,
    governance: BTreeSet<GovernanceImpact>,
    local_meta_domains: BTreeSet<LocalImpactDomain>,
    unknown_paths: BTreeSet<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum GovernanceImpact {
    PythonHooks,
    CargoWrapper,
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

    /// Coverage seed categories. Manifest/Test are intentionally excluded (COVERAGE-SCOPE-PROJECTION-01).
    const fn is_coverage_seed(self) -> bool {
        match self {
            Self::Source | Self::Generated | Self::ContractOwner | Self::ContractSubscriber => true,
            Self::Test | Self::Manifest => false,
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
                if !selective.unknown_paths.is_empty() {
                    return Self(Recommendation::Full(FullCause::UnknownPath));
                }
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
        // Plan-side guard: do not schedule ci-coverage when CoverageProjection is Skip
        // (empty seeds / filtered-empty packages). Full recommendations stay untouched.
        if matches!(
            CoverageProjection::from(impact).decision(),
            CoverageDecision::Skip
        ) && let Recommendation::Selective(selected) = &mut recommendation
        {
            selected.remove(&CiJobKey::CiCoverage);
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
    Meta(Vec<GateId>),
    Selective {
        meta_gates: Vec<GateId>,
        check_packages: Vec<String>,
        /// Whether Check should pass `--lib` (false for bin-only reverse closures).
        check_includes_lib: bool,
        test_clippy_packages: Vec<String>,
        governance: BTreeSet<GovernanceImpact>,
    },
}

impl From<&ImpactSet> for LocalProjection {
    fn from(impact: &ImpactSet) -> Self {
        match impact {
            ImpactSet::Empty => Self::Empty,
            ImpactSet::Full(FullCause::UnknownPath) => Self::Meta(local_meta_gates(None)),
            ImpactSet::Full(_) => Self::Meta(all_local_meta_gates()),
            ImpactSet::Selective(selective)
                if selective.packages.is_empty() && selective.governance.is_empty() =>
            {
                Self::Meta(local_meta_gates(Some(&selective.local_meta_domains)))
            }
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
                Self::Selective {
                    meta_gates: local_meta_gates(Some(&selective.local_meta_domains)),
                    check_packages: selective.reverse_closure.iter().cloned().collect(),
                    check_includes_lib: selective.check_includes_lib,
                    test_clippy_packages,
                    governance: selective.governance.clone(),
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LocalCargoTarget {
    Lib,
    Bin(String),
    Test(String),
    Doc,
}

impl LocalCargoTarget {
    fn checkpoint_label(&self) -> String {
        match self {
            Self::Lib => "lib".to_owned(),
            Self::Bin(name) => format!("bin:{name}"),
            Self::Test(name) => format!("test:{name}"),
            Self::Doc => "doc".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalStep {
    Meta(Vec<GateId>),
    PythonHooks,
    CargoWrapperSelftest,
    Packages {
        operation: LocalCargoOperation,
        packages: Vec<String>,
        target: Option<LocalCargoTarget>,
        /// Meaningful for [`LocalCargoOperation::Check`] only.
        check_includes_lib: bool,
    },
}

impl LocalProjection {
    fn steps(&self) -> Vec<LocalStep> {
        match self {
            Self::Empty => Vec::new(),
            Self::Meta(gates) => vec![LocalStep::Meta(gates.clone())],
            Self::Selective {
                meta_gates,
                check_packages,
                check_includes_lib,
                test_clippy_packages,
                governance,
            } => {
                let mut steps = vec![LocalStep::Meta(meta_gates.clone())];
                if !check_packages.is_empty() {
                    steps.push(LocalStep::Packages {
                        operation: LocalCargoOperation::Check,
                        packages: check_packages.clone(),
                        target: None,
                        check_includes_lib: *check_includes_lib,
                    });
                }
                steps.extend(test_clippy_packages.iter().cloned().map(|package| {
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Test,
                        packages: vec![package],
                        target: None,
                        check_includes_lib: true,
                    }
                }));
                steps.extend(test_clippy_packages.iter().cloned().map(|package| {
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Clippy,
                        packages: vec![package],
                        target: None,
                        check_includes_lib: true,
                    }
                }));
                steps.extend(governance.iter().map(|impact| match impact {
                    GovernanceImpact::PythonHooks => LocalStep::PythonHooks,
                    GovernanceImpact::CargoWrapper => LocalStep::CargoWrapperSelftest,
                }));
                steps
            }
        }
    }
}

fn local_meta_gates(domains: Option<&BTreeSet<LocalImpactDomain>>) -> Vec<GateId> {
    REGISTRY
        .iter()
        .filter_map(|spec| match spec.id().local_meta_policy() {
            LocalMetaPolicy::Always => Some(spec.id()),
            LocalMetaPolicy::OnImpact(domain)
                if domains.is_some_and(|domains| domains.contains(&domain)) =>
            {
                Some(spec.id())
            }
            LocalMetaPolicy::OnImpact(_)
            | LocalMetaPolicy::FullOnly
            | LocalMetaPolicy::NeverLocal => None,
        })
        .collect()
}

fn all_local_meta_gates() -> Vec<GateId> {
    REGISTRY
        .iter()
        .filter_map(|spec| match spec.id().local_meta_policy() {
            LocalMetaPolicy::Always | LocalMetaPolicy::OnImpact(_) => Some(spec.id()),
            LocalMetaPolicy::FullOnly | LocalMetaPolicy::NeverLocal => None,
        })
        .collect()
}

fn local_steps(impact: &ImpactSet) -> Vec<LocalStep> {
    LocalProjection::from(impact).steps()
}

/// Workspace-wide coverage cause mapped from [`FullCause`] (exhaustive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoverageWorkspaceCause {
    MandatoryCatalog,
    GlobalImpact,
    RenameOrCopy,
    UnknownPath,
    FallbackUncertainty,
}

impl From<FullCause> for CoverageWorkspaceCause {
    fn from(cause: FullCause) -> Self {
        match cause {
            FullCause::MandatoryCatalog => Self::MandatoryCatalog,
            FullCause::GlobalImpact => Self::GlobalImpact,
            FullCause::RenameOrCopy => Self::RenameOrCopy,
            FullCause::UnknownPath => Self::UnknownPath,
            FullCause::FallbackUncertainty => Self::FallbackUncertainty,
        }
    }
}

/// Closed coverage execution scope. `Packages.packages` is non-empty by construction
/// ([`CoverageScope::packages`]); empty seeds are [`CoverageDecision::Skip`], never this enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CoverageScope {
    Packages {
        packages: Vec<String>,
        strict_touched: Vec<String>,
    },
    Workspace {
        cause: CoverageWorkspaceCause,
    },
}

impl CoverageScope {
    /// Non-empty Packages constructor (COVERAGE-SCOPE-NONEMPTY-01). Empty → `None` (= Skip).
    pub(crate) fn packages(packages: Vec<String>, strict_touched: Vec<String>) -> Option<Self> {
        if packages.is_empty() {
            None
        } else {
            Some(Self::Packages {
                packages,
                strict_touched,
            })
        }
    }

    pub(crate) fn summary(&self) -> String {
        match self {
            Self::Packages {
                packages,
                strict_touched,
            } => format!(
                "kind=packages packages=[{}] strict_touched=[{}]",
                packages.join(","),
                strict_touched.join(",")
            ),
            Self::Workspace { cause } => format!("kind=workspace cause={cause:?}"),
        }
    }
}

/// Plan/execute decision from [`ImpactSet`]: skip scheduling, or run a concrete [`CoverageScope`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum CoverageDecision {
    Skip,
    Scope(CoverageScope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoverageProjection(CoverageDecision);

impl From<&ImpactSet> for CoverageProjection {
    fn from(impact: &ImpactSet) -> Self {
        match impact {
            ImpactSet::Empty => Self(CoverageDecision::Skip),
            ImpactSet::Full(cause) => Self(CoverageDecision::Scope(CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::from(*cause),
            })),
            ImpactSet::Selective(selective) => {
                if !selective.unknown_paths.is_empty() {
                    return Self(CoverageDecision::Scope(CoverageScope::Workspace {
                        cause: CoverageWorkspaceCause::UnknownPath,
                    }));
                }
                let packages = selective
                    .coverage_closure
                    .iter()
                    .filter(|name| selective.packages_with_tests.contains(*name))
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let strict_touched = crate::coverage::STRICT_CRATES
                    .iter()
                    .filter(|name| packages.contains(**name))
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>();
                match CoverageScope::packages(packages.into_iter().collect(), strict_touched) {
                    Some(scope) => Self(CoverageDecision::Scope(scope)),
                    None => Self(CoverageDecision::Skip),
                }
            }
        }
    }
}

impl CoverageProjection {
    fn decision(self) -> CoverageDecision {
        self.0
    }

    fn into_scope_or_fallback(self) -> CoverageScope {
        match self.0 {
            CoverageDecision::Scope(scope) => scope,
            // Forced execution (Shadow / full catalog) with no seeds: fail-safe Workspace.
            CoverageDecision::Skip => CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::FallbackUncertainty,
            },
        }
    }
}

fn coverage_fallback_uncertainty() -> CoverageScope {
    CoverageScope::Workspace {
        cause: CoverageWorkspaceCause::FallbackUncertainty,
    }
}

/// True when `path` is under `RUNNER_TEMP` (if set) or `root` after canonicalize (F13).
fn event_path_is_trusted(root: &Path, path: &Path) -> bool {
    let Ok(canonical) = fs::canonicalize(path) else {
        return false;
    };
    if let Some(runner_temp) = std::env::var_os("RUNNER_TEMP")
        && let Ok(temp) = fs::canonicalize(runner_temp)
        && canonical.starts_with(&temp)
    {
        return true;
    }
    let Ok(workspace) = fs::canonicalize(root) else {
        return false;
    };
    canonical.starts_with(&workspace)
}

/// Resolve coverage scope for the typed `ci-coverage` job using the same base as `ci plan`.
/// Non-PR → Workspace (full catalog). PR parse/diff/metadata failures → Workspace
/// FallbackUncertainty (aligns with plan FallbackFull); never hard-red on planner uncertainty.
pub(crate) fn coverage_scope_for_typed_job(root: &Path) -> Result<CoverageScope> {
    let event_name = std::env::var(CiIdentityKey::EventName.env_name()).unwrap_or_default();
    if event_name != "pull_request" {
        return Ok(CoverageScope::Workspace {
            cause: CoverageWorkspaceCause::MandatoryCatalog,
        });
    }
    Ok(coverage_scope_for_pull_request(root).unwrap_or_else(coverage_fallback_uncertainty))
}

fn coverage_scope_for_pull_request(root: &Path) -> Option<CoverageScope> {
    let event_path = PathBuf::from(std::env::var_os("GITHUB_EVENT_PATH")?);
    if !event_path_is_trusted(root, &event_path) {
        return None;
    }
    let event_source = fs::read_to_string(&event_path).ok()?;
    let event: GithubEvent = serde_json::from_str(&event_source).ok()?;
    let pull_request = event.pull_request?;
    validate_revision(&pull_request.base.sha, "base revision").ok()?;
    validate_revision(&pull_request.head.sha, "head revision").ok()?;
    let shallow = git_stdout(root, ["rev-parse", "--is-shallow-repository"]).ok()?;
    if shallow.trim() != "false" {
        return None;
    }
    let merge_base = git_stdout(
        root,
        [
            "merge-base",
            pull_request.base.sha.as_str(),
            pull_request.head.sha.as_str(),
        ],
    )
    .ok()?;
    let merge_base = merge_base.trim();
    validate_revision(merge_base, "merge-base revision").ok()?;
    let entries = read_diff(root, &pull_request.base.sha, &pull_request.head.sha).ok()?;
    if let Some(cause) = immediate_full_cause(&entries, None) {
        return Some(CoverageProjection::from(&ImpactSet::Full(cause)).into_scope_or_fallback());
    }
    let graph = WorkspaceGraph::load(root).ok()?;
    let impact = impact_with_graph(root, &entries, &graph, merge_base).ok()?;
    Some(CoverageProjection::from(&impact).into_scope_or_fallback())
}

/// Full local CI / CompatibilityCi always evaluates workspace coverage.
pub(crate) fn coverage_scope_for_full_ci() -> CoverageScope {
    CoverageScope::Workspace {
        cause: CoverageWorkspaceCause::MandatoryCatalog,
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
        for key in CiJobKey::ALL {
            if key.required_evidence().is_some() {
                selected.insert(key, BTreeSet::from([JobReason::RequiredEvidence]));
            }
        }
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
    let event_name = std::env::var(CiIdentityKey::EventName.env_name()).unwrap_or_default();
    let execution_revision = std::env::var(CiIdentityKey::HeadRevision.env_name())
        .unwrap_or_else(|_| UNKNOWN_REVISION.to_owned());
    validate_revision(&execution_revision, "execution revision")?;
    let run_id =
        std::env::var(CiIdentityKey::RunId.env_name()).unwrap_or_else(|_| "local".to_owned());
    let run_attempt =
        std::env::var(CiIdentityKey::RunAttempt.env_name()).unwrap_or_else(|_| "1".to_owned());
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
    let clock = SystemLocalClock;
    let run_started = clock.now();
    let context = LocalExecutionContext::new(root, &options.base)?;
    let entries = context.diff_entries()?;
    let impact = context
        .impact_entries(&entries)
        .context("ci local 影响分析失败；未自动执行 full，请修复分析输入或显式运行 make ci-full")?;
    let projected = local_steps(&impact);
    let steps = if projected.iter().any(|step| {
        matches!(
            step,
            LocalStep::Packages {
                operation: LocalCargoOperation::Test | LocalCargoOperation::Clippy,
                ..
            }
        )
    }) {
        expand_local_cargo_targets(projected, &WorkspaceGraph::load(context.root())?)
    } else {
        projected
    };
    let steps = select_local_steps(steps, &options.only)?;
    let mut ledger = crate::local_run_ledger::LocalRunLedger::for_worktree(root)?;
    if options.fresh {
        ledger
            .as_mut()
            .context("ci local --fresh 需要有分支的 worktree")?
            .fresh()?;
    }
    if steps.is_empty() {
        eprintln!("ci local：<base>...HEAD 无需执行本地步骤");
        return Ok(());
    }
    if options.only.is_empty() {
        eprintln!(
            "ci local：{} 步，由外层 supervisor 约束 wall-clock 预算",
            steps.len()
        );
    } else {
        eprintln!(
            "ci local partial：{} 步；仅供诊断，不代表完整 affected CI 通过",
            steps.len()
        );
    }
    let execution_policy = crate::cmd::ExecutionPolicy::from_fail_fast(options.fail_fast);
    let mut index = 0;
    execute_local_steps(&steps, execution_policy, |step| {
        index += 1;
        eprintln!("ci local：[{}/{}] {}", index, steps.len(), step.label());
        if let Some(unit) = step.checkpoint_key()
            && ledger.as_ref().is_some_and(|ledger| ledger.contains(&unit))
        {
            eprintln!(
                "ci local：[{}/{}] checkpoint 已通过，跳过",
                index,
                steps.len()
            );
            return Ok(());
        }
        let step_started = clock.now();
        let result = run_local_step(&context, step, execution_policy, ledger.as_ref());
        let result = finalize_local_step_result(step, ledger.as_mut(), result);
        let step_elapsed = clock.elapsed(step_started, clock.now()).as_secs_f64();
        match result {
            Ok(()) => {
                eprintln!(
                    "ci local：[{}/{}] 通过，耗时 {:.1} 秒",
                    index,
                    steps.len(),
                    step_elapsed
                );
                Ok(())
            }
            Err(error) => {
                eprintln!(
                    "ci local：[{}/{}] 失败，步骤耗时 {:.1} 秒，总耗时 {:.1} 秒",
                    index,
                    steps.len(),
                    step_elapsed,
                    clock.elapsed(run_started, clock.now()).as_secs_f64()
                );
                Err(error.context(format!("步骤耗时 {step_elapsed:.1} 秒")))
            }
        }
    })?;
    if options.only.is_empty() {
        eprintln!(
            "ci local：全部通过，总耗时 {:.1} 秒",
            clock.elapsed(run_started, clock.now()).as_secs_f64()
        );
    } else {
        eprintln!(
            "ci local partial：所选 stage 通过，总耗时 {:.1} 秒；不代表完整 affected CI 通过",
            clock.elapsed(run_started, clock.now()).as_secs_f64()
        );
    }
    Ok(())
}

fn finalize_local_step_result(
    step: &LocalStep,
    ledger: Option<&mut crate::local_run_ledger::LocalRunLedger>,
    result: Result<()>,
) -> Result<()> {
    let mut ledger = ledger;
    if matches!(step, LocalStep::Meta(_))
        && let Some(ledger) = ledger.as_deref_mut()
    {
        // The detached verify child records individual gates through its own handle.
        ledger.refresh();
    }
    if result.is_ok()
        && let Some(unit) = step.checkpoint_key()
        && let Some(ledger) = ledger
    {
        ledger.mark_passed(unit);
    }
    result
}

fn execute_local_steps(
    steps: &[LocalStep],
    execution_policy: crate::cmd::ExecutionPolicy,
    mut execute: impl FnMut(&LocalStep) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    for step in steps {
        if let Err(error) = execute(step) {
            if !execution_policy.keeps_going() {
                return Err(error);
            }
            failures.push((step.label(), format!("{error:#}")));
        }
    }
    if !failures.is_empty() {
        eprintln!("ci local：失败汇总（{} 项）", failures.len());
        for (label, error) in &failures {
            eprintln!("- {label}：{error}");
        }
        bail!("ci local：{} 个步骤失败", failures.len());
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
    cargo_target: PathBuf,
    snapshot: CommittedSnapshot,
}

impl LocalExecutionContext {
    fn new(repository: &Path, base: &str) -> Result<Self> {
        let base = resolve_commit(repository, base)?;
        let head = resolve_commit(repository, "HEAD")?;
        let merge_base = git_stdout(repository, ["merge-base", base.as_str(), head.as_str()])?;
        let merge_base = merge_base.trim();
        validate_revision(merge_base, "local merge-base revision")?;
        let cargo_target =
            snapshot_target_dir(repository, std::env::var_os("CARGO_TARGET_DIR").as_deref())?;
        let snapshot_cache = snapshot_cache_dir(repository, &cargo_target)?;
        let snapshot = CommittedSnapshot::checkout(repository, &head, &snapshot_cache)?;
        Ok(Self {
            base,
            head,
            merge_base: merge_base.to_owned(),
            cargo_target,
            snapshot,
        })
    }

    fn root(&self) -> &Path {
        self.snapshot.root()
    }

    fn cargo_target_text(&self) -> Result<&str> {
        self.cargo_target
            .to_str()
            .context("local snapshot Cargo target path is not valid UTF-8")
    }

    fn diff_entries(&self) -> Result<Vec<DiffEntry>> {
        read_diff(self.root(), &self.base, &self.head)
    }

    #[cfg(test)]
    fn impact(&self) -> Result<ImpactSet> {
        let entries = self.diff_entries()?;
        self.impact_entries(&entries)
    }

    fn impact_entries(&self, entries: &[DiffEntry]) -> Result<ImpactSet> {
        if entries.is_empty() {
            return Ok(ImpactSet::Empty);
        }
        if let Some(cause) = immediate_full_cause(entries, None) {
            return Ok(ImpactSet::Full(cause));
        }
        if entries.iter().all(|entry| documentation(&entry.path)) {
            return Ok(impact_entries(
                entries,
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            ));
        }
        let graph = WorkspaceGraph::load(self.root())?;
        impact_with_graph(self.root(), entries, &graph, &self.merge_base)
    }

    #[cfg(test)]
    fn impact_or_full(&self) -> ImpactSet {
        self.impact().unwrap_or_else(|error| {
            eprintln!("ci local：影响分析失败，fail-safe 到完整 verify：{error:#}");
            ImpactSet::Full(FullCause::FallbackUncertainty)
        })
    }
}

fn snapshot_target_dir(repository: &Path, ambient: Option<&OsStr>) -> Result<PathBuf> {
    let base = if let Some(ambient) = ambient {
        let ambient = PathBuf::from(ambient);
        if ambient.is_absolute() {
            ambient
        } else {
            repository.join(ambient)
        }
    } else {
        let repository_text = repository
            .to_str()
            .context("workspace path is not valid UTF-8")?;
        std::env::temp_dir()
            .join("rss-ci-local-targets")
            .join(sha256(repository_text.as_bytes()))
    };
    Ok(base.join(LOCAL_SNAPSHOT_TARGET_SUFFIX))
}

fn snapshot_cache_dir(repository: &Path, cargo_target: &Path) -> Result<PathBuf> {
    let repository_text = repository
        .to_str()
        .context("workspace path is not valid UTF-8")?;
    let target_root = cargo_target
        .parent()
        .context("local snapshot Cargo target has no parent directory")?;
    Ok(target_root
        .join("ci-local-sources")
        .join(sha256(repository_text.as_bytes())))
}

fn ensure_private_cache_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("create committed CI snapshot cache")?;
    let metadata = fs::symlink_metadata(path).context("inspect committed CI snapshot cache")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("committed CI snapshot cache must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .context("set committed CI snapshot cache permissions")?;
    }
    Ok(())
}

static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// An isolated checkout of one committed revision. Local impact classification must not read
/// manifests, contract metadata, generated files, or package topology from the caller's dirty
/// working tree after the diff revisions have been resolved.
struct CommittedSnapshot {
    scratch: PathBuf,
    root: PathBuf,
    persistent: bool,
}

impl CommittedSnapshot {
    fn checkout(repository: &Path, revision: &str, cache_root: &Path) -> Result<Self> {
        let repository_text = repository
            .to_str()
            .context("workspace path is not valid UTF-8")?;
        ensure_private_cache_dir(cache_root)?;
        let scratch = cache_root.join(revision);
        if scratch.exists() {
            return Self::open_cached(scratch, revision);
        }

        let counter = SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary =
            cache_root.join(format!(".{revision}.tmp-{}-{counter}", std::process::id()));
        fs::create_dir(&temporary).context("create committed CI snapshot staging directory")?;
        let root = temporary.join("tree");
        let root_text = root
            .to_str()
            .context("snapshot path is not valid UTF-8")?
            .to_owned();
        let snapshot = Self {
            scratch: temporary,
            root,
            persistent: false,
        };
        let clone = external_cmd(
            ExternalProgram::SystemGit,
            &[
                "clone",
                "--quiet",
                "--shared",
                "--no-checkout",
                "--",
                repository_text,
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
        match fs::rename(&snapshot.scratch, &scratch) {
            Ok(()) => Self::open_cached(scratch, revision),
            Err(_) if scratch.exists() => Self::open_cached(scratch, revision),
            Err(error) => Err(error).context("publish committed CI snapshot cache"),
        }
    }

    fn open_cached(scratch: PathBuf, revision: &str) -> Result<Self> {
        let scratch_metadata = fs::symlink_metadata(&scratch)
            .context("inspect committed CI snapshot revision cache")?;
        if scratch_metadata.file_type().is_symlink() || !scratch_metadata.is_dir() {
            bail!("committed CI snapshot revision cache must be a real directory");
        }
        let root = scratch.join("tree");
        let root_metadata =
            fs::symlink_metadata(&root).context("inspect committed CI snapshot checkout")?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            bail!("committed CI snapshot checkout must be a real directory");
        }
        let observed = git_stdout(&root, ["rev-parse", "--verify", "HEAD"])?;
        if observed.trim() != revision {
            bail!(
                "committed CI snapshot cache revision mismatch; remove the local Cargo snapshot cache and retry"
            );
        }
        git_stdout(&root, ["clean", "-ffdx", "--"])?;
        let dirty = git_stdout(&root, ["status", "--porcelain", "--untracked-files=all"])?;
        if !dirty.is_empty() {
            bail!(
                "committed CI snapshot cache is dirty; remove the local Cargo snapshot cache and retry"
            );
        }
        let root = fs::canonicalize(root).context("canonicalize committed CI snapshot root")?;
        Ok(Self {
            scratch,
            root,
            persistent: true,
        })
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for CommittedSnapshot {
    fn drop(&mut self) {
        if !self.persistent {
            let _ = fs::remove_dir_all(&self.scratch);
        }
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
    const fn stage(&self) -> LocalStage {
        match self {
            Self::Meta(_) => LocalStage::Meta,
            Self::PythonHooks => LocalStage::PythonHooks,
            Self::CargoWrapperSelftest => LocalStage::CargoWrapperSelftest,
            Self::Packages { operation, .. } => match operation {
                LocalCargoOperation::Check => LocalStage::Check,
                LocalCargoOperation::Test => LocalStage::Test,
                LocalCargoOperation::Clippy => LocalStage::Clippy,
            },
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Meta(gates) => format!("meta（{} gates）", gates.len()),
            Self::PythonHooks => "python hook tests".to_owned(),
            Self::CargoWrapperSelftest => "cargo wrapper selftest".to_owned(),
            Self::Packages {
                operation,
                packages,
                target,
                ..
            } => target.as_ref().map_or_else(
                || format!("{} {}", operation.label(), packages.join(",")),
                |target| {
                    format!(
                        "{} {} {}",
                        operation.label(),
                        packages.join(","),
                        target.checkpoint_label()
                    )
                },
            ),
        }
    }

    fn checkpoint_key(&self) -> Option<String> {
        match self {
            Self::Meta(_) => None,
            Self::PythonHooks => Some("stage:python-hooks".to_owned()),
            Self::CargoWrapperSelftest => Some("stage:cargo-wrapper-selftest".to_owned()),
            Self::Packages {
                operation,
                packages,
                target,
                check_includes_lib,
            } => Some(format!(
                "stage:{}:lib={}:{}:{}",
                operation.stage_name(),
                check_includes_lib,
                packages.join(","),
                target
                    .as_ref()
                    .map_or_else(|| "package".to_owned(), LocalCargoTarget::checkpoint_label)
            )),
        }
    }
}

fn select_local_steps(
    steps: Vec<LocalStep>,
    only: &BTreeSet<LocalStage>,
) -> Result<Vec<LocalStep>> {
    if only.is_empty() {
        return Ok(steps);
    }
    for stage in only {
        if !steps.iter().any(|step| step.stage() == *stage) {
            bail!(
                "ci local --only stage 不属于当前 affected plan: {}",
                stage.as_str()
            );
        }
    }
    Ok(steps
        .into_iter()
        .filter(|step| only.contains(&step.stage()))
        .collect())
}

fn expand_local_cargo_targets(steps: Vec<LocalStep>, graph: &WorkspaceGraph) -> Vec<LocalStep> {
    steps
        .into_iter()
        .flat_map(|step| match step {
            LocalStep::Packages {
                operation,
                packages,
                target: None,
                check_includes_lib,
            } if matches!(
                operation,
                LocalCargoOperation::Test | LocalCargoOperation::Clippy
            ) =>
            {
                packages
                    .into_iter()
                    .flat_map(|package| {
                        graph
                            .local_cargo_targets(&package, operation)
                            .into_iter()
                            .map(move |target| LocalStep::Packages {
                                operation,
                                packages: vec![package.clone()],
                                target: Some(target),
                                check_includes_lib,
                            })
                    })
                    .collect::<Vec<_>>()
            }
            other => vec![other],
        })
        .collect()
}

impl LocalCargoOperation {
    const fn stage_name(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Test => "test",
            Self::Clippy => "clippy",
        }
    }

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

fn run_local_step(
    context: &LocalExecutionContext,
    step: &LocalStep,
    execution_policy: crate::cmd::ExecutionPolicy,
    ledger: Option<&crate::local_run_ledger::LocalRunLedger>,
) -> Result<()> {
    match step {
        LocalStep::Meta(gates) => run_snapshot_verify(context, gates, execution_policy, ledger),
        LocalStep::PythonHooks => {
            let status = external_cmd(
                ExternalProgram::SystemPython,
                &[
                    "-B",
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    ".codex/hooks",
                    "-p",
                    "test_*.py",
                ],
                &[],
                Some(context.root()),
            )
            .status()?;
            if !status.success() {
                bail!("ci local python hook tests failed");
            }
            Ok(())
        }
        LocalStep::CargoWrapperSelftest => {
            let status = external_cmd(
                ExternalProgram::SystemShell,
                &["hack/cargo.selftest.sh"],
                &[],
                Some(context.root()),
            )
            .status()?;
            if !status.success() {
                bail!("ci local cargo wrapper selftest failed");
            }
            Ok(())
        }
        LocalStep::Packages {
            operation,
            packages,
            target,
            check_includes_lib,
        } => run_package_operation(
            context.root(),
            context.cargo_target_text()?,
            *operation,
            packages,
            target.as_ref(),
            *check_includes_lib,
            execution_policy,
        ),
    }
}

fn run_snapshot_verify(
    context: &LocalExecutionContext,
    gates: &[GateId],
    execution_policy: crate::cmd::ExecutionPolicy,
    ledger: Option<&crate::local_run_ledger::LocalRunLedger>,
) -> Result<()> {
    let mut args = vec!["verify"];
    for gate in gates {
        args.extend(["--only", gate.spec().label()]);
    }
    if !execution_policy.keeps_going() {
        args.push("--fail-fast");
    }
    args.extend(["--against", context.merge_base.as_str()]);
    let target = context.cargo_target_text()?;
    let environment = snapshot_verify_environment(context, target, ledger);
    let status = cargo_cmd(
        CargoSubcommand::Xtask,
        &args,
        &environment,
        Some(context.root()),
    )
    .status()?;
    if !status.success() {
        bail!("ci local snapshot verify failed");
    }
    Ok(())
}

fn snapshot_verify_environment<'a>(
    context: &'a LocalExecutionContext,
    cargo_target: &'a str,
    ledger: Option<&'a crate::local_run_ledger::LocalRunLedger>,
) -> Vec<(&'static str, &'a str)> {
    let mut environment = vec![
        ("CARGO_TARGET_DIR", cargo_target),
        (
            crate::runtime_root_guard::BASE_ENV,
            context.merge_base.as_str(),
        ),
    ];
    if let Some(ledger) = ledger {
        environment.push((crate::local_run_ledger::PATH_ENV, ledger.path_text()));
        environment.push((crate::local_run_ledger::BRANCH_ENV, ledger.branch()));
    }
    environment
}

fn run_package_operation(
    root: &Path,
    cargo_target: &str,
    operation: LocalCargoOperation,
    packages: &[String],
    target: Option<&LocalCargoTarget>,
    check_includes_lib: bool,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    let owned = package_operation_args(
        operation,
        packages,
        target,
        check_includes_lib,
        execution_policy,
    )?;
    let args = owned.iter().map(String::as_str).collect::<Vec<_>>();
    let status = cargo_cmd(
        operation.subcommand(),
        &args,
        &[("CARGO_TARGET_DIR", cargo_target)],
        Some(root),
    )
    .status()?;
    if !status.success() {
        bail!("ci local {} failed", operation.label());
    }
    Ok(())
}

fn package_operation_args(
    operation: LocalCargoOperation,
    packages: &[String],
    target: Option<&LocalCargoTarget>,
    check_includes_lib: bool,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<Vec<String>> {
    if packages.is_empty() {
        bail!("ci local selective operation has an empty package set");
    }
    let mut owned = vec!["--locked".to_owned()];
    // Check uses lib+bins only: `--all-targets` plus multi-package reverse closure can
    // activate `testkit`'s `containers` cfg without linking optional deps (feature-unification
    // interaction with integration-gated test targets). Clippy keeps `--all-targets` for lint
    // coverage; integration feature matrices are outside the local preflight plan.
    // Bin-only reverse closures (e.g. xtask alone) must omit `--lib` — cargo rejects
    // `--lib` when no selected package has a library target.
    match (operation, target) {
        (LocalCargoOperation::Check, Some(_)) => bail!("check local step cannot select a target"),
        (LocalCargoOperation::Test | LocalCargoOperation::Clippy, Some(LocalCargoTarget::Lib)) => {
            owned.push("--lib".to_owned())
        }
        (
            LocalCargoOperation::Test | LocalCargoOperation::Clippy,
            Some(LocalCargoTarget::Bin(name)),
        ) => {
            owned.extend(["--bin".to_owned(), name.clone()]);
        }
        (
            LocalCargoOperation::Test | LocalCargoOperation::Clippy,
            Some(LocalCargoTarget::Test(name)),
        ) => {
            owned.extend(["--test".to_owned(), name.clone()]);
        }
        (LocalCargoOperation::Test, Some(LocalCargoTarget::Doc)) => {
            owned.push("--doc".to_owned());
        }
        (LocalCargoOperation::Clippy, Some(LocalCargoTarget::Doc)) => {
            bail!("clippy local target cannot be doc")
        }
        (LocalCargoOperation::Check, None) if check_includes_lib => {
            owned.push("--lib".to_owned());
            owned.push("--bins".to_owned());
        }
        (LocalCargoOperation::Check, None) => {
            owned.push("--bins".to_owned());
        }
        (LocalCargoOperation::Clippy, None) => owned.push("--all-targets".to_owned()),
        (LocalCargoOperation::Test, None) => {}
    }
    for package in packages {
        owned.push("-p".to_owned());
        owned.push(package.clone());
    }
    if execution_policy.keeps_going() {
        owned.push(
            match operation {
                LocalCargoOperation::Check | LocalCargoOperation::Clippy => "--keep-going",
                LocalCargoOperation::Test => "--no-fail-fast",
            }
            .to_owned(),
        );
    }
    if operation == LocalCargoOperation::Clippy {
        owned.extend(["--".to_owned(), "-D".to_owned(), "warnings".to_owned()]);
    }
    Ok(owned)
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
    let mut governance = BTreeSet::new();
    let mut local_meta_domains = BTreeSet::new();
    let mut unknown_paths = BTreeSet::new();
    for entry in entries {
        documentation_only |= classify_selective_entry(
            entry,
            graph,
            &mut packages,
            &mut governance,
            &mut local_meta_domains,
            &mut unknown_paths,
        );
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
    let packages_with_tests = match graph {
        Some(graph) => graph.test_capable_packages(),
        None => packages
            .keys()
            .cloned()
            .chain(closure.iter().cloned())
            .collect(),
    };
    let check_includes_lib = match graph {
        Some(graph) => closure.iter().any(|name| graph.has_lib_target(name)),
        // Without metadata, preserve historical `--lib --bins` (fail closed on unknown).
        None => true,
    };
    let coverage_closure = coverage_closure_for(graph, &packages, closure);
    ImpactSet::Selective(SelectiveImpact {
        documentation: documentation_only,
        packages,
        reverse_closure: closure.clone(),
        coverage_closure,
        packages_with_tests,
        check_includes_lib,
        integration_shards: selected_shards,
        governance,
        local_meta_domains,
        unknown_paths,
    })
}

fn classify_selective_entry(
    entry: &DiffEntry,
    graph: Option<&WorkspaceGraph>,
    packages: &mut BTreeMap<String, BTreeSet<PackageImpact>>,
    governance: &mut BTreeSet<GovernanceImpact>,
    local_meta_domains: &mut BTreeSet<LocalImpactDomain>,
    unknown_paths: &mut BTreeSet<String>,
) -> bool {
    let path = entry.path.as_str();
    local_meta_domains.extend(local_impact_domains(path));
    if let Some(impact) = governance_impact(path) {
        governance.insert(impact);
        return true;
    }
    if documentation(path) {
        return true;
    }
    if path.starts_with("contracts/") {
        if graph.is_none() {
            packages
                .entry("contract-owner".to_owned())
                .or_default()
                .insert(PackageImpact::ContractOwner);
        }
        return false;
    }
    if path.starts_with("generated/src/") {
        if graph.is_none() {
            packages
                .entry("generated-domain".to_owned())
                .or_default()
                .insert(PackageImpact::Generated);
        }
        return false;
    }
    let package = match graph {
        Some(graph) => graph.package_for_path(path).map(str::to_owned),
        None => path_package(path),
    };
    let Some(package) = package else {
        unknown_paths.insert(path.to_owned());
        return false;
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
    false
}

fn local_impact_domains(path: &str) -> BTreeSet<LocalImpactDomain> {
    use LocalImpactDomain as Domain;

    const SHARED_POLICY_PATHS: &[&str] = &[
        "xtask/src/ci_lanes.rs",
        "xtask/src/ci_impact.rs",
        "xtask/src/verify.rs",
        "xtask/src/main.rs",
        "xtask/src/contract/governance.rs",
        "xtask/src/contract/source_funnel.rs",
        "xtask/src/assembly_governance.rs",
    ];
    // Root set used by scanners which discover production crates through workspace.members.
    // Keep this catalog here, next to the domain policy: scanner-specific subsets below must be
    // projections of this set instead of independently drifting copies.
    const WORKSPACE_MEMBER_PREFIXES: &[&str] = &[
        "adapters/",
        "assemblies/",
        "bins/",
        "composition/",
        "crates/",
        "examples/",
        "generated/",
        "journeys/",
        "journeys-fault-matrix/",
    ];
    const RUNTIME_PREFIXES: &[&str] = &[
        "assemblies/runtime/",
        "composition/eventing/",
        "crates/consistency/",
        "crates/eventexec/",
        "crates/runtimeexec/",
        "adapters/amqp/",
        "adapters/mqtt/",
        "adapters/postgres/",
        "contracts/event/",
        "generated/src/event/",
    ];
    const RUNTIME_CARRIERS: &[&str] = &[
        "xtask/src/runtime_root_guard.rs",
        "xtask/src/runtime_env_guard.rs",
        "xtask/src/runtime_deps_guard.rs",
        "xtask/src/event_transport_guard.rs",
        "xtask/src/dlx_lifecycle_funnel.rs",
        "xtask/src/inbox_cutover_guard.rs",
        "xtask/src/outbox_same_id_guard.rs",
        "xtask/src/reconcile_outbox_command_guard.rs",
        "xtask/runtime-root-ratchet.toml",
        "xtask/runtime-deps-guard.toml",
    ];
    const EVENT_TRANSPORT_SCAN_PREFIXES: &[&str] =
        &["crates/", "adapters/", "assemblies/", "bins/", "journeys/"];
    const RUNTIME_DOC_PREFIXES: &[&str] = &["docs/rules/"];
    const OUTBOX_SAME_ID_CARRIER_PREFIXES: &[&str] = &[
        "lints/rss_dlq_operator_callsite/",
        "docs/ops/outbox-relay-alerts.",
    ];
    const ASSEMBLY_PREFIXES: &[&str] = &[
        "assemblies/",
        "generated/",
        "contracts/",
        "crates/assembly-schema/",
        "deploy/",
        "journeys/",
        "journeys-fault-matrix/",
        "docs/architecture/generated/runtime-assembly",
    ];
    const ASSEMBLY_CARRIERS: &[&str] = &[
        "xtask/src/assembly_artifacts.rs",
        "xtask/src/assembly_codegen.rs",
        "xtask/src/assembly_lock.rs",
        "xtask/src/assembly_runtime_plan.rs",
        "xtask/src/graph.rs",
        ".gitattributes",
        "Dockerfile",
    ];
    const CONSISTENCY_PREFIXES: &[&str] = &[
        "crates/consistency/",
        "contracts/",
        "generated/",
        "journeys/",
        "journeys-fault-matrix/",
        "fixtures/",
    ];
    const CONSISTENCY_CARRIERS: &[&str] = &[
        "xtask/src/consistency_fixtures.rs",
        "xtask/src/consistency_effects.rs",
        "xtask/src/localtx_coverage.rs",
    ];
    const CONSISTENCY_EXTRA_RUST_PREFIXES: &[&str] = &["lints/", "xtask/"];
    const TENANCY_PREFIXES: &[&str] = &[
        "adapters/postgres/",
        "adapters/postgres-migration/",
        "crates/postgres-migration-inventory/",
        "crates/audit/",
        "crates/identity/",
        "crates/settings/",
        "composition/audit/",
        "composition/identity/",
        "composition/settings/",
        "examples/tenancy-consumer/",
    ];
    const TENANCY_CARRIERS: &[&str] = &[
        "xtask/src/schema_rls.rs",
        "xtask/src/setlocal_funnel.rs",
        "xtask/src/pg_tenant_tx_guard.rs",
        "xtask/src/repo_scope_guard.rs",
        "xtask/src/tenancy_closeout.rs",
        "xtask/src/migrations.rs",
        "Cargo.toml",
        "lints/Cargo.toml",
        "xtask/tests/tenancy_closeout_generated_specs.rs",
        "assemblies/runtime/tests/auth_e2e.rs",
    ];
    const TENANCY_GOVERNANCE_PREFIXES: &[&str] = &["lints/"];
    const CONTRACT_BINDING_PREFIXES: &[&str] = &[
        "contracts/",
        "generated/",
        "journeys/",
        "journeys-fault-matrix/",
    ];
    const PDP_RUST_PREFIXES: &[&str] = &["crates/", "assemblies/", "bins/"];
    const COMMAND_RUST_PREFIXES: &[&str] = &["crates/", "adapters/", "assemblies/", "bins/"];
    const COMMAND_PREFIXES: &[&str] =
        &["contracts/command/", "generated/src/command/", "journeys/"];

    if SHARED_POLICY_PATHS.contains(&path) {
        return Domain::ALL.into_iter().collect();
    }

    let mut domains = BTreeSet::new();
    let matches_any = |prefixes: &[&str]| prefixes.iter().any(|prefix| path.starts_with(prefix));
    let workspace_member_rust = path.ends_with(".rs") && matches_any(WORKSPACE_MEMBER_PREFIXES);
    let workspace_member_manifest =
        path.ends_with("Cargo.toml") && matches_any(WORKSPACE_MEMBER_PREFIXES);
    if matches_any(RUNTIME_PREFIXES)
        || RUNTIME_CARRIERS.contains(&path)
        || (path.ends_with(".rs") && matches_any(EVENT_TRANSPORT_SCAN_PREFIXES))
        // dlx-lifecycle-funnel discovers every shipped workspace member from root Cargo.toml.
        || workspace_member_rust
        || path == "Cargo.toml"
        || (path.ends_with(".toml") && path.starts_with("assemblies/"))
        || matches_any(RUNTIME_DOC_PREFIXES)
        || matches_any(OUTBOX_SAME_ID_CARRIER_PREFIXES)
    {
        domains.insert(Domain::RuntimeEventing);
    }
    if matches_any(ASSEMBLY_PREFIXES)
        || ASSEMBLY_CARRIERS.contains(&path)
        // Cargo enrollment and declared binary/journey targets are inputs to the shared IR and
        // artifact matrix. Source changes are covered by their declared carrier roots above.
        || path == "Cargo.toml"
        || workspace_member_manifest
    {
        domains.insert(Domain::AssemblyGeneration);
    }
    if matches_any(CONSISTENCY_PREFIXES)
        || CONSISTENCY_CARRIERS.contains(&path)
        || workspace_member_rust
        || (path.ends_with(".rs") && matches_any(CONSISTENCY_EXTRA_RUST_PREFIXES))
    {
        domains.insert(Domain::Consistency);
    }
    if matches_any(TENANCY_PREFIXES)
        || TENANCY_CARRIERS.contains(&path)
        || matches_any(TENANCY_GOVERNANCE_PREFIXES)
        // pg-tenant-tx-guard loads every root-workspace member's production Rust sources.
        || workspace_member_rust
        || (path.ends_with(".rs") && path.starts_with("xtask/src/"))
        || matches_any(&["contracts/", "generated/"])
    {
        domains.insert(Domain::TenancyPostgres);
    }
    if (path.ends_with(".rs") && matches_any(PDP_RUST_PREFIXES)) || path == "xtask/src/pdpallow.rs"
    {
        domains.insert(Domain::Pdp);
    }
    if matches_any(CONTRACT_BINDING_PREFIXES)
        || workspace_member_rust
        || workspace_member_manifest
        || path == "Cargo.toml"
        || path == "xtask/src/contract_binding_guard.rs"
    {
        domains.insert(Domain::ContractBinding);
    }
    if (path.ends_with(".rs") && matches_any(COMMAND_RUST_PREFIXES))
        || matches_any(COMMAND_PREFIXES)
        || path == "xtask/src/command_symmetry.rs"
    {
        domains.insert(Domain::CommandSymmetry);
    }
    domains
}

fn coverage_closure_for(
    graph: Option<&WorkspaceGraph>,
    packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
    closure: &BTreeSet<String>,
) -> BTreeSet<String> {
    let seeds = packages
        .iter()
        .filter(|(_, impacts)| impacts.iter().any(|impact| impact.is_coverage_seed()))
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    if seeds.is_empty() {
        return BTreeSet::new();
    }
    match graph {
        Some(graph) => graph.reverse_closure(&seeds),
        None => {
            let mut coverage_closure = closure.clone();
            coverage_closure.extend(seeds);
            coverage_closure
        }
    }
}

fn governance_impact(path: &str) -> Option<GovernanceImpact> {
    if path.starts_with(".codex/hooks/") {
        Some(GovernanceImpact::PythonHooks)
    } else if matches!(
        path,
        ".cargo/config.toml"
            | "hack/cargo.sh"
            | "hack/cargo.selftest.sh"
            | "hack/target-pool.py"
            | "hack/ci-local-supervisor.py"
            | "hack/tests/test_ci_local_supervisor.py"
            | "hack/tests/test_target_pool.py"
    ) {
        Some(GovernanceImpact::CargoWrapper)
    } else {
        None
    }
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
    crate::ci_entry_guard::CONTROLLED_PATHS.contains(&path)
        || DOCUMENTATION_PATHS.contains(&path)
        || DOCUMENTATION_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || matches!(path, "Makefile" | "CLAUDE.md")
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
        ["xtask", ..] => Some("xtask".to_owned()),
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
    let impact = crate::contract::governance::contract_impact_from_manifest(source)?;
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    packages
        .entry(impact.owner().to_owned())
        .or_default()
        .insert(PackageImpact::ContractOwner);
    for subscription in impact.subscribers() {
        packages
            .entry(subscription.clone())
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
    #[serde(default)]
    targets: Vec<MetadataTarget>,
}

#[derive(Debug, Deserialize)]
struct MetadataTarget {
    name: String,
    kind: Vec<String>,
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
    test_capable: BTreeSet<String>,
    lib_capable: BTreeSet<String>,
    local_cargo_targets: BTreeMap<String, Vec<LocalCargoTarget>>,
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
        let test_capable = wire
            .packages
            .iter()
            .filter(|package| wire.workspace_members.contains(&package.id))
            .filter(|package| {
                package.targets.iter().any(|target| {
                    target.kind.iter().any(|kind| {
                        matches!(
                            kind.as_str(),
                            "lib" | "bin" | "test" | "bench" | "proc-macro"
                        )
                    })
                })
            })
            .map(|package| package.name.clone())
            .collect();
        let lib_capable = wire
            .packages
            .iter()
            .filter(|package| wire.workspace_members.contains(&package.id))
            .filter(|package| {
                package.targets.iter().any(|target| {
                    target
                        .kind
                        .iter()
                        .any(|kind| matches!(kind.as_str(), "lib" | "proc-macro"))
                })
            })
            .map(|package| package.name.clone())
            .collect();
        let local_cargo_targets = wire
            .packages
            .iter()
            .filter(|package| wire.workspace_members.contains(&package.id))
            .map(|package| {
                let mut targets = BTreeSet::new();
                for target in &package.targets {
                    for kind in &target.kind {
                        match kind.as_str() {
                            "lib" | "proc-macro" => {
                                targets.insert(LocalCargoTarget::Lib);
                            }
                            "bin" => {
                                targets.insert(LocalCargoTarget::Bin(target.name.clone()));
                            }
                            "test"
                                if !crate::integration_shards::is_remote_only_test_target(
                                    &package.name,
                                    &target.name,
                                ) =>
                            {
                                targets.insert(LocalCargoTarget::Test(target.name.clone()));
                            }
                            _ => {}
                        }
                    }
                }
                (package.name.clone(), targets.into_iter().collect())
            })
            .collect();
        Ok(Self {
            package_paths,
            id_to_name,
            reverse,
            test_capable,
            lib_capable,
            local_cargo_targets,
        })
    }

    fn test_capable_packages(&self) -> BTreeSet<String> {
        self.test_capable.clone()
    }

    #[cfg(test)]
    fn has_test_targets(&self, package: &str) -> bool {
        self.test_capable.contains(package)
    }

    fn has_lib_target(&self, package: &str) -> bool {
        self.lib_capable.contains(package)
    }

    fn local_cargo_targets(
        &self,
        package: &str,
        operation: LocalCargoOperation,
    ) -> Vec<LocalCargoTarget> {
        let mut targets = self
            .local_cargo_targets
            .get(package)
            .cloned()
            .unwrap_or_default();
        if operation == LocalCargoOperation::Test && targets.contains(&LocalCargoTarget::Lib) {
            targets.push(LocalCargoTarget::Doc);
        }
        targets
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
        catalog.push(format!(
            "job-required-evidence={}:{}",
            key.as_str(),
            key.required_evidence()
                .map_or("", |evidence| evidence.as_str())
        ));
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
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct PathCaseGolden {
        status: String,
        path: String,
        expected: PathExpectationGolden,
    }

    #[derive(Debug, Deserialize)]
    #[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
    enum PathExpectationGolden {
        Selective { jobs: Vec<String> },
        Full { cause: String },
    }

    fn parse_policy_golden(source: &str) -> Result<PolicyGolden> {
        let golden: PolicyGolden =
            serde_json::from_str(source).context("parse CI impact policy golden")?;
        if golden.path_cases.is_empty() {
            bail!("CI impact policy golden pathCases must be non-empty");
        }
        Ok(golden)
    }

    fn policy_golden() -> Result<PolicyGolden> {
        parse_policy_golden(POLICY_BEHAVIOR_SPEC)
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

    fn rust_consumed_machine_inputs(root: &Path) -> Result<BTreeSet<String>> {
        struct IncludeVisitor<'a> {
            root: &'a Path,
            source: &'a Path,
            inputs: BTreeSet<String>,
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
                                Ok(relative)
                                    if relative.starts_with("docs")
                                        || relative
                                            .starts_with("crates/assembly-schema/schemas")
                                        || relative
                                            == Path::new(
                                                "crates/assembly-schema/tests/fixtures/fingerprint-v2-vectors.json",
                                            ) =>
                                {
                                    self.inputs
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
        let mut inputs = BTreeSet::new();
        let mut errors = Vec::new();
        for source in rust_sources(&canonical_root)? {
            let text = fs::read_to_string(&source)
                .with_context(|| format!("read Rust source {}", source.display()))?;
            let mut visitor = IncludeVisitor {
                root: &canonical_root,
                source: &source,
                inputs: BTreeSet::new(),
                errors: Vec::new(),
            };
            match syn::parse_file(&text) {
                Ok(syntax) => visitor.visit_file(&syntax),
                Err(file_error) => match syn::parse_str::<syn::Expr>(&text) {
                    Ok(syntax) => visitor.visit_expr(&syntax),
                    Err(expression_error) => bail!(
                        "parse Rust source {} as file or expression: file: {file_error}; expression: {expression_error}",
                        source.display()
                    ),
                },
            }
            inputs.append(&mut visitor.inputs);
            errors.append(&mut visitor.errors);
        }
        if !errors.is_empty() {
            bail!("invalid machine input includes: {}", errors.join("; "));
        }
        Ok(inputs)
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
                fail_fast: false,
                fresh: false,
                only: BTreeSet::new(),
            }
        );
        assert_eq!(
            parse_local_options(&[
                "--base",
                "origin/develop",
                "--fail-fast",
                "--fresh",
                "--only",
                "meta",
                "--only",
                "clippy",
            ])?,
            LocalOptions {
                base: "origin/develop".to_owned(),
                fail_fast: true,
                fresh: true,
                only: BTreeSet::from([LocalStage::Meta, LocalStage::Clippy]),
            }
        );
        for args in [
            Vec::<&str>::new(),
            vec!["--base"],
            vec!["--base", "main", "--base", "develop"],
            vec!["--base", "--working-tree"],
            vec!["--head", "main"],
            vec!["main"],
            vec!["--base", "main", "--only"],
            vec!["--base", "main", "--only", "--fail-fast"],
            vec!["--base", "main", "--only", "unknown"],
            vec!["--base", "main", "--only", "test", "--only", "test"],
            vec!["--base", "main", "--fail-fast", "--fail-fast"],
            vec!["--base", "main", "--fresh", "--fresh"],
            vec!["--base", "main", "--only", "fast-meta"],
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
            vec!["ci-meta", "ci-local-only", "integration/postgres-domain"]
        );

        let docs = impact_entries(
            &[DiffEntry::modified("docs/ops/example.md")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            LocalProjection::from(&docs),
            LocalProjection::Meta(local_meta_gates(None))
        );

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
                meta_gates: local_meta_gates(Some(&BTreeSet::from([
                    LocalImpactDomain::RuntimeEventing,
                    LocalImpactDomain::Consistency,
                    LocalImpactDomain::TenancyPostgres,
                    LocalImpactDomain::Pdp,
                    LocalImpactDomain::ContractBinding,
                    LocalImpactDomain::CommandSymmetry,
                ]))),
                check_packages: vec!["consumer".to_owned(), "leaf".to_owned()],
                check_includes_lib: true,
                test_clippy_packages: vec!["leaf".to_owned()],
                governance: BTreeSet::new(),
            }
        );
        assert!(
            RemoteProjection::from(&selective)
                .selected_names()
                .contains(&"ci-core-tests/1-of-2")
        );

        let full = impact_entries(
            &[DiffEntry::modified(".gitattributes")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            LocalProjection::from(&full),
            LocalProjection::Meta(all_local_meta_gates())
        );
        assert_eq!(
            RemoteProjection::from(&full).selected_names().len(),
            CiJobKey::COUNT
        );
    }

    #[test]
    fn coverage_projection_table_covers_seeds_consumers_and_exclusions() {
        // label, package impacts, coverage_closure, packages_with_tests, expected packages, expected strict
        // Empty expected_packages ⇒ CoverageDecision::Skip.
        type CoverageCase<'a> = (
            &'a str,
            &'a [(&'a str, &'a [PackageImpact])],
            &'a [&'a str],
            &'a [&'a str],
            &'a [&'a str],
            &'a [&'a str],
        );
        let cases: &[CoverageCase<'_>] = &[
            (
                "source-seed-with-consumer",
                &[("leaf", &[PackageImpact::Source])],
                &["leaf", "consumer"],
                &["leaf", "consumer"],
                &["consumer", "leaf"],
                &[],
            ),
            (
                "test-only-not-seed",
                &[("leaf", &[PackageImpact::Test])],
                &[],
                &["leaf", "consumer"],
                &[],
                &[],
            ),
            (
                "manifest-only-not-seed",
                &[("leaf", &[PackageImpact::Manifest])],
                &[],
                &["leaf"],
                &[],
                &[],
            ),
            (
                "consumer-without-tests-filtered",
                &[("leaf", &[PackageImpact::Source])],
                &["leaf", "consumer"],
                &["leaf"],
                &["leaf"],
                &[],
            ),
            (
                "strict-touched",
                &[("vocab", &[PackageImpact::Source])],
                &["vocab"],
                &["vocab"],
                &["vocab"],
                &["vocab"],
            ),
            (
                "contract-owner-seed",
                &[("owner", &[PackageImpact::ContractOwner])],
                &["owner", "runtime"],
                &["owner", "runtime"],
                &["owner", "runtime"],
                &[],
            ),
        ];
        for (
            label,
            package_impacts,
            coverage_closure,
            with_tests,
            expected_packages,
            expected_strict,
        ) in cases
        {
            let mut packages = BTreeMap::new();
            for (name, impacts) in *package_impacts {
                packages.insert(
                    (*name).to_owned(),
                    impacts.iter().copied().collect::<BTreeSet<_>>(),
                );
            }
            let impact = ImpactSet::Selective(SelectiveImpact {
                documentation: false,
                packages,
                reverse_closure: coverage_closure.iter().map(|s| (*s).to_owned()).collect(),
                coverage_closure: coverage_closure.iter().map(|s| (*s).to_owned()).collect(),
                packages_with_tests: with_tests.iter().map(|s| (*s).to_owned()).collect(),
                check_includes_lib: true,
                integration_shards: BTreeSet::new(),
                governance: BTreeSet::new(),
                local_meta_domains: BTreeSet::new(),
                unknown_paths: BTreeSet::new(),
            });
            match CoverageProjection::from(&impact).decision() {
                CoverageDecision::Skip => {
                    assert!(
                        expected_packages.is_empty(),
                        "{label}: unexpected Skip when packages expected"
                    );
                }
                CoverageDecision::Scope(CoverageScope::Packages {
                    packages,
                    strict_touched,
                }) => {
                    assert_eq!(
                        packages,
                        expected_packages
                            .iter()
                            .map(|s| (*s).to_owned())
                            .collect::<Vec<_>>(),
                        "{label} packages"
                    );
                    assert_eq!(
                        strict_touched,
                        expected_strict
                            .iter()
                            .map(|s| (*s).to_owned())
                            .collect::<Vec<_>>(),
                        "{label} strict_touched"
                    );
                }
                CoverageDecision::Scope(CoverageScope::Workspace { cause }) => {
                    assert_eq!(
                        "Packages/Skip",
                        format!("Workspace({cause:?})"),
                        "{label}: expected Packages/Skip"
                    );
                }
            }
        }

        let full = CoverageProjection::from(&ImpactSet::Full(FullCause::GlobalImpact)).decision();
        assert_eq!(
            full,
            CoverageDecision::Scope(CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::GlobalImpact
            })
        );
        assert_eq!(
            CoverageProjection::from(&ImpactSet::Empty).decision(),
            CoverageDecision::Skip
        );

        let mut unknown = BTreeMap::new();
        unknown.insert("leaf".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let unknown_impact = ImpactSet::Selective(SelectiveImpact {
            documentation: false,
            packages: unknown,
            reverse_closure: BTreeSet::from(["leaf".to_owned()]),
            coverage_closure: BTreeSet::from(["leaf".to_owned()]),
            packages_with_tests: BTreeSet::from(["leaf".to_owned()]),
            check_includes_lib: true,
            integration_shards: BTreeSet::new(),
            governance: BTreeSet::new(),
            local_meta_domains: BTreeSet::new(),
            unknown_paths: BTreeSet::from(["mystery/path.rs".to_owned()]),
        });
        assert_eq!(
            CoverageProjection::from(&unknown_impact).decision(),
            CoverageDecision::Scope(CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::UnknownPath
            })
        );
        assert!(CoverageScope::packages(Vec::new(), Vec::new()).is_none());
    }

    #[test]
    fn remote_skips_coverage_when_projection_is_skip() {
        // Source seed whose coverage_closure members all lack tests → Skip → no CiCoverage.
        let mut packages = BTreeMap::new();
        packages.insert("leaf".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let impact = ImpactSet::Selective(SelectiveImpact {
            documentation: false,
            packages,
            reverse_closure: BTreeSet::from(["leaf".to_owned()]),
            coverage_closure: BTreeSet::from(["leaf".to_owned()]),
            packages_with_tests: BTreeSet::new(),
            check_includes_lib: true,
            integration_shards: BTreeSet::new(),
            governance: BTreeSet::new(),
            local_meta_domains: BTreeSet::new(),
            unknown_paths: BTreeSet::new(),
        });
        assert_eq!(
            CoverageProjection::from(&impact).decision(),
            CoverageDecision::Skip
        );
        let names = RemoteProjection::from(&impact).selected_names();
        assert!(
            !names.contains(&"ci-coverage"),
            "Skip projection must not schedule ci-coverage: {names:?}"
        );
        assert!(
            names.iter().any(|name| name.starts_with("ci-core-tests")),
            "core tests still scheduled from Source: {names:?}"
        );
    }

    #[test]
    fn coverage_decision_skip_falls_back_to_workspace_for_forced_execution() {
        assert_eq!(
            CoverageProjection::from(&ImpactSet::Empty).into_scope_or_fallback(),
            CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::FallbackUncertainty
            }
        );
        assert_eq!(
            coverage_fallback_uncertainty(),
            CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::FallbackUncertainty
            }
        );
    }

    #[test]
    fn coverage_scope_for_typed_job_non_pr_defaults_to_mandatory_catalog() -> Result<()> {
        // Process-isolated: do not mutate env. Skip when already in PR event context.
        if std::env::var(CiIdentityKey::EventName.env_name()).as_deref() == Ok("pull_request") {
            return Ok(());
        }
        let Ok(scope) = coverage_scope_for_typed_job(Path::new(".")) else {
            bail!("non-PR scope must resolve");
        };
        assert_eq!(
            scope,
            CoverageScope::Workspace {
                cause: CoverageWorkspaceCause::MandatoryCatalog
            }
        );
        Ok(())
    }

    #[test]
    fn event_path_trust_requires_runner_temp_or_workspace_prefix() {
        let root = Path::new(".");
        // Absolute path outside workspace / without RUNNER_TEMP prefix is untrusted.
        assert!(!event_path_is_trusted(root, Path::new("/etc/passwd")));
        // Missing path cannot canonicalize → untrusted.
        assert!(!event_path_is_trusted(
            root,
            Path::new("/tmp/rss-coverage-event-missing.json")
        ));
    }

    #[test]
    fn coverage_scope_packages_constructor_rejects_empty() {
        assert!(CoverageScope::packages(Vec::new(), Vec::new()).is_none());
        assert!(CoverageScope::packages(vec!["leaf".to_owned()], Vec::new()).is_some());
    }

    #[test]
    fn local_unknown_paths_are_ignored_and_governance_paths_are_metadata_only() {
        let unknown = impact_entries(
            &[DiffEntry::modified("unowned/input.bin")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            LocalProjection::from(&unknown),
            LocalProjection::Meta(local_meta_gates(None))
        );

        let mixed = impact_entries(
            &[
                DiffEntry::modified("crates/leaf/src/lib.rs"),
                DiffEntry::modified("unowned/input.bin"),
            ],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            local_steps(&mixed)
                .iter()
                .map(LocalStep::label)
                .collect::<Vec<_>>(),
            vec![
                LocalStep::Meta(local_meta_gates(Some(&BTreeSet::from([
                    LocalImpactDomain::RuntimeEventing,
                    LocalImpactDomain::Consistency,
                    LocalImpactDomain::TenancyPostgres,
                    LocalImpactDomain::Pdp,
                    LocalImpactDomain::ContractBinding,
                    LocalImpactDomain::CommandSymmetry,
                ]))))
                .label(),
                "test direct packages leaf".to_owned(),
                "clippy direct packages leaf".to_owned(),
            ],
            "unknown paths must not erase known package checks"
        );
        assert_eq!(
            RemoteProjection::from(&mixed).selected_names().len(),
            CiJobKey::COUNT,
            "remote unknown handling remains fail-safe full"
        );

        for path in [
            ".github/workflows/ci.yml",
            "hack/automation/forge.sh",
            "docs/architecture/README.md",
            "Makefile",
            "CLAUDE.md",
        ] {
            let impact = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                LocalProjection::from(&impact),
                LocalProjection::Meta(local_meta_gates(None)),
                "{path} must not trigger local full CI"
            );
        }
        for path in ["docs/rules/architecture.md", "docs/rules/README.md"] {
            let impact = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                LocalProjection::from(&impact),
                LocalProjection::Meta(local_meta_gates(Some(&BTreeSet::from([
                    LocalImpactDomain::RuntimeEventing,
                ])))),
                "{path} is a real dlx-lifecycle scanner input"
            );
        }

        let xtask_entries = [DiffEntry::modified("xtask/src/ci_impact.rs")];
        let xtask_impact = impact_entries(&xtask_entries, None, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            local_steps(&xtask_impact)
                .iter()
                .map(LocalStep::label)
                .collect::<Vec<_>>(),
            vec![
                LocalStep::Meta(all_local_meta_gates()).label(),
                "test direct packages xtask".to_owned(),
                "clippy direct packages xtask".to_owned(),
            ]
        );

        let always_meta = LocalStep::Meta(local_meta_gates(None)).label();
        for (path, expected) in [
            (
                ".codex/hooks/test_guard.py",
                vec![always_meta.clone(), "python hook tests".to_owned()],
            ),
            (
                "hack/cargo.sh",
                vec![always_meta.clone(), "cargo wrapper selftest".to_owned()],
            ),
            (
                "hack/target-pool.py",
                vec![always_meta.clone(), "cargo wrapper selftest".to_owned()],
            ),
            (
                "hack/ci-local-supervisor.py",
                vec![always_meta.clone(), "cargo wrapper selftest".to_owned()],
            ),
            (
                "hack/tests/test_ci_local_supervisor.py",
                vec![always_meta.clone(), "cargo wrapper selftest".to_owned()],
            ),
            (
                "hack/tests/test_target_pool.py",
                vec![always_meta.clone(), "cargo wrapper selftest".to_owned()],
            ),
        ] {
            let entries = [DiffEntry::modified(path)];
            let impact = impact_entries(&entries, None, &BTreeSet::new(), &BTreeMap::new());
            assert_eq!(
                local_steps(&impact)
                    .iter()
                    .map(LocalStep::label)
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn local_impact_domains_are_closed_and_shared_policy_selects_all() {
        use LocalImpactDomain as Domain;

        for (path, expected) in [
            (
                "contracts/event/identity/v1/demo/contract.toml",
                Domain::RuntimeEventing,
            ),
            (
                "assemblies/runtime/assembly.toml",
                Domain::AssemblyGeneration,
            ),
            ("journeys/status-board.toml", Domain::Consistency),
            (
                "adapters/postgres/migrations/0001.sql",
                Domain::TenancyPostgres,
            ),
            ("crates/vocab/src/lib.rs", Domain::Pdp),
            (
                "contracts/http/identity/v1/demo/contract.toml",
                Domain::ContractBinding,
            ),
            (
                "generated/src/command/identity_v1.rs",
                Domain::CommandSymmetry,
            ),
            ("crates/bootstrap/src/shutdown.rs", Domain::RuntimeEventing),
            ("composition/identity/src/lib.rs", Domain::Consistency),
            ("lints/src/lib.rs", Domain::TenancyPostgres),
            ("lints/Cargo.toml", Domain::TenancyPostgres),
            (
                "xtask/tests/tenancy_closeout_generated_specs.rs",
                Domain::TenancyPostgres,
            ),
        ] {
            assert!(
                local_impact_domains(path).contains(&expected),
                "{path} must select {expected:?}"
            );
        }
        assert!(local_impact_domains("docs/ops/runbook.md").is_empty());
        assert_eq!(
            local_impact_domains("xtask/src/ci_impact.rs"),
            Domain::ALL.into_iter().collect()
        );

        let group_sizes = [
            (Domain::RuntimeEventing, 8),
            (Domain::AssemblyGeneration, 6),
            (Domain::Consistency, 3),
            (Domain::TenancyPostgres, 6),
            (Domain::Pdp, 1),
            (Domain::ContractBinding, 1),
            (Domain::CommandSymmetry, 1),
        ];
        for (domain, affected) in group_sizes {
            assert_eq!(
                local_meta_gates(Some(&BTreeSet::from([domain]))).len(),
                9 + affected,
                "{domain:?} gate projection drift"
            );
        }
        assert_eq!(all_local_meta_gates().len(), 35);
    }

    #[test]
    fn local_impact_domain_catalog_matches_real_scanner_closures() {
        use LocalImpactDomain as Domain;

        let cases = [
            (
                "composition/identity/src/lib.rs",
                BTreeSet::from([
                    Domain::RuntimeEventing,
                    Domain::Consistency,
                    Domain::TenancyPostgres,
                    Domain::ContractBinding,
                ]),
            ),
            (
                "crates/identity/src/lib.rs",
                BTreeSet::from([
                    Domain::RuntimeEventing,
                    Domain::Consistency,
                    Domain::TenancyPostgres,
                    Domain::Pdp,
                    Domain::ContractBinding,
                    Domain::CommandSymmetry,
                ]),
            ),
            (
                "examples/iotdevice/Cargo.toml",
                BTreeSet::from([Domain::AssemblyGeneration, Domain::ContractBinding]),
            ),
            (
                "docs/rules/eventbus.md",
                BTreeSet::from([Domain::RuntimeEventing]),
            ),
            (
                "deploy/docker-compose.yml",
                BTreeSet::from([Domain::AssemblyGeneration]),
            ),
            ("Dockerfile", BTreeSet::from([Domain::AssemblyGeneration])),
            (
                "lints/rss_dlq_operator_callsite/ui/runtime.stderr",
                BTreeSet::from([Domain::RuntimeEventing, Domain::TenancyPostgres]),
            ),
            (
                "xtask/src/publicapi.rs",
                BTreeSet::from([Domain::Consistency, Domain::TenancyPostgres]),
            ),
            ("docs/ops/unrelated-runbook.md", BTreeSet::new()),
        ];

        for (path, expected) in cases {
            let actual = local_impact_domains(path);
            assert_eq!(actual, expected, "domain closure drift for {path}");

            let impact = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            let expected_meta = local_meta_gates(Some(&expected));
            assert_eq!(
                local_steps(&impact).first(),
                Some(&LocalStep::Meta(expected_meta)),
                "exact meta projection drift for {path}"
            );
        }

        assert_eq!(
            local_impact_domains("xtask/src/assembly_governance.rs"),
            Domain::ALL.into_iter().collect(),
            "shared assembly governance IR must invalidate every local domain"
        );
    }

    #[test]
    fn every_controlled_ci_carrier_takes_the_meta_path() {
        for path in crate::ci_entry_guard::CONTROLLED_PATHS {
            let impact = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                local_steps(&impact)
                    .iter()
                    .map(LocalStep::label)
                    .collect::<Vec<_>>(),
                vec![LocalStep::Meta(local_meta_gates(None)).label()],
                "controlled carrier {path} must run meta"
            );
        }
    }

    #[test]
    fn selective_local_steps_are_bounded_to_affected_package_operations() {
        let projection = LocalProjection::Selective {
            meta_gates: local_meta_gates(None),
            check_packages: vec!["redis-adapter".to_owned(), "runtime".to_owned()],
            check_includes_lib: true,
            test_clippy_packages: vec!["redis-adapter".to_owned()],
            governance: BTreeSet::new(),
        };
        assert_eq!(
            projection.steps(),
            vec![
                LocalStep::Meta(local_meta_gates(None)),
                LocalStep::Packages {
                    operation: LocalCargoOperation::Check,
                    packages: vec!["redis-adapter".to_owned(), "runtime".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["redis-adapter".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Clippy,
                    packages: vec!["redis-adapter".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
            ]
        );
    }

    #[test]
    fn selected_integration_shards_are_excluded_from_local_preflight() -> Result<()> {
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
        assert!(
            labels.iter().all(|label| !label.contains("integration")),
            "integration compile belongs to nightly/develop, not local preflight: {labels:?}"
        );
        Ok(())
    }

    #[test]
    fn local_cargo_targets_split_checkpoints_by_typed_local_test_policy() -> Result<()> {
        let root = crate::workspace_root()?;
        let graph = WorkspaceGraph::load(&root)?;
        let steps = expand_local_cargo_targets(
            vec![
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["runtime".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["xtask".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["mqtt".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
            ],
            &graph,
        );
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Lib), .. }
                if packages == &["runtime"]
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Doc), .. }
                if packages == &["runtime"]
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Bin(name)), .. }
                if packages == &["xtask"] && name == "xtask"
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test(name)), .. }
                if packages == &["xtask"] && name == "consistency_report_cli"
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test(name)), .. }
                if packages == &["mqtt"] && name == "ownership_gate"
        )));
        assert!(!steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test(name)), .. }
                if packages == &["mqtt"] && name == "integration"
        )));
        for step in &steps {
            if let LocalStep::Packages {
                packages,
                target: Some(LocalCargoTarget::Test(target)),
                ..
            } = step
            {
                assert!(
                    !crate::integration_shards::is_remote_only_test_target(&packages[0], target,),
                    "remote-only target leaked into local preflight: {packages:?}/{target}"
                );
            }
        }
        let keys = steps
            .iter()
            .filter_map(LocalStep::checkpoint_key)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys.len(),
            steps.len(),
            "every Cargo target needs a unique checkpoint"
        );
        Ok(())
    }

    #[test]
    fn meta_child_refresh_preserves_gate_successes_before_later_stage_write() -> Result<()> {
        let root = crate::testutil::unique_tmp("ci-impact-meta-refresh");
        fs::create_dir_all(&root)?;
        let path = root.join("checkpoint.json");
        let mut parent =
            crate::local_run_ledger::LocalRunLedger::fixture(path.clone(), "feature/resume")?;
        let mut child =
            crate::local_run_ledger::LocalRunLedger::fixture(path.clone(), "feature/resume")?;
        child.mark_passed("gate:fmt".to_owned());

        let meta = LocalStep::Meta(vec![GateId::Fmt]);
        assert!(
            finalize_local_step_result(
                &meta,
                Some(&mut parent),
                Err(anyhow::anyhow!("one gate failed")),
            )
            .is_err()
        );
        let later = LocalStep::CargoWrapperSelftest;
        finalize_local_step_result(&later, Some(&mut parent), Ok(()))?;

        let stored = crate::local_run_ledger::LocalRunLedger::fixture(path, "feature/resume")?;
        assert!(stored.contains("gate:fmt"));
        assert!(stored.contains(&later.checkpoint_key().context("stage checkpoint")?));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn local_executor_supports_keep_going_and_fail_fast() {
        let steps = vec![
            LocalStep::Meta(local_meta_gates(None)),
            LocalStep::Packages {
                operation: LocalCargoOperation::Check,
                packages: vec!["leaf".to_owned()],
                target: None,
                check_includes_lib: true,
            },
            LocalStep::Packages {
                operation: LocalCargoOperation::Test,
                packages: vec!["leaf".to_owned()],
                target: None,
                check_includes_lib: true,
            },
        ];
        let mut executed = Vec::new();
        let result = execute_local_steps(&steps, crate::cmd::ExecutionPolicy::KeepGoing, |step| {
            executed.push(step.clone());
            if executed.len() <= 2 {
                bail!("synthetic failure");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(executed, steps);

        executed.clear();
        let result = execute_local_steps(&steps, crate::cmd::ExecutionPolicy::FailFast, |step| {
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
    fn local_stage_selection_preserves_affected_plan_order_and_scope() -> Result<()> {
        let steps = vec![
            LocalStep::Meta(local_meta_gates(None)),
            LocalStep::Packages {
                operation: LocalCargoOperation::Check,
                packages: vec!["consumer".to_owned(), "leaf".to_owned()],
                target: None,
                check_includes_lib: true,
            },
            LocalStep::Packages {
                operation: LocalCargoOperation::Test,
                packages: vec!["leaf".to_owned()],
                target: None,
                check_includes_lib: true,
            },
            LocalStep::Packages {
                operation: LocalCargoOperation::Clippy,
                packages: vec!["leaf".to_owned()],
                target: None,
                check_includes_lib: true,
            },
        ];
        let selected = select_local_steps(
            steps,
            &BTreeSet::from([LocalStage::Clippy, LocalStage::Check]),
        )?;
        assert_eq!(
            selected.iter().map(LocalStep::stage).collect::<Vec<_>>(),
            [LocalStage::Check, LocalStage::Clippy]
        );
        assert!(
            select_local_steps(
                vec![LocalStep::Meta(local_meta_gates(None))],
                &BTreeSet::from([LocalStage::Test]),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn local_package_native_flags_follow_execution_policy() -> Result<()> {
        use crate::cmd::ExecutionPolicy;
        let packages = vec!["leaf".to_owned()];
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Check,
                &packages,
                None,
                true,
                ExecutionPolicy::KeepGoing
            )?,
            ["--locked", "--lib", "--bins", "-p", "leaf", "--keep-going"]
        );
        let xtask = vec!["xtask".to_owned()];
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Check,
                &xtask,
                None,
                false,
                ExecutionPolicy::KeepGoing
            )?,
            ["--locked", "--bins", "-p", "xtask", "--keep-going"]
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Test,
                &packages,
                Some(&LocalCargoTarget::Test("leaf_api".to_owned())),
                true,
                ExecutionPolicy::KeepGoing
            )?,
            [
                "--locked",
                "--test",
                "leaf_api",
                "-p",
                "leaf",
                "--no-fail-fast"
            ]
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Test,
                &packages,
                Some(&LocalCargoTarget::Doc),
                true,
                ExecutionPolicy::KeepGoing
            )?,
            ["--locked", "--doc", "-p", "leaf", "--no-fail-fast"]
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Clippy,
                &packages,
                Some(&LocalCargoTarget::Lib),
                true,
                ExecutionPolicy::KeepGoing
            )?,
            [
                "--locked",
                "--lib",
                "-p",
                "leaf",
                "--keep-going",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert!(
            package_operation_args(
                LocalCargoOperation::Check,
                &packages,
                Some(&LocalCargoTarget::Lib),
                true,
                ExecutionPolicy::KeepGoing
            )
            .is_err()
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Clippy,
                &packages,
                None,
                true,
                ExecutionPolicy::KeepGoing
            )?,
            [
                "--locked",
                "--all-targets",
                "-p",
                "leaf",
                "--keep-going",
                "--",
                "-D",
                "warnings"
            ]
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Test,
                &packages,
                None,
                true,
                ExecutionPolicy::FailFast
            )?,
            ["--locked", "-p", "leaf"]
        );
        Ok(())
    }

    #[test]
    fn bin_only_reverse_closure_projects_check_without_lib() -> Result<()> {
        use crate::cmd::ExecutionPolicy;

        let leaf = "leaf 0.0.0 (path+file:///workspace/crates/leaf)";
        let xtask = "xtask 0.0.0 (path+file:///workspace/xtask)";
        let graph = WorkspaceGraph::from_wire(
            Path::new("/workspace"),
            MetadataWire {
                packages: vec![
                    MetadataPackage {
                        name: "leaf".to_owned(),
                        id: leaf.to_owned(),
                        manifest_path: "/workspace/crates/leaf/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "leaf".to_owned(),
                            kind: vec!["lib".to_owned()],
                        }],
                    },
                    MetadataPackage {
                        name: "xtask".to_owned(),
                        id: xtask.to_owned(),
                        manifest_path: "/workspace/xtask/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "xtask".to_owned(),
                            kind: vec!["bin".to_owned()],
                        }],
                    },
                ],
                workspace_members: BTreeSet::from([leaf.to_owned(), xtask.to_owned()]),
                resolve: Some(MetadataResolve {
                    nodes: vec![
                        MetadataNode {
                            id: leaf.to_owned(),
                            deps: Vec::new(),
                        },
                        MetadataNode {
                            id: xtask.to_owned(),
                            deps: Vec::new(),
                        },
                    ],
                }),
            },
        )?;
        assert!(graph.has_lib_target("leaf"));
        assert!(!graph.has_lib_target("xtask"));

        let mut seeded = BTreeMap::new();
        seeded.insert("xtask".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let impact = impact_entries(
            &[DiffEntry::modified("xtask/src/ci_impact.rs")],
            Some(&graph),
            &BTreeSet::from(["xtask".to_owned()]),
            &seeded,
        );
        let LocalProjection::Selective {
            check_packages,
            check_includes_lib,
            ..
        } = LocalProjection::from(&impact)
        else {
            bail!("expected selective local projection for bin-only xtask closure");
        };
        assert!(!check_includes_lib);
        assert!(check_packages.iter().any(|name| name == "xtask"));

        let check_step = local_steps(&impact)
            .into_iter()
            .find(|step| {
                matches!(
                    step,
                    LocalStep::Packages {
                        operation: LocalCargoOperation::Check,
                        ..
                    }
                )
            })
            .context("expected Check local step")?;
        let LocalStep::Packages {
            packages,
            check_includes_lib: step_includes_lib,
            ..
        } = check_step
        else {
            unreachable!("matched Check Packages step");
        };
        assert!(!step_includes_lib);
        let check_args = package_operation_args(
            LocalCargoOperation::Check,
            &packages,
            None,
            step_includes_lib,
            ExecutionPolicy::KeepGoing,
        )?;
        assert!(!check_args.iter().any(|arg| arg == "--lib"));
        assert!(check_args.iter().any(|arg| arg == "--bins"));

        let mut leaf_seeded = BTreeMap::new();
        leaf_seeded.insert("leaf".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let leaf_impact = impact_entries(
            &[DiffEntry::modified("crates/leaf/src/lib.rs")],
            Some(&graph),
            &BTreeSet::from(["leaf".to_owned()]),
            &leaf_seeded,
        );
        let LocalProjection::Selective {
            check_includes_lib: leaf_includes_lib,
            ..
        } = LocalProjection::from(&leaf_impact)
        else {
            bail!("expected selective local projection for leaf lib closure");
        };
        assert!(leaf_includes_lib);

        Ok(())
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
            LocalProjection::Meta(local_meta_gates(None))
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
        assert_eq!(
            snapshot_verify_environment(&context, "/tmp/isolated-target", None),
            vec![
                ("CARGO_TARGET_DIR", "/tmp/isolated-target"),
                (crate::runtime_root_guard::BASE_ENV, base.as_str()),
            ],
            "snapshot verify must bind the root ratchet to the same resolved base commit as --against"
        );
        let ledger = crate::local_run_ledger::LocalRunLedger::for_worktree(&root)?
            .context("attached fixture must have a local resume ledger")?;
        let handed_off =
            snapshot_verify_environment(&context, "/tmp/isolated-target", Some(&ledger));
        assert!(handed_off.contains(&(crate::local_run_ledger::PATH_ENV, ledger.path_text())));
        assert!(handed_off.contains(&(crate::local_run_ledger::BRANCH_ENV, ledger.branch())));
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

        let snapshot_root = context.root().to_path_buf();
        fs::write(
            snapshot_root.join("test_injected.py"),
            "raise SystemExit(1)\n",
        )?;
        drop(context);
        let cached = LocalExecutionContext::new(&root, "refs/heads/base-ref")?;
        assert_eq!(
            cached.root(),
            snapshot_root,
            "the same worktree and HEAD must reuse one stable snapshot path"
        );
        assert!(
            !cached.root().join("test_injected.py").exists(),
            "reused snapshots must remove untracked executable pollution"
        );
        assert!(
            snapshot_root
                .components()
                .any(|component| component.as_os_str() == "ci-local-sources"),
            "snapshot cache must stay under the local Cargo cache namespace: {}",
            snapshot_root.display()
        );
        drop(cached);
        if let Some(snapshot_revision_root) = snapshot_root.parent() {
            fs::remove_dir_all(snapshot_revision_root)?;
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn local_execution_uses_merge_base_when_remote_base_advanced() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-diverged-base");
        fs::create_dir_all(&temporary_root)?;
        let root = fs::canonicalize(temporary_root)?;
        fs::write(root.join("tracked.txt"), "common\n")?;
        git(&root, &["init"])?;
        let common = commit_all(&root, "common")?;
        git(&root, &["branch", "base-ref", &common])?;
        git(&root, &["checkout", "-b", "local-head"])?;
        fs::write(root.join("tracked.txt"), "local\n")?;
        let local_head = commit_all(&root, "local")?;

        git(&root, &["checkout", "base-ref"])?;
        fs::write(root.join("remote.txt"), "advanced\n")?;
        let advanced_base = commit_all(&root, "advanced base")?;
        git(&root, &["checkout", "local-head"])?;

        let context = LocalExecutionContext::new(&root, "refs/heads/base-ref")?;
        assert_eq!(context.base, advanced_base);
        assert_eq!(context.head, local_head);
        assert_eq!(context.merge_base, common);
        assert_eq!(
            snapshot_verify_environment(&context, "/tmp/isolated-target", None),
            vec![
                ("CARGO_TARGET_DIR", "/tmp/isolated-target"),
                (crate::runtime_root_guard::BASE_ENV, common.as_str()),
            ],
            "local gates must compare against the shared merge base, not a newer sibling base"
        );
        drop(context);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn local_snapshot_target_is_stable_and_isolated_from_the_launcher() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-local-target");
        fs::create_dir_all(&temporary_root)?;
        let root = fs::canonicalize(temporary_root)?;
        let launcher_target = root.join("caller-target");

        let isolated = snapshot_target_dir(&root, Some(launcher_target.as_os_str()))?;
        assert_eq!(isolated, launcher_target.join(LOCAL_SNAPSHOT_TARGET_SUFFIX));
        assert_ne!(isolated, launcher_target);
        assert_eq!(
            snapshot_target_dir(&root, Some(launcher_target.as_os_str()))?,
            isolated,
            "the same launcher target must map to one stable snapshot target"
        );

        let fallback = snapshot_target_dir(&root, None)?;
        assert!(
            fallback
                .components()
                .any(|component| component.as_os_str() == "rss-ci-local-targets")
        );
        assert!(fallback.ends_with(LOCAL_SNAPSHOT_TARGET_SUFFIX));
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

        fs::write(
            root.join("clippy.toml"),
            "avoid-breaking-exported-api = false\n",
        )?;
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
        assert_eq!(
            docs.selected_names(),
            vec!["ci-meta", "ci-local-only", "integration/postgres-domain"]
        );

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
    fn policy_behavior_matches_id_based_golden() -> Result<()> {
        let golden = policy_golden()?;
        assert_eq!(golden.schema_version, 2);
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
            let (expected_jobs, expected_cause) = match case.expected {
                PathExpectationGolden::Selective { jobs } => (jobs, None),
                PathExpectationGolden::Full { cause } => (
                    CiJobKey::ALL
                        .into_iter()
                        .map(|job| job.as_str().to_owned())
                        .collect(),
                    Some(cause),
                ),
            };
            assert_eq!(
                recommendation.selected_names(),
                expected_jobs.iter().map(String::as_str).collect::<Vec<_>>(),
                "golden recommendation drift for {}",
                case.path
            );
            assert_eq!(
                match recommendation {
                    Recommendation::Full(cause) => Some(full_cause_name(cause)),
                    Recommendation::Selective(_) => None,
                },
                expected_cause.as_deref(),
                "golden decision drift for {}",
                case.path
            );
        }
        Ok(())
    }

    #[test]
    fn policy_golden_rejects_removed_shadow_matrix_shape() -> Result<()> {
        let mut old_shape: serde_json::Value = serde_json::from_str(POLICY_BEHAVIOR_SPEC)?;
        old_shape["shadowMatrix"] = serde_json::json!({ "include": [] });
        assert!(serde_json::from_value::<PolicyGolden>(old_shape).is_err());
        Ok(())
    }

    #[test]
    fn policy_golden_rejects_removed_path_case_shape() -> Result<()> {
        let mut old_shape: serde_json::Value = serde_json::from_str(POLICY_BEHAVIOR_SPEC)?;
        let path_case = old_shape["pathCases"][0]
            .as_object_mut()
            .context("policy golden path case must be an object")?;
        path_case.remove("expected");
        path_case.insert("fullCause".to_owned(), serde_json::Value::Null);
        path_case.insert("recommended".to_owned(), serde_json::json!(["ci-meta"]));
        assert!(serde_json::from_value::<PolicyGolden>(old_shape).is_err());
        Ok(())
    }

    #[test]
    fn policy_golden_rejects_empty_path_cases() -> Result<()> {
        let mut empty: serde_json::Value = serde_json::from_str(POLICY_BEHAVIOR_SPEC)?;
        empty["pathCases"] = serde_json::json!([]);
        let source = serde_json::to_string(&empty)?;
        let error = parse_policy_golden(&source)
            .err()
            .context("empty pathCases must fail before policy consumption")?;
        assert_eq!(
            error.to_string(),
            "CI impact policy golden pathCases must be non-empty"
        );
        Ok(())
    }

    #[test]
    fn matrix_is_the_canonical_typed_job_descriptor_projection() -> Result<()> {
        let plan = test_plan()?;
        let matrix = plan.matrix();
        assert!(
            matrix
                .include
                .iter()
                .map(|row| row.job_key)
                .eq(CiJobKey::ALL),
            "matrix jobKey order must follow the closed typed catalog"
        );
        for (row, key) in matrix.include.iter().zip(CiJobKey::ALL) {
            assert_eq!(row.display_name, key.as_str());
            assert_eq!(row.lane, key.lane_kind());
            assert_eq!(row.shard, key.shard());
            assert_eq!(row.partition, key.partition());
            assert_eq!(row.partition_label, key.partition_label());
            assert_eq!(
                row.required_evidence_target,
                key.required_evidence_staged_artifact_path()
            );
        }

        let serialized = serde_json::to_value(&matrix)?;
        let first = &serialized["include"][0];
        assert_eq!(first["jobKey"], CiJobKey::CiMeta.as_str());
        assert_eq!(first["displayName"], CiJobKey::CiMeta.as_str());
        assert_eq!(first["lane"], CiJobKey::CiMeta.lane_kind().workflow_name());
        assert!(first.get("job_key").is_none());
        assert!(first.get("requiredEvidenceTarget").is_none());
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
    fn workspace_rust_consumed_machine_inputs_are_exact_and_mutation_hardened() -> Result<()> {
        let root = crate::workspace_root()?;
        let discovered = rust_consumed_machine_inputs(&root)?;
        let configured = MACHINE_INPUT_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<BTreeSet<_>>();
        let golden = policy_golden()?
            .machine_inputs
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            discovered, configured,
            "machine-input classifier drift from independently discovered Rust includes"
        );
        assert_eq!(discovered, golden, "machine-input golden drift");

        for path in &discovered {
            let mut missing = configured.clone();
            assert!(missing.remove(path));
            assert_ne!(
                discovered, missing,
                "removing machine-consumed input `{path}` must fail closed"
            );
        }

        let mut extra = configured;
        extra.insert("docs/runbooks/not-machine-consumed.md".to_owned());
        assert_ne!(discovered, extra);
        Ok(())
    }

    #[test]
    fn rust_consumed_machine_inputs_discovers_includes_in_expression_fragments() -> Result<()> {
        let root = crate::testutil::unique_tmp("ci-impact-expression-fragment");
        fs::create_dir_all(root.join("docs"))?;
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("docs/machine.json"), "{}")?;
        fs::write(
            root.join("src/included_expr.rs"),
            r#"include_str!("../docs/machine.json")"#,
        )?;

        assert_eq!(
            rust_consumed_machine_inputs(&root)?,
            BTreeSet::from(["docs/machine.json".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn rust_consumed_machine_inputs_rejects_invalid_rust_fragments_with_source_path() -> Result<()>
    {
        let root = crate::testutil::unique_tmp("ci-impact-invalid-fragment");
        fs::create_dir_all(root.join("src"))?;
        let source = root.join("src/invalid.rs");
        fs::write(&source, "let = ;")?;

        let Err(error) = rust_consumed_machine_inputs(&root) else {
            bail!("invalid Rust must fail closed");
        };
        let error = error.to_string();
        assert!(
            error.contains(&source.display().to_string()),
            "parse error must identify its source: {error}"
        );
        Ok(())
    }

    #[test]
    fn plan_roundtrip_rejects_wrong_duplicate_missing_and_extra_catalog_entries() -> Result<()> {
        let plan = test_plan()?;
        let source = plan.to_json()?;
        assert_eq!(CiImpactPlan::from_json(&source)?, plan);

        let mut wrong_id: serde_json::Value = serde_json::from_str(&source)?;
        wrong_id["jobs"][0]["key"] = "not-a-closed-job".into();
        assert_eq!(
            wrong_id["jobs"].as_array().map(Vec::len),
            Some(plan.jobs.len())
        );
        let Err(wrong_id_error) = CiImpactPlan::from_json(&wrong_id.to_string()) else {
            bail!("equal-cardinality wrong CI job ID must fail closed");
        };
        let wrong_id_error = format!("{wrong_id_error:#}");
        assert!(wrong_id_error.contains("unknown CI job key 'not-a-closed-job'"));

        let mut duplicate = plan.clone();
        duplicate.jobs[1] = duplicate.jobs[0].clone();
        duplicate.plan_digest = duplicate.compute_digest()?;
        let Err(duplicate_error) = CiImpactPlan::from_json(&duplicate.to_json()?) else {
            bail!("duplicate CI job ID must fail closed");
        };
        assert_eq!(
            duplicate_error.to_string(),
            "CI impact plan job catalog contains duplicate ID `ci-meta`"
        );

        let mut missing = plan.clone();
        missing.jobs.retain(|job| {
            !matches!(
                job.key,
                CiJobKey::CiCorePrerequisites | CiJobKey::IntegrationProductionRuntime
            )
        });
        missing.plan_digest = missing.compute_digest()?;
        let Err(missing_error) = CiImpactPlan::from_json(&missing.to_json()?) else {
            bail!("missing CI job IDs must fail closed");
        };
        assert_eq!(
            missing_error.to_string(),
            "CI impact plan job ID closure drift: missing=[\"ci-core-prerequisites\", \"integration/production-runtime\"], extra=[]"
        );

        let mut extra = plan.clone();
        extra.jobs.push(extra.jobs[CiJobKey::COUNT - 1].clone());
        extra.plan_digest = extra.compute_digest()?;
        let Err(extra_error) = CiImpactPlan::from_json(&extra.to_json()?) else {
            bail!("extra duplicate CI job ID must fail closed");
        };
        assert_eq!(
            extra_error.to_string(),
            "CI impact plan job catalog contains duplicate ID `audit`"
        );

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
    fn adaptive_plan_requires_every_required_evidence_owner() -> Result<()> {
        let plan = test_adaptive_plan()?;
        let owners = CiJobKey::ALL
            .into_iter()
            .filter(|job| job.required_evidence().is_some())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            owners,
            BTreeSet::from([CiJobKey::CiLocalOnly, CiJobKey::IntegrationPostgresDomain,]),
            "required-evidence ownership must stay bound to stable job IDs"
        );
        for owner in owners {
            let decision = plan
                .jobs()
                .iter()
                .find(|job| job.key() == owner)
                .context("adaptive plan must contain every required-evidence owner")?;
            assert!(
                decision.recommended() && decision.execute(),
                "adaptive plan must recommend and execute {owner}"
            );
        }
        Ok(())
    }

    #[test]
    fn adaptive_plan_json_cannot_disable_required_evidence_owners_red() -> Result<()> {
        for owner_key in CiJobKey::ALL
            .into_iter()
            .filter(|job| job.required_evidence().is_some())
        {
            let mut forged = test_adaptive_plan()?;
            let owner = forged
                .jobs
                .iter_mut()
                .find(|job| job.key == owner_key)
                .context("adaptive plan must contain every required-evidence owner")?;
            owner.recommended = false;
            owner.execute = false;
            owner.reasons = vec![JobReason::NotImpacted];
            forged.plan_digest = forged.compute_digest()?;
            assert!(
                CiImpactPlan::from_json(&forged.to_json()?).is_err(),
                "a digest-consistent plan that disables {owner_key} must be rejected"
            );

            let mut forged_reason = test_adaptive_plan()?;
            let owner = forged_reason
                .jobs
                .iter_mut()
                .find(|job| job.key == owner_key)
                .context("adaptive plan must contain every required-evidence owner")?;
            owner.reasons = vec![JobReason::IntegrationClosure];
            forged_reason.plan_digest = forged_reason.compute_digest()?;
            assert!(
                CiImpactPlan::from_json(&forged_reason.to_json()?).is_err(),
                "a digest-consistent plan that strips {owner_key}'s evidence reason must be rejected"
            );
        }
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
        assert_eq!(adaptive.jobs.iter().filter(|job| job.execute).count(), 3);
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
        let derive = "securederive 0.0.0 (path+file:///workspace/crates/securederive)";
        let xtask = "xtask 0.0.0 (path+file:///workspace/xtask)";
        let registry = "serde 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)";
        let graph = WorkspaceGraph::from_wire(
            Path::new("/workspace"),
            MetadataWire {
                packages: vec![
                    MetadataPackage {
                        name: "leaf".to_owned(),
                        id: leaf.to_owned(),
                        manifest_path: "/workspace/crates/leaf/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "leaf".to_owned(),
                            kind: vec!["lib".to_owned()],
                        }],
                    },
                    MetadataPackage {
                        name: "consumer".to_owned(),
                        id: consumer.to_owned(),
                        manifest_path: "/workspace/crates/consumer/Cargo.toml".to_owned(),
                        targets: vec![
                            MetadataTarget {
                                name: "consumer".to_owned(),
                                kind: vec!["lib".to_owned()],
                            },
                            MetadataTarget {
                                name: "consumer_integration".to_owned(),
                                kind: vec!["test".to_owned()],
                            },
                        ],
                    },
                    MetadataPackage {
                        name: "securederive".to_owned(),
                        id: derive.to_owned(),
                        manifest_path: "/workspace/crates/securederive/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "securederive".to_owned(),
                            kind: vec!["proc-macro".to_owned()],
                        }],
                    },
                    MetadataPackage {
                        name: "xtask".to_owned(),
                        id: xtask.to_owned(),
                        manifest_path: "/workspace/xtask/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "xtask".to_owned(),
                            kind: vec!["bin".to_owned()],
                        }],
                    },
                    MetadataPackage {
                        name: "serde".to_owned(),
                        id: registry.to_owned(),
                        manifest_path: "/registry/serde/Cargo.toml".to_owned(),
                        targets: vec![MetadataTarget {
                            name: "serde".to_owned(),
                            kind: vec!["lib".to_owned()],
                        }],
                    },
                ],
                workspace_members: BTreeSet::from([
                    leaf.to_owned(),
                    consumer.to_owned(),
                    derive.to_owned(),
                    xtask.to_owned(),
                ]),
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
                            id: derive.to_owned(),
                            deps: Vec::new(),
                        },
                        MetadataNode {
                            id: xtask.to_owned(),
                            deps: Vec::new(),
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
        assert!(graph.has_test_targets("leaf"));
        assert!(graph.has_test_targets("consumer"));
        assert!(
            graph.has_test_targets("securederive"),
            "proc-macro kind must count as test-capable"
        );
        assert!(graph.has_test_targets("xtask"));
        assert!(graph.has_lib_target("leaf"));
        assert!(graph.has_lib_target("consumer"));
        assert!(
            graph.has_lib_target("securederive"),
            "proc-macro kind must count as lib-capable for check --lib"
        );
        assert!(
            !graph.has_lib_target("xtask"),
            "bin-only package must not be lib-capable"
        );
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
        let mut test_capable =
            BTreeSet::from(["synthetic-adapter".to_owned(), "runtime".to_owned()]);
        let mut lib_capable =
            BTreeSet::from(["synthetic-adapter".to_owned(), "runtime".to_owned()]);
        for (_, name) in leaves {
            id_to_name.insert((*name).to_owned(), (*name).to_owned());
            test_capable.insert((*name).to_owned());
            lib_capable.insert((*name).to_owned());
        }
        let local_cargo_targets = test_capable
            .iter()
            .map(|name| (name.clone(), vec![LocalCargoTarget::Lib]))
            .collect();
        WorkspaceGraph {
            package_paths,
            id_to_name,
            reverse: BTreeMap::new(),
            test_capable,
            lib_capable,
            local_cargo_targets,
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
        assert_eq!(
            catalog
                .iter()
                .filter(|field| {
                    field.starts_with("job-required-evidence=") && !field.ends_with(':')
                })
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "job-required-evidence=ci-local-only:localonly",
                "job-required-evidence=integration/postgres-domain:localtx",
            ],
            "required-evidence mapping must be a complete policy semantic"
        );
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
        assert!(
            !graph.has_lib_target("xtask"),
            "xtask is bin-only; check reverse closure must omit --lib"
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
