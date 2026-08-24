//! Typed, fail-safe CI impact planning for GitHub Actions.
//!
//! INVARIANT: CI-IMPACT-SELECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "validated selection construction owns the adaptive, PR-complete, and release-check projections" }.
//! INVARIANT: CI-IMPACT-POLICY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "ordinary_rename_preserves_both_paths_as_delete_and_add_red", anti_vacuity = "workspace_policy_catalog_is_non_vacuous" }.
//! INVARIANT: CI-IMPACT-PROJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "private ImpactSet construction and exhaustive local/remote/coverage projections prevent divergent path maps" }.
//! INVARIANT: COVERAGE-SCOPE-PROJECTION-01 { level = "Hard", exec = "native-compile", source = "code", native = "CoverageDecision Skip|Scope exhaustively projected from private ImpactSet" }.

use crate::ci_lanes::{GateId, LocalImpactDomain, LocalMetaPolicy, REGISTRY};
use crate::cmd::{CargoSubcommand, ExternalProgram, cargo_cmd, external_cmd};
use crate::execution_profiles::{DeviceLatentEvidenceId, ExecutionUnitId};
use crate::integration_shards::{
    self, AdapterPackage, AdapterProjection, ChangedIntegrationSource, ImpactMarker,
    IntegrationSelection, IntegrationShard, IntegrationUnitId, Resource,
};
use crate::workspace_facts::CommandWorkspaceFacts;
use anyhow::{Context, Result, bail};
use assembly_schema::repository_contract::{ComponentGraph, ComponentId};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use workspacefacts::{PackageKey, TargetKind, WorkspaceFacts};

const SELECTION_SCHEMA_VERSION: u8 = 2;
const POLICY_SCHEMA_VERSION: u8 = 3;
const UNKNOWN_REVISION: &str = "unknown";
const GITHUB_EVENT_NAME_ENV: &str = "GITHUB_EVENT_NAME";
const GITHUB_SHA_ENV: &str = "GITHUB_SHA";
pub(crate) const LOCAL_WORKER_ENV: &str = "RSS_CI_LOCAL_WORKER";
pub(crate) const LOCAL_SUPERVISED_ENV: &str = "RSS_CI_LOCAL_SUPERVISED";
pub(crate) const LOCAL_HANDSHAKE_FD_ENV: &str = "RSS_CI_LOCAL_HANDSHAKE_FD";
pub(crate) const LOCAL_HANDSHAKE_TOKEN_ENV: &str = "RSS_CI_LOCAL_HANDSHAKE_TOKEN";
pub(crate) const LOCAL_DEADLINE_ENV: &str = "RSS_CI_LOCAL_DEADLINE";
pub(crate) const LOCAL_CALLER_WORKTREE_ENV: &str = "RSS_CI_CALLER_WORKTREE";
pub(crate) const LOCAL_CALLER_BRANCH_ENV: &str = "RSS_CI_CALLER_BRANCH";
pub(crate) const LOCAL_SNAPSHOT_ROOT_ENV: &str = "RSS_CI_EXPECTED_SNAPSHOT_ROOT";
pub(crate) const LOCAL_HEAD_ENV: &str = "RSS_CI_EXPECTED_HEAD";
pub(crate) const LOCAL_BASE_ENV: &str = "RSS_CI_EXPECTED_BASE";
pub(crate) const LOCAL_MERGE_BASE_ENV: &str = "RSS_CI_EXPECTED_MERGE_BASE";
pub(crate) const LOCAL_PRIVATE_ENV: &[&str] = &[
    LOCAL_WORKER_ENV,
    LOCAL_SUPERVISED_ENV,
    LOCAL_HANDSHAKE_FD_ENV,
    LOCAL_HANDSHAKE_TOKEN_ENV,
    LOCAL_DEADLINE_ENV,
    LOCAL_CALLER_WORKTREE_ENV,
    LOCAL_CALLER_BRANCH_ENV,
    LOCAL_SNAPSHOT_ROOT_ENV,
    LOCAL_HEAD_ENV,
    LOCAL_BASE_ENV,
    LOCAL_MERGE_BASE_ENV,
];
const DOCUMENTATION_PATHS: &[&str] = &["README.md", "contracts/README.md"];
const DOCUMENTATION_PREFIXES: &[&str] = &["docs/", ".github/", ".codex/", "hack/"];
#[cfg(test)]
const LOCAL_SNAPSHOT_TARGET_SUFFIX: &str = "ci-local-snapshot";
#[derive(Clone, Copy)]
enum XtaskTestScope {
    Filters(&'static [&'static str]),
    Complete,
}

const LOCAL_CI_XTASK_SCOPES: &[(&str, XtaskTestScope)] = &[
    (
        "xtask/src/ci_impact.rs",
        XtaskTestScope::Filters(&["ci_impact::"]),
    ),
    ("xtask/src/ci_lanes.rs", XtaskTestScope::Complete),
    ("xtask/src/cmd.rs", XtaskTestScope::Complete),
    ("xtask/src/integration_shards.rs", XtaskTestScope::Complete),
];

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
/// 规则目录属于治理元数据，因此它们改动时只走 docs-only 快路径。
const MACHINE_INPUT_PATHS: &[&str] = &[
    "docs/ops/0069-account-security-capacity-gate.selftest.sh",
    "docs/ops/0069-account-security-capacity-gate.sh",
    "docs/ops/localtx-alerts.rules.yaml",
    "docs/spec/007-l4-device-latent-production-loop/contracts/application-receipt.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/apply-device-certificate.command.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/device-certificate-reported.event.schema.json",
    "docs/spec/007-l4-device-latent-production-loop/contracts/device-command-acked.event.schema.json",
    "docs/spec/009-observability-priority-levels/contracts/structured-log-schema.json",
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
    "xtask/src/ci_impact.rs",
    "xtask/src/ci_lanes.rs",
    "xtask/src/cli.rs",
    "xtask/src/execution_profiles.rs",
    "xtask/src/integration_shards.rs",
    "xtask/src/main.rs",
    "xtask/src/nextest.rs",
    "xtask/src/report_format.rs",
    "xtask/src/verify.rs",
];
const HIGH_IMPACT_PREFIXES: &[&str] = &[
    ".config/ci-impact",
    ".github/actions/finalize-rss-ci/",
    ".github/actions/setup-rss-ci/",
    ".github/scripts/ci-cache-",
    ".github/scripts/ci-sccache-stats",
    ".github/workflows/",
];
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub(crate) struct Options {
    #[arg(long = "event-path", required = true)]
    pub(crate) event_path: PathBuf,
    #[arg(long = "policy", required = true)]
    pub(crate) policy_path: PathBuf,
    #[arg(long = "output", required = true)]
    pub(crate) output_path: PathBuf,
    #[arg(long = "github-output", required = true)]
    pub(crate) github_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub(crate) struct LocalOptions {
    /// 对比的 git base ref；`ArgAction::Append` + validate 拒绝重复（clap Set 默认为 last-wins）。
    #[arg(long, action = clap::ArgAction::Append)]
    base: Vec<String>,
    /// Count 拒绝 `--fail-fast` 重复（默认 SetTrue 为 last-wins）。
    #[arg(long, action = clap::ArgAction::Count)]
    fail_fast: u8,
    #[arg(long = "only", value_enum, action = clap::ArgAction::Append)]
    only: Vec<LocalStage>,
}

impl LocalOptions {
    /// `--base` / bool flag 唯一性 + `--only` 拒绝重复 stage。
    pub(crate) fn validate(&self) -> Result<()> {
        match self.base.as_slice() {
            [] => bail!("ci local 缺少 --base"),
            [base] => {
                if base.is_empty() || base.starts_with('-') {
                    bail!("ci local 参数 --base 必须是非空 git ref，不能是 flag");
                }
            }
            _ => bail!("ci local 重复参数: --base"),
        }
        if self.fail_fast > 1 {
            bail!("ci local 重复参数: --fail-fast");
        }
        let mut seen = BTreeSet::new();
        for stage in &self.only {
            if !seen.insert(*stage) {
                bail!("ci local 重复 stage: {}", stage.as_str());
            }
        }
        Ok(())
    }

    fn base_ref(&self) -> &str {
        self.base.first().map(String::as_str).unwrap_or("")
    }

    fn fail_fast(&self) -> bool {
        self.fail_fast > 0
    }

    fn only_set(&self) -> BTreeSet<LocalStage> {
        self.only.iter().copied().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LocalStage {
    Meta,
    #[value(name = "python-hooks")]
    PythonHooks,
    #[value(name = "cargo-wrapper-selftest")]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PolicyMode {
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
pub(crate) enum SelectionMode {
    Adaptive,
    PrComplete,
    ReleaseCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DecisionReason {
    PullRequestImpact,
    DevelopPush,
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
            Self::RenameOrCopy => {
                "Review the contract rename or copy and keep the conservative PR-complete run."
            }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RevisionIdentity {
    base_revision: String,
    head_revision: String,
    merge_base_revision: String,
    execution_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct NonEmptyPackageSet(Vec<String>);

impl NonEmptyPackageSet {
    fn new(packages: Vec<String>) -> Result<Self> {
        if packages.is_empty() {
            bail!("adaptive package selection must be non-empty");
        }
        Ok(Self(packages))
    }

    pub(crate) fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyPackageSet {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let packages = Vec::<String>::deserialize(deserializer)?;
        Self::new(packages).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AdaptiveTestSelection {
    None,
    Packages { packages: NonEmptyPackageSet },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
enum PublicApiSelection {
    None,
    Affected { packages: NonEmptyPackageSet },
    CompleteInternal,
}

impl PublicApiSelection {
    fn affected(packages: BTreeSet<String>) -> Result<Self> {
        if packages.is_empty() {
            Ok(Self::None)
        } else {
            Ok(Self::Affected {
                packages: NonEmptyPackageSet::new(packages.into_iter().collect())?,
            })
        }
    }

    fn packages(&self) -> &[String] {
        match self {
            Self::Affected { packages } => packages.as_slice(),
            Self::None | Self::CompleteInternal => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedPublicApiSelection<'a> {
    None,
    Affected(&'a NonEmptyPackageSet),
    CompleteInternal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedTestSelection<'a> {
    None,
    Packages(&'a NonEmptyPackageSet),
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
enum Selection {
    Adaptive {
        affected_packages: Vec<String>,
        public_api: PublicApiSelection,
        test_selection: AdaptiveTestSelection,
        integration_selection: IntegrationSelection,
    },
    PrComplete {
        public_api: PublicApiSelection,
    },
    ReleaseCheck {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SelectionPlan {
    schema_version: u8,
    policy_version: String,
    selection: Selection,
    decision_reason: DecisionReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_context: Option<FallbackContext>,
    revisions: RevisionIdentity,
    unknown_paths: Vec<String>,
}

struct SelectionInput {
    policy_version: String,
    mode: SelectionMode,
    decision_reason: DecisionReason,
    fallback_context: Option<FallbackContext>,
    revisions: RevisionIdentity,
    affected_packages: BTreeSet<String>,
    public_api: PublicApiInput,
    test_packages: BTreeSet<String>,
    integration_units: BTreeSet<IntegrationUnitId>,
    unknown_paths: BTreeSet<String>,
}

enum PublicApiInput {
    Affected(BTreeSet<String>),
    CompleteInternal,
}

impl PublicApiInput {
    fn into_selection(self) -> Result<PublicApiSelection> {
        match self {
            Self::Affected(packages) => PublicApiSelection::affected(packages),
            Self::CompleteInternal => Ok(PublicApiSelection::CompleteInternal),
        }
    }
}

impl SelectionPlan {
    fn new(input: SelectionInput) -> Result<Self> {
        let selection = match input.mode {
            SelectionMode::Adaptive => {
                let test_selection = if input.test_packages.is_empty() {
                    AdaptiveTestSelection::None
                } else {
                    AdaptiveTestSelection::Packages {
                        packages: NonEmptyPackageSet::new(
                            input.test_packages.into_iter().collect(),
                        )?,
                    }
                };
                let mut units = input.integration_units;
                units.extend(
                    integration_shards::localtx_required_selection()?
                        .unit_ids()
                        .iter()
                        .copied(),
                );
                Selection::Adaptive {
                    affected_packages: input.affected_packages.into_iter().collect(),
                    public_api: input.public_api.into_selection()?,
                    test_selection,
                    integration_selection: IntegrationSelection::critical(units)?,
                }
            }
            SelectionMode::PrComplete => Selection::PrComplete {
                public_api: input.public_api.into_selection()?,
            },
            SelectionMode::ReleaseCheck => Selection::ReleaseCheck {},
        };
        let selection = Self {
            schema_version: SELECTION_SCHEMA_VERSION,
            policy_version: input.policy_version,
            selection,
            decision_reason: input.decision_reason,
            fallback_context: input.fallback_context,
            revisions: input.revisions,
            unknown_paths: input.unknown_paths.into_iter().collect(),
        };
        selection.validate()?;
        Ok(selection)
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != SELECTION_SCHEMA_VERSION {
            bail!("unsupported CI selection schema");
        }
        validate_hex_digest(&self.policy_version, "policy version")?;
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
        validate_canonical_strings(self.affected_packages(), "affected packages")?;
        validate_canonical_strings(self.public_api_packages(), "public-api packages")?;
        validate_canonical_strings(&self.unknown_paths, "unknown paths")?;
        if self.unknown_paths.iter().any(|path| {
            Path::new(path).is_absolute() || path.split('/').any(|component| component == "..")
        }) {
            bail!("CI selection unknown path must be repository-relative and safe");
        }
        if let Selection::Adaptive {
            test_selection,
            integration_selection,
            public_api,
            ..
        } = &self.selection
        {
            if public_api
                .packages()
                .iter()
                .any(|package| !self.affected_packages().contains(package))
            {
                bail!("adaptive public-api packages must be an affected-package subset");
            }
            match test_selection {
                AdaptiveTestSelection::None => {}
                AdaptiveTestSelection::Packages { packages } => {
                    validate_canonical_strings(packages.as_slice(), "test packages")?;
                    if packages
                        .as_slice()
                        .iter()
                        .any(|package| !self.affected_packages().contains(package))
                    {
                        bail!("adaptive test packages must be a non-empty affected-package subset");
                    }
                }
            }
            if integration_selection.profile()
                != crate::execution_profiles::ExecutionProfile::IntegrationCritical
            {
                bail!("adaptive selection requires integration-critical units");
            }
            let required = integration_shards::localtx_required_selection()?;
            if !required
                .unit_ids()
                .is_subset(integration_selection.unit_ids())
            {
                bail!("adaptive integration selection omits LocalTx required units");
            }
        }
        if !legal_selection(self.mode(), self.decision_reason) {
            bail!("CI selection mode and decision reason are inconsistent");
        }
        match &self.fallback_context {
            Some(context) => context.validate(self.decision_reason)?,
            None if matches!(
                self.decision_reason,
                DecisionReason::PolicyInvalid
                    | DecisionReason::EventInvalid
                    | DecisionReason::DiffUnavailable
                    | DecisionReason::MetadataUnavailable
                    | DecisionReason::ContractUnavailable
                    | DecisionReason::RenameOrCopy
                    | DecisionReason::UnknownPath
            ) =>
            {
                bail!("fallback CI selection must contain typed fallback context");
            }
            None => {}
        }
        if self.mode() == SelectionMode::Adaptive
            && !self.unknown_paths.is_empty()
            && self.affected_packages().is_empty()
        {
            bail!("adaptive selection cannot ignore an entirely unowned diff");
        }
        if self.decision_reason == DecisionReason::UnknownPath
            && (self.unknown_paths.is_empty() || !self.affected_packages().is_empty())
        {
            bail!("unknown-only PR-complete selection must retain only its unknown path trace");
        }
        Ok(())
    }

    #[cfg(test)]
    fn from_json(source: &str) -> Result<Self> {
        source.parse()
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize CI selection")
    }

    pub(crate) const fn mode(&self) -> SelectionMode {
        match self.selection {
            Selection::Adaptive { .. } => SelectionMode::Adaptive,
            Selection::PrComplete { .. } => SelectionMode::PrComplete,
            Selection::ReleaseCheck {} => SelectionMode::ReleaseCheck,
        }
    }

    pub(crate) const fn test_selection(&self) -> ProjectedTestSelection<'_> {
        match &self.selection {
            Selection::Adaptive {
                test_selection: AdaptiveTestSelection::None,
                ..
            } => ProjectedTestSelection::None,
            Selection::Adaptive {
                test_selection: AdaptiveTestSelection::Packages { packages },
                ..
            } => ProjectedTestSelection::Packages(packages),
            Selection::PrComplete { .. } | Selection::ReleaseCheck {} => {
                ProjectedTestSelection::Workspace
            }
        }
    }

    pub(crate) fn integration_selection(&self) -> Result<IntegrationSelection> {
        match &self.selection {
            Selection::Adaptive {
                integration_selection,
                ..
            } => Ok(integration_selection.clone()),
            Selection::PrComplete { .. } => IntegrationSelection::for_profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical,
            ),
            Selection::ReleaseCheck {} => Ok(IntegrationSelection::release_check()),
        }
    }

    pub(crate) fn affected_packages(&self) -> &[String] {
        match &self.selection {
            Selection::Adaptive {
                affected_packages, ..
            } => affected_packages,
            Selection::PrComplete { .. } | Selection::ReleaseCheck {} => &[],
        }
    }

    pub(crate) fn public_api_packages(&self) -> &[String] {
        match &self.selection {
            Selection::Adaptive { public_api, .. } => public_api.packages(),
            Selection::PrComplete { public_api } => public_api.packages(),
            Selection::ReleaseCheck {} => &[],
        }
    }

    pub(crate) const fn public_api_selection(&self) -> ProjectedPublicApiSelection<'_> {
        let selection = match &self.selection {
            Selection::Adaptive { public_api, .. } | Selection::PrComplete { public_api } => {
                public_api
            }
            Selection::ReleaseCheck {} => return ProjectedPublicApiSelection::None,
        };
        match selection {
            PublicApiSelection::None => ProjectedPublicApiSelection::None,
            PublicApiSelection::Affected { packages } => {
                ProjectedPublicApiSelection::Affected(packages)
            }
            PublicApiSelection::CompleteInternal => ProjectedPublicApiSelection::CompleteInternal,
        }
    }

    #[cfg(test)]
    pub(crate) fn unknown_paths(&self) -> &[String] {
        &self.unknown_paths
    }
}

impl std::str::FromStr for SelectionPlan {
    type Err = anyhow::Error;

    fn from_str(source: &str) -> Result<Self> {
        let selection: Self = serde_json::from_str(source).context("invalid CI selection plan")?;
        selection.validate()?;
        Ok(selection)
    }
}

fn validate_canonical_strings(values: &[String], label: &str) -> Result<()> {
    if values.iter().any(|value| value.is_empty())
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("CI selection {label} must be non-empty, unique, and canonically ordered");
    }
    Ok(())
}

fn legal_selection(mode: SelectionMode, reason: DecisionReason) -> bool {
    match reason {
        DecisionReason::PullRequestImpact => mode == SelectionMode::Adaptive,
        DecisionReason::GlobalImpact => mode == SelectionMode::PrComplete,
        DecisionReason::DevelopPush
        | DecisionReason::WorkflowDispatch
        | DecisionReason::FullOverride => mode == SelectionMode::ReleaseCheck,
        DecisionReason::PolicyInvalid
        | DecisionReason::EventInvalid
        | DecisionReason::DiffUnavailable
        | DecisionReason::MetadataUnavailable
        | DecisionReason::ContractUnavailable => mode != SelectionMode::Adaptive,
        DecisionReason::RenameOrCopy | DecisionReason::UnknownPath => {
            mode == SelectionMode::PrComplete
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscalationCause {
    #[cfg(test)]
    MandatoryCatalog,
    GlobalImpact,
    RenameOrCopy,
    UnknownPath,
    #[cfg(test)]
    FallbackUncertainty,
}

/// The only path-to-impact model. Its constructors stay private so callers can only consume a
/// projection produced by this module's closed classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImpactSet {
    Empty,
    Selective(SelectiveImpact),
    Escalated {
        cause: EscalationCause,
        public_api_packages: BTreeSet<String>,
    },
}

impl ImpactSet {
    fn escalated(cause: EscalationCause) -> Self {
        Self::Escalated {
            cause,
            public_api_packages: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectiveImpact {
    documentation: bool,
    packages: BTreeMap<String, BTreeSet<PackageImpact>>,
    reverse_closure: BTreeSet<String>,
    /// Reverse dependency closure of coverage seeds only (Source/Generated/Contract*).
    coverage_closure: BTreeSet<String>,
    /// Workspace members whose Cargo target explicitly enables a test harness.
    /// Truly empty binaries declare `test = false` in their manifest so they
    /// cannot create an empty package-scoped owner.
    packages_with_tests: BTreeSet<String>,
    /// True when `reverse_closure` contains at least one `lib`/`proc-macro` package.
    /// Drives `cargo check --lib --bins` vs `--bins` for bin-only reverse closures.
    check_includes_lib: bool,
    integration_units: BTreeSet<IntegrationUnitId>,
    governance: BTreeSet<GovernanceImpact>,
    local_meta_domains: BTreeSet<LocalImpactDomain>,
    unknown_paths: BTreeSet<String>,
    public_api_packages: BTreeSet<String>,
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

    /// Deterministic component-test seed categories. Manifest is compile-only; test changes must
    /// join source changes when coverage is the sole component-test owner.
    const fn is_coverage_seed(self) -> bool {
        match self {
            Self::Source
            | Self::Test
            | Self::Generated
            | Self::ContractOwner
            | Self::ContractSubscriber => true,
            Self::Manifest => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteProjection {
    mode: SelectionMode,
    cause: Option<EscalationCause>,
    affected_packages: BTreeSet<String>,
    public_api_packages: BTreeSet<String>,
    test_packages: BTreeSet<String>,
    integration_units: BTreeSet<IntegrationUnitId>,
    unknown_paths: BTreeSet<String>,
}

impl From<&ImpactSet> for RemoteProjection {
    fn from(impact: &ImpactSet) -> Self {
        match impact {
            ImpactSet::Empty => Self {
                mode: SelectionMode::Adaptive,
                cause: None,
                affected_packages: BTreeSet::new(),
                public_api_packages: BTreeSet::new(),
                test_packages: BTreeSet::new(),
                integration_units: BTreeSet::new(),
                unknown_paths: BTreeSet::new(),
            },
            ImpactSet::Escalated {
                cause,
                public_api_packages,
            } => Self {
                mode: match cause {
                    #[cfg(test)]
                    EscalationCause::MandatoryCatalog => SelectionMode::ReleaseCheck,
                    EscalationCause::GlobalImpact
                    | EscalationCause::RenameOrCopy
                    | EscalationCause::UnknownPath => SelectionMode::PrComplete,
                    #[cfg(test)]
                    EscalationCause::FallbackUncertainty => SelectionMode::PrComplete,
                },
                cause: Some(*cause),
                affected_packages: BTreeSet::new(),
                public_api_packages: public_api_packages.clone(),
                test_packages: BTreeSet::new(),
                integration_units: BTreeSet::new(),
                unknown_paths: BTreeSet::new(),
            },
            ImpactSet::Selective(selective) => {
                let mut affected_packages = selective.reverse_closure.clone();
                affected_packages.extend(selective.packages.keys().cloned());
                let test_packages = affected_packages
                    .intersection(&selective.packages_with_tests)
                    .cloned()
                    .collect();
                let unknown_only = !selective.unknown_paths.is_empty()
                    && affected_packages.is_empty()
                    && selective.integration_units.is_empty();
                Self {
                    mode: if unknown_only {
                        SelectionMode::PrComplete
                    } else {
                        SelectionMode::Adaptive
                    },
                    cause: unknown_only.then_some(EscalationCause::UnknownPath),
                    affected_packages,
                    public_api_packages: selective.public_api_packages.clone(),
                    test_packages,
                    integration_units: selective.integration_units.clone(),
                    unknown_paths: selective.unknown_paths.clone(),
                }
            }
        }
    }
}

impl RemoteProjection {
    fn decision_reason(&self) -> DecisionReason {
        match self.cause {
            None => DecisionReason::PullRequestImpact,
            #[cfg(test)]
            Some(EscalationCause::MandatoryCatalog) => DecisionReason::DevelopPush,
            Some(EscalationCause::GlobalImpact) => DecisionReason::GlobalImpact,
            Some(EscalationCause::RenameOrCopy) => DecisionReason::RenameOrCopy,
            Some(EscalationCause::UnknownPath) => DecisionReason::UnknownPath,
            #[cfg(test)]
            Some(EscalationCause::FallbackUncertainty) => DecisionReason::DiffUnavailable,
        }
    }

    fn fallback_context(&self) -> Option<FallbackContext> {
        self.cause.and_then(EscalationCause::fallback_context)
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
        public_api_packages: Vec<String>,
        governance: BTreeSet<GovernanceImpact>,
    },
}

impl From<&ImpactSet> for LocalProjection {
    fn from(impact: &ImpactSet) -> Self {
        match impact {
            ImpactSet::Empty => Self::Empty,
            ImpactSet::Escalated {
                cause: EscalationCause::UnknownPath,
                public_api_packages,
            } if public_api_packages.is_empty() => Self::Meta(local_meta_gates(None)),
            ImpactSet::Escalated {
                public_api_packages,
                ..
            } if public_api_packages.is_empty() => Self::Meta(all_local_meta_gates()),
            ImpactSet::Escalated {
                public_api_packages,
                ..
            } => Self::Selective {
                meta_gates: all_local_meta_gates(),
                check_packages: Vec::new(),
                check_includes_lib: true,
                test_clippy_packages: Vec::new(),
                public_api_packages: public_api_packages.iter().cloned().collect(),
                governance: BTreeSet::new(),
            },
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
                    public_api_packages: selective.public_api_packages.iter().cloned().collect(),
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
    BinTestFilter {
        name: String,
        filter: String,
    },
    Test {
        name: String,
        required_features: Vec<String>,
    },
    Doc,
}

impl LocalCargoTarget {
    fn display_label(&self) -> String {
        match self {
            Self::Lib => "lib".to_owned(),
            Self::Bin(name) => format!("bin:{name}"),
            Self::BinTestFilter { name, filter } => format!("bin:{name}/filter:{filter}"),
            Self::Test {
                name,
                required_features,
            } if required_features.is_empty() => format!("test:{name}"),
            Self::Test {
                name,
                required_features,
            } => format!("test:{name}/features:{}", required_features.join(",")),
            Self::Doc => "doc".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalStep {
    Meta(Vec<GateId>),
    PublicApi(Vec<String>),
    CompleteInternalPublicApi,
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
                public_api_packages,
                governance,
            } => {
                let mut steps = vec![LocalStep::Meta(meta_gates.clone())];
                if !public_api_packages.is_empty() {
                    steps.push(LocalStep::PublicApi(public_api_packages.clone()));
                }
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
    let mut steps = LocalProjection::from(impact).steps();
    if matches!(
        impact,
        ImpactSet::Escalated {
            cause: EscalationCause::UnknownPath,
            public_api_packages,
        } if public_api_packages.is_empty()
    ) {
        steps.push(LocalStep::CompleteInternalPublicApi);
    }
    steps
}

/// Workspace-wide coverage cause mapped from [`EscalationCause`] (exhaustive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoverageWorkspaceCause {
    MandatoryCatalog,
    GlobalImpact,
    RenameOrCopy,
    UnknownPath,
    FallbackUncertainty,
}

impl From<EscalationCause> for CoverageWorkspaceCause {
    fn from(cause: EscalationCause) -> Self {
        match cause {
            #[cfg(test)]
            EscalationCause::MandatoryCatalog => Self::MandatoryCatalog,
            EscalationCause::GlobalImpact => Self::GlobalImpact,
            EscalationCause::RenameOrCopy => Self::RenameOrCopy,
            EscalationCause::UnknownPath => Self::UnknownPath,
            #[cfg(test)]
            EscalationCause::FallbackUncertainty => Self::FallbackUncertainty,
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
            ImpactSet::Escalated { cause, .. } => {
                Self(CoverageDecision::Scope(CoverageScope::Workspace {
                    cause: CoverageWorkspaceCause::from(*cause),
                }))
            }
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
    #[cfg(test)]
    fn decision(self) -> CoverageDecision {
        self.0
    }

    fn into_scope_or_fallback(self) -> CoverageScope {
        match self.0 {
            CoverageDecision::Scope(scope) => scope,
            // Canonical release execution with no seeds: fail-safe Workspace.
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

/// Resolve coverage scope for the fixed `test-affected` job in ReleaseCheck mode using the same
/// base as `ci plan`.
/// Non-PR → Workspace (full catalog). PR event/diff uncertainty → Workspace
/// FallbackUncertainty; canonical Cargo/catalog drift is a hard error before any projection.
pub(crate) fn coverage_scope_for_typed_job(root: &Path) -> Result<CoverageScope> {
    let command_facts = CommandWorkspaceFacts::new(root);
    if matches!(
        validate_planner_catalog(root, &command_facts)?,
        PlannerCatalog::FactsUnavailable(_)
    ) {
        return Ok(coverage_fallback_uncertainty());
    }
    let event_name = std::env::var(GITHUB_EVENT_NAME_ENV).unwrap_or_default();
    if event_name != "pull_request" {
        return Ok(CoverageScope::Workspace {
            cause: CoverageWorkspaceCause::MandatoryCatalog,
        });
    }
    Ok(coverage_scope_for_pull_request(root, &command_facts)
        .unwrap_or_else(coverage_fallback_uncertainty))
}

fn coverage_scope_for_pull_request(
    root: &Path,
    command_facts: &CommandWorkspaceFacts,
) -> Option<CoverageScope> {
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
    if let Some(cause) = immediate_escalation_cause(&entries) {
        return Some(
            CoverageProjection::from(&ImpactSet::escalated(cause)).into_scope_or_fallback(),
        );
    }
    let impact = match workspace_facts_for_impact(&entries, command_facts).ok()? {
        Some(facts) => impact_with_facts(root, &entries, facts, merge_base).ok()?,
        None => try_impact_entries(&entries, None, &BTreeSet::new(), &BTreeMap::new()).ok()?,
    };
    Some(CoverageProjection::from(&impact).into_scope_or_fallback())
}

/// Full local release-check always evaluates workspace coverage.
pub(crate) fn coverage_scope_for_full_ci() -> CoverageScope {
    CoverageScope::Workspace {
        cause: CoverageWorkspaceCause::MandatoryCatalog,
    }
}

impl EscalationCause {
    fn fallback_context(self) -> Option<FallbackContext> {
        match self {
            Self::RenameOrCopy => Some(FallbackContext::new(FallbackCode::RenameOrCopy, None)),
            Self::UnknownPath => Some(FallbackContext::new(FallbackCode::UnknownPath, None)),
            Self::GlobalImpact => None,
            #[cfg(test)]
            Self::MandatoryCatalog | Self::FallbackUncertainty => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffStatus {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiffEntry {
    status: DiffStatus,
    path: String,
    rename_or_copy: bool,
}

impl DiffEntry {
    #[cfg(test)]
    fn modified(path: &str) -> Self {
        Self {
            status: DiffStatus::Modified,
            path: path.to_owned(),
            rename_or_copy: false,
        }
    }

    #[cfg(test)]
    fn rename(path: &str) -> Self {
        Self {
            status: DiffStatus::Modified,
            path: path.to_owned(),
            rename_or_copy: true,
        }
    }
}

/// Shared lazy-load decision for every CI impact consumer. Empty and true documentation-only
/// diffs never touch Cargo metadata; any other diff obtains the command-scoped cached facts.
fn workspace_facts_for_impact<'a>(
    entries: &[DiffEntry],
    command_facts: &'a CommandWorkspaceFacts,
) -> Result<Option<&'a WorkspaceFacts>> {
    if entries.is_empty() || entries.iter().all(|entry| documentation(&entry.path)) {
        Ok(None)
    } else {
        command_facts.get().map(Some)
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
    let event_name = std::env::var(GITHUB_EVENT_NAME_ENV).unwrap_or_default();
    let execution_revision =
        std::env::var(GITHUB_SHA_ENV).unwrap_or_else(|_| UNKNOWN_REVISION.to_owned());
    validate_revision(&execution_revision, "execution revision")?;
    let event_source = fs::read_to_string(&options.event_path)
        .with_context(|| format!("读取 {}", options.event_path.display()));
    let fallback_mode = if event_name == "pull_request" {
        SelectionMode::PrComplete
    } else {
        SelectionMode::ReleaseCheck
    };
    let command_facts = CommandWorkspaceFacts::new(root);
    let catalog_available = matches!(
        validate_planner_catalog(root, &command_facts)?,
        PlannerCatalog::Available
    );

    let selection = if !catalog_available {
        fallback_selection_with_code(
            policy_version,
            FallbackCode::MetadataUnavailable,
            fallback_mode,
            execution_revision,
        )?
    } else {
        match policy {
            Err(_) => fallback_selection(
                policy_version,
                DecisionReason::PolicyInvalid,
                fallback_mode,
                execution_revision,
            )?,
            Ok(policy) if policy.schema_version != POLICY_SCHEMA_VERSION => fallback_selection(
                policy_version,
                DecisionReason::PolicyInvalid,
                fallback_mode,
                execution_revision,
            )?,
            Ok(policy) => plan_event_with_facts(
                root,
                &command_facts,
                &event_name,
                event_source.as_deref().unwrap_or("{}"),
                policy_version,
                policy.mode,
                execution_revision,
            )?,
        }
    };

    if let Some(parent) = options.output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&options.output_path, selection.to_json()?)
        .with_context(|| format!("写 {}", options.output_path.display()))?;
    let compact_selection =
        serde_json::to_string(&selection).context("serialize canonical CI selection")?;
    let outputs = format!("selection={compact_selection}\n");
    fs::write(&options.github_output, outputs)
        .with_context(|| format!("写 {}", options.github_output.display()))?;
    if let Ok(summary_path) = std::env::var("GITHUB_STEP_SUMMARY") {
        let summary = render_selection_summary(&selection);
        fs::write(summary_path, summary)?;
    }
    Ok(())
}

fn render_selection_summary(selection: &SelectionPlan) -> String {
    let mut summary = format!(
        "## Typed CI selection\n\n- Policy: `{}`\n- Mode: `{}`\n- Reason: `{}`\n- Affected packages: `{}`\n- Internal public-api owners: `{}`\n- Integration selection: `{}`\n- Unknown paths retained for trace: `{}`\n",
        selection.policy_version,
        selection_mode_name(selection.mode()),
        decision_reason_name(selection.decision_reason),
        selection.affected_packages().len(),
        match selection.public_api_selection() {
            ProjectedPublicApiSelection::None => "none".to_owned(),
            ProjectedPublicApiSelection::Affected(packages) => packages.as_slice().join(", "),
            ProjectedPublicApiSelection::CompleteInternal => "complete-internal".to_owned(),
        },
        selection
            .integration_selection()
            .map(|value| value.to_string())
            .unwrap_or_else(|error| format!("invalid: {error}")),
        selection.unknown_paths.len(),
    );
    if let Some(context) = &selection.fallback_context {
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

#[cfg(test)]
fn plan_event(
    root: &Path,
    event_name: &str,
    event_source: &str,
    policy_version: String,
    _policy_mode: PolicyMode,
    execution_revision: String,
) -> Result<SelectionPlan> {
    let command_facts = CommandWorkspaceFacts::new(root);
    if matches!(
        validate_planner_catalog(root, &command_facts)?,
        PlannerCatalog::FactsUnavailable(_)
    ) {
        let fallback_mode = if event_name == "pull_request" {
            SelectionMode::PrComplete
        } else {
            SelectionMode::ReleaseCheck
        };
        return fallback_selection_with_code(
            policy_version,
            FallbackCode::MetadataUnavailable,
            fallback_mode,
            execution_revision,
        );
    }
    plan_event_with_facts(
        root,
        &command_facts,
        event_name,
        event_source,
        policy_version,
        _policy_mode,
        execution_revision,
    )
}

fn plan_event_with_facts(
    root: &Path,
    command_facts: &CommandWorkspaceFacts,
    event_name: &str,
    event_source: &str,
    policy_version: String,
    _policy_mode: PolicyMode,
    execution_revision: String,
) -> Result<SelectionPlan> {
    let fallback_mode = if event_name == "pull_request" {
        SelectionMode::PrComplete
    } else {
        SelectionMode::ReleaseCheck
    };
    let force_full = match full_override(std::env::var_os("RSS_CI_FORCE_FULL").as_deref()) {
        FullOverride::Disabled => false,
        FullOverride::Enabled => true,
        FullOverride::Invalid => {
            return fallback_selection_with_code(
                policy_version,
                FallbackCode::ForceFullInvalid,
                fallback_mode,
                execution_revision,
            );
        }
    };
    if force_full {
        return release_selection(
            policy_version,
            DecisionReason::FullOverride,
            execution_revision,
        );
    }
    match event_name {
        "push" => release_selection(
            policy_version,
            DecisionReason::DevelopPush,
            execution_revision,
        ),
        "workflow_dispatch" => release_selection(
            policy_version,
            DecisionReason::WorkflowDispatch,
            execution_revision,
        ),
        "pull_request" => {
            let event = serde_json::from_str::<GithubEvent>(event_source);
            let Some(pull_request) = event.ok().and_then(|event| event.pull_request) else {
                return fallback_selection(
                    policy_version,
                    DecisionReason::EventInvalid,
                    SelectionMode::PrComplete,
                    execution_revision,
                );
            };
            if validate_revision(&pull_request.base.sha, "base revision").is_err()
                || validate_revision(&pull_request.head.sha, "head revision").is_err()
            {
                return fallback_selection(
                    policy_version,
                    DecisionReason::EventInvalid,
                    SelectionMode::PrComplete,
                    execution_revision,
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
                    return fallback_selection_with_code(
                        policy_version,
                        FallbackCode::MergeBaseUnavailable,
                        SelectionMode::PrComplete,
                        execution_revision,
                    );
                }
            };
            let revisions = RevisionIdentity {
                base_revision: pull_request.base.sha.clone(),
                head_revision: pull_request.head.sha.clone(),
                merge_base_revision: merge_base.clone(),
                execution_revision,
            };
            let projection = match pull_request_projection(
                root,
                command_facts,
                &pull_request.base.sha,
                &pull_request.head.sha,
                &merge_base,
            ) {
                Ok(value) => value,
                Err(failure) => {
                    return fallback_selection_with_revisions(
                        policy_version,
                        failure.context,
                        SelectionMode::PrComplete,
                        revisions,
                    );
                }
            };
            let decision_reason = projection.decision_reason();
            let fallback_context = projection.fallback_context();
            let public_api =
                if projection.public_api_packages.is_empty() && fallback_context.is_some() {
                    PublicApiInput::CompleteInternal
                } else {
                    PublicApiInput::Affected(projection.public_api_packages)
                };
            SelectionPlan::new(SelectionInput {
                policy_version,
                mode: projection.mode,
                decision_reason,
                fallback_context,
                revisions,
                affected_packages: projection.affected_packages,
                public_api,
                test_packages: projection.test_packages,
                integration_units: projection.integration_units,
                unknown_paths: projection.unknown_paths,
            })
        }
        _ => fallback_selection(
            policy_version,
            DecisionReason::EventInvalid,
            SelectionMode::ReleaseCheck,
            execution_revision,
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

fn release_selection(
    policy_version: String,
    reason: DecisionReason,
    execution_revision: String,
) -> Result<SelectionPlan> {
    SelectionPlan::new(SelectionInput {
        policy_version,
        mode: SelectionMode::ReleaseCheck,
        decision_reason: reason,
        fallback_context: None,
        revisions: unknown_revisions(execution_revision),
        affected_packages: BTreeSet::new(),
        public_api: PublicApiInput::Affected(BTreeSet::new()),
        test_packages: BTreeSet::new(),
        integration_units: BTreeSet::new(),
        unknown_paths: BTreeSet::new(),
    })
}

fn fallback_selection(
    policy_version: String,
    reason: DecisionReason,
    mode: SelectionMode,
    execution_revision: String,
) -> Result<SelectionPlan> {
    fallback_selection_with_code(
        policy_version,
        fallback_code(reason)?,
        mode,
        execution_revision,
    )
}

fn fallback_selection_with_code(
    policy_version: String,
    code: FallbackCode,
    mode: SelectionMode,
    execution_revision: String,
) -> Result<SelectionPlan> {
    fallback_selection_with_revisions(
        policy_version,
        FallbackContext::new(code, None),
        mode,
        unknown_revisions(execution_revision),
    )
}

fn fallback_selection_with_revisions(
    policy_version: String,
    fallback_context: FallbackContext,
    mode: SelectionMode,
    revisions: RevisionIdentity,
) -> Result<SelectionPlan> {
    let reason = fallback_context.code.reason();
    SelectionPlan::new(SelectionInput {
        policy_version,
        mode,
        decision_reason: reason,
        fallback_context: Some(fallback_context),
        revisions,
        affected_packages: BTreeSet::new(),
        public_api: PublicApiInput::CompleteInternal,
        test_packages: BTreeSet::new(),
        integration_units: BTreeSet::new(),
        unknown_paths: BTreeSet::new(),
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

fn pull_request_projection(
    root: &Path,
    command_facts: &CommandWorkspaceFacts,
    base: &str,
    head: &str,
    merge_base: &str,
) -> std::result::Result<RemoteProjection, PlannerFailure> {
    let shallow = git_stdout(root, ["rev-parse", "--is-shallow-repository"])
        .map_err(|_| PlannerFailure::new(FallbackCode::DiffUnavailable, None))?;
    if shallow.trim() != "false" {
        return Err(PlannerFailure::new(FallbackCode::ShallowRepository, None));
    }
    let entries = read_diff(root, base, head)
        .map_err(|_| PlannerFailure::new(FallbackCode::GitDiffUnavailable, None))?;
    let facts = workspace_facts_for_impact(&entries, command_facts).map_err(|_| {
        PlannerFailure::new(
            FallbackCode::MetadataUnavailable,
            Some("Cargo.toml".to_owned()),
        )
    })?;
    match facts {
        None => try_impact_entries(&entries, None, &BTreeSet::new(), &BTreeMap::new())
            .map(|impact| RemoteProjection::from(&impact))
            .map_err(|_| PlannerFailure::new(FallbackCode::DiffUnavailable, None)),
        Some(facts) => impact_with_facts(root, &entries, facts, merge_base)
            .map(|impact| RemoteProjection::from(&impact))
            .map_err(|_| {
                let subject = entries
                    .iter()
                    .find(|entry| {
                        entry.path.starts_with("contracts/") || entry.path.starts_with("generated/")
                    })
                    .map(|entry| entry.path.clone());
                PlannerFailure::new(FallbackCode::ContractUnavailable, subject)
            }),
    }
}

pub(crate) fn run_local(root: &Path, options: &LocalOptions) -> Result<()> {
    let clock = SystemLocalClock;
    let run_started = clock.now();
    let worker = LocalWorkerProvenance::from_environment()?.context(
        "ci local 必须通过 make ci 或 ./hack/cargo.sh xtask ci local 的 committed-snapshot supervisor 启动",
    )?;
    let context = LocalExecutionContext::from_worker(root, options.base_ref(), &worker)?;
    let entries = context.diff_entries()?;
    let command_facts = CommandWorkspaceFacts::new(context.root());
    let impact = context
        .impact_entries(&entries, &command_facts)
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
        expand_local_cargo_targets(projected, command_facts.get()?)?
    } else {
        projected
    };
    let steps = scope_xtask_unit_test_steps(steps, &impact, &entries);
    let only = options.only_set();
    let steps = select_local_steps(steps, &only)?;
    if steps.is_empty() {
        eprintln!("ci local：<base>...HEAD 无需执行本地步骤");
        return Ok(());
    }
    if only.is_empty() {
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
    let execution_policy = crate::cmd::ExecutionPolicy::from_fail_fast(options.fail_fast());
    let mut index = 0;
    execute_local_steps(&steps, execution_policy, |step| {
        index += 1;
        eprintln!("ci local：[{}/{}] {}", index, steps.len(), step.label());
        let step_started = clock.now();
        let result = run_local_step(&context, step, execution_policy);
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
    if only.is_empty() {
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
            ImpactSet::escalated(EscalationCause::FallbackUncertainty)
        },
        |context| {
            let command_facts = CommandWorkspaceFacts::new(context.root());
            context.impact_or_full(&command_facts)
        },
    )
}

#[derive(Debug)]
struct LocalWorkerProvenance {
    caller_worktree: PathBuf,
    snapshot_root: PathBuf,
    head: String,
    base: String,
    merge_base: String,
}

impl LocalWorkerProvenance {
    fn from_environment() -> Result<Option<Self>> {
        let values = LOCAL_PRIVATE_ENV
            .iter()
            .map(|name| (*name, env::var_os(name)))
            .collect::<BTreeMap<_, _>>();
        if values.values().all(Option::is_none) {
            return Ok(None);
        }
        let required = |name: &'static str| -> Result<String> {
            values
                .get(name)
                .and_then(Option::as_ref)
                .context(format!("local CI provenance is partial: {name}"))?
                .clone()
                .into_string()
                .map_err(|_| anyhow::anyhow!("local CI provenance is not UTF-8: {name}"))
        };
        if required(LOCAL_WORKER_ENV)? != "1" || required(LOCAL_SUPERVISED_ENV)? != "1" {
            bail!("local CI worker and supervision markers must both equal 1");
        }
        validate_local_handshake(
            &required(LOCAL_HANDSHAKE_FD_ENV)?,
            &required(LOCAL_HANDSHAKE_TOKEN_ENV)?,
        )?;
        required(LOCAL_DEADLINE_ENV)?
            .parse::<f64>()
            .context("local CI deadline is malformed")?;
        required(LOCAL_CALLER_BRANCH_ENV)?;
        let head = required(LOCAL_HEAD_ENV)?;
        let base = required(LOCAL_BASE_ENV)?;
        let merge_base = required(LOCAL_MERGE_BASE_ENV)?;
        validate_revision(&head, "local worker HEAD")?;
        validate_revision(&base, "local worker base")?;
        validate_revision(&merge_base, "local worker merge-base")?;
        Ok(Some(Self {
            caller_worktree: PathBuf::from(required(LOCAL_CALLER_WORKTREE_ENV)?),
            snapshot_root: PathBuf::from(required(LOCAL_SNAPSHOT_ROOT_ENV)?),
            head,
            base,
            merge_base,
        }))
    }
}

fn validate_local_handshake(descriptor: &str, token: &str) -> Result<()> {
    let descriptor = descriptor
        .parse::<i32>()
        .context("local CI handshake descriptor is malformed")?;
    if descriptor < 0 || token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("local CI handshake is malformed");
    }
    let expected = token
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).context("local CI handshake token is not UTF-8")?;
            u8::from_str_radix(text, 16).context("local CI handshake token is not hexadecimal")
        })
        .collect::<Result<Vec<_>>>()?;
    let handshake = File::open(format!("/dev/fd/{descriptor}"))
        .context("open inherited local CI handshake descriptor")?;
    let mut observed = [0_u8; 32];
    (&handshake)
        .read_exact(&mut observed)
        .context("read inherited local CI handshake")?;
    if observed.as_slice() != expected.as_slice() {
        bail!("local CI handshake token does not match inherited descriptor");
    }
    Ok(())
}

enum LocalSource {
    #[cfg(test)]
    Committed(CommittedSnapshot),
    Worker(PathBuf),
}

impl LocalSource {
    fn root(&self) -> &Path {
        match self {
            #[cfg(test)]
            Self::Committed(snapshot) => snapshot.root(),
            Self::Worker(root) => root,
        }
    }
}

/// Immutable source identity shared by local impact analysis and every selected gate.
struct LocalExecutionContext {
    base: String,
    head: String,
    merge_base: String,
    cargo_target: PathBuf,
    source: LocalSource,
}

impl LocalExecutionContext {
    #[cfg(test)]
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
            source: LocalSource::Committed(snapshot),
        })
    }

    fn from_worker(repository: &Path, base: &str, worker: &LocalWorkerProvenance) -> Result<Self> {
        let root = fs::canonicalize(repository).context("canonicalize local worker root")?;
        let expected_root = fs::canonicalize(&worker.snapshot_root)
            .context("canonicalize expected local worker snapshot root")?;
        if root != expected_root {
            bail!("local worker workspace root does not match committed snapshot root");
        }
        let current = env::current_dir()
            .context("read local worker current directory")?
            .canonicalize()
            .context("canonicalize local worker current directory")?;
        if current != root {
            bail!("local worker current directory does not match compiled workspace root");
        }
        if base != worker.base {
            bail!("local worker --base does not match captured base revision");
        }
        let observed_head = git_stdout(&root, ["rev-parse", "--verify", "HEAD"])?;
        if observed_head.trim() != worker.head {
            bail!("local worker HEAD does not match captured committed HEAD");
        }
        let symbolic = external_cmd(
            ExternalProgram::SystemGit,
            &["symbolic-ref", "--quiet", "HEAD"],
            &[],
            Some(&root),
        )
        .status()
        .context("inspect local worker detached HEAD")?;
        if symbolic.success() {
            bail!("local worker snapshot must use detached HEAD");
        }
        let dirty = git_stdout(&root, ["status", "--porcelain", "--untracked-files=all"])?;
        if !dirty.is_empty() {
            bail!("local worker committed snapshot is dirty");
        }
        let observed_merge = git_stdout(
            &root,
            ["merge-base", worker.base.as_str(), worker.head.as_str()],
        )?;
        if observed_merge.trim() != worker.merge_base {
            bail!("local worker merge-base does not match captured revision identity");
        }
        let caller = fs::canonicalize(&worker.caller_worktree)
            .context("canonicalize local worker caller worktree")?;
        if caller == root {
            bail!("local worker caller worktree must differ from committed snapshot root");
        }
        let cargo_target = env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .context("local worker requires CARGO_TARGET_DIR from the controlled wrapper")?;
        Ok(Self {
            base: worker.base.clone(),
            head: worker.head.clone(),
            merge_base: worker.merge_base.clone(),
            cargo_target,
            source: LocalSource::Worker(root),
        })
    }

    fn root(&self) -> &Path {
        self.source.root()
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
    fn impact(&self, command_facts: &CommandWorkspaceFacts) -> Result<ImpactSet> {
        let entries = self.diff_entries()?;
        self.impact_entries(&entries, command_facts)
    }

    fn impact_entries(
        &self,
        entries: &[DiffEntry],
        command_facts: &CommandWorkspaceFacts,
    ) -> Result<ImpactSet> {
        if let PlannerCatalog::FactsUnavailable(error) =
            validate_planner_catalog(self.root(), command_facts)?
        {
            return Err(error);
        }
        match workspace_facts_for_impact(entries, command_facts)? {
            Some(facts) => impact_with_facts(self.root(), entries, facts, &self.merge_base),
            None => try_impact_entries(entries, None, &BTreeSet::new(), &BTreeMap::new()),
        }
    }

    #[cfg(test)]
    fn impact_or_full(&self, command_facts: &CommandWorkspaceFacts) -> ImpactSet {
        self.impact(command_facts).unwrap_or_else(|error| {
            eprintln!("ci local：影响分析失败，fail-safe 到完整 verify：{error:#}");
            ImpactSet::escalated(EscalationCause::FallbackUncertainty)
        })
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// An isolated checkout of one committed revision. Local impact classification must not read
/// manifests, contract metadata, generated files, or package topology from the caller's dirty
/// working tree after the diff revisions have been resolved.
#[cfg(test)]
struct CommittedSnapshot {
    scratch: PathBuf,
    root: PathBuf,
    persistent: bool,
}

#[cfg(test)]
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

#[cfg(test)]
impl Drop for CommittedSnapshot {
    fn drop(&mut self) {
        if !self.persistent {
            let _ = fs::remove_dir_all(&self.scratch);
        }
    }
}

#[cfg(test)]
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
            Self::PublicApi(_) => LocalStage::Meta,
            Self::CompleteInternalPublicApi => LocalStage::Meta,
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
            Self::PublicApi(packages) => {
                format!("public-api affected {}", packages.join(","))
            }
            Self::CompleteInternalPublicApi => "public-api complete internal".to_owned(),
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
                        target.display_label()
                    )
                },
            ),
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

fn expand_local_cargo_targets(
    steps: Vec<LocalStep>,
    facts: &WorkspaceFacts,
) -> Result<Vec<LocalStep>> {
    let mut expanded = Vec::new();
    for step in steps {
        match step {
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
                for package in packages {
                    for target in local_cargo_targets(facts, &package, operation)? {
                        expanded.push(LocalStep::Packages {
                            operation,
                            packages: vec![package.clone()],
                            target: Some(target),
                            check_includes_lib,
                        });
                    }
                }
            }
            other => expanded.push(other),
        }
    }
    Ok(expanded)
}

fn scope_xtask_unit_test_steps(
    steps: Vec<LocalStep>,
    impact: &ImpactSet,
    entries: &[DiffEntry],
) -> Vec<LocalStep> {
    if !matches!(impact, ImpactSet::Selective(_)) {
        return steps;
    }
    let Some(filters) = xtask_unit_test_filters(entries) else {
        return steps;
    };
    steps
        .into_iter()
        .flat_map(|step| match step {
            LocalStep::Packages {
                operation: LocalCargoOperation::Test,
                packages,
                target: Some(LocalCargoTarget::Bin(name)),
                check_includes_lib,
            } if packages == ["xtask"] && name == "xtask" => filters
                .iter()
                .cloned()
                .map(|filter| LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: packages.clone(),
                    target: Some(LocalCargoTarget::BinTestFilter {
                        name: name.clone(),
                        filter,
                    }),
                    check_includes_lib,
                })
                .collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect()
}

fn xtask_unit_test_filters(entries: &[DiffEntry]) -> Option<BTreeSet<String>> {
    let paths = entries
        .iter()
        .map(|entry| entry.path.as_str())
        .filter(|path| path.starts_with("xtask/"))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return None;
    }
    let mut filters = BTreeSet::new();
    for path in paths {
        let scope = LOCAL_CI_XTASK_SCOPES
            .iter()
            .find_map(|(candidate, scope)| (*candidate == path).then_some(*scope))?;
        match scope {
            XtaskTestScope::Filters(scoped) => {
                filters.extend(scoped.iter().map(|filter| (*filter).to_owned()));
            }
            XtaskTestScope::Complete => return None,
        }
    }
    (!filters.is_empty()).then_some(filters)
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

fn run_local_step(
    context: &LocalExecutionContext,
    step: &LocalStep,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    match step {
        LocalStep::Meta(gates) => crate::verify::run_local_meta(
            context.root(),
            gates,
            &context.merge_base,
            execution_policy,
        ),
        LocalStep::PublicApi(packages) => {
            let command_facts = CommandWorkspaceFacts::new(context.root());
            crate::publicapi::run_affected_internal_check(
                context.root(),
                command_facts.get()?,
                packages,
            )
        }
        LocalStep::CompleteInternalPublicApi => {
            let command_facts = CommandWorkspaceFacts::new(context.root());
            crate::publicapi::run_complete_internal_check(context.root(), command_facts.get()?)
        }
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
    if operation == LocalCargoOperation::Clippy {
        owned.push("--no-deps".to_owned());
    }
    // Check uses lib+bins only: `--all-targets` plus multi-package reverse closure can
    // activate `testkit`'s `containers` cfg without linking optional deps (feature-unification
    // interaction with integration-gated test targets). Clippy keeps `--all-targets` for lint
    // coverage. Test/clippy add only the shared typed deterministic component features; integration
    // feature matrices remain outside the local preflight plan.
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
        (LocalCargoOperation::Test, Some(LocalCargoTarget::BinTestFilter { name, .. })) => {
            owned.extend(["--bin".to_owned(), name.clone()])
        }
        (LocalCargoOperation::Clippy, Some(LocalCargoTarget::BinTestFilter { .. })) => {
            bail!("filtered bin target is valid only for local tests")
        }
        (
            LocalCargoOperation::Test | LocalCargoOperation::Clippy,
            Some(LocalCargoTarget::Test { name, .. }),
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
    let mut features = BTreeSet::new();
    if let Some(LocalCargoTarget::Test {
        required_features, ..
    }) = target
    {
        features.extend(required_features.iter().cloned());
    }
    if matches!(
        operation,
        LocalCargoOperation::Test | LocalCargoOperation::Clippy
    ) {
        features.extend(crate::nextest::deterministic_test_feature_args(Some(
            packages,
        )));
    }
    if !features.is_empty() {
        owned.extend([
            "--features".to_owned(),
            features.into_iter().collect::<Vec<_>>().join(","),
        ]);
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
    if let (LocalCargoOperation::Test, Some(LocalCargoTarget::BinTestFilter { filter, .. })) =
        (operation, target)
    {
        owned.push("--".to_owned());
        owned.push(filter.clone());
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
        match status {
            "A" | "M" | "D" => {
                let Some(raw_path) = fields.get(index) else {
                    bail!("truncated git diff record");
                };
                let path = std::str::from_utf8(raw_path)
                    .context("non-UTF-8 diff path")?
                    .to_owned();
                index += 1;
                let status = match status {
                    "A" => DiffStatus::Added,
                    "M" => DiffStatus::Modified,
                    "D" => DiffStatus::Deleted,
                    _ => bail!("validated diff status `{status}` escaped closed mapping"),
                };
                entries.push(DiffEntry {
                    status,
                    path,
                    rename_or_copy: false,
                });
            }
            value if valid_similarity_status(value, 'R') || valid_similarity_status(value, 'C') => {
                if index + 2 > fields.len() {
                    bail!("truncated git diff record");
                }
                let old_path = std::str::from_utf8(fields[index])
                    .context("non-UTF-8 old diff path")?
                    .to_owned();
                let new_path = std::str::from_utf8(fields[index + 1])
                    .context("non-UTF-8 new diff path")?
                    .to_owned();
                index += 2;
                entries.push(DiffEntry {
                    status: DiffStatus::Deleted,
                    path: old_path,
                    rename_or_copy: true,
                });
                entries.push(DiffEntry {
                    status: DiffStatus::Added,
                    path: new_path,
                    rename_or_copy: true,
                });
            }
            _ => bail!("unknown git diff status"),
        }
    }
    Ok(entries)
}

fn valid_similarity_status(value: &str, prefix: char) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|score| !score.is_empty() && score.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
#[allow(clippy::expect_used)] // reason: path-only test helper has no fallible workspace-facts query.
fn classify_diff(entries: &[DiffEntry]) -> RemoteProjection {
    RemoteProjection::from(
        &try_impact_entries(entries, None, &BTreeSet::new(), &BTreeMap::new())
            .expect("path-only impact classification is infallible"),
    )
}

#[cfg(test)]
fn classify_with_facts(
    root: &Path,
    entries: &[DiffEntry],
    facts: &WorkspaceFacts,
    merge_base: &str,
) -> Result<RemoteProjection> {
    let internal_owners = facts
        .workspace_packages()
        .into_iter()
        .map(|package| package.key().as_str().to_owned())
        .filter(|package| crate::publicapi::target_crates(None).contains(&package.as_str()))
        .collect::<BTreeSet<_>>();
    Ok(RemoteProjection::from(&impact_with_facts_and_owners(
        root,
        entries,
        facts,
        merge_base,
        Some(&internal_owners),
    )?))
}

fn impact_with_facts(
    root: &Path,
    entries: &[DiffEntry],
    facts: &WorkspaceFacts,
    merge_base: &str,
) -> Result<ImpactSet> {
    impact_with_facts_and_owners(root, entries, facts, merge_base, None)
}

enum PlannerCatalog {
    Available,
    FactsUnavailable(anyhow::Error),
}

/// Production planning boundary: successful Cargo facts must match the integration catalog.
/// Facts acquisition failure remains distinct so remote planning can emit its typed conservative
/// fallback while local impact analysis preserves its fail-closed diagnostic.
fn validate_planner_catalog(
    root: &Path,
    command_facts: &CommandWorkspaceFacts,
) -> Result<PlannerCatalog> {
    let facts = match command_facts.get() {
        Ok(facts) => facts,
        Err(error) => {
            return Ok(PlannerCatalog::FactsUnavailable(error.context(
                "load workspace facts for affected integration catalog closure",
            )));
        }
    };
    integration_shards::validate_catalog_facts(root, facts)?;
    Ok(PlannerCatalog::Available)
}

fn impact_with_facts_and_owners(
    root: &Path,
    entries: &[DiffEntry],
    facts: &WorkspaceFacts,
    merge_base: &str,
    internal_owners: Option<&BTreeSet<String>>,
) -> Result<ImpactSet> {
    let affected_internal = |candidates: &BTreeSet<String>| -> Result<BTreeSet<String>> {
        internal_owners.map_or_else(
            || crate::publicapi::affected_internal_packages(root, facts, candidates),
            |owners| Ok(candidates.intersection(owners).cloned().collect()),
        )
    };
    let path_packages = entries
        .iter()
        .map(|entry| facts.package_for_repo_path(Path::new(&entry.path)))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .map(|package| package.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if let Some(cause) = immediate_escalation_cause(entries) {
        return Ok(ImpactSet::Escalated {
            cause,
            public_api_packages: affected_internal(&path_packages)?,
        });
    }
    let mut direct = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    for entry in entries {
        if device_latent_candidate_impact_path(&entry.path) {
            continue;
        }
        // Same documentation gate as classify_selective_entry: governance docs under
        // contracts/ (e.g. README.md) must not enter contract.toml manifest impact.
        if entry.path.starts_with("contracts/") && !documentation(&entry.path) {
            let packages = contract_package_impacts(root, &entry.path, entry.status, merge_base)?;
            if packages.is_empty()
                || packages
                    .keys()
                    .any(|package| facts.package_key(package).is_err())
            {
                bail!("contract owner or subscriber is outside the workspace catalog");
            }
            if packages
                .keys()
                .any(|package| ImpactMarker::for_package(package).is_none())
            {
                bail!(
                    "contract owner or subscriber is outside the closed integration impact relation"
                );
            }
            for (package, reasons) in packages {
                direct.entry(package).or_default().extend(reasons);
            }
        } else if entry.path.starts_with("generated/src/") && !generated_entrypoint(&entry.path) {
            let domain = generated_domain(&entry.path)
                .context("generated source path has no closed domain identity")?;
            if facts.package_key(&domain).is_err() {
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
            .filter(|entry| !device_latent_candidate_impact_path(&entry.path))
            .map(|entry| facts.package_for_repo_path(Path::new(&entry.path)))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .map(|package| package.as_str().to_owned()),
    );
    let closure = reverse_closure(facts, &impacted)?;
    let public_api_packages = affected_internal(&impacted)?;
    let mut impact = try_impact_entries(entries, Some(facts), &closure, &direct)?;
    if let ImpactSet::Selective(selective) = &mut impact {
        selective.public_api_packages = public_api_packages;
    }
    Ok(impact)
}

fn changed_integration_sources(
    entries: &[DiffEntry],
) -> Option<(BTreeSet<IntegrationUnitId>, BTreeSet<&str>)> {
    let mut units = BTreeSet::new();
    let mut exact_paths = BTreeSet::new();
    for entry in entries {
        if device_latent_candidate_impact_path(&entry.path) {
            continue;
        }
        match integration_shards::changed_integration_source(&entry.path) {
            Some(ChangedIntegrationSource::Exact(selected)) => {
                units.extend(selected);
                exact_paths.insert(entry.path.as_str());
            }
            Some(ChangedIntegrationSource::ReleaseCheck) => return None,
            None => {}
        }
    }
    Some((units, exact_paths))
}

fn try_impact_entries(
    entries: &[DiffEntry],
    facts: Option<&WorkspaceFacts>,
    closure: &BTreeSet<String>,
    seeded_packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
) -> Result<ImpactSet> {
    if let Some(cause) = immediate_escalation_cause(entries) {
        return Ok(ImpactSet::escalated(cause));
    }
    if entries.is_empty() {
        return Ok(ImpactSet::Empty);
    }
    let mut documentation_only = false;
    let mut packages = seeded_packages.clone();
    let mut governance = BTreeSet::new();
    let mut local_meta_domains = BTreeSet::new();
    let mut unknown_paths = BTreeSet::new();
    for entry in entries {
        documentation_only |= classify_selective_entry(
            entry,
            facts,
            &mut packages,
            &mut governance,
            &mut local_meta_domains,
            &mut unknown_paths,
        )?;
    }
    let Some((exact_units, exact_source_paths)) = changed_integration_sources(entries) else {
        return Ok(ImpactSet::escalated(EscalationCause::GlobalImpact));
    };
    let exact_packages = exact_units
        .iter()
        .map(|id| id.spec().package.to_owned())
        .collect::<BTreeSet<_>>();
    let non_exact_packages = entries
        .iter()
        .map(|entry| -> Result<Option<String>> {
            let package = match facts {
                Some(facts) => facts
                    .package_for_repo_path(Path::new(&entry.path))?
                    .map(|package| package.as_str().to_owned()),
                None => path_package(&entry.path),
            };
            Ok(package.filter(|_| !exact_source_paths.contains(entry.path.as_str())))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>();
    let mut markers = BTreeSet::new();
    let mut resources = BTreeSet::new();
    let mut providers = BTreeSet::new();
    add_device_certificate_candidate_impact(entries, facts, &mut packages, &mut markers)?;
    add_vault_pki_seam_impact(entries, &mut markers);
    for (package, reasons) in &packages {
        let has_structured_relation = reasons.iter().any(|impact| {
            matches!(
                impact,
                PackageImpact::ContractOwner
                    | PackageImpact::ContractSubscriber
                    | PackageImpact::Generated
            )
        });
        if exact_packages.contains(package)
            && !non_exact_packages.contains(package)
            && !has_structured_relation
        {
            continue;
        }
        let source_or_test = reasons.iter().any(|impact| {
            matches!(
                impact,
                PackageImpact::Source | PackageImpact::Test | PackageImpact::Manifest
            )
        });
        if source_or_test && let Some(adapter) = AdapterPackage::for_package(package) {
            match adapter.projection() {
                AdapterProjection::Resource(resource) => {
                    resources.insert(resource);
                }
                AdapterProjection::SecurityProvider(provider) => {
                    providers.insert(provider);
                }
            }
            continue;
        }
        if package == "runtime" && source_or_test {
            markers.insert(ImpactMarker::RuntimeSurface);
        } else if let Some(marker) = ImpactMarker::for_package(package) {
            markers.insert(marker);
        }
        if reasons.iter().any(|impact| {
            matches!(
                impact,
                PackageImpact::ContractOwner | PackageImpact::ContractSubscriber
            )
        }) && matches!(
            ImpactMarker::for_package(package),
            Some(
                ImpactMarker::AuditPackage
                    | ImpactMarker::AuthnPackage
                    | ImpactMarker::IdentityPackage
                    | ImpactMarker::SettingsPackage
                    | ImpactMarker::PostgresPackage
            )
        ) {
            markers.insert(ImpactMarker::LocalTxContract);
        }
    }
    let mut selected_units = exact_units;
    selected_units.extend(integration_shards::critical_units_for_markers(&markers));
    for resource in resources {
        selected_units.extend(integration_shards::critical_units_for_resource(resource));
    }
    for provider in providers {
        let Some(units) = integration_shards::critical_units_for_provider(provider) else {
            return Ok(ImpactSet::escalated(EscalationCause::GlobalImpact));
        };
        selected_units.extend(units);
    }
    let packages_with_tests = match facts {
        Some(facts) => package_names_with_test_targets(facts, &packages, closure)?,
        None => packages
            .keys()
            .cloned()
            .chain(closure.iter().cloned())
            .collect(),
    };
    let check_includes_lib = match facts {
        Some(facts) => closure
            .iter()
            .map(|name| package_has_lib_target(facts, name))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .any(|has_lib| has_lib),
        // Without metadata, preserve historical `--lib --bins` (fail closed on unknown).
        None => true,
    };
    let coverage_closure = coverage_closure_for(facts, &packages, closure)?;
    Ok(ImpactSet::Selective(SelectiveImpact {
        documentation: documentation_only,
        packages,
        reverse_closure: closure.clone(),
        coverage_closure,
        packages_with_tests,
        check_includes_lib,
        integration_units: selected_units,
        governance,
        local_meta_domains,
        unknown_paths,
        public_api_packages: BTreeSet::new(),
    }))
}

fn add_device_certificate_candidate_impact(
    entries: &[DiffEntry],
    facts: Option<&WorkspaceFacts>,
    packages: &mut BTreeMap<String, BTreeSet<PackageImpact>>,
    markers: &mut BTreeSet<ImpactMarker>,
) -> Result<()> {
    if !entries
        .iter()
        .any(|entry| device_latent_semantic_impact_path(&entry.path))
    {
        return Ok(());
    }
    markers.insert(ImpactMarker::DeviceCertificateCandidate);
    for evidence in DeviceLatentEvidenceId::ALL
        .into_iter()
        .map(DeviceLatentEvidenceId::spec)
        .filter(|spec| spec.owner == ExecutionUnitId::Gate(GateId::ComponentTests))
    {
        let package = match facts {
            Some(facts) => facts
                .package_for_repo_path(Path::new(evidence.source_path))?
                .map(|package| package.as_str().to_owned()),
            None => path_package(evidence.source_path),
        };
        if let Some(package) = package {
            packages
                .entry(package)
                .or_default()
                .insert(PackageImpact::Test);
        }
    }
    Ok(())
}

fn add_vault_pki_seam_impact(entries: &[DiffEntry], markers: &mut BTreeSet<ImpactMarker>) {
    const VAULT_PKI_SEAM_PATHS: &[&str] = &[
        "crates/diport/src/pki_artifact.rs",
        "crates/diport/src/lib.rs",
    ];
    if entries
        .iter()
        .any(|entry| VAULT_PKI_SEAM_PATHS.contains(&entry.path.as_str()))
    {
        markers.insert(ImpactMarker::VaultProvider);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // reason: callers provide validated synthetic facts and repo-relative paths.
fn impact_entries(
    entries: &[DiffEntry],
    facts: Option<&WorkspaceFacts>,
    closure: &BTreeSet<String>,
    seeded_packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
) -> ImpactSet {
    try_impact_entries(entries, facts, closure, seeded_packages)
        .expect("valid test workspace facts and repo-relative paths")
}

fn classify_selective_entry(
    entry: &DiffEntry,
    facts: Option<&WorkspaceFacts>,
    packages: &mut BTreeMap<String, BTreeSet<PackageImpact>>,
    governance: &mut BTreeSet<GovernanceImpact>,
    local_meta_domains: &mut BTreeSet<LocalImpactDomain>,
    unknown_paths: &mut BTreeSet<String>,
) -> Result<bool> {
    let path = entry.path.as_str();
    local_meta_domains.extend(local_impact_domains(path));
    if device_latent_candidate_impact_path(path) {
        return Ok(false);
    }
    if let Some(impact) = governance_impact(path) {
        governance.insert(impact);
        return Ok(true);
    }
    if documentation(path) {
        return Ok(true);
    }
    if path.starts_with("contracts/") {
        if facts.is_none() {
            packages
                .entry("contract-owner".to_owned())
                .or_default()
                .insert(PackageImpact::ContractOwner);
        }
        return Ok(false);
    }
    if path.starts_with("generated/src/") {
        if facts.is_none() {
            packages
                .entry("generated-domain".to_owned())
                .or_default()
                .insert(PackageImpact::Generated);
        }
        return Ok(false);
    }
    let package = match facts {
        Some(facts) => facts
            .package_for_repo_path(Path::new(path))?
            .map(|package| package.as_str().to_owned()),
        None => path_package(path),
    };
    let Some(package) = package else {
        unknown_paths.insert(path.to_owned());
        return Ok(false);
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
    Ok(false)
}

fn local_impact_domains(path: &str) -> BTreeSet<LocalImpactDomain> {
    use LocalImpactDomain as Domain;

    const SHARED_POLICY_PATHS: &[&str] = &[
        "xtask/src/ci_lanes.rs",
        "xtask/src/ci_impact.rs",
        "xtask/src/cli.rs",
        "xtask/src/report_format.rs",
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
        "xtask/runtime-deps-guard.toml",
    ];
    const EVENT_TRANSPORT_SCAN_PREFIXES: &[&str] =
        &["crates/", "adapters/", "assemblies/", "bins/", "journeys/"];
    const RUNTIME_DOC_PREFIXES: &[&str] = &["docs/rules/"];
    const OUTBOX_SAME_ID_CARRIER_PREFIXES: &[&str] = &[
        "lints/rss_operator_authorization_callsite/",
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
    ];
    const ASSEMBLY_CARRIERS: &[&str] = &[
        "xtask/src/assembly_artifacts.rs",
        "xtask/src/assembly_codegen.rs",
        "xtask/src/assembly_lock.rs",
        "xtask/src/assembly_runtime_plan.rs",
        "xtask/src/graph.rs",
        ".gitattributes",
        ".dockerignore",
        "Dockerfile",
    ];
    const CONSISTENCY_PREFIXES: &[&str] = &[
        "crates/consistency/",
        // LocalTx/LocalOnly scanners load Cargo inventory exclusively via workspacefacts;
        // a Cargo.toml-only edit must schedule those gates (Cargo.toml is not `.rs`).
        "crates/workspacefacts/",
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
        "xtask/src/pg_tenant_tx_guard.rs",
        "xtask/src/repo_scope_guard.rs",
        "xtask/src/tenancy_closeout.rs",
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

fn device_latent_candidate_impact_path(path: &str) -> bool {
    path == "generated/src/device_certificate.rs"
        || crate::contract::DeviceCertificateCandidateId::ALL
            .into_iter()
            .map(crate::contract::DeviceCertificateCandidateId::spec)
            .any(|candidate| {
                path == candidate.source_dir
                    || path.starts_with(&format!("{}/", candidate.source_dir))
            })
}

fn device_latent_evidence_impact_path(path: &str) -> bool {
    DeviceLatentEvidenceId::ALL
        .into_iter()
        .map(DeviceLatentEvidenceId::spec)
        .any(|evidence| path == evidence.source_path)
}

fn device_latent_semantic_impact_path(path: &str) -> bool {
    device_latent_candidate_impact_path(path) || device_latent_evidence_impact_path(path)
}

fn coverage_closure_for(
    facts: Option<&WorkspaceFacts>,
    packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
    closure: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let seeds = packages
        .iter()
        .filter(|(_, impacts)| impacts.iter().any(|impact| impact.is_coverage_seed()))
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    if seeds.is_empty() {
        return Ok(BTreeSet::new());
    }
    match facts {
        Some(facts) => reverse_closure(facts, &seeds),
        None => {
            let mut coverage_closure = closure.clone();
            coverage_closure.extend(seeds);
            Ok(coverage_closure)
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

fn immediate_escalation_cause(entries: &[DiffEntry]) -> Option<EscalationCause> {
    if entries
        .iter()
        .any(|entry| entry.rename_or_copy && entry.path.starts_with("contracts/"))
    {
        return Some(EscalationCause::RenameOrCopy);
    }
    entries.iter().find_map(|entry| {
        let path = entry.path.as_str();
        if machine_input(path) || high_impact(path) || generated_entrypoint(path) {
            return Some(EscalationCause::GlobalImpact);
        }
        None
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
    if changed_path.starts_with("contracts/components/") {
        let component_id = ComponentId::from_repository_path(changed_path)?
            .context("changed component path did not identify a schema component")?;
        return component_package_impacts(root, &component_id, changed_path, status, merge_base);
    }
    let manifest_path =
        contract_manifest_path(changed_path).context("contract path has no manifest")?;
    let absolute = root.join(&manifest_path);
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    let mut extend = |source: &str, origin: &str| -> Result<()> {
        for (package, reasons) in
            contract_manifest_impacts(root, source).with_context(|| origin.to_owned())?
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
    }
    Ok(packages)
}

fn component_package_impacts(
    root: &Path,
    component_id: &ComponentId,
    changed_path: &str,
    status: DiffStatus,
    merge_base: &str,
) -> Result<BTreeMap<String, BTreeSet<PackageImpact>>> {
    let working = match status {
        DiffStatus::Added | DiffStatus::Modified => {
            working_component_consumers(root, component_id)?
        }
        DiffStatus::Deleted if root.join(changed_path).is_file() => {
            working_component_consumers(root, component_id)?
        }
        DiffStatus::Deleted => BTreeSet::new(),
    };
    let base = match status {
        DiffStatus::Added => BTreeSet::new(),
        DiffStatus::Modified | DiffStatus::Deleted => {
            base_component_consumers(root, merge_base, component_id)?
        }
    };
    if working.is_empty() && base.is_empty() {
        bail!("changed contract component has no working or merge-base consumer");
    }
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    for manifest_path in working {
        let current = root.join(&manifest_path);
        let source = fs::read_to_string(&current)
            .with_context(|| format!("read working component consumer {}", current.display()))?;
        merge_contract_impacts(root, &source, &mut packages)?;
    }
    for manifest_path in base {
        let source = git_stdout(root, ["show", &format!("{merge_base}:{manifest_path}")])
            .with_context(|| format!("read merge-base component consumer {manifest_path}"))?;
        merge_contract_impacts(root, &source, &mut packages)?;
    }
    Ok(packages)
}

fn merge_contract_impacts(
    root: &Path,
    source: &str,
    packages: &mut BTreeMap<String, BTreeSet<PackageImpact>>,
) -> Result<()> {
    for (package, reasons) in contract_manifest_impacts(root, source)? {
        packages.entry(package).or_default().extend(reasons);
    }
    Ok(())
}

fn working_component_consumers(
    root: &Path,
    component_id: &ComponentId,
) -> Result<BTreeSet<String>> {
    let mut files = Vec::new();
    collect_regular_files(&root.join("contracts"), &mut files)?;
    let files = files
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("schema path escaped workspace: {}", path.display()))?
                .to_string_lossy()
                .to_string();
            let source = fs::read_to_string(&path)
                .with_context(|| format!("read working component graph node {}", path.display()))?;
            Ok((relative, source))
        })
        .collect::<Result<Vec<_>>>()?;
    component_consumers_from_files(component_id, files)
}

fn base_component_consumers(
    root: &Path,
    merge_base: &str,
    component_id: &ComponentId,
) -> Result<BTreeSet<String>> {
    let listing = git_stdout(
        root,
        ["ls-tree", "-r", "--name-only", merge_base, "contracts"],
    )?;
    let files = listing
        .lines()
        .filter(|path| path.ends_with(".schema.json"))
        .map(|path| {
            let source = git_stdout(root, ["show", &format!("{merge_base}:{path}")])
                .with_context(|| format!("read merge-base component graph node {path}"))?;
            Ok((path.to_string(), source))
        })
        .collect::<Result<Vec<_>>>()?;
    component_consumers_from_files(component_id, files)
}

fn component_consumers_from_files(
    component_id: &ComponentId,
    files: impl IntoIterator<Item = (String, String)>,
) -> Result<BTreeSet<String>> {
    let documents = files
        .into_iter()
        .map(|(path, source)| {
            let value: serde_json::Value = serde_json::from_str(&source)
                .with_context(|| format!("parse component graph node {path}"))?;
            Ok((path, value))
        })
        .collect::<Result<Vec<_>>>()?;
    let manifests = ComponentGraph::from_documents(documents)?
        .transitive_consumer_paths(component_id)?
        .into_iter()
        .filter_map(|path| contract_manifest_path(&path))
        .collect();
    Ok(manifests)
}

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read contract tree {}", directory.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            bail!(
                "contract component graph rejects symlink {}",
                entry.path().display()
            );
        }
        if file_type.is_dir() {
            collect_regular_files(&entry.path(), files)?;
        } else if entry.path().to_string_lossy().ends_with(".schema.json") {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn contract_manifest_impacts(
    root: &Path,
    source: &str,
) -> Result<BTreeMap<String, BTreeSet<PackageImpact>>> {
    let impact = crate::contract::governance::contract_impact_from_manifest(source)?;
    let mut packages = BTreeMap::<String, BTreeSet<PackageImpact>>::new();
    if let Some(owner) = impact.owner() {
        packages
            .entry(owner.to_owned())
            .or_default()
            .insert(PackageImpact::ContractOwner);
    } else {
        let governance = crate::assembly_governance::AssemblyGovernanceIr::<
            crate::assembly_governance::Core,
        >::load(root)
        .context("load canonical assembly consumers for framework contract")?;
        let consumers = governance
            .assemblies()
            .iter()
            .filter(|assembly| {
                assembly
                    .manifest()
                    .framework_contracts()
                    .iter()
                    .any(|mount| mount.id == impact.id())
            })
            .map(|assembly| assembly.manifest().name().to_owned())
            .collect::<BTreeSet<_>>();
        if consumers.is_empty() {
            bail!(
                "framework contract `{}` has no canonical assembly consumer",
                impact.id()
            );
        }
        for consumer in consumers {
            packages
                .entry(consumer)
                .or_default()
                .insert(PackageImpact::ContractOwner);
        }
    }
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

fn package_key(facts: &WorkspaceFacts, name: &str) -> Result<PackageKey> {
    facts
        .package_key(name)
        .with_context(|| format!("resolve workspace package `{name}`"))
}

fn reverse_closure(facts: &WorkspaceFacts, names: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    if names.is_empty() {
        return Ok(BTreeSet::new());
    }
    let seeds = names
        .iter()
        .map(|name| package_key(facts, name))
        .collect::<Result<BTreeSet<_>>>()?;
    Ok(facts
        .reverse_workspace_closure(&seeds)?
        .into_iter()
        .map(|package| package.as_str().to_owned())
        .collect())
}

fn package_has_test_targets(facts: &WorkspaceFacts, name: &str) -> Result<bool> {
    let key = package_key(facts, name)?;
    Ok(facts.targets_for(&key)?.iter().any(|target| {
        target.test_by_default()
            && matches!(
                target.kind(),
                TargetKind::Library | TargetKind::ProcMacro | TargetKind::Binary | TargetKind::Test
            )
    }))
}

fn package_names_with_test_targets(
    facts: &WorkspaceFacts,
    packages: &BTreeMap<String, BTreeSet<PackageImpact>>,
    closure: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    packages
        .keys()
        .chain(closure)
        .map(|name| Ok((name.clone(), package_has_test_targets(facts, name)?)))
        .filter_map(|result: Result<(String, bool)>| match result {
            Ok((name, true)) => Some(Ok(name)),
            Ok((_, false)) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn package_has_lib_target(facts: &WorkspaceFacts, name: &str) -> Result<bool> {
    let key = package_key(facts, name)?;
    Ok(facts
        .targets_for(&key)?
        .iter()
        .any(|target| matches!(target.kind(), TargetKind::Library | TargetKind::ProcMacro)))
}

fn local_cargo_targets(
    facts: &WorkspaceFacts,
    package: &str,
    operation: LocalCargoOperation,
) -> Result<Vec<LocalCargoTarget>> {
    let key = package_key(facts, package)?;
    let mut targets = BTreeSet::new();
    for target in facts.targets_for(&key)? {
        match target.kind() {
            TargetKind::Library | TargetKind::ProcMacro => {
                targets.insert(LocalCargoTarget::Lib);
            }
            TargetKind::Binary => {
                targets.insert(LocalCargoTarget::Bin(target.name().to_owned()));
            }
            TargetKind::Test
                if !crate::integration_shards::is_remote_only_test_target(
                    package,
                    target.name(),
                ) =>
            {
                targets.insert(LocalCargoTarget::Test {
                    name: target.name().to_owned(),
                    required_features: target.required_features().to_vec(),
                });
            }
            TargetKind::Test
            | TargetKind::Example
            | TargetKind::Benchmark
            | TargetKind::BuildScript
            | TargetKind::Other => {}
        }
    }
    if operation == LocalCargoOperation::Test && targets.contains(&LocalCargoTarget::Lib) {
        targets.insert(LocalCargoTarget::Doc);
    }
    Ok(targets.into_iter().collect())
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
            push_policy_field(&mut material, b"adaptive");
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
    policy_semantic_catalog_with_selector_overrides(behavior_spec, None, None, None)
}

fn policy_semantic_catalog_with_selector_overrides(
    behavior_spec: &str,
    resource_override: Option<(IntegrationUnitId, &'static [Resource])>,
    adapter_override: Option<(AdapterPackage, AdapterProjection)>,
    impact_override: Option<(&'static str, ImpactMarker)>,
) -> Vec<String> {
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
    for mode in [
        SelectionMode::Adaptive,
        SelectionMode::PrComplete,
        SelectionMode::ReleaseCheck,
    ] {
        catalog.push(format!("selection-mode={}", selection_mode_name(mode)));
    }
    for adapter in AdapterPackage::ALL {
        let projection = adapter_override
            .filter(|(candidate, _)| *candidate == adapter)
            .map_or_else(|| adapter.projection(), |(_, projection)| projection);
        catalog.push(format!(
            "integration-adapter-projection={}:{}",
            adapter.package(),
            projection.label()
        ));
    }
    for (package, marker) in ImpactMarker::PACKAGE_RELATIONS {
        let marker = impact_override
            .filter(|(candidate, _)| *candidate == package)
            .map_or(marker, |(_, marker)| marker);
        catalog.push(format!(
            "integration-impact-package={}:{}",
            package,
            marker.label()
        ));
    }
    catalog.extend(integration_shards::shared_source_relation_semantics());
    let release = IntegrationSelection::release_check();
    for shard in IntegrationShard::ALL {
        catalog.push(format!("integration-shard={}", shard.as_str()));
        catalog.push(format!(
            "integration-partition-policy={}",
            match shard.partition_policy() {
                integration_shards::PartitionPolicy::Unpartitioned => "unpartitioned",
                integration_shards::PartitionPolicy::TwoWayHash => "two-way-hash",
            }
        ));
        for batch in integration_shards::batches(&release, *shard) {
            catalog.push(format!("integration-package={}", batch.package));
            catalog.push(format!("integration-filter={}", batch.filter));
        }
    }
    for id in IntegrationUnitId::ALL {
        let spec = id.spec();
        catalog.push(format!("integration-unit={}", id.as_str()));
        catalog.push(format!(
            "integration-unit-owner={}:{}",
            id.as_str(),
            spec.primary_owner.as_str()
        ));
        catalog.push(format!(
            "integration-unit-execution={}:{}:{}:{}:{}:{}:{}",
            id.as_str(),
            spec.shard.as_str(),
            spec.package,
            spec.target,
            spec.kind.as_str(),
            spec.scheduling.label(),
            spec.local_eligibility.label(),
        ));
        catalog.push(format!(
            "integration-unit-feature={}:{}",
            id.as_str(),
            integration_shards::LocalFeatureScope::for_package(spec.package)
                .map_or("", |scope| scope.feature())
        ));
        let resources = resource_override
            .filter(|(override_id, _)| *override_id == id)
            .map_or(spec.resources, |(_, resources)| resources);
        for resource in resources {
            catalog.push(format!(
                "integration-unit-resource={}:{}",
                id.as_str(),
                resource.label()
            ));
        }
        for capability in id.capability_labels() {
            catalog.push(format!(
                "integration-unit-capability={}:{}",
                id.as_str(),
                capability
            ));
        }
        for marker in id.impact_markers() {
            catalog.push(format!(
                "integration-unit-impact={}:{}",
                id.as_str(),
                marker.label()
            ));
        }
    }
    for candidate in crate::contract::DeviceCertificateCandidateId::ALL {
        let spec = candidate.spec();
        catalog.push(format!(
            "device-certificate-candidate={}:{}:{:?}:{:?}:{:?}",
            spec.source_dir, spec.id, spec.kind, spec.consistency_level, spec.lifecycle
        ));
    }
    for evidence in DeviceLatentEvidenceId::ALL {
        let spec = evidence.spec();
        catalog.push(format!(
            "device-latent-evidence={evidence:?}:{}:{:?}:{:?}:{}:{}",
            spec.issue, spec.tier, spec.owner, spec.source_path, spec.selector
        ));
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
        bail!("CI selection {label} must be a SHA-256 digest");
    }
    Ok(())
}

fn validate_revision(value: &str, label: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("CI selection {label} must be a 40- or 64-hex object ID");
    }
    Ok(())
}

const fn selection_mode_name(mode: SelectionMode) -> &'static str {
    match mode {
        SelectionMode::Adaptive => "adaptive",
        SelectionMode::PrComplete => "pr-complete",
        SelectionMode::ReleaseCheck => "release-check",
    }
}

const fn decision_reason_name(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::PullRequestImpact => "pull-request-impact",
        DecisionReason::DevelopPush => "develop-push",
        DecisionReason::WorkflowDispatch => "workflow-dispatch",
        DecisionReason::FullOverride => "full-override",
        DecisionReason::GlobalImpact => "global-impact",
        DecisionReason::PolicyInvalid => "policy-invalid",
        DecisionReason::EventInvalid => "event-invalid",
        DecisionReason::DiffUnavailable => "diff-unavailable",
        DecisionReason::MetadataUnavailable => "metadata-unavailable",
        DecisionReason::ContractUnavailable => "contract-unavailable",
        DecisionReason::RenameOrCopy => "rename-or-copy",
        DecisionReason::UnknownPath => "unknown-path",
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
pub(crate) fn test_selection_plan() -> Result<SelectionPlan> {
    SelectionPlan::new(SelectionInput {
        policy_version: "a".repeat(64),
        mode: SelectionMode::ReleaseCheck,
        decision_reason: DecisionReason::DevelopPush,
        fallback_context: None,
        revisions: RevisionIdentity {
            base_revision: "b".repeat(40),
            head_revision: "c".repeat(40),
            merge_base_revision: "d".repeat(40),
            execution_revision: "e".repeat(40),
        },
        affected_packages: BTreeSet::new(),
        public_api: PublicApiInput::Affected(BTreeSet::new()),
        test_packages: BTreeSet::new(),
        integration_units: BTreeSet::new(),
        unknown_paths: BTreeSet::new(),
    })
}

#[cfg(test)]
pub(crate) fn test_adaptive_selection_plan() -> Result<SelectionPlan> {
    SelectionPlan::new(SelectionInput {
        policy_version: "a".repeat(64),
        mode: SelectionMode::Adaptive,
        decision_reason: DecisionReason::PullRequestImpact,
        fallback_context: None,
        revisions: RevisionIdentity {
            base_revision: "b".repeat(40),
            head_revision: "c".repeat(40),
            merge_base_revision: "d".repeat(40),
            execution_revision: "e".repeat(40),
        },
        affected_packages: BTreeSet::new(),
        public_api: PublicApiInput::Affected(BTreeSet::new()),
        test_packages: BTreeSet::new(),
        integration_units: BTreeSet::new(),
        unknown_paths: BTreeSet::new(),
    })
}

#[cfg(test)]
pub(crate) fn test_pr_complete_selection_plan() -> Result<SelectionPlan> {
    SelectionPlan::new(SelectionInput {
        policy_version: "a".repeat(64),
        mode: SelectionMode::PrComplete,
        decision_reason: DecisionReason::GlobalImpact,
        fallback_context: None,
        revisions: RevisionIdentity {
            base_revision: "b".repeat(40),
            head_revision: "c".repeat(40),
            merge_base_revision: "d".repeat(40),
            execution_revision: "e".repeat(40),
        },
        affected_packages: BTreeSet::new(),
        public_api: PublicApiInput::Affected(BTreeSet::new()),
        test_packages: BTreeSet::new(),
        integration_units: BTreeSet::new(),
        unknown_paths: BTreeSet::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::visit::Visit;
    use workspacefacts::testing::{
        metadata_json, path_dependency, path_package, path_package_id, registry_package,
        resolve_node, target as testing_target,
    };

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
        Adaptive,
        PrComplete { cause: String },
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

    fn escalation_cause_name(cause: EscalationCause) -> &'static str {
        match cause {
            EscalationCause::MandatoryCatalog => "mandatory-catalog",
            EscalationCause::GlobalImpact => "global-impact",
            EscalationCause::RenameOrCopy => "rename-or-copy",
            EscalationCause::UnknownPath => "unknown-path",
            EscalationCause::FallbackUncertainty => "fallback-uncertainty",
        }
    }

    fn selective_impact_fixture() -> ImpactSet {
        ImpactSet::Selective(SelectiveImpact {
            documentation: false,
            packages: BTreeMap::new(),
            reverse_closure: BTreeSet::new(),
            coverage_closure: BTreeSet::new(),
            packages_with_tests: BTreeSet::new(),
            check_includes_lib: true,
            integration_units: BTreeSet::new(),
            governance: BTreeSet::new(),
            local_meta_domains: BTreeSet::new(),
            unknown_paths: BTreeSet::new(),
            public_api_packages: BTreeSet::new(),
        })
    }

    fn metadata_target(
        name: &str,
        kind: &str,
        test: bool,
        required_features: &[&str],
        package_path: &str,
    ) -> serde_json::Value {
        crate::testutil::target_with_default_src(
            &format!("/workspace/{package_path}"),
            name,
            kind,
            test,
            required_features,
        )
    }

    type SyntheticPackage<'a> = (&'a str, &'a str, Vec<serde_json::Value>, Vec<&'a str>);

    fn synthetic_workspace_metadata(
        specs: Vec<SyntheticPackage<'_>>,
        externals: Vec<serde_json::Value>,
    ) -> Result<String> {
        let paths = specs
            .iter()
            .map(|(name, path, _, _)| (*name, *path))
            .collect::<BTreeMap<_, _>>();
        let package_id = |name: &str| -> Result<String> {
            let path = paths
                .get(name)
                .with_context(|| format!("synthetic dependency `{name}` is missing"))?;
            Ok(path_package_id(&format!("/workspace/{path}")))
        };
        let mut packages = specs
            .iter()
            .map(
                |(name, path, targets, dependencies)| -> Result<serde_json::Value> {
                    let dependencies = dependencies
                        .iter()
                        .map(|dependency| -> Result<serde_json::Value> {
                            let dependency_path = paths.get(dependency).with_context(|| {
                                format!("synthetic dependency `{dependency}` is missing")
                            })?;
                            Ok(path_dependency(
                                dependency,
                                &format!("/workspace/{dependency_path}"),
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Ok(path_package(
                        name,
                        &format!("/workspace/{path}"),
                        targets.clone(),
                        dependencies,
                        serde_json::json!({"integration": [], "remote": []}),
                    ))
                },
            )
            .collect::<Result<Vec<_>>>()?;
        packages.extend(externals);
        let workspace_members = specs
            .iter()
            .map(|(name, _, _, _)| package_id(name))
            .collect::<Result<Vec<_>>>()?;
        let mut nodes = specs
            .iter()
            .map(|(name, _, _, dependencies)| -> Result<serde_json::Value> {
                let deps = dependencies
                    .iter()
                    .map(|dependency| Ok(((*dependency), package_id(dependency)?)))
                    .collect::<Result<Vec<_>>>()?;
                let deps_refs = deps
                    .iter()
                    .map(|(dependency, id)| (*dependency, id.as_str()))
                    .collect::<Vec<_>>();
                let id = package_id(name)?;
                Ok(resolve_node(&id, &deps_refs))
            })
            .collect::<Result<Vec<_>>>()?;
        for external in &packages[specs.len()..] {
            let id = external["id"]
                .as_str()
                .context("external package missing id")?;
            nodes.push(resolve_node(id, &[]));
        }
        Ok(metadata_json(
            "/workspace",
            packages,
            workspace_members,
            nodes,
        ))
    }

    fn synthetic_workspace_facts(specs: Vec<SyntheticPackage<'_>>) -> Result<WorkspaceFacts> {
        synthetic_workspace_facts_with_externals(specs, Vec::new())
    }

    fn synthetic_workspace_facts_with_externals(
        specs: Vec<SyntheticPackage<'_>>,
        externals: Vec<serde_json::Value>,
    ) -> Result<WorkspaceFacts> {
        let packages = specs
            .into_iter()
            .map(|(name, path, targets, dependencies)| {
                crate::testutil::SyntheticPathPackage::new(
                    name,
                    format!("/workspace/{path}"),
                    targets,
                )
                .with_dependencies(dependencies.into_iter().map(str::to_owned).collect())
                .with_features(serde_json::json!({"integration": [], "remote": []}))
            })
            .collect::<Vec<_>>();
        crate::testutil::synthetic_workspace_facts(Path::new("/workspace"), &packages, &externals)
    }

    fn synthetic_chain_facts(
        leaves: &[(&str, &str)],
        connected_leaf: Option<&str>,
    ) -> Result<WorkspaceFacts> {
        let mut specs = leaves
            .iter()
            .map(|(path, name)| {
                (
                    *name,
                    *path,
                    vec![metadata_target(name, "lib", true, &[], path)],
                    Vec::new(),
                )
            })
            .collect::<Vec<_>>();
        let adapter_dependencies = connected_leaf.into_iter().collect::<Vec<_>>();
        specs.push((
            "synthetic_adapter",
            "adapters/synthetic-adapter",
            vec![metadata_target(
                "synthetic_adapter",
                "lib",
                true,
                &[],
                "adapters/synthetic-adapter",
            )],
            adapter_dependencies,
        ));
        specs.push((
            "runtime",
            "crates/runtime",
            vec![metadata_target(
                "runtime",
                "lib",
                true,
                &[],
                "crates/runtime",
            )],
            vec!["synthetic_adapter"],
        ));
        synthetic_workspace_facts(specs)
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
    ) -> Result<SelectionPlan> {
        plan_event(
            root,
            "pull_request",
            &pr_event(base, head),
            policy_version(b"schemaVersion=3\nmode='adaptive'\n"),
            mode,
            head.to_owned(),
        )
    }

    #[test]
    fn policy_escalates_contract_rename_and_unknown_only() {
        assert_eq!(
            classify_diff(&[DiffEntry::rename("contracts/event/renamed/contract.toml")]).mode,
            SelectionMode::PrComplete
        );
        assert_eq!(
            classify_diff(&[DiffEntry::modified("unowned/input.bin")]).mode,
            SelectionMode::PrComplete
        );
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
    fn fixed_events_exclude_scheduled_nightly() -> Result<()> {
        let root = Path::new(".");
        let facts = CommandWorkspaceFacts::new(root);
        let policy = policy_version(b"schemaVersion=3\nmode='adaptive'\n");
        let revision = "a".repeat(40);

        for (event, reason) in [
            ("push", DecisionReason::DevelopPush),
            ("workflow_dispatch", DecisionReason::WorkflowDispatch),
        ] {
            let plan = plan_event_with_facts(
                root,
                &facts,
                event,
                "{}",
                policy.clone(),
                PolicyMode::Adaptive,
                revision.clone(),
            )?;
            assert_eq!(plan.mode(), SelectionMode::ReleaseCheck);
            assert_eq!(plan.decision_reason, reason);
        }

        let plan = plan_event_with_facts(
            root,
            &facts,
            "schedule",
            "{}",
            policy,
            PolicyMode::Adaptive,
            revision,
        )?;
        assert_eq!(plan.mode(), SelectionMode::ReleaseCheck);
        assert_eq!(plan.decision_reason, DecisionReason::EventInvalid);
        assert_eq!(
            plan.fallback_context.map(|context| context.code),
            Some(FallbackCode::EventInvalid)
        );
        Ok(())
    }

    #[test]
    fn ordinary_rename_and_copy_merge_both_crate_paths_red() -> Result<()> {
        for status in ["R100", "C100"] {
            let raw = format!("{status}\0crates/leaf/src/old.rs\0crates/consumer/src/new.rs\0");
            let entries = parse_diff(raw.as_bytes())?;
            assert_eq!(
                entries,
                vec![
                    DiffEntry {
                        status: DiffStatus::Deleted,
                        path: "crates/leaf/src/old.rs".to_owned(),
                        rename_or_copy: true,
                    },
                    DiffEntry {
                        status: DiffStatus::Added,
                        path: "crates/consumer/src/new.rs".to_owned(),
                        rename_or_copy: true,
                    },
                ]
            );
            assert_eq!(immediate_escalation_cause(&entries), None);
            let projection = classify_diff(&entries);
            assert_eq!(projection.mode, SelectionMode::Adaptive);
            assert_eq!(
                projection.affected_packages,
                BTreeSet::from(["consumer".to_owned(), "leaf".to_owned()]),
                "{status} must merge both crate endpoints"
            );
        }
        Ok(())
    }

    #[test]
    fn basis_change_uses_package_reverse_closure_red() -> Result<()> {
        let entries = [DiffEntry::modified("crates/vocab/src/lib.rs")];
        assert_eq!(immediate_escalation_cause(&entries), None);
        let facts = synthetic_workspace_facts(vec![
            (
                "vocab",
                "crates/vocab",
                vec![metadata_target("vocab", "lib", true, &[], "crates/vocab")],
                Vec::new(),
            ),
            (
                "consumer",
                "crates/consumer",
                vec![metadata_target(
                    "consumer",
                    "lib",
                    true,
                    &[],
                    "crates/consumer",
                )],
                vec!["vocab"],
            ),
        ])?;
        let projection = classify_with_facts(Path::new("/workspace"), &entries, &facts, "unknown")?;
        assert_eq!(projection.mode, SelectionMode::Adaptive);
        assert_eq!(
            projection.affected_packages,
            BTreeSet::from(["consumer".to_owned(), "vocab".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn internal_api_sources_select_only_their_owner_baselines() -> Result<()> {
        let facts = synthetic_workspace_facts(vec![
            (
                "diport",
                "crates/diport",
                vec![metadata_target("diport", "lib", true, &[], "crates/diport")],
                Vec::new(),
            ),
            (
                "runtimeexec",
                "crates/runtimeexec",
                vec![metadata_target(
                    "runtimeexec",
                    "lib",
                    true,
                    &[],
                    "crates/runtimeexec",
                )],
                Vec::new(),
            ),
            (
                "leaf",
                "crates/leaf",
                vec![metadata_target("leaf", "lib", true, &[], "crates/leaf")],
                Vec::new(),
            ),
        ])?;

        for (path, expected) in [
            ("crates/diport/src/lib.rs", Some("diport")),
            ("crates/runtimeexec/src/lib.rs", Some("runtimeexec")),
            ("crates/leaf/src/lib.rs", None),
        ] {
            let projection = classify_with_facts(
                Path::new("/workspace"),
                &[DiffEntry::modified(path)],
                &facts,
                "unknown",
            )?;
            assert_eq!(
                projection.public_api_packages,
                expected.into_iter().map(str::to_owned).collect(),
                "{path}"
            );
            let impact = impact_with_facts_and_owners(
                Path::new("/workspace"),
                &[DiffEntry::modified(path)],
                &facts,
                "unknown",
                Some(&BTreeSet::from([
                    "diport".to_owned(),
                    "runtimeexec".to_owned(),
                ])),
            )?;
            let local_public_api =
                LocalProjection::from(&impact)
                    .steps()
                    .into_iter()
                    .find_map(|step| match step {
                        LocalStep::PublicApi(packages) => Some(packages),
                        _ => None,
                    });
            assert_eq!(
                local_public_api,
                expected.map(|package| vec![package.to_owned()]),
                "local projection: {path}"
            );
        }

        let mixed = classify_with_facts(
            Path::new("/workspace"),
            &[
                DiffEntry::modified("Cargo.toml"),
                DiffEntry::modified("crates/diport/src/lib.rs"),
            ],
            &facts,
            "unknown",
        )?;
        assert_eq!(mixed.mode, SelectionMode::PrComplete);
        assert_eq!(
            mixed.public_api_packages,
            BTreeSet::from(["diport".to_owned()])
        );
        let selection = SelectionPlan::new(SelectionInput {
            policy_version: "a".repeat(64),
            mode: mixed.mode,
            decision_reason: mixed.decision_reason(),
            fallback_context: mixed.fallback_context(),
            revisions: unknown_revisions("e".repeat(40)),
            affected_packages: mixed.affected_packages,
            public_api: PublicApiInput::Affected(mixed.public_api_packages),
            test_packages: mixed.test_packages,
            integration_units: mixed.integration_units,
            unknown_paths: mixed.unknown_paths,
        })?;
        assert!(selection.affected_packages().is_empty());
        assert_eq!(selection.public_api_packages(), ["diport"]);
        assert_eq!(
            SelectionPlan::from_json(&selection.to_json()?)?.public_api_packages(),
            ["diport"]
        );
        Ok(())
    }

    #[test]
    fn contract_rename_remains_pr_complete() -> Result<()> {
        let entries = parse_diff(
            b"R100\0contracts/event/identity/v1/old/contract.toml\0contracts/event/identity/v1/new/contract.toml\0",
        )?;
        assert_eq!(entries.len(), 2);
        assert_eq!(
            immediate_escalation_cause(&entries),
            Some(EscalationCause::RenameOrCopy)
        );
        assert_eq!(
            RemoteProjection::from(&ImpactSet::escalated(EscalationCause::RenameOrCopy)).mode,
            SelectionMode::PrComplete
        );
        Ok(())
    }

    #[test]
    fn local_options_are_closed_and_fail_closed() -> Result<()> {
        assert_eq!(
            parse_local_options(&["--base", "origin/develop"])?,
            LocalOptions {
                base: vec!["origin/develop".to_owned()],
                fail_fast: 0,
                only: Vec::new(),
            }
        );
        assert_eq!(
            parse_local_options(&[
                "--base",
                "origin/develop",
                "--fail-fast",
                "--only",
                "meta",
                "--only",
                "clippy",
            ])?,
            LocalOptions {
                base: vec!["origin/develop".to_owned()],
                fail_fast: 1,
                only: vec![LocalStage::Meta, LocalStage::Clippy],
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
            vec!["--base", "main", "--only", "fast-meta"],
        ] {
            assert!(parse_local_options(&args).is_err(), "accepted {args:?}");
        }
        Ok(())
    }

    fn parse_local_options(args: &[&str]) -> Result<LocalOptions> {
        use clap::Parser;
        #[derive(Parser)]
        #[command(name = "ci-local")]
        struct Wrapper {
            #[command(flatten)]
            options: LocalOptions,
        }
        let options =
            Wrapper::try_parse_from(std::iter::once("ci-local").chain(args.iter().copied()))?
                .options;
        options.validate()?;
        Ok(options)
    }

    #[test]
    fn one_impact_set_projects_to_local_and_remote_without_path_remapping() {
        let empty = impact_entries(&[], None, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(LocalProjection::from(&empty), LocalProjection::Empty);
        assert_eq!(RemoteProjection::from(&empty).mode, SelectionMode::Adaptive);

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
                public_api_packages: Vec::new(),
                governance: BTreeSet::new(),
            }
        );
        let remote = RemoteProjection::from(&selective);
        assert_eq!(remote.mode, SelectionMode::Adaptive);
        assert_eq!(
            remote.affected_packages,
            BTreeSet::from(["consumer".to_owned(), "leaf".to_owned()])
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
            RemoteProjection::from(&full).mode,
            SelectionMode::PrComplete
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
                "test-only-package-closure",
                &[("leaf", &[PackageImpact::Test])],
                &["leaf", "consumer"],
                &["leaf", "consumer"],
                &["consumer", "leaf"],
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
                integration_units: BTreeSet::new(),
                governance: BTreeSet::new(),
                local_meta_domains: BTreeSet::new(),
                unknown_paths: BTreeSet::new(),
                public_api_packages: BTreeSet::new(),
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

        let full = CoverageProjection::from(&ImpactSet::escalated(EscalationCause::GlobalImpact))
            .decision();
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
            integration_units: BTreeSet::new(),
            governance: BTreeSet::new(),
            local_meta_domains: BTreeSet::new(),
            unknown_paths: BTreeSet::from(["mystery/path.rs".to_owned()]),
            public_api_packages: BTreeSet::new(),
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
    fn remote_source_with_no_test_harness_keeps_an_empty_test_selection() {
        let mut packages = BTreeMap::new();
        packages.insert("leaf".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let impact = ImpactSet::Selective(SelectiveImpact {
            documentation: false,
            packages,
            reverse_closure: BTreeSet::from(["leaf".to_owned()]),
            coverage_closure: BTreeSet::from(["leaf".to_owned()]),
            packages_with_tests: BTreeSet::new(),
            check_includes_lib: true,
            integration_units: BTreeSet::new(),
            governance: BTreeSet::new(),
            local_meta_domains: BTreeSet::new(),
            unknown_paths: BTreeSet::new(),
            public_api_packages: BTreeSet::new(),
        });
        assert_eq!(
            CoverageProjection::from(&impact).decision(),
            CoverageDecision::Skip
        );
        let remote = RemoteProjection::from(&impact);
        assert_eq!(remote.mode, SelectionMode::Adaptive);
        assert!(remote.test_packages.is_empty());
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
        if std::env::var(GITHUB_EVENT_NAME_ENV).as_deref() == Ok("pull_request") {
            return Ok(());
        }
        let root = crate::workspace_root()?;
        let Ok(scope) = coverage_scope_for_typed_job(&root) else {
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
    fn local_unknown_paths_preserve_known_package_selection() -> Result<()> {
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
        let remote = RemoteProjection::from(&mixed);
        assert_eq!(remote.mode, SelectionMode::Adaptive);
        assert_eq!(
            remote.affected_packages,
            BTreeSet::from(["leaf".to_owned()])
        );
        assert_eq!(
            remote.unknown_paths,
            BTreeSet::from(["unowned/input.bin".to_owned()]),
            "mixed unknown paths must remain visible without erasing known package selection"
        );
        let selection = SelectionPlan::new(SelectionInput {
            policy_version: "a".repeat(64),
            mode: remote.mode,
            decision_reason: remote.decision_reason(),
            fallback_context: remote.fallback_context(),
            revisions: unknown_revisions("e".repeat(40)),
            affected_packages: remote.affected_packages,
            public_api: PublicApiInput::Affected(remote.public_api_packages),
            test_packages: remote.test_packages,
            integration_units: remote.integration_units,
            unknown_paths: remote.unknown_paths,
        })?;
        assert_eq!(selection.mode(), SelectionMode::Adaptive);
        assert_eq!(selection.unknown_paths(), ["unowned/input.bin"]);

        Ok(())
    }

    #[test]
    fn governance_paths_are_metadata_only() {
        for path in [
            ".github/workflows/ci.yml",
            ".github/workflows/rss-rust-job.yml",
        ] {
            let impact = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                LocalProjection::from(&impact),
                LocalProjection::Meta(all_local_meta_gates()),
                "{path} is a high-risk execution protocol and must fail closed"
            );
        }
        for path in [
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
        for path in ["docs/rules/example.md", "docs/rules/nested/example.md"] {
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
            vec![LocalStep::Meta(all_local_meta_gates()).label()]
        );
    }

    #[test]
    fn local_tooling_paths_select_targeted_selftests() {
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
            ("crates/workspacefacts/Cargo.toml", Domain::Consistency),
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

        // Asserts the projector filters the same as local_meta_policy (catches projector
        // bugs). Domain→gate membership is locked by
        // ci_lanes::local_meta_policy_is_exact_9_24_7_partition.
        for domain in Domain::ALL {
            let expected: Vec<_> = GateId::ALL
                .iter()
                .copied()
                .filter(|id| match id.local_meta_policy() {
                    LocalMetaPolicy::Always => true,
                    LocalMetaPolicy::OnImpact(impact) => impact == domain,
                    LocalMetaPolicy::FullOnly | LocalMetaPolicy::NeverLocal => false,
                })
                .collect();
            assert_eq!(
                local_meta_gates(Some(&BTreeSet::from([domain]))),
                expected,
                "{domain:?} gate projection drift"
            );
        }
        let expected_all: Vec<_> = GateId::ALL
            .iter()
            .copied()
            .filter(|id| {
                matches!(
                    id.local_meta_policy(),
                    LocalMetaPolicy::Always | LocalMetaPolicy::OnImpact(_)
                )
            })
            .collect();
        assert_eq!(all_local_meta_gates(), expected_all);
    }

    #[test]
    fn local_impact_domain_catalog_matches_real_scanner_closures() -> Result<()> {
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
                "docs/rules/example.md",
                BTreeSet::from([Domain::RuntimeEventing]),
            ),
            (
                "deploy/docker-compose.yml",
                BTreeSet::from([Domain::AssemblyGeneration]),
            ),
            (
                ".dockerignore",
                BTreeSet::from([Domain::AssemblyGeneration]),
            ),
            ("Dockerfile", BTreeSet::from([Domain::AssemblyGeneration])),
            (
                "lints/rss_operator_authorization_callsite/ui/runtime.stderr",
                BTreeSet::from([Domain::RuntimeEventing, Domain::TenancyPostgres]),
            ),
            (
                "xtask/src/publicapi.rs",
                BTreeSet::from([Domain::Consistency, Domain::TenancyPostgres]),
            ),
            (
                // Cargo.toml-only edit under workspacefacts must hit Consistency
                // (LocalTxCoverage / LocalOnlyEffects); `.rs`-only workspace_member_rust
                // cannot cover this path.
                "crates/workspacefacts/Cargo.toml",
                BTreeSet::from([
                    Domain::AssemblyGeneration,
                    Domain::Consistency,
                    Domain::ContractBinding,
                ]),
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
            if path == "crates/workspacefacts/Cargo.toml" {
                let steps = local_steps(&impact);
                let Some(LocalStep::Meta(meta)) = steps.first() else {
                    bail!("workspacefacts Cargo.toml must project Meta")
                };
                assert!(
                    meta.contains(&GateId::LocalTxCoverage),
                    "workspacefacts Cargo.toml must schedule LocalTxCoverage"
                );
                assert!(
                    meta.contains(&GateId::LocalOnlyEffects),
                    "workspacefacts Cargo.toml must schedule LocalOnlyEffects"
                );
            }
        }

        assert_eq!(
            local_impact_domains("xtask/src/assembly_governance.rs"),
            Domain::ALL.into_iter().collect(),
            "shared assembly governance IR must invalidate every local domain"
        );
        assert_eq!(
            local_impact_domains("xtask/src/cli.rs"),
            Domain::ALL.into_iter().collect(),
            "clap CLI ADT carrier must invalidate every local domain"
        );
        assert_eq!(
            immediate_escalation_cause(&[DiffEntry::modified("xtask/src/cli.rs")]),
            Some(EscalationCause::GlobalImpact),
            "cli.rs must escalate like main.rs high-impact carriers"
        );
        assert_eq!(
            local_impact_domains("xtask/src/report_format.rs"),
            Domain::ALL.into_iter().collect(),
            "report format ADT is shared CLI policy"
        );
        Ok(())
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
            let steps = local_steps(&impact)
                .iter()
                .map(LocalStep::label)
                .collect::<Vec<_>>();
            assert_eq!(
                steps.first(),
                Some(&LocalStep::Meta(local_meta_gates(None)).label()),
                "controlled carrier {path} must run meta first"
            );
            if *path == "hack/cargo.sh" {
                assert!(
                    steps.contains(&LocalStep::CargoWrapperSelftest.label()),
                    "the executable wrapper carrier must also run its selftest"
                );
            }
        }
    }

    #[test]
    fn selective_local_steps_are_bounded_to_affected_package_operations() {
        let projection = LocalProjection::Selective {
            meta_gates: local_meta_gates(None),
            check_packages: vec!["redis-adapter".to_owned(), "runtime".to_owned()],
            check_includes_lib: true,
            test_clippy_packages: vec!["redis-adapter".to_owned()],
            public_api_packages: Vec::new(),
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
            .integration_units
            .insert(IntegrationUnitId::MqttIntegration);

        let labels = LocalProjection::from(&ImpactSet::Selective(selective))
            .steps()
            .iter()
            .map(LocalStep::label)
            .collect::<Vec<_>>();
        assert!(
            labels.iter().all(|label| !label.contains("integration")),
            "integration compile belongs to develop/release, not local preflight: {labels:?}"
        );
        Ok(())
    }

    #[test]
    fn local_cargo_targets_follow_typed_local_test_policy() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
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
                LocalStep::Packages {
                    operation: LocalCargoOperation::Test,
                    packages: vec!["identityaudit".to_owned()],
                    target: None,
                    check_includes_lib: true,
                },
            ],
            facts,
        )?;
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Lib), .. }
                if packages == &["runtime"]
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Doc), .. }
                if packages == &["runtime"]
        )));
        for target in ["auth_e2e", "refresh_mint_e2e", "key_rotation_e2e"] {
            assert!(steps.iter().any(|step| matches!(step,
                LocalStep::Packages {
                    packages,
                    target: Some(LocalCargoTarget::Test { name, required_features }),
                    ..
                } if packages == &["runtime"]
                    && name == target
                    && required_features == &["integration"]
            )));
        }
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Bin(name)), .. }
                if packages == &["xtask"] && name == "xtask"
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["xtask"] && name == "consistency_report_cli"
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["mqtt"] && name == "ownership_gate"
        )));
        assert!(!steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["mqtt"] && name == "integration"
        )));
        assert!(steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["identityaudit"] && name == "artifact_acceptance"
        )));
        assert!(!steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["identityaudit"] && name == "runtime_image_acceptance"
        )));
        assert!(!steps.iter().any(|step| matches!(step,
            LocalStep::Packages { packages, target: Some(LocalCargoTarget::Test { name, .. }), .. }
                if packages == &["deviceidentity"] && name == "runtime_image_acceptance"
        )));
        for step in &steps {
            if let LocalStep::Packages {
                packages,
                target: Some(LocalCargoTarget::Test { name: target, .. }),
                ..
            } = step
            {
                assert!(
                    !crate::integration_shards::is_remote_only_test_target(&packages[0], target,),
                    "remote-only target leaked into local preflight: {packages:?}/{target}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn local_xtask_tests_fail_closed_for_shared_modules_and_mixed_inputs() {
        let selective = selective_impact_fixture();
        let step = LocalStep::Packages {
            operation: LocalCargoOperation::Test,
            packages: vec!["xtask".to_owned()],
            target: Some(LocalCargoTarget::Bin("xtask".to_owned())),
            check_includes_lib: true,
        };
        let scoped = scope_xtask_unit_test_steps(
            vec![step.clone()],
            &selective,
            &[DiffEntry::modified("xtask/src/ci_impact.rs")],
        );
        let filters = scoped
            .iter()
            .filter_map(|step| match step {
                LocalStep::Packages {
                    target: Some(LocalCargoTarget::BinTestFilter { filter, .. }),
                    ..
                } => Some(filter.as_str()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(filters, BTreeSet::from(["ci_impact::"]));
        for path in [
            "xtask/src/cmd.rs",
            "xtask/src/ci_lanes.rs",
            "xtask/src/integration_shards.rs",
        ] {
            assert_eq!(
                scope_xtask_unit_test_steps(
                    vec![step.clone()],
                    &selective,
                    &[DiffEntry::modified(path)],
                ),
                vec![step.clone()],
                "shared xtask module {path} must keep the complete bin target"
            );
        }
        assert_eq!(
            scope_xtask_unit_test_steps(
                vec![step.clone()],
                &selective,
                &[
                    DiffEntry::modified("xtask/src/ci_impact.rs"),
                    DiffEntry::modified("xtask/Cargo.toml"),
                ],
            ),
            vec![step.clone()],
            "mixed manifest input must keep the complete bin target"
        );
        for path in ["xtask/src/testutil.rs", "xtask/src/main.rs"] {
            assert_eq!(
                scope_xtask_unit_test_steps(
                    vec![step.clone()],
                    &selective,
                    &[DiffEntry::modified(path)],
                ),
                vec![step.clone()],
                "unregistered xtask source {path} must keep the complete bin target"
            );
        }
        for (impact, entries) in [
            (
                ImpactSet::escalated(EscalationCause::MandatoryCatalog),
                vec![DiffEntry::modified("xtask/src/ci_impact.rs")],
            ),
            (
                ImpactSet::escalated(EscalationCause::RenameOrCopy),
                vec![DiffEntry::rename("xtask/src/ci_impact.rs")],
            ),
        ] {
            assert_eq!(
                scope_xtask_unit_test_steps(vec![step.clone()], &impact, &entries),
                vec![step.clone()],
                "non-selective impact must keep the complete bin target"
            );
        }
    }

    #[test]
    fn local_executor_supports_keep_going_and_fail_fast() -> Result<()> {
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

        executed.clear();
        for _ in 0..2 {
            execute_local_steps(&steps, crate::cmd::ExecutionPolicy::KeepGoing, |step| {
                executed.push(step.clone());
                Ok(())
            })?;
        }
        assert_eq!(executed, [steps.clone(), steps].concat());
        Ok(())
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
                Some(&LocalCargoTarget::Test {
                    name: "leaf_api".to_owned(),
                    required_features: Vec::new(),
                }),
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
                Some(&LocalCargoTarget::Test {
                    name: "auth_e2e".to_owned(),
                    required_features: vec!["integration".to_owned()],
                }),
                true,
                ExecutionPolicy::KeepGoing
            )?,
            [
                "--locked",
                "--test",
                "auth_e2e",
                "--features",
                "integration",
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
                "--no-deps",
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
                "--no-deps",
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
        let identity_composition = vec!["identity-composition".to_owned()];
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Test,
                &identity_composition,
                Some(&LocalCargoTarget::Lib),
                true,
                ExecutionPolicy::FailFast
            )?,
            [
                "--locked",
                "--lib",
                "--features",
                "identity-composition/device-mqtt",
                "-p",
                "identity-composition"
            ]
        );
        assert_eq!(
            package_operation_args(
                LocalCargoOperation::Clippy,
                &identity_composition,
                Some(&LocalCargoTarget::Lib),
                true,
                ExecutionPolicy::FailFast
            )?,
            [
                "--locked",
                "--no-deps",
                "--lib",
                "--features",
                "identity-composition/device-mqtt",
                "-p",
                "identity-composition",
                "--",
                "-D",
                "warnings"
            ]
        );
        Ok(())
    }

    #[test]
    fn local_xtask_unit_tests_use_one_positive_module_filter() -> Result<()> {
        use crate::cmd::ExecutionPolicy;

        let args = package_operation_args(
            LocalCargoOperation::Test,
            &["xtask".to_owned()],
            Some(&LocalCargoTarget::BinTestFilter {
                name: "xtask".to_owned(),
                filter: "ci_impact::".to_owned(),
            }),
            true,
            ExecutionPolicy::KeepGoing,
        )?;
        assert_eq!(
            args,
            [
                "--locked",
                "--bin",
                "xtask",
                "-p",
                "xtask",
                "--no-fail-fast",
                "--",
                "ci_impact::",
            ]
        );
        Ok(())
    }

    #[test]
    fn bin_only_reverse_closure_projects_check_without_lib() -> Result<()> {
        use crate::cmd::ExecutionPolicy;

        let facts = synthetic_workspace_facts(vec![
            (
                "leaf",
                "crates/leaf",
                vec![metadata_target("leaf", "lib", false, &[], "crates/leaf")],
                Vec::new(),
            ),
            (
                "xtask",
                "xtask",
                vec![metadata_target("xtask", "bin", true, &[], "xtask")],
                Vec::new(),
            ),
        ])?;
        assert!(package_has_lib_target(&facts, "leaf")?);
        assert!(!package_has_lib_target(&facts, "xtask")?);

        let mut seeded = BTreeMap::new();
        seeded.insert("xtask".to_owned(), BTreeSet::from([PackageImpact::Source]));
        let impact = impact_entries(
            &[DiffEntry::modified("xtask/src/assembly.rs")],
            Some(&facts),
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
            bail!("matched Check step changed variant before extraction");
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
            Some(&facts),
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
            root.join("crates/leaf/Cargo.toml"),
            "[package]\nname='leaf'\nversion='0.0.0'\nedition='2024'\n",
        )?;
        let source_path = root.join("crates/leaf/src/lib.rs");
        fs::write(&source_path, "pub fn value() -> u8 { 1 }\n")?;
        integration_shards::write_catalog_workspace_fixture(
            &root,
            &["crates/leaf"],
            integration_shards::IntegrationCatalogFixtureDrift::Exact,
        )?;
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
            ImpactSet::Escalated {
                cause: EscalationCause::FallbackUncertainty,
                ..
            }
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
    fn real_git_pr_plans_preserve_adaptive_global_and_fallback_semantics() -> Result<()> {
        let temporary_root = crate::testutil::unique_tmp("ci-impact-real-pr");
        fs::create_dir_all(temporary_root.join("crates/leaf/src"))?;
        let root = fs::canonicalize(temporary_root)?;
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
        integration_shards::write_catalog_workspace_fixture(
            &root,
            &["crates/leaf"],
            integration_shards::IntegrationCatalogFixtureDrift::Exact,
        )?;
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
        let adaptive = plan_fixture_pr(&root, &base, &ordinary, PolicyMode::Adaptive)?;
        assert_eq!(adaptive.mode(), SelectionMode::Adaptive);
        assert_eq!(adaptive.decision_reason, DecisionReason::PullRequestImpact);
        assert_eq!(adaptive.affected_packages(), ["leaf".to_owned()]);
        assert_eq!(SelectionPlan::from_json(&adaptive.to_json()?)?, adaptive);

        fs::write(
            root.join("clippy.toml"),
            "avoid-breaking-exported-api = false\n",
        )?;
        let global = commit_all(&root, "global")?;
        let global_plan = plan_fixture_pr(&root, &ordinary, &global, PolicyMode::Adaptive)?;
        assert_eq!(global_plan.mode(), SelectionMode::PrComplete);
        assert_eq!(global_plan.decision_reason, DecisionReason::GlobalImpact);
        assert!(matches!(
            global_plan.test_selection(),
            ProjectedTestSelection::Workspace
        ));
        assert_eq!(
            global_plan.integration_selection()?,
            IntegrationSelection::for_profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical
            )?
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
        let rename_plan = plan_fixture_pr(&root, &global, &renamed, PolicyMode::Adaptive)?;
        assert_eq!(rename_plan.mode(), SelectionMode::Adaptive);
        assert_eq!(
            rename_plan.decision_reason,
            DecisionReason::PullRequestImpact
        );
        assert_eq!(rename_plan.affected_packages(), ["leaf".to_owned()]);

        fs::copy(
            root.join("crates/leaf/src/renamed.rs"),
            root.join("crates/leaf/src/copied.rs"),
        )?;
        let copied = commit_all(&root, "copy unchanged source")?;
        let copy_plan = plan_fixture_pr(&root, &renamed, &copied, PolicyMode::Adaptive)?;
        assert_eq!(copy_plan.mode(), SelectionMode::Adaptive);
        assert_eq!(copy_plan.decision_reason, DecisionReason::PullRequestImpact);

        fs::create_dir_all(root.join("unowned"))?;
        fs::write(root.join("unowned/input.bin"), "unknown")?;
        let unknown = commit_all(&root, "unknown")?;
        let unknown_plan = plan_fixture_pr(&root, &copied, &unknown, PolicyMode::Adaptive)?;
        assert_eq!(unknown_plan.mode(), SelectionMode::PrComplete);
        assert_eq!(unknown_plan.decision_reason, DecisionReason::UnknownPath);
        assert!(matches!(
            unknown_plan.test_selection(),
            ProjectedTestSelection::Workspace
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn policy_selects_docs_core_and_integration_green() {
        let docs = classify_diff(&[DiffEntry::modified("docs/ops/example.md")]);
        assert_eq!(docs.mode, SelectionMode::Adaptive);
        assert!(docs.affected_packages.is_empty());

        let core = classify_diff(&[DiffEntry::modified("crates/identity/src/service.rs")]);
        assert_eq!(core.mode, SelectionMode::Adaptive);
        assert!(core.affected_packages.contains("identity"));

        let adapter = classify_diff(&[DiffEntry::modified("adapters/postgres/src/lib.rs")]);
        assert!(
            adapter
                .integration_units
                .iter()
                .any(|unit| unit.spec().shard == IntegrationShard::PostgresDomain)
        );
    }

    #[test]
    fn policy_behavior_matches_id_based_golden() -> Result<()> {
        let golden = policy_golden()?;
        assert_eq!(golden.schema_version, 3);
        assert_eq!(
            golden.machine_inputs,
            MACHINE_INPUT_PATHS
                .iter()
                .map(|path| (*path).to_owned())
                .collect::<Vec<_>>()
        );
        for case in golden.path_cases {
            let (status, rename_or_copy) = match case.status.as_str() {
                "modified" => (DiffStatus::Modified, false),
                "renamed" => (DiffStatus::Modified, true),
                other => bail!("unknown golden diff status: {other}"),
            };
            let projection = classify_diff(&[DiffEntry {
                status,
                path: case.path.clone(),
                rename_or_copy,
            }]);
            let (expected_mode, expected_cause) = match case.expected {
                PathExpectationGolden::Adaptive => (SelectionMode::Adaptive, None),
                PathExpectationGolden::PrComplete { cause } => {
                    (SelectionMode::PrComplete, Some(cause))
                }
            };
            assert_eq!(
                projection.mode, expected_mode,
                "golden selection mode drift for {}",
                case.path
            );
            assert_eq!(
                projection.cause.map(escalation_cause_name),
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
    fn selection_plan_is_strict_and_contains_no_dynamic_job_control_plane() -> Result<()> {
        let selection = test_selection_plan()?;
        let source = selection.to_json()?;
        assert_eq!(SelectionPlan::from_json(&source)?, selection);
        let wire: serde_json::Value = serde_json::from_str(&source)?;
        let selection_wire = wire
            .get("selection")
            .and_then(serde_json::Value::as_object)
            .context("selection plan must contain one tagged selection")?;
        for removed in [
            "jobs",
            "matrix",
            "planDigest",
            "artifacts",
            "affectedPackages",
            "testSelection",
            "integrationSelection",
        ] {
            assert!(
                wire.get(removed).is_none(),
                "removed field leaked: {removed}"
            );
            assert!(
                selection_wire.get(removed).is_none(),
                "removed selection payload leaked: {removed}"
            );
        }

        let mut extra = wire.clone();
        extra["jobs"] = serde_json::json!([]);
        assert!(SelectionPlan::from_json(&extra.to_string()).is_err());
        let mut invalid_mode = wire;
        invalid_mode["selection"]["mode"] = serde_json::json!("pr-complete");
        assert!(SelectionPlan::from_json(&invalid_mode.to_string()).is_err());

        let mut legacy_version: serde_json::Value =
            serde_json::from_str(&test_adaptive_selection_plan()?.to_json()?)?;
        legacy_version["schemaVersion"] = serde_json::json!(1);
        assert!(SelectionPlan::from_json(&legacy_version.to_string()).is_err());
        let mut missing_owner_field: serde_json::Value =
            serde_json::from_str(&test_adaptive_selection_plan()?.to_json()?)?;
        missing_owner_field["selection"]
            .as_object_mut()
            .context("adaptive selection must be an object")?
            .remove("public_api");
        assert!(SelectionPlan::from_json(&missing_owner_field.to_string()).is_err());
        let mut legacy_alias: serde_json::Value =
            serde_json::from_str(&test_adaptive_selection_plan()?.to_json()?)?;
        legacy_alias["selection"]["public_api_packages"] = serde_json::json!([]);
        assert!(SelectionPlan::from_json(&legacy_alias.to_string()).is_err());

        let mut forged_payload: serde_json::Value =
            serde_json::from_str(&test_pr_complete_selection_plan()?.to_json()?)?;
        forged_payload["selection"]["affectedPackages"] = serde_json::json!(["xtask"]);
        forged_payload["selection"]["testSelection"] =
            serde_json::json!({"kind":"packages","packages":["xtask"]});
        assert!(SelectionPlan::from_json(&forged_payload.to_string()).is_err());
        Ok(())
    }

    #[test]
    fn selection_modes_bind_exact_test_and_integration_scope() -> Result<()> {
        let adaptive = test_adaptive_selection_plan()?;
        assert!(matches!(
            adaptive.test_selection(),
            ProjectedTestSelection::None
        ));
        assert_eq!(
            adaptive.integration_selection()?,
            integration_shards::localtx_required_selection()?
        );

        let pr_complete = fallback_selection(
            "a".repeat(64),
            DecisionReason::DiffUnavailable,
            SelectionMode::PrComplete,
            "e".repeat(40),
        )?;
        assert!(matches!(
            pr_complete.test_selection(),
            ProjectedTestSelection::Workspace
        ));
        assert_eq!(
            pr_complete.integration_selection()?,
            IntegrationSelection::for_profile(
                crate::execution_profiles::ExecutionProfile::IntegrationCritical
            )?
        );

        let release = test_selection_plan()?;
        assert!(matches!(
            release.test_selection(),
            ProjectedTestSelection::Workspace
        ));
        assert_eq!(
            release.integration_selection()?,
            IntegrationSelection::release_check()
        );
        Ok(())
    }

    #[test]
    fn semantic_package_impact_selects_units_before_shard_projection() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let convergence = IntegrationUnitId::DeviceCertificateConvergenceJourney;
        for (package, path, expected) in [
            (
                "mqtt",
                "adapters/mqtt/src/lib.rs",
                BTreeSet::from([IntegrationUnitId::MqttIntegration, convergence]),
            ),
            (
                "iotdevice",
                "examples/iotdevice/src/lib.rs",
                BTreeSet::from([convergence]),
            ),
            (
                "identity-composition",
                "composition/identity/src/lib.rs",
                BTreeSet::from([convergence]),
            ),
            (
                "deviceidentity",
                "assemblies/deviceidentity/src/lib.rs",
                BTreeSet::from([IntegrationUnitId::PostgresLib, convergence]),
            ),
        ] {
            let impact = impact_with_facts(
                &root,
                &[DiffEntry::modified(path)],
                facts,
                "unused-for-non-contract-source",
            )?;
            let ImpactSet::Selective(selective) = impact else {
                bail!("{package} change must remain selective");
            };
            assert_eq!(selective.integration_units, expected, "{package}");
            assert!(
                !selective
                    .integration_units
                    .contains(&IntegrationUnitId::AmqpIntegration),
                "{package} must not select the AMQP carrier"
            );
        }
        Ok(())
    }

    #[test]
    fn planning_boundary_rejects_catalog_drift_before_projection() -> Result<()> {
        for (drift, expected) in [
            (
                integration_shards::IntegrationCatalogFixtureDrift::Unassigned,
                "unassigned=[(\"postgres\", \"unassigned_target\", \"test\")]; stale=[]",
            ),
            (
                integration_shards::IntegrationCatalogFixtureDrift::Stale,
                "unassigned=[]; stale=[(\"postgres\", \"migration_0107_resource_security_fact_ledger\", \"test\")]",
            ),
        ] {
            let root = crate::testutil::unique_tmp("ci-impact-catalog-drift");
            fs::create_dir_all(&root)?;
            integration_shards::write_catalog_workspace_fixture(&root, &[], drift)?;
            let status =
                cargo_cmd(CargoSubcommand::GenerateLockfile, &[], &[], Some(&root)).status()?;
            if !status.success() {
                bail!("generate catalog fixture Cargo.lock");
            }

            let Err(error) = plan_event(
                &root,
                "push",
                "{}",
                policy_version(b"schemaVersion=3\nmode='adaptive'\n"),
                PolicyMode::Adaptive,
                "a".repeat(40),
            ) else {
                bail!("catalog drift must fail before SelectionPlan")
            };
            assert!(error.to_string().contains(expected), "{error:#}");

            let Err(coverage_error) = coverage_scope_for_typed_job(&root) else {
                bail!("coverage projection must share catalog fail-closed boundary")
            };
            assert!(
                coverage_error.to_string().contains(expected),
                "{coverage_error:#}"
            );
            let context = LocalExecutionContext {
                base: "a".repeat(40),
                head: "b".repeat(40),
                merge_base: "a".repeat(40),
                cargo_target: root.join("target/local"),
                source: LocalSource::Worker(root.clone()),
            };
            let local_facts = CommandWorkspaceFacts::new(context.root());
            let Err(local_error) = context.impact_entries(&[], &local_facts) else {
                bail!("local planning must share catalog fail-closed boundary")
            };
            assert!(
                local_error.to_string().contains(expected),
                "{local_error:#}"
            );
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn metadata_unavailable_remains_a_conservative_planning_fallback() {
        let root = crate::testutil::unique_tmp("ci-impact-metadata-unavailable");
        let command_facts = CommandWorkspaceFacts::with_metadata_loader(&root, |_| {
            Err("synthetic cargo metadata failure".to_owned())
        });
        assert!(
            matches!(
                validate_planner_catalog(&root, &command_facts),
                Ok(PlannerCatalog::FactsUnavailable(_))
            ),
            "facts acquisition failure must not be confused with catalog drift"
        );
    }

    #[test]
    fn planning_catalog_uses_one_cached_metadata_load_per_command() -> Result<()> {
        use std::cell::Cell;
        use std::rc::Rc;

        let root = crate::testutil::unique_tmp("ci-impact-catalog-cache");
        fs::create_dir_all(&root)?;
        integration_shards::write_catalog_workspace_fixture(
            &root,
            &[],
            integration_shards::IntegrationCatalogFixtureDrift::Exact,
        )?;
        let metadata = cargo_cmd(
            CargoSubcommand::Metadata,
            &["--all-features", "--format-version", "1"],
            &[],
            Some(&root),
        )
        .output()?;
        if !metadata.status.success() {
            bail!("load exact catalog fixture metadata");
        }
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let bytes = metadata.stdout;
        let command_facts = CommandWorkspaceFacts::with_metadata_loader(&root, move |_| {
            counter.set(counter.get() + 1);
            Ok(bytes.clone())
        });
        assert!(matches!(
            validate_planner_catalog(&root, &command_facts)?,
            PlannerCatalog::Available
        ));
        let plan = plan_event_with_facts(
            &root,
            &command_facts,
            "push",
            "{}",
            policy_version(b"schemaVersion=3\nmode='adaptive'\n"),
            PolicyMode::Adaptive,
            "b".repeat(40),
        )?;
        assert_eq!(plan.mode(), SelectionMode::ReleaseCheck);
        assert_eq!(calls.get(), 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn adapter_resources_and_direct_targets_project_exact_critical_units() -> Result<()> {
        use IntegrationUnitId as Id;
        let cases = [
            (
                "adapters/postgres/src/lib.rs",
                "postgres",
                integration_shards::critical_units_for_resource(Resource::Postgres),
            ),
            (
                "adapters/redis/src/lib.rs",
                "redis-adapter",
                integration_shards::critical_units_for_resource(Resource::Redis),
            ),
            (
                "adapters/amqp/src/lib.rs",
                "amqp",
                integration_shards::critical_units_for_resource(Resource::Amqp),
            ),
            (
                "adapters/mqtt/src/lib.rs",
                "mqtt",
                integration_shards::critical_units_for_resource(Resource::Mqtt),
            ),
            (
                "adapters/s3/src/lib.rs",
                "s3",
                integration_shards::critical_units_for_resource(Resource::ObjectStorage),
            ),
        ];
        for (path, package, expected) in cases {
            let mut direct = BTreeMap::new();
            direct.insert(package.to_owned(), BTreeSet::from([PackageImpact::Source]));
            let ImpactSet::Selective(selective) = impact_entries(
                &[DiffEntry::modified(path)],
                None,
                &BTreeSet::new(),
                &direct,
            ) else {
                bail!("adapter path must remain selective: {path}");
            };
            assert_eq!(selective.integration_units, expected, "{path}");
            assert!(
                selective
                    .integration_units
                    .iter()
                    .all(|id| id.spec().shard != IntegrationShard::ProductionRuntime),
                "adapter projection cannot pull T3: {path}"
            );
        }

        let mut direct = BTreeMap::new();
        direct.insert("mqtt".to_owned(), BTreeSet::from([PackageImpact::Test]));
        let ImpactSet::Selective(target) = impact_entries(
            &[DiffEntry::modified("adapters/mqtt/tests/integration.rs")],
            None,
            &BTreeSet::new(),
            &direct,
        ) else {
            bail!("critical target edit must remain selective");
        };
        assert_eq!(
            target.integration_units,
            BTreeSet::from([Id::MqttIntegration])
        );
        assert!(
            !target
                .integration_units
                .contains(&Id::EventTransportDurableE2e)
        );
        Ok(())
    }

    #[test]
    fn postgres_migration_sql_selects_postgres_lib_and_postgres_resource_critical_units()
    -> Result<()> {
        use IntegrationUnitId as Id;
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let rename_entries = parse_diff(
            b"R100\0adapters/postgres/migrations/0001_old.sql\0adapters/postgres/migrations/0001.sql\0",
        )?;
        assert_eq!(rename_entries.len(), 2);
        assert_eq!(rename_entries[0].status, DiffStatus::Deleted);
        assert!(rename_entries[0].rename_or_copy);
        assert_eq!(rename_entries[1].status, DiffStatus::Added);
        assert!(rename_entries[1].rename_or_copy);

        let cases: [(&str, Vec<DiffEntry>); 3] = [
            (
                "added",
                vec![DiffEntry {
                    status: DiffStatus::Added,
                    path: "adapters/postgres/migrations/0001.sql".to_owned(),
                    rename_or_copy: false,
                }],
            ),
            (
                "modified",
                vec![DiffEntry::modified("adapters/postgres/migrations/0001.sql")],
            ),
            ("rename_via_parse_diff", rename_entries),
        ];
        let postgres_critical = integration_shards::critical_units_for_resource(Resource::Postgres);
        for (label, entries) in cases {
            let impact =
                impact_with_facts(&root, &entries, facts, "unused-for-non-contract-source")?;
            let ImpactSet::Selective(selective) = impact else {
                bail!("postgres migration SQL ({label}) must remain selective");
            };
            assert!(
                selective
                    .packages
                    .get("postgres")
                    .is_some_and(|reasons| reasons.contains(&PackageImpact::Source)),
                "migration SQL ({label}) must seed postgres package source impact"
            );
            assert!(
                selective.integration_units.contains(&Id::PostgresLib),
                "migration SQL ({label}) must select IntegrationUnitId::PostgresLib; got {:?}",
                selective.integration_units
            );
            assert!(
                selective.integration_units.is_superset(&postgres_critical),
                "migration SQL ({label}) must project PostgreSQL resource critical units; missing {:?}",
                postgres_critical
                    .difference(&selective.integration_units)
                    .collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    #[test]
    fn shared_journey_sources_follow_their_declared_execution_profiles() -> Result<()> {
        use IntegrationUnitId as Id;
        assert!(matches!(
            impact_entries(
                &[DiffEntry::modified("journeys/tests/common/mod.rs")],
                None,
                &BTreeSet::new(),
                &BTreeMap::new(),
            ),
            ImpactSet::Escalated {
                cause: EscalationCause::GlobalImpact,
                ..
            }
        ));

        let localtx_path = "journeys/tests/support/localtx_validation.rs";
        let ImpactSet::Selective(localtx) = impact_entries(
            &[DiffEntry::modified(localtx_path)],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("critical-only shared journey source must remain selective: {localtx_path}");
        };
        assert_eq!(
            localtx.integration_units,
            BTreeSet::from([
                Id::AuditListTenantEntriesLocalTxJourney,
                Id::SettingsSecretPublishLocalTxJourney,
            ])
        );

        let ImpactSet::Selective(manifest) = impact_entries(
            &[DiffEntry::modified("journeys/Cargo.toml")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("journeys manifest must select its critical target set");
        };
        let expected = IntegrationUnitId::ALL
            .into_iter()
            .filter(|id| {
                id.spec().package == "journeys"
                    && id.spec().primary_owner
                        == crate::execution_profiles::ExecutionProfile::IntegrationCritical
            })
            .collect::<BTreeSet<_>>();
        assert!(!expected.is_empty(), "journeys critical-set anti-vacuity");
        assert_eq!(manifest.integration_units, expected);
        Ok(())
    }

    #[test]
    fn undeclared_journey_support_fails_closed() {
        let path = "journeys/tests/support/new_shared_fixture.rs";
        assert!(
            classify_diff(&[DiffEntry::modified(path)]).mode == SelectionMode::PrComplete,
            "{path} must require the complete PR set without a declared critical carrier"
        );
    }

    #[test]
    fn oidc_provider_change_selects_all_declared_critical_carriers() -> Result<()> {
        use IntegrationUnitId as Id;
        let ImpactSet::Selective(impact) = impact_entries(
            &[DiffEntry::modified("adapters/oidc/src/verify.rs")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("OIDC provider must use its exact critical carrier set");
        };
        assert_eq!(
            impact.integration_units,
            BTreeSet::from([
                Id::IdentityPasswordSecurityEventJourney,
                Id::IdentityRefreshProducerTransactionJourney,
                Id::IdentityLoginWireE2e,
                Id::ServiceTokenReplayE2e,
            ])
        );
        Ok(())
    }

    #[test]
    fn vault_provider_change_selects_the_unique_live_carrier() -> Result<()> {
        use IntegrationUnitId as Id;
        let ImpactSet::Selective(impact) = impact_entries(
            &[DiffEntry::modified("adapters/vault/src/pki.rs")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("Vault provider must use its exact critical carrier set");
        };
        assert_eq!(impact.integration_units, BTreeSet::from([Id::VaultLive]));
        let ImpactSet::Selective(unrelated) = impact_entries(
            &[DiffEntry::modified("crates/diport/src/outbox_emitter.rs")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("unrelated diport source must stay selective");
        };
        assert!(
            !unrelated.integration_units.contains(&Id::VaultLive),
            "the relation must remain path-exact"
        );
        Ok(())
    }

    #[test]
    fn diport_pki_seam_selects_the_unique_vault_live_carrier() -> Result<()> {
        use IntegrationUnitId as Id;
        let ImpactSet::Selective(impact) = impact_entries(
            &[DiffEntry::modified("crates/diport/src/pki_artifact.rs")],
            None,
            &BTreeSet::new(),
            &BTreeMap::new(),
        ) else {
            bail!("diport PKI seam must select its exact critical carrier");
        };
        assert_eq!(impact.integration_units, BTreeSet::from([Id::VaultLive]));
        Ok(())
    }

    #[test]
    fn contract_runtime_and_localtx_relations_are_closed_markers() -> Result<()> {
        use IntegrationUnitId as Id;
        let mut contracts = BTreeMap::new();
        contracts.insert(
            "identity".to_owned(),
            BTreeSet::from([PackageImpact::ContractOwner]),
        );
        contracts.insert(
            "audit".to_owned(),
            BTreeSet::from([PackageImpact::ContractSubscriber]),
        );
        let ImpactSet::Selective(contract) = impact_entries(
            &[DiffEntry::modified(
                "contracts/http/identity/v1/login/contract.toml",
            )],
            None,
            &BTreeSet::new(),
            &contracts,
        ) else {
            bail!("contract relation must remain selective");
        };
        for localtx in [
            Id::AuditListTenantEntriesLocalTxJourney,
            Id::IdentityPasswordSecurityEventJourney,
            Id::IdentityRefreshProducerTransactionJourney,
            Id::SettingsSecretPublishLocalTxJourney,
        ] {
            assert!(contract.integration_units.contains(&localtx));
        }

        let mut runtime = BTreeMap::new();
        runtime.insert(
            "runtime".to_owned(),
            BTreeSet::from([PackageImpact::Source]),
        );
        let ImpactSet::Selective(runtime) = impact_entries(
            &[DiffEntry::modified("assemblies/runtime/src/lib.rs")],
            None,
            &BTreeSet::new(),
            &runtime,
        ) else {
            bail!("runtime surface must remain selective");
        };
        assert_eq!(
            runtime.integration_units,
            integration_shards::critical_units_for_markers(&BTreeSet::from([
                ImpactMarker::RuntimeSurface,
            ]))
        );
        assert!(
            runtime
                .integration_units
                .iter()
                .all(|id| id.spec().shard != IntegrationShard::ProductionRuntime)
        );
        Ok(())
    }

    #[test]
    fn device_latent_candidate_selects_only_declared_pr_critical_carriers() -> Result<()> {
        use IntegrationUnitId as Id;

        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let ImpactSet::Selective(impact) = impact_with_facts(
            &root,
            &[DiffEntry::modified(
                "contracts/http/identity/v2/device-certificate-policy-put/contract.toml",
            )],
            command_facts.get()?,
            UNKNOWN_REVISION,
        )?
        else {
            bail!("device-certificate candidate must remain selectively planned");
        };

        assert_eq!(
            impact.integration_units,
            BTreeSet::from([Id::PostgresLib, Id::DeviceCertificateConvergenceJourney])
        );
        assert!(impact.packages.contains_key("observ"));
        for release_only in [
            Id::DeviceIdentityLib,
            Id::RuntimeLib,
            Id::MqttBackpressureFaultJourney,
        ] {
            assert!(!impact.integration_units.contains(&release_only));
            assert_eq!(
                release_only.spec().primary_owner,
                crate::execution_profiles::ExecutionProfile::ReleaseCheck
            );
        }
        assert!(
            impact
                .local_meta_domains
                .contains(&LocalImpactDomain::ContractBinding)
        );
        let local_gates = local_meta_gates(Some(&impact.local_meta_domains));
        for gate in [
            GateId::ContractValidate,
            GateId::CodegenCheck,
            GateId::ContractBindingGuard,
        ] {
            assert!(
                local_gates.contains(&gate),
                "missing candidate gate {gate:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn device_latent_candidate_and_evidence_paths_are_typed_and_non_vacuous() -> Result<()> {
        use IntegrationUnitId as Id;

        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let mut candidate_paths = BTreeSet::new();
        for candidate in crate::contract::DeviceCertificateCandidateId::ALL {
            let source_dir = candidate.spec().source_dir;
            candidate_paths.insert(format!("{source_dir}/contract.toml"));
            for entry in std::fs::read_dir(root.join(source_dir))? {
                let path = entry?.path();
                if path.extension() == Some(OsStr::new("json")) {
                    candidate_paths
                        .insert(path.strip_prefix(&root)?.to_string_lossy().into_owned());
                }
            }
        }
        let evidence_paths = DeviceLatentEvidenceId::ALL
            .into_iter()
            .map(DeviceLatentEvidenceId::spec)
            .map(|spec| spec.source_path)
            .collect::<BTreeSet<_>>();

        assert!(candidate_paths.len() > 6);
        assert_eq!(evidence_paths.len(), 6);
        assert!(device_latent_candidate_impact_path(
            "generated/src/device_certificate.rs"
        ));
        for path in candidate_paths
            .iter()
            .map(String::as_str)
            .chain(["generated/src/device_certificate.rs"])
        {
            assert!(
                device_latent_candidate_impact_path(path),
                "missing typed impact edge for {path}"
            );
            let ImpactSet::Selective(impact) =
                impact_with_facts(&root, &[DiffEntry::modified(path)], facts, UNKNOWN_REVISION)?
            else {
                bail!("typed DeviceLatent path {path} must remain selective");
            };
            assert_eq!(
                impact.integration_units,
                BTreeSet::from([Id::PostgresLib, Id::DeviceCertificateConvergenceJourney]),
                "unexpected PR-critical projection for {path}"
            );
            assert!(
                !impact
                    .integration_units
                    .contains(&Id::MqttBackpressureFaultJourney),
                "ReleaseCheck-only MQTT evidence leaked for {path}"
            );
        }
        for path in evidence_paths {
            assert!(
                device_latent_evidence_impact_path(path),
                "missing typed evidence impact edge for {path}"
            );
            assert!(device_latent_semantic_impact_path(path));
            assert!(!device_latent_candidate_impact_path(path));
        }
        Ok(())
    }

    #[test]
    fn device_latent_evidence_paths_preserve_owner_first_selection_red() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let evidence_paths = DeviceLatentEvidenceId::ALL
            .into_iter()
            .map(DeviceLatentEvidenceId::spec)
            .map(|spec| spec.source_path)
            .collect::<BTreeSet<_>>();

        for path in evidence_paths {
            let impact =
                impact_with_facts(&root, &[DiffEntry::modified(path)], facts, UNKNOWN_REVISION)?;
            match integration_shards::changed_integration_source(path) {
                Some(ChangedIntegrationSource::ReleaseCheck) => assert!(
                    matches!(
                        impact,
                        ImpactSet::Escalated {
                            cause: EscalationCause::GlobalImpact,
                            ..
                        }
                    ),
                    "release-owned evidence must retain its ordinary fail-closed selection: {path}"
                ),
                exact => {
                    let ImpactSet::Selective(impact) = impact else {
                        bail!("affected evidence owner must remain selectively planned: {path}");
                    };
                    let package = facts
                        .package_for_repo_path(Path::new(path))?
                        .context("DeviceLatent evidence package")?;
                    assert!(
                        impact.packages.contains_key(package.as_str()),
                        "evidence owner package was swallowed for {path}"
                    );
                    if let Some(ChangedIntegrationSource::Exact(units)) = exact {
                        assert!(
                            units.is_subset(&impact.integration_units),
                            "exact evidence target was swallowed for {path}"
                        );
                    }
                }
            }
        }
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
                    RemoteProjection {
                        mode: SelectionMode::PrComplete,
                        cause: Some(EscalationCause::GlobalImpact),
                        ..
                    }
                ),
                "machine-consumed input {path} must conservatively execute the complete PR set"
            );
        }
    }

    #[test]
    fn ci_cache_governance_inputs_always_select_the_complete_pr_set() {
        for path in [
            ".github/actions/setup-rss-ci/action.yml",
            ".github/actions/finalize-rss-ci/action.yml",
            ".github/scripts/ci-cache-maintain.sh",
            ".github/scripts/ci-sccache-stats.sh",
            ".github/workflows/new-cache-caller.yaml",
        ] {
            assert!(
                matches!(
                    classify_diff(&[DiffEntry::modified(path)]),
                    RemoteProjection {
                        mode: SelectionMode::PrComplete,
                        cause: Some(EscalationCause::GlobalImpact),
                        ..
                    }
                ),
                "cache governance input {path} must execute the complete PR set"
            );
        }
    }

    #[test]
    fn shared_impact_facts_decision_loads_zero_for_empty_and_docs_and_once_for_rust() -> Result<()>
    {
        use std::cell::Cell;
        use std::rc::Rc;

        let metadata = synthetic_workspace_metadata(
            vec![(
                "leaf",
                "crates/leaf",
                vec![metadata_target("leaf", "lib", true, &[], "crates/leaf")],
                Vec::new(),
            )],
            Vec::new(),
        )?;
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let command_facts =
            CommandWorkspaceFacts::with_metadata_loader(Path::new("/workspace"), move |_| {
                counter.set(counter.get() + 1);
                Ok(metadata.clone().into_bytes())
            });

        assert!(workspace_facts_for_impact(&[], &command_facts)?.is_none());
        assert!(
            workspace_facts_for_impact(
                &[DiffEntry::modified("docs/guides/workspace-facts.md")],
                &command_facts,
            )?
            .is_none()
        );
        assert_eq!(calls.get(), 0);

        assert!(
            workspace_facts_for_impact(
                &[DiffEntry::modified("crates/leaf/src/lib.rs")],
                &command_facts,
            )?
            .is_some()
        );
        assert!(
            workspace_facts_for_impact(
                &[DiffEntry::modified("crates/leaf/src/other.rs")],
                &command_facts,
            )?
            .is_some()
        );
        assert_eq!(calls.get(), 1);
        Ok(())
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
    fn nul_diff_parser_rejects_unknown_and_non_utf8() -> Result<()> {
        assert!(parse_diff(b"X\0path\0").is_err());
        assert!(parse_diff(b"M100\0path\0").is_err());
        assert!(parse_diff(b"Rfoo\0old\0new\0").is_err());
        assert!(parse_diff(b"M\0\0").is_err());
        assert!(parse_diff(b"M\0bad\xff\0").is_err());
        let rename = parse_diff(b"R100\0old\0new\0")?;
        assert_eq!(rename.len(), 2);
        assert_eq!(rename[0].status, DiffStatus::Deleted);
        assert_eq!(rename[0].path, "old");
        assert_eq!(rename[1].status, DiffStatus::Added);
        assert_eq!(rename[1].path, "new");
        assert!(rename.iter().all(|entry| entry.rename_or_copy));
        Ok(())
    }

    #[test]
    fn workspace_facts_close_reverse_dependencies_and_preserve_target_semantics() -> Result<()> {
        let serde_external = registry_package(
            "serde",
            "1.0.0",
            "/registry/serde/Cargo.toml",
            vec![testing_target(
                "serde",
                "lib",
                "/registry/serde/src/lib.rs",
                true,
                &[],
            )],
        );
        let facts = synthetic_workspace_facts_with_externals(
            vec![
                (
                    "leaf",
                    "crates/leaf",
                    vec![metadata_target("leaf", "lib", false, &[], "crates/leaf")],
                    Vec::new(),
                ),
                (
                    "consumer",
                    "crates/consumer",
                    vec![
                        metadata_target("consumer", "lib", true, &[], "crates/consumer"),
                        metadata_target(
                            "consumer_integration",
                            "test",
                            true,
                            &[],
                            "crates/consumer",
                        ),
                        metadata_target("demo", "example", true, &[], "crates/consumer"),
                        metadata_target("throughput", "bench", true, &[], "crates/consumer"),
                        metadata_target(
                            "build-script",
                            "custom-build",
                            false,
                            &[],
                            "crates/consumer",
                        ),
                    ],
                    vec!["leaf"],
                ),
                (
                    "securederive",
                    "crates/securederive",
                    vec![metadata_target(
                        "securederive",
                        "proc-macro",
                        true,
                        &[],
                        "crates/securederive",
                    )],
                    Vec::new(),
                ),
                (
                    "xtask",
                    "xtask",
                    vec![metadata_target("xtask", "bin", true, &[], "xtask")],
                    Vec::new(),
                ),
            ],
            vec![serde_external],
        )?;
        assert_eq!(
            facts
                .package_for_repo_path(Path::new("crates/leaf/src/lib.rs"))?
                .as_ref()
                .map(PackageKey::as_str),
            Some("leaf"),
        );
        assert_eq!(
            reverse_closure(&facts, &BTreeSet::from(["leaf".to_owned()]))?,
            BTreeSet::from(["consumer".to_owned(), "leaf".to_owned()])
        );
        assert!(
            matches!(
                facts.package_key("serde"),
                Err(workspacefacts::WorkspaceFactsError::UnknownPackage(_))
            ),
            "registry package in packages[] but not workspace_members must stay unknown"
        );
        assert!(
            !reverse_closure(&facts, &BTreeSet::from(["leaf".to_owned()]))?.contains("serde"),
            "reverse closure must not admit registry packages"
        );
        assert!(
            !package_has_test_targets(&facts, "leaf")?,
            "a lib harness does not prove a non-empty nextest inventory"
        );
        assert!(package_has_test_targets(&facts, "consumer")?);
        assert!(
            package_has_test_targets(&facts, "securederive")?,
            "an enabled proc-macro harness remains package-test capable"
        );
        assert!(package_has_test_targets(&facts, "xtask")?);
        assert!(package_has_lib_target(&facts, "leaf")?);
        assert!(package_has_lib_target(&facts, "consumer")?);
        assert!(
            package_has_lib_target(&facts, "securederive")?,
            "proc-macro kind must count as lib-capable for check --lib"
        );
        assert!(
            !package_has_lib_target(&facts, "xtask")?,
            "bin-only package must not be lib-capable"
        );
        let local_targets = local_cargo_targets(&facts, "consumer", LocalCargoOperation::Test)?;
        assert_eq!(
            local_targets,
            vec![
                LocalCargoTarget::Lib,
                LocalCargoTarget::Test {
                    name: "consumer_integration".to_owned(),
                    required_features: Vec::new(),
                },
                LocalCargoTarget::Doc,
            ],
            "example/bench/build-script must not enter local cargo eligibility"
        );
        Ok(())
    }

    #[test]
    fn workspace_facts_distinguish_unit_test_lib_from_empty_binary_harness() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        assert!(
            package_has_test_targets(facts, "grpc")?,
            "grpc lib unit tests must retain package-scoped execution"
        );
        assert!(
            package_has_test_targets(facts, "iotdevice")?,
            "iotdevice is a library test-support actor with package-scoped tests"
        );
        Ok(())
    }

    #[test]
    fn reverse_closure_cannot_invent_integration_relations_and_unknown_contracts_fail_closed()
    -> Result<()> {
        let source_facts = synthetic_chain_facts(
            &[("generated", "generated"), ("crates/leaf", "leaf")],
            Some("leaf"),
        )?;
        for path in ["crates/leaf/src/lib.rs", "generated/src/http/leaf_v1.rs"] {
            let projection = classify_with_facts(
                Path::new("/workspace"),
                &[DiffEntry::modified(path)],
                &source_facts,
                UNKNOWN_REVISION,
            )?;
            assert!(
                projection
                    .integration_units
                    .iter()
                    .all(|unit| unit.spec().shard != IntegrationShard::RuntimeHttpAuth),
                "{path} has no closed runtime marker; dependency closure cannot invent one"
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
        let contract_facts = synthetic_chain_facts(
            &[("crates/owner", "owner"), ("crates/consumer", "consumer")],
            Some("consumer"),
        )?;
        let error = classify_with_facts(
            &root,
            &[DiffEntry {
                status: DiffStatus::Added,
                path: "contracts/event/owner/v1/policy-updated/contract.toml".to_owned(),
                rename_or_copy: false,
            }],
            &contract_facts,
            UNKNOWN_REVISION,
        )
        .err()
        .context("unknown contract relation must fail closed")?;
        assert!(
            error
                .to_string()
                .contains("outside the closed integration impact relation"),
            "{error:#}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn contracts_readme_is_documentation_not_manifest_impact() -> Result<()> {
        assert!(
            documentation("contracts/README.md"),
            "contracts/README.md must use the shared documentation classifier"
        );
        assert!(
            contract_manifest_path("contracts/README.md").is_none(),
            "contracts/README.md is not a contract package path"
        );

        let facts = synthetic_chain_facts(
            &[
                ("crates/identity", "identity"),
                ("crates/audit", "audit"),
                ("adapters/postgres", "postgres"),
            ],
            Some("identity"),
        )?;
        let root = crate::testutil::unique_tmp("ci-impact-contracts-readme");
        fs::create_dir_all(root.join("contracts"))?;
        fs::write(root.join("contracts/README.md"), "# contracts\n")?;

        let impact = impact_with_facts(
            &root,
            &[DiffEntry::modified("contracts/README.md")],
            &facts,
            UNKNOWN_REVISION,
        )
        .context("contracts/README.md must not fail facts contract preprocessing")?;
        let ImpactSet::Selective(selective) = impact else {
            bail!("contracts/README.md must remain selective documentation");
        };
        assert!(
            selective.documentation,
            "contracts/README.md is documentation/governance"
        );
        assert!(
            selective.packages.is_empty(),
            "contracts/README.md must not seed contract owner/subscriber packages"
        );
        fs::remove_dir_all(&root)?;

        // Basename matching must not widen nested README into docs-only.
        for (path, expect_docs) in [
            ("adapters/postgres/migrations/README.md", false),
            ("deploy/demo-tls/README.md", false),
        ] {
            assert_eq!(
                documentation(path),
                expect_docs,
                "{path} must not inherit basename README documentation"
            );
        }

        let nested_package = impact_with_facts(
            Path::new("/workspace"),
            &[DiffEntry::modified(
                "adapters/postgres/migrations/README.md",
            )],
            &facts,
            UNKNOWN_REVISION,
        )?;
        let ImpactSet::Selective(nested) = nested_package else {
            bail!("package-owned nested README must remain selective");
        };
        assert!(
            !nested.documentation,
            "adapters/postgres/migrations/README.md must not become docs-only"
        );
        assert!(
            nested
                .packages
                .get("postgres")
                .is_some_and(|reasons| reasons.contains(&PackageImpact::Source)),
            "package-owned nested README keeps package source impact"
        );

        let unknown = impact_with_facts(
            Path::new("/workspace"),
            &[DiffEntry::modified("deploy/demo-tls/README.md")],
            &facts,
            UNKNOWN_REVISION,
        )?;
        let ImpactSet::Selective(unknown_selective) = unknown else {
            bail!("unowned nested README must stay selective until unknown projection");
        };
        assert!(
            !unknown_selective.documentation,
            "deploy/demo-tls/README.md must not become docs-only"
        );
        assert!(
            unknown_selective
                .unknown_paths
                .contains("deploy/demo-tls/README.md"),
            "unowned nested README remains fail-closed unknown"
        );
        assert_eq!(
            RemoteProjection::from(&ImpactSet::Selective(unknown_selective)).mode,
            SelectionMode::PrComplete,
            "unowned nested README escalates via unknown-path fail-closed"
        );

        // Real contract.toml / schema keep owner+subscriber through impact_with_facts.
        let workspace = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&workspace);
        let workspace_facts = command_facts.get()?;
        for path in [
            "contracts/event/identity/v1/policy-updated/contract.toml",
            "contracts/event/identity/v1/policy-updated/payload.schema.json",
        ] {
            let ImpactSet::Selective(contract) = impact_with_facts(
                &workspace,
                &[DiffEntry {
                    status: DiffStatus::Added,
                    path: path.to_owned(),
                    rename_or_copy: false,
                }],
                workspace_facts,
                UNKNOWN_REVISION,
            )
            .with_context(|| format!("{path} must classify through impact_with_facts"))?
            else {
                bail!("{path} must remain selective contract impact");
            };
            assert!(
                !contract.documentation,
                "{path} is a real contract artifact, not documentation"
            );
            assert!(
                contract
                    .packages
                    .get("identity")
                    .is_some_and(|reasons| reasons.contains(&PackageImpact::ContractOwner)),
                "{path} must keep contract owner impact"
            );
            assert!(
                contract
                    .packages
                    .get("audit")
                    .is_some_and(|reasons| reasons.contains(&PackageImpact::ContractSubscriber)),
                "{path} must keep contract subscriber impact"
            );
        }
        Ok(())
    }

    #[test]
    fn contract_owner_subscriber_and_merge_base_deletion_are_preserved() -> Result<()> {
        let workspace = crate::workspace_root()?;
        assert_eq!(
            contract_packages(
                &workspace,
                "contracts/http/runtime/v1/inventory/response.schema.json",
                DiffStatus::Added,
                "unused",
            )?,
            BTreeSet::from([
                "identityaudit".to_owned(),
                "runtime".to_owned(),
                "settingsonly".to_owned(),
            ]),
            "framework-owned contracts must select every assembly that mounts the contract"
        );
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
    fn component_change_fans_out_to_every_referencing_contract_owner() -> Result<()> {
        let workspace = crate::workspace_root()?;
        let component_path = "contracts/components/identity/v1/common-abac-operator.schema.json";
        assert_eq!(
            contract_packages(
                &workspace,
                component_path,
                DiffStatus::Added,
                "origin/develop",
            )?,
            BTreeSet::from(["identity".to_owned()])
        );
        let domains = local_impact_domains(component_path);
        assert!(domains.contains(&LocalImpactDomain::ContractBinding));
        assert!(
            local_meta_gates(Some(&domains)).contains(&GateId::CodegenCheck),
            "component changes must run generated output drift detection"
        );
        Ok(())
    }

    #[test]
    fn component_graph_uses_exact_parsed_refs_and_follows_transitive_components() -> Result<()> {
        let target = ComponentId::parse("rss://component/identity/v1/target")?;
        let referrer = "rss://component/identity/v1/referrer";
        let consumers = component_consumers_from_files(
            &target,
            [
                (
                    "contracts/components/identity/v1/target.schema.json".to_owned(),
                    format!(r#"{{"$id":"{target}","title":"Target"}}"#),
                ),
                (
                    "contracts/components/identity/v1/referrer.schema.json".to_owned(),
                    format!(
                        r#"{{"$id":"{referrer}","$ref":"rss:\/\/component\/identity\/v1\/target"}}"#
                    ),
                ),
                (
                    "contracts/http/alpha/v1/use/request.schema.json".to_owned(),
                    format!(r#"{{"$ref":"{referrer}"}}"#),
                ),
                (
                    "contracts/http/decoy/v1/use/request.schema.json".to_owned(),
                    format!(r#"{{"description":"{target}"}}"#),
                ),
            ],
        )?;
        assert_eq!(
            consumers,
            BTreeSet::from(["contracts/http/alpha/v1/use/contract.toml".to_owned()])
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn component_graph_rejects_working_schema_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("ci-impact-component-symlink");
        let contract = root.join("contracts/http/identity/v1/consumer");
        fs::create_dir_all(&contract)?;
        fs::write(
            root.join("outside.schema.json"),
            r#"{"$ref":"rss://component/identity/v1/shared"}"#,
        )?;
        symlink(
            root.join("outside.schema.json"),
            contract.join("request.schema.json"),
        )?;
        let component = ComponentId::parse("rss://component/identity/v1/shared")?;
        let Err(error) = working_component_consumers(&root, &component) else {
            bail!("schema symlink must fail closed")
        };
        assert!(error.to_string().contains("rejects symlink"), "{error:#}");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn component_change_unions_required_working_and_base_consumers() -> Result<()> {
        fn write_consumer(root: &Path, domain: &str, subscriber: &str, schema: &str) -> Result<()> {
            let directory = root.join(format!("contracts/event/{domain}/v1/changed"));
            fs::create_dir_all(&directory)?;
            fs::write(
                directory.join("contract.toml"),
                format!(
                    r#"id = "{domain}.changed"
kind = "event"
domain = "{domain}"
version = "v1"
owner = "{domain}"
consistencyLevel = "OutboxFact"
lifecycle = "active"
topic = "{domain}.changed"
delivery = "at-least-once"
[schemas]
payload = "payload.schema.json"
[[subscriptions]]
consumer = "{subscriber}"
group = "{subscriber}.changed"
execution = "adapter-native"
externalEffectPolicy = "transactional-only"
[subscriptions.topology]
partitionKey = "none"
readiness = "required"
"#,
                ),
            )?;
            fs::write(directory.join("payload.schema.json"), schema)?;
            Ok(())
        }

        let root = crate::testutil::unique_tmp("ci-impact-component-union");
        let component = root.join("contracts/components/identity/v1");
        fs::create_dir_all(&component)?;
        fs::write(
            component.join("shared.schema.json"),
            r#"{"$id":"rss://component/identity/v1/shared","title":"Shared","type":"string"}"#,
        )?;
        write_consumer(
            &root,
            "baseowner",
            "basesubscriber",
            r#"{"$ref":"rss://component/identity/v1/shared"}"#,
        )?;
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
                bail!("failed to create component fanout fixture");
            }
        }
        let base = git_stdout(&root, ["rev-parse", "HEAD"])?;
        fs::write(
            root.join("contracts/event/baseowner/v1/changed/payload.schema.json"),
            "{}",
        )?;
        write_consumer(
            &root,
            "workingowner",
            "workingsubscriber",
            r#"{"$ref":"rss:\/\/component\/identity\/v1\/shared"}"#,
        )?;
        assert_eq!(
            contract_packages(
                &root,
                "contracts/components/identity/v1/shared.schema.json",
                DiffStatus::Modified,
                base.trim(),
            )?,
            BTreeSet::from([
                "baseowner".to_owned(),
                "basesubscriber".to_owned(),
                "workingowner".to_owned(),
                "workingsubscriber".to_owned(),
            ])
        );
        assert!(
            contract_packages(
                &root,
                "contracts/components/identity/v1/shared.schema.json",
                DiffStatus::Deleted,
                "missing-base",
            )
            .is_err(),
            "required merge-base reads must fail closed"
        );
        fs::remove_file(root.join("contracts/event/workingowner/v1/changed/contract.toml"))?;
        assert!(
            contract_packages(
                &root,
                "contracts/components/identity/v1/shared.schema.json",
                DiffStatus::Added,
                "unused",
            )
            .is_err(),
            "a missing working consumer manifest must fail closed"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn path_policy_covers_full_core_security_and_generated_cases() {
        let cases = [
            ("Cargo.lock", SelectionMode::PrComplete, None),
            (
                "crates/identity/tests/route.rs",
                SelectionMode::Adaptive,
                Some("identity"),
            ),
            (
                "crates/identity/Cargo.toml",
                SelectionMode::Adaptive,
                Some("identity"),
            ),
            (
                "generated/src/event/mod.rs",
                SelectionMode::PrComplete,
                None,
            ),
        ];
        for (path, mode, affected) in cases {
            let projection = classify_diff(&[DiffEntry::modified(path)]);
            assert_eq!(projection.mode, mode, "{path}");
            if let Some(package) = affected {
                assert!(projection.affected_packages.contains(package), "{path}");
            }
        }
    }

    fn assert_policy_catalog_shape(catalog: &[String]) {
        assert_eq!(
            catalog
                .iter()
                .filter(|field| field.starts_with("integration-adapter-projection="))
                .count(),
            AdapterPackage::ALL.len(),
            "adapter selector relation catalog must be non-vacuous and complete"
        );
        assert_eq!(
            catalog
                .iter()
                .filter(|field| field.starts_with("integration-impact-package="))
                .count(),
            ImpactMarker::PACKAGE_RELATIONS.len(),
            "impact selector relation catalog must be non-vacuous and complete"
        );
        let shared_source_fields = catalog
            .iter()
            .filter(|field| field.starts_with("integration-shared-source="))
            .collect::<Vec<_>>();
        assert_eq!(
            shared_source_fields.len(),
            integration_shards::shared_source_relation_semantics().len(),
            "shared-source relation catalog must be complete"
        );
        assert_eq!(
            catalog
                .iter()
                .filter(|field| field.starts_with("documentation-path="))
                .count(),
            DOCUMENTATION_PATHS.len(),
            "documentation-path catalog must mirror DOCUMENTATION_PATHS"
        );
        assert!(
            catalog
                .iter()
                .any(|field| field == "documentation-path=contracts/README.md"),
            "contracts/README.md must be an exact documentation catalog entry"
        );
        assert!(shared_source_fields.iter().any(|field| {
            field.contains("journeys/tests/common/mod.rs")
                && field.contains("amqp-consumer-at-least-once-journey")
                && field.contains("identity-login-audit-durable-journey")
        }));
        assert_eq!(
            catalog
                .iter()
                .filter(|field| field.starts_with("selection-mode="))
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "selection-mode=adaptive",
                "selection-mode=pr-complete",
                "selection-mode=release-check",
            ],
            "the closed selection modes must be complete policy semantics"
        );
        assert!(
            catalog.iter().all(|field| !field.starts_with("job-")),
            "dynamic job and receipt identities must not remain policy semantics"
        );
    }

    fn assert_policy_selector_mutations_rotate(compact: &[u8], catalog: &[String]) -> Result<()> {
        let mut changed_catalog = catalog.to_vec();
        changed_catalog.push("impact-rule=new-semantic-rule".to_owned());
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &changed_catalog),
            "an explicit catalog semantic change must rotate policyVersion"
        );
        assert_ne!(
            policy_version_with_catalog(compact, &["ab".to_owned(), "c".to_owned()]),
            policy_version_with_catalog(compact, &["a".to_owned(), "bc".to_owned()]),
            "length-delimited fields must not permit concatenation ambiguity"
        );
        let resource_mutation = policy_semantic_catalog_with_selector_overrides(
            POLICY_BEHAVIOR_SPEC,
            Some((IntegrationUnitId::PostgresLib, &[Resource::Redis])),
            None,
            None,
        );
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &resource_mutation),
            "integration execution-resource mutation must rotate policyVersion"
        );
        let adapter_relation_mutation = policy_semantic_catalog_with_selector_overrides(
            POLICY_BEHAVIOR_SPEC,
            None,
            Some((
                AdapterPackage::Postgres,
                AdapterProjection::Resource(Resource::Redis),
            )),
            None,
        );
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &adapter_relation_mutation),
            "adapter package-to-resource mutation must rotate policyVersion"
        );
        let provider_relation_mutation = policy_semantic_catalog_with_selector_overrides(
            POLICY_BEHAVIOR_SPEC,
            None,
            Some((
                AdapterPackage::Oidc,
                AdapterProjection::SecurityProvider(
                    crate::integration_shards::SecurityProvider::Vault,
                ),
            )),
            None,
        );
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &provider_relation_mutation),
            "security-provider projection mutation must rotate policyVersion"
        );
        let mut shared_source_mutation = catalog.to_vec();
        let source = shared_source_mutation
            .iter_mut()
            .find(|field| field.contains("journeys/tests/common/mod.rs"))
            .context("shared journey source policy field")?;
        source.push_str(",settings-config-publish-durable-e2e");
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &shared_source_mutation),
            "shared source-to-carrier mutation must rotate policyVersion"
        );
        let impact_relation_mutation = policy_semantic_catalog_with_selector_overrides(
            POLICY_BEHAVIOR_SPEC,
            None,
            None,
            Some(("postgres", ImpactMarker::RedisAdapterPackage)),
        );
        assert_ne!(
            policy_version_with_catalog(compact, catalog),
            policy_version_with_catalog(compact, &impact_relation_mutation),
            "impact package-to-marker mutation must rotate policyVersion"
        );
        Ok(())
    }

    fn assert_policy_behavior_formatting_semantics(compact: &[u8]) -> Result<()> {
        let semantically_same_behavior =
            serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(
                POLICY_BEHAVIOR_SPEC,
            )?)?;
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
        Ok(())
    }

    #[test]
    fn policy_digest_is_deterministic_and_binds_config() -> Result<()> {
        let compact = b"schemaVersion=3\nmode='adaptive'\n";
        let formatted =
            b"# operator comment\nschemaVersion = 3\n\nmode = \"adaptive\" # same policy\n";
        assert_eq!(
            policy_version(compact),
            policy_version(formatted),
            "formatting and comments are not policy semantics"
        );
        assert_ne!(
            policy_version(compact),
            policy_version(b"schemaVersion=1\nmode='adaptive'\n")
        );
        assert!(toml::from_str::<PolicyWire>("schemaVersion=3\nmode='shadow'\n").is_err());
        assert!(matches!(
            toml::from_str::<PolicyWire>("schemaVersion=2\nmode='adaptive'\n"),
            Ok(legacy) if legacy.schema_version != POLICY_SCHEMA_VERSION
        ));
        let catalog = policy_semantic_catalog();
        assert_policy_catalog_shape(&catalog);
        assert_policy_selector_mutations_rotate(compact, &catalog)?;
        assert_policy_behavior_formatting_semantics(compact)
    }

    #[test]
    fn fallback_selection_exposes_stable_actionable_context_red() -> Result<()> {
        let selection = fallback_selection(
            "a".repeat(64),
            DecisionReason::DiffUnavailable,
            SelectionMode::PrComplete,
            "e".repeat(40),
        )?;
        let wire: serde_json::Value = serde_json::from_str(&selection.to_json()?)?;
        assert_eq!(wire["fallbackContext"]["code"], "CI-PLAN-DIFF-UNAVAILABLE");
        assert_eq!(wire["fallbackContext"]["stage"], "diff");
        assert!(
            wire["fallbackContext"]["action"]
                .as_str()
                .is_some_and(|action| action.to_ascii_lowercase().contains("fetch")),
            "fallback diagnostic must include a stable remediation without leaking raw errors"
        );
        assert!(matches!(
            selection.public_api_selection(),
            ProjectedPublicApiSelection::CompleteInternal
        ));
        assert_eq!(
            wire["selection"]["public_api"]["scope"],
            "complete-internal"
        );
        assert!(
            local_steps(&ImpactSet::escalated(EscalationCause::UnknownPath))
                .contains(&LocalStep::CompleteInternalPublicApi)
        );
        let summary = render_selection_summary(&selection);
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

        let mut forged = selection.clone();
        let context = forged
            .fallback_context
            .as_mut()
            .context("fallback fixture context is missing")?;
        context.subject = Some("/runner/_work/private".to_owned());
        context.action = "`injected`\n# heading".to_owned();
        assert!(SelectionPlan::from_json(&forged.to_json()?).is_err());
        Ok(())
    }

    #[test]
    fn workspace_policy_catalog_is_non_vacuous() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        assert_eq!(
            facts
                .package_for_repo_path(Path::new("xtask/src/ci_impact.rs"))?
                .as_ref()
                .map(PackageKey::as_str),
            Some("xtask"),
        );
        assert!(
            !package_has_lib_target(facts, "xtask")?,
            "xtask is bin-only; check reverse closure must omit --lib"
        );
        let release = IntegrationSelection::for_profile(
            crate::execution_profiles::ExecutionProfile::ReleaseCheck,
        )?;
        for shard in IntegrationShard::ALL {
            let batches = integration_shards::batches(&release, *shard);
            assert!(
                !batches.is_empty(),
                "{} has no execution units",
                shard.as_str()
            );
            assert!(
                batches
                    .iter()
                    .all(|batch| facts.package_key(batch.package).is_ok()),
                "{} references a package outside cargo metadata",
                shard.as_str()
            );
        }
        let projection = classify_with_facts(
            &root,
            &[DiffEntry::modified("adapters/postgres/src/lib.rs")],
            facts,
            UNKNOWN_REVISION,
        )?;
        assert!(
            projection
                .integration_units
                .iter()
                .any(|unit| unit.spec().shard == IntegrationShard::PostgresDomain)
        );

        let release_owner_impact = impact_with_facts(
            &root,
            &[
                DiffEntry::modified("Cargo.toml"),
                DiffEntry::modified("crates/platform/src/lib.rs"),
            ],
            facts,
            UNKNOWN_REVISION,
        )?;
        let release_owner_projection = RemoteProjection::from(&release_owner_impact);
        assert_eq!(release_owner_projection.mode, SelectionMode::PrComplete);
        assert!(
            release_owner_projection.public_api_packages.is_empty(),
            "release baseline owners must never enter the affected-internal selector"
        );
        Ok(())
    }
}
