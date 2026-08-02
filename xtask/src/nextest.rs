//! cargo-nextest 的唯一执行漏斗：typed profile/partition、JUnit 搬运与可重放 JSON sidecar。
//!
//! INVARIANT: NEXTEST-PROFILE-REGISTRY-01 { level = "Hard", exec = "native-compile", source = "code", native = "NextestProfile closed enum is exhaustive at every profile routing site" }——profile 只能由闭枚举产生。
//! INVARIANT: NEXTEST-PARTITION-TYPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "HashPartition private fields and validated constructor exclude illegal states" }——hash partition 的非法状态不可构造。
//! INVARIANT: NEXTEST-EVIDENCE-DTO-01 { level = "Hard", exec = "native-compile", source = "code", native = "Evidence construction requires the closed typed DTO and Outcome enum" }——证据内部状态只能由闭合类型构造。
//! INVARIANT: NEXTEST-EVIDENCE-SCHEMA-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "evidence_schema_rejects_wire_drift", anti_vacuity = "evidence_schema_matches_golden" }——serde wire 形态由可失败的 committed golden 治理。
//! INVARIANT: NEXTEST-CONFIG-POLICY-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "config_policy_rejects_retry_override_and_missing_timeout", anti_vacuity = "committed_nextest_config_obeys_policy|production_artifact_profile_route_is_typed_and_exclusive" }——CI profiles 零重试、JUnit 与 timeout fail-closed；production artifact 只能由 typed execution unit 路由到专用预算。
//! INVARIANT: NEXTEST-EXECUTION-FUNNEL-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "execution_funnel_rejects_private_capability_api_bypass|local_only_command_rejects_real_nonzero_exit_status", anti_vacuity = "real_nextest_call_sites_use_funnel|localtx_journey_serial_batch_fails_when_compiled_inventory_is_empty" }——xtask 的 nextest 子进程只能经 typed cargo capability 构造，且非零退出码不能生成成功能力。
//! INVARIANT: NEXTEST-TRYBUILD-SCHEDULING-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "trybuild_inventory_is_bidirectionally_closed|trybuild_inventory_rejects_non_dedicated_sources", anti_vacuity = "workspace_trybuild_inventory_is_non_vacuous_and_closed" }——任何 trybuild 语义引用只能位于专用 integration test target 入口，且与 nextest 单线程 selector 双向闭合；lib/bin/module/macro 间接 carrier 均 fail-closed。
//! INVARIANT: COVERAGE-SCOPE-NONEMPTY-01 { level = "Hard", exec = "native-compile", source = "code", native = "CoverageScope::packages returns None for empty package lists; execution paths only accept CoverageScope" }.
//! INVARIANT: COVERAGE-ARGV-SCOPE-01 { level = "Hard", exec = "native-compile", source = "code", native = "Packages argv uses -p exclusively; Workspace uses --workspace exclusively" }.
//! INVARIANT: COVERAGE-REPLAY-SCOPE-01 { level = "Medium", exec = "release-check", source = "code", synthetic_red = "coverage_argv_scope_mutex_packages_vs_workspace", anti_vacuity = "llvm_cov_replay_spec_closes_profile_without_raw_args" }——ReplaySpec::Coverage 必须携带 CoverageScope.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const NEXTEST_VERSION: &str = env!("RSS_TOOL_VERSION_CARGO_NEXTEST");
const TOOL_NAME: &str = "nextest";
const INSTALL_HINT: &str = concat!(
    "cargo install cargo-nextest@",
    env!("RSS_TOOL_VERSION_CARGO_NEXTEST"),
    " --locked"
);
const EVIDENCE_SCHEMA_VERSION: u8 = 4;
const EVIDENCE_DIR: &str = "target/nextest-evidence";
const TRYBUILD_FILTER: &str = "binary(/(^trybuild$|_trybuild$)/)";

/// nextest capability 的唯一 typed 门；调用方既不能取得 capability 名，也不能绕过安装提示策略。
pub(crate) fn run_gated<T>(
    lane: &str,
    allow_missing: bool,
    label: &str,
    on_run: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    run_gated_with_probe(lane, allow_missing, label, is_available, on_run)
}

pub(crate) fn is_available() -> bool {
    super::nextest_available(super::NextestCapability)
}

pub(crate) fn run_gated_with_probe<T>(
    lane: &str,
    allow_missing: bool,
    label: &str,
    probe: impl FnOnce() -> bool,
    on_run: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    if probe() {
        return on_run().map(Some);
    }
    if allow_missing {
        eprintln!("{lane}: [跳过] 缺少 {TOOL_NAME}，未执行 {label}；安装：{INSTALL_HINT}");
        return Ok(None);
    }
    bail!("{lane}: 缺少 {TOOL_NAME}，无法执行 {label}；安装：{INSTALL_HINT}")
}

/// Execute the exact canonical LocalOnly conformance tests selected by the source-receipt AST
/// inventory. The caller owns reconciliation of the emitted runtime markers; this function only
/// returns after nextest reports that every selected test passed.
pub(crate) fn run_local_only_exact(
    root: &Path,
    packages: &[String],
    tests: &[String],
    marker_dir: &Path,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<()> {
    let args = local_only_args(packages, tests, execution_policy)?;
    let marker_dir = marker_dir
        .to_str()
        .context("LocalOnly execution marker directory must be UTF-8")?;
    run_gated(
        "ci-local-only",
        false,
        "LocalOnly exact conformance",
        || {
            let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
            let command = super::nextest_cmd(
                super::NextestCapability,
                super::NextestMode::Direct,
                &borrowed,
                &[("RSS_LOCAL_ONLY_EXECUTION_DIR", marker_dir)],
                Some(root),
            );
            execute_local_only_command(command)
        },
    )?
    .context("LocalOnly nextest execution unexpectedly skipped")
}

fn execute_local_only_command(mut command: Command) -> Result<()> {
    let status = command
        .status()
        .context("启动 LocalOnly cargo-nextest 失败")?;
    if !status.success() {
        bail!("LocalOnly canonical conformance tests failed: exit={status}");
    }
    Ok(())
}

/// Cargo package identity charset shared by LocalOnly and coverage `-p` argv (defense-in-depth).
fn valid_cargo_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn local_only_args(
    packages: &[String],
    tests: &[String],
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<Vec<String>> {
    if packages.is_empty() || tests.is_empty() {
        bail!("LocalOnly exact conformance inventory must be non-empty");
    }
    if packages.windows(2).any(|pair| pair[0] >= pair[1])
        || tests.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("LocalOnly packages and tests must be uniquely sorted");
    }
    if packages
        .iter()
        .any(|package| !valid_cargo_package_name(package))
        || tests.iter().any(|test| {
            test.is_empty()
                || !test
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':'))
                || test.contains(":::")
        })
    {
        bail!("LocalOnly package or test identity is invalid");
    }
    let mut args = vec![
        "--profile".to_owned(),
        NextestProfile::CiCore.as_str().to_owned(),
        "--locked".to_owned(),
        "--no-tests=fail".to_owned(),
        "--lib".to_owned(),
    ];
    if execution_policy.keeps_going() {
        args.push("--no-fail-fast".to_owned());
    }
    for package in packages {
        args.extend(["-p".to_owned(), package.clone()]);
    }
    args.push("--".to_owned());
    args.extend(tests.iter().cloned());
    args.push("--exact".to_owned());
    Ok(args)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NextestProfile {
    CiCore,
    CoverageIdentityaudit,
    Integration,
    ProductionArtifact,
    FaultMatrix,
}

impl NextestProfile {
    const ALL: [Self; 5] = [
        Self::CiCore,
        Self::CoverageIdentityaudit,
        Self::Integration,
        Self::ProductionArtifact,
        Self::FaultMatrix,
    ];

    const VALIDATED_EXECUTION: [Self; 4] = [
        Self::CiCore,
        Self::Integration,
        Self::ProductionArtifact,
        Self::FaultMatrix,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CiCore => "ci-core",
            Self::CoverageIdentityaudit => "coverage-identityaudit",
            Self::Integration => "integration",
            Self::ProductionArtifact => "production-artifact",
            Self::FaultMatrix => "fault-matrix",
        }
    }

    const fn junit_path(self) -> &'static str {
        match self {
            Self::CiCore => "target/nextest/ci-core/junit.xml",
            Self::CoverageIdentityaudit => "target/nextest/coverage-identityaudit/junit.xml",
            Self::Integration => "target/nextest/integration/junit.xml",
            Self::ProductionArtifact => "target/nextest/production-artifact/junit.xml",
            Self::FaultMatrix => "target/nextest/fault-matrix/junit.xml",
        }
    }

    const fn junit_config_path(self) -> &'static str {
        "junit.xml"
    }

    const fn timeout_policy(self) -> Option<(&'static str, i64)> {
        match self {
            Self::CiCore => Some(("120s", 2)),
            Self::Integration => Some(("300s", 2)),
            Self::ProductionArtifact => Some(("900s", 1)),
            Self::FaultMatrix => Some(("600s", 1)),
            Self::CoverageIdentityaudit => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HashPartition {
    index: u8,
    total: u8,
}

impl HashPartition {
    pub(crate) fn new(index: u8, total: u8) -> Result<Self> {
        if index == 0 || total == 0 || index > total || total > 32 {
            bail!("partition 必须满足 1 ≤ M ≤ N ≤ 32，收到 {index}/{total}");
        }
        Ok(Self { index, total })
    }

    pub(crate) fn nextest_arg(self) -> String {
        format!("hash:{self}")
    }

    pub(crate) const fn is_two_way(self) -> bool {
        self.total == 2 && (self.index == 1 || self.index == 2)
    }
}

impl fmt::Display for HashPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.index, self.total)
    }
}

impl FromStr for HashPartition {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let (index, total) = raw
            .split_once('/')
            .filter(|_| raw.matches('/').count() == 1)
            .ok_or_else(|| anyhow::anyhow!("partition 必须使用 M/N 格式，收到 {raw:?}"))?;
        if index.is_empty()
            || total.is_empty()
            || !index.bytes().all(|byte| byte.is_ascii_digit())
            || !total.bytes().all(|byte| byte.is_ascii_digit())
        {
            bail!("partition 必须使用十进制 M/N 格式，收到 {raw:?}");
        }
        Self::new(
            index.parse().context("partition M 超出范围")?,
            total.parse().context("partition N 超出范围")?,
        )
    }
}

impl Serialize for HashPartition {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HashPartition {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NextestLane {
    Verify,
    CiCore,
    Coverage,
    Integration,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(crate) struct NonEmptyPackageSet(Vec<String>);

impl<'de> Deserialize<'de> for NonEmptyPackageSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let packages = Vec::<String>::deserialize(deserializer)?;
        let canonical = Self::new(packages.clone()).ok_or_else(|| {
            serde::de::Error::custom(
                "package selection must be non-empty and contain valid Cargo package names",
            )
        })?;
        if canonical.0 != packages {
            return Err(serde::de::Error::custom(
                "package selection must be sorted, unique, and canonical",
            ));
        }
        Ok(canonical)
    }
}

impl NonEmptyPackageSet {
    fn new(mut packages: Vec<String>) -> Option<Self> {
        packages.sort();
        packages.dedup();
        (!packages.is_empty()
            && packages
                .iter()
                .all(|package| valid_cargo_package_name(package)))
        .then_some(Self(packages))
    }

    fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// Closed package selection for the sole deterministic component-test owner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum CoreTestSelection {
    Workspace,
    Packages { packages: NonEmptyPackageSet },
}

impl CoreTestSelection {
    pub(crate) const fn workspace() -> Self {
        Self::Workspace
    }

    pub(crate) fn packages(packages: Vec<String>) -> Option<Self> {
        NonEmptyPackageSet::new(packages).map(|packages| Self::Packages { packages })
    }

    pub(crate) fn packages_ref(&self) -> Option<&[String]> {
        match self {
            Self::Workspace => None,
            Self::Packages { packages } => Some(packages.as_slice()),
        }
    }

    fn args(&self, partitioned: bool) -> Vec<String> {
        let mut args = Vec::new();
        match self {
            Self::Workspace => args.push("--workspace".to_owned()),
            Self::Packages { packages } => {
                for package in packages.as_slice() {
                    args.extend(["-p".to_owned(), package.clone()]);
                }
            }
        }
        args.push(if partitioned {
            "--no-tests=pass".to_owned()
        } else {
            "--no-tests=fail".to_owned()
        });
        let features = deterministic_feature_args(self);
        if !features.is_empty() {
            args.extend(["--features".to_owned(), features.join(",")]);
        }
        args
    }
}

/// Workspace coverage must opt feature-gated test support into instrumentation explicitly.
/// Keeping package/feature pairs typed prevents the coverage lane and core test registry from
/// drifting through duplicated raw strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DeterministicTestFeature {
    AmqpBackend,
    S3Backend,
    RedisBackend,
    OidcBackend,
    PrometheusBackend,
    OtelBackend,
    GrpcBackend,
    VaultBackend,
    SoftcaBackend,
    TestkitContainers,
    IdentityCompositionDeviceMqtt,
}

impl DeterministicTestFeature {
    const ALL: [Self; 11] = [
        Self::AmqpBackend,
        Self::S3Backend,
        Self::RedisBackend,
        Self::OidcBackend,
        Self::PrometheusBackend,
        Self::OtelBackend,
        Self::GrpcBackend,
        Self::VaultBackend,
        Self::SoftcaBackend,
        Self::TestkitContainers,
        Self::IdentityCompositionDeviceMqtt,
    ];

    const fn package(self) -> &'static str {
        match self {
            Self::AmqpBackend => "amqp",
            Self::S3Backend => "s3",
            Self::RedisBackend => "redis-adapter",
            Self::OidcBackend => "oidc",
            Self::PrometheusBackend => "prometheus-adapter",
            Self::OtelBackend => "otel",
            Self::GrpcBackend => "grpc",
            Self::VaultBackend => "vault",
            Self::SoftcaBackend => "softca",
            Self::TestkitContainers => "testkit",
            Self::IdentityCompositionDeviceMqtt => "identity-composition",
        }
    }

    const fn feature(self) -> &'static str {
        match self {
            Self::TestkitContainers => "containers",
            Self::IdentityCompositionDeviceMqtt => "device-mqtt",
            Self::AmqpBackend
            | Self::S3Backend
            | Self::RedisBackend
            | Self::OidcBackend
            | Self::PrometheusBackend
            | Self::OtelBackend
            | Self::GrpcBackend
            | Self::VaultBackend
            | Self::SoftcaBackend => "backend",
        }
    }

    fn as_namespaced(self) -> String {
        format!("{}/{}", self.package(), self.feature())
    }
}

fn deterministic_feature_args(selection: &CoreTestSelection) -> Vec<String> {
    deterministic_test_feature_args(selection.packages_ref())
}

pub(crate) fn deterministic_test_feature_args(packages: Option<&[String]>) -> Vec<String> {
    DeterministicTestFeature::ALL
        .into_iter()
        .filter(|feature| {
            packages
                .is_none_or(|packages| packages.iter().any(|package| package == feature.package()))
        })
        .map(DeterministicTestFeature::as_namespaced)
        .collect()
}

fn validate_deterministic_features(metadata: &serde_json::Value) -> Result<()> {
    let packages = metadata["packages"]
        .as_array()
        .context("cargo metadata packages must be an array")?;
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .context("cargo metadata workspace_members must be an array")?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    let deterministic_feature_names = DeterministicTestFeature::ALL
        .into_iter()
        .map(DeterministicTestFeature::feature)
        .collect::<BTreeSet<_>>();
    let candidates = packages
        .iter()
        .filter(|package| {
            package["id"]
                .as_str()
                .is_some_and(|id| workspace_members.contains(id))
        })
        .flat_map(|package| {
            let name = package["name"].as_str().unwrap_or_default();
            let features = package["features"].as_object();
            deterministic_feature_names
                .iter()
                .copied()
                .filter(move |feature| {
                    features.is_some_and(|features| features.contains_key(*feature))
                })
                .map(move |feature| format!("{name}/{feature}"))
        })
        .collect::<BTreeSet<_>>();
    let expected = DeterministicTestFeature::ALL
        .into_iter()
        .map(DeterministicTestFeature::as_namespaced)
        .collect::<BTreeSet<_>>();
    if candidates != expected {
        let missing = candidates
            .difference(&expected)
            .cloned()
            .collect::<Vec<_>>();
        let stale = expected
            .difference(&candidates)
            .cloned()
            .collect::<Vec<_>>();
        bail!("deterministic test feature catalog drift: missing={missing:?}, stale={stale:?}");
    }
    for feature in DeterministicTestFeature::ALL {
        let package = packages
            .iter()
            .find(|package| package["name"].as_str() == Some(feature.package()))
            .with_context(|| {
                format!(
                    "deterministic test package is missing: {}",
                    feature.package()
                )
            })?;
        let manifest_features = package["features"]
            .as_object()
            .with_context(|| format!("package {} has no feature catalog", feature.package()))?;
        if !manifest_features.contains_key(feature.feature()) {
            bail!(
                "deterministic test feature is missing from manifest: {}",
                feature.as_namespaced()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverageSupplementFeature {
    TestkitContainers,
    JourneysIntegration,
}

impl CoverageSupplementFeature {
    const fn package(self) -> &'static str {
        match self {
            Self::TestkitContainers => "testkit",
            Self::JourneysIntegration => "journeys",
        }
    }

    const fn feature(self) -> &'static str {
        match self {
            Self::TestkitContainers => "containers",
            Self::JourneysIntegration => "integration",
        }
    }

    fn as_namespaced(self) -> String {
        format!("{}/{}", self.package(), self.feature())
    }
}

/// Single source for feature-gated code that the workspace llvm-cov run must instrument.
/// Feature closure for the one real IdentityAudit executable journey appended to the same
/// llvm-cov profdata. The nextest profile owns the exact binary selector.
const IDENTITYAUDIT_COVERAGE_FEATURES: [CoverageSupplementFeature; 2] = [
    CoverageSupplementFeature::TestkitContainers,
    CoverageSupplementFeature::JourneysIntegration,
];

impl NextestLane {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::CiCore => "ci-core",
            Self::Coverage => "coverage",
            Self::Integration => "integration",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextestRunner {
    Cargo,
    LlvmCov,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct Evidence {
    schema_version: u8,
    lane: NextestLane,
    #[serde(skip_serializing_if = "Option::is_none")]
    shard: Option<String>,
    profile: NextestProfile,
    invocation_id: String,
    gate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_label: Option<String>,
    outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    junit_path: Option<String>,
    nextest_version: String,
    source_revision: String,
    replay: ReplaySpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    Passed,
    Failed,
    SetupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum ReplaySpec {
    Core {
        selection: CoreTestSelection,
        partition: Option<HashPartition>,
    },
    Coverage {
        scope: crate::ci_impact::CoverageScope,
    },
    CoverageSupplement {
        supplement: CoverageSupplement,
    },
    Integration {
        profile: NextestProfile,
        shard: crate::integration_shards::IntegrationShard,
        selection: crate::integration_shards::IntegrationSelection,
        #[serde(rename = "unitIds")]
        unit_ids: IntegrationReplayUnitIds,
        partition: Option<HashPartition>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntegrationReplayUnitIds(BTreeSet<crate::integration_shards::IntegrationUnitId>);

impl IntegrationReplayUnitIds {
    pub(crate) fn new(
        unit_ids: BTreeSet<crate::integration_shards::IntegrationUnitId>,
    ) -> Result<Self> {
        if unit_ids.is_empty() {
            bail!("integration replay unitIds must be non-empty");
        }
        Ok(Self(unit_ids))
    }

    pub(crate) const fn as_set(&self) -> &BTreeSet<crate::integration_shards::IntegrationUnitId> {
        &self.0
    }

    fn iter(&self) -> impl Iterator<Item = crate::integration_shards::IntegrationUnitId> {
        crate::integration_shards::IntegrationUnitId::wire_order(&self.0).into_iter()
    }
}

impl Serialize for IntegrationReplayUnitIds {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::integration_shards::IntegrationUnitId::wire_order(&self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IntegrationReplayUnitIds {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = Vec::<crate::integration_shards::IntegrationUnitId>::deserialize(deserializer)?;
        let unit_ids = wire.iter().copied().collect::<BTreeSet<_>>();
        if wire.len() != unit_ids.len() {
            return Err(serde::de::Error::custom(
                "integration replay unitIds must not contain duplicates",
            ));
        }
        if wire != crate::integration_shards::IntegrationUnitId::wire_order(&unit_ids) {
            return Err(serde::de::Error::custom(
                "integration replay unitIds must be in canonical order",
            ));
        }
        Self::new(unit_ids).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CoverageSupplement {
    IdentityAudit,
}

pub(crate) struct NextestInvocation {
    profile: NextestProfile,
    lane: NextestLane,
    shard: Option<&'static str>,
    partition: Option<HashPartition>,
    runner: NextestRunner,
    args: Vec<String>,
    replay_spec: ReplaySpec,
    execution_policy: crate::cmd::ExecutionPolicy,
}

impl NextestInvocation {
    fn new(
        profile: NextestProfile,
        lane: NextestLane,
        shard: Option<&'static str>,
        partition: Option<HashPartition>,
        runner: NextestRunner,
        args: Vec<String>,
    ) -> Self {
        Self {
            profile,
            lane,
            shard,
            partition,
            runner,
            args,
            replay_spec: if runner == NextestRunner::LlvmCov {
                ReplaySpec::Coverage {
                    scope: crate::ci_impact::coverage_scope_for_full_ci(),
                }
            } else {
                ReplaySpec::Core {
                    selection: CoreTestSelection::workspace(),
                    partition,
                }
            },
            execution_policy: crate::cmd::ExecutionPolicy::FailFast,
        }
    }

    pub(crate) fn with_execution_policy(
        mut self,
        execution_policy: crate::cmd::ExecutionPolicy,
    ) -> Self {
        self.execution_policy = execution_policy;
        self
    }

    pub(crate) fn for_core(
        selection: CoreTestSelection,
        lane: NextestLane,
        partition: Option<HashPartition>,
    ) -> Self {
        let args = selection.args(partition.is_some());
        let mut invocation = Self::new(
            NextestProfile::CiCore,
            lane,
            None,
            partition,
            NextestRunner::Cargo,
            args,
        );
        invocation.replay_spec = ReplaySpec::Core {
            selection,
            partition,
        };
        invocation
    }

    pub(crate) fn for_coverage(
        output_path: &str,
        scope: crate::ci_impact::CoverageScope,
    ) -> Result<Self> {
        validate_coverage_output_path(output_path)?;
        let mut args = Vec::new();
        let selection = match &scope {
            crate::ci_impact::CoverageScope::Workspace { .. } => {
                args.push("--workspace".to_owned());
                CoreTestSelection::workspace()
            }
            crate::ci_impact::CoverageScope::Packages { packages, .. } => {
                if packages.is_empty() {
                    bail!(
                        "coverage: empty Packages scope is forbidden (COVERAGE-SCOPE-NONEMPTY-01); \
                         expected CoverageScope::packages non-empty or Workspace — check plan/execute \
                         CoverageProjection (no seeds / filtered-empty) and GITHUB_EVENT_*"
                    );
                }
                for package in packages {
                    if !valid_cargo_package_name(package) {
                        bail!("coverage: invalid package name for -p: {package:?}");
                    }
                    args.push("-p".to_owned());
                    args.push(package.clone());
                }
                CoreTestSelection::packages(packages.clone())
                    .context("coverage package scope must be non-empty and valid")?
            }
        };
        args.push("--locked".to_owned());
        let features = deterministic_feature_args(&selection);
        if !features.is_empty() {
            args.extend(["--features".to_owned(), features.join(",")]);
        }
        args.extend(["--json", "--output-path", output_path].map(str::to_owned));
        let mut invocation = Self::new(
            NextestProfile::CiCore,
            NextestLane::Coverage,
            None,
            None,
            NextestRunner::LlvmCov,
            args,
        );
        invocation.replay_spec = ReplaySpec::Coverage { scope };
        Ok(invocation)
    }

    pub(crate) fn for_identityaudit_coverage(output_path: &str) -> Result<Self> {
        validate_coverage_output_path(output_path)?;
        let mut args = ["--no-clean", "--workspace", "--locked"]
            .map(str::to_owned)
            .to_vec();
        args.extend([
            "--features".to_owned(),
            IDENTITYAUDIT_COVERAGE_FEATURES
                .iter()
                .copied()
                .map(CoverageSupplementFeature::as_namespaced)
                .collect::<Vec<_>>()
                .join(","),
        ]);
        args.extend(["--lcov", "--output-path", output_path].map(str::to_owned));
        let mut invocation = Self::new(
            NextestProfile::CoverageIdentityaudit,
            NextestLane::Coverage,
            None,
            None,
            NextestRunner::LlvmCov,
            args,
        );
        invocation.replay_spec = ReplaySpec::CoverageSupplement {
            supplement: CoverageSupplement::IdentityAudit,
        };
        Ok(invocation)
    }

    pub(crate) fn for_integration_batch(
        selection: &crate::integration_shards::IntegrationSelection,
        shard_batch: &crate::integration_shards::ShardBatch,
        partition: Option<HashPartition>,
    ) -> Result<Self> {
        let shard = shard_for_integration_batch(shard_batch)?;
        shard.validate_partition(partition)?;
        let batch = exact_canonical_integration_batch(selection, shard, &shard_batch.unit_ids)?;
        if &batch != shard_batch {
            bail!("integration batch fields drift from selection-derived registry");
        }
        let profile = profile_for_integration_batch(&batch)?;
        let mut invocation = Self::new(
            profile,
            NextestLane::Integration,
            Some(shard.as_str()),
            partition,
            NextestRunner::Cargo,
            integration_batch_args(&batch, partition.is_some()),
        );
        invocation.replay_spec = ReplaySpec::Integration {
            profile,
            shard,
            selection: selection.clone(),
            unit_ids: IntegrationReplayUnitIds::new(batch.unit_ids)?,
            partition,
        };
        Ok(invocation)
    }

    #[cfg(test)]
    pub(crate) fn replay_spec(&self) -> &ReplaySpec {
        &self.replay_spec
    }

    pub(crate) fn execution_argv(&self) -> Vec<String> {
        let mut argv = vec!["cargo".to_owned()];
        match self.runner {
            NextestRunner::Cargo => {
                argv.extend(["nextest".to_owned(), "run".to_owned()]);
                argv.extend(["--profile".to_owned(), self.profile.as_str().to_owned()]);
            }
            NextestRunner::LlvmCov => {
                argv.extend(["llvm-cov".to_owned(), "nextest".to_owned()]);
            }
        }
        if self.execution_policy.keeps_going() {
            argv.push("--no-fail-fast".to_owned());
        }
        argv.extend(self.args.iter().cloned());
        if let Some(partition) = self.partition {
            argv.extend(["--partition".to_owned(), partition.nextest_arg()]);
        }
        argv
    }

    pub(crate) fn run(&self, root: &Path, env: &[(&str, &str)]) -> Result<()> {
        let canonical = root.join(self.profile.junit_path());
        prepare_canonical_junit(&canonical)?;
        let evidence_dir = root.join(EVIDENCE_DIR);
        fs::create_dir_all(&evidence_dir)?;
        let execution = self.execution_argv();
        let source_revision = super::source_revision(root)?;
        let id = unique_invocation_id(&evidence_dir, &self.base_id(&execution));
        let cargo_args = &execution[3..];
        let borrowed = cargo_args.iter().map(String::as_str).collect::<Vec<_>>();
        let mut owned_env = env.to_vec();
        if self.runner == NextestRunner::LlvmCov {
            owned_env.push(("NEXTEST_PROFILE", self.profile.as_str()));
        }
        let mode = match self.runner {
            NextestRunner::Cargo => super::NextestMode::Direct,
            NextestRunner::LlvmCov => super::NextestMode::LlvmCov,
        };
        let spawn = super::nextest_cmd(
            super::NextestCapability,
            mode,
            &borrowed,
            &owned_env,
            Some(root),
        )
        .status();
        match spawn {
            Ok(status) => self.finish(&evidence_dir, &canonical, &id, &source_revision, status),
            Err(error) => {
                self.write_sidecar(
                    &evidence_dir,
                    &id,
                    &source_revision,
                    Outcome::SetupFailed,
                    None,
                )?;
                Err(error).context("启动 cargo-nextest 失败")
            }
        }
    }

    fn finish(
        &self,
        evidence_dir: &Path,
        canonical: &Path,
        id: &str,
        source_revision: &str,
        status: ExitStatus,
    ) -> Result<()> {
        let junit_path = if canonical.is_file() {
            let destination = evidence_dir.join(format!("{id}.xml"));
            fs::rename(canonical, &destination).or_else(|_| {
                fs::copy(canonical, &destination)?;
                fs::remove_file(canonical)
            })?;
            Some(format!("nextest/{id}.xml"))
        } else {
            None
        };
        let outcome = match (status.success(), junit_path.is_some()) {
            (true, true) => Outcome::Passed,
            (false, true) => Outcome::Failed,
            (_, false) => Outcome::SetupFailed,
        };
        self.write_sidecar(evidence_dir, id, source_revision, outcome, junit_path)?;
        if !canonical.exists() && matches!(outcome, Outcome::SetupFailed) {
            bail!("nextest invocation {id} 未生成 JUnit，按 setup-failed 处理");
        }
        if status.success() {
            Ok(())
        } else {
            let code = status
                .code()
                .map_or_else(|| "signal".to_owned(), |value| value.to_string());
            bail!("nextest invocation {id} 失败（退出码 {code}）")
        }
    }

    fn write_sidecar(
        &self,
        evidence_dir: &Path,
        id: &str,
        source_revision: &str,
        outcome: Outcome,
        junit_path: Option<String>,
    ) -> Result<()> {
        let (gate, batch_label) = self.evidence_labels();
        let evidence = Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            lane: self.lane,
            shard: self.shard.map(str::to_owned),
            profile: self.profile,
            invocation_id: id.to_owned(),
            gate,
            batch_label,
            outcome,
            junit_path,
            nextest_version: NEXTEST_VERSION.to_owned(),
            source_revision: source_revision.to_owned(),
            replay: self.replay_spec.clone(),
        };
        let destination = evidence_dir.join(format!("{id}.json"));
        let temporary = evidence_dir.join(format!(".{id}.json.tmp"));
        fs::write(&temporary, serde_json::to_vec_pretty(&evidence)?)?;
        fs::rename(&temporary, &destination)?;
        Ok(())
    }

    fn evidence_labels(&self) -> (String, Option<String>) {
        match &self.replay_spec {
            ReplaySpec::Core {
                selection: CoreTestSelection::Workspace,
                ..
            } => ("core-workspace".to_owned(), None),
            ReplaySpec::Core {
                selection: CoreTestSelection::Packages { packages },
                ..
            } => (
                format!("core-packages:{}", packages.as_slice().join(",")),
                None,
            ),
            ReplaySpec::Coverage { .. } => ("coverage".to_owned(), None),
            ReplaySpec::CoverageSupplement { supplement } => (
                format!("coverage-supplement-{supplement:?}").to_ascii_lowercase(),
                None,
            ),
            ReplaySpec::Integration {
                shard, unit_ids, ..
            } => (
                format!("integration-{shard}"),
                Some(format!(
                    "units:{}",
                    unit_ids
                        .iter()
                        .map(|unit_id| unit_id.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                )),
            ),
        }
    }

    fn base_id(&self, replay: &[String]) -> String {
        let mut digest = Sha256::new();
        for arg in replay {
            digest.update(arg.as_bytes());
            digest.update([0]);
        }
        let hash = format!("{:x}", digest.finalize());
        let shard = self.shard.unwrap_or("workspace");
        format!(
            "{}-{shard}-{}-{}",
            self.lane.as_str(),
            self.profile.as_str(),
            &hash[..12]
        )
    }
}

fn profile_for_integration_batch(
    batch: &crate::integration_shards::ShardBatch,
) -> Result<NextestProfile> {
    use crate::integration_shards::IntegrationUnitId;

    let mut matching = [
        (
            IntegrationUnitId::SettingsOnlyProductionArtifact,
            NextestProfile::ProductionArtifact,
        ),
        (
            IntegrationUnitId::ConsistencyFaultMatrixJourney,
            NextestProfile::FaultMatrix,
        ),
    ]
    .into_iter()
    .filter(|(unit, _)| batch.unit_ids.contains(unit));
    let profile = matching
        .next()
        .map_or(NextestProfile::Integration, |(_, profile)| profile);
    if matching.next().is_some() {
        bail!("integration batch contains multiple special-profile execution units");
    }
    Ok(profile)
}

fn shard_for_integration_batch(
    batch: &crate::integration_shards::ShardBatch,
) -> Result<crate::integration_shards::IntegrationShard> {
    let mut unit_ids = batch.unit_ids.iter().copied();
    let shard = unit_ids
        .next()
        .context("integration batch unit IDs must be non-empty")?
        .spec()
        .shard;
    if unit_ids.any(|unit_id| unit_id.spec().shard != shard) {
        bail!("integration batch unit IDs span multiple shards");
    }
    Ok(shard)
}

fn exact_canonical_integration_batch(
    selection: &crate::integration_shards::IntegrationSelection,
    shard: crate::integration_shards::IntegrationShard,
    unit_ids: &BTreeSet<crate::integration_shards::IntegrationUnitId>,
) -> Result<crate::integration_shards::ShardBatch> {
    if unit_ids.is_empty() {
        bail!("integration replay unitIds must be non-empty");
    }
    if selection.unit_ids_for_shard(shard).is_empty() {
        bail!("integration selection has no unit in replay shard `{shard}`");
    }
    if selection.profile() == crate::execution_profiles::ExecutionProfile::IntegrationCritical
        && selection
            .unit_ids()
            .iter()
            .any(|unit_id| unit_id.spec().shard != shard)
    {
        bail!("integration-critical replay selection spans multiple shards");
    }
    let mut matching = crate::integration_shards::batches(selection, shard)
        .into_iter()
        .filter(|batch| &batch.unit_ids == unit_ids);
    let batch = matching
        .next()
        .context("integration replay unitIds do not match a selection-derived batch")?;
    if matching.next().is_some() {
        bail!("integration replay unitIds ambiguously match multiple batches");
    }
    Ok(batch)
}

fn validate_coverage_output_path(output_path: &str) -> Result<()> {
    if output_path.is_empty() || Path::new(output_path).is_absolute() || output_path.contains("..")
    {
        bail!("coverage output path 必须是 workspace 内安全相对路径");
    }
    Ok(())
}

const MAX_EVIDENCE_FILES: usize = 256;
const MAX_EVIDENCE_FILE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_EVIDENCE_TOTAL_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceManifest {
    schema_version: u8,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestEntry {
    invocation_id: String,
    outcome: Outcome,
    gate: String,
    batch_label: Option<String>,
    sidecar: String,
}

pub(crate) fn stage(root: &Path) -> Result<()> {
    let source = root.join(EVIDENCE_DIR);
    let parent = root.join("target/job-evidence");
    fs::create_dir_all(&parent)?;
    let parent_metadata = fs::symlink_metadata(&parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("job evidence parent 必须是普通目录");
    }
    let destination = parent.join("nextest");
    remove_without_follow(&destination)?;
    static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let temporary = parent.join(format!(
        ".nextest-stage-v2-{}-{}",
        std::process::id(),
        STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&temporary)?;
    let mut guard = StagingGuard::new(temporary.clone());
    stage_into(&source, &temporary)?;
    fs::rename(&temporary, &destination)?;
    guard.published = true;
    Ok(())
}

struct StagingGuard {
    path: PathBuf,
    published: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = remove_without_follow(&self.path);
        }
    }
}

fn remove_without_follow(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
        }
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("lstat {}", path.display())),
    }
    Ok(())
}

fn stage_into(source: &Path, destination: &Path) -> Result<()> {
    let mut records = BTreeMap::new();
    let mut xml_stems = BTreeSet::new();
    let mut total = 0_u64;
    match fs::symlink_metadata(source) {
        Ok(source_meta) => {
            if source_meta.file_type().is_symlink() || !source_meta.is_dir() {
                bail!("nextest evidence source 必须是普通目录");
            }
            let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(fs::DirEntry::file_name);
            if entries.len() > MAX_EVIDENCE_FILES {
                bail!("nextest evidence 文件数超限");
            }
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!("nextest evidence 只允许顶层普通文件");
                }
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("evidence 文件名非 UTF-8"))?;
                let (stem, extension) = name
                    .rsplit_once('.')
                    .context("evidence 文件名必须有扩展名")?;
                if !matches!(extension, "json" | "xml")
                    || stem.is_empty()
                    || !stem
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                {
                    bail!("nextest evidence 文件名不在闭合命名内: {name}");
                }
                if metadata.len() > MAX_EVIDENCE_FILE_BYTES {
                    bail!("nextest evidence 单文件超限");
                }
                if extension == "xml" && metadata.len() == 0 {
                    bail!("nextest JUnit 不得为空");
                }
                if extension == "xml" && !xml_stems.insert(stem.to_owned()) {
                    bail!("nextest evidence XML stem 重复");
                }
                let copied_path = destination.join(&name);
                let copied = copy_checked(&path, &copied_path, metadata.len())?;
                total = total
                    .checked_add(copied)
                    .context("evidence size overflow")?;
                if total > MAX_EVIDENCE_TOTAL_BYTES {
                    bail!("nextest evidence 总大小超限");
                }
                if extension == "json" {
                    let record: Evidence = serde_json::from_slice(&fs::read(&copied_path)?)?;
                    validate_evidence_record(&record, stem)?;
                    if records.insert(stem.to_owned(), record).is_some() {
                        bail!("nextest evidence JSON stem 重复");
                    }
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("读取 nextest evidence source"),
    }
    for (stem, record) in &records {
        let expects_xml = record.junit_path.is_some();
        if xml_stems.contains(stem) != expects_xml {
            bail!("sidecar 与 JUnit 必须按 stem 一一配对");
        }
    }
    if xml_stems.iter().any(|stem| !records.contains_key(stem)) {
        bail!("存在无 JSON sidecar 的孤儿 JUnit");
    }
    let mut records = records.into_values().collect::<Vec<_>>();
    records.sort_by_key(|record| match record.outcome {
        Outcome::Failed => 0,
        Outcome::SetupFailed => 1,
        Outcome::Passed => 2,
    });
    let manifest = EvidenceManifest {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        entries: records
            .into_iter()
            .map(|record| ManifestEntry {
                sidecar: format!("nextest/{}.json", record.invocation_id),
                invocation_id: record.invocation_id,
                outcome: record.outcome,
                gate: record.gate,
                batch_label: record.batch_label,
            })
            .collect(),
    };
    fs::write(
        destination.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(())
}

fn copy_checked(source: &Path, destination: &Path, expected_bytes: u64) -> Result<u64> {
    let copied = fs::copy(source, destination)?;
    let source_after = fs::symlink_metadata(source)?;
    let destination_after = fs::symlink_metadata(destination)?;
    if source_after.file_type().is_symlink()
        || !source_after.is_file()
        || destination_after.file_type().is_symlink()
        || !destination_after.is_file()
        || copied != expected_bytes
        || source_after.len() != copied
        || destination_after.len() != copied
        || copied > MAX_EVIDENCE_FILE_BYTES
    {
        bail!("nextest evidence copy 后身份或大小漂移");
    }
    Ok(copied)
}

fn validate_evidence_record(record: &Evidence, stem: &str) -> Result<()> {
    if record.schema_version != EVIDENCE_SCHEMA_VERSION
        || record.invocation_id != stem
        || record.nextest_version != NEXTEST_VERSION
        || record.source_revision.len() != 40
        || !record
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("nextest evidence DTO identity/schema/version 非法");
    }
    let expected = invocation_for_replay(&record.replay, record.lane)?;
    let (expected_gate, expected_batch) = expected.evidence_labels();
    if record.profile != expected.profile
        || record.partition_for_validation() != expected.partition
        || record.shard.as_deref() != expected.shard
        || record.gate != expected_gate
        || record.batch_label != expected_batch
        || record.lane != expected.lane
    {
        bail!("nextest evidence replay 派生字段矛盾");
    }
    if !safe_display(&record.gate)
        || record
            .batch_label
            .as_deref()
            .is_some_and(|value| !safe_display(value))
    {
        bail!("nextest evidence label 含控制字符");
    }
    match (&record.outcome, &record.junit_path) {
        (Outcome::Passed | Outcome::Failed, Some(junit))
            if junit == &format!("nextest/{stem}.xml") => {}
        (Outcome::SetupFailed, None) => {}
        _ => bail!("outcome 与 JUnit 必须精确配对"),
    }
    Ok(())
}

impl Evidence {
    fn partition_for_validation(&self) -> Option<HashPartition> {
        match &self.replay {
            ReplaySpec::Core { partition, .. } | ReplaySpec::Integration { partition, .. } => {
                *partition
            }
            ReplaySpec::Coverage { .. } | ReplaySpec::CoverageSupplement { .. } => None,
        }
    }
}

fn invocation_for_replay(replay: &ReplaySpec, lane: NextestLane) -> Result<NextestInvocation> {
    match replay {
        ReplaySpec::Core {
            selection,
            partition,
        } if matches!(lane, NextestLane::Verify | NextestLane::CiCore) => Ok(
            NextestInvocation::for_core(selection.clone(), lane, *partition),
        ),
        ReplaySpec::Coverage { scope } if lane == NextestLane::Coverage => {
            NextestInvocation::for_coverage("target/coverage/nextest.json", scope.clone())
        }
        ReplaySpec::CoverageSupplement {
            supplement: CoverageSupplement::IdentityAudit,
        } if lane == NextestLane::Coverage => {
            NextestInvocation::for_identityaudit_coverage("target/coverage/identityaudit.lcov")
        }
        ReplaySpec::Integration {
            profile,
            shard,
            selection,
            unit_ids,
            partition,
        } if lane == NextestLane::Integration => {
            let batch = exact_canonical_integration_batch(selection, *shard, unit_ids.as_set())?;
            if profile_for_integration_batch(&batch)? != *profile {
                bail!("integration replay profile drifts from the exact selected batch");
            }
            NextestInvocation::for_integration_batch(selection, &batch, *partition)
        }
        _ => bail!("replay kind 与 lane 矛盾"),
    }
}

fn safe_display(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != 0x1b)
}

pub(crate) fn inspect(artifact_root: &Path) -> Result<()> {
    let nextest_dir = artifact_root.join("nextest");
    let directory_metadata = fs::symlink_metadata(&nextest_dir)?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        bail!("artifact nextest 必须是普通目录");
    }
    let mut actual_files = BTreeSet::new();
    for entry in fs::read_dir(&nextest_dir)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("artifact evidence 文件名非 UTF-8"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_EVIDENCE_FILE_BYTES
            || (name.ends_with(".xml") && metadata.len() == 0)
            || !actual_files.insert(name)
        {
            bail!("artifact evidence 仅允许闭合顶层普通文件");
        }
    }
    let manifest_path = nextest_dir.join("manifest.json");
    let manifest_metadata = fs::symlink_metadata(&manifest_path)?;
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        bail!("manifest 必须是 artifact 内普通文件");
    }
    let manifest: EvidenceManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    if manifest.schema_version != EVIDENCE_SCHEMA_VERSION {
        bail!("manifest schemaVersion 非 v4");
    }
    let mut seen = BTreeSet::new();
    let mut expected_files = BTreeSet::from(["manifest.json".to_owned()]);
    let mut reports = Vec::new();
    for entry in manifest.entries {
        if !safe_evidence_stem(&entry.invocation_id)
            || !safe_display(&entry.gate)
            || entry
                .batch_label
                .as_deref()
                .is_some_and(|value| !safe_display(value))
            || !seen.insert(entry.invocation_id.clone())
        {
            bail!("manifest entry identity/display 非法");
        }
        let expected_sidecar = format!("nextest/{}.json", entry.invocation_id);
        if entry.sidecar != expected_sidecar {
            bail!("manifest sidecar 必须是闭合 nextest/<id>.json");
        }
        expected_files.insert(format!("{}.json", entry.invocation_id));
        if matches!(entry.outcome, Outcome::Passed | Outcome::Failed) {
            expected_files.insert(format!("{}.xml", entry.invocation_id));
        }
        let sidecar = artifact_root.join(&entry.sidecar);
        let metadata = fs::symlink_metadata(&sidecar)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("manifest sidecar 必须是 artifact 内普通文件");
        }
        let record: Evidence = serde_json::from_slice(&fs::read(&sidecar)?)?;
        validate_evidence_record(&record, &entry.invocation_id)?;
        let recomputed = ManifestEntry {
            invocation_id: record.invocation_id,
            outcome: record.outcome,
            gate: record.gate,
            batch_label: record.batch_label,
            sidecar: expected_sidecar,
        };
        if entry != recomputed {
            bail!("manifest entry 与 sidecar 内容矛盾");
        }
        if !matches!(entry.outcome, Outcome::Passed) {
            reports.push(format!(
                "{}\t{}\t{}\t{}",
                entry.invocation_id,
                entry.gate,
                entry.batch_label.as_deref().unwrap_or("-"),
                entry.sidecar
            ));
        }
    }
    if actual_files != expected_files {
        bail!("artifact nextest 文件集与 manifest 非双向闭合");
    }
    for report in reports {
        println!("{report}");
    }
    Ok(())
}

fn safe_evidence_stem(stem: &str) -> bool {
    !stem.is_empty()
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn replay(sidecar: &Path, root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(sidecar)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("replay sidecar 必须是普通 JSON 文件");
    }
    let record: Evidence = serde_json::from_slice(&fs::read(sidecar)?)?;
    let stem = sidecar
        .file_stem()
        .and_then(|value| value.to_str())
        .context("replay sidecar 文件名非法")?;
    validate_evidence_record(&record, stem)?;
    if record.source_revision != super::source_revision(root)? {
        bail!("sidecar sourceRevision 与当前 HEAD 不匹配");
    }
    match record.replay {
        ReplaySpec::Core {
            selection,
            partition,
        } => NextestInvocation::for_core(selection, NextestLane::CiCore, partition).run(root, &[]),
        ReplaySpec::Coverage { scope } => {
            crate::coverage::run(scope, crate::cmd::ExecutionPolicy::FailFast)
        }
        ReplaySpec::CoverageSupplement {
            supplement: CoverageSupplement::IdentityAudit,
        } => NextestInvocation::for_identityaudit_coverage("target/coverage/identityaudit.lcov")?
            .run(root, &[]),
        ReplaySpec::Integration {
            profile: _,
            shard,
            selection,
            unit_ids,
            partition,
        } => crate::verify::run_nextest_replay(&selection, shard, unit_ids.as_set(), partition),
    }
}

pub(crate) fn integration_batch_fails_on_empty(
    batch: &crate::integration_shards::ShardBatch,
) -> bool {
    let args = integration_batch_args(batch, false);
    args.iter().any(|argument| argument == "--no-tests=fail")
        && !args.iter().any(|argument| argument == "--no-tests=pass")
}

fn integration_batch_args(
    batch: &crate::integration_shards::ShardBatch,
    allow_empty_partition: bool,
) -> Vec<String> {
    use crate::integration_shards::{Scheduling, TargetKind};

    let mut args = vec![
        "--features".to_owned(),
        batch.feature.to_owned(),
        if allow_empty_partition {
            "--no-tests=pass".to_owned()
        } else {
            "--no-tests=fail".to_owned()
        },
    ];
    if batch.scheduling == Scheduling::Serial {
        args.extend(["--test-threads".to_owned(), "1".to_owned()]);
    }
    args.extend(["-p".to_owned(), batch.package.to_owned()]);
    match batch.kind {
        TargetKind::Lib => args.push("--lib".to_owned()),
        TargetKind::Test => {
            for target in &batch.targets {
                args.extend(["--test".to_owned(), (*target).to_owned()]);
            }
        }
    }
    args.extend(["-E".to_owned(), batch.filter.clone()]);
    args
}

fn prepare_canonical_junit(canonical: &Path) -> Result<()> {
    if canonical.exists() {
        fs::remove_file(canonical)
            .with_context(|| format!("清理陈旧 JUnit 失败: {}", canonical.display()))?;
    }
    if let Some(parent) = canonical.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn unique_invocation_id(dir: &Path, base: &str) -> String {
    for suffix in 1_u32.. {
        let candidate = if suffix == 1 {
            base.to_owned()
        } else {
            format!("{base}-{suffix}")
        };
        if !dir.join(format!("{candidate}.json")).exists()
            && !dir.join(format!("{candidate}.xml")).exists()
        {
            return candidate;
        }
    }
    unreachable!("u32 invocation suffix space exhausted")
}

#[cfg(test)]
fn validate_evidence_schema(actual: &str, golden: &str) -> Result<()> {
    let _: serde_json::Value = serde_json::from_str(actual).context("evidence JSON 非法")?;
    if actual.trim_end() != golden.trim_end() {
        bail!("nextest evidence wire schema 与 committed golden 漂移");
    }
    Ok(())
}

#[cfg(test)]
fn validate_staged_evidence(artifact_root: &Path) -> Result<()> {
    let nextest_dir = artifact_root.join("nextest");
    for entry in fs::read_dir(&nextest_dir).context("读取 staged nextest evidence")? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        let Some(junit_path) = value.get("junitPath").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let relative = Path::new(junit_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !relative.starts_with("nextest")
        {
            bail!("staged junitPath 必须是 artifact 根下 nextest/ 的安全相对路径");
        }
        if !artifact_root.join(relative).is_file() {
            bail!("staged junitPath 未解析到同 artifact 内 XML");
        }
    }
    Ok(())
}

pub(crate) fn validate_config(source: &str) -> Result<()> {
    let value: toml::Value = toml::from_str(source).context("解析 nextest TOML 失败")?;
    let profiles = value
        .get("profile")
        .and_then(toml::Value::as_table)
        .context("缺少 [profile]")?;
    let mut profile_names = profiles.keys().map(String::as_str).collect::<Vec<_>>();
    profile_names.sort_unstable();
    let mut expected_profile_names = NextestProfile::ALL
        .into_iter()
        .map(NextestProfile::as_str)
        .chain(std::iter::once("default"))
        .collect::<Vec<_>>();
    expected_profile_names.sort_unstable();
    if profile_names != expected_profile_names {
        bail!("nextest profiles 必须与 closed NextestProfile registry 加 default 精确一致");
    }
    let coverage = profiles
        .get(NextestProfile::CoverageIdentityaudit.as_str())
        .and_then(toml::Value::as_table)
        .context("缺少 profile.coverage-identityaudit")?;
    if coverage.len() != 3
        || coverage.get("inherits").and_then(toml::Value::as_str) != Some("ci-core")
        || coverage.get("default-filter").and_then(toml::Value::as_str)
            != Some("binary(identityaudit_runtime)")
        || coverage
            .get("junit")
            .and_then(toml::Value::as_table)
            .and_then(|report| report.get("path"))
            .and_then(toml::Value::as_str)
            != Some(NextestProfile::CoverageIdentityaudit.junit_config_path())
    {
        bail!(
            "profile.coverage-identityaudit 必须继承 ci-core、精确选择 identityaudit_runtime 并保留 canonical JUnit"
        );
    }
    for profile in NextestProfile::VALIDATED_EXECUTION {
        let table = profiles
            .get(profile.as_str())
            .and_then(toml::Value::as_table)
            .with_context(|| format!("缺少 profile.{}", profile.as_str()))?;
        if table.contains_key("global-timeout") {
            bail!("profile.{} 禁止 global-timeout", profile.as_str());
        }
        if table.get("retries").and_then(toml::Value::as_integer) != Some(0) {
            bail!("profile.{} 必须 retries=0", profile.as_str());
        }
        if table.get("flaky-result").and_then(toml::Value::as_str) != Some("fail") {
            bail!("profile.{} 必须 flaky-result=fail", profile.as_str());
        }
        let timeout = table.get("slow-timeout").and_then(toml::Value::as_table);
        let period = timeout
            .and_then(|timeout| timeout.get("period"))
            .and_then(toml::Value::as_str);
        let (expected, expected_terminate) = profile
            .timeout_policy()
            .context("validated execution profile must own an exact timeout policy")?;
        if period != Some(expected) {
            bail!(
                "profile.{} slow-timeout 必须为 {expected}",
                profile.as_str()
            );
        }
        if timeout
            .and_then(|timeout| timeout.get("terminate-after"))
            .and_then(toml::Value::as_integer)
            != Some(expected_terminate)
        {
            bail!(
                "profile.{} terminate-after 必须为 {expected_terminate}",
                profile.as_str()
            );
        }
        let junit = table
            .get("junit")
            .and_then(toml::Value::as_table)
            .and_then(|report| report.get("path"))
            .and_then(toml::Value::as_str);
        if junit != Some(profile.junit_config_path()) {
            bail!("profile.{} JUnit path 漂移", profile.as_str());
        }
        if profile != NextestProfile::CiCore && table.contains_key("overrides") {
            bail!("profile.{} 禁止 overrides", profile.as_str());
        }
    }
    validate_trybuild_scheduling(&value, profiles)?;
    Ok(())
}

fn validate_trybuild_scheduling(
    value: &toml::Value,
    profiles: &toml::map::Map<String, toml::Value>,
) -> Result<()> {
    let groups = value
        .get("test-groups")
        .and_then(toml::Value::as_table)
        .context("缺少 test-groups.trybuild")?;
    if groups.len() != 1
        || groups
            .get("trybuild")
            .and_then(toml::Value::as_table)
            .and_then(|group| group.get("max-threads"))
            .and_then(toml::Value::as_integer)
            != Some(1)
    {
        bail!("test-groups 必须仅含 trybuild max-threads=1");
    }
    for profile in ["default", "ci-core"] {
        let overrides = profiles
            .get(profile)
            .and_then(toml::Value::as_table)
            .and_then(|table| table.get("overrides"))
            .and_then(toml::Value::as_array)
            .with_context(|| format!("profile.{profile} 缺 trybuild override"))?;
        if overrides.len() != 1 {
            bail!("profile.{profile} 必须仅含一个 trybuild override");
        }
        let rule = overrides[0]
            .as_table()
            .context("trybuild override 非 table")?;
        if rule.len() != 2
            || rule.get("filter").and_then(toml::Value::as_str) != Some(TRYBUILD_FILTER)
            || rule.get("test-group").and_then(toml::Value::as_str) != Some("trybuild")
        {
            bail!("profile.{profile} trybuild override 漂移");
        }
    }
    Ok(())
}

fn validate_capability_boundary_source(source: &str) -> Result<()> {
    fn forbidden_identifier(ident: &syn::Ident) -> bool {
        matches!(
            ident.to_string().as_str(),
            "clean_cmd" | "nextest_cmd" | "nextest_available"
        )
    }

    fn macro_contains_forbidden_api(tokens: proc_macro2::TokenStream) -> bool {
        tokens.into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => forbidden_identifier(&ident),
            proc_macro2::TokenTree::Group(group) => macro_contains_forbidden_api(group.stream()),
            _ => false,
        })
    }

    #[derive(Default)]
    struct CapabilityVisitor {
        findings: Vec<&'static str>,
    }
    impl<'ast> syn::visit::Visit<'ast> for CapabilityVisitor {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| forbidden_identifier(&segment.ident))
            {
                self.findings.push("private cargo capability API call");
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if macro_contains_forbidden_api(node.tokens.clone()) {
                self.findings.push("private cargo capability API in macro");
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let syntax = syn::parse_file(source).context("解析 xtask production Rust AST 失败")?;
    let mut visitor = CapabilityVisitor::default();
    syn::visit::Visit::visit_file(&mut visitor, &syntax);
    if !visitor.findings.is_empty() {
        bail!("cargo/nextest private capability API 只能由 cmd::nextest carrier 构造")
    }
    Ok(())
}

pub(crate) fn validate_workspace(root: &Path) -> Result<()> {
    validate_config(&fs::read_to_string(root.join(".config/nextest.toml"))?)?;
    let metadata = cargo_metadata(root)?;
    validate_deterministic_features(&metadata)?;
    let (carriers, targets) = trybuild_inventory(root, &metadata)?;
    validate_trybuild_inventory(&carriers, &targets)?;
    let source_root = root.join("xtask/src");
    for path in rust_files_under(&source_root)? {
        if path == source_root.join("nextest.rs") || path == source_root.join("cmd.rs") {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .context("读取 production source")?;
        validate_capability_boundary_source(production)
            .with_context(|| format!("nextest execution funnel: {}", path.display()))?;
    }
    Ok(())
}

fn cargo_metadata(root: &Path) -> Result<serde_json::Value> {
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Metadata,
        &["--locked", "--no-deps", "--format-version", "1"],
        &[],
        Some(root),
    )
    .output()
    .context("执行 cargo metadata 发现 trybuild target")?;
    if !output.status.success() {
        bail!(
            "cargo metadata 发现 trybuild target 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("解析 cargo metadata trybuild inventory")
}

fn source_uses_trybuild(source: &str) -> Result<bool> {
    #[derive(Default)]
    struct TrybuildImports {
        modules: BTreeSet<String>,
        test_cases: BTreeSet<String>,
    }

    fn record_use(tree: &syn::UseTree, prefix: &mut Vec<String>, imports: &mut TrybuildImports) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                record_use(&path.tree, prefix, imports);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                let mut canonical = prefix.clone();
                canonical.push(name.ident.to_string());
                if canonical.as_slice() == ["trybuild", "TestCases"] {
                    imports.test_cases.insert(name.ident.to_string());
                }
            }
            syn::UseTree::Rename(rename) => {
                let mut canonical = prefix.clone();
                if rename.ident != "self" {
                    canonical.push(rename.ident.to_string());
                }
                let local = rename.rename.to_string();
                if canonical.as_slice() == ["trybuild"] {
                    imports.modules.insert(local);
                } else if canonical.as_slice() == ["trybuild", "TestCases"] {
                    imports.test_cases.insert(local);
                }
            }
            syn::UseTree::Glob(_) => {
                if prefix.as_slice() == ["trybuild"] {
                    imports.test_cases.insert("TestCases".to_owned());
                }
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    record_use(item, prefix, imports);
                }
            }
        }
    }

    #[derive(Default)]
    struct ImportVisitor {
        imports: TrybuildImports,
    }

    impl<'ast> syn::visit::Visit<'ast> for ImportVisitor {
        fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
            record_use(&node.tree, &mut Vec::new(), &mut self.imports);
            syn::visit::visit_item_use(self, node);
        }

        fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
            if node.ident == "trybuild" {
                self.imports.modules.insert(
                    node.rename
                        .as_ref()
                        .map_or_else(|| node.ident.to_string(), |(_, rename)| rename.to_string()),
                );
            }
            syn::visit::visit_item_extern_crate(self, node);
        }
    }

    struct TrybuildVisitor<'a> {
        imports: &'a TrybuildImports,
        found: bool,
    }

    fn tokens_contain_trybuild(tokens: &proc_macro2::TokenStream) -> bool {
        tokens.clone().into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(ident) => ident == "trybuild",
            proc_macro2::TokenTree::Group(group) => tokens_contain_trybuild(&group.stream()),
            proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
        })
    }

    impl<'ast> syn::visit::Visit<'ast> for TrybuildVisitor<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref() {
                let segments = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>();
                self.found |= match segments.as_slice() {
                    [module, test_cases, new] => {
                        self.imports.modules.contains(module)
                            && test_cases == "TestCases"
                            && new == "new"
                    }
                    [test_cases, new] => {
                        self.imports.test_cases.contains(test_cases) && new == "new"
                    }
                    _ => false,
                };
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            self.found |= tokens_contain_trybuild(&node.tokens);
            syn::visit::visit_macro(self, node);
        }
    }

    let syntax = syn::parse_file(source).context("解析 trybuild carrier Rust AST")?;
    let mut import_visitor = ImportVisitor::default();
    import_visitor.imports.modules.insert("trybuild".to_owned());
    syn::visit::Visit::visit_file(&mut import_visitor, &syntax);
    let mut visitor = TrybuildVisitor {
        imports: &import_visitor.imports,
        found: false,
    };
    syn::visit::Visit::visit_file(&mut visitor, &syntax);
    Ok(visitor.found)
}

fn is_trybuild_target(name: &str) -> bool {
    name == "trybuild" || name.ends_with("_trybuild")
}

fn trybuild_inventory(
    root: &Path,
    metadata: &serde_json::Value,
) -> Result<(BTreeSet<String>, BTreeMap<String, String>)> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .context("cargo metadata 缺 packages")?;
    let mut carriers = BTreeSet::new();
    let mut selected_targets = BTreeMap::new();

    for package in packages {
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .context("cargo metadata package 缺 manifest_path")?;
        let member_root = Path::new(manifest)
            .parent()
            .context("workspace member manifest 缺父目录")?;
        if !member_root.starts_with(root) {
            bail!("workspace member 越出根目录: {member_root:?}");
        }
        for path in rust_files_under(member_root)? {
            if source_uses_trybuild(&fs::read_to_string(&path)?)? {
                carriers.insert(path.to_string_lossy().into_owned());
            }
        }
        let targets = package
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .context("cargo metadata package 缺 targets")?;
        for target in targets {
            let kinds = target
                .get("kind")
                .and_then(serde_json::Value::as_array)
                .context("cargo metadata target 缺 kind")?;
            let name = target
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("cargo metadata target 缺 name")?;
            if !kinds.iter().any(|kind| kind.as_str() == Some("test")) {
                continue;
            }
            let source = target
                .get("src_path")
                .and_then(serde_json::Value::as_str)
                .context("cargo metadata target 缺 src_path")?;
            let source_path = Path::new(source);
            if !source_path.starts_with(member_root) || !source_path.starts_with(root) {
                bail!("Cargo test target 越出 workspace member: {source}");
            }
            let source_metadata = fs::symlink_metadata(source_path)
                .with_context(|| format!("读取 Cargo test target source 失败: {source}"))?;
            if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
                bail!("Cargo test target source 必须是普通文件: {source}");
            }
            if !is_trybuild_target(name) {
                continue;
            }
            if selected_targets
                .insert(source.to_owned(), name.to_owned())
                .is_some()
            {
                bail!("多个 trybuild target 共享 source: {source}");
            }
        }
    }
    Ok((carriers, selected_targets))
}

fn validate_trybuild_inventory(
    carriers: &BTreeSet<String>,
    selected_targets: &BTreeMap<String, String>,
) -> Result<()> {
    let invalid_names = selected_targets
        .values()
        .filter(|name| !is_trybuild_target(name))
        .cloned()
        .collect::<Vec<_>>();
    let selected_sources = selected_targets.keys().cloned().collect::<BTreeSet<_>>();
    let unselected = carriers
        .difference(&selected_sources)
        .cloned()
        .collect::<Vec<_>>();
    let stale = selected_sources
        .difference(carriers)
        .cloned()
        .collect::<Vec<_>>();
    if !unselected.is_empty() || !stale.is_empty() || !invalid_names.is_empty() {
        bail!(
            "trybuild nextest selector 漂移; unselected={unselected:?}; stale={stale:?}; invalid_names={invalid_names:?}"
        );
    }
    Ok(())
}

fn rust_files_under(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .with_context(|| format!("读取 Rust source 目录失败: {}", directory.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("Rust source 禁止符号链接: {}", path.display());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;
    use crate::workspace_root;

    #[test]
    fn local_only_invocation_is_exact_non_empty_and_inventory_derived() -> Result<()> {
        let packages = vec!["audit".to_owned(), "identity".to_owned()];
        let tests = vec![
            "application::tests::audit_receipt".to_owned(),
            "application::tests::identity_receipt".to_owned(),
        ];
        let args = local_only_args(&packages, &tests, crate::cmd::ExecutionPolicy::FailFast)?;
        assert_eq!(
            args,
            [
                "--profile",
                "ci-core",
                "--locked",
                "--no-tests=fail",
                "--lib",
                "-p",
                "audit",
                "-p",
                "identity",
                "--",
                "application::tests::audit_receipt",
                "application::tests::identity_receipt",
                "--exact",
            ]
        );
        assert!(local_only_args(&[], &tests, crate::cmd::ExecutionPolicy::FailFast).is_err());
        assert!(local_only_args(&packages, &[], crate::cmd::ExecutionPolicy::FailFast).is_err());
        assert!(
            local_only_args(
                &["identity".into(), "audit".into()],
                &tests,
                crate::cmd::ExecutionPolicy::FailFast,
            )
            .is_err()
        );
        assert!(
            local_only_args(
                &packages,
                &["bad/name".into()],
                crate::cmd::ExecutionPolicy::FailFast,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn nextest_failure_policy_is_explicit_and_local_only() -> Result<()> {
        use crate::cmd::ExecutionPolicy;

        let remote =
            NextestInvocation::for_core(CoreTestSelection::workspace(), NextestLane::CiCore, None)
                .execution_argv();
        assert!(!remote.iter().any(|arg| arg == "--no-fail-fast"));

        let local =
            NextestInvocation::for_core(CoreTestSelection::workspace(), NextestLane::Verify, None)
                .with_execution_policy(ExecutionPolicy::KeepGoing)
                .execution_argv();
        assert!(local.iter().any(|arg| arg == "--no-fail-fast"));

        let packages = vec!["identity".to_owned()];
        let tests = vec!["application::tests::identity_receipt".to_owned()];
        assert!(
            local_only_args(&packages, &tests, ExecutionPolicy::KeepGoing)?
                .iter()
                .any(|arg| arg == "--no-fail-fast")
        );
        Ok(())
    }

    #[test]
    fn local_only_command_rejects_real_nonzero_exit_status() -> Result<()> {
        #[cfg(unix)]
        let command = super::super::clean_cmd("sh", &["-c", "exit 23"], &[], None);
        #[cfg(windows)]
        let command = super::super::clean_cmd("cmd", &["/C", "exit 23"], &[], None);

        let error = execute_local_only_command(command)
            .err()
            .context("exit 23 must fail closed")?;
        assert!(
            error.to_string().contains("23"),
            "helper must observe the real child exit status: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn hash_partition_accepts_only_closed_m_over_n() -> Result<()> {
        for (raw, expected) in [
            ("1/1", "hash:1/1"),
            ("1/32", "hash:1/32"),
            ("32/32", "hash:32/32"),
        ] {
            assert_eq!(raw.parse::<HashPartition>()?.nextest_arg(), expected);
        }
        for raw in [
            "0/1",
            "2/1",
            "1/0",
            "1/33",
            "33/33",
            "hash:1/2",
            "count:1/2",
            "slice:1/2",
            "1",
            "1/2/3",
            "01/x",
            "999999999999999999999/2",
        ] {
            assert!(raw.parse::<HashPartition>().is_err(), "{raw} must fail");
        }
        Ok(())
    }

    fn valid_config() -> String {
        let profiles: String = [
            ("ci-core", "120s", "junit.xml", 2),
            ("integration", "300s", "junit.xml", 2),
            ("production-artifact", "900s", "junit.xml", 1),
            ("fault-matrix", "600s", "junit.xml", 1),
        ]
        .into_iter()
        .map(|(name, period, path, terminate)| format!("[profile.{name}]\nretries = 0\nflaky-result = \"fail\"\nslow-timeout = {{ period = \"{period}\", terminate-after = {terminate} }}\n[profile.{name}.junit]\npath = \"{path}\"\n"))
        .collect();
        format!(
            "[profile.default]\nretries=0\n{profiles}\n[profile.coverage-identityaudit]\ninherits='ci-core'\ndefault-filter='binary(identityaudit_runtime)'\n[profile.coverage-identityaudit.junit]\npath='junit.xml'\n[test-groups.trybuild]\nmax-threads=1\n[[profile.default.overrides]]\nfilter='{TRYBUILD_FILTER}'\ntest-group='trybuild'\n[[profile.ci-core.overrides]]\nfilter='{TRYBUILD_FILTER}'\ntest-group='trybuild'\n"
        )
    }

    #[test]
    fn config_policy_rejects_retry_override_and_missing_timeout() {
        let green = valid_config();
        assert!(validate_config(&green).is_ok());
        for red in [
            green.replacen("retries = 0", "retries = 2", 1),
            green.replacen("[profile.ci-core]", "[profile.missing-ci-core]", 1),
            green.replacen("slow-timeout", "missing-timeout", 1),
            green.replacen("path = \"junit.xml\"", "path = \"wrong.xml\"", 1),
            green.replacen("flaky-result = \"fail\"", "flaky-result = \"pass\"", 1),
            format!("{green}\n[profile.ci]\nretries=0\n"),
            format!("{green}\n[[profile.integration.overrides]]\nfilter='all()'\nretries=2\n"),
            green.replacen("max-threads=1", "max-threads=2", 1),
            green.replacen(TRYBUILD_FILTER, "binary(/trybuild/)", 1),
            green.replacen("test-group='trybuild'", "test-group='other'", 1),
            green.replacen("terminate-after = 2", "terminate-after = 1", 1),
            green.replacen("period = \"900s\"", "period = \"300s\"", 1),
            green.replacen("terminate-after = 1", "terminate-after = 2", 1),
            green.replacen(
                "[profile.production-artifact]",
                "[profile.production-artifact-stale]",
                1,
            ),
            green.replacen("retries = 0", "global-timeout = \"60s\"\nretries = 0", 1),
            green.replacen("inherits='ci-core'", "inherits='integration'", 1),
            green.replacen(
                "binary(identityaudit_runtime)",
                "binary(settingsonly_runtime)",
                1,
            ),
        ] {
            assert!(validate_config(&red).is_err());
        }
    }

    #[test]
    fn committed_nextest_config_obeys_policy() -> Result<()> {
        let source = fs::read_to_string(workspace_root()?.join(".config/nextest.toml"))?;
        validate_config(&source)
    }

    #[test]
    fn trybuild_inventory_is_bidirectionally_closed() {
        let carriers = BTreeSet::from(["/workspace/crates/demo/tests/api_trybuild.rs".into()]);
        let targets = BTreeMap::from([(
            "/workspace/crates/demo/tests/api_trybuild.rs".into(),
            "api_trybuild".into(),
        )]);
        assert!(validate_trybuild_inventory(&carriers, &targets).is_ok());

        let mut selector_only = targets.clone();
        selector_only.insert(
            "/workspace/crates/demo/tests/stale_trybuild.rs".into(),
            "stale_trybuild".into(),
        );
        assert!(validate_trybuild_inventory(&carriers, &selector_only).is_err());

        let unselected = BTreeMap::from([(
            "/workspace/crates/demo/tests/api_trybuild.rs".into(),
            "compile_contract".into(),
        )]);
        assert!(validate_trybuild_inventory(&carriers, &unselected).is_err());
    }

    #[test]
    fn trybuild_carrier_detection_uses_rust_ast() -> Result<()> {
        assert!(source_uses_trybuild(
            "fn ui() { let _ = trybuild::TestCases::new(); }"
        )?);
        assert!(source_uses_trybuild(
            "use trybuild::TestCases; fn ui() { let _ = TestCases::new(); }"
        )?);
        assert!(source_uses_trybuild(
            "use trybuild::TestCases as Cases; fn ui() { let _ = Cases::new(); }"
        )?);
        assert!(source_uses_trybuild(
            "use trybuild as tb; fn ui() { let _ = tb::TestCases::new(); }"
        )?);
        assert!(source_uses_trybuild(
            "macro_rules! cases { () => { trybuild::TestCases::new() } }"
        )?);
        assert!(!source_uses_trybuild(
            "fn ordinary() { let _ = \"trybuild::TestCases::new()\"; }"
        )?);
        assert!(!source_uses_trybuild(
            "fn ordinary() { let _ = local::TestCases::new(); }"
        )?);
        Ok(())
    }

    #[test]
    fn trybuild_inventory_rejects_non_dedicated_sources() -> Result<()> {
        let root = unique_tmp("nextest-trybuild-targets");
        let package = root.join("crates/demo");
        let test_source = package.join("tests/api_trybuild.rs");
        let non_target_source = package.join("src/helper.rs");
        fs::create_dir_all(test_source.parent().context("test source parent")?)?;
        fs::create_dir_all(
            non_target_source
                .parent()
                .context("non-target source parent")?,
        )?;
        fs::write(
            &test_source,
            "fn ui() { let _ = trybuild::TestCases::new(); }",
        )?;
        fs::write(
            &non_target_source,
            "fn helper() { let _ = trybuild::TestCases::new(); }",
        )?;
        let metadata = serde_json::json!({
            "packages": [{
                "manifest_path": package.join("Cargo.toml"),
                "targets": [
                    {"kind": ["lib"], "name": "demo", "src_path": non_target_source},
                    {"kind": ["test"], "name": "api_trybuild", "src_path": test_source},
                ],
            }],
        });

        let (carriers, targets) = trybuild_inventory(&root, &metadata)?;
        let expected_source = test_source.to_string_lossy().into_owned();
        let hidden_source = non_target_source.to_string_lossy().into_owned();
        assert_eq!(
            carriers,
            BTreeSet::from([expected_source.clone(), hidden_source]),
            "trybuild references outside a dedicated integration target must be discovered"
        );
        assert_eq!(
            targets,
            BTreeMap::from([(expected_source, "api_trybuild".to_owned())])
        );
        assert!(
            validate_trybuild_inventory(&carriers, &targets).is_err(),
            "a lib/unit/module trybuild carrier must fail closed instead of escaping the selector"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_trybuild_inventory_is_non_vacuous_and_closed() -> Result<()> {
        let root = workspace_root()?;
        let metadata = cargo_metadata(&root)?;
        let (carriers, targets) = trybuild_inventory(&root, &metadata)?;
        assert!(
            carriers.len() >= 19,
            "real workspace must exercise the guard"
        );
        validate_trybuild_inventory(&carriers, &targets)
    }

    #[test]
    fn execution_funnel_rejects_private_capability_api_bypass() {
        assert!(
            validate_capability_boundary_source(
                "fn f() { cargo_cmd(CargoSubcommand::Check, &[\"--locked\"]); }"
            )
            .is_ok()
        );
        for red in [
            // 普通 macro_rules literal：不依赖展开或 nextest 字面量识别，只守 private API 边界。
            "macro_rules! run { () => { clean_cmd(\"cargo\", &[\"nextest\", \"run\"]) } }",
            // array concat：即使 capability 在运行期才拼出，旧 raw cargo API 仍不可调用。
            "fn f() { let args = [[\"next\", \"est\"].concat(), \"run\".into()]; clean_cmd(\"cargo\", &args); }",
            // 变量传播：validator 不追踪值，只拒绝越过 typed boundary。
            "fn f(program: &str, args: &[&str]) { let forwarded = (program, args); clean_cmd(forwarded.0, forwarded.1); }",
            "fn f() { nextest_cmd(token, mode, &[], &[], None); }",
            "fn f() { nextest_available(token); }",
        ] {
            assert!(
                validate_capability_boundary_source(red).is_err(),
                "red must fail: {red}"
            );
        }
    }

    #[test]
    fn real_nextest_call_sites_use_funnel() -> Result<()> {
        validate_workspace(&workspace_root()?)
    }

    #[test]
    fn replay_spec_is_closed_and_partition_is_typed() -> Result<()> {
        let partition = Some("2/2".parse()?);
        let invocation = NextestInvocation::for_core(
            CoreTestSelection::workspace(),
            NextestLane::CiCore,
            partition,
        );
        assert_eq!(
            invocation.replay_spec(),
            &ReplaySpec::Core {
                selection: CoreTestSelection::workspace(),
                partition
            }
        );
        Ok(())
    }

    #[test]
    fn component_test_selection_is_typed_nonempty_and_feature_closed() -> Result<()> {
        let workspace = CoreTestSelection::workspace();
        assert!(workspace.packages_ref().is_none());

        let packages = CoreTestSelection::packages(vec!["grpc".to_owned(), "testkit".to_owned()])
            .context("non-empty package selection")?;
        assert_eq!(
            packages.packages_ref(),
            Some(&["grpc".to_owned(), "testkit".to_owned()][..])
        );
        assert!(CoreTestSelection::packages(Vec::new()).is_none());

        let features = deterministic_feature_args(&workspace);
        assert!(features.iter().any(|value| value == "grpc/backend"));
        assert!(features.iter().any(|value| value == "testkit/containers"));
        assert!(
            features
                .iter()
                .any(|value| value == "identity-composition/device-mqtt")
        );
        let pilot = CoreTestSelection::packages(vec!["identity-composition".to_owned()])
            .context("pilot package selection")?;
        assert_eq!(
            deterministic_feature_args(&pilot),
            ["identity-composition/device-mqtt"]
        );
        assert!(
            features
                .iter()
                .all(|value| { !value.contains("integration") && !value.contains("broker-tests") })
        );
        Ok(())
    }

    #[test]
    fn postgres_transaction_journey_serial_batch_fails_when_compiled_inventory_is_empty()
    -> Result<()> {
        let selection = crate::integration_shards::localtx_required_selection()?;
        let batch =
            crate::integration_shards::postgres_transaction_journey_execution_batch(&selection)?;
        let expected_targets = batch.targets.iter().copied().collect::<BTreeSet<_>>();
        assert!(integration_batch_fails_on_empty(&batch));
        let invocation = NextestInvocation::for_integration_batch(&selection, &batch, None)?;
        let args = invocation.execution_argv();
        let selected: BTreeSet<_> = args
            .windows(2)
            .filter_map(|pair| (pair[0] == "--test").then_some(pair[1].as_str()))
            .collect();
        assert_eq!(selected, expected_targets);
        assert!(args.iter().any(|argument| argument == "--no-tests=fail"));
        assert!(!args.iter().any(|argument| argument == "--no-tests=pass"));
        Ok(())
    }

    #[test]
    fn production_artifact_profile_route_is_typed_and_exclusive() -> Result<()> {
        use crate::integration_shards::{IntegrationShard, IntegrationUnitId};

        let production_unit = IntegrationUnitId::SettingsOnlyProductionArtifact.spec();
        let fault_unit = IntegrationUnitId::ConsistencyFaultMatrixJourney.spec();
        let selection = crate::integration_shards::IntegrationSelection::for_profile(
            crate::execution_profiles::ExecutionProfile::ReleaseCheck,
        )?;
        let mut production_batches = 0;
        for shard in IntegrationShard::ALL {
            for batch in crate::integration_shards::batches(&selection, *shard) {
                let invocation =
                    NextestInvocation::for_integration_batch(&selection, &batch, None)?;
                let contains_production_unit = batch.package == production_unit.package
                    && batch.kind == production_unit.kind
                    && batch.scheduling == production_unit.scheduling
                    && batch.targets.contains(&production_unit.target);
                let contains_fault_unit = batch.package == fault_unit.package
                    && batch.kind == fault_unit.kind
                    && batch.scheduling == fault_unit.scheduling
                    && batch.targets.contains(&fault_unit.target);
                let expected = if contains_production_unit {
                    production_batches += 1;
                    NextestProfile::ProductionArtifact
                } else if contains_fault_unit {
                    NextestProfile::FaultMatrix
                } else {
                    NextestProfile::Integration
                };
                assert_eq!(invocation.profile, expected);
                if contains_production_unit {
                    assert!(
                        invocation
                            .execution_argv()
                            .windows(2)
                            .any(|pair| pair == ["--profile", "production-artifact"])
                    );
                }
            }
        }
        assert_eq!(
            production_batches, 1,
            "typed production unit must route once"
        );
        assert_eq!(
            NextestProfile::ProductionArtifact.junit_path(),
            "target/nextest/production-artifact/junit.xml"
        );
        assert_ne!(
            NextestProfile::ProductionArtifact.junit_path(),
            NextestProfile::Integration.junit_path()
        );
        Ok(())
    }

    #[test]
    fn llvm_cov_replay_spec_closes_profile_without_raw_args() -> Result<()> {
        let workspace = crate::ci_impact::coverage_scope_for_full_ci();
        let invocation =
            NextestInvocation::for_coverage("target/coverage.json", workspace.clone())?;
        assert_eq!(
            invocation.execution_argv(),
            [
                "cargo",
                "llvm-cov",
                "nextest",
                "--workspace",
                "--locked",
                "--features",
                "amqp/backend,s3/backend,redis-adapter/backend,oidc/backend,prometheus-adapter/backend,otel/backend,grpc/backend,vault/backend,softca/backend,testkit/containers,identity-composition/device-mqtt",
                "--json",
                "--output-path",
                "target/coverage.json"
            ]
            .map(str::to_owned)
        );
        assert_eq!(
            invocation.replay_spec(),
            &ReplaySpec::Coverage { scope: workspace }
        );
        Ok(())
    }

    #[test]
    fn coverage_argv_scope_mutex_packages_vs_workspace() -> Result<()> {
        let packages = crate::ci_impact::CoverageScope::Packages {
            packages: vec!["leaf".to_owned(), "consumer".to_owned()],
            strict_touched: Vec::new(),
        };
        let argv =
            NextestInvocation::for_coverage("target/coverage.json", packages)?.execution_argv();
        assert!(
            argv.iter().any(|a| a == "-p"),
            "Packages scope must use -p: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "--workspace"),
            "Packages scope must not use --workspace: {argv:?}"
        );
        assert_eq!(
            argv.windows(2)
                .filter(|w| w[0] == "-p")
                .map(|w| w[1].as_str())
                .collect::<Vec<_>>(),
            vec!["leaf", "consumer"]
        );

        let workspace = crate::ci_impact::coverage_scope_for_full_ci();
        let argv =
            NextestInvocation::for_coverage("target/coverage.json", workspace)?.execution_argv();
        assert!(argv.iter().any(|a| a == "--workspace"));
        assert!(!argv.iter().any(|a| a == "-p"));

        assert!(
            crate::ci_impact::CoverageScope::packages(Vec::new(), Vec::new()).is_none(),
            "empty packages must be unconstructible"
        );
        let invalid = crate::ci_impact::CoverageScope::Packages {
            packages: vec!["Bad/Name".to_owned()],
            strict_touched: Vec::new(),
        };
        match NextestInvocation::for_coverage("target/coverage.json", invalid) {
            Ok(_invocation) => {
                bail!("invalid package identity must bail");
            }
            Err(err) => assert!(
                err.to_string().contains("invalid package name"),
                "invalid package identity must bail: {err}"
            ),
        }
        Ok(())
    }

    #[test]
    fn identityaudit_coverage_supplement_is_workspace_scoped_and_exact() -> Result<()> {
        let invocation =
            NextestInvocation::for_identityaudit_coverage("target/identityaudit.lcov")?;
        assert_eq!(
            invocation.execution_argv(),
            [
                "cargo",
                "llvm-cov",
                "nextest",
                "--no-clean",
                "--workspace",
                "--locked",
                "--features",
                "testkit/containers,journeys/integration",
                "--lcov",
                "--output-path",
                "target/identityaudit.lcov"
            ]
            .map(str::to_owned)
        );
        assert_eq!(invocation.profile, NextestProfile::CoverageIdentityaudit);
        assert_eq!(
            invocation.replay_spec(),
            &ReplaySpec::CoverageSupplement {
                supplement: CoverageSupplement::IdentityAudit
            }
        );
        let (gate, batch_label) = invocation.evidence_labels();
        let record = Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            lane: NextestLane::Coverage,
            shard: None,
            profile: NextestProfile::CoverageIdentityaudit,
            invocation_id: "identityaudit-supplement".to_owned(),
            gate,
            batch_label,
            outcome: Outcome::SetupFailed,
            junit_path: None,
            nextest_version: NEXTEST_VERSION.to_owned(),
            source_revision: "0".repeat(40),
            replay: invocation.replay_spec().clone(),
        };
        validate_evidence_record(&record, "identityaudit-supplement")?;
        Ok(())
    }

    #[test]
    fn deterministic_feature_registry_is_non_empty_namespaced_and_safe() -> Result<()> {
        assert!(
            !DeterministicTestFeature::ALL.is_empty(),
            "component tests must explicitly activate feature-gated code"
        );
        let rendered = deterministic_feature_args(&CoreTestSelection::workspace());
        assert_eq!(rendered.len(), DeterministicTestFeature::ALL.len());
        assert!(rendered.iter().all(|feature| feature.contains('/')));
        assert!(
            rendered.iter().all(
                |feature| !feature.contains("integration") && !feature.contains("broker-tests")
            )
        );
        validate_deterministic_features(&cargo_metadata(&workspace_root()?)?)?;
        let invalid = serde_json::json!({"packages": []});
        assert!(validate_deterministic_features(&invalid).is_err());
        let extra_backend = serde_json::json!({
            "workspace_members": ["demo 0.0.0 (path+file:///demo)"],
            "packages": [{
                "id": "demo 0.0.0 (path+file:///demo)",
                "name": "demo",
                "features": {"backend": []}
            }]
        });
        assert!(
            validate_deterministic_features(&extra_backend).is_err(),
            "a new backend feature must fail until the typed catalog is extended"
        );
        Ok(())
    }

    #[test]
    fn component_package_wire_rejects_noncanonical_or_invalid_sets() -> Result<()> {
        let canonical: CoreTestSelection =
            serde_json::from_str(r#"{"kind":"packages","packages":["oidc","vault"]}"#)?;
        assert_eq!(
            canonical.packages_ref(),
            Some(&["oidc".to_owned(), "vault".to_owned()][..])
        );
        for invalid in [
            r#"{"kind":"packages","packages":[]}"#,
            r#"{"kind":"packages","packages":["Bad/Name"]}"#,
            r#"{"kind":"packages","packages":["vault","oidc"]}"#,
            r#"{"kind":"packages","packages":["oidc","oidc"]}"#,
        ] {
            assert!(
                serde_json::from_str::<CoreTestSelection>(invalid).is_err(),
                "invalid package wire must fail closed: {invalid}"
            );
        }
        Ok(())
    }

    #[test]
    fn integration_replay_unit_ids_reject_duplicates_and_noncanonical_order() -> Result<()> {
        use crate::integration_shards::{IntegrationSelection, IntegrationUnitId};

        let selection = IntegrationSelection::critical([
            IntegrationUnitId::AmqpLib,
            IntegrationUnitId::AmqpIntegration,
        ])?;
        let unit_ids = IntegrationReplayUnitIds::new(
            [
                IntegrationUnitId::AmqpLib,
                IntegrationUnitId::AmqpIntegration,
            ]
            .into_iter()
            .collect(),
        )?;
        let replay = ReplaySpec::Integration {
            profile: NextestProfile::Integration,
            shard: crate::integration_shards::IntegrationShard::EventTransport,
            selection,
            unit_ids,
            partition: None,
        };
        let mut wire = serde_json::to_value(replay)?;
        let canonical = wire.clone();
        assert_eq!(
            canonical["selection"],
            serde_json::json!("integration-critical:amqp-integration,amqp-lib")
        );
        assert_eq!(
            canonical["unitIds"],
            serde_json::json!(["amqp-integration", "amqp-lib"]),
            "replay unitIds must share the selection token's wire order"
        );
        let mut invocation = NextestInvocation::new(
            NextestProfile::Integration,
            NextestLane::Integration,
            Some("event-transport"),
            None,
            NextestRunner::Cargo,
            Vec::new(),
        );
        invocation.replay_spec = serde_json::from_value(canonical.clone())?;
        assert_eq!(
            invocation.evidence_labels().1.as_deref(),
            Some("units:amqp-integration,amqp-lib")
        );
        wire["unitIds"] = serde_json::json!(["amqp-lib", "amqp-lib"]);
        assert!(serde_json::from_value::<ReplaySpec>(wire.clone()).is_err());
        wire["unitIds"] = serde_json::json!(["amqp-lib", "amqp-integration"]);
        assert!(serde_json::from_value::<ReplaySpec>(wire).is_err());
        let mut raw_filter = canonical;
        raw_filter["filter"] = serde_json::json!("all()");
        assert!(serde_json::from_value::<ReplaySpec>(raw_filter).is_err());

        let mismatched = ReplaySpec::Integration {
            profile: NextestProfile::ProductionArtifact,
            shard: crate::integration_shards::IntegrationShard::EventTransport,
            selection: IntegrationSelection::critical([
                IntegrationUnitId::AmqpLib,
                IntegrationUnitId::AmqpIntegration,
            ])?,
            unit_ids: IntegrationReplayUnitIds::new(
                [
                    IntegrationUnitId::AmqpLib,
                    IntegrationUnitId::AmqpIntegration,
                ]
                .into_iter()
                .collect(),
            )?,
            partition: None,
        };
        assert!(invocation_for_replay(&mismatched, NextestLane::Integration).is_err());
        Ok(())
    }

    #[test]
    fn component_package_evidence_label_is_stable_and_human_readable() -> Result<()> {
        let selection = CoreTestSelection::packages(vec!["vault".to_owned(), "oidc".to_owned()])
            .context("valid package selection")?;
        let invocation = NextestInvocation::for_core(selection, NextestLane::CiCore, None);
        assert_eq!(
            invocation.evidence_labels(),
            ("core-packages:oidc,vault".to_owned(), None)
        );
        Ok(())
    }

    #[test]
    fn evidence_schema_matches_golden() -> Result<()> {
        let evidence = Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            lane: NextestLane::CiCore,
            shard: None,
            profile: NextestProfile::CiCore,
            invocation_id: "ci-core-workspace-ci-core-0123456789ab".to_owned(),
            gate: "core-workspace".to_owned(),
            batch_label: None,
            outcome: Outcome::Failed,
            junit_path: Some("nextest/ci-core.xml".to_owned()),
            nextest_version: NEXTEST_VERSION.to_owned(),
            source_revision: "0000000000000000000000000000000000000000".to_owned(),
            replay: ReplaySpec::Core {
                selection: CoreTestSelection::workspace(),
                partition: Some("1/2".parse()?),
            },
        };
        validate_evidence_schema(
            &serde_json::to_string_pretty(&evidence)?,
            include_str!("../tests/golden/nextest-evidence.json"),
        )?;
        Ok(())
    }

    #[test]
    fn integration_evidence_v4_matches_committed_golden() -> Result<()> {
        use crate::integration_shards::{
            IntegrationSelection, IntegrationShard, IntegrationUnitId,
        };

        let evidence = Evidence {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            lane: NextestLane::Integration,
            shard: Some(IntegrationShard::EventTransport.to_string()),
            profile: NextestProfile::Integration,
            invocation_id: "integration-event-transport-integration-0123456789ab".to_owned(),
            gate: "integration-event-transport".to_owned(),
            batch_label: Some("units:amqp-lib".to_owned()),
            outcome: Outcome::Failed,
            junit_path: Some(
                "nextest/integration-event-transport-integration-0123456789ab.xml".to_owned(),
            ),
            nextest_version: NEXTEST_VERSION.to_owned(),
            source_revision: "0000000000000000000000000000000000000000".to_owned(),
            replay: ReplaySpec::Integration {
                profile: NextestProfile::Integration,
                shard: IntegrationShard::EventTransport,
                selection: IntegrationSelection::critical([IntegrationUnitId::AmqpLib])?,
                unit_ids: IntegrationReplayUnitIds::new(BTreeSet::from([
                    IntegrationUnitId::AmqpLib,
                ]))?,
                partition: Some("1/2".parse()?),
            },
        };
        let actual = serde_json::to_string_pretty(&evidence)?;
        validate_evidence_schema(
            &actual,
            include_str!("../tests/golden/nextest-integration-evidence-v4.json"),
        )?;
        validate_evidence_record(&evidence, &evidence.invocation_id)?;
        Ok(())
    }

    #[test]
    fn evidence_schema_rejects_wire_drift() -> Result<()> {
        let golden = include_str!("../tests/golden/nextest-evidence.json");
        let drift = golden.replacen("\"schemaVersion\"", "\"schema_version\"", 1);
        assert!(validate_evidence_schema(&drift, golden).is_err());
        let legacy = golden.replacen("\"schemaVersion\": 4", "\"schemaVersion\": 3", 1);
        assert!(validate_evidence_schema(&legacy, golden).is_err());
        let old_scope = golden.replacen(
            "\"selection\": {\n      \"kind\": \"workspace\"\n    }",
            "\"scope\": \"workspace\"",
            1,
        );
        assert!(serde_json::from_str::<Evidence>(&old_scope).is_err());
        Ok(())
    }

    #[test]
    fn integration_evidence_v4_rejects_legacy_and_noncanonical_wire() -> Result<()> {
        let golden = include_str!("../tests/golden/nextest-integration-evidence-v4.json");

        let legacy_schema = golden.replacen("\"schemaVersion\": 4", "\"schemaVersion\": 3", 1);
        let legacy: Evidence = serde_json::from_str(&legacy_schema)?;
        assert!(validate_evidence_record(&legacy, &legacy.invocation_id).is_err());

        for legacy_field in ["batch", "batchNumber"] {
            let mut wire: serde_json::Value = serde_json::from_str(golden)?;
            wire["replay"][legacy_field] = serde_json::json!(1);
            assert!(serde_json::from_value::<Evidence>(wire).is_err());
        }

        let mut missing_selection: serde_json::Value = serde_json::from_str(golden)?;
        missing_selection["replay"]
            .as_object_mut()
            .context("integration replay object")?
            .remove("selection");
        assert!(serde_json::from_value::<Evidence>(missing_selection).is_err());

        for unit_ids in [
            serde_json::json!(["amqp-lib", "amqp-lib"]),
            serde_json::json!(["amqp-lib", "amqp-integration"]),
            serde_json::json!(["unknown-integration-unit"]),
        ] {
            let mut wire: serde_json::Value = serde_json::from_str(golden)?;
            wire["replay"]["selection"] =
                serde_json::json!("integration-critical:amqp-integration,amqp-lib");
            wire["replay"]["unitIds"] = unit_ids;
            assert!(serde_json::from_value::<Evidence>(wire).is_err());
        }

        let mut contradiction: Evidence = serde_json::from_str(golden)?;
        let ReplaySpec::Integration { selection, .. } = &mut contradiction.replay else {
            unreachable!("committed integration golden must carry integration replay")
        };
        *selection = "integration-critical:amqp-integration".parse()?;
        assert!(
            validate_evidence_record(&contradiction, &contradiction.invocation_id).is_err(),
            "selection and exact unitIds must agree"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn failed_test_preserves_junit_and_sidecar_before_error() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;

        let root = crate::testutil::unique_tmp("nextest-evidence-failure");
        let canonical = root.join(NextestProfile::CiCore.junit_path());
        let evidence_dir = root.join(EVIDENCE_DIR);
        fs::create_dir_all(canonical.parent().context("canonical parent")?)?;
        fs::create_dir_all(&evidence_dir)?;
        fs::write(&canonical, "<testsuites/>")?;
        let invocation = NextestInvocation::new(
            NextestProfile::CiCore,
            NextestLane::CiCore,
            None,
            Some("1/2".parse()?),
            NextestRunner::Cargo,
            vec!["--workspace".to_owned()],
        );
        let result = invocation.finish(
            &evidence_dir,
            &canonical,
            "failure-case",
            "0000000000000000000000000000000000000000",
            ExitStatus::from_raw(1 << 8),
        );
        assert!(result.is_err());
        assert!(!canonical.exists());
        assert_eq!(
            fs::read_to_string(evidence_dir.join("failure-case.xml"))?,
            "<testsuites/>"
        );
        let json = fs::read_to_string(evidence_dir.join("failure-case.json"))?;
        assert!(json.contains("\"outcome\": \"failed\""));
        assert!(!json.contains(root.to_string_lossy().as_ref()));
        assert!(json.contains("\"junitPath\": \"nextest/failure-case.xml\""));

        stage(&root)?;
        let artifact_root = root.join("target/job-evidence");
        let staged_nextest = artifact_root.join("nextest");
        validate_staged_evidence(&artifact_root)?;
        assert!(staged_nextest.join("manifest.json").is_file());
        fs::write(
            staged_nextest.join("failure-case.json"),
            json.replace(
                "nextest/failure-case.xml",
                "target/nextest-evidence/failure-case.xml",
            ),
        )?;
        assert!(validate_staged_evidence(&artifact_root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn missing_junit_is_setup_failed_for_zero_and_nonzero_status() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;

        for (name, raw_status) in [("success-missing", 0), ("failure-missing", 1 << 8)] {
            let root = crate::testutil::unique_tmp(name);
            let canonical = root.join(NextestProfile::CiCore.junit_path());
            let evidence_dir = root.join(EVIDENCE_DIR);
            fs::create_dir_all(&evidence_dir)?;
            let invocation = NextestInvocation::new(
                NextestProfile::CiCore,
                NextestLane::CiCore,
                None,
                None,
                NextestRunner::Cargo,
                vec!["--workspace".to_owned()],
            );
            assert!(
                invocation
                    .finish(
                        &evidence_dir,
                        &canonical,
                        name,
                        "0000000000000000000000000000000000000000",
                        ExitStatus::from_raw(raw_status),
                    )
                    .is_err()
            );
            let json = fs::read_to_string(evidence_dir.join(format!("{name}.json")))?;
            assert!(json.contains("\"outcome\": \"setup-failed\""));
            assert!(!evidence_dir.join(format!("{name}.xml")).exists());
            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn repeated_invocation_ids_never_overwrite() -> Result<()> {
        let root = crate::testutil::unique_tmp("nextest-evidence-id");
        fs::create_dir_all(&root)?;
        assert_eq!(unique_invocation_id(&root, "stable"), "stable");
        fs::write(root.join("stable.json"), "{}")?;
        assert_eq!(unique_invocation_id(&root, "stable"), "stable-2");
        fs::write(root.join("stable-2.xml"), "<testsuites/>")?;
        assert_eq!(unique_invocation_id(&root, "stable"), "stable-3");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_canonical_junit_is_removed_before_every_run() -> Result<()> {
        let root = crate::testutil::unique_tmp("nextest-stale-junit");
        let canonical = root.join(NextestProfile::CiCore.junit_path());
        fs::create_dir_all(canonical.parent().context("canonical parent")?)?;
        fs::write(&canonical, "stale-secret-canary")?;
        prepare_canonical_junit(&canonical)?;
        assert!(!canonical.exists());
        assert!(canonical.parent().is_some_and(Path::is_dir));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stage_rejects_symlink_unknown_dto_and_oversize() -> Result<()> {
        use std::os::unix::fs::symlink;

        let valid_sidecar = include_str!("../tests/golden/nextest-evidence.json")
            .replace("ci-core-workspace-ci-core-0123456789ab", "case")
            .replace("nextest/ci-core.xml", "nextest/case.xml");

        let unknown_root = crate::testutil::unique_tmp("nextest-stage-unknown");
        let unknown_source = unknown_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&unknown_source)?;
        fs::write(unknown_source.join("case.xml"), "<testsuites/>")?;
        fs::write(
            unknown_source.join("case.json"),
            valid_sidecar.replacen("\"gate\":", "\"unknown\": true,\n  \"gate\":", 1),
        )?;
        assert!(stage(&unknown_root).is_err());
        assert!(!unknown_root.join("target/job-evidence/nextest").exists());
        fs::remove_dir_all(unknown_root)?;

        let invalid_root = crate::testutil::unique_tmp("nextest-stage-invalid-json");
        let invalid_source = invalid_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&invalid_source)?;
        fs::create_dir_all(invalid_root.join("target/job-evidence/nextest"))?;
        fs::write(
            invalid_root.join("target/job-evidence/nextest/old.json"),
            "old",
        )?;
        fs::write(invalid_source.join("case.json"), "{")?;
        assert!(stage(&invalid_root).is_err());
        assert!(!invalid_root.join("target/job-evidence/nextest").exists());
        fs::remove_dir_all(invalid_root)?;

        let symlink_root = crate::testutil::unique_tmp("nextest-stage-symlink");
        let symlink_source = symlink_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&symlink_source)?;
        fs::write(symlink_root.join("outside.xml"), "x")?;
        symlink(
            symlink_root.join("outside.xml"),
            symlink_source.join("case.xml"),
        )?;
        assert!(stage(&symlink_root).is_err());
        fs::remove_dir_all(symlink_root)?;

        let dangling_root = crate::testutil::unique_tmp("nextest-stage-dangling-root");
        fs::create_dir_all(dangling_root.join("target"))?;
        symlink("missing", dangling_root.join(EVIDENCE_DIR))?;
        assert!(stage(&dangling_root).is_err());
        fs::remove_dir_all(dangling_root)?;

        let orphan_root = crate::testutil::unique_tmp("nextest-stage-orphan-xml");
        let orphan_source = orphan_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&orphan_source)?;
        fs::write(orphan_source.join("orphan.xml"), "<testsuites/>")?;
        assert!(stage(&orphan_root).is_err());
        assert!(!orphan_root.join("target/job-evidence/nextest").exists());
        fs::remove_dir_all(orphan_root)?;

        let oversize_root = crate::testutil::unique_tmp("nextest-stage-oversize");
        let oversize_source = oversize_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&oversize_source)?;
        let file = fs::File::create(oversize_source.join("case.xml"))?;
        file.set_len(MAX_EVIDENCE_FILE_BYTES + 1)?;
        assert!(stage(&oversize_root).is_err());
        assert!(!oversize_root.join("target/job-evidence/nextest").exists());
        fs::remove_dir_all(oversize_root)?;

        let total_root = crate::testutil::unique_tmp("nextest-stage-total-overflow");
        let total_source = total_root.join(EVIDENCE_DIR);
        fs::create_dir_all(&total_source)?;
        for index in 0..6 {
            let id = format!("total-{index}");
            let mut sidecar = valid_sidecar
                .replace("case", &id)
                .replace(
                    "  \"outcome\": \"failed\",",
                    "  \"outcome\": \"setup-failed\",",
                )
                .replace(&format!("  \"junitPath\": \"nextest/{id}.xml\",\n"), "");
            sidecar.extend(std::iter::repeat_n(' ', (9 * 1024 * 1024) - sidecar.len()));
            fs::write(total_source.join(format!("{id}.json")), sidecar)?;
        }
        assert!(stage(&total_root).is_err());
        assert!(!total_root.join("target/job-evidence/nextest").exists());
        fs::remove_dir_all(total_root)?;

        let copy_root = crate::testutil::unique_tmp("nextest-copy-size");
        fs::create_dir_all(&copy_root)?;
        fs::write(copy_root.join("source"), "abc")?;
        assert!(copy_checked(&copy_root.join("source"), &copy_root.join("dest"), 2).is_err());
        fs::remove_dir_all(copy_root)?;
        Ok(())
    }

    #[test]
    fn evidence_validator_rejects_derived_contradictions_before_dispatch() -> Result<()> {
        let mut record: Evidence = serde_json::from_str(
            &include_str!("../tests/golden/nextest-evidence.json").replace(
                "nextest/ci-core.xml",
                "nextest/ci-core-workspace-ci-core-0123456789ab.xml",
            ),
        )?;
        assert!(validate_evidence_record(&record, &record.invocation_id).is_ok());
        record.gate = "core-vaultbackend".to_owned();
        assert!(validate_evidence_record(&record, &record.invocation_id).is_err());

        record.replay = ReplaySpec::Integration {
            profile: NextestProfile::Integration,
            shard: crate::integration_shards::IntegrationShard::PostgresDomain,
            selection: "integration-critical:postgres-lib".parse()?,
            unit_ids: IntegrationReplayUnitIds(BTreeSet::new()),
            partition: None,
        };
        assert!(validate_evidence_record(&record, &record.invocation_id).is_err());
        Ok(())
    }

    #[test]
    fn inspect_revalidates_manifest_sidecars_and_display_fields() -> Result<()> {
        let root = crate::testutil::unique_tmp("nextest-inspect-trust");
        let source = root.join(EVIDENCE_DIR);
        fs::create_dir_all(&source)?;
        let sidecar = include_str!("../tests/golden/nextest-evidence.json")
            .replace("ci-core-workspace-ci-core-0123456789ab", "case")
            .replace("nextest/ci-core.xml", "nextest/case.xml");
        fs::write(source.join("case.json"), sidecar)?;
        fs::write(source.join("case.xml"), "<testsuites/>")?;
        stage(&root)?;
        let artifact = root.join("target/job-evidence");
        let manifest_path = artifact.join("nextest/manifest.json");
        let green: EvidenceManifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
        assert!(inspect(&artifact).is_ok());

        let mut reds = Vec::new();
        let mut path_escape = green.clone();
        path_escape.entries[0].sidecar = "../case.json".to_owned();
        reds.push(path_escape);
        let mut control = green.clone();
        control.entries[0].gate = "bad\tgate\u{1b}".to_owned();
        reds.push(control);
        let mut mismatch = green.clone();
        mismatch.entries[0].outcome = Outcome::Passed;
        reds.push(mismatch);
        let mut missing = green.clone();
        missing.entries[0].invocation_id = "missing".to_owned();
        missing.entries[0].sidecar = "nextest/missing.json".to_owned();
        reds.push(missing);
        for red in reds {
            fs::write(&manifest_path, serde_json::to_vec_pretty(&red)?)?;
            assert!(inspect(&artifact).is_err());
        }
        let empty = EvidenceManifest {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            entries: Vec::new(),
        };
        fs::write(&manifest_path, serde_json::to_vec_pretty(&empty)?)?;
        assert!(
            inspect(&artifact).is_err(),
            "empty manifest cannot hide sidecars"
        );

        fs::write(&manifest_path, serde_json::to_vec_pretty(&green)?)?;
        fs::remove_file(artifact.join("nextest/case.xml"))?;
        assert!(inspect(&artifact).is_err(), "required XML must exist");
        fs::write(artifact.join("nextest/case.xml"), "<testsuites/>")?;

        fs::write(artifact.join("nextest/extra.xml"), "<testsuites/>")?;
        assert!(inspect(&artifact).is_err(), "extra XML must fail closed");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn replay_rejects_source_revision_mismatch_before_execution() -> Result<()> {
        let root = crate::testutil::unique_tmp("nextest-replay-revision");
        fs::create_dir_all(&root)?;
        let sidecar = root.join("case.json");
        fs::write(
            &sidecar,
            include_str!("../tests/golden/nextest-evidence.json"),
        )?;
        assert!(replay(&sidecar, &crate::workspace_root()?).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
