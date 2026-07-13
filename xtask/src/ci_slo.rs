//! Strict CI SLO budget evaluation.
//!
//! INVARIANT: CI-SLO-CONFIG-SCHEMA-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "config_rejects_schema_drift_and_incomplete_catalog", anti_vacuity = "ci_slo_config_is_complete_and_has_expected_limits" }.
//! INVARIANT: CI-SLO-EVALUATION-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "ci_slo_rejects_incomplete_evidence", anti_vacuity = "ci_slo_accepts_complete_evidence_and_renders_golden" }.

use crate::ci_lanes::CiJobKey;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CONFIG_SCHEMA_VERSION: u8 = 2;
const EVIDENCE_SCHEMA_VERSION: u8 = 3;
const GIB: u64 = 1024 * 1024 * 1024;
const MAX_JSON_INTEGER: u64 = (1_u64 << 53) - 1;
const MAX_ARTIFACT_FILES: usize = 512;
const MAX_ARTIFACT_DEPTH: usize = 2;
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UploadOutcome {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

impl FromStr for UploadOutcome {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "cancelled" => Ok(Self::Cancelled),
            "skipped" => Ok(Self::Skipped),
            _ => bail!("invalid upload outcome"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SummaryMode {
    Stdout,
    Github,
}

impl Verdict {
    const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Fail => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationalErrorKind {
    Identity,
    Config,
    Evidence,
    Artifact,
    Summary,
}

impl OperationalErrorKind {
    #[cfg(test)]
    const ALL: [Self; 5] = [
        Self::Identity,
        Self::Config,
        Self::Evidence,
        Self::Artifact,
        Self::Summary,
    ];

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Identity => "CI-SLO-IDENTITY",
            Self::Config => "CI-SLO-CONFIG",
            Self::Evidence => "CI-SLO-EVIDENCE",
            Self::Artifact => "CI-SLO-ARTIFACT",
            Self::Summary => "CI-SLO-SUMMARY",
        }
    }

    pub(crate) const fn category(self) -> &'static str {
        match self {
            Self::Identity => "run-identity",
            Self::Config => "configuration",
            Self::Evidence => "evidence",
            Self::Artifact => "staged-artifact",
            Self::Summary => "job-summary",
        }
    }

    pub(crate) const fn action(self) -> &'static str {
        match self {
            Self::Identity => "Check the evaluator run ID and attempt arguments.",
            Self::Config => "Restore .config/ci-slo.toml schema v2 and rerun.",
            Self::Evidence => "Inspect the uploaded evidence artifact and rerun the producer.",
            Self::Artifact => "Inspect target/job-evidence for the closed regular-file layout.",
            Self::Summary => "Restore the GitHub Job Summary file channel and rerun.",
        }
    }
}

#[derive(Debug)]
pub(crate) struct OperationalFailure {
    kind: OperationalErrorKind,
    source: anyhow::Error,
}

impl OperationalFailure {
    pub(crate) fn new(kind: OperationalErrorKind, source: anyhow::Error) -> Self {
        Self { kind, source }
    }

    pub(crate) const fn kind(&self) -> OperationalErrorKind {
        self.kind
    }
}

impl std::fmt::Display for OperationalFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {:#}", self.kind.code(), self.source)
    }
}

impl std::error::Error for OperationalFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Metric {
    Duration,
    DiskFree,
    Target,
    DownloadCache,
    ToolCache,
    Artifact,
}

impl Metric {
    const ALL: [Self; 6] = [
        Self::Duration,
        Self::DiskFree,
        Self::Target,
        Self::DownloadCache,
        Self::ToolCache,
        Self::Artifact,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Duration => "duration",
            Self::DiskFree => "disk-free",
            Self::Target => "target",
            Self::DownloadCache => "download-cache",
            Self::ToolCache => "tool-cache",
            Self::Artifact => "artifact",
        }
    }

    const fn unit(self) -> &'static str {
        match self {
            Self::Duration => "seconds",
            _ => "bytes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
struct PositiveBudget(u64);

impl PositiveBudget {
    fn get(self, field: &str) -> Result<u64> {
        if self.0 == 0 || self.0 > MAX_JSON_INTEGER {
            bail!("{field} must be a positive safe integer");
        }
        Ok(self.0)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigWire {
    schema_version: u8,
    limits: LimitsWire,
    duration_budgets: Vec<DurationBudgetWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsWire {
    min_disk_free_gib: PositiveBudget,
    max_target_gib: PositiveBudget,
    max_download_cache_gib: PositiveBudget,
    max_tool_cache_gib: PositiveBudget,
    max_artifact_gib: PositiveBudget,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurationBudgetWire {
    job: CiJobKey,
    max_duration_seconds: PositiveBudget,
}

#[derive(Debug)]
pub(crate) struct Config {
    limits: Limits,
    durations: BTreeMap<CiJobKey, u64>,
}

#[derive(Debug)]
struct Limits {
    min_disk_free_bytes: u64,
    max_target_bytes: u64,
    max_download_cache_bytes: u64,
    max_tool_cache_bytes: u64,
    max_artifact_bytes: u64,
}

impl Config {
    pub(crate) fn parse(source: &str) -> Result<Self> {
        let wire: ConfigWire = toml::from_str(source).context("invalid CI SLO config")?;
        if wire.schema_version != CONFIG_SCHEMA_VERSION {
            bail!("unsupported CI SLO config schema");
        }
        let min_disk_free_gib = wire.limits.min_disk_free_gib.get("min_disk_free_gib")?;
        let limits = Limits {
            min_disk_free_bytes: gib_to_bytes(min_disk_free_gib, "min_disk_free_gib")?,
            max_target_bytes: gib_to_bytes(
                wire.limits.max_target_gib.get("max_target_gib")?,
                "max_target_gib",
            )?,
            max_download_cache_bytes: gib_to_bytes(
                wire.limits
                    .max_download_cache_gib
                    .get("max_download_cache_gib")?,
                "max_download_cache_gib",
            )?,
            max_tool_cache_bytes: gib_to_bytes(
                wire.limits.max_tool_cache_gib.get("max_tool_cache_gib")?,
                "max_tool_cache_gib",
            )?,
            max_artifact_bytes: gib_to_bytes(
                wire.limits.max_artifact_gib.get("max_artifact_gib")?,
                "max_artifact_gib",
            )?,
        };
        let mut durations = BTreeMap::new();
        for entry in wire.duration_budgets {
            let seconds = entry.max_duration_seconds.get("max_duration_seconds")?;
            if durations.insert(entry.job, seconds).is_some() {
                bail!("duplicate CI SLO duration job");
            }
        }
        let configured = durations.keys().copied().collect::<Vec<_>>();
        if configured != CiJobKey::ALL {
            bail!("CI SLO duration jobs must exactly cover the closed job catalog");
        }
        Ok(Self { limits, durations })
    }

    fn duration_seconds(&self, job: CiJobKey) -> u64 {
        self.durations[&job]
    }

    #[cfg(test)]
    fn duration_budget_count(&self) -> usize {
        self.durations.len()
    }

    #[cfg(test)]
    const fn limits_gib(&self) -> [u64; 5] {
        [
            self.limits.min_disk_free_bytes / GIB,
            self.limits.max_target_bytes / GIB,
            self.limits.max_download_cache_bytes / GIB,
            self.limits.max_tool_cache_bytes / GIB,
            self.limits.max_artifact_bytes / GIB,
        ]
    }
}

fn gib_to_bytes(value: u64, label: &str) -> Result<u64> {
    value
        .checked_mul(GIB)
        .filter(|bytes| *bytes <= MAX_JSON_INTEGER)
        .with_context(|| format!("{label} exceeds safe byte range"))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceWire {
    schema_version: u8,
    job: EvidenceJob,
    snapshots: Vec<Snapshot>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceJob {
    repository: String,
    workflow: String,
    job: String,
    run_id: String,
    run_attempt: String,
    runner_os: String,
    runner_arch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum EvidenceStage {
    #[serde(rename = "start")]
    Start,
    #[serde(rename = "after-cache")]
    AfterCache,
    #[serde(rename = "after-build")]
    AfterBuild,
    #[serde(rename = "before-save")]
    BeforeSave,
    #[serde(rename = "after-save")]
    AfterSave,
}

impl EvidenceStage {
    const ALL: [Self; 5] = [
        Self::Start,
        Self::AfterCache,
        Self::AfterBuild,
        Self::BeforeSave,
        Self::AfterSave,
    ];
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Snapshot {
    stage: EvidenceStage,
    outcome: Option<JobOutcome>,
    recorded_at: String,
    filesystem: Filesystem,
    directories: Vec<DirectorySize>,
    largest_directories: Vec<LargestDirectory>,
    cache: CacheEvidence,
    resource_usage: ResourceUsage,
    tool_versions: ToolVersions,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JobOutcome {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Filesystem {
    capacity_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DirectoryKind {
    Workspace,
    Target,
    Sccache,
    CargoRegistry,
    CargoGit,
    Rustup,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DirectorySize {
    path: DirectoryKind,
    size_bytes: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LargestDirectory {
    path: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheEvidence {
    compiler_cache: CompilerCache,
    download: CacheSize,
    tools: CacheSize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerCache {
    enabled: bool,
    version: Option<String>,
    access: CompilerCacheAccess,
    requests: u64,
    hits: u64,
    misses: u64,
    non_cacheable: u64,
    errors: CompilerCacheErrors,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompilerCacheErrors {
    restore: u64,
    stats: u64,
    cache_io: u64,
    no_requests: u64,
    measure: u64,
    save: u64,
}

impl CompilerCacheErrors {
    const fn total(self) -> u64 {
        self.restore + self.stats + self.cache_io + self.no_requests + self.measure + self.save
    }

    fn merge_max(self, other: Self) -> Self {
        Self {
            restore: self.restore.max(other.restore),
            stats: self.stats.max(other.stats),
            cache_io: self.cache_io.max(other.cache_io),
            no_requests: self.no_requests.max(other.no_requests),
            measure: self.measure.max(other.measure),
            save: self.save.max(other.save),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CompilerCacheAccess {
    Disabled,
    Local,
    RemoteReadOnly,
    RemoteReadWrite,
}

impl CompilerCacheAccess {
    const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Local => "local",
            Self::RemoteReadOnly => "remote-read-only",
            Self::RemoteReadWrite => "remote-read-write",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceUsage {
    cpu_time_ms: Option<u64>,
    peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct CompilerCacheDiagnostics {
    enabled: bool,
    access: CompilerCacheAccess,
    requests: u64,
    hits: u64,
    misses: u64,
    non_cacheable: u64,
    errors: CompilerCacheErrors,
}

impl CompilerCacheDiagnostics {
    const DISABLED: Self = Self {
        enabled: false,
        access: CompilerCacheAccess::Disabled,
        requests: 0,
        hits: 0,
        misses: 0,
        non_cacheable: 0,
        errors: CompilerCacheErrors {
            restore: 0,
            stats: 0,
            cache_io: 0,
            no_requests: 0,
            measure: 0,
            save: 0,
        },
    };

    const fn degraded(self) -> bool {
        self.errors.total() > 0
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CacheSize {
    restore_result: RestoreResult,
    restored_footprint_bytes: u64,
    save_mode: SaveMode,
    candidate_size_bytes: u64,
    save_outcome: SaveOutcome,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum RestoreResult {
    NotAttempted,
    Exact,
    Prefix,
    Miss,
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SaveMode {
    Writer,
    ReadOnly,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SaveOutcome {
    Unknown,
    Ineligible,
    Eligible,
    Skipped,
    AttemptedSuccess,
    AttemptedFailure,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolVersions {
    rustc: Option<String>,
    cargo: Option<String>,
    git: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Evidence {
    identity: RunIdentity,
    duration_seconds: u64,
    disk_free_bytes: u64,
    target_bytes: u64,
    download_cache_bytes: u64,
    tool_cache_bytes: u64,
    compiler_cache: CompilerCacheDiagnostics,
    resource_usage: ResourceUsage,
}

#[derive(Debug, Clone, Copy)]
struct RunIdentity {
    run_id: u64,
    run_attempt: u64,
}

impl RunIdentity {
    fn parse(run_id: &str, run_attempt: &str) -> Result<Self> {
        Ok(Self {
            run_id: parse_decimal_identity(run_id, "run id")?,
            run_attempt: parse_decimal_identity(run_attempt, "run attempt")?,
        })
    }
}

impl Evidence {
    #[cfg(test)]
    pub(crate) fn parse(source: &str, run_id: &str, run_attempt: &str) -> Result<Self> {
        let identity = RunIdentity::parse(run_id, run_attempt)?;
        Self::parse_with_identity(source, run_id, run_attempt, identity)
    }

    fn parse_with_identity(
        source: &str,
        run_id: &str,
        run_attempt: &str,
        identity: RunIdentity,
    ) -> Result<Self> {
        let wire: EvidenceWire = serde_json::from_str(source).context("invalid CI evidence")?;
        if wire.schema_version != EVIDENCE_SCHEMA_VERSION {
            bail!("unsupported CI evidence schema");
        }
        if wire.job.run_id != run_id || wire.job.run_attempt != run_attempt {
            bail!("CI evidence run identity mismatch");
        }
        validate_job_metadata(&wire.job)?;
        if wire.snapshots.len() != EvidenceStage::ALL.len() {
            bail!("CI evidence must contain exactly five snapshots");
        }

        let mut times = Vec::with_capacity(wire.snapshots.len());
        let mut disk_free_bytes = u64::MAX;
        let mut target_bytes = 0;
        let mut download_cache_bytes = 0;
        let mut tool_cache_bytes = 0;
        let mut compiler_cache_errors = CompilerCacheErrors::default();
        for (snapshot, expected_stage) in wire.snapshots.iter().zip(EvidenceStage::ALL) {
            if snapshot.stage != expected_stage {
                bail!("CI evidence stages are incomplete or out of order");
            }
            validate_snapshot_shape(snapshot)?;
            let timestamp = parse_timestamp(&snapshot.recorded_at)?;
            if times.last().is_some_and(|previous| *previous > timestamp) {
                bail!("CI evidence timestamps are not monotonic");
            }
            times.push(timestamp);
            disk_free_bytes = disk_free_bytes.min(snapshot.filesystem.available_bytes);
            let target = snapshot
                .directories
                .iter()
                .find(|entry| entry.path == DirectoryKind::Target)
                .context("CI evidence target measurement missing")?
                .size_bytes
                .context("CI evidence target measurement unavailable")?;
            target_bytes = target_bytes.max(target);
            download_cache_bytes =
                download_cache_bytes.max(cache_actual(&snapshot.cache.download)?);
            tool_cache_bytes = tool_cache_bytes.max(cache_actual(&snapshot.cache.tools)?);
            compiler_cache_errors =
                compiler_cache_errors.merge_max(snapshot.cache.compiler_cache.errors);
        }
        let duration = times[4] - times[0];
        let duration_seconds =
            u64::try_from(duration.whole_seconds()).context("CI evidence duration is negative")?;
        let final_snapshot = wire
            .snapshots
            .last()
            .context("CI evidence final snapshot missing")?;
        let final_cache = &final_snapshot.cache.compiler_cache;
        Ok(Self {
            identity,
            duration_seconds,
            disk_free_bytes,
            target_bytes,
            download_cache_bytes,
            tool_cache_bytes,
            compiler_cache: CompilerCacheDiagnostics {
                enabled: final_cache.enabled,
                access: final_cache.access,
                requests: final_cache.requests,
                hits: final_cache.hits,
                misses: final_cache.misses,
                non_cacheable: final_cache.non_cacheable,
                errors: compiler_cache_errors,
            },
            resource_usage: final_snapshot.resource_usage,
        })
    }
}

fn parse_decimal_identity(value: &str, label: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{label} must be decimal");
    }
    let parsed = value
        .parse::<u64>()
        .with_context(|| format!("{label} is out of range"))?;
    if parsed == 0 {
        bail!("{label} must be positive");
    }
    Ok(parsed)
}

fn validate_job_metadata(job: &EvidenceJob) -> Result<()> {
    for value in [
        &job.repository,
        &job.workflow,
        &job.job,
        &job.runner_os,
        &job.runner_arch,
    ] {
        if value.len() > 1024 || value.chars().any(char::is_control) {
            bail!("CI evidence job metadata is invalid");
        }
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime> {
    let bytes = value.as_bytes();
    let punctuation = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if bytes.len() != 20
        || punctuation
            .iter()
            .any(|(index, expected)| bytes[*index] != *expected)
        || bytes.iter().enumerate().any(|(index, byte)| {
            !punctuation.iter().any(|(position, _)| *position == index) && !byte.is_ascii_digit()
        })
    {
        bail!("CI evidence timestamp must use whole-second UTC Z form");
    }
    OffsetDateTime::parse(value, &Rfc3339).context("invalid CI evidence timestamp")
}

fn validate_snapshot_shape(snapshot: &Snapshot) -> Result<()> {
    for value in [
        snapshot.filesystem.capacity_bytes,
        snapshot.filesystem.used_bytes,
        snapshot.filesystem.available_bytes,
    ] {
        validate_safe_integer(value)?;
    }
    let accounted_bytes = snapshot
        .filesystem
        .used_bytes
        .checked_add(snapshot.filesystem.available_bytes)
        .context("CI evidence filesystem byte accounting overflow")?;
    if accounted_bytes > snapshot.filesystem.capacity_bytes {
        bail!("CI evidence filesystem byte accounting exceeds capacity");
    }
    let expected = [
        DirectoryKind::Workspace,
        DirectoryKind::Target,
        DirectoryKind::Sccache,
        DirectoryKind::CargoRegistry,
        DirectoryKind::CargoGit,
        DirectoryKind::Rustup,
    ];
    if snapshot.directories.len() != expected.len()
        || !snapshot
            .directories
            .iter()
            .zip(expected)
            .all(|(entry, expected)| entry.path == expected)
    {
        bail!("CI evidence directories are incomplete or out of order");
    }
    for entry in &snapshot.directories {
        if let Some(value) = entry.size_bytes {
            validate_safe_integer(value)?;
        }
    }
    if snapshot.largest_directories.len() > 20 {
        bail!("CI evidence largest directory list is oversized");
    }
    for entry in &snapshot.largest_directories {
        validate_safe_integer(entry.size_bytes)?;
        if !(entry.path.starts_with("workspace/") || entry.path.starts_with("target/"))
            || entry.path.contains("//")
            || entry.path.chars().any(char::is_control)
        {
            bail!("CI evidence largest directory path is invalid");
        }
    }
    validate_compiler_cache(&snapshot.cache.compiler_cache)?;
    for value in [
        snapshot.resource_usage.cpu_time_ms,
        snapshot.resource_usage.peak_rss_bytes,
    ]
    .into_iter()
    .flatten()
    {
        validate_safe_integer(value)?;
    }
    if !snapshot.errors.is_empty() {
        bail!("CI evidence contains collection errors");
    }
    match snapshot.stage {
        EvidenceStage::AfterBuild => {}
        _ if snapshot.outcome.is_some() => bail!("CI evidence outcome is only valid after build"),
        _ => {}
    }
    for version in [
        &snapshot.tool_versions.rustc,
        &snapshot.tool_versions.cargo,
        &snapshot.tool_versions.git,
    ]
    .into_iter()
    .flatten()
    {
        if version.len() > 1024 || version.chars().any(char::is_control) {
            bail!("CI evidence tool version is invalid");
        }
    }
    Ok(())
}

fn validate_compiler_cache(cache: &CompilerCache) -> Result<()> {
    for value in [
        cache.requests,
        cache.hits,
        cache.misses,
        cache.non_cacheable,
        cache.errors.restore,
        cache.errors.stats,
        cache.errors.cache_io,
        cache.errors.no_requests,
        cache.errors.measure,
        cache.errors.save,
    ] {
        validate_safe_integer(value)?;
    }
    if cache.hits.saturating_add(cache.misses) > cache.requests {
        bail!("CI evidence compiler cache counts exceed requests");
    }
    match (cache.enabled, cache.version.as_deref(), cache.access) {
        (false, None, CompilerCacheAccess::Disabled) => {}
        (
            true,
            Some("0.15.0"),
            CompilerCacheAccess::Local
            | CompilerCacheAccess::RemoteReadOnly
            | CompilerCacheAccess::RemoteReadWrite,
        ) => {}
        _ => bail!("CI evidence compiler cache identity is invalid"),
    }
    Ok(())
}

fn cache_actual(cache: &CacheSize) -> Result<u64> {
    let _ = (&cache.restore_result, &cache.save_mode, &cache.save_outcome);
    validate_safe_integer(cache.restored_footprint_bytes)?;
    validate_safe_integer(cache.candidate_size_bytes)?;
    Ok(cache
        .restored_footprint_bytes
        .max(cache.candidate_size_bytes))
}

fn validate_safe_integer(value: u64) -> Result<()> {
    if value > MAX_JSON_INTEGER {
        bail!("CI evidence integer exceeds the JSON safe range");
    }
    Ok(())
}

#[derive(Debug)]
struct MetricResult {
    metric: Metric,
    actual: u64,
    budget: u64,
    verdict: Verdict,
}

#[derive(Debug)]
pub(crate) struct Evaluation {
    job: CiJobKey,
    identity: RunIdentity,
    metrics: Vec<MetricResult>,
    compiler_cache: CompilerCacheDiagnostics,
    resource_usage: ResourceUsage,
    verdict: Verdict,
}

impl Evaluation {
    pub(crate) const fn verdict(&self) -> Verdict {
        self.verdict
    }
}

pub(crate) fn evaluate(
    config: &Config,
    job: CiJobKey,
    evidence: &Evidence,
    artifact_root: &Path,
) -> Result<Evaluation> {
    let artifact_bytes = measure_artifact(artifact_root)?;
    let metrics = Metric::ALL
        .into_iter()
        .map(|metric| {
            let actual = match metric {
                Metric::Duration => evidence.duration_seconds,
                Metric::DiskFree => evidence.disk_free_bytes,
                Metric::Target => evidence.target_bytes,
                Metric::DownloadCache => evidence.download_cache_bytes,
                Metric::ToolCache => evidence.tool_cache_bytes,
                Metric::Artifact => artifact_bytes,
            };
            let budget = match metric {
                Metric::Duration => config.duration_seconds(job),
                Metric::DiskFree => config.limits.min_disk_free_bytes,
                Metric::Target => config.limits.max_target_bytes,
                Metric::DownloadCache => config.limits.max_download_cache_bytes,
                Metric::ToolCache => config.limits.max_tool_cache_bytes,
                Metric::Artifact => config.limits.max_artifact_bytes,
            };
            let violated = match metric {
                Metric::DiskFree => actual < budget,
                _ => actual > budget,
            };
            let verdict = if !violated {
                Verdict::Pass
            } else if metric == Metric::DiskFree {
                Verdict::Fail
            } else {
                Verdict::Warn
            };
            MetricResult {
                metric,
                actual,
                budget,
                verdict,
            }
        })
        .collect::<Vec<_>>();
    let mut verdict = metrics
        .iter()
        .map(|result| result.verdict)
        .max_by_key(|verdict| verdict.rank())
        .unwrap_or(Verdict::Fail);
    if evidence.compiler_cache.degraded() && verdict.rank() < Verdict::Warn.rank() {
        verdict = Verdict::Warn;
    }
    Ok(Evaluation {
        job,
        identity: evidence.identity,
        metrics,
        compiler_cache: evidence.compiler_cache,
        resource_usage: evidence.resource_usage,
        verdict,
    })
}

fn measure_artifact(root: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(root).context("staged artifact is missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("staged artifact root must be a regular directory");
    }
    let mut files = 0;
    let mut total = 0;
    measure_directory(root, 0, true, &mut files, &mut total)?;
    Ok(total)
}

fn measure_directory(
    directory: &Path,
    depth: usize,
    top_level: bool,
    files: &mut usize,
    total: &mut u64,
) -> Result<()> {
    if depth > MAX_ARTIFACT_DEPTH {
        bail!("staged artifact depth exceeds the closed limit");
    }
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("staged artifact name is not UTF-8"))?;
        if name.is_empty() || name.chars().any(char::is_control) {
            bail!("staged artifact name is invalid");
        }
        if top_level && !matches!(name.as_str(), "ci" | "integration" | "nextest") {
            bail!("staged artifact top-level entry is outside the closed layout");
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("staged artifact symlinks are forbidden");
        }
        if top_level && !metadata.is_dir() {
            bail!("staged artifact top-level entries must be directories");
        }
        if metadata.is_dir() {
            measure_directory(&path, depth + 1, false, files, total)?;
        } else if metadata.is_file() {
            *files = files
                .checked_add(1)
                .context("artifact file count overflow")?;
            if *files > MAX_ARTIFACT_FILES {
                bail!("staged artifact file count exceeds the closed limit");
            }
            validate_safe_integer(metadata.len())?;
            *total = total
                .checked_add(metadata.len())
                .context("staged artifact size overflow")?;
            validate_safe_integer(*total)?;
        } else {
            bail!("staged artifact only permits regular files and directories");
        }
    }
    Ok(())
}

pub(crate) fn render_markdown(evaluation: &Evaluation, upload: UploadOutcome) -> String {
    let artifact = if upload == UploadOutcome::Success {
        format!("`{}`", artifact_name(evaluation))
    } else {
        "unavailable".to_owned()
    };
    let mut output = format!(
        "## CI SLO: {}\n\nJob: `{}`\n\nEvidence artifact: {}\n\n| Metric | Budget | Actual | Verdict |\n|---|---:|---:|---|\n",
        evaluation.verdict.label(),
        evaluation.job,
        artifact
    );
    for result in &evaluation.metrics {
        output.push_str(&format!(
            "| {} | {} {} | {} {} | {} |\n",
            result.metric.label(),
            result.budget,
            result.metric.unit(),
            result.actual,
            result.metric.unit(),
            result.verdict.label()
        ));
    }
    let cache = evaluation.compiler_cache;
    let cache_status = if !cache.enabled {
        "DISABLED"
    } else if cache.degraded() {
        "DEGRADED"
    } else {
        "HEALTHY"
    };
    let optional = |value: Option<u64>, unit: &str| {
        value.map_or_else(
            || "unavailable".to_owned(),
            |value| format!("{value} {unit}"),
        )
    };
    output.push_str(&format!(
        "\n### Compiler cache: {cache_status}\n\nAccess: `{}`\n\nRequests: {}; hits: {}; misses: {}; non-cacheable: {}.\n\nErrors: restore={}; stats={}; cache-io={}; no-requests={}; measure={}; save={}.\n\nCPU time: {}; peak RSS: {}.\n",
        cache.access.label(),
        cache.requests,
        cache.hits,
        cache.misses,
        cache.non_cacheable,
        cache.errors.restore,
        cache.errors.stats,
        cache.errors.cache_io,
        cache.errors.no_requests,
        cache.errors.measure,
        cache.errors.save,
        optional(evaluation.resource_usage.cpu_time_ms, "ms"),
        optional(evaluation.resource_usage.peak_rss_bytes, "bytes"),
    ));
    output
}

pub(crate) fn render_workflow_annotations(evaluation: &Evaluation) -> String {
    let mut output: String = evaluation
        .metrics
        .iter()
        .filter(|result| result.verdict == Verdict::Warn)
        .map(|result| {
            format!(
                "::warning title=CI SLO budget::metric={} actual={} budget={} unit={}\n",
                result.metric.label(),
                result.actual,
                result.budget,
                result.metric.unit()
            )
        })
        .collect();
    let errors = evaluation.compiler_cache.errors;
    if evaluation.compiler_cache.degraded() {
        output.push_str(&format!(
            "::warning title=CI compiler cache degraded::restore={} stats={} cacheIo={} noRequests={} measure={} save={}\n",
            errors.restore,
            errors.stats,
            errors.cache_io,
            errors.no_requests,
            errors.measure,
            errors.save,
        ));
    }
    output
}

#[derive(Debug, PartialEq, Eq)]
struct OutputPayload {
    stdout: String,
    summary: String,
}

fn route_success(
    evaluation: &Evaluation,
    upload: UploadOutcome,
    mode: SummaryMode,
) -> OutputPayload {
    let markdown = render_markdown(evaluation, upload);
    match mode {
        SummaryMode::Stdout => OutputPayload {
            stdout: markdown,
            summary: String::new(),
        },
        SummaryMode::Github => OutputPayload {
            stdout: render_workflow_annotations(evaluation),
            summary: markdown,
        },
    }
}

fn route_summary(summary: &str, mode: SummaryMode) -> OutputPayload {
    match mode {
        SummaryMode::Stdout => OutputPayload {
            stdout: format!("{summary}\n"),
            summary: String::new(),
        },
        SummaryMode::Github => OutputPayload {
            stdout: String::new(),
            summary: format!("{summary}\n"),
        },
    }
}

fn write_output(payload: OutputPayload, mode: SummaryMode) -> Result<()> {
    if !payload.stdout.is_empty() {
        io::stdout()
            .lock()
            .write_all(payload.stdout.as_bytes())
            .context("cannot write CI SLO stdout")?;
    }
    if mode == SummaryMode::Github {
        let path = std::env::var_os("GITHUB_STEP_SUMMARY")
            .filter(|value| !value.is_empty())
            .context("GITHUB_STEP_SUMMARY is unavailable")?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .context("cannot open GITHUB_STEP_SUMMARY")?;
        file.write_all(payload.summary.as_bytes())
            .context("cannot write GITHUB_STEP_SUMMARY")?;
    }
    Ok(())
}

pub(crate) fn emit_summary(
    summary: &str,
    mode: SummaryMode,
) -> std::result::Result<(), OperationalFailure> {
    write_output(route_summary(summary, mode), mode)
        .map_err(|source| OperationalFailure::new(OperationalErrorKind::Summary, source))
}

pub(crate) fn render_operational_error(
    job: CiJobKey,
    run_id: &str,
    run_attempt: &str,
    upload: UploadOutcome,
    kind: OperationalErrorKind,
) -> String {
    let artifact = if upload == UploadOutcome::Success {
        RunIdentity::parse(run_id, run_attempt)
            .map(|identity| {
                artifact_name(&Evaluation {
                    job,
                    identity,
                    metrics: Vec::new(),
                    compiler_cache: CompilerCacheDiagnostics::DISABLED,
                    resource_usage: ResourceUsage {
                        cpu_time_ms: None,
                        peak_rss_bytes: None,
                    },
                    verdict: Verdict::Fail,
                })
            })
            .map_or_else(|_| "unavailable".to_owned(), |name| format!("`{name}`"))
    } else {
        "unavailable".to_owned()
    };
    format!(
        "## CI SLO: ERROR\n\nJob: `{job}`\n\nEvidence artifact: {artifact}\n\nError code: `{}`\n\nCategory: `{}`\n\nAction: {}",
        kind.code(),
        kind.category(),
        kind.action()
    )
}

fn artifact_name(evaluation: &Evaluation) -> String {
    let (lane, shard, partition) = artifact_parts(evaluation.job);
    format!(
        "ci-evidence-{lane}-{shard}-{partition}-{}-{}",
        evaluation.identity.run_id, evaluation.identity.run_attempt
    )
}

fn artifact_parts(job: CiJobKey) -> (&'static str, &'static str, &'static str) {
    job.artifact_parts()
}

#[cfg(test)]
pub(crate) fn run(
    workspace: &Path,
    job: CiJobKey,
    run_id: &str,
    run_attempt: &str,
    upload: UploadOutcome,
) -> std::result::Result<Verdict, OperationalFailure> {
    run_with_mode(
        workspace,
        job,
        run_id,
        run_attempt,
        upload,
        SummaryMode::Stdout,
    )
}

pub(crate) fn run_with_mode(
    workspace: &Path,
    job: CiJobKey,
    run_id: &str,
    run_attempt: &str,
    upload: UploadOutcome,
    summary_mode: SummaryMode,
) -> std::result::Result<Verdict, OperationalFailure> {
    let classify = |kind| move |source| OperationalFailure::new(kind, source);
    let identity = RunIdentity::parse(run_id, run_attempt)
        .map_err(classify(OperationalErrorKind::Identity))?;
    let config = (|| -> Result<Config> {
        let path = ensure_regular_file(
            workspace,
            Path::new(".config/ci-slo.toml"),
            MAX_CONFIG_BYTES,
            "config",
        )?;
        Config::parse(&fs::read_to_string(path)?)
    })()
    .map_err(classify(OperationalErrorKind::Config))?;
    let evidence = (|| -> Result<Evidence> {
        let path = ensure_regular_file(
            workspace,
            Path::new("target/job-evidence/ci/ci-evidence.json"),
            MAX_EVIDENCE_BYTES,
            "evidence",
        )?;
        Evidence::parse_with_identity(&fs::read_to_string(path)?, run_id, run_attempt, identity)
    })()
    .map_err(classify(OperationalErrorKind::Evidence))?;
    let evaluation = evaluate(
        &config,
        job,
        &evidence,
        &workspace.join("target/job-evidence"),
    )
    .map_err(classify(OperationalErrorKind::Artifact))?;
    write_output(
        route_success(&evaluation, upload, summary_mode),
        summary_mode,
    )
    .map_err(classify(OperationalErrorKind::Summary))?;
    Ok(evaluation.verdict())
}

fn ensure_regular_file(
    workspace: &Path,
    relative: &Path,
    max_bytes: u64,
    label: &str,
) -> Result<PathBuf> {
    let mut path = workspace.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(segment) = component else {
            bail!("CI SLO {label} path is invalid");
        };
        path.push(segment);
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("CI SLO {label} is missing"))?;
        if metadata.file_type().is_symlink() {
            bail!("CI SLO {label} path contains a symlink");
        }
        let is_last = index + 1 == components.len();
        if (!is_last && !metadata.is_dir()) || (is_last && !metadata.is_file()) {
            bail!("CI SLO {label} path has an invalid file type");
        }
        if is_last && metadata.len() > max_bytes {
            bail!("CI SLO {label} exceeds the closed size limit");
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    const CONFIG: &str = include_str!("../../.config/ci-slo.toml");

    #[test]
    fn ci_slo_config_is_complete_and_has_expected_limits() -> Result<()> {
        let config = Config::parse(CONFIG)?;
        assert_eq!(config.duration_budget_count(), 14);
        assert_eq!(config.limits_gib(), [5, 6, 8, 2, 1]);
        assert_eq!(config.duration_seconds(CiJobKey::CiMeta), 90);
        assert_eq!(config.duration_seconds(CiJobKey::CiCorePrerequisites), 600);
        assert_eq!(config.duration_seconds(CiJobKey::CiSecurity), 300);
        assert_eq!(config.duration_seconds(CiJobKey::CiCoverage), 480);
        assert_eq!(
            config.duration_seconds(CiJobKey::IntegrationPostgresDomain),
            900
        );
        Ok(())
    }

    #[test]
    fn ci_slo_rejects_incomplete_evidence() -> Result<()> {
        let mut evidence: Value =
            serde_json::from_str(include_str!("../tests/fixtures/ci_slo/pass.json"))?;
        let _ = evidence["snapshots"].as_array_mut().and_then(Vec::pop);
        assert!(Evidence::parse(&serde_json::to_string(&evidence)?, "42", "3").is_err());
        Ok(())
    }

    #[test]
    fn ci_slo_accepts_complete_evidence_and_renders_golden() -> Result<()> {
        let evidence = fixture()?;
        let config = Config::parse(CONFIG)?;
        let root = tempfile_dir("golden");
        fs::create_dir_all(root.join("ci"))?;
        fs::write(root.join("ci/evidence.json"), b"12345678")?;
        let evaluation = evaluate(&config, CiJobKey::CiMeta, &evidence, &root)?;
        assert_eq!(evaluation.verdict(), Verdict::Pass);
        assert_eq!(
            render_markdown(&evaluation, UploadOutcome::Success),
            include_str!("../tests/golden/ci-slo-summary.md")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn compiler_cache_degradation_warns_and_remains_diagnostic() -> Result<()> {
        let mut source: Value =
            serde_json::from_str(include_str!("../tests/fixtures/ci_slo/pass.json"))?;
        source["snapshots"][1]["cache"]["compilerCache"]["errors"]["restore"] = 2.into();
        source["snapshots"][4]["cache"]["compilerCache"]["errors"]["stats"] = 1.into();
        let evidence = Evidence::parse(&serde_json::to_string(&source)?, "42", "3")?;
        let config = Config::parse(CONFIG)?;
        let root = tempfile_dir("compiler-cache-degraded");
        fs::create_dir_all(root.join("ci"))?;
        fs::write(root.join("ci/evidence.json"), b"evidence")?;

        let evaluation = evaluate(&config, CiJobKey::CiMeta, &evidence, &root)?;
        assert_eq!(evaluation.verdict(), Verdict::Warn);
        let summary = render_markdown(&evaluation, UploadOutcome::Success);
        for expected in [
            "### Compiler cache: DEGRADED",
            "Requests: 12; hits: 6; misses: 4; non-cacheable: 2.",
            "Errors: restore=2; stats=1; cache-io=0; no-requests=0; measure=0; save=0.",
            "CPU time: 20000 ms; peak RSS: 104857600 bytes.",
        ] {
            assert!(summary.contains(expected), "missing diagnostic: {expected}");
        }
        assert_eq!(
            render_workflow_annotations(&evaluation),
            "::warning title=CI compiler cache degraded::restore=2 stats=1 cacheIo=0 noRequests=0 measure=0 save=0\n"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn config_rejects_schema_drift_and_incomplete_catalog() {
        for invalid in [
            CONFIG.replacen("schema_version = 2", "schema_version = 3", 1),
            CONFIG.replacen("min_disk_free_gib = 5", "min_disk_free_gib = 0", 1),
            CONFIG.replacen("max_target_gib = 6", "max_target_gib = -1", 1),
            CONFIG.replacen("max_target_gib = 6", "max_target_gib = 1.5", 1),
            CONFIG.replacen("max_target_gib = 6", "max_target_gib = 6\nextra = 1", 1),
            CONFIG.replacen("job = \"audit\"", "job = \"unknown\"", 1),
            CONFIG.replacen(
                "[[duration_budgets]]\njob = \"audit\"\nmax_duration_seconds = 300\n",
                "",
                1,
            ),
            CONFIG.replacen("job = \"audit\"", "job = \"ci-meta\"", 1),
        ] {
            assert!(Config::parse(&invalid).is_err());
        }
    }

    #[test]
    fn config_is_the_runtime_disk_threshold_source() -> Result<()> {
        let changed = CONFIG.replacen("min_disk_free_gib = 5", "min_disk_free_gib = 9", 1);
        let config = Config::parse(&changed)?;
        assert_eq!(config.limits.min_disk_free_bytes, 9 * GIB);
        Ok(())
    }

    #[test]
    fn evaluation_table_covers_warn_fail_and_equal_boundaries() -> Result<()> {
        let config = Config::parse(CONFIG)?;
        let root = tempfile_dir("verdicts");
        fs::create_dir_all(root.join("ci"))?;
        fs::write(root.join("ci/evidence.json"), b"evidence")?;
        let baseline = fixture()?;

        let mut equal = Evidence { ..baseline };
        equal.duration_seconds = 90;
        equal.disk_free_bytes = 5 * GIB;
        equal.target_bytes = 6 * GIB;
        equal.download_cache_bytes = 8 * GIB;
        equal.tool_cache_bytes = 2 * GIB;
        assert_eq!(
            evaluate(&config, CiJobKey::CiMeta, &equal, &root)?.verdict(),
            Verdict::Pass
        );

        for metric in [
            Metric::Duration,
            Metric::Target,
            Metric::DownloadCache,
            Metric::ToolCache,
        ] {
            let mut evidence = Evidence { ..equal };
            match metric {
                Metric::Duration => evidence.duration_seconds += 1,
                Metric::Target => evidence.target_bytes += 1,
                Metric::DownloadCache => evidence.download_cache_bytes += 1,
                Metric::ToolCache => evidence.tool_cache_bytes += 1,
                Metric::DiskFree | Metric::Artifact => continue,
            }
            assert_eq!(
                evaluate(&config, CiJobKey::CiMeta, &evidence, &root)?.verdict(),
                Verdict::Warn
            );
        }
        let low_disk = Evidence {
            disk_free_bytes: 5 * GIB - 1,
            target_bytes: 6 * GIB + 1,
            ..equal
        };
        assert_eq!(
            evaluate(&config, CiJobKey::CiMeta, &low_disk, &root)?.verdict(),
            Verdict::Fail
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workflow_annotations_are_closed_for_advisory_metrics() {
        let evaluation = Evaluation {
            job: CiJobKey::CiMeta,
            identity: RunIdentity {
                run_id: 42,
                run_attempt: 3,
            },
            metrics: vec![
                MetricResult {
                    metric: Metric::Duration,
                    actual: 91,
                    budget: 90,
                    verdict: Verdict::Warn,
                },
                MetricResult {
                    metric: Metric::Target,
                    actual: 7,
                    budget: 6,
                    verdict: Verdict::Warn,
                },
                MetricResult {
                    metric: Metric::DownloadCache,
                    actual: 9,
                    budget: 8,
                    verdict: Verdict::Warn,
                },
                MetricResult {
                    metric: Metric::ToolCache,
                    actual: 3,
                    budget: 2,
                    verdict: Verdict::Warn,
                },
                MetricResult {
                    metric: Metric::Artifact,
                    actual: 2,
                    budget: 1,
                    verdict: Verdict::Warn,
                },
            ],
            compiler_cache: CompilerCacheDiagnostics::DISABLED,
            resource_usage: ResourceUsage {
                cpu_time_ms: None,
                peak_rss_bytes: None,
            },
            verdict: Verdict::Warn,
        };
        assert_eq!(
            render_workflow_annotations(&evaluation),
            concat!(
                "::warning title=CI SLO budget::metric=duration actual=91 budget=90 unit=seconds\n",
                "::warning title=CI SLO budget::metric=target actual=7 budget=6 unit=bytes\n",
                "::warning title=CI SLO budget::metric=download-cache actual=9 budget=8 unit=bytes\n",
                "::warning title=CI SLO budget::metric=tool-cache actual=3 budget=2 unit=bytes\n",
                "::warning title=CI SLO budget::metric=artifact actual=2 budget=1 unit=bytes\n",
            )
        );
        let github = route_success(&evaluation, UploadOutcome::Success, SummaryMode::Github);
        assert_eq!(github.stdout, render_workflow_annotations(&evaluation));
        assert!(!github.stdout.contains("## CI SLO"));
        assert!(github.summary.starts_with("## CI SLO: WARN"));
        assert!(!github.summary.contains("::warning"));

        let local = route_success(&evaluation, UploadOutcome::Success, SummaryMode::Stdout);
        assert!(local.stdout.starts_with("## CI SLO: WARN"));
        assert!(local.summary.is_empty());
    }

    #[test]
    fn operational_summary_routes_to_the_selected_closed_channel() {
        let summary = "## CI SLO: ERROR";
        assert_eq!(
            route_summary(summary, SummaryMode::Github),
            OutputPayload {
                stdout: String::new(),
                summary: format!("{summary}\n"),
            }
        );
        assert_eq!(
            route_summary(summary, SummaryMode::Stdout),
            OutputPayload {
                stdout: format!("{summary}\n"),
                summary: String::new(),
            }
        );
    }

    #[test]
    fn operational_summaries_use_closed_kind_code_and_action() {
        let summaries = OperationalErrorKind::ALL.map(|kind| {
            render_operational_error(CiJobKey::CiMeta, "42", "3", UploadOutcome::Failure, kind)
        });
        for (kind, summary) in OperationalErrorKind::ALL.into_iter().zip(&summaries) {
            assert!(summary.contains(kind.code()));
            assert!(summary.contains(kind.category()));
            assert!(summary.contains(kind.action()));
            assert!(!summary.contains("synthetic secret"));
        }
        let unique = summaries.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), OperationalErrorKind::ALL.len());
    }

    #[test]
    fn artifact_over_budget_warns() -> Result<()> {
        let config = Config::parse(CONFIG)?;
        let evidence = fixture()?;
        let root = tempfile_dir("artifact-warn");
        fs::create_dir_all(root.join("ci"))?;
        let file = fs::File::create(root.join("ci/large.bin"))?;
        file.set_len(GIB + 1)?;
        assert_eq!(
            evaluate(&config, CiJobKey::CiMeta, &evidence, &root)?.verdict(),
            Verdict::Warn
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn evidence_rejects_schema_stage_time_measurement_and_identity_drift() -> Result<()> {
        let source = include_str!("../tests/fixtures/ci_slo/pass.json");
        let mutate = |apply: fn(&mut Value)| -> Result<String> {
            let mut value: Value = serde_json::from_str(source)?;
            apply(&mut value);
            Ok(serde_json::to_string(&value)?)
        };
        let invalid = [
            mutate(|value| value["schemaVersion"] = 2.into())?,
            mutate(|value| value["extra"] = true.into())?,
            mutate(|value| {
                let _ = value["snapshots"].as_array_mut().and_then(Vec::pop);
            })?,
            mutate(|value| value["snapshots"][1]["stage"] = "after-build".into())?,
            mutate(|value| value["snapshots"][2]["recordedAt"] = "not-time".into())?,
            mutate(|value| {
                value["snapshots"][2]["recordedAt"] = "2026-07-12T00:00:30+00:00".into()
            })?,
            mutate(|value| value["snapshots"][2]["recordedAt"] = "2026-07-12T00:00:30.1Z".into())?,
            mutate(|value| value["snapshots"][2]["recordedAt"] = "2026-07-11T00:00:00Z".into())?,
            mutate(|value| value["snapshots"][0]["directories"][1]["sizeBytes"] = Value::Null)?,
            mutate(|value| {
                value["snapshots"][0]["filesystem"]["availableBytes"] =
                    (MAX_JSON_INTEGER + 1).into()
            })?,
            mutate(|value| {
                value["snapshots"][0]["toolVersions"]["cargo"] = "cargo\nsecret".into()
            })?,
            mutate(|value| value["snapshots"][1]["cache"]["compilerCache"]["hits"] = 6.into())?,
            mutate(|value| {
                value["snapshots"][1]["cache"]["compilerCache"]["version"] = "0.14.0".into()
            })?,
            mutate(|value| {
                value["snapshots"][2]["resourceUsage"]["peakRssBytes"] =
                    (MAX_JSON_INTEGER + 1).into()
            })?,
        ];
        for source in invalid {
            assert!(Evidence::parse(&source, "42", "3").is_err());
        }
        for error_class in [
            "restore",
            "stats",
            "cacheIo",
            "noRequests",
            "measure",
            "save",
        ] {
            let mut value: Value = serde_json::from_str(source)?;
            value["snapshots"][4]["cache"]["compilerCache"]["errors"][error_class] =
                (MAX_JSON_INTEGER + 1).into();
            assert!(
                Evidence::parse(&serde_json::to_string(&value)?, "42", "3").is_err(),
                "compiler cache error class must reject unsafe integer: {error_class}"
            );
        }
        for invalid_errors in [
            serde_json::json!(1),
            serde_json::json!({
                "restore": 0,
                "stats": 0,
                "cacheIo": 0,
                "noRequests": 0,
                "measure": 0,
                "save": 0,
                "unknown": 0
            }),
        ] {
            let mut value: Value = serde_json::from_str(source)?;
            value["snapshots"][4]["cache"]["compilerCache"]["errors"] = invalid_errors;
            assert!(Evidence::parse(&serde_json::to_string(&value)?, "42", "3").is_err());
        }
        assert!(Evidence::parse(source, "41", "3").is_err());
        assert!(Evidence::parse(source, "42", "x").is_err());
        Ok(())
    }

    #[test]
    fn evidence_rejects_collection_errors_and_impossible_filesystem() -> Result<()> {
        let source = include_str!("../tests/fixtures/ci_slo/pass.json");
        let mutate = |apply: fn(&mut Value)| -> Result<String> {
            let mut value: Value = serde_json::from_str(source)?;
            apply(&mut value);
            Ok(serde_json::to_string(&value)?)
        };
        let invalid = [
            (
                "collection-errors",
                mutate(|value| {
                    value["snapshots"][0]["errors"] =
                        serde_json::json!(["directory measurement failed: target"])
                })?,
            ),
            (
                "used-exceeds-capacity",
                mutate(|value| {
                    value["snapshots"][0]["filesystem"]["usedBytes"] = (20 * GIB + 1).into()
                })?,
            ),
            (
                "available-exceeds-capacity",
                mutate(|value| {
                    value["snapshots"][0]["filesystem"]["availableBytes"] = (20 * GIB + 1).into()
                })?,
            ),
            (
                "used-plus-available-exceeds-capacity",
                mutate(|value| {
                    value["snapshots"][0]["filesystem"] = serde_json::json!({
                        "capacityBytes": 100,
                        "usedBytes": 60,
                        "availableBytes": 60
                    })
                })?,
            ),
        ];
        let accepted = invalid
            .into_iter()
            .filter_map(|(label, source)| {
                Evidence::parse(&source, "42", "3").is_ok().then_some(label)
            })
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "accepted invalid evidence cases: {}",
            accepted.join(", ")
        );
        Ok(())
    }

    #[test]
    fn artifact_layout_rejects_escape_and_excess() -> Result<()> {
        let root = tempfile_dir("artifact-layout");
        fs::create_dir_all(&root)?;
        fs::write(root.join("ci"), b"not-a-directory")?;
        assert!(measure_artifact(&root).is_err());
        fs::remove_file(root.join("ci"))?;
        fs::create_dir(root.join("other"))?;
        assert!(measure_artifact(&root).is_err());
        fs::remove_dir(root.join("other"))?;
        fs::create_dir(root.join("ci"))?;
        for index in 0..=MAX_ARTIFACT_FILES {
            fs::write(root.join("ci").join(format!("{index}.json")), b"")?;
        }
        assert!(measure_artifact(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn artifact_layout_rejects_symlinks_and_special_files() -> Result<()> {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let root = std::env::temp_dir().join(format!("rs{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("ci"))?;
        symlink("missing", root.join("ci/link"))?;
        assert!(measure_artifact(&root).is_err());
        fs::remove_file(root.join("ci/link"))?;
        let _listener = UnixListener::bind(root.join("ci/socket"))?;
        assert!(measure_artifact(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fixed_input_paths_reject_symlink_ancestors_and_oversize_files() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile_dir("fixed-input");
        fs::create_dir_all(root.join("real-config"))?;
        fs::write(root.join("real-config/ci-slo.toml"), CONFIG)?;
        symlink("real-config", root.join(".config"))?;
        assert!(
            ensure_regular_file(
                &root,
                Path::new(".config/ci-slo.toml"),
                MAX_CONFIG_BYTES,
                "config"
            )
            .is_err()
        );
        fs::remove_file(root.join(".config"))?;
        fs::create_dir(root.join(".config"))?;
        let oversized = fs::File::create(root.join(".config/ci-slo.toml"))?;
        oversized.set_len(MAX_CONFIG_BYTES + 1)?;
        assert!(
            ensure_regular_file(
                &root,
                Path::new(".config/ci-slo.toml"),
                MAX_CONFIG_BYTES,
                "config"
            )
            .is_err()
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn summary_uses_closed_artifact_identity_or_unavailable() {
        let evaluation = Evaluation {
            job: CiJobKey::IntegrationEventTransport1Of2,
            identity: RunIdentity {
                run_id: 42,
                run_attempt: 3,
            },
            metrics: Vec::new(),
            compiler_cache: CompilerCacheDiagnostics::DISABLED,
            resource_usage: ResourceUsage {
                cpu_time_ms: None,
                peak_rss_bytes: None,
            },
            verdict: Verdict::Warn,
        };
        let success = render_markdown(&evaluation, UploadOutcome::Success);
        assert!(success.contains("`ci-evidence-integration-event-transport-1-of-2-42-3`"));
        assert!(render_markdown(&evaluation, UploadOutcome::Failure).contains("unavailable"));
    }

    #[test]
    fn fixed_path_entry_maps_pass_warn_fail_and_operational_error() -> Result<()> {
        let root = tempfile_dir("entry-outcomes");
        fs::create_dir_all(root.join(".config"))?;
        fs::create_dir_all(root.join("target/job-evidence/ci"))?;
        fs::write(root.join(".config/ci-slo.toml"), CONFIG)?;
        let evidence_path = root.join("target/job-evidence/ci/ci-evidence.json");
        let source = include_str!("../tests/fixtures/ci_slo/pass.json");
        fs::write(&evidence_path, source)?;
        assert_eq!(
            run(&root, CiJobKey::CiMeta, "42", "3", UploadOutcome::Success)?,
            Verdict::Pass
        );

        let mut evidence: Value = serde_json::from_str(source)?;
        evidence["snapshots"][4]["directories"][1]["sizeBytes"] = (6 * GIB + 1).into();
        fs::write(&evidence_path, serde_json::to_vec(&evidence)?)?;
        assert_eq!(
            run(&root, CiJobKey::CiMeta, "42", "3", UploadOutcome::Failure)?,
            Verdict::Warn
        );

        evidence["snapshots"][4]["filesystem"]["availableBytes"] = (5 * GIB - 1).into();
        fs::write(&evidence_path, serde_json::to_vec(&evidence)?)?;
        assert_eq!(
            run(&root, CiJobKey::CiMeta, "42", "3", UploadOutcome::Failure)?,
            Verdict::Fail
        );

        fs::remove_file(&evidence_path)?;
        assert!(run(&root, CiJobKey::CiMeta, "42", "3", UploadOutcome::Failure).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn operational_failure_funnel_classifies_pipeline_boundaries() -> Result<()> {
        let kind = |result: std::result::Result<Verdict, OperationalFailure>| match result {
            Ok(verdict) => bail!("expected operational failure, got {verdict:?}"),
            Err(failure) => Ok(failure.kind()),
        };
        let root = tempfile_dir("operational-kinds");
        let _ = fs::remove_dir_all(&root);
        assert_eq!(
            kind(run(
                &root,
                CiJobKey::CiMeta,
                "x",
                "3",
                UploadOutcome::Failure,
            ))?,
            OperationalErrorKind::Identity
        );

        assert_eq!(
            kind(run(
                &root,
                CiJobKey::CiMeta,
                "42",
                "3",
                UploadOutcome::Failure,
            ))?,
            OperationalErrorKind::Config
        );
        fs::create_dir_all(root.join(".config"))?;
        fs::write(root.join(".config/ci-slo.toml"), CONFIG)?;
        assert_eq!(
            kind(run(
                &root,
                CiJobKey::CiMeta,
                "42",
                "3",
                UploadOutcome::Failure,
            ))?,
            OperationalErrorKind::Evidence
        );

        fs::create_dir_all(root.join("target/job-evidence/ci"))?;
        fs::write(
            root.join("target/job-evidence/ci/ci-evidence.json"),
            include_str!("../tests/fixtures/ci_slo/pass.json"),
        )?;
        fs::create_dir(root.join("target/job-evidence/outside"))?;
        assert_eq!(
            kind(run(
                &root,
                CiJobKey::CiMeta,
                "42",
                "3",
                UploadOutcome::Failure,
            ))?,
            OperationalErrorKind::Artifact
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn fixture() -> Result<Evidence> {
        Evidence::parse(
            include_str!("../tests/fixtures/ci_slo/pass.json"),
            "42",
            "3",
        )
    }

    fn tempfile_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rss-ci-slo-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ))
    }
}
