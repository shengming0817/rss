//! Shared, closed parser for CI evidence v4.
//!
use crate::ci_lanes::CiJobKey;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(crate) const SCHEMA_VERSION: u8 = 4;
pub(crate) const MAX_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

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
    ci_job_key: CiJobKey,
    source_revision: String,
    plan_digest: String,
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
pub(crate) struct CompilerCacheErrors {
    pub(crate) restore: u64,
    pub(crate) stats: u64,
    pub(crate) cache_io: u64,
    pub(crate) no_requests: u64,
    pub(crate) measure: u64,
    pub(crate) save: u64,
}

impl CompilerCacheErrors {
    pub(crate) const fn total(self) -> u64 {
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
pub(crate) enum CompilerCacheAccess {
    Disabled,
    Local,
    RemoteReadOnly,
    RemoteReadWrite,
}

impl CompilerCacheAccess {
    pub(crate) const fn label(self) -> &'static str {
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
pub(crate) struct ResourceUsage {
    pub(crate) cpu_time_ms: Option<u64>,
    pub(crate) peak_rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CompilerCacheDiagnostics {
    pub(crate) enabled: bool,
    pub(crate) access: CompilerCacheAccess,
    pub(crate) requests: u64,
    pub(crate) hits: u64,
    pub(crate) misses: u64,
    pub(crate) non_cacheable: u64,
    pub(crate) errors: CompilerCacheErrors,
}

impl CompilerCacheDiagnostics {
    pub(crate) const DISABLED: Self = Self {
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

    pub(crate) const fn degraded(self) -> bool {
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

#[derive(Debug)]
pub(crate) struct ValidatedEvidence {
    pub(crate) job_key: CiJobKey,
    pub(crate) source_revision: String,
    pub(crate) plan_digest: String,
    pub(crate) run_id: String,
    pub(crate) run_attempt: String,
    pub(crate) started_at: String,
    pub(crate) finished_at: String,
    pub(crate) duration_seconds: u64,
    pub(crate) disk_free_bytes: u64,
    pub(crate) target_bytes: u64,
    pub(crate) download_cache_bytes: u64,
    pub(crate) tool_cache_bytes: u64,
    pub(crate) compiler_cache: CompilerCacheDiagnostics,
    pub(crate) resource_usage: ResourceUsage,
}

impl ValidatedEvidence {
    pub(crate) fn parse(source: &str) -> Result<Self> {
        let wire: EvidenceWire = serde_json::from_str(source).context("invalid CI evidence")?;
        if wire.schema_version != SCHEMA_VERSION {
            bail!("unsupported CI evidence schema");
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
        let first_snapshot = wire
            .snapshots
            .first()
            .context("CI evidence first snapshot missing")?;
        let final_snapshot = wire
            .snapshots
            .last()
            .context("CI evidence final snapshot missing")?;
        let final_cache = &final_snapshot.cache.compiler_cache;
        Ok(Self {
            job_key: wire.job.ci_job_key,
            source_revision: wire.job.source_revision,
            plan_digest: wire.job.plan_digest,
            run_id: wire.job.run_id,
            run_attempt: wire.job.run_attempt,
            started_at: first_snapshot.recorded_at.clone(),
            finished_at: final_snapshot.recorded_at.clone(),
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

fn validate_job_metadata(job: &EvidenceJob) -> Result<()> {
    for value in [
        &job.repository,
        &job.workflow,
        &job.job,
        &job.runner_os,
        &job.runner_arch,
    ] {
        if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
            bail!("CI evidence job metadata is invalid");
        }
    }
    if !(job.source_revision.len() == 40 || job.source_revision.len() == 64)
        || !job
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("CI evidence source revision is invalid");
    }
    if job.plan_digest.len() != 64 || !job.plan_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("CI evidence plan digest is invalid");
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
