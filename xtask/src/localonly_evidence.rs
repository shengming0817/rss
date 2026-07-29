//! Typed producer and strict consumer for LocalOnly execution exact-set evidence.
//!
//! INVARIANT: LOCAL-ONLY-EXECUTION-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "LocalOnlyEvidenceRequest::publish requires both the private LocalOnlySuitePassed and VerifiedLocalOnlyExecutionSet capabilities" }.
//! INVARIANT: LOCAL-ONLY-EXECUTION-EXACTSET-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "execution_exact_set_rejects_missing_extra_duplicate_and_equal_count_wrong_set|raw_marker_schema_and_file_boundary_red_matrix|ordinary_file_read_rejects_path_replacement_after_precheck|nextest_failure_after_all_canonical_markers_blocks_publish_and_cleans_raw_directory", anti_vacuity = "real_workspace_execution_inventory_is_exact_and_non_empty" }.
//! INVARIANT: LOCAL-ONLY-EXECUTION-WIRE-01 { level = "Hard", exec = "native-compile", source = "code", native = "the private deny_unknown_fields v1 DTO fixes the report field inventory and closed CiJobKey owner" }.

use crate::ci_lanes::CiJobKey;
use crate::consistency_effects::LocalOnlyExecutionInventory;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const FILE_NAME: &str = "localonly-execution.json";
pub(crate) const OWNER: CiJobKey = CiJobKey::CiLocalOnly;
const SCHEMA_VERSION: u8 = 1;
const MARKER_SCHEMA_VERSION: u8 = 1;
const MAX_REPORT_BYTES: u64 = 64 * 1024;
const MAX_MARKER_BYTES: u64 = 4 * 1024;
static RAW_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportWire {
    schema_version: u8,
    job_key: CiJobKey,
    source_revision: String,
    active_contract_ids: Vec<String>,
    source_receipt_contract_ids: Vec<String>,
    executed_contract_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MarkerWire {
    schema_version: u8,
    contract_id: String,
}

/// Private proof that every typed nextest invocation returned success.
pub(crate) struct LocalOnlySuitePassed(());

/// Private exact-set proof. Construction is confined to [`reconcile_execution_sets`].
pub(crate) struct VerifiedLocalOnlyExecutionSet {
    active_contract_ids: Vec<String>,
    source_receipt_contract_ids: Vec<String>,
    executed_contract_ids: Vec<String>,
}

pub(crate) struct LocalOnlyEvidenceRequest {
    output: PathBuf,
    source_revision: String,
}

pub(crate) fn prepare_request(
    job: CiJobKey,
    output: Option<&Path>,
    root: &Path,
) -> Result<Option<LocalOnlyEvidenceRequest>> {
    prepare_request_with(
        job,
        output,
        root,
        |name| match std::env::var_os(name) {
            None => Ok(None),
            Some(value) => value
                .into_string()
                .map(Some)
                .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8")),
        },
        crate::cmd::source_revision,
    )
}

fn prepare_request_with(
    job: CiJobKey,
    output: Option<&Path>,
    root: &Path,
    mut environment: impl FnMut(&str) -> Result<Option<String>>,
    checkout_revision: impl FnOnce(&Path) -> Result<String>,
) -> Result<Option<LocalOnlyEvidenceRequest>> {
    if job != OWNER {
        return Ok(None);
    }
    if let Some(environment_job) = environment("RSS_CI_JOB_KEY")? {
        let environment_job = environment_job
            .parse::<CiJobKey>()
            .context("invalid RSS_CI_JOB_KEY for LocalOnly evidence")?;
        if environment_job != OWNER {
            bail!("LocalOnly evidence job identity must be {OWNER}");
        }
    }
    let source_revision = checkout_revision(root)?;
    validate_revision(&source_revision)?;
    for carrier in [
        "RSS_CI_SOURCE_REVISION",
        "GITHUB_SHA",
        "BUILD_SOURCEVERSION",
    ] {
        if let Some(claimed_revision) = environment(carrier)? {
            validate_revision(&claimed_revision)
                .with_context(|| format!("{carrier} is not a valid source revision"))?;
            if claimed_revision != source_revision {
                bail!("{carrier} must equal the checked-out git HEAD");
            }
        }
    }
    let output = resolve_output_path(root, output);
    prepare_output_slot(&output)?;
    Ok(Some(LocalOnlyEvidenceRequest {
        output,
        source_revision,
    }))
}

fn resolve_output_path(root: &Path, output: Option<&Path>) -> PathBuf {
    match output {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => root.join(path),
        None => root.join("target/localonly-execution").join(FILE_NAME),
    }
}

pub(crate) fn execute(
    root: &Path,
    request: LocalOnlyEvidenceRequest,
    execution_policy: crate::cmd::ExecutionPolicy,
) -> Result<ValidatedLocalOnlyReport> {
    execute_with_suite_runner(root, request, |root, packages, tests, marker_dir| {
        crate::nextest::run_local_only_exact(root, packages, tests, marker_dir, execution_policy)
    })
}

fn execute_with_suite_runner(
    root: &Path,
    request: LocalOnlyEvidenceRequest,
    suite_runner: impl FnOnce(&Path, &[String], &[String], &Path) -> Result<()>,
) -> Result<ValidatedLocalOnlyReport> {
    let inventory = crate::consistency_effects::local_only_execution_inventory(root)?;
    let packages = inventory
        .tests
        .iter()
        .map(|test| test.package.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let tests = inventory
        .tests
        .iter()
        .map(|test| test.test_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if inventory.tests.iter().any(|test| test.test_target != "lib") {
        bail!("LocalOnly execution inventory contains an unsupported test target");
    }
    let raw_dir = create_raw_directory(&request.output)?;
    let result = (|| {
        suite_runner(root, &packages, &tests, &raw_dir)?;
        let suite = LocalOnlySuitePassed(());
        let executed = load_raw_markers(&raw_dir)?;
        let verified = reconcile_execution_sets(&inventory, executed)?;
        request.publish(suite, verified)
    })();
    let cleanup = fs::remove_dir_all(&raw_dir).context("remove LocalOnly raw marker directory");
    match (result, cleanup) {
        (Ok(report), Ok(())) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

impl LocalOnlyEvidenceRequest {
    fn publish(
        self,
        _suite: LocalOnlySuitePassed,
        verified: VerifiedLocalOnlyExecutionSet,
    ) -> Result<ValidatedLocalOnlyReport> {
        let wire = ReportWire {
            schema_version: SCHEMA_VERSION,
            job_key: OWNER,
            source_revision: self.source_revision,
            active_contract_ids: verified.active_contract_ids,
            source_receipt_contract_ids: verified.source_receipt_contract_ids,
            executed_contract_ids: verified.executed_contract_ids,
        };
        validate_wire(&wire)?;
        let mut contents =
            serde_json::to_vec_pretty(&wire).context("serialize LocalOnly execution evidence")?;
        contents.push(b'\n');
        ensure_size(contents.len() as u64, MAX_REPORT_BYTES, "report")?;
        atomic_publish(&self.output, &contents)?;
        ValidatedLocalOnlyReport::load(&self.output)
    }
}

#[derive(Debug)]
pub(crate) struct ValidatedLocalOnlyReport {
    wire: ReportWire,
}

impl ValidatedLocalOnlyReport {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let bytes = read_ordinary_file(
            path,
            "LocalOnly execution evidence",
            MAX_REPORT_BYTES,
            "report",
        )?;
        let source =
            std::str::from_utf8(&bytes).context("LocalOnly execution evidence must be UTF-8")?;
        Self::parse(source)
    }

    pub(crate) fn parse(source: &str) -> Result<Self> {
        ensure_size(source.len() as u64, MAX_REPORT_BYTES, "report")?;
        let wire: ReportWire =
            serde_json::from_str(source).context("invalid LocalOnly execution evidence")?;
        validate_wire(&wire)?;
        Ok(Self { wire })
    }

    pub(crate) const fn job_key(&self) -> CiJobKey {
        self.wire.job_key
    }

    pub(crate) fn source_revision(&self) -> &str {
        &self.wire.source_revision
    }

    pub(crate) fn active_contract_ids(&self) -> &[String] {
        &self.wire.active_contract_ids
    }

    pub(crate) fn source_receipt_contract_ids(&self) -> &[String] {
        &self.wire.source_receipt_contract_ids
    }

    pub(crate) fn executed_contract_ids(&self) -> &[String] {
        &self.wire.executed_contract_ids
    }
}

fn reconcile_execution_sets(
    inventory: &LocalOnlyExecutionInventory,
    executed: Vec<String>,
) -> Result<VerifiedLocalOnlyExecutionSet> {
    let active = inventory
        .active_contract_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let source = inventory
        .source_receipt_contract_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let executed_set = executed.iter().cloned().collect::<BTreeSet<_>>();
    if executed_set.len() != executed.len() {
        bail!("duplicate LocalOnly execution marker");
    }
    let executed = executed_set.into_iter().collect::<Vec<_>>();
    if active.is_empty() || active != source || active != executed {
        bail!(
            "LocalOnly active/source/executed contract sets are not exact: {}",
            exact_set_difference_summary(&active, &source, &executed)
        );
    }
    Ok(VerifiedLocalOnlyExecutionSet {
        active_contract_ids: active,
        source_receipt_contract_ids: source,
        executed_contract_ids: executed,
    })
}

pub(crate) fn exact_set_difference_summary(
    active: &[String],
    source: &[String],
    executed: &[String],
) -> String {
    let active = active.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let source = source.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let executed = executed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let missing_from_source = active.difference(&source).copied().collect::<Vec<_>>();
    let extra_in_source = source.difference(&active).copied().collect::<Vec<_>>();
    let missing_from_executed = active.difference(&executed).copied().collect::<Vec<_>>();
    let extra_in_executed = executed.difference(&active).copied().collect::<Vec<_>>();
    format!(
        "missing_from_source={missing_from_source:?} extra_in_source={extra_in_source:?} missing_from_executed={missing_from_executed:?} extra_in_executed={extra_in_executed:?}"
    )
}

fn load_raw_markers(dir: &Path) -> Result<Vec<String>> {
    let directory_before = ordinary_directory_metadata(dir, "LocalOnly raw marker root")?;
    let mut entries = fs::read_dir(dir)
        .context("read LocalOnly raw marker directory")?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let directory_after = ordinary_directory_metadata(dir, "LocalOnly raw marker root")?;
    ensure_same_path_identity(
        &directory_before,
        &directory_after,
        "LocalOnly raw marker root",
    )?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut executed = Vec::new();
    for entry in entries {
        let path = entry.path();
        let source = read_ordinary_file(&path, "LocalOnly raw marker", MAX_MARKER_BYTES, "marker")?;
        let marker: MarkerWire =
            serde_json::from_slice(&source).context("invalid LocalOnly raw marker")?;
        if marker.schema_version != MARKER_SCHEMA_VERSION || !valid_contract_id(&marker.contract_id)
        {
            bail!("invalid LocalOnly raw marker identity");
        }
        let expected_name = format!("{}.json", marker.contract_id);
        if entry.file_name() != std::ffi::OsStr::new(&expected_name) {
            bail!("LocalOnly raw marker filename is not canonical");
        }
        executed.push(marker.contract_id);
    }
    Ok(executed)
}

fn valid_contract_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || value.contains("--") {
        return false;
    }
    let segments = value.split('.').collect::<Vec<_>>();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_wire(wire: &ReportWire) -> Result<()> {
    if wire.schema_version != SCHEMA_VERSION {
        bail!("unsupported LocalOnly execution evidence schema");
    }
    if wire.job_key != OWNER {
        bail!("LocalOnly execution evidence owner must be {OWNER}");
    }
    validate_revision(&wire.source_revision)?;
    for values in [
        &wire.active_contract_ids,
        &wire.source_receipt_contract_ids,
        &wire.executed_contract_ids,
    ] {
        if values.is_empty()
            || values.windows(2).any(|pair| pair[0] >= pair[1])
            || values.iter().any(|value| !valid_contract_id(value))
        {
            bail!("LocalOnly execution evidence contract set is invalid");
        }
    }
    if wire.active_contract_ids != wire.source_receipt_contract_ids
        || wire.active_contract_ids != wire.executed_contract_ids
    {
        bail!("LocalOnly execution evidence sets are not exact");
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<()> {
    if !(value.len() == 40 || value.len() == 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("LocalOnly evidence source revision is invalid");
    }
    Ok(())
}

fn ensure_size(size: u64, limit: u64, label: &str) -> Result<()> {
    if size == 0 || size > limit {
        bail!("LocalOnly execution {label} has an invalid size");
    }
    Ok(())
}

fn ordinary_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be an ordinary file");
    }
    Ok(metadata)
}

fn ordinary_directory_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} must be an ordinary directory");
    }
    Ok(metadata)
}

fn read_ordinary_file(
    path: &Path,
    label: &str,
    size_limit: u64,
    size_label: &str,
) -> Result<Vec<u8>> {
    read_ordinary_file_with_hook(path, label, size_limit, size_label, || Ok(()))
}

fn read_ordinary_file_with_hook(
    path: &Path,
    label: &str,
    size_limit: u64,
    size_label: &str,
    after_precheck: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let path_before = ordinary_file_metadata(path, label)?;
    after_precheck()?;

    let mut file = File::open(path).with_context(|| format!("open {label}"))?;
    let opened_before = file
        .metadata()
        .with_context(|| format!("inspect opened {label}"))?;
    if !opened_before.is_file() {
        bail!("{label} opened as a non-ordinary file");
    }
    ensure_same_path_identity(&path_before, &opened_before, label)?;
    ensure_size(opened_before.len(), size_limit, size_label)?;

    let read_limit = size_limit
        .checked_add(1)
        .context("LocalOnly execution read limit overflow")?;
    let mut contents = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut contents)
        .with_context(|| format!("read {label}"))?;

    let opened_after = file
        .metadata()
        .with_context(|| format!("reinspect opened {label}"))?;
    let path_after = ordinary_file_metadata(path, label)?;
    ensure_same_path_identity(&opened_before, &opened_after, label)?;
    ensure_same_path_identity(&opened_before, &path_after, label)?;
    ensure_size(contents.len() as u64, size_limit, size_label)?;
    if contents.len() as u64 != opened_before.len() || opened_before.len() != opened_after.len() {
        bail!("{label} changed while being read");
    }
    Ok(contents)
}

#[cfg(unix)]
fn ensure_same_path_identity(
    expected: &fs::Metadata,
    observed: &fs::Metadata,
    label: &str,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if expected.dev() != observed.dev()
        || expected.ino() != observed.ino()
        || expected.len() != observed.len()
        || expected.mtime() != observed.mtime()
        || expected.mtime_nsec() != observed.mtime_nsec()
        || expected.ctime() != observed.ctime()
        || expected.ctime_nsec() != observed.ctime_nsec()
    {
        bail!("{label} path identity changed during validation");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_path_identity(
    _expected: &fs::Metadata,
    _observed: &fs::Metadata,
    label: &str,
) -> Result<()> {
    bail!("{label} cannot prove stable file identity on this platform")
}

fn prepare_output_slot(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("create LocalOnly execution evidence directory")?;
    let metadata =
        fs::symlink_metadata(parent).context("inspect LocalOnly execution evidence directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("LocalOnly execution evidence parent must be an ordinary directory");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("LocalOnly execution evidence output must be absent or an ordinary file")
        }
        Ok(_) => fs::remove_file(path).context("remove stale LocalOnly execution evidence")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn create_raw_directory(output: &Path) -> Result<PathBuf> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let mut entries = fs::read_dir(parent)
        .context("inspect LocalOnly report directory for stale marker roots")?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    if entries.iter().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with(".localonly-raw-")
    }) {
        bail!("stale LocalOnly raw marker directory exists");
    }
    let sequence = RAW_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = parent.join(format!(".localonly-raw-{}-{sequence}", std::process::id()));
    create_owner_only_directory(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .context("create fresh LocalOnly raw marker directory")?;
    let metadata = ordinary_directory_metadata(path, "fresh LocalOnly raw marker directory")?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        bail!("fresh LocalOnly raw marker directory must have mode 0700");
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_owner_only_directory(_path: &Path) -> Result<()> {
    bail!("LocalOnly raw marker directory cannot enforce owner-only mode on this platform")
}

fn atomic_publish(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".{FILE_NAME}.tmp-{}", std::process::id()));
    match fs::symlink_metadata(&temporary) {
        Ok(_) => fs::remove_file(&temporary).context("remove stale LocalOnly report temporary")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("create LocalOnly execution report temporary")?;
    file.write_all(contents)
        .context("write LocalOnly execution report temporary")?;
    file.sync_all()
        .context("sync LocalOnly execution report temporary")?;
    drop(file);
    fs::rename(&temporary, path).context("publish LocalOnly execution report atomically")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consistency_effects::{LocalOnlyExecutionInventory, LocalOnlyExecutionTest};
    use std::collections::BTreeMap;

    #[test]
    fn request_revision_is_checkout_head_and_carrier_mismatch_leaves_no_output() -> Result<()> {
        let root = crate::testutil::unique_tmp("localonly-revision-identity");
        fs::create_dir_all(&root)?;
        let checkout_head = "b".repeat(40);

        for carrier in [
            "RSS_CI_SOURCE_REVISION",
            "GITHUB_SHA",
            "BUILD_SOURCEVERSION",
        ] {
            let output = root.join(format!("{carrier}.json"));
            let values = BTreeMap::from([
                ("RSS_CI_JOB_KEY", OWNER.as_str().to_owned()),
                (carrier, "a".repeat(40)),
            ]);
            let error = prepare_request_with(
                OWNER,
                Some(&output),
                &root,
                |name| Ok(values.get(name).cloned()),
                |_| Ok(checkout_head.clone()),
            )
            .err()
            .with_context(|| format!("{carrier} mismatch must fail closed"))?;
            assert!(error.to_string().contains(carrier), "{error:#}");
            assert!(!output.exists(), "identity mismatch created {output:?}");
        }

        let output = root.join("matched.json");
        let values = BTreeMap::from([
            ("RSS_CI_JOB_KEY", OWNER.as_str().to_owned()),
            ("RSS_CI_SOURCE_REVISION", checkout_head.clone()),
            ("GITHUB_SHA", checkout_head.clone()),
            ("BUILD_SOURCEVERSION", checkout_head.clone()),
        ]);
        let request = prepare_request_with(
            OWNER,
            Some(&output),
            &root,
            |name| Ok(values.get(name).cloned()),
            |_| Ok(checkout_head.clone()),
        )?
        .context("matched carrier identities must prepare LocalOnly evidence")?;
        assert_eq!(request.source_revision, checkout_head);
        assert!(!output.exists(), "prepare must not publish evidence");

        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn inventory(ids: &[&str]) -> LocalOnlyExecutionInventory {
        let active_contract_ids = ids.iter().map(|id| (*id).to_owned()).collect();
        let source_receipt_contract_ids = ids.iter().map(|id| (*id).to_owned()).collect();
        let tests = ids
            .iter()
            .map(|id| LocalOnlyExecutionTest {
                contract_id: (*id).to_owned(),
                package: "demo".to_owned(),
                test_target: "lib".to_owned(),
                test_name: format!("tests::{}", id.replace(['.', '-'], "_")),
            })
            .collect();
        LocalOnlyExecutionInventory {
            active_contract_ids,
            source_receipt_contract_ids,
            tests,
        }
    }

    #[test]
    fn execution_exact_set_rejects_missing_extra_duplicate_and_equal_count_wrong_set() -> Result<()>
    {
        let canonical = inventory(&["audit.list-entries", "identity.profile"]);
        assert!(
            reconcile_execution_sets(
                &canonical,
                vec!["audit.list-entries".into(), "identity.profile".into()]
            )
            .is_ok()
        );
        for (label, executed, expected) in [
            (
                "missing",
                vec!["audit.list-entries".into()],
                "missing_from_source=[] extra_in_source=[] missing_from_executed=[\"identity.profile\"] extra_in_executed=[]",
            ),
            (
                "extra",
                vec![
                    "audit.list-entries".into(),
                    "identity.profile".into(),
                    "settings.config-get".into(),
                ],
                "missing_from_source=[] extra_in_source=[] missing_from_executed=[] extra_in_executed=[\"settings.config-get\"]",
            ),
            (
                "equal-count-wrong-set",
                vec!["audit.list-entries".into(), "settings.config-get".into()],
                "missing_from_source=[] extra_in_source=[] missing_from_executed=[\"identity.profile\"] extra_in_executed=[\"settings.config-get\"]",
            ),
        ] {
            let Err(error) = reconcile_execution_sets(&canonical, executed) else {
                bail!("{label}: synthetic exact-set drift must fail");
            };
            assert!(error.to_string().contains(expected), "{label}: {error:#}");
        }

        let Err(duplicate) = reconcile_execution_sets(
            &canonical,
            vec!["identity.profile".into(), "identity.profile".into()],
        ) else {
            bail!("duplicate marker must fail before set reconciliation");
        };
        assert_eq!(
            duplicate.to_string(),
            "duplicate LocalOnly execution marker"
        );

        let mut source_drift = canonical;
        source_drift.source_receipt_contract_ids = BTreeSet::from([
            "audit.list-entries".to_owned(),
            "settings.config-get".to_owned(),
        ]);
        let Err(error) = reconcile_execution_sets(
            &source_drift,
            vec!["audit.list-entries".into(), "identity.profile".into()],
        ) else {
            bail!("source drift must fail");
        };
        assert!(error.to_string().contains(
            "missing_from_source=[\"identity.profile\"] extra_in_source=[\"settings.config-get\"] missing_from_executed=[] extra_in_executed=[]"
        ));
        Ok(())
    }

    #[test]
    fn report_wire_is_strict_exact_and_deterministic() -> Result<()> {
        let source = serde_json::json!({
            "schemaVersion": 1,
            "jobKey": "ci-local-only",
            "sourceRevision": "a".repeat(40),
            "activeContractIds": ["audit.list-entries", "identity.profile"],
            "sourceReceiptContractIds": ["audit.list-entries", "identity.profile"],
            "executedContractIds": ["audit.list-entries", "identity.profile"]
        });
        let parsed = ValidatedLocalOnlyReport::parse(&serde_json::to_string(&source)?)?;
        assert_eq!(parsed.job_key(), OWNER);
        assert_eq!(parsed.executed_contract_ids().len(), 2);

        let mut unknown = source.clone();
        unknown["legacyCount"] = 2.into();
        assert!(ValidatedLocalOnlyReport::parse(&serde_json::to_string(&unknown)?).is_err());
        let mut schema_drift = source.clone();
        schema_drift["schemaVersion"] = 2.into();
        assert!(ValidatedLocalOnlyReport::parse(&serde_json::to_string(&schema_drift)?).is_err());
        let mut invalid_id = source.clone();
        for field in [
            "activeContractIds",
            "sourceReceiptContractIds",
            "executedContractIds",
        ] {
            invalid_id[field] = serde_json::json!(["../escape"]);
        }
        assert!(ValidatedLocalOnlyReport::parse(&serde_json::to_string(&invalid_id)?).is_err());
        assert!(ValidatedLocalOnlyReport::parse("{").is_err());
        assert!(ValidatedLocalOnlyReport::parse("").is_err());
        assert!(
            ValidatedLocalOnlyReport::parse(&" ".repeat(MAX_REPORT_BYTES as usize + 1)).is_err()
        );
        let mut wrong = source;
        wrong["executedContractIds"] =
            serde_json::json!(["audit.list-entries", "settings.config-get"]);
        assert!(ValidatedLocalOnlyReport::parse(&serde_json::to_string(&wrong)?).is_err());

        let root = crate::testutil::unique_tmp("localonly-report-golden");
        fs::create_dir_all(&root)?;
        let output = root.join(FILE_NAME);
        LocalOnlyEvidenceRequest {
            output: output.clone(),
            source_revision: "a".repeat(40),
        }
        .publish(
            LocalOnlySuitePassed(()),
            VerifiedLocalOnlyExecutionSet {
                active_contract_ids: vec!["audit.list-entries".into(), "identity.profile".into()],
                source_receipt_contract_ids: vec![
                    "audit.list-entries".into(),
                    "identity.profile".into(),
                ],
                executed_contract_ids: vec!["audit.list-entries".into(), "identity.profile".into()],
            },
        )?;
        assert_eq!(
            fs::read_to_string(&output)?,
            include_str!("../tests/golden/localonly-execution-v1.json")
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn raw_marker_schema_and_file_boundary_red_matrix() -> Result<()> {
        let root = crate::testutil::unique_tmp("localonly-markers");
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("audit.list-entries.json"),
            r#"{"schemaVersion":1,"contractId":"audit.list-entries"}"#,
        )?;
        assert_eq!(load_raw_markers(&root)?, ["audit.list-entries"]);
        fs::write(
            root.join("wrong.json"),
            r#"{"schemaVersion":1,"contractId":"identity.profile"}"#,
        )?;
        assert!(load_raw_markers(&root).is_err());
        fs::remove_dir_all(&root)?;

        for (label, source) in [
            ("malformed", "{".to_owned()),
            (
                "unknown-field",
                r#"{"schemaVersion":1,"contractId":"audit.list-entries","legacy":true}"#.to_owned(),
            ),
            (
                "schema-drift",
                r#"{"schemaVersion":2,"contractId":"audit.list-entries"}"#.to_owned(),
            ),
            (
                "invalid-id",
                r#"{"schemaVersion":1,"contractId":"../escape"}"#.to_owned(),
            ),
            ("empty", String::new()),
            ("oversize", "x".repeat(MAX_MARKER_BYTES as usize + 1)),
        ] {
            let root = crate::testutil::unique_tmp(&format!("localonly-marker-{label}"));
            fs::create_dir_all(&root)?;
            fs::write(root.join("audit.list-entries.json"), source)?;
            assert!(load_raw_markers(&root).is_err(), "{label}");
            fs::remove_dir_all(root)?;
        }

        let root = crate::testutil::unique_tmp("localonly-marker-directory-entry");
        fs::create_dir_all(root.join("audit.list-entries.json"))?;
        assert!(load_raw_markers(&root).is_err());
        fs::remove_dir_all(root)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let root = crate::testutil::unique_tmp("localonly-marker-symlink");
            fs::create_dir_all(&root)?;
            let target = root.join("target.json");
            fs::write(
                &target,
                r#"{"schemaVersion":1,"contractId":"audit.list-entries"}"#,
            )?;
            symlink(&target, root.join("audit.list-entries.json"))?;
            assert!(load_raw_markers(&root).is_err());
            fs::remove_dir_all(&root)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_file_read_rejects_path_replacement_after_precheck() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("localonly-read-replacement");
        fs::create_dir_all(&root)?;
        let path = root.join("marker.json");
        let replacement = root.join("replacement.json");
        fs::write(&path, b"same")?;
        fs::write(&replacement, b"size")?;
        assert!(
            read_ordinary_file_with_hook(&path, "fixture", 4, "fixture", || {
                fs::rename(&replacement, &path)?;
                Ok(())
            })
            .is_err(),
            "same-length replacement must fail closed"
        );

        fs::write(&path, b"same")?;
        let target = root.join("target.json");
        fs::write(&target, b"size")?;
        assert!(
            read_ordinary_file_with_hook(&path, "fixture", 4, "fixture", || {
                fs::remove_file(&path)?;
                symlink(&target, &path)?;
                Ok(())
            })
            .is_err(),
            "symlink swap after precheck must fail closed"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn raw_marker_directory_is_owner_only() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::testutil::unique_tmp("localonly-marker-permissions");
        fs::create_dir_all(&root)?;
        let raw = create_raw_directory(&root.join(FILE_NAME))?;
        assert_eq!(fs::metadata(&raw)?.permissions().mode() & 0o777, 0o700);
        fs::remove_dir_all(raw)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn real_workspace_execution_inventory_is_exact_and_non_empty() -> Result<()> {
        let inventory =
            crate::consistency_effects::local_only_execution_inventory(&crate::workspace_root()?)?;
        let expected_ids = generated::http::LOCAL_ONLY_SPECS
            .iter()
            .map(|spec| spec.route.contract_id().to_owned())
            .collect::<BTreeSet<_>>();
        assert!(!expected_ids.is_empty());
        assert_eq!(inventory.active_contract_ids, expected_ids);
        assert_eq!(
            inventory.active_contract_ids,
            inventory.source_receipt_contract_ids
        );
        let test_ids = inventory
            .tests
            .iter()
            .map(|test| test.contract_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(inventory.tests.len(), test_ids.len());
        assert_eq!(test_ids, inventory.active_contract_ids);
        assert!(inventory.tests.iter().all(|test| test.test_target == "lib"));
        assert!(
            inventory
                .tests
                .iter()
                .all(|test| !test.package.is_empty() && !test.test_name.is_empty())
        );
        Ok(())
    }

    #[test]
    fn relative_report_path_is_bound_to_the_workspace_before_marker_derivation() -> Result<()> {
        let root = crate::testutil::unique_tmp("localonly-relative-output");
        fs::create_dir_all(&root)?;
        let output = resolve_output_path(&root, Some(Path::new("target/report.json")));
        assert_eq!(output, root.join("target/report.json"));
        assert!(output.is_absolute());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stale_raw_marker_directory_is_rejected_before_execution() -> Result<()> {
        let root = crate::testutil::unique_tmp("localonly-stale-raw");
        fs::create_dir_all(root.join(".localonly-raw-stale"))?;
        assert!(create_raw_directory(&root.join(FILE_NAME)).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn nextest_failure_after_all_canonical_markers_blocks_publish_and_cleans_raw_directory()
    -> Result<()> {
        let workspace = crate::workspace_root()?;
        let canonical = crate::consistency_effects::local_only_execution_inventory(&workspace)?
            .active_contract_ids
            .into_iter()
            .collect::<Vec<_>>();
        assert!(!canonical.is_empty());

        let report_root = crate::testutil::unique_tmp("localonly-nextest-failure");
        fs::create_dir_all(&report_root)?;
        let output = report_root.join(FILE_NAME);
        let request = LocalOnlyEvidenceRequest {
            output: output.clone(),
            source_revision: "a".repeat(40),
        };
        let reached_complete_marker_set = std::cell::Cell::new(false);
        let result =
            execute_with_suite_runner(&workspace, request, |_root, packages, tests, raw_dir| {
                assert!(!packages.is_empty());
                assert_eq!(tests.len(), canonical.len());
                for contract_id in &canonical {
                    fs::write(
                        raw_dir.join(format!("{contract_id}.json")),
                        serde_json::to_vec(&serde_json::json!({
                            "schemaVersion": MARKER_SCHEMA_VERSION,
                            "contractId": contract_id,
                        }))?,
                    )?;
                }
                assert_eq!(load_raw_markers(raw_dir)?, canonical);
                reached_complete_marker_set.set(true);
                bail!("synthetic nextest failure after complete marker emission")
            });
        let error = result
            .err()
            .context("synthetic nextest failure must fail execution")?;
        assert_eq!(
            error.to_string(),
            "synthetic nextest failure after complete marker emission"
        );
        assert!(
            reached_complete_marker_set.get(),
            "suite seam must fail only after the complete exact marker set"
        );
        assert!(!output.exists(), "failed suite must not publish a report");
        assert!(
            fs::read_dir(&report_root)?.all(|entry| {
                entry.is_ok_and(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".localonly-raw-")
                })
            }),
            "failed suite must clean its raw marker directory"
        );
        fs::remove_dir_all(report_root)?;
        Ok(())
    }
}
