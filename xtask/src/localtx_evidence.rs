//! Typed producer and strict consumer for the LocalTx required evidence receipt.
//!
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "LocalTxEvidenceRequest::publish requires the private PostgresDomainPassed and VerifiedLocalTxCounts capabilities; the receipt wire has one closed owner/outcome/kind" }.
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-WIRE-01 { level = "Hard", exec = "native-compile", source = "code", native = "the private closed receipt DTO fixes the field inventory and typed values; deny_unknown_fields plus a committed v1 serialization golden reject schema drift" }.

use crate::ci_identity::CiIdentityKey;
use crate::ci_lanes::CiJobKey;
use crate::localtx_coverage::VerifiedLocalTxCounts;
use crate::verify::PostgresDomainPassed;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(crate) const FILE_NAME: &str = "localtx-required.json";
pub(crate) const OWNER: CiJobKey = CiJobKey::IntegrationPostgresDomain;
const SCHEMA_VERSION: u8 = 1;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceKind {
    LocaltxRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceOutcome {
    Success,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptWire {
    schema_version: u8,
    evidence_kind: EvidenceKind,
    job_key: CiJobKey,
    source_revision: String,
    plan_digest: String,
    run_id: String,
    run_attempt: String,
    outcome: EvidenceOutcome,
    localtx_active_count: usize,
    localtx_journey_count: usize,
    localtx_backend_profile_count: usize,
}

#[derive(Debug)]
struct CiIdentity {
    source_revision: String,
    plan_digest: String,
    run_id: String,
    run_attempt: String,
}

/// A prepared output request. Its fields and constructor are private so a caller cannot mint or
/// redirect a receipt after the pre-run identity and output-slot checks.
#[derive(Debug)]
pub(crate) struct LocalTxEvidenceRequest {
    output: PathBuf,
    identity: CiIdentity,
}

/// Prepare the sole LocalTx evidence output before executing the typed CI job.
pub(crate) fn prepare_request(
    job: CiJobKey,
    output: Option<&Path>,
) -> Result<Option<LocalTxEvidenceRequest>> {
    prepare_request_with(job, output, |name| match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => value
            .into_string()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8")),
    })
}

fn prepare_request_with(
    job: CiJobKey,
    output: Option<&Path>,
    mut environment: impl FnMut(&str) -> Result<Option<String>>,
) -> Result<Option<LocalTxEvidenceRequest>> {
    if job != OWNER {
        if output.is_some() {
            bail!("only {OWNER} may request LocalTx required evidence output");
        }
        return Ok(None);
    }

    let mut values = Vec::with_capacity(CiIdentityKey::LOCALTX_REQUIRED.len());
    for key in CiIdentityKey::LOCALTX_REQUIRED {
        values.push((key, environment(key.env_name())?));
    }
    if output.is_none() && values.iter().all(|(_, value)| value.is_none()) {
        return Ok(None);
    }
    let output = output.context(
        "LocalTx required evidence output is mandatory when any CI identity variable is present",
    )?;
    let required = |key: CiIdentityKey| -> Result<String> {
        values
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .and_then(|(_, value)| value.clone())
            .with_context(|| format!("{} is required for LocalTx evidence", key.env_name()))
    };
    let environment_job = required(CiIdentityKey::JobKey)?
        .parse::<CiJobKey>()
        .context("invalid RSS_CI_JOB_KEY for LocalTx evidence")?;
    if environment_job != job || environment_job != OWNER {
        bail!("LocalTx evidence job identity must be {OWNER}");
    }
    let source_revision = required(CiIdentityKey::SourceRevision)?;
    let plan_digest = required(CiIdentityKey::PlanDigest)?;
    let run_id = required(CiIdentityKey::RunId)?;
    let run_attempt = required(CiIdentityKey::RunAttempt)?;
    let head_revision = required(CiIdentityKey::HeadRevision)?;
    validate_revision(&source_revision, "source revision")?;
    validate_digest(&plan_digest)?;
    validate_run_component(&run_id, "run ID")?;
    validate_run_component(&run_attempt, "run attempt")?;
    validate_revision(&head_revision, "GitHub HEAD revision")?;
    if source_revision != head_revision {
        bail!("LocalTx evidence source revision must equal GITHUB_SHA");
    }
    prepare_output_slot(output)?;
    Ok(Some(LocalTxEvidenceRequest {
        output: output.to_path_buf(),
        identity: CiIdentity {
            source_revision,
            plan_digest,
            run_id,
            run_attempt,
        },
    }))
}

impl LocalTxEvidenceRequest {
    /// Publish only after the postgres-domain execution and canonical inventory verification have
    /// both produced their private success capabilities.
    pub(crate) fn publish(
        self,
        _passed: PostgresDomainPassed,
        counts: VerifiedLocalTxCounts,
    ) -> Result<()> {
        let active_count = counts.active_count();
        let journey_count = counts.journey_count();
        let backend_profile_count = counts.backend_profile_count();
        if [active_count, journey_count, backend_profile_count]
            != [VerifiedLocalTxCounts::EXPECTED; 3]
        {
            bail!("verified LocalTx counts must all equal the required count");
        }
        let wire = ReceiptWire {
            schema_version: SCHEMA_VERSION,
            evidence_kind: EvidenceKind::LocaltxRequired,
            job_key: OWNER,
            source_revision: self.identity.source_revision,
            plan_digest: self.identity.plan_digest,
            run_id: self.identity.run_id,
            run_attempt: self.identity.run_attempt,
            outcome: EvidenceOutcome::Success,
            localtx_active_count: active_count,
            localtx_journey_count: journey_count,
            localtx_backend_profile_count: backend_profile_count,
        };
        let mut contents =
            serde_json::to_vec_pretty(&wire).context("serialize LocalTx evidence")?;
        contents.push(b'\n');
        ensure_receipt_size(contents.len() as u64)?;
        atomic_publish(&self.output, &contents)
    }
}

/// Fully validated, read-only receipt consumed by ci-gate.
#[derive(Debug)]
pub(crate) struct ValidatedLocalTxReceipt {
    wire: ReceiptWire,
}

impl ValidatedLocalTxReceipt {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect LocalTx evidence {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "LocalTx evidence must be an ordinary file: {}",
                path.display()
            );
        }
        ensure_receipt_size(metadata.len())?;
        let source = fs::read_to_string(path)
            .with_context(|| format!("read LocalTx evidence {}", path.display()))?;
        let after = fs::symlink_metadata(path)
            .with_context(|| format!("reinspect LocalTx evidence {}", path.display()))?;
        if after.file_type().is_symlink() || !after.is_file() || after.len() != metadata.len() {
            bail!("LocalTx evidence changed while being read");
        }
        Self::parse(&source)
    }

    pub(crate) fn parse(source: &str) -> Result<Self> {
        ensure_receipt_size(source.len() as u64)?;
        let wire: ReceiptWire =
            serde_json::from_str(source).context("invalid LocalTx evidence receipt")?;
        validate_wire(&wire)?;
        Ok(Self { wire })
    }

    pub(crate) const fn job_key(&self) -> CiJobKey {
        self.wire.job_key
    }

    pub(crate) fn source_revision(&self) -> &str {
        &self.wire.source_revision
    }

    pub(crate) fn plan_digest(&self) -> &str {
        &self.wire.plan_digest
    }

    pub(crate) fn run_id(&self) -> &str {
        &self.wire.run_id
    }

    pub(crate) fn run_attempt(&self) -> &str {
        &self.wire.run_attempt
    }

    pub(crate) const fn active_count(&self) -> usize {
        self.wire.localtx_active_count
    }

    pub(crate) const fn journey_count(&self) -> usize {
        self.wire.localtx_journey_count
    }

    pub(crate) const fn backend_profile_count(&self) -> usize {
        self.wire.localtx_backend_profile_count
    }
}

fn validate_wire(wire: &ReceiptWire) -> Result<()> {
    if wire.schema_version != SCHEMA_VERSION {
        bail!("unsupported LocalTx evidence schema");
    }
    if wire.evidence_kind != EvidenceKind::LocaltxRequired {
        bail!("LocalTx evidence kind mismatch");
    }
    if wire.job_key != OWNER {
        bail!("LocalTx evidence owner must be {OWNER}");
    }
    if wire.outcome != EvidenceOutcome::Success {
        bail!("LocalTx evidence outcome must be success");
    }
    validate_revision(&wire.source_revision, "source revision")?;
    validate_digest(&wire.plan_digest)?;
    validate_run_component(&wire.run_id, "run ID")?;
    validate_run_component(&wire.run_attempt, "run attempt")?;
    if [
        wire.localtx_active_count,
        wire.localtx_journey_count,
        wire.localtx_backend_profile_count,
    ] != [VerifiedLocalTxCounts::EXPECTED; 3]
    {
        bail!(
            "LocalTx evidence counts mismatch: active={} journey={} backend-profile={} expected={}",
            wire.localtx_active_count,
            wire.localtx_journey_count,
            wire.localtx_backend_profile_count,
            VerifiedLocalTxCounts::EXPECTED,
        );
    }
    Ok(())
}

fn ensure_receipt_size(size: u64) -> Result<()> {
    if size > MAX_RECEIPT_BYTES {
        bail!("LocalTx evidence receipt exceeds 16 KiB");
    }
    Ok(())
}

fn validate_revision(value: &str, label: &str) -> Result<()> {
    if !(value.len() == 40 || value.len() == 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("LocalTx evidence {label} is invalid");
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("LocalTx evidence plan digest is invalid");
    }
    Ok(())
}

fn validate_run_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("LocalTx evidence {label} is invalid");
    }
    Ok(())
}

fn prepare_output_slot(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create LocalTx evidence directory {}", parent.display()))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect LocalTx evidence directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("LocalTx evidence parent must be an ordinary directory");
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("LocalTx evidence output must be absent or an ordinary file")
        }
        Ok(_) => fs::remove_file(path)
            .with_context(|| format!("remove stale LocalTx evidence {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn atomic_publish(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("LocalTx evidence output has no file name")?
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
    let (temporary_path, mut file) = temporary.context("cannot allocate LocalTx evidence file")?;
    let publish_result = (|| -> Result<()> {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary_path, path)
            .with_context(|| format!("publish LocalTx evidence {}", path.display()))?;
        Ok(())
    })();
    let _ = fs::remove_file(&temporary_path);
    publish_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn identity() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("RSS_CI_JOB_KEY", OWNER.as_str().to_owned()),
            ("RSS_CI_SOURCE_REVISION", "e".repeat(40)),
            ("RSS_CI_PLAN_DIGEST", "c".repeat(64)),
            ("GITHUB_RUN_ID", "42".to_owned()),
            ("GITHUB_RUN_ATTEMPT", "3".to_owned()),
            ("GITHUB_SHA", "e".repeat(40)),
        ])
    }

    fn request_with(
        job: CiJobKey,
        output: Option<&Path>,
        values: &BTreeMap<&'static str, String>,
    ) -> Result<Option<LocalTxEvidenceRequest>> {
        prepare_request_with(job, output, |name| Ok(values.get(name).cloned()))
    }

    fn golden_wire() -> ReceiptWire {
        ReceiptWire {
            schema_version: SCHEMA_VERSION,
            evidence_kind: EvidenceKind::LocaltxRequired,
            job_key: OWNER,
            source_revision: "e".repeat(40),
            plan_digest: "c".repeat(64),
            run_id: "42".to_owned(),
            run_attempt: "3".to_owned(),
            outcome: EvidenceOutcome::Success,
            localtx_active_count: 5,
            localtx_journey_count: 5,
            localtx_backend_profile_count: 5,
        }
    }

    fn publish_when_ready(
        request: LocalTxEvidenceRequest,
        passed: Result<PostgresDomainPassed>,
        counts: Result<VerifiedLocalTxCounts>,
    ) -> Result<()> {
        request.publish(passed?, counts?)
    }

    #[test]
    fn receipt_v1_wire_matches_committed_golden() -> Result<()> {
        let actual = format!("{}\n", serde_json::to_string_pretty(&golden_wire())?);
        assert_eq!(
            actual,
            include_str!("../tests/golden/localtx-required-receipt.json")
        );
        ValidatedLocalTxReceipt::parse(&actual)?;
        Ok(())
    }

    #[test]
    fn producer_publishes_only_after_both_success_capabilities() -> Result<()> {
        let root = crate::testutil::unique_tmp("localtx-evidence-publish");
        let output = root.join("integration/localtx-required.json");
        let request = request_with(OWNER, Some(&output), &identity())?
            .context("canonical producer request")?;

        publish_when_ready(
            request,
            Ok(PostgresDomainPassed::for_test()),
            Ok(VerifiedLocalTxCounts::for_test()),
        )?;

        let serialized = fs::read_to_string(&output)?;
        assert_eq!(
            serialized,
            include_str!("../tests/golden/localtx-required-receipt.json"),
            "the sole producer must emit the committed receipt-v1 wire"
        );
        let receipt = ValidatedLocalTxReceipt::load(&output)?;
        assert_eq!(receipt.job_key(), OWNER);
        assert_eq!(receipt.source_revision(), "e".repeat(40));
        assert_eq!(receipt.plan_digest(), "c".repeat(64));
        assert_eq!(receipt.run_id(), "42");
        assert_eq!(receipt.run_attempt(), "3");
        assert_eq!(receipt.active_count(), VerifiedLocalTxCounts::EXPECTED);
        assert_eq!(receipt.journey_count(), VerifiedLocalTxCounts::EXPECTED);
        assert_eq!(
            receipt.backend_profile_count(),
            VerifiedLocalTxCounts::EXPECTED
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn producer_failure_before_either_capability_leaves_no_receipt() -> Result<()> {
        let root = crate::testutil::unique_tmp("localtx-evidence-no-premature-publish");
        let runner_output = root.join("runner/localtx-required.json");
        let runner_request = request_with(OWNER, Some(&runner_output), &identity())?
            .context("runner failure request")?;
        assert!(
            publish_when_ready(
                runner_request,
                Err(anyhow::anyhow!("postgres-domain failed")),
                Ok(VerifiedLocalTxCounts::for_test()),
            )
            .is_err()
        );
        assert!(
            !runner_output.exists(),
            "a failed postgres-domain run must not publish evidence"
        );

        let counts_output = root.join("counts/localtx-required.json");
        let counts_request = request_with(OWNER, Some(&counts_output), &identity())?
            .context("count verification failure request")?;
        assert!(
            publish_when_ready(
                counts_request,
                Ok(PostgresDomainPassed::for_test()),
                Err(anyhow::anyhow!("LocalTx inventory verification failed")),
            )
            .is_err()
        );
        assert!(
            !counts_output.exists(),
            "failed count verification must not publish evidence"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn parser_rejects_schema_unknown_outcome_counts_and_static_report_bait() -> Result<()> {
        let valid = serde_json::to_value(golden_wire())?;
        for (label, mutation) in [
            ("legacy-schema", ("schemaVersion", serde_json::json!(0))),
            ("failure", ("outcome", serde_json::json!("failure"))),
            ("count-four", ("localtxActiveCount", serde_json::json!(4))),
            ("count-six", ("localtxJourneyCount", serde_json::json!(6))),
        ] {
            let mut value = valid.clone();
            value[mutation.0] = mutation.1;
            assert!(
                ValidatedLocalTxReceipt::parse(&serde_json::to_string(&value)?).is_err(),
                "{label}"
            );
        }
        let mut invalid_counts = valid.clone();
        invalid_counts["localtxActiveCount"] = serde_json::json!(4);
        invalid_counts["localtxJourneyCount"] = serde_json::json!(6);
        invalid_counts["localtxBackendProfileCount"] = serde_json::json!(7);
        let error = match ValidatedLocalTxReceipt::parse(&serde_json::to_string(&invalid_counts)?) {
            Err(error) => error.to_string(),
            Ok(_) => bail!("mismatched LocalTx counts must fail"),
        };
        assert_eq!(
            error,
            "LocalTx evidence counts mismatch: active=4 journey=6 backend-profile=7 expected=5"
        );
        let mut unknown = valid;
        unknown["staticProofInventory"] = serde_json::json!({"active": 5});
        assert!(ValidatedLocalTxReceipt::parse(&serde_json::to_string(&unknown)?).is_err());
        assert!(
            ValidatedLocalTxReceipt::parse(
                r#"{"schemaVersion":1,"activeContracts":5,"journeys":5,"backendProfiles":5}"#
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn preparation_is_closed_to_owner_complete_identity_and_safe_output() -> Result<()> {
        let root = crate::testutil::unique_tmp("localtx-evidence-prepare");
        let output = root.join("integration/localtx-required.json");
        assert!(
            request_with(CiJobKey::CiMeta, Some(&output), &BTreeMap::new()).is_err(),
            "non-owner must not request the output"
        );
        assert!(request_with(OWNER, None, &BTreeMap::new())?.is_none());
        assert!(request_with(OWNER, None, &identity()).is_err());
        let mut partial = identity();
        partial.remove("GITHUB_RUN_ATTEMPT");
        assert!(request_with(OWNER, Some(&output), &partial).is_err());
        fs::create_dir_all(output.parent().context("fixture parent")?)?;
        fs::write(&output, "stale")?;
        assert!(request_with(OWNER, Some(&output), &identity())?.is_some());
        assert!(
            !output.exists(),
            "preparation must remove a stale ordinary file"
        );
        fs::create_dir(&output)?;
        assert!(request_with(OWNER, Some(&output), &identity()).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn preparation_and_reader_reject_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = crate::testutil::unique_tmp("localtx-evidence-symlink");
        fs::create_dir_all(&root)?;
        let target = root.join("target.json");
        fs::write(&target, serde_json::to_vec(&golden_wire())?)?;
        let link = root.join(FILE_NAME);
        symlink(&target, &link)?;
        assert!(request_with(OWNER, Some(&link), &identity()).is_err());
        assert!(ValidatedLocalTxReceipt::load(&link).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
