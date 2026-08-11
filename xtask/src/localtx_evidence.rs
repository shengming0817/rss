//! Semantic LocalTx exact-set report produced by the fixed integration job.
//!
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "LocalTxEvidenceRequest::publish requires PostgresDomainPassed and VerifiedLocalTxContractSet" }.
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-WIRE-01 { level = "Hard", exec = "native-compile", source = "code", native = "deny_unknown_fields fixes the v4 semantic report and its FixedCiJob owner" }.

use crate::ci_lanes::FixedCiJob;
use crate::localtx_coverage::VerifiedLocalTxContractSet;
use crate::verify::PostgresDomainPassed;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const FILE_NAME: &str = "localtx-required.json";
pub(crate) const OWNER: FixedCiJob = FixedCiJob::IntegrationCritical;
const SCHEMA_VERSION: u8 = 4;
const MAX_REPORT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportWire {
    schema_version: u8,
    job: FixedCiJob,
    source_revision: String,
    localtx_contract_ids: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct LocalTxEvidenceRequest {
    output: PathBuf,
    source_revision: String,
}

pub(crate) fn prepare_request(
    job: FixedCiJob,
    output: Option<&Path>,
    root: &Path,
) -> Result<LocalTxEvidenceRequest> {
    if job != OWNER {
        bail!("only {OWNER} may produce LocalTx required evidence");
    }
    let source_revision = crate::cmd::source_revision(root)?;
    validate_revision(&source_revision)?;
    if let Some(claimed) = std::env::var_os("GITHUB_SHA") {
        let claimed = claimed
            .into_string()
            .map_err(|_| anyhow::anyhow!("GITHUB_SHA is not valid UTF-8"))?;
        validate_revision(&claimed)?;
        if claimed != source_revision {
            bail!("GITHUB_SHA must equal the checked-out git HEAD");
        }
    }
    let output = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("target/required-evidence").join(FILE_NAME));
    prepare_output_slot(&output)?;
    Ok(LocalTxEvidenceRequest {
        output,
        source_revision,
    })
}

impl LocalTxEvidenceRequest {
    pub(crate) fn publish(
        self,
        _passed: PostgresDomainPassed,
        verified: VerifiedLocalTxContractSet,
    ) -> Result<()> {
        let wire = ReportWire {
            schema_version: SCHEMA_VERSION,
            job: OWNER,
            source_revision: self.source_revision,
            localtx_contract_ids: verified.active_contract_ids().to_vec(),
        };
        validate_wire(&wire)?;
        let mut contents = serde_json::to_vec_pretty(&wire).context("serialize LocalTx report")?;
        contents.push(b'\n');
        ensure_size(contents.len() as u64)?;
        atomic_publish(&self.output, &contents)
    }
}

fn validate_wire(wire: &ReportWire) -> Result<()> {
    if wire.schema_version != SCHEMA_VERSION || wire.job != OWNER {
        bail!("invalid LocalTx report identity");
    }
    validate_revision(&wire.source_revision)?;
    if wire.localtx_contract_ids.is_empty()
        || wire
            .localtx_contract_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || wire
            .localtx_contract_ids
            .iter()
            .any(|value| !consistency::is_canonical_topic_name(value))
    {
        bail!("LocalTx report contract set is not canonical");
    }
    Ok(())
}

pub(crate) fn validate_upload_snapshot(
    input: &Path,
    output: &Path,
    root: &Path,
    facts: &workspacefacts::WorkspaceFacts,
) -> Result<()> {
    let bytes =
        crate::evidence_file::read_stable_ordinary_file(input, "LocalTx report", MAX_REPORT_BYTES)?;
    let wire: ReportWire =
        serde_json::from_slice(&bytes).context("invalid LocalTx required evidence")?;
    validate_wire(&wire)?;
    if wire.source_revision != crate::cmd::source_revision(root)? {
        bail!("LocalTx evidence revision does not match checked-out HEAD");
    }
    let verified = crate::localtx_coverage::verify_required_evidence_set(root, facts)?;
    if wire.localtx_contract_ids != verified.active_contract_ids() {
        bail!("LocalTx evidence does not match the current canonical contract set");
    }
    prepare_output_slot(output)?;
    atomic_publish(output, &bytes)
}

#[cfg(test)]
fn read_stable_ordinary_file(
    path: &Path,
    after_precheck: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    crate::evidence_file::read_stable_ordinary_file_with_hook(
        path,
        "LocalTx report",
        MAX_REPORT_BYTES,
        after_precheck,
    )
}

fn validate_revision(value: &str) -> Result<()> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("source revision must be a 40-character hexadecimal git object ID");
    }
    Ok(())
}

fn ensure_size(size: u64) -> Result<()> {
    if size == 0 || size > MAX_REPORT_BYTES {
        bail!("LocalTx report size is outside the accepted range");
    }
    Ok(())
}

fn prepare_output_slot(path: &Path) -> Result<()> {
    crate::evidence_file::prepare_output_slot(path, "LocalTx report")?;
    Ok(())
}

fn atomic_publish(path: &Path, contents: &[u8]) -> Result<()> {
    crate::evidence_file::atomic_publish(path, contents, "LocalTx report", "localtx-required")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn wire_rejects_old_receipt_fields_and_wrong_owner() -> Result<()> {
        let old = r#"{"schemaVersion":3,"jobKey":"integration/postgres-domain","planDigest":"00"}"#;
        assert!(serde_json::from_str::<ReportWire>(old).is_err());
        let wrong = ReportWire {
            schema_version: SCHEMA_VERSION,
            job: FixedCiJob::Check,
            source_revision: "a".repeat(40),
            localtx_contract_ids: vec!["identity.session-created".to_owned()],
        };
        assert!(validate_wire(&wrong).is_err());
        let unknown = format!(
            r#"{{"schemaVersion":4,"job":"integration-critical","sourceRevision":"{}","localtxContractIds":["identity.session-created"],"unexpected":true}}"#,
            "a".repeat(40)
        );
        assert!(serde_json::from_str::<ReportWire>(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn upload_consumer_rejects_a_nonempty_wrong_contract_set() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let fixture = crate::testutil::unique_tmp("localtx-upload-consumer");
        fs::create_dir_all(&fixture)?;
        let input = fixture.join("input.json");
        let output = fixture.join("validated.json");
        let wrong = ReportWire {
            schema_version: SCHEMA_VERSION,
            job: OWNER,
            source_revision: crate::cmd::source_revision(&root)?,
            localtx_contract_ids: vec!["identity.session-created".to_owned()],
        };
        fs::write(&input, serde_json::to_vec(&wrong)?)?;
        assert!(validate_upload_snapshot(&input, &output, &root, facts).is_err());
        assert!(!output.exists());
        let replacement = fixture.join("replacement.json");
        fs::write(&replacement, serde_json::to_vec(&wrong)?)?;
        assert!(
            read_stable_ordinary_file(&input, || {
                fs::remove_file(&input)?;
                fs::rename(&replacement, &input)?;
                Ok(())
            })
            .is_err()
        );
        fs::remove_dir_all(fixture)?;
        Ok(())
    }
}
