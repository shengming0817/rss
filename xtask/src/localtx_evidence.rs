//! Semantic LocalTx exact-set report produced by the fixed integration job.
//!
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-FUNNEL-01 { level = "Hard", exec = "native-compile", source = "code", native = "LocalTxEvidenceRequest::publish requires PostgresDomainPassed and VerifiedLocalTxContractSet" }.
//! INVARIANT: LOCALTX-REQUIRED-EVIDENCE-WIRE-01 { level = "Hard", exec = "native-compile", source = "code", native = "deny_unknown_fields fixes the v4 semantic report and its FixedCiJob owner" }.

use crate::ci_lanes::FixedCiJob;
use crate::localtx_coverage::VerifiedLocalTxContractSet;
use crate::verify::PostgresDomainPassed;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
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
    let parent = path
        .parent()
        .context("LocalTx report output must have a parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create LocalTx report directory {}", parent.display()))?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("LocalTx report output must be an ordinary file");
        }
        fs::remove_file(path).with_context(|| format!("replace {}", path.display()))?;
    }
    Ok(())
}

fn atomic_publish(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("LocalTx report output has no parent")?;
    let temporary = parent.join(format!(".localtx-required-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    let result: std::io::Result<()> = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("publish LocalTx report atomically")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        Ok(())
    }
}
