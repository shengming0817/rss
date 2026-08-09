//! Best-effort PR-local progress ledger for resumable local verification.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

pub(crate) const PATH_ENV: &str = "RSS_LOCAL_CI_LEDGER_PATH";
pub(crate) const BRANCH_ENV: &str = "RSS_LOCAL_CI_LEDGER_BRANCH";
const SCHEMA_VERSION: u32 = 1;
const RELATIVE_PATH: &str = "rss-local-ci/checkpoint-v1.json";
static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredLedger {
    schema_version: u32,
    branch: String,
    passed: BTreeSet<String>,
}

impl StoredLedger {
    fn empty(branch: String) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            branch,
            passed: BTreeSet::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct LocalRunLedger {
    path: PathBuf,
    state: StoredLedger,
}

impl LocalRunLedger {
    #[cfg(test)]
    pub(crate) fn fixture(path: PathBuf, branch: &str) -> Result<Self> {
        Self::open(path, branch.to_owned())
    }

    /// Resolve the caller worktree ledger. Detached callers deliberately run without resume.
    pub(crate) fn for_worktree(root: &Path) -> Result<Option<Self>> {
        let Some(branch) = git_branch(root)? else {
            eprintln!("local resume：detached HEAD，禁用 checkpoint");
            return Ok(None);
        };
        let path = git_path(root)?;
        Self::open(path, branch).map(Some)
    }

    /// The provenance-checked snapshot worker receives the attached caller ledger explicitly.
    pub(crate) fn for_local_worker() -> Result<Option<Self>> {
        match (std::env::var_os(PATH_ENV), std::env::var_os(BRANCH_ENV)) {
            (Some(path), Some(branch)) => {
                let branch = branch
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{BRANCH_ENV} 不是 UTF-8"))?;
                Self::open(PathBuf::from(path), branch).map(Some)
            }
            (None, None) => Ok(None),
            _ => bail!("{PATH_ENV} 与 {BRANCH_ENV} 必须同时设置"),
        }
    }

    /// Direct `verify --fast` uses the current attached worktree; full verify has no ledger.
    pub(crate) fn for_verify(root: &Path, direct_fast: bool) -> Result<Option<Self>> {
        if direct_fast {
            Self::for_worktree(root)
        } else {
            Ok(None)
        }
    }

    fn open(path: PathBuf, branch: String) -> Result<Self> {
        let state = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<StoredLedger>(&bytes) {
                Ok(state) if state.schema_version == SCHEMA_VERSION && state.branch == branch => {
                    state
                }
                Ok(_) => {
                    eprintln!("local resume：checkpoint schema/branch 不匹配，按空状态重跑");
                    StoredLedger::empty(branch)
                }
                Err(error) => {
                    eprintln!("local resume：checkpoint 损坏，按空状态重跑：{error}");
                    StoredLedger::empty(branch)
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                StoredLedger::empty(branch)
            }
            Err(error) => {
                eprintln!("local resume：读取 checkpoint 失败，按空状态重跑：{error}");
                StoredLedger::empty(branch)
            }
        };
        Ok(Self { path, state })
    }

    pub(crate) fn contains(&self, unit: &str) -> bool {
        self.state.passed.contains(unit)
    }

    pub(crate) fn mark_passed(&mut self, unit: String) {
        if !self.state.passed.insert(unit) {
            return;
        }
        if let Err(error) = self.persist() {
            eprintln!("local resume：保存 checkpoint 失败；本次结果有效，下次将重跑：{error:#}");
        }
    }

    pub(crate) fn fresh(&mut self) -> Result<()> {
        self.state.passed.clear();
        self.persist().context("清空 local resume checkpoint")
    }

    fn persist(&self) -> Result<()> {
        let parent = self.path.parent().context("checkpoint 路径缺少父目录")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("创建 checkpoint 目录 {}", parent.display()))?;
        let bytes = serde_json::to_vec_pretty(&self.state).context("序列化 checkpoint")?;
        let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".checkpoint-v1.json.tmp-{}-{nonce}",
            std::process::id()
        ));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .with_context(|| format!("创建 {}", temporary.display()))?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path).with_context(|| {
                format!(
                    "发布 checkpoint {} -> {}",
                    temporary.display(),
                    self.path.display()
                )
            })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn git_branch(root: &Path) -> Result<Option<String>> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
        &[],
        Some(root),
    )
    .output()
    .context("解析 checkpoint branch")?;
    if !output.status.success() {
        return Ok(None);
    }
    let branch = String::from_utf8(output.stdout).context("checkpoint branch 不是 UTF-8")?;
    Ok(Some(branch.trim().to_owned()))
}

fn git_path(root: &Path) -> Result<PathBuf> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["rev-parse", "--git-path", RELATIVE_PATH],
        &[],
        Some(root),
    )
    .output()
    .context("解析 checkpoint git path")?;
    if !output.status.success() {
        bail!("git rev-parse --git-path {RELATIVE_PATH} 失败");
    }
    let raw = String::from_utf8(output.stdout).context("checkpoint git path 不是 UTF-8")?;
    let path = PathBuf::from(raw.trim());
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_fresh_and_branch_mismatch() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("local-run-ledger");
        fs::create_dir_all(&root)?;
        let path = root.join("checkpoint.json");
        let mut ledger = LocalRunLedger::open(path.clone(), "feature/a".to_owned())?;
        ledger.mark_passed("gate:fmt".to_owned());
        assert!(LocalRunLedger::open(path.clone(), "feature/a".to_owned())?.contains("gate:fmt"));
        assert!(!LocalRunLedger::open(path.clone(), "feature/b".to_owned())?.contains("gate:fmt"));
        ledger.fresh()?;
        assert!(!LocalRunLedger::open(path, "feature/a".to_owned())?.contains("gate:fmt"));
        Ok(())
    }

    #[test]
    fn corrupt_checkpoint_is_empty() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("local-run-ledger-corrupt");
        fs::create_dir_all(&root)?;
        let path = root.join("checkpoint.json");
        fs::write(&path, b"not-json")?;
        assert!(!LocalRunLedger::open(path, "feature/a".to_owned())?.contains("gate:fmt"));
        Ok(())
    }

    #[test]
    fn detached_worktree_cannot_open_or_inherit_a_resume_ledger() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("local-run-ledger-detached");
        fs::create_dir_all(&root)?;
        let status = crate::cmd::external_cmd(
            crate::cmd::ExternalProgram::SystemGit,
            &["init", "-q"],
            &[],
            Some(&root),
        )
        .status()?;
        assert!(status.success());
        fs::write(root.join(".git/HEAD"), format!("{}\n", "0".repeat(40)))?;

        assert!(LocalRunLedger::for_worktree(&root)?.is_none());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
