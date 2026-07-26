//! inbox receipt runtime cutover source guard.
//!
//! INVARIANT: INBOX-RECEIPTS-CUTOVER-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_rejects_legacy_table_and_const_tokens", anti_vacuity = "tests::scan_accepts_current_receipt_name" }——
//! production sources must use the tenant-scoped receipt table after the cutover; legacy receipt storage names may
//! remain only in historical migrations and the retirement migration.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    LegacyReceiptReference,
}

pub(crate) struct InboxCutoverGuard;

impl GovernanceCheck for InboxCutoverGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "inbox-cutover-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let findings = scan_workspace(&root)?;
        Ok((
            "生产源已切到 inbox_receipts；旧 receipt storage token 仅保留在历史迁移白名单"
                .to_string(),
            findings,
        ))
    }
}

fn legacy_table_token() -> String {
    ["inbox", "_dedup"].concat()
}

fn legacy_const_token() -> String {
    ["INBOX_", "DEDUP"].concat()
}

fn forbidden_tokens() -> [String; 2] {
    [legacy_table_token(), legacy_const_token()]
}

fn scan_workspace(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let allow = allowed_paths();
    let mut findings = Vec::new();
    for path in scannable_files(root)? {
        let rel = rel_path(root, &path);
        if allow.iter().any(|allowed| rel == Path::new(allowed)) {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("inbox-cutover-guard: read {}", path.display()))?;
        findings.extend(scan_content(&rel, &content));
    }
    Ok(findings)
}

fn scannable_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_scannable_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_scannable_files(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("inbox-cutover-guard: read dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if should_skip_dir(root, &path) {
                continue;
            }
            collect_scannable_files(root, &path, files)?;
        } else if file_type.is_file() && is_scannable_file(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn should_skip_dir(root: &Path, path: &Path) -> bool {
    let rel = rel_path(root, path);
    let mut segments = rel
        .components()
        .filter_map(|component| component.as_os_str().to_str());
    matches!(
        segments.next(),
        Some(".cache" | ".git" | ".nextest" | "target" | "worktrees")
    )
}

fn is_scannable_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("rs" | "sql" | "toml" | "yaml" | "yml")
    )
}

fn scan_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let forbidden = forbidden_tokens();
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        for token in &forbidden {
            if line.contains(token) {
                findings.push(finding(
                    Rule::LegacyReceiptReference,
                    format!("{}:{}", path.display(), idx + 1),
                    format!(
                        "旧 receipt storage token `{token}` 已退役；生产载体应使用 `inbox_receipts`"
                    ),
                ));
            }
        }
    }
    findings
}

fn allowed_paths() -> Vec<String> {
    let legacy = legacy_table_token();
    vec![
        "adapters/postgres/migrations/0001_init_schema.sql".to_string(),
        format!("adapters/postgres/migrations/0002_create_{legacy}.sql"),
        "adapters/postgres/migrations/0014_add_inbox_lease.sql".to_string(),
        format!("adapters/postgres/migrations/0020_add_{legacy}_sweep_index.sql"),
        "adapters/postgres/migrations/0030_grant_runtime_serving.sql".to_string(),
        "adapters/postgres/migrations/0038_create_inbox_receipts.sql".to_string(),
        format!("adapters/postgres/migrations/0039_retire_{legacy}.sql"),
    ]
}

fn rel_path(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_rejects_legacy_table_and_const_tokens() {
        let content = format!(
            "SELECT * FROM {};\nlet _ = {}_RETENTION_SECONDS;",
            legacy_table_token(),
            legacy_const_token()
        );
        let findings = scan_content(Path::new("crates/runtime/src/lib.rs"), &content);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::LegacyReceiptReference)
        );
    }

    #[test]
    fn allowlist_contains_retirement_migration_without_literal_source_token() {
        let legacy = legacy_table_token();
        assert!(
            allowed_paths()
                .iter()
                .any(|path| path.ends_with(&format!("0039_retire_{legacy}.sql")))
        );
    }

    #[test]
    fn scan_accepts_current_receipt_name() {
        let findings = scan_content(
            Path::new("adapters/postgres/src/inbox.rs"),
            "SELECT * FROM inbox_receipts",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn markdown_is_not_a_scannable_carrier() {
        assert!(!is_scannable_file(Path::new(
            "docs/architecture/cutover.md"
        )));
        assert!(is_scannable_file(Path::new(
            "adapters/postgres/migrations/0039.sql"
        )));
    }

    #[test]
    fn workspace_scan_ignores_local_build_cache_snapshots() -> anyhow::Result<()> {
        let root = crate::testutil::unique_tmp("inbox-cutover-cache");
        let cached = root.join(".cache/cargo-target/ci-local-sources/base/tree");
        std::fs::create_dir_all(&cached)?;
        std::fs::write(cached.join("historical.sql"), legacy_table_token())?;
        assert!(scan_workspace(&root)?.is_empty());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
