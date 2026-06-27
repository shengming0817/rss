//! `migrations-serial` —— migration 序号唯一性 + 连续性守卫（AI-robust **Medium** 内容扫描门）。
//!
//! 扫 `adapters/postgres/migrations/*.sql`，校验文件名前缀 `{4位序号}_{描述}.sql` 的序号：
//!   - **唯一性**：任意两文件序号相同 → 门红，列出冲突序号 + 涉及文件名。
//!   - **连续性**：排序后须从 `0001` 起步长 1 无缺号（`0001..=N`）。
//!
//! 背景：此前两个 PR 各自加了同序号 `0013` 迁移（重号），sqlx 按 `version` 键迁移 →
//! 重号让 `run_migrations` 在任意 fresh DB 上失败；本门补上该无机器门的 governance 缺口。
//!
//! INVARIANT: MIGRATION-SERIAL-UNIQUE-01 —— migrations 目录的 SQL 文件序号必须：
//!   ① 唯一（任意两文件序号不同）；
//!   ② 从 0001 起、步长 1、连续到最大序号（无缺号）。
//!   重号或缺号均让 `sqlx::migrate!` 在任意 fresh DB 上失败。
//!
//! **评级**：Medium（内容扫描门，接入 `cargo xtask verify`，no-compile meta 步）。
//!
//! **盲区**（文件名扫描，不读 SQL 内容）：
//!   - 仅校验文件名前缀的数字序号；不解析 sqlx migration 内部版本字段。
//!   - 不校验文件名 `{描述}` 部分（可自由命名）。
//!   - 序号必须以 4 位数字 `0001`–`9999` 开头（`0000` 视为格式错误）。
//!
//! `ref: xtask/src/schema_rls.rs`（内容扫描守卫范式）

use anyhow::{Context, Result};
use std::collections::BTreeSet;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// MIGRATION-SERIAL-UNIQUE-01：文件名不以 4 位正整数序号 + 下划线开头（格式错误）。
    ParseError,
    /// MIGRATION-SERIAL-UNIQUE-01：两个或以上文件具有相同序号（重号）。
    DuplicateSerial,
    /// MIGRATION-SERIAL-UNIQUE-01：序号不连续（应从 0001 起步长 1 无缺号）。
    GapInSerial,
}

pub(crate) struct MigrationSerialGuard;

impl GovernanceCheck for MigrationSerialGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "migrations-serial"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let dir = root.join("adapters").join("postgres").join("migrations");
        let filenames = load_sql_filenames(&dir)?;
        let fname_refs: Vec<&str> = filenames.iter().map(String::as_str).collect();
        Ok(validate_serials(&fname_refs))
    }
}

/// 读迁移目录下全部 `.sql` 文件名（按文件名排序确保确定性；不读文件内容）。
fn load_sql_filenames(dir: &std::path::Path) -> Result<Vec<String>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("读迁移目录 {} 失败", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "遍历迁移目录条目失败")?;
    entries.sort_by_key(|e| e.file_name());
    let mut names = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "sql") {
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            names.push(fname);
        }
    }
    Ok(names)
}

// ---- 纯函数校验逻辑（输入文件名列表，便于 synthetic 单测）----

/// 从文件名解析 4 位数字序号（须为 1..=9999 且紧跟 `_`）。格式不符返回 `None`。
///
/// 示例：`"0001_init_schema.sql"` → `Some(1)`；`"readme.sql"` / `"0001foo.sql"` → `None`。
pub(crate) fn parse_serial(filename: &str) -> Option<i64> {
    let prefix = filename.get(..4)?;
    let n: i64 = prefix.parse().ok()?;
    let fifth = filename.as_bytes().get(4).copied()?;
    (fifth == b'_' && n >= 1).then_some(n)
}

/// 序号唯一性 + 连续性校验纯函数（不读 FS，便于 synthetic 单测）。
///
/// 步骤：
/// 1. 解析每个文件名前缀为 `i64`；格式错误报 [`Rule::ParseError`]（有则早返，跳过后续校验）。
/// 2. 排序后检查相邻重号 → [`Rule::DuplicateSerial`]（有则早返，跳过连续性校验）。
/// 3. 检查是否从 0001 起步长 1 无缺号 → [`Rule::GapInSerial`]。
/// 4. 无 finding → 返回含文件数的成功摘要。
pub(crate) fn validate_serials(filenames: &[&str]) -> (String, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut parsed: Vec<(i64, &str)> = Vec::new();

    for &fname in filenames {
        match parse_serial(fname) {
            Some(n) => parsed.push((n, fname)),
            None => findings.push(finding(
                Rule::ParseError,
                fname,
                "文件名未以 4 位正整数序号 + 下划线开头（期望格式：0001_desc.sql）",
            )),
        }
    }
    if !findings.is_empty() {
        return (String::new(), findings);
    }

    parsed.sort_unstable_by_key(|&(n, _)| n);

    for w in parsed.windows(2) {
        if w[0].0 == w[1].0 {
            findings.push(finding(
                Rule::DuplicateSerial,
                format!("{:04}", w[0].0),
                format!("序号 {:04} 重复：「{}」与「{}」", w[0].0, w[0].1, w[1].1),
            ));
        }
    }
    if !findings.is_empty() {
        return (String::new(), findings);
    }

    // 无重号 → 检查连续性（0001..=max_serial 无缺号）
    let max_serial = parsed.last().map(|&(n, _)| n).unwrap_or(0);
    let present: BTreeSet<i64> = parsed.iter().map(|&(n, _)| n).collect();
    for expected in 1..=max_serial {
        if !present.contains(&expected) {
            findings.push(finding(
                Rule::GapInSerial,
                format!("{:04}", expected),
                format!(
                    "缺序号 {:04}（序列应为 0001..={:04} 无缺号）",
                    expected, max_serial
                ),
            ));
        }
    }

    if findings.is_empty() {
        let n = parsed.len();
        let summary = if n == 0 {
            "0 个迁移文件（目录为空）".to_string()
        } else {
            format!(
                "{n} 个迁移文件序号唯一且连续（{:04}–{:04}）",
                parsed[0].0, max_serial
            )
        };
        (summary, vec![])
    } else {
        (String::new(), findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- green ----

    #[test]
    fn green_three_consecutive() {
        let fnames = ["0001_a.sql", "0002_b.sql", "0003_c.sql"];
        let (summary, findings) = validate_serials(&fnames);
        assert!(findings.is_empty(), "连续序号不应有 finding: {findings:?}");
        assert!(summary.contains('3'), "摘要应含文件数: {summary}");
    }

    #[test]
    fn green_single_file() {
        let (_, findings) = validate_serials(&["0001_init.sql"]);
        assert!(findings.is_empty(), "单文件应 PASS: {findings:?}");
    }

    #[test]
    fn green_empty_dir() {
        let (summary, findings) = validate_serials(&[]);
        assert!(findings.is_empty(), "空目录应 PASS");
        assert!(summary.contains('0'), "空目录摘要应含 0: {summary}");
    }

    // ---- red: ParseError ----

    #[test]
    fn red_parse_error_bad_prefix() {
        let fnames = ["readme.sql", "0002_b.sql"];
        let (_, findings) = validate_serials(&fnames);
        assert_eq!(findings.len(), 1, "应报 1 条 ParseError: {findings:?}");
        assert_eq!(findings[0].rule, Rule::ParseError);
        assert_eq!(findings[0].subject, "readme.sql");
    }

    #[test]
    fn red_parse_error_no_underscore() {
        let (_, findings) = validate_serials(&["0001foo.sql"]);
        assert_eq!(findings.len(), 1, "缺下划线应报 ParseError: {findings:?}");
        assert_eq!(findings[0].rule, Rule::ParseError);
    }

    #[test]
    fn red_parse_error_zero_serial() {
        // 0000 不合法（序号须 >= 1）
        let (_, findings) = validate_serials(&["0000_foo.sql"]);
        assert_eq!(findings.len(), 1, "0000 应报 ParseError: {findings:?}");
        assert_eq!(findings[0].rule, Rule::ParseError);
    }

    // ---- red: DuplicateSerial（anti-vacuity）----

    /// anti-vacuity 红例：重号 0001 → Err，错误含序号 + 两文件名。
    #[test]
    fn red_duplicate_serial() {
        let fnames = ["0001_a.sql", "0001_b.sql"];
        let (_, findings) = validate_serials(&fnames);
        assert_eq!(findings.len(), 1, "应报 1 条 DuplicateSerial: {findings:?}");
        assert_eq!(findings[0].rule, Rule::DuplicateSerial);
        assert!(
            findings[0].subject.contains("0001"),
            "subject 须含冲突序号: {}",
            findings[0].subject
        );
        assert!(
            findings[0].detail.contains("0001_a.sql"),
            "detail 须含 0001_a.sql: {}",
            findings[0].detail
        );
        assert!(
            findings[0].detail.contains("0001_b.sql"),
            "detail 须含 0001_b.sql: {}",
            findings[0].detail
        );
    }

    #[test]
    fn red_multiple_duplicates() {
        let fnames = ["0001_a.sql", "0001_b.sql", "0002_c.sql", "0002_d.sql"];
        let (_, findings) = validate_serials(&fnames);
        assert_eq!(findings.len(), 2, "两对重号应报 2 条 finding: {findings:?}");
        assert!(findings.iter().all(|f| f.rule == Rule::DuplicateSerial));
    }

    // ---- red: GapInSerial（anti-vacuity）----

    /// anti-vacuity 红例：缺号 0002 → Err（连续性检查生效）。
    #[test]
    fn red_gap_in_serial() {
        let fnames = ["0001_a.sql", "0003_c.sql"];
        let (_, findings) = validate_serials(&fnames);
        assert!(!findings.is_empty(), "缺序号应报 finding: {findings:?}");
        assert_eq!(findings[0].rule, Rule::GapInSerial);
        assert!(
            findings[0].subject.contains("0002"),
            "subject 须含缺失序号 0002: {}",
            findings[0].subject
        );
    }

    #[test]
    fn red_starts_from_two_not_one() {
        let fnames = ["0002_a.sql", "0003_b.sql"];
        let (_, findings) = validate_serials(&fnames);
        assert_eq!(
            findings.len(),
            1,
            "从 0002 起始（缺 0001）应报 1 条: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::GapInSerial);
        assert!(
            findings[0].subject.contains("0001"),
            "subject 须含 0001: {}",
            findings[0].subject
        );
    }

    #[test]
    fn red_multiple_gaps() {
        let fnames = ["0001_a.sql", "0005_e.sql"];
        let (_, findings) = validate_serials(&fnames);
        // 缺 0002, 0003, 0004 → 3 条 GapInSerial
        assert_eq!(findings.len(), 3, "3 个缺号应报 3 条 finding: {findings:?}");
        assert!(findings.iter().all(|f| f.rule == Rule::GapInSerial));
    }

    // ---- parse_serial 单元测试 ----

    #[test]
    fn parse_serial_valid() {
        assert_eq!(parse_serial("0001_init.sql"), Some(1));
        assert_eq!(parse_serial("0018_foo_bar.sql"), Some(18));
        assert_eq!(parse_serial("9999_max.sql"), Some(9999));
    }

    #[test]
    fn parse_serial_invalid() {
        assert_eq!(parse_serial("readme.md"), None); // 非数字前缀
        assert_eq!(parse_serial("0001foo.sql"), None); // 无下划线（第5位非 '_'）
        assert_eq!(parse_serial("abc_foo.sql"), None); // 字母前缀
        assert_eq!(parse_serial("001_short.sql"), None); // 3 位（"001_" 解析失败）
        assert_eq!(parse_serial(""), None); // 空字符串
        assert_eq!(parse_serial("0000_foo.sql"), None); // 0 不合法（须 >= 1）
    }
}
