//! `setlocal-funnel` —— tenant-scope SET-LOCAL 单漏斗守卫（AI-robust **Medium** 内容扫描门）。
//!
//! 扫 `adapters/postgres/src/` 下全部生产 Rust 源文件，断言 tenant-scope GUC 写入仅出现在
//! `adapters/postgres/src/cotx/mod.rs`（单 typed 漏斗函数 `set_local_tenant`）。把「租户 scope 注入只经一处」
//! 从注释约定升为机器可判定门。检测经**归一化**（去空白 + 小写）匹配 [`FUNNEL_NEEDLES`]——覆盖
//! `set_config('rss.tenant_id'` 的空白变体与裸 `SET LOCAL rss.tenant_id =/to` 赋值式（不止裸字面量，F4）；
//! 放行做**路径精确**匹配（相对 src 根的 `cotx/mod.rs`，嵌套同名 `sub/cotx.rs` 不放行，F4）。
//!
//! INVARIANT: TENANCY-SETLOCAL-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" }—— `set_config('rss.tenant_id'` 字面量在
//!   生产 postgres adapter 源中只能出现在 `cotx/mod.rs`；任何其他生产文件含此串
//!   → [`Rule::FunnelEscape`] finding（违反单漏斗）；`cotx/mod.rs` 若完全不含该串
//!   → [`Rule::FunnelAbsent`] finding（守卫真空化——漏斗被移除或重命名）。
//!
//! **评级**：Medium（内容扫描门，接入 `cargo xtask verify`，no-compile meta 步）。
//!
//! **盲区**（文本级扫描，非 Rust AST；故意不引重型解析器，匹配 xtask 轻量设计）：
//!   - 生产文件内 `#[cfg(test)] mod tests { ... }` 内联测试块：本守卫不解析 cfg 属性、
//!     不豁免内联测试块——若内联块含字面量仍会被捕获（文本扫描载体固有局限）。
//!     残留盲区，需 review 兜底；`integration_tests.rs` 等独立测试文件按文件名/目录豁免。
//!   - raw 字符串（`r"..."` / `r#"..."#`）不特判（罕见）。
//!
//! `ref: xtask/src/schema_rls.rs`（内容扫描守卫范式）

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// TENANCY-SETLOCAL-FUNNEL-01：`set_config('rss.tenant_id'` 出现在 `cotx/mod.rs`
    /// 以外的生产文件（单漏斗逃逸）。
    FunnelEscape,
    /// TENANCY-SETLOCAL-FUNNEL-01：`cotx/mod.rs` 完全不含 `set_config('rss.tenant_id'`——
    /// 漏斗被移除或重命名，守卫真空化（反真空检测）。
    FunnelAbsent,
}

/// funnel 字面量（display 用，finding 文案）。检测经 [`contains_funnel`] 归一化匹配 [`FUNNEL_NEEDLES`]。
const FUNNEL_LITERAL: &str = "set_config('rss.tenant_id'";

/// 唯一允许含 funnel 写入的生产文件（**相对 `adapters/postgres/src` 的路径**，路径精确——
/// 嵌套同名 `sub/cotx.rs` / 历史 `cotx.rs` 单文件形态不放行）。
const ALLOWED_FILE: &str = "cotx/mod.rs";

/// 归一化（去全部空白 + 小写）后的 tenant-scope GUC **写入**特征。归一化使空白变体（`set_config ( '…`）
/// 与裸 `SET LOCAL` 赋值式均被覆盖（F4：不止裸字面量）。SET-LOCAL 特征锚定赋值号 `=` / `to`，避开散文注释
/// 「SET LOCAL rss.tenant_id」的误报（散文无赋值号）。
const FUNNEL_NEEDLES: &[&str] = &[
    "set_config('rss.tenant_id'", // set_config 函数式（容忍 `set_config ( '…` 空白变体）
    "setlocalrss.tenant_id=",     // SET LOCAL rss.tenant_id = …（裸赋值式）
    "setlocalrss.tenant_idto",    // SET LOCAL rss.tenant_id TO …
];

/// 归一化文本：去全部空白 + 小写（使空白 / 大小写变体收敛到同一特征串）。
fn normalize_sql(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase()
}

/// 文件内容是否含 tenant-scope GUC 写入（经归一化匹配 [`FUNNEL_NEEDLES`] 任一）。
fn contains_funnel(content: &str) -> bool {
    let norm = normalize_sql(content);
    FUNNEL_NEEDLES.iter().any(|n| norm.contains(n))
}

/// SET-LOCAL 单漏斗守卫（TENANCY-SETLOCAL-FUNNEL-01）。
pub(crate) struct SetLocalFunnelGuard;

impl GovernanceCheck for SetLocalFunnelGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "setlocal-funnel"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let src_dir = root.join("adapters").join("postgres").join("src");
        let files = load_prod_files(&src_dir)?;
        let (summary, findings) = scan_funnel(&files);
        Ok((summary, findings))
    }
}

/// 递归读 `dir` 下全部生产 `.rs` 文件（排除测试文件）。
/// 返回 `(相对 dir 的路径, 内容)` 列表（按路径排序，确定性）。相对路径（非纯文件名）使
/// 漏斗放行可做**路径精确**匹配——嵌套同名 `sub/cotx.rs` 不会被基名误放行（F4）。
fn load_prod_files(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut paths = collect_rs_paths(dir)?;
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        if is_test_file(&path) {
            continue;
        }
        // 相对 src 根的路径（forward-slash 归一），用于路径精确放行 `cotx/mod.rs`。
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("读 {} 失败", path.display()))?;
        files.push((rel, content));
    }
    Ok(files)
}

/// 递归收集目录下全部 `.rs` 路径（不过滤，过滤在 [`load_prod_files`] 层）。
fn collect_rs_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("遍历 {} 失败", dir.display()))?
    {
        let path = entry
            .with_context(|| format!("读条目失败（{}）", dir.display()))?
            .path();
        if path.is_dir() {
            out.extend(collect_rs_paths(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(out)
}

/// 判断路径是否为测试文件（应豁免扫描）。
///
/// 豁免规则（三档）：
/// - 文件名为 `integration_tests.rs`
/// - 文件名以 `_test.rs` 或 `_tests.rs` 结尾
/// - 任意祖先路径段名为 `tests`（位于 `tests/` 目录下）
fn is_test_file(path: &Path) -> bool {
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if stem == "integration_tests.rs" || stem.ends_with("_test.rs") || stem.ends_with("_tests.rs") {
        return true;
    }
    // 检查任意祖先路径段是否为 "tests"（目录级豁免）。
    path.components().any(|c| c.as_os_str() == "tests")
}

// ---- 纯函数扫描逻辑（输入 &[(文件名, 内容)]，便于 synthetic 单测）----

/// 主扫描纯函数：输入已过滤的生产文件列表，返回 `(摘要, findings)`。
///
/// - 若任意非 `cotx/mod.rs` 文件含 [`FUNNEL_LITERAL`] → [`Rule::FunnelEscape`]。
/// - 若 `cotx/mod.rs` 不含 [`FUNNEL_LITERAL`] → [`Rule::FunnelAbsent`]（反真空）。
pub(crate) fn scan_funnel(files: &[(String, String)]) -> (String, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut cotx_has_literal = false;
    for (rel_path, content) in files {
        if is_cotx_path(rel_path) {
            if contains_funnel(content) {
                cotx_has_literal = true;
            }
        } else if contains_funnel(content) {
            findings.push(finding(
                Rule::FunnelEscape,
                rel_path,
                format!(
                    "含 tenant-scope GUC 写入（`{FUNNEL_LITERAL}` 等价式，仅 {ALLOWED_FILE} 允许）"
                ),
            ));
        }
    }
    if !cotx_has_literal {
        findings.push(finding(
            Rule::FunnelAbsent,
            ALLOWED_FILE,
            format!("`{ALLOWED_FILE}` 不含 `{FUNNEL_LITERAL}`——漏斗被移除或重命名，守卫真空化"),
        ));
    }
    let summary = format!(
        "单漏斗完整（`{ALLOWED_FILE}` 含字面量，{} 个生产文件扫描通过）",
        files.len()
    );
    (summary, findings)
}

/// 判断相对路径是否为允许的漏斗文件（路径精确 `cotx/mod.rs`——嵌套同名不放行）。
fn is_cotx_path(rel_path: &str) -> bool {
    rel_path == ALLOWED_FILE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(n, c)| ((*n).to_string(), (*c).to_string()))
            .collect()
    }

    // ---- green：仅 cotx/mod.rs 含字面量 → 0 findings ----

    #[test]
    fn green_only_cotx_has_literal() {
        let fs = files(&[
            (
                "cotx/mod.rs",
                "pub fn set_local_tenant() { \
                 let _ = sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\"); }",
            ),
            ("auth_grant_lifecycle.rs", "pub fn create_session() {}"),
            ("pool.rs", "pub fn pool() {}"),
        ]);
        let (_, findings) = scan_funnel(&fs);
        assert!(
            findings.is_empty(),
            "仅 cotx/mod.rs 含字面量不应有 findings: {findings:?}"
        );
    }

    // ---- red：非 cotx/mod.rs 文件含字面量 → FunnelEscape ----

    #[test]
    fn red_funnel_escape_non_cotx_file() {
        let fs = files(&[
            (
                "cotx/mod.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "auth_grant_lifecycle.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
        ]);
        let (_, findings) = scan_funnel(&fs);
        assert_eq!(
            findings.len(),
            1,
            "应仅报 1 条 FunnelEscape finding: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::FunnelEscape);
        assert_eq!(findings[0].subject, "auth_grant_lifecycle.rs");
    }

    // ---- red：多个非 cotx/mod.rs 文件含字面量 → 多条 FunnelEscape ----

    #[test]
    fn red_multiple_escapes() {
        let fs = files(&[
            (
                "cotx/mod.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "file_a.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "file_b.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
        ]);
        let (_, findings) = scan_funnel(&fs);
        let escapes: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == Rule::FunnelEscape)
            .collect();
        assert_eq!(
            escapes.len(),
            2,
            "两个逃逸文件应报 2 条 FunnelEscape: {findings:?}"
        );
    }

    // ---- anti-vacuity：cotx/mod.rs 不含字面量 → FunnelAbsent ----

    #[test]
    fn anti_vacuity_funnel_absent_cotx_lacks_literal() {
        let fs = files(&[
            ("cotx/mod.rs", "pub fn set_local_tenant() {}"),
            ("other.rs", "pub fn foo() {}"),
        ]);
        let (_, findings) = scan_funnel(&fs);
        assert_eq!(
            findings.len(),
            1,
            "cotx/mod.rs 不含字面量应报 FunnelAbsent: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::FunnelAbsent);
        assert_eq!(findings[0].subject, ALLOWED_FILE);
    }

    // ---- anti-vacuity：无 cotx/mod.rs 文件时 → FunnelAbsent ----

    #[test]
    fn anti_vacuity_funnel_absent_no_cotx_file() {
        let fs = files(&[("other.rs", "pub fn foo() {}")]);
        let (_, findings) = scan_funnel(&fs);
        assert!(
            findings.iter().any(|f| f.rule == Rule::FunnelAbsent),
            "无 cotx/mod.rs 应报 FunnelAbsent: {findings:?}"
        );
    }

    // ---- is_test_file 单元测试 ----

    #[test]
    fn is_test_file_integration_tests_rs() {
        assert!(
            is_test_file(Path::new("/adapters/postgres/src/integration_tests.rs")),
            "integration_tests.rs 应被豁免"
        );
    }

    #[test]
    fn is_test_file_suffix_test_and_tests() {
        assert!(
            is_test_file(Path::new("/foo/auth_grant_lifecycle_test.rs")),
            "_test.rs 后缀应被豁免"
        );
        assert!(
            is_test_file(Path::new("/foo/auth_grant_lifecycle_tests.rs")),
            "_tests.rs 后缀应被豁免"
        );
    }

    #[test]
    fn is_test_file_tests_directory() {
        assert!(
            is_test_file(Path::new("/foo/tests/bar.rs")),
            "tests/ 目录下的文件应被豁免"
        );
        assert!(
            is_test_file(Path::new("/foo/tests/subdir/baz.rs")),
            "tests/ 子目录下的文件应被豁免"
        );
    }

    #[test]
    fn is_test_file_production_files_not_matched() {
        assert!(
            !is_test_file(Path::new("/foo/cotx.rs")),
            "cotx.rs 不是测试文件"
        );
        assert!(
            !is_test_file(Path::new("/foo/auth_grant_lifecycle.rs")),
            "auth_grant_lifecycle.rs 不是测试文件"
        );
        // test_pg.rs：以 test_ 开头但不以 _test.rs / _tests.rs 结尾，不豁免。
        assert!(
            !is_test_file(Path::new("/foo/test_pg.rs")),
            "test_pg.rs 以 test_ 开头而非 _test.rs 结尾，不豁免"
        );
    }

    // ---- is_cotx_path 单元测试（路径精确，非基名）----

    #[test]
    fn is_cotx_path_exact_only() {
        assert!(is_cotx_path("cotx/mod.rs"));
        assert!(!is_cotx_path("cotx.rs"));
        assert!(!is_cotx_path("cotx2.rs"));
        assert!(!is_cotx_path("auth_grant_lifecycle.rs"));
        // 嵌套同名不放行（路径精确，防基名绕过）。
        assert!(!is_cotx_path("sub/cotx.rs"));
        assert!(!is_cotx_path("nested/dir/cotx.rs"));
    }

    // ---- red：嵌套 sub/cotx.rs 含字面量 → FunnelEscape（基名匹配会误放行，路径精确则拒）----

    #[test]
    fn red_nested_cotx_path_not_allowed() {
        let fs = files(&[
            (
                "cotx/mod.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "sub/cotx.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
        ]);
        let (_, findings) = scan_funnel(&fs);
        assert_eq!(
            findings.len(),
            1,
            "嵌套 cotx.rs 应报 FunnelEscape: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::FunnelEscape);
        assert_eq!(findings[0].subject, "sub/cotx.rs");
    }

    // ---- red：SQL 归一化捕获空白变体 + 裸 SET LOCAL 赋值（不止裸字面量）----

    #[test]
    fn red_sql_variants_caught_after_normalization() {
        // 空白变体的 set_config + 裸 SET LOCAL 赋值，分处两个非 cotx 文件，均应被捕获。
        let fs = files(&[
            (
                "cotx/mod.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "whitespace.rs",
                "sqlx::query(\"SELECT set_config ( 'rss.tenant_id' , $1 , true )\")",
            ),
            (
                "raw_setlocal.rs",
                "sqlx::query(\"SET LOCAL rss.tenant_id = '...'\")",
            ),
        ]);
        let (_, findings) = scan_funnel(&fs);
        let escapes: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == Rule::FunnelEscape)
            .collect();
        assert_eq!(
            escapes.len(),
            2,
            "空白变体 + 裸 SET LOCAL 应各报 1 条: {findings:?}"
        );
    }

    // ---- green：散文注释「SET LOCAL rss.tenant_id」（无赋值号）不误报 ----

    #[test]
    fn green_prose_setlocal_mention_not_flagged() {
        let fs = files(&[
            (
                "cotx/mod.rs",
                "sqlx::query(\"SELECT set_config('rss.tenant_id', $1, true)\")",
            ),
            (
                "role_repo.rs",
                "// 经 SET LOCAL rss.tenant_id 注入 scope（散文，无赋值号）\npub fn find() {}",
            ),
        ]);
        let (_, findings) = scan_funnel(&fs);
        assert!(
            findings.is_empty(),
            "散文提及 SET LOCAL rss.tenant_id（无 = / to）不应误报: {findings:?}"
        );
    }
}
