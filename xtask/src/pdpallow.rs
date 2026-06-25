//! `pdp-allow-guard` —— bins 生产 src 内 `#[allow(rss_pdp_impl_adapter_only)]` 逃生门**计数门**（治理 lint）。
//!
//! INVARIANT: PDP-ALLOW-CONFINE-01（T004.6 / #1198 / ADR-006 §5 信任根二次门）
//!
//! 背景：dylint `rss_pdp_impl_adapter_only`（PDP-IMPL-ADAPTER-ONLY-01）守「`diport::Pdp` 仅 adapter 可 impl」，
//! 但其 item-level 逃生门 `#[allow(rss_pdp_impl_adapter_only)] // reason: ...` 可在 bins 生产 src 内**抑制**该
//! lint，从而内联一个 always-allow `impl Pdp` 旁路真验签。azure 无 CI ⇒ `cargo xtask verify` 是唯一实际 gate，
//! 该逃生门若被滥用无任何机器二次门（评审 F20）。本计数门补足：扫 `bins/*/src/**` 生产源，**任一**
//! `#[allow(...rss_pdp_impl_adapter_only...)]` 用量即 fail（count 必须为 0），与 dylint 同源 fail-closed。
//!
//! 判定面（评审 F4 强化——comment-stripped + 属性 span，不引 regex）：先 string-aware 去 `//` 行注释 +
//! `/* */` 块注释（杜绝 doc / 注释里 `allow(...lint...)` 示例误判），再对每个 `allow(` **或 `expect(`** 找配对
//! `)`、span 内含 lint 名 ⇒ 逃生门用量。覆盖：① **多行属性**（`allow(` 与 lint 名跨行）；② **`expect`**
//! （`expect` 同样抑制 lint）；③ **范围扩至 `crates/*` + `bins/*` 生产 `src/`**（dylint 适用全面——非 adapter
//! 的任一 crate `impl Pdp` 都会触 dylint，逃生门可在任一处抑制）。`adapters/*`（合法 Pdp impl 站点）不扫；
//! `*/tests/`（集成测试）非 `src/`、不扫——test 替身合法（与 dylint 默认不扫 `#[cfg(test)]` 一致）。
//!
//! 盲区（AI-robust 写明）：comment-strip 不处理 raw string（`r"..."`）；**字符串字面量内**的 `allow(...lint...)`
//! （如本 governance 工具自身的演示串）会误判——故本扫描**不含** `xtask/`（工具自身）与 `lints/`（独立 workspace）。
//!
//! 评级 Medium（CI 门，接入 `cargo xtask verify`，no-compile meta 步）；synthetic red case + anti-vacuity 见
//! `#[cfg(test)]`：红向（单行 / 多行 / `expect` allow-attr 必判）+ 绿向（doc 提名 / 其它 allow / 真工作区 0 用量）。

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// PDP-ALLOW-CONFINE-01：bins 生产 src 内出现 `#[allow(rss_pdp_impl_adapter_only)]` 逃生门。
    ProdEscapeHatch,
}

/// 守卫的 dylint 名（逃生门即 `#[allow(<此名>)]` / `#[expect(<此名>)]`）。
const LINT: &str = "rss_pdp_impl_adapter_only";

/// 扫描的生产源根（dylint 适用全面，排除 adapters legit impl 站点 + 工具自身）：`crates/*` + `bins/*` 的 `src/`。
const ROOTS: &[&str] = &["crates", "bins"];

pub(crate) struct PdpAllowGuard;

impl GovernanceCheck for PdpAllowGuard {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "pdp-allow-guard"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (scanned, findings) = scan_sources(&root)?;
        // canary：crates/* + bins/* 生产 src 数十个 .rs；扫到过少疑似结构异常 / 路径漂移，静默通过会让门形同
        // 虚设。下界显著低于实际，仅捕「扫到几乎为空」的灾难，不误伤正常增减。
        if scanned < 10 {
            bail!("pdp-allow-guard: 仅扫到 {scanned} 个生产 src 文件，疑似 crates/bins 结构异常");
        }
        let summary = format!(
            "{scanned} 生产 src 文件扫描，无 `#[allow({LINT})]` / `#[expect(...)]` 逃生门用量"
        );
        Ok((summary, findings))
    }
}

/// string-aware 去 `//` 行注释 + `/* */` 块注释（→ 丢弃，保留 `\n` 供行号计算；保留字符串字面量）。
/// 杜绝 doc / 注释里 `allow(...lint...)` 示例误判。盲区：raw string（`r"..."`）不特判（罕见）。
fn strip_comments(src: &str) -> String {
    #[derive(PartialEq)]
    enum St {
        Code,
        Line,
        Block,
        Str,
    }
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut st = St::Code;
    while let Some(c) = chars.next() {
        match st {
            St::Code => match c {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    st = St::Line;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    st = St::Block;
                }
                '"' => {
                    st = St::Str;
                    out.push('"');
                }
                _ => out.push(c),
            },
            St::Line => {
                if c == '\n' {
                    st = St::Code;
                    out.push('\n');
                }
            }
            St::Block => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    st = St::Code;
                } else if c == '\n' {
                    out.push('\n');
                }
            }
            St::Str => match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    st = St::Code;
                    out.push('"');
                }
                '\n' => out.push('\n'),
                _ => out.push(c),
            },
        }
    }
    out
}

/// comment-stripped 内容里 `allow(...lint...)` / `expect(...lint...)` 逃生门的 1-based 行号（去重排序）。纯函数。
fn escape_hatch_lines(content: &str) -> Vec<usize> {
    let stripped = strip_comments(content);
    let bytes = stripped.as_bytes();
    let mut lines = Vec::new();
    for kw in ["allow(", "expect("] {
        let mut from = 0;
        while let Some(rel) = stripped[from..].find(kw) {
            let open = from + rel + kw.len() - 1; // '(' 索引
            from = open + 1;
            // 配对 ')'（paren 深度）。
            let mut depth = 1usize;
            let mut j = open + 1;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            if stripped[open + 1..j.min(stripped.len())].contains(LINT) {
                lines.push(stripped[..open].bytes().filter(|&b| b == b'\n').count() + 1);
            }
        }
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// 扫 `crates/*/src/**` + `bins/*/src/**`（生产源）的逃生门用量，返回 `(扫描文件数, findings)`。
fn scan_sources(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    for top in ROOTS {
        let top_dir = root.join(top);
        for member in member_dirs(&top_dir)? {
            for path in rs_files(&member.join("src"))? {
                scanned += 1;
                let content = std::fs::read_to_string(&path).map_err(|e| {
                    anyhow::anyhow!("pdp-allow-guard: 读 {} 失败: {e}", path.display())
                })?;
                for line in escape_hatch_lines(&content) {
                    findings.push(finding(
                        Rule::ProdEscapeHatch,
                        format!("{}:{}", path.display(), line),
                        format!(
                            "生产 src 内 `#[allow({LINT})]` / `#[expect(...)]` 逃生门——禁止旁路验签端口守卫；验签实现须放 adapters/"
                        ),
                    ));
                }
            }
        }
    }
    Ok((scanned, findings))
}

/// `top_dir` 下的直接子目录（workspace 成员目录；`top_dir` 不存在 → 空）。
fn member_dirs(top_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !top_dir.is_dir() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(top_dir)
        .map_err(|e| anyhow::anyhow!("pdp-allow-guard: 读目录 {} 失败: {e}", top_dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| anyhow::anyhow!("pdp-allow-guard: 遍历 {} 失败: {e}", top_dir.display()))?
            .path();
        if path.is_dir() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// 递归收集 `dir` 下全部 `.rs` 文件（目录不存在 → 空，由 canary 兜底）。
fn rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("pdp-allow-guard: 读目录 {} 失败: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| anyhow::anyhow!("pdp-allow-guard: 遍历 {} 失败: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            out.extend(rs_files(&path)?);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 红向 anti-vacuity：单行 / 多行 / `expect` allow-attr（含 lint 名）必判，且行号正确。
    #[test]
    fn flags_single_multi_line_and_expect() {
        // 单行。
        assert_eq!(
            escape_hatch_lines("#[allow(rss_pdp_impl_adapter_only)] // reason: x\n"),
            vec![1]
        );
        // 多行属性（allow( 与 lint 名跨行）——旧单行 substring 漏，新 span 捕。
        assert_eq!(
            escape_hatch_lines(
                "struct S;\n#[allow(\n    rss_pdp_impl_adapter_only,\n)]\nimpl S {}\n"
            ),
            vec![2]
        );
        // expect 同样抑制 lint。
        assert_eq!(
            escape_hatch_lines("#[expect(rss_pdp_impl_adapter_only)]\n"),
            vec![1]
        );
        // 与其它 lint 同列。
        assert_eq!(
            escape_hatch_lines("    #[allow(clippy::dead_code, rss_pdp_impl_adapter_only)]\n"),
            vec![1]
        );
    }

    /// 绿向 anti-vacuity（非恒真）：doc / 注释里的示例 + 其它 allow + 普通代码均不判（comment-strip 生效）。
    #[test]
    fn ignores_comments_and_other_allows() {
        // doc 注释提名（含 attr 示例语法）——comment-strip 后不判。
        assert!(
            escape_hatch_lines("//! 逃生门 `#[allow(rss_pdp_impl_adapter_only)]` 示例\n")
                .is_empty()
        );
        assert!(
            escape_hatch_lines("/// 见 `rss_pdp_impl_adapter_only`（PDP-IMPL-ADAPTER-ONLY-01）\n")
                .is_empty()
        );
        assert!(
            escape_hatch_lines("/* #[allow(rss_pdp_impl_adapter_only)] 块注释示例 */\n").is_empty()
        );
        // 其它 allow（不含 lint 名）。
        assert!(
            escape_hatch_lines("#![allow(clippy::unwrap_used, clippy::expect_used)]\n").is_empty()
        );
        // 普通代码提名（无 allow/expect 包裹）。
        assert!(escape_hatch_lines("const X: &str = \"rss_pdp_impl_adapter_only\";\n").is_empty());
    }

    /// 绿向工作区门：真 crates/* + bins/* 生产 src 0 逃生门用量（接 `cargo xtask verify` 机器门）。
    #[test]
    #[allow(clippy::expect_used)]
    fn real_sources_have_no_escape_hatch() {
        let root = crate::workspace_root().expect("workspace root");
        let (scanned, findings) = scan_sources(&root).expect("scan sources");
        assert!(scanned >= 10, "至少扫到数十个生产 src 文件，实际 {scanned}");
        assert!(
            findings.is_empty(),
            "生产 src 不应有 rss_pdp_impl_adapter_only 逃生门: {findings:?}"
        );
    }
}
