//! `defer-gate` —— governed 高风险路径内**结构化 defer 完整性 + 经典注解**治理门（#1432）。
//!
//! INVARIANT: DEFER-GATE-01 { level = "Medium", exec = "verify", source = "code" }—— 在 governed scope（`docs/rules` / `docs/architecture` / `.claude/rules`
//! 及根 `deny.toml` / `clippy.toml` / `CLAUDE.md`）内强制两条：(1) 任一 `DEFER(#<issue>)` 标签须四字段齐全
//! 非空——`owner=<..>`、`blocked-by=<#NNNN|trigger:..>`、`closes-when=<..>`（折行式可落在 DEFER 行 + 后续
//! ≤[`FIELD_WINDOW`] 行注释续行窗口内），ID 须 `#<digits>`，缺即 fail；(2) governed scope 禁用经典注解
//! `TODO` / `FIXME` / `XXX` / `HACK`（`[:(]` 注解位），须升级为完整 `DEFER(...)` 或删除（DEFER 行本身豁免）。
//!
//! 背景：仓内 follow-up/defer/后续/todo 标记约 6700 处散乱分布，缺机器门区分「可接受 defer」与「未追踪未完成工作」
//! （#1432）。v1 守治理高风险 docs + 根 config，强制结构化 `DEFER(...)` 完整性。
//!
//! 标记集精度（实测 governed scope 定稿）：自由词 `defer`/`follow-up`/`后续` 在 governed docs 中**绝大多数是描述性
//! 散文**（ADR `§8 Follow-up` 标题 / `后续 issue` 引用 / `deferred` 状态），触发即对约 59 处散文 + 本门自身文档误报；
//! 故 v1 **不**触发自由词散文，只锁结构化 `DEFER(` 标签 + 经典注解。自由词散文 + 代码注释（`crates/*`、`xtask/*`）
//! 扩域 + 历史约 6700 baseline 冻结 = ratchet follow-up #1447（届时引入 baseline allowlist 轨道）。
//!
//! 盲区（AI-robust 写明）：① markdown 扫描前剥 fenced（N≥3 同字符 run 配对，4-backtick 外层 fence 不被内层 3-backtick
//! 误闭）+ inline（N-backtick span 配对）代码（格式示例不误报，代码示例非真 defer）；`.toml` 按 raw 扫。② `DEFER(`
//! 大写字面触发；散文小写 "defer gate" / 无括号 "DEFER 格式" 不触发。③ 折行窗口 join 后做字段判定，理论上窗口内紧邻
//! 文本若巧含 `owner=`/`closes-when=` 可让缺字段 DEFER 误判合规——实测零命中，governed 多为 .md/.toml。④ 本门自身源
//! `xtask/src/**` 不在 governed scope（避免扫到测试夹具串）。
//!
//! 评级 Medium（CI 门，接入 `cargo xtask verify` no-compile meta 步 + 独立 `cargo xtask defer-gate`）；synthetic red +
//! anti-vacuity green 见 `#[cfg(test)]`。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// DEFER 行 + 后续至多 N 行续行视为同一逻辑 defer 块（折行式字段窗口）。
const FIELD_WINDOW: usize = 6;

/// governed 扫描目录根（递归取 `.md`）。
const GOVERNED_DIRS: &[&str] = &["docs/rules", "docs/architecture", ".claude/rules"];

/// governed 扫描根级文件（显式）。
const GOVERNED_FILES: &[&str] = &["deny.toml", "clippy.toml", "CLAUDE.md"];

/// 经典 debt 注解词（注解位 `[:(]` 才触发）。
const CLASSIC: &[&str] = &["TODO", "FIXME", "XXX", "HACK"];

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Rule {
    /// `DEFER(#NNNN)` 标签 ID 非法或缺 owner/blocked-by/closes-when 字段。
    DeferIncomplete,
    /// governed scope 内裸 `TODO`/`FIXME`/`XXX`/`HACK` 注解（非 DEFER 行、注解位）。
    ClassicAnnotation,
}

pub(crate) struct DeferGate;

impl GovernanceCheck for DeferGate {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "defer-gate"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (scanned, findings) = scan_governed(&root)?;
        // canary 次级下界：每目录 / 每根文件已由 scan_governed fail-closed 守（路径漂移 / 目录被移走即 bail）；此处
        // 再兜「所有目录同时缩到极小」的灾难（显著低于实际，不误伤正常增减）。
        if scanned < 10 {
            bail!(
                "defer-gate: 仅扫到 {scanned} 个 governed 文件，疑似 docs/rules·docs/architecture·.claude/rules 结构异常"
            );
        }
        let summary =
            format!("{scanned} governed 文件扫描，DEFER 标签完整 + 无裸 TODO/FIXME/XXX/HACK 注解");
        Ok((summary, findings))
    }
}

/// 扫 governed scope，返回 `(扫描文件数, findings)`。任一 governed 目录无 `.md` / 任一根文件缺失即 fail-closed。
fn scan_governed(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut dir_counts: Vec<(&str, usize)> = Vec::new();
    for dir in GOVERNED_DIRS {
        let df = md_files(&root.join(dir))?;
        dir_counts.push((dir, df.len()));
        files.extend(df);
    }
    ensure_governed_coverage(&dir_counts)?;
    for f in GOVERNED_FILES {
        let p = root.join(f);
        if !p.is_file() {
            bail!("defer-gate: governed 根文件 {f} 缺失——疑似路径漂移，fail-closed");
        }
        files.push(p);
    }
    files.sort();
    let mut findings = Vec::new();
    for path in &files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("defer-gate: 读 {} 失败: {e}", path.display()))?;
        let is_md = path.extension().is_some_and(|x| x == "md");
        let prepared = if is_md {
            strip_md_code(&content)
        } else {
            content
        };
        let lines: Vec<&str> = prepared.lines().collect();
        let rel = path.strip_prefix(root).unwrap_or(path);
        for (line, rule) in scan_lines(&lines) {
            let detail = hit_detail(rule, &lines, line - 1);
            findings.push(finding(rule, format!("{}:{}", rel.display(), line), detail));
        }
    }
    Ok((files.len(), findings))
}

/// 任一 governed 目录无 `.md` → fail-closed（目录被改名/清空时门静默放水不可接受）。纯函数，便于 anti-vacuity 测试。
fn ensure_governed_coverage(dir_counts: &[(&str, usize)]) -> Result<()> {
    for (dir, n) in dir_counts {
        if *n == 0 {
            bail!(
                "defer-gate: governed 目录 {dir} 无 .md 文件——疑似路径漂移 / 目录被移走，fail-closed"
            );
        }
    }
    Ok(())
}

/// 富化 finding detail：指明 DEFER 缺的具体字段 / 命中的经典词，开发者可直接照改。
fn hit_detail(rule: Rule, lines: &[&str], idx: usize) -> String {
    match rule {
        Rule::DeferIncomplete => {
            let end = window_end(lines, idx);
            let block = lines[idx..end].join(" ");
            format!(
                "DEFER 标签{}——须 ID #<digits> + owner=<..>; blocked-by=<#NNNN|trigger:..>; closes-when=<..>",
                defer_missing_reason(&block)
            )
        }
        Rule::ClassicAnnotation => format!(
            "governed scope 禁用裸 {} 注解（注解位）——升级为完整 DEFER(#NNNN) 标签或删除",
            first_classic_keyword(lines[idx])
        ),
    }
}

/// 递归收集 `dir` 下全部 `.md` 文件（目录不存在 → 空，由 [`ensure_governed_coverage`] / canary 兜底）。
fn md_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| anyhow::anyhow!("defer-gate: 读目录 {} 失败: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| anyhow::anyhow!("defer-gate: 遍历 {} 失败: {e}", dir.display()))?
            .path();
        if path.is_dir() {
            out.extend(md_files(&path)?);
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// 已 prepare（md 剥码后）的行集扫描核心：返回 `(1-based 行号, 违反规则)`（排序去重）。
fn scan_lines(lines: &[&str]) -> Vec<(usize, Rule)> {
    let mut findings = Vec::new();
    // DEFER 标签所在行（仅这些行豁免经典注解扫描，避免 desc 内 `TODO:` 误报；续行不整体豁免）。
    let mut covered: HashSet<usize> = HashSet::new();

    // ① DEFER 标签完整性。
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains("DEFER(") {
            continue;
        }
        let end = window_end(lines, idx);
        let block = lines[idx..end].join(" ");
        // 块内每个 `DEFER(` occurrence 独立校验（同行/同块多标签都不漏，F2）。
        if !all_defers_ok(&block) {
            findings.push((idx + 1, Rule::DeferIncomplete));
        }
        // 仅豁免 DEFER 标签所在行本身——避免吞掉 DEFER 之后紧邻的无关经典注解（B3 false-negative）。
        covered.insert(idx);
    }

    // ② 经典注解（不在 DEFER 标签行）。
    for (idx, line) in lines.iter().enumerate() {
        if covered.contains(&idx) {
            continue;
        }
        if classic_anno_line(line) {
            findings.push((idx + 1, Rule::ClassicAnnotation));
        }
    }

    findings.sort_unstable();
    findings.dedup();
    findings
}

/// 单文件内容扫描（纯函数，**测试入口**——生产路径走 [`scan_governed`] 内联 strip + [`scan_lines`]）：
/// `is_md` → 先剥 markdown 代码块（格式示例 / 代码不误报）。
#[cfg(test)]
fn scan_content(content: &str, is_md: bool) -> Vec<(usize, Rule)> {
    let prepared = if is_md {
        strip_md_code(content)
    } else {
        content.to_string()
    };
    let lines: Vec<&str> = prepared.lines().collect();
    scan_lines(&lines)
}

/// DEFER 行起的逻辑块结束行（exclusive）：含 DEFER 行 + 后续至多 [`FIELD_WINDOW`] 行非空续行（总窗口
/// `1 + FIELD_WINDOW` 行），至首个空行止。
fn window_end(lines: &[&str], start: usize) -> usize {
    // 续行计数语义：DEFER 行（start）之外再吸收至多 FIELD_WINDOW 行 → exclusive cap = start + 1 + FIELD_WINDOW。
    let cap = (start + 1 + FIELD_WINDOW).min(lines.len());
    let mut end = start + 1;
    while end < cap && !lines[end].trim().is_empty() {
        end += 1;
    }
    end
}

/// 块内全部 `DEFER(` segment 均合规（无 occurrence → false；`contains("DEFER(")` 已保证 ≥1）。
fn all_defers_ok(block: &str) -> bool {
    let segs = defer_segments(block);
    !segs.is_empty() && segs.iter().all(|s| defer_block_ok(s))
}

/// 把 block 按 `DEFER(` occurrence 切段：每段 = 一个 `DEFER(` 到下一个 `DEFER(`（或块尾）。
fn defer_segments(block: &str) -> Vec<&str> {
    let starts: Vec<usize> = block.match_indices("DEFER(").map(|(i, _)| i).collect();
    starts
        .iter()
        .enumerate()
        .map(|(k, &s)| &block[s..starts.get(k + 1).copied().unwrap_or(block.len())])
        .collect()
}

/// 单个 DEFER segment 合规 = 合法 `#<digits>` ID + owner/closes-when 非空 + blocked-by 为 `#<digits>` 或 `trigger:..`。
fn defer_block_ok(seg: &str) -> bool {
    defer_id_ok(seg)
        && field_nonempty(seg, "owner=")
        && blocked_by_ok(seg)
        && field_nonempty(seg, "closes-when=")
}

/// 块内首个不合规 DEFER segment 的缺因（既已判 DeferIncomplete，必命中其一）。
fn defer_missing_reason(block: &str) -> &'static str {
    for seg in defer_segments(block) {
        if !defer_block_ok(seg) {
            return segment_reason(seg);
        }
    }
    "字段不全"
}

/// 单 segment 首个不合规字段。
fn segment_reason(seg: &str) -> &'static str {
    if !defer_id_ok(seg) {
        "ID 非 #<digits>"
    } else if !field_nonempty(seg, "owner=") {
        "缺/空 owner="
    } else if !blocked_by_ok(seg) {
        "缺/非法 blocked-by=（须 #<digits> 或 trigger:..）"
    } else if !field_nonempty(seg, "closes-when=") {
        "缺/空 closes-when="
    } else {
        "字段不全"
    }
}

/// `DEFER(` 后紧跟 `#<≥1 digits>)`。
fn defer_id_ok(block: &str) -> bool {
    let Some(i) = block.find("DEFER(") else {
        return false;
    };
    let after = &block[i + "DEFER(".len()..];
    let mut chars = after.chars();
    if chars.next() != Some('#') {
        return false;
    }
    let mut saw_digit = false;
    for c in chars {
        if c.is_ascii_digit() {
            saw_digit = true;
            continue;
        }
        return saw_digit && c == ')';
    }
    false
}

/// `key`（含尾 `=`）对应的字段值（截到 `;` 或行尾，trim）；不存在 → `None`。
fn field_value<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let i = block.find(key)?;
    let rest = &block[i + key.len()..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim())
}

fn field_nonempty(block: &str, key: &str) -> bool {
    field_value(block, key).is_some_and(|v| !v.is_empty())
}

/// blocked-by 合规 = `trigger:<非空>` 或 `#<全位数字>`（与 [`defer_id_ok`] 对称——`#1todo` / 空 `trigger:` 均不合法）。
fn blocked_by_ok(block: &str) -> bool {
    match field_value(block, "blocked-by=") {
        Some(v) => {
            v.strip_prefix("trigger:")
                .is_some_and(|s| !s.trim().is_empty())
                || (v.starts_with('#') && v.len() > 1 && v[1..].chars().all(|c| c.is_ascii_digit()))
        }
        None => false,
    }
}

/// 行内是否含注解位经典 debt 词。
fn classic_anno_line(line: &str) -> bool {
    CLASSIC.iter().any(|kw| classic_kw_hit(line, kw))
}

/// 行内首个注解位经典词（既已判 ClassicAnnotation，必有命中）。
fn first_classic_keyword(line: &str) -> &'static str {
    CLASSIC
        .iter()
        .copied()
        .find(|kw| classic_kw_hit(line, kw))
        .unwrap_or("TODO/FIXME/XXX/HACK")
}

/// 经典词 `kw` 是否在 `line` 注解位出现（前词边界 + 后跳空格为 `:`/`(`）。
fn classic_kw_hit(line: &str, kw: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(rel) = line[from..].find(kw) {
        let start = from + rel;
        let end = start + kw.len();
        from = end;
        // 前词边界：起始处或前一字节非 ascii 字母数字 / 下划线。
        let prev_boundary = start == 0 || !is_word_byte(bytes[start - 1]);
        if !prev_boundary {
            continue;
        }
        // 后：跳空格后为 `:` 或 `(`。
        let mut k = end;
        while k < bytes.len() && bytes[k] == b' ' {
            k += 1;
        }
        if k < bytes.len() && (bytes[k] == b':' || bytes[k] == b'(') {
            return true;
        }
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 剥 markdown fenced + inline 代码，保留行数（每源行 → 一输出行；代码内容→空）。fenced 按 run 长度 + 字符配对
/// （`````` ```` `````` 外层 fence 不被内层 ```` ``` ```` 误闭）。
fn strip_md_code(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut fence: Option<(char, usize)> = None;
    for line in src.lines() {
        let (fc, fl) = fence_marker(line.trim_start());
        match fence {
            None => {
                if fl >= 3 {
                    fence = Some((fc, fl)); // 开 fence
                    out.push('\n');
                } else {
                    out.push_str(&strip_inline_code(line));
                    out.push('\n');
                }
            }
            Some((open_c, open_n)) => {
                // 闭合：同字符且 run 长度 ≥ 开 fence。
                if fc == open_c && fl >= open_n {
                    fence = None;
                }
                out.push('\n'); // fenced 内容 + 闭 fence 行清空
            }
        }
    }
    out
}

/// 行首（已 trim）的 fence marker run：`(字符, 连续长度)`；非 ```` ``` ````/`~~~` 起始 → `(' ', 0)`。
fn fence_marker(t: &str) -> (char, usize) {
    match t.chars().next() {
        Some(c) if c == '`' || c == '~' => (c, t.chars().take_while(|&x| x == c).count()),
        _ => (' ', 0),
    }
}

/// 剥行内 backtick code span（N-backtick 开 run 配等长闭 run，含两端 run 与内容）；未闭合 run 当字面量保留。
fn strip_inline_code(line: &str) -> String {
    let b: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != '`' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        // 开 backtick run 长度 n。
        let mut n = 0;
        while i + n < b.len() && b[i + n] == '`' {
            n += 1;
        }
        // 从 run 之后找等长闭 run。
        let mut k = i + n;
        let mut close: Option<usize> = None;
        while k < b.len() {
            if b[k] == '`' {
                let mut m = 0;
                while k + m < b.len() && b[k + m] == '`' {
                    m += 1;
                }
                if m == n {
                    close = Some(k);
                    break;
                }
                k += m;
            } else {
                k += 1;
            }
        }
        match close {
            Some(c) => i = c + n, // 丢弃整个 span（两端 run + 内容）
            None => {
                for _ in 0..n {
                    out.push('`'); // 未闭合：开 run 当字面量
                }
                i += n;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // —— ① DEFER 标签完整性（红 / 绿） ——

    /// 绿：单行完整 DEFER（四字段齐全 + 合法 ID）→ 0 finding。
    #[test]
    fn defer_single_line_complete_passes() {
        let src = "// DEFER(#1432): 路由未接线; owner=settings; blocked-by=#1421; closes-when=runtime 挂载\n";
        assert_eq!(scan_content(src, false), vec![]);
    }

    /// 绿：折行式完整 DEFER（字段散落在窗口内续行）→ 0 finding。
    #[test]
    fn defer_folded_complete_passes() {
        let src = "// DEFER(#1432): 路由未接线;\n//   owner=settings; blocked-by=#1421;\n//   closes-when=runtime 挂载 settings RouteGroup\n";
        assert_eq!(scan_content(src, false), vec![]);
    }

    /// 绿：blocked-by 用 trigger: 形态亦合规。
    #[test]
    fn defer_blocked_by_trigger_passes() {
        let src =
            "// DEFER(#9): x; owner=a; blocked-by=trigger:Topology=Distributed; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![]);
    }

    /// 红：空 `trigger:`（冒号后无内容 / 仅空白）须拒——trigger value 是必填阻塞条件（F1 修复回归）。
    #[test]
    fn defer_empty_trigger_flags() {
        let empty = "// DEFER(#1): x; owner=a; blocked-by=trigger:; closes-when=done\n";
        assert_eq!(scan_content(empty, false), vec![(1, Rule::DeferIncomplete)]);
        let ws = "// DEFER(#1): x; owner=a; blocked-by=trigger:   ; closes-when=done\n";
        assert_eq!(scan_content(ws, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：同一行多个 `DEFER(`——首个完整、第二个缺字段，第二个须独立判 DeferIncomplete（F2 修复回归）。
    #[test]
    fn defer_same_line_second_incomplete_flags() {
        let src = "// DEFER(#1): a; owner=x; blocked-by=#2; closes-when=d; DEFER(#3): b\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 绿：同一行两个**均完整** DEFER 标签 → 0 finding（F2：occurrence 级校验不误伤）。
    #[test]
    fn defer_same_line_both_complete_passes() {
        let src = "// DEFER(#1): a; owner=x; blocked-by=#2; closes-when=d; DEFER(#3): b; owner=y; blocked-by=#4; closes-when=e\n";
        assert_eq!(scan_content(src, false), vec![]);
    }

    /// 边界：closes-when 落在第 FIELD_WINDOW(6) 续行（窗口内）→ 完整；落在第 7 续行（越窗）→ 缺字段（F3 修复回归）。
    #[test]
    fn defer_window_boundary() {
        let within = "// DEFER(#1): a;\n//  owner=x;\n//  blocked-by=#2;\n//  c1;\n//  c2;\n//  c3;\n//  closes-when=d\n";
        assert_eq!(scan_content(within, false), vec![]);
        let beyond = "// DEFER(#1): a;\n//  owner=x;\n//  blocked-by=#2;\n//  c1;\n//  c2;\n//  c3;\n//  c4;\n//  closes-when=d\n";
        assert_eq!(
            scan_content(beyond, false),
            vec![(1, Rule::DeferIncomplete)]
        );
    }

    /// 红：缺 owner → DeferIncomplete（行 1）。
    #[test]
    fn defer_missing_owner_flags() {
        let src = "// DEFER(#1): x; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：缺 blocked-by → DeferIncomplete。
    #[test]
    fn defer_missing_blocked_by_flags() {
        let src = "// DEFER(#1): x; owner=a; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：缺 closes-when → DeferIncomplete。
    #[test]
    fn defer_missing_closes_when_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#2\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：owner= 空值 → DeferIncomplete。
    #[test]
    fn defer_empty_owner_flags() {
        let src = "// DEFER(#1): x; owner=; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：blocked-by 既非 #digits 也非 trigger: → DeferIncomplete。
    #[test]
    fn defer_bad_blocked_by_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=soon; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：blocked-by=#<digit><alpha>（如 `#1todo`）须拒——首位数字不代表合法 issue ref（B1/A2 修复回归）。
    #[test]
    fn defer_blocked_by_digit_then_alpha_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#1abc; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：ID 非 #digits（占位 `#NNNN`）→ DeferIncomplete。
    #[test]
    fn defer_bad_id_placeholder_flags() {
        let src = "// DEFER(#NNNN): x; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：ID 缺 `#` → DeferIncomplete。
    #[test]
    fn defer_missing_hash_flags() {
        let src = "// DEFER(123): x; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    // —— ② 经典注解（红 / 绿 / 行内豁免） ——

    /// 红：裸 `TODO:` 注解 → ClassicAnnotation。
    #[test]
    fn classic_todo_colon_flags() {
        assert_eq!(
            scan_content("行首\n// TODO: 之后修\n", false),
            vec![(2, Rule::ClassicAnnotation)]
        );
    }

    /// 红：`FIXME(` 注解位亦触发。
    #[test]
    fn classic_fixme_paren_flags() {
        assert_eq!(
            scan_content("# FIXME(owner): 修\n", false),
            vec![(1, Rule::ClassicAnnotation)]
        );
    }

    /// 绿：DEFER 行内的 `TODO:`（desc 内）豁免——不重复计为 ClassicAnnotation。
    #[test]
    fn classic_inside_defer_line_exempt() {
        let src = "// DEFER(#1): 见 TODO: 迁移; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src, false), vec![]);
    }

    /// 红：DEFER 块**之后紧邻**的无关经典注解仍须报（仅 DEFER 行豁免，续行不整体豁免——B3 修复回归）。
    #[test]
    fn classic_after_defer_block_not_exempt() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#2; closes-when=done\n// TODO: 无关债\n";
        assert_eq!(scan_content(src, false), vec![(2, Rule::ClassicAnnotation)]);
    }

    /// 绿：词非注解位（`TODOS` / 散文 `todo` / `TODO` 后无 `:`/`(`）不触发。
    #[test]
    fn classic_non_annotation_position_passes() {
        assert_eq!(
            scan_content("the TODOS list and a todo item\n", false),
            vec![]
        );
        assert_eq!(scan_content("讨论 TODO 项的处理方式\n", false), vec![]);
    }

    // —— ③ 自由词散文不触发（dogfood 安全） ——

    /// 绿：描述性散文 `defer gate` / `follow-up issue` / `后续` / 无括号 `DEFER 格式` 不触发。
    #[test]
    fn prose_words_not_flagged() {
        let src = "本节描述 defer gate 与 follow-up issue；后续 issue 待建。DEFER 格式见下。deferred 状态。\n";
        assert_eq!(scan_content(src, true), vec![]);
    }

    // —— ④ markdown 代码块剥离 ——

    /// 绿：fenced 代码块内的不完整 DEFER 示例（is_md）被剥离 → 不误报。
    #[test]
    fn md_fenced_code_stripped() {
        let src = "正文\n```\n// DEFER(#1): 缺字段示例\n```\n更多正文\n";
        assert_eq!(scan_content(src, true), vec![]);
    }

    /// 绿：4-backtick 外层 fence 嵌套 3-backtick 内层（is_md）——外层不被内层误闭，整段剥离 → 不误报（B4 修复回归）。
    #[test]
    fn md_nested_4backtick_fence_stripped() {
        let src = "正文\n````md\n```\n// DEFER(#1): 缺字段\n```\n````\n尾\n";
        assert_eq!(scan_content(src, true), vec![]);
    }

    /// 绿：inline single-backtick 内的 `DEFER(#NNNN)` 模板（is_md）被剥离 → 不误报。
    #[test]
    fn md_inline_code_stripped() {
        let src = "格式 `DEFER(#NNNN): ...` 见正文。\n";
        assert_eq!(scan_content(src, true), vec![]);
    }

    /// 绿：inline double-backtick span（含单反引号内容）内的不完整 DEFER（is_md）被剥离 → 不误报（A3/B5 修复回归）。
    #[test]
    fn md_inline_double_backtick_stripped() {
        let src = "见 ``DEFER(#1): 缺字段`` 示例\n";
        assert_eq!(scan_content(src, true), vec![]);
    }

    /// 红 anti-vacuity：非 md（raw .toml/.rs）不剥代码——同样的不完整 DEFER 在 raw 模式触发（证明剥离仅限 md）。
    #[test]
    fn raw_mode_does_not_strip_flags() {
        let src = "# DEFER(#1): 缺字段\n";
        assert_eq!(scan_content(src, false), vec![(1, Rule::DeferIncomplete)]);
    }

    // —— ⑤ 富化 detail / fail-closed canary（纯函数） ——

    /// `defer_missing_reason` 按字段顺序报首个缺因（DX：错误消息可操作）。
    #[test]
    fn defer_missing_reason_names_first_gap() {
        assert_eq!(
            defer_missing_reason("DEFER(#NNNN): x; owner=a; blocked-by=#2; closes-when=d"),
            "ID 非 #<digits>"
        );
        assert_eq!(
            defer_missing_reason("DEFER(#1): x; blocked-by=#2; closes-when=d"),
            "缺/空 owner="
        );
        assert!(
            defer_missing_reason("DEFER(#1): x; owner=a; blocked-by=soon; closes-when=d")
                .contains("blocked-by")
        );
        assert_eq!(
            defer_missing_reason("DEFER(#1): x; owner=a; blocked-by=#2"),
            "缺/空 closes-when="
        );
    }

    /// `first_classic_keyword` 返回命中的具体词（DX）。
    #[test]
    fn first_classic_keyword_names_hit() {
        assert_eq!(first_classic_keyword("// FIXME(x): 修"), "FIXME");
        assert_eq!(first_classic_keyword("// TODO: y"), "TODO");
    }

    /// fail-closed canary：任一 governed 目录 0 .md → Err（路径漂移不放水）；全非空 → Ok。anti-vacuity。
    #[test]
    fn governed_coverage_fail_closed() {
        assert!(
            ensure_governed_coverage(&[
                ("docs/rules", 7),
                ("docs/architecture", 9),
                (".claude/rules", 13)
            ])
            .is_ok()
        );
        assert!(
            ensure_governed_coverage(&[
                ("docs/rules", 7),
                ("docs/architecture", 0),
                (".claude/rules", 13)
            ])
            .is_err()
        );
    }

    // —— ⑥ 真 workspace governed scope 绿门（接 verify 机器门） ——

    /// 绿向工作区门：真 governed scope 0 finding + canary。anti-vacuity 由上方 synthetic red 守（非恒真）。
    #[test]
    #[allow(clippy::expect_used)]
    fn real_governed_scope_is_clean() {
        let root = crate::workspace_root().expect("workspace root");
        let (scanned, findings) = scan_governed(&root).expect("scan governed");
        assert!(
            scanned >= 10,
            "至少扫到 ~28 个 governed 文件，实际 {scanned}"
        );
        assert!(
            findings.is_empty(),
            "governed scope 应 0 defer-gate finding: {findings:?}"
        );
    }
}
