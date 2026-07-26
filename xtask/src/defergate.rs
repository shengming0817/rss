//! `defer-gate` —— governed 高风险路径内**结构化 defer 完整性 + 经典注解**治理门（#1432）。
//!
//! INVARIANT: DEFER-GATE-01 { level = "Medium", exec = "verify", source = "code" }—— 在 governed config（根 `deny.toml` / `clippy.toml`）内强制两条：(1) 任一 `DEFER(#<issue>)` 标签须四字段齐全
//! 非空——`owner=<..>`、`blocked-by=<#NNNN|trigger:..>`、`closes-when=<..>`（折行式可落在 DEFER 行 + 后续
//! ≤[`FIELD_WINDOW`] 行注释续行窗口内），ID 须 `#<digits>`，缺即 fail；(2) governed scope 禁用经典注解
//! `TODO` / `FIXME` / `XXX` / `HACK`（`[:(]` 注解位），须升级为完整 `DEFER(...)` 或删除（DEFER 行本身豁免）。
//!
//! Markdown prose and `CLAUDE.md` are intentionally outside the governed scope. The gate only
//! checks machine-owned TOML carriers where the annotations can affect repository policy.
//!
//! 评级 Medium（CI 门，接入 `cargo xtask verify` no-compile meta 步 + 独立 `cargo xtask defer-gate`）；synthetic red +
//! anti-vacuity green 见 `#[cfg(test)]`。

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, bail};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// DEFER 行 + 后续至多 N 行续行视为同一逻辑 defer 块（折行式字段窗口）。
const FIELD_WINDOW: usize = 6;

/// governed 扫描根级文件（显式）。
const GOVERNED_FILES: &[&str] = &["deny.toml", "clippy.toml"];

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
        let summary =
            format!("{scanned} governed 文件扫描，DEFER 标签完整 + 无裸 TODO/FIXME/XXX/HACK 注解");
        Ok((summary, findings))
    }
}

/// 扫 governed config，返回 `(扫描文件数, findings)`。任一根文件缺失即 fail-closed。
fn scan_governed(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let mut files = Vec::with_capacity(GOVERNED_FILES.len());
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
        let lines: Vec<&str> = content.lines().collect();
        let rel = path.strip_prefix(root).unwrap_or(path);
        for (line, rule) in scan_lines(&lines) {
            let detail = hit_detail(rule, &lines, line - 1);
            findings.push(finding(rule, format!("{}:{}", rel.display(), line), detail));
        }
    }
    Ok((files.len(), findings))
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

/// 单文件内容扫描（纯函数，测试入口）。
#[cfg(test)]
fn scan_content(content: &str) -> Vec<(usize, Rule)> {
    let lines: Vec<&str> = content.lines().collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    // —— ① DEFER 标签完整性（红 / 绿） ——

    /// 绿：单行完整 DEFER（四字段齐全 + 合法 ID）→ 0 finding。
    #[test]
    fn defer_single_line_complete_passes() {
        let src = "// DEFER(#1432): 路由未接线; owner=settings; blocked-by=#1421; closes-when=runtime 挂载\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 绿：折行式完整 DEFER（字段散落在窗口内续行）→ 0 finding。
    #[test]
    fn defer_folded_complete_passes() {
        let src = "// DEFER(#1432): 路由未接线;\n//   owner=settings; blocked-by=#1421;\n//   closes-when=runtime 挂载 settings RouteGroup\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 绿：blocked-by 用 trigger: 形态亦合规。
    #[test]
    fn defer_blocked_by_trigger_passes() {
        let src =
            "// DEFER(#9): x; owner=a; blocked-by=trigger:Topology=Distributed; closes-when=done\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 红：空 `trigger:`（冒号后无内容 / 仅空白）须拒——trigger value 是必填阻塞条件（F1 修复回归）。
    #[test]
    fn defer_empty_trigger_flags() {
        let empty = "// DEFER(#1): x; owner=a; blocked-by=trigger:; closes-when=done\n";
        assert_eq!(scan_content(empty), vec![(1, Rule::DeferIncomplete)]);
        let ws = "// DEFER(#1): x; owner=a; blocked-by=trigger:   ; closes-when=done\n";
        assert_eq!(scan_content(ws), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：同一行多个 `DEFER(`——首个完整、第二个缺字段，第二个须独立判 DeferIncomplete（F2 修复回归）。
    #[test]
    fn defer_same_line_second_incomplete_flags() {
        let src = "// DEFER(#1): a; owner=x; blocked-by=#2; closes-when=d; DEFER(#3): b\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 绿：同一行两个**均完整** DEFER 标签 → 0 finding（F2：occurrence 级校验不误伤）。
    #[test]
    fn defer_same_line_both_complete_passes() {
        let src = "// DEFER(#1): a; owner=x; blocked-by=#2; closes-when=d; DEFER(#3): b; owner=y; blocked-by=#4; closes-when=e\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 边界：closes-when 落在第 FIELD_WINDOW(6) 续行（窗口内）→ 完整；落在第 7 续行（越窗）→ 缺字段（F3 修复回归）。
    #[test]
    fn defer_window_boundary() {
        let within = "// DEFER(#1): a;\n//  owner=x;\n//  blocked-by=#2;\n//  c1;\n//  c2;\n//  c3;\n//  closes-when=d\n";
        assert_eq!(scan_content(within), vec![]);
        let beyond = "// DEFER(#1): a;\n//  owner=x;\n//  blocked-by=#2;\n//  c1;\n//  c2;\n//  c3;\n//  c4;\n//  closes-when=d\n";
        assert_eq!(scan_content(beyond), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：缺 owner → DeferIncomplete（行 1）。
    #[test]
    fn defer_missing_owner_flags() {
        let src = "// DEFER(#1): x; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：缺 blocked-by → DeferIncomplete。
    #[test]
    fn defer_missing_blocked_by_flags() {
        let src = "// DEFER(#1): x; owner=a; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：缺 closes-when → DeferIncomplete。
    #[test]
    fn defer_missing_closes_when_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#2\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：owner= 空值 → DeferIncomplete。
    #[test]
    fn defer_empty_owner_flags() {
        let src = "// DEFER(#1): x; owner=; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：blocked-by 既非 #digits 也非 trigger: → DeferIncomplete。
    #[test]
    fn defer_bad_blocked_by_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=soon; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：blocked-by=#<digit><alpha>（如 `#1todo`）须拒——首位数字不代表合法 issue ref（B1/A2 修复回归）。
    #[test]
    fn defer_blocked_by_digit_then_alpha_flags() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#1abc; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：ID 非 #digits（占位 `#NNNN`）→ DeferIncomplete。
    #[test]
    fn defer_bad_id_placeholder_flags() {
        let src = "// DEFER(#NNNN): x; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    /// 红：ID 缺 `#` → DeferIncomplete。
    #[test]
    fn defer_missing_hash_flags() {
        let src = "// DEFER(123): x; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
    }

    // —— ② 经典注解（红 / 绿 / 行内豁免） ——

    /// 红：裸 `TODO:` 注解 → ClassicAnnotation。
    #[test]
    fn classic_todo_colon_flags() {
        assert_eq!(
            scan_content("行首\n// TODO: 之后修\n"),
            vec![(2, Rule::ClassicAnnotation)]
        );
    }

    /// 红：`FIXME(` 注解位亦触发。
    #[test]
    fn classic_fixme_paren_flags() {
        assert_eq!(
            scan_content("# FIXME(owner): 修\n"),
            vec![(1, Rule::ClassicAnnotation)]
        );
    }

    /// 绿：DEFER 行内的 `TODO:`（desc 内）豁免——不重复计为 ClassicAnnotation。
    #[test]
    fn classic_inside_defer_line_exempt() {
        let src = "// DEFER(#1): 见 TODO: 迁移; owner=a; blocked-by=#2; closes-when=done\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 红：DEFER 块**之后紧邻**的无关经典注解仍须报（仅 DEFER 行豁免，续行不整体豁免——B3 修复回归）。
    #[test]
    fn classic_after_defer_block_not_exempt() {
        let src = "// DEFER(#1): x; owner=a; blocked-by=#2; closes-when=done\n// TODO: 无关债\n";
        assert_eq!(scan_content(src), vec![(2, Rule::ClassicAnnotation)]);
    }

    /// 绿：词非注解位（`TODOS` / 散文 `todo` / `TODO` 后无 `:`/`(`）不触发。
    #[test]
    fn classic_non_annotation_position_passes() {
        assert_eq!(scan_content("the TODOS list and a todo item\n"), vec![]);
        assert_eq!(scan_content("讨论 TODO 项的处理方式\n"), vec![]);
    }

    // —— ③ TOML 注释中的普通词语不触发 ——

    /// 绿：配置注释里的 `defer gate` / `follow-up issue` / `后续` / 无括号 `DEFER 格式` 不触发。
    #[test]
    fn non_annotation_config_words_not_flagged() {
        let src = "本节描述 defer gate 与 follow-up issue；后续 issue 待建。DEFER 格式见下。deferred 状态。\n";
        assert_eq!(scan_content(src), vec![]);
    }

    /// 红 anti-vacuity：配置中的不完整 DEFER 触发。
    #[test]
    fn incomplete_defer_in_config_is_flagged() {
        let src = "# DEFER(#1): 缺字段\n";
        assert_eq!(scan_content(src), vec![(1, Rule::DeferIncomplete)]);
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

    // —— ⑥ 真 workspace governed scope 绿门（接 verify 机器门） ——

    /// 绿向工作区门：真 governed scope 0 finding + canary。anti-vacuity 由上方 synthetic red 守（非恒真）。
    #[test]
    #[allow(clippy::expect_used)]
    fn real_governed_scope_is_clean() {
        let root = crate::workspace_root().expect("workspace root");
        let (scanned, findings) = scan_governed(&root).expect("scan governed");
        assert_eq!(scanned, GOVERNED_FILES.len());
        assert!(
            findings.is_empty(),
            "governed scope 应 0 defer-gate finding: {findings:?}"
        );
    }
}
