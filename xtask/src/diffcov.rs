//! `cargo xtask ci` per-PR-diff **增量**覆盖率门 —— 与「全 crate 绝对地板」门（[`crate::coverage`]）**共享
//! 同一次 `cargo llvm-cov` 测试运行**（不重复跑测试）：地板门吃 export JSON，本门吃同一 profdata 出的
//! lcov。判定 = 本 PR diff（相对 base，默认 `origin/develop`）**新增/修改的可执行行**聚合覆盖率必须
//! ≥ [`DIFF_MIN_PERCENT`]。补 v1 地板门测不到的洞：全在 adapters/域 crate 的大改动可零新测试照样过绝对
//! 地板门，本门强制「新代码自身被测」。
//!
//! 语义对标 diff-cover：「diff coverage = % of new/modified lines covered by tests」，计入分母的是**出现在
//! 覆盖报告里的可执行行**（非可执行/未插桩行不计）；三点式 `base...HEAD` 取分叉后改动行。
//! ref: diff-cover (Bachmann1234/diff_cover) README.rst@main（compare-branch 三点式 + lcov + 上述定义）
//! ref: cargo-llvm-cov（lcov 产出，与 [`crate::coverage`] 的 export JSON 同 profdata）
//!
//! **fail-closed / anti-vacuity 面**（防 false-green，见 [`verdict`]）：base ref 不可解析（如 `origin/develop`
//! 未 fetch）/ 非法 / 自引用（`HEAD`，diff 恒空绕门）⇒ fail-closed（[`git_diff`]）；生产文件整体缺 lcov 数据
//! （feature-gated/未编译）记 [`Score::missing`]，**单独** 0/0 时 fail-closed（F1）；inline `#[cfg(test)]` 行从
//! 分母剔除（[`test_line_ranges`]，F2，防测试码稀释）。真无可度量生产新代码（无 missing）⇒ pass。
//!
//! 唯一子进程 = `git`，经 [`crate::cmd::clean_cmd`] 构造（CMD-FUNNEL-01：`xtask/src` 禁裸 `Command::new`）。
//!
//! INVARIANT: COVERAGE-DIFF-FLOOR-01 { level = "Medium", exec = "ci-only", source = "code" }—— diff 可执行新增行聚合覆盖率 < [`DIFF_MIN_PERCENT`] ⇒ ci 非零退出；
//!   base 不可解析/自引用 ⇒ fail-closed；生产文件缺 lcov 数据且无可度量行 ⇒ fail-closed（非静默 0/0 绿）。

use crate::cmd::clean_cmd;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Stdio;

/// 增量覆盖率下限（%，整数——判定走整数比较避免浮点边界误差）= CLAUDE.md / rust-standards.md
/// 「新增/修改代码覆盖率 ≥ 80%」逐字值。单一事实源；与文档一致性由 `diff_min_percent_is_doc_verbatim` 测试守。
const DIFF_MIN_PERCENT: u64 = 80;

/// 默认 diff base ref。azure checkout 远端恒 `origin`（fetchDepth:0 ⇒ origin/develop 可见）；本地 forge
/// remote 名异于 origin 时用 [`BASE_ENV`] 覆盖。
const DEFAULT_BASE: &str = "origin/develop";

/// 覆盖默认 base ref 的环境变量（本地用 forge remote 名 / 已存在的 ref）。
const BASE_ENV: &str = "RSS_DIFF_COV_BASE";

/// 路径含这些子串者排除出分母：测试 / 基准代码本身不计入「新代码被测」。同文件内 inline `#[cfg(test)]` 行
/// 另由 [`test_line_ranges`]（F2）剔除。被 crate 级 `#[cfg(...)]` 完全条件编译排除的文件无 `DA` 记录 ⇒ 走
/// [`Score::missing`]（F1，由 [`verdict`] 裁决：单独 0/0 时 fail-closed），不静默跳过。
const EXCLUDE_SUBSTR: &[&str] = &["/tests/", "/benches/"];

/// 这些前缀的路径排除出分母：codegen 产物（非手写代码）不被门。
const EXCLUDE_PREFIX: &[&str] = &["generated/"];

/// 一次评分结果：分子（covered）/ 分母（executable 新增行）/ 未覆盖明细（诊断用）/ **缺覆盖数据**的新增
/// 生产行（`missing`：非排除生产文件出现在 diff 但无 lcov 记录——feature-gated/未编译，防 false-green）。
#[derive(Debug, PartialEq, Default)]
struct Score {
    covered: u64,
    executable: u64,
    uncovered: Vec<(String, u32)>,
    missing: Vec<(String, u32)>,
}

// ====== impl region (TDD: stub → 实现) ======

/// 解析 `git diff --unified=0` 文本 → 每文件**新侧**新增行号集。`+++ /dev/null`（删除）不记。
fn parse_unified_diff(diff: &str) -> BTreeMap<String, BTreeSet<u32>> {
    let mut added: BTreeMap<String, BTreeSet<u32>> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut new_line: Option<u32> = None;
    for line in diff.lines() {
        if let Some(spec) = line.strip_prefix("+++ ") {
            current = new_side_path(spec);
            new_line = None;
        } else if line.starts_with("--- ") {
            // 旧侧文件头：忽略。
        } else if line.starts_with("@@") {
            new_line = parse_hunk_new_start(line);
        } else if line.starts_with('\\') {
            // `\ No newline at end of file` —— 不推进新侧计数。
        } else if line.starts_with('+') {
            // `+++ ` 已在上面处理 ⇒ 此处必为单 `+` 新增行。
            if let (Some(f), Some(ln)) = (current.as_ref(), new_line) {
                added.entry(f.clone()).or_default().insert(ln);
                new_line = Some(ln + 1);
            }
        } else if line.starts_with('-') {
            // 删除行不推进新侧计数。
        } else if let Some(ln) = new_line {
            // 上下文行（-U0 下罕见）：推进新侧计数。
            new_line = Some(ln + 1);
        }
    }
    added
}

/// `+++` 行的新侧路径：`/dev/null`（删除）→ `None`；否则去 git 默认 `b/` 前缀。rename（含 `git mv` + 改动）
/// 的新增行按**新路径**计入——lcov 的 `SF:` 也是当前（新）路径，故能对上；纯 rename 无 hunk ⇒ 无新增行。
fn new_side_path(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec == "/dev/null" {
        return None;
    }
    Some(spec.strip_prefix("b/").unwrap_or(spec).to_owned())
}

/// 从 hunk 头 `@@ -a,b +c,d @@` 取新侧起始行号 `c`（`d` 省略=单行）。非 hunk 行 → `None`。
fn parse_hunk_new_start(header: &str) -> Option<u32> {
    if !header.starts_with("@@") {
        return None;
    }
    header
        .split_whitespace()
        .find(|t| t.starts_with('+'))
        .map(|t| t.trim_start_matches('+'))
        .and_then(|t| t.split(',').next())
        .and_then(|n| n.parse::<u32>().ok())
}

/// 解析 lcov 文本 → 每 `SF:` 文件的 `行号 → 命中数`（仅取 `DA:` 记录，其余 FN/BRDA/LF/LH 忽略）。
/// 同行多 `DA`（多测试二进制）取最大命中数（任一 >0 即视为被覆盖）。
fn parse_lcov(lcov: &str) -> BTreeMap<String, BTreeMap<u32, u64>> {
    let mut per_file: BTreeMap<String, BTreeMap<u32, u64>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in lcov.lines() {
        if let Some(sf) = line.strip_prefix("SF:") {
            current = Some(sf.trim().to_owned());
        } else if line == "end_of_record" {
            current = None;
        } else if let Some(da) = line.strip_prefix("DA:")
            && let (Some(file), Some((ln, hits))) = (current.as_ref(), parse_da(da))
        {
            let e = per_file
                .entry(file.clone())
                .or_default()
                .entry(ln)
                .or_insert(0);
            *e = (*e).max(hits);
        }
    }
    per_file
}

/// 解析 `DA:` 值 `<line>,<hits>[,checksum]` → `(line, hits)`。字段缺失/非数字 → `None`。
fn parse_da(da: &str) -> Option<(u32, u64)> {
    let mut it = da.split(',');
    let line = it.next()?.trim().parse::<u32>().ok()?;
    let hits = it.next()?.trim().parse::<u64>().ok()?;
    Some((line, hits))
}

/// lcov 的 `SF:` 绝对路径归一为 repo 相对（去 `root/` 前缀），与 diff 的 `b/<path>` 对齐。已相对则原样。
fn repo_rel(sf: &str, root: &Path) -> String {
    let sf = sf.trim();
    if let Some(root_str) = root.to_str() {
        let prefix = format!("{}/", root_str.trim_end_matches('/'));
        if let Some(rel) = sf.strip_prefix(&prefix) {
            return rel.to_owned();
        }
    }
    sf.to_owned()
}

/// 路径是否排除出分母（测试 / 基准 / codegen 产物）。
fn is_excluded(relpath: &str) -> bool {
    EXCLUDE_SUBSTR.iter().any(|s| relpath.contains(s))
        || EXCLUDE_PREFIX.iter().any(|p| relpath.starts_with(p))
}

/// 纯函数：交叉 diff 新增行 × lcov（已归一为 repo 相对 key）→ 评分。先剔除排除路径文件与 `test_lines`
/// （inline `#[cfg(test)]` 行，F2 防测试码稀释），余下**生产**新增行：
/// - 文件有 lcov 记录：有 `DA` = 可执行（命中 >0 计分子，否则 `uncovered`）；无 `DA` = 非可执行（注释/签名）不计；
/// - 文件**无** lcov 记录（feature-gated/未编译）：生产行进 `missing`（F1 防 false-green；由 [`verdict`] 裁决）。
///
/// `test_lines`：每文件 inline 测试模块行号集（[`score_diff`] 经 [`test_line_ranges`] 读源码算出；缺省=空）。
fn score(
    added: &BTreeMap<String, BTreeSet<u32>>,
    lcov_rel: &BTreeMap<String, BTreeMap<u32, u64>>,
    test_lines: &BTreeMap<String, BTreeSet<u32>>,
) -> Score {
    let mut s = Score::default();
    let empty = BTreeSet::new();
    for (file, lines) in added {
        if is_excluded(file) {
            continue;
        }
        let file_tests = test_lines.get(file).unwrap_or(&empty);
        let file_cov = lcov_rel.get(file);
        for &ln in lines {
            // F2：inline `#[cfg(test)]` 行不计入分母（测试码被测即覆盖会稀释生产未覆盖风险）。
            if file_tests.contains(&ln) {
                continue;
            }
            match file_cov {
                // 行无 DA 记录 ⇒ 非可执行（注释/空行/签名）⇒ 不计入分母。
                Some(cov) => {
                    if let Some(&hits) = cov.get(&ln) {
                        s.executable += 1;
                        if hits > 0 {
                            s.covered += 1;
                        } else {
                            s.uncovered.push((file.clone(), ln));
                        }
                    }
                }
                // F1：生产文件整体缺 lcov 记录（feature-gated/未编译）⇒ 记 missing，不静默折叠成 0/0。
                None => s.missing.push((file.clone(), ln)),
            }
        }
    }
    s
}

/// 源码（HEAD 内容）里 inline `#[cfg(test)]` 模块的行号集（1-based）。顶层（col 0）`#[cfg(test)]` 属性起，
/// 到下一个 col-0 闭合 `}`（含）为测试范围——锁定 RSS/rustfmt 主流 idiom `#[cfg(test)] mod tests { … }`（col-0
/// 闭合，免 brace 计数 ⇒ 不被字符串内 `{}` 干扰）。**已知限制**：缩进的 / 非 col-0 的 `#[cfg(test)]`（嵌套）
/// 不排除（罕见；稀释源主要是顶层 test 模块）。
fn test_line_ranges(content: &str) -> BTreeSet<u32> {
    let lines: Vec<&str> = content.lines().collect();
    let mut excluded = BTreeSet::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].starts_with("#[cfg(test)]") {
            // 从属性行到下一个以 `}` 起头的 col-0 行（含）= 该 test 项范围。
            let mut j = i + 1;
            while j < lines.len() && !lines[j].starts_with('}') {
                j += 1;
            }
            let end = j.min(lines.len().saturating_sub(1));
            for k in i..=end {
                excluded.insert((k as u32) + 1);
            }
            i = end + 1;
        } else {
            i += 1;
        }
    }
    excluded
}

/// 纯判定：`executable==0` → `None`（pass，确无可度量新代码）；否则 covered/executable < [`DIFF_MIN_PERCENT`]%
/// → `Some(pct)`（fail）。边界 `>=`（恰 80% 过）。判定用**整数比较**（`covered*100 < executable*80`）避免浮点
/// 边界误差；返回的 `pct` 仅供 [`render`] 诊断展示，不参与判定。
fn evaluate(covered: u64, executable: u64) -> Option<f64> {
    if executable == 0 {
        return None;
    }
    let pct = covered as f64 * 100.0 / executable as f64; // 仅诊断展示
    (covered * 100 < executable * DIFF_MIN_PERCENT).then_some(pct)
}

/// 失败诊断：含实际百分比、下限、分子/分母、未覆盖 file:line（截断），便于定位补测。调用方（[`verdict`]）
/// 保证仅在 pct < 下限时调用 ⇒ `s.uncovered` 必非空（covered < executable ⇒ 必有 hits=0 行）。
fn render(pct: f64, s: &Score) -> String {
    const MAX_UNCOVERED_SHOWN: usize = 10;
    let shown: Vec<String> = s
        .uncovered
        .iter()
        .take(MAX_UNCOVERED_SHOWN)
        .map(|(f, ln)| format!("{f}:{ln}"))
        .collect();
    let more = s.uncovered.len().saturating_sub(MAX_UNCOVERED_SHOWN);
    let tail = if more > 0 {
        format!("（另 {more} 处省略，全部见本地 `cargo llvm-cov report --lcov`）")
    } else {
        String::new()
    };
    format!(
        "本 PR diff 增量覆盖率 {pct:.1}% < {DIFF_MIN_PERCENT}% 下限（{}/{} 可执行新增行被测）。\
         未覆盖：{}{tail}（补表驱动测试覆盖这些新增行）",
        s.covered,
        s.executable,
        shown.join(", "),
    )
}

/// 解析 diff base ref：[`BASE_ENV`] 覆盖否则 [`DEFAULT_BASE`]。env 读取与决策分离（[`resolve_base_from`] 可测）。
fn resolve_base() -> String {
    resolve_base_from(std::env::var(BASE_ENV).ok())
}

/// 纯决策：有 [`BASE_ENV`] 值取之，否则 [`DEFAULT_BASE`]。
fn resolve_base_from(env: Option<String>) -> String {
    env.unwrap_or_else(|| DEFAULT_BASE.to_owned())
}

/// base 是否是「当前 HEAD」的自引用字面值（`HEAD`/`@`/`HEAD~0`/`HEAD^0`/`@~0`）——此类 base 令 `base...HEAD`
/// 恒空、门静默通过（F3 绕门面）。纯字面判定（见 [`git_diff`] 注：故意不做 commit 相等判定）。
fn is_self_ref(base: &str) -> bool {
    matches!(
        base.trim(),
        "HEAD" | "@" | "HEAD~0" | "HEAD^0" | "@~0" | "@^0"
    )
}

/// 跑 git 取 diff 文本。base 非法/不可解析 ⇒ **fail-closed**（非静默空 diff）。三点式 `base...HEAD` 取分叉后改动。
fn git_diff(root: &Path, base: &str) -> Result<String> {
    // base 输入校验：空 / 以 `-` 开头（会被 git 误解析为选项）即拒，fail-closed（COVERAGE-DIFF-FLOOR-01）。
    if base.is_empty() || base.starts_with('-') {
        bail!(
            "diff-coverage: 非法 base ref `{base}`（空或 `-` 前缀）—— 设 {BASE_ENV}=<remote>/<branch>（如 origin/develop）"
        );
    }
    // F3：拒绝**自引用** base（`HEAD`/`@`/`HEAD~0`）——`{base}...HEAD` 退化为空 diff 而静默 0/0 通过 = 绕门。
    // 注：用字面值判定而非「base commit == HEAD commit」——后者会误杀 develop 上 `origin/develop`(==HEAD) 的
    // 合法空 diff（真无新代码应 pass）。默认 base `origin/develop` 不在此名单，develop 直跑不受影响。
    if is_self_ref(base) {
        bail!(
            "diff-coverage: base ref `{base}` 是自引用（diff 恒空 ⇒ 绕门）—— {BASE_ENV} 须为真实远端 base（如 origin/develop），不可设 HEAD/@"
        );
    }
    // base 不可解析 ⇒ fail-closed（非静默当空 diff）。`^{{commit}}` = git peeling：强制确认 base 能解析为
    // commit 对象（非裸 tag/tree），比裸 rev-parse 更严格，防误传非 commit ref 致 diff 错误。
    let commitish = format!("{base}^{{commit}}");
    let resolved = clean_cmd(
        "git",
        &["rev-parse", "--verify", "--quiet", commitish.as_str()],
        &[],
        Some(root),
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .with_context(|| format!("git rev-parse {base} 启动失败"))?
    .success();
    if !resolved {
        bail!(
            "diff-coverage: base ref `{base}` 不可解析 —— fail-closed（`git remote -v` 查 remote 名后 \
             `git fetch <remote> develop`，或设 {BASE_ENV}=<remote>/<branch>；不静默放行以免漏门）"
        );
    }
    let range = format!("{base}...HEAD");
    let out = clean_cmd(
        "git",
        &[
            "diff",
            "--unified=0",
            "--no-color",
            range.as_str(),
            "--",
            "*.rs",
        ],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("git diff {range} 启动失败"))?;
    if !out.status.success() {
        bail!(
            "diff-coverage: git diff {range} 非零退出:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// ci 入口：base → git diff → 评分 → 判定。I/O（[`resolve_base`]/[`git_diff`]）与可测核（[`score_diff`]/
/// [`verdict`]）分离。`lcov_text` 由 [`crate::coverage`] 用同一 profdata 产出后传入（不在本门重跑测试）。
pub(crate) fn check(root: &Path, lcov_text: &str) -> Result<()> {
    let base = resolve_base();
    let diff = git_diff(root, &base)?;
    let s = score_diff(&diff, lcov_text, root);
    verdict(&s, &base)
}

/// diff 文本 × lcov 文本 → 评分。lcov 的 `SF:` key 先归一为 repo 相对再与 diff 的 `b/<path>` 交叉；并读各
/// 变更文件 HEAD 内容算 inline `#[cfg(test)]` 行（[`test_line_ranges`]，F2 排除）。读文件失败（不存在等）⇒
/// 该文件 test 行视为空（不影响 fail-closed：缺 lcov 仍走 missing）。
fn score_diff(diff: &str, lcov_text: &str, root: &Path) -> Score {
    let added = parse_unified_diff(diff);
    let lcov_rel: BTreeMap<String, BTreeMap<u32, u64>> = parse_lcov(lcov_text)
        .into_iter()
        .map(|(sf, m)| (repo_rel(&sf, root), m))
        .collect();
    let test_lines: BTreeMap<String, BTreeSet<u32>> = added
        .keys()
        .filter(|f| !is_excluded(f))
        .filter_map(|f| {
            std::fs::read_to_string(root.join(f))
                .ok()
                .map(|c| (f.clone(), test_line_ranges(&c)))
        })
        .collect();
    score(&added, &lcov_rel, &test_lines)
}

/// 判定 + 诊断（无 I/O，可测）。COVERAGE-DIFF-FLOOR-01：
/// - 可执行新增行 < [`DIFF_MIN_PERCENT`]% ⇒ `bail`；
/// - **F1 anti-vacuity**：`executable==0` 但有 `missing`（生产文件缺 lcov 数据，feature-gated/未编译）⇒
///   `bail`（**不**静默 0/0 通过）；
/// - `executable>0` 但有 `missing` ⇒ 通过但 `eprintln` 警示（surface 缺测面，非阻断——避免误杀 feature-gated）；
/// - 否则（`executable==0` 且无 missing = 真无新生产代码 / 达标）⇒ `Ok`。
fn verdict(s: &Score, base: &str) -> Result<()> {
    if let Some(pct) = evaluate(s.covered, s.executable) {
        bail!("diff-coverage: {}", render(pct, s));
    }
    if s.executable == 0 && !s.missing.is_empty() {
        bail!("diff-coverage: {}", render_missing(s));
    }
    if !s.missing.is_empty() {
        eprintln!(
            "diff-coverage: ⚠ {} 行新增生产代码缺覆盖数据（feature-gated/未编译，不计门；如 {} 等）——\
             集成 lane（#1145 第②项）覆盖或显式 exclude",
            s.missing.len(),
            sample_loc(&s.missing),
        );
    }
    eprintln!(
        "diff-coverage: 增量覆盖率门通过（{}/{} 可执行新增行被测，base {base}）",
        s.covered, s.executable
    );
    Ok(())
}

/// F1 fail-closed 诊断：可执行新增行为 0 但有生产文件缺 lcov 数据（疑 false-green）。
fn render_missing(s: &Score) -> String {
    format!(
        "diff 含 {} 行新增生产代码无覆盖数据（feature-gated/未编译？如 {}），且无任何可度量可执行行 —— \
         fail-closed 拒静默 0/0 通过：加测试覆盖、或把这些文件纳入 EXCLUDE（tests/benches/generated 范式）",
        s.missing.len(),
        sample_loc(&s.missing),
    )
}

/// 取前若干 `file:line` 作样例（诊断，截断）。
fn sample_loc(items: &[(String, u32)]) -> String {
    const SHOW: usize = 5;
    let shown: Vec<String> = items
        .iter()
        .take(SHOW)
        .map(|(f, ln)| format!("{f}:{ln}"))
        .collect();
    let more = items.len().saturating_sub(SHOW);
    if more > 0 {
        format!("{}…(+{more})", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

// ====== end impl region ======

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;

    // ---------- parse_unified_diff ----------

    #[test]
    fn diff_single_hunk_added_lines() {
        let d = "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n\
                 index 0..1 100644\n--- a/crates/x/src/a.rs\n+++ b/crates/x/src/a.rs\n\
                 @@ -10,0 +11,2 @@\n+let a = 1;\n+let b = 2;\n";
        let m = parse_unified_diff(d);
        assert_eq!(m.get("crates/x/src/a.rs"), Some(&BTreeSet::from([11, 12])));
    }

    #[test]
    fn diff_count_omitted_means_one() {
        let d = "+++ b/x.rs\n@@ -5 +6 @@\n+one line\n";
        assert_eq!(
            parse_unified_diff(d).get("x.rs"),
            Some(&BTreeSet::from([6]))
        );
    }

    #[test]
    fn diff_multi_hunk_multi_file() {
        let d = "+++ b/a.rs\n@@ -1,0 +2,1 @@\n+a\n@@ -10,0 +20,2 @@\n+b\n+c\n\
                 +++ b/sub/d.rs\n@@ -0,0 +1,1 @@\n+d\n";
        let m = parse_unified_diff(d);
        assert_eq!(m.get("a.rs"), Some(&BTreeSet::from([2, 20, 21])));
        assert_eq!(m.get("sub/d.rs"), Some(&BTreeSet::from([1])));
    }

    #[test]
    fn diff_new_file_dev_null_old() {
        let d = "diff --git a/n.rs b/n.rs\nnew file mode 100644\n--- /dev/null\n\
                 +++ b/n.rs\n@@ -0,0 +1,2 @@\n+x\n+y\n";
        assert_eq!(
            parse_unified_diff(d).get("n.rs"),
            Some(&BTreeSet::from([1, 2]))
        );
    }

    #[test]
    fn diff_deleted_file_no_added() {
        let d = "diff --git a/g.rs b/g.rs\ndeleted file mode 100644\n--- a/g.rs\n\
                 +++ /dev/null\n@@ -1,2 +0,0 @@\n-x\n-y\n";
        assert!(parse_unified_diff(d).is_empty());
    }

    #[test]
    fn diff_removed_lines_dont_advance_new_counter() {
        // 删一行 + 加一行：新增行号取 +c（删除不推进新侧计数）。
        let d = "+++ b/m.rs\n@@ -5,1 +5,1 @@\n-old\n+new\n";
        assert_eq!(
            parse_unified_diff(d).get("m.rs"),
            Some(&BTreeSet::from([5]))
        );
    }

    // ---------- parse_hunk_new_start ----------

    #[test]
    fn hunk_start_parses_new_side() {
        assert_eq!(parse_hunk_new_start("@@ -10,0 +11,2 @@"), Some(11));
        assert_eq!(parse_hunk_new_start("@@ -5 +6 @@ fn foo()"), Some(6));
        assert_eq!(parse_hunk_new_start("not a hunk"), None);
    }

    // ---------- parse_lcov ----------

    /// 取 `file → line` 命中数（避免测试用 `unwrap`——本 workspace clippy deny `unwrap_used`）。
    fn hit(m: &BTreeMap<String, BTreeMap<u32, u64>>, file: &str, line: u32) -> Option<u64> {
        m.get(file).and_then(|f| f.get(&line).copied())
    }

    #[test]
    fn lcov_da_per_file() {
        let l = "SF:/r/crates/x/src/a.rs\nDA:1,5\nDA:2,0\nDA:3,1\nend_of_record\n\
                 SF:/r/crates/y/b.rs\nDA:10,0\nend_of_record\n";
        let m = parse_lcov(l);
        assert_eq!(hit(&m, "/r/crates/x/src/a.rs", 1), Some(5));
        assert_eq!(hit(&m, "/r/crates/x/src/a.rs", 2), Some(0));
        assert_eq!(hit(&m, "/r/crates/x/src/a.rs", 3), Some(1));
        assert_eq!(hit(&m, "/r/crates/y/b.rs", 10), Some(0));
    }

    #[test]
    fn lcov_da_with_checksum_field() {
        let l = "SF:/r/a.rs\nDA:7,3,abcdef0123\nend_of_record\n";
        assert_eq!(hit(&parse_lcov(l), "/r/a.rs", 7), Some(3));
    }

    #[test]
    fn lcov_ignores_non_da_records() {
        let l =
            "SF:/r/a.rs\nFN:1,foo\nFNDA:2,foo\nDA:1,1\nBRDA:1,0,0,1\nLF:1\nLH:1\nend_of_record\n";
        let m = parse_lcov(l);
        assert_eq!(m.get("/r/a.rs").map(BTreeMap::len), Some(1));
        assert_eq!(hit(&m, "/r/a.rs", 1), Some(1));
    }

    // ---------- repo_rel ----------

    #[test]
    fn repo_rel_strips_root_prefix() {
        let root = Path::new("/repo/wt");
        assert_eq!(
            repo_rel("/repo/wt/crates/x/src/a.rs", root),
            "crates/x/src/a.rs"
        );
        // 已相对 → 原样。
        assert_eq!(repo_rel("crates/x/src/a.rs", root), "crates/x/src/a.rs");
    }

    // ---------- is_excluded ----------

    #[test]
    fn excluded_paths() {
        assert!(is_excluded("adapters/amqp/tests/integration.rs"));
        assert!(is_excluded("crates/x/benches/b.rs"));
        assert!(is_excluded("generated/src/http.rs"));
        assert!(!is_excluded("crates/x/src/a.rs"));
        assert!(!is_excluded("adapters/amqp/src/lib.rs"));
    }

    // ---------- score ----------

    fn added(pairs: &[(&str, &[u32])]) -> BTreeMap<String, BTreeSet<u32>> {
        pairs
            .iter()
            .map(|(f, lns)| ((*f).to_owned(), lns.iter().copied().collect()))
            .collect()
    }
    fn lcov(pairs: &[(&str, &[(u32, u64)])]) -> BTreeMap<String, BTreeMap<u32, u64>> {
        pairs
            .iter()
            .map(|(f, das)| ((*f).to_owned(), das.iter().copied().collect()))
            .collect()
    }
    /// 无 inline test 行排除（多数 score 测试不涉及 F2）。
    fn no_tests() -> BTreeMap<String, BTreeSet<u32>> {
        BTreeMap::new()
    }
    fn loc(pairs: &[(&str, u32)]) -> Vec<(String, u32)> {
        pairs.iter().map(|(f, l)| ((*f).to_owned(), *l)).collect()
    }

    #[test]
    fn score_all_covered() {
        let s = score(
            &added(&[("crates/x/src/a.rs", &[1, 2, 3])]),
            &lcov(&[("crates/x/src/a.rs", &[(1, 5), (2, 1), (3, 2)])]),
            &no_tests(),
        );
        assert_eq!((s.covered, s.executable), (3, 3));
        assert!(s.missing.is_empty());
    }

    #[test]
    fn score_some_uncovered() {
        let s = score(
            &added(&[("crates/x/src/a.rs", &[1, 2, 3, 4, 5])]),
            &lcov(&[(
                "crates/x/src/a.rs",
                &[(1, 1), (2, 1), (3, 1), (4, 0), (5, 0)],
            )]),
            &no_tests(),
        );
        assert_eq!((s.covered, s.executable), (3, 5));
        assert_eq!(
            s.uncovered,
            loc(&[("crates/x/src/a.rs", 4), ("crates/x/src/a.rs", 5)])
        );
    }

    #[test]
    fn score_non_executable_added_lines_excluded() {
        // 行 2、4 无 DA（注释/空行）⇒ 不计入分母；仅 1、3 可执行。
        let s = score(
            &added(&[("crates/x/src/a.rs", &[1, 2, 3, 4])]),
            &lcov(&[("crates/x/src/a.rs", &[(1, 1), (3, 0)])]),
            &no_tests(),
        );
        assert_eq!((s.covered, s.executable), (1, 2));
    }

    #[test]
    fn score_excludes_test_bench_generated() {
        let s = score(
            &added(&[
                ("adapters/x/tests/it.rs", &[1]),
                ("crates/x/benches/b.rs", &[1]),
                ("generated/src/g.rs", &[1]),
                ("crates/x/src/a.rs", &[1]),
            ]),
            &lcov(&[
                ("adapters/x/tests/it.rs", &[(1, 0)]),
                ("crates/x/benches/b.rs", &[(1, 0)]),
                ("generated/src/g.rs", &[(1, 0)]),
                ("crates/x/src/a.rs", &[(1, 1)]),
            ]),
            &no_tests(),
        );
        // 仅 prod a.rs 计入；排除路径不进 missing。
        assert_eq!((s.covered, s.executable), (1, 1));
        assert!(s.missing.is_empty());
    }

    /// F1：生产文件整体缺 lcov 记录（feature-gated/未编译）⇒ 进 `missing`（非静默跳过），不计入分母。
    #[test]
    fn score_missing_coverage_data_tracked() {
        let s = score(
            &added(&[("crates/x/src/new.rs", &[1, 2])]),
            &lcov(&[]),
            &no_tests(),
        );
        assert_eq!((s.covered, s.executable), (0, 0));
        assert_eq!(
            s.missing,
            loc(&[("crates/x/src/new.rs", 1), ("crates/x/src/new.rs", 2)])
        );
    }

    /// F2：inline `#[cfg(test)]` 行（test_lines）从分母剔除——避免被测的测试码稀释生产未覆盖。
    #[test]
    fn score_excludes_inline_test_lines() {
        let tests: BTreeMap<String, BTreeSet<u32>> =
            [("crates/x/src/a.rs".to_owned(), BTreeSet::from([3, 4]))].into();
        let s = score(
            &added(&[("crates/x/src/a.rs", &[1, 2, 3, 4])]),
            // 行 1 未覆盖（生产）、行 2 覆盖（生产）、行 3/4 是被覆盖的 inline test 行。
            &lcov(&[("crates/x/src/a.rs", &[(1, 0), (2, 1), (3, 1), (4, 1)])]),
            &tests,
        );
        // 仅生产行 1、2 计入：1/2（test 行 3/4 不抬高分子分母）。
        assert_eq!((s.covered, s.executable), (1, 2));
        assert_eq!(s.uncovered, loc(&[("crates/x/src/a.rs", 1)]));
    }

    #[test]
    fn score_empty_diff() {
        let s = score(&added(&[]), &lcov(&[]), &no_tests());
        assert_eq!((s.covered, s.executable), (0, 0));
        assert!(s.missing.is_empty());
    }

    // ---------- evaluate ----------

    #[test]
    fn evaluate_total_zero_passes() {
        assert_eq!(evaluate(0, 0), None);
    }

    #[test]
    fn evaluate_below_threshold_fails() {
        assert_eq!(evaluate(79, 100), Some(79.0));
    }

    #[test]
    fn evaluate_exactly_threshold_passes() {
        assert_eq!(evaluate(80, 100), None); // 80.0 ≥ 80
        assert_eq!(evaluate(4, 5), None); // 80%
    }

    #[test]
    fn evaluate_just_below_fails() {
        assert_eq!(evaluate(3, 4), Some(75.0)); // 75 < 80
    }

    // ---------- doc-verbatim ----------

    #[test]
    fn diff_min_percent_is_doc_verbatim() {
        assert_eq!(DIFF_MIN_PERCENT, 80);
    }

    // ---------- render ----------

    #[test]
    fn render_mentions_pct_and_uncovered() {
        let s = Score {
            covered: 3,
            executable: 5,
            uncovered: vec![("crates/x/src/a.rs".to_owned(), 4)],
            ..Default::default()
        };
        let msg = render(60.0, &s);
        assert!(msg.contains("60"));
        assert!(msg.contains("80"));
        assert!(msg.contains("crates/x/src/a.rs"));
        assert!(msg.contains('4'));
    }

    // ---------- score_diff / verdict / resolve_base ----------

    #[test]
    fn score_diff_intersects_diff_and_lcov() {
        // diff 新增行 1/2/3；lcov：行1覆盖、行2未覆盖、行3无 DA（非可执行）⇒ 1/2。
        let diff = "+++ b/crates/x/src/a.rs\n@@ -0,0 +1,3 @@\n+a\n+b\n+c\n";
        let lcov = "SF:/wt/crates/x/src/a.rs\nDA:1,1\nDA:2,0\nend_of_record\n";
        let s = score_diff(diff, lcov, Path::new("/wt"));
        assert_eq!((s.covered, s.executable), (1, 2));
    }

    fn sc(covered: u64, executable: u64) -> Score {
        Score {
            covered,
            executable,
            ..Default::default()
        }
    }

    #[test]
    fn verdict_pass_empty_and_fail() {
        assert!(verdict(&sc(4, 5), "origin/develop").is_ok()); // 80% 达标
        assert!(verdict(&sc(0, 0), "origin/develop").is_ok()); // 空：无可度量新代码
        assert!(verdict(&sc(1, 5), "origin/develop").is_err()); // 20% < 80（COVERAGE-DIFF-FLOOR-01）
        // 边界红例（强化 anti-vacuity）：79/100 = 79% < 80 ⇒ verdict 层亦 fail（render 需 uncovered 非空）。
        let near = Score {
            covered: 79,
            executable: 100,
            uncovered: vec![("crates/x/src/a.rs".to_owned(), 7)],
            ..Default::default()
        };
        assert!(verdict(&near, "origin/develop").is_err());
    }

    /// F1：`executable==0` 但有 missing（生产文件缺 lcov 数据）⇒ verdict **fail-closed**（不静默 0/0 通过）。
    #[test]
    fn verdict_missing_with_no_executable_fails_closed() {
        let s = Score {
            missing: loc(&[("crates/x/src/new.rs", 1)]),
            ..Default::default()
        };
        assert!(verdict(&s, "origin/develop").is_err());
    }

    /// F1：有可执行行达标 + 有 missing ⇒ 通过（missing 仅 warn，不误杀 feature-gated）。
    #[test]
    fn verdict_missing_with_executable_passes() {
        let s = Score {
            covered: 5,
            executable: 5,
            missing: loc(&[("adapters/y/src/feat.rs", 9)]),
            ..Default::default()
        };
        assert!(verdict(&s, "origin/develop").is_ok());
    }

    #[test]
    fn resolve_base_from_env_or_default() {
        assert_eq!(resolve_base_from(None), DEFAULT_BASE);
        assert_eq!(
            resolve_base_from(Some("azure/develop".to_owned())),
            "azure/develop"
        );
    }

    // ---------- F2 test_line_ranges / F3 is_self_ref ----------

    #[test]
    fn test_line_ranges_marks_top_level_cfg_test_block() {
        let src = "fn prod() {}\n\
                   #[cfg(test)]\n\
                   mod tests {\n\
                   \x20\x20\x20\x20fn t() { let s = format!(\"{x}\"); }\n\
                   }\n\
                   fn after() {}\n";
        // 行 2(#[cfg(test)]) 3(mod) 4(fn t，含字符串内 `{}`) 5(}) 为 test 范围；行 1、6 是生产。
        let r = test_line_ranges(src);
        assert_eq!(r, BTreeSet::from([2, 3, 4, 5]));
        assert!(!r.contains(&1) && !r.contains(&6));
    }

    #[test]
    fn test_line_ranges_none_when_no_cfg_test() {
        assert!(test_line_ranges("fn a() {}\nfn b() {}\n").is_empty());
    }

    #[test]
    fn is_self_ref_rejects_head_variants() {
        for b in ["HEAD", "@", "HEAD~0", "HEAD^0", "@~0", " HEAD "] {
            assert!(is_self_ref(b), "{b} 应判为自引用");
        }
        for b in [
            "origin/develop",
            "azure/develop",
            "HEAD~1",
            "main",
            "develop",
        ] {
            assert!(!is_self_ref(b), "{b} 不应判为自引用");
        }
    }

    // ---------- end-to-end: 临时 git repo + fixture lcov ----------

    /// 跑 git 子进程（经 clean_cmd——CMD-FUNNEL-01；身份经 env，静默 stdio）。
    fn git(dir: &Path, args: &[&str]) -> Result<()> {
        let st = clean_cmd(
            "git",
            args,
            &[
                ("GIT_AUTHOR_NAME", "t"),
                ("GIT_AUTHOR_EMAIL", "t@t"),
                ("GIT_COMMITTER_NAME", "t"),
                ("GIT_COMMITTER_EMAIL", "t@t"),
            ],
            Some(dir),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
        if !st.success() {
            bail!("git {args:?} 失败");
        }
        Ok(())
    }

    #[test]
    fn end_to_end_git_diff_scores_below_threshold() -> Result<()> {
        let dir = unique_tmp("diffcov");
        std::fs::create_dir_all(dir.join("crates/x/src"))?;
        git(&dir, &["-c", "init.defaultBranch=main", "init", "-q"])?;
        std::fs::write(dir.join("crates/x/src/a.rs"), "fn base() {}\n")?;
        git(&dir, &["add", "-A"])?;
        git(&dir, &["commit", "-q", "-m", "base"])?;
        git(&dir, &["checkout", "-q", "-b", "feat"])?;
        // 加两条可执行行：一覆盖一未覆盖。
        std::fs::write(
            dir.join("crates/x/src/a.rs"),
            "fn base() {}\nfn covered() {}\nfn uncovered() {}\n",
        )?;
        git(&dir, &["add", "-A"])?;
        git(&dir, &["commit", "-q", "-m", "feat"])?;

        let abs = dir.join("crates/x/src/a.rs");
        let lcov_text = format!("SF:{}\nDA:2,1\nDA:3,0\nend_of_record\n", abs.display());

        let diff = git_diff(&dir, "main")?;
        // pathspec `*.rs` 须匹配子目录文件（git pathspec `*` 跨 `/`）——空 diff = pathspec 漏子目录回归。
        assert!(
            !diff.is_empty(),
            "git diff 返回空——pathspec 可能漏匹配子目录"
        );
        assert_eq!(
            parse_unified_diff(&diff).get("crates/x/src/a.rs"),
            Some(&BTreeSet::from([2, 3]))
        );
        // score_diff 端到端：行2覆盖、行3未覆盖 ⇒ 1/2 = 50% < 80。
        let s = score_diff(&diff, &lcov_text, &dir);
        assert_eq!((s.covered, s.executable), (1, 2));
        assert_eq!(evaluate(s.covered, s.executable), Some(50.0));

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn git_diff_unresolved_base_fails_closed() -> Result<()> {
        let dir = unique_tmp("diffcov-nobase");
        std::fs::create_dir_all(&dir)?;
        git(&dir, &["init", "-q"])?;
        assert!(git_diff(&dir, "does/not/exist").is_err());
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// base 输入校验 fail-closed：空 / `-` 前缀（git 误解析为选项）/ 自引用 `HEAD`（diff 恒空绕门，F3）即拒
    /// （校验先于任何 git 调用，无需 repo）。
    #[test]
    fn git_diff_rejects_illegal_base() {
        let nonexist = Path::new("/nonexistent-rss-diffcov");
        assert!(git_diff(nonexist, "").is_err());
        assert!(git_diff(nonexist, "-e").is_err());
        assert!(git_diff(nonexist, "--output=/etc/passwd").is_err());
        assert!(git_diff(nonexist, "HEAD").is_err()); // F3 自引用绕门
        assert!(git_diff(nonexist, "@").is_err());
    }

    /// check 经 [`resolve_base`]（默认 `origin/develop`）+ [`git_diff`]：临时 repo 无该 base ⇒ fail-closed
    /// （非静默放行）。覆盖 check 的 I/O 编排 + git_diff 错误路径。
    #[test]
    fn check_fails_closed_when_base_absent() -> Result<()> {
        let dir = unique_tmp("diffcov-check");
        std::fs::create_dir_all(&dir)?;
        git(&dir, &["init", "-q"])?;
        assert!(check(&dir, "").is_err());
        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
