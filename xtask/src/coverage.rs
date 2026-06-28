//! `cargo xtask ci` 覆盖率门 —— 跑**一次** `cargo llvm-cov nextest --workspace`（出 export JSON，**兼作
//! nextest 门**：测试必须全绿，并留下 profdata）后评**两子门**（不重复跑测试）：
//!
//! 1. **绝对地板门**（本模块）：export JSON → basis/engine 严格 crate（`vocab`/`ids`/`consistency`/
//!    `primitives`，CLAUDE.md / rust-standards.md「引擎与基础 crate ≥90%」逐字集）per-crate 行覆盖率下限。
//! 2. **per-diff 增量门**（[`crate::diffcov`]）：复用同一 profdata 经 `cargo llvm-cov report --lcov` 出 lcov
//!    （[`lcov_report`]，不重跑测试）→ 本 PR diff（相对 base，默认 `origin/develop`）新增/修改可执行行聚合
//!    覆盖率 ≥80%（CLAUDE.md「新增/修改代码 ≥80%」）。补地板门测不到的「新代码自身被测」洞——全在
//!    adapters/域 crate 的大改动可零新测试照样过地板门。
//!
//! **不入 `cargo xtask verify`**（verify 是 stable-only 本地快门；覆盖率门慢、需 `cargo-llvm-cov` 工具 +
//! 全 workspace 跑），只在 `cargo xtask ci`（CI 超集）内、由 azure-pipelines.yml 调用。issue #1132 验收
//! 「cargo nextest run --workspace + cargo llvm-cov 阈值门（引擎/基础 ≥90%）」由本**一步**同时兑现——
//! 单跑一次测试既是 nextest 门又出覆盖率（不重复跑）。集成测试 `#[cfg(feature="integration")]` 默认不
//! 编入 ⇒ 无需 DB/broker。
//!
//! **ratchet 例外**：`consistency` 的 L3/L4 接缝（`saga`/`reconcile`/`projection`）当前是签名冻结
//! `todo!()` 桩（「行为 PR 兑现」，无法测——调用即 panic），把 crate 覆盖率压到 ~88%。这**非测试债**
//! （已实现的 idempotency/outbox/error ~100%）。故 `consistency` 暂设 ratchet 下限 85%（[`RATCHET_FLOORS`]，
//! 留 thaw 余量）；待接缝兑现+测试落地后 restore 90%（follow-up #1146）。其余 STRICT crate 守默认 90%。
//!
//! INVARIANT: COVERAGE-STRICT-FLOOR-01 { level = "Medium", exec = "ci-only", source = "code" }—— [`STRICT_CRATES`] 任一 crate 行覆盖率 < 其 [`floor_for`] 下限
//!   **或未被测量**（JSON 无其数据 / 0 行）⇒ ci 非零退出。缺测量也 fail：杜绝「没跑到 = 静默绿」的 vacuity。
//!   per-diff 增量门的不变式（COVERAGE-DIFF-FLOOR-01）见 [`crate::diffcov`]。

use crate::cmd::clean_cmd;
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// 强制行覆盖率下限的 basis/engine crate —— CLAUDE.md / rust-standards.md「引擎与基础 crate
/// （`consistency` / `primitives` / `vocab` / `ids`）≥90%」**逐字集**（非 `BASIS_CRATES ∪ ENGINE_CRATES`
/// 全集：`secure`/`support`/`runctx` 不在 90 档）。单一事实源；与文档集一致性由 `strict_set_is_doc_verbatim`
/// 测试守（改文档不改这里即测试红）。
pub(crate) const STRICT_CRATES: &[&str] = &["vocab", "ids", "consistency", "primitives"];

/// STRICT crate 默认行覆盖率下限（%）= CLAUDE.md 目标。
const DEFAULT_MIN_PERCENT: f64 = 90.0;

/// ratchet 例外：暂未达 [`DEFAULT_MIN_PERCENT`] 的 STRICT crate 的**有记录**下限（含原因）。仅
/// `consistency`——其 L3/L4 接缝（saga/reconcile/projection）仍是签名冻结 `todo!()` 桩（行为 PR 未兑现，
/// 无法测），把 crate 压到 ~88%；暂设 85（thaw 余量），待桩兑现+测试落地 restore 90（follow-up #1146）。
/// **新增 ratchet 必须显式登记于此并附 follow-up**——`ratchet_floors_only_consistency` 测试守不被静默扩容。
const RATCHET_FLOORS: &[(&str, f64)] = &[("consistency", 85.0)];

/// 某 crate 的行覆盖率下限：有 ratchet 例外取例外值，否则取默认 90%。
fn floor_for(crate_name: &str) -> f64 {
    RATCHET_FLOORS
        .iter()
        .find(|(c, _)| *c == crate_name)
        .map_or(DEFAULT_MIN_PERCENT, |(_, f)| *f)
}

/// llvm-cov `export` JSON 顶层（仅取本门需要字段，其余 serde 忽略）。
/// schema ref: cargo-llvm-cov src/json.rs@main（`data[].files[].summary.lines.{count,covered}`）。
#[derive(serde::Deserialize)]
struct LlvmCovExport {
    data: Vec<ExportDatum>,
}
#[derive(serde::Deserialize)]
struct ExportDatum {
    files: Vec<FileCov>,
}
#[derive(serde::Deserialize)]
struct FileCov {
    filename: String,
    summary: FileSummary,
}
#[derive(serde::Deserialize)]
struct FileSummary {
    lines: LineCounts,
}
#[derive(serde::Deserialize)]
struct LineCounts {
    count: u64,
    covered: u64,
}

/// 一条不达标记录：crate + 实际行覆盖率（`None` = 未测量/0 行）+ 该 crate 下限。
#[derive(Debug, PartialEq)]
struct Shortfall {
    krate: String,
    actual: Option<f64>,
    floor: f64,
}

/// 把绝对文件名归属到 workspace crate 名：找**路径组件** `crates`，取紧随的下一段为 crate 名。非
/// `crates/` 路径（`adapters/` / `bins/` / `generated` / …）→ `None`。用组件级匹配（非裸 substring
/// `split("crates/")`）以免 `…/extracrates/vocab/…` 误归属（review #206 A2/A3）。
fn crate_of_file(filename: &str) -> Option<&str> {
    let mut comps = filename.split('/');
    while let Some(c) = comps.next() {
        if c == "crates" {
            return comps.next().filter(|s| !s.is_empty());
        }
    }
    None
}

/// 从 llvm-cov export JSON 文本聚合每 STRICT crate 的 `(covered, count)` 行数。
fn aggregate(json: &str, strict: &[&str]) -> Result<BTreeMap<String, (u64, u64)>> {
    let export: LlvmCovExport = serde_json::from_str(json).context("解析 llvm-cov JSON 失败")?;
    let mut per_crate: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for datum in &export.data {
        for file in &datum.files {
            if let Some(c) = crate_of_file(&file.filename)
                && strict.contains(&c)
            {
                let e = per_crate.entry(c.to_owned()).or_insert((0, 0));
                e.0 += file.summary.lines.covered;
                e.1 += file.summary.lines.count;
            }
        }
    }
    Ok(per_crate)
}

/// 纯函数：判定每 STRICT crate 是否达其 [`floor_for`] 下限。返回不达标项——`actual=None` = JSON 无该
/// crate 数据 / 0 行 = **未测量**（按 fail，COVERAGE-STRICT-FLOOR-01 anti-vacuity）。空返回 = 全过。
fn evaluate(per_crate: &BTreeMap<String, (u64, u64)>, strict: &[&str]) -> Vec<Shortfall> {
    let mut failing = Vec::new();
    for &c in strict {
        let floor = floor_for(c);
        match per_crate.get(c) {
            None | Some(&(_, 0)) => failing.push(Shortfall {
                krate: c.to_owned(),
                actual: None,
                floor,
            }),
            Some(&(covered, count)) => {
                let pct = covered as f64 / count as f64 * 100.0;
                if pct < floor {
                    failing.push(Shortfall {
                        krate: c.to_owned(),
                        actual: Some(pct),
                        floor,
                    });
                }
            }
        }
    }
    failing
}

fn render_failures(failing: &[Shortfall]) -> String {
    let items: Vec<String> = failing
        .iter()
        .map(|s| match s.actual {
            Some(p) => format!("{} {p:.1}% < {:.0}%", s.krate, s.floor),
            None => format!("{}（未测量/0 行）", s.krate),
        })
        .collect();
    format!(
        "{} 个 basis/engine crate 未达行覆盖率下限：{}（补表驱动测试或按 ratchet issue 处理）",
        failing.len(),
        items.join("; ")
    )
}

/// ci 覆盖率门：跑 llvm-cov nextest（= nextest 门，留 profdata）→ 评**两子门**（任一红即 ci 非零退出）：
/// ① 绝对地板（export JSON）；② per-diff 增量（复用同一 profdata 出 lcov，不重跑测试，见 [`crate::diffcov`]）。
pub(crate) fn run() -> Result<()> {
    let root = workspace_root()?;
    let json = run_llvm_cov(&root)?;
    // ① 绝对地板门：basis/engine STRICT crate per-crate 行覆盖率下限（COVERAGE-STRICT-FLOOR-01）。
    let per_crate = aggregate(&json, STRICT_CRATES)?;
    let failing = evaluate(&per_crate, STRICT_CRATES);
    if !failing.is_empty() {
        bail!("coverage: {}", render_failures(&failing));
    }
    // ratchet 提示从 RATCHET_FLOORS 派生（单源，避免硬编码 "85%" 与 ratchet 改动漂移）。
    let ratchet = RATCHET_FLOORS
        .iter()
        .map(|(c, f)| format!("{c} ratchet {f:.0}%"))
        .collect::<Vec<_>>()
        .join("、");
    eprintln!(
        "coverage: STRICT basis/engine crate 均达行覆盖率下限（{}；{ratchet}）",
        STRICT_CRATES.join(", ")
    );
    // ② per-diff 增量门：复用 nextest 跑测试留下的 profdata 出 lcov（不重跑测试），本 PR 新增/修改可执行行
    //    ≥80%（COVERAGE-DIFF-FLOOR-01，见 crate::diffcov）。
    let lcov = lcov_report(&root)?;
    crate::diffcov::check(&root, &lcov)
}

/// 跑 `cargo llvm-cov nextest --workspace --json --output-path <file>`（默认 feature——集成测试不编入
/// ⇒ 无需 DB/broker）。stdio 继承（实时看测试输出）。非零退出 = 测试失败（nextest 门）⇒ `Err`。
/// `NEXTEST_PROFILE=ci`（fail-fast=false + retries，见 `.config/nextest.toml`；用 env 而非 `--profile`
/// 避免与 llvm-cov 自身 `--profile`（cargo build profile）的 flag 撞名）。本步留下的 profdata 由
/// [`lcov_report`] 复用出 lcov（per-diff 增量门），不重跑测试。
fn run_llvm_cov(root: &Path) -> Result<String> {
    // 跟随 CARGO_TARGET_DIR（clean_cmd 不清它——见 cmd.rs STRIPPED_ENV charter），否则默认 root/target；
    // 与 llvm-cov 实际写 JSON 的 target 目录一致（review #206 C6）。
    let out = coverage_target_dir(root).join("xtask-ci-coverage.json");
    let out_str = out.to_str().context("覆盖率 JSON 输出路径非法 UTF-8")?;
    let status = clean_cmd(
        "cargo",
        &[
            "llvm-cov",
            "nextest",
            "--workspace",
            "--locked", // CI 确定性：Cargo.lock 漂移即 fail（review #206 codex F2）
            "--json",
            "--output-path",
            out_str,
        ],
        &[("NEXTEST_PROFILE", "ci")],
        Some(root),
    )
    .status()
    .context("启动 cargo llvm-cov nextest 失败")?;
    if !status.success() {
        let code = status
            .code()
            .map_or_else(|| "signal".to_owned(), |c| c.to_string());
        bail!("coverage: nextest 门失败（cargo llvm-cov nextest 退出码 {code}）");
    }
    std::fs::read_to_string(&out).with_context(|| format!("读覆盖率 JSON 失败: {}", out.display()))
}

/// 复用 [`run_llvm_cov`] 跑测试留下的 profdata 出 lcov（`cargo llvm-cov report --lcov`，**不重跑测试**），
/// 供 per-diff 增量门（[`crate::diffcov`]）。落盘同 [`run_llvm_cov`] 跟随 `CARGO_TARGET_DIR`。
///
/// **不传 `--workspace`**（与 [`run_llvm_cov`] 不同）：`report` 无编译阶段，覆盖范围由上一步 `--workspace`
/// instrumented 编译的 profdata 决定，已含全 workspace（实测 `report` 输出全 workspace crate 的 lcov）；
/// 且 `cargo llvm-cov report` **不接受** `--workspace`（传入即报错）——勿误加。
fn lcov_report(root: &Path) -> Result<String> {
    let out = coverage_target_dir(root).join("xtask-ci-coverage.lcov");
    let out_str = out.to_str().context("覆盖率 lcov 输出路径非法 UTF-8")?;
    let status = clean_cmd(
        "cargo",
        &["llvm-cov", "report", "--lcov", "--output-path", out_str],
        &[],
        Some(root),
    )
    .status()
    .context("启动 cargo llvm-cov report --lcov 失败")?;
    if !status.success() {
        let code = status
            .code()
            .map_or_else(|| "signal".to_owned(), |c| c.to_string());
        bail!("coverage: cargo llvm-cov report --lcov 退出码 {code}");
    }
    std::fs::read_to_string(&out).with_context(|| format!("读覆盖率 lcov 失败: {}", out.display()))
}

/// 覆盖率产物落盘目录：跟随 `CARGO_TARGET_DIR`（clean_cmd 不清它），否则默认 `root/target`。JSON / lcov 共用。
fn coverage_target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, u64, u64)]) -> BTreeMap<String, (u64, u64)> {
        pairs
            .iter()
            .map(|(c, covered, count)| ((*c).to_owned(), (*covered, *count)))
            .collect()
    }

    fn shortfall(krate: &str, actual: Option<f64>, floor: f64) -> Shortfall {
        Shortfall {
            krate: krate.to_owned(),
            actual,
            floor,
        }
    }

    /// STRICT 集 = CLAUDE.md / rust-standards.md「引擎与基础 crate ≥90%」逐字集（anti-drift）。
    #[test]
    fn strict_set_is_doc_verbatim() {
        assert_eq!(
            STRICT_CRATES,
            &["vocab", "ids", "consistency", "primitives"]
        );
    }

    /// ratchet 例外只含 consistency（防 ratchet floor 被静默扩容架空 90% 目标）。
    #[test]
    fn ratchet_floors_only_consistency() {
        assert_eq!(RATCHET_FLOORS, &[("consistency", 85.0)]);
    }

    /// floor_for：默认 90，ratchet crate（consistency）取例外 85。
    #[test]
    fn floor_for_default_and_ratchet() {
        assert_eq!(floor_for("vocab"), 90.0);
        assert_eq!(floor_for("primitives"), 90.0);
        assert_eq!(floor_for("consistency"), 85.0);
    }

    /// crate 归属：`crates/<name>/` → `<name>`；非 `crates/`（adapters/generated）→ `None`。
    #[test]
    fn crate_of_file_maps_crates_path_only() {
        assert_eq!(
            crate_of_file("/repo/crates/vocab/src/lib.rs"),
            Some("vocab")
        );
        assert_eq!(
            crate_of_file("/repo/crates/consistency/src/outbox/mod.rs"),
            Some("consistency")
        );
        assert_eq!(crate_of_file("/repo/adapters/redis/src/lib.rs"), None);
        assert_eq!(crate_of_file("/repo/generated/src/http.rs"), None);
        assert_eq!(crate_of_file("/repo/bins/server/src/main.rs"), None);
        // 组件级匹配 anti-false-positive（review #206 A2/A3）：`crates` 作为非独立路径组件不误归属。
        assert_eq!(crate_of_file("/repo/extracrates/vocab/src/lib.rs"), None);
        assert_eq!(crate_of_file("/repo/my_crates/vocab/lib.rs"), None);
        // 相对路径（无前导 /）仍正确。
        assert_eq!(crate_of_file("crates/ids/src/lib.rs"), Some("ids"));
    }

    /// aggregate：跨同 crate 多文件求和；非 STRICT crate（redis）不计。
    #[test]
    fn aggregate_sums_strict_crate_files_only() -> anyhow::Result<()> {
        let json = r#"{"data":[{"files":[
          {"filename":"/r/crates/vocab/src/lib.rs","summary":{"lines":{"count":60,"covered":57}}},
          {"filename":"/r/crates/vocab/src/error.rs","summary":{"lines":{"count":40,"covered":38}}},
          {"filename":"/r/adapters/redis/src/lib.rs","summary":{"lines":{"count":50,"covered":5}}}
        ]}]}"#;
        let agg = aggregate(json, STRICT_CRATES)?;
        assert_eq!(agg.get("vocab"), Some(&(95, 100)));
        assert!(!agg.contains_key("redis")); // 非 STRICT 不计
        Ok(())
    }

    /// aggregate 红例（边界，review #206 A4）：畸形 JSON ⇒ `Err`（不静默吞）。
    #[test]
    fn aggregate_invalid_json_is_err() {
        assert!(aggregate("{ not json", STRICT_CRATES).is_err());
        assert!(aggregate("{\"data\":[{}]}", STRICT_CRATES).is_err()); // 缺 files 字段
    }

    /// evaluate 绿例：全 STRICT crate ≥各自下限（含 consistency 88% ≥ ratchet 85）⇒ 无不达标项。
    #[test]
    fn evaluate_all_pass_is_empty() {
        let m = map(&[
            ("vocab", 95, 100),
            ("ids", 90, 100),
            ("consistency", 88, 100), // 88 ≥ ratchet 85 ⇒ 过
            ("primitives", 91, 100),
        ]);
        assert!(evaluate(&m, STRICT_CRATES).is_empty());
    }

    /// evaluate 红例（anti-vacuity）：默认档 crate 低于 90% 进不达标列表，带实际百分比 + 下限。
    #[test]
    fn evaluate_default_below_threshold_fails() {
        let m = map(&[
            ("vocab", 85, 100), // < 90
            ("ids", 95, 100),
            ("consistency", 95, 100),
            ("primitives", 95, 100),
        ]);
        let failing = evaluate(&m, STRICT_CRATES);
        assert_eq!(failing, vec![shortfall("vocab", Some(85.0), 90.0)]);
    }

    /// ratchet 档（consistency）低于其 85% 下限才 fail（84 < 85 红；88 ≥ 85 绿见上）。
    #[test]
    fn evaluate_ratchet_below_its_floor_fails() {
        let m = map(&[
            ("vocab", 95, 100),
            ("ids", 95, 100),
            ("consistency", 84, 100), // < 85 ratchet
            ("primitives", 95, 100),
        ]);
        let failing = evaluate(&m, STRICT_CRATES);
        assert_eq!(failing, vec![shortfall("consistency", Some(84.0), 85.0)]);
    }

    /// 边界：恰达下限通过（≥，非 >）——consistency 恰 85、vocab 恰 90 均过。
    #[test]
    fn evaluate_exactly_floor_passes() {
        let m = map(&[
            ("vocab", 90, 100),
            ("ids", 90, 100),
            ("consistency", 85, 100),
            ("primitives", 90, 100),
        ]);
        assert!(evaluate(&m, STRICT_CRATES).is_empty());
    }

    /// COVERAGE-STRICT-FLOOR-01：STRICT crate **未测量**（json 缺数据）⇒ fail（`actual=None`），非静默绿。
    #[test]
    fn evaluate_missing_crate_fails_not_vacuous() {
        let m = map(&[
            ("vocab", 99, 100),
            ("ids", 99, 100),
            ("consistency", 99, 100),
        ]);
        // primitives 缺 ⇒ 必须报 fail
        assert_eq!(
            evaluate(&m, STRICT_CRATES),
            vec![shortfall("primitives", None, 90.0)]
        );
    }

    /// 0 行（count=0）也按未测量 fail（防除零 + 防空壳 crate 静默绿）。
    #[test]
    fn evaluate_zero_lines_fails() {
        let m = map(&[
            ("vocab", 0, 0),
            ("ids", 99, 100),
            ("consistency", 99, 100),
            ("primitives", 99, 100),
        ]);
        assert_eq!(
            evaluate(&m, STRICT_CRATES),
            vec![shortfall("vocab", None, 90.0)]
        );
    }

    /// 端到端解析→判定红例：json 里 vocab 88% ⇒ aggregate+evaluate 报 vocab 不达默认 90%。
    #[test]
    fn aggregate_then_evaluate_red() -> anyhow::Result<()> {
        let json = r#"{"data":[{"files":[
          {"filename":"/r/crates/vocab/src/lib.rs","summary":{"lines":{"count":100,"covered":88}}},
          {"filename":"/r/crates/ids/src/lib.rs","summary":{"lines":{"count":100,"covered":95}}},
          {"filename":"/r/crates/consistency/src/lib.rs","summary":{"lines":{"count":100,"covered":95}}},
          {"filename":"/r/crates/primitives/src/lib.rs","summary":{"lines":{"count":100,"covered":95}}}
        ]}]}"#;
        let agg = aggregate(json, STRICT_CRATES)?;
        let failing = evaluate(&agg, STRICT_CRATES);
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0].krate, "vocab");
        Ok(())
    }

    /// render 含 crate 名 + 下限（诊断不空洞）。
    #[test]
    fn render_failures_mentions_crate_and_threshold() {
        let msg = render_failures(&[
            shortfall("vocab", Some(85.0), 90.0),
            shortfall("ids", None, 90.0),
        ]);
        assert!(msg.contains("vocab"));
        assert!(msg.contains("ids"));
        assert!(msg.contains("90"));
    }
}
