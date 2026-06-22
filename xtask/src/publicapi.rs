//! `cargo xtask public-api` —— 库公开 API 面 baseline（封装外部 `cargo-public-api`）。
//!
//! 用途：基础/引擎层签名冻结后把 exported 符号面冻结为可 commit 的 baseline，后续 PR diff
//! （crate 公开 API = 轴 A SemVer，见 `.claude/rules/rss/api-versioning.md`）。
//!
//! **PR-0 仅落工具入口**；baseline 快照随 PR-1/PR-2 产出并 commit 到 `public-api/<crate>.txt`
//! （PR-1 `--layer basis`、PR-2 `--layer engine`；无 `--layer` = 全集，收口 GATE 用）。
//!
//! **漂移门闭环**：`--check` 对目标层任一 baseline 缺失 / 不一致 **默认 fail-fast**；仅 PR-0
//! 自检可显式 `--allow-missing` 宽限缺失（drift 仍 fail）——对齐 cargo-public-api snapshot-gate
//! 范式，杜绝「无 baseline 也绿」的误绿。
//!
//! 依赖：外部 `cargo-public-api`（`cargo install cargo-public-api`）+ nightly rustdoc-json
//! （`rustup toolchain install nightly`）。未满足时本命令给指引并**非零退出**（非静默 noop）。
//!
//! **不在 `cargo xtask verify` 聚合门内**：verify 聚合每次代码改动的强制门（fmt/build/clippy/nextest/deny/
//! dylint + meta）；public-api 是**库封装面 baseline 冻结门**（轴 A SemVer，需 nightly rustdoc-json 重新生成
//! baseline），语义与触发节奏不同，故为独立可选门（单独 `cargo xtask public-api --check`）。
//!
//! INVARIANT: PUBLICAPI-TOOL-GATE-01 —— 工具缺失 fail-fast，不静默成功。
//! INVARIANT: PUBLICAPI-DRIFT-GATE-01 —— `--check` 缺失/漂移默认 fail-fast；缺失豁免仅经显式 `--allow-missing`。

use crate::layers::{BASIS_CRATES, ENGINE_CRATES};
use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;

// 分层成员单源 = `layers.rs`（basis = PR-1 验收集、engine = PR-2 验收集）；此处复用，不另列副本。

/// 封装面 baseline 的目标层。无 `--layer` 时取 basis + engine 全集（收口 GATE 用）。
/// 服务/域/adapters 内部接缝多变，不入 baseline。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Layer {
    Basis,
    Engine,
}

/// 解析 layer → 目标 crate 集。`None` = basis + engine（不另列第三份 ALL，避免漂移）。
fn target_crates(layer: Option<Layer>) -> Vec<&'static str> {
    match layer {
        Some(Layer::Basis) => BASIS_CRATES.to_vec(),
        Some(Layer::Engine) => ENGINE_CRATES.to_vec(),
        None => BASIS_CRATES.iter().chain(ENGINE_CRATES).copied().collect(),
    }
}

/// 生成（`check=false`）或校验（`check=true`）目标层封装面 baseline。
/// `allow_missing`：仅 PR-0 自检显式宽限缺失 baseline（默认缺失即 fail-fast，漂移门闭环）。
pub(crate) fn run(check: bool, allow_missing: bool, layer: Option<Layer>) -> Result<()> {
    ensure_tool_available()?;
    let crates = target_crates(layer);
    let dir = baseline_dir()?;
    if !check {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("创建 baseline 目录失败: {}", dir.display()))?;
    }

    let mut drift = Vec::new();
    let mut missing = Vec::new();
    for krate in &crates {
        let actual = capture_public_api(krate)?;
        let path = dir.join(format!("{krate}.txt"));
        if check {
            match std::fs::read_to_string(&path) {
                Ok(expected) if expected == actual => {}
                Ok(_) => drift.push((*krate).to_owned()),
                // 仅「baseline 尚未生成」(NotFound) 降级为警告；其余 I/O 错误（权限/损坏）fail-fast。
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push((*krate).to_owned())
                }
                Err(e) => {
                    return Err(e).with_context(|| format!("读 baseline 失败: {}", path.display()));
                }
            }
        } else {
            std::fs::write(&path, &actual)
                .with_context(|| format!("写 baseline 失败: {}", path.display()))?;
            eprintln!("public-api: 写入 baseline {}", path.display());
        }
    }
    report(check, allow_missing, &drift, &missing)
}

fn baseline_dir() -> Result<PathBuf> {
    Ok(workspace_root()?.join("public-api"))
}

/// 检测外部 cargo-public-api；缺失即 fail-fast 给安装指引（INVARIANT PUBLICAPI-TOOL-GATE-01）。
fn ensure_tool_available() -> Result<()> {
    if crate::cmd::tool_available("public-api") {
        return Ok(());
    }
    bail!(
        "未找到 `cargo public-api`。安装：\n  \
         cargo install cargo-public-api\n  \
         rustup toolchain install nightly   # rustdoc-json 需 nightly\n\
         仅基础/引擎层封装面冻结需要本工具（非全 workspace 强制门）。"
    )
}

/// 运行 `cargo public-api -p <crate>` 捕获其封装面快照文本。
fn capture_public_api(krate: &str) -> Result<String> {
    let out = crate::cmd::clean_cmd("cargo", &["public-api", "-p", krate], &[], None)
        .output()
        .with_context(|| format!("运行 cargo public-api -p {krate} 失败"))?;
    if !out.status.success() {
        let code = out
            .status
            .code()
            .map_or_else(|| "signal".to_owned(), |c| c.to_string());
        bail!(
            "cargo public-api -p {krate} 非零退出（退出码 {code}）:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 汇报结果。生成模式只报数。校验模式漂移门闭环：
/// - drift 非空 → fail-fast（最高优先，`--allow-missing` 不豁免漂移）。
/// - missing 非空 → 默认 fail-fast；仅 `allow_missing`（PR-0 自检显式宽限）降级为警告。
fn report(check: bool, allow_missing: bool, drift: &[String], missing: &[String]) -> Result<()> {
    if !check {
        eprintln!("public-api: baseline 生成完成");
        return Ok(());
    }
    if !drift.is_empty() {
        bail!(
            "public-api drift：{} crate 封装面与 committed baseline 不一致：{}（确认是否破坏式 API 变更，按 api-versioning.md 轴 A 处理）",
            drift.len(),
            drift.join(", ")
        );
    }
    if !missing.is_empty() {
        if !allow_missing {
            bail!(
                "public-api --check：{} crate 缺 committed baseline：{}（先 `cargo xtask public-api [--layer …]` 生成并提交；PR-0 自检可显式 `--allow-missing`）",
                missing.len(),
                missing.join(", ")
            );
        }
        // reason: --allow-missing 是 PR-0 自检的显式宽限（baseline 尚未产出），非默认路径——drift 仍 fail。
        eprintln!(
            "public-api --check（--allow-missing）：{} crate 暂无 baseline，宽限通过：{}",
            missing.len(),
            missing.join(", ")
        );
    }
    eprintln!("public-api --check: 无 drift");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn report_generate_always_ok() {
        assert!(report(false, false, &[], &[]).is_ok());
    }

    #[test]
    fn report_check_clean_ok() {
        assert!(report(true, false, &[], &[]).is_ok());
    }

    /// 复现测试（F1）：check 模式 missing-only **默认 fail-fast**（漂移门闭环，非误绿）。
    #[test]
    fn report_check_missing_only_fails_by_default() {
        assert!(report(true, false, &[], &v(&["vocab", "ids"])).is_err());
    }

    /// 仅 `--allow-missing` 显式宽限 missing（PR-0 自检）。
    #[test]
    fn report_check_missing_only_ok_with_allow_missing() {
        assert!(report(true, true, &[], &v(&["vocab", "ids"])).is_ok());
    }

    #[test]
    fn report_check_drift_fails() {
        assert!(report(true, false, &v(&["vocab"]), &[]).is_err());
    }

    /// drift 优先 fail-fast，即便同时有 missing。
    #[test]
    fn report_check_drift_fails_even_with_missing() {
        assert!(report(true, false, &v(&["vocab"]), &v(&["ids"])).is_err());
    }

    /// `--allow-missing` 宽限缺失，但**绝不**豁免 drift。
    #[test]
    fn report_check_drift_fails_even_with_allow_missing() {
        assert!(report(true, true, &v(&["vocab"]), &v(&["ids"])).is_err());
    }

    #[test]
    fn target_crates_by_layer() {
        assert_eq!(target_crates(Some(Layer::Basis)).len(), 5);
        assert_eq!(target_crates(Some(Layer::Engine)).len(), 2);
        // None = basis + engine 全集，无第三份硬编码列表。
        assert_eq!(target_crates(None).len(), 7);
        assert!(target_crates(Some(Layer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(Layer::Engine)).contains(&"primitives"));
    }

    #[test]
    fn baseline_dir_is_public_api_under_root() -> anyhow::Result<()> {
        let dir = baseline_dir()?;
        assert!(dir.ends_with("public-api"));
        assert!(dir.parent().is_some());
        Ok(())
    }
}
