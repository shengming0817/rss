//! `cargo xtask public-api` —— 库公开 API 面 baseline（封装外部 `cargo-public-api`）。
//!
//! 用途：基础/引擎层签名冻结后把 exported 符号面冻结为可 commit 的 baseline，后续 PR diff
//! （crate 公开 API = 轴 A SemVer，见 `.claude/rules/rss/api-versioning.md`）。
//!
//! **PR-0 仅落工具入口**；baseline 快照随 PR-1/PR-2 产出并 commit 到 `public-api/<crate>.txt`。
//!
//! 依赖：外部 `cargo-public-api`（`cargo install cargo-public-api`）+ nightly rustdoc-json
//! （`rustup toolchain install nightly`）。未满足时本命令给指引并**非零退出**（非静默 noop）。
//!
//! **不在 `cargo xtask verify` 聚合门内**：verify（contract validate + codegen --check）须工具/网络
//! 无关、人人可跑；public-api 依赖外部工具 + nightly，故为独立可选门（单独 `cargo xtask public-api --check`），
//! 不污染 verify 的可移植性。
//!
//! INVARIANT: PUBLICAPI-TOOL-GATE-01 —— 工具缺失 fail-fast，不静默成功。

use crate::workspace_root;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// 封装面需冻结的基础 + 引擎层 crate。服务/域/adapters 内部接缝多变，不入 baseline。
const BASELINE_CRATES: &[&str] = &[
    "vocab",
    "ids",
    "secure",
    "support",
    "runctx",
    "consistency",
    "primitives",
];

/// 生成（`check=false`）或校验（`check=true`）基础/引擎层封装面 baseline。
pub(crate) fn run(check: bool) -> Result<()> {
    ensure_tool_available()?;
    let dir = baseline_dir()?;
    if !check {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("创建 baseline 目录失败: {}", dir.display()))?;
    }

    let mut drift = Vec::new();
    let mut missing = Vec::new();
    for krate in BASELINE_CRATES {
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
    report(check, &drift, &missing)
}

fn baseline_dir() -> Result<PathBuf> {
    Ok(workspace_root()?.join("public-api"))
}

/// 检测外部 cargo-public-api；缺失即 fail-fast 给安装指引（INVARIANT PUBLICAPI-TOOL-GATE-01）。
fn ensure_tool_available() -> Result<()> {
    let ok = Command::new("cargo")
        .args(["public-api", "--version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
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
    let out = Command::new("cargo")
        .args(["public-api", "-p", krate])
        .output()
        .with_context(|| format!("运行 cargo public-api -p {krate} 失败"))?;
    if !out.status.success() {
        bail!(
            "cargo public-api -p {krate} 非零退出:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// 汇报结果：生成模式只报数；校验模式 missing 警告（PR-1/PR-2 产出前正常）、drift fail-fast。
fn report(check: bool, drift: &[String], missing: &[String]) -> Result<()> {
    if !check {
        eprintln!(
            "public-api: baseline 生成完成（{} crate）",
            BASELINE_CRATES.len()
        );
        return Ok(());
    }
    if !missing.is_empty() {
        // reason: PR-0 仅落入口，baseline 快照在 PR-1/PR-2 产出，此前缺失属正常，警告而非失败。
        eprintln!(
            "public-api: {} crate 尚无 committed baseline（PR-1/PR-2 产出前正常）：{}",
            missing.len(),
            missing.join(", ")
        );
    }
    if !drift.is_empty() {
        bail!(
            "public-api drift：{} crate 封装面与 committed baseline 不一致：{}（确认是否破坏式 API 变更，按 api-versioning.md 轴 A 处理）",
            drift.len(),
            drift.join(", ")
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
        assert!(report(false, &[], &[]).is_ok());
    }

    #[test]
    fn report_check_clean_ok() {
        assert!(report(true, &[], &[]).is_ok());
    }

    /// PR-0 阶段 baseline 未产出：check 模式下 missing-only 警告而非失败。
    #[test]
    fn report_check_missing_only_ok() {
        assert!(report(true, &[], &v(&["vocab", "ids"])).is_ok());
    }

    #[test]
    fn report_check_drift_fails() {
        assert!(report(true, &v(&["vocab"]), &[]).is_err());
    }

    /// drift 优先 fail-fast，即便同时有 missing。
    #[test]
    fn report_check_drift_fails_even_with_missing() {
        assert!(report(true, &v(&["vocab"]), &v(&["ids"])).is_err());
    }

    #[test]
    fn baseline_dir_is_public_api_under_root() -> anyhow::Result<()> {
        let dir = baseline_dir()?;
        assert!(dir.ends_with("public-api"));
        assert!(dir.parent().is_some());
        Ok(())
    }
}
