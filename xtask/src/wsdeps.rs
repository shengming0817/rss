//! `cargo xtask wsdeps-drift` —— workspace.dependencies pin ↔ Cargo.lock 漂移治理。
//!
//! 守「根 `Cargo.toml` 的 `[workspace.dependencies]` 每个外部 pin 必须被 `Cargo.lock`
//! 的 resolved 版本满足，或为带注释标注的 inert 前瞻预留」。接入 `cargo xtask verify`
//! （fail-closed 门）。
//!
//! INVARIANT: WSDEPS-DRIFT-01 { level = "Medium", exec = "check", source = "code" }—— 外部 pin 若其 crate 在 Cargo.lock 中，pin（VersionReq）
//!   须被至少一个 locked Version 满足。
//! INVARIANT: WSDEPS-DRIFT-02 { level = "Medium", exec = "check", source = "code" }—— 外部 pin 若其 crate 不在 Cargo.lock（纯 inert 前瞻），
//!   须带前瞻标注注释（任一：inert / 前瞻 / forward-reserv / 预留，大小写不敏感）。
//!
//! ref: oxidecomputer/omicron dev-tools/xtask/src/check_workspace_deps.rs@main
//!   （手解析 workspace manifest + 规则校验）。

use anyhow::{Context, Result, bail};
use semver::{Version, VersionReq};
use std::collections::BTreeMap;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的 wsdeps 规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// WSDEPS-DRIFT-01：pin（VersionReq）不被 Cargo.lock 任何 resolved 版本满足。
    PinLockDrift,
    /// WSDEPS-DRIFT-02：inert 前瞻预留 pin（lock 中无此 crate）须带注释标注。
    UnannotatedInertReserve,
}

/// `cargo xtask wsdeps-drift` 校验器。
pub(crate) struct WsDepsDrift;

impl GovernanceCheck for WsDepsDrift {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "wsdeps-drift"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let manifest_src = std::fs::read_to_string(root.join("Cargo.toml"))
            .with_context(|| "读根 Cargo.toml 失败")?;
        let lock_src = std::fs::read_to_string(root.join("Cargo.lock"))
            .with_context(|| "读 Cargo.lock 失败")?;
        let findings = evaluate(&manifest_src, &lock_src)?;
        let n_external = count_external_pins(&manifest_src)?;
        let n_locked = count_lock_packages(&lock_src)?;
        let summary = format!("{n_external} 外部 pin / {n_locked} 在 lock，全部对齐");
        Ok((summary, findings))
    }
}

// ---- 注释标注 token（大小写不敏感；WSDEPS-DRIFT-02）----
const INERT_TOKENS: &[&str] = &["inert", "前瞻", "forward-reserv", "预留"];

/// 判定行文本是否含任一 inert 标注 token（大小写不敏感）。
fn has_inert_annotation(line: &str) -> bool {
    let lower = line.to_lowercase();
    INERT_TOKENS.iter().any(|tok| lower.contains(tok))
}

/// 核心判定逻辑（纯函数，便于测试；`check()` 读文件后调此函数）。
///
/// 参数：
/// - `manifest_src`：根 `Cargo.toml` 原文（含注释）。
/// - `lock_src`：`Cargo.lock` 原文。
///
/// 返回所有违规 findings。
pub(crate) fn evaluate(manifest_src: &str, lock_src: &str) -> Result<Vec<Finding>> {
    let lock_map = parse_lock_packages(lock_src)?;
    let entries = parse_ws_dep_entries(manifest_src)?;

    let mut findings = Vec::new();

    for entry in &entries {
        let Some(req_str) = &entry.version_req else {
            // 无 version req（path-only 等），skip。
            continue;
        };

        let req = VersionReq::parse(req_str).with_context(|| {
            format!(
                "解析 VersionReq `{req_str}` 失败（依赖: {}）",
                entry.manifest_key
            )
        })?;

        // lock lookup 用真实 package name（Cargo alias 下 manifest key 可 != crate 名）。
        if let Some(locked_versions) = lock_map.get(&entry.package_name) {
            // WSDEPS-DRIFT-01：pin 须被至少一个 locked 版本满足。
            let satisfied = locked_versions.iter().any(|v| req.matches(v));
            if !satisfied {
                let versions: Vec<String> = locked_versions.iter().map(|v| v.to_string()).collect();
                let alias = if entry.package_name == entry.manifest_key {
                    String::new()
                } else {
                    format!("（alias → package `{}`）", entry.package_name)
                };
                findings.push(finding(
                    Rule::PinLockDrift,
                    entry.manifest_key.clone(),
                    format!(
                        "pin `{req_str}`{alias} 不被 Cargo.lock resolved 版本 {versions:?} 满足"
                    ),
                ));
            }
        } else if !inert_has_annotation(manifest_src, &entry.manifest_key) {
            // WSDEPS-DRIFT-02：真实 package name 不在 lock（inert 前瞻），须有注释标注。
            findings.push(finding(
                Rule::UnannotatedInertReserve,
                entry.manifest_key.clone(),
                "inert 前瞻预留 pin 须带注释标注（inert/前瞻/预留）".to_string(),
            ));
        }
    }

    Ok(findings)
}

/// 辅助：统计 manifest 中外部 pin 数量（供 summary 使用）。
fn count_external_pins(manifest_src: &str) -> Result<usize> {
    Ok(parse_ws_dep_entries(manifest_src)?
        .into_iter()
        .filter(|e| e.version_req.is_some())
        .count())
}

/// 辅助：统计 lock 中 package 名称数量（供 summary 使用）。
fn count_lock_packages(lock_src: &str) -> Result<usize> {
    Ok(parse_lock_packages(lock_src)?.len())
}

/// workspace.dependencies 中的单个外部 entry（解析结果）。
struct WsDepEntry {
    /// manifest key（`[workspace.dependencies]` 左侧名）——原文注释扫描 + 诊断 subject 用。
    manifest_key: String,
    /// 实际 crate 名 = Cargo.lock package name：table 形 `package` alias，否则 = `manifest_key`。
    /// lock lookup 用此名（Cargo alias `foo = { package = "real-crate", .. }` 下二者不同）。
    package_name: String,
    /// Some = 有 version req 的外部 pin；None = 纯 path dep 等（跳过）。
    version_req: Option<String>,
}

/// 解析 `[workspace.dependencies]` 段中所有 entry。
///
/// - value 为 string → req = 该串，非 path dep。
/// - value 为 table → `version` 字段为 req（无则 None）；有 `path` 键 → is_path=true → skip。
/// - 不在 workspace.dependencies 的 entry 不解析。
fn parse_ws_dep_entries(manifest_src: &str) -> Result<Vec<WsDepEntry>> {
    let val: toml::Value =
        toml::from_str(manifest_src).with_context(|| "解析根 Cargo.toml 失败")?;

    let deps = val
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table());

    let Some(deps_table) = deps else {
        return Ok(Vec::new());
    };

    let mut entries = Vec::new();

    for (name, spec) in deps_table {
        let entry = match spec {
            toml::Value::String(s) => WsDepEntry {
                manifest_key: name.clone(),
                package_name: name.clone(),
                version_req: Some(s.clone()),
            },
            toml::Value::Table(t) => {
                // 有 path 键 → path dep，跳过。
                if t.contains_key("path") {
                    continue;
                }
                let version_req = t.get("version").and_then(|v| v.as_str()).map(str::to_owned);
                // Cargo alias：`alias = { package = "real-crate", version = ".." }` —— lock lookup 用真实包名。
                let package_name = t
                    .get("package")
                    .and_then(|v| v.as_str())
                    .map_or_else(|| name.clone(), str::to_owned);
                WsDepEntry {
                    manifest_key: name.clone(),
                    package_name,
                    version_req,
                }
            }
            _ => continue,
        };
        entries.push(entry);
    }

    Ok(entries)
}

/// 解析 `Cargo.lock` → `BTreeMap<crate_name, Vec<Version>>`。
/// Cargo.lock 是 TOML，`[[package]]` 数组 entry 含 `name` + `version`。
///
/// canary：packages 数组为空或不存在 → `bail!`（配置灾难，分层门形同虚设）。
fn parse_lock_packages(lock_src: &str) -> Result<BTreeMap<String, Vec<Version>>> {
    let val: toml::Value = toml::from_str(lock_src).with_context(|| "解析 Cargo.lock 失败")?;

    let packages = val
        .get("package")
        .and_then(|p| p.as_array())
        .ok_or_else(|| anyhow::anyhow!("Cargo.lock 缺 [[package]] 数组（配置灾难 canary）"))?;

    if packages.is_empty() {
        bail!("Cargo.lock [[package]] 数组为空（配置灾难 canary）");
    }

    let mut map: BTreeMap<String, Vec<Version>> = BTreeMap::new();

    for pkg in packages {
        let name = pkg.get("name").and_then(|n| n.as_str()).unwrap_or_default();
        let version_str = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if name.is_empty() || version_str.is_empty() {
            // reason: 跳过无 name/version 的异常条目是防御性容错，真实 Cargo.lock 不产生此类条目；
            //   空 package 数组的配置灾难已由上方 canary bail! 守，此处为二次防御。
            continue;
        }
        let version = Version::parse(version_str).with_context(|| {
            format!("解析 Cargo.lock package `{name}` version `{version_str}` 失败")
        })?;
        map.entry(name.to_owned()).or_default().push(version);
    }

    Ok(map)
}

/// WSDEPS-DRIFT-02：扫 manifest 原文，判定 `name` 所在声明行（或声明行上方**连续**注释块）是否含 inert 标注。
///
/// 原始行扫描（toml::Value 丢注释），匹配规则：
/// 1. 找到 `^<name>\s*=` 开头的声明行。
/// 2. 检查该行行尾注释（`#` 后文本）是否含标注 token。
/// 3. 若无，向上扫描**连续**以 `#` 开头的注释行（遇到空行或非注释行即停），
///    任一行含 inert 标注 token 即视为已标注。
///    标注须在行尾注释或声明行上方**连续**注释块内；隔空行的注释不计入。
fn inert_has_annotation(manifest_src: &str, name: &str) -> bool {
    let lines: Vec<&str> = manifest_src.lines().collect();
    let key_prefix = name.to_owned() + " ";
    let key_eq = name.to_owned() + "=";

    for (idx, &line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        // 声明行：以 `<name> ` 或 `<name>=` 开头（处理 `foo = ...` 与 `foo=...` 两形）。
        if trimmed.starts_with(key_prefix.as_str()) || trimmed.starts_with(key_eq.as_str()) {
            // 检查行尾注释（collapse nested if）。
            if let Some(comment_part) = trimmed.split_once('#').map(|(_, c)| c)
                && has_inert_annotation(comment_part)
            {
                return true;
            }
            // 向上扫连续注释行（遇到空行或非注释行即停），任一行含标注即返回 true。
            if idx > 0 {
                let mut scan = idx - 1;
                loop {
                    let prev = lines[scan].trim();
                    if !prev.starts_with('#') {
                        // 非注释行（含空行）：连续注释块终止。
                        break;
                    }
                    if has_inert_annotation(prev) {
                        return true;
                    }
                    if scan == 0 {
                        break;
                    }
                    scan -= 1;
                }
            }
            return false;
        }
    }
    // 未找到声明行 → 无标注。
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    // ---- 辅助构造 minimal manifest / lock ----

    fn manifest_with(deps: &str) -> String {
        format!("[workspace]\nmembers = []\n\n[workspace.dependencies]\n{deps}\n")
    }

    fn lock_with_pkg(name: &str, version: &str) -> String {
        format!("version = 3\n\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
    }

    #[allow(clippy::expect_used)] // reason: 测试辅助函数，Err 即测试失败，符合 item-level carve-out。
    fn eval(manifest: &str, lock: &str) -> Vec<Finding> {
        evaluate(manifest, lock).expect("evaluate 不应 Err")
    }

    // ---- green cases ----

    /// DRIFT-01 绿：pin `0.14` 被 lock `0.14.6` 满足。
    #[test]
    fn green_pin_satisfied_by_locked() {
        let manifest = manifest_with("tonic = \"0.14\"");
        let lock = lock_with_pkg("tonic", "0.14.6");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "tonic 0.14 被 0.14.6 满足，应无 finding：{findings:?}"
        );
    }

    /// exact-pin 绿：`=0.3.0` 被 lock `0.3.0` 满足。
    #[test]
    fn green_exact_pin_satisfied() {
        let manifest = manifest_with("dynosaur = \"=0.3.0\"");
        let lock = lock_with_pkg("dynosaur", "0.3.0");
        let findings = eval(&manifest, &lock);
        assert!(findings.is_empty(), "=0.3.0 被 0.3.0 满足：{findings:?}");
    }

    /// table 形 dep 同样按版本 req 校验。
    #[test]
    fn green_table_form_dep() {
        let manifest = manifest_with("foo = { version = \"1\", features = [\"full\"] }");
        let lock = lock_with_pkg("foo", "1.2.3");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "table 形 dep 1.x 被 1.2.3 满足：{findings:?}"
        );
    }

    /// Cargo alias 绿（F4 anti-regression）：`serde_x = { package = "serde", .. }` → lock lookup 用真实包名
    /// `serde`（非 manifest key `serde_x`）；否则会被误判为 lock 缺失 → false-positive UnannotatedInertReserve。
    #[test]
    fn green_alias_resolves_to_lock_package_name() {
        let manifest = manifest_with("serde_x = { package = \"serde\", version = \"1\" }");
        let lock = lock_with_pkg("serde", "1.0.219");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "alias serde_x→serde 被 lock serde 1.0.219 满足，应无 finding：{findings:?}"
        );
    }

    /// Cargo alias 红（F4 anti-vacuity）：alias 真实包名在 lock 但 pin 不满足 → 按真实包名查到、报 PinLockDrift
    /// （证明 lock lookup 走 `package` 而非 manifest key——否则会落 UnannotatedInertReserve 而非 PinLockDrift）。
    #[test]
    fn red_alias_pin_drift_against_lock_package() {
        let manifest = manifest_with("serde_x = { package = \"serde\", version = \"2\" }");
        let lock = lock_with_pkg("serde", "1.0.219");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.iter().any(|f| f.rule == Rule::PinLockDrift),
            "alias pin 2 vs lock serde 1.0.219 应 PinLockDrift：{findings:?}"
        );
    }

    /// path dep 跳过：不产生 finding（无 version req）。
    #[test]
    fn green_path_dep_skipped() {
        let manifest = manifest_with("bar = { path = \"../bar\" }");
        // lock 须非空以通过 canary
        let lock =
            "version = 3\n\n[[package]]\nname = \"anchor\"\nversion = \"0.1.0\"\n".to_string();
        let findings = eval(&manifest, &lock);
        assert!(findings.is_empty(), "path dep 应跳过：{findings:?}");
    }

    /// inert 前瞻有标注 → 无 finding（行尾注释形）。
    #[test]
    fn green_inert_with_inline_annotation() {
        let manifest = manifest_with("futurecrate = \"1\" # inert 前瞻");
        // futurecrate 不在 lock
        let lock = lock_with_pkg("anchor", "0.1.0");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "inert 有标注应无 finding：{findings:?}"
        );
    }

    /// inert 前瞻有标注 → 无 finding（上一行注释形）。
    #[test]
    fn green_inert_with_preceding_comment() {
        let manifest = manifest_with("# 预留\nfuturecrate = \"1\"");
        let lock = lock_with_pkg("anchor", "0.1.0");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "inert 上一行有标注应无 finding：{findings:?}"
        );
    }

    // ---- red cases (anti-vacuity) ----

    /// DRIFT-01 anti-vacuity：pin `0.13` 被 lock `0.14.6` 拒绝 → PinLockDrift。
    #[test]
    fn red_drift01_pin_not_satisfied() {
        let manifest = manifest_with("tonic = \"0.13\"");
        let lock = lock_with_pkg("tonic", "0.14.6");
        let findings = eval(&manifest, &lock);
        assert_eq!(findings.len(), 1, "应有 1 条 finding：{findings:?}");
        assert_eq!(findings[0].rule, Rule::PinLockDrift);
        assert_eq!(findings[0].subject, "tonic");
    }

    /// exact-pin red：`=0.3.0` 被 lock `0.3.1` 拒绝 → PinLockDrift。
    #[test]
    fn red_exact_pin_wrong_version() {
        let manifest = manifest_with("dynosaur = \"=0.3.0\"");
        let lock = lock_with_pkg("dynosaur", "0.3.1");
        let findings = eval(&manifest, &lock);
        assert_eq!(findings.len(), 1, "=0.3.0 不匹配 0.3.1：{findings:?}");
        assert_eq!(findings[0].rule, Rule::PinLockDrift);
    }

    /// DRIFT-02 anti-vacuity：inert 无标注 → UnannotatedInertReserve。
    #[test]
    fn red_drift02_inert_without_annotation() {
        let manifest = manifest_with("futurecrate = \"1\"");
        // futurecrate 不在 lock
        let lock = lock_with_pkg("anchor", "0.1.0");
        let findings = eval(&manifest, &lock);
        assert_eq!(findings.len(), 1, "inert 无标注应有 finding：{findings:?}");
        assert_eq!(findings[0].rule, Rule::UnannotatedInertReserve);
        assert_eq!(findings[0].subject, "futurecrate");
    }

    /// canary：lock 无 [[package]] 键 → evaluate 返回 Err。
    #[test]
    fn canary_no_package_key_is_err() {
        let manifest = manifest_with("tonic = \"0.14\"");
        let lock = "version = 3\n".to_string();
        assert!(evaluate(&manifest, &lock).is_err(), "无 package 键应 Err");
    }

    /// canary：lock [[package]] 数组为空 → evaluate 返回 Err。
    #[test]
    fn canary_explicit_empty_package_array_is_err() {
        let manifest = manifest_with("tonic = \"0.14\"");
        let lock = "version = 3\npackage = []\n".to_string();
        assert!(evaluate(&manifest, &lock).is_err(), "空 package 数组应 Err");
    }

    // ---- has_inert_annotation 单元测试 ----

    #[test]
    fn inert_annotation_tokens_case_insensitive() {
        assert!(has_inert_annotation("# INERT reserve"));
        assert!(has_inert_annotation("# forward-reserv for future"));
        assert!(has_inert_annotation("# 前瞻预留"));
        assert!(has_inert_annotation("# 预留 future use"));
        assert!(!has_inert_annotation("# plain comment"));
    }

    /// F4 green：声明行上方两行连续注释块（第一行 description、第二行含 `inert`）→ 无 finding。
    /// 验证多行连续注释块扫描正确识别非紧邻行的标注。
    #[test]
    fn green_inert_with_multiline_preceding_comment_block() {
        // 两行连续注释：第一行描述、第二行含 inert token，声明行紧跟其后。
        let manifest =
            manifest_with("# description of the crate\n# inert 前瞻预留\nfuturecrate = \"1\"");
        let lock = lock_with_pkg("anchor", "0.1.0");
        let findings = eval(&manifest, &lock);
        assert!(
            findings.is_empty(),
            "连续注释块含 inert 应无 finding：{findings:?}"
        );
    }

    /// F4 anti-vacuity red：含 token 的注释行与声明行之间**隔了一个空行**（非连续）→ 仍报 UnannotatedInertReserve。
    /// 证明扫描按「连续注释块」语义、非任意上方注释。
    #[test]
    fn red_inert_annotation_separated_by_blank_line_is_missed() {
        // 含 token 的注释与声明行之间有空行 → 连续注释块被空行截断 → 应报 UnannotatedInertReserve。
        let manifest = manifest_with("# inert 前瞻预留\n\nfuturecrate = \"1\"");
        let lock = lock_with_pkg("anchor", "0.1.0");
        let findings = eval(&manifest, &lock);
        assert_eq!(
            findings.len(),
            1,
            "注释与声明行隔空行时应报 UnannotatedInertReserve：{findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::UnannotatedInertReserve);
        assert_eq!(findings[0].subject, "futurecrate");
    }

    // ---- 真实树 green（端到端，接入真实 Cargo.toml + Cargo.lock）----

    /// 真实树端到端绿（非纯 unit 测试）：WsDepsDrift.check() 读真实 Cargo.toml + Cargo.lock 做端到端校验。
    /// 依赖 workspace pin 与 lock 对齐；pin 漂移时此测试会红（即 WSDEPS-DRIFT-01/02 lint 生效证据）。
    #[test]
    fn real_tree_green() -> Result<()> {
        let (_, findings) = WsDepsDrift.check()?;
        assert!(
            findings.is_empty(),
            "真实树 wsdeps-drift 应无 finding，实有：{findings:#?}"
        );
        Ok(())
    }
}
