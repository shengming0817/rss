//! `cargo xtask layer-deps` —— source-centric 分层依赖治理 lint。
//!
//! 读各 workspace 成员 `Cargo.toml` 的全部 shipped 依赖表——`[dependencies]` +
//! `[build-dependencies]` + 每个 `[target.<cfg>.dependencies]` / `[target.<cfg>.build-dependencies]`
//! 条件依赖表——按 `docs/rules/architecture.md §分层` 矩阵（`layers::allows`）校验工作区**内部边**。
//! source-centric：只解析含 `path`（或经根 `[workspace.dependencies]` 解析出 path 的 `workspace = true`）
//! 的本地依赖到工作区成员再判层，外部 crates.io 依赖（纯 version / 无 path）一律忽略——**免疫裸名×crates.io
//! 命名冲突**（如 adapter `redis` 与 crates.io `redis`），补 cargo-deny target-centric wrappers 表达不了的
//! source-centric 反向边（无 back-path 的基础/引擎→上层）。**fail-closed**：含 `path` 但逃逸 workspace
//! root / 不指向任何成员的本地依赖，作 `UnresolvedPath` finding 显式报错，绝不静默丢（LAYER-DEPS-07）。
//!
//! 评级 Medium（CI 门，接入 `cargo xtask verify`）；每条规则配 synthetic red case（见
//! `#[cfg(test)]`），anti-vacuity：真实工作区绿用例必过、各红用例必失。Hard 兜底（crate 图
//! 未声明即 import 不到 + cargo 无环）与 cargo-deny wrappers 并存。
//!
//! `ref: oxidecomputer/omicron dev-tools/xtask/src/check_workspace_deps.rs@main`
//!   （读工作区成员 manifest + 规则校验范式）。偏离：手解析既有 `toml` crate、不引
//!   `cargo_metadata`/`guppy`（匹配 xtask 轻量设计 + issue「读各成员 Cargo.toml」要求）。
//! `ref: EmbarkStudios/cargo-deny src/bans/cfg.rs@main`（target-centric wrappers 无法表达
//!   source-centric 反向边 + issue #343 path-dep bug —— 自建本 lint 的理由）。
//!
//! INVARIANT: LAYER-DEPS-01 —— back-path 反向边（上行 / 横向同层 / 跨界依赖）。
//! INVARIANT: LAYER-DEPS-02 —— 兄弟域互斥（跨域只经 contract）。
//! INVARIANT: LAYER-DEPS-03 —— adapter 仅组合根注入（不被域 / 服务依赖）。
//! INVARIANT: LAYER-DEPS-04 —— generated 仅域 + 组合根依赖。
//! INVARIANT: LAYER-DEPS-05 —— 每个 workspace 成员必落唯一分层（anti-drift：新增 crate 须登记层）。
//! INVARIANT: LAYER-DEPS-06 —— deny.toml 分层 wrappers ⟷ 源分类一致（守 `LAYER-WRAP-01` 漂移）。
//! INVARIANT: LAYER-DEPS-07 —— 含 path 的本地依赖须解析到现存 workspace 成员；逃逸 / 非成员
//!   一律 fail-closed 报错（杜绝 path-dep 静默绕过分层门）。

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::layers::{self, Layer};

/// 被违反的分层规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// LAYER-DEPS-01：上行 / 横向同层 / 跨界依赖（基础→服务、引擎→域、服务→兄弟服务 等）。
    BackPath,
    /// LAYER-DEPS-02：域 crate 依赖兄弟域 crate。
    SiblingDomain,
    /// LAYER-DEPS-03：非组合根依赖 adapter（含兄弟 adapter）。
    AdapterScope,
    /// LAYER-DEPS-04：非域 / 非根依赖 generated。
    GeneratedScope,
    /// LAYER-DEPS-05：workspace 成员未落任何分层（新增未登记）。
    LayerCoverage,
    /// LAYER-DEPS-06：deny.toml 分层 wrappers 与源分类不一致。
    WrapperCoverage,
    /// LAYER-DEPS-07：含 path 的本地依赖未解析到现存 workspace 成员（逃逸 / 非成员 / typo）。
    UnresolvedPath,
}

/// 单条 lint 失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) rule: Rule,
    /// 出错主体（成员名或路径）。
    pub(crate) subject: String,
    pub(crate) detail: String,
}

/// workspace 成员（名 + 相对 root 路径 + 分层；`layer = None` = 未分类）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) layer: Option<Layer>,
}

/// 工作区内部依赖边（`from` 成员依赖 `to` 成员，均为 crate 名）。
/// 携带声明位置（manifest 路径 + 依赖表 section + dep key），供失败输出直接定位（LAYER-DEPS-DX）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Edge {
    pub(crate) from: String,
    /// `from` 成员的 manifest 相对路径，如 `crates/foo/Cargo.toml`。
    pub(crate) from_manifest: String,
    /// 声明该边的依赖表 section，如 `[dependencies]` / `[build-dependencies]` / `[target.cfg(unix).dependencies]`。
    pub(crate) section: String,
    /// manifest 中书写的依赖 key。
    pub(crate) key: String,
    pub(crate) to: String,
}

/// `load_edges` 一趟扫描结果：内部边 + path 解析期 fail-closed findings（LAYER-DEPS-07）。
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct EdgeScan {
    pub(crate) edges: Vec<Edge>,
    pub(crate) findings: Vec<Finding>,
}

/// deny.toml `[bans.deny]` 中带 wrappers 的分层 ban 条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BanEntry {
    pub(crate) crate_name: String,
    pub(crate) wrappers: Vec<String>,
}

fn finding(rule: Rule, subject: impl Into<String>, detail: impl Into<String>) -> Finding {
    Finding {
        rule,
        subject: subject.into(),
        detail: detail.into(),
    }
}

/// 入口：校验真实工作区，有失败则 `bail`（非零退出）。
pub(crate) fn run() -> Result<()> {
    let root = crate::workspace_root()?;
    let workspace = parse_root_manifest(&root)?.workspace;
    let members = load_members(&root, &workspace.members)?;
    // canary：根 Cargo.toml 解析异常 / [workspace] members 被意外缩减时，静默通过会让分层门形同
    // 虚设。下界显著低于实际成员数（35），仅捕「解析返回空/极少」的配置灾难，不误伤正常增减。
    if members.len() < 10 {
        bail!(
            "layer-deps: 仅解析到 {} 个 workspace 成员，疑似根 Cargo.toml [workspace] members 异常",
            members.len()
        );
    }
    let scan = load_edges(&root, &members, &workspace.dependencies)?;
    let bans = load_bans(&root)?;

    let mut findings = check_layers(&members, &scan.edges);
    findings.extend(scan.findings);
    findings.extend(check_wrappers(&members, &bans));

    if findings.is_empty() {
        eprintln!(
            "layer-deps: {} 成员 / {} 内部边 / {} wrappers 全部通过",
            members.len(),
            scan.edges.len(),
            bans.len()
        );
        return Ok(());
    }
    for f in &findings {
        eprintln!("  [{:?}] {}: {}", f.rule, f.subject, f.detail);
    }
    bail!("layer-deps: {} 项分层依赖校验失败", findings.len());
}

/// 规则 (a)(b)(c)(d) + LAYER-DEPS-05：分类覆盖 + 每条内部边对照 `layers::allows`。
pub(crate) fn check_layers(members: &[Member], edges: &[Edge]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut layer_of: BTreeMap<&str, Layer> = BTreeMap::new();
    for m in members {
        match m.layer {
            Some(l) => {
                layer_of.insert(m.name.as_str(), l);
            }
            None => findings.push(finding(
                Rule::LayerCoverage,
                m.path.clone(),
                format!(
                    "成员 `{}` 未落任何分层；在 xtask/src/layers.rs 的 BASIS/ENGINE/SERVICE/DOMAIN_CRATES 之一登记（adapters/·bins/·generated 按路径自动判层）",
                    m.name
                ),
            )),
        }
    }
    for edge in edges {
        let (Some(&from), Some(&to)) = (
            layer_of.get(edge.from.as_str()),
            layer_of.get(edge.to.as_str()),
        ) else {
            // 未分类成员已单独 flag（LAYER-DEPS-05）；edges 只含内部成员，无外部边。
            continue;
        };
        if !layers::allows(from, to) {
            findings.push(finding(
                violation_rule(from, to),
                edge.from.clone(),
                format!(
                    "{} {}.{} → `{}`（{to:?}）违反 {from:?}→{to:?} 分层矩阵",
                    edge.from_manifest, edge.section, edge.key, edge.to
                ),
            ));
        }
    }
    findings
}

/// 外部 crate 收敛 wrapper（`(外部 crate, 唯一允许依赖它的内部 crate)`）——**非分层 wrapper**。
/// 把某外部 crate 的直接依赖方限定到单一内部 crate（cargo-deny wrappers），与「域/adapter/generated
/// 分层 wrapper」是不同类别：目标是**外部** crate（不在 workspace 成员集），故不走 stale / 反向② 校验，
/// 改校验 wrappers 恰为指定内部 crate（防开洞 / typo）。
///
/// INVARIANT: DIPORT-MACRO-CONFINE-01 —— DI port 的 dyn-dispatch 宏（dynosaur）+ Send 变体生成
///   （trait-variant）只能被 `diport` 依赖（DI port trait + Dyn wrapper 集中到 DI-infra 单一 crate）。
const EXTERNAL_CONFINEMENT_WRAPPERS: &[(&str, &str)] =
    &[("dynosaur", "diport"), ("trait-variant", "diport")];

/// LAYER-DEPS-06：deny.toml 分层 wrappers ⟷ 源分类一致性（守 LAYER-WRAP-01 漂移）。
/// 正向：每个 Domain/Adapter/Generated 成员须有 ban entry 且 wrappers ⊇ 所需消费者
/// （Domain/Adapter ⊇ 全部组合根；Generated ⊇ 全部域 + 组合根）。
/// 反向：① 每条带 wrappers 的 ban 须对应现存 Domain/Adapter/Generated 成员（无 stale），
/// **例外** [`EXTERNAL_CONFINEMENT_WRAPPERS`]（外部 crate 收敛，单独校验）；
/// ② wrappers 中每个消费者须是 `layers::allows` 允许依赖被 ban crate 的层（防过宽 wrapper 开洞,
/// 如把某服务塞进域的 wrappers）。与 `check_layers` 的 AdapterScope/SiblingDomain（source-centric
/// 实际边）互为两条 Medium 防线，须同绿。
pub(crate) fn check_wrappers(members: &[Member], bans: &[BanEntry]) -> Vec<Finding> {
    let layer_of: BTreeMap<&str, Layer> = members
        .iter()
        .filter_map(|m| m.layer.map(|l| (m.name.as_str(), l)))
        .collect();
    let names_in = |layer: Layer| -> Vec<&str> {
        members
            .iter()
            .filter(|m| m.layer == Some(layer))
            .map(|m| m.name.as_str())
            .collect()
    };
    let roots = names_in(Layer::Root);
    let domains = names_in(Layer::Domain);
    let ban_of: BTreeMap<&str, &[String]> = bans
        .iter()
        .map(|b| (b.crate_name.as_str(), b.wrappers.as_slice()))
        .collect();

    let mut findings = Vec::new();
    for m in members {
        let required: Vec<&str> = match m.layer {
            Some(Layer::Domain | Layer::Adapter) => roots.clone(),
            Some(Layer::Generated) => domains.iter().chain(&roots).copied().collect(),
            _ => continue,
        };
        match ban_of.get(m.name.as_str()) {
            None => findings.push(finding(
                Rule::WrapperCoverage,
                m.name.clone(),
                "deny.toml 缺该 crate 的分层 ban entry（应被组合根 wrappers 守）",
            )),
            Some(wraps) => {
                let missing: Vec<&str> = required
                    .iter()
                    .copied()
                    .filter(|r| !wraps.iter().any(|w| w == r))
                    .collect();
                if !missing.is_empty() {
                    findings.push(finding(
                        Rule::WrapperCoverage,
                        m.name.clone(),
                        format!(
                            "deny.toml [bans.deny] 该 crate wrappers 缺组合根/消费者: {}",
                            missing.join(", ")
                        ),
                    ));
                }
            }
        }
    }

    for b in bans {
        // 外部 crate 收敛 wrapper（dynosaur/trait-variant → diport）：独立类别，单独校验，跳过分层 stale/反向②。
        if let Some((_, expect)) = EXTERNAL_CONFINEMENT_WRAPPERS
            .iter()
            .find(|(ext, _)| *ext == b.crate_name.as_str())
        {
            let target_exists = members.iter().any(|mem| mem.name.as_str() == *expect);
            if !target_exists {
                findings.push(finding(
                    Rule::WrapperCoverage,
                    b.crate_name.clone(),
                    format!("外部收敛 wrapper 目标 `{expect}` 不是工作区成员（typo / 已删除）"),
                ));
            } else if b.wrappers.len() != 1 || b.wrappers[0].as_str() != *expect {
                findings.push(finding(
                    Rule::WrapperCoverage,
                    b.crate_name.clone(),
                    format!(
                        "外部收敛 wrapper 须恰为 [`{expect}`]（DI port 单一依赖点），实为: {}",
                        b.wrappers.join(", ")
                    ),
                ));
            }
            continue;
        }
        // 反向①：ban 目标须是现存 Domain/Adapter/Generated 成员（否则 stale：已删/未分类/外部误配）。
        let stale = match layer_of.get(b.crate_name.as_str()) {
            Some(l) => !matches!(l, Layer::Domain | Layer::Adapter | Layer::Generated),
            None => true,
        };
        if stale {
            findings.push(finding(
                Rule::WrapperCoverage,
                b.crate_name.clone(),
                "deny.toml 分层 wrapper 指向非 域/adapter/generated 成员（stale）",
            ));
            continue;
        }
        // 反向②：wrappers 中每个消费者须是矩阵允许依赖被 ban crate 的层。
        let banned = layer_of[b.crate_name.as_str()];
        for w in &b.wrappers {
            match layer_of.get(w.as_str()) {
                Some(&wl) if layers::allows(wl, banned) => {}
                Some(&wl) => findings.push(finding(
                    Rule::WrapperCoverage,
                    b.crate_name.clone(),
                    format!(
                        "deny.toml wrapper `{w}`（{wl:?}）非分层允许的 `{}`（{banned:?}）消费者",
                        b.crate_name
                    ),
                )),
                None => findings.push(finding(
                    Rule::WrapperCoverage,
                    b.crate_name.clone(),
                    format!("deny.toml wrapper `{w}` 不是工作区成员（typo / 已删除）"),
                )),
            }
        }
    }
    findings
}

/// 由 `from`/`to` 分层判定具体被违反的规则（前提：`allows(from,to) == false`）。
fn violation_rule(from: Layer, to: Layer) -> Rule {
    match (from, to) {
        (_, Layer::Adapter) => Rule::AdapterScope,
        (_, Layer::Generated) => Rule::GeneratedScope,
        (Layer::Domain, Layer::Domain) => Rule::SiblingDomain,
        _ => Rule::BackPath,
    }
}

// ---- IO / discovery（手解析 Cargo.toml；逻辑与上面纯规则 fn 分离便于测试）----

#[derive(Deserialize)]
struct RootManifest {
    workspace: WorkspaceSection,
}

#[derive(Deserialize)]
struct WorkspaceSection {
    members: Vec<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, DepSpec>,
}

#[derive(Deserialize)]
struct MemberManifest {
    package: PackageSection,
    #[serde(default)]
    dependencies: BTreeMap<String, DepSpec>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, DepSpec>,
    /// 条件依赖：`[target.<cfg>.dependencies]` / `[target.<cfg>.build-dependencies]`。
    /// 与普通表同为 shipped 边，必须入 lint——否则条件依赖可绕过分层门（LAYER-DEPS-01..04）。
    #[serde(default)]
    target: BTreeMap<String, TargetSection>,
    // reason: [dev-dependencies] 是测试期边，非 shipped artifact 分层边，不入本 lint。
    // 已知盲区：域单测 dev-dep 兄弟域/adapter（CLAUDE.md 禁）当前不机器强制——见 issue #1057。
}

/// 单个 `[target.<cfg>]` 块内的 shipped 依赖表。
#[derive(Deserialize)]
struct TargetSection {
    #[serde(default)]
    dependencies: BTreeMap<String, DepSpec>,
    #[serde(default, rename = "build-dependencies")]
    build_dependencies: BTreeMap<String, DepSpec>,
}

impl MemberManifest {
    /// 遍历全部 shipped 依赖表，yield `(section 标签, dep key, spec)`——`[dependencies]` +
    /// `[build-dependencies]` + 每个 `[target.<cfg>.{dependencies,build-dependencies}]`。
    /// 单源迭代点：所有依赖表共用此处，新增表形态只在此扩展（DRY）。
    fn dep_entries(&self) -> Vec<(String, &str, &DepSpec)> {
        let mut out: Vec<(String, &str, &DepSpec)> = Vec::new();
        for (k, v) in &self.dependencies {
            out.push(("[dependencies]".to_string(), k.as_str(), v));
        }
        for (k, v) in &self.build_dependencies {
            out.push(("[build-dependencies]".to_string(), k.as_str(), v));
        }
        for (cfg, sect) in &self.target {
            for (k, v) in &sect.dependencies {
                out.push((format!("[target.{cfg}.dependencies]"), k.as_str(), v));
            }
            for (k, v) in &sect.build_dependencies {
                out.push((format!("[target.{cfg}.build-dependencies]"), k.as_str(), v));
            }
        }
        out
    }
}

#[derive(Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DepSpec {
    /// 纯 version 字符串（外部 crate）。
    // reason: String 仅供 untagged 区分「字符串 version 依赖」与 detailed 表；version 值本身不消费。
    // dead_code 为 rustc 内置 lint（非 clippy carve-out），不入 error-handling.md §Carve-out 的 ADR registry。
    #[allow(dead_code)]
    Version(String),
    Detailed(DetailedDep),
}

#[derive(Deserialize)]
struct DetailedDep {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    workspace: bool,
}

#[derive(Deserialize)]
struct DenyManifest {
    #[serde(default)]
    bans: BansSection,
}

#[derive(Default, Deserialize)]
struct BansSection {
    #[serde(default)]
    deny: Vec<DenyEntry>,
}

#[derive(Deserialize)]
struct DenyEntry {
    #[serde(rename = "crate")]
    crate_name: String,
    #[serde(default)]
    wrappers: Vec<String>,
}

/// 逐成员读名 + 分类（`member_paths` = 根 `[workspace] members`，由 `run` 单次解析后传入）。
fn load_members(root: &Path, member_paths: &[String]) -> Result<Vec<Member>> {
    let mut members = Vec::with_capacity(member_paths.len());
    for path in member_paths {
        let name = read_member_manifest(root, path)?.package.name;
        let layer = layers::classify(&name, path);
        members.push(Member {
            name,
            path: path.clone(),
            layer,
        });
    }
    Ok(members)
}

/// 读各成员全部 shipped 依赖表（`dep_entries`），解析内部 path 边 + fail-closed 标记未解析的本地 path 依赖。
/// `ws_deps` = 根 `[workspace.dependencies]`（解析 `workspace = true` 形态用），由 `run` 传入避免重复解析根 manifest。
fn load_edges(
    root: &Path,
    members: &[Member],
    ws_deps: &BTreeMap<String, DepSpec>,
) -> Result<EdgeScan> {
    let path_to_name: BTreeMap<&str, &str> = members
        .iter()
        .map(|m| (m.path.as_str(), m.name.as_str()))
        .collect();

    let mut scan = EdgeScan::default();
    for m in members {
        let manifest = read_member_manifest(root, &m.path)?;
        let manifest_file = format!("{}/Cargo.toml", m.path);
        for (section, key, spec) in manifest.dep_entries() {
            let target = classify_dep(&m.path, key, spec, ws_deps);
            match edge_or_unresolved(
                &m.name,
                &manifest_file,
                &section,
                key,
                target,
                &path_to_name,
            ) {
                Some(Ok(edge)) => scan.edges.push(edge),
                Some(Err(f)) => scan.findings.push(f),
                None => {} // reason: 外部 crate（纯 version / 无 path），非内部边，按设计忽略。
            }
        }
    }
    Ok(scan)
}

/// 读 `deny.toml [bans.deny]` 中带 wrappers 的分层 ban 条目。
fn load_bans(root: &Path) -> Result<Vec<BanEntry>> {
    let path = root.join("deny.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("读 deny.toml 失败: {}", path.display()))?;
    let manifest: DenyManifest = toml::from_str(&text)
        .with_context(|| format!("解析 deny.toml 失败: {}", path.display()))?;
    Ok(manifest
        .bans
        .deny
        .into_iter()
        .filter(|e| !e.wrappers.is_empty())
        .map(|e| BanEntry {
            crate_name: e.crate_name,
            wrappers: e.wrappers,
        })
        .collect())
}

/// 一条 dep 的解析归类（fail-closed 前置：把"外部 / 本地路径 / 逃逸路径"三态分开，
/// 杜绝把"含 path 但解析不到"误当外部静默丢——LAYER-DEPS-07）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum DepTarget {
    /// 外部 crate（纯 version 字符串 / 无 path 的 `workspace = true`）——非内部边，忽略。
    External,
    /// 含 path 且归一到 workspace root 内的相对路径（仍需对照成员集判存在性）。
    LocalPath(String),
    /// 含 path 但 `..` 下溢逃逸 workspace root——非法本地路径，fail-closed。
    EscapedPath,
}

/// 把一条 dep 归类为 `External` / `LocalPath` / `EscapedPath`。
/// 仅认含 `path` 的本地依赖（或经根 `[workspace.dependencies]` 解析出 path 的 `workspace = true`）。
fn classify_dep(
    member_path: &str,
    key: &str,
    spec: &DepSpec,
    ws_deps: &BTreeMap<String, DepSpec>,
) -> DepTarget {
    let DepSpec::Detailed(d) = spec else {
        return DepTarget::External; // 纯 version 字符串 = 外部 crate。
    };
    if let Some(rel) = &d.path {
        return resolve_rel(member_path, rel);
    }
    // `workspace = true`：经根 [workspace.dependencies] 解析出 path 才算本地边。
    // 已知约束：内部 crate 须以 path 声明；以纯 registry version 声明（无 path）视为外部
    // ——内部 crate 不走 registry 形式，故安全。
    if d.workspace
        && let Some(DepSpec::Detailed(root_dep)) = ws_deps.get(key)
        && let Some(rel) = &root_dep.path
    {
        return resolve_rel("", rel); // base = "" → rel 已相对 workspace root。
    }
    DepTarget::External
}

/// 归一 path 依赖：成功 → `LocalPath`；`..` 下溢逃逸 root → `EscapedPath`（不再静默当外部）。
fn resolve_rel(base_dir: &str, rel: &str) -> DepTarget {
    match normalize_rel(base_dir, rel) {
        Some(p) => DepTarget::LocalPath(p),
        None => DepTarget::EscapedPath,
    }
}

/// 把已归类的 dep 落成内部边或 fail-closed finding（LAYER-DEPS-07）。
/// `None` = 外部 crate（忽略）；`Some(Ok)` = 命中成员的内部边；`Some(Err)` = 含 path 但未解析到成员。
fn edge_or_unresolved(
    from_name: &str,
    manifest_file: &str,
    section: &str,
    key: &str,
    target: DepTarget,
    path_to_name: &BTreeMap<&str, &str>,
) -> Option<std::result::Result<Edge, Finding>> {
    match target {
        DepTarget::External => None,
        DepTarget::LocalPath(p) => Some(match path_to_name.get(p.as_str()) {
            Some(to) => Ok(Edge {
                from: from_name.to_string(),
                from_manifest: manifest_file.to_string(),
                section: section.to_string(),
                key: key.to_string(),
                to: (*to).to_string(),
            }),
            None => Err(finding(
                Rule::UnresolvedPath,
                manifest_file,
                format!(
                    "{section}.{key} 的 path 依赖解析到 `{p}`，非任何 workspace 成员（typo / 已删 / 未登记 member / 指向 workspace 外）"
                ),
            )),
        }),
        DepTarget::EscapedPath => Some(Err(finding(
            Rule::UnresolvedPath,
            manifest_file,
            format!("{section}.{key} 的 path 依赖 `..` 下溢逃逸 workspace root"),
        ))),
    }
}

/// 词法解析 `base_dir` 下相对路径 `rel`（处理 `.`/`..`），返回相对 workspace root 的归一路径。
/// 不触碰文件系统（可测、不依赖目录存在）。`..` 下溢（逃逸 workspace root）→ `None`：由 `resolve_rel`
/// 转为 `EscapedPath`，再由 `edge_or_unresolved` fail-closed 报错（LAYER-DEPS-07），不再静默当外部丢。
fn normalize_rel(base_dir: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = base_dir.split('/').filter(|s| !s.is_empty()).collect();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

fn parse_root_manifest(root: &Path) -> Result<RootManifest> {
    let path = root.join("Cargo.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("读根 Cargo.toml 失败: {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("解析根 Cargo.toml 失败: {}", path.display()))
}

fn read_member_manifest(root: &Path, member_path: &str) -> Result<MemberManifest> {
    let path = root.join(member_path).join("Cargo.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("读成员 Cargo.toml 失败: {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("解析成员 Cargo.toml 失败: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, path: &str, layer: Option<Layer>) -> Member {
        Member {
            name: name.to_string(),
            path: path.to_string(),
            layer,
        }
    }

    fn e(from: &str, to: &str) -> Edge {
        Edge {
            from: from.to_string(),
            from_manifest: format!("crates/{from}/Cargo.toml"),
            section: "[dependencies]".to_string(),
            key: to.to_string(),
            to: to.to_string(),
        }
    }

    /// 代表性合法图：域→服务 / 服务→引擎 / 引擎→基础 / 域→generated → 0 finding（anti-vacuity 绿）。
    #[test]
    fn check_layers_green_valid_graph() {
        let members = vec![
            m("vocab", "crates/vocab", Some(Layer::Basis)),
            m("consistency", "crates/consistency", Some(Layer::Engine)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("identity", "crates/identity", Some(Layer::Domain)),
            m("generated", "generated", Some(Layer::Generated)),
        ];
        let edges = vec![
            e("identity", "httpserve"),
            e("identity", "generated"),
            e("httpserve", "consistency"),
            e("consistency", "vocab"),
        ];
        assert!(check_layers(&members, &edges).is_empty());
    }

    #[test]
    fn check_layers_red_sibling_domain() {
        let members = vec![
            m("identity", "crates/identity", Some(Layer::Domain)),
            m("settings", "crates/settings", Some(Layer::Domain)),
        ];
        let findings = check_layers(&members, &[e("settings", "identity")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SiblingDomain);
    }

    #[test]
    fn check_layers_red_adapter_scope() {
        let members = vec![
            m("settings", "crates/settings", Some(Layer::Domain)),
            m("redis", "adapters/redis", Some(Layer::Adapter)),
        ];
        let findings = check_layers(&members, &[e("settings", "redis")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::AdapterScope);
    }

    #[test]
    fn check_layers_red_generated_scope() {
        let members = vec![
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("generated", "generated", Some(Layer::Generated)),
        ];
        let findings = check_layers(&members, &[e("httpserve", "generated")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::GeneratedScope);
    }

    #[test]
    fn check_layers_red_back_path() {
        let members = vec![
            m("secure", "crates/secure", Some(Layer::Basis)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
        ];
        let findings = check_layers(&members, &[e("secure", "httpserve")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BackPath);
    }

    /// F1：同层横向依赖（服务→兄弟服务）违规——§分层 未授予同层依赖（→ BackPath）。
    #[test]
    fn check_layers_red_same_layer_service() {
        let members = vec![
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("authn", "crates/authn", Some(Layer::Service)),
        ];
        let findings = check_layers(&members, &[e("httpserve", "authn")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BackPath);
    }

    /// F1：基础→兄弟基础违规——基础"仅 std+外部"，不依赖任何内部成员（→ BackPath）。
    #[test]
    fn check_layers_red_same_layer_basis() {
        let members = vec![
            m("vocab", "crates/vocab", Some(Layer::Basis)),
            m("support", "crates/support", Some(Layer::Basis)),
        ];
        let findings = check_layers(&members, &[e("support", "vocab")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BackPath);
    }

    /// F1：adapter→兄弟 adapter 违规——§分层 未授予 adapter 互依赖（→ AdapterScope）。
    #[test]
    fn check_layers_red_same_layer_adapter() {
        let members = vec![
            m("redis", "adapters/redis", Some(Layer::Adapter)),
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
        ];
        let findings = check_layers(&members, &[e("redis", "postgres")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::AdapterScope);
    }

    /// F4：内部边违规 finding 的 detail 携带 manifest 路径 + section + dep key，供 CI 直接定位。
    #[test]
    fn check_layers_finding_detail_carries_location() {
        let members = vec![
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("authn", "crates/authn", Some(Layer::Service)),
        ];
        let edge = Edge {
            from: "httpserve".to_string(),
            from_manifest: "crates/httpserve/Cargo.toml".to_string(),
            section: "[dependencies]".to_string(),
            key: "authn".to_string(),
            to: "authn".to_string(),
        };
        let findings = check_layers(&members, &[edge]);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .detail
                .contains("crates/httpserve/Cargo.toml [dependencies].authn"),
            "detail 缺定位信息: {}",
            findings[0].detail
        );
    }

    #[test]
    fn check_layers_red_unclassified_member() {
        let members = vec![m("brandnew", "crates/brandnew", None)];
        let findings = check_layers(&members, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::LayerCoverage);
    }

    #[test]
    fn check_layers_classified_to_unclassified_skips_edge() {
        // httpserve（已分类）→ brandnew（未分类）：边跳过（无法判层），仅 brandnew 的 LayerCoverage。
        let members = vec![
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("brandnew", "crates/brandnew", None),
        ];
        let findings = check_layers(&members, &[e("httpserve", "brandnew")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::LayerCoverage);
        assert_eq!(findings[0].subject, "crates/brandnew");
    }

    fn ban(crate_name: &str, wrappers: &[&str]) -> BanEntry {
        BanEntry {
            crate_name: crate_name.to_string(),
            wrappers: wrappers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn wrapper_fixture_members() -> Vec<Member> {
        vec![
            m("server", "bins/server", Some(Layer::Root)),
            m("rss", "bins/rss", Some(Layer::Root)),
            m("xtask", "xtask", Some(Layer::Root)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
            m("identity", "crates/identity", Some(Layer::Domain)),
            m("redis", "adapters/redis", Some(Layer::Adapter)),
            m("generated", "generated", Some(Layer::Generated)),
        ]
    }

    #[test]
    fn check_wrappers_green() {
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        assert!(check_wrappers(&wrapper_fixture_members(), &bans).is_empty());
    }

    #[test]
    fn check_wrappers_red_missing_root() {
        // identity 的 wrappers 漏了 xtask（新增组合根未同步）。
        let bans = vec![
            ban("identity", &["server", "rss"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "identity");
    }

    #[test]
    fn check_wrappers_red_missing_ban_entry() {
        // identity（Domain）完全没有 ban entry → None arm（缺分层守卫）。
        let bans = vec![
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "identity");
    }

    #[test]
    fn check_wrappers_red_generated_missing_domain() {
        // generated 的 wrappers 漏了域消费者 identity。
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "generated");
    }

    #[test]
    fn check_wrappers_red_disallowed_wrapper() {
        // identity（Domain）的 wrappers 含 httpserve（Service）——allows(Service,Domain)=false，过宽开洞。
        let mut members = wrapper_fixture_members();
        members.push(m("httpserve", "crates/httpserve", Some(Layer::Service)));
        let bans = vec![
            ban("identity", &["server", "rss", "xtask", "httpserve"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&members, &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "identity");
    }

    #[test]
    fn check_wrappers_red_stale_entry() {
        // ghost 不是任何域/adapter/generated 成员 —— stale wrapper。
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
            ban("ghost", &["server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "ghost");
    }

    // DIPORT-MACRO-CONFINE-01：外部收敛 wrapper（dynosaur/trait-variant → diport）独立类别，
    // 不被当作 stale 分层 wrapper，且收敛目标须恰为 diport。
    #[test]
    fn check_wrappers_green_external_confinement() {
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
            ban("dynosaur", &["diport"]),
            ban("trait-variant", &["diport"]),
        ];
        assert!(check_wrappers(&wrapper_fixture_members(), &bans).is_empty());
    }

    #[test]
    fn check_wrappers_red_external_confinement_widened() {
        // dynosaur 收敛被开洞：wrappers 含 diport 之外的 crate（DI port 单一依赖点被破坏）。
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
            ban("dynosaur", &["diport", "server"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "dynosaur");
    }

    // ---- 真实工作区 anti-vacuity（守卫非恒错 / 分类非恒空）----
    // 本测试只守「骨架真实工作区绿路径」；各规则的 red case 由上面 synthetic fixture 测试覆盖。

    #[test]
    fn real_workspace_passes() -> Result<()> {
        let root = crate::workspace_root()?;
        let workspace = parse_root_manifest(&root)?.workspace;
        let members = load_members(&root, &workspace.members)?;
        let scan = load_edges(&root, &members, &workspace.dependencies)?;
        let bans = load_bans(&root)?;

        assert!(members.len() > 20, "成员数异常少: {}", members.len());
        assert!(scan.edges.len() > 20, "内部边异常少: {}", scan.edges.len());
        assert!(!bans.is_empty(), "未读到任何分层 wrappers");
        // fail-closed 不误伤：真实工作区无 path 解析期 finding（LAYER-DEPS-07 anti-false-positive）。
        assert!(
            scan.findings.is_empty(),
            "真实工作区不应有未解析 path: {:?}",
            scan.findings
        );
        // anti-vacuity：每个真实成员都被分类（classify 非恒 None）。
        assert!(
            members.iter().all(|m| m.layer.is_some()),
            "存在未分类成员: {:?}",
            members
                .iter()
                .filter(|m| m.layer.is_none())
                .collect::<Vec<_>>()
        );

        let mut findings = check_layers(&members, &scan.edges);
        findings.extend(scan.findings);
        findings.extend(check_wrappers(&members, &bans));
        assert!(findings.is_empty(), "真实工作区应无违规: {findings:?}");
        Ok(())
    }

    // ---- F2：条件依赖表（[target.*]）必须入 lint ----

    /// `dep_entries` 覆盖 normal + build + `[target.*]` 两类条件依赖表——否则条件依赖可绕过分层门。
    #[test]
    fn dep_entries_includes_target_specific_tables() -> Result<()> {
        let src = r#"
[package]
name = "x"
[dependencies]
a = { path = "../a" }
[build-dependencies]
b = { path = "../b" }
[target.'cfg(unix)'.dependencies]
c = { path = "../c" }
[target.'cfg(windows)'.build-dependencies]
d = { path = "../d" }
"#;
        let manifest: MemberManifest = toml::from_str(src)?;
        let keys: Vec<&str> = manifest.dep_entries().iter().map(|(_, k, _)| *k).collect();
        for want in ["a", "b", "c", "d"] {
            assert!(keys.contains(&want), "dep_entries 漏 `{want}`: {keys:?}");
        }
        Ok(())
    }

    // ---- F3：含 path 的本地依赖 fail-closed（LAYER-DEPS-07）----

    fn detailed(path: Option<&str>, workspace: bool) -> DepSpec {
        DepSpec::Detailed(DetailedDep {
            path: path.map(str::to_string),
            workspace,
        })
    }

    /// classify_dep 三态：外部 / 本地路径 / 逃逸路径。
    #[test]
    fn classify_dep_three_states() {
        let ws: BTreeMap<String, DepSpec> = BTreeMap::new();
        // 纯 version → External。
        assert_eq!(
            classify_dep("crates/x", "serde", &DepSpec::Version("1".into()), &ws),
            DepTarget::External
        );
        // 无 path 的 detailed（非 workspace）→ External。
        assert_eq!(
            classify_dep("crates/x", "serde", &detailed(None, false), &ws),
            DepTarget::External
        );
        // 含 path 命中 root 内 → LocalPath（归一）。
        assert_eq!(
            classify_dep("crates/x", "vocab", &detailed(Some("../vocab"), false), &ws),
            DepTarget::LocalPath("crates/vocab".into())
        );
        // 含 path 但 `..` 下溢逃逸 → EscapedPath。
        assert_eq!(
            classify_dep("xtask", "e", &detailed(Some("../../escape"), false), &ws),
            DepTarget::EscapedPath
        );
    }

    /// edge_or_unresolved：命中成员=边；含 path 非成员 / 逃逸=UnresolvedPath finding；外部=忽略。
    #[test]
    fn edge_or_unresolved_fail_closed() {
        let mut p2n: BTreeMap<&str, &str> = BTreeMap::new();
        p2n.insert("crates/vocab", "vocab");

        let hit = edge_or_unresolved(
            "x",
            "crates/x/Cargo.toml",
            "[dependencies]",
            "vocab",
            DepTarget::LocalPath("crates/vocab".into()),
            &p2n,
        );
        assert!(
            matches!(hit, Some(Ok(ref edge)) if edge.to == "vocab"),
            "{hit:?}"
        );

        let miss = edge_or_unresolved(
            "x",
            "crates/x/Cargo.toml",
            "[dependencies]",
            "ghost",
            DepTarget::LocalPath("crates/ghost".into()),
            &p2n,
        );
        assert!(
            matches!(miss, Some(Err(ref f)) if f.rule == Rule::UnresolvedPath),
            "非成员 path 应 fail-closed: {miss:?}"
        );

        let escaped = edge_or_unresolved(
            "x",
            "crates/x/Cargo.toml",
            "[target.cfg(unix).dependencies]",
            "e",
            DepTarget::EscapedPath,
            &p2n,
        );
        assert!(
            matches!(escaped, Some(Err(ref f)) if f.rule == Rule::UnresolvedPath),
            "逃逸 path 应 fail-closed: {escaped:?}"
        );

        let external = edge_or_unresolved(
            "x",
            "m",
            "[dependencies]",
            "serde",
            DepTarget::External,
            &p2n,
        );
        assert!(external.is_none(), "外部 crate 应忽略: {external:?}");
    }

    /// normalize_rel 词法解析（含跨目录 `..` + 下溢逃逸）。
    #[test]
    fn normalize_rel_resolves_dotdot() {
        assert_eq!(
            normalize_rel("crates/identity", "../vocab").as_deref(),
            Some("crates/vocab")
        );
        assert_eq!(
            normalize_rel("crates/audit", "../../generated").as_deref(),
            Some("generated")
        );
        assert_eq!(
            normalize_rel("adapters/redis", "../../crates/vocab").as_deref(),
            Some("crates/vocab")
        );
        assert_eq!(
            normalize_rel("", "crates/foo").as_deref(),
            Some("crates/foo")
        );
        // 下溢逃逸 workspace root → None（由 resolve_rel 转 EscapedPath，fail-closed 报错）。
        assert_eq!(normalize_rel("xtask", "../../escape"), None);
        assert_eq!(normalize_rel("", "../escape"), None);
    }
}
