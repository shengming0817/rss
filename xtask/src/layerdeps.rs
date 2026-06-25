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
//! INVARIANT: LAYER-DEPS-08 —— test-support 库（`layers::TEST_SUPPORT_CRATES`，如 `testkit`）只准经
//!   `[dev-dependencies]` 消费，禁进生产 shipped 依赖图。本 lint 只扫 shipped 依赖表，故**任一**指向
//!   test-support 成员的内部边即 shipped 误用（dev-dep 边压根不入 `edges`）；补 `allows` 矩阵盲区
//!   （`allows(Domain,Service)=true` 不阻止域 crate 误把 testkit 放进 `[dependencies]`）。

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::layers::{self, Layer};

pub(crate) type Finding = diagnostic::Finding<Rule>;

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
    /// LAYER-DEPS-08：test-support 库被 shipped 依赖（应只经 `[dev-dependencies]` 消费）。
    TestSupportShipped,
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

/// `cargo xtask layer-deps` 校验器（issue #1058：经 [`GovernanceCheck`] 统一编排）。
pub(crate) struct LayerDeps;

impl GovernanceCheck for LayerDeps {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "layer-deps"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
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
        findings.extend(check_wrappers(&members, &bans, &scan.edges));
        findings.extend(check_external_confinement(&members, &bans));
        findings.extend(check_test_support_confinement(&scan.edges));

        let summary = format!(
            "{} 成员 / {} 内部边 / {} wrappers 全部通过",
            members.len(),
            scan.edges.len(),
            bans.len()
        );
        Ok((summary, findings))
    }
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
                    "成员 `{}` 未落任何分层；在 xtask/src/layers.rs 的 BASIS/ENGINE/DIPORT/SERVICE/DOMAIN_CRATES 之一登记（adapters/·bins/·generated 按路径自动判层）",
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
        // 基础同层横向默认禁，唯一例外 = intra-base DAG 前向边（BASE-INTRADAG-01，如 runctx → vocab）；
        // Service 同层横向默认禁，唯一例外 = 受控 bootstrap → httpserve 路由类型边（LAYER-DEPS-ROUTE-FUNNEL-01，ADR-009）。
        if !layers::allows(from, to)
            && !layers::basis_intra_dag_allows(&edge.from, &edge.to)
            && !layers::route_funnel_allows(&edge.from, &edge.to)
        {
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

/// 外部 crate 收敛 wrapper（`(外部 crate, 允许依赖它的内部 crate 白名单)`）——**非分层 wrapper**。
/// 把某外部 crate 的直接依赖方限定到一组 sanctioned 内部 crate（cargo-deny wrappers），与「域/adapter/
/// generated 分层 wrapper」是不同类别：目标是**外部** crate（不在 workspace 成员集），故不走 stale / 反向②
/// 校验，改校验 deny.toml wrappers 恰等白名单（集合相等，防开洞 / 漏列 / typo）。
///
/// INVARIANT: DIPORT-MACRO-CONFINE-01′（Option 2 / ADR-005 把 `-01` 由「仅 diport」放宽为白名单）——
///   DI port 的 dyn-dispatch 宏（dynosaur）+ Send 变体生成（trait-variant）只能被 **DI port 定义点 crate**
///   依赖：provider-agnostic infra port 定义点 `diport`（DiPort 层），及**定义自身 repo/service DI port 的
///   域 crate**（Domain 层，Option 2）。provider-agnostic vs 域形 port 的归属 category line 见 ADR-005 /
///   domain-patterns.md。原 `-01`「单一 dyn-dispatch 依赖点」前提随 Option 2（repo port 必然多点定义）失效；
///   其 unsafe 论据更早已被 def-site hygiene 中和（ADR-003 落地结论 1），故放宽零安全代价。
///
/// **不变量（防漂移）**：① 左元素必须是**外部** crate（不在 workspace 成员集）——若误把内部 crate 放左元素，
/// `check_wrappers` stale/反向② 旁路会静默放过其分层依赖违规；② 白名单每个条目须现存且属 DI port 定义层
/// （DiPort/Domain），由 [`check_confinement_entry`] 守（防白名单本身越层 / typo）。新增 sanctioned 域 crate
/// 时同步更新本白名单与 `deny.toml` 对应 ban 的 wrappers（二者集合相等，否则 lint 红）。
const EXTERNAL_CONFINEMENT_WRAPPERS: &[(&str, &[&str])] = &[
    ("dynosaur", &["diport", "identity", "settings"]),
    ("trait-variant", &["diport", "identity", "settings"]),
];

/// LAYER-DEPS-06：deny.toml 分层 wrappers ⟷ 源分类一致性（守 LAYER-WRAP-01 漂移）。
/// 正向：每个 Domain/Adapter/Generated 成员须有 ban entry 且 wrappers ⊇ 所需消费者
/// （Domain/Adapter ⊇ 全部组合根；Generated ⊇ 全部域 + 组合根）。
/// 反向：① 每条带 wrappers 的 ban 须对应现存 Domain/Adapter/Generated 成员（无 stale），
/// **例外** [`EXTERNAL_CONFINEMENT_WRAPPERS`]（外部 crate 收敛，单独校验）；
/// ② wrappers 中每个消费者须是 `layers::allows` 允许依赖被 ban crate 的层（防过宽 wrapper 开洞,
/// 如把某服务塞进域的 wrappers）；**②补强（ADR-005）**：`adapter→域` wrapper 须有**真实 source edge**
/// （adapter 实际依赖该域 crate）——否则「层级允许 adapter→域」会被误当「任意 adapter 可进任意域 wrapper」
/// 而空泛放过（`allows(Adapter,Domain)=true` 对所有 adapter 恒真）。edge-presence 是「该 adapter 真为该域
/// repo port 实现方」的 source-centric 代理（强代理：adapter 依赖域 crate 仅为 impl 其 port——域逻辑
/// `pub(crate)` 不外泄）；「仅 adapter 可 impl」的完整 implementer-allowlist 仍待 #1060。与 `check_layers`
/// 的 AdapterScope/SiblingDomain 互为两条 Medium 防线，须同绿。
/// 成员所需的 wrapper 消费者集（正向覆盖）：Domain/Adapter ⊇ 全组合根、Generated ⊇ 全域 + 组合根；
/// 非这三层返回 `None`（跳过）。dev/test adapter（[`layers::is_dev_adapter`]）正向只要 dev 组合根
/// （[`layers::DEV_ADAPTER_ROOTS`]，LAYER-DEPS-07）——生产 bin 不在 required。
fn required_consumers<'a>(
    layer: Option<Layer>,
    name: &str,
    roots: &[&'a str],
    domains: &[&'a str],
) -> Option<Vec<&'a str>> {
    match layer {
        Some(Layer::Adapter) if layers::is_dev_adapter(name) => Some(
            roots
                .iter()
                .copied()
                .filter(|r| layers::DEV_ADAPTER_ROOTS.contains(r))
                .collect(),
        ),
        Some(Layer::Domain | Layer::Adapter) => Some(roots.to_vec()),
        Some(Layer::Generated) => Some(domains.iter().chain(roots).copied().collect()),
        _ => None,
    }
}

/// LAYER-DEPS-07 反向排除：dev/test adapter 的 wrapper 须 ⊆ [`layers::DEV_ADAPTER_ROOTS`]
/// （禁 server/rss 生产 bin）。非 dev adapter 返回空。
fn dev_adapter_exclusions(b: &BanEntry, banned: Layer) -> Vec<Finding> {
    if !(matches!(banned, Layer::Adapter) && layers::is_dev_adapter(&b.crate_name)) {
        return Vec::new();
    }
    b.wrappers
        .iter()
        .filter(|w| !layers::DEV_ADAPTER_ROOTS.contains(&w.as_str()))
        .map(|w| {
            finding(
                Rule::WrapperCoverage,
                b.crate_name.clone(),
                format!(
                    "dev/test adapter `{}` 不得被非 dev 组合根 `{w}` 依赖（禁生产 bin，LAYER-DEPS-07）",
                    b.crate_name
                ),
            )
        })
        .collect()
}

pub(crate) fn check_wrappers(
    members: &[Member],
    bans: &[BanEntry],
    edges: &[Edge],
) -> Vec<Finding> {
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
        let Some(required) = required_consumers(m.layer, &m.name, &roots, &domains) else {
            continue;
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
        // 外部 crate 收敛 wrapper（dynosaur/trait-variant → diport+域 crate 白名单，DIPORT-MACRO-CONFINE-01′）
        // 是独立类别——由 `check_external_confinement` 单独校验（白名单越层 + 正向覆盖 + 集合相等），此处跳过，
        // 避免被误判为 stale 分层 wrapper。
        if EXTERNAL_CONFINEMENT_WRAPPERS
            .iter()
            .any(|(ext, _)| *ext == b.crate_name.as_str())
        {
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
        // LAYER-DEPS-07：dev/test adapter 禁生产组合根依赖（与正向 required 收窄互为表里）。
        findings.extend(dev_adapter_exclusions(b, banned));
        for w in &b.wrappers {
            match layer_of.get(w.as_str()) {
                Some(&wl) if layers::allows(wl, banned) => {
                    // ②补强（ADR-005）：adapter→域 wrapper 须有真实 source edge（adapter 实际依赖该域），
                    // 否则空泛放过任意 adapter。仅对 Adapter→Domain 这条 DIP 内向边校验（其它放行边不变）。
                    if wl == Layer::Adapter
                        && banned == Layer::Domain
                        && !edges.iter().any(|e| e.from == *w && e.to == b.crate_name)
                    {
                        findings.push(finding(
                            Rule::WrapperCoverage,
                            b.crate_name.clone(),
                            format!(
                                "deny.toml wrapper `{w}`（Adapter）未实际依赖域 `{}`（无 adapter→域 source edge）——\
                                 域 wrapper 只放行真实 impl 其 repo/service port 的 adapter（ADR-005 DIP 内向边）",
                                b.crate_name
                            ),
                        ));
                    }
                }
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

/// 外部 crate 收敛 wrapper 校验（DIPORT-MACRO-CONFINE-01′）——与分层 wrapper（[`check_wrappers`]）正交：
/// 目标是**外部** crate（不在 workspace 成员集）。委托 [`check_confinement_against`]（生产用真实
/// [`EXTERNAL_CONFINEMENT_WRAPPERS`]）。
pub(crate) fn check_external_confinement(members: &[Member], bans: &[BanEntry]) -> Vec<Finding> {
    check_confinement_against(EXTERNAL_CONFINEMENT_WRAPPERS, members, bans)
}

/// LAYER-DEPS-08：test-support 库（[`layers::TEST_SUPPORT_CRATES`]）禁进生产 shipped 依赖图。
///
/// 本 lint 只扫 shipped 依赖表（见模块头），dev-dependency 边不入 `edges`；故**任一**指向 test-support
/// 成员的内部边都是 shipped 误用——应改放 `[dev-dependencies]`。补 `allows` 矩阵盲区：`allows(Domain,
/// Service)=true` 不阻止域 crate 把 `testkit` 误放 `[dependencies]`（把 architecture.md「testkit 不进
/// 生产 shipped 图」从注释 Soft 升为 Medium 机器门）。anti-vacuity：真实工作区 testkit 仅 dev-dep，0 finding；
/// 红 case 见 `check_test_support_confinement_red_shipped_dep`。
pub(crate) fn check_test_support_confinement(edges: &[Edge]) -> Vec<Finding> {
    edges
        .iter()
        .filter(|edge| layers::is_test_support(&edge.to))
        .map(|edge| {
            finding(
                Rule::TestSupportShipped,
                edge.from.clone(),
                format!(
                    "{} {}.{} → `{}`：test-support 库禁进生产 shipped 图，只准 [dev-dependencies] 消费（INVARIANT LAYER-DEPS-08；改放 [dev-dependencies]）",
                    edge.from_manifest, edge.section, edge.key, edge.to
                ),
            )
        })
        .collect()
}

/// 对给定白名单逐 entry 委托 [`check_confinement_entry`]。allowlist 作参数（非直读 const）使**完整路径**
/// 可被注入合成白名单的红 case 覆盖——含「白名单本身越层」（const 漂移）这条否则无法合成的分支。
fn check_confinement_against(
    allowlist: &[(&str, &[&str])],
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    allowlist
        .iter()
        .flat_map(|(ext, allow)| check_confinement_entry(ext, allow, members, bans))
        .collect()
}

/// 单个外部收敛 entry 的双向 fail-closed 校验（DIPORT-MACRO-CONFINE-01′）：
/// - **白名单越层 / typo**：`allow` 每个条目须现存且属 DI port 定义层（DiPort/Domain）——防白名单本身把
///   非 port 层 crate 列为 sanctioned 依赖方。
/// - **正向覆盖**：`ext` 必须有对应 ban——否则删除 `dynosaur`/`trait-variant` ban 会使 dyn-dispatch 宏收敛
///   静默失效而 lint 不报错。
/// - **集合相等**：deny.toml wrappers 须恰等白名单（既不多——多则开洞；也不少——少则 sanctioned 域 crate
///   的合法 dynosaur 依赖被 cargo-deny 误拦）。顺序无关。
fn check_confinement_entry(
    ext: &str,
    allow: &[&str],
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let layer_of: BTreeMap<&str, Layer> = members
        .iter()
        .filter_map(|m| m.layer.map(|l| (m.name.as_str(), l)))
        .collect();
    let mut findings = Vec::new();

    // 白名单条目须现存 + 属 DI port 定义层（DiPort/Domain）。
    for w in allow {
        match layer_of.get(w) {
            Some(Layer::DiPort | Layer::Domain) => {}
            Some(other) => findings.push(finding(
                Rule::WrapperCoverage,
                (*w).to_string(),
                format!(
                    "外部收敛白名单 `{w}`（{other:?}）非 DI port 定义层（DiPort/Domain），不得 sanctioned 依赖 `{ext}`"
                ),
            )),
            None => findings.push(finding(
                Rule::WrapperCoverage,
                (*w).to_string(),
                format!("外部收敛白名单 `{w}` 不是工作区成员（typo / 已删除）"),
            )),
        }
    }

    match bans.iter().find(|b| b.crate_name.as_str() == ext) {
        // 正向覆盖：ban 缺失（删除即收敛失效）。
        None => findings.push(finding(
            Rule::WrapperCoverage,
            ext.to_string(),
            format!(
                "deny.toml 缺外部收敛 ban：`{ext}` 须恰限定到白名单 {allow:?}（删除会使 dyn-dispatch 宏收敛静默失效）"
            ),
        )),
        Some(b) => {
            let have: BTreeSet<&str> = b.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = allow.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    b.crate_name.clone(),
                    format!(
                        "外部收敛 wrapper `{ext}` 与白名单漂移：deny.toml 多列 {extra:?}（开洞）/ 欠列 {missing:?}（误拦合法依赖）。\
                         权威来源 = xtask/src/layerdeps.rs::EXTERNAL_CONFINEMENT_WRAPPERS（白名单 {allow:?}）——同步 deny.toml 该 ban 的 wrappers 使两侧集合相等即消除"
                    ),
                ));
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

    /// LAYER-DEPS-08 anti-vacuity（绿）：testkit 仅经 dev-dep 消费 ⇒ shipped `edges` 无指向它的边 ⇒ 0 finding。
    #[test]
    fn check_test_support_confinement_green_no_shipped_edge() {
        // shipped 边均不指向 testkit（identity→testkit 是 dev-dep，不入 edges）。
        let edges = vec![e("identity", "httpserve"), e("identity", "generated")];
        assert!(check_test_support_confinement(&edges).is_empty());
    }

    /// LAYER-DEPS-08（红）：误把 testkit 放进 `[dependencies]`（shipped 边）⇒ flagged。
    #[test]
    fn check_test_support_confinement_red_shipped_dep() {
        let findings = check_test_support_confinement(&[e("identity", "testkit")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::TestSupportShipped);
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

    /// ADR-005：`adapter→域` DIP 内向边在 `check_layers` 端到端**不报** finding（anti-vacuity 绿；
    /// 与 layers.rs 矩阵 `allows(Adapter,Domain)=true` 互证）。反向 `域→adapter` 仍红见
    /// `check_layers_red_adapter_scope` + 矩阵 `Domain→Adapter=false`。
    #[test]
    fn check_layers_green_adapter_to_domain() {
        let members = vec![
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
            m("identity", "crates/identity", Some(Layer::Domain)),
        ];
        assert!(check_layers(&members, &[e("postgres", "identity")]).is_empty());
    }

    /// ADR-009：受控 `bootstrap → httpserve` 路由类型边在 `check_layers` 端到端**不报** finding（anti-vacuity
    /// 绿；与 layers.rs `route_funnel_allows` + LAYER-DEPS-ROUTE-FUNNEL-01 互证）。反向 `httpserve → bootstrap`
    /// 仍红见下方 `check_layers_red_route_funnel_reverse`；其它 Service→Service 仍红见 `check_layers_red_same_layer_service`。
    #[test]
    fn check_layers_green_route_funnel_bootstrap_to_httpserve() {
        let members = vec![
            m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
        ];
        assert!(check_layers(&members, &[e("bootstrap", "httpserve")]).is_empty());
    }

    /// 反向 `httpserve → bootstrap` 仍红（httpserve 禁依赖 bootstrap，funnel 例外只放行单向）——BackPath。
    #[test]
    fn check_layers_red_route_funnel_reverse() {
        let members = vec![
            m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
        ];
        let findings = check_layers(&members, &[e("httpserve", "bootstrap")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::BackPath);
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

    /// F1：基础 intra-base DAG **反向**边违规——DAG 为 `vocab ◁ … ◁ support`，`vocab → support` 是倒挂边
    /// （非 BASE-INTRADAG-01 放行的前向边 → BackPath）。前向边（如 `support → vocab` / `runctx → vocab`）由
    /// `basis_intra_dag_allows` 放行，见 layers.rs `basis_intra_dag_allows_forward_only`。
    #[test]
    fn check_layers_red_same_layer_basis() {
        let members = vec![
            m("vocab", "crates/vocab", Some(Layer::Basis)),
            m("support", "crates/support", Some(Layer::Basis)),
        ];
        let findings = check_layers(&members, &[e("vocab", "support")]);
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

    /// 外部收敛专用 fixture：在 [`wrapper_fixture_members`] 上加 `settings`（Domain，定义自身 repo port），
    /// 使 `EXTERNAL_CONFINEMENT_WRAPPERS` 白名单的 `settings` 条目能解析到 Domain 成员（DIPORT-MACRO-CONFINE-01′）。
    /// 不复用 `wrapper_fixture_members`（加 settings 会令 `check_wrappers_*` fixtures 需补 settings ban，cascade）。
    fn confinement_fixture_members() -> Vec<Member> {
        let mut members = wrapper_fixture_members();
        members.push(m("settings", "crates/settings", Some(Layer::Domain)));
        members
    }

    #[test]
    fn check_wrappers_green() {
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        assert!(check_wrappers(&wrapper_fixture_members(), &bans, &[]).is_empty());
    }

    #[test]
    fn check_wrappers_red_missing_root() {
        // identity 的 wrappers 漏了 xtask（新增组合根未同步）。
        let bans = vec![
            ban("identity", &["server", "rss"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans, &[]);
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
        let findings = check_wrappers(&wrapper_fixture_members(), &bans, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "identity");
    }

    fn dev_adapter_fixture_members() -> Vec<Member> {
        vec![
            m("server", "bins/server", Some(Layer::Root)),
            m("rss", "bins/rss", Some(Layer::Root)),
            m("xtask", "xtask", Some(Layer::Root)),
            m("journeys", "journeys", Some(Layer::Root)),
            m("memory", "adapters/memory", Some(Layer::Adapter)),
        ]
    }

    #[test]
    fn check_wrappers_dev_adapter_green() {
        // LAYER-DEPS-07 green：dev adapter `memory` 只被 dev 组合根（journeys/xtask）依赖。
        let bans = vec![ban("memory", &["journeys", "xtask"])];
        assert!(check_wrappers(&dev_adapter_fixture_members(), &bans, &[]).is_empty());
    }

    #[test]
    fn check_wrappers_dev_adapter_red_production_bin() {
        // LAYER-DEPS-07 red（anti-vacuity）：dev adapter `memory` 的 wrapper 含生产 bin `server` → 红。
        let bans = vec![ban("memory", &["server", "journeys", "xtask"])];
        let findings = check_wrappers(&dev_adapter_fixture_members(), &bans, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.subject == "memory" && f.rule == Rule::WrapperCoverage),
            "生产 bin server 依赖 dev adapter 须被 LAYER-DEPS-07 拦截"
        );
    }

    #[test]
    fn check_wrappers_red_generated_missing_domain() {
        // generated 的 wrappers 漏了域消费者 identity。
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["server", "rss", "xtask"]),
        ];
        let findings = check_wrappers(&wrapper_fixture_members(), &bans, &[]);
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
        let findings = check_wrappers(&members, &bans, &[]);
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
        let findings = check_wrappers(&wrapper_fixture_members(), &bans, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "ghost");
    }

    // DiPort 层成员本身不需要分层 ban entry（只有 Domain/Adapter/Generated 需要）——
    // 守 `check_wrappers` 的 `_ => continue` 正向旁路非恒错：仅含一个 diport 成员、无 ban 时 findings 为空。
    // 外部收敛 ban（dynosaur/trait-variant）在 check_wrappers reverse loop 被 `continue` 跳过、不误判 stale。
    #[test]
    fn check_wrappers_diport_layer_needs_no_ban_entry() {
        let members = vec![m("diport", "crates/diport", Some(Layer::DiPort))];
        assert!(check_wrappers(&members, &[], &[]).is_empty());
    }

    /// F1（ADR-005 #1083）：域 ban 的 adapter wrapper **有真实 adapter→域 edge** → 绿（postgres 实现
    /// identity repo port，依赖 identity）。
    #[test]
    fn check_wrappers_green_domain_adapter_with_edge() {
        let mut members = wrapper_fixture_members();
        members.push(m("postgres", "adapters/postgres", Some(Layer::Adapter)));
        let bans = vec![
            ban("identity", &["server", "rss", "xtask", "postgres"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("postgres", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        let edges = vec![e("postgres", "identity")];
        assert!(check_wrappers(&members, &bans, &edges).is_empty());
    }

    /// F1（ADR-005 #1083）：域 ban 的 adapter wrapper **无 adapter→域 edge** → 红（redis 未依赖 identity、
    /// 不实现其 port，却被塞进 identity wrapper）——守空泛放过（`allows(Adapter,Domain)=true` 对所有 adapter 恒真）。
    #[test]
    fn check_wrappers_red_domain_adapter_without_edge() {
        let bans = vec![
            ban("identity", &["server", "rss", "xtask", "redis"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("generated", &["identity", "server", "rss", "xtask"]),
        ];
        // 无 redis→identity edge。
        let findings = check_wrappers(&wrapper_fixture_members(), &bans, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "identity");
    }

    // DIPORT-MACRO-CONFINE-01′（check_external_confinement）：外部收敛 wrapper 白名单 = DI port 定义点集
    // （diport[DiPort] + 定义自身 repo/service port 的域 crate，Option 2/ADR-005）。双向 fail-closed。
    #[test]
    fn external_confinement_green() {
        let bans = vec![
            ban("dynosaur", &["diport", "identity", "settings"]),
            ban("trait-variant", &["diport", "identity", "settings"]),
        ];
        assert!(check_external_confinement(&confinement_fixture_members(), &bans).is_empty());
    }

    // wrappers 顺序无关（集合相等）：白名单乱序仍绿。
    #[test]
    fn external_confinement_green_order_insensitive() {
        let bans = vec![
            ban("dynosaur", &["settings", "identity", "diport"]),
            ban("trait-variant", &["identity", "settings", "diport"]),
        ];
        assert!(check_external_confinement(&confinement_fixture_members(), &bans).is_empty());
    }

    #[test]
    fn external_confinement_red_ban_deleted() {
        // 删掉 dynosaur ban（保留 trait-variant）→ 正向覆盖报 dynosaur 缺失（防收敛静默失效，F4）。
        let bans = vec![ban("trait-variant", &["diport", "identity", "settings"])];
        let findings = check_external_confinement(&confinement_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "dynosaur");
    }

    #[test]
    fn external_confinement_red_widened() {
        // 过覆盖（开洞）：wrappers 含白名单外的 crate（server[Root]），DI port 定义点集被破坏。
        let bans = vec![
            ban("dynosaur", &["diport", "identity", "settings", "server"]),
            ban("trait-variant", &["diport", "identity", "settings"]),
        ];
        let findings = check_external_confinement(&confinement_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "dynosaur");
    }

    #[test]
    fn external_confinement_red_under_covered() {
        // 欠覆盖：deny.toml 漏列 sanctioned 域 crate（settings）→ 该域的合法 dynosaur 依赖会被 cargo-deny
        // 误拦。集合不等 → 报 dynosaur（防 deny.toml 与白名单漂移）。
        let bans = vec![
            ban("dynosaur", &["diport", "identity"]),
            ban("trait-variant", &["diport", "identity", "settings"]),
        ];
        let findings = check_external_confinement(&confinement_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "dynosaur");
    }

    #[test]
    fn external_confinement_red_non_port_layer_in_allowlist() {
        // 白名单条目须属 DI port 定义层（DiPort/Domain）。经**完整路径** check_confinement_against 注入一个
        // 含非 port 层成员（redis[Adapter]）的合成白名单、deny.toml 与之一致，仍应因「白名单越层」红——
        // 守住「EXTERNAL_CONFINEMENT_WRAPPERS 常量本身越层漂移」（const 无法在测试内改，故经注入合成白名单
        // 走完整 loop 验证）。真实白名单 = diport + 定义 repo port 的域 crate。
        let bans = vec![ban("dynosaur", &["diport", "redis"])];
        let findings = check_confinement_against(
            &[("dynosaur", &["diport", "redis"])],
            &wrapper_fixture_members(),
            &bans,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::WrapperCoverage && f.subject == "redis"),
            "白名单含非 port 层成员应红: {findings:?}"
        );
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
        findings.extend(check_wrappers(&members, &bans, &scan.edges));
        findings.extend(check_external_confinement(&members, &bans));
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
