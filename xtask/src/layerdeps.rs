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
//! INVARIANT: LAYER-DEPS-01 { level = "Medium", exec = "check", source = "code" }—— back-path 反向边（上行 / 横向同层 / 跨界依赖）。
//! INVARIANT: LAYER-DEPS-02 { level = "Medium", exec = "check", source = "code" }—— 兄弟域互斥（跨域只经 contract）。
//! INVARIANT: LAYER-DEPS-03 { level = "Medium", exec = "check", source = "code" }—— adapter 仅组合根注入（不被域 / 服务依赖）。
//! INVARIANT: LAYER-DEPS-04 { level = "Medium", exec = "check", source = "code" }—— generated 仅域 + 组合根，以及精确
//!   `eventexec|bootstrap → generated` sealed runtime authoring/registration seam 依赖；其它 Service→Generated 仍禁。
//! INVARIANT: LAYER-DEPS-GENERATED-BOOTSTRAP-REGISTRAR-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::bootstrap_generated_registrar_surface_rejects_non_registrar_matrix", anti_vacuity = "tests::bootstrap_generated_registrar_surface_accepts_exact_vocabulary|tests::real_workspace_green" }——
//!   `bootstrap → generated` 的 crate edge 只承载 sealed subscription registrar vocabulary；production source
//!   引用 event authoring、command/workflow、catalog、per-event module 或宽 module/glob import 均 fail-closed。
//! INVARIANT: LAYER-DEPS-05 { level = "Medium", exec = "check", source = "code" }—— 每个 workspace 成员必落唯一分层（anti-drift：新增 crate 须登记层）。
//! INVARIANT: LAYER-DEPS-06 { level = "Medium", exec = "check", source = "code" }—— deny.toml 分层 wrappers ⟷ 源分类一致（守 `LAYER-WRAP-01` 漂移）。
//! INVARIANT: LAYER-DEPS-07 { level = "Medium", exec = "check", source = "code" }—— 含 path 的本地依赖须解析到现存 workspace 成员；逃逸 / 非成员
//!   一律 fail-closed 报错（杜绝 path-dep 静默绕过分层门）。
//! INVARIANT: LAYER-DEPS-08 { level = "Medium", exec = "check", source = "code" }—— test-support 库（`layers::TEST_SUPPORT_CRATES`，当前为 `testkit`、`tracewiretest` 与 `iotdevice`）只准经
//!   `[dev-dependencies]` 消费，禁进生产 shipped 依赖图。本 lint 只扫 shipped 依赖表，故**任一**指向
//!   test-support 成员的内部边即 shipped 误用（dev-dep 边压根不入 `edges`）；补 `allows` 矩阵盲区
//!   （例如 `allows(Domain,Service)=true` 不阻止域 crate 误把 testkit 放进 `[dependencies]`，Example
//!   分类也不会自行阻止 root/其它允许边把 iotdevice 带入 shipped 图）。
//! INVARIANT: LAYER-DEPS-09 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_runctx_testsupport_in_dependencies|tests::red_testsupport_features_follow_direct_and_workspace_package_aliases|tests::red_testsupport_feature_closure_follows_default_alias_recursion_and_cycle|tests::red_eventexec_testsupport_feature_closure_is_shipped|tests::red_generated_testsupport_direct_alias_and_forwarding_are_shipped|tests::red_testsupport_feature_closure_follows_dep_activation_and_dependency_default|tests::red_domain_scope_testsupport_in_dependencies|tests::red_bootstrap_testsupport_in_dependencies", anti_vacuity = "tests::green_runctx_without_testsupport|tests::real_workspace_testsupport_forwarding_graph_is_nonempty|tests::real_workspace_green" }—— scoped construction 的
//!   `test-support` **feature** 只准经 `[dev-dependencies]` 启用，禁在任一 shipped feature 闭包
//!   （成员默认 feature + `[dependencies]`/`[build-dependencies]`/`[target.*]` activation）启用。闭包解析
//!   Cargo `default`、本地递归/循环、`dep:`、依赖 feature forwarding 与 package alias。覆盖 `runctx/test-support`
//!   （构造 `AppCtx`）、`identity`/`settings`/`audit` 的 `TenantRepoScope::for_test`、
//!   `eventexec/test-support`（构造 Projection conformance source/operator authority）、
//!   `generated/test-support`（暴露 sealed test-only contract catalog）、以及
//!   `bootstrap/test-support`（`forge_topology_for_test`）与 `identity-composition|deviceidentity/test-support`
//!   （暂停 application-receipt relay 的测试控制）；生产构建启用即可伪造 tenant scope / 事件拓扑或
//!   暴露 relay 控制，绕过 typed funnel（#1105 review C-3 + #1594 review F6：Soft→Medium 机器门）。
//! INVARIANT: LAYER-DEPS-10 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::test_support_internal_dependencies_red_shipped_edges", anti_vacuity = "tests::test_support_internal_dependencies_green_no_shipped_edge" }—— test-support 库（`layers::TEST_SUPPORT_CRATES`）的 shipped
//!   出边只能指向外部 crate；任一指向 workspace 内部成员的出边均失败，保持 test-support crate 为零
//!   production-adapter、零 workspace 依赖的独立测试工具。与 LAYER-DEPS-08 的 shipped 入边约束正交。
//! INVARIANT: RUNTIMEEXEC-LAYER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtimeexec_wrapper_widened_to_bin_red|tests::runtimeexec_wrapper_missing_assembly_red", anti_vacuity = "tests::runtimeexec_wrapper_exact_green" }——
//!   `runtimeexec` target wrapper 必须恰为 runtime/settingsonly/identityaudit 三个 assembly，禁止 bins、composition、
//!   journeys 与 xtask 直接依赖；该特殊 wrapper 不得被一般 Domain/Adapter/Generated stale 逻辑误判。
//! INVARIANT: AUTHMINT-LAYER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::authmint_wrapper_widened_to_bin_red|tests::authmint_wrapper_missing_consumer_red", anti_vacuity = "tests::authmint_wrapper_exact_green" }——
//!   `authmint` target wrapper 必须恰为 httpserve + runtime/settingsonly/identityaudit；域 / journeys 不得持有
//!   Authenticated production mint capability（AUTH-EVIDENCE-MINT-01 Hard 的 deny.toml 半段）。
//! INVARIANT: RUNTIME-INVENTORY-MINT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtimeinventorymint_wrapper_widened_to_assembly_red", anti_vacuity = "tests::runtimeinventorymint_wrapper_exact_green|tests::real_workspace_green" }——
//!   inventory mint token 只准 assembly-schema 声明签名、runtimeexec 铸造完整计划 receipt，以及 runtime
//!   的 placement-projected provider transaction 持有；其它 assembly roots 不得依赖。
//! INVARIANT: RUNTIMEEXEC-DEPS-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::runtimeexec_direct_dependencies_extra_internal_and_external_red|tests::runtimeexec_direct_dependencies_package_alias_red", anti_vacuity = "tests::runtimeexec_direct_dependencies_allowlist_green|tests::real_workspace_green" }——
//!   `runtimeexec` shipped direct dependency 只准内部 assembly-schema/authn/bootstrap/diport/eventexec/primitives/secure 与外部
//!   anyhow/serde/serde_json/thiserror/tokio/tokio-util/tracing/zeroize；
//!   `[dev-dependencies]` 不入扫描。
//! `LAYER-DEPS-PROVIDER-BOOTSTRAP-01` 的精确 deny 与元数据单源见 `layers.rs`；本 lint 在通用允许矩阵
//! 之前应用它，并以 Redis/S3/Vault synthetic red + postgres/diport anti-vacuity green 承载。

use anyhow::{Context, Result, bail};
use quote::ToTokens as _;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use syn::visit::Visit as _;

use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::layers::{self, Layer};
use crate::src_scan::rs_files;

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
    /// LAYER-DEPS-GENERATED-BOOTSTRAP-REGISTRAR-01：bootstrap 引用了 registrar 外的 generated surface。
    GeneratedBootstrapSurface,
    /// LAYER-DEPS-05：workspace 成员未落任何分层（新增未登记）。
    LayerCoverage,
    /// LAYER-DEPS-06：deny.toml 分层 wrappers 与源分类不一致。
    WrapperCoverage,
    /// LAYER-DEPS-07：含 path 的本地依赖未解析到现存 workspace 成员（逃逸 / 非成员 / typo）。
    UnresolvedPath,
    /// LAYER-DEPS-08：test-support 库被 shipped 依赖（应只经 `[dev-dependencies]` 消费）。
    TestSupportShipped,
    /// LAYER-DEPS-09：scoped construction 的 `test-support` **feature** 被 shipped 依赖表启用（应只经
    /// `[dev-dependencies]` 启用）。
    TestSupportFeatureShipped,
    /// LAYER-DEPS-10：test-support 库 shipped 依赖 workspace 内部成员（只准依赖外部 crate）。
    TestSupportInternalShipped,
    /// RUNTIMEEXEC-DEPS-01：runtimeexec 出现 allowlist 外的 shipped direct dependency。
    RuntimeExecDependencyScope,
    /// WORKSPACEFACTS-CONFINEMENT-01：workspacefacts/guppy 只能沿精确 tooling funnel 消费。
    WorkspaceFactsConfinement,
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

        let shipped_deps = collect_shipped_deps(&root, &members, &workspace.dependencies)?;
        let shipped_test_support_features =
            scan_workspace_testsupport_features(&root, &members, &workspace.dependencies)?;
        let mut findings = check_layers(&members, &scan.edges);
        findings.extend(scan.findings);
        findings.extend(scan_bootstrap_generated_sources(&root)?);
        findings.extend(check_wrappers(&members, &bans, &scan.edges));
        findings.extend(check_external_confinement(&members, &bans));
        findings.extend(check_workspacefacts_confinement(
            &members,
            &bans,
            &scan.edges,
            &shipped_deps,
        ));
        findings.extend(check_test_support_confinement(&scan.edges));
        findings.extend(check_test_support_internal_dependencies(&scan.edges));
        findings.extend(shipped_test_support_features);
        findings.extend(check_runtimeexec_direct_dependencies(
            &scan.edges,
            &shipped_deps,
        ));

        let summary = format!(
            "{} 成员 / {} 内部边 / {} wrappers / {} shipped 依赖（feature + RuntimeExec allowlist 扫描）全部通过",
            members.len(),
            scan.edges.len(),
            bans.len(),
            shipped_deps.len(),
        );
        Ok((summary, findings))
    }
}

const BOOTSTRAP_GENERATED_REGISTRAR_SURFACE: &[&str] = &[
    "generated::event::EventContract",
    "generated::event::EventSubscribe",
    "generated::event::EventSubscription",
    "generated::event::SubscriptionEffect",
    "generated::event::SubscriptionExecution",
];

fn scan_bootstrap_generated_sources(root: &Path) -> Result<Vec<Finding>> {
    let source_root = root.join("crates/bootstrap/src");
    let files = rs_files(&source_root)?;
    if files.is_empty() {
        return Ok(vec![finding(
            Rule::GeneratedBootstrapSurface,
            "crates/bootstrap/src",
            "bootstrap registrar surface guard 未发现 production Rust source".to_string(),
        )]);
    }
    let mut findings = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("读 bootstrap source 失败: {}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path);
        findings.extend(scan_bootstrap_generated_surface(relative, &source));
    }
    Ok(findings)
}

fn scan_bootstrap_generated_surface(path: &Path, source: &str) -> Vec<Finding> {
    let Ok(file) = syn::parse_file(source) else {
        return vec![finding(
            Rule::GeneratedBootstrapSurface,
            path.display().to_string(),
            "bootstrap generated registrar source AST 无法解析".to_string(),
        )];
    };
    let mut visitor = BootstrapGeneratedSurfaceVisitor::default();
    visitor.visit_file(&file);
    visitor
        .forbidden
        .into_iter()
        .map(|surface| {
            finding(
                Rule::GeneratedBootstrapSurface,
                path.display().to_string(),
                format!(
                    "bootstrap → generated 只允许 sealed subscription registrar vocabulary，禁止 `{surface}`"
                ),
            )
        })
        .collect()
}

#[derive(Default)]
struct BootstrapGeneratedSurfaceVisitor {
    forbidden: BTreeSet<String>,
}

impl BootstrapGeneratedSurfaceVisitor {
    fn inspect(&mut self, path: String) {
        let path = path.trim_start_matches("::").to_string();
        if !is_generated_surface(&path) {
            return;
        }
        if !bootstrap_generated_surface_allowed(&path) {
            self.forbidden.insert(path);
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for BootstrapGeneratedSurfaceVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if node.ident == "tests" || has_test_attr(&node.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if has_test_attr(&node.attrs) {
            return;
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if has_test_attr(&node.attrs) {
            return;
        }
        collect_use_surfaces(&node.tree, Vec::new(), &mut self.forbidden);
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        if node.ident == "generated" {
            self.forbidden
                .insert("generated::<extern-crate>".to_string());
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.inspect(path.to_token_stream().to_string().replace(' ', ""));
        syn::visit::visit_path(self, path);
    }
}

fn collect_use_surfaces(
    tree: &syn::UseTree,
    mut prefix: Vec<String>,
    forbidden: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_surfaces(&path.tree, prefix, forbidden);
        }
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            inspect_use_surface(prefix.join("::"), forbidden);
        }
        syn::UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            inspect_use_surface(prefix.join("::"), forbidden);
        }
        syn::UseTree::Glob(_) => {
            prefix.push("*".to_string());
            inspect_use_surface(prefix.join("::"), forbidden);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_surfaces(item, prefix.clone(), forbidden);
            }
        }
    }
}

fn inspect_use_surface(path: String, forbidden: &mut BTreeSet<String>) {
    if !is_generated_surface(&path) {
        return;
    }
    if !bootstrap_generated_surface_allowed(&path) {
        forbidden.insert(path);
    }
}

fn is_generated_surface(path: &str) -> bool {
    path == "generated" || path.starts_with("generated::")
}

fn bootstrap_generated_surface_allowed(path: &str) -> bool {
    BOOTSTRAP_GENERATED_REGISTRAR_SURFACE.contains(&path)
}

fn has_test_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if attr.path().is_ident("test") {
            return true;
        }
        if !attr.path().is_ident("cfg") {
            return false;
        }
        attr.parse_args::<syn::Meta>()
            .is_ok_and(|meta| cfg_predicate_includes_test(&meta))
    })
}

/// True only for the bare `test` cfg option (`cfg(test)`, `cfg(any(..., test, ...))`,
/// `cfg(all(test, ...))`). Feature names that merely contain `"test"` (e.g.
/// `feature = "test-support"`) must not match — substring scans false-positive those.
fn cfg_predicate_includes_test(meta: &syn::Meta) -> bool {
    use syn::parse::Parser as _;
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("any") || list.path.is_ident("all") => {
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated
                .parse2(list.tokens.clone())
                .is_ok_and(|nested| nested.iter().any(cfg_predicate_includes_test))
        }
        // `not(test)` is production-facing; never treat as test-only skip.
        _ => false,
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
        // Service→Generated 默认禁；仅 eventexec|bootstrap 可分别实现 generated sealed
        // authoring/runtime 与 event subscription registration seam。
        let provider_bootstrap_forbidden =
            layers::provider_adapter_bootstrap_forbidden(&edge.from, &edge.to);
        if provider_bootstrap_forbidden
            || (!layers::allows(from, to)
                && !layers::basis_intra_dag_allows(&edge.from, &edge.to)
                && !layers::route_funnel_allows(&edge.from, &edge.to)
                && !layers::generated_seam_allows(&edge.from, &edge.to))
        {
            let reason = if provider_bootstrap_forbidden {
                "违反 Redis/S3/Vault provider output 边界（禁止 adapter → bootstrap）".to_string()
            } else {
                format!("违反 {from:?}→{to:?} 分层矩阵")
            };
            findings.push(finding(
                violation_rule(from, to),
                edge.from.clone(),
                format!(
                    "{} {}.{} → `{}`（{to:?}）{reason}",
                    edge.from_manifest, edge.section, edge.key, edge.to,
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
/// INVARIANT: DIPORT-MACRO-CONFINE-02 { level = "Medium", exec = "check", source = "code" }（Option 2 / ADR-005 把 `-01` 由「仅 diport」放宽为白名单）——
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
    ("dynosaur", &["diport", "identity", "settings", "audit"]),
    (
        "trait-variant",
        &["diport", "identity", "settings", "audit"],
    ),
];

const RUNTIMEEXEC_CRATE: &str = "runtimeexec";
const RUNTIMEEXEC_ALLOWED_WRAPPERS: &[&str] = &["runtime", "settingsonly", "identityaudit"];
const AUTHMINT_CRATE: &str = "authmint";
const AUTHMINT_ALLOWED_WRAPPERS: &[&str] = &[
    "diport",
    "httpserve",
    "runtime",
    "settingsonly",
    "identityaudit",
];
const SAGAAUTHMINT_CRATE: &str = "sagaauthmint";
const SAGAAUTHMINT_ALLOWED_WRAPPERS: &[&str] = &["diport", "runtime"];
const DLQAUTHMINT_CRATE: &str = "dlqauthmint";
const DLQAUTHMINT_ALLOWED_WRAPPERS: &[&str] = &["diport", "runtime"];
const REQUESTIDMINT_CRATE: &str = "requestidmint";
const REQUESTIDMINT_ALLOWED_WRAPPERS: &[&str] = &["httpserve", "generated"];
const RUNTIMEINVENTORYMINT_CRATE: &str = "runtimeinventorymint";
const RUNTIMEINVENTORYMINT_ALLOWED_WRAPPERS: &[&str] =
    &["assembly-schema", "runtimeexec", "runtime"];
const WORKSPACEFACTS_CRATE: &str = "workspacefacts";
const WORKSPACEFACTS_CONSUMER: &str = "xtask";
const GUPPY_CRATE: &str = "guppy";
const RUNTIMEEXEC_INTERNAL_SHIPPED_DEPS: &[&str] = &[
    "assembly-schema",
    "authn",
    "bootstrap",
    "diport",
    "eventexec",
    "primitives",
    "runtimeinventorymint",
    "secure",
];
const RUNTIMEEXEC_EXTERNAL_SHIPPED_DEPS: &[&str] = &[
    "anyhow",
    "serde",
    "serde_json",
    "thiserror",
    "tokio",
    "tokio-util",
    "tracing",
    "zeroize",
];
const POSTGRES_MIGRATION_OPERATOR_CRATE: &str = "postgres-migration";
const POSTGRES_MIGRATION_OPERATOR_ROOT: &str = "rss";

/// LAYER-DEPS-06：deny.toml 分层 wrappers ⟷ 源分类一致性（守 LAYER-WRAP-01 漂移）。
/// 正向：每个 Domain/Adapter/Generated 成员须有 ban entry 且 wrappers ⊇ 所需消费者
/// （Domain/Adapter ⊇ 全部组合根；Generated ⊇ 全部域 + 组合根）。
/// 反向：① 每条带 wrappers 的 ban 须对应现存 Domain/Adapter/Generated 成员（无 stale），
/// **例外** [`EXTERNAL_CONFINEMENT_WRAPPERS`]（外部 crate 收敛）与 RuntimeExec / authmint 精确 target wrapper，均单独校验；
/// ② wrappers 中每个消费者须是 `layers::allows` 允许依赖被 ban crate 的层（防过宽 wrapper 开洞,
/// 如把某服务塞进域的 wrappers）；**②补强（ADR-005）**：`adapter→域` wrapper 须有**真实 source edge**
/// （adapter 实际依赖该域 crate）——否则「层级允许 adapter→域」会被误当「任意 adapter 可进任意域 wrapper」
/// 而空泛放过（`allows(Adapter,Domain)=true` 对所有 adapter 恒真）。edge-presence 是「该 adapter 真为该域
/// repo port 实现方」的 source-centric 代理（强代理：adapter 依赖域 crate 仅为 impl 其 port——域逻辑
/// `pub(crate)` 不外泄）；「仅 adapter 可 impl」的完整 implementer-allowlist 仍待 #1060。与 `check_layers`
/// 的 AdapterScope/SiblingDomain 互为两条 Medium 防线，须同绿。
/// 成员所需的 wrapper 消费者集（正向覆盖）：Domain/Adapter ⊇ 全组合根、Generated ⊇ 全域 + 组合根；
/// 非这三层返回 `None`（跳过；RuntimeExec / authmint 由精确 target wrapper 校验单独覆盖）。dev/test adapter（[`layers::is_dev_adapter`]）正向只要 dev 组合根
/// （[`layers::DEV_ADAPTER_ROOTS`]，LAYER-DEPS-07）——生产 bin 不在 required。
fn required_consumers<'a>(
    layer: Option<Layer>,
    name: &str,
    roots: &[&'a str],
    domains: &[&'a str],
    services: &[&'a str],
) -> Option<Vec<&'a str>> {
    if layer == Some(Layer::Adapter) && name == POSTGRES_MIGRATION_OPERATOR_CRATE {
        return Some(
            roots
                .iter()
                .copied()
                .filter(|root| *root == POSTGRES_MIGRATION_OPERATOR_ROOT)
                .collect(),
        );
    }
    match layer {
        Some(Layer::Adapter) if layers::is_dev_adapter(name) => Some(
            roots
                .iter()
                .copied()
                .filter(|r| layers::DEV_ADAPTER_ROOTS.contains(r))
                .collect(),
        ),
        Some(Layer::Domain | Layer::Adapter) => Some(roots.to_vec()),
        Some(Layer::Generated) => Some(
            domains
                .iter()
                .chain(roots)
                .copied()
                .chain(
                    services
                        .iter()
                        .copied()
                        .filter(|service| layers::generated_seam_allows(service, name)),
                )
                .collect(),
        ),
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
    let services = names_in(Layer::Service);
    let ban_of: BTreeMap<&str, &[String]> = bans
        .iter()
        .map(|b| (b.crate_name.as_str(), b.wrappers.as_slice()))
        .collect();

    let mut findings = check_runtimeexec_wrapper_coverage(members, bans);
    findings.extend(check_authmint_wrapper_coverage(members, bans));
    findings.extend(check_sagaauthmint_wrapper_coverage(members, bans));
    findings.extend(check_dlqauthmint_wrapper_coverage(members, bans));
    findings.extend(check_requestidmint_wrapper_coverage(members, bans));
    findings.extend(check_runtimeinventorymint_wrapper_coverage(members, bans));
    findings.extend(check_postgres_migration_operator_confinement(
        members, bans, edges,
    ));
    for m in members {
        let Some(required) = required_consumers(m.layer, &m.name, &roots, &domains, &services)
        else {
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
        // 外部 crate 收敛 wrapper（dynosaur/trait-variant → diport+域 crate 白名单，DIPORT-MACRO-CONFINE-02）
        // 是独立类别——由 `check_external_confinement` 单独校验（白名单越层 + 正向覆盖 + 集合相等），此处跳过，
        // 避免被误判为 stale 分层 wrapper。
        if EXTERNAL_CONFINEMENT_WRAPPERS
            .iter()
            .any(|(ext, _)| *ext == b.crate_name.as_str())
            || b.crate_name == RUNTIMEEXEC_CRATE
            || b.crate_name == AUTHMINT_CRATE
            || b.crate_name == SAGAAUTHMINT_CRATE
            || b.crate_name == DLQAUTHMINT_CRATE
            || b.crate_name == REQUESTIDMINT_CRATE
            || b.crate_name == RUNTIMEINVENTORYMINT_CRATE
            || b.crate_name == WORKSPACEFACTS_CRATE
            || b.crate_name == GUPPY_CRATE
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
                Some(&wl)
                    if layers::allows(wl, banned)
                        || layers::generated_seam_allows(w, &b.crate_name)
                        || layers::generated_dev_wrapper_allows(w, &b.crate_name) =>
                {
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

fn check_postgres_migration_operator_confinement(
    members: &[Member],
    bans: &[BanEntry],
    edges: &[Edge],
) -> Vec<Finding> {
    if !members
        .iter()
        .any(|member| member.name == POSTGRES_MIGRATION_OPERATOR_CRATE)
    {
        return Vec::new();
    }
    let mut findings = Vec::new();
    let wrappers = bans
        .iter()
        .find(|ban| ban.crate_name == POSTGRES_MIGRATION_OPERATOR_CRATE)
        .map(|ban| {
            ban.wrappers
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let expected = BTreeSet::from([POSTGRES_MIGRATION_OPERATOR_ROOT]);
    if wrappers != expected {
        findings.push(finding(
            Rule::WrapperCoverage,
            POSTGRES_MIGRATION_OPERATOR_CRATE,
            "migration capability wrapper must be exactly the rss operator binary",
        ));
    }
    if !members.iter().any(|member| {
        member.name == POSTGRES_MIGRATION_OPERATOR_ROOT && member.layer == Some(Layer::Root)
    }) || !edges.iter().any(|edge| {
        edge.from == POSTGRES_MIGRATION_OPERATOR_ROOT
            && edge.to == POSTGRES_MIGRATION_OPERATOR_CRATE
    }) {
        findings.push(finding(
            Rule::WrapperCoverage,
            POSTGRES_MIGRATION_OPERATOR_CRATE,
            "rss must have the non-vacuous source edge to migration capability",
        ));
    }
    let unauthorized = edges.iter().any(|edge| {
        edge.to == POSTGRES_MIGRATION_OPERATOR_CRATE
            && edge.from != POSTGRES_MIGRATION_OPERATOR_ROOT
    });
    if unauthorized {
        findings.push(finding(
            Rule::WrapperCoverage,
            POSTGRES_MIGRATION_OPERATOR_CRATE,
            "migration capability is reachable from a non-rss workspace crate",
        ));
    }
    findings
}

/// `runtimeexec` 是内部 target crate，但 wrapper 比普通分层 leaf 更窄：只准三个 assembly 直接消费。
/// 集合相等同时拒绝过宽和漏项；批准项自身必须是对应 `assemblies/*` 成员，防 const 漂移到其它 Root。
pub(crate) fn check_runtimeexec_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members.iter().find(|m| m.name == RUNTIMEEXEC_CRATE);
    let ban = bans.iter().find(|b| b.crate_name == RUNTIMEEXEC_CRATE);
    // 纯函数的其它分层 fixture 可不携带 RuntimeExec；真实工作区至少含 target 或 ban，缺一侧仍会红。
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|m| m.layer), Some(Some(Layer::RuntimeExec))) {
        findings.push(finding(
            Rule::WrapperCoverage,
            RUNTIMEEXEC_CRATE,
            "runtimeexec wrapper target 不是已分类的 RuntimeExec workspace 成员",
        ));
        return findings;
    }

    for allowed in RUNTIMEEXEC_ALLOWED_WRAPPERS {
        match members.iter().find(|m| m.name == *allowed) {
            Some(m)
                if m.layer == Some(Layer::Root)
                    && m.path == format!("assemblies/{allowed}") => {}
            Some(m) => findings.push(finding(
                Rule::WrapperCoverage,
                RUNTIMEEXEC_CRATE,
                format!(
                    "runtimeexec 批准消费者 `{allowed}` 必须是 `assemblies/{allowed}` Root，实际为 `{}` / {:?}",
                    m.path, m.layer
                ),
            )),
            None => findings.push(finding(
                Rule::WrapperCoverage,
                RUNTIMEEXEC_CRATE,
                format!("runtimeexec 批准消费者 `{allowed}` 不是 workspace 成员"),
            )),
        }
    }

    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            RUNTIMEEXEC_CRATE,
            "deny.toml 缺 runtimeexec target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = RUNTIMEEXEC_ALLOWED_WRAPPERS.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    RUNTIMEEXEC_CRATE,
                    format!(
                        "runtimeexec wrapper 必须与批准 assembly 集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// `authmint` 是独立 Basis capability token：wrapper 只准 diport（opaque proof mint）、
/// httpserve（构造面）+ 三个 assembly 验签桥。
/// 集合相等同时拒绝过宽（域/journeys）和漏项；批准项自身必须匹配精确路径与层。
pub(crate) fn check_authmint_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members.iter().find(|m| m.name == AUTHMINT_CRATE);
    let ban = bans.iter().find(|b| b.crate_name == AUTHMINT_CRATE);
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|m| m.layer), Some(Some(Layer::Basis)))
        || target.is_some_and(|m| m.path != "crates/authmint")
    {
        findings.push(finding(
            Rule::WrapperCoverage,
            AUTHMINT_CRATE,
            "authmint wrapper target 不是已分类的 Basis workspace 成员 `crates/authmint`",
        ));
        return findings;
    }

    for allowed in AUTHMINT_ALLOWED_WRAPPERS {
        match members.iter().find(|m| m.name == *allowed) {
            Some(m) if *allowed == "diport" => {
                if !(m.layer == Some(Layer::DiPort) && m.path == "crates/diport") {
                    findings.push(finding(
                        Rule::WrapperCoverage,
                        AUTHMINT_CRATE,
                        format!(
                            "authmint 批准消费者 `diport` 必须是 `crates/diport` DiPort，实际为 `{}` / {:?}",
                            m.path, m.layer
                        ),
                    ));
                }
            }
            Some(m) if *allowed == "httpserve" => {
                if !(m.layer == Some(Layer::Service) && m.path == "crates/httpserve") {
                    findings.push(finding(
                        Rule::WrapperCoverage,
                        AUTHMINT_CRATE,
                        format!(
                            "authmint 批准消费者 `httpserve` 必须是 `crates/httpserve` Service，实际为 `{}` / {:?}",
                            m.path, m.layer
                        ),
                    ));
                }
            }
            Some(m)
                if m.layer == Some(Layer::Root) && m.path == format!("assemblies/{allowed}") => {}
            Some(m) => findings.push(finding(
                Rule::WrapperCoverage,
                AUTHMINT_CRATE,
                format!(
                    "authmint 批准消费者 `{allowed}` 必须是 `assemblies/{allowed}` Root，实际为 `{}` / {:?}",
                    m.path, m.layer
                ),
            )),
            None => findings.push(finding(
                Rule::WrapperCoverage,
                AUTHMINT_CRATE,
                format!("authmint 批准消费者 `{allowed}` 不是 workspace 成员"),
            )),
        }
    }

    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            AUTHMINT_CRATE,
            "deny.toml 缺 authmint target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = AUTHMINT_ALLOWED_WRAPPERS.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    AUTHMINT_CRATE,
                    format!(
                        "authmint wrapper 必须与批准消费者集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// The Saga operator mint is a separate high-authority Basis root. Its exact wrapper set excludes
/// every ordinary authenticated-evidence consumer.
///
/// INVARIANT: SAGA-OPERATOR-MINT-02 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::sagaauthmint_wrapper_widened_red", anti_vacuity = "tests::sagaauthmint_wrapper_exact_green" }
pub(crate) fn check_sagaauthmint_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members
        .iter()
        .find(|member| member.name == SAGAAUTHMINT_CRATE);
    let ban = bans
        .iter()
        .find(|entry| entry.crate_name == SAGAAUTHMINT_CRATE);
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|member| member.layer), Some(Some(Layer::Basis)))
        || target.is_some_and(|member| member.path != "crates/sagaauthmint")
    {
        findings.push(finding(
            Rule::WrapperCoverage,
            SAGAAUTHMINT_CRATE,
            "sagaauthmint 必须是 `crates/sagaauthmint` 的 isolated Basis workspace member",
        ));
        return findings;
    }
    for (name, path, layer) in [
        ("diport", "crates/diport", Layer::DiPort),
        ("runtime", "assemblies/runtime", Layer::Root),
    ] {
        if !members
            .iter()
            .any(|member| member.name == name && member.path == path && member.layer == Some(layer))
        {
            findings.push(finding(
                Rule::WrapperCoverage,
                SAGAAUTHMINT_CRATE,
                format!("sagaauthmint 批准消费者 `{name}` 的 path/layer 不精确"),
            ));
        }
    }
    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            SAGAAUTHMINT_CRATE,
            "deny.toml 缺 sagaauthmint target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = SAGAAUTHMINT_ALLOWED_WRAPPERS.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    SAGAAUTHMINT_CRATE,
                    format!(
                        "sagaauthmint wrapper 必须与批准消费者集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// The DLQ operator mint is an isolated high-authority Basis root with an exact consumer set.
///
/// INVARIANT: DLQ-OPERATOR-MINT-02 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::dlqauthmint_wrapper_widened_red|tests::dlqauthmint_wrapper_missing_consumer_red|tests::dlqauthmint_reverse_dependency_red", anti_vacuity = "tests::dlqauthmint_wrapper_exact_green" }
pub(crate) fn check_dlqauthmint_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members
        .iter()
        .find(|member| member.name == DLQAUTHMINT_CRATE);
    let ban = bans
        .iter()
        .find(|entry| entry.crate_name == DLQAUTHMINT_CRATE);
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|member| member.layer), Some(Some(Layer::Basis)))
        || target.is_some_and(|member| member.path != "crates/dlqauthmint")
    {
        findings.push(finding(
            Rule::WrapperCoverage,
            DLQAUTHMINT_CRATE,
            "dlqauthmint 必须是 `crates/dlqauthmint` 的 isolated Basis workspace member",
        ));
        return findings;
    }
    for (name, path, layer) in [
        ("diport", "crates/diport", Layer::DiPort),
        ("runtime", "assemblies/runtime", Layer::Root),
    ] {
        if !members
            .iter()
            .any(|member| member.name == name && member.path == path && member.layer == Some(layer))
        {
            findings.push(finding(
                Rule::WrapperCoverage,
                DLQAUTHMINT_CRATE,
                format!("dlqauthmint 批准消费者 `{name}` 的 path/layer 不精确"),
            ));
        }
    }
    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            DLQAUTHMINT_CRATE,
            "deny.toml 缺 dlqauthmint target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = DLQAUTHMINT_ALLOWED_WRAPPERS.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    DLQAUTHMINT_CRATE,
                    format!(
                        "dlqauthmint wrapper 必须与批准消费者集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// The HTTP request-id mint is an isolated Basis capability. Only the transport owner may mint
/// it, and generated response factories may consume it; domains and composition roots stay out.
///
/// INVARIANT: HTTP-REQUEST-ID-AUTHORITY-01 { level = "Hard", exec = "native-compile", source = "code", native = "opaque carrier + exact wrapper allowlist" }
pub(crate) fn check_requestidmint_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members
        .iter()
        .find(|member| member.name == REQUESTIDMINT_CRATE);
    let ban = bans
        .iter()
        .find(|entry| entry.crate_name == REQUESTIDMINT_CRATE);
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|member| member.layer), Some(Some(Layer::Basis)))
        || target.is_some_and(|member| member.path != "crates/requestidmint")
    {
        findings.push(finding(
            Rule::WrapperCoverage,
            REQUESTIDMINT_CRATE,
            "requestidmint 必须是 `crates/requestidmint` 的 isolated Basis workspace member",
        ));
        return findings;
    }
    for (name, path, layer) in [
        ("httpserve", "crates/httpserve", Layer::Service),
        ("generated", "generated", Layer::Generated),
    ] {
        if !members
            .iter()
            .any(|member| member.name == name && member.path == path && member.layer == Some(layer))
        {
            findings.push(finding(
                Rule::WrapperCoverage,
                REQUESTIDMINT_CRATE,
                format!("requestidmint 批准消费者 `{name}` 的 path/layer 不精确"),
            ));
        }
    }
    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            REQUESTIDMINT_CRATE,
            "deny.toml 缺 requestidmint target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = REQUESTIDMINT_ALLOWED_WRAPPERS.iter().copied().collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    REQUESTIDMINT_CRATE,
                    format!(
                        "requestidmint wrapper 必须与批准消费者集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// Runtime inventory observations require an opaque mint token that assembly roots cannot name.
pub(crate) fn check_runtimeinventorymint_wrapper_coverage(
    members: &[Member],
    bans: &[BanEntry],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let target = members
        .iter()
        .find(|member| member.name == RUNTIMEINVENTORYMINT_CRATE);
    let ban = bans
        .iter()
        .find(|entry| entry.crate_name == RUNTIMEINVENTORYMINT_CRATE);
    if target.is_none() && ban.is_none() {
        return findings;
    }
    if !matches!(target.map(|member| member.layer), Some(Some(Layer::Basis)))
        || target.is_some_and(|member| member.path != "crates/runtimeinventorymint")
    {
        findings.push(finding(
            Rule::WrapperCoverage,
            RUNTIMEINVENTORYMINT_CRATE,
            "runtimeinventorymint 必须是 `crates/runtimeinventorymint` 的 Basis workspace member",
        ));
        return findings;
    }
    for (name, path, layer) in [
        ("assembly-schema", "crates/assembly-schema", Layer::Basis),
        ("runtimeexec", "crates/runtimeexec", Layer::RuntimeExec),
        ("runtime", "assemblies/runtime", Layer::Root),
    ] {
        if !members
            .iter()
            .any(|member| member.name == name && member.path == path && member.layer == Some(layer))
        {
            findings.push(finding(
                Rule::WrapperCoverage,
                RUNTIMEINVENTORYMINT_CRATE,
                format!("runtimeinventorymint 批准消费者 `{name}` 的 path/layer 不精确"),
            ));
        }
    }
    match ban {
        None => findings.push(finding(
            Rule::WrapperCoverage,
            RUNTIMEINVENTORYMINT_CRATE,
            "deny.toml 缺 runtimeinventorymint target wrapper",
        )),
        Some(ban) => {
            let have: BTreeSet<&str> = ban.wrappers.iter().map(String::as_str).collect();
            let want: BTreeSet<&str> = RUNTIMEINVENTORYMINT_ALLOWED_WRAPPERS
                .iter()
                .copied()
                .collect();
            if have != want {
                let extra: Vec<&str> = have.difference(&want).copied().collect();
                let missing: Vec<&str> = want.difference(&have).copied().collect();
                findings.push(finding(
                    Rule::WrapperCoverage,
                    RUNTIMEINVENTORYMINT_CRATE,
                    format!(
                        "runtimeinventorymint wrapper 必须与批准消费者集合相等：多列 {extra:?} / 欠列 {missing:?}"
                    ),
                ));
            }
        }
    }
    findings
}

/// 外部 crate 收敛 wrapper 校验（DIPORT-MACRO-CONFINE-02）——与分层 wrapper（[`check_wrappers`]）正交：
/// 目标是**外部** crate（不在 workspace 成员集）。委托 [`check_confinement_against`]（生产用真实
/// [`EXTERNAL_CONFINEMENT_WRAPPERS`]）。
pub(crate) fn check_external_confinement(members: &[Member], bans: &[BanEntry]) -> Vec<Finding> {
    check_confinement_against(EXTERNAL_CONFINEMENT_WRAPPERS, members, bans)
}

/// INVARIANT: WORKSPACEFACTS-CONFINEMENT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "workspacefacts_confinement_rejects_widening_and_missing_edges|workspacefacts_confinement_rejects_actual_workspace_consumer_with_exact_wrappers|workspacefacts_confinement_rejects_direct_guppy_consumer_with_exact_wrappers|workspacefacts_confinement_rejects_noncanonical_xtask_path", anti_vacuity = "workspacefacts_confinement_exact_green|real_workspace_green" }
/// ——唯一合法链路为 `xtask → workspacefacts → guppy`。Cargo graph/visibility 是 Hard 基线，
/// deny wrappers 与 source edge anti-vacuity 防止未来 manifest 绕过 façade 或把 tooling crate 引入生产层。
pub(crate) fn check_workspacefacts_confinement(
    members: &[Member],
    bans: &[BanEntry],
    edges: &[Edge],
    deps: &[ShippedDep],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let workspacefacts_valid = members.iter().any(|member| {
        member.name == WORKSPACEFACTS_CRATE
            && member.path == "crates/workspacefacts"
            && member.layer == Some(Layer::Tooling)
    });
    let xtask_valid = members.iter().any(|member| {
        member.name == WORKSPACEFACTS_CONSUMER
            && member.path == "xtask"
            && member.layer == Some(Layer::Root)
    });
    if !workspacefacts_valid || !xtask_valid {
        findings.push(finding(
            Rule::WorkspaceFactsConfinement,
            WORKSPACEFACTS_CRATE,
            "workspacefacts 必须是 crates/workspacefacts 的 Tooling 成员，且 xtask 必须是 path=xtask 的 Root consumer",
        ));
    }

    for (target, expected) in [
        (WORKSPACEFACTS_CRATE, WORKSPACEFACTS_CONSUMER),
        (GUPPY_CRATE, WORKSPACEFACTS_CRATE),
    ] {
        let have = bans
            .iter()
            .find(|ban| ban.crate_name == target)
            .map(|ban| {
                ban.wrappers
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if have != BTreeSet::from([expected]) {
            findings.push(finding(
                Rule::WorkspaceFactsConfinement,
                target,
                format!("deny wrapper 必须精确为 `{target}` ← [`{expected}`]，实际 {have:?}"),
            ));
        }
    }

    let workspace_consumers = edges
        .iter()
        .filter(|edge| edge.to == WORKSPACEFACTS_CRATE)
        .map(|edge| edge.from.as_str())
        .collect::<BTreeSet<_>>();
    let expected_workspace_consumers = BTreeSet::from([WORKSPACEFACTS_CONSUMER]);
    if workspace_consumers != expected_workspace_consumers {
        findings.push(finding(
            Rule::WorkspaceFactsConfinement,
            WORKSPACEFACTS_CRATE,
            format!(
                "workspacefacts 实际 shipped workspace consumers 必须精确为 {expected_workspace_consumers:?}，实际 {workspace_consumers:?}"
            ),
        ));
    }

    let guppy_consumers = deps
        .iter()
        .filter(|dep| dep.package_name == GUPPY_CRATE && !dep.is_workspace_internal)
        .map(|dep| dep.from.as_str())
        .collect::<BTreeSet<_>>();
    let expected_guppy_consumers = BTreeSet::from([WORKSPACEFACTS_CRATE]);
    if guppy_consumers != expected_guppy_consumers {
        findings.push(finding(
            Rule::WorkspaceFactsConfinement,
            GUPPY_CRATE,
            format!(
                "guppy 实际 direct shipped consumers 必须精确为 {expected_guppy_consumers:?}，实际 {guppy_consumers:?}"
            ),
        ));
    }
    findings
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

/// LAYER-DEPS-10：test-support 库的 shipped 出边不得指向 workspace 内部成员。
///
/// [`Edge`] 只表示已解析的 workspace 内部 shipped 边，因此只需按 source 精确筛选
/// [`layers::TEST_SUPPORT_CRATES`]；外部依赖不会进入 `edges`，`[dev-dependencies]` 也不在扫描范围。
/// 该规则只约束 test-support 的**出边**，不复用或放宽 LAYER-DEPS-08 的入边检查。
pub(crate) fn check_test_support_internal_dependencies(edges: &[Edge]) -> Vec<Finding> {
    edges
        .iter()
        .filter(|edge| layers::is_test_support(&edge.from))
        .map(|edge| {
            finding(
                Rule::TestSupportInternalShipped,
                edge.from.clone(),
                format!(
                    "{} {}.{} → `{}`：test-support 库只准依赖外部 crate，禁止 shipped workspace 内部依赖（INVARIANT LAYER-DEPS-10）",
                    edge.from_manifest, edge.section, edge.key, edge.to
                ),
            )
        })
        .collect()
}

/// shipped 依赖表禁止启用的 scoped-construction test feature（LAYER-DEPS-09 守卫常量）。
const SHIPPED_TEST_SUPPORT_FEATURE_BANS: &[(&str, &str, &str)] = &[
    (
        "generated",
        "test-support",
        "sealed test-only contract definitions and catalogs must stay outside every shipped feature closure",
    ),
    (
        "assembly-schema",
        "test-support",
        "repository contract fixture construction must stay outside every shipped feature closure",
    ),
    (
        "runctx",
        "test-support",
        "constructing AppCtx via runctx::test_support bypasses PrincipalFacet minting",
    ),
    (
        "identity",
        "test-support",
        "identity::ports::TenantRepoScope::for_test bypasses authenticated tenant scope minting",
    ),
    (
        "settings",
        "test-support",
        "settings::ports::TenantRepoScope::for_test bypasses authenticated tenant scope minting",
    ),
    (
        "audit",
        "test-support",
        "audit::ports::TenantRepoScope::for_test bypasses authenticated tenant scope minting",
    ),
    (
        "bootstrap",
        "test-support",
        "SubscriberBinding::forge_topology_for_test forges event topology; must stay [dev-dependencies]-only",
    ),
    (
        "eventexec",
        "test-support",
        "Projection conformance fixtures mint source and operator authority outside the generated production registry",
    ),
    (
        "identity-composition",
        "test-support",
        "pause_receipt_relay_for_test and pause_ingress_for_test expose pilot loop pause controls; must stay [dev-dependencies]-only",
    ),
    (
        "deviceidentity",
        "test-support",
        "pause_receipt_relay_for_test and pause_ingress_for_test expose assembly pilot loop pause controls; must stay [dev-dependencies]-only",
    ),
    (
        "mqtt",
        "test-support",
        "MqttSession::uplink_queue_is_saturated_for_test exposes adapter-private queue saturation; must stay [dev-dependencies]-only",
    ),
    (
        "diport",
        "dlq-test-support",
        "DLQ authorization test mint bypasses the production runtime mint funnel",
    ),
];

/// 一条 **shipped**（非 dev）依赖表条目的 feature 视图——供依赖 allowlist 与 feature 单测扫描。
/// `[dev-dependencies]` 不入（[`MemberManifest`] 刻意不解析 dev 表），故收集到的均为 shipped。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShippedDep {
    /// 声明该依赖的成员 crate 名。
    pub(crate) from: String,
    /// 该成员 manifest 相对路径（finding 定位用）。
    pub(crate) manifest_file: String,
    /// 依赖表 section（`[dependencies]` / `[build-dependencies]` / `[target.<cfg>.…]`）。
    pub(crate) section: String,
    /// manifest 中书写的依赖 key。
    pub(crate) key: String,
    /// Cargo 解析后的真实 package identity；`package` rename 与根 `[workspace.dependencies]`
    /// 继承均已展开。外部闭包必须看该字段，不能信任可任意命名的 manifest key。
    pub(crate) package_name: String,
    /// 该依赖启用的 feature 列表。
    pub(crate) features: Vec<String>,
    /// 是否解析为 workspace 内部 path dependency。`false` 表示外部依赖。
    pub(crate) is_workspace_internal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeatureNode {
    package_name: String,
    feature: String,
}

impl FeatureNode {
    fn new(package_name: impl Into<String>, feature: impl Into<String>) -> Self {
        Self {
            package_name: package_name.into(),
            feature: feature.into(),
        }
    }

    fn label(&self) -> String {
        format!("{}/{}", self.package_name, self.feature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeatureOrigin {
    from: String,
    manifest_file: String,
    section: String,
    key: String,
}

#[derive(Debug, Clone)]
struct FeatureDependency {
    section: String,
    key: String,
    package_name: String,
    features: Vec<String>,
    default_features: bool,
    optional: bool,
}

#[derive(Debug, Clone)]
struct FeatureStep {
    node: FeatureNode,
    label: String,
}

impl FeatureStep {
    fn direct(node: FeatureNode) -> Self {
        let label = node.label();
        Self { node, label }
    }
}

#[derive(Debug)]
struct FeatureGraph {
    origins: BTreeMap<FeatureOrigin, Vec<FeatureStep>>,
    edges: BTreeMap<FeatureNode, Vec<FeatureStep>>,
}

fn test_support_feature_ban(package_name: &str, feature: &str) -> Option<&'static str> {
    SHIPPED_TEST_SUPPORT_FEATURE_BANS
        .iter()
        .find_map(|(banned, banned_feature, reason)| {
            (*banned == package_name && *banned_feature == feature).then_some(*reason)
        })
}

/// LAYER-DEPS-09 纯扫描：flag 任一 shipped 依赖表里 scoped-construction crate 启用 `test-support` feature 的条目。
///
/// 这些 feature 只准 `[dev-dependencies]` 启用（dev 边不进生产 artifact，resolver 2 下 dev-dep feature 不
/// unify 进 normal build）。纯函数（输入 `&[ShippedDep]`）便于 synthetic 红/绿单测。
#[cfg(test)]
pub(crate) fn scan_shipped_testsupport_features(deps: &[ShippedDep]) -> Vec<Finding> {
    deps.iter()
        .filter_map(|d| {
            d.features
                .iter()
                .find_map(|feature| {
                    test_support_feature_ban(&d.package_name, feature).map(|reason| (feature, reason))
                })
                .map(|(feature, reason)| (d, feature, reason))
        })
        .map(|(d, feature, reason)| {
            finding(
                Rule::TestSupportFeatureShipped,
                d.from.clone(),
                format!(
                    "{} {}.{}（package `{}`）启用 `{}/{}` ⇒ {reason}；只准 [dev-dependencies] 启用该 feature（INVARIANT LAYER-DEPS-09；改放 [dev-dependencies]）",
                    d.manifest_file, d.section, d.key,
                    d.package_name,
                    d.package_name,
                    feature,
                ),
            )
        })
        .collect()
}

/// LAYER-DEPS-09 closure scan：从每个成员的 root `default` 与全部 shipped dependency
/// feature activation 出发，沿 Cargo 本地 feature forwarding 图跑到不动点。图遍历按 origin
/// 隔离并用 `(package, feature)` visited set 终止合法环；环内的全部出边仍会被检查，不能借环绕过。
fn scan_workspace_testsupport_features(
    root: &Path,
    members: &[Member],
    ws_deps: &BTreeMap<String, DepSpec>,
) -> Result<Vec<Finding>> {
    let FeatureGraph { origins, edges } = load_feature_graph(root, members, ws_deps)?;
    Ok(origins
        .into_iter()
        .filter_map(|(origin, seeds)| {
            first_banned_feature_path(&edges, seeds).map(|(node, path, reason)| {
                finding(
                    Rule::TestSupportFeatureShipped,
                    origin.from,
                    format!(
                        "{} {}.{} 的 shipped feature 闭包 `{}` ⇒ {reason}；`{}` 只准 [dev-dependencies] 启用（INVARIANT LAYER-DEPS-09）",
                        origin.manifest_file,
                        origin.section,
                        origin.key,
                        path.join(" → "),
                        node.label(),
                    ),
                )
            })
        })
        .collect())
}

fn load_feature_graph(
    root: &Path,
    members: &[Member],
    ws_deps: &BTreeMap<String, DepSpec>,
) -> Result<FeatureGraph> {
    let mut graph = FeatureGraph {
        origins: BTreeMap::new(),
        edges: BTreeMap::new(),
    };
    for member in members {
        let manifest = read_member_manifest(root, &member.path)?;
        let dependencies = feature_dependencies(&manifest, ws_deps);
        let manifest_file = format!("{}/Cargo.toml", member.path);
        add_feature_origins(
            &mut graph.origins,
            &member.name,
            &manifest_file,
            &manifest.features,
            &dependencies,
        );
        add_feature_edges(
            &mut graph.edges,
            &member.name,
            &manifest.features,
            &dependencies,
        );
    }
    Ok(graph)
}

fn feature_dependencies(
    manifest: &MemberManifest,
    ws_deps: &BTreeMap<String, DepSpec>,
) -> BTreeMap<String, Vec<FeatureDependency>> {
    let mut dependencies: BTreeMap<String, Vec<FeatureDependency>> = BTreeMap::new();
    for (section, key, spec) in manifest.dep_entries() {
        dependencies
            .entry(key.to_string())
            .or_default()
            .push(FeatureDependency {
                section,
                key: key.to_string(),
                package_name: dependency_package_name(key, spec, ws_deps).to_string(),
                features: dependency_features(key, spec, ws_deps),
                default_features: dependency_uses_default_features(key, spec, ws_deps),
                optional: dependency_is_optional(key, spec, ws_deps),
            });
    }
    dependencies
}

fn add_feature_origins(
    origins: &mut BTreeMap<FeatureOrigin, Vec<FeatureStep>>,
    package_name: &str,
    manifest_file: &str,
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &BTreeMap<String, Vec<FeatureDependency>>,
) {
    if features.contains_key("default") {
        origins.insert(
            FeatureOrigin {
                from: package_name.to_string(),
                manifest_file: manifest_file.to_string(),
                section: "[features]".to_string(),
                key: "default".to_string(),
            },
            vec![FeatureStep::direct(FeatureNode::new(
                package_name,
                "default",
            ))],
        );
    }
    for dependency in dependencies.values().flatten() {
        let origin = FeatureOrigin {
            from: package_name.to_string(),
            manifest_file: manifest_file.to_string(),
            section: dependency.section.clone(),
            key: dependency.key.clone(),
        };
        let seeds = origins.entry(origin).or_default();
        seeds.extend(dependency.features.iter().map(|feature| {
            FeatureStep::direct(FeatureNode::new(&dependency.package_name, feature))
        }));
        if !dependency.optional && dependency.default_features {
            seeds.push(FeatureStep::direct(FeatureNode::new(
                &dependency.package_name,
                "default",
            )));
        }
    }
}

fn add_feature_edges(
    edges: &mut BTreeMap<FeatureNode, Vec<FeatureStep>>,
    package_name: &str,
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &BTreeMap<String, Vec<FeatureDependency>>,
) {
    for (feature, forwarded) in features {
        let from = FeatureNode::new(package_name, feature);
        let targets = edges.entry(from).or_default();
        for token in forwarded {
            targets.extend(expand_feature_token(
                package_name,
                token,
                features,
                dependencies,
            ));
        }
    }
}

fn expand_feature_token(
    owner_package: &str,
    token: &str,
    local_features: &BTreeMap<String, Vec<String>>,
    dependencies: &BTreeMap<String, Vec<FeatureDependency>>,
) -> Vec<FeatureStep> {
    if let Some(dependency_key) = token.strip_prefix("dep:") {
        return dependency_activation_steps(owner_package, dependency_key, token, dependencies);
    }
    if let Some((dependency_key, feature)) = token.split_once('/') {
        let weak = dependency_key.ends_with('?');
        let dependency_key = dependency_key.strip_suffix('?').unwrap_or(dependency_key);
        let mut steps = if weak {
            Vec::new()
        } else {
            dependency_activation_steps(owner_package, dependency_key, token, dependencies)
        };
        steps.extend(dependency_feature_steps(
            owner_package,
            dependency_key,
            feature,
            token,
            dependencies,
        ));
        return steps;
    }
    if local_features.contains_key(token) {
        return vec![FeatureStep::direct(FeatureNode::new(owner_package, token))];
    }
    dependency_activation_steps(owner_package, token, token, dependencies)
}

fn dependency_activation_steps(
    owner_package: &str,
    dependency_key: &str,
    token: &str,
    dependencies: &BTreeMap<String, Vec<FeatureDependency>>,
) -> Vec<FeatureStep> {
    dependencies
        .get(dependency_key)
        .into_iter()
        .flatten()
        .flat_map(|dependency| {
            let mut features = dependency.features.clone();
            if dependency.default_features {
                features.push("default".to_string());
            }
            features.into_iter().map(|feature| FeatureStep {
                node: FeatureNode::new(&dependency.package_name, &feature),
                label: format!(
                    "{owner_package}/{token} → {}/{feature}",
                    dependency.package_name
                ),
            })
        })
        .collect()
}

fn dependency_feature_steps(
    owner_package: &str,
    dependency_key: &str,
    feature: &str,
    token: &str,
    dependencies: &BTreeMap<String, Vec<FeatureDependency>>,
) -> Vec<FeatureStep> {
    dependencies
        .get(dependency_key)
        .into_iter()
        .flatten()
        .map(|dependency| FeatureStep {
            node: FeatureNode::new(&dependency.package_name, feature),
            label: format!(
                "{owner_package}/{token} → {}/{feature}",
                dependency.package_name
            ),
        })
        .collect()
}

fn first_banned_feature_path(
    edges: &BTreeMap<FeatureNode, Vec<FeatureStep>>,
    seeds: Vec<FeatureStep>,
) -> Option<(FeatureNode, Vec<String>, &'static str)> {
    let mut queue: VecDeque<(FeatureNode, Vec<String>)> = seeds
        .into_iter()
        .map(|step| (step.node, vec![step.label]))
        .collect();
    let mut visited = BTreeSet::new();
    while let Some((node, path)) = queue.pop_front() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if let Some(reason) = test_support_feature_ban(&node.package_name, &node.feature) {
            return Some((node, path, reason));
        }
        for step in edges.get(&node).into_iter().flatten() {
            let mut next_path = path.clone();
            next_path.push(step.label.clone());
            queue.push_back((step.node.clone(), next_path));
        }
    }
    None
}

/// 读各成员全部 shipped 依赖表（`dep_entries`），收集每条依赖的 feature 与内/外部视图（[`ShippedDep`]）。
/// dev-dependencies 不入（[`MemberManifest`] 不解析 dev 表），故天然只覆盖 shipped 表。
fn collect_shipped_deps(
    root: &Path,
    members: &[Member],
    ws_deps: &BTreeMap<String, DepSpec>,
) -> Result<Vec<ShippedDep>> {
    let mut out = Vec::new();
    for m in members {
        let manifest = read_member_manifest(root, &m.path)?;
        let manifest_file = format!("{}/Cargo.toml", m.path);
        for (section, key, spec) in manifest.dep_entries() {
            let features = dependency_features(key, spec, ws_deps);
            out.push(ShippedDep {
                from: m.name.clone(),
                manifest_file: manifest_file.clone(),
                section,
                key: key.to_string(),
                package_name: dependency_package_name(key, spec, ws_deps).to_string(),
                features,
                is_workspace_internal: !matches!(
                    classify_dep(&m.path, key, spec, ws_deps),
                    DepTarget::External
                ),
            });
        }
    }
    Ok(out)
}

/// RuntimeExec direct shipped dependency 闭包：内部看解析后的 package edge，外部看 Cargo 展开
/// `package` rename / workspace dependency 继承后的真实 package identity。
/// dev-dependency 不进入 `Edge` / `ShippedDep`，因此测试依赖不受本规则约束。
pub(crate) fn check_runtimeexec_direct_dependencies(
    edges: &[Edge],
    deps: &[ShippedDep],
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = edges
        .iter()
        .filter(|edge| {
            edge.from == RUNTIMEEXEC_CRATE
                && !RUNTIMEEXEC_INTERNAL_SHIPPED_DEPS.contains(&edge.to.as_str())
        })
        .map(|edge| {
            finding(
                Rule::RuntimeExecDependencyScope,
                RUNTIMEEXEC_CRATE,
                format!(
                    "{} {}.{} → `{}`：runtimeexec 内部 shipped direct dependency 只准 {:?}",
                    edge.from_manifest,
                    edge.section,
                    edge.key,
                    edge.to,
                    RUNTIMEEXEC_INTERNAL_SHIPPED_DEPS
                ),
            )
        })
        .collect();

    findings.extend(
        deps.iter()
            .filter(|dep| {
                dep.from == RUNTIMEEXEC_CRATE
                    && !dep.is_workspace_internal
                    && !RUNTIMEEXEC_EXTERNAL_SHIPPED_DEPS.contains(&dep.package_name.as_str())
            })
            .map(|dep| {
                finding(
                    Rule::RuntimeExecDependencyScope,
                    RUNTIMEEXEC_CRATE,
                    format!(
                        "{} {}.{} → `{}`：runtimeexec 外部 shipped direct dependency 只准 {:?}",
                        dep.manifest_file,
                        dep.section,
                        dep.key,
                        dep.package_name,
                        RUNTIMEEXEC_EXTERNAL_SHIPPED_DEPS
                    ),
                )
            }),
    );
    findings
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

/// 单个外部收敛 entry 的双向 fail-closed 校验（DIPORT-MACRO-CONFINE-02）：
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
    /// Cargo local feature graph. LAYER-DEPS-09 resolves this graph from shipped activation
    /// roots so a harmless-looking feature name cannot forward into a scoped `test-support` seam.
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
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
    /// Cargo dependency rename 的真实 package 名（`alias = { package = "real", ... }`）。
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    workspace: bool,
    /// `None` preserves Cargo's default (`true`) and lets workspace inheritance merge fail closed.
    #[serde(default, rename = "default-features")]
    default_features: Option<bool>,
    #[serde(default)]
    optional: bool,
    /// 该依赖启用的 feature 列表（LAYER-DEPS-09：守 scoped construction `test-support` 不进 shipped 依赖表）。
    #[serde(default)]
    features: Vec<String>,
}

/// 返回 Cargo 使用的真实 package identity，而不是 manifest 中可任意选择的 dependency key。
/// `workspace = true` 时 package rename 归根 `[workspace.dependencies]` 所有，必须继续展开；
/// 缺少 rename 时 package 名才等于当前 key。
fn dependency_package_name<'a>(
    key: &'a str,
    spec: &'a DepSpec,
    ws_deps: &'a BTreeMap<String, DepSpec>,
) -> &'a str {
    let DepSpec::Detailed(dep) = spec else {
        return key;
    };
    if let Some(package) = dep.package.as_deref() {
        return package;
    }
    if dep.workspace
        && let Some(DepSpec::Detailed(workspace_dep)) = ws_deps.get(key)
        && let Some(package) = workspace_dep.package.as_deref()
    {
        return package;
    }
    key
}

/// Resolve the effective feature set using Cargo's workspace-inheritance merge semantics.
/// A member may add features beside `workspace = true`; inherited and local features are both
/// shipped and therefore both participate in LAYER-DEPS-09.
fn dependency_features(
    key: &str,
    spec: &DepSpec,
    ws_deps: &BTreeMap<String, DepSpec>,
) -> Vec<String> {
    let DepSpec::Detailed(dep) = spec else {
        return Vec::new();
    };
    let mut features = BTreeSet::new();
    if dep.workspace
        && let Some(DepSpec::Detailed(workspace_dep)) = ws_deps.get(key)
    {
        features.extend(workspace_dep.features.iter().cloned());
    }
    features.extend(dep.features.iter().cloned());
    features.into_iter().collect()
}

fn dependency_uses_default_features(
    key: &str,
    spec: &DepSpec,
    ws_deps: &BTreeMap<String, DepSpec>,
) -> bool {
    let DepSpec::Detailed(dep) = spec else {
        return true;
    };
    let inherited = if dep.workspace {
        ws_deps
            .get(key)
            .and_then(detailed_dep)
            .and_then(|workspace_dep| workspace_dep.default_features)
            .unwrap_or(true)
    } else {
        true
    };
    inherited && dep.default_features.unwrap_or(true)
}

fn dependency_is_optional(key: &str, spec: &DepSpec, ws_deps: &BTreeMap<String, DepSpec>) -> bool {
    let DepSpec::Detailed(dep) = spec else {
        return false;
    };
    dep.optional
        || (dep.workspace
            && ws_deps
                .get(key)
                .and_then(detailed_dep)
                .is_some_and(|workspace_dep| workspace_dep.optional))
}

fn detailed_dep(spec: &DepSpec) -> Option<&DetailedDep> {
    match spec {
        DepSpec::Detailed(dep) => Some(dep),
        DepSpec::Version(_) => None,
    }
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
    fn bootstrap_generated_registrar_surface_accepts_exact_vocabulary() {
        let findings = scan_bootstrap_generated_surface(
            Path::new("crates/bootstrap/src/registry.rs"),
            r#"
            impl generated::event::EventSubscribe for Registry {
                type Capability = Capability;
                type Output = Result<(), Error>;

                fn subscribe<S: generated::event::EventSubscription>(
                    &mut self,
                    capability: Self::Capability,
                ) -> Self::Output {
                    use generated::event::{
                        EventContract, SubscriptionEffect, SubscriptionExecution,
                    };
                    todo!()
                }
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn bootstrap_generated_registrar_surface_rejects_non_registrar_matrix() {
        for source in [
            "fn bad<T: generated::event::EventEmit>() {}",
            "fn bad<T: ::generated::event::EventEmit>() {}",
            "fn bad<T: generated::command::CommandJournal>() {}",
            "fn bad() { let _ = generated::event::EVENTS; }",
            "use generated::event::identity_v1::session_created;",
            "use generated::event::*;",
            "use generated as generated_api;",
            "use generated::command as generated_command;",
        ] {
            let findings = scan_bootstrap_generated_surface(
                Path::new("crates/bootstrap/src/registry.rs"),
                source,
            );
            assert_eq!(
                findings.len(),
                1,
                "source must fail closed: {source}\n{findings:#?}"
            );
            assert_eq!(findings[0].rule, Rule::GeneratedBootstrapSurface);
        }
    }

    #[test]
    fn bootstrap_generated_registrar_surface_ignores_test_only_wrappers() {
        let findings = scan_bootstrap_generated_surface(
            Path::new("crates/bootstrap/src/registry.rs"),
            r#"
            #[cfg(test)]
            mod tests {
                fn fixture() {
                    generated::event::identity_v1::session_created::subscribe_audit();
                }
            }

            #[cfg(any(test, unix))]
            fn also_test_gated() {
                generated::event::identity_v1::session_created::subscribe_audit();
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:#?}");
    }

    /// 红：`feature = "test-support"` 不是 `cfg(test)`——不得被 `has_test_attr` 误跳过。
    #[test]
    fn bootstrap_generated_registrar_surface_scans_test_support_feature_cfg() {
        let findings = scan_bootstrap_generated_surface(
            Path::new("crates/bootstrap/src/registry.rs"),
            r#"
            #[cfg(feature = "test-support")]
            fn forge_helper() {
                generated::event::identity_v1::session_created::subscribe_audit();
            }
            "#,
        );
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule, Rule::GeneratedBootstrapSurface);
    }

    /// RUNTIMEEXEC-LAYER-01 anti-vacuity：assembly Root 可消费 runtimeexec，runtimeexec 可向批准下层出边。
    #[test]
    fn check_layers_green_runtimeexec_allowed_inbound_and_outbound() {
        let members = vec![
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
            m(
                "runtimeexec",
                "crates/runtimeexec",
                Some(Layer::RuntimeExec),
            ),
            m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
        ];
        let edges = vec![
            e("runtime", "runtimeexec"),
            e("runtimeexec", "bootstrap"),
            e("runtimeexec", "diport"),
        ];
        assert!(check_layers(&members, &edges).is_empty());
    }

    /// RUNTIMEEXEC-LAYER-01 synthetic red：RuntimeExec 不得取得域/adapter，非 Root 也不得消费 RuntimeExec。
    #[test]
    fn check_layers_red_runtimeexec_illegal_inbound_and_outbound() {
        let members = vec![
            m(
                "runtimeexec",
                "crates/runtimeexec",
                Some(Layer::RuntimeExec),
            ),
            m("identity", "crates/identity", Some(Layer::Domain)),
            m("httpd", "adapters/httpd", Some(Layer::Adapter)),
            m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
        ];
        let findings = check_layers(
            &members,
            &[
                e("runtimeexec", "identity"),
                e("runtimeexec", "httpd"),
                e("bootstrap", "runtimeexec"),
            ],
        );
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::BackPath)
                .count(),
            2
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::AdapterScope)
                .count(),
            1
        );
    }

    /// LAYER-DEPS-08 anti-vacuity（绿）：test-support 仅经 dev-dep 消费 ⇒ shipped `edges` 无指向它们的边。
    #[test]
    fn check_test_support_confinement_green_no_shipped_edge() {
        // identity→testkit、httpd→tracewiretest 与 journeys→iotdevice 均为 dev-dep，不入 shipped edges。
        let edges = vec![e("identity", "httpserve"), e("identity", "generated")];
        assert!(check_test_support_confinement(&edges).is_empty());
    }

    /// LAYER-DEPS-08（红）：任一 test-support crate 进入 shipped 依赖 ⇒ flagged。
    #[test]
    fn check_test_support_confinement_red_shipped_dep() {
        let findings = check_test_support_confinement(&[
            e("identity", "testkit"),
            e("httpd", "tracewiretest"),
            e("deviceidentity", "iotdevice"),
        ]);
        assert_eq!(findings.len(), 3, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::TestSupportShipped),
            "{findings:?}"
        );
    }

    /// LAYER-DEPS-10（红）：test-support 的任意 shipped workspace 内部出边均被拒绝。
    #[test]
    fn test_support_internal_dependencies_red_shipped_edges() {
        let findings = check_test_support_internal_dependencies(&[
            e("testkit", "vocab"),
            e("testkit", "consistency"),
            e("tracewiretest", "tracewire"),
            e("iotdevice", "mqtt"),
        ]);
        assert_eq!(findings.len(), 4, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::TestSupportInternalShipped),
            "{findings:?}"
        );
    }

    /// LAYER-DEPS-10 specificity：非 test-support 的内部出边不属于本规则。
    #[test]
    fn test_support_internal_dependencies_green_non_test_support_source() {
        let findings = check_test_support_internal_dependencies(&[
            e("identity", "vocab"),
            e("httpserve", "consistency"),
        ]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// LAYER-DEPS-10 anti-vacuity：无 shipped 出边时不误报；dev-dep 本来就不进入 `edges`。
    #[test]
    fn test_support_internal_dependencies_green_no_shipped_edge() {
        assert!(check_test_support_internal_dependencies(&[]).is_empty());
    }

    // ---- LAYER-DEPS-09：scoped construction 的 test-support feature 进 shipped 依赖表 ----

    fn sdep(from: &str, section: &str, key: &str, features: &[&str]) -> ShippedDep {
        ShippedDep {
            from: from.to_string(),
            manifest_file: format!("crates/{from}/Cargo.toml"),
            section: section.to_string(),
            key: key.to_string(),
            package_name: key.to_string(),
            features: features.iter().map(|f| (*f).to_string()).collect(),
            is_workspace_internal: false,
        }
    }

    /// 红：`[dependencies]` 启用 `runctx/test-support` ⇒ TestSupportFeatureShipped。
    #[test]
    fn red_runctx_testsupport_in_dependencies() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "badcrate",
            "[dependencies]",
            "runctx",
            &["test-support"],
        )]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::TestSupportFeatureShipped);
        assert_eq!(findings[0].subject, "badcrate");
    }

    #[test]
    fn red_testsupport_features_follow_direct_and_workspace_package_aliases() -> Result<()> {
        let root = crate::testutil::unique_tmp("testsupport-feature-package-alias-red");
        let manifest_path = root.join("crates/badcrate/Cargo.toml");
        std::fs::create_dir_all(manifest_path.parent().context("badcrate manifest parent")?)?;
        std::fs::write(
            &manifest_path,
            r#"
[package]
name = "badcrate"

[dependencies]
ctx_alias = { package = "runctx", version = "1", features = ["test-support"] }
identity_alias = { workspace = true }
relay_alias = { package = "identity-composition", version = "1", features = ["test-support"] }
deviceidentity = { workspace = true }
"#,
        )?;
        let members = [m("badcrate", "crates/badcrate", Some(Layer::Root))];
        let workspace_dependencies: BTreeMap<String, DepSpec> = toml::from_str::<RootManifest>(
            r#"
[workspace]
members = []

[workspace.dependencies]
identity_alias = { package = "identity", version = "1", features = ["test-support"] }
deviceidentity = { version = "1", features = ["test-support"] }
"#,
        )?
        .workspace
        .dependencies;

        let deps = collect_shipped_deps(&root, &members, &workspace_dependencies)?;
        let findings = scan_shipped_testsupport_features(&deps);
        assert_eq!(findings.len(), 4, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("ctx_alias"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("identity_alias"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("relay_alias"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("deviceidentity"))
        );
        Ok(())
    }

    /// LAYER-DEPS-09 synthetic red：依赖条目只启用无害的本地 feature 名时，仍须沿
    /// `default` / local forwarding / package alias / dependency-feature 递归到真正的
    /// `identity-composition/test-support`；本地 feature 环不能让遍历提前静默放行。
    #[test]
    fn red_testsupport_feature_closure_follows_default_alias_recursion_and_cycle() -> Result<()> {
        let root = crate::testutil::unique_tmp("testsupport-feature-closure-red");
        let manifests = [
            (
                "crates/identity-composition/Cargo.toml",
                r#"
[package]
name = "identity-composition"

[features]
default = []
test-support = []
"#,
            ),
            (
                "crates/feature-bridge/Cargo.toml",
                r#"
[package]
name = "feature-bridge"

[features]
default = ["relay-control"]
relay-control = ["cycle-a"]
cycle-a = ["cycle-b"]
cycle-b = ["cycle-a", "relay_alias/test-support"]

[dependencies]
relay_alias = { package = "identity-composition", path = "../identity-composition", default-features = false }
"#,
            ),
            (
                "crates/consumer/Cargo.toml",
                r#"
[package]
name = "consumer"

[dependencies]
bridge_alias = { package = "feature-bridge", path = "../feature-bridge" }
"#,
            ),
        ];
        for (relative, source) in manifests {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().context("feature fixture parent")?)?;
            std::fs::write(path, source)?;
        }
        let members = [
            m(
                "identity-composition",
                "crates/identity-composition",
                Some(Layer::Root),
            ),
            m("feature-bridge", "crates/feature-bridge", Some(Layer::Root)),
            m("consumer", "crates/consumer", Some(Layer::Root)),
        ];

        let findings = scan_workspace_testsupport_features(&root, &members, &BTreeMap::new())?;
        assert_eq!(
            findings.len(),
            2,
            "root default + consumer default: {findings:#?}"
        );
        assert!(findings.iter().all(|finding| {
            finding.rule == Rule::TestSupportFeatureShipped
                && finding.detail.contains("identity-composition/test-support")
                && finding.detail.contains("cycle-a")
        }));
        assert!(findings.iter().any(|finding| finding.subject == "consumer"));
        Ok(())
    }

    #[test]
    fn red_eventexec_testsupport_feature_closure_is_shipped() -> Result<()> {
        let root = crate::testutil::unique_tmp("eventexec-testsupport-feature-closure-red");
        let manifests = [
            (
                "crates/eventexec/Cargo.toml",
                r#"
[package]
name = "eventexec"

[features]
default = []
test-support = []
"#,
            ),
            (
                "adapters/postgres/Cargo.toml",
                r#"
[package]
name = "postgres"

[features]
default = []
integration = ["eventexec/test-support"]

[dependencies]
eventexec = { path = "../../crates/eventexec" }
"#,
            ),
            (
                "assemblies/runtime/Cargo.toml",
                r#"
[package]
name = "runtime"

[dependencies]
postgres = { path = "../../adapters/postgres", features = ["integration"] }
"#,
            ),
        ];
        for (relative, source) in manifests {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().context("feature fixture parent")?)?;
            std::fs::write(path, source)?;
        }
        let members = [
            m("eventexec", "crates/eventexec", Some(Layer::Service)),
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
        ];

        let findings = scan_workspace_testsupport_features(&root, &members, &BTreeMap::new())?;
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].subject, "runtime");
        assert!(
            findings[0].detail.contains(
                "postgres/integration → postgres/eventexec/test-support → eventexec/test-support",
            ),
            "{findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn red_generated_testsupport_direct_alias_and_forwarding_are_shipped() -> Result<()> {
        let direct = scan_shipped_testsupport_features(&[ShippedDep {
            from: "direct-consumer".to_owned(),
            manifest_file: "crates/direct-consumer/Cargo.toml".to_owned(),
            section: "[dependencies]".to_owned(),
            key: "generated_alias".to_owned(),
            package_name: "generated".to_owned(),
            features: vec!["test-support".to_owned()],
            is_workspace_internal: true,
        }]);
        assert_eq!(direct.len(), 1, "{direct:#?}");
        assert!(direct[0].detail.contains("generated_alias"));

        let root = crate::testutil::unique_tmp("generated-testsupport-feature-closure-red");
        let manifests = [
            (
                "generated/Cargo.toml",
                r#"
[package]
name = "generated"

[features]
default = []
test-support = []
"#,
            ),
            (
                "crates/feature-bridge/Cargo.toml",
                r#"
[package]
name = "feature-bridge"

[features]
default = []
fixtures = ["generated_alias/test-support"]

[dependencies]
generated_alias = { package = "generated", path = "../../generated" }
"#,
            ),
            (
                "crates/consumer/Cargo.toml",
                r#"
[package]
name = "consumer"

[dependencies]
bridge = { package = "feature-bridge", path = "../feature-bridge", features = ["fixtures"] }
"#,
            ),
        ];
        for (relative, source) in manifests {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().context("feature fixture parent")?)?;
            std::fs::write(path, source)?;
        }
        let members = [
            m("generated", "generated", Some(Layer::Generated)),
            m("feature-bridge", "crates/feature-bridge", Some(Layer::Root)),
            m("consumer", "crates/consumer", Some(Layer::Root)),
        ];
        let findings = scan_workspace_testsupport_features(&root, &members, &BTreeMap::new())?;
        assert!(
            findings.iter().any(|finding| {
                finding.subject == "consumer"
                    && finding.detail.contains("generated_alias/test-support")
            }),
            "{findings:#?}"
        );
        Ok(())
    }

    /// LAYER-DEPS-09 synthetic red：`dep:` 激活 optional dependency 后，其 default feature
    /// 与跨包 dependency-feature forwarding 同属 shipped closure，不能只检查入口 dependency entry。
    #[test]
    fn red_testsupport_feature_closure_follows_dep_activation_and_dependency_default() -> Result<()>
    {
        let root = crate::testutil::unique_tmp("testsupport-feature-dep-activation-red");
        let manifests = [
            (
                "crates/deviceidentity/Cargo.toml",
                r#"
[package]
name = "deviceidentity"

[features]
default = ["relay-control"]
relay-control = ["test-support"]
test-support = []
"#,
            ),
            (
                "crates/feature-bridge/Cargo.toml",
                r#"
[package]
name = "feature-bridge"

[features]
default = []
ship = ["dep:device_alias"]

[dependencies]
device_alias = { package = "deviceidentity", path = "../deviceidentity", optional = true }
"#,
            ),
            (
                "crates/consumer/Cargo.toml",
                r#"
[package]
name = "consumer"

[dependencies]
bridge_alias = { package = "feature-bridge", path = "../feature-bridge", default-features = false, features = ["ship"] }
"#,
            ),
        ];
        for (relative, source) in manifests {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().context("feature fixture parent")?)?;
            std::fs::write(path, source)?;
        }
        let members = [
            m("deviceidentity", "crates/deviceidentity", Some(Layer::Root)),
            m("feature-bridge", "crates/feature-bridge", Some(Layer::Root)),
            m("consumer", "crates/consumer", Some(Layer::Root)),
        ];

        let findings = scan_workspace_testsupport_features(&root, &members, &BTreeMap::new())?;
        assert!(
            findings.iter().any(|finding| {
                finding.subject == "consumer"
                    && finding.detail.contains("dep:device_alias")
                    && finding.detail.contains("deviceidentity/test-support")
            }),
            "{findings:#?}"
        );
        Ok(())
    }

    /// LAYER-DEPS-09 real-graph anti-vacuity：当前 assembly 的 test-only façade 确实存在跨包
    /// forwarding；该断言防止 synthetic parser 自洽但没有解析真实 Cargo feature 图。
    #[test]
    fn real_workspace_testsupport_forwarding_graph_is_nonempty() -> Result<()> {
        let root = crate::workspace_root()?;
        let workspace = parse_root_manifest(&root)?.workspace;
        let members = load_members(&root, &workspace.members)?;
        let graph = load_feature_graph(&root, &members, &workspace.dependencies)?;
        let node = FeatureNode::new("deviceidentity", "test-support");
        let forwarding = graph
            .edges
            .get(&node)
            .context("真实 deviceidentity/test-support feature 未进入解析图")?;
        assert!(
            forwarding.iter().any(|step| {
                step.node == FeatureNode::new("identity-composition", "test-support")
                    && step.label.contains("identity-composition/test-support")
            }),
            "真实 deviceidentity forwarding 未进入 feature closure: {forwarding:#?}"
        );
        Ok(())
    }

    /// 红：domain / bootstrap scoped-construction 的 `test-support` 也不得经 shipped 依赖启用。
    #[test]
    fn red_domain_scope_testsupport_in_dependencies() {
        let findings = scan_shipped_testsupport_features(&[
            sdep(
                "bad-identity",
                "[dependencies]",
                "identity",
                &["test-support"],
            ),
            sdep(
                "bad-settings",
                "[dependencies]",
                "settings",
                &["test-support"],
            ),
            sdep("bad-audit", "[dependencies]", "audit", &["test-support"]),
            sdep(
                "bad-bootstrap",
                "[dependencies]",
                "bootstrap",
                &["test-support"],
            ),
            sdep(
                "bad-identity-composition",
                "[dependencies]",
                "identity-composition",
                &["test-support"],
            ),
            sdep(
                "bad-deviceidentity",
                "[dependencies]",
                "deviceidentity",
                &["test-support"],
            ),
            sdep(
                "bad-eventexec",
                "[dependencies]",
                "eventexec",
                &["test-support"],
            ),
        ]);
        assert_eq!(findings.len(), 7, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::TestSupportFeatureShipped),
            "{findings:?}"
        );
    }

    /// 红：DLQ test mint 的精确 feature 不得进入 shipped graph。
    #[test]
    fn red_diport_dlq_testsupport_in_dependencies() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "postgres",
            "[dependencies]",
            "diport",
            &["dlq-test-support"],
        )]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("DLQ authorization test mint"));
    }

    /// 绿：普通 diport test-support 不隐式获得 DLQ mint 权限。
    #[test]
    fn green_diport_generic_testsupport_has_no_dlq_mint() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "postgres",
            "[dependencies]",
            "diport",
            &["test-support"],
        )]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// 红：assembly-schema 的 repository fixture writer 不得进入 shipped graph。
    #[test]
    fn red_assembly_schema_repository_builder_in_dependencies() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "bad-codegen",
            "[dependencies]",
            "assembly-schema",
            &["test-support"],
        )]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].detail.contains("fixture construction"));
    }

    /// 红：`bootstrap/test-support` 单独条目（forge_topology_for_test）须 flagged。
    #[test]
    fn red_bootstrap_testsupport_in_dependencies() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "runtime",
            "[dependencies]",
            "bootstrap",
            &["test-support"],
        )]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::TestSupportFeatureShipped);
        assert!(findings[0].detail.contains("bootstrap"), "{findings:?}");
    }

    /// 红：build-dependencies / target 依赖同为 shipped ⇒ 均 flagged（feature 仍泄进生产构建）。
    #[test]
    fn red_runctx_testsupport_in_build_and_target_deps() {
        let findings = scan_shipped_testsupport_features(&[
            sdep("b1", "[build-dependencies]", "runctx", &["test-support"]),
            sdep(
                "b2",
                "[target.cfg(unix).dependencies]",
                "runctx",
                &["test-support"],
            ),
        ]);
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    /// 绿：runctx 不启用 test-support（无 feature / 仅其它 feature）⇒ 无 finding。
    #[test]
    fn green_runctx_without_testsupport() {
        let findings = scan_shipped_testsupport_features(&[
            sdep("authn", "[dependencies]", "runctx", &[]),
            sdep("other", "[dependencies]", "runctx", &["some-other-feature"]),
        ]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// 绿（specificity）：别的 crate 有名为 `test-support` 的 feature（非 ban list）⇒ 不误报。
    #[test]
    fn green_testsupport_feature_on_non_runctx_dep() {
        let findings = scan_shipped_testsupport_features(&[sdep(
            "x",
            "[dependencies]",
            "someother",
            &["test-support"],
        )]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// anti-vacuity：空输入 ⇒ 无 finding（守卫非恒报；非恒绿由上方红例证）。
    #[test]
    fn antivacuity_runctx_testsupport_empty_is_clean() {
        assert!(scan_shipped_testsupport_features(&[]).is_empty());
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

    /// #1676：Redis/S3/Vault 的 provider output 必须只在 runtime 组合根适配；三条
    /// Adapter→bootstrap 反向边均须被精确拒绝（synthetic red）。
    #[test]
    fn check_layers_red_provider_adapter_to_bootstrap() {
        for adapter in ["redis-adapter", "s3", "vault"] {
            let members = vec![
                m(
                    adapter,
                    &format!("adapters/{adapter}"),
                    Some(Layer::Adapter),
                ),
                m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
            ];
            let findings = check_layers(&members, &[e(adapter, "bootstrap")]);
            assert_eq!(findings.len(), 1, "{adapter} → bootstrap must fail");
            assert_eq!(findings[0].rule, Rule::BackPath);
            assert!(
                findings[0].detail.contains("provider output 边界"),
                "finding 应明确报告窄化规则: {}",
                findings[0].detail
            );
        }
    }

    /// 精确 deny 不改变一般 Adapter→Service：postgres→bootstrap 仍合法；目标 provider
    /// 依赖 diport 也仍合法（anti-vacuity green）。
    #[test]
    fn check_layers_green_provider_boundary_keeps_sanctioned_edges() {
        let members = vec![
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
            m("redis-adapter", "adapters/redis", Some(Layer::Adapter)),
            m("s3", "adapters/s3", Some(Layer::Adapter)),
            m("vault", "adapters/vault", Some(Layer::Adapter)),
            m("bootstrap", "crates/bootstrap", Some(Layer::Service)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
        ];
        let edges = vec![
            e("postgres", "bootstrap"),
            e("redis-adapter", "diport"),
            e("s3", "diport"),
            e("vault", "diport"),
        ];
        assert!(check_layers(&members, &edges).is_empty());
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
    fn check_layers_green_eventexec_to_generated_command_workflow_seam() {
        let members = vec![
            m("eventexec", "crates/eventexec", Some(Layer::Service)),
            m("generated", "generated", Some(Layer::Generated)),
        ];
        assert!(check_layers(&members, &[e("eventexec", "generated")]).is_empty());
    }

    #[test]
    fn check_layers_red_other_service_to_generated_remains_closed() {
        let members = vec![
            m("authn", "crates/authn", Some(Layer::Service)),
            m("generated", "generated", Some(Layer::Generated)),
        ];
        let findings = check_layers(&members, &[e("authn", "generated")]);
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

    fn runtimeexec_fixture_members() -> Vec<Member> {
        vec![
            m(
                "runtimeexec",
                "crates/runtimeexec",
                Some(Layer::RuntimeExec),
            ),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
            m("settingsonly", "assemblies/settingsonly", Some(Layer::Root)),
            m(
                "identityaudit",
                "assemblies/identityaudit",
                Some(Layer::Root),
            ),
            m("server", "bins/server", Some(Layer::Root)),
        ]
    }

    #[test]
    fn runtimeexec_wrapper_exact_green() {
        let bans = vec![ban(
            "runtimeexec",
            &["runtime", "settingsonly", "identityaudit"],
        )];
        assert!(
            check_runtimeexec_wrapper_coverage(&runtimeexec_fixture_members(), &bans).is_empty()
        );
    }

    #[test]
    fn runtimeexec_wrapper_widened_to_bin_red() {
        let bans = vec![ban(
            "runtimeexec",
            &["runtime", "settingsonly", "identityaudit", "server"],
        )];
        let findings = check_runtimeexec_wrapper_coverage(&runtimeexec_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "runtimeexec");
    }

    #[test]
    fn runtimeexec_wrapper_missing_assembly_red() {
        let bans = vec![ban("runtimeexec", &["runtime", "settingsonly"])];
        let findings = check_runtimeexec_wrapper_coverage(&runtimeexec_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "runtimeexec");
    }

    fn authmint_fixture_members() -> Vec<Member> {
        vec![
            m("authmint", "crates/authmint", Some(Layer::Basis)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
            m("settingsonly", "assemblies/settingsonly", Some(Layer::Root)),
            m(
                "identityaudit",
                "assemblies/identityaudit",
                Some(Layer::Root),
            ),
            m("server", "bins/server", Some(Layer::Root)),
            m("identity", "crates/identity", Some(Layer::Domain)),
        ]
    }

    #[test]
    fn authmint_wrapper_exact_green() {
        let bans = vec![ban(
            "authmint",
            &[
                "diport",
                "httpserve",
                "runtime",
                "settingsonly",
                "identityaudit",
            ],
        )];
        assert!(check_authmint_wrapper_coverage(&authmint_fixture_members(), &bans).is_empty());
    }

    #[test]
    fn authmint_wrapper_widened_to_bin_red() {
        let bans = vec![ban(
            "authmint",
            &[
                "diport",
                "httpserve",
                "runtime",
                "settingsonly",
                "identityaudit",
                "server",
            ],
        )];
        let findings = check_authmint_wrapper_coverage(&authmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "authmint");
    }

    #[test]
    fn authmint_wrapper_missing_consumer_red() {
        let bans = vec![ban(
            "authmint",
            &["diport", "httpserve", "runtime", "settingsonly"],
        )];
        let findings = check_authmint_wrapper_coverage(&authmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "authmint");
    }

    fn sagaauthmint_fixture_members() -> Vec<Member> {
        vec![
            m("sagaauthmint", "crates/sagaauthmint", Some(Layer::Basis)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("settingsonly", "assemblies/settingsonly", Some(Layer::Root)),
        ]
    }

    #[test]
    fn sagaauthmint_wrapper_exact_green() {
        let bans = vec![ban("sagaauthmint", &["diport", "runtime"])];
        assert!(
            check_sagaauthmint_wrapper_coverage(&sagaauthmint_fixture_members(), &bans).is_empty()
        );
    }

    #[test]
    fn sagaauthmint_wrapper_widened_red() {
        let bans = vec![ban("sagaauthmint", &["diport", "runtime", "httpserve"])];
        let findings = check_sagaauthmint_wrapper_coverage(&sagaauthmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "sagaauthmint");
    }

    fn dlqauthmint_fixture_members() -> Vec<Member> {
        vec![
            m("dlqauthmint", "crates/dlqauthmint", Some(Layer::Basis)),
            m("diport", "crates/diport", Some(Layer::DiPort)),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
        ]
    }

    #[test]
    fn dlqauthmint_wrapper_exact_green() {
        let bans = vec![ban("dlqauthmint", &["diport", "runtime"])];
        assert!(
            check_dlqauthmint_wrapper_coverage(&dlqauthmint_fixture_members(), &bans).is_empty()
        );
    }

    #[test]
    fn dlqauthmint_wrapper_widened_red() {
        let bans = vec![ban("dlqauthmint", &["diport", "runtime", "postgres"])];
        let findings = check_dlqauthmint_wrapper_coverage(&dlqauthmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "dlqauthmint");
    }

    #[test]
    fn dlqauthmint_wrapper_missing_consumer_red() {
        let bans = vec![ban("dlqauthmint", &["diport"])];
        let findings = check_dlqauthmint_wrapper_coverage(&dlqauthmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "dlqauthmint");
    }

    #[test]
    fn dlqauthmint_reverse_dependency_red() {
        let members = dlqauthmint_fixture_members();
        let findings = check_layers(&members, &[e("dlqauthmint", "diport")]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "dlqauthmint"
                    && finding.rule == Rule::BackPath
                    && finding.detail.contains("diport")),
            "{findings:?}"
        );
    }

    fn requestidmint_fixture_members() -> Vec<Member> {
        vec![
            m("requestidmint", "crates/requestidmint", Some(Layer::Basis)),
            m("httpserve", "crates/httpserve", Some(Layer::Service)),
            m("generated", "generated", Some(Layer::Generated)),
            m("audit", "crates/audit", Some(Layer::Domain)),
        ]
    }

    #[test]
    fn requestidmint_wrapper_exact_green() {
        let bans = vec![ban("requestidmint", &["httpserve", "generated"])];
        assert!(
            check_requestidmint_wrapper_coverage(&requestidmint_fixture_members(), &bans)
                .is_empty()
        );
    }

    #[test]
    fn requestidmint_wrapper_widened_to_domain_red() {
        let bans = vec![ban("requestidmint", &["httpserve", "generated", "audit"])];
        let findings =
            check_requestidmint_wrapper_coverage(&requestidmint_fixture_members(), &bans);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "requestidmint");
    }

    fn runtimeinventorymint_fixture_members() -> Vec<Member> {
        vec![
            m(
                "runtimeinventorymint",
                "crates/runtimeinventorymint",
                Some(Layer::Basis),
            ),
            m(
                "assembly-schema",
                "crates/assembly-schema",
                Some(Layer::Basis),
            ),
            m(
                "runtimeexec",
                "crates/runtimeexec",
                Some(Layer::RuntimeExec),
            ),
            m("runtime", "assemblies/runtime", Some(Layer::Root)),
        ]
    }

    #[test]
    fn runtimeinventorymint_wrapper_exact_green() {
        let bans = vec![ban(
            "runtimeinventorymint",
            &["assembly-schema", "runtimeexec", "runtime"],
        )];
        assert!(
            check_runtimeinventorymint_wrapper_coverage(
                &runtimeinventorymint_fixture_members(),
                &bans,
            )
            .is_empty()
        );
    }

    #[test]
    fn runtimeinventorymint_wrapper_widened_to_assembly_red() {
        let bans = vec![ban(
            "runtimeinventorymint",
            &["assembly-schema", "runtimeexec", "runtime", "settingsonly"],
        )];
        let findings = check_runtimeinventorymint_wrapper_coverage(
            &runtimeinventorymint_fixture_members(),
            &bans,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].subject, "runtimeinventorymint");
    }

    fn runtime_dep(key: &str, is_workspace_internal: bool) -> ShippedDep {
        ShippedDep {
            from: "runtimeexec".to_string(),
            manifest_file: "crates/runtimeexec/Cargo.toml".to_string(),
            section: "[dependencies]".to_string(),
            key: key.to_string(),
            package_name: key.to_string(),
            features: Vec::new(),
            is_workspace_internal,
        }
    }

    #[test]
    fn runtimeexec_direct_dependencies_allowlist_green() {
        let edges = [
            e("runtimeexec", "assembly-schema"),
            e("runtimeexec", "authn"),
            e("runtimeexec", "bootstrap"),
            e("runtimeexec", "diport"),
            e("runtimeexec", "eventexec"),
            e("runtimeexec", "primitives"),
            e("runtimeexec", "runtimeinventorymint"),
            e("runtimeexec", "secure"),
        ];
        let deps = [
            runtime_dep("assembly-schema", true),
            runtime_dep("authn", true),
            runtime_dep("bootstrap", true),
            runtime_dep("diport", true),
            runtime_dep("eventexec", true),
            runtime_dep("primitives", true),
            runtime_dep("runtimeinventorymint", true),
            runtime_dep("secure", true),
            runtime_dep("anyhow", false),
            runtime_dep("serde", false),
            runtime_dep("serde_json", false),
            runtime_dep("thiserror", false),
            runtime_dep("tokio", false),
            runtime_dep("tokio-util", false),
            runtime_dep("tracing", false),
            runtime_dep("zeroize", false),
        ];
        assert!(check_runtimeexec_direct_dependencies(&edges, &deps).is_empty());
    }

    #[test]
    fn runtimeexec_direct_dependencies_extra_internal_and_external_red() {
        let edges = [e("runtimeexec", "bootstrap"), e("runtimeexec", "httpserve")];
        let deps = [
            runtime_dep("bootstrap", true),
            runtime_dep("httpserve", true),
            runtime_dep("axum", false),
        ];
        let findings = check_runtimeexec_direct_dependencies(&edges, &deps);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::RuntimeExecDependencyScope)
        );
    }

    /// RUNTIMEEXEC-DEPS-01 synthetic-red：直接 rename 与根 workspace dependency rename 都必须
    /// 按真实 package identity 拒绝，不能借用 `tokio`/`tracing` 等 allowlisted 本地 key 绕过。
    #[test]
    fn runtimeexec_direct_dependencies_package_alias_red() -> Result<()> {
        let root = crate::testutil::unique_tmp("runtimeexec-dependency-package-alias-red");
        let manifest_path = root.join("crates/runtimeexec/Cargo.toml");
        std::fs::create_dir_all(
            manifest_path
                .parent()
                .context("runtimeexec manifest parent")?,
        )?;
        std::fs::write(
            &manifest_path,
            r#"
[package]
name = "runtimeexec"

[dependencies]
tokio = { package = "axum", version = "1" }
tracing = { workspace = true }
"#,
        )?;
        let members = [m(
            "runtimeexec",
            "crates/runtimeexec",
            Some(Layer::RuntimeExec),
        )];
        let workspace_dependencies: BTreeMap<String, DepSpec> = toml::from_str::<RootManifest>(
            r#"
[workspace]
members = []

[workspace.dependencies]
tracing = { package = "tower", version = "1" }
"#,
        )?
        .workspace
        .dependencies;

        let deps = collect_shipped_deps(&root, &members, &workspace_dependencies)?;
        let findings = check_runtimeexec_direct_dependencies(&[], &deps);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::RuntimeExecDependencyScope)
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("`axum`"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("`tower`"))
        );
        Ok(())
    }

    /// 外部收敛专用 fixture：在 [`wrapper_fixture_members`] 上加 `settings`（Domain，定义自身 repo port），
    /// 使 `EXTERNAL_CONFINEMENT_WRAPPERS` 白名单的 `settings` 条目能解析到 Domain 成员（DIPORT-MACRO-CONFINE-02）。
    /// 不复用 `wrapper_fixture_members`（加 settings 会令 `check_wrappers_*` fixtures 需补 settings ban，cascade）。
    fn confinement_fixture_members() -> Vec<Member> {
        let mut members = wrapper_fixture_members();
        members.push(m("settings", "crates/settings", Some(Layer::Domain)));
        members.push(m("audit", "crates/audit", Some(Layer::Domain)));
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
    fn check_wrappers_green_postgres_generated_dev_wrapper() {
        let mut members = wrapper_fixture_members();
        members.push(m("postgres", "adapters/postgres", Some(Layer::Adapter)));
        let bans = vec![
            ban("identity", &["server", "rss", "xtask"]),
            ban("redis", &["server", "rss", "xtask"]),
            ban("postgres", &["server", "rss", "xtask"]),
            ban(
                "generated",
                &["identity", "postgres", "server", "rss", "xtask"],
            ),
        ];
        assert!(check_wrappers(&members, &bans, &[]).is_empty());
    }

    #[test]
    fn check_layers_red_postgres_generated_production_edge_remains_closed() {
        let members = vec![
            m("postgres", "adapters/postgres", Some(Layer::Adapter)),
            m("generated", "generated", Some(Layer::Generated)),
        ];
        let findings = check_layers(&members, &[e("postgres", "generated")]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::GeneratedScope);
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

    // DIPORT-MACRO-CONFINE-02（check_external_confinement）：外部收敛 wrapper 白名单 = DI port 定义点集
    // （diport[DiPort] + 定义自身 repo/service port 的域 crate，Option 2/ADR-005）。双向 fail-closed。
    #[test]
    fn external_confinement_green() {
        let bans = vec![
            ban("dynosaur", &["diport", "identity", "settings", "audit"]),
            ban(
                "trait-variant",
                &["diport", "identity", "settings", "audit"],
            ),
        ];
        assert!(check_external_confinement(&confinement_fixture_members(), &bans).is_empty());
    }

    // wrappers 顺序无关（集合相等）：白名单乱序仍绿。
    #[test]
    fn external_confinement_green_order_insensitive() {
        let bans = vec![
            ban("dynosaur", &["audit", "settings", "identity", "diport"]),
            ban(
                "trait-variant",
                &["identity", "audit", "settings", "diport"],
            ),
        ];
        assert!(check_external_confinement(&confinement_fixture_members(), &bans).is_empty());
    }

    #[test]
    fn external_confinement_red_ban_deleted() {
        // 删掉 dynosaur ban（保留 trait-variant）→ 正向覆盖报 dynosaur 缺失（防收敛静默失效，F4）。
        let bans = vec![ban(
            "trait-variant",
            &["diport", "identity", "settings", "audit"],
        )];
        let findings = check_external_confinement(&confinement_fixture_members(), &bans);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::WrapperCoverage);
        assert_eq!(findings[0].subject, "dynosaur");
    }

    #[test]
    fn external_confinement_red_widened() {
        // 过覆盖（开洞）：wrappers 含白名单外的 crate（server[Root]），DI port 定义点集被破坏。
        let bans = vec![
            ban(
                "dynosaur",
                &["diport", "identity", "settings", "audit", "server"],
            ),
            ban(
                "trait-variant",
                &["diport", "identity", "settings", "audit"],
            ),
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
            ban(
                "trait-variant",
                &["diport", "identity", "settings", "audit"],
            ),
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

    fn workspacefacts_fixture() -> (Vec<Member>, Vec<Edge>, Vec<ShippedDep>) {
        (
            vec![
                m("xtask", "xtask", Some(Layer::Root)),
                m(
                    "workspacefacts",
                    "crates/workspacefacts",
                    Some(Layer::Tooling),
                ),
            ],
            vec![e("xtask", "workspacefacts")],
            vec![ShippedDep {
                from: "workspacefacts".to_owned(),
                manifest_file: "crates/workspacefacts/Cargo.toml".to_owned(),
                section: "dependencies".to_owned(),
                key: "guppy".to_owned(),
                package_name: "guppy".to_owned(),
                features: Vec::new(),
                is_workspace_internal: false,
            }],
        )
    }

    #[test]
    fn workspacefacts_confinement_exact_green() {
        let (members, edges, deps) = workspacefacts_fixture();
        let bans = vec![
            ban("workspacefacts", &["xtask"]),
            ban("guppy", &["workspacefacts"]),
        ];
        assert!(check_workspacefacts_confinement(&members, &bans, &edges, &deps).is_empty());
    }

    #[test]
    fn workspacefacts_confinement_rejects_widening_and_missing_edges() {
        let (mut members, _, _) = workspacefacts_fixture();
        members.push(m("server", "bins/server", Some(Layer::Root)));
        let bans = vec![
            ban("workspacefacts", &["xtask", "server"]),
            ban("guppy", &["workspacefacts", "xtask"]),
        ];
        let findings = check_workspacefacts_confinement(&members, &bans, &[], &[]);
        assert_eq!(findings.len(), 4, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::WorkspaceFactsConfinement)
        );
    }

    #[test]
    fn workspacefacts_confinement_rejects_actual_workspace_consumer_with_exact_wrappers() {
        let (mut members, mut edges, deps) = workspacefacts_fixture();
        members.push(m("server", "bins/server", Some(Layer::Root)));
        edges.push(e("server", "workspacefacts"));
        let bans = vec![
            ban("workspacefacts", &["xtask"]),
            ban("guppy", &["workspacefacts"]),
        ];

        let findings = check_workspacefacts_confinement(&members, &bans, &edges, &deps);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("server"))
        );
    }

    #[test]
    fn workspacefacts_confinement_rejects_direct_guppy_consumer_with_exact_wrappers() {
        let (members, edges, mut deps) = workspacefacts_fixture();
        deps.push(ShippedDep {
            from: "xtask".to_owned(),
            manifest_file: "xtask/Cargo.toml".to_owned(),
            section: "dependencies".to_owned(),
            key: "guppy_alias".to_owned(),
            package_name: "guppy".to_owned(),
            features: Vec::new(),
            is_workspace_internal: false,
        });
        let bans = vec![
            ban("workspacefacts", &["xtask"]),
            ban("guppy", &["workspacefacts"]),
        ];

        let findings = check_workspacefacts_confinement(&members, &bans, &edges, &deps);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("xtask"))
        );
    }

    #[test]
    fn workspacefacts_confinement_rejects_noncanonical_xtask_path() {
        let (mut members, edges, deps) = workspacefacts_fixture();
        let xtask = members.iter_mut().find(|member| member.name == "xtask");
        assert!(xtask.is_some(), "fixture must contain xtask");
        if let Some(xtask) = xtask {
            xtask.path = "tools/xtask".to_owned();
        }
        let bans = vec![
            ban("workspacefacts", &["xtask"]),
            ban("guppy", &["workspacefacts"]),
        ];

        let findings = check_workspacefacts_confinement(&members, &bans, &edges, &deps);
        assert_eq!(findings.len(), 1, "{findings:?}");
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
        let shipped_deps = collect_shipped_deps(&root, &members, &workspace.dependencies)?;

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
        findings.extend(check_workspacefacts_confinement(
            &members,
            &bans,
            &scan.edges,
            &shipped_deps,
        ));
        findings.extend(check_test_support_confinement(&scan.edges));
        findings.extend(check_test_support_internal_dependencies(&scan.edges));
        findings.extend(scan_workspace_testsupport_features(
            &root,
            &members,
            &workspace.dependencies,
        )?);
        findings.extend(check_runtimeexec_direct_dependencies(
            &scan.edges,
            &shipped_deps,
        ));
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
            package: None,
            path: path.map(str::to_string),
            workspace,
            default_features: None,
            optional: false,
            features: Vec::new(),
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
