//! 两类 Rust exported-symbol baseline 的唯一实现。
//!
//! `internal` owner 写入 `public-api/`，只证明内部签名漂移；`release` owner 写入
//! `release-api/`，目标严格来自 validated positive Release Surface。baseline 本身不授予 Release API。
//!
//! 依赖：外部 `cargo-public-api`（版本由 CI tool catalog 编译期派生）+ 钉版 nightly rustdoc-json
//! （`rustup toolchain install <PINNED_NIGHTLY>`，见 [`PINNED_NIGHTLY`]）。未满足时本命令给指引并**非零退出**（非静默 noop）。
//!
//! **不在 `cargo xtask verify` 快门内**：本命令提供 owner-typed baseline；完整 ReleaseCheck 的唯一
//! `public-api` gate 在同一实现内聚合 internal/release exact-set、逐包 SemVer、公共依赖与类型泄漏。
//!
//! INVARIANT: PUBLICAPI-TOOL-GATE-01 { level = "Medium", exec = "release-check", source = "public-api" }—— 工具缺失 fail-fast，不静默成功。
//! INVARIANT: PUBLICAPI-DRIFT-GATE-01 { level = "Medium", exec = "release-check", source = "public-api" }—— owner exact-set 的缺失、漂移、孤儿和异常目录均 fail-closed。
//! INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }—— rustdoc-json 用钉版 nightly（[`PINNED_NIGHTLY`]，非 rolling）；该 pin 四处
//!   一致：`PINNED_NIGHTLY` ⇔ `lints/rust-toolchain.toml` channel ⇔ reusable CI `RSS_NIGHTLY_PINNED`（三方功能值，
//!   `pinned_nightly_single_source_of_truth` 守）+ `verify.rs` public-api install_hint（`verify::tests::
//!   public_api_install_hint_pins_nightly` 守，绑真实字段值非源码全文）。漂移即 fail。

use crate::layers::{BASIS_CRATES, ENGINE_CRATES};
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicU64, Ordering};
use workspacefacts::{PackageKey, PublicApiOwner, TargetKind, WorkspaceFacts};

static GENERATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// 分层成员单源 = `layers.rs`（basis = PR-1 验收集、engine = PR-2 验收集）；此处复用，不另列副本。
// curated extras 不是架构 layer，只是安全敏感 exported-symbol 面的定点 golden 例外；其中 internal crate
// 的 baseline 是漂移审查，不是 Release API / SemVer 承诺。
// `diport`（DI-infra 层，非 basis/engine）：持全部安全敏感 DI port（Signer/SecretResolver/Pdp/Revocation/
// KeyProvider…），以 internal exported-symbol baseline 锁住安全/封装漂移，列入 curated extras（#1470）。
// `generated` 暴露 contract-derived metadata，作为 PR review 审查材料定点冻结（#1472/#1688）。
// `runtimeexec` 的 launch/probe/inventory hook 是三个 assembly 的稳定内部接缝（#1795）；冻结其窄公开面，
// 防止 ShutdownStack、HTTP/provider 类型或第二 executor 意外外泄。
const CURATED_EXTRA_CRATES: &[&str] = &["authn", "diport", "generated", "runtimeexec"];

/// public-api baseline（rustdoc-json）用的**钉版 nightly**。cargo-public-api 在 stable 上探测到 stable
/// 编译器即强制回退 rolling `nightly`（其 rustdoc-json 格式随日期漂移 ⇒ baseline 误报）；本 const 经
/// [`public_api_cmd`] 设 `RUSTUP_TOOLCHAIN`（等价 `cargo +<此值> public-api`）把 nightly 钉死，使快照可复现（#1145）。
///
/// **单一事实源（NIGHTLY-PIN-01）**：本 const ⇔ `lints/rust-toolchain.toml` 的 `[toolchain].channel`
/// （dylint 实际 nightly）⇔ `.github/workflows/rss-rust-job.yml` 的 `RSS_NIGHTLY_PINNED`（CI 安装的 nightly）三方功能值由
/// `pinned_nightly_single_source_of_truth` 守；第四处 `verify.rs` public-api install_hint 由
/// `verify::tests::public_api_install_hint_pins_nightly` 守（绑真实 install_hint 字段值、非源码全文，避免注释
/// 含 pin 的误绿）——漂移即 fail。**与 dylint nightly 成对、CI 只装一份**：dylint 因 `clippy_utils` rev 升 nightly 时——
/// 该 rev 与本 nightly 配对（见 `lints/rss_*/Cargo.toml`，由 dylint 编译失败 **Hard** 强制，非本治理测试
/// 覆盖）——**须同步重跑 owner-typed `cargo xtask public-api internal|release`**；忘记不会静默，会被
/// PUBLICAPI-DRIFT-GATE-01（`--check`，共用同一 pin）在 CI 直接 drift-fail 抓住。
pub(crate) const PINNED_NIGHTLY: &str = "nightly-2026-04-16";

/// 封装面 baseline 的目标层。无 `--layer` 时取 basis + engine + curated extras 全集（收口 GATE 用）。
/// 服务/域/adapters 内部接缝默认多变，不整体入 baseline；安全敏感 crate 需定点列入 curated extras。
#[derive(Debug, PartialEq, Eq, Clone, Copy, clap::ValueEnum)]
pub(crate) enum InternalLayer {
    Basis,
    Engine,
    Curated,
}

/// 解析 layer → 目标 crate 集。`None` = basis + engine + curated extras（不另列第三份 ALL，避免漂移）。
/// 排除 proc-macro 工具 crate（[`crate::layers::is_proc_macro`]）——其契约由 codegen golden 守，
/// 非 SemVer 库 API 面，不入 public-api baseline。
pub(crate) fn target_crates(layer: Option<InternalLayer>) -> Vec<&'static str> {
    let select: Vec<&'static str> = match layer {
        Some(InternalLayer::Basis) => BASIS_CRATES.to_vec(),
        Some(InternalLayer::Engine) => ENGINE_CRATES.to_vec(),
        Some(InternalLayer::Curated) => CURATED_EXTRA_CRATES.to_vec(),
        None => BASIS_CRATES
            .iter()
            .chain(ENGINE_CRATES)
            .chain(CURATED_EXTRA_CRATES)
            .copied()
            .collect(),
    };
    select
        .into_iter()
        .filter(|c| !crate::layers::is_proc_macro(c))
        .collect()
}

#[derive(Debug, PartialEq, Eq, clap::Subcommand)]
pub(crate) enum Command {
    /// Update/check internal signatures; update removes stale snapshots in the selected scope.
    Internal {
        /// Read-only fail-closed validation; without it, update the selected baseline scope.
        #[arg(long)]
        check: bool,
        /// Limit update/check and stale cleanup to one complete layer ownership universe.
        #[arg(long, value_enum)]
        layer: Option<InternalLayer>,
    },
    /// Update/check the complete release-selected owner and remove stale snapshots on update.
    Release {
        /// Read-only fail-closed validation; without it, atomically update the complete owner.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaselineOwner {
    Internal,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BaselineScope {
    Complete(BaselineOwner),
    InternalLayer(InternalLayer),
}

impl BaselineScope {
    const fn owner(self) -> BaselineOwner {
        match self {
            Self::Complete(owner) => owner,
            Self::InternalLayer(_) => BaselineOwner::Internal,
        }
    }
}

impl BaselineOwner {
    const fn label(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Release => "release",
        }
    }

    const fn directory(self) -> &'static str {
        match self {
            Self::Internal => "public-api",
            Self::Release => "release-api",
        }
    }
}

#[derive(Debug)]
struct BaselineCatalog {
    internal_universe: Vec<PackageKey>,
    internal: Vec<PackageKey>,
    release: Vec<PackageKey>,
    library_targets: BTreeMap<PackageKey, String>,
}

impl BaselineCatalog {
    fn derive(root: &Path, facts: &WorkspaceFacts) -> Result<Self> {
        crate::workspace_facts::validate_command_funnel(root)?;
        crate::assembly_governance::validate_source_funnel(root)?;
        let ir = crate::assembly_governance::AssemblyGovernanceIr::<
            crate::assembly_governance::Core,
        >::load(root)?;
        let artifacts = if crate::release_surface::requires_artifact_join(facts) {
            let joined =
                ir.join_artifacts(crate::assembly_governance::load_artifact_declaration(root)?)?;
            crate::release_surface::project_artifacts(&joined)
        } else {
            Vec::new()
        };
        let (surface, findings) = crate::release_surface::validate(facts, &artifacts);
        if !findings.is_empty() {
            let details = findings
                .iter()
                .map(crate::diagnostic::format_finding)
                .collect::<Vec<_>>()
                .join("\n");
            bail!("validated Release Surface 失败:\n{details}");
        }
        let surface = surface.context("validated Release Surface 未生成 typed surface")?;
        Self::from_release_surface(facts, &surface)
    }

    fn from_release_surface(
        facts: &WorkspaceFacts,
        surface: &crate::release_surface::ReleaseSurface,
    ) -> Result<Self> {
        Self::from_selected_packages(
            facts,
            surface.packages().iter().map(|package| package.package()),
        )
    }

    fn from_selected_packages<'a>(
        facts: &WorkspaceFacts,
        selected: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self> {
        let release = selected
            .into_iter()
            .map(|name| resolve_library(facts, name))
            .collect::<Result<BTreeSet<_>>>()?;
        let internal_universe = target_crates(None)
            .into_iter()
            .map(|name| resolve_library(facts, name))
            .collect::<Result<BTreeSet<_>>>()?;
        let internal = internal_universe.difference(&release).cloned().collect();
        let library_targets = internal_universe
            .union(&release)
            .map(|package| {
                let target = facts
                    .targets_for(package)?
                    .iter()
                    .find(|target| target.kind() == TargetKind::Library)
                    .with_context(|| {
                        format!("baseline target `{}` 没有 library target", package.as_str())
                    })?;
                Ok((package.clone(), target.name().to_owned()))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            internal_universe: internal_universe.into_iter().collect(),
            internal,
            release: release.into_iter().collect(),
            library_targets,
        })
    }

    fn plan(&self, scope: BaselineScope) -> BaselinePlan {
        let (targets, universe) = match scope {
            BaselineScope::Complete(BaselineOwner::Internal) => {
                (self.internal.clone(), BaselineUniverse::Complete)
            }
            BaselineScope::Complete(BaselineOwner::Release) => {
                (self.release.clone(), BaselineUniverse::Complete)
            }
            BaselineScope::InternalLayer(layer) => {
                let selected = target_crates(Some(layer))
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                let targets = self
                    .internal
                    .iter()
                    .filter(|package| selected.contains(package.as_str()))
                    .cloned()
                    .collect();
                let universe = self
                    .internal_universe
                    .iter()
                    .filter(|package| selected.contains(package.as_str()))
                    .cloned()
                    .collect();
                (targets, BaselineUniverse::Packages(universe))
            }
        };
        BaselinePlan {
            scope,
            universe,
            targets,
            library_targets: self.library_targets.clone(),
        }
    }
}

fn resolve_library(facts: &WorkspaceFacts, name: &str) -> Result<PackageKey> {
    let package = facts
        .package_key(name)
        .with_context(|| format!("baseline target `{name}` 不属于 workspace"))?;
    let has_library = facts
        .targets_for(&package)?
        .iter()
        .any(|target| target.kind() == TargetKind::Library);
    if !has_library {
        bail!("baseline target `{name}` 没有 library target");
    }
    Ok(package)
}

#[derive(Debug)]
struct BaselinePlan {
    scope: BaselineScope,
    universe: BaselineUniverse,
    targets: Vec<PackageKey>,
    library_targets: BTreeMap<PackageKey, String>,
}

#[derive(Debug, Eq, PartialEq)]
struct ReleaseSelectionDelta {
    semver_packages: Vec<String>,
    first_release_packages: Vec<String>,
    removed_packages: Vec<String>,
}

impl ReleaseSelectionDelta {
    fn derive(current: &BTreeSet<String>, base: &BTreeSet<String>) -> Self {
        Self {
            semver_packages: current.intersection(base).cloned().collect(),
            first_release_packages: current.difference(base).cloned().collect(),
            removed_packages: base.difference(current).cloned().collect(),
        }
    }
}

fn referenced_type_paths(tokens: &[public_api::tokens::Token]) -> BTreeSet<String> {
    use public_api::tokens::Token;
    let mut paths = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        if !matches!(token, Token::Type(_)) {
            continue;
        }
        let mut parts = vec![token.text()];
        let mut cursor = index;
        while cursor >= 2
            && matches!(&tokens[cursor - 1], Token::Symbol(symbol) if symbol == "::")
            && matches!(
                &tokens[cursor - 2],
                Token::Identifier(_) | Token::Type(_) | Token::Self_(_)
            )
        {
            parts.push(tokens[cursor - 2].text());
            cursor -= 2;
        }
        parts.reverse();
        paths.insert(parts.join("::"));
    }
    paths
}

fn normalized_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn forbidden_type_root<'a>(
    owner: PublicApiOwner,
    library_target: &str,
    path: &'a str,
    workspace: &BTreeSet<String>,
    selected: &BTreeSet<String>,
    resolved_workspace_dependency: Option<&str>,
) -> Option<&'a str> {
    let (root, qualified) = path
        .split_once("::")
        .map_or((path, false), |(root, _)| (root, true));
    if !qualified
        || matches!(root, "std" | "core" | "alloc")
        || root == normalized_crate_name(library_target)
    {
        return None;
    }
    let workspace_package = resolved_workspace_dependency.or_else(|| {
        workspace
            .iter()
            .find(|candidate| normalized_crate_name(candidate) == root)
            .map(String::as_str)
    });
    if let Some(candidate) = workspace_package {
        return match owner {
            PublicApiOwner::PlatformPublic => Some(root),
            PublicApiOwner::StandaloneComponent => (!selected.contains(candidate)).then_some(root),
        };
    }
    match owner {
        PublicApiOwner::PlatformPublic => Some(root),
        PublicApiOwner::StandaloneComponent if path == "tracing::Span" => None,
        PublicApiOwner::StandaloneComponent => Some(root),
    }
}

fn release_api_findings(
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    captures: &BTreeMap<String, ApiCapture>,
) -> Result<Vec<crate::diagnostic::Finding<ReleaseApiRule>>> {
    let mut items = BTreeMap::new();
    for release_package in surface.packages() {
        let package = release_package.package();
        let capture = captures
            .get(package)
            .with_context(|| format!("release package `{package}` 缺 API capture"))?;
        let mut package_items = Vec::new();
        for (profile, rustdoc_json) in &capture.rustdoc_json {
            let api = public_api::Builder::from_rustdoc_json(rustdoc_json)
                .build()
                .with_context(|| {
                    format!("解析 `{package}` {} rustdoc JSON 失败", profile.label())
                })?;
            let rustdoc: rustdoc_types::Crate =
                serde_json::from_slice(&fs::read(rustdoc_json).with_context(|| {
                    format!("读取 `{package}` {} rustdoc JSON 失败", profile.label())
                })?)
                .with_context(|| {
                    format!(
                        "解析 `{package}` {} typed rustdoc JSON 失败",
                        profile.label()
                    )
                })?;
            package_items.extend(
                api.items()
                    .map(|item| {
                        Ok(ApiItemProjection {
                            rendered: format!("profile={} {}", profile.label(), item),
                            tokens: item.tokens().cloned().collect(),
                            source_paths: source_type_paths(&rustdoc, item.id())?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        items.insert(package.to_owned(), package_items);
    }
    release_api_findings_from_items(facts, surface, &items)
}

#[derive(Debug)]
struct ApiItemProjection {
    rendered: String,
    tokens: Vec<public_api::tokens::Token>,
    source_paths: BTreeSet<String>,
}

fn release_api_findings_from_items(
    facts: &WorkspaceFacts,
    surface: &crate::release_surface::ReleaseSurface,
    items: &BTreeMap<String, Vec<ApiItemProjection>>,
) -> Result<Vec<crate::diagnostic::Finding<ReleaseApiRule>>> {
    let workspace = facts
        .workspace_packages()
        .into_iter()
        .map(|package| package.key().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let selected = surface
        .packages()
        .iter()
        .map(|package| package.package().to_owned())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    for release_package in surface.packages() {
        let package = release_package.package();
        let package_key = facts
            .package_key(package)
            .with_context(|| format!("release package `{package}` 不属于 workspace"))?;
        let dependencies = facts.direct_dependencies_for(&package_key)?;
        let library_target = facts
            .targets_for(&package_key)?
            .iter()
            .find(|target| target.kind() == TargetKind::Library)
            .with_context(|| format!("release package `{package}` 缺 library target"))?
            .name();
        let package_items = items
            .get(package)
            .with_context(|| format!("release package `{package}` 缺 API item projection"))?;

        for item in package_items {
            let paths = referenced_type_paths(&item.tokens)
                .union(&item.source_paths)
                .cloned()
                .collect::<BTreeSet<_>>();
            for path in paths {
                let resolved_workspace =
                    resolved_workspace_dependency(dependencies, &path, &workspace).or_else(|| {
                        let root = path.split("::").next().unwrap_or(path.as_str());
                        workspace
                            .iter()
                            .find(|candidate| normalized_crate_name(candidate) == root)
                            .map(String::as_str)
                    });
                let Some(root) = forbidden_type_root(
                    release_package.public_api_owner(),
                    library_target,
                    &path,
                    &workspace,
                    &selected,
                    resolved_workspace,
                ) else {
                    let root = path.split("::").next().unwrap_or(path.as_str());
                    if path.contains("::")
                        && !matches!(path.split("::").next(), Some("std" | "core" | "alloc"))
                        && root != normalized_crate_name(library_target)
                        && !has_direct_normal_dependency(dependencies, &path, None)
                    {
                        findings.push(crate::diagnostic::finding(
                            ReleaseApiRule::PublicDependency,
                            release_subject(package, &item.rendered),
                            format!(
                                "public type `{path}` is not backed by a direct normal dependency"
                            ),
                        ));
                    }
                    continue;
                };

                findings.push(crate::diagnostic::finding(
                    ReleaseApiRule::ForbiddenType,
                    release_subject(package, &item.rendered),
                    format!("forbidden public type `{path}` (crate root `{root}`)"),
                ));
                if resolved_workspace.is_some_and(|dependency| !selected.contains(dependency))
                    || (resolved_workspace.is_some()
                        && !has_direct_normal_dependency(dependencies, &path, resolved_workspace))
                {
                    findings.push(crate::diagnostic::finding(
                        ReleaseApiRule::PublicDependency,
                        release_subject(package, &item.rendered),
                        format!("public workspace type `{path}` is not a selected direct normal dependency"),
                    ));
                }
            }
        }
    }
    findings.sort_by(|left, right| {
        (left.rule, &left.subject, &left.detail).cmp(&(right.rule, &right.subject, &right.detail))
    });
    findings.dedup();
    Ok(findings)
}

fn source_type_paths(
    krate: &rustdoc_types::Crate,
    item_id: rustdoc_types::Id,
) -> Result<BTreeSet<String>> {
    let item = krate
        .index
        .get(&item_id)
        .with_context(|| format!("public rustdoc item {} 缺 index entry", item_id.0))?;
    let value = serde_json::to_value(item).context("投影 rustdoc item 失败")?;
    let mut ids = BTreeSet::new();
    collect_source_ids(&value, &mut ids);
    Ok(ids
        .into_iter()
        .filter_map(|id| krate.paths.get(&rustdoc_types::Id(id)))
        .map(|summary| summary.path.join("::"))
        .collect())
}

fn collect_source_ids(value: &serde_json::Value, ids: &mut BTreeSet<u32>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, nested) in object {
                if matches!(key.as_str(), "resolved_path" | "use") {
                    if let Some(id) = nested
                        .as_object()
                        .and_then(|fields| fields.get("id"))
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|id| u32::try_from(id).ok())
                    {
                        ids.insert(id);
                    }
                }
                collect_source_ids(nested, ids);
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_source_ids(nested, ids);
            }
        }
        _ => {}
    }
}

fn release_subject(package: &str, rendered: &str) -> String {
    let module = rendered
        .split_whitespace()
        .find(|part| part.contains("::"))
        .unwrap_or("<root>")
        .trim_matches(|character: char| {
            !character.is_alphanumeric() && character != ':' && character != '_'
        });
    format!("package={package}/module={module}/item={rendered}")
}

fn has_direct_normal_dependency(
    dependencies: &[workspacefacts::DirectDependencyFacts],
    path: &str,
    expected_package: Option<&str>,
) -> bool {
    let root = path.split("::").next().unwrap_or(path);
    dependencies.iter().any(|dependency| {
        dependency.kind() == workspacefacts::DependencyKind::Normal
            && (normalized_crate_name(dependency.name()) == root
                || dependency
                    .resolved()
                    .is_some_and(|resolved| normalized_crate_name(resolved.as_str()) == root))
            && expected_package.is_none_or(|expected| {
                dependency
                    .resolved()
                    .is_some_and(|resolved| resolved.as_str() == expected)
            })
    })
}

fn resolved_workspace_dependency<'a>(
    dependencies: &'a [workspacefacts::DirectDependencyFacts],
    path: &str,
    workspace: &BTreeSet<String>,
) -> Option<&'a str> {
    let root = path.split("::").next().unwrap_or(path);
    dependencies.iter().find_map(|dependency| {
        let resolved = dependency.resolved()?.as_str();
        (workspace.contains(resolved)
            && (normalized_crate_name(dependency.name()) == root
                || normalized_crate_name(resolved) == root))
            .then_some(resolved)
    })
}

#[derive(Debug)]
enum BaselineUniverse {
    Complete,
    Packages(BTreeSet<PackageKey>),
}

impl BaselineUniverse {
    fn contains_file(&self, name: &str) -> bool {
        match self {
            Self::Complete => true,
            Self::Packages(packages) => name
                .strip_suffix(".txt")
                .is_some_and(|package| packages.iter().any(|key| key.as_str() == package)),
        }
    }
}

pub(crate) fn run(command: Command) -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts.get()?;
    let catalog = BaselineCatalog::derive(&root, facts)?;
    let (plan, check) = match command {
        Command::Internal { check, layer } => {
            let scope = layer.map_or(
                BaselineScope::Complete(BaselineOwner::Internal),
                BaselineScope::InternalLayer,
            );
            (catalog.plan(scope), check)
        }
        Command::Release { check } => (
            catalog.plan(BaselineScope::Complete(BaselineOwner::Release)),
            check,
        ),
    };
    execute(&root, &plan, check).map(drop)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ReleaseApiRule {
    PublicDependency,
    ForbiddenType,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReleaseProofFailure {
    stage: u8,
    subject: String,
    detail: String,
}

impl ReleaseProofFailure {
    fn from_error(stage: u8, subject: impl Into<String>, error: anyhow::Error) -> Self {
        Self {
            stage,
            subject: subject.into(),
            detail: format!("{error:#}"),
        }
    }
}

fn collect_release_stage<T>(
    failures: &mut Vec<ReleaseProofFailure>,
    stage: u8,
    subject: &str,
    run: impl FnOnce() -> Result<T>,
) -> Option<T> {
    match run() {
        Ok(value) => Some(value),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(stage, subject, error));
            None
        }
    }
}

/// Canonical ReleaseCheck proof. The Cargo graph and validated positive selection remain the typed
/// authority; rustdoc token projection only closes residual public-signature leakage.
/// INVARIANT: RELEASE-API-COMPAT-01 { level = "Medium", exec = "release-check", source = "rustdoc-json", synthetic_red = "tests::checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection", anti_vacuity = "tests::checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection" }.
pub(crate) fn run_release_check(against: &str, allow_missing_tools: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
    let facts = command_facts.get()?;
    let catalog = BaselineCatalog::derive(&root, facts)?;

    let mut failures = Vec::new();
    collect_release_stage(&mut failures, 0, "internal-exact-set", || {
        execute(
            &root,
            &catalog.plan(BaselineScope::Complete(BaselineOwner::Internal)),
            true,
        )
    });

    let base_revision = match merge_base(&root, against) {
        Ok(revision) => Some(revision),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(1, "base-revision", error));
            None
        }
    };
    let base_packages = match &base_revision {
        Some(revision) => match release_packages_at(&root, revision) {
            Ok(packages) => Some(packages),
            Err(error) => {
                failures.push(ReleaseProofFailure::from_error(
                    1,
                    "base-release-surface",
                    error,
                ));
                None
            }
        },
        None => None,
    };
    let current_packages = catalog
        .release
        .iter()
        .map(|package| package.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let delta = base_packages
        .as_ref()
        .map(|base| ReleaseSelectionDelta::derive(&current_packages, base));

    let captures = match execute(
        &root,
        &catalog.plan(BaselineScope::Complete(BaselineOwner::Release)),
        true,
    ) {
        Ok(captures) => Some(captures),
        Err(error) => {
            failures.push(ReleaseProofFailure::from_error(
                2,
                "release-exact-set",
                error,
            ));
            None
        }
    };

    if !current_packages.is_empty() {
        match (validated_release_surface(&root, facts), captures.as_ref()) {
            (Ok(surface), Some(captures)) => {
                match release_api_findings(facts, &surface, captures) {
                    Ok(findings) => {
                        failures.extend(findings.into_iter().map(|finding| ReleaseProofFailure {
                            stage: 3,
                            subject: finding.subject,
                            detail: format!("rule={:?}: {}", finding.rule, finding.detail),
                        }))
                    }
                    Err(error) => failures.push(ReleaseProofFailure::from_error(
                        3,
                        "release-type-projection",
                        error,
                    )),
                }
            }
            (Err(error), _) => failures.push(ReleaseProofFailure::from_error(
                3,
                "validated-release-surface",
                error,
            )),
            (Ok(_), None) => {}
        }
    }

    if let (Some(delta), Some(base_revision)) = (&delta, &base_revision) {
        if !delta.semver_packages.is_empty() {
            match ensure_semver_tool_available(allow_missing_tools) {
                Ok(true) => {
                    if let Err(error) =
                        run_semver_packages(&delta.semver_packages, |package, profile| {
                            run_semver_check(&root, package, base_revision, profile)
                        })
                    {
                        failures.push(ReleaseProofFailure::from_error(4, "semver", error));
                    }
                }
                Ok(false) => {}
                Err(error) => failures.push(ReleaseProofFailure::from_error(
                    4,
                    "semver-prerequisite",
                    error,
                )),
            }
        }
    }

    if !failures.is_empty() {
        failures.sort();
        for failure in &failures {
            eprintln!(
                "release-check finding: stage={} subject={} detail={}",
                failure.stage, failure.subject, failure.detail
            );
        }
        bail!(
            "release-check public-api: {} 项聚合校验失败",
            failures.len()
        );
    }
    let Some(delta) = delta else {
        bail!("release-check public-api: base Release Surface 不可用")
    };
    if current_packages.is_empty() {
        eprintln!(
            "release-check public-api: Release Surface 为空；release drift/SemVer/leakage 无目标"
        );
    }
    eprintln!(
        "release-check public-api: {} release package(s), {} SemVer package comparison(s) × {} profiles, {} first-release baseline(s), {} explicit removal(s)",
        current_packages.len(),
        delta.semver_packages.len(),
        ApiProfile::RELEASE.len(),
        delta.first_release_packages.len(),
        delta.removed_packages.len()
    );
    Ok(())
}

fn run_semver_packages(
    packages: &[String],
    mut run: impl FnMut(&str, ApiProfile) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    for package in packages {
        for profile in ApiProfile::RELEASE {
            if let Err(error) = run(package, profile) {
                failures.push(format!(
                    "package={package}/profile={}: {error:#}",
                    profile.label()
                ));
            }
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    bail!(
        "release-check public-api: {} 项 SemVer 校验失败:\n{}",
        failures.len(),
        failures.join("\n")
    )
}

fn validated_release_surface(
    root: &Path,
    facts: &WorkspaceFacts,
) -> Result<crate::release_surface::ReleaseSurface> {
    let ir =
        crate::assembly_governance::AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(
            root,
        )?;
    let artifacts = if crate::release_surface::requires_artifact_join(facts) {
        let joined =
            ir.join_artifacts(crate::assembly_governance::load_artifact_declaration(root)?)?;
        crate::release_surface::project_artifacts(&joined)
    } else {
        Vec::new()
    };
    let (surface, findings) = crate::release_surface::validate(facts, &artifacts);
    if !findings.is_empty() {
        bail!(
            "validated Release Surface 失败:\n{}",
            findings
                .iter()
                .map(crate::diagnostic::format_finding)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    surface.context("validated Release Surface 未生成 typed surface")
}

fn merge_base(root: &Path, against: &str) -> Result<String> {
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["merge-base", against, "HEAD"],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("运行 git merge-base {against} HEAD 失败"))?;
    if !output.status.success() {
        bail!(
            "git merge-base {against} HEAD 非零退出:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let revision = String::from_utf8(output.stdout)?.trim().to_owned();
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("git merge-base 返回非法 revision `{revision}`");
    }
    Ok(revision)
}

fn release_packages_at(root: &Path, revision: &str) -> Result<BTreeSet<String>> {
    let object = format!("{revision}:Cargo.toml");
    let output = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::SystemGit,
        &["show", &object],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("运行 git show {object} 失败"))?;
    if !output.status.success() {
        bail!(
            "git show {object} 非零退出:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let manifest = String::from_utf8(output.stdout)?
        .parse::<toml::Value>()
        .context("解析 base Cargo.toml 失败")?;
    let metadata = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("metadata"))
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
    let metadata = serde_json::to_value(metadata).context("投影 base workspace.metadata 失败")?;
    let selection = workspacefacts::parse_release_selection(&metadata)
        .map_err(anyhow::Error::new)?
        .context("base Cargo.toml 缺 workspace.metadata.release-surface")?;
    let mut packages = BTreeSet::new();
    for package in selection.packages() {
        if !packages.insert(package.package().to_owned()) {
            bail!(
                "base Cargo.toml Release Surface 重复选择 package `{}`",
                package.package()
            );
        }
    }
    Ok(packages)
}

#[derive(Debug)]
struct ApiCapture {
    baseline: String,
    rustdoc_json: Vec<(ApiProfile, PathBuf)>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ApiProfile {
    Default,
    AllFeatures,
}

impl ApiProfile {
    const RELEASE: [Self; 2] = [Self::Default, Self::AllFeatures];

    const fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AllFeatures => "all-features",
        }
    }

    const fn all_features(self) -> bool {
        matches!(self, Self::AllFeatures)
    }
}

fn combine_release_captures(default: ApiCapture, all_features: ApiCapture) -> ApiCapture {
    let baseline = format!(
        "== release-api profile: default ==\n{}\n== release-api profile: all-features ==\n{}\n",
        default.baseline.trim_end_matches('\n'),
        all_features.baseline.trim_end_matches('\n')
    );
    let mut rustdoc_json = default.rustdoc_json;
    rustdoc_json.extend(all_features.rustdoc_json);
    ApiCapture {
        baseline,
        rustdoc_json,
    }
}

fn execute(root: &Path, plan: &BaselinePlan, check: bool) -> Result<BTreeMap<String, ApiCapture>> {
    let owner = plan.scope.owner();
    let _owner_lock = BaselineOwnerLock::acquire(root, owner, check)?;
    let dir = root.join(owner.directory());
    let before = scan_baselines(&dir)?;
    if plan.targets.is_empty() {
        finish_empty_or_orphan(plan, &dir, check, &before)?;
        return Ok(BTreeMap::new());
    }

    ensure_tool_available()?;
    let target_dir = root.join(".cache/public-api-target").join(owner.label());
    let mut captures = BTreeMap::new();
    for package in &plan.targets {
        let library_target = plan
            .library_targets
            .get(package)
            .with_context(|| format!("{} 缺 library target identity", package.as_str()))?;
        let capture = if owner == BaselineOwner::Release {
            combine_release_captures(
                capture_public_api(
                    root,
                    package.as_str(),
                    library_target,
                    &target_dir.join(ApiProfile::Default.label()),
                    ApiProfile::Default,
                )?,
                capture_public_api(
                    root,
                    package.as_str(),
                    library_target,
                    &target_dir.join(ApiProfile::AllFeatures.label()),
                    ApiProfile::AllFeatures,
                )?,
            )
        } else {
            capture_public_api(
                root,
                package.as_str(),
                library_target,
                &target_dir,
                ApiProfile::Default,
            )?
        };
        captures.insert(package.as_str().to_owned(), capture);
    }
    let expected = captures
        .iter()
        .map(|(package, capture)| {
            (
                format!("{package}.txt"),
                capture.baseline.as_bytes().to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if scan_baselines(&dir)? != before {
        bail!("baseline capture 期间目录发生并发变化: {}", dir.display());
    }
    let differences = differences(plan, &dir, &before.files, &expected);
    if check {
        report_differences(owner, &differences)?;
        return Ok(captures);
    }
    apply_generation(&dir, plan, &before, &expected)?;
    eprintln!(
        "public-api {}: {} baseline 已原子更新",
        owner.label(),
        expected.len()
    );
    Ok(captures)
}

fn finish_empty_or_orphan(
    plan: &BaselinePlan,
    dir: &Path,
    check: bool,
    before: &BaselineSnapshot,
) -> Result<()> {
    if scan_baselines(dir)? != *before {
        bail!("baseline 校验期间目录发生并发变化: {}", dir.display());
    }
    let expected = BTreeMap::new();
    let differences = differences(plan, dir, &before.files, &expected);
    if check {
        return report_differences(plan.scope.owner(), &differences);
    }
    if differences
        .items
        .iter()
        .any(|difference| difference.kind == DifferenceKind::Orphan)
    {
        apply_generation(dir, plan, before, &expected)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DifferenceKind {
    Missing,
    Drift,
    Orphan,
}

impl DifferenceKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Drift => "drift",
            Self::Orphan => "orphan",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct BaselineDifference {
    kind: DifferenceKind,
    package: String,
    path: PathBuf,
}

#[derive(Default)]
struct Differences {
    items: Vec<BaselineDifference>,
}

fn differences(
    plan: &BaselinePlan,
    dir: &Path,
    actual: &BTreeMap<String, Vec<u8>>,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Differences {
    let mut result = Differences::default();
    for (name, bytes) in expected {
        match actual.get(name) {
            None => result
                .items
                .push(difference(DifferenceKind::Missing, dir, name)),
            Some(current) if current != bytes => {
                result
                    .items
                    .push(difference(DifferenceKind::Drift, dir, name))
            }
            Some(_) => {}
        }
    }
    result.items.extend(
        actual
            .keys()
            .filter(|name| plan.universe.contains_file(name) && !expected.contains_key(*name))
            .map(|name| difference(DifferenceKind::Orphan, dir, name)),
    );
    result
}

fn difference(kind: DifferenceKind, dir: &Path, name: &str) -> BaselineDifference {
    BaselineDifference {
        kind,
        package: name.strip_suffix(".txt").unwrap_or(name).to_owned(),
        path: dir.join(name),
    }
}

fn report_differences(owner: BaselineOwner, differences: &Differences) -> Result<()> {
    if differences.items.is_empty() {
        eprintln!("public-api {} --check: exact-set 无 drift", owner.label());
        return Ok(());
    }
    let details = differences
        .items
        .iter()
        .map(|difference| {
            format!(
                "status={} owner={} package={} path={}",
                difference.kind.label(),
                owner.label(),
                difference.package,
                difference.path.display()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "public-api owner={} 校验失败（{} 项）:\n{}",
        owner.label(),
        differences.items.len(),
        details
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BaselineSnapshot {
    directory: Option<DirectoryIdentity>,
    files: BTreeMap<String, Vec<u8>>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: rustix::fs::Dev,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    canonical_path: std::path::PathBuf,
}

fn scan_baselines(dir: &Path) -> Result<BaselineSnapshot> {
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BaselineSnapshot {
            directory: None,
            files: BTreeMap::new(),
        }),
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", dir.display())),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "baseline owner 路径必须是非 symlink 目录: {}",
                dir.display()
            )
        }
        Ok(metadata) => scan_baseline_files(dir, Some(directory_identity(dir, &metadata)?)),
    }
}

#[cfg(unix)]
fn directory_identity(_dir: &Path, metadata: &fs::Metadata) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(DirectoryIdentity {
        device: metadata.dev() as rustix::fs::Dev,
        inode: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn directory_identity(dir: &Path, _metadata: &fs::Metadata) -> Result<DirectoryIdentity> {
    Ok(DirectoryIdentity {
        canonical_path: fs::canonicalize(dir)?,
    })
}

fn scan_baseline_files(
    dir: &Path,
    directory: Option<DirectoryIdentity>,
) -> Result<BaselineSnapshot> {
    scan_baseline_files_with_hook(dir, directory, || {})
}

fn scan_baseline_files_with_hook(
    dir: &Path,
    directory: Option<DirectoryIdentity>,
    after_identity: impl FnOnce(),
) -> Result<BaselineSnapshot> {
    after_identity();
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("扫描 {} 失败", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "baseline 目录含 symlink/子目录/异常条目: {}",
                path.display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline 文件名不是 UTF-8: {}", path.display()))?;
        if Path::new(&name)
            .extension()
            .and_then(|value| value.to_str())
            != Some("txt")
        {
            bail!("baseline 目录含非预期文件: {}", path.display());
        }
        let content = crate::generated_file::read_stable_utf8_file(
            &path,
            32 * 1024 * 1024,
            "public-api baseline",
        )?;
        files.insert(name, content.into_bytes());
    }
    let after = fs::symlink_metadata(dir)?;
    if after.file_type().is_symlink()
        || !after.is_dir()
        || directory.as_ref() != Some(&directory_identity(dir, &after)?)
    {
        bail!("baseline 目录在扫描期间被替换: {}", dir.display());
    }
    Ok(BaselineSnapshot { directory, files })
}

struct BaselineOwnerLock {
    #[cfg(unix)]
    _file: fs::File,
}

impl BaselineOwnerLock {
    fn acquire(root: &Path, owner: BaselineOwner, shared: bool) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (root, owner, shared);
            bail!("public-api owner lock / atomic generation update 不支持当前平台")
        }
        #[cfg(unix)]
        {
            use rustix::fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, openat};

            let cache = root.join(".cache");
            ensure_real_directory(&cache)?;
            let lock_dir = cache.join("public-api-locks");
            ensure_real_directory(&lock_dir)?;
            let capability = crate::generated_file::open_directory_capability(&lock_dir)?;
            let name = format!("{}.lock", owner.label());
            let fd = openat(
                capability.fd(),
                name.as_str(),
                OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?;
            let stat = fstat(&fd)?;
            anyhow::ensure!(
                FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
                "baseline owner lock 不是普通文件"
            );
            flock(
                &fd,
                if shared {
                    FlockOperation::LockShared
                } else {
                    FlockOperation::LockExclusive
                },
            )?;
            Ok(Self {
                _file: fs::File::from(fd),
            })
        }
    }
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "目录必须是非 symlink 真实目录: {}",
                path.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .with_context(|| format!("{} 无父目录", path.display()))?;
            anyhow::ensure!(parent.exists(), "目录父路径不存在: {}", parent.display());
            fs::create_dir(path).with_context(|| format!("创建 {} 失败", path.display()))?;
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn apply_generation(
    dir: &Path,
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    apply_generation_with_hook(dir, plan, before, expected, || Ok(()))
}

fn apply_generation_with_hook(
    dir: &Path,
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if scan_baselines(dir)? != *before {
        bail!("baseline apply 前目录发生并发变化: {}", dir.display());
    }
    let intended = intended_generation(plan, before, expected);
    let stage = prepare_generation(dir, plan.scope.owner(), &intended)?;
    let result = commit_generation(dir, &stage, before, &intended, before_commit);
    if result.is_err() && stage.exists() {
        cleanup_generation(&stage).with_context(|| {
            format!(
                "baseline generation 提交失败且 staging 清理失败: {}",
                stage.display()
            )
        })?;
    }
    result
}

fn intended_generation(
    plan: &BaselinePlan,
    before: &BaselineSnapshot,
    expected: &BTreeMap<String, Vec<u8>>,
) -> BTreeMap<String, Vec<u8>> {
    let mut intended = before.files.clone();
    intended.extend(
        expected
            .iter()
            .map(|(name, bytes)| (name.clone(), bytes.clone())),
    );
    intended.retain(|name, _| expected.contains_key(name) || !plan.universe.contains_file(name));
    intended
}

fn prepare_generation(
    dir: &Path,
    owner: BaselineOwner,
    intended: &BTreeMap<String, Vec<u8>>,
) -> Result<PathBuf> {
    let root = dir
        .parent()
        .with_context(|| format!("{} 无 workspace root", dir.display()))?;
    let cache = root.join(".cache");
    ensure_real_directory(&cache)?;
    let staging = cache.join("public-api-staging");
    ensure_real_directory(&staging)?;
    cleanup_stale_generations(&staging, owner)?;

    let mut stage = None;
    for _ in 0..64 {
        let candidate = staging.join(format!(
            "{}-{}-{}",
            owner.label(),
            std::process::id(),
            GENERATION_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                stage = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("创建 baseline staging generation 失败"),
        }
    }
    let stage = stage.context("baseline staging generation 名称冲突次数超限")?;
    for (name, bytes) in intended {
        anyhow::ensure!(
            Path::new(name).components().count() == 1 && name.ends_with(".txt"),
            "非法 baseline generation 文件名: {name}"
        );
        let path = stage.join(name);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::File::open(&stage)?.sync_all()?;
    fs::File::open(&staging)?.sync_all()?;
    Ok(stage)
}

fn cleanup_stale_generations(staging: &Path, owner: BaselineOwner) -> Result<()> {
    let prefix = format!("{}-", owner.label());
    for entry in fs::read_dir(staging)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline staging 文件名不是 UTF-8"))?;
        if name.starts_with(&prefix) {
            let suffix = name
                .strip_prefix(&prefix)
                .context("owner generation prefix must match")?;
            let (pid, sequence) = suffix
                .split_once('-')
                .context("baseline staging generation 名称形状非法")?;
            anyhow::ensure!(
                !pid.is_empty()
                    && !sequence.is_empty()
                    && pid.bytes().all(|byte| byte.is_ascii_digit())
                    && sequence.bytes().all(|byte| byte.is_ascii_digit()),
                "baseline staging generation 名称形状非法: {name}"
            );
            cleanup_generation(&entry.path())?;
        }
    }
    Ok(())
}

fn cleanup_generation(stage: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(stage)?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "baseline staging 不是非 symlink 目录: {}",
        stage.display()
    );
    for entry in fs::read_dir(stage)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("baseline staging 文件名不是 UTF-8"))?;
        let metadata = fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && Path::new(&name)
                    .extension()
                    .and_then(|value| value.to_str())
                    == Some("txt"),
            "baseline staging 含异常条目: {}",
            path.display()
        );
        fs::remove_file(&path)?;
    }
    fs::remove_dir(stage)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn commit_generation(
    dir: &Path,
    stage: &Path,
    before: &BaselineSnapshot,
    intended: &BTreeMap<String, Vec<u8>>,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    use rustix::fs::{RenameFlags, fsync, renameat_with};

    anyhow::ensure!(
        scan_baselines(dir)? == *before,
        "baseline commit 前 live owner 已变化"
    );
    before_commit()?;
    let root = dir.parent().context("baseline owner 无 parent")?;
    let stage_parent = stage.parent().context("baseline stage 无 parent")?;
    let owner_name = dir.file_name().context("baseline owner 无文件名")?;
    let stage_name = stage.file_name().context("baseline stage 无文件名")?;
    let root_capability = crate::generated_file::open_directory_capability(root)?;
    let stage_capability = crate::generated_file::open_directory_capability(stage_parent)?;

    if before.directory.is_some() {
        renameat_with(
            root_capability.fd(),
            owner_name,
            stage_capability.fd(),
            stage_name,
            RenameFlags::EXCHANGE,
        )
        .context("原子交换 baseline generation 失败")?;
    } else {
        renameat_with(
            stage_capability.fd(),
            stage_name,
            root_capability.fd(),
            owner_name,
            RenameFlags::NOREPLACE,
        )
        .context("原子发布首个 baseline generation 失败")?;
    }
    fsync(root_capability.fd())?;
    fsync(stage_capability.fd())?;

    let live = scan_baselines(dir)?;
    if live.files != *intended {
        bail!(
            "baseline generation commit 后 live owner 被并发修改；旧 generation 保留于 {}",
            stage.display()
        );
    }
    if before.directory.is_some() {
        let displaced = scan_baselines(stage)?;
        if displaced != *before {
            renameat_with(
                root_capability.fd(),
                owner_name,
                stage_capability.fd(),
                stage_name,
                RenameFlags::EXCHANGE,
            )
            .context("拒绝 raced generation 时恢复 live owner 失败")?;
            fsync(root_capability.fd())?;
            fsync(stage_capability.fd())?;
            bail!("baseline commit 窗口检测到并发修改，已原子恢复 raced owner");
        }
        cleanup_generation(stage)?;
        fsync(stage_capability.fd())?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn commit_generation(
    _dir: &Path,
    _stage: &Path,
    _before: &BaselineSnapshot,
    _intended: &BTreeMap<String, Vec<u8>>,
    _before_commit: impl FnOnce() -> Result<()>,
) -> Result<()> {
    bail!("当前平台不支持原子 baseline generation exchange")
}

#[cfg(test)]
fn baseline_dir() -> Result<std::path::PathBuf> {
    Ok(crate::workspace_root()?.join(BaselineOwner::Internal.directory()))
}

/// 检测外部 cargo-public-api；缺失即 fail-fast 给安装指引（INVARIANT PUBLICAPI-TOOL-GATE-01）。
fn ensure_tool_available() -> Result<()> {
    const PUBLIC_API_VERSION: &str = env!("RSS_TOOL_VERSION_CARGO_PUBLIC_API");
    if crate::cmd::tool_available(crate::cmd::CargoSubcommand::PublicApi) {
        return Ok(());
    }
    bail!(
        "未找到 `cargo public-api`。安装：\n  \
         cargo install cargo-public-api@{PUBLIC_API_VERSION}\n  \
         rustup toolchain install {PINNED_NIGHTLY}   # rustdoc-json 需钉版 nightly（NIGHTLY-PIN-01）\n\
         仅基础/引擎层与 curated extras 封装面冻结需要本工具（非全 workspace 强制门）。"
    )
}

fn ensure_semver_tool_available(allow_missing: bool) -> Result<bool> {
    semver_tool_action(
        crate::cmd::tool_available(crate::cmd::CargoSubcommand::SemverChecks),
        allow_missing,
    )
}

fn semver_tool_action(available: bool, allow_missing: bool) -> Result<bool> {
    const VERSION: &str = env!("RSS_TOOL_VERSION_CARGO_SEMVER_CHECKS");
    if available {
        return Ok(true);
    }
    if allow_missing {
        eprintln!(
            "release-check: [跳过] SemVer comparison（缺 `cargo semver-checks`，--allow-missing-tools 宽限）。装：cargo install cargo-semver-checks@{VERSION} --locked"
        );
        return Ok(false);
    }
    bail!(
        "未找到 `cargo semver-checks`。安装：\n  cargo install cargo-semver-checks@{VERSION} --locked"
    )
}

fn run_semver_check(
    root: &Path,
    package: &str,
    baseline_revision: &str,
    profile: ApiProfile,
) -> Result<()> {
    let output = semver_check_cmd(root, package, baseline_revision, profile)
        .output()
        .with_context(|| format!("运行 cargo semver-checks -p {package} 失败"))?;
    if !output.status.success() {
        bail!(
            "cargo semver-checks -p {package} profile={} 非零退出:\n{}",
            profile.label(),
            format_semver_failure(output.status.code(), &output.stdout, &output.stderr)
        );
    }
    Ok(())
}

fn format_semver_failure(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    let class = match code {
        Some(100) => "compatibility-violation",
        Some(101) => "tool-failure",
        _ => "process-failure",
    };
    let code = code.map_or_else(|| "signal".to_owned(), |code| code.to_string());
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    format!(
        "class={class} exit={code}\nstdout:\n{}\nstderr:\n{}",
        if stdout.is_empty() {
            "<empty>"
        } else {
            &stdout
        },
        if stderr.is_empty() {
            "<empty>"
        } else {
            &stderr
        }
    )
}

fn semver_check_cmd(
    root: &Path,
    package: &str,
    baseline_revision: &str,
    profile: ApiProfile,
) -> ProcessCommand {
    let mut args = vec!["check-release", "--package", package];
    if profile.all_features() {
        args.push("--all-features");
    }
    args.extend(["--baseline-rev", baseline_revision]);
    crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::SemverChecks,
        &args,
        &[],
        Some(root),
    )
}

/// 构造 `cargo public-api -p <crate>` 子进程，经 [`crate::cmd::cargo_cmd`] 漏斗把 `RUSTUP_TOOLCHAIN`
/// 显式重设为 `toolchain`（剥离后成该变量唯一来源，CMD-ENV-CLEAN-01）——等价 `cargo +<toolchain> public-api`，
/// 让 cargo-public-api 在钉版 nightly 下生成可复现 rustdoc-json（`is_probably_stable()`==false ⇒ 透传当前
/// toolchain，不再强制 rolling `nightly`）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
fn public_api_cmd(
    root: &Path,
    krate: &str,
    toolchain: &str,
    target_dir: &Path,
    all_features: bool,
) -> ProcessCommand {
    let mut args = vec!["-p", krate, "--omit", "blanket-impls"];
    if all_features {
        args.push("--all-features");
    }
    let mut cmd = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::PublicApi,
        &args,
        &[("RUSTUP_TOOLCHAIN", toolchain)],
        Some(root),
    );
    // cargo-public-api 的 rustdoc-json 缓存不能与前序 all-features/coverage 编译共享；否则同一
    // CI 首次 check 可能读到不同 feature 面的旧 JSON，执行刷新后立即重跑却转绿。
    cmd.env("CARGO_TARGET_DIR", target_dir);
    cmd
}

/// 运行 `cargo public-api -p <crate>`（钉版 nightly）捕获其封装面快照文本。
fn capture_public_api(
    root: &Path,
    krate: &str,
    library_target: &str,
    target_dir: &Path,
    profile: ApiProfile,
) -> Result<ApiCapture> {
    let out = public_api_cmd(
        root,
        krate,
        PINNED_NIGHTLY,
        target_dir,
        profile.all_features(),
    )
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
    let rustdoc_json = target_dir
        .join("doc")
        .join(format!("{}.json", normalized_crate_name(library_target)));
    if !rustdoc_json.is_file() {
        bail!(
            "cargo public-api -p {krate} 未留下预期 rustdoc JSON: {}",
            rustdoc_json.display()
        );
    }
    Ok(ApiCapture {
        baseline: String::from_utf8_lossy(&out.stdout).into_owned(),
        rustdoc_json: vec![(profile, rustdoc_json)],
    })
}

#[cfg(test)]
fn public_api_target_dir() -> Result<std::path::PathBuf> {
    Ok(crate::workspace_root()?
        .join(".cache/public-api-target")
        .join(BaselineOwner::Internal.label()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use workspacefacts::testing::{
        metadata_json, path_dependency, path_package, path_package_id, resolve_node, target,
    };

    const HTTP_ROUTE_EVIDENCE_PRIVATE_FIELDS: &[&str] = &[
        "owner",
        "contract",
        "path",
        "method",
        "query_parameters",
        "success_status",
        "idempotency",
        "auth",
        "resource",
        "self_scoped",
        "consistency_level",
        "effect_profile",
    ];

    fn exposed_http_route_evidence_fields(baseline: &str) -> Vec<&'static str> {
        HTTP_ROUTE_EVIDENCE_PRIVATE_FIELDS
            .iter()
            .copied()
            .filter(|field| {
                let symbol = format!("pub vocab::http::HttpRouteEvidence::{field}:");
                baseline.lines().any(|line| line.contains(&symbol))
            })
            .collect()
    }

    fn baseline_plan(scope: BaselineScope, names: &[&str]) -> Result<BaselinePlan> {
        let root = crate::workspace_root()?;
        let facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = facts.get()?;
        let universe = match scope {
            BaselineScope::Complete(_) => BaselineUniverse::Complete,
            BaselineScope::InternalLayer(layer) => BaselineUniverse::Packages(
                target_crates(Some(layer))
                    .into_iter()
                    .map(|name| facts.package_key(name).map_err(Into::into))
                    .collect::<Result<_>>()?,
            ),
        };
        let targets = names
            .iter()
            .map(|name| facts.package_key(name).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        let library_targets = targets
            .iter()
            .map(|package| {
                let target = facts
                    .targets_for(package)?
                    .iter()
                    .find(|target| target.kind() == TargetKind::Library)
                    .context("test baseline target must be a library")?;
                Ok((package.clone(), target.name().to_owned()))
            })
            .collect::<Result<_>>()?;
        Ok(BaselinePlan {
            scope,
            universe,
            targets,
            library_targets,
        })
    }

    fn facts_with_nonempty_release_surface() -> Result<WorkspaceFacts> {
        let mut names = target_crates(None);
        names.push("alpha-release");
        let mut packages = Vec::<Value>::new();
        let mut member_ids = Vec::new();
        let mut nodes = Vec::new();
        for name in names {
            let path = format!("/workspace/crates/{name}");
            let mut package = path_package(
                name,
                &path,
                vec![target(
                    name,
                    "lib",
                    &format!("{path}/src/lib.rs"),
                    true,
                    &[],
                )],
                vec![],
                json!({}),
            );
            if name == "alpha-release" {
                package["publish"] = Value::Null;
            }
            let id = path_package_id(&path);
            member_ids.push(id.clone());
            nodes.push(resolve_node(&id, &[]));
            packages.push(package);
        }
        let metadata = metadata_json("/workspace", packages, member_ids, nodes);
        let mut metadata: Value = serde_json::from_str(&metadata)?;
        metadata["metadata"] = json!({
            "release-surface": {
                "packages": [{
                    "package": "alpha-release",
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }
        });
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?)
    }

    fn facts_with_selected_renamed_dependency() -> Result<WorkspaceFacts> {
        let alpha_path = "/workspace/crates/alpha-release";
        let beta_path = "/workspace/crates/beta-release";
        let alpha_id = path_package_id(alpha_path);
        let beta_id = path_package_id(beta_path);
        let mut dependency = path_dependency("beta-release", beta_path);
        dependency["rename"] = json!("beta_api");
        let mut alpha = path_package(
            "alpha-release",
            alpha_path,
            vec![target(
                "facade_api",
                "lib",
                &format!("{alpha_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![dependency],
            json!({}),
        );
        alpha["publish"] = Value::Null;
        let mut beta = path_package(
            "beta-release",
            beta_path,
            vec![target(
                "beta_release",
                "lib",
                &format!("{beta_path}/src/lib.rs"),
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        beta["publish"] = Value::Null;
        let metadata = metadata_json(
            "/workspace",
            vec![alpha, beta],
            vec![alpha_id.clone(), beta_id.clone()],
            vec![
                resolve_node(&alpha_id, &[("beta_api", &beta_id)]),
                resolve_node(&beta_id, &[]),
            ],
        );
        let mut metadata: Value = serde_json::from_str(&metadata)?;
        metadata["metadata"] = json!({
            "release-surface": {
                "packages": [
                    {"package":"alpha-release","public-api-owner":"standalone-component","api-stability":"stable","profiles":[]},
                    {"package":"beta-release","public-api-owner":"standalone-component","api-stability":"stable","profiles":[]}
                ],
                "profile-artifacts": []
            }
        });
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?)
    }

    #[test]
    fn closed_owner_routes_are_distinct() {
        assert_eq!(BaselineOwner::Internal.directory(), "public-api");
        assert_eq!(BaselineOwner::Release.directory(), "release-api");
        assert_ne!(
            BaselineOwner::Internal.directory(),
            BaselineOwner::Release.directory()
        );
    }

    #[test]
    fn selected_release_library_moves_to_one_owner_with_stable_sorting() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let catalog = BaselineCatalog::from_selected_packages(facts, ["vocab", "ids"])?;
        assert_eq!(
            catalog
                .release
                .iter()
                .map(PackageKey::as_str)
                .collect::<Vec<_>>(),
            vec!["ids", "vocab"]
        );
        let internal = catalog
            .internal
            .iter()
            .map(PackageKey::as_str)
            .collect::<BTreeSet<_>>();
        assert!(!internal.contains("ids"));
        assert!(!internal.contains("vocab"));
        assert!(internal.contains("diport"));
        Ok(())
    }

    #[test]
    fn validated_nonempty_surface_flows_into_release_owner_catalog() -> Result<()> {
        let facts = facts_with_nonempty_release_surface()?;
        let (surface, findings) = crate::release_surface::validate(&facts, &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let surface = surface.context("synthetic surface must validate")?;
        let catalog = BaselineCatalog::from_release_surface(&facts, &surface)?;
        assert_eq!(
            catalog
                .release
                .iter()
                .map(PackageKey::as_str)
                .collect::<Vec<_>>(),
            vec!["alpha-release"]
        );
        assert!(
            catalog
                .internal
                .iter()
                .all(|package| package.as_str() != "alpha-release")
        );
        Ok(())
    }

    #[test]
    fn real_workspace_catalog_has_empty_release_and_disjoint_owners() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let catalog = BaselineCatalog::derive(&root, facts)?;
        assert!(catalog.release.is_empty());
        let internal = catalog.internal.iter().collect::<BTreeSet<_>>();
        let release = catalog.release.iter().collect::<BTreeSet<_>>();
        assert!(internal.is_disjoint(&release));
        assert_eq!(
            internal.len(),
            target_crates(None)
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len()
        );
        Ok(())
    }

    #[test]
    fn release_selection_rejects_non_library_package() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let binary_only = facts
            .workspace_packages()
            .into_iter()
            .find(|package| {
                facts.targets_for(package.key()).is_ok_and(|targets| {
                    targets
                        .iter()
                        .any(|target| target.kind() == TargetKind::Binary)
                        && !targets
                            .iter()
                            .any(|target| target.kind() == TargetKind::Library)
                })
            })
            .context("workspace must contain a binary-only negative fixture")?;
        assert!(
            BaselineCatalog::from_selected_packages(facts, [binary_only.key().as_str()]).is_err()
        );
        Ok(())
    }

    #[test]
    fn exact_set_reports_missing_drift_and_orphan_with_owner_paths() -> Result<()> {
        let dir = Path::new("/repo/release-api");
        let plan = baseline_plan(
            BaselineScope::Complete(BaselineOwner::Release),
            &["vocab", "ids"],
        )?;
        let actual = BTreeMap::from([
            ("ids.txt".to_owned(), b"old".to_vec()),
            ("stale.txt".to_owned(), b"stale".to_vec()),
        ]);
        let expected = BTreeMap::from([
            ("ids.txt".to_owned(), b"new".to_vec()),
            ("vocab.txt".to_owned(), b"new".to_vec()),
        ]);
        let diff = differences(&plan, dir, &actual, &expected);
        assert_eq!(
            diff.items,
            vec![
                BaselineDifference {
                    kind: DifferenceKind::Drift,
                    package: "ids".to_owned(),
                    path: dir.join("ids.txt"),
                },
                BaselineDifference {
                    kind: DifferenceKind::Missing,
                    package: "vocab".to_owned(),
                    path: dir.join("vocab.txt"),
                },
                BaselineDifference {
                    kind: DifferenceKind::Orphan,
                    package: "stale".to_owned(),
                    path: dir.join("stale.txt"),
                },
            ]
        );
        let error = report_differences(BaselineOwner::Release, &diff)
            .err()
            .context("all differences must fail closed")?
            .to_string();
        assert!(error.contains("owner=release"));
        assert!(error.contains("status=missing owner=release package=vocab"));
        assert!(error.contains("status=orphan owner=release package=stale"));
        Ok(())
    }

    #[test]
    fn internal_layer_reports_release_selected_package_as_owner_moved_orphan() -> Result<()> {
        let root = crate::workspace_root()?;
        let facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let catalog = BaselineCatalog::from_selected_packages(facts.get()?, ["vocab"])?;
        let plan = catalog.plan(BaselineScope::InternalLayer(InternalLayer::Basis));
        let dir = Path::new("/repo/public-api");
        let actual = BTreeMap::from([("vocab.txt".to_owned(), b"stale".to_vec())]);
        let diff = differences(&plan, dir, &actual, &BTreeMap::new());

        assert_eq!(
            diff.items,
            vec![BaselineDifference {
                kind: DifferenceKind::Orphan,
                package: "vocab".to_owned(),
                path: dir.join("vocab.txt"),
            }]
        );
        Ok(())
    }

    #[test]
    fn absent_empty_release_directory_is_valid_without_tool() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-empty-release");
        fs::create_dir(&root)?;
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Release), &[])?;
        execute(&root, &plan, true)?;
        assert!(!root.join("release-api").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn scanner_rejects_symlink_subdirectory_and_non_txt() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-shape");
        let dir = root.join("release-api");
        fs::create_dir_all(dir.join("nested"))?;
        assert!(scan_baselines(&dir).is_err());
        fs::remove_dir_all(dir.join("nested"))?;
        fs::write(dir.join("README.md"), b"not owned")?;
        assert!(scan_baselines(&dir).is_err());
        fs::remove_file(dir.join("README.md"))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("missing", dir.join("link.txt"))?;
            assert!(scan_baselines(&dir).is_err());
        }
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn scanner_rejects_same_content_directory_identity_swap() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-scan-swap");
        let dir = root.join("public-api");
        let moved = root.join("moved-public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"same")?;
        let metadata = fs::symlink_metadata(&dir)?;
        let identity = directory_identity(&dir, &metadata)?;
        let result = scan_baseline_files_with_hook(&dir, Some(identity), || {
            fs::rename(&dir, &moved).expect("move original baseline dir");
            fs::create_dir(&dir).expect("create replacement baseline dir");
            fs::write(dir.join("vocab.txt"), b"same").expect("write same-content replacement");
        });
        assert!(result.is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generation_rejects_concurrent_change_before_prepare() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-concurrent");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        fs::write(dir.join("vocab.txt"), b"raced")?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;
        assert!(apply_generation(&dir, &plan, &before, &expected).is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"raced");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn failed_prepare_preserves_live_generation() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-failure");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        fs::write(dir.join("stale.txt"), b"stale")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            bail!("synthetic prepare failure")
        });
        assert!(error.is_err());
        assert_eq!(scan_baselines(&dir)?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn failed_first_generation_preserves_absent_owner() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-first-create-failure");
        fs::create_dir(&root)?;
        let dir = root.join("release-api");
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Release), &["vocab"])?;

        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            bail!("synthetic prepare failure")
        });

        assert!(error.is_err());
        assert!(!dir.exists(), "failed first commit must preserve absence");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn prepare_keeps_live_owner_unchanged_until_commit() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-prepare");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        fs::write(dir.join("stale.txt"), b"stale")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(BaselineScope::Complete(BaselineOwner::Internal), &["vocab"])?;

        apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            anyhow::ensure!(
                scan_baselines(&dir)? == before,
                "prepare exposed a mixed live generation"
            );
            Ok(())
        })?;

        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"after");
        assert!(!dir.join("stale.txt").exists());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn crashed_staging_generation_is_recovered_before_next_update() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-staging-recovery");
        let staging = root.join(".cache/public-api-staging");
        let crashed = staging.join("internal-999-1");
        fs::create_dir_all(&crashed)?;
        fs::write(crashed.join("vocab.txt"), b"old generation")?;
        let dir = root.join("public-api");
        let intended = BTreeMap::from([("vocab.txt".to_owned(), b"next".to_vec())]);

        let prepared = prepare_generation(&dir, BaselineOwner::Internal, &intended)?;

        assert!(!crashed.exists());
        assert_eq!(scan_baselines(&prepared)?.files, intended);
        cleanup_generation(&prepared)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn generation_exchange_never_clobbers_concurrent_live_output() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-generation-race");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::write(dir.join("vocab.txt"), b"concurrent")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"concurrent");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn partial_update_rejects_but_preserves_unselected_concurrent_change() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-partial-cas");
        let dir = root.join("public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before-vocab")?;
        fs::write(dir.join("ids.txt"), b"before-ids")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after-vocab".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::write(dir.join("ids.txt"), b"concurrent-ids")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"before-vocab");
        assert_eq!(fs::read(dir.join("ids.txt"))?, b"concurrent-ids");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generation_commit_never_redirects_to_replacement_directory() -> Result<()> {
        let root = crate::testutil::unique_tmp("publicapi-owner-swap");
        let dir = root.join("public-api");
        let moved = root.join("moved-public-api");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("vocab.txt"), b"before")?;
        let before = scan_baselines(&dir)?;
        let expected = BTreeMap::from([("vocab.txt".to_owned(), b"after".to_vec())]);
        let plan = baseline_plan(
            BaselineScope::InternalLayer(InternalLayer::Basis),
            &["vocab"],
        )?;
        let error = apply_generation_with_hook(&dir, &plan, &before, &expected, || {
            fs::rename(&dir, &moved)?;
            fs::create_dir(&dir)?;
            fs::write(dir.join("vocab.txt"), b"replacement")?;
            Ok(())
        });
        assert!(error.is_err());
        assert_eq!(fs::read(moved.join("vocab.txt"))?, b"before");
        assert_eq!(fs::read(dir.join("vocab.txt"))?, b"replacement");
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn target_crates_counts_and_curated_exact_set() {
        // exact-set 单源 = layers + CURATED_EXTRA_CRATES，经 is_proc_macro 过滤（含 sagaauthmint；securederive 排除）。
        let expected_basis: Vec<_> = BASIS_CRATES
            .iter()
            .copied()
            .filter(|c| !crate::layers::is_proc_macro(c))
            .collect();
        let expected_engine: Vec<_> = ENGINE_CRATES
            .iter()
            .copied()
            .filter(|c| !crate::layers::is_proc_macro(c))
            .collect();
        let expected_curated: Vec<_> = CURATED_EXTRA_CRATES.to_vec();
        let expected_all: Vec<_> = expected_basis
            .iter()
            .chain(expected_engine.iter())
            .chain(expected_curated.iter())
            .copied()
            .collect();

        assert_eq!(target_crates(Some(InternalLayer::Basis)), expected_basis);
        assert_eq!(target_crates(Some(InternalLayer::Engine)), expected_engine);
        assert_eq!(
            target_crates(Some(InternalLayer::Curated)),
            expected_curated
        );
        assert_eq!(target_crates(None), expected_all);
        // len 仅由 exact-set 派生，禁止裸魔法数主证。
        assert_eq!(
            target_crates(Some(InternalLayer::Basis)).len(),
            expected_basis.len()
        );
        assert_eq!(
            target_crates(Some(InternalLayer::Engine)).len(),
            expected_engine.len()
        );
        assert_eq!(target_crates(None).len(), expected_all.len());
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"assembly-schema"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"authmint"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"sagaauthmint"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"tracewire"));
    }

    #[test]
    fn target_crates_membership_keeps_curated_in_baseline() {
        assert!(target_crates(None).contains(&"authn"));
        assert!(target_crates(None).contains(&"diport"));
        assert!(target_crates(None).contains(&"generated"));
        assert!(target_crates(None).contains(&"runtimeexec"));
        assert!(target_crates(Some(InternalLayer::Basis)).contains(&"vocab"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"primitives"));
        assert!(target_crates(Some(InternalLayer::Engine)).contains(&"tracewire"));
    }

    #[test]
    fn target_crates_membership_keeps_curated_out_of_layers() {
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"authn"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"authn"));
        // diport 是 DI-infra 层，既非 basis 也非 engine——只经 curated extras 入 baseline。
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"diport"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"diport"));
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"generated"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"generated"));
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"runtimeexec"));
        assert!(!target_crates(Some(InternalLayer::Engine)).contains(&"runtimeexec"));
        // proc-macro 工具 crate 不入 public-api baseline（契约由 codegen golden 守）。
        assert!(!target_crates(Some(InternalLayer::Basis)).contains(&"securederive"));
    }

    #[test]
    fn target_crates_have_no_duplicates() {
        let crates = target_crates(None);
        let set: std::collections::BTreeSet<_> = crates.iter().copied().collect();
        assert_eq!(set.len(), crates.len(), "public-api 目标 crate 不得重复");
    }

    #[test]
    fn runtimeexec_public_api_golden_keeps_launch_kernel_narrow() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("runtimeexec.txt"))?;
        for required in [
            "pub trait runtimeexec::LaunchAdapter",
            "pub struct runtimeexec::LaunchPlan",
            "pub fn runtimeexec::LaunchPlan<Adapter, ProbeReceipt, ReadyHook>::new",
            "pub struct runtimeexec::LaunchTransaction",
            "pub fn runtimeexec::LaunchTransaction<'stack>::stage_resource",
            "pub struct runtimeexec::LaunchRegistrar",
            "pub fn runtimeexec::LaunchRegistrar<'_>::register_listener_with_token",
            "pub fn runtimeexec::LaunchRegistrar<'_>::complete",
            "pub struct runtimeexec::Activated",
            "pub struct runtimeexec::ProviderLifecycleBatch",
            "pub struct runtimeexec::DomainLifecycleBatch",
            "pub struct runtimeexec::LaunchLifecycleBatches",
            "pub struct runtimeexec::RuntimeOutputs",
            "pub async fn runtimeexec::launch",
        ] {
            assert!(
                baseline.contains(required),
                "runtimeexec public-api golden 缺必要启动内核项: {required}"
            );
        }
        for forbidden in [
            "ShutdownStack",
            "wait_for_shutdown_signal",
            "register_detached",
            "listener_count",
            "launch_until",
            "httpd::",
            "httpserve::",
            "pub mod runtimeexec::authn",
            "pub struct runtimeexec::RuntimeInventory",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "runtimeexec public-api golden 不得泄露内部/transport/provider 项: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn authn_public_api_golden_keeps_verified_token_seal_private() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("authn.txt"))?;
        for required in [
            "pub struct authn::VerifiedJwt",
            "pub fn authn::VerifiedJwt::raw(&self) -> &str",
            "pub struct authn::VerifiedServiceToken",
            "pub fn authn::VerifiedServiceToken::raw(&self) -> &str",
            "pub fn authn::Principal::from_verified_jwt(&authn::VerifiedJwt)",
            "pub fn authn::Principal::from_verified_service_token(&authn::VerifiedServiceToken)",
            "pub async fn authn::verify_rss_access",
            "pub async fn authn::verify_federated_access",
            "pub async fn authn::verify_service_token",
            "pub struct authn::RssAccessIssueInput",
            "pub struct authn::VerifiedGrantReceipt",
            "pub fn authn::VerifiedJwt::grant_receipt(&self)",
            "pub fn authn::AuthGrant::access_issue_input(&self)",
        ] {
            assert!(
                baseline.contains(required),
                "authn public-api golden 缺少必要公开项: {required}"
            );
        }
        for forbidden in [
            "pub fn authn::VerifiedJwt::seal",
            "pub fn authn::VerifiedServiceToken::seal",
            "VerifiedJwt::seal",
            "VerifiedServiceToken::seal",
            "JwtAccessPrincipal",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "authn public-api golden 不得暴露私有 mint funnel: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn diport_internal_export_baseline_reexports_send_variant_not_base_trait() -> anyhow::Result<()>
    {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("diport.txt"))?;
        // crate 根 re-export = Send 变体 + Dyn wrapper + KeyProvider 公开类型（adapters/组合根消费面）。
        for required in [
            "pub trait diport::KeyProvider: core::marker::Send",
            "pub struct diport::DynKeyProvider",
            "pub struct diport::KeyRef",
            "pub struct diport::EncryptOutput",
            // 方法列在定义路径（cargo-public-api 惯例），非 re-export 路径；parse ⇄ to_token 对称 token 存储面单源。
            "pub fn diport::key_provider::KeyRef::to_token",
            "pub struct diport::VerifiedAccessGrantFacts",
            "pub fn diport::pdp::VerifiedClaims::rss_user",
            "pub enum diport::pdp::VerifiedClaimsView<'a>",
            "pub fn diport::pdp::VerifiedClaims::view(&self) -> diport::pdp::VerifiedClaimsView<'_>",
        ] {
            assert!(
                baseline.contains(required),
                "diport internal export baseline 缺少必要导出项: {required}"
            );
        }
        // 非 Send 基 trait `*Local` **不**在 crate 根 re-export（仅 `diport::key_provider::KeyProviderLocal`
        // 经 pub mod 可达），避免 glob import 方法解析歧义（ADR-003 落地结论）。
        assert!(
            !baseline.contains("pub trait diport::KeyProviderLocal"),
            "diport internal export baseline 不得在 crate 根 re-export 基 trait KeyProviderLocal"
        );
        assert!(
            !baseline.contains("VerifiedClaims::new"),
            "diport internal export baseline 不得恢复开放的 VerifiedClaims 构造器"
        );
        // 安全负向不变式（ADR-011 §D3 防 timing oracle）：key 标识 `KeyName`/`KeyVersion`/`KeyRef` **禁** derive
        // `PartialEq`/`Eq`——只能经 `ct_eq` 等值-only 匹配。golden 锁住「无 `==` 能力」，杜绝后续 PR 重生 baseline
        // 时误把 `==`（非常数时间）纳入公开面。负向 golden + 不 derive（类型层）双守。
        for forbidden in [
            "impl core::cmp::PartialEq for diport::key_provider::KeyName",
            "impl core::cmp::Eq for diport::key_provider::KeyName",
            "impl core::cmp::PartialEq for diport::key_provider::KeyVersion",
            "impl core::cmp::Eq for diport::key_provider::KeyVersion",
            "impl core::cmp::PartialEq for diport::key_provider::KeyRef",
            "impl core::cmp::Eq for diport::key_provider::KeyRef",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "diport internal export baseline 不得暴露 key 标识的非常数时间 `==`（ADR-011 §D3）: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn generated_public_api_golden_exposes_generated_metadata_surfaces() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("generated.txt"))?;
        for required in [
            "pub trait generated::FieldProtectionMetadata",
            "pub const generated::FieldProtectionMetadata::FIELD_PROTECTIONS: &'static [generated::FieldProtectionSpec]",
            "impl generated::FieldProtectionMetadata for generated::http::settings_v1::SettingsConfigPublishRequest",
            "pub const generated::http::settings_v1::SettingsConfigPublishRequest::FIELD_PROTECTIONS: &'static [generated::FieldProtectionSpec]",
            "pub struct generated::FieldProtectionSpec",
            "pub generated::FieldProtectionSpec::field_path: &'static str",
            "pub generated::FieldProtectionSpec::at_rest: generated::ProtectionAtRest",
            "pub generated::FieldProtectionSpec::mode: core::option::Option<generated::ProtectionMode>",
            "pub enum generated::ProtectionAadDim",
            "pub enum generated::ProtectionAtRest",
            "pub enum generated::ProtectionMode",
            "pub generated::http::HttpSpec::route: vocab::http::HttpRouteEvidence",
            "pub const generated::http::settings_v4::ROUTE: vocab::http::HttpRouteBinding<generated::http::settings_v4::RouteMarker, vocab::http::LocalOnly>",
            "pub enum generated::http::settings_v4::RouteMarker",
            "pub generated::http::HttpSpec::local_tx: core::option::Option<generated::http::LocalTxSpec>",
            "pub struct generated::http::LocalTxSpec",
            "pub generated::http::LocalTxSpec::boundary: vocab::http::LocalTxBoundary",
            "pub generated::http::LocalTxSpec::tx_model: vocab::http::LocalTxModel",
            "pub generated::http::LocalTxSpec::retry: vocab::http::LocalTxRetry",
            "pub generated::http::LocalTxSpec::commit_unknown: vocab::http::LocalTxCommitUnknown",
            "pub const generated::http::LOCAL_TX_SPECS: &[generated::http::HttpSpec]",
            "pub const generated::http::LOCAL_ONLY_SPECS: &[generated::http::HttpSpec]",
            "pub trait generated::http::HttpResponseBinding",
            "pub const generated::http::identity_v2::device_certificate_policy_put::RESPONSES: &[generated::http::HttpResponseSpec]",
            "impl generated::http::HttpResponseBinding for generated::http::identity_v2::device_certificate_policy_put::IdentityDeviceCertificatePolicyPutConflictResponse",
            "pub enum generated::http::audit_v1::list_entries::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::policies_get::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::policies_list::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::profile::LocalOnlyConformanceMarker",
            "pub enum generated::http::identity_v1::roles_list::LocalOnlyConformanceMarker",
            "pub enum generated::http::settings_v4::LocalOnlyConformanceMarker",
            "pub const generated::http::audit_v1::list_tenant_entries::LOCAL_TX: generated::http::LocalTxSpec",
            "pub const generated::http::identity_v1::logout::PRODUCER: vocab::http::HttpProducerBinding<generated::http::identity_v1::logout::RouteMarker>",
            "pub const generated::http::identity_v1::refresh::PRODUCER: vocab::http::HttpProducerBinding<generated::http::identity_v1::refresh::RouteMarker>",
            "pub const generated::http::settings_v2::LOCAL_TX: generated::http::LocalTxSpec",
            "pub struct generated::command::CommandSpec",
            "pub trait generated::command::CommandJournal",
            "pub const fn generated::command::CommandSpec::journal(self) -> generated::command::CommandJournalPolicy",
            "pub struct generated::event::EventSpec",
            "pub enum generated::event::PartitionKeyStrategy",
            "pub enum generated::event::SubscriberReadiness",
            "pub enum generated::event::SubscriptionDispatchKey",
            "pub const generated::event::EVENTS: &[generated::event::EventSpec]",
            "pub const fn generated::event::EventSpec::subscriptions(self) -> &'static [generated::event::SubscriptionSpec]",
            "pub const fn generated::event::SubscriptionSpec::dispatch(self) -> generated::event::SubscriptionDispatchKey",
            "pub const fn generated::event::SubscriptionSpec::external_effect_policy(self) -> vocab::ExternalEffectPolicy",
        ] {
            assert!(
                baseline.contains(required),
                "generated public-api golden 缺少 metadata API: {required}"
            );
        }
        for forbidden in [
            "diport::",
            "secure::aead",
            "secure::Ciphertext",
            "generated::KeyProvider",
            "generated::ProtectionContext",
            "generated::DerivedAad",
            "generated::ValueTransformer",
            "generated::KeyRef",
            "generated::EncryptOutput",
            "generated::DecryptOutput",
            "generated::seal",
            "generated::open",
            "generated::rewrap",
            "pub generated::event::SubscriptionSpec::consumer:",
            "pub generated::event::SubscriptionSpec::group:",
            "pub generated::event::EventSpec::topic:",
            "pub generated::command::CommandSpec::topic:",
            "generated::http::HttpConsistencyLevel",
            "generated::http::EffectProfile",
            "generated::http::EffectKind",
            "generated::http::HttpAuthMode",
            "generated::http::HttpAuthSpec",
            "pub generated::http::HttpSpec::contract_id:",
            "pub generated::http::HttpSpec::contract:",
            "pub generated::http::HttpSpec::path:",
            "pub generated::http::HttpSpec::method:",
            "pub generated::http::HttpSpec::auth:",
            "pub generated::http::HttpSpec::resource:",
            "pub generated::http::HttpSpec::self_scoped:",
            "pub generated::http::HttpSpec::consistency_level:",
            "pub generated::http::HttpSpec::effect_profile:",
            "generated::http::LocalTxBoundary",
            "generated::http::LocalTxModel",
            "generated::http::LocalTxRetry",
            "generated::http::LocalTxCommitUnknown",
        ] {
            assert!(
                !baseline.lines().any(|line| line.contains(forbidden)),
                "generated public-api golden 不得暴露加解密执行面符号: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn vocab_public_api_golden_exposes_canonical_http_route_evidence() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("vocab.txt"))?;
        for required in [
            "pub enum vocab::http::HttpConsistencyLevel",
            "pub trait vocab::http::HttpConsistencyClass",
            "pub trait vocab::http::NonLocalHttpConsistency",
            "pub struct vocab::http::LocalOnly",
            "pub enum vocab::http::HttpEffectKind",
            "pub struct vocab::http::HttpEffectProfile",
            "pub const fn vocab::http::HttpEffectProfile::new",
            "pub struct vocab::http::HttpSuccessStatus",
            "pub const fn vocab::http::HttpSuccessStatus::new",
            "pub const fn vocab::http::HttpSuccessStatus::get",
            "pub enum vocab::http::HttpIdempotency",
            "pub vocab::http::HttpIdempotency::Idempotent",
            "pub vocab::http::HttpIdempotency::NonIdempotent",
            "pub enum vocab::http::HttpRouteAuth",
            "pub struct vocab::http::HttpQueryParameterSpec",
            "pub const fn vocab::http::HttpQueryParameterSpec::from_static",
            "pub struct vocab::http::HttpContractOwner",
            "pub const fn vocab::http::HttpContractOwner::framework",
            "pub const fn vocab::http::HttpContractOwner::domain_name",
            "pub struct vocab::http::HttpRouteBinding<M, C>",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::from_static",
            "pub const fn vocab::http::HttpRouteBinding<M, C>::evidence",
            "pub struct vocab::http::HttpRouteEvidence",
            "pub const fn vocab::http::HttpRouteEvidence::from_static",
            "pub const fn vocab::http::HttpRouteEvidence::success_status",
            "pub const fn vocab::http::HttpRouteEvidence::idempotency",
            "pub const fn vocab::http::HttpRouteEvidence::query_parameters",
            "pub const fn vocab::http::HttpRouteEvidence::effect_profile",
            "pub enum vocab::http::LocalTxBoundary",
            "pub const vocab::http::LocalTxBoundary::ALL: &'static [Self]",
            "pub const fn vocab::http::LocalTxBoundary::as_label",
            "pub enum vocab::http::LocalTxModel",
            "pub enum vocab::http::LocalTxRetry",
            "pub enum vocab::http::LocalTxCommitUnknown",
        ] {
            assert!(
                baseline.contains(required),
                "vocab public-api golden 缺少 canonical HTTP evidence API: {required}"
            );
        }
        let exposed_fields = exposed_http_route_evidence_fields(&baseline);
        assert!(
            exposed_fields.is_empty(),
            "vocab HttpRouteEvidence 全部字段必须保持私有: {exposed_fields:?}"
        );
        for forbidden in [
            "pub vocab::http::HttpEffectProfile::effects:",
            "pub vocab::http::HttpRouteBinding::evidence:",
            "pub vocab::http::HttpRouteBinding::marker:",
            "impl<M, C> core::default::Default for vocab::http::HttpRouteBinding<M, C>",
            "impl core::default::Default for vocab::http::HttpEffectProfile",
        ] {
            assert!(
                !baseline.contains(forbidden),
                "vocab HTTP evidence 必须保持私有字段且无 Default: {forbidden}"
            );
        }
        Ok(())
    }

    #[test]
    fn consistency_public_api_golden_exposes_closed_local_tx_vocabulary() -> anyhow::Result<()> {
        let baseline = std::fs::read_to_string(baseline_dir()?.join("consistency.txt"))?;
        for required in [
            "pub use consistency::localtx::LocalTxBoundary",
            "pub use consistency::localtx::LocalTxCommitUnknown",
            "pub use consistency::localtx::LocalTxModel",
            "pub use consistency::localtx::LocalTxRetry",
            "pub enum consistency::localtx::LocalTxFinalStatus",
            "pub consistency::localtx::LocalTxFinalStatus::Committed",
            "pub consistency::localtx::LocalTxFinalStatus::RolledBack",
            "pub consistency::localtx::LocalTxFinalStatus::RollbackFailed",
            "pub consistency::localtx::LocalTxFinalStatus::CommitUnknown",
            "pub const consistency::localtx::LocalTxFinalStatus::ALL: &'static [Self]",
            "pub const fn consistency::localtx::LocalTxFinalStatus::as_label",
            "pub const consistency::tx_retry::TxRetryClass::ALL: &'static [Self]",
            "pub const consistency::tx_retry::TxRetryFinalStatus::ALL: &'static [Self]",
        ] {
            assert!(
                baseline.contains(required),
                "consistency public-api golden 缺少闭合 LocalTx API: {required}"
            );
        }
        Ok(())
    }

    #[test]
    fn http_route_evidence_private_field_guard_covers_all_fields() {
        let synthetic = r#"
pub vocab::http::HttpRouteEvidence::owner: vocab::http::HttpContractOwner
pub vocab::http::HttpRouteEvidence::contract: vocab::contract::binding::ContractBinding
pub vocab::http::HttpRouteEvidence::path: &'static str
pub vocab::http::HttpRouteEvidence::method: &'static str
pub vocab::http::HttpRouteEvidence::success_status: vocab::http::HttpSuccessStatus
pub vocab::http::HttpRouteEvidence::idempotency: vocab::http::HttpIdempotency
pub vocab::http::HttpRouteEvidence::auth: vocab::http::HttpRouteAuth
pub vocab::http::HttpRouteEvidence::resource: core::option::Option<&'static str>
pub vocab::http::HttpRouteEvidence::self_scoped: bool
pub vocab::http::HttpRouteEvidence::consistency_level: vocab::http::HttpConsistencyLevel
pub vocab::http::HttpRouteEvidence::effect_profile: vocab::http::HttpEffectProfile
"#;
        assert_eq!(
            exposed_http_route_evidence_fields(synthetic),
            vec![
                "owner",
                "contract",
                "path",
                "method",
                "success_status",
                "idempotency",
                "auth",
                "resource",
                "self_scoped",
                "consistency_level",
                "effect_profile",
            ],
            "a refreshed golden must not hide any newly public HttpRouteEvidence field"
        );
    }

    #[test]
    fn baseline_dir_is_public_api_under_root() -> anyhow::Result<()> {
        let dir = baseline_dir()?;
        assert!(dir.ends_with("public-api"));
        assert!(dir.parent().is_some());
        Ok(())
    }

    // ---- NIGHTLY-PIN-01：public-api 钉版 nightly（RUSTUP_TOOLCHAIN 重设）+ 三方 SoT 一致 ----

    /// `public_api_cmd` 构造 `cargo public-api -p <crate>`、cwd 为 None（与原 capture 行为一致）。
    #[test]
    fn public_api_cmd_sets_program_and_args() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "vocab",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        assert_eq!(cmd.get_program(), std::ffi::OsStr::new("cargo"));
        let args: Vec<&std::ffi::OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            vec![
                std::ffi::OsStr::new("public-api"),
                std::ffi::OsStr::new("-p"),
                std::ffi::OsStr::new("vocab"),
                std::ffi::OsStr::new("--omit"),
                std::ffi::OsStr::new("blanket-impls"),
            ]
        );
        assert_eq!(cmd.get_current_dir(), Some(root.as_path()));
        Ok(())
    }

    /// 传 `PINNED_NIGHTLY` 时 `RUSTUP_TOOLCHAIN` 被经 clean_cmd 显式重设为钉版 nightly
    /// （等价 `cargo +nightly-2026-04-16 public-api`，使 rustdoc-json 可复现）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
    #[test]
    fn public_api_cmd_injects_pinned_toolchain() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "ids",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(PINNED_NIGHTLY))),
            "RUSTUP_TOOLCHAIN 应被显式重设为 PINNED_NIGHTLY"
        );
        Ok(())
    }

    /// rustdoc-json 快照必须使用独占 target，避免前序 all-features/coverage 产物令同一 CI 首次
    /// `public-api internal --check` 漂移、立即重跑却转绿。
    #[test]
    fn public_api_cmd_isolates_rustdoc_json_target() -> anyhow::Result<()> {
        let expected = public_api_target_dir()?;
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(&root, "consistency", PINNED_NIGHTLY, &expected, false);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter().any(|(k, v)| {
                *k == std::ffi::OsStr::new("CARGO_TARGET_DIR") && *v == Some(expected.as_os_str())
            }),
            "public-api 须使用独占 CARGO_TARGET_DIR"
        );
        Ok(())
    }

    /// 经 clean_cmd 漏斗：除 `RUSTUP_TOOLCHAIN`（本步显式重设）外，其它 ambient toolchain/flag 变量
    /// （`RUSTC`/`RUSTDOC`/`RUSTFLAGS`/…）仍被 env_remove —— 剥离后由显式 env 成唯一来源（CMD-ENV-CLEAN-01）。
    #[test]
    fn public_api_cmd_strips_other_ambient_but_resets_toolchain() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(
            &root,
            "vocab",
            PINNED_NIGHTLY,
            &public_api_target_dir()?,
            false,
        );
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        for stripped in crate::cmd::STRIPPED_ENV
            .iter()
            .filter(|v| !matches!(**v, "RUSTUP_TOOLCHAIN" | "RUSTC_WRAPPER"))
        {
            assert!(
                envs.iter()
                    .any(|(k, v)| *k == std::ffi::OsStr::new(stripped) && v.is_none()),
                "{stripped} 应被 env_remove"
            );
        }
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(PINNED_NIGHTLY))),
            "RUSTUP_TOOLCHAIN 在剥离后由显式 env 重设"
        );
        let wrapper = envs
            .iter()
            .find(|(key, _)| *key == std::ffi::OsStr::new("RUSTC_WRAPPER"))
            .and_then(|(_, value)| *value);
        assert!(
            wrapper.is_none_or(|value| std::path::Path::new(value).is_absolute()),
            "RUSTC_WRAPPER 只能由 compiler-cache policy 注入绝对路径"
        );
        Ok(())
    }

    /// anti-vacuity：toolchain 入参透传（非把 `PINNED_NIGHTLY` 硬编码忽略参数）。
    #[test]
    fn public_api_cmd_toolchain_arg_flows_through() -> anyhow::Result<()> {
        let fake = "nightly-1999-01-01";
        let root = crate::workspace_root()?;
        let cmd = public_api_cmd(&root, "vocab", fake, &public_api_target_dir()?, false);
        let envs: Vec<(&std::ffi::OsStr, Option<&std::ffi::OsStr>)> = cmd.get_envs().collect();
        assert!(
            envs.iter()
                .any(|(k, v)| *k == std::ffi::OsStr::new("RUSTUP_TOOLCHAIN")
                    && *v == Some(std::ffi::OsStr::new(fake))),
            "toolchain 入参应透传进 RUSTUP_TOOLCHAIN"
        );
        Ok(())
    }

    #[test]
    fn release_capture_uses_all_features_without_changing_internal_capture() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let target = public_api_target_dir()?;
        let release = public_api_cmd(&root, "vocab", PINNED_NIGHTLY, &target, true);
        let internal = public_api_cmd(&root, "vocab", PINNED_NIGHTLY, &target, false);
        assert!(release.get_args().any(|arg| arg == "--all-features"));
        assert!(!internal.get_args().any(|arg| arg == "--all-features"));
        Ok(())
    }

    #[test]
    fn public_api_library_pin_matches_cli_tool_catalog() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let manifest = std::fs::read_to_string(root.join("Cargo.toml"))?.parse::<toml::Value>()?;
        let dependency = manifest["workspace"]["dependencies"]["public-api"]["version"]
            .as_str()
            .context("workspace public-api dependency must carry an exact version")?;
        let catalog = std::fs::read_to_string(root.join(".github/scripts/ci-tool-catalog.txt"))?;
        let cli = catalog
            .lines()
            .find_map(|line| {
                let mut fields = line.split('|');
                (fields.next() == Some("cargo-public-api"))
                    .then(|| fields.next())
                    .flatten()
            })
            .context("cargo-public-api tool catalog row is missing")?;
        assert_eq!(dependency, format!("={cli}"));
        Ok(())
    }

    // 三方 pinned-nightly SoT 解析（仅 test 用——production 无消费方读这两文件）。

    /// 从 `rust-toolchain.toml` 文本取 `[toolchain].channel`。
    fn parse_toolchain_channel(toml_src: &str) -> Option<String> {
        toml_src
            .parse::<toml::Value>()
            .ok()?
            .get("toolchain")?
            .get("channel")?
            .as_str()
            .map(str::to_owned)
    }

    /// 从 GitHub CI workflow 文本取 `RSS_NIGHTLY_PINNED` 变量值：行扫描，先 `split('#')` 剥注释、
    /// 再结构绑定 `RSS_NIGHTLY_PINNED:` 前缀——防注释内同名误满足（无 serde_yaml 依赖）。
    fn github_ci_nightly_pinned(yaml_src: &str) -> Option<String> {
        yaml_src.lines().find_map(|line| {
            let code = line.split('#').next().unwrap_or("").trim();
            let rest = code.strip_prefix("RSS_NIGHTLY_PINNED:")?;
            Some(rest.trim().to_owned())
        })
    }

    /// 三方 pinned-nightly 是否一致。
    fn nightly_pins_agree(const_val: &str, channel: &str, github_ci: &str) -> bool {
        const_val == channel && channel == github_ci
    }

    #[test]
    fn parse_toolchain_channel_extracts_channel() {
        assert_eq!(
            parse_toolchain_channel("[toolchain]\nchannel = \"nightly-2026-04-16\"\n").as_deref(),
            Some("nightly-2026-04-16")
        );
        // 缺 channel → None（不静默成空串）。
        assert_eq!(
            parse_toolchain_channel("[toolchain]\nprofile = \"minimal\"\n"),
            None
        );
    }

    #[test]
    fn github_ci_nightly_pinned_extracts_value() {
        assert_eq!(
            github_ci_nightly_pinned("env:\n  RSS_NIGHTLY_PINNED: nightly-2026-04-16\n").as_deref(),
            Some("nightly-2026-04-16")
        );
        // 值后带行尾注释：split('#') 剥注释后取值（YAML unquoted scalar 行尾注释语义，刻意支持）。
        assert_eq!(
            github_ci_nightly_pinned("  RSS_NIGHTLY_PINNED: nightly-2026-04-16 # 钉版\n")
                .as_deref(),
            Some("nightly-2026-04-16")
        );
        // synthetic red（fail-closed）：仅注释行不可误满足（对标 verify.rs codex F1）。
        assert_eq!(
            github_ci_nightly_pinned("  # RSS_NIGHTLY_PINNED: nightly-2026-04-16\n"),
            None
        );
    }

    #[test]
    fn nightly_pin_predicate_green_and_red() {
        let p = PINNED_NIGHTLY;
        // 绿：三相等。
        assert!(nightly_pins_agree(p, p, p));
        // 红：逐方向构造不一致三元组均 false（守卫非恒真）。
        let other = "nightly-2026-05-01";
        assert!(!nightly_pins_agree(p, p, other));
        assert!(!nightly_pins_agree(p, other, p));
        assert!(!nightly_pins_agree(other, p, p));
    }

    /// anti-vacuity 真实绿例：从真实 `lints/rust-toolchain.toml` + reusable workflow 解析，断言
    /// 三方功能 pinned-nightly 一致（`PINNED_NIGHTLY` == lints channel == GitHub CI `RSS_NIGHTLY_PINNED`）。
    /// 第四处镜像（verify.rs public-api install_hint）由 `verify::tests::public_api_install_hint_pins_nightly`
    /// 守——绑真实 install_hint 字段值（非源码全文，避免注释含 pin 的误绿）。INVARIANT: NIGHTLY-PIN-01 { level = "Medium", exec = "release-check", source = "public-api" }.
    #[test]
    fn pinned_nightly_single_source_of_truth() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let toolchain_toml =
            std::fs::read_to_string(root.join("lints").join("rust-toolchain.toml"))?;
        let github_ci_yaml = std::fs::read_to_string(
            root.join(".github")
                .join("workflows")
                .join("rss-rust-job.yml"),
        )?;
        let channel = parse_toolchain_channel(&toolchain_toml)
            .ok_or_else(|| anyhow::anyhow!("lints/rust-toolchain.toml 应有 [toolchain].channel"))?;
        let github_ci = github_ci_nightly_pinned(&github_ci_yaml).ok_or_else(|| {
            anyhow::anyhow!(".github/workflows/rss-rust-job.yml 应有 RSS_NIGHTLY_PINNED 变量")
        })?;
        assert!(
            nightly_pins_agree(PINNED_NIGHTLY, &channel, &github_ci),
            "pinned nightly 三方漂移：PINNED_NIGHTLY={PINNED_NIGHTLY}, lints channel={channel}, github_ci={github_ci}"
        );
        Ok(())
    }

    #[test]
    fn release_selection_delta_checks_only_intersection_and_records_explicit_removal() {
        let current = BTreeSet::from(["added".to_owned(), "kept".to_owned()]);
        let base = BTreeSet::from(["kept".to_owned(), "removed".to_owned()]);
        let delta = ReleaseSelectionDelta::derive(&current, &base);
        assert_eq!(delta.semver_packages, vec!["kept"]);
        assert_eq!(delta.first_release_packages, vec!["added"]);
        assert_eq!(delta.removed_packages, vec!["removed"]);
    }

    #[test]
    fn semver_command_is_per_package_all_features_and_revision_bound() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let command = semver_check_cmd(
            &root,
            "facade",
            "0123456789abcdef0123456789abcdef01234567",
            ApiProfile::AllFeatures,
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "semver-checks",
                "check-release",
                "--package",
                "facade",
                "--all-features",
                "--baseline-rev",
                "0123456789abcdef0123456789abcdef01234567",
            ]
        );
        assert!(!args.iter().any(|arg| arg == "--workspace"));
        let default = semver_check_cmd(
            &root,
            "facade",
            "0123456789abcdef0123456789abcdef01234567",
            ApiProfile::Default,
        );
        assert!(!default.get_args().any(|arg| arg == "--all-features"));
        Ok(())
    }

    #[test]
    fn semver_runner_checks_both_profiles_for_every_selected_intersection_and_aggregates() {
        let packages = vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()];
        let mut called = Vec::new();
        let error = run_semver_packages(&packages, |package, profile| {
            called.push((package.to_owned(), profile));
            if matches!(package, "alpha" | "gamma") && profile == ApiProfile::Default {
                bail!("synthetic breaking change")
            }
            Ok(())
        })
        .err()
        .map(|error| error.to_string());
        assert_eq!(called.len(), packages.len() * 2);
        for package in &packages {
            assert!(called.contains(&(package.clone(), ApiProfile::Default)));
            assert!(called.contains(&(package.clone(), ApiProfile::AllFeatures)));
        }
        let error = error.as_deref().unwrap_or("");
        assert!(error.contains("2 项 SemVer 校验失败"));
        assert!(error.contains("package=alpha"));
        assert!(error.contains("package=gamma"));
        assert!(error.contains("profile=default"));
    }

    #[test]
    fn release_capture_combines_default_and_all_features_without_unioning_them() {
        let capture = combine_release_captures(
            ApiCapture {
                baseline: "pub fn facade::default_only()\n".to_owned(),
                rustdoc_json: vec![(ApiProfile::Default, PathBuf::from("default.json"))],
            },
            ApiCapture {
                baseline: "pub fn facade::feature_only()\n".to_owned(),
                rustdoc_json: vec![(ApiProfile::AllFeatures, PathBuf::from("all.json"))],
            },
        );
        assert!(capture.baseline.contains("profile: default"));
        assert!(capture.baseline.contains("facade::default_only"));
        assert!(capture.baseline.contains("profile: all-features"));
        assert!(capture.baseline.contains("facade::feature_only"));
        assert_eq!(capture.rustdoc_json.len(), 2);
    }

    #[test]
    fn semver_failure_preserves_both_labeled_channels_and_exit_class() {
        let message = format_semver_failure(Some(100), b"lint: function_missing", b"major bump");
        assert!(message.contains("compatibility-violation"));
        assert!(message.contains("stdout:\nlint: function_missing"));
        assert!(message.contains("stderr:\nmajor bump"));
        assert!(format_semver_failure(Some(101), b"", b"boom").contains("tool-failure"));
    }

    #[test]
    fn semver_lazy_prerequisite_honors_explicit_missing_tool_policy() {
        assert!(semver_tool_action(true, false).is_ok_and(|run| run));
        assert!(semver_tool_action(false, true).is_ok_and(|run| !run));
        assert!(semver_tool_action(false, false).is_err());
    }

    #[test]
    fn release_stage_collector_continues_and_sorts_independent_failures() {
        let mut called = Vec::new();
        let mut failures = Vec::new();
        for (stage, subject) in [(3, "leakage"), (0, "internal"), (2, "release")] {
            collect_release_stage::<()>(&mut failures, stage, subject, || {
                called.push(subject);
                bail!("synthetic {subject} failure")
            });
        }
        failures.sort();
        assert_eq!(called, ["leakage", "internal", "release"]);
        assert_eq!(
            failures
                .iter()
                .map(|failure| failure.subject.as_str())
                .collect::<Vec<_>>(),
            ["internal", "release", "leakage"]
        );
    }

    #[test]
    fn structured_tokens_find_nested_reexport_error_and_conversion_type_paths() {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let tokens = vec![
            Identifier("core".into()),
            Symbol("::".into()),
            Type("Result".into()),
            Symbol("<".into()),
            Identifier("internal_crate".into()),
            Symbol("::".into()),
            Identifier("errors".into()),
            Symbol("::".into()),
            Type("SecretError".into()),
            Symbol(",".into()),
            Identifier("tracing".into()),
            Symbol("::".into()),
            Type("Span".into()),
            Symbol(">".into()),
        ];

        assert_eq!(
            referenced_type_paths(&tokens),
            BTreeSet::from([
                "core::Result".to_owned(),
                "internal_crate::errors::SecretError".to_owned(),
                "tracing::Span".to_owned(),
            ])
        );
    }

    #[test]
    fn owner_policy_is_closed_and_anti_vacuous() {
        let workspace = BTreeSet::from(["facade".to_owned(), "internal_crate".to_owned()]);
        let selected = BTreeSet::from(["facade".to_owned()]);
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::PlatformPublic,
                "facade",
                "internal_crate::Secret",
                &workspace,
                &selected,
                None,
            ),
            Some("internal_crate")
        );
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::StandaloneComponent,
                "facade",
                "tracing::Span",
                &workspace,
                &selected,
                None,
            ),
            None
        );
        assert_eq!(
            forbidden_type_root(
                workspacefacts::PublicApiOwner::StandaloneComponent,
                "facade",
                "opentelemetry_sdk::trace::Tracer",
                &workspace,
                &selected,
                None,
            ),
            Some("opentelemetry_sdk")
        );
    }

    #[test]
    fn nonempty_release_surface_green_and_forbidden_workspace_type_red() -> anyhow::Result<()> {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let facts = facts_with_nonempty_release_surface()?;
        let (surface, findings) = crate::release_surface::validate(&facts, &[]);
        assert!(
            findings.is_empty(),
            "synthetic Release Surface must be valid: {findings:?}"
        );
        let surface = surface.context("synthetic Release Surface missing")?;

        let green = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                rendered: "pub fn alpha_release::clean() -> core::Result".to_owned(),
                tokens: vec![
                    Identifier("alpha_release".into()),
                    Symbol("::".into()),
                    Type("Public".into()),
                    Identifier("core".into()),
                    Symbol("::".into()),
                    Type("Result".into()),
                ],
                source_paths: BTreeSet::new(),
            }],
        )]);
        assert!(release_api_findings_from_items(&facts, &surface, &green)?.is_empty());

        let red = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                rendered: "pub fn alpha_release::leak() -> vocab::Secret".to_owned(),
                tokens: vec![
                    Identifier("vocab".into()),
                    Symbol("::".into()),
                    Type("Secret".into()),
                ],
                source_paths: BTreeSet::new(),
            }],
        )]);
        let findings = release_api_findings_from_items(&facts, &surface, &red)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding
                    .subject
                    .contains("package=alpha-release/module=alpha_release::leak")
                && finding.detail.contains("vocab::Secret")
        }));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == ReleaseApiRule::PublicDependency)
        );

        let reexport_red = BTreeMap::from([(
            "alpha-release".to_owned(),
            vec![ApiItemProjection {
                rendered: "pub use alpha_release::Secret".to_owned(),
                tokens: vec![
                    Identifier("alpha_release".into()),
                    Symbol("::".into()),
                    Type("Secret".into()),
                ],
                source_paths: BTreeSet::from(["vocab::Secret".to_owned()]),
            }],
        )]);
        let findings = release_api_findings_from_items(&facts, &surface, &reexport_red)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding.detail.contains("vocab::Secret")
        }));
        Ok(())
    }

    #[test]
    fn checked_in_rustdoc_fixture_crosses_builder_and_source_identity_projection() -> Result<()> {
        let facts = facts_with_nonempty_release_surface()?;
        let (surface, validation) = crate::release_surface::validate(&facts, &[]);
        assert!(validation.is_empty(), "{validation:?}");
        let surface = surface.context("synthetic Release Surface missing")?;
        let fixture =
            crate::workspace_root()?.join("xtask/tests/fixtures/release_api/reexport.json");
        let captures = BTreeMap::from([(
            "alpha-release".to_owned(),
            ApiCapture {
                baseline: String::new(),
                rustdoc_json: vec![
                    (ApiProfile::Default, fixture.clone()),
                    (ApiProfile::AllFeatures, fixture),
                ],
            },
        )]);

        let findings = release_api_findings(&facts, &surface, &captures)?;
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::ForbiddenType
                && finding.detail.contains("vocab::Secret")
        }));
        for profile in ApiProfile::RELEASE {
            assert!(findings.iter().any(|finding| {
                finding
                    .subject
                    .contains(&format!("profile={}", profile.label()))
            }));
        }
        assert!(findings.iter().any(|finding| {
            finding.rule == ReleaseApiRule::PublicDependency
                && finding.subject.contains("package=alpha-release")
        }));
        Ok(())
    }

    #[test]
    fn typed_rustdoc_source_ids_cover_reexports_and_nested_resolved_paths() {
        let value = json!({
            "inner": {
                "use": {"source":"vocab::Secret","name":"Secret","id": 17,"is_glob":false},
                "function": {"output":{"resolved_path":{"path":"Alias","id":23,"args":null}}}
            }
        });
        let mut ids = BTreeSet::new();
        collect_source_ids(&value, &mut ids);
        assert_eq!(ids, BTreeSet::from([17, 23]));
    }

    #[test]
    fn selected_direct_normal_dependency_is_allowed_through_cargo_rename() -> anyhow::Result<()> {
        use public_api::tokens::Token::{Identifier, Symbol, Type};

        let facts = facts_with_selected_renamed_dependency()?;
        let (surface, validation) = crate::release_surface::validate(&facts, &[]);
        assert!(validation.is_empty(), "{validation:?}");
        let surface = surface.context("synthetic selected dependency surface missing")?;
        let items = BTreeMap::from([
            (
                "alpha-release".to_owned(),
                vec![ApiItemProjection {
                    rendered: "pub fn facade_api::api() -> beta_api::Public".to_owned(),
                    tokens: vec![
                        Identifier("facade_api".into()),
                        Symbol("::".into()),
                        Type("OwnPublic".into()),
                        Identifier("beta_api".into()),
                        Symbol("::".into()),
                        Type("Public".into()),
                    ],
                    source_paths: BTreeSet::new(),
                }],
            ),
            (
                "beta-release".to_owned(),
                vec![ApiItemProjection {
                    rendered: "pub struct beta_release::Public".to_owned(),
                    tokens: vec![Type("Public".into())],
                    source_paths: BTreeSet::new(),
                }],
            ),
        ]);
        assert!(release_api_findings_from_items(&facts, &surface, &items)?.is_empty());
        Ok(())
    }
}
