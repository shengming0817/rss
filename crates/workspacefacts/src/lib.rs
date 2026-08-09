//! Owned、窄语义的 Cargo workspace facts façade。
//!
//! `cargo metadata --locked --all-features --format-version 1` 的执行由调用方持有；本 crate
//! 用 guppy `PackageGraph` 持有 catalog、用私有 `CargoSet` 解析 root selection，并且只暴露
//! RSS tooling consumer 已使用的 owned facts。

#[cfg(feature = "test-support")]
pub mod testing;

mod build;
mod declarations;
mod release;

pub use build::{
    ActivationNode, ActivationPath, BuildFacts, BuildPlatforms, BuildSelection, BuildSide,
    CargoPlatform, FeatureKey, FeatureSelection, ResolverVersion,
};
pub use release::{
    ApiStability, OfficialProfile, PublicApiOwner, ReleasePackageSelection,
    ReleaseProfileArtifactSelection, ReleaseSelection, ReleaseSelectionError,
    parse_release_selection,
};

use declarations::{
    PackageIndexes, index_resolve_nodes, parse_raw_metadata, project_direct_declarations,
};
use guppy::graph::{
    BuildTargetId, BuildTargetKind, DependencyDirection, PackageGraph, PackagePublish,
};
use semver::{Version, VersionReq};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Cargo package-name typed identity（进程内；不承诺跨进程稳定编码）。
///
/// 可包装 workspace member **或** resolve 图中的外部 package name——例如
/// [`DependencyResolution::Resolved`] 对 registry / path / git 依赖亦持有本类型。
/// Workspace-only 查询（[`WorkspaceFacts::package_key`]、[`WorkspaceFacts::targets_for`]、
/// [`WorkspaceFacts::direct_dependencies_for`]、[`WorkspaceFacts::repo_relative_root_for`] 等）
/// 在 key 不是当前 workspace member 时返回 [`WorkspaceFactsError::UnknownPackage`]。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageKey(String);

impl PackageKey {
    /// 返回 Cargo package name。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cargo target 的窄分类；不泄漏 guppy/Cargo opaque target identity。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TargetKind {
    Library,
    ProcMacro,
    Binary,
    Test,
    Example,
    Benchmark,
    BuildScript,
    /// Guppy/Cargo 后续新增的 target identity；不得误投影成现有 eligibility。
    Other,
}

/// Workspace member 的 owned package catalog 条目；不泄漏 guppy identity / lifetime。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspacePackageFacts {
    key: PackageKey,
    repo_relative_root: PathBuf,
    version: Version,
    minimum_rust_version: Option<Version>,
    publish_policy: PublishPolicy,
    publish_metadata: PackagePublishMetadata,
}

impl WorkspacePackageFacts {
    #[must_use]
    pub fn key(&self) -> &PackageKey {
        &self.key
    }

    /// Package root 相对 workspace root 的路径；根包为空路径。
    #[must_use]
    pub fn repo_relative_root(&self) -> &Path {
        &self.repo_relative_root
    }

    /// Cargo-resolved package version.
    #[must_use]
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Cargo-resolved minimum supported Rust version, when declared.
    #[must_use]
    pub fn minimum_rust_version(&self) -> Option<&Version> {
        self.minimum_rust_version.as_ref()
    }

    /// Cargo `publish` policy projected without conflating unrestricted and disabled.
    #[must_use]
    pub fn publish_policy(&self) -> &PublishPolicy {
        &self.publish_policy
    }

    #[must_use]
    pub fn publish_metadata(&self) -> &PackagePublishMetadata {
        &self.publish_metadata
    }
}

/// Cargo-owned package metadata required before a package can enter the positive Release Surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackagePublishMetadata {
    description: Option<String>,
    license: Option<String>,
    license_file: Option<PathBuf>,
    repository: Option<String>,
    readme: Option<PathBuf>,
    categories: BTreeSet<String>,
    keywords: BTreeSet<String>,
    features: BTreeMap<String, BTreeSet<String>>,
}

impl PackagePublishMetadata {
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[must_use]
    pub fn license(&self) -> Option<&str> {
        self.license.as_deref()
    }

    #[must_use]
    pub fn license_file(&self) -> Option<&Path> {
        self.license_file.as_deref()
    }

    #[must_use]
    pub fn repository(&self) -> Option<&str> {
        self.repository.as_deref()
    }

    #[must_use]
    pub fn readme(&self) -> Option<&Path> {
        self.readme.as_deref()
    }

    #[must_use]
    pub fn categories(&self) -> &BTreeSet<String> {
        &self.categories
    }

    #[must_use]
    pub fn keywords(&self) -> &BTreeSet<String> {
        &self.keywords
    }

    #[must_use]
    pub fn features(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.features
    }
}

/// Owned projection of Cargo's three-state `publish` semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublishPolicy {
    /// `publish = false`, represented by Cargo metadata as an empty registry list.
    Disabled,
    /// No registry restriction (`publish = null` in Cargo metadata).
    Unrestricted,
    /// Publication is limited to this non-empty, stably ordered registry set.
    Registries(BTreeSet<String>),
}

impl PublishPolicy {
    #[must_use]
    pub const fn is_publishable(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// Manifest dependency section kind；闭合枚举，不泄漏 guppy `DependencyKind`。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyKind {
    Normal,
    Dev,
    Build,
}

impl DependencyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Dev => "dev",
            Self::Build => "build",
        }
    }
}

/// Git dependency 请求形态；对应 guppy `GitReq` 的 owned 投影。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GitDependencyReq {
    Default,
    Branch(String),
    Tag(String),
    Rev(String),
}

/// Resolved package source 的闭合 owned 表达；不泄漏 guppy lifetime。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencySource {
    Workspace {
        repo_relative_root: PathBuf,
    },
    Path {
        repo_relative_root: PathBuf,
    },
    Registry {
        url: String,
    },
    Sparse {
        url: String,
    },
    Git {
        repository: String,
        req: GitDependencyReq,
        resolved: String,
    },
    UnknownExternal {
        source: String,
    },
}

/// Manifest dependency 到 resolve graph 的关联结果。
///
/// 不按 package name 猜测；无法在 resolve 中唯一匹配时为 [`Self::Unresolved`]，多包冲突在加载期
/// fail-closed（[`WorkspaceFactsError::AmbiguousDependencyResolution`]）。
///
/// [`Self::Resolved`] 持有的 [`PackageKey`] 是 Cargo package-name identity，**不保证**是 workspace
/// member（外部依赖同样用本变体包装）。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DependencyResolution {
    Resolved(PackageKey),
    Unresolved,
}

/// 单条 manifest dependency declaration 事实（声明粒度，非 Guppy `PackageLink` 折叠投影）。
///
/// `name` 是 rename 后的 manifest dependency key。同一 resolved package 的多个 rename、以及同一
/// key 的 unconditional + target-conditioned 声明各自保留一条。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectDependencyFacts {
    dependent: PackageKey,
    resolution: DependencyResolution,
    name: String,
    kind: DependencyKind,
    source: DependencySource,
    version_requirement: VersionReq,
    optional: bool,
    uses_default_features: bool,
    unconditional: bool,
    requested_features: BTreeSet<String>,
}

impl DirectDependencyFacts {
    #[must_use]
    pub fn dependent(&self) -> &PackageKey {
        &self.dependent
    }

    #[must_use]
    pub fn resolution(&self) -> &DependencyResolution {
        &self.resolution
    }

    /// Resolved package identity when uniquely matched in `resolve.nodes`.
    #[must_use]
    pub fn resolved(&self) -> Option<&PackageKey> {
        match &self.resolution {
            DependencyResolution::Resolved(key) => Some(key),
            DependencyResolution::Unresolved => None,
        }
    }

    /// Manifest dependency name after rename（Cargo metadata `rename` key，否则 package name）。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> DependencyKind {
        self.kind
    }

    #[must_use]
    pub fn source(&self) -> &DependencySource {
        &self.source
    }

    #[must_use]
    pub fn version_requirement(&self) -> &VersionReq {
        &self.version_requirement
    }

    #[must_use]
    pub const fn optional(&self) -> bool {
        self.optional
    }

    #[must_use]
    pub const fn uses_default_features(&self) -> bool {
        self.uses_default_features
    }

    /// 该 declaration 的 `target` 是否为 `null`（无 target 条件）。
    #[must_use]
    pub const fn unconditional(&self) -> bool {
        self.unconditional
    }

    /// Features requested by this exact Cargo dependency declaration.
    #[must_use]
    pub fn requested_features(&self) -> &BTreeSet<String> {
        &self.requested_features
    }
}

/// Consumer 所需的 owned target facts。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetFacts {
    name: String,
    kind: TargetKind,
    required_features: Vec<String>,
    repo_relative_src_path: PathBuf,
    test_by_default: bool,
}

impl TargetFacts {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        self.kind
    }

    #[must_use]
    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }

    #[must_use]
    pub fn repo_relative_src_path(&self) -> &Path {
        &self.repo_relative_src_path
    }

    /// Cargo metadata 的 target `test` 字段；不是 custom harness presence。
    #[must_use]
    pub const fn test_by_default(&self) -> bool {
        self.test_by_default
    }
}

#[derive(Clone, Debug, Error)]
pub enum WorkspaceFactsError {
    #[error("cargo metadata/guppy graph invalid: {0}")]
    InvalidMetadata(String),
    #[error("metadata workspace root mismatch: expected `{expected}`, got `{actual}`")]
    WorkspaceRootMismatch { expected: PathBuf, actual: PathBuf },
    #[error("workspace root must be an absolute normalized UTF-8 path: `{0}`")]
    InvalidWorkspaceRoot(PathBuf),
    #[error("metadata path escapes workspace root: `{0}`")]
    WorkspacePathEscape(PathBuf),
    #[error("repo-relative path must not be absolute or contain parent traversal: `{0}`")]
    InvalidRepoPath(PathBuf),
    #[error("unknown workspace package `{0}`")]
    UnknownPackage(String),
    #[error("unknown feature `{package}/{feature}`")]
    UnknownFeature { package: String, feature: String },
    #[error("unknown Cargo platform: {0}")]
    UnknownPlatform(String),
    #[error("incomplete Guppy feature graph: {0}")]
    IncompleteFeatureGraph(String),
    #[error("Cargo build query failed: {0}")]
    BuildQuery(String),
    #[error(
        "enabled feature `{package}/{feature}` on {side} has no path from selected root `{root}`"
    )]
    UnexplainedFeatureActivation {
        root: String,
        package: String,
        feature: String,
        side: String,
    },
    #[error("guppy package query failed: {0}")]
    Query(String),
    #[error("ambiguous dependency resolution for `{dependent}` key `{name}` ({kind}): {detail}")]
    AmbiguousDependencyResolution {
        dependent: String,
        name: String,
        kind: String,
        detail: String,
    },
    #[error("unknown Cargo dependency kind `{0}`")]
    UnknownDependencyKind(String),
}

pub(crate) fn map_query_err(error: impl ToString) -> WorkspaceFactsError {
    WorkspaceFactsError::Query(error.to_string())
}

#[derive(Debug)]
struct PackageRecord {
    repo_relative_root: PathBuf,
    version: Version,
    minimum_rust_version: Option<Version>,
    publish_policy: PublishPolicy,
    publish_metadata: PackagePublishMetadata,
    targets: Vec<TargetFacts>,
    direct_dependencies: Vec<DirectDependencyFacts>,
}

/// 单次 `PackageGraph` 加载后共享的 workspace facts。
#[derive(Debug)]
pub struct WorkspaceFacts {
    graph: PackageGraph,
    packages: BTreeMap<PackageKey, PackageRecord>,
    package_roots: Vec<(PathBuf, PackageKey)>,
    release_selection: Result<Option<ReleaseSelection>, ReleaseSelectionError>,
}

impl WorkspaceFacts {
    /// 从调用方取得的完整 Cargo metadata JSON 构造事实图。
    ///
    /// # 双解析职责
    ///
    /// 1. **Declaration parse/validate**（`declarations` 模块）：严格解析
    ///    `packages[].dependencies` 与 `resolve.nodes[].deps[].dep_kinds`，在 guppy 之前
    ///    fail-closed（缺失 / null / 空 `dep_kinds`、畸形 optional 字段等）。
    /// 2. **Guppy catalog**：同一份 JSON 经 `PackageGraph::from_json` 建立 workspace member
    ///    catalog / target / reverse-query 图；declaration 投影再挂到各 member record。
    ///
    /// Guppy `PackageLink` 会折叠同 from→to 的多 rename / target 声明，故 declaration 路径
    /// 不可省略。两路共用同一 JSON，任一失败即整体失败。
    pub fn from_metadata_json(
        expected_root: &Path,
        metadata_json: &str,
    ) -> Result<Self, WorkspaceFactsError> {
        validate_workspace_root(expected_root)?;
        let raw = parse_raw_metadata(metadata_json)?;
        let graph = PackageGraph::from_json(metadata_json)
            .map_err(|error| WorkspaceFactsError::InvalidMetadata(error.to_string()))?;
        let actual_root = graph.workspace().root().as_std_path();
        if actual_root != expected_root {
            return Err(WorkspaceFactsError::WorkspaceRootMismatch {
                expected: expected_root.to_path_buf(),
                actual: actual_root.to_path_buf(),
            });
        }
        let release_selection =
            release::parse_release_selection(graph.workspace().metadata_table());

        let indexes = PackageIndexes::build(&raw.packages);
        let workspace_member_ids = raw
            .workspace_members
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let resolve_by_package = index_resolve_nodes(&raw.resolve);

        let mut packages = BTreeMap::new();
        let mut package_roots = Vec::new();
        for (workspace_path, package) in graph.workspace().iter_by_path() {
            let root = normalize_relative_path(workspace_path.as_std_path())?;
            let key = PackageKey(package.name().to_owned());
            let version = package.version().clone();
            let minimum_rust_version = package.minimum_rust_version().cloned();
            let publish_policy = match package.publish() {
                PackagePublish::Unrestricted => PublishPolicy::Unrestricted,
                PackagePublish::Registries([]) => PublishPolicy::Disabled,
                PackagePublish::Registries(registries) => {
                    PublishPolicy::Registries(registries.iter().cloned().collect())
                }
                _ => {
                    return Err(WorkspaceFactsError::InvalidMetadata(
                        "unsupported Cargo publish policy".to_owned(),
                    ));
                }
            };
            let mut targets = package
                .build_targets()
                .map(|target| {
                    let kind = match target.id() {
                        BuildTargetId::Library => match target.kind() {
                            BuildTargetKind::ProcMacro => TargetKind::ProcMacro,
                            _ => TargetKind::Library,
                        },
                        BuildTargetId::BuildScript => TargetKind::BuildScript,
                        BuildTargetId::Binary(_) => TargetKind::Binary,
                        BuildTargetId::Example(_) => TargetKind::Example,
                        BuildTargetId::Test(_) => TargetKind::Test,
                        BuildTargetId::Benchmark(_) => TargetKind::Benchmark,
                        _ => TargetKind::Other,
                    };
                    let absolute_src_path = target.path().as_std_path();
                    let relative_src_path =
                        absolute_src_path.strip_prefix(expected_root).map_err(|_| {
                            WorkspaceFactsError::WorkspacePathEscape(
                                absolute_src_path.to_path_buf(),
                            )
                        })?;
                    Ok(TargetFacts {
                        name: target.name().to_owned(),
                        kind,
                        required_features: target.required_features().to_vec(),
                        repo_relative_src_path: normalize_relative_path(relative_src_path)?,
                        test_by_default: target.test_by_default(),
                    })
                })
                .collect::<Result<Vec<_>, WorkspaceFactsError>>()?;
            targets
                .sort_by(|left, right| (&left.kind, &left.name).cmp(&(&right.kind, &right.name)));

            let package_id = package.id().repr();
            if !workspace_member_ids.contains(package_id) {
                return Err(WorkspaceFactsError::InvalidMetadata(format!(
                    "guppy workspace member `{package_id}` missing from metadata workspace_members"
                )));
            }
            let raw_package = indexes.package(package_id).ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata(format!(
                    "workspace member `{package_id}` missing from metadata packages"
                ))
            })?;
            let publish_metadata = PackagePublishMetadata {
                description: raw_package.description.clone(),
                license: raw_package.license.clone(),
                license_file: raw_package.license_file.as_deref().map(PathBuf::from),
                repository: raw_package.repository.clone(),
                readme: raw_package.readme.as_deref().map(PathBuf::from),
                categories: raw_package.categories.clone(),
                keywords: raw_package.keywords.clone(),
                features: raw_package.features.clone(),
            };
            let resolve_deps = resolve_by_package.get(package_id).copied().unwrap_or(&[]);
            let direct_dependencies = project_direct_declarations(
                &key,
                &raw_package.dependencies,
                resolve_deps,
                &indexes,
                &graph,
                expected_root,
            )?;

            package_roots.push((root.clone(), key.clone()));
            packages.insert(
                key,
                PackageRecord {
                    repo_relative_root: root,
                    version,
                    minimum_rust_version,
                    publish_policy,
                    publish_metadata,
                    targets,
                    direct_dependencies,
                },
            );
        }
        package_roots.sort_by(|(left, _), (right, _)| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| left.cmp(right))
        });

        Ok(Self {
            graph,
            packages,
            package_roots,
            release_selection,
        })
    }

    /// Return the strict positive Release Surface declaration, if the root workspace declares it.
    ///
    /// Invalid governance metadata is retained as a typed error instead of preventing unrelated
    /// Cargo facts from loading, so the canonical xtask gate can emit a structured finding.
    pub fn release_selection(&self) -> Result<Option<&ReleaseSelection>, ReleaseSelectionError> {
        match &self.release_selection {
            Ok(selection) => Ok(selection.as_ref()),
            Err(error) => Err(error.clone()),
        }
    }

    pub fn package_key(&self, name: &str) -> Result<PackageKey, WorkspaceFactsError> {
        let key = PackageKey(name.to_owned());
        self.packages
            .contains_key(&key)
            .then_some(key)
            .ok_or_else(|| WorkspaceFactsError::UnknownPackage(name.to_owned()))
    }

    /// 返回仅含 workspace members 的 owned package catalog。
    ///
    /// 顺序按 [`PackageKey`] 字典序稳定；与内部最深路径 ownership 扫描顺序无关。返回值不借用本
    /// owner，可在 `WorkspaceFacts` drop 后继续使用。
    #[must_use]
    pub fn workspace_packages(&self) -> Vec<WorkspacePackageFacts> {
        self.packages
            .iter()
            .map(|(key, record)| WorkspacePackageFacts {
                key: key.clone(),
                repo_relative_root: record.repo_relative_root.clone(),
                version: record.version.clone(),
                minimum_rust_version: record.minimum_rust_version.clone(),
                publish_policy: record.publish_policy.clone(),
                publish_metadata: record.publish_metadata.clone(),
            })
            .collect()
    }

    /// 返回拥有给定仓库路径的 workspace package。
    ///
    /// `path` 必须是相对 workspace root 的 repo-relative 路径；绝对路径或含 `..` 的路径会被拒绝。
    /// 嵌套 package root 按最深匹配解析，返回值是 owned key。
    pub fn package_for_repo_path(
        &self,
        path: &Path,
    ) -> Result<Option<PackageKey>, WorkspaceFactsError> {
        let normalized = normalize_relative_path(path)?;
        Ok(self
            .package_roots
            .iter()
            .find(|(root, _)| root.as_os_str().is_empty() || normalized.starts_with(root))
            .map(|(_, key)| key.clone()))
    }

    /// 计算 seed package 的 workspace 反向依赖闭包。
    ///
    /// 结果包含 seeds 自身，只保留 workspace members，不包含 external packages。返回 owned、按
    /// [`PackageKey`] 稳定排序的集合。
    pub fn reverse_workspace_closure(
        &self,
        seeds: &BTreeSet<PackageKey>,
    ) -> Result<BTreeSet<PackageKey>, WorkspaceFactsError> {
        let workspace = self.graph.workspace();
        let packages = seeds
            .iter()
            .map(|seed| {
                workspace
                    .member_by_name(seed.as_str())
                    .map_err(|_| WorkspaceFactsError::UnknownPackage(seed.as_str().to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let query = self
            .graph
            .query_reverse(packages.iter().map(|package| package.id()))
            .map_err(map_query_err)?;
        Ok(query
            .resolve()
            .packages(DependencyDirection::Reverse)
            .filter(|package| package.in_workspace())
            .map(|package| PackageKey(package.name().to_owned()))
            .collect())
    }

    /// 返回 package 的 borrowed target facts；热路径优先用本 API，避免整表 clone。
    ///
    /// 顺序稳定为 target kind 后 name。
    pub fn targets_for(&self, package: &PackageKey) -> Result<&[TargetFacts], WorkspaceFactsError> {
        self.packages
            .get(package)
            .map(|record| record.targets.as_slice())
            .ok_or_else(|| WorkspaceFactsError::UnknownPackage(package.as_str().to_owned()))
    }

    /// 返回 package 的 owned target facts clone。
    ///
    /// 返回值不借用本 owner，可在 `WorkspaceFacts` drop 后继续使用；顺序稳定为 target kind 后 name。
    pub fn targets(&self, package: &PackageKey) -> Result<Vec<TargetFacts>, WorkspaceFactsError> {
        Ok(self.targets_for(package)?.to_vec())
    }

    /// 返回 package 的 borrowed direct-dependency facts；热路径优先用本 API，避免整表 clone。
    ///
    /// 语义与 [`Self::direct_dependencies`] 相同（manifest declaration 粒度）；顺序稳定为
    /// `(name, kind, unconditional, resolved package name)`。非 workspace member key 返回
    /// [`WorkspaceFactsError::UnknownPackage`]。
    pub fn direct_dependencies_for(
        &self,
        package: &PackageKey,
    ) -> Result<&[DirectDependencyFacts], WorkspaceFactsError> {
        self.packages
            .get(package)
            .map(|record| record.direct_dependencies.as_slice())
            .ok_or_else(|| WorkspaceFactsError::UnknownPackage(package.as_str().to_owned()))
    }

    /// 返回 package 的 owned direct-dependency facts（manifest declaration 粒度）。
    ///
    /// 每条 Cargo metadata `packages[].dependencies[]` 声明对应一条事实；Guppy `PackageLink`
    /// 对同 from→to 的 rename/target 折叠不会丢失 provenance。返回值不借用本 owner；顺序稳定为
    /// `(name, kind, unconditional, resolved package name)`。
    pub fn direct_dependencies(
        &self,
        package: &PackageKey,
    ) -> Result<Vec<DirectDependencyFacts>, WorkspaceFactsError> {
        Ok(self.direct_dependencies_for(package)?.to_vec())
    }

    /// 返回 workspace member 的 borrowed repo-relative package root。
    ///
    /// 热路径优先用本 API，避免 [`Self::workspace_packages`] 全表 clone/find。根包为空路径。
    /// 非 workspace member key 返回 [`WorkspaceFactsError::UnknownPackage`]。
    pub fn repo_relative_root_for(
        &self,
        package: &PackageKey,
    ) -> Result<&Path, WorkspaceFactsError> {
        self.packages
            .get(package)
            .map(|record| record.repo_relative_root.as_path())
            .ok_or_else(|| WorkspaceFactsError::UnknownPackage(package.as_str().to_owned()))
    }
}

fn validate_workspace_root(root: &Path) -> Result<(), WorkspaceFactsError> {
    if !root.is_absolute()
        || root.to_str().is_none()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(WorkspaceFactsError::InvalidWorkspaceRoot(
            root.to_path_buf(),
        ));
    }
    Ok(())
}

pub(crate) fn normalize_relative_path(path: &Path) -> Result<PathBuf, WorkspaceFactsError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(WorkspaceFactsError::InvalidRepoPath(path.to_path_buf()));
    }
    Ok(path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            Component::CurDir => None,
            _ => None,
        })
        .collect())
}
