//! Owned、窄语义的 Cargo workspace facts façade。
//!
//! `cargo metadata --locked --all-features --format-version 1` 的执行由调用方持有；本 crate
//! 只把 JSON 构造成 guppy `PackageGraph`，并且只暴露 RSS tooling consumer 已使用的 owned facts。

#[cfg(feature = "test-support")]
pub mod testing;

use guppy::graph::{BuildTargetId, BuildTargetKind, DependencyDirection, PackageGraph};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Workspace 内包的进程内 typed identity；不承诺跨进程稳定编码。
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
    #[error("guppy package query failed: {0}")]
    Query(String),
}

#[derive(Debug)]
struct PackageRecord {
    targets: Vec<TargetFacts>,
}

/// 单次 `PackageGraph` 加载后共享的 workspace facts。
#[derive(Debug)]
pub struct WorkspaceFacts {
    graph: PackageGraph,
    packages: BTreeMap<PackageKey, PackageRecord>,
    package_roots: Vec<(PathBuf, PackageKey)>,
}

impl WorkspaceFacts {
    /// 从调用方取得的完整 Cargo metadata JSON 构造事实图。
    pub fn from_metadata_json(
        expected_root: &Path,
        metadata_json: &str,
    ) -> Result<Self, WorkspaceFactsError> {
        validate_workspace_root(expected_root)?;
        let graph = PackageGraph::from_json(metadata_json)
            .map_err(|error| WorkspaceFactsError::InvalidMetadata(error.to_string()))?;
        let actual_root = graph.workspace().root().as_std_path();
        if actual_root != expected_root {
            return Err(WorkspaceFactsError::WorkspaceRootMismatch {
                expected: expected_root.to_path_buf(),
                actual: actual_root.to_path_buf(),
            });
        }

        let mut packages = BTreeMap::new();
        let mut package_roots = Vec::new();
        for (workspace_path, package) in graph.workspace().iter_by_path() {
            let root = normalize_relative_path(workspace_path.as_std_path())?;
            let key = PackageKey(package.name().to_owned());
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
            package_roots.push((root.clone(), key.clone()));
            packages.insert(key, PackageRecord { targets });
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
        })
    }

    pub fn package_key(&self, name: &str) -> Result<PackageKey, WorkspaceFactsError> {
        let key = PackageKey(name.to_owned());
        self.packages
            .contains_key(&key)
            .then_some(key)
            .ok_or_else(|| WorkspaceFactsError::UnknownPackage(name.to_owned()))
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
            .map_err(|error| WorkspaceFactsError::Query(error.to_string()))?;
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

fn normalize_relative_path(path: &Path) -> Result<PathBuf, WorkspaceFactsError> {
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
