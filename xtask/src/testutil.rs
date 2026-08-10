//! 跨模块测试工具（仅 `#[cfg(test)]` 编译）。
//!
//! `unique_tmp`：基于 process id + 原子递增计数器生成唯一临时目录路径，
//! 避免并发测试在同一进程内路径碰撞。
//!
//! `synthetic_workspace_facts`：共享 synthetic Cargo metadata → WorkspaceFacts 工厂，
//! contract-binding / nextest / ci_impact 测试只传 package 规格，避免平行维护。
#![cfg(test)]

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use workspacefacts::WorkspaceFacts;
use workspacefacts::testing::{
    metadata_json, path_dependency, path_package, path_package_id, resolve_node, target,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 生成唯一临时目录路径（不自动创建，调用方负责 `fs::create_dir_all` 与清理）。
///
/// Base temp dir is canonicalized so macOS `/var` → `/private/var` aliases do not break
/// assembly-lock repository-root identity checks.
pub(crate) fn unique_tmp(prefix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = std::env::temp_dir();
    let temp = std::fs::canonicalize(&temp).unwrap_or(temp);
    temp.join(format!("rss-xtask-{prefix}-{}-{n}", std::process::id()))
}

/// 一个 workspace path package 的 synthetic 规格。
#[derive(Clone, Debug)]
pub(crate) struct SyntheticPathPackage {
    pub name: String,
    pub absolute_path: String,
    pub targets: Vec<Value>,
    pub dependency_names: Vec<String>,
    pub features: Value,
}

impl SyntheticPathPackage {
    pub(crate) fn new(
        name: impl Into<String>,
        absolute_path: impl Into<String>,
        targets: Vec<Value>,
    ) -> Self {
        Self {
            name: name.into(),
            absolute_path: absolute_path.into(),
            targets,
            dependency_names: Vec::new(),
            features: json!({}),
        }
    }

    pub(crate) fn with_dependencies(mut self, dependency_names: Vec<String>) -> Self {
        self.dependency_names = dependency_names;
        self
    }

    pub(crate) fn with_features(mut self, features: Value) -> Self {
        self.features = features;
        self
    }
}

/// 按 Cargo target kind 推导默认 src_path（绝对路径）。
pub(crate) fn default_target_src(absolute_package: &str, target_name: &str, kind: &str) -> String {
    match kind {
        "bin" => format!("{absolute_package}/src/main.rs"),
        "test" => format!("{absolute_package}/tests/{target_name}.rs"),
        "example" => format!("{absolute_package}/examples/{target_name}.rs"),
        "bench" => format!("{absolute_package}/benches/{target_name}.rs"),
        "custom-build" => format!("{absolute_package}/build.rs"),
        _ => format!("{absolute_package}/src/lib.rs"),
    }
}

/// 用默认 src_path 构造 metadata target。
pub(crate) fn target_with_default_src(
    absolute_package: &str,
    target_name: &str,
    kind: &str,
    test: bool,
    required_features: &[&str],
) -> Value {
    target(
        target_name,
        kind,
        &default_target_src(absolute_package, target_name, kind),
        test,
        required_features,
    )
}

/// 共享 synthetic WorkspaceFacts builder。
///
/// `packages` 为 workspace members；`externals` 为非 member package（registry 等），
/// 会进入 packages 列表并挂空 resolve node，但不进入 workspace_members。
pub(crate) fn synthetic_workspace_facts(
    workspace_root: &Path,
    packages: &[SyntheticPathPackage],
    externals: &[Value],
) -> Result<WorkspaceFacts> {
    let root = workspace_root
        .to_str()
        .context("workspace root must be UTF-8")?;
    let paths = packages
        .iter()
        .map(|package| (package.name.as_str(), package.absolute_path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let package_id = |name: &str| -> Result<String> {
        let path = paths
            .get(name)
            .with_context(|| format!("synthetic dependency `{name}` is missing"))?;
        Ok(path_package_id(path))
    };

    let mut package_values = packages
        .iter()
        .map(|package| -> Result<Value> {
            let dependencies = package
                .dependency_names
                .iter()
                .map(|dependency| -> Result<Value> {
                    let dependency_path = paths.get(dependency.as_str()).with_context(|| {
                        format!("synthetic dependency `{dependency}` is missing")
                    })?;
                    Ok(path_dependency(dependency, dependency_path))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(path_package(
                &package.name,
                &package.absolute_path,
                package.targets.clone(),
                dependencies,
                package.features.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    package_values.extend(externals.iter().cloned());

    let member_ids = packages
        .iter()
        .map(|package| package_id(&package.name))
        .collect::<Result<Vec<_>>>()?;
    let mut nodes = packages
        .iter()
        .map(|package| -> Result<Value> {
            let deps = package
                .dependency_names
                .iter()
                .map(|dependency| Ok((dependency.as_str(), package_id(dependency)?)))
                .collect::<Result<Vec<_>>>()?;
            let deps_refs = deps
                .iter()
                .map(|(dependency, id)| (*dependency, id.as_str()))
                .collect::<Vec<_>>();
            let id = package_id(&package.name)?;
            Ok(resolve_node(&id, &deps_refs))
        })
        .collect::<Result<Vec<_>>>()?;
    for external in externals {
        let id = external["id"]
            .as_str()
            .context("external package missing id")?;
        nodes.push(resolve_node(id, &[]));
    }

    WorkspaceFacts::from_metadata_json(
        workspace_root,
        &metadata_json(root, package_values, member_ids, nodes),
    )
    .context("synthetic workspace facts")
}

/// Construct synthetic facts from fully specified Cargo metadata parts.
///
/// Tests that need feature-bearing external edges use this shared parse owner instead of creating
/// a second Cargo metadata owner inside the production module under test.
pub(crate) fn synthetic_workspace_facts_from_parts(
    workspace_root: &Path,
    packages: Vec<Value>,
    workspace_member_ids: Vec<String>,
    nodes: Vec<Value>,
) -> Result<WorkspaceFacts> {
    let root = workspace_root
        .to_str()
        .context("workspace root must be UTF-8")?;
    WorkspaceFacts::from_metadata_json(
        workspace_root,
        &metadata_json(root, packages, workspace_member_ids, nodes),
    )
    .context("synthetic workspace facts from explicit metadata parts")
}
