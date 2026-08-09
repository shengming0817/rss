//! Raw Cargo metadata declaration / resolve projection.
//!
//! Guppy's `PackageLink` folds multiple rename / target-conditioned declarations on the same
//! from→to edge. This module parses the same metadata JSON strictly and projects declaration-
//! granularity facts that the catalog path cannot recover from the graph alone.

use crate::{
    DependencyKind, DependencyResolution, DependencySource, DirectDependencyFacts,
    GitDependencyReq, PackageKey, WorkspaceFactsError,
};
use guppy::graph::{ExternalSource, GitReq, PackageGraph, PackageSource};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub(crate) struct RawMetadata {
    pub(crate) packages: Vec<RawPackage>,
    pub(crate) workspace_members: Vec<String>,
    pub(crate) resolve: Vec<RawResolveNode>,
}

#[derive(Debug)]
pub(crate) struct RawPackage {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) license: Option<String>,
    pub(crate) license_file: Option<String>,
    pub(crate) repository: Option<String>,
    pub(crate) readme: Option<String>,
    pub(crate) categories: BTreeSet<String>,
    pub(crate) keywords: BTreeSet<String>,
    pub(crate) features: BTreeMap<String, BTreeSet<String>>,
    pub(crate) dependencies: Vec<RawDependency>,
}

#[derive(Debug)]
pub(crate) struct RawDependency {
    name: String,
    rename: Option<String>,
    kind: DependencyKind,
    target: Option<String>,
    path: Option<String>,
    source: Option<String>,
    requirement: String,
    optional: bool,
    uses_default_features: bool,
    features: BTreeSet<String>,
}

#[derive(Debug)]
pub(crate) struct RawResolveNode {
    id: String,
    deps: Vec<RawResolveDep>,
}

#[derive(Clone, Debug)]
pub(crate) struct RawResolveDep {
    name: String,
    pkg: String,
    dep_kinds: Vec<RawDepKind>,
}

#[derive(Clone, Debug)]
pub(crate) struct RawDepKind {
    kind: DependencyKind,
    target: Option<String>,
}

/// Package-id → package indexes built once per metadata load (avoids per-member linear find).
#[derive(Debug)]
pub(crate) struct PackageIndexes<'a> {
    by_id: BTreeMap<&'a str, &'a RawPackage>,
    id_to_name: BTreeMap<&'a str, &'a str>,
}

impl<'a> PackageIndexes<'a> {
    pub(crate) fn build(packages: &'a [RawPackage]) -> Self {
        let mut by_id = BTreeMap::new();
        let mut id_to_name = BTreeMap::new();
        for package in packages {
            by_id.insert(package.id.as_str(), package);
            id_to_name.insert(package.id.as_str(), package.name.as_str());
        }
        Self { by_id, id_to_name }
    }

    pub(crate) fn package(&self, id: &str) -> Option<&'a RawPackage> {
        self.by_id.get(id).copied()
    }

    fn name_for_id(&self, id: &str) -> Option<&'a str> {
        self.id_to_name.get(id).copied()
    }
}

pub(crate) fn parse_raw_metadata(metadata_json: &str) -> Result<RawMetadata, WorkspaceFactsError> {
    let root: Value = serde_json::from_str(metadata_json)
        .map_err(|error| WorkspaceFactsError::InvalidMetadata(error.to_string()))?;
    let packages = root
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkspaceFactsError::InvalidMetadata("missing packages".into()))?
        .iter()
        .map(parse_raw_package)
        .collect::<Result<Vec<_>, _>>()?;
    let workspace_members = root
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkspaceFactsError::InvalidMetadata("missing workspace_members".into()))?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata("workspace_members entry not string".into())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resolve = match root.get("resolve") {
        None | Some(Value::Null) => Vec::new(),
        Some(resolve) => resolve
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| WorkspaceFactsError::InvalidMetadata("missing resolve.nodes".into()))?
            .iter()
            .map(parse_raw_resolve_node)
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(RawMetadata {
        packages,
        workspace_members,
        resolve,
    })
}

fn parse_raw_package(value: &Value) -> Result<RawPackage, WorkspaceFactsError> {
    let id = required_string(value, "id")?;
    let name = required_string(value, "name")?;
    let description = optional_string(value, "description")?;
    let license = optional_string(value, "license")?;
    let license_file = optional_string(value, "license_file")?;
    let repository = optional_string(value, "repository")?;
    let readme = optional_string(value, "readme")?;
    let categories = required_string_set(value, "categories")?;
    let keywords = required_string_set(value, "keywords")?;
    let features = required_string_set_map(value, "features")?;
    let dependencies = value
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WorkspaceFactsError::InvalidMetadata(format!("package `{id}` missing dependencies"))
        })?
        .iter()
        .map(parse_raw_dependency)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RawPackage {
        id,
        name,
        description,
        license,
        license_file,
        repository,
        readme,
        categories,
        keywords,
        features,
        dependencies,
    })
}

fn parse_raw_dependency(value: &Value) -> Result<RawDependency, WorkspaceFactsError> {
    Ok(RawDependency {
        name: required_string(value, "name")?,
        rename: optional_string(value, "rename")?,
        kind: parse_dependency_kind(value.get("kind"))?,
        target: optional_string(value, "target")?,
        path: optional_string(value, "path")?,
        source: optional_string(value, "source")?,
        requirement: required_string(value, "req")?,
        optional: required_bool(value, "optional")?,
        uses_default_features: required_bool(value, "uses_default_features")?,
        features: required_string_set(value, "features")?,
    })
}

fn parse_raw_resolve_node(value: &Value) -> Result<RawResolveNode, WorkspaceFactsError> {
    let id = required_string(value, "id")?;
    let deps = value
        .get("deps")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WorkspaceFactsError::InvalidMetadata(format!("resolve node `{id}` missing deps"))
        })?
        .iter()
        .map(parse_raw_resolve_dep)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RawResolveNode { id, deps })
}

fn parse_raw_resolve_dep(value: &Value) -> Result<RawResolveDep, WorkspaceFactsError> {
    let name = required_string(value, "name")?;
    let pkg = required_string(value, "pkg")?;
    let dep_kinds = match value.get("dep_kinds") {
        None | Some(Value::Null) => {
            return Err(WorkspaceFactsError::InvalidMetadata(format!(
                "resolve dep `{name}` missing dep_kinds"
            )));
        }
        Some(kinds) => {
            let kinds = kinds.as_array().ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata(format!(
                    "resolve dep `{name}` dep_kinds not array"
                ))
            })?;
            if kinds.is_empty() {
                return Err(WorkspaceFactsError::InvalidMetadata(format!(
                    "resolve dep `{name}` empty dep_kinds"
                )));
            }
            kinds
                .iter()
                .map(|kind| {
                    Ok(RawDepKind {
                        kind: parse_dependency_kind(kind.get("kind"))?,
                        target: optional_string(kind, "target")?,
                    })
                })
                .collect::<Result<Vec<_>, WorkspaceFactsError>>()?
        }
    };
    Ok(RawResolveDep {
        name,
        pkg,
        dep_kinds,
    })
}

fn parse_dependency_kind(value: Option<&Value>) -> Result<DependencyKind, WorkspaceFactsError> {
    match value {
        None | Some(Value::Null) => Ok(DependencyKind::Normal),
        Some(Value::String(kind)) => match kind.as_str() {
            "normal" => Ok(DependencyKind::Normal),
            "dev" => Ok(DependencyKind::Dev),
            "build" => Ok(DependencyKind::Build),
            other => Err(WorkspaceFactsError::UnknownDependencyKind(other.to_owned())),
        },
        Some(other) => Err(WorkspaceFactsError::UnknownDependencyKind(
            other.to_string(),
        )),
    }
}

fn required_string(value: &Value, field: &str) -> Result<String, WorkspaceFactsError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            WorkspaceFactsError::InvalidMetadata(format!("missing string field `{field}`"))
        })
}

fn optional_string(value: &Value, field: &str) -> Result<Option<String>, WorkspaceFactsError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(WorkspaceFactsError::InvalidMetadata(format!(
            "field `{field}` must be string or null"
        ))),
    }
}

fn required_bool(value: &Value, field: &str) -> Result<bool, WorkspaceFactsError> {
    value.get(field).and_then(Value::as_bool).ok_or_else(|| {
        WorkspaceFactsError::InvalidMetadata(format!("missing boolean field `{field}`"))
    })
}

fn required_string_set_map(
    value: &Value,
    field: &str,
) -> Result<BTreeMap<String, BTreeSet<String>>, WorkspaceFactsError> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            WorkspaceFactsError::InvalidMetadata(format!("missing object field `{field}`"))
        })?
        .iter()
        .map(|(key, values)| {
            let values = values
                .as_array()
                .ok_or_else(|| {
                    WorkspaceFactsError::InvalidMetadata(format!(
                        "field `{field}.{key}` must be an array"
                    ))
                })?
                .iter()
                .map(|entry| {
                    entry.as_str().map(str::to_owned).ok_or_else(|| {
                        WorkspaceFactsError::InvalidMetadata(format!(
                            "field `{field}.{key}` entries must be strings"
                        ))
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            Ok((key.clone(), values))
        })
        .collect()
}

fn required_string_set(
    value: &Value,
    field: &str,
) -> Result<BTreeSet<String>, WorkspaceFactsError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            WorkspaceFactsError::InvalidMetadata(format!("missing array field `{field}`"))
        })?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata(format!(
                    "field `{field}` entries must be strings"
                ))
            })
        })
        .collect()
}

pub(crate) fn index_resolve_nodes(nodes: &[RawResolveNode]) -> BTreeMap<&str, &[RawResolveDep]> {
    nodes
        .iter()
        .map(|node| (node.id.as_str(), node.deps.as_slice()))
        .collect()
}

pub(crate) fn project_direct_declarations(
    dependent: &PackageKey,
    declarations: &[RawDependency],
    resolve_deps: &[RawResolveDep],
    indexes: &PackageIndexes<'_>,
    graph: &PackageGraph,
    workspace_root: &Path,
) -> Result<Vec<DirectDependencyFacts>, WorkspaceFactsError> {
    let mut facts = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        let name = declaration
            .rename
            .clone()
            .unwrap_or_else(|| declaration.name.clone());
        let (resolution, resolved_package_id) = resolve_declaration(
            dependent,
            &name,
            &declaration.name,
            declaration.kind,
            declaration.target.as_deref(),
            resolve_deps,
            indexes,
        )?;
        let source = project_declaration_source(
            declaration.path.as_deref().map(Path::new),
            declaration.source.as_deref(),
            resolved_package_id.as_deref(),
            graph,
            workspace_root,
        )?;
        let version_requirement = declaration.requirement.parse().map_err(|error| {
            WorkspaceFactsError::InvalidMetadata(format!(
                "dependency `{name}` has invalid version requirement `{}`: {error}",
                declaration.requirement
            ))
        })?;
        facts.push(DirectDependencyFacts {
            dependent: dependent.clone(),
            resolution,
            name,
            kind: declaration.kind,
            source,
            version_requirement,
            optional: declaration.optional,
            uses_default_features: declaration.uses_default_features,
            unconditional: declaration.target.is_none(),
            requested_features: declaration.features.clone(),
        });
    }
    facts.sort_by(|left, right| {
        (
            left.name.as_str(),
            left.kind,
            left.unconditional,
            resolution_sort_key(&left.resolution),
            &left.requested_features,
        )
            .cmp(&(
                right.name.as_str(),
                right.kind,
                right.unconditional,
                resolution_sort_key(&right.resolution),
                &right.requested_features,
            ))
    });
    Ok(facts)
}

fn resolution_sort_key(resolution: &DependencyResolution) -> &str {
    match resolution {
        DependencyResolution::Resolved(key) => key.as_str(),
        DependencyResolution::Unresolved => "",
    }
}

fn resolve_declaration(
    dependent: &PackageKey,
    name: &str,
    package_name: &str,
    kind: DependencyKind,
    target: Option<&str>,
    resolve_deps: &[RawResolveDep],
    indexes: &PackageIndexes<'_>,
) -> Result<(DependencyResolution, Option<String>), WorkspaceFactsError> {
    let mut matched_ids = BTreeSet::new();
    for dep in resolve_deps {
        let resolve_name_matches =
            dep.name == name || dep.name.replace('_', "-") == name.replace('_', "-");
        let package_identity_matches = indexes
            .package(&dep.pkg)
            .is_some_and(|package| package.name == package_name);
        if !resolve_name_matches && !package_identity_matches {
            continue;
        }
        if !resolve_dep_matches_declaration(dep, kind, target) {
            continue;
        }
        matched_ids.insert(dep.pkg.clone());
    }
    match matched_ids.len() {
        0 => Ok((DependencyResolution::Unresolved, None)),
        1 => {
            let package_id = matched_ids.into_iter().next().ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata(
                    "matched dependency ids emptied after len check".into(),
                )
            })?;
            let package_name = indexes.name_for_id(&package_id).ok_or_else(|| {
                WorkspaceFactsError::InvalidMetadata(format!(
                    "resolve package id `{package_id}` missing from metadata packages"
                ))
            })?;
            Ok((
                DependencyResolution::Resolved(PackageKey(package_name.to_owned())),
                Some(package_id),
            ))
        }
        _ => Err(WorkspaceFactsError::AmbiguousDependencyResolution {
            dependent: dependent.as_str().to_owned(),
            name: name.to_owned(),
            kind: kind.as_str().to_owned(),
            detail: matched_ids.into_iter().collect::<Vec<_>>().join(", "),
        }),
    }
}

fn resolve_dep_matches_declaration(
    dep: &RawResolveDep,
    kind: DependencyKind,
    target: Option<&str>,
) -> bool {
    dep.dep_kinds
        .iter()
        .any(|entry| entry.kind == kind && entry.target.as_deref() == target)
}

fn project_declaration_source(
    declaration_path: Option<&Path>,
    declaration_source: Option<&str>,
    resolved_package_id: Option<&str>,
    graph: &PackageGraph,
    workspace_root: &Path,
) -> Result<DependencySource, WorkspaceFactsError> {
    if let Some(path) = declaration_path {
        return project_path_declaration_source(path, resolved_package_id, graph, workspace_root);
    }
    if let Some(source) = declaration_source {
        return Ok(project_external_source_string(source));
    }
    if let Some(package_id) = resolved_package_id {
        let package = graph
            .metadata(&guppy::PackageId::new(package_id))
            .map_err(|error| WorkspaceFactsError::InvalidMetadata(error.to_string()))?;
        return project_package_source(package.source());
    }
    Ok(DependencySource::UnknownExternal {
        source: String::new(),
    })
}

fn project_path_declaration_source(
    absolute_or_declared: &Path,
    resolved_package_id: Option<&str>,
    graph: &PackageGraph,
    workspace_root: &Path,
) -> Result<DependencySource, WorkspaceFactsError> {
    if let Some(package_id) = resolved_package_id {
        let package = graph
            .metadata(&guppy::PackageId::new(package_id))
            .map_err(|error| WorkspaceFactsError::InvalidMetadata(error.to_string()))?;
        return project_package_source(package.source());
    }
    let relative = relativize_to_workspace(absolute_or_declared, workspace_root)?;
    Ok(DependencySource::Path {
        repo_relative_root: relative,
    })
}

fn project_package_source(
    source: PackageSource<'_>,
) -> Result<DependencySource, WorkspaceFactsError> {
    Ok(match source {
        PackageSource::Workspace(path) => DependencySource::Workspace {
            repo_relative_root: project_source_relative_path(path.as_std_path())?,
        },
        PackageSource::Path(path) => DependencySource::Path {
            repo_relative_root: project_source_relative_path(path.as_std_path())?,
        },
        PackageSource::External(raw) => project_external_source_string(raw),
    })
}

fn project_external_source_string(raw: &str) -> DependencySource {
    match ExternalSource::new(raw) {
        Some(ExternalSource::Registry(url)) => DependencySource::Registry {
            url: url.to_owned(),
        },
        Some(ExternalSource::Sparse(url)) => DependencySource::Sparse {
            url: url.to_owned(),
        },
        Some(ExternalSource::Git {
            repository,
            req,
            resolved,
        }) => match project_git_req(req) {
            Some(req) => DependencySource::Git {
                repository: repository.to_owned(),
                req,
                resolved: resolved.to_owned(),
            },
            None => DependencySource::UnknownExternal {
                source: raw.to_owned(),
            },
        },
        _ => DependencySource::UnknownExternal {
            source: raw.to_owned(),
        },
    }
}

fn project_git_req(req: GitReq<'_>) -> Option<GitDependencyReq> {
    match req {
        GitReq::Default => Some(GitDependencyReq::Default),
        GitReq::Branch(branch) => Some(GitDependencyReq::Branch(branch.to_owned())),
        GitReq::Tag(tag) => Some(GitDependencyReq::Tag(tag.to_owned())),
        GitReq::Rev(rev) => Some(GitDependencyReq::Rev(rev.to_owned())),
        _ => None,
    }
}

/// Project a guppy package-source path relative to the workspace root.
///
/// Unlike crate-root `normalize_relative_path`, parent components are retained: non-workspace path
/// dependencies are routinely reported as `../…` by guppy (`PackageSource::Path`).
fn project_source_relative_path(path: &Path) -> Result<PathBuf, WorkspaceFactsError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
    {
        return Err(WorkspaceFactsError::InvalidRepoPath(path.to_path_buf()));
    }
    Ok(path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(Component::Normal(value)),
            Component::ParentDir => Some(Component::ParentDir),
            Component::CurDir => None,
            _ => None,
        })
        .collect())
}

fn relativize_to_workspace(
    path: &Path,
    workspace_root: &Path,
) -> Result<PathBuf, WorkspaceFactsError> {
    if let Ok(relative) = path.strip_prefix(workspace_root) {
        return project_source_relative_path(relative);
    }
    if !path.is_absolute() {
        return project_source_relative_path(path);
    }
    if !workspace_root.is_absolute() {
        return Err(WorkspaceFactsError::InvalidWorkspaceRoot(
            workspace_root.to_path_buf(),
        ));
    }
    let path_components = path.components().collect::<Vec<_>>();
    let root_components = workspace_root.components().collect::<Vec<_>>();
    let common = path_components
        .iter()
        .zip(root_components.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..root_components.len() {
        relative.push(Component::ParentDir.as_os_str());
    }
    for component in &path_components[common..] {
        relative.push(component.as_os_str());
    }
    Ok(relative)
}
