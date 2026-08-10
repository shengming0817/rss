use crate::{DependencyKind, PackageKey, WorkspaceFacts, WorkspaceFactsError};
use guppy::PackageId;
use guppy::errors::{FeatureBuildStage, FeatureGraphWarning};
use guppy::graph::cargo::{
    BuildPlatform, CargoOptions, CargoResolverVersion, CargoSet, InitialsPlatform,
};
use guppy::graph::feature::{FeatureEdge, FeatureLabel, FeatureMetadata, StandardFeatures};
use guppy::graph::{DependencyDirection, PackageLink};
use guppy::platform::{Platform, TargetFeatures};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// RSS 当前支持的 Cargo feature resolver 闭值。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResolverVersion {
    V2,
}

/// selected package 的 Cargo feature selection。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FeatureSelection {
    Default,
    All,
}

/// Cargo target/host build graph 的一侧。
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BuildSide {
    Target,
    Host,
}

impl fmt::Display for BuildSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target => formatter.write_str("target"),
            Self::Host => formatter.write_str("host"),
        }
    }
}

/// 已验证的 Cargo build platform。
#[derive(Clone, Debug)]
pub struct CargoPlatform {
    platform: Platform,
}

impl CargoPlatform {
    /// 返回编译当前 `workspacefacts` 的 target platform。
    pub fn build_target() -> Result<Self, WorkspaceFactsError> {
        Platform::build_target()
            .map(|platform| Self { platform })
            .map_err(|error| WorkspaceFactsError::UnknownPlatform(error.to_string()))
    }

    /// 从严格 Rust target triple 与显式 target features 构造平台。
    pub fn from_triple(
        triple: impl Into<String>,
        target_features: BTreeSet<String>,
    ) -> Result<Self, WorkspaceFactsError> {
        let triple = triple.into();
        Platform::new_strict(triple.clone(), TargetFeatures::features(target_features))
            .map(|platform| Self { platform })
            .map_err(|error| WorkspaceFactsError::UnknownPlatform(format!("`{triple}`: {error}")))
    }
}

/// Cargo target 与 host platform 的必填输入。
#[derive(Clone, Debug)]
pub struct BuildPlatforms {
    target: CargoPlatform,
    host: CargoPlatform,
}

impl BuildPlatforms {
    #[must_use]
    pub fn new(target: CargoPlatform, host: CargoPlatform) -> Self {
        Self { target, host }
    }
}

/// Workspace 内已声明 named feature 的 owned identity。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeatureKey {
    package: PackageKey,
    name: String,
}

impl FeatureKey {
    #[must_use]
    pub fn package(&self) -> &PackageKey {
        &self.package
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// 一次 root-specific Cargo build 查询的全部必填输入。
///
/// `explain_features` 是按需 explain 集合：`resolve_build` 只为其中且实际启用的 named feature
/// 填充 [`BuildFacts::activation_path`]；集合外的已启用 feature 不解释（返回 `None`）。
#[derive(Clone, Debug)]
pub struct BuildSelection {
    root_package: PackageKey,
    resolver: ResolverVersion,
    features: FeatureSelection,
    platforms: BuildPlatforms,
    /// 需要生成 activation path 的 named feature 闭集（按需 explain，非全量）。
    explain_features: BTreeSet<FeatureKey>,
}

impl BuildSelection {
    #[must_use]
    pub fn new(
        root_package: PackageKey,
        resolver: ResolverVersion,
        features: FeatureSelection,
        platforms: BuildPlatforms,
        explain_features: BTreeSet<FeatureKey>,
    ) -> Self {
        Self {
            root_package,
            resolver,
            features,
            platforms,
            explain_features,
        }
    }
}

/// Activation path 中的 owned package / named-feature / optional-dep 节点。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivationNode {
    Package {
        side: BuildSide,
        package: PackageKey,
    },
    Feature {
        side: BuildSide,
        feature: FeatureKey,
    },
    OptionalDependency {
        side: BuildSide,
        package: PackageKey,
        name: String,
    },
}

impl fmt::Display for ActivationNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package { side, package } => write!(formatter, "{side}:{}", package.as_str()),
            Self::Feature { side, feature } => write!(
                formatter,
                "{side}:{}/{}",
                feature.package().as_str(),
                feature.name()
            ),
            Self::OptionalDependency {
                side,
                package,
                name,
            } => write!(formatter, "{side}:{}/dep:{name}", package.as_str()),
        }
    }
}

/// 从 selected root 到 enabled named feature 的稳定 owned path（保留中间 feature / optional-dep）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPath {
    nodes: Vec<ActivationNode>,
}

impl ActivationPath {
    #[must_use]
    pub fn nodes(&self) -> &[ActivationNode] {
        &self.nodes
    }
}

impl fmt::Display for ActivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, node) in self.nodes.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" -> ")?;
            }
            write!(formatter, "{node}")?;
        }
        Ok(())
    }
}

/// Root-specific Cargo build 的 owned workspace facts。
#[derive(Clone, Debug)]
pub struct BuildFacts {
    target: SideFacts,
    host: SideFacts,
    activation_paths: BTreeMap<(BuildSide, FeatureKey), ActivationPath>,
}

#[derive(Clone, Debug)]
struct SideFacts {
    packages: BTreeSet<PackageKey>,
    /// Selected package names including registry/crates.io deps (for serving clap absence etc.).
    selected_package_names: BTreeSet<String>,
    /// Selected named features for every package, including registry/crates.io dependencies.
    selected_package_features: BTreeSet<(String, String)>,
    features: BTreeSet<FeatureKey>,
    selected_dependencies: BTreeSet<SelectedDependency>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectedDependency {
    dependent: PackageKey,
    dependency: PackageKey,
    name: String,
}

impl BuildFacts {
    #[must_use]
    pub fn workspace_packages(&self, side: BuildSide) -> &BTreeSet<PackageKey> {
        &self.side_facts(side).packages
    }

    /// Whether `name` is selected on `side`, including non-workspace packages.
    #[must_use]
    pub fn is_package_selected(&self, side: BuildSide, name: &str) -> bool {
        self.side_facts(side).selected_package_names.contains(name)
    }

    /// Whether any selected version of `package` enables the named Cargo `feature` on `side`.
    ///
    /// Unlike [`Self::enabled_features`], this query includes registry/crates.io packages. It is
    /// intentionally name-based: policy checks normally need to reject the feature if any selected
    /// version enables it.
    #[must_use]
    pub fn is_package_feature_enabled(
        &self,
        side: BuildSide,
        package: &str,
        feature: &str,
    ) -> bool {
        self.side_facts(side).selected_package_features.iter().any(
            |(selected_package, selected_feature)| {
                selected_package == package && selected_feature == feature
            },
        )
    }

    #[must_use]
    pub fn enabled_features(&self, side: BuildSide) -> &BTreeSet<FeatureKey> {
        &self.side_facts(side).features
    }

    #[must_use]
    pub fn is_feature_enabled(&self, side: BuildSide, feature: &FeatureKey) -> bool {
        self.enabled_features(side).contains(feature)
    }

    /// Whether one dependency edge from a workspace package is selected for this root-specific
    /// Cargo build. The dependency identity may be another workspace package or an external crate.
    ///
    /// `dependency_name` is the manifest dependency key after rename. The query is edge-specific:
    /// selecting `dependency` through another direct or transitive path does not make this edge
    /// selected.
    #[must_use]
    pub fn is_dependency_selected(
        &self,
        side: BuildSide,
        dependent: &PackageKey,
        dependency_name: &str,
        dependency: &PackageKey,
    ) -> bool {
        self.side_facts(side)
            .selected_dependencies
            .contains(&SelectedDependency {
                dependent: dependent.clone(),
                dependency: dependency.clone(),
                name: dependency_name.to_owned(),
            })
    }

    /// 返回 `feature` 在 `side` 上的 activation path（若有）。
    ///
    /// 仅当构造 [`BuildSelection`] 时把该 feature 放进 `explain_features`、且 resolve 后该
    /// side 确实启用了它时才有值；已启用但不在 explain 集合中的 feature 返回 `None`。
    #[must_use]
    pub fn activation_path(
        &self,
        side: BuildSide,
        feature: &FeatureKey,
    ) -> Option<&ActivationPath> {
        self.activation_paths.get(&(side, feature.clone()))
    }

    fn side_facts(&self, side: BuildSide) -> &SideFacts {
        match side {
            BuildSide::Target => &self.target,
            BuildSide::Host => &self.host,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectedFeatureNode {
    side: BuildSide,
    package: PackageKey,
    label: SelectedFeatureLabel,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SelectedFeatureLabel {
    Base,
    Named(String),
    OptionalDependency(String),
}

type SelectedFeatureStarts = BTreeSet<SelectedFeatureNode>;
type SelectedFeatureAdjacency = BTreeMap<SelectedFeatureNode, BTreeSet<SelectedFeatureNode>>;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectedPackageLink {
    from: PackageId,
    to: PackageId,
    dep_name: String,
}

impl WorkspaceFacts {
    /// 验证 workspace package 的 named feature，并返回 owned key。
    pub fn feature_key(
        &self,
        package: &PackageKey,
        feature: &str,
    ) -> Result<FeatureKey, WorkspaceFactsError> {
        let metadata = self
            .graph
            .workspace()
            .member_by_name(package.as_str())
            .map_err(|_| WorkspaceFactsError::UnknownPackage(package.as_str().to_owned()))?;
        let features = self
            .graph
            .feature_graph()
            .all_features_for(metadata.id())
            .map_err(crate::map_query_err)?;
        if !features.has_named_feature(feature) {
            return Err(WorkspaceFactsError::UnknownFeature {
                package: package.as_str().to_owned(),
                feature: feature.to_owned(),
            });
        }
        Ok(FeatureKey {
            package: package.clone(),
            name: feature.to_owned(),
        })
    }

    /// 用 Guppy 模拟一次 root-specific normal Cargo build，并返回 owned facts。
    pub fn resolve_build(
        &self,
        selection: BuildSelection,
    ) -> Result<BuildFacts, WorkspaceFactsError> {
        let feature_graph = self.graph.feature_graph();
        for feature in &selection.explain_features {
            self.feature_key(feature.package(), feature.name())?;
        }

        let root = self
            .graph
            .workspace()
            .member_by_name(selection.root_package.as_str())
            .map_err(|_| {
                WorkspaceFactsError::UnknownPackage(selection.root_package.as_str().to_owned())
            })?;
        let initials = root.to_feature_set(match selection.features {
            FeatureSelection::Default => StandardFeatures::Default,
            FeatureSelection::All => StandardFeatures::All,
        });
        let mut options = CargoOptions::new();
        options
            .set_resolver(match selection.resolver {
                ResolverVersion::V2 => CargoResolverVersion::V2,
            })
            .set_include_dev(false)
            .set_initials_platform(InitialsPlatform::Standard)
            .set_target_platform(selection.platforms.target.platform.clone())
            .set_host_platform(selection.platforms.host.platform.clone());
        let cargo_set = initials
            .into_cargo_set(&options)
            .map_err(|error| WorkspaceFactsError::BuildQuery(error.to_string()))?;
        let relevant_warnings = feature_graph
            .build_warnings()
            .iter()
            .filter(|warning| warning_affects_selection(&cargo_set, warning))
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !relevant_warnings.is_empty() {
            return Err(WorkspaceFactsError::IncompleteFeatureGraph(
                relevant_warnings.join("; "),
            ));
        }

        let target_dependencies =
            self.collect_selected_dependencies(cargo_set.target_links(), DependencyKind::Normal);
        let host_dependencies = self
            .collect_selected_dependencies(cargo_set.build_dep_links(), DependencyKind::Build)
            .into_iter()
            .chain(self.collect_selected_dependencies(
                cargo_set.proc_macro_links().chain(cargo_set.host_links()),
                DependencyKind::Normal,
            ))
            .collect();
        let target = collect_side_facts(&cargo_set, BuildSide::Target, target_dependencies);
        let host = collect_side_facts(&cargo_set, BuildSide::Host, host_dependencies);

        let (starts, adjacency) = selected_feature_graph(&cargo_set)?;
        let mut activation_paths = BTreeMap::new();
        for side in [BuildSide::Target, BuildSide::Host] {
            for feature in &selection.explain_features {
                let side_features = match side {
                    BuildSide::Target => &target.features,
                    BuildSide::Host => &host.features,
                };
                if !side_features.contains(feature) {
                    continue;
                }
                let path = required_activation_path(
                    &selection.root_package,
                    &starts,
                    side,
                    feature,
                    &adjacency,
                )?;
                activation_paths.insert((side, feature.clone()), path);
            }
        }

        Ok(BuildFacts {
            target,
            host,
            activation_paths,
        })
    }

    fn collect_selected_dependencies<'g>(
        &self,
        links: impl Iterator<Item = PackageLink<'g>>,
        kind: DependencyKind,
    ) -> BTreeSet<SelectedDependency> {
        links
            .filter_map(|link| {
                let (from, to) = link.endpoints();
                if !from.in_workspace() {
                    return None;
                }
                let dependent = PackageKey(from.name().to_owned());
                let dependency = PackageKey(to.name().to_owned());
                let candidate_names = self
                    .packages
                    .get(&dependent)?
                    .direct_dependencies
                    .iter()
                    .filter(|declaration| {
                        declaration.kind() == kind && declaration.resolved() == Some(&dependency)
                    })
                    .map(|declaration| declaration.name())
                    .collect::<BTreeSet<_>>();
                let name = if candidate_names.contains(link.dep_name()) {
                    link.dep_name()
                } else if candidate_names.len() == 1 {
                    candidate_names.first().copied()?
                } else {
                    return None;
                };
                Some(SelectedDependency {
                    dependent,
                    dependency,
                    name: name.to_owned(),
                })
            })
            .collect()
    }
}

fn collect_side_facts(
    cargo_set: &CargoSet<'_>,
    side: BuildSide,
    selected_dependencies: BTreeSet<SelectedDependency>,
) -> SideFacts {
    let selected = selected_features(cargo_set, side);
    let mut packages = BTreeSet::new();
    let mut selected_package_names = BTreeSet::new();
    let mut selected_package_features = BTreeSet::new();
    let mut features = BTreeSet::new();
    for feature_list in selected.packages_with_features(DependencyDirection::Forward) {
        let package = feature_list.package();
        selected_package_names.insert(package.name().to_owned());
        selected_package_features.extend(
            feature_list
                .named_features()
                .map(|name| (package.name().to_owned(), name.to_owned())),
        );
        if !package.in_workspace() {
            continue;
        }
        let package_key = PackageKey(package.name().to_owned());
        packages.insert(package_key.clone());
        features.extend(feature_list.named_features().map(|name| FeatureKey {
            package: package_key.clone(),
            name: name.to_owned(),
        }));
    }
    SideFacts {
        packages,
        selected_package_names,
        selected_package_features,
        features,
        selected_dependencies,
    }
}

fn selected_features<'g>(
    cargo_set: &'g CargoSet<'g>,
    side: BuildSide,
) -> &'g guppy::graph::feature::FeatureSet<'g> {
    cargo_set.platform_features(match side {
        BuildSide::Target => BuildPlatform::Target,
        BuildSide::Host => BuildPlatform::Host,
    })
}

fn warning_affects_selection(cargo_set: &CargoSet<'_>, warning: &FeatureGraphWarning) -> bool {
    match warning {
        FeatureGraphWarning::MissingFeature { stage, .. } => match stage {
            FeatureBuildStage::AddNamedFeatureEdges {
                package_id,
                from_feature,
            } => selected_named_feature(cargo_set, package_id, from_feature),
            FeatureBuildStage::AddDependencyEdges {
                package_id,
                dep_name,
            } => selected_dependency(cargo_set, package_id, dep_name),
            _ => true,
        },
        FeatureGraphWarning::SelfLoop {
            package_id,
            feature_name,
        } => selected_named_feature(cargo_set, package_id, feature_name),
        _ => true,
    }
}

fn selected_named_feature(cargo_set: &CargoSet<'_>, package_id: &PackageId, feature: &str) -> bool {
    [BuildSide::Target, BuildSide::Host]
        .into_iter()
        .any(|side| {
            selected_features(cargo_set, side)
                .features_for(package_id)
                .is_ok_and(|features| {
                    features.is_some_and(|features| features.has_named_feature(feature))
                })
        })
}

fn selected_dependency(cargo_set: &CargoSet<'_>, package_id: &PackageId, dep_name: &str) -> bool {
    cargo_set
        .target_links()
        .chain(cargo_set.build_dep_links())
        .chain(cargo_set.proc_macro_links())
        .chain(cargo_set.host_links())
        .any(|link| link.from().id() == package_id && link.dep_name() == dep_name)
}

fn selected_feature_graph(
    cargo_set: &CargoSet<'_>,
) -> Result<(SelectedFeatureStarts, SelectedFeatureAdjacency), WorkspaceFactsError> {
    let feature_graph = cargo_set.target_features().graph();
    let mut starts = BTreeSet::new();
    for feature_id in cargo_set
        .initials()
        .feature_ids(DependencyDirection::Forward)
    {
        let metadata = feature_graph
            .metadata(feature_id)
            .map_err(crate::map_query_err)?;
        let side = if metadata.package().is_proc_macro() {
            BuildSide::Host
        } else {
            BuildSide::Target
        };
        if let Some(node) = selected_feature_node(side, &metadata) {
            starts.insert(node);
        }
    }

    let target = cargo_set.target_features();
    let host = cargo_set.host_features();
    let union = target.union(host);
    // CargoSet 的四类 link 已包含 resolver、platform 与 weak-dependency 判定；这里只投影 provenance，
    // 不在 façade 内重放第二套 Cargo feature resolver。
    let target_links = selected_package_links(cargo_set.target_links());
    let build_links = selected_package_links(cargo_set.build_dep_links());
    let proc_macro_links = selected_package_links(cargo_set.proc_macro_links());
    let host_links = selected_package_links(cargo_set.host_links());
    let mut adjacency = BTreeMap::<SelectedFeatureNode, BTreeSet<SelectedFeatureNode>>::new();

    for (from_id, to_id, edge) in union.links(DependencyDirection::Forward) {
        if !matches!(edge, FeatureEdge::FeatureToBase | FeatureEdge::NamedFeature) {
            continue;
        }
        let from = feature_graph
            .metadata(from_id)
            .map_err(crate::map_query_err)?;
        let to = feature_graph
            .metadata(to_id)
            .map_err(crate::map_query_err)?;
        for (side, selected) in [(BuildSide::Target, target), (BuildSide::Host, host)] {
            if selected
                .contains(from.feature_id())
                .map_err(crate::map_query_err)?
                && selected
                    .contains(to.feature_id())
                    .map_err(crate::map_query_err)?
            {
                add_selected_feature_edge(&mut adjacency, side, &from, side, &to);
            }
        }
    }

    for link in union.conditional_links(DependencyDirection::Forward) {
        let (from, to) = link.endpoints();
        let from_target = target
            .contains(from.feature_id())
            .map_err(crate::map_query_err)?;
        let to_target = target
            .contains(to.feature_id())
            .map_err(crate::map_query_err)?;
        let from_host = host
            .contains(from.feature_id())
            .map_err(crate::map_query_err)?;
        let to_host = host
            .contains(to.feature_id())
            .map_err(crate::map_query_err)?;
        let same_package = from.package_id() == to.package_id();
        let package_link = selected_package_link(link.package_link());
        let selected_for_target = target_links.contains(&package_link);
        let selected_for_target_host =
            build_links.contains(&package_link) || proc_macro_links.contains(&package_link);
        let selected_for_host = host_links.contains(&package_link);

        if from_target
            && to_target
            && (selected_for_target || (same_package && selected_for_target_host))
        {
            add_selected_feature_edge(
                &mut adjacency,
                BuildSide::Target,
                &from,
                BuildSide::Target,
                &to,
            );
        }
        if from_target && to_host && !same_package && selected_for_target_host {
            add_selected_feature_edge(
                &mut adjacency,
                BuildSide::Target,
                &from,
                BuildSide::Host,
                &to,
            );
        }
        if from_host && to_host && selected_for_host {
            add_selected_feature_edge(&mut adjacency, BuildSide::Host, &from, BuildSide::Host, &to);
        }
    }

    Ok((starts, adjacency))
}

fn selected_package_links<'g>(
    links: impl Iterator<Item = PackageLink<'g>>,
) -> BTreeSet<SelectedPackageLink> {
    links.map(selected_package_link).collect()
}

fn selected_package_link(link: PackageLink<'_>) -> SelectedPackageLink {
    let (from, to) = link.endpoints();
    SelectedPackageLink {
        from: from.id().clone(),
        to: to.id().clone(),
        dep_name: link.dep_name().to_owned(),
    }
}

fn add_selected_feature_edge(
    adjacency: &mut SelectedFeatureAdjacency,
    from_side: BuildSide,
    from: &FeatureMetadata<'_>,
    to_side: BuildSide,
    to: &FeatureMetadata<'_>,
) {
    let Some(from) = selected_feature_node(from_side, from) else {
        return;
    };
    let Some(to) = selected_feature_node(to_side, to) else {
        return;
    };
    adjacency.entry(from).or_default().insert(to);
}

fn selected_feature_node(
    side: BuildSide,
    metadata: &FeatureMetadata<'_>,
) -> Option<SelectedFeatureNode> {
    let package = metadata.package();
    if !package.in_workspace() {
        return None;
    }
    let label = match metadata.label() {
        FeatureLabel::Base => SelectedFeatureLabel::Base,
        FeatureLabel::Named(name) => SelectedFeatureLabel::Named(name.to_owned()),
        FeatureLabel::OptionalDependency(name) => {
            SelectedFeatureLabel::OptionalDependency(name.to_owned())
        }
    };
    Some(SelectedFeatureNode {
        side,
        package: PackageKey(package.name().to_owned()),
        label,
    })
}

fn required_activation_path(
    root: &PackageKey,
    starts: &SelectedFeatureStarts,
    side: BuildSide,
    feature: &FeatureKey,
    adjacency: &SelectedFeatureAdjacency,
) -> Result<ActivationPath, WorkspaceFactsError> {
    activation_path(starts, side, feature, adjacency).ok_or_else(|| {
        WorkspaceFactsError::UnexplainedFeatureActivation {
            root: root.as_str().to_owned(),
            package: feature.package().as_str().to_owned(),
            feature: feature.name().to_owned(),
            side: side.to_string(),
        }
    })
}

fn activation_path(
    starts: &SelectedFeatureStarts,
    side: BuildSide,
    feature: &FeatureKey,
    adjacency: &SelectedFeatureAdjacency,
) -> Option<ActivationPath> {
    let goal = SelectedFeatureNode {
        side,
        package: feature.package().clone(),
        label: SelectedFeatureLabel::Named(feature.name().to_owned()),
    };
    let mut queue = starts.iter().cloned().collect::<VecDeque<_>>();
    let mut previous = BTreeMap::<SelectedFeatureNode, SelectedFeatureNode>::new();
    let mut visited = starts.clone();
    while let Some(node) = queue.pop_front() {
        if node == goal {
            break;
        }
        for next in adjacency.get(&node).into_iter().flatten() {
            if visited.insert(next.clone()) {
                previous.insert(next.clone(), node.clone());
                queue.push_back(next.clone());
            }
        }
    }
    if !visited.contains(&goal) {
        return None;
    }

    let mut feature_path = vec![goal.clone()];
    let mut cursor = goal;
    while let Some(parent) = previous.get(&cursor) {
        cursor = parent.clone();
        feature_path.push(cursor.clone());
    }
    feature_path.reverse();
    let nodes = feature_path
        .into_iter()
        .map(|node| match node.label {
            SelectedFeatureLabel::Base => ActivationNode::Package {
                side: node.side,
                package: node.package,
            },
            SelectedFeatureLabel::Named(name) => ActivationNode::Feature {
                side: node.side,
                feature: FeatureKey {
                    package: node.package,
                    name,
                },
            },
            SelectedFeatureLabel::OptionalDependency(name) => ActivationNode::OptionalDependency {
                side: node.side,
                package: node.package,
                name,
            },
        })
        .collect();
    Some(ActivationPath { nodes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_selected_path_fails_closed() {
        let root = PackageKey("root".to_owned());
        let feature = FeatureKey {
            package: PackageKey("guarded".to_owned()),
            name: "danger".to_owned(),
        };
        assert!(matches!(
            required_activation_path(
                &root,
                &SelectedFeatureStarts::new(),
                BuildSide::Target,
                &feature,
                &SelectedFeatureAdjacency::new(),
            ),
            Err(WorkspaceFactsError::UnexplainedFeatureActivation {
                root,
                package,
                feature,
                side,
            }) if root == "root"
                && package == "guarded"
                && feature == "danger"
                && side == "target"
        ));
    }
}
