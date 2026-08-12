//! Positive Release Surface derived from Cargo facts and selected assembly artifacts.

use semver::{Op, Version, VersionReq};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use workspacefacts::{
    ApiStability, DependencyKind, DependencyResolution, DependencySource, OfficialProfile,
    PublicApiOwner, PublishPolicy, TargetKind, WorkspaceFacts,
};

use crate::assembly::{Finding, Rule};
use crate::assembly_governance::{ArtifactLifecycle, ArtifactsJoined, AssemblyGovernanceIr};
use crate::diagnostic::finding;

const CRATES_IO_REGISTRY: &str = "crates-io";
const CRATES_IO_GIT_INDEX: &str = "https://github.com/rust-lang/crates.io-index";
const CRATES_IO_SPARSE_INDEX: &str = "https://index.crates.io/";

/// INVARIANT: RELEASE-SURFACE-EXACT-SET-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::exact_set_and_reference_conflicts_are_aggregated_and_sorted", anti_vacuity = "tests::real_workspace_release_surface_joins_live_facts_without_snapshot_golden" } -- Cargo-publishable workspace packages and the positive package selection are an exact set; selected profile artifacts require independent activation authority and join the existing assembly artifact IR.
#[derive(Debug)]
pub(crate) struct ReleaseSurface {
    packages: Vec<ReleasePackage>,
    profile_artifacts: Vec<ReleaseProfileArtifact>,
    publish_order: Vec<String>,
}

impl ReleaseSurface {
    pub(crate) fn packages(&self) -> &[ReleasePackage] {
        &self.packages
    }

    pub(crate) fn profile_artifacts(&self) -> &[ReleaseProfileArtifact] {
        &self.profile_artifacts
    }

    #[cfg(test)]
    pub(crate) fn publish_order(&self) -> &[String] {
        &self.publish_order
    }

    pub(crate) fn observed_summary(&self) -> String {
        let mut output = String::from("release packages=[");
        for (index, package) in self.packages.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            let registries = match package.publish_policy() {
                PublishPolicy::Disabled => "disabled".to_owned(),
                PublishPolicy::Unrestricted => "unrestricted".to_owned(),
                PublishPolicy::Registries(registries) => {
                    format!(
                        "registries:{}",
                        registries.iter().cloned().collect::<Vec<_>>().join("+")
                    )
                }
            };
            let owner = match package.public_api_owner() {
                PublicApiOwner::StandaloneComponent => "standalone-component",
                PublicApiOwner::FoundationPublic => "foundation-public",
                PublicApiOwner::PlatformPublic => "platform-public",
            };
            let stability = match package.api_stability() {
                ApiStability::Experimental => "experimental",
                ApiStability::Stable => "stable",
            };
            let profiles = package
                .profiles()
                .iter()
                .map(|profile| profile.as_str())
                .collect::<Vec<_>>()
                .join("+");
            let _ = write!(
                output,
                "{}@{}/msrv:{}/{registries}/{owner}/{stability}/profiles:{profiles}",
                package.package(),
                package.version(),
                package.minimum_rust_version()
            );
        }
        output.push_str("], profile artifacts=[");
        for (index, artifact) in self.profile_artifacts.iter().enumerate() {
            if index > 0 {
                output.push_str(", ");
            }
            let _ = write!(
                output,
                "{}={}:{}#{}:{}#{}",
                artifact.profile().as_str(),
                artifact.assembly(),
                artifact.binary_package(),
                artifact.binary_target(),
                artifact.image_dockerfile(),
                artifact.image_target()
            );
        }
        output.push_str("], publish order=[");
        output.push_str(&self.publish_order.join(", "));
        output.push(']');
        output
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PublishClosurePlan {
    order: Vec<String>,
}

impl PublishClosurePlan {
    #[cfg(test)]
    pub(crate) fn order(&self) -> &[String] {
        &self.order
    }
}

/// Validate an explicitly requested candidate set and derive a stable dependency-first order.
///
/// The requested set is deliberately supplied by the caller: this function is closure policy,
/// not a second package inventory. Dev dependencies never enter the registry publish closure.
///
/// INVARIANT: RELEASE-PUBLISH-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::closure_planner_rejects_wildcard_outside_and_disabled_edges", anti_vacuity = "tests::real_workspace_release_surface_joins_live_facts_without_snapshot_golden" } -- selected Cargo packages and every normal/build dependency must form an exact, versioned crates.io closure with a stable dependency-first order.
pub(crate) fn plan_publish_closure(
    facts: &WorkspaceFacts,
    requested: &BTreeSet<String>,
) -> (Option<PublishClosurePlan>, Vec<Finding>) {
    let catalog = facts.workspace_packages();
    let packages_by_name = catalog
        .iter()
        .map(|package| (package.key().as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    let mut dependency_to_dependents = requested
        .iter()
        .map(|name| (name.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, BTreeSet<String>>>();
    let mut indegree = requested
        .iter()
        .map(|name| (name.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();

    for name in requested {
        let Some(package) = packages_by_name.get(name.as_str()).copied() else {
            findings.push(finding(
                Rule::ReleasePublishClosure,
                "publish-closure/requested-package",
                "requested publish-closure package is not a workspace member",
            ));
            continue;
        };

        validate_publish_metadata(package, &mut findings);

        let Ok(package_key) = facts.package_key(name) else {
            findings.push(finding(
                Rule::ReleasePublishClosure,
                format!("package:{name}"),
                "requested package identity cannot be resolved",
            ));
            continue;
        };
        let Ok(dependencies) = facts.direct_dependencies_for(&package_key) else {
            findings.push(finding(
                Rule::ReleasePublishClosure,
                format!("package:{name}"),
                "direct dependency facts are unavailable",
            ));
            continue;
        };

        for dependency in dependencies {
            if dependency.kind() == DependencyKind::Dev {
                continue;
            }
            let dependency_subject = format!("package:{name}/dependency:{}", dependency.name());
            if let Some(detail) =
                dependency_version_requirement_error(dependency.version_requirement())
            {
                findings.push(finding(
                    Rule::ReleasePublishClosure,
                    dependency_subject.clone(),
                    detail,
                ));
            }
            match dependency.source() {
                DependencySource::Workspace { .. } => {
                    let DependencyResolution::Resolved(target_key) = dependency.resolution() else {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject,
                            "workspace path dependency does not resolve to a package identity",
                        ));
                        continue;
                    };
                    let target_name = target_key.as_str();
                    let Some(target) = packages_by_name.get(target_name).copied() else {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject,
                            "workspace path dependency does not resolve to a workspace member",
                        ));
                        continue;
                    };
                    if let Some(detail) = workspace_dependency_version_error(
                        dependency.version_requirement(),
                        target.version(),
                    ) {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject.clone(),
                            detail,
                        ));
                    }
                    if !requested.contains(target_name) {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject.clone(),
                            "workspace path dependency is outside the requested publish closure",
                        ));
                        continue;
                    }
                    if !publish_policy_targets_crates_io(target.publish_policy()) {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject.clone(),
                            "workspace path dependency is not restricted to the crates.io registry",
                        ));
                    }
                    if dependency_to_dependents
                        .get_mut(target_name)
                        .is_some_and(|dependents| dependents.insert(name.clone()))
                    {
                        if let Some(degree) = indegree.get_mut(name) {
                            *degree += 1;
                        } else {
                            findings.push(finding(
                                Rule::ReleasePublishClosure,
                                dependency_subject,
                                "requested package is missing from the closure topology",
                            ));
                        }
                    }
                }
                DependencySource::Path { .. } => findings.push(finding(
                    Rule::ReleasePublishClosure,
                    dependency_subject,
                    "non-workspace path dependency cannot enter a registry publish closure",
                )),
                source @ (DependencySource::Registry { .. }
                | DependencySource::Sparse { .. }
                | DependencySource::Git { .. }
                | DependencySource::UnknownExternal { .. }) => {
                    if let Some(detail) = invalid_external_source_detail(source) {
                        findings.push(finding(
                            Rule::ReleasePublishClosure,
                            dependency_subject,
                            detail,
                        ));
                    }
                }
            }
        }
    }

    let order = stable_publish_order(&dependency_to_dependents, &mut indegree, &mut findings);
    if order.len() != requested.len() {
        findings.push(finding(
            Rule::ReleasePublishClosure,
            "publish-closure",
            "workspace path dependency cycle prevents a publish order",
        ));
    }

    findings.sort_by(|left, right| {
        (&left.subject, left.rule, &left.detail).cmp(&(&right.subject, right.rule, &right.detail))
    });
    if findings.is_empty() {
        (Some(PublishClosurePlan { order }), findings)
    } else {
        (None, findings)
    }
}

fn workspace_dependency_version_error(
    requirement: &VersionReq,
    target: &Version,
) -> Option<&'static str> {
    if !requirement.matches(target) {
        Some(
            "workspace path dependency version requirement does not match the resolved package version",
        )
    } else {
        None
    }
}

fn dependency_version_requirement_error(requirement: &VersionReq) -> Option<&'static str> {
    if requirement == &VersionReq::STAR
        || requirement
            .comparators
            .iter()
            .any(|comparator| comparator.op == Op::Wildcard)
    {
        Some("normal/build dependency must declare a non-wildcard version requirement")
    } else {
        None
    }
}

fn publish_policy_targets_crates_io(policy: &PublishPolicy) -> bool {
    matches!(
        policy,
        PublishPolicy::Registries(registries)
            if registries.len() == 1 && registries.contains(CRATES_IO_REGISTRY)
    )
}

fn invalid_external_source_detail(source: &DependencySource) -> Option<&'static str> {
    match source {
        DependencySource::Registry { url } if url == CRATES_IO_GIT_INDEX => None,
        DependencySource::Sparse { url } if url == CRATES_IO_SPARSE_INDEX => None,
        DependencySource::Registry { .. } | DependencySource::Sparse { .. } => {
            Some("external dependency resolves from a non-crates.io registry")
        }
        DependencySource::Git { .. } => {
            Some("Git dependency cannot enter a crates.io publish closure")
        }
        DependencySource::UnknownExternal { .. } => {
            Some("unknown external dependency source cannot enter a crates.io publish closure")
        }
        DependencySource::Workspace { .. } | DependencySource::Path { .. } => None,
    }
}

fn stable_publish_order(
    dependency_to_dependents: &BTreeMap<String, BTreeSet<String>>,
    indegree: &mut BTreeMap<String, usize>,
    findings: &mut Vec<Finding>,
) -> Vec<String> {
    let mut ready = indegree
        .iter()
        .filter_map(|(name, degree)| (*degree == 0).then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(indegree.len());
    while let Some(name) = ready.pop_first() {
        order.push(name.clone());
        for dependent in dependency_to_dependents.get(&name).into_iter().flatten() {
            let Some(degree) = indegree.get_mut(dependent) else {
                findings.push(finding(
                    Rule::ReleasePublishClosure,
                    "publish-closure",
                    "dependent package is missing from the closure topology",
                ));
                continue;
            };
            *degree -= 1;
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    order
}

fn validate_publish_metadata(
    package: &workspacefacts::WorkspacePackageFacts,
    findings: &mut Vec<Finding>,
) {
    let subject = format!("package:{}", package.key().as_str());
    if package.version() == &Version::new(0, 0, 0) {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package must use an independent non-0.0.0 version",
        ));
    }
    if package.minimum_rust_version().is_none() {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package must declare a minimum Rust version",
        ));
    }
    if package.publish_policy().is_publishable()
        && !publish_policy_targets_crates_io(package.publish_policy())
    {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "publishable candidate must be restricted to the crates.io registry",
        ));
    }
    let metadata = package.publish_metadata();
    if metadata.description().is_none_or(str::is_empty) {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package description is missing",
        ));
    }
    if metadata.license().is_none() && metadata.license_file().is_none() {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package license or license-file is missing",
        ));
    }
    if metadata.repository().is_none_or(str::is_empty) {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package repository is missing",
        ));
    }
    if metadata.readme().is_none() {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package README is missing",
        ));
    }
    if metadata.categories().is_empty() {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package categories are missing",
        ));
    }
    if metadata.keywords().is_empty() {
        findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject.clone(),
            "candidate package keywords are missing",
        ));
    }
    match metadata.features().get("default") {
        Some(default) if default.is_empty() => {}
        Some(_) => findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject,
            "candidate package default feature must be explicitly empty",
        )),
        None => findings.push(finding(
            Rule::ReleasePackageMetadata,
            subject,
            "candidate package must explicitly declare an empty default feature",
        )),
    }
}

#[derive(Debug)]
pub(crate) struct ReleasePackage {
    package: String,
    version: Version,
    minimum_rust_version: Version,
    publish_policy: PublishPolicy,
    public_api_owner: PublicApiOwner,
    api_stability: ApiStability,
    profiles: Vec<OfficialProfile>,
}

impl ReleasePackage {
    pub(crate) fn package(&self) -> &str {
        &self.package
    }

    pub(crate) fn version(&self) -> &Version {
        &self.version
    }

    pub(crate) fn minimum_rust_version(&self) -> &Version {
        &self.minimum_rust_version
    }

    pub(crate) fn publish_policy(&self) -> &PublishPolicy {
        &self.publish_policy
    }

    pub(crate) const fn public_api_owner(&self) -> PublicApiOwner {
        self.public_api_owner
    }

    pub(crate) const fn api_stability(&self) -> ApiStability {
        self.api_stability
    }

    pub(crate) fn profiles(&self) -> &[OfficialProfile] {
        &self.profiles
    }
}

#[derive(Debug)]
pub(crate) struct ReleaseProfileArtifact {
    profile: OfficialProfile,
    assembly: String,
    binary_package: String,
    binary_target: String,
    image_dockerfile: String,
    image_target: String,
}

impl ReleaseProfileArtifact {
    pub(crate) const fn profile(&self) -> OfficialProfile {
        self.profile
    }

    pub(crate) fn assembly(&self) -> &str {
        &self.assembly
    }

    pub(crate) fn binary_package(&self) -> &str {
        &self.binary_package
    }

    pub(crate) fn binary_target(&self) -> &str {
        &self.binary_target
    }

    pub(crate) fn image_dockerfile(&self) -> &str {
        &self.image_dockerfile
    }

    pub(crate) fn image_target(&self) -> &str {
        &self.image_target
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ArtifactProjection {
    assembly: String,
    lifecycle: ProjectedArtifactLifecycle,
}

#[derive(Clone, Debug)]
enum ProjectedArtifactLifecycle {
    Supported {
        binary_package: String,
        binary_target: String,
        image_dockerfile: String,
        image_target: String,
    },
    CompileOnly,
}

impl ArtifactProjection {
    #[cfg(test)]
    fn supported(
        assembly: &str,
        binary_package: &str,
        binary_target: &str,
        image_dockerfile: &str,
        image_target: &str,
    ) -> Self {
        Self {
            assembly: assembly.to_owned(),
            lifecycle: ProjectedArtifactLifecycle::Supported {
                binary_package: binary_package.to_owned(),
                binary_target: binary_target.to_owned(),
                image_dockerfile: image_dockerfile.to_owned(),
                image_target: image_target.to_owned(),
            },
        }
    }

    #[cfg(test)]
    fn compile_only(assembly: &str) -> Self {
        Self {
            assembly: assembly.to_owned(),
            lifecycle: ProjectedArtifactLifecycle::CompileOnly,
        }
    }
}

pub(crate) fn requires_artifact_join(facts: &WorkspaceFacts) -> bool {
    matches!(
        facts.release_selection(),
        Ok(Some(selection)) if !selection.profile_artifacts().is_empty()
    )
}

pub(crate) fn project_artifacts(
    ir: &AssemblyGovernanceIr<ArtifactsJoined>,
) -> Vec<ArtifactProjection> {
    ir.artifacts()
        .iter()
        .map(|artifact| {
            let lifecycle = match &artifact.lifecycle {
                ArtifactLifecycle::Supported(supported) => ProjectedArtifactLifecycle::Supported {
                    binary_package: supported.binary.package.clone(),
                    binary_target: supported.binary.target.clone(),
                    image_dockerfile: supported.image.dockerfile.clone(),
                    image_target: supported.image.target.clone(),
                },
                ArtifactLifecycle::CompileOnly(_) => ProjectedArtifactLifecycle::CompileOnly,
            };
            ArtifactProjection {
                assembly: artifact.id.as_str().to_owned(),
                lifecycle,
            }
        })
        .collect()
}

pub(crate) fn validate(
    facts: &WorkspaceFacts,
    artifacts: &[ArtifactProjection],
) -> (Option<ReleaseSurface>, Vec<Finding>) {
    // INVARIANT: PREPUBLICATION-PATCH-LINE-01 { level = "Medium", exec = "release-surface", synthetic_red = "tests::release_version_line_rejects_major_or_minor_changes" }.
    let mut surface = ReleaseSurface {
        packages: Vec::new(),
        profile_artifacts: Vec::new(),
        publish_order: Vec::new(),
    };
    let selection = match facts.release_selection() {
        Ok(Some(selection)) => selection,
        Ok(None) => {
            return (
                None,
                vec![finding(
                    Rule::ReleaseSurfaceDeclaration,
                    "workspace.metadata.release-surface",
                    "positive release selection is missing",
                )],
            );
        }
        Err(error) => {
            return (
                None,
                vec![finding(
                    Rule::ReleaseSurfaceDeclaration,
                    error.subject(),
                    error.detail(),
                )],
            );
        }
    };

    let catalog = facts.workspace_packages();
    let packages_by_name = catalog
        .iter()
        .map(|package| (package.key().as_str(), package))
        .collect::<BTreeMap<_, _>>();
    let publishable = catalog
        .iter()
        .filter(|package| package.publish_policy().is_publishable())
        .map(|package| package.key().as_str().to_owned())
        .collect::<BTreeSet<_>>();
    let selected = selection
        .packages()
        .iter()
        .map(|package| package.package().to_owned())
        .collect::<BTreeSet<_>>();
    let mut findings = Vec::new();

    findings.extend(project_publish_order(facts, &selected, &mut surface));

    for package in publishable.difference(&selected) {
        findings.push(finding(
            Rule::ReleaseSurfaceExactSet,
            format!("package:{package}"),
            "Cargo-publishable package is missing from the positive selection",
        ));
    }

    let mut profile_rows = BTreeMap::new();
    for (index, selected_profile) in selection.profile_artifacts().iter().enumerate() {
        let profile = selected_profile.profile();
        let subject = format!("workspace.metadata.release-surface.profile-artifacts[{index}]");
        findings.push(finding(
            Rule::ReleaseSurfaceProfile,
            subject.clone(),
            "official profile activation facts are unavailable; artifact support alone cannot authorize selection",
        ));
        if profile_rows.insert(profile, selected_profile).is_some() {
            findings.push(finding(
                Rule::ReleaseSurfaceProfile,
                subject,
                "profile artifact is selected more than once",
            ));
            continue;
        }
        if selected_profile.assembly() != "runtime" {
            findings.push(finding(
                Rule::ReleaseSurfaceProfile,
                subject,
                "ADR-024 designates the runtime assembly for this official profile",
            ));
            continue;
        }
        let Some(artifact) = artifacts
            .iter()
            .find(|artifact| artifact.assembly == selected_profile.assembly())
        else {
            findings.push(finding(
                Rule::ReleaseSurfaceProfile,
                subject,
                "selected assembly has no joined artifact declaration",
            ));
            continue;
        };
        match &artifact.lifecycle {
            ProjectedArtifactLifecycle::CompileOnly => findings.push(finding(
                Rule::ReleaseSurfaceProfile,
                subject,
                "compile-only assembly cannot be a release profile artifact",
            )),
            ProjectedArtifactLifecycle::Supported {
                binary_package,
                binary_target,
                image_dockerfile,
                image_target,
            } => {
                let artifact_identity_valid = !image_dockerfile.is_empty()
                    && !image_target.is_empty()
                    && facts
                        .package_key(binary_package)
                        .ok()
                        .and_then(|package| facts.targets_for(&package).ok())
                        .is_some_and(|targets| {
                            targets.iter().any(|target| {
                                target.kind() == TargetKind::Binary
                                    && target.name() == binary_target
                            })
                        });
                if !artifact_identity_valid {
                    findings.push(finding(
                        Rule::ReleaseSurfaceProfile,
                        subject,
                        "selected artifact binary/image identity does not resolve in governed facts",
                    ));
                    continue;
                }
                // The joined artifact proves identity only. A later profile-activation owner must
                // provide independent typed authority before this row may mint surface state.
            }
        }
    }

    let selected_profiles = BTreeSet::<OfficialProfile>::new();
    let mut seen_packages = BTreeSet::new();
    for (index, selected_package) in selection.packages().iter().enumerate() {
        let name = selected_package.package();
        let subject = format!("workspace.metadata.release-surface.packages[{index}]");
        if !seen_packages.insert(name.to_owned()) {
            findings.push(finding(
                Rule::ReleaseSurfacePackage,
                subject,
                "package is selected more than once",
            ));
            continue;
        }
        let Some(package) = packages_by_name.get(name).copied() else {
            findings.push(finding(
                Rule::ReleaseSurfacePackage,
                subject,
                "selected package is not a workspace member",
            ));
            continue;
        };
        if !package.publish_policy().is_publishable() {
            findings.push(finding(
                Rule::ReleaseSurfaceExactSet,
                subject.clone(),
                "selected package has Cargo publish disabled",
            ));
        }
        let Some(minimum_rust_version) = package.minimum_rust_version() else {
            findings.push(finding(
                Rule::ReleaseSurfacePackage,
                subject.clone(),
                "selected package has no resolved minimum Rust version",
            ));
            continue;
        };
        let Some(version_line) = selected_package.version_line() else {
            findings.push(finding(
                Rule::ReleaseSurfacePackage,
                subject.clone(),
                "selected package must declare a frozen `version-line` as `major.minor`",
            ));
            continue;
        };
        if !version_line_matches(version_line, package.version()) {
            findings.push(finding(
                Rule::ReleaseSurfacePackage,
                subject.clone(),
                format!(
                    "version-line `{version_line}` does not match package version `{}`; before first publication only the patch component may change",
                    package.version()
                ),
            ));
            continue;
        }
        let mut package_profiles = BTreeSet::new();
        let mut profiles_valid = true;
        for profile in selected_package.profiles() {
            if !package_profiles.insert(*profile) {
                findings.push(finding(
                    Rule::ReleaseSurfacePackage,
                    subject.clone(),
                    format!(
                        "profile `{}` is referenced more than once",
                        profile.as_str()
                    ),
                ));
                profiles_valid = false;
            }
            if !selected_profiles.contains(profile) {
                findings.push(finding(
                    Rule::ReleaseSurfacePackage,
                    subject.clone(),
                    format!(
                        "profile `{}` has no selected release artifact",
                        profile.as_str()
                    ),
                ));
                profiles_valid = false;
            }
        }
        if package.publish_policy().is_publishable() && profiles_valid {
            surface.packages.push(ReleasePackage {
                package: package.key().as_str().to_owned(),
                version: package.version().clone(),
                minimum_rust_version: minimum_rust_version.clone(),
                publish_policy: package.publish_policy().clone(),
                public_api_owner: selected_package.public_api_owner(),
                api_stability: selected_package.api_stability(),
                profiles: package_profiles.into_iter().collect(),
            });
        }
    }

    surface
        .packages
        .sort_by(|left, right| left.package.cmp(&right.package));
    surface
        .profile_artifacts
        .sort_by_key(|artifact| artifact.profile);
    findings.sort_by(|left, right| {
        (&left.subject, left.rule, &left.detail).cmp(&(&right.subject, right.rule, &right.detail))
    });
    if findings.is_empty() {
        (Some(surface), findings)
    } else {
        (None, findings)
    }
}

fn version_line_matches(line: &str, version: &Version) -> bool {
    let Some((major, minor)) = line.split_once('.') else {
        return false;
    };
    !minor.contains('.')
        && major.parse::<u64>().ok() == Some(version.major)
        && minor.parse::<u64>().ok() == Some(version.minor)
        && line == format!("{}.{}", version.major, version.minor)
}

fn project_publish_order(
    facts: &WorkspaceFacts,
    selected: &BTreeSet<String>,
    surface: &mut ReleaseSurface,
) -> Vec<Finding> {
    let (closure, findings) = plan_publish_closure(facts, selected);
    if let Some(closure) = closure {
        surface.publish_order = closure.order;
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::path::Path;
    use workspacefacts::WorkspaceFacts;
    use workspacefacts::testing::{
        metadata_json, path_dependency, path_package, path_package_id, registry_package,
        resolve_node, resolve_node_with_dep_kinds, target,
    };

    fn make_release_ready(package: &mut Value, absolute_path: &str) {
        package["version"] = json!("0.1.0");
        package["id"] = json!(format!("path+file://{absolute_path}#0.1.0"));
        package["description"] = json!("Synthetic release candidate");
        package["license_file"] = json!(format!("{absolute_path}/LICENSE"));
        package["repository"] = json!("https://example.invalid/repository");
        package["readme"] = json!(format!("{absolute_path}/README.md"));
        package["categories"] = json!(["development-tools"]);
        package["keywords"] = json!(["synthetic"]);
        package["features"] = json!({"default": []});
    }

    fn facts_with_selection(
        selection: Value,
        alpha_publish: Value,
        alpha_msrv: Value,
        beta_publish: Value,
    ) -> Result<WorkspaceFacts> {
        let alpha_path = "/workspace/crates/alpha";
        let beta_path = "/workspace/crates/beta";
        let server_path = "/workspace/bins/server";
        let mut alpha = path_package(
            "alpha",
            alpha_path,
            vec![target(
                "alpha",
                "lib",
                "/workspace/crates/alpha/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        make_release_ready(&mut alpha, alpha_path);
        alpha["publish"] = alpha_publish;
        alpha["rust_version"] = alpha_msrv;
        let mut beta = path_package(
            "beta",
            beta_path,
            vec![target(
                "beta",
                "lib",
                "/workspace/crates/beta/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        beta["publish"] = beta_publish;
        let server = path_package(
            "server",
            server_path,
            vec![target(
                "server",
                "bin",
                "/workspace/bins/server/src/main.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        let alpha_id = alpha["id"]
            .as_str()
            .context("synthetic alpha id")?
            .to_owned();
        let beta_id = path_package_id(beta_path);
        let server_id = path_package_id(server_path);
        let metadata = metadata_json(
            "/workspace",
            vec![alpha, beta, server],
            vec![alpha_id.clone(), beta_id.clone(), server_id.clone()],
            vec![
                resolve_node(&alpha_id, &[]),
                resolve_node(&beta_id, &[]),
                resolve_node(&server_id, &[]),
            ],
        );
        let mut metadata: Value = serde_json::from_str(&metadata)?;
        metadata["metadata"] = json!({"release-surface": selection});
        let metadata = serde_json::to_string(&metadata)?;
        Ok(WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &metadata,
        )?)
    }

    fn supported_runtime() -> ArtifactProjection {
        ArtifactProjection::supported("runtime", "server", "server", "Dockerfile", "runtime")
    }

    fn two_package_closure_findings(
        requirement: &str,
        dependency_publish: Value,
        include_dependency: bool,
        kind: Option<&str>,
    ) -> Result<Vec<Finding>> {
        let dependency_path = "/workspace/crates/dependency";
        let root_path = "/workspace/crates/root";
        let mut dependency = path_package(
            "dependency",
            dependency_path,
            vec![target(
                "dependency",
                "lib",
                "/workspace/crates/dependency/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        make_release_ready(&mut dependency, dependency_path);
        dependency["publish"] = dependency_publish;
        let mut declaration = path_dependency("dependency", dependency_path);
        declaration["req"] = json!(requirement);
        declaration["kind"] = json!(kind);
        let mut root = path_package(
            "root",
            root_path,
            vec![target(
                "root",
                "lib",
                "/workspace/crates/root/src/lib.rs",
                true,
                &[],
            )],
            vec![declaration],
            json!({}),
        );
        make_release_ready(&mut root, root_path);
        let dependency_id = dependency["id"]
            .as_str()
            .context("dependency id")?
            .to_owned();
        let root_id = root["id"].as_str().context("root id")?.to_owned();
        let metadata = metadata_json(
            "/workspace",
            vec![root, dependency],
            vec![root_id.clone(), dependency_id.clone()],
            vec![
                resolve_node_with_dep_kinds(&root_id, &[("dependency", &dependency_id, kind)], &[]),
                resolve_node(&dependency_id, &[]),
            ],
        );
        let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
        let mut requested = BTreeSet::from(["root".to_owned()]);
        if include_dependency {
            requested.insert("dependency".to_owned());
        }
        Ok(plan_publish_closure(&facts, &requested).1)
    }

    fn external_dependency_findings(requirement: &str, source: &str) -> Result<Vec<Finding>> {
        let root_path = "/workspace/crates/root";
        let external = registry_package(
            "external",
            "1.0.0",
            "/registry/external/Cargo.toml",
            vec![target(
                "external",
                "lib",
                "/registry/external/src/lib.rs",
                true,
                &[],
            )],
        );
        let external_id = external["id"].as_str().context("external id")?.to_owned();
        let declaration = json!({
            "name": "external",
            "source": source,
            "req": requirement,
            "kind": null,
            "rename": null,
            "optional": false,
            "uses_default_features": false,
            "features": [],
            "target": null,
            "registry": null,
            "path": null
        });
        let mut root = path_package(
            "root",
            root_path,
            vec![target(
                "root",
                "lib",
                "/workspace/crates/root/src/lib.rs",
                true,
                &[],
            )],
            vec![declaration],
            json!({}),
        );
        make_release_ready(&mut root, root_path);
        let root_id = root["id"].as_str().context("root id")?.to_owned();
        let metadata = metadata_json(
            "/workspace",
            vec![root, external],
            vec![root_id.clone()],
            vec![
                resolve_node(&root_id, &[("external", &external_id)]),
                resolve_node(&external_id, &[]),
            ],
        );
        let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
        Ok(plan_publish_closure(&facts, &BTreeSet::from(["root".to_owned()])).1)
    }

    #[test]
    fn closure_planner_rejects_incomplete_publish_metadata() -> Result<()> {
        let path = "/workspace/crates/incomplete";
        let mut package = path_package(
            "incomplete",
            path,
            vec![target(
                "incomplete",
                "lib",
                "/workspace/crates/incomplete/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        package["rust_version"] = Value::Null;
        let id = path_package_id(path);
        let metadata = metadata_json(
            "/workspace",
            vec![package],
            vec![id.clone()],
            vec![resolve_node(&id, &[])],
        );
        let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
        let requested = BTreeSet::from(["incomplete".to_owned()]);
        let (plan, findings) = plan_publish_closure(&facts, &requested);
        assert!(plan.is_none());
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ReleasePackageMetadata)
        );
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.detail.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "candidate package categories are missing",
                "candidate package description is missing",
                "candidate package keywords are missing",
                "candidate package license or license-file is missing",
                "candidate package must declare a minimum Rust version",
                "candidate package must explicitly declare an empty default feature",
                "candidate package must use an independent non-0.0.0 version",
                "candidate package README is missing",
                "candidate package repository is missing",
            ])
        );
        Ok(())
    }

    #[test]
    fn closure_planner_rejects_wildcard_outside_and_disabled_edges() -> Result<()> {
        let wildcard = two_package_closure_findings("*", json!(null), true, None)?;
        assert!(wildcard.iter().any(|finding| {
            finding.rule == Rule::ReleasePublishClosure && finding.detail.contains("non-wildcard")
        }));

        let outside = two_package_closure_findings("^0.1", json!(null), false, None)?;
        assert!(outside.iter().any(|finding| {
            finding.rule == Rule::ReleasePublishClosure
                && finding
                    .detail
                    .contains("outside the requested publish closure")
        }));

        let disabled = two_package_closure_findings("^0.1", json!([]), true, None)?;
        assert!(disabled.iter().any(|finding| {
            finding.rule == Rule::ReleasePublishClosure
                && finding.detail.contains("not restricted to the crates.io")
        }));
        Ok(())
    }

    #[test]
    fn closure_planner_rejects_wildcard_crates_io_dependency() -> Result<()> {
        for source in [
            format!("registry+{CRATES_IO_GIT_INDEX}"),
            format!("sparse+{CRATES_IO_SPARSE_INDEX}"),
        ] {
            let findings = external_dependency_findings("*", &source)?;
            assert!(findings.iter().any(|finding| {
                finding.rule == Rule::ReleasePublishClosure
                    && finding.detail.contains("non-wildcard")
            }));
        }
        Ok(())
    }

    #[test]
    fn build_dependencies_share_the_publish_closure_policy() -> Result<()> {
        let wildcard = two_package_closure_findings("*", json!(null), true, Some("build"))?;
        assert!(wildcard.iter().any(|finding| {
            finding.rule == Rule::ReleasePublishClosure && finding.detail.contains("non-wildcard")
        }));

        let outside = two_package_closure_findings("^0.1", json!(null), false, Some("build"))?;
        assert!(outside.iter().any(|finding| {
            finding.rule == Rule::ReleasePublishClosure
                && finding
                    .detail
                    .contains("outside the requested publish closure")
        }));

        // Guppy rejects a resolve graph whose selected package cannot satisfy the declared
        // requirement before the planner can observe it. The typed policy helper therefore owns
        // this otherwise-unconstructable RED, while the build fixture above proves build edges
        // reach the same workspace-source branch.
        let mismatch =
            workspace_dependency_version_error(&"^0.2".parse()?, &Version::parse("0.1.0")?);
        assert!(mismatch.is_some_and(|detail| detail.contains("does not match")));
        Ok(())
    }

    #[test]
    fn closure_policy_rejects_version_mismatch_and_non_crates_io_sources() -> Result<()> {
        let mismatch =
            workspace_dependency_version_error(&"^0.2".parse()?, &Version::parse("0.1.0")?);
        assert!(mismatch.is_some_and(|detail| detail.contains("does not match")));
        assert!(
            invalid_external_source_detail(&DependencySource::Registry {
                url: "https://example.invalid/index".to_owned(),
            })
            .is_some()
        );
        assert!(
            invalid_external_source_detail(&DependencySource::Git {
                repository: "https://example.invalid/repo".to_owned(),
                req: workspacefacts::GitDependencyReq::Default,
                resolved: "deadbeef".to_owned(),
            })
            .is_some()
        );
        assert!(
            invalid_external_source_detail(&DependencySource::UnknownExternal {
                source: "mystery".to_owned(),
            })
            .is_some()
        );
        assert!(
            invalid_external_source_detail(&DependencySource::Registry {
                url: CRATES_IO_GIT_INDEX.to_owned(),
            })
            .is_none()
        );
        assert!(publish_policy_targets_crates_io(
            &PublishPolicy::Registries(BTreeSet::from([CRATES_IO_REGISTRY.to_owned()]),)
        ));
        assert!(!publish_policy_targets_crates_io(
            &PublishPolicy::Unrestricted
        ));
        Ok(())
    }

    #[test]
    fn publishable_candidate_must_be_restricted_to_crates_io() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [{
                    "package": "alpha",
                    "version-line": "0.1",
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }),
            json!(null),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[]);
        assert!(surface.is_none());
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::ReleasePackageMetadata
                && finding.detail.contains("restricted to the crates.io")
        }));
        Ok(())
    }

    #[test]
    fn closure_planner_is_dependency_first_and_dev_edges_do_not_expand_it() -> Result<()> {
        let leaf_path = "/workspace/crates/leaf";
        let dev_path = "/workspace/crates/dev-only";
        let root_path = "/workspace/crates/root";
        let mut leaf = path_package(
            "leaf",
            leaf_path,
            vec![target(
                "leaf",
                "lib",
                "/workspace/crates/leaf/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        make_release_ready(&mut leaf, leaf_path);
        leaf["publish"] = json!(["crates-io"]);
        let mut dev_only = path_package(
            "dev-only",
            dev_path,
            vec![target(
                "dev_only",
                "lib",
                "/workspace/crates/dev-only/src/lib.rs",
                true,
                &[],
            )],
            vec![],
            json!({}),
        );
        make_release_ready(&mut dev_only, dev_path);
        let mut normal = path_dependency("leaf", leaf_path);
        normal["req"] = json!("^0.1.0");
        normal["optional"] = json!(true);
        normal["target"] = json!("cfg(unix)");
        let mut dev = path_dependency("dev-only", dev_path);
        dev["kind"] = json!("dev");
        let mut root = path_package(
            "root",
            root_path,
            vec![target(
                "root",
                "lib",
                "/workspace/crates/root/src/lib.rs",
                true,
                &[],
            )],
            vec![normal, dev],
            json!({}),
        );
        make_release_ready(&mut root, root_path);
        root["features"] = json!({"default": [], "leaf": ["dep:leaf"]});

        let leaf_id = leaf["id"].as_str().context("leaf id")?.to_owned();
        let dev_id = dev_only["id"].as_str().context("dev id")?.to_owned();
        let root_id = root["id"].as_str().context("root id")?.to_owned();
        let mut root_node = resolve_node_with_dep_kinds(
            &root_id,
            &[("leaf", &leaf_id, None), ("dev_only", &dev_id, Some("dev"))],
            &["leaf"],
        );
        root_node["deps"][0]["dep_kinds"][0]["target"] = json!("cfg(unix)");
        let metadata = metadata_json(
            "/workspace",
            vec![root, leaf, dev_only],
            vec![root_id.clone(), leaf_id.clone(), dev_id.clone()],
            vec![
                root_node,
                resolve_node(&leaf_id, &[]),
                resolve_node(&dev_id, &[]),
            ],
        );
        let facts = WorkspaceFacts::from_metadata_json(Path::new("/workspace"), &metadata)?;
        let requested = BTreeSet::from(["root".to_owned(), "leaf".to_owned()]);
        let (plan, findings) = plan_publish_closure(&facts, &requested);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        assert_eq!(
            plan.context("valid closure")?.order(),
            &["leaf".to_owned(), "root".to_owned()]
        );
        Ok(())
    }

    #[test]
    fn synthetic_nonempty_surface_derives_cargo_facts() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [{
                    "package": "alpha",
                    "version-line": "0.1",
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }),
            json!(["crates-io"]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[]);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        let surface = surface.context("valid selection must mint a ReleaseSurface")?;
        assert_eq!(surface.packages().len(), 1);
        assert_eq!(surface.packages()[0].package(), "alpha");
        assert_eq!(surface.packages()[0].version().to_string(), "0.1.0");
        assert_eq!(surface.publish_order(), &["alpha"]);
        assert_eq!(
            surface.packages()[0].minimum_rust_version().to_string(),
            "1.86.0"
        );
        assert!(surface.profile_artifacts().is_empty());
        Ok(())
    }

    #[test]
    fn release_version_line_rejects_major_or_minor_changes() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [{
                    "package": "alpha",
                    "version-line": "0.2",
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }),
            json!(["crates-io"]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[]);
        assert!(surface.is_none());
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::ReleaseSurfacePackage && finding.detail.contains("version-line")
        }));
        Ok(())
    }

    #[test]
    fn exact_set_and_reference_conflicts_are_aggregated_and_sorted() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [
                    {
                        "package": "alpha",
                        "version-line": "0.1",
                        "public-api-owner": "platform-public",
                        "api-stability": "stable",
                        "profiles": ["eventing", "eventing"]
                    },
                    {
                        "package": "alpha",
                        "version-line": "0.1",
                        "public-api-owner": "platform-public",
                        "api-stability": "stable",
                        "profiles": []
                    },
                    {
                        "package": "ghost",
                        "version-line": "0.1",
                        "public-api-owner": "standalone-component",
                        "api-stability": "experimental",
                        "profiles": []
                    }
                ],
                "profile-artifacts": [
                    {"profile": "core", "assembly": "identityaudit"},
                    {"profile": "core", "assembly": "runtime"}
                ]
            }),
            json!([]),
            json!(null),
            json!(null),
        )?;
        let artifacts = [
            supported_runtime(),
            ArtifactProjection::supported(
                "identityaudit",
                "identityaudit",
                "identityaudit-server",
                "Dockerfile",
                "identityaudit-runtime",
            ),
        ];
        let (surface, findings) = validate(&facts, &artifacts);
        assert!(
            surface.is_none(),
            "invalid selection must not mint a ReleaseSurface"
        );
        let rules = findings
            .iter()
            .map(|finding| finding.rule)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            rules,
            BTreeSet::from([
                Rule::ReleaseSurfaceExactSet,
                Rule::ReleaseSurfacePackage,
                Rule::ReleasePackageMetadata,
                Rule::ReleasePublishClosure,
                Rule::ReleaseSurfaceProfile,
            ])
        );
        assert!(
            findings.len() >= 7,
            "all independent conflicts must be reported: {findings:?}"
        );
        let subjects = findings
            .iter()
            .map(|finding| finding.subject.as_str())
            .collect::<Vec<_>>();
        assert!(subjects.windows(2).all(|pair| pair[0] <= pair[1]));
        Ok(())
    }

    #[test]
    fn supported_artifacts_do_not_auto_select_a_profile() -> Result<()> {
        let facts = facts_with_selection(
            json!({"packages": [], "profile-artifacts": []}),
            json!([]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[supported_runtime()]);
        assert!(findings.is_empty());
        let surface = surface.context("valid empty selection must mint a ReleaseSurface")?;
        assert!(surface.packages().is_empty());
        assert!(surface.profile_artifacts().is_empty());
        Ok(())
    }

    #[test]
    fn supported_artifact_cannot_authorize_an_official_profile() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [],
                "profile-artifacts": [{"profile": "core", "assembly": "runtime"}]
            }),
            json!([]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[supported_runtime()]);
        assert!(surface.is_none());
        assert!(findings.iter().any(|finding| {
            finding.rule == Rule::ReleaseSurfaceProfile
                && finding.detail.contains("activation facts are unavailable")
        }));
        Ok(())
    }

    #[test]
    fn compile_only_selected_profile_is_rejected() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [],
                "profile-artifacts": [{"profile": "core", "assembly": "runtime"}]
            }),
            json!([]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[ArtifactProjection::compile_only("runtime")]);
        assert!(surface.is_none());
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ReleaseSurfaceProfile)
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("compile-only"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("activation facts are unavailable"))
        );
        Ok(())
    }

    #[test]
    fn selected_profile_binary_identity_must_resolve_in_cargo_facts() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [],
                "profile-artifacts": [{"profile": "core", "assembly": "runtime"}]
            }),
            json!([]),
            json!("1.86"),
            json!([]),
        )?;
        let artifact = ArtifactProjection::supported(
            "runtime",
            "missing-package",
            "missing-target",
            "Dockerfile",
            "runtime",
        );
        let (surface, findings) = validate(&facts, &[artifact]);
        assert!(surface.is_none());
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule == Rule::ReleaseSurfaceProfile)
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("binary/image identity"))
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("activation facts are unavailable"))
        );
        Ok(())
    }

    #[test]
    fn untrusted_package_identity_is_never_echoed_in_diagnostics() -> Result<()> {
        let bait = "secret-bait\n\u{1b}[31m[ReleaseSurfaceExactSet]";
        let facts = facts_with_selection(
            json!({
                "packages": [{
                    "package": bait,
                    "public-api-owner": "standalone-component",
                    "api-stability": "experimental",
                    "profiles": []
                }],
                "profile-artifacts": []
            }),
            json!([]),
            json!("1.86"),
            json!([]),
        )?;
        let (surface, findings) = validate(&facts, &[]);
        assert!(surface.is_none());
        assert!(!findings.is_empty());
        for finding in &findings {
            assert!(!finding.subject.contains(bait));
            assert!(!finding.detail.contains(bait));
            assert!(!finding.subject.contains(['\n', '\u{1b}']));
            assert!(!finding.detail.contains(['\n', '\u{1b}']));
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::cognitive_complexity)] // reason: one anti-vacuity test joins the live selection, closure, metadata, and dependency budgets.
    fn real_workspace_release_surface_joins_live_facts_without_snapshot_golden() -> Result<()> {
        let root = crate::workspace_root()?;
        let command_facts = crate::workspace_facts::CommandWorkspaceFacts::new(&root);
        let facts = command_facts.get()?;
        let catalog = facts.workspace_packages();
        assert!(!catalog.is_empty(), "workspace catalog must be non-empty");
        let selection = facts
            .release_selection()
            .context("valid real release selection")?
            .context("root release selection must be declared")?;
        let publishable = catalog
            .iter()
            .filter(|package| package.publish_policy().is_publishable())
            .map(|package| package.key().as_str())
            .collect::<BTreeSet<_>>();
        let selected = selection
            .packages()
            .iter()
            .map(|package| package.package())
            .collect::<BTreeSet<_>>();
        assert_eq!(publishable, selected, "real exact-set must be data-driven");

        let ir = AssemblyGovernanceIr::<crate::assembly_governance::Core>::load(&root)?;
        let joined = ir.join_artifacts(crate::assembly_governance::load_artifact_declaration(
            &root,
        )?)?;
        let artifacts = project_artifacts(&joined);
        assert!(
            !artifacts.is_empty(),
            "real assembly artifact projection must be non-empty"
        );
        assert!(
            artifacts.iter().any(|artifact| {
                artifact.assembly == "runtime"
                    && matches!(
                        &artifact.lifecycle,
                        ProjectedArtifactLifecycle::Supported {
                            binary_package,
                            binary_target,
                            image_dockerfile,
                            image_target,
                        } if !binary_package.is_empty()
                            && !binary_target.is_empty()
                            && !image_dockerfile.is_empty()
                            && !image_target.is_empty()
                    )
            }),
            "real runtime must project a complete supported artifact identity"
        );

        let (surface, findings) = validate(facts, &artifacts);
        assert!(
            findings.is_empty(),
            "real Release Surface findings: {findings:?}"
        );
        let surface = surface.context("valid real selection must mint a ReleaseSurface")?;
        let surfaced = surface
            .packages()
            .iter()
            .map(|package| package.package())
            .collect::<BTreeSet<_>>();
        assert_eq!(surfaced, selected);
        assert!(surface.profile_artifacts().is_empty());
        let publish_order = surface
            .publish_order()
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(publish_order, selected);
        assert_eq!(surface.publish_order().len(), selected.len());

        let diag_release = surface
            .packages()
            .iter()
            .find(|package| package.package() == "rss-diag-context")
            .context("diag release package")?;
        assert_eq!(
            diag_release.public_api_owner(),
            PublicApiOwner::StandaloneComponent
        );
        assert_eq!(diag_release.api_stability(), ApiStability::Experimental);
        let trace_release = surface
            .packages()
            .iter()
            .find(|package| package.package() == "rss-trace-context")
            .context("trace release package")?;
        assert_eq!(
            trace_release.public_api_owner(),
            PublicApiOwner::StandaloneComponent
        );
        assert_eq!(trace_release.api_stability(), ApiStability::Experimental);

        // Issue #2050 acceptance input, not a production candidate registry. Spec 011 forbids a
        // package inventory; Cargo publish policy plus the positive Release Surface remain the
        // only lifecycle authorities, and later candidate PBIs must supply their own exact set.
        let candidates = BTreeSet::from([
            "rss-diag-context".to_owned(),
            "rss-trace-context".to_owned(),
        ]);
        let (candidate_plan, candidate_findings) = plan_publish_closure(facts, &candidates);
        assert!(
            candidate_findings.is_empty(),
            "real candidate closure findings: {candidate_findings:?}"
        );
        assert_eq!(
            candidate_plan
                .context("candidate closure must be ready")?
                .order(),
            &[
                "rss-diag-context".to_owned(),
                "rss-trace-context".to_owned(),
            ]
        );
        for name in &candidates {
            let key = facts.package_key(name)?;
            let package = catalog
                .iter()
                .find(|package| package.key() == &key)
                .context("candidate catalog row")?;
            assert!(package.publish_policy().is_publishable());
            assert!(selected.contains(name.as_str()));
        }

        let diag = facts.package_key("rss-diag-context")?;
        let diag_dependencies = facts.direct_dependencies_for(&diag)?;
        assert_eq!(
            diag_dependencies
                .iter()
                .filter(|dependency| {
                    dependency.kind() == DependencyKind::Normal && !dependency.optional()
                })
                .map(|dependency| dependency.name())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["thiserror", "tokio"])
        );
        let diag_tokio = diag_dependencies
            .iter()
            .find(|dependency| {
                dependency.kind() == DependencyKind::Normal && dependency.name() == "tokio"
            })
            .context("diag Tokio dependency")?;
        assert!(!diag_tokio.optional());
        assert!(!diag_tokio.uses_default_features());
        assert_eq!(
            diag_tokio.requested_features(),
            &BTreeSet::from(["rt".to_owned()])
        );

        let trace = facts.package_key("rss-trace-context")?;
        let trace_package = catalog
            .iter()
            .find(|package| package.key() == &trace)
            .context("trace package catalog row")?;
        assert_eq!(
            trace_package.publish_metadata().features(),
            &BTreeMap::from([("default".to_owned(), BTreeSet::new())])
        );
        let trace_dependencies = facts.direct_dependencies_for(&trace)?;
        let production = trace_dependencies
            .iter()
            .filter(|dependency| dependency.kind() == DependencyKind::Normal)
            .map(|dependency| (dependency.name(), dependency))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            production.keys().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "opentelemetry",
                "opentelemetry_sdk",
                "tracing",
                "tracing-opentelemetry",
            ])
        );
        assert!(
            production
                .values()
                .all(|dependency| !dependency.optional() && !dependency.uses_default_features())
        );
        for name in ["opentelemetry", "opentelemetry_sdk"] {
            assert_eq!(
                production[name].requested_features(),
                &BTreeSet::from(["trace".to_owned()])
            );
        }
        assert_eq!(
            production["tracing"].requested_features(),
            &BTreeSet::from(["std".to_owned()])
        );
        assert!(
            production["tracing-opentelemetry"]
                .requested_features()
                .is_empty()
        );
        Ok(())
    }
}
