//! Positive Release Surface derived from Cargo facts and selected assembly artifacts.

use semver::Version;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use workspacefacts::{
    ApiStability, OfficialProfile, PublicApiOwner, PublishPolicy, TargetKind, WorkspaceFacts,
};

use crate::assembly::{Finding, Rule};
use crate::assembly_governance::{ArtifactLifecycle, ArtifactsJoined, AssemblyGovernanceIr};
use crate::diagnostic::finding;

/// INVARIANT: RELEASE-SURFACE-EXACT-SET-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::exact_set_and_reference_conflicts_are_aggregated_and_sorted", anti_vacuity = "tests::real_workspace_release_surface_joins_live_facts_without_snapshot_golden" } -- Cargo-publishable workspace packages and the positive package selection are an exact set; selected profile artifacts require independent activation authority and join the existing assembly artifact IR.
#[derive(Debug)]
pub(crate) struct ReleaseSurface {
    packages: Vec<ReleasePackage>,
    profile_artifacts: Vec<ReleaseProfileArtifact>,
}

impl ReleaseSurface {
    pub(crate) fn packages(&self) -> &[ReleasePackage] {
        &self.packages
    }

    pub(crate) fn profile_artifacts(&self) -> &[ReleaseProfileArtifact] {
        &self.profile_artifacts
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
        output.push(']');
        output
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
    let mut surface = ReleaseSurface {
        packages: Vec::new(),
        profile_artifacts: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::path::Path;
    use workspacefacts::WorkspaceFacts;
    use workspacefacts::testing::{
        metadata_json, path_package, path_package_id, resolve_node, target,
    };

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
        let alpha_id = path_package_id(alpha_path);
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

    #[test]
    fn synthetic_nonempty_surface_derives_cargo_facts() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [{
                    "package": "alpha",
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
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
        let surface = surface.context("valid selection must mint a ReleaseSurface")?;
        assert_eq!(surface.packages().len(), 1);
        assert_eq!(surface.packages()[0].package(), "alpha");
        assert_eq!(surface.packages()[0].version().to_string(), "0.0.0");
        assert_eq!(
            surface.packages()[0].minimum_rust_version().to_string(),
            "1.86.0"
        );
        assert!(surface.profile_artifacts().is_empty());
        Ok(())
    }

    #[test]
    fn exact_set_and_reference_conflicts_are_aggregated_and_sorted() -> Result<()> {
        let facts = facts_with_selection(
            json!({
                "packages": [
                    {
                        "package": "alpha",
                        "public-api-owner": "platform-public",
                        "api-stability": "stable",
                        "profiles": ["eventing", "eventing"]
                    },
                    {
                        "package": "alpha",
                        "public-api-owner": "platform-public",
                        "api-stability": "stable",
                        "profiles": []
                    },
                    {
                        "package": "ghost",
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
        Ok(())
    }
}
