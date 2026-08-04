//! Actual shipped feature-graph guard for production binaries.
//!
//! `httpserve` intentionally exposes raw route helpers behind `test-util`, `runtime` exposes
//! integration-only construction seams behind `integration`, and `identity` exposes plaintext
//! seed-login constructors behind `seed-login`. Isolated consumers prove default crate surfaces,
//! but only Cargo's root-specific resolved graph can prove that feature unification did not
//! re-enable any of those surfaces in a shipped binary. This guard consumes the owned
//! `WorkspaceFacts` CargoSet façade for both production package roots and reports the selected
//! activation path when a forbidden feature is present.
//!
//! INVARIANT: ROUTE-MOUNT-SHIPPED-FEATURES-01 { level = "Medium", exec = "check", source = "code" }.

use anyhow::{Context, Result};
use std::collections::BTreeSet;
use workspacefacts::{
    BuildPlatforms, BuildSelection, BuildSide, CargoPlatform, FeatureKey, FeatureSelection,
    ResolverVersion, WorkspaceFacts,
};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_facts::CommandWorkspaceFacts;
use crate::workspace_root;

const SHIPPED_PACKAGES: &[&str] = &["server", "rss"];
const GUARDED_FEATURES: &[GuardedFeature] = &[
    GuardedFeature {
        crate_name: "httpserve",
        feature: "test-util",
        rule: Rule::TestFeatureLeak,
    },
    GuardedFeature {
        crate_name: "runtime",
        feature: "integration",
        rule: Rule::RuntimeIntegrationLeak,
    },
    GuardedFeature {
        crate_name: "identity",
        feature: "seed-login",
        rule: Rule::IdentitySeedLogin,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    TestFeatureLeak,
    RuntimeIntegrationLeak,
    /// Production graph enabled `identity/seed-login` (name avoids shared `Leak` postfix for clippy).
    IdentitySeedLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardedFeature {
    crate_name: &'static str,
    feature: &'static str,
    rule: Rule,
}

pub(crate) struct ShippedFeatureGuard;

impl GovernanceCheck for ShippedFeatureGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "shipped-feature-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Rule>>)> {
        let root = workspace_root()?;
        let command_facts = CommandWorkspaceFacts::new(&root);
        let facts = command_facts
            .get()
            .context("加载 shipped feature workspace facts 失败")?;
        findings_for_builds(facts)
    }
}

fn findings_for_builds(facts: &WorkspaceFacts) -> Result<(String, Vec<Finding<Rule>>)> {
    let guarded_keys = GUARDED_FEATURES
        .iter()
        .map(|guarded| {
            let package = facts.package_key(guarded.crate_name).with_context(|| {
                format!(
                    "shipped-feature-guard: package `{}` missing — sync GUARDED_FEATURES",
                    guarded.crate_name
                )
            })?;
            let feature = facts
                .feature_key(&package, guarded.feature)
                .with_context(|| {
                    format!(
                        "shipped-feature-guard: feature `{}/{}` missing — sync GUARDED_FEATURES \
                         or fix IncompleteFeatureGraph edges",
                        guarded.crate_name, guarded.feature
                    )
                })?;
            Ok((guarded, feature))
        })
        .collect::<Result<Vec<_>>>()?;
    let guarded_features = guarded_keys
        .iter()
        .map(|(_, feature)| feature.clone())
        .collect::<BTreeSet<_>>();
    let platform = CargoPlatform::build_target()
        .context("shipped-feature-guard: resolve Cargo build target platform")?;
    let platforms = BuildPlatforms::new(platform.clone(), platform);

    let mut findings = Vec::new();
    for package in SHIPPED_PACKAGES {
        let root_package = facts.package_key(package).with_context(|| {
            format!("shipped-feature-guard: shipped package `{package}` missing from workspace")
        })?;
        let build = facts
            .resolve_build(BuildSelection::new(
                root_package,
                ResolverVersion::V2,
                FeatureSelection::Default,
                platforms.clone(),
                guarded_features.clone(),
            ))
            .with_context(|| {
                format!(
                    "shipped-feature-guard: resolve_build for `{package}` failed — check \
                     IncompleteFeatureGraph / GUARDED_FEATURES"
                )
            })?;
        for side in [BuildSide::Target, BuildSide::Host] {
            for (guarded, feature) in &guarded_keys {
                if !build.is_feature_enabled(side, feature) {
                    continue;
                }
                let path = required_activation_path(&build, side, feature)?;
                findings.push(finding(
                    guarded.rule,
                    format!("bins/{package}"),
                    format!(
                        "shipped `{package}` feature graph 在 {side} 启用了 `{}/{}`；移除以下 \
                         production feature activation：\n{path}",
                        guarded.crate_name, guarded.feature
                    ),
                ));
            }
        }
    }
    Ok((
        format!(
            "{} shipped binaries 的 production feature graph 未启用 {} 个登记的非生产 feature",
            SHIPPED_PACKAGES.len(),
            GUARDED_FEATURES.len()
        ),
        findings,
    ))
}

fn required_activation_path<'a>(
    build: &'a workspacefacts::BuildFacts,
    side: BuildSide,
    feature: &FeatureKey,
) -> Result<&'a workspacefacts::ActivationPath> {
    build.activation_path(side, feature).with_context(|| {
        format!(
            "enabled feature `{}/{}` on {side} 缺少 activation path",
            feature.package().as_str(),
            feature.name()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::path::Path;
    use syn::visit::Visit;
    use workspacefacts::testing::{
        metadata_json, path_build_dependency_with_features, path_dependency_with_features,
        path_package, path_package_id, resolve_node_with_dep_kinds, resolve_node_with_features,
        target,
    };

    #[test]
    fn shipped_package_roots_are_server_and_rss() {
        assert_eq!(SHIPPED_PACKAGES, &["server", "rss"]);
        assert_eq!(
            GUARDED_FEATURES,
            &[
                GuardedFeature {
                    crate_name: "httpserve",
                    feature: "test-util",
                    rule: Rule::TestFeatureLeak,
                },
                GuardedFeature {
                    crate_name: "runtime",
                    feature: "integration",
                    rule: Rule::RuntimeIntegrationLeak,
                },
                GuardedFeature {
                    crate_name: "identity",
                    feature: "seed-login",
                    rule: Rule::IdentitySeedLogin,
                },
            ]
        );
    }

    #[test]
    fn every_guarded_feature_leak_reports_owned_activation_path() -> anyhow::Result<()> {
        for shipped_package in SHIPPED_PACKAGES {
            for guarded in GUARDED_FEATURES {
                let facts = WorkspaceFacts::from_metadata_json(
                    Path::new("/workspace"),
                    &metadata_with_leak(shipped_package, *guarded),
                )?;
                let (_, findings) = findings_for_builds(&facts)?;
                assert_eq!(
                    findings.len(),
                    1,
                    "{shipped_package} -> {}/{} must fail: {findings:?}",
                    guarded.crate_name,
                    guarded.feature
                );
                let finding = &findings[0];
                assert_eq!(finding.rule, guarded.rule);
                assert_eq!(finding.subject, format!("bins/{shipped_package}"));
                assert!(
                    finding
                        .detail
                        .contains(&format!("target:{shipped_package}"))
                );
                assert!(finding.detail.contains("target:bridge"));
                assert!(finding.detail.contains(&format!(
                    "target:{}/{}",
                    guarded.crate_name, guarded.feature
                )));
            }
        }
        Ok(())
    }

    #[test]
    fn host_feature_leak_reports_build_dependency_path() -> anyhow::Result<()> {
        let mut metadata: Value =
            serde_json::from_str(&metadata_with_leak("server", GUARDED_FEATURES[0]))?;
        let server = metadata["packages"]
            .as_array_mut()
            .and_then(|packages| {
                packages
                    .iter_mut()
                    .find(|package| package["name"] == "server")
            })
            .context("synthetic server package missing")?;
        server["targets"]
            .as_array_mut()
            .context("synthetic server targets missing")?
            .push(target(
                "build-script-build",
                "custom-build",
                "/workspace/bins/server/build.rs",
                false,
                &[],
            ));
        *server["dependencies"]
            .as_array_mut()
            .and_then(|dependencies| {
                dependencies
                    .iter_mut()
                    .find(|dependency| dependency["name"] == "bridge")
            })
            .context("synthetic bridge dependency missing")? =
            path_build_dependency_with_features("bridge", package_path("bridge"), false, true, &[]);

        let server_resolve = metadata["resolve"]["nodes"]
            .as_array_mut()
            .and_then(|nodes| {
                nodes.iter_mut().find(|node| {
                    node["id"]
                        .as_str()
                        .is_some_and(|id| id.contains("bins/server"))
                })
            })
            .context("synthetic server resolve node missing")?;
        let bridge_pkg = server_resolve["deps"]
            .as_array()
            .and_then(|dependencies| {
                dependencies
                    .iter()
                    .find(|dependency| dependency["name"] == "bridge")
            })
            .and_then(|dependency| dependency["pkg"].as_str())
            .context("synthetic bridge resolve dependency missing")?
            .to_owned();
        let server_id = server_resolve["id"]
            .as_str()
            .context("server resolve id missing")?
            .to_owned();
        *server_resolve = resolve_node_with_dep_kinds(
            &server_id,
            &[("bridge", bridge_pkg.as_str(), Some("build"))],
            &[],
        );

        let facts = WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?;
        let (_, findings) = findings_for_builds(&facts)?;
        assert_eq!(findings.len(), 1, "host leak must fail: {findings:?}");
        assert!(findings[0].detail.contains("target:server"));
        assert!(findings[0].detail.contains("host:bridge"));
        assert!(findings[0].detail.contains("host:httpserve/test-util"));
        Ok(())
    }

    #[test]
    fn missing_guarded_feature_fails_closed() -> anyhow::Result<()> {
        let leak = GUARDED_FEATURES[0];
        let mut metadata: Value = serde_json::from_str(&metadata_with_leak("server", leak))?;
        let packages = metadata
            .get_mut("packages")
            .and_then(Value::as_array_mut)
            .context("synthetic packages missing")?;
        let leaked = packages
            .iter_mut()
            .find(|package| package["name"] == leak.crate_name)
            .with_context(|| format!("synthetic {} package missing", leak.crate_name))?;
        leaked["features"] = json!({});
        let facts = WorkspaceFacts::from_metadata_json(
            Path::new("/workspace"),
            &serde_json::to_string(&metadata)?,
        )?;
        assert!(findings_for_builds(&facts).is_err());
        Ok(())
    }

    #[test]
    fn shipped_feature_implementation_has_no_tree_protocol_residual() -> anyhow::Result<()> {
        let old = "fn old() { let _ = CargoSubcommand::Tree; let _ = \"--invert\"; }";
        assert!(
            !tree_protocol_residuals(old)?.is_empty(),
            "synthetic old implementation must be rejected"
        );

        let live = include_str!("shipped_feature_guard.rs");
        let implementation = live
            .split_once("#[cfg(test)]")
            .map_or(live, |(implementation, _)| implementation);
        assert!(
            tree_protocol_residuals(implementation)?.is_empty(),
            "live implementation retained cargo tree protocol symbols"
        );
        Ok(())
    }

    #[test]
    fn actual_shipped_feature_graphs_exclude_guarded_features() -> anyhow::Result<()> {
        let (summary, findings) = ShippedFeatureGuard.check()?;
        assert!(
            findings.is_empty(),
            "server/rss shipped graphs must stay clean: {findings:?}"
        );
        assert!(summary.contains("2 shipped binaries"));
        assert!(summary.contains("3 个登记的非生产 feature"));
        Ok(())
    }

    #[derive(Default)]
    struct TreeProtocolVisitor {
        residuals: BTreeSet<&'static str>,
        in_doc_attr: bool,
    }

    impl TreeProtocolVisitor {
        fn record_ident(&mut self, ident: &str) {
            match ident {
                "CargoSubcommand" => {
                    self.residuals.insert("CargoSubcommand");
                }
                "cargo_cmd" => {
                    self.residuals.insert("cargo_cmd");
                }
                "shipped_feature_tree" => {
                    self.residuals.insert("shipped_feature_tree");
                }
                "findings_for_tree_output" => {
                    self.residuals.insert("findings_for_tree_output");
                }
                _ => {}
            }
        }
    }

    impl<'ast> Visit<'ast> for TreeProtocolVisitor {
        fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
            let was_doc = self.in_doc_attr;
            self.in_doc_attr = attribute.path().is_ident("doc");
            syn::visit::visit_attribute(self, attribute);
            self.in_doc_attr = was_doc;
        }

        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            self.record_ident(&function.sig.ident.to_string());
            syn::visit::visit_item_fn(self, function);
        }

        fn visit_path(&mut self, path: &'ast syn::Path) {
            let segments = path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            for segment in &segments {
                self.record_ident(segment);
            }
            if segments.windows(2).any(|window| window == ["crate", "cmd"]) {
                self.residuals.insert("crate::cmd");
            }
            syn::visit::visit_path(self, path);
        }

        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            let value = literal.value();
            if value == "--invert" {
                self.residuals.insert("\"--invert\"");
            }
            if !self.in_doc_attr && value.contains("cargo tree") {
                self.residuals.insert("cargo tree");
            }
            syn::visit::visit_lit_str(self, literal);
        }
    }

    fn tree_protocol_residuals(source: &str) -> anyhow::Result<Vec<&'static str>> {
        let syntax = syn::parse_file(source).context("parse shipped feature source")?;
        let mut visitor = TreeProtocolVisitor::default();
        visitor.visit_file(&syntax);
        Ok(visitor.residuals.into_iter().collect())
    }

    #[test]
    fn rustdoc_cargo_tree_mentions_are_not_residuals() -> anyhow::Result<()> {
        let source = r#"
            //! Migrated off `cargo tree --invert`.
            /// Still documents cargo tree history.
            fn live() {}
        "#;
        assert!(
            tree_protocol_residuals(source)?.is_empty(),
            "rustdoc mentions of cargo tree must not count as protocol residuals"
        );
        Ok(())
    }

    fn metadata_with_leak(shipped_package: &str, leak: GuardedFeature) -> String {
        let package_paths = [
            ("server", package_path("server")),
            ("rss", package_path("rss")),
            ("bridge", package_path("bridge")),
            ("httpserve", package_path("httpserve")),
            ("runtime", package_path("runtime")),
            ("identity", package_path("identity")),
        ];
        let ids = package_paths
            .iter()
            .map(|(name, path)| (*name, path_package_id(path)))
            .collect::<std::collections::BTreeMap<_, _>>();
        let packages = package_paths
            .iter()
            .map(|(name, path)| {
                let dependencies = if *name == shipped_package {
                    vec![path_dependency_with_features(
                        "bridge",
                        package_path("bridge"),
                        false,
                        true,
                        &[],
                    )]
                } else if *name == "bridge" {
                    vec![path_dependency_with_features(
                        leak.crate_name,
                        package_path(leak.crate_name),
                        false,
                        true,
                        &[leak.feature],
                    )]
                } else {
                    vec![]
                };
                let features = GUARDED_FEATURES
                    .iter()
                    .find(|guarded| guarded.crate_name == *name)
                    .map_or_else(|| json!({}), |guarded| json!({guarded.feature: []}));
                path_package(
                    name,
                    path,
                    vec![target(
                        name,
                        if matches!(*name, "server" | "rss") {
                            "bin"
                        } else {
                            "lib"
                        },
                        &format!("{path}/src/lib.rs"),
                        true,
                        &[],
                    )],
                    dependencies,
                    features,
                )
            })
            .collect();
        let resolve_nodes = package_paths
            .iter()
            .map(|(name, _)| {
                let dependencies = if *name == shipped_package {
                    vec![("bridge", ids["bridge"].as_str())]
                } else if *name == "bridge" {
                    vec![(leak.crate_name, ids[leak.crate_name].as_str())]
                } else {
                    vec![]
                };
                let features = GUARDED_FEATURES
                    .iter()
                    .find(|guarded| guarded.crate_name == *name)
                    .map_or(&[][..], |guarded| std::slice::from_ref(&guarded.feature));
                resolve_node_with_features(&ids[name], &dependencies, features)
            })
            .collect();
        metadata_json(
            "/workspace",
            packages,
            package_paths
                .iter()
                .map(|(name, _)| ids[name].clone())
                .collect(),
            resolve_nodes,
        )
    }

    fn package_path(package: &str) -> &'static str {
        match package {
            "server" => "/workspace/bins/server",
            "rss" => "/workspace/bins/rss",
            "bridge" => "/workspace/crates/bridge",
            "httpserve" => "/workspace/crates/httpserve",
            "runtime" => "/workspace/assemblies/runtime",
            "identity" => "/workspace/crates/identity",
            _ => "/workspace/invalid",
        }
    }
}
