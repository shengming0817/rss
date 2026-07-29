//! Actual shipped feature-graph guard for production binaries.
//!
//! `httpserve` intentionally exposes raw route helpers behind `test-util`, while `runtime` exposes
//! integration-only construction seams behind `integration`. Isolated consumers prove default
//! crate surfaces, but only Cargo's root-specific resolved graph can prove that feature unification
//! did not re-enable either surface in a shipped binary. This guard runs `cargo tree` for both
//! production package roots and reports the complete inverse dependency chain when a forbidden
//! feature is present.
//!
//! INVARIANT: ROUTE-MOUNT-SHIPPED-FEATURES-01 { level = "Medium", exec = "check", source = "code" }.

use anyhow::{Context, Result, bail};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
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
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    TestFeatureLeak,
    RuntimeIntegrationLeak,
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
        let mut findings = Vec::new();
        for package in SHIPPED_PACKAGES {
            for guarded in GUARDED_FEATURES {
                let tree = shipped_feature_tree(&root, package, guarded.crate_name)?;
                findings.extend(findings_for_tree_output(package, &tree, *guarded));
            }
        }
        Ok((
            format!(
                "{} shipped binaries 的 production feature graph 未启用 {} 个 test-only feature",
                SHIPPED_PACKAGES.len(),
                GUARDED_FEATURES.len()
            ),
            findings,
        ))
    }
}

fn shipped_feature_tree(
    root: &std::path::Path,
    package: &str,
    guarded_crate: &str,
) -> Result<String> {
    let output = crate::cmd::cargo_cmd(
        crate::cmd::CargoSubcommand::Tree,
        &[
            "--locked",
            "--color",
            "never",
            "--package",
            package,
            "--edges",
            "features",
            "--invert",
            guarded_crate,
        ],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("执行 `{package}` shipped feature graph 失败"))?;
    if !output.status.success() {
        bail!(
            "`cargo tree -p {package} -e features -i {guarded_crate}` 失败：\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("`{package}` shipped feature graph 不是 UTF-8"))
}

fn findings_for_tree_output(
    package: &str,
    tree: &str,
    guarded: GuardedFeature,
) -> Vec<Finding<Rule>> {
    let forbidden = format!(r#"{} feature "{}""#, guarded.crate_name, guarded.feature);
    let enabled = tree.lines().any(|line| {
        let node = line.trim_start_matches(|ch: char| {
            ch.is_whitespace() || matches!(ch, '│' | '├' | '└' | '─')
        });
        node == forbidden || node == format!("{forbidden} (*)")
    });
    enabled
        .then(|| {
            finding(
                guarded.rule,
                format!("bins/{package}"),
                format!(
                    "shipped `{package}` feature graph 启用了 `{}/{}`；移除以下依赖链中的 \
                     production feature activation：\n{tree}",
                    guarded.crate_name, guarded.feature
                ),
            )
        })
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_feature_tree_reports_test_util_with_dependency_chain() {
        let tree = r#"httpserve v0.0.0 (/repo/crates/httpserve)
├── httpserve feature "default"
│   └── runtime v0.0.0 (/repo/assemblies/runtime)
│       └── server v0.0.0 (/repo/bins/server)
└── httpserve feature "test-util"
    └── identity v0.0.0 (/repo/crates/identity)
        └── runtime v0.0.0 (/repo/assemblies/runtime)
            └── server v0.0.0 (/repo/bins/server)
"#;
        let findings = findings_for_tree_output("server", tree, GUARDED_FEATURES[0]);
        assert_eq!(findings.len(), 1, "test-util must fail: {findings:?}");
        assert_eq!(findings[0].rule, Rule::TestFeatureLeak);
        assert!(findings[0].detail.contains("identity v0.0.0"));
        assert!(findings[0].detail.contains("server v0.0.0"));
    }

    #[test]
    fn synthetic_feature_tree_reports_runtime_integration_with_dependency_chain() {
        let tree = r#"runtime v0.0.0 (/repo/assemblies/runtime)
├── runtime feature "default"
│   └── server v0.0.0 (/repo/bins/server)
└── runtime feature "integration"
    └── server v0.0.0 (/repo/bins/server)
"#;
        let findings = findings_for_tree_output("server", tree, GUARDED_FEATURES[1]);
        assert_eq!(
            findings.len(),
            1,
            "runtime/integration must fail: {findings:?}"
        );
        assert!(
            findings[0]
                .detail
                .contains("runtime feature \"integration\"")
        );
        assert!(findings[0].detail.contains("server v0.0.0"));
    }

    #[test]
    fn default_only_feature_tree_is_clean() {
        let tree = r#"httpserve v0.0.0 (/repo/crates/httpserve)
└── httpserve feature "default"
    └── runtime v0.0.0 (/repo/assemblies/runtime)
    └── rss v0.0.0 (/repo/bins/rss)
"#;
        assert!(findings_for_tree_output("rss", tree, GUARDED_FEATURES[0]).is_empty());
    }

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
            ]
        );
    }

    #[test]
    fn actual_shipped_feature_graphs_exclude_test_only_features() -> anyhow::Result<()> {
        let (summary, findings) = ShippedFeatureGuard.check()?;
        assert!(
            findings.is_empty(),
            "server/rss shipped graphs must stay clean: {findings:?}"
        );
        assert!(summary.contains("2 shipped binaries"));
        assert!(summary.contains("2 个 test-only feature"));
        Ok(())
    }
}
