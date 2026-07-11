//! Actual shipped feature-graph guard for production binaries.
//!
//! `httpserve` intentionally exposes raw route helpers behind `test-util`. An isolated consumer
//! proves the default crate surface, but only Cargo's root-specific resolved graph can prove that
//! feature unification did not re-enable the helpers in a shipped binary. This guard runs
//! `cargo tree` for both production package roots and reports the complete inverse dependency
//! chain when the forbidden feature is present.
//!
//! INVARIANT: ROUTE-MOUNT-SHIPPED-FEATURES-01 { level = "Medium", exec = "verify", source = "code" }.

use anyhow::{Context, Result, bail};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;

const SHIPPED_PACKAGES: &[&str] = &["server", "rss"];
const GUARDED_CRATE: &str = "httpserve";
const FORBIDDEN_FEATURE: &str = "test-util";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    TestFeatureLeak,
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
            let tree = shipped_feature_tree(&root, package)?;
            findings.extend(findings_for_tree_output(package, &tree));
        }
        Ok((
            format!(
                "{} shipped binaries 的 `{GUARDED_CRATE}` feature graph 未启用 `{FORBIDDEN_FEATURE}`",
                SHIPPED_PACKAGES.len()
            ),
            findings,
        ))
    }
}

fn shipped_feature_tree(root: &std::path::Path, package: &str) -> Result<String> {
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
            GUARDED_CRATE,
        ],
        &[],
        Some(root),
    )
    .output()
    .with_context(|| format!("执行 `{package}` shipped feature graph 失败"))?;
    if !output.status.success() {
        bail!(
            "`cargo tree -p {package} -e features -i {GUARDED_CRATE}` 失败：\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .with_context(|| format!("`{package}` shipped feature graph 不是 UTF-8"))
}

fn findings_for_tree_output(package: &str, tree: &str) -> Vec<Finding<Rule>> {
    let forbidden = format!(r#"{GUARDED_CRATE} feature "{FORBIDDEN_FEATURE}""#);
    let enabled = tree.lines().any(|line| {
        let node = line.trim_start_matches(|ch: char| {
            ch.is_whitespace() || matches!(ch, '│' | '├' | '└' | '─')
        });
        node == forbidden || node == format!("{forbidden} (*)")
    });
    enabled
        .then(|| {
            finding(
                Rule::TestFeatureLeak,
                format!("bins/{package}"),
                format!(
                    "shipped `{package}` feature graph 启用了 `{GUARDED_CRATE}/{FORBIDDEN_FEATURE}`；\
                     移除以下依赖链中的 production feature activation：\n{tree}"
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
        let findings = findings_for_tree_output("server", tree);
        assert_eq!(findings.len(), 1, "test-util must fail: {findings:?}");
        assert_eq!(findings[0].rule, Rule::TestFeatureLeak);
        assert!(findings[0].detail.contains("identity v0.0.0"));
        assert!(findings[0].detail.contains("server v0.0.0"));
    }

    #[test]
    fn default_only_feature_tree_is_clean() {
        let tree = r#"httpserve v0.0.0 (/repo/crates/httpserve)
└── httpserve feature "default"
    └── runtime v0.0.0 (/repo/assemblies/runtime)
        └── rss v0.0.0 (/repo/bins/rss)
"#;
        assert!(findings_for_tree_output("rss", tree).is_empty());
    }

    #[test]
    fn shipped_package_roots_are_server_and_rss() {
        assert_eq!(SHIPPED_PACKAGES, &["server", "rss"]);
        assert_eq!(GUARDED_CRATE, "httpserve");
        assert_eq!(FORBIDDEN_FEATURE, "test-util");
    }

    #[test]
    fn actual_shipped_feature_graphs_exclude_test_util() -> anyhow::Result<()> {
        let (summary, findings) = ShippedFeatureGuard.check()?;
        assert!(
            findings.is_empty(),
            "server/rss shipped graphs must stay clean: {findings:?}"
        );
        assert!(summary.contains("2 shipped binaries"));
        Ok(())
    }
}
