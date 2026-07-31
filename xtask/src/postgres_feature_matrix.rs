//! Persistent compile gate for the Postgres domain-feature matrix.
//!
//! This module deliberately keeps execution outside Rust tests: nextest validates the typed plan,
//! while `cargo xtask verify` and `cargo xtask ci run --job ci-core-prerequisites` execute each
//! command exactly once.
//!
//! Domain feature cases are derived from `adapters/postgres/Cargo.toml` so a new `domain-*`
//! feature enters the matrix automatically; workspace all-features remains owned by release-check.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::workspace_root;
use anyhow::{Context, Result, bail};

const POSTGRES_MANIFEST: &str = "adapters/postgres/Cargo.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MatrixCase {
    Core,
    SingleDomain(String),
}

impl MatrixCase {
    fn label(&self) -> &str {
        match self {
            Self::Core => "core",
            Self::SingleDomain(feature) => feature.as_str(),
        }
    }

    pub(crate) fn args(&self) -> Vec<String> {
        let mut args = vec!["check".to_owned(), "-p".to_owned(), "postgres".to_owned()];
        match self {
            Self::Core => args.push("--no-default-features".to_owned()),
            Self::SingleDomain(feature) => {
                args.extend([
                    "--no-default-features".to_owned(),
                    "--features".to_owned(),
                    feature.clone(),
                ]);
            }
        }
        args
    }
}

fn domain_features_from_manifest(root: &Path) -> Result<Vec<String>> {
    let path = root.join(POSTGRES_MANIFEST);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("postgres-feature-matrix: read {}", path.display()))?;
    let manifest: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("postgres-feature-matrix: parse {}", path.display()))?;
    let features = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            anyhow::anyhow!("postgres-feature-matrix: missing [features] in {POSTGRES_MANIFEST}")
        })?;
    let mut domains: Vec<String> = features
        .keys()
        .filter(|name| name.starts_with("domain-"))
        .cloned()
        .collect();
    domains.sort();
    if domains.is_empty() {
        bail!("postgres-feature-matrix: no domain-* features in {POSTGRES_MANIFEST}");
    }
    Ok(domains)
}

fn build_matrix(domains: &[String]) -> Vec<MatrixCase> {
    let mut cases = Vec::with_capacity(domains.len() + 1);
    cases.push(MatrixCase::Core);
    cases.extend(domains.iter().cloned().map(MatrixCase::SingleDomain));
    cases
}

fn validate_matrix(cases: &[MatrixCase], expected_domains: &[String]) -> Result<()> {
    let expected: BTreeSet<&str> = expected_domains.iter().map(String::as_str).collect();
    let mut core = 0;
    let mut domains = BTreeSet::new();
    for case in cases {
        match case {
            MatrixCase::Core => core += 1,
            MatrixCase::SingleDomain(feature) => {
                if !expected.contains(feature.as_str()) || !domains.insert(feature.as_str()) {
                    bail!("invalid or duplicate Postgres domain feature case: {feature}");
                }
            }
        }
    }
    if core != 1 || domains.len() != expected.len() {
        bail!("Postgres feature matrix must contain core and every manifest domain-* feature");
    }
    Ok(())
}

pub(crate) fn run(execution_policy: crate::cmd::ExecutionPolicy) -> Result<()> {
    let root = workspace_root()?;
    let domains = domain_features_from_manifest(&root)?;
    let cases = build_matrix(&domains);
    validate_matrix(&cases, &domains)?;
    let mut failures = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        let mut args = case.args();
        if execution_policy.keeps_going() {
            args.push("--keep-going".to_owned());
        }
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        eprintln!(
            "postgres-feature-matrix: [{}/{}] {}",
            index + 1,
            cases.len(),
            case.label()
        );
        let status = crate::cmd::cargo_cmd(
            crate::cmd::CargoSubcommand::Check,
            &arg_refs[1..],
            &[],
            Some(&root),
        )
        .status()?;
        if !status.success() {
            let failure = format!(
                "Postgres feature matrix case `{}` failed (cargo {})",
                case.label(),
                args.join(" ")
            );
            if !execution_policy.keeps_going() {
                bail!(failure);
            }
            failures.push(failure);
        }
    }
    if !failures.is_empty() {
        bail!(
            "Postgres feature matrix failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_matrix_covers_core_and_manifest_domains_without_all_features() -> Result<()> {
        let root = workspace_root()?;
        let domains = domain_features_from_manifest(&root)?;
        assert!(
            domains.iter().any(|feature| feature == "domain-settings"),
            "settings domain must remain a postgres capability: {domains:?}"
        );
        let cases = build_matrix(&domains);
        validate_matrix(&cases, &domains)?;
        assert_eq!(cases.len(), domains.len() + 1);
        assert_eq!(
            cases[0].args(),
            ["check", "-p", "postgres", "--no-default-features"]
        );
        assert_eq!(
            cases[1].args(),
            [
                "check",
                "-p",
                "postgres",
                "--no-default-features",
                "--features",
                domains[0].as_str(),
            ]
        );
        assert!(
            cases
                .iter()
                .all(|case| !case.args().iter().any(|arg| arg == "--all-features"))
        );
        Ok(())
    }

    #[test]
    fn matrix_validation_rejects_missing_duplicate_and_unknown_cases() -> Result<()> {
        let domains = vec![
            "domain-settings".to_owned(),
            "domain-identity".to_owned(),
            "domain-audit".to_owned(),
        ];
        let cases = build_matrix(&domains);
        assert!(validate_matrix(&cases[..cases.len() - 1], &domains).is_err());
        assert!(
            validate_matrix(
                &[
                    MatrixCase::Core,
                    MatrixCase::SingleDomain("domain-settings".to_owned()),
                    MatrixCase::SingleDomain("domain-settings".to_owned()),
                    MatrixCase::SingleDomain("domain-audit".to_owned()),
                ],
                &domains
            )
            .is_err()
        );
        assert!(
            validate_matrix(
                &[
                    MatrixCase::Core,
                    MatrixCase::SingleDomain("domain-settings".to_owned()),
                    MatrixCase::SingleDomain("domain-identity".to_owned()),
                    MatrixCase::SingleDomain("domain-unknown".to_owned()),
                ],
                &domains
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn missing_manifest_domain_feature_fails_closed() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-postgres-feature-matrix-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("adapters/postgres"))?;
        fs::write(
            root.join(POSTGRES_MANIFEST),
            r#"
[package]
name = "postgres"

[features]
default = []
"#,
        )?;
        let err = match domain_features_from_manifest(&root) {
            Ok(_) => bail!("empty domain set must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no domain-* features"), "{err:#}");
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
