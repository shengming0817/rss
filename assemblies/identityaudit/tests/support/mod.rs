//! Shared executable-artifact contract helpers for identityaudit acceptance tests.
//!
//! This module is imported by explicit `[[test]]` targets and is not itself a Cargo test target.

use std::process::{Command, Output};

pub(crate) const HELP_USAGE: &str = "Usage: identityaudit-server --config <path>";
#[allow(dead_code)] // Image target only; binary target shares this module.
pub(crate) const ACCEPTANCE_IMAGE_ENV: &str = "RSS_IDENTITYAUDIT_ACCEPTANCE_IMAGE";

#[derive(Clone, Copy)]
#[allow(dead_code)] // Shared across binary/image test crates; each target constructs one variant.
pub(crate) enum Artifact<'a> {
    Binary(&'a str),
    Image(&'a str),
}

impl Artifact<'_> {
    pub(crate) fn execute(self, arguments: &[&str]) -> std::io::Result<Output> {
        match self {
            Self::Binary(path) => Command::new(path).args(arguments).output(),
            // `--` keeps image refs that start with `-` from being parsed as docker options.
            Self::Image(image) => Command::new("docker")
                .args(["run", "--rm", "--", image])
                .args(arguments)
                .output(),
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Binary(_) => "identityaudit-server binary",
            Self::Image(_) => "identityaudit-runtime image",
        }
    }
}

/// Reject empty values, leading `-`, and any whitespace so docker argv stays unambiguous.
#[allow(dead_code)] // Image target only; binary target shares this module.
pub(crate) fn validate_acceptance_image(env_name: &str, image: &str) -> anyhow::Result<String> {
    anyhow::ensure!(!image.is_empty(), "{env_name} must not be empty");
    anyhow::ensure!(
        !image.starts_with('-'),
        "{env_name} must not start with '-'"
    );
    anyhow::ensure!(
        !image.chars().any(char::is_whitespace),
        "{env_name} must not contain whitespace"
    );
    Ok(image.to_owned())
}

pub(crate) fn assert_executable_contract(artifact: Artifact<'_>) -> anyhow::Result<()> {
    let label = artifact.label();
    let help = artifact.execute(&["--help"])?;
    assert!(
        help.status.success(),
        "{label} --help failed: {}",
        String::from_utf8_lossy(&help.stderr)
    );
    let help_stdout = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_stdout.contains(HELP_USAGE),
        "{label} omitted its usage contract: {help_stdout}"
    );

    let missing_config = artifact.execute(&[])?;
    assert!(
        !missing_config.status.success(),
        "{label} unexpectedly started without --config"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&missing_config.stdout),
        String::from_utf8_lossy(&missing_config.stderr)
    );
    assert!(
        diagnostics.contains("--config"),
        "{label} did not explain its closed config requirement: {diagnostics}"
    );
    Ok(())
}
