//! Minimal executable-artifact contract for the identityaudit binary and runtime image.

use std::process::{Command, Output};

const IMAGE_ENV: &str = "RSS_IDENTITYAUDIT_ACCEPTANCE_IMAGE";
const HELP_USAGE: &str = "Usage: identityaudit-server --config <path>";

#[derive(Clone, Copy)]
enum Artifact<'a> {
    Binary(&'a str),
    Image(&'a str),
}

impl Artifact<'_> {
    fn execute(self, arguments: &[&str]) -> std::io::Result<Output> {
        match self {
            Self::Binary(path) => Command::new(path).args(arguments).output(),
            Self::Image(image) => Command::new("docker")
                .args(["run", "--rm", image])
                .args(arguments)
                .output(),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Binary(_) => "identityaudit-server binary",
            Self::Image(_) => "identityaudit-runtime image",
        }
    }
}

fn assert_executable_contract(artifact: Artifact<'_>) -> anyhow::Result<()> {
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

#[test]
fn identityaudit_server_binary_is_an_executable_artifact() -> anyhow::Result<()> {
    assert_executable_contract(Artifact::Binary(env!("CARGO_BIN_EXE_identityaudit-server")))
}

#[test]
#[ignore = "run through hack/identityaudit-artifact-acceptance.sh with a freshly built image"]
fn identityaudit_runtime_image_is_an_executable_artifact() -> anyhow::Result<()> {
    let image = std::env::var(IMAGE_ENV)?;
    anyhow::ensure!(!image.trim().is_empty(), "{IMAGE_ENV} must not be empty");
    assert_executable_contract(Artifact::Image(&image))
}
