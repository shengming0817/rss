//! Thin operator entrypoint for the executable Identity + Audit assembly.
//!
//! ref: oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;

const HELP: &str = r#"Usage: identityaudit-server --config <path>

Runs the closed Identity + Audit deployment closure.

Options:
  --config <path>  Closed schemaVersion=1 TOML document
  -h, --help       Show this help

Image schema: /usr/share/rss/identityaudit/config.schema.json

Required read-only secret file:
  /var/run/rss/secrets/serving-secret-bundle

Required build identity environment:
  RSS_BUILD_SOURCE_SHA
  RSS_BUILD_IMAGE_DIGEST

Surfaces: Primary /api/v1/identity, Admin /api/v1/audit, Health /health/v1
Health endpoints: /health/v1/healthz, /health/v1/readyz, /health/v1/metrics
"#;

enum CliCommand {
    Help,
    Run(PathBuf),
}

fn usage_error(message: &'static str) -> anyhow::Error {
    anyhow::anyhow!("{message}\n\n{HELP}")
}

fn parse_command(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<CliCommand> {
    let mut arguments = arguments.into_iter();
    let Some(flag) = arguments.next() else {
        return Err(usage_error("missing required --config <path>"));
    };
    if flag == "--help" || flag == "-h" {
        anyhow::ensure!(
            arguments.next().is_none(),
            usage_error("--help does not accept trailing arguments")
        );
        return Ok(CliCommand::Help);
    }
    if flag != "--config" {
        return Err(usage_error("expected --config <path>"));
    }
    let path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| usage_error("--config requires a path"))?;
    anyhow::ensure!(
        arguments.next().is_none(),
        usage_error("unexpected trailing arguments")
    );
    Ok(CliCommand::Run(path))
}

fn main() -> anyhow::Result<()> {
    let CliCommand::Run(config) = parse_command(std::env::args_os().skip(1))? else {
        std::io::stdout()
            .lock()
            .write_all(HELP.as_bytes())
            .map_err(|_| anyhow::anyhow!("write identityaudit-server help"))?;
        return Ok(());
    };
    tracing_subscriber::fmt()
        .with_env_filter(identityaudit::TRACING_FILTER)
        .try_init()
        .map_err(|_| anyhow::anyhow!("initialize identityaudit tracing subscriber"))?;
    identityaudit::run(&config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_is_a_successful_command_without_configuration() -> anyhow::Result<()> {
        assert!(matches!(
            parse_command([OsString::from("--help")])?,
            CliCommand::Help
        ));
        assert!(matches!(
            parse_command([OsString::from("-h")])?,
            CliCommand::Help
        ));
        Ok(())
    }

    #[test]
    fn argument_errors_share_the_operator_usage() -> anyhow::Result<()> {
        let cases = [
            Vec::new(),
            vec![OsString::from("--unknown")],
            vec![OsString::from("--config")],
            vec![
                OsString::from("--config"),
                OsString::from("identityaudit.toml"),
                OsString::from("extra"),
            ],
        ];
        for arguments in cases {
            let error = parse_command(arguments)
                .err()
                .ok_or_else(|| anyhow::anyhow!("invalid arguments unexpectedly passed"))?;
            assert!(error.to_string().contains(HELP));
        }
        Ok(())
    }
}
