use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;

const HELP: &str = "Usage: deviceidentity-server --config <path>\n\nDevice-security candidate only; not a production-activated T3 surface.\nImage schema: /usr/share/rss/deviceidentity/config.schema.json\nFixed secret bundle: /var/run/rss/secrets/serving-secret-bundle\nListeners: Primary API, Internal mTLS, and health/readiness (addresses come from config)\n\nOptions:\n  --config <path>  Closed schemaVersion=2 TOML document\n  -h, --help       Show this help\n";

enum Command {
    Help,
    Run(PathBuf),
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Command> {
    let mut arguments = arguments.into_iter();
    let Some(flag) = arguments.next() else {
        anyhow::bail!("missing required --config <path>\n\n{HELP}")
    };
    if flag == "--help" || flag == "-h" {
        anyhow::ensure!(
            arguments.next().is_none(),
            "--help does not accept trailing arguments\n\n{HELP}"
        );
        return Ok(Command::Help);
    }
    anyhow::ensure!(flag == "--config", "expected --config <path>\n\n{HELP}");
    let path = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("--config requires a path\n\n{HELP}"))?;
    anyhow::ensure!(
        arguments.next().is_none(),
        "unexpected trailing arguments\n\n{HELP}"
    );
    Ok(Command::Run(path))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    runtimeexec::install_redacted_panic_hook();
    match parse(std::env::args_os().skip(1))? {
        Command::Help => std::io::stdout()
            .lock()
            .write_all(HELP.as_bytes())
            .map_err(Into::into),
        Command::Run(path) => {
            tracing_subscriber::fmt()
                .try_init()
                .map_err(|_| anyhow::anyhow!("initialize structured observation"))?;
            runtimeexec::activate_structured_panic_observation();
            deviceidentity::run(&path).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_help_succeeds_without_config() {
        assert!(matches!(
            parse([OsString::from("--help")]),
            Ok(Command::Help)
        ));
        assert!(parse(Vec::<OsString>::new()).is_err());
        for required in [
            "/usr/share/rss/deviceidentity/config.schema.json",
            "/var/run/rss/secrets/serving-secret-bundle",
            "Primary API",
            "Internal mTLS",
            "candidate only",
        ] {
            assert!(HELP.contains(required), "help omitted {required}");
        }
    }
}
