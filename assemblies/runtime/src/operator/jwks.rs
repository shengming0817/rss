#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use crate::phase::OperatorRuntimeInputs;

const RSS_ACCESS_JWKS_CLI: &str = "rss-access-jwks";
const RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI: &str = "export-vault-transit";

#[must_use]
pub fn is_rss_access_jwks_export_command(args: &[String]) -> bool {
    matches!(
        args,
        [command, subcommand, ..]
            if command == RSS_ACCESS_JWKS_CLI
                && subcommand == RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI
    )
}

pub async fn run_rss_access_jwks_export_command(
    args: &[String],
    runtime_inputs: &OperatorRuntimeInputs,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_rss_access_jwks_export_command(args),
        "usage: rss rss-access-jwks export-vault-transit [--out <path>]"
    );
    crate::infra::vault::export_rss_access_jwks(
        args,
        runtime_inputs.config(),
        runtime_inputs.operator_capability(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        RSS_ACCESS_JWKS_CLI, RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI,
        is_rss_access_jwks_export_command,
    };

    #[test]
    fn command_family_is_closed() {
        assert!(is_rss_access_jwks_export_command(&[
            RSS_ACCESS_JWKS_CLI.to_owned(),
            RSS_ACCESS_JWKS_EXPORT_VAULT_TRANSIT_CLI.to_owned(),
        ]));
        assert!(!is_rss_access_jwks_export_command(&[
            RSS_ACCESS_JWKS_CLI.to_owned(),
        ]));
    }
}
