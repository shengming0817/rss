//! Shared clap helpers for operator CLI surfaces (reconcile / projection / saga).

#![forbid(unused_imports)]
// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![deny(clippy::wildcard_imports)]

use clap::Args;
use clap::error::ErrorKind;
use vocab::TenantId;

/// Help/version text was already printed by clap; caller should exit success without further work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClapHelpPrinted;

/// Shared auth surface for operator clap families (token presence + tenant scope).
///
/// Field name `operator_service_token_stdin` derives clap long id `operator-service-token-stdin`,
/// which must stay aligned with [`crate::operator::service_token::OPERATOR_SERVICE_TOKEN_STDIN_FLAG`]
/// (without `--`).
#[derive(Debug, Args)]
pub(super) struct OperatorAuthSharedArgs {
    /// Presence-only proof that the operator service token will be supplied on stdin.
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub operator_service_token_stdin: bool,

    /// Operator tenant that minted the operator service token (UUID).
    #[arg(long, value_parser = parse_operator_tenant_cli)]
    pub operator_tenant: TenantId,

    /// Target tenant scope for the operator command (UUID).
    #[arg(long, value_parser = parse_tenant_cli)]
    pub tenant: TenantId,
}

/// Map every non-help clap failure to a fixed family-prefixed diagnostic that never echoes argv.
///
/// Covers UnknownArgument / InvalidSubcommand / InvalidValue / TooManyValues /
/// ValueValidation and any future kind — never `{err}` (would re-echo user input).
pub(super) fn map_clap_parse_error(
    err: clap::Error,
    family: &'static str,
) -> anyhow::Result<ClapHelpPrinted> {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = err.print();
            Ok(ClapHelpPrinted)
        }
        kind => anyhow::bail!("{}", sanitized_operator_clap_message(family, kind)),
    }
}

fn sanitized_operator_clap_message(family: &'static str, kind: ErrorKind) -> String {
    match kind {
        ErrorKind::InvalidSubcommand => format!("{family}: unknown subcommand; see --help"),
        ErrorKind::UnknownArgument => format!("{family}: unexpected argument; see --help"),
        ErrorKind::InvalidValue | ErrorKind::TooManyValues | ErrorKind::ValueValidation => {
            format!("{family}: invalid value; see --help")
        }
        _ => format!("{family}: invalid arguments; see --help"),
    }
}

pub(super) fn parse_tenant_named(flag: &str, raw: &str) -> Result<TenantId, String> {
    TenantId::parse(raw).map_err(|_| format!("{flag} must be a tenant UUID"))
}

pub(super) fn parse_operator_tenant_cli(raw: &str) -> Result<TenantId, String> {
    parse_tenant_named("--operator-tenant", raw)
}

pub(super) fn parse_tenant_cli(raw: &str) -> Result<TenantId, String> {
    parse_tenant_named("--tenant", raw)
}

/// Assert a bucketed operator clap diagnostic: `{family}: …; see --help`, never SECRET_BAIT.
#[cfg(test)]
pub(super) fn assert_operator_cli_err(err: &anyhow::Error, family: &str) {
    let message = err.to_string();
    let prefix = format!("{family}: ");
    assert!(
        message.starts_with(&prefix) && message.contains("; see --help"),
        "expected bucketed {family} diagnostic, got: {message}"
    );
    assert!(
        !message.contains("SECRET_BAIT"),
        "diagnostic leaked SECRET_BAIT: {message}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::service_token::OPERATOR_SERVICE_TOKEN_STDIN_FLAG;

    #[test]
    fn operator_service_token_stdin_clap_long_matches_flag_const() {
        // clap `#[arg(long)]` on `operator_service_token_stdin` → kebab-case long id.
        let clap_long = "operator_service_token_stdin".replace('_', "-");
        assert_eq!(
            format!("--{clap_long}"),
            OPERATOR_SERVICE_TOKEN_STDIN_FLAG,
            "OperatorAuthSharedArgs field long must stay the single source with service_token const"
        );
        assert_eq!(
            OPERATOR_SERVICE_TOKEN_STDIN_FLAG.strip_prefix("--"),
            Some(clap_long.as_str())
        );
    }

    #[test]
    fn sanitized_messages_are_family_prefixed_and_bucketed() {
        assert_eq!(
            sanitized_operator_clap_message("sagas", ErrorKind::InvalidSubcommand),
            "sagas: unknown subcommand; see --help"
        );
        assert_eq!(
            sanitized_operator_clap_message("projections", ErrorKind::UnknownArgument),
            "projections: unexpected argument; see --help"
        );
        assert_eq!(
            sanitized_operator_clap_message("reconcile-target", ErrorKind::TooManyValues),
            "reconcile-target: invalid value; see --help"
        );
        assert_eq!(
            sanitized_operator_clap_message("sagas", ErrorKind::MissingRequiredArgument),
            "sagas: invalid arguments; see --help"
        );
    }
}
