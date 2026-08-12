//! Shared clap helpers for operator CLI surfaces
//! (reconcile / sagas / projections / audit-ledger / settings / device-latent /
//! l2-dr-recovery / dlq).

#![forbid(unused_imports)]
// `forbid(clippy::wildcard_imports)` 与 clap derive 的 `allow(clippy::pedantic)` 冲突（E0453）；
// unused_imports 可保持 forbid；wildcard_imports 用 deny。
#![deny(clippy::wildcard_imports)]

use clap::Args;
use clap::error::ErrorKind;
use rss_request_context::TenantId;

use crate::operator::service_token::OPERATOR_SERVICE_TOKEN_STDIN_FLAG;

/// Production linkage nail: clap long id must stay aligned with the service_token flag const.
const _: &str = OPERATOR_SERVICE_TOKEN_STDIN_FLAG;

/// Help/version text was already printed by clap; caller should exit success without further work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ClapHelpPrinted;

/// Presence-only stdin token carrier shared by operator clap families.
///
/// Field name `operator_service_token_stdin` derives clap long id `operator-service-token-stdin`,
/// which must stay aligned with [`crate::operator::service_token::OPERATOR_SERVICE_TOKEN_STDIN_FLAG`]
/// (without `--`).
#[derive(Debug, Args)]
pub(super) struct OperatorServiceTokenStdinArg {
    /// Presence-only proof that the operator service token will be supplied on stdin.
    #[arg(long, required = true, action = clap::ArgAction::SetTrue)]
    pub operator_service_token_stdin: bool,
}

/// Shared auth surface for operator clap families (token presence + tenant scope).
#[derive(Debug, Args)]
pub(super) struct OperatorAuthSharedArgs {
    #[command(flatten)]
    pub token_stdin: OperatorServiceTokenStdinArg,

    /// Operator tenant that minted the operator service token (UUID).
    #[arg(long, value_parser = parse_operator_tenant_cli)]
    pub operator_tenant: TenantId,

    /// Target tenant scope for the operator command (UUID).
    #[arg(long, value_parser = parse_tenant_cli)]
    pub tenant: TenantId,
}

/// Fixed `{family}: invalid value; see --help` — shared by ValueValidation buckets and typed
/// parsers that must never interpolate argv/`SECRET_BAIT`.
pub(super) fn operator_cli_invalid_value(family: &'static str) -> String {
    format!("{family}: invalid value; see --help")
}

/// Map every non-help clap failure to a fixed family-prefixed diagnostic that never echoes argv.
///
/// Buckets: MissingRequiredArgument / MissingSubcommand / InvalidSubcommand / UnknownArgument /
/// InvalidValue|TooManyValues|ValueValidation / residual → invalid arguments.
/// Never `{err}` (would re-echo user input).
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
        // Bare namespace (`rss dlq` / try_parse_from(["prog","dlq"])) surfaces as
        // DisplayHelpOnMissingArgumentOrSubcommand on current clap; MissingSubcommand is kept
        // for forward compatibility.
        ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            format!("{family}: missing subcommand; see --help")
        }
        ErrorKind::UnknownArgument => format!("{family}: unexpected argument; see --help"),
        ErrorKind::MissingRequiredArgument => {
            format!("{family}: missing required argument; see --help")
        }
        ErrorKind::InvalidValue | ErrorKind::TooManyValues | ErrorKind::ValueValidation => {
            operator_cli_invalid_value(family)
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
///
/// When `exact_bucket` is `Some("missing subcommand")`, require the full message
/// `{family}: missing subcommand; see --help`.
#[cfg(test)]
pub(super) fn assert_operator_cli_err(err: &anyhow::Error, family: &str) {
    assert_operator_cli_err_bucket(err, family, None);
}

/// Like [`assert_operator_cli_err`], optionally locking the exact bucket text after `{family}: `.
#[cfg(test)]
pub(super) fn assert_operator_cli_err_bucket(
    err: &anyhow::Error,
    family: &str,
    exact_bucket: Option<&str>,
) {
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
    if let Some(bucket) = exact_bucket {
        assert_eq!(
            message,
            format!("{family}: {bucket}; see --help"),
            "expected exact bucket {bucket:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::service_token::OPERATOR_SERVICE_TOKEN_STDIN_FLAG;
    use clap::Parser;

    #[test]
    fn operator_service_token_stdin_clap_long_matches_flag_const() {
        // clap `#[arg(long)]` on `operator_service_token_stdin` → kebab-case long id.
        let clap_long = "operator_service_token_stdin".replace('_', "-");
        assert_eq!(
            format!("--{clap_long}"),
            OPERATOR_SERVICE_TOKEN_STDIN_FLAG,
            "OperatorServiceTokenStdinArg field long must stay the single source with service_token const"
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
            sanitized_operator_clap_message("dlq", ErrorKind::MissingSubcommand),
            "dlq: missing subcommand; see --help"
        );
        assert_eq!(
            sanitized_operator_clap_message(
                "dlq",
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ),
            "dlq: missing subcommand; see --help"
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
            "sagas: missing required argument; see --help"
        );
        assert_eq!(
            sanitized_operator_clap_message("dlq", ErrorKind::ValueValidation),
            operator_cli_invalid_value("dlq")
        );
        assert_eq!(
            sanitized_operator_clap_message("dlq", ErrorKind::ArgumentConflict),
            "dlq: invalid arguments; see --help"
        );
    }

    /// Family prepare passes argv whose `[0]` is the namespace (clap bin name). Bare namespace
    /// (`["prog", "dlq"]` with a parent that only selects the family, or `["dlq"]` as bin-only)
    /// must map to the `missing subcommand` bucket — never echo argv.
    #[derive(Debug, Parser)]
    #[command(
        name = "prog",
        disable_help_subcommand = true,
        disable_version_flag = true
    )]
    struct FamilyMissingSubcommandProbe {
        #[command(subcommand)]
        _family: FamilyMissingSubcommandProbeFamily,
    }

    #[derive(Debug, clap::Subcommand)]
    enum FamilyMissingSubcommandProbeFamily {
        /// Nested operator family that itself requires a subcommand (list/inspect/…).
        #[command(subcommand)]
        Dlq(FamilyMissingSubcommandProbeDlq),
    }

    #[derive(Debug, clap::Subcommand)]
    enum FamilyMissingSubcommandProbeDlq {
        List,
    }

    #[test]
    fn try_parse_from_prog_dlq_locks_missing_subcommand_bucket() {
        let err = FamilyMissingSubcommandProbe::try_parse_from(["prog", "dlq"])
            .expect_err("prog dlq without family action must miss a subcommand");
        assert!(
            matches!(
                err.kind(),
                ErrorKind::MissingSubcommand | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            ),
            "unexpected kind {:?}",
            err.kind()
        );
        assert_eq!(
            sanitized_operator_clap_message("dlq", err.kind()),
            "dlq: missing subcommand; see --help"
        );
    }
}
