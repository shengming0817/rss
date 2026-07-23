#![forbid(unused_imports)]
#![forbid(clippy::wildcard_imports)]

use crate::infra::vault::VaultTenantStoreAllowlistConfigError;
use vault::TenantStoreAllowlistError;

const VAULT_ALLOWLIST_CLI: &str = "vault-allowlist";
const VAULT_ALLOWLIST_VALIDATE_CLI: &str = "validate";
const VALIDATION_SUCCEEDED: &str = "vault allowlist validation succeeded";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum VaultAllowlistValidationCommandError {
    #[error("vault allowlist validator input selection is invalid")]
    InputSelection,
    #[error("vault allowlist validator input read failed")]
    InputRead,
    #[error("vault allowlist validation failed: missing")]
    Missing,
    #[error("vault allowlist validation failed: blank")]
    Blank,
    #[error("vault allowlist validation failed: invalid-json")]
    InvalidJson,
    #[error("vault allowlist validation failed: invalid-tenant-id")]
    InvalidTenantId,
    #[error("vault allowlist validation failed: invalid-store-id")]
    InvalidStoreId,
    #[error("vault allowlist validation failed: empty-bindings")]
    EmptyBindings,
    #[error("vault allowlist validation failed: duplicate-binding")]
    DuplicateBinding,
    #[error("vault allowlist validation failed: overlapping-namespace")]
    OverlappingNamespace,
    #[error("vault allowlist validation failed: invalid-mount")]
    InvalidMount,
    #[error("vault allowlist validation failed: invalid-prefix")]
    InvalidPrefix,
    #[error("vault allowlist validator output write failed")]
    OutputWrite,
}

impl From<VaultTenantStoreAllowlistConfigError> for VaultAllowlistValidationCommandError {
    fn from(error: VaultTenantStoreAllowlistConfigError) -> Self {
        match error {
            VaultTenantStoreAllowlistConfigError::Missing => Self::Missing,
            VaultTenantStoreAllowlistConfigError::Blank => Self::Blank,
            VaultTenantStoreAllowlistConfigError::InvalidJson => Self::InvalidJson,
            VaultTenantStoreAllowlistConfigError::InvalidTenantId => Self::InvalidTenantId,
            VaultTenantStoreAllowlistConfigError::InvalidStoreId => Self::InvalidStoreId,
            VaultTenantStoreAllowlistConfigError::InvalidBinding(error) => match error {
                TenantStoreAllowlistError::EmptyStoreAllowlist => Self::EmptyBindings,
                TenantStoreAllowlistError::DuplicateStoreBinding => Self::DuplicateBinding,
                TenantStoreAllowlistError::OverlappingTenantNamespace => Self::OverlappingNamespace,
                TenantStoreAllowlistError::EmptyMount
                | TenantStoreAllowlistError::InvalidMountSegment => Self::InvalidMount,
                TenantStoreAllowlistError::InvalidPrefixSegment => Self::InvalidPrefix,
            },
        }
    }
}

enum VaultAllowlistInput<'a> {
    File(&'a str),
    Stdin,
}

#[must_use]
pub fn is_vault_allowlist_validation_command(args: &[String]) -> bool {
    matches!(args, [command, ..] if command == VAULT_ALLOWLIST_CLI)
}

fn parse_input(
    args: &[String],
) -> Result<VaultAllowlistInput<'_>, VaultAllowlistValidationCommandError> {
    match args {
        [command, subcommand, flag, path]
            if command == VAULT_ALLOWLIST_CLI
                && subcommand == VAULT_ALLOWLIST_VALIDATE_CLI
                && flag == "--file"
                && !path.trim().is_empty() =>
        {
            Ok(VaultAllowlistInput::File(path))
        }
        [command, subcommand, flag]
            if command == VAULT_ALLOWLIST_CLI
                && subcommand == VAULT_ALLOWLIST_VALIDATE_CLI
                && flag == "--stdin" =>
        {
            Ok(VaultAllowlistInput::Stdin)
        }
        _ => Err(VaultAllowlistValidationCommandError::InputSelection),
    }
}

fn read_input(
    input: VaultAllowlistInput<'_>,
    stdin: &mut impl std::io::Read,
) -> Result<String, VaultAllowlistValidationCommandError> {
    match input {
        VaultAllowlistInput::File(path) => std::fs::read_to_string(path)
            .map_err(|_| VaultAllowlistValidationCommandError::InputRead),
        VaultAllowlistInput::Stdin => {
            let mut raw = String::new();
            stdin
                .read_to_string(&mut raw)
                .map_err(|_| VaultAllowlistValidationCommandError::InputRead)?;
            Ok(raw)
        }
    }
}

fn run_vault_allowlist_validation_with_io(
    args: &[String],
    stdin: &mut impl std::io::Read,
    stdout: &mut impl std::io::Write,
) -> Result<(), VaultAllowlistValidationCommandError> {
    let raw = read_input(parse_input(args)?, stdin)?;
    crate::infra::vault::tenant_store_allowlist_from_value(Some(&raw))?;
    writeln!(stdout, "{VALIDATION_SUCCEEDED}")
        .map_err(|_| VaultAllowlistValidationCommandError::OutputWrite)
}

/// Validate the serving allowlist wire and adapter invariants without capturing runtime
/// configuration or constructing any provider.
pub fn run_vault_allowlist_validation_command(args: &[String]) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    run_vault_allowlist_validation_with_io(args, &mut stdin.lock(), &mut stdout.lock())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn args(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn canonical_allowlist() -> &'static str {
        r#"{"bindings":[{"tenantId":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","storeId":"vault","mount":"secret","kvPathPrefix":"tenants/a"}]}"#
    }

    fn temp_path() -> std::path::PathBuf {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "rss-vault-allowlist-validator-{}-{sequence}.json",
            std::process::id()
        ))
    }

    #[test]
    fn command_family_claims_the_namespace_and_rejects_other_namespaces() {
        assert!(is_vault_allowlist_validation_command(&args(&[
            "vault-allowlist",
            "validate",
            "--stdin",
        ])));
        assert!(is_vault_allowlist_validation_command(&args(&[
            "vault-allowlist",
            "unknown",
        ])));
        assert!(!is_vault_allowlist_validation_command(&args(&[
            "vault", "validate",
        ])));
    }

    #[test]
    fn stdin_validation_accepts_only_the_canonical_shape_and_static_success_output() {
        let mut stdin = std::io::Cursor::new(canonical_allowlist());
        let mut stdout = Vec::new();
        run_vault_allowlist_validation_with_io(
            &args(&["vault-allowlist", "validate", "--stdin"]),
            &mut stdin,
            &mut stdout,
        )
        .expect("canonical allowlist must validate");
        assert_eq!(stdout, b"vault allowlist validation succeeded\n");
    }

    #[test]
    fn file_validation_uses_the_same_parser_without_provider_configuration() {
        let path = temp_path();
        std::fs::write(&path, canonical_allowlist()).expect("write allowlist fixture");
        let path_arg = path.to_string_lossy().into_owned();
        let mut stdin = std::io::empty();
        let mut stdout = Vec::new();
        let result = run_vault_allowlist_validation_with_io(
            &args(&["vault-allowlist", "validate", "--file", &path_arg]),
            &mut stdin,
            &mut stdout,
        );
        std::fs::remove_file(path).expect("remove allowlist fixture");
        result.expect("canonical allowlist file must validate");
        assert_eq!(stdout, b"vault allowlist validation succeeded\n");
    }

    #[test]
    fn invalid_inputs_return_only_closed_static_categories() {
        const MARKER: &str = "sensitive-validator-marker";
        let invalid_json = format!(
            r#"{{"bindings":[{{"tenantId":"{MARKER}","storeId":"{MARKER}","mount":"{MARKER}","kvPathPrefix":"{MARKER}","unknown":true}}]}}"#
        );
        let mut stdin = std::io::Cursor::new(invalid_json);
        let mut stdout = Vec::new();
        let error = run_vault_allowlist_validation_with_io(
            &args(&["vault-allowlist", "validate", "--stdin"]),
            &mut stdin,
            &mut stdout,
        )
        .expect_err("unknown field must fail");
        assert_eq!(error, VaultAllowlistValidationCommandError::InvalidJson);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(MARKER));
        assert!(stdout.is_empty());

        let secret_path = format!("/missing/{MARKER}.json");
        let error = run_vault_allowlist_validation_with_io(
            &args(&["vault-allowlist", "validate", "--file", &secret_path]),
            &mut std::io::empty(),
            &mut Vec::new(),
        )
        .expect_err("missing file must fail");
        let rendered = format!("{error:?} {error}");
        assert_eq!(error, VaultAllowlistValidationCommandError::InputRead);
        assert!(!rendered.contains(MARKER));
    }

    #[test]
    fn alternate_shapes_flags_and_sources_are_rejected() {
        for parts in [
            vec!["vault-allowlist", "validate"],
            vec!["vault-allowlist", "validate", "--env"],
            vec!["vault-allowlist", "validate", "--stdin", "extra"],
            vec!["vault-allowlist", "validate", "--file", ""],
            vec!["vault-allowlist", "validate", "--file", "a", "--stdin"],
        ] {
            let error = run_vault_allowlist_validation_with_io(
                &args(&parts),
                &mut std::io::empty(),
                &mut Vec::new(),
            )
            .expect_err("non-canonical command shape must fail");
            assert_eq!(error, VaultAllowlistValidationCommandError::InputSelection);
        }
    }

    #[test]
    fn adapter_invariant_failures_keep_closed_categories_without_binding_details() {
        const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        const OTHER_TENANT: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
        const PREFIX: &str = "tenants/secret-marker";
        let duplicate = format!(
            r#"{{"bindings":[{{"tenantId":"{TENANT}","storeId":"vault","mount":"secret","kvPathPrefix":"{PREFIX}"}},{{"tenantId":"{TENANT}","storeId":"vault","mount":"secret","kvPathPrefix":"{PREFIX}"}}]}}"#
        );
        let overlap = format!(
            r#"{{"bindings":[{{"tenantId":"{TENANT}","storeId":"vault-a","mount":"secret","kvPathPrefix":"{PREFIX}"}},{{"tenantId":"{OTHER_TENANT}","storeId":"vault-b","mount":"secret","kvPathPrefix":"{PREFIX}/nested"}}]}}"#
        );
        let invalid_mount = format!(
            r#"{{"bindings":[{{"tenantId":"{TENANT}","storeId":"vault","mount":"secret/..","kvPathPrefix":"{PREFIX}"}}]}}"#
        );
        let invalid_prefix = format!(
            r#"{{"bindings":[{{"tenantId":"{TENANT}","storeId":"vault","mount":"secret","kvPathPrefix":"{PREFIX}/../nested"}}]}}"#
        );
        for (raw, expected) in [
            (
                r#"{"bindings":[]}"#.to_owned(),
                VaultAllowlistValidationCommandError::EmptyBindings,
            ),
            (
                duplicate,
                VaultAllowlistValidationCommandError::DuplicateBinding,
            ),
            (
                overlap,
                VaultAllowlistValidationCommandError::OverlappingNamespace,
            ),
            (
                invalid_mount,
                VaultAllowlistValidationCommandError::InvalidMount,
            ),
            (
                invalid_prefix,
                VaultAllowlistValidationCommandError::InvalidPrefix,
            ),
        ] {
            let error = run_vault_allowlist_validation_with_io(
                &args(&["vault-allowlist", "validate", "--stdin"]),
                &mut std::io::Cursor::new(raw),
                &mut Vec::new(),
            )
            .expect_err("invalid adapter invariant must fail");
            assert_eq!(error, expected);
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains(TENANT));
            assert!(!rendered.contains(OTHER_TENANT));
            assert!(!rendered.contains(PREFIX));
        }
    }
}
