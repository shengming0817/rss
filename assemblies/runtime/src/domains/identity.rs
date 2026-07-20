//! Runtime-specific identity configuration and composition delegation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::DomainBinding;
use identity_composition::{FederatedIdentityModuleDeps, IdentityModuleDeps};
use postgres::{PgDomainDeps, caps};

use crate::config::{ServingConfigMapper, SnapshotConfig};
use crate::infra::vault::build_vault_signer_with;
#[cfg(any(test, feature = "integration"))]
use crate::infra::vault::{VAULT_ADDR_ENV, VAULT_TOKEN_ENV, VAULT_TRANSIT_MOUNT_ENV};
use crate::{SharedRuntimeDeps, SystemClock};

const DEFAULT_IDENTITY_AUTH_GRANT_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_IDENTITY_AUTH_GRANT_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const IDENTITY_AUTH_GRANT_TTL_ENV: &str = "RSS_IDENTITY_AUTH_GRANT_TTL_SECS";
const REFRESH_TTL_ENV: &str = "RSS_REFRESH_TTL_SECS";
pub(crate) const PASSWORD_BLOCKLIST_PATH_ENV: &str = "RSS_PASSWORD_BLOCKLIST_PATH";
const DEFAULT_REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_REFRESH_TTL_SECS: u64 = 365 * 24 * 60 * 60;
pub(crate) enum IdentityTokenProfileInput {
    RssAccess(authn::JwtIssuerConfig<diport::RssAccessProfile>),
    FederatedAccess,
}

impl IdentityTokenProfileInput {
    pub(crate) fn rss_access(issuer: authn::JwtIssuerConfig<diport::RssAccessProfile>) -> Self {
        Self::RssAccess(issuer)
    }

    pub(crate) const fn federated_access() -> Self {
        Self::FederatedAccess
    }
}

pub(crate) struct RssLocalAuthGrantInput {
    signer: Arc<vault::VaultSigner>,
    rss_access_issuer: authn::JwtIssuerConfig<diport::RssAccessProfile>,
    auth_grant_ttl: Duration,
    refresh_ttl: Duration,
}

pub(crate) enum IdentityModuleInput {
    RssAccess(RssLocalAuthGrantInput),
    FederatedAccess,
}

impl IdentityModuleInput {
    pub(crate) fn from_mapper(
        mapper: &ServingConfigMapper<'_>,
        token_profile: IdentityTokenProfileInput,
    ) -> anyhow::Result<Self> {
        let IdentityTokenProfileInput::RssAccess(rss_access_issuer) = token_profile else {
            return Ok(Self::FederatedAccess);
        };
        let config = mapper.config();
        // Preserve the fail-fast contract: bounded lifetimes first, then Vault, then RSS access policy.
        let auth_grant_ttl = Duration::from_secs(identity_auth_grant_ttl_secs(
            config.value(IDENTITY_AUTH_GRANT_TTL_ENV),
        )?);
        let refresh_ttl = Duration::from_secs(refresh_ttl_secs(config.value(REFRESH_TTL_ENV))?);
        validate_auth_grant_covers_refresh(auth_grant_ttl, refresh_ttl)?;
        let signer = Arc::new(build_vault_signer_with(
            |name| config.value(name).map(str::to_owned),
            false,
        )?);
        Ok(Self::RssAccess(RssLocalAuthGrantInput {
            signer,
            rss_access_issuer,
            auth_grant_ttl,
            refresh_ttl,
        }))
    }

    #[cfg(any(test, feature = "integration"))]
    fn from_test_values(values: IdentityTestValues) -> anyhow::Result<Self> {
        validate_explicit_ttl(
            values.auth_grant_ttl,
            IDENTITY_AUTH_GRANT_TTL_ENV,
            MAX_IDENTITY_AUTH_GRANT_TTL_SECS,
        )?;
        validate_explicit_ttl(values.refresh_ttl, REFRESH_TTL_ENV, MAX_REFRESH_TTL_SECS)?;
        validate_auth_grant_covers_refresh(values.auth_grant_ttl, values.refresh_ttl)?;
        anyhow::ensure!(
            !values.access_token_ttl.is_zero(),
            "RSS access-token TTL must be > 0"
        );
        anyhow::ensure!(
            values.access_token_ttl <= diport::TokenProfile::RssAccess.policy().maximum_lifetime(),
            "RSS access-token TTL exceeds the profile maximum lifetime"
        );

        let signer = Arc::new(build_vault_signer_with(
            |name| match name {
                VAULT_ADDR_ENV => Some(values.vault_addr.clone()),
                VAULT_TOKEN_ENV => Some(values.vault_token.clone()),
                VAULT_TRANSIT_MOUNT_ENV => Some(values.vault_transit_mount.clone()),
                _ => None,
            },
            values.vault_allow_http,
        )?);
        let rss_access_issuer = authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(diport::KeyId::new(values.access_token_key_id))
                .expect("non-empty signing key id"),
            diport::SigningPurpose::new("auth.rss-access"),
            values.access_token_issuer,
            values.access_token_audience,
            values.access_token_ttl,
        );
        Ok(Self::RssAccess(RssLocalAuthGrantInput {
            signer,
            rss_access_issuer,
            auth_grant_ttl: values.auth_grant_ttl,
            refresh_ttl: values.refresh_ttl,
        }))
    }

    #[cfg(test)]
    pub(crate) const fn is_federated_access(&self) -> bool {
        matches!(self, Self::FederatedAccess)
    }
}

/// Explicit identity configuration for hermetic integration tests.
#[cfg(any(test, feature = "integration"))]
#[allow(missing_docs)]
pub struct IdentityTestValues {
    pub vault_addr: String,
    pub vault_token: String,
    pub vault_transit_mount: String,
    pub access_token_issuer: String,
    pub access_token_audience: String,
    pub access_token_key_id: String,
    pub access_token_ttl: Duration,
    pub auth_grant_ttl: Duration,
    pub refresh_ttl: Duration,
    pub vault_allow_http: bool,
}

/// Build the identity binding from the runtime's production providers and process configuration.
///
/// # Errors
///
/// Returns an error when RSS Primary requires local AuthGrant configuration and that configuration
/// is absent or invalid, or when the profile-specific identity composition fails.
pub async fn module(
    deps: &SharedRuntimeDeps,
    input: IdentityModuleInput,
) -> anyhow::Result<DomainBinding> {
    wire_with_profile(
        deps.pg.for_domain(),
        Arc::clone(&deps.password_blocklist),
        input,
    )
}

fn wire_with_profile(
    pg: PgDomainDeps<caps::Identity>,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
    input: IdentityModuleInput,
) -> anyhow::Result<DomainBinding> {
    match input {
        IdentityModuleInput::RssAccess(input) => wire_rss_access(pg, blocklist, input),
        IdentityModuleInput::FederatedAccess => identity_composition::wire_federated(
            FederatedIdentityModuleDeps::new(pg, Arc::new(SystemClock)),
        ),
    }
}

/// Load the immutable password policy provider from the captured process generation.
///
/// This is the sole production file-read boundary. Startup calls it before constructing external
/// providers and carries the result into identity wiring, which never reopens the source file.
pub(crate) fn load_password_blocklist(
    config: SnapshotConfig<'_>,
) -> anyhow::Result<Arc<secure::DigestPasswordBlocklist>> {
    let path = config.value(PASSWORD_BLOCKLIST_PATH_ENV).ok_or_else(|| {
        anyhow::anyhow!("missing required env var: {PASSWORD_BLOCKLIST_PATH_ENV}")
    })?;
    crypto::load_password_blocklist(path)
        .map(Arc::new)
        .context("load required password blocklist")
}

fn identity_auth_grant_ttl_secs(raw: Option<&str>) -> anyhow::Result<u64> {
    match raw {
        Some(raw) => {
            let ttl = raw.parse::<u64>().with_context(|| {
                format!("{IDENTITY_AUTH_GRANT_TTL_ENV} must be an integer seconds value")
            })?;
            anyhow::ensure!(ttl > 0, "{IDENTITY_AUTH_GRANT_TTL_ENV} must be > 0");
            anyhow::ensure!(
                ttl <= MAX_IDENTITY_AUTH_GRANT_TTL_SECS,
                "{IDENTITY_AUTH_GRANT_TTL_ENV} must be <= {MAX_IDENTITY_AUTH_GRANT_TTL_SECS}"
            );
            Ok(ttl)
        }
        None => Ok(DEFAULT_IDENTITY_AUTH_GRANT_TTL_SECS),
    }
}

fn refresh_ttl_secs(raw: Option<&str>) -> anyhow::Result<u64> {
    match raw {
        Some(raw) => {
            let ttl = raw
                .parse::<u64>()
                .with_context(|| format!("{REFRESH_TTL_ENV} must be an integer seconds value"))?;
            anyhow::ensure!(ttl > 0, "{REFRESH_TTL_ENV} must be > 0");
            anyhow::ensure!(
                ttl <= MAX_REFRESH_TTL_SECS,
                "{REFRESH_TTL_ENV} must be <= {MAX_REFRESH_TTL_SECS}"
            );
            Ok(ttl)
        }
        None => Ok(DEFAULT_REFRESH_TTL_SECS),
    }
}

fn validate_auth_grant_covers_refresh(
    auth_grant_ttl: Duration,
    refresh_ttl: Duration,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        auth_grant_ttl >= refresh_ttl,
        "{IDENTITY_AUTH_GRANT_TTL_ENV} must be >= {REFRESH_TTL_ENV}"
    );
    Ok(())
}

fn wire_rss_access(
    pg: PgDomainDeps<caps::Identity>,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
    input: RssLocalAuthGrantInput,
) -> anyhow::Result<DomainBinding> {
    let RssLocalAuthGrantInput {
        signer,
        rss_access_issuer,
        auth_grant_ttl,
        refresh_ttl,
    } = input;
    let composition = IdentityModuleDeps::new(
        pg,
        signer,
        Arc::new(SystemClock),
        rss_access_issuer,
        auth_grant_ttl,
        refresh_ttl,
        blocklist,
    );
    identity_composition::wire(composition)
}

#[cfg(any(test, feature = "integration"))]
fn validate_explicit_ttl(ttl: Duration, name: &str, max_secs: u64) -> anyhow::Result<()> {
    anyhow::ensure!(!ttl.is_zero(), "{name} must be > 0");
    anyhow::ensure!(
        ttl <= Duration::from_secs(max_secs),
        "{name} must be <= {max_secs}"
    );
    Ok(())
}

#[cfg(feature = "integration")]
fn wire_configured_from_test_values(
    pg: PgDomainDeps<caps::Identity>,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
    values: IdentityTestValues,
) -> anyhow::Result<DomainBinding> {
    wire_with_profile(
        pg,
        blocklist,
        IdentityModuleInput::from_test_values(values)?,
    )
}

/// Integration-only identity binding with explicit configuration and Vault HTTP policy.
///
/// The explicit values include the HTTP opt-in used only with a loopback mock Vault. The generated
/// production module path is HTTPS-only and cannot receive this test-only type.
///
/// # Errors
///
/// Returns an error when configuration or identity composition fails.
#[cfg(feature = "integration")]
pub(crate) fn wire_identity_with(
    deps: &SharedRuntimeDeps,
    values: IdentityTestValues,
) -> anyhow::Result<DomainBinding> {
    wire_configured_from_test_values(
        deps.pg.for_domain(),
        Arc::clone(&deps.password_blocklist),
        values,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bootstrap::compose_bindings;

    fn test_blocklist() -> Arc<secure::DigestPasswordBlocklist> {
        Arc::new(
            crypto::load_password_blocklist_from_reader(std::io::Cursor::new(include_bytes!(
                "../../../../deploy/password-blocklist.demo.sha256"
            )))
            .unwrap_or_else(|_| unreachable!()),
        )
    }

    fn test_values() -> IdentityTestValues {
        IdentityTestValues {
            vault_addr: "http://127.0.0.1:1".to_string(),
            vault_token: "module-test-token".to_string(),
            vault_transit_mount: "transit".to_string(),
            access_token_issuer: "https://issuer.test".to_string(),
            access_token_audience: "rss".to_string(),
            access_token_key_id: "module-test-es256".to_string(),
            access_token_ttl: Duration::from_secs(900),
            auth_grant_ttl: Duration::from_secs(DEFAULT_IDENTITY_AUTH_GRANT_TTL_SECS),
            refresh_ttl: Duration::from_secs(2_592_000),
            vault_allow_http: true,
        }
    }

    pub(crate) fn test_input() -> anyhow::Result<IdentityModuleInput> {
        IdentityModuleInput::from_test_values(test_values())
    }

    pub(crate) async fn test_binding(input: IdentityModuleInput) -> anyhow::Result<DomainBinding> {
        wire_with_profile(
            postgres::PgRuntimeHandle::for_module_test().for_domain(),
            test_blocklist(),
            input,
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_providers_and_has_stable_empty_output() {
        let mut bindings = vec![
            test_binding(test_input().expect("identity test input"))
                .await
                .expect("identity module builds"),
        ];
        assert_eq!(bindings[0].name(), "identity");

        let (_, output) = compose_bindings(&mut bindings).expect("identity domain composes");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_auth_grant_ttl_defaults_and_accepts_valid_value() {
        assert_eq!(
            DEFAULT_IDENTITY_AUTH_GRANT_TTL_SECS, DEFAULT_REFRESH_TTL_SECS,
            "default AuthGrant must cover the full default refresh lifetime"
        );
        assert_eq!(
            identity_auth_grant_ttl_secs(None).expect("default ttl"),
            DEFAULT_IDENTITY_AUTH_GRANT_TTL_SECS
        );
        assert_eq!(
            identity_auth_grant_ttl_secs(Some("7200")).expect("valid ttl"),
            7_200
        );
    }

    #[test]
    fn identity_auth_grant_ttl_rejects_invalid_values() {
        for raw in [
            "not-a-number".to_string(),
            "0".to_string(),
            (MAX_IDENTITY_AUTH_GRANT_TTL_SECS + 1).to_string(),
        ] {
            assert!(identity_auth_grant_ttl_secs(Some(&raw)).is_err());
        }
    }

    #[test]
    fn auth_grant_ttl_must_cover_refresh_ttl() {
        let thirty_days = Duration::from_secs(DEFAULT_REFRESH_TTL_SECS);
        assert!(validate_auth_grant_covers_refresh(thirty_days, thirty_days).is_ok());
        assert!(
            validate_auth_grant_covers_refresh(thirty_days + Duration::from_secs(1), thirty_days,)
                .is_ok()
        );
        assert!(
            validate_auth_grant_covers_refresh(thirty_days - Duration::from_secs(1), thirty_days,)
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn production_mapper_rejects_refresh_longer_than_auth_grant_before_provider_setup() {
        let snapshot = crate::config::test_snapshot(&[
            (IDENTITY_AUTH_GRANT_TTL_ENV, "3600"),
            (REFRESH_TTL_ENV, "7200"),
        ])
        .expect("capture explicit invalid lifetime relation");
        let mapper = ServingConfigMapper::for_test(snapshot.view());
        let issuer = authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(diport::KeyId::new("ttl-relation-test"))
                .expect("non-empty signing key id"),
            diport::SigningPurpose::new("auth.rss-access"),
            "https://issuer.test",
            "rss",
            Duration::from_secs(900),
        );

        assert!(
            IdentityModuleInput::from_mapper(
                &mapper,
                IdentityTokenProfileInput::rss_access(issuer),
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_test_values_reject_refresh_longer_than_auth_grant() {
        let mut values = test_values();
        values.auth_grant_ttl = Duration::from_secs(3_600);
        values.refresh_ttl = Duration::from_secs(7_200);

        assert!(IdentityModuleInput::from_test_values(values).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_ttl_defaults_and_rejects_bounds() {
        assert_eq!(
            refresh_ttl_secs(None).expect("default refresh ttl"),
            DEFAULT_REFRESH_TTL_SECS
        );
        for raw in ["0".to_string(), (MAX_REFRESH_TTL_SECS + 1).to_string()] {
            assert!(refresh_ttl_secs(Some(&raw)).is_err());
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn federated_profile_does_not_read_or_construct_local_rss_auth_grant_inputs() {
        let snapshot = crate::config::test_snapshot(&[]).expect("empty captured generation");
        let mapper = ServingConfigMapper::for_test(snapshot.view());
        let input = IdentityModuleInput::from_mapper(
            &mapper,
            IdentityTokenProfileInput::federated_access(),
        )
        .expect("federated identity needs no local RSS issuer or Vault signer");
        assert!(matches!(input, IdentityModuleInput::FederatedAccess));
    }
}
