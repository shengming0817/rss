//! Runtime-specific identity configuration and composition delegation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::DomainBinding;
use identity_composition::IdentityModuleDeps;
use postgres::{PgDomainDeps, caps};

use crate::config::{ServingConfigMapper, SnapshotConfig};
use crate::infra::vault::build_vault_signer_with;
#[cfg(any(test, feature = "integration"))]
use crate::infra::vault::{VAULT_ADDR_ENV, VAULT_TOKEN_ENV, VAULT_TRANSIT_MOUNT_ENV};
use crate::{SharedRuntimeDeps, SystemClock};

const DEFAULT_IDENTITY_SESSION_TTL_SECS: u64 = 3_600;
const MAX_IDENTITY_SESSION_TTL_SECS: u64 = 90 * 24 * 60 * 60;
const IDENTITY_SESSION_TTL_ENV: &str = "RSS_IDENTITY_SESSION_TTL_SECS";
const JWT_ISSUER_ENV: &str = "RSS_JWT_ISSUER";
const JWT_AUDIENCE_ENV: &str = "RSS_JWT_AUDIENCE";
const JWT_KEY_ID_ENV: &str = "RSS_JWT_ES256_KEY_ID";
const JWT_ACCESS_TTL_ENV: &str = "RSS_JWT_ACCESS_TTL_SECS";
const REFRESH_TTL_ENV: &str = "RSS_REFRESH_TTL_SECS";
pub(crate) const PASSWORD_BLOCKLIST_PATH_ENV: &str = "RSS_PASSWORD_BLOCKLIST_PATH";
const DEFAULT_REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_REFRESH_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const JWT_SIGNING_PURPOSE: &str = "auth.jwt.access";

pub(crate) struct IdentityModuleInput {
    signer: Arc<vault::VaultSigner>,
    jwt: authn::JwtIssuerConfig,
    session_ttl: Duration,
    refresh_ttl: Duration,
}

impl IdentityModuleInput {
    pub(crate) fn from_mapper(mapper: &ServingConfigMapper<'_>) -> anyhow::Result<Self> {
        let config = mapper.config();
        // Preserve the fail-fast contract: bounded lifetimes first, then Vault, then JWT policy.
        let session_ttl = Duration::from_secs(identity_session_ttl_secs(
            config.value(IDENTITY_SESSION_TTL_ENV),
        )?);
        let refresh_ttl = Duration::from_secs(refresh_ttl_secs(config.value(REFRESH_TTL_ENV))?);
        let signer = Arc::new(build_vault_signer_with(
            |name| config.value(name).map(str::to_owned),
            false,
        )?);
        let jwt = build_jwt_issuer_config(
            config.value(JWT_ISSUER_ENV),
            config.value(JWT_AUDIENCE_ENV),
            config.value(JWT_KEY_ID_ENV),
            config.value(JWT_ACCESS_TTL_ENV),
        )?;
        Ok(Self {
            signer,
            jwt,
            session_ttl,
            refresh_ttl,
        })
    }

    #[cfg(any(test, feature = "integration"))]
    fn from_test_values(values: IdentityTestValues) -> anyhow::Result<Self> {
        validate_explicit_ttl(
            values.session_ttl,
            IDENTITY_SESSION_TTL_ENV,
            MAX_IDENTITY_SESSION_TTL_SECS,
        )?;
        validate_explicit_ttl(values.refresh_ttl, REFRESH_TTL_ENV, MAX_REFRESH_TTL_SECS)?;
        anyhow::ensure!(
            !values.jwt_access_ttl.is_zero(),
            "{JWT_ACCESS_TTL_ENV} must be > 0"
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
        let jwt = authn::JwtIssuerConfig {
            key: diport::KeyId::new(values.jwt_key_id),
            alg: authn::JwtAlg::Es256,
            purpose: diport::SigningPurpose::new(JWT_SIGNING_PURPOSE),
            issuer: values.jwt_issuer,
            audience: values.jwt_audience,
            ttl: values.jwt_access_ttl,
        };
        Ok(Self {
            signer,
            jwt,
            session_ttl: values.session_ttl,
            refresh_ttl: values.refresh_ttl,
        })
    }
}

/// Explicit identity configuration for hermetic integration tests.
#[cfg(any(test, feature = "integration"))]
#[allow(missing_docs)]
pub struct IdentityTestValues {
    pub vault_addr: String,
    pub vault_token: String,
    pub vault_transit_mount: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_key_id: String,
    pub jwt_access_ttl: Duration,
    pub session_ttl: Duration,
    pub refresh_ttl: Duration,
    pub vault_allow_http: bool,
}

/// Build the identity binding from the runtime's production providers and process configuration.
///
/// # Errors
///
/// Returns an error when required JWT or Vault configuration is absent or invalid, session or
/// refresh TTLs violate their bounds, or identity composition fails.
pub async fn module(
    deps: &SharedRuntimeDeps,
    input: IdentityModuleInput,
) -> anyhow::Result<DomainBinding> {
    wire_configured(
        deps.pg.for_domain(),
        Arc::clone(&deps.password_blocklist),
        input,
    )
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

fn identity_session_ttl_secs(raw: Option<&str>) -> anyhow::Result<u64> {
    match raw {
        Some(raw) => {
            let ttl = raw.parse::<u64>().with_context(|| {
                format!("{IDENTITY_SESSION_TTL_ENV} must be an integer seconds value")
            })?;
            anyhow::ensure!(ttl > 0, "{IDENTITY_SESSION_TTL_ENV} must be > 0");
            anyhow::ensure!(
                ttl <= MAX_IDENTITY_SESSION_TTL_SECS,
                "{IDENTITY_SESSION_TTL_ENV} must be <= {MAX_IDENTITY_SESSION_TTL_SECS}"
            );
            Ok(ttl)
        }
        None => Ok(DEFAULT_IDENTITY_SESSION_TTL_SECS),
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

fn build_jwt_issuer_config(
    issuer: Option<&str>,
    audience: Option<&str>,
    key_id: Option<&str>,
    ttl_secs: Option<&str>,
) -> anyhow::Result<authn::JwtIssuerConfig> {
    let issuer =
        issuer.ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ISSUER_ENV}"))?;
    let audience =
        audience.ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_AUDIENCE_ENV}"))?;
    let key_id =
        key_id.ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_KEY_ID_ENV}"))?;
    let ttl_secs = ttl_secs
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ACCESS_TTL_ENV}"))?
        .parse::<u64>()
        .with_context(|| format!("{JWT_ACCESS_TTL_ENV} must be an integer seconds value"))?;
    anyhow::ensure!(ttl_secs > 0, "{JWT_ACCESS_TTL_ENV} must be > 0");
    Ok(authn::JwtIssuerConfig {
        key: diport::KeyId::new(key_id.to_owned()),
        alg: authn::JwtAlg::Es256,
        purpose: diport::SigningPurpose::new(JWT_SIGNING_PURPOSE),
        issuer: issuer.to_owned(),
        audience: audience.to_owned(),
        ttl: Duration::from_secs(ttl_secs),
    })
}

fn wire_configured(
    pg: PgDomainDeps<caps::Identity>,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
    input: IdentityModuleInput,
) -> anyhow::Result<DomainBinding> {
    let IdentityModuleInput {
        signer,
        jwt,
        session_ttl,
        refresh_ttl,
    } = input;
    let composition = IdentityModuleDeps::new(
        pg,
        signer,
        Arc::new(SystemClock),
        jwt,
        session_ttl,
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
    wire_configured(
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

    pub(crate) fn test_input() -> anyhow::Result<IdentityModuleInput> {
        IdentityModuleInput::from_test_values(IdentityTestValues {
            vault_addr: "http://127.0.0.1:1".to_string(),
            vault_token: "module-test-token".to_string(),
            vault_transit_mount: "transit".to_string(),
            jwt_issuer: "https://issuer.test".to_string(),
            jwt_audience: "rss".to_string(),
            jwt_key_id: "module-test-es256".to_string(),
            jwt_access_ttl: Duration::from_secs(900),
            session_ttl: Duration::from_secs(DEFAULT_IDENTITY_SESSION_TTL_SECS),
            refresh_ttl: Duration::from_secs(2_592_000),
            vault_allow_http: true,
        })
    }

    pub(crate) async fn test_binding(input: IdentityModuleInput) -> anyhow::Result<DomainBinding> {
        wire_configured(
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
    fn identity_session_ttl_defaults_and_accepts_valid_value() {
        assert_eq!(
            identity_session_ttl_secs(None).expect("default ttl"),
            DEFAULT_IDENTITY_SESSION_TTL_SECS
        );
        assert_eq!(
            identity_session_ttl_secs(Some("7200")).expect("valid ttl"),
            7_200
        );
    }

    #[test]
    fn identity_session_ttl_rejects_invalid_values() {
        for raw in [
            "not-a-number".to_string(),
            "0".to_string(),
            (MAX_IDENTITY_SESSION_TTL_SECS + 1).to_string(),
        ] {
            assert!(identity_session_ttl_secs(Some(&raw)).is_err());
        }
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
    fn jwt_issuer_config_requires_every_field_and_positive_ttl() {
        for missing in [JWT_ISSUER_ENV, JWT_AUDIENCE_ENV, JWT_KEY_ID_ENV] {
            let result = build_jwt_issuer_config(
                (missing != JWT_ISSUER_ENV).then_some("https://issuer.test"),
                (missing != JWT_AUDIENCE_ENV).then_some("rss"),
                (missing != JWT_KEY_ID_ENV).then_some("my-es256-key"),
                Some("3600"),
            );
            assert!(
                matches!(&result, Err(error) if format!("{error:#}").contains(missing)),
                "missing {missing} must be named in the error"
            );
        }

        let result = build_jwt_issuer_config(
            Some("https://issuer.test"),
            Some("rss"),
            Some("my-es256-key"),
            Some("0"),
        );
        assert!(matches!(&result, Err(error) if error.to_string().contains("must be > 0")));
    }

    #[test]
    fn jwt_issuer_config_accepts_complete_configuration() {
        assert!(
            build_jwt_issuer_config(
                Some("https://issuer.test"),
                Some("rss"),
                Some("my-es256-key"),
                Some("3600"),
            )
            .is_ok()
        );
    }
}
