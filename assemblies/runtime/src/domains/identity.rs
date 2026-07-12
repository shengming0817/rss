//! Runtime-specific identity configuration and composition delegation.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::DomainBinding;
use identity_composition::IdentityModuleDeps;
use postgres::{PgDomainDeps, caps};

use crate::infra::vault::build_vault_signer_with;
use crate::{SharedRuntimeDeps, SystemClock};

const DEFAULT_IDENTITY_SESSION_TTL_SECS: u64 = 3_600;
const MAX_IDENTITY_SESSION_TTL_SECS: u64 = 90 * 24 * 60 * 60;
const IDENTITY_SESSION_TTL_ENV: &str = "RSS_IDENTITY_SESSION_TTL_SECS";
const JWT_ISSUER_ENV: &str = "RSS_JWT_ISSUER";
const JWT_AUDIENCE_ENV: &str = "RSS_JWT_AUDIENCE";
const JWT_KEY_ID_ENV: &str = "RSS_JWT_ES256_KEY_ID";
const JWT_ACCESS_TTL_ENV: &str = "RSS_JWT_ACCESS_TTL_SECS";
const REFRESH_TTL_ENV: &str = "RSS_REFRESH_TTL_SECS";
const DEFAULT_REFRESH_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_REFRESH_TTL_SECS: u64 = 365 * 24 * 60 * 60;
const JWT_SIGNING_PURPOSE: &str = "auth.jwt.access";

/// Build the identity binding from the runtime's production providers and process configuration.
///
/// # Errors
///
/// Returns an error when required JWT or Vault configuration is absent or invalid, session or
/// refresh TTLs violate their bounds, or identity composition fails.
pub async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
    wire_configured(deps.pg.for_domain(), |name| std::env::var(name).ok(), false)
}

fn identity_session_ttl_secs(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<u64> {
    match env(IDENTITY_SESSION_TTL_ENV) {
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

fn refresh_ttl_secs(env: impl Fn(&str) -> Option<String>) -> anyhow::Result<u64> {
    match env(REFRESH_TTL_ENV) {
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
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<authn::JwtIssuerConfig> {
    let issuer = get(JWT_ISSUER_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ISSUER_ENV}"))?;
    let audience = get(JWT_AUDIENCE_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_AUDIENCE_ENV}"))?;
    let key_id = get(JWT_KEY_ID_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_KEY_ID_ENV}"))?;
    let ttl_secs = get(JWT_ACCESS_TTL_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {JWT_ACCESS_TTL_ENV}"))?
        .parse::<u64>()
        .with_context(|| format!("{JWT_ACCESS_TTL_ENV} must be an integer seconds value"))?;
    anyhow::ensure!(ttl_secs > 0, "{JWT_ACCESS_TTL_ENV} must be > 0");
    Ok(authn::JwtIssuerConfig {
        key: diport::KeyId::new(key_id),
        alg: authn::JwtAlg::Es256,
        purpose: diport::SigningPurpose::new(JWT_SIGNING_PURPOSE),
        issuer,
        audience,
        ttl: Duration::from_secs(ttl_secs),
    })
}

fn wire_configured(
    pg: PgDomainDeps<caps::Identity>,
    get: impl Fn(&str) -> Option<String>,
    vault_allow_http: bool,
) -> anyhow::Result<DomainBinding> {
    // Keep the established fail-fast order: validate bounded lifetimes before constructing the
    // Vault signer, then validate the JWT policy.
    let session_ttl = Duration::from_secs(identity_session_ttl_secs(|name| get(name))?);
    let refresh_ttl = Duration::from_secs(refresh_ttl_secs(|name| get(name))?);
    let signer = Arc::new(build_vault_signer_with(|name| get(name), vault_allow_http)?);
    let jwt = build_jwt_issuer_config(get)?;
    let composition = IdentityModuleDeps::new(
        pg,
        signer,
        Arc::new(SystemClock),
        jwt,
        session_ttl,
        refresh_ttl,
    );
    identity_composition::wire(composition)
}

/// Integration-only identity binding with injectable configuration and Vault HTTP policy.
///
/// `vault_allow_http` exists only for hermetic tests with a loopback mock Vault. The generated
/// production module path is HTTPS-only.
///
/// # Errors
///
/// Returns an error when configuration or identity composition fails.
#[cfg(feature = "integration")]
pub(crate) fn wire_identity_with(
    deps: &SharedRuntimeDeps,
    get: impl Fn(&str) -> Option<String>,
    vault_allow_http: bool,
) -> anyhow::Result<DomainBinding> {
    wire_configured(deps.pg.for_domain(), get, vault_allow_http)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bootstrap::compose_bindings;

    fn module_env(name: &str) -> Option<String> {
        match name {
            "RSS_VAULT_ADDR" => Some("http://127.0.0.1:1".to_string()),
            "RSS_VAULT_TOKEN" => Some("module-test-token".to_string()),
            "RSS_VAULT_TRANSIT_MOUNT" => Some("transit".to_string()),
            JWT_ISSUER_ENV => Some("https://issuer.test".to_string()),
            JWT_AUDIENCE_ENV => Some("rss".to_string()),
            JWT_KEY_ID_ENV => Some("module-test-es256".to_string()),
            JWT_ACCESS_TTL_ENV => Some("900".to_string()),
            REFRESH_TTL_ENV => Some("2592000".to_string()),
            _ => None,
        }
    }

    pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
        wire_configured(
            postgres::PgRuntimeDeps::for_module_test().for_domain(),
            module_env,
            true,
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_providers_and_has_stable_empty_output() {
        let mut bindings = vec![test_binding().await.expect("identity module builds")];
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
            identity_session_ttl_secs(|_| None).expect("default ttl"),
            DEFAULT_IDENTITY_SESSION_TTL_SECS
        );
        assert_eq!(
            identity_session_ttl_secs(|name| {
                (name == IDENTITY_SESSION_TTL_ENV).then(|| "7200".to_string())
            })
            .expect("valid ttl"),
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
            assert!(
                identity_session_ttl_secs(|name| {
                    (name == IDENTITY_SESSION_TTL_ENV).then(|| raw.clone())
                })
                .is_err()
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn refresh_ttl_defaults_and_rejects_bounds() {
        assert_eq!(
            refresh_ttl_secs(|_| None).expect("default refresh ttl"),
            DEFAULT_REFRESH_TTL_SECS
        );
        for raw in ["0".to_string(), (MAX_REFRESH_TTL_SECS + 1).to_string()] {
            assert!(
                refresh_ttl_secs(|name| { (name == REFRESH_TTL_ENV).then(|| raw.clone()) })
                    .is_err()
            );
        }
    }

    fn jwt_env(name: &str) -> Option<String> {
        match name {
            JWT_ISSUER_ENV => Some("https://issuer.test".to_string()),
            JWT_AUDIENCE_ENV => Some("rss".to_string()),
            JWT_KEY_ID_ENV => Some("my-es256-key".to_string()),
            JWT_ACCESS_TTL_ENV => Some("3600".to_string()),
            _ => None,
        }
    }

    #[test]
    fn jwt_issuer_config_requires_every_field_and_positive_ttl() {
        for missing in [JWT_ISSUER_ENV, JWT_AUDIENCE_ENV, JWT_KEY_ID_ENV] {
            let result =
                build_jwt_issuer_config(|name| if name == missing { None } else { jwt_env(name) });
            assert!(
                matches!(&result, Err(error) if format!("{error:#}").contains(missing)),
                "missing {missing} must be named in the error"
            );
        }

        let result = build_jwt_issuer_config(|name| {
            if name == JWT_ACCESS_TTL_ENV {
                Some("0".to_string())
            } else {
                jwt_env(name)
            }
        });
        assert!(matches!(&result, Err(error) if error.to_string().contains("must be > 0")));
    }

    #[test]
    fn jwt_issuer_config_accepts_complete_configuration() {
        assert!(build_jwt_issuer_config(jwt_env).is_ok());
    }
}
