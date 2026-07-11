//! Identity domain wiring.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bootstrap::{Domain, DomainBinding, DomainModuleResult};
use identity::{
    IdentityDomain, IdentityDomainDeps, LoginService, PolicyManageService, RbacAdminService,
    RefreshService,
    ports::{
        DynCredentialRepo, DynPolicyLifecycle, DynPolicyRepo, DynRefreshTokenStore,
        DynResourceAttributeRepo, DynRoleBindingLifecycle, DynRoleRepo, DynSessionLifecycle,
    },
};
use postgres::{PgDomainDeps, caps};
use vault::VaultSigner;

use crate::infra::vault::build_vault_signer_with;
use crate::{SharedRuntimeDeps, SystemClock};

const DOMAIN_NAME: &str = "identity";
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

mod sealed {
    pub trait Sealed {}
}

/// Typed provider seam for the identity module factory.
///
/// The trait is sealed: production uses [`SharedRuntimeDeps`], while this crate's tests provide a
/// hermetic source that exercises the same public [`module`] entrypoint without a live database or
/// Vault service.
#[doc(hidden)]
pub trait IdentityModuleSource: sealed::Sealed {
    fn identity_pg(&self) -> PgDomainDeps<caps::Identity>;
    fn config(&self, name: &str) -> Option<String>;
    fn vault_allow_http(&self) -> bool;
}

impl sealed::Sealed for SharedRuntimeDeps {}

impl IdentityModuleSource for SharedRuntimeDeps {
    fn identity_pg(&self) -> PgDomainDeps<caps::Identity> {
        self.pg.for_domain()
    }

    fn config(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn vault_allow_http(&self) -> bool {
        false
    }
}

fn bind<D>(domain: D, output: DomainModuleResult) -> DomainBinding
where
    D: Domain,
{
    DomainBinding::new(DOMAIN_NAME, Box::new(domain), output)
}

/// Build the identity domain as a single-owned runtime binding.
///
/// # Errors
///
/// Returns an error when required JWT or Vault configuration is absent or invalid, session or
/// refresh TTLs violate their bounds, or the typed identity providers cannot be constructed.
pub async fn module(source: &impl IdentityModuleSource) -> anyhow::Result<DomainBinding> {
    let domain = wire_identity_from(
        source.identity_pg(),
        |name| source.config(name),
        source.vault_allow_http(),
    )?;
    Ok(bind(domain, DomainModuleResult::default()))
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

/// Integration-only typed identity constructor with injectable configuration and Vault HTTP policy.
///
/// `get` supplies `RSS_VAULT_ADDR`, `RSS_VAULT_TOKEN`, `RSS_VAULT_TRANSIT_MOUNT`,
/// `RSS_JWT_ISSUER`, `RSS_JWT_AUDIENCE`, `RSS_JWT_ES256_KEY_ID`, and
/// `RSS_JWT_ACCESS_TTL_SECS`; session and refresh TTL variables are optional and bounded.
/// `vault_allow_http` exists only for hermetic tests with a loopback mock Vault. Production callers
/// production generated module path is HTTPS-only.
///
/// # Errors
///
/// Returns an error when required configuration is absent or invalid, TTL bounds are violated, or
/// the Vault signer or JWT issuer cannot be constructed.
#[cfg(feature = "integration")]
pub(crate) fn wire_identity_with(
    deps: &SharedRuntimeDeps,
    get: impl Fn(&str) -> Option<String>,
    vault_allow_http: bool,
) -> anyhow::Result<IdentityDomain<VaultSigner>> {
    wire_identity_from(
        deps.pg.for_domain::<caps::Identity>(),
        get,
        vault_allow_http,
    )
}

fn wire_identity_from(
    identity_pg: PgDomainDeps<caps::Identity>,
    get: impl Fn(&str) -> Option<String>,
    vault_allow_http: bool,
) -> anyhow::Result<IdentityDomain<VaultSigner>> {
    let ttl = Duration::from_secs(identity_session_ttl_secs(|name| get(name))?);
    let refresh_ttl = Duration::from_secs(refresh_ttl_secs(|name| get(name))?);

    let credentials = Arc::from(DynCredentialRepo::new_box(identity_pg.credential_repo()));
    let lifecycle = Arc::from(DynSessionLifecycle::new_box(
        identity_pg.session_lifecycle(Box::new(SystemClock)),
    ));
    let roles_for_admin = Arc::from(DynRoleRepo::new_box(identity_pg.role_repo()));
    let roles_for_list = Arc::from(DynRoleRepo::new_box(identity_pg.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(identity_pg.policy_repo()));
    let resource_attrs = Arc::from(DynResourceAttributeRepo::new_box(
        identity_pg.resource_attribute_repo(),
    ));
    let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
        identity_pg.policy_lifecycle(Box::new(SystemClock)),
    ));
    let bindings = Arc::from(DynRoleBindingLifecycle::new_box(
        identity_pg.role_binding_lifecycle(Box::new(SystemClock)),
    ));

    let signer = Arc::new(build_vault_signer_with(|name| get(name), vault_allow_http)?);
    let issuer = Arc::new(
        authn::JwtIssuer::new(
            signer,
            Box::new(SystemClock),
            build_jwt_issuer_config(|name| get(name))?,
        )
        .map_err(|error| anyhow::anyhow!("jwt issuer config error: {error}"))?,
    );

    let refresh = Arc::new(RefreshService::new(
        DynRefreshTokenStore::new_box(identity_pg.refresh_token_store()),
        issuer,
        Box::new(SystemClock),
        refresh_ttl,
    ));
    let login = Arc::new(LoginService::new(
        credentials,
        lifecycle,
        Arc::clone(&refresh),
        Box::new(SystemClock),
        ttl,
    ));
    let rbac_admin = Arc::new(RbacAdminService::new(
        roles_for_admin,
        Arc::clone(&bindings),
        Box::new(SystemClock),
    ));
    let policy_manage = Arc::new(PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle,
        Box::new(SystemClock),
    ));
    Ok(IdentityDomain::new(IdentityDomainDeps {
        login,
        refresh,
        rbac_admin,
        policy_manage,
        roles: roles_for_list,
        bindings,
        policies,
        resource_attrs,
        clock: Arc::new(SystemClock),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bootstrap::compose_bindings;

    struct TestModuleSource {
        pg: postgres::PgRuntimeDeps,
    }

    impl sealed::Sealed for TestModuleSource {}

    impl IdentityModuleSource for TestModuleSource {
        fn identity_pg(&self) -> PgDomainDeps<caps::Identity> {
            self.pg.for_domain()
        }

        fn config(&self, name: &str) -> Option<String> {
            module_env(name)
        }

        fn vault_allow_http(&self) -> bool {
            true
        }
    }

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
        let source = TestModuleSource {
            pg: postgres::PgRuntimeDeps::for_module_test(),
        };
        module(&source).await
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_source_and_has_stable_empty_output() {
        let mut bindings = vec![test_binding().await.expect("identity module builds")];
        assert_eq!(bindings[0].name(), DOMAIN_NAME);

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
