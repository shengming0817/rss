//! Reusable identity wiring with mandatory typed providers and no fallback path.

use std::sync::Arc;
use std::time::Duration;

use bootstrap::{DomainBinding, DomainModuleResult};
use diport::{Clock, Signer};
use identity::{
    IdentityDomain, IdentityDomainDeps, LoginService, PolicyManageService, RbacAdminService,
    RefreshService,
    ports::{
        DynCredentialRepo, DynPolicyLifecycle, DynPolicyRepo, DynRefreshTokenStore,
        DynResourceAttributeRepo, DynRoleBindingLifecycle, DynRoleReadRepo, DynSessionLifecycle,
    },
};
use postgres::{PgDomainDeps, caps};

const DOMAIN_NAME: &str = "identity";

pub struct IdentityModuleDeps<S> {
    pg: PgDomainDeps<caps::Identity>,
    signer: Arc<S>,
    clock: Arc<dyn Clock>,
    jwt: authn::JwtIssuerConfig,
    session_ttl: Duration,
    refresh_ttl: Duration,
}

impl<S> IdentityModuleDeps<S> {
    #[must_use]
    pub fn new(
        pg: PgDomainDeps<caps::Identity>,
        signer: Arc<S>,
        clock: Arc<dyn Clock>,
        jwt: authn::JwtIssuerConfig,
        session_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Self {
        Self {
            pg,
            signer,
            clock,
            jwt,
            session_ttl,
            refresh_ttl,
        }
    }
}

struct SharedClock(Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0.now()
    }
}

fn boxed_clock(clock: &Arc<dyn Clock>) -> Box<dyn Clock> {
    Box::new(SharedClock(Arc::clone(clock)))
}

/// Build the identity domain and its lifecycle output as one owned binding.
/// # Errors
/// Returns an error when the JWT issuer configuration is invalid.
pub fn wire<S>(deps: IdentityModuleDeps<S>) -> anyhow::Result<DomainBinding>
where
    S: Signer + Send + Sync + 'static,
{
    let IdentityModuleDeps {
        pg,
        signer,
        clock,
        jwt,
        session_ttl,
        refresh_ttl,
    } = deps;

    let credentials = Arc::from(DynCredentialRepo::new_box(pg.credential_repo()));
    let lifecycle = Arc::from(DynSessionLifecycle::new_box(
        pg.session_lifecycle(boxed_clock(&clock)),
    ));
    let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(pg.role_repo()));
    let roles_for_list = Arc::from(DynRoleReadRepo::new_box(pg.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(pg.policy_repo()));
    let resource_attrs = Arc::from(DynResourceAttributeRepo::new_box(
        pg.resource_attribute_repo(),
    ));
    let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
        pg.policy_lifecycle(boxed_clock(&clock)),
    ));
    let bindings = Arc::from(DynRoleBindingLifecycle::new_box(
        pg.role_binding_lifecycle(boxed_clock(&clock)),
    ));

    let issuer = Arc::new(
        authn::JwtIssuer::new(signer, boxed_clock(&clock), jwt)
            .map_err(|error| anyhow::anyhow!("jwt issuer config error: {error}"))?,
    );
    let refresh = Arc::new(RefreshService::new(
        DynRefreshTokenStore::new_box(pg.refresh_token_store()),
        issuer,
        boxed_clock(&clock),
        refresh_ttl,
    ));
    let login = Arc::new(LoginService::new(
        credentials,
        lifecycle,
        Arc::clone(&refresh),
        boxed_clock(&clock),
        session_ttl,
    ));
    let rbac_admin = Arc::new(RbacAdminService::new(
        roles_for_admin,
        Arc::clone(&bindings),
        boxed_clock(&clock),
    ));
    let policy_manage = Arc::new(PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle,
        boxed_clock(&clock),
    ));
    let domain = IdentityDomain::new(IdentityDomainDeps {
        login,
        refresh,
        rbac_admin,
        policy_manage,
        roles: roles_for_list,
        bindings,
        policies,
        resource_attrs,
        clock,
    });

    Ok(DomainBinding::new(
        DOMAIN_NAME,
        Box::new(domain),
        DomainModuleResult::default(),
    ))
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use diport::{Clock, SignRequest, Signature, Signer, SignerError};

    use super::{IdentityModuleDeps, wire};

    /// Deterministic signer used only to prove composition without a live Vault service.
    pub struct TestSigner;

    impl Signer for TestSigner {
        async fn sign(&self, _request: SignRequest) -> Result<Signature, SignerError> {
            Ok(Signature::new(vec![0x5a; 64]))
        }

        async fn shutdown(&self) -> Result<(), SignerError> {
            Ok(())
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        }
    }

    /// Construct complete hermetic identity composition inputs.
    #[must_use]
    pub fn deps() -> IdentityModuleDeps<TestSigner> {
        IdentityModuleDeps::new(
            postgres::PgRuntimeDeps::for_module_test().for_domain(),
            Arc::new(TestSigner),
            Arc::new(FixedClock),
            authn::JwtIssuerConfig {
                key: diport::KeyId::new("identity-composition-test-key"),
                alg: authn::JwtAlg::Es256,
                purpose: diport::SigningPurpose::new("auth.jwt.access"),
                issuer: "https://issuer.test".to_string(),
                audience: "rss".to_string(),
                ttl: Duration::from_secs(900),
            },
            Duration::from_secs(3_600),
            Duration::from_secs(30 * 24 * 60 * 60),
        )
    }

    /// Build a hermetic binding through the production [`wire`] entrypoint.
    /// # Errors
    /// Returns an error if the fixed JWT configuration is rejected.
    pub fn binding() -> anyhow::Result<bootstrap::DomainBinding> {
        wire(deps())
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityModuleDeps, test_support, wire};

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn test_support_binding_uses_the_public_wiring_path() {
        let deps: IdentityModuleDeps<test_support::TestSigner> = test_support::deps();
        let binding = wire(deps).expect("identity composition builds");
        assert_eq!(binding.name(), "identity");

        let binding = test_support::binding().expect("test-support binding builds");
        assert_eq!(binding.name(), "identity");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn invalid_jwt_configuration_fails_closed() {
        let mut deps = test_support::deps();
        deps.jwt.issuer.clear();
        let error = wire(deps).err().expect("empty issuer must fail");
        assert!(error.to_string().contains("jwt issuer config error"));
    }
}
