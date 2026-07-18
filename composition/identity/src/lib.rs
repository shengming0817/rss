//! Reusable identity wiring with mandatory typed providers and no fallback path.

use std::sync::Arc;
use std::time::Duration;

use bootstrap::{DomainBinding, DomainModuleResult};
use diport::{Clock, Signer};
use identity::{
    FederatedIdentityDomain, FederatedIdentityDomainDeps, IdentityDomain, IdentityDomainDeps,
    LoginService, PolicyManageService, RbacAdminService, RefreshService,
    ports::{
        DynCredentialRepo, DynPolicyLifecycle, DynPolicyRepo, DynRefreshTokenStore,
        DynResourceAttributeReadRepo, DynRoleBindingLifecycle, DynRoleBindingReadRepo,
        DynRoleReadRepo, DynSessionLifecycle,
    },
};
use postgres::{PgDomainDeps, caps};

const DOMAIN_NAME: &str = "identity";

pub struct IdentityModuleDeps<S> {
    pg: PgDomainDeps<caps::Identity>,
    signer: Arc<S>,
    clock: Arc<dyn Clock>,
    jwt: authn::JwtIssuerConfig<diport::RssAccessProfile>,
    session_ttl: Duration,
    refresh_ttl: Duration,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
}

impl<S> IdentityModuleDeps<S> {
    #[must_use]
    pub fn new(
        pg: PgDomainDeps<caps::Identity>,
        signer: Arc<S>,
        clock: Arc<dyn Clock>,
        jwt: authn::JwtIssuerConfig<diport::RssAccessProfile>,
        session_ttl: Duration,
        refresh_ttl: Duration,
        blocklist: Arc<secure::DigestPasswordBlocklist>,
    ) -> Self {
        Self {
            pg,
            signer,
            clock,
            jwt,
            session_ttl,
            refresh_ttl,
            blocklist,
        }
    }
}

/// Identity composition inputs for a Primary listener fixed to federated access tokens.
///
/// No signer, RSS issuer, refresh lifetime, session lifetime, or password blocklist can enter this
/// path, so local RSS session routes cannot be assembled accidentally.
pub struct FederatedIdentityModuleDeps {
    pg: PgDomainDeps<caps::Identity>,
    clock: Arc<dyn Clock>,
}

impl FederatedIdentityModuleDeps {
    #[must_use]
    pub fn new(pg: PgDomainDeps<caps::Identity>, clock: Arc<dyn Clock>) -> Self {
        Self { pg, clock }
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

struct CommonIdentityServices {
    rbac_admin: Arc<RbacAdminService>,
    policy_manage: Arc<PolicyManageService>,
    roles: Arc<DynRoleReadRepo<'static>>,
    binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
    policies: Arc<DynPolicyRepo<'static>>,
    resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
}

fn common_identity_services(
    pg: &PgDomainDeps<caps::Identity>,
    clock: &Arc<dyn Clock>,
) -> CommonIdentityServices {
    let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(pg.role_repo()));
    let roles_for_list = Arc::from(DynRoleReadRepo::new_box(pg.role_repo()));
    let policies = Arc::from(DynPolicyRepo::new_box(pg.policy_repo()));
    let resource_attribute_reads = Arc::from(DynResourceAttributeReadRepo::new_box(
        pg.resource_attribute_repo(),
    ));
    let policy_lifecycle = Arc::from(DynPolicyLifecycle::new_box(
        pg.policy_lifecycle(boxed_clock(clock)),
    ));
    let binding_lifecycle = Arc::from(DynRoleBindingLifecycle::new_box(
        pg.role_binding_lifecycle(boxed_clock(clock)),
    ));
    let binding_reads = Arc::from(DynRoleBindingReadRepo::new_box(pg.role_binding_read_repo()));
    let rbac_admin = Arc::new(RbacAdminService::new(
        roles_for_admin,
        binding_lifecycle,
        boxed_clock(clock),
    ));
    let policy_manage = Arc::new(PolicyManageService::new(
        Arc::clone(&policies),
        policy_lifecycle,
        boxed_clock(clock),
    ));
    CommonIdentityServices {
        rbac_admin,
        policy_manage,
        roles: roles_for_list,
        binding_reads,
        policies,
        resource_attribute_reads,
    }
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
        blocklist,
    } = deps;

    let credentials = Arc::from(DynCredentialRepo::new_box(pg.credential_repo()));
    let lifecycle = Arc::from(DynSessionLifecycle::new_box(
        pg.session_lifecycle(boxed_clock(&clock)),
    ));
    let common = common_identity_services(&pg, &clock);

    let issuer = Arc::new(
        authn::JwtIssuer::<diport::RssAccessProfile, _>::new(signer, boxed_clock(&clock), jwt)
            .map_err(|error| anyhow::anyhow!("jwt issuer config error: {error}"))?,
    );
    let refresh = Arc::new(RefreshService::new(
        DynRefreshTokenStore::new_box(pg.refresh_token_store()),
        issuer,
        boxed_clock(&clock),
        refresh_ttl,
    ));
    let password_policy = secure::PasswordPolicy::new(blocklist);
    let login = Arc::new(LoginService::new(
        credentials,
        lifecycle,
        Arc::clone(&refresh),
        password_policy,
        boxed_clock(&clock),
        session_ttl,
    ));
    let domain = IdentityDomain::new(IdentityDomainDeps {
        login,
        refresh,
        rbac_admin: common.rbac_admin,
        policy_manage: common.policy_manage,
        roles: common.roles,
        binding_reads: common.binding_reads,
        policies: common.policies,
        resource_attribute_reads: common.resource_attribute_reads,
        clock,
    });

    Ok(DomainBinding::new(
        DOMAIN_NAME,
        Box::new(domain),
        DomainModuleResult::default(),
    ))
}

/// Build the identity domain without RSS-local session issuance or mutation routes.
///
/// # Errors
/// Returns an error if the domain binding cannot be assembled.
pub fn wire_federated(deps: FederatedIdentityModuleDeps) -> anyhow::Result<DomainBinding> {
    let FederatedIdentityModuleDeps { pg, clock } = deps;
    let common = common_identity_services(&pg, &clock);
    let domain = FederatedIdentityDomain::new(FederatedIdentityDomainDeps {
        rbac_admin: common.rbac_admin,
        policy_manage: common.policy_manage,
        roles: common.roles,
        binding_reads: common.binding_reads,
        policies: common.policies,
        resource_attribute_reads: common.resource_attribute_reads,
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

    /// Fixed composition clock for hermetic profile wiring tests.
    pub struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
        }
    }

    /// Construct complete hermetic identity composition inputs.
    ///
    /// # Errors
    /// Returns an error if the embedded non-empty blocklist fixture is malformed.
    pub fn deps() -> anyhow::Result<IdentityModuleDeps<TestSigner>> {
        let blocklist = crypto::load_password_blocklist_from_reader(std::io::Cursor::new(
            include_bytes!("../../../deploy/password-blocklist.demo.sha256"),
        ))?;
        Ok(IdentityModuleDeps::new(
            postgres::PgRuntimeHandle::for_module_test().for_domain(),
            Arc::new(TestSigner),
            Arc::new(TestClock),
            authn::JwtIssuerConfig::rss_access(
                diport::KeyId::new("identity-composition-test-key"),
                diport::SigningPurpose::new("auth.jwt.access"),
                "https://issuer.test",
                "rss",
                Duration::from_secs(900),
            ),
            Duration::from_secs(3_600),
            Duration::from_secs(30 * 24 * 60 * 60),
            Arc::new(blocklist),
        ))
    }

    /// Build a hermetic binding through the production [`wire`] entrypoint.
    /// # Errors
    /// Returns an error if the fixed JWT configuration is rejected.
    pub fn binding() -> anyhow::Result<bootstrap::DomainBinding> {
        wire(deps()?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        FederatedIdentityModuleDeps, IdentityModuleDeps, test_support, wire, wire_federated,
    };

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn test_support_binding_uses_the_public_wiring_path() {
        let deps: IdentityModuleDeps<test_support::TestSigner> =
            test_support::deps().expect("test dependencies build");
        let binding = wire(deps).expect("identity composition builds");
        assert_eq!(binding.name(), "identity");

        let binding = test_support::binding().expect("test-support binding builds");
        assert_eq!(binding.name(), "identity");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn invalid_jwt_configuration_fails_closed() {
        let mut deps = test_support::deps().expect("test dependencies build");
        deps.jwt = authn::JwtIssuerConfig::rss_access(
            diport::KeyId::new("identity-composition-test-key"),
            diport::SigningPurpose::new("auth.jwt.access"),
            "",
            "rss",
            std::time::Duration::from_secs(900),
        );
        let error = wire(deps).err().expect("empty issuer must fail");
        assert!(error.to_string().contains("jwt issuer config error"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn federated_wiring_needs_no_signer_or_local_issuer_configuration() {
        let binding = wire_federated(FederatedIdentityModuleDeps::new(
            postgres::PgRuntimeHandle::for_module_test().for_domain(),
            Arc::new(test_support::TestClock),
        ))
        .expect("federated identity composition builds");
        assert_eq!(binding.name(), "identity");
    }
}
