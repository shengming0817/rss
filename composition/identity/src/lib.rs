//! Reusable identity wiring with mandatory typed providers and no fallback path.

use std::sync::Arc;
use std::time::Duration;

use bootstrap::{DomainBinding, DomainModuleResult};
use diport::{Clock, Signer};
use identity::{
    AuthGrantServices, CredentialSecurityService, FederatedIdentityDomain,
    FederatedIdentityDomainDeps, IdentityDomain, IdentityDomainDeps, LoginService,
    PolicyManageService, RbacAdminService,
    ports::{
        DynAccountSecurityReadRepo, DynAuthGrantValidator, DynCredentialRepo, DynPolicyLifecycle,
        DynPolicyRepo, DynResourceAttributeReadRepo, DynRoleBindingLifecycle,
        DynRoleBindingReadRepo, DynRoleReadRepo,
    },
};
use postgres::{PgDomainDeps, caps};

const DOMAIN_NAME: &str = "identity";

/// Closed RSS-local token and grant lifetimes captured once by an assembly root.
///
/// Keeping these values together prevents composition roots from passing loose strings and
/// durations through their shared infrastructure bag.
pub struct IdentityRuntimeConfig {
    jwt_key_id: diport::KeyId,
    jwt_issuer: String,
    jwt_audience: String,
    jwt_access_ttl: Duration,
    auth_grant_ttl: Duration,
    refresh_ttl: Duration,
}

impl IdentityRuntimeConfig {
    #[must_use]
    pub fn new(
        jwt_key_id: diport::KeyId,
        jwt_issuer: impl Into<String>,
        jwt_audience: impl Into<String>,
        jwt_access_ttl: Duration,
        auth_grant_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Self {
        Self {
            jwt_key_id,
            jwt_issuer: jwt_issuer.into(),
            jwt_audience: jwt_audience.into(),
            jwt_access_ttl,
            auth_grant_ttl,
            refresh_ttl,
        }
    }

    /// Rebuild the sealed RSS access-token issuer input for one domain wiring pass.
    pub fn jwt_issuer_config(
        &self,
    ) -> Result<authn::JwtIssuerConfig<diport::RssAccessProfile>, authn::KeyRingError> {
        Ok(authn::JwtIssuerConfig::rss_access(
            authn::SigningKeyRing::single(self.jwt_key_id.clone())?,
            diport::SigningPurpose::new("auth.jwt.access"),
            &self.jwt_issuer,
            &self.jwt_audience,
            self.jwt_access_ttl,
        ))
    }

    #[must_use]
    pub fn jwt_key_id(&self) -> &str {
        self.jwt_key_id.as_str()
    }

    #[must_use]
    pub const fn auth_grant_ttl(&self) -> Duration {
        self.auth_grant_ttl
    }

    #[must_use]
    pub const fn refresh_ttl(&self) -> Duration {
        self.refresh_ttl
    }
}

pub struct IdentityModuleDeps<S> {
    pg: PgDomainDeps<caps::Identity>,
    signer: Arc<S>,
    clock: Arc<dyn Clock>,
    jwt: authn::JwtIssuerConfig<diport::RssAccessProfile>,
    auth_grant_ttl: Duration,
    refresh_ttl: Duration,
    blocklist: Arc<secure::DigestPasswordBlocklist>,
    pseudonym_keys: Arc<secure::PseudonymKeyRing>,
}

impl<S> IdentityModuleDeps<S> {
    #[must_use]
    pub fn new(
        pg: PgDomainDeps<caps::Identity>,
        signer: Arc<S>,
        clock: Arc<dyn Clock>,
        jwt: authn::JwtIssuerConfig<diport::RssAccessProfile>,
        auth_grant_ttl: Duration,
        refresh_ttl: Duration,
        blocklist: Arc<secure::DigestPasswordBlocklist>,
        pseudonym_keys: Arc<secure::PseudonymKeyRing>,
    ) -> Self {
        Self {
            pg,
            signer,
            clock,
            jwt,
            auth_grant_ttl,
            refresh_ttl,
            blocklist,
            pseudonym_keys,
        }
    }
}

/// Identity composition inputs for a Primary listener fixed to federated access tokens.
///
/// No signer, RSS issuer, AuthGrant/refresh lifetime, or password blocklist can enter this path, so
/// RSS-local login and refresh mutation routes cannot be assembled accidentally.
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

/// Build the mandatory request-time RSS grant fence from the same identity capability bundle as
/// login and refresh. The returned service exposes only the read-only validation port.
#[must_use]
pub fn access_grant_validation_service(
    pg: &PgDomainDeps<caps::Identity>,
    clock: &Arc<dyn Clock>,
) -> Arc<identity::AuthGrantValidationService> {
    Arc::new(identity::AuthGrantValidationService::new(
        DynAuthGrantValidator::new_arc(pg.auth_grant_validator()),
        boxed_clock(clock),
    ))
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
        auth_grant_ttl,
        refresh_ttl,
        blocklist,
        pseudonym_keys,
    } = deps;

    let credentials = Arc::from(DynCredentialRepo::new_box(pg.credential_repo()));
    let account_security_reads = DynAccountSecurityReadRepo::new_box(pg.account_security_repo());
    let common = common_identity_services(&pg, &clock);

    let issuer = Arc::new(
        authn::JwtIssuer::<diport::RssAccessProfile, _>::new(signer, boxed_clock(&clock), jwt)
            .map_err(|error| anyhow::anyhow!("jwt issuer config error: {error}"))?,
    );
    let auth_grant_provider =
        pg.auth_grant_provider(boxed_clock(&clock), Arc::clone(&pseudonym_keys));
    let auth_grants = AuthGrantServices::from_provider(
        auth_grant_provider,
        account_security_reads,
        issuer,
        boxed_clock(&clock),
        refresh_ttl,
    );
    let refresh = auth_grants.refresh_service();
    let account_reactivation_lifecycle = pg.account_reactivation_lifecycle();
    let password_policy = secure::PasswordPolicy::new(blocklist);
    let credential_security = Arc::new(CredentialSecurityService::new_with_shared_lifecycle(
        Arc::clone(&credentials),
        auth_grants.lifecycle(),
        DynAccountSecurityReadRepo::new_box(pg.account_security_repo()),
        auth_grants.security_lifecycle(),
        account_reactivation_lifecycle,
        password_policy,
        boxed_clock(&clock),
    ));
    let login = Arc::new(LoginService::new(
        credentials,
        auth_grants,
        boxed_clock(&clock),
        auth_grant_ttl,
    ));
    let domain = IdentityDomain::new(IdentityDomainDeps {
        login,
        refresh,
        credential_security,
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

/// Build the identity domain without RSS-local login, AuthGrant issuance, or refresh mutation routes.
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

    fn test_pseudonym_keys() -> Arc<secure::PseudonymKeyRing> {
        let key =
            secure::RedactionHashKey::from_bytes(vec![0x42; 32]).expect("valid pseudonym key");
        Arc::new(
            secure::PseudonymKeyRing::new(
                secure::VersionedPseudonymKey::new(
                    secure::PseudonymKeyId::new(std::num::NonZeroU16::MIN),
                    key,
                ),
                Vec::new(),
            )
            .expect("valid pseudonym key ring"),
        )
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
                authn::SigningKeyRing::single(diport::KeyId::new("identity-composition-test-key"))?,
                diport::SigningPurpose::new("auth.jwt.access"),
                "https://issuer.test",
                "rss",
                Duration::from_secs(900),
            ),
            Duration::from_secs(3_600),
            Duration::from_secs(30 * 24 * 60 * 60),
            Arc::new(blocklist),
            test_pseudonym_keys(),
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
            authn::SigningKeyRing::single(diport::KeyId::new("identity-composition-test-key"))
                .expect("non-empty signing key id"),
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
