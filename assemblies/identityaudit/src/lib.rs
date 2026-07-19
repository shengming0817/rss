//! Identity + audit demo/test assembly: no launch/transport; generated wiring and capabilities agree.
//! ref: oxidecomputer/omicron nexus/src/lib.rs@3298185e6cb3f6934a581122101e52988dc81895

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use postgres::PgRuntimeHandle;
use primitives::MacKey;

#[path = "generated/modules_gen.rs"]
mod modules_gen;
#[path = "generated/providers_gen.rs"]
mod providers_gen;
const _: () = assert!(!providers_gen::PROVIDER_CATALOG.is_empty());
pub use modules_gen::{DOMAIN_LISTENER_BINDINGS, PROVIDER_OUTPUT_BINDINGS};

const DEMO_JWT_ISSUER: &str = "https://identityaudit.demo.invalid";
const DEMO_JWT_AUDIENCE: &str = "rss-identityaudit-demo";
const DEMO_JWT_KEY_ID: &str = "identityaudit-demo-es256";
const DEMO_JWT_ACCESS_TTL: Duration = Duration::from_secs(15 * 60);
const DEMO_SESSION_TTL: Duration = Duration::from_secs(60 * 60);
const DEMO_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub struct SystemClock;

impl diport::Clock for SystemClock {
    fn now(&self) -> SystemTime {
        // reason: assembly-root production clock — only sanctioned direct system-clock read.
        #[allow(clippy::disallowed_methods)]
        SystemTime::now()
    }
}

pub struct SharedRuntimeDeps {
    pg: PgRuntimeHandle,
    signer: Arc<vault::VaultSigner>,
    _pdp: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
    audit_chain_key: MacKey,
}

impl SharedRuntimeDeps {
    #[must_use]
    pub fn new(
        pg: PgRuntimeHandle,
        signer: Arc<vault::VaultSigner>,
        pdp: Arc<oidc::OidcProvider<diport::RssAccessProfile>>,
        audit_chain_key: MacKey,
    ) -> Self {
        require_pdp(pdp.as_ref());
        require_active_domains();
        Self {
            pg,
            signer,
            _pdp: pdp,
            audit_chain_key,
        }
    }
}

async fn wire_domains(deps: &SharedRuntimeDeps) -> anyhow::Result<Vec<bootstrap::DomainBinding>> {
    modules_gen::wire_domains(deps).await
}

const _: () = {
    let _ = wire_domains;
};

fn require_pdp<P: diport::Pdp + ?Sized>(_provider: &P) {}

fn require_active_domains() {
    fn require_domain<D: bootstrap::Domain>() {}
    require_domain::<identity::IdentityDomain<vault::VaultSigner>>();
    require_domain::<audit::AuditDomain<postgres::PgAuthAuditSink>>();
}

mod domains {
    pub(crate) mod identity {
        use std::sync::Arc;

        use bootstrap::DomainBinding;

        use crate::{
            DEMO_JWT_ACCESS_TTL, DEMO_JWT_AUDIENCE, DEMO_JWT_ISSUER, DEMO_JWT_KEY_ID,
            DEMO_REFRESH_TTL, DEMO_SESSION_TTL, SharedRuntimeDeps, SystemClock,
        };

        pub(crate) async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
            let blocklist = crypto::load_password_blocklist_from_reader(std::io::Cursor::new(
                include_bytes!("../../../deploy/password-blocklist.demo.sha256"),
            ))?;
            identity_composition::wire(identity_composition::IdentityModuleDeps::new(
                deps.pg.for_domain(),
                Arc::clone(&deps.signer),
                Arc::new(SystemClock),
                authn::JwtIssuerConfig::rss_access(
                    diport::KeyId::new(DEMO_JWT_KEY_ID),
                    diport::SigningPurpose::new("auth.jwt.access"),
                    DEMO_JWT_ISSUER,
                    DEMO_JWT_AUDIENCE,
                    DEMO_JWT_ACCESS_TTL,
                ),
                DEMO_SESSION_TTL,
                DEMO_REFRESH_TTL,
                Arc::new(blocklist),
            ))
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::DomainBinding;

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                identity_composition::test_support::binding()
            }
        }
    }

    pub(crate) mod audit {
        use std::sync::Arc;

        use bootstrap::DomainBinding;

        use crate::{SharedRuntimeDeps, SystemClock};

        pub(crate) async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
            audit_composition::wire(audit_composition::AuditModuleDeps::new(
                deps.pg.for_domain(),
                crypto::RustCryptoMacVerifier,
                deps.audit_chain_key.clone(),
                Arc::new(SystemClock),
            ))
        }

        #[cfg(test)]
        pub(crate) mod tests {
            use bootstrap::DomainBinding;

            pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
                audit_composition::test_support::binding()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bootstrap::compose_bindings;

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn generated_modules_wire_identity_and_audit_in_manifest_order() {
        let mut bindings = crate::modules_gen::wire_test_domains()
            .await
            .expect("generated identity/audit bindings build");
        assert_eq!(
            bindings
                .iter()
                .map(bootstrap::DomainBinding::name)
                .collect::<Vec<_>>(),
            ["identity", "audit"]
        );
        let (_, output) = compose_bindings(&mut bindings).expect("identity/audit domains compose");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }
}
