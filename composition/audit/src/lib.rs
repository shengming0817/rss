//! Reusable audit wiring with mandatory postgres, MAC, key, and clock; no fallback path.

use std::sync::Arc;

use anyhow::Context as _;
use audit::AuditDomain;
use audit::ports::{AuditChainHasher, DynAuditAdminRepo, DynAuditReadRepo};
use bootstrap::{DomainBinding, DomainModuleResult};
use diport::Clock;
use postgres::{PgAuthAuditSink, PgDomainDeps, caps};
use primitives::{MacKey, MacVerifier};

const DOMAIN_NAME: &str = "audit";

/// Complete typed inputs; consuming this private-field value enforces one wiring path.
pub struct AuditModuleDeps<M> {
    pg: PgDomainDeps<caps::Audit>,
    mac: M,
    key: MacKey,
    clock: Arc<dyn Clock>,
}

impl<M> AuditModuleDeps<M> {
    /// Construct the complete audit composition inputs.
    #[must_use]
    pub fn new(pg: PgDomainDeps<caps::Audit>, mac: M, key: MacKey, clock: Arc<dyn Clock>) -> Self {
        Self {
            pg,
            mac,
            key,
            clock,
        }
    }
}

/// Build the audit domain and its lifecycle output as one owned binding.
/// # Errors
/// Returns an error when the audit chain key is weaker than 32 bytes.
pub fn wire<M>(deps: AuditModuleDeps<M>) -> anyhow::Result<DomainBinding>
where
    M: MacVerifier + Clone + Send + Sync + 'static,
{
    let AuditModuleDeps {
        pg,
        mac,
        key,
        clock,
    } = deps;

    let hasher = AuditChainHasher::new(mac.clone(), key.clone())
        .ok_or_else(weak_key_error)
        .context("audit chain key")?;
    let admin_hasher = AuditChainHasher::new(mac, key)
        .ok_or_else(weak_key_error)
        .context("audit admin chain key")?;
    let repo = Arc::new(pg.audit_repo(hasher));
    let read_repo: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(repo));
    let admin_repo = pg
        .audit_admin_repo(admin_hasher)
        .map(|repo| Arc::from(DynAuditAdminRepo::new_box(repo)));
    let domain =
        AuditDomain::<PgAuthAuditSink>::new(read_repo, admin_repo, pg.auth_audit_sink(), clock);

    Ok(DomainBinding::new(
        DOMAIN_NAME,
        Box::new(domain),
        DomainModuleResult::default(),
    ))
}

fn weak_key_error() -> anyhow::Error {
    anyhow::anyhow!("audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)")
}

/// Hermetic binding factory for assembly tests.
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;
    use primitives::{Mac, MacAlgorithm};

    #[derive(Clone)]
    struct TestMac;

    impl MacVerifier for TestMac {
        fn sign(&self, _key: &MacKey, _algorithm: MacAlgorithm, _message: &[u8]) -> Mac {
            Mac::from_bytes(vec![0x42; 32])
        }

        fn verify(
            &self,
            _key: &MacKey,
            _algorithm: MacAlgorithm,
            _message: &[u8],
            _tag: &Mac,
        ) -> bool {
            true
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::UNIX_EPOCH
        }
    }

    /// Build a hermetic audit binding through the production [`wire`] path.
    /// # Errors
    /// Returns an error if the fixed test key violates the production strength requirement.
    pub fn binding() -> anyhow::Result<DomainBinding> {
        wire(AuditModuleDeps::new(
            postgres::PgRuntimeDeps::for_module_test().for_domain(),
            TestMac,
            MacKey::from_bytes(vec![0x42; 32]),
            Arc::new(TestClock),
        ))
    }
}
