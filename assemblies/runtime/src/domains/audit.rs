//! Audit domain wiring.

use std::sync::Arc;

use anyhow::Context as _;
use audit::AuditDomain;
use audit::ports::{AuditChainHasher, DynAuditReadRepo};
use base64::Engine as _;
use bootstrap::{Domain, DomainBinding, DomainModuleResult};
use crypto::RustCryptoMacVerifier;
use postgres::{PgAuthAuditSink, PgDomainDeps, caps};
use primitives::MacKey;

use crate::{SharedRuntimeDeps, SystemClock};

const DOMAIN_NAME: &str = "audit";
const AUDIT_CHAIN_KEY_ENV: &str = "RSS_AUDIT_CHAIN_KEY_B64URL";

mod sealed {
    pub trait Sealed {}
}

/// Typed provider seam for the audit module factory.
///
/// The trait is sealed: production uses [`SharedRuntimeDeps`], while this crate's tests inject a
/// lazy postgres capability and deterministic key configuration into the same public [`module`]
/// entrypoint.
#[doc(hidden)]
pub trait AuditModuleSource: sealed::Sealed {
    fn audit_pg(&self) -> PgDomainDeps<caps::Audit>;
    fn config(&self, name: &str) -> Option<String>;
}

impl sealed::Sealed for SharedRuntimeDeps {}

impl AuditModuleSource for SharedRuntimeDeps {
    fn audit_pg(&self) -> PgDomainDeps<caps::Audit> {
        self.pg.for_domain()
    }

    fn config(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

fn bind<D>(domain: D, output: DomainModuleResult) -> DomainBinding
where
    D: Domain,
{
    DomainBinding::new(DOMAIN_NAME, Box::new(domain), output)
}

/// Build the audit domain as a single-owned runtime binding.
///
/// # Errors
///
/// Returns an error when the audit chain key is missing, malformed, or weaker than 32 bytes.
pub async fn module(source: &impl AuditModuleSource) -> anyhow::Result<DomainBinding> {
    let domain = wire_audit_from(source.audit_pg(), |name| source.config(name))?;
    Ok(bind(domain, DomainModuleResult::default()))
}

/// Build the production keyed-HMAC audit chain hasher from injected configuration.
///
/// `RSS_AUDIT_CHAIN_KEY_B64URL` is mandatory and must decode to at least 32 bytes. Errors mention
/// only the variable name and validation class; key material is never included.
///
/// # Errors
///
/// Returns an error when the key is absent, not valid unpadded base64url, or too short.
pub(crate) fn build_audit_hasher(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<AuditChainHasher<RustCryptoMacVerifier>> {
    let encoded = get(AUDIT_CHAIN_KEY_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {AUDIT_CHAIN_KEY_ENV}"))?;
    let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .with_context(|| format!("{AUDIT_CHAIN_KEY_ENV} not valid base64url"))?;
    AuditChainHasher::new(RustCryptoMacVerifier, MacKey::from_bytes(key_bytes)).ok_or_else(|| {
        anyhow::anyhow!("audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)")
    })
}

/// Wire the typed audit domain using the postgres audit capability projection.
///
/// The domain receives only `PgDomainDeps<caps::Audit>`-derived repositories, so it cannot obtain
/// identity/settings repositories or a raw pool. Both scoped and optional admin repositories use
/// independently constructed hashers from the same required chain-key configuration.
///
/// # Errors
///
/// Returns an error when the audit chain key is missing, malformed, or weaker than 32 bytes.
pub fn wire_audit(deps: &SharedRuntimeDeps) -> anyhow::Result<AuditDomain<PgAuthAuditSink>> {
    wire_audit_from(deps.pg.for_domain(), |name| std::env::var(name).ok())
}

fn wire_audit_from(
    audit_deps: PgDomainDeps<caps::Audit>,
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<AuditDomain<PgAuthAuditSink>> {
    let hasher = build_audit_hasher(|name| get(name)).context("audit chain key")?;
    let repo = Arc::new(audit_deps.audit_repo(hasher));
    let read_repo: Arc<DynAuditReadRepo<'static>> = Arc::from(DynAuditReadRepo::new_box(repo));
    let admin_repo = build_audit_hasher(get)
        .context("audit admin chain key")
        .map(|hasher| {
            audit_deps
                .audit_admin_repo(hasher)
                .map(|repo| Arc::from(audit::ports::DynAuditAdminRepo::new_box(repo)))
        })?;
    Ok(AuditDomain::new(
        read_repo,
        admin_repo,
        audit_deps.auth_audit_sink(),
        Arc::new(SystemClock),
    ))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use bootstrap::compose_bindings;

    struct TestModuleSource {
        pg: postgres::PgRuntimeDeps,
        encoded_key: String,
    }

    impl sealed::Sealed for TestModuleSource {}

    impl AuditModuleSource for TestModuleSource {
        fn audit_pg(&self) -> PgDomainDeps<caps::Audit> {
            self.pg.for_domain()
        }

        fn config(&self, name: &str) -> Option<String> {
            (name == AUDIT_CHAIN_KEY_ENV).then(|| self.encoded_key.clone())
        }
    }

    pub(in crate::domains) async fn test_binding() -> anyhow::Result<DomainBinding> {
        let source = TestModuleSource {
            pg: postgres::PgRuntimeDeps::for_module_test(),
            encoded_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42_u8; 32]),
        };
        module(&source).await
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_source_and_has_stable_empty_output() {
        let mut bindings = vec![test_binding().await.expect("audit module builds")];
        assert_eq!(bindings[0].name(), DOMAIN_NAME);

        let (_, output) = compose_bindings(&mut bindings).expect("audit domain composes");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }

    #[test]
    fn build_audit_hasher_missing_key_fails_fast() {
        let result = build_audit_hasher(|_| None);
        assert!(matches!(&result, Err(error) if error.to_string().contains(AUDIT_CHAIN_KEY_ENV)));
    }

    #[test]
    fn build_audit_hasher_invalid_base64_fails_fast() {
        let get = |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| "!!not-b64!!".to_string());
        assert!(build_audit_hasher(get).is_err());
    }

    #[test]
    fn build_audit_hasher_weak_key_fails_fast() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 16]);
        let get = move |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| encoded.clone());
        assert!(
            matches!(&build_audit_hasher(get), Err(error) if error.to_string().contains("at least 32 bytes"))
        );
    }

    #[test]
    fn build_audit_hasher_valid_32_byte_key_succeeds() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
        let get = move |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| encoded.clone());
        assert!(build_audit_hasher(get).is_ok());
    }
}
