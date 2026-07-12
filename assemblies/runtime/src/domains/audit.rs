//! Runtime-specific audit configuration and composition delegation.

use std::sync::Arc;

use anyhow::Context as _;
use audit::ports::AuditChainHasher;
use audit_composition::{AuditModuleDeps, wire};
use base64::Engine as _;
use bootstrap::DomainBinding;
use crypto::RustCryptoMacVerifier;
use primitives::MacKey;

use crate::{SharedRuntimeDeps, SystemClock};

const AUDIT_CHAIN_KEY_ENV: &str = "RSS_AUDIT_CHAIN_KEY_B64URL";

/// Build the audit domain as a single-owned runtime binding.
///
/// # Errors
///
/// Returns an error when the audit chain key is missing, malformed, or weaker than 32 bytes.
pub async fn module(deps: &SharedRuntimeDeps) -> anyhow::Result<DomainBinding> {
    let key = build_audit_key(|name| std::env::var(name).ok())?;
    wire(AuditModuleDeps::new(
        deps.pg.for_domain(),
        RustCryptoMacVerifier,
        key,
        Arc::new(SystemClock),
    ))
}

/// Decode the production keyed-HMAC audit chain key from injected configuration.
///
/// `RSS_AUDIT_CHAIN_KEY_B64URL` is mandatory and must decode to at least 32 bytes. Errors mention
/// only the variable name and validation class; key material is never included.
///
/// # Errors
///
/// Returns an error when the key is absent, not valid unpadded base64url, or too short.
pub(crate) fn build_audit_key(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<MacKey> {
    let encoded = get(AUDIT_CHAIN_KEY_ENV)
        .ok_or_else(|| anyhow::anyhow!("missing required env var: {AUDIT_CHAIN_KEY_ENV}"))?;
    let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .with_context(|| format!("{AUDIT_CHAIN_KEY_ENV} not valid base64url"))?;
    if key_bytes.len() < 32 {
        anyhow::bail!("audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)");
    }
    Ok(MacKey::from_bytes(key_bytes))
}

/// Build a keyed hasher for runtime event-consumer wiring from the same fail-closed key parser.
///
/// # Errors
///
/// Returns an error when the key is absent, malformed, or weaker than 32 bytes.
pub(crate) fn build_audit_hasher(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<AuditChainHasher<RustCryptoMacVerifier>> {
    let key = build_audit_key(get)?;
    AuditChainHasher::new(RustCryptoMacVerifier, key).ok_or_else(|| {
        anyhow::anyhow!("audit chain key must be at least 32 bytes (weak key, see audit-ledger.md)")
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bootstrap::compose_bindings;

    pub(crate) async fn test_binding() -> anyhow::Result<DomainBinding> {
        wire(AuditModuleDeps::new(
            postgres::PgRuntimeHandle::for_module_test().for_domain(),
            RustCryptoMacVerifier,
            MacKey::from_bytes(vec![0x42; 32]),
            Arc::new(SystemClock),
        ))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn module_executes_hermetic_composition_and_has_stable_empty_output() {
        let mut bindings = vec![test_binding().await.expect("audit module builds")];
        assert_eq!(bindings[0].name(), "audit");

        let (_, output) = compose_bindings(&mut bindings).expect("audit domain composes");
        assert!(bindings.is_empty());
        assert!(output.probes.is_empty());
        assert!(output.resources.is_empty());
        assert!(output.workers.is_empty());
    }

    #[test]
    fn build_audit_key_missing_key_fails_fast() {
        let result = build_audit_key(|_| None);
        assert!(matches!(&result, Err(error) if error.to_string().contains(AUDIT_CHAIN_KEY_ENV)));
    }

    #[test]
    fn build_audit_key_invalid_base64_fails_fast() {
        let get = |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| "!!not-b64!!".to_string());
        assert!(build_audit_key(get).is_err());
    }

    #[test]
    fn build_audit_key_weak_key_fails_fast() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 16]);
        let get = move |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| encoded.clone());
        assert!(
            matches!(&build_audit_key(get), Err(error) if error.to_string().contains("at least 32 bytes"))
        );
    }

    #[test]
    fn build_audit_key_valid_32_byte_key_succeeds() {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42_u8; 32]);
        let get = move |name: &str| (name == AUDIT_CHAIN_KEY_ENV).then(|| encoded.clone());
        assert!(build_audit_key(get).is_ok());
    }
}
