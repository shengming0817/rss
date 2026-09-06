//! Saga-owned receipt protection. No stored bytes can mint a trusted context.
//! ref: RustCrypto/traits aead/src/lib.rs@master
use crate::integrity::{
    SagaReceiptFingerprint, SagaReceiptIntegrityKeyId, SagaReceiptIntegrityKeyring,
};
use crate::{Definition, EffectKey, Error, Phase, Scope};
use rss_data_protection::Plaintext;
use serde::{Deserialize, Serialize};
use std::future::Future;
use zeroize::Zeroizing;

/// Provider-owned ciphertext encoding and its exact key version reference.
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    key_ref: String,
    bytes: Vec<u8>,
}
impl Ciphertext {
    /// Validate bounded nonempty key reference and encrypted provider bytes. The provider owns its nonce/tag framing.
    pub fn new(key_ref: String, bytes: Vec<u8>) -> Result<Self, Error> {
        if key_ref.is_empty()
            || key_ref.len() > 1024
            || bytes.is_empty()
            || bytes.len() > 2 * 1024 * 1024
        {
            return Err(Error::new(crate::ErrorKind::Protection));
        }
        Ok(Self { key_ref, bytes })
    }
    /// Exact encryption key version/reference needed by the trusted provider.
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }
    /// Encrypted provider payload, including its provider-owned nonce/tag representation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ciphertext(<redacted>)")
    }
}
/// The expected scope is constructed only by the executor, independently of stored metadata.
pub struct ReceiptContext {
    scope: Scope,
    canonical: Vec<u8>,
    components: Vec<Vec<u8>>,
    attempt: u32,
    seq: u64,
}
impl ReceiptContext {
    /// Expected tenant derived by the executor, independent of stored ciphertext metadata.
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.scope.tenant()
    }
    /// Exact v1 authenticated bytes. Providers must supply all these bytes unchanged to AEAD.
    pub fn canonical_aad(&self) -> &[u8] {
        &self.canonical
    }
    pub(crate) fn new(
        scope: Scope,
        definition: &Definition,
        step: usize,
        attempt: u32,
        seq: u64,
    ) -> Result<Self, Error> {
        let spec = definition
            .steps()
            .get(step)
            .ok_or(Error::new(crate::ErrorKind::Integrity))?;
        let key = definition.effect_key(scope, step, Phase::Forward)?;
        let identity = definition.identity();
        let tenant = scope.tenant().to_string();
        let id = scope.id().to_string();
        let version = identity.version().to_string();
        let fields = [
            tenant.as_bytes(),
            id.as_bytes(),
            definition.owner().as_bytes(),
            identity.contract().as_str().as_bytes(),
            version.as_bytes(),
            identity.schema().as_str().as_bytes(),
            identity.generation().as_str().as_bytes(),
            spec.name().as_bytes(),
            key.as_bytes(),
            spec.receipt_schema().as_bytes(),
        ];
        let mut canonical = b"rss-saga-receipt-aad-v1".to_vec();
        for field in fields {
            push(&mut canonical, field, 4);
        }
        push(&mut canonical, &1u16.to_be_bytes(), 4);
        let components = vec![
            b"rss.saga-receipt.content.v1".to_vec(),
            tenant.into_bytes(),
            scope.id().as_bytes().to_vec(),
            definition.owner().as_bytes().to_vec(),
            identity.contract().as_str().as_bytes().to_vec(),
            identity.version().to_string().as_bytes().to_vec(),
            identity.schema().as_str().as_bytes().to_vec(),
            identity.generation().as_str().as_bytes().to_vec(),
            spec.name().as_bytes().to_vec(),
            key.as_bytes().to_vec(),
            spec.receipt_schema().as_bytes().to_vec(),
            1u16.to_be_bytes().to_vec(),
            attempt.to_be_bytes().to_vec(),
            seq.to_be_bytes().to_vec(),
        ];
        Ok(Self {
            scope,
            canonical,
            components,
            attempt,
            seq,
        })
    }
    fn content(&self, plaintext: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::new());
        for field in &self.components {
            push(&mut bytes, field, 8);
        }
        push(&mut bytes, plaintext, 8);
        bytes
    }
}
fn push(target: &mut Vec<u8>, bytes: &[u8], width: usize) {
    let len = (bytes.len() as u64).to_be_bytes();
    target.extend_from_slice(&len[8 - width..]);
    target.extend_from_slice(bytes);
}
/// Trusted application cryptography adapter; AAD is mandatory and comes from the executor.
pub trait SagaReceiptProtector: Send + Sync {
    /// Encrypt with the exact executor-derived AAD and an explicit key reference. Return authenticated ciphertext, never plaintext.
    fn seal(
        &self,
        plaintext: &[u8],
        context: &ReceiptContext,
    ) -> impl Future<Output = Result<Ciphertext, Error>> + Send;
    /// Authenticate ciphertext and its key/format using the expected AAD; fail closed on any mismatch and return zeroizing plaintext.
    fn open(
        &self,
        ciphertext: &Ciphertext,
        context: &ReceiptContext,
    ) -> impl Future<Output = Result<Plaintext, Error>> + Send;
}
#[derive(Clone, Serialize, Deserialize)]
/// Opaque encrypted receipt and integrity metadata. Deserialization does not authenticate it.
pub struct ProtectedReceipt {
    ciphertext: Ciphertext,
    key_id: String,
    digest: Vec<u8>,
    aad: Vec<u8>,
    format: u16,
    attempt: u32,
    seq: u64,
}
impl ProtectedReceipt {
    /// Forward intent attempt authenticated by this receipt.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    /// Exact forward completion sequence authenticated by this receipt.
    pub fn completed_seq(&self) -> u64 {
        self.seq
    }
}
/// Saga-owned keyed integrity and mandatory application-supplied authenticated encryption.
pub struct ReceiptProtection<P> {
    provider: P,
    integrity: SagaReceiptIntegrityKeyring,
}
impl<P: SagaReceiptProtector> ReceiptProtection<P> {
    /// Require an authenticated-encryption provider and current/previous integrity keys; no plaintext fallback exists.
    pub const fn new(provider: P, integrity: SagaReceiptIntegrityKeyring) -> Self {
        Self {
            provider,
            integrity,
        }
    }
    pub(crate) async fn seal(
        &self,
        plaintext: Plaintext,
        context: &ReceiptContext,
    ) -> Result<ProtectedReceipt, Error> {
        if plaintext.expose().len() > 1024 * 1024 {
            return Err(Error::new(crate::ErrorKind::Protection));
        }
        let message = context.content(plaintext.expose());
        let fingerprint = self.integrity.current(&[&message]);
        let ciphertext = self
            .provider
            .seal(plaintext.expose(), context)
            .await
            .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        Ok(ProtectedReceipt {
            ciphertext,
            key_id: fingerprint.key_id().as_str().into(),
            digest: fingerprint.as_bytes().to_vec(),
            aad: context.canonical.clone(),
            format: 1,
            attempt: context.attempt,
            seq: context.seq,
        })
    }
    pub(crate) async fn open(
        &self,
        receipt: &ProtectedReceipt,
        context: &ReceiptContext,
    ) -> Result<Plaintext, Error> {
        if receipt.aad != context.canonical
            || receipt.format != 1
            || receipt.attempt != context.attempt
            || receipt.seq != context.seq
        {
            return Err(Error::new(crate::ErrorKind::Protection));
        }
        let key = SagaReceiptIntegrityKeyId::parse(receipt.key_id.clone())
            .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        let fingerprint = SagaReceiptFingerprint::from_stored(key, receipt.digest.clone())
            .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        let plaintext = self
            .provider
            .open(&receipt.ciphertext, context)
            .await
            .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        if !self
            .integrity
            .verify(&[&context.content(plaintext.expose())], &fingerprint)
        {
            return Err(Error::new(crate::ErrorKind::Protection));
        }
        Ok(plaintext)
    }
}
/// Phase-specific, executor-minted effect context. Constructors are intentionally private.
#[derive(Debug, Clone)]
pub struct EffectContext {
    scope: Scope,
    step: String,
    phase: Phase,
    key: EffectKey,
}
impl EffectContext {
    pub(crate) fn new(
        scope: Scope,
        definition: &Definition,
        step: usize,
        phase: Phase,
    ) -> Result<Self, Error> {
        Ok(Self {
            scope,
            step: definition
                .steps()
                .get(step)
                .ok_or(Error::new(crate::ErrorKind::Integrity))?
                .name()
                .into(),
            phase,
            key: definition.effect_key(scope, step, phase)?,
        })
    }
    /// Executor-authorized tenant and instance for this admitted effect.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    /// Definition-owned step name, unchanged across retries and recovery.
    pub fn step(&self) -> &str {
        &self.step
    }
    /// Forward or compensation phase, with a separate stable effect key.
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Pass this unchanged to the external provider for every retry and probe.
    pub fn idempotency_key(&self) -> &EffectKey {
        &self.key
    }
}

impl std::fmt::Debug for ProtectedReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedReceipt(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn historical_wire_vectors_are_unchanged() -> Result<(), Error> {
        let identity = crate::Identity::new(
            rss_contract::ContractId::from_static("orders.checkout"),
            rss_contract::ContractVersion::from_static_major(1),
            rss_contract::SchemaDigest::from_static(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            crate::ActionGeneration::parse(&format!("sha256:{}", "b".repeat(64)))?,
        );
        let definition = Definition::new(
            "orders",
            identity,
            vec![crate::StepSpec::new(
                "reserve",
                "receipt.v1",
                "reserve",
                "release",
                2,
            )?],
        )?;
        let tenant = rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")
            .map_err(|_| Error::new(crate::ErrorKind::Definition))?;
        let context =
            ReceiptContext::new(Scope::new(tenant, uuid::Uuid::nil()), &definition, 0, 3, 9)?;
        assert_eq!(
            context.canonical_aad(),
            include_bytes!("../tests/fixtures/receipt-aad-v1.bin")
        );
        let plaintext = serde_json_canonicalizer::to_vec(&serde_json::json!({"z":2,"a":1}))
            .map_err(|_| Error::new(crate::ErrorKind::Integrity))?;
        let content = context.content(&plaintext);
        assert_eq!(
            content.as_slice(),
            include_bytes!("../tests/fixtures/receipt-content-v1.bin")
        );
        let key = crate::VersionedSagaReceiptIntegrityKey::from_bytes(
            crate::SagaReceiptIntegrityKeyId::parse("integrity-v1")
                .map_err(|_| Error::new(crate::ErrorKind::Protection))?,
            vec![13; 32],
        )
        .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        let ring = crate::SagaReceiptIntegrityKeyring::new(key, vec![])
            .map_err(|_| Error::new(crate::ErrorKind::Protection))?;
        let fingerprint = ring.current(&[&content]);
        let hex: String = fingerprint
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "7b36e4a6b637970555ae1dc147272c1efafcb5ee85a50da073db1d51f34fee45"
        );
        Ok(())
    }
}
