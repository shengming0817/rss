//! DLX payload encryption codec for `dead_letter.original_entry`.

use std::sync::Arc;

use diport::key_provider::KeyProviderErrorKind;
use diport::{
    DynKeyProvider, EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef, RedactedBytes,
};
use secure::{Plaintext, ProtectionContext};
use tokio::sync::Mutex;

pub(crate) const DLX_ORIGINAL_ENTRY_ENCODING: &str = "key-provider-v1";
const DLX_ORIGINAL_ENTRY_FIELD: &str = "original_entry";
const DLX_ORIGINAL_ENTRY_SCHEMA_VERSION: u32 = 1;

/// Explicit DLX payload protector. There is no plaintext production constructor.
#[derive(Clone)]
pub struct DlxPayloadProtector {
    provider: Arc<Mutex<Box<DynKeyProvider<'static>>>>,
    key_name: KeyName,
}

impl DlxPayloadProtector {
    #[must_use]
    pub fn new(provider: Box<DynKeyProvider<'static>>, key_name: KeyName) -> Self {
        Self {
            provider: Arc::new(Mutex::new(provider)),
            key_name,
        }
    }

    pub(crate) async fn encrypt(
        &self,
        ctx: DlxPayloadContext<'_>,
        payload: &[u8],
    ) -> Result<ProtectedDlxPayload, KeyProviderError> {
        let aad = ctx.derive_aad()?;
        let output = self
            .provider
            .lock()
            .await
            .encrypt(self.key_name.clone(), Plaintext::new(payload.to_vec()), aad)
            .await?;
        Ok(ProtectedDlxPayload::from_encrypt_output(
            output,
            payload.len(),
        ))
    }

    pub(crate) async fn decrypt(
        &self,
        ctx: DlxPayloadContext<'_>,
        original_entry: &serde_json::Value,
        key_ref: &str,
    ) -> Result<Vec<u8>, KeyProviderError> {
        let ciphertext = ciphertext_from_json(original_entry)?;
        let key = KeyRef::parse(key_ref)
            .map_err(|e| KeyProviderError::new(KeyProviderErrorKind::Rejected, e))?;
        let plaintext = self
            .provider
            .lock()
            .await
            .decrypt(RedactedBytes::new(ciphertext), key, ctx.derive_aad()?)
            .await?;
        Ok(plaintext.expose().to_vec())
    }
}

pub(crate) struct ProtectedDlxPayload {
    original_entry: serde_json::Value,
    key_ref: String,
    payload_len: i64,
}

impl ProtectedDlxPayload {
    fn from_encrypt_output(output: EncryptOutput, payload_len: usize) -> Self {
        Self {
            original_entry: ciphertext_json(output.ciphertext()),
            key_ref: output.key().to_token(),
            payload_len: i64::try_from(payload_len).unwrap_or(i64::MAX),
        }
    }

    pub(crate) fn original_entry(&self) -> &serde_json::Value {
        &self.original_entry
    }

    pub(crate) fn key_ref(&self) -> &str {
        &self.key_ref
    }

    pub(crate) fn payload_len(&self) -> i64 {
        self.payload_len
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DlxPayloadContext<'a> {
    tenant: vocab::TenantId,
    source_kind: &'a str,
    domain: &'a str,
    contract_id: &'a str,
    topic: &'a str,
    consumer_group: Option<&'a str>,
    message_id: &'a str,
}

impl<'a> DlxPayloadContext<'a> {
    pub(crate) fn new(
        tenant: vocab::TenantId,
        source_kind: &'a str,
        domain: &'a str,
        contract_id: &'a str,
        topic: &'a str,
        consumer_group: Option<&'a str>,
        message_id: &'a str,
    ) -> Self {
        Self {
            tenant,
            source_kind,
            domain,
            contract_id,
            topic,
            consumer_group,
            message_id,
        }
    }

    fn record_key(&self) -> String {
        format!(
            "dead_letter/{}/{}/{}/{}/{}/{}",
            self.source_kind,
            self.domain,
            self.contract_id,
            self.topic,
            self.consumer_group.unwrap_or("_none"),
            self.message_id
        )
    }

    fn derive_aad(&self) -> Result<secure::DerivedAad, KeyProviderError> {
        ProtectionContext::authorized_maintenance(
            self.tenant,
            &self.record_key(),
            DLX_ORIGINAL_ENTRY_FIELD,
            DLX_ORIGINAL_ENTRY_SCHEMA_VERSION,
        )
        .map(|ctx| ctx.derive())
        .map_err(|e| KeyProviderError::new(KeyProviderErrorKind::Rejected, e))
    }
}

pub(crate) fn ciphertext_json(ciphertext: &[u8]) -> serde_json::Value {
    let bytes_arr: Vec<serde_json::Value> = ciphertext
        .iter()
        .map(|&b| serde_json::Value::Number(b.into()))
        .collect();
    serde_json::json!({"ciphertext": bytes_arr})
}

fn ciphertext_from_json(value: &serde_json::Value) -> Result<Vec<u8>, KeyProviderError> {
    if value.get("bytes").is_some() {
        return Err(rejected("plaintext original_entry shape is forbidden"));
    }
    let bytes = value
        .get("ciphertext")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| rejected("missing ciphertext"))?;
    let mut decoded = Vec::with_capacity(bytes.len());
    for item in bytes {
        let n = item
            .as_u64()
            .ok_or_else(|| rejected("invalid ciphertext byte"))?;
        decoded.push(u8::try_from(n).map_err(|_| rejected("ciphertext byte out of range"))?);
    }
    Ok(decoded)
}

fn rejected(message: &'static str) -> KeyProviderError {
    KeyProviderError::new(
        KeyProviderErrorKind::Rejected,
        std::io::Error::other(message),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use diport::key_provider::KeyProviderErrorKind;
    use diport::{EncryptOutput, KeyProvider, KeyProviderError, KeyVersion};

    #[derive(Clone)]
    pub(crate) struct TestKeyProvider;

    impl KeyProvider for TestKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            plaintext: Plaintext,
            aad: secure::DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            let mut ciphertext = aad.as_canonical_bytes().to_vec();
            ciphertext.extend(plaintext.expose().iter().map(|byte| byte ^ 0xA5));
            Ok(EncryptOutput::new(
                ciphertext,
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            ciphertext: RedactedBytes,
            _key: KeyRef,
            aad: secure::DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            let ciphertext = ciphertext.into_bytes();
            let aad_bytes = aad.as_canonical_bytes();
            if !ciphertext.starts_with(aad_bytes) {
                return Err(KeyProviderError::new(
                    KeyProviderErrorKind::Rejected,
                    std::io::Error::other("AAD mismatch"),
                ));
            }
            let plaintext: Vec<u8> = ciphertext[aad_bytes.len()..]
                .iter()
                .copied()
                .map(|byte| byte ^ 0xA5)
                .collect();
            Ok(Plaintext::new(plaintext))
        }

        async fn rewrap(
            &self,
            _ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Err(KeyProviderError::new(
                KeyProviderErrorKind::Forbidden,
                std::io::Error::other("not used"),
            ))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    pub(crate) fn test_protector() -> DlxPayloadProtector {
        DlxPayloadProtector::new(
            DynKeyProvider::new_box(TestKeyProvider),
            KeyName::try_new("dlx-test").expect("valid key name"),
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn plaintext_shape_is_rejected() {
        let protector = test_protector();
        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let ctx = DlxPayloadContext::new(tenant, "consumer", "d", "c", "t", Some("g"), "m");
        let err = protector
            .decrypt(ctx, &serde_json::json!({"bytes":[1,2,3]}), "dlx-test:1")
            .await
            .expect_err("plaintext shape must fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn aad_binds_contract_id_and_consumer_group() {
        let protector = test_protector();
        let tenant =
            vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let ctx =
            DlxPayloadContext::new(tenant, "consumer", "d", "contract-a", "t", Some("g-a"), "m");
        let protected = protector
            .encrypt(ctx, b"payload")
            .await
            .expect("encrypt with original aad");

        let contract_tampered =
            DlxPayloadContext::new(tenant, "consumer", "d", "contract-b", "t", Some("g-a"), "m");
        let err = protector
            .decrypt(
                contract_tampered,
                protected.original_entry(),
                protected.key_ref(),
            )
            .await
            .expect_err("contract id tamper must fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);

        let group_tampered =
            DlxPayloadContext::new(tenant, "consumer", "d", "contract-a", "t", Some("g-b"), "m");
        let err = protector
            .decrypt(
                group_tampered,
                protected.original_entry(),
                protected.key_ref(),
            )
            .await
            .expect_err("consumer group tamper must fail");
        assert_eq!(err.kind(), KeyProviderErrorKind::Rejected);

        let plaintext = protector
            .decrypt(ctx, protected.original_entry(), protected.key_ref())
            .await
            .expect("original aad decrypts");
        assert_eq!(plaintext, b"payload");
    }
}
