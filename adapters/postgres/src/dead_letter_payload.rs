//! DLX v3 replay-capsule encryption codec.
//!
//! Payload and every persisted envelope-metadata value are serialized once and encrypted as one
//! authenticated plaintext. `tenantAuthority` is rejected at this boundary and is never part of
//! the capsule. Provenance remains in separately queryable, AAD-authenticated safe columns.

use std::sync::Arc;

use diport::key_provider::KeyProviderErrorKind;
use diport::{
    DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES, DynKeyProvider, EncryptOutput, KEY_TENANT_AUTHORITY,
    KeyProvider, KeyProviderError, KeyRef, RedactedBytes,
};
use eventexec::DlxHotKeyName;
use secure::{Plaintext, ProtectionContext};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use zeroize::Zeroize;

pub(crate) const DLX_REPLAY_CAPSULE_ENCODING: &str = "key-provider-v3";
const DLX_REPLAY_CAPSULE_FIELD: &str = "replay_capsule";
const DLX_REPLAY_CAPSULE_SCHEMA_VERSION: u32 = 3;
const DLX_REPLAY_CAPSULE_WIRE_VERSION: u64 = 3;

/// Explicit DLX hot-capsule protector. There is no plaintext production constructor.
#[derive(Clone)]
pub struct DlxPayloadProtector {
    provider: Arc<Mutex<Box<DynKeyProvider<'static>>>>,
    key_name: DlxHotKeyName,
}

impl DlxPayloadProtector {
    #[must_use]
    pub fn new(provider: Box<DynKeyProvider<'static>>, key_name: DlxHotKeyName) -> Self {
        Self {
            provider: Arc::new(Mutex::new(provider)),
            key_name,
        }
    }

    pub(crate) async fn encrypt(
        &self,
        ctx: DlxPayloadContext<'_>,
        payload: &[u8],
        metadata: &serde_json::Value,
    ) -> Result<ProtectedDlxCapsule, KeyProviderError> {
        let (plaintext, metadata_digest) = encode_replay_capsule(ctx, payload, metadata)?;
        let output = self
            .provider
            .lock()
            .await
            .encrypt(
                self.key_name.as_key_name().clone(),
                plaintext,
                ctx.derive_aad()?,
            )
            .await?;
        Ok(ProtectedDlxCapsule::from_encrypt_output(
            output,
            payload.len(),
            metadata_digest,
        ))
    }

    /// Decrypts to the zeroize-on-drop security type; callers never receive naked plaintext bytes.
    pub(crate) async fn decrypt_plaintext(
        &self,
        ctx: DlxPayloadContext<'_>,
        replay_capsule: &serde_json::Value,
        key_ref: &str,
    ) -> Result<Plaintext, KeyProviderError> {
        let ciphertext = ciphertext_from_json(replay_capsule)?;
        let key = KeyRef::parse(key_ref)
            .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))?;
        self.provider
            .lock()
            .await
            .decrypt(ciphertext, key, ctx.derive_aad()?)
            .await
    }

    pub(crate) async fn decrypt_replay_capsule(
        &self,
        ctx: DlxPayloadContext<'_>,
        replay_capsule: &serde_json::Value,
        key_ref: &str,
    ) -> Result<DecryptedReplayCapsule, KeyProviderError> {
        let plaintext = self.decrypt_plaintext(ctx, replay_capsule, key_ref).await?;
        decode_replay_capsule(&plaintext, ctx)
    }
}

pub(crate) struct ProtectedDlxCapsule {
    replay_capsule: serde_json::Value,
    key_ref: String,
    payload_len: i64,
    metadata_digest: [u8; 32],
}

impl ProtectedDlxCapsule {
    fn from_encrypt_output(
        output: EncryptOutput,
        payload_len: usize,
        metadata_digest: [u8; 32],
    ) -> Self {
        Self {
            replay_capsule: ciphertext_json(output.ciphertext()),
            key_ref: output.key().to_token(),
            payload_len: i64::try_from(payload_len).unwrap_or(i64::MAX),
            metadata_digest,
        }
    }

    pub(crate) fn replay_capsule(&self) -> &serde_json::Value {
        &self.replay_capsule
    }

    pub(crate) fn key_ref(&self) -> &str {
        &self.key_ref
    }

    pub(crate) fn payload_len(&self) -> i64 {
        self.payload_len
    }

    pub(crate) fn metadata_digest(&self) -> &[u8] {
        &self.metadata_digest
    }
}

/// Parsed replay data keeps the sensitive payload in a zeroize-on-drop wrapper.
pub(crate) struct DecryptedReplayCapsule {
    payload: Plaintext,
    metadata: SensitiveJson,
}

impl DecryptedReplayCapsule {
    pub(crate) fn into_parts(mut self) -> (Plaintext, SensitiveJson) {
        let payload = std::mem::replace(&mut self.payload, Plaintext::new(Vec::new()));
        let metadata = std::mem::replace(
            &mut self.metadata,
            SensitiveJson::new(serde_json::Value::Null),
        );
        (payload, metadata)
    }
}

/// JSON decoded from a hot capsule. serde_json's containers do not zeroize by default, so this
/// adapter-local owner recursively wipes string/key buffers on all success and error paths.
pub(crate) struct SensitiveJson(serde_json::Value);

impl SensitiveJson {
    pub(crate) fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &serde_json::Value {
        &self.0
    }

    /// Transfers the tree only to the replay transformation funnel, which immediately rewraps it
    /// before its next fallible operation.
    pub(crate) fn take(&mut self) -> serde_json::Value {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json(std::mem::take(&mut self.0));
    }
}

fn zeroize_json(value: serde_json::Value) {
    match value {
        serde_json::Value::String(mut value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json(value);
            }
        }
        serde_json::Value::Object(values) => {
            for (mut key, value) in values {
                key.zeroize();
                zeroize_json(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Mutable decode buffer that wipes partially-decoded bytes on every error path. Successful
/// ownership transfer moves the same allocation into a security wrapper without cloning it.
struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn push(&mut self, byte: u8) {
        self.0.push(byte);
    }

    fn into_plaintext(mut self) -> Plaintext {
        Plaintext::new(std::mem::take(&mut self.0))
    }

    fn into_redacted(mut self) -> RedactedBytes {
        RedactedBytes::new(std::mem::take(&mut self.0))
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        wipe_sensitive_bytes(&mut self.0);
    }
}

fn wipe_sensitive_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[derive(Clone, Copy)]
pub(crate) struct DlxPayloadContext<'a> {
    tenant: rss_request_context::TenantId,
    source_kind: &'a str,
    producer_domain: &'a str,
    consumer_domain: Option<&'a str>,
    contract_id: &'a str,
    topic: &'a str,
    consumer_group: Option<&'a str>,
    message_id: &'a str,
}

impl<'a> DlxPayloadContext<'a> {
    #[allow(clippy::too_many_arguments)]
    // reason: AAD v3 authenticates all eight coordinates as one complete security context.
    pub(crate) fn new(
        tenant: rss_request_context::TenantId,
        source_kind: &'a str,
        producer_domain: &'a str,
        consumer_domain: Option<&'a str>,
        contract_id: &'a str,
        topic: &'a str,
        consumer_group: Option<&'a str>,
        message_id: &'a str,
    ) -> Self {
        Self {
            tenant,
            source_kind,
            producer_domain,
            consumer_domain,
            contract_id,
            topic,
            consumer_group,
            message_id,
        }
    }

    fn record_key(&self) -> String {
        format!(
            "dead_letter/v3/{}/{}/{}/{}/{}/{}/{}",
            self.source_kind,
            self.producer_domain,
            self.consumer_domain.unwrap_or("_none"),
            self.contract_id,
            self.topic,
            self.consumer_group.unwrap_or("_none"),
            self.message_id
        )
    }

    fn provenance_wire(&self) -> DlxProvenanceWire<'a> {
        DlxProvenanceWire {
            consumer_domain: self.consumer_domain,
            consumer_group: self.consumer_group,
            contract_id: self.contract_id,
            message_id: self.message_id,
            producer_domain: self.producer_domain,
            source_kind: self.source_kind,
            tenant_id: self.tenant.to_string(),
            topic: self.topic,
        }
    }

    fn derive_aad(&self) -> Result<secure::DerivedAad, KeyProviderError> {
        ProtectionContext::authorized_maintenance(
            self.tenant,
            &self.record_key(),
            DLX_REPLAY_CAPSULE_FIELD,
            DLX_REPLAY_CAPSULE_SCHEMA_VERSION,
        )
        .map(|context| context.derive())
        .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DlxProvenanceWire<'a> {
    consumer_domain: Option<&'a str>,
    consumer_group: Option<&'a str>,
    contract_id: &'a str,
    message_id: &'a str,
    producer_domain: &'a str,
    source_kind: &'a str,
    tenant_id: String,
    topic: &'a str,
}

#[derive(serde::Serialize)]
struct DlxReplayCapsuleWire<'a> {
    metadata: &'a serde_json::Map<String, serde_json::Value>,
    payload: &'a [u8],
    provenance: DlxProvenanceWire<'a>,
    version: u64,
}

fn encode_replay_capsule(
    ctx: DlxPayloadContext<'_>,
    payload: &[u8],
    metadata: &serde_json::Value,
) -> Result<(Plaintext, [u8; 32]), KeyProviderError> {
    let metadata = metadata
        .as_object()
        .ok_or_else(|| rejected("DLX metadata must be an object"))?;
    if metadata.contains_key(KEY_TENANT_AUTHORITY) {
        return Err(rejected(
            "tenantAuthority is forbidden in DLX replay capsule",
        ));
    }
    let canonical_metadata = Plaintext::new(
        serde_json::to_vec(metadata)
            .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))?,
    );
    let metadata_digest: [u8; 32] = Sha256::digest(canonical_metadata.expose()).into();
    let encoded = Plaintext::new(
        serde_json::to_vec(&DlxReplayCapsuleWire {
            metadata,
            payload,
            provenance: ctx.provenance_wire(),
            version: DLX_REPLAY_CAPSULE_WIRE_VERSION,
        })
        .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))?,
    );
    if encoded.expose().len() > DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES {
        return Err(rejected("DLX replay capsule exceeds archiveability limit"));
    }
    Ok((encoded, metadata_digest))
}

fn decode_replay_capsule(
    plaintext: &Plaintext,
    ctx: DlxPayloadContext<'_>,
) -> Result<DecryptedReplayCapsule, KeyProviderError> {
    if plaintext.expose().len() > DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES {
        return Err(rejected("DLX replay capsule exceeds archiveability limit"));
    }
    let sensitive = SensitiveJson::new(
        serde_json::from_slice(plaintext.expose())
            .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))?,
    );
    let value = sensitive.expose();
    let object = value
        .as_object()
        .ok_or_else(|| rejected("invalid DLX replay capsule"))?;
    const TOP_LEVEL_FIELDS: [&str; 4] = ["metadata", "payload", "provenance", "version"];
    if object.len() != TOP_LEVEL_FIELDS.len()
        || object
            .keys()
            .any(|field| !TOP_LEVEL_FIELDS.contains(&field.as_str()))
    {
        return Err(rejected("unknown DLX replay capsule field"));
    }
    if value.get("version").and_then(serde_json::Value::as_u64)
        != Some(DLX_REPLAY_CAPSULE_WIRE_VERSION)
    {
        return Err(rejected("invalid DLX replay capsule version"));
    }
    if !provenance_matches(value.get("provenance"), ctx) {
        return Err(rejected("DLX replay capsule provenance mismatch"));
    }
    let metadata = value.get("metadata").and_then(serde_json::Value::as_object);
    let Some(metadata) = metadata else {
        return Err(rejected("missing DLX replay metadata"));
    };
    if metadata.contains_key(KEY_TENANT_AUTHORITY) {
        return Err(rejected("invalid DLX replay metadata"));
    }
    let metadata = object
        .get("metadata")
        .cloned()
        .ok_or_else(|| rejected("missing DLX replay metadata"))?;
    let payload = object
        .get("payload")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| rejected("missing DLX replay payload"))?;
    let mut decoded = SensitiveBytes::with_capacity(payload.len());
    for item in payload {
        let byte = item
            .as_u64()
            .and_then(|number| u8::try_from(number).ok())
            .ok_or_else(|| rejected("invalid DLX replay payload byte"))?;
        decoded.push(byte);
    }
    Ok(DecryptedReplayCapsule {
        payload: decoded.into_plaintext(),
        metadata: SensitiveJson::new(metadata),
    })
}

fn provenance_matches(value: Option<&serde_json::Value>, ctx: DlxPayloadContext<'_>) -> bool {
    let Some(value) = value.and_then(serde_json::Value::as_object) else {
        return false;
    };
    value.len() == 8
        && value
            .get("consumerDomain")
            .and_then(serde_json::Value::as_str)
            == ctx.consumer_domain
        && value
            .get("consumerGroup")
            .and_then(serde_json::Value::as_str)
            == ctx.consumer_group
        && value.get("contractId").and_then(serde_json::Value::as_str) == Some(ctx.contract_id)
        && value.get("messageId").and_then(serde_json::Value::as_str) == Some(ctx.message_id)
        && value
            .get("producerDomain")
            .and_then(serde_json::Value::as_str)
            == Some(ctx.producer_domain)
        && value.get("sourceKind").and_then(serde_json::Value::as_str) == Some(ctx.source_kind)
        && value.get("tenantId").and_then(serde_json::Value::as_str)
            == Some(ctx.tenant.to_string().as_str())
        && value.get("topic").and_then(serde_json::Value::as_str) == Some(ctx.topic)
}

pub(crate) fn validate_replay_capsule(
    plaintext: &Plaintext,
    ctx: DlxPayloadContext<'_>,
    expected_payload_len: i64,
    expected_metadata_digest: &[u8],
) -> Result<(), KeyProviderError> {
    let decoded = decode_replay_capsule(plaintext, ctx)?;
    let payload_len = i64::try_from(decoded.payload.expose().len())
        .map_err(|_| rejected("DLX payload length overflow"))?;
    let metadata_bytes = Plaintext::new(
        serde_json::to_vec(decoded.metadata.expose())
            .map_err(|error| KeyProviderError::new(KeyProviderErrorKind::Rejected, error))?,
    );
    let digest: [u8; 32] = Sha256::digest(metadata_bytes.expose()).into();
    if payload_len != expected_payload_len || digest.as_slice() != expected_metadata_digest {
        return Err(rejected("DLX replay capsule safe-column mismatch"));
    }
    Ok(())
}

pub(crate) fn ciphertext_json(ciphertext: &[u8]) -> serde_json::Value {
    serde_json::json!({"ciphertext": ciphertext})
}

fn ciphertext_from_json(value: &serde_json::Value) -> Result<RedactedBytes, KeyProviderError> {
    if value.get("bytes").is_some() || value.get("payload").is_some() {
        return Err(rejected("plaintext replay_capsule shape is forbidden"));
    }
    let bytes = value
        .get("ciphertext")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| rejected("missing ciphertext"))?;
    let mut decoded = SensitiveBytes::with_capacity(bytes.len());
    for item in bytes {
        let number = item
            .as_u64()
            .ok_or_else(|| rejected("invalid ciphertext byte"))?;
        decoded.push(u8::try_from(number).map_err(|_| rejected("ciphertext byte out of range"))?);
    }
    Ok(decoded.into_redacted())
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
    use diport::{EncryptOutput, KeyName, KeyProvider, KeyVersion};

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
                return Err(rejected("AAD mismatch"));
            }
            let plaintext = ciphertext[aad_bytes.len()..]
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
            DlxHotKeyName::try_new("dlx-test").expect("valid key name"),
        )
    }

    #[allow(clippy::expect_used)]
    fn test_context() -> DlxPayloadContext<'static> {
        DlxPayloadContext::new(
            rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                .expect("tenant"),
            "consumer",
            "identity",
            Some("audit"),
            "contract-a",
            "topic",
            Some("group-a"),
            "message-a",
        )
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn replay_capsule_v3_bytes_are_golden_and_authority_is_rejected() {
        let metadata = serde_json::json!({"correlation":"corr-1"});
        let (plaintext, _) = encode_replay_capsule(test_context(), &[0, 255], &metadata)
            .expect("valid replay capsule");
        assert_eq!(
            plaintext.expose(),
            br#"{"metadata":{"correlation":"corr-1"},"payload":[0,255],"provenance":{"consumerDomain":"audit","consumerGroup":"group-a","contractId":"contract-a","messageId":"message-a","producerDomain":"identity","sourceKind":"consumer","tenantId":"f47ac10b-58cc-4372-a567-0e02b2c3d479","topic":"topic"},"version":3}"#
        );

        let forbidden = serde_json::json!({KEY_TENANT_AUTHORITY:"secret"});
        assert!(encode_replay_capsule(test_context(), b"payload", &forbidden).is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn replay_capsule_rejects_unknown_top_level_fields_and_oversize_on_both_boundaries() {
        let (plaintext, _) = encode_replay_capsule(
            test_context(),
            b"payload",
            &serde_json::json!({"correlation":"corr-1"}),
        )
        .expect("valid replay capsule");
        let mut value: serde_json::Value =
            serde_json::from_slice(plaintext.expose()).expect("golden JSON");
        value
            .as_object_mut()
            .expect("capsule object")
            .insert("futureField".to_owned(), serde_json::Value::Bool(true));
        let with_unknown = Plaintext::new(serde_json::to_vec(&value).expect("serialize mutation"));
        assert!(decode_replay_capsule(&with_unknown, test_context()).is_err());

        let oversized_plaintext =
            Plaintext::new(vec![b'x'; DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES + 1]);
        assert!(decode_replay_capsule(&oversized_plaintext, test_context()).is_err());

        let oversized_metadata = serde_json::json!({
            "sensitive": "x".repeat(DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES)
        });
        assert!(encode_replay_capsule(test_context(), b"payload", &oversized_metadata).is_err());
    }

    #[test]
    fn replay_capsule_temporary_byte_wipe_covers_partial_error_buffers() {
        let mut bytes = *b"sensitive-partial-buffer";
        wipe_sensitive_bytes(&mut bytes);
        assert!(bytes.iter().all(|byte| *byte == 0));

        let invalid_payload = Plaintext::new(
            br#"{"metadata":{},"payload":[1,999],"provenance":{"consumerDomain":"audit","consumerGroup":"group-a","contractId":"contract-a","messageId":"message-a","producerDomain":"identity","sourceKind":"consumer","tenantId":"f47ac10b-58cc-4372-a567-0e02b2c3d479","topic":"topic"},"version":3}"#
                .to_vec(),
        );
        assert!(decode_replay_capsule(&invalid_payload, test_context()).is_err());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn aad_v3_binds_provenance_and_capsule_roundtrips() {
        let protector = test_protector();
        let tenant = rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("tenant");
        let ctx = test_context();
        let protected = protector
            .encrypt(
                ctx,
                b"payload",
                &serde_json::json!({"correlation":"corr-1"}),
            )
            .await
            .expect("encrypt");

        let tampered = DlxPayloadContext::new(
            tenant,
            "consumer",
            "identity",
            Some("billing"),
            "contract-a",
            "topic",
            Some("group-a"),
            "message-a",
        );
        assert!(
            protector
                .decrypt_plaintext(tampered, protected.replay_capsule(), protected.key_ref())
                .await
                .is_err()
        );

        let decoded = protector
            .decrypt_replay_capsule(ctx, protected.replay_capsule(), protected.key_ref())
            .await
            .expect("decrypt");
        let (payload, metadata) = decoded.into_parts();
        assert_eq!(payload.expose(), b"payload");
        assert_eq!(
            metadata.expose(),
            &serde_json::json!({"correlation":"corr-1"})
        );
    }
}
