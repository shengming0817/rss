//! Authored-only encrypted dead-letter capsules; no transport authority is retained.
//! ref: RustCrypto/traits aead/src/lib.rs@master (authenticated additional data).
use crate::Error;
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::TenantId;
use rss_transactional_messaging::message::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    id: String,
    tenant: String,
    occurred_at: i64,
    domain: String,
    route: String,
    contract: String,
    version: String,
    schema: String,
    correlation: Option<String>,
    partition: Option<String>,
    causation: Option<String>,
    attributes: BTreeMap<String, String>,
    payload: Vec<u8>,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.id.zeroize();
        self.tenant.zeroize();
        self.domain.zeroize();
        self.route.zeroize();
        self.contract.zeroize();
        self.version.zeroize();
        self.schema.zeroize();
        self.correlation.zeroize();
        self.partition.zeroize();
        self.causation.zeroize();
        self.payload.zeroize();
        for (mut key, mut value) in std::mem::take(&mut self.attributes) {
            key.zeroize();
            value.zeroize();
        }
    }
}
impl Envelope {
    fn encode<P: AsRef<[u8]>>(message: &MessageEnvelope<P>) -> Result<String, Error> {
        let m = message.metadata();
        serde_json::to_string(&Self {
            id: message.id().as_str().into(),
            tenant: m.tenant_id().to_string(),
            occurred_at: m.occurred_at().unix_seconds(),
            domain: m.domain().as_str().into(),
            route: m.route().as_str().into(),
            contract: m.contract().id().as_str().into(),
            version: m.contract().version().to_string(),
            schema: m.contract().schema_digest().as_str().into(),
            correlation: m.correlation().map(Into::into),
            partition: m.partition().map(|p| p.key().as_str().into()),
            causation: m.causation().map(|id| id.as_str().into()),
            attributes: m.attributes().map(|(k, v)| (k.into(), v.into())).collect(),
            payload: message.payload().as_ref().to_vec(),
        })
        .map_err(|_| Error::Protection)
    }
    fn decode(raw: &str) -> Result<MessageEnvelope<Payload>, Error> {
        let mut value: Self = serde_json::from_str(raw).map_err(|_| Error::Protection)?;
        let invalid = |_| Error::Protection;
        let contract = ContractIdentity::new(
            ContractId::parse(&value.contract).map_err(invalid)?,
            ContractVersion::parse(&value.version).map_err(invalid)?,
            SchemaDigest::parse(&value.schema).map_err(invalid)?,
        );
        let required = AuthoredMessageMetadata::new(
            TenantId::parse(&value.tenant).map_err(|_| Error::Protection)?,
            Timepoint::try_from(value.occurred_at).map_err(|_| Error::Protection)?,
            MessagingDomain::parse(&value.domain).map_err(|_| Error::Protection)?,
            MessageRoute::parse(&value.route).map_err(|_| Error::Protection)?,
            contract,
        );
        let extensions = MessageMetadataExtensions::new(
            value
                .correlation
                .as_deref()
                .map(CorrelationId::parse)
                .transpose()
                .map_err(|_| Error::Protection)?,
            value
                .partition
                .as_deref()
                .map(PartitionKey::parse)
                .transpose()
                .map_err(|_| Error::Protection)?,
            value
                .causation
                .as_deref()
                .map(MessageId::parse)
                .transpose()
                .map_err(|_| Error::Protection)?,
            std::mem::take(&mut value.attributes),
        );
        Ok(MessageEnvelope::new(
            MessageId::parse(&value.id).map_err(|_| Error::Protection)?,
            MessageMetadata::new(required, extensions),
            Payload(Plaintext::new(std::mem::take(&mut value.payload))),
        ))
    }
}

use crate::DeadLetterId;
use rss_data_protection::{
    Aead, CipherAlg, CiphertextEnvelope, EncryptionMode, Plaintext, ProtectionContext,
};
use rss_transactional_messaging::inbox::ConsumerIdentity;
use zeroize::{Zeroize, Zeroizing};

/// Decrypted payload with zeroizing storage and redacted diagnostics.
#[derive(Debug)]
pub struct Payload(Plaintext);
impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        self.0.expose()
    }
}

/// Exact trusted durable context; providers derive it from verified consumer identity or authorized storage coordinates.
#[derive(Clone)]
pub struct CaptureContext {
    id: DeadLetterId,
    consumer: ConsumerIdentity,
    fingerprint: MessageFingerprint,
}
impl CaptureContext {
    /// Bind the provider's dead-letter identity to verified consumer facts.
    pub fn from_provider(
        id: DeadLetterId,
        consumer: ConsumerIdentity,
        fingerprint: MessageFingerprint,
    ) -> Self {
        Self {
            id,
            consumer,
            fingerprint,
        }
    }
    /// Dead-letter identity.
    pub const fn id(&self) -> DeadLetterId {
        self.id
    }
    /// Full tenant/message/group/contract identity.
    pub const fn consumer(&self) -> &ConsumerIdentity {
        &self.consumer
    }
    /// Original authored fingerprint.
    pub const fn fingerprint(&self) -> MessageFingerprint {
        self.fingerprint
    }
    fn aad(&self) -> Result<rss_data_protection::DerivedAad, Error> {
        let contract = self.consumer.contract();
        let coordinates = crate::model::hash(&[
            &self.id.to_string(),
            self.consumer.message_id().as_str(),
            self.consumer.group().as_str(),
            contract.id().as_str(),
            &contract.version().to_string(),
            contract.schema_digest().as_str(),
            &format!("{:x}", sha2::Sha256::digest(self.fingerprint.as_bytes())),
        ]);
        let key = coordinates
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ProtectionContext::authorized_maintenance(
            self.consumer.tenant_id(),
            &key,
            "rss.message.recovery.capsule",
            1,
        )
        .map(|context| context.derive())
        .map_err(|_| Error::Protection)
    }
    fn validate<P: AsRef<[u8]>>(&self, message: &MessageEnvelope<P>) -> Result<(), Error> {
        if message.metadata().tenant_id() != self.consumer.tenant_id()
            || message.id() != self.consumer.message_id()
            || message.metadata().contract() != self.consumer.contract()
            || MessageFingerprint::of(message) != self.fingerprint
        {
            return Err(Error::Protection);
        }
        Ok(())
    }
}
use sha2::Digest;

/// Bounded serialized ciphertext; Debug never exposes ciphertext or key references.
#[derive(Clone)]
pub struct Capsule(Vec<u8>);
impl std::fmt::Debug for Capsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Capsule(<redacted>)")
    }
}
impl Capsule {
    /// Rehydrate provider bytes; authentication happens only in `open` with trusted coordinates.
    pub fn from_provider(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
            Err(Error::Protection)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Opaque encrypted storage bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCipher {
    version: u8,
    key: String,
    key_version: u32,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

/// Seal authored facts, stripping all unverified transport data before encoding.
pub fn seal<K: Aead, P: AsRef<[u8]>>(
    key: &K,
    context: &CaptureContext,
    message: &MessageEnvelope<P>,
) -> Result<Capsule, Error> {
    context.validate(message)?;
    let plaintext = Zeroizing::new(Envelope::encode(message)?);
    if plaintext.len() > 4 * 1024 * 1024 {
        return Err(Error::Protection);
    }
    let aad = context.aad()?;
    let cipher = key
        .seal(plaintext.as_bytes(), &aad)
        .map_err(|_| Error::Protection)?;
    if cipher.alg() != CipherAlg::Aes256Gcm
        || cipher.mode() != EncryptionMode::Randomized
        || cipher.aad() != aad.coordinates()
    {
        return Err(Error::Protection);
    }
    let stored = StoredCipher {
        version: 1,
        key: cipher.kid().into(),
        key_version: cipher.key_version(),
        nonce: cipher.nonce().into(),
        ciphertext: cipher.ciphertext().into(),
        tag: cipher.tag().into(),
    };
    Capsule::from_provider(serde_json::to_vec(&stored).map_err(|_| Error::Protection)?)
}
/// Authenticate stored bytes against caller-derived context before reconstructing authored facts.
pub fn open<K: Aead>(
    key: &K,
    context: &CaptureContext,
    capsule: &Capsule,
) -> Result<MessageEnvelope<Payload>, Error> {
    let stored: StoredCipher =
        serde_json::from_slice(capsule.bytes()).map_err(|_| Error::Protection)?;
    if stored.version != 1 {
        return Err(Error::Protection);
    }
    let aad = context.aad()?;
    let cipher = CiphertextEnvelope::new(
        CipherAlg::Aes256Gcm,
        EncryptionMode::Randomized,
        &stored.key,
        stored.key_version,
        stored.nonce,
        stored.ciphertext,
        stored.tag,
        aad.coordinates().clone(),
    )
    .map_err(|_| Error::Protection)?;
    let plain = key.open(&cipher, &aad).map_err(|_| Error::Protection)?;
    if plain.expose().len() > 4 * 1024 * 1024 {
        return Err(Error::Protection);
    }
    let raw = std::str::from_utf8(plain.expose()).map_err(|_| Error::Protection)?;
    let message = Envelope::decode(raw)?;
    context.validate(&message)?;
    Ok(message)
}
