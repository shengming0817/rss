use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, DerivedAad, EncryptionMode, Plaintext,
};
use rss_request_context::{Clock, Deadline, ExecutionTimer};
use rss_transactional_messaging::{
    inbox::{ConsumerGroup, ConsumerIdentity},
    message::*,
};
use rss_transactional_messaging_recovery::{DeadLetterId, protection::CaptureContext};
use std::{collections::BTreeMap, time::Duration};
pub struct Key(pub u8);
impl Aead for Key {
    fn seal(&self, plain: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &[self.0; 32])
            .map_err(|_| AeadError::Seal)?;
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AeadError::Seal)?;
        let mut bytes = plain.to_vec();
        let tag = aead::LessSafeKey::new(key)
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut bytes,
            )
            .map_err(|_| AeadError::Seal)?;
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            "fixture",
            1,
            nonce.to_vec(),
            bytes,
            tag.as_ref().to_vec(),
            aad.coordinates().clone(),
        )
        .map_err(|_| AeadError::Seal)
    }
    fn open(&self, cipher: &CiphertextEnvelope, aad: &DerivedAad) -> Result<Plaintext, AeadError> {
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, &[self.0; 32])
            .map_err(|_| AeadError::Open)?;
        let nonce: [u8; 12] = cipher.nonce().try_into().map_err(|_| AeadError::Open)?;
        let mut bytes = cipher.ciphertext().to_vec();
        bytes.extend(cipher.tag());
        let key = aead::LessSafeKey::new(key);
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut bytes,
            )
            .map_err(|_| AeadError::Open)?;
        Ok(Plaintext::new(plain.to_vec()))
    }
}
pub struct Timer;
#[allow(clippy::expect_used)] // reason: fixed test deadline.
impl Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected test clock reads the real monotonic source.
    pub fn new() -> Self {
        Self
    }
    pub fn cutoff(&self) -> Deadline {
        Deadline::from_timeout(self, Duration::from_secs(5)).expect("fixture cutoff")
    }
}
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: implementation of the injected test clock.
    fn now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }
}
impl ExecutionTimer for Timer {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(async move {
            tokio::time::sleep_until(deadline.instant().into()).await;
        })
        .await;
    }
}
#[allow(clippy::expect_used)] // reason: fixed authored message test fixtures.
pub fn message(id: &str) -> MessageEnvelope<Vec<u8>> {
    let contract = ContractIdentity::new(
        rss_contract::ContractId::from_static("orders.created"),
        rss_contract::ContractVersion::from_static_major(1),
        rss_contract::SchemaDigest::from_static(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
    );
    let authored = AuthoredMessageMetadata::new(
        tenant(),
        rss_contract::Timepoint::try_from(1700000000).expect("time"),
        MessagingDomain::parse("orders").expect("domain"),
        MessageRoute::parse("orders.created").expect("route"),
        contract,
    );
    MessageEnvelope::new(
        MessageId::parse(id).expect("id"),
        MessageMetadata::new(
            authored,
            MessageMetadataExtensions::new(
                None,
                Some(PartitionKey::parse("order-1").expect("partition")),
                None,
                BTreeMap::new(),
            ),
        ),
        b"secret-body".to_vec(),
    )
    .with_transport_context(TransportContext::new(
        Some("trace-secret".into()),
        Some("authority-secret".into()),
    ))
}
#[allow(clippy::expect_used)] // reason: fixed test tenant.
pub fn tenant() -> rss_request_context::TenantId {
    rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111").expect("tenant")
}
#[allow(clippy::expect_used)] // reason: fixed test consumer group.
pub fn context(message: &MessageEnvelope<Vec<u8>>) -> CaptureContext {
    CaptureContext::from_provider(
        DeadLetterId::new(),
        ConsumerIdentity::new(
            tenant(),
            ConsumerGroup::parse("orders").expect("group"),
            message.id().clone(),
            message.metadata().contract().clone(),
        ),
        MessageFingerprint::of(message),
    )
}
