//! Consumer-owned, ephemeral AES-GCM key; no KMS, persistence or authentication policy.
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, DerivedAad, EncryptionMode, Plaintext,
    ProtectionContext,
};
use rss_request_context::TenantId;

struct EphemeralKey(aead::LessSafeKey);

impl Aead for EphemeralKey {
    fn seal(&self, plaintext: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AeadError::Seal)?;
        let mut ciphertext = plaintext.to_vec();
        let tag = self
            .0
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| AeadError::Seal)?;
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            "ephemeral-example",
            1,
            nonce.to_vec(),
            ciphertext,
            tag.as_ref().to_vec(),
            aad.coordinates().clone(),
        )
        .map_err(|_| AeadError::Seal)
    }

    fn open(
        &self,
        envelope: &CiphertextEnvelope,
        aad: &DerivedAad,
    ) -> Result<Plaintext, AeadError> {
        if envelope.alg() != CipherAlg::Aes256Gcm
            || envelope.mode() != EncryptionMode::Randomized
            || envelope.kid() != "ephemeral-example"
            || envelope.key_version() != 1
            || envelope.aad() != aad.coordinates()
        {
            return Err(AeadError::Open);
        }
        let nonce = aead::Nonce::try_assume_unique_for_key(envelope.nonce())
            .map_err(|_| AeadError::Open)?;
        let mut ciphertext = envelope.ciphertext().to_vec();
        ciphertext.extend_from_slice(envelope.tag());
        let plaintext = self
            .0
            .open_in_place(
                nonce,
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| AeadError::Open)?;
        Ok(Plaintext::new(plaintext.to_vec()))
    }
}

pub(super) fn run() -> anyhow::Result<()> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| AeadError::Seal)?;
    let key = EphemeralKey(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &bytes).map_err(|_| AeadError::Seal)?,
    ));
    // Fixture coordinates only; the application must authorize them before constructing context.
    let tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")?;
    let other = TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")?;
    let context = ProtectionContext::new(tenant, "db.dsn", "password", 1)?.derive();
    let envelope = key.seal(b"do-not-log", &context)?;
    let plaintext = key.open(&envelope, &context)?;
    assert_eq!(plaintext.expose(), b"do-not-log");
    assert!(!format!("{plaintext:?}").contains("do-not-log"));
    for (tenant, field) in [(other, "password"), (tenant, "other-field")] {
        let wrong = ProtectionContext::new(tenant, "db.dsn", field, 1)?.derive();
        assert!(matches!(key.open(&envelope, &wrong), Err(AeadError::Open)));
    }
    let corrupted = CiphertextEnvelope::new(
        envelope.alg(),
        envelope.mode(),
        envelope.kid(),
        envelope.key_version(),
        envelope.nonce().to_vec(),
        vec![0; envelope.ciphertext().len()],
        envelope.tag().to_vec(),
        envelope.aad().clone(),
    )?;
    assert!(matches!(
        key.open(&corrupted, &context),
        Err(AeadError::Open)
    ));
    Ok(())
}
