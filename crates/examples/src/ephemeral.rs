//! Consumer-owned ephemeral AES-GCM; example hosts supply fresh key bytes and identity.
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use rss_data_protection::{
    Aead, AeadError, CipherAlg, CiphertextEnvelope, DerivedAad, EncryptionMode, Plaintext,
};

pub struct EphemeralKey {
    key: aead::LessSafeKey,
    kid: &'static str,
}
impl EphemeralKey {
    pub fn from_bytes(bytes: &[u8; 32], kid: &'static str) -> Result<Self, AeadError> {
        Ok(Self {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, bytes).map_err(|_| AeadError::Seal)?,
            ),
            kid,
        })
    }
}

impl Aead for EphemeralKey {
    fn seal(&self, plaintext: &[u8], aad: &DerivedAad) -> Result<CiphertextEnvelope, AeadError> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| AeadError::Seal)?;
        let mut ciphertext = plaintext.to_vec();
        let tag = self
            .key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| AeadError::Seal)?;
        CiphertextEnvelope::new(
            CipherAlg::Aes256Gcm,
            EncryptionMode::Randomized,
            self.kid,
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
            || envelope.kid() != self.kid
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
            .key
            .open_in_place(
                nonce,
                aead::Aad::from(aad.as_canonical_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| AeadError::Open)?;
        Ok(Plaintext::new(plaintext.to_vec()))
    }
}
