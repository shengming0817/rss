//! Versioned keyed fingerprints for protected Saga receipts.
//!
//! This module owns the HMAC construction and rotation window. Callers provide an ordered set of
//! canonical receipt identity components; the implementation length-prefixes every component and
//! zeroizes the assembled message after use.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq as _};
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"rss.saga-receipt.integrity.v1";
const SHA256_BYTES: usize = 32;
const KEY_ID_MAX_BYTES: usize = 64;
const KEY_MIN_BYTES: usize = 32;

/// Stable non-secret identifier for one Saga receipt integrity key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SagaReceiptIntegrityKeyId(Box<str>);

impl SagaReceiptIntegrityKeyId {
    /// Parse the durable key id used alongside a receipt fingerprint.
    pub fn parse(raw: impl Into<String>) -> Result<Self, SagaReceiptIntegrityError> {
        let raw = raw.into();
        if raw.is_empty()
            || raw.len() > KEY_ID_MAX_BYTES
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(SagaReceiptIntegrityError::InvalidKeyId);
        }
        Ok(Self(raw.into_boxed_str()))
    }

    /// Durable text representation.
    pub const fn as_str(&self) -> &str {
        &self.0
    }
}

/// One zeroized HMAC key paired with its durable rotation identifier.
pub struct VersionedSagaReceiptIntegrityKey {
    id: SagaReceiptIntegrityKeyId,
    key: Zeroizing<Vec<u8>>,
}

impl VersionedSagaReceiptIntegrityKey {
    /// Pair a durable rotation identifier with zeroized HMAC key material.
    ///
    /// The identifier is persisted beside fingerprints and must be unique within a keyring. The
    /// key remains owned by this value and is never exposed; [`SagaReceiptIntegrityKeyring::new`]
    /// enforces the identifier invariant when the key enters a rotation window.
    pub fn from_bytes(
        id: SagaReceiptIntegrityKeyId,
        key: impl Into<Vec<u8>>,
    ) -> Result<Self, SagaReceiptIntegrityError> {
        let key = Zeroizing::new(key.into());
        if key.len() < KEY_MIN_BYTES {
            return Err(SagaReceiptIntegrityError::KeyTooShort);
        }
        Ok(Self { id, key })
    }
}

impl std::fmt::Debug for VersionedSagaReceiptIntegrityKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedSagaReceiptIntegrityKey")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Current write key plus the bounded previous-key verification window.
pub struct SagaReceiptIntegrityKeyring {
    current: VersionedSagaReceiptIntegrityKey,
    previous: Vec<VersionedSagaReceiptIntegrityKey>,
}

impl SagaReceiptIntegrityKeyring {
    /// Build a bounded rotation window with one write key and zero or more verification-only keys.
    ///
    /// `current` signs all new fingerprints. `previous` preserves read compatibility during key
    /// rotation and is never used for writes. Every durable key id must be unique across the full
    /// window so one stored id cannot select ambiguous key material.
    pub fn new(
        current: VersionedSagaReceiptIntegrityKey,
        previous: Vec<VersionedSagaReceiptIntegrityKey>,
    ) -> Result<Self, SagaReceiptIntegrityError> {
        for (index, key) in previous.iter().enumerate() {
            if key.id == current.id || previous[..index].iter().any(|prior| prior.id == key.id) {
                return Err(SagaReceiptIntegrityError::DuplicateKeyId);
            }
        }
        Ok(Self { current, previous })
    }

    /// Sign canonical ordered components with the current key.
    pub fn current(&self, components: &[&[u8]]) -> SagaReceiptFingerprint {
        fingerprint(&self.current, components)
    }

    /// Verify a stored fingerprint with its exact current/previous key id in constant time.
    pub fn verify(&self, components: &[&[u8]], candidate: &SagaReceiptFingerprint) -> bool {
        let mut verified = Choice::from(0);
        for key in self.keys() {
            let id_matches = constant_time_key_id_eq(&key.id, &candidate.key_id);
            let expected = fingerprint(key, components);
            let digest_matches = expected.digest.ct_eq(&candidate.digest);
            verified |= id_matches & digest_matches;
        }
        verified.into()
    }

    fn keys(&self) -> impl Iterator<Item = &VersionedSagaReceiptIntegrityKey> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }
}

impl std::fmt::Debug for SagaReceiptIntegrityKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SagaReceiptIntegrityKeyring")
            .field("current_id", &self.current.id)
            .field("previous_key_count", &self.previous.len())
            .finish()
    }
}

/// Durable keyed fingerprint. Equality is intentionally available only through the keyring.
pub struct SagaReceiptFingerprint {
    key_id: SagaReceiptIntegrityKeyId,
    digest: [u8; SHA256_BYTES],
}

impl SagaReceiptFingerprint {
    /// Rehydrate a fixed-width stored fingerprint for keyring verification.
    pub fn from_stored(
        key_id: SagaReceiptIntegrityKeyId,
        digest: Vec<u8>,
    ) -> Result<Self, SagaReceiptIntegrityError> {
        let digest = digest
            .try_into()
            .map_err(|_| SagaReceiptIntegrityError::InvalidDigestLength)?;
        Ok(Self { key_id, digest })
    }

    /// Durable rotation id that must be persisted alongside [`Self::as_bytes`].
    ///
    /// Verification accepts this id only when it exactly matches one key in the bounded keyring;
    /// it is metadata and never exposes the associated HMAC key material.
    pub const fn key_id(&self) -> &SagaReceiptIntegrityKeyId {
        &self.key_id
    }

    /// Opaque fixed-width bytes for durable storage. Never log this value.
    pub const fn as_bytes(&self) -> &[u8; SHA256_BYTES] {
        &self.digest
    }
}

impl std::fmt::Debug for SagaReceiptFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SagaReceiptFingerprint")
            .field("key_id", &self.key_id)
            .field("digest", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SagaReceiptIntegrityError {
    #[error("saga receipt integrity key too short")]
    KeyTooShort,
    #[error("saga receipt integrity key id is invalid")]
    InvalidKeyId,
    #[error("saga receipt integrity key ids must be unique")]
    DuplicateKeyId,
    #[error("saga receipt integrity digest length is invalid")]
    InvalidDigestLength,
}

fn fingerprint(
    key: &VersionedSagaReceiptIntegrityKey,
    components: &[&[u8]],
) -> SagaReceiptFingerprint {
    let mut message = Zeroizing::new(Vec::new());
    push_length_prefixed(&mut message, CONTEXT);
    for component in components {
        push_length_prefixed(&mut message, component);
    }
    let mut mac = match Hmac::<Sha256>::new_from_slice(key.key.as_slice()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA256 accepts every key length"),
    };
    mac.update(&message);
    SagaReceiptFingerprint {
        key_id: key.id.clone(),
        digest: mac.finalize().into_bytes().into(),
    }
}

fn push_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn constant_time_key_id_eq(
    lhs: &SagaReceiptIntegrityKeyId,
    rhs: &SagaReceiptIntegrityKeyId,
) -> Choice {
    let mut lhs_padded = [0_u8; KEY_ID_MAX_BYTES + 1];
    let mut rhs_padded = [0_u8; KEY_ID_MAX_BYTES + 1];
    lhs_padded[0] = lhs.0.len() as u8;
    rhs_padded[0] = rhs.0.len() as u8;
    lhs_padded[1..=lhs.0.len()].copy_from_slice(lhs.0.as_bytes());
    rhs_padded[1..=rhs.0.len()].copy_from_slice(rhs.0.as_bytes());
    lhs_padded.ct_eq(&rhs_padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_key_is_rejected() -> Result<(), SagaReceiptIntegrityError> {
        let id = SagaReceiptIntegrityKeyId::parse("receipt-v1")?;
        assert!(matches!(
            VersionedSagaReceiptIntegrityKey::from_bytes(id, vec![0x42; KEY_MIN_BYTES - 1]),
            Err(SagaReceiptIntegrityError::KeyTooShort)
        ));
        Ok(())
    }

    #[test]
    fn key_material_is_owned_by_a_zeroizing_container() -> Result<(), SagaReceiptIntegrityError> {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}

        let id = SagaReceiptIntegrityKeyId::parse("receipt-v1")?;
        let key = VersionedSagaReceiptIntegrityKey::from_bytes(id, vec![0x42; KEY_MIN_BYTES])?;
        assert_zeroizes_on_drop(&key.key);
        Ok(())
    }
}
