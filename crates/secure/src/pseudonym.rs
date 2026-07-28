//! Versioned HMAC pseudonyms for low-entropy durable identifiers.

use std::num::NonZeroU16;

use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use vocab::TenantId;

use crate::RedactionHashKey;

const CONTEXT: &[u8] = b"rss.pseudonym.hmac-sha256.v1";
const UUID_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PseudonymKeyId(NonZeroU16);

impl PseudonymKeyId {
    pub const fn new(value: NonZeroU16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// One zeroized HMAC key paired with its durable rotation identifier.
pub struct VersionedPseudonymKey {
    id: PseudonymKeyId,
    key: RedactionHashKey,
}

impl VersionedPseudonymKey {
    pub fn new(id: PseudonymKeyId, key: RedactionHashKey) -> Self {
        Self { id, key }
    }
}

impl std::fmt::Debug for VersionedPseudonymKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VersionedPseudonymKey")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PseudonymError {
    #[error("pseudonym domain must not be empty")]
    EmptyDomain,
    #[error("pseudonym key ids must be unique")]
    DuplicateKeyId,
}

/// Current write key plus the bounded previous-key lookup window.
pub struct PseudonymKeyRing {
    current: VersionedPseudonymKey,
    previous: Vec<VersionedPseudonymKey>,
}

impl PseudonymKeyRing {
    pub fn new(
        current: VersionedPseudonymKey,
        previous: Vec<VersionedPseudonymKey>,
    ) -> Result<Self, PseudonymError> {
        let current_id = current.id;
        for (index, key) in previous.iter().enumerate() {
            if key.id == current_id || previous[..index].iter().any(|prior| prior.id == key.id) {
                return Err(PseudonymError::DuplicateKeyId);
            }
        }
        Ok(Self { current, previous })
    }

    pub fn current(
        &self,
        tenant: TenantId,
        domain: &str,
        value: &[u8],
    ) -> Result<PseudonymRef, PseudonymError> {
        pseudonymize(&self.current, tenant, domain, value)
    }

    /// Current-first reference set used while old events remain in the rotation window.
    pub fn lookup_set(
        &self,
        tenant: TenantId,
        domain: &str,
        value: &[u8],
    ) -> Result<Vec<PseudonymRef>, PseudonymError> {
        let mut refs = Vec::with_capacity(1 + self.previous.len());
        refs.push(pseudonymize(&self.current, tenant, domain, value)?);
        for key in &self.previous {
            refs.push(pseudonymize(key, tenant, domain, value)?);
        }
        Ok(refs)
    }
}

impl std::fmt::Debug for PseudonymKeyRing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PseudonymKeyRing")
            .field("current_id", &self.current.id)
            .field("previous_key_count", &self.previous.len())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PseudonymRef {
    key_id: PseudonymKeyId,
    bytes: [u8; UUID_BYTES],
}

impl PseudonymRef {
    #[must_use]
    pub const fn key_id(self) -> PseudonymKeyId {
        self.key_id
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; UUID_BYTES] {
        self.bytes
    }
}

impl std::fmt::Debug for PseudonymRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PseudonymRef")
            .field("key_id", &self.key_id)
            .field("value", &"<redacted>")
            .finish()
    }
}

fn pseudonymize(
    key: &VersionedPseudonymKey,
    tenant: TenantId,
    domain: &str,
    value: &[u8],
) -> Result<PseudonymRef, PseudonymError> {
    if domain.is_empty() {
        return Err(PseudonymError::EmptyDomain);
    }
    let mut message = Vec::new();
    push_length_prefixed(&mut message, CONTEXT);
    push_length_prefixed(&mut message, tenant.as_uuid().as_bytes());
    push_length_prefixed(&mut message, domain.as_bytes());
    push_length_prefixed(&mut message, value);
    let mut mac = match Hmac::<Sha256>::new_from_slice(key.key.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => unreachable!("HMAC-SHA256 accepts every key length"),
    };
    mac.update(&message);
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0_u8; UUID_BYTES];
    bytes.copy_from_slice(&digest[..UUID_BYTES]);
    Ok(PseudonymRef {
        key_id: key.id,
        bytes,
    })
}

fn push_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u16, fill: u8) -> VersionedPseudonymKey {
        VersionedPseudonymKey::new(
            PseudonymKeyId::new(NonZeroU16::new(id).expect("non-zero key id")),
            RedactionHashKey::from_bytes(vec![fill; 32]).expect("valid key"),
        )
    }

    #[test]
    fn domain_tenant_and_key_are_all_separated() {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant");
        let other = TenantId::parse("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").expect("tenant");
        let ring = PseudonymKeyRing::new(key(2, 0x42), vec![key(1, 0x24)]).expect("ring");
        let subject = ring.current(tenant, "actor/user", b"alice").expect("ref");
        assert_ne!(
            subject,
            ring.current(tenant, "target/subject", b"alice")
                .expect("ref")
        );
        assert_ne!(
            subject,
            ring.current(other, "actor/user", b"alice").expect("ref")
        );
        let lookup = ring
            .lookup_set(tenant, "actor/user", b"alice")
            .expect("lookup");
        assert_eq!(lookup.len(), 2);
        assert_eq!(lookup[0], subject);
        assert_eq!(lookup[0].key_id().get(), 2);
        assert_eq!(lookup[1].key_id().get(), 1);
        assert_ne!(lookup[0], lookup[1]);
    }

    #[test]
    fn duplicate_rotation_ids_are_rejected() {
        assert_eq!(
            PseudonymKeyRing::new(key(1, 0x42), vec![key(1, 0x24)]).expect_err("duplicate"),
            PseudonymError::DuplicateKeyId
        );
    }
}
