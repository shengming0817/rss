use super::{Candidate, Claim, Error, Object, Prepared, Request};
use rss_data_protection::{Aead, CipherAlg, CiphertextEnvelope, EncryptionMode, ProtectionContext};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
pub(super) const FORMAT_VERSION: u8 = 1;
pub(super) const OBJECT_SUFFIX: &str = ".v1.enc";
/// HOT decryption capability, deliberately distinct from archive encryption.
pub struct HotKey<K>(pub K);
/// Archive encryption capability, with independently checked actual key identity.
/// ```compile_fail
/// use rss_transactional_messaging_recovery::archive::{ArchiveKey,HotKey};
/// fn archive<K>(_: ArchiveKey<K>) {}
/// archive(HotKey(()));
/// ```
pub struct ArchiveKey<K>(pub K);
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Canonical {
    version: u8,
    tenant: String,
    dead_letter: String,
    captured_at: i64,
    reason: String,
    fingerprint: [u8; 32],
    authored: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cipher {
    version: u8,
    key: String,
    key_version: u32,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}
#[derive(Deserialize)]
struct HotIdentity {
    key: String,
}
pub(super) fn prepare<H: Aead, K: Aead>(
    hot: &HotKey<H>,
    archive: &ArchiveKey<K>,
    request: &Request,
    claim: &Claim,
    candidate: &Candidate,
) -> Result<Prepared, Error> {
    if candidate.context.id() != request.id()
        || candidate.context.consumer().tenant_id() != request.tenant()
    {
        return Err(Error::Evidence);
    }
    let message = crate::protection::open(&hot.0, &candidate.context, &candidate.capsule)
        .map_err(|_| Error::Protection)?;
    let authored = Zeroizing::new(
        crate::protection::Envelope::encode(&message).map_err(|_| Error::Protection)?,
    );
    let plain = Zeroizing::new(
        serde_json::to_vec(&Canonical {
            version: FORMAT_VERSION,
            tenant: request.tenant().to_string(),
            dead_letter: request.id().to_string(),
            captured_at: candidate.captured_at,
            reason: reason(candidate).into(),
            fingerprint: *candidate.context.fingerprint().as_bytes(),
            authored: authored.to_string(),
        })
        .map_err(|_| Error::Protection)?,
    );
    let key = object_key(request, &claim.generation);
    let aad = aad(request, &key)?;
    let cipher = archive
        .0
        .seal(&plain, &aad)
        .map_err(|_| Error::Protection)?;
    let old: HotIdentity =
        serde_json::from_slice(candidate.capsule.bytes()).map_err(|_| Error::Protection)?;
    if cipher.kid() == old.key
        || cipher.alg() != CipherAlg::Aes256Gcm
        || cipher.mode() != EncryptionMode::Randomized
        || cipher.aad() != aad.coordinates()
    {
        return Err(Error::Protection);
    }
    let bytes = serde_json::to_vec(&Cipher {
        version: FORMAT_VERSION,
        key: cipher.kid().into(),
        key_version: cipher.key_version(),
        nonce: cipher.nonce().into(),
        ciphertext: cipher.ciphertext().into(),
        tag: cipher.tag().into(),
    })
    .map_err(|_| Error::Protection)?;
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(Error::Protection);
    }
    // Cover the earliest purge plus a full receipt horizon; delayed workers supersede this generation.
    let retain_until = request
        .retention()
        .minimum_lock_until(claim.now.max(claim.hot_until), claim.receipt_seconds)?
        .checked_add(claim.receipt_seconds)
        .ok_or(Error::Retention)?;
    Ok(Prepared {
        object: Object {
            key,
            checksum: super::model::checksum(&bytes),
            length: bytes.len() as u64,
            version: None,
            retain_until,
        },
        bytes,
    })
}
/// Upper bound enforced before buffering or persisting any archive object.
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;

impl Drop for Canonical {
    fn drop(&mut self) {
        self.authored.zeroize();
        self.reason.zeroize();
    }
}
fn reason(candidate: &Candidate) -> &'static str {
    match candidate.reason {
        rss_transactional_messaging::transaction::RejectKind::Permanent => "rejected_permanent",
        rss_transactional_messaging::transaction::RejectKind::Invariant => "rejected_invariant",
    }
}
fn object_key(request: &Request, generation: &str) -> String {
    format!(
        "consumer/{}/{}/{}{OBJECT_SUFFIX}",
        request.tenant(),
        request.id(),
        generation
    )
}
fn aad(request: &Request, key: &str) -> Result<rss_data_protection::DerivedAad, Error> {
    ProtectionContext::authorized_maintenance(
        request.tenant(),
        key,
        "rss.message.recovery.archive",
        u32::from(FORMAT_VERSION),
    )
    .map(|context| context.derive())
    .map_err(|_| Error::Protection)
}
/// Exercise the format reader before minting a purge proof; this is not a cold replay capability.
pub(super) fn validate<K: Aead>(
    archive: &ArchiveKey<K>,
    request: &Request,
    candidate: &Candidate,
    key: &str,
    bytes: &[u8],
) -> Result<(), Error> {
    let stored: Cipher = serde_json::from_slice(bytes).map_err(|_| Error::Evidence)?;
    if stored.version != FORMAT_VERSION {
        return Err(Error::Evidence);
    }
    let aad = aad(request, key)?;
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
    .map_err(|_| Error::Evidence)?;
    let plain = archive
        .0
        .open(&cipher, &aad)
        .map_err(|_| Error::Protection)?;
    let value: Canonical = serde_json::from_slice(plain.expose()).map_err(|_| Error::Evidence)?;
    if value.version != FORMAT_VERSION
        || value.tenant != request.tenant().to_string()
        || value.dead_letter != request.id().to_string()
        || value.captured_at != candidate.captured_at
        || value.reason != reason(candidate)
        || value.fingerprint != *candidate.context.fingerprint().as_bytes()
    {
        return Err(Error::Evidence);
    }
    let message =
        crate::protection::Envelope::decode(&value.authored).map_err(|_| Error::Evidence)?;
    candidate
        .context
        .validate(&message)
        .map_err(|_| Error::Evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_v1_golden() -> Result<(), Box<dyn std::error::Error>> {
        let value = Canonical {
            version: FORMAT_VERSION,
            tenant: "tenant".into(),
            dead_letter: "dead-letter".into(),
            captured_at: 42,
            reason: "rejected_permanent".into(),
            fingerprint: [0; 32],
            authored: "{}".into(),
        };
        let golden = r#"{"version":1,"tenant":"tenant","deadLetter":"dead-letter","capturedAt":42,"reason":"rejected_permanent","fingerprint":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"authored":"{}"}"#;
        assert_eq!(serde_json::to_string(&value)?, golden);
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<Canonical>(golden)?)?,
            golden
        );
        let cipher = Cipher {
            version: FORMAT_VERSION,
            key: "archive-key".into(),
            key_version: 7,
            nonce: vec![1],
            ciphertext: vec![2],
            tag: vec![3],
        };
        let encrypted = r#"{"version":1,"key":"archive-key","keyVersion":7,"nonce":[1],"ciphertext":[2],"tag":[3]}"#;
        assert_eq!(serde_json::to_string(&cipher)?, encrypted);
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<Cipher>(encrypted)?)?,
            encrypted
        );
        assert!(
            serde_json::from_str::<Cipher>(
                &encrypted.replace("\"version\":1", "\"version\":1,\"extra\":true")
            )
            .is_err()
        );
        assert_eq!(OBJECT_SUFFIX, ".v1.enc");
        Ok(())
    }
    #[test]
    fn archive_coordinates_golden() -> Result<(), Box<dyn std::error::Error>> {
        let request = Request::new(
            rss_request_context::TenantId::parse("11111111-1111-1111-1111-111111111111")?,
            crate::DeadLetterId::parse("22222222-2222-2222-2222-222222222222")?,
            crate::OperationId::new(),
            crate::Version::new(1)?,
            super::super::Retention::new(1, 1)?,
            super::super::Hold::Release,
        );
        let key = object_key(&request, "33333333-3333-3333-3333-333333333333");
        assert_eq!(
            key,
            "consumer/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/33333333-3333-3333-3333-333333333333.v1.enc"
        );
        assert_eq!(
            super::super::model::checksum(aad(&request, &key)?.as_canonical_bytes()),
            [
                197, 156, 213, 204, 216, 150, 245, 40, 191, 115, 195, 197, 39, 162, 20, 93, 61,
                197, 100, 244, 18, 224, 249, 233, 94, 198, 217, 114, 57, 76, 248, 171
            ]
        );
        Ok(())
    }
}
