//! Complete canonical DLX archive record.

use diport::{
    DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES, DeadLetterSource, DlxLifecycleError,
    DlxLifecycleOperation, DlxLifecycleReason,
};
use rss_data_protection::Plaintext;
use zeroize::Zeroizing;

use crate::dead_letter::DeadLetterId;

/// Aggregate bound for the independently persisted safe text columns.
///
/// Together with the 4 MiB HOT capsule bound, this proves the canonical hex envelope remains
/// below [`DLX_MAX_ARCHIVE_CANONICAL_PLAINTEXT_BYTES`] before it reaches the archive key provider.
pub const DLX_MAX_ARCHIVE_SAFE_TEXT_BYTES: usize = 64 * 1024;

/// Maximum canonical archive plaintext accepted by the archive cipher.
///
/// A maximum HOT capsule contributes at most 8 MiB after hex encoding and safe text contributes
/// at most 128 KiB. The remaining headroom covers fixed coordinates, numbers and delimiters.
pub const DLX_MAX_ARCHIVE_CANONICAL_PLAINTEXT_BYTES: usize = 9 * 1024 * 1024;

/// SHA-256 of canonical replay metadata inside the v3 capsule.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DlxMetadataDigest([u8; 32]);

impl DlxMetadataDigest {
    pub const fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        lower_hex(&self.0)
    }
}

impl std::fmt::Debug for DlxMetadataDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// Every independently persisted safe column needed to interpret and audit a cold DLX record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlxArchiveSafeMetadata {
    message_id: String,
    producer_domain: String,
    consumer_domain: Option<String>,
    contract_id: String,
    topic: String,
    consumer_group: Option<String>,
    source_kind: DeadLetterSource,
    error_summary: String,
    num_attempts: u32,
    first_attempt_epoch_micros: i64,
    last_attempt_epoch_micros: i64,
    payload_len: u64,
    metadata_digest: DlxMetadataDigest,
}

/// Named construction input for independently persisted safe archive columns.
///
/// Keeping the fields named makes schema-to-domain hydration reviewable: adding or reordering a
/// column cannot silently bind it to another same-typed positional argument.
pub struct DlxArchiveSafeMetadataInput {
    pub message_id: String,
    pub producer_domain: String,
    pub consumer_domain: Option<String>,
    pub contract_id: String,
    pub topic: String,
    pub consumer_group: Option<String>,
    pub source_kind: DeadLetterSource,
    pub error_summary: String,
    pub num_attempts: u32,
    pub first_attempt_epoch_micros: i64,
    pub last_attempt_epoch_micros: i64,
    pub payload_len: u64,
    pub metadata_digest: DlxMetadataDigest,
}

impl DlxArchiveSafeMetadata {
    pub fn try_new(input: DlxArchiveSafeMetadataInput) -> Result<Self, DlxLifecycleError> {
        let value = Self {
            message_id: input.message_id,
            producer_domain: input.producer_domain,
            consumer_domain: input.consumer_domain,
            contract_id: input.contract_id,
            topic: input.topic,
            consumer_group: input.consumer_group,
            source_kind: input.source_kind,
            error_summary: input.error_summary,
            num_attempts: input.num_attempts,
            first_attempt_epoch_micros: input.first_attempt_epoch_micros,
            last_attempt_epoch_micros: input.last_attempt_epoch_micros,
            payload_len: input.payload_len,
            metadata_digest: input.metadata_digest,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DlxLifecycleError> {
        let required = [
            self.message_id.as_str(),
            self.producer_domain.as_str(),
            self.contract_id.as_str(),
            self.topic.as_str(),
            self.error_summary.as_str(),
        ];
        let optional_empty = self.consumer_domain.as_deref() == Some("")
            || self.consumer_group.as_deref() == Some("");
        let consumer_shape_valid = match self.source_kind {
            DeadLetterSource::Consumer | DeadLetterSource::Projection => {
                self.consumer_domain.is_some()
            }
            DeadLetterSource::OutboxRelay | DeadLetterSource::Saga => {
                self.consumer_domain.is_none()
            }
        };
        let safe_text_bytes = [
            Some(self.message_id.as_str()),
            Some(self.producer_domain.as_str()),
            self.consumer_domain.as_deref(),
            Some(self.contract_id.as_str()),
            Some(self.topic.as_str()),
            self.consumer_group.as_deref(),
            Some(self.error_summary.as_str()),
        ]
        .into_iter()
        .flatten()
        .try_fold(0usize, |total, value| total.checked_add(value.len()))
        .ok_or_else(|| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeArchiveCandidate,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
        if required.iter().any(|value| value.is_empty())
            || optional_empty
            || !consumer_shape_valid
            || safe_text_bytes > DLX_MAX_ARCHIVE_SAFE_TEXT_BYTES
            || self.first_attempt_epoch_micros <= 0
            || self.last_attempt_epoch_micros < self.first_attempt_epoch_micros
        {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeArchiveCandidate,
                DlxLifecycleReason::InvalidPersistedData,
            ));
        }
        Ok(())
    }

    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    pub fn producer_domain(&self) -> &str {
        &self.producer_domain
    }

    pub fn consumer_domain(&self) -> Option<&str> {
        self.consumer_domain.as_deref()
    }

    pub fn contract_id(&self) -> &str {
        &self.contract_id
    }

    pub fn topic(&self) -> &str {
        &self.topic
    }

    pub fn consumer_group(&self) -> Option<&str> {
        self.consumer_group.as_deref()
    }

    pub const fn source_kind(&self) -> DeadLetterSource {
        self.source_kind
    }

    pub fn error_summary(&self) -> &str {
        &self.error_summary
    }

    pub const fn num_attempts(&self) -> u32 {
        self.num_attempts
    }

    pub const fn first_attempt_epoch_micros(&self) -> i64 {
        self.first_attempt_epoch_micros
    }

    pub const fn last_attempt_epoch_micros(&self) -> i64 {
        self.last_attempt_epoch_micros
    }

    pub const fn payload_len(&self) -> u64 {
        self.payload_len
    }

    pub const fn metadata_digest(&self) -> DlxMetadataDigest {
        self.metadata_digest
    }
}

/// Canonical v1 archive plaintext: complete safe row plus the encrypted-at-rest v3 capsule
/// decrypted only into [`Plaintext`]. Tenant authority is absent from the capsule by construction.
pub struct ArchiveCanonicalRecord {
    id: DeadLetterId,
    tenant: rss_request_context::TenantId,
    safe: DlxArchiveSafeMetadata,
    capsule: Plaintext,
}

impl ArchiveCanonicalRecord {
    pub fn new(
        id: DeadLetterId,
        tenant: rss_request_context::TenantId,
        safe: DlxArchiveSafeMetadata,
        capsule: Plaintext,
    ) -> Self {
        Self {
            id,
            tenant,
            safe,
            capsule,
        }
    }

    pub fn dead_letter_id(&self) -> &DeadLetterId {
        &self.id
    }

    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.tenant
    }

    pub fn safe_metadata(&self) -> &DlxArchiveSafeMetadata {
        &self.safe
    }

    /// Frozen canonical bytes. Text fields are hex-encoded so delimiters cannot be forged.
    pub fn encode(&self) -> Plaintext {
        let optional_hex = |value: Option<&str>| value.map_or_else(|| "-".to_string(), hex_text);
        let mut encoded = Zeroizing::new(
            format!(
                concat!(
                    "rss-dlx-archive-v1\n",
                    "deadLetterId:{}\n",
                    "tenantId:{}\n",
                    "sourceKind:{}\n",
                    "messageIdHex:{}\n",
                    "producerDomainHex:{}\n",
                    "consumerDomainHex:{}\n",
                    "contractIdHex:{}\n",
                    "topicHex:{}\n",
                    "consumerGroupHex:{}\n",
                    "errorSummaryHex:{}\n",
                    "numAttempts:{}\n",
                    "firstAttemptEpochMicros:{}\n",
                    "lastAttemptEpochMicros:{}\n",
                    "payloadLength:{}\n",
                    "metadataDigestSha256:{}\n",
                    "capsuleLength:{}\n",
                    "capsuleHex:"
                ),
                self.id,
                self.tenant,
                self.safe.source_kind().as_str(),
                hex_text(self.safe.message_id()),
                hex_text(self.safe.producer_domain()),
                optional_hex(self.safe.consumer_domain()),
                hex_text(self.safe.contract_id()),
                hex_text(self.safe.topic()),
                optional_hex(self.safe.consumer_group()),
                hex_text(self.safe.error_summary()),
                self.safe.num_attempts(),
                self.safe.first_attempt_epoch_micros(),
                self.safe.last_attempt_epoch_micros(),
                self.safe.payload_len(),
                self.safe.metadata_digest().as_hex(),
                self.capsule.expose().len(),
            )
            .into_bytes(),
        );
        append_lower_hex(&mut encoded, self.capsule.expose());
        encoded.push(b'\n');
        Plaintext::new(std::mem::take(&mut *encoded))
    }

    /// Returns canonical bytes only when the HOT-to-cold size proof still holds.
    pub(crate) fn encode_for_archive(&self) -> Result<Plaintext, DlxLifecycleError> {
        if self.capsule.expose().len() > DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::EncodeArchive,
                DlxLifecycleReason::SizeLimitExceeded,
            ));
        }
        let encoded = self.encode();
        if encoded.expose().len() > DLX_MAX_ARCHIVE_CANONICAL_PLAINTEXT_BYTES {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::EncodeArchive,
                DlxLifecycleReason::SizeLimitExceeded,
            ));
        }
        Ok(encoded)
    }
}

impl std::fmt::Debug for ArchiveCanonicalRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveCanonicalRecord")
            .field("id", &self.id)
            .field("tenant", &self.tenant)
            .field("safe", &self.safe)
            .field("capsule", &"<redacted>")
            .finish()
    }
}

/// A claimed HOT row whose v3 replay capsule has already been fail-closed decrypted.
#[derive(Debug)]
pub struct DlxArchiveCandidate(ArchiveCanonicalRecord);

impl DlxArchiveCandidate {
    pub fn try_new(
        id: DeadLetterId,
        tenant: rss_request_context::TenantId,
        safe: DlxArchiveSafeMetadata,
        capsule: Plaintext,
    ) -> Result<Self, DlxLifecycleError> {
        if capsule.expose().len() > DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeArchiveCandidate,
                DlxLifecycleReason::SizeLimitExceeded,
            ));
        }
        let candidate = Self(ArchiveCanonicalRecord::new(id, tenant, safe, capsule));
        candidate.0.encode_for_archive()?;
        Ok(candidate)
    }

    pub fn canonical(&self) -> &ArchiveCanonicalRecord {
        &self.0
    }
}

fn hex_text(value: &str) -> String {
    lower_hex(value.as_bytes())
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn append_lower_hex(encoded: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    encoded.reserve(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)]);
        encoded.push(HEX[usize::from(byte & 0x0f)]);
    }
}

#[cfg(test)]
mod tests {
    use diport::DeadLetterSource;
    use rss_data_protection::Plaintext;

    use super::{
        ArchiveCanonicalRecord, DLX_MAX_ARCHIVE_CANONICAL_PLAINTEXT_BYTES,
        DLX_MAX_ARCHIVE_SAFE_TEXT_BYTES, DlxArchiveCandidate, DlxArchiveSafeMetadata,
        DlxArchiveSafeMetadataInput, DlxMetadataDigest,
    };
    use crate::DeadLetterId;
    use diport::DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES;

    fn outbox_safe(error_summary: String) -> DlxArchiveSafeMetadataInput {
        DlxArchiveSafeMetadataInput {
            message_id: "m".to_owned(),
            producer_domain: "p".to_owned(),
            consumer_domain: None,
            contract_id: "c".to_owned(),
            topic: "t".to_owned(),
            consumer_group: None,
            source_kind: DeadLetterSource::OutboxRelay,
            error_summary,
            num_attempts: 1,
            first_attempt_epoch_micros: 1,
            last_attempt_epoch_micros: 1,
            payload_len: 1,
            metadata_digest: DlxMetadataDigest::from_sha256_bytes([0; 32]),
        }
    }

    #[test]
    fn debug_is_auditable_without_exposing_capsule_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let digest = DlxMetadataDigest::from_sha256_bytes([0xab; 32]);
        assert_eq!(format!("{digest:?}"), "ab".repeat(32));

        let safe = DlxArchiveSafeMetadata::try_new(DlxArchiveSafeMetadataInput {
            message_id: "message-1".to_owned(),
            producer_domain: "orders".to_owned(),
            consumer_domain: None,
            contract_id: "orders.created.v1".to_owned(),
            topic: "orders.created".to_owned(),
            consumer_group: None,
            source_kind: DeadLetterSource::OutboxRelay,
            error_summary: "delivery failed".to_owned(),
            num_attempts: 3,
            first_attempt_epoch_micros: 1,
            last_attempt_epoch_micros: 2,
            payload_len: 18,
            metadata_digest: digest,
        })?;
        let record = ArchiveCanonicalRecord::new(
            DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")?,
            rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")?,
            safe,
            Plaintext::new(b"TOP_SECRET_CAPSULE".to_vec()),
        );

        let rendered = format!("{record:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("TOP_SECRET_CAPSULE"));
        Ok(())
    }

    #[test]
    fn hot_capsule_and_safe_text_bounds_prove_archive_canonical_headroom()
    -> Result<(), Box<dyn std::error::Error>> {
        const REQUIRED_SHORT_TEXT: usize = 4;
        let exact_safe = DlxArchiveSafeMetadata::try_new(outbox_safe(
            "x".repeat(DLX_MAX_ARCHIVE_SAFE_TEXT_BYTES - REQUIRED_SHORT_TEXT),
        ))?;
        assert!(
            DlxArchiveSafeMetadata::try_new(outbox_safe(
                "x".repeat(DLX_MAX_ARCHIVE_SAFE_TEXT_BYTES - REQUIRED_SHORT_TEXT + 1,)
            ))
            .is_err()
        );

        let id = DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")?;
        let tenant = rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")?;
        let candidate = DlxArchiveCandidate::try_new(
            id.clone(),
            tenant,
            exact_safe,
            Plaintext::new(vec![0; DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES]),
        )?;
        assert!(
            candidate.canonical().encode_for_archive()?.expose().len()
                <= DLX_MAX_ARCHIVE_CANONICAL_PLAINTEXT_BYTES
        );
        let normal_safe = DlxArchiveSafeMetadata::try_new(outbox_safe("error".to_owned()))?;
        assert!(
            DlxArchiveCandidate::try_new(
                id,
                tenant,
                normal_safe,
                Plaintext::new(vec![0; DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES + 1]),
            )
            .is_err()
        );
        Ok(())
    }
}
