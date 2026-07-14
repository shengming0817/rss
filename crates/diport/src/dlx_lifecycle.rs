//! Provider-neutral ports and observation DTOs for the verified DLX lifecycle.
//!
//! The service owns state transitions and sealed proofs. This module owns only values that cross
//! provider boundaries plus the two replaceable providers: lifecycle persistence and WORM object
//! storage. Both ports use static dispatch because the worker calls them repeatedly from a Send +
//! Sync runtime; no dyn wrapper or third crypto port exists.

use sha2::{Digest, Sha256};

use crate::{KeyRef, RedactedBytes};

/// Maximum plaintext size accepted by the HOT replay capsule codec.
///
/// This leaves deterministic headroom for the canonical archive envelope and provider framing
/// beneath [`DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES`]. Writers and lifecycle readers both enforce it.
pub const DLX_MAX_HOT_CAPSULE_PLAINTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum ciphertext size accepted by the dedicated archive provider.
pub const DLX_MAX_ARCHIVE_CIPHERTEXT_BYTES: usize = 16 * 1024 * 1024;

/// Provider-issued immutable S3 object-version coordinate.
///
/// Construction validates the provider response before a version can cross the capability
/// boundary. The private field prevents callers from fabricating an unchecked version token.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ArchiveVersionId(Box<str>);

impl ArchiveVersionId {
    pub fn try_from_provider(raw: &str) -> Result<Self, DlxLifecycleError> {
        if raw.is_empty()
            || raw.len() > 1024
            || raw != raw.trim()
            || raw.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::ParseArchiveVersion,
                DlxLifecycleReason::UnexpectedProviderResponse,
            ));
        }
        Ok(Self(raw.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ArchiveVersionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveVersionId(<redacted>)")
    }
}

/// SHA-256 of the exact archive object ciphertext.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchiveChecksum([u8; 32]);

impl ArchiveChecksum {
    pub const fn from_sha256_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn sha256(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

impl std::fmt::Debug for ArchiveChecksum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ArchiveChecksum(<redacted>)")
    }
}

/// Opaque archive ciphertext and the exact key version required for retry verification.
#[derive(Debug, Clone)]
pub struct DlxArchiveCiphertext {
    ciphertext: RedactedBytes,
    key_ref: KeyRef,
}

impl DlxArchiveCiphertext {
    pub fn new(ciphertext: RedactedBytes, key_ref: KeyRef) -> Self {
        Self {
            ciphertext,
            key_ref,
        }
    }

    pub const fn ciphertext(&self) -> &RedactedBytes {
        &self.ciphertext
    }

    pub const fn key_ref(&self) -> &KeyRef {
        &self.key_ref
    }
}

/// The only Object Lock mode accepted beyond the verified provider boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLockMode {
    Compliance,
}

impl ObjectLockMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compliance => "COMPLIANCE",
        }
    }
}

/// Verified WORM metadata observed by the narrow archive provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlxArchiveObjectMetadata {
    checksum: ArchiveChecksum,
    version_id: ArchiveVersionId,
    retain_until_epoch_secs: i64,
}

impl DlxArchiveObjectMetadata {
    pub const fn new(
        checksum: ArchiveChecksum,
        version_id: ArchiveVersionId,
        retain_until_epoch_secs: i64,
    ) -> Self {
        Self {
            checksum,
            version_id,
            retain_until_epoch_secs,
        }
    }

    pub const fn checksum(&self) -> ArchiveChecksum {
        self.checksum
    }

    pub const fn object_lock_mode(&self) -> ObjectLockMode {
        ObjectLockMode::Compliance
    }

    pub const fn version_id(&self) -> &ArchiveVersionId {
        &self.version_id
    }

    pub const fn retain_until_epoch_secs(&self) -> i64 {
        self.retain_until_epoch_secs
    }
}

/// Conditional create request. Its checksum covers ciphertext bytes only.
#[derive(Debug, Clone)]
pub struct DlxArchivePutRequest<K> {
    object_key: K,
    ciphertext: DlxArchiveCiphertext,
    checksum: ArchiveChecksum,
}

impl<K> DlxArchivePutRequest<K> {
    pub fn new(object_key: K, ciphertext: DlxArchiveCiphertext) -> Self {
        let checksum = ArchiveChecksum::sha256(ciphertext.ciphertext().as_bytes());
        Self {
            object_key,
            ciphertext,
            checksum,
        }
    }

    pub const fn object_key(&self) -> &K {
        &self.object_key
    }

    pub const fn ciphertext(&self) -> &DlxArchiveCiphertext {
        &self.ciphertext
    }

    pub const fn checksum(&self) -> ArchiveChecksum {
        self.checksum
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlxArchivePutOutcome {
    Created(DlxArchiveObjectMetadata),
    AlreadyExists(DlxArchiveObjectMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlxArchiveHeadOutcome {
    Present(DlxArchiveObjectMetadata),
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlxLifecycleErrorKind {
    Transient,
    Invariant,
}

/// Closed lifecycle operation coordinates used by errors, logs, and metrics.
///
/// The values deliberately describe lifecycle phases rather than provider method names. No tenant,
/// object key, database statement, or provider response can enter this low-cardinality taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DlxLifecycleOperation {
    ParseArchiveVersion,
    ArchiveBacklog,
    ClaimArchiveCandidates,
    DecodeArchiveCandidate,
    DecodeExpiredReceipt,
    EncodeArchive,
    EncryptArchive,
    PutArchive,
    GetArchive,
    DecryptArchive,
    HeadArchive,
    VerifyArchive,
    RecordArchiveReceipt,
    PurgeVerified,
    ClaimExpiredReceipts,
    DeleteExpiredReceipt,
}

impl DlxLifecycleOperation {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ParseArchiveVersion => "parse_archive_version",
            Self::ArchiveBacklog => "archive_backlog",
            Self::ClaimArchiveCandidates => "claim_archive_candidates",
            Self::DecodeArchiveCandidate => "decode_archive_candidate",
            Self::DecodeExpiredReceipt => "decode_expired_receipt",
            Self::EncodeArchive => "encode_archive",
            Self::EncryptArchive => "encrypt_archive",
            Self::PutArchive => "put_archive",
            Self::GetArchive => "get_archive",
            Self::DecryptArchive => "decrypt_archive",
            Self::HeadArchive => "head_archive",
            Self::VerifyArchive => "verify_archive",
            Self::RecordArchiveReceipt => "record_archive_receipt",
            Self::PurgeVerified => "purge_verified",
            Self::ClaimExpiredReceipts => "claim_expired_receipts",
            Self::DeleteExpiredReceipt => "delete_expired_receipt",
        }
    }
}

/// Closed, redacted reason taxonomy for lifecycle failures.
///
/// Each reason owns its retry class, making an invalid combination such as an invariant
/// `ProviderTimeout` unrepresentable. Provider error strings remain behind adapter-local tracing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DlxLifecycleReason {
    ProviderUnavailable,
    ProviderTimeout,
    InvalidPersistedData,
    InvalidArchiveFormat,
    SizeLimitExceeded,
    KeyNotFound,
    KeyForbidden,
    KeyRejected,
    KeyMismatch,
    ObjectMissing,
    VersionDrift,
    ChecksumMismatch,
    CanonicalMismatch,
    RetentionInvalid,
    CasRejected,
    ArithmeticOverflow,
    UnexpectedProviderResponse,
    InternalInvariant,
}

impl DlxLifecycleReason {
    pub const fn kind(self) -> DlxLifecycleErrorKind {
        match self {
            Self::ProviderUnavailable
            | Self::ProviderTimeout
            | Self::ObjectMissing
            | Self::VersionDrift => DlxLifecycleErrorKind::Transient,
            Self::InvalidPersistedData
            | Self::InvalidArchiveFormat
            | Self::SizeLimitExceeded
            | Self::KeyNotFound
            | Self::KeyForbidden
            | Self::KeyRejected
            | Self::KeyMismatch
            | Self::ChecksumMismatch
            | Self::CanonicalMismatch
            | Self::RetentionInvalid
            | Self::CasRejected
            | Self::ArithmeticOverflow
            | Self::UnexpectedProviderResponse
            | Self::InternalInvariant => DlxLifecycleErrorKind::Invariant,
        }
    }

    pub const fn as_label(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderTimeout => "provider_timeout",
            Self::InvalidPersistedData => "invalid_persisted_data",
            Self::InvalidArchiveFormat => "invalid_archive_format",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::KeyNotFound => "key_not_found",
            Self::KeyForbidden => "key_forbidden",
            Self::KeyRejected => "key_rejected",
            Self::KeyMismatch => "key_mismatch",
            Self::ObjectMissing => "object_missing",
            Self::VersionDrift => "version_drift",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::CanonicalMismatch => "canonical_mismatch",
            Self::RetentionInvalid => "retention_invalid",
            Self::CasRejected => "cas_rejected",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::UnexpectedProviderResponse => "unexpected_provider_response",
            Self::InternalInvariant => "internal_invariant",
        }
    }
}

/// Redacted provider-neutral lifecycle error.
///
/// `Display` stays constant and provider detail never crosses the port. In-process consumers retain
/// only closed operation/reason coordinates for retry routing and low-cardinality diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("dead-letter lifecycle operation failed")]
pub struct DlxLifecycleError {
    operation: DlxLifecycleOperation,
    reason: DlxLifecycleReason,
}

impl DlxLifecycleError {
    pub const fn new(operation: DlxLifecycleOperation, reason: DlxLifecycleReason) -> Self {
        Self { operation, reason }
    }

    pub const fn kind(self) -> DlxLifecycleErrorKind {
        self.reason.kind()
    }

    pub const fn operation(self) -> DlxLifecycleOperation {
        self.operation
    }

    pub const fn reason(self) -> DlxLifecycleReason {
        self.reason
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptCasOutcome {
    Applied,
    AlreadyApplied,
}

/// Durable archive-claim failure settlement result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveClaimSettleOutcome {
    Applied,
    Stale,
}

/// Candidate paired with a provider-owned opaque durable claim.
///
/// The lifecycle service can carry the claim back to the repository but cannot inspect or forge
/// its token/deadline coordinates. This keeps lease authority inside the persistence provider.
#[derive(Debug)]
pub struct ClaimedArchiveCandidate<C, T> {
    claim: C,
    candidate: T,
}

impl<C, T> ClaimedArchiveCandidate<C, T> {
    pub fn new(claim: C, candidate: T) -> Self {
        Self { claim, candidate }
    }

    pub const fn claim(&self) -> &C {
        &self.claim
    }

    pub const fn candidate(&self) -> &T {
        &self.candidate
    }

    pub fn into_parts(self) -> (C, T) {
        (self.claim, self.candidate)
    }
}

/// Label-free archive backlog observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlxArchiveBacklog {
    depth: u64,
    oldest_age_seconds: u64,
}

impl DlxArchiveBacklog {
    pub const fn new(depth: u64, oldest_age_seconds: u64) -> Self {
        Self {
            depth,
            oldest_age_seconds,
        }
    }

    pub const fn depth(self) -> u64 {
        self.depth
    }

    pub const fn oldest_age_seconds(self) -> u64 {
        self.oldest_age_seconds
    }
}

/// Narrow verified archive capability. Delete/list/replay are intentionally unrepresentable.
#[trait_variant::make(DlxArchiveStore: Send)]
#[allow(async_fn_in_trait)]
// reason: the worker uses static Send dispatch for repeated calls; no dyn wrapper is required.
pub trait DlxArchiveStoreLocal: Send + Sync {
    type ObjectKey: Clone + Send + Sync + 'static;

    async fn put_if_absent(
        &self,
        request: DlxArchivePutRequest<Self::ObjectKey>,
    ) -> Result<DlxArchivePutOutcome, DlxLifecycleError>;

    async fn get_ciphertext(
        &self,
        key: &Self::ObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<Option<DlxArchiveCiphertext>, DlxLifecycleError>;

    async fn head(
        &self,
        key: &Self::ObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<DlxArchiveHeadOutcome, DlxLifecycleError>;
}

/// Cross-tenant persistence is confined behind fixed SECURITY DEFINER functions.
#[trait_variant::make(DlxLifecycleRepository: Send)]
#[allow(async_fn_in_trait)]
// reason: the worker uses static Send dispatch for repeated calls; no dyn wrapper is required.
pub trait DlxLifecycleRepositoryLocal: Send + Sync {
    type ArchiveClaim: Send + Sync + 'static;
    type ArchiveCandidate: Send + 'static;
    type VerifiedReceipt: Send + 'static;
    type ExpiredReceipt: Send + 'static;
    type MissingProof: Send + 'static;

    async fn archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError>;

    async fn claim_archive_candidates(
        &self,
    ) -> Result<
        Vec<ClaimedArchiveCandidate<Self::ArchiveClaim, Self::ArchiveCandidate>>,
        DlxLifecycleError,
    >;

    async fn record_verified_receipt(
        &self,
        claim: &Self::ArchiveClaim,
        receipt: Self::VerifiedReceipt,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError>;

    async fn settle_archive_failure(
        &self,
        claim: Self::ArchiveClaim,
        failure: DlxLifecycleError,
    ) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError>;

    async fn purge_verified(&self) -> Result<u64, DlxLifecycleError>;

    async fn claim_expired_receipts(&self) -> Result<Vec<Self::ExpiredReceipt>, DlxLifecycleError>;

    async fn delete_expired_receipt(
        &self,
        proof: Self::MissingProof,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        ArchiveChecksum, ArchiveVersionId, DlxArchiveBacklog, DlxLifecycleError,
        DlxLifecycleErrorKind, DlxLifecycleOperation, DlxLifecycleReason,
    };

    #[test]
    #[allow(clippy::expect_used)] // reason: fixed provider-version fixture is known-valid.
    fn observations_are_closed_and_debug_redacted() {
        let checksum = ArchiveChecksum::sha256(b"ciphertext");
        assert_eq!(checksum.as_hex().len(), 64);
        assert_eq!(format!("{checksum:?}"), "ArchiveChecksum(<redacted>)");
        assert_eq!(DlxArchiveBacklog::new(3, 7).depth(), 3);
        assert_ne!(
            DlxLifecycleErrorKind::Transient,
            DlxLifecycleErrorKind::Invariant
        );
        let version = ArchiveVersionId::try_from_provider("provider-version-1")
            .expect("fixed provider version is valid");
        assert_eq!(version.as_str(), "provider-version-1");
        assert_eq!(format!("{version:?}"), "ArchiveVersionId(<redacted>)");
        for invalid in ["", " leading", "trailing ", "control\n"] {
            assert!(ArchiveVersionId::try_from_provider(invalid).is_err());
        }
    }

    #[test]
    fn lifecycle_errors_preserve_closed_operation_and_reason_without_provider_detail() {
        let unavailable = DlxLifecycleError::new(
            DlxLifecycleOperation::GetArchive,
            DlxLifecycleReason::ProviderUnavailable,
        );
        let mismatch = DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::CanonicalMismatch,
        );

        assert_eq!(unavailable.kind(), DlxLifecycleErrorKind::Transient);
        assert_eq!(unavailable.operation(), DlxLifecycleOperation::GetArchive);
        assert_eq!(
            unavailable.reason(),
            DlxLifecycleReason::ProviderUnavailable
        );
        assert_eq!(mismatch.kind(), DlxLifecycleErrorKind::Invariant);
        assert_ne!(unavailable.reason(), mismatch.reason());
        assert_eq!(
            unavailable.to_string(),
            "dead-letter lifecycle operation failed"
        );
        assert!(!format!("{unavailable:?}").contains("provider-secret"));
    }

    #[test]
    fn lifecycle_taxonomy_labels_are_complete_unique_and_low_cardinality() {
        let operations = [
            DlxLifecycleOperation::ParseArchiveVersion,
            DlxLifecycleOperation::ArchiveBacklog,
            DlxLifecycleOperation::ClaimArchiveCandidates,
            DlxLifecycleOperation::DecodeArchiveCandidate,
            DlxLifecycleOperation::DecodeExpiredReceipt,
            DlxLifecycleOperation::EncodeArchive,
            DlxLifecycleOperation::EncryptArchive,
            DlxLifecycleOperation::PutArchive,
            DlxLifecycleOperation::GetArchive,
            DlxLifecycleOperation::DecryptArchive,
            DlxLifecycleOperation::HeadArchive,
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleOperation::RecordArchiveReceipt,
            DlxLifecycleOperation::PurgeVerified,
            DlxLifecycleOperation::ClaimExpiredReceipts,
            DlxLifecycleOperation::DeleteExpiredReceipt,
        ];
        let reasons = [
            DlxLifecycleReason::ProviderUnavailable,
            DlxLifecycleReason::ProviderTimeout,
            DlxLifecycleReason::InvalidPersistedData,
            DlxLifecycleReason::InvalidArchiveFormat,
            DlxLifecycleReason::SizeLimitExceeded,
            DlxLifecycleReason::KeyNotFound,
            DlxLifecycleReason::KeyForbidden,
            DlxLifecycleReason::KeyRejected,
            DlxLifecycleReason::KeyMismatch,
            DlxLifecycleReason::ObjectMissing,
            DlxLifecycleReason::VersionDrift,
            DlxLifecycleReason::ChecksumMismatch,
            DlxLifecycleReason::CanonicalMismatch,
            DlxLifecycleReason::RetentionInvalid,
            DlxLifecycleReason::CasRejected,
            DlxLifecycleReason::ArithmeticOverflow,
            DlxLifecycleReason::UnexpectedProviderResponse,
            DlxLifecycleReason::InternalInvariant,
        ];

        let operation_labels: HashSet<_> = operations.map(DlxLifecycleOperation::as_label).into();
        let reason_labels: HashSet<_> = reasons.map(DlxLifecycleReason::as_label).into();
        assert_eq!(operation_labels.len(), operations.len());
        assert_eq!(reason_labels.len(), reasons.len());
        assert!(operation_labels.iter().all(|label| !label.is_empty()));
        assert!(reason_labels.iter().all(|label| !label.is_empty()));
        assert_eq!(
            reasons
                .into_iter()
                .filter(|reason| reason.kind() == DlxLifecycleErrorKind::Transient)
                .count(),
            4
        );
    }
}
