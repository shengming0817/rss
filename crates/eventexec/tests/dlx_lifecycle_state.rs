use std::collections::VecDeque;
use std::error::Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use diport::{
    ArchiveChecksum, ArchiveClaimSettleOutcome, ArchiveVersionId, ClaimedArchiveCandidate,
    DlxArchiveBacklog, DlxArchiveCiphertext, DlxArchiveHeadOutcome, DlxArchiveObjectMetadata,
    DlxArchivePutOutcome, DlxArchivePutRequest, DlxArchiveStore, DlxLifecycleError,
    DlxLifecycleOperation, DlxLifecycleReason, DlxLifecycleRepository, EncryptOutput, KeyName,
    KeyProvider, KeyProviderError, KeyRef, KeyVersion, ReceiptCasOutcome,
};
use eventexec::{
    ArchiveCanonicalRecord, DeadLetterId, DlxArchiveCandidate, DlxArchiveKeyName,
    DlxArchiveObjectKey, DlxArchiveSafeMetadata, DlxArchiveSafeMetadataInput, DlxLifecycle,
    DlxLifecycleHealth, DlxMetadataDigest, ExpiredArchiveReceipt, MissingArchiveProof,
    VerifiedArchiveReceipt,
};
use rss_data_protection::Plaintext;
use rss_redact::RedactedBytes;

const NOW: i64 = 1_800_000_000;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn id(suffix: &str) -> TestResult<DeadLetterId> {
    let raw = format!("018f31a8-893d-7a52-8e17-{suffix}");
    Ok(DeadLetterId::parse(&raw)?)
}

fn tenant() -> TestResult<rss_request_context::TenantId> {
    Ok(rss_request_context::TenantId::parse(
        "11111111-2222-4333-8444-555555555555",
    )?)
}

fn key_ref_at(version: u32) -> TestResult<KeyRef> {
    Ok(KeyRef::new(
        KeyName::try_new("dlx-archive")?,
        KeyVersion::new(version),
    ))
}

fn archive_key() -> TestResult<DlxArchiveKeyName> {
    Ok(DlxArchiveKeyName::try_new("dlx-archive")?)
}

fn archive_version_id() -> Result<ArchiveVersionId, DlxLifecycleError> {
    ArchiveVersionId::try_from_provider("archive-version-1")
}

fn candidate(suffix: &str, body: &[u8]) -> TestResult<DlxArchiveCandidate> {
    Ok(DlxArchiveCandidate::try_new(
        id(suffix)?,
        tenant()?,
        safe_metadata()?,
        Plaintext::new(body.to_vec()),
    )?)
}

fn safe_metadata() -> TestResult<DlxArchiveSafeMetadata> {
    Ok(DlxArchiveSafeMetadata::try_new(
        DlxArchiveSafeMetadataInput {
            message_id: "message-17".to_string(),
            producer_domain: "runtime".to_string(),
            consumer_domain: Some("observer".to_string()),
            contract_id: "runtime.fact-recorded.v1".to_string(),
            topic: "identity.session.created".to_string(),
            consumer_group: Some("audit.projector".to_string()),
            source_kind: diport::DeadLetterSource::Consumer,
            error_summary: "retry budget exhausted".to_string(),
            num_attempts: 10,
            first_attempt_epoch_micros: 1_700_000_000_123_456,
            last_attempt_epoch_micros: 1_700_000_100_654_321,
            payload_len: 42,
            metadata_digest: DlxMetadataDigest::from_sha256_bytes([0xAB; 32]),
        },
    )?)
}

fn push(events: &Arc<Mutex<Vec<&'static str>>>, event: &'static str) {
    if let Ok(mut events) = events.lock() {
        events.push(event);
    }
}

struct FakeRepository {
    candidates: Mutex<VecDeque<Vec<DlxArchiveCandidate>>>,
    expired: Mutex<Option<Vec<ExpiredArchiveReceipt>>>,
    receipt_outcomes: Mutex<VecDeque<Result<ReceiptCasOutcome, DlxLifecycleError>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl FakeRepository {
    fn new(
        candidates: Vec<DlxArchiveCandidate>,
        expired: Vec<ExpiredArchiveReceipt>,
        events: Arc<Mutex<Vec<&'static str>>>,
    ) -> Self {
        Self {
            candidates: Mutex::new(VecDeque::from([candidates])),
            expired: Mutex::new(Some(expired)),
            receipt_outcomes: Mutex::new(VecDeque::new()),
            events,
        }
    }

    fn with_archive_retries(
        first_candidate: DlxArchiveCandidate,
        retry_candidate: DlxArchiveCandidate,
        receipt_outcomes: Vec<Result<ReceiptCasOutcome, DlxLifecycleError>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    ) -> Self {
        Self {
            candidates: Mutex::new(VecDeque::from([
                vec![first_candidate],
                vec![retry_candidate],
            ])),
            expired: Mutex::new(Some(Vec::new())),
            receipt_outcomes: Mutex::new(receipt_outcomes.into()),
            events,
        }
    }
}

impl DlxLifecycleRepository for FakeRepository {
    type ArchiveClaim = DeadLetterId;
    type ArchiveCandidate = DlxArchiveCandidate;
    type VerifiedReceipt = VerifiedArchiveReceipt;
    type ExpiredReceipt = ExpiredArchiveReceipt;
    type MissingProof = MissingArchiveProof;

    async fn archive_backlog(&self) -> Result<DlxArchiveBacklog, DlxLifecycleError> {
        Ok(DlxArchiveBacklog::new(0, 0))
    }

    async fn claim_archive_candidates(
        &self,
    ) -> Result<Vec<ClaimedArchiveCandidate<DeadLetterId, DlxArchiveCandidate>>, DlxLifecycleError>
    {
        push(&self.events, "claim");
        let Ok(mut candidates) = self.candidates.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::ClaimArchiveCandidates,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        Ok(candidates
            .pop_front()
            .unwrap_or_default()
            .into_iter()
            .map(|candidate| {
                let claim = candidate.canonical().dead_letter_id().clone();
                ClaimedArchiveCandidate::new(claim, candidate)
            })
            .collect())
    }

    async fn record_verified_receipt(
        &self,
        claim: &DeadLetterId,
        receipt: VerifiedArchiveReceipt,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
        assert_eq!(claim, receipt.dead_letter_id());
        assert_eq!(receipt.object_lock_mode().as_str(), "COMPLIANCE");
        assert_eq!(receipt.archive_version_id().as_str(), "archive-version-1");
        assert_eq!(receipt.archive_key_ref().version().as_u32(), 7);
        push(&self.events, "receipt");
        let Ok(mut outcomes) = self.receipt_outcomes.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::RecordArchiveReceipt,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        if let Some(outcome) = outcomes.pop_front() {
            return outcome;
        }
        Ok(ReceiptCasOutcome::Applied)
    }

    async fn settle_archive_failure(
        &self,
        _claim: DeadLetterId,
        _failure: DlxLifecycleError,
    ) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError> {
        push(&self.events, "settle_failure");
        Ok(ArchiveClaimSettleOutcome::Applied)
    }

    async fn purge_verified(&self) -> Result<u64, DlxLifecycleError> {
        push(&self.events, "purge");
        Ok(1)
    }

    async fn claim_expired_receipts(
        &self,
    ) -> Result<Vec<ExpiredArchiveReceipt>, DlxLifecycleError> {
        push(&self.events, "reconcile");
        let Ok(mut expired) = self.expired.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::ClaimExpiredReceipts,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        Ok(expired.take().unwrap_or_default())
    }

    async fn delete_expired_receipt(
        &self,
        proof: MissingArchiveProof,
    ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
        assert_eq!(
            proof.object_key().as_str(),
            DlxArchiveObjectKey::from_dead_letter(proof.dead_letter_id()).as_str()
        );
        assert_eq!(proof.archive_version_id().as_str(), "archive-version-1");
        push(&self.events, "delete_receipt");
        Ok(ReceiptCasOutcome::Applied)
    }
}

#[derive(Clone)]
struct VersionedKeyProvider {
    current_version: Arc<AtomicU32>,
    decrypted_versions: Arc<Mutex<Vec<u32>>>,
}

impl VersionedKeyProvider {
    fn new(version: u32) -> Self {
        Self {
            current_version: Arc::new(AtomicU32::new(version)),
            decrypted_versions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn rotate_to(&self, version: u32) {
        self.current_version.store(version, Ordering::Release);
    }

    fn decrypted_versions(&self) -> Vec<u32> {
        self.decrypted_versions.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |seen| seen.clone(),
        )
    }
}

impl KeyProvider for VersionedKeyProvider {
    async fn encrypt(
        &self,
        key: KeyName,
        plaintext: Plaintext,
        _aad: rss_data_protection::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        let version = self.current_version.load(Ordering::Acquire);
        let mut ciphertext = version.to_be_bytes().to_vec();
        ciphertext.extend_from_slice(plaintext.expose());
        Ok(EncryptOutput::new(
            ciphertext,
            KeyRef::new(key, KeyVersion::new(version)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        _aad: rss_data_protection::DerivedAad,
    ) -> Result<Plaintext, KeyProviderError> {
        let bytes = ciphertext.into_bytes();
        let Some(version_bytes) = bytes.get(..4).and_then(|raw| raw.try_into().ok()) else {
            return Err(test_key_rejected("missing version header"));
        };
        let persisted_version = KeyVersion::new(u32::from_be_bytes(version_bytes));
        if !persisted_version.ct_eq(&key.version()) {
            return Err(test_key_rejected("persisted key version mismatch"));
        }
        if let Ok(mut seen) = self.decrypted_versions.lock() {
            seen.push(key.version().as_u32());
        }
        Ok(Plaintext::new(bytes[4..].to_vec()))
    }

    async fn rewrap(
        &self,
        ciphertext: RedactedBytes,
        key: KeyRef,
        _aad: rss_data_protection::DerivedAad,
    ) -> Result<EncryptOutput, KeyProviderError> {
        Ok(EncryptOutput::new(ciphertext.into_bytes(), key))
    }

    async fn shutdown(&self) -> Result<(), KeyProviderError> {
        Ok(())
    }
}

fn test_key_rejected(message: &'static str) -> KeyProviderError {
    KeyProviderError::new(
        diport::key_provider::KeyProviderErrorKind::Rejected,
        std::io::Error::other(message),
    )
}

#[tokio::test]
async fn lifecycle_key_provider_fake_rejects_mismatched_persisted_version() -> TestResult {
    let mut ciphertext = KeyVersion::new(7).as_u32().to_be_bytes().to_vec();
    ciphertext.extend_from_slice(b"canonical");
    let result = VersionedKeyProvider::new(8)
        .decrypt(
            RedactedBytes::new(ciphertext),
            KeyRef::new(KeyName::try_new("dlx-archive")?, KeyVersion::new(8)),
            rss_data_protection::ProtectionContext::authorized_maintenance(
                tenant()?,
                "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc",
                "canonical_archive",
                1,
            )?
            .derive(),
        )
        .await;
    assert!(matches!(
        result,
        Err(ref error) if error.kind() == diport::key_provider::KeyProviderErrorKind::Rejected
    ));
    Ok(())
}

enum StoreMode {
    Create,
    TransientOnce,
    Existing(DlxArchiveCiphertext),
    ExistingGetMissing,
    ExistingHeadMissing(DlxArchiveCiphertext),
    VersionDrift(DlxArchiveCiphertext),
    PresentWithChecksum(ArchiveChecksum),
    Missing,
}

struct FakeStore {
    mode: Mutex<StoreMode>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl FakeStore {
    fn new(mode: StoreMode, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            mode: Mutex::new(mode),
            events,
        }
    }
}

impl DlxArchiveStore for FakeStore {
    type ObjectKey = DlxArchiveObjectKey;

    async fn put_if_absent(
        &self,
        request: DlxArchivePutRequest<Self::ObjectKey>,
    ) -> Result<DlxArchivePutOutcome, DlxLifecycleError> {
        push(&self.events, "put");
        let Ok(mut mode) = self.mode.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::PutArchive,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        match &*mode {
            StoreMode::Create => {
                let metadata = DlxArchiveObjectMetadata::new(
                    request.checksum(),
                    archive_version_id()?,
                    NOW + 31 * 86_400,
                );
                *mode = StoreMode::Existing(request.ciphertext().clone());
                Ok(DlxArchivePutOutcome::Created(metadata))
            }
            StoreMode::TransientOnce => {
                *mode = StoreMode::Create;
                Err(DlxLifecycleError::new(
                    DlxLifecycleOperation::PutArchive,
                    DlxLifecycleReason::ProviderUnavailable,
                ))
            }
            StoreMode::Existing(ciphertext)
            | StoreMode::ExistingHeadMissing(ciphertext)
            | StoreMode::VersionDrift(ciphertext) => Ok(DlxArchivePutOutcome::AlreadyExists(
                DlxArchiveObjectMetadata::new(
                    ArchiveChecksum::sha256(ciphertext.ciphertext().as_bytes()),
                    archive_version_id()?,
                    NOW + 31 * 86_400,
                ),
            )),
            StoreMode::ExistingGetMissing => Ok(DlxArchivePutOutcome::AlreadyExists(
                DlxArchiveObjectMetadata::new(
                    ArchiveChecksum::sha256(b"missing"),
                    archive_version_id()?,
                    NOW + 31 * 86_400,
                ),
            )),
            StoreMode::PresentWithChecksum(_) | StoreMode::Missing => Err(DlxLifecycleError::new(
                DlxLifecycleOperation::PutArchive,
                DlxLifecycleReason::InternalInvariant,
            )),
        }
    }

    async fn get_ciphertext(
        &self,
        _key: &DlxArchiveObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<Option<DlxArchiveCiphertext>, DlxLifecycleError> {
        push(&self.events, "get");
        let Ok(mode) = self.mode.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::GetArchive,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        if version_id.as_str() != "archive-version-1" {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::GetArchive,
                DlxLifecycleReason::VersionDrift,
            ));
        }
        match &*mode {
            StoreMode::Existing(ciphertext)
            | StoreMode::ExistingHeadMissing(ciphertext)
            | StoreMode::VersionDrift(ciphertext) => Ok(Some(ciphertext.clone())),
            _ => Ok(None),
        }
    }

    async fn head(
        &self,
        _key: &DlxArchiveObjectKey,
        version_id: &ArchiveVersionId,
    ) -> Result<DlxArchiveHeadOutcome, DlxLifecycleError> {
        push(&self.events, "head");
        let Ok(mode) = self.mode.lock() else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::InternalInvariant,
            ));
        };
        if version_id.as_str() != "archive-version-1" {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::VersionDrift,
            ));
        }
        match &*mode {
            StoreMode::Existing(ciphertext) => Ok(DlxArchiveHeadOutcome::Present(
                DlxArchiveObjectMetadata::new(
                    ArchiveChecksum::sha256(ciphertext.ciphertext().as_bytes()),
                    archive_version_id()?,
                    NOW + 31 * 86_400,
                ),
            )),
            StoreMode::VersionDrift(ciphertext) => Ok(DlxArchiveHeadOutcome::Present(
                DlxArchiveObjectMetadata::new(
                    ArchiveChecksum::sha256(ciphertext.ciphertext().as_bytes()),
                    ArchiveVersionId::try_from_provider("archive-version-2")?,
                    NOW + 31 * 86_400,
                ),
            )),
            StoreMode::PresentWithChecksum(checksum) => Ok(DlxArchiveHeadOutcome::Present(
                DlxArchiveObjectMetadata::new(*checksum, archive_version_id()?, NOW + 31 * 86_400),
            )),
            StoreMode::ExistingHeadMissing(_) => Ok(DlxArchiveHeadOutcome::Missing),
            StoreMode::Missing => Ok(DlxArchiveHeadOutcome::Missing),
            _ => Err(DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::InternalInvariant,
            )),
        }
    }
}

fn event_snapshot(events: &Arc<Mutex<Vec<&'static str>>>) -> Vec<&'static str> {
    events
        .lock()
        .map_or_else(|_| Vec::new(), |events| events.clone())
}

#[tokio::test]
async fn put_precedes_receipt_and_receipt_precedes_purge() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(
            vec![candidate("3ca9df50120b", b"capsule")?],
            vec![],
            Arc::clone(&events),
        ),
        FakeStore::new(StoreMode::Create, Arc::clone(&events)),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Healthy);
    assert_eq!(report.archived(), 1);
    assert_eq!(report.purged(), 1);
    assert_eq!(
        event_snapshot(&events),
        vec!["claim", "put", "receipt", "reconcile", "purge"]
    );
    Ok(())
}

#[tokio::test]
async fn crash_retry_uses_persisted_archive_key_version_after_rotation() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let repository = FakeRepository::with_archive_retries(
        candidate("3ca9df50120b", b"capsule")?,
        candidate("3ca9df50120b", b"capsule")?,
        vec![
            Err(DlxLifecycleError::new(
                DlxLifecycleOperation::RecordArchiveReceipt,
                DlxLifecycleReason::ProviderUnavailable,
            )),
            Ok(ReceiptCasOutcome::Applied),
        ],
        Arc::clone(&events),
    );
    let key_provider = VersionedKeyProvider::new(7);
    let lifecycle = DlxLifecycle::new(
        repository,
        FakeStore::new(StoreMode::Create, Arc::clone(&events)),
        key_provider.clone(),
        archive_key()?,
    );

    let interrupted = lifecycle.tick(NOW).await;
    assert_eq!(interrupted.health(), DlxLifecycleHealth::Degraded);
    assert_eq!(interrupted.archived(), 0);
    assert_eq!(interrupted.purged(), 0);

    key_provider.rotate_to(8);
    let recovered = lifecycle.tick(NOW).await;
    assert_eq!(recovered.health(), DlxLifecycleHealth::Healthy);
    assert_eq!(recovered.archived(), 1);
    assert_eq!(recovered.purged(), 1);
    assert_eq!(
        event_snapshot(&events),
        vec![
            "claim",
            "put",
            "receipt",
            "settle_failure",
            "claim",
            "put",
            "get",
            "head",
            "receipt",
            "reconcile",
            "purge"
        ]
    );
    assert_eq!(key_provider.decrypted_versions(), vec![7]);
    Ok(())
}

#[tokio::test]
async fn transient_item_continues_batch_but_suppresses_all_deletion() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(
            vec![
                candidate("3ca9df50120b", b"one")?,
                candidate("3ca9df50120c", b"two")?,
            ],
            vec![],
            Arc::clone(&events),
        ),
        FakeStore::new(StoreMode::TransientOnce, Arc::clone(&events)),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Degraded);
    assert_eq!(
        report.primary_failure(),
        Some(DlxLifecycleError::new(
            DlxLifecycleOperation::PutArchive,
            DlxLifecycleReason::ProviderUnavailable,
        ))
    );
    assert_eq!(report.archived(), 1);
    assert_eq!(report.purged(), 0);
    assert_eq!(
        event_snapshot(&events),
        vec!["claim", "put", "settle_failure", "put", "receipt"]
    );
    Ok(())
}

#[tokio::test]
async fn existing_object_semantic_conflict_is_unhealthy_and_never_purges() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let existing = versioned_ciphertext(7, b"different")?;
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(
            vec![candidate("3ca9df50120b", b"capsule")?],
            vec![],
            Arc::clone(&events),
        ),
        FakeStore::new(StoreMode::Existing(existing), Arc::clone(&events)),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Unhealthy);
    assert_eq!(
        report.primary_failure(),
        Some(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::CanonicalMismatch,
        ))
    );
    assert_eq!(report.purged(), 0);
    assert_eq!(
        event_snapshot(&events),
        vec!["claim", "put", "get", "settle_failure"]
    );
    Ok(())
}

#[tokio::test]
async fn existing_object_with_equal_canonical_record_backfills_receipt() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let record = ArchiveCanonicalRecord::new(
        id("3ca9df50120b")?,
        tenant()?,
        safe_metadata()?,
        Plaintext::new(b"capsule".to_vec()),
    );
    let existing = versioned_ciphertext(7, record.encode().expose())?;
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(
            vec![candidate("3ca9df50120b", b"capsule")?],
            vec![],
            Arc::clone(&events),
        ),
        FakeStore::new(StoreMode::Existing(existing), Arc::clone(&events)),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Healthy);
    assert_eq!(report.archived(), 1);
    assert_eq!(report.purged(), 1);
    assert_eq!(
        event_snapshot(&events),
        vec![
            "claim",
            "put",
            "get",
            "head",
            "receipt",
            "reconcile",
            "purge"
        ]
    );
    Ok(())
}

fn canonical_ciphertext() -> TestResult<DlxArchiveCiphertext> {
    let record = ArchiveCanonicalRecord::new(
        id("3ca9df50120b")?,
        tenant()?,
        safe_metadata()?,
        Plaintext::new(b"capsule".to_vec()),
    );
    versioned_ciphertext(7, record.encode().expose())
}

fn versioned_ciphertext(version: u32, plaintext: &[u8]) -> TestResult<DlxArchiveCiphertext> {
    let mut bytes = version.to_be_bytes().to_vec();
    bytes.extend_from_slice(plaintext);
    Ok(DlxArchiveCiphertext::new(
        RedactedBytes::new(bytes),
        key_ref_at(version)?,
    ))
}

#[tokio::test]
async fn already_exists_races_are_transient_and_never_purge() -> TestResult {
    for (mode, expected) in [
        (
            StoreMode::ExistingGetMissing,
            DlxLifecycleError::new(
                DlxLifecycleOperation::GetArchive,
                DlxLifecycleReason::ObjectMissing,
            ),
        ),
        (
            StoreMode::ExistingHeadMissing(canonical_ciphertext()?),
            DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::ObjectMissing,
            ),
        ),
        (
            StoreMode::VersionDrift(canonical_ciphertext()?),
            DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::VersionDrift,
            ),
        ),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let lifecycle = DlxLifecycle::new(
            FakeRepository::new(
                vec![candidate("3ca9df50120b", b"capsule")?],
                vec![],
                Arc::clone(&events),
            ),
            FakeStore::new(mode, Arc::clone(&events)),
            VersionedKeyProvider::new(7),
            archive_key()?,
        );
        let report = lifecycle.tick(NOW).await;
        assert_eq!(report.health(), DlxLifecycleHealth::Degraded);
        assert_eq!(report.primary_failure(), Some(expected));
        assert_eq!(report.purged(), 0);
        assert!(!event_snapshot(&events).contains(&"purge"));
    }
    Ok(())
}

#[tokio::test]
async fn reconcile_present_checksum_conflict_is_invariant() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let receipt_id = id("3ca9df50120b")?;
    let key = DlxArchiveObjectKey::from_dead_letter(&receipt_id);
    let expired = ExpiredArchiveReceipt::from_persisted(
        receipt_id,
        tenant()?,
        key.as_str(),
        ArchiveChecksum::sha256(b"receipt-ciphertext"),
        archive_version_id()?,
    )?;
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(vec![], vec![expired], Arc::clone(&events)),
        FakeStore::new(
            StoreMode::PresentWithChecksum(ArchiveChecksum::sha256(b"other-ciphertext")),
            Arc::clone(&events),
        ),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Unhealthy);
    assert_eq!(
        report.primary_failure(),
        Some(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::ChecksumMismatch,
        ))
    );
    assert_eq!(report.receipts_reconciled(), 0);
    assert_eq!(report.purged(), 0);
    Ok(())
}

#[tokio::test]
async fn head_missing_is_the_only_path_that_reconciles_expired_receipt() -> TestResult {
    let events = Arc::new(Mutex::new(Vec::new()));
    let receipt_id = id("3ca9df50120b")?;
    let key = DlxArchiveObjectKey::from_dead_letter(&receipt_id);
    let expired = ExpiredArchiveReceipt::from_persisted(
        receipt_id,
        tenant()?,
        key.as_str(),
        ArchiveChecksum::sha256(b"ciphertext"),
        archive_version_id()?,
    )?;
    let lifecycle = DlxLifecycle::new(
        FakeRepository::new(vec![], vec![expired], Arc::clone(&events)),
        FakeStore::new(StoreMode::Missing, Arc::clone(&events)),
        VersionedKeyProvider::new(7),
        archive_key()?,
    );
    let report = lifecycle.tick(NOW).await;
    assert_eq!(report.health(), DlxLifecycleHealth::Healthy);
    assert_eq!(report.receipts_reconciled(), 1);
    assert_eq!(
        event_snapshot(&events),
        vec!["claim", "reconcile", "head", "delete_receipt", "purge"]
    );
    Ok(())
}
