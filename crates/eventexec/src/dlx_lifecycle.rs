//! Verified dead-letter HOT → WORM → COLD lifecycle.
//!
//! The service owns the proof types and state transition. Providers can return observations, but
//! cannot manufacture a [`VerifiedArchiveReceipt`] or [`MissingArchiveProof`]. The archive store
//! capability deliberately has no delete/list surface.

use diport::{
    ArchiveChecksum, ArchiveVersionId, DlxArchiveHeadOutcome, DlxArchiveObjectMetadata,
    DlxArchivePutOutcome, DlxArchivePutRequest, DlxArchiveStore, DlxLifecycleError,
    DlxLifecycleErrorKind, DlxLifecycleOperation, DlxLifecycleReason, DlxLifecycleRepository,
    KeyName, KeyParseError, KeyProvider, KeyRef, ObjectLockMode,
};

use crate::dlq::DeadLetterId;
use crate::dlx_archive_cipher::DlxArchiveCrypto;
use crate::dlx_archive_record::{ArchiveCanonicalRecord, DlxArchiveCandidate};

/// Exact global HOT retention window. A receipt is minted only while the WORM object remains
/// locked strictly beyond this entire window, so later HOT purge cannot outrun cold retention.
pub const DLX_HOT_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Stable, low-cardinality retention target labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionTarget {
    OutboxPublished,
    InboxReceipts,
    DeadLetter,
}

impl RetentionTarget {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::OutboxPublished => "outbox_published",
            Self::InboxReceipts => "inbox_receipts",
            Self::DeadLetter => "dead_letter",
        }
    }
}

/// Stable lifecycle outcome labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionOutcome {
    Success,
    Transient,
    Invariant,
}

impl RetentionOutcome {
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Transient => "transient",
            Self::Invariant => "invariant",
        }
    }
}

/// Hot replay-capsule key. Its private field prevents archive-key substitution at wiring sites.
#[derive(Debug, Clone)]
pub struct DlxHotKeyName(KeyName);

impl DlxHotKeyName {
    pub fn try_new(name: impl Into<String>) -> Result<Self, KeyParseError> {
        KeyName::try_new(name).map(Self)
    }

    pub fn as_key_name(&self) -> &KeyName {
        &self.0
    }
}

/// Cold archive key. It is intentionally not convertible from [`DlxHotKeyName`].
#[derive(Debug, Clone)]
pub struct DlxArchiveKeyName(KeyName);

impl DlxArchiveKeyName {
    pub fn try_new(name: impl Into<String>) -> Result<Self, KeyParseError> {
        KeyName::try_new(name).map(Self)
    }

    pub fn as_key_name(&self) -> &KeyName {
        &self.0
    }
}

/// Archive key derived only from a parsed dead-letter id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DlxArchiveObjectKey(String);

impl DlxArchiveObjectKey {
    pub fn from_dead_letter(id: &DeadLetterId) -> Self {
        Self(format!("dead-letter/{}.v1.enc", id.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Proof consumed by Postgres before purge. Construction stays inside this lifecycle module.
#[derive(Debug)]
pub struct VerifiedArchiveReceipt {
    id: DeadLetterId,
    tenant: vocab::TenantId,
    object_key: DlxArchiveObjectKey,
    checksum: ArchiveChecksum,
    archive_version_id: ArchiveVersionId,
    archive_key_ref: KeyRef,
    retain_until_epoch_secs: i64,
    verified_at_epoch_secs: i64,
}

impl VerifiedArchiveReceipt {
    pub fn dead_letter_id(&self) -> &DeadLetterId {
        &self.id
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn object_key(&self) -> &DlxArchiveObjectKey {
        &self.object_key
    }

    pub fn checksum(&self) -> ArchiveChecksum {
        self.checksum
    }

    pub fn archive_version_id(&self) -> &ArchiveVersionId {
        &self.archive_version_id
    }

    pub fn archive_key_ref(&self) -> &KeyRef {
        &self.archive_key_ref
    }

    pub const fn object_lock_mode(&self) -> ObjectLockMode {
        ObjectLockMode::Compliance
    }

    pub fn retain_until_epoch_secs(&self) -> i64 {
        self.retain_until_epoch_secs
    }

    pub fn verified_at_epoch_secs(&self) -> i64 {
        self.verified_at_epoch_secs
    }
}

/// Receipt whose Object Lock retention has expired and is eligible for HEAD reconciliation.
#[derive(Debug, Clone)]
pub struct ExpiredArchiveReceipt {
    id: DeadLetterId,
    tenant: vocab::TenantId,
    object_key: DlxArchiveObjectKey,
    checksum: ArchiveChecksum,
    archive_version_id: ArchiveVersionId,
}

impl ExpiredArchiveReceipt {
    pub fn from_persisted(
        id: DeadLetterId,
        tenant: vocab::TenantId,
        object_key: &str,
        checksum: ArchiveChecksum,
        archive_version_id: ArchiveVersionId,
    ) -> Result<Self, DlxLifecycleError> {
        let derived = DlxArchiveObjectKey::from_dead_letter(&id);
        if derived.as_str() != object_key {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::DecodeExpiredReceipt,
                DlxLifecycleReason::InvalidPersistedData,
            ));
        }
        Ok(Self {
            id,
            tenant,
            object_key: derived,
            checksum,
            archive_version_id,
        })
    }

    pub fn dead_letter_id(&self) -> &DeadLetterId {
        &self.id
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }

    pub fn object_key(&self) -> &DlxArchiveObjectKey {
        &self.object_key
    }

    pub fn checksum(&self) -> ArchiveChecksum {
        self.checksum
    }

    pub fn archive_version_id(&self) -> &ArchiveVersionId {
        &self.archive_version_id
    }
}

/// HEAD-missing proof consumed by the receipt CAS. It has no public constructor.
#[derive(Debug)]
pub struct MissingArchiveProof {
    receipt: ExpiredArchiveReceipt,
}

impl MissingArchiveProof {
    pub fn dead_letter_id(&self) -> &DeadLetterId {
        self.receipt.dead_letter_id()
    }

    pub fn tenant(&self) -> vocab::TenantId {
        self.receipt.tenant()
    }

    pub fn object_key(&self) -> &DlxArchiveObjectKey {
        self.receipt.object_key()
    }

    pub fn checksum(&self) -> ArchiveChecksum {
        self.receipt.checksum()
    }

    pub fn archive_version_id(&self) -> &ArchiveVersionId {
        self.receipt.archive_version_id()
    }
}

/// Lifecycle health mapping used by readyz without arbitrary labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlxLifecycleHealth {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Typed health funnel for assembly-owned lifecycle loops. An invariant state is latched by
/// [`crate::WorkerHealth`] and cannot be healed by a later tick.
pub fn apply_dlx_lifecycle_health(
    health: &crate::WorkerHealth,
    lifecycle_health: DlxLifecycleHealth,
) {
    match lifecycle_health {
        DlxLifecycleHealth::Healthy => health.mark_healthy(),
        DlxLifecycleHealth::Degraded => health.mark_degraded(),
        DlxLifecycleHealth::Unhealthy => health.mark_invariant(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DlxLifecycleTickReport {
    health: DlxLifecycleHealth,
    archived: u64,
    purged: u64,
    receipts_reconciled: u64,
    primary_failure: Option<DlxLifecycleError>,
}

impl DlxLifecycleTickReport {
    pub fn health(self) -> DlxLifecycleHealth {
        self.health
    }

    pub fn outcome(self) -> RetentionOutcome {
        match self.health {
            DlxLifecycleHealth::Healthy => RetentionOutcome::Success,
            DlxLifecycleHealth::Degraded => RetentionOutcome::Transient,
            DlxLifecycleHealth::Unhealthy => RetentionOutcome::Invariant,
        }
    }

    pub fn archived(self) -> u64 {
        self.archived
    }

    pub fn purged(self) -> u64 {
        self.purged
    }

    pub fn receipts_reconciled(self) -> u64 {
        self.receipts_reconciled
    }

    /// The first failure at the highest severity observed in this tick.
    ///
    /// A later invariant replaces an earlier transient; failures of equal severity preserve the
    /// first observation. This gives operators a deterministic diagnostic without unbounded data.
    pub fn primary_failure(self) -> Option<DlxLifecycleError> {
        self.primary_failure
    }
}

/// Dedicated state machine. Any transient failure keeps HOT rows and suppresses purge for the
/// entire tick; an invariant failure additionally marks the worker Unhealthy.
pub struct DlxLifecycle<R, S, K> {
    repository: R,
    store: S,
    crypto: DlxArchiveCrypto<K>,
}

impl<R, S, K> DlxLifecycle<R, S, K>
where
    R: DlxLifecycleRepository<
            ArchiveCandidate = DlxArchiveCandidate,
            VerifiedReceipt = VerifiedArchiveReceipt,
            ExpiredReceipt = ExpiredArchiveReceipt,
            MissingProof = MissingArchiveProof,
        >,
    S: DlxArchiveStore<ObjectKey = DlxArchiveObjectKey>,
    K: KeyProvider,
{
    pub fn new(repository: R, store: S, key_provider: K, archive_key: DlxArchiveKeyName) -> Self {
        Self {
            repository,
            store,
            crypto: DlxArchiveCrypto::new(key_provider, archive_key),
        }
    }

    pub async fn tick(&self, now_epoch_secs: i64) -> DlxLifecycleTickReport {
        let candidates = match self.repository.claim_archive_candidates().await {
            Ok(candidates) => candidates,
            Err(error) => return report_for_error(error),
        };
        let mut report = DlxLifecycleTickReport {
            health: DlxLifecycleHealth::Healthy,
            archived: 0,
            purged: 0,
            receipts_reconciled: 0,
            primary_failure: None,
        };
        for claimed in candidates {
            let (claim, candidate) = claimed.into_parts();
            match self.archive_one(&candidate, now_epoch_secs).await {
                Ok(receipt) => match self
                    .repository
                    .record_verified_receipt(&claim, receipt)
                    .await
                {
                    Ok(_) => report.archived = report.archived.saturating_add(1),
                    Err(error) => {
                        self.settle_archive_failure(claim, error, &mut report).await;
                    }
                },
                Err(error) => {
                    self.settle_archive_failure(claim, error, &mut report).await;
                }
            }
        }
        if report.health != DlxLifecycleHealth::Healthy {
            return report;
        }
        self.reconcile_receipts(&mut report).await;
        if report.health != DlxLifecycleHealth::Healthy {
            return report;
        }
        match self.repository.purge_verified().await {
            Ok(purged) => report.purged = purged,
            Err(error) => merge_error(&mut report, error),
        }
        report
    }

    async fn settle_archive_failure(
        &self,
        claim: R::ArchiveClaim,
        failure: DlxLifecycleError,
        report: &mut DlxLifecycleTickReport,
    ) {
        merge_error(report, failure);
        if let Err(settle_error) = self.repository.settle_archive_failure(claim, failure).await {
            merge_error(report, settle_error);
        }
    }

    async fn archive_one(
        &self,
        candidate: &DlxArchiveCandidate,
        now_epoch_secs: i64,
    ) -> Result<VerifiedArchiveReceipt, DlxLifecycleError> {
        let canonical = candidate.canonical();
        let object_key = DlxArchiveObjectKey::from_dead_letter(canonical.dead_letter_id());
        let encoded = canonical.encode_for_archive()?;
        let sealed = self
            .crypto
            .seal(canonical.tenant(), encoded, &object_key)
            .await?;
        let request = DlxArchivePutRequest::new(object_key.clone(), sealed.clone());
        let expected_checksum = request.checksum();
        let outcome = self.store.put_if_absent(request).await?;
        let (metadata, key_ref, verified_checksum) = match outcome {
            DlxArchivePutOutcome::Created(metadata) => {
                (metadata, sealed.key_ref().clone(), expected_checksum)
            }
            DlxArchivePutOutcome::AlreadyExists(observed) => {
                let (metadata, key_ref) = self
                    .verify_existing(canonical, &object_key, observed)
                    .await?;
                let verified_checksum = metadata.checksum();
                (metadata, key_ref, verified_checksum)
            }
        };
        verify_worm_metadata(&metadata, verified_checksum, now_epoch_secs)?;
        Ok(VerifiedArchiveReceipt {
            id: canonical.dead_letter_id().clone(),
            tenant: canonical.tenant(),
            object_key,
            checksum: metadata.checksum(),
            archive_version_id: metadata.version_id().clone(),
            archive_key_ref: key_ref,
            retain_until_epoch_secs: metadata.retain_until_epoch_secs(),
            verified_at_epoch_secs: now_epoch_secs,
        })
    }

    async fn verify_existing(
        &self,
        canonical: &ArchiveCanonicalRecord,
        object_key: &DlxArchiveObjectKey,
        observed: DlxArchiveObjectMetadata,
    ) -> Result<(DlxArchiveObjectMetadata, KeyRef), DlxLifecycleError> {
        let version_id = observed.version_id();
        let Some(existing) = self.store.get_ciphertext(object_key, version_id).await? else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::GetArchive,
                DlxLifecycleReason::ObjectMissing,
            ));
        };
        let existing_checksum = ArchiveChecksum::sha256(existing.ciphertext().as_bytes());
        let key_ref = existing.key_ref().clone();
        let opened = self
            .crypto
            .open(canonical.tenant(), existing, object_key)
            .await?;
        if opened.expose() != canonical.encode_for_archive()?.expose() {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::VerifyArchive,
                DlxLifecycleReason::CanonicalMismatch,
            ));
        }
        let DlxArchiveHeadOutcome::Present(metadata) =
            self.store.head(object_key, version_id).await?
        else {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::ObjectMissing,
            ));
        };
        if metadata.version_id() != version_id {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::HeadArchive,
                DlxLifecycleReason::VersionDrift,
            ));
        }
        if metadata.checksum() != existing_checksum {
            return Err(DlxLifecycleError::new(
                DlxLifecycleOperation::VerifyArchive,
                DlxLifecycleReason::ChecksumMismatch,
            ));
        }
        Ok((metadata, key_ref))
    }

    async fn reconcile_receipts(&self, report: &mut DlxLifecycleTickReport) {
        let receipts = match self.repository.claim_expired_receipts().await {
            Ok(receipts) => receipts,
            Err(error) => {
                merge_error(report, error);
                return;
            }
        };
        for receipt in receipts {
            match self
                .store
                .head(receipt.object_key(), receipt.archive_version_id())
                .await
            {
                Ok(DlxArchiveHeadOutcome::Present(metadata))
                    if metadata.version_id() != receipt.archive_version_id() =>
                {
                    merge_error(
                        report,
                        DlxLifecycleError::new(
                            DlxLifecycleOperation::HeadArchive,
                            DlxLifecycleReason::VersionDrift,
                        ),
                    );
                }
                Ok(DlxArchiveHeadOutcome::Present(metadata))
                    if metadata.checksum() != receipt.checksum() =>
                {
                    merge_error(
                        report,
                        DlxLifecycleError::new(
                            DlxLifecycleOperation::VerifyArchive,
                            DlxLifecycleReason::ChecksumMismatch,
                        ),
                    );
                }
                Ok(DlxArchiveHeadOutcome::Present(_)) => {}
                Ok(DlxArchiveHeadOutcome::Missing) => {
                    let proof = MissingArchiveProof { receipt };
                    match self.repository.delete_expired_receipt(proof).await {
                        Ok(_) => {
                            report.receipts_reconciled =
                                report.receipts_reconciled.saturating_add(1);
                        }
                        Err(error) => merge_error(report, error),
                    }
                }
                Err(error) => merge_error(report, error),
            }
            if report.health == DlxLifecycleHealth::Unhealthy {
                return;
            }
        }
    }
}

fn verify_worm_metadata(
    metadata: &DlxArchiveObjectMetadata,
    expected_checksum: ArchiveChecksum,
    now_epoch_secs: i64,
) -> Result<(), DlxLifecycleError> {
    let minimum_retain_until = now_epoch_secs
        .checked_add(DLX_HOT_RETENTION_SECONDS)
        .ok_or_else(|| {
            DlxLifecycleError::new(
                DlxLifecycleOperation::VerifyArchive,
                DlxLifecycleReason::ArithmeticOverflow,
            )
        })?;
    if metadata.checksum() != expected_checksum {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::ChecksumMismatch,
        ));
    }
    if metadata.retain_until_epoch_secs() <= minimum_retain_until {
        return Err(DlxLifecycleError::new(
            DlxLifecycleOperation::VerifyArchive,
            DlxLifecycleReason::RetentionInvalid,
        ));
    }
    Ok(())
}

fn merge_error(report: &mut DlxLifecycleTickReport, error: DlxLifecycleError) {
    let replace_primary = match report.primary_failure {
        None => true,
        Some(current) => {
            current.kind() == DlxLifecycleErrorKind::Transient
                && error.kind() == DlxLifecycleErrorKind::Invariant
        }
    };
    if replace_primary {
        report.primary_failure = Some(error);
    }
    report.health = match error.kind() {
        DlxLifecycleErrorKind::Transient if report.health == DlxLifecycleHealth::Healthy => {
            DlxLifecycleHealth::Degraded
        }
        DlxLifecycleErrorKind::Transient => report.health,
        DlxLifecycleErrorKind::Invariant => DlxLifecycleHealth::Unhealthy,
    };
}

fn report_for_error(error: DlxLifecycleError) -> DlxLifecycleTickReport {
    let health = match error.kind() {
        DlxLifecycleErrorKind::Transient => DlxLifecycleHealth::Degraded,
        DlxLifecycleErrorKind::Invariant => DlxLifecycleHealth::Unhealthy,
    };
    DlxLifecycleTickReport {
        health,
        archived: 0,
        purged: 0,
        receipts_reconciled: 0,
        primary_failure: Some(error),
    }
}

#[cfg(test)]
#[path = "dlx_lifecycle_tests.rs"]
mod tests;
