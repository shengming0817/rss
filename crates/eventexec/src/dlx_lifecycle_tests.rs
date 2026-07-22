use diport::{
    ArchiveChecksum, ArchiveVersionId, DlxArchiveCiphertext, DlxArchiveObjectMetadata,
    DlxArchivePutRequest, DlxLifecycleError, DlxLifecycleErrorKind, DlxLifecycleOperation,
    DlxLifecycleReason, KeyName, KeyRef, KeyVersion, ObjectLockMode, ReceiptCasOutcome,
    RedactedBytes,
};

use super::*;

const NOW: i64 = 1_800_000_000;

fn id() -> Result<DeadLetterId, Box<dyn std::error::Error>> {
    Ok(DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")?)
}

fn tenant() -> Result<vocab::TenantId, Box<dyn std::error::Error>> {
    Ok(vocab::TenantId::parse(
        "11111111-2222-4333-8444-555555555555",
    )?)
}

fn key_ref() -> Result<KeyRef, Box<dyn std::error::Error>> {
    Ok(KeyRef::new(
        KeyName::try_new("dlx-archive")?,
        KeyVersion::new(3),
    ))
}

fn version_id() -> Result<ArchiveVersionId, Box<dyn std::error::Error>> {
    Ok(ArchiveVersionId::try_from_provider("archive-version-1")?)
}

#[test]
fn closed_labels_cover_every_variant() {
    let targets = [
        (RetentionTarget::OutboxPublished, "outbox_published"),
        (RetentionTarget::InboxReceipts, "inbox_receipts"),
        (RetentionTarget::DeadLetter, "dead_letter"),
        (
            RetentionTarget::CertificateRevocations,
            "certificate_revocations",
        ),
    ];
    for (value, expected) in targets {
        assert_eq!(value.as_label(), expected);
    }
    let outcomes = [
        (RetentionOutcome::Success, "success"),
        (RetentionOutcome::Transient, "transient"),
        (RetentionOutcome::Invariant, "invariant"),
    ];
    for (value, expected) in outcomes {
        assert_eq!(value.as_label(), expected);
    }
}

#[test]
fn key_checksum_and_put_request_accessors_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let hot = DlxHotKeyName::try_new("dlx-hot")?;
    let archive = DlxArchiveKeyName::try_new("dlx-archive")?;
    assert_eq!(hot.as_key_name().as_str(), "dlx-hot");
    assert_eq!(archive.as_key_name().as_str(), "dlx-archive");
    assert!(DlxHotKeyName::try_new("").is_err());
    assert!(DlxArchiveKeyName::try_new("").is_err());

    let object_key = DlxArchiveObjectKey::from_dead_letter(&id()?);
    let ciphertext = DlxArchiveCiphertext::new(RedactedBytes::new(b"cipher".to_vec()), key_ref()?);
    let request = DlxArchivePutRequest::new(object_key.clone(), ciphertext);
    assert_eq!(request.object_key(), &object_key);
    assert_eq!(request.ciphertext().ciphertext().as_bytes(), b"cipher");
    assert_eq!(request.ciphertext().key_ref().version().as_u32(), 3);
    assert_eq!(request.checksum().as_bytes().len(), 32);
    assert_eq!(request.checksum().as_hex().len(), 64);
    assert_eq!(
        format!("{:?}", request.checksum()),
        "ArchiveChecksum(<redacted>)"
    );
    assert_eq!(
        ArchiveChecksum::from_sha256_bytes(*request.checksum().as_bytes()),
        request.checksum()
    );
    Ok(())
}

#[test]
fn worm_metadata_validation_rejects_checksum_and_expiry() -> Result<(), Box<dyn std::error::Error>>
{
    let checksum = ArchiveChecksum::sha256(b"cipher");
    let other = ArchiveChecksum::sha256(b"other");
    let valid =
        DlxArchiveObjectMetadata::new(checksum, version_id()?, NOW + DLX_HOT_RETENTION_SECONDS + 1);
    assert!(verify_worm_metadata(&valid, checksum, NOW).is_ok());
    assert_eq!(valid.checksum(), checksum);
    assert_eq!(valid.object_lock_mode(), ObjectLockMode::Compliance);
    assert_eq!(
        valid.retain_until_epoch_secs(),
        NOW + DLX_HOT_RETENTION_SECONDS + 1
    );
    assert_eq!(valid.object_lock_mode().as_str(), "COMPLIANCE");

    let cases = [
        (
            DlxArchiveObjectMetadata::new(
                checksum,
                version_id()?,
                NOW + DLX_HOT_RETENTION_SECONDS + 1,
            ),
            other,
        ),
        (
            DlxArchiveObjectMetadata::new(checksum, version_id()?, NOW + DLX_HOT_RETENTION_SECONDS),
            checksum,
        ),
    ];
    for (metadata, expected) in cases {
        let error = verify_worm_metadata(&metadata, expected, NOW);
        assert!(matches!(
            error.map_err(DlxLifecycleError::kind),
            Err(DlxLifecycleErrorKind::Invariant)
        ));
    }
    Ok(())
}

fn coordinates() -> Result<
    (
        DeadLetterId,
        vocab::TenantId,
        DlxArchiveObjectKey,
        ArchiveChecksum,
    ),
    Box<dyn std::error::Error>,
> {
    let id = id()?;
    let tenant = tenant()?;
    let object_key = DlxArchiveObjectKey::from_dead_letter(&id);
    let checksum = ArchiveChecksum::sha256(b"cipher");
    Ok((id, tenant, object_key, checksum))
}

#[test]
fn verified_receipt_accessors_preserve_archive_coordinates()
-> Result<(), Box<dyn std::error::Error>> {
    let (id, tenant, object_key, checksum) = coordinates()?;
    let receipt = VerifiedArchiveReceipt {
        id: id.clone(),
        tenant,
        object_key: object_key.clone(),
        checksum,
        archive_version_id: version_id()?,
        archive_key_ref: key_ref()?,
        retain_until_epoch_secs: NOW + DLX_HOT_RETENTION_SECONDS + 1,
        verified_at_epoch_secs: NOW,
    };
    assert_eq!(receipt.dead_letter_id(), &id);
    assert_eq!(receipt.tenant(), tenant);
    assert_eq!(receipt.object_key(), &object_key);
    assert_eq!(receipt.checksum(), checksum);
    assert_eq!(receipt.archive_version_id().as_str(), "archive-version-1");
    assert_eq!(receipt.archive_key_ref().version().as_u32(), 3);
    assert_eq!(receipt.object_lock_mode(), ObjectLockMode::Compliance);
    assert_eq!(
        receipt.retain_until_epoch_secs(),
        NOW + DLX_HOT_RETENTION_SECONDS + 1
    );
    assert_eq!(receipt.verified_at_epoch_secs(), NOW);
    Ok(())
}

#[test]
fn missing_proof_accessors_preserve_receipt_cas_coordinates()
-> Result<(), Box<dyn std::error::Error>> {
    let (id, tenant, object_key, checksum) = coordinates()?;
    let expired = ExpiredArchiveReceipt::from_persisted(
        id.clone(),
        tenant,
        object_key.as_str(),
        checksum,
        version_id()?,
    )?;
    assert_eq!(expired.dead_letter_id(), &id);
    assert_eq!(expired.tenant(), tenant);
    assert_eq!(expired.object_key(), &object_key);
    assert_eq!(expired.checksum(), checksum);
    assert_eq!(expired.archive_version_id().as_str(), "archive-version-1");
    let proof = MissingArchiveProof { receipt: expired };
    assert_eq!(proof.dead_letter_id(), &id);
    assert_eq!(proof.tenant(), tenant);
    assert_eq!(proof.object_key(), &object_key);
    assert_eq!(proof.checksum(), checksum);
    assert_eq!(proof.archive_version_id().as_str(), "archive-version-1");
    Ok(())
}

#[test]
fn persisted_receipt_rejects_object_key_not_derived_from_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (id, tenant, _object_key, checksum) = coordinates()?;
    let invalid = ExpiredArchiveReceipt::from_persisted(
        id,
        tenant,
        "dead-letter/not-derived.v1.enc",
        checksum,
        version_id()?,
    );
    assert!(matches!(
        invalid.map_err(DlxLifecycleError::kind),
        Err(DlxLifecycleErrorKind::Invariant)
    ));
    Ok(())
}

#[test]
fn error_merge_is_closed_and_fail_closed() {
    let first = DlxLifecycleError::new(
        DlxLifecycleOperation::GetArchive,
        DlxLifecycleReason::ProviderUnavailable,
    );
    let second = DlxLifecycleError::new(
        DlxLifecycleOperation::VerifyArchive,
        DlxLifecycleReason::VersionDrift,
    );
    let invariant = DlxLifecycleError::new(
        DlxLifecycleOperation::VerifyArchive,
        DlxLifecycleReason::CanonicalMismatch,
    );
    let mut report = report_for_error(first);
    assert_eq!(report.health(), DlxLifecycleHealth::Degraded);
    assert_eq!(report.outcome(), RetentionOutcome::Transient);
    assert_eq!(report.primary_failure(), Some(first));
    assert_eq!(report.archived(), 0);
    assert_eq!(report.purged(), 0);
    assert_eq!(report.receipts_reconciled(), 0);
    merge_error(&mut report, second);
    assert_eq!(report.health(), DlxLifecycleHealth::Degraded);
    assert_eq!(report.primary_failure(), Some(first));
    merge_error(&mut report, invariant);
    assert_eq!(report.health(), DlxLifecycleHealth::Unhealthy);
    assert_eq!(report.outcome(), RetentionOutcome::Invariant);
    assert_eq!(report.primary_failure(), Some(invariant));
}

#[test]
fn reports_expose_only_closed_outcomes_and_counts() {
    let failure = DlxLifecycleError::new(
        DlxLifecycleOperation::VerifyArchive,
        DlxLifecycleReason::ChecksumMismatch,
    );
    let invariant = report_for_error(failure);
    assert_eq!(invariant.health(), DlxLifecycleHealth::Unhealthy);
    assert_eq!(invariant.primary_failure(), Some(failure));
    let healthy = DlxLifecycleTickReport {
        health: DlxLifecycleHealth::Healthy,
        archived: 2,
        purged: 3,
        receipts_reconciled: 4,
        primary_failure: None,
    };
    assert_eq!(healthy.outcome(), RetentionOutcome::Success);
    assert_eq!(healthy.archived(), 2);
    assert_eq!(healthy.purged(), 3);
    assert_eq!(healthy.receipts_reconciled(), 4);
    assert_eq!(healthy.primary_failure(), None);
    assert_eq!(ReceiptCasOutcome::Applied, ReceiptCasOutcome::Applied);
    assert_ne!(
        ReceiptCasOutcome::Applied,
        ReceiptCasOutcome::AlreadyApplied
    );
}
