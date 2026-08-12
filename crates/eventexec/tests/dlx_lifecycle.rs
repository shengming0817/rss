use std::error::Error;

use diport::ObjectLockMode;
use eventexec::{
    ArchiveCanonicalRecord, DeadLetterId, DlxArchiveKeyName, DlxArchiveObjectKey,
    DlxArchiveSafeMetadata, DlxArchiveSafeMetadataInput, DlxHotKeyName, DlxLifecycleHealth,
    DlxMetadataDigest, RetentionOutcome, RetentionTarget, WorkerHealth, apply_dlx_lifecycle_health,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn dead_letter_id() -> TestResult<DeadLetterId> {
    Ok(DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")?)
}

#[test]
fn archive_object_key_is_derived_from_typed_id() -> TestResult {
    let id = dead_letter_id()?;
    let key = DlxArchiveObjectKey::from_dead_letter(&id);
    assert_eq!(
        key.as_str(),
        "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc"
    );
    Ok(())
}

#[test]
fn lifecycle_labels_are_closed_and_stable() {
    assert_eq!(RetentionTarget::DeadLetter.as_label(), "dead_letter");
    assert_eq!(RetentionOutcome::Invariant.as_label(), "invariant");
    assert_eq!(ObjectLockMode::Compliance.as_str(), "COMPLIANCE");
}

#[test]
fn hot_and_archive_keys_are_distinct_configuration_types() {
    let hot = DlxHotKeyName::try_new("dlx-hot");
    let archive = DlxArchiveKeyName::try_new("dlx-archive");
    assert!(hot.is_ok());
    assert!(archive.is_ok());
}

#[test]
fn canonical_archive_envelope_matches_committed_bytes() -> TestResult {
    let tenant = rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")?;
    let metadata = DlxArchiveSafeMetadata::try_new(DlxArchiveSafeMetadataInput {
        message_id: "message-17".to_string(),
        producer_domain: "identity".to_string(),
        consumer_domain: Some("audit".to_string()),
        contract_id: "identity.session-created.v1".to_string(),
        topic: "identity.session.created".to_string(),
        consumer_group: Some("audit.projector".to_string()),
        source_kind: diport::DeadLetterSource::Consumer,
        error_summary: "retry budget exhausted".to_string(),
        num_attempts: 10,
        first_attempt_epoch_micros: 1_700_000_000_123_456,
        last_attempt_epoch_micros: 1_700_000_100_654_321,
        payload_len: 42,
        metadata_digest: DlxMetadataDigest::from_sha256_bytes([0xAB; 32]),
    })?;
    let record = ArchiveCanonicalRecord::new(
        dead_letter_id()?,
        tenant,
        metadata,
        secure::Plaintext::new(b"capsule-v3".to_vec()),
    );
    assert_eq!(
        record.encode().expose(),
        include_bytes!("fixtures/dlx_archive_v1.bin")
    );
    Ok(())
}

#[test]
fn invariant_health_is_unhealthy_and_latched() {
    let health = WorkerHealth::healthy();
    apply_dlx_lifecycle_health(&health, DlxLifecycleHealth::Unhealthy);
    assert_eq!(health.status(), primitives::HealthStatus::Unhealthy);
    assert_eq!(health.detail(), "invariant");
    apply_dlx_lifecycle_health(&health, DlxLifecycleHealth::Healthy);
    assert_eq!(health.status(), primitives::HealthStatus::Unhealthy);
    assert_eq!(health.detail(), "invariant");
}
