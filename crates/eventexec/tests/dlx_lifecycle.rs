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
        producer_domain: "runtime".to_string(),
        consumer_domain: Some("observer".to_string()),
        contract_id: "runtime.fact-recorded.v1".to_string(),
        topic: "runtime.fact.recorded".to_string(),
        consumer_group: Some("runtime.projector".to_string()),
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
        b"rss-dlx-archive-v1\ndeadLetterId:018f31a8-893d-7a52-8e17-3ca9df50120b\ntenantId:11111111-2222-4333-8444-555555555555\nsourceKind:consumer\nmessageIdHex:6d6573736167652d3137\nproducerDomainHex:72756e74696d65\nconsumerDomainHex:6f62736572766572\ncontractIdHex:72756e74696d652e666163742d7265636f726465642e7631\ntopicHex:72756e74696d652e666163742e7265636f72646564\nconsumerGroupHex:72756e74696d652e70726f6a6563746f72\nerrorSummaryHex:72657472792062756467657420657868617573746564\nnumAttempts:10\nfirstAttemptEpochMicros:1700000000123456\nlastAttemptEpochMicros:1700000100654321\npayloadLength:42\nmetadataDigestSha256:abababababababababababababababababababababababababababababababab\ncapsuleLength:10\ncapsuleHex:63617073756c652d7633\n"
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
