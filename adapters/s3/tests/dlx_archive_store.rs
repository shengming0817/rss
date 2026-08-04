//! MinIO / S3 DLX archive store coverage (mock client).
//!
//! Cargo `[[test]] required-features = ["integration"]` is the sole eligibility owner;
//! `integration` transitively enables `backend`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_sdk_s3::error::ErrorMetadata;
use aws_sdk_s3::operation::get_bucket_lifecycle_configuration::GetBucketLifecycleConfigurationOutput;
use aws_sdk_s3::operation::get_bucket_versioning::GetBucketVersioningOutput;
use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
use aws_sdk_s3::operation::get_object_lock_configuration::GetObjectLockConfigurationOutput;
use aws_sdk_s3::operation::head_object::{HeadObjectError, HeadObjectOutput};
use aws_sdk_s3::operation::put_object::{PutObjectError, PutObjectOutput};
use aws_sdk_s3::primitives::{ByteStream, DateTime};
use aws_sdk_s3::types::error::{NoSuchKey, NotFound};
use aws_sdk_s3::types::{
    BucketVersioningStatus, DefaultRetention, ExpirationStatus, LifecycleExpiration, LifecycleRule,
    LifecycleRuleFilter, NoncurrentVersionExpiration, ObjectLockConfiguration, ObjectLockEnabled,
    ObjectLockMode, ObjectLockRetentionMode, ObjectLockRule,
};
use aws_smithy_mocks::{Rule, mock, mock_client};
use base64::Engine as _;
use diport::{
    ArchiveChecksum, ArchiveVersionId, Clock, DlxArchiveCiphertext, DlxArchiveHeadOutcome,
    DlxArchivePutOutcome, DlxArchivePutRequest, DlxArchiveStore, DlxLifecycleErrorKind, KeyRef,
    RedactedBytes,
};
use eventexec::DeadLetterId;
use s3::{S3DlxArchiveCapabilityError, S3DlxArchiveStore, VerifiedS3DlxArchiveStore};

const BUCKET: &str = "dlx-archive-test";
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;
const CANARY_BODY: &[u8] = b"rss-dlx-worm-capability-v2";
const NOW: i64 = 1_900_000_000;
const RETAIN_UNTIL: i64 = NOW + 31 * SECONDS_PER_DAY;
const VERSION_ID: &str = "archive-version-1";

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.0 as u64)
    }
}

struct ProbeRules {
    versioning: Rule,
    object_lock: Rule,
    lifecycle: Rule,
    canary_created: Rule,
    canary_exists: Rule,
    canary_created_head: Rule,
    canary_existing_head: Rule,
}

impl ProbeRules {
    fn healthy() -> Self {
        Self::healthy_at(NOW)
    }

    fn healthy_at(now: i64) -> Self {
        let canary_key = canary_key(now);
        let checksum = checksum_header(CANARY_BODY);
        let versioning = mock!(aws_sdk_s3::Client::get_bucket_versioning)
            .match_requests(|request| request.bucket() == Some(BUCKET))
            .then_output(|| {
                GetBucketVersioningOutput::builder()
                    .status(BucketVersioningStatus::Enabled)
                    .build()
            });
        let object_lock = mock!(aws_sdk_s3::Client::get_object_lock_configuration)
            .match_requests(|request| request.bucket() == Some(BUCKET))
            .then_output(|| object_lock_output(31, ObjectLockRetentionMode::Compliance));
        let lifecycle = mock!(aws_sdk_s3::Client::get_bucket_lifecycle_configuration)
            .match_requests(|request| request.bucket() == Some(BUCKET))
            .then_output(|| lifecycle_output(32, 32, ExpirationStatus::Enabled));
        let create_checksum = checksum.clone();
        let matcher_checksum = checksum.clone();
        let create_key = canary_key.clone();
        let canary_created = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(move |request| {
                request.bucket() == Some(BUCKET)
                    && request.key() == Some(create_key.as_str())
                    && request.if_none_match() == Some("*")
                    && request.checksum_sha256() == Some(matcher_checksum.as_str())
            })
            .then_output(move || {
                PutObjectOutput::builder()
                    .checksum_sha256(create_checksum.clone())
                    .version_id(VERSION_ID)
                    .build()
            });
        let exists_key = canary_key.clone();
        let canary_exists = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(move |request| {
                request.bucket() == Some(BUCKET)
                    && request.key() == Some(exists_key.as_str())
                    && request.if_none_match() == Some("*")
            })
            .then_error(precondition_failed);
        let canary_created_head = head_rule(
            canary_key.clone(),
            CANARY_BODY,
            now + 31 * SECONDS_PER_DAY,
            None,
        );
        let canary_existing_head =
            head_rule(canary_key, CANARY_BODY, now + 31 * SECONDS_PER_DAY, None);
        Self {
            versioning,
            object_lock,
            lifecycle,
            canary_created,
            canary_exists,
            canary_created_head,
            canary_existing_head,
        }
    }

    fn refs(&self) -> Vec<&Rule> {
        vec![
            &self.versioning,
            &self.object_lock,
            &self.lifecycle,
            &self.canary_created,
            &self.canary_created_head,
            &self.canary_exists,
            &self.canary_existing_head,
        ]
    }
}

fn canary_key(now: i64) -> String {
    format!(
        "__rss_capability_probe/dlx-worm-v2/{}",
        now / SECONDS_PER_DAY
    )
}

fn checksum_header(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(ArchiveChecksum::sha256(bytes).as_bytes())
}

fn precondition_failed() -> PutObjectError {
    PutObjectError::generic(ErrorMetadata::builder().code("PreconditionFailed").build())
}

fn access_denied() -> PutObjectError {
    PutObjectError::generic(ErrorMetadata::builder().code("AccessDenied").build())
}

fn object_lock_output(
    days: i32,
    mode: ObjectLockRetentionMode,
) -> GetObjectLockConfigurationOutput {
    let retention = DefaultRetention::builder().mode(mode).days(days).build();
    let rule = ObjectLockRule::builder()
        .default_retention(retention)
        .build();
    let configuration = ObjectLockConfiguration::builder()
        .object_lock_enabled(ObjectLockEnabled::Enabled)
        .rule(rule)
        .build();
    GetObjectLockConfigurationOutput::builder()
        .object_lock_configuration(configuration)
        .build()
}

#[allow(clippy::expect_used)]
fn lifecycle_output(
    current_days: i32,
    noncurrent_days: i32,
    status: ExpirationStatus,
) -> GetBucketLifecycleConfigurationOutput {
    let rule = LifecycleRule::builder()
        .id("rss-dlx-archive-expiration")
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .expiration(LifecycleExpiration::builder().days(current_days).build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(noncurrent_days)
                .build(),
        )
        .status(status)
        .build()
        .expect("valid lifecycle rule");
    GetBucketLifecycleConfigurationOutput::builder()
        .rules(rule)
        .build()
}

#[allow(clippy::expect_used)]
fn lifecycle_output_without_modern_filter() -> GetBucketLifecycleConfigurationOutput {
    let rule = LifecycleRule::builder()
        .id("rss-dlx-archive-expiration")
        .expiration(LifecycleExpiration::builder().days(32).build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(32)
                .build(),
        )
        .status(ExpirationStatus::Enabled)
        .build()
        .expect("valid lifecycle rule");
    GetBucketLifecycleConfigurationOutput::builder()
        .rules(rule)
        .build()
}

fn head_rule(
    key: impl Into<String>,
    body: &'static [u8],
    retain_until: i64,
    key_ref: Option<&'static str>,
) -> Rule {
    let key = key.into();
    mock!(aws_sdk_s3::Client::head_object)
        .match_requests(move |request| {
            request.bucket() == Some(BUCKET) && request.key() == Some(key.as_str())
        })
        .then_output(move || {
            let mut output = HeadObjectOutput::builder()
                .checksum_sha256(checksum_header(body))
                .version_id(VERSION_ID)
                .object_lock_mode(ObjectLockMode::Compliance)
                .object_lock_retain_until_date(DateTime::from_secs(retain_until));
            if let Some(key_ref) = key_ref {
                output = output.metadata("rss-dlx-key-ref", key_ref);
            }
            output.build()
        })
}

#[allow(clippy::expect_used)]
fn unverified(client: aws_sdk_s3::Client) -> S3DlxArchiveStore {
    unverified_at(client, NOW)
}

#[allow(clippy::expect_used)]
fn unverified_at(client: aws_sdk_s3::Client, now: i64) -> S3DlxArchiveStore {
    S3DlxArchiveStore::new(client, BUCKET, Arc::new(FixedClock(now))).expect("valid test store")
}

#[allow(clippy::expect_used)]
async fn verified(client: aws_sdk_s3::Client) -> VerifiedS3DlxArchiveStore {
    unverified(client)
        .verify()
        .await
        .expect("healthy test capability")
}

#[allow(clippy::expect_used)]
fn archive_version_id() -> ArchiveVersionId {
    ArchiveVersionId::try_from_provider(VERSION_ID).expect("fixed test version is valid")
}

#[allow(clippy::expect_used)]
fn object_key() -> eventexec::DlxArchiveObjectKey {
    let id = DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")
        .expect("valid test dead-letter id");
    eventexec::DlxArchiveObjectKey::from_dead_letter(&id)
}

#[allow(clippy::expect_used)]
fn archive_ciphertext(body: &[u8]) -> DlxArchiveCiphertext {
    DlxArchiveCiphertext::new(
        RedactedBytes::new(body.to_vec()),
        KeyRef::parse("dlx-archive:1").expect("valid test key ref"),
    )
}

#[test]
fn unverified_store_rejects_empty_archive_bucket() {
    let rule =
        mock!(aws_sdk_s3::Client::put_object).then_output(|| PutObjectOutput::builder().build());
    let client = mock_client!(aws_sdk_s3, &[&rule]);

    assert!(S3DlxArchiveStore::new(client, "", Arc::new(FixedClock(NOW))).is_err());
}

#[tokio::test]
async fn capability_probe_verifies_versioning_compliance_conditional_create_and_head() {
    let rules = ProbeRules::healthy();
    let client = mock_client!(aws_sdk_s3, rules.refs().as_slice());

    assert!(unverified(client).verify().await.is_ok());
    assert_eq!(rules.versioning.num_calls(), 1);
    assert_eq!(rules.object_lock.num_calls(), 1);
    assert_eq!(rules.lifecycle.num_calls(), 1);
    assert_eq!(rules.canary_created.num_calls(), 1);
    assert_eq!(rules.canary_exists.num_calls(), 1);
    assert_eq!(rules.canary_created_head.num_calls(), 1);
    assert_eq!(rules.canary_existing_head.num_calls(), 1);
}

#[tokio::test]
async fn capability_probe_rejects_disabled_versioning() {
    let rule = mock!(aws_sdk_s3::Client::get_bucket_versioning).then_output(|| {
        GetBucketVersioningOutput::builder()
            .status(BucketVersioningStatus::Suspended)
            .build()
    });
    let client = mock_client!(aws_sdk_s3, &[&rule]);

    assert!(matches!(
        unverified(client).verify().await,
        Err(S3DlxArchiveCapabilityError::VersioningRequired)
    ));
}

#[tokio::test]
async fn capability_probe_rejects_governance_or_thirty_day_default() {
    for (days, mode, expected_compliance) in [
        (31, ObjectLockRetentionMode::Governance, true),
        (30, ObjectLockRetentionMode::Compliance, false),
    ] {
        let versioning = mock!(aws_sdk_s3::Client::get_bucket_versioning).then_output(|| {
            GetBucketVersioningOutput::builder()
                .status(BucketVersioningStatus::Enabled)
                .build()
        });
        let object_lock = mock!(aws_sdk_s3::Client::get_object_lock_configuration)
            .then_output(move || object_lock_output(days, mode.clone()));
        let client = mock_client!(aws_sdk_s3, &[&versioning, &object_lock]);
        let result = unverified(client).verify().await;
        if expected_compliance {
            assert!(matches!(
                result,
                Err(S3DlxArchiveCapabilityError::ComplianceRequired)
            ));
        } else {
            assert!(matches!(
                result,
                Err(S3DlxArchiveCapabilityError::RetentionTooShort)
            ));
        }
    }
}

#[tokio::test]
async fn capability_probe_rejects_missing_or_incomplete_lifecycle_expiration() {
    for (current_days, noncurrent_days, status) in [
        (30, 32, ExpirationStatus::Enabled),
        (31, 32, ExpirationStatus::Enabled),
        (32, 30, ExpirationStatus::Enabled),
        (32, 31, ExpirationStatus::Enabled),
        (32, 32, ExpirationStatus::Disabled),
    ] {
        let versioning = mock!(aws_sdk_s3::Client::get_bucket_versioning).then_output(|| {
            GetBucketVersioningOutput::builder()
                .status(BucketVersioningStatus::Enabled)
                .build()
        });
        let object_lock = mock!(aws_sdk_s3::Client::get_object_lock_configuration)
            .then_output(|| object_lock_output(31, ObjectLockRetentionMode::Compliance));
        let lifecycle = mock!(aws_sdk_s3::Client::get_bucket_lifecycle_configuration)
            .then_output(move || lifecycle_output(current_days, noncurrent_days, status.clone()));
        let client = mock_client!(aws_sdk_s3, &[&versioning, &object_lock, &lifecycle]);

        assert!(matches!(
            unverified(client).verify().await,
            Err(S3DlxArchiveCapabilityError::LifecycleRequired)
        ));
    }
}

#[tokio::test]
async fn capability_probe_rejects_lifecycle_without_modern_bucket_wide_filter() {
    let versioning = mock!(aws_sdk_s3::Client::get_bucket_versioning).then_output(|| {
        GetBucketVersioningOutput::builder()
            .status(BucketVersioningStatus::Enabled)
            .build()
    });
    let object_lock = mock!(aws_sdk_s3::Client::get_object_lock_configuration)
        .then_output(|| object_lock_output(31, ObjectLockRetentionMode::Compliance));
    let lifecycle = mock!(aws_sdk_s3::Client::get_bucket_lifecycle_configuration)
        .then_output(lifecycle_output_without_modern_filter);
    let client = mock_client!(aws_sdk_s3, &[&versioning, &object_lock, &lifecycle]);

    assert!(matches!(
        unverified(client).verify().await,
        Err(S3DlxArchiveCapabilityError::LifecycleRequired)
    ));
}

#[tokio::test]
async fn capability_probe_rejects_overwriting_second_canary_put() {
    let rules = ProbeRules::healthy();
    let checksum = checksum_header(CANARY_BODY);
    let overwrite = mock!(aws_sdk_s3::Client::put_object).then_output(move || {
        PutObjectOutput::builder()
            .checksum_sha256(checksum.clone())
            .version_id(VERSION_ID)
            .build()
    });
    let refs = vec![
        &rules.versioning,
        &rules.object_lock,
        &rules.lifecycle,
        &rules.canary_created,
        &rules.canary_created_head,
        &overwrite,
    ];
    let client = mock_client!(aws_sdk_s3, refs.as_slice());

    assert!(matches!(
        unverified(client).verify().await,
        Err(S3DlxArchiveCapabilityError::CanaryInvariant)
    ));
}

#[tokio::test]
async fn capability_probe_accepts_an_existing_generation_canary_on_restart() {
    let rules = ProbeRules::healthy();
    let first_exists = mock!(aws_sdk_s3::Client::put_object).then_error(precondition_failed);
    let second_exists = mock!(aws_sdk_s3::Client::put_object).then_error(precondition_failed);
    let refs = vec![
        &rules.versioning,
        &rules.object_lock,
        &rules.lifecycle,
        &first_exists,
        &rules.canary_created_head,
        &second_exists,
        &rules.canary_existing_head,
    ];
    let client = mock_client!(aws_sdk_s3, refs.as_slice());

    assert!(unverified(client).verify().await.is_ok());
    assert_eq!(first_exists.num_calls(), 1);
    assert_eq!(second_exists.num_calls(), 1);
}

#[tokio::test]
async fn capability_probe_rotates_generation_after_retention_period() {
    let after_retention = NOW + 32 * SECONDS_PER_DAY;
    assert_ne!(canary_key(NOW), canary_key(after_retention));
    let rules = ProbeRules::healthy_at(after_retention);
    let client = mock_client!(aws_sdk_s3, rules.refs().as_slice());

    assert!(
        unverified_at(client, after_retention)
            .verify()
            .await
            .is_ok()
    );
    assert_eq!(rules.canary_created.num_calls(), 1);
    assert_eq!(rules.canary_created_head.num_calls(), 1);
    assert_eq!(rules.canary_existing_head.num_calls(), 1);
}

#[tokio::test]
async fn verified_store_readiness_rechecks_only_read_only_capabilities() {
    let rules = ProbeRules::healthy();
    let readiness_versioning = mock!(aws_sdk_s3::Client::get_bucket_versioning).then_output(|| {
        GetBucketVersioningOutput::builder()
            .status(BucketVersioningStatus::Enabled)
            .build()
    });
    let readiness_object_lock = mock!(aws_sdk_s3::Client::get_object_lock_configuration)
        .then_output(|| object_lock_output(31, ObjectLockRetentionMode::Compliance));
    let readiness_lifecycle = mock!(aws_sdk_s3::Client::get_bucket_lifecycle_configuration)
        .then_output(|| lifecycle_output(32, 32, ExpirationStatus::Enabled));
    let mut refs = rules.refs();
    refs.extend([
        &readiness_versioning,
        &readiness_object_lock,
        &readiness_lifecycle,
    ]);
    let client = mock_client!(aws_sdk_s3, refs.as_slice());
    let store = verified(client).await;

    assert!(store.probe_readiness().await.is_ok());
    assert_eq!(rules.versioning.num_calls(), 1);
    assert_eq!(rules.object_lock.num_calls(), 1);
    assert_eq!(rules.lifecycle.num_calls(), 1);
    assert_eq!(readiness_versioning.num_calls(), 1);
    assert_eq!(readiness_object_lock.num_calls(), 1);
    assert_eq!(readiness_lifecycle.num_calls(), 1);
    assert_eq!(rules.canary_created.num_calls(), 1);
    assert_eq!(rules.canary_exists.num_calls(), 1);
}

#[tokio::test]
async fn verified_put_heads_object_before_reporting_created() {
    let rules = ProbeRules::healthy();
    let body = b"encrypted-archive";
    let key = object_key();
    let put_checksum = checksum_header(body);
    let expected_checksum = put_checksum.clone();
    let key_string = key.as_str().to_string();
    let put = mock!(aws_sdk_s3::Client::put_object)
        .match_requests(move |request| {
            request.key() == Some(key_string.as_str())
                && request.if_none_match() == Some("*")
                && request.checksum_sha256() == Some(expected_checksum.as_str())
                && request.metadata().is_some_and(|metadata| {
                    metadata.get("rss-dlx-key-ref").map(String::as_str) == Some("dlx-archive:1")
                })
        })
        .then_output(move || {
            PutObjectOutput::builder()
                .checksum_sha256(put_checksum.clone())
                .version_id(VERSION_ID)
                .build()
        });
    let head = head_rule(
        "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc",
        body,
        RETAIN_UNTIL,
        Some("dlx-archive:1"),
    );
    let mut refs = rules.refs();
    refs.extend([&put, &head]);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    let outcome = store
        .put_if_absent(DlxArchivePutRequest::new(key, archive_ciphertext(body)))
        .await;
    assert!(matches!(
        outcome,
        Ok(DlxArchivePutOutcome::Created(ref metadata))
            if metadata.checksum() == ArchiveChecksum::sha256(body)
                && metadata.retain_until_epoch_secs() == RETAIN_UNTIL
    ));
    assert_eq!(put.num_calls(), 1);
    assert_eq!(head.num_calls(), 1);
}

#[tokio::test]
async fn verified_put_maps_precondition_to_already_exists() {
    let rules = ProbeRules::healthy();
    let put = mock!(aws_sdk_s3::Client::put_object).then_error(precondition_failed);
    let head = head_rule(
        "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc",
        b"retry",
        RETAIN_UNTIL,
        Some("dlx-archive:1"),
    );
    let mut refs = rules.refs();
    refs.extend([&put, &head]);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    let outcome = store
        .put_if_absent(DlxArchivePutRequest::new(
            object_key(),
            archive_ciphertext(b"retry"),
        ))
        .await;
    assert!(matches!(
        outcome,
        Ok(DlxArchivePutOutcome::AlreadyExists(ref metadata))
            if metadata.version_id().as_str() == VERSION_ID
    ));
}

#[tokio::test]
async fn verified_put_rejects_missing_key_reference_on_created_head() {
    let rules = ProbeRules::healthy();
    let body = b"encrypted-archive";
    let checksum = checksum_header(body);
    let put = mock!(aws_sdk_s3::Client::put_object).then_output(move || {
        PutObjectOutput::builder()
            .checksum_sha256(checksum.clone())
            .version_id(VERSION_ID)
            .build()
    });
    let head = head_rule(
        "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc",
        body,
        RETAIN_UNTIL,
        None,
    );
    let mut refs = rules.refs();
    refs.extend([&put, &head]);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .put_if_absent(DlxArchivePutRequest::new(
                object_key(),
                archive_ciphertext(body),
            ))
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Invariant
    ));
}

#[tokio::test]
async fn verified_put_rejects_only_thirty_days_of_remaining_worm_retention() {
    let rules = ProbeRules::healthy();
    let body = b"encrypted-archive";
    let checksum = checksum_header(body);
    let put = mock!(aws_sdk_s3::Client::put_object).then_output(move || {
        PutObjectOutput::builder()
            .checksum_sha256(checksum.clone())
            .version_id(VERSION_ID)
            .build()
    });
    let head = head_rule(
        "dead-letter/018f31a8-893d-7a52-8e17-3ca9df50120b.v1.enc",
        body,
        NOW + 30 * SECONDS_PER_DAY,
        Some("dlx-archive:1"),
    );
    let mut refs = rules.refs();
    refs.extend([&put, &head]);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .put_if_absent(DlxArchivePutRequest::new(
                object_key(),
                archive_ciphertext(body),
            ))
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Invariant
    ));
}

#[tokio::test]
async fn verified_put_maps_provider_failure_to_transient() {
    let rules = ProbeRules::healthy();
    let put = mock!(aws_sdk_s3::Client::put_object).then_error(access_denied);
    let mut refs = rules.refs();
    refs.push(&put);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .put_if_absent(DlxArchivePutRequest::new(
                object_key(),
                archive_ciphertext(b"ciphertext"),
            ))
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Transient
    ));
}

#[tokio::test]
async fn verified_get_rejects_checksum_mismatch_as_invariant() {
    let rules = ProbeRules::healthy();
    let get = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
        GetObjectOutput::builder()
            .body(ByteStream::from_static(b"tampered"))
            .checksum_sha256(checksum_header(b"original"))
            .version_id(VERSION_ID)
            .metadata("rss-dlx-key-ref", "dlx-archive:1")
            .build()
    });
    let mut refs = rules.refs();
    refs.push(&get);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .get_ciphertext(&object_key(), &archive_version_id())
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Invariant
    ));
}

#[tokio::test]
async fn verified_head_maps_provider_missing_without_a_destructive_capability() {
    let rules = ProbeRules::healthy();
    let head = mock!(aws_sdk_s3::Client::head_object)
        .match_requests(|request| request.version_id() == Some(VERSION_ID))
        .then_error(|| HeadObjectError::NotFound(NotFound::builder().build()));
    let mut refs = rules.refs();
    refs.push(&head);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store.head(&object_key(), &archive_version_id()).await,
        Ok(DlxArchiveHeadOutcome::Missing)
    ));
}

#[tokio::test]
async fn verified_get_maps_no_such_key_to_none() {
    let rules = ProbeRules::healthy();
    let get = mock!(aws_sdk_s3::Client::get_object)
        .then_error(|| GetObjectError::NoSuchKey(NoSuchKey::builder().build()));
    let mut refs = rules.refs();
    refs.push(&get);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .get_ciphertext(&object_key(), &archive_version_id())
            .await,
        Ok(None)
    ));
}

testkit::provider_conformance_catalog! {
    provider: s3,
    error: provider_conformance_cases::CaseError,
    capabilities: {
        identity => {
            #[tokio::test]
            verified_get_validates_checksum_and_restores_key_ref
                => provider_conformance_cases::identity
        },
        conflict => {
            #[tokio::test]
            lifecycle_rejects_same_identity_with_different_canonical_facts
                => provider_conformance_cases::conflict
        },
        archive_receipt => {
            #[tokio::test]
            lifecycle_records_opaque_verified_receipt_before_purge
                => provider_conformance_cases::archive_receipt
        },
    }
}

mod provider_conformance_cases {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::head_object::HeadObjectOutput;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::primitives::{ByteStream, DateTime};
    use aws_sdk_s3::types::ObjectLockMode;
    use aws_smithy_mocks::{mock, mock_client};
    use diport::{
        ArchiveClaimSettleOutcome, ClaimedArchiveCandidate, DlxArchiveBacklog, DlxArchiveStore,
        DlxLifecycleError, DlxLifecycleOperation, DlxLifecycleReason, DlxLifecycleRepository,
        EncryptOutput, KeyName, KeyProvider, KeyProviderError, KeyRef, KeyVersion,
        ReceiptCasOutcome, RedactedBytes,
    };
    use eventexec::{
        DeadLetterId, DlxArchiveCandidate, DlxArchiveKeyName, DlxArchiveSafeMetadata,
        DlxArchiveSafeMetadataInput, DlxLifecycle, DlxLifecycleHealth, DlxMetadataDigest,
        ExpiredArchiveReceipt, MissingArchiveProof, VerifiedArchiveReceipt,
    };
    use secure::Plaintext;

    use super::{
        NOW, ProbeRules, RETAIN_UNTIL, VERSION_ID, archive_version_id, checksum_header, object_key,
        precondition_failed, unverified, verified,
    };

    pub(super) type CaseError = Box<dyn std::error::Error + Send + Sync>;

    pub(super) async fn identity() -> Result<(), CaseError> {
        let rules = ProbeRules::healthy();
        let body = b"existing-ciphertext";
        let get = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|request| request.version_id() == Some(VERSION_ID))
            .then_output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(body))
                    .checksum_sha256(checksum_header(body))
                    .version_id(VERSION_ID)
                    .metadata("rss-dlx-key-ref", "dlx-archive:7")
                    .build()
            });
        let mut refs = rules.refs();
        refs.push(&get);
        let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

        let result = store
            .get_ciphertext(&object_key(), &archive_version_id())
            .await;
        assert!(matches!(
            result,
            Ok(Some(ref ciphertext))
                if ciphertext.ciphertext().as_bytes() == body
                    && ciphertext.key_ref().to_token() == "dlx-archive:7"
        ));
        Ok(())
    }

    pub(super) async fn conflict() -> Result<(), CaseError> {
        let id = dead_letter_id()?;
        let existing = candidate(id.clone(), b"stable-fact-a")?;
        let conflicting = candidate(id, b"stable-fact-b")?;
        let existing_plaintext = existing.canonical().encode().expose().to_vec();
        let checksum = checksum_header(&existing_plaintext);
        let key = eventexec::DlxArchiveObjectKey::from_dead_letter(
            conflicting.canonical().dead_letter_id(),
        )
        .as_str()
        .to_string();

        let put_key = key.clone();
        let put = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(move |request| request.key() == Some(put_key.as_str()))
            .then_error(precondition_failed);
        let head_key = key.clone();
        let head_checksum = checksum.clone();
        let head = mock!(aws_sdk_s3::Client::head_object)
            .match_requests(move |request| request.key() == Some(head_key.as_str()))
            .then_output(move || {
                HeadObjectOutput::builder()
                    .checksum_sha256(head_checksum.clone())
                    .version_id(VERSION_ID)
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from_secs(RETAIN_UNTIL))
                    .metadata("rss-dlx-key-ref", "dlx-archive:1")
                    .build()
            });
        let get_key = key;
        let get_checksum = checksum;
        let get_body = existing_plaintext;
        let get = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(move |request| {
                request.key() == Some(get_key.as_str()) && request.version_id() == Some(VERSION_ID)
            })
            .then_output(move || {
                GetObjectOutput::builder()
                    .body(ByteStream::from(get_body.clone()))
                    .checksum_sha256(get_checksum.clone())
                    .version_id(VERSION_ID)
                    .metadata("rss-dlx-key-ref", "dlx-archive:1")
                    .build()
            });
        let probes = ProbeRules::healthy();
        let mut refs = probes.refs();
        refs.extend([&put, &head, &get]);
        let store = unverified(mock_client!(aws_sdk_s3, refs.as_slice()))
            .verify()
            .await?;
        let repository = LifecycleRepository::new(conflicting);
        let lifecycle = DlxLifecycle::new(
            repository.clone(),
            store,
            PassthroughKeyProvider,
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
        assert_eq!(repository.receipt_count(), 0);
        assert_eq!(repository.purge_calls(), 0);
        assert_eq!(
            repository.events(),
            vec!["claim", "settle_failure"],
            "canonical conflict must fail before receipt and purge"
        );
        Ok(())
    }

    pub(super) async fn archive_receipt() -> Result<(), CaseError> {
        let candidate = candidate(dead_letter_id()?, b"stable-archive-fact")?;
        let plaintext = candidate.canonical().encode().expose().to_vec();
        let checksum = checksum_header(&plaintext);
        let key = eventexec::DlxArchiveObjectKey::from_dead_letter(
            candidate.canonical().dead_letter_id(),
        )
        .as_str()
        .to_string();
        let put_key = key.clone();
        let put_checksum = checksum.clone();
        let put = mock!(aws_sdk_s3::Client::put_object)
            .match_requests(move |request| {
                request.key() == Some(put_key.as_str())
                    && request.if_none_match() == Some("*")
                    && request.metadata().is_some_and(|metadata| {
                        metadata.get("rss-dlx-key-ref").map(String::as_str) == Some("dlx-archive:1")
                    })
            })
            .then_output(move || {
                PutObjectOutput::builder()
                    .checksum_sha256(put_checksum.clone())
                    .version_id(VERSION_ID)
                    .build()
            });
        let head_key = key;
        let head_checksum = checksum;
        let head = mock!(aws_sdk_s3::Client::head_object)
            .match_requests(move |request| request.key() == Some(head_key.as_str()))
            .then_output(move || {
                HeadObjectOutput::builder()
                    .checksum_sha256(head_checksum.clone())
                    .version_id(VERSION_ID)
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from_secs(RETAIN_UNTIL))
                    .metadata("rss-dlx-key-ref", "dlx-archive:1")
                    .build()
            });
        let probes = ProbeRules::healthy();
        let mut refs = probes.refs();
        refs.extend([&put, &head]);
        let store = unverified(mock_client!(aws_sdk_s3, refs.as_slice()))
            .verify()
            .await?;
        let repository = LifecycleRepository::new(candidate);
        let lifecycle = DlxLifecycle::new(
            repository.clone(),
            store,
            PassthroughKeyProvider,
            archive_key()?,
        );

        let report = lifecycle.tick(NOW).await;
        assert_eq!(report.health(), DlxLifecycleHealth::Healthy);
        assert_eq!(report.archived(), 1);
        assert_eq!(report.purged(), 1);
        assert_eq!(repository.receipt_count(), 1);
        assert_eq!(repository.purge_calls(), 1);
        assert_eq!(
            repository.events(),
            vec!["claim", "receipt", "reconcile", "purge"],
            "opaque receipt must be consumed before purge authorization"
        );
        Ok(())
    }

    fn dead_letter_id() -> Result<DeadLetterId, CaseError> {
        Ok(DeadLetterId::parse("018f31a8-893d-7a52-8e17-3ca9df50120b")?)
    }

    fn tenant() -> Result<vocab::TenantId, CaseError> {
        Ok(vocab::TenantId::parse(
            "11111111-2222-4333-8444-555555555555",
        )?)
    }

    fn safe_metadata() -> Result<DlxArchiveSafeMetadata, DlxLifecycleError> {
        DlxArchiveSafeMetadata::try_new(DlxArchiveSafeMetadataInput {
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
        })
    }

    fn candidate(id: DeadLetterId, payload: &[u8]) -> Result<DlxArchiveCandidate, CaseError> {
        Ok(DlxArchiveCandidate::try_new(
            id,
            tenant()?,
            safe_metadata()?,
            Plaintext::new(payload.to_vec()),
        )?)
    }

    fn archive_key() -> Result<DlxArchiveKeyName, CaseError> {
        Ok(DlxArchiveKeyName::try_new("dlx-archive")?)
    }

    #[derive(Clone)]
    struct LifecycleRepository {
        state: Arc<LifecycleRepositoryState>,
    }

    struct LifecycleRepositoryState {
        candidates: Mutex<VecDeque<DlxArchiveCandidate>>,
        receipt_count: AtomicUsize,
        purge_calls: AtomicUsize,
        events: Mutex<Vec<&'static str>>,
    }

    impl LifecycleRepository {
        fn new(candidate: DlxArchiveCandidate) -> Self {
            Self {
                state: Arc::new(LifecycleRepositoryState {
                    candidates: Mutex::new(VecDeque::from([candidate])),
                    receipt_count: AtomicUsize::new(0),
                    purge_calls: AtomicUsize::new(0),
                    events: Mutex::new(Vec::new()),
                }),
            }
        }

        fn push(&self, event: &'static str) {
            self.state
                .events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(event);
        }

        fn events(&self) -> Vec<&'static str> {
            self.state
                .events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }

        fn receipt_count(&self) -> usize {
            self.state.receipt_count.load(Ordering::Acquire)
        }

        fn purge_calls(&self) -> usize {
            self.state.purge_calls.load(Ordering::Acquire)
        }
    }

    impl DlxLifecycleRepository for LifecycleRepository {
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
        ) -> Result<
            Vec<ClaimedArchiveCandidate<Self::ArchiveClaim, Self::ArchiveCandidate>>,
            DlxLifecycleError,
        > {
            self.push("claim");
            let candidates = self
                .state
                .candidates
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .drain(..)
                .map(|candidate| {
                    ClaimedArchiveCandidate::new(
                        candidate.canonical().dead_letter_id().clone(),
                        candidate,
                    )
                })
                .collect();
            Ok(candidates)
        }

        async fn record_verified_receipt(
            &self,
            claim: &Self::ArchiveClaim,
            receipt: Self::VerifiedReceipt,
        ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
            assert_eq!(claim, receipt.dead_letter_id());
            assert_eq!(receipt.archive_version_id().as_str(), VERSION_ID);
            assert_eq!(receipt.archive_key_ref().to_token(), "dlx-archive:1");
            assert_eq!(receipt.retain_until_epoch_secs(), RETAIN_UNTIL);
            self.state.receipt_count.fetch_add(1, Ordering::AcqRel);
            self.push("receipt");
            Ok(ReceiptCasOutcome::Applied)
        }

        async fn settle_archive_failure(
            &self,
            _claim: Self::ArchiveClaim,
            failure: DlxLifecycleError,
        ) -> Result<ArchiveClaimSettleOutcome, DlxLifecycleError> {
            assert_eq!(failure.kind(), diport::DlxLifecycleErrorKind::Invariant);
            self.push("settle_failure");
            Ok(ArchiveClaimSettleOutcome::Applied)
        }

        async fn purge_verified(&self) -> Result<u64, DlxLifecycleError> {
            self.state.purge_calls.fetch_add(1, Ordering::AcqRel);
            self.push("purge");
            Ok(1)
        }

        async fn claim_expired_receipts(
            &self,
        ) -> Result<Vec<Self::ExpiredReceipt>, DlxLifecycleError> {
            self.push("reconcile");
            Ok(Vec::new())
        }

        async fn delete_expired_receipt(
            &self,
            _proof: Self::MissingProof,
        ) -> Result<ReceiptCasOutcome, DlxLifecycleError> {
            Err(DlxLifecycleError::new(
                DlxLifecycleOperation::DeleteExpiredReceipt,
                DlxLifecycleReason::InternalInvariant,
            ))
        }
    }

    #[derive(Clone, Copy)]
    struct PassthroughKeyProvider;

    impl KeyProvider for PassthroughKeyProvider {
        async fn encrypt(
            &self,
            key: KeyName,
            plaintext: Plaintext,
            _aad: secure::DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(
                plaintext.expose().to_vec(),
                KeyRef::new(key, KeyVersion::new(1)),
            ))
        }

        async fn decrypt(
            &self,
            ciphertext: RedactedBytes,
            _key: KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<Plaintext, KeyProviderError> {
            Ok(Plaintext::new(ciphertext.into_bytes()))
        }

        async fn rewrap(
            &self,
            ciphertext: RedactedBytes,
            key: KeyRef,
            _aad: secure::DerivedAad,
        ) -> Result<EncryptOutput, KeyProviderError> {
            Ok(EncryptOutput::new(ciphertext.into_bytes(), key))
        }

        async fn shutdown(&self) -> Result<(), KeyProviderError> {
            Ok(())
        }
    }
}

#[tokio::test]
async fn version_observation_drift_is_transient() {
    let rules = ProbeRules::healthy();
    let get = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
        GetObjectOutput::builder()
            .body(ByteStream::from_static(b"ciphertext"))
            .checksum_sha256(checksum_header(b"ciphertext"))
            .version_id("archive-version-2")
            .metadata("rss-dlx-key-ref", "dlx-archive:1")
            .build()
    });
    let mut refs = rules.refs();
    refs.push(&get);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .get_ciphertext(&object_key(), &archive_version_id())
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Transient
    ));
}

#[tokio::test]
async fn already_exists_with_current_delete_marker_is_transient() {
    let rules = ProbeRules::healthy();
    let put = mock!(aws_sdk_s3::Client::put_object).then_error(precondition_failed);
    let current_head = mock!(aws_sdk_s3::Client::head_object)
        .match_requests(|request| request.version_id().is_none())
        .then_error(|| HeadObjectError::NotFound(NotFound::builder().build()));
    let mut refs = rules.refs();
    refs.extend([&put, &current_head]);
    let store = verified(mock_client!(aws_sdk_s3, refs.as_slice())).await;

    assert!(matches!(
        store
            .put_if_absent(DlxArchivePutRequest::new(
                object_key(),
                archive_ciphertext(b"retry"),
            ))
            .await,
        Err(error) if error.kind() == DlxLifecycleErrorKind::Transient
    ));
}
