#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::SystemTime;

use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, DefaultRetention, ExpirationStatus, LifecycleExpiration,
    LifecycleRule, LifecycleRuleFilter, NoncurrentVersionExpiration, ObjectLockConfiguration,
    ObjectLockEnabled, ObjectLockRetentionMode, ObjectLockRule,
};
use aws_smithy_http_client::Builder;
use diport::{
    ArchiveChecksum, Clock, DlxArchiveCiphertext, DlxArchiveHeadOutcome, DlxArchivePutOutcome,
    DlxArchivePutRequest, DlxArchiveStore, KeyRef, RedactedBytes,
};
use eventexec::{DeadLetterId, DlxArchiveObjectKey};
use s3::S3DlxArchiveStore;

fn live_client(params: &testkit::MinioConnParams) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            params.access_key_id(),
            params.secret_access_key(),
            None,
            None,
            "rss-minio-testkit",
        ))
        .endpoint_url(params.endpoint_url())
        .force_path_style(true)
        .http_client(Builder::new().build_http())
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::disallowed_methods)] // Live WORM retention is measured against provider wall time.
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

async fn provision_worm_bucket(
    client: &aws_sdk_s3::Client,
    bucket: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    client
        .create_bucket()
        .bucket(bucket)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await?;

    let retention = DefaultRetention::builder()
        .mode(ObjectLockRetentionMode::Compliance)
        .days(31)
        .build();
    let lock_rule = ObjectLockRule::builder()
        .default_retention(retention)
        .build();
    let lock_configuration = ObjectLockConfiguration::builder()
        .object_lock_enabled(ObjectLockEnabled::Enabled)
        .rule(lock_rule)
        .build();
    client
        .put_object_lock_configuration()
        .bucket(bucket)
        .object_lock_configuration(lock_configuration)
        .send()
        .await?;

    let expiration_rule = LifecycleRule::builder()
        .id("rss-dlx-archive-expiration")
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .expiration(LifecycleExpiration::builder().days(32).build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(32)
                .build(),
        )
        .status(ExpirationStatus::Enabled)
        .build()?;
    let lifecycle = BucketLifecycleConfiguration::builder()
        .rules(expiration_rule)
        .build()?;
    client
        .put_bucket_lifecycle_configuration()
        .bucket(bucket)
        .lifecycle_configuration(lifecycle)
        .send()
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn live_dlx_archive_worm_capability_and_roundtrip()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fixture = testkit::env_or_minio().await?;
    let client = live_client(fixture.params());
    let bucket = format!("rss-dlx-worm-{}", uuid::Uuid::new_v4());
    provision_worm_bucket(&client, &bucket).await?;

    let store = S3DlxArchiveStore::new(client.clone(), &bucket, Arc::new(SystemClock))?
        .verify()
        .await?;
    store.probe_readiness().await?;

    let id = DeadLetterId::parse(&uuid::Uuid::new_v4().to_string())?;
    let object_key = DlxArchiveObjectKey::from_dead_letter(&id);
    let body = format!("rss-live-dlx-worm:{}", id.as_str()).into_bytes();
    let key_ref = KeyRef::parse("dlx-archive:1")?;
    let request = || {
        DlxArchivePutRequest::new(
            object_key.clone(),
            DlxArchiveCiphertext::new(RedactedBytes::new(body.clone()), key_ref.clone()),
        )
    };

    let created = store.put_if_absent(request()).await?;
    let DlxArchivePutOutcome::Created(created_metadata) = created else {
        return Err("unique archive key unexpectedly existed".into());
    };
    assert_eq!(created_metadata.checksum(), ArchiveChecksum::sha256(&body));
    assert!(created_metadata.retain_until_epoch_secs() > 0);

    let duplicate = store.put_if_absent(request()).await?;
    let DlxArchivePutOutcome::AlreadyExists(existing_metadata) = duplicate else {
        return Err("duplicate archive key unexpectedly created a new version".into());
    };
    assert_eq!(
        existing_metadata.version_id(),
        created_metadata.version_id()
    );

    let head = store
        .head(&object_key, created_metadata.version_id())
        .await?;
    assert!(matches!(
        head,
        DlxArchiveHeadOutcome::Present(ref metadata)
            if metadata.version_id() == created_metadata.version_id()
                && metadata.checksum() == ArchiveChecksum::sha256(&body)
                && metadata.retain_until_epoch_secs()
                    == created_metadata.retain_until_epoch_secs()
    ));
    let ciphertext = store
        .get_ciphertext(&object_key, created_metadata.version_id())
        .await?
        .ok_or("archive ciphertext missing after create")?;
    assert_eq!(ciphertext.ciphertext().as_bytes(), body);
    assert_eq!(ciphertext.key_ref().to_token(), "dlx-archive:1");

    let delete = client
        .delete_object()
        .bucket(&bucket)
        .key(object_key.as_str())
        .version_id(created_metadata.version_id().as_str())
        .send()
        .await;
    assert!(
        delete.is_err(),
        "COMPLIANCE-retained exact version must reject deletion"
    );
    drop(fixture);
    Ok(())
}
