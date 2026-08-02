#![cfg(feature = "integration")]

use std::sync::Arc;
use std::time::SystemTime;

use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::primitives::ByteStream;
use diport::{
    ArchiveChecksum, Clock, DlxArchiveCiphertext, DlxArchiveHeadOutcome, DlxArchivePutOutcome,
    DlxArchivePutRequest, DlxArchiveStore, KeyRef, RedactedBytes,
};
use eventexec::{DeadLetterId, DlxArchiveObjectKey};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn live_factory(
    credentials: &testkit::MinioCredentials,
    ca_pem: &str,
) -> TestResult<s3::PrivateCaS3ClientFactory> {
    Ok(s3::PrivateCaS3ClientFactory::new(
        secure::S3Endpoint::parse(
            credentials.endpoint_url(),
            secure::PlaintextEndpointPolicy::Deny,
        )?,
        "us-east-1",
        Credentials::new(
            credentials.access_key_id(),
            credentials.secret_access_key(),
            None,
            None,
            "rss-minio-testkit",
        ),
        true,
        ca_pem.as_bytes().to_vec(),
    ))
}

struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::disallowed_methods)] // Live WORM retention is measured against provider wall time.
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

fn response_status<E>(error: &aws_sdk_s3::error::SdkError<E>) -> Option<u16> {
    error
        .raw_response()
        .map(|response| response.status().as_u16())
}

#[tokio::test(flavor = "multi_thread")]
async fn live_dlx_archive_tls_scoped_acl_worm_and_roundtrip() -> TestResult {
    let network = testkit::bridge_network("rss-minio-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::minio_tls_archive(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: &dns_name,
    })
    .await?;
    let workload_factory = live_factory(fixture.workload(), fixture.ca_pem())?;
    let workload = workload_factory.build_client()?;
    let wrong_ca = live_factory(fixture.workload(), fixture.wrong_ca_pem())?.build_client()?;
    let bucket = fixture.archive_bucket();

    let wrong_ca_connection = wrong_ca.get_bucket_versioning().bucket(bucket).send().await;
    assert!(
        wrong_ca_connection
            .as_ref()
            .err()
            .is_some_and(|error| error.raw_response().is_none()),
        "an untrusted private CA must fail before receiving an HTTP response"
    );

    let store = workload_factory
        .build_verified_dlx_archive_store(bucket, Arc::new(SystemClock))
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

    let delete_missing = workload
        .delete_object()
        .bucket(bucket)
        .key("acl/missing-object")
        .send()
        .await;
    assert_eq!(
        delete_missing.as_ref().err().and_then(response_status),
        Some(403),
        "workload identity must not have delete permission"
    );

    let list = workload.list_objects_v2().bucket(bucket).send().await;
    assert_eq!(
        list.as_ref().err().and_then(response_status),
        Some(403),
        "workload identity must not have list permission"
    );

    let neighbor_put = workload
        .put_object()
        .bucket(fixture.neighbor_bucket())
        .key("acl/neighbor-object")
        .body(ByteStream::from_static(b"denied"))
        .send()
        .await;
    assert_eq!(
        neighbor_put.as_ref().err().and_then(response_status),
        Some(403),
        "workload identity must not write to a neighboring bucket"
    );

    fixture
        .assert_admin_cannot_delete_retained_version(
            object_key.as_str(),
            created_metadata.version_id().as_str(),
        )
        .await?;
    Ok(())
}
