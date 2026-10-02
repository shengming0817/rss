use std::time::Duration;

use aws_sdk_s3::{
    Client,
    config::{Credentials, Region, retry::RetryConfig, timeout::TimeoutConfig},
    error::{ProvideErrorMetadata, SdkError},
    types::{
        BucketLifecycleConfiguration, BucketVersioningStatus, DefaultRetention, ExpirationStatus,
        LifecycleExpiration, LifecycleRule, LifecycleRuleFilter, NoncurrentVersionExpiration,
        ObjectLockConfiguration, ObjectLockEnabled, ObjectLockRetentionMode, ObjectLockRule,
        VersioningConfiguration,
    },
};
use aws_smithy_http_client::tls::{self, TrustStore};
use testcontainers::core::IntoContainerPort as _;
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};

use super::runtime::run_container_command_output;
use super::{NetworkAttachment, Result, start_on_network, tls_material};
const ARCHIVE_BUCKET: &str = "archive";
const UNVERSIONED_BUCKET: &str = "archive-unversioned";
const UNLOCKED_BUCKET: &str = "archive-unlocked";
const NEIGHBOR_BUCKET: &str = "neighbor";
const POLICY_NAME: &str = "archive-workload";
const PORT: u16 = 9000;
const ROOT_USER: &str = "fixture-root";
const ROOT_PASSWORD: &str = "fixture-root-password";
const WORKLOAD_USER: &str = "fixture-archive";
const WORKLOAD_PASSWORD: &str = "fixture-archive-password";
// RustFS 1.0.0 multi-architecture index; pin both architectures to the same release artifact.
const IMAGE: &str = "1.0.0@sha256:8cc9801755448b71a786705ce76692c77e14936cccd87cf2fc31842e58f4d1ff";

fn archive_policy() -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetBucketVersioning","s3:GetBucketObjectLockConfiguration"],"Resource":["arn:aws:s3:::{ARCHIVE_BUCKET}","arn:aws:s3:::{UNVERSIONED_BUCKET}","arn:aws:s3:::{UNLOCKED_BUCKET}"]}},{{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:GetObjectRetention","s3:PutObject","s3:PutObjectRetention"],"Resource":"arn:aws:s3:::{ARCHIVE_BUCKET}/*"}}]}}"#
    )
}

/// Redacted S3 connection coordinates for archive integration tests.
#[derive(Clone)]
pub struct S3Credentials {
    endpoint_url: String,
    access_key_id: String,
    secret_access_key: String,
}
impl S3Credentials {
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }
}
impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("endpoint_url", &self.endpoint_url)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// Hermetic RustFS TLS guard with a locked bucket and one scoped workload identity.
pub struct S3ArchiveFixture {
    _container: Box<ContainerAsync<GenericImage>>,
    admin: Client,
    workload: S3Credentials,
    ca_pem: String,
    wrong_ca_pem: String,
}
impl S3ArchiveFixture {
    pub fn workload(&self) -> &S3Credentials {
        &self.workload
    }
    pub const fn archive_bucket(&self) -> &'static str {
        ARCHIVE_BUCKET
    }
    pub const fn neighbor_bucket(&self) -> &'static str {
        NEIGHBOR_BUCKET
    }
    /// Readable bucket without versioning, for capability rejection.
    pub const fn unversioned_bucket(&self) -> &'static str {
        UNVERSIONED_BUCKET
    }
    /// Readable versioned bucket without Object Lock, for capability rejection.
    pub const fn unlocked_bucket(&self) -> &'static str {
        UNLOCKED_BUCKET
    }
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }
    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }
    /// Delete an expired exact version using fixture administration, never the archive port.
    pub async fn delete_expired_version(&self, key: &str, version: &str) -> Result<()> {
        self.admin
            .delete_object()
            .bucket(ARCHIVE_BUCKET)
            .key(key)
            .version_id(version)
            .send()
            .await
            .map_err(|e| sdk_failure("delete expired fixture version failed", e))?;
        let result = self
            .admin
            .head_object()
            .bucket(ARCHIVE_BUCKET)
            .key(key)
            .version_id(version)
            .send()
            .await;
        anyhow::ensure!(
            matches!(result, Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 404)),
            "deleted exact fixture version must be absent"
        );
        Ok(())
    }
    /// Even the fixture root identity must be unable to delete a retained exact version.
    pub async fn assert_admin_cannot_delete_retained_version(
        &self,
        key: &str,
        version: &str,
    ) -> Result<()> {
        anyhow::ensure!(
            !key.is_empty() && !version.is_empty(),
            "empty retained S3 coordinates"
        );
        let result = self
            .admin
            .delete_object()
            .bucket(ARCHIVE_BUCKET)
            .key(key)
            .version_id(version)
            .send()
            .await;
        anyhow::ensure!(
            matches!(result, Err(e) if e.raw_response().is_some_and(|r| r.status().as_u16() == 403)
            && e.as_service_error().is_some_and(|e| e.meta().code() == Some("AccessDenied"))),
            "fixture root retained-version deletion must return AccessDenied"
        );
        let object = self
            .admin
            .head_object()
            .bucket(ARCHIVE_BUCKET)
            .key(key)
            .version_id(version)
            .send()
            .await
            .map_err(|e| sdk_failure("retained fixture version disappeared", e))?;
        anyhow::ensure!(
            object.version_id() == Some(version),
            "retained fixture version changed"
        );
        Ok(())
    }
}

fn sdk_failure<E: ProvideErrorMetadata>(
    operation: &'static str,
    error: SdkError<E>,
) -> anyhow::Error {
    let status = error.raw_response().map(|r| r.status().as_u16());
    let category = match &error {
        SdkError::TimeoutError(_) => "timeout",
        SdkError::DispatchFailure(_) => "transport",
        SdkError::ConstructionFailure(_) => "request",
        SdkError::ResponseError(_) => "response",
        SdkError::ServiceError(_) => match error
            .as_service_error()
            .and_then(ProvideErrorMetadata::code)
        {
            Some("AccessDenied") => "access-denied",
            Some("InvalidAccessKeyId" | "SignatureDoesNotMatch") => "authentication",
            Some("InvalidRequest" | "InvalidArgument" | "InvalidBucketName") => "configuration",
            Some("NoSuchBucket" | "NoSuchKey" | "NoSuchVersion") => "missing",
            Some("SlowDown" | "Throttling") => "throttled",
            _ => "service",
        },
        _ => "sdk",
    };
    anyhow::anyhow!("S3 fixture {operation} (category={category}, status={status:?})")
}

fn admin_client(endpoint: &str, ca: &str) -> Result<Client> {
    let tls = tls::TlsContext::builder()
        .with_trust_store(TrustStore::empty().with_pem_certificate(ca.as_bytes().to_vec()))
        .build()?;
    let http = aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .tls_context(tls)
        .build_https();
    Ok(Client::from_conf(
        aws_sdk_s3::config::Builder::new()
            .behavior_version_latest()
            .endpoint_url(endpoint)
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                ROOT_USER,
                ROOT_PASSWORD,
                None,
                None,
                "fixture",
            ))
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(5))
                    .build(),
            )
            .http_client(http)
            .build(),
    ))
}

async fn buckets(admin: &Client) -> Result<()> {
    admin
        .create_bucket()
        .bucket(ARCHIVE_BUCKET)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .map_err(|e| sdk_failure("create locked fixture bucket failed", e))?;
    admin
        .put_object_lock_configuration()
        .bucket(ARCHIVE_BUCKET)
        .object_lock_configuration(
            ObjectLockConfiguration::builder()
                .object_lock_enabled(ObjectLockEnabled::Enabled)
                .rule(
                    ObjectLockRule::builder()
                        .default_retention(
                            DefaultRetention::builder()
                                .mode(ObjectLockRetentionMode::Compliance)
                                .days(31)
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .map_err(|e| sdk_failure("configure fixture retention failed", e))?;
    admin
        .put_bucket_lifecycle_configuration()
        .bucket(ARCHIVE_BUCKET)
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(
                    LifecycleRule::builder()
                        .id("archive-expiry")
                        .status(ExpirationStatus::Enabled)
                        .filter(LifecycleRuleFilter::builder().prefix("").build())
                        .expiration(LifecycleExpiration::builder().days(32).build())
                        .noncurrent_version_expiration(
                            NoncurrentVersionExpiration::builder()
                                .noncurrent_days(32)
                                .build(),
                        )
                        .build()?,
                )
                .build()?,
        )
        .send()
        .await
        .map_err(|e| sdk_failure("configure fixture lifecycle failed", e))?;
    for bucket in [NEIGHBOR_BUCKET, UNVERSIONED_BUCKET, UNLOCKED_BUCKET] {
        admin
            .create_bucket()
            .bucket(bucket)
            .send()
            .await
            .map_err(|e| sdk_failure("create fixture posture bucket failed", e))?;
    }
    admin
        .put_bucket_versioning()
        .bucket(UNLOCKED_BUCKET)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .map_err(|e| sdk_failure("configure unlocked fixture versioning failed", e))?;
    Ok(())
}

// ref: rustfs/rustfs rustfs/src/admin/handlers/user.rs@1.0.0.
// Native admin bodies are JSON; curl bundled in the pinned image owns SigV4 and TLS.
// S3 does not provide identity administration. Keep these calls private to fixture setup.
async fn workload_identity(container: &ContainerAsync<GenericImage>) -> Result<()> {
    for (operation, path, body) in [
        (
            "create workload policy",
            format!("add-canned-policy?name={POLICY_NAME}"),
            "/rss-s3/policy.json",
        ),
        (
            "create workload user",
            format!("add-user?accessKey={WORKLOAD_USER}"),
            "/rss-s3/user.json",
        ),
        (
            "attach workload policy",
            format!(
                "set-user-or-group-policy?policyName={POLICY_NAME}&userOrGroup={WORKLOAD_USER}&isGroup=false"
            ),
            "/dev/null",
        ),
    ] {
        let url = format!("https://localhost:{PORT}/rustfs/admin/v3/{path}");
        let auth = format!("{ROOT_USER}:{ROOT_PASSWORD}");
        let file = format!("@{body}");
        let output = run_container_command_output(
            container,
            operation,
            &[
                "curl",
                "--fail",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "--cacert",
                "/rss-tls/ca.pem",
                "--aws-sigv4",
                "aws:amz:us-east-1:s3",
                "--user",
                &auth,
                "--request",
                "PUT",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                &file,
                &url,
            ],
        )
        .await?;
        let status = output.stdout.trim().parse::<u16>().ok();
        anyhow::ensure!(
            output.exit_code == Some(0),
            "S3 fixture {operation} failed (status={status:?}, exit={:?})",
            output.exit_code
        );
    }
    Ok(())
}

/// Starts one pinned RustFS server and provisions the archive-only test posture.
pub async fn s3_tls_archive(attachment: NetworkAttachment<'_>) -> Result<S3ArchiveFixture> {
    let material = tls_material(attachment.dns_name)?;
    let user = serde_json::to_vec(&serde_json::json!({
        "secretKey": WORKLOAD_PASSWORD, "status": "enabled",
    }))?;
    let container = start_on_network(
        GenericImage::new("rustfs/rustfs", IMAGE)
            .with_exposed_port(PORT.tcp())
            .with_env_var("RUSTFS_ACCESS_KEY", ROOT_USER)
            .with_env_var("RUSTFS_SECRET_KEY", ROOT_PASSWORD)
            .with_env_var("RUSTFS_TLS_PATH", "/rss-tls")
            .with_env_var("RUSTFS_CONSOLE_ENABLE", "false")
            .with_copy_to("/rss-tls/ca.pem", material.ca_pem.as_bytes().to_vec())
            .with_copy_to(
                "/rss-tls/rustfs_cert.pem",
                material.server_cert_pem.as_bytes().to_vec(),
            )
            // Copied files are root-owned; only this disposable container can read its generated key.
            .with_copy_to(
                CopyTargetOptions::new("/rss-tls/rustfs_key.pem").with_mode(0o644),
                material.server_key_pem.as_bytes().to_vec(),
            )
            .with_copy_to("/rss-s3/policy.json", archive_policy().into_bytes())
            .with_copy_to("/rss-s3/user.json", user),
        attachment,
    )
    .await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(PORT).await?;
    let endpoint_url = format!("https://{host}:{port}");
    let admin = admin_client(&endpoint_url, &material.ca_pem)?;
    let mut last_failure = None;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match admin.list_buckets().send().await {
                Ok(_) => return Ok::<(), anyhow::Error>(()),
                Err(error) => {
                    let rejected = error
                        .raw_response()
                        .is_some_and(|r| (400..500).contains(&r.status().as_u16()));
                    let failure = sdk_failure("TLS readiness", error);
                    if rejected {
                        return Err(failure);
                    }
                    last_failure = Some(failure);
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "RustFS TLS readiness deadline elapsed; last_failure={}",
            last_failure.map_or_else(|| "operation pending".into(), |e| e.to_string())
        )
    })??;
    buckets(&admin).await?;
    workload_identity(&container).await?;
    Ok(S3ArchiveFixture {
        _container: Box::new(container),
        admin,
        workload: S3Credentials {
            endpoint_url,
            access_key_id: WORKLOAD_USER.into(),
            secret_access_key: WORKLOAD_PASSWORD.into(),
        },
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
    })
}
