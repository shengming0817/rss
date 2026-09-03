use testcontainers::core::{IntoContainerPort as _, WaitFor};
use testcontainers::{ContainerAsync, CopyTargetOptions, GenericImage, ImageExt as _};

use super::runtime::{run_container_command, run_container_command_output};
use super::{
    MINIO_ARCHIVE_BUCKET, MINIO_NEIGHBOR_BUCKET, MINIO_POLICY_NAME, MINIO_PORT,
    MINIO_ROOT_PASSWORD, MINIO_ROOT_USER, MINIO_WORKLOAD_PASSWORD, MINIO_WORKLOAD_USER,
    NetworkAttachment, Result, attach_network, runtime, tls_material,
};

// ── MinIO / S3-compatible object storage ────────────────────────────────────

pub(super) fn minio_archive_policy() -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":["s3:GetBucketVersioning","s3:GetBucketObjectLockConfiguration","s3:GetLifecycleConfiguration"],"Resource":"arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}"}},{{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:GetObjectRetention","s3:PutObject"],"Resource":"arn:aws:s3:::{MINIO_ARCHIVE_BUCKET}/*"}}]}}"#
    )
}

/// Redacted MinIO connection coordinates used by the single provider conformance test.
#[derive(Clone)]
pub struct MinioCredentials {
    pub(super) endpoint_url: String,
    pub(super) access_key_id: String,
    pub(super) secret_access_key: String,
}

impl MinioCredentials {
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

impl std::fmt::Debug for MinioCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MinioCredentials")
            .field("endpoint_url", &self.endpoint_url)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// Hermetic TLS MinIO guard with one fixed locked bucket and one scoped workload identity.
pub struct MinioTlsFixture {
    pub(super) _container: Box<ContainerAsync<GenericImage>>,
    pub(super) workload: MinioCredentials,
    pub(super) ca_pem: String,
    pub(super) wrong_ca_pem: String,
}

impl MinioTlsFixture {
    pub fn workload(&self) -> &MinioCredentials {
        &self.workload
    }

    pub const fn archive_bucket(&self) -> &'static str {
        MINIO_ARCHIVE_BUCKET
    }

    pub const fn neighbor_bucket(&self) -> &'static str {
        MINIO_NEIGHBOR_BUCKET
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn wrong_ca_pem(&self) -> &str {
        &self.wrong_ca_pem
    }

    /// Proves that even the fixture-internal root identity cannot delete one exact retained version.
    pub async fn assert_admin_cannot_delete_retained_version(
        &self,
        object_key: &str,
        version_id: &str,
    ) -> Result<()> {
        if object_key.is_empty() || object_key.starts_with('-') || object_key.contains('\0') {
            return Err(anyhow::anyhow!("invalid retained MinIO object key"));
        }
        if version_id.is_empty()
            || !version_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(anyhow::anyhow!("invalid retained MinIO version id"));
        }
        let target = format!("rss/{MINIO_ARCHIVE_BUCKET}/{object_key}");
        let output = run_container_command_output(
            &self._container,
            "probe retained exact-version deletion",
            &[
                "mc",
                "--insecure",
                "rm",
                "--version-id",
                version_id,
                target.as_str(),
            ],
        )
        .await?;
        if output.exit_code == Some(0) {
            return Err(anyhow::anyhow!(
                "container fixture retained exact-version deletion unexpectedly succeeded"
            ));
        }
        let diagnostic = format!("{}\n{}", output.stdout, output.stderr).to_ascii_lowercase();
        if !diagnostic.contains("worm protected") {
            return Err(output.failure("probe retained exact-version deletion"));
        }
        Ok(())
    }
}

/// Starts one TLS MinIO server and provisions the exact SettingsOnly archive posture.
pub async fn minio_tls_archive(attachment: NetworkAttachment<'_>) -> Result<MinioTlsFixture> {
    let material = tls_material(attachment.dns_name)?;
    let policy = minio_archive_policy();
    let archive_alias = format!("rss/{MINIO_ARCHIVE_BUCKET}");
    let neighbor_alias = format!("rss/{MINIO_NEIGHBOR_BUCKET}");
    let image = GenericImage::new("minio/minio", "RELEASE.2025-02-28T09-55-16Z")
        .with_exposed_port(MINIO_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stderr("API:"));
    let request = attach_network(
        image
            .with_env_var("MINIO_ROOT_USER", MINIO_ROOT_USER)
            .with_env_var("MINIO_ROOT_PASSWORD", MINIO_ROOT_PASSWORD)
            .with_copy_to(
                "/rss-tls/CAs/rss-test-ca.pem",
                material.ca_pem.as_bytes().to_vec(),
            )
            .with_copy_to(
                "/rss-tls/public.crt",
                material.server_cert_pem.as_bytes().to_vec(),
            )
            .with_copy_to(
                CopyTargetOptions::new("/rss-tls/private.key").with_mode(0o600),
                material.server_key_pem.as_bytes().to_vec(),
            )
            .with_copy_to("/rss-minio/archive-policy.json", policy.into_bytes())
            .with_cmd([
                "server",
                "/data",
                "--certs-dir",
                "/rss-tls",
                "--console-address",
                ":9001",
            ]),
        attachment,
    )?;
    let container = runtime::start(request).await?;
    run_container_command(
        &container,
        "configure admin alias",
        &[
            "mc",
            "--insecure",
            "alias",
            "set",
            "rss",
            "https://127.0.0.1:9000",
            MINIO_ROOT_USER,
            MINIO_ROOT_PASSWORD,
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create locked archive bucket",
        &[
            "mc",
            "--insecure",
            "mb",
            "--with-lock",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "configure archive retention",
        &[
            "mc",
            "--insecure",
            "retention",
            "set",
            "--default",
            "COMPLIANCE",
            "31d",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "configure archive lifecycle",
        &[
            "mc",
            "--insecure",
            "ilm",
            "rule",
            "add",
            "--expire-days",
            "32",
            "--noncurrent-expire-days",
            "32",
            archive_alias.as_str(),
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create neighbor bucket",
        &["mc", "--insecure", "mb", neighbor_alias.as_str()],
    )
    .await?;
    run_container_command(
        &container,
        "create workload policy",
        &[
            "mc",
            "--insecure",
            "admin",
            "policy",
            "create",
            "rss",
            MINIO_POLICY_NAME,
            "/rss-minio/archive-policy.json",
        ],
    )
    .await?;
    run_container_command(
        &container,
        "create workload identity",
        &[
            "mc",
            "--insecure",
            "admin",
            "user",
            "add",
            "rss",
            MINIO_WORKLOAD_USER,
            MINIO_WORKLOAD_PASSWORD,
        ],
    )
    .await?;
    run_container_command(
        &container,
        "attach workload policy",
        &[
            "mc",
            "--insecure",
            "admin",
            "policy",
            "attach",
            "rss",
            MINIO_POLICY_NAME,
            "--user",
            MINIO_WORKLOAD_USER,
        ],
    )
    .await?;
    let host = container.get_host().await?.to_string();
    let port = container.get_host_port_ipv4(MINIO_PORT).await?;
    let credentials = |access_key_id: &str, secret_access_key: &str| MinioCredentials {
        endpoint_url: format!("https://{host}:{port}"),
        access_key_id: access_key_id.to_owned(),
        secret_access_key: secret_access_key.to_owned(),
    };
    Ok(MinioTlsFixture {
        _container: Box::new(container),
        workload: credentials(MINIO_WORKLOAD_USER, MINIO_WORKLOAD_PASSWORD),
        ca_pem: material.ca_pem,
        wrong_ca_pem: material.wrong_ca_pem,
    })
}
