use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use aws_sdk_s3::config::ProvideCredentials as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ObjectStore, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use s3::{S3DlxArchiveStore, S3RuntimeDeps, S3Store};
use tokio_util::sync::CancellationToken;

use crate::config::SnapshotConfig;
use crate::{EnvSecret, SharedRuntimeDeps};

/// 默认 S3 canary 周期（60 秒）。
const DEFAULT_S3_CANARY_INTERVAL: Duration = Duration::from_secs(60);
/// 默认 S3 canary 单轮超时（5 秒）。
const DEFAULT_S3_CANARY_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_S3_CANARY_INTERVAL_SECS: u64 = 300;
const MAX_S3_CANARY_TIMEOUT_SECS: u64 = 60;

// ── S3 object-store wiring + canary ──────────────────────────────────────────────────────────

const S3_ENDPOINT_URL_ENV: &str = "RSS_S3_ENDPOINT_URL";
const S3_BUCKET_ENV: &str = "RSS_S3_BUCKET";
const S3_CA_CERT_PEM_PATH_ENV: &str = "RSS_S3_CA_CERT_PEM_PATH";
const S3_ACCESS_KEY_ID_ENV: &str = "RSS_S3_ACCESS_KEY_ID";
const S3_SECRET_ACCESS_KEY_ENV: &str = "RSS_S3_SECRET_ACCESS_KEY";
const S3_SESSION_TOKEN_ENV: &str = "RSS_S3_SESSION_TOKEN";
const S3_REGION_ENV: &str = "RSS_S3_REGION";
const S3_FORCE_PATH_STYLE_ENV: &str = "RSS_S3_FORCE_PATH_STYLE";
const DLX_ARCHIVE_S3_BUCKET_ENV: &str = "RSS_DLX_ARCHIVE_S3_BUCKET";
const S3_CANARY_KEY_PREFIX_ENV: &str = "RSS_S3_CANARY_KEY_PREFIX";
const S3_CANARY_INTERVAL_SECS_ENV: &str = "RSS_S3_CANARY_INTERVAL_SECS";
const S3_CANARY_TIMEOUT_SECS_ENV: &str = "RSS_S3_CANARY_TIMEOUT_SECS";
const DEFAULT_S3_REGION: &str = "us-east-1";
const DEFAULT_S3_CANARY_KEY_PREFIX: &str = "rss/runtime-canary";
const DLX_IDENTITY_COLLISION_ERROR: &str =
    "DLX archive workload identity collides with the snapshot S3 general identity";
const S3_CANARY_COLLECT_LIMIT: usize = 1024;
pub(crate) const S3_CANARY_PAYLOAD: &[u8] = b"rss-s3-canary";
pub const S3_READY_PROBE_NAME: &str = "s3_object_store_ready";

fn validate_s3_bucket(raw: String, env: &'static str) -> anyhow::Result<String> {
    let bucket = raw.trim();
    anyhow::ensure!(
        (3..=63).contains(&bucket.len()),
        "{env} must be 3..=63 characters"
    );
    anyhow::ensure!(
        bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
        "{env} must contain only lowercase letters, digits, dots, or hyphens"
    );
    let first = bucket.as_bytes()[0];
    let last = bucket.as_bytes()[bucket.len() - 1];
    anyhow::ensure!(
        (first.is_ascii_lowercase() || first.is_ascii_digit())
            && (last.is_ascii_lowercase() || last.is_ascii_digit()),
        "{env} must start and end with a lowercase letter or digit"
    );
    anyhow::ensure!(
        !bucket.contains("..") && !bucket.contains(".-") && !bucket.contains("-."),
        "{env} must not contain adjacent dots or dot-hyphen pairs"
    );
    anyhow::ensure!(
        bucket.parse::<std::net::Ipv4Addr>().is_err(),
        "{env} must not be formatted as an IPv4 address"
    );
    Ok(bucket.to_string())
}

/// One fully parsed S3 configuration generation. Private fields and the snapshot-only production
/// constructor keep the general store, canary, and DLX archive settings bound to one capture.
pub(crate) struct S3RuntimeConfig {
    general: S3GeneralConfig,
    canary: S3CanaryConfig,
    dlx_archive: S3DlxArchiveConfig,
}

impl std::fmt::Debug for S3RuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("S3RuntimeConfig(<redacted>)")
    }
}

/// Named consumed form; names keep the general and archive workloads impossible to transpose by
/// tuple position at the composition root.
pub(crate) struct S3RuntimeConfigParts {
    pub(crate) general: S3GeneralConfig,
    pub(crate) canary: S3CanaryConfig,
    pub(crate) dlx_archive: S3DlxArchiveConfig,
}

pub(crate) struct S3GeneralConfig {
    settings: Arc<S3ClientSettings>,
    bucket: String,
    credentials: aws_sdk_s3::config::Credentials,
}

struct S3GeneralIdentityMarker(secure::SecretText);

impl S3GeneralIdentityMarker {
    fn from_credentials(credentials: &aws_sdk_s3::config::Credentials) -> Self {
        Self(secure::SecretText::from_string(
            credentials.access_key_id().to_owned(),
        ))
    }

    fn collides_with(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        self.0.expose() == credentials.access_key_id()
    }
}

impl std::fmt::Debug for S3GeneralIdentityMarker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("S3GeneralIdentityMarker(<redacted>)")
    }
}

pub(crate) struct S3DlxArchiveConfig {
    settings: Arc<S3ClientSettings>,
    bucket: String,
    general_identity: S3GeneralIdentityMarker,
}

struct S3GeneralConfigValues<'a> {
    endpoint_url: Option<&'a str>,
    ca_cert_pem_path: Option<&'a str>,
    bucket: Option<&'a str>,
    access_key_id: Option<&'a str>,
    secret_access_key: Option<&'a str>,
    session_token: Option<&'a str>,
    region: Option<&'a str>,
    force_path_style: Option<&'a str>,
}

impl S3RuntimeConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        let general = s3_general_config_from_values(S3GeneralConfigValues {
            endpoint_url: config.value(S3_ENDPOINT_URL_ENV),
            ca_cert_pem_path: config.value(S3_CA_CERT_PEM_PATH_ENV),
            bucket: config.value(S3_BUCKET_ENV),
            access_key_id: config.value(S3_ACCESS_KEY_ID_ENV),
            secret_access_key: config.value(S3_SECRET_ACCESS_KEY_ENV),
            session_token: config.value(S3_SESSION_TOKEN_ENV),
            region: config.value(S3_REGION_ENV),
            force_path_style: config.value(S3_FORCE_PATH_STYLE_ENV),
        })?;
        let dlx_archive_bucket = validate_s3_bucket(
            required_value(
                config.value(DLX_ARCHIVE_S3_BUCKET_ENV),
                DLX_ARCHIVE_S3_BUCKET_ENV,
            )?,
            DLX_ARCHIVE_S3_BUCKET_ENV,
        )?;
        anyhow::ensure!(
            dlx_archive_bucket != general.bucket,
            "{DLX_ARCHIVE_S3_BUCKET_ENV} must differ from {S3_BUCKET_ENV}"
        );
        let canary = s3_canary_config_from_values(
            config.value(S3_CANARY_KEY_PREFIX_ENV),
            config.value(S3_CANARY_INTERVAL_SECS_ENV),
            config.value(S3_CANARY_TIMEOUT_SECS_ENV),
        )?;
        let settings = Arc::clone(&general.settings);
        let general_identity = S3GeneralIdentityMarker::from_credentials(&general.credentials);

        Ok(Self {
            general,
            canary,
            dlx_archive: S3DlxArchiveConfig {
                settings,
                bucket: dlx_archive_bucket,
                general_identity,
            },
        })
    }

    pub(crate) fn into_parts(self) -> S3RuntimeConfigParts {
        S3RuntimeConfigParts {
            general: self.general,
            canary: self.canary,
            dlx_archive: self.dlx_archive,
        }
    }
}

fn required_value(value: Option<&str>, name: &'static str) -> anyhow::Result<String> {
    let value = value.ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{name} must not be empty");
    Ok(trimmed.to_owned())
}

fn s3_general_config_from_values(
    values: S3GeneralConfigValues<'_>,
) -> anyhow::Result<S3GeneralConfig> {
    let settings = Arc::new(s3_client_settings_from_values(
        values.endpoint_url,
        values.ca_cert_pem_path,
        values.region,
        values.force_path_style,
    )?);
    let bucket = validate_s3_bucket(required_value(values.bucket, S3_BUCKET_ENV)?, S3_BUCKET_ENV)?;
    let access_key_id = EnvSecret::required_value(values.access_key_id, S3_ACCESS_KEY_ID_ENV)?;
    let secret_access_key =
        EnvSecret::required_value(values.secret_access_key, S3_SECRET_ACCESS_KEY_ENV)?;
    let session_token = EnvSecret::optional_value(values.session_token, S3_SESSION_TOKEN_ENV)?;
    let credentials = aws_sdk_s3::config::Credentials::new(
        access_key_id.transfer_secret_allocation(),
        secret_access_key.transfer_secret_allocation(),
        session_token.map(EnvSecret::transfer_secret_allocation),
        None,
        "rss-runtime-snapshot",
    );
    Ok(S3GeneralConfig {
        settings,
        bucket,
        credentials,
    })
}

pub(crate) fn build_s3_runtime_deps(config: S3GeneralConfig) -> anyhow::Result<S3RuntimeDeps> {
    let S3GeneralConfig {
        settings,
        bucket,
        credentials,
    } = config;
    let factory = s3::PrivateCaS3ClientFactory::new(
        settings.endpoint.clone(),
        settings.region.clone(),
        credentials,
        settings.force_path_style,
        settings.ca_cert_pem.clone(),
    );
    let client = factory
        .build_client()
        .context("build S3 client with private CA")?;
    let store = S3Store::new(client, bucket).context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
}

/// Integration-only explicit-values seam. Production callers must use
/// [`S3RuntimeConfig::from_snapshot`].
#[cfg(any(test, feature = "integration"))]
pub(crate) fn build_s3_runtime_deps_from_values(
    endpoint_url: String,
    bucket: String,
    access_key_id: String,
    secret_access_key: String,
    force_path_style: bool,
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<S3RuntimeDeps> {
    let endpoint = secure::S3Endpoint::parse(endpoint_url, secure::PlaintextEndpointPolicy::Deny)
        .with_context(|| {
        format!("{S3_ENDPOINT_URL_ENV} must be https:// (plaintext http:// is banned)")
    })?;
    let factory = s3::PrivateCaS3ClientFactory::new(
        endpoint,
        DEFAULT_S3_REGION,
        aws_sdk_s3::config::Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "rss-runtime-integration",
        ),
        force_path_style,
        ca_cert_pem,
    );
    let client = factory
        .build_client()
        .context("build S3 client with private CA")?;
    let store = S3Store::new(client, bucket).context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
}

struct DlxIsolatedCredentialsProvider<P> {
    inner: P,
    general_identity: S3GeneralIdentityMarker,
}

impl<P> DlxIsolatedCredentialsProvider<P> {
    fn new(inner: P, general_identity: S3GeneralIdentityMarker) -> Self {
        Self {
            inner,
            general_identity,
        }
    }

    fn identity_is_distinct(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        !self.general_identity.collides_with(credentials)
    }
}

impl<P> std::fmt::Debug for DlxIsolatedCredentialsProvider<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DlxIsolatedCredentialsProvider(<redacted>)")
    }
}

impl<P> aws_sdk_s3::config::ProvideCredentials for DlxIsolatedCredentialsProvider<P>
where
    P: aws_sdk_s3::config::ProvideCredentials,
{
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::new(async move {
            let credentials = self.inner.provide_credentials().await?;
            if self.identity_is_distinct(&credentials) {
                Ok(credentials)
            } else {
                Err(
                    aws_credential_types::provider::error::CredentialsError::invalid_configuration(
                        DLX_IDENTITY_COLLISION_ERROR,
                    ),
                )
            }
        })
    }

    fn fallback_on_interrupt(&self) -> Option<aws_sdk_s3::config::Credentials> {
        self.inner
            .fallback_on_interrupt()
            .filter(|credentials| self.identity_is_distinct(credentials))
    }
}

pub(crate) async fn build_s3_dlx_archive_store(
    config: S3DlxArchiveConfig,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<S3DlxArchiveStore> {
    let S3DlxArchiveConfig {
        settings,
        bucket,
        general_identity,
    } = config;
    // Placeholder static credentials are unused: DLX always builds through a credentials provider.
    let factory = s3::PrivateCaS3ClientFactory::new(
        settings.endpoint.clone(),
        settings.region.clone(),
        aws_sdk_s3::config::Credentials::new(
            "rss-runtime-dlx-provider-driven",
            "rss-runtime-dlx-provider-driven",
            None,
            None,
            "rss-runtime-dlx",
        ),
        settings.force_path_style,
        settings.ca_cert_pem.clone(),
    );
    let http_client = factory
        .build_https_client()
        .context("build S3 private-CA HTTPS client for DLX default credentials chain")?;
    let region = aws_sdk_s3::config::Region::new(settings.region.clone());
    let provider_config = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(Some(region.clone()))
        .with_http_client(http_client);
    let credentials_provider =
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .region(region)
            .configure(provider_config)
            .build()
            .await;
    let credentials_provider =
        DlxIsolatedCredentialsProvider::new(credentials_provider, general_identity);
    credentials_provider
        .provide_credentials()
        .await
        .context("validate isolated DLX archive credentials from the AWS default provider chain")?;
    factory
        .build_dlx_archive_store(bucket, clock, credentials_provider)
        .context("construct DLX archive S3 store through PrivateCaS3ClientFactory")
}

struct S3ClientSettings {
    endpoint: secure::S3Endpoint,
    region: String,
    force_path_style: bool,
    ca_cert_pem: Vec<u8>,
}

fn s3_client_settings_from_values(
    endpoint_url: Option<&str>,
    ca_cert_pem_path: Option<&str>,
    region: Option<&str>,
    force_path_style: Option<&str>,
) -> anyhow::Result<S3ClientSettings> {
    // Production egress: plaintext opt-in knobs are banned (#1710); always Deny.
    let endpoint = secure::S3Endpoint::parse(
        required_value(endpoint_url, S3_ENDPOINT_URL_ENV)?,
        secure::PlaintextEndpointPolicy::Deny,
    )
    .with_context(|| {
        format!("{S3_ENDPOINT_URL_ENV} must be https:// (plaintext http:// is banned)")
    })?;
    let ca_cert_pem =
        crate::infra::read_required_ca_pem(ca_cert_pem_path, S3_CA_CERT_PEM_PATH_ENV)?;
    let region = region
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .unwrap_or(DEFAULT_S3_REGION)
        .to_owned();
    let force_path_style = parse_bool_value(force_path_style, S3_FORCE_PATH_STYLE_ENV, false)?;
    Ok(S3ClientSettings {
        endpoint,
        region,
        force_path_style,
        ca_cert_pem,
    })
}

#[cfg(test)]
fn build_s3_client_from_settings(
    settings: &S3ClientSettings,
    credentials_provider: impl aws_sdk_s3::config::ProvideCredentials + 'static,
    http_client: impl aws_sdk_s3::config::HttpClient + 'static,
) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(settings.region.clone()))
        .credentials_provider(credentials_provider)
        .endpoint_url(settings.endpoint.expose())
        .force_path_style(settings.force_path_style)
        .http_client(http_client)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

#[cfg(test)]
fn build_s3_dlx_client_from_settings<P>(
    settings: &S3ClientSettings,
    credentials_provider: DlxIsolatedCredentialsProvider<P>,
    http_client: impl aws_sdk_s3::config::HttpClient + 'static,
) -> aws_sdk_s3::Client
where
    P: aws_sdk_s3::config::ProvideCredentials + 'static,
{
    build_s3_client_from_settings(settings, credentials_provider, http_client)
}

fn parse_s3_duration_secs_value(
    raw: Option<&str>,
    name: &'static str,
    default: Duration,
    max_secs: u64,
) -> anyhow::Result<Duration> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let secs = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{name} must be an integer number of seconds"))?;
    anyhow::ensure!(
        secs > 0 && secs <= max_secs,
        "{name} must be 1..={max_secs}"
    );
    Ok(Duration::from_secs(secs))
}

fn parse_bool_value(raw: Option<&str>, name: &'static str, default: bool) -> anyhow::Result<bool> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("{name} must be false or true"),
    }
}

fn validate_s3_canary_prefix(raw: String) -> anyhow::Result<String> {
    let prefix = raw.trim().trim_matches('/');
    anyhow::ensure!(
        !prefix.is_empty(),
        "{S3_CANARY_KEY_PREFIX_ENV} must not be empty"
    );
    anyhow::ensure!(
        !prefix.contains("//")
            && prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.')),
        "{S3_CANARY_KEY_PREFIX_ENV} must contain only ASCII path-safe characters"
    );
    Ok(prefix.to_string())
}

#[derive(Clone)]
pub(crate) struct S3CanaryConfig {
    key: diport::ObjectKey,
    interval: Duration,
    timeout: Duration,
}

fn s3_canary_config_from_values(
    key_prefix: Option<&str>,
    interval_secs: Option<&str>,
    timeout_secs: Option<&str>,
) -> anyhow::Result<S3CanaryConfig> {
    let prefix = validate_s3_canary_prefix(
        key_prefix
            .unwrap_or(DEFAULT_S3_CANARY_KEY_PREFIX)
            .to_owned(),
    )?;
    let interval = parse_s3_duration_secs_value(
        interval_secs,
        S3_CANARY_INTERVAL_SECS_ENV,
        DEFAULT_S3_CANARY_INTERVAL,
        MAX_S3_CANARY_INTERVAL_SECS,
    )?;
    let timeout = parse_s3_duration_secs_value(
        timeout_secs,
        S3_CANARY_TIMEOUT_SECS_ENV,
        DEFAULT_S3_CANARY_TIMEOUT,
        MAX_S3_CANARY_TIMEOUT_SECS,
    )?;
    anyhow::ensure!(
        timeout <= interval,
        "{S3_CANARY_TIMEOUT_SECS_ENV} must be <= {S3_CANARY_INTERVAL_SECS_ENV}"
    );
    Ok(S3CanaryConfig {
        key: diport::ObjectKey::new(format!("{prefix}/{}.txt", uuid::Uuid::new_v4())),
        interval,
        timeout,
    })
}

pub(crate) async fn verify_s3_canary_round<S>(
    store: &S,
    key: diport::ObjectKey,
) -> anyhow::Result<()>
where
    S: ObjectStore,
{
    store
        .put_object(key.clone(), S3_CANARY_PAYLOAD.to_vec())
        .await
        .context("s3 canary put")?;
    let payload = store
        .get_object(key.clone())
        .await
        .context("s3 canary get after put")?
        .ok_or_else(|| anyhow::anyhow!("s3 canary object missing after put"))?;
    let bytes = payload
        .collect_limited(S3_CANARY_COLLECT_LIMIT)
        .await
        .context("s3 canary collect")?;
    anyhow::ensure!(bytes == S3_CANARY_PAYLOAD, "s3 canary payload mismatch");
    store
        .delete_object(key.clone())
        .await
        .context("s3 canary delete")?;
    anyhow::ensure!(
        store
            .get_object(key)
            .await
            .context("s3 canary get after delete")?
            .is_none(),
        "s3 canary object still exists after delete"
    );
    Ok(())
}

pub struct S3ReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl S3ReadyProbe {
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        let name = ProbeName::parse(S3_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for S3ReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

struct S3CanarySampler {
    handle: tokio::sync::Mutex<Option<diport::OwnedTask<()>>>,
    token: CancellationToken,
}

impl ManagedResource for S3CanarySampler {
    fn name(&self) -> &str {
        "s3-canary-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take() {
            handle
                .join()
                .await
                .map_err(ShutdownError::from_join_error)?;
        }
        Ok(())
    }
}

fn spawn_s3_canary_sampler(
    s3: S3RuntimeDeps,
    config: S3CanaryConfig,
    token: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) -> S3CanarySampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let store = s3.object_store();
    let handle = tokio::spawn(async move {
        loop {
            let round = tokio::time::timeout(
                config.timeout,
                verify_s3_canary_round(&*store, config.key.clone()),
            )
            .await;
            let is_ready = match round {
                Ok(Ok(())) => true,
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "s3 canary round failed");
                    false
                }
                Err(_) => {
                    tracing::warn!("s3 canary round timed out");
                    false
                }
            };
            ready.store(is_ready, std::sync::atomic::Ordering::Release);
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(config.interval) => {}
            }
        }
    });
    S3CanarySampler {
        handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(handle))),
        token: child,
    }
}

pub(crate) fn wire_s3_canary(
    deps: &SharedRuntimeDeps,
    config: S3CanaryConfig,
) -> anyhow::Result<DomainModuleResult> {
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe_name =
        ProbeName::parse(S3_READY_PROBE_NAME).context("parse s3_object_store_ready probe name")?;
    let probe_ready = Arc::clone(&ready);
    let worker_ready = Arc::clone(&ready);
    let s3 = deps.s3.clone();
    let worker = bootstrap::WorkerSpec::observational_phase_one(
        "assemblies.runtime.src.infra.s3.01",
        move |token| {
            DynManagedResource::new_box(spawn_s3_canary_sampler(
                s3.clone(),
                config,
                token,
                worker_ready,
            ))
        },
    );
    let mut output = DomainModuleResult::default();
    output.push_probe((probe_name, Box::new(S3ReadyProbe::new(probe_ready))));
    output.push_worker(worker);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[allow(clippy::expect_used)]
    fn assert_shutdown_error_redacts(error: &ShutdownError, marker: &str) {
        assert!(!error.to_string().contains(marker));
        assert!(!format!("{error:?}").contains(marker));
        let source = std::error::Error::source(error).expect("redacted source remains visible");
        assert!(!source.to_string().contains(marker));
        assert!(
            source.source().is_none(),
            "source chain stops at redaction boundary"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn canary_sampler_propagates_redacted_join_failure() {
        const MARKER: &str = "s3-canary-plain-panic-secret";
        let sampler = S3CanarySampler {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(tokio::spawn(async {
                panic!("{MARKER}");
            })))),
            token: CancellationToken::new(),
        };

        let error = ManagedResource::shutdown(&sampler)
            .await
            .expect_err("join failure must propagate");
        assert_shutdown_error_redacts(&error, MARKER);
        assert_eq!(error.kind(), diport::ShutdownErrorKind::TaskPanicked);
        assert!(
            ManagedResource::shutdown(&sampler).await.is_ok(),
            "shutdown is idempotent"
        );

        let cancelled_handle = tokio::spawn(std::future::pending::<()>());
        cancelled_handle.abort();
        let cancelled = S3CanarySampler {
            handle: tokio::sync::Mutex::new(Some(diport::OwnedTask::new(cancelled_handle))),
            token: CancellationToken::new(),
        };
        let cancelled_error = ManagedResource::shutdown(&cancelled)
            .await
            .expect_err("cancelled join must propagate");
        assert_eq!(
            cancelled_error.kind(),
            diport::ShutdownErrorKind::TaskCancelled
        );
    }

    fn valid_s3_values() -> Vec<(&'static str, String)> {
        vec![
            (S3_ENDPOINT_URL_ENV, "https://s3.snapshot.test".to_owned()),
            (S3_BUCKET_ENV, "rss-snapshot-general".to_owned()),
            (S3_CA_CERT_PEM_PATH_ENV, test_s3_ca_pem_path()),
            (S3_ACCESS_KEY_ID_ENV, "snapshot-access-marker".to_owned()),
            (
                S3_SECRET_ACCESS_KEY_ENV,
                "snapshot-secret-marker".to_owned(),
            ),
            (S3_SESSION_TOKEN_ENV, "snapshot-session-marker".to_owned()),
            (S3_REGION_ENV, "snapshot-region-1".to_owned()),
            (S3_FORCE_PATH_STYLE_ENV, "true".to_owned()),
            (DLX_ARCHIVE_S3_BUCKET_ENV, "rss-snapshot-archive".to_owned()),
            (S3_CANARY_KEY_PREFIX_ENV, "rss/snapshot-canary".to_owned()),
            (S3_CANARY_INTERVAL_SECS_ENV, "30".to_owned()),
            (S3_CANARY_TIMEOUT_SECS_ENV, "7".to_owned()),
        ]
    }

    use crate::infra::TEST_PRIVATE_CA_PEM as TEST_S3_CA_PEM;

    #[allow(clippy::expect_used)]
    fn test_s3_ca_pem_path() -> String {
        static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        PATH.get_or_init(|| {
            let path = std::env::temp_dir()
                .join(format!("rss-runtime-s3-test-ca-{}.pem", std::process::id()));
            std::fs::write(&path, TEST_S3_CA_PEM).expect("write s3 test CA");
            path
        })
        .display()
        .to_string()
    }

    fn snapshot_with_value(
        name: &'static str,
        value: &str,
    ) -> anyhow::Result<crate::config::RuntimeConfigSnapshot> {
        let mut values = valid_s3_values();
        let Some(entry) = values.iter_mut().find(|(key, _)| *key == name) else {
            anyhow::bail!("unknown S3 fixture key: {name}");
        };
        entry.1 = value.to_owned();
        let borrowed: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        Ok(crate::config::test_snapshot(&borrowed)?)
    }

    fn snapshot_from_valid_s3() -> anyhow::Result<crate::config::RuntimeConfigSnapshot> {
        let values = valid_s3_values();
        let borrowed: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        Ok(crate::config::test_snapshot(&borrowed)?)
    }

    fn assert_general_config(general: &S3GeneralConfig) {
        assert_eq!(
            general.settings.endpoint.expose(),
            "https://s3.snapshot.test"
        );
        assert_eq!(general.settings.region, "snapshot-region-1");
        assert!(general.settings.force_path_style);
        assert_eq!(general.bucket, "rss-snapshot-general");
        assert_eq!(
            general.credentials.access_key_id(),
            "snapshot-access-marker"
        );
        assert_eq!(
            general.credentials.secret_access_key(),
            "snapshot-secret-marker"
        );
        assert_eq!(
            general.credentials.session_token(),
            Some("snapshot-session-marker")
        );
    }

    fn assert_archive_and_canary_config(
        general: &S3GeneralConfig,
        dlx_archive: &S3DlxArchiveConfig,
        canary: &S3CanaryConfig,
    ) {
        assert!(Arc::ptr_eq(&general.settings, &dlx_archive.settings));
        assert_eq!(dlx_archive.bucket, "rss-snapshot-archive");
        assert!(
            dlx_archive
                .general_identity
                .collides_with(&general.credentials)
        );
        assert!(canary.key.as_str().starts_with("rss/snapshot-canary/"));
        assert_eq!(canary.interval, Duration::from_secs(30));
        assert_eq!(canary.timeout, Duration::from_secs(7));
    }

    #[test]
    fn runtime_infra_s3_snapshot_binds_one_generation_and_builds_general_store()
    -> anyhow::Result<()> {
        let snapshot = snapshot_from_valid_s3()?;
        let config = S3RuntimeConfig::from_snapshot(snapshot.view())?;
        assert_eq!(format!("{config:?}"), "S3RuntimeConfig(<redacted>)");

        let S3RuntimeConfigParts {
            general,
            canary,
            dlx_archive,
        } = config.into_parts();
        assert_general_config(&general);
        assert_archive_and_canary_config(&general, &dlx_archive, &canary);

        let deps = build_s3_runtime_deps(general)?;
        assert_eq!(deps.runtime_resources()[0].name(), "s3");
        Ok(())
    }

    #[test]
    fn runtime_infra_s3_snapshot_rejects_invalid_boundaries() -> anyhow::Result<()> {
        for (name, value, expected) in [
            (
                S3_ENDPOINT_URL_ENV,
                "http://127.0.0.1:9000",
                S3_ENDPOINT_URL_ENV,
            ),
            (S3_BUCKET_ENV, "INVALID_BUCKET", S3_BUCKET_ENV),
            (S3_ACCESS_KEY_ID_ENV, " access-marker", S3_ACCESS_KEY_ID_ENV),
            (
                S3_SECRET_ACCESS_KEY_ENV,
                "secret-marker ",
                S3_SECRET_ACCESS_KEY_ENV,
            ),
            (S3_SESSION_TOKEN_ENV, " ", S3_SESSION_TOKEN_ENV),
            (
                DLX_ARCHIVE_S3_BUCKET_ENV,
                "rss-snapshot-general",
                DLX_ARCHIVE_S3_BUCKET_ENV,
            ),
            (
                S3_CANARY_KEY_PREFIX_ENV,
                "bad//prefix",
                S3_CANARY_KEY_PREFIX_ENV,
            ),
            (
                S3_CANARY_INTERVAL_SECS_ENV,
                "301",
                S3_CANARY_INTERVAL_SECS_ENV,
            ),
            (S3_CANARY_TIMEOUT_SECS_ENV, "31", S3_CANARY_TIMEOUT_SECS_ENV),
        ] {
            let snapshot = snapshot_with_value(name, value)?;
            let Err(error) = S3RuntimeConfig::from_snapshot(snapshot.view()) else {
                anyhow::bail!("invalid {name} fixture unexpectedly succeeded");
            };
            anyhow::ensure!(
                format!("{error:#}").contains(expected),
                "unexpected error for {name}: {error:#}"
            );
        }

        let values = valid_s3_values();
        let values = values
            .into_iter()
            .filter(|(name, _)| *name != S3_ENDPOINT_URL_ENV)
            .collect::<Vec<_>>();
        let borrowed: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let snapshot = crate::config::test_snapshot(&borrowed)?;
        let Err(error) = S3RuntimeConfig::from_snapshot(snapshot.view()) else {
            anyhow::bail!("missing endpoint fixture unexpectedly succeeded");
        };
        assert!(format!("{error:#}").contains(S3_ENDPOINT_URL_ENV));

        let values = valid_s3_values();
        let values = values
            .into_iter()
            .filter(|(name, _)| *name != S3_CA_CERT_PEM_PATH_ENV)
            .collect::<Vec<_>>();
        let borrowed: Vec<(&str, &str)> = values.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let snapshot = crate::config::test_snapshot(&borrowed)?;
        let Err(error) = S3RuntimeConfig::from_snapshot(snapshot.view()) else {
            anyhow::bail!("missing S3 CA path fixture unexpectedly succeeded");
        };
        assert!(
            format!("{error:#}").contains(S3_CA_CERT_PEM_PATH_ENV),
            "missing CA must fail-fast with env name: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn runtime_infra_s3_snapshot_debug_and_errors_are_opaque() -> anyhow::Result<()> {
        let snapshot = snapshot_from_valid_s3()?;
        let config = S3RuntimeConfig::from_snapshot(snapshot.view())?;
        let debug = format!("{config:?}");
        for raw in [
            "s3.snapshot.test",
            "rss-snapshot-general",
            "snapshot-access-marker",
            "snapshot-secret-marker",
            "snapshot-session-marker",
        ] {
            assert!(!debug.contains(raw), "config Debug leaked {raw}: {debug}");
        }

        let endpoint = "https://endpoint-user:endpoint-secret@s3.snapshot.test";
        let snapshot = snapshot_with_value(S3_ENDPOINT_URL_ENV, endpoint)?;
        let Err(error) = S3RuntimeConfig::from_snapshot(snapshot.view()) else {
            anyhow::bail!("endpoint userinfo fixture unexpectedly succeeded");
        };
        let message = format!("{error:#}");
        for raw in [endpoint, "endpoint-user", "endpoint-secret"] {
            assert!(!message.contains(raw), "S3 error leaked {raw}: {message}");
        }
        Ok(())
    }

    #[test]
    fn runtime_infra_s3_snapshot_explicit_values_seam_uses_typed_mapping() -> anyhow::Result<()> {
        let ca_path = test_s3_ca_pem_path();
        let general = s3_general_config_from_values(S3GeneralConfigValues {
            endpoint_url: Some("https://s3.explicit.test"),
            ca_cert_pem_path: Some(ca_path.as_str()),
            bucket: Some("rss-explicit-values-unused-dlx"),
            access_key_id: Some("explicit-access-marker"),
            secret_access_key: Some("explicit-secret-marker"),
            session_token: None,
            region: None,
            force_path_style: Some("true"),
        })?;
        assert_eq!(general.bucket, "rss-explicit-values-unused-dlx");

        let deps = build_s3_runtime_deps_from_values(
            "https://s3.explicit.test".to_owned(),
            "rss-explicit-values-unused-dlx".to_owned(),
            "explicit-access-marker".to_owned(),
            "explicit-secret-marker".to_owned(),
            true,
            TEST_S3_CA_PEM.as_bytes().to_vec(),
        )?;
        assert_eq!(deps.runtime_resources()[0].name(), "s3");
        Ok(())
    }

    fn test_credentials(
        access_key_id: impl Into<String>,
        expires_after: Option<std::time::SystemTime>,
    ) -> aws_credential_types::Credentials {
        aws_credential_types::Credentials::new(
            access_key_id,
            "test-secret",
            None,
            expires_after,
            "runtime-test-provider",
        )
    }

    fn test_general_identity_marker(access_key_id: &str) -> S3GeneralIdentityMarker {
        S3GeneralIdentityMarker::from_credentials(&test_credentials(access_key_id, None))
    }

    #[test]
    fn dlx_general_identity_marker_is_access_key_only_and_opaque() {
        let marker = test_general_identity_marker("general-access-marker");
        let same_identity_different_secret = aws_credential_types::Credentials::new(
            "general-access-marker",
            "different-secret",
            Some("different-session".to_owned()),
            None,
            "runtime-test-provider",
        );
        let different_identity_same_secret = aws_credential_types::Credentials::new(
            "archive-access-marker",
            "test-secret",
            None,
            None,
            "runtime-test-provider",
        );

        assert!(marker.collides_with(&same_identity_different_secret));
        assert!(!marker.collides_with(&different_identity_same_secret));
        let debug = format!("{marker:?}");
        assert_eq!(debug, "S3GeneralIdentityMarker(<redacted>)");
        assert!(!debug.contains("general-access-marker"));
        assert!(!debug.contains("different-secret"));
        assert!(!debug.contains("different-session"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn dlx_isolated_credentials_provider_accepts_distinct_and_rejects_equal_identity() {
        use aws_credential_types::credential_fn::provide_credentials_fn;

        let distinct = DlxIsolatedCredentialsProvider::new(
            provide_credentials_fn(|| async { Ok(test_credentials("archive-access", None)) }),
            test_general_identity_marker("general-access"),
        );
        let credentials = distinct
            .provide_credentials()
            .await
            .expect("distinct DLX identity");
        assert_eq!(credentials.access_key_id(), "archive-access");

        let equal = DlxIsolatedCredentialsProvider::new(
            provide_credentials_fn(|| async { Ok(test_credentials("general-access", None)) }),
            test_general_identity_marker("general-access"),
        );
        let error = equal
            .provide_credentials()
            .await
            .expect_err("equal general and DLX identities must fail closed");
        let chain = format!("{error:?}");
        assert!(chain.contains(DLX_IDENTITY_COLLISION_ERROR));
        assert!(!chain.contains("general-access"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn archive_client_refreshes_expiring_provider_credentials() {
        use aws_credential_types::Credentials;
        use aws_credential_types::credential_fn::provide_credentials_fn;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let provider_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&provider_calls);
        let provider = provide_credentials_fn(move || {
            let sequence = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                Ok(Credentials::new(
                    format!("rotating-access-{sequence}"),
                    "rotating-secret",
                    None,
                    Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                    "runtime-test-rotating-provider",
                ))
            }
        });
        let authorizations = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let captured = Arc::clone(&authorizations);
        let http_client = aws_smithy_http_client::test_util::infallible_client_fn(move |request| {
            if let Some(value) = request.headers().get(http::header::AUTHORIZATION) {
                captured
                    .lock()
                    .expect("authorization capture mutex")
                    .push(value.to_str().expect("ASCII authorization").to_string());
            }
            http::Response::builder()
                .status(200)
                .body(Vec::<u8>::new())
                .expect("valid response")
        });
        let ca_path = test_s3_ca_pem_path();
        let settings = s3_client_settings_from_values(
            Some("https://s3.signing.test"),
            Some(ca_path.as_str()),
            None,
            Some("true"),
        )
        .expect("valid test endpoint");
        let provider = DlxIsolatedCredentialsProvider::new(
            provider,
            test_general_identity_marker("snapshot-general-access"),
        );
        let client = build_s3_dlx_client_from_settings(&settings, provider, http_client);

        client
            .head_bucket()
            .bucket("rss-prod-dlx-archive")
            .send()
            .await
            .expect("first signed request");
        client
            .head_bucket()
            .bucket("rss-prod-dlx-archive")
            .send()
            .await
            .expect("second signed request");

        assert!(provider_calls.load(Ordering::SeqCst) >= 2);
        let authorizations = authorizations.lock().expect("authorization capture mutex");
        assert_eq!(authorizations.len(), 2);
        assert!(authorizations[0].contains("rotating-access-1"));
        assert!(authorizations[1].contains("rotating-access-2"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn archive_client_rejects_identity_collision_after_refresh() {
        use aws_credential_types::credential_fn::provide_credentials_fn;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let provider_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&provider_calls);
        let provider = provide_credentials_fn(move || {
            let sequence = calls.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                let access_key_id = if sequence == 1 {
                    "archive-access"
                } else {
                    "general-access"
                };
                Ok(test_credentials(
                    access_key_id,
                    Some(std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
                ))
            }
        });
        let provider = DlxIsolatedCredentialsProvider::new(
            provider,
            test_general_identity_marker("general-access"),
        );
        let signed_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let captured = Arc::clone(&signed_requests);
        let http_client = aws_smithy_http_client::test_util::infallible_client_fn(move |_| {
            captured.fetch_add(1, Ordering::SeqCst);
            http::Response::builder()
                .status(200)
                .body(Vec::<u8>::new())
                .expect("valid response")
        });
        let ca_path = test_s3_ca_pem_path();
        let settings = s3_client_settings_from_values(
            Some("https://s3.signing.test"),
            Some(ca_path.as_str()),
            None,
            Some("true"),
        )
        .expect("valid test endpoint");
        let client = build_s3_dlx_client_from_settings(&settings, provider, http_client);

        client
            .head_bucket()
            .bucket("rss-prod-dlx-archive")
            .send()
            .await
            .expect("first distinct identity request");
        let error = client
            .head_bucket()
            .bucket("rss-prod-dlx-archive")
            .send()
            .await
            .expect_err("refreshed colliding identity must fail closed");

        assert!(provider_calls.load(Ordering::SeqCst) >= 2);
        assert_eq!(signed_requests.load(Ordering::SeqCst), 1);
        assert!(!format!("{error:?}").contains("general-access"));
    }

    #[derive(Clone, Copy)]
    enum CanaryScript {
        Happy,
        MissingAfterPut,
        PresentAfterDelete,
    }

    #[derive(Clone)]
    struct ScriptedObjectStore {
        script: CanaryScript,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl ScriptedObjectStore {
        fn new(script: CanaryScript) -> Self {
            Self {
                script,
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        #[allow(clippy::expect_used)]
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().expect("calls mutex").clone()
        }

        fn record(&self, call: &'static str) -> Result<(), diport::ObjectStoreError> {
            self.calls
                .lock()
                .map_err(|_| {
                    diport::ObjectStoreError::new(std::io::Error::other("calls mutex poisoned"))
                })?
                .push(call);
            Ok(())
        }
    }

    impl diport::ObjectStore for ScriptedObjectStore {
        async fn put_object(
            &self,
            _key: diport::ObjectKey,
            _body: Vec<u8>,
        ) -> Result<(), diport::ObjectStoreError> {
            self.record("put")
        }

        async fn get_object(
            &self,
            _key: diport::ObjectKey,
        ) -> Result<Option<diport::ObjectPayload>, diport::ObjectStoreError> {
            let get_count = {
                let mut calls = self.calls.lock().map_err(|_| {
                    diport::ObjectStoreError::new(std::io::Error::other("calls mutex poisoned"))
                })?;
                calls.push("get");
                calls.iter().filter(|&&call| call == "get").count()
            };
            match (self.script, get_count) {
                (CanaryScript::MissingAfterPut, 1) => Ok(None),
                (CanaryScript::PresentAfterDelete, 2) => Ok(Some(diport::ObjectPayload::new(
                    Box::pin(futures::stream::once(async {
                        Ok::<Vec<u8>, diport::ObjectStoreError>(S3_CANARY_PAYLOAD.to_vec())
                    })),
                ))),
                (_, 1) => Ok(Some(diport::ObjectPayload::new(Box::pin(
                    futures::stream::once(async {
                        Ok::<Vec<u8>, diport::ObjectStoreError>(S3_CANARY_PAYLOAD.to_vec())
                    }),
                )))),
                _ => Ok(None),
            }
        }

        async fn delete_object(
            &self,
            _key: diport::ObjectKey,
        ) -> Result<(), diport::ObjectStoreError> {
            self.record("delete")
        }

        async fn shutdown(&self) -> Result<(), diport::ObjectStoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_runs_put_get_delete_get_miss() -> anyhow::Result<()> {
        let store = ScriptedObjectStore::new(CanaryScript::Happy);
        verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await?;
        assert_eq!(store.calls(), vec!["put", "get", "delete", "get"]);
        Ok(())
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_fails_when_written_object_is_missing() {
        let store = ScriptedObjectStore::new(CanaryScript::MissingAfterPut);
        let result =
            verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn s3_canary_roundtrip_fails_when_delete_does_not_remove_object() {
        let store = ScriptedObjectStore::new(CanaryScript::PresentAfterDelete);
        let result =
            verify_s3_canary_round(&store, diport::ObjectKey::new("rss/runtime-canary/test")).await;
        assert!(result.is_err());
    }
}
