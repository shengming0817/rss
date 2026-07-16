use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use aws_sdk_s3::config::ProvideCredentials as _;
use bootstrap::DomainModuleResult;
use diport::{DynManagedResource, ManagedResource, ObjectStore, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use s3::{S3DlxArchiveStore, S3RuntimeDeps, S3Store};
use tokio_util::sync::CancellationToken;

use crate::infra::plaintext_endpoint_policy_from;
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
const S3_ACCESS_KEY_ID_ENV: &str = "RSS_S3_ACCESS_KEY_ID";
const S3_SECRET_ACCESS_KEY_ENV: &str = "RSS_S3_SECRET_ACCESS_KEY";
const S3_SESSION_TOKEN_ENV: &str = "RSS_S3_SESSION_TOKEN";
const S3_REGION_ENV: &str = "RSS_S3_REGION";
const S3_FORCE_PATH_STYLE_ENV: &str = "RSS_S3_FORCE_PATH_STYLE";
const S3_ALLOW_PLAINTEXT_ENV: &str = "RSS_S3_ALLOW_PLAINTEXT";
const DLX_ARCHIVE_S3_BUCKET_ENV: &str = "RSS_DLX_ARCHIVE_S3_BUCKET";
const S3_CANARY_KEY_PREFIX_ENV: &str = "RSS_S3_CANARY_KEY_PREFIX";
const S3_CANARY_INTERVAL_SECS_ENV: &str = "RSS_S3_CANARY_INTERVAL_SECS";
const S3_CANARY_TIMEOUT_SECS_ENV: &str = "RSS_S3_CANARY_TIMEOUT_SECS";
const DEFAULT_S3_REGION: &str = "us-east-1";
const DEFAULT_S3_CANARY_KEY_PREFIX: &str = "rss/runtime-canary";
const S3_CANARY_COLLECT_LIMIT: usize = 1024;
pub(crate) const S3_CANARY_PAYLOAD: &[u8] = b"rss-s3-canary";
pub const S3_READY_PROBE_NAME: &str = "s3_object_store_ready";

fn required_env(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> anyhow::Result<String> {
    let value = get(name).ok_or_else(|| anyhow::anyhow!("missing required env var: {name}"))?;
    let trimmed = value.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{name} must not be empty");
    Ok(trimmed.to_string())
}

fn parse_bool_env(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: bool,
) -> anyhow::Result<bool> {
    let Some(raw) = get(name) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("{name} must be false or true"),
    }
}

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

pub fn build_s3_runtime_deps_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<S3RuntimeDeps> {
    let bucket = validate_s3_bucket(required_env(&get, S3_BUCKET_ENV)?, S3_BUCKET_ENV)?;
    let credentials = S3EnvCredentials {
        access_key_id: required_env(&get, S3_ACCESS_KEY_ID_ENV)?,
        secret_access_key: EnvSecret::required(&get, S3_SECRET_ACCESS_KEY_ENV)?,
        session_token: EnvSecret::optional(&get, S3_SESSION_TOKEN_ENV)?,
    };
    let client = build_s3_client_from(&get, credentials, "rss-runtime-env")?;
    let store = S3Store::new(client, bucket).context("construct s3 object store")?;
    Ok(S3RuntimeDeps::new(store))
}

pub(crate) async fn build_s3_dlx_archive_store_from(
    get: impl Fn(&str) -> Option<String>,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<S3DlxArchiveStore> {
    let bucket = dlx_archive_bucket_from(&get)?;
    let settings = s3_client_settings_from(&get)?;
    let http_client = s3_http_client(&settings.endpoint);
    let region = aws_sdk_s3::config::Region::new(settings.region.clone());
    let provider_config = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(Some(region.clone()))
        .with_http_client(http_client.clone());
    let credentials_provider =
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .region(region)
            .configure(provider_config)
            .build()
            .await;
    let initial_credentials = credentials_provider
        .provide_credentials()
        .await
        .context("resolve DLX archive credentials from the AWS default provider chain")?;
    if let Some(general_access_key) = get(S3_ACCESS_KEY_ID_ENV) {
        anyhow::ensure!(
            initial_credentials.access_key_id() != general_access_key.trim(),
            "DLX archive workload identity must differ from {S3_ACCESS_KEY_ID_ENV}"
        );
    }
    let client = build_s3_client_from_settings(settings, credentials_provider, http_client);
    S3DlxArchiveStore::new(client, bucket, clock).context("construct DLX archive S3 store")
}

fn dlx_archive_bucket_from(get: &impl Fn(&str) -> Option<String>) -> anyhow::Result<String> {
    let bucket = validate_s3_bucket(
        required_env(&get, DLX_ARCHIVE_S3_BUCKET_ENV)?,
        DLX_ARCHIVE_S3_BUCKET_ENV,
    )?;
    if let Some(general_bucket) = get(S3_BUCKET_ENV) {
        anyhow::ensure!(
            bucket != general_bucket.trim(),
            "{DLX_ARCHIVE_S3_BUCKET_ENV} must differ from {S3_BUCKET_ENV}"
        );
    }
    Ok(bucket)
}

struct S3EnvCredentials {
    access_key_id: String,
    secret_access_key: EnvSecret,
    session_token: Option<EnvSecret>,
}

fn build_s3_client_from(
    get: &impl Fn(&str) -> Option<String>,
    credentials: S3EnvCredentials,
    credential_source: &'static str,
) -> anyhow::Result<aws_sdk_s3::Client> {
    let settings = s3_client_settings_from(get)?;
    let http_client = s3_http_client(&settings.endpoint);
    let S3EnvCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    } = credentials;
    let credentials = aws_sdk_s3::config::Credentials::new(
        access_key_id,
        secret_access_key.transfer_secret_allocation(),
        session_token.map(EnvSecret::transfer_secret_allocation),
        None,
        credential_source,
    );
    Ok(build_s3_client_from_settings(
        settings,
        credentials,
        http_client,
    ))
}

struct S3ClientSettings {
    endpoint: secure::S3Endpoint,
    region: String,
    force_path_style: bool,
}

fn s3_client_settings_from(
    get: &impl Fn(&str) -> Option<String>,
) -> anyhow::Result<S3ClientSettings> {
    let endpoint = secure::S3Endpoint::parse(
        required_env(&get, S3_ENDPOINT_URL_ENV)?,
        plaintext_endpoint_policy_from(get, S3_ALLOW_PLAINTEXT_ENV)?,
    )
    .with_context(|| {
        format!("{S3_ENDPOINT_URL_ENV} must be https:// or loopback http:// with explicit opt-in")
    })?;
    let region = get(S3_REGION_ENV)
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .unwrap_or_else(|| DEFAULT_S3_REGION.to_string());
    let force_path_style = parse_bool_env(&get, S3_FORCE_PATH_STYLE_ENV, false)?;
    Ok(S3ClientSettings {
        endpoint,
        region,
        force_path_style,
    })
}

fn s3_http_client(endpoint: &secure::S3Endpoint) -> aws_sdk_s3::config::SharedHttpClient {
    if endpoint.is_plaintext() {
        aws_smithy_http_client::Builder::new().build_http()
    } else {
        aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https()
    }
}

fn build_s3_client_from_settings(
    settings: S3ClientSettings,
    credentials_provider: impl aws_sdk_s3::config::ProvideCredentials + 'static,
    http_client: impl aws_sdk_s3::config::HttpClient + 'static,
) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::config::Builder::new()
        .behavior_version_latest()
        .region(aws_sdk_s3::config::Region::new(settings.region))
        .credentials_provider(credentials_provider)
        .endpoint_url(settings.endpoint.expose())
        .force_path_style(settings.force_path_style)
        .http_client(http_client)
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

fn parse_s3_duration_secs(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: Duration,
    max_secs: u64,
) -> anyhow::Result<Duration> {
    let Some(raw) = get(name) else {
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

pub(crate) fn build_s3_canary_config_from(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<S3CanaryConfig> {
    let prefix = validate_s3_canary_prefix(
        get(S3_CANARY_KEY_PREFIX_ENV).unwrap_or_else(|| DEFAULT_S3_CANARY_KEY_PREFIX.to_string()),
    )?;
    let interval = parse_s3_duration_secs(
        &get,
        S3_CANARY_INTERVAL_SECS_ENV,
        DEFAULT_S3_CANARY_INTERVAL,
        MAX_S3_CANARY_INTERVAL_SECS,
    )?;
    let timeout = parse_s3_duration_secs(
        &get,
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
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for S3CanarySampler {
    fn name(&self) -> &str {
        "s3-canary-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "s3 canary sampler join failed");
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
        handle: tokio::sync::Mutex::new(Some(handle)),
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
    let worker: bootstrap::WorkerSpec = Box::new(move |token| {
        DynManagedResource::new_box(spawn_s3_canary_sampler(
            s3.clone(),
            config,
            token,
            worker_ready,
        ))
    });
    Ok(DomainModuleResult {
        probes: vec![(probe_name, Box::new(S3ReadyProbe::new(probe_ready)))],
        resources: Vec::new(),
        workers: vec![worker],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn full_s3_get(k: &str) -> Option<String> {
        match k {
            "RSS_S3_ENDPOINT_URL" => Some("https://s3.us-east-1.amazonaws.com".to_string()),
            "RSS_S3_BUCKET" => Some("rss-prod-bucket".to_string()),
            "RSS_S3_ACCESS_KEY_ID" => Some("access-key".to_string()),
            "RSS_S3_SECRET_ACCESS_KEY" => Some("secret-key".to_string()),
            _ => None,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_missing_endpoint_fails_fast() {
        let result = build_s3_runtime_deps_from(|k| {
            if k == "RSS_S3_ENDPOINT_URL" {
                None
            } else {
                full_s3_get(k)
            }
        });
        let err = result.err().expect("missing endpoint must fail");
        assert!(format!("{err:#}").contains("RSS_S3_ENDPOINT_URL"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_rejects_plaintext_by_default() {
        let result = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:9000".to_string()),
            _ => full_s3_get(k),
        });
        let err = result.err().expect("plaintext needs explicit opt-in");
        assert!(format!("{err:#}").contains("RSS_S3_ENDPOINT_URL"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_rejects_non_loopback_plaintext_even_with_opt_in() {
        let result = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://minio.internal:9000".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
            _ => full_s3_get(k),
        });
        let err = result
            .err()
            .expect("non-loopback plaintext must fail closed");
        assert!(format!("{err:#}").contains("loopback"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_allows_dev_container_minio_only_with_explicit_policy() {
        let deps = build_s3_runtime_deps_from(|k| match k {
            "RSS_S3_ENDPOINT_URL" => Some("http://minio:9000".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("dev-container".to_string()),
            "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
            _ => full_s3_get(k),
        })
        .expect("dev-container minio endpoint should build");
        assert_eq!(deps.runtime_resources()[0].name(), "s3");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn build_s3_runtime_deps_https_single_sources_resource_guard() {
        let deps = build_s3_runtime_deps_from(full_s3_get).expect("valid s3 config");
        let resources = deps.runtime_resources();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].name(), "s3");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn dlx_archive_requires_a_dedicated_bucket() {
        let err = dlx_archive_bucket_from(&full_s3_get)
            .expect_err("general object-store config must not satisfy DLX archive config");
        assert!(format!("{err:#}").contains("RSS_DLX_ARCHIVE_S3_BUCKET"));

        let err = dlx_archive_bucket_from(&|name| match name {
            "RSS_DLX_ARCHIVE_S3_BUCKET" => Some("rss-prod-bucket".to_string()),
            _ => full_s3_get(name),
        })
        .expect_err("archive bucket reuse must fail closed");
        assert!(format!("{err:#}").contains("RSS_S3_BUCKET"));

        let bucket = dlx_archive_bucket_from(&|name| match name {
            "RSS_DLX_ARCHIVE_S3_BUCKET" => Some("rss-prod-dlx-archive".to_string()),
            _ => full_s3_get(name),
        })
        .expect("dedicated archive bucket");
        assert_eq!(bucket, "rss-prod-dlx-archive");
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
        let settings = s3_client_settings_from(&|name| match name {
            "RSS_S3_ENDPOINT_URL" => Some("http://127.0.0.1:9000".to_string()),
            "RSS_S3_ALLOW_PLAINTEXT" => Some("true".to_string()),
            "RSS_S3_FORCE_PATH_STYLE" => Some("true".to_string()),
            _ => full_s3_get(name),
        })
        .expect("valid test endpoint");
        let client = build_s3_client_from_settings(settings, provider, http_client);

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
