use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::{ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

use crate::config::SnapshotConfig;

/// 默认 Redis readiness 采样周期（5 秒）。
pub(crate) const DEFAULT_REDIS_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// Redis 是 distributed lock 运行期依赖，摘流延迟上限更短。
const MAX_REDIS_READINESS_INTERVAL_SECS: u64 = 30;
const REDIS_URL_ENV: &str = "RSS_REDIS_URL";
const REDIS_CA_CERT_PEM_PATH_ENV: &str = "RSS_REDIS_CA_CERT_PEM_PATH";
const REDIS_READINESS_INTERVAL_ENV: &str = "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS";

fn redis_readiness_interval_from_value(raw: Option<&str>) -> Duration {
    match raw {
        None => DEFAULT_REDIS_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_REDIS_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = REDIS_READINESS_INTERVAL_ENV,
                    raw = %raw,
                    max_secs = MAX_REDIS_READINESS_INTERVAL_SECS,
                    "invalid redis readiness sample interval (need 1..=30s); using default 5s"
                );
                DEFAULT_REDIS_READINESS_INTERVAL
            }
        },
    }
}

/// One parsed Redis generation. Private fields and a snapshot-only production constructor keep the
/// endpoint, private CA, and readiness freshness from being mixed across captures.
pub(crate) struct RedisRuntimeConfig {
    endpoint: secure::RedisEndpoint,
    ca: redis::RedisPrivateCa,
    readiness_interval: Duration,
}

struct RedisConfigValues<'a> {
    url: Option<String>,
    ca_cert_pem_path: Option<&'a str>,
    readiness_interval: Option<&'a str>,
}

impl RedisRuntimeConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        Self::from_values(RedisConfigValues {
            url: config.value(REDIS_URL_ENV).map(str::to_owned),
            ca_cert_pem_path: config.value(REDIS_CA_CERT_PEM_PATH_ENV),
            readiness_interval: config.value(REDIS_READINESS_INTERVAL_ENV),
        })
    }

    fn from_values(values: RedisConfigValues<'_>) -> anyhow::Result<Self> {
        // Production egress: plaintext opt-in knobs are banned (#1710); always Deny.
        let url = values
            .url
            .ok_or_else(|| anyhow::anyhow!("missing required env var: {REDIS_URL_ENV}"))?;
        let endpoint = secure::RedisEndpoint::parse(url, secure::PlaintextEndpointPolicy::Deny)
            .with_context(|| {
                format!(
                    "{REDIS_URL_ENV} must be rediss:// (plaintext redis:// is banned in production)"
                )
            })?;
        let pem = crate::infra::read_required_ca_pem(
            values.ca_cert_pem_path,
            REDIS_CA_CERT_PEM_PATH_ENV,
        )?;
        let ca = redis::RedisPrivateCa::from_pem(pem).with_context(|| {
            format!("parse Redis private CA PEM from {REDIS_CA_CERT_PEM_PATH_ENV}")
        })?;
        let readiness_interval = redis_readiness_interval_from_value(values.readiness_interval);
        Ok(Self {
            endpoint,
            ca,
            readiness_interval,
        })
    }
}

/// Consume the captured config to construct the only Redis pool and return its bound readiness
/// period with the capability bundle.
pub(crate) async fn build_redis_runtime_deps(
    config: RedisRuntimeConfig,
) -> anyhow::Result<(redis::RedisRuntimeDeps, Duration)> {
    let RedisRuntimeConfig {
        endpoint,
        ca,
        readiness_interval,
    } = config;
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build redis TLS pool with private CA")?;
    deps.ping()
        .await
        .with_context(|| format!("verify redis connectivity for {REDIS_URL_ENV}"))?;
    Ok((deps, readiness_interval))
}

/// Integration-only explicit-values seam. Production callers must use [`RedisRuntimeConfig::from_snapshot`].
#[cfg(any(test, feature = "integration"))]
pub(crate) async fn build_redis_runtime_deps_from_values(
    url: String,
    ca_cert_pem: Vec<u8>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let endpoint = secure::RedisEndpoint::parse(url, secure::PlaintextEndpointPolicy::Deny)
        .with_context(|| {
            format!("{REDIS_URL_ENV} must be rediss:// (plaintext redis:// is banned)")
        })?;
    let ca = redis::RedisPrivateCa::from_pem(ca_cert_pem).context("parse Redis private CA PEM")?;
    let deps = redis::RedisRuntimeDeps::connect_with_private_ca(&endpoint, ca)
        .context("build redis TLS pool with private CA")?;
    deps.ping()
        .await
        .with_context(|| format!("verify redis connectivity for {REDIS_URL_ENV}"))?;
    Ok(deps)
}

// ── RedisReadyProbe ───────────────────────────────────────────────────────────────────────────

/// Redis readiness probe stable name.
pub const REDIS_READY_PROBE_NAME: &str = "redis_ready";

/// Redis dependency readiness probe. Startup PING is fail-fast; this probe keeps the dependency
/// visible to `/readyz` and lets later Redis outages fail readiness.
pub struct RedisReadyProbe {
    ready: Arc<std::sync::atomic::AtomicBool>,
    name: ProbeName,
}

impl RedisReadyProbe {
    #[allow(clippy::expect_used)]
    pub fn new(ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        let name = ProbeName::parse(REDIS_READY_PROBE_NAME).expect("valid probe name const");
        Self { ready, name }
    }
}

impl bootstrap::HealthProbe for RedisReadyProbe {
    fn check(&self) -> HealthCheck {
        let (status, detail) = if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            (HealthStatus::Healthy, "ready")
        } else {
            (HealthStatus::Unhealthy, "down")
        };
        HealthCheck::new(self.name.clone(), status, detail)
    }
}

pub(crate) struct RedisReadinessSampler {
    handle: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    token: CancellationToken,
}

impl ManagedResource for RedisReadinessSampler {
    fn name(&self) -> &str {
        "redis-readiness-sampler"
    }

    async fn shutdown(&self) -> Result<(), ShutdownError> {
        self.token.cancel();
        let mut handle = self.handle.lock().await;
        if let Some(handle) = handle.take()
            && let Err(err) = handle.await
        {
            tracing::warn!(error = %err, "redis readiness sampler join failed");
        }
        Ok(())
    }
}

pub(crate) fn spawn_redis_readiness_sampler(
    redis: redis::RedisRuntimeDeps,
    period: Duration,
    token: CancellationToken,
    ready: Arc<std::sync::atomic::AtomicBool>,
) -> RedisReadinessSampler {
    let child = token.child_token();
    let worker_token = child.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                () = worker_token.cancelled() => break,
                () = tokio::time::sleep(period) => {
                    let is_ready = redis.ping().await.is_ok();
                    ready.store(is_ready, std::sync::atomic::Ordering::Release);
                }
            }
        }
    });
    RedisReadinessSampler {
        handle: tokio::sync::Mutex::new(Some(handle)),
        token: child,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    /// Stable self-signed CA PEM for unit tests that do not need a live matching server.
    use crate::infra::TEST_PRIVATE_CA_PEM as TEST_CA_PEM;

    #[allow(clippy::expect_used)]
    fn test_ca_pem_path() -> &'static str {
        static PATH: OnceLock<PathBuf> = OnceLock::new();
        PATH.get_or_init(|| {
            let path = std::env::temp_dir().join(format!(
                "rss-runtime-redis-test-ca-{}.pem",
                std::process::id()
            ));
            std::fs::write(&path, TEST_CA_PEM).expect("write redis test CA");
            path
        })
        .to_str()
        .expect("utf-8 temp path")
    }

    fn test_ca_pem_bytes() -> Vec<u8> {
        TEST_CA_PEM.as_bytes().to_vec()
    }

    struct GetterSource<F>(F);

    impl<F> crate::config::RuntimeConfigSource for GetterSource<F>
    where
        F: Fn(&str) -> Option<String>,
    {
        fn read(
            &mut self,
            key: &crate::config::RuntimeConfigKey,
        ) -> crate::config::CapturedConfigValue {
            (self.0)(key.as_str()).map_or(crate::config::CapturedConfigValue::Missing, |value| {
                crate::config::CapturedConfigValue::Present(secure::SecretText::from_string(value))
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn snapshot_from_get(
        get: impl Fn(&str) -> Option<String>,
    ) -> crate::config::RuntimeConfigSnapshot {
        crate::config::RuntimeConfigSnapshot::capture_test(GetterSource(get))
            .expect("closed test catalog")
    }

    async fn build_redis_runtime_deps(
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<redis::RedisRuntimeDeps> {
        let snapshot = snapshot_from_get(get);
        let config = RedisRuntimeConfig::from_snapshot(snapshot.view())?;
        super::build_redis_runtime_deps(config)
            .await
            .map(|(deps, _)| deps)
    }

    fn with_ca(get: impl Fn(&str) -> Option<String>) -> impl Fn(&str) -> Option<String> {
        move |name| {
            if name == REDIS_CA_CERT_PEM_PATH_ENV {
                Some(test_ca_pem_path().to_owned())
            } else {
                get(name)
            }
        }
    }

    fn build_redis_readiness_interval_from(get: impl Fn(&str) -> Option<String>) -> Duration {
        let snapshot = snapshot_from_get(get);
        redis_readiness_interval_from_value(snapshot.view().value(REDIS_READINESS_INTERVAL_ENV))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_redis_snapshot_binds_endpoint_ca_readiness_and_redacts_debug() {
        let snapshot = crate::config::test_snapshot(&[
            (
                REDIS_URL_ENV,
                "rediss://redis-user:redis-secret@cache.internal:6379/4",
            ),
            (REDIS_CA_CERT_PEM_PATH_ENV, test_ca_pem_path()),
            (REDIS_READINESS_INTERVAL_ENV, "13"),
        ])
        .expect("snapshot");
        let config = RedisRuntimeConfig::from_snapshot(snapshot.view()).expect("redis config");
        assert_eq!(config.readiness_interval, Duration::from_secs(13));
        let debug = format!("{:?}", config.endpoint);
        assert!(debug.contains("cache.internal:6379/4"));
        assert!(!debug.contains("redis-user"));
        assert!(!debug.contains("redis-secret"));
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn runtime_infra_redis_errors_and_values_seam_never_disclose_credentials() {
        let raw = "redis://redis-user:redis-secret@cache.internal:6379/0";
        let result =
            build_redis_runtime_deps_from_values(raw.to_owned(), test_ca_pem_bytes()).await;
        let error = result
            .err()
            .unwrap_or_else(|| panic!("plaintext redis URL must fail under Deny"));
        let message = format!("{error:#}");
        for secret in [raw, "redis-user", "redis-secret"] {
            assert!(!message.contains(secret), "credential leaked: {message}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn runtime_infra_redis_connection_errors_never_disclose_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("read loopback address");
        drop(listener);

        let username = "redis-user";
        let password = "redis-secret";
        let raw = format!("rediss://{username}:{password}@{addr}/0");
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            build_redis_runtime_deps_from_values(raw.clone(), test_ca_pem_bytes()),
        )
        .await
        .expect("redis connection failure must be bounded");

        let Err(error) = result else {
            panic!("unreachable rediss endpoint must fail pool.get or startup PING");
        };
        let message = format!("{error:#}");
        for secret in [raw.as_str(), username, password] {
            assert!(!message.contains(secret), "credential leaked: {message}");
        }
    }

    /// RedisReadyProbe：`true → Healthy("ready")` / `false → Unhealthy("down")`（fail-closed）。
    #[test]
    fn redis_ready_probe_maps_flag_to_health() {
        use bootstrap::HealthProbe;
        use std::sync::atomic::{AtomicBool, Ordering};

        let flag = Arc::new(AtomicBool::new(true));
        let probe = RedisReadyProbe::new(Arc::clone(&flag));
        let ready = probe.check();
        assert_eq!(ready.status(), HealthStatus::Healthy);
        assert_eq!(ready.detail(), "ready");
        assert_eq!(ready.name().as_str(), REDIS_READY_PROBE_NAME);

        flag.store(false, Ordering::Release);
        let down = probe.check();
        assert_eq!(down.status(), HealthStatus::Unhealthy);
        assert_eq!(down.detail(), "down");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_missing_url_fails_fast() {
        let result = build_redis_runtime_deps(with_ca(|_| None)).await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains(REDIS_URL_ENV)),
            "缺 redis url env 须 fail-fast 且错误含变量名"
        );
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_missing_ca_fails_fast() {
        let result = build_redis_runtime_deps(|name| {
            (name == REDIS_URL_ENV).then(|| "rediss://cache.internal:6379/0".to_string())
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_CA_CERT_PEM_PATH_ENV), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_plaintext_by_default() {
        let result = build_redis_runtime_deps(with_ca(|name| {
            (name == REDIS_URL_ENV).then(|| "redis://127.0.0.1:6379/0".to_string())
        }))
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_URL_ENV), "{err}");
        assert!(err.contains("rediss://"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_loopback_plaintext_under_deny() {
        let result = build_redis_runtime_deps(with_ca(|name| {
            (name == REDIS_URL_ENV).then(|| "redis://127.0.0.1:6379/0".to_string())
        }))
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_URL_ENV), "{err}");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_redis_runtime_deps_unreachable_url_fails_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

        let result = build_redis_runtime_deps(with_ca(|name| {
            (name == REDIS_URL_ENV).then(|| format!("rediss://{addr}"))
        }))
        .await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains(REDIS_URL_ENV)),
            "不可达 redis url 须启动期 fail-fast 且错误含变量名"
        );
    }

    #[cfg(feature = "integration")]
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_redis_runtime_deps_valid_env_single_sources_pool_guard() {
        let network = testkit::bridge_network("rss-runtime-redis-tls")
            .await
            .expect("bridge network");
        let dns_name = format!("{}-node", network.name());
        let fixture = testkit::redis_tls(testkit::NetworkAttachment {
            network: network.name(),
            dns_name: &dns_name,
        })
        .await
        .expect("redis tls fixture");
        let url = fixture.url().to_string();
        assert!(
            url.starts_with("rediss://"),
            "integration redis fixture must expose rediss:// after #1710"
        );
        let ca_path = std::env::temp_dir().join(format!(
            "rss-runtime-redis-it-ca-{}.pem",
            std::process::id()
        ));
        std::fs::write(&ca_path, fixture.ca_pem()).expect("write fixture CA");
        let deps = build_redis_runtime_deps(|name| match name {
            REDIS_URL_ENV => Some(url.clone()),
            REDIS_CA_CERT_PEM_PATH_ENV => Some(ca_path.display().to_string()),
            _ => None,
        })
        .await;
        assert!(deps.is_ok(), "有效 redis url + matching CA 须构造成功");
        let resources = deps.expect("valid redis deps").runtime_resources();
        assert_eq!(resources.len(), 1, "redis bundle 单源派生 pool guard");
        assert_eq!(resources[0].name(), "redis", "redis resource 即 pool guard");
    }

    #[test]
    fn build_redis_readiness_interval_uses_redis_env_not_pg_env() {
        let d = build_redis_readiness_interval_from(|n| match n {
            "RSS_PG_READINESS_SAMPLE_INTERVAL_SECS" => Some("300".to_string()),
            REDIS_READINESS_INTERVAL_ENV => Some("7".to_string()),
            _ => None,
        });
        assert_eq!(d, Duration::from_secs(7));
    }

    #[test]
    fn build_redis_readiness_interval_rejects_pg_sized_upper_bound() {
        let d = build_redis_readiness_interval_from(|n| {
            (n == REDIS_READINESS_INTERVAL_ENV).then(|| "300".to_string())
        });
        assert_eq!(d, DEFAULT_REDIS_READINESS_INTERVAL);
    }
}
