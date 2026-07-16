use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::{ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

use crate::config::SnapshotConfig;
use crate::infra::plaintext_endpoint_policy_from_value;

/// 默认 Redis readiness 采样周期（5 秒）。
pub(crate) const DEFAULT_REDIS_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// Redis 是 distributed lock 运行期依赖，摘流延迟上限更短。
const MAX_REDIS_READINESS_INTERVAL_SECS: u64 = 30;
const REDIS_URL_ENV: &str = "RSS_REDIS_URL";
const REDIS_ALLOW_PLAINTEXT_ENV: &str = "RSS_REDIS_ALLOW_PLAINTEXT";
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
/// endpoint, transport policy, and readiness freshness from being mixed across captures.
pub(crate) struct RedisRuntimeConfig {
    endpoint: secure::RedisEndpoint,
    plaintext_policy: secure::PlaintextEndpointPolicy,
    readiness_interval: Duration,
}

struct RedisConfigValues<'a> {
    url: Option<String>,
    allow_plaintext: Option<&'a str>,
    readiness_interval: Option<&'a str>,
}

impl RedisRuntimeConfig {
    pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> anyhow::Result<Self> {
        Self::from_values(RedisConfigValues {
            url: config.value(REDIS_URL_ENV).map(str::to_owned),
            allow_plaintext: config.value(REDIS_ALLOW_PLAINTEXT_ENV),
            readiness_interval: config.value(REDIS_READINESS_INTERVAL_ENV),
        })
    }

    fn from_values(values: RedisConfigValues<'_>) -> anyhow::Result<Self> {
        let plaintext_policy = plaintext_endpoint_policy_from_value(
            values.allow_plaintext,
            REDIS_ALLOW_PLAINTEXT_ENV,
        )?;
        let url = values
            .url
            .ok_or_else(|| anyhow::anyhow!("missing required env var: {REDIS_URL_ENV}"))?;
        let endpoint = secure::RedisEndpoint::parse(url, plaintext_policy).with_context(|| {
            format!(
                "{REDIS_URL_ENV} must be rediss:// or loopback redis:// with explicit plaintext opt-in"
            )
        })?;
        let readiness_interval = redis_readiness_interval_from_value(values.readiness_interval);
        Ok(Self {
            endpoint,
            plaintext_policy,
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
        plaintext_policy,
        readiness_interval,
    } = config;
    let _bound_plaintext_policy = plaintext_policy;
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 Redis pool builder callsite；endpoint 已经由 secure::RedisEndpoint 校验。
    let raw_url = endpoint.expose();
    let pool = deadpool_redis::Config::from_url(raw_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("create redis pool")?;
    verify_redis_pool(&pool)
        .await
        .with_context(|| format!("verify redis connectivity for {REDIS_URL_ENV}"))?;
    Ok((redis::RedisRuntimeDeps::setup(pool), readiness_interval))
}

/// Integration-only explicit-values seam. Production callers must use [`RedisRuntimeConfig::from_snapshot`].
#[cfg(any(test, feature = "integration"))]
pub(crate) async fn build_redis_runtime_deps_from_values(
    url: String,
    allow_plaintext: Option<&str>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let config = RedisRuntimeConfig::from_values(RedisConfigValues {
        url: Some(url),
        allow_plaintext,
        readiness_interval: None,
    })?;
    build_redis_runtime_deps(config).await.map(|(deps, _)| deps)
}

async fn verify_redis_pool(pool: &deadpool_redis::Pool) -> anyhow::Result<()> {
    let mut conn = pool.get().await.context("connect redis resource")?;
    let pong: String = deadpool_redis::redis::cmd("PING")
        .query_async(&mut *conn)
        .await
        .context("ping redis resource")?;
    anyhow::ensure!(pong == "PONG", "redis resource returned non-PONG ping");
    Ok(())
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
    use std::sync::Arc;
    use std::time::Duration;

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
        crate::config::RuntimeConfigSnapshot::capture(GetterSource(get))
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

    fn build_redis_readiness_interval_from(get: impl Fn(&str) -> Option<String>) -> Duration {
        let snapshot = snapshot_from_get(get);
        redis_readiness_interval_from_value(snapshot.view().value(REDIS_READINESS_INTERVAL_ENV))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn runtime_infra_redis_snapshot_binds_endpoint_policy_readiness_and_redacts_debug() {
        let snapshot = crate::config::test_snapshot(&[
            (
                REDIS_URL_ENV,
                "redis://redis-user:redis-secret@127.0.0.1:6379/4",
            ),
            (REDIS_ALLOW_PLAINTEXT_ENV, "true"),
            (REDIS_READINESS_INTERVAL_ENV, "13"),
        ])
        .expect("snapshot");
        let config = RedisRuntimeConfig::from_snapshot(snapshot.view()).expect("redis config");
        assert_eq!(
            config.plaintext_policy,
            secure::PlaintextEndpointPolicy::AllowLoopback
        );
        assert_eq!(config.readiness_interval, Duration::from_secs(13));
        let debug = format!("{:?}", config.endpoint);
        assert!(debug.contains("127.0.0.1:6379/4"));
        assert!(!debug.contains("redis-user"));
        assert!(!debug.contains("redis-secret"));
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn runtime_infra_redis_errors_and_values_seam_never_disclose_credentials() {
        let raw = "redis://redis-user:redis-secret@cache.internal:6379/0";
        let result = build_redis_runtime_deps_from_values(raw.to_owned(), Some("true")).await;
        let error = result
            .err()
            .unwrap_or_else(|| panic!("non-loopback URL must fail"));
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
        let disconnect = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept redis connection");
            drop(stream);
        });

        let username = "redis-user";
        let password = "redis-secret";
        let raw = format!("redis://{username}:{password}@{addr}/0");
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            build_redis_runtime_deps_from_values(raw.clone(), Some("true")),
        )
        .await
        .expect("redis connection failure must be bounded");
        disconnect.await.expect("disconnect fixture task");

        let Err(error) = result else {
            panic!("fixture disconnect must fail pool.get or startup PING");
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
        let result = build_redis_runtime_deps(|_| None).await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains(REDIS_URL_ENV)),
            "缺 redis url env 须 fail-fast 且错误含变量名"
        );
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_plaintext_by_default() {
        let result = build_redis_runtime_deps(|name| {
            (name == REDIS_URL_ENV).then(|| "redis://127.0.0.1:6379/0".to_string())
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_URL_ENV), "{err}");
        assert!(err.contains("rediss://"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_non_loopback_plaintext_even_with_opt_in() {
        let result = build_redis_runtime_deps(|name| match name {
            REDIS_URL_ENV => Some("redis://cache.internal:6379/0".to_string()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("loopback"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_invalid_plaintext_opt_in() {
        let result = build_redis_runtime_deps(|name| match name {
            REDIS_URL_ENV => Some("rediss://cache.internal:6379/0".to_string()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("enabled".to_string()),
            _ => None,
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains(REDIS_ALLOW_PLAINTEXT_ENV), "{err}");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn build_redis_runtime_deps_unreachable_url_fails_fast() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

        let result = build_redis_runtime_deps(|name| match name {
            REDIS_URL_ENV => Some(format!("redis://{addr}")),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
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
        let fixture = testkit::env_or_redis().await.expect("redis fixture");
        let url = fixture.url().to_string();
        let deps = build_redis_runtime_deps(|name| match name {
            REDIS_URL_ENV => Some(url.clone()),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .await;
        assert!(deps.is_ok(), "有效 redis url 须构造成功");
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
