use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use diport::{ManagedResource, ShutdownError};
use primitives::{HealthCheck, HealthStatus, ProbeName};
use tokio_util::sync::CancellationToken;

use crate::infra::plaintext_endpoint_policy_from;

/// 默认 Redis readiness 采样周期（5 秒）。
pub(crate) const DEFAULT_REDIS_READINESS_INTERVAL: Duration = Duration::from_secs(5);
/// Redis 是 distributed lock 运行期依赖，摘流延迟上限更短。
const MAX_REDIS_READINESS_INTERVAL_SECS: u64 = 30;
/// redis_ready 采样周期（env `RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS`）。
pub(crate) fn build_redis_readiness_interval_from(
    get: impl Fn(&str) -> Option<String>,
) -> Duration {
    match get("RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS") {
        None => DEFAULT_REDIS_READINESS_INTERVAL,
        Some(raw) => match raw.parse::<u64>() {
            Ok(n) if (1..=MAX_REDIS_READINESS_INTERVAL_SECS).contains(&n) => Duration::from_secs(n),
            _ => {
                tracing::warn!(
                    env = "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS",
                    raw = %raw,
                    max_secs = MAX_REDIS_READINESS_INTERVAL_SECS,
                    "invalid redis readiness sample interval (need 1..=30s); using default 5s"
                );
                DEFAULT_REDIS_READINESS_INTERVAL
            }
        },
    }
}

pub(crate) fn build_redis_readiness_interval() -> Duration {
    build_redis_readiness_interval_from(|n| std::env::var(n).ok())
}

pub(crate) const REDIS_ALLOW_PLAINTEXT_ENV: &str = "RSS_REDIS_ALLOW_PLAINTEXT";

/// 组合根级 redis capability bundle 构造：`RSS_REDIS_URL` → typed TLS endpoint → deadpool redis pool + PING → [`redis::RedisRuntimeDeps`].
///
/// 缺 `RSS_REDIS_URL` 或 Redis 不可达均 fail-fast；错误上下文只含 env/resource 名，不含 URL 值。
/// 生命周期关闭经 `RedisRuntimeDeps::runtime_resources()` 单源进入
/// [`DomainModuleResult::resources`]。
pub async fn build_redis_runtime_deps(
    get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<redis::RedisRuntimeDeps> {
    let policy = plaintext_endpoint_policy_from(&get, REDIS_ALLOW_PLAINTEXT_ENV)?;
    let url = get("RSS_REDIS_URL")
        .ok_or_else(|| anyhow::anyhow!("missing required env var: RSS_REDIS_URL"))?;
    let endpoint = secure::RedisEndpoint::parse(url, policy).context(
        "RSS_REDIS_URL must be rediss:// or loopback redis:// with explicit plaintext opt-in",
    )?;
    #[allow(clippy::disallowed_methods)]
    // reason: 唯一 Redis pool builder callsite；endpoint 已经由 secure::RedisEndpoint 校验。
    let raw_url = endpoint.expose();
    let pool = deadpool_redis::Config::from_url(raw_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .context("create redis pool")?;
    verify_redis_pool(&pool)
        .await
        .context("verify redis connectivity for RSS_REDIS_URL")?;
    Ok(redis::RedisRuntimeDeps::setup(pool))
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
            matches!(&result, Err(e) if format!("{e:#}").contains("RSS_REDIS_URL")),
            "缺 redis url env 须 fail-fast 且错误含变量名"
        );
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_plaintext_by_default() {
        let result = build_redis_runtime_deps(|name| {
            (name == "RSS_REDIS_URL").then(|| "redis://127.0.0.1:6379/0".to_string())
        })
        .await;
        let err = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(err.contains("RSS_REDIS_URL"), "{err}");
        assert!(err.contains("rediss://"), "{err}");
    }

    #[tokio::test]
    async fn build_redis_runtime_deps_rejects_non_loopback_plaintext_even_with_opt_in() {
        let result = build_redis_runtime_deps(|name| match name {
            "RSS_REDIS_URL" => Some("redis://cache.internal:6379/0".to_string()),
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
            "RSS_REDIS_URL" => Some("rediss://cache.internal:6379/0".to_string()),
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
            "RSS_REDIS_URL" => Some(format!("redis://{addr}")),
            REDIS_ALLOW_PLAINTEXT_ENV => Some("true".to_string()),
            _ => None,
        })
        .await;
        assert!(
            matches!(&result, Err(e) if format!("{e:#}").contains("RSS_REDIS_URL")),
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
            "RSS_REDIS_URL" => Some(url.clone()),
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
            "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS" => Some("7".to_string()),
            _ => None,
        });
        assert_eq!(d, Duration::from_secs(7));
    }

    #[test]
    fn build_redis_readiness_interval_rejects_pg_sized_upper_bound() {
        let d = build_redis_readiness_interval_from(|n| {
            (n == "RSS_REDIS_READINESS_SAMPLE_INTERVAL_SECS").then(|| "300".to_string())
        });
        assert_eq!(d, DEFAULT_REDIS_READINESS_INTERVAL);
    }
}
