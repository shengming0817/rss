//! Redis shared-infrastructure key registry for listener rate limiting.
//!
//! Keys are `_runtime:listener-rate-limit:v2:<assembly>:<sha256(policy)>:<sha256(subject)>`. The fixed second
//! segment `listener-rate-limit` is structurally disjoint from the adapter's registered
//! `_runtime:cas`, `_runtime:distlock`, and `_runtime:inbox_receipts` families. Only the opaque
//! subject is hashed; neither the subject nor the client IP is stored or logged.

use std::sync::Arc;
use std::time::Duration;

use deadpool_redis::redis::Script;
use diport::{RateLimitDecision, RateLimitError, RateLimitKey, RateLimitQuota, RateLimiter};
use sha2::{Digest, Sha256};

use crate::RedisStore;

const KEY_NAMESPACE: &str = "_runtime:listener-rate-limit:v2";
const POOL_WAIT_TIMEOUT: Duration = Duration::from_millis(25);
const CHECK_TIMEOUT: Duration = Duration::from_millis(100);
const GCRA_SCRIPT: &str = r#"
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000000 + tonumber(time[2])
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local stored = redis.call('GET', KEYS[1])
local tat = stored and tonumber(stored) or now
if tat < now then
  tat = now
end
local tolerance = (burst - 1) * interval
local allow_at = tat - tolerance
if now < allow_at then
  return {0, math.max(1, math.ceil(allow_at - now))}
end
local new_tat = tat + interval
local ttl_ms = math.max(1, math.ceil((new_tat - now) / 1000))
redis.call('SET', KEYS[1], string.format('%.6f', new_tat), 'PX', ttl_ms)
return {1, 0}
"#;

/// Invalid generated assembly namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("rate-limit namespace is invalid")]
pub struct InvalidRateLimitNamespace;

/// Startup verification failure for the Redis listener rate-limiter capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("redis rate-limit capability verification failed")]
pub struct RedisRateLimitCapabilityError;

#[derive(Debug, thiserror::Error)]
#[error("redis rate-limit operation failed")]
struct RedisRateLimitBackendError;

/// Redis-backed GCRA handle. The underlying pool lifecycle remains owned exclusively by
/// `RedisRuntimeDeps`; dropping or shutting down this handle never closes shared infrastructure.
#[derive(Clone)]
pub struct RedisRateLimiter {
    store: Arc<RedisStore>,
    namespace: &'static str,
    quota: RateLimitQuota,
}

/// Move-only evidence that the shared Redis pool executed the real GCRA command set.
///
/// Only [`crate::RedisInfraDeps`] can mint this value. Consuming it yields the concrete limiter,
/// binding provider receipt completion to a successful startup capability check.
pub struct RedisRateLimiterCapability {
    limiter: RedisRateLimiter,
}

impl RedisRateLimiterCapability {
    #[must_use]
    pub fn into_limiter(self) -> RedisRateLimiter {
        self.limiter
    }
}

impl RedisRateLimiter {
    pub(crate) fn new(
        store: Arc<RedisStore>,
        namespace: &'static str,
        quota: RateLimitQuota,
    ) -> Result<Self, InvalidRateLimitNamespace> {
        if namespace.is_empty()
            || namespace.len() > 128
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(InvalidRateLimitNamespace);
        }
        Ok(Self {
            store,
            namespace,
            quota,
        })
    }

    fn redis_key(&self, key: &RateLimitKey) -> String {
        let mut policy_digest = Sha256::new();
        policy_digest.update(self.quota.per_second().to_be_bytes());
        policy_digest.update(self.quota.burst().to_be_bytes());
        let policy_digest = policy_digest.finalize();
        let mut digest = Sha256::new();
        digest.update(key.as_str().as_bytes());
        let digest = digest.finalize();
        format!(
            "{KEY_NAMESPACE}:{}:{policy_digest:x}:{digest:x}",
            self.namespace
        )
    }

    async fn check_redis(
        &self,
        key: &RateLimitKey,
    ) -> Result<(i64, i64), RedisRateLimitBackendError> {
        let redis_key = self.redis_key(key);
        let interval_micros = 1_000_000_f64 / f64::from(self.quota.per_second());
        let mut connection = self
            .store
            .pool()
            .timeout_get(&deadpool_redis::Timeouts {
                wait: Some(POOL_WAIT_TIMEOUT),
                create: None,
                recycle: None,
            })
            .await
            .map_err(|_| RedisRateLimitBackendError)?;
        Script::new(GCRA_SCRIPT)
            .key(redis_key)
            .arg(interval_micros)
            .arg(self.quota.burst())
            .invoke_async(&mut *connection)
            .await
            .map_err(|_| RedisRateLimitBackendError)
    }

    async fn load_script(&self) -> Result<(), RedisRateLimitBackendError> {
        let mut connection = self
            .store
            .pool()
            .timeout_get(&deadpool_redis::Timeouts {
                wait: Some(POOL_WAIT_TIMEOUT),
                create: None,
                recycle: None,
            })
            .await
            .map_err(|_| RedisRateLimitBackendError)?;
        Script::new(GCRA_SCRIPT)
            .load_async(&mut *connection)
            .await
            .map(|_| ())
            .map_err(|_| RedisRateLimitBackendError)
    }

    pub(crate) async fn verify_capability(
        self,
    ) -> Result<RedisRateLimiterCapability, RedisRateLimitCapabilityError> {
        // This fixed opaque subject contains no client data. Running the production script verifies
        // EVAL/SCRIPT plus TIME/GET/SET ACLs; its finite TTL is owned by the same GCRA algorithm.
        let key = RateLimitKey::new("startup-capability-preflight");
        tokio::time::timeout(CHECK_TIMEOUT, async {
            self.load_script().await?;
            self.check_redis(&key).await
        })
        .await
        .map_err(|_| RedisRateLimitCapabilityError)?
        .map_err(|_| RedisRateLimitCapabilityError)?;
        Ok(RedisRateLimiterCapability { limiter: self })
    }
}

impl RateLimiter for RedisRateLimiter {
    async fn check(&self, key: RateLimitKey) -> Result<RateLimitDecision, RateLimitError> {
        let outcome = tokio::time::timeout(CHECK_TIMEOUT, self.check_redis(&key))
            .await
            .map_err(|_| RateLimitError::new(RedisRateLimitBackendError))?
            .map_err(RateLimitError::new)?;
        match outcome {
            (1, _) => Ok(RateLimitDecision::Allowed),
            (0, retry_micros) => Ok(RateLimitDecision::Limited {
                retry_after: Duration::from_micros(u64::try_from(retry_micros).unwrap_or(1).max(1)),
            }),
            _ => Err(RateLimitError::new(RedisRateLimitBackendError)),
        }
    }

    async fn shutdown(&self) -> Result<(), RateLimitError> {
        // reason: RedisRuntimeDeps exclusively owns the shared pool lifecycle; this handle must not
        // close infrastructure also used by locks, CAS, inbox, readiness, or other adapters.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_rejects_empty_and_ambiguous_values() {
        fn validates(namespace: &'static str) -> bool {
            RedisRateLimiter::new(
                Arc::new(RedisStore::new(
                    deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
                        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                        .unwrap_or_else(|_| unreachable!("lazy test pool")),
                )),
                namespace,
                RateLimitQuota::try_new(10, 20).unwrap_or_else(|_| unreachable!("test quota")),
            )
            .is_ok()
        }

        assert!(validates("runtime"));
        assert!(!validates(""));
        assert!(!validates("runtime/shared"));
    }

    #[test]
    fn redis_key_is_namespaced_hashed_and_contains_no_subject() {
        let pool = deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap_or_else(|_| unreachable!("lazy test pool"));
        let store = Arc::new(RedisStore::new(pool));
        let quota = RateLimitQuota::try_new(10, 20).unwrap_or_else(|_| unreachable!("test quota"));
        let runtime = RedisRateLimiter::new(Arc::clone(&store), "runtime", quota)
            .unwrap_or_else(|_| unreachable!("valid namespace"));
        let audit = RedisRateLimiter::new(store, "audit", quota)
            .unwrap_or_else(|_| unreachable!("valid namespace"));
        let key = RateLimitKey::new("203.0.113.9");
        let runtime_key = runtime.redis_key(&key);
        assert!(runtime_key.starts_with("_runtime:listener-rate-limit:v2:runtime:"));
        assert!(!runtime_key.contains("203.0.113.9"));
        assert_ne!(runtime_key, audit.redis_key(&key));

        let changed_quota = RedisRateLimiter::new(
            Arc::new(RedisStore::new(
                deadpool_redis::Config::from_url("redis://127.0.0.1:6379")
                    .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                    .unwrap_or_else(|_| unreachable!("lazy test pool")),
            )),
            "runtime",
            RateLimitQuota::try_new(11, 20).unwrap_or_else(|_| unreachable!("test quota")),
        )
        .unwrap_or_else(|_| unreachable!("valid namespace"));
        assert_ne!(
            runtime_key,
            changed_quota.redis_key(&key),
            "persistent bucket identity must include the quota policy"
        );
    }
}
