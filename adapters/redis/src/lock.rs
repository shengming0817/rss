//! Redis distlock provider (`diport::LockStore`).

use core::time::Duration;

use diport::{LockAcquireOutcome, LockRenewOutcome, LockStore, LockStoreError, LockStoreKey};

use crate::bundle::{RedisLockStore, RedisRuntimeDeps};

const RESOURCE: &str = "redis";
const REDIS_CMD_EVAL: &str = "EVAL";
const LOCK_NAMESPACE: &str = "_runtime:distlock";

// KEYS[1] = held key, KEYS[2] = per-lock sequence key.
// ARGV[1] = ttl milliseconds.
// Returns {1, token} when acquired, {0, 0} when already held.
const LUA_ACQUIRE: &str = r#"
local held = redis.call('GET', KEYS[1])
if held then
  return {0, 0}
end
local token = redis.call('INCR', KEYS[2])
redis.call('SET', KEYS[1], token, 'PX', ARGV[1])
return {1, token}
"#;

// KEYS[1] = held key. ARGV[1] = expected token, ARGV[2] = ttl milliseconds.
// Returns 1 when renewed by current holder, 0 when the token is stale/lost.
const LUA_RENEW: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return 1
end
return 0
"#;

// KEYS[1] = held key. ARGV[1] = expected token.
// Release is a stale-token no-op and always returns 0.
const LUA_RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('DEL', KEYS[1])
end
return 0
"#;

fn lock_key(raw: &str) -> String {
    format!("{LOCK_NAMESPACE}:{}:{raw}", raw.len())
}

fn held_key(raw: &str) -> String {
    format!("{}:held", lock_key(raw))
}

fn seq_key(raw: &str) -> String {
    format!("{}:seq", lock_key(raw))
}

fn ttl_millis(ttl: Duration) -> u64 {
    u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)
}

fn lock_error<E>(operation: &'static str, error: E) -> LockStoreError
where
    E: std::error::Error + Send + Sync + 'static,
{
    tracing::warn!(
        resource = RESOURCE,
        operation,
        error = %secure::redact_error(&error),
        "redis distlock operation failed"
    );
    LockStoreError::new(error)
}

impl LockStore for RedisLockStore {
    async fn acquire(
        &self,
        key: LockStoreKey,
        ttl: Duration,
    ) -> Result<LockAcquireOutcome, LockStoreError> {
        RedisRuntimeDeps::validate_ttl(ttl).map_err(|e| lock_error("distlock-ttl", e))?;
        let mut conn = self
            .store()
            .pool()
            .get()
            .await
            .map_err(|e| lock_error("distlock-acquire-pool", e))?;
        let (status, token): (i64, u64) = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_ACQUIRE)
            .arg(2)
            .arg(held_key(key.as_str()))
            .arg(seq_key(key.as_str()))
            .arg(ttl_millis(ttl))
            .query_async(&mut *conn)
            .await
            .map_err(|e| lock_error("distlock-acquire", e))?;
        if status == 1 {
            Ok(LockAcquireOutcome::Acquired {
                token: vocab::Epoch::new(token),
            })
        } else {
            Ok(LockAcquireOutcome::Held)
        }
    }

    async fn renew(
        &self,
        key: LockStoreKey,
        token: vocab::Epoch,
        ttl: Duration,
    ) -> Result<LockRenewOutcome, LockStoreError> {
        RedisRuntimeDeps::validate_ttl(ttl).map_err(|e| lock_error("distlock-ttl", e))?;
        let mut conn = self
            .store()
            .pool()
            .get()
            .await
            .map_err(|e| lock_error("distlock-renew-pool", e))?;
        let renewed: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_RENEW)
            .arg(1)
            .arg(held_key(key.as_str()))
            .arg(token.get())
            .arg(ttl_millis(ttl))
            .query_async(&mut *conn)
            .await
            .map_err(|e| lock_error("distlock-renew", e))?;
        if renewed == 1 {
            Ok(LockRenewOutcome::Renewed { token })
        } else {
            Ok(LockRenewOutcome::Lost)
        }
    }

    async fn release(&self, key: LockStoreKey, token: vocab::Epoch) -> Result<(), LockStoreError> {
        let mut conn = self
            .store()
            .pool()
            .get()
            .await
            .map_err(|e| lock_error("distlock-release-pool", e))?;
        let _: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_RELEASE)
            .arg(1)
            .arg(held_key(key.as_str()))
            .arg(token.get())
            .query_async(&mut *conn)
            .await
            .map_err(|e| lock_error("distlock-release", e))?;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), LockStoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedisRuntimeDeps;
    use deadpool_redis::{Config, Runtime};

    #[allow(clippy::expect_used)]
    fn lazy_pool() -> deadpool_redis::Pool {
        Config::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(Runtime::Tokio1))
            .expect("lazy pool build")
    }

    #[test]
    fn lock_key_uses_length_prefix() {
        assert_ne!(lock_key("a:b:c"), lock_key("a:b"));
        assert_eq!(held_key("abc"), "_runtime:distlock:3:abc:held");
        assert_eq!(seq_key("abc"), "_runtime:distlock:3:abc:seq");
    }

    #[tokio::test]
    async fn acquire_rejects_subms_ttl_before_pool_io() {
        let lock = RedisRuntimeDeps::setup_for_test(lazy_pool())
            .infra()
            .lock_store();
        let result = lock
            .acquire(LockStoreKey::new("subms"), Duration::from_nanos(999_999))
            .await;
        assert!(result.is_err(), "sub-ms ttl must fail before Redis I/O");
    }

    #[tokio::test]
    async fn renew_rejects_zero_ttl_before_pool_io() {
        let lock = RedisRuntimeDeps::setup_for_test(lazy_pool())
            .infra()
            .lock_store();
        let result = lock
            .renew(
                LockStoreKey::new("zero"),
                vocab::Epoch::new(1),
                Duration::ZERO,
            )
            .await;
        assert!(result.is_err(), "zero ttl must fail before Redis I/O");
    }
}
