//! Real Redis effect fixture for provider integration tests.
//!
//! The handle deliberately exposes no pool, storage key, stored effect bytes, lease, journal, or
//! checkpoint API. It exists only to prove external Saga effect recovery against a real provider.
//!
//! ref: redis-rs/redis-rs redis/src/cmd.rs@main (`cmd` builder and async `query_async`).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use consistency::SagaIdempotencyKey;

use crate::RedisStore;

const REDIS_CMD_EVAL: &str = "EVAL";
const REDIS_CMD_EXISTS: &str = "EXISTS";
const SAGA_EFFECT_NAMESPACE: &str = "_integration:saga_effect";
const STATUS_APPLIED: i64 = 1;
const STATUS_EXACT_DUPLICATE: i64 = 2;
const STATUS_CONFLICT: i64 = 3;

// KEYS[1] = opaque Saga effect key, ARGV[1] = opaque provider effect bytes.
// The write and equality decision are one Redis operation, so concurrent calls cannot both apply.
const LUA_APPLY: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then
  redis.call('SET', KEYS[1], ARGV[1])
  return 1
end
if current == ARGV[1] then
  return 2
end
return 3
"#;

/// Closed result of one atomic effect application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisSagaEffectApplyOutcome {
    /// The effect was written for the first time.
    Applied,
    /// The same effect bytes were already present.
    ExactDuplicate,
    /// Different effect bytes were already present for the same idempotency key.
    Conflict,
}

/// Closed result of a read-only effect probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisSagaEffectProbeOutcome {
    /// No effect is recorded.
    Missing,
    /// An effect is recorded; its bytes remain private to Redis.
    Applied,
}

/// Sanitized provider failure. Endpoint, key, and stored bytes are never retained.
#[derive(Debug, thiserror::Error)]
#[error("redis saga effect fixture operation failed")]
pub struct RedisSagaEffectError;

#[derive(Default)]
struct Counters {
    apply: AtomicU64,
    write: AtomicU64,
    duplicate: AtomicU64,
    conflict: AtomicU64,
    probe: AtomicU64,
}

/// Sanitized counter-only snapshot used by component-test evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedisSagaEffectObservation {
    apply: u64,
    write: u64,
    duplicate: u64,
    conflict: u64,
    probe: u64,
}

impl RedisSagaEffectObservation {
    /// Number of provider apply calls (including failed calls and duplicate/conflict decisions).
    pub const fn apply_count(self) -> u64 {
        self.apply
    }

    /// Number of first writes.
    pub const fn write_count(self) -> u64 {
        self.write
    }

    /// Number of exact duplicate decisions.
    pub const fn duplicate_count(self) -> u64 {
        self.duplicate
    }

    /// Number of conflicting duplicate decisions.
    pub const fn conflict_count(self) -> u64 {
        self.conflict
    }

    /// Number of read-only probe calls, including provider failures.
    pub const fn probe_count(self) -> u64 {
        self.probe
    }
}

/// Minimal provider-backed Saga effect fixture.
#[derive(Clone)]
pub struct RedisSagaEffectFixture {
    store: Arc<RedisStore>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for RedisSagaEffectFixture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RedisSagaEffectFixture(<redacted>)")
    }
}

impl RedisSagaEffectFixture {
    pub(crate) fn new(store: Arc<RedisStore>) -> Self {
        Self {
            store,
            counters: Arc::new(Counters::default()),
        }
    }

    /// Atomically records an opaque external effect or classifies its existing value.
    pub async fn apply(
        &self,
        key: &SagaIdempotencyKey,
        effect: &[u8],
    ) -> Result<RedisSagaEffectApplyOutcome, RedisSagaEffectError> {
        self.counters.apply.fetch_add(1, Ordering::Relaxed);
        let redis_key = storage_key(key);
        let mut conn = self.store.pool().get().await.map_err(provider_error)?;
        let status: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EVAL)
            .arg(LUA_APPLY)
            .arg(1)
            .arg(redis_key)
            .arg(effect)
            .query_async(&mut *conn)
            .await
            .map_err(provider_error)?;

        let outcome = match status {
            STATUS_APPLIED => {
                self.counters.write.fetch_add(1, Ordering::Relaxed);
                RedisSagaEffectApplyOutcome::Applied
            }
            STATUS_EXACT_DUPLICATE => {
                self.counters.duplicate.fetch_add(1, Ordering::Relaxed);
                RedisSagaEffectApplyOutcome::ExactDuplicate
            }
            STATUS_CONFLICT => {
                self.counters.conflict.fetch_add(1, Ordering::Relaxed);
                RedisSagaEffectApplyOutcome::Conflict
            }
            _ => return Err(RedisSagaEffectError),
        };
        Ok(outcome)
    }

    /// Checks only whether an effect exists; stored bytes never cross the fixture API.
    pub async fn probe(
        &self,
        key: &SagaIdempotencyKey,
    ) -> Result<RedisSagaEffectProbeOutcome, RedisSagaEffectError> {
        self.counters.probe.fetch_add(1, Ordering::Relaxed);
        let redis_key = storage_key(key);
        let mut conn = self.store.pool().get().await.map_err(provider_error)?;
        let exists: i64 = deadpool_redis::redis::cmd(REDIS_CMD_EXISTS)
            .arg(redis_key)
            .query_async(&mut *conn)
            .await
            .map_err(provider_error)?;
        let outcome = match exists {
            0 => RedisSagaEffectProbeOutcome::Missing,
            1 => RedisSagaEffectProbeOutcome::Applied,
            _ => return Err(RedisSagaEffectError),
        };
        Ok(outcome)
    }

    /// Returns a counter-only observation suitable for sanitized integration evidence.
    #[must_use]
    pub fn observation(&self) -> RedisSagaEffectObservation {
        RedisSagaEffectObservation {
            apply: self.counters.apply.load(Ordering::Relaxed),
            write: self.counters.write.load(Ordering::Relaxed),
            duplicate: self.counters.duplicate.load(Ordering::Relaxed),
            conflict: self.counters.conflict.load(Ordering::Relaxed),
            probe: self.counters.probe.load(Ordering::Relaxed),
        }
    }
}

fn storage_key(key: &SagaIdempotencyKey) -> String {
    format!("{SAGA_EFFECT_NAMESPACE}:{}", key.to_hex())
}

fn provider_error<E>(error: E) -> RedisSagaEffectError
where
    E: std::error::Error,
{
    tracing::warn!(
        error = %secure::redact_error(&error),
        "redis saga effect fixture operation failed"
    );
    RedisSagaEffectError
}
