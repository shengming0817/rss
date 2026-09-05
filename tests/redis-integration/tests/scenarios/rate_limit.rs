//! Real-Redis conformance for the cluster-global listener rate limiter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use deadpool_redis::{Config, Pool, Runtime};
use diport::{RateLimitDecision, RateLimitKey, RateLimitQuota, RateLimiter};
use redis::{RedisRateLimiter, RedisRuntimeDeps};
use sha2::{Digest as _, Sha256};
use testkit::FixtureError;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique(label: &str) -> String {
    format!(
        "{label}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn setup(url: &str) -> Result<(Pool, RedisRuntimeDeps), FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    Ok((pool.clone(), RedisRuntimeDeps::setup_for_test(pool)))
}

async fn limiter(
    deps: &RedisRuntimeDeps,
    namespace: &'static str,
    per_second: u32,
    burst: u32,
) -> RedisRateLimiter {
    let quota = RateLimitQuota::try_new(per_second, burst)
        .unwrap_or_else(|_| unreachable!("fixed integration quota is valid"));
    deps.infra()
        .rate_limiter_capability(namespace, quota)
        .await
        .unwrap_or_else(|_| unreachable!("fixed integration namespace is valid"))
        .into_limiter()
}

fn is_allowed(decision: &RateLimitDecision) -> bool {
    matches!(decision, RateLimitDecision::Allowed)
}

fn expected_redis_key(namespace: &str, quota: RateLimitQuota, key: &RateLimitKey) -> String {
    let mut policy_digest = Sha256::new();
    policy_digest.update(quota.per_second().to_be_bytes());
    policy_digest.update(quota.burst().to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(key.as_str().as_bytes());
    format!(
        "_runtime:listener-rate-limit:v2:{namespace}:{:x}:{:x}",
        policy_digest.finalize(),
        digest.finalize()
    )
}

pub(super) async fn two_handles_share_atomic_buckets_and_expire(
    url: &str,
) -> Result<(), FixtureError> {
    let (pool, deps) = setup(url)?;
    let left = limiter(&deps, "integration_rate_limit", 1, 3).await;
    let right = limiter(&deps, "integration_rate_limit", 1, 3).await;
    let shared = RateLimitKey::new(unique("shared"));
    let shared_redis_key = expected_redis_key(
        "integration_rate_limit",
        RateLimitQuota::try_new(1, 3)
            .unwrap_or_else(|_| unreachable!("fixed integration quota is valid")),
        &shared,
    );

    assert_shared_burst(&left, &right, &shared).await?;

    let isolated = RateLimitKey::new(unique("isolated"));
    assert!(is_allowed(&right.check(isolated).await?));

    let mut connection = pool.get().await?;
    let ttl_millis: i64 = deadpool_redis::redis::cmd("PTTL")
        .arg(&shared_redis_key)
        .query_async(&mut *connection)
        .await?;
    assert!(ttl_millis > 0, "bucket must own a finite recovery TTL");

    testkit::await_try(Duration::from_secs(3), async || {
        let decision = right.check(shared.clone()).await?;
        Ok::<_, FixtureError>(is_allowed(&decision).then_some(()))
    })
    .await?;
    Ok(())
}

pub(super) async fn policy_changes_have_independent_bucket_identity(
    url: &str,
) -> Result<(), FixtureError> {
    let (pool, deps) = setup(url)?;
    let strict = limiter(&deps, "integration_rate_policy", 1, 1).await;
    let fast = limiter(&deps, "integration_rate_policy", 10, 2).await;
    let key = RateLimitKey::new(unique("policy"));

    assert_policy_bursts(&strict, &fast, &key).await?;

    let strict_quota = RateLimitQuota::try_new(1, 1)
        .unwrap_or_else(|_| unreachable!("fixed integration quota is valid"));
    let fast_quota = RateLimitQuota::try_new(10, 2)
        .unwrap_or_else(|_| unreachable!("fixed integration quota is valid"));
    let strict_key = expected_redis_key("integration_rate_policy", strict_quota, &key);
    let fast_key = expected_redis_key("integration_rate_policy", fast_quota, &key);
    assert_ne!(strict_key, fast_key);
    let mut connection = pool.get().await?;
    let exists: (bool, bool) = deadpool_redis::redis::cmd("EXISTS")
        .arg(&strict_key)
        .arg(&fast_key)
        .query_async(&mut *connection)
        .await
        .map(|count: i64| (count >= 1, count == 2))?;
    assert_eq!(exists, (true, true));

    testkit::await_try(Duration::from_secs(3), async || {
        let decision = fast.check(key.clone()).await?;
        Ok::<_, FixtureError>(is_allowed(&decision).then_some(()))
    })
    .await?;
    Ok(())
}

pub(super) async fn concurrent_burst_is_exactly_atomic(url: &str) -> Result<(), FixtureError> {
    let (_, deps) = setup(url)?;
    let limiter = Arc::new(limiter(&deps, "integration_rate_atomic", 1, 1).await);
    let key = RateLimitKey::new(unique("atomic"));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let limiter = Arc::clone(&limiter);
        let key = key.clone();
        tasks.push(tokio::spawn(async move { limiter.check(key).await }));
    }
    let mut allowed = 0;
    for task in tasks {
        if is_allowed(&task.await??) {
            allowed += 1;
        }
    }
    assert_eq!(allowed, 1, "Lua GCRA must serialize concurrent replicas");
    Ok(())
}

#[allow(clippy::disallowed_methods)]
// reason: this T2 wall-clock assertion verifies the real pool wait is bounded; no domain time is modeled.
pub(super) async fn saturated_pool_fails_within_limiter_budget(
    url: &str,
) -> Result<(), FixtureError> {
    let mut config = Config::from_url(url);
    config.pool = Some(deadpool_redis::PoolConfig::new(1));
    let pool = config.create_pool(Some(Runtime::Tokio1))?;
    let deps = RedisRuntimeDeps::setup_for_test(pool.clone());
    let _held = pool.get().await?;

    let started = std::time::Instant::now();
    let result = deps
        .infra()
        .rate_limiter_capability(
            "integration_rate_saturated",
            RateLimitQuota::try_new(1, 1)
                .unwrap_or_else(|_| unreachable!("fixed integration quota is valid")),
        )
        .await;
    let error = match result {
        Ok(_) => {
            return Err(FixtureError::msg(
                "saturated pool minted a startup capability",
            ));
        }
        Err(error) => error,
    };
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "pool saturation must not consume the request budget"
    );
    assert_eq!(
        error.to_string(),
        "redis rate-limit capability verification failed"
    );
    Ok(())
}

pub(super) async fn acl_without_time_rejects_startup_capability(
    url: &str,
) -> Result<(), FixtureError> {
    let (admin_pool, admin_deps) = setup(url)?;
    let user = unique("rate-limit-acl");
    let password = unique("rate-limit-secret");
    let mut admin = admin_pool.get().await?;
    let _: () = deadpool_redis::redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&user)
        .arg("on")
        .arg(format!(">{password}"))
        .arg("~*")
        .arg("+@all")
        .arg("-time")
        .query_async(&mut *admin)
        .await?;

    let authenticated_url = url.replacen("redis://", &format!("redis://{user}:{password}@"), 1);
    let (_, restricted) = setup(&authenticated_url)?;
    let quota = RateLimitQuota::try_new(1, 1)
        .unwrap_or_else(|_| unreachable!("fixed integration quota is valid"));
    let result = restricted
        .infra()
        .rate_limiter_capability("integration_rate_acl", quota)
        .await;
    let error = match result {
        Ok(_) => {
            return Err(FixtureError::msg(
                "missing TIME ACL minted a startup capability",
            ));
        }
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "redis rate-limit capability verification failed"
    );

    let _: () = deadpool_redis::redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&user)
        .query_async(&mut *admin)
        .await?;

    // Preload the exact script as an administrator, then prove a user lacking SCRIPT LOAD cannot
    // mint a capability merely because EVALSHA would hit the shared cache.
    let _preloaded = limiter(&admin_deps, "integration_rate_script_acl", 1, 1).await;
    let script_user = unique("rate-limit-script-acl");
    let script_password = unique("rate-limit-script-secret");
    let _: () = deadpool_redis::redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&script_user)
        .arg("on")
        .arg(format!(">{script_password}"))
        .arg("~*")
        .arg("+@all")
        .arg("-script")
        .query_async(&mut *admin)
        .await?;
    let script_url = url.replacen(
        "redis://",
        &format!("redis://{script_user}:{script_password}@"),
        1,
    );
    let (_, script_restricted) = setup(&script_url)?;
    let script_result = script_restricted
        .infra()
        .rate_limiter_capability("integration_rate_script_acl", quota)
        .await;
    assert!(
        script_result.is_err(),
        "cached script must not bypass SCRIPT LOAD capability verification"
    );
    let _: () = deadpool_redis::redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&script_user)
        .query_async(&mut *admin)
        .await?;
    Ok(())
}

async fn assert_shared_burst(
    left: &RedisRateLimiter,
    right: &RedisRateLimiter,
    shared: &RateLimitKey,
) -> Result<(), FixtureError> {
    assert!(is_allowed(&left.check(shared.clone()).await?));
    assert!(is_allowed(&right.check(shared.clone()).await?));
    assert!(is_allowed(&left.check(shared.clone()).await?));
    let limited = right.check(shared.clone()).await?;
    assert!(matches!(
        limited,
        RateLimitDecision::Limited { retry_after }
            if retry_after > Duration::ZERO && retry_after <= Duration::from_secs(1)
    ));

    Ok(())
}

async fn assert_policy_bursts(
    strict: &RedisRateLimiter,
    fast: &RedisRateLimiter,
    key: &RateLimitKey,
) -> Result<(), FixtureError> {
    assert!(is_allowed(&strict.check(key.clone()).await?));
    assert!(matches!(
        strict.check(key.clone()).await?,
        RateLimitDecision::Limited { .. }
    ));
    assert!(is_allowed(&fast.check(key.clone()).await?));
    assert!(is_allowed(&fast.check(key.clone()).await?));
    assert!(matches!(
        fast.check(key.clone()).await?,
        RateLimitDecision::Limited { retry_after }
            if retry_after > Duration::ZERO && retry_after <= Duration::from_millis(100)
    ));

    Ok(())
}
