//! 集成测试：Redis 基建能力（真实 redis 后端）。
//!
//! 容器经 `testkit::env_or_redis()` self-provision（testcontainers）——无需手工预置；
//! 设 `REDIS_TEST_URL` 则对接长存外部 redis（快速本地迭代，不起容器）。需 docker（容器路径）。
//! 连不上即失败（fail-loud，不 silent skip）。
//!
//! nextest test-group 串行（名称前缀 `integration_`）。

#![allow(clippy::expect_used)]
// reason: canonical live-provider fixtures must fail loudly when typed identities drift.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use deadpool_redis::{Config, Runtime};
use diport::{
    CasStore, CasStoreOutcome, CasStoreRequest, GlobalCasStoreKey, LockAcquireOutcome,
    LockRenewOutcome, LockStore, LockStoreKey,
};
use redis::{RedisPrivateCa, RedisRuntimeDeps};
use sha2::{Digest, Sha256};
use testkit::{FixtureError, await_try};
use tokio::sync::Barrier;

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn integration_explicit_private_ca_accepts_matching_redis_and_rejects_wrong_ca()
-> Result<(), FixtureError> {
    let network = testkit::bridge_network("rss-redis-tls").await?;
    let dns_name = format!("{}-node", network.name());
    let fixture = testkit::redis_tls(testkit::NetworkAttachment {
        network: network.name(),
        dns_name: &dns_name,
    })
    .await?;
    let endpoint =
        secure::RedisEndpoint::parse(fixture.url(), secure::PlaintextEndpointPolicy::Deny)?;
    let good_ca = RedisPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?;
    let deps = RedisRuntimeDeps::connect_with_private_ca(&endpoint, good_ca)?;
    deps.ping().await?;

    let wrong_ca = RedisPrivateCa::from_pem(fixture.wrong_ca_pem().as_bytes().to_vec())?;
    let wrong = RedisRuntimeDeps::connect_with_private_ca(&endpoint, wrong_ca)?;
    assert!(wrong.ping().await.is_err());
    Ok(())
}

fn unique_lock_key(label: &str) -> LockStoreKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    LockStoreKey::new(format!("{label}:pid{}:n{n}", std::process::id()))
}

fn unique_cas_key(label: &str) -> GlobalCasStoreKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let digest: [u8; 32] =
        Sha256::digest(format!("{label}:pid{}:n{n}", std::process::id()).as_bytes()).into();
    GlobalCasStoreKey::for_resource(diport::GlobalCasResource::OutboxBacklog, digest)
}

fn make_deps(url: &str) -> Result<RedisRuntimeDeps, FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    Ok(RedisRuntimeDeps::setup_for_test(pool))
}

#[tokio::test]
async fn integration_distlock_mutex_ttl_and_fencing() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    let lock = deps.infra().lock_store();
    let key = unique_lock_key("integration_distlock");
    let ttl = Duration::from_millis(500);

    let first = lock.acquire(key.clone(), ttl).await?;
    let token_a = match first {
        LockAcquireOutcome::Acquired { token } => token,
        other => {
            return Err(FixtureError::msg(format!(
                "first acquire must win, got {other:?}"
            )));
        }
    };
    assert_eq!(
        lock.acquire(key.clone(), ttl).await?,
        LockAcquireOutcome::Held,
        "second acquire while held must be Held"
    );
    assert_eq!(
        lock.renew(key.clone(), token_a, ttl).await?,
        LockRenewOutcome::Renewed { token: token_a },
        "owner renew must keep same token"
    );

    let token_b = await_try(Duration::from_secs(3), async || {
        match lock.acquire(key.clone(), ttl).await? {
            LockAcquireOutcome::Acquired { token } => Ok(Some(token)),
            LockAcquireOutcome::Held => Ok(None),
            other => Err(FixtureError::msg(format!(
                "unexpected acquire outcome while waiting for TTL takeover: {other:?}"
            ))),
        }
    })
    .await?;
    assert!(
        token_b > token_a,
        "fencing token must be monotonic across TTL expiry"
    );
    assert_eq!(
        lock.renew(key.clone(), token_a, ttl).await?,
        LockRenewOutcome::Lost,
        "stale token must be fenced after takeover"
    );
    lock.release(key.clone(), token_a).await?;
    assert_eq!(
        lock.acquire(key.clone(), ttl).await?,
        LockAcquireOutcome::Held,
        "stale release must be no-op"
    );
    lock.release(key, token_b).await?;
    Ok(())
}

#[tokio::test]
async fn integration_distlock_cross_key_isolation() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    let lock = deps.infra().lock_store();
    let ttl = Duration::from_secs(30);

    let a = lock.acquire(unique_lock_key("lock-a"), ttl).await?;
    let b = lock.acquire(unique_lock_key("lock-b"), ttl).await?;
    assert!(matches!(a, LockAcquireOutcome::Acquired { .. }));
    assert!(matches!(b, LockAcquireOutcome::Acquired { .. }));
    Ok(())
}

#[tokio::test]
async fn integration_distlock_concurrent_same_key_single_winner() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = Arc::new(make_deps(redis.url())?);
    let key = unique_lock_key("integration_distlock_race");
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = Vec::new();

    for _ in 0..8 {
        let deps = Arc::clone(&deps);
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let lock = deps.infra().lock_store();
            barrier.wait().await;
            lock.acquire(key, Duration::from_secs(30)).await
        }));
    }

    let mut acquired = 0;
    let mut held = 0;
    for task in tasks {
        match task.await?? {
            LockAcquireOutcome::Acquired { .. } => acquired += 1,
            LockAcquireOutcome::Held => held += 1,
            other => {
                return Err(FixtureError::msg(format!(
                    "unexpected lock outcome: {other:?}"
                )));
            }
        }
    }
    assert_eq!(
        acquired, 1,
        "same-key concurrent acquire must have one winner"
    );
    assert_eq!(held, 7, "all other contenders must observe Held");
    Ok(())
}

#[tokio::test]
async fn integration_redis_cas_three_states_and_fencing() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    let cas = deps.infra().cas_store();
    let key = unique_cas_key("integration_redis_cas");

    let created = cas
        .compare_and_swap(CasStoreRequest {
            key: key.clone(),
            expected: None,
            new_value: b"v1".to_vec().into(),
            expected_token: None,
        })
        .await?;
    let token1 = match created {
        CasStoreOutcome::Applied { token } => token,
        other => {
            return Err(FixtureError::msg(format!(
                "create must apply, got {other:?}"
            )));
        }
    };

    let updated = cas
        .compare_and_swap(CasStoreRequest {
            key: key.clone(),
            expected: Some(b"v1".to_vec().into()),
            new_value: b"v2".to_vec().into(),
            expected_token: Some(token1),
        })
        .await?;
    let token2 = match updated {
        CasStoreOutcome::Applied { token } => token,
        other => {
            return Err(FixtureError::msg(format!(
                "matching update must apply, got {other:?}"
            )));
        }
    };
    assert!(token2 > token1);

    let conflict = cas
        .compare_and_swap(CasStoreRequest {
            key: key.clone(),
            expected: Some(b"wrong".to_vec().into()),
            new_value: b"v3".to_vec().into(),
            expected_token: Some(token2),
        })
        .await?;
    assert!(
        matches!(&conflict, CasStoreOutcome::Conflict { current: Some(current) } if current.as_bytes() == b"v2"),
        "mismatch must return current value, got {conflict:?}"
    );

    let fenced = cas
        .compare_and_swap(CasStoreRequest {
            key,
            expected: Some(b"v2".to_vec().into()),
            new_value: b"v3".to_vec().into(),
            expected_token: Some(token1),
        })
        .await?;
    assert!(
        matches!(fenced, CasStoreOutcome::Fenced { current_token } if current_token == token2),
        "stale token must be fenced, got {fenced:?}"
    );
    Ok(())
}

#[tokio::test]
async fn integration_redis_cas_concurrent_create_has_single_winner() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = Arc::new(make_deps(redis.url())?);
    let key = unique_cas_key("integration_redis_cas_race");
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = Vec::new();

    for idx in 0_u8..8 {
        let deps = Arc::clone(&deps);
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let cas = deps.infra().cas_store();
            barrier.wait().await;
            cas.compare_and_swap(CasStoreRequest {
                key,
                expected: None,
                new_value: vec![idx].into(),
                expected_token: None,
            })
            .await
        }));
    }

    let mut applied = 0;
    let mut conflicts = 0;
    for task in tasks {
        match task.await?? {
            CasStoreOutcome::Applied { .. } => applied += 1,
            CasStoreOutcome::Conflict { current: Some(_) } => conflicts += 1,
            other => {
                return Err(FixtureError::msg(format!("unexpected outcome: {other:?}")));
            }
        }
    }
    assert_eq!(
        applied, 1,
        "same-key concurrent CAS create must have one winner"
    );
    assert_eq!(
        conflicts, 7,
        "all other contenders must observe current value"
    );
    Ok(())
}

#[tokio::test]
async fn integration_redis_cas_token_overflow_fails_fast() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    let key = unique_cas_key("integration_redis_cas_overflow");
    let redis_key = format!("_runtime:cas:{}:{}", key.as_str().len(), key.as_str());
    let pool = Config::from_url(redis.url()).create_pool(Some(Runtime::Tokio1))?;
    let mut conn = pool.get().await?;
    let _: () = deadpool_redis::redis::cmd("HSET")
        .arg(&redis_key)
        .arg("value")
        .arg(b"v1")
        .arg("token")
        .arg(9_007_199_254_740_991_u64)
        .query_async(&mut *conn)
        .await?;

    let result = deps
        .infra()
        .cas_store()
        .compare_and_swap(CasStoreRequest {
            key,
            expected: Some(b"v1".to_vec().into()),
            new_value: b"v2".to_vec().into(),
            expected_token: Some(vocab::Epoch::new(9_007_199_254_740_991_u64)),
        })
        .await;
    let Err(err) = result else {
        return Err(FixtureError::msg(
            "max Lua-safe token must fail before increment",
        ));
    };
    drop(err);
    Ok(())
}
