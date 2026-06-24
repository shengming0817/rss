//! 集成测试：幂等 claimer（真实 redis 后端）。
//!
//! 容器经 `testkit::env_or_redis()` self-provision（testcontainers）——无需手工预置；
//! 设 `REDIS_TEST_URL` 则对接长存外部 redis（快速本地迭代，不起容器）。需 docker（容器路径）。
//! 连不上即失败（fail-loud，不 silent skip）。
//!
//! nextest test-group 串行（名称前缀 `integration_`）。

#![cfg(feature = "integration")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, SeenState};
use deadpool_redis::{Config, Runtime};
use diport::ManagedResource;
use redis::RedisStore;
use testkit::FixtureError;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_key(label: &str) -> IdemKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[allow(clippy::unwrap_used)]
    // reason: 构造的字符串非空，parse 不可能失败；测试 helper，item-level carve-out。
    IdemKey::parse(&format!("{label}:pid{pid}:n{n}")).unwrap()
}

fn make_store(url: &str, ttl: Duration, group: &str) -> Result<RedisStore, FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    let group = ConsumerGroup::parse(group)?;
    Ok(RedisStore::new(pool, ttl, group)?)
}

#[tokio::test]
async fn integration_first_check_is_fresh_then_duplicate() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_first_fresh");

    let first = store.check(&key).await?;
    assert_eq!(first, SeenState::Fresh, "first check must be Fresh");

    let second = store.check(&key).await?;
    assert_eq!(
        second,
        SeenState::Duplicate,
        "second check must be Duplicate"
    );
    Ok(())
}

#[tokio::test]
async fn integration_ttl_expiry_refresh() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(1), "integration-group")?;
    let key = unique_key("integration_ttl_expiry");

    let first = store.check(&key).await?;
    assert_eq!(first, SeenState::Fresh, "initial check must be Fresh");

    // TTL=1s → 等 1.1s 后 key 应过期。
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let after_expiry = store.check(&key).await?;
    assert_eq!(
        after_expiry,
        SeenState::Fresh,
        "after TTL expiry key must be Fresh again"
    );
    Ok(())
}

#[tokio::test]
async fn integration_shutdown_closes_pool() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    store.shutdown().await?;
    Ok(())
}

// review #216 F5（跨组去重隔离的真实后端回归）：两个不同 ConsumerGroup 的 store 对**同一** key
// 各自首见 Fresh——证明组维度纳入 claim key 后跨组不再互相去重（修前 key 丢 group ⇒ 第二组误判 Duplicate）。
#[tokio::test]
async fn integration_distinct_groups_do_not_dedup_same_key() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let url = redis.url();
    let store_a = make_store(url, Duration::from_secs(60), "group-a")?;
    let store_b = make_store(url, Duration::from_secs(60), "group-b")?;
    let key = unique_key("integration_cross_group");

    let a = store_a.check(&key).await?;
    assert_eq!(a, SeenState::Fresh, "group-a 首见须 Fresh");

    let b = store_b.check(&key).await?;
    assert_eq!(
        b,
        SeenState::Fresh,
        "group-b 对同一 key 独立首见须 Fresh（组隔离，非跨组去重）"
    );
    Ok(())
}
