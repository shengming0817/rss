//! 集成测试：幂等 claimer（真实 redis 后端）。
//!
//! 需本地 redis（`docker run -p 6379:6379 redis`）。
//! 环境变量 `REDIS_TEST_URL`（默认 `redis://127.0.0.1:6379`）。
//! 连不上即失败（fail-loud，不 silent skip）。
//!
//! nextest test-group 串行（名称前缀 `integration_`）。

#![cfg(feature = "integration")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use consistency::{IdemKey, IdempotencyStore, SeenState};
use deadpool_redis::{Config, Runtime};
use diport::ManagedResource;
use redis::RedisStore;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_url() -> String {
    std::env::var("REDIS_TEST_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

fn unique_key(label: &str) -> IdemKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[allow(clippy::unwrap_used)]
    // reason: 构造的字符串非空，parse 不可能失败；测试 helper，item-level carve-out。
    IdemKey::parse(&format!("{label}:pid{pid}:n{n}")).unwrap()
}

fn make_store(ttl: Duration) -> RedisStore {
    let cfg = Config::from_url(test_url());
    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud——连不上 redis 即失败；item-level carve-out。
    let pool = cfg
        .create_pool(Some(Runtime::Tokio1))
        .expect("failed to create deadpool-redis pool (is redis running?)");
    #[allow(clippy::expect_used)]
    // reason: 测试用 TTL 恒 ≥ 1ms，构造期校验必过；item-level carve-out。
    RedisStore::new(pool, ttl).expect("ttl must be ≥ 1ms")
}

#[tokio::test]
async fn integration_first_check_is_fresh_then_duplicate() {
    let store = make_store(Duration::from_secs(60));
    let key = unique_key("integration_first_fresh");

    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud；item-level carve-out。
    let first = store.check(&key).await.expect("first check failed");
    assert_eq!(first, SeenState::Fresh, "first check must be Fresh");

    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud；item-level carve-out。
    let second = store.check(&key).await.expect("second check failed");
    assert_eq!(
        second,
        SeenState::Duplicate,
        "second check must be Duplicate"
    );
}

#[tokio::test]
async fn integration_ttl_expiry_refresh() {
    let store = make_store(Duration::from_secs(1));
    let key = unique_key("integration_ttl_expiry");

    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud；item-level carve-out。
    let first = store.check(&key).await.expect("first check failed");
    assert_eq!(first, SeenState::Fresh, "initial check must be Fresh");

    // TTL=1s → 等 1.1s 后 key 应过期。
    tokio::time::sleep(Duration::from_millis(1100)).await;

    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud；item-level carve-out。
    let after_expiry = store.check(&key).await.expect("post-expiry check failed");
    assert_eq!(
        after_expiry,
        SeenState::Fresh,
        "after TTL expiry key must be Fresh again"
    );
}

#[tokio::test]
async fn integration_shutdown_closes_pool() {
    let store = make_store(Duration::from_secs(60));
    #[allow(clippy::expect_used)]
    // reason: 集成测试 fail-loud；item-level carve-out。
    store.shutdown().await.expect("shutdown must succeed");
}
