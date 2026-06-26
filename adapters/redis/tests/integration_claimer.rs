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

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken, SeenState};
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

/// 铸出一个新的随机 lease token（uuid v4）；消费方在真实协议中每次 claim 前铸出。
fn mint_token() -> LeaseToken {
    LeaseToken::mint()
}

fn make_store(url: &str, ttl: Duration, group: &str) -> Result<RedisStore, FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    let group = ConsumerGroup::parse(group)?;
    Ok(RedisStore::new(pool, ttl, group)?)
}

// ─── 既有基础行为（更新至新签名：try_claim/commit/release 均携带 lease token）────────────────

#[tokio::test]
async fn integration_first_check_is_fresh_then_duplicate() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_first_fresh");

    // 首次 claim：token 写入 redis value；返回 Fresh。
    let token_a = mint_token();
    let first = store.try_claim(&key, &token_a).await?;
    assert_eq!(first, SeenState::Fresh, "first try_claim must be Fresh");

    // 再次 try_claim：SET NX 失败（key 已存在）→ Duplicate，无论传入哪个 token。
    let token_b = mint_token();
    let second = store.try_claim(&key, &token_b).await?;
    assert_eq!(
        second,
        SeenState::Duplicate,
        "second try_claim must be Duplicate"
    );
    Ok(())
}

#[tokio::test]
async fn integration_ttl_expiry_refresh() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(1), "integration-group")?;
    let key = unique_key("integration_ttl_expiry");

    let token_a = mint_token();
    let first = store.try_claim(&key, &token_a).await?;
    assert_eq!(first, SeenState::Fresh, "initial try_claim must be Fresh");

    // TTL=1s → 等 1.1s 后 key 应过期。
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 过期后新 token 可重领：TTL 自然重捞（key 消失 → SET NX 成功 = Fresh）。
    let token_b = mint_token();
    let after_expiry = store.try_claim(&key, &token_b).await?;
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

    let lease_a = mint_token();
    let a = store_a.try_claim(&key, &lease_a).await?;
    assert_eq!(a, SeenState::Fresh, "group-a 首见须 Fresh");

    let lease_b = mint_token();
    let b = store_b.try_claim(&key, &lease_b).await?;
    assert_eq!(
        b,
        SeenState::Fresh,
        "group-b 对同一 key 独立首见须 Fresh（组隔离，非跨组去重）"
    );
    Ok(())
}

// ─── 新增：lease-token CAS 语义（#1213）──────────────────────────────────────────────────

/// claim → extend(same token) = Held；extend(other token) = Lost（CAS 围栏）。
#[tokio::test]
async fn integration_extend_held_then_other_token_lost() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_extend_held");

    let mine = mint_token();
    assert_eq!(
        store.try_claim(&key, &mine).await?,
        SeenState::Fresh,
        "initial claim must be Fresh"
    );

    // 持有者续租 → Held。
    assert_eq!(
        store.extend(&key, &mine).await?,
        LeaseOutcome::Held,
        "owner extend must be Held"
    );

    // 他人 token 续租 → Lost（CAS 不匹配）。
    let other = mint_token();
    assert_eq!(
        store.extend(&key, &other).await?,
        LeaseOutcome::Lost,
        "non-owner extend must be Lost"
    );
    Ok(())
}

/// claim → commit(token) = Held → re-try_claim with new token = Duplicate（done 永久去重）。
#[tokio::test]
async fn integration_commit_held_then_recheck_duplicate() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_commit_held");

    let mine = mint_token();
    assert_eq!(store.try_claim(&key, &mine).await?, SeenState::Fresh);

    // CAS commit → 原子切 done 哨兵（清 TTL，永久去重），返回 Held。
    assert_eq!(
        store.commit(&key, &mine).await?,
        LeaseOutcome::Held,
        "commit with correct token must be Held"
    );

    // done key 对任何新 token 的 SET NX 均失败（key 永久存在）→ Duplicate。
    assert_eq!(
        store.try_claim(&key, &mint_token()).await?,
        SeenState::Duplicate,
        "done key must be Duplicate on re-try_claim"
    );
    Ok(())
}

/// claim → commit(wrong token) = Lost（hard-fence：stale token 不可 commit）。
#[tokio::test]
async fn integration_commit_with_wrong_token_is_lost() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_commit_wrong_token");

    let mine = mint_token();
    assert_eq!(store.try_claim(&key, &mine).await?, SeenState::Fresh);

    // 错误 token commit → GET != ARGV[1] → Lua 返回 0 → Lost（hard-fence）。
    let wrong = mint_token();
    assert_eq!(
        store.commit(&key, &wrong).await?,
        LeaseOutcome::Lost,
        "wrong token commit must be Lost (hard-fence)"
    );
    Ok(())
}

/// claim → release(wrong token) = no-op → key 仍存在 → re-try_claim = Duplicate。
#[tokio::test]
async fn integration_release_wrong_token_is_noop_key_survives() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_release_noop");

    let mine = mint_token();
    assert_eq!(store.try_claim(&key, &mine).await?, SeenState::Fresh);

    // 错误 token release：Lua GET != ARGV[1] → DEL 不执行 → key 仍存在。
    let wrong = mint_token();
    store.release(&key, &wrong).await?;

    // claim 未被误删 → 新 token SET NX 失败 → Duplicate。
    assert_eq!(
        store.try_claim(&key, &mint_token()).await?,
        SeenState::Duplicate,
        "key must survive no-op release with wrong token"
    );
    Ok(())
}

/// #279 review F1：claim → commit(token) → extend(**same** token) = Lost（done 行不可被同 token 再续租）。
///
/// 修前 commit=PERSIST 保留 token value，done key 仍匹配 `GET==token` ⇒ extend 会 `PEXPIRE` 给 done key
/// 重加 TTL → 过期后去重丢失 → 双执行。修后 commit 切 done 哨兵（value≠token）⇒ extend CAS 不命中 → Lost。
#[tokio::test]
async fn integration_commit_then_extend_same_token_is_lost() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_done_extend_fenced");

    let mine = mint_token();
    assert_eq!(store.try_claim(&key, &mine).await?, SeenState::Fresh);
    assert_eq!(store.commit(&key, &mine).await?, LeaseOutcome::Held);

    // done 行：同 token extend 必 Lost（不可给 done key 重加 TTL）。
    assert_eq!(
        store.extend(&key, &mine).await?,
        LeaseOutcome::Lost,
        "extend on a done key with the same token must be Lost (no re-TTL)"
    );
    // done key 仍永久存在 → re-try_claim Duplicate（未被 extend 重加 TTL 后过期）。
    assert_eq!(
        store.try_claim(&key, &mint_token()).await?,
        SeenState::Duplicate,
        "done key must remain Duplicate (not re-TTL'd to expiry)"
    );
    Ok(())
}

/// #279 review F2：claim → commit(token) → release(**same** token) = no-op → re-try_claim = Duplicate
/// （done 去重记录不可被同 token release 删除）。
///
/// 修前 release=`DEL if GET==token`，done key value 仍是 token ⇒ 被同 token 删除 → 去重丢失。
/// 修后 done value=哨兵≠token ⇒ release CAS 不命中 → done 记录存活。
#[tokio::test]
async fn integration_commit_then_release_same_token_is_noop() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_done_release_fenced");

    let mine = mint_token();
    assert_eq!(store.try_claim(&key, &mine).await?, SeenState::Fresh);
    assert_eq!(store.commit(&key, &mine).await?, LeaseOutcome::Held);

    // done 行：同 token release 须 no-op（不删 done 去重记录）。
    store.release(&key, &mine).await?;
    assert_eq!(
        store.try_claim(&key, &mint_token()).await?,
        SeenState::Duplicate,
        "done dedup record must survive release with the committing token"
    );
    Ok(())
}

/// claim → 等 TTL 到期 → 以新 token re-try_claim = Fresh（自然重捞，不依赖显式 release）。
///
/// 验证 done-state 之外的 TTL 重捞路径：crash-after-claim 时 key 自然消亡，
/// 新消费者用新 token 重领（#1213 修 crash-后-key-永久-Duplicate 风险）。
#[tokio::test]
async fn integration_natural_reclaim_after_ttl_expiry() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    // 500ms TTL：比 integration_ttl_expiry_refresh（1s）更短，专测自然重捞。
    let store = make_store(redis.url(), Duration::from_millis(500), "integration-group")?;
    let key = unique_key("integration_natural_reclaim");

    let token_a = mint_token();
    assert_eq!(
        store.try_claim(&key, &token_a).await?,
        SeenState::Fresh,
        "initial claim with token_a must be Fresh"
    );

    // 等 key PX 到期（700ms > 500ms TTL）。
    tokio::time::sleep(Duration::from_millis(700)).await;

    // 新 token 重领：key 已消失 → SET NX 成功 → Fresh（自然重捞）。
    let token_b = mint_token();
    assert_eq!(
        store.try_claim(&key, &token_b).await?,
        SeenState::Fresh,
        "after TTL expiry new token must reclaim as Fresh"
    );
    Ok(())
}

/// TTL 自然到期 → 新持有者重领 → 原持有者 commit 被围栏（parity：postgres adapter 有相同场景）。
///
/// 场景：原持有者 token_a 在 TTL 内未 commit（模拟 crash / 超时），key 自然消亡；
/// 新持有者 token_b 重领后 commit 成功；原持有者 token_a 在重领后仍试图 commit → Lost
/// （Lua CAS：GET key ≠ token_a → 围栏，不误提交旧 worker 的结果）。
#[tokio::test]
async fn integration_ttl_reclaim_original_holder_commit_fenced() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    // 500ms TTL：与 integration_natural_reclaim_after_ttl_expiry 一致，等 700ms 确保过期。
    let store = make_store(redis.url(), Duration::from_millis(500), "integration-group")?;
    let key = unique_key("integration_ttl_reclaim_fenced");

    // 1. 原持有者 token_a 首次 claim。
    let token_a = mint_token();
    assert_eq!(
        store.try_claim(&key, &token_a).await?,
        SeenState::Fresh,
        "original holder try_claim must be Fresh"
    );

    // 2. 等 key PX 到期（700ms > 500ms TTL）——模拟原持有者 crash/超时未 commit。
    tokio::time::sleep(Duration::from_millis(700)).await;

    // 3. 新持有者 token_b 自然重领：key 已消失 → SET NX 成功 → Fresh。
    let token_b = mint_token();
    assert_eq!(
        store.try_claim(&key, &token_b).await?,
        SeenState::Fresh,
        "reclaimer try_claim after TTL expiry must be Fresh"
    );

    // 4. 原持有者 token_a 试图 commit：GET key = token_b ≠ token_a → Lua CAS 失败 → Lost（围栏）。
    assert_eq!(
        store.commit(&key, &token_a).await?,
        LeaseOutcome::Lost,
        "original holder commit after reclaim must be Lost (fenced)"
    );

    // 5. 新持有者 token_b commit：CAS 匹配 → Held（PERSIST，永久化）。
    assert_eq!(
        store.commit(&key, &token_b).await?,
        LeaseOutcome::Held,
        "reclaimer commit must be Held"
    );
    Ok(())
}
