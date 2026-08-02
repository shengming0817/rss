//! 集成测试：幂等 claimer（真实 redis 后端）。
//!
//! 容器经 `testkit::env_or_redis()` self-provision（testcontainers）——无需手工预置；
//! 设 `REDIS_TEST_URL` 则对接长存外部 redis（快速本地迭代，不起容器）。需 docker（容器路径）。
//! 连不上即失败（fail-loud，不 silent skip）。
//!
//! nextest test-group 串行（名称前缀 `integration_`）。

#![cfg(feature = "integration")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use consistency::{
    ConsumerGroup, IdemKey, InboxReceiptContext, InboxStore, LeaseOutcome, LeaseToken, SeenState,
};
use deadpool_redis::{Config, Runtime};
use diport::{
    CasStore, CasStoreKey, CasStoreOutcome, CasStoreRequest, LockAcquireOutcome, LockRenewOutcome,
    LockStore, LockStoreKey, ManagedResource,
};
use redis::{RedisInboxStore, RedisPrivateCa, RedisRuntimeDeps};
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

fn unique_key(label: &str) -> IdemKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    #[allow(clippy::unwrap_used)]
    // reason: 构造的字符串非空，parse 不可能失败；测试 helper，item-level carve-out。
    IdemKey::parse(&format!("{label}:pid{pid}:n{n}")).unwrap()
}

fn unique_lock_key(label: &str) -> LockStoreKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    LockStoreKey::new(format!("{label}:pid{pid}:n{n}"))
}

fn unique_cas_key(label: &str) -> CasStoreKey {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    CasStoreKey::new(format!("{label}:pid{pid}:n{n}"))
}

/// 铸出一个新的随机 lease token（uuid v4）；消费方在真实协议中每次 claim 前铸出。
fn mint_token() -> LeaseToken {
    LeaseToken::mint()
}

// 经 bundle funnel 构造（REDIS-BUNDLE-FUNNEL-01：`RedisStore::new` 已 pub(crate)，唯一公开装配出口是
// `RedisRuntimeDeps::setup`）；派发带 group/ttl 的幂等句柄。
fn make_deps(url: &str) -> Result<RedisRuntimeDeps, FixtureError> {
    let pool = Config::from_url(url).create_pool(Some(Runtime::Tokio1))?;
    Ok(RedisRuntimeDeps::setup(pool))
}

#[allow(clippy::expect_used)]
// reason: 测试 fixture 使用固定合法 receipt metadata，构造失败即测试配置错误。
fn receipt_ctx_for(tenant: &str, group: &str) -> Result<InboxReceiptContext, FixtureError> {
    Ok(InboxReceiptContext::new(
        vocab::TenantId::parse(tenant)?,
        ConsumerGroup::parse(group)?,
        "identity",
        "identity.session-created",
        "identity.session-created",
        "v1",
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        None,
        None,
    )
    .expect("valid inbox receipt context"))
}

struct ScopedRedisInboxStore {
    store: RedisInboxStore,
    ctx: InboxReceiptContext,
}

impl ScopedRedisInboxStore {
    async fn try_claim(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<SeenState, consistency::EngineError> {
        self.store.try_claim(&self.ctx, key, lease).await
    }

    async fn extend(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, consistency::EngineError> {
        self.store.extend(&self.ctx, key, lease).await
    }

    async fn commit(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, consistency::EngineError> {
        self.store.commit(&self.ctx, key, lease).await
    }

    async fn release(
        &self,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<(), consistency::EngineError> {
        self.store.release(&self.ctx, key, lease).await
    }
}

fn make_store(
    url: &str,
    ttl: Duration,
    group: &str,
) -> Result<ScopedRedisInboxStore, FixtureError> {
    make_store_for(url, ttl, "f47ac10b-58cc-4372-a567-0e02b2c3d479", group)
}

fn make_store_for(
    url: &str,
    ttl: Duration,
    tenant: &str,
    group: &str,
) -> Result<ScopedRedisInboxStore, FixtureError> {
    Ok(ScopedRedisInboxStore {
        store: make_deps(url)?.infra().inbox(ttl)?,
        ctx: receipt_ctx_for(tenant, group)?,
    })
}

// ─── 既有基础行为（更新至新签名：try_claim/commit/release 均携带 lease token）────────────────

#[tokio::test]
async fn integration_first_check_is_fresh_then_active_in_progress() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let store = make_store(redis.url(), Duration::from_secs(60), "integration-group")?;
    let key = unique_key("integration_first_fresh");

    // 首次 claim：token 写入 redis value；返回 Fresh。
    let token_a = mint_token();
    let first = store.try_claim(&key, &token_a).await?;
    assert_eq!(first, SeenState::Fresh, "first try_claim must be Fresh");

    // 再次 try_claim：key 是 active claimed → typed InProgress，使 consumer 延迟 Requeue。
    let token_b = mint_token();
    assert_eq!(
        store.try_claim(&key, &token_b).await?,
        SeenState::InProgress,
        "second try_claim must be in progress"
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

    // TTL=1s → 轮询直至新 token 可重领（key 过期 → Fresh）。
    let token_b = mint_token();
    await_try(Duration::from_secs(3), async || {
        let state = store.try_claim(&key, &token_b).await?;
        Ok::<Option<()>, FixtureError>((state == SeenState::Fresh).then_some(()))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn integration_shutdown_closes_pool() -> Result<(), FixtureError> {
    let redis = testkit::env_or_redis().await?;
    let deps = make_deps(redis.url())?;
    for resource in deps.runtime_resources() {
        resource.shutdown().await?;
    }
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
    let store_tenant_b = make_store_for(
        url,
        Duration::from_secs(60),
        "00000000-0000-4000-8000-000000000abc",
        "group-a",
    )?;
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

    let lease_tenant_b = mint_token();
    let tenant_b = store_tenant_b.try_claim(&key, &lease_tenant_b).await?;
    assert_eq!(
        tenant_b,
        SeenState::Fresh,
        "tenant-b 对同一 group/key 独立首见须 Fresh（租户隔离）"
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

    // done key 对任何新 token 的原子 claim 均分类为 Duplicate。
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

/// claim → release(wrong token) = no-op → key 仍存在 → re-try_claim = InProgress。
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

    // claim 未被误删 → 必须返回 InProgress 保留 broker 投递，不得伪装 done 而 ACK。
    assert_eq!(
        store.try_claim(&key, &mint_token()).await?,
        SeenState::InProgress
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

    // 轮询直至 TTL 到期后新 token 自然重捞为 Fresh（500ms TTL）。
    let token_b = mint_token();
    await_try(Duration::from_secs(3), async || {
        let state = store.try_claim(&key, &token_b).await?;
        Ok::<Option<()>, FixtureError>((state == SeenState::Fresh).then_some(()))
    })
    .await?;
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

    // 2–3. 轮询直至 TTL 到期后新持有者 token_b 自然重领为 Fresh。
    let token_b = mint_token();
    await_try(Duration::from_secs(3), async || {
        let state = store.try_claim(&key, &token_b).await?;
        Ok::<Option<()>, FixtureError>((state == SeenState::Fresh).then_some(()))
    })
    .await?;

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
