//! postgres adapter 集成测试（crate-internal；需真实 postgres，`integration` feature 门控；#1116 review F2/F5/F6）。
//!
//! crate-internal（非 `tests/`）以行使 `pub(crate)` 的 [`crate::PgStore::run_in_transaction`]（裸事务非公开
//! API，review F2）。本地 docker postgres：设 libpq 标准 env（`PGHOST` / `PGPORT` / `PGDATABASE` / `PGUSER`
//! / `PGPASSWORD`，`PGDATABASE` 须含 `test`），跑 `cargo nextest run -p postgres --features integration`。
//!
//! **fail-closed（review F5）**：缺任一 env / `PGDATABASE` 不含 `test` → 测试**失败**（非静默跳过），杜绝
//! 「未配置 DB 却显示 passed」的假绿，并防破坏性 DDL 打到非测试库（review F6）。

use std::time::Duration;

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, SeenState};
use diport::ManagedResource;
use futures::future::BoxFuture;

use crate::{PgConfig, PgPassword, PgSslMode, PgStore};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 由 libpq 标准 env 构造配置。fail-closed：缺 env / 非测试库名 → `Err`（测试失败，非跳过）。
fn config_from_env() -> Result<PgConfig, String> {
    let var = |k: &str| {
        std::env::var(k).map_err(|_| {
            format!("integration 测试需设置 {k}（libpq env）；见 migrations/README.md")
        })
    };
    let host = var("PGHOST")?;
    let port: u16 = var("PGPORT")?
        .parse()
        .map_err(|_| "PGPORT 不是合法 u16".to_string())?;
    let database = var("PGDATABASE")?;
    // review F6：集成测试执行破坏性 DDL（CREATE/DROP TABLE），拒绝打到非测试库。
    if !database.contains("test") {
        return Err(format!(
            "PGDATABASE='{database}' 不含 'test'——集成测试会执行破坏性 DDL，拒绝打到非测试库"
        ));
    }
    let username = var("PGUSER")?;
    let password = var("PGPASSWORD")?;
    Ok(
        PgConfig::new(host, port, database, username, PgPassword::new(password))
            // 本地无 TLS docker postgres：显式降级（默认 VerifyFull 对未启 TLS 的 docker pg 连不上）。
            .with_ssl_mode(PgSslMode::Prefer)
            .with_acquire_timeout(Duration::from_secs(5)),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_connects_and_shuts_down() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    assert_eq!(store.name(), "postgres");
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrator_applies_and_is_idempotent() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    store.run_migrations().await?; // 应用 0001 占位
    store.run_migrations().await?; // 再跑：checksum 命中 → 幂等 no-op
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_commit_persists_and_rollback_discards() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;

    // setup：干净表 + 1 行，commit（committed 数据对所有池连接可见）。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("DROP TABLE IF EXISTS rss_tx_probe")
                    .execute(&mut *c)
                    .await?;
                sqlx::query("CREATE TABLE rss_tx_probe (id int)")
                    .execute(&mut *c)
                    .await?;
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (1)")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 1);

    // rollback 路径：插入后强制 Err → run_in_transaction 回滚。
    let rolled_back = store
        .run_in_transaction::<_, (), sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (2)")
                    .execute(&mut *c)
                    .await?;
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled_back.is_err());
    assert_eq!(probe_count(&store).await?, 1); // 回滚 → 行数不变

    // commit 路径：插入后 Ok → 持久化。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (3)")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 2);

    // cleanup
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                sqlx::query("DROP TABLE rss_tx_probe")
                    .execute(&mut *c)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    store.shutdown().await?;
    Ok(())
}

/// inbox_dedup claim-or-skip + 多组隔离集成验证（#1118）。
///
/// 唯一 event_id 法——每次运行生成新 UUID key，跨轮次无需清理旧数据，且可重复安全运行。
/// 验证三个语义断言：
/// 1. 同组同 key 首见 → Fresh；
/// 2. 同组同 key 再见 → Duplicate（幂等短路）；
/// 3. 不同组同 key → Fresh（去重按组隔离，两组独立 PK）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path —— uuid v4 生成不失败、测试专用固定组名非空、IdemKey 非空 parse 不失败；
// 函数级 item-level carve-out（error-handling.md §Carve-out）。
async fn inbox_dedup_claims_then_duplicates_and_group_drift() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    store.run_migrations().await?;

    // 唯一 event_id：每次生成新 UUID，跨轮次不冲突，无需 DELETE 清理。
    let evt = format!("test-evt-{}", uuid::Uuid::new_v4());

    let s_a = store.inbox(ConsumerGroup::parse("test-grp-a").unwrap());
    let key = IdemKey::parse(&evt).unwrap();

    // 断言 1：同组同 key 首见 → Fresh。
    assert_eq!(
        s_a.check(&key).await?,
        SeenState::Fresh,
        "首次 claim 应返回 Fresh"
    );

    // 断言 2：同组同 key 再见 → Duplicate（PK 冲突，幂等短路）。
    assert_eq!(
        s_a.check(&key).await?,
        SeenState::Duplicate,
        "同 key 再见应返回 Duplicate"
    );

    // 断言 3：不同消费者组同 key → Fresh（PK = (event_id, consumer_group)，组间去重独立）。
    let s_b = store.inbox(ConsumerGroup::parse("test-grp-b").unwrap());
    assert_eq!(
        s_b.check(&key).await?,
        SeenState::Fresh,
        "不同组同 key 应返回 Fresh（group drift 隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

/// 在独立事务内读 `rss_tx_probe` 行数（committed 数据跨池连接可见）。
async fn probe_count(store: &PgStore) -> Result<i64, sqlx::Error> {
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            Box::pin(async move {
                let row: (i64,) = sqlx::query_as("SELECT count(*) FROM rss_tx_probe")
                    .fetch_one(&mut *c)
                    .await?;
                Ok(row.0)
            }) as BoxFuture<'_, Result<i64, sqlx::Error>>
        })
        .await
}

// ── outbox integration tests ───────────────────────────────────────────────────
//
// T1: OUTBOX-ATOMIC-IDEM-01 回滚→无 entry（L1 原子性，INVARIANT）
// T2: 提交→恰 1 行 pending（T1 anti-vacuity 配对）
// T3: relay→published（Ack）
// T4: relay→pending+retry_after（Requeue）
// T5: relay→dlx（Reject）
// T6: 崩溃重投（stale publishing → poll_pending 重捞 → relay → published；幂等 Ack）+ 跨域隔离负向
// T7: 并发 CAS fencing（两连接各 relay → 至多 publish 一次）
// T8: sweep 删超保留期 published、保留 dlx + 保留期内 published/pending anti-vacuity
// T9: lease_token CAS fencing（stale token 不能结算被新租约接管的行）

use std::sync::{Arc, Mutex};

use consistency::{Disposition, Entry, IdemKey, OutboxRelay, OutboxSource, OutboxSweeper, Topic};
use diport::{DynPublisher, PublishRequest, Publisher, PublisherError};

use crate::outbox::{
    MAX_PUBLISH_ATTEMPTS, OutboxEnvelope, OutboxMetadata, PgOutbox, SettleOutcome, append_outbox,
};

/// setup 阶段：应用 migration（含 outbox 表），清空 outbox（防测试间污染）。
async fn setup_outbox(store: &PgStore) -> Result<(), Box<dyn std::error::Error>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM outbox")
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// 产生唯一 event_id（防并发测试冲突）。
#[allow(clippy::disallowed_methods)]
// reason: SystemTime::now() 仅用于测试隔离产生唯一 id，非时钟注入场景；item-level carve-out（error-handling.md §Carve-out）。
fn unique_event_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}-{nanos}-{}", uuid_like())
}

/// 简单递增计数器生成伪唯一后缀（不引 uuid crate）。
fn uuid_like() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    format!("{:x}", CTR.fetch_add(1, Ordering::Relaxed))
}

/// 构造测试用 Entry + Envelope。
fn make_entry(event_id: &str) -> Entry {
    #[allow(clippy::unwrap_used)]
    // reason: 测试 happy-path 构造已知合法值，item-level carve-out（error-handling.md §Carve-out）。
    Entry::new(
        Topic::parse("test.event").unwrap(),
        IdemKey::parse(event_id).unwrap(),
        b"payload".to_vec(),
    )
}

fn make_envelope(event_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        "test-domain".to_string(),
        "contract-1".to_string(),
        OutboxMetadata::new().with_subject_id(event_id),
    )
}

/// 构造测试 envelope（domain + contract_id，空 metadata）——去重 `OutboxEnvelope::new` 内联重复。
fn make_test_env(domain: &str, contract_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(),
    )
}

/// Fake publisher：记录调用次数，返回可控 Result。
struct RecordingPublisher {
    result: fn() -> Result<(), PublisherError>,
    calls: Arc<Mutex<u32>>,
}

impl RecordingPublisher {
    fn always_ok() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || Ok(()),
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    fn always_err() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::new(std::io::Error::other(
                        "fake publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }
}

impl Publisher for RecordingPublisher {
    async fn publish(&self, _request: PublishRequest) -> Result<(), PublisherError> {
        #[allow(clippy::unwrap_used)]
        // reason: 测试内部 Mutex 不存在 poisoning 来源（无 panic 在 lock 持有期间），item-level carve-out。
        {
            *self.calls.lock().unwrap() += 1;
        }
        (self.result)()
    }

    async fn shutdown(&self) -> Result<(), PublisherError> {
        Ok(())
    }
}

fn make_pg_outbox(store: &PgStore, pub_result_fn: fn() -> Result<(), PublisherError>) -> PgOutbox {
    // 临时构造 RecordingPublisher（calls 丢弃；调用方只需验证 DB 状态时用这个）
    let pub_ = RecordingPublisher {
        result: pub_result_fn,
        calls: Arc::new(Mutex::new(0)),
    };
    PgOutbox::new(store, DynPublisher::new_box(pub_))
}

// ── T1: INVARIANT OUTBOX-ATOMIC-IDEM-01：回滚→无 entry ──────────────────────

/// INVARIANT: OUTBOX-ATOMIC-IDEM-01
/// L1 原子性：append_outbox 在事务内，业务返回 Err → 回滚 → outbox 无该行。
#[tokio::test(flavor = "multi_thread")]
async fn t1_rollback_leaves_no_outbox_entry() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t1");
    let entry = make_entry(&event_id);
    let env = make_envelope(&event_id);

    // 事务内 append_outbox，然后返回 Err → 回滚。
    let result = store
        .run_in_transaction::<_, (), sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new().with_subject_id(event_id.as_str()),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                // 强制回滚。
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(result.is_err(), "should have rolled back");

    // 验证 outbox 无该行。
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        count.0, 0,
        "rollback must leave no outbox entry (OUTBOX-ATOMIC-IDEM-01)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T2: 提交→恰 1 行 pending（T1 anti-vacuity 配对）─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t2_commit_creates_exactly_one_pending_row() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t2");
    let entry = make_entry(&event_id);
    let env = make_envelope(&event_id);

    // 事务内 append_outbox + Ok → commit。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new().with_subject_id(event_id.as_str()),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 验证恰 1 行，status=pending，字段正确。
    let row: (i64, String, String, String) = sqlx::query_as(
        "SELECT count(*), status, domain, topic FROM outbox WHERE event_id = $1 GROUP BY status, domain, topic",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    assert_eq!(row.0, 1, "should have exactly 1 row");
    assert_eq!(row.1, "pending", "status should be pending");
    assert_eq!(row.2, "test-domain", "domain should match");
    assert_eq!(row.3, "test.event", "topic should match");

    store.shutdown().await?;
    Ok(())
}

// ── T3: relay→published（Ack）────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t3_relay_ok_publishes_and_acks() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t3");
    let entry = make_entry(&event_id);
    let env = make_envelope(&event_id);

    // seed: 1 行 pending。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, calls) = RecordingPublisher::always_ok();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_));

    let disposition = outbox.relay(&entry).await?;
    assert_eq!(disposition, Disposition::Ack, "should Ack on publish Ok");

    // DB 状态 published。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    // publisher 确实被调用了一次。
    #[allow(clippy::unwrap_used)]
    let call_count = *calls.lock().unwrap();
    assert_eq!(call_count, 1, "publisher should be called once");

    store.shutdown().await?;
    Ok(())
}

// ── T4: relay→pending+retry_after（Requeue）──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t4_relay_err_requeues_with_retry_after() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t4");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，retry_count=0。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "test-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, _) = RecordingPublisher::always_err();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_));

    let disposition = outbox.relay(&entry).await?;
    assert_eq!(
        disposition,
        Disposition::Requeue,
        "should Requeue on publish Err"
    );

    // DB 状态回 pending，retry_count=1，retry_after 非空且在将来，lease_token NULL。
    let row: (String, i32, bool, bool) = sqlx::query_as(
        r#"SELECT status, retry_count,
                  retry_after IS NOT NULL AS has_retry_after,
                  lease_token IS NULL     AS lease_cleared
           FROM outbox WHERE event_id = $1"#,
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;

    assert_eq!(row.0, "pending", "status should be pending after requeue");
    assert_eq!(row.1, 1, "retry_count should be incremented");
    assert!(row.2, "retry_after should be set");
    assert!(row.3, "lease_token should be cleared");

    // retry_after 在当前时间之后（退避，不应立即重试）。
    let future_check: (bool,) =
        sqlx::query_as("SELECT retry_after > now() FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(future_check.0, "retry_after should be in the future");

    // 退避负向：retry_after 在将来 → poll_pending 本轮不应重新捞回该行（L2 退避可靠性闭环）。
    let re = outbox.poll_pending("test-domain", 10).await?;
    assert!(
        !re.iter().any(|e| e.idem_key().as_str() == event_id),
        "requeued entry must not be re-polled within backoff window"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T5: relay→dlx（Reject）──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t5_relay_err_at_budget_exhaustion_dlxes() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t5");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，手动置 retry_count=MAX-1。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "test-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 直接 UPDATE retry_count 到 MAX-1（seed entry + sqlx query）。
    sqlx::query("UPDATE outbox SET retry_count = $1 WHERE event_id = $2")
        .bind(MAX_PUBLISH_ATTEMPTS - 1)
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    let (pub_, _) = RecordingPublisher::always_err();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_));

    let disposition = outbox.relay(&entry).await?;
    assert_eq!(
        disposition,
        Disposition::Reject,
        "should Reject when budget exhausted"
    );

    // DB 状态 dlx。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        status.0, "dlx",
        "status should be dlx after budget exhaustion"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T6: 崩溃重投（stale publishing → poll_pending 重捞 → relay → published）──

#[tokio::test(flavor = "multi_thread")]
async fn t6_crash_recovery_stale_lease_redelivered() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t6");
    let entry = make_entry(&event_id);

    // seed: 1 行，手动置为 status='publishing' 且 updated_at 早于 LEASE_TTL+10s 前（模拟崩溃残留）。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = make_test_env("crash-domain", "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 模拟崩溃：把行置 publishing + updated_at 很久之前。
    let lease_ttl = crate::outbox::LEASE_TTL_SECONDS;
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&event_id)
    .execute(&store.pool)
    .await?;

    // 跨域隔离负向：另插一条 other-domain 的 stale publishing 行；poll("crash-domain") 不应返回它
    //（令下方 entries.len()==1 断言具 anti-vacuity 意义）。
    let other_id = unique_event_id("t6-other");
    let other_entry = make_entry(&other_id);
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = other_entry.clone();
            Box::pin(async move {
                append_outbox(c, &entry, &make_test_env("other-domain", "c")).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(lease_ttl + 10)
    .bind(&other_id)
    .execute(&store.pool)
    .await?;

    // poll_pending 能捞回 stale publishing 行。
    let (pub_, calls) = RecordingPublisher::always_ok();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_));

    let entries = outbox.poll_pending("crash-domain", 10).await?;
    assert_eq!(
        entries.len(),
        1,
        "stale publishing row should be returned by poll_pending"
    );
    assert_eq!(entries[0].idem_key().as_str(), event_id);

    // relay → published。
    let disposition = outbox.relay(&entries[0]).await?;
    assert_eq!(disposition, Disposition::Ack);

    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    // 再 relay 一次（已 published）→ acquire 0 行 → 幂等 Ack，publisher 不再被调用（calls = 1）。
    let outbox2 = make_pg_outbox(&store, || Ok(()));
    let disposition2 = outbox2.relay(&entries[0]).await?;
    assert_eq!(
        disposition2,
        Disposition::Ack,
        "second relay of published entry should be Ack"
    );

    #[allow(clippy::unwrap_used)]
    let call_count = *calls.lock().unwrap();
    assert_eq!(
        call_count, 1,
        "publisher should only be called once (at-least-once idempotent)"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T7: 并发 CAS fencing（两连接各 relay → 至多 publish 一次）────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t7_concurrent_relay_publishes_at_most_once() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t7");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = make_test_env("t7-domain", "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 两个独立 PgOutbox 各自 relay 同一行——共享 calls 计数器。
    let calls = Arc::new(Mutex::new(0u32));
    let calls_clone = Arc::clone(&calls);

    let pub1 = RecordingPublisher {
        result: || Ok(()),
        calls: Arc::clone(&calls),
    };
    let pub2 = RecordingPublisher {
        result: || Ok(()),
        calls: calls_clone,
    };

    let outbox1 = PgOutbox::new(&store, DynPublisher::new_box(pub1));
    let outbox2 = PgOutbox::new(&store, DynPublisher::new_box(pub2));

    // 两个 relay 并发执行：只有一个能 CAS acquire 成功，另一个返回 Ack（0 行更新）。
    let entry_clone = entry.clone();
    let (d1, d2) = tokio::join!(outbox1.relay(&entry), outbox2.relay(&entry_clone));

    assert!(d1.is_ok() && d2.is_ok(), "both relay should return Ok");
    let d1 = d1?;
    let d2 = d2?;

    // 两个都返回 Ack（一个真正 publish，另一个 CAS 0 行 → 幂等 Ack）。
    assert_eq!(d1, Disposition::Ack);
    assert_eq!(d2, Disposition::Ack);

    // publisher 至多调用一次。
    #[allow(clippy::unwrap_used)]
    let total_calls = *calls.lock().unwrap();
    assert_eq!(
        total_calls, 1,
        "publisher should be called at most once across concurrent relays"
    );

    // 行终态 published。
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "published");

    store.shutdown().await?;
    Ok(())
}

// ── sweep 基础验证 ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn t8_sweep_removes_old_published_keeps_dlx() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_pub = unique_event_id("t8-pub");
    let event_dlx = unique_event_id("t8-dlx");
    let entry_pub = make_entry(&event_pub);
    let entry_dlx = make_entry(&event_dlx);

    // seed 2 行。
    for (entry, env_id) in [(&entry_pub, &event_pub), (&entry_dlx, &event_dlx)] {
        let entry_c = (*entry).clone();
        let env_id_c = env_id.to_string();
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                Box::pin(async move {
                    let env = make_test_env("sweep-domain", "c");
                    append_outbox(c, &entry_c, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        // 置旧 created_at + 目标 status。
        let new_status = if env_id == &event_pub {
            "published"
        } else {
            "dlx"
        };
        sqlx::query(
            "UPDATE outbox SET status=$1, created_at = now() - make_interval(secs=>7200) WHERE event_id=$2",
        )
        .bind(new_status)
        .bind(env_id_c)
        .execute(&store.pool)
        .await?;
    }

    // anti-vacuity：保留期内的 published（created_at=now）与 pending 行不应被 sweep 删。
    let event_fresh = unique_event_id("t8-fresh");
    let event_pending = unique_event_id("t8-pending");
    for (eid, new_status) in [(&event_fresh, "published"), (&event_pending, "pending")] {
        let entry_c = make_entry(eid);
        let eid_c = eid.to_string();
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                Box::pin(async move {
                    append_outbox(c, &entry_c, &make_test_env("sweep-domain", "c")).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        sqlx::query("UPDATE outbox SET status=$1 WHERE event_id=$2")
            .bind(new_status)
            .bind(eid_c)
            .execute(&store.pool)
            .await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    // 保留期 3600s = 1h；旧 published 行 created_at 早于 2h 前 → 应被删（恰 1 条）。
    let deleted = outbox.sweep(3600).await?;
    assert_eq!(deleted, 1, "sweep should delete exactly 1 published row");

    // dlx 行应保留。
    let remaining: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&event_dlx)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(remaining.0, 1, "dlx row should not be swept");

    // anti-vacuity：保留期内的 published 与 pending 行仍在（sweep 只删超保留期的 published）。
    for eid in [&event_fresh, &event_pending] {
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
            .bind(eid)
            .fetch_one(&store.pool)
            .await?;
        assert_eq!(cnt.0, 1, "in-retention row must survive sweep: {eid}");
    }

    store.shutdown().await?;
    Ok(())
}

// ── T9: lease_token CAS fencing（stale token 不能结算被新租约接管的行）─────────
//
// spec data-model §outbox 强制「CAS：status 转移以 lease_token 比对（防并发双发）」。

#[tokio::test(flavor = "multi_thread")]
async fn t9_settle_rejects_stale_lease_token() -> TestResult {
    let store = PgStore::connect(&config_from_env()?).await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t9");
    let entry = make_entry(&event_id);

    // seed 1 行 pending。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            Box::pin(async move {
                append_outbox(c, &entry, &make_test_env("t9-domain", "c")).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // A 取租约 → tokenA（行置 publishing）。
    let lease = crate::outbox::acquire_lease(&store.pool, &event_id).await?;
    let (_rc, token_a) = lease.ok_or("acquire_lease should return a lease for pending row")?;

    // 模拟 B 重新 acquire：覆盖 lease_token = tokenB，A 的 tokenA 变 stale。
    sqlx::query("UPDATE outbox SET lease_token = gen_random_uuid() WHERE event_id = $1")
        .bind(&event_id)
        .execute(&store.pool)
        .await?;

    // A 用 stale tokenA 结算 → WHERE lease_token 不匹配 → 0 行 → 行不变（仍 publishing）且返 LostLease（F3）。
    let stale_outcome = crate::outbox::settle_published(&store.pool, &event_id, &token_a).await?;
    assert_eq!(
        stale_outcome,
        SettleOutcome::LostLease,
        "stale lease token settle must report LostLease (0-row CAS fencing miss)"
    );
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        status.0, "publishing",
        "stale lease token must not settle the row (CAS fencing)"
    );

    // B 用正确 tokenB 结算 → published；返 Settled（F3）。
    let token_b: (String,) =
        sqlx::query_as("SELECT lease_token::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    let settled_outcome =
        crate::outbox::settle_published(&store.pool, &event_id, &token_b.0).await?;
    assert_eq!(
        settled_outcome,
        SettleOutcome::Settled,
        "valid lease token must report Settled"
    );
    let status2: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        status2.0, "published",
        "valid lease token must settle the row"
    );

    store.shutdown().await?;
    Ok(())
}
