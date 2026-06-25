//! postgres adapter 集成测试（crate-internal；需真实 postgres，`integration` feature 门控；#1116 review F2/F5/F6）。
//!
//! crate-internal（非 `tests/`）以行使 `pub(crate)` 的 [`crate::PgStore::run_in_transaction`]（裸事务非公开
//! API，review F2）。容器经 `testkit::env_or_postgres()` self-provision（testcontainers，#1137）——无需手工预置。
//! **外部 PG 路径（快速本地迭代）**：须设 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES`（显式 opt-in）+
//! 5 元组 `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD`；`PGDATABASE` 须以 `_test` 结尾或 `== "test"`
//! （严格库名，单源校验在 testkit）。需 docker（容器路径）。跑 `cargo nextest run -p postgres --features integration`。
//!
//! **fail-closed（review F5/F6）**：连不上 → 测试**失败**（非静默跳过）；
//! 库名校验由 `testkit::env_or_postgres` 单源执行，此处无需重复。
//! 连接配置由 [`crate::test_pg::connect_pg`] 统一管理，不在各测试内分散。

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, SeenState};
use diport::ManagedResource;
use futures::future::BoxFuture;

use crate::PgStore;

// 统一 Send+Sync 错误（= testkit::FixtureError）：sqlx::Error / PgError / FixtureError 均 Send+Sync，
// 全 `?` 无跨界转换（避免 Box<dyn Error+Send+Sync> → Box<dyn Error> 的 ? 转换 papercut）。
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

use crate::test_pg::connect_pg;

/// 测试用固定事件发生时刻（unix 秒）——t10/t11 断言 envelope `occurred_at`（#1129）。
const TEST_OCCURRED_SECS: u64 = 1_700_000_000;

/// 固定时钟时刻（`Duration::from_secs` 取 `u64`）。
fn fixed_clock_time() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(TEST_OCCURRED_SECS)
}

/// DB 中 `occurred_at` 的期望编码值——经与生产**同一** `crate::outbox::unix_secs` 编码路径求得（`i64`），
/// 避免断言端 `u64` 字面量与写入端 `i64` 在边界值上漂移（review F4）。
fn expected_occurred_at() -> i64 {
    crate::outbox::unix_secs(fixed_clock_time())
}

/// 集成测试固定时钟（impl [`diport::Clock`]）：确定性 `occurred_at`，不取系统时钟（#1129）。
/// 本地定义——**不**引 `memory` adapter 作 dev-dep（避免 adapter→adapter 依赖），同 oidc/relay 各自定义替身范式。
struct FixedClock(std::time::SystemTime);
impl diport::Clock for FixedClock {
    fn now(&self) -> std::time::SystemTime {
        self.0
    }
}

/// 构造注入用 clock（`Box<dyn Clock>`，与全项目 clock 注入约定一致，固定 [`fixed_clock_time`]）。
fn fixed_clock() -> Box<dyn diport::Clock> {
    Box::new(FixedClock(fixed_clock_time()))
}

#[tokio::test(flavor = "multi_thread")]
async fn pool_connects_and_shuts_down() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    assert_eq!(store.name(), "postgres");
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrator_applies_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 应用 0001 占位
    store.run_migrations().await?; // 再跑：checksum 命中 → 幂等 no-op
    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_commit_persists_and_rollback_discards() -> TestResult {
    let (_pg, store) = connect_pg().await?;

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
    let (_pg, store) = connect_pg().await?;
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

use consistency::{Disposition, Entry, OutboxRelay, OutboxSource, OutboxSweeper, Topic};
use diport::{DynPublisher, PublishRequest, Publisher, PublisherError};

use crate::outbox::{
    MAX_PUBLISH_ATTEMPTS, OutboxEnvelope, OutboxMetadata, PgOutbox, SettleOutcome, append_outbox,
};

/// setup 阶段：应用 migration（含 outbox 表），清空 outbox（防测试间污染）。
async fn setup_outbox(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

/// 测试用简化 envelope（占位 `occurred_at=0`）：仅供原子性 / relay 路径验证（T1–T2 等直调 `append_outbox`
/// 的用例，不断言 occurred_at 值）。`occurred_at` 构造期必填（#262 F1），此处取占位 0；envelope occurred_at 的
/// 生产注入路径（从注入 Clock）由 t10（`PgEmitter`）/ t11（`PgSessionUnitOfWork`）/ config co-tx 专门覆盖（#1129）。
fn make_envelope(event_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        "test-domain".to_string(),
        "contract-1".to_string(),
        OutboxMetadata::new(0).with_subject_id(event_id),
    )
}

/// 构造测试 envelope（domain + contract_id，仅占位 `occurred_at=0` 的 metadata）——去重 `OutboxEnvelope::new` 内联重复。
fn make_test_env(domain: &str, contract_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0),
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
    let (_pg, store) = connect_pg().await?;
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
                OutboxMetadata::new(0).with_subject_id(event_id.as_str()),
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
    let (_pg, store) = connect_pg().await?;
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
                OutboxMetadata::new(0).with_subject_id(event_id.as_str()),
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
    let (_pg, store) = connect_pg().await?;
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
                OutboxMetadata::new(0),
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
    let (_pg, store) = connect_pg().await?;
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
                OutboxMetadata::new(0),
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
    let (_pg, store) = connect_pg().await?;
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
                OutboxMetadata::new(0),
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
    let (_pg, store) = connect_pg().await?;
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
    let (_pg, store) = connect_pg().await?;
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
    let (_pg, store) = connect_pg().await?;
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
    let (_pg, store) = connect_pg().await?;
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

// ── T10: PgEmitter durable emit（#1100/T008）──────────────────────────────────
//
// 原子性回滚（acc #3）由 T1（append_outbox in rolled-back tx → 无 entry）守——PgEmitter::emit 复用
// append_outbox + 事务，故原子性结构上同源。本测覆盖 emit commit 路径的写正确性（acc #1 的 entry 形态）。

/// PgEmitter::emit 落 durable outbox：恰 1 行 pending，event_id(=EventId)/domain/topic 正确，
/// metadata 仅含 opaque subjectId（无 PII / 无 reserved key，FR-020）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——Topic/IdemKey parse 已知合法值；函数级 item-level carve-out（error-handling.md §Carve-out）。
async fn t10_pg_emitter_commits_one_pending_with_eventid_and_subject() -> TestResult {
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    // F5(#1194)：仅建表、不全表 DELETE——本用例按 unique `event_id` 隔离断言（`WHERE event_id = $1`），
    // 不需净表起点，避免并发共享库下污染他用例刚写入的行（`setup_outbox` 的全表清理是 pre-existing，#1194 收口）。
    store.run_migrations().await?;

    let event_id = unique_event_id("t10-emit");
    let entry = Entry::new(
        Topic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        br#"{"sessionId":"s"}"#.to_vec(),
    );
    crate::PgEmitter::new(&store, fixed_clock())
        .emit(
            entry,
            OutboxEnvelopeParts {
                domain: "identity".to_string(),
                contract_id: SESSION_CREATED_TOPIC.to_string(),
                subject_id: "subj-opaque-77".to_string(),
            },
        )
        .await?;

    let row: (String, String, String, String, String) = sqlx::query_as(
        "SELECT event_id, domain, topic, status, metadata::text FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, event_id, "event_id = EventId");
    assert_eq!(row.1, "identity", "domain");
    assert_eq!(row.2, SESSION_CREATED_TOPIC, "topic");
    assert_eq!(row.3, "pending", "新 entry pending 待 relay");
    // metadata 含 opaque subjectId + sealed 注入的 reserved occurred_at（#1129）；无完整 PII（FR-020 funnel）。
    assert!(
        row.4.contains("subjectId") && row.4.contains("subj-opaque-77"),
        "metadata 应含 opaque subjectId: {}",
        row.4
    );
    assert!(
        row.4
            .contains(&format!(r#""occurred_at":{}"#, expected_occurred_at())),
        "metadata 应含 sealed 注入的 occurred_at（unix 秒，来自注入 Clock）: {}",
        row.4
    );
    // trace / correlation / principal 为后续 follow-up 空接缝，本 PR 不写。
    for reserved in ["trace", "correlation", "principal"] {
        assert!(
            !row.4.contains(reserved),
            "空接缝 reserved key {reserved} 本 PR 不应写入: {}",
            row.4
        );
    }

    store.shutdown().await?;
    Ok(())
}

// ── T11–T14: PgSessionUnitOfWork co-tx（session 持久化 + outbox append 同一事务，#1083/#1192）─────────
//
// OUTBOX-COTX-SESSION-01 anti-vacuity：t11 证真实 method commit 两行皆在（含 tenant-correct）、t13 证幂等
// 重写各恰一行；负向 rollback 双覆盖——t12 在单事务内复刻 co-tx SQL 序列后强制 Err 证两写共回滚，**t14 驱动
// 真实 `persist_session_and_emit` 的 rollback 分支**（to_timestamp 溢出使 session INSERT 失败）证两行皆无
// （review #1192 F1：补 t12 仅复刻序列的盲区，直测真实 method 的错误→rollback 路径）。

use std::time::{Duration, SystemTime};

use diport::OutboxEnvelopeParts;
use identity::ports::{SessionUnitOfWork, TenantId};

/// co-tx 测试用 canonical 租户 UUID。
const COTX_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

/// session-created 契约 topic / contract_id 局部单源（本文件内 topic parse / contract_id / 断言统一引用，
/// 避免同义字面量重复——review #244 F4）。
const SESSION_CREATED_TOPIC: &str = "identity.session-created";

/// 构造 session-created Entry（topic/event_id/payload）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——Topic/IdemKey parse 已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn session_entry(event_id: &str) -> Entry {
    Entry::new(
        Topic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(event_id).unwrap(),
        br#"{"sessionId":"s"}"#.to_vec(),
    )
}

/// 构造 session-created envelope（opaque subject）。
fn session_envelope() -> OutboxEnvelopeParts {
    OutboxEnvelopeParts {
        domain: "identity".to_string(),
        contract_id: SESSION_CREATED_TOPIC.to_string(),
        subject_id: "subj-opaque-cotx".to_string(),
    }
}

/// t11：`persist_session_and_emit` commit → session 行 + outbox 行皆在，且 session tenant-correct。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t11_cotx_commits_session_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t11-sess");
    let event_id = unique_event_id("t11-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    crate::PgSessionUnitOfWork::new(&store, fixed_clock())
        .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
        .await?;

    // session 行：恰 1，subject / tenant_id（tenant-correct）正确。
    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 1, "session 行应写入");
    let srow: (String, String) =
        sqlx::query_as("SELECT subject, tenant_id::text FROM sessions WHERE session_id = $1")
            .bind(&session_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(srow.0, "subj-opaque-cotx", "session subject");
    assert_eq!(srow.1, COTX_TENANT_A, "session tenant_id（tenant-correct）");

    // outbox 行：恰 1，pending。
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "outbox 行应写入");
    let status: (String,) = sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(status.0, "pending", "新 outbox entry pending 待 relay");

    // co-tx 路径（第二装配点）同样经构造期 OutboxMetadata::new 从注入 Clock 注入 reserved occurred_at（#1129）。
    let meta: (String,) = sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        meta.0
            .contains(&format!(r#""occurred_at":{}"#, expected_occurred_at())),
        "co-tx outbox metadata 应含 sealed 注入的 occurred_at: {}",
        meta.0
    );

    store.shutdown().await?;
    Ok(())
}

/// t12：co-tx 写序列在单事务内执行后强制 Err → session 行 + outbox 行**共**回滚（both-or-neither）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t12_cotx_rollback_leaves_neither() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t12-sess");
    let event_id = unique_event_id("t12-evt");
    let entry = session_entry(&event_id);
    let env = OutboxEnvelope::new(
        "identity".to_string(),
        SESSION_CREATED_TOPIC.to_string(),
        OutboxMetadata::new(0).with_subject_id("subj-12"),
    );
    let tenant = COTX_TENANT_A.to_string();
    let sid = session_id.clone();

    // 同 PgSessionUnitOfWork 写序列（SET LOCAL + INSERT session + append_outbox）在单事务内执行后强制 Err →
    // run_in_transaction 回滚。证明两写**共**回滚（真实 method rollback 路径结构同源，见本节注释 + T10）。
    let rolled = store
        .run_in_transaction::<_, (), sqlx::Error>(move |c| {
            Box::pin(async move {
                sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
                    .bind(&tenant)
                    .execute(&mut *c)
                    .await?;
                sqlx::query(
                    r#"INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at)
                       VALUES ($1, $2, $3::uuid, to_timestamp($4), to_timestamp($5))
                       ON CONFLICT (session_id) DO NOTHING"#,
                )
                .bind(&sid)
                .bind("subj-12")
                .bind(&tenant)
                .bind(1_700_003_600_i64)
                .bind(1_700_000_000_i64)
                .execute(&mut *c)
                .await?;
                append_outbox(&mut *c, &entry, &env).await?;
                // 模拟 commit 前任一步失败 → 整体回滚（both-or-neither）。
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled.is_err(), "事务应回滚");

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        sess_cnt.0, 0,
        "回滚后 session 行不应存在（co-tx both-or-neither）"
    );
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "回滚后 outbox 行不应存在（co-tx both-or-neither）"
    );

    store.shutdown().await?;
    Ok(())
}

/// t13：同 session + 同 event_id 调两次 → session / outbox 各恰 1 行（ON CONFLICT DO NOTHING 幂等）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t13_cotx_idempotent_reemit() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t13-sess");
    let event_id = unique_event_id("t13-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let uow = crate::PgSessionUnitOfWork::new(&store, fixed_clock());

    for _ in 0..2 {
        let session = identity::test_support::session(
            &session_id,
            "subj-opaque-cotx",
            tenant,
            expires,
            created,
        );
        uow.persist_session_and_emit(session, session_entry(&event_id), session_envelope())
            .await?;
    }

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 1, "幂等：session 行恰 1");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "幂等：outbox 行恰 1");
    // 幂等重写不覆盖 metadata（ON CONFLICT DO NOTHING）：occurred_at 仍是首次写入值（规约固化，review F5）。
    let meta: (String,) = sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert!(
        meta.0
            .contains(&format!(r#""occurred_at":{}"#, expected_occurred_at())),
        "幂等重写不应覆盖首次 occurred_at: {}",
        meta.0
    );

    store.shutdown().await?;
    Ok(())
}

// ── T15–T18: OutboxBacklog::sample_backlog（#1209）────────────────────────────
//
// T15: 空表 → BacklogSample::empty()（depth=0, age=0）。
// T16: pending 行计入 depth；published/dlx/publishing 行不计。
// T17: oldest_age_seconds 来自 min(created_at)（最老 pending 行；允许小容差）。
// T18: retry_after > now() 的行排除在 depth 之外（与 poll_pending pending 谓词同源）。

use consistency::{BacklogSample, OutboxBacklog};

/// T15: 空 outbox（仅 migrations）→ sample_backlog 返 BacklogSample::empty()。
#[tokio::test(flavor = "multi_thread")]
async fn t15_sample_backlog_empty_table_returns_empty() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let sample = outbox.sample_backlog("test-domain").await?;

    assert_eq!(
        sample,
        BacklogSample::empty(),
        "空表应返 BacklogSample::empty()"
    );
    assert_eq!(sample.depth(), 0);
    assert_eq!(sample.oldest_age_seconds(), 0);

    store.shutdown().await?;
    Ok(())
}

/// T16: pending 行计入 depth；published/dlx/**非-stale** publishing 行**不**计
/// （此处 publishing 行 updated_at≈now()、lease 仍有效，属正常 in-flight，正确排除；stale publishing 见 T19）。
#[tokio::test(flavor = "multi_thread")]
async fn t16_sample_backlog_counts_only_pending_rows() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = "t16-domain";

    // seed：1 pending + 1 published + 1 dlx + 1 publishing。
    for (prefix, target_status) in [
        ("t16-pend", "pending"),
        ("t16-pub", "published"),
        ("t16-dlx", "dlx"),
        ("t16-pubing", "publishing"),
    ] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                let env = make_test_env(domain, "c");
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if target_status != "pending" {
            sqlx::query("UPDATE outbox SET status = $1 WHERE event_id = $2")
                .bind(target_status)
                .bind(&eid)
                .execute(&store.pool)
                .await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let sample = outbox.sample_backlog(domain).await?;

    assert_eq!(sample.depth(), 1, "仅 pending 行计入 depth，应为 1");

    store.shutdown().await?;
    Ok(())
}

/// T17: oldest_age_seconds 来自最老 pending 行的 created_at（min(created_at)）。
///
/// 插两行，旧行 created_at 人工回拨 10s；断言 oldest_age_seconds >= 10（允许 ±3s 容差）。
#[tokio::test(flavor = "multi_thread")]
async fn t17_sample_backlog_age_tracks_oldest_pending() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = "t17-domain";

    // 先插"新" pending 行（created_at = now()）。
    let new_id = unique_event_id("t17-new");
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = make_entry(&new_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    // 插"旧" pending 行，并把 created_at 回拨 10s（模拟 10 秒前写入）。
    let old_id = unique_event_id("t17-old");
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = make_entry(&old_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    sqlx::query(
        "UPDATE outbox SET created_at = now() - make_interval(secs => 10) WHERE event_id = $1",
    )
    .bind(&old_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let sample = outbox.sample_backlog(domain).await?;

    assert_eq!(sample.depth(), 2, "两条 pending 行");
    // oldest_age_seconds 须 ≥ 10（旧行回拨 10s）；上限放宽容差至 20s 吸收 testcontainer/CI round-trip
    // 抖动（断言意图是「取最老行龄」而非精确计时，宽上限避免慢 CI 偶发 flaky）。
    assert!(
        sample.oldest_age_seconds() >= 10,
        "oldest_age_seconds 应 ≥ 10，实际={}",
        sample.oldest_age_seconds()
    );
    assert!(
        sample.oldest_age_seconds() < 20,
        "oldest_age_seconds 不应超过 20（宽容差吸收 CI round-trip），实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}

/// T18: retry_after > now() 的行**不**计入 depth（与 poll_pending pending 谓词同源）。
#[tokio::test(flavor = "multi_thread")]
async fn t18_sample_backlog_excludes_future_retry_after() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = "t18-domain";

    // seed：1 到期 pending（retry_after IS NULL）+ 1 未到期 pending（retry_after = now()+3600）。
    let due_id = unique_event_id("t18-due");
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = make_entry(&due_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let future_id = unique_event_id("t18-future");
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = make_entry(&future_id);
            let env = make_test_env(domain, "c");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    // 把 future 行的 retry_after 置未来（3600s 后），status 保持 pending。
    sqlx::query(
        "UPDATE outbox SET retry_after = now() + make_interval(secs => 3600) WHERE event_id = $1",
    )
    .bind(&future_id)
    .execute(&store.pool)
    .await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    let sample = outbox.sample_backlog(domain).await?;

    // 仅 due_id（retry_after IS NULL）计入；future_id（retry_after > now()）排除。
    assert_eq!(
        sample.depth(),
        1,
        "retry_after > now() 的行不应计入 depth，应为 1"
    );

    store.shutdown().await?;
    Ok(())
}

/// T19: **stale** publishing（lease 过期、poll_pending 会重捞）计入 depth + oldest-age；**非-stale**
/// publishing（lease 仍有效）排除。锁定 sample_backlog 与 poll_pending 可投递集合同源（#1209 review F1）。
#[tokio::test(flavor = "multi_thread")]
async fn t19_sample_backlog_counts_stale_publishing() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = "t19-domain";
    let lease_ttl = crate::outbox::LEASE_TTL_SECONDS;

    // seed 两行 publishing：stale（updated_at 回拨 LEASE_TTL+10s）+ fresh（updated_at≈now()）。
    for (prefix, stale) in [("t19-stale", true), ("t19-fresh", false)] {
        let eid = unique_event_id(prefix);
        let entry = make_entry(&eid);
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                let env = make_test_env(domain, "c");
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
        if stale {
            sqlx::query(
                "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
            )
            .bind(lease_ttl + 10)
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE outbox SET status='publishing', updated_at = now() WHERE event_id = $1",
            )
            .bind(&eid)
            .execute(&store.pool)
            .await?;
        }
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let sample = outbox.sample_backlog(domain).await?;

    // 仅 stale publishing 计入（fresh 行 lease 有效、属正常 in-flight 排除）。
    assert_eq!(
        sample.depth(),
        1,
        "stale publishing 应计入 depth、fresh publishing 排除，应为 1"
    );
    // stale 行存在 ⇒ oldest-age 反映其积压龄（> 0）。
    assert!(
        sample.oldest_age_seconds() > 0,
        "stale publishing 的 oldest_age_seconds 应 > 0，实际={}",
        sample.oldest_age_seconds()
    );

    store.shutdown().await?;
    Ok(())
}

/// t14：驱动**真实** `persist_session_and_emit` 的 rollback 分支——session INSERT 因 `to_timestamp` 溢出失败
/// → co-tx 整体回滚 → session/outbox 两行皆无（OUTBOX-COTX-SESSION-01 负向 anti-vacuity，直测真实 method；
/// review #1192 F1：补 t12 仅复刻 SQL 序列的盲区）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t14_cotx_real_method_rollback_on_session_insert_failure() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t14-sess");
    let event_id = unique_event_id("t14-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    // expires_at 远超 Postgres timestamptz 上界（年 ~294277）：`to_timestamp(1e13 秒 ≈ 年 ~318850)` 溢出报错
    // → session INSERT 失败，驱动真实 `PgSessionUnitOfWork` 的 `write_session_and_outbox`→Err→rollback 分支。
    let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    let result = crate::PgSessionUnitOfWork::new(&store, fixed_clock())
        .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
        .await;
    assert!(
        result.is_err(),
        "session INSERT 溢出应使真实 co-tx method 返 Err"
    );

    // 真实 method rollback → 两行皆无（both-or-neither）。
    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 0, "真实 method 回滚后 session 行不应存在");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "真实 method 回滚后 outbox 行不应存在");

    store.shutdown().await?;
    Ok(())
}

// ── PgConfigRepo / PgConfigUnitOfWork：配置仓储 + co-tx 集成测试（#1249）─────────────
//
// OUTBOX-COTX-CONFIG-01 anti-vacuity：正向 `tc5` 证真实 method commit 两行皆在 ↔ 负向双覆盖——`tc6` 经真实
// `co_tx_with_outbox`（业务写真插一行后强制 Err）证两写共回滚，`tc7` 驱动真实 `save_and_append_outbox` 的 CAS
// 冲突分支证「冲突 → 无 outbox 行」（write-without-event 不发生）。

use settings::ports::{ConfigEntry, ConfigRepo, ConfigRepoError, ConfigUnitOfWork, SettingKey};

use crate::PgConfigRepo;
use crate::cotx::co_tx_with_outbox;

/// config 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值，避免两 const 漂移）。
const CONFIG_TENANT: &str = COTX_TENANT_A;
/// 第二租户（跨租户隔离测试 tc9）——与 `application.rs` 单测 TENANT_B 同值。
const CONFIG_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";
/// config-version-changed 契约 topic 局部单源。
const CONFIG_VERSION_CHANGED_TOPIC: &str = "settings.config-version-changed";

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn config_tenant() -> TenantId {
    TenantId::parse(CONFIG_TENANT).unwrap()
}

/// 构造 ConfigEntry（经 `ConfigEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
fn config_entry(key: &str, value: &str, version: u64) -> ConfigEntry {
    ConfigEntry::hydrate(
        SettingKey::parse(key).unwrap(),
        value,
        config_tenant(),
        version,
    )
}

/// 构造 config-version-changed outbox Entry。
#[allow(clippy::unwrap_used)]
fn config_outbox_entry(event_id: &str) -> Entry {
    Entry::new(
        Topic::parse(CONFIG_VERSION_CHANGED_TOPIC).unwrap(),
        IdemKey::parse(event_id).unwrap(),
        br#"{"key":"app.k","version":1}"#.to_vec(),
    )
}

/// 构造 config-version-changed envelope（opaque subject = 配置 key）。
fn config_envelope(subject: &str) -> OutboxEnvelopeParts {
    OutboxEnvelopeParts {
        domain: "settings".to_string(),
        contract_id: CONFIG_VERSION_CHANGED_TOPIC.to_string(),
        subject_id: subject.to_string(),
    }
}

/// setup：应用 migration（含 config_entries 表），清空 config_entries（防测试间污染）。outbox 用唯一
/// event_id 隔离断言，无需全表清。integration profile 串行执行（`.config/nextest.toml` `integration`
/// group `max-threads = 1` + self-provision 容器每轮独占），故全表 DELETE 无并发竞态。
async fn setup_config(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM config_entries")
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// tc1：save → find round-trip（未写 → None；写后 getter 全字段正确）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.timeout").unwrap();

    assert!(repo.find(tenant, &key).await?.is_none(), "未写入 → None");

    repo.save(tenant, config_entry("app.timeout", "30s", 1))
        .await?;
    let found = repo.find(tenant, &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "find 取回值");
    assert_eq!(found.version(), 1, "find 取回版本");
    assert_eq!(found.key().as_str(), "app.timeout", "find 取回 key");
    assert_eq!(found.tenant(), tenant, "find 取回 tenant（tenant-correct）");

    store.shutdown().await?;
    Ok(())
}

/// tc2：版本历史——find = max(version)；find_version 取精确历史版本；缺失版本 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc2_config_find_version_returns_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    repo.save(tenant, config_entry("app.k", "v1", 1)).await?;
    repo.save(tenant, config_entry("app.k", "v2", 2)).await?;

    assert_eq!(
        repo.find(tenant, &key).await?.unwrap().value(),
        "v2",
        "find = 最高版本"
    );
    assert_eq!(
        repo.find_version(tenant, &key, 1).await?.unwrap().value(),
        "v1",
        "find_version(1) = 历史 v1"
    );
    assert_eq!(
        repo.find_version(tenant, &key, 2).await?.unwrap().value(),
        "v2"
    );
    assert!(
        repo.find_version(tenant, &key, 9).await?.is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc3：CAS——陈旧版本（重复）与跳版（gap）均 VersionConflict；恰 max+1 成功。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc3_config_save_cas_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();

    repo.save(tenant, config_entry("app.k", "v1", 1)).await?;
    // 陈旧：再写 v1 → 冲突。
    assert!(matches!(
        repo.save(tenant, config_entry("app.k", "v1b", 1)).await,
        Err(ConfigRepoError::VersionConflict)
    ));
    // 跳版：max 是 1，写 v3 → 冲突（非 max+1）。
    assert!(matches!(
        repo.save(tenant, config_entry("app.k", "v3", 3)).await,
        Err(ConfigRepoError::VersionConflict)
    ));
    // 恰 max+1：v2 成功。
    repo.save(tenant, config_entry("app.k", "v2", 2)).await?;
    assert_eq!(
        repo.find(tenant, &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        "v2"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc4：delete 软删（tombstone）——find 返 None；历史值行**保留**（find_version 可读）；幂等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4_config_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    repo.save(tenant, config_entry("app.k", "v1", 1)).await?;
    repo.save(tenant, config_entry("app.k", "v2", 2)).await?;

    repo.delete(tenant, &key).await?;
    assert!(
        repo.find(tenant, &key).await?.is_none(),
        "delete 后 find None（latest 为 tombstone）"
    );
    // 软删：历史值行保留——find_version 仍可读 v1/v2（audit 友好）。
    assert_eq!(
        repo.find_version(tenant, &key, 1).await?.unwrap().value(),
        "v1",
        "历史 v1 保留"
    );
    assert_eq!(
        repo.find_version(tenant, &key, 2).await?.unwrap().value(),
        "v2",
        "历史 v2 保留"
    );
    // tombstone 版本（v3）本身 find_version 返 None。
    assert!(
        repo.find_version(tenant, &key, 3).await?.is_none(),
        "tombstone 版本 v3 不可读"
    );
    // latest_version 含 tombstone（= 3），version 不重置。
    assert_eq!(repo.latest_version(tenant, &key).await?, Some(3));
    // 幂等：latest 已 tombstone → 再删 no-op（latest_version 不变）。
    repo.delete(tenant, &key).await?;
    assert_eq!(
        repo.latest_version(tenant, &key).await?,
        Some(3),
        "再删幂等：不追加新 tombstone"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc5：co-tx commit → config 行 + outbox 行皆在（OUTBOX-COTX-CONFIG-01 正向）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5_config_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5-evt");

    repo.save_and_append_outbox(
        tenant,
        config_entry("app.k", "v1", 1),
        config_outbox_entry(&event_id),
        config_envelope("app.k"),
    )
    .await?;

    // config 行：恰 1（v1），且 tenant_id 正确落库（tenant-correct，co-tx SET LOCAL + 显式列写入；对齐 t11）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("app.k")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(crow.0, 1, "config 行应写入");
    assert_eq!(
        crow.1, CONFIG_TENANT,
        "config 行 tenant_id（tenant-correct）"
    );
    // outbox 行：恰 1。
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "outbox 行应写入（co-tx 两行皆在）");
    // #262 F1：settings config co-tx outbox metadata 含构造期注入的 occurred_at（第三装配点，从注入 Clock）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .contains(&format!(r#""occurred_at":{}"#, expected_occurred_at())),
        "config co-tx outbox metadata 应含构造期注入的 occurred_at: {}",
        cfg_meta.0
    );
    // 值经 find 取回正确。
    assert_eq!(
        repo.find(tenant, &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        "v1"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc6：co-tx 业务写后强制 Err → config 行 + outbox 行**共回滚**（both-or-neither，真实 `co_tx_with_outbox`）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc6_config_cotx_business_failure_rolls_back_both() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let tenant_uuid = tenant.as_uuid().to_string();
    let event_id = unique_event_id("cfg-tc6-evt");
    let entry = config_outbox_entry(&event_id);
    let env = OutboxEnvelope::new(
        "settings".to_string(),
        CONFIG_VERSION_CHANGED_TOPIC.to_string(),
        OutboxMetadata::new(0).with_subject_id("app.rollback".to_string()),
    );

    // 业务写：真插一行 config（成功）后强制 Err（模拟「配置写后、后续步骤失败」= emit/commit 失败等价物）。
    let result = co_tx_with_outbox(
        &store.pool,
        &tenant_uuid,
        &entry,
        &env,
        move |conn| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO config_entries (tenant_id, config_key, version, value) \
                     VALUES ($1::uuid, $2, $3, $4)",
                )
                .bind(CONFIG_TENANT)
                .bind("app.rollback")
                .bind(1_i64)
                .bind("v1")
                .execute(&mut *conn)
                .await
                .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Err::<(), ConfigRepoError>(ConfigRepoError::VersionConflict)
            })
        },
        |e| ConfigRepoError::Storage(Box::new(e)),
    )
    .await;
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    // both-or-neither：config 行回滚（不落库）+ outbox 行不落库。
    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.rollback")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "业务写失败 → 配置行回滚（不落库）");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "业务写失败 → outbox 行不落库（both-or-neither）"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc7：**真实 method** `save_and_append_outbox` 的 CAS 冲突分支 → VersionConflict 且**无 outbox 行**
/// （write-without-event 不发生）；原版本不被覆盖。
///
/// 与 tc6（直测 `co_tx_with_outbox` 骨架的业务写失败回滚）互补：tc7 驱动**真实 method** 的 rollback 路径
/// （CAS Err → 整事务回滚 → outbox 不落库），对齐 session t14「直测真实 method rollback 分支」范式，消除 tc6
/// 仅测骨架的盲区——OUTBOX-COTX-CONFIG-01 anti-vacuity（正向 tc5 ↔ 负向 tc6+tc7）由此闭合。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7_config_cotx_cas_conflict_emits_no_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();

    repo.save(tenant, config_entry("app.k", "v1", 1)).await?;

    // 以陈旧 v1 走 co-tx → CAS 冲突 → 整事务回滚（无 outbox 行）。
    let event_id = unique_event_id("cfg-tc7-evt");
    let result = repo
        .save_and_append_outbox(
            tenant,
            config_entry("app.k", "v1-stale", 1),
            config_outbox_entry(&event_id),
            config_envelope("app.k"),
        )
        .await;
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "CAS 冲突 → 无 outbox 行（write-without-event 不发生）"
    );
    // 原 v1 不被覆盖。
    assert_eq!(
        repo.find(tenant, &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        "v1",
        "冲突写不覆盖原值"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc8：storage 错误通道——关池后 find 返回 `ConfigRepoError::Storage`（基础设施错误分层映射，保留 source）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc8_config_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();

    // 关池（PgConfigRepo 持 pool clone，sqlx Pool 共享底座 → 一并关闭）→ 后续查询 sqlx 错误 → Storage。
    store.shutdown().await?;
    let result = repo
        .find(tenant, &SettingKey::parse("app.k").unwrap())
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "关池后 find 应映射为 ConfigRepoError::Storage（基础设施错误分层，保留 source）"
    );

    Ok(())
}

/// tc9：**跨租户隔离**——tenant A 的配置对 tenant B 不可见，独立版本空间，delete 互不影响。
///
/// pre-GA 无 RLS policy，租户隔离完全依赖各查询的显式 `WHERE tenant_id = $1::uuid`——本例是该约束在真实
/// postgres 路径下的**唯一自动化门**（in-mem 路径由 `application.rs::cross_tenant_isolation` 守，二者实现不同）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9_config_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.k").unwrap();

    // tenant A 写 app.k v1。
    repo.save(
        tenant_a,
        ConfigEntry::hydrate(SettingKey::parse("app.k").unwrap(), "a-secret", tenant_a, 1),
    )
    .await?;

    // tenant B 读同 key → None（find / find_version 均不泄漏 A 的数据）。
    assert!(
        repo.find(tenant_b, &key).await?.is_none(),
        "tenant B 不应看到 tenant A 的 config（find 隔离）"
    );
    assert!(
        repo.find_version(tenant_b, &key, 1).await?.is_none(),
        "tenant B find_version 同样隔离"
    );

    // tenant B 写同 key v1（独立版本空间，不受 A 的 v1 影响）→ 成功；各读各的值。
    repo.save(
        tenant_b,
        ConfigEntry::hydrate(SettingKey::parse("app.k").unwrap(), "b-value", tenant_b, 1),
    )
    .await?;
    assert_eq!(
        repo.find(tenant_a, &key).await?.unwrap().value(),
        "a-secret",
        "tenant A 值不被 tenant B 覆盖"
    );
    assert_eq!(
        repo.find(tenant_b, &key).await?.unwrap().value(),
        "b-value",
        "tenant B 读自己的值"
    );

    // tenant B delete 不影响 tenant A。
    repo.delete(tenant_b, &key).await?;
    assert!(
        repo.find(tenant_b, &key).await?.is_none(),
        "tenant B 删除后自身不可见"
    );
    assert_eq!(
        repo.find(tenant_a, &key).await?.unwrap().value(),
        "a-secret",
        "tenant B delete 不影响 tenant A"
    );

    store.shutdown().await?;
    Ok(())
}

/// 构造 application 同款 event_id（`{topic}:{tenant}:{key}:v{version}`）——tc10 验 delete+republish 不复用。
fn config_event_id(tenant: TenantId, key: &str, version: u64) -> String {
    format!("{CONFIG_VERSION_CHANGED_TOPIC}:{tenant}:{key}:v{version}")
}

/// tc10：**F1 回归（postgres 层，exercises ON CONFLICT dedup）**——delete 软删后 republish 不复用 event_id，
/// outbox 事件不被吞（write-without-event 不重现）。
///
/// 旧 bug：delete 物理清历史 → republish 经 `latest_version` 回 v1 → event_id `...:v1` 复用 → outbox
/// `append_outbox` 的 `ON CONFLICT (event_id) DO NOTHING` 吞掉新事件（config 写入但事件丢失）。tombstone 软删
/// 使 version 单调（v1 → tombstone v2 → republish v3）→ event_id 不复用 → 两次 publish 各落一条 outbox 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc10_config_delete_republish_no_event_id_reuse() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    // publish v1 经 co-tx（content-派生 event_id ...:v1）。
    let ev1 = config_event_id(tenant, "app.k", 1);
    repo.save_and_append_outbox(
        tenant,
        config_entry("app.k", "v1", 1),
        config_outbox_entry(&ev1),
        config_envelope("app.k"),
    )
    .await?;

    // delete → tombstone v2（version 不重置）。
    repo.delete(tenant, &key).await?;

    // republish：下一版本 = latest_version(含 tombstone) + 1 = 3（**非**重置回 1，旧 bug 的根因）。
    let next = repo
        .latest_version(tenant, &key)
        .await?
        .map_or(1, |v| v + 1);
    assert_eq!(next, 3, "delete 软删后下一版本 = 3，不重置回 1");
    let ev3 = config_event_id(tenant, "app.k", next);
    assert_ne!(ev1, ev3, "republish event_id 不复用（v1 ≠ v3）");
    repo.save_and_append_outbox(
        tenant,
        config_entry("app.k", "v1-again", next),
        config_outbox_entry(&ev3),
        config_envelope("app.k"),
    )
    .await?;

    // 两次 publish 各落一条 outbox 行——republish 事件未被 ON CONFLICT 吞。
    let ob1: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev1)
        .fetch_one(&store.pool)
        .await?;
    let ob3: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev3)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob1.0, 1, "v1 outbox 行存在");
    assert_eq!(
        ob3.0, 1,
        "republish (v3) outbox 行存在——event_id 不复用，事件未被吞"
    );
    // 活跃值恢复。
    assert_eq!(
        repo.find(tenant, &key).await?.unwrap().value(),
        "v1-again",
        "republish 后活跃值恢复"
    );

    store.shutdown().await?;
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// PgRoleRepo（identity 角色仓储）集成测试（#1250）：CRUD / upsert / tenant 行级隔离 / 并发收敛。
//
// 构造 `Role` 经 `Role::hydrate`（pub funnel，无需 identity test-support）；`RoleId` 经 `role.id().clone()`
// 取得——RoleId 构造封闭（`pub(crate)` parse/new），测试不可裸 mint，符合 funnel 设计（外部可读不可伪造）。
// ───────────────────────────────────────────────────────────────────────────

use identity::ports::{Role, RoleRepo};

use crate::PgRoleRepo;

const ROLE_TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const ROLE_TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

fn role_tenant(raw: &str) -> Result<TenantId, Box<dyn std::error::Error + Send + Sync>> {
    Ok(TenantId::parse(raw)?)
}

// CRUD：save 新角色 → find 往返一致；同 id 二次 save → upsert 覆盖 name+permissions（非新增行）；查无 → None。
#[tokio::test(flavor = "multi_thread")]
async fn role_repo_save_find_roundtrip_and_upsert() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 未保存 → None（fail-closed，anti-vacuity 的负例基线）。
    let admin = Role::hydrate("role-admin", "Admin", &["docs:read".to_string()])?;
    let admin_id = admin.id().clone();
    assert!(
        repo.find(tenant, admin_id.clone()).await?.is_none(),
        "未保存 → None"
    );

    // save → find 往返一致（id / name / permissions）。
    repo.save(tenant, admin).await?;
    let got = repo
        .find(tenant, admin_id.clone())
        .await?
        .expect("saved role visible");
    assert_eq!(got.id().as_str(), "role-admin");
    assert_eq!(got.name(), "Admin");
    assert_eq!(got.permission_ids().collect::<Vec<_>>(), vec!["docs:read"]);

    // 同 id 二次 save → upsert 覆盖 name + permissions。
    let admin_v2 = Role::hydrate(
        "role-admin",
        "Administrator",
        &["docs:read".to_string(), "docs:write".to_string()],
    )?;
    repo.save(tenant, admin_v2).await?;
    let got2 = repo
        .find(tenant, admin_id)
        .await?
        .expect("upserted role visible");
    assert_eq!(got2.name(), "Administrator", "upsert 覆盖 name");
    assert_eq!(
        got2.permission_ids().collect::<Vec<_>>(),
        vec!["docs:read", "docs:write"],
        "upsert 覆盖 permissions"
    );
    // upsert 不新增行（DO UPDATE，非 INSERT）。
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("role-admin")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "upsert 不新增行");

    store.shutdown().await?;
    Ok(())
}

// tenant 行级隔离：A 保存的角色 B 查不到（负例）；A 自己可见（正例 anti-vacuity）。
#[tokio::test(flavor = "multi_thread")]
async fn role_repo_tenant_row_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgRoleRepo::new(&store);
    let tenant_a = role_tenant(ROLE_TENANT_A)?;
    let tenant_b = role_tenant(ROLE_TENANT_B)?;

    let role = Role::hydrate("shared-id", "OnlyInA", &["docs:read".to_string()])?;
    let id = role.id().clone();
    repo.save(tenant_a, role).await?;

    // 跨租不可见（负例）：tenant B 查同 id → None（行级隔离，不泄露存在性）。
    assert!(
        repo.find(tenant_b, id.clone()).await?.is_none(),
        "跨租 find → None（tenant 行级隔离）"
    );
    // 同租可见（正例，证明上面 None 非因数据未写入 = anti-vacuity）。
    assert_eq!(
        repo.find(tenant_a, id)
            .await?
            .expect("visible in own tenant")
            .name(),
        "OnlyInA"
    );

    store.shutdown().await?;
    Ok(())
}

// 并发：同 (tenant,id) 并发 save → ON CONFLICT 收敛、全 Ok（无 PK 错逃逸）、终态单行；不同 id 并发 → 各自落库。
#[tokio::test(flavor = "multi_thread")]
async fn role_repo_concurrent_save_converges() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgRoleRepo::new(&store));
    let tenant = role_tenant(ROLE_TENANT_A)?;

    // 同 id 并发 upsert：8 个 task 竞写同一 (tenant,id)。
    let mut handles = Vec::new();
    for i in 0..8 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            let role = Role::hydrate("contended", "C", &[format!("perm:{i}")])?;
            repo.save(tenant, role).await
        }));
    }
    for h in handles {
        // 每个 save 必 Ok——并发 PK 冲突由 ON CONFLICT DO UPDATE 收敛，不逃逸为 unique violation。
        h.await.expect("join")?;
    }
    // throwaway role 取 contended 的 RoleId（不 save，仅为 mint id 查终态）。
    let contended_id = Role::hydrate("contended", "x", &[])?.id().clone();
    let got = repo
        .find(tenant, contended_id)
        .await?
        .expect("contended role converged");
    assert_eq!(got.id().as_str(), "contended");
    // name 在所有 writer 间确定（恒 "C"）→ 终态 name 一致；permissions 因 writer 非确定（perm:0..7）不断言具体值。
    assert_eq!(got.name(), "C", "并发收敛终态 name 一致");
    let n: (i64,) =
        sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
            .bind(ROLE_TENANT_A)
            .bind("contended")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(n.0, 1, "并发同 id → 终态单行");

    // 不同 id 并发 save → 各自落库（无相互干扰）。
    let mut handles2 = Vec::new();
    for i in 0..8 {
        let repo = Arc::clone(&repo);
        handles2.push(tokio::spawn(async move {
            let role = Role::hydrate(&format!("role-{i}"), "N", &[])?;
            repo.save(tenant, role).await
        }));
    }
    for h in handles2 {
        h.await.expect("join")?;
    }
    let n2: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id LIKE 'role-%'",
    )
    .bind(ROLE_TENANT_A)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n2.0, 8, "8 个不同 id 各落一行");

    store.shutdown().await?;
    Ok(())
}
