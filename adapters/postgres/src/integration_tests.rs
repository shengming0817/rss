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

use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, LeaseToken, SeenState};
use diport::ManagedResource;
use futures::future::BoxFuture;

use crate::PgStore;

// 统一 Send+Sync 错误（= testkit::FixtureError）：sqlx::Error / PgError / FixtureError 均 Send+Sync，
// 全 `?` 无跨界转换（避免 Box<dyn Error+Send+Sync> → Box<dyn Error> 的 ? 转换 papercut）。
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

use crate::test_pg::{connect_pg, connect_pg_nobypass_role};

#[allow(clippy::unwrap_used)]
fn test_tenant() -> vocab::TenantId {
    vocab::TenantId::parse(COTX_TENANT_A).unwrap()
}

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

/// 构造注入用 clock（`Box<dyn Clock>`，emitter / session lifecycle 注入约定，固定 [`fixed_clock_time`]）。
fn fixed_clock() -> Box<dyn diport::Clock> {
    Box::new(FixedClock(fixed_clock_time()))
}

/// 构造注入用 clock（`Arc<dyn Clock>`，`PgConfigRepo` 共享扇出约定，固定 [`fixed_clock_time`]，#1424）。
fn fixed_clock_arc() -> std::sync::Arc<dyn diport::Clock> {
    std::sync::Arc::new(FixedClock(fixed_clock_time()))
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

/// RLS 能力门反例（**连接角色绕过**，最先 fail-fast）：superuser 连接（容器默认 `postgres`）→
/// `Err(RlsBypassRole)`。superuser / BYPASSRLS 绕过 FORCE RLS，能力门须先拒（tenancy.md「生产 owner 须为
/// 非 superuser」的运行期强制）。本测试**用默认 superuser 连接**直证绕过检测。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_bypass_role() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let verdict = store.verify_rls_capability().await; // superuser → 角色绕过门最先命中
    assert!(
        matches!(verdict, Err(crate::PgError::RlsBypassRole)),
        "superuser/BYPASSRLS 连接应使能力门 fail-fast，实得: {verdict:?}"
    );
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门正例：迁移后所有 tenant 表均 FORCE RLS + 规范 policy + GUC roundtrip，且**非绕过角色**连接 →
/// `verify_rls_capability` 放行。serving 连接须为非 superuser（superuser 会先触发 `RlsBypassRole`），故正例
/// 经 [`connect_pg_nobypass_role`] 建的 NOBYPASSRLS 角色驱动。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_ok_after_migrations() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?; // 迁移经 owner/superuser
    let app = connect_pg_nobypass_role(&_pg, &store).await?;
    app.verify_rls_capability().await?; // 非绕过角色 + FORCE RLS + 规范 policy + GUC roundtrip 全通过
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（fail-closed）：存在含 `tenant_id` 列却**无** RLS 的表 → `Err(RlsNotEnforced)`。
/// throwaway 表经 owner 建，能力门经**非绕过角色**判定（pg_catalog 不受权限过滤、仍可见该表）；DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_tenant_table_without_rls() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS _rls_probe_bad (tenant_id uuid NOT NULL, x int)")
        .execute(&store.pool)
        .await?;
    let app = connect_pg_nobypass_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_bad")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "含 tenant_id 列却无 FORCE RLS 的表应使能力门 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
    store.shutdown().await?;
    Ok(())
}

/// RLS 能力门反例（policy 内容校验 + OR-widening）：tenant 表 FORCE RLS 但 policy 为 `USING (true)`（不引用
/// `rss.tenant_id` GUC）→ 仍 `Err(RlsNotEnforced)`。守「policy 存在但表达式错误 / allow-all permissive 放宽」
/// 的运行时隔离静默失效路径（能力门校验 policy 内容、非仅存在性；与 xtask schema-rls 静态扫描互补）。
/// 经**非绕过角色**判定；throwaway 表隔离 + DROP 还原。
#[tokio::test(flavor = "multi_thread")]
async fn verify_rls_capability_rejects_permissive_policy() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    for stmt in [
        "CREATE TABLE IF NOT EXISTS _rls_probe_permissive (tenant_id uuid NOT NULL, x int)",
        "ALTER TABLE _rls_probe_permissive ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE _rls_probe_permissive FORCE ROW LEVEL SECURITY",
        "CREATE POLICY allow_all ON _rls_probe_permissive USING (true)",
    ] {
        sqlx::query(stmt).execute(&store.pool).await?;
    }
    let app = connect_pg_nobypass_role(&_pg, &store).await?;
    let verdict = app.verify_rls_capability().await;
    sqlx::query("DROP TABLE IF EXISTS _rls_probe_permissive")
        .execute(&store.pool)
        .await?;
    assert!(
        matches!(verdict, Err(crate::PgError::RlsNotEnforced)),
        "FORCE RLS 但 policy 为 USING(true)（不引用 rss.tenant_id）应 fail-closed，实得: {verdict:?}"
    );
    app.shutdown().await?;
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
    let lease_a = LeaseToken::mint();
    assert_eq!(
        s_a.try_claim(&key, &lease_a).await?,
        SeenState::Fresh,
        "首次 claim 应返回 Fresh"
    );

    // 断言 2：同组同 key 再见 → Duplicate（claimed_at 仍在 TTL 内，DO UPDATE WHERE false）。
    let lease_a2 = LeaseToken::mint();
    assert_eq!(
        s_a.try_claim(&key, &lease_a2).await?,
        SeenState::Duplicate,
        "同 key 再见应返回 Duplicate"
    );

    // 断言 3：不同消费者组同 key → Fresh（PK = (event_id, consumer_group)，组间去重独立）。
    let s_b = store.inbox(ConsumerGroup::parse("test-grp-b").unwrap());
    let lease_b = LeaseToken::mint();
    assert_eq!(
        s_b.try_claim(&key, &lease_b).await?,
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

use consistency::{Disposition, Entry, OutboxRelay, OutboxSource, RetentionSweeper, Topic};
use diport::{DynPublisher, PublishRequest, Publisher, PublisherError};

use crate::outbox::{
    MAX_PUBLISH_ATTEMPTS, OutboxEnvelope, OutboxMetadata, PgOutbox, SettleOutcome, append_outbox,
};

/// setup 阶段：应用 migration（含 outbox 表）。**不**全表 DELETE——每个 outbox 用例按唯一 `event_id`
/// （[`unique_event_id`]）+ 唯一 domain 命名空间自隔离断言（`WHERE event_id = $1` / domain-scoped 查询用各自
/// 专属 domain），故无需净表起点。去掉全表清后用例 correct-by-construction：在并发执行下亦互不污染——既覆盖
/// 官方串行 lane（`cargo nextest run --profile integration`，`.config/nextest.toml` `integration` test-group
/// `max-threads=1`），也覆盖直接 `cargo test -p postgres --features integration`（libtest 并行、绕过 nextest
/// 串行组）这条残留路径，隔离不再依赖调度器串行（#1194；nextest 串行组保留作 defense-in-depth）。
async fn setup_outbox(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
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

/// 产生唯一 domain（防 **domain-scoped 聚合断言**被跨轮 / 并发旧行污染）——与 [`unique_event_id`] 同源唯一性。
///
/// INVARIANT：按 domain 聚合且断言**精确 depth/计数**的用例（t16–t19 的 `sample_backlog`）必须用 **per-run 唯一**
/// domain。`outbox.event_id` UNIQUE + `ON CONFLICT (event_id) DO NOTHING` 只隔离**单行** `WHERE event_id` 查询；
/// 对 `sample_backlog(domain)` 这种**按 domain 聚合**的查询不够——外部持久库重复跑时，上一轮同 domain 旧行会被
/// 计入，使精确 depth 累加而 flaky（#1194 review F1）。去全表 DELETE 后唯一隔离手段即「event_id + domain 双唯一」。
fn unique_domain(prefix: &str) -> String {
    unique_event_id(prefix)
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
/// 生产注入路径（从注入 Clock）由 t10（`PgEmitter`）/ t11（`PgSessionLifecycle`）/ config co-tx 专门覆盖（#1129）。
fn make_envelope(domain: &str, event_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        "contract-1".to_string(),
        OutboxMetadata::new(0, test_tenant()).with_subject_id(event_id),
    )
}

/// 构造测试 envelope（domain + contract_id，仅占位 `occurred_at=0` 的 metadata）——去重 `OutboxEnvelope::new` 内联重复。
fn make_test_env(domain: &str, contract_id: &str) -> OutboxEnvelope {
    OutboxEnvelope::new(
        domain.to_string(),
        contract_id.to_string(),
        OutboxMetadata::new(0, test_tenant()),
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

    fn always_transient() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::transient(std::io::Error::other(
                        "fake transient publish error",
                    )))
                },
                calls: Arc::clone(&calls),
            },
            calls,
        )
    }

    fn always_permanent() -> (Self, Arc<Mutex<u32>>) {
        let calls = Arc::new(Mutex::new(0u32));
        (
            Self {
                result: || {
                    Err(PublisherError::permanent(std::io::Error::other(
                        "fake permanent publish error",
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
    let env = make_envelope("t1-domain", &event_id);

    // 事务内 append_outbox，然后返回 Err → 回滚。
    let result = store
        .run_in_transaction::<_, (), sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant()).with_subject_id(event_id.as_str()),
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
    let env = make_envelope("t2-domain", &event_id);

    // 事务内 append_outbox + Ok → commit。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant()).with_subject_id(event_id.as_str()),
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
    assert_eq!(row.2, "t2-domain", "domain should match");
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
    // t3 仅验 relay 路径、不断言 metadata；用 make_test_env（无 subject_id），避免 make_envelope 的
    // subject_id 在下方闭包重建时被丢弃的冗余（#1194 review F3）。
    let env = make_test_env("t3-domain", "contract-1");

    // seed: 1 行 pending。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                env.domain().to_string(),
                env.contract_id().to_string(),
                OutboxMetadata::new(0, test_tenant()),
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
                "t4-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant()),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, _) = RecordingPublisher::always_transient();
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
    let re = outbox.poll_pending("t4-domain", 10).await?;
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
                "t5-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant()),
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

    let (pub_, _) = RecordingPublisher::always_transient();
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

// ── T5b: permanent 错误首投即 dlx（#1212：跳过重试预算）─────────────────────────

/// #1212：permanent publish 错误在 retry_count=0（首投）即 → dlx（Reject），**不**熬满 MAX_PUBLISH_ATTEMPTS。
/// 对照 T5（transient 需预算耗尽才 dlx）：本测试 entry 全新（retry_count=0）、publisher 仅调 1 次。
#[tokio::test(flavor = "multi_thread")]
async fn t5b_relay_permanent_err_dlxes_on_first_attempt() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let event_id = unique_event_id("t5b");
    let entry = make_entry(&event_id);

    // seed: 1 行 pending，retry_count 保持默认 0（首投）。
    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = OutboxEnvelope::new(
                "t5b-domain".to_string(),
                "c".to_string(),
                OutboxMetadata::new(0, test_tenant()),
            );
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (pub_, calls) = RecordingPublisher::always_permanent();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_));

    let disposition = outbox.relay(&entry).await?;
    assert_eq!(
        disposition,
        Disposition::Reject,
        "permanent error should Reject (dlx) on first attempt"
    );

    // DB 状态 dlx，retry_count=1（首投失败累计，非耗尽到 MAX）。
    let row: (String, i32) =
        sqlx::query_as("SELECT status, retry_count FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(row.0, "dlx", "permanent error → dlx on first attempt");
    assert_eq!(
        row.1, 1,
        "retry_count=1 (first attempt), not exhausted to MAX"
    );

    // anti-vacuity：permanent 首投即 DLX ⇒ publisher 仅调 1 次（未走退避重试预算）。
    #[allow(clippy::unwrap_used)]
    // reason: 测试内部 Mutex 无 poisoning 来源，item-level carve-out（同 RecordingPublisher::publish）。
    let call_count = *calls.lock().unwrap();
    assert_eq!(call_count, 1, "publisher called exactly once (no retry)");

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
    // 保留期 3600s = 1h；本用例的旧 published 行 created_at 早于 2h 前 → 必被删。
    // 注：`sweep` 是**全表** DELETE（无 domain 过滤），故**不**断言精确全局计数——去掉 `setup_outbox` 全表 DELETE
    // 后本用例的 `event_fresh`（in-retention published，created_at≈now()）本轮不被删而遗留；外部持久库下若跨轮
    // 间隔 > 保留期，遗留行老化后会被本轮 sweep 多删，使 `== 1` flaky（#1194 review F1）。改为：
    //   ① 全局只断言「至少删 ≥1」(anti-vacuity，本用例 aged 行必被删)；
    //   ② 精确性由下方 **event_id-scoped** 断言（被删的确是 event_pub）承载——跨轮 / 并发稳健。
    let deleted = outbox.sweep(3600).await?;
    assert!(
        deleted >= 1,
        "sweep should delete at least the aged published row"
    );
    // 被删的确是本用例的 aged published 行（event_pub）——event_id-scoped，非全局计数。
    let pub_gone: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id=$1")
        .bind(&event_pub)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        pub_gone.0, 0,
        "aged published row (event_pub) must be swept"
    );

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

// ── #1210 inbox_dedup 保留期清理：done 超期被删；claimed + 保留期内 done 存活（anti-vacuity）。──
// sweep 是**全表** DELETE（无 group 过滤），故全局只断言「≥1」+ per-row event_id-scoped 精确断言（跨轮/并发稳健，同 t8）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
async fn t_inbox_sweep_removes_old_done_keeps_claimed_and_recent() -> TestResult {
    use consistency::LeaseOutcome;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let grp = unique_domain("inbox-sweep-grp");
    let inbox = store.inbox(ConsumerGroup::parse(&grp).unwrap());

    // 回拨 claimed_at 过期的 helper（2h 前）。
    async fn backdate(store: &PgStore, event_id: &str, grp: &str) -> TestResult {
        sqlx::query(
            "UPDATE inbox_dedup SET claimed_at = now() - make_interval(secs => $1) \
             WHERE event_id = $2 AND consumer_group = $3",
        )
        .bind(7200i64)
        .bind(event_id)
        .bind(grp)
        .execute(&store.pool)
        .await?;
        Ok(())
    }

    // 1) old done：claim → commit（done）→ 回拨过期。
    let key_old = unique_event_id("inbox-sweep-old");
    let k_old = IdemKey::parse(&key_old).unwrap();
    let lease_old = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&k_old, &lease_old).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&k_old, &lease_old).await.unwrap(),
        LeaseOutcome::Held
    );
    backdate(&store, &key_old, &grp).await?;

    // 2) recent done（anti-vacuity）：claim → commit，不回拨。
    let key_recent = unique_event_id("inbox-sweep-recent");
    let k_recent = IdemKey::parse(&key_recent).unwrap();
    let lease_recent = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&k_recent, &lease_recent).await.unwrap(),
        SeenState::Fresh
    );
    assert_eq!(
        inbox.commit(&k_recent, &lease_recent).await.unwrap(),
        LeaseOutcome::Held
    );

    // 3) claimed（anti-vacuity）：claim 但不 commit，回拨过期——sweep 只删 done，不删 claimed。
    let key_claimed = unique_event_id("inbox-sweep-claimed");
    let k_claimed = IdemKey::parse(&key_claimed).unwrap();
    let lease_claimed = LeaseToken::mint();
    assert_eq!(
        inbox.try_claim(&k_claimed, &lease_claimed).await.unwrap(),
        SeenState::Fresh
    );
    backdate(&store, &key_claimed, &grp).await?;

    // sweep 保留期 1h：仅 old done（2h 前）被删。
    let deleted = store.inbox_sweeper().sweep(3600).await?;
    assert!(deleted >= 1, "至少删除老 done 行: deleted={deleted}");

    let cnt = |event_id: String| {
        let pool = store.pool.clone();
        let grp = grp.clone();
        async move {
            let row: (i64,) = sqlx::query_as(
                "SELECT count(*) FROM inbox_dedup WHERE event_id = $1 AND consumer_group = $2",
            )
            .bind(event_id)
            .bind(grp)
            .fetch_one(&pool)
            .await?;
            Ok::<i64, Box<dyn std::error::Error + Send + Sync>>(row.0)
        }
    };
    assert_eq!(cnt(key_old).await?, 0, "超保留期 done 行必须被 sweep 删");
    assert_eq!(cnt(key_recent).await?, 1, "保留期内 done 行不应被 sweep 删");
    assert_eq!(
        cnt(key_claimed).await?,
        1,
        "claimed 行（非 done）不应被 sweep 删"
    );

    store.shutdown().await?;
    Ok(())
}

// ── #1210 dead_letter 保留期清理：超期死信被删；保留期内死信存活（anti-vacuity）。──
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
async fn t_dead_letter_sweep_removes_old_keeps_recent() -> TestResult {
    use diport::{
        DeadLetterRecord, DeadLetterStore, DeadLetterSummary, EnvelopeMetadata,
        WritableDeadLetterSource,
    };
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let dl = store.dead_letter();
    let domain = unique_domain("dl-sweep");

    // old 死信：写入 → 回拨 last_attempt_at 过期（2h 前）。
    dl.write_dead_letter(DeadLetterRecord::new(
        vocab::TenantId::parse(COTX_TENANT_A).unwrap(),
        "msg-dl-old",
        domain.as_str(),
        "contract-x",
        "dl.old",
        b"payload".to_vec(),
        DeadLetterSummary::new("aged dead letter"),
        10,
        WritableDeadLetterSource::Consumer,
        EnvelopeMetadata::empty(),
    ))
    .await?;
    sqlx::query(
        "UPDATE dead_letter SET last_attempt_at = now() - make_interval(secs => $1) \
         WHERE domain = $2 AND topic = $3",
    )
    .bind(7200i64)
    .bind(&domain)
    .bind("dl.old")
    .execute(&store.pool)
    .await?;

    // recent 死信（anti-vacuity）：写入，不回拨。
    dl.write_dead_letter(DeadLetterRecord::new(
        vocab::TenantId::parse(COTX_TENANT_A).unwrap(),
        "msg-dl-recent",
        domain.as_str(),
        "contract-x",
        "dl.recent",
        b"payload".to_vec(),
        DeadLetterSummary::new("recent dead letter"),
        10,
        WritableDeadLetterSource::Consumer,
        EnvelopeMetadata::empty(),
    ))
    .await?;

    // sweep 保留期 1h：仅 old（2h 前）被删。
    let deleted = dl.sweep(3600).await?;
    assert!(deleted >= 1, "至少删除老死信: deleted={deleted}");

    let cnt_old: (i64,) =
        sqlx::query_as("SELECT count(*) FROM dead_letter WHERE domain = $1 AND topic = $2")
            .bind(&domain)
            .bind("dl.old")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cnt_old.0, 0, "超保留期死信必须被 sweep 删");

    let cnt_recent: (i64,) =
        sqlx::query_as("SELECT count(*) FROM dead_letter WHERE domain = $1 AND topic = $2")
            .bind(&domain)
            .bind("dl.recent")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cnt_recent.0, 1, "保留期内死信不应被 sweep 删");

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_dead_letter_replay_inserts_new_outbox_id() -> TestResult {
    use diport::{
        DeadLetterRecord, DeadLetterSource, DeadLetterStore, DeadLetterSummary, EnvelopeMetadata,
        KEY_CORRELATION, KEY_TENANT_ID, WritableDeadLetterSource,
    };
    use eventexec::{
        DeadLetterId, DlqCursor, DlqError, DlqListQuery, DlqReplayOutcome, DlqReplayRequest,
        DlqStore as _, OperatorDlqCapability,
    };

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let dl = store.dead_letter();
    let dlq = store.dlq();
    let domain = unique_domain("dlq-replay");
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let message_id = unique_event_id("consumer-msg");
    let mut metadata = EnvelopeMetadata::empty();
    metadata.insert_wire_pair(KEY_TENANT_ID, COTX_TENANT_A);
    metadata.insert_wire_pair(KEY_CORRELATION, "corr-dlq-replay");

    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &message_id,
        domain.as_str(),
        "contract-dlq",
        "test.event",
        b"consumer-payload".to_vec(),
        DeadLetterSummary::new("consumer exhausted"),
        3,
        WritableDeadLetterSource::Consumer,
        metadata,
    ))
    .await?;

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let replay_id = IdemKey::parse(&unique_event_id("replay")).unwrap();
    let cap = OperatorDlqCapability::issue_for_authorized_operator();
    let outcome = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
            cap,
        ))
        .await?;
    assert_eq!(outcome, DlqReplayOutcome::Inserted);

    let row: (String, String, Vec<u8>, String, String, String) = sqlx::query_as(
        r#"
        SELECT domain,
               contract_id,
               payload,
               metadata ->> 'tenantId',
               metadata ->> 'deadLetterId',
               metadata ->> 'originalMessageId'
        FROM outbox
        WHERE event_id = $1
        "#,
    )
    .bind(replay_id.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, domain);
    assert_eq!(row.1, "contract-dlq");
    assert_eq!(row.2, b"consumer-payload".to_vec());
    assert_eq!(row.3, COTX_TENANT_A);
    assert_eq!(row.4, dead_letter_id);
    assert_eq!(row.5, message_id);

    let duplicate = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&dead_letter_id)?,
            replay_id.clone(),
            cap,
        ))
        .await?;
    assert_eq!(duplicate, DlqReplayOutcome::AlreadyExists);

    let missing_id = uuid::Uuid::new_v4().to_string();
    let missing_replay_id = IdemKey::parse(&unique_event_id("missing-replay")).unwrap();
    let missing = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&missing_id)?,
            missing_replay_id,
            cap,
        ))
        .await;
    assert!(
        matches!(missing, Err(DlqError::NotFound)),
        "missing dead_letter id must map to NotFound"
    );

    let saga_message_id = unique_event_id("saga-msg");
    let saga_replay_id = IdemKey::parse(&unique_event_id("saga-replay")).unwrap();
    dl.write_dead_letter(DeadLetterRecord::new(
        tenant,
        &saga_message_id,
        domain.as_str(),
        "contract-dlq",
        "test.saga",
        b"saga-payload".to_vec(),
        DeadLetterSummary::new("saga compensation failed"),
        2,
        WritableDeadLetterSource::Saga,
        EnvelopeMetadata::empty(),
    ))
    .await?;
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (saga_dead_letter_id,): (String,) = sqlx::query_as(
        "SELECT id::text FROM dead_letter WHERE tenant_id = $1::uuid AND message_id = $2",
    )
    .bind(COTX_TENANT_A)
    .bind(&saga_message_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let saga_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&saga_dead_letter_id)?,
            saga_replay_id.clone(),
            cap,
        ))
        .await?;
    assert_eq!(saga_replay, DlqReplayOutcome::Inserted);

    let invalid_payload_id = unique_event_id("invalid-payload-dl");
    let invalid_entry = serde_json::json!({"unexpected": true});
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (invalid_dead_letter_id,): (String,) = sqlx::query_as(
        r#"
        INSERT INTO dead_letter
            (tenant_id, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts, source_kind, metadata)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'consumer', '{}'::jsonb)
        RETURNING id::text
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&invalid_payload_id)
    .bind(domain.as_str())
    .bind("contract-dlq")
    .bind("test.invalid")
    .bind(sqlx::types::Json(&invalid_entry))
    .bind("invalid payload row")
    .bind(1_i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    let invalid_payload = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&invalid_dead_letter_id)?,
            IdemKey::parse(&unique_event_id("invalid-payload-replay")).unwrap(),
            cap,
        ))
        .await;
    assert!(
        matches!(invalid_payload, Err(DlqError::InvalidPayload)),
        "malformed original_entry must map to InvalidPayload"
    );

    let first_page = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1),
        )
        .await?;
    assert!(
        first_page.has_more(),
        "limit=1 over 2 consumer rows must page"
    );
    let cursor = first_page.next_cursor().unwrap();
    let second_page = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_domain(domain.as_str())
                .with_source(DeadLetterSource::Consumer)
                .with_limit(1)
                .with_cursor(DlqCursor::parse(cursor)?),
        )
        .await?;
    assert_eq!(
        second_page.data().len(),
        1,
        "cursor must advance to next row"
    );

    let legacy_id = unique_event_id("legacy-dl");
    let legacy_entry = serde_json::json!({"bytes": [1, 2, 3]});
    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let (legacy_dead_letter_id,): (String,) = sqlx::query_as(
        r#"
        INSERT INTO dead_letter
            (tenant_id, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts, source_kind, metadata)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, 'legacy', '{}'::jsonb)
        RETURNING id::text
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&legacy_id)
    .bind(domain.as_str())
    .bind("contract-dlq")
    .bind("test.event")
    .bind(sqlx::types::Json(&legacy_entry))
    .bind("legacy row")
    .bind(1_i32)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    let legacy_replay_id = IdemKey::parse(&unique_event_id("legacy-replay")).unwrap();
    let legacy_replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&legacy_dead_letter_id)?,
            legacy_replay_id,
            cap,
        ))
        .await;
    assert!(
        matches!(legacy_replay, Err(DlqError::NotReplayable)),
        "legacy rows are audit-only and must not be replayable"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: integration test fixtures use known-valid ids; assertions should fail loud.
async fn t_outbox_dlx_registers_dead_letter_and_redrive_is_tenant_scoped() -> TestResult {
    use eventexec::{
        DeadLetterId, DlqEntryKind, DlqError, DlqListQuery, DlqRedriveOutcome, DlqRedriveRequest,
        DlqReplayRequest, DlqStore as _, OperatorDlqCapability,
    };

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;
    let tenant = vocab::TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B).unwrap();
    let domain = unique_domain("dlq-outbox");
    let event_id = unique_event_id("outbox-dlx");
    let entry = make_entry(&event_id);

    store
        .run_in_transaction::<_, _, sqlx::Error>(|c| {
            let entry = entry.clone();
            let env = make_test_env(&domain, "contract-dlq");
            Box::pin(async move {
                append_outbox(c, &entry, &env).await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    let (publisher, calls) = RecordingPublisher::always_permanent();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(publisher));
    let disposition = outbox.relay(&entry).await?;
    assert_eq!(disposition, Disposition::Reject);
    assert_eq!(*calls.lock().unwrap(), 1);

    let mut tx = store.pool.begin().await?;
    crate::cotx::set_local_tenant(&mut tx, tenant).await?;
    let row: (String, String, String, i32, serde_json::Value) = sqlx::query_as(
        r#"
        SELECT id::text, source_kind, message_id, num_attempts, metadata
        FROM dead_letter
        WHERE tenant_id = $1::uuid
          AND message_id = $2
        "#,
    )
    .bind(COTX_TENANT_A)
    .bind(&event_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    assert_eq!(row.1, "outbox_relay");
    assert_eq!(row.2, event_id);
    assert_eq!(row.3, 1);
    assert_eq!(row.4["tenantId"], COTX_TENANT_A);

    let dlq = store.dlq();
    let cap = OperatorDlqCapability::issue_for_authorized_operator();
    let replay_id = IdemKey::parse(&unique_event_id("bad-replay")).unwrap();
    let replay = dlq
        .replay_dead_letter(DlqReplayRequest::new(
            tenant,
            DeadLetterId::parse(&row.0)?,
            replay_id,
            cap,
        ))
        .await;
    assert!(matches!(replay, Err(DlqError::NotReplayable)));

    let listed = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_domain(domain.as_str()),
        )
        .await?;
    assert_eq!(
        listed.data().len(),
        1,
        "current outbox dlx should be listed"
    );
    assert_eq!(listed.data()[0].kind(), DlqEntryKind::OutboxDlx);
    assert_eq!(listed.data()[0].id(), event_id);
    assert_eq!(listed.data()[0].message_id(), event_id);

    let event_key = IdemKey::parse(&event_id).unwrap();
    let wrong_tenant = dlq
        .redrive_outbox(DlqRedriveRequest::new(tenant_b, event_key.clone(), cap))
        .await?;
    assert_eq!(wrong_tenant, DlqRedriveOutcome::NotFound);

    let status_after_wrong: (String,) =
        sqlx::query_as("SELECT status FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(status_after_wrong.0, STATUS_DLX);

    let redriven = dlq
        .redrive_outbox(DlqRedriveRequest::new(tenant, event_key, cap))
        .await?;
    assert_eq!(redriven, DlqRedriveOutcome::Redriven);
    let status_after_redrive: (String, i32) =
        sqlx::query_as("SELECT status, retry_count FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(status_after_redrive.0, STATUS_PENDING);
    assert_eq!(status_after_redrive.1, 0);

    let listed_after_redrive = dlq
        .list_dlq(
            DlqListQuery::new(tenant)
                .with_source(diport::DeadLetterSource::OutboxRelay)
                .with_domain(domain.as_str()),
        )
        .await?;
    assert!(
        listed_after_redrive.data().is_empty(),
        "redriven outbox rows must disappear from current DLQ list"
    );

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
    let (_rc, token_a, _metadata_json) =
        lease.ok_or("acquire_lease should return a lease for pending row")?;

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
    // F5(#1194)：仅建表、不全表 DELETE——本用例按 unique `event_id` 隔离断言（`WHERE event_id = $1`），不需
    // 净表起点。#1194 现已全量收口：`setup_outbox` 亦不再全表 DELETE，全部 outbox 用例按 event_id + 专属
    // domain 自隔离（correct-by-construction，并发下亦不互污染）；此处直接 `run_migrations` 与之一致。
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
            OutboxEnvelopeParts::new(
                vocab::ContractBinding::from_static("identity", SESSION_CREATED_TOPIC),
                test_tenant(),
                "subj-opaque-77",
            ),
        )
        .await?;

    let row: (String, String, String, String, String, String) = sqlx::query_as(
        "SELECT event_id, domain, topic, contract_id, status, metadata::text FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0, event_id, "event_id = EventId");
    assert_eq!(row.1, "identity", "domain");
    assert_eq!(row.2, SESSION_CREATED_TOPIC, "topic");
    // contract_id 列 = ContractBinding.contract_id()（#1193 typed 绑定经 adapter 落库的 drift-lock）。
    assert_eq!(row.3, "identity.session-created", "contract_id");
    assert_eq!(row.4, "pending", "新 entry pending 待 relay");
    // metadata 含 opaque subjectId + sealed 注入的 reserved occurred_at（#1129）；无完整 PII（FR-020 funnel）。
    assert!(
        row.5.contains("subjectId") && row.5.contains("subj-opaque-77"),
        "metadata 应含 opaque subjectId: {}",
        row.5
    );
    assert!(
        row.5
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "metadata 应含 sealed 注入的 occurred_at（unix 秒，来自注入 Clock）: {}",
        row.5
    );
    // trace / correlation / principal 为后续 follow-up 空接缝，本 PR 不写。
    for reserved in ["trace", "correlation", "principal"] {
        assert!(
            !row.5.contains(reserved),
            "空接缝 reserved key {reserved} 本 PR 不应写入: {}",
            row.5
        );
    }

    store.shutdown().await?;
    Ok(())
}

// ── T11–T14: PgSessionLifecycle co-tx（session 持久化 + outbox append 同一事务，#1083/#1192）─────────
//
// OUTBOX-COTX-SESSION-01 anti-vacuity：t11 证真实 method commit 两行皆在（含 tenant-correct）、t13 证幂等
// 重写各恰一行；负向 rollback 双覆盖——t12 在单事务内复刻 co-tx SQL 序列后强制 Err 证两写共回滚，**t14 驱动
// 真实 `persist_session_and_emit` 的 rollback 分支**（to_timestamp 溢出使 session INSERT 失败）证两行皆无
// （review #1192 F1：补 t12 仅复刻序列的盲区，直测真实 method 的错误→rollback 路径）。

use std::time::{Duration, SystemTime};

use diport::OutboxEnvelopeParts;
use identity::ports::{SessionLifecycle, TenantId};

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
    OutboxEnvelopeParts::new(
        vocab::ContractBinding::from_static("identity", SESSION_CREATED_TOPIC),
        test_tenant(),
        "subj-opaque-cotx",
    )
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

    crate::PgSessionLifecycle::new(&store, fixed_clock())
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
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "co-tx outbox metadata 应含 sealed 注入的 occurred_at: {}",
        meta.0
    );

    store.shutdown().await?;
    Ok(())
}

/// t11b：session tenant 与 envelope tenant 不一致 → fail-closed，session / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t11b_cotx_rejects_envelope_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t11b-sess");
    let event_id = unique_event_id("t11b-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let envelope_tenant = TenantId::parse("00000000-0000-4000-8000-000000000abc").unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);
    let envelope = OutboxEnvelopeParts::new(
        vocab::ContractBinding::from_static("identity", SESSION_CREATED_TOPIC),
        envelope_tenant,
        "subj-opaque-cotx",
    );

    let result = crate::PgSessionLifecycle::new(&store, fixed_clock())
        .persist_session_and_emit(session, session_entry(&event_id), envelope)
        .await;
    assert!(
        result.is_err(),
        "session/envelope tenant mismatch must fail closed"
    );

    let sess_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(sess_cnt.0, 0, "mismatch 不得写 session 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "mismatch 不得写 outbox 行");

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
        OutboxMetadata::new(0, test_tenant()).with_subject_id("subj-12"),
    );
    let tenant = COTX_TENANT_A.to_string();
    let sid = session_id.clone();

    // 同 PgSessionLifecycle 写序列（SET LOCAL + INSERT session + append_outbox）在单事务内执行后强制 Err →
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
    let uow = crate::PgSessionLifecycle::new(&store, fixed_clock());

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
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "幂等重写不应覆盖首次 occurred_at: {}",
        meta.0
    );

    store.shutdown().await?;
    Ok(())
}

// ── T15–T18: OutboxBacklog::sample_backlog（#1209）────────────────────────────
//
// T15: 专属 domain 无行 → BacklogSample::empty()（depth=0, age=0；domain-scoped，不依赖全表净起点）。
// T16: pending 行计入 depth；published/dlx/publishing 行不计。
// T17: oldest_age_seconds 来自 min(created_at)（最老 pending 行；允许小容差）。
// T18: retry_after > now() 的行排除在 depth 之外（与 poll_pending pending 谓词同源）。

use consistency::{BacklogSample, OutboxBacklog};

/// T15: 对一个无任何用例写入的专属 domain（`t15-domain`）采样 → sample_backlog 返 BacklogSample::empty()。
/// domain-scoped 断言：不依赖全表净起点，去掉 `setup_outbox` 全表 DELETE 后仍恒空（#1194）。
#[tokio::test(flavor = "multi_thread")]
async fn t15_sample_backlog_empty_domain_returns_empty() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let outbox = make_pg_outbox(&store, || Ok(()));
    // 用 t15 专属 domain（无任何其它用例写入）→ domain-scoped 采样恒空，断言不依赖全表净起点（#1194）。
    let sample = outbox.sample_backlog("t15-domain").await?;

    assert_eq!(
        sample,
        BacklogSample::empty(),
        "无写入的专属 domain 采样应返 BacklogSample::empty()"
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

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t16-domain");
    let domain = domain.as_str();

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

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t17-domain");
    let domain = domain.as_str();

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

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t18-domain");
    let domain = domain.as_str();

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

    // per-run 唯一 domain：sample_backlog 按 domain 聚合，跨轮持久库须唯一防旧行计入（#1194 review F1）。
    let domain = unique_domain("t19-domain");
    let domain = domain.as_str();
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
                "UPDATE outbox SET status='publishing', created_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
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

// ── t24-t29: outbox partition-key + seq 集成验证（#1211 Batch 2a）──────────────
//
// t24: seq 单调且应用不可伪造（GENERATED ALWAYS 拒绝显式写入）
// t25: 同 partition 串行有序（head-of-partition gating：H→S2→S3 按序投递）
// t26: 跨 partition 不互阻 + NULL-partition 无序并行路径不变
// t27: dlx 队头阻塞 partition，re-drive 后恢复
// t28: crash recovery 保持 partition 顺序（stale publishing 头 gate 后继）
// t29: sample_backlog 计入 gated 后继（backlog poll-only by design）

use crate::outbox::{LEASE_TTL_SECONDS, STATUS_DLX, STATUS_PENDING};

/// t24：append 3 行（同 domain，无 partition）→ SELECT seq 严格递增、互异、非空；
/// 尝试 INSERT 显式写 seq 被 GENERATED ALWAYS 拒（应用不可伪造）。
///
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t24_seq_monotonic_and_app_cannot_forge() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t24");
    let ids: Vec<_> = (0..3)
        .map(|i| unique_event_id(&format!("t24-{i}")))
        .collect();

    // append 3 行，无 partition。
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c");
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // SELECT seq 并验证严格递增、互异、非空。
    let seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM outbox WHERE event_id = ANY($1::text[]) ORDER BY seq ASC",
    )
    .bind(ids.as_slice())
    .fetch_all(&store.pool)
    .await?;
    assert_eq!(seqs.len(), 3, "t24: 应有 3 行 seq");
    for w in seqs.windows(2) {
        assert!(
            w[0] < w[1],
            "t24: seq 应严格递增，实际 {} >= {}",
            w[0],
            w[1]
        );
    }

    // GENERATED ALWAYS 拒绝应用显式写入 seq。
    let fake_seq: i64 = 999_999_999;
    let forge_id = unique_event_id("t24-forge");
    let forge_result = sqlx::query(
        "INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status, seq) \
         VALUES ($1, $2, 'test.event', 'c', $3, '{}'::jsonb, 'pending', $4)",
    )
    .bind(&forge_id)
    .bind(&domain)
    .bind(b"p".as_slice())
    .bind(fake_seq)
    .execute(&store.pool)
    .await;
    assert!(
        forge_result.is_err(),
        "t24: GENERATED ALWAYS 应拒绝应用写入 seq（反真空：伪造尝试必须失败）"
    );

    store.shutdown().await?;
    Ok(())
}

/// t25：同 (domain, 'p1') partition → `poll_pending` 仅返队头；relay → published → poll → 后继。
///
/// 反真空：S2/S3 在 H 未 published 前缺席（head-of-partition gating 生效）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t25_partition_serial_in_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t25");
    let key = PartitionKey::parse("p1").unwrap();

    let h_id = unique_event_id("t25-H");
    let s2_id = unique_event_id("t25-S2");
    let s3_id = unique_event_id("t25-S3");

    // append H, S2, S3 同 (domain, 'p1')——顺序由 seq 的 IDENTITY 单调递增保证。
    for eid in [&h_id, &s2_id, &s3_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_ok));

    // poll → 仅 H（S2/S3 被 gate）。
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries.len(), 1, "t25: 首轮 poll 应仅返队头 H");
    assert_eq!(
        entries[0].idem_key().as_str(),
        h_id,
        "t25: 首轮 poll 必须是 H"
    );
    // 反真空：S2/S3 确实缺席。
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t25: S2 不应出现（被 gate）"
    );
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 不应出现（被 gate）"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(&h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t25: relay H 应返 Ack");

    // poll → S2（H 已 published，S2 现在是队头）。
    let entries2 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries2.len(), 1, "t25: 第二轮 poll 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t25: 第二轮 poll 必须是 S2"
    );
    // 反真空：S3 第二轮仍被 gate（与首轮 S3 缺席对称）。
    assert!(
        !entries2.iter().any(|e| e.idem_key().as_str() == s3_id),
        "t25: S3 第二轮仍被 gate 不应出现"
    );

    // relay S2 → published。
    let s2_entry = entries2.into_iter().next().unwrap();
    outbox.relay(&s2_entry).await?;

    // poll → S3。
    let entries3 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries3.len(), 1, "t25: 第三轮 poll 应仅返 S3");
    assert_eq!(
        entries3[0].idem_key().as_str(),
        s3_id,
        "t25: 第三轮 poll 必须是 S3"
    );

    store.shutdown().await?;
    Ok(())
}

/// t26：跨 partition 不互阻 + NULL-partition 无序并行路径不变。
///
/// 同 domain 下：p1-head + p2-head + 2 个 NULL-partition 行 → 一轮 poll 返 4 行。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t26_cross_partition_and_null_parallel() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t26");

    let p1_key = PartitionKey::parse("p1").unwrap();
    let p2_key = PartitionKey::parse("p2").unwrap();

    // p1-head, p2-head, null1, null2。
    let p1_id = unique_event_id("t26-p1");
    let p2_id = unique_event_id("t26-p2");
    let n1_id = unique_event_id("t26-null1");
    let n2_id = unique_event_id("t26-null2");

    // p1-head
    {
        let entry = make_entry(&p1_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p1_key));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // p2-head
    {
        let entry = make_entry(&p2_id);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(p2_key));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    // null1, null2（无 partition）。
    for nid in [&n1_id, &n2_id] {
        let entry = make_entry(nid);
        let env = make_test_env(&domain, "c");
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(
        entries.len(),
        4,
        "t26: p1-head + p2-head + null1 + null2 = 4 行（跨 partition 不互阻，NULL 不约束）"
    );

    // 验证四个预期 ID 都在返回集合中。
    let ids_in: Vec<&str> = entries.iter().map(|e| e.idem_key().as_str()).collect();
    for expected in [
        p1_id.as_str(),
        p2_id.as_str(),
        n1_id.as_str(),
        n2_id.as_str(),
    ] {
        assert!(
            ids_in.contains(&expected),
            "t26: {expected} 应在 poll 结果中"
        );
    }

    store.shutdown().await?;
    Ok(())
}

/// t27：dlx 队头阻塞 partition，re-drive 后恢复。
///
/// append H, S2 同 partition；强制 H→dlx；poll 该 partition 空；
/// re-drive H → relay → published → poll → S2。
/// 反真空：NULL-partition dlx 行不阻塞任何东西。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t27_dlx_head_blocks_then_unblocks() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t27");
    let key = PartitionKey::parse("part-dlx").unwrap();

    let h_id = unique_event_id("t27-H");
    let s2_id = unique_event_id("t27-S2");

    // append H, S2 同 (domain, 'part-dlx')。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 强制 H → dlx（直接 UPDATE status）。
    sqlx::query("UPDATE outbox SET status = $1 WHERE event_id = $2")
        .bind(STATUS_DLX)
        .bind(&h_id)
        .execute(&store.pool)
        .await?;

    // poll → 该 partition 空（H 在 dlx，S2 被 gate）。
    let outbox = make_pg_outbox(&store, || Ok(()));
    let blocked = outbox.poll_pending(&domain, 10).await?;
    assert!(
        blocked.is_empty(),
        "t27: dlx 队头必须完全阻塞 partition（blocked={blocked:?}）"
    );

    // 反真空：NULL-partition dlx 行不阻塞任何东西。
    let null_dlx_id = unique_event_id("t27-null-dlx");
    let null_live_id = unique_event_id("t27-null-live");
    for eid in [&null_dlx_id, &null_live_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c"); // no partition
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }
    sqlx::query("UPDATE outbox SET status = $1 WHERE event_id = $2")
        .bind(STATUS_DLX)
        .bind(&null_dlx_id)
        .execute(&store.pool)
        .await?;

    let after_null_dlx = outbox.poll_pending(&domain, 10).await?;
    assert!(
        after_null_dlx
            .iter()
            .any(|e| e.idem_key().as_str() == null_live_id),
        "t27: NULL-partition dlx 不阻塞 null_live 行（反真空）"
    );

    // re-drive H：把 H 从 dlx 重置回 pending。
    sqlx::query(
        "UPDATE outbox SET status = 'pending', retry_count = 0, retry_after = NULL WHERE event_id = $1",
    )
    .bind(&h_id)
    .execute(&store.pool)
    .await?;

    // relay H → published。
    let redriven = outbox.poll_pending(&domain, 10).await?;
    let h_entry = redriven
        .iter()
        .find(|e| e.idem_key().as_str() == h_id)
        .expect("t27: re-drive 后 H 应出现在 poll 结果中");
    let disp = outbox.relay(h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t27: relay H 应返 Ack");

    // poll → S2 现在可见。
    let unblocked = outbox.poll_pending(&domain, 10).await?;
    assert!(
        unblocked.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t27: H published 后 S2 应解除阻塞"
    );

    store.shutdown().await?;
    Ok(())
}

/// t28：crash recovery 保持 partition 顺序（stale publishing 头 gate 后继）。
///
/// append H, S2 同 partition；置 H status='publishing', updated_at 很久之前（模拟崩溃）；
/// poll → 仅 H（stale publishing 被重捞，S2 被 gate）；relay H→published → poll → S2。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t28_crash_recovery_preserves_partition_order() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t28");
    let key = PartitionKey::parse("part-crash").unwrap();

    let h_id = unique_event_id("t28-H");
    let s2_id = unique_event_id("t28-S2");

    // append H, S2 同 partition。
    for eid in [&h_id, &s2_id] {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    // 模拟 H 崩溃：status=publishing, updated_at 回拨超 LEASE_TTL。
    sqlx::query(
        "UPDATE outbox SET status='publishing', updated_at = now() - make_interval(secs => $1) WHERE event_id = $2",
    )
    .bind(LEASE_TTL_SECONDS + 10)
    .bind(&h_id)
    .execute(&store.pool)
    .await?;

    let (pub_ok, _) = RecordingPublisher::always_ok();
    let outbox = PgOutbox::new(&store, DynPublisher::new_box(pub_ok));

    // poll → 仅 H（stale publishing 可捞，S2 被 gate）。
    let entries = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries.len(), 1, "t28: crash recovery 仅应返回 H");
    assert_eq!(entries[0].idem_key().as_str(), h_id, "t28: 返回的必须是 H");
    assert!(
        !entries.iter().any(|e| e.idem_key().as_str() == s2_id),
        "t28: S2 被 stale-publishing H gate，不应出现"
    );

    // relay H → published。
    let h_entry = entries.into_iter().next().unwrap();
    let disp = outbox.relay(&h_entry).await?;
    assert_eq!(disp, Disposition::Ack, "t28: relay H 应返 Ack");

    // poll → S2（H published 后解锁）。
    let entries2 = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(entries2.len(), 1, "t28: 第二轮 poll 应仅返 S2");
    assert_eq!(
        entries2[0].idem_key().as_str(),
        s2_id,
        "t28: 第二轮 poll 必须是 S2"
    );

    store.shutdown().await?;
    Ok(())
}

/// t29：sample_backlog 计入 gated 后继（backlog poll-only by design）。
///
/// H + 3 后继同 partition → `sample_backlog.depth()==4`（gate 不减 depth）；
/// `poll_pending` 返 1（仅队头）。
/// INVARIANT: OUTBOX-PARTITION-ORDER-01
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out。
async fn t29_sample_backlog_counts_gated_successors() -> TestResult {
    use consistency::PartitionKey;

    let (_pg, store) = connect_pg().await?;
    setup_outbox(&store).await?;

    let domain = unique_domain("t29");
    let key = PartitionKey::parse("part-backlog").unwrap();

    // append H + 3 后继同 partition。
    let ids: Vec<_> = (0..4)
        .map(|i| unique_event_id(&format!("t29-{i}")))
        .collect();
    for eid in &ids {
        let entry = make_entry(eid);
        let env = make_test_env(&domain, "c").with_partition_key_opt(Some(key.clone()));
        store
            .run_in_transaction::<_, _, sqlx::Error>(|c| {
                let entry = entry.clone();
                Box::pin(async move {
                    append_outbox(c, &entry, &env).await?;
                    Ok(())
                }) as BoxFuture<'_, Result<(), sqlx::Error>>
            })
            .await?;
    }

    let outbox = make_pg_outbox(&store, || Ok(()));

    // sample_backlog depth = 4（全部计入，gate 不减少 backlog 深度）。
    let sample = outbox.sample_backlog(&domain).await?;
    assert_eq!(
        sample.depth(),
        4,
        "t29: backlog depth 应计入所有 4 行（含 gated 后继），实际={}",
        sample.depth()
    );
    assert_eq!(
        sample.oldest_age_seconds(),
        0,
        "t29: fresh rows，gate 不扭曲 age（age 应为 0 秒），实际={}",
        sample.oldest_age_seconds()
    );

    // poll_pending 仅返 1（队头）——反真空：gate 确实生效。
    let polled = outbox.poll_pending(&domain, 10).await?;
    assert_eq!(
        polled.len(),
        1,
        "t29: poll_pending 应仅返队头（1 行），gate 生效"
    );
    assert_eq!(
        polled[0].idem_key().as_str(),
        ids[0],
        "t29: poll_pending 返回的必须是 H（最小 seq 的队头）"
    );

    store.shutdown().await?;
    Ok(())
}

/// t30：partition_key 经**真实 public port** `OutboxEnvelopeParts::with_partition_key` → `PgEmitter::emit`
/// 落库（F5，#1211 review）。t24-t29 直调 adapter-private `OutboxEnvelope::with_partition_key_opt` 验 gating；
/// 本用例补最易漏接的 **public port → adapter envelope 映射层**：经 `PgEmitter::emit` 写入后 `SELECT
/// partition_key` 应等于传入 key（证 `into_parts` → `with_partition_key_opt` → INSERT $8 全链路透传）。
#[tokio::test]
#[allow(clippy::unwrap_used)]
// reason: 集成测试构造已知合法输入，item-level carve-out。
async fn t30_with_partition_key_persists_via_real_emit_port() -> TestResult {
    use consistency::PartitionKey;
    use diport::{OutboxEmitter, OutboxEnvelopeParts};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let event_id = unique_event_id("t30-pk-port");
    let entry = Entry::new(
        Topic::parse(SESSION_CREATED_TOPIC).unwrap(),
        IdemKey::parse(&event_id).unwrap(),
        br#"{"sessionId":"s"}"#.to_vec(),
    );
    // tenant-scoped key（推荐形态 <tenantId>:<aggregateId>）经 public builder 传入。
    let pk = "tenant-7:session-42";
    crate::PgEmitter::new(&store, fixed_clock())
        .emit(
            entry,
            OutboxEnvelopeParts::new(
                vocab::ContractBinding::from_static("identity", SESSION_CREATED_TOPIC),
                test_tenant(),
                "subj-opaque-30",
            )
            .with_partition_key(PartitionKey::parse(pk).unwrap()),
        )
        .await?;

    let row: (Option<String>,) =
        sqlx::query_as("SELECT partition_key FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        row.0.as_deref(),
        Some(pk),
        "t30: public port with_partition_key 应经 into_parts → adapter envelope → INSERT 透传落库"
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
    // → session INSERT 失败，驱动真实 `PgSessionLifecycle` 的 `write_session_and_outbox`→Err→rollback 分支。
    let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(10_000_000_000_000);
    let session =
        identity::test_support::session(&session_id, "subj-opaque-cotx", tenant, expires, created);

    let result = crate::PgSessionLifecycle::new(&store, fixed_clock())
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

// ── T20–T22: PgSessionLifecycle durable find/revoke（合并端口后完整生命周期，#1278；原 #1116）──────────
//
// 第二租户（跨租隔离 t22）——与 config/secret 测试 TENANT_B 同值。
const COTX_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

/// t20：persist → `find` 命中，重建 session 字段（subject/tenant/时刻）与持久化一致。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t20_find_returns_persisted_session() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t15-sess");
    let event_id = unique_event_id("t15-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-find", tenant, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
        .await?;

    // find 命中：经 Session::hydrate 重建，字段（含 epoch 时刻 roundtrip）与持久化一致。
    let s = lifecycle
        .find(tenant, sid)
        .await?
        .expect("persisted session should be found");
    assert_eq!(s.id().as_str(), session_id, "session_id roundtrip");
    assert_eq!(s.subject(), "subj-find", "subject roundtrip");
    assert_eq!(s.tenant(), tenant, "tenant roundtrip");
    assert_eq!(s.expires_at(), expires, "expires_at epoch roundtrip");
    assert_eq!(s.created_at(), created, "created_at epoch roundtrip");

    store.shutdown().await?;
    Ok(())
}

/// t21：`revoke` → `find` 返回 None（软撤销）；重复 / 未知 sid revoke 仍 Ok（幂等）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t21_revoke_soft_deletes_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t16-sess");
    let event_id = unique_event_id("t16-evt");
    let tenant = TenantId::parse(COTX_TENANT_A).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-revoke", tenant, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
        .await?;
    assert!(
        lifecycle.find(tenant, sid.clone()).await?.is_some(),
        "revoke 前应能 find 到"
    );

    // 软撤销 → find None（行仍在、revoked=true）。
    lifecycle.revoke(tenant, sid.clone()).await?;
    assert!(
        lifecycle.find(tenant, sid.clone()).await?.is_none(),
        "revoke 后 find 应 None"
    );
    let row_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
        .bind(&session_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(row_cnt.0, 1, "软撤销不删行（行仍在、revoked=true）");

    // 幂等：重复 revoke + 未知 sid revoke 均 Ok。
    lifecycle.revoke(tenant, sid).await?;
    let ghost = identity::test_support::session(
        &unique_event_id("t16-ghost"),
        "x",
        tenant,
        expires,
        created,
    );
    lifecycle.revoke(tenant, ghost.id().clone()).await?;

    store.shutdown().await?;
    Ok(())
}

/// t22：跨租 revoke no-op（不撤销他租会话）+ 跨租 find None；同租 revoke 生效。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
async fn t22_cross_tenant_revoke_and_find_isolated() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t17-sess");
    let event_id = unique_event_id("t17-evt");
    let tenant_a = TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = TenantId::parse(COTX_TENANT_B).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-iso", tenant_a, expires, created);
    let sid = session.id().clone();

    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());
    lifecycle
        .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
        .await?;

    // 跨租 find（tenant B 查 tenant A sid）→ None（不泄露存在性）。
    assert!(
        lifecycle.find(tenant_b, sid.clone()).await?.is_none(),
        "跨租 find 应 None"
    );
    // 跨租 revoke（tenant B）→ no-op：tenant A 会话仍 find 到。
    lifecycle.revoke(tenant_b, sid.clone()).await?;
    assert!(
        lifecycle.find(tenant_a, sid.clone()).await?.is_some(),
        "跨租 revoke 不应撤销 tenant A 的会话"
    );
    // 同租 revoke → find None（隔离正确、撤销生效）。
    lifecycle.revoke(tenant_a, sid.clone()).await?;
    assert!(
        lifecycle.find(tenant_a, sid).await?.is_none(),
        "同租 revoke 后 find 应 None"
    );

    store.shutdown().await?;
    Ok(())
}

/// t22b：`PgSessionLifecycle` 接入 tenant no-op conformance：跨租 find 不可见、跨租 revoke 不影响 owner。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn t22b_session_lifecycle_tenant_noop_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let session_id = unique_event_id("t22b-sess");
    let event_id = unique_event_id("t22b-evt");
    let tenant_a = TenantId::parse(COTX_TENANT_A).unwrap();
    let tenant_b = TenantId::parse(COTX_TENANT_B).unwrap();
    let created = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = created + Duration::from_secs(3_600);
    let session =
        identity::test_support::session(&session_id, "subj-iso", tenant_a, expires, created);
    let sid = session.id().clone();
    let lifecycle = crate::PgSessionLifecycle::new(&store, fixed_clock());

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            lifecycle
                .persist_session_and_emit(session, session_entry(&event_id), session_envelope())
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle.find(tenant_a, sid.clone()).await?.is_some(),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle.find(tenant_b, sid.clone()).await?.is_some(),
            )
        },
        || async {
            lifecycle.revoke(tenant_b, sid.clone()).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                lifecycle.find(tenant_a, sid.clone()).await?.is_some(),
            )
        },
    )
    .await?;

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
    OutboxEnvelopeParts::new(
        vocab::ContractBinding::from_static("settings", CONFIG_VERSION_CHANGED_TOPIC),
        config_tenant(),
        subject,
    )
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
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
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

/// tc1b：经 `settings_bundle` funnel 解包的 `DynConfigRepo` 在真实 DB 上 save→find 闭合——验证 bundle
/// 预包装的 config 读写路径（非散装 `PgConfigRepo::new`）端到端可用（PG-BUNDLE-SETTINGS-04 集成覆盖，#1424）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1b_bundle_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // 经 funnel：PgRuntimeDeps → for_domain::<Settings> → settings_bundle → into_parts（取 read config box）。
    let deps = crate::PgRuntimeDeps::from_store_for_test(std::sync::Arc::new(store));
    let (configs, _writer, _secrets) = deps
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc())
        .into_parts();
    let tenant = config_tenant();
    let key = SettingKey::parse("bundle.timeout").unwrap();

    assert!(configs.find(tenant, &key).await?.is_none(), "未写入 → None");
    configs
        .save(tenant, config_entry("bundle.timeout", "30s", 1))
        .await?;
    let found = configs.find(tenant, &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "bundle DynConfigRepo find 取回值");
    assert_eq!(found.version(), 1, "bundle DynConfigRepo find 取回版本");
    Ok(())
}

/// tc1c：经 `settings_bundle` funnel 解包的 `writer`（`DynConfigUnitOfWork`）在真实 DB 上 `save_and_append_outbox`
/// co-tx 落 config 行 + outbox 行 + 构造期注入 occurred_at——证 bundle write lane 与 direct co-tx（tc5）语义等价
/// （F2，#1424；补 tc1b 只覆盖 read lane 的缺口）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1c_bundle_writer_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // store 即将移入 deps（PG-BUNDLE-POOL-03 无 pool accessor）→ 先 clone pool 供验证查询。
    let pool = store.pool.clone();
    let deps = crate::PgRuntimeDeps::from_store_for_test(std::sync::Arc::new(store));
    let (_configs, writer, _secrets) = deps
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc())
        .into_parts();
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc1c-evt");

    writer
        .save_and_append_outbox(
            tenant,
            config_entry("bundle.cotx", "v1", 1),
            config_outbox_entry(&event_id),
            config_envelope("bundle.cotx"),
        )
        .await?;

    // config 行 + outbox 行 co-tx 两行皆在（tenant-correct）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("bundle.cotx")
    .fetch_one(&pool)
    .await?;
    assert_eq!(crow.0, 1, "bundle writer：config 行应写入");
    assert_eq!(crow.1, CONFIG_TENANT, "bundle writer：config 行 tenant_id");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 1,
        "bundle writer：outbox 行应写入（co-tx 两行皆在）"
    );
    // occurred_at 来自 bundle 构造期注入的 Arc clock（write lane 经 save_and_append_outbox 用）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "bundle writer co-tx outbox metadata 应含注入 clock 的 occurred_at: {}",
        cfg_meta.0
    );
    Ok(())
}

/// tc2：版本历史——find = max(version)；find_version 取精确历史版本；缺失版本 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc2_config_find_version_returns_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
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
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_versioned_cas_repo(
        "v1".to_string(),
        "v1b".to_string(),
        "v3".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(tenant, config_entry("app.k", &marker, version))
                    .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(tenant, key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc4：delete 软删（tombstone）——find 返 None；历史值行**保留**（find_version 可读）；幂等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4_config_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tombstone_repo(
        "v1".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(tenant, config_entry("app.k", &marker, version))
                    .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.delete(tenant, key).await }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(tenant, key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |version| {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find_version(tenant, key, version)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.latest_version(tenant, key).await }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc5：co-tx commit → config 行 + outbox 行皆在（OUTBOX-COTX-CONFIG-01 正向）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5_config_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
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
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
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

/// tc5b：config 事务 tenant 与 envelope tenant 不一致 → fail-closed，config / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5b_config_cotx_rejects_envelope_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5b-evt");
    let envelope = OutboxEnvelopeParts::new(
        vocab::ContractBinding::from_static("settings", CONFIG_VERSION_CHANGED_TOPIC),
        TenantId::parse(CONFIG_TENANT_B).unwrap(),
        "app.mismatch",
    );

    let result = repo
        .save_and_append_outbox(
            tenant,
            config_entry("app.mismatch", "v1", 1),
            config_outbox_entry(&event_id),
            envelope,
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "config/envelope tenant mismatch must fail closed as storage boundary error"
    );

    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.mismatch")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "mismatch 不得写 config 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "mismatch 不得写 outbox 行");

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
    let event_id = unique_event_id("cfg-tc6-evt");
    let entry = config_outbox_entry(&event_id);
    let env = OutboxEnvelope::new(
        "settings".to_string(),
        CONFIG_VERSION_CHANGED_TOPIC.to_string(),
        OutboxMetadata::new(0, test_tenant()).with_subject_id("app.rollback".to_string()),
    );

    // 业务写：真插一行 config（成功）后强制 Err（模拟「配置写后、后续步骤失败」= emit/commit 失败等价物）。
    let result = co_tx_with_outbox(
        &store.pool,
        tenant,
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
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
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

/// tc7b：`PgConfigRepo` 接入 L2 co-tx conformance：commit 两边皆在；业务失败两边皆无；CAS 冲突无 outbox。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7b_config_cotx_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant = config_tenant();
    let ok_event = unique_event_id("cfg-tc7b-ok");
    let rollback_event = unique_event_id("cfg-tc7b-rollback");
    let conflict_event = unique_event_id("cfg-tc7b-conflict");

    repo.save(tenant, config_entry("app.cotx-conflict", "v1", 1))
        .await?;

    testkit::repo_conformance::assert_cotx_both_or_neither(
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.save_and_append_outbox(
                    tenant,
                    config_entry("app.cotx-ok", "v1", 1),
                    config_outbox_entry(&ok_event),
                    config_envelope("app.cotx-ok"),
                )
                .await
            },
            business_exists: || async {
                let cnt: (i64,) = sqlx::query_as(
                    "SELECT count(*) FROM config_entries WHERE config_key = $1 AND value = $2",
                )
                .bind("app.cotx-ok")
                .bind("v1")
                .fetch_one(&store.pool)
                .await
                .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&ok_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                let entry = config_outbox_entry(&rollback_event);
                let env = OutboxEnvelope::new(
                    "settings".to_string(),
                    CONFIG_VERSION_CHANGED_TOPIC.to_string(),
                    OutboxMetadata::new(0, test_tenant())
                        .with_subject_id("app.cotx-rollback".to_string()),
                );
                co_tx_with_outbox(
                    &store.pool,
                    tenant,
                    &entry,
                    &env,
                    move |conn| {
                        Box::pin(async move {
                            sqlx::query(
                                "INSERT INTO config_entries (tenant_id, config_key, version, value) \
                                 VALUES ($1::uuid, $2, $3, $4)",
                            )
                            .bind(CONFIG_TENANT)
                            .bind("app.cotx-rollback")
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
                .await
            },
            business_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind("app.cotx-rollback")
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&rollback_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.save_and_append_outbox(
                    tenant,
                    config_entry("app.cotx-conflict", "stale", 1),
                    config_outbox_entry(&conflict_event),
                    config_envelope("app.cotx-conflict"),
                )
                .await
            },
            business_exists: || async {
                let cnt: (i64,) = sqlx::query_as(
                    "SELECT count(*) FROM config_entries WHERE config_key = $1 AND value = $2",
                )
                .bind("app.cotx-conflict")
                .bind("stale")
                .fetch_one(&store.pool)
                .await
                .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
            outbox_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                        .bind(&conflict_event)
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc8：storage 错误通道——关池后 find 返回 `ConfigRepoError::Storage`（基础设施错误分层映射，保留 source）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc8_config_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(tenant, &key).await.map(|_| ()) },
        |e| matches!(e, ConfigRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// tc9：**跨租户隔离**——tenant A 的配置对 tenant B 不可见，独立版本空间，delete 互不影响。
///
/// tc9 以 owner/superuser 连接（绕过 RLS）验证显式 `WHERE tenant_id` 子句隔离；0009 落地后
/// config_entries 已有 RLS policy，DB 层 RLS 强制力由 t21（rss_app 角色）专门覆盖，二者互补
/// （in-mem 路径由 `application.rs::cross_tenant_isolation` 守，实现不同）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9_config_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tenant_scoped_repo(
        testkit::repo_conformance::TenantScopedCase {
            tenant_a,
            tenant_b,
            a_marker: "a-secret".to_string(),
            b_marker: "b-value".to_string(),
            save: |tenant, version, marker: String| {
                let repo = &repo;
                async move {
                    repo.save(
                        tenant,
                        ConfigEntry::hydrate(
                            SettingKey::parse("app.k").unwrap(),
                            &marker,
                            tenant,
                            version,
                        ),
                    )
                    .await
                }
            },
            delete: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.delete(tenant, key).await }
            },
            current: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find(tenant, key)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            history: |tenant, version| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find_version(tenant, key, version)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            latest_version: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.latest_version(tenant, key).await }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc9b：`PgConfigRepo` 接入 #1437 最小 tenant-scope **conformance 骨架**（#1426 种子的首个 enroll
/// 消费方 + anti-vacuity 真实 repo 驱动）：round-trip / 跨租不可见 / 跨租不干扰 三断言一次过。
/// 与 tc9（手写逐断言）互补——本测试证骨架对真实 RLS-scoped repo 可用，#1426 在骨架上扩 CAS/rollback 等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9b_config_repo_tenant_isolation_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.conformance").unwrap();

    testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |t| {
            let repo = &repo;
            async move {
                let entry =
                    ConfigEntry::hydrate(SettingKey::parse("app.conformance").unwrap(), "v1", t, 1);
                repo.save(t, entry).await
            }
        },
        |t| {
            let repo = &repo;
            let key = &key;
            async move { repo.find(t, key).await.map(|o| o.is_some()) }
        },
    )
    .await?;

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
    let repo = PgConfigRepo::new(&store, fixed_clock_arc());
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

// ── PgSecretRepo：secret 引用坐标仓储集成测试（#1274）──────────────────────────
//
// ts1:  save → find round-trip（全字段回环）
// ts1b: ref_version=None round-trip
// ts2:  find_version 历史（精确版本）
// ts3:  CAS 冲突（陈旧 + 跳版 → VersionConflict；恰 max+1 成功）
// ts4:  delete tombstone + 幂等（latest_version 含 tombstone；历史行保留；不存在 key → no-op）
// ts5:  storage 错误通道（关池 → SecretRepoError::Storage）
// ts6:  跨租户隔离（find / find_version / delete 互不影响）
// ts7:  delete + republish 版本不重置（version 单调）
// ts8:  material-never-persisted 断言（information_schema.columns 列集校验）

use settings::ports::{SecretEntry, SecretKey, SecretRepo, SecretRepoError, StoreId};

use crate::PgSecretRepo;

/// secret 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值）。
const SECRET_TENANT_A: &str = COTX_TENANT_A;
/// 第二租户（跨租户隔离 ts6）。
const SECRET_TENANT_B: &str = CONFIG_TENANT_B;

/// setup：应用 migration（含 secret_refs 表），清空 secret_refs（防测试间污染）。
async fn setup_secret(store: &PgStore) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM secret_refs")
        .execute(&store.pool)
        .await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
fn secret_tenant_a() -> TenantId {
    TenantId::parse(SECRET_TENANT_A).unwrap()
}

/// 构造 SecretEntry（经 `SecretEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
fn make_secret_entry(
    key: &str,
    store_id: &str,
    ref_key: &str,
    ref_version: Option<&str>,
    version: u64,
    tenant: TenantId,
) -> SecretEntry {
    SecretEntry::hydrate(
        SecretKey::parse(key).unwrap(),
        StoreId::parse(store_id).unwrap(),
        ref_key,
        ref_version.map(|s| s.to_string()),
        tenant,
        version,
    )
}

/// ts1：save → find round-trip（store_id / ref_key / ref_version / version / tenant 全字段正确）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts1_secret_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.db-password").unwrap();

    // 未写入 → None。
    assert!(repo.find(tenant, &key).await?.is_none(), "未写入 → None");

    repo.save(
        tenant,
        make_secret_entry(
            "myapp.db-password",
            "vault",
            "secret/data/myapp",
            Some("v2"),
            1,
            tenant,
        ),
    )
    .await?;

    let found = repo.find(tenant, &key).await?.unwrap();
    assert_eq!(found.key().as_str(), "myapp.db-password", "key 回环");
    assert_eq!(
        found.secret_ref().store_id().as_str(),
        "vault",
        "store_id 回环"
    );
    assert_eq!(
        found.secret_ref().ref_key(),
        "secret/data/myapp",
        "ref_key 回环"
    );
    assert_eq!(
        found.secret_ref().ref_version(),
        Some("v2"),
        "ref_version 回环"
    );
    assert_eq!(found.version(), 1, "version 回环");
    assert_eq!(found.tenant(), tenant, "tenant 回环（tenant-correct）");

    store.shutdown().await?;
    Ok(())
}

/// ts1b：ref_version=None（NULL=latest）round-trip。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts1b_secret_save_find_ref_version_null() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();

    repo.save(
        tenant,
        make_secret_entry(
            "myapp.api-key",
            "k8s-secrets",
            "ns/my-secret",
            None,
            1,
            tenant,
        ),
    )
    .await?;

    let found = repo
        .find(tenant, &SecretKey::parse("myapp.api-key").unwrap())
        .await?
        .unwrap();
    assert_eq!(
        found.secret_ref().ref_version(),
        None,
        "ref_version=None 回环"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts2：find_version 历史（精确版本；缺失版本 → None）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts2_secret_find_version_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.db-pass").unwrap();

    repo.save(
        tenant,
        make_secret_entry("myapp.db-pass", "vault", "secret/v1", None, 1, tenant),
    )
    .await?;
    repo.save(
        tenant,
        make_secret_entry(
            "myapp.db-pass",
            "vault",
            "secret/v2",
            Some("rev-2"),
            2,
            tenant,
        ),
    )
    .await?;

    // find 取最高版本。
    let latest = repo.find(tenant, &key).await?.unwrap();
    assert_eq!(latest.version(), 2, "find = max version");
    assert_eq!(latest.secret_ref().ref_key(), "secret/v2");

    // find_version 精确历史。
    let v1 = repo.find_version(tenant, &key, 1).await?.unwrap();
    assert_eq!(v1.secret_ref().ref_key(), "secret/v1", "find_version(1)");
    let v2 = repo.find_version(tenant, &key, 2).await?.unwrap();
    assert_eq!(
        v2.secret_ref().ref_version(),
        Some("rev-2"),
        "find_version(2)"
    );

    // 缺失版本 → None。
    assert!(
        repo.find_version(tenant, &key, 9).await?.is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts3：CAS——陈旧版本与跳版均 VersionConflict；恰 max+1 成功。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts3_secret_save_cas_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.token").unwrap();

    testkit::repo_conformance::assert_versioned_cas_repo(
        "secret/tok".to_string(),
        "secret/tok-b".to_string(),
        "secret/tok-c".to_string(),
        "secret/tok-v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(
                    tenant,
                    make_secret_entry("myapp.token", "vault", &marker, None, version, tenant),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(tenant, key)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        |e| matches!(e, SecretRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// ts4：delete tombstone + 幂等（find → None；latest_version 含 tombstone；历史行保留；再删 no-op；
/// 不存在 key → no-op）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts4_secret_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.cred").unwrap();

    testkit::repo_conformance::assert_tombstone_repo(
        "secret/cred".to_string(),
        "secret/cred-v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.save(
                    tenant,
                    make_secret_entry("myapp.cred", "vault", &marker, None, version, tenant),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.delete(tenant, key).await }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(tenant, key)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        |version| {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find_version(tenant, key, version)
                    .await
                    .map(|entry| entry.map(|entry| entry.secret_ref().ref_key().to_string()))
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.latest_version(tenant, key).await }
        },
    )
    .await?;

    // 不存在 key → no-op（无 panic / 无错误）。
    let phantom = SecretKey::parse("myapp.nonexistent").unwrap();
    repo.delete(tenant, &phantom).await?;

    store.shutdown().await?;
    Ok(())
}

/// ts5：storage 错误通道——关池后 find 返回 `SecretRepoError::Storage`（基础设施错误分层映射）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts5_secret_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(tenant, &key).await.map(|_| ()) },
        |e| matches!(e, SecretRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// ts6：跨租户隔离——tenant A 的 secret 对 tenant B 不可见；各自独立版本空间；delete 互不影响。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts6_secret_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant_a = secret_tenant_a();
    let tenant_b = TenantId::parse(SECRET_TENANT_B).unwrap();
    let key = SecretKey::parse("shared.key").unwrap();

    testkit::repo_conformance::assert_tenant_scoped_repo(
        testkit::repo_conformance::TenantScopedCase {
            tenant_a,
            tenant_b,
            a_marker: "vault-a".to_string(),
            b_marker: "vault-b".to_string(),
            save: |tenant, version, marker: String| {
                let repo = &repo;
                async move {
                    repo.save(
                        tenant,
                        make_secret_entry(
                            "shared.key",
                            &marker,
                            "secret/ref",
                            None,
                            version,
                            tenant,
                        ),
                    )
                    .await
                }
            },
            delete: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.delete(tenant, key).await }
            },
            current: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find(tenant, key).await.map(|entry| {
                        entry.map(|entry| entry.secret_ref().store_id().as_str().to_string())
                    })
                }
            },
            history: |tenant, version| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find_version(tenant, key, version).await.map(|entry| {
                        entry.map(|entry| entry.secret_ref().store_id().as_str().to_string())
                    })
                }
            },
            latest_version: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.latest_version(tenant, key).await }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// ts7：delete + republish 版本不重置——delete 软删后 republish 取 latest_version+1（非重置回 1）。
///
/// 对标 tc10 config 同款回归防护：tombstone 使 version 单调，防止版本号复用。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts7_secret_delete_republish_version_not_reset() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = PgSecretRepo::new(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.rotate-key").unwrap();

    // 写 v1。
    repo.save(
        tenant,
        make_secret_entry(
            "myapp.rotate-key",
            "vault",
            "secret/rotate",
            None,
            1,
            tenant,
        ),
    )
    .await?;

    // delete → tombstone v2。
    repo.delete(tenant, &key).await?;
    assert_eq!(
        repo.latest_version(tenant, &key).await?,
        Some(2),
        "tombstone v2"
    );

    // republish：下一版本 = latest+1 = 3（不是重置回 1）。
    let next = repo
        .latest_version(tenant, &key)
        .await?
        .map_or(1, |v| v + 1);
    assert_eq!(next, 3, "delete 软删后下一版本 = 3，不重置回 1");

    repo.save(
        tenant,
        make_secret_entry(
            "myapp.rotate-key",
            "vault",
            "secret/rotate-new",
            Some("v3"),
            next,
            tenant,
        ),
    )
    .await?;

    // 活跃值恢复，版本 = 3。
    let active = repo.find(tenant, &key).await?.unwrap();
    assert_eq!(active.version(), 3, "republish 后版本 = 3");
    assert_eq!(active.secret_ref().ref_key(), "secret/rotate-new");

    store.shutdown().await?;
    Ok(())
}

/// ts8：material-never-persisted 断言——`information_schema.columns` 校验 secret_refs 列集
/// 恰为 {created_at, deleted, ref_key, ref_version, secret_key, store_id, tenant_id, version}，
/// 无任何 secret 材料列（review-critical）。
#[tokio::test(flavor = "multi_thread")]
async fn ts8_secret_refs_table_has_no_material_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 从 information_schema.columns 取 secret_refs 的全部列名（ORDER BY 确定顺序）。
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'secret_refs' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;

    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    // 期望的列集（字母序排列后）：坐标列 + 版本标记列，无任何材料列。
    let expected = [
        "created_at",
        "deleted",
        "ref_key",
        "ref_version",
        "secret_key",
        "store_id",
        "tenant_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "secret_refs 列集应恰为坐标列（无材料列），实际：{cols:?}"
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
#[allow(clippy::expect_used)]
// reason: 已保存/upserted role 必定可查到；集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
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
#[allow(clippy::expect_used)]
// reason: 同租 find 必定可见（anti-vacuity 正例）；item-level carve-out（error-handling.md §Carve-out）。
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: tokio::spawn join 必定成功（task 正常 Ok）；converged role 必定可查到；item-level carve-out（error-handling.md §Carve-out）。
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

// ── T20–T23: RLS 强制力证明（#1298）────────────────────────────────────────────
//
// 0009 迁移落地 ENABLE ROW LEVEL SECURITY + FORCE ROW LEVEL SECURITY + tenant_isolation policy（四表：
// sessions / config_entries / roles / secret_refs）+ rss_app serving role；本组测试以 SET LOCAL ROLE
// rss_app 切换到非 owner 角色，验证 RLS 对 rss_app 生效（superuser 永远绕过 RLS，不适合做验证角色）。
//
// 测试结构：
//   • Tx1（rss_app + tenant_a scope）：INSERT tenant_a 行 → 成功（WITH CHECK pass）。
//   • Tx2（rss_app + tenant_a scope）：SELECT → tenant_a 行可见（USING pass）。
//   • Tx3（rss_app + tenant_b scope）：SELECT 同行 → 不可见（USING 过滤，跨租读被阻）。
//   • Tx4（rss_app + tenant_a scope）：INSERT tenant_b 行 → 错误（WITH CHECK 拒绝，跨租写被阻）。
//
// 前置：`GRANT rss_app TO CURRENT_USER`——testcontainer 连接角色（superuser）需先 member of rss_app
// 才能执行 `SET LOCAL ROLE rss_app`；幂等，不影响后续 superuser 权限。

/// T20：RLS 强制力证明 — sessions 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 和固定 UUID 格式化不会失败；函数级 item-level carve-out。
async fn t20_rls_sessions_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let session_a = uuid::Uuid::new_v4().to_string();

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a session → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at) \
             VALUES ($1, $2, $3::uuid, now() + interval '1 hour', now())",
        )
        .bind(&session_a)
        .bind("rls-test-subject")
        .bind(&tenant_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a session failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT session_a → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 1,
            "t20: rss_app + tenant_a scope — session_a 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT session_a → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions WHERE session_id = $1")
            .bind(&session_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + tenant_b scope — session_a 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b session → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at) \
             VALUES ($1, $2, $3::uuid, now() + interval '1 hour', now())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("rls-test-subject")
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t20: WITH CHECK 应拒绝 tenant_b 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT sessions → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t20: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T21：RLS 强制力证明 — config_entries 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t21_rls_config_entries_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let cfg_key = format!("rls.test.key.{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT config_entry → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO config_entries (tenant_id, config_key, version, value) \
             VALUES ($1::uuid, $2, 1, $3)",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .bind("rls-test-value")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a config failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
        )
        .bind(&tenant_a)
        .bind(&cfg_key)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t21: rss_app + tenant_a scope — config_entry 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 key → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + tenant_b scope — tenant_a config_entry 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b config → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO config_entries (tenant_id, config_key, version, value) \
             VALUES ($1::uuid, $2, 1, $3)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{cfg_key}.cross"))
        .bind("cross-tenant-value")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t21: WITH CHECK 应拒绝 tenant_b config 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT config_entries → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                .bind(&cfg_key)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t21: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T22：RLS 强制力证明 — roles 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t22_rls_roles_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let role_id = format!("rls-role-{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT role → 成功。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO roles (tenant_id, id, name, permissions) \
             VALUES ($1::uuid, $2, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&role_id)
        .bind("RlsTestRole")
        .bind(vec!["docs:read".to_string()])
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a role failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM roles WHERE tenant_id = $1::uuid AND id = $2")
                .bind(&tenant_a)
                .bind(&role_id)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 1,
            "t22: rss_app + tenant_a scope — role 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 role_id → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + tenant_b scope — tenant_a role 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b role → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO roles (tenant_id, id, name, permissions) \
             VALUES ($1::uuid, $2, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{role_id}-cross"))
        .bind("CrossTenantRole")
        .bind(vec!["docs:read".to_string()])
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t22: WITH CHECK 应拒绝 tenant_b role 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT roles → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM roles WHERE id = $1")
            .bind(&role_id)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t22: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// T23：RLS 强制力证明 — secret_refs 表（#1298）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
/// 同 config_entries t21 范式（secret_refs 版本历史模型同 config_entries 0005 范式，#1298）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t23_secret_refs_rls_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    // 唯一 secret_key（防并发测试污染）。
    let secret_key = format!("rls.test.secret.{}", uuid::Uuid::new_v4());

    // Tx1：rss_app + tenant_a scope → INSERT secret_refs 行 → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
             VALUES ($1::uuid, $2, 1, $3, $4)",
        )
        .bind(&tenant_a)
        .bind(&secret_key)
        .bind("vault-a")
        .bind("secret/rls-test")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a secret_ref failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as(
            "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
        )
        .bind(&tenant_a)
        .bind(&secret_key)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(
            cnt.0, 1,
            "t23: rss_app + tenant_a scope — secret_ref 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同 key → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM secret_refs WHERE secret_key = $1")
            .bind(&secret_key)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t23: rss_app + tenant_b scope — tenant_a secret_ref 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b secret_ref → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
             VALUES ($1::uuid, $2, 1, $3, $4)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(format!("{secret_key}.cross"))
        .bind("vault-b")
        .bind("secret/cross-tenant")
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t23: WITH CHECK 应拒绝 tenant_b secret_ref 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT secret_refs → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM secret_refs WHERE secret_key = $1")
            .bind(&secret_key)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t23: rss_app + 未设 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── RT: PgRefreshTokenStore 集成验证（#1325）────────────────────────────────────
//
// 覆盖：insert→find_by_hash 往返；rotate CAS（Active→true, 再次 rotate same old→false）；
// rotate 后 old 变 consumed（find 仍可查到，status=consumed）；revoke_lineage 整条谱系变 revoked；
// 跨租隔离（tenant B 查 tenant A 的 hash → None）。

use identity::ports::{RefreshTokenStore, TenantId as RtTenantId};
use vocab::PrincipalKind;

use crate::PgRefreshTokenStore;

/// 构造测试用固定 hash（32 字节全 0xAB 填充，可识别但不冲突）。
fn test_hash_for(suffix: u8) -> [u8; 32] {
    [suffix; 32]
}

/// RT-1：insert → find_by_hash 往返——record 各字段正确重建。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；find_by_hash 结果必定 Some；集成测试 happy-path；item-level carve-out（error-handling.md §Carve-out）。
async fn rt1_insert_then_find_by_hash_roundtrip() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let lineage = id.clone(); // 签发根：lineage_id == id
    let hash_bytes = test_hash_for(0xA1);
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let expires = issued + Duration::from_secs(3_600);

    let record = RefreshTokenRecord::hydrate(
        id.clone(),
        tenant,
        "alice-subject",
        PrincipalKind::User,
        hash_bytes,
        None, // 签发根 parent_id = None
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    // RefreshTokenHash::new は pub(crate)——hydrate した record から clone して取り出す（外部 crate 直接构造不可）。
    let hash_to_find = record.token_hash().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(record).await?;

    let found = rt_store.find_by_hash(tenant, hash_to_find).await?;
    let found = found.expect("rt1: 应能按 hash 找到刚写入的 record");

    assert_eq!(found.id().as_str(), id, "rt1: id 往返");
    assert_eq!(found.subject(), "alice-subject", "rt1: subject 往返");
    assert_eq!(found.kind(), PrincipalKind::User, "rt1: kind 往返");
    assert_eq!(found.status(), RefreshStatus::Active, "rt1: status=active");
    assert!(found.parent_id().is_none(), "rt1: 签发根 parent_id=None");
    assert_eq!(found.lineage_id().as_str(), lineage, "rt1: lineage_id 往返");
    // 时间精度：epoch 秒往返，millisecond sub-second 被截断，断言到秒粒度。
    assert_eq!(
        found
            .issued_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        issued
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "rt1: issued_at 往返"
    );
    assert_eq!(
        found
            .expires_at()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expires
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "rt1: expires_at 往返"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-2：rotate CAS（Active → consumed + new 写入）返 true；再次 rotate 同 old → false（already consumed）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 已知合法值；old/new record 必定可查到；集成测试 happy-path；item-level carve-out。
async fn rt2_rotate_cas_active_then_consumed() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let old_id_str = uuid::Uuid::new_v4().to_string();
    let lineage_str = old_id_str.clone();
    let hash_old = test_hash_for(0xB1);
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_100_000);
    let expires = issued + Duration::from_secs(3_600);

    // 写入 old（Active）——clone id 和 hash 供后续调用（RefreshTokenId::new / RefreshTokenHash::new 是 pub(crate)）。
    let old_record = RefreshTokenRecord::hydrate(
        old_id_str.clone(),
        tenant,
        "bob",
        PrincipalKind::User,
        hash_old,
        None,
        lineage_str.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_old_typed = old_record.token_hash().clone();
    // sealed command: clone 源 record 供 begin_rotation（移动前保留引用，rotate 不再接受裸 id/record）。
    let old_for_rotate = old_record.clone();
    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(old_record).await?;

    // 构造 new record（rotation 子节点），clone hash 供后续 find 使用。
    let new_id_str = uuid::Uuid::new_v4().to_string();
    let hash_new = test_hash_for(0xB2);
    let new_record = RefreshTokenRecord::hydrate(
        new_id_str.clone(),
        tenant,
        "bob",
        PrincipalKind::User,
        hash_new,
        Some(old_id_str.clone()),
        lineage_str.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_new_typed = new_record.token_hash().clone();

    // 首次 rotate：old Active → CAS 命中 → true，new 已写入。
    // begin_rotation 从 old_for_rotate（同一 tenant）派生 sealed 命令（REFRESH-ROTATE-LINEAGE-01）。
    let rotation1 = old_for_rotate.begin_rotation(
        new_record.id().clone(),
        new_record.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let result = rt_store.rotate(rotation1).await?;
    assert!(result, "rt2: 首次 rotate 应返回 true（CAS 命中）");

    // 验证 old 变 consumed。
    let old_found = rt_store
        .find_by_hash(tenant, hash_old_typed)
        .await?
        .expect("rt2: old 仍可查到");
    assert_eq!(
        old_found.status(),
        RefreshStatus::Consumed,
        "rt2: old 应为 consumed"
    );

    // 验证 new 可查到且为 Active。
    let new_found = rt_store
        .find_by_hash(tenant, hash_new_typed)
        .await?
        .expect("rt2: new 应可查到");
    assert_eq!(
        new_found.status(),
        RefreshStatus::Active,
        "rt2: new 应为 active"
    );

    // 再次 rotate 同 old（已 consumed）→ CAS miss → false，new2 不写入。
    let new2_record = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "bob",
        PrincipalKind::User,
        test_hash_for(0xB3),
        Some(old_id_str.clone()),
        lineage_str.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let hash_new2_typed = new2_record.token_hash().clone();
    let rotation2 = old_for_rotate.begin_rotation(
        new2_record.id().clone(),
        new2_record.token_hash().clone(),
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let result2 = rt_store.rotate(rotation2).await?;
    assert!(
        !result2,
        "rt2: 再次 rotate consumed old 应返回 false（CAS miss）"
    );

    // new2 不应被写入。
    let new2_found = rt_store.find_by_hash(tenant, hash_new2_typed).await?;
    assert!(new2_found.is_none(), "rt2: CAS miss 时 new2 不应写入");

    store.shutdown().await?;
    Ok(())
}

/// RT-3：revoke_lineage 把整条谱系（multiple records）全部置 Revoked；幂等（再次调用也 Ok）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 已知合法值；revoked records 仍可按 hash 查到；集成测试 happy-path；item-level carve-out。
async fn rt3_revoke_lineage_revokes_all_and_is_idempotent() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let lineage_str = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_200_000);
    let expires = issued + Duration::from_secs(3_600);
    let rt_store = PgRefreshTokenStore::new(&store);

    // 插入同一 lineage 的两条记录（root + child）——clone 类型值供后续 revoke/find 使用。
    // RefreshTokenId::new / RefreshTokenHash::new 是 pub(crate)，从 hydrate 后的 record clone 取出。
    let root_id = uuid::Uuid::new_v4().to_string();
    let root_record = RefreshTokenRecord::hydrate(
        root_id.clone(),
        tenant,
        "carol",
        PrincipalKind::Admin,
        test_hash_for(0xC1),
        None,
        lineage_str.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let lineage_id = root_record.lineage_id().clone();
    let hash_root_typed = root_record.token_hash().clone();
    rt_store.insert(root_record).await?;

    let child_record = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "carol",
        PrincipalKind::Admin,
        test_hash_for(0xC2),
        Some(root_id.clone()),
        lineage_str.clone(),
        RefreshStatus::Consumed,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_child_typed = child_record.token_hash().clone();
    rt_store.insert(child_record).await?;

    // revoke_lineage → 整条谱系置 Revoked。
    rt_store.revoke_lineage(tenant, lineage_id.clone()).await?;

    // root 变 revoked。
    let root_found = rt_store
        .find_by_hash(tenant, hash_root_typed)
        .await?
        .expect("rt3: root 仍可查到");
    assert_eq!(
        root_found.status(),
        RefreshStatus::Revoked,
        "rt3: root 应为 revoked"
    );

    // child 变 revoked。
    let child_found = rt_store
        .find_by_hash(tenant, hash_child_typed)
        .await?
        .expect("rt3: child 仍可查到");
    assert_eq!(
        child_found.status(),
        RefreshStatus::Revoked,
        "rt3: child 应为 revoked"
    );

    // 幂等：再次 revoke_lineage 也 Ok（0 行 UPDATE）。
    rt_store.revoke_lineage(tenant, lineage_id).await?;

    store.shutdown().await?;
    Ok(())
}

/// RT-4：跨租隔离——tenant B 查 tenant A 的 hash → None（不泄露存在性）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid / TenantId parse 已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt4_cross_tenant_isolation() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = RtTenantId::parse(&tenant_a_str).unwrap();
    let tenant_b = RtTenantId::parse(&tenant_b_str).unwrap();

    let id_a = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_300_000);
    let expires = issued + Duration::from_secs(3_600);

    // tenant A 写入一条 record，clone hash 供后续 find 使用（RefreshTokenHash::new 是 pub(crate)）。
    let record_a = RefreshTokenRecord::hydrate(
        id_a.clone(),
        tenant_a,
        "dave",
        PrincipalKind::User,
        test_hash_for(0xD1),
        None,
        id_a.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a_typed = record_a.token_hash().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(record_a).await?;

    // tenant A 查自己 hash → 可以找到（anti-vacuity：record 确实存在）。
    let found_a = rt_store
        .find_by_hash(tenant_a, hash_a_typed.clone())
        .await?;
    assert!(found_a.is_some(), "rt4: tenant A 应能查到自己的 record");

    // tenant B 查 tenant A 的 hash → None（跨租 WHERE tenant_id 隔离，fail-closed）。
    let found_b = rt_store.find_by_hash(tenant_b, hash_a_typed).await?;
    assert!(
        found_b.is_none(),
        "rt4: tenant B 不应查到 tenant A 的 record（跨租隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-5：nonexistent old_id → rotate CAS miss → Ok(false)，new 不写入。
///
/// sealed [`RefreshRotation`] 命令（`begin_rotation` 从源 record 派生）使跨租 rotate 在类型层不可表达
/// （REFRESH-ROTATE-LINEAGE-01）——直接 rotate 未入库的"幽灵" old_id 是 DB 层 CAS miss 的正规路径。
/// 验证：`do_rotate_tx` 在找不到匹配的 `(tenant_id, old_id, status=active)` 行时正确返回 false。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt5_rotate_nonexistent_old_id_returns_false() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_500_000);
    let expires = issued + Duration::from_secs(3_600);

    // 构造"幽灵"源 record（从未入库）——begin_rotation 仍可调用，old_id 在 DB 中不存在。
    let phantom = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "ghost-subj",
        PrincipalKind::User,
        test_hash_for(0xE1),
        None,
        uuid::Uuid::new_v4().to_string(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    // 新 record 用于提取 RefreshTokenId / RefreshTokenHash 类型值（pub(crate) ctor 不可直接用）。
    let new_seed = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "ghost-subj",
        PrincipalKind::User,
        test_hash_for(0xE2),
        None,
        uuid::Uuid::new_v4().to_string(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let new_hash_typed = new_seed.token_hash().clone();

    // phantom 未插入 DB → CAS UPDATE 0 行 → rotate 返 false，new_seed 不写入。
    let rotation = phantom.begin_rotation(
        new_seed.id().clone(),
        new_seed.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let rt_store = PgRefreshTokenStore::new(&store);
    let result = rt_store.rotate(rotation).await?;
    assert!(
        !result,
        "rt5: 未入库 old_id → CAS miss → rotate 应返回 false"
    );

    // new_seed 也未被写入（CAS miss 不写 new）。
    let new_found = rt_store.find_by_hash(tenant, new_hash_typed).await?;
    assert!(new_found.is_none(), "rt5: CAS miss 时 new 不应写入");

    store.shutdown().await?;
    Ok(())
}

/// RT-6：跨租 revoke_lineage no-op——tenant B 调用 → tenant A 的记录不被撤销。
///
/// 验证 `revoke_lineage` 的 SQL WHERE `tenant_id = $1` 保证跨租级联撤销为空操作（0 行受影响，仍 Ok）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试 happy-path；item-level carve-out。
async fn rt6_revoke_lineage_cross_tenant_noop() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = RtTenantId::parse(&tenant_a_str).unwrap();
    let tenant_b = RtTenantId::parse(&tenant_b_str).unwrap();

    let id_str = uuid::Uuid::new_v4().to_string();
    let lineage = id_str.clone();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_600_000);
    let expires = issued + Duration::from_secs(3_600);

    let record_a = RefreshTokenRecord::hydrate(
        id_str.clone(),
        tenant_a,
        "revoke-subj",
        PrincipalKind::User,
        test_hash_for(0xF1),
        None,
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a_typed = record_a.token_hash().clone();
    let lineage_id_typed = record_a.lineage_id().clone();

    let rt_store = PgRefreshTokenStore::new(&store);
    rt_store.insert(record_a).await?;

    // tenant B 用 tenant A 的 lineage_id 调 revoke_lineage → WHERE tenant_id = B 不匹配 → no-op（0 行）
    rt_store.revoke_lineage(tenant_b, lineage_id_typed).await?;

    // tenant A 的记录仍 Active（未被跨租撤销）
    let found_a = rt_store
        .find_by_hash(tenant_a, hash_a_typed)
        .await?
        .expect("rt6: tenant A record 仍可查到");
    assert_eq!(
        found_a.status(),
        RefreshStatus::Active,
        "rt6: 跨租 revoke_lineage no-op，tenant A 记录仍 Active"
    );

    store.shutdown().await?;
    Ok(())
}

/// RT-6b：`PgRefreshTokenStore` 接入 tenant no-op conformance。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn rt6b_refresh_token_store_tenant_noop_conformance() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a = RtTenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = RtTenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let id_str = uuid::Uuid::new_v4().to_string();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_650_000);
    let expires = issued + Duration::from_secs(3_600);
    let record_a = RefreshTokenRecord::hydrate(
        id_str.clone(),
        tenant_a,
        "refresh-conformance",
        PrincipalKind::User,
        test_hash_for(0xF6),
        None,
        id_str,
        RefreshStatus::Active,
        issued,
        expires,
    );
    let hash_a = record_a.token_hash().clone();
    let lineage_a = record_a.lineage_id().clone();
    let rt_store = PgRefreshTokenStore::new(&store);

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            rt_store.insert(record_a).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(tenant_a, hash_a.clone())
                    .await?
                    .is_some_and(|record| record.status() == RefreshStatus::Active),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(tenant_b, hash_a.clone())
                    .await?
                    .is_some(),
            )
        },
        || async {
            rt_store.revoke_lineage(tenant_b, lineage_a.clone()).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                rt_store
                    .find_by_hash(tenant_a, hash_a.clone())
                    .await?
                    .is_some_and(|record| record.status() == RefreshStatus::Active),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// RT-7：并发 rotate CAS fencing——两个 `PgRefreshTokenStore` 实例 `tokio::join!` 并发 rotate 同一 Active 记录。
///
/// 验证：恰一个 rotate 返回 `true`（CAS 命中），一个返回 `false`（miss）；
/// old 变 Consumed，new 恰一条（CAS miss 的 rotate 不写 new）。
/// INVARIANT：`UPDATE ... WHERE ... AND status = $4`（CAS）保证行级互斥（同 fosite `flow_refresh.go`）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: uuid / TenantId parse 是已知合法值；集成测试并发验证；item-level carve-out。
async fn rt7_concurrent_rotate_cas_fencing() -> TestResult {
    use identity::ports::{RefreshStatus, RefreshTokenRecord};
    use std::time::{Duration, SystemTime};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = RtTenantId::parse(&tenant_str).unwrap();

    let old_id_str = uuid::Uuid::new_v4().to_string();
    let lineage = old_id_str.clone();
    let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_700_000);
    let expires = issued + Duration::from_secs(3_600);

    // 插入一条 Active 记录
    let old_record = RefreshTokenRecord::hydrate(
        old_id_str.clone(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xA7),
        None,
        lineage.clone(),
        RefreshStatus::Active,
        issued,
        expires,
    );
    let old_hash_typed = old_record.token_hash().clone();
    // sealed command: clone 源 record 供 begin_rotation（两次并发各构造独立 RefreshRotation）。
    let old_for_rotate = old_record.clone();

    let rt_store1 = PgRefreshTokenStore::new(&store);
    rt_store1.insert(old_record).await?;

    // 两个不同 new record（不同 id + hash 避免 PK / unique 冲突；只有 CAS 命中的会被写入）
    let new_record_1 = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xB7),
        Some(old_id_str.clone()),
        lineage.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let hash_new1 = new_record_1.token_hash().clone();

    let new_record_2 = RefreshTokenRecord::hydrate(
        uuid::Uuid::new_v4().to_string(),
        tenant,
        "concurrent-subj",
        PrincipalKind::User,
        test_hash_for(0xC7),
        Some(old_id_str.clone()),
        lineage.clone(),
        RefreshStatus::Active,
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );
    let hash_new2 = new_record_2.token_hash().clone();

    // 各自构造 RefreshRotation（begin_rotation 从同一源 record 派生，CAS key = old_for_rotate.id）。
    let rotation1 = old_for_rotate.begin_rotation(
        new_record_1.id().clone(),
        new_record_1.token_hash().clone(),
        issued + Duration::from_secs(1),
        expires + Duration::from_secs(1),
    );
    let rotation2 = old_for_rotate.begin_rotation(
        new_record_2.id().clone(),
        new_record_2.token_hash().clone(),
        issued + Duration::from_secs(2),
        expires + Duration::from_secs(2),
    );

    // 共享 pool 的两个独立 store 实例：并发 rotate 同一 old_id
    let rt_store2 = PgRefreshTokenStore::new(&store);
    let (r1, r2) = tokio::join!(rt_store1.rotate(rotation1), rt_store2.rotate(rotation2),);

    let r1 = r1?;
    let r2 = r2?;

    // 恰一个 true（CAS 命中），一个 false（CAS miss）
    assert!(r1 || r2, "rt7: 至少一个 rotate 应成功（CAS 命中）");
    assert!(
        !(r1 && r2),
        "rt7: 两个 rotate 不能都成功（CAS fencing：同一 old_id 只能消费一次）"
    );

    // old 应已变 Consumed
    let old_found = rt_store1
        .find_by_hash(tenant, old_hash_typed)
        .await?
        .expect("rt7: old 仍可查到（status = consumed）");
    assert_eq!(
        old_found.status(),
        RefreshStatus::Consumed,
        "rt7: 并发 rotate CAS 命中后 old 应为 Consumed"
    );

    // new 恰一条（CAS miss 的 rotate 不写 new）
    let new1_found = rt_store1.find_by_hash(tenant, hash_new1).await?;
    let new2_found = rt_store1.find_by_hash(tenant, hash_new2).await?;
    let new_count = u32::from(new1_found.is_some()) + u32::from(new2_found.is_some());
    assert_eq!(
        new_count, 1,
        "rt7: new 应恰一条（CAS miss 的 rotate 不写 new）"
    );

    store.shutdown().await?;
    Ok(())
}

// ── F8：真实 DB liveness 采样集成验证 ─────────────────────────────────────────

/// t50：真实 DB 连接下 `probe_db_liveness` 返回 Ready。
///
/// 验证：`SELECT 1` 成功 → `PoolReadiness::Ready`（端到端 DB 可达性真实探针）。
#[tokio::test(flavor = "multi_thread")]
async fn probe_db_liveness_returns_ready_with_live_db() -> TestResult {
    use crate::pool::PoolReadiness;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let result = store.probe_db_liveness().await;
    assert_eq!(
        result,
        PoolReadiness::Ready,
        "t50: 真实 DB 连接下 probe_db_liveness 应返回 Ready"
    );

    store.shutdown().await?;
    Ok(())
}

/// t51：起 sampling loop 推进一 tick → health 反映 Ready。
///
/// 验证：`pg_readiness_sampling_loop` 在真实 DB 下一轮 tick 后
/// `PgDbReadiness::snapshot()` 返回 `PoolReadiness::Ready`。
#[tokio::test(flavor = "multi_thread")]
async fn sampling_loop_marks_ready_with_live_db() -> TestResult {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;

    use crate::pool::PoolReadiness;
    use crate::readiness::{PgDbReadiness, pg_readiness_sampling_loop};

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let store = Arc::new(store);
    let health = Arc::new(PgDbReadiness::new());
    let token = CancellationToken::new();

    // 短 period 确保首 tick 快速到来（集成测试真实时间，不 pause）。
    let handle = tokio::spawn(pg_readiness_sampling_loop(
        Arc::clone(&store),
        Duration::from_millis(50),
        token.clone(),
        Arc::clone(&health),
    ));

    // 等待至少一轮 tick 完成（period=50ms，sleep 300ms 留足余量）。
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        health.snapshot(),
        PoolReadiness::Ready,
        "t51: 真实 DB 一 tick 后 health 应为 Ready"
    );

    token.cancel();
    assert!(handle.await.is_ok(), "sampling loop 应正常退出");

    // reason: Arc<PgStore> 在此作用域末尾 drop；pool 关闭由 Arc drop 时触发，
    // 集成测试无需显式 shutdown Arc<PgStore>（与 Arc 所有权语义一致）。
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// PgCredentialRepo（identity 凭据仓储）集成测试（#1316）：find/save/upsert · authenticate 三态（含成功清锁）·
// 折叠锁定态原子 RMW（累计→锁→lazy-unlock 持久化）· bump_version CAS · 跨租 fail-closed · F2 未知主体不建行 ·
// information_schema 明文列断言（DoD）。
//
// 构造 `Credential` 经 `Credential::hydrate`（pub funnel + `secure::hash_password`）；`LoginIdentifier` 经
// `identity::test_support::login_identifier`（`pub(crate)` funnel 经 test-support feature 暴露，同
// `test_support::session` 范式）。锁定策略阈值（5 次 / 15min 窗口 / 15min TTL）域 `AccountLockout` 单源，
// adapter 仅 I/O；`now` 由测试直传（确定性，无需 Clock）。known/wrong/correct/lazy-unlock 行为镜像 in-mem
// `InMemCredentialRepo` 单测（crates/identity/src/internal/mem.rs），此处证 postgres provider 行为等价 + durable。
// ───────────────────────────────────────────────────────────────────────────

use identity::ports::{AuthOutcome, Credential, CredentialRepo, IdentityError, LoginIdentifier};

use crate::PgCredentialRepo;

const CRED_TENANT_A: &str = "a1a2a3a4-b1b2-4c3c-8d4d-e1e2e3e4e5e6";
const CRED_TENANT_B: &str = "b9b8b7b6-c5c4-4a3a-8f2f-d1d2d3d4d5d6";
const CRED_USER_ALICE: &str = "11111111-2222-4333-8444-555555555555";
const CRED_USER_BOB: &str = "22222222-3333-4444-8555-666666666666";
// 锁定 TTL（域 AccountLockout 单源镜像；仅供测试时间步进推算，非生产复刻）。
const LOCK_TTL_SECS: u64 = 15 * 60;
// 测试基准时刻（well-after-epoch，避开 unix_secs 的 epoch 前钳零边界）。
const CRED_BASE_SECS: u64 = 1_700_000_000;

type CredHelperResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn cred_tenant(raw: &str) -> CredHelperResult<TenantId> {
    Ok(TenantId::parse(raw)?)
}

fn cred_uid(raw: &str) -> CredHelperResult<ids::UserId> {
    Ok(ids::UserId::parse(raw)?)
}

// 登录查找键（经 test-support funnel；known 主体亦可 `cred.login().clone()`，未知主体仅经此入口）。
fn login_id(raw: &str) -> LoginIdentifier {
    identity::test_support::login_identifier(raw)
}

fn make_cred(
    login: &str,
    user: &str,
    password: &str,
    version: u32,
    tenant: TenantId,
) -> CredHelperResult<Credential> {
    let hash = secure::hash_password(password)?;
    Ok(Credential::hydrate(
        login,
        cred_uid(user)?,
        tenant,
        hash,
        version,
    ))
}

fn cred_epoch(secs: u64) -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}

// 直查持久化 failure_count（断言锁定态原子推进 / 清零）。
async fn db_failure_count(store: &PgStore, tenant: &str, login: &str) -> CredHelperResult<i64> {
    let row: (i64,) = sqlx::query_as(
        "SELECT failure_count FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}

// 直查持久化 locked_until epoch（NULL → None；断言 lazy-unlock 持久化解锁）。
async fn db_locked_until(
    store: &PgStore,
    tenant: &str,
    login: &str,
) -> CredHelperResult<Option<i64>> {
    let row: (Option<i64>,) = sqlx::query_as(
        "SELECT extract(epoch from locked_until)::bigint \
         FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(tenant)
    .bind(login)
    .fetch_one(&store.pool)
    .await?;
    Ok(row.0)
}

// CRUD：未存 → None；save → find_by_user_id 往返一致（user_id/login/version + PHC 列形态）；同 login 二次 save
// → upsert 覆盖 version（非新增行）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_save_find_roundtrip_and_upsert() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;

    // 未保存 → None（fail-closed 基线，anti-vacuity 负例）。
    assert!(
        repo.find_by_user_id(tenant, cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "未保存 → None"
    );

    // save → find_by_user_id 往返一致。
    repo.save(make_cred("alice", CRED_USER_ALICE, "pw1", 1, tenant)?)
        .await?;
    let Some(got) = repo
        .find_by_user_id(tenant, cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("saved credential visible".into());
    };
    assert_eq!(
        got.user_id(),
        cred_uid(CRED_USER_ALICE)?,
        "canonical subject 保真"
    );
    assert_eq!(got.login().as_str(), "alice", "login 查找键保真");
    assert_eq!(got.version(), 1, "version 保真");
    assert!(
        got.password_hash().as_str().starts_with("$argon2"),
        "回读 PHC 为 argon2 格式（明文永不落库）"
    );

    // 同 login 二次 save → upsert 覆盖 version（DO UPDATE，非新增行）。
    repo.save(make_cred("alice", CRED_USER_ALICE, "pw2", 2, tenant)?)
        .await?;
    let Some(got2) = repo
        .find_by_user_id(tenant, cred_uid(CRED_USER_ALICE)?)
        .await?
    else {
        return Err("upserted credential visible".into());
    };
    assert_eq!(got2.version(), 2, "upsert 覆盖 version");
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid AND login = $2",
    )
    .bind(CRED_TENANT_A)
    .bind("alice")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(n.0, 1, "upsert 不新增行");

    store.shutdown().await?;
    Ok(())
}

// authenticate 三态：已知+正确 → Authenticated(canonical user_id)；已知+错 → InvalidKnownUser；
// 查无凭据 → InvalidUnknown（恒定成本 KDF 仍跑，不 panic）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_known_wrong_and_unknown() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?)
        .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    assert_eq!(
        repo.authenticate(tenant, login_id("alice"), "correct".to_string(), now)
            .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?),
        "已知+正确 → Authenticated(canonical user_id)"
    );
    assert_eq!(
        repo.authenticate(tenant, login_id("alice"), "wrong".to_string(), now)
            .await?,
        AuthOutcome::InvalidKnownUser,
        "已知+错 → InvalidKnownUser"
    );
    assert_eq!(
        repo.authenticate(tenant, login_id("ghost"), "correct".to_string(), now)
            .await?,
        AuthOutcome::InvalidUnknown,
        "查无凭据 → InvalidUnknown"
    );

    store.shutdown().await?;
    Ok(())
}

// F2：未知主体登录失败**不建行 / 不建锁**——不可经枚举撑大 credentials 表（折叠列 ⇒ 无行即无锁，结构层成立）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_unknown_subject_creates_no_row() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let tenant = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, tenant)?)
        .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    for i in 0..20 {
        assert_eq!(
            repo.authenticate(
                tenant,
                login_id(&format!("ghost-{i}")),
                "x".to_string(),
                now
            )
            .await?,
            AuthOutcome::InvalidUnknown
        );
    }
    // 仅 alice 一行（未知主体未建任何行 ⇒ lockout 表不随枚举增长，F2）。
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM credentials WHERE tenant_id = $1::uuid")
        .bind(CRED_TENANT_A)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(n.0, 1, "未知主体不建行（F2：lockout 表不随枚举增长）");

    store.shutdown().await?;
    Ok(())
}

// 跨租 fail-closed：A 种入 alice，B 视角 find → None / authenticate → InvalidUnknown / lockout_status → false
// （即使 A 已锁定 alice）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_cross_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    // 跨租 find → None（不泄露存在性）。
    assert!(
        repo.find_by_user_id(b, cred_uid(CRED_USER_ALICE)?)
            .await?
            .is_none(),
        "跨租 find → None"
    );
    // 跨租 authenticate → InvalidUnknown（跨租即未知）。
    assert_eq!(
        repo.authenticate(b, login_id("alice"), "correct".to_string(), now)
            .await?,
        AuthOutcome::InvalidUnknown,
        "跨租 authenticate → InvalidUnknown"
    );
    // 在 A 锁定 alice（5 次错），B 视角 lockout_status 仍 false（隔离）。
    for i in 1..=5 {
        repo.authenticate(
            a,
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert!(
        repo.lockout_status(a, login_id("alice"), cred_epoch(CRED_BASE_SECS + 5))
            .await?,
        "A 视角 alice 已锁"
    );
    assert!(
        !repo
            .lockout_status(b, login_id("alice"), cred_epoch(CRED_BASE_SECS + 5))
            .await?,
        "B 视角不受 A 锁定影响（跨租隔离）"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_tenant_noop_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    let alice_uid = cred_uid(CRED_USER_ALICE)?;
    let now = cred_epoch(CRED_BASE_SECS);
    let credential = make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?;

    testkit::repo_conformance::assert_cross_tenant_noop(
        || async {
            repo.save(credential).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(a, alice_uid).await?.is_some(),
            )
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(b, alice_uid).await?.is_some(),
            )
        },
        || async {
            let outcome = repo
                .authenticate(b, login_id("alice"), "correct".to_string(), now)
                .await?;
            if outcome == AuthOutcome::InvalidUnknown {
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            } else {
                Err(format!("cross-tenant authenticate returned {outcome:?}").into())
            }
        },
        || async {
            Ok::<bool, Box<dyn std::error::Error + Send + Sync>>(
                repo.find_by_user_id(a, alice_uid).await?.is_some(),
            )
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

// 原子推进：连续 authenticate(错) 经仓储持久化累计——未达阈值未锁，第 5 次（窗口内）达阈值锁定。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_accumulate_failures_then_locks() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;

    for i in 1..5 {
        assert_eq!(
            repo.authenticate(
                a,
                login_id("alice"),
                "wrong".to_string(),
                cred_epoch(CRED_BASE_SECS + i)
            )
            .await?,
            AuthOutcome::InvalidKnownUser,
            "第 {i} 次失败"
        );
        assert!(
            !repo
                .lockout_status(a, login_id("alice"), cred_epoch(CRED_BASE_SECS + i))
                .await?,
            "未达阈值仍未锁"
        );
    }
    // 第 5 次（窗口内）→ 达阈值锁定（DB 持久化失败计数 = 5）。
    repo.authenticate(
        a,
        login_id("alice"),
        "wrong".to_string(),
        cred_epoch(CRED_BASE_SECS + 5),
    )
    .await?;
    assert!(
        repo.lockout_status(a, login_id("alice"), cred_epoch(CRED_BASE_SECS + 5))
            .await?,
        "第 5 次达阈值锁定"
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "失败计数持久化推进至阈值"
    );

    store.shutdown().await?;
    Ok(())
}

// lazy-unlock：TTL 内仍锁；TTL 后 lockout_status 原子解锁（持久化清 locked_until）+ 计数从 1 重计。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_lockout_lazy_unlocks_after_ttl() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;
    for i in 1..=5 {
        repo.authenticate(
            a,
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    let lock_at = CRED_BASE_SECS + 5;

    // TTL 内仍锁。
    assert!(
        repo.lockout_status(
            a,
            login_id("alice"),
            cred_epoch(lock_at + LOCK_TTL_SECS - 1)
        )
        .await?,
        "TTL 内仍锁"
    );
    // TTL 后 lazy-unlock → false + 持久化清 locked_until。
    assert!(
        !repo
            .lockout_status(
                a,
                login_id("alice"),
                cred_epoch(lock_at + LOCK_TTL_SECS + 1)
            )
            .await?,
        "TTL 后 lazy-unlock 解锁"
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none(),
        "lazy-unlock 持久化清 locked_until"
    );
    // 解锁后再失败从 1 重计（不沿用旧计数）→ InvalidKnownUser、未锁。
    let after = lock_at + LOCK_TTL_SECS + 2;
    assert_eq!(
        repo.authenticate(a, login_id("alice"), "wrong".to_string(), cred_epoch(after))
            .await?,
        AuthOutcome::InvalidKnownUser
    );
    assert!(
        !repo
            .lockout_status(a, login_id("alice"), cred_epoch(after))
            .await?,
        "重计未达阈值未锁"
    );

    store.shutdown().await?;
    Ok(())
}

// 成功登录原子清零失败计数（authenticate 内折叠 clear——不需独立 clear 端口）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_success_clears_lockout() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;

    // 4 次错（未达阈值 5，未锁）→ 失败计数持久化 = 4。
    for i in 1..=4 {
        repo.authenticate(
            a,
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        4,
        "失败累积 4"
    );
    // 正确密码 → Authenticated + 原子清零失败计数。
    assert_eq!(
        repo.authenticate(
            a,
            login_id("alice"),
            "correct".to_string(),
            cred_epoch(CRED_BASE_SECS + 5)
        )
        .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?)
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        0,
        "成功登录清零失败计数"
    );

    store.shutdown().await?;
    Ok(())
}

// bump_version CAS：期望不匹配 → VersionConflict；命中 → 替换 hash+version（authenticate 新密码真）；
// 查无 → CredentialNotFound；跨租（next 在 B）→ CredentialNotFound 且不动 A。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_bump_version_cas() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    let b = cred_tenant(CRED_TENANT_B)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "pw1", 1, a)?)
        .await?;
    let now = cred_epoch(CRED_BASE_SECS);

    // 期望版本不匹配 → VersionConflict。
    assert!(
        matches!(
            repo.bump_version(99, make_cred("alice", CRED_USER_ALICE, "pw2", 2, a)?)
                .await,
            Err(IdentityError::VersionConflict)
        ),
        "期望不匹配 → VersionConflict"
    );
    // 命中 → 替换 hash + version。
    repo.bump_version(1, make_cred("alice", CRED_USER_ALICE, "pw2", 2, a)?)
        .await?;
    let Some(got) = repo.find_by_user_id(a, cred_uid(CRED_USER_ALICE)?).await? else {
        return Err("credential visible after CAS hit".into());
    };
    assert_eq!(got.version(), 2, "CAS 命中后 version = 2");
    assert_eq!(
        repo.authenticate(a, login_id("alice"), "pw2".to_string(), now)
            .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?),
        "新密码验签真"
    );
    // 查无凭据 → CredentialNotFound。
    assert!(
        matches!(
            repo.bump_version(1, make_cred("ghost", CRED_USER_BOB, "x", 1, a)?)
                .await,
            Err(IdentityError::CredentialNotFound)
        ),
        "查无 → CredentialNotFound"
    );
    // 跨租 bump（next 在 B）→ CredentialNotFound（key 派生自 next，B 无行），不动 A。
    assert!(
        matches!(
            repo.bump_version(2, make_cred("alice", CRED_USER_ALICE, "pw3", 3, b)?)
                .await,
            Err(IdentityError::CredentialNotFound)
        ),
        "跨租 bump → CredentialNotFound"
    );
    let Some(still_a) = repo.find_by_user_id(a, cred_uid(CRED_USER_ALICE)?).await? else {
        return Err("tenant A credential still present after cross-tenant bump".into());
    };
    assert_eq!(still_a.version(), 2, "跨租 bump 不动 A（仍 v2）");

    store.shutdown().await?;
    Ok(())
}

/// material-never-persisted 断言（DoD review-critical）：`information_schema.columns` 校验 credentials 列集
/// 恰为预期（含 `password_hash`，**无明文 `password` 列**）。
#[tokio::test(flavor = "multi_thread")]
async fn ts_credentials_no_plaintext_password_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'credentials' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;
    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    let expected = [
        "created_at",
        "failure_count",
        "locked_until",
        "lockout_window_start",
        "login",
        "password_hash",
        "tenant_id",
        "user_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "credentials 列集应恰为预期（仅 PHC，无明文密码列），实际：{cols:?}"
    );
    // 显式守 DoD：无明文 password 列，仅 argon2 PHC。
    assert!(
        !cols.contains(&"password"),
        "禁止明文 password 列（明文永不落库）"
    );
    assert!(cols.contains(&"password_hash"), "仅持久化 argon2 PHC 列");

    store.shutdown().await?;
    Ok(())
}

// 已锁定（达阈值，locked_until 持久化非 NULL）→ 正确密码 authenticate → Authenticated + 原子清锁。
// （authenticate 成功分支无视锁定态、只负责清锁；「已锁拒绝」由上层 lockout_status 门控承载，#1277）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_authenticate_correct_clears_active_lock() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = PgCredentialRepo::new(&store);
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;

    // 5 次错 → 达阈值锁定（locked_until 持久化非 NULL）。
    for i in 1..=5 {
        repo.authenticate(
            a,
            login_id("alice"),
            "wrong".to_string(),
            cred_epoch(CRED_BASE_SECS + i),
        )
        .await?;
    }
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_some(),
        "达阈值后 locked_until 持久化"
    );

    // 正确密码 → Authenticated + 原子清锁（locked_until + failure_count 持久化清零）。
    assert_eq!(
        repo.authenticate(
            a,
            login_id("alice"),
            "correct".to_string(),
            cred_epoch(CRED_BASE_SECS + 6)
        )
        .await?,
        AuthOutcome::Authenticated(cred_uid(CRED_USER_ALICE)?)
    );
    assert!(
        db_locked_until(&store, CRED_TENANT_A, "alice")
            .await?
            .is_none(),
        "成功登录清 locked_until（解锁持久化）"
    );
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        0,
        "成功登录清 failure_count"
    );

    store.shutdown().await?;
    Ok(())
}

/// T24：RLS 强制力证明 — credentials 表（#1316，与 T20–T23 同范式补 credentials 表 DB 层隔离）。
///
/// 以 `SET LOCAL ROLE rss_app`（非 owner，superuser 永远绕过 RLS 不适合验证）+ tenant scope 切换，验证
/// `0012` 的 RLS policy 真实生效：tenant_a scope INSERT/SELECT 成功可见；切 tenant_b → 不可见（USING 过滤）；
/// tenant_a scope 写 tenant_b 行 → WITH CHECK 拒绝。
///
/// 注：不含「未设 rss.tenant_id → 0 行」子用例——`set_config(..,is_local=true)` 在 pool 复用连接上 tx 末 revert
/// 为 placeholder GUC 默认值 `''`（非 NULL），`''::uuid` 在 USING 谓词 raise（仍 fail-closed=不泄数据，但非「0 行」），
/// 该 unset-scope 行为依赖连接是否曾被 set（pool 不可控）⇒ 不在本测试断言（T20–T23 的同款 null-scope 子用例有相同
/// 连接态依赖，见 OOS issue）。核心 RLS 强制力由下列 4 步 USING/WITH CHECK 证明已足。
#[tokio::test(flavor = "multi_thread")]
async fn t24_rls_credentials_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let user_a = uuid::Uuid::new_v4().to_string();

    // Tx1：rss_app + tenant_a scope → INSERT tenant_a 凭据 → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-alice', 'phc-placeholder', 1)",
        )
        .bind(&tenant_a)
        .bind(&user_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a credential failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(cnt.0, 1, "t24: tenant_a scope — 凭据应可见（USING pass）");
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT 同行 → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM credentials WHERE login = 'rls-alice'")
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: tenant_b scope — 凭据应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b 凭据 → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query(
            "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
             VALUES ($1::uuid, $2::uuid, 'rls-bob', 'phc-placeholder', 1)",
        )
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t24: WITH CHECK 应拒绝 tenant_b 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// DB CHECK 约束红用例（#1316 review F2）：0012 的域不变式 CHECK 拒非法行——version/failure_count 越 u32 界、
// 锁定态缺滑窗起点。证 domain `u32` 边界 + 锁定一致性已下沉为 DB 硬约束（坏迁移/外部直写不可绕）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_db_check_constraints_reject_invalid() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let t = CRED_TENANT_A;
    let u = CRED_USER_ALICE;

    // 正例基线（合法行 INSERT 成功 → 证下列拒绝非因其它列约束，anti-vacuity）。
    sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'ok', 'phc', 1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await?;

    // 非法：version < 0 → credentials_version_u32 拒。
    let neg_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad1', 'phc', -1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(neg_ver.is_err(), "version < 0 应被 CHECK 拒");

    // 非法：version > u32::MAX（4294967296）→ credentials_version_u32 拒。
    let over_ver = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version) \
         VALUES ($1::uuid, $2::uuid, 'bad2', 'phc', 4294967296)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(over_ver.is_err(), "version > u32::MAX 应被 CHECK 拒");

    // 非法：failure_count < 0 → credentials_failure_count_u32 拒。
    let neg_fc = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, failure_count) \
         VALUES ($1::uuid, $2::uuid, 'bad3', 'phc', 1, -1)",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(neg_fc.is_err(), "failure_count < 0 应被 CHECK 拒");

    // 非法：locked_until 非空但 lockout_window_start 为空 → credentials_lock_requires_window 拒。
    let lock_no_window = sqlx::query(
        "INSERT INTO credentials (tenant_id, user_id, login, password_hash, version, locked_until) \
         VALUES ($1::uuid, $2::uuid, 'bad4', 'phc', 1, now())",
    )
    .bind(t)
    .bind(u)
    .execute(&store.pool)
    .await;
    assert!(
        lock_no_window.is_err(),
        "locked_until 非空但 lockout_window_start 为空应被 CHECK 拒"
    );

    store.shutdown().await?;
    Ok(())
}

// 并发行锁 RMW 红用例（#1316 review F1）：同 (tenant, login) 5 路并发 wrong-password authenticate——
// SELECT ... FOR UPDATE 串行化各事务 RMW，全部完成后失败计数恰 = 5（无丢更新）且达阈值锁定。
// 对标 role_repo_concurrent_save_converges（Arc<repo> + tokio::spawn 竞争同行）。
#[tokio::test(flavor = "multi_thread")]
async fn credential_repo_concurrent_failures_no_lost_update() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let repo = Arc::new(PgCredentialRepo::new(&store));
    let a = cred_tenant(CRED_TENANT_A)?;
    repo.save(make_cred("alice", CRED_USER_ALICE, "correct", 1, a)?)
        .await?;

    // 5 路并发错密码（同一行）——同一 now，行锁强制串行 RMW（非各自读 stale 副本各 +1 丢更新）。
    let now = cred_epoch(CRED_BASE_SECS);
    let mut handles = Vec::new();
    for _ in 0..5 {
        let repo = Arc::clone(&repo);
        handles.push(tokio::spawn(async move {
            repo.authenticate(a, login_id("alice"), "wrong".to_string(), now)
                .await
        }));
    }
    for h in handles {
        // 每路均应返回 InvalidKnownUser（已知主体 + 错），无 task panic / Storage 错。
        let outcome = h.await.map_err(|e| format!("join failed: {e}"))??;
        assert_eq!(
            outcome,
            AuthOutcome::InvalidKnownUser,
            "并发错密码各路 InvalidKnownUser"
        );
    }

    // 行锁串行化 ⇒ 失败计数恰 5（无丢更新）+ 达阈值锁定。
    assert_eq!(
        db_failure_count(&store, CRED_TENANT_A, "alice").await?,
        5,
        "5 路并发错密码 → 失败计数恰 5（FOR UPDATE 无丢更新）"
    );
    assert!(
        repo.lockout_status(a, login_id("alice"), now).await?,
        "达阈值后锁定"
    );

    store.shutdown().await?;
    Ok(())
}

// ── T24: RLS 强制力证明 — refresh_tokens 表（#1325 review #284 F5）──────────────────
//
// 0013 迁移落地 ENABLE + FORCE ROW LEVEL SECURITY + tenant_isolation policy（同 0009 范式）。
// 本测试以 SET LOCAL ROLE rss_app 切换到非 owner 角色，验证 RLS 对 refresh_tokens 生效。
//
// 测试结构（同 T20–T23 范式）：
//   • Tx1（rss_app + tenant_a scope）：INSERT tenant_a refresh_token → 成功（WITH CHECK pass）。
//   • Tx2（rss_app + tenant_a scope）：SELECT → tenant_a 行可见（USING pass）。
//   • Tx3（rss_app + tenant_b scope）：SELECT 同行 → 不可见（USING 过滤，跨租读被阻）。
//   • Tx4（rss_app + tenant_a scope）：INSERT tenant_b 行 → 错误（WITH CHECK 拒绝，跨租写被阻）。
//   • Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → 行不可见（fail-closed）。

/// T24：RLS 强制力证明 — refresh_tokens 表（#1325 review #284 F5）。
///
/// 验证：rss_app 角色 + tenant_a scope 下 INSERT 成功 / SELECT 可见；切换 tenant_b scope → 不可见；
/// tenant_a scope 内尝试写 tenant_b 行 → WITH CHECK 拒绝；未设 rss.tenant_id → fail-closed（0 行）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: uuid::Uuid::new_v4().to_string() 不会失败；函数级 item-level carve-out。
async fn t24_rls_refresh_tokens_enforces_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 提权：superuser 需成为 rss_app member 才能 SET LOCAL ROLE；幂等（已是 member 则 no-op）。
    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_a = uuid::Uuid::new_v4().to_string();
    let tenant_b = uuid::Uuid::new_v4().to_string();
    let token_id_a = uuid::Uuid::new_v4().to_string();
    let lineage_id_a = uuid::Uuid::new_v4().to_string();
    // SHA-256 固定 32 字节（满足 CHECK octet_length = 32）。
    let hash_a = vec![0xABu8; 32];

    // Tx1：rss_app + tenant_a scope → INSERT refresh_token → 成功（WITH CHECK pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, tenant_id, subject, kind, token_hash, lineage_id, status, issued_at, expires_at) \
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, 'active', now(), now() + interval '1 hour')",
        )
        .bind(&token_id_a)
        .bind(&tenant_a)
        .bind("rls-test-subject")
        .bind("user")
        .bind(&hash_a)
        .bind(&lineage_id_a)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Tx1 INSERT tenant_a refresh_token failed (should succeed): {e}"))?;
        tx.commit().await?;
    }

    // Tx2：rss_app + tenant_a scope → SELECT token_id_a → 可见（USING pass）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 1,
            "t24: rss_app + tenant_a scope — refresh_token 应可见（USING policy pass）"
        );
        tx.rollback().await?;
    }

    // Tx3：rss_app + tenant_b scope → SELECT token_id_a → 不可见（跨租 USING 过滤）。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: rss_app + tenant_b scope — tenant_a refresh_token 应不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    // Tx4：rss_app + tenant_a scope，尝试写 tenant_b refresh_token → WITH CHECK 拒绝。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_a)
            .execute(&mut *tx)
            .await?;
        let cross_hash = vec![0xCDu8; 32];
        let result = sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, tenant_id, subject, kind, token_hash, lineage_id, status, issued_at, expires_at) \
             VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, 'active', now(), now() + interval '1 hour')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&tenant_b) // tenant_b ≠ rss.tenant_id(=tenant_a) → WITH CHECK fail
        .bind("rls-test-subject")
        .bind("user")
        .bind(&cross_hash)
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await;
        assert!(
            result.is_err(),
            "t24: WITH CHECK 应拒绝 tenant_b refresh_token 写入（rss.tenant_id=tenant_a）"
        );
        tx.rollback().await?;
    }

    // Tx5（NULL fail-closed）：rss_app + 未设 rss.tenant_id → SELECT refresh_tokens → 0 行。
    // current_setting('rss.tenant_id', true) 返 NULL → RLS USING 谓词 NULL → 所有行过滤，fail-closed。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 不调用 set_config('rss.tenant_id', ...) → current_setting 返 NULL → 行不可见。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM refresh_tokens WHERE id = $1::uuid")
            .bind(&token_id_a)
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "t24: rss_app + 未設 rss.tenant_id — current_setting NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

// ── audit_entries 集成测试 ────────────────────────────────────────────────────
//
// TA1:  genesis + 单调递增 seq
// TA2:  prev_hash 链接前驱 entry_hash
// TA3:  并发 append——no seq gap/dup（advisory lock 串行）
// TA4:  租户隔离——两租户独立 genesis
// TA5:  RLS 跨租读隔离（rss_app + tenant_b scope → 0 行）
// TA6:  list 分页游标 + has_more（5 条 ÷ page=2 → 3 页）
// TA7:  list InvalidCursor fail-closed（base64url 合法但语义无效）
// TA8:  verify_tail 增量：小窗口不覆盖被篡改 genesis → Ok；大窗口 → HashMismatch
// TA9:  recorded_at 非零 nanos 往返（regression for secs+nanos 两列设计）
// TA10: append-only——rss_app DELETE/UPDATE 被 DB 权限拒绝
// TA11: RLS NULL tenant fail-closed——未设 rss.tenant_id → 0 行
// TA12: 空租户链 list + verify_tail 均 Ok

// trait AuditRepo 须在 scope 才能调用 append / list / verify_tail 方法。
use audit::ports::AuditRepo as _;
// base64::Engine::encode 须在 scope（URL_SAFE_NO_PAD.encode(...)）。
use base64::Engine as _;

/// 构造审计仓储（共享 pool，固定 0x5a key hasher）。
fn make_audit_repo(
    store: &PgStore,
) -> crate::PgAuditRepo<crate::audit_repo::test_support::TestVerifier> {
    crate::PgAuditRepo::new(store, crate::audit_repo::test_support::test_hasher(0x5a))
}

/// 构造审计记录（nanos 可变，其余字段固定；actor UUID 硬编码确定性 ID）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——固定格式 UUID / action parse 不失败；item-level carve-out。
fn make_audit_record(tenant: vocab::TenantId, nanos: u32) -> audit::ports::AuditRecord {
    use std::time::{Duration, UNIX_EPOCH};
    audit::ports::AuditRecord {
        tenant,
        actor: ids::UserId::parse("11111111-2222-4333-8444-555555555555").unwrap(),
        actor_kind: vocab::PrincipalKind::User,
        action: vocab::Action::parse("audit:read").unwrap(),
        resource: audit::ports::ResourceRef::new("session", "sess-1"),
        outcome: audit::ports::AuditOutcome::Success,
        recorded_at: UNIX_EPOCH + Duration::new(1_700_000_000, nanos),
    }
}

/// 构造分页请求（limit ≤ 500 不失败）。
#[allow(clippy::unwrap_used)]
// reason: 集成测试 helper——limit 值由测试代码控制，均合法；item-level carve-out。
fn audit_page(limit: u16, cursor: Option<vocab::Cursor>) -> audit::ports::AuditPage {
    audit::ports::AuditPage {
        limit: vocab::Limit::new(limit).unwrap(),
        cursor,
    }
}

/// TA1: genesis 条目 seq=0，连续 append seq 单调递增。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path——UUID v4 生成不失败；item-level carve-out。
async fn ta1_audit_append_genesis_and_monotonic_seq() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(make_audit_record(tenant, 0)).await?;
    repo.append(make_audit_record(tenant, 0)).await?;
    repo.append(make_audit_record(tenant, 0)).await?;

    let result = repo.list(tenant, audit_page(500, None)).await?;
    assert_eq!(result.entries.len(), 3, "TA1: 应恰有 3 条");
    assert_eq!(result.entries[0].seq(), 0, "TA1: genesis seq=0");
    assert_eq!(result.entries[1].seq(), 1, "TA1: seq 单调+1");
    assert_eq!(result.entries[2].seq(), 2, "TA1: seq 单调+2");
    assert!(!result.has_more);
    assert!(result.next_cursor.is_none());

    store.shutdown().await?;
    Ok(())
}

/// TA2: 每条 prev_hash == 前一条 entry_hash，genesis prev 全零。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta2_audit_prev_links_to_predecessor_entry_hash() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..3 {
        repo.append(make_audit_record(tenant, 0)).await?;
    }

    let result = repo.list(tenant, audit_page(500, None)).await?;
    let e = &result.entries;

    assert_eq!(
        e[0].prev_hash().as_bytes(),
        &[0u8; 32],
        "TA2: genesis prev 须全零"
    );
    assert_eq!(
        e[1].prev_hash().as_bytes(),
        e[0].entry_hash().as_bytes(),
        "TA2: e[1].prev_hash 须 == e[0].entry_hash"
    );
    assert_eq!(
        e[2].prev_hash().as_bytes(),
        e[1].entry_hash().as_bytes(),
        "TA2: e[2].prev_hash 须 == e[1].entry_hash"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA3: 同租户并发 append（5 task）——advisory lock 保证 no seq gap / dup。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta3_audit_concurrent_appends_no_seq_gap() -> TestResult {
    use std::sync::Arc;
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = Arc::new(make_audit_repo(&store));

    const N: usize = 5;
    let handles: Vec<_> = (0..N)
        .map(|_| {
            let r = Arc::clone(&repo);
            tokio::spawn(async move { r.append(make_audit_record(tenant, 0)).await })
        })
        .collect();
    for h in handles {
        h.await.map_err(|e| format!("join error: {e}"))??;
    }

    let result = repo.list(tenant, audit_page(500, None)).await?;
    assert_eq!(result.entries.len(), N, "TA3: 应恰有 {N} 条");
    let mut seqs: Vec<u64> = result.entries.iter().map(|e| e.seq()).collect();
    seqs.sort_unstable();
    for (i, &s) in seqs.iter().enumerate() {
        assert_eq!(s, i as u64, "TA3: seq 须连续无 gap，i={i} s={s}");
    }

    store.shutdown().await?;
    Ok(())
}

/// TA4: 两租户独立 genesis（seq 各从 0 起），互不干扰。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta4_audit_tenant_isolation_independent_genesis() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(make_audit_record(tenant_a, 0)).await?;
    repo.append(make_audit_record(tenant_a, 0)).await?;
    repo.append(make_audit_record(tenant_b, 0)).await?;

    let a = repo.list(tenant_a, audit_page(500, None)).await?;
    let b = repo.list(tenant_b, audit_page(500, None)).await?;
    assert_eq!(a.entries.len(), 2, "TA4: tenant_a 应有 2 条");
    assert_eq!(b.entries.len(), 1, "TA4: tenant_b 应有 1 条");
    assert_eq!(a.entries[0].seq(), 0, "TA4: tenant_a genesis seq=0");
    assert_eq!(b.entries[0].seq(), 0, "TA4: tenant_b 独立 genesis seq=0");

    store.shutdown().await?;
    Ok(())
}

/// TA5: RLS 跨租读隔离——rss_app + tenant_b scope 下看不到 tenant_a 的审计行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta5_audit_rls_cross_tenant_read_denied() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    let tenant_a_str = uuid::Uuid::new_v4().to_string();
    let tenant_a = vocab::TenantId::parse(&tenant_a_str).unwrap();
    let tenant_b_str = uuid::Uuid::new_v4().to_string();

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let repo = make_audit_repo(&store);
    repo.append(make_audit_record(tenant_a, 0)).await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_b_str)
            .execute(&mut *tx)
            .await?;
        let cnt: (i64,) =
            sqlx::query_as("SELECT count(*) FROM audit_entries WHERE tenant_id = $1::uuid")
                .bind(&tenant_a_str)
                .fetch_one(&mut *tx)
                .await?;
        assert_eq!(
            cnt.0, 0,
            "TA5: rss_app + tenant_b scope — tenant_a 行须不可见（跨租 RLS 过滤）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA6: list 分页游标——5 条, page=2 → 3 页（2+2+1），has_more 正确，cursor 续页完整。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta6_audit_list_pagination_cursor_and_has_more() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(make_audit_record(tenant, 0)).await?;
    }

    let p1 = repo.list(tenant, audit_page(2, None)).await?;
    assert_eq!(p1.entries.len(), 2, "TA6: p1 应有 2 条");
    assert!(p1.has_more, "TA6: p1 has_more=true");
    assert!(p1.next_cursor.is_some(), "TA6: p1 应有 next_cursor");
    assert_eq!(p1.entries[0].seq(), 0);
    assert_eq!(p1.entries[1].seq(), 1);

    let p2 = repo.list(tenant, audit_page(2, p1.next_cursor)).await?;
    assert_eq!(p2.entries.len(), 2, "TA6: p2 应有 2 条");
    assert!(p2.has_more, "TA6: p2 has_more=true");
    assert_eq!(p2.entries[0].seq(), 2);
    assert_eq!(p2.entries[1].seq(), 3);

    let p3 = repo.list(tenant, audit_page(2, p2.next_cursor)).await?;
    assert_eq!(p3.entries.len(), 1, "TA6: p3 应有 1 条");
    assert!(!p3.has_more, "TA6: p3 has_more=false");
    assert!(p3.next_cursor.is_none(), "TA6: p3 无 next_cursor");
    assert_eq!(p3.entries[0].seq(), 4);

    store.shutdown().await?;
    Ok(())
}

/// TA7: list 语义无效游标（base64url 合法但解码后非数字）→ InvalidCursor（fail-closed）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta7_audit_list_invalid_cursor_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(make_audit_record(tenant, 0)).await?;

    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
    let cursor = vocab::Cursor::parse(&raw).unwrap();
    let result = repo.list(tenant, audit_page(10, Some(cursor))).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::InvalidCursor)),
        "TA7: 语义无效游标须返回 InvalidCursor"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA8: verify_tail 增量性——篡改 genesis 后，小窗口（不覆盖 seq=0）Ok；大窗口 → HashMismatch。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta8_audit_verify_tail_incremental_and_tamper_detection() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    for _ in 0..5 {
        repo.append(make_audit_record(tenant, 0)).await?;
    }

    // 干净链：verify_tail 均通过。
    repo.verify_tail(tenant, 2).await?;
    repo.verify_tail(tenant, 10).await?;

    // 超级用户篡改 seq=0 的 entry_hash（rss_app 无 UPDATE 权）。
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xAAu8; 32])
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    // 小窗口（末 2 条 = seq 3,4 + 前驱 seq 2）：不覆盖被篡改 seq 0 → 增量验证仍 Ok。
    let tail2 = repo.verify_tail(tenant, 2).await;
    assert!(
        tail2.is_ok(),
        "TA8: 小窗口不覆盖被篡改 genesis → verify_tail(2) 须 Ok，got: {tail2:?}"
    );

    // 大窗口（全 5 条 seq 0-4）：覆盖被篡改 seq 0 → HashMismatch。
    let tail10 = repo.verify_tail(tenant, 10).await;
    assert!(
        matches!(tail10, Err(audit::ports::AuditError::HashMismatch)),
        "TA8: 大窗口覆盖被篡改 genesis → HashMismatch，got: {tail10:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA9: recorded_at 非零 nanos 往返——存储+读取后 nanos 精确保留，且链哈希仍验证通过。
///
/// Regression: 若用 timestamptz 存储则 nanos 被截断 → 重算 entry_hash 不匹配。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
// reason: 集成测试——recorded_at 由 UNIX_EPOCH+Duration 构造，duration_since(UNIX_EPOCH) 不失败；item-level carve-out。
async fn ta9_audit_recorded_at_nanos_roundtrip_and_chain_verifies() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let nanos_input: u32 = 123_456_789;
    repo.append(make_audit_record(tenant, nanos_input)).await?;

    let result = repo.list(tenant, audit_page(10, None)).await?;
    assert_eq!(result.entries.len(), 1, "TA9: 应恰有 1 条");

    let e = &result.entries[0];
    let since_epoch = e
        .recorded_at()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("recorded_at >= UNIX_EPOCH");
    assert_eq!(
        since_epoch.subsec_nanos(),
        nanos_input,
        "TA9: nanos 须精确往返（secs+nanos 两列，非 timestamptz）"
    );

    // list 内置增量验证；额外 verify_tail 确认链完整。
    repo.verify_tail(tenant, 10).await?;

    store.shutdown().await?;
    Ok(())
}

/// TA10: append-only——rss_app 对 audit_entries 的 DELETE / UPDATE 被 DB 权限拒绝。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta10_audit_append_only_delete_update_rejected_for_rss_app() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(make_audit_record(tenant, 0)).await?;

    // rss_app DELETE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let del = sqlx::query("DELETE FROM audit_entries WHERE tenant_id = $1::uuid")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await;
        assert!(
            del.is_err(),
            "TA10: rss_app 应无 DELETE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    // rss_app UPDATE → permission denied。
    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant_str)
            .execute(&mut *tx)
            .await?;
        let upd = sqlx::query(
            "UPDATE audit_entries SET action = 'tampered:value' WHERE tenant_id = $1::uuid",
        )
        .bind(&tenant_str)
        .execute(&mut *tx)
        .await;
        assert!(
            upd.is_err(),
            "TA10: rss_app 应无 UPDATE 权限（append-only）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA11: RLS NULL tenant fail-closed——rss_app 未设 rss.tenant_id → current_setting NULL → 0 行。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta11_audit_rls_null_tenant_fail_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    sqlx::query("GRANT rss_app TO CURRENT_USER")
        .execute(&store.pool)
        .await?;

    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);
    repo.append(make_audit_record(tenant, 0)).await?;

    {
        let mut tx = store.pool.begin().await?;
        sqlx::query("SET LOCAL ROLE rss_app")
            .execute(&mut *tx)
            .await?;
        // 故意不设 rss.tenant_id → current_setting 返 NULL → RLS USING 全过滤。
        let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_entries")
            .fetch_one(&mut *tx)
            .await?;
        assert_eq!(
            cnt.0, 0,
            "TA11: rss_app + 未设 rss.tenant_id → NULL → RLS fail-closed（0 行）"
        );
        tx.rollback().await?;
    }

    store.shutdown().await?;
    Ok(())
}

/// TA12: 空租户链 list → Ok（空结果），verify_tail → Ok（空链无前驱）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ta12_audit_empty_tenant_list_and_verify_tail_ok() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = make_audit_repo(&store);

    let result = repo.list(tenant, audit_page(10, None)).await?;
    assert!(result.entries.is_empty(), "TA12: 空租户 list 须空");
    assert!(!result.has_more);

    repo.verify_tail(tenant, 10).await?;

    store.shutdown().await?;
    Ok(())
}

// ── TA13–TA14: hydrate_row 错误臂覆盖 ─────────────────────────────────────────
//
// TA13: entry_hash 错误字节长度（bypasss CHECK 约束后注入短 bytea）→ list 返回 AuditError::Storage
// TA14: 未知 actor_kind（bypass CHECK 约束后注入不在闭值集中的文本）→ list 返回 AuditError::Storage
//
// 以 superuser（store.pool 默认连接角色）DROP IF EXISTS 临时删除列级 CHECK 约束，UPDATE 注入非法值，
// 再通过 repo.list 触发 hydrate_row 的错误臂——复用 TA8 的超级用户篡改模式（FORCE RLS 对 owner 也生效，
// 但 store.pool 是 superuser，superuser 绕过 RLS、能执行 DDL）。
// compile-check only（无 docker）：断言结构正确、类型正确；运行期约束名须与 PostgreSQL 自动生成名匹配。

/// TA13: hydrate_row wrong-length entry_hash — 超级用户临时删 CHECK 约束后注入短 bytea，
/// list 读取时 try_into 失败 → `Err(AuditError::Storage(...))`（bytea-length arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta13_audit_hydrate_row_wrong_length_entry_hash_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(make_audit_record(tenant, 0)).await?;

    // 超级用户临时删 entry_hash 长度 CHECK 约束（PostgreSQL 自动命名 audit_entries_entry_hash_check），
    // 注入错误长度 bytea（10B ≠ 32B）以覆盖 hydrate_row wrong-length arm。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_entry_hash_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query("UPDATE audit_entries SET entry_hash = $1 WHERE tenant_id = $2::uuid AND seq = 0")
        .bind(vec![0xBBu8; 10]) // 10B != 32B，触发 hydrate_row try_into 失败臂
        .bind(&tenant_str)
        .execute(&store.pool)
        .await?;

    let result = repo.list(tenant, audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA13: 错误长度 entry_hash 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}

/// TA14: hydrate_row unknown actor_kind — 超级用户临时删 CHECK 约束后注入闭值集外文本，
/// list 读取时 actor_kind_from_db 返回 None → `Err(AuditError::Storage(...))`（unknown-enum arm 覆盖）。
#[cfg(feature = "integration")]
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造——UUID v4 + audit_page 参数已知合法；item-level carve-out。
async fn ta14_audit_hydrate_row_unknown_actor_kind_returns_storage() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_str = uuid::Uuid::new_v4().to_string();
    let tenant = vocab::TenantId::parse(&tenant_str).unwrap();
    let repo = make_audit_repo(&store);

    repo.append(make_audit_record(tenant, 0)).await?;

    // 超级用户临时删 actor_kind IN 值集 CHECK 约束（PostgreSQL 自动命名 audit_entries_actor_kind_check），
    // 注入闭值集外的 actor_kind 文本以覆盖 hydrate_row actor_kind_from_db → None 的错误臂。
    sqlx::query(
        "ALTER TABLE audit_entries DROP CONSTRAINT IF EXISTS audit_entries_actor_kind_check",
    )
    .execute(&store.pool)
    .await?;
    sqlx::query(
        "UPDATE audit_entries SET actor_kind = 'robot' WHERE tenant_id = $1::uuid AND seq = 0",
    )
    .bind(&tenant_str)
    .execute(&store.pool)
    .await?;

    let result = repo.list(tenant, audit_page(10, None)).await;
    assert!(
        matches!(result, Err(audit::ports::AuditError::Storage(_))),
        "TA14: 未知 actor_kind 须返回 AuditError::Storage（实际为 Ok 或其它 Err 变体）"
    );

    store.shutdown().await?;
    Ok(())
}
