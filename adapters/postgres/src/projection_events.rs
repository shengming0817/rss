//! PostgreSQL projection_events adapter（append-only changelog 源，#1122）。
//!
//! [`PgProjectionEvents`] 提供两条路径：
//! - `append`（**crate 内 sanctioned 写入入口，非公开**）：生产侧写，INSERT RETURNING id 作 Lsn 源（DB IDENTITY 单调）。
//! - `read_from`（公开）：replay 读，`id > after ORDER BY id ASC LIMIT limit`，喂投影 harness。
//!
//! **写入口 sealed（eventbus.md §Projection）**：`projection_events` 须由 emit 期同事务双写装饰器写入、
//! append 收口单一 sanctioned 路径、双写 topic 集从域投影声明派生（非手写）。本 PR 先把 `append` +
//! `NewProjectionEvent` 降为 **`pub(crate)` 受控入口**（不 re-export，外部 crate 无法手写全局 journal）；
//! 完整 co-tx 双写 decorator + 派生 topic 绑定随 bootstrap/emit wiring 落地（GitHub issue 跟踪，本 PR 外）。
//!
//! **append-only**：当前由 dylint `rss_projection_append_only`（Medium，代码侧 DELETE/TRUNCATE 字面量）守；
//! DB 引擎 `REVOKE UPDATE, DELETE` 主守卫（Hard）待 dual-pool projection serving role 落地一并接
//! （projection_events 全局表当前不授任何 serving role，对齐 outbox/saga_journal/checkpoint，见 migration 注释）。
//! INVARIANT PROJECTION-APPEND-ONLY-01。
//!
//! **全局表**：无 tenant_id / 无 RLS，对标 outbox/saga_journal/checkpoint。
//!
//! **固有方法（非注入 port）**：事件源由 adapter 直接持有，harness 不注入源（方案 B）。
//!
//! **时间戳**：`occurred_at`/`created_at` 用 DB DEFAULT `now()`（不注入 Clock，
//! 对标 saga_journal/checkpoint）。
//!
//! **错误 PII 边界**：sqlx 错误不进 Display——经 [`ProjectionEventsError::new`] 包成
//! source（error-handling.md §Message 与 PII）。
//!
//! ref: adapters/postgres/src/saga_journal.rs（append-only adapter 范式）。

use consistency::{Lsn, PartitionSerialDelivery, ProjectionEvent, Topic};
use diport::RedactedSource;
use sqlx::PgPool;

use crate::PgStore;

/// PostgreSQL projection_events adapter（append-only changelog 源）。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::projection_events`] 构造（`PgStore::projection_events` 为 `pub(crate)` funnel）。
pub struct PgProjectionEvents {
    pool: PgPool,
}

impl PgStore {
    /// 构造 [`PgProjectionEvents`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::projection_events`] 收口。
    pub(crate) fn projection_events(&self) -> PgProjectionEvents {
        PgProjectionEvents {
            pool: self.pool.clone(),
        }
    }
}

/// append 入参（生产侧构造；id 由 DB IDENTITY 自动生成单调序，不在此结构携带）。
///
/// **`pub(crate)` 受控入口（eventbus.md §Projection sealed 写入）**：不 re-export，外部 crate 无法命名/构造，
/// 杜绝任意 caller 手写全局 projection journal。完整派生 topic 绑定随 emit 期 co-tx 双写 decorator 落地（本 PR 外）。
#[allow(dead_code)]
// reason: sanctioned 写入入口，当前仅 integration 测试构造；生产 caller = 未来 emit co-tx 双写 decorator
// （wiring 本 PR 外）。默认 build 无生产 caller，同 tx.rs::run_in_transaction 范式（pub(crate) 受控入口待接线）。
pub(crate) struct NewProjectionEvent {
    /// 事件所属域（如 `"identity"`）。
    pub(crate) domain: String,
    /// 聚合根标识（如 `"user-uuid"`）。
    pub(crate) aggregate_id: String,
    /// 规范 topic（canonical dotted，= `event_type` 列）。
    pub(crate) event_type: Topic,
    /// 已编码 payload（投影器解码到读模型；解码不在本接缝）。
    pub(crate) payload: Vec<u8>,
    /// 可选关联 ID（tracing / 链路追踪用）。
    ///
    /// **PII 边界**：仅限不含 PII 的 trace-span / request ID（如 `X-Request-Id` / `tracing::Span` id）；
    /// 不得携带用户标识、设备 ID、tenant 凭据等业务数据。
    pub(crate) correlation_id: Option<String>,
}

impl PgProjectionEvents {
    /// 追加一条投影事件，RETURNING id → Lsn。
    ///
    /// `occurred_at`/`created_at` 走 DB DEFAULT `now()`；id 由 `GENERATED ALWAYS AS IDENTITY`
    /// 单调自增，直接作 Lsn 源。sqlx 错误不进 Display——经 [`ProjectionEventsError::new`] 包成
    /// source（PII 边界）。
    ///
    /// **`pub(crate)` sanctioned 写入（eventbus.md §Projection sealed 写入入口）**：不 re-export，
    /// 外部 crate 不可手写全局 journal；emit 期 co-tx 双写 decorator 经此唯一受控路径写入（接线本 PR 外）。
    #[allow(dead_code)]
    // reason: 当前仅 integration 测试调用；生产 caller = 未来 emit co-tx 双写 decorator（wiring 本 PR 外）。
    // 同 tx.rs::run_in_transaction 范式（pub(crate) 受控入口待接线，默认 build 无生产 caller）。
    pub(crate) async fn append(
        &self,
        ev: NewProjectionEvent,
    ) -> Result<Lsn, ProjectionEventsError> {
        let (id,): (i64,) = sqlx::query_as(
            r#"
            INSERT INTO projection_events (domain, aggregate_id, event_type, payload, correlation_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(&ev.domain)
        .bind(&ev.aggregate_id)
        .bind(ev.event_type.as_str())
        .bind(ev.payload.as_slice())
        .bind(ev.correlation_id.as_deref())
        .fetch_one(&self.pool)
        .await
        .map_err(ProjectionEventsError::new)?;

        let lsn_u64 = u64::try_from(id).map_err(ProjectionEventsError::new)?;
        Ok(Lsn::new(lsn_u64))
    }

    /// 读 `id > after` 的事件，按 id 升序，最多 `limit` 条（replay / tail 喂 harness）。
    ///
    /// sqlx 错误不进 Display——经 [`ProjectionEventsError::new`] 包成 source（PII 边界）。
    /// `event_type` 解析失败升 Invariant 错误（我们写入的数据不该含无效 topic）。
    ///
    /// **批大小指引**：推荐小批（如 200–1000 条）分批驱动；超大 `limit` 会导致 DB 单次查询压力过大，
    /// harness 应以小批 tail 循环调用（内存 + 延迟权衡）。
    pub async fn read_from(
        &self,
        after: Lsn,
        limit: u32,
    ) -> Result<Vec<PgProjectionRecord>, ProjectionEventsError> {
        let after_i64 = i64::try_from(after.get()).map_err(ProjectionEventsError::new)?;
        let limit_i64 = i64::from(limit);

        let rows: Vec<(i64, String, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT id, event_type, payload
            FROM projection_events
            WHERE id > $1
            ORDER BY id ASC
            LIMIT $2
            "#,
        )
        .bind(after_i64)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(ProjectionEventsError::new)?;

        rows.into_iter()
            .map(|(id, event_type_str, payload)| {
                let lsn_u64 = u64::try_from(id).map_err(ProjectionEventsError::new)?;
                let lsn = Lsn::new(lsn_u64);
                let topic = Topic::parse(&event_type_str).map_err(|_| {
                    ProjectionEventsError::new(InvariantError(
                        "invalid event_type in projection_events",
                    ))
                })?;
                Ok(PgProjectionRecord {
                    lsn,
                    topic,
                    payload,
                })
            })
            .collect()
    }
}

/// 从 DB 读出的一条投影事件记录，impl [`consistency::ProjectionEvent`]。
///
/// `payload` 经手写 `Debug` 脱敏（渲 `<redacted>`），对标 [`diport::JournalEntry`] PII 边界。
/// 字段私有——外部经 trait 方法（`topic`/`lsn`/`payload`）读取，不可伪造。
pub struct PgProjectionRecord {
    lsn: Lsn,
    topic: Topic,
    payload: Vec<u8>,
}

// PII 边界：payload 可能含 PII，不进 Debug；lsn / topic 安全可见（对标 JournalEntry.output 脱敏范式）。
impl std::fmt::Debug for PgProjectionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgProjectionRecord")
            .field("lsn", &self.lsn)
            .field("topic", &self.topic)
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl ProjectionEvent for PgProjectionRecord {
    fn topic(&self) -> &Topic {
        &self.topic
    }

    fn lsn(&self) -> Lsn {
        self.lsn
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// `PgProjectionEvents` 是串行有序 source：`read_from` 以 `ORDER BY id ASC` 全局单调序逐行交付，
/// 满足 [`PartitionSerialDelivery`] 契约（消费方按此 bound 铸造 `SerialInOrder` witness）。
///
/// INVARIANT: ADAPTER-PORT-FREEZE-14 —— PartitionSerialDelivery on PgProjectionEvents；
/// 去掉 impl 或 read_from 改为非顺序查询即编译失败（smoke 测试 anti-vacuity）。
impl PartitionSerialDelivery for PgProjectionEvents {}

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// projection_events 操作失败（infra 故障）。
///
/// PII 边界（对标 [`diport::SagaJournalError`] 范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`）。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01。
#[derive(Debug, thiserror::Error)]
#[error("projection_events operation failed")]
pub struct ProjectionEventsError {
    #[source]
    source: RedactedSource,
}

impl ProjectionEventsError {
    /// 把 adapter 内部错误包成 projection_events 操作失败。原始错误仅作 internal source 保留，
    /// 不经 `Display` 暴露（PII 边界）。
    pub fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            source: RedactedSource::new(source),
        }
    }
}

// ── internal error helper ─────────────────────────────────────────────────────

/// Invariant parse 失败（`event_type` 无法从 DB 值解析为合法 Topic）——我们写入的数据不该
/// 含无效值；进 [`ProjectionEventsError::new`] source，不 unwrap。
#[derive(Debug)]
struct InvariantError(&'static str);

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvariantError {}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：`PgProjectionRecord: ProjectionEvent`（via trait bound）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-13 —— ProjectionEvent on PgProjectionRecord；
    //! 去掉 impl 即编译失败（anti-vacuity）。

    use core::marker::PhantomData;

    use consistency::{PartitionSerialDelivery, ProjectionEvent};

    fn assert_projection_event<T: ProjectionEvent>(_: PhantomData<T>) {}

    #[test]
    fn pg_projection_record_impl_frozen() {
        assert_projection_event(PhantomData::<super::PgProjectionRecord>);
    }

    /// INVARIANT: ADAPTER-PORT-FREEZE-14 —— PartitionSerialDelivery on PgProjectionEvents；
    /// 去掉 impl 即编译失败（smoke anti-vacuity）。
    fn _assert_partition_serial<T: PartitionSerialDelivery>() {}

    #[test]
    fn pg_projection_events_partition_serial_impl_frozen() {
        _assert_partition_serial::<super::PgProjectionEvents>();
    }

    /// drift 测试：断言 0010 migration 含 append-only 强制（`REVOKE UPDATE, DELETE`）、
    /// 不含 `tenant_id` / `ENABLE ROW LEVEL SECURITY`（全局表，无 RLS）、
    /// **不含 `TO rss_app`**（全局 payload 表不授 tenant serving role，闭跨租读边界，#1122 F2）。
    ///
    /// INVARIANT: PROJECTION-APPEND-ONLY-01（DB 引擎 REVOKE serving-role 主守卫待 dual-pool；当前
    /// dylint Medium + 本 drift Medium 辅守卫）。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试解析编译期 include_str! 的已知 migration 文本，缺关键子句应 fail；
    // item-level carve-out（error-handling.md §Carve-out）。
    fn projection_events_migration_append_only_and_no_rls() {
        const MIGRATION: &str = include_str!("../migrations/0010_create_projection_events.sql");

        // append-only 强制：必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）。
        // anti-vacuity：migration 文本非空，此断言可失败（若去掉 REVOKE 子句即红）。
        assert!(
            MIGRATION.contains("REVOKE UPDATE, DELETE"),
            "migration 0010 必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）"
        );

        // 全局表：不含 tenant_id（对标 outbox/saga_journal/checkpoint）。
        assert!(
            !MIGRATION.contains("tenant_id"),
            "projection_events 是全局表，不应含 tenant_id"
        );

        // 全局表：不含 ENABLE ROW LEVEL SECURITY。
        assert!(
            !MIGRATION.contains("ENABLE ROW LEVEL SECURITY"),
            "projection_events 是全局表，不应含 ENABLE ROW LEVEL SECURITY"
        );

        // 跨租读边界（#1122 F2）：全局 payload 表不授 tenant serving role rss_app（对齐 outbox）。
        // anti-vacuity：migration 非空且含其它 GRANT/REVOKE 语义，此断言可失败（若误加 `TO rss_app` 即红）。
        assert!(
            !MIGRATION.contains("TO rss_app"),
            "projection_events 不得授 serving role rss_app（全局 payload 表跨租读边界，对齐 outbox；#1122 F2）"
        );
    }
}

/// 集成测试：`PgProjectionEvents` append → read_from 往返
/// （`integration` feature 门控；需真实 postgres）。
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use consistency::{Lsn, ProjectionEvent, Topic};

    use super::NewProjectionEvent;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// append 3 条（不同 domain/aggregate/topic）→ read_from(0,10) 回 3 条 id 升序且单调；
    /// read_from(第2条 id, 10) 仅回 id > 该值的条目。
    /// 验证 Topic 往返、payload 往返。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    // reason: 集成测试 happy-path，已知合法值构造；item-level carve-out（error-handling.md §Carve-out）。
    async fn projection_events_append_read_roundtrip() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let pe = store.projection_events();

        // append 3 条事件（新 DB，无先前数据）。
        let topic1 = Topic::parse("identity.user.created").unwrap();
        let topic2 = Topic::parse("settings.config.updated").unwrap();
        let topic3 = Topic::parse("audit.entry.written").unwrap();

        let lsn1 = pe
            .append(NewProjectionEvent {
                domain: "identity".to_string(),
                aggregate_id: "user-001".to_string(),
                event_type: topic1,
                payload: b"payload1".to_vec(),
                correlation_id: None,
            })
            .await?;
        let lsn2 = pe
            .append(NewProjectionEvent {
                domain: "settings".to_string(),
                aggregate_id: "cfg-001".to_string(),
                event_type: topic2,
                payload: b"payload2".to_vec(),
                correlation_id: Some("corr-001".to_string()),
            })
            .await?;
        let lsn3 = pe
            .append(NewProjectionEvent {
                domain: "audit".to_string(),
                aggregate_id: "audit-001".to_string(),
                event_type: topic3,
                payload: b"payload3".to_vec(),
                correlation_id: None,
            })
            .await?;

        // id 单调递增。
        assert!(
            lsn1.get() < lsn2.get() && lsn2.get() < lsn3.get(),
            "id 应单调递增: {} < {} < {}",
            lsn1.get(),
            lsn2.get(),
            lsn3.get()
        );

        // read_from(0) → 3 条，按 id 升序。
        let all = pe.read_from(Lsn::new(0), 10).await?;
        assert_eq!(all.len(), 3, "应有 3 条事件");
        assert_eq!(all[0].lsn().get(), lsn1.get(), "第1条 lsn 不符");
        assert_eq!(all[1].lsn().get(), lsn2.get(), "第2条 lsn 不符");
        assert_eq!(all[2].lsn().get(), lsn3.get(), "第3条 lsn 不符");

        // Topic 往返。
        assert_eq!(
            all[0].topic().as_str(),
            "identity.user.created",
            "topic[0] 往返"
        );
        assert_eq!(
            all[1].topic().as_str(),
            "settings.config.updated",
            "topic[1] 往返"
        );
        assert_eq!(
            all[2].topic().as_str(),
            "audit.entry.written",
            "topic[2] 往返"
        );

        // payload 往返。
        assert_eq!(all[0].payload(), b"payload1", "payload[0] 往返");
        assert_eq!(all[1].payload(), b"payload2", "payload[1] 往返");
        assert_eq!(all[2].payload(), b"payload3", "payload[2] 往返");

        // read_from(lsn2) → 仅 lsn3。
        let tail = pe.read_from(Lsn::new(lsn2.get()), 10).await?;
        assert_eq!(tail.len(), 1, "lsn2 之后仅有 1 条");
        assert_eq!(tail[0].lsn().get(), lsn3.get(), "tail 中仅 lsn3");

        Ok(())
    }
}
