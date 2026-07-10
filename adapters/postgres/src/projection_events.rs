//! PostgreSQL projection_events adapter（append-only changelog 源，#1122/#1628）。
//!
//! 写路径没有 naked `PgPool` / `PgConnection` append API。生产 outbox 持久化在同一事务内拿
//! [`crate::cotx::TxCapability`] 调 [`append_projection_event_if_bound`]，该 helper 仅在 outbox `event_id`
//! 新插入且 `(contract_id, version, schema_hash, topic)` 命中 generated [`ProjectionWriteRegistry`] 时，
//! 调用 DB 固定 `rss_append_projection_event(...)` 函数写入 projection journal。
//!
//! 读路径调用 DB 固定 `rss_read_projection_events(...)` 函数。`rss_app` 只拿函数 EXECUTE，不持
//! `projection_events` 表级 SELECT/INSERT/UPDATE/DELETE 权限。
//!
//! **append-only**：DB 层 `REVOKE UPDATE, DELETE` + fixed-shape SECURITY DEFINER functions 是主守卫；
//! 代码侧不保留裸 append 函数。INVARIANT PROJECTION-APPEND-ONLY-01。
//!
//! **全局表**：无 tenant_id / 无 RLS，是 projection changelog 的显式特例；outbox 与 saga journal
//! 均已 tenant-scoped。
//!
//! **事件源接缝**：adapter 实现 `consistency::ProjectionEventSource`，返回 engine-owned
//! `ProjectionEventRecord`；harness 当前仍不注入源（方案 B）。
//!
//! **时间戳**：`occurred_at`/`created_at` 用 DB DEFAULT `now()`（不注入 Clock，
//! 对标 DB-owned journal/changelog timestamp）。
//!
//! **错误 PII 边界**：append 路径 sqlx 错误不进 Display——经 [`ProjectionEventsError::new`] 包成
//! source；read source 路径只返回 [`EngineError`] 分类（error-handling.md §Message 与 PII）。
//!
//! ref: adapters/postgres/src/saga.rs（tenant-scoped append-only journal 范式）。

use consistency::{
    EngineError, EngineErrorKind, EventTopic, Lsn, PartitionSerialDelivery, ProjectionBatchLimit,
    ProjectionEventMetadata, ProjectionEventRecord, ProjectionEventSource,
};
use diport::RedactedSource;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use vocab::ProjectionInputBinding;

use crate::PgStore;
use crate::cotx::TxCapability;
use crate::outbox::{OutboxEnvelope, ReplayedOutboxAppend};

/// PostgreSQL projection_events adapter（append-only changelog 源）。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::projection_events`] 构造（`PgStore::projection_events` 为 `pub(crate)` funnel）。
pub struct PgProjectionEvents {
    pool: PgPool,
}

/// Generated projection writer registry.
///
/// Constructed only from `generated::event::PROJECTION_INPUTS` (or test fixtures) and consumed by
/// postgres writer funnels to decide whether an inserted outbox fact is mirrored into
/// `projection_events`. There is no API to add raw `(contract_id, topic)` pairs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProjectionWriteRegistry {
    bindings: &'static [ProjectionInputBinding],
}

impl ProjectionWriteRegistry {
    pub(crate) const fn from_generated(bindings: &'static [ProjectionInputBinding]) -> Self {
        Self { bindings }
    }

    pub(crate) const fn empty() -> Self {
        Self { bindings: &[] }
    }

    pub(crate) fn is_bound(
        &self,
        contract_id: &str,
        contract_version: &str,
        schema_hash: &str,
        topic: &str,
    ) -> bool {
        self.bindings.iter().any(|binding| {
            binding.contract_id() == contract_id
                && binding.version() == contract_version
                && binding.schema_hash() == schema_hash
                && binding.topic() == topic
        })
    }
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

    /// Add one deployment generation to the DB-side projection input registry.
    ///
    /// This runs during [`crate::PgRuntimeDeps::setup`] on the migrator connection. Runtime
    /// `rss_app` can execute the fixed append function, but the function only accepts rows whose
    /// outbox metadata matches this DB-side generated registry.
    pub(crate) async fn register_projection_input_bindings(
        &self,
        generation: &'static str,
        bindings: &'static [ProjectionInputBinding],
    ) -> Result<(), sqlx::Error> {
        let expected = projection_input_generation(bindings);
        if generation != expected {
            return Err(sqlx::Error::Protocol(
                "generated projection input generation does not match binding set".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        for binding in bindings {
            sqlx::query(
                r#"
                SELECT rss_register_projection_input_binding($1, $2, $3, $4, $5)
                "#,
            )
            .bind(generation)
            .bind(binding.contract_id())
            .bind(binding.version())
            .bind(binding.schema_hash())
            .bind(binding.topic())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
}

fn projection_input_generation(bindings: &[ProjectionInputBinding]) -> String {
    let mut tuples = bindings
        .iter()
        .map(|binding| {
            (
                binding.contract_id(),
                binding.version(),
                binding.schema_hash(),
                binding.topic(),
            )
        })
        .collect::<Vec<_>>();
    tuples.sort_unstable();

    let mut digest = Sha256::new();
    for tuple in tuples {
        for value in [tuple.0, tuple.1, tuple.2, tuple.3] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
    }
    format!("sha256:{:x}", digest.finalize())
}

/// Mirror an inserted outbox fact into projection_events when generated workflow metadata binds it.
///
/// This function accepts only [`TxCapability`], so it can run solely inside the same transaction as
/// the outbox insert. It intentionally returns `Ok(None)` for unbound facts.
pub(crate) async fn append_projection_event_if_bound(
    tx: &mut TxCapability<'_>,
    entry: &consistency::EventEntry,
    env: &OutboxEnvelope,
    registry: &ProjectionWriteRegistry,
) -> Result<Option<Lsn>, sqlx::Error> {
    if !registry.is_bound(
        env.contract_id(),
        env.contract_version(),
        env.schema_hash(),
        entry.topic().as_str(),
    ) {
        return Ok(None);
    }

    let aggregate_id = env.partition_key().unwrap_or(entry.idem_key().as_str());
    let metadata_json = env.metadata_json();
    append_projection_event(
        tx,
        ProjectionAppend {
            event_id: entry.idem_key().as_str(),
            domain: env.domain(),
            aggregate_id,
            topic: entry.topic().as_str(),
            payload: entry.payload(),
            correlation_id: env.causation_id(),
            contract_id: env.contract_id(),
            contract_version: env.contract_version(),
            schema_hash: env.schema_hash(),
            metadata_json: &metadata_json,
            partition_key: env.partition_key(),
            causation_id: env.causation_id(),
        },
    )
    .await
    .map(Some)
}

pub(crate) async fn append_replayed_projection_event_if_bound(
    tx: &mut TxCapability<'_>,
    replay: &ReplayedOutboxAppend,
    registry: &ProjectionWriteRegistry,
) -> Result<Option<Lsn>, sqlx::Error> {
    if !registry.is_bound(
        &replay.contract_id,
        &replay.contract_version,
        &replay.schema_hash,
        &replay.topic,
    ) {
        return Ok(None);
    }

    append_projection_event(
        tx,
        ProjectionAppend {
            event_id: &replay.event_id,
            domain: &replay.domain,
            aggregate_id: &replay.event_id,
            topic: &replay.topic,
            payload: &replay.payload,
            correlation_id: replay.causation_id.as_deref(),
            contract_id: &replay.contract_id,
            contract_version: &replay.contract_version,
            schema_hash: &replay.schema_hash,
            metadata_json: &replay.metadata_json,
            partition_key: None,
            causation_id: replay.causation_id.as_deref(),
        },
    )
    .await
    .map(Some)
}

struct ProjectionAppend<'a> {
    event_id: &'a str,
    domain: &'a str,
    aggregate_id: &'a str,
    topic: &'a str,
    payload: &'a [u8],
    correlation_id: Option<&'a str>,
    contract_id: &'a str,
    contract_version: &'a str,
    schema_hash: &'a str,
    metadata_json: &'a str,
    partition_key: Option<&'a str>,
    causation_id: Option<&'a str>,
}

async fn append_projection_event(
    tx: &mut TxCapability<'_>,
    append: ProjectionAppend<'_>,
) -> Result<Lsn, sqlx::Error> {
    let (id,): (i64,) = sqlx::query_as(
        r#"
        SELECT rss_append_projection_event(
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12
        )
        "#,
    )
    .bind(append.event_id)
    .bind(append.domain)
    .bind(append.aggregate_id)
    .bind(append.topic)
    .bind(append.payload)
    .bind(append.correlation_id)
    .bind(append.contract_id)
    .bind(append.contract_version)
    .bind(append.schema_hash)
    .bind(append.metadata_json)
    .bind(append.partition_key)
    .bind(append.causation_id)
    .fetch_one(tx.conn())
    .await?;

    let lsn = u64::try_from(id).map_err(|err| sqlx::Error::Decode(Box::new(err)))?;
    Ok(Lsn::new(lsn))
}

impl PgProjectionEvents {
    /// 读 `id > after` 的事件，按 id 升序，最多 `limit` 条（replay / tail 喂 harness）。
    ///
    /// sqlx 错误映射为 [`EngineErrorKind::Transient`]；`event_type` / id 解析失败映射为
    /// [`EngineErrorKind::Invariant`]（我们写入的数据不该含无效 topic / id）。
    ///
    /// `ProjectionBatchLimit` 在调用边界保证非零且不超过 1000；harness 应以小批 tail 循环调用
    /// （内存 + 延迟权衡）。
    pub async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        // projection_events.id 是 BIGSERIAL/IDENTITY 1-based；`None` 表示从起点读，映射到 DB
        // 函数的 exclusive `after=0`。
        let after_i64 = after
            .map(|lsn| lsn.get())
            .map(i64::try_from)
            .transpose()
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?
            .unwrap_or(0);
        let limit_i64 = i64::from(limit.get());

        let rows: Vec<ProjectionEventRow> = sqlx::query_as(
            r#"
            SELECT id, event_id, domain, event_type, payload, contract_id, contract_version,
                   schema_hash, metadata, partition_key, causation_id
            FROM rss_read_projection_events($1, $2::integer)
            "#,
        )
        .bind(after_i64)
        .bind(limit_i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| EngineError::new(EngineErrorKind::Transient))?;

        rows.into_iter()
            .map(
                |(
                    id,
                    event_id,
                    domain,
                    event_type_str,
                    payload,
                    contract_id,
                    contract_version,
                    schema_hash,
                    metadata,
                    partition_key,
                    causation_id,
                )| {
                    let lsn_u64 = u64::try_from(id)
                        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                    let lsn = Lsn::new(lsn_u64);
                    let topic = EventTopic::parse(&event_type_str)
                        .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                    let tenant = metadata
                        .get(diport::KEY_TENANT_ID)
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))
                        .and_then(|raw| {
                            vocab::TenantId::parse(raw)
                                .map_err(|_| EngineError::new(EngineErrorKind::Invariant))
                        })?;
                    let metadata = ProjectionEventMetadata::new(
                        tenant,
                        event_id,
                        domain,
                        contract_id,
                        contract_version,
                        schema_hash,
                        metadata,
                        partition_key,
                        causation_id,
                    );
                    Ok(ProjectionEventRecord::with_metadata(
                        lsn, topic, payload, metadata,
                    ))
                },
            )
            .collect()
    }
}

type ProjectionEventRow = (
    i64,
    String,
    String,
    String,
    Vec<u8>,
    String,
    String,
    String,
    serde_json::Value,
    Option<String>,
    Option<String>,
);

/// `PgProjectionEvents` 是串行有序 source：`read_from` 以 `ORDER BY id ASC` 全局单调序逐行交付，
/// 满足 [`PartitionSerialDelivery`] 契约（消费方按此 bound 铸造 `SerialInOrder` witness）。
///
/// INVARIANT: ADAPTER-PORT-FREEZE-14 { level = "Medium", exec = "manual/opt-in", source = "code" }—— PartitionSerialDelivery on PgProjectionEvents；
/// 去掉 impl 或 read_from 改为非顺序查询即编译失败（smoke 测试 anti-vacuity）。
impl PartitionSerialDelivery for PgProjectionEvents {}

impl ProjectionEventSource for PgProjectionEvents {
    async fn read_from(
        &self,
        after: Option<Lsn>,
        limit: ProjectionBatchLimit,
    ) -> Result<Vec<ProjectionEventRecord>, EngineError> {
        PgProjectionEvents::read_from(self, after, limit).await
    }
}

// ── 错误 ──────────────────────────────────────────────────────────────────────

/// projection_events 操作失败（infra 故障）。
///
/// PII 边界（对标 [`diport::SagaJournalError`] 范式）：`Display` 仅安全摘要常量；source 经
/// [`RedactedSource`] 脱敏（`Debug`/`Display` 固定 `<redacted>`、`Error::source()` 恒 `None`）。
/// 见 INVARIANT: DIPORT-ERR-SOURCE-REDACT-01 { level = "Medium", exec = "manual/opt-in", source = "code" }。
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

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：projection event record 归 consistency，`PgProjectionEvents` 只实现事件源。

    use core::marker::PhantomData;

    use consistency::{
        PartitionSerialDelivery, ProjectionEvent, ProjectionEventRecord, ProjectionEventSource,
    };

    fn assert_projection_event<T: ProjectionEvent>(_: PhantomData<T>) {}

    #[test]
    fn projection_event_record_impl_frozen() {
        assert_projection_event(PhantomData::<ProjectionEventRecord>);
    }

    fn assert_projection_event_source<T: ProjectionEventSource>() {}

    #[test]
    fn pg_projection_events_source_impl_frozen() {
        assert_projection_event_source::<super::PgProjectionEvents>();
    }

    /// INVARIANT: ADAPTER-PORT-FREEZE-14 { level = "Medium", exec = "manual/opt-in", source = "code" }—— PartitionSerialDelivery on PgProjectionEvents；
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
        const MIGRATION: &str = include_str!("../migrations/0013_create_projection_events.sql");

        // append-only 强制：必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）。
        // anti-vacuity：migration 文本非空，此断言可失败（若去掉 REVOKE 子句即红）。
        assert!(
            MIGRATION.contains("REVOKE UPDATE, DELETE"),
            "migration 0010 必须含 REVOKE UPDATE, DELETE（PROJECTION-APPEND-ONLY-01）"
        );

        // 全局表：不含 tenant_id（对标 checkpoint；outbox/saga_journal 已 tenant-scoped）。
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

    /// INVARIANT: PROJECTION-INPUT-GENERATION-01 { level = "Medium", exec = "manual/opt-in", source = "code", synthetic_red = "projection_input_registry_is_generation_bound_and_additive rejects destructive runtime replacement", anti_vacuity = "migration carrier and runtime source are both scanned" }.
    #[test]
    fn projection_input_registry_is_generation_bound_and_additive() {
        const MIGRATION: &str =
            include_str!("../migrations/0054_generation_bound_projection_registry.sql");
        const SOURCE: &str = include_str!("projection_events.rs");

        assert!(MIGRATION.contains("ADD COLUMN generation text"));
        assert!(MIGRATION.contains("ALTER COLUMN generation SET NOT NULL"));
        assert!(MIGRATION.contains("rss_register_projection_input_binding"));
        assert!(MIGRATION.contains("rss_retire_projection_input_generation"));
        assert!(MIGRATION.contains("PRIMARY KEY (generation,"));
        let destructive_replace = ["DELETE FROM", "projection_input_bindings"].join(" ");
        assert!(
            !SOURCE.contains(&destructive_replace),
            "runtime startup must never destructively replace the projection registry"
        );
    }

    #[test]
    fn projection_input_generation_is_order_independent_and_tuple_complete() {
        const HASH_A: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const HASH_B: &str =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const A: vocab::ProjectionInputBinding = vocab::ProjectionInputBinding::from_static(
            "projection-a",
            "owner",
            "owner.contract-a",
            "v1",
            HASH_A,
            "owner.fact-a",
        );
        const B: vocab::ProjectionInputBinding = vocab::ProjectionInputBinding::from_static(
            "projection-b",
            "owner",
            "owner.contract-b",
            "v2",
            HASH_B,
            "owner.fact-b",
        );

        let forward = super::projection_input_generation(&[A, B]);
        let reversed = super::projection_input_generation(&[B, A]);
        assert_eq!(forward, reversed);
        assert!(forward.starts_with("sha256:"));
        assert_eq!(forward.len(), "sha256:".len() + 64);

        let changed_topic = vocab::ProjectionInputBinding::from_static(
            "projection-a",
            "owner",
            "owner.contract-a",
            "v1",
            HASH_A,
            "owner.fact-changed",
        );
        assert_ne!(
            forward,
            super::projection_input_generation(&[changed_topic, B])
        );
    }
}
