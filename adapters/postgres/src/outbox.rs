//! Outbox 持久化实现——L2 OutboxFact adapter（#1117 P4）。
//!
//! [`PgOutbox`] impl [`consistency::OutboxSource`] / [`consistency::OutboxRelay`] /
//! [`consistency::OutboxSweeper`]——三个 native AFIT trait（泛型静态分发，非 dyn，不引 dynosaur）。
//!
//! **`append_outbox`**（`pub(crate)` free fn，收 `&mut sqlx::PgConnection`）是 L1 原子性的编译期硬约束：
//! 只能在已有事务内调用，不能脱离事务双写；调用方（域 crate 业务写路径）经 `PgStore::run_in_transaction`
//! 取 `&mut PgConnection` 后传入——类型系统天然阻止无事务直接调用（`PgPool` 无法隐式降级）。
//!
//! **CAS fencing**：`relay` 以 `event_id`（= `IdemKey::as_str()`）为键 `UPDATE ... RETURNING retry_count`，
//! 0 行 → 已被他人发或已 published → `Ok(Disposition::Ack)`，防二次 publish（at-least-once 幂等收口）。
//!
//! **崩溃重投**：`poll_pending` 捞回 `status='publishing' AND updated_at <= now() - LEASE_TTL` 的 stale 行；
//! relay 幂等 CAS 保证即使重投也至多 publish 一次。
//!
//! ref: serverlesstechnology/cqrs `persistence/postgres-es/src/event_repository.rs@main`
//! （`rows_affected()==1` 乐观锁 + UNIQUE 幂等 idiom 采纳来源）。

use consistency::{
    EngineError, EngineErrorKind, Entry, IdemKey, OutboxRelay, OutboxSource, OutboxSweeper, Topic,
};
use diport::{DynPublisher, PublishRequest, Publisher, PublisherError};
use sqlx::PgConnection;

use crate::PgStore;

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// relay 每次最多重试次数（含当次）；超过后转 dlx。
pub(crate) const MAX_PUBLISH_ATTEMPTS: i32 = 10;

/// `publishing` 状态 lease 过期阈值（秒）；超过后 poll_pending 重新捞回（崩溃重投）。
pub(crate) const LEASE_TTL_SECONDS: i64 = 60;

/// outbox status 值集——**生产单源**（F8）。所有 SQL 谓词 / SET 一律 `.bind(STATUS_*)`，不再内联裸
/// 字符串；与 migration `0002` 的 `CHECK (status IN (...))` 由 `status_consts_match_migration_check`
/// 解析对齐守（两处漂移即单测红，Medium anti-vacuity），单测亦复用同一单源。
pub(crate) const STATUS_PENDING: &str = "pending";
pub(crate) const STATUS_PUBLISHING: &str = "publishing";
pub(crate) const STATUS_PUBLISHED: &str = "published";
pub(crate) const STATUS_DLX: &str = "dlx";

// ── OutboxMetadata（typed sealed funnel，F1）──────────────────────────────────

/// envelope reserved key——调用方 metadata **不得**携带（由 envelope / 框架层注入，不容业务伪造）。
const RESERVED_METADATA_KEYS: [&str; 4] = ["trace", "correlation", "principal", "occurred_at"];

/// metadata 主体 id key（仅 opaque subject，不容完整 Principal / email / 姓名 / phone）。
const METADATA_SUBJECT_KEY: &str = "subjectId";

/// [`OutboxMetadata`] 构造错误（free-form key 命中 reserved 集）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum MetadataError {
    /// 调用方试图写 reserved envelope key（fail-closed 拒）。
    #[error("reserved outbox metadata key is not allowed")]
    ReservedKey,
}

/// Outbox envelope metadata——**sealed typed funnel**（私有内层 `Map`，仅经受控入口构造）。
///
/// 安全边界从「调用方注释自律」上移到类型层：raw `serde_json::Value` 入口已删，外部无法绕过；
/// reserved key（[`RESERVED_METADATA_KEYS`]）被 [`OutboxMetadata::try_insert`] fail-closed 拒；
/// principal 仅允许 opaque subject id（[`OutboxMetadata::with_subject_id`]，不容完整 Principal / PII，
/// `observability.md` §outbox envelope）。
///
/// # INVARIANT: OUTBOX-METADATA-FUNNEL-01
///
/// envelope metadata 只能经此 funnel 构造（Hard：无 raw `Value` 入口，reserved/PII 不可表达）；
/// reserved key 拒绝由 `metadata_try_insert_rejects_reserved_key` 负向单测守 anti-vacuity。
pub(crate) struct OutboxMetadata(serde_json::Map<String, serde_json::Value>);

impl OutboxMetadata {
    /// 空 metadata。
    pub(crate) fn new() -> Self {
        Self(serde_json::Map::new())
    }

    /// 设置 opaque 主体 id（唯一允许的 principal 形态——不容完整 Principal / PII）。
    /// 生产 caller：`PgEmitter::emit` 从 `diport::OutboxEnvelopeParts.subject_id` 组装（T008/#1100）。
    pub(crate) fn with_subject_id(mut self, subject_id: impl Into<String>) -> Self {
        self.0.insert(
            METADATA_SUBJECT_KEY.to_string(),
            serde_json::Value::String(subject_id.into()),
        );
        self
    }

    /// 插入 free-form key（fail-closed 拒 reserved key）。
    // reason(dead_code): 同 with_subject_id——生产 caller 在 T008/#1100 接入；负向单测行使 reserved 拒绝。
    #[allow(dead_code)]
    pub(crate) fn try_insert(
        &mut self,
        key: impl Into<String>,
        value: serde_json::Value,
    ) -> Result<(), MetadataError> {
        let key = key.into();
        if RESERVED_METADATA_KEYS.contains(&key.as_str()) {
            return Err(MetadataError::ReservedKey);
        }
        self.0.insert(key, value);
        Ok(())
    }

    /// 序列化为 JSON object 字符串（绑 `$N::jsonb` 用）。
    fn to_json_string(&self) -> String {
        serde_json::to_string(&self.0).unwrap_or_else(|_| "{}".to_string())
        // reason: Map<String, Value> 序列化理论上不失败（已验证 JSON 树）；
        // 即便极端情况失败，退化到空对象比 panic 更安全（不阻写路径）。
    }
}

impl Default for OutboxMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ── OutboxEnvelope ────────────────────────────────────────────────────────────

/// Outbox 行 envelope（adapter 本地，`pub(crate)`；由域写路径在 `append_outbox` 调用前构造）。
///
/// `metadata` 经 [`OutboxMetadata`] sealed funnel 收口（拒 reserved key + 仅 opaque subject id，
/// PII 边界；`observability.md` §outbox envelope）。
pub(crate) struct OutboxEnvelope {
    domain: String,
    contract_id: String,
    metadata: OutboxMetadata,
}

impl OutboxEnvelope {
    /// 构造 envelope（funnel；字段私有，仅经此入口）。
    /// 生产 caller：`PgEmitter::emit` 从 `diport::OutboxEnvelopeParts` 组装（T008/#1100）。
    pub(crate) fn new(domain: String, contract_id: String, metadata: OutboxMetadata) -> Self {
        Self {
            domain,
            contract_id,
            metadata,
        }
    }

    /// 借出 domain。
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    /// 借出 contract_id。
    pub(crate) fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// metadata 序列化为 JSON 字符串（绑 `$N::jsonb` 用）。
    pub(crate) fn metadata_json(&self) -> String {
        self.metadata.to_json_string()
    }
}

// ── append_outbox ─────────────────────────────────────────────────────────────

/// 在事务内向 outbox 双写一条 entry（L1 原子性硬约束）。
///
/// **`pub(crate)`，收 `&mut PgConnection`**——类型系统保证只能在已有事务内调用
/// （`PgStore::run_in_transaction` 的闭包参数，不可脱离事务直接取到 `&mut PgConnection`）。
///
/// ON CONFLICT (event_id) DO NOTHING：同 idem_key 的 entry 已在表中时幂等跳过（不报错）。
/// uuid/timestamptz 生成全部交给 server-side SQL（不给 sqlx 加 uuid/time feature）。
///
/// # INVARIANT: OUTBOX-ATOMIC-IDEM-01
///
/// outbox 双写必须在业务事务内原子执行——caller 须在 `run_in_transaction` 闭包内传入
/// `&mut PgConnection`；裸 `PgPool::acquire()` 拿到的连接类型不同，类型系统阻止误用（Hard）。
// 生产 caller：`PgEmitter::emit`（impl `diport::OutboxEmitter`）在事务内调用——域 crate 不直接 import 本
// adapter（域→adapter 反向依赖被 deny.toml 禁），域侧只经 `OutboxEmitter` port 触发该 durable 写路径（T008/#1100）。
pub(crate) async fn append_outbox(
    conn: &mut PgConnection,
    entry: &Entry,
    env: &OutboxEnvelope,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
        ON CONFLICT (event_id) DO NOTHING
        "#,
    )
    .bind(entry.idem_key().as_str())
    .bind(env.domain())
    .bind(entry.topic().as_str())
    .bind(env.contract_id())
    .bind(entry.payload())
    .bind(env.metadata_json())
    .bind(STATUS_PENDING)
    .execute(conn)
    .await?;
    Ok(())
}

// ── PgOutbox ──────────────────────────────────────────────────────────────────

/// PostgreSQL outbox adapter：impl [`OutboxSource`] + [`OutboxRelay`] + [`OutboxSweeper`]。
///
/// 持 `PgPool`（clone 自 [`PgStore`]）+ `Box<DynPublisher>`（Send 变体，跨 await 安全）。
/// 构造必填两个参数，缺一编译报错（构造器必填参数 Hard 约束）。
///
/// **时间源**：`poll_pending` / `acquire_lease` / `settle_retry` / `sweep` 的所有时间谓词
/// 用 PostgreSQL `now()`（DB 事务时间），**刻意不注入 `Clock`**——relay 多实例并发下需要单一、
/// 无跨进程偏移的时间源（lease TTL / retry_after / 保留期比较都在 DB 端一致求值）。这是对
/// rust-standards `Clock` 构造器位置参规则的有意例外（clippy `disallowed_methods` 不覆盖 SQL `now()`）。
pub struct PgOutbox {
    pool: sqlx::PgPool,
    publisher: Box<DynPublisher<'static>>,
}

impl PgOutbox {
    /// 由 [`PgStore`] + `Box<DynPublisher>` 构造（两者均必填）。
    /// pool 从 `PgStore.pool`（`pub(crate)`，同 crate 可取）clone；DynPublisher 转移所有权。
    pub fn new(store: &PgStore, publisher: Box<DynPublisher<'static>>) -> Self {
        Self {
            pool: store.pool.clone(),
            publisher,
        }
    }
}

// ── OutboxSource impl ─────────────────────────────────────────────────────────

impl OutboxSource for PgOutbox {
    /// 扫描 `domain` 下至多 `limit` 条待发 entry（pending 且到期，或 lease 过期 stale publishing）。
    ///
    /// `FOR UPDATE SKIP LOCKED` 尽力去重并发扫描（pool 直连下扫描锁随语句结束释放，**非**严格互斥）；
    /// at-most-once 正确性由 `relay` 的 `acquire_lease` CAS + `settle_*` 的 lease_token 比对保证，不靠扫描锁。
    /// parse 失败（topic / idem_key 无效）→ `EngineErrorKind::Invariant`（我们写入的数据不该无效）。
    async fn poll_pending(&self, domain: &str, limit: usize) -> Result<Vec<Entry>, EngineError> {
        let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT topic, event_id, payload
            FROM outbox
            WHERE domain = $1
              AND (
                    (status = $4 AND (retry_after IS NULL OR retry_after <= now()))
                 OR (status = $5 AND updated_at <= now() - make_interval(secs => $2))
              )
            ORDER BY retry_after NULLS FIRST, created_at
            LIMIT $3
            FOR UPDATE SKIP LOCKED
            "#,
        )
        .bind(domain)
        .bind(LEASE_TTL_SECONDS)
        .bind(limit as i64)
        .bind(STATUS_PENDING)
        .bind(STATUS_PUBLISHING)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: poll_pending db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        rows.into_iter()
            .map(|(topic_str, event_id, payload)| {
                let topic = Topic::parse(&topic_str)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                let idem_key = IdemKey::parse(&event_id)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                Ok(Entry::new(topic, idem_key, payload))
            })
            .collect()
    }
}

// ── OutboxRelay impl ──────────────────────────────────────────────────────────

impl OutboxRelay for PgOutbox {
    /// CAS relay 单条 entry：acquire → publish → settle。
    ///
    /// `PublisherError` 无 kind——瞬态/永久按重试预算耗尽区分（不按错误种类）。
    /// DB/CAS 失败返 `Err(EngineError)`；publish 失败是**已处置**（返 `Ok(Disposition)`）。
    async fn relay(&self, entry: &Entry) -> Result<consistency::Disposition, EngineError> {
        let event_id = entry.idem_key().as_str();

        // 1. CAS acquire：把 pending（或 stale publishing）行翻转到 publishing，返 (retry_count, lease_token)。
        let maybe_lease = acquire_lease(&self.pool, event_id).await?;

        let (retry_count, lease_token) = match maybe_lease {
            // 0 行：已被他人发或已 published → 幂等 Ack，禁二次 publish。
            None => return Ok(consistency::Disposition::Ack),
            Some(lease) => lease,
        };

        // 2. 发布到 broker。event_id（= idem_key）盖章到 broker message_id，经订阅侧流回消费幂等键
        //    （至少一次 + 幂等去重端到端，eventbus.md §DLX 与幂等）。
        let publish_result = self
            .publisher
            .publish(PublishRequest {
                topic: diport::Topic::new(entry.topic().as_str()),
                event_id: diport::MessageId::new(event_id),
                payload: entry.payload().to_vec(),
            })
            .await;

        match publish_result {
            Ok(()) => {
                // 3a. 发布成功 → published（以本次 lease_token 比对，防 stale 持租者结算）。
                // LostLease（0 行 CAS）= 租约已被新持租者接管并自行结算：事件仍已达 broker，故 Ack；
                // 但不当「干净成功」静默吞——结构化记录 lost-lease 供运维感知（F3）。
                if settle_published(&self.pool, event_id, &lease_token).await?
                    == SettleOutcome::LostLease
                {
                    log_lost_lease(event_id, "settle_published");
                }
                Ok(consistency::Disposition::Ack)
            }
            // 3b. 发布失败 → dlx（预算耗尽）/ retry（退避），见 helper。
            Err(e) => {
                settle_publish_failure(&self.pool, entry, retry_count, &lease_token, &e).await
            }
        }
    }
}

/// publish 失败处置（抽出控制 `relay` 认知复杂度 ≤15）：预算耗尽 → dlx；否则退避 retry。
///
/// settle CAS 命中 `LostLease`（0 行）⇒ 行已被新租约接管：本租约不拥有该行、不重复处置，记 lost-lease
/// 后退化为 `Ack`（benign handoff，新持租者负责重投/退避），不误把 broker 失败上抛成本 worker 的降级（F3）。
async fn settle_publish_failure(
    pool: &sqlx::PgPool,
    entry: &Entry,
    retry_count: i32,
    lease_token: &str,
    err: &PublisherError,
) -> Result<consistency::Disposition, EngineError> {
    let event_id = entry.idem_key().as_str();
    let new_count = retry_count + 1;
    log_publish_failed(event_id, entry.topic().as_str(), retry_count, err);
    if new_count >= MAX_PUBLISH_ATTEMPTS {
        match settle_dlx(pool, event_id, new_count, lease_token).await? {
            SettleOutcome::Settled => {
                log_dlx(event_id, new_count);
                Ok(consistency::Disposition::Reject)
            }
            SettleOutcome::LostLease => {
                log_lost_lease(event_id, "settle_dlx");
                Ok(consistency::Disposition::Ack)
            }
        }
    } else {
        let backoff = backoff_seconds(retry_count);
        match settle_retry(pool, event_id, new_count, backoff, lease_token).await? {
            SettleOutcome::Settled => Ok(consistency::Disposition::Requeue),
            SettleOutcome::LostLease => {
                log_lost_lease(event_id, "settle_retry");
                Ok(consistency::Disposition::Ack)
            }
        }
    }
}

// ── 结构化日志 helper（抽出 tracing 宏展开，控制调用方认知复杂度 ≤15）。勿记 payload/PII。──

/// publish 失败：退避/dlx 前结构化记录（带 `event_id` 关联键，F9）。
/// `PublisherError::Display` 是受控安全摘要（diport PII 边界）。
fn log_publish_failed(event_id: &str, topic: &str, retry_count: i32, err: &PublisherError) {
    tracing::warn!(target: "postgres", event_id, topic, retry_count, error = %err, "outbox: publish failed");
}

/// 预算耗尽进 dlx（永久失败，运维须感知）。
fn log_dlx(event_id: &str, attempts: i32) {
    tracing::error!(target: "postgres", event_id, attempts, "outbox: publish budget exhausted, moved to dlx");
}

/// settle CAS 0 行（lost-lease fencing miss）：行已被新租约接管或已终结。结构化 warn（benign handoff，
/// 运维据 `event_id` + `operation` 关联，区分「干净结算」与「丢租约」，F3/F9）。
fn log_lost_lease(event_id: &str, operation: &str) {
    tracing::warn!(target: "postgres", event_id, operation, "outbox: settle hit lost lease (0 rows); row owned by another lease");
}

// ── OutboxSweeper impl ────────────────────────────────────────────────────────

impl OutboxSweeper for PgOutbox {
    /// 删除 `status='published'` 且早于保留期的行，返回删除条数。
    /// dlx 行不删（留运维巡检）。
    ///
    /// 时间谓词用 PostgreSQL `now()`（DB 事务时间）是刻意决策——见 [`PgOutbox`] 顶注。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        // u64→i64：超 i64::MAX 的保留期是非法输入（负 interval 会反向清空全表），fail-closed。
        let secs = i64::try_from(retain_seconds)
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
        let result = sqlx::query(
            r#"
            DELETE FROM outbox
            WHERE status = $2
              AND created_at <= now() - make_interval(secs => $1)
            "#,
        )
        .bind(secs)
        .bind(STATUS_PUBLISHED)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "outbox: sweep db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        Ok(result.rows_affected())
    }
}

// ── relay 拆分 helper fn（认知复杂度 ≤ 15）────────────────────────────────────

/// CAS acquire：把 pending（或 stale publishing）行置 publishing，返回 `(retry_count, lease_token)`。
/// 返回 `None` 表示 0 行更新（已 published 或被他人占）。
///
/// `lease_token::text` 文本往返（不给 sqlx 加 uuid feature）；`settle_*` 以此 token 比对，
/// 防 stale 持租者把已被新租约结算的行误改（CAS fencing，spec data-model §outbox）。
/// `pub(crate)`：integration 测试做 lease fencing 断言。
pub(crate) async fn acquire_lease(
    pool: &sqlx::PgPool,
    event_id: &str,
) -> Result<Option<(i32, String)>, EngineError> {
    let row: Option<(i32, String)> = sqlx::query_as(
        r#"
        UPDATE outbox
        SET status = $3,
            lease_token = gen_random_uuid(),
            updated_at = now()
        WHERE event_id = $1
          AND (
                status = $4
             OR (status = $5 AND updated_at <= now() - make_interval(secs => $2))
          )
        RETURNING retry_count, lease_token::text
        "#,
    )
    .bind(event_id)
    .bind(LEASE_TTL_SECONDS)
    .bind(STATUS_PUBLISHING)
    .bind(STATUS_PENDING)
    .bind(STATUS_PUBLISHING)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "acquire_lease", error = %secure::redact_error(&e), "outbox: acquire_lease db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    Ok(row)
}

/// CAS settle 结果：本租约确实结算（1 行），或租约已 stale（0 行 = lost-lease fencing miss）。
///
/// 调用方据此区分「干净结算」与「丢租约」——后者不得当成功静默吞（F3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SettleOutcome {
    /// 本租约成功结算（`rows_affected() == 1`）。
    Settled,
    /// 租约已 stale——0 行更新（行被新租约接管或已终结）。
    LostLease,
}

/// `rows_affected()` → [`SettleOutcome`]（1 = Settled，否则 LostLease）——三个 settle helper 同源映射。
fn settle_outcome(rows_affected: u64) -> SettleOutcome {
    if rows_affected == 1 {
        SettleOutcome::Settled
    } else {
        SettleOutcome::LostLease
    }
}

/// 发布成功后把行置 published（以 `lease_token` 比对，防 stale 持租者结算）。
/// `pub(crate)`：integration 测试做 lease fencing 断言。
pub(crate) async fn settle_published(
    pool: &sqlx::PgPool,
    event_id: &str,
    lease_token: &str,
) -> Result<SettleOutcome, EngineError> {
    let result = sqlx::query(
        r#"
        UPDATE outbox
        SET status = $3,
            updated_at = now()
        WHERE event_id = $1
          AND status = $4
          AND lease_token = $2::uuid
        "#,
    )
    .bind(event_id)
    .bind(lease_token)
    .bind(STATUS_PUBLISHED)
    .bind(STATUS_PUBLISHING)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_published", error = %secure::redact_error(&e), "outbox: settle_published db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;
    Ok(settle_outcome(result.rows_affected()))
}

/// 预算耗尽后把行置 dlx（以 `lease_token` 比对，防 stale 持租者把已被新租约结算的行误标 dlx）。
async fn settle_dlx(
    pool: &sqlx::PgPool,
    event_id: &str,
    new_retry_count: i32,
    lease_token: &str,
) -> Result<SettleOutcome, EngineError> {
    let result = sqlx::query(
        r#"
        UPDATE outbox
        SET status = $4,
            retry_count = $2,
            updated_at = now()
        WHERE event_id = $1
          AND status = $5
          AND lease_token = $3::uuid
        "#,
    )
    .bind(event_id)
    .bind(new_retry_count)
    .bind(lease_token)
    .bind(STATUS_DLX)
    .bind(STATUS_PUBLISHING)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;
    Ok(settle_outcome(result.rows_affected()))
}

/// 还有预算时把行退回 pending + 退避（以 `lease_token` 比对，防 stale 持租者结算；WHERE 先于 SET 求值）。
async fn settle_retry(
    pool: &sqlx::PgPool,
    event_id: &str,
    new_retry_count: i32,
    backoff_secs: i64,
    lease_token: &str,
) -> Result<SettleOutcome, EngineError> {
    let result = sqlx::query(
        r#"
        UPDATE outbox
        SET status = $5,
            retry_count = $2,
            retry_after = now() + make_interval(secs => $3),
            lease_token = NULL,
            updated_at = now()
        WHERE event_id = $1
          AND status = $6
          AND lease_token = $4::uuid
        "#,
    )
    .bind(event_id)
    .bind(new_retry_count)
    .bind(backoff_secs)
    .bind(lease_token)
    .bind(STATUS_PENDING)
    .bind(STATUS_PUBLISHING)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_retry", error = %secure::redact_error(&e), "outbox: settle_retry db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;
    Ok(settle_outcome(result.rows_affected()))
}

// ── 纯函数（单测覆盖）────────────────────────────────────────────────────────

/// 指数退避（秒），上限 3600。`retry_count` 是当前已重试次数（0-based，即 UPDATE 前的值）。
///
/// backoff = min(2^retry_count, 3600)。
pub(crate) fn backoff_seconds(retry_count: i32) -> i64 {
    const MAX_BACKOFF: i64 = 3600;
    if retry_count < 0 {
        // DB retry_count 理论恒 ≥0（DEFAULT 0，只递增）；防御负值左移 panic（debug）/ 掩码异常（release）。
        return 1;
    }
    if retry_count >= 12 {
        // 2^12 = 4096 > 3600，提前封顶避免 i64 溢出（12 次后全部封顶）。
        return MAX_BACKOFF;
    }
    let val = 1i64 << retry_count; // 2^retry_count
    val.min(MAX_BACKOFF)
}

// ── 单测 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::{
        LEASE_TTL_SECONDS, MAX_PUBLISH_ATTEMPTS, MetadataError, OutboxMetadata, STATUS_DLX,
        STATUS_PENDING, STATUS_PUBLISHED, STATUS_PUBLISHING, backoff_seconds,
    };

    // OutboxEnvelope 构造 + 字段访问（metadata 经 OutboxMetadata funnel，F1）。
    #[test]
    fn envelope_new_and_fields() {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new(
            "identity".to_string(),
            "contract-1".to_string(),
            OutboxMetadata::new().with_subject_id("tenant-42"),
        );
        assert_eq!(env.domain(), "identity");
        assert_eq!(env.contract_id(), "contract-1");
        assert_eq!(env.metadata_json(), r#"{"subjectId":"tenant-42"}"#);
    }

    // metadata_json 空 metadata 退化 "{}"。
    #[test]
    fn envelope_metadata_json_empty_object() {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new("d".to_string(), "c".to_string(), OutboxMetadata::new());
        assert_eq!(env.metadata_json(), "{}");
    }

    // F1 负向（anti-vacuity，INVARIANT OUTBOX-METADATA-FUNNEL-01）：reserved key 经 try_insert
    // fail-closed 拒；非 reserved key 接受并经 funnel 序列化。
    #[test]
    fn metadata_try_insert_rejects_reserved_key() {
        for reserved in ["trace", "correlation", "principal", "occurred_at"] {
            let mut m = OutboxMetadata::new();
            assert_eq!(
                m.try_insert(reserved, serde_json::Value::Bool(true)),
                Err(MetadataError::ReservedKey),
                "reserved key must be rejected: {reserved}"
            );
        }
        let mut ok = OutboxMetadata::new();
        assert!(
            ok.try_insert("tenantTier", serde_json::Value::String("gold".into()))
                .is_ok()
        );
        let env = super::OutboxEnvelope::new("d".to_string(), "c".to_string(), ok);
        assert_eq!(env.metadata_json(), r#"{"tenantTier":"gold"}"#);
    }

    // 常量合理值（MAX_PUBLISH_ATTEMPTS > 0；LEASE_TTL_SECONDS > 0）——编译期常量断言（强于运行期）。
    #[test]
    fn constants_sane() {
        const { assert!(MAX_PUBLISH_ATTEMPTS > 0) };
        const { assert!(LEASE_TTL_SECONDS > 0) };
    }

    // F8 anti-vacuity：解析 0002 migration 的 `CHECK (status IN (...))` 子句，断言与生产 const 集同源
    // （SQL 全经 .bind(STATUS_*)，此测试守 const ↔ migration 不漂移；两处任一改动不同步即红）。
    // 集合相等比较隐式覆盖「四常量互异」——migration 四值互异，若两常量重复则集合不等而失败。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试解析编译期 include_str! 的已知 migration 文本，CHECK 子句缺失即应 fail（测试本身的断言），
    // item-level carve-out（error-handling.md §Carve-out）。
    fn status_consts_match_migration_check() {
        const MIGRATION: &str = include_str!("../migrations/0002_create_outbox.sql");
        let in_pos = MIGRATION
            .find("status IN (")
            .expect("migration must declare status CHECK IN clause");
        let rest = &MIGRATION[in_pos..];
        let open = rest.find('(').expect("IN clause needs '('");
        let close = rest.find(')').expect("IN clause needs ')'");
        let mut migration_values: Vec<&str> = rest[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\''))
            .collect();
        migration_values.sort_unstable();
        let mut const_values = [
            STATUS_PENDING,
            STATUS_PUBLISHING,
            STATUS_PUBLISHED,
            STATUS_DLX,
        ];
        const_values.sort_unstable();
        assert_eq!(
            migration_values, const_values,
            "outbox status const 集与 migration 0002 CHECK 漂移"
        );
    }

    // backoff_seconds 表驱动（指数 + 封顶 3600）。
    #[test]
    fn backoff_seconds_table() {
        let cases: &[(i32, i64)] = &[
            (-100, 1), // 负值防御：恒返 1（不 panic）
            (-1, 1),
            (0, 1),
            (1, 2),
            (2, 4),
            (3, 8),
            (4, 16),
            (5, 32),
            (6, 64),
            (7, 128),
            (8, 256),
            (9, 512),
            (10, 1024),
            (11, 2048),
            (12, 3600), // 2^12=4096 → 封顶
            (20, 3600),
            (100, 3600),
        ];
        for &(retry_count, expected) in cases {
            assert_eq!(
                backoff_seconds(retry_count),
                expected,
                "retry_count={retry_count}"
            );
        }
    }

    // backoff 单调不减且上限 3600。
    #[test]
    fn backoff_seconds_monotone_and_capped() {
        let mut prev = backoff_seconds(0);
        for rc in 1..=20 {
            let cur = backoff_seconds(rc);
            assert!(cur >= prev, "not monotone at retry_count={rc}");
            assert!(cur <= 3600, "exceeds cap at retry_count={rc}");
            prev = cur;
        }
    }
}
