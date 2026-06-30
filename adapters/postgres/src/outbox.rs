//! Outbox 持久化实现——L2 OutboxFact adapter（#1117 P4）。
//!
//! [`PgOutbox`] impl [`consistency::OutboxSource`] / [`consistency::OutboxRelay`] /
//! [`consistency::RetentionSweeper`]——三个 native AFIT trait（泛型静态分发，非 dyn，不引 dynosaur）。
//!
//! **`append_outbox`**（`pub(crate)` free fn，收 `&mut sqlx::PgConnection`）是 L1 原子性的编译期硬约束：
//! 只能在已有事务内调用，不能脱离事务双写；tenant-scoped 业务写经
//! `PgTenantPool::co_tx_with_outbox` 注入租户事务后传入 `&mut PgConnection`，全局 outbox-only infra
//! 路径也必须先显式打开事务——类型系统天然阻止无事务直接调用（`PgPool` 无法隐式降级）。
//!
//! **CAS fencing**：`relay` 以 `event_id`（= `IdemKey::as_str()`）为键 `UPDATE ... RETURNING retry_count`，
//! 0 行 → 已被他人发或已 published → `Ok(Disposition::Ack)`，防二次 publish（at-least-once 幂等收口）。
//!
//! **崩溃重投**：`poll_pending` 捞回 `status='publishing' AND updated_at <= now() - LEASE_TTL` 的 stale 行；
//! relay 幂等 CAS 保证即使重投也至多 publish 一次。
//!
//! ref: serverlesstechnology/cqrs `persistence/postgres-es/src/event_repository.rs@main`
//! （`rows_affected()==1` 乐观锁 + UNIQUE 幂等 idiom 采纳来源）。

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use consistency::{
    BacklogSample, EngineError, EngineErrorKind, Entry, IdemKey, OutboxBacklog, OutboxPayload,
    OutboxRelay, OutboxSource, RetentionSweeper, Topic,
};
use diport::{
    DeadLetterSource, DynPublisher, EnvelopeMetadata, EnvelopeSubjectId, KEY_ACTOR,
    KEY_CORRELATION, KEY_OCCURRED_AT, KEY_SUBJECT_ID, KEY_TENANT_ID, KEY_TRACE, MetadataError,
    OutboxActor, PublishRequest, Publisher, PublisherError, RESERVED_METADATA_KEYS,
};
use eventexec::{TenantAuthority, TenantAuthorityBinding};
use sqlx::PgConnection;

use crate::PgStore;
use crate::cotx::set_local_tenant;
use crate::dead_letter_payload::{
    DLX_ORIGINAL_ENTRY_ENCODING, DlxPayloadContext, DlxPayloadProtector,
};

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
const OUTBOX_RELAY_DLX_SUMMARY: &str = "outbox relay publish failed";

// ── OutboxMetadata（typed sealed funnel，F1）──────────────────────────────────
//
// reserved key / subject key 常量已迁至 diport 单源（#1160 A4）：
// `diport::{RESERVED_METADATA_KEYS, KEY_OCCURRED_AT, KEY_TRACE, KEY_CORRELATION,
//           KEY_TENANT_ID, KEY_SUBJECT_ID}`。本 adapter funnel 逻辑不变，key 字面量引 diport 单源。

/// Outbox envelope metadata——**sealed typed funnel**（私有内层 `Map`，仅经受控入口构造）。
///
/// 安全边界从「调用方注释自律」上移到类型层：raw `serde_json::Value` 入口已删，外部无法绕过；
/// reserved key（[`RESERVED_METADATA_KEYS`]）被 [`OutboxMetadata::try_insert`] fail-closed 拒；
/// principal 仅允许 opaque subject id（[`OutboxMetadata::with_subject_id`]，不容完整 Principal / PII，
/// `observability.md` §outbox envelope）。
///
/// # INVARIANT: OUTBOX-METADATA-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// envelope metadata 只能经此 funnel 构造（Hard：无 raw `Value` 入口，reserved/PII 不可表达）；
/// reserved key 拒绝由 `metadata_try_insert_rejects_reserved_key` 负向单测守 anti-vacuity。
#[derive(Clone)]
pub(crate) struct OutboxMetadata(serde_json::Map<String, serde_json::Value>);

impl OutboxMetadata {
    /// 由 reserved `occurred_at`（unix 秒 i64，producer 端事件发生时刻）+ typed `tenantId` 构造。
    ///
    /// occurred_at / tenantId 注入折叠进构造器 ⇒「无 occurred_at/tenantId 的 outbox metadata」**类型层不可表达**（Hard），杜绝
    /// producer 漏接：三条生产路径（`PgEmitter` / `PgSessionLifecycle` / `PgConfigRepo`）各从注入 `Clock`
    /// 取 `unix_secs(clock.now())` 传入，新增 producer 也必须提供（缺失即编译错误）。reserved key 不经业务可见
    /// 入口写入——[`OutboxMetadata::try_insert`] 对 free-form 路径仍 fail-closed 拒 reserved（业务侧不可伪造）。
    ///
    /// `occurredAt` 仅供**诊断 / 观测**，**不**进入 relay / sweep 的 SQL WHERE 谓词、不建索引。trace 经
    /// #1224 接线（emit 侧 `tracewire::capture`）；correlation 已接线 #1160；principal 待 #1397。
    pub(crate) fn new(occurred_at_secs: i64, tenant: vocab::TenantId) -> Self {
        // KEY_OCCURRED_AT = diport 单源（#1160 A4）。
        let mut map = serde_json::Map::new();
        map.insert(
            KEY_OCCURRED_AT.to_string(),
            serde_json::Value::from(occurred_at_secs),
        );
        map.insert(
            KEY_TENANT_ID.to_string(),
            serde_json::Value::String(tenant.to_string()),
        );
        Self(map)
    }

    /// 设置 opaque 主体 id（唯一允许的 principal 形态——不容完整 Principal / PII）。
    /// 生产 caller：`PgEmitter::emit` 从 `diport::OutboxEnvelopeParts.subject_id` 组装（T008/#1100）。
    /// KEY_SUBJECT_ID = diport 单源（#1160 A4）。
    pub(crate) fn with_subject_id(mut self, subject_id: EnvelopeSubjectId) -> Self {
        self.0.insert(
            KEY_SUBJECT_ID.to_string(),
            serde_json::Value::String(subject_id.as_str().to_string()),
        );
        self
    }

    /// 设置最小化 actor envelope（persisted-only，不进 broker header）。
    pub(crate) fn with_actor(mut self, actor: OutboxActor) -> Self {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "kind".to_string(),
            serde_json::Value::String(actor.kind().as_actor_metadata_label().to_string()),
        );
        obj.insert(
            "id".to_string(),
            serde_json::Value::String(actor.actor_id().as_str().to_string()),
        );
        if let Some(tenant) = actor.tenant() {
            obj.insert(
                "tenantId".to_string(),
                serde_json::Value::String(tenant.to_string()),
            );
        }
        obj.insert(
            "scope".to_string(),
            serde_json::Value::String(actor.scope().as_label().to_string()),
        );
        self.0
            .insert(KEY_ACTOR.to_string(), serde_json::Value::Object(obj));
        self
    }

    /// 注入 reserved key `trace`（#1193）——**sealed setter**：funnel 内特权写 reserved key（business
    /// free-form [`OutboxMetadata::try_insert`] 仍 fail-closed 拒），承载「业务不可伪造 trace」（Hard）。
    /// KEY_TRACE = diport 单源（#1160 A4）。
    /// 生产 caller：[`metadata_with_ambient`]（从当前 tracing span 经 `tracewire::capture` 取 W3C traceparent，
    /// fail-open；#1224 接线，关闭 #1076 预留槽）。
    pub(crate) fn with_trace(mut self, trace: impl Into<String>) -> Self {
        self.0.insert(
            KEY_TRACE.to_string(),
            serde_json::Value::String(trace.into()),
        );
        self
    }

    /// 注入 reserved key `correlation`（#1193 / #1160 B3）——**sealed setter**：funnel 内特权写 reserved key
    /// （同 [`OutboxMetadata::with_trace`]，业务侧 `try_insert` 仍拒），承载「业务不可伪造 correlation」（Hard）。
    /// 生产 caller：[`metadata_with_ambient`]（从 `diagctx` ambient 读回 correlation，fail-open）。
    /// KEY_CORRELATION = diport 单源（#1160 A4）。
    pub(crate) fn with_correlation(mut self, correlation: impl Into<String>) -> Self {
        self.0.insert(
            KEY_CORRELATION.to_string(),
            serde_json::Value::String(correlation.into()),
        );
        self
    }

    /// 插入 free-form key（fail-closed 拒 reserved key）。
    /// RESERVED_METADATA_KEYS = diport 单源（#1160 A4）。
    // reason(dead_code): 生产 caller 在 T008/#1100 接入；负向单测行使 reserved 拒绝。
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

// ── 时间编码 ──────────────────────────────────────────────────────────────────

/// `SystemTime` → UNIX epoch 秒（i64）；负偏移收口 0、溢出收口 `i64::MAX`。
///
/// 本 crate **时间编码单源**（#1129 合并）：emitter / session_lifecycle 的 envelope `occurred_at` 与 session 行
/// `expires_at` / `created_at` 共用，消除同 crate 内重复。timestamptz / 整数秒由 server-side `to_timestamp($N)`
/// 或直绑生成（不给 sqlx 加 time feature）。负偏移 / 正常路径由 outbox 单测 `unix_secs_*` 守。
///
/// 溢出分支（`as_secs > i64::MAX`，约年 ~2920 亿）为防御性收口：`i64::try_from(..).unwrap_or(i64::MAX)`
/// **类型层静态保证不 panic**；该输入 `SystemTime` 不可移植构造（`UNIX_EPOCH + Duration::from_secs(u64::MAX)`
/// 在 `SystemTime::add` 即 panic），故不写平台相关红 case（沿用合并前 session_lifecycle 的既定理由）。
///
/// 跨 crate 另有 `identity::application::unix_secs` / `settings::application::unix_secs` 同名 helper（域 crate
/// 不依赖本 adapter，故各自「独立维护、语义对齐」）；跨 crate 收敛为单源 + governance 守语义一致已登记 #1294。
pub(crate) fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ── metadata_with_ambient ─────────────────────────────────────────────────────

/// occurred_at 构造期必填 + 有 ambient correlation / 当前 trace 则盖章（均 fail-open：无则省略）。
///
/// 三条生产 outbox 路径（`PgEmitter` / `PgSessionLifecycle` / `PgConfigRepo`）统一经此 helper 构造
/// envelope metadata，保证 correlation ambient（#1160 B3）+ trace 透传（#1224）接线一致。
/// - correlation：从 `diagctx` ambient 读回（无 scope → 省略）。
/// - trace：`tracewire::capture()` 从当前 tracing span 导出 W3C traceparent（emit 与 handler 同 task 同步执行
///   ⇒ `Span::current()` 即请求 span；无 otel 层 / 未采样 → `None` 省略）。落 outbox `metadata` 保留键 `trace`，
///   经 relay → broker header → consumer `tracewire::restore_parent` 还原，使 handler span 与 producer 同 trace_id。
///
/// 全部缺失（worker 任务 / 批次未绑 correlation、无 otel）→ 仅含 occurred_at，不 panic（fail-open，不阻投递）。
pub(crate) fn metadata_with_ambient(
    occurred_at_secs: i64,
    tenant: vocab::TenantId,
) -> OutboxMetadata {
    let mut m = OutboxMetadata::new(occurred_at_secs, tenant);
    if let Some(c) = diagctx::correlation() {
        m = m.with_correlation(c.as_str());
    }
    if let Some(tp) = tracewire::capture() {
        m = m.with_trace(tp);
    }
    m
}

/// 持久化 epoch 秒（`extract(epoch ...)::bigint`）→ `SystemTime`：[`unix_secs`] 的**解码对称**（编码 / 解码
/// 同源单向往返）。负值（早于 epoch，理论不可达）收口 epoch 0，不 panic。session / credential 等 adapter 读
/// 路径共用此 decode 单源（避免各模块重复 decode helper；与 `unix_secs` encode 单源并列，#1316 review C-F1）。
pub(crate) fn epoch_secs_to_time(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

// ── OutboxEnvelope ────────────────────────────────────────────────────────────

/// Outbox 行 envelope（adapter 本地，`pub(crate)`；由域写路径在 `append_outbox` 调用前构造）。
///
/// `metadata` 经 [`OutboxMetadata`] sealed funnel 收口（拒 reserved key + 仅 opaque subject id，
/// PII 边界；`observability.md` §outbox envelope）。
/// `partition_key` 来自 [`diport::OutboxEnvelopeParts::partition_key`]，`None` = 无序并行（DB NULL）、
/// `Some(s)` = 串行有序（head-of-partition gating，#1211）。
#[derive(Clone)]
pub(crate) struct OutboxEnvelope {
    domain: String,
    contract_id: String,
    metadata: OutboxMetadata,
    partition_key: Option<String>,
}

impl OutboxEnvelope {
    /// 构造 envelope（funnel；字段私有，仅经此入口）。
    /// 生产 caller：`PgEmitter::emit` 从 `diport::OutboxEnvelopeParts` 组装（T008/#1100）。
    pub(crate) fn new(domain: String, contract_id: String, metadata: OutboxMetadata) -> Self {
        Self {
            domain,
            contract_id,
            metadata,
            partition_key: None,
        }
    }

    /// 设置可选分区键（builder；`None` = 无序并行，`Some(PartitionKey)` → adapter 内存 String，#1211）。
    pub(crate) fn with_partition_key_opt(mut self, key: Option<consistency::PartitionKey>) -> Self {
        self.partition_key = key.map(|k| k.as_str().to_string());
        self
    }

    /// 借出 domain。
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    /// 借出 contract_id。
    pub(crate) fn contract_id(&self) -> &str {
        &self.contract_id
    }

    /// 借出可选分区键（`None` → DB NULL，无序并行；`Some(&str)` → 串行有序）。
    pub(crate) fn partition_key(&self) -> Option<&str> {
        self.partition_key.as_deref()
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
/// （tenant-scoped caller 由 `PgTenantPool::co_tx_with_outbox` 提供事务连接；不可脱离事务直接取到
/// `&mut PgConnection`）。
///
/// ON CONFLICT (event_id) DO NOTHING：同 idem_key 的 entry 已在表中时幂等跳过（不报错）。
/// uuid/timestamptz 生成全部交给 server-side SQL（不给 sqlx 加 uuid/time feature）。
///
/// # INVARIANT: OUTBOX-ATOMIC-IDEM-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// outbox 双写必须在业务事务内原子执行——tenant-scoped caller 须经 `PgTenantPool::co_tx_with_outbox`
/// 传入 `&mut PgConnection`；裸 `PgPool::acquire()` 拿到的连接类型不同，类型系统阻止误用（Hard）。
// 生产 caller：`PgEmitter::emit`（impl `diport::OutboxEmitter`）在事务内调用——域 crate 不直接 import 本
// adapter（域→adapter 反向依赖被 deny.toml 禁），域侧只经 `OutboxEmitter` port 触发该 durable 写路径（T008/#1100）。
pub(crate) async fn append_outbox(
    conn: &mut PgConnection,
    entry: &Entry,
    env: &OutboxEnvelope,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO outbox (event_id, domain, topic, contract_id, payload, metadata, status, partition_key)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
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
    .bind(env.partition_key())
    .execute(conn)
    .await?;
    Ok(())
}

// ── PgOutbox ──────────────────────────────────────────────────────────────────

/// PostgreSQL outbox adapter：impl [`OutboxSource`] + [`OutboxRelay`] + [`RetentionSweeper`]。
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
    tenant_authority: Arc<TenantAuthority>,
    payload_protector: DlxPayloadProtector,
}

impl PgOutbox {
    /// 由 [`PgStore`] + `Box<DynPublisher>` 构造（两者均必填）。
    /// pool 从 `PgStore.pool`（`pub(crate)`，同 crate 可取）clone；DynPublisher 转移所有权。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::outbox` 收口。
    pub(crate) fn new(
        store: &PgStore,
        publisher: Box<DynPublisher<'static>>,
        tenant_authority: Arc<TenantAuthority>,
        payload_protector: DlxPayloadProtector,
    ) -> Self {
        Self {
            pool: store.pool.clone(),
            publisher,
            tenant_authority,
            payload_protector,
        }
    }
}

/// PostgreSQL outbox maintenance adapter：impl [`OutboxBacklog`] + [`RetentionSweeper`]，不持 publisher。
///
/// relay 需要 per-domain publisher，因此仍由 [`PgOutbox`] 承载；sampler/sweeper 只需要 DB pool，不应为了
/// 采样/清理而构造可发布的 relay outbox（#1429）。本类型经 [`crate::PgInfraDeps::outbox_maintenance`]
/// 暴露给组合根，用于 runtime module worker 接线。
#[derive(Clone)]
pub struct PgOutboxMaintenance {
    pool: sqlx::PgPool,
}

impl PgOutboxMaintenance {
    /// 由 [`PgStore`] 构造 outbox maintenance 能力（pool clone，轻量）。
    ///
    /// `pub(crate)`（PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::outbox_maintenance`] 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

// ── OutboxSource impl ─────────────────────────────────────────────────────────

impl OutboxSource for PgOutbox {
    /// 扫描 `domain` 下至多 `limit` 条待发 entry（pending 且到期，或 lease 过期 stale publishing）。
    ///
    /// **Head-of-partition gating（#1211）**：对 `partition_key IS NOT NULL` 的行，仅当同 (domain, partition_key)
    /// 内所有 `seq < o.seq` 的行均已 `published` 时才放行，保证同 partition 内按 seq 顺序串行投递。
    /// `partition_key IS NULL` 的行保持原语义——无序并行，不受 gate 约束。
    ///
    /// - **dlx fail-closed 语义**：队头进 dlx（`b.status <> 'published'`，dlx 计「未结清」）会**阻塞**该
    ///   partition 直到运维 re-drive（`UPDATE outbox SET status='pending', retry_count=0, retry_after=NULL
    ///   WHERE event_id=…`）——这是与「serial in order」一致的唯一选择。
    /// - **已知前提**：`b.seq < o.seq` 队头判据假设同 partition 行按 seq 序提交，成立条件是同 partition 写入由
    ///   聚合根并发控制（行锁/version CAS）串行化（partition = aggregate 标准契约）。
    /// - **backlog 注意**：head-of-partition gate 是 **poll-only by design**——被 gate 的后继仍计入 backlog
    ///   depth（见 `sample_backlog` 注释），否则 stalled partition 对 SLO 失明。
    ///
    /// `FOR UPDATE OF o SKIP LOCKED` 尽力去重并发扫描；at-most-once 正确性由 `acquire_lease` CAS 保证。
    /// parse 失败（topic / idem_key 无效）→ `EngineErrorKind::Invariant`（我们写入的数据不该无效）。
    ///
    /// INVARIANT: OUTBOX-PARTITION-ORDER-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
    async fn poll_pending(&self, domain: &str, limit: usize) -> Result<Vec<Entry>, EngineError> {
        let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as(
            r#"
            SELECT o.topic, o.event_id, o.payload
            FROM outbox o
            WHERE o.domain = $1
              AND (
                    (o.status = $4 AND (o.retry_after IS NULL OR o.retry_after <= now()))
                 OR (o.status = $5 AND o.updated_at <= now() - make_interval(secs => $2))
              )
              AND (o.partition_key IS NULL
                OR NOT EXISTS (
                    SELECT 1 FROM outbox b
                    WHERE b.domain = o.domain
                      AND b.partition_key = o.partition_key
                      AND b.seq < o.seq
                      AND b.status <> $6
                ))
            ORDER BY o.seq
            LIMIT $3
            FOR UPDATE OF o SKIP LOCKED
            "#,
        )
        .bind(domain)
        .bind(LEASE_TTL_SECONDS)
        .bind(limit as i64)
        .bind(STATUS_PENDING)
        .bind(STATUS_PUBLISHING)
        .bind(STATUS_PUBLISHED)
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
                Ok(Entry::new(
                    topic,
                    idem_key,
                    OutboxPayload::from_reviewed_event_bytes(payload),
                ))
            })
            .collect()
    }
}

// ── OutboxRelay impl ──────────────────────────────────────────────────────────

impl OutboxRelay for PgOutbox {
    /// CAS relay 单条 entry：acquire → publish → settle。
    ///
    /// `PublisherError` 携 kind（#1212）——`Permanent`（序列化 / 路由 / 编码非法）首投即 dlx（跳过重试预算）；
    /// `Transient`（连接闪断等可恢复）退避重试至预算耗尽再 dlx。分流见 [`settle_publish_failure`] /
    /// [`dlx_decision`]。DB/CAS 失败返 `Err(EngineError)`；publish 失败是**已处置**（返 `Ok(Disposition)`）。
    async fn relay(&self, entry: &Entry) -> Result<consistency::Disposition, EngineError> {
        let event_id = entry.idem_key().as_str();

        // 1. CAS acquire：把 pending（或 stale publishing）行翻转到 publishing，返 (retry_count, lease_token)。
        let maybe_lease = acquire_lease(&self.pool, event_id).await?;

        let (retry_count, lease_token, metadata_json, domain, contract_id, topic, now_epoch) =
            match maybe_lease {
                // 0 行：已被他人发或已 published → 幂等 Ack，禁二次 publish。
                None => return Ok(consistency::Disposition::Ack),
                Some(lease) => lease,
            };
        let metadata = self.sign_metadata(
            hydrate_envelope_metadata(&metadata_json),
            &domain,
            &contract_id,
            &topic,
            event_id,
            now_epoch,
        )?;

        // 2. 发布到 broker。event_id（= idem_key）盖章到 broker message_id，经订阅侧流回消费幂等键
        //    （至少一次 + 幂等去重端到端，eventbus.md §DLX 与幂等）。
        //    metadata_json 从 outbox.metadata 列 hydrate → EnvelopeMetadata（#1160 A4）。
        let publish_result = self
            .publisher
            .publish(
                PublishRequest::new(
                    diport::Topic::new(entry.topic().as_str()),
                    diport::MessageId::new(event_id),
                    entry.payload().to_vec(),
                )
                .with_metadata(metadata),
            )
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
                settle_publish_failure(
                    &self.pool,
                    &self.payload_protector,
                    entry,
                    retry_count,
                    &lease_token,
                    &e,
                )
                .await
            }
        }
    }
}

impl PgOutbox {
    fn sign_metadata(
        &self,
        mut metadata: EnvelopeMetadata,
        domain: &str,
        contract_id: &str,
        topic: &str,
        event_id: &str,
        now_epoch: i64,
    ) -> Result<EnvelopeMetadata, EngineError> {
        let tenant = metadata
            .tenant_id()
            .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))?;
        let token = self
            .tenant_authority
            .sign_at(
                TenantAuthorityBinding::new(tenant, domain, contract_id, topic, event_id),
                now_epoch,
            )
            .map_err(|e| {
                tracing::error!(
                    target: "postgres",
                    domain,
                    contract_id,
                    topic,
                    event_id,
                    error = %secure::redact_error(&e),
                    "outbox relay failed to sign tenant authority"
                );
                EngineError::new(EngineErrorKind::Invariant)
            })?;
        metadata.insert_wire_pair(diport::KEY_TENANT_AUTHORITY, token);
        Ok(metadata)
    }
}

/// outbox.metadata（jsonb→text）→ [`EnvelopeMetadata`]：逐 key-value 经 `insert_wire_pair` 透传。
///
/// string 值直接用；number / bool 等 stringify（occurred_at 在 DB 存 number → 十进制 string，
/// [`EnvelopeMetadata::occurred_at_secs`] 再反解析）。
// reason: fail-safe——非对象 JSON / 解析失败返 empty 而非 Err，不阻 relay；relay 核心语义是
// at-least-once 投递，envelope 降级省略 metadata 比阻断投递更安全。
fn hydrate_envelope_metadata(json: &str) -> EnvelopeMetadata {
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json) else {
        tracing::debug!(target: "postgres", json_len = json.len(), "outbox: hydrate_envelope_metadata: non-object/invalid json, proceeding without metadata");
        return EnvelopeMetadata::empty();
    };
    let mut md = EnvelopeMetadata::empty();
    for (k, v) in map {
        let s = match v {
            serde_json::Value::String(s) => s,
            // number（如 occurred_at）→ 十进制 string（无 JSON 引号），boolean/null → compact form。
            other => other.to_string(),
        };
        md.insert_wire_pair(k, s);
    }
    md
}

/// publish 失败处置（抽出控制 `relay` 认知复杂度 ≤15）：永久错误首投即 dlx、预算耗尽 → dlx；否则退避 retry
/// （#1212，分流谓词见 [`dlx_decision`]）。
///
/// settle CAS 命中 `LostLease`（0 行）⇒ 行已被新租约接管：本租约不拥有该行、不重复处置，记 lost-lease
/// 后退化为 `Ack`（benign handoff，新持租者负责重投/退避），不误把 broker 失败上抛成本 worker 的降级（F3）。
async fn settle_publish_failure(
    pool: &sqlx::PgPool,
    payload_protector: &DlxPayloadProtector,
    entry: &Entry,
    retry_count: i32,
    lease_token: &str,
    err: &PublisherError,
) -> Result<consistency::Disposition, EngineError> {
    let event_id = entry.idem_key().as_str();
    let new_count = retry_count + 1;
    let permanent = err.is_permanent();
    log_publish_failed(event_id, entry.topic().as_str(), retry_count, err);
    if dlx_decision(permanent, new_count) {
        match settle_dlx(pool, payload_protector, event_id, new_count, lease_token).await? {
            SettleOutcome::Settled => {
                log_dlx(event_id, new_count, permanent);
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
/// `PublisherError::Display` 是受控安全摘要（diport PII 边界）；`permanent` 字段（#1212）让单条日志即可
/// 区分「瞬态退避重试」与「永久即将首投 DLX」，无需关联后续 `log_dlx`（便于 metric 聚合 / alert）。
fn log_publish_failed(event_id: &str, topic: &str, retry_count: i32, err: &PublisherError) {
    tracing::warn!(target: "postgres", event_id, topic, retry_count, permanent = err.is_permanent(), error = %secure::redact_error(err), "outbox: publish failed");
}

/// 进 dlx（运维须感知）。`permanent`：`true`=错误本身永久（首投即 DLX，跳过预算）；`false`=瞬态重试预算耗尽。
///
/// **排障路径**：relay 侧 Entry 不携 partition_key；dlx 冻结某 partition 时，运维可经
/// `SELECT partition_key, domain FROM outbox WHERE event_id = $event_id` 定位被冻结的 partition，
/// 再经 re-drive（`UPDATE outbox SET status='pending', retry_count=0, retry_after=NULL WHERE event_id=…`）
/// 解冻队头并放行后继。主动 partition 级监控信号（batch dlx gauge）见 issue **#1406**（不在本 PR）。
fn log_dlx(event_id: &str, attempts: i32, permanent: bool) {
    tracing::error!(target: "postgres", event_id, attempts, permanent, "outbox: publish failed, moved to dlx");
}

/// settle CAS 0 行（lost-lease fencing miss）：行已被新租约接管或已终结。结构化 warn（benign handoff，
/// 运维据 `event_id` + `operation` 关联，区分「干净结算」与「丢租约」，F3/F9）。
fn log_lost_lease(event_id: &str, operation: &str) {
    tracing::warn!(target: "postgres", event_id, operation, "outbox: settle hit lost lease (0 rows); row owned by another lease");
}

// ── RetentionSweeper impl ────────────────────────────────────────────────────────

impl RetentionSweeper for PgOutbox {
    /// 删除 `status='published'` 且早于保留期的行，返回删除条数。
    /// dlx 行不删（留运维巡检）。
    ///
    /// 时间谓词用 PostgreSQL `now()`（DB 事务时间）是刻意决策——见 [`PgOutbox`] 顶注。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        sweep_published_outbox(&self.pool, retain_seconds).await
    }
}

impl RetentionSweeper for PgOutboxMaintenance {
    /// 删除 `status='published'` 且早于保留期的行，返回删除条数。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        sweep_published_outbox(&self.pool, retain_seconds).await
    }
}

// ── OutboxBacklog impl ────────────────────────────────────────────────────────

/// Outbox 积压采样实现（单次聚合 SELECT，服务端 `now()`，读路径，不 FOR UPDATE）。
///
/// **索引决策（无新建）**：pre-GA 阶段 pending 行量小；现有
/// `idx_outbox_relay_scan ON outbox (domain, status, retry_after)` 已覆盖
/// `WHERE domain = $1 AND status = $2 AND (retry_after IS NULL OR retry_after <= now())`
/// 谓词，代价低廉。`min(created_at)` 聚合运行在已被索引过滤的小行集上，额外排序开销可忽略。
/// 若后续 profiling 显示瓶颈，跟进路径为偏索引
/// `CREATE INDEX ON outbox (domain, status, created_at) WHERE status = 'pending'`。
impl OutboxBacklog for PgOutbox {
    /// 采样 `domain` 的**可投递积压**（深度 + 最老积压龄）。
    ///
    /// 谓词与 [`OutboxSource::poll_pending`] 的可重捞集合**同源**（见本文件 `poll_pending` 的 WHERE）：
    /// `(status=pending 且到期) OR (status=publishing 且 lease 过期 `updated_at <= now()-LEASE_TTL_SECONDS`)`。
    /// stale `publishing`（崩溃/超时 in-flight）会被 relay 重投，属可投递积压，**必须计入**——否则 oldest-age
    /// SLO 对可恢复积压失明（relay 重捞但 gauge 报 0）。只排除 lease 仍有效的正常 in-flight。无可投递行 ⇒
    /// [`BacklogSample::empty`]。**不变式**：本谓词须随 `poll_pending` 同步改（集成测试 T16/T18 + stale-publishing
    /// 用例锁定漂移）。
    ///
    /// **head-of-partition gate 是 poll-only by design**——被 gate 的后继仍计入 backlog depth（否则 stalled
    /// partition 对 SLO 失明）。backlog 谓词刻意不含 head-of-partition gate（见 `poll_pending` INVARIANT:
    /// OUTBOX-PARTITION-ORDER-01）。
    async fn sample_backlog(&self, domain: &str) -> Result<BacklogSample, EngineError> {
        sample_outbox_backlog(&self.pool, domain).await
    }
}

impl OutboxBacklog for PgOutboxMaintenance {
    /// 采样 `domain` 的**可投递积压**（深度 + 最老积压龄）。
    async fn sample_backlog(&self, domain: &str) -> Result<BacklogSample, EngineError> {
        sample_outbox_backlog(&self.pool, domain).await
    }
}

async fn sweep_published_outbox(
    pool: &sqlx::PgPool,
    retain_seconds: u64,
) -> Result<u64, EngineError> {
    // u64→i64：超 i64::MAX 的保留期是非法输入（负 interval 会反向清空全表），fail-closed。
    let secs =
        i64::try_from(retain_seconds).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
    let result = sqlx::query(
        r#"
        DELETE FROM outbox
        WHERE status = $2
          AND created_at <= now() - make_interval(secs => $1)
        "#,
    )
    .bind(secs)
    .bind(STATUS_PUBLISHED)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "outbox: sweep db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    Ok(result.rows_affected())
}

async fn sample_outbox_backlog(
    pool: &sqlx::PgPool,
    domain: &str,
) -> Result<BacklogSample, EngineError> {
    let row: (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*)                                                         AS depth,
               COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at)))::bigint, 0) AS oldest_age_seconds
        FROM outbox
        WHERE domain = $1
          AND (
                (status = $2 AND (retry_after IS NULL OR retry_after <= now()))
             OR (status = $3 AND updated_at <= now() - make_interval(secs => $4))
          )
        "#,
    )
    .bind(domain)
    .bind(STATUS_PENDING)
    .bind(STATUS_PUBLISHING)
    .bind(LEASE_TTL_SECONDS)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", domain, error = %secure::redact_error(&e), "outbox: sample_backlog db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    let (raw_depth, raw_age) = row;

    // count(*) 恒 ≥ 0；i64→u64 转换失败在理论上不可表达，fail-closed。
    let depth =
        u64::try_from(raw_depth).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;

    // clock skew 或极端 EXTRACT 结果可能返负值；负龄无语义，截断到 0。
    let oldest_age_seconds =
        u64::try_from(raw_age.max(0)).map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;

    Ok(BacklogSample::new(depth, oldest_age_seconds))
}

// ── relay 拆分 helper fn（认知复杂度 ≤ 15）────────────────────────────────────

/// CAS acquire：把 pending（或 stale publishing）行置 publishing，返回 `(retry_count, lease_token, metadata_json)`。
/// 返回 `None` 表示 0 行更新（已 published 或被他人占）。
///
/// `lease_token::text` 文本往返（不给 sqlx 加 uuid feature）；`settle_*` 以此 token 比对，
/// 防 stale 持租者把已被新租约结算的行误改（CAS fencing，spec data-model §outbox）。
/// `metadata::text` 返回 jsonb 列的 JSON 字符串表示（NOT NULL DEFAULT '{}'，恒有值），
/// relay 经 [`hydrate_envelope_metadata`] 重建为 [`EnvelopeMetadata`] 透传到 broker（#1160 A4）。
/// `pub(crate)`：integration 测试做 lease fencing 断言。
pub(crate) async fn acquire_lease(
    pool: &sqlx::PgPool,
    event_id: &str,
) -> Result<Option<(i32, String, String, String, String, String, i64)>, EngineError> {
    let row: Option<(i32, String, String, String, String, String, i64)> = sqlx::query_as(
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
        RETURNING retry_count, lease_token::text, metadata::text, domain, contract_id, topic,
                  EXTRACT(EPOCH FROM now())::bigint
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
    payload_protector: &DlxPayloadProtector,
    event_id: &str,
    new_retry_count: i32,
    lease_token: &str,
) -> Result<SettleOutcome, EngineError> {
    let mut tx = pool.begin().await.map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx begin db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    let row: Option<(String, String, String, Vec<u8>, String)> = sqlx::query_as(
        r#"
        UPDATE outbox
        SET status = $4,
            retry_count = $2,
            updated_at = now()
        WHERE event_id = $1
          AND status = $5
          AND lease_token = $3::uuid
        RETURNING domain, contract_id, topic, payload, metadata::text
        "#,
    )
    .bind(event_id)
    .bind(new_retry_count)
    .bind(lease_token)
    .bind(STATUS_DLX)
    .bind(STATUS_PUBLISHING)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    let Some((domain, contract_id, topic, payload, metadata_json)) = row else {
        tx.rollback().await.map_err(|e| {
            tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx rollback db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;
        return Ok(SettleOutcome::LostLease);
    };

    let metadata = parse_metadata_json(&metadata_json)?;
    let tenant = hydrate_envelope_metadata(&metadata_json)
        .tenant_id()
        .ok_or_else(|| EngineError::new(EngineErrorKind::Invariant))?;
    set_local_tenant(&mut tx, tenant).await.map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx set tenant db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    let protected = payload_protector
        .encrypt(
            DlxPayloadContext::new(
                tenant,
                DeadLetterSource::OutboxRelay.as_str(),
                &domain,
                &contract_id,
                &topic,
                None,
                event_id,
            ),
            &payload,
        )
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx encrypt payload error");
            EngineError::new(EngineErrorKind::Transient)
        })?;
    sqlx::query(
        r#"
        INSERT INTO dead_letter
            (tenant_id, message_id, domain, contract_id, topic, consumer_group,
             original_entry, original_entry_key_ref, original_entry_payload_len,
             original_entry_encoding, error_summary, num_attempts, source_kind, metadata)
        VALUES ($1::uuid, $2, $3, $4, $5, NULL, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(tenant.to_string())
    .bind(event_id)
    .bind(domain)
    .bind(contract_id)
    .bind(topic)
    .bind(sqlx::types::Json(protected.original_entry()))
    .bind(protected.key_ref())
    .bind(protected.payload_len())
    .bind(DLX_ORIGINAL_ENTRY_ENCODING)
    .bind(OUTBOX_RELAY_DLX_SUMMARY)
    .bind(new_retry_count)
    .bind(DeadLetterSource::OutboxRelay.as_str())
    .bind(sqlx::types::Json(&metadata))
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx dead_letter db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;

    tx.commit().await.map_err(|e| {
        tracing::warn!(target: "postgres", event_id, operation = "settle_dlx", error = %secure::redact_error(&e), "outbox: settle_dlx commit db error");
        EngineError::new(EngineErrorKind::Transient)
    })?;
    Ok(SettleOutcome::Settled)
}

fn parse_metadata_json(json: &str) -> Result<serde_json::Value, EngineError> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(_)) => {
            serde_json::from_str(json).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
        }
        Ok(_) | Err(_) => Err(EngineError::new(EngineErrorKind::Invariant)),
    }
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

/// 该次 publish 失败是否应进 DLX（而非退避重试）——#1212 瞬态/永久分流谓词。
///
/// `is_permanent`（来自 [`PublisherError::is_permanent`]）为真 ⇒ 首投即 dlx（重试同一消息无意义，跳过预算）；
/// 否则瞬态错误熬满重试预算（`new_count >= MAX_PUBLISH_ATTEMPTS`）才 dlx。`new_count` 是本次失败后的累计
/// 重试次数（= UPDATE 前 `retry_count + 1`）。
fn dlx_decision(is_permanent: bool, new_count: i32) -> bool {
    is_permanent || new_count >= MAX_PUBLISH_ATTEMPTS
}

/// 指数退避（秒），上限 3600。`retry_count` 是当前已重试次数（0-based，即 UPDATE 前的值）。
///
/// backoff = min(2^retry_count, 3600)。`const fn` ⇒ 可在 [`max_redelivery_window_secs`] 的 const
/// 求值与下游 `const { assert!(..) }` 编译期断言中复用（`.min()` 非 const，故展开成显式 `if`）。
pub(crate) const fn backoff_seconds(retry_count: i32) -> i64 {
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
    if val < MAX_BACKOFF { val } else { MAX_BACKOFF }
}

/// outbox 发布侧最坏重投窗口（秒）：`Σ backoff_seconds(0..MAX_PUBLISH_ATTEMPTS)`——一条 entry 从首投到
/// 耗尽重试预算（转 dlx）期间所有退避之和（当前策略 = 1+2+…+512 = 1023s）。
///
/// `inbox_dedup` 保留期下限校验引用此窗口（NServiceBus 去重铁律：去重保留期必须 > 重投窗口，否则迟到重投被
/// 误判 Fresh 重复执行；见 `inbox.rs` INVARIANT INBOX-DEDUP-RETENTION-FLOOR-01）。`const fn` ⇒ 可在
/// `const { assert!(..) }` 编译期断言中求值（把铁律上移到常量层，违反即编译失败，非运行期治理测试）。
pub(crate) const fn max_redelivery_window_secs() -> i64 {
    let mut total = 0i64;
    let mut rc = 0i32;
    while rc < MAX_PUBLISH_ATTEMPTS {
        total += backoff_seconds(rc);
        rc += 1;
    }
    total
}

// ── 单测 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // reserved key / subject key 常量来自 diport 单源（#1160 A4）。
    use super::{
        LEASE_TTL_SECONDS, MAX_PUBLISH_ATTEMPTS, OutboxEnvelope, OutboxMetadata, STATUS_DLX,
        STATUS_PENDING, STATUS_PUBLISHED, STATUS_PUBLISHING, backoff_seconds, dlx_decision,
        hydrate_envelope_metadata, max_redelivery_window_secs, metadata_with_ambient, unix_secs,
    };
    use diport::{
        EnvelopeSubjectId, KEY_ACTOR, KEY_CORRELATION, KEY_OCCURRED_AT, KEY_TRACE, MetadataError,
        OpaqueActorId, OutboxActor, RESERVED_METADATA_KEYS,
    };

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[allow(clippy::expect_used)]
    fn tenant() -> vocab::TenantId {
        vocab::TenantId::parse(TENANT).expect("canonical tenant")
    }

    fn metadata(occurred_at_secs: i64) -> OutboxMetadata {
        OutboxMetadata::new(occurred_at_secs, tenant())
    }

    #[allow(clippy::expect_used)]
    fn subject(raw: &str) -> EnvelopeSubjectId {
        EnvelopeSubjectId::from_opaque(raw).expect("valid envelope subject")
    }

    #[allow(clippy::expect_used)]
    fn actor(raw: &str) -> OutboxActor {
        OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            OpaqueActorId::from_opaque(raw).expect("valid actor id"),
            tenant(),
            vocab::ScopedTenant::Tenant,
        )
    }

    // #1212 dlx 分流谓词表驱动：permanent 首投（new_count=1）即 dlx；transient 仅预算耗尽
    // （new_count >= MAX_PUBLISH_ATTEMPTS）才 dlx。anti-vacuity：transient 未到预算返 false（仍退避）。
    #[test]
    fn dlx_decision_table() {
        let cases: &[(bool, i32, bool)] = &[
            (true, 1, true),                          // permanent 首投即 dlx
            (true, MAX_PUBLISH_ATTEMPTS, true),       // permanent 任意次数仍 dlx
            (false, 1, false),                        // transient 首投 → 退避（不 dlx）
            (false, MAX_PUBLISH_ATTEMPTS - 1, false), // transient 预算未尽 → 退避
            (false, MAX_PUBLISH_ATTEMPTS, true),      // transient 预算耗尽 → dlx
            (false, MAX_PUBLISH_ATTEMPTS + 1, true),  // transient 超预算 → dlx
        ];
        for &(is_permanent, new_count, want) in cases {
            assert_eq!(
                dlx_decision(is_permanent, new_count),
                want,
                "dlx_decision(permanent={is_permanent}, new_count={new_count})"
            );
        }
    }

    // OutboxEnvelope 构造 + 字段访问（metadata 经 OutboxMetadata funnel，F1）。
    #[test]
    fn envelope_new_and_fields() -> Result<(), serde_json::Error> {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new(
            "identity".to_string(),
            "contract-1".to_string(),
            metadata(1_700_000_000).with_subject_id(subject("tenant-42")),
        );
        assert_eq!(env.domain(), "identity");
        assert_eq!(env.contract_id(), "contract-1");
        let parsed = serde_json::from_str::<serde_json::Value>(&env.metadata_json())?;
        assert_eq!(
            parsed,
            serde_json::json!({
                "occurredAt": 1_700_000_000,
                "subjectId": "tenant-42",
                "tenantId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            })
        );
        Ok(())
    }

    // #262 F1：occurredAt 构造期必填——`new(secs)` 仅 occurredAt（无 subject）即含该 reserved key。
    #[test]
    fn metadata_new_always_carries_occurred_at() {
        use super::OutboxEnvelope;
        let env = OutboxEnvelope::new("d".to_string(), "c".to_string(), metadata(0));
        assert_eq!(
            env.metadata_json(),
            r#"{"occurredAt":0,"tenantId":"f47ac10b-58cc-4372-a567-0e02b2c3d479"}"#
        );
    }

    // F1 负向（anti-vacuity，INVARIANT OUTBOX-METADATA-FUNNEL-01）：reserved key 经 try_insert
    // fail-closed 拒；非 reserved key 接受并经 funnel 序列化（occurredAt 由 new 构造期注入）。
    #[test]
    fn metadata_try_insert_rejects_reserved_key() {
        for reserved in RESERVED_METADATA_KEYS {
            let mut m = metadata(0);
            assert_eq!(
                m.try_insert(reserved, serde_json::Value::Bool(true)),
                Err(MetadataError::ReservedKey),
                "reserved key must be rejected: {reserved}"
            );
        }
        let mut ok = metadata(0);
        assert!(
            ok.try_insert("tenantTier", serde_json::Value::String("gold".into()))
                .is_ok()
        );
        let env = super::OutboxEnvelope::new("d".to_string(), "c".to_string(), ok);
        // 键序字母：occurredAt < tenantTier。
        assert_eq!(
            env.metadata_json(),
            r#"{"occurredAt":0,"tenantId":"f47ac10b-58cc-4372-a567-0e02b2c3d479","tenantTier":"gold"}"#
        );
    }

    // #1129/#262 F1：new(secs) 构造期注入 reserved occurredAt（unix 秒 i64）；opaque subjectId 共存。
    // 本测试走**直接** new()+with_subject_id 路径（非 metadata_with_ambient）：trace（#1224 经
    // tracewire::capture 注入）/ correlation（#1160 经 diagctx 注入）/ principal（待 #1397）都只在 ambient
    // helper 路径盖章，故此直接构造路径不含——验证 new 的最小接缝不夹带 ambient reserved key。
    #[test]
    fn metadata_new_writes_occurred_at_unix_secs() {
        let env = super::OutboxEnvelope::new(
            "identity".to_string(),
            "c".to_string(),
            metadata(1_700_000_000).with_subject_id(subject("subj-1")),
        );
        let json = env.metadata_json();
        assert!(
            json.contains(r#""occurredAt":1700000000"#),
            "occurredAt 应以 unix 秒 i64 写入: {json}"
        );
        assert!(
            json.contains(r#""subjectId":"subj-1""#),
            "opaque subjectId 应共存: {json}"
        );
        for absent in ["trace", "correlation", "principal"] {
            assert!(
                !json.contains(absent),
                "此路径（new+with_subject_id，非 metadata_with_ambient）不盖章 ambient reserved key {absent}: {json}"
            );
        }
    }

    // #1129/#262 anti-vacuity：构造期 new 注入 occurred_at，而业务 free-form try_insert 对同名 reserved key
    // 仍 fail-closed 拒——构造期注入与业务写入两路径互斥，业务侧不可伪造 reserved。
    #[test]
    fn occurred_at_construct_writes_but_free_form_rejects() {
        // 构造期注入成功。
        let sealed = metadata(42);
        let env = super::OutboxEnvelope::new("d".to_string(), "c".to_string(), sealed);
        assert!(env.metadata_json().contains(r#""occurredAt":42"#));
        // 业务 free-form 路径仍拒同名 reserved key。
        let mut free = metadata(0);
        assert_eq!(
            free.try_insert(KEY_OCCURRED_AT, serde_json::Value::from(42)),
            Err(MetadataError::ReservedKey),
            "业务 free-form 路径不得写 reserved occurred_at"
        );
    }

    // #1129 drift-lock：构造期注入的 occurred_at key 必属 reserved 集（注入集 ⊆ 拒绝集，防漂移）。
    #[test]
    fn occurred_at_key_is_reserved() {
        assert!(
            RESERVED_METADATA_KEYS.contains(&KEY_OCCURRED_AT),
            "new 写的 occurred_at key 必须在 RESERVED_METADATA_KEYS 内"
        );
    }

    // #1193 正向：sealed setter with_trace / with_correlation 写入对应 reserved key（funnel 特权），
    // 与 occurred_at / subjectId 共存。键序 order-independent 断言——`serde_json::Map` 序列化次序随
    // `preserve_order` feature 变（workspace 统一 on=插入序 / 隔离 off=字母序），故逐 key-value 子串校验。
    #[test]
    fn sealed_setters_write_reserved_keys() -> Result<(), serde_json::Error> {
        let env = super::OutboxEnvelope::new(
            "identity".to_string(),
            "identity.session-created".to_string(),
            metadata(1_700_000_000)
                .with_subject_id(subject("subj-1"))
                .with_actor(actor("actor-1"))
                .with_trace("trace-abc")
                .with_correlation("corr-xyz"),
        );
        let json = env.metadata_json();
        for kv in [
            r#""occurredAt":1700000000"#,
            r#""subjectId":"subj-1""#,
            r#""trace":"trace-abc""#,
            r#""correlation":"corr-xyz""#,
        ] {
            assert!(
                json.contains(kv),
                "sealed setter metadata 应含 {kv}: {json}"
            );
        }
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        assert_eq!(parsed["actor"]["kind"], "admin");
        assert_eq!(parsed["actor"]["id"], "actor-1");
        assert_eq!(parsed["actor"]["scope"], "tenant");
        assert_eq!(parsed["actor"]["tenantId"], TENANT);
        Ok(())
    }

    // #1193 anti-vacuity：sealed setter 注入成功，而业务 free-form try_insert 对同名 reserved key 仍
    // fail-closed 拒——两路径互斥，业务侧不可伪造 trace / correlation。
    #[test]
    fn sealed_setter_keys_rejected_on_free_form() {
        for reserved in [KEY_TRACE, KEY_CORRELATION] {
            let mut free = metadata(0);
            assert_eq!(
                free.try_insert(reserved, serde_json::Value::String("x".into())),
                Err(MetadataError::ReservedKey),
                "业务 free-form 路径不得写 reserved {reserved}"
            );
        }
    }

    // #1193 drift-lock：sealed setter 注入的 trace / correlation key 必属 reserved 集（注入集 ⊆ 拒绝集）。
    #[test]
    fn reserved_setter_keys_are_reserved() {
        for key in [KEY_TRACE, KEY_CORRELATION, KEY_ACTOR] {
            assert!(
                RESERVED_METADATA_KEYS.contains(&key),
                "sealed setter 写的 {key} 必须在 RESERVED_METADATA_KEYS 内"
            );
        }
    }

    // #1129 unix_secs 边界收口（从 session_lifecycle 合并入本 crate 单源）：正常偏移直映。
    #[test]
    fn unix_secs_maps_offset() {
        let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(unix_secs(t), 1_700_000_000);
    }

    // 负偏移（早于 epoch，时钟偏斜）：duration_since 返回 Err → 收口 0（不 panic、不返负）。
    #[test]
    fn unix_secs_clamps_before_epoch_to_zero() {
        let t = std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1);
        assert_eq!(unix_secs(t), 0);
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
        const MIGRATION: &str = include_str!("../migrations/0003_create_outbox.sql");
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

    #[test]
    fn runtime_serving_migration_grants_current_outbox_runtime_dml_to_rss_app() {
        const MIGRATION: &str = include_str!("../migrations/0030_grant_runtime_serving.sql");
        assert!(
            MIGRATION.contains("GRANT SELECT, INSERT, UPDATE, DELETE ON outbox TO rss_app"),
            "current runtime uses rss_app PgStore for outbox write, relay, sampler, and sweeper until dedicated outbox roles land"
        );
        assert!(
            MIGRATION.contains("ON inbox_dedup TO rss_app"),
            "anti-vacuity: runtime serving migration should still contain serving grants"
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

    // max_redelivery_window_secs = Σ backoff_seconds(0..MAX_PUBLISH_ATTEMPTS)。当前策略 10 次：
    // 1+2+4+8+16+32+64+128+256+512 = 1023s。anti-vacuity：窗口 > 0（供 inbox 保留期下限编译期断言引用）。
    #[test]
    fn max_redelivery_window_secs_sums_backoffs() {
        let expected: i64 = (0..MAX_PUBLISH_ATTEMPTS).map(backoff_seconds).sum();
        assert_eq!(
            max_redelivery_window_secs(),
            expected,
            "window must equal Σ backoff over the retry budget"
        );
        assert_eq!(max_redelivery_window_secs(), 1023, "current policy = 1023s");
        assert!(max_redelivery_window_secs() > 0, "window must be positive");
    }

    // ── hydrate_envelope_metadata 表驱动（#1160 A4）──────────────────────────

    // occurredAt number → 十进制 string（occurred_at_secs() 可反解析）。
    // subjectId string → 原值透传。
    // correlation string → 原值透传。
    // 空对象 → empty metadata。
    // 无效 JSON → empty metadata（fail-safe，不阻 relay）。
    // 多键确定性（BTreeMap 序）→ 全部可读取。
    // boolean/null value → compact string（other.to_string() 分支）。
    #[test]
    fn hydrate_envelope_metadata_table() {
        // occurredAt number → string（occurred_at_secs 解析为 i64）。
        let md = hydrate_envelope_metadata(r#"{"occurredAt":1700000000}"#);
        assert_eq!(
            md.occurred_at_secs(),
            Some(1_700_000_000),
            "occurredAt number → parseable string"
        );

        // subjectId string → 直接透传。
        let md = hydrate_envelope_metadata(r#"{"subjectId":"user-7"}"#);
        assert_eq!(
            md.get("subjectId"),
            Some("user-7"),
            "subjectId string passthrough"
        );

        // correlation string → 直接透传。
        let md = hydrate_envelope_metadata(r#"{"correlation":"corr-1"}"#);
        assert_eq!(
            md.get("correlation"),
            Some("corr-1"),
            "correlation string passthrough"
        );

        // 空对象 → empty（is_empty 为真）。
        let md = hydrate_envelope_metadata("{}");
        assert!(md.is_empty(), "空对象 → empty metadata");

        // 无效 JSON → fail-safe empty（不阻 relay）。
        let md = hydrate_envelope_metadata("not-valid-json");
        assert!(md.is_empty(), "invalid JSON → empty metadata (fail-safe)");

        // 多键：全部可读。
        let md =
            hydrate_envelope_metadata(r#"{"correlation":"c","occurredAt":42,"subjectId":"u"}"#);
        assert_eq!(md.occurred_at_secs(), Some(42), "multi-key occurredAt");
        assert_eq!(md.get("subjectId"), Some("u"), "multi-key subjectId");
        assert_eq!(md.get("correlation"), Some("c"), "multi-key correlation");

        // boolean value → "true"（other.to_string() 分支，F4）。
        let md = hydrate_envelope_metadata(r#"{"k":true}"#);
        assert_eq!(md.get("k"), Some("true"), "boolean true → \"true\"");

        // null value → "null"（other.to_string() 分支，F4）。
        let md = hydrate_envelope_metadata(r#"{"k":null}"#);
        assert_eq!(md.get("k"), Some("null"), "null → \"null\"");
    }

    // anti-vacuity（fail-safe）：有效 object 解析成功（上面测过）；这里再验 non-object 也走 empty 分支
    // （JSON array 是合法 JSON 但不是 object）。
    #[test]
    fn hydrate_envelope_metadata_non_object_json_is_empty() {
        let md = hydrate_envelope_metadata("[1,2,3]");
        assert!(md.is_empty(), "JSON array 不是 object → empty");
    }

    // ── metadata_with_ambient 测试（#1160 B3）────────────────────────────────

    // 有 diagctx scope → correlation 注入到 metadata（与 occurredAt 共存）。
    #[tokio::test]
    async fn metadata_with_ambient_injects_correlation_inside_scope() {
        // reason: 测试 fixture，输入为合法 correlation id。
        #[allow(clippy::unwrap_used)]
        let ctx = diagctx::DiagnosticCtx::new(diagctx::CorrelationId::parse("corr-x").unwrap());
        let json = diagctx::scope(ctx, async {
            let m = metadata_with_ambient(42, tenant());
            OutboxEnvelope::new("d".to_string(), "c".to_string(), m).metadata_json()
        })
        .await;
        assert!(
            json.contains(r#""correlation":"corr-x""#),
            "scope 内应含 correlation: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":42"#),
            "occurredAt 应存在: {json}"
        );
    }

    // 无 scope → correlation 不注入（fail-open 省略），occurredAt 仍在。
    // anti-vacuity：无 scope 不 panic、不 Err（fail-open 契约）。
    #[tokio::test]
    async fn metadata_with_ambient_omits_correlation_outside_scope() {
        let m = metadata_with_ambient(42, tenant());
        let json = OutboxEnvelope::new("d".to_string(), "c".to_string(), m).metadata_json();
        assert!(
            !json.contains("correlation"),
            "无 scope 时不应含 correlation key: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":42"#),
            "occurredAt 应存在: {json}"
        );
    }

    // ── metadata_with_ambient trace 透传测试（#1224）─────────────────────────

    // 活跃采样 span → metadata_with_ambient 经 tracewire::capture 盖章 reserved key `trace`
    //（W3C traceparent，与 occurredAt 共存）——#1224 emit 接线正路。otel subscriber 经 tracewire 脚手架装配
    //（本 crate 不直接 import otel）。
    #[test]
    fn metadata_with_ambient_stamps_trace_inside_span() {
        let json = tracewire::with_test_subscriber(|| {
            tracing::info_span!("producer").in_scope(|| {
                OutboxEnvelope::new(
                    "d".to_string(),
                    "c".to_string(),
                    metadata_with_ambient(7, tenant()),
                )
                .metadata_json()
            })
        });
        assert!(
            json.contains(r#""trace":"00-"#),
            "活跃 span 应盖章 W3C traceparent trace 键: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":7"#),
            "occurredAt 应存在: {json}"
        );
    }

    // 无 otel 层（capture→None）→ 不盖章 trace（fail-open 省略），occurredAt 仍在。
    // anti-vacuity：缺 otel 不 panic、不写 trace 键（与 inside-span 正路互证分支）。
    #[test]
    fn metadata_with_ambient_omits_trace_without_otel() {
        let json = OutboxEnvelope::new(
            "d".to_string(),
            "c".to_string(),
            metadata_with_ambient(7, tenant()),
        )
        .metadata_json();
        assert!(
            !json.contains(r#""trace""#),
            "无 otel 时不应含 trace 键: {json}"
        );
        assert!(
            json.contains(r#""occurredAt":7"#),
            "occurredAt 应存在: {json}"
        );
    }
}
