//! `PgAuditRepo` —— audit 审计链仓储的 PostgreSQL adapter（#1230 Part A step 5）。
//!
//! impl `audit::ports::AuditWriteRepo` + `AuditReadRepo`，作 per-tenant keyed-HMAC 链的
//! durable provider（替换 in-mem `InMemAuditRepo` 于生产路径）。adapter→域 DIP 内向边（postgres 依赖 audit，
//! 经 deny.toml audit wrapper + `allows(Adapter,Domain)` 放行；adapter 仍不被域依赖）。
//!
//! 持久化模型（`0018_create_audit_entries.sql`）：audit_entries 表 PK (tenant_id, seq)；
//! **append-only**（rss_app 仅 SELECT+INSERT，无 UPDATE/DELETE；DB 层阻止覆写）。
//! **recorded_at 两列**（`recorded_at_secs bigint` + `recorded_at_nanos integer`，非 timestamptz）：
//! timestamptz 截断 ns 精度，canonical HMAC message 含 secs(u64 BE)+nanos(u32 BE)（AUDIT-LEDGER-BYTES-01），
//! 截断会使重算 entry_hash 不匹配 → verify 假阳；两列精确对称哈希输入（见 migration 注释）。
//!
//! 原子性：append 经 `pg_advisory_xact_lock`（per-tenant i64 key）串行化同租户并发写——读 tail → 分配
//! seq → INSERT 在单事务锁保护下，消除 seq 竞争 / 重复；`(tenant_id, seq)` PK 作兜底 unique 拦截。
//! list / verify_tail 是只读路径（begin + typed tenant scope + SELECT + commit），增量 verify_window（窗口+1前驱）。
//!
//! 租户隔离：写 / 读路径分别经 typed write/read scope funnel 注入租户 GUC + 显式
//! `WHERE tenant_id = $1::uuid`（双重隔离，跨租 → 0 行 → fail-closed）。
//!
//! ref: adapters/postgres/src/credential_repo.rs（pool 注入 / tenant scope / storage 收口 / hydrate 范本）
//! ref: crates/audit/src/internal/mem.rs（cursor encode/decode + verify_window 调用语义；postgres 改用 seq 键，
//!   非 Vec 下标）

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use audit::ports::{
    AuditAdminRepo, AuditChainHasher, AuditEntry, AuditError, AuditLedgerVerifyReport,
    AuditListResult, AuditOutcome, AuditPage, AuditReadRepo, AuditRecord, AuditWriteRepo,
    CrossTenantReadScope, EntryHash, ResourceRef, TenantId, TenantRepoScope, actor_kind_from_db,
    actor_kind_to_db,
};
use base64::Engine as _;
use primitives::MacVerifier;
use sqlx::{PgConnection, Row};

use crate::cotx::{PgAuditAdminReadPool, PgTenantReadPool, PgTenantWritePool, infra_tenant_scope};
use crate::pool::{VerifiedPgAuditAdminStore, VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::tx_retry::{AUDIT_APPEND_BOUNDARY, classify_audit_error, run_pg_tx_retry};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// SELECT 列清单（list / verify_tail / 前驱行共用；actor::text 转换 UUID→String，无需 uuid feature）。
const SELECT_COLS: &str = "tenant_id::text AS tenant_id, seq, prev_hash, entry_hash, key_id, actor::text AS actor, actor_kind, \
                           action, resource_kind, resource_id, outcome, \
                           recorded_at_secs, recorded_at_nanos";

/// audit 数据表名（const 单源，消除 5 处 SQL 字面量漂移，同义字符串 ≥3 次须抽 const）。
const TABLE: &str = "audit_entries";

/// Closed identity of the only audit-chain HMAC key generation accepted by this release.
///
/// Rotation is intentionally not implicit: a future key requires a new typed variant, migration,
/// and row-level verification policy. A different secret under `V1` is rejected by the durable
/// startup pin before any listener or event consumer is activated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditChainKeyIdentity(i16);

impl AuditChainKeyIdentity {
    /// Current and only supported chain key generation.
    pub const V1: Self = Self(1);

    pub(crate) const fn as_i16(self) -> i16 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// PgAuditRepo
// ---------------------------------------------------------------------------

/// audit 审计链仓储的 PostgreSQL adapter（impl read/write ports，#1230）。
///
/// 仅由已验证 reader/writer capability 构造（同 [`crate::PgRoleRepo`]）。
/// `hasher` 持 keyed HMAC verifier + key（构造器必填，无 key 不可造 hasher，防篡改属性类型层成立）。
pub struct PgAuditRepo<M: primitives::MacVerifier> {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
    hasher: Arc<AuditChainHasher<M>>,
}

/// audit 审计链的跨租户只读 admin adapter。
///
/// 使用专用 `rss_audit_admin` pool，但仍通过 [`PgAuditAdminReadPool`] 注入 target tenant scope，
/// 复用 `audit_entries` 现有 FORCE RLS tenant policy；本类型不实现 append/write 能力。
pub struct PgAuditAdminRepo<M: primitives::MacVerifier> {
    pool: PgAuditAdminReadPool,
    hasher: Arc<AuditChainHasher<M>>,
}

impl<M: MacVerifier + Send + Sync> PgAuditRepo<M> {
    /// 由已验证 reader/writer capability + `hasher` 构造。
    pub(crate) fn new(
        reader: &VerifiedPgReadStore,
        writer: &VerifiedPgWriteStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::new(writer),
            hasher: Arc::new(hasher),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(
        store: &crate::PgStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
            hasher: Arc::new(hasher),
        }
    }
}

impl<M: MacVerifier + Send + Sync> PgAuditAdminRepo<M> {
    /// 由专用已验证 audit-admin capability + `hasher` 构造（不暴露裸 pool）。
    pub(crate) fn new(store: &VerifiedPgAuditAdminStore, hasher: AuditChainHasher<M>) -> Self {
        Self {
            pool: PgAuditAdminReadPool::new_admin(store),
            hasher: Arc::new(hasher),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(
        store: &crate::PgStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self {
            pool: PgAuditAdminReadPool::from_unverified_for_test(store),
            hasher: Arc::new(hasher),
        }
    }
}

// ---------------------------------------------------------------------------
// 错误 / 类型辅助
// ---------------------------------------------------------------------------

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口）。
fn storage(e: sqlx::Error) -> AuditError {
    AuditError::storage(e)
}

/// `TenantId` → SQL bind 参数（UUID string；与 `$N::uuid` server-side cast 配合，不加 sqlx uuid feature）。
pub(crate) fn tenant_str(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

/// per-tenant advisory lock key（i64；XOR UUID 高低 8 字节；均匀分布、确定性）。
pub(crate) fn advisory_lock_key(tenant: TenantId) -> i64 {
    let b = *tenant.as_uuid().as_bytes();
    let hi = i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let lo = i64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
    hi ^ lo
}

// ---------------------------------------------------------------------------
// 游标 encode / decode（base64url, URL_SAFE_NO_PAD）
// ---------------------------------------------------------------------------

/// 把 seq（u64）编码为不透明游标（下一页起始 seq 的 base64url 十进制字符串）。
///
/// # Errors
/// base64url(十进制数字串) 始终满足 `Cursor::parse` 格式约束，`Err` 分支防御性 fail-closed（不可达）。
// reason: base64url(decimal) 始终合法，Err 分支不可达；返回 Result 防止静默产出 next_cursor=None +
// has_more=true 的矛盾分页响应（broken pagination fail-closed 优于 silent drop）。
fn encode_cursor(next_seq: u64) -> Result<vocab::Cursor, AuditError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(next_seq.to_string());
    vocab::Cursor::parse(&raw)
        .map_err(|_| AuditError::storage(std::io::Error::other("cursor encode failed")))
}

/// 解码游标回 u64 seq（fail-closed：非法 base64url / 非 UTF-8 / 非数字 → `InvalidCursor`）。
fn decode_cursor(cursor: &vocab::Cursor) -> Result<u64, AuditError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| AuditError::InvalidCursor)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| AuditError::InvalidCursor)?;
    s.parse::<u64>().map_err(|_| AuditError::InvalidCursor)
}

// ---------------------------------------------------------------------------
// 行 hydration
// ---------------------------------------------------------------------------

/// 从数据库行重建 [`AuditEntry`]（fail-closed：未知 actor_kind / outcome / 无效 UUID → Storage）。
///
/// 所有列名须与 [`SELECT_COLS`] + 查询 `actor::text AS actor` 对齐。`tenant` 来自调用方 typed scope；
/// 行内 `tenant_id` 仍读取并比对，作为 RLS + WHERE 之外的混租户防御纵深。
fn hydrate_row(row: &sqlx::postgres::PgRow, tenant: TenantId) -> Result<AuditEntry, AuditError> {
    let tenant_str: String = row.try_get("tenant_id").map_err(storage)?;
    let row_tenant = TenantId::parse(&tenant_str).map_err(AuditError::storage)?;
    if row_tenant != tenant {
        return Err(AuditError::ChainBroken);
    }
    let key_id: i16 = row.try_get("key_id").map_err(storage)?;
    if key_id != AuditChainKeyIdentity::V1.as_i16() {
        return Err(AuditError::ChainBroken);
    }

    let seq_i64: i64 = row.try_get("seq").map_err(storage)?;
    let seq = u64::try_from(seq_i64).map_err(AuditError::storage)?;

    let prev_bytes: Vec<u8> = row.try_get("prev_hash").map_err(storage)?;
    let prev_arr: [u8; 32] = prev_bytes.try_into().map_err(|_| {
        AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "prev_hash wrong length",
        ))
    })?;

    let hash_bytes: Vec<u8> = row.try_get("entry_hash").map_err(storage)?;
    let hash_arr: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "entry_hash wrong length",
        ))
    })?;

    let actor_str: String = row.try_get("actor").map_err(storage)?;
    let actor = ids::UserId::parse(&actor_str).map_err(AuditError::storage)?;

    let actor_kind_str: String = row.try_get("actor_kind").map_err(storage)?;
    let actor_kind = actor_kind_from_db(&actor_kind_str).ok_or_else(|| {
        AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown actor_kind",
        ))
    })?;

    let action_str: String = row.try_get("action").map_err(storage)?;
    let action = vocab::Action::parse(&action_str).map_err(AuditError::storage)?;

    let resource_kind: String = row.try_get("resource_kind").map_err(storage)?;
    let resource_id: String = row.try_get("resource_id").map_err(storage)?;
    let resource = ResourceRef::new(resource_kind, resource_id);

    let outcome_str: String = row.try_get("outcome").map_err(storage)?;
    let outcome = AuditOutcome::from_db(&outcome_str).ok_or_else(|| {
        AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown outcome",
        ))
    })?;

    let at_secs: i64 = row.try_get("recorded_at_secs").map_err(storage)?;
    let at_nanos: i32 = row.try_get("recorded_at_nanos").map_err(storage)?;
    // reason: 注入时钟产生的 recorded_at 必 ≥ epoch，secs 为负（pre-epoch）在审计场景不可达；0 = epoch 防御兜底。
    let secs = u64::try_from(at_secs).unwrap_or(0);
    // reason: DB CHECK (recorded_at_nanos >= 0 AND < 1_000_000_000) 保证 i32→u32 转换不失败；0 = 0ns 防御兜底。
    let nanos = u32::try_from(at_nanos).unwrap_or(0);
    let recorded_at = UNIX_EPOCH + Duration::new(secs, nanos);

    Ok(AuditEntry::hydrate(
        seq,
        EntryHash::new(prev_arr),
        EntryHash::new(hash_arr),
        actor,
        actor_kind,
        tenant,
        action,
        resource,
        outcome,
        recorded_at,
    ))
}

// ---------------------------------------------------------------------------
// append 辅助
// ---------------------------------------------------------------------------

/// 读取租户子链尾部（seq + entry_hash）；空链返回 (0, genesis)。
async fn read_tail(
    tx: &mut PgConnection,
    tenant_uuid: &str,
) -> Result<(u64, EntryHash), AuditError> {
    let row = sqlx::query(&format!(
        "SELECT seq, entry_hash \
         FROM {TABLE} \
         WHERE tenant_id = $1::uuid \
         ORDER BY seq DESC LIMIT 1",
    ))
    .bind(tenant_uuid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;

    let Some(r) = row else {
        return Ok((0, EntryHash::genesis()));
    };

    let seq_i64: i64 = r.try_get("seq").map_err(storage)?;
    let seq = u64::try_from(seq_i64).map_err(AuditError::storage)?;
    let next_seq = seq.checked_add(1).ok_or(AuditError::SequenceGap)?;
    let hash_bytes: Vec<u8> = r.try_get("entry_hash").map_err(storage)?;
    let arr: [u8; 32] = hash_bytes.try_into().map_err(|_| {
        AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tail entry_hash wrong length",
        ))
    })?;

    Ok((next_seq, EntryHash::new(arr)))
}

/// 在事务内插入审计行（所有字段）。
async fn insert_entry(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    seq: u64,
    prev: &EntryHash,
    entry_hash: &EntryHash,
    record: &AuditRecord,
) -> Result<(), AuditError> {
    let seq_i64 = i64::try_from(seq).map_err(AuditError::storage)?;
    let since_epoch = record
        .recorded_at
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    // reason: secs 在 u64::MAX / 2 量级，epoch 后的时间 secs 适合 i64，转换不失败；
    // 越界（理论不可达，2^63 秒 ≈ 292 亿年）fail-closed 取 i64::MAX（DB bigint 可存）。
    let at_secs = i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX);
    // safe: subsec_nanos ∈ 0..=999_999_999 < i32::MAX，无截断。
    let at_nanos = since_epoch.subsec_nanos() as i32;

    sqlx::query(&format!(
        "INSERT INTO {TABLE} \
         (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, \
          resource_kind, resource_id, outcome, recorded_at_secs, recorded_at_nanos, key_id) \
         VALUES \
         ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13)",
    ))
    .bind(tenant_uuid)
    .bind(seq_i64)
    .bind(prev.as_bytes().as_slice())
    .bind(entry_hash.as_bytes().as_slice())
    .bind(record.actor.as_uuid().to_string())
    .bind(actor_kind_to_db(record.actor_kind))
    .bind(record.action.as_str())
    .bind(record.resource.kind())
    .bind(record.resource.id())
    .bind(record.outcome.to_db())
    .bind(at_secs)
    .bind(at_nanos)
    .bind(AuditChainKeyIdentity::V1.as_i16())
    .execute(&mut *tx)
    .await
    .map_err(storage)?;

    Ok(())
}

/// append 事务体：SET LOCAL → advisory lock → tail → link → INSERT。
pub(crate) async fn append_in_tx<M: MacVerifier>(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    lock_key: i64,
    record: &AuditRecord,
    hasher: &AuditChainHasher<M>,
) -> Result<(), AuditError> {
    // 串行化同租户并发 append（xact-level advisory lock，commit/rollback 自动释放）。
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *tx)
        .await
        .map_err(storage)?;

    let (seq, prev) = read_tail(tx, tenant_uuid).await?;

    // 用占位 entry_hash 构造 raw（算哈希时不含 entry_hash 自身，canonical_message 仅含 entry 内容）。
    let raw = AuditEntry::hydrate(
        seq,
        prev,
        EntryHash::genesis(),
        record.actor,
        record.actor_kind,
        record.tenant,
        record.action.clone(),
        record.resource.clone(),
        record.outcome,
        record.recorded_at,
    );
    let entry_hash = hasher.link(&prev, &raw);

    insert_entry(tx, tenant_uuid, seq, &prev, &entry_hash, record).await
}

// ---------------------------------------------------------------------------
// list / verify_tail 辅助
// ---------------------------------------------------------------------------

/// 取前驱行（seq = pred_seq）并 hydrate；行不存在返回 None（链首 genesis，前驱 = None）。
async fn fetch_predecessor(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    pred_seq_i64: i64,
    tenant: TenantId,
) -> Result<Option<AuditEntry>, AuditError> {
    let row = sqlx::query(&format!(
        "SELECT {SELECT_COLS} \
         FROM {TABLE} \
         WHERE tenant_id = $1::uuid AND seq = $2"
    ))
    .bind(tenant_uuid)
    .bind(pred_seq_i64)
    .fetch_optional(&mut *tx)
    .await
    .map_err(storage)?;

    match row {
        None => Ok(None),
        Some(r) => Ok(Some(hydrate_row(&r, tenant)?)),
    }
}

/// list 事务体：SET LOCAL → 前驱 + 窗口读取 → hydrate → verify_window → 游标组装。
async fn list_in_tx<M: MacVerifier>(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    tenant: TenantId,
    start_seq: u64,
    limit: usize,
    hasher: &AuditChainHasher<M>,
) -> Result<AuditListResult, AuditError> {
    let start_seq_i64 = i64::try_from(start_seq).map_err(AuditError::storage)?;
    let fetch_limit = i64::try_from(limit + 1).unwrap_or(i64::MAX);

    // 前驱行（窗口首条的前一条，用于 verify_window 增量接续校验）。
    let predecessor = if start_seq > 0 {
        fetch_predecessor(tx, tenant_uuid, start_seq_i64 - 1, tenant).await?
    } else {
        None
    };

    // 窗口：limit+1 行以检测 has_more。
    let window_rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} \
         FROM {TABLE} \
         WHERE tenant_id = $1::uuid AND seq >= $2 \
         ORDER BY seq ASC \
         LIMIT $3"
    ))
    .bind(tenant_uuid)
    .bind(start_seq_i64)
    .bind(fetch_limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(storage)?;

    let mut entries = Vec::with_capacity(window_rows.len().min(limit));
    for r in &window_rows {
        entries.push(hydrate_row(r, tenant)?);
    }

    let has_more = entries.len() > limit;
    if has_more {
        entries.truncate(limit);
    }

    // 增量完整性验证（窗口+1前驱，非全扫；篡改 fail-closed → Err，handler 映 500，不下发脏数据）。
    hasher.verify_window(predecessor.as_ref(), &entries)?;

    let next_cursor = if has_more {
        Some(encode_cursor(start_seq + limit as u64)?)
    } else {
        None
    };

    Ok(AuditListResult {
        entries,
        next_cursor,
        has_more,
    })
}

/// verify_tail 事务体：SET LOCAL → 末 limit 行 DESC → 升序 → 前驱 → verify_window。
async fn verify_tail_in_tx<M: MacVerifier>(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    tenant: TenantId,
    limit: u32,
    hasher: &AuditChainHasher<M>,
) -> Result<(), AuditError> {
    let limit_i64 = i64::from(limit);

    // 取末 `limit` 行（DESC），再升序排列。
    let mut window_rows = sqlx::query(&format!(
        "SELECT {SELECT_COLS} \
         FROM {TABLE} \
         WHERE tenant_id = $1::uuid \
         ORDER BY seq DESC \
         LIMIT $2"
    ))
    .bind(tenant_uuid)
    .bind(limit_i64)
    .fetch_all(&mut *tx)
    .await
    .map_err(storage)?;

    window_rows.reverse();

    let mut entries: Vec<AuditEntry> = Vec::with_capacity(window_rows.len());
    for r in &window_rows {
        entries.push(hydrate_row(r, tenant)?);
    }

    // 前驱：窗口首条 seq - 1（若窗口含 genesis 则 seq=0，无前驱）。
    let predecessor = match entries.first() {
        Some(first) if first.seq() > 0 => {
            let pred_seq = i64::try_from(first.seq() - 1).map_err(AuditError::storage)?;
            fetch_predecessor(tx, tenant_uuid, pred_seq, tenant).await?
        }
        _ => None,
    };

    hasher.verify_window(predecessor.as_ref(), &entries)
}

/// verify_tenant 事务体：从 genesis 起按 batch 分页扫完整条 tenant chain。
async fn verify_full_in_tx<M: MacVerifier>(
    tx: &mut PgConnection,
    tenant_uuid: &str,
    tenant: TenantId,
    batch: usize,
    hasher: &AuditChainHasher<M>,
) -> Result<AuditLedgerVerifyReport, AuditError> {
    if batch == 0 {
        return Err(AuditError::storage(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audit ledger verify batch must be greater than zero",
        )));
    }

    let mut start_seq = 0u64;
    let mut checked_entries = 0u64;
    loop {
        let result = list_in_tx(tx, tenant_uuid, tenant, start_seq, batch, hasher).await?;
        let window_len = u64::try_from(result.entries.len()).map_err(AuditError::storage)?;
        checked_entries = checked_entries
            .checked_add(window_len)
            .ok_or(AuditError::SequenceGap)?;
        if !result.has_more {
            break;
        }
        if window_len == 0 {
            return Err(AuditError::SequenceGap);
        }
        start_seq = start_seq
            .checked_add(window_len)
            .ok_or(AuditError::SequenceGap)?;
    }
    Ok(AuditLedgerVerifyReport {
        tenant,
        checked_entries,
    })
}

// ---------------------------------------------------------------------------
// AuditWriteRepo / AuditReadRepo impl
// ---------------------------------------------------------------------------

impl<M: MacVerifier + Send + Sync + 'static> AuditWriteRepo for PgAuditRepo<M> {
    /// **原子封链 append**：advisory-lock 串行化 → 读 tail → 链接 → INSERT（单事务原子）。
    async fn append(&self, scope: TenantRepoScope, record: AuditRecord) -> Result<(), AuditError> {
        let tenant = scope.tenant();
        if record.tenant != tenant {
            return Err(AuditError::storage(std::io::Error::other(
                "audit append tenant scope mismatch",
            )));
        }
        let tenant_uuid = tenant_str(record.tenant);
        let lock_key = advisory_lock_key(record.tenant);
        let record = Arc::new(record);
        run_pg_tx_retry(
            AUDIT_APPEND_BOUNDARY,
            |_attempt, deadline| {
                let tenant_uuid = tenant_uuid.clone();
                let record = Arc::clone(&record);
                let hasher = Arc::clone(&self.hasher);
                async move {
                    self.write_pool
                        .retry_write(
                            scope,
                            deadline,
                            move |tx| {
                                Box::pin(async move {
                                    append_in_tx(
                                        tx.conn(),
                                        &tenant_uuid,
                                        lock_key,
                                        &record,
                                        &hasher,
                                    )
                                    .await?;
                                    Ok(())
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_audit_error,
        )
        .await
    }
}

impl<M: MacVerifier + Send + Sync + 'static> AuditReadRepo for PgAuditRepo<M> {
    /// 按租户分页列出审计条目（读路径**增量验证**窗口+1前驱，篡改 fail-closed → `Err`）。
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant_str(tenant);
        let start_seq = match page.cursor.as_ref() {
            Some(c) => decode_cursor(c)?,
            None => 0u64,
        };
        let limit = usize::from(page.limit.get());
        let hasher = Arc::clone(&self.hasher);
        self.read_pool
            .read_map(
                scope,
                move |conn| {
                    Box::pin(async move {
                        list_in_tx(conn, &tenant_uuid, tenant, start_seq, limit, &hasher).await
                    })
                },
                storage,
            )
            .await
    }

    /// **尾部增量验证**（末 `limit` 条 + 前驱，非全扫整链；bootstrap 启动自检用）。
    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant_str(tenant);
        let hasher = Arc::clone(&self.hasher);
        self.read_pool
            .read_map(
                scope,
                move |conn| {
                    Box::pin(async move {
                        verify_tail_in_tx(conn, &tenant_uuid, tenant, limit, &hasher).await
                    })
                },
                storage,
            )
            .await
    }
}

impl<M: MacVerifier + Send + Sync + 'static> AuditAdminRepo for PgAuditAdminRepo<M> {
    /// 按目标租户分页列出审计条目；tenant scope 由专用 admin pool 上的 `SET LOCAL` 注入。
    async fn list_tenant(
        &self,
        scope: CrossTenantReadScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        let tenant = scope.target();
        let tenant_uuid = tenant_str(tenant);
        let start_seq = match page.cursor.as_ref() {
            Some(c) => decode_cursor(c)?,
            None => 0u64,
        };
        let limit = usize::from(page.limit.get());
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .read_map(
                infra_tenant_scope(tenant),
                move |conn| {
                    Box::pin(async move {
                        list_in_tx(conn, &tenant_uuid, tenant, start_seq, limit, &hasher).await
                    })
                },
                storage,
            )
            .await
    }

    /// 按目标租户验证完整审计链；tenant scope 由专用 admin pool 上的 `SET LOCAL` 注入。
    async fn verify_tenant(
        &self,
        tenant: TenantId,
        batch: vocab::Limit,
    ) -> Result<AuditLedgerVerifyReport, AuditError> {
        let tenant_uuid = tenant_str(tenant);
        let batch = usize::from(batch.get());
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .read_map(
                infra_tenant_scope(tenant),
                move |conn| {
                    Box::pin(async move {
                        verify_full_in_tx(conn, &tenant_uuid, tenant, batch, &hasher).await
                    })
                },
                storage,
            )
            .await
    }
}

// ---------------------------------------------------------------------------
// 测试辅助（#[cfg(test)]）
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    //! 本地测试 MacVerifier——keyed FNV-1a 折叠（32B，key+message 均敏感；非加密，
    //! 仅用于集成测试链完整性验证，与 audit::domain::test_support::TestKeyedHasher 同语义）。
    //! 无需 dev-dep crypto-adapter（deny.toml crypto-adapter wrappers 不含 postgres）。

    use primitives::{Mac, MacAlgorithm, MacKey, MacVerifier, constant_time_eq};

    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    /// keyed FNV-1a 折叠 verifier（4 lane → 32B）。
    pub(crate) struct TestVerifier;

    impl MacVerifier for TestVerifier {
        fn sign(&self, key: &MacKey, _algorithm: MacAlgorithm, message: &[u8]) -> Mac {
            let mut lanes = [
                FNV_OFFSET,
                FNV_OFFSET ^ 0x1111_1111_1111_1111,
                FNV_OFFSET ^ 0x2222_2222_2222_2222,
                FNV_OFFSET ^ 0x3333_3333_3333_3333,
            ];
            for (i, &b) in key.as_bytes().iter().chain(message).enumerate() {
                let lane = i % 4;
                lanes[lane] ^= u64::from(b);
                lanes[lane] = lanes[lane].wrapping_mul(FNV_PRIME);
            }
            let mut out = [0u8; 32];
            for (lane, chunk) in lanes.iter().zip(out.chunks_mut(8)) {
                chunk.copy_from_slice(&lane.to_be_bytes());
            }
            Mac::from_bytes(out.to_vec())
        }

        fn verify(&self, key: &MacKey, algorithm: MacAlgorithm, message: &[u8], tag: &Mac) -> bool {
            constant_time_eq(
                self.sign(key, algorithm, message).as_bytes(),
                tag.as_bytes(),
            )
        }
    }

    /// 构造带固定 key 的 hasher（key_byte 重复 32 次，满足 MinKeyLen=32B）。
    #[allow(clippy::expect_used, dead_code)]
    // reason: 集成测试 helper——32B key 满足 MIN_KEY_LEN 构造不失败；item-level carve-out。
    // dead_code: 仅 integration feature 下被 integration_tests 使用，非 integration 构建静默即可。
    pub(crate) fn test_hasher(key_byte: u8) -> audit::ports::AuditChainHasher<TestVerifier> {
        audit::ports::AuditChainHasher::new(
            TestVerifier,
            primitives::MacKey::from_bytes(vec![key_byte; 32]),
        )
        .expect("32B test key satisfies MIN_KEY_LEN")
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    // cursor round-trip
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 单元测试 happy-path——固定 seq 不失败；item-level carve-out。
    fn cursor_encode_decode_round_trips() {
        for seq in [0u64, 1, 42, u16::MAX as u64, u32::MAX as u64] {
            let cursor = encode_cursor(seq).expect("encode_cursor must succeed for valid seq");
            let decoded = decode_cursor(&cursor).expect("decode_cursor must round-trip");
            assert_eq!(decoded, seq, "seq={seq} round-trip failed");
        }
    }

    // invalid cursor → InvalidCursor
    #[test]
    fn decode_cursor_invalid_returns_invalid_cursor() {
        // base64url of "not-a-number"
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
        #[allow(clippy::unwrap_used)]
        // reason: unit test — valid base64url parse succeeds; unwrap is intentional in test.
        let cursor = vocab::Cursor::parse(&raw).unwrap();
        assert!(
            matches!(decode_cursor(&cursor), Err(AuditError::InvalidCursor)),
            "semantic invalid cursor must return InvalidCursor"
        );
    }

    // advisory_lock_key is deterministic and distinct across tenants
    #[test]
    #[allow(clippy::unwrap_used)]
    // reason: unit test, canonical UUID parse does not fail.
    fn advisory_lock_key_is_deterministic() {
        let tid = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let k1 = advisory_lock_key(tid);
        let k2 = advisory_lock_key(tid);
        assert_eq!(k1, k2, "同 TenantId 须产生相同 advisory lock key（确定性）");
        // collision-resistance smoke：不同 TenantId 须产生不同 key，防止两租户共用同一串行化锁。
        let tid2 = vocab::TenantId::parse("00000000-0000-4000-8000-000000000abc").unwrap();
        let k3 = advisory_lock_key(tid2);
        assert_ne!(
            k1, k3,
            "不同 TenantId 须产生不同 advisory lock key（防碰撞）"
        );
    }
}
