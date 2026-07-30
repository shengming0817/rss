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

use audit::ports::{
    AuditAdminRepo, AuditChainHasher, AuditError, AuditLedgerVerifyReport, AuditListResult,
    AuditPage, AuditReadRepo, AuditRecord, AuditWriteRepo, CrossTenantReadScope, TenantId,
    TenantRepoScope,
};
use base64::Engine as _;
use primitives::MacVerifier;

#[cfg(test)]
use crate::cotx::settings_audit::advisory_lock_key;
use crate::cotx::{
    AuditAdminReadLane, ServingReadLane, ServingWriteLane, TenantDb, infra_tenant_scope,
};
use crate::pool::{VerifiedPgAuditAdminStore, VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::tx_retry::{AUDIT_APPEND_BOUNDARY, classify_audit_error, run_pg_tx_retry};

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

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
    read_pool: TenantDb<ServingReadLane>,
    write_pool: TenantDb<ServingWriteLane>,
    hasher: Arc<AuditChainHasher<M>>,
}

/// audit 审计链的跨租户只读 admin adapter。
///
/// 使用专用 `rss_audit_admin` pool，但仍通过 [`TenantDb<AuditAdminReadLane>`] 注入 target tenant scope，
/// 复用 `audit_entries` 现有 FORCE RLS tenant policy；本类型不实现 append/write 能力。
pub struct PgAuditAdminRepo<M: primitives::MacVerifier> {
    pool: TenantDb<AuditAdminReadLane>,
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
            read_pool: TenantDb::<ServingReadLane>::new(reader),
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
            hasher: Arc::new(hasher),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(
        store: &crate::PgStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
            hasher: Arc::new(hasher),
        }
    }
}

impl<M: MacVerifier + Send + Sync> PgAuditAdminRepo<M> {
    /// 由专用已验证 audit-admin capability + `hasher` 构造（不暴露裸 pool）。
    pub(crate) fn new(store: &VerifiedPgAuditAdminStore, hasher: AuditChainHasher<M>) -> Self {
        Self {
            pool: TenantDb::<AuditAdminReadLane>::new_admin(store),
            hasher: Arc::new(hasher),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(
        store: &crate::PgStore,
        hasher: AuditChainHasher<M>,
    ) -> Self {
        Self {
            pool: TenantDb::<AuditAdminReadLane>::from_unverified_for_test(store),
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

// ---------------------------------------------------------------------------
// 游标 encode / decode（base64url, URL_SAFE_NO_PAD）
// ---------------------------------------------------------------------------

/// 解码游标回 u64 seq（fail-closed：非法 base64url / 非 UTF-8 / 非数字 → `InvalidCursor`）。
fn decode_cursor(cursor: &vocab::Cursor) -> Result<u64, AuditError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| AuditError::InvalidCursor)?;
    let s = std::str::from_utf8(&bytes).map_err(|_| AuditError::InvalidCursor)?;
    s.parse::<u64>().map_err(|_| AuditError::InvalidCursor)
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
        let record = Arc::new(record);
        run_pg_tx_retry(
            AUDIT_APPEND_BOUNDARY,
            |_attempt, deadline| {
                let record = Arc::clone(&record);
                let hasher = Arc::clone(&self.hasher);
                async move {
                    self.write_pool
                        .retry_audit_write(
                            scope,
                            deadline,
                            move |mut tx| {
                                Box::pin(async move {
                                    tx.append(&record, &hasher).await?;
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
        let start_seq = match page.cursor.as_ref() {
            Some(c) => decode_cursor(c)?,
            None => 0u64,
        };
        let limit = usize::from(page.limit.get());
        let hasher = Arc::clone(&self.hasher);
        self.read_pool
            .audit_read(
                scope,
                move |mut tx| Box::pin(async move { tx.list(start_seq, limit, &hasher).await }),
                storage,
            )
            .await
    }

    /// **尾部增量验证**（末 `limit` 条 + 前驱，非全扫整链；bootstrap 启动自检用）。
    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError> {
        let hasher = Arc::clone(&self.hasher);
        self.read_pool
            .audit_read(
                scope,
                move |mut tx| Box::pin(async move { tx.verify_tail(limit, &hasher).await }),
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
        let start_seq = match page.cursor.as_ref() {
            Some(c) => decode_cursor(c)?,
            None => 0u64,
        };
        let limit = usize::from(page.limit.get());
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .audit_admin_read(
                infra_tenant_scope(tenant),
                move |mut tx| Box::pin(async move { tx.list(start_seq, limit, &hasher).await }),
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
        let batch = usize::from(batch.get());
        let hasher = Arc::clone(&self.hasher);
        self.pool
            .audit_admin_read(
                infra_tenant_scope(tenant),
                move |mut tx| Box::pin(async move { tx.verify_full(batch, &hasher).await }),
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
