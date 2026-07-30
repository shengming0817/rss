//! `PgRefreshTokenStore` —— identity refresh token 持久化 adapter（impl `identity::ports::RefreshTokenStore`，#1325）。
//!
//! **哈希存储（不存明文）**：`token_hash` 列只持 SHA-256 摘要（`bytea`，32 字节）；secret 生成 / 摘要计算在
//! `secure::refresh`（base 层 crypto），编排在 `application::RefreshService`（adapter 只做透传落库）。
//!
//! 本类型是纯 reader。rotation、reuse containment 与 family revocation 只能进入
//! `PgIdentitySecurityLifecycle::execute_refresh` 的单一 producer transaction。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + reuse-detection，概念谱系）
//! ref: adapters/postgres/src/role_repo.rs（pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）
//! ref: adapters/postgres/src/auth_grant_lifecycle.rs（epoch 列编解码 + rollback warn 范式）

use std::time::{Duration, SystemTime};

use crate::cotx::{ServingReadLane, TenantDb};
use crate::pool::VerifiedPgReadStore;
use authn::{AuthGrantId, AuthGrantStatus, AuthnEpoch};
use identity::ports::{
    IdentityError, RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord,
    RefreshTokenSnapshot, RefreshTokenStore, TenantRepoScope,
};

/// refresh token 持久化 PostgreSQL adapter（impl [`RefreshTokenStore`]，#1325）。
///
/// 仅由已验证 reader capability 构造（同 [`crate::PgRoleRepo`]）。
pub struct PgRefreshTokenStore {
    read_pool: TenantDb<ServingReadLane>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RefreshTokenRow {
    pub(crate) id: String,
    pub(crate) auth_grant_id: String,
    pub(crate) user_id: String,
    pub(crate) auth_grant_status: String,
    pub(crate) parent_id: Option<String>,
    pub(crate) lineage_id: String,
    pub(crate) authn_epoch_at_issue: i64,
    pub(crate) status: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
}

impl PgRefreshTokenStore {
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::refresh_token_store` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::new(reader),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: TenantDb::<ServingReadLane>::from_unverified_for_test(store),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// 持久化 epoch 秒（`extract(epoch ...)::bigint`）→ `SystemTime`（与写路径 `unix_secs` 编码对称；
/// 负值——早于 epoch，理论不可达——收口为 epoch 0，不 panic）。
fn epoch_secs_to_time(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

impl RefreshTokenStore for PgRefreshTokenStore {
    /// 按 secret 摘要查找（`tenant_scoped_read` RLS-safe 读；跨租 → None；
    /// INVARIANT RLS-TENANT-SCOPE-READ-01：SET LOCAL rss.tenant_id 注入到同一事务后 RLS 策略生效，
    /// 与 `PgRoleRepo::find` 模式一致；hydrate 在事务外进行，不持有 conn）。
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
        let tenant = scope.tenant();
        let hash_bytes = *hash.as_bytes();

        let raw = self
            .read_pool
            .identity_read(scope, move |mut conn| {
                Box::pin(async move { conn.identity().refresh_token_by_hash(&hash).await })
            })
            .await
            .map_err(storage)?;

        match raw {
            None => Ok(None),
            Some(row) => {
                let user_id = ids::UserId::parse(&row.user_id).map_err(|_| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.user_id",
                    ))
                })?;
                let auth_grant_status = AuthGrantStatus::from_db_str(&row.auth_grant_status)
                    .ok_or_else(|| {
                        IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                            "corrupt refresh_tokens.auth_grant_status",
                        ))
                    })?;
                let status = RefreshStatus::from_db_str(&row.status).ok_or_else(|| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.status",
                    ))
                })?;
                let issuance_epoch = u64::try_from(row.authn_epoch_at_issue)
                    .map_err(|_| {
                        IdentityError::Storage(Box::new(std::io::Error::other(
                            "negative refresh issuance epoch",
                        )))
                    })
                    .and_then(|epoch| {
                        AuthnEpoch::hydrate(epoch)
                            .map_err(|error| IdentityError::Storage(Box::new(error)))
                    })?;
                let auth_grant_id = AuthGrantId::hydrate(row.auth_grant_id)
                    .map_err(|error| IdentityError::Storage(Box::new(error)))?;
                RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                    id: RefreshTokenId::hydrate(row.id),
                    tenant,
                    auth_grant_id,
                    user_id,
                    authn_epoch_at_issue: issuance_epoch,
                    auth_grant_status,
                    token_hash: RefreshTokenHash::hydrate(hash_bytes),
                    parent_id: row.parent_id.map(RefreshTokenId::hydrate),
                    lineage_id: RefreshTokenId::hydrate(row.lineage_id),
                    status,
                    issued_at: epoch_secs_to_time(row.issued_at),
                    expires_at: epoch_secs_to_time(row.expires_at),
                })
                .map(Some)
                .ok_or_else(|| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens time order",
                    ))
                })
            }
        }
    }
}
