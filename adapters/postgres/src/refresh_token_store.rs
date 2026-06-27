//! `PgRefreshTokenStore` —— identity refresh token 持久化 adapter（impl `identity::ports::RefreshTokenStore`，#1325）。
//!
//! **哈希存储（不存明文）**：`token_hash` 列只持 SHA-256 摘要（`bytea`，32 字节）；secret 生成 / 摘要计算在
//! `secure::refresh`（base 层 crypto），编排在 `application::RefreshService`（adapter 只做透传落库）。
//!
//! **原子 CAS 轮换**（`rotate`）：单事务内 `UPDATE status='consumed' WHERE ... AND status='active'`（CAS）；
//! 0 行更新即 CAS miss（old 已非 Active）→ 返 `false`，不写 new；1 行即命中 → 在同一事务 INSERT new → 返 `true`。
//! 杜绝 TOCTOU 双换（两次并发 rotate 只有一个能成功 CAS）。
//!
//! **谱系级联撤销**（`revoke_lineage`）：`UPDATE status='revoked' WHERE lineage_id=$2`（幂等，0 行也 Ok）；
//! logout / reuse-detection 共用此路径（整条 rotation 链一次撤销）。
//!
//! **租户隔离**：写路径先 `set_local_tenant`（RLS SET LOCAL 锚点，tenancy.md §RLS 与 PG scope）；
//! 读路径显式 `WHERE tenant_id=$1::uuid`（与 `PgSessionLifecycle::find` / `PgRoleRepo::find` 一致，pre-GA 双重隔离）。
//!
//! **Clock 不注入**：issued_at / expires_at 来自 `RefreshTokenRecord`（由 `RefreshService` 的 Clock 派生），
//! adapter 只做透传落库（`to_timestamp(unix_secs(record.issued_at()))`）——与注释「不写 outbox、不需要 Clock」对齐。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + reuse-detection，概念谱系）
//! ref: adapters/postgres/src/role_repo.rs（pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）
//! ref: adapters/postgres/src/session_lifecycle.rs（epoch 列编解码 + rollback warn 范式）

use std::time::{Duration, SystemTime};

use identity::ports::{
    IdentityError, RefreshRotation, RefreshStatus, RefreshTokenHash, RefreshTokenId,
    RefreshTokenRecord, RefreshTokenStore, TenantId, kind_from_db, kind_to_db,
};
use sqlx::{PgPool, Row};

use crate::PgStore;
use crate::cotx::{set_local_tenant, tenant_scoped_read};
use crate::outbox::unix_secs;

/// refresh token 持久化 PostgreSQL adapter（impl [`RefreshTokenStore`]，#1325）。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，同 [`crate::PgRoleRepo`]）clone 构造。
/// **Clock 不注入**：issued_at/expires_at 来自 record，由 `RefreshService` 的 Clock 派生，adapter 只透传落库。
pub struct PgRefreshTokenStore {
    pool: PgPool,
}

impl PgRefreshTokenStore {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）。Clock 不注入（issued_at/expires_at 来自 record）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::refresh_token_store` 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// 持久化 epoch 秒（`extract(epoch ...)::bigint`）→ `SystemTime`（与写路径 `unix_secs` 编码对称；
/// 负值——早于 epoch，理论不可达——收口为 epoch 0，不 panic；同 `session_lifecycle::epoch_secs_to_time`）。
fn epoch_secs_to_time(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

/// refresh_tokens INSERT 写体（提取以控认知复杂度；供 [`RefreshTokenStore::insert`] 和
/// [`RefreshTokenStore::rotate`] CAS 成功路径共用；同 `session_lifecycle::write_session_and_outbox`）。
async fn do_insert(
    conn: &mut sqlx::PgConnection,
    record: &RefreshTokenRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
            (id, tenant_id, subject, kind, token_hash,
             parent_id, lineage_id, status, issued_at, expires_at)
        VALUES
            ($1::uuid, $2::uuid, $3, $4, $5,
             $6::uuid, $7::uuid, $8, to_timestamp($9), to_timestamp($10))
        "#,
    )
    .bind(record.id().as_str())
    .bind(record.tenant().as_uuid().to_string())
    .bind(record.subject())
    .bind(kind_to_db(record.kind()))
    .bind(record.token_hash().as_bytes() as &[u8])
    .bind(record.parent_id().map(|p| p.as_str()))
    .bind(record.lineage_id().as_str())
    .bind(record.status().as_db_str())
    .bind(unix_secs(record.issued_at()))
    .bind(unix_secs(record.expires_at()))
    .execute(conn)
    .await
    .map(|_| ())
}

/// CAS UPDATE（old active→consumed）+ 条件写 new，纯 sqlx 错误返回（调用方负责 tx rollback/commit）。
/// 抽取以控制 [`RefreshTokenStore::rotate`] 认知复杂度（≤ 15，CLAUDE.md §认知复杂度）。
///
/// 返回：`Ok(true)` = CAS 命中 + new 写入；`Ok(false)` = miss（old 非 Active），不写 new；
/// `Err(_)` = SQL 错误（调用方需 rollback）。
async fn do_rotate_tx(
    tenant_uuid: &str,
    tx: &mut sqlx::PgConnection,
    old_id: &RefreshTokenId,
    new: &RefreshTokenRecord,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE refresh_tokens SET status = $3 \
         WHERE tenant_id = $1::uuid AND id = $2::uuid AND status = $4",
    )
    .bind(tenant_uuid)
    .bind(old_id.as_str())
    .bind(RefreshStatus::Consumed.as_db_str())
    .bind(RefreshStatus::Active.as_db_str())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(false); // CAS miss：old 已非 Active，不写 new。
    }
    do_insert(tx, new).await?;
    Ok(true)
}

impl RefreshTokenStore for PgRefreshTokenStore {
    /// 持久化新签发记录（tenant-scoped 事务，SET LOCAL 锚点，`do_insert` 写体）。
    async fn insert(&self, record: RefreshTokenRecord) -> Result<(), IdentityError> {
        let tenant = record.tenant();
        let tenant_uuid = tenant.as_uuid().to_string();
        let mut tx = self.pool.begin().await.map_err(storage)?;
        set_local_tenant(&mut tx, tenant).await.map_err(storage)?;
        match do_insert(&mut tx, &record).await {
            Ok(()) => tx.commit().await.map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = tenant_uuid.as_str(),
                    operation = "refresh_token.insert",
                    error = %secure::redact_error(&e),
                    "refresh token insert: commit failed"
                );
                storage(e)
            }),
            Err(e) => {
                if let Err(rb) = tx.rollback().await {
                    tracing::warn!(
                        target: "postgres",
                        tenant_id = tenant_uuid.as_str(),
                        operation = "refresh_token.insert",
                        error = %secure::redact_error(&rb),
                        "refresh token insert: rollback failed after write error"
                    );
                }
                Err(storage(e))
            }
        }
    }

    /// 按 secret 摘要查找（`tenant_scoped_read` RLS-safe 读；跨租 → None；
    /// INVARIANT RLS-TENANT-SCOPE-READ-01：SET LOCAL rss.tenant_id 注入到同一事务后 RLS 策略生效，
    /// 与 `PgRoleRepo::find` 模式一致；hydrate 在事务外进行，不持有 conn）。
    async fn find_by_hash(
        &self,
        tenant: TenantId,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
        let tenant_uuid = tenant.as_uuid().to_string();
        let tenant_uuid_q = tenant_uuid.clone();
        let hash_bytes = *hash.as_bytes();

        let raw = tenant_scoped_read(&self.pool, tenant, move |conn| {
            Box::pin(async move {
                let row = sqlx::query(
                    r#"
                    SELECT id::text, subject, kind, parent_id::text, lineage_id::text, status,
                           extract(epoch from issued_at)::bigint AS issued_at,
                           extract(epoch from expires_at)::bigint AS expires_at
                    FROM refresh_tokens
                    WHERE tenant_id = $1::uuid AND token_hash = $2
                    "#,
                )
                .bind(&tenant_uuid_q)
                .bind(&hash_bytes as &[u8])
                .fetch_optional(&mut *conn)
                .await?;
                match row {
                    None => Ok(None),
                    Some(r) => {
                        let id: String = r.try_get("id")?;
                        let subject: String = r.try_get("subject")?;
                        let kind_str: String = r.try_get("kind")?;
                        let parent_id: Option<String> = r.try_get("parent_id")?;
                        let lineage_id: String = r.try_get("lineage_id")?;
                        let status_str: String = r.try_get("status")?;
                        let issued_secs: i64 = r.try_get("issued_at")?;
                        let expires_secs: i64 = r.try_get("expires_at")?;
                        Ok(Some((
                            id,
                            subject,
                            kind_str,
                            parent_id,
                            lineage_id,
                            status_str,
                            issued_secs,
                            expires_secs,
                        )))
                    }
                }
            })
        })
        .await
        .map_err(storage)?;

        match raw {
            None => Ok(None),
            Some((
                id,
                subject,
                kind_str,
                parent_id,
                lineage_id,
                status_str,
                issued_secs,
                expires_secs,
            )) => {
                let kind = kind_from_db(&kind_str).ok_or_else(|| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.kind",
                    ))
                })?;
                let status = RefreshStatus::from_db_str(&status_str).ok_or_else(|| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.status",
                    ))
                })?;
                Ok(Some(RefreshTokenRecord::hydrate(
                    id,
                    tenant,
                    subject,
                    kind,
                    hash_bytes,
                    parent_id,
                    lineage_id,
                    status,
                    epoch_secs_to_time(issued_secs),
                    epoch_secs_to_time(expires_secs),
                )))
            }
        }
    }

    /// **原子 CAS 轮换**：`do_rotate_tx`（CAS UPDATE + 条件 INSERT）→ `Ok(true)` 命中 / `Ok(false)` miss。
    /// CAS 逻辑已提取到 [`do_rotate_tx`]（认知复杂度分离，≤15；rotate 本身只做 tx 生命周期管理）。
    ///
    /// 入参 [`RefreshRotation`] 是 sealed command（`begin_rotation` 从源 record 派生）——tenant 从
    /// `rotation.new_record().tenant()` 取，无独立 `tenant` 入参错位风险（REFRESH-ROTATE-LINEAGE-01）。
    async fn rotate(&self, rotation: RefreshRotation) -> Result<bool, IdentityError> {
        let old_id = rotation.old_id();
        let new = rotation.new_record();
        let tenant = new.tenant();
        let tenant_uuid = tenant.as_uuid().to_string();
        let mut tx = self.pool.begin().await.map_err(storage)?;
        set_local_tenant(&mut tx, tenant).await.map_err(storage)?;
        match do_rotate_tx(&tenant_uuid, &mut tx, old_id, new).await {
            Err(e) => {
                if let Err(rb) = tx.rollback().await {
                    tracing::warn!(
                        target: "postgres",
                        tenant_id = tenant_uuid.as_str(),
                        operation = "refresh_token.rotate",
                        error = %secure::redact_error(&rb),
                        "refresh token rotate: rollback failed"
                    );
                }
                Err(storage(e))
            }
            Ok(hit) => {
                // CAS miss（hit=false）或命中（hit=true）：均 commit（合并两臂控复杂度 ≤15）。
                tx.commit().await.map_err(|e| {
                    tracing::warn!(
                        target: "postgres",
                        tenant_id = tenant_uuid.as_str(),
                        operation = "refresh_token.rotate",
                        error = %secure::redact_error(&e),
                        "refresh token rotate: commit failed"
                    );
                    storage(e)
                })?;
                Ok(hit)
            }
        }
    }

    /// **级联撤销整条谱系**（幂等；0 行也 Ok）：tenant-scoped 事务内批量 `UPDATE status='revoked'
    /// WHERE lineage_id=$2`（logout / reuse-detection 共用）。
    async fn revoke_lineage(
        &self,
        tenant: TenantId,
        lineage_id: RefreshTokenId,
    ) -> Result<(), IdentityError> {
        let tenant_uuid = tenant.as_uuid().to_string();
        let mut tx = self.pool.begin().await.map_err(storage)?;
        set_local_tenant(&mut tx, tenant).await.map_err(storage)?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET status = $3 \
             WHERE tenant_id = $1::uuid AND lineage_id = $2::uuid",
        )
        .bind(&tenant_uuid)
        .bind(lineage_id.as_str())
        .bind(RefreshStatus::Revoked.as_db_str())
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => tx.commit().await.map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = tenant_uuid.as_str(),
                    operation = "refresh_token.revoke_lineage",
                    error = %secure::redact_error(&e),
                    "refresh token revoke_lineage: commit failed"
                );
                storage(e)
            }),
            Err(e) => {
                if let Err(rb) = tx.rollback().await {
                    tracing::warn!(
                        target: "postgres",
                        tenant_id = tenant_uuid.as_str(),
                        operation = "refresh_token.revoke_lineage",
                        error = %secure::redact_error(&rb),
                        "refresh token revoke_lineage: rollback failed after update error"
                    );
                }
                Err(storage(e))
            }
        }
    }
}
