//! `PgRefreshTokenStore` —— identity refresh token 持久化 adapter（impl `identity::ports::RefreshTokenStore`，#1325）。
//!
//! **哈希存储（不存明文）**：`token_hash` 列只持 SHA-256 摘要（`bytea`，32 字节）；secret 生成 / 摘要计算在
//! `secure::refresh`（base 层 crypto），编排在 `application::RefreshService`（adapter 只做透传落库）。
//!
//! **原子 CAS 轮换**（`rotate`）：单事务先锁定 account-security 与绑定的 AuthGrant，校验二者均
//! Active、未过期且 issuance epoch 一致，再执行 `UPDATE status='consumed' ...`（CAS）+ 条件 INSERT。
//! `Applied|Replay|AccountStale|Expired` 区分成功、refresh CAS miss、账号 fence 与最终 writer 过期 fence。
//!
//! **显式 refresh 撤销 primitive**（`revoke_lineage`）：`UPDATE status='revoked' WHERE lineage_id=$2`
//! （幂等，0 行也 Ok）。logout / reuse-detection 经 `PgAuthGrantLifecycle::close` 在同一事务关闭
//! AuthGrant root 与其 grant-bound family，不走此独立写。
//!
//! **租户隔离**：写路径先 `set_local_tenant`（RLS SET LOCAL 锚点，tenancy.md §RLS 与 PG scope）；
//! 读路径显式 `WHERE tenant_id=$1::uuid`（与 `PgAuthGrantLifecycle::find_active` /
//! `PgRoleRepo::find` 一致，pre-GA 双重隔离）。
//!
//! **最终时钟归 writer**：record 的 issued/expires 时间来自 `RefreshService` 注入的 Clock；轮换提交仍在
//! 持锁事务内以 PostgreSQL `clock_timestamp()` 复核 old refresh 与 AuthGrant 未过期，消除应用预检 TOCTOU。
//!
//! ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + reuse-detection，概念谱系）
//! ref: adapters/postgres/src/role_repo.rs（pool 注入 / SET LOCAL / storage 收口 / hydrate 范本）
//! ref: adapters/postgres/src/auth_grant_lifecycle.rs（epoch 列编解码 + rollback warn 范式）

use std::time::{Duration, SystemTime};

use authn::{AuthGrantId, AuthGrantStatus, AuthnEpoch};
use identity::ports::{
    IdentityError, RefreshRotationMutation, RefreshRotationOutcome, RefreshStatus,
    RefreshTokenHash, RefreshTokenId, RefreshTokenRecord, RefreshTokenSnapshot, RefreshTokenStore,
    TenantRepoScope,
};
use sqlx::Row;

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
use std::collections::HashMap;
#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
use std::sync::{Arc, Mutex};

use crate::cotx::{PgTenantReadPool, PgTenantWritePool};
use crate::outbox::unix_secs;
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::tx_retry::{classify_identity_error, run_pg_localtx_retry};

/// refresh token 持久化 PostgreSQL adapter（impl [`RefreshTokenStore`]，#1325）。
///
/// 仅由已验证 reader/writer capability 构造（同 [`crate::PgRoleRepo`]）。
/// record 时间来自 `RefreshService`；安全相关的最终过期判定由 writer 事务的数据库时钟完成。
pub struct PgRefreshTokenStore {
    read_pool: PgTenantReadPool,
    write_pool: PgTenantWritePool,
    #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
    rotation_faults: Arc<Mutex<RefreshRotationFaultState>>,
}

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
#[derive(Clone, Copy)]
pub(crate) enum RefreshRotationFault {
    #[cfg(all(test, feature = "integration"))]
    Permanent,
    #[cfg(all(test, feature = "integration"))]
    Transient,
    #[cfg(all(test, feature = "integration"))]
    TransientBeforeWrite,
    #[cfg(all(test, feature = "integration"))]
    Conflict,
    CommitUnknown,
    #[cfg(all(test, feature = "integration"))]
    RollbackFailed,
}

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
#[derive(Clone, Copy)]
struct RefreshRotationFaultPlan {
    fault: RefreshRotationFault,
    remaining: usize,
}

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
#[derive(Default)]
struct RefreshRotationFaultState {
    plans: HashMap<String, RefreshRotationFaultPlan>,
    #[cfg(all(test, feature = "integration"))]
    attempts: HashMap<String, usize>,
}

#[cfg(all(test, feature = "integration"))]
pub(crate) struct RefreshRotationAttemptProbe {
    state: Arc<Mutex<RefreshRotationFaultState>>,
}

#[cfg(all(test, feature = "integration"))]
impl RefreshRotationAttemptProbe {
    pub(crate) fn attempts(&self, old_id: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attempts
            .get(old_id)
            .copied()
            .unwrap_or_default()
    }
}

impl PgRefreshTokenStore {
    /// 由已验证 reader/writer capability 构造。最终过期判定使用 writer 事务的数据库时钟。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::refresh_token_store` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore, writer: &VerifiedPgWriteStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::new(reader),
            write_pool: PgTenantWritePool::new(writer),
            #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
            rotation_faults: Arc::new(Mutex::new(RefreshRotationFaultState::default())),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            read_pool: PgTenantReadPool::from_unverified_for_test(store),
            write_pool: PgTenantWritePool::from_unverified_for_test(store),
            rotation_faults: Arc::new(Mutex::new(RefreshRotationFaultState::default())),
        }
    }

    #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
    pub(crate) fn with_rotation_fault(
        self,
        old_id: &str,
        fault: RefreshRotationFault,
        remaining: usize,
    ) -> Self {
        assert!(remaining > 0, "fault plan must affect at least one attempt");
        self.rotation_faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .plans
            .insert(
                old_id.to_owned(),
                RefreshRotationFaultPlan { fault, remaining },
            );
        self
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn rotation_attempt_probe(&self) -> RefreshRotationAttemptProbe {
        RefreshRotationAttemptProbe {
            state: Arc::clone(&self.rotation_faults),
        }
    }
}

#[cfg(all(test, feature = "integration"))]
fn record_rotation_attempt(state: &Mutex<RefreshRotationFaultState>, old_id: &str) {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *state.attempts.entry(old_id.to_owned()).or_default() += 1;
}

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
fn take_rotation_fault_if(
    state: &Mutex<RefreshRotationFaultState>,
    old_id: &str,
    predicate: impl FnOnce(RefreshRotationFault) -> bool,
) -> Option<RefreshRotationFault> {
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let plan = state.plans.get_mut(old_id)?;
    let fault = plan.fault;
    if !predicate(fault) {
        return None;
    }
    plan.remaining -= 1;
    if plan.remaining == 0 {
        state.plans.remove(old_id);
    }
    Some(fault)
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

/// refresh_tokens INSERT 写体。初始记录只能由 AuthGrant login co-tx 写入；本函数仅供既有
/// refresh family 的 [`RefreshTokenStore::rotate`] CAS 成功路径使用。
async fn do_insert(
    conn: &mut sqlx::PgConnection,
    record: &RefreshTokenRecord,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens
            (id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue,
             auth_grant_status, token_hash, parent_id, lineage_id, status, issued_at, expires_at)
        VALUES
            ($1::uuid, $2::uuid, $3, $4::uuid, $5,
             $6, $7, $8::uuid, $9::uuid, $10, to_timestamp($11), to_timestamp($12))
        "#,
    )
    .bind(record.id().as_str())
    .bind(record.tenant().as_uuid().to_string())
    .bind(record.auth_grant_id().as_str())
    .bind(record.user_id().as_uuid().to_string())
    .bind(i64::try_from(record.issuance_epoch().get()).map_err(|_| {
        sqlx::Error::Protocol("refresh issuance epoch exceeds PostgreSQL bigint".to_owned())
    })?)
    .bind(record.auth_grant_status().as_db_str())
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

/// 锁内复核 old/root 过期 + CAS UPDATE（old active→consumed）+ 条件写 new，纯 sqlx 错误返回
/// （调用方负责 tx rollback/commit）。
/// 抽取以控制 [`RefreshTokenStore::rotate`] 认知复杂度（≤ 15，CLAUDE.md §认知复杂度）。
///
/// 返回 [`RefreshRotationOutcome::Applied`] = CAS 命中 + new 写入；
/// [`RefreshRotationOutcome::Replay`] = old 非 Active；
/// [`RefreshRotationOutcome::AccountStale`] = 最终锁内账号非 Active 或签发 epoch 已过期；
/// [`RefreshRotationOutcome::Expired`] = 最终锁内 old refresh/AuthGrant 已过期或根不能覆盖 family 绝对期限；
/// fence 结果均不写 new，`Err(_)` = SQL 错误（调用方需 rollback）。
async fn do_rotate_tx(
    tenant_uuid: &str,
    tx: &mut sqlx::PgConnection,
    old_id: &RefreshTokenId,
    new: &RefreshTokenRecord,
) -> Result<RefreshRotationOutcome, sqlx::Error> {
    let expected_epoch = i64::try_from(new.issuance_epoch().get()).map_err(|_| {
        sqlx::Error::Protocol("refresh issuance epoch exceeds PostgreSQL bigint".to_owned())
    })?;
    // Every authentication writer takes account -> refresh -> grant. The account row is both the
    // revocation fence and the first canonical lock, so a credential-security event cannot invert
    // this rotation path while it closes every grant belonging to the same subject.
    let account = sqlx::query(
        "SELECT status, authn_epoch FROM account_security_states \
         WHERE tenant_id = $1::uuid AND user_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant_uuid)
    .bind(new.user_id().as_uuid().to_string())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(account) = account else {
        return Ok(RefreshRotationOutcome::AccountStale);
    };
    let status: String = account.try_get("status")?;
    let current_epoch: i64 = account.try_get("authn_epoch")?;
    if status != "active" || current_epoch != expected_epoch {
        return Ok(RefreshRotationOutcome::AccountStale);
    }

    // The database clock is intentionally read inside this final writer transaction: the
    // application-layer expiry check is only an early rejection and cannot authorize a later
    // commit.
    let old = sqlx::query(
        r#"
        SELECT status,
               auth_grant_status,
               expires_at > clock_timestamp() AS unexpired
        FROM refresh_tokens
        WHERE tenant_id = $1::uuid
          AND id = $2::uuid
          AND authn_epoch_at_issue = $3
          AND auth_grant_id = $4
          AND user_id = $5::uuid
        FOR UPDATE
        "#,
    )
    .bind(tenant_uuid)
    .bind(old_id.as_str())
    .bind(expected_epoch)
    .bind(new.auth_grant_id().as_str())
    .bind(new.user_id().as_uuid().to_string())
    .fetch_optional(&mut *tx)
    .await?;
    let Some(old) = old else {
        return Ok(RefreshRotationOutcome::Replay);
    };
    let old_grant_status: String = old.try_get("auth_grant_status")?;
    if old_grant_status != AuthGrantStatus::Active.as_db_str() {
        return Ok(RefreshRotationOutcome::AccountStale);
    }
    let old_status: String = old.try_get("status")?;
    if old_status != RefreshStatus::Active.as_db_str() {
        return Ok(RefreshRotationOutcome::Replay);
    }
    let old_unexpired: bool = old.try_get("unexpired")?;
    if !old_unexpired {
        return Ok(RefreshRotationOutcome::Expired);
    }

    let grant = sqlx::query(
        r#"
        SELECT status,
               expires_at > clock_timestamp() AS unexpired,
               expires_at >= to_timestamp($5) AS covers_family
        FROM auth_grants
        WHERE tenant_id = $1::uuid
          AND grant_id = $2
          AND user_id = $3::uuid
          AND authn_epoch_at_issue = $4
        FOR UPDATE
        "#,
    )
    .bind(tenant_uuid)
    .bind(new.auth_grant_id().as_str())
    .bind(new.user_id().as_uuid().to_string())
    .bind(expected_epoch)
    .bind(unix_secs(new.expires_at()))
    .fetch_optional(&mut *tx)
    .await?;
    let Some(grant) = grant else {
        return Ok(RefreshRotationOutcome::AccountStale);
    };
    let grant_status: String = grant.try_get("status")?;
    if grant_status != AuthGrantStatus::Active.as_db_str()
        || new.auth_grant_status() != AuthGrantStatus::Active
    {
        return Ok(RefreshRotationOutcome::AccountStale);
    }
    let grant_unexpired: bool = grant.try_get("unexpired")?;
    let grant_covers_family: bool = grant.try_get("covers_family")?;
    if !grant_unexpired || !grant_covers_family {
        return Ok(RefreshRotationOutcome::Expired);
    }

    let res = sqlx::query(
        "UPDATE refresh_tokens SET status = $3 \
         WHERE tenant_id = $1::uuid AND id = $2::uuid AND status = $4 \
           AND authn_epoch_at_issue = $5 \
           AND auth_grant_id = $6 \
           AND user_id = $7::uuid \
           AND auth_grant_status = 'active' \
           AND expires_at > clock_timestamp()",
    )
    .bind(tenant_uuid)
    .bind(old_id.as_str())
    .bind(RefreshStatus::Consumed.as_db_str())
    .bind(RefreshStatus::Active.as_db_str())
    .bind(expected_epoch)
    .bind(new.auth_grant_id().as_str())
    .bind(new.user_id().as_uuid().to_string())
    .execute(&mut *tx)
    .await?;
    if res.rows_affected() == 0 {
        return Ok(RefreshRotationOutcome::Expired);
    }
    do_insert(tx, new).await?;
    Ok(RefreshRotationOutcome::Applied)
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
        let tenant_uuid = tenant.as_uuid().to_string();
        let tenant_uuid_q = tenant_uuid.clone();
        let hash_bytes = *hash.as_bytes();

        let raw = self
            .read_pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"
                    SELECT id::text, auth_grant_id, user_id::text, authn_epoch_at_issue,
                           auth_grant_status, parent_id::text, lineage_id::text, status,
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
                            let auth_grant_id: String = r.try_get("auth_grant_id")?;
                            let user_id: String = r.try_get("user_id")?;
                            let auth_grant_status: String = r.try_get("auth_grant_status")?;
                            let parent_id: Option<String> = r.try_get("parent_id")?;
                            let lineage_id: String = r.try_get("lineage_id")?;
                            let issuance_epoch: i64 = r.try_get("authn_epoch_at_issue")?;
                            let status_str: String = r.try_get("status")?;
                            let issued_secs: i64 = r.try_get("issued_at")?;
                            let expires_secs: i64 = r.try_get("expires_at")?;
                            Ok(Some((
                                id,
                                auth_grant_id,
                                user_id,
                                auth_grant_status,
                                parent_id,
                                lineage_id,
                                issuance_epoch,
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
                auth_grant_id,
                user_id,
                auth_grant_status,
                parent_id,
                lineage_id,
                issuance_epoch,
                status_str,
                issued_secs,
                expires_secs,
            )) => {
                let user_id = ids::UserId::parse(&user_id).map_err(|_| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.user_id",
                    ))
                })?;
                let auth_grant_status = AuthGrantStatus::from_db_str(&auth_grant_status)
                    .ok_or_else(|| {
                        IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                            "corrupt refresh_tokens.auth_grant_status",
                        ))
                    })?;
                let status = RefreshStatus::from_db_str(&status_str).ok_or_else(|| {
                    IdentityError::Storage(Box::<dyn std::error::Error + Send + Sync>::from(
                        "corrupt refresh_tokens.status",
                    ))
                })?;
                let issuance_epoch = u64::try_from(issuance_epoch)
                    .map_err(|_| {
                        IdentityError::Storage(Box::new(std::io::Error::other(
                            "negative refresh issuance epoch",
                        )))
                    })
                    .and_then(|epoch| {
                        AuthnEpoch::hydrate(epoch)
                            .map_err(|error| IdentityError::Storage(Box::new(error)))
                    })?;
                let auth_grant_id = AuthGrantId::hydrate(auth_grant_id)
                    .map_err(|error| IdentityError::Storage(Box::new(error)))?;
                RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                    id: RefreshTokenId::hydrate(id),
                    tenant,
                    auth_grant_id,
                    user_id,
                    authn_epoch_at_issue: issuance_epoch,
                    auth_grant_status,
                    token_hash: RefreshTokenHash::hydrate(hash_bytes),
                    parent_id: parent_id.map(RefreshTokenId::hydrate),
                    lineage_id: RefreshTokenId::hydrate(lineage_id),
                    status,
                    issued_at: epoch_secs_to_time(issued_secs),
                    expires_at: epoch_secs_to_time(expires_secs),
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

    /// **原子 CAS 轮换**：`do_rotate_tx` 在同一 writer 事务锁定账号安全态、校验 Active + 签发
    /// epoch，再执行 refresh CAS + 条件 INSERT，返回 typed [`RefreshRotationOutcome`]。
    /// CAS 逻辑已提取到 [`do_rotate_tx`]（认知复杂度分离，≤15；rotate 本身只做 tx 生命周期管理）。
    ///
    /// 入参 [`RefreshRotation`] 是 sealed command（`begin_rotation` 从源 record 派生）——tenant 从
    /// `rotation.new_record().tenant()` 取，无独立 `tenant` 入参错位风险（REFRESH-ROTATE-LINEAGE-01）。
    async fn rotate(
        &self,
        scope: TenantRepoScope,
        mutation: RefreshRotationMutation,
    ) -> Result<RefreshRotationOutcome, IdentityError> {
        let (rotation, observation) = mutation.into_parts();
        let old_id = rotation.old_id().clone();
        let new = rotation.new_record().clone();
        let tenant = scope.tenant();
        if new.tenant() != tenant {
            return Err(IdentityError::Storage(Box::new(std::io::Error::other(
                "refresh rotate tenant scope mismatch",
            ))));
        }
        let tenant_uuid = tenant.as_uuid().to_string();
        #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
        let old_id_key = old_id.as_str().to_owned();
        #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
        let rotation_faults = Arc::clone(&self.rotation_faults);
        run_pg_localtx_retry(
            observation,
            |_attempt, deadline| {
                let tenant_uuid = tenant_uuid.clone();
                let old_id = old_id.clone();
                #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
                let old_id_key = old_id_key.clone();
                let new = new.clone();
                #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
                let rotation_faults = Arc::clone(&rotation_faults);
                #[cfg(all(test, feature = "integration"))]
                record_rotation_attempt(&rotation_faults, &old_id_key);
                async move {
                    self.write_pool
                        .retry_write(
                            scope,
                            deadline,
                            move |tx| {
                                Box::pin(async move {
                                    #[cfg(all(test, feature = "integration"))]
                                    if take_rotation_fault_if(
                                        &rotation_faults,
                                        &old_id_key,
                                        |fault| {
                                            matches!(
                                                fault,
                                                RefreshRotationFault::TransientBeforeWrite
                                            )
                                        },
                                    )
                                    .is_some()
                                    {
                                        return Err(storage(sqlx::Error::PoolTimedOut));
                                    }
                                    let applied =
                                        do_rotate_tx(&tenant_uuid, tx.conn(), &old_id, &new)
                                            .await
                                            .map_err(storage)?;
                                    #[cfg(any(
                                        all(test, feature = "integration"),
                                        feature = "journey-fault-support"
                                    ))]
                                    if let Some(fault) = take_rotation_fault_if(
                                        &rotation_faults,
                                        &old_id_key,
                                        |fault| {
                                            #[cfg(all(test, feature = "integration"))]
                                            {
                                                !matches!(
                                                    fault,
                                                    RefreshRotationFault::TransientBeforeWrite
                                                )
                                            }
                                            #[cfg(not(all(test, feature = "integration")))]
                                            {
                                                let _ = fault;
                                                true
                                            }
                                        },
                                    ) {
                                        match fault {
                                            #[cfg(all(test, feature = "integration"))]
                                            RefreshRotationFault::Permanent => {
                                                return Err(IdentityError::Storage(Box::new(
                                                    std::io::Error::other(
                                                        "injected refresh rotation failure",
                                                    ),
                                                )));
                                            }
                                            #[cfg(all(test, feature = "integration"))]
                                            RefreshRotationFault::Transient => {
                                                return Err(storage(sqlx::Error::PoolTimedOut));
                                            }
                                            #[cfg(all(test, feature = "integration"))]
                                            RefreshRotationFault::TransientBeforeWrite => {
                                                unreachable!(
                                                    "before-write fault is consumed before SQL"
                                                )
                                            }
                                            #[cfg(all(test, feature = "integration"))]
                                            RefreshRotationFault::Conflict => {
                                                return Err(IdentityError::VersionConflict);
                                            }
                                            RefreshRotationFault::CommitUnknown => {
                                                tx.inject_commit_unknown_after_commit()
                                                    .await
                                                    .map_err(storage)?;
                                            }
                                            #[cfg(all(test, feature = "integration"))]
                                            RefreshRotationFault::RollbackFailed => {
                                                tx.inject_rollback_failed_after_rollback()
                                                    .await
                                                    .map_err(storage)?;
                                                return Err(storage(sqlx::Error::PoolTimedOut));
                                            }
                                        }
                                    }
                                    Ok(applied)
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_identity_error,
        )
        .await
    }

    /// **显式 refresh 撤销 primitive**（幂等；0 行也 Ok）：tenant-scoped 事务内批量
    /// `UPDATE status='revoked' WHERE lineage_id=$2`。logout / reuse-detection 由
    /// `PgAuthGrantLifecycle::close` 原子关闭 root/family，不走此独立写。
    async fn revoke_lineage(
        &self,
        scope: TenantRepoScope,
        lineage_id: RefreshTokenId,
    ) -> Result<(), IdentityError> {
        let tenant = scope.tenant();
        let tenant_uuid = tenant.as_uuid().to_string();
        self.write_pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE refresh_tokens SET status = $3 \
                             WHERE tenant_id = $1::uuid AND lineage_id = $2::uuid",
                        )
                        .bind(&tenant_uuid)
                        .bind(lineage_id.as_str())
                        .bind(RefreshStatus::Revoked.as_db_str())
                        .execute(conn.conn())
                        .await
                        .map_err(storage)
                        .map(|_| ())
                    })
                },
                storage,
            )
            .await
    }
}
