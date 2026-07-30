//! settings secret 引用坐标 PostgreSQL adapter（#1274）。
//!
//! [`PgSecretRepo`] impl `settings::ports::SecretRepo`，只承载 find / find_version /
//! latest_version；[`PgSecretUnitOfWork`] impl `settings::ports::SecretUnitOfWork`，独占 publish /
//! internal publish / republish / delete 写能力。
//! adapter→域 DIP 内向边（postgres 依赖 settings、native AFIT impl 其域形 port，经 deny.toml settings wrapper +
//! `allows(Adapter,Domain)` 放行；adapter 不被域依赖）。
//!
//! !! **本 adapter 只持久化引用坐标，绝无任何 secret 材料字段** !!（store_id / ref_key / ref_version）。
//! 读取真实材料须经 `diport::SecretResolver::resolve` 在调用栈内获取，不经本 adapter。
//!
//! 版本历史模型 + CAS（同 config_repo.rs etcd 版本模型）：每 (tenant, key) 全版本行；`find` = max(version) 非
//! tombstone；`find_version` = 精确版本非 tombstone；三个 publish command 均以
//! `INSERT ... WHERE $v = 1 + COALESCE(max,0)` 落库（0 行 → VersionConflict；PK unique violation(23505) →
//! VersionConflict）。
//!
//! `delete` = tombstone 软删：max+1 追加 deleted=true 占位行（幂等；latest 已 tombstone/key 不存在 → no-op）；
//! 占位坐标列 store_id='', ref_key='', ref_version=NULL——不携带有效坐标，version 单调不重置。
//!
//! storage 错误经 `SecretRepoError::Storage(Box::new(sqlx_err))` 分层冒泡（保留 source；域 crate 不依赖 sqlx）。
//! 读路径经 [`tenant_scoped_read`]（cotx）注入 SET LOCAL，对齐 RLS policy current_setting（#1298）；
//! 写路径另经 `set_local_tenant` 事务内 SET LOCAL 锚点。
//!
//! ref: adapters/postgres/src/config_repo.rs（版本历史 + CAS + tombstone + tenant_scoped 范式）

use settings::ports::{
    SecretEntry, SecretInternalPublishCommand, SecretKey, SecretPublishCommand, SecretRepo,
    SecretRepoError, SecretRepublishCommand, SecretUnitOfWork, StoreId, TenantId, TenantRepoScope,
};
#[cfg(all(test, feature = "integration"))]
use std::collections::HashMap;
#[cfg(all(test, feature = "integration"))]
use std::sync::{Arc, LazyLock, Mutex};

use crate::cotx::identity::SecretTx;
use crate::cotx::{ServingReadLane, ServingWriteLane, TenantDb};
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};
use crate::tx_retry::{
    SETTINGS_SECRET_BOUNDARY, classify_secret_repo_error, run_pg_localtx_retry, run_pg_tx_retry,
};

/// settings secret 引用坐标仓储 PostgreSQL adapter。
///
/// !! **只存引用坐标，绝无 secret 材料** !!
///
/// 仅由已验证 reader capability 构造；本类型不暴露写能力。
pub struct PgSecretRepo {
    pool: TenantDb<ServingReadLane>,
}

impl PgSecretRepo {
    /// 由已验证 reader capability 构造。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Settings>::secret_repo` 收口。
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            pool: TenantDb::<ServingReadLane>::new(reader),
        }
    }
}

#[cfg(all(test, feature = "integration"))]
impl crate::PgStore {
    pub(crate) fn secret_repo(&self) -> PgSecretRepo {
        PgSecretRepo {
            pool: TenantDb::<ServingReadLane>::from_unverified_for_test(self),
        }
    }
}

/// settings secret 引用坐标写 Unit of Work。
///
/// HTTP publish 必须携带 settings 域铸造的 typed LocalTx observation；内部 publish / republish
/// 使用 generic repository retry，不冒充 HTTP contract。三个 active-row 写入口共享同一个私有 CAS body。
pub struct PgSecretUnitOfWork {
    pool: TenantDb<ServingWriteLane>,
}

impl PgSecretUnitOfWork {
    /// 由已验证 writer capability 构造。
    ///
    /// `pub(crate)`：仅经 [`crate::PgDomainDeps`]`<caps::Settings>::settings_bundle` 收口。
    pub(crate) fn new(writer: &VerifiedPgWriteStore) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::new(writer),
        }
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }

    fn validate_entry_scope(
        scope: TenantRepoScope,
        entry: &SecretEntry,
    ) -> Result<(), SecretRepoError> {
        if entry.tenant() == scope.tenant() {
            Ok(())
        } else {
            Err(SecretRepoError::Storage(Box::new(std::io::Error::other(
                "secret publish tenant scope mismatch",
            ))))
        }
    }

    /// Execute the canonical transaction-bound secret CAS body.
    ///
    /// Retry policy, runner selection and `retry_write` stay co-located at the three typed public
    /// operation entries. This method owns the only active-row mutation body so their lock and CAS
    /// behavior cannot drift.
    async fn cas_insert_locked(
        tx: &mut SecretTx<'_, '_, ServingWriteLane>,
        entry: SecretEntry,
    ) -> Result<(), SecretRepoError> {
        let key = entry.key().clone();
        #[cfg(all(test, feature = "integration"))]
        note_secret_save_attempt(key.as_str());
        tx.secrets()
            .lock_key(&key)
            .await?
            .cas_insert(&entry)
            .await?;
        #[cfg(all(test, feature = "integration"))]
        if let Some(fault) = take_post_insert_fault(key.as_str()) {
            match fault {
                PostInsertFault::CommitUnknown => {
                    tx.inject_commit_unknown_after_commit()
                        .await
                        .map_err(storage)?;
                }
                fault => return Err(post_insert_fault_error(fault)),
            }
        }
        Ok(())
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx）。
fn storage(e: sqlx::Error) -> SecretRepoError {
    SecretRepoError::Storage(Box::new(e))
}

/// u64 版本号 → wire i64（绑 `bigint` 列）。
///
/// reason: 版本号从 1 单调递增，实践中远不及 `i64::MAX`；溢出收口 `i64::MAX` 而非 panic——CAS WHERE 永不
/// 成立 → `VersionConflict`、`find_version` 不匹配任何行 → `None`，均 fail-closed（同 config_repo）。
/// Decode an optional database version without turning corrupt negative values into "not found".
fn decode_optional_version(value: Option<i64>) -> Result<Option<u64>, SecretRepoError> {
    value
        .map(|version| {
            u64::try_from(version).map_err(|error| SecretRepoError::Storage(Box::new(error)))
        })
        .transpose()
}

/// DB row → [`SecretEntry`]（受控 hydrate）。
///
/// - `secret_key` 经 `SecretKey::parse` 复核（持久化时已校验，失败属数据完整性问题 → `Storage`）。
/// - `store_id` 经 `StoreId::parse` 复核（同上）。
/// - `version` i64 → u64（负值不可能：CAS 从 1 单调递增）。
/// - `ref_version` Option<String>（NULL → None）。
#[derive(sqlx::FromRow)]
pub(crate) struct SecretRow {
    pub(crate) secret_key: String,
    pub(crate) store_id: String,
    pub(crate) ref_key: String,
    pub(crate) ref_version: Option<String>,
    pub(crate) version: i64,
    pub(crate) deleted: bool,
}

fn hydrate_row(tenant: TenantId, row: &SecretRow) -> Result<SecretEntry, SecretRepoError> {
    let key =
        SecretKey::parse(&row.secret_key).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;
    let store_id =
        StoreId::parse(&row.store_id).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;
    let version = u64::try_from(row.version).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;

    Ok(SecretEntry::hydrate(
        key,
        store_id,
        row.ref_key.clone(),
        row.ref_version.clone(),
        tenant,
        version,
    ))
}

/// row（含 `deleted` 列）→ 活跃 `SecretEntry`：tombstone（`deleted=true`）⇒ 视为已删 `None`；否则 hydrate。
fn hydrate_active(
    tenant: TenantId,
    row: Option<SecretRow>,
) -> Result<Option<SecretEntry>, SecretRepoError> {
    match row {
        None => Ok(None),
        Some(r) => {
            if r.deleted {
                Ok(None)
            } else {
                Ok(Some(hydrate_row(tenant, &r)?))
            }
        }
    }
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
enum PostInsertFault {
    Permanent,
    Transient,
    CommitUnknown,
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy)]
struct PostInsertFaultPlan {
    fault: PostInsertFault,
    remaining: usize,
}

#[cfg(all(test, feature = "integration"))]
static POST_INSERT_FAULTS: LazyLock<Mutex<HashMap<String, PostInsertFaultPlan>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(all(test, feature = "integration"))]
static SAVE_ATTEMPTS: LazyLock<Mutex<HashMap<String, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(all(test, feature = "integration"))]
static KEY_LOCK_RENDEZVOUS: LazyLock<Mutex<HashMap<String, Arc<tokio::sync::Barrier>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Inject one permanent failure after the active row INSERT and before settlement.
#[cfg(all(test, feature = "integration"))]
pub(crate) fn fail_secret_save_after_insert_once(key: &SecretKey) {
    install_post_insert_fault(key, PostInsertFault::Permanent, 1);
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn fail_secret_save_transient_after_insert(key: &SecretKey, attempts: usize) {
    install_post_insert_fault(key, PostInsertFault::Transient, attempts);
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn fail_secret_save_commit_unknown_after_insert_once(key: &SecretKey) {
    install_post_insert_fault(key, PostInsertFault::CommitUnknown, 1);
}

#[cfg(all(test, feature = "integration"))]
fn install_post_insert_fault(key: &SecretKey, fault: PostInsertFault, remaining: usize) {
    assert!(remaining > 0, "fault plan must affect at least one attempt");
    POST_INSERT_FAULTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            key.as_str().to_owned(),
            PostInsertFaultPlan { fault, remaining },
        );
}

#[cfg(all(test, feature = "integration"))]
fn take_post_insert_fault(key: &str) -> Option<PostInsertFault> {
    let mut plans = POST_INSERT_FAULTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let plan = plans.get_mut(key)?;
    let fault = plan.fault;
    plan.remaining -= 1;
    if plan.remaining == 0 {
        plans.remove(key);
    }
    Some(fault)
}

#[cfg(all(test, feature = "integration"))]
fn post_insert_fault_error(fault: PostInsertFault) -> SecretRepoError {
    match fault {
        PostInsertFault::Permanent => SecretRepoError::Storage(Box::new(std::io::Error::other(
            "injected secret save post-insert failure",
        ))),
        PostInsertFault::Transient => SecretRepoError::Storage(Box::new(sqlx::Error::PoolTimedOut)),
        PostInsertFault::CommitUnknown => unreachable!("commit fault is handled by settlement"),
    }
}

#[cfg(all(test, feature = "integration"))]
fn note_secret_save_attempt(key: &str) {
    let mut attempts = SAVE_ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *attempts.entry(key.to_owned()).or_default() += 1;
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn secret_save_attempts(key: &SecretKey) -> usize {
    SAVE_ATTEMPTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key.as_str())
        .copied()
        .unwrap_or_default()
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn rendezvous_secret_key_lock_attempts(key: &SecretKey, parties: usize) {
    assert!(parties > 1, "lock rendezvous needs concurrent parties");
    KEY_LOCK_RENDEZVOUS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            key.as_str().to_owned(),
            Arc::new(tokio::sync::Barrier::new(parties)),
        );
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn wait_at_secret_key_lock_rendezvous(key: &str) {
    let barrier = KEY_LOCK_RENDEZVOUS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key)
        .cloned();
    let Some(barrier) = barrier else {
        return;
    };
    let leader = barrier.wait().await.is_leader();
    if leader {
        let mut barriers = KEY_LOCK_RENDEZVOUS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if barriers
            .get(key)
            .is_some_and(|installed| Arc::ptr_eq(installed, &barrier))
        {
            barriers.remove(key);
        }
    }
}

impl SecretRepo for PgSecretRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 活跃值 = 最高版本行且非 tombstone（latest 为 tombstone ⇒ 已删 None）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned，不借连接）；hydrate_active 在 tx 外执行。
        let query_key = key.clone();

        let row = self
            .pool
            .secret_read(scope, move |mut conn| {
                Box::pin(async move { conn.secrets().find(&query_key).await })
            })
            .await
            .map_err(storage)?;
        hydrate_active(tenant, row)
    }

    async fn find_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned）；hydrate_active 在 tx 外执行。
        let query_key = key.clone();

        let row = self
            .pool
            .secret_read(scope, move |mut conn| {
                Box::pin(async move { conn.secrets().find_version(&query_key, version).await })
            })
            .await
            .map_err(storage)?;
        hydrate_active(tenant, row)
    }

    async fn latest_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 真实最高版本（含 tombstone）；max() 对空集返 NULL（fetch_one 恒一行）。
        // rss_app 角色下 RLS 过滤后 max() 仅对当前 tenant 行计算（否则无 SET LOCAL 时 rss_app 下所有行不可见
        // → max() 返 NULL，后续版本序列断裂）——此为 tenant_scoped_read 覆盖 latest_version 的关键理由。
        let query_key = key.clone();

        let mv: Option<i64> = self
            .pool
            .secret_read(scope, move |mut conn| {
                Box::pin(async move { conn.secrets().latest_version(&query_key).await })
            })
            .await
            .map_err(storage)?;
        decode_optional_version(mv)
    }
}

impl SecretUnitOfWork for PgSecretUnitOfWork {
    async fn publish(
        &self,
        scope: TenantRepoScope,
        command: SecretPublishCommand,
    ) -> Result<(), SecretRepoError> {
        let (entry, observation) = command.into_parts();
        Self::validate_entry_scope(scope, &entry)?;
        run_pg_localtx_retry(
            observation,
            |_attempt, deadline| {
                let entry = entry.clone();
                async move {
                    self.pool
                        .retry_secret_write(
                            scope,
                            deadline,
                            move |mut tx| {
                                Box::pin(
                                    async move { Self::cas_insert_locked(&mut tx, entry).await },
                                )
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_secret_repo_error,
        )
        .await
    }

    async fn publish_internal(
        &self,
        scope: TenantRepoScope,
        command: SecretInternalPublishCommand,
    ) -> Result<(), SecretRepoError> {
        let entry = command.into_entry();
        Self::validate_entry_scope(scope, &entry)?;
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| {
                let entry = entry.clone();
                async move {
                    self.pool
                        .retry_secret_write(
                            scope,
                            deadline,
                            move |mut tx| {
                                Box::pin(
                                    async move { Self::cas_insert_locked(&mut tx, entry).await },
                                )
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_secret_repo_error,
        )
        .await
    }

    async fn republish(
        &self,
        scope: TenantRepoScope,
        command: SecretRepublishCommand,
    ) -> Result<(), SecretRepoError> {
        let entry = command.into_entry();
        Self::validate_entry_scope(scope, &entry)?;
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| {
                let entry = entry.clone();
                async move {
                    self.pool
                        .retry_secret_write(
                            scope,
                            deadline,
                            move |mut tx| {
                                Box::pin(
                                    async move { Self::cas_insert_locked(&mut tx, entry).await },
                                )
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_secret_repo_error,
        )
        .await
    }

    async fn delete(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<(), SecretRepoError> {
        let key = key.clone();
        self.pool
            .secret_write(
                scope,
                move |mut tx| {
                    Box::pin(
                        async move { tx.secrets().lock_key(&key).await?.append_tombstone().await },
                    )
                },
                storage,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_latest_version_is_storage_corruption() -> Result<(), SecretRepoError> {
        assert!(matches!(
            decode_optional_version(Some(-1)),
            Err(SecretRepoError::Storage(_))
        ));
        assert_eq!(decode_optional_version(None)?, None);
        assert_eq!(decode_optional_version(Some(7))?, Some(7));
        Ok(())
    }
}
