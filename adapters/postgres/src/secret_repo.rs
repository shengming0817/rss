//! `PgSecretRepo` —— settings secret 引用坐标仓储的 postgres adapter（#1274）。
//!
//! impl `settings::ports::SecretRepo`（find / find_version / latest_version / save / delete）。
//! adapter→域 DIP 内向边（postgres 依赖 settings、native AFIT impl 其域形 port，经 deny.toml settings wrapper +
//! `allows(Adapter,Domain)` 放行；adapter 不被域依赖）。
//!
//! !! **本 adapter 只持久化引用坐标，绝无任何 secret 材料字段** !!（store_id / ref_key / ref_version）。
//! 读取真实材料须经 `diport::SecretResolver::resolve` 在调用栈内获取，不经本 adapter。
//!
//! 版本历史模型 + CAS（同 config_repo.rs etcd 版本模型）：每 (tenant, key) 全版本行；`find` = max(version) 非
//! tombstone；`find_version` = 精确版本非 tombstone；`save` = `INSERT ... WHERE $v = 1 + COALESCE(max,0)`（0
//! 行 → VersionConflict；PK unique violation(23505) → VersionConflict）。
//!
//! `delete` = tombstone 软删：max+1 追加 deleted=true 占位行（幂等；latest 已 tombstone/key 不存在 → no-op）；
//! 占位坐标列 store_id='', ref_key='', ref_version=NULL——不携带有效坐标，version 单调不重置。
//!
//! storage 错误经 `SecretRepoError::Storage(Box::new(sqlx_err))` 分层冒泡（保留 source；域 crate 不依赖 sqlx）。
//! 读路径经 [`tenant_scoped_read`]（cotx）注入 SET LOCAL，对齐 RLS policy current_setting（#1298）；
//! 写路径另经 `set_local_tenant` 事务内 SET LOCAL 锚点。
//!
//! ref: adapters/postgres/src/config_repo.rs（版本历史 + CAS + tombstone + tenant_scoped 范式）

use futures::future::BoxFuture;
use settings::ports::{SecretEntry, SecretKey, SecretRepo, SecretRepoError, StoreId, TenantId};
use sqlx::{Executor, PgConnection, Postgres, Row};

use crate::PgStore;
use crate::cotx::{set_local_tenant, tenant_scoped_read};

/// settings secret 引用坐标仓储 PostgreSQL adapter。
///
/// !! **只存引用坐标，绝无 secret 材料** !!
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入）clone 构造；读路径与写路径共用同一 pool。
pub struct PgSecretRepo {
    pool: sqlx::PgPool,
}

impl PgSecretRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Settings>::secret_repo` 收口。
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx）。
fn storage(e: sqlx::Error) -> SecretRepoError {
    SecretRepoError::Storage(Box::new(e))
}

/// `TenantId` → SQL bind 参数（stringify UUID，绑 `$N::uuid` server-side cast；同 config_repo 范式）。
fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

/// u64 版本号 → wire i64（绑 `bigint` 列）。
///
/// reason: 版本号从 1 单调递增，实践中远不及 `i64::MAX`；溢出收口 `i64::MAX` 而非 panic——CAS WHERE 永不
/// 成立 → `VersionConflict`、`find_version` 不匹配任何行 → `None`，均 fail-closed（同 config_repo）。
fn version_param(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// DB row → [`SecretEntry`]（受控 hydrate）。
///
/// - `secret_key` 经 `SecretKey::parse` 复核（持久化时已校验，失败属数据完整性问题 → `Storage`）。
/// - `store_id` 经 `StoreId::parse` 复核（同上）。
/// - `version` i64 → u64（负值不可能：CAS 从 1 单调递增）。
/// - `ref_version` Option<String>（NULL → None）。
fn hydrate_row(
    tenant: TenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<SecretEntry, SecretRepoError> {
    let key_str: String = row.try_get("secret_key").map_err(storage)?;
    let store_id_str: String = row.try_get("store_id").map_err(storage)?;
    let ref_key: String = row.try_get("ref_key").map_err(storage)?;
    let ref_version: Option<String> = row.try_get("ref_version").map_err(storage)?;
    let version: i64 = row.try_get("version").map_err(storage)?;

    let key = SecretKey::parse(&key_str).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;
    let store_id =
        StoreId::parse(&store_id_str).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;
    let version = u64::try_from(version).map_err(|e| SecretRepoError::Storage(Box::new(e)))?;

    Ok(SecretEntry::hydrate(
        key,
        store_id,
        ref_key,
        ref_version,
        tenant,
        version,
    ))
}

/// row（含 `deleted` 列）→ 活跃 `SecretEntry`：tombstone（`deleted=true`）⇒ 视为已删 `None`；否则 hydrate。
fn hydrate_active(
    tenant: TenantId,
    row: Option<sqlx::postgres::PgRow>,
) -> Result<Option<SecretEntry>, SecretRepoError> {
    match row {
        None => Ok(None),
        Some(r) => {
            let deleted: bool = r.try_get("deleted").map_err(storage)?;
            if deleted {
                Ok(None)
            } else {
                Ok(Some(hydrate_row(tenant, &r)?))
            }
        }
    }
}

/// CAS 追加新版本（泛型 executor：`&PgPool`（plain save）/ `&mut PgConnection`（事务内）共用）。
///
/// 新版本须 = 当前最高 + 1（首版 = 1），否则 0 行 affected → `VersionConflict`；并发同版本写经 PK
/// unique violation(23505) → `VersionConflict`；其余 sqlx 错误 → `Storage`。
async fn cas_insert<'e, E>(
    executor: E,
    tenant: TenantId,
    entry: &SecretEntry,
) -> Result<(), SecretRepoError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key, ref_version)
        SELECT $1::uuid, $2, $3, $4, $5, $6
        WHERE $3 = 1 + COALESCE(
            (SELECT max(version) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2),
            0
        )
        "#,
    )
    .bind(tenant_param(tenant))
    .bind(entry.key().as_str())
    .bind(version_param(entry.version()))
    .bind(entry.secret_ref().store_id().as_str())
    .bind(entry.secret_ref().ref_key())
    .bind(entry.secret_ref().ref_version())
    .execute(executor)
    .await;

    match result {
        Ok(done) if done.rows_affected() == 1 => Ok(()),
        // 0 行：版本号非「当前最高 + 1」（陈旧 / 跳版）——乐观并发写冲突。
        Ok(_) => Err(SecretRepoError::VersionConflict),
        // 并发同版本写：PK (tenant, key, version) unique violation ⇒ 另一写者已占该版本 ⇒ 冲突。
        Err(e)
            if e.as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            Err(SecretRepoError::VersionConflict)
        }
        Err(e) => Err(storage(e)),
    }
}

/// 在 tenant-scoped 事务内执行单条写（begin → SET LOCAL tenant → write → commit；失败 rollback）。
///
/// 写路径经 [`set_local_tenant`] 注入 scope，与 config_repo 写路径一致（未来 RLS policy 锚点）。
async fn tenant_scoped<F>(
    pool: &sqlx::PgPool,
    tenant_uuid: &str,
    write: F,
) -> Result<(), SecretRepoError>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<(), SecretRepoError>> + Send,
{
    let mut tx = pool.begin().await.map_err(storage)?;
    set_local_tenant(&mut tx, tenant_uuid)
        .await
        .map_err(storage)?;
    match write(&mut tx).await {
        Ok(()) => tx.commit().await.map_err(storage),
        Err(e) => {
            let _ = tx.rollback().await;
            Err(e)
        }
    }
}

impl SecretRepo for PgSecretRepo {
    async fn find(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 活跃值 = 最高版本行且非 tombstone（latest 为 tombstone ⇒ 已删 None）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned，不借连接）；hydrate_active 在 tx 外执行。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();

        let row = tenant_scoped_read(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move {
                sqlx::query(
                    r#"
                    SELECT secret_key, store_id, ref_key, ref_version, version, deleted
                    FROM secret_refs
                    WHERE tenant_id = $1::uuid AND secret_key = $2
                    ORDER BY version DESC
                    LIMIT 1
                    "#,
                )
                .bind(tenant_uuid_q)
                .bind(key_str)
                .fetch_optional(&mut *conn)
                .await
            })
        })
        .await
        .map_err(storage)?;
        hydrate_active(tenant, row)
    }

    async fn find_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned）；hydrate_active 在 tx 外执行。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();
        let version_i = version_param(version);

        let row = tenant_scoped_read(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move {
                sqlx::query(
                    r#"
                    SELECT secret_key, store_id, ref_key, ref_version, version, deleted
                    FROM secret_refs
                    WHERE tenant_id = $1::uuid AND secret_key = $2 AND version = $3
                    "#,
                )
                .bind(tenant_uuid_q)
                .bind(key_str)
                .bind(version_i)
                .fetch_optional(&mut *conn)
                .await
            })
        })
        .await
        .map_err(storage)?;
        hydrate_active(tenant, row)
    }

    async fn latest_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError> {
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 真实最高版本（含 tombstone）；max() 对空集返 NULL（fetch_one 恒一行）。
        // rss_app 角色下 RLS 过滤后 max() 仅对当前 tenant 行计算（否则无 SET LOCAL 时 rss_app 下所有行不可见
        // → max() 返 NULL，后续版本序列断裂）——此为 tenant_scoped_read 覆盖 latest_version 的关键理由。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();

        let (mv,): (Option<i64>,) = tenant_scoped_read(
            &self.pool,
            &tenant_uuid,
            move |conn| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT max(version) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
                    )
                    .bind(tenant_uuid_q)
                    .bind(key_str)
                    .fetch_one(&mut *conn)
                    .await
                })
            },
        )
        .await
        .map_err(storage)?;
        Ok(mv.and_then(|v| u64::try_from(v).ok()))
    }

    async fn save(&self, tenant: TenantId, entry: SecretEntry) -> Result<(), SecretRepoError> {
        // 写路径经 tenant-scoped 事务（SET LOCAL），与 co-tx 写路径一致（未来 RLS policy 锚点）。
        let tenant_uuid = tenant_param(tenant);
        tenant_scoped(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move { cas_insert(conn, tenant, &entry).await })
        })
        .await
    }

    async fn delete(&self, tenant: TenantId, key: &SecretKey) -> Result<(), SecretRepoError> {
        // 软删：仅当 latest 非 tombstone 时在 max+1 追加 tombstone（幂等；version 单调不重置）。
        // 占位坐标列 store_id='', ref_key='', ref_version=NULL——不携带有效坐标。
        let tenant_uuid = tenant_param(tenant);
        let tu = tenant_uuid.clone();
        let key_str = key.as_str().to_string();
        tenant_scoped(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move {
                sqlx::query(
                    r#"
                    INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key, ref_version, deleted)
                    SELECT $1::uuid, $2, 1 + COALESCE(max(version), 0), '', '', NULL, true
                    FROM secret_refs
                    WHERE tenant_id = $1::uuid AND secret_key = $2
                    HAVING NOT COALESCE(
                        (SELECT deleted FROM secret_refs
                         WHERE tenant_id = $1::uuid AND secret_key = $2
                         ORDER BY version DESC LIMIT 1),
                        true)
                    "#,
                )
                .bind(&tu)
                .bind(&key_str)
                .execute(&mut *conn)
                .await
                .map_err(storage)
                .map(|_| ())
            })
        })
        .await
    }
}
