//! `PgConfigRepo` —— settings 配置版本化仓储 + co-tx UoW 的 postgres adapter（#1249）。
//!
//! impl `settings::ports::ConfigRepo`（find / find_version / save / delete）+ `settings::ports::ConfigUnitOfWork`
//! （`save_and_append_outbox` co-tx）。adapter→域 DIP 内向边（postgres 依赖 settings、native AFIT impl 其域形
//! port，经 deny.toml settings wrapper + `allows(Adapter,Domain)` 放行；adapter 不被域依赖）。
//!
//! 版本历史模型 + CAS（etcd 版本模型，settings ports.rs）：每 (tenant, key) 全版本行；`find` = max(version)、
//! `find_version` = 精确版本、`save` = `INSERT ... WHERE $v = 1 + COALESCE(max(version),0)`（0 行 → VersionConflict；
//! 并发同版本写经 PK unique violation 亦 → VersionConflict）。`save_and_append_outbox` 经 `co_tx_with_outbox`
//! 把同一 CAS INSERT 与 outbox append 收进单事务（both-or-neither，OUTBOX-COTX-CONFIG-01）。
//!
//! storage 错误经 `ConfigRepoError::Storage(Box::new(sqlx_err))` 分层冒泡（保留 source 链；域 crate 不依赖
//! sqlx）。读路径经 [`tenant_scoped_read`]（cotx）注入 SET LOCAL，与 0009 迁移的 RLS policy
//! `current_setting('rss.tenant_id', true)` 对齐（#1298）；写路径另经 co-tx SET LOCAL 锚点。
//!
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型：save 以 version+1 守乐观并发）
//! ref: crates/identity 域形 UoW 端口范式 + adapters/postgres/src/session_lifecycle.rs（co-tx 范式）

use consistency::Entry;
use diport::{Clock, OutboxEnvelopeParts};
use futures::future::BoxFuture;
use settings::ports::{
    ConfigEntry, ConfigRepo, ConfigRepoError, ConfigUnitOfWork, SettingKey, TenantId,
};
use sqlx::{Executor, PgConnection, Postgres, Row};

use crate::PgStore;
use crate::cotx::{co_tx_with_outbox, set_local_tenant, tenant_scoped_read};
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};

/// settings 配置仓储 + co-tx UoW 的 PostgreSQL adapter。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，同 [`crate::PgSessionLifecycle`]）clone 构造；
/// 读端口与 co-tx 写共用同一 `pool`（保证读得到已提交写）。
///
/// `clock` 是注入的 [`Clock`]（必填构造器位置参，`Box<dyn Clock>`，同 [`crate::PgEmitter`] /
/// [`crate::PgSessionLifecycle`]）：co-tx outbox envelope `occurred_at` 时间源（#1129/#262 F1——settings 的
/// `settings.config-version-changed` 生产 outbox 路径，本是第三条漏接 occurred_at 的构造点）。
pub struct PgConfigRepo {
    pool: sqlx::PgPool,
    clock: Box<dyn Clock>,
}

impl PgConfigRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    pub fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: store.pool.clone(),
            clock,
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，故在 adapter 边界收口）。
fn storage(e: sqlx::Error) -> ConfigRepoError {
    ConfigRepoError::Storage(Box::new(e))
}

/// `TenantId` → SQL bind 参数（stringify UUID，绑 `$N::uuid` server-side cast；不给 sqlx 加 uuid feature，
/// 同 `session_lifecycle` / outbox.event_id 范式）。收口此处避免 `as_uuid().to_string()` 在各查询点漂移。
fn tenant_param(tenant: TenantId) -> String {
    tenant.as_uuid().to_string()
}

/// u64 版本号 → wire i64（绑 `bigint` 列）。
///
/// reason: 版本号实践中从 1 单调递增、远不及 `i64::MAX`（2^63 次写在系统生命周期内不可达）；溢出收口
/// `i64::MAX` 而非 panic——`cas_insert` 的 CAS WHERE 永不成立 → `VersionConflict`、`find_version` 不匹配任何
/// 行 → `None`，均 fail-closed（与 `application::wire_version` 同语义，边界收口一致）。
fn version_param(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// DB row → [`ConfigEntry`]（受控 hydrate）。`config_key` 经 `SettingKey::parse` 复核——持久化值写入时已校验，
/// 复核失败属数据完整性问题，归 `Storage`（保留原错误）。`version` i64 → u64（负值不可能：CAS 从 1 递增）。
fn hydrate_row(
    tenant: TenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<ConfigEntry, ConfigRepoError> {
    let key_str: String = row.try_get("config_key").map_err(storage)?;
    let value: String = row.try_get("value").map_err(storage)?;
    let version: i64 = row.try_get("version").map_err(storage)?;
    let key = SettingKey::parse(&key_str).map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
    let version = u64::try_from(version).map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
    Ok(ConfigEntry::hydrate(key, value, tenant, version))
}

/// CAS 追加新版本（泛型 executor：`&PgPool`（plain save）/ `&mut PgConnection`（co-tx 事务内）共用一条语句）。
///
/// 新版本须 = 当前最高 + 1（首版 = 1），否则 0 行 affected → `VersionConflict`；并发同版本写经 PK
/// unique violation(23505) 亦 → `VersionConflict`（另一写者已占该版本）；其余 sqlx 错误 → `Storage`。
async fn cas_insert<'e, E>(
    executor: E,
    tenant: TenantId,
    entry: &ConfigEntry,
) -> Result<(), ConfigRepoError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        INSERT INTO config_entries (tenant_id, config_key, version, value)
        SELECT $1::uuid, $2, $3, $4
        WHERE $3 = 1 + COALESCE(
            (SELECT max(version) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2),
            0
        )
        "#,
    )
    .bind(tenant_param(tenant))
    .bind(entry.key().as_str())
    .bind(version_param(entry.version()))
    .bind(entry.value())
    .execute(executor)
    .await;
    match result {
        Ok(done) if done.rows_affected() == 1 => Ok(()),
        // 0 行：版本号非「当前最高 + 1」（陈旧 / 重复）——乐观并发写冲突。
        Ok(_) => Err(ConfigRepoError::VersionConflict),
        // 并发同版本写：PK (tenant, key, version) unique violation ⇒ 另一写者已占该版本 ⇒ 冲突。
        Err(e)
            if e.as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            Err(ConfigRepoError::VersionConflict)
        }
        Err(e) => Err(storage(e)),
    }
}

/// row（含 `deleted` 列）→ 活跃 `ConfigEntry`：tombstone（`deleted=true`）⇒ 视为已删 `None`；否则 hydrate。
/// `find` / `find_version` 共用（活跃值语义；版本计数器经 `latest_version` 单独读，含 tombstone）。
fn hydrate_active(
    tenant: TenantId,
    row: Option<sqlx::postgres::PgRow>,
) -> Result<Option<ConfigEntry>, ConfigRepoError> {
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

/// 在 tenant-scoped 事务内执行单条写（begin → SET LOCAL tenant → write → 单 commit；失败 rollback）。
///
/// F3：plain `save` / `delete` 与 co-tx 写路径一致经 [`set_local_tenant`] 注入 scope，不绕过 tenant scope
/// （未来 RLS policy 锚点）。错误已是域 [`ConfigRepoError`]（业务写闭包内 map），骨架 sqlx 错误经 `storage` 收口。
async fn tenant_scoped<F>(
    pool: &sqlx::PgPool,
    tenant_uuid: &str,
    write: F,
) -> Result<(), ConfigRepoError>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<(), ConfigRepoError>> + Send,
{
    let mut tx = pool.begin().await.map_err(storage)?;
    set_local_tenant(&mut tx, tenant_uuid)
        .await
        .map_err(storage)?;
    match write(&mut tx).await {
        Ok(()) => tx.commit().await.map_err(|e| {
            tracing::warn!(
                target: "postgres",
                tenant_id = tenant_uuid,
                error = %secure::redact_error(&e),
                "tenant_scoped: commit failed"
            );
            storage(e)
        }),
        Err(e) => {
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = tenant_uuid,
                    error = %secure::redact_error(&rb),
                    "tenant_scoped: rollback failed after write error"
                );
            }
            Err(e)
        }
    }
}

impl ConfigRepo for PgConfigRepo {
    async fn find(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
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
                        SELECT config_key, value, version, deleted
                        FROM config_entries
                        WHERE tenant_id = $1::uuid AND config_key = $2
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
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
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
                        SELECT config_key, value, version, deleted
                        FROM config_entries
                        WHERE tenant_id = $1::uuid AND config_key = $2 AND version = $3
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
        key: &SettingKey,
    ) -> Result<Option<u64>, ConfigRepoError> {
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
                        "SELECT max(version) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
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

    async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), ConfigRepoError> {
        // F3：plain CAS 写经 tenant-scoped 事务（SET LOCAL），与 co-tx 写路径一致。
        let tenant_uuid = tenant_param(tenant);
        tenant_scoped(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move { cas_insert(conn, tenant, &entry).await })
        })
        .await
    }

    async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), ConfigRepoError> {
        // F1 软删：仅当 latest 非 tombstone 时在 max+1 追加 tombstone（幂等；version 单调不重置，防 event_id
        // 复用）。F3：经 tenant-scoped 事务（SET LOCAL）。
        let tenant_uuid = tenant_param(tenant);
        let tu = tenant_uuid.clone();
        let key_str = key.as_str().to_string();
        tenant_scoped(&self.pool, &tenant_uuid, move |conn| {
            Box::pin(async move {
                sqlx::query(
                    r#"
                    INSERT INTO config_entries (tenant_id, config_key, version, value, deleted)
                    SELECT $1::uuid, $2, 1 + COALESCE(max(version), 0), '', true
                    FROM config_entries
                    WHERE tenant_id = $1::uuid AND config_key = $2
                    HAVING NOT COALESCE(
                        (SELECT deleted FROM config_entries
                         WHERE tenant_id = $1::uuid AND config_key = $2
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

impl ConfigUnitOfWork for PgConfigRepo {
    async fn save_and_append_outbox(
        &self,
        tenant: TenantId,
        entry: ConfigEntry,
        outbox_entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subjectId，FR-020；同 PgSessionLifecycle）。
        // `contract` 契约派生绑定（#1193），routing 列经 `domain()`/`contract_id()` 取。reserved key occurred_at
        // 由 `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1：settings 生产 outbox 路径补齐
        // occurred_at；漏接编译期不可表达）。
        let (contract, subject_id, partition_key) = envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now())).with_subject_id(subject_id),
        )
        .with_partition_key_opt(partition_key);
        let tenant_uuid = tenant_param(tenant);
        // co-tx：CAS 配置写 + outbox append 同事务（OUTBOX-COTX-CONFIG-01）。CAS 冲突 → VersionConflict 使整
        // 事务回滚（outbox 不落库）；storage 失败 → Storage。
        co_tx_with_outbox(
            &self.pool,
            &tenant_uuid,
            &outbox_entry,
            &env,
            move |conn| Box::pin(async move { cas_insert(conn, tenant, &entry).await }),
            storage,
        )
        .await
    }
}
