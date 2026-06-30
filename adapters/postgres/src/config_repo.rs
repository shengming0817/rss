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

use std::sync::Arc;
#[cfg(all(test, feature = "integration"))]
use std::sync::Mutex;
#[cfg(all(test, feature = "integration"))]
use std::sync::atomic::{AtomicUsize, Ordering};

use consistency::Entry;
use diport::key_provider::KeyProviderErrorKind;
use diport::{
    Clock, DynKeyProvider, KeyName, KeyProvider, KeyProviderError, KeyRef, OutboxEnvelopeParts,
    RedactedBytes,
};
use secure::{DerivedAad, Plaintext, ProtectionContext};
use settings::ports::{
    ConfigEntry, ConfigRepo, ConfigRepoError, ConfigUnitOfWork, SettingKey, TenantId,
};
use sqlx::{Executor, Postgres, Row};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::tx_retry::{SETTINGS_CONFIG_BOUNDARY, classify_config_repo_error, run_pg_tx_retry};

#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_REMAINING: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_TARGET: Mutex<Option<&'static str>> = Mutex::new(None);

/// settings 配置仓储 + co-tx UoW 的 PostgreSQL adapter。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，同 [`crate::PgSessionLifecycle`]）clone 构造；
/// 读端口与 co-tx 写共用同一 `pool`（保证读得到已提交写）。
///
/// `clock` 是注入的 [`Clock`]（必填构造器位置参，`Arc<dyn Clock>`）：co-tx outbox envelope `occurred_at`
/// 时间源（#1129/#262 F1——settings 的 `settings.config-version-changed` 生产 outbox 路径，本是第三条漏接
/// occurred_at 的构造点）。用 `Arc`（非 `Box`，区别于 [`crate::PgEmitter`] / [`crate::PgSessionLifecycle`]）：
/// settings bundle 以**单一**注入 clock 经 `Arc::clone` 扇出到 read/write 两个实例（PERSIST-003，#1424）。
pub struct PgConfigRepo {
    pool: PgTenantPool,
    clock: Arc<dyn Clock>,
    protection: ConfigValueProtection,
}

/// settings `ConfigValue` 字段保护依赖：KeyProvider 句柄 + 写入 keyset 名。
///
/// 字段私有，唯一构造经 [`ConfigValueProtection::new`]。`PgConfigRepo` 只持此参数对象，不知道具体 Vault
/// adapter；组合根 / bundle 负责传入共享 KeyProvider handle。
pub struct ConfigValueProtection {
    key_provider: Box<DynKeyProvider<'static>>,
    key_name: KeyName,
}

impl ConfigValueProtection {
    /// 构造 config value 字段保护依赖。两项必填，无 plaintext-write flag。
    #[must_use]
    pub fn new(key_provider: Box<DynKeyProvider<'static>>, key_name: KeyName) -> Self {
        Self {
            key_provider,
            key_name,
        }
    }
}

/// settings bundle 读写两条 config lane 的字段保护依赖。
///
/// `settings_bundle` 只接收此聚合类型，不暴露两个同类型 `ConfigValueProtection` 位置参，避免组合根把
/// read/write lane 误调换（F6）。读写 lane 各持独立 `DynKeyProvider` handle；共享同一 key name。
pub struct ConfigValueProtections {
    read: ConfigValueProtection,
    write: ConfigValueProtection,
}

impl ConfigValueProtections {
    /// 构造 settings bundle 的读写字段保护依赖。两条 lane 的 provider handle 与 key name 均显式注入。
    #[must_use]
    pub fn new(
        read_key_provider: Box<DynKeyProvider<'static>>,
        write_key_provider: Box<DynKeyProvider<'static>>,
        key_name: KeyName,
    ) -> Self {
        Self {
            read: ConfigValueProtection::new(read_key_provider, key_name.clone()),
            write: ConfigValueProtection::new(write_key_provider, key_name),
        }
    }

    pub(crate) fn into_parts(self) -> (ConfigValueProtection, ConfigValueProtection) {
        (self.read, self.write)
    }
}

impl PgConfigRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Settings>::settings_bundle` 收口。
    pub(crate) fn new(
        store: &PgStore,
        clock: Arc<dyn Clock>,
        protection: ConfigValueProtection,
    ) -> Self {
        Self {
            pool: PgTenantPool::new(store),
            clock,
            protection,
        }
    }
}

const CONFIG_VALUE_FIELD: &str = "settings.config.value";
const CONFIG_VALUE_PROTECTION_SCHEME: i32 = 1;

#[derive(Clone)]
struct EncodedConfigValue {
    value: Option<String>,
    protection_scheme: i32,
    value_enc: Option<Vec<u8>>,
    key_id: Option<String>,
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，故在 adapter 边界收口）。
fn storage(e: sqlx::Error) -> ConfigRepoError {
    ConfigRepoError::Storage(Box::new(e))
}

fn protection_unavailable<E>(e: E) -> ConfigRepoError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ConfigRepoError::ProtectionUnavailable(Box::new(e))
}

fn protection_auth_failure<E>(e: E) -> ConfigRepoError
where
    E: std::error::Error + Send + Sync + 'static,
{
    ConfigRepoError::ProtectionAuthFailure(Box::new(e))
}

fn protection_auth_message(message: &'static str) -> ConfigRepoError {
    protection_auth_failure(std::io::Error::other(message))
}

fn key_provider_error(e: KeyProviderError) -> ConfigRepoError {
    match e.kind() {
        KeyProviderErrorKind::Rejected => protection_auth_failure(e),
        KeyProviderErrorKind::NotFound
        | KeyProviderErrorKind::Forbidden
        | KeyProviderErrorKind::Unavailable
        | KeyProviderErrorKind::Timeout => protection_unavailable(e),
        _ => protection_unavailable(e),
    }
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn arm_config_retry_failpoint(target_key: &'static str, failures: usize) {
    if let Ok(mut target) = CONFIG_RETRY_FAIL_TARGET.lock() {
        *target = Some(target_key);
    }
    CONFIG_RETRY_FAIL_HITS.store(0, Ordering::Release);
    CONFIG_RETRY_FAIL_REMAINING.store(failures, Ordering::Release);
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn config_retry_failpoint_hits() -> usize {
    CONFIG_RETRY_FAIL_HITS.load(Ordering::Acquire)
}

#[cfg(all(test, feature = "integration"))]
fn maybe_fail_config_retry(key: &SettingKey) -> Result<(), ConfigRepoError> {
    let target_matches = CONFIG_RETRY_FAIL_TARGET
        .lock()
        .map(|target| target.is_some_and(|target| target == key.as_str()))
        .unwrap_or(false);
    if !target_matches {
        return Ok(());
    }
    CONFIG_RETRY_FAIL_HITS.fetch_add(1, Ordering::AcqRel);
    if CONFIG_RETRY_FAIL_REMAINING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        Err(storage(sqlx::Error::PoolTimedOut))
    } else {
        Ok(())
    }
}

fn is_unique_violation(error: &ConfigRepoError) -> bool {
    match error {
        ConfigRepoError::Storage(source) => source
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .is_some_and(|db| db.is_unique_violation()),
        _ => false,
    }
}

fn tenant_mismatch_storage_error(path: &'static str) -> ConfigRepoError {
    ConfigRepoError::Storage(Box::new(std::io::Error::other(format!(
        "{path}: outbox envelope tenant does not match transaction tenant"
    ))))
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

fn config_value_aad(tenant: TenantId, key: &SettingKey) -> Result<DerivedAad, ConfigRepoError> {
    ProtectionContext::authenticated_request(
        tenant,
        key.as_str(),
        CONFIG_VALUE_FIELD,
        CONFIG_VALUE_PROTECTION_SCHEME as u32,
    )
    .map(|ctx| ctx.derive())
    .map_err(protection_auth_failure)
}

impl PgConfigRepo {
    async fn encode_value(
        &self,
        tenant: TenantId,
        entry: &ConfigEntry,
    ) -> Result<EncodedConfigValue, ConfigRepoError> {
        self.encode_value_bytes(tenant, entry.key(), entry.value().as_bytes())
            .await
    }

    async fn encode_value_bytes(
        &self,
        tenant: TenantId,
        key: &SettingKey,
        value: &[u8],
    ) -> Result<EncodedConfigValue, ConfigRepoError> {
        let aad = config_value_aad(tenant, key)?;
        let encrypted = self
            .protection
            .key_provider
            .encrypt(
                self.protection.key_name.clone(),
                Plaintext::new(value.to_vec()),
                aad,
            )
            .await
            .map_err(key_provider_error)?;
        Ok(EncodedConfigValue {
            value: None,
            protection_scheme: CONFIG_VALUE_PROTECTION_SCHEME,
            value_enc: Some(encrypted.ciphertext().to_vec()),
            key_id: Some(encrypted.key().to_token()),
        })
    }

    async fn decode_value(
        &self,
        tenant: TenantId,
        key: &SettingKey,
        row: &sqlx::postgres::PgRow,
    ) -> Result<String, ConfigRepoError> {
        let scheme: i32 = row.try_get("protection_scheme").map_err(storage)?;
        let value: Option<String> = row.try_get("value").map_err(storage)?;
        let value_enc: Option<Vec<u8>> = row.try_get("value_enc").map_err(storage)?;
        let key_id: Option<String> = row.try_get("key_id").map_err(storage)?;

        match scheme {
            0 => {
                if value_enc.is_some() || key_id.is_some() {
                    return Err(protection_auth_message(
                        "legacy config value has encrypted columns",
                    ));
                }
                value.ok_or_else(|| protection_auth_message("legacy config value is null"))
            }
            CONFIG_VALUE_PROTECTION_SCHEME => {
                if value.is_some() {
                    return Err(protection_auth_message(
                        "encrypted config value has plaintext",
                    ));
                }
                let ciphertext = value_enc.ok_or_else(|| {
                    protection_auth_message("encrypted config value missing ciphertext")
                })?;
                let key_ref = key_id
                    .ok_or_else(|| protection_auth_message("encrypted config value missing key id"))
                    .and_then(|raw| KeyRef::parse(&raw).map_err(protection_auth_failure))?;
                let aad = config_value_aad(tenant, key)?;
                let plaintext = self
                    .protection
                    .key_provider
                    .decrypt(RedactedBytes::new(ciphertext), key_ref, aad)
                    .await
                    .map_err(key_provider_error)?;
                String::from_utf8(plaintext.expose().to_vec()).map_err(protection_auth_failure)
            }
            _ => Err(protection_auth_message(
                "unknown config value protection scheme",
            )),
        }
    }

    /// DB row → [`ConfigEntry`]（受控 hydrate）。`config_key` 经 `SettingKey::parse` 复核——持久化值写入时
    /// 已校验，复核失败属数据完整性问题。`version` i64 → u64（负值不可能：CAS 从 1 递增）。
    async fn hydrate_row(
        &self,
        tenant: TenantId,
        row: &sqlx::postgres::PgRow,
    ) -> Result<ConfigEntry, ConfigRepoError> {
        let key_str: String = row.try_get("config_key").map_err(storage)?;
        let version: i64 = row.try_get("version").map_err(storage)?;
        let key = SettingKey::parse(&key_str).map_err(protection_auth_failure)?;
        let value = self.decode_value(tenant, &key, row).await?;
        let version = u64::try_from(version).map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
        Ok(ConfigEntry::hydrate(key, value, tenant, version))
    }
}

/// CAS 追加新版本（泛型 executor：`&PgPool`（plain save）/ `&mut PgConnection`（co-tx 事务内）共用一条语句）。
///
/// 新版本须 = 当前最高 + 1（首版 = 1），否则 0 行 affected → `VersionConflict`；并发同版本写经 PK
/// unique violation(23505) 亦 → `VersionConflict`（另一写者已占该版本）；其余 sqlx 错误 → `Storage`。
async fn cas_insert<'e, E>(
    executor: E,
    tenant: TenantId,
    entry: &ConfigEntry,
    encoded: &EncodedConfigValue,
) -> Result<(), ConfigRepoError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        INSERT INTO config_entries (
            tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
        )
        SELECT $1::uuid, $2, $3, $4, $5, $6, $7
        WHERE $3 = 1 + COALESCE(
            (SELECT max(version) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2),
            0
        )
        "#,
    )
    .bind(tenant_param(tenant))
    .bind(entry.key().as_str())
    .bind(version_param(entry.version()))
    .bind(encoded.value.as_deref())
    .bind(encoded.protection_scheme)
    .bind(encoded.value_enc.as_deref())
    .bind(encoded.key_id.as_deref())
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
async fn hydrate_active(
    repo: &PgConfigRepo,
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
                Ok(Some(repo.hydrate_row(tenant, &r).await?))
            }
        }
    }
}

async fn latest_deleted(
    pool: &PgTenantPool,
    tenant: TenantId,
    key: &SettingKey,
) -> Result<bool, ConfigRepoError> {
    let tenant_uuid = tenant_param(tenant);
    let key_str = key.as_str().to_owned();
    let deleted = pool
        .read(tenant, move |conn| {
            Box::pin(async move {
                sqlx::query_scalar(
                    r#"
                    SELECT deleted
                    FROM config_entries
                    WHERE tenant_id = $1::uuid AND config_key = $2
                    ORDER BY version DESC
                    LIMIT 1
                    "#,
                )
                .bind(tenant_uuid)
                .bind(key_str)
                .fetch_optional(&mut *conn)
                .await
            })
        })
        .await
        .map_err(storage)?;
    Ok(deleted.unwrap_or(false))
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

        let row = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        r#"
                        SELECT config_key, value, version, deleted, protection_scheme, value_enc, key_id
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
        hydrate_active(self, tenant, row).await
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

        let row = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query(
                        r#"
                        SELECT config_key, value, version, deleted, protection_scheme, value_enc, key_id
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
        hydrate_active(self, tenant, row).await
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

        let (mv,): (Option<i64>,) = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT max(version) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
                    )
                    .bind(tenant_uuid_q)
                    .bind(key_str)
                    .fetch_one(&mut *conn)
                    .await
                })
            })
        .await
        .map_err(storage)?;
        Ok(mv.and_then(|v| u64::try_from(v).ok()))
    }

    async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), ConfigRepoError> {
        // F3：plain CAS 写经 tenant-scoped 事务（SET LOCAL），与 co-tx 写路径一致。
        let encoded = self.encode_value(tenant, &entry).await?;
        run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |_attempt| {
                let entry = entry.clone();
                let encoded = encoded.clone();
                async move {
                    self.pool
                        .retry_write(
                            tenant,
                            move |conn| {
                                Box::pin(
                                    async move { cas_insert(conn, tenant, &entry, &encoded).await },
                                )
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_config_repo_error,
        )
        .await
    }

    async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), ConfigRepoError> {
        // F1 软删：仅当 latest 非 tombstone 时在 max+1 追加 tombstone（幂等；version 单调不重置，防 event_id
        // 复用）。F3：经 tenant-scoped 事务（SET LOCAL）。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_string();
        let tenant_uuid_q = tenant_uuid.clone();
        let key_str_q = key_str.clone();
        let latest_deleted_before: Option<bool> = self
            .pool
            .read(tenant, move |conn| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        r#"
                        SELECT deleted
                        FROM config_entries
                        WHERE tenant_id = $1::uuid AND config_key = $2
                        ORDER BY version DESC
                        LIMIT 1
                        "#,
                    )
                    .bind(tenant_uuid_q)
                    .bind(key_str_q)
                    .fetch_optional(&mut *conn)
                    .await
                })
            })
            .await
            .map_err(storage)?;
        if latest_deleted_before.unwrap_or(true) {
            return Ok(());
        }

        let encoded = self.encode_value_bytes(tenant, key, b"").await?;
        let result = run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |_attempt| {
                let tenant_uuid = tenant_uuid.clone();
                let key_str = key_str.clone();
                let encoded = encoded.clone();
                async move {
                    self.pool
                        .retry_write(
                            tenant,
                            move |conn| {
                                Box::pin(async move {
                                    sqlx::query(
                                        r#"
                    INSERT INTO config_entries (
                        tenant_id, config_key, version, value, deleted, protection_scheme, value_enc, key_id
                    )
                    SELECT $1::uuid, $2, 1 + COALESCE(max(version), 0), $3, true, $4, $5, $6
                    FROM config_entries
                    WHERE tenant_id = $1::uuid AND config_key = $2
                    HAVING NOT COALESCE(
                        (SELECT deleted FROM config_entries
                         WHERE tenant_id = $1::uuid AND config_key = $2
                         ORDER BY version DESC LIMIT 1),
                        true)
                    "#,
                                    )
                                    .bind(&tenant_uuid)
                                    .bind(&key_str)
                                    .bind(encoded.value.as_deref())
                                    .bind(encoded.protection_scheme)
                                    .bind(encoded.value_enc.as_deref())
                                    .bind(encoded.key_id.as_deref())
                                    .execute(&mut *conn)
                                    .await
                                    .map_err(storage)
                                    .map(|_| ())
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_config_repo_error,
        )
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(e)
                if is_unique_violation(&e) && latest_deleted(&self.pool, tenant, key).await? =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
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
        let (contract, env_tenant, subject_id, actor, partition_key) = envelope.into_parts();
        if env_tenant != tenant {
            return Err(tenant_mismatch_storage_error("config co-tx"));
        }
        let encoded = self.encode_value(tenant, &entry).await?;
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key);
        // co-tx：CAS 配置写 + outbox append 同事务（OUTBOX-COTX-CONFIG-01）。CAS 冲突 → VersionConflict 使整
        // 事务回滚（outbox 不落库）；storage 失败 → Storage。
        run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |_attempt| {
                let entry = entry.clone();
                let encoded = encoded.clone();
                let outbox_entry = outbox_entry.clone();
                let env = env.clone();
                async move {
                    self.pool
                        .retry_co_tx_with_outbox(
                            tenant,
                            &outbox_entry,
                            &env,
                            move |conn| {
                                Box::pin(async move {
                                    cas_insert(conn, tenant, &entry, &encoded).await?;
                                    #[cfg(all(test, feature = "integration"))]
                                    maybe_fail_config_retry(entry.key())?;
                                    Ok(())
                                })
                            },
                            storage,
                        )
                        .await
                }
            },
            classify_config_repo_error,
        )
        .await
    }
}
