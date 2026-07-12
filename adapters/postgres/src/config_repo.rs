//! `PgConfigRepo` —— settings 配置版本化仓储 + co-tx UoW 的 postgres adapter（#1249）。
//!
//! impl `settings::ports::ConfigRepo`（find / find_version / save / delete）+ `settings::ports::ConfigUnitOfWork`
//! （`commit` co-tx）。adapter→域 DIP 内向边（postgres 依赖 settings、native AFIT impl 其域形
//! port，经 deny.toml settings wrapper + `allows(Adapter,Domain)` 放行；adapter 不被域依赖）。
//!
//! 版本历史模型 + CAS（etcd 版本模型，settings ports.rs）：每 (tenant, key) 全版本行；`find` = max(version)、
//! `find_version` = 精确版本、`save` = `INSERT ... WHERE $v = 1 + COALESCE(max(version),0)`（0 行 → VersionConflict；
//! 并发同版本写经 PK unique violation 亦 → VersionConflict）。`commit` 经 `co_tx_with_outbox`
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

use consistency::EventEntry;
use diport::key_provider::KeyProviderErrorKind;
use diport::{
    Clock, DynKeyProvider, KeyName, KeyProvider, KeyProviderError, KeyRef, OutboxEnvelopeParts,
    RedactedBytes,
};
use secure::{DerivedAad, Plaintext, ProtectionContext};
use settings::ports::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepo, ConfigRepoError, ConfigTombstone,
    ConfigUnitOfWork, SettingKey, TenantId, TenantRepoScope,
};
use sqlx::{Executor, Postgres, Row};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{OutboxEnvelope, metadata_with_ambient, unix_secs};
use crate::projection_events::ProjectionWriteRegistry;
use crate::tx_retry::{SETTINGS_CONFIG_BOUNDARY, classify_config_repo_error, run_pg_tx_retry};

#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_REMAINING: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_HITS: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "integration"))]
static CONFIG_RETRY_FAIL_PERMANENT: AtomicUsize = AtomicUsize::new(0);
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

/// settings `ConfigValue` 存量维护操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigValueMaintenanceOperation {
    /// 仅把 legacy plaintext `protection_scheme=0` 行转换为 encrypted scheme。
    Backfill,
    /// 仅把 encrypted 行重包裹到 provider current-primary。
    Rewrap,
    /// 先 backfill，再 rewrap。
    Both,
}

impl ConfigValueMaintenanceOperation {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backfill => "backfill",
            Self::Rewrap => "rewrap",
            Self::Both => "both",
        }
    }

    fn includes_backfill(self) -> bool {
        matches!(self, Self::Backfill | Self::Both)
    }

    fn includes_rewrap(self) -> bool {
        matches!(self, Self::Rewrap | Self::Both)
    }
}

/// settings `ConfigValue` 存量维护参数。
#[derive(Debug, Clone)]
pub struct ConfigValueMaintenanceOptions {
    operation: ConfigValueMaintenanceOperation,
    tenant: Option<TenantId>,
    batch_size: usize,
    max_rows: Option<usize>,
    dry_run: bool,
}

impl ConfigValueMaintenanceOptions {
    /// 默认执行 backfill + rewrap，batch size = 500。
    #[must_use]
    pub fn new(operation: ConfigValueMaintenanceOperation) -> Self {
        Self {
            operation,
            tenant: None,
            batch_size: 500,
            max_rows: None,
            dry_run: false,
        }
    }

    /// 限定单租户。
    #[must_use]
    pub fn with_tenant(mut self, tenant: TenantId) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// 设置可选租户过滤。
    #[must_use]
    pub fn with_tenant_opt(mut self, tenant: Option<TenantId>) -> Self {
        self.tenant = tenant;
        self
    }

    /// 设置每批扫描行数。`0` 由执行入口 fail-closed 拒绝。
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// 设置本次最多处理的匹配行数。`Some(0)` 表示处理 0 行，供测试/脚本显式 dry boundary。
    #[must_use]
    pub fn with_max_rows(mut self, max_rows: Option<usize>) -> Self {
        self.max_rows = max_rows;
        self
    }

    /// 只统计，不写库、不调用 KeyProvider。
    #[must_use]
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// 当前租户过滤。
    #[must_use]
    pub fn tenant_opt(&self) -> Option<TenantId> {
        self.tenant
    }

    /// 当前 batch size。
    #[must_use]
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// 当前 max rows。
    #[must_use]
    pub fn max_rows(&self) -> Option<usize> {
        self.max_rows
    }

    /// 是否 dry-run。
    #[must_use]
    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    /// 当前维护操作。
    #[must_use]
    pub fn operation(&self) -> ConfigValueMaintenanceOperation {
        self.operation
    }
}

impl Default for ConfigValueMaintenanceOptions {
    fn default() -> Self {
        Self::new(ConfigValueMaintenanceOperation::Both)
    }
}

/// 已授权的 settings `ConfigValue` 维护能力。
///
/// 该类型由 runtime 验证 operator service-token 并写入 job-start durable audit 后 mint。维护 AAD 派生 helper
/// 必须持有该 capability，避免普通读写路径复用 legacy plaintext backfill/rewrap 入口。
#[derive(Debug, Clone)]
pub struct ConfigValueMaintenanceCapability {
    operator_subject: Box<str>,
}

impl ConfigValueMaintenanceCapability {
    pub fn from_verified_service_subject(
        operator_subject: impl Into<String>,
    ) -> Result<Self, ConfigRepoError> {
        Self::new(operator_subject)
    }

    pub(crate) fn new(operator_subject: impl Into<String>) -> Result<Self, ConfigRepoError> {
        let operator_subject = operator_subject.into();
        let operator_subject = operator_subject.trim();
        if operator_subject.is_empty() {
            return Err(protection_auth_message(
                "config value maintenance operator subject must be non-empty",
            ));
        }
        Ok(Self {
            operator_subject: operator_subject.into(),
        })
    }

    #[must_use]
    pub fn operator_subject(&self) -> &str {
        &self.operator_subject
    }
}

/// settings `ConfigValue` 存量维护结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigValueMaintenanceReport {
    pub selected: u64,
    pub backfilled: u64,
    pub rewrapped: u64,
    pub unchanged: u64,
    pub failed: u64,
    pub remaining_plaintext: u64,
}

impl ConfigValueMaintenanceReport {
    fn add(&mut self, other: Self) {
        self.selected += other.selected;
        self.backfilled += other.backfilled;
        self.rewrapped += other.rewrapped;
        self.unchanged += other.unchanged;
        self.failed += other.failed;
        self.remaining_plaintext = other.remaining_plaintext;
    }
}

/// settings `ConfigValue` 存量维护执行器。
pub struct PgConfigValueMaintenance {
    store: Arc<PgStore>,
    protection: ConfigValueProtection,
    capability: ConfigValueMaintenanceCapability,
}

impl PgConfigValueMaintenance {
    pub(crate) fn new(
        store: Arc<PgStore>,
        protection: ConfigValueProtection,
        capability: ConfigValueMaintenanceCapability,
    ) -> Self {
        Self {
            store,
            protection,
            capability,
        }
    }
}

impl PgConfigRepo {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Settings>::settings_bundle` 收口。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(
        store: &PgStore,
        clock: Arc<dyn Clock>,
        protection: ConfigValueProtection,
    ) -> Self {
        Self::new_with_projection_registry(
            store,
            clock,
            protection,
            ProjectionWriteRegistry::empty(),
        )
    }

    pub(crate) fn new_with_projection_registry(
        store: &PgStore,
        clock: Arc<dyn Clock>,
        protection: ConfigValueProtection,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: PgTenantPool::with_projection_registry(store, projection_registry),
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
    CONFIG_RETRY_ATTEMPTS.store(0, Ordering::Release);
    CONFIG_RETRY_FAIL_PERMANENT.store(0, Ordering::Release);
    CONFIG_RETRY_FAIL_REMAINING.store(failures, Ordering::Release);
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn arm_config_retry_permanent_failpoint(target_key: &'static str) {
    arm_config_retry_failpoint(target_key, 0);
    CONFIG_RETRY_FAIL_PERMANENT.store(1, Ordering::Release);
}

#[cfg(all(test, feature = "integration"))]
pub(crate) fn config_retry_attempts() -> usize {
    CONFIG_RETRY_ATTEMPTS.load(Ordering::Acquire)
}

#[cfg(all(test, feature = "integration"))]
fn record_config_retry_attempt(key: &SettingKey) {
    let target_matches = CONFIG_RETRY_FAIL_TARGET
        .lock()
        .map(|target| target.is_some_and(|target| target == key.as_str()))
        .unwrap_or(false);
    if target_matches {
        CONFIG_RETRY_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    }
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
    if CONFIG_RETRY_FAIL_PERMANENT.load(Ordering::Acquire) == 1 {
        return Err(storage(sqlx::Error::Protocol(
            "test-only permanent retry failure".to_owned(),
        )));
    }
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
                let _ = value;
                let _ = value_enc;
                let _ = key_id;
                Err(protection_auth_message(
                    "legacy config value requires maintenance backfill",
                ))
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

async fn cas_insert_tombstone<'e, E>(
    executor: E,
    tenant: TenantId,
    tombstone: &ConfigTombstone,
    encoded: &EncodedConfigValue,
) -> Result<(), ConfigRepoError>
where
    E: Executor<'e, Database = Postgres>,
{
    let result = sqlx::query(
        r#"
        INSERT INTO config_entries (
            tenant_id, config_key, version, value, deleted, protection_scheme, value_enc, key_id
        )
        SELECT $1::uuid, $2, $3, $4, true, $5, $6, $7
        WHERE $3 = 1 + COALESCE(
            (SELECT max(version) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2),
            0
        )
          AND COALESCE(
            (SELECT NOT deleted FROM config_entries
             WHERE tenant_id = $1::uuid AND config_key = $2
             ORDER BY version DESC LIMIT 1),
            false
          )
        "#,
    )
    .bind(tenant_param(tenant))
    .bind(tombstone.key().as_str())
    .bind(version_param(tombstone.version()))
    .bind(encoded.value.as_deref())
    .bind(encoded.protection_scheme)
    .bind(encoded.value_enc.as_deref())
    .bind(encoded.key_id.as_deref())
    .execute(executor)
    .await;
    match result {
        Ok(done) if done.rows_affected() == 1 => Ok(()),
        Ok(_) => Err(ConfigRepoError::VersionConflict),
        Err(error)
            if error
                .as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            Err(ConfigRepoError::VersionConflict)
        }
        Err(error) => Err(storage(error)),
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

#[derive(Clone)]
struct ConfigValueMaintenanceCursor {
    tenant_id: String,
    config_key: String,
    version: i64,
}

struct ConfigValueMaintenanceRow {
    tenant: TenantId,
    tenant_id: String,
    key: SettingKey,
    config_key: String,
    version: i64,
    value: Option<String>,
    value_enc: Option<Vec<u8>>,
    key_id: Option<String>,
}

impl ConfigValueMaintenanceRow {
    fn from_pg(row: sqlx::postgres::PgRow) -> Result<Self, ConfigRepoError> {
        let tenant_id: String = row.try_get("tenant_id").map_err(storage)?;
        let config_key: String = row.try_get("config_key").map_err(storage)?;
        let version: i64 = row.try_get("version").map_err(storage)?;
        let value: Option<String> = row.try_get("value").map_err(storage)?;
        let value_enc: Option<Vec<u8>> = row.try_get("value_enc").map_err(storage)?;
        let key_id: Option<String> = row.try_get("key_id").map_err(storage)?;
        let tenant = TenantId::parse(&tenant_id).map_err(protection_auth_failure)?;
        let key = SettingKey::parse(&config_key).map_err(protection_auth_failure)?;
        Ok(Self {
            tenant,
            tenant_id,
            key,
            config_key,
            version,
            value,
            value_enc,
            key_id,
        })
    }

    fn cursor(&self) -> ConfigValueMaintenanceCursor {
        ConfigValueMaintenanceCursor {
            tenant_id: self.tenant_id.clone(),
            config_key: self.config_key.clone(),
            version: self.version,
        }
    }
}

fn config_value_maintenance_aad(
    _capability: &ConfigValueMaintenanceCapability,
    tenant: TenantId,
    key: &SettingKey,
) -> Result<DerivedAad, ConfigRepoError> {
    ProtectionContext::authorized_maintenance(
        tenant,
        key.as_str(),
        CONFIG_VALUE_FIELD,
        CONFIG_VALUE_PROTECTION_SCHEME as u32,
    )
    .map(|ctx| ctx.derive())
    .map_err(protection_auth_failure)
}

fn maintenance_capacity(options: &ConfigValueMaintenanceOptions, selected: u64) -> usize {
    let remaining = options
        .max_rows
        .map(|max| max.saturating_sub(selected as usize))
        .unwrap_or(usize::MAX);
    options.batch_size.min(remaining)
}

impl PgConfigValueMaintenance {
    /// 执行 settings `ConfigValue` 存量 backfill/rewrap。
    pub async fn run(
        &self,
        options: &ConfigValueMaintenanceOptions,
    ) -> Result<ConfigValueMaintenanceReport, ConfigRepoError> {
        if options.batch_size == 0 {
            return Err(protection_auth_message(
                "config value maintenance batch size must be greater than zero",
            ));
        }
        let mut report = ConfigValueMaintenanceReport::default();
        if options.operation.includes_backfill() {
            report.add(self.run_backfill(options).await?);
        }
        if options.operation.includes_rewrap() {
            let rewrap_options = options.clone().with_max_rows(
                options
                    .max_rows
                    .map(|max_rows| max_rows.saturating_sub(report.selected as usize)),
            );
            if maintenance_capacity(&rewrap_options, 0) > 0 {
                report.add(self.run_rewrap(&rewrap_options).await?);
            }
        }
        report.remaining_plaintext = self.remaining_plaintext(options.tenant).await?;
        Ok(report)
    }

    // reason: batch scan loop + per-row disposition accounting is linear operational code; splitting would obscure
    // the maintenance report invariants more than it helps.
    #[allow(clippy::cognitive_complexity)]
    async fn run_backfill(
        &self,
        options: &ConfigValueMaintenanceOptions,
    ) -> Result<ConfigValueMaintenanceReport, ConfigRepoError> {
        let mut report = ConfigValueMaintenanceReport::default();
        let mut cursor = None;
        loop {
            let limit = maintenance_capacity(options, report.selected);
            if limit == 0 {
                break;
            }
            let rows = self
                .select_maintenance_rows(0, options.tenant, cursor.as_ref(), limit)
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = Some(row.cursor());
                report.selected += 1;
                if options.dry_run {
                    continue;
                }
                match self.backfill_row(&row).await {
                    Ok(true) => report.backfilled += 1,
                    Ok(false) => report.unchanged += 1,
                    Err(err) => {
                        report.failed += 1;
                        tracing::warn!(
                            error = %secure::redact_error(&err),
                            operator_subject = self.capability.operator_subject(),
                            tenant_id = row.tenant_id,
                            config_key = row.config_key,
                            version = row.version,
                            "config value backfill row failed"
                        );
                    }
                }
                if maintenance_capacity(options, report.selected) == 0 {
                    break;
                }
            }
        }
        Ok(report)
    }

    // reason: batch scan loop + key filtering + per-row disposition accounting is linear operational code; keeping it
    // together makes selected/backfilled/rewrapped/failed counters auditable.
    #[allow(clippy::cognitive_complexity)]
    async fn run_rewrap(
        &self,
        options: &ConfigValueMaintenanceOptions,
    ) -> Result<ConfigValueMaintenanceReport, ConfigRepoError> {
        let mut report = ConfigValueMaintenanceReport::default();
        let mut cursor = None;
        loop {
            let limit = maintenance_capacity(options, report.selected);
            if limit == 0 {
                break;
            }
            let rows = self
                .select_maintenance_rows(
                    CONFIG_VALUE_PROTECTION_SCHEME,
                    options.tenant,
                    cursor.as_ref(),
                    limit,
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                cursor = Some(row.cursor());
                let Some(raw_key_ref) = row.key_id.as_deref() else {
                    report.selected += 1;
                    report.failed += 1;
                    tracing::warn!(
                        operator_subject = self.capability.operator_subject(),
                        tenant_id = row.tenant_id,
                        config_key = row.config_key,
                        version = row.version,
                        "config value rewrap row missing key_id"
                    );
                    if maintenance_capacity(options, report.selected) == 0 {
                        break;
                    }
                    continue;
                };
                let Ok(key_ref) = KeyRef::parse(raw_key_ref) else {
                    report.selected += 1;
                    report.failed += 1;
                    tracing::warn!(
                        operator_subject = self.capability.operator_subject(),
                        tenant_id = row.tenant_id,
                        config_key = row.config_key,
                        version = row.version,
                        key_id = raw_key_ref,
                        "config value rewrap row invalid key_id"
                    );
                    if maintenance_capacity(options, report.selected) == 0 {
                        break;
                    }
                    continue;
                };
                if !key_ref.name().ct_eq(&self.protection.key_name) {
                    continue;
                }
                report.selected += 1;
                if options.dry_run {
                    continue;
                }
                match self.rewrap_row(&row, raw_key_ref, key_ref).await {
                    Ok(RewrapDisposition::Rewrapped) => report.rewrapped += 1,
                    Ok(RewrapDisposition::Unchanged) => report.unchanged += 1,
                    Err(err) => {
                        report.failed += 1;
                        tracing::warn!(
                            error = %secure::redact_error(&err),
                            operator_subject = self.capability.operator_subject(),
                            tenant_id = row.tenant_id,
                            config_key = row.config_key,
                            version = row.version,
                            "config value rewrap row failed"
                        );
                    }
                }
                if maintenance_capacity(options, report.selected) == 0 {
                    break;
                }
            }
        }
        Ok(report)
    }

    async fn select_maintenance_rows(
        &self,
        scheme: i32,
        tenant: Option<TenantId>,
        cursor: Option<&ConfigValueMaintenanceCursor>,
        limit: usize,
    ) -> Result<Vec<ConfigValueMaintenanceRow>, ConfigRepoError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = match (tenant, cursor) {
            (Some(tenant), Some(cursor)) => sqlx::query(
                r#"
                SELECT tenant_id::text, config_key, version, value, value_enc, key_id
                FROM config_entries
                WHERE protection_scheme = $1
                  AND tenant_id = $2::uuid
                  AND (tenant_id::text, config_key, version) > ($3, $4, $5)
                ORDER BY tenant_id::text, config_key, version
                LIMIT $6
                "#,
            )
            .bind(scheme)
            .bind(tenant_param(tenant))
            .bind(&cursor.tenant_id)
            .bind(&cursor.config_key)
            .bind(cursor.version)
            .bind(limit)
            .fetch_all(&self.store.pool)
            .await
            .map_err(storage)?,
            (Some(tenant), None) => sqlx::query(
                r#"
                SELECT tenant_id::text, config_key, version, value, value_enc, key_id
                FROM config_entries
                WHERE protection_scheme = $1
                  AND tenant_id = $2::uuid
                ORDER BY tenant_id::text, config_key, version
                LIMIT $3
                "#,
            )
            .bind(scheme)
            .bind(tenant_param(tenant))
            .bind(limit)
            .fetch_all(&self.store.pool)
            .await
            .map_err(storage)?,
            (None, Some(cursor)) => sqlx::query(
                r#"
                SELECT tenant_id::text, config_key, version, value, value_enc, key_id
                FROM config_entries
                WHERE protection_scheme = $1
                  AND (tenant_id::text, config_key, version) > ($2, $3, $4)
                ORDER BY tenant_id::text, config_key, version
                LIMIT $5
                "#,
            )
            .bind(scheme)
            .bind(&cursor.tenant_id)
            .bind(&cursor.config_key)
            .bind(cursor.version)
            .bind(limit)
            .fetch_all(&self.store.pool)
            .await
            .map_err(storage)?,
            (None, None) => sqlx::query(
                r#"
                SELECT tenant_id::text, config_key, version, value, value_enc, key_id
                FROM config_entries
                WHERE protection_scheme = $1
                ORDER BY tenant_id::text, config_key, version
                LIMIT $2
                "#,
            )
            .bind(scheme)
            .bind(limit)
            .fetch_all(&self.store.pool)
            .await
            .map_err(storage)?,
        };
        rows.into_iter()
            .map(ConfigValueMaintenanceRow::from_pg)
            .collect()
    }

    async fn backfill_row(&self, row: &ConfigValueMaintenanceRow) -> Result<bool, ConfigRepoError> {
        let value = row
            .value
            .as_ref()
            .ok_or_else(|| protection_auth_message("legacy config value is null"))?;
        if row.value_enc.is_some() || row.key_id.is_some() {
            return Err(protection_auth_message(
                "legacy config value has encrypted columns",
            ));
        }
        let aad = config_value_maintenance_aad(&self.capability, row.tenant, &row.key)?;
        let encrypted = self
            .protection
            .key_provider
            .encrypt(
                self.protection.key_name.clone(),
                Plaintext::new(value.as_bytes().to_vec()),
                aad,
            )
            .await
            .map_err(key_provider_error)?;
        let done = sqlx::query(
            r#"
            UPDATE config_entries
            SET value = NULL, protection_scheme = $4, value_enc = $5, key_id = $6
            WHERE tenant_id = $1::uuid
              AND config_key = $2
              AND version = $3
              AND protection_scheme = 0
              AND value IS NOT DISTINCT FROM $7
              AND value_enc IS NULL
              AND key_id IS NULL
            "#,
        )
        .bind(&row.tenant_id)
        .bind(&row.config_key)
        .bind(row.version)
        .bind(CONFIG_VALUE_PROTECTION_SCHEME)
        .bind(encrypted.ciphertext())
        .bind(encrypted.key().to_token())
        .bind(value)
        .execute(&self.store.pool)
        .await
        .map_err(storage)?;
        Ok(done.rows_affected() == 1)
    }

    async fn rewrap_row(
        &self,
        row: &ConfigValueMaintenanceRow,
        raw_key_ref: &str,
        key_ref: KeyRef,
    ) -> Result<RewrapDisposition, ConfigRepoError> {
        let ciphertext = row
            .value_enc
            .as_ref()
            .ok_or_else(|| protection_auth_message("encrypted config value missing ciphertext"))?;
        if row.value.is_some() {
            return Err(protection_auth_message(
                "encrypted config value has plaintext",
            ));
        }
        let aad = config_value_maintenance_aad(&self.capability, row.tenant, &row.key)?;
        let encrypted = self
            .protection
            .key_provider
            .rewrap(RedactedBytes::new(ciphertext.clone()), key_ref, aad)
            .await
            .map_err(key_provider_error)?;
        let new_key_ref = encrypted.key().to_token();
        if encrypted.ciphertext() == ciphertext.as_slice() && new_key_ref == raw_key_ref {
            return Ok(RewrapDisposition::Unchanged);
        }
        let done = sqlx::query(
            r#"
            UPDATE config_entries
            SET value_enc = $4, key_id = $5
            WHERE tenant_id = $1::uuid
              AND config_key = $2
              AND version = $3
              AND protection_scheme = 1
              AND value_enc = $6
              AND key_id = $7
            "#,
        )
        .bind(&row.tenant_id)
        .bind(&row.config_key)
        .bind(row.version)
        .bind(encrypted.ciphertext())
        .bind(new_key_ref)
        .bind(ciphertext)
        .bind(raw_key_ref)
        .execute(&self.store.pool)
        .await
        .map_err(storage)?;
        if done.rows_affected() == 1 {
            Ok(RewrapDisposition::Rewrapped)
        } else {
            Ok(RewrapDisposition::Unchanged)
        }
    }

    async fn remaining_plaintext(&self, tenant: Option<TenantId>) -> Result<u64, ConfigRepoError> {
        let count: i64 = if let Some(tenant) = tenant {
            sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM config_entries \
                 WHERE protection_scheme = 0 AND tenant_id = $1::uuid",
            )
            .bind(tenant_param(tenant))
            .fetch_one(&self.store.pool)
            .await
            .map_err(storage)?
        } else {
            sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0",
            )
            .fetch_one(&self.store.pool)
            .await
            .map_err(storage)?
        };
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

enum RewrapDisposition {
    Rewrapped,
    Unchanged,
}

impl ConfigRepo for PgConfigRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 活跃值 = 最高版本行且非 tombstone（latest 为 tombstone ⇒ 已删 None）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned，不借连接）；hydrate_active 在 tx 外执行。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();

        let row = self
            .pool
            .read(scope, move |conn| {
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
        scope: TenantRepoScope,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 读闭包内仅 SQL fetch 返回 Option<PgRow>（owned）；hydrate_active 在 tx 外执行。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();
        let version_i = version_param(version);

        let row = self
            .pool
            .read(scope, move |conn| {
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

    async fn head(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigHead>, ConfigRepoError> {
        let tenant = scope.tenant();
        // 经 tenant_scoped_read 注入 SET LOCAL，与 0009 迁移的 RLS policy current_setting 对齐（#1298）。
        // 真实最高版本（含 tombstone）；max() 对空集返 NULL（fetch_one 恒一行）。
        // rss_app 角色下 RLS 过滤后 max() 仅对当前 tenant 行计算（否则无 SET LOCAL 时 rss_app 下所有行不可见
        // → max() 返 NULL，后续版本序列断裂）——此为 tenant_scoped_read 覆盖 latest_version 的关键理由。
        let tenant_uuid = tenant_param(tenant);
        let key_str = key.as_str().to_owned();
        let tenant_uuid_q = tenant_uuid.clone();

        let row: Option<(i64, bool)> = self
            .pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT version, deleted FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 ORDER BY version DESC LIMIT 1",
                    )
                    .bind(tenant_uuid_q)
                    .bind(key_str)
                    .fetch_optional(&mut *conn)
                    .await
                })
            })
        .await
        .map_err(storage)?;
        row.map(|(version, deleted)| {
            let version =
                u64::try_from(version).map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
            Ok(if deleted {
                ConfigHead::Deleted(version)
            } else {
                ConfigHead::Active(version)
            })
        })
        .transpose()
    }
}

impl ConfigUnitOfWork for PgConfigRepo {
    async fn commit(
        &self,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        let tenant = scope.tenant();
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subjectId，FR-020；同 PgSessionLifecycle）。
        // `contract` 契约派生绑定（#1193），routing 列经 `domain()`/`contract_id()` 取。reserved key occurred_at
        // 由 `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1：settings 生产 outbox 路径补齐
        // occurred_at；漏接编译期不可表达）。
        let (contract, env_tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        if env_tenant != tenant {
            return Err(tenant_mismatch_storage_error("config co-tx"));
        }
        if mutation.tenant() != tenant {
            return Err(tenant_mismatch_storage_error("config co-tx mutation"));
        }
        let encoded = match &mutation {
            ConfigMutation::Put(entry) => self.encode_value(tenant, entry).await?,
            ConfigMutation::Delete(tombstone) => {
                self.encode_value_bytes(tenant, tombstone.key(), b"")
                    .await?
            }
        };
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        // co-tx：CAS 配置写 + outbox append 同事务（OUTBOX-COTX-CONFIG-01）。CAS 冲突 → VersionConflict 使整
        // 事务回滚（outbox 不落库）；storage 失败 → Storage。
        run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |_attempt| {
                let mutation = mutation.clone();
                let encoded = encoded.clone();
                let outbox_entry = outbox_entry.clone();
                let env = env.clone();
                #[cfg(all(test, feature = "integration"))]
                record_config_retry_attempt(mutation.key());
                async move {
                    self.pool
                        .retry_co_tx_with_outbox(
                            scope,
                            &outbox_entry,
                            &env,
                            move |conn| {
                                Box::pin(async move {
                                    match &mutation {
                                        ConfigMutation::Put(entry) => {
                                            cas_insert(conn.conn(), tenant, entry, &encoded)
                                                .await?;
                                        }
                                        ConfigMutation::Delete(tombstone) => {
                                            cas_insert_tombstone(
                                                conn.conn(),
                                                tenant,
                                                tombstone,
                                                &encoded,
                                            )
                                            .await?;
                                        }
                                    }
                                    #[cfg(all(test, feature = "integration"))]
                                    maybe_fail_config_retry(mutation.key())?;
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
