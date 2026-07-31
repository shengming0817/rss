//! settings 应用层：版本化配置 CRUD/CAS + 发布/回滚（L2 OutboxFact）+ feature flag 求值编排。
//!
//! 配置写入路径证明 L2 接缝：CAS upsert 新版本 + outbox append 经 [`crate::ports::ConfigUnitOfWork`]
//! **同事务**原子落库（both-or-neither，消除 emit-after-save 的 write-without-event 窗口，#1232；in-mem 共享
//! store 替身 / 生产 postgres `PgConfigUnitOfWork`）→ 返回新版本。读路径（next_version / get_config /
//! rollback 源值）经 [`crate::ports::ConfigRepo`]。发布与回滚复用同一 fact，`changeKind` 判别（published /
//! rolledBack）。flag 求值经域内
//! [`crate::internal::ports::FlagStore`] 取快照 + `domain::evaluate_flag`（L0 纯计算）。
//!
//! HTTP 接缝（#1430 PERSIST-009 settings 首条 durable module 闭环）：[`SettingsDomain`] 持 config + secret
//! 应用服务，`init` 经 typed `route_group::<Primary>` + `GeneratedPrimaryEndpoint`（#1690
//! atomic evidence/handler funnel）从 generated SPEC 挂 config publish/get/delete/rollback、secret-publish
//! 与 secret-resolve 六条认证路由（鉴权 = permission，租户来自 route gate 注入的
//! [`httpserve::AuthorizedSubject`]、非 pre-auth header）。
//! 域错误经 `vocab::CoreErrorKind` 映射状态码；CAS 与 outbox 事实冲突分别具有可重试/终止 wire 分类。
//!
//! ref: Unleash/unleash-types-rs src/client_features.rs@main（flag 求值语义）
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型）
//! ref: crates/identity/src/application.rs（generated ReviewedEvent + domain UoW 范式）

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ::generated::http::settings_v1::{
    PRODUCER as CONFIG_HTTP_PRODUCER, SPEC as CONFIG_HTTP_SPEC, SettingsConfigPublishData,
    SettingsConfigPublishRequest, SettingsConfigPublishResponse,
};
use ::generated::http::settings_v2::ROUTE as SECRET_HTTP_ROUTE;
#[cfg(test)]
use ::generated::http::settings_v2::SPEC as SECRET_HTTP_SPEC;
use ::generated::http::settings_v4::{
    ROUTE as CONFIG_GET_HTTP_ROUTE, SPEC as CONFIG_GET_HTTP_SPEC, SettingsConfigGetData,
    SettingsConfigGetResponse,
};
use ::generated::http::settings_v5::{
    PRODUCER as CONFIG_DELETE_PRODUCER, SPEC as CONFIG_DELETE_HTTP_SPEC,
};
use ::generated::http::settings_v6::{
    PRODUCER as CONFIG_ROLLBACK_PRODUCER, SPEC as CONFIG_ROLLBACK_HTTP_SPEC,
    SettingsConfigRollbackData, SettingsConfigRollbackRequest, SettingsConfigRollbackResponse,
};
use ::generated::http::settings_v7::ROUTE as SECRET_RESOLVE_HTTP_ROUTE;
#[cfg(test)]
use ::generated::http::settings_v7::SPEC as SECRET_RESOLVE_HTTP_SPEC;
use ::httpserve::{
    AuthorizedSubject, ContractMarker, GeneratedPrimaryEndpoint, Primary, ProducerMarker,
};
use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::routing::{delete, get, post};
use bootstrap::{KernelError, ReconcileSubscriberOwner, SubscriberCapability};
#[cfg(test)]
use consistency::EventEntry;
use consistency::{
    EngineError, EngineErrorKind, HandleResult, IdemKey, PermanentError, PermanentErrorKind,
};
#[cfg(test)]
use diport::OutboxEnvelopeParts;
use diport::{Clock, EnvelopeSubjectId, Message, OpaqueActorId, OutboxActor};
use eventexec::event::{EventEncodeError, GeneratedEventEncoder, ReviewedEvent};
use generated::event::settings_v1::{
    self as version_changed, SPEC as VERSION_CHANGED_SPEC, SettingsConfigChangeKind,
    SettingsConfigVersionChangedPayload,
};
#[cfg(test)]
use generated::event::{SubscriptionEffect, SubscriptionExecution};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use vocab::{CoreError, CoreErrorKind, TenantId};

use crate::secret_application::{
    SecretPublishState, SecretResolveState, secret_publish_handler, secret_resolve_handler,
};

use crate::domain::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepoError, ConfigTombstone, ConfigValue,
    ConfigVersion, EvalContext, FlagDecision, FlagKey, SettingKey, SettingsError, evaluate_flag,
};
#[cfg(any(test, feature = "seed-data"))]
use crate::internal::mem::{
    InMemConfigRepo, InMemConfigUnitOfWork, InMemFlagStore, new_config_store,
};
use crate::internal::ports::FlagStore;
use crate::ports::{
    ConfigDeleteReceipt, ConfigPublishReceipt, ConfigRepo, ConfigRollbackReceipt, ConfigUnitOfWork,
    DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo, DynSecretUnitOfWork, TenantRepoScope,
};

/// 配置路由组前缀（Primary listener，业务 API）。
pub const SETTINGS_ROUTE_PREFIX: &str = "/api/v1/settings";
#[cfg(test)]
const SETTINGS_DOMAIN: &str = "settings";

type ConfigCacheKey = (TenantId, String);

#[derive(Default)]
struct ConfigCache {
    entries: Mutex<HashMap<ConfigCacheKey, ConfigEntry>>,
}

impl ConfigCache {
    fn find(&self, tenant: TenantId, key: &SettingKey) -> Option<ConfigEntry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.get(&(tenant, key.as_str().to_string())).cloned()
    }

    fn upsert(&self, entry: ConfigEntry) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.insert((entry.tenant(), entry.key().as_str().to_string()), entry);
    }

    fn remove(&self, tenant: TenantId, key: &SettingKey) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(&(tenant, key.as_str().to_string()));
    }
}

/// Read-only state for `settings.config-get`.
///
/// The state owns only the tenant-scoped read repository and its correctness-preserving cache. It
/// cannot reach the config UoW, outbox append, flag mutation, clock, or secret write capability.
#[derive(Clone)]
pub struct ConfigQueryService {
    configs: Arc<DynConfigRepo<'static>>,
    cache: Arc<ConfigCache>,
}

impl ConfigQueryService {
    fn new(configs: Arc<DynConfigRepo<'static>>, cache: Arc<ConfigCache>) -> Self {
        Self { configs, cache }
    }

    /// Read the active value for a key, returning `None` for absent or deleted values.
    ///
    /// The authoritative head is checked before consulting the cache, so delayed subscriber
    /// delivery cannot make this query return stale data.
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn get_config(
        &self,
        tenant: TenantId,
        key: &str,
    ) -> Result<Option<ConfigEntry>, SettingsServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let key = SettingKey::parse(key)?;
        let head = match self.configs.head(scope, &key).await {
            Ok(head) => head,
            Err(error) => {
                self.cache.remove(tenant, &key);
                return Err(error.into());
            }
        };
        let active_version = match head {
            Some(ConfigHead::Active(version)) => {
                if let Some(entry) = self.cache.find(tenant, &key)
                    && entry.tenant() == tenant
                    && entry.key() == &key
                    && entry.version() == version
                {
                    return Ok(Some(entry));
                }
                version
            }
            Some(ConfigHead::Deleted(_)) | None => {
                self.cache.remove(tenant, &key);
                return Ok(None);
            }
        };
        let entry = match self.configs.find_version(scope, &key, active_version).await {
            Ok(entry) => entry,
            Err(error) => {
                self.cache.remove(tenant, &key);
                return Err(error.into());
            }
        };
        let Some(entry) = entry else {
            self.cache.remove(tenant, &key);
            return Err(SettingsServiceError::ConfigReadIntegrity);
        };
        if entry.tenant() != tenant || entry.key() != &key || entry.version() != active_version {
            self.cache.remove(tenant, &key);
            return Err(SettingsServiceError::ConfigReadIntegrity);
        }
        self.cache.upsert(entry.clone());
        Ok(Some(entry))
    }

    /// Rebuild the local config cache from the authoritative read repository.
    ///
    /// This method deliberately lives on the read-only query capability: a reconcile subscriber
    /// cannot reach the settings write UoW, outbox emitter, flag store, clock, or secret ports.
    async fn handle_config_version_changed_event(
        &self,
        event: ConfigVersionChangedEvent,
    ) -> HandleResult {
        match self
            .apply_config_version_changed(event.tenant, event.key, event.version, event.change_kind)
            .await
        {
            Ok(()) => HandleResult::ack(),
            Err(error) => HandleResult::requeue(error),
        }
    }

    async fn apply_config_version_changed(
        &self,
        tenant: TenantId,
        key: SettingKey,
        version: u64,
        change_kind: SettingsConfigChangeKind,
    ) -> Result<(), EngineError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let latest = self
            .configs
            .head(scope, &key)
            .await
            .map_err(|_| config_refresh_error())?;
        match latest {
            Some(current) if current.version() > version => {
                let current = self
                    .configs
                    .find(scope, &key)
                    .await
                    .map_err(|_| config_refresh_error())?;
                match current {
                    Some(entry) => self.cache.upsert(entry),
                    None => self.cache.remove(tenant, &key),
                }
                return Ok(());
            }
            Some(current) if current.version() < version => {
                return Err(config_refresh_error());
            }
            Some(ConfigHead::Deleted(_)) if change_kind == SettingsConfigChangeKind::Deleted => {
                self.cache.remove(tenant, &key);
                return Ok(());
            }
            Some(ConfigHead::Active(_)) if change_kind == SettingsConfigChangeKind::Deleted => {
                return Err(config_refresh_error());
            }
            Some(ConfigHead::Deleted(_)) => {
                return Err(config_refresh_error());
            }
            Some(ConfigHead::Active(_)) => {}
            None => {
                return Err(config_refresh_error());
            }
        }

        let entry = self
            .configs
            .find_version(scope, &key, version)
            .await
            .map_err(|_| config_refresh_error())?
            .ok_or_else(config_refresh_error)?;
        self.cache.upsert(entry);
        Ok(())
    }
}

impl httpserve::ClassifiedRouteState for ConfigQueryService {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

/// settings 应用层错误。库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SettingsServiceError {
    /// 配置 / flag 键格式非法。
    #[error("setting key is invalid")]
    InvalidKey,
    /// 乐观并发写冲突（读后被并发版本超前）。
    #[error("version conflict")]
    VersionConflict,
    /// 同一 event id 已绑定到不同稳定事实；与配置 CAS 冲突分轨。
    #[error("outbox fact conflict")]
    OutboxFactConflict(#[source] consistency::OutboxFactConflict),
    /// 目标配置 / 版本不存在（回滚源缺失）。
    #[error("config entry not found")]
    NotFound,
    /// 权威 active head 与读取条目的 tenant / key / version 不一致，或条目缺失。
    #[error("config read integrity check failed")]
    ConfigReadIntegrity,
    /// 灰度百分比超出 0..=100 范围。
    #[error("percentage out of range; must be 0..=100")]
    PercentageOutOfRange,
    /// config-version-changed payload 编码失败（原始错误进 source，不进 Display）。
    #[error("config-version-changed payload encode failed")]
    PayloadEncode(#[source] EventEncodeError),
    /// Reviewed envelope subject identity is invalid.
    #[error("config-version-changed envelope identity validation failed")]
    EnvelopeIdentity(#[source] diport::EnvelopeIdentityError),
    /// Stable event idempotency identity is invalid.
    #[error("config-version-changed idempotency identity validation failed")]
    IdempotencyKey(#[source] consistency::IdemKeyError),
    /// 底层存储失败（配置写 / 同事务 outbox append 持久化错误；原始错误进 source，不进 Display/wire）。
    #[error("config storage failed")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// 配置值保护 provider 不可用（KMS/KeyProvider 暂不可用或配置拒绝）。
    #[error("config value protection unavailable")]
    ProtectionUnavailable(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// 配置值保护认证失败（AAD mismatch / 坏密文 / envelope 损坏）。
    #[error("config value protection authentication failed")]
    ProtectionAuthFailure(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<SettingsError> for SettingsServiceError {
    fn from(error: SettingsError) -> Self {
        match error {
            // 敏感 key 拒绝与格式非法同属 4xx 客户端键错误（域层保留 SensitiveKey 具体语义供日志/诊断）。
            SettingsError::KeyInvalid | SettingsError::SensitiveKey => Self::InvalidKey,
            SettingsError::PercentageOutOfRange => Self::PercentageOutOfRange,
            // secret 键 / 引用格式错误：同属 4xx 客户端输入错误（secret path 不走 config service 处理路径，
            // 此分支为 From impl 穷举完整性守卫，不应在 config 发布流程中命中）。
            SettingsError::SecretKeyInvalid | SettingsError::SecretRefInvalid => Self::InvalidKey,
        }
    }
}

impl From<ConfigRepoError> for SettingsServiceError {
    fn from(error: ConfigRepoError) -> Self {
        match error {
            // 业务：乐观并发 CAS 冲突（读后重写重试可恢复）。
            ConfigRepoError::VersionConflict => Self::VersionConflict,
            ConfigRepoError::OutboxFactConflict(source) => Self::OutboxFactConflict(source),
            ConfigRepoError::ProtectionUnavailable(source) => Self::ProtectionUnavailable(source),
            ConfigRepoError::ProtectionAuthFailure(source) => Self::ProtectionAuthFailure(source),
            // 基础设施：保留 source 链（adapter 已 redact 日志；5xx 时 wire strip）。
            ConfigRepoError::Storage(source) => Self::Storage(source),
        }
    }
}

/// `SystemTime` → UNIX epoch 秒（i64）。负偏移收口为 0；溢出收口为 `i64::MAX`。不取系统时钟（经注入 [`Clock`]）。
fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        // reason: 时钟早于 UNIX_EPOCH（容器时间错误）→ 收口 0，不 panic
        .unwrap_or(0)
}

/// u64 版本号 → wire i64（溢出收口 `i64::MAX`）。config / secret handler 共用。
pub(crate) fn wire_version(version: u64) -> i64 {
    i64::try_from(version).unwrap_or(i64::MAX)
}

/// 不透明 flag 仓储封装（newtype funnel，Hard）。
///
/// `FlagStore` trait 保持 `pub(crate)`；外部组合根经 [`crate::empty_flag_store`] 构造此 box，
/// 再传给 [`SettingsService::with_postgres`]——无需在外部 crate 命名 `FlagStore` trait。
pub struct FlagStoreBox(pub(crate) Box<dyn FlagStore>);

#[derive(Debug, thiserror::Error)]
pub enum ConfigVersionChangedEventError {
    #[error("config-version-changed payload decode failed")]
    Decode(#[source] serde_json::Error),
    #[error("config-version-changed tenant parse failed")]
    Tenant(#[source] vocab::TenantIdError),
    #[error("config-version-changed key parse failed")]
    Key(#[source] SettingsError),
    #[error("config-version-changed version is negative")]
    NegativeVersion,
}

/// Parsed `settings.config-version-changed` payload in domain-ready form.
pub struct ConfigVersionChangedEvent {
    tenant: TenantId,
    key: SettingKey,
    version: u64,
    change_kind: SettingsConfigChangeKind,
}

impl ConfigVersionChangedEvent {
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn change_kind(&self) -> SettingsConfigChangeKind {
        self.change_kind
    }
}

/// Decode the generated settings event payload into domain-ready typed values.
pub fn config_version_changed_event_from_message(
    message: &Message,
) -> Result<ConfigVersionChangedEvent, ConfigVersionChangedEventError> {
    let payload: SettingsConfigVersionChangedPayload =
        serde_json::from_slice(message.payload.as_bytes())
            .map_err(ConfigVersionChangedEventError::Decode)?;
    let tenant =
        TenantId::parse(&payload.tenant_id).map_err(ConfigVersionChangedEventError::Tenant)?;
    let key = SettingKey::parse(&payload.key).map_err(ConfigVersionChangedEventError::Key)?;
    let version = u64::try_from(payload.version)
        .map_err(|_| ConfigVersionChangedEventError::NegativeVersion)?;
    Ok(ConfigVersionChangedEvent {
        tenant,
        key,
        version,
        change_kind: payload.change_kind,
    })
}

/// settings 应用服务。必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）。
///
/// 读路径经 [`ConfigRepo`]（`configs`）；写路径（publish / rollback）经 **co-tx** [`ConfigUnitOfWork`]
/// （`writer`）——CAS 配置写 + outbox append 同事务原子（#1232），消除「先 save 后 emit」write-without-event
/// 窗口（旧 emitter 字段已删除，发射收口进 `writer`）。
pub struct SettingsService {
    query: ConfigQueryService,
    writer: Box<DynConfigUnitOfWork<'static>>,
    flags: Box<dyn FlagStore>,
    clock: Box<dyn Clock>,
}

impl SettingsService {
    /// 生产构造器（非门控 `pub`，组合根注入真实 postgres provider）。
    ///
    /// `flags` 为域内 `FlagStore` newtype，经 [`crate::empty_flag_store`] 构造后传入；
    /// `clock` 是构造器位置参（rust-standards §Clock 构造器位置参），生产传 `SystemClock`。
    ///
    /// `flags` 类型使用不透明封装 [`FlagStoreBox`]——调用方无需知道 `FlagStore` trait（`pub(crate)`）。
    pub fn with_postgres(
        configs: Box<DynConfigRepo<'static>>,
        writer: Box<DynConfigUnitOfWork<'static>>,
        flags: FlagStoreBox,
        clock: Box<dyn Clock>,
    ) -> Self {
        let configs = Arc::from(configs);
        let cache = Arc::new(ConfigCache::default());
        Self {
            query: ConfigQueryService::new(configs, cache),
            writer,
            flags: flags.0,
            clock,
        }
    }

    /// 组合根构造：注入 outbox emitter + clock，以空 in-mem 配置 / flag 仓储初始化（追踪弹 / demo）。
    ///
    /// 门控于 `test` / `seed-data` feature（编译期边界，对标 identity seed-login）：生产组合根不启用即无
    /// in-mem provider 路径。组合根（journeys）经 `settings = { features = ["seed-data"] }` 启用 + 注入
    /// `memory::MemEmitter`。读端口 [`InMemConfigRepo`] 与写 UoW [`InMemConfigUnitOfWork`] 经 `Arc` **共享同一
    /// store**——`find` 读得到 `commit` 写入。真实持久化（postgres adapter）留 Join。
    ///
    /// `emitter` 取**具体** [`diport::OutboxEmitter`] 类型（非 `Box<DynOutboxEmitter>`）：in-mem co-tx UoW 须
    /// `Sync`（`ConfigUnitOfWork: Send` 端口），dyn wrapper 仅 `Send`；组合根（journey）传 `memory::MemEmitter`
    /// （`Arc` 底座，`Sync`）。详见 [`InMemConfigUnitOfWork`]。
    #[cfg(any(test, feature = "seed-data"))]
    pub fn with_seed<E>(emitter: E, clock: Box<dyn Clock>) -> Self
    where
        E: diport::OutboxEmitter + Send + Sync + 'static,
    {
        let store = new_config_store();
        Self::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, emitter)),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            clock,
        )
    }

    /// Return the narrow read-only state used by the LocalOnly config query route.
    #[must_use]
    pub fn config_query_service(&self) -> ConfigQueryService {
        self.query.clone()
    }

    /// 当前 key 的下一版本号（无历史 → 1）。
    async fn next_version(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<u64, SettingsServiceError> {
        // 真实最高版本（含 tombstone）+ 1——delete 软删后 version 单调不重置，防 event_id 复用（#1249 F1）。
        // 用 `head` 而非 `find`：`find` 排除 tombstone，删后返 `None` 会误回 v1 → 复用旧 event_id。
        let current = self.query.configs.head(scope, key).await?;
        Ok(current.map_or(1, |head| head.version().saturating_add(1)))
    }

    /// 经 generated sealed carrier 构造 `config-version-changed` [`ReviewedEvent`]（纯派生，无 I/O）；实际落
    /// durable outbox 与配置写**同事务**由 route-specific [`ConfigUnitOfWork`] 方法承载（L2 OutboxFact）。
    ///
    /// EventId（outbox `event_id` / `IdemKey`）= 内容派生 `{topic}:{tenant}:{key}:v{version}`：每个
    /// (tenant, key, version) 仅一次发射（version 单调递增，publish/rollback 各产新版本），故按内容确定唯一——
    /// 重试同版本产同锚点，经 relay 盖章 broker message_id 流回消费侧实现「至少一次 + 幂等」端到端去重（#1100）。
    /// tenant 是可观测标识（非凭据，ADR-002）；key 是 opaque 配置标识（非 value，无 secret）。
    async fn build_version_changed_entry(
        &self,
        key: &SettingKey,
        tenant: TenantId,
        actor: OutboxActor,
        version: u64,
        change_kind: SettingsConfigChangeKind,
        source_version: Option<u64>,
    ) -> Result<ReviewedEvent, SettingsServiceError> {
        let payload = SettingsConfigVersionChangedPayload {
            change_kind,
            key: key.as_str().to_string(),
            occurred_at: unix_secs(self.clock.now()),
            source_version: source_version.map(wire_version),
            tenant_id: tenant.to_string(),
            version: wire_version(version),
        };
        let event_id = format!(
            "{}:{tenant}:{}:v{version}",
            VERSION_CHANGED_SPEC.topic(),
            key.as_str()
        );
        // 契约归属经 generated `CONTRACT`（domain + contract_id + version + schema_hash 同源绑定，#1193/#1618）；
        // subject = opaque 配置 key。
        let subject_id = EnvelopeSubjectId::from_opaque(key.as_str())
            .map_err(SettingsServiceError::EnvelopeIdentity)?;
        version_changed::emit(
            &GeneratedEventEncoder,
            payload,
            tenant,
            subject_id,
            actor,
            IdemKey::parse(&event_id).map_err(SettingsServiceError::IdempotencyKey)?,
        )
        .await
        .map_err(SettingsServiceError::PayloadEncode)
    }

    /// 写入新配置版本并发射 outbox fact（L2 OutboxFact）。CAS：读当前版本 → 写 +1；并发冲突冒泡 `VersionConflict`。
    ///
    /// `skip_all`：不记 `value`（可能含 secret）/ `key`；失败经 `err` 记 [`SettingsServiceError`] Display（无 PII）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn publish_config(
        &self,
        receipt: ConfigPublishReceipt,
        tenant: TenantId,
        actor: OutboxActor,
        request: SettingsConfigPublishRequest,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let key = SettingKey::parse(&request.key)?;
        let version = self.next_version(scope, &key).await?;
        let entry = ConfigEntry::new(
            key.clone(),
            ConfigValue::new(request.value),
            tenant,
            ConfigVersion::new(version),
        );
        let event = self
            .build_version_changed_entry(
                &key,
                tenant,
                actor,
                version,
                SettingsConfigChangeKind::Published,
                None,
            )
            .await?;
        // co-tx：CAS 配置写 + outbox append 同事务（both-or-neither）——冲突冒泡 `VersionConflict`，
        // 存储失败冒泡 `Storage`；二者皆使配置写与 outbox 行共回滚（消除 write-without-event 窗口）。
        self.writer
            .commit_publish(receipt, scope, ConfigMutation::Put(entry.clone()), event)
            .await?;
        self.query.cache.upsert(entry);
        Ok(SettingsConfigPublishResponse {
            data: SettingsConfigPublishData {
                key: key.as_str().to_string(),
                version: wire_version(version),
            },
        })
    }

    /// 回滚：以 `to_version` 的值生成新版本并发射（`changeKind=rolledBack`，`sourceVersion=to_version`）。
    ///
    /// `skip_all` + 仅 `tenant` field（与 `publish_config` 一致，不记 `key`/`value`，统一可观测安全策略）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn rollback(
        &self,
        receipt: ConfigRollbackReceipt,
        tenant: TenantId,
        actor: OutboxActor,
        key: &str,
        to_version: u64,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let key = SettingKey::parse(key)?;
        let source = self
            .query
            .configs
            .find_version(scope, &key, to_version)
            .await?
            .ok_or(SettingsServiceError::NotFound)?;
        let value = ConfigValue::new(source.value());
        let version = self.next_version(scope, &key).await?;
        let entry = ConfigEntry::new(key.clone(), value, tenant, ConfigVersion::new(version));
        let event = self
            .build_version_changed_entry(
                &key,
                tenant,
                actor,
                version,
                SettingsConfigChangeKind::RolledBack,
                Some(to_version),
            )
            .await?;
        // co-tx：回滚新版本写 + outbox append 同事务（both-or-neither）。源值（`find_version` 读历史行）
        // 不可变无 TOCTOU；新版本号（`next_version`）存在 read-then-write 窗口，由 CAS INSERT 守住——并发
        // 冲突返 `VersionConflict`，调用方读后重写重试。
        self.writer
            .commit_rollback(receipt, scope, ConfigMutation::Put(entry.clone()), event)
            .await?;
        self.query.cache.upsert(entry);
        Ok(SettingsConfigPublishResponse {
            data: SettingsConfigPublishData {
                key: key.as_str().to_string(),
                version: wire_version(version),
            },
        })
    }

    /// 软删除 key（tombstone，幂等）：仓储在 `max+1` 追加 tombstone 版本 → version 单调不重置（防 event_id
    /// 复用，#1249 F1）；此后 `get_config` 返回 `None`，历史值仍可 `find_version` 读。
    ///
    /// tombstone 与 `changeKind=deleted` 的版本变更事实经同一个 UoW 原子提交；幂等 no-op 也会清除
    /// 本实例缓存，避免其它实例已删除而当前实例仍返回旧值。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn delete(
        &self,
        receipt: ConfigDeleteReceipt,
        tenant: TenantId,
        actor: OutboxActor,
        key: &str,
    ) -> Result<(), SettingsServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let key = SettingKey::parse(key)?;
        let current = match self.query.configs.head(scope, &key).await? {
            Some(ConfigHead::Active(current)) => current,
            Some(ConfigHead::Deleted(_)) | None => {
                self.query.cache.remove(tenant, &key);
                return Ok(());
            }
        };
        let version = current.saturating_add(1);
        let mutation = ConfigMutation::Delete(ConfigTombstone::new(
            key.clone(),
            tenant,
            ConfigVersion::new(version),
        ));
        let event = self
            .build_version_changed_entry(
                &key,
                tenant,
                actor,
                version,
                SettingsConfigChangeKind::Deleted,
                None,
            )
            .await?;
        match self
            .writer
            .commit_delete(receipt, scope, mutation, event)
            .await
        {
            Ok(()) => {}
            Err(ConfigRepoError::VersionConflict)
                if matches!(
                    self.query.configs.head(scope, &key).await?,
                    Some(ConfigHead::Deleted(_))
                ) => {}
            Err(error) => return Err(error.into()),
        }
        self.query.cache.remove(tenant, &key);
        Ok(())
    }

    /// 求值 flag 对给定上下文是否启用（L0 纯计算）。未知 flag → `false`（fail-closed）。
    ///
    /// 返回 bool 为当前 interim 形态；如需决策详情（命中规则/桶/stale）GA 前可升结构化返回（见 follow-up）。
    pub fn is_flag_enabled(
        &self,
        tenant: TenantId,
        flag_key: &str,
        attrs: &[(&str, &str)],
    ) -> Result<bool, SettingsServiceError> {
        let key = FlagKey::parse(flag_key)?;
        let Some(state) = self.flags.find(tenant, &key) else {
            return Ok(false);
        };
        let owned: Vec<(String, String)> = attrs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        Ok(evaluate_flag(&state, &EvalContext::new(&owned)) == FlagDecision::Enabled)
    }
}

fn config_refresh_error() -> EngineError {
    EngineError::new(EngineErrorKind::Transient)
}

// ---------------------------------------------------------------------------
// HTTP handler / route 装配（config-publish；secret-publish 在 secret_application）
// ---------------------------------------------------------------------------

/// config publish 请求体上界（防御性 body 限额，对标 identity `MAX_LOGIN_BODY_BYTES`）。
const MAX_CONFIG_BODY_BYTES: usize = 64 * 1024;

/// 取请求注入的 request id（中间件注入；缺失回退 `"unknown"`）。
pub(crate) fn request_id_from(req: &Request<Body>) -> String {
    httpserve::request_id_str(req.extensions())
        .unwrap_or("unknown")
        .to_string()
}

/// 认证拒因（small；避免 `Result<_, Response>` 触 clippy `result_large_err`——`Response` ≥128B）。
/// config / secret handler 共用，经 [`AuthReject::into_response`] 落地。
pub(crate) enum AuthReject {
    /// 无 [`AuthorizedSubject`] 证据（fail-closed；正常经 primary route gate 后必有，缺失即框架接线异常）→ 401。
    Unauthenticated,
    /// 授权证据无法派生 outbox actor（认证主体与 envelope actor 约束不一致；接线/issuer invariant）。
    InvalidActor,
}

impl AuthReject {
    pub(crate) fn into_response(self, request_id: &str) -> Response {
        match self {
            AuthReject::Unauthenticated => httpserve::error::unauthenticated(request_id),
            AuthReject::InvalidActor => httpserve::error::internal_error(request_id),
        }
    }
}

/// 从 route gate 授权证据取租户（post-auth/post-authz 单源，对标零信任）。**不读** pre-auth
/// `X-Tenant-ID` header，也不回读 [`httpserve::Authenticated`]。
pub(crate) fn authenticated_tenant(req: &Request<Body>) -> Result<TenantId, AuthReject> {
    match req.extensions().get::<AuthorizedSubject>() {
        None => Err(AuthReject::Unauthenticated),
        Some(auth) => Ok(auth.tenant_id()),
    }
}

pub(crate) fn authenticated_tenant_scope(
    req: &Request<Body>,
) -> Result<TenantRepoScope, AuthReject> {
    authenticated_tenant(req).map(TenantRepoScope::from_authenticated_tenant)
}

fn authenticated_actor(
    req: &Request<Body>,
    spec: &::generated::http::HttpSpec,
) -> Result<(TenantId, OutboxActor), AuthReject> {
    let auth = req
        .extensions()
        .get::<AuthorizedSubject>()
        .ok_or(AuthReject::Unauthenticated)?;
    let tenant = auth.tenant_id();
    let actor_id = OpaqueActorId::from_opaque(auth.principal_id()).map_err(|err| {
        tracing::error!(
            error = %err,
            tenant_id = %tenant,
            principal_kind = ?auth.principal_kind(),
            contract_id = spec.route.contract_id(),
            "settings authorized subject cannot be represented as outbox actor id"
        );
        AuthReject::InvalidActor
    })?;
    Ok((
        tenant,
        OutboxActor::scoped(
            auth.principal_kind(),
            actor_id,
            tenant,
            vocab::ScopedTenant::Tenant,
        ),
    ))
}

/// `settings.config-publish` handler（Primary listener，JWT 认证）：route gate 授权证据取租户 → parse body →
/// `publish_config`（CAS 写 + outbox co-tx，L2）→ 201。租户来自 `AuthorizedSubject`，非 pre-auth header。
async fn config_publish_handler(
    producer: ProducerMarker<::generated::http::settings_v1::RouteMarker>,
    State(service): State<Arc<SettingsService>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (scope, actor) = match authenticated_actor(&req, &CONFIG_HTTP_SPEC) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let (_, body) = req.into_parts();
    let body = match to_bytes(body, MAX_CONFIG_BODY_BYTES).await {
        Ok(body) => body,
        Err(err) if httpserve::error::body_error_is_length_limit(&err) => {
            return httpserve::error::payload_too_large(&request_id);
        }
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    config_publish_handler_bytes(
        service,
        producer.into_receipt(),
        scope,
        actor,
        body,
        &request_id,
    )
    .await
}

/// config-publish 核心（tenant 已解析）：parse → service → typed 响应 / 错误映射。供单测直接驱动。
pub(crate) async fn config_publish_handler_bytes(
    service: Arc<SettingsService>,
    receipt: ConfigPublishReceipt,
    tenant: TenantId,
    actor: OutboxActor,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: SettingsConfigPublishRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    match service
        .publish_config(receipt, tenant, actor, request)
        .await
    {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => config_error_response(
            &err,
            tenant,
            request_id,
            &CONFIG_HTTP_SPEC,
            "config_publish",
        ),
    }
}

/// `settings.config-get` handler：租户只来自 route gate 的 [`AuthorizedSubject`]；读取先验证权威
/// revision，事件未送达也不会返回 stale cache。
async fn config_get_handler(
    _: ContractMarker<::generated::http::settings_v4::RouteMarker>,
    Path(key): Path<String>,
    State(service): State<ConfigQueryService>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let tenant = match authenticated_tenant(&req) {
        Ok(tenant) => tenant,
        Err(reject) => return reject.into_response(&request_id),
    };
    match service.get_config(tenant, &key).await {
        Ok(Some(entry)) => (
            StatusCode::OK,
            Json(SettingsConfigGetResponse {
                data: SettingsConfigGetData {
                    key: entry.key().as_str().to_string(),
                    value: entry.value().to_string(),
                    version: wire_version(entry.version()),
                },
            }),
        )
            .into_response(),
        Ok(None) => config_error_response(
            &SettingsServiceError::NotFound,
            tenant,
            &request_id,
            &CONFIG_GET_HTTP_SPEC,
            "config_get",
        ),
        Err(error) => config_error_response(
            &error,
            tenant,
            &request_id,
            &CONFIG_GET_HTTP_SPEC,
            "config_get",
        ),
    }
}

/// `settings.config-delete` handler：首次删除提交 tombstone + Deleted fact，已删除/不存在为 204 no-op。
async fn config_delete_handler(
    producer: ProducerMarker<::generated::http::settings_v5::RouteMarker>,
    Path(key): Path<String>,
    State(service): State<Arc<SettingsService>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, actor) = match authenticated_actor(&req, &CONFIG_DELETE_HTTP_SPEC) {
        Ok(context) => context,
        Err(reject) => return reject.into_response(&request_id),
    };
    match service
        .delete(producer.into_receipt(), tenant, actor, &key)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => config_error_response(
            &error,
            tenant,
            &request_id,
            &CONFIG_DELETE_HTTP_SPEC,
            "config_delete",
        ),
    }
}

/// `settings.config-rollback` handler：历史版本值作为新 active version 原子写入并发出 RolledBack fact。
async fn config_rollback_handler(
    producer: ProducerMarker<::generated::http::settings_v6::RouteMarker>,
    Path(key): Path<String>,
    State(service): State<Arc<SettingsService>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, actor) = match authenticated_actor(&req, &CONFIG_ROLLBACK_HTTP_SPEC) {
        Ok(context) => context,
        Err(reject) => return reject.into_response(&request_id),
    };
    let (_, body) = req.into_parts();
    let body = match to_bytes(body, MAX_CONFIG_BODY_BYTES).await {
        Ok(body) => body,
        Err(err) if httpserve::error::body_error_is_length_limit(&err) => {
            return httpserve::error::payload_too_large(&request_id);
        }
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let request: SettingsConfigRollbackRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let source_version = request.to_version.get();
    match service
        .rollback(producer.into_receipt(), tenant, actor, &key, source_version)
        .await
    {
        Ok(response) => (
            StatusCode::CREATED,
            Json(SettingsConfigRollbackResponse {
                data: SettingsConfigRollbackData {
                    key: response.data.key,
                    version: response.data.version,
                    source_version: wire_version(source_version),
                },
            }),
        )
            .into_response(),
        Err(error) => config_error_response(
            &error,
            tenant,
            &request_id,
            &CONFIG_ROLLBACK_HTTP_SPEC,
            "config_rollback",
        ),
    }
}

/// `SettingsServiceError` → wire 响应：generic [`CoreErrorKind`] 派生状态码（4xx 客户端 / 5xx 内部），
/// outbox 事实冲突使用专用、不可重试 kind，其余复用 vocab 通用 kind。5xx 记结构化 error（const message，无 PII；
/// `tenant_id` 是合法低基数可观测字段、非凭据，透传供跨租定位——对标 identity handler 错误日志）。
fn config_error_response(
    err: &SettingsServiceError,
    tenant: TenantId,
    request_id: &str,
    spec: &::generated::http::HttpSpec,
    operation: &'static str,
) -> Response {
    let kind = match err {
        SettingsServiceError::InvalidKey | SettingsServiceError::PercentageOutOfRange => {
            CoreErrorKind::Validation
        }
        SettingsServiceError::VersionConflict => CoreErrorKind::VersionConflict,
        SettingsServiceError::OutboxFactConflict(_) => CoreErrorKind::OutboxFactConflict,
        SettingsServiceError::NotFound => CoreErrorKind::NotFound,
        SettingsServiceError::ConfigReadIntegrity
        | SettingsServiceError::PayloadEncode(_)
        | SettingsServiceError::EnvelopeIdentity(_)
        | SettingsServiceError::IdempotencyKey(_)
        | SettingsServiceError::ProtectionUnavailable(_)
        | SettingsServiceError::ProtectionAuthFailure(_)
        | SettingsServiceError::Storage(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            request_id,
            tenant_id = %tenant,
            contract_id = spec.route.contract_id(),
            operation,
            "settings config operation failed"
        );
    }
    httpserve::error::core_error_response(&CoreError::new(kind), request_id)
}

/// settings 域 bootstrap 生命周期：挂载 config 与 secret publish/resolve 业务路由。
///
/// 持有 config 应用服务 + secret read repo / mutation UoW（构造器必填位置参注入，缺失即编译错误）；
/// `init` 经 typed `route_group::<Primary>` + `GeneratedPrimaryEndpoint` 从 generated SPEC 单源挂六条认证路由
/// （对标 identity `IdentityDomain`）。
///
/// secret-publish State 持 read repo + mutation UoW；secret-resolve State 只持
/// [`crate::SecretResolveService`]（read repo + resolver），因此 LocalOnly read dispatch 无法携带写端口。
///
/// `configs_ready` 探针由组合根（`assemblies/runtime::wire_settings`）经 `DomainModuleResult` 注册——探针包
/// `PgDbReadiness`（adapter 类型，域 crate 不可依赖 adapter），故不在此声明（层序约束）。
pub struct SettingsDomain {
    config: Arc<SettingsService>,
    config_query: ConfigQueryService,
    secret_repo: Arc<DynSecretRepo<'static>>,
    secret_uow: Arc<DynSecretUnitOfWork<'static>>,
    secret_service: Arc<crate::SecretResolveService>,
    http_surface: SettingsHttpSurface,
}

#[derive(Clone, Copy)]
enum SettingsHttpSurface {
    Full,
    ConfigCud,
}

impl SettingsDomain {
    /// 组合根构造：注入 config 应用服务 + secret 仓储端口（已装配域形 repo / UoW provider）。
    pub fn new(
        config: Arc<SettingsService>,
        secret_repo: Arc<DynSecretRepo<'static>>,
        secret_uow: Arc<DynSecretUnitOfWork<'static>>,
        secret_service: Arc<crate::SecretResolveService>,
    ) -> Self {
        let config_query = config.config_query_service();
        Self {
            config,
            config_query,
            secret_repo,
            secret_uow,
            secret_service,
            http_surface: SettingsHttpSurface::Full,
        }
    }

    /// Restrict the mounted HTTP surface to the three durable config mutations.
    ///
    /// The settingsonly assembly consumes this typed choice because its federated permission
    /// universe deliberately excludes config reads and secret operations.
    #[must_use]
    pub fn config_cud_only(mut self) -> Self {
        self.http_surface = SettingsHttpSurface::ConfigCud;
        self
    }
}

fn log_config_version_tenant_mismatch(
    message_id: &str,
    payload_tenant: &TenantId,
    authenticated_tenant: &TenantId,
) {
    tracing::warn!(
        message_id,
        payload_tenant = %payload_tenant,
        authenticated_tenant = %authenticated_tenant,
        "settings config-version tenant mismatch rejected"
    );
}

/// Narrow, read-only reconciler for `settings.config-version-changed`.
///
/// Its only state is [`ConfigQueryService`], whose fields are the owner-defined config read port
/// and cache. It cannot reach [`SettingsService`]'s writer, flag store, clock, or any outbox path.
pub struct ConfigVersionReconciler {
    state: ConfigVersionReconcilerState,
}

enum ConfigVersionReconcilerState {
    Query(ConfigQueryService),
    #[cfg(feature = "test-support")]
    TestAck,
    #[cfg(feature = "test-support")]
    TestRequeue,
}

impl ConfigVersionReconciler {
    fn new(query: ConfigQueryService) -> Self {
        Self {
            state: ConfigVersionReconcilerState::Query(query),
        }
    }

    /// Test-only exact owner capability used by runtime topology tests.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn test_ack() -> Self {
        Self {
            state: ConfigVersionReconcilerState::TestAck,
        }
    }

    /// Test-only exact owner capability that returns a transient reconciliation result.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn test_requeue() -> Self {
        Self {
            state: ConfigVersionReconcilerState::TestRequeue,
        }
    }

    /// Reconcile one authenticated config-version event using only the owner-defined read/cache
    /// capability captured by this opaque concrete type.
    pub fn reconcile(
        &self,
        message: Message,
        authenticated_tenant: TenantId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandleResult> + Send + 'static>> {
        let query = match &self.state {
            ConfigVersionReconcilerState::Query(query) => query.clone(),
            #[cfg(feature = "test-support")]
            ConfigVersionReconcilerState::TestAck => {
                return Box::pin(async { HandleResult::ack() });
            }
            #[cfg(feature = "test-support")]
            ConfigVersionReconcilerState::TestRequeue => {
                return Box::pin(async {
                    HandleResult::requeue(EngineError::new(EngineErrorKind::Transient))
                });
            }
        };
        Box::pin(async move {
            let event = match config_version_changed_event_from_message(&message) {
                Ok(event) => event,
                Err(error) => {
                    tracing::warn!(
                        message_id = message.id.as_str(),
                        error = %secure::redact_error(&error),
                        "settings config-version payload rejected"
                    );
                    return HandleResult::reject(PermanentError::new(
                        PermanentErrorKind::Permanent,
                    ));
                }
            };
            if event.tenant() != authenticated_tenant {
                log_config_version_tenant_mismatch(
                    message.id.as_str(),
                    &event.tenant(),
                    &authenticated_tenant,
                );
                return HandleResult::reject(PermanentError::new(PermanentErrorKind::Invariant));
            }
            query.handle_config_version_changed_event(event).await
        })
    }
}

impl ::bootstrap::Domain for SettingsDomain {
    fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
        let effect = ReconcileSubscriberOwner::from_owner(ConfigVersionReconciler::new(
            self.config_query.clone(),
        ));
        version_changed::subscribe_settings(reg, SubscriberCapability::DomainReconcile(effect))?;

        let config = Arc::clone(&self.config);
        let config_query = self.config_query.clone();
        let secret_state =
            SecretPublishState::new(Arc::clone(&self.secret_repo), Arc::clone(&self.secret_uow));
        let secret_service = SecretResolveState::new(Arc::clone(&self.secret_service));
        let http_surface = self.http_surface;
        reg.route_group::<Primary>(SETTINGS_ROUTE_PREFIX, move |rb| {
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(
                    CONFIG_HTTP_PRODUCER,
                    config_publish_handler,
                )?
                .with_state(Arc::clone(&config)),
            )?;
            if matches!(http_surface, SettingsHttpSurface::ConfigCud) {
                let rb = rb.mount(
                    GeneratedPrimaryEndpoint::new_producer(
                        CONFIG_DELETE_PRODUCER,
                        config_delete_handler,
                    )?
                    .with_state(Arc::clone(&config)),
                )?;
                let rb = rb.mount(
                    GeneratedPrimaryEndpoint::new_producer(
                        CONFIG_ROLLBACK_PRODUCER,
                        config_rollback_handler,
                    )?
                    .with_state(config),
                )?;
                return Ok(rb);
            }
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new(CONFIG_GET_HTTP_ROUTE, config_get_handler)?
                    .with_classified_state(config_query),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(
                    CONFIG_DELETE_PRODUCER,
                    config_delete_handler,
                )?
                .with_state(Arc::clone(&config)),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(
                    CONFIG_ROLLBACK_PRODUCER,
                    config_rollback_handler,
                )?
                .with_state(config),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new(SECRET_HTTP_ROUTE, secret_publish_handler)?
                    .with_state(secret_state),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new(SECRET_RESOLVE_HTTP_ROUTE, secret_resolve_handler)?
                    .with_classified_state(secret_service),
            )?;
            Ok(rb)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use diport::{
        DynSecretResolver, OutboxEmitError, OutboxEmitter, SecretCoordinate, SecretMaterial,
        SecretResolver, SecretResolverError,
    };

    use crate::domain::{FlagState, RolloutPercentage, RolloutRule};

    fn assert_local_read_state<T>()
    where
        T: httpserve::ClassifiedRouteState<
                Effect = diport::ReadEffect,
                Privilege = diport::LocalPrivilege,
            >,
    {
    }

    #[test]
    fn config_query_service_is_local_read_state() {
        assert_local_read_state::<ConfigQueryService>();
    }

    #[test]
    fn secret_resolve_state_is_local_read_state() {
        assert_local_read_state::<SecretResolveState>();
    }

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // 测试 helper：解析已知合法常量 —— expect item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used, clippy::panic)]
    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("canonical uuid")
    }

    #[allow(clippy::expect_used)]
    fn actor() -> OutboxActor {
        OutboxActor::scoped(
            vocab::PrincipalKind::Admin,
            OpaqueActorId::from_opaque("settings-test-actor").expect("opaque actor"),
            tenant(),
            vocab::ScopedTenant::Tenant,
        )
    }

    fn publish_receipt() -> ConfigPublishReceipt {
        ProducerMarker::for_test(CONFIG_HTTP_PRODUCER).into_receipt()
    }

    fn delete_receipt() -> ConfigDeleteReceipt {
        ProducerMarker::for_test(CONFIG_DELETE_PRODUCER).into_receipt()
    }

    fn rollback_receipt() -> ConfigRollbackReceipt {
        ProducerMarker::for_test(CONFIG_ROLLBACK_PRODUCER).into_receipt()
    }

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：OutboxEmitter / Clock 替身在此手写。
    #[derive(Clone, Default)]
    struct CapturingEmitter {
        emitted: Arc<Mutex<Vec<(EventEntry, OutboxEnvelopeParts)>>>,
    }
    impl OutboxEmitter for CapturingEmitter {
        async fn emit(
            &self,
            entry: EventEntry,
            envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            self.emitted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((entry, envelope));
            Ok(())
        }
    }

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn service_with(capture: &CapturingEmitter, flags: InMemFlagStore) -> SettingsService {
        // 读端口与写 UoW 共享同一 store（与 with_seed / postgres 同源一致性）；emitter 取具体
        // `CapturingEmitter`（`Arc` 底座 Sync）满足 co-tx UoW 的 Send/Sync 约束。
        let store = new_config_store();
        SettingsService::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            FlagStoreBox(Box::new(flags)),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        )
    }

    /// 单条发射事实（topic + idem-key + envelope 三元 + 解码 payload），避免依赖 `Entry: Clone`。
    struct EmittedFact {
        topic: String,
        idem: String,
        domain: String,
        contract_id: String,
        subject_id: String,
        payload: SettingsConfigVersionChangedPayload,
    }

    #[allow(clippy::expect_used)]
    fn emitted_facts(capture: &CapturingEmitter) -> Vec<EmittedFact> {
        capture
            .emitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(entry, env)| EmittedFact {
                topic: entry.topic().as_str().to_string(),
                idem: entry.idem_key().as_str().to_string(),
                domain: env.contract().domain().to_string(),
                contract_id: env.contract().contract_id().to_string(),
                subject_id: env.subject_id().as_str().to_string(),
                payload: serde_json::from_slice(entry.payload()).expect("decode payload"),
            })
            .collect()
    }

    fn publish_req(key: &str, value: &str) -> SettingsConfigPublishRequest {
        SettingsConfigPublishRequest {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    fn config_value(entry: Option<ConfigEntry>) -> Option<String> {
        entry.map(|entry| entry.value().to_string())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_creates_v1_and_emits() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let resp = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.timeout", "30s"),
            )
            .await
            .expect("publish ok");

        assert_eq!(resp.data.key, "app.timeout");
        assert_eq!(resp.data.version, 1);

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 1, "L2：每次 publish 恰发射一条 outbox entry");
        let fact = &facts[0];
        assert_eq!(fact.topic, VERSION_CHANGED_SPEC.topic());
        // envelope：域 / 契约 / opaque subject（config key）——域 + 契约同源 generated `CONTRACT`（#1193）。
        assert_eq!(fact.domain, VERSION_CHANGED_SPEC.contract().domain());
        assert_eq!(
            fact.contract_id,
            VERSION_CHANGED_SPEC.contract().contract_id()
        );
        assert_eq!(fact.subject_id, "app.timeout");
        // payload。
        assert_eq!(fact.payload.key, "app.timeout");
        assert_eq!(fact.payload.version, 1);
        assert_eq!(
            fact.payload.change_kind,
            SettingsConfigChangeKind::Published
        );
        assert_eq!(fact.payload.source_version, None);
        assert_eq!(fact.payload.tenant_id, TENANT);
        assert_eq!(fact.payload.occurred_at, 1_000);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_increments_version() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("v1");
        let resp = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v2"),
            )
            .await
            .expect("v2");
        assert_eq!(resp.data.version, 2);
        assert_eq!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .expect("get")
                .map(|entry| entry.value().to_string()),
            Some("v2".to_string())
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_rejects_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("nodot", "v"),
            )
            .await
            .expect_err("invalid key");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
        assert!(emitted_facts(&capture).is_empty(), "非法 key 不发射");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_restores_value_and_emits_rolled_back() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("v1");
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v2"),
        )
        .await
        .expect("v2");

        let resp = svc
            .rollback(rollback_receipt(), tenant(), actor(), "app.k", 1)
            .await
            .expect("rollback");
        assert_eq!(resp.data.version, 3, "回滚生成新版本 v3");
        assert_eq!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .expect("get")
                .map(|entry| entry.value().to_string()),
            Some("v1".to_string()),
            "v3 值 = v1 的值"
        );

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 3, "publish v1 + v2 + rollback v3 = 3 条 fact");
        let last = facts.last().expect("event");
        assert_eq!(
            last.payload.change_kind,
            SettingsConfigChangeKind::RolledBack
        );
        assert_eq!(last.payload.version, 3);
        assert_eq!(last.payload.source_version, Some(1));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_missing_version_is_not_found() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("v1");
        let err = svc
            .rollback(rollback_receipt(), tenant(), actor(), "app.k", 9)
            .await
            .expect_err("missing version");
        assert!(matches!(err, SettingsServiceError::NotFound));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_removes_config() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("v1");
        svc.delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("delete");
        assert!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .expect("get")
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn is_flag_enabled_evaluates_seeded_flag() {
        let capture = CapturingEmitter::default();
        let rule = RolloutRule::new(
            "region",
            crate::domain::RolloutOperator::In,
            vec!["us".to_string()],
        );
        let flag = FlagState::new(
            FlagKey::parse("checkout").expect("flag key"),
            true,
            false,
            vec![rule],
            Some(RolloutPercentage::new(100).expect("pct")),
        );
        let svc = service_with(&capture, InMemFlagStore::new().with_flag(tenant(), flag));

        assert!(
            svc.is_flag_enabled(tenant(), "checkout", &[("region", "us")])
                .expect("eval")
        );
        assert!(
            !svc.is_flag_enabled(tenant(), "checkout", &[("region", "eu")])
                .expect("eval")
        );
        // 未知 flag → fail-closed false。
        assert!(!svc.is_flag_enabled(tenant(), "unknown", &[]).expect("eval"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn is_flag_enabled_rejects_invalid_flag_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .is_flag_enabled(tenant(), "bad key", &[])
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // ── #1430 settings durable module：HTTP handler / route 装配测试 ──────────────────
    use crate::internal::mem::{InMemSecretRepo, new_secret_store};
    use testkit::ContractRequest;
    use vocab::PrincipalKind;

    /// 共享同一 in-mem store 的 secret read repo + mutation UoW。
    fn secret_ports_arc() -> (
        Arc<DynSecretRepo<'static>>,
        Arc<DynSecretUnitOfWork<'static>>,
    ) {
        let store = new_secret_store();
        (
            Arc::from(DynSecretRepo::new_box(InMemSecretRepo::from_shared(
                Arc::clone(&store),
            ))),
            Arc::from(DynSecretUnitOfWork::new_box(InMemSecretRepo::from_shared(
                store,
            ))),
        )
    }

    struct TestSecretResolver;

    impl SecretResolver for TestSecretResolver {
        async fn resolve(
            &self,
            _tenant: TenantId,
            _coordinate: &SecretCoordinate,
        ) -> Result<SecretMaterial, SecretResolverError> {
            Err(SecretResolverError::NotFound)
        }
    }

    fn secret_resolve_service_for(
        repo: Arc<DynSecretRepo<'static>>,
    ) -> Arc<crate::SecretResolveService> {
        Arc::new(crate::SecretResolveService::new(
            repo,
            DynSecretResolver::new_box(TestSecretResolver),
        ))
    }

    #[derive(Clone)]
    struct ConfigGetProbeResponse {
        head: Option<ConfigHead>,
        entry: Option<ConfigEntry>,
    }

    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum ConfigGetProbeFailure {
        #[default]
        None,
        Head,
        FindVersion,
    }

    #[derive(Clone, Copy, Default, PartialEq, Eq)]
    enum ConfigGetSyntheticWrite {
        #[default]
        None,
        Head,
        FindVersion,
    }

    #[derive(Default)]
    struct ConfigGetProbeState {
        responses: HashMap<ConfigCacheKey, ConfigGetProbeResponse>,
        head_calls: Vec<ConfigCacheKey>,
        find_version_calls: Vec<(TenantId, String, u64)>,
        failure: ConfigGetProbeFailure,
        synthetic_write: ConfigGetSyntheticWrite,
    }

    /// Provider-side observer for the real `settings.config-get` repository seam.
    #[derive(Clone)]
    struct SettingsConfigGetRepoProbe {
        state: Arc<Mutex<ConfigGetProbeState>>,
        business_write_effects:
            ::testkit::local_only::ProviderCounter<::testkit::local_only::BusinessWrite>,
    }

    impl Default for SettingsConfigGetRepoProbe {
        fn default() -> Self {
            Self {
                state: Arc::new(Mutex::new(ConfigGetProbeState::default())),
                business_write_effects: ::testkit::local_only::ProviderCounter::business_write(),
            }
        }
    }

    impl SettingsConfigGetRepoProbe {
        #[allow(clippy::expect_used)]
        fn active(tenant: TenantId, key: &str, value: &str, version: u64) -> Self {
            let probe = Self::default();
            probe.set_active(tenant, key, value, version);
            probe
        }

        #[allow(clippy::expect_used)]
        fn set_active(&self, tenant: TenantId, key: &str, value: &str, version: u64) {
            let key = SettingKey::parse(key).expect("valid probe setting key");
            self.set_response(
                tenant,
                &key,
                Some(ConfigHead::Active(version)),
                Some(ConfigEntry::new(
                    key.clone(),
                    ConfigValue::new(value),
                    tenant,
                    ConfigVersion::new(version),
                )),
            );
        }

        #[allow(clippy::expect_used)]
        fn set_deleted(&self, tenant: TenantId, key: &str, version: u64) {
            let key = SettingKey::parse(key).expect("valid probe setting key");
            self.set_response(tenant, &key, Some(ConfigHead::Deleted(version)), None);
        }

        #[allow(clippy::expect_used)]
        fn set_missing(&self, tenant: TenantId, key: &str) {
            let key = SettingKey::parse(key).expect("valid probe setting key");
            self.set_response(tenant, &key, None, None);
        }

        fn set_response(
            &self,
            tenant: TenantId,
            key: &SettingKey,
            head: Option<ConfigHead>,
            entry: Option<ConfigEntry>,
        ) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .responses
                .insert(
                    (tenant, key.as_str().to_string()),
                    ConfigGetProbeResponse { head, entry },
                );
        }

        fn fail_at(&self, failure: ConfigGetProbeFailure) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .failure = failure;
        }

        fn inject_write_at(&self, injection: ConfigGetSyntheticWrite) {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .synthetic_write = injection;
        }

        fn head_calls(&self) -> Vec<ConfigCacheKey> {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .head_calls
                .clone()
        }

        fn find_version_calls(&self) -> Vec<(TenantId, String, u64)> {
            self.state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .find_version_calls
                .clone()
        }

        fn test_repo(&self) -> TestRepo {
            TestRepo::from_provider(Arc::new(self.clone()))
        }
    }

    impl ConfigRepo for SettingsConfigGetRepoProbe {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _key: &SettingKey,
        ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
            Ok(None)
        }

        async fn find_version(
            &self,
            scope: TenantRepoScope,
            key: &SettingKey,
            version: u64,
        ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
            let cache_key = (scope.tenant(), key.as_str().to_string());
            let (failure, synthetic_write, entry) = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                state
                    .find_version_calls
                    .push((cache_key.0, cache_key.1.clone(), version));
                (
                    state.failure,
                    state.synthetic_write,
                    state
                        .responses
                        .get(&cache_key)
                        .and_then(|response| response.entry.clone()),
                )
            };
            if synthetic_write == ConfigGetSyntheticWrite::FindVersion {
                self.business_write_effects.record();
            }
            if failure == ConfigGetProbeFailure::FindVersion {
                return Err(ConfigRepoError::Storage(Box::new(std::io::Error::other(
                    "probe find-version failure",
                ))));
            }
            Ok(entry)
        }

        async fn head(
            &self,
            scope: TenantRepoScope,
            key: &SettingKey,
        ) -> Result<Option<ConfigHead>, ConfigRepoError> {
            let cache_key = (scope.tenant(), key.as_str().to_string());
            let (failure, synthetic_write, head) = {
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                state.head_calls.push(cache_key.clone());
                (
                    state.failure,
                    state.synthetic_write,
                    state
                        .responses
                        .get(&cache_key)
                        .and_then(|response| response.head),
                )
            };
            if synthetic_write == ConfigGetSyntheticWrite::Head {
                self.business_write_effects.record();
            }
            if failure == ConfigGetProbeFailure::Head {
                return Err(ConfigRepoError::Storage(Box::new(std::io::Error::other(
                    "probe head failure",
                ))));
            }
            Ok(head)
        }
    }

    struct TestRepo {
        configs: Box<DynConfigRepo<'static>>,
    }

    impl TestRepo {
        fn from_provider<T>(provider: Arc<T>) -> Self
        where
            T: ConfigRepo + Clone + 'static,
        {
            Self {
                configs: DynConfigRepo::new_box(provider.as_ref().clone()),
            }
        }
    }

    fn config_get_service(repo: TestRepo) -> Arc<SettingsService> {
        let writer_store = new_config_store();
        Arc::new(SettingsService::with_postgres(
            repo.configs,
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                writer_store,
                CapturingEmitter::default(),
            )),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        ))
    }

    #[derive(Clone)]
    struct SettingsConfigGetAuthorizer {
        allow: bool,
        contract_id: &'static str,
        permission: vocab::RoutePermissionId,
        requests: Arc<Mutex<Vec<httpserve::RouteAuthorizationRequest>>>,
    }

    impl SettingsConfigGetAuthorizer {
        fn allowing() -> Self {
            Self {
                allow: true,
                contract_id: ::generated::http::settings_v4::CONTRACT_ID,
                permission: vocab::RoutePermissionId::SettingsConfigGet,
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn allowing_secret_resolve() -> Self {
            Self {
                allow: true,
                contract_id: ::generated::http::settings_v7::CONTRACT_ID,
                permission: vocab::RoutePermissionId::SettingsSecretResolve,
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn denying() -> Self {
            Self {
                allow: false,
                ..Self::allowing()
            }
        }

        fn requests(&self) -> Vec<httpserve::RouteAuthorizationRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl httpserve::RouteAuthorizer for SettingsConfigGetAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            let allow = self.allow
                && request.contract_id == self.contract_id
                && request.permission == self.permission
                && request.tenant_id.is_some()
                && !matches!(request.principal_kind, PrincipalKind::Device);
            self.requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(request);
            Box::pin(async move {
                if allow {
                    httpserve::RouteAuthorizationDecision::Allow
                } else {
                    httpserve::RouteAuthorizationDecision::Deny
                }
            })
        }
    }

    #[derive(Clone)]
    struct RecordingAuthAuditSink {
        events: Arc<Mutex<Vec<diport::AuditEvent>>>,
        fail: bool,
    }

    impl RecordingAuthAuditSink {
        fn ok() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::ok()
            }
        }

        fn events(&self) -> Vec<diport::AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl diport::AuditSink for RecordingAuthAuditSink {
        async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
            if self.fail {
                return Err(diport::AuditSinkError::new(std::io::Error::other(
                    "settings auth audit failure",
                )));
            }
            self.events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(event);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }
    }

    #[allow(clippy::expect_used)]
    fn finalized_config_get_router(
        repo: TestRepo,
        auth_sink: RecordingAuthAuditSink,
        authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::settings_v4::RouteMarker,
            ConfigQueryService,
        >,
    ) {
        let (secret_repo, secret_uow) = secret_ports_arc();
        let writer_store = new_config_store();
        let service = Arc::new(super::SettingsService::with_postgres(
            repo.configs,
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                writer_store,
                CapturingEmitter::default(),
            )),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        ));
        let secret_service = secret_resolve_service_for(Arc::clone(&secret_repo));
        let domain = super::SettingsDomain::new(service, secret_repo, secret_uow, secret_service);
        let mut registry = bootstrap::compose(&[&domain]).expect("compose settings domain");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize settings routes");
        assert_eq!(finalized.len(), 1, "settings owns one Primary listener");
        let (listener, routes) = finalized.pop().expect("settings Primary routes");
        assert_eq!(listener, ListenerKind::Primary);
        let proof = ::httpserve::prove_local_only_mounted_route_state::<ConfigQueryService, _>(
            &routes,
            &::generated::http::settings_v4::ROUTE,
        )
        .expect("settings config-get is mounted with classified read state");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::RssAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    #[allow(clippy::expect_used)]
    fn finalized_secret_resolve_router(
        auth_sink: RecordingAuthAuditSink,
        authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::settings_v7::RouteMarker,
            SecretResolveState,
        >,
    ) {
        let domain = settings_domain_for_test();
        let mut registry = bootstrap::compose(&[&domain]).expect("compose settings domain");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize settings routes");
        let (listener, routes) = finalized.pop().expect("settings Primary routes");
        assert_eq!(listener, ListenerKind::Primary);
        let proof = ::httpserve::prove_local_only_mounted_route_state::<SecretResolveState, _>(
            &routes,
            &::generated::http::settings_v7::ROUTE,
        )
        .expect("settings secret-resolve is mounted with classified read state");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::RssAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            Arc::new(FixedClock(SystemTime::UNIX_EPOCH)),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    fn with_config_get_auth(
        router: axum::Router,
        principal_kind: PrincipalKind,
        tenant_id: Option<TenantId>,
    ) -> axum::Router {
        router.layer(axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::RssAccessToken,
            principal_kind,
            "settings-config-get-subject",
            tenant_id,
        )))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_integrity_rejects_active_head_without_an_exact_entry() {
        let key = SettingKey::parse("app.k").expect("valid key");
        let cases = [
            ("missing entry", None),
            (
                "wrong tenant",
                Some(ConfigEntry::new(
                    key.clone(),
                    ConfigValue::new("wrong-tenant"),
                    tenant_b(),
                    ConfigVersion::new(2),
                )),
            ),
            (
                "wrong key",
                Some(ConfigEntry::new(
                    SettingKey::parse("app.other").expect("valid alternate key"),
                    ConfigValue::new("wrong-key"),
                    tenant(),
                    ConfigVersion::new(2),
                )),
            ),
            (
                "wrong version",
                Some(ConfigEntry::new(
                    key.clone(),
                    ConfigValue::new("wrong-version"),
                    tenant(),
                    ConfigVersion::new(3),
                )),
            ),
        ];

        for (label, returned_entry) in cases {
            let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
            let service = config_get_service(probe.test_repo());
            let query = service.config_query_service();
            assert_eq!(
                query
                    .get_config(tenant(), "app.k")
                    .await
                    .expect("prime valid cache")
                    .map(|entry| entry.value().to_string()),
                Some("v1".to_string())
            );
            probe.set_response(tenant(), &key, Some(ConfigHead::Active(2)), returned_entry);

            let error = query.get_config(tenant(), "app.k").await.expect_err(label);

            assert!(
                matches!(error, SettingsServiceError::ConfigReadIntegrity),
                "{label}"
            );
            assert_eq!(error.to_string(), "config read integrity check failed");
            assert!(
                query.cache.find(tenant(), &key).is_none(),
                "{label} must evict the request cache slot"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_concurrent_publish_or_delete_returns_observed_head_version() {
        #[derive(Clone, Copy, Debug)]
        enum ConcurrentMutation {
            Publish,
            Delete,
        }

        struct SnapshotDriftRepo {
            inner: InMemConfigRepo,
            head_observed: Arc<tokio::sync::Barrier>,
            mutation_committed: Arc<tokio::sync::Barrier>,
        }

        impl ConfigRepo for SnapshotDriftRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.mutation_committed.wait().await;
                self.inner.find(scope, key).await
            }

            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.mutation_committed.wait().await;
                self.inner.find_version(scope, key, version).await
            }

            async fn head(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigHead>, ConfigRepoError> {
                let head = self.inner.head(scope, key).await?;
                self.head_observed.wait().await;
                Ok(head)
            }
        }

        let mut reads = Vec::new();
        for mutation in [ConcurrentMutation::Publish, ConcurrentMutation::Delete] {
            let store = new_config_store();
            let capture = CapturingEmitter::default();
            let writer = SettingsService::with_postgres(
                DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
                DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                    store.clone(),
                    capture.clone(),
                )),
                FlagStoreBox(Box::new(InMemFlagStore::new())),
                Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
            );
            writer
                .publish_config(
                    publish_receipt(),
                    tenant(),
                    actor(),
                    publish_req("app.k", "v1"),
                )
                .await
                .expect("seed v1");

            let head_observed = Arc::new(tokio::sync::Barrier::new(2));
            let mutation_committed = Arc::new(tokio::sync::Barrier::new(2));
            let reader = SettingsService::with_postgres(
                DynConfigRepo::new_box(SnapshotDriftRepo {
                    inner: InMemConfigRepo::from_shared(store.clone()),
                    head_observed: Arc::clone(&head_observed),
                    mutation_committed: Arc::clone(&mutation_committed),
                }),
                DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
                FlagStoreBox(Box::new(InMemFlagStore::new())),
                Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
            );
            let query = reader.config_query_service();
            let concurrent_mutation = async {
                head_observed.wait().await;
                match mutation {
                    ConcurrentMutation::Publish => {
                        writer
                            .publish_config(
                                publish_receipt(),
                                tenant(),
                                actor(),
                                publish_req("app.k", "v2"),
                            )
                            .await
                            .expect("publish v2");
                    }
                    ConcurrentMutation::Delete => {
                        writer
                            .delete(delete_receipt(), tenant(), actor(), "app.k")
                            .await
                            .expect("delete v1");
                    }
                }
                mutation_committed.wait().await;
            };

            let (read, ()) = tokio::join!(query.get_config(tenant(), "app.k"), concurrent_mutation);

            reads.push((mutation, read.map(config_value)));
        }

        for (mutation, read) in reads {
            assert_eq!(
                read.expect("snapshot drift is a valid concurrent read"),
                Some("v1".to_string()),
                "{mutation:?} must linearize at the observed active head"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_finalized_route_has_canonical_receipt() {
        let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
        let auth_sink = RecordingAuthAuditSink::ok();
        let authorizer = SettingsConfigGetAuthorizer::allowing();
        let (router, proof) = self::finalized_config_get_router(
            probe.test_repo(),
            auth_sink.clone(),
            Arc::new(authorizer.clone()),
        );
        // RssAccessToken 证据仅 User 可通过 AUTH-EVIDENCE-REQUIRE-01（Admin 会被滤成无证据 → 401）。
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::RssAccessToken,
            vocab::PrincipalKind::User,
            "settings-config-get-subject",
            Some(tenant()),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );

        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::settings_v4::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::settings_v4::SPEC.route.contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::settings_v4::SPEC
                            .route
                            .path()
                            .replace("{key}", "app.k"),
                    ),
                )
            },
        )
        .await
        .expect("settings config-get remains LocalOnly");
        let response = response.expect("call finalized settings config-get route");
        response
            .ensure_status(StatusCode::OK)
            .expect("config-get 200");
        let body: SettingsConfigGetResponse = response.json().expect("config-get response body");
        assert_eq!(body.data.key, "app.k");
        assert_eq!(body.data.value, "v1");
        assert_eq!(body.data.version, 1);
        assert_eq!(probe.head_calls(), vec![(tenant(), "app.k".to_string())]);
        assert_eq!(
            probe.find_version_calls(),
            vec![(tenant(), "app.k".to_string(), 1)]
        );
        let requests = authorizer.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].contract_id,
            ::generated::http::settings_v4::SPEC.route.contract_id()
        );
        assert_eq!(
            requests[0].permission,
            vocab::RoutePermissionId::SettingsConfigGet
        );
        assert_eq!(requests[0].tenant_id, Some(tenant()));
        assert_eq!(requests[0].principal_kind, PrincipalKind::User);
        let audit_events = auth_sink.events();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].principal_kind, PrincipalKind::User);
        assert_eq!(audit_events[0].tenant_id, Some(tenant()));
        assert_eq!(audit_events[0].resource_kind, "http_route");
        assert_eq!(
            audit_events[0].resource_id,
            ::generated::http::settings_v4::SPEC.route.contract_id()
        );
        assert_eq!(audit_events[0].action, "httpserve:authz");
        assert_eq!(audit_events[0].outcome, diport::AuditOutcome::Success);
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::settings_v4::SPEC.route.contract_id()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_resolve_local_only_finalized_route_has_canonical_receipt() {
        let authorizer = SettingsConfigGetAuthorizer::allowing_secret_resolve();
        let (router, proof) = self::finalized_secret_resolve_router(
            RecordingAuthAuditSink::ok(),
            Arc::new(authorizer.clone()),
        );
        // RssAccessToken 证据仅 User 可通过 AUTH-EVIDENCE-REQUIRE-01（Admin 会被滤成无证据 → 401）。
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::RssAccessToken,
            vocab::PrincipalKind::User,
            "settings-secret-resolve-subject",
            Some(tenant()),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            ::testkit::local_only::StaticExclusion::<
                ::testkit::local_only::BusinessWrite,
            >::from_governed(&proof),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::settings_v7::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::settings_v7::SPEC.route.contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::settings_v7::SPEC
                            .route
                            .path()
                            .replace("{key}", "app.k"),
                    ),
                )
            },
        )
        .await
        .expect("settings secret-resolve remains LocalOnly");
        response
            .expect("call finalized settings secret-resolve route")
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("missing coordinate is 404");
        assert_eq!(authorizer.requests().len(), 1);
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::settings_v7::SPEC.route.contract_id()
        );
    }

    async fn drive_config_get_local_only(
        probe: &SettingsConfigGetRepoProbe,
        key: &str,
        authenticated: Option<(PrincipalKind, Option<TenantId>)>,
        authorizer: SettingsConfigGetAuthorizer,
        auth_sink: RecordingAuthAuditSink,
    ) -> Result<
        Result<::testkit::ContractResponse, ::testkit::TestkitError>,
        ::testkit::local_only::LocalOnlyConformanceError,
    > {
        let (router, proof) =
            finalized_config_get_router(probe.test_repo(), auth_sink, Arc::new(authorizer));
        let router = authenticated.map_or(router.clone(), |(kind, tenant_id)| {
            with_config_get_auth(router, kind, tenant_id)
        });
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let path = ::generated::http::settings_v4::SPEC
            .route
            .path()
            .replace("{key}", key);
        ::testkit::local_only::assert_local_only(observers, move || {
            ::testkit::call(router, ::testkit::ContractRequest::get(path))
        })
        .await
    }

    #[allow(clippy::expect_used)]
    async fn call_finalized_config_get_local_only(
        router: &axum::Router,
        proof: &::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::settings_v4::RouteMarker,
            ConfigQueryService,
        >,
        probe: &SettingsConfigGetRepoProbe,
        tenant_id: TenantId,
    ) -> Result<::testkit::ContractResponse, ::testkit::local_only::LocalOnlyConformanceError> {
        let router = with_config_get_auth(router.clone(), PrincipalKind::User, Some(tenant_id));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                proof,
            ),
        );
        ::testkit::local_only::assert_local_only(observers, move || {
            ::testkit::call(
                router,
                ::testkit::ContractRequest::get(
                    ::generated::http::settings_v4::SPEC
                        .route
                        .path()
                        .replace("{key}", "app.k"),
                ),
            )
        })
        .await
        .map(|response| response.expect("call finalized config-get route"))
    }

    #[allow(clippy::expect_used)]
    fn assert_config_get_body(response: &::testkit::ContractResponse, value: &str, version: i64) {
        response
            .ensure_status(StatusCode::OK)
            .expect("config-get 200");
        let body: SettingsConfigGetResponse = response.json().expect("config-get response body");
        assert_eq!(body.data.key, "app.k");
        assert_eq!(body.data.value, value);
        assert_eq!(body.data.version, version);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_cache_hit_stale_refresh_and_tenant_isolation() {
        let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "a-v1", 1);
        probe.set_active(tenant_b(), "app.k", "b-v1", 1);
        let (router, proof) = finalized_config_get_router(
            probe.test_repo(),
            RecordingAuthAuditSink::ok(),
            Arc::new(SettingsConfigGetAuthorizer::allowing()),
        );

        let miss = call_finalized_config_get_local_only(&router, &proof, &probe, tenant())
            .await
            .expect("cache miss remains LocalOnly");
        assert_config_get_body(&miss, "a-v1", 1);
        assert_eq!(probe.head_calls(), vec![(tenant(), "app.k".to_string())]);
        assert_eq!(
            probe.find_version_calls(),
            vec![(tenant(), "app.k".to_string(), 1)]
        );

        let hit = call_finalized_config_get_local_only(&router, &proof, &probe, tenant())
            .await
            .expect("cache hit remains LocalOnly");
        assert_config_get_body(&hit, "a-v1", 1);
        assert_eq!(
            probe.head_calls(),
            vec![
                (tenant(), "app.k".to_string()),
                (tenant(), "app.k".to_string()),
            ]
        );
        assert_eq!(
            probe.find_version_calls(),
            vec![(tenant(), "app.k".to_string(), 1)],
            "valid cache hit skips find_version"
        );

        probe.set_active(tenant(), "app.k", "a-v2", 2);
        let refreshed = call_finalized_config_get_local_only(&router, &proof, &probe, tenant())
            .await
            .expect("stale refresh remains LocalOnly");
        assert_config_get_body(&refreshed, "a-v2", 2);
        assert_eq!(probe.head_calls().len(), 3);
        assert_eq!(probe.find_version_calls().len(), 2);

        let tenant_b_miss =
            call_finalized_config_get_local_only(&router, &proof, &probe, tenant_b())
                .await
                .expect("tenant B miss remains LocalOnly");
        assert_config_get_body(&tenant_b_miss, "b-v1", 1);
        let tenant_b_hit =
            call_finalized_config_get_local_only(&router, &proof, &probe, tenant_b())
                .await
                .expect("tenant B hit remains LocalOnly");
        assert_config_get_body(&tenant_b_hit, "b-v1", 1);
        assert_eq!(
            probe.head_calls(),
            vec![
                (tenant(), "app.k".to_string()),
                (tenant(), "app.k".to_string()),
                (tenant(), "app.k".to_string()),
                (tenant_b(), "app.k".to_string()),
                (tenant_b(), "app.k".to_string()),
            ]
        );
        assert_eq!(
            probe.find_version_calls(),
            vec![
                (tenant(), "app.k".to_string(), 1),
                (tenant(), "app.k".to_string(), 2),
                (tenant_b(), "app.k".to_string(), 1),
            ],
            "tenant cache slots remain isolated and valid hits skip find_version"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_repo_errors_evict_stale_cache_on_finalized_route() {
        let key = SettingKey::parse("app.k").expect("valid key");

        let head_probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
        let (head_router, head_proof) = finalized_config_get_router(
            head_probe.test_repo(),
            RecordingAuthAuditSink::ok(),
            Arc::new(SettingsConfigGetAuthorizer::allowing()),
        );
        let prime =
            call_finalized_config_get_local_only(&head_router, &head_proof, &head_probe, tenant())
                .await
                .expect("head cache prime remains LocalOnly");
        assert_config_get_body(&prime, "v1", 1);
        head_probe.fail_at(ConfigGetProbeFailure::Head);
        let head_failure =
            call_finalized_config_get_local_only(&head_router, &head_proof, &head_probe, tenant())
                .await
                .expect("head failure remains LocalOnly");
        assert_eq!(head_failure.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(head_probe.head_calls().len(), 2);
        assert_eq!(head_probe.find_version_calls().len(), 1);

        head_probe.fail_at(ConfigGetProbeFailure::None);
        head_probe.set_response(tenant(), &key, Some(ConfigHead::Active(1)), None);
        let after_head_failure =
            call_finalized_config_get_local_only(&head_router, &head_proof, &head_probe, tenant())
                .await
                .expect("post-head-failure integrity check remains LocalOnly");
        assert_eq!(
            after_head_failure.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Active+None reaches integrity failure only when the stale cache was evicted"
        );
        assert_eq!(head_probe.head_calls().len(), 3);
        assert_eq!(head_probe.find_version_calls().len(), 2);

        let find_version_probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
        let (find_version_router, find_version_proof) = finalized_config_get_router(
            find_version_probe.test_repo(),
            RecordingAuthAuditSink::ok(),
            Arc::new(SettingsConfigGetAuthorizer::allowing()),
        );
        let prime = call_finalized_config_get_local_only(
            &find_version_router,
            &find_version_proof,
            &find_version_probe,
            tenant(),
        )
        .await
        .expect("find-version cache prime remains LocalOnly");
        assert_config_get_body(&prime, "v1", 1);
        find_version_probe.set_active(tenant(), "app.k", "v2", 2);
        find_version_probe.fail_at(ConfigGetProbeFailure::FindVersion);
        let find_version_failure = call_finalized_config_get_local_only(
            &find_version_router,
            &find_version_proof,
            &find_version_probe,
            tenant(),
        )
        .await
        .expect("find-version failure remains LocalOnly");
        assert_eq!(
            find_version_failure.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(find_version_probe.head_calls().len(), 2);
        assert_eq!(find_version_probe.find_version_calls().len(), 2);

        find_version_probe.fail_at(ConfigGetProbeFailure::None);
        find_version_probe.set_response(tenant(), &key, Some(ConfigHead::Active(1)), None);
        let after_find_version_failure = call_finalized_config_get_local_only(
            &find_version_router,
            &find_version_proof,
            &find_version_probe,
            tenant(),
        )
        .await
        .expect("post-find-version-failure integrity check remains LocalOnly");
        assert_eq!(
            after_find_version_failure.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "same-version Active+None reaches integrity failure only when the cache slot was evicted"
        );
        assert_eq!(find_version_probe.head_calls().len(), 3);
        assert_eq!(find_version_probe.find_version_calls().len(), 3);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_absent_deleted_invalid_and_repo_failures_are_fail_closed() {
        for (label, probe, expected) in [
            (
                "not found",
                {
                    let probe = SettingsConfigGetRepoProbe::default();
                    probe.set_missing(tenant(), "app.k");
                    probe
                },
                StatusCode::NOT_FOUND,
            ),
            (
                "deleted",
                {
                    let probe = SettingsConfigGetRepoProbe::default();
                    probe.set_deleted(tenant(), "app.k", 2);
                    probe
                },
                StatusCode::NOT_FOUND,
            ),
            (
                "head failure",
                {
                    let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
                    probe.fail_at(ConfigGetProbeFailure::Head);
                    probe
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                "find-version failure",
                {
                    let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
                    probe.fail_at(ConfigGetProbeFailure::FindVersion);
                    probe
                },
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let response = drive_config_get_local_only(
                &probe,
                "app.k",
                Some((PrincipalKind::User, Some(tenant()))),
                SettingsConfigGetAuthorizer::allowing(),
                RecordingAuthAuditSink::ok(),
            )
            .await
            .expect("forbidden effects remain zero")
            .expect("finalized route call");
            assert_eq!(response.status(), expected, "{label}");
            let body = String::from_utf8_lossy(response.body_bytes());
            assert!(!body.contains("probe"), "{label} must redact provider data");
        }

        let invalid_probe = SettingsConfigGetRepoProbe::default();
        let response = drive_config_get_local_only(
            &invalid_probe,
            "nodot",
            Some((PrincipalKind::User, Some(tenant()))),
            SettingsConfigGetAuthorizer::allowing(),
            RecordingAuthAuditSink::ok(),
        )
        .await
        .expect("invalid input remains LocalOnly")
        .expect("finalized route call");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(invalid_probe.head_calls().is_empty());
        assert!(invalid_probe.find_version_calls().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_integrity_maps_active_without_entry_to_redacted_500() {
        let probe = SettingsConfigGetRepoProbe::default();
        let key = SettingKey::parse("app.k").expect("valid key");
        probe.set_response(tenant(), &key, Some(ConfigHead::Active(1)), None);

        let response = drive_config_get_local_only(
            &probe,
            "app.k",
            Some((PrincipalKind::User, Some(tenant()))),
            SettingsConfigGetAuthorizer::allowing(),
            RecordingAuthAuditSink::ok(),
        )
        .await
        .expect("integrity failure remains LocalOnly")
        .expect("finalized route call");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = String::from_utf8_lossy(response.body_bytes());
        assert!(!body.contains("integrity"));
        assert!(!body.contains("app.k"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_auth_boundary_rejects_without_provider_reads() {
        let cases = [
            (
                "missing auth",
                None,
                SettingsConfigGetAuthorizer::allowing(),
                StatusCode::UNAUTHORIZED,
                0,
            ),
            (
                "PDP deny",
                Some((PrincipalKind::User, Some(tenant()))),
                SettingsConfigGetAuthorizer::denying(),
                StatusCode::FORBIDDEN,
                1,
            ),
            (
                // Device + RssAccessToken 证据被 AUTH-EVIDENCE-REQUIRE-01 滤掉 → 401（达不到 PDP）。
                "device deny",
                Some((PrincipalKind::Device, Some(tenant()))),
                SettingsConfigGetAuthorizer::allowing(),
                StatusCode::UNAUTHORIZED,
                0,
            ),
            (
                "tenantless deny",
                Some((PrincipalKind::User, None)),
                SettingsConfigGetAuthorizer::allowing(),
                StatusCode::FORBIDDEN,
                1,
            ),
        ];

        for (label, authenticated, authorizer, expected, expected_authorizer_calls) in cases {
            let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
            let auth_sink = RecordingAuthAuditSink::ok();
            let observed_authorizer = authorizer.clone();
            let response = drive_config_get_local_only(
                &probe,
                "app.k",
                authenticated,
                authorizer,
                auth_sink.clone(),
            )
            .await
            .expect("auth rejection remains LocalOnly")
            .expect("finalized route call");

            assert_eq!(response.status(), expected, "{label}");
            assert_eq!(
                observed_authorizer.requests().len(),
                expected_authorizer_calls,
                "{label}"
            );
            assert!(probe.head_calls().is_empty(), "{label}");
            assert!(probe.find_version_calls().is_empty(), "{label}");
            let audit_events = auth_sink.events();
            match authenticated {
                None => assert!(audit_events.is_empty(), "{label}"),
                // Device + RssAccessToken：证据可达但 scheme/kind 不合 → authz unauthorized（达不到 PDP）。
                Some((PrincipalKind::Device, tenant_id)) => {
                    assert_eq!(audit_events.len(), 1, "{label}");
                    let event = &audit_events[0];
                    assert_eq!(event.principal_kind, PrincipalKind::Device, "{label}");
                    assert_eq!(event.tenant_id, tenant_id, "{label}");
                    assert_eq!(
                        event.outcome,
                        diport::AuditOutcome::Failure {
                            reason: "unauthorized"
                        },
                        "{label}"
                    );
                }
                Some((principal_kind, tenant_id)) => {
                    assert_eq!(audit_events.len(), 1, "{label}");
                    let event = &audit_events[0];
                    assert_eq!(event.principal_kind, principal_kind, "{label}");
                    assert_eq!(event.tenant_id, tenant_id, "{label}");
                    assert_eq!(event.resource_kind, "http_route", "{label}");
                    assert_eq!(
                        event.resource_id,
                        ::generated::http::settings_v4::SPEC.route.contract_id(),
                        "{label}"
                    );
                    assert_eq!(event.action, "httpserve:authz", "{label}");
                    let expected_reason = if matches!(principal_kind, PrincipalKind::Device) {
                        "unauthorized"
                    } else {
                        "forbidden"
                    };
                    assert_eq!(
                        event.outcome,
                        diport::AuditOutcome::Failure {
                            reason: expected_reason
                        },
                        "{label}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_cache_paths_trip_provider_business_write_probe() {
        #[derive(Clone, Copy, Debug)]
        enum Scenario {
            CacheHit,
            StaleRefresh,
            TenantMiss,
        }

        for scenario in [
            Scenario::CacheHit,
            Scenario::StaleRefresh,
            Scenario::TenantMiss,
        ] {
            let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "a-v1", 1);
            probe.set_active(tenant_b(), "app.k", "b-v1", 1);
            let (router, proof) = finalized_config_get_router(
                probe.test_repo(),
                RecordingAuthAuditSink::ok(),
                Arc::new(SettingsConfigGetAuthorizer::allowing()),
            );
            let prime = call_finalized_config_get_local_only(&router, &proof, &probe, tenant())
                .await
                .expect("prime remains LocalOnly");
            assert_config_get_body(&prime, "a-v1", 1);

            let target_tenant = match scenario {
                Scenario::CacheHit => {
                    probe.inject_write_at(ConfigGetSyntheticWrite::Head);
                    tenant()
                }
                Scenario::StaleRefresh => {
                    probe.set_active(tenant(), "app.k", "a-v2", 2);
                    probe.inject_write_at(ConfigGetSyntheticWrite::FindVersion);
                    tenant()
                }
                Scenario::TenantMiss => {
                    probe.inject_write_at(ConfigGetSyntheticWrite::Head);
                    tenant_b()
                }
            };
            let result =
                call_finalized_config_get_local_only(&router, &proof, &probe, target_tenant).await;

            assert!(
                matches!(
                    result,
                    Err(
                        ::testkit::local_only::LocalOnlyConformanceError::ForbiddenEffects {
                            business_writes: 1,
                            outbox: 0,
                            publishes: 0,
                        }
                    )
                ),
                "{scenario:?} must observe the provider-owned write counter"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_local_only_auth_audit_failure_returns_500_before_provider_read() {
        let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
        let response = drive_config_get_local_only(
            &probe,
            "app.k",
            Some((PrincipalKind::User, Some(tenant()))),
            SettingsConfigGetAuthorizer::allowing(),
            RecordingAuthAuditSink::failing(),
        )
        .await
        .expect("audit failure remains LocalOnly")
        .expect("finalized route call");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(probe.head_calls().is_empty());
        assert!(probe.find_version_calls().is_empty());
    }

    #[tokio::test]
    async fn config_get_local_only_synthetic_provider_business_writes_trip_exact_probe() {
        for injection in [
            ConfigGetSyntheticWrite::Head,
            ConfigGetSyntheticWrite::FindVersion,
        ] {
            let probe = SettingsConfigGetRepoProbe::active(tenant(), "app.k", "v1", 1);
            probe.inject_write_at(injection);
            let result = drive_config_get_local_only(
                &probe,
                "app.k",
                Some((PrincipalKind::User, Some(tenant()))),
                SettingsConfigGetAuthorizer::allowing(),
                RecordingAuthAuditSink::ok(),
            )
            .await;

            assert!(matches!(
                result,
                Err(
                    ::testkit::local_only::LocalOnlyConformanceError::ForbiddenEffects {
                        business_writes: 1,
                        outbox: 0,
                        publishes: 0,
                    }
                )
            ));
        }
    }

    /// 测试用 SettingsDomain 实例（config 服务 + secret 仓储端口，均 in-mem 替身）。
    fn settings_domain_for_test() -> SettingsDomain {
        let capture = CapturingEmitter::default();
        let (secret_repo, secret_uow) = secret_ports_arc();
        let secret_service = secret_resolve_service_for(Arc::clone(&secret_repo));
        SettingsDomain::new(
            Arc::new(service_with(&capture, InMemFlagStore::new())),
            secret_repo,
            secret_uow,
            secret_service,
        )
    }

    #[allow(clippy::expect_used, clippy::panic)]
    fn subscriber_effect_for(service: Arc<SettingsService>) -> Arc<ConfigVersionReconciler> {
        let (secret_repo, secret_uow) = secret_ports_arc();
        let secret_service = secret_resolve_service_for(Arc::clone(&secret_repo));
        let domain = SettingsDomain::new(service, secret_repo, secret_uow, secret_service);
        let mut registry = bootstrap::compose(&[&domain]).expect("settings domain composes");
        let binding = registry
            .drain_subscribers()
            .pop()
            .expect("settings subscription exists");
        let (_, _, _, _, capability) = binding.into_parts();
        match capability {
            SubscriberCapability::DomainReconcile(effect) => {
                match effect.into_owner::<ConfigVersionReconciler>() {
                    Ok(reconciler) => reconciler,
                    Err(_) => panic!("settings registration must carry its exact owner reconciler"),
                }
            }
            SubscriberCapability::AdapterNativeTransactional => {
                panic!("settings subscription must be reconcile")
            }
        }
    }

    /// post-authz 授权证据（Primary route gate 注入）。
    fn user_evidence(t: TenantId) -> AuthorizedSubject {
        AuthorizedSubject::for_test(t, PrincipalKind::User, "test-subject", None)
    }

    fn user_evidence_with_subject(t: TenantId, subject: impl Into<String>) -> AuthorizedSubject {
        AuthorizedSubject::for_test(t, PrincipalKind::User, subject, None)
    }

    fn config_router(
        service: Arc<SettingsService>,
        auth: Option<AuthorizedSubject>,
    ) -> axum::Router {
        let publish = httpserve::with_producer_witness_for_test(
            post(config_publish_handler).with_state(service),
            CONFIG_HTTP_PRODUCER,
        );
        let router = axum::Router::new().route("/configs", publish);
        match auth {
            Some(a) => router.layer(axum::Extension(a)),
            None => router,
        }
    }

    fn config_resource_router(
        service: Arc<SettingsService>,
        auth: Option<AuthorizedSubject>,
    ) -> axum::Router {
        let config_query = service.config_query_service();
        let delete = httpserve::with_producer_witness_for_test(
            delete(config_delete_handler).with_state(Arc::clone(&service)),
            CONFIG_DELETE_PRODUCER,
        );
        let rollback = httpserve::with_producer_witness_for_test(
            post(config_rollback_handler).with_state(service),
            CONFIG_ROLLBACK_PRODUCER,
        );
        let router = axum::Router::new()
            .route(
                "/configs/{key}",
                get(config_get_handler).with_state(config_query),
            )
            .route("/configs/{key}", delete)
            .route("/configs/{key}/rollbacks", rollback);
        match auth {
            Some(evidence) => router.layer(axum::Extension(evidence)),
            None => router,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settings_domain_declares_business_route_group() {
        let domain = settings_domain_for_test();
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(
            groups.len(),
            1,
            "config + secret 同 /api/v1/settings 路由组"
        );
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, SETTINGS_ROUTE_PREFIX);
        let finalized = reg.finalize_routes().expect("active routes finalize");
        assert_eq!(finalized.len(), 1, "six routes share one Primary listener");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn config_cud_surface_mounts_only_the_three_mutation_contracts() {
        let domain = settings_domain_for_test().config_cud_only();
        let mut reg = bootstrap::compose(&[&domain]).expect("compose config CUD domain");
        let finalized = reg.finalize_routes().expect("config CUD routes finalize");
        let evidence = finalized[0].1.route_evidence();
        let contracts = evidence
            .iter()
            .map(vocab::HttpRouteEvidence::contract_id)
            .collect::<Vec<_>>();
        assert_eq!(
            contracts,
            [
                generated::http::settings_v1::CONTRACT_ID,
                generated::http::settings_v5::CONTRACT_ID,
                generated::http::settings_v6::CONTRACT_ID,
            ]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settings_domain_declares_config_version_changed_subscriber() {
        let domain = settings_domain_for_test();
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let mut subs = reg.drain_subscribers().into_iter();
        let spec = VERSION_CHANGED_SPEC.subscriptions()[0];
        assert_eq!(spec.consumer(), SETTINGS_DOMAIN);
        assert_eq!(spec.execution(), SubscriptionExecution::DomainEffect);
        assert_eq!(
            spec.effect(),
            Some(SubscriptionEffect::SettingsConfigVersionRefresh)
        );
        assert_eq!(
            spec.external_effect_policy(),
            vocab::ExternalEffectPolicy::Reconcile
        );
        let (contract_id, topic, consumer, group, capability) =
            subs.next().expect("settings subscriber").into_parts();
        assert!(subs.next().is_none());
        assert_eq!(contract_id, VERSION_CHANGED_SPEC.contract_id());
        assert_eq!(topic, VERSION_CHANGED_SPEC.topic());
        assert_eq!(consumer, spec.consumer());
        assert_eq!(group.as_str(), spec.group());
        assert!(matches!(
            capability,
            SubscriberCapability::DomainReconcile(_)
        ));
    }

    #[allow(clippy::expect_used)]
    fn version_changed_payload(tenant_id: &str) -> Vec<u8> {
        version_changed_payload_for(tenant_id, "app.feature", 1)
    }

    #[allow(clippy::expect_used)]
    fn version_changed_payload_for(tenant_id: &str, key: &str, version: i64) -> Vec<u8> {
        version_changed_payload_with_kind(
            tenant_id,
            key,
            version,
            SettingsConfigChangeKind::Published,
        )
    }

    #[allow(clippy::expect_used)]
    fn version_changed_payload_with_kind(
        tenant_id: &str,
        key: &str,
        version: i64,
        change_kind: SettingsConfigChangeKind,
    ) -> Vec<u8> {
        let payload = SettingsConfigVersionChangedPayload {
            change_kind,
            key: key.to_string(),
            occurred_at: 1_700_000_000,
            source_version: None,
            tenant_id: tenant_id.to_string(),
            version,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_version_deleted_durable_handler_removes_cache() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "enabled"),
            )
            .await
            .expect("publish config");
        service
            .delete(delete_receipt(), tenant(), actor(), "app.feature")
            .await
            .expect("delete config");
        let key = SettingKey::parse("app.feature").expect("valid key");
        assert!(service.query.cache.find(tenant(), &key).is_none());

        let message = Message::new(
            "m-settings-deleted",
            version_changed_payload_with_kind(
                TENANT,
                "app.feature",
                2,
                SettingsConfigChangeKind::Deleted,
            ),
        );
        let event = config_version_changed_event_from_message(&message).expect("parse event");
        let result = service
            .config_query_service()
            .handle_config_version_changed_event(event)
            .await;
        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        assert!(service.query.cache.find(tenant(), &key).is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_version_changed_durable_handler_refreshes_config_cache() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "enabled"),
            )
            .await
            .expect("publish config");
        let key = SettingKey::parse("app.feature").expect("valid key");
        service.query.cache.remove(tenant(), &key);
        assert!(
            service.query.cache.find(tenant(), &key).is_none(),
            "test must start with an empty cache slot"
        );

        let message = Message::new("m-settings", version_changed_payload(TENANT));
        let event = config_version_changed_event_from_message(&message).expect("parse event");
        let result = service
            .config_query_service()
            .handle_config_version_changed_event(event)
            .await;
        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        let cached = service
            .query
            .cache
            .find(tenant(), &key)
            .expect("subscriber refreshed cache");
        assert_eq!(cached.value(), "enabled");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_version_changed_handle_result_refreshes_config_cache() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "enabled"),
            )
            .await
            .expect("publish config");
        let key = SettingKey::parse("app.feature").expect("valid key");
        service.query.cache.remove(tenant(), &key);

        let message = Message::new("m-settings", version_changed_payload(TENANT));
        let event = config_version_changed_event_from_message(&message).expect("parse event");
        let result = service
            .config_query_service()
            .handle_config_version_changed_event(event)
            .await;

        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        let cached = service
            .query
            .cache
            .find(tenant(), &key)
            .expect("ConsumerTx refresh method refreshed cache");
        assert_eq!(cached.value(), "enabled");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn subscriber_effect_refreshes_the_route_service_cache_instance() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "enabled"),
            )
            .await
            .expect("publish config");
        let key = SettingKey::parse("app.feature").expect("valid key");
        service.query.cache.remove(tenant(), &key);
        let effect = subscriber_effect_for(Arc::clone(&service));

        let result = effect
            .reconcile(
                Message::new("m-settings-effect", version_changed_payload(TENANT)),
                tenant(),
            )
            .await;

        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        assert_eq!(
            service
                .query
                .cache
                .find(tenant(), &key)
                .expect("shared service cache refreshed")
                .value(),
            "enabled"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn subscriber_effect_rejects_invalid_payload_and_tenant_mismatch() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let effect = subscriber_effect_for(service);
        let other_tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")
            .expect("canonical other tenant");

        let invalid = effect
            .reconcile(Message::new("m-invalid", b"not-json".to_vec()), tenant())
            .await;
        let mismatch = effect
            .reconcile(
                Message::new("m-mismatch", version_changed_payload(TENANT)),
                other_tenant,
            )
            .await;

        assert_eq!(invalid.disposition(), consistency::Disposition::Reject);
        assert_eq!(
            invalid.as_settled(),
            consistency::Settled::Reject {
                summary: PermanentErrorKind::Permanent.message()
            }
        );
        assert_eq!(mismatch.disposition(), consistency::Disposition::Reject);
        assert_eq!(
            mismatch.as_settled(),
            consistency::Settled::Reject {
                summary: PermanentErrorKind::Invariant.message()
            }
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn config_version_tenant_mismatch_log_carries_both_tenants() {
        use std::collections::HashMap;
        use tracing::field::{Field, Visit};
        use tracing::subscriber::Interest;
        use tracing::{Event, Id, Metadata, span};

        struct FieldVisitor {
            fields: HashMap<String, String>,
        }

        impl Visit for FieldVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.fields
                    .insert(field.name().to_string(), format!("{value:?}"));
            }

            fn record_str(&mut self, field: &Field, value: &str) {
                self.fields
                    .insert(field.name().to_string(), value.to_string());
            }
        }

        struct CaptureSubscriber {
            events: Arc<Mutex<Vec<HashMap<String, String>>>>,
        }

        impl tracing::Subscriber for CaptureSubscriber {
            fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
                Interest::always()
            }

            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
            fn enter(&self, _span: &Id) {}
            fn exit(&self, _span: &Id) {}

            fn event(&self, event: &Event<'_>) {
                if *event.metadata().level() != tracing::Level::WARN {
                    return;
                }
                let mut visitor = FieldVisitor {
                    fields: HashMap::new(),
                };
                event.record(&mut visitor);
                self.events.lock().unwrap().push(visitor.fields);
            }
        }

        let payload_tenant = tenant();
        let authenticated_tenant = TenantId::parse("11111111-2222-4333-8444-555555555555")
            .expect("canonical other tenant");
        let authenticated_tenant_text = authenticated_tenant.to_string();
        let events = Arc::new(Mutex::new(Vec::new()));
        tracing::subscriber::with_default(
            CaptureSubscriber {
                events: Arc::clone(&events),
            },
            || {
                log_config_version_tenant_mismatch(
                    "m-mismatch-log",
                    &payload_tenant,
                    &authenticated_tenant,
                );
            },
        );

        let events = events.lock().unwrap();
        let event = events.first().expect("tenant mismatch warning captured");
        assert!(
            event
                .get("payload_tenant")
                .is_some_and(|value| value.contains(TENANT))
        );
        assert!(
            event
                .get("authenticated_tenant")
                .is_some_and(|value| value.contains(&authenticated_tenant_text))
        );
        assert!(!event.contains_key("payload"));
        assert!(!event.contains_key("value"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn subscriber_effect_preserves_transient_refresh_as_requeue() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let effect = subscriber_effect_for(service);

        let result = effect
            .reconcile(
                Message::new(
                    "m-future-version",
                    version_changed_payload_for(TENANT, "app.feature", 2),
                ),
                tenant(),
            )
            .await;

        assert_eq!(result.disposition(), consistency::Disposition::Requeue);
        assert_eq!(
            result.as_settled(),
            consistency::Settled::Requeue {
                summary: EngineErrorKind::Transient.message()
            }
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_version_changed_durable_handler_ignores_stale_event_version() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "v1"),
            )
            .await
            .expect("publish v1");
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.feature", "v2"),
            )
            .await
            .expect("publish v2");
        let key = SettingKey::parse("app.feature").expect("valid key");
        service.query.cache.remove(tenant(), &key);

        let message = Message::new(
            "m-settings-stale",
            version_changed_payload_for(TENANT, "app.feature", 1),
        );
        let event = config_version_changed_event_from_message(&message).expect("parse event");
        let result = service
            .config_query_service()
            .handle_config_version_changed_event(event)
            .await;
        assert_eq!(result.disposition(), consistency::Disposition::Ack);
        let cached = service
            .query
            .cache
            .find(tenant(), &key)
            .expect("stale event refreshes to latest active value");
        assert_eq!(cached.value(), "v2");
        assert_eq!(cached.version(), 2);
    }

    #[test]
    fn config_version_changed_decode_rejects_invalid_tenant() {
        let result = config_version_changed_event_from_message(&Message::new(
            "m-settings",
            version_changed_payload("not-a-uuid"),
        ));
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settings_routes_carry_complete_generated_evidence() {
        let cases = [
            (
                CONFIG_HTTP_SPEC.route,
                "/api/v1/settings/configs",
                "POST",
                "settings.config-publish",
                vocab::RoutePermissionId::SettingsConfigPublish,
                vocab::HttpConsistencyLevel::OutboxFact,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::BusinessWrite,
                    vocab::HttpEffectKind::BusinessTransaction,
                    vocab::HttpEffectKind::Outbox,
                    vocab::HttpEffectKind::Publish,
                ][..],
            ),
            (
                SECRET_HTTP_SPEC.route,
                "/api/v1/settings/secrets",
                "POST",
                "settings.secret-publish",
                vocab::RoutePermissionId::SettingsSecretPublish,
                vocab::HttpConsistencyLevel::LocalTx,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::BusinessWrite,
                    vocab::HttpEffectKind::BusinessTransaction,
                ][..],
            ),
            (
                SECRET_RESOLVE_HTTP_SPEC.route,
                "/api/v1/settings/secrets/{key}/material",
                "GET",
                "settings.secret-resolve",
                vocab::RoutePermissionId::SettingsSecretResolve,
                vocab::HttpConsistencyLevel::LocalOnly,
                &[vocab::HttpEffectKind::Auth, vocab::HttpEffectKind::Read][..],
            ),
            (
                CONFIG_GET_HTTP_SPEC.route,
                "/api/v1/settings/configs/{key}",
                "GET",
                "settings.config-get",
                vocab::RoutePermissionId::SettingsConfigGet,
                vocab::HttpConsistencyLevel::LocalOnly,
                &[vocab::HttpEffectKind::Auth, vocab::HttpEffectKind::Read][..],
            ),
            (
                CONFIG_DELETE_HTTP_SPEC.route,
                "/api/v1/settings/configs/{key}",
                "DELETE",
                "settings.config-delete",
                vocab::RoutePermissionId::SettingsConfigDelete,
                vocab::HttpConsistencyLevel::OutboxFact,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::BusinessWrite,
                    vocab::HttpEffectKind::BusinessTransaction,
                    vocab::HttpEffectKind::Outbox,
                    vocab::HttpEffectKind::Publish,
                ][..],
            ),
            (
                CONFIG_ROLLBACK_HTTP_SPEC.route,
                "/api/v1/settings/configs/{key}/rollbacks",
                "POST",
                "settings.config-rollback",
                vocab::RoutePermissionId::SettingsConfigRollback,
                vocab::HttpConsistencyLevel::OutboxFact,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::BusinessWrite,
                    vocab::HttpEffectKind::BusinessTransaction,
                    vocab::HttpEffectKind::Outbox,
                    vocab::HttpEffectKind::Publish,
                ][..],
            ),
        ];
        for (evidence, path, method, contract_id, permission, consistency, effects) in cases {
            assert_eq!(evidence.path(), path);
            assert_eq!(evidence.method(), method);
            assert_eq!(evidence.contract_id(), contract_id);
            assert_eq!(
                evidence.auth(),
                vocab::HttpRouteAuth::Permission(permission)
            );
            assert_eq!(evidence.resource(), None);
            assert!(!evidence.self_scoped());
            assert_eq!(evidence.consistency_level(), consistency);
            assert_eq!(evidence.effect_profile().effects(), effects);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn generated_primary_endpoints_preserve_all_six_route_proofs() {
        {
            const _: ::vocab::HttpRouteBinding<
                ::generated::http::settings_v2::RouteMarker,
                ::vocab::http::LocalTx,
            > = ::generated::http::settings_v2::ROUTE;
        }

        {
            let config_publish = GeneratedPrimaryEndpoint::new_producer(
                CONFIG_HTTP_PRODUCER,
                config_publish_handler,
            )
            .expect("config publish endpoint");
            assert_eq!(config_publish.evidence(), &CONFIG_HTTP_SPEC.route);

            let secret_publish =
                GeneratedPrimaryEndpoint::new(SECRET_HTTP_ROUTE, secret_publish_handler)
                    .expect("secret publish endpoint");
            assert_eq!(secret_publish.evidence(), &SECRET_HTTP_SPEC.route);

            let secret_resolve =
                GeneratedPrimaryEndpoint::new(SECRET_RESOLVE_HTTP_ROUTE, secret_resolve_handler)
                    .expect("secret resolve endpoint");
            assert_eq!(secret_resolve.evidence(), &SECRET_RESOLVE_HTTP_SPEC.route);

            let config_get =
                GeneratedPrimaryEndpoint::new(CONFIG_GET_HTTP_ROUTE, config_get_handler)
                    .expect("config get endpoint");
            assert_eq!(config_get.evidence(), &CONFIG_GET_HTTP_SPEC.route);

            let config_delete = GeneratedPrimaryEndpoint::new_producer(
                CONFIG_DELETE_PRODUCER,
                config_delete_handler,
            )
            .expect("config delete endpoint");
            assert_eq!(config_delete.evidence(), &CONFIG_DELETE_HTTP_SPEC.route);

            let config_rollback = GeneratedPrimaryEndpoint::new_producer(
                CONFIG_ROLLBACK_PRODUCER,
                config_rollback_handler,
            )
            .expect("config rollback endpoint");
            assert_eq!(config_rollback.evidence(), &CONFIG_ROLLBACK_HTTP_SPEC.route);
        }
    }

    #[test]
    fn settings_production_uses_atomic_generated_endpoint_funnel() {
        let source = include_str!("application.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(source);

        assert_eq!(
            production.matches("GeneratedPrimaryEndpoint::new(").count(),
            3
        );
        assert_eq!(
            production
                .matches("GeneratedPrimaryEndpoint::new_producer(")
                .count(),
            5
        );
        assert_eq!(production.matches("rb.mount(").count(), 8);
        assert!(!production.contains("mount_primary("));
        assert!(!production.contains("PrimaryRoute"));
        assert!(!production.contains("RoutePermission"));
        assert!(!production.contains("RouteResourceScope"));
        assert!(!production.contains("HttpAuthMode"));
        assert!(!production.contains("axum::routing::on("));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_handler_authed_returns_201_and_emits_fact() {
        let capture = CapturingEmitter::default();
        let svc = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let router = config_router(svc, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/configs").json(&publish_req("app.timeout", "30s")),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::CREATED).expect("201");
        let decoded: SettingsConfigPublishResponse = resp.json().expect("json");
        assert_eq!(decoded.data.key, "app.timeout");
        assert_eq!(decoded.data.version, 1, "首次发布 = v1");
        assert_eq!(emitted_facts(&capture).len(), 1, "co-tx 发一次 outbox fact");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_handler_missing_auth_returns_401() {
        let capture = CapturingEmitter::default();
        let svc = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let router = config_router(svc, None);
        let resp = testkit::call(
            router,
            ContractRequest::post("/configs").json(&publish_req("app.k", "v")),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::UNAUTHORIZED)
            .expect("缺认证证据 → 401");
        assert_eq!(emitted_facts(&capture).len(), 0, "未认证 → 零写");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_body_limit_and_provider_failure_are_413_and_400_without_write() {
        use futures::stream;
        use tower::ServiceExt as _;

        for (body, expected) in [
            (
                Body::from(vec![b'x'; MAX_CONFIG_BODY_BYTES + 1]),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                Body::from_stream(stream::once(async {
                    Err::<Bytes, _>(std::io::Error::other("body provider failed"))
                })),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let capture = CapturingEmitter::default();
            let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
            let response = config_router(service, Some(user_evidence(tenant())))
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/configs")
                        .body(body)
                        .expect("request"),
                )
                .await
                .expect("router response");

            assert_eq!(response.status(), expected);
            assert!(
                emitted_facts(&capture).is_empty(),
                "body 读取失败不得进入 co-tx"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_get_delete_and_rollback_handlers_serve_typed_contracts() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish v1");
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v2"),
            )
            .await
            .expect("publish v2");
        let router = config_resource_router(Arc::clone(&service), Some(user_evidence(tenant())));

        let get_response = testkit::call(router.clone(), ContractRequest::get("/configs/app.k"))
            .await
            .expect("get call");
        get_response.ensure_status(StatusCode::OK).expect("200");
        let get_body: SettingsConfigGetResponse = get_response.json().expect("get json");
        assert_eq!(get_body.data.key, "app.k");
        assert_eq!(get_body.data.value, "v2");
        assert_eq!(get_body.data.version, 2);

        let rollback_response = testkit::call(
            router.clone(),
            ContractRequest::post("/configs/app.k/rollbacks").json(
                &SettingsConfigRollbackRequest {
                    to_version: std::num::NonZeroU64::new(1).expect("non-zero"),
                },
            ),
        )
        .await
        .expect("rollback call");
        rollback_response
            .ensure_status(StatusCode::CREATED)
            .expect("201");
        let rollback_body: SettingsConfigRollbackResponse =
            rollback_response.json().expect("rollback json");
        assert_eq!(rollback_body.data.key, "app.k");
        assert_eq!(rollback_body.data.version, 3);
        assert_eq!(rollback_body.data.source_version, 1);

        let delete_response =
            testkit::call(router.clone(), ContractRequest::delete("/configs/app.k"))
                .await
                .expect("delete call");
        delete_response
            .ensure_status(StatusCode::NO_CONTENT)
            .expect("204");
        let repeat_delete =
            testkit::call(router.clone(), ContractRequest::delete("/configs/app.k"))
                .await
                .expect("repeat delete");
        repeat_delete
            .ensure_status(StatusCode::NO_CONTENT)
            .expect("idempotent 204");
        assert_eq!(
            emitted_facts(&capture).len(),
            4,
            "two publishes, rollback, and only the first delete emit"
        );

        let missing = testkit::call(router, ContractRequest::get("/configs/app.k"))
            .await
            .expect("get deleted");
        missing
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("deleted is 404");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_rollback_body_limit_and_provider_failure_are_413_and_400_without_write() {
        use futures::stream;
        use tower::ServiceExt as _;

        for (body, expected) in [
            (
                Body::from(vec![b'x'; MAX_CONFIG_BODY_BYTES + 1]),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                Body::from_stream(stream::once(async {
                    Err::<Bytes, _>(std::io::Error::other("body provider failed"))
                })),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let capture = CapturingEmitter::default();
            let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
            service
                .publish_config(
                    publish_receipt(),
                    tenant(),
                    actor(),
                    publish_req("app.k", "v1"),
                )
                .await
                .expect("seed v1");
            let response =
                config_resource_router(Arc::clone(&service), Some(user_evidence(tenant())))
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/configs/app.k/rollbacks")
                            .body(body)
                            .expect("request"),
                    )
                    .await
                    .expect("router response");

            assert_eq!(response.status(), expected);
            assert_eq!(
                emitted_facts(&capture).len(),
                1,
                "body 读取失败不得产生 rollback fact"
            );
            assert_eq!(
                service
                    .config_query_service()
                    .get_config(tenant(), "app.k")
                    .await
                    .expect("read current")
                    .map(|entry| entry.version()),
                Some(1),
                "body 读取失败不得提交新版本"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_resource_handlers_reject_bad_input_missing_source_and_missing_auth() {
        let capture = CapturingEmitter::default();
        let service = Arc::new(service_with(&capture, InMemFlagStore::new()));
        service
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish");
        let authed = config_resource_router(Arc::clone(&service), Some(user_evidence(tenant())));

        let invalid_key = testkit::call(authed.clone(), ContractRequest::get("/configs/nodot"))
            .await
            .expect("invalid key get");
        invalid_key
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("path key is validated by the domain funnel");

        let invalid = testkit::call(
            authed.clone(),
            ContractRequest::post("/configs/app.k/rollbacks")
                .json(&serde_json::json!({"toVersion": 0})),
        )
        .await
        .expect("invalid rollback");
        invalid
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("zero source version is 400");

        let missing_source = testkit::call(
            authed,
            ContractRequest::post("/configs/app.k/rollbacks").json(
                &SettingsConfigRollbackRequest {
                    to_version: std::num::NonZeroU64::new(9).expect("non-zero"),
                },
            ),
        )
        .await
        .expect("missing rollback source");
        missing_source
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("missing source is 404");

        let unauthenticated = config_resource_router(service, None);
        for request in [
            ContractRequest::get("/configs/app.k"),
            ContractRequest::delete("/configs/app.k"),
            ContractRequest::post("/configs/app.k/rollbacks").json(
                &SettingsConfigRollbackRequest {
                    to_version: std::num::NonZeroU64::new(1).expect("non-zero"),
                },
            ),
        ] {
            let response = testkit::call(unauthenticated.clone(), request)
                .await
                .expect("unauthenticated call");
            response
                .ensure_status(StatusCode::UNAUTHORIZED)
                .expect("missing AuthorizedSubject is 401");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_rollback_handler_maps_cas_conflict_and_get_is_tenant_scoped() {
        struct ConflictUnitOfWork;

        impl ConfigUnitOfWork for ConflictUnitOfWork {
            async fn commit_publish(
                &self,
                _receipt: ConfigPublishReceipt,
                _scope: TenantRepoScope,
                _mutation: ConfigMutation,
                _event: ReviewedEvent,
            ) -> Result<(), ConfigRepoError> {
                Err(ConfigRepoError::VersionConflict)
            }

            async fn commit_delete(
                &self,
                _receipt: ConfigDeleteReceipt,
                _scope: TenantRepoScope,
                _mutation: ConfigMutation,
                _event: ReviewedEvent,
            ) -> Result<(), ConfigRepoError> {
                Err(ConfigRepoError::VersionConflict)
            }

            async fn commit_rollback(
                &self,
                _receipt: ConfigRollbackReceipt,
                _scope: TenantRepoScope,
                _mutation: ConfigMutation,
                _event: ReviewedEvent,
            ) -> Result<(), ConfigRepoError> {
                Err(ConfigRepoError::VersionConflict)
            }
        }

        let store = new_config_store();
        let capture = CapturingEmitter::default();
        let writer = SettingsService::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store.clone(), capture)),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        );
        writer
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("seed v1");

        let conflict_service = Arc::new(SettingsService::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store)),
            DynConfigUnitOfWork::new_box(ConflictUnitOfWork),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        ));
        let tenant_b_router = config_resource_router(
            Arc::clone(&conflict_service),
            Some(user_evidence(tenant_b())),
        );
        let cross_tenant = testkit::call(tenant_b_router, ContractRequest::get("/configs/app.k"))
            .await
            .expect("cross-tenant get");
        cross_tenant
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("other tenant cannot see config");

        let tenant_a_router =
            config_resource_router(conflict_service, Some(user_evidence(tenant())));
        let conflict = testkit::call(
            tenant_a_router,
            ContractRequest::post("/configs/app.k/rollbacks").json(
                &SettingsConfigRollbackRequest {
                    to_version: std::num::NonZeroU64::new(1).expect("non-zero"),
                },
            ),
        )
        .await
        .expect("conflicting rollback");
        conflict
            .ensure_status(StatusCode::CONFLICT)
            .expect("CAS conflict is 409");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_handler_actor_id_overflow_returns_500_not_forbidden() {
        let capture = CapturingEmitter::default();
        let svc = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let router = config_router(
            svc,
            Some(user_evidence_with_subject(tenant(), "x".repeat(257))),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/configs").json(&publish_req("app.k", "v")),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::INTERNAL_SERVER_ERROR)
            .expect("actor id invariant mismatch → 500");
        assert_eq!(emitted_facts(&capture).len(), 0, "actor 派生失败 → 零写");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_bytes_invalid_json_returns_400() {
        let capture = CapturingEmitter::default();
        let svc = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let resp = config_publish_handler_bytes(
            svc,
            publish_receipt(),
            tenant(),
            actor(),
            axum::body::Bytes::from_static(b"not json"),
            "rid",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_publish_bytes_invalid_key_returns_400() {
        let capture = CapturingEmitter::default();
        let svc = Arc::new(service_with(&capture, InMemFlagStore::new()));
        let body = serde_json::to_vec(&publish_req("bad key", "v")).expect("serialize");
        let resp = config_publish_handler_bytes(
            svc,
            publish_receipt(),
            tenant(),
            actor(),
            body.into(),
            "rid",
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "非法 key → 400 Validation"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_error_response_maps_status_codes() {
        let cases = [
            (SettingsServiceError::InvalidKey, StatusCode::BAD_REQUEST),
            (
                SettingsServiceError::PercentageOutOfRange,
                StatusCode::BAD_REQUEST,
            ),
            (SettingsServiceError::VersionConflict, StatusCode::CONFLICT),
            (
                SettingsServiceError::OutboxFactConflict(consistency::OutboxFactConflict),
                StatusCode::CONFLICT,
            ),
            (SettingsServiceError::NotFound, StatusCode::NOT_FOUND),
            (
                SettingsServiceError::ConfigReadIntegrity,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                SettingsServiceError::EnvelopeIdentity(diport::EnvelopeIdentityError::Empty),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(
                config_error_response(&err, tenant(), "rid", &CONFIG_HTTP_SPEC, "config_publish",)
                    .status(),
                want,
                "{err:?} → {want}"
            );
        }

        for (err, want_code, want_retryable) in [
            (
                SettingsServiceError::VersionConflict,
                "ERR_CORE_VERSION_CONFLICT",
                true,
            ),
            (
                SettingsServiceError::OutboxFactConflict(consistency::OutboxFactConflict),
                "ERR_CORE_OUTBOX_FACT_CONFLICT",
                false,
            ),
        ] {
            let response =
                config_error_response(&err, tenant(), "rid", &CONFIG_HTTP_SPEC, "config_publish");
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("collect error body");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("parse error body");
            assert_eq!(json["error"]["code"], want_code);
            assert_eq!(json["error"]["retryable"], want_retryable);
            let rendered = String::from_utf8_lossy(&body);
            assert!(!rendered.contains("payload"));
            assert!(!rendered.contains("fingerprint"));
        }
    }

    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse(TENANT_B).expect("canonical uuid")
    }

    // cross-tenant 隔离：tenant_a publish "app.k"，tenant_b get_config("app.k")==None。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_isolation() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "secret"),
        )
        .await
        .expect("tenant_a publish");
        let val = svc
            .config_query_service()
            .get_config(tenant_b(), "app.k")
            .await
            .expect("tenant_b get");
        assert!(val.is_none(), "跨租户隔离：tenant_b 不应读到 tenant_a 的值");
    }

    // event_id (idem_key) 派生稳定性：同 tenant/key/version → 同 idem-key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn event_id_derivation_is_stable() {
        // 两个独立 service 实例对同 tenant+key publish v1，idem-key 应相同（内容派生）。
        let cap1 = CapturingEmitter::default();
        let svc1 = service_with(&cap1, InMemFlagStore::new());
        let cap2 = CapturingEmitter::default();
        let svc2 = service_with(&cap2, InMemFlagStore::new());

        svc1.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.timeout", "30s"),
        )
        .await
        .expect("svc1 publish");
        svc2.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.timeout", "30s"),
        )
        .await
        .expect("svc2 publish");

        let facts1 = emitted_facts(&cap1);
        let facts2 = emitted_facts(&cap2);
        assert_eq!(facts1.len(), 1);
        assert_eq!(facts2.len(), 1);
        assert_eq!(
            facts1[0].idem, facts2[0].idem,
            "同 tenant/key/version 应产生相同 idem-key（去重锚点）"
        );
        // 断言 idem-key 格式包含 topic:tenant:key:vN。
        let eid = &facts1[0].idem;
        assert!(
            eid.contains(VERSION_CHANGED_SPEC.topic()),
            "idem 含 topic: {eid}"
        );
        assert!(eid.contains(TENANT), "idem 含 tenant: {eid}");
        assert!(eid.contains("app.timeout"), "idem 含 key: {eid}");
        assert!(eid.contains("v1"), "idem 含版本: {eid}");
    }

    // wire_version 溢出收口：u64::MAX → i64::MAX。
    #[test]
    fn wire_version_clamps_on_overflow() {
        assert_eq!(wire_version(u64::MAX), i64::MAX);
        assert_eq!(wire_version(0), 0);
        assert_eq!(wire_version(42), 42);
    }

    // invalid-key 测试：rollback 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .rollback(rollback_receipt(), tenant(), actor(), "nodot", 1)
            .await
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：get_config 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn get_config_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .config_query_service()
            .get_config(tenant(), "nodot")
            .await
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：delete 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .delete(delete_receipt(), tenant(), actor(), "nodot")
            .await
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // delete 后底层 find_version 断言已清除 + 不存在 key delete 幂等。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_hides_value_and_is_idempotent() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("publish");

        // 软删（tombstone）。
        svc.delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("delete");

        // get_config 已是 None（latest 为 tombstone）。
        assert!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .expect("get")
                .is_none()
        );

        // 再次 delete 应幂等（latest 已 tombstone → no-op，返回 Ok）。
        svc.delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("幂等 delete");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn idempotent_delete_clears_stale_cache_after_other_instance_deleted() {
        let store = new_config_store();
        let capture = CapturingEmitter::default();
        let make_service = || {
            SettingsService::with_postgres(
                DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
                DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                    store.clone(),
                    capture.clone(),
                )),
                FlagStoreBox(Box::new(InMemFlagStore::new())),
                Box::new(FixedClock(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
                )),
            )
        };
        let writer = make_service();
        let stale_reader = make_service();

        writer
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("prime stale cache"),
            Some("v1".to_string())
        );
        writer
            .delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("first instance delete");

        stale_reader
            .delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("idempotent delete");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("read after idempotent delete"),
            None
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn authoritative_reads_refresh_cross_instance_cache_without_events() {
        let store = new_config_store();
        let capture = CapturingEmitter::default();
        let make_service = || {
            SettingsService::with_postgres(
                DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
                DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                    store.clone(),
                    capture.clone(),
                )),
                FlagStoreBox(Box::new(InMemFlagStore::new())),
                Box::new(FixedClock(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
                )),
            )
        };
        let writer = make_service();
        let stale_reader = make_service();

        writer
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish v1");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("prime cache"),
            Some("v1".to_string())
        );

        writer
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v2"),
            )
            .await
            .expect("publish v2");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("read after remote publish"),
            Some("v2".to_string()),
            "cache is an optimization: reads must validate the authoritative revision"
        );

        writer
            .rollback(rollback_receipt(), tenant(), actor(), "app.k", 1)
            .await
            .expect("rollback to v1");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("read after remote rollback"),
            Some("v1".to_string())
        );

        writer
            .delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("remote delete");
        assert_eq!(
            stale_reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("read after remote delete"),
            None
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn authoritative_read_failure_never_falls_back_to_cached_value() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct HeadFailureRepo {
            inner: InMemConfigRepo,
            fail_head: Arc<AtomicBool>,
        }

        impl ConfigRepo for HeadFailureRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find(scope, key).await
            }

            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find_version(scope, key, version).await
            }

            async fn head(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigHead>, ConfigRepoError> {
                if self.fail_head.load(Ordering::SeqCst) {
                    return Err(ConfigRepoError::Storage(Box::new(std::io::Error::other(
                        "head unavailable",
                    ))));
                }
                self.inner.head(scope, key).await
            }
        }

        let store = new_config_store();
        let capture = CapturingEmitter::default();
        let writer = SettingsService::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(
                store.clone(),
                capture.clone(),
            )),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        );
        let fail_head = Arc::new(AtomicBool::new(false));
        let reader = SettingsService::with_postgres(
            DynConfigRepo::new_box(HeadFailureRepo {
                inner: InMemConfigRepo::from_shared(store.clone()),
                fail_head: Arc::clone(&fail_head),
            }),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture)),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(SystemTime::UNIX_EPOCH)),
        );

        writer
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish");
        assert_eq!(
            reader
                .config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("prime cache"),
            Some("v1".to_string())
        );

        fail_head.store(true, Ordering::SeqCst);
        let error = reader
            .config_query_service()
            .get_config(tenant(), "app.k")
            .await
            .expect_err("authoritative failure must be visible");
        assert!(matches!(error, SettingsServiceError::Storage(_)));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn concurrent_delete_converges_after_losing_tombstone_cas() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DeleteBarrierConfigRepo {
            inner: InMemConfigRepo,
            barrier: tokio::sync::Barrier,
            head_reads: AtomicUsize,
        }

        impl ConfigRepo for DeleteBarrierConfigRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find(scope, key).await
            }

            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find_version(scope, key, version).await
            }

            async fn head(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigHead>, ConfigRepoError> {
                let result = self.inner.head(scope, key).await;
                if matches!(self.head_reads.fetch_add(1, Ordering::SeqCst), 1 | 2) {
                    self.barrier.wait().await;
                }
                result
            }
        }

        let capture = CapturingEmitter::default();
        let store = new_config_store();
        let svc = SettingsService::with_postgres(
            DynConfigRepo::new_box(DeleteBarrierConfigRepo {
                inner: InMemConfigRepo::from_shared(store.clone()),
                barrier: tokio::sync::Barrier::new(2),
                head_reads: AtomicUsize::new(0),
            }),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        );
        svc.publish_config(
            publish_receipt(),
            tenant(),
            actor(),
            publish_req("app.k", "v1"),
        )
        .await
        .expect("publish");

        let (first, second) = tokio::join!(
            svc.delete(delete_receipt(), tenant(), actor(), "app.k"),
            svc.delete(delete_receipt(), tenant(), actor(), "app.k"),
        );
        first.expect("first delete");
        second.expect("second delete converges to tombstone");
        assert!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .expect("get")
                .is_none()
        );
        assert_eq!(
            emitted_facts(&capture).len(),
            2,
            "publish and the single winning delete each emit one fact"
        );
    }

    // F1 回归（service 层）：delete 软删后 republish **不重置版本**——next_version 经 latest_version（含
    // tombstone），故 publish v1 → delete(tombstone v2) → publish 得 v3（而非 v1），event_id 不复用。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_republish_continues_version_not_reset() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let v1 = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1"),
            )
            .await
            .expect("publish v1");
        assert_eq!(v1.data.version, 1);

        svc.delete(delete_receipt(), tenant(), actor(), "app.k")
            .await
            .expect("delete");

        // republish：版本继续递增（v1 + tombstone v2 → v3），**非**重置回 1。
        let v3 = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "v1-again"),
            )
            .await
            .expect("republish");
        assert_eq!(
            v3.data.version, 3,
            "delete 软删后 republish 版本应继续（v3），不重置回 1"
        );
        assert_eq!(
            svc.config_query_service()
                .get_config(tenant(), "app.k")
                .await
                .map(config_value)
                .expect("get"),
            Some("v1-again".to_string()),
            "republish 后活跃值恢复"
        );

        // 发射事实：publish v1 + delete v2 + republish v3，三次 mutation 均有 co-tx fact。
        let facts = emitted_facts(&capture);
        assert_eq!(
            facts.len(),
            3,
            "publish/delete/republish 三次 mutation 各发一条 fact"
        );
        assert_eq!(facts[0].payload.version, 1);
        assert_eq!(facts[1].payload.version, 2);
        assert_eq!(
            facts[1].payload.change_kind,
            SettingsConfigChangeKind::Deleted
        );
        assert_eq!(
            facts[2].payload.version, 3,
            "republish 事件版本 = 3（新 event_id）"
        );
        assert_ne!(
            facts[0].idem, facts[2].idem,
            "delete+republish 的 event_id 不复用"
        );
    }

    // 多 key 独立版本：publish "app.a" 与 "app.b" 各 v1，两者 version 均为 1。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn multiple_keys_have_independent_versions() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let resp_a = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.a", "val-a"),
            )
            .await
            .expect("publish a");
        let resp_b = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.b", "val-b"),
            )
            .await
            .expect("publish b");

        assert_eq!(resp_a.data.version, 1, "app.a 应从 v1 开始");
        assert_eq!(resp_b.data.version, 1, "app.b 应从 v1 开始，与 app.a 独立");
    }

    // F2：service 层并发 CAS 回归——两个并发 publish 同 key，恰一个成功一个 VersionConflict，只发一条 fact。
    // barrier 迫使两个 publish 都读到同版本（latest_version=None）后再各自 save，制造 read-then-write 竞争。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn concurrent_publish_same_key_one_wins_one_conflicts() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // next_version 经 latest_version 读版本——前 2 次在 barrier(2) 同步；后续直通（避免末尾死锁）。
        struct BarrierConfigRepo {
            inner: InMemConfigRepo,
            barrier: tokio::sync::Barrier,
            version_reads: AtomicUsize,
        }
        impl ConfigRepo for BarrierConfigRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find(scope, key).await
            }
            async fn find_version(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find_version(scope, key, version).await
            }
            async fn head(
                &self,
                scope: TenantRepoScope,
                key: &SettingKey,
            ) -> Result<Option<ConfigHead>, ConfigRepoError> {
                let result = self.inner.head(scope, key).await;
                if self.version_reads.fetch_add(1, Ordering::SeqCst) < 2 {
                    self.barrier.wait().await;
                }
                result
            }
        }

        let capture = CapturingEmitter::default();
        // 读端口（barrier-wrapped）与写 UoW 共享同一 store：barrier 同步两 find（皆读 None）后，各自经
        // writer.commit 对共享 store CAS，制造 read-then-write 竞争（恰一胜一冲突）。
        let store = new_config_store();
        let svc = SettingsService::with_postgres(
            DynConfigRepo::new_box(BarrierConfigRepo {
                inner: InMemConfigRepo::from_shared(store.clone()),
                barrier: tokio::sync::Barrier::new(2),
                version_reads: AtomicUsize::new(0),
            }),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        );

        // 单任务 join! 并发：两 future 都在 barrier 处 yield，同步后各自 save（CAS 竞争）。
        let (r1, r2) = tokio::join!(
            svc.publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "a")
            ),
            svc.publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.k", "b")
            ),
        );

        let results = [r1, r2];
        let oks = results.iter().filter(|r| r.is_ok()).count();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Err(SettingsServiceError::VersionConflict)))
            .count();
        assert_eq!(oks, 1, "并发 publish 同 key 恰一个成功");
        assert_eq!(conflicts, 1, "另一个应 VersionConflict（CAS 守住）");

        // 失败方在 save 冲突后不发射 ⇒ 恰一条 outbox fact。
        assert_eq!(
            emitted_facts(&capture).len(),
            1,
            "并发只发一条 outbox fact（write-without-event 不发生）"
        );

        // 最终活跃版本是某个胜者的值（v1）。
        let val = svc
            .config_query_service()
            .get_config(tenant(), "app.k")
            .await
            .map(config_value)
            .expect("get");
        assert!(
            val == Some("a".to_string()) || val == Some("b".to_string()),
            "最终值是某个胜者的值"
        );
    }

    // ---------------------------------------------------------------------------
    // with_postgres 构造器 + empty_flag_store 工厂签名锁（fn-pointer smoke）
    // ---------------------------------------------------------------------------

    /// `with_postgres` 接受 in-mem box 后可正常 publish v1（end-to-end 构造器 smoke）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn with_postgres_constructs_and_publishes() {
        let store = new_config_store();
        let capture = CapturingEmitter::default();
        let svc = SettingsService::with_postgres(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            FlagStoreBox(Box::new(InMemFlagStore::new())),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        );
        let resp = svc
            .publish_config(
                publish_receipt(),
                tenant(),
                actor(),
                publish_req("app.smoke", "v1-value"),
            )
            .await
            .expect("publish ok");
        assert_eq!(resp.data.version, 1);
        assert_eq!(resp.data.key, "app.smoke");

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 1, "with_postgres 路径应发射一条 outbox fact");
        assert_eq!(facts[0].payload.version, 1);
    }

    /// `with_postgres` 函数指针签名锁（fn-pointer 不调用 body，仅断言签名稳定）。
    #[test]
    #[allow(clippy::type_complexity)]
    // incidental: 预存 type_complexity（函数指针类型用于签名锁定测试，不可拆分为 type alias 而不改变语义）。
    fn with_postgres_fn_pointer_locks_signature() {
        let _lock: fn(
            Box<DynConfigRepo<'static>>,
            Box<DynConfigUnitOfWork<'static>>,
            FlagStoreBox,
            Box<dyn Clock>,
        ) -> SettingsService = SettingsService::with_postgres;
        let _ = _lock;
    }

    /// `empty_flag_store` 函数指针签名锁（fn-pointer smoke）。
    #[test]
    fn empty_flag_store_fn_pointer_locks_signature() {
        let _lock: fn() -> FlagStoreBox = crate::empty_flag_store;
        let _ = _lock;
    }
}
