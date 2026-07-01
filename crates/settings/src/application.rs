//! settings 应用层：版本化配置 CRUD/CAS + 发布/回滚（L2 OutboxFact）+ feature flag 求值编排。
//!
//! 配置写入路径证明 L2 接缝：CAS upsert 新版本 + outbox append 经 [`crate::ports::ConfigUnitOfWork`]
//! **同事务**原子落库（both-or-neither，消除 emit-after-save 的 write-without-event 窗口，#1232；in-mem 共享
//! store 替身 / 生产 postgres `PgConfigUnitOfWork`）→ 返回新版本。读路径（next_version / get_value /
//! rollback 源值）经 [`crate::ports::ConfigRepo`]。发布与回滚复用同一 fact，`changeKind` 判别（published /
//! rolledBack）。flag 求值经域内
//! [`crate::internal::ports::FlagStore`] 取快照 + `domain::evaluate_flag`（L0 纯计算）。
//!
//! HTTP 接缝（#1430 PERSIST-009 settings 首条 durable module 闭环）：[`SettingsDomain`] 持 config + secret
//! 应用服务，`init` 经 typed `route_group::<Primary>` + `mount_primary`（`ListenerRouter<Primary>` 方法，
//! #1113/#1103 typed route funnel）从 generated SPEC 挂 `settings.config-publish` / `settings.secret-publish`
//! 两条认证路由（鉴权 = permission，租户来自 route gate 注入的 [`httpserve::AuthorizedSubject`]、非 pre-auth header）。
//! 域错误经 generic `vocab::CoreErrorKind` 映射状态码（4xx 客户端 / 5xx 内部，不铸 `ERR_SETTINGS_` 命名空间）。
//!
//! ref: Unleash/unleash-types-rs src/client_features.rs@main（flag 求值语义）
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型）
//! ref: crates/identity/src/application.rs（L2 OutboxFact 经 OutboxEmitter 落 durable outbox 范式，#1100）

use std::sync::Arc;
use std::time::SystemTime;

use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, OutboxPayload, Topic};
use diport::{Clock, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEnvelopeParts};
use generated::event::settings_v1::{
    CONTRACT, SettingsConfigChangeKind, SettingsConfigVersionChangedPayload,
    TOPIC as VERSION_CHANGED_TOPIC,
};
use generated::http::HttpAuthMode;
use generated::http::settings_v1::{
    SPEC as CONFIG_HTTP_SPEC, SettingsConfigPublishData, SettingsConfigPublishRequest,
    SettingsConfigPublishResponse,
};
use generated::http::settings_v2::SPEC as SECRET_HTTP_SPEC;
use httpserve::{AuthorizedSubject, Primary, PrimaryRoute, RoutePermission, RouteResourceScope};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use primitives::RouteAuthOptOut;
use vocab::{CoreError, CoreErrorKind, TenantId};

use crate::secret_application::secret_publish_handler;

use crate::domain::{
    ConfigEntry, ConfigRepoError, ConfigValue, ConfigVersion, EvalContext, FlagDecision, FlagKey,
    SettingKey, SettingsError, evaluate_flag,
};
#[cfg(any(test, feature = "seed-data"))]
use crate::internal::mem::{
    InMemConfigRepo, InMemConfigUnitOfWork, InMemFlagStore, new_config_store,
};
use crate::internal::ports::FlagStore;
use crate::ports::{
    ConfigRepo, ConfigUnitOfWork, DynConfigRepo, DynConfigUnitOfWork, DynSecretRepo,
};

/// 配置路由组前缀（Primary listener，业务 API）。
pub const SETTINGS_ROUTE_PREFIX: &str = "/api/v1/settings";

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
    /// 目标配置 / 版本不存在（回滚源缺失）。
    #[error("config entry not found")]
    NotFound,
    /// 灰度百分比超出 0..=100 范围。
    #[error("percentage out of range; must be 0..=100")]
    PercentageOutOfRange,
    /// config-version-changed payload 编码失败（原始错误进 source，不进 Display）。
    #[error("config-version-changed payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// outbox Entry 构造失败（topic / idem-key 形态非法——programmer error，topic/event_id 内部派生）。
    #[error("config-version-changed outbox entry build failed")]
    EntryBuild,
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

/// settings 应用服务。必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）。
///
/// 读路径经 [`ConfigRepo`]（`configs`）；写路径（publish / rollback）经 **co-tx** [`ConfigUnitOfWork`]
/// （`writer`）——CAS 配置写 + outbox append 同事务原子（#1232），消除「先 save 后 emit」write-without-event
/// 窗口（旧 emitter 字段已删除，发射收口进 `writer`）。
pub struct SettingsService {
    configs: Box<DynConfigRepo<'static>>,
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
        Self {
            configs,
            writer,
            flags: flags.0,
            clock,
        }
    }

    /// 构造（必填位置参注入读仓储 + 写 co-tx UoW + clock）。`pub(crate)`：`flags` 为域内 [`FlagStore`]，不外泄；
    /// 开发 / 测试经 `with_seed`（in-mem）构造；生产组合根经 [`Self::with_postgres`] 注入真实 postgres adapter。
    #[cfg(any(test, feature = "seed-data"))]
    pub(crate) fn new(
        configs: Box<DynConfigRepo<'static>>,
        writer: Box<DynConfigUnitOfWork<'static>>,
        flags: Box<dyn FlagStore>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            configs,
            writer,
            flags,
            clock,
        }
    }

    /// 组合根构造：注入 outbox emitter + clock，以空 in-mem 配置 / flag 仓储初始化（追踪弹 / demo）。
    ///
    /// 门控于 `test` / `seed-data` feature（编译期边界，对标 identity seed-login）：生产组合根不启用即无
    /// in-mem provider 路径。组合根（journeys）经 `settings = { features = ["seed-data"] }` 启用 + 注入
    /// `memory::MemEmitter`。读端口 [`InMemConfigRepo`] 与写 UoW [`InMemConfigUnitOfWork`] 经 `Arc` **共享同一
    /// store**——`find` 读得到 `save_and_append_outbox` 写入。真实持久化（postgres adapter）留 Join。
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
        Self::new(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, emitter)),
            Box::new(InMemFlagStore::new()),
            clock,
        )
    }

    /// 当前 key 的下一版本号（无历史 → 1）。
    async fn next_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<u64, SettingsServiceError> {
        // 真实最高版本（含 tombstone）+ 1——delete 软删后 version 单调不重置，防 event_id 复用（#1249 F1）。
        // 用 `latest_version` 而非 `find`：`find` 排除 tombstone，删后返 `None` 会误回 v1 → 复用旧 event_id。
        let current = self.configs.latest_version(tenant, key).await?;
        Ok(current.map_or(1, |v| v + 1))
    }

    /// 构造 `config-version-changed` outbox [`Entry`] + [`OutboxEnvelopeParts`]（纯派生，无 I/O）；实际落
    /// durable outbox 与配置写**同事务**由 [`ConfigUnitOfWork::save_and_append_outbox`] 承载（L2 OutboxFact）。
    ///
    /// EventId（outbox `event_id` / `IdemKey`）= 内容派生 `{topic}:{tenant}:{key}:v{version}`：每个
    /// (tenant, key, version) 仅一次发射（version 单调递增，publish/rollback 各产新版本），故按内容确定唯一——
    /// 重试同版本产同锚点，经 relay 盖章 broker message_id 流回消费侧实现「至少一次 + 幂等」端到端去重（#1100）。
    /// tenant 是可观测标识（非凭据，ADR-002）；key 是 opaque 配置标识（非 value，无 secret）。
    fn build_version_changed_entry(
        &self,
        key: &SettingKey,
        tenant: TenantId,
        actor: OutboxActor,
        version: u64,
        change_kind: SettingsConfigChangeKind,
        source_version: Option<u64>,
    ) -> Result<(Entry, OutboxEnvelopeParts), SettingsServiceError> {
        let payload = SettingsConfigVersionChangedPayload {
            change_kind,
            key: key.as_str().to_string(),
            occurred_at: unix_secs(self.clock.now()),
            source_version: source_version.map(wire_version),
            tenant_id: tenant.to_string(),
            version: wire_version(version),
        };
        let bytes = serde_json::to_vec(&payload).map_err(SettingsServiceError::PayloadEncode)?;
        let event_id = format!(
            "{VERSION_CHANGED_TOPIC}:{tenant}:{}:v{version}",
            key.as_str()
        );
        let entry = Entry::new(
            Topic::parse(VERSION_CHANGED_TOPIC).map_err(|_| SettingsServiceError::EntryBuild)?,
            IdemKey::parse(&event_id).map_err(|_| SettingsServiceError::EntryBuild)?,
            OutboxPayload::from_reviewed_event_bytes(bytes),
        );
        // 契约归属经 generated `CONTRACT`（domain + contract_id + version + schema_hash 同源绑定，#1193/#1618）；
        // subject = opaque 配置 key。
        let subject_id = EnvelopeSubjectId::from_opaque(key.as_str())
            .map_err(|_| SettingsServiceError::EntryBuild)?;
        let envelope = OutboxEnvelopeParts::new(CONTRACT, tenant, subject_id, actor);
        Ok((entry, envelope))
    }

    /// 写入新配置版本并发射 outbox fact（L2 OutboxFact）。CAS：读当前版本 → 写 +1；并发冲突冒泡 `VersionConflict`。
    ///
    /// `skip_all`：不记 `value`（可能含 secret）/ `key`；失败经 `err` 记 [`SettingsServiceError`] Display（无 PII）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn publish_config(
        &self,
        tenant: TenantId,
        actor: OutboxActor,
        request: SettingsConfigPublishRequest,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let key = SettingKey::parse(&request.key)?;
        let version = self.next_version(tenant, &key).await?;
        let entry = ConfigEntry::new(
            key.clone(),
            ConfigValue::new(request.value),
            tenant,
            ConfigVersion::new(version),
        );
        let (outbox_entry, envelope) = self.build_version_changed_entry(
            &key,
            tenant,
            actor,
            version,
            SettingsConfigChangeKind::Published,
            None,
        )?;
        // co-tx：CAS 配置写 + outbox append 同事务（both-or-neither）——冲突冒泡 `VersionConflict`，
        // 存储失败冒泡 `Storage`；二者皆使配置写与 outbox 行共回滚（消除 write-without-event 窗口）。
        self.writer
            .save_and_append_outbox(tenant, entry, outbox_entry, envelope)
            .await?;
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
        tenant: TenantId,
        actor: OutboxActor,
        key: &str,
        to_version: u64,
    ) -> Result<SettingsConfigPublishResponse, SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        let source = self
            .configs
            .find_version(tenant, &key, to_version)
            .await?
            .ok_or(SettingsServiceError::NotFound)?;
        let value = ConfigValue::new(source.value());
        let version = self.next_version(tenant, &key).await?;
        let entry = ConfigEntry::new(key.clone(), value, tenant, ConfigVersion::new(version));
        let (outbox_entry, envelope) = self.build_version_changed_entry(
            &key,
            tenant,
            actor,
            version,
            SettingsConfigChangeKind::RolledBack,
            Some(to_version),
        )?;
        // co-tx：回滚新版本写 + outbox append 同事务（both-or-neither）。源值（`find_version` 读历史行）
        // 不可变无 TOCTOU；新版本号（`next_version`）存在 read-then-write 窗口，由 CAS INSERT 守住——并发
        // 冲突返 `VersionConflict`，调用方读后重写重试。
        self.writer
            .save_and_append_outbox(tenant, entry, outbox_entry, envelope)
            .await?;
        Ok(SettingsConfigPublishResponse {
            data: SettingsConfigPublishData {
                key: key.as_str().to_string(),
                version: wire_version(version),
            },
        })
    }

    /// 读取 key 当前活跃配置值（不存在返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn get_value(
        &self,
        tenant: TenantId,
        key: &str,
    ) -> Result<Option<String>, SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        Ok(self
            .configs
            .find(tenant, &key)
            .await?
            .map(|entry| entry.value().to_string()))
    }

    /// 软删除 key（tombstone，幂等）：仓储在 `max+1` 追加 tombstone 版本 → version 单调不重置（防 event_id
    /// 复用，#1249 F1）；此后 `get_value` 返回 `None`，历史值仍可 `find_version` 读。
    ///
    /// **不发射删除事件**（已知 gap）：订阅缓存 consumer（flag 缓存 / 投影）感知删除的 `config-version-deleted`
    /// 事件留订阅缓存单元 #1120（同 `ports.rs` 注记）；届时 delete 亦走 co-tx writer 发 tombstone fact。
    #[tracing::instrument(skip_all, err, fields(tenant = %tenant))]
    pub async fn delete(&self, tenant: TenantId, key: &str) -> Result<(), SettingsServiceError> {
        let key = SettingKey::parse(key)?;
        self.configs.delete(tenant, &key).await?;
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

fn authenticated_actor(req: &Request<Body>) -> Result<(TenantId, OutboxActor), AuthReject> {
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
            contract_id = CONFIG_HTTP_SPEC.contract_id,
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

/// 从 generated SPEC 派生 [`PrimaryRoute`]（method / 相对 path / contract_id / opt_out 单源，杜绝手写漂移）。
/// 相对 path = SPEC 绝对 path 剥 [`SETTINGS_ROUTE_PREFIX`]（对标 identity `login_relative_path`）。
fn primary_route_from_spec(spec: &generated::http::HttpSpec) -> Result<PrimaryRoute, KernelError> {
    let rel = spec
        .path
        .strip_prefix(SETTINGS_ROUTE_PREFIX)
        .filter(|rel| rel.starts_with('/') && rel.len() > 1)
        .ok_or(KernelError::RouteGroup)?;
    let method = Method::from_bytes(spec.method.as_bytes()).map_err(|_| KernelError::RouteGroup)?;
    match spec.auth.mode {
        HttpAuthMode::Permission => {
            let permission = spec.auth.permission.ok_or(KernelError::RouteGroup)?;
            let scope = match (spec.resource, spec.self_scoped) {
                (Some(resource), false) => RouteResourceScope::PathParam(resource),
                (None, true) => RouteResourceScope::SelfSubject,
                (None, false) => RouteResourceScope::None,
                (Some(_), true) => return Err(KernelError::RouteGroup),
            };
            Ok(PrimaryRoute::permission(
                method,
                rel,
                spec.contract_id,
                RoutePermission { permission, scope },
            ))
        }
        HttpAuthMode::Public => Ok(PrimaryRoute::opt_out(
            method,
            rel,
            spec.contract_id,
            RouteAuthOptOut::Public,
        )),
        HttpAuthMode::Bootstrap | HttpAuthMode::ClientsOnly | HttpAuthMode::ServiceOwned => {
            Err(KernelError::RouteGroup)
        }
    }
}

/// `settings.config-publish` handler（Primary listener，JWT 认证）：route gate 授权证据取租户 → parse body →
/// `publish_config`（CAS 写 + outbox co-tx，L2）→ 201。租户来自 `AuthorizedSubject`，非 pre-auth header。
async fn config_publish_handler(
    State(service): State<Arc<SettingsService>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, actor) = match authenticated_actor(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let (_, body) = req.into_parts();
    let body = match to_bytes(body, MAX_CONFIG_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    config_publish_handler_bytes(service, tenant, actor, body, &request_id).await
}

/// config-publish 核心（tenant 已解析）：parse → service → typed 响应 / 错误映射。供单测直接驱动。
pub(crate) async fn config_publish_handler_bytes(
    service: Arc<SettingsService>,
    tenant: TenantId,
    actor: OutboxActor,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: SettingsConfigPublishRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    match service.publish_config(tenant, actor, request).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => config_error_response(&err, tenant, request_id),
    }
}

/// `SettingsServiceError` → wire 响应：generic [`CoreErrorKind`] 派生状态码（4xx 客户端 / 5xx 内部），
/// **不**铸 `ERR_SETTINGS_` 命名空间（复用 vocab 通用 kind）。5xx 记结构化 error（const message，无 PII；
/// `tenant_id` 是合法低基数可观测字段、非凭据，透传供跨租定位——对标 identity handler 错误日志）。
fn config_error_response(
    err: &SettingsServiceError,
    tenant: TenantId,
    request_id: &str,
) -> Response {
    let kind = match err {
        SettingsServiceError::InvalidKey | SettingsServiceError::PercentageOutOfRange => {
            CoreErrorKind::Validation
        }
        SettingsServiceError::VersionConflict => CoreErrorKind::Conflict,
        SettingsServiceError::NotFound => CoreErrorKind::NotFound,
        SettingsServiceError::PayloadEncode(_)
        | SettingsServiceError::EntryBuild
        | SettingsServiceError::ProtectionUnavailable(_)
        | SettingsServiceError::ProtectionAuthFailure(_)
        | SettingsServiceError::Storage(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            request_id,
            tenant_id = %tenant,
            contract_id = CONFIG_HTTP_SPEC.contract_id,
            operation = "config_publish",
            "settings config publish failed"
        );
    }
    httpserve::error::core_error_response(&CoreError::new(kind), request_id)
}

/// settings 域 bootstrap 生命周期：挂载 config-publish / secret-publish 业务路由（Primary listener）。
///
/// 持有 config 应用服务 + secret 仓储端口（构造器必填位置参注入，缺失即编译错误，rust-standards §工程护栏）；
/// `init` 经 typed `route_group::<Primary>` + `mount_primary` 从 generated SPEC 单源挂两条认证路由
/// （对标 identity `IdentityDomain`）。
///
/// secret 路由 State 持 `Arc<DynSecretRepo>`（而非 `SecretService`）：`SecretService` 含 `Box<DynSecretResolver>`
/// （diport infra 端口，ADR-003 Amendment #1095 故意 `Send` 非 `Sync`）⇒ 非 `Sync`、不可作 axum State；
/// publish 路径不需 resolver，故经仓储端口直挂（见 `secret_application::publish_secret_to_repo`）。
///
/// `configs_ready` 探针由组合根（`assemblies/runtime::wire_settings`）经 `DomainModuleResult` 注册——探针包
/// `PgDbReadiness`（adapter 类型，域 crate 不可依赖 adapter），故不在此声明（层序约束）。
pub struct SettingsDomain {
    config: Arc<SettingsService>,
    secret_repo: Arc<DynSecretRepo<'static>>,
}

impl SettingsDomain {
    /// 组合根构造：注入 config 应用服务 + secret 仓储端口（已装配域形 repo / UoW provider）。
    pub fn new(config: Arc<SettingsService>, secret_repo: Arc<DynSecretRepo<'static>>) -> Self {
        Self {
            config,
            secret_repo,
        }
    }
}

impl Domain for SettingsDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        let config = Arc::clone(&self.config);
        let secret_repo = Arc::clone(&self.secret_repo);
        reg.route_group::<Primary>(SETTINGS_ROUTE_PREFIX, move |rb| {
            let rb = rb.mount_primary(
                primary_route_from_spec(&CONFIG_HTTP_SPEC)?,
                post(config_publish_handler).with_state(config),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&SECRET_HTTP_SPEC)?,
                post(secret_publish_handler).with_state(secret_repo),
            );
            Ok(rb)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use diport::{OutboxEmitError, OutboxEmitter};

    use crate::domain::{FlagState, RolloutPercentage, RolloutRule};

    const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // 测试 helper：解析已知合法常量 —— expect item-level carve-out（error-handling.md §Carve-out）。
    #[allow(clippy::expect_used)]
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

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：OutboxEmitter / Clock 替身在此手写。
    #[derive(Clone, Default)]
    struct CapturingEmitter {
        emitted: Arc<Mutex<Vec<(Entry, OutboxEnvelopeParts)>>>,
    }
    impl OutboxEmitter for CapturingEmitter {
        async fn emit(
            &self,
            entry: Entry,
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
        SettingsService::new(
            DynConfigRepo::new_box(InMemConfigRepo::from_shared(store.clone())),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            Box::new(flags),
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

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_creates_v1_and_emits() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let resp = svc
            .publish_config(tenant(), actor(), publish_req("app.timeout", "30s"))
            .await
            .expect("publish ok");

        assert_eq!(resp.data.key, "app.timeout");
        assert_eq!(resp.data.version, 1);

        let facts = emitted_facts(&capture);
        assert_eq!(facts.len(), 1, "L2：每次 publish 恰发射一条 outbox entry");
        let fact = &facts[0];
        assert_eq!(fact.topic, VERSION_CHANGED_TOPIC);
        // envelope：域 / 契约 / opaque subject（config key）——域 + 契约同源 generated `CONTRACT`（#1193）。
        assert_eq!(fact.domain, CONTRACT.domain());
        assert_eq!(fact.contract_id, CONTRACT.contract_id());
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

        svc.publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        let resp = svc
            .publish_config(tenant(), actor(), publish_req("app.k", "v2"))
            .await
            .expect("v2");
        assert_eq!(resp.data.version, 2);
        assert_eq!(
            svc.get_value(tenant(), "app.k").await.expect("get"),
            Some("v2".to_string())
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_config_rejects_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc
            .publish_config(tenant(), actor(), publish_req("nodot", "v"))
            .await
            .expect_err("invalid key");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
        assert!(emitted_facts(&capture).is_empty(), "非法 key 不发射");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cas_conflict_on_stale_save() {
        // 直接对 repo 验 CAS：写 v1 后，再写 v1（陈旧版本号）→ VersionConflict。
        let repo = InMemConfigRepo::from_shared(new_config_store());
        let t = tenant();
        let key = SettingKey::parse("app.k").expect("key");
        let entry_v1 = ConfigEntry::new(
            key.clone(),
            ConfigValue::new("v1"),
            t,
            ConfigVersion::new(1),
        );
        repo.save(t, entry_v1).await.expect("v1 ok");
        let stale = ConfigEntry::new(key, ConfigValue::new("v1b"), t, ConfigVersion::new(1));
        assert!(matches!(
            repo.save(t, stale).await,
            Err(ConfigRepoError::VersionConflict)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_restores_value_and_emits_rolled_back() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        svc.publish_config(tenant(), actor(), publish_req("app.k", "v2"))
            .await
            .expect("v2");

        let resp = svc
            .rollback(tenant(), actor(), "app.k", 1)
            .await
            .expect("rollback");
        assert_eq!(resp.data.version, 3, "回滚生成新版本 v3");
        assert_eq!(
            svc.get_value(tenant(), "app.k").await.expect("get"),
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
        svc.publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        let err = svc
            .rollback(tenant(), actor(), "app.k", 9)
            .await
            .expect_err("missing version");
        assert!(matches!(err, SettingsServiceError::NotFound));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_removes_config() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("v1");
        svc.delete(tenant(), "app.k").await.expect("delete");
        assert_eq!(svc.get_value(tenant(), "app.k").await.expect("get"), None);
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

    /// in-mem secret 仓储端口（secret-publish 路由 State / SettingsDomain 构造替身）。
    fn secret_repo_arc() -> Arc<DynSecretRepo<'static>> {
        Arc::from(DynSecretRepo::new_box(InMemSecretRepo::from_shared(
            new_secret_store(),
        )))
    }

    /// 测试用 SettingsDomain 实例（config 服务 + secret 仓储端口，均 in-mem 替身）。
    fn settings_domain_for_test() -> SettingsDomain {
        let capture = CapturingEmitter::default();
        SettingsDomain::new(
            Arc::new(service_with(&capture, InMemFlagStore::new())),
            secret_repo_arc(),
        )
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
        let router =
            axum::Router::new().route("/configs", post(config_publish_handler).with_state(service));
        match auth {
            Some(a) => router.layer(axum::Extension(a)),
            None => router,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn settings_domain_declares_business_route_group() {
        let domain = settings_domain_for_test();
        let reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(
            groups.len(),
            1,
            "config + secret 同 /api/v1/settings 路由组"
        );
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, SETTINGS_ROUTE_PREFIX);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn primary_route_from_config_spec_derives_relative_path_no_optout() {
        let route = primary_route_from_spec(&CONFIG_HTTP_SPEC).expect("route");
        assert_eq!(
            route.path(),
            "/configs",
            "SPEC 绝对 path 剥前缀得相对挂载段"
        );
        assert_eq!(*route.method(), Method::POST);
        assert_eq!(route.contract_id(), "settings.config-publish");
        assert!(
            route.opt_out_kind().is_none(),
            "permission 模式无 opt-out 降级"
        );
        assert!(
            route.route_permission().is_some(),
            "permission 模式携带 route permission"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn primary_route_from_spec_preserves_resource_scope() {
        let spec = generated::http::HttpSpec {
            resource: Some("configId"),
            ..CONFIG_HTTP_SPEC
        };
        let route = primary_route_from_spec(&spec).expect("route");
        assert_eq!(
            route.route_permission().map(|p| p.scope),
            Some(RouteResourceScope::PathParam("configId")),
            "generated resource path-param must flow into route gate"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn primary_route_from_spec_preserves_self_scope() {
        let spec = generated::http::HttpSpec {
            self_scoped: true,
            ..CONFIG_HTTP_SPEC
        };
        let route = primary_route_from_spec(&spec).expect("route");
        assert_eq!(
            route.route_permission().map(|p| p.scope),
            Some(RouteResourceScope::SelfSubject),
            "generated selfScoped must flow into route gate"
        );
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
        let resp = config_publish_handler_bytes(svc, tenant(), actor(), body.into(), "rid").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "非法 key → 400 Validation"
        );
    }

    #[test]
    fn config_error_response_maps_status_codes() {
        let cases = [
            (SettingsServiceError::InvalidKey, StatusCode::BAD_REQUEST),
            (
                SettingsServiceError::PercentageOutOfRange,
                StatusCode::BAD_REQUEST,
            ),
            (SettingsServiceError::VersionConflict, StatusCode::CONFLICT),
            (SettingsServiceError::NotFound, StatusCode::NOT_FOUND),
            (
                SettingsServiceError::EntryBuild,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(
                config_error_response(&err, tenant(), "rid").status(),
                want,
                "{err:?} → {want}"
            );
        }
    }

    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse(TENANT_B).expect("canonical uuid")
    }

    // cross-tenant 隔离：tenant_a publish "app.k"，tenant_b get_value("app.k")==None。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_isolation() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), actor(), publish_req("app.k", "secret"))
            .await
            .expect("tenant_a publish");
        let val = svc
            .get_value(tenant_b(), "app.k")
            .await
            .expect("tenant_b get");
        assert_eq!(val, None, "跨租户隔离：tenant_b 不应读到 tenant_a 的值");
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

        svc1.publish_config(tenant(), actor(), publish_req("app.timeout", "30s"))
            .await
            .expect("svc1 publish");
        svc2.publish_config(tenant(), actor(), publish_req("app.timeout", "30s"))
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
        assert!(eid.contains(VERSION_CHANGED_TOPIC), "idem 含 topic: {eid}");
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
            .rollback(tenant(), actor(), "nodot", 1)
            .await
            .expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：get_value 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn get_value_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc.get_value(tenant(), "nodot").await.expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // invalid-key 测试：delete 非法 key。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_invalid_key_returns_invalid_key() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        let err = svc.delete(tenant(), "nodot").await.expect_err("invalid");
        assert!(matches!(err, SettingsServiceError::InvalidKey));
    }

    // delete 后底层 find_version 断言已清除 + 不存在 key delete 幂等。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_hides_value_and_is_idempotent() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());
        svc.publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("publish");

        // 软删（tombstone）。
        svc.delete(tenant(), "app.k").await.expect("delete");

        // get_value 已是 None（latest 为 tombstone）。
        assert_eq!(svc.get_value(tenant(), "app.k").await.expect("get"), None);

        // 再次 delete 应幂等（latest 已 tombstone → no-op，返回 Ok）。
        svc.delete(tenant(), "app.k").await.expect("幂等 delete");
    }

    // F1 回归（service 层）：delete 软删后 republish **不重置版本**——next_version 经 latest_version（含
    // tombstone），故 publish v1 → delete(tombstone v2) → publish 得 v3（而非 v1），event_id 不复用。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_republish_continues_version_not_reset() {
        let capture = CapturingEmitter::default();
        let svc = service_with(&capture, InMemFlagStore::new());

        let v1 = svc
            .publish_config(tenant(), actor(), publish_req("app.k", "v1"))
            .await
            .expect("publish v1");
        assert_eq!(v1.data.version, 1);

        svc.delete(tenant(), "app.k").await.expect("delete");

        // republish：版本继续递增（v1 + tombstone v2 → v3），**非**重置回 1。
        let v3 = svc
            .publish_config(tenant(), actor(), publish_req("app.k", "v1-again"))
            .await
            .expect("republish");
        assert_eq!(
            v3.data.version, 3,
            "delete 软删后 republish 版本应继续（v3），不重置回 1"
        );
        assert_eq!(
            svc.get_value(tenant(), "app.k").await.expect("get"),
            Some("v1-again".to_string()),
            "republish 后活跃值恢复"
        );

        // 发射事实：publish v1 + republish v3 = 2 条，version 各异 → event_id 不复用（防 outbox 吞事件）。
        let facts = emitted_facts(&capture);
        assert_eq!(
            facts.len(),
            2,
            "delete 不发事件；publish v1 + republish v3 = 2 条 fact"
        );
        assert_eq!(facts[0].payload.version, 1);
        assert_eq!(
            facts[1].payload.version, 3,
            "republish 事件版本 = 3（新 event_id）"
        );
        assert_ne!(
            facts[0].idem, facts[1].idem,
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
            .publish_config(tenant(), actor(), publish_req("app.a", "val-a"))
            .await
            .expect("publish a");
        let resp_b = svc
            .publish_config(tenant(), actor(), publish_req("app.b", "val-b"))
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
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find(tenant, key).await
            }
            async fn find_version(
                &self,
                tenant: TenantId,
                key: &SettingKey,
                version: u64,
            ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
                self.inner.find_version(tenant, key, version).await
            }
            async fn latest_version(
                &self,
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<Option<u64>, ConfigRepoError> {
                let result = self.inner.latest_version(tenant, key).await;
                if self.version_reads.fetch_add(1, Ordering::SeqCst) < 2 {
                    self.barrier.wait().await;
                }
                result
            }
            async fn save(
                &self,
                tenant: TenantId,
                entry: ConfigEntry,
            ) -> Result<(), ConfigRepoError> {
                self.inner.save(tenant, entry).await
            }
            async fn delete(
                &self,
                tenant: TenantId,
                key: &SettingKey,
            ) -> Result<(), ConfigRepoError> {
                self.inner.delete(tenant, key).await
            }
        }

        let capture = CapturingEmitter::default();
        // 读端口（barrier-wrapped）与写 UoW 共享同一 store：barrier 同步两 find（皆读 None）后，各自经
        // writer.save_and_append_outbox 对共享 store CAS，制造 read-then-write 竞争（恰一胜一冲突）。
        let store = new_config_store();
        let svc = SettingsService::new(
            DynConfigRepo::new_box(BarrierConfigRepo {
                inner: InMemConfigRepo::from_shared(store.clone()),
                barrier: tokio::sync::Barrier::new(2),
                version_reads: AtomicUsize::new(0),
            }),
            DynConfigUnitOfWork::new_box(InMemConfigUnitOfWork::new(store, capture.clone())),
            Box::new(InMemFlagStore::new()),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            )),
        );

        // 单任务 join! 并发：两 future 都在 barrier 处 yield，同步后各自 save（CAS 竞争）。
        let (r1, r2) = tokio::join!(
            svc.publish_config(tenant(), actor(), publish_req("app.k", "a")),
            svc.publish_config(tenant(), actor(), publish_req("app.k", "b")),
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
        let val = svc.get_value(tenant(), "app.k").await.expect("get");
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
            .publish_config(tenant(), actor(), publish_req("app.smoke", "v1-value"))
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
