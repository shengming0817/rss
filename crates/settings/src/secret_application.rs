//! settings secret 应用层：secret 引用 CAS CRUD + 按坐标 resolve 材料（L1 本地事务，无 outbox）。
//!
//! [`SecretService`] 持只读 [`crate::ports::SecretRepo`] + typed
//! [`crate::ports::SecretUnitOfWork`]（坐标存储）+
//! [`diport::SecretResolver`]（材料解析，fail-closed）+ [`diport::Clock`]（保留供未来扩展，当前未使用）；
//! 生产 secret-resolve 路由只持 [`SecretResolveService`]，从类型上排除 mutation UoW。
//! 版本 CAS 逻辑镜像 [`crate::application::SettingsService`]，差异：L1 无 outbox。
//!
//! # 安全语义
//!
//! - `resolve_secret`：每次调用均对 resolver 发起一次 fresh 解析，**绝不缓存材料**（fail-closed 契约）。
//! - tombstone 软删使 version 单调不重置（与 ConfigRepo F1 同逻辑）。
//!
//! ref: etcd-io/etcd api/etcdserverpb/rpc.proto@main（CAS 版本模型）
//! ref: external-secrets/external-secrets api/v1beta1/secretstore_types.go（SecretResolver 对标）

use std::sync::Arc;

use ::generated::http::settings_v2::{
    SPEC as SECRET_HTTP_SPEC, SettingsSecretPublishData, SettingsSecretPublishRequest,
    SettingsSecretPublishResponse,
};
use ::httpserve::ContractMarker;
use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use diport::{Clock, DynSecretResolver, SecretMaterial, SecretResolver};
use generated::http::settings_v7::{
    SPEC as SECRET_RESOLVE_HTTP_SPEC, SettingsSecretResolveData, SettingsSecretResolveResponse,
};
use vocab::{CoreError, CoreErrorKind, TenantId};

use crate::application::{authenticated_tenant_scope, request_id_from, wire_version};
use crate::domain::{
    SecretEntry, SecretKey, SecretRef, SecretRepoError, SecretVersion, SettingsError, StoreId,
};
use crate::ports::{
    DynSecretRepo, DynSecretUnitOfWork, SecretInternalPublishCommand, SecretPublishCommand,
    SecretRepo, SecretRepublishCommand, SecretUnitOfWork, TenantRepoScope,
};

#[cfg(test)]
use crate::internal::mem::{InMemSecretRepo, new_secret_store};

/// 错误消息常量（`&'static str` const literal，不拼 runtime 数据，符合 error-handling.md §Message 与 PII）。
const MSG_STORAGE: &str = "secret storage failed";
const MSG_NOT_FOUND: &str = "secret entry not found";
const MSG_VERSION_NOT_FOUND: &str = "secret version not found";
const MSG_FORBIDDEN: &str = "secret access forbidden";
const MSG_STORE_UNAVAILABLE: &str = "secret store unavailable";
const MSG_VERSION_CONFLICT: &str = "secret version conflict";
const MSG_INVALID_KEY: &str = "secret key is invalid";

/// secret 应用层错误（库错误枚举，不含 HTTP 状态码——handler 层映射）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretServiceError {
    /// 键格式非法。
    #[error("{}", MSG_INVALID_KEY)]
    InvalidKey,
    /// 乐观并发写冲突（读后被并发版本超前）。
    #[error("{}", MSG_VERSION_CONFLICT)]
    VersionConflict,
    /// secret 条目 / 本地坐标不存在（不含 pinned store version miss）。
    #[error("{}", MSG_NOT_FOUND)]
    NotFound,
    /// key 存在但指定 store 版本不存在。
    #[error("{}", MSG_VERSION_NOT_FOUND)]
    VersionNotFound,
    /// 对 secret 无访问权限（IAM / allowlist 拒绝）。
    #[error("{}", MSG_FORBIDDEN)]
    SecretForbidden,
    /// secret store 不可达 / 超时（5xx 语义，fail-closed）。
    #[error("{}", MSG_STORE_UNAVAILABLE)]
    SecretStoreUnavailable,
    /// 底层仓储持久化失败。
    #[error("{}", MSG_STORAGE)]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl From<SettingsError> for SecretServiceError {
    fn from(e: SettingsError) -> Self {
        match e {
            SettingsError::SecretKeyInvalid | SettingsError::SecretRefInvalid => Self::InvalidKey,
            // 配置键错误同属 4xx 客户端输入（完整性守卫）。
            SettingsError::KeyInvalid | SettingsError::SensitiveKey => Self::InvalidKey,
        }
    }
}

impl From<SecretRepoError> for SecretServiceError {
    fn from(e: SecretRepoError) -> Self {
        match e {
            SecretRepoError::VersionConflict => Self::VersionConflict,
            SecretRepoError::Storage(src) => Self::Storage(src),
        }
    }
}

impl From<diport::SecretResolverError> for SecretServiceError {
    fn from(e: diport::SecretResolverError) -> Self {
        use diport::SecretResolverError as R;
        match e {
            R::StoreUnreachable { .. } | R::Timeout => Self::SecretStoreUnavailable,
            R::NotFound => Self::NotFound,
            R::VersionNotFound => Self::VersionNotFound,
            R::Forbidden => Self::SecretForbidden,
            // non_exhaustive 未知变体 → fail-closed 不可达
            _ => Self::SecretStoreUnavailable,
        }
    }
}

/// 将 domain `SecretRef` 坐标转换为 `diport::SecretCoordinate`（应用层 adapter 函数）。
///
/// domain 层不依赖 diport；此自由函数在 application 层完成跨层转换，是 resolver 调用前的唯一桥接点。
/// （Finding 7：从 `SecretRef::to_coordinate` 提升到 application 层，去除 domain→diport 依赖。）
fn secret_ref_to_coordinate(r: &SecretRef) -> diport::SecretCoordinate {
    diport::SecretCoordinate::new(
        r.store_id().as_str(),
        r.ref_key(),
        r.ref_version().map(str::to_owned),
    )
}

/// 生产 secret-resolve 路由的窄化只读服务。
///
/// 字段私有，构造器只接收坐标仓储与 resolver；mutation UoW 无法进入 LocalOnly 路由 State。
pub struct SecretResolveService {
    secrets: Arc<DynSecretRepo<'static>>,
    resolver: Box<DynSecretResolver<'static>>,
}

impl SecretResolveService {
    /// 从两个必填端口构造生产只读能力。
    #[must_use]
    pub fn new(
        secrets: Arc<DynSecretRepo<'static>>,
        resolver: Box<DynSecretResolver<'static>>,
    ) -> Self {
        Self { secrets, resolver }
    }

    /// 经当前已存坐标 fresh 解析材料，不缓存。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn resolve_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<SecretMaterial, SecretServiceError> {
        resolve_secret_from_ports(&self.secrets, &self.resolver, tenant, key).await
    }
}

/// settings secret 读写应用服务（L1 本地事务，无 outbox）。
///
/// 必填依赖走构造器位置参（缺失即编译错误）：`secrets`（只读坐标仓储）、`secret_uow`（typed mutation）、
/// `resolver`（材料解析 provider）、`clock`（保留位置参，未来扩展审计时间戳用，当前未使用）。
///
/// # 生产构造约束（#1430）
///
/// 生产 HTTP dispatch 不把此宽服务存入路由 State：publish 直接接收 typed repo/UoW，resolve 仅接收
/// 无法携带 mutation capability 的 [`SecretResolveService`]。
///
/// # fail-closed 契约
///
/// `resolve_secret` 每次均发起 fresh resolver 调用，绝不缓存材料——零信任边界要求 secret 读取须 fresh。
pub struct SecretService {
    secrets: Arc<DynSecretRepo<'static>>,
    secret_uow: Arc<DynSecretUnitOfWork<'static>>,
    resolver: Box<DynSecretResolver<'static>>,
    // reason: Clock 是构造器必填位置参（rust-standards §Clock 构造器位置参）；当前未使用字段，
    // 保留为未来 publish_secret 审计时间戳扩展点，不删除——删除需改构造器签名（breaking change）。
    #[allow(dead_code)]
    clock: Box<dyn Clock>,
}

impl SecretService {
    /// 生产构造器（非门控 `pub`，组合根注入真实 postgres provider + Vault resolver）。
    ///
    /// `clock` 是构造器位置参（rust-standards §Clock 构造器位置参），生产传 `SystemClock`。
    pub fn with_postgres(
        secrets: Arc<DynSecretRepo<'static>>,
        secret_uow: Arc<DynSecretUnitOfWork<'static>>,
        resolver: Box<DynSecretResolver<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            secrets,
            secret_uow,
            resolver,
            clock,
        }
    }

    /// 测试 / seed-data 构造器（同参数，门控于 `test` / `seed-data`）。
    // reason: 测试场景注入 in-mem 替身用；seed-data 生产模式暂未接线（生产走 with_postgres）。
    #[allow(dead_code)]
    #[cfg(any(test, feature = "seed-data"))]
    pub(crate) fn new(
        secrets: Box<DynSecretRepo<'static>>,
        secret_uow: Box<DynSecretUnitOfWork<'static>>,
        resolver: Box<DynSecretResolver<'static>>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            secrets: Arc::from(secrets),
            secret_uow: Arc::from(secret_uow),
            resolver,
            clock,
        }
    }

    /// 写入新 secret 引用版本（CAS，L1 本地事务）。返回新版本号。并发冲突冒泡 `VersionConflict`。
    ///
    /// 逻辑收口进 internal typed publish helper（仅依赖 repo/UoW，无 resolver / clock）。handler 的 axum
    /// State 只持 publish 所需 typed ports，而非携带 resolver/clock 的整个 `SecretService`。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn publish_secret(
        &self,
        tenant: TenantId,
        key: SecretKey,
        secret_ref: SecretRef,
    ) -> Result<u64, SecretServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        publish_secret_internal_to_ports(&self.secrets, &self.secret_uow, scope, key, secret_ref)
            .await
    }

    /// 读取当前活跃 secret 引用（不存在返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn find_secret_ref(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<SecretRef>, SecretServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        Ok(self
            .secrets
            .find(scope, key)
            .await?
            .map(|entry| entry.secret_ref().clone()))
    }

    /// 读取指定版本的 secret 引用（不存在 / tombstone 返回 `Ok(None)`）。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn find_secret_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretRef>, SecretServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        Ok(self
            .secrets
            .find_version(scope, key, version)
            .await?
            .map(|entry| entry.secret_ref().clone()))
    }

    /// 回滚：以 `to_version` 的引用重新发布（生成新版本，无事件）。
    ///
    /// 源版本不存在返回 `SecretServiceError::NotFound`。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn rollback_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        to_version: u64,
    ) -> Result<u64, SecretServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        let source_ref = self
            .secrets
            .find_version(scope, key, to_version)
            .await?
            .ok_or(SecretServiceError::NotFound)?
            .secret_ref()
            .clone();
        republish_secret_to_ports(
            &self.secrets,
            &self.secret_uow,
            scope,
            key.clone(),
            source_ref,
        )
        .await
    }

    /// 软删除 secret 引用（tombstone 语义：版本单调不重置；幂等——key 不存在 / 已删 → no-op）。
    ///
    /// 删除后 `find_secret_ref` 返 `None`；历史版本仍可经 `find_secret_version` 查询。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn delete_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<(), SecretServiceError> {
        let scope = TenantRepoScope::from_authenticated_tenant(tenant);
        self.secret_uow.delete(scope, key).await.map_err(Into::into)
    }

    /// 按 secret 引用解析材料（每次 fresh 调用 resolver，绝不缓存）。
    ///
    /// fail-closed：找不到引用返 `NotFound`；resolver 返错误经 `From` 映射。
    #[tracing::instrument(skip_all, err(level = "warn"), fields(tenant = %tenant))]
    pub async fn resolve_secret(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<SecretMaterial, SecretServiceError> {
        resolve_secret_from_ports(&self.secrets, &self.resolver, tenant, key).await
    }
}

async fn resolve_secret_from_ports(
    secrets: &DynSecretRepo<'static>,
    resolver: &DynSecretResolver<'static>,
    tenant: TenantId,
    key: &SecretKey,
) -> Result<SecretMaterial, SecretServiceError> {
    let scope = TenantRepoScope::from_authenticated_tenant(tenant);
    let secret_ref = secrets
        .find(scope, key)
        .await?
        .ok_or(SecretServiceError::NotFound)?
        .secret_ref()
        .clone();
    let coordinate = secret_ref_to_coordinate(&secret_ref);
    resolver
        .resolve(tenant, &coordinate)
        .await
        .map_err(Into::into)
}

// ---------------------------------------------------------------------------
// HTTP handler（secret-publish；route 装配在 application::SettingsDomain::init）
// ---------------------------------------------------------------------------

/// `settings.secret-publish` 请求体上界（防御性 body 限额）。
const MAX_SECRET_BODY_BYTES: usize = 64 * 1024;

/// 预读最高版本并构造下一条 active entry；最终并发正确性仍由单次 UoW CAS 保证。
async fn next_secret_entry(
    secrets: &DynSecretRepo<'static>,
    scope: TenantRepoScope,
    key: SecretKey,
    secret_ref: SecretRef,
) -> Result<(SecretEntry, u64), SecretServiceError> {
    let tenant = scope.tenant();
    let current = secrets.latest_version(scope, &key).await?;
    let version = current.map_or(1, |v| v + 1);
    let entry = SecretEntry::new(key, secret_ref, tenant, SecretVersion::new(version));
    Ok((entry, version))
}

/// HTTP secret-publish 单源：只允许 typed HTTP command 进入 `publish` UoW slot。
pub(crate) async fn publish_secret_to_ports(
    secrets: &DynSecretRepo<'static>,
    secret_uow: &DynSecretUnitOfWork<'static>,
    scope: TenantRepoScope,
    key: SecretKey,
    secret_ref: SecretRef,
) -> Result<u64, SecretServiceError> {
    let (entry, version) = next_secret_entry(secrets, scope, key, secret_ref).await?;
    let command = SecretPublishCommand::from_entry(entry);
    secret_uow.publish(scope, command).await?;
    Ok(version)
}

/// 程序内 SecretService publish：与 HTTP contract 分离，不携带 LocalTx observation。
async fn publish_secret_internal_to_ports(
    secrets: &DynSecretRepo<'static>,
    secret_uow: &DynSecretUnitOfWork<'static>,
    scope: TenantRepoScope,
    key: SecretKey,
    secret_ref: SecretRef,
) -> Result<u64, SecretServiceError> {
    let (entry, version) = next_secret_entry(secrets, scope, key, secret_ref).await?;
    secret_uow
        .publish_internal(scope, SecretInternalPublishCommand::from_entry(entry))
        .await?;
    Ok(version)
}

/// rollback republish：typed republish slot，绝不回调 HTTP/internal publish。
async fn republish_secret_to_ports(
    secrets: &DynSecretRepo<'static>,
    secret_uow: &DynSecretUnitOfWork<'static>,
    scope: TenantRepoScope,
    key: SecretKey,
    secret_ref: SecretRef,
) -> Result<u64, SecretServiceError> {
    let (entry, version) = next_secret_entry(secrets, scope, key, secret_ref).await?;
    secret_uow
        .republish(scope, SecretRepublishCommand::from_entry(entry))
        .await?;
    Ok(version)
}

/// HTTP handler 的可共享 typed state；resolver/clock 不进入路由 State。
#[derive(Clone)]
pub(crate) struct SecretPublishState {
    secrets: Arc<DynSecretRepo<'static>>,
    secret_uow: Arc<DynSecretUnitOfWork<'static>>,
}

impl SecretPublishState {
    pub(crate) fn new(
        secrets: Arc<DynSecretRepo<'static>>,
        secret_uow: Arc<DynSecretUnitOfWork<'static>>,
    ) -> Self {
        Self {
            secrets,
            secret_uow,
        }
    }
}

/// `settings.secret-publish` handler（Primary listener，JWT 认证）：route gate 授权证据取租户 → parse body →
/// domain newtype funnel（`SecretKey` / `StoreId` / `SecretRef::parse` 权威校验，路径穿越在此 fail-closed）→
/// [`publish_secret_to_ports`]（CAS 写引用坐标，L1 无 outbox）→ 201。请求 / 响应**绝无 secret 材料**。
/// State 仅持 read repo + mutation UoW，避开 `SecretService` 非 `Sync`。
pub(crate) async fn secret_publish_handler(
    _: ContractMarker<::generated::http::settings_v2::RouteMarker>,
    State(state): State<SecretPublishState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let scope = match authenticated_tenant_scope(&req) {
        Ok(scope) => scope,
        Err(reject) => return reject.into_response(&request_id),
    };
    let (_, body) = req.into_parts();
    let body = match to_bytes(body, MAX_SECRET_BODY_BYTES).await {
        Ok(body) => body,
        Err(err) if httpserve::error::body_error_is_length_limit(&err) => {
            return httpserve::error::payload_too_large(&request_id);
        }
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    secret_publish_handler_bytes(&state.secrets, &state.secret_uow, scope, body, &request_id).await
}

/// `settings.secret-resolve` handler. The tenant is taken only from authenticated route evidence;
/// the stored reference and active Vault resolver are consulted on every request.
pub(crate) async fn secret_resolve_handler(
    _: ContractMarker<::generated::http::settings_v7::RouteMarker>,
    Path(key): Path<String>,
    State(state): State<SecretResolveState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let scope = match authenticated_tenant_scope(&req) {
        Ok(scope) => scope,
        Err(reject) => return reject.into_response(&request_id),
    };
    let key = match SecretKey::parse(&key) {
        Ok(key) => key,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    match state.service.resolve_secret(scope.tenant(), &key).await {
        Ok(material) => (
            StatusCode::OK,
            Json(SettingsSecretResolveResponse {
                data: SettingsSecretResolveData {
                    material_base64: base64::engine::general_purpose::STANDARD
                        .encode(material.expose()),
                },
            }),
        )
            .into_response(),
        Err(error) => secret_error_response(
            &error,
            scope.tenant(),
            &request_id,
            &SECRET_RESOLVE_HTTP_SPEC,
            "secret_resolve",
        ),
    }
}

/// Narrow classified state for the LocalOnly resolve route.
#[derive(Clone)]
pub(crate) struct SecretResolveState {
    service: Arc<SecretResolveService>,
}

impl SecretResolveState {
    pub(crate) fn new(service: Arc<SecretResolveService>) -> Self {
        Self { service }
    }
}

impl httpserve::ClassifiedRouteState for SecretResolveState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

/// secret-publish 核心（tenant 已解析）：parse + domain funnel + 仓储发布。供单测直接驱动。
pub(crate) async fn secret_publish_handler_bytes(
    secrets: &DynSecretRepo<'static>,
    secret_uow: &DynSecretUnitOfWork<'static>,
    scope: TenantRepoScope,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: SettingsSecretPublishRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    // domain newtype 权威校验（key 两段 / store 单段 / ref 路径穿越防御，Hard funnel）→ 非法即 4xx Validation。
    let (key, secret_ref) = match parse_secret_publish(&request) {
        Ok(parsed) => parsed,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    match publish_secret_to_ports(secrets, secret_uow, scope, key, secret_ref).await {
        Ok(version) => {
            let response = SettingsSecretPublishResponse {
                data: SettingsSecretPublishData {
                    key: request.key,
                    version: wire_version(version),
                },
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(err) => secret_error_response(
            &err,
            scope.tenant(),
            request_id,
            &SECRET_HTTP_SPEC,
            "secret_publish",
        ),
    }
}

/// 请求体 → domain newtype（权威校验单源；非法坐标 / 穿越路径从此不可表达）。
fn parse_secret_publish(
    request: &SettingsSecretPublishRequest,
) -> Result<(SecretKey, SecretRef), SettingsError> {
    let key = SecretKey::parse(&request.key)?;
    let store_id = StoreId::parse(&request.store_id)?;
    let secret_ref = SecretRef::parse(store_id, &request.ref_key, request.ref_version.as_deref())?;
    Ok((key, secret_ref))
}

/// `SecretServiceError` → wire 响应：generic [`CoreErrorKind`] 派生状态码（4xx 客户端 / 5xx 内部），
/// **不**铸 `ERR_SETTINGS_` 命名空间（复用 vocab 通用 kind）。5xx 记结构化 error（const message，无 PII；
/// `tenant_id` 是合法低基数可观测字段、非凭据，透传供跨租定位——对标 identity handler 错误日志）。
fn secret_error_response(
    err: &SecretServiceError,
    tenant: TenantId,
    request_id: &str,
    spec: &::generated::http::HttpSpec,
    operation: &'static str,
) -> Response {
    let core = match err {
        SecretServiceError::InvalidKey => CoreError::new(CoreErrorKind::Validation),
        SecretServiceError::VersionConflict => CoreError::new(CoreErrorKind::VersionConflict),
        // VersionNotFound 与 NotFound 同为无 detail 的 404：Vault 启发式不足以公开
        // `versionNotFound` taxonomy（路径 miss 也会 404）；Rust 调用方仍可区分服务层变体。
        SecretServiceError::NotFound | SecretServiceError::VersionNotFound => {
            CoreError::new(CoreErrorKind::NotFound)
        }
        SecretServiceError::SecretForbidden => CoreError::new(CoreErrorKind::Forbidden),
        SecretServiceError::SecretStoreUnavailable | SecretServiceError::Storage(_) => {
            CoreError::new(CoreErrorKind::Internal)
        }
    };
    log_secret_internal_error(err, tenant, request_id, spec, operation);
    httpserve::error::core_error_response(&core, request_id)
}

/// 5xx Internal 路径的结构化 RCA 日志：仅固定顶层 Display（Storage / SecretStoreUnavailable），
/// 不记录底层 `Error` source 文本（sqlx 等可能含连接串片段）。
fn log_secret_internal_error(
    err: &SecretServiceError,
    tenant: TenantId,
    request_id: &str,
    spec: &::generated::http::HttpSpec,
    operation: &'static str,
) {
    match err {
        SecretServiceError::Storage(_) | SecretServiceError::SecretStoreUnavailable => {
            tracing::error!(
                error = %err,
                request_id,
                tenant_id = %tenant,
                contract_id = spec.route.contract_id(),
                operation,
                "settings secret operation failed"
            );
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use diport::{DynSecretResolver, SecretCoordinate, SecretMaterial, SecretResolverError};
    use vocab::TenantId;

    use super::*;
    use crate::domain::{SecretKey, SecretRef, StoreId};
    use crate::ports::{DynSecretRepo, DynSecretUnitOfWork};

    use axum::routing::post;
    use httpserve::AuthorizedSubject;
    use testkit::ContractRequest;
    use vocab::PrincipalKind;

    const TENANT_STR: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B_STR: &str = "00000000-0000-4000-8000-000000000abc";

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(TENANT_STR).expect("canonical uuid")
    }

    #[allow(clippy::expect_used)]
    fn tenant_b() -> TenantId {
        TenantId::parse(TENANT_B_STR).expect("canonical uuid")
    }

    fn tenant_scope() -> TenantRepoScope {
        TenantRepoScope::for_test(tenant())
    }

    #[allow(clippy::expect_used)]
    fn make_key(s: &str) -> SecretKey {
        SecretKey::parse(s).expect("valid secret key")
    }

    #[allow(clippy::expect_used)]
    fn make_ref(store: &str, path: &str) -> SecretRef {
        let sid = StoreId::parse(store).expect("valid store id");
        SecretRef::parse(sid, path, None).expect("valid secret ref")
    }

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn fixed_clock() -> Box<dyn Clock> {
        Box::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        ))
    }

    // mockall mock for SecretResolver（域 crate 单测不依赖 adapter crate）。
    mockall::mock! {
        pub TestSecretResolver {}
        impl diport::SecretResolver for TestSecretResolver {
            async fn resolve(
                &self,
                tenant: TenantId,
                coord: &SecretCoordinate,
            ) -> Result<SecretMaterial, SecretResolverError>;
        }
    }

    fn service_with_mock_resolver(mock: MockTestSecretResolver) -> SecretService {
        let store = new_secret_store();
        SecretService::new(
            DynSecretRepo::new_box(InMemSecretRepo::from_shared(Arc::clone(&store))),
            DynSecretUnitOfWork::new_box(InMemSecretRepo::from_shared(store)),
            DynSecretResolver::new_box(mock),
            fixed_clock(),
        )
    }

    fn plain_service() -> SecretService {
        let mut mock = MockTestSecretResolver::new();
        // 默认 resolver：happy path 返回固定材料。
        mock.expect_resolve()
            .returning(|_, _| Ok(SecretMaterial::new(b"material".to_vec())));
        service_with_mock_resolver(mock)
    }

    // ── #1430 settings durable module：secret-publish HTTP handler 测试 ────────────────

    /// 共享同一 in-mem store 的 read repo + mutation UoW。
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

    #[derive(Clone, Copy)]
    enum SaveScript {
        Succeed,
        Conflict,
        StorageFailure,
    }

    #[derive(Clone)]
    struct MutationAttempt {
        scope_tenant: TenantId,
        entry: SecretEntry,
    }

    #[derive(Default)]
    struct ProbeState {
        find_calls: usize,
        find_version_calls: usize,
        latest_calls: usize,
        publish_attempts: Vec<MutationAttempt>,
        internal_publish_attempts: Vec<MutationAttempt>,
        republish_attempts: Vec<MutationAttempt>,
        delete_calls: usize,
        committed: Vec<SecretEntry>,
    }

    impl ProbeState {
        fn total_calls(&self) -> usize {
            self.find_calls
                + self.find_version_calls
                + self.latest_calls
                + self.publish_attempts.len()
                + self.internal_publish_attempts.len()
                + self.republish_attempts.len()
                + self.delete_calls
        }
    }

    struct ProbeSecretRepo {
        state: Arc<Mutex<ProbeState>>,
        latest: Option<u64>,
        find_version_entry: Option<SecretEntry>,
    }

    impl SecretRepo for ProbeSecretRepo {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .find_calls += 1;
            Ok(None)
        }

        async fn find_version(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
            version: u64,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .find_version_calls += 1;
            Ok(self
                .find_version_entry
                .as_ref()
                .filter(|entry| entry.version() == version)
                .cloned())
        }

        async fn latest_version(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<Option<u64>, SecretRepoError> {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .latest_calls += 1;
            Ok(self.latest)
        }
    }

    struct ProbeSecretUow {
        state: Arc<Mutex<ProbeState>>,
        save_script: SaveScript,
    }

    impl ProbeSecretUow {
        fn apply(
            &self,
            scope: TenantRepoScope,
            entry: SecretEntry,
            slot: fn(&mut ProbeState) -> &mut Vec<MutationAttempt>,
        ) -> Result<(), SecretRepoError> {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            slot(&mut state).push(MutationAttempt {
                scope_tenant: scope.tenant(),
                entry: entry.clone(),
            });
            match self.save_script {
                SaveScript::Succeed => {
                    state.committed.push(entry);
                    Ok(())
                }
                SaveScript::Conflict => Err(SecretRepoError::VersionConflict),
                SaveScript::StorageFailure => Err(SecretRepoError::Storage(Box::new(
                    std::io::Error::other("backend leaked sentinel"),
                ))),
            }
        }
    }

    impl SecretUnitOfWork for ProbeSecretUow {
        async fn publish(
            &self,
            scope: TenantRepoScope,
            command: SecretPublishCommand,
        ) -> Result<(), SecretRepoError> {
            let (entry, _observation) = command.into_parts();
            self.apply(scope, entry, |state| &mut state.publish_attempts)
        }

        async fn publish_internal(
            &self,
            scope: TenantRepoScope,
            command: SecretInternalPublishCommand,
        ) -> Result<(), SecretRepoError> {
            self.apply(scope, command.into_entry(), |state| {
                &mut state.internal_publish_attempts
            })
        }

        async fn republish(
            &self,
            scope: TenantRepoScope,
            command: SecretRepublishCommand,
        ) -> Result<(), SecretRepoError> {
            self.apply(scope, command.into_entry(), |state| {
                &mut state.republish_attempts
            })
        }

        async fn delete(
            &self,
            _scope: TenantRepoScope,
            _key: &SecretKey,
        ) -> Result<(), SecretRepoError> {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .delete_calls += 1;
            Ok(())
        }
    }

    fn probe_ports(
        latest: Option<u64>,
        save_script: SaveScript,
    ) -> (
        Arc<DynSecretRepo<'static>>,
        Arc<DynSecretUnitOfWork<'static>>,
        Arc<Mutex<ProbeState>>,
    ) {
        let state = Arc::new(Mutex::new(ProbeState::default()));
        let repo = ProbeSecretRepo {
            state: Arc::clone(&state),
            latest,
            find_version_entry: None,
        };
        let uow = ProbeSecretUow {
            state: Arc::clone(&state),
            save_script,
        };
        (
            Arc::from(DynSecretRepo::new_box(repo)),
            Arc::from(DynSecretUnitOfWork::new_box(uow)),
            state,
        )
    }

    fn probe_service(
        latest: Option<u64>,
        find_version_entry: Option<SecretEntry>,
    ) -> (SecretService, Arc<Mutex<ProbeState>>) {
        let state = Arc::new(Mutex::new(ProbeState::default()));
        let repo = ProbeSecretRepo {
            state: Arc::clone(&state),
            latest,
            find_version_entry,
        };
        let uow = ProbeSecretUow {
            state: Arc::clone(&state),
            save_script: SaveScript::Succeed,
        };
        let resolver = MockTestSecretResolver::new();
        (
            SecretService::new(
                DynSecretRepo::new_box(repo),
                DynSecretUnitOfWork::new_box(uow),
                DynSecretResolver::new_box(resolver),
                fixed_clock(),
            ),
            state,
        )
    }

    struct SameSnapshotRepo {
        inner: InMemSecretRepo,
        latest_barrier: Arc<tokio::sync::Barrier>,
    }

    impl SecretRepo for SameSnapshotRepo {
        async fn find(
            &self,
            scope: TenantRepoScope,
            key: &SecretKey,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            self.inner.find(scope, key).await
        }

        async fn find_version(
            &self,
            scope: TenantRepoScope,
            key: &SecretKey,
            version: u64,
        ) -> Result<Option<SecretEntry>, SecretRepoError> {
            self.inner.find_version(scope, key, version).await
        }

        async fn latest_version(
            &self,
            scope: TenantRepoScope,
            key: &SecretKey,
        ) -> Result<Option<u64>, SecretRepoError> {
            let snapshot = self.inner.latest_version(scope, key).await?;
            self.latest_barrier.wait().await;
            Ok(snapshot)
        }
    }

    /// post-authz 授权证据（Primary route gate 注入）。
    fn user_evidence(t: TenantId) -> AuthorizedSubject {
        AuthorizedSubject::for_test(
            SECRET_HTTP_SPEC.route.contract_id(),
            vocab::RoutePermissionId::SettingsSecretPublish,
            t,
            PrincipalKind::User,
            "subject",
            None,
        )
    }

    fn secret_router(
        repo: Arc<DynSecretRepo<'static>>,
        uow: Arc<DynSecretUnitOfWork<'static>>,
        auth: Option<AuthorizedSubject>,
    ) -> axum::Router {
        let state = SecretPublishState::new(repo, uow);
        let router =
            axum::Router::new().route("/secrets", post(secret_publish_handler).with_state(state));
        match auth {
            Some(a) => router.layer(axum::Extension(a)),
            None => router,
        }
    }

    fn publish_request(version: Option<&str>) -> SettingsSecretPublishRequest {
        SettingsSecretPublishRequest {
            key: "vault.db".to_string(),
            store_id: "vault".to_string(),
            ref_key: "myapp/db-password".to_string(),
            ref_version: version.map(str::to_owned),
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_handler_authed_returns_201() {
        let (repo, uow) = secret_ports_arc();
        let router = secret_router(repo, uow, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").json(&publish_request(Some("v3"))),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::CREATED).expect("201");
        let decoded: SettingsSecretPublishResponse = resp.json().expect("json");
        assert_eq!(decoded.data.key, "vault.db");
        assert_eq!(decoded.data.version, 1, "首次发布 = v1");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_handler_missing_auth_returns_401() {
        let (repo, uow, state) = probe_ports(None, SaveScript::Succeed);
        let router = secret_router(repo, uow, None);
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").json(&publish_request(None)),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::UNAUTHORIZED)
            .expect("缺认证证据 → 401");
        assert_eq!(
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .total_calls(),
            0,
            "未认证请求不得触碰仓储"
        );
    }

    #[tokio::test]
    async fn secret_publish_bytes_invalid_json_returns_400() {
        let invalid_bodies = [
            "not json",
            r#"{"key":"vault.db","storeId":"vault"}"#,
            r#"{"key":"vault.db","storeId":"vault","refKey":"db/pw","extra":true}"#,
            r#"{"key":"bad.key.extra","storeId":"vault","refKey":"db/pw"}"#,
            r#"{"key":"vault.db","storeId":"bad/store","refKey":"db/pw"}"#,
            r#"{"key":"vault.db","storeId":"vault","refKey":"a/../evil"}"#,
        ];
        for body in invalid_bodies {
            let (repo, uow, state) = probe_ports(None, SaveScript::Succeed);
            let resp = secret_publish_handler_bytes(
                &repo,
                &uow,
                tenant_scope(),
                Bytes::copy_from_slice(body.as_bytes()),
                "rid",
            )
            .await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "body={body}");
            assert_eq!(
                state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .total_calls(),
                0,
                "非法请求不得触碰仓储: {body}"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_bytes_path_traversal_returns_400() {
        let (repo, uow) = secret_ports_arc();
        let req = SettingsSecretPublishRequest {
            key: "vault.db".to_string(),
            store_id: "vault".to_string(),
            ref_key: "a/../evil".to_string(),
            ref_version: None,
        };
        let body = serde_json::to_vec(&req).expect("serialize");
        let resp =
            secret_publish_handler_bytes(&repo, &uow, tenant_scope(), body.into(), "rid").await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "路径穿越坐标 → 400 Validation（domain newtype funnel fail-closed）"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_handler_oversize_returns_413_without_repo_calls() {
        let (repo, uow, state) = probe_ports(None, SaveScript::Succeed);
        let router = secret_router(repo, uow, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").raw_body(vec![b'x'; MAX_SECRET_BODY_BYTES + 1]),
        )
        .await
        .expect("call");
        resp.ensure_error(StatusCode::PAYLOAD_TOO_LARGE, "ERR_CORE_PAYLOAD_TOO_LARGE")
            .expect("oversize contract");
        assert_eq!(
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .total_calls(),
            0,
            "超限请求不得触碰仓储"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_handler_stream_failure_returns_400_without_repo_calls() {
        use futures::stream;
        use tower::ServiceExt as _;

        let (repo, uow, state) = probe_ports(None, SaveScript::Succeed);
        let router = secret_router(repo, uow, Some(user_evidence(tenant())));
        let body = Body::from_stream(stream::once(async {
            Err::<Bytes, _>(std::io::Error::other("body provider failed"))
        }));
        let request = Request::builder()
            .method("POST")
            .uri("/secrets")
            .body(body)
            .expect("request");
        let response = router.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("error response body");
        let envelope: serde_json::Value = serde_json::from_slice(&bytes).expect("error envelope");
        assert_eq!(envelope["error"]["code"], "ERR_CORE_VALIDATION");
        assert_eq!(envelope["error"]["message"], "validation error");
        assert_eq!(envelope["error"]["retryable"], false);
        assert_eq!(
            state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .total_calls(),
            0,
            "body provider 读取失败不得触碰仓储"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_success_passes_authenticated_scope_and_coordinate_once() {
        let (repo, uow, state) = probe_ports(Some(6), SaveScript::Succeed);
        let router = secret_router(Arc::clone(&repo), uow, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").json(&publish_request(Some("v3"))),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::CREATED).expect("201");
        let decoded: SettingsSecretPublishResponse = resp.json().expect("json");
        assert_eq!(decoded.data.version, 7);

        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.latest_calls, 1);
        assert_eq!(state.publish_attempts.len(), 1);
        assert!(state.internal_publish_attempts.is_empty());
        assert!(state.republish_attempts.is_empty());
        assert_eq!(state.committed.len(), 1);
        let call = &state.publish_attempts[0];
        assert_eq!(call.scope_tenant, tenant());
        assert_eq!(call.entry.tenant(), tenant());
        assert_eq!(call.entry.key().as_str(), "vault.db");
        assert_eq!(call.entry.version(), 7);
        assert_eq!(call.entry.secret_ref().store_id().as_str(), "vault");
        assert_eq!(call.entry.secret_ref().ref_key(), "myapp/db-password");
        assert_eq!(call.entry.secret_ref().ref_version(), Some("v3"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_conflict_is_retryable_409_without_retry_or_commit() {
        let (repo, uow, state) = probe_ports(Some(2), SaveScript::Conflict);
        let router = secret_router(repo, uow, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").json(&publish_request(None)),
        )
        .await
        .expect("call");
        resp.ensure_error(StatusCode::CONFLICT, "ERR_CORE_VERSION_CONFLICT")
            .expect("conflict contract");
        assert!(resp.wire_error().expect("wire error").retryable);
        let body = String::from_utf8_lossy(resp.body_bytes());
        assert!(!body.contains("vault.db"));
        assert!(!body.contains("myapp/db-password"));

        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.latest_calls, 1, "handler 不重读 head");
        assert_eq!(state.publish_attempts.len(), 1, "handler 不自动重试 CAS");
        assert!(state.internal_publish_attempts.is_empty());
        assert!(state.republish_attempts.is_empty());
        assert!(state.committed.is_empty(), "冲突必须零提交");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_publish_storage_failure_is_generic_500_without_commit() {
        let (repo, uow, state) = probe_ports(None, SaveScript::StorageFailure);
        let router = secret_router(repo, uow, Some(user_evidence(tenant())));
        let resp = testkit::call(
            router,
            ContractRequest::post("/secrets").json(&publish_request(Some("private-version"))),
        )
        .await
        .expect("call");
        resp.ensure_error(StatusCode::INTERNAL_SERVER_ERROR, "ERR_CORE_INTERNAL")
            .expect("storage contract");
        let body = String::from_utf8_lossy(resp.body_bytes());
        for secret in [
            "backend leaked sentinel",
            "vault.db",
            "vault",
            "myapp/db-password",
            "private-version",
        ] {
            assert!(!body.contains(secret), "response leaked {secret}");
        }
        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(state.latest_calls, 1);
        assert_eq!(state.publish_attempts.len(), 1);
        assert!(state.internal_publish_attempts.is_empty());
        assert!(state.republish_attempts.is_empty());
        assert!(state.committed.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn concurrent_same_snapshot_has_exactly_one_commit_and_one_conflict() {
        let store = new_secret_store();
        let repo: Arc<DynSecretRepo<'static>> =
            Arc::from(DynSecretRepo::new_box(SameSnapshotRepo {
                inner: InMemSecretRepo::from_shared(Arc::clone(&store)),
                latest_barrier: Arc::new(tokio::sync::Barrier::new(2)),
            }));
        let uow: Arc<DynSecretUnitOfWork<'static>> = Arc::from(DynSecretUnitOfWork::new_box(
            InMemSecretRepo::from_shared(store),
        ));
        let first = publish_secret_internal_to_ports(
            &repo,
            &uow,
            tenant_scope(),
            make_key("vault.db"),
            make_ref("vault", "first"),
        );
        let second = publish_secret_internal_to_ports(
            &repo,
            &uow,
            tenant_scope(),
            make_key("vault.db"),
            make_ref("vault", "second"),
        );
        let (a, b) = tokio::join!(first, second);
        assert!(
            matches!(
                (&a, &b),
                (Ok(1), Err(SecretServiceError::VersionConflict))
                    | (Err(SecretServiceError::VersionConflict), Ok(1))
            ),
            "same-snapshot CAS outcomes: a={a:?}, b={b:?}"
        );
        let stored = repo
            .find(tenant_scope(), &make_key("vault.db"))
            .await
            .expect("find")
            .expect("one committed row");
        assert_eq!(stored.version(), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_secret_internal_to_ports_increments_version_monotonically() {
        let (repo, uow) = secret_ports_arc();
        let v1 = publish_secret_internal_to_ports(
            &repo,
            &uow,
            tenant_scope(),
            make_key("vault.db"),
            make_ref("vault", "k"),
        )
        .await
        .expect("v1");
        let v2 = publish_secret_internal_to_ports(
            &repo,
            &uow,
            tenant_scope(),
            make_key("vault.db"),
            make_ref("vault", "k"),
        )
        .await
        .expect("v2");
        assert_eq!((v1, v2), (1, 2), "CAS latest+1 单调递增");
    }

    #[test]
    fn secret_error_response_maps_status_codes() {
        let cases = [
            (SecretServiceError::InvalidKey, StatusCode::BAD_REQUEST),
            (SecretServiceError::VersionConflict, StatusCode::CONFLICT),
            (SecretServiceError::NotFound, StatusCode::NOT_FOUND),
            (SecretServiceError::VersionNotFound, StatusCode::NOT_FOUND),
            (SecretServiceError::SecretForbidden, StatusCode::FORBIDDEN),
            (
                SecretServiceError::SecretStoreUnavailable,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                SecretServiceError::Storage(Box::new(std::io::Error::other("db down"))),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, want) in cases {
            assert_eq!(
                secret_error_response(&err, tenant(), "rid", &SECRET_HTTP_SPEC, "secret_publish",)
                    .status(),
                want,
                "{err:?}"
            );
        }
    }

    /// VersionNotFound / NotFound → 同为无 detail 的 404（不公开 `versionNotFound` reason）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_error_response_not_found_variants_omit_version_reason() {
        for err in [
            SecretServiceError::NotFound,
            SecretServiceError::VersionNotFound,
        ] {
            let response =
                secret_error_response(&err, tenant(), "rid", &SECRET_HTTP_SPEC, "secret_resolve");
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{err:?}");
            let bytes = to_bytes(response.into_body(), 16 * 1024)
                .await
                .expect("error response body");
            let envelope: serde_json::Value =
                serde_json::from_slice(&bytes).expect("error envelope");
            let details = envelope["error"]["details"]
                .as_array()
                .expect("details array");
            assert!(
                details
                    .iter()
                    .all(|d| d.get("reason").is_none_or(|r| r != "versionNotFound")),
                "{err:?} must not carry versionNotFound reason, got {details:?}"
            );
        }
    }

    // ── resolve_secret：resolver 恰调一次 ─────────────────────────────────────────────────

    /// resolve_secret 对 resolver 恰好调用一次（`.times(1)`）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_calls_resolver_exactly_once() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .times(1)
            .returning(|_, _| Ok(SecretMaterial::new(b"mat".to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("store1", "db/pw"))
            .await
            .expect("publish ok");
        let _mat = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect("resolve ok");
        // mock::times(1) 在 drop 时 assert，无需额外调用。
    }

    /// store 不可达 → `SecretStoreUnavailable`（fail-closed）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_store_unreachable_is_err() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve().returning(|_, _| {
            Err(SecretResolverError::store_unreachable(
                std::io::Error::other("down"),
            ))
        });
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("expect err");
        assert!(
            matches!(err, SecretServiceError::SecretStoreUnavailable),
            "got {err:?}"
        );
    }

    /// resolver 返 NotFound → `SecretServiceError::NotFound` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_not_found_maps() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::NotFound));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    /// resolver 返 VersionNotFound → `SecretServiceError::VersionNotFound`（不坍缩成 NotFound）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_version_not_found_maps() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::VersionNotFound));
        let svc = service_with_mock_resolver(mock);

        let sid = StoreId::parse("s").expect("valid store");
        let secret_ref =
            SecretRef::parse(sid, "path", Some("3")).expect("valid versioned secret ref");
        svc.publish_secret(tenant(), make_key("vault.db"), secret_ref)
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(
            matches!(err, SecretServiceError::VersionNotFound),
            "got {err:?}"
        );
    }

    /// resolver 返 Forbidden → `SecretForbidden` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_forbidden_maps() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::Forbidden));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::SecretForbidden));
    }

    /// resolver 返 Timeout → `SecretStoreUnavailable` 映射。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_timeout_maps_to_store_unavailable() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Err(SecretResolverError::Timeout));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::SecretStoreUnavailable));
    }

    /// 正常 resolve → 返回 material（happy path）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_happy_returns_material() {
        let expected = b"my-secret-bytes";
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .returning(|_, _| Ok(SecretMaterial::new(expected.to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let mat = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect("resolve ok");
        assert_eq!(mat.expose(), expected);
    }

    /// 两次 resolve → resolver 被调用两次（绝不缓存）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_never_caches() {
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve()
            .times(2)
            .returning(|_, _| Ok(SecretMaterial::new(b"mat".to_vec())));
        let svc = service_with_mock_resolver(mock);

        svc.publish_secret(tenant(), make_key("vault.db"), make_ref("s", "k"))
            .await
            .expect("publish");
        let _ = svc.resolve_secret(tenant(), &make_key("vault.db")).await;
        let _ = svc.resolve_secret(tenant(), &make_key("vault.db")).await;
        // mock::times(2) 在 drop 时 assert。
    }

    // ── publish / find roundtrip ──────────────────────────────────────────────────────────

    /// publish 后 find_secret_ref 能读到已存引用。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_then_find_roundtrip() {
        let svc = plain_service();
        let key = make_key("vault.db");
        let secret_ref = make_ref("store1", "db/password");
        let version = svc
            .publish_secret(tenant(), key.clone(), secret_ref.clone())
            .await
            .expect("publish ok");
        assert_eq!(version, 1, "首次 publish 版本号应为 1");

        let found = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(found, Some(secret_ref));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn service_publish_uses_only_internal_publish_slot() {
        let (svc, state) = probe_service(None, None);
        let version = svc
            .publish_secret(tenant(), make_key("vault.db"), make_ref("store", "path"))
            .await
            .expect("internal publish");
        assert_eq!(version, 1);

        let state = state.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.internal_publish_attempts.len(), 1);
        assert!(state.publish_attempts.is_empty());
        assert!(state.republish_attempts.is_empty());
    }

    /// 找不到 secret key 时 resolve_secret 返 NotFound（非 resolver 调用）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn resolve_secret_key_not_found_returns_not_found() {
        // resolver 不应被调用（引用都找不到），故用 times(0) mock。
        let mut mock = MockTestSecretResolver::new();
        mock.expect_resolve().times(0);
        let svc = service_with_mock_resolver(mock);

        let err = svc
            .resolve_secret(tenant(), &make_key("vault.db"))
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    // ── rollback ──────────────────────────────────────────────────────────────────────────

    /// rollback 创建新版本（版本号递增）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_secret_creates_new_version() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "v1"))
            .await
            .expect("v1");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "v2"))
            .await
            .expect("v2");

        let v3 = svc
            .rollback_secret(tenant(), &key, 1)
            .await
            .expect("rollback ok");
        assert_eq!(v3, 3, "回滚应生成新版本 v3");

        // 活跃引用回到 v1 的 ref。
        let current_ref = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(current_ref, Some(make_ref("s", "v1")));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_uses_only_republish_slot() {
        let key = make_key("vault.db");
        let source = SecretEntry::new(
            key.clone(),
            make_ref("store", "source"),
            tenant(),
            SecretVersion::new(1),
        );
        let (svc, state) = probe_service(Some(1), Some(source));

        let version = svc
            .rollback_secret(tenant(), &key, 1)
            .await
            .expect("republish");
        assert_eq!(version, 2);

        let state = state.lock().unwrap_or_else(|error| error.into_inner());
        assert_eq!(state.republish_attempts.len(), 1);
        assert!(state.publish_attempts.is_empty());
        assert!(state.internal_publish_attempts.is_empty());
    }

    /// rollback 找不到源版本 → NotFound。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rollback_missing_version_is_not_found() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("v1");
        let err = svc
            .rollback_secret(tenant(), &key, 99)
            .await
            .expect_err("err");
        assert!(matches!(err, SecretServiceError::NotFound));
    }

    // ── 构造器必填参数（编译锁）────────────────────────────────────────────────────────────

    /// 编译锁：`SecretService::with_postgres` 须接受四个必填位置参（类型签名断言）。
    #[test]
    #[allow(clippy::type_complexity)]
    // reason: 四个互不可换的必填 DI port 正是本编译锁要完整表达的构造器签名。
    fn secret_service_ctor_required_params() {
        // 绑定函数指针断言签名——缺参 / 类型不符即编译失败（ADR-004 C5）。
        let _ctor: fn(
            Arc<DynSecretRepo<'static>>,
            Arc<DynSecretUnitOfWork<'static>>,
            Box<DynSecretResolver<'static>>,
            Box<dyn Clock>,
        ) -> SecretService = SecretService::with_postgres;
        let _ = _ctor;
    }

    // ── cross-tenant 隔离 ─────────────────────────────────────────────────────────────────

    /// tenant_a publish，tenant_b find_secret_ref 返 None。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn cross_tenant_isolation() {
        let svc = plain_service();
        let key = make_key("vault.db");
        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("publish");
        let found = svc.find_secret_ref(tenant_b(), &key).await.expect("find");
        assert_eq!(
            found, None,
            "跨租户隔离：tenant_b 不应读到 tenant_a 的 secret"
        );
    }

    // ── Finding 5 补充测试 ────────────────────────────────────────────────────────────────

    /// `find_secret_version` 返回历史版本引用（非活跃版本）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn find_secret_version_returns_historical() {
        let svc = plain_service();
        let key = make_key("vault.db");
        let ref_v1 = make_ref("store1", "db/v1");
        let ref_v2 = make_ref("store1", "db/v2");

        svc.publish_secret(tenant(), key.clone(), ref_v1.clone())
            .await
            .expect("v1");
        svc.publish_secret(tenant(), key.clone(), ref_v2.clone())
            .await
            .expect("v2");

        // 当前活跃应是 v2。
        let current = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(current, Some(ref_v2), "活跃引用应为 v2");

        // 历史版本 v1 仍可按版本号查询。
        let historical = svc
            .find_secret_version(tenant(), &key, 1)
            .await
            .expect("find v1 ok");
        assert_eq!(historical, Some(ref_v1), "历史版本 v1 应可查");
    }

    /// 同一 key 两次 publish 版本号单调递增；再 publish 与上次引用相同也视为新版本。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn publish_secret_version_monotonic() {
        let svc = plain_service();
        let key = make_key("vault.token");

        let v1 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v1"))
            .await
            .expect("v1");
        let v2 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v2"))
            .await
            .expect("v2");
        let v3 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "tk/v2"))
            .await
            .expect("v3 same ref");

        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(v3, 3, "再次 publish 应生成新版本（不去重）");
    }

    /// delete 后 find_secret_ref 返 None（tombstone 软删）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_find_secret_ref_none() {
        let svc = plain_service();
        let key = make_key("vault.db");

        svc.publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("publish");

        // 验证先能读到。
        let before = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert!(before.is_some(), "删除前应能读到引用");

        svc.delete_secret(tenant(), &key).await.expect("delete ok");

        let after = svc.find_secret_ref(tenant(), &key).await.expect("find ok");
        assert_eq!(after, None, "删除后 find_secret_ref 应返 None");
    }

    /// delete 后 re-publish → 版本号单调不重置（新版本号 > 删除前版本号）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn delete_then_republish_version_monotonic() {
        let svc = plain_service();
        let key = make_key("vault.db");

        let v1 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "k"))
            .await
            .expect("v1");
        svc.delete_secret(tenant(), &key).await.expect("delete");

        let v2 = svc
            .publish_secret(tenant(), key.clone(), make_ref("s", "k2"))
            .await
            .expect("re-publish");

        assert!(
            v2 > v1,
            "re-publish 版本号应大于删除前版本号（单调不重置）：v1={v1} v2={v2}"
        );
    }
}
