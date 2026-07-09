//! audit 应用层：session→链 append 订阅 handler + 跨租户 admin 读 handler + bootstrap 生命周期。
//!
//! 消费 identity 域 `identity.session-created` event（跨域只经 contract）→ 构造域 [`AuditRecord`] →
//! 经注入的 [`InMemAuditRepo`] **原子封链** append（domain hash chain，#1014 RW-W 写实，取代 G1 的 flat
//! `diport::AuditSink` 路径）。admin 读 handler（`GET /api/v1/audit/entries`，Admin listener）按已认证
//! 租户分页列出审计条目；指定 `tenantId` 时只允许已验证 SuperAdmin 在 durable cross-tenant audit append
//! 成功后读取目标租户审计链。
//!
//! # 鉴权作用域
//!
//! `AppCtx.principal` 是 `Arc<dyn runctx::PrincipalFacet>`（authn 的 `Principal` 经擦除注入；`runctx → authn`
//! 是禁止的依赖环，故 runctx 不按具体类型持有 principal，#1105）。本 handler 对普通 scoped read 只读 ctx
//! **tenant**；对 `tenantId` cross-tenant read 则使用 runtime bridge 写入的具体 `Arc<authn::Principal>`
//! 做 SuperAdmin 判定，再经 `Principal::audited_cross_tenant_visibility` 先写持久审计。未配置专用
//! `rss_audit_admin` repo 时 privileged read 返回 501 fail-closed。Admin listener auth 限定可达者。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main（audit sink 接缝）
//! ref: sigstore/sigstore-rs src/rekor（append-only transparency log → 域 hash chain）

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Query};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bootstrap::{Domain, KernelError, Registry, SubscriberHandler, SubscriberHandlerError};
use consistency::ConsumerGroup;
use diport::Message;
use futures::future::BoxFuture;
use generated::event::SubscriptionSpec;
use generated::event::identity_v1::{
    policy_updated::{
        IdentityPolicyUpdatedPayload, IdentityPolicyUpdatedPayloadActorKind,
        IdentityPolicyUpdatedPayloadChangeKind, SUBSCRIPTIONS as POLICY_UPDATED_SUBSCRIPTIONS,
    },
    role_assigned::{
        IdentityRoleAssignedPayload, IdentityRoleAssignedPayloadActorKind,
        SUBSCRIPTIONS as ROLE_ASSIGNED_SUBSCRIPTIONS,
    },
    role_revoked::{
        IdentityRoleRevokedPayload, IdentityRoleRevokedPayloadActorKind,
        SUBSCRIPTIONS as ROLE_REVOKED_SUBSCRIPTIONS,
    },
    session_created::{
        IdentitySessionCreatedPayload, SUBSCRIPTIONS as SESSION_CREATED_SUBSCRIPTIONS,
    },
};
use generated::http::audit_v1::{
    AuditEntryView, AuditListEntriesRequest, AuditListEntriesResponse, SPEC as AUDIT_LIST_HTTP_SPEC,
};
use httpserve::{Admin, ResourceProjection, Route, RouteAuthorizer};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Admin>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;

use crate::domain::{AuditEntry, AuditError, AuditOutcome, ResourceRef};
use crate::ports::{
    AuditAdminRepo, AuditListResult, AuditPage, AuditRecord, AuditRepo, DynAuditAdminRepo,
    DynAuditRepo, TenantRepoScope,
};

/// 本域 DomainId（在 generated `SUBSCRIPTIONS` 中筛选本域那条订阅；非 wire 元数据，是本域身份）。
const AUDIT_DOMAIN: &str = "audit";

/// 审计资源类别（const literal）。
const RESOURCE_KIND_SESSION: &str = "session";
const RESOURCE_KIND_ROLE_BINDING: &str = "role-binding";
const RESOURCE_KIND_POLICY: &str = "policy";
/// 登录动作（`domain:verb`，vocab::Action 形态）。
const ACTION_LOGIN: &str = "identity:login";
const ACTION_ROLE_ASSIGN: &str = "identity:role_assign";
const ACTION_ROLE_REVOKE: &str = "identity:role_revoke";
const ACTION_POLICY_CREATE: &str = "identity:policy_create";
const ACTION_POLICY_UPDATE: &str = "identity:policy_update";
const ACTION_POLICY_DEACTIVATE: &str = "identity:policy_deactivate";

/// admin 读路由组 nest 前缀（Admin listener；与 contracts/http/audit/v1 单源对齐）。
const AUDIT_ROUTE_PREFIX: &str = "/api/v1/audit";
/// admin 读路由在路由组内的**相对**路径——route group 经 `finalize_routes` nest 到 [`AUDIT_ROUTE_PREFIX`]
/// 下，组内 route 须用相对路径（axum `Router::nest` 语义）；用完整路径会被前缀再 nest 一次 ⇒ 真实挂载
/// 路径漂移成 `prefix‖full`（F1）。finalize 后真实路径 = `AUDIT_ROUTE_PREFIX` ‖ `AUDIT_ENTRIES_SUBPATH`
/// （= `/api/v1/audit/entries`，contract.toml / generated `HttpSpec` 声明值）。
const AUDIT_ENTRIES_SUBPATH: &str = "/entries";
const RESOURCE_KIND_AUDIT_ENTRIES: &str = "audit_entries";
const ACTION_AUDIT_LIST_CROSS_TENANT: &str = "audit:list-cross-tenant";

/// Audit consumer event variants that can be converted into [`AuditRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventKind {
    /// `identity.session-created`.
    SessionCreated,
    /// `identity.role-assigned`.
    RoleAssigned,
    /// `identity.role-revoked`.
    RoleRevoked,
    /// `identity.policy-updated`.
    PolicyUpdated,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditEventRecordError {
    #[error("audit event payload decode failed")]
    Decode(#[source] serde_json::Error),
    #[error("audit event tenant parse failed")]
    Tenant(#[source] vocab::TenantIdError),
    #[error("audit event action parse failed")]
    Action(#[source] vocab::ActionError),
    #[error("audit event session parse failed")]
    Session(#[source] ids::IdParseError),
}

/// Decode a generated identity event payload into the audit domain record shape.
///
/// This is the single generated-wire decode path for durable audit consumers; adapters keep only
/// storage transaction capability and call this domain helper.
pub fn audit_record_from_event_message(
    kind: AuditEventKind,
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    match kind {
        AuditEventKind::SessionCreated => session_created_record_from_message(message),
        AuditEventKind::RoleAssigned => role_assigned_record_from_message(message),
        AuditEventKind::RoleRevoked => role_revoked_record_from_message(message),
        AuditEventKind::PolicyUpdated => policy_updated_record_from_message(message),
    }
}

/// 分页上限（上限 500 由 [`vocab::Limit`] 类型 funnel 兜底；下限 ≥1 由 wire 类型 `NonZeroU32` 反序列化层
/// 保证；默认值 50 由 schema default 经 serde 派生）。
const MAX_LIMIT: u32 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetCursorError {
    Invalid,
    TenantMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageRequestError {
    Validation,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditReadAuthError {
    Forbidden,
}

struct AuditReadDeps<S>
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    repo: Arc<DynAuditRepo<'static>>,
    admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
    audit_sink: Arc<S>,
    audit_clock: Arc<dyn diport::Clock>,
}

impl<S> Clone for AuditReadDeps<S>
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            repo: self.repo.clone(),
            admin_repo: self.admin_repo.clone(),
            audit_sink: self.audit_sink.clone(),
            audit_clock: self.audit_clock.clone(),
        }
    }
}

/// i64 unix 秒 → `SystemTime`（负值收口为 epoch）。
fn from_unix_secs(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

fn session_created_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentitySessionCreatedPayload = serde_json::from_slice(message.payload.as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant =
        vocab::TenantId::parse(&payload.tenant_id).map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_LOGIN).map_err(AuditEventRecordError::Action)?;
    let session =
        ids::SessionId::parse(&payload.session_id).map_err(AuditEventRecordError::Session)?;
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.subject),
        actor_kind: vocab::PrincipalKind::User,
        action,
        resource: ResourceRef::new(RESOURCE_KIND_SESSION, session.as_uuid().to_string()),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at),
    })
}

fn role_assigned_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityRoleAssignedPayload = serde_json::from_slice(message.payload.as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant =
        vocab::TenantId::parse(&payload.tenant_id).map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_ROLE_ASSIGN).map_err(AuditEventRecordError::Action)?;
    let resource_id = role_binding_resource_id(tenant, &payload.role_id, &payload.subject);
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.assigned_by),
        actor_kind: assigned_actor_kind(payload.actor_kind),
        action,
        resource: ResourceRef::new(RESOURCE_KIND_ROLE_BINDING, resource_id),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at),
    })
}

fn role_revoked_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityRoleRevokedPayload = serde_json::from_slice(message.payload.as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant =
        vocab::TenantId::parse(&payload.tenant_id).map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_ROLE_REVOKE).map_err(AuditEventRecordError::Action)?;
    let resource_id = role_binding_resource_id(tenant, &payload.role_id, &payload.subject);
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.revoked_by),
        actor_kind: revoked_actor_kind(payload.actor_kind),
        action,
        resource: ResourceRef::new(RESOURCE_KIND_ROLE_BINDING, resource_id),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at),
    })
}

fn policy_updated_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityPolicyUpdatedPayload = serde_json::from_slice(message.payload.as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant =
        vocab::TenantId::parse(&payload.tenant_id).map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(policy_updated_action(payload.change_kind))
        .map_err(AuditEventRecordError::Action)?;
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.updated_by),
        actor_kind: policy_updated_actor_kind(payload.actor_kind),
        action,
        resource: ResourceRef::new(
            RESOURCE_KIND_POLICY,
            policy_resource_id(
                tenant,
                &payload.policy_id,
                &payload.contract_id,
                &payload.permission,
            ),
        ),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at),
    })
}

/// `SystemTime` → i64 unix 秒（epoch 前 / 溢出收口为 0 / i64::MAX）。
fn to_unix_secs(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `vocab::PrincipalKind` → wire 字符串（camelCase）。
fn principal_kind_wire(kind: vocab::PrincipalKind) -> &'static str {
    match kind {
        vocab::PrincipalKind::User => "user",
        vocab::PrincipalKind::Device => "device",
        vocab::PrincipalKind::Admin => "admin",
        vocab::PrincipalKind::SuperAdmin => "superAdmin",
        vocab::PrincipalKind::Service => "service",
        vocab::PrincipalKind::Anonymous => "anonymous",
        // reason: 跨 crate non_exhaustive，未知 kind fail-safe 落 "unknown"（不泄、不 panic）。
        _ => "unknown",
    }
}

/// `AuditOutcome` → wire 字符串（同 crate 穷尽 match ⇒ 新变体编译期强制补）。
fn outcome_wire(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Success => "success",
        AuditOutcome::Denied => "denied",
        AuditOutcome::Error => "error",
    }
}

/// `EntryHash` 字节 → 不透明 base64url 摘要（wire 用；非可逆校验凭据）。
fn encode_hash(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 域条目 → wire view（域→wire 转换收口在 handler 层；domain entity 不直接序列化）。
fn to_view(entry: &AuditEntry, projection: ResourceProjection) -> AuditEntryView {
    AuditEntryView {
        seq: i64::try_from(entry.seq()).unwrap_or(i64::MAX),
        tenant_id: projection.render(
            vocab::ProjectionField::AuditTenantId,
            &entry.tenant().to_string(),
        ),
        actor: projection.render(
            vocab::ProjectionField::AuditActor,
            &entry.actor().as_uuid().to_string(),
        ),
        actor_kind: principal_kind_wire(entry.actor_kind()).to_string(),
        action: entry.action().as_str().to_string(),
        resource_kind: entry.resource().kind().to_string(),
        resource_id: projection.render(
            vocab::ProjectionField::AuditResourceId,
            entry.resource().id(),
        ),
        outcome: outcome_wire(entry.outcome()).to_string(),
        recorded_at: to_unix_secs(entry.recorded_at()),
        entry_hash: encode_hash(entry.entry_hash().as_bytes()),
    }
}

/// 仓储分页结果 → wire 响应信封（`data` / `nextCursor` / `hasMore`）。
fn to_response(
    result: AuditListResult,
    projection: ResourceProjection,
) -> AuditListEntriesResponse {
    AuditListEntriesResponse {
        data: result
            .entries
            .iter()
            .map(|entry| to_view(entry, projection))
            .collect(),
        next_cursor: result.next_cursor.map(|c| c.as_str().to_string()),
        has_more: result.has_more,
    }
}

fn to_target_response(
    tenant: vocab::TenantId,
    result: AuditListResult,
    projection: ResourceProjection,
) -> Result<AuditListEntriesResponse, TargetCursorError> {
    let next_cursor = match result.next_cursor {
        Some(cursor) => Some(encode_target_cursor(tenant, &cursor)?),
        None => None,
    };
    Ok(AuditListEntriesResponse {
        data: result
            .entries
            .iter()
            .map(|entry| to_view(entry, projection))
            .collect(),
        next_cursor: next_cursor.map(|c| c.as_str().to_string()),
        has_more: result.has_more,
    })
}

fn encode_target_cursor(
    tenant: vocab::TenantId,
    inner: &vocab::Cursor,
) -> Result<vocab::Cursor, TargetCursorError> {
    let raw = format!("{tenant}:{}", inner.as_str());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    vocab::Cursor::parse(&encoded).map_err(|_| TargetCursorError::Invalid)
}

fn decode_target_cursor(
    expected_tenant: vocab::TenantId,
    cursor: &vocab::Cursor,
) -> Result<vocab::Cursor, TargetCursorError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| TargetCursorError::Invalid)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| TargetCursorError::Invalid)?;
    let Some((tenant_raw, inner_raw)) = raw.split_once(':') else {
        return Err(TargetCursorError::Invalid);
    };
    let tenant = vocab::TenantId::parse(tenant_raw).map_err(|_| TargetCursorError::Invalid)?;
    if tenant != expected_tenant {
        return Err(TargetCursorError::TenantMismatch);
    }
    vocab::Cursor::parse(inner_raw).map_err(|_| TargetCursorError::Invalid)
}

fn request_id_from_parts(
    headers: &axum::http::HeaderMap,
    extensions: &axum::http::Extensions,
) -> String {
    httpserve::request_id_str(extensions)
        .or_else(|| {
            headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_default()
        .to_string()
}

fn request_correlation(headers: &axum::http::HeaderMap, request_id: &str) -> String {
    if let Some(correlation) = diagctx::correlation() {
        return correlation.as_str().to_string();
    }
    headers
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| diagctx::CorrelationId::parse(v).ok())
        .map(|v| v.as_str().to_string())
        .unwrap_or_else(|| request_id.to_string())
}

fn page_from_request(request: &AuditListEntriesRequest) -> Result<AuditPage, PageRequestError> {
    let limit_value = request.limit.get().min(MAX_LIMIT);
    let limit = vocab::Limit::new(limit_value as u16).map_err(|_| PageRequestError::Internal)?;
    let cursor = match request.cursor.as_deref() {
        None => None,
        Some(raw) => Some(vocab::Cursor::parse(raw).map_err(|_| PageRequestError::Validation)?),
    };
    Ok(AuditPage { limit, cursor })
}

fn validation_or_internal(kind: PageRequestError, request_id: &str) -> Response {
    match kind {
        PageRequestError::Validation => httpserve::error::validation_bad_request(request_id),
        PageRequestError::Internal => httpserve::error::internal_error(request_id),
    }
}

/// admin 读 handler：无 `tenantId` 走已认证 ctx 租户；带 `tenantId` 走 audited SuperAdmin 指定租户读。
async fn list_entries<S>(
    deps: AuditReadDeps<S>,
    principal: Option<Arc<authn::Principal>>,
    authenticated: Option<httpserve::Authenticated>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    request: AuditListEntriesRequest,
    request_id: String,
    correlation_id: String,
) -> Response
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    if request.tenant_id.is_some() {
        return list_entries_target_tenant(
            deps,
            principal,
            authenticated,
            authorizer,
            request,
            request_id,
            correlation_id,
        )
        .await;
    }
    list_entries_scoped(deps.repo, authenticated, authorizer, request, request_id).await
}

async fn list_entries_scoped(
    repo: Arc<DynAuditRepo<'static>>,
    authenticated: Option<httpserve::Authenticated>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    request: AuditListEntriesRequest,
    request_id: String,
) -> Response {
    // 租户 fail-closed：缺 ctx（未经认证通道）即 500，不静默落空租户。
    let Ok(tenant) = runctx::try_with(|ctx| *ctx.tenant()) else {
        return httpserve::error::internal_error(&request_id);
    };
    let projection =
        match authorize_read_projection(authorizer, authenticated.as_ref(), tenant).await {
            Ok(projection) => projection,
            Err(AuditReadAuthError::Forbidden) => return httpserve::error::forbidden(&request_id),
        };
    // 下限 ≥1 由 wire 类型 `NonZeroU32` 在反序列化层 type-enforced（F5）：limit=0 / 负值反序列化即失败
    // → QueryRejection → 统一 400（见路由闭包）。此处仅做上限 500 截断（contract 语义）；截断后 ∈[1,500]，
    // Limit::new 必 Ok（Err 分支 fail-closed 防御，不可达）。
    let page = match page_from_request(&request) {
        Ok(page) => page,
        Err(kind) => return validation_or_internal(kind, &request_id),
    };
    let scope = TenantRepoScope::from_authenticated_tenant(tenant);
    match repo.list(scope, page).await {
        Ok(result) => Json(to_response(result, projection)).into_response(),
        // 语义无效游标（合法 base64url 但非有效页索引）是客户端错误 → 400（F4）。
        Err(AuditError::InvalidCursor) => httpserve::error::validation_bad_request(&request_id),
        // 链完整性等其它失败不可静默：记录后 500（无 wire 泄漏）。
        Err(error) => {
            tracing::error!(tenant = %tenant, error = %error, "audit handler: list failed");
            httpserve::error::internal_error(&request_id)
        }
    }
}

async fn list_entries_target_tenant<S>(
    deps: AuditReadDeps<S>,
    principal: Option<Arc<authn::Principal>>,
    authenticated: Option<httpserve::Authenticated>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    request: AuditListEntriesRequest,
    request_id: String,
    correlation_id: String,
) -> Response
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    let Some(target_raw) = request.tenant_id.as_deref() else {
        return httpserve::error::validation_bad_request(&request_id);
    };
    let target = match vocab::TenantId::parse(target_raw) {
        Ok(tenant) => tenant,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let Some(principal) = principal else {
        return httpserve::error::forbidden(&request_id);
    };
    if principal.kind() != vocab::PrincipalKind::SuperAdmin {
        return httpserve::error::forbidden(&request_id);
    }
    let projection =
        match authorize_read_projection(authorizer, authenticated.as_ref(), target).await {
            Ok(projection) => projection,
            Err(AuditReadAuthError::Forbidden) => return httpserve::error::forbidden(&request_id),
        };
    let Some(admin_repo) = deps.admin_repo else {
        return httpserve::error::not_implemented(&request_id);
    };

    let mut page = match page_from_request(&request) {
        Ok(page) => page,
        Err(kind) => return validation_or_internal(kind, &request_id),
    };
    if let Some(cursor) = page.cursor.as_ref() {
        page.cursor = match decode_target_cursor(target, cursor) {
            Ok(inner) => Some(inner),
            Err(TargetCursorError::Invalid | TargetCursorError::TenantMismatch) => {
                return httpserve::error::validation_bad_request(&request_id);
            }
        };
    }

    let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
    let ctx = runctx::RequestCtx::new(target, facet);
    let audit = match authn::CrossTenantAuditContext::new(
        RESOURCE_KIND_AUDIT_ENTRIES,
        target.to_string(),
        ACTION_AUDIT_LIST_CROSS_TENANT,
        request_id.clone(),
        correlation_id,
    ) {
        Ok(audit) => audit,
        Err(_) => return httpserve::error::internal_error(&request_id),
    };
    match principal
        .audited_cross_tenant_visibility(
            &ctx,
            deps.audit_sink.as_ref(),
            deps.audit_clock.as_ref(),
            &audit,
        )
        .await
    {
        Ok(_) => {}
        Err(authn::CrossTenantError::NotSuperAdmin) => {
            return httpserve::error::forbidden(&request_id);
        }
        Err(authn::CrossTenantError::Audit(_)) => {
            return httpserve::error::internal_error(&request_id);
        }
        Err(_) => {
            return httpserve::error::internal_error(&request_id);
        }
    }

    match admin_repo.list_tenant(target, page).await {
        Ok(result) => match to_target_response(target, result, projection) {
            Ok(response) => Json(response).into_response(),
            Err(_) => httpserve::error::internal_error(&request_id),
        },
        Err(AuditError::InvalidCursor) => httpserve::error::validation_bad_request(&request_id),
        Err(error) => {
            tracing::error!(tenant = %target, error = %error, "audit handler: target-tenant list failed");
            httpserve::error::internal_error(&request_id)
        }
    }
}

async fn authorize_read_projection(
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    authenticated: Option<&httpserve::Authenticated>,
    tenant: vocab::TenantId,
) -> Result<ResourceProjection, AuditReadAuthError> {
    let Some(permission) = AUDIT_LIST_HTTP_SPEC.auth.permission else {
        return Err(AuditReadAuthError::Forbidden);
    };
    httpserve::authorize_subject_for_permission(
        authorizer,
        authenticated,
        AUDIT_LIST_HTTP_SPEC.contract_id,
        permission,
        tenant,
        None,
    )
    .await
    .map(|subject| subject.projection())
    .ok_or(AuditReadAuthError::Forbidden)
}

/// session-created 订阅 handler：解码 payload → 构造 [`AuditRecord`] → [`AuditRepo`] 原子封链 append。
///
/// crate-local（私有 module 内，不外泄）；持 `Arc<DynAuditRepo>`（erased provider）：clone 进 `Send` future
/// （被 eventexec 分发 / `tokio::spawn`；`AuditRepo` Send 变体 future + `DynAuditRepo: Send + Sync` ⇒ `Arc` 可跨 await 持有）。
pub(crate) struct SessionCreatedAuditHandler {
    repo: Arc<DynAuditRepo<'static>>,
}

impl SessionCreatedAuditHandler {
    /// 注入审计仓储构造。
    pub(crate) fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl SubscriberHandler for SessionCreatedAuditHandler {
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let repo = self.repo.clone();
        Box::pin(async move {
            let msg_id = message.id.as_str().to_string();
            let record = audit_record_from_event_message(AuditEventKind::SessionCreated, &message)
                .map_err(|e| {
                    reject_audit_event_record_error(&msg_id, "identity.session-created", e)
                })?;
            let scope = TenantRepoScope::from_authenticated_tenant(record.tenant);
            repo.append(scope, record).await.map_err(|e| {
                tracing::error!(
                    message_id = msg_id.as_str(),
                    error = %e,
                    "audit handler: chain append failed"
                );
                // 瞬态：append/存储失败可恢复，走 ConsumerBase 有界重试预算，不首投即 DLX（F2/C2）。
                SubscriberHandlerError::transient(e)
            })?;
            Ok(())
        })
    }
}

fn reject_audit_event_record_error(
    message_id: &str,
    event_name: &'static str,
    error: AuditEventRecordError,
) -> SubscriberHandlerError {
    tracing::error!(
        message_id,
        event_name,
        error = %error,
        "audit handler: event payload rejected"
    );
    SubscriberHandlerError::permanent(error)
}

fn role_binding_resource_id(tenant: vocab::TenantId, role_id: &str, subject: &str) -> String {
    format!("tenant/{tenant}/role/{role_id}/subject/{subject}")
}

fn policy_resource_id(
    tenant: vocab::TenantId,
    policy_id: &str,
    contract_id: &str,
    permission: &str,
) -> String {
    format!("tenant/{tenant}/policy/{policy_id}/contract/{contract_id}/permission/{permission}")
}

fn policy_updated_action(kind: IdentityPolicyUpdatedPayloadChangeKind) -> &'static str {
    match kind {
        IdentityPolicyUpdatedPayloadChangeKind::Created => ACTION_POLICY_CREATE,
        IdentityPolicyUpdatedPayloadChangeKind::Updated => ACTION_POLICY_UPDATE,
        IdentityPolicyUpdatedPayloadChangeKind::Deactivated => ACTION_POLICY_DEACTIVATE,
    }
}

fn assigned_actor_kind(kind: IdentityRoleAssignedPayloadActorKind) -> vocab::PrincipalKind {
    match kind {
        IdentityRoleAssignedPayloadActorKind::User => vocab::PrincipalKind::User,
        IdentityRoleAssignedPayloadActorKind::Device => vocab::PrincipalKind::Device,
        IdentityRoleAssignedPayloadActorKind::Admin => vocab::PrincipalKind::Admin,
        IdentityRoleAssignedPayloadActorKind::SuperAdmin => vocab::PrincipalKind::SuperAdmin,
        IdentityRoleAssignedPayloadActorKind::Service => vocab::PrincipalKind::Service,
        IdentityRoleAssignedPayloadActorKind::Anonymous => vocab::PrincipalKind::Anonymous,
    }
}

fn revoked_actor_kind(kind: IdentityRoleRevokedPayloadActorKind) -> vocab::PrincipalKind {
    match kind {
        IdentityRoleRevokedPayloadActorKind::User => vocab::PrincipalKind::User,
        IdentityRoleRevokedPayloadActorKind::Device => vocab::PrincipalKind::Device,
        IdentityRoleRevokedPayloadActorKind::Admin => vocab::PrincipalKind::Admin,
        IdentityRoleRevokedPayloadActorKind::SuperAdmin => vocab::PrincipalKind::SuperAdmin,
        IdentityRoleRevokedPayloadActorKind::Service => vocab::PrincipalKind::Service,
        IdentityRoleRevokedPayloadActorKind::Anonymous => vocab::PrincipalKind::Anonymous,
    }
}

fn policy_updated_actor_kind(kind: IdentityPolicyUpdatedPayloadActorKind) -> vocab::PrincipalKind {
    match kind {
        IdentityPolicyUpdatedPayloadActorKind::User => vocab::PrincipalKind::User,
        IdentityPolicyUpdatedPayloadActorKind::Device => vocab::PrincipalKind::Device,
        IdentityPolicyUpdatedPayloadActorKind::Admin => vocab::PrincipalKind::Admin,
        IdentityPolicyUpdatedPayloadActorKind::SuperAdmin => vocab::PrincipalKind::SuperAdmin,
        IdentityPolicyUpdatedPayloadActorKind::Service => vocab::PrincipalKind::Service,
        IdentityPolicyUpdatedPayloadActorKind::Anonymous => vocab::PrincipalKind::Anonymous,
    }
}

async fn append_audit_record(
    repo: Arc<DynAuditRepo<'static>>,
    message_id: &str,
    event_name: &'static str,
    record: AuditRecord,
) -> Result<(), SubscriberHandlerError> {
    let scope = TenantRepoScope::from_authenticated_tenant(record.tenant);
    repo.append(scope, record).await.map_err(|e| {
        tracing::error!(
            message_id,
            event_name,
            error = %e,
            "audit handler: chain append failed"
        );
        SubscriberHandlerError::transient(e)
    })
}

pub(crate) struct RoleAssignedAuditHandler {
    repo: Arc<DynAuditRepo<'static>>,
}

impl RoleAssignedAuditHandler {
    pub(crate) fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl SubscriberHandler for RoleAssignedAuditHandler {
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let repo = self.repo.clone();
        Box::pin(async move {
            let msg_id = message.id.as_str().to_string();
            let record = audit_record_from_event_message(AuditEventKind::RoleAssigned, &message)
                .map_err(|e| {
                    reject_audit_event_record_error(&msg_id, "identity.role-assigned", e)
                })?;
            append_audit_record(repo, &msg_id, "identity.role-assigned", record).await
        })
    }
}

pub(crate) struct RoleRevokedAuditHandler {
    repo: Arc<DynAuditRepo<'static>>,
}

impl RoleRevokedAuditHandler {
    pub(crate) fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl SubscriberHandler for RoleRevokedAuditHandler {
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let repo = self.repo.clone();
        Box::pin(async move {
            let msg_id = message.id.as_str().to_string();
            let record = audit_record_from_event_message(AuditEventKind::RoleRevoked, &message)
                .map_err(|e| {
                    reject_audit_event_record_error(&msg_id, "identity.role-revoked", e)
                })?;
            append_audit_record(repo, &msg_id, "identity.role-revoked", record).await
        })
    }
}

pub(crate) struct PolicyUpdatedAuditHandler {
    repo: Arc<DynAuditRepo<'static>>,
}

impl PolicyUpdatedAuditHandler {
    pub(crate) fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
        Self { repo }
    }
}

impl SubscriberHandler for PolicyUpdatedAuditHandler {
    fn handle(&self, message: Message) -> BoxFuture<'static, Result<(), SubscriberHandlerError>> {
        let repo = self.repo.clone();
        Box::pin(async move {
            let msg_id = message.id.as_str().to_string();
            let record = audit_record_from_event_message(AuditEventKind::PolicyUpdated, &message)
                .map_err(|e| {
                reject_audit_event_record_error(&msg_id, "identity.policy-updated", e)
            })?;
            append_audit_record(repo, &msg_id, "identity.policy-updated", record).await
        })
    }
}

fn register_audit_subscriber(
    reg: &mut Registry,
    specs: &[SubscriptionSpec],
    handler: Box<dyn SubscriberHandler>,
) -> Result<(), KernelError> {
    let spec = specs
        .iter()
        .find(|s| s.consumer == AUDIT_DOMAIN)
        .ok_or(KernelError::Subscriber)?;
    let group = ConsumerGroup::parse(spec.group).map_err(|_| KernelError::Subscriber)?;
    reg.subscriber(spec.contract_id, spec.topic, spec.consumer, group, handler)
}

/// audit 域 bootstrap 生命周期：声明 session-created 订阅 + admin 读路由组。
///
/// 持 erased [`Arc<DynAuditRepo>`](crate::ports::DynAuditRepo)（ADR-005 Option 2 域形 repo port 注入；组合根选
/// provider：prod postgres `PgAuditRepo` / demo in-mem [`crate::internal::mem::InMemAuditRepo`]）——订阅 handler +
/// admin 读路由 clone 共享**同一链 store**（故 `Arc`，`DynAuditRepo: Send + Sync`）。链 HMAC key 强度 fail-fast
/// 在组合根构造 [`AuditChainHasher`](crate::ports::AuditChainHasher) 时收口（`new` 返回 `Option`，弱 key → `None`），
/// 不在本域——本域只消费已装配的 erased provider。
pub struct AuditDomain<S>
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    repo: Arc<DynAuditRepo<'static>>,
    admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
    audit_sink: Arc<S>,
    audit_clock: Arc<dyn diport::Clock>,
}

impl<S> AuditDomain<S>
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    /// 注入 erased 审计仓储 provider 构造。
    ///
    /// `admin_repo=None` 表示未配置 `rss_audit_admin` pool；普通 scoped read 不受影响，带 `tenantId` 的
    /// privileged read fail-closed 为 501。
    pub fn new(
        repo: Arc<DynAuditRepo<'static>>,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        audit_sink: S,
        audit_clock: Arc<dyn diport::Clock>,
    ) -> Self {
        Self {
            repo,
            admin_repo,
            audit_sink: Arc::new(audit_sink),
            audit_clock,
        }
    }
}

impl<S> Domain for AuditDomain<S>
where
    S: diport::AuditSink + Send + Sync + 'static,
{
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        // 订阅元数据（contract_id / topic / group）单源自 generated `SUBSCRIPTIONS`（契约 codegen 派生）——
        // 不手维护平行 const，消除 contract↔consumer 漂移（AI-HARD：codegen funnel + golden）。缺失即 fail-fast。
        register_audit_subscriber(
            reg,
            SESSION_CREATED_SUBSCRIPTIONS,
            Box::new(SessionCreatedAuditHandler::new(self.repo.clone())),
        )?;
        register_audit_subscriber(
            reg,
            ROLE_ASSIGNED_SUBSCRIPTIONS,
            Box::new(RoleAssignedAuditHandler::new(self.repo.clone())),
        )?;
        register_audit_subscriber(
            reg,
            ROLE_REVOKED_SUBSCRIPTIONS,
            Box::new(RoleRevokedAuditHandler::new(self.repo.clone())),
        )?;
        register_audit_subscriber(
            reg,
            POLICY_UPDATED_SUBSCRIPTIONS,
            Box::new(PolicyUpdatedAuditHandler::new(self.repo.clone())),
        )?;

        // admin 读路由组（Admin listener，typed marker；operator/管理面，非业务对外 Primary）。
        let read_deps = AuditReadDeps {
            repo: self.repo.clone(),
            admin_repo: self.admin_repo.clone(),
            audit_sink: self.audit_sink.clone(),
            audit_clock: self.audit_clock.clone(),
        };
        reg.route_group::<Admin>(AUDIT_ROUTE_PREFIX, move |rb| {
            let read_deps = read_deps.clone();
            let handler = axum::routing::get(
                move |principal: Option<Extension<Arc<authn::Principal>>>,
                      authenticated: Option<Extension<httpserve::Authenticated>>,
                      authorizer: Option<Extension<Arc<dyn RouteAuthorizer>>>,
                      query: Result<Query<AuditListEntriesRequest>, QueryRejection>,
                      request: axum::extract::Request| {
                    let read_deps = read_deps.clone();
                    let principal = principal.map(|Extension(principal)| principal);
                    let authenticated = authenticated.map(|Extension(authenticated)| authenticated);
                    let authorizer = authorizer.map(|Extension(authorizer)| authorizer);
                    let request_id = request_id_from_parts(request.headers(), request.extensions());
                    let correlation_id = request_correlation(request.headers(), &request_id);
                    async move {
                        // F6：Query 解析失败（非法 limit / 未知字段）不返回 axum 裸 400——统一 envelope。
                        let Ok(query) = query else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        list_entries(
                            read_deps,
                            principal,
                            authenticated,
                            authorizer,
                            query.0,
                            request_id,
                            correlation_id,
                        )
                        .await
                    }
                },
            );
            // route group 内用相对 SUBPATH；nest 到 AUDIT_ROUTE_PREFIX 下真实路径 = AUDIT_ENTRIES_PATH（F1）。
            // Admin listener typed builder：`mount`（非-Primary，无 opt-out；Admin 不可携 opt-out）。
            Ok(rb.mount(
                Route {
                    method: axum::http::Method::GET,
                    path: AUDIT_ENTRIES_SUBPATH,
                    contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                },
                handler,
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use std::future::Future;
    use std::pin::Pin;
    use tower::ServiceExt as _;

    use crate::domain::AuditChainHasher;
    use crate::domain::test_support::{TestKeyedHasher, keyed_hasher};
    use crate::internal::mem::InMemAuditRepo;
    use crate::ports::AuditLedgerVerifyReport;

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const CANON_SUBJECT: &str = "11111111-2222-4333-8444-555555555555";
    /// canonical UUID session_id（审计 resource id 是 typed `ids::SessionId`，非 uuid 被 fail-closed 拒，F3）。
    const CANON_SESSION: &str = "22222222-3333-4444-8555-666666666666";
    const ROLE_ID: &str = "tenant-admin";
    const POLICY_ID: &str = "policy-admin-read";
    /// contract.toml 声明的完整路径（= `AUDIT_ROUTE_PREFIX` ‖ `AUDIT_ENTRIES_SUBPATH`）；测试据此断言
    /// finalize 后真实挂载路径 + 直挂 handler-logic 测试路径。
    const AUDIT_ENTRIES_PATH: &str = "/api/v1/audit/entries";

    /// erased in-mem 审计仓储（订阅 + 路由共享形：`Arc<DynAuditRepo>`，同生产装配路径）。
    fn repo() -> Arc<DynAuditRepo<'static>> {
        Arc::from(DynAuditRepo::new_box(InMemAuditRepo::new(keyed_hasher(
            0x5a,
        ))))
    }

    #[derive(Clone, Default)]
    struct NoopAuditSink;

    impl diport::AuditSink for NoopAuditSink {
        async fn record(&self, _event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }
    }

    struct TestClock;

    impl diport::Clock for TestClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::UNIX_EPOCH
        }
    }

    fn audit_sink() -> NoopAuditSink {
        NoopAuditSink
    }

    fn audit_clock() -> Arc<dyn diport::Clock> {
        Arc::new(TestClock)
    }

    fn domain(repo: Arc<DynAuditRepo<'static>>) -> AuditDomain<NoopAuditSink> {
        AuditDomain::new(repo, None, audit_sink(), audit_clock())
    }

    struct DelegatingAdminRepo {
        repo: Arc<DynAuditRepo<'static>>,
    }

    impl DelegatingAdminRepo {
        fn new(repo: Arc<DynAuditRepo<'static>>) -> Self {
            Self { repo }
        }
    }

    impl crate::ports::AuditAdminRepo for DelegatingAdminRepo {
        async fn list_tenant(
            &self,
            tenant: vocab::TenantId,
            page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            self.repo
                .list(TenantRepoScope::for_test(tenant), page)
                .await
        }

        async fn verify_tenant(
            &self,
            tenant: vocab::TenantId,
            batch: vocab::Limit,
        ) -> Result<AuditLedgerVerifyReport, AuditError> {
            let mut cursor = None;
            let mut checked_entries = 0u64;
            loop {
                let result = self
                    .repo
                    .list(
                        TenantRepoScope::for_test(tenant),
                        AuditPage {
                            limit: batch,
                            cursor,
                        },
                    )
                    .await?;
                checked_entries = checked_entries
                    .checked_add(u64::try_from(result.entries.len()).map_err(AuditError::storage)?)
                    .ok_or(AuditError::SequenceGap)?;
                if !result.has_more {
                    break;
                }
                cursor = result.next_cursor;
                if cursor.is_none() {
                    return Err(AuditError::SequenceGap);
                }
            }
            Ok(AuditLedgerVerifyReport {
                tenant,
                checked_entries,
            })
        }
    }

    fn admin_repo(repo: Arc<DynAuditRepo<'static>>) -> Arc<DynAuditAdminRepo<'static>> {
        Arc::from(DynAuditAdminRepo::new_box(DelegatingAdminRepo::new(repo)))
    }

    #[derive(Default)]
    struct CountingAdminRepo {
        list_calls: Arc<std::sync::atomic::AtomicUsize>,
        verify_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingAdminRepo {
        fn list_calls(&self) -> Arc<std::sync::atomic::AtomicUsize> {
            Arc::clone(&self.list_calls)
        }

        fn boxed(self) -> Arc<DynAuditAdminRepo<'static>> {
            Arc::from(DynAuditAdminRepo::new_box(self))
        }
    }

    impl crate::ports::AuditAdminRepo for CountingAdminRepo {
        async fn list_tenant(
            &self,
            _tenant: vocab::TenantId,
            _page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(AuditError::HashMismatch)
        }

        async fn verify_tenant(
            &self,
            tenant: vocab::TenantId,
            _batch: vocab::Limit,
        ) -> Result<AuditLedgerVerifyReport, AuditError> {
            self.verify_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(AuditLedgerVerifyReport {
                tenant,
                checked_entries: 0,
            })
        }
    }

    #[derive(Clone)]
    struct RecordingAuditSink {
        events: Arc<std::sync::Mutex<Vec<diport::AuditEvent>>>,
        fail: bool,
    }

    impl RecordingAuditSink {
        fn ok() -> Self {
            Self {
                events: Arc::new(std::sync::Mutex::new(Vec::new())),
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
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl diport::AuditSink for RecordingAuditSink {
        async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
            if self.fail {
                return Err(diport::AuditSinkError::new(std::io::Error::other(
                    "test audit failure",
                )));
            }
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
            Ok(())
        }

        async fn shutdown(&self) -> Result<(), diport::AuditSinkError> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ProjectionAuthorizer {
        fields: &'static [vocab::ProjectionField],
        allow: bool,
    }

    impl httpserve::RouteAuthorizer for ProjectionAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            Box::pin(async move {
                if self.allow
                    && request.contract_id == AUDIT_LIST_HTTP_SPEC.contract_id
                    && request.permission == vocab::AUDIT_READ_PERMISSION
                {
                    if self.fields.is_empty() {
                        httpserve::RouteAuthorizationDecision::Allow
                    } else {
                        httpserve::RouteAuthorizationDecision::allow_with_unmasked_fields(
                            self.fields,
                        )
                    }
                } else {
                    httpserve::RouteAuthorizationDecision::Deny
                }
            })
        }
    }

    fn projection_authorizer(
        fields: &'static [vocab::ProjectionField],
    ) -> Arc<dyn httpserve::RouteAuthorizer> {
        Arc::new(ProjectionAuthorizer {
            fields,
            allow: true,
        })
    }

    fn denying_authorizer() -> Arc<dyn httpserve::RouteAuthorizer> {
        Arc::new(ProjectionAuthorizer {
            fields: &[],
            allow: false,
        })
    }

    #[allow(clippy::expect_used)]
    fn default_admin_principal() -> Arc<authn::Principal> {
        principal(
            vocab::PrincipalKind::Admin,
            Some(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
        )
    }

    fn principal(
        kind: vocab::PrincipalKind,
        tenant: Option<vocab::TenantId>,
    ) -> Arc<authn::Principal> {
        Arc::new(authn::test_support::principal(kind, CANON_SUBJECT, tenant))
    }

    #[allow(clippy::expect_used)]
    fn payload_bytes(subject: &str, tenant: &str) -> Vec<u8> {
        payload_bytes_with_session(subject, tenant, CANON_SESSION)
    }

    #[allow(clippy::expect_used)]
    fn payload_bytes_with_session(subject: &str, tenant: &str, session_id: &str) -> Vec<u8> {
        let payload = IdentitySessionCreatedPayload {
            session_id: session_id.to_string(),
            // subject 是 typed `uuid::Uuid`（#1277 F1，schema `format:uuid`）——helper 入参为 canonical UUID 串，
            // 非 UUID 用例（rejects_non_canonical_subject）走 raw JSON、不经本构造器。
            subject: uuid::Uuid::parse_str(subject).expect("canonical subject uuid"),
            tenant_id: tenant.to_string(),
            occurred_at: 1_700_000_000,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[allow(clippy::expect_used)]
    fn role_assigned_payload_bytes() -> Vec<u8> {
        role_assigned_payload_bytes_for("target-subject")
    }

    #[allow(clippy::expect_used)]
    fn role_assigned_payload_bytes_for(subject: &str) -> Vec<u8> {
        role_assigned_payload_bytes_for_kind(subject, IdentityRoleAssignedPayloadActorKind::Admin)
    }

    #[allow(clippy::expect_used)]
    fn role_assigned_payload_bytes_for_kind(
        subject: &str,
        actor_kind: IdentityRoleAssignedPayloadActorKind,
    ) -> Vec<u8> {
        let payload = IdentityRoleAssignedPayload {
            role_id: ROLE_ID.to_string(),
            subject: subject.to_string(),
            assigned_by: uuid::Uuid::parse_str(CANON_SUBJECT).expect("canonical actor uuid"),
            actor_kind,
            tenant_id: CANON_TENANT.to_string(),
            occurred_at: 1_700_000_100,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[allow(clippy::expect_used)]
    fn role_revoked_payload_bytes() -> Vec<u8> {
        role_revoked_payload_bytes_for("target-subject")
    }

    #[allow(clippy::expect_used)]
    fn role_revoked_payload_bytes_for(subject: &str) -> Vec<u8> {
        let payload = IdentityRoleRevokedPayload {
            role_id: ROLE_ID.to_string(),
            subject: subject.to_string(),
            revoked_by: uuid::Uuid::parse_str(CANON_SUBJECT).expect("canonical actor uuid"),
            actor_kind: IdentityRoleRevokedPayloadActorKind::Admin,
            tenant_id: CANON_TENANT.to_string(),
            occurred_at: 1_700_000_200,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    fn expected_role_binding_resource_id(subject: &str) -> String {
        format!("tenant/{CANON_TENANT}/role/{ROLE_ID}/subject/{subject}")
    }

    #[allow(clippy::expect_used)]
    fn policy_updated_payload_bytes(
        change_kind: IdentityPolicyUpdatedPayloadChangeKind,
    ) -> Vec<u8> {
        let payload = IdentityPolicyUpdatedPayload {
            policy_id: POLICY_ID.to_string(),
            change_kind,
            version: std::num::NonZeroU32::new(2).expect("non-zero version"),
            contract_id: "identity.policies-get".to_string(),
            permission: "identity:policy:read".to_string(),
            updated_by: uuid::Uuid::parse_str(CANON_SUBJECT).expect("canonical actor uuid"),
            actor_kind: IdentityPolicyUpdatedPayloadActorKind::Admin,
            tenant_id: CANON_TENANT.to_string(),
            occurred_at: 1_700_000_300,
        };
        serde_json::to_vec(&payload).expect("encode")
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn session_created_appends_verifiable_chain_entry() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-1",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("handle ok");

        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let page = AuditPage {
            limit: vocab::Limit::new(10).expect("limit"),
            cursor: None,
        };
        let listed = repo
            .list(TenantRepoScope::for_test(tenant), page)
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 1);
        let entry = &listed.entries[0];
        assert_eq!(entry.seq(), 0);
        assert_eq!(entry.action().as_str(), ACTION_LOGIN);
        assert_eq!(entry.resource().kind(), RESOURCE_KIND_SESSION);
        assert_eq!(entry.resource().id(), CANON_SESSION);
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        // 落库链条可被同 key hasher 验证完整。
        let verifier: AuditChainHasher<TestKeyedHasher> = keyed_hasher(0x5a);
        assert!(verifier.verify(&listed.entries).is_ok());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_assigned_appends_audit_entry() {
        let repo = repo();
        let handler = RoleAssignedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-role-assigned",
                role_assigned_payload_bytes(),
            ))
            .await
            .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 1);
        let entry = &listed.entries[0];
        assert_eq!(entry.action().as_str(), ACTION_ROLE_ASSIGN);
        assert_eq!(entry.resource().kind(), RESOURCE_KIND_ROLE_BINDING);
        assert_eq!(
            entry.resource().id(),
            expected_role_binding_resource_id("target-subject")
        );
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        assert_eq!(entry.actor_kind(), vocab::PrincipalKind::Admin);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_revoked_appends_audit_entry() {
        let repo = repo();
        let handler = RoleRevokedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new("m-role-revoked", role_revoked_payload_bytes()))
            .await
            .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 1);
        let entry = &listed.entries[0];
        assert_eq!(entry.action().as_str(), ACTION_ROLE_REVOKE);
        assert_eq!(entry.resource().kind(), RESOURCE_KIND_ROLE_BINDING);
        assert_eq!(
            entry.resource().id(),
            expected_role_binding_resource_id("target-subject")
        );
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        assert_eq!(entry.actor_kind(), vocab::PrincipalKind::Admin);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policy_updated_appends_audit_entry() {
        let repo = repo();
        let handler = PolicyUpdatedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-policy-updated",
                policy_updated_payload_bytes(IdentityPolicyUpdatedPayloadChangeKind::Updated),
            ))
            .await
            .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 1);
        let entry = &listed.entries[0];
        assert_eq!(entry.action().as_str(), ACTION_POLICY_UPDATE);
        assert_eq!(entry.resource().kind(), RESOURCE_KIND_POLICY);
        assert_eq!(
            entry.resource().id(),
            format!(
                "tenant/{CANON_TENANT}/policy/{POLICY_ID}/contract/identity.policies-get/permission/identity:policy:read"
            )
        );
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        assert_eq!(entry.actor_kind(), vocab::PrincipalKind::Admin);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_assigned_preserves_service_actor_kind() {
        let repo = repo();
        let handler = RoleAssignedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-role-assigned-service",
                role_assigned_payload_bytes_for_kind(
                    "target-subject",
                    IdentityRoleAssignedPayloadActorKind::Service,
                ),
            ))
            .await
            .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 1);
        assert_eq!(
            listed.entries[0].actor_kind(),
            vocab::PrincipalKind::Service
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_binding_audit_resource_distinguishes_subjects() {
        let repo = repo();
        let handler = RoleAssignedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m-role-assigned-a",
                role_assigned_payload_bytes_for("target-a"),
            ))
            .await
            .expect("handle target-a");
        handler
            .handle(Message::new(
                "m-role-assigned-b",
                role_assigned_payload_bytes_for("target-b"),
            ))
            .await
            .expect("handle target-b");

        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert_eq!(listed.entries.len(), 2);
        let first = listed.entries[0].resource().id();
        let second = listed.entries[1].resource().id();
        assert_ne!(first, second, "role binding resource must include subject");
        assert_eq!(first, expected_role_binding_resource_id("target-a"));
        assert_eq!(second, expected_role_binding_resource_id("target-b"));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_undecodable_payload_without_appending() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new("m-bad", b"not json".to_vec()))
            .await;
        assert!(result.is_err());
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let listed = repo
            .list(
                TenantRepoScope::for_test(tenant),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert!(listed.entries.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_tenant() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, "NOT-A-UUID"),
            ))
            .await;
        assert!(result.is_err());
    }

    /// #1277 F1：subject 是 typed `uuid::Uuid`（schema `format:uuid`）——非 UUID subject 在 payload **decode**
    /// 即 fail-closed（serde 反序列化失败），不进链。用 raw JSON（typed 构造器无法表达非 UUID）证 decode-层拒绝。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_subject() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        // 手造 payload JSON：subject 为非 UUID 字符串（typed `uuid::Uuid` 字段无法表达，故走 raw bytes）。
        let raw = format!(
            r#"{{"sessionId":"{CANON_SESSION}","subject":"alice-not-uuid","tenantId":"{CANON_TENANT}","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result = handler.handle(Message::new("m", raw)).await;
        assert!(
            result.is_err(),
            "非 UUID subject 须在 wire decode 层 fail-closed 拒（typed uuid::Uuid 不可表达）"
        );
    }

    /// F3：非 canonical UUID 的 session_id 被 fail-closed 拒（不进链），与 tenant/actor 同纪律。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_session_id() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        let result = handler
            .handle(Message::new(
                "m",
                payload_bytes_with_session(CANON_SUBJECT, CANON_TENANT, "sess-not-uuid"),
            ))
            .await;
        assert!(result.is_err(), "非 canonical session_id 须拒绝");
        // anti-vacuity：未 append（链空）。
        let listed = repo
            .list(
                TenantRepoScope::for_test(vocab::TenantId::parse(CANON_TENANT).expect("tenant")),
                AuditPage {
                    limit: vocab::Limit::new(10).expect("limit"),
                    cursor: None,
                },
            )
            .await
            .expect("list");
        assert!(listed.entries.is_empty(), "非法 session_id 不得进链");
    }

    // 弱 key（<32B）fail-closed 已上移组合根：`AuditChainHasher::new` 返回 `None`（domain/mod.rs
    // `hasher_construction_rejects_keys_shorter_than_32_bytes` 覆盖）；AuditDomain 只消费已装配 provider。

    #[test]
    #[allow(clippy::expect_used)]
    fn audit_domain_declares_subscriber_and_admin_route_group() {
        let domain = domain(repo());
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert!(
            groups
                .iter()
                .any(|(listener, prefix)| matches!(listener, ListenerKind::Admin)
                    && *prefix == AUDIT_ROUTE_PREFIX),
            "admin 读路由组须声明在 Admin listener: {groups:?}"
        );
        assert_eq!(AUDIT_LIST_HTTP_SPEC.path, AUDIT_ENTRIES_PATH);
        assert_eq!(AUDIT_LIST_HTTP_SPEC.method, "GET");
        assert_eq!(
            AUDIT_LIST_HTTP_SPEC.auth.permission,
            Some(vocab::AUDIT_READ_PERMISSION)
        );
        let subs = reg.drain_subscribers();
        let expected: Vec<_> = [
            SESSION_CREATED_SUBSCRIPTIONS,
            ROLE_ASSIGNED_SUBSCRIPTIONS,
            ROLE_REVOKED_SUBSCRIPTIONS,
            POLICY_UPDATED_SUBSCRIPTIONS,
        ]
        .into_iter()
        .flat_map(|specs| specs.iter())
        .collect();
        assert_eq!(expected.len(), 4);
        assert_eq!(subs.len(), expected.len());
        for spec in expected {
            assert_eq!(spec.consumer, AUDIT_DOMAIN);
            assert!(
                subs.iter().any(|sub| sub.contract_id == spec.contract_id
                    && sub.topic == spec.topic
                    && sub.consumer == spec.consumer
                    && sub.group.as_str() == spec.group),
                "missing subscriber binding for {}",
                spec.contract_id
            );
        }
    }

    /// 在注入 ctx tenant 的 Router 上 oneshot 一个 GET（参数绑定 + 状态码 + 响应体）。
    #[allow(clippy::expect_used)]
    async fn get_entries(repo: Arc<DynAuditRepo<'static>>, query: &str) -> (StatusCode, Vec<u8>) {
        get_entries_with(repo, None, Some(default_admin_principal()), query).await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with(
        repo: Arc<DynAuditRepo<'static>>,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        query: &str,
    ) -> (StatusCode, Vec<u8>) {
        get_entries_with_sink(repo, admin_repo, principal, audit_sink(), query).await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with_sink<S>(
        repo: Arc<DynAuditRepo<'static>>,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: diport::AuditSink + Send + Sync + 'static,
    {
        get_entries_with_sink_and_authorizer(
            repo,
            admin_repo,
            principal,
            audit_sink,
            Some(projection_authorizer(&[])),
            query,
        )
        .await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with_sink_and_authorizer<S>(
        repo: Arc<DynAuditRepo<'static>>,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        authorizer: Option<Arc<dyn httpserve::RouteAuthorizer>>,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: diport::AuditSink + Send + Sync + 'static,
    {
        let read_deps = AuditReadDeps {
            repo,
            admin_repo,
            audit_sink: Arc::new(audit_sink),
            audit_clock: audit_clock(),
        };
        let authenticated = principal.as_ref().map(|principal| {
            httpserve::Authenticated::new(
                primitives::RequiredScheme::Jwt,
                principal.kind(),
                CANON_SUBJECT,
                principal.tenant(),
            )
        });
        let app = axum::Router::new().route(
            AUDIT_ENTRIES_PATH,
            axum::routing::get(
                move |headers: axum::http::HeaderMap,
                      principal_ext: Option<Extension<Arc<authn::Principal>>>,
                      auth_ext: Option<Extension<httpserve::Authenticated>>,
                      authorizer_ext: Option<Extension<Arc<dyn httpserve::RouteAuthorizer>>>,
                      q: Result<Query<AuditListEntriesRequest>, QueryRejection>| {
                    let read_deps = read_deps.clone();
                    let principal = principal_ext
                        .map(|Extension(principal)| principal)
                        .or_else(|| principal.clone());
                    let authenticated = auth_ext
                        .map(|Extension(authenticated)| authenticated)
                        .or_else(|| authenticated.clone());
                    let authorizer = authorizer_ext
                        .map(|Extension(authorizer)| authorizer)
                        .or_else(|| authorizer.clone());
                    let request_id = headers
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("rid-test")
                        .to_string();
                    let correlation_id = request_correlation(&headers, &request_id);
                    async move {
                        let Ok(q) = q else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        list_entries(
                            read_deps,
                            principal,
                            authenticated,
                            authorizer,
                            q.0,
                            request_id,
                            correlation_id,
                        )
                        .await
                    }
                },
            ),
        );
        let uri = format!("{AUDIT_ENTRIES_PATH}{query}");
        let request = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("request");
        let ctx = runctx::test_support::app_ctx(
            vocab::TenantId::parse(CANON_TENANT).expect("tenant"),
            "admin-subject",
        );
        let response = runctx::scope(ctx, async move { app.oneshot(request).await })
            .await
            .expect("oneshot");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, body.to_vec())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_lists_tenant_entries_with_pagination() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        for _ in 0..3 {
            handler
                .handle(Message::new(
                    "m",
                    payload_bytes(CANON_SUBJECT, CANON_TENANT),
                ))
                .await
                .expect("append");
        }
        // 首页 limit=2 → 2 条 + hasMore + nextCursor。
        let (status, body) = get_entries(repo.clone(), "?limit=2").await;
        assert_eq!(status, StatusCode::OK);
        let page1: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page1.data.len(), 2);
        assert!(page1.has_more);
        assert_eq!(page1.data[0].seq, 0);
        assert_eq!(page1.data[0].action, ACTION_LOGIN);
        assert_eq!(page1.data[0].tenant_id, "<redacted>");
        assert_eq!(page1.data[0].actor_kind, "user");
        assert_eq!(page1.data[0].outcome, "success");
        assert_eq!(page1.data[0].actor, "<redacted>");
        assert_eq!(page1.data[0].resource_id, "<redacted>");
        let cursor = page1.next_cursor.expect("next cursor");
        // 续页：剩 1 条 + 无更多。
        let (status, body) = get_entries(repo, &format!("?limit=2&cursor={cursor}")).await;
        assert_eq!(status, StatusCode::OK);
        let page2: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page2.data.len(), 1);
        assert!(!page2.has_more);
        assert!(page2.next_cursor.is_none());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_masks_sensitive_fields_by_default() {
        let repo = repo();
        SessionCreatedAuditHandler::new(repo.clone())
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("append");

        let (status, body) = get_entries(repo, "").await;

        assert_eq!(status, StatusCode::OK);
        let raw = std::str::from_utf8(&body).expect("utf8");
        assert!(
            !raw.contains(CANON_SUBJECT),
            "serialized response must not leak actor"
        );
        assert!(
            !raw.contains(CANON_SESSION),
            "serialized response must not leak resource id"
        );
        assert!(
            !raw.contains(CANON_TENANT),
            "serialized response must not leak tenant id"
        );
        let page: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].actor, "<redacted>");
        assert_eq!(page.data[0].resource_id, "<redacted>");
        assert_eq!(page.data[0].tenant_id, "<redacted>");
        assert_eq!(page.data[0].action, ACTION_LOGIN);
        assert!(!page.data[0].entry_hash.is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_unmasks_only_explicitly_allowed_fields() {
        static FIELDS: &[vocab::ProjectionField] = &[
            vocab::ProjectionField::AuditActor,
            vocab::ProjectionField::AuditTenantId,
        ];
        let repo = repo();
        SessionCreatedAuditHandler::new(repo.clone())
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("append");
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let admin = principal(vocab::PrincipalKind::Admin, Some(tenant));

        let (status, body) = get_entries_with_sink_and_authorizer(
            repo,
            None,
            Some(admin),
            audit_sink(),
            Some(projection_authorizer(FIELDS)),
            "",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let raw = std::str::from_utf8(&body).expect("utf8");
        assert!(
            raw.contains(CANON_SUBJECT),
            "actor should be explicitly unmasked"
        );
        assert!(
            !raw.contains(CANON_SESSION),
            "resource id must stay masked without its field grant"
        );
        let page: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].actor, CANON_SUBJECT);
        assert_eq!(page.data[0].tenant_id, CANON_TENANT);
        assert_eq!(page.data[0].resource_id, "<redacted>");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_requires_audit_read_before_repo_list() {
        struct ReadFailsRepo {
            list_calls: Arc<std::sync::atomic::AtomicUsize>,
        }

        impl AuditRepo for ReadFailsRepo {
            async fn append(
                &self,
                _scope: TenantRepoScope,
                _record: AuditRecord,
            ) -> Result<(), AuditError> {
                Ok(())
            }

            async fn list(
                &self,
                _scope: TenantRepoScope,
                _page: AuditPage,
            ) -> Result<AuditListResult, AuditError> {
                self.list_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(AuditError::HashMismatch)
            }

            async fn verify_tail(
                &self,
                _scope: TenantRepoScope,
                _limit: u32,
            ) -> Result<(), AuditError> {
                Ok(())
            }
        }

        for (label, authorizer) in [
            ("missing authorizer", None),
            ("denied authorizer", Some(denying_authorizer())),
        ] {
            let list_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let repo: Arc<DynAuditRepo<'static>> =
                Arc::from(DynAuditRepo::new_box(ReadFailsRepo {
                    list_calls: list_calls.clone(),
                }));

            let (status, body) = get_entries_with_sink_and_authorizer(
                repo,
                None,
                Some(default_admin_principal()),
                audit_sink(),
                authorizer,
                "",
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(
                list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{label} must not read repo"
            );
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN", "{label}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_requires_super_admin_and_writes_audit() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        handler
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("append");
        let sink = RecordingAuditSink::ok();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);

        let (status, body) = get_entries_with_sink(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            sink.clone(),
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let page: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].tenant_id, "<redacted>");
        assert_eq!(page.data[0].actor, "<redacted>");
        assert_eq!(page.data[0].resource_id, "<redacted>");
        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "target-tenant read must be durably audited first"
        );
        let event = &events[0];
        assert_eq!(event.principal_kind, vocab::PrincipalKind::SuperAdmin);
        assert_eq!(
            event.tenant_id,
            Some(vocab::TenantId::parse(CANON_TENANT).expect("tenant"))
        );
        assert_eq!(event.resource_kind, RESOURCE_KIND_AUDIT_ENTRIES);
        assert_eq!(event.resource_id, CANON_TENANT);
        assert_eq!(event.action, ACTION_AUDIT_LIST_CROSS_TENANT);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_via_sealed_router_uses_generated_request_context() {
        let repo = repo();
        SessionCreatedAuditHandler::new(repo.clone())
            .handle(Message::new(
                "m",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ))
            .await
            .expect("append");
        let sink = RecordingAuditSink::ok();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);
        let domain = AuditDomain::new(
            repo.clone(),
            Some(admin_repo(repo)),
            sink.clone(),
            audit_clock(),
        );
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routes = reg.finalize_routes().expect("finalize ok");
        let (_, admin) = routes
            .into_iter()
            .find(|(listener, _)| matches!(listener, ListenerKind::Admin))
            .expect("admin routes");
        let plan = primitives::AuthPlan::new(ListenerKind::Admin, primitives::AuthScheme::Jwt)
            .expect("admin jwt plan");
        let principal_for_bridge = principal.clone();
        let router = httpserve::finalize_auth_with_audit_and_authorizer(
            admin,
            plan,
            httpserve::AuditSinkHandle::new(audit_sink()),
            audit_clock(),
            projection_authorizer(&[]),
        )
        .expect("finalize auth")
        .layer(axum::middleware::from_fn(
            move |mut req: axum::extract::Request, next: axum::middleware::Next| {
                let principal = principal_for_bridge.clone();
                async move {
                    req.extensions_mut().insert(httpserve::Authenticated::new(
                        primitives::RequiredScheme::Jwt,
                        vocab::PrincipalKind::SuperAdmin,
                        CANON_SUBJECT,
                        None,
                    ));
                    req.extensions_mut().insert(principal);
                    next.run(req).await
                }
            },
        ))
        .into_router_for_test();
        let request = axum::http::Request::builder()
            .uri(format!("{AUDIT_ENTRIES_PATH}?tenantId={CANON_TENANT}"))
            .body(axum::body::Body::empty())
            .expect("request");

        let response = router.oneshot(request).await.expect("oneshot");

        assert_eq!(response.status(), StatusCode::OK);
        let response_request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .expect("sealed router generated request id")
            .to_string();
        let response_correlation_id = response
            .headers()
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok())
            .expect("sealed router generated correlation id")
            .to_string();
        assert!(
            !response_request_id.is_empty(),
            "generated request id must be non-empty"
        );
        assert!(
            !response_correlation_id.is_empty(),
            "generated correlation id must be non-empty"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let page: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        assert_eq!(page.data.len(), 1);
        let events = sink.events();
        assert_eq!(events.len(), 1, "target read must write audit event");
        assert_eq!(
            events[0].request_id.as_deref(),
            Some(response_request_id.as_str())
        );
        assert_eq!(
            events[0].correlation_id.as_deref(),
            Some(response_correlation_id.as_str())
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_rejects_non_super_admin_even_same_tenant() {
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        for (label, kind, principal_tenant) in [
            ("user", vocab::PrincipalKind::User, Some(tenant)),
            ("device", vocab::PrincipalKind::Device, Some(tenant)),
            ("admin", vocab::PrincipalKind::Admin, Some(tenant)),
            ("service", vocab::PrincipalKind::Service, None),
            ("anonymous", vocab::PrincipalKind::Anonymous, None),
        ] {
            let repo = repo();
            let admin = CountingAdminRepo::default();
            let list_calls = admin.list_calls();
            let principal = principal(kind, principal_tenant);

            let (status, body) = get_entries_with(
                repo,
                Some(admin.boxed()),
                Some(principal),
                &format!("?tenantId={CANON_TENANT}"),
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(
                list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{label} must be rejected before admin repo read"
            );
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN", "{label}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_rejects_non_super_admin_before_admin_repo_check() {
        let repo = repo();
        let tenant = vocab::TenantId::parse(CANON_TENANT).expect("tenant");
        let admin = principal(vocab::PrincipalKind::Admin, Some(tenant));

        let (status, body) = get_entries_with(
            repo,
            None,
            Some(admin),
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_authorizes_before_admin_repo_check() {
        let repo = repo();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);

        let (status, body) = get_entries_with_sink_and_authorizer(
            repo,
            None,
            Some(principal),
            audit_sink(),
            None,
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_without_admin_repo_is_501() {
        let repo = repo();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);

        let (status, body) = get_entries_with(
            repo,
            None,
            Some(principal),
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_NOT_IMPLEMENTED");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_denies_before_success_audit() {
        let repo = repo();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);
        let sink = RecordingAuditSink::ok();

        let (status, body) = get_entries_with_sink_and_authorizer(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            sink.clone(),
            Some(denying_authorizer()),
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            sink.events().is_empty(),
            "denied final read must not write success cross-tenant audit"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_fails_closed_when_audit_fails() {
        let repo = repo();
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);
        let admin = CountingAdminRepo::default();
        let list_calls = admin.list_calls();

        let (status, body) = get_entries_with_sink(
            repo,
            Some(admin.boxed()),
            Some(principal),
            RecordingAuditSink::failing(),
            &format!("?tenantId={CANON_TENANT}"),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "audit append failure must stop before admin repo read"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_cursor_is_bound_to_requested_tenant() {
        let repo = repo();
        let handler = SessionCreatedAuditHandler::new(repo.clone());
        for _ in 0..2 {
            handler
                .handle(Message::new(
                    "m",
                    payload_bytes(CANON_SUBJECT, CANON_TENANT),
                ))
                .await
                .expect("append");
        }
        let principal = principal(vocab::PrincipalKind::SuperAdmin, None);
        let (status, body) = get_entries_with(
            repo.clone(),
            Some(admin_repo(repo.clone())),
            Some(principal.clone()),
            &format!("?tenantId={CANON_TENANT}&limit=1"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: AuditListEntriesResponse = serde_json::from_slice(&body).expect("decode");
        let cursor = page.next_cursor.expect("next cursor");

        let other_tenant = "00000000-0000-4000-8000-000000000abc";
        let (status, body) = get_entries_with(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            &format!("?tenantId={other_tenant}&limit=1&cursor={cursor}"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_malformed_cursor() {
        let (status, body) = get_entries(repo(), "?cursor=!!!not-base64!!!").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // 验证 JSON 信封：error.code == "ERR_CORE_VALIDATION"。
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    /// F4：合法 base64url 但语义无效（解码后非页索引）的游标 → 400 统一信封（不静默回首页）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_semantically_invalid_cursor() {
        let bogus = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not-a-number");
        let (status, body) = get_entries(repo(), &format!("?cursor={bogus}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "语义无效游标须 400");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    /// F5：limit=0（及负值）是无效页大小 → 400（不静默回退 / 无限续页）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_rejects_non_positive_limit() {
        for q in ["?limit=0", "?limit=-1"] {
            let (status, body) = get_entries(repo(), q).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{q} 须 400");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
        }
    }

    /// F6：Query 解析失败（非整数 limit / 未知字段）→ 统一 400 信封（不漏 axum 裸 400 文本）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_query_rejection_maps_to_envelope() {
        for q in ["?limit=abc", "?bogus=1"] {
            let (status, body) = get_entries(repo(), q).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{q} 须 400");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(
                json["error"]["code"], "ERR_CORE_VALIDATION",
                "{q} 须走统一 validation 信封"
            );
        }
    }

    /// F1/F7：经真实 bootstrap compose + finalize_routes 驱动，断言 contract 路径 `/api/v1/audit/entries`
    /// 命中已挂载 route（无 plan ⇒ fail-closed 非 404），且旧 bug 的 doubled 前缀路径不存在（404）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_route_finalizes_at_contract_path() {
        async fn route_status(router: &axum::Router, path: &str) -> StatusCode {
            let request = axum::http::Request::builder()
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("request");
            router
                .clone()
                .oneshot(request)
                .await
                .expect("oneshot")
                .status()
        }

        let domain = domain(repo());
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routers = reg.finalize_routes().expect("finalize ok");
        let (_, admin) = routers
            .into_iter()
            .find(|(listener, _)| matches!(listener, ListenerKind::Admin))
            .expect("admin router");
        // 取回裸 Router 做 oneshot（`#[doc(hidden)]` 测试入口；生产无此 bindable 出口，ROUTE-AUTH-FUNNEL-01）。
        let admin = admin.into_router_for_test();

        // contract 路径命中 route（enforce_layer 无 plan ⇒ fail-closed 403，证明 route 已挂载于此）。
        let hit = route_status(&admin, AUDIT_ENTRIES_PATH).await;
        assert_ne!(
            hit,
            StatusCode::NOT_FOUND,
            "contract 路径 {AUDIT_ENTRIES_PATH} 须命中已挂载 route（实际 {hit}）"
        );
        // 旧 bug（组内用完整路径）会把 route 挂到 doubled 前缀下；该路径不应存在（F1 回归守卫）。
        let doubled = route_status(&admin, "/api/v1/audit/api/v1/audit/entries").await;
        assert_eq!(
            doubled,
            StatusCode::NOT_FOUND,
            "doubled 前缀路径不应存在（F1 回归）"
        );
    }

    /// 链完整性失败（repo.list → `Err(HashMismatch)`）时 admin 读 fail-closed 返回 500 + ERR_CORE_INTERNAL。
    ///
    /// 经 `FailingAuditRepo` 双 直接验 handler 的 `AuditError`→500 映射（repo 层篡改→`HashMismatch` 的实证由
    /// `internal::mem` 的 `list_returns_error_when_chain_tampered` 覆盖；inherent `corrupt_first_entry_hash`
    /// 在 erased `DynAuditRepo` 不可达，故此处用 typed 双更直接测 handler 行为）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_fails_closed_when_list_errors() {
        struct FailingAuditRepo;
        impl AuditRepo for FailingAuditRepo {
            async fn append(
                &self,
                _scope: TenantRepoScope,
                _record: AuditRecord,
            ) -> Result<(), AuditError> {
                Ok(())
            }
            async fn list(
                &self,
                _scope: TenantRepoScope,
                _page: AuditPage,
            ) -> Result<AuditListResult, AuditError> {
                Err(AuditError::HashMismatch)
            }
            async fn verify_tail(
                &self,
                _scope: TenantRepoScope,
                _limit: u32,
            ) -> Result<(), AuditError> {
                Err(AuditError::HashMismatch)
            }
        }
        let repo: Arc<DynAuditRepo<'static>> = Arc::from(DynAuditRepo::new_box(FailingAuditRepo));
        let (status, body) = get_entries(repo, "").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }

    /// 无 runctx ctx（未经认证通道）⇒ handler fail-closed 500，不静默落空租户。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_without_ctx_fails_closed() {
        let response = list_entries(
            AuditReadDeps {
                repo: repo(),
                admin_repo: None,
                audit_sink: Arc::new(audit_sink()),
                audit_clock: audit_clock(),
            },
            None,
            None,
            None,
            AuditListEntriesRequest {
                limit: std::num::NonZeroU32::new(10).expect("nonzero"),
                cursor: None,
                tenant_id: None,
            },
            String::new(),
            "corr-test".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // 验证 JSON 信封：error.code == "ERR_CORE_INTERNAL"。
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }
}
