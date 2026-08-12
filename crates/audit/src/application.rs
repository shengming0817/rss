//! audit 应用层：session→链 append 订阅 handler + 跨租户 admin 读 handler + bootstrap 生命周期。
//!
//! 消费 identity 域 `identity.session-created` event（跨域只经 contract）→ 构造域 [`AuditRecord`] →
//! 经注入的 [`AuditWriteRepo`](crate::ports::AuditWriteRepo) **原子封链** append（domain hash chain，
//! #1014 RW-W 写实，取代 G1 的 flat `diport::AuditSink` 路径）。admin 读 handler
//! （`GET /api/v1/audit/entries`，Admin listener）按已认证
//! 租户分页列出审计条目；独立 target-tenant 路由只允许已验证 SuperAdmin 在 durable cross-tenant audit
//! append 成功后读取目标租户审计链。
//!
//! # 鉴权作用域
//!
//! `AppCtx.principal` 是 `Arc<dyn runctx::PrincipalFacet>`（authn 的 `Principal` 经擦除注入；`runctx → authn`
//! 是禁止的依赖环，故 runctx 不按具体类型持有 principal，#1105）。本 handler 对普通 scoped read 只读 ctx
//! **tenant**；对 target-tenant cross-tenant read 则使用 runtime bridge 写入的具体 `Arc<authn::Principal>`
//! 做 SuperAdmin 判定，消费 target-bound grant 并先写 route-specific 持久审计，再 mint read scope。未配置专用
//! `rss_audit_admin` repo 时 privileged read 返回 501 fail-closed。Admin listener auth 限定可达者。
//!
//! ref: open-telemetry/opentelemetry-rust opentelemetry/src/logs/logger.rs@main（audit sink 接缝）
//! ref: sigstore/sigstore-rs src/rekor（append-only transparency log → 域 hash chain）

use std::sync::Arc;
use std::time::SystemTime;

#[cfg(test)]
use ::generated::http::audit_v1::list_entries::SPEC as AUDIT_LIST_HTTP_SPEC;
use ::generated::http::audit_v1::{
    list_entries::{
        AuditEntryView, AuditListEntriesFrameworkFailure, AuditListEntriesHandlerResult,
        AuditListEntriesRequest, AuditListEntriesResponse, AuditListEntriesResponseEnvelope,
        AuditListEntriesResponseError, ROUTE as AUDIT_LIST_HTTP_ROUTE,
    },
    list_tenant_entries::{
        AuditListTenantEntriesRequest, AuditListTenantEntriesResponse, AuditTenantEntryView,
        ROUTE as AUDIT_LIST_TENANT_HTTP_ROUTE, SPEC as AUDIT_LIST_TENANT_HTTP_SPEC,
    },
};
use ::httpserve::{
    Admin, AuthorizedSubject, ContractMarker, GeneratedEndpoint, ResourceProjection,
    RouteAuthorizer, VerifiedRequestId,
};
use axum::Json;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Extension, Path, Query, State};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use bootstrap::{KernelError, SubscriberCapability};
use diport::Message;
#[cfg(test)]
use generated::event::SubscriptionExecution;
#[cfg(test)]
use generated::event::identity_v1::{
    policy_updated::SPEC as POLICY_UPDATED_SPEC, role_assigned::SPEC as ROLE_ASSIGNED_SPEC,
    role_revoked::SPEC as ROLE_REVOKED_SPEC, security_event::SPEC as SECURITY_EVENT_SPEC,
    session_created::SPEC as SESSION_CREATED_SPEC,
};
use generated::event::identity_v1::{
    policy_updated::{
        IdentityPolicyUpdatedPayload, IdentityPolicyUpdatedPayloadActorKind,
        IdentityPolicyUpdatedPayloadChangeKind,
    },
    role_assigned::{IdentityRoleAssignedPayload, IdentityRoleAssignedPayloadActorKind},
    role_revoked::{IdentityRoleRevokedPayload, IdentityRoleRevokedPayloadActorKind},
    security_event::{
        IdentitySecurityEventPayload, IdentitySecurityEventPayloadActorKind,
        IdentitySecurityEventPayloadKind, IdentitySecurityEventPayloadTargetKind,
    },
    session_created::IdentitySessionCreatedPayload,
};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Admin>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;

use crate::domain::{AuditEntry, AuditError, AuditOutcome, ResourceRef};
use crate::ports::{
    AuditAdminRepo, AuditListResult, AuditListTenantAppend, AuditListTenantAppender, AuditPage,
    AuditReadRepo, AuditRecord, CrossTenantReadScope, DynAuditAdminRepo, DynAuditReadRepo,
    TenantRepoScope,
};

/// 本域 DomainId（在 generated event spec 中筛选本域那条订阅；非 wire 元数据，是本域身份）。
const AUDIT_DOMAIN: &str = "audit";

/// 审计资源类别（const literal）。
const RESOURCE_KIND_SESSION: &str = "session";
const RESOURCE_KIND_ROLE_BINDING: &str = "role-binding";
const RESOURCE_KIND_POLICY: &str = "policy";
const RESOURCE_KIND_SECURITY_TARGET: &str = "credential-security-target";
/// 登录动作（`domain:verb`，vocab::Action 形态）。
const ACTION_LOGIN: &str = "identity:login";
const ACTION_ROLE_ASSIGN: &str = "identity:role_assign";
const ACTION_ROLE_REVOKE: &str = "identity:role_revoke";
const ACTION_POLICY_CREATE: &str = "identity:policy_create";
const ACTION_POLICY_UPDATE: &str = "identity:policy_update";
const ACTION_POLICY_DEACTIVATE: &str = "identity:policy_deactivate";
const ACTION_PASSWORD_CHANGED: &str = "identity:password_changed";
const ACTION_PASSWORD_RESET: &str = "identity:password_reset";
const ACTION_ACCOUNT_LOCKED: &str = "identity:account_locked";
const ACTION_ACCOUNT_SUSPENDED: &str = "identity:account_suspended";
const ACTION_ACCOUNT_DEACTIVATED: &str = "identity:account_deactivated";
const ACTION_ACCOUNT_REACTIVATED: &str = "identity:account_reactivated";
const ACTION_LOGOUT_ALL: &str = "identity:logout_all";
const ACTION_CREDENTIAL_DELETED: &str = "identity:credential_deleted";
const ACTION_LOGOUT_CURRENT: &str = "identity:logout_current";
const ACTION_REFRESH_REUSE_DETECTED: &str = "identity:refresh_reuse_detected";
/// admin 读路由组 nest 前缀（Admin listener；与 contracts/http/audit/v1 单源对齐）。
const AUDIT_ROUTE_PREFIX: &str = "/api/v1/audit";
const RESOURCE_KIND_AUDIT_ENTRIES: &str = "audit_entries";
const ACTION_AUDIT_LIST_CROSS_TENANT: &str = "audit:list-cross-tenant";
const AUDIT_FORBIDDEN_REASON: &str = "forbidden";

/// Module-sealed proof that the route-specific append completed successfully for `target`.
///
/// The type is visible to `ports` so [`CrossTenantReadScope`] can consume it, but its fields and
/// constructor remain private to this application module. No other audit module or adapter can
/// mint a successful durable append receipt.
pub(crate) struct AuditListTenantAppendReceipt {
    target: rss_request_context::TenantId,
    _seal: (),
}

impl AuditListTenantAppendReceipt {
    fn after_success(target: rss_request_context::TenantId) -> Self {
        Self { target, _seal: () }
    }

    pub(crate) fn target(&self) -> rss_request_context::TenantId {
        self.target
    }
}

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
    SecurityEvent,
}

/// Sealed audit command decoded entirely from the redacted security-event fact.
///
/// Security events deliberately use the event-scoped opaque target reference as their audit actor
/// correlation. The raw identity subject/grant never crosses the event contract, and adapters
/// cannot replace any record field after the generated payload has been validated.
pub struct SecurityAuditCommand {
    record: AuditRecord,
}

impl std::fmt::Debug for SecurityAuditCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecurityAuditCommand(<redacted>)")
    }
}

impl SecurityAuditCommand {
    pub fn tenant(&self) -> rss_request_context::TenantId {
        self.record.tenant
    }

    pub fn into_record(self) -> AuditRecord {
        self.record
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditEventRecordError {
    #[error("audit event payload decode failed")]
    Decode(#[source] serde_json::Error),
    #[error("audit event tenant parse failed")]
    Tenant(#[source] rss_request_context::TenantIdError),
    #[error("audit event action parse failed")]
    Action(#[source] vocab::ActionError),
    #[error("audit event id parse failed")]
    EventId(#[source] uuid::Error),
    #[error("audit event id must be a canonical UUID v4")]
    EventIdVersion,
    #[error("audit event id must be independent from the bearer session id")]
    EventIdReusesSession,
    #[error("audit security event kind is not auditable")]
    SecurityKind,
    #[error("audit event timestamp is outside the Unix int64 range")]
    Time(#[source] vocab::UnixEpochSecondsError),
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
        AuditEventKind::SecurityEvent => Err(AuditEventRecordError::SecurityKind),
    }
}

pub fn security_audit_command_from_message(
    message: &Message,
) -> Result<SecurityAuditCommand, AuditEventRecordError> {
    let payload: IdentitySecurityEventPayload =
        serde_json::from_slice(message.payload().as_bytes())
            .map_err(AuditEventRecordError::Decode)?;
    let tenant = rss_request_context::TenantId::parse(&payload.tenant_id)
        .map_err(AuditEventRecordError::Tenant)?;
    let action_raw = match (payload.kind, payload.target.kind) {
        (
            IdentitySecurityEventPayloadKind::PasswordChanged,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_PASSWORD_CHANGED,
        (
            IdentitySecurityEventPayloadKind::PasswordReset,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_PASSWORD_RESET,
        (
            IdentitySecurityEventPayloadKind::AccountLocked,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_ACCOUNT_LOCKED,
        (
            IdentitySecurityEventPayloadKind::AccountSuspended,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_ACCOUNT_SUSPENDED,
        (
            IdentitySecurityEventPayloadKind::AccountDeactivated,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_ACCOUNT_DEACTIVATED,
        (
            IdentitySecurityEventPayloadKind::AccountReactivated,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_ACCOUNT_REACTIVATED,
        (
            IdentitySecurityEventPayloadKind::LogoutAll,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_LOGOUT_ALL,
        (
            IdentitySecurityEventPayloadKind::CredentialDeleted,
            IdentitySecurityEventPayloadTargetKind::Subject,
        ) => ACTION_CREDENTIAL_DELETED,
        (
            IdentitySecurityEventPayloadKind::LogoutCurrent,
            IdentitySecurityEventPayloadTargetKind::Grant,
        ) => ACTION_LOGOUT_CURRENT,
        (
            IdentitySecurityEventPayloadKind::RefreshReuseDetected,
            IdentitySecurityEventPayloadTargetKind::Grant,
        ) => ACTION_REFRESH_REUSE_DETECTED,
        _ => return Err(AuditEventRecordError::SecurityKind),
    };
    let action = vocab::Action::parse(action_raw).map_err(AuditEventRecordError::Action)?;
    let target_ref = payload.target.ref_;
    let actor_kind = match payload.actor.kind {
        IdentitySecurityEventPayloadActorKind::User => rss_request_context::PrincipalKind::User,
        IdentitySecurityEventPayloadActorKind::Device => rss_request_context::PrincipalKind::Device,
        IdentitySecurityEventPayloadActorKind::Admin => rss_request_context::PrincipalKind::Admin,
        IdentitySecurityEventPayloadActorKind::SuperAdmin => {
            rss_request_context::PrincipalKind::SuperAdmin
        }
        IdentitySecurityEventPayloadActorKind::Service => {
            rss_request_context::PrincipalKind::Service
        }
    };
    Ok(SecurityAuditCommand {
        record: AuditRecord {
            tenant,
            actor: ids::UserId::new(payload.actor.ref_),
            actor_kind,
            action,
            resource: ResourceRef::new(RESOURCE_KIND_SECURITY_TARGET, target_ref.to_string()),
            outcome: AuditOutcome::Success,
            recorded_at: from_unix_secs(payload.occurred_at)?,
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetCursorError {
    Invalid,
    TenantMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PageRequestError;

enum TargetPageRequestError {
    Page(PageRequestError),
    Cursor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditReadAuthError {
    Forbidden,
}

struct TargetAuditReadDeps<S>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
    audit_sink: Arc<S>,
    audit_clock: Arc<dyn diport::Clock>,
}

struct TargetReadRequest {
    target_raw: String,
    page: AuditListTenantEntriesRequest,
    request_id: String,
    correlation_id: String,
}

impl<S> Clone for TargetAuditReadDeps<S>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            admin_repo: self.admin_repo.clone(),
            audit_sink: self.audit_sink.clone(),
            audit_clock: self.audit_clock.clone(),
        }
    }
}

/// i64 unix 秒 → `SystemTime`，任何负值或平台范围溢出都显式失败。
fn from_unix_secs(secs: i64) -> Result<SystemTime, AuditEventRecordError> {
    vocab::UnixEpochSeconds::try_from(secs)
        .and_then(vocab::UnixEpochSeconds::to_system_time)
        .map_err(AuditEventRecordError::Time)
}

fn session_created_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentitySessionCreatedPayload =
        serde_json::from_slice(message.payload().as_bytes())
            .map_err(AuditEventRecordError::Decode)?;
    let tenant = rss_request_context::TenantId::parse(&payload.tenant_id.to_string())
        .map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_LOGIN).map_err(AuditEventRecordError::Action)?;
    let session = ids::SessionId::new(payload.session_id);
    let resource_id = SessionAuditResourceId::from_message(message.id(), &session)?;
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.subject),
        actor_kind: rss_request_context::PrincipalKind::User,
        action,
        resource: ResourceRef::new(RESOURCE_KIND_SESSION, resource_id.into_string()),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at)?,
    })
}

/// Session audit resources are derived only from an independent canonical event identity. The
/// private field prevents the bearer SessionId from being passed directly to `ResourceRef`.
struct SessionAuditResourceId(String);

impl SessionAuditResourceId {
    fn from_message(
        message_id: &diport::MessageId,
        session: &ids::SessionId,
    ) -> Result<Self, AuditEventRecordError> {
        let event_id =
            uuid::Uuid::parse_str(message_id.as_str()).map_err(AuditEventRecordError::EventId)?;
        let canonical = event_id.to_string();
        if event_id.get_version() != Some(uuid::Version::Random)
            || event_id.get_variant() != uuid::Variant::RFC4122
            || canonical != message_id.as_str()
        {
            return Err(AuditEventRecordError::EventIdVersion);
        }
        if event_id.as_bytes() == session.as_uuid().as_bytes() {
            return Err(AuditEventRecordError::EventIdReusesSession);
        }
        Ok(Self(format!("event:{canonical}")))
    }

    fn into_string(self) -> String {
        self.0
    }
}

fn role_assigned_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityRoleAssignedPayload = serde_json::from_slice(message.payload().as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant = rss_request_context::TenantId::parse(&payload.tenant_id)
        .map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_ROLE_ASSIGN).map_err(AuditEventRecordError::Action)?;
    let resource_id = role_binding_resource_id(tenant, &payload.role_id, &payload.subject);
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.assigned_by),
        actor_kind: assigned_actor_kind(payload.actor_kind),
        action,
        resource: ResourceRef::new(RESOURCE_KIND_ROLE_BINDING, resource_id),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at)?,
    })
}

fn role_revoked_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityRoleRevokedPayload = serde_json::from_slice(message.payload().as_bytes())
        .map_err(AuditEventRecordError::Decode)?;
    let tenant = rss_request_context::TenantId::parse(&payload.tenant_id)
        .map_err(AuditEventRecordError::Tenant)?;
    let action = vocab::Action::parse(ACTION_ROLE_REVOKE).map_err(AuditEventRecordError::Action)?;
    let resource_id = role_binding_resource_id(tenant, &payload.role_id, &payload.subject);
    Ok(AuditRecord {
        tenant,
        actor: ids::UserId::new(payload.revoked_by),
        actor_kind: revoked_actor_kind(payload.actor_kind),
        action,
        resource: ResourceRef::new(RESOURCE_KIND_ROLE_BINDING, resource_id),
        outcome: AuditOutcome::Success,
        recorded_at: from_unix_secs(payload.occurred_at)?,
    })
}

fn policy_updated_record_from_message(
    message: &Message,
) -> Result<AuditRecord, AuditEventRecordError> {
    let payload: IdentityPolicyUpdatedPayload =
        serde_json::from_slice(message.payload().as_bytes())
            .map_err(AuditEventRecordError::Decode)?;
    let tenant = rss_request_context::TenantId::parse(&payload.tenant_id)
        .map_err(AuditEventRecordError::Tenant)?;
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
        recorded_at: from_unix_secs(payload.occurred_at)?,
    })
}

/// `SystemTime` → i64 unix 秒（epoch 前 / 溢出收口为 0 / i64::MAX）。
fn to_unix_secs(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `rss_request_context::PrincipalKind` → wire 字符串（camelCase）。
fn principal_kind_wire(kind: rss_request_context::PrincipalKind) -> &'static str {
    match kind {
        rss_request_context::PrincipalKind::User => "user",
        rss_request_context::PrincipalKind::Device => "device",
        rss_request_context::PrincipalKind::Admin => "admin",
        rss_request_context::PrincipalKind::SuperAdmin => "superAdmin",
        rss_request_context::PrincipalKind::Service => "service",
        rss_request_context::PrincipalKind::Anonymous => "anonymous",
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

/// scoped / target-tenant wire view 共用的单源投影结果。
struct ProjectedAuditEntry {
    seq: i64,
    tenant_id: String,
    actor: String,
    actor_kind: String,
    action: String,
    resource_kind: String,
    resource_id: String,
    outcome: String,
    recorded_at: i64,
    entry_hash: String,
}

/// 域条目 → wire 投影中间值（domain entity 不直接序列化）。
fn project_audit_entry(entry: &AuditEntry, projection: ResourceProjection) -> ProjectedAuditEntry {
    ProjectedAuditEntry {
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

mod projected_audit_entry_views {
    use super::*;

    macro_rules! impl_projected_audit_entry_view {
        ($view:ty) => {
            impl From<ProjectedAuditEntry> for $view {
                fn from(projected: ProjectedAuditEntry) -> Self {
                    Self {
                        seq: projected.seq,
                        tenant_id: projected.tenant_id,
                        actor: projected.actor,
                        actor_kind: projected.actor_kind,
                        action: projected.action,
                        resource_kind: projected.resource_kind,
                        resource_id: projected.resource_id,
                        outcome: projected.outcome,
                        recorded_at: projected.recorded_at,
                        entry_hash: projected.entry_hash,
                    }
                }
            }
        };
    }

    impl_projected_audit_entry_view!(AuditEntryView);
    impl_projected_audit_entry_view!(AuditTenantEntryView);
}

/// 域条目 → scoped wire view。
fn to_view(entry: &AuditEntry, projection: ResourceProjection) -> AuditEntryView {
    project_audit_entry(entry, projection).into()
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
    tenant: rss_request_context::TenantId,
    result: AuditListResult,
    projection: ResourceProjection,
) -> Result<AuditListTenantEntriesResponse, TargetCursorError> {
    let next_cursor = match result.next_cursor {
        Some(cursor) => Some(encode_target_cursor(tenant, &cursor)?),
        None => None,
    };
    Ok(AuditListTenantEntriesResponse {
        data: result
            .entries
            .iter()
            .map(|entry| to_target_view(entry, projection))
            .collect(),
        next_cursor: next_cursor.map(|c| c.as_str().to_string()),
        has_more: result.has_more,
    })
}

fn to_target_view(entry: &AuditEntry, projection: ResourceProjection) -> AuditTenantEntryView {
    project_audit_entry(entry, projection).into()
}

fn encode_target_cursor(
    tenant: rss_request_context::TenantId,
    inner: &vocab::Cursor,
) -> Result<vocab::Cursor, TargetCursorError> {
    let raw = format!("{tenant}:{}", inner.as_str());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    vocab::Cursor::parse(&encoded).map_err(|_| TargetCursorError::Invalid)
}

fn decode_target_cursor(
    expected_tenant: rss_request_context::TenantId,
    cursor: &vocab::Cursor,
) -> Result<vocab::Cursor, TargetCursorError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| TargetCursorError::Invalid)?;
    let raw = std::str::from_utf8(&bytes).map_err(|_| TargetCursorError::Invalid)?;
    let Some((tenant_raw, inner_raw)) = raw.split_once(':') else {
        return Err(TargetCursorError::Invalid);
    };
    let tenant =
        rss_request_context::TenantId::parse(tenant_raw).map_err(|_| TargetCursorError::Invalid)?;
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

fn page_from_parts(
    limit: std::num::NonZeroU32,
    cursor: Option<&str>,
) -> Result<AuditPage, PageRequestError> {
    let limit = u16::try_from(limit.get()).map_err(|_| PageRequestError)?;
    let limit = vocab::Limit::new(limit).map_err(|_| PageRequestError)?;
    let cursor = match cursor {
        None => None,
        Some(raw) => Some(vocab::Cursor::parse(raw).map_err(|_| PageRequestError)?),
    };
    Ok(AuditPage { limit, cursor })
}

fn target_page_from_request(
    request: &AuditListTenantEntriesRequest,
    target: rss_request_context::TenantId,
) -> Result<AuditPage, TargetPageRequestError> {
    let mut page = page_from_parts(request.limit, request.cursor.as_deref())
        .map_err(TargetPageRequestError::Page)?;
    if let Some(cursor) = page.cursor.as_ref() {
        page.cursor =
            Some(decode_target_cursor(target, cursor).map_err(|_| TargetPageRequestError::Cursor)?);
    }
    Ok(page)
}

/// Tenant-scoped admin read. Target tenant input is not part of this wire shape.
async fn list_entries(
    repo: Arc<DynAuditReadRepo<'static>>,
    projection: ResourceProjection,
    request: AuditListEntriesRequest,
    request_id: VerifiedRequestId,
) -> AuditListEntriesHandlerResult {
    // 租户 fail-closed：缺 ctx（未经认证通道）即 500，不静默落空租户。
    let Ok(tenant) = runctx::try_with(|ctx| *ctx.tenant()) else {
        tracing::error!(
            domain = AUDIT_DOMAIN,
            request_id = request_id.as_str(),
            reason = "missing_run_context",
            "audit handler: framework request context missing"
        );
        return Err(AuditListEntriesFrameworkFailure::internal(
            request_id.into_wire(),
        ));
    };
    // 下限 ≥1 由 wire 类型 `NonZeroU32` 在反序列化层 type-enforced（F5）：limit=0 / 负值反序列化即失败
    // → QueryRejection → 统一 400（见路由闭包）。上限由 `vocab::Limit::new` 与 schema maximum=500
    // 收口；超限不截断，直接返回 400。
    let page = match page_from_parts(request.limit, request.cursor.as_deref()) {
        Ok(page) => page,
        Err(_) => return Ok(list_entries_bad_request(request_id)),
    };
    let scope = TenantRepoScope::from_authenticated_tenant(tenant);
    match repo.list(scope, page).await {
        Ok(result) => Ok(AuditListEntriesResponseEnvelope::Success(to_response(
            result, projection,
        ))),
        // 语义无效游标（合法 base64url 但非有效页索引）是客户端错误 → 400（F4）。
        Err(AuditError::InvalidCursor) => Ok(list_entries_bad_request(request_id)),
        // 链完整性等其它失败不可静默：记录后 500（无 wire 泄漏）。
        Err(error) => {
            tracing::error!(
                domain = AUDIT_DOMAIN,
                tenant = %tenant,
                error_chain = %secure::redact_error(&error),
                "audit handler: list failed"
            );
            Ok(list_entries_internal_error(request_id))
        }
    }
}

fn list_entries_bad_request(request_id: VerifiedRequestId) -> AuditListEntriesResponseEnvelope {
    AuditListEntriesResponseEnvelope::Error(AuditListEntriesResponseError::status_400(
        request_id.into_wire(),
    ))
}

fn list_entries_internal_error(request_id: VerifiedRequestId) -> AuditListEntriesResponseEnvelope {
    AuditListEntriesResponseEnvelope::Error(AuditListEntriesResponseError::status_500(
        request_id.into_wire(),
    ))
}

#[derive(Clone)]
struct AuditListHandlerState {
    repo: Arc<DynAuditReadRepo<'static>>,
}

impl httpserve::ClassifiedRouteState for AuditListHandlerState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

async fn list_entries_handler(
    _: ContractMarker<::generated::http::audit_v1::list_entries::RouteMarker>,
    State(state): State<AuditListHandlerState>,
    Extension(authorized): Extension<AuthorizedSubject>,
    Extension(request_id): Extension<VerifiedRequestId>,
    query: Result<Query<AuditListEntriesRequest>, QueryRejection>,
) -> AuditListEntriesHandlerResult {
    let Ok(query) = query else {
        return Ok(list_entries_bad_request(request_id));
    };
    list_entries(state.repo, authorized.projection(), query.0, request_id).await
}

fn log_cross_tenant_audit_append_failure(
    target: rss_request_context::TenantId,
    request: &TargetReadRequest,
    error: &dyn std::error::Error,
) {
    tracing::error!(
        domain = AUDIT_DOMAIN,
        contract_id = AUDIT_LIST_TENANT_HTTP_SPEC.route.contract_id(),
        operation = "audit_list_cross_tenant",
        tenant = %target,
        request_id = request.request_id.as_str(),
        correlation_id = request.correlation_id.as_str(),
        error_chain = %secure::redact_error(error),
        retry = false,
        "audit handler: durable cross-tenant audit append failed"
    );
}

/// Target-bound durable `Failure{reason:"forbidden"}` for a final cross-tenant deny.
///
/// AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01 ledger write (canonical anchor on
/// [`audited_forbidden_response`]). Ownership: audit domain handler only. authn
/// `cross_tenant_audit_grant` never appends denial; httpserve coarse route Deny is a
/// separate `http_route` Failure path.
async fn record_cross_tenant_denial<S>(
    deps: &TargetAuditReadDeps<S>,
    authenticated: &httpserve::Authenticated,
    target: rss_request_context::TenantId,
    request: &TargetReadRequest,
) -> Result<(), diport::AuditSinkError>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    deps.audit_sink
        .append(AuditListTenantAppend::new(
            target,
            authenticated.audit_event(httpserve::AuthenticatedAuditEvent {
                occurred_at: deps.audit_clock.now(),
                tenant_id: Some(target),
                resource_kind: RESOURCE_KIND_AUDIT_ENTRIES,
                resource_id: target.to_string(),
                action: ACTION_AUDIT_LIST_CROSS_TENANT,
                outcome: diport::AuditOutcome::Failure {
                    reason: AUDIT_FORBIDDEN_REASON,
                },
                request_id: Some(request.request_id.clone()),
                correlation_id: Some(request.correlation_id.clone()),
            }),
        ))
        .await
}

/// Final cross-tenant deny → durable Failure then HTTP 403 (append fail → 500).
///
/// INVARIANT: AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01 { level = "Medium", exec = "test", source = "code", synthetic_red = "tests::target_tenant_permission_deny_before_grant_writes_durable_failure", anti_vacuity = "tests::target_tenant_non_super_admin_deny_before_grant_writes_durable_failure" }
/// Deny-before-grant: both non-SuperAdmin and permission Forbidden branches call this
/// **before** [`audited_cross_tenant_scope`] / grant Success.
async fn audited_forbidden_response<S>(
    deps: &TargetAuditReadDeps<S>,
    authenticated: Option<&httpserve::Authenticated>,
    target: rss_request_context::TenantId,
    request: &TargetReadRequest,
) -> Response
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    let Some(authenticated) = authenticated else {
        return httpserve::error::internal_error(&request.request_id);
    };
    if let Err(error) = record_cross_tenant_denial(deps, authenticated, target, request).await {
        log_cross_tenant_audit_append_failure(target, request, &error);
        return httpserve::error::internal_error(&request.request_id);
    }
    httpserve::error::forbidden(&request.request_id)
}

/// Grant path only: SuperAdmin → durable Success append → sealed read scope.
///
/// AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01: caller must already have audited final
/// deny branches via [`audited_forbidden_response`]. Reaching
/// [`authn::CrossTenantGrantError::NotSuperAdmin`] here is an invariant break → 500
/// (never an unaudited 403). authn grant owns Success only; no denial ledger.
async fn audited_cross_tenant_scope<S>(
    deps: &TargetAuditReadDeps<S>,
    principal: &Arc<authn::Principal>,
    target: rss_request_context::TenantId,
    request: &TargetReadRequest,
) -> Result<CrossTenantReadScope, Response>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    let facet: Arc<dyn runctx::PrincipalFacet> = principal.clone();
    let ctx = runctx::RequestCtx::new(target, facet);
    let audit = authn::CrossTenantAuditContext::new(
        RESOURCE_KIND_AUDIT_ENTRIES,
        target.to_string(),
        ACTION_AUDIT_LIST_CROSS_TENANT,
        request.request_id.as_str(),
        request.correlation_id.as_str(),
    )
    .map_err(|_| httpserve::error::internal_error(&request.request_id))?;
    let grant = match principal.cross_tenant_audit_grant(&ctx, deps.audit_clock.as_ref(), &audit) {
        Ok(grant) => grant,
        // Deny-before-grant already audited both final deny branches. Reaching NotSuperAdmin
        // (or any other grant Err) here is an internal invariant failure, never an unaudited 403.
        Err(authn::CrossTenantGrantError::NotSuperAdmin) => {
            return Err(httpserve::error::internal_error(&request.request_id));
        }
        Err(_) => return Err(httpserve::error::internal_error(&request.request_id)),
    };
    let grant_target = grant.target();
    if grant_target != target {
        return Err(httpserve::error::internal_error(&request.request_id));
    }
    if let Err(error) = deps
        .audit_sink
        .append(AuditListTenantAppend::new(grant_target, grant.into_event()))
        .await
    {
        log_cross_tenant_audit_append_failure(target, request, &error);
        return Err(httpserve::error::internal_error(&request.request_id));
    }
    Ok(CrossTenantReadScope::from_durable_append(
        AuditListTenantAppendReceipt::after_success(grant_target),
    ))
}

async fn list_target_page(
    admin_repo: Arc<DynAuditAdminRepo<'static>>,
    scope: CrossTenantReadScope,
    page: AuditPage,
    target: rss_request_context::TenantId,
    projection: ResourceProjection,
    request_id: &str,
) -> Response {
    match admin_repo.list_tenant(scope, page).await {
        Ok(result) => match to_target_response(target, result, projection) {
            Ok(response) => Json(response).into_response(),
            Err(_) => httpserve::error::internal_error(request_id),
        },
        Err(AuditError::InvalidCursor) => httpserve::error::validation_bad_request(request_id),
        Err(error) => {
            tracing::error!(
                domain = AUDIT_DOMAIN,
                tenant = %target,
                error_chain = %secure::redact_error(&error),
                "audit handler: target-tenant list failed"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

/// Target-tenant audit list: deny-before-grant then grant Success append then read.
///
/// AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01: non-SuperAdmin and permission Forbidden →
/// [`audited_forbidden_response`] (target-bound durable Failure) **before**
/// [`audited_cross_tenant_scope`]. Only verified SuperAdmin with route permission
/// reaches grant/Success. Identity-less early 403 (`principal=None`) does not enter this
/// ledger path — closed by
/// `tests::target_tenant_identity_less_403_has_empty_deny_ledger` (empty RecordingAuditSink).
async fn list_entries_target_tenant<S>(
    deps: TargetAuditReadDeps<S>,
    principal: Option<Arc<authn::Principal>>,
    authenticated: Option<httpserve::Authenticated>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    request: TargetReadRequest,
) -> Response
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    let target = match rss_request_context::TenantId::parse(&request.target_raw) {
        Ok(tenant) => tenant,
        Err(_) => return httpserve::error::validation_bad_request(&request.request_id),
    };
    let Some(principal) = principal else {
        return httpserve::error::forbidden(&request.request_id);
    };
    if principal.kind() != rss_request_context::PrincipalKind::SuperAdmin {
        return audited_forbidden_response(&deps, authenticated.as_ref(), target, &request).await;
    }
    let projection = match authorize_read_projection(
        authorizer,
        authenticated.as_ref(),
        target,
        &AUDIT_LIST_TENANT_HTTP_SPEC,
    )
    .await
    {
        Ok(projection) => projection,
        Err(AuditReadAuthError::Forbidden) => {
            return audited_forbidden_response(&deps, authenticated.as_ref(), target, &request)
                .await;
        }
    };
    let Ok(page) = target_page_from_request(&request.page, target) else {
        return httpserve::error::validation_bad_request(&request.request_id);
    };
    let Some(admin_repo) = deps.admin_repo.clone() else {
        return httpserve::error::not_implemented(&request.request_id);
    };

    let scope = match audited_cross_tenant_scope(&deps, &principal, target, &request).await {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    list_target_page(
        admin_repo,
        scope,
        page,
        target,
        projection,
        &request.request_id,
    )
    .await
}

async fn authorize_read_projection(
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    authenticated: Option<&httpserve::Authenticated>,
    tenant: rss_request_context::TenantId,
    spec: &'static ::generated::http::HttpSpec,
) -> Result<ResourceProjection, AuditReadAuthError> {
    let vocab::HttpRouteAuth::Permission(permission) = spec.route.auth() else {
        return Err(AuditReadAuthError::Forbidden);
    };
    httpserve::authorize_subject_for_permission(
        authorizer,
        authenticated,
        spec.route.contract_id(),
        permission,
        tenant,
        None,
    )
    .await
    .map(|subject| subject.projection())
    .ok_or(AuditReadAuthError::Forbidden)
}

#[cfg(test)]
async fn authorize_and_list_entries_for_test(
    repo: Arc<DynAuditReadRepo<'static>>,
    authorizer: Option<Arc<dyn RouteAuthorizer>>,
    authenticated: Option<httpserve::Authenticated>,
    request: AuditListEntriesRequest,
    request_id: String,
) -> Response {
    let Ok(ambient_tenant) = runctx::try_with(|ctx| *ctx.tenant()) else {
        return httpserve::error::internal_error(&request_id);
    };
    if authenticated
        .as_ref()
        .and_then(httpserve::Authenticated::tenant_id)
        != Some(ambient_tenant)
    {
        return httpserve::error::forbidden(&request_id);
    }
    let projection = match authorize_read_projection(
        authorizer,
        authenticated.as_ref(),
        ambient_tenant,
        &AUDIT_LIST_HTTP_SPEC,
    )
    .await
    {
        Ok(projection) => projection,
        Err(AuditReadAuthError::Forbidden) => return httpserve::error::forbidden(&request_id),
    };
    list_entries(
        repo,
        projection,
        request,
        VerifiedRequestId::for_test(request_id),
    )
    .await
    .into_response()
}

fn role_binding_resource_id(
    tenant: rss_request_context::TenantId,
    role_id: &str,
    subject: &str,
) -> String {
    format!("tenant/{tenant}/role/{role_id}/subject/{subject}")
}

fn policy_resource_id(
    tenant: rss_request_context::TenantId,
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

fn assigned_actor_kind(
    kind: IdentityRoleAssignedPayloadActorKind,
) -> rss_request_context::PrincipalKind {
    match kind {
        IdentityRoleAssignedPayloadActorKind::User => rss_request_context::PrincipalKind::User,
        IdentityRoleAssignedPayloadActorKind::Device => rss_request_context::PrincipalKind::Device,
        IdentityRoleAssignedPayloadActorKind::Admin => rss_request_context::PrincipalKind::Admin,
        IdentityRoleAssignedPayloadActorKind::SuperAdmin => {
            rss_request_context::PrincipalKind::SuperAdmin
        }
        IdentityRoleAssignedPayloadActorKind::Service => {
            rss_request_context::PrincipalKind::Service
        }
        IdentityRoleAssignedPayloadActorKind::Anonymous => {
            rss_request_context::PrincipalKind::Anonymous
        }
    }
}

fn revoked_actor_kind(
    kind: IdentityRoleRevokedPayloadActorKind,
) -> rss_request_context::PrincipalKind {
    match kind {
        IdentityRoleRevokedPayloadActorKind::User => rss_request_context::PrincipalKind::User,
        IdentityRoleRevokedPayloadActorKind::Device => rss_request_context::PrincipalKind::Device,
        IdentityRoleRevokedPayloadActorKind::Admin => rss_request_context::PrincipalKind::Admin,
        IdentityRoleRevokedPayloadActorKind::SuperAdmin => {
            rss_request_context::PrincipalKind::SuperAdmin
        }
        IdentityRoleRevokedPayloadActorKind::Service => rss_request_context::PrincipalKind::Service,
        IdentityRoleRevokedPayloadActorKind::Anonymous => {
            rss_request_context::PrincipalKind::Anonymous
        }
    }
}

fn policy_updated_actor_kind(
    kind: IdentityPolicyUpdatedPayloadActorKind,
) -> rss_request_context::PrincipalKind {
    match kind {
        IdentityPolicyUpdatedPayloadActorKind::User => rss_request_context::PrincipalKind::User,
        IdentityPolicyUpdatedPayloadActorKind::Device => rss_request_context::PrincipalKind::Device,
        IdentityPolicyUpdatedPayloadActorKind::Admin => rss_request_context::PrincipalKind::Admin,
        IdentityPolicyUpdatedPayloadActorKind::SuperAdmin => {
            rss_request_context::PrincipalKind::SuperAdmin
        }
        IdentityPolicyUpdatedPayloadActorKind::Service => {
            rss_request_context::PrincipalKind::Service
        }
        IdentityPolicyUpdatedPayloadActorKind::Anonymous => {
            rss_request_context::PrincipalKind::Anonymous
        }
    }
}

/// audit 域 bootstrap 生命周期：声明 durable 订阅元数据 + admin 读路由组。
///
/// 本 ambient domain 只持 erased read capability；真实 durable append 由 postgres adapter 的 classified
/// ConsumerTx capability 执行，并与 inbox commit 保持同一事务。链 HMAC key 强度 fail-fast
/// 在组合根构造 [`AuditChainHasher`](crate::ports::AuditChainHasher) 时收口（`new` 返回 `Option`，弱 key → `None`），
/// 不在本域——本域只消费已装配的 erased provider。
pub struct AuditDomain<S>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    read_repo: Arc<DynAuditReadRepo<'static>>,
    admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
    audit_sink: Arc<S>,
    audit_clock: Arc<dyn diport::Clock>,
}

impl<S> AuditDomain<S>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    /// 注入 erased 审计仓储 provider 构造。
    ///
    /// `admin_repo=None` 表示未配置 `rss_audit_admin` pool；普通 scoped read 不受影响，独立
    /// `/tenants/{tenantId}/entries` privileged route fail-closed 为 501。
    pub fn new(
        read_repo: Arc<DynAuditReadRepo<'static>>,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        audit_sink: S,
        audit_clock: Arc<dyn diport::Clock>,
    ) -> Self {
        Self {
            read_repo,
            admin_repo,
            audit_sink: Arc::new(audit_sink),
            audit_clock,
        }
    }
}

fn register_audit_subscriber(reg: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
    generated::event::identity_v1::session_created::subscribe_audit(
        reg,
        SubscriberCapability::AdapterNativeTransactional,
    )?;
    generated::event::identity_v1::role_assigned::subscribe_audit(
        reg,
        SubscriberCapability::AdapterNativeTransactional,
    )?;
    generated::event::identity_v1::role_revoked::subscribe_audit(
        reg,
        SubscriberCapability::AdapterNativeTransactional,
    )?;
    generated::event::identity_v1::policy_updated::subscribe_audit(
        reg,
        SubscriberCapability::AdapterNativeTransactional,
    )?;
    generated::event::identity_v1::security_event::subscribe_audit(
        reg,
        SubscriberCapability::AdapterNativeTransactional,
    )?;
    Ok(())
}

impl<S> ::bootstrap::Domain for AuditDomain<S>
where
    S: AuditListTenantAppender + Send + Sync + 'static,
{
    fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
        // 订阅元数据（contract_id / topic / group）单源自 generated event `SPEC`（契约 codegen 派生）——
        // 不手维护平行 const，消除 contract↔consumer 漂移（AI-HARD：codegen funnel + golden）。缺失即 fail-fast。
        register_audit_subscriber(reg)?;

        // admin 读路由组（Admin listener，typed marker；operator/管理面，非业务对外 Primary）。
        let scoped_repo = self.read_repo.clone();
        let target_deps = TargetAuditReadDeps {
            admin_repo: self.admin_repo.clone(),
            audit_sink: self.audit_sink.clone(),
            audit_clock: self.audit_clock.clone(),
        };
        reg.route_group::<Admin>(AUDIT_ROUTE_PREFIX, move |rb| {
            let scoped_endpoint =
                GeneratedEndpoint::new_declared(AUDIT_LIST_HTTP_ROUTE, list_entries_handler)?
                    .with_classified_state(AuditListHandlerState {
                        repo: scoped_repo.clone(),
                    });
            let rb = rb.mount(scoped_endpoint)?;
            let target_deps = target_deps.clone();
            let target_endpoint = GeneratedEndpoint::new(
                AUDIT_LIST_TENANT_HTTP_ROUTE,
                move |_: ContractMarker<
                    ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                >,
                      principal: Option<Extension<Arc<authn::Principal>>>,
                      authenticated: Option<Extension<httpserve::Authenticated>>,
                      authorizer: Option<Extension<Arc<dyn RouteAuthorizer>>>,
                      target: Result<Path<String>, PathRejection>,
                      query: Result<Query<AuditListTenantEntriesRequest>, QueryRejection>,
                      request: axum::extract::Request| {
                    let deps = target_deps.clone();
                    let principal = principal.map(|Extension(principal)| principal);
                    let authenticated = authenticated.map(|Extension(authenticated)| authenticated);
                    let authorizer = authorizer.map(|Extension(authorizer)| authorizer);
                    let request_id = request_id_from_parts(request.headers(), request.extensions());
                    let correlation_id = request_correlation(request.headers(), &request_id);
                    async move {
                        let Ok(Path(target)) = target else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        let Ok(query) = query else {
                            return httpserve::error::validation_bad_request(&request_id);
                        };
                        list_entries_target_tenant(
                            deps,
                            principal,
                            authenticated,
                            authorizer,
                            TargetReadRequest {
                                target_raw: target,
                                page: query.0,
                                request_id,
                                correlation_id,
                            },
                        )
                        .await
                    }
                },
            )?;
            Ok(rb.mount(target_endpoint)?)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{AuditWriteRepo, DynAuditWriteRepo};

    use axum::http::StatusCode;
    use std::future::Future;
    use std::pin::Pin;
    use tower::ServiceExt as _;

    use crate::domain::AuditChainHasher;
    use crate::ports::AuditLedgerVerifyReport;
    use crate::test_support::{InMemAuditRepo, TestKeyedHasher, keyed_hasher};

    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const CANON_SUBJECT: &str = "11111111-2222-4333-8444-555555555555";
    /// canonical UUID session_id bearer（必须解析，但不得进入审计 resource/canonical bytes）。
    const CANON_SESSION: &str = "22222222-3333-4444-8555-666666666666";
    /// identity producer 独立 mint 的 canonical UUID v4 EventId。
    const CANON_EVENT_ID: &str = "33333333-4444-4555-8666-777777777777";
    const ROLE_ID: &str = "tenant-admin";
    const POLICY_ID: &str = "policy-admin-read";
    /// contract.toml 声明的完整路径（= `AUDIT_ROUTE_PREFIX` ‖ `AUDIT_ENTRIES_SUBPATH`）；测试据此断言
    /// finalize 后真实挂载路径 + 直挂 handler-logic 测试路径。
    const AUDIT_ENTRIES_PATH: &str = "/api/v1/audit/entries";
    const AUDIT_TENANT_ENTRIES_PATH: &str = "/api/v1/audit/tenants/{tenantId}/entries";

    #[test]
    fn scoped_list_state_is_local_read_only() {
        fn assert_local_read<T>()
        where
            T: httpserve::ClassifiedRouteState<
                    Effect = diport::ReadEffect,
                    Privilege = diport::LocalPrivilege,
                >,
        {
        }

        assert_local_read::<AuditListHandlerState>();
    }

    #[derive(Clone)]
    struct TestRepo {
        read: Arc<DynAuditReadRepo<'static>>,
        write: Arc<DynAuditWriteRepo<'static>>,
    }

    impl TestRepo {
        fn from_provider<T>(provider: Arc<T>) -> Self
        where
            T: AuditReadRepo + AuditWriteRepo + 'static,
        {
            Self {
                read: Arc::from(DynAuditReadRepo::new_box(Arc::clone(&provider))),
                write: Arc::from(DynAuditWriteRepo::new_box(provider)),
            }
        }

        fn read_only<T>(provider: T) -> Self
        where
            T: AuditReadRepo + 'static,
        {
            struct NoopWrite;
            impl AuditWriteRepo for NoopWrite {
                async fn append(
                    &self,
                    _scope: TenantRepoScope,
                    _record: AuditRecord,
                ) -> Result<(), AuditError> {
                    Ok(())
                }
            }
            Self {
                read: Arc::from(DynAuditReadRepo::new_box(provider)),
                write: Arc::from(DynAuditWriteRepo::new_box(NoopWrite)),
            }
        }

        async fn append(
            &self,
            scope: TenantRepoScope,
            record: AuditRecord,
        ) -> Result<(), AuditError> {
            self.write.append(scope, record).await
        }

        async fn list(
            &self,
            scope: TenantRepoScope,
            page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            self.read.list(scope, page).await
        }
    }

    /// Shared provider exposed through independent read and write capability wrappers.
    fn repo() -> TestRepo {
        TestRepo::from_provider(Arc::new(InMemAuditRepo::new(keyed_hasher(0x5a))))
    }

    async fn append_event_for_test(
        repo: TestRepo,
        kind: AuditEventKind,
        message: Message,
    ) -> Result<(), String> {
        let record = audit_record_from_event_message(kind, &message).map_err(|e| e.to_string())?;
        let scope = TenantRepoScope::from_authenticated_tenant(record.tenant);
        repo.append(scope, record).await.map_err(|e| e.to_string())
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

    impl crate::ports::AuditListTenantAppender for NoopAuditSink {
        async fn append(
            &self,
            _command: crate::ports::AuditListTenantAppend,
        ) -> Result<(), diport::AuditSinkError> {
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

    fn domain(repo: TestRepo) -> AuditDomain<NoopAuditSink> {
        AuditDomain::new(repo.read, None, audit_sink(), audit_clock())
    }

    struct DelegatingAdminRepo {
        repo: Arc<DynAuditReadRepo<'static>>,
    }

    impl DelegatingAdminRepo {
        fn new(repo: Arc<DynAuditReadRepo<'static>>) -> Self {
            Self { repo }
        }
    }

    impl crate::ports::AuditAdminRepo for DelegatingAdminRepo {
        async fn list_tenant(
            &self,
            scope: CrossTenantReadScope,
            page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            let tenant = scope.target();
            self.repo
                .list(TenantRepoScope::for_test(tenant), page)
                .await
        }

        async fn verify_tenant(
            &self,
            tenant: rss_request_context::TenantId,
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

    fn admin_repo(repo: TestRepo) -> Arc<DynAuditAdminRepo<'static>> {
        Arc::from(DynAuditAdminRepo::new_box(DelegatingAdminRepo::new(
            repo.read,
        )))
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
            _scope: CrossTenantReadScope,
            _page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(AuditError::HashMismatch)
        }

        async fn verify_tenant(
            &self,
            tenant: rss_request_context::TenantId,
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
    struct CountingScopedReadRepo {
        list_calls: Arc<std::sync::atomic::AtomicUsize>,
        business_write_effects:
            testkit::local_only::ProviderCounter<testkit::local_only::BusinessWrite>,
        scopes: Arc<std::sync::Mutex<Vec<rss_request_context::TenantId>>>,
        fail: bool,
        inject_forbidden_write: bool,
    }

    impl Default for CountingScopedReadRepo {
        fn default() -> Self {
            Self {
                list_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                business_write_effects: ::testkit::local_only::ProviderCounter::business_write(),
                scopes: Arc::new(std::sync::Mutex::new(Vec::new())),
                fail: false,
                inject_forbidden_write: false,
            }
        }
    }

    impl CountingScopedReadRepo {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        fn with_forbidden_write() -> Self {
            Self {
                inject_forbidden_write: true,
                ..Self::default()
            }
        }

        fn list_calls(&self) -> usize {
            self.list_calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn scopes(&self) -> Vec<rss_request_context::TenantId> {
            self.scopes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }

        fn test_repo(&self) -> TestRepo {
            TestRepo::from_provider(Arc::new(self.clone()))
        }
    }

    impl AuditWriteRepo for CountingScopedReadRepo {
        async fn append(
            &self,
            _scope: TenantRepoScope,
            _record: AuditRecord,
        ) -> Result<(), AuditError> {
            self.business_write_effects.record();
            Ok(())
        }
    }

    impl AuditReadRepo for CountingScopedReadRepo {
        async fn list(
            &self,
            scope: TenantRepoScope,
            _page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            self.list_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.scopes
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(scope.tenant());
            if self.inject_forbidden_write {
                self.business_write_effects.record();
            }
            if self.fail {
                Err(AuditError::HashMismatch)
            } else {
                Ok(AuditListResult {
                    entries: Vec::new(),
                    next_cursor: None,
                    has_more: false,
                })
            }
        }

        async fn verify_tail(
            &self,
            _scope: TenantRepoScope,
            _limit: u32,
        ) -> Result<(), AuditError> {
            Ok(())
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

    impl crate::ports::AuditListTenantAppender for RecordingAuditSink {
        async fn append(
            &self,
            command: crate::ports::AuditListTenantAppend,
        ) -> Result<(), diport::AuditSinkError> {
            let (scope, event, _observation) = command.into_parts();
            debug_assert_eq!(event.tenant_id, Some(scope.tenant()));
            diport::AuditSink::record(self, event).await
        }
    }

    #[derive(Clone)]
    struct ProjectionAuthorizer {
        fields: &'static [vocab::ProjectionField],
        allow: bool,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ProjectionAuthorizer {
        fn new(fields: &'static [vocab::ProjectionField], allow: bool) -> Self {
            Self {
                fields,
                allow,
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl httpserve::RouteAuthorizer for ProjectionAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if self.allow
                    && [
                        AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                        AUDIT_LIST_TENANT_HTTP_SPEC.route.contract_id(),
                    ]
                    .contains(&request.contract_id)
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
        Arc::new(ProjectionAuthorizer::new(fields, true))
    }

    fn denying_authorizer() -> Arc<dyn httpserve::RouteAuthorizer> {
        Arc::new(ProjectionAuthorizer::new(&[], false))
    }

    #[derive(Clone)]
    struct StrictTargetAuthorizer {
        expected_tenant: rss_request_context::TenantId,
        requests: Arc<std::sync::Mutex<Vec<httpserve::RouteAuthorizationRequest>>>,
    }

    impl StrictTargetAuthorizer {
        fn new(expected_tenant: rss_request_context::TenantId) -> Self {
            Self {
                expected_tenant,
                requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn requests(&self) -> Vec<httpserve::RouteAuthorizationRequest> {
            self.requests
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl httpserve::RouteAuthorizer for StrictTargetAuthorizer {
        fn authorize<'a>(
            &'a self,
            request: httpserve::RouteAuthorizationRequest,
        ) -> Pin<Box<dyn Future<Output = httpserve::RouteAuthorizationDecision> + Send + 'a>>
        {
            Box::pin(async move {
                let allow = request.contract_id == AUDIT_LIST_TENANT_HTTP_SPEC.route.contract_id()
                    && request.permission == vocab::AUDIT_READ_PERMISSION
                    && request.tenant_id == Some(self.expected_tenant);
                self.requests
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .push(request);
                if allow {
                    httpserve::RouteAuthorizationDecision::Allow
                } else {
                    httpserve::RouteAuthorizationDecision::Deny
                }
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn default_admin_principal() -> Arc<authn::Principal> {
        principal(
            rss_request_context::PrincipalKind::Admin,
            Some(rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant")),
        )
    }

    fn principal(
        kind: rss_request_context::PrincipalKind,
        tenant: Option<rss_request_context::TenantId>,
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
            session_id: uuid::Uuid::parse_str(session_id).expect("canonical session uuid"),
            // subject 是 typed `uuid::Uuid`（#1277 F1，schema `format:uuid`）——helper 入参为 canonical UUID 串，
            // 非 UUID 用例（rejects_non_canonical_subject）走 raw JSON、不经本构造器。
            subject: uuid::Uuid::parse_str(subject).expect("canonical subject uuid"),
            tenant_id: uuid::Uuid::parse_str(tenant).expect("canonical tenant uuid"),
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

    #[test]
    #[allow(clippy::expect_used)]
    fn security_event_fact_maps_all_legal_kinds_and_rejects_target_mismatches() {
        let target = "550e8400-e29b-41d4-a716-446655440000";
        let actor_ref = "550e8400-e29b-41d4-a716-446655440001";
        let legal_cases = [
            ("passwordChanged", "subject", ACTION_PASSWORD_CHANGED),
            ("passwordReset", "subject", ACTION_PASSWORD_RESET),
            ("accountLocked", "subject", ACTION_ACCOUNT_LOCKED),
            ("accountSuspended", "subject", ACTION_ACCOUNT_SUSPENDED),
            ("accountDeactivated", "subject", ACTION_ACCOUNT_DEACTIVATED),
            ("accountReactivated", "subject", ACTION_ACCOUNT_REACTIVATED),
            ("logoutAll", "subject", ACTION_LOGOUT_ALL),
            ("credentialDeleted", "subject", ACTION_CREDENTIAL_DELETED),
            ("logoutCurrent", "grant", ACTION_LOGOUT_CURRENT),
            (
                "refreshReuseDetected",
                "grant",
                ACTION_REFRESH_REUSE_DETECTED,
            ),
        ];

        for (kind, target_kind, action) in legal_cases {
            let payload = format!(
                r#"{{"actor":{{"keyId":1,"kind":"admin","ref":"{actor_ref}"}},"kind":"{kind}","occurredAt":1700000400,"target":{{"keyId":1,"kind":"{target_kind}","ref":"{target}"}},"tenantId":"{CANON_TENANT}"}}"#
            );
            let command = security_audit_command_from_message(&Message::new(
                "security",
                payload.into_bytes(),
            ))
            .expect("logout security event");
            assert_eq!(command.tenant().to_string(), CANON_TENANT);
            assert_eq!(format!("{command:?}"), "SecurityAuditCommand(<redacted>)");
            let record = command.into_record();
            assert_eq!(record.actor.as_uuid().to_string(), actor_ref);
            assert_eq!(record.actor_kind, rss_request_context::PrincipalKind::Admin);
            assert_eq!(record.resource.id(), target);
            assert_eq!(record.action.as_str(), action);
        }

        for (kind, target_kind, _) in legal_cases {
            let mismatched_target_kind = match target_kind {
                "subject" => "grant",
                "grant" => "subject",
                _ => unreachable!("legal target kinds are sealed by the test table"),
            };
            let payload = format!(
                r#"{{"actor":{{"keyId":1,"kind":"admin","ref":"{actor_ref}"}},"kind":"{kind}","occurredAt":1,"target":{{"keyId":1,"kind":"{mismatched_target_kind}","ref":"{target}"}},"tenantId":"{CANON_TENANT}"}}"#
            );
            let error = security_audit_command_from_message(&Message::new(
                "security",
                payload.into_bytes(),
            ))
            .expect_err("kind/target mismatch must fail closed");
            assert!(matches!(error, AuditEventRecordError::SecurityKind));
        }

        let pre_epoch = format!(
            r#"{{"actor":{{"keyId":1,"kind":"admin","ref":"{actor_ref}"}},"kind":"logoutAll","occurredAt":-1,"target":{{"keyId":1,"kind":"subject","ref":"{target}"}},"tenantId":"{CANON_TENANT}"}}"#
        );
        let error =
            security_audit_command_from_message(&Message::new("security", pre_epoch.into_bytes()))
                .expect_err("pre-epoch security event must fail closed");
        assert!(matches!(error, AuditEventRecordError::Time(_)));

        let payload_with_unknown_field = format!(
            r#"{{"actor":{{"keyId":1,"kind":"admin","ref":"{actor_ref}"}},"kind":"logoutAll","occurredAt":1,"target":{{"keyId":1,"kind":"subject","ref":"{target}"}},"tenantId":"{CANON_TENANT}","sid":"secret"}}"#
        );
        let error = security_audit_command_from_message(&Message::new(
            "security",
            payload_with_unknown_field.into_bytes(),
        ))
        .expect_err("unknown fields must remain rejected");
        assert!(matches!(error, AuditEventRecordError::Decode(_)));

        for (actor_kind, expected) in [
            ("user", rss_request_context::PrincipalKind::User),
            ("admin", rss_request_context::PrincipalKind::Admin),
            ("service", rss_request_context::PrincipalKind::Service),
        ] {
            let payload = format!(
                r#"{{"actor":{{"keyId":1,"kind":"{actor_kind}","ref":"{actor_ref}"}},"kind":"accountReactivated","occurredAt":1,"target":{{"keyId":1,"kind":"subject","ref":"{target}"}},"tenantId":"{CANON_TENANT}"}}"#
            );
            let record = security_audit_command_from_message(&Message::new(
                "security",
                payload.into_bytes(),
            ))
            .expect("typed security actor")
            .into_record();
            assert_eq!(record.actor.as_uuid().to_string(), actor_ref);
            assert_eq!(record.actor_kind, expected);
        }

        let payload_with_unknown_actor_field = format!(
            r#"{{"actor":{{"keyId":1,"kind":"admin","ref":"{actor_ref}","subject":"secret"}},"kind":"logoutAll","occurredAt":1,"target":{{"keyId":1,"kind":"subject","ref":"{target}"}},"tenantId":"{CANON_TENANT}"}}"#
        );
        let error = security_audit_command_from_message(&Message::new(
            "security",
            payload_with_unknown_actor_field.into_bytes(),
        ))
        .expect_err("unknown actor fields must remain rejected");
        assert!(matches!(error, AuditEventRecordError::Decode(_)));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn session_created_appends_verifiable_chain_entry() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
        )
        .await
        .expect("handle ok");

        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
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
        assert_eq!(entry.resource().id(), format!("event:{CANON_EVENT_ID}"));
        assert!(!entry.resource().id().contains(CANON_SESSION));
        assert_eq!(entry.actor().as_uuid().to_string(), CANON_SUBJECT);
        // 落库链条可被同 key hasher 验证完整。
        let verifier: AuditChainHasher<TestKeyedHasher> = keyed_hasher(0x5a);
        assert!(verifier.verify(&listed.entries).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_created_rejects_non_uuid_event_id() {
        let error = audit_record_from_event_message(
            AuditEventKind::SessionCreated,
            &Message::new(
                "not-an-event-uuid",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ),
        )
        .err()
        .expect("session audit EventId must be a canonical UUID v4");

        assert!(matches!(error, AuditEventRecordError::EventId(_)));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_created_rejects_non_v4_event_id() {
        let error = audit_record_from_event_message(
            AuditEventKind::SessionCreated,
            &Message::new(
                "33333333-4444-1555-8666-777777777777",
                payload_bytes(CANON_SUBJECT, CANON_TENANT),
            ),
        )
        .err()
        .expect("session audit EventId must be UUID v4");

        assert!(matches!(error, AuditEventRecordError::EventIdVersion));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_created_rejects_noncanonical_or_non_rfc_v4_event_id() {
        for event_id in [
            "33333333-4444-4555-8666-77777777777A",
            "33333333444445558666777777777777",
            "33333333-4444-4555-7666-777777777777",
            "33333333-4444-4555-c666-777777777777",
            "33333333-4444-4555-e666-777777777777",
        ] {
            let error = audit_record_from_event_message(
                AuditEventKind::SessionCreated,
                &Message::new(event_id, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
            )
            .err()
            .expect("session audit EventId must be canonical UUID v4 in the RFC variant");
            assert!(matches!(error, AuditEventRecordError::EventIdVersion));
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_created_rejects_event_id_equal_to_session_id() {
        let error = audit_record_from_event_message(
            AuditEventKind::SessionCreated,
            &Message::new(CANON_SESSION, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
        )
        .err()
        .expect("EventId must be independent from the bearer session id");

        assert!(matches!(error, AuditEventRecordError::EventIdReusesSession));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_assigned_appends_audit_entry() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::RoleAssigned,
            Message::new("m-role-assigned", role_assigned_payload_bytes()),
        )
        .await
        .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
        assert_eq!(
            entry.actor_kind(),
            rss_request_context::PrincipalKind::Admin
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_revoked_appends_audit_entry() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::RoleRevoked,
            Message::new("m-role-revoked", role_revoked_payload_bytes()),
        )
        .await
        .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
        assert_eq!(
            entry.actor_kind(),
            rss_request_context::PrincipalKind::Admin
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policy_updated_appends_audit_entry() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::PolicyUpdated,
            Message::new(
                "m-policy-updated",
                policy_updated_payload_bytes(IdentityPolicyUpdatedPayloadChangeKind::Updated),
            ),
        )
        .await
        .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
        assert_eq!(
            entry.actor_kind(),
            rss_request_context::PrincipalKind::Admin
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_assigned_preserves_service_actor_kind() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::RoleAssigned,
            Message::new(
                "m-role-assigned-service",
                role_assigned_payload_bytes_for_kind(
                    "target-subject",
                    IdentityRoleAssignedPayloadActorKind::Service,
                ),
            ),
        )
        .await
        .expect("handle ok");

        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
            rss_request_context::PrincipalKind::Service
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn role_binding_audit_resource_distinguishes_subjects() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::RoleAssigned,
            Message::new(
                "m-role-assigned-a",
                role_assigned_payload_bytes_for("target-a"),
            ),
        )
        .await
        .expect("handle target-a");
        append_event_for_test(
            repo.clone(),
            AuditEventKind::RoleAssigned,
            Message::new(
                "m-role-assigned-b",
                role_assigned_payload_bytes_for("target-b"),
            ),
        )
        .await
        .expect("handle target-b");

        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
        let result = append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new("m-bad", b"not json".to_vec()),
        )
        .await;
        assert!(result.is_err());
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
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
        let raw = format!(
            r#"{{"sessionId":"{CANON_SESSION}","subject":"{CANON_SUBJECT}","tenantId":"NOT-A-UUID","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result = append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new("m", raw),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rejects_nil_tenant() {
        let repo = repo();
        let raw = format!(
            r#"{{"sessionId":"{CANON_SESSION}","subject":"{CANON_SUBJECT}","tenantId":"00000000-0000-0000-0000-000000000000","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result =
            append_event_for_test(repo, AuditEventKind::SessionCreated, Message::new("m", raw))
                .await;
        assert!(result.is_err(), "nil tenant must fail the TenantId funnel");
    }

    /// #1277 F1：subject 是 typed `uuid::Uuid`（schema `format:uuid`）——非 UUID subject 在 payload **decode**
    /// 即 fail-closed（serde 反序列化失败），不进链。用 raw JSON（typed 构造器无法表达非 UUID）证 decode-层拒绝。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rejects_non_canonical_subject() {
        let repo = repo(); // 手造 payload JSON：subject 为非 UUID 字符串（typed `uuid::Uuid` 字段无法表达，故走 raw bytes）。
        let raw = format!(
            r#"{{"sessionId":"{CANON_SESSION}","subject":"alice-not-uuid","tenantId":"{CANON_TENANT}","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result = append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new("m", raw),
        )
        .await;
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
        let raw = format!(
            r#"{{"sessionId":"sess-not-uuid","subject":"{CANON_SUBJECT}","tenantId":"{CANON_TENANT}","occurredAt":1700000000}}"#
        )
        .into_bytes();
        let result = append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new("m", raw),
        )
        .await;
        assert!(result.is_err(), "非 canonical session_id 须拒绝");
        // anti-vacuity：未 append（链空）。
        let listed = repo
            .list(
                TenantRepoScope::for_test(
                    rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
                ),
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
        assert_eq!(AUDIT_LIST_HTTP_SPEC.route.path(), AUDIT_ENTRIES_PATH);
        assert_eq!(AUDIT_LIST_HTTP_SPEC.route.method(), "GET");
        assert_eq!(
            AUDIT_LIST_HTTP_SPEC.route.auth(),
            vocab::HttpRouteAuth::Permission(vocab::AUDIT_READ_PERMISSION)
        );
        assert_eq!(
            AUDIT_LIST_TENANT_HTTP_SPEC.route.path(),
            AUDIT_TENANT_ENTRIES_PATH
        );
        assert_eq!(AUDIT_LIST_TENANT_HTTP_SPEC.route.method(), "GET");
        let subs: Vec<_> = reg
            .drain_subscribers()
            .into_iter()
            .map(bootstrap::SubscriberBinding::into_parts)
            .collect();
        let expected: Vec<_> = [
            SESSION_CREATED_SPEC,
            ROLE_ASSIGNED_SPEC,
            ROLE_REVOKED_SPEC,
            POLICY_UPDATED_SPEC,
            SECURITY_EVENT_SPEC,
        ]
        .into_iter()
        .flat_map(|event| {
            event
                .subscriptions()
                .iter()
                .filter(|spec| spec.consumer() == AUDIT_DOMAIN)
                .map(move |spec| (event, spec))
        })
        .collect();
        assert_eq!(expected.len(), 5);
        assert_eq!(subs.len(), expected.len());
        for (event, spec) in expected {
            assert_eq!(spec.consumer(), AUDIT_DOMAIN);
            assert_eq!(spec.execution(), SubscriptionExecution::AdapterNative);
            assert_eq!(spec.effect(), None);
            assert_eq!(
                spec.external_effect_policy(),
                vocab::ExternalEffectPolicy::TransactionalOnly
            );
            assert!(
                subs.iter()
                    .any(|(contract_id, topic, consumer, group, capability)| {
                        *contract_id == event.contract_id()
                            && *topic == event.topic()
                            && *consumer == spec.consumer()
                            && group.as_str() == spec.group()
                            && matches!(
                                capability,
                                SubscriberCapability::AdapterNativeTransactional
                            )
                    }),
                "missing subscriber binding for {}",
                event.contract_id()
            );
        }
    }

    #[test]
    fn audit_http_routes_and_error_logs_use_single_source_funnels() {
        let source = include_str!("application.rs");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(source);
        let first_subpath = ["AUDIT_ENTRIES", "_SUBPATH"].concat();
        let target_subpath = ["AUDIT_TENANT_ENTRIES", "_SUBPATH"].concat();
        let raw_error = ["error = %", "error"].concat();
        let raw_short_error = ["error = %", "e"].concat();

        assert!(
            !production.contains(&first_subpath) && !production.contains(&target_subpath),
            "production route path metadata must be derived from generated HttpSpec"
        );
        assert!(
            !production.contains(&raw_error) && !production.contains(&raw_short_error),
            "production error logs must use secure::redact_error"
        );
        let error_logs = production.matches("tracing::error!(").count();
        let error_chain_logs = production.matches("error_chain = %").count();
        assert_eq!(
            production.matches("secure::redact_error(").count(),
            error_chain_logs,
            "every logged error chain must use the secure redaction funnel"
        );
        assert_eq!(
            production.matches("domain = AUDIT_DOMAIN").count(),
            error_logs,
            "every production error log must carry the audit domain"
        );
        assert_eq!(
            production.matches("GeneratedEndpoint::new(").count()
                + production
                    .matches("GeneratedEndpoint::new_declared(")
                    .count(),
            2
        );
        assert_eq!(production.matches(".mount(").count(), 2);
        assert!(!production.contains("axum::routing::on("));
    }

    #[test]
    fn audit_routes_carry_complete_generated_evidence() {
        let cases = [
            (
                AUDIT_LIST_HTTP_SPEC.route,
                AUDIT_ENTRIES_PATH,
                vocab::HttpConsistencyLevel::LocalOnly,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::Read,
                    vocab::HttpEffectKind::Projection,
                ][..],
            ),
            (
                AUDIT_LIST_TENANT_HTTP_SPEC.route,
                AUDIT_TENANT_ENTRIES_PATH,
                vocab::HttpConsistencyLevel::LocalTx,
                &[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::Read,
                    vocab::HttpEffectKind::Projection,
                    vocab::HttpEffectKind::BusinessWrite,
                    vocab::HttpEffectKind::BusinessTransaction,
                    vocab::HttpEffectKind::CrossTenantAudit,
                ][..],
            ),
        ];

        for (route, path, consistency, effects) in cases {
            assert_eq!(route.path(), path);
            assert_eq!(route.method(), "GET");
            assert_eq!(
                route.auth(),
                vocab::HttpRouteAuth::Permission(vocab::AUDIT_READ_PERMISSION)
            );
            assert_eq!(route.consistency_level(), consistency);
            assert_eq!(route.effect_profile().effects(), effects);
        }
    }

    /// 在注入 ctx tenant 的 Router 上 oneshot 一个 GET（参数绑定 + 状态码 + 响应体）。
    #[allow(clippy::expect_used)]
    async fn get_entries(repo: TestRepo, query: &str) -> (StatusCode, Vec<u8>) {
        get_entries_with(repo, None, Some(default_admin_principal()), query).await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        query: &str,
    ) -> (StatusCode, Vec<u8>) {
        get_entries_with_sink(repo, admin_repo, principal, audit_sink(), query).await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with_sink<S>(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: AuditListTenantAppender + Send + Sync + 'static,
    {
        get_entries_with_sink_and_authorizer(
            repo,
            admin_repo,
            principal,
            audit_sink,
            Some(projection_authorizer(&[])),
            None,
            query,
        )
        .await
    }

    #[allow(clippy::expect_used)]
    async fn get_entries_with_sink_and_authorizer<S>(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        authorizer: Option<Arc<dyn httpserve::RouteAuthorizer>>,
        target: Option<&str>,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: AuditListTenantAppender + Send + Sync + 'static,
    {
        let target_deps = TargetAuditReadDeps {
            admin_repo,
            audit_sink: Arc::new(audit_sink),
            audit_clock: audit_clock(),
        };
        let authenticated = principal.as_ref().map(|principal| match principal.kind() {
            rss_request_context::PrincipalKind::User => match principal.tenant() {
                Some(tenant) => {
                    httpserve::Authenticated::new_rss_user_for_test(CANON_SUBJECT, tenant)
                }
                None => httpserve::Authenticated::new_rss_user_tenantless_for_test(CANON_SUBJECT),
            },
            kind => httpserve::Authenticated::new(
                httpserve::NonRssTestScheme::FederatedAccessToken,
                kind,
                CANON_SUBJECT,
                principal.tenant(),
            ),
        });
        let scoped_authenticated = authenticated.clone();
        let scoped_authorizer = authorizer.clone();
        let target_authenticated = authenticated;
        let target_authorizer = authorizer;
        let target_principal = principal;
        let app = axum::Router::new()
            .route(
                AUDIT_ENTRIES_PATH,
                axum::routing::get(
                    move |headers: axum::http::HeaderMap,
                          q: Result<Query<AuditListEntriesRequest>, QueryRejection>| {
                        let repo = repo.read.clone();
                        let authenticated = scoped_authenticated.clone();
                        let authorizer = scoped_authorizer.clone();
                        let request_id = headers
                            .get("x-request-id")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("rid-test")
                            .to_string();
                        async move {
                            let Ok(q) = q else {
                                return httpserve::error::validation_bad_request(&request_id);
                            };
                            authorize_and_list_entries_for_test(
                                repo,
                                authorizer,
                                authenticated,
                                q.0,
                                request_id,
                            )
                            .await
                        }
                    },
                ),
            )
            .route(
                AUDIT_TENANT_ENTRIES_PATH,
                axum::routing::get(
                    move |headers: axum::http::HeaderMap,
                          Path(target): Path<String>,
                          q: Result<Query<AuditListTenantEntriesRequest>, QueryRejection>| {
                        let deps = target_deps.clone();
                        let principal = target_principal.clone();
                        let authenticated = target_authenticated.clone();
                        let authorizer = target_authorizer.clone();
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
                            list_entries_target_tenant(
                                deps,
                                principal,
                                authenticated,
                                authorizer,
                                TargetReadRequest {
                                    target_raw: target,
                                    page: q.0,
                                    request_id,
                                    correlation_id,
                                },
                            )
                            .await
                        }
                    },
                ),
            );
        let path = target.map_or_else(
            || AUDIT_ENTRIES_PATH.to_string(),
            |tenant| AUDIT_TENANT_ENTRIES_PATH.replace("{tenantId}", tenant),
        );
        let uri = format!("{path}{query}");
        let request = axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("request");
        let ctx = runctx::test_support::app_ctx(
            rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"),
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

    #[allow(clippy::expect_used)]
    #[allow(clippy::too_many_arguments)]
    fn finalized_scoped_router(
        repo: TestRepo,
        admin_repo: Arc<DynAuditAdminRepo<'static>>,
        domain_sink: RecordingAuditSink,
        auth_sink: RecordingAuditSink,
        evidence_tenant: Option<rss_request_context::TenantId>,
        ambient_principal_kind: rss_request_context::PrincipalKind,
        ambient_subject: &'static str,
        authorizer: Arc<dyn httpserve::RouteAuthorizer>,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::audit_v1::list_entries::RouteMarker,
            AuditListHandlerState,
        >,
    ) {
        let domain = AuditDomain::new(
            repo.read,
            Some(admin_repo),
            domain_sink.clone(),
            audit_clock(),
        );
        let mut registry = bootstrap::compose(&[&domain]).expect("compose audit domain");
        let finalized = registry.finalize_routes().expect("finalize routes");
        let (_, routes) = finalized
            .into_iter()
            .find(|(listener, _)| matches!(listener, ListenerKind::Admin))
            .expect("admin routes");
        let proof = ::httpserve::prove_local_only_mounted_route_state::<AuditListHandlerState, _>(
            &routes,
            &::generated::http::audit_v1::list_entries::ROUTE,
        )
        .expect("audit list route is mounted in finalized routes");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Admin,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("admin jwt plan");
        let ambient = rss_request_context::TenantId::parse(CANON_TENANT).expect("ambient tenant");
        let bridge_principal =
            principal(rss_request_context::PrincipalKind::Admin, evidence_tenant);
        let authenticated = httpserve::Authenticated::new(
            httpserve::NonRssTestScheme::FederatedAccessToken,
            rss_request_context::PrincipalKind::Admin,
            CANON_SUBJECT,
            evidence_tenant,
        );
        let scope = httpserve::PendingScopeCtx::new(runctx::test_support::app_ctx_with_kind(
            ambient,
            ambient_principal_kind,
            ambient_subject,
        ));
        let router = ::httpserve::finalize_auth_with_audit_and_authorizer(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            audit_clock(),
            authorizer,
        )
        .expect("finalize auth")
        .layer(::axum::Extension(scope))
        .layer(::axum::Extension(bridge_principal))
        .layer(::axum::Extension(authenticated))
        .into_plaintext_router_for_test();
        (router, proof)
    }

    async fn get_target_entries_with(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        target: &str,
        query: &str,
    ) -> (StatusCode, Vec<u8>) {
        get_target_entries_with_sink(repo, admin_repo, principal, audit_sink(), target, query).await
    }

    async fn get_target_entries_with_sink<S>(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        target: &str,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: AuditListTenantAppender + Send + Sync + 'static,
    {
        get_target_entries_with_sink_and_authorizer(
            repo,
            admin_repo,
            principal,
            audit_sink,
            Some(projection_authorizer(&[])),
            target,
            query,
        )
        .await
    }

    async fn get_target_entries_with_sink_and_authorizer<S>(
        repo: TestRepo,
        admin_repo: Option<Arc<DynAuditAdminRepo<'static>>>,
        principal: Option<Arc<authn::Principal>>,
        audit_sink: S,
        authorizer: Option<Arc<dyn httpserve::RouteAuthorizer>>,
        target: &str,
        query: &str,
    ) -> (StatusCode, Vec<u8>)
    where
        S: AuditListTenantAppender + Send + Sync + 'static,
    {
        get_entries_with_sink_and_authorizer(
            repo,
            admin_repo,
            principal,
            audit_sink,
            authorizer,
            Some(target),
            query,
        )
        .await
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_lists_tenant_entries_with_pagination() {
        let repo = repo();
        for _ in 0..3 {
            append_event_for_test(
                repo.clone(),
                AuditEventKind::SessionCreated,
                Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
            )
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
        append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
        )
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
        append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
        )
        .await
        .expect("append");
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        let admin = principal(rss_request_context::PrincipalKind::Admin, Some(tenant));

        let (status, body) = get_entries_with_sink_and_authorizer(
            repo,
            None,
            Some(admin),
            audit_sink(),
            Some(projection_authorizer(FIELDS)),
            None,
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

        impl AuditReadRepo for ReadFailsRepo {
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
            let repo = TestRepo::read_only(ReadFailsRepo {
                list_calls: list_calls.clone(),
            });

            let (status, body) = get_entries_with_sink_and_authorizer(
                repo,
                None,
                Some(default_admin_principal()),
                audit_sink(),
                authorizer,
                None,
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
    async fn local_only_scoped_read_rejects_unbound_tenant_evidence_before_repo() {
        let other = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000abc")
            .expect("other tenant");

        for (label, evidence_tenant) in [
            ("mismatched tenant", Some(other)),
            ("tenantless evidence", None),
        ] {
            let probe = CountingScopedReadRepo::default();
            let (status, body) = get_entries_with_sink_and_authorizer(
                probe.test_repo(),
                None,
                Some(principal(
                    rss_request_context::PrincipalKind::Admin,
                    evidence_tenant,
                )),
                audit_sink(),
                Some(projection_authorizer(&[])),
                None,
                "",
            )
            .await;

            assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
            assert_eq!(probe.list_calls(), 0, "{label} must not read repo");
            assert!(probe.scopes().is_empty(), "{label} must not mint a scope");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN", "{label}");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn local_only_scoped_read_conforms_via_finalized_admin_router() {
        struct Case {
            label: &'static str,
            evidence_tenant: Option<rss_request_context::TenantId>,
            ambient_kind: rss_request_context::PrincipalKind,
            ambient_subject: &'static str,
            allow: bool,
            fail_read: bool,
            query: String,
            expected_status: StatusCode,
            expected_reads: usize,
            expected_pdp_calls: usize,
            expected_denial: bool,
        }

        impl Case {
            fn new(
                label: &'static str,
                evidence_tenant: Option<rss_request_context::TenantId>,
                expected_status: StatusCode,
                expected_reads: usize,
            ) -> Self {
                Self {
                    label,
                    evidence_tenant,
                    ambient_kind: rss_request_context::PrincipalKind::Admin,
                    ambient_subject: CANON_SUBJECT,
                    allow: true,
                    fail_read: false,
                    query: String::new(),
                    expected_status,
                    expected_reads,
                    expected_pdp_calls: 1,
                    expected_denial: false,
                }
            }
        }

        let ambient = rss_request_context::TenantId::parse(CANON_TENANT).expect("ambient tenant");
        let other = rss_request_context::TenantId::parse("00000000-0000-4000-8000-000000000abc")
            .expect("other tenant");
        let cases = [
            Case::new("success", Some(ambient), StatusCode::OK, 1),
            Case {
                allow: false,
                expected_denial: true,
                ..Case::new(
                    "authorization denied",
                    Some(ambient),
                    StatusCode::FORBIDDEN,
                    0,
                )
            },
            Case {
                fail_read: true,
                ..Case::new(
                    "hash mismatch",
                    Some(ambient),
                    StatusCode::INTERNAL_SERVER_ERROR,
                    1,
                )
            },
            Case {
                expected_pdp_calls: 0,
                expected_denial: true,
                ..Case::new("mismatched tenant", Some(other), StatusCode::FORBIDDEN, 0)
            },
            Case {
                expected_pdp_calls: 0,
                expected_denial: true,
                ..Case::new("tenantless evidence", None, StatusCode::FORBIDDEN, 0)
            },
            Case {
                ambient_subject: "different-subject",
                expected_pdp_calls: 0,
                expected_denial: true,
                ..Case::new(
                    "mismatched subject",
                    Some(ambient),
                    StatusCode::FORBIDDEN,
                    0,
                )
            },
            Case {
                ambient_kind: rss_request_context::PrincipalKind::User,
                expected_pdp_calls: 0,
                expected_denial: true,
                ..Case::new(
                    "mismatched principal kind",
                    Some(ambient),
                    StatusCode::FORBIDDEN,
                    0,
                )
            },
            Case {
                query: format!("?tenantId={other}"),
                ..Case::new(
                    "legacy tenant query",
                    Some(ambient),
                    StatusCode::BAD_REQUEST,
                    0,
                )
            },
        ];

        for case in cases {
            let repo_probe = if case.fail_read {
                CountingScopedReadRepo::failing()
            } else {
                CountingScopedReadRepo::default()
            };
            let admin_probe = CountingAdminRepo::default();
            let admin_calls = admin_probe.list_calls();
            let domain_sink = RecordingAuditSink::ok();
            let auth_sink = RecordingAuditSink::ok();
            let authorizer = Arc::new(ProjectionAuthorizer::new(&[], case.allow));
            let (router, proof) = finalized_scoped_router(
                repo_probe.test_repo(),
                admin_probe.boxed(),
                domain_sink.clone(),
                auth_sink.clone(),
                case.evidence_tenant,
                case.ambient_kind,
                case.ambient_subject,
                authorizer.clone(),
            );
            let observers = ::testkit::local_only::LocalOnlyObservers::new(
                repo_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                    &proof,
                ),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                    &proof,
                ),
            );
            let request = axum::http::Request::builder()
                .uri(format!("{AUDIT_ENTRIES_PATH}{}", case.query))
                .body(axum::body::Body::empty())
                .expect("request");

            let response =
                ::testkit::local_only::assert_local_only(observers, move || async move {
                    router.oneshot(request).await
                })
                .await
                .expect("LocalOnly conformance")
                .expect("oneshot");

            assert_eq!(response.status(), case.expected_status, "{}", case.label);
            let response_request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .expect("sealed router generated request id")
                .to_string();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            match case.label {
                "success" => {
                    let page: AuditListEntriesResponse =
                        serde_json::from_slice(&body).expect("typed success response");
                    assert!(page.data.is_empty());
                    assert!(!page.has_more);
                    assert!(page.next_cursor.is_none());
                }
                "legacy tenant query" => {
                    let json: serde_json::Value =
                        serde_json::from_slice(&body).expect("typed validation response");
                    assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
                    assert_eq!(json["error"]["message"], "validation error");
                    assert_eq!(json["error"]["retryable"], false);
                    assert_eq!(json["error"]["details"], serde_json::json!([]));
                    assert_eq!(json["error"]["requestId"], response_request_id);
                }
                "hash mismatch" => {
                    let json: serde_json::Value =
                        serde_json::from_slice(&body).expect("typed internal response");
                    assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
                    assert_eq!(json["error"]["message"], "internal error");
                    assert_eq!(json["error"]["retryable"], false);
                    assert_eq!(json["error"]["details"], serde_json::json!([]));
                    assert_eq!(json["error"]["requestId"], response_request_id);
                    assert!(!String::from_utf8_lossy(&body).contains("HashMismatch"));
                }
                _ => {}
            }
            let auth_events = auth_sink.events();
            assert_eq!(
                auth_events.len(),
                1,
                "{}: auth audit cardinality",
                case.label
            );
            let auth_event = &auth_events[0];
            assert_eq!(auth_event.principal_id, CANON_SUBJECT, "{}", case.label);
            assert_eq!(
                auth_event.principal_kind,
                rss_request_context::PrincipalKind::Admin,
                "{}",
                case.label
            );
            assert_eq!(auth_event.tenant_id, case.evidence_tenant, "{}", case.label);
            assert_eq!(auth_event.resource_kind, "http_route", "{}", case.label);
            assert_eq!(
                auth_event.resource_id,
                AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                "{}",
                case.label
            );
            assert_eq!(auth_event.action, "httpserve:authz", "{}", case.label);
            let expected_outcome = if case.expected_denial {
                diport::AuditOutcome::Failure {
                    reason: "forbidden",
                }
            } else {
                diport::AuditOutcome::Success
            };
            assert_eq!(auth_event.outcome, expected_outcome, "{}", case.label);
            assert_eq!(
                authorizer.calls(),
                case.expected_pdp_calls,
                "{}",
                case.label
            );
            assert_eq!(
                repo_probe.list_calls(),
                case.expected_reads,
                "{}",
                case.label
            );
            assert_eq!(
                admin_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{}: target LocalTx admin repo must stay excluded",
                case.label
            );
            assert!(
                domain_sink.events().is_empty(),
                "{}: scoped handler must not publish a domain/cross-tenant audit event",
                case.label
            );
            let expected_scopes = if case.expected_reads == 0 {
                Vec::new()
            } else {
                vec![ambient]
            };
            assert_eq!(repo_probe.scopes(), expected_scopes, "{}", case.label);
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn local_only_scoped_read_registers_top_level_source_receipt() {
        let ambient = rss_request_context::TenantId::parse(CANON_TENANT).expect("ambient tenant");
        let repo_probe = CountingScopedReadRepo::default();
        let domain_sink = RecordingAuditSink::ok();
        let (router, proof) = self::finalized_scoped_router(
            repo_probe.test_repo(),
            CountingAdminRepo::default().boxed(),
            domain_sink.clone(),
            RecordingAuditSink::ok(),
            Some(ambient),
            rss_request_context::PrincipalKind::Admin,
            CANON_SUBJECT,
            Arc::new(ProjectionAuthorizer::new(&[], true)),
        );
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            repo_probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );

        #[rustfmt::skip]
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::audit_v1::list_entries::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::audit_v1::list_entries::SPEC
                .route
                .contract_id(),
            observers,
            move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::audit_v1::list_entries::SPEC.route.path())),
        )
        .await
        .expect("LocalOnly conformance");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::audit_v1::list_entries::SPEC
                .route
                .contract_id()
        );
        let response = response.expect("call finalized audit route");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(repo_probe.list_calls(), 1);
        assert!(domain_sink.events().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn local_only_real_route_provider_business_write_effect_trips_typed_probe() {
        let ambient = rss_request_context::TenantId::parse(CANON_TENANT).expect("ambient tenant");
        let repo_probe = CountingScopedReadRepo::with_forbidden_write();
        let domain_sink = RecordingAuditSink::ok();
        let (router, proof) = finalized_scoped_router(
            repo_probe.test_repo(),
            CountingAdminRepo::default().boxed(),
            domain_sink.clone(),
            RecordingAuditSink::ok(),
            Some(ambient),
            rss_request_context::PrincipalKind::Admin,
            CANON_SUBJECT,
            Arc::new(ProjectionAuthorizer::new(&[], true)),
        );
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            repo_probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let request = axum::http::Request::builder()
            .uri(AUDIT_ENTRIES_PATH)
            .body(axum::body::Body::empty())
            .expect("request");

        let result = ::testkit::local_only::assert_local_only(observers, move || async move {
            router.oneshot(request).await
        })
        .await;

        assert!(matches!(
            result,
            Err(
                testkit::local_only::LocalOnlyConformanceError::ForbiddenEffects {
                    business_writes: 1,
                    outbox: 0,
                    publishes: 0,
                }
            )
        ));
        assert_eq!(repo_probe.list_calls(), 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_requires_super_admin_and_writes_audit() {
        let repo = repo();
        append_event_for_test(
            repo.clone(),
            AuditEventKind::SessionCreated,
            Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
        )
        .await
        .expect("append");
        let sink = RecordingAuditSink::ok();
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);

        let (status, body) = get_target_entries_with_sink(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            sink.clone(),
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let page: AuditListTenantEntriesResponse = serde_json::from_slice(&body).expect("decode");
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
        assert_eq!(
            event.principal_kind,
            rss_request_context::PrincipalKind::SuperAdmin
        );
        assert_eq!(
            event.tenant_id,
            Some(rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"))
        );
        assert_eq!(event.resource_kind, RESOURCE_KIND_AUDIT_ENTRIES);
        assert_eq!(event.resource_id, CANON_TENANT);
        assert_eq!(event.action, ACTION_AUDIT_LIST_CROSS_TENANT);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_via_sealed_router_uses_generated_request_context() {
        {
            const _: ::vocab::HttpRouteBinding<
                ::generated::http::audit_v1::list_tenant_entries::RouteMarker,
                ::vocab::http::LocalTx,
            > = ::generated::http::audit_v1::list_tenant_entries::ROUTE;
        }

        {
            let repo = repo();
            append_event_for_test(
                repo.clone(),
                AuditEventKind::SessionCreated,
                Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
            )
            .await
            .expect("append");
            let sink = RecordingAuditSink::ok();
            let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
            let domain = AuditDomain::new(
                repo.read.clone(),
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
            let plan = primitives::AuthPlan::new(
                ListenerKind::Admin,
                primitives::AuthScheme::FederatedAccessToken,
            )
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
                            httpserve::NonRssTestScheme::FederatedAccessToken,
                            rss_request_context::PrincipalKind::SuperAdmin,
                            CANON_SUBJECT,
                            None,
                        ));
                        req.extensions_mut().insert(principal);
                        next.run(req).await
                    }
                },
            ))
            .into_plaintext_router_for_test();
            let request = axum::http::Request::builder()
                .uri(AUDIT_TENANT_ENTRIES_PATH.replace("{tenantId}", CANON_TENANT))
                .body(axum::body::Body::empty())
                .expect("request");

            let response = router.clone().oneshot(request).await.expect("oneshot");

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
            let page: AuditListTenantEntriesResponse =
                serde_json::from_slice(&body).expect("decode");
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

            let invalid_path = axum::http::Request::builder()
                .uri("/api/v1/audit/tenants/%FF/entries")
                .body(axum::body::Body::empty())
                .expect("invalid UTF-8 path URI");
            let response = router.oneshot(invalid_path).await.expect("oneshot");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("validation envelope");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_rejects_non_super_admin_even_same_tenant() {
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        for (label, kind, principal_tenant) in [
            (
                "user",
                rss_request_context::PrincipalKind::User,
                Some(tenant),
            ),
            (
                "device",
                rss_request_context::PrincipalKind::Device,
                Some(tenant),
            ),
            (
                "admin",
                rss_request_context::PrincipalKind::Admin,
                Some(tenant),
            ),
            ("service", rss_request_context::PrincipalKind::Service, None),
            (
                "anonymous",
                rss_request_context::PrincipalKind::Anonymous,
                None,
            ),
        ] {
            let repo = repo();
            let admin = CountingAdminRepo::default();
            let list_calls = admin.list_calls();
            let principal = principal(kind, principal_tenant);

            let (status, body) = get_target_entries_with(
                repo,
                Some(admin.boxed()),
                Some(principal),
                CANON_TENANT,
                "",
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
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        let admin = principal(rss_request_context::PrincipalKind::Admin, Some(tenant));

        let (status, body) =
            get_target_entries_with(repo, None, Some(admin), CANON_TENANT, "").await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_authorizes_before_admin_repo_check() {
        let repo = repo();
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);

        let (status, body) = get_target_entries_with_sink_and_authorizer(
            repo,
            None,
            Some(principal),
            audit_sink(),
            None,
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_authorizes_with_target_contract_permission_and_tenant() {
        let repo = repo();
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
        let authorizer = Arc::new(StrictTargetAuthorizer::new(tenant));
        let dyn_authorizer: Arc<dyn httpserve::RouteAuthorizer> = authorizer.clone();

        let (status, _) = get_target_entries_with_sink_and_authorizer(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            audit_sink(),
            Some(dyn_authorizer),
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let requests = authorizer.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].contract_id,
            AUDIT_LIST_TENANT_HTTP_SPEC.route.contract_id()
        );
        assert_eq!(requests[0].permission, vocab::AUDIT_READ_PERMISSION);
        assert_eq!(requests[0].tenant_id, Some(tenant));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_without_admin_repo_is_501() {
        let repo = repo();
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);

        let (status, body) =
            get_target_entries_with(repo, None, Some(principal), CANON_TENANT, "").await;

        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_NOT_IMPLEMENTED");
    }

    /// Tripwire: permission Forbidden must durable-append Failure before grant/Success.
    ///
    /// AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01 synthetic_red — deleting
    /// [`audited_forbidden_response`] on the permission branch or swapping to grant-first
    /// fails this lock (no Success event; exact Failure reason).
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_permission_deny_before_grant_writes_durable_failure() {
        let repo = repo();
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
        let sink = RecordingAuditSink::ok();
        let admin = CountingAdminRepo::default();
        let list_calls = admin.list_calls();

        let (status, body) = get_target_entries_with_sink_and_authorizer(
            repo,
            Some(admin.boxed()),
            Some(principal),
            sink.clone(),
            Some(denying_authorizer()),
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "permission deny must stop before admin read / grant Success"
        );
        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "permission deny must write exactly one durable Failure before grant"
        );
        let event = &events[0];
        assert_eq!(event.principal_id, CANON_SUBJECT);
        assert_eq!(
            event.principal_kind,
            rss_request_context::PrincipalKind::SuperAdmin
        );
        assert_eq!(
            event.tenant_id,
            Some(rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant"))
        );
        assert_eq!(event.resource_kind, RESOURCE_KIND_AUDIT_ENTRIES);
        assert_eq!(event.resource_id, CANON_TENANT);
        assert_eq!(event.action, ACTION_AUDIT_LIST_CROSS_TENANT);
        assert_eq!(event.request_id.as_deref(), Some("rid-test"));
        assert_eq!(event.correlation_id.as_deref(), Some("rid-test"));
        assert_eq!(
            event.outcome,
            diport::AuditOutcome::Failure {
                reason: AUDIT_FORBIDDEN_REASON
            }
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    /// Tripwire: non-SuperAdmin final deny must durable-append Failure before grant.
    ///
    /// AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01 anti_vacuity — deleting
    /// [`audited_forbidden_response`] on the kind branch or falling through to
    /// [`audited_cross_tenant_scope`] fails this lock (admin read stays 0; Failure only).
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_non_super_admin_deny_before_grant_writes_durable_failure() {
        let repo = repo();
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        let principal = principal(rss_request_context::PrincipalKind::Admin, Some(tenant));
        let sink = RecordingAuditSink::ok();
        let admin = CountingAdminRepo::default();
        let list_calls = admin.list_calls();

        let (status, _) = get_target_entries_with_sink(
            repo,
            Some(admin.boxed()),
            Some(principal),
            sink.clone(),
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "non-SuperAdmin deny must stop before admin read / grant Success"
        );
        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "non-SuperAdmin deny must write exactly one durable Failure before grant"
        );
        assert_eq!(events[0].principal_id, CANON_SUBJECT);
        assert_eq!(
            events[0].principal_kind,
            rss_request_context::PrincipalKind::Admin
        );
        assert_eq!(events[0].tenant_id, Some(tenant));
        assert_eq!(events[0].resource_kind, RESOURCE_KIND_AUDIT_ENTRIES);
        assert_eq!(events[0].resource_id, CANON_TENANT);
        assert_eq!(events[0].action, ACTION_AUDIT_LIST_CROSS_TENANT);
        assert_eq!(
            events[0].outcome,
            diport::AuditOutcome::Failure {
                reason: AUDIT_FORBIDDEN_REASON
            }
        );
    }

    /// Tripwire: identity-less early 403 must leave the durable deny ledger empty.
    ///
    /// Complements AUDIT-CROSS-TENANT-DENY-BEFORE-GRANT-01: authenticated final denies
    /// append target-bound Failure; `principal=None` returns 403 **without** calling
    /// [`audited_forbidden_response`] / [`record_cross_tenant_denial`]. Routing the early
    /// branch into those helpers (or writing any sink event) fails this lock.
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_identity_less_403_has_empty_deny_ledger() {
        let repo = repo();
        let sink = RecordingAuditSink::ok();
        let admin = CountingAdminRepo::default();
        let list_calls = admin.list_calls();

        let (status, body) = get_target_entries_with_sink(
            repo,
            Some(admin.boxed()),
            None,
            sink.clone(),
            CANON_TENANT,
            "",
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            list_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "identity-less 403 must stop before admin read"
        );
        assert!(
            sink.events().is_empty(),
            "identity-less early 403 must not write durable deny ledger"
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_FORBIDDEN");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_denial_audit_failure_returns_500_without_admin_read() {
        let tenant = rss_request_context::TenantId::parse(CANON_TENANT).expect("tenant");
        for (label, principal, authorizer) in [
            (
                "kind denial",
                principal(rss_request_context::PrincipalKind::Admin, Some(tenant)),
                Some(projection_authorizer(&[])),
            ),
            (
                "permission denial",
                principal(rss_request_context::PrincipalKind::SuperAdmin, None),
                Some(denying_authorizer()),
            ),
        ] {
            let admin = CountingAdminRepo::default();
            let list_calls = admin.list_calls();
            let (status, _) = get_target_entries_with_sink_and_authorizer(
                repo(),
                Some(admin.boxed()),
                Some(principal),
                RecordingAuditSink::failing(),
                authorizer,
                CANON_TENANT,
                "",
            )
            .await;

            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{label}");
            assert_eq!(
                list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{label} must stop before admin read"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_fails_closed_when_audit_fails() {
        let repo = repo();
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
        let admin = CountingAdminRepo::default();
        let list_calls = admin.list_calls();

        let (status, body) = get_target_entries_with_sink(
            repo,
            Some(admin.boxed()),
            Some(principal),
            RecordingAuditSink::failing(),
            CANON_TENANT,
            "",
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
        for _ in 0..2 {
            append_event_for_test(
                repo.clone(),
                AuditEventKind::SessionCreated,
                Message::new(CANON_EVENT_ID, payload_bytes(CANON_SUBJECT, CANON_TENANT)),
            )
            .await
            .expect("append");
        }
        let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
        let (status, body) = get_target_entries_with(
            repo.clone(),
            Some(admin_repo(repo.clone())),
            Some(principal.clone()),
            CANON_TENANT,
            "?limit=1",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let page: AuditListTenantEntriesResponse = serde_json::from_slice(&body).expect("decode");
        let cursor = page.next_cursor.expect("next cursor");

        let (status, body) = get_target_entries_with(
            repo.clone(),
            Some(admin_repo(repo.clone())),
            Some(principal.clone()),
            CANON_TENANT,
            &format!("?limit=1&cursor={cursor}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let continuation: AuditListTenantEntriesResponse =
            serde_json::from_slice(&body).expect("decode continuation");
        assert_eq!(continuation.data.len(), 1);
        assert!(!continuation.has_more);
        assert!(continuation.next_cursor.is_none());

        let other_tenant = "00000000-0000-4000-8000-000000000abc";
        let (status, body) = get_target_entries_with(
            repo.clone(),
            Some(admin_repo(repo)),
            Some(principal),
            other_tenant,
            &format!("?limit=1&cursor={cursor}"),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn target_tenant_read_rejects_invalid_path_query_and_cursor_with_validation_envelope() {
        let malformed_cursor =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"missing-tenant-separator");
        let cases = [
            ("invalid tenant", "not-a-tenant", String::new()),
            ("zero limit", CANON_TENANT, "?limit=0".to_string()),
            ("unknown query", CANON_TENANT, "?bogus=1".to_string()),
            (
                "malformed cursor",
                CANON_TENANT,
                format!("?cursor={malformed_cursor}"),
            ),
        ];

        for (label, target, query) in cases {
            let repo = repo();
            let principal = principal(rss_request_context::PrincipalKind::SuperAdmin, None);
            let (status, body) = get_target_entries_with(
                repo.clone(),
                Some(admin_repo(repo)),
                Some(principal),
                target,
                &query,
            )
            .await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION", "{label}");
        }
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

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn audit_read_limit_matches_schema_maximum_on_both_routes() {
        let (status, _) = get_entries(repo(), "?limit=500").await;
        assert_eq!(status, StatusCode::OK, "scoped limit=500 must be accepted");

        let target_repo = repo();
        let (status, _) = get_target_entries_with(
            target_repo.clone(),
            Some(admin_repo(target_repo)),
            Some(principal(
                rss_request_context::PrincipalKind::SuperAdmin,
                None,
            )),
            CANON_TENANT,
            "?limit=500",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "target limit=500 must be accepted");

        for query in ["?limit=501", "?limit=4294967295"] {
            let (status, body) = get_entries(repo(), query).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "scoped {query}");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION", "{query}");

            let (status, _) = get_target_entries_with(
                repo(),
                None,
                Some(principal(
                    rss_request_context::PrincipalKind::SuperAdmin,
                    None,
                )),
                CANON_TENANT,
                query,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "target validation must precede admin-repo availability for {query}"
            );

            let sink = RecordingAuditSink::ok();
            let admin = CountingAdminRepo::default();
            let list_calls = admin.list_calls();
            let (status, body) = get_target_entries_with_sink(
                repo(),
                Some(admin.boxed()),
                Some(principal(
                    rss_request_context::PrincipalKind::SuperAdmin,
                    None,
                )),
                sink.clone(),
                CANON_TENANT,
                query,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "target {query}");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
            assert_eq!(json["error"]["code"], "ERR_CORE_VALIDATION", "{query}");
            assert!(
                sink.events().is_empty(),
                "invalid target page must not emit an audit event"
            );
            assert_eq!(
                list_calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "invalid target page must not call admin repo"
            );
        }
    }

    /// F6：Query 解析失败（非整数 limit / 未知字段）→ 统一 400 信封（不漏 axum 裸 400 文本）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_query_rejection_maps_to_envelope() {
        for q in [
            "?limit=abc",
            "?bogus=1",
            &format!("?tenantId={CANON_TENANT}"),
        ] {
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
        let target_path = AUDIT_TENANT_ENTRIES_PATH.replace("{tenantId}", CANON_TENANT);
        let target_hit = route_status(&admin, &target_path).await;
        assert_ne!(
            target_hit,
            StatusCode::NOT_FOUND,
            "target contract path {target_path} must be mounted"
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
    /// 在 erased read wrapper 不可达，故此处用 typed 双更直接测 handler 行为）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn admin_read_fails_closed_when_list_errors() {
        struct FailingAuditRepo;
        impl AuditReadRepo for FailingAuditRepo {
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
        let repo = TestRepo::read_only(FailingAuditRepo);
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
            repo().read,
            ResourceProjection::default_masked(),
            AuditListEntriesRequest {
                limit: std::num::NonZeroU32::new(10).expect("nonzero"),
                cursor: None,
            },
            VerifiedRequestId::for_test("missing-context"),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // 验证 JSON 信封：error.code == "ERR_CORE_INTERNAL"。
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "ERR_CORE_INTERNAL");
    }
}
