//! identity 应用层：登录编排（哈希凭据 + lockout + L2 co-tx）/ 密码变更（CAS）/ AuthGrant 关闭。
//!
//! 登录路径：账户状态/epoch 门控 → 有界 KDF 验签 + 原子 lockout 记账 → 构造 [`AuthGrant`] 与
//! `identity.session-created` fact → `prepare_initial` 只在内存生成 bearer 和哈希记录 →
//! `AuthGrantLifecycle::persist_login_grant` 在一个 provider 事务中提交根、初始 refresh 和 outbox。
//! 明文 bearer 不进入 mutation 或存储；只有持久化成功收据才能释放响应 secrets。任一写入失败或提交结果未知
//! 都不会向客户端返回 bearer。logout 经同一 lifecycle 先撤销整个 refresh 族，再关闭 AuthGrant。
//!
//! 下游 audit 订阅消费该事件。co-tx 接缝由 postgres adapter `PgAuthGrantLifecycle`
//! （INVARIANT OUTBOX-COTX-SESSION-01）落地。
//!
//! ref: uber-go/fx lifecycle.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（Domain::init push 声明）

use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(test)]
use ::generated::http::audit_v1::list_entries::SPEC as AUDIT_LIST_HTTP_SPEC;
use ::generated::http::identity_v1::{
    account_status_get::{
        IdentityAccountStatusGetData, IdentityAccountStatusGetDataStatus,
        IdentityAccountStatusGetResponse, ROUTE as ACCOUNT_STATUS_GET_HTTP_ROUTE,
        SPEC as ACCOUNT_STATUS_GET_HTTP_SPEC,
    },
    account_status_set::{
        IdentityAccountStatusSetData, IdentityAccountStatusSetDataStatus,
        IdentityAccountStatusSetRequest, IdentityAccountStatusSetRequestTargetStatus,
        IdentityAccountStatusSetResponse, PRODUCER as ACCOUNT_STATUS_SET_PRODUCER,
        SPEC as ACCOUNT_STATUS_SET_HTTP_SPEC,
    },
    login::{
        IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse, PRODUCER as LOGIN_PRODUCER,
        SPEC as LOGIN_HTTP_SPEC,
    },
    logout::{
        IdentityLogoutData, IdentityLogoutRequest, IdentityLogoutResponse,
        PRODUCER as LOGOUT_PRODUCER, SPEC as LOGOUT_HTTP_SPEC,
    },
    logout_all::{
        IdentityLogoutAllData, IdentityLogoutAllRequest, IdentityLogoutAllResponse,
        PRODUCER as LOGOUT_ALL_PRODUCER, SPEC as LOGOUT_ALL_HTTP_SPEC,
    },
    password_change::{
        IdentityPasswordChangeData, IdentityPasswordChangeRequest, IdentityPasswordChangeResponse,
        PRODUCER as PASSWORD_CHANGE_PRODUCER, SPEC as PASSWORD_CHANGE_HTTP_SPEC,
    },
    policies_create::{
        IdentityPoliciesCreateRequest, PRODUCER as POLICIES_CREATE_PRODUCER,
        SPEC as POLICIES_CREATE_HTTP_SPEC,
    },
    policies_deactivate::{
        IdentityPoliciesDeactivateRequest, PRODUCER as POLICIES_DEACTIVATE_PRODUCER,
        SPEC as POLICIES_DEACTIVATE_HTTP_SPEC,
    },
    policies_get::{ROUTE as POLICIES_GET_HTTP_ROUTE, SPEC as POLICIES_GET_HTTP_SPEC},
    policies_list::{
        IdentityPoliciesListRequest, ROUTE as POLICIES_LIST_HTTP_ROUTE,
        SPEC as POLICIES_LIST_HTTP_SPEC,
    },
    policies_update::{
        IdentityPoliciesUpdateRequest, PRODUCER as POLICIES_UPDATE_PRODUCER,
        SPEC as POLICIES_UPDATE_HTTP_SPEC,
    },
    profile::{
        IdentityProfileData, IdentityProfileDataKind, IdentityProfileResponse,
        ROUTE as PROFILE_HTTP_ROUTE, SPEC as PROFILE_HTTP_SPEC,
    },
    refresh::{
        IdentityRefreshData, IdentityRefreshRequest, IdentityRefreshResponse,
        PRODUCER as REFRESH_PRODUCER, SPEC as REFRESH_HTTP_SPEC,
    },
    roles_assign::{
        IdentityRolesAssignData, IdentityRolesAssignRequest, IdentityRolesAssignResponse,
        PRODUCER as ROLES_ASSIGN_PRODUCER, SPEC as ROLES_ASSIGN_HTTP_SPEC,
    },
    roles_list::{
        IdentityRoleView, IdentityRolesListRequest, IdentityRolesListResponse,
        ROUTE as ROLES_LIST_HTTP_ROUTE, SPEC as ROLES_LIST_HTTP_SPEC,
    },
    roles_revoke::{
        IdentityRolesRevokeData, IdentityRolesRevokeResponse, PRODUCER as ROLES_REVOKE_PRODUCER,
        SPEC as ROLES_REVOKE_HTTP_SPEC,
    },
};
use ::generated::http::runtime_v1::inventory::SPEC as RUNTIME_INVENTORY_HTTP_SPEC;
use ::generated::http::{
    HttpHeaderMode, HttpSpec, SPECS as HTTP_SPECS, settings_v1::SPEC as SETTINGS_CONFIG_HTTP_SPEC,
    settings_v2::SPEC as SETTINGS_SECRET_HTTP_SPEC,
    settings_v4::SPEC as SETTINGS_CONFIG_GET_HTTP_SPEC,
    settings_v5::SPEC as SETTINGS_CONFIG_DELETE_HTTP_SPEC,
    settings_v6::SPEC as SETTINGS_CONFIG_ROLLBACK_HTTP_SPEC,
};
use ::httpserve::{
    AuthorizedSubject, ContractMarker, GeneratedPrimaryEndpoint, ListenerRouter, Primary,
    ProducerMarker, ResourceProjection, RouteAuthorizationDecision, RouteAuthorizationRequest,
    RouteAuthorizer,
};
#[cfg(test)]
use authn::AuthGrantSnapshot;
#[cfg(test)]
use authn::GrantSecurityEventKind;
use authn::{AuthGrant, AuthGrantId, AuthGrantStatus};
use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
#[cfg(test)]
use axum::routing::{delete, get, post, put};
use base64::Engine as _;
#[cfg(test)]
use bootstrap::Domain as _;
use bootstrap::KernelError;
use consistency::IdemKey;
use diport::{
    Clock, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError, OutboxEmitErrorKind,
};
#[cfg(test)]
use eventexec::event::ReviewedEvent;
use eventexec::event::{EventEncodeError, GeneratedEventEncoder};
use generated::event::identity_v1::session_created::{
    self, IdentitySessionCreatedPayload, SPEC as SESSION_CREATED_SPEC,
};
use vocab::http::HttpResourceSharing as HttpResourceSharingMode;
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use uuid::Uuid;
use vocab::{
    CoreError, CoreErrorKind, GrantPermission, HttpRouteAuth, ProjectionField, PublicDetail,
    RoutePermissionId, TenantId,
};

#[cfg(test)]
use crate::domain::RefreshTokenSnapshot;
use crate::domain::{
    AbacAttribute, AttributeKey, AttributeValue, AuthOutcome, IdentityError, LoginIdentifier,
    POLICY_ATTR_CONTRACT_ID, POLICY_ATTR_PERMISSION, POLICY_ATTR_PRINCIPAL_ID,
    POLICY_ATTR_PRINCIPAL_KIND, POLICY_ATTR_RESOURCE_ID, POLICY_ATTR_TENANT_ID, Policy,
    PolicyEvaluation, PolicyId, PolicyObligations, PolicyRouteScope, RefreshStatus,
    RefreshTokenHash, RefreshTokenId, RefreshTokenRecord, ResourceAttributeKey,
    ResourceAttributeResolution, ResourceAttributeResourceId, ResourcePolicyAttributeKey, RoleId,
    evaluate_policies_for_tenant,
};
use crate::ports::{
    AccountReactivationLifecycle, AccountSecurityReadRepo, AccountStatusSetProducerReceipt,
    AuthGrantLifecycle, AuthGrantProvider, CredentialRepo, DynAccountReactivationLifecycle,
    DynAccountSecurityReadRepo, DynAuthGrantLifecycle, DynCredentialRepo,
    DynIdentitySecurityLifecycle, DynPolicyRepo, DynResourceAttributeReadRepo,
    DynRoleBindingReadRepo, DynRoleReadRepo, IdentitySecurityLifecycle, LoginGrantMutation,
    LoginProducerReceipt, LogoutAllProducerReceipt, LogoutCurrentProducerReceipt,
    PasswordChangeProducerReceipt, PersistedLoginGrantReceipt, PersistedRefreshRotationReceipt,
    PolicyPage, PolicyRepo, RefreshExecutionCommand, RefreshExecutionOutcome,
    RefreshProducerReceipt, RefreshTokenStore, ResourceAttributeReadRepo, RoleBindingReadRepo,
    RolePage, RoleReadRepo, TenantRepoScope,
};
#[cfg(test)]
use crate::ports::{DynRoleBindingLifecycle, RoleWriteRepo};

/// RBAC 角色管理子域（角色分配 / 撤销 + L2 角色事件发布，#1190 US5）。私有——只经 facade re-export 暴露。
mod rbac_admin;
pub use rbac_admin::{RbacAdminError, RbacAdminService};
mod grant_validation;
pub use grant_validation::{
    AccessGrantValidationError, AuthGrantValidationService, CurrentAuthGrant, ValidatedAuthGrant,
};
mod policy_manage;
use policy_manage::PolicyQueryService;
pub use policy_manage::{PolicyManageError, PolicyManageService};

/// 发布域（tracing span 标签）。从契约绑定 `CONTRACT` 单源派生（= contract.toml `domain`，#1193），
/// 不再手写字面量——envelope `domain` 由 `OutboxEnvelopeParts::new(CONTRACT, ..)` 同源承载。
const SESSION_DOMAIN: &str = SESSION_CREATED_SPEC.contract().domain();

fn tenant_repo_scope(tenant: TenantId) -> TenantRepoScope {
    TenantRepoScope::from_authenticated_tenant(tenant)
}
/// 登录路由组前缀（Primary listener，业务 API）。
pub const LOGIN_ROUTE_PREFIX: &str = "/api/v1/identity";
/// JWT 署名用途字面量（seed-login / test 路径；≥ 3 处使用，rust-standards §工程护栏抽 const）。
#[cfg(any(test, feature = "seed-login"))]
pub(crate) const SEED_JWT_PURPOSE: &str = "auth.jwt.access";

#[cfg(test)]
pub(crate) fn seed_password_policy() -> secure::PasswordPolicy {
    secure::PasswordPolicy::for_test("passwordpassword", &[])
}

/// Failure while projecting a closed domain value into a generated wire enum or scalar.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EventWireProjectionError {
    /// A future principal kind has no reviewed event-wire representation.
    #[error("principal kind has no event wire representation")]
    PrincipalKind,
    /// A domain version could not be represented by the generated positive wire scalar.
    #[error("domain version has no event wire representation")]
    Version,
}

/// 登录失败。库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射，error-handling.md）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// 用户不存在或密码不匹配（fail-closed：不区分以免用户枚举）。已锁账户亦返回此 variant（lockout 门控）。
    #[error("invalid credentials")]
    InvalidCredentials,
    /// session-created payload 编码失败（原始错误进 source，不进 Display）。
    #[error("session-created payload encode failed")]
    PayloadEncode(#[source] EventEncodeError),
    /// Reviewed envelope subject or actor identity is invalid.
    #[error("session-created envelope identity validation failed")]
    EnvelopeIdentity(#[source] diport::EnvelopeIdentityError),
    /// Stable event idempotency identity is invalid.
    #[error("session-created idempotency identity validation failed")]
    IdempotencyKey(#[source] consistency::IdemKeyError),
    /// AuthGrant 过期时间计算溢出（组合根 ttl/clock 误配，fail-closed）。
    #[error("authentication grant expiration time overflow")]
    AuthGrantTimeOverflow,
    /// AuthGrant + 初始 refresh + outbox 的 **co-tx** 写失败（任一写入或 commit 失败；
    /// 原始错误进 source，已 PII-redacted，不进 Display）。
    #[error("login grant co-tx write failed")]
    AuthGrantWrite(#[source] OutboxEmitError),
    /// 凭据仓储操作失败（CredentialRepo 方法错误通道；in-mem 不触发，postgres 接线 W）。
    #[error("credential store error")]
    Credential(#[source] IdentityError),
    /// 首发 token 签发失败（access JWT 铸造或 refresh token 落库失败，如 vault `Signer` 不可用，#1252）。
    /// mint 先于 co-tx（F4 reorder）：签发失败 ⇒ **clean failure**——无 AuthGrant、无 outbox 事件。
    #[error("initial token issuance failed")]
    TokenIssue(#[source] RefreshError),
}

/// 密码变更失败。库错误枚举（const-literal message）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChangePasswordError {
    /// 当前密码不匹配。
    #[error("invalid credentials")]
    InvalidCredentials,
    /// 凭据不存在（未知 subject）。
    #[error("credential not found")]
    NotFound,
    /// 并发密码变更版本冲突（CAS 期望版本不匹配）。
    #[error("credential version conflict")]
    VersionConflict,
    /// 新密码哈希失败（argon2 处理失败，理论极少触发）。
    #[error("password hash failed")]
    Hash,
    /// 新密码未通过固定长度或 compromised-password policy。
    #[error("password policy rejected")]
    Policy(#[source] secure::PasswordPolicyError),
    /// 凭据仓储操作失败。
    #[error("credential store error")]
    Store(#[source] IdentityError),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccountStatusChangeError {
    #[error("account security state not found")]
    NotFound,
    #[error("account security transition is invalid")]
    InvalidTransition,
    #[error("account security version conflict")]
    VersionConflict,
    #[error("account security store error")]
    Store(#[source] IdentityError),
}

fn map_account_transition_error(
    error: crate::domain::AccountSecurityTransitionError,
) -> AccountStatusChangeError {
    match error {
        crate::domain::AccountSecurityTransitionError::Illegal => {
            AccountStatusChangeError::InvalidTransition
        }
        other => AccountStatusChangeError::Store(IdentityError::Storage(Box::new(other))),
    }
}

/// `SystemTime` → UNIX epoch 秒（i64）。负偏移（早于 epoch）收口为 0；溢出收口为 `i64::MAX`。
/// 不取系统时钟（`now` 经注入 [`Clock`]）；`SystemTime::duration_since` 不在 clippy disallowed-methods。
pub(crate) fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// 登录应用服务。必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）。
///
/// 认证授权根生命周期由**单一** [`DynAuthGrantLifecycle`] provider 承载：login 经
/// `persist_login_grant` 原子创建、logout 经 `close` 原子撤销刷新族并关闭、查询经 `find_active`——同源。
/// 「创建写与关闭/查询落入不同 store」从类型层不可表达。
///
/// 注入形态为 `Arc<DynCredentialRepo>` + `Arc<DynAuthGrantLifecycle>`：域形端口基 trait 为 `Send + Sync`，
/// 使 `LoginService` 可作为 axum handler 共享 state，且 `login().await` future 为 `Send`（#1234）。
///
/// 泛型 `S: Signer`（#1252）：登录成功后经注入的 [`RefreshService<S>`] 首发 access JWT + refresh token bundle
/// （回带至响应）——令组合根注入的 vault `Signer` 有生产消费方。`S` 静态分发（`DynSigner` 非 Sync，见
/// [`authn::JwtIssuer`] DIPORT-ASYNC-ARC-SEND-01），组合根单态化 `S = vault::VaultSigner`。
pub struct LoginService<S> {
    credentials: Arc<DynCredentialRepo<'static>>,
    lifecycle: Arc<DynAuthGrantLifecycle<'static>>,
    refresh: Arc<RefreshService<S>>,
    clock: Box<dyn Clock>,
    auth_grant_ttl: Duration,
}

/// Opaque login/refresh dependency bundle minted from one provider owner.
///
/// The only constructor consumes one [`AuthGrantProvider`] owner. The owner yields both capability
/// views together, so a login service cannot accept lifecycle provider A and refresh provider B as
/// independent constructor arguments.
pub struct AuthGrantServices<S> {
    lifecycle: Arc<DynAuthGrantLifecycle<'static>>,
    security: Arc<DynIdentitySecurityLifecycle<'static>>,
    refresh: Arc<RefreshService<S>>,
}

impl<S: diport::Signer + Send + Sync + 'static> AuthGrantServices<S> {
    pub fn from_provider<P>(
        provider: P,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        issuer: Arc<authn::JwtIssuer<diport::RssAccessProfile, S>>,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> Self
    where
        P: AuthGrantProvider,
    {
        let (lifecycle, refresh_store, security) = provider.into_auth_grant_parts();
        let lifecycle = Arc::from(DynAuthGrantLifecycle::new_box(lifecycle));
        let security = Arc::from(DynIdentitySecurityLifecycle::new_box(security));
        let refresh = Arc::new(RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(refresh_store),
            Arc::clone(&lifecycle),
            Arc::clone(&security),
            accounts,
            issuer,
            clock,
            refresh_ttl,
        ));
        Self {
            lifecycle,
            security,
            refresh,
        }
    }

    pub fn refresh_service(&self) -> Arc<RefreshService<S>> {
        Arc::clone(&self.refresh)
    }

    pub fn lifecycle(&self) -> Arc<DynAuthGrantLifecycle<'static>> {
        Arc::clone(&self.lifecycle)
    }

    pub fn security_lifecycle(&self) -> Arc<DynIdentitySecurityLifecycle<'static>> {
        Arc::clone(&self.security)
    }

    fn into_parts(self) -> (Arc<DynAuthGrantLifecycle<'static>>, Arc<RefreshService<S>>) {
        (self.lifecycle, self.refresh)
    }
}

impl<S: diport::Signer + Send + Sync + 'static> LoginService<S> {
    /// 组合根构造。AuthGrant lifecycle 与 refresh store 只能经同源 [`AuthGrantServices`] 注入。
    pub fn new(
        credentials: Arc<DynCredentialRepo<'static>>,
        auth_grants: AuthGrantServices<S>,
        clock: Box<dyn Clock>,
        auth_grant_ttl: Duration,
    ) -> Self {
        let (lifecycle, refresh) = auth_grants.into_parts();
        Self {
            credentials,
            lifecycle,
            refresh,
            clock,
            auth_grant_ttl,
        }
    }

    /// 种子构造（test/seed-login 门控）：哈希凭据种子 + 注入的 AuthGrant 生命周期 provider。
    /// 明文 `password` 仅入参，经 argon2 哈希入库，不存明文。
    #[cfg(any(test, feature = "seed-login"))]
    // reason: seed-login constructor carries the required provider, clock, ttl and seed identity.
    // 每个均为不可省略的域依赖，不拆 builder（YAGNI；test-only / seed-login feature-gated，非业务 public API）。
    #[allow(clippy::too_many_arguments)]
    pub fn with_seed_credential<F>(
        make_auth_grants: F,
        clock: Box<dyn Clock>,
        auth_grant_ttl: Duration,
        login: impl Into<String>,
        user_id: ids::UserId,
        password: &str,
        tenant: TenantId,
    ) -> Result<Self, secure::PasswordError>
    where
        F: FnOnce(Box<DynAccountSecurityReadRepo<'static>>) -> AuthGrantServices<S>,
    {
        let creds = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            login, user_id, password, tenant,
        )?;
        let auth_grants = make_auth_grants(DynAccountSecurityReadRepo::new_box(creds.clone()));
        // AuthGrant lifecycle 由组合根注入；单一共享 store 同时承载 login/find/close 与 refresh，
        // 避免测试或 demo 形成互不一致的双存储。
        Ok(Self::new(
            Arc::from(crate::ports::DynCredentialRepo::new_box(creds)),
            auth_grants,
            clock,
            auth_grant_ttl,
        ))
    }

    /// 登录：lockout 门控 → 有界 KDF 验签 + 原子锁定记账（`authenticate`）→ 据 [`AuthOutcome`] 分流 →
    /// 构造 AuthGrant → prepare 首发 token → co-tx（grant + refresh + outbox）→ 持久化成功后释放响应 bearer。
    ///
    /// `tenant` 已由 handler 从 `X-Tenant-ID` header parse，不在本方法重新 parse。`request.username` 仅作
    /// [`LoginIdentifier`] 凭据查找键；写 wire / audit 的是 credential 携带的 canonical [`ids::UserId`]
    /// （`AuthOutcome::Authenticated`，#1277 F1）——登录标识（准 PII）永不进 payload / outbox / broker metadata。
    ///
    /// `skip_all`：不记 password / username（zero-trust：username 可能 email/UPN，按 PII 处理）；
    /// 失败经 `err` 记 [`LoginError`] Display（const literal，无 PII）。低基数定位字段
    /// `domain` / `operation` / `tenant_id`（tenant id 是 audit/tracing 合法可观测字段、非凭据，
    /// observability.md §日志）显式记入，便于跨租定位；password/subject/session_id 仍 skip（F5）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "login", tenant_id = %tenant),
        err
    )]
    pub async fn login(
        &self,
        receipt: LoginProducerReceipt,
        tenant: TenantId,
        request: IdentityLoginRequest,
    ) -> Result<IdentityLoginResponse, LoginError> {
        let tenant_scope = tenant_repo_scope(tenant);
        let login = LoginIdentifier::new(request.username);
        let now = self.clock.now();

        // 1. 有界 KDF 验签 + durable state + temporary lockout 原子门控：provider 据 outcome 分流——已知+错已推进 lockout、
        //    未知不建锁、成功清零并返回 canonical actor subject；对外一律 InvalidCredentials（防枚举）。
        let active = match self
            .credentials
            .authenticate(
                tenant_scope,
                login,
                secure::RawPassword::new(request.password),
                now,
            )
            .await
            .map_err(LoginError::Credential)?
        {
            AuthOutcome::Authenticated(state) => {
                if state.tenant() != tenant {
                    return Err(LoginError::InvalidCredentials);
                }
                state
                    .try_into_active()
                    .ok_or(LoginError::InvalidCredentials)?
            }
            AuthOutcome::RejectedKnown | AuthOutcome::RejectedUnknown => {
                return Err(LoginError::InvalidCredentials);
            }
        };
        let user_id = active.user_id();

        // 3. canonical subject（F1）：来自 credential 的 ids::UserId。payload.subject 是 typed `uuid::Uuid`
        //    （下方直接 `user_id.as_uuid()`，schema `format:uuid`）；此 hyphenated 串供 envelope.subject_id /
        //    AuthGrant.subject（仍 opaque String）。登录标识（准 PII）永不进 payload / outbox / broker metadata。
        let subject = user_id.as_uuid().hyphenated().to_string();

        // 4. mint AuthGrant
        let expires_at = now
            .checked_add(self.auth_grant_ttl)
            .ok_or(LoginError::AuthGrantTimeOverflow)?;
        let grant =
            AuthGrant::new_active(tenant, user_id, now, active.authn_epoch(), expires_at, now)
                .map_err(|error| LoginError::Credential(IdentityError::Storage(Box::new(error))))?;
        let grant_id = grant.id().clone();

        let payload = IdentitySessionCreatedPayload {
            session_id: grant_id.as_str().to_string(),
            // typed canonical actor subject（generated `subject: uuid::Uuid`，#1277 F1：schema `format:uuid`
            // 收紧后非 UUID subject 在 wire decode 即不可表达，consumer 无需 parse）。
            subject: user_id.as_uuid(),
            tenant_id: tenant.to_string(), // canonical hyphenated
            occurred_at: unix_secs(now),
        };
        // EventId 是独立 opaque 标识（非 session_id；session_id 敏感，不得进 broker metadata/日志）。
        let event_id = Uuid::new_v4().to_string();
        // 契约归属经 generated `CONTRACT`（domain + contract_id + version + schema_hash 同源绑定，#1193/#1618）；
        // business 只给 opaque subject。
        let subject_id = EnvelopeSubjectId::from_opaque(subject.clone())
            .map_err(LoginError::EnvelopeIdentity)?;
        let actor_id =
            OpaqueActorId::from_opaque(subject.clone()).map_err(LoginError::EnvelopeIdentity)?;
        let actor = OutboxActor::scoped(
            vocab::PrincipalKind::User,
            actor_id,
            tenant,
            vocab::ScopedTenant::SelfOnly,
        );
        let event = session_created::emit(
            &GeneratedEventEncoder,
            payload,
            tenant,
            subject_id,
            actor,
            IdemKey::parse(&event_id).map_err(LoginError::IdempotencyKey)?,
        )
        .await
        .map_err(LoginError::PayloadEncode)?;

        // 5. Prepare 首发 token bundle：只在内存生成 access/refresh bearer 与哈希记录，不写库。
        //    mint 失败 ⇒ 无任何持久化；co-tx 失败或提交未知 ⇒ pending secrets 被丢弃且不返回 bearer。
        //    `subject` = canonical user uuid（JWT `sub`）。
        let prepared = self
            .refresh
            .prepare_initial(&grant)
            .await
            .map_err(|error| match error {
                RefreshError::Invalid | RefreshError::Replayed | RefreshError::Expired => {
                    LoginError::InvalidCredentials
                }
                error @ (RefreshError::Store(_) | RefreshError::Mint(_)) => {
                    LoginError::TokenIssue(error)
                }
            })?;

        let (initial_refresh, pending_secrets) = prepared.into_parts();
        let mutation = LoginGrantMutation::new(grant, initial_refresh);
        let persisted = self
            .lifecycle
            .persist_login_grant(receipt, tenant_scope, mutation, event)
            .await
            .map_err(LoginError::AuthGrantWrite)?;
        let bundle = pending_secrets.release(persisted);

        Ok(IdentityLoginResponse {
            data: IdentityLoginData {
                session_id: grant_id.as_str().to_string(),
                expires_at: unix_secs(expires_at),
                access_token: bundle.access.as_str().to_string(),
                refresh_token: bundle.refresh.as_str().to_string(),
                access_expires_at: bundle.access.expires_at(),
            },
        })
    }
}

pub struct CredentialSecurityService {
    credentials: Arc<DynCredentialRepo<'static>>,
    grants: Arc<DynAuthGrantLifecycle<'static>>,
    accounts: Arc<DynAccountSecurityReadRepo<'static>>,
    lifecycle: Arc<DynIdentitySecurityLifecycle<'static>>,
    reactivation: Box<DynAccountReactivationLifecycle<'static>>,
    password_policy: secure::PasswordPolicy,
    clock: Box<dyn Clock>,
}

/// Linear proof that the current credential passed the shared authentication/lockout funnel.
///
/// The producer receipt and authenticated aggregate are consumed together by the final write, so
/// callers cannot validate or persist a replacement password before reauthentication succeeds.
struct PreparedPasswordChange {
    scope: TenantRepoScope,
    credential: crate::domain::Credential,
    account: crate::domain::AccountSecurityState,
    initiator: crate::domain::CredentialSecurityInitiator,
    occurred_at: SystemTime,
}

impl std::fmt::Debug for PreparedPasswordChange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedPasswordChange(<redacted>)")
    }
}

impl CredentialSecurityService {
    pub fn new<P, R>(
        credentials: Arc<DynCredentialRepo<'static>>,
        grants: Arc<DynAuthGrantLifecycle<'static>>,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        lifecycle: P,
        reactivation: R,
        password_policy: secure::PasswordPolicy,
        clock: Box<dyn Clock>,
    ) -> Self
    where
        P: IdentitySecurityLifecycle + 'static,
        R: AccountReactivationLifecycle + 'static,
    {
        Self::new_with_shared_lifecycle(
            credentials,
            grants,
            accounts,
            Arc::from(DynIdentitySecurityLifecycle::new_box(lifecycle)),
            reactivation,
            password_policy,
            clock,
        )
    }

    pub fn new_with_shared_lifecycle<R>(
        credentials: Arc<DynCredentialRepo<'static>>,
        grants: Arc<DynAuthGrantLifecycle<'static>>,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        lifecycle: Arc<DynIdentitySecurityLifecycle<'static>>,
        reactivation: R,
        password_policy: secure::PasswordPolicy,
        clock: Box<dyn Clock>,
    ) -> Self
    where
        R: AccountReactivationLifecycle + 'static,
    {
        Self {
            credentials,
            grants,
            accounts: Arc::from(accounts),
            lifecycle,
            reactivation: DynAccountReactivationLifecycle::new_box(reactivation),
            password_policy,
            clock,
        }
    }

    pub fn validate_new_password(
        &self,
        password: secure::RawPassword,
    ) -> Result<secure::ValidatedPassword, ChangePasswordError> {
        self.password_policy
            .validate(password)
            .map_err(ChangePasswordError::Policy)
    }

    async fn reauthenticate_password_change(
        &self,
        tenant: TenantId,
        user_id: ids::UserId,
        current_password: secure::RawPassword,
    ) -> Result<PreparedPasswordChange, ChangePasswordError> {
        let scope = tenant_repo_scope(tenant);
        let now = self.clock.now();
        let Some(credential) = self
            .credentials
            .find_by_user_id(scope, user_id)
            .await
            .map_err(ChangePasswordError::Store)?
        else {
            secure::verify_password(current_password, None)
                .map_err(|_| ChangePasswordError::Hash)?;
            return Err(ChangePasswordError::NotFound);
        };
        let account = match self
            .credentials
            .authenticate(scope, credential.login().clone(), current_password, now)
            .await
            .map_err(ChangePasswordError::Store)?
        {
            AuthOutcome::Authenticated(account)
                if account.tenant() == tenant && account.user_id() == user_id =>
            {
                account
            }
            AuthOutcome::Authenticated(_)
            | AuthOutcome::RejectedKnown
            | AuthOutcome::RejectedUnknown => {
                return Err(ChangePasswordError::InvalidCredentials);
            }
        };
        Ok(PreparedPasswordChange {
            scope,
            credential,
            account,
            initiator: crate::domain::CredentialSecurityInitiator::authenticated(
                tenant,
                vocab::PrincipalKind::User,
                user_id.as_uuid().hyphenated().to_string(),
            ),
            occurred_at: now,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "change_password"),
        err
    )]
    async fn change_password(
        &self,
        receipt: PasswordChangeProducerReceipt,
        prepared: PreparedPasswordChange,
        new_password: secure::ValidatedPassword,
    ) -> Result<(), ChangePasswordError> {
        let PreparedPasswordChange {
            scope,
            credential,
            account,
            initiator,
            occurred_at,
        } = prepared;
        let command = crate::domain::PasswordChangeCommand::new(
            credential,
            account,
            new_password,
            initiator,
            occurred_at,
        )
        .map_err(|error| match error {
            crate::domain::PasswordChangeCommandError::AccountInactive
            | crate::domain::PasswordChangeCommandError::IdentityMismatch => {
                ChangePasswordError::InvalidCredentials
            }
            crate::domain::PasswordChangeCommandError::Password(_) => ChangePasswordError::Hash,
            crate::domain::PasswordChangeCommandError::Account(_) => {
                ChangePasswordError::VersionConflict
            }
        })?;
        self.lifecycle
            .execute_password_change(receipt, scope, command)
            .await
            .map(|_| ())
            .map_err(|error| match error {
                IdentityError::VersionConflict => ChangePasswordError::VersionConflict,
                IdentityError::CredentialNotFound => ChangePasswordError::NotFound,
                other => ChangePasswordError::Store(other),
            })
    }

    pub async fn set_account_status(
        &self,
        receipt: AccountStatusSetProducerReceipt,
        tenant: TenantId,
        user_id: ids::UserId,
        target: crate::domain::AccountStatus,
        initiator: crate::domain::CredentialSecurityInitiator,
    ) -> Result<bool, AccountStatusChangeError> {
        let scope = tenant_repo_scope(tenant);
        let state = self
            .accounts
            .find(scope, user_id)
            .await
            .map_err(AccountStatusChangeError::Store)?
            .ok_or(AccountStatusChangeError::NotFound)?;
        if state.status() == target {
            return Ok(false);
        }
        let command =
            crate::domain::AccountStatusSetCommand::new(state, target, initiator, self.clock.now())
                .map_err(map_account_transition_error)?;
        match self
            .lifecycle
            .execute_account_status_set(receipt, scope, command)
            .await
        {
            Ok(_) => Ok(true),
            Err(IdentityError::VersionConflict) => {
                let converged = self
                    .accounts
                    .find(scope, user_id)
                    .await
                    .map_err(AccountStatusChangeError::Store)?
                    .ok_or(AccountStatusChangeError::NotFound)?;
                if converged.status() == target {
                    Ok(false)
                } else {
                    Err(AccountStatusChangeError::VersionConflict)
                }
            }
            Err(IdentityError::CredentialNotFound) => Err(AccountStatusChangeError::NotFound),
            Err(other) => Err(AccountStatusChangeError::Store(other)),
        }
    }
}

#[derive(Clone)]
struct AccountStatusQueryService {
    accounts: Arc<DynAccountSecurityReadRepo<'static>>,
}

impl AccountStatusQueryService {
    async fn account_status(
        &self,
        tenant: TenantId,
        user_id: ids::UserId,
    ) -> Result<crate::domain::AccountStatus, AccountStatusChangeError> {
        self.accounts
            .find(tenant_repo_scope(tenant), user_id)
            .await
            .map_err(AccountStatusChangeError::Store)?
            .map(|state| state.status())
            .ok_or(AccountStatusChangeError::NotFound)
    }
}

impl CredentialSecurityService {
    // Internal-only typed entrypoint: reactivation is deliberately not mounted on HTTP.
    #[allow(dead_code)]
    pub(crate) async fn reactivate_account(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<crate::domain::AccountSecurityState, AccountStatusChangeError> {
        let state = self
            .accounts
            .find(scope, user_id)
            .await
            .map_err(AccountStatusChangeError::Store)?
            .ok_or(AccountStatusChangeError::NotFound)?;
        let command = crate::domain::ReactivateAccountCommand::new(state, self.clock.now())
            .map_err(map_account_transition_error)?;
        self.reactivation
            .execute_reactivation(scope, command)
            .await
            .map_err(|error| match error {
                IdentityError::VersionConflict => AccountStatusChangeError::VersionConflict,
                IdentityError::CredentialNotFound => AccountStatusChangeError::NotFound,
                other => AccountStatusChangeError::Store(other),
            })
    }

    pub async fn logout_current(
        &self,
        receipt: LogoutCurrentProducerReceipt,
        evidence: &CurrentAuthGrant,
    ) -> Result<(), IdentityError> {
        let scope = tenant_repo_scope(evidence.tenant_id());
        let grant_id = AuthGrantId::hydrate(evidence.grant_id().to_string())
            .map_err(|error| IdentityError::Storage(Box::new(error)))?;
        let now = self.clock.now();
        let grant = self
            .grants
            .find_active(scope, grant_id, now)
            .await?
            .ok_or(IdentityError::VersionConflict)?;
        if grant.tenant() != evidence.tenant_id()
            || grant.user_id() != evidence.user_id()
            || grant.authn_epoch_at_issue().get() != evidence.authn_epoch()
        {
            return Err(IdentityError::VersionConflict);
        }
        let initiator = crate::domain::CredentialSecurityInitiator::authenticated(
            evidence.tenant_id(),
            vocab::PrincipalKind::User,
            evidence.user_id().as_uuid().hyphenated().to_string(),
        );
        let command =
            crate::domain::CredentialSecurityCommand::logout_current(grant, initiator, now)
                .map_err(|error| IdentityError::Storage(Box::new(error)))?;
        self.lifecycle
            .execute_logout_current(receipt, scope, command)
            .await
            .map(|_| ())
    }

    pub async fn logout_all(
        &self,
        receipt: LogoutAllProducerReceipt,
        evidence: &CurrentAuthGrant,
    ) -> Result<(), IdentityError> {
        let scope = tenant_repo_scope(evidence.tenant_id());
        let state = self
            .accounts
            .find(scope, evidence.user_id())
            .await?
            .ok_or(IdentityError::VersionConflict)?;
        if state.tenant() != evidence.tenant_id()
            || state.user_id() != evidence.user_id()
            || state.authn_epoch().get() != evidence.authn_epoch()
            || state.status() != crate::domain::AccountStatus::Active
        {
            return Err(IdentityError::VersionConflict);
        }
        let initiator = crate::domain::CredentialSecurityInitiator::authenticated(
            evidence.tenant_id(),
            vocab::PrincipalKind::User,
            evidence.user_id().as_uuid().hyphenated().to_string(),
        );
        let command = crate::domain::CredentialSecurityCommand::logout_all(
            state,
            initiator,
            self.clock.now(),
        )
        .map_err(|error| IdentityError::Storage(Box::new(error)))?;
        self.lifecycle
            .execute_logout_all(receipt, scope, command)
            .await
            .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// RefreshError / RefreshBundle / RefreshService
// ---------------------------------------------------------------------------

/// refresh token 操作失败（库枚举；thiserror；message 为 `&'static str` const literal，token 永不进 message）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshError {
    /// 呈递的 refresh token 未找到（未知 / 跨租）。
    #[error("refresh token is invalid")]
    Invalid,
    /// refresh token 已被消费过（重放检测原子 compromise grant root 并撤销其 refresh family）。
    #[error("refresh token was replayed")]
    Replayed,
    /// refresh token 已过期。
    #[error("refresh token is expired")]
    Expired,
    /// refresh token store 操作失败。
    #[error("refresh token store error")]
    Store(#[source] crate::domain::IdentityError),
    /// access token 签发失败。
    #[error("access token mint failed")]
    Mint(#[source] authn::JwtIssueError),
}

/// rotate 成功后的返回对象（access JWT + 新 refresh token）。不 derive Serialize（非 wire DTO）。
#[derive(Debug)]
pub struct RefreshBundle {
    /// 新签发的 access JWT。
    pub access: authn::MintedJwt,
    /// 轮换后的新 refresh token（bearer secret，仅本次传递给客户端）。
    pub refresh: authn::RefreshToken,
}

struct PreparedInitialRefresh {
    record: RefreshTokenRecord,
    pending: PendingLoginSecrets,
}

impl PreparedInitialRefresh {
    fn into_parts(self) -> (RefreshTokenRecord, PendingLoginSecrets) {
        (self.record, self.pending)
    }
}

struct PendingLoginSecrets {
    bundle: RefreshBundle,
}

impl PendingLoginSecrets {
    fn release(self, _receipt: PersistedLoginGrantReceipt) -> RefreshBundle {
        self.bundle
    }
}

struct PendingRotatedSecrets {
    bundle: RefreshBundle,
}

impl PendingRotatedSecrets {
    fn release(self, _receipt: PersistedRefreshRotationReceipt) -> RefreshBundle {
        self.bundle
    }
}

/// Refresh token 应用服务：验证、签发与原子轮换。必填依赖走构造器位置参（缺失即编译错误）。
///
/// ## rotate 设计决策：mint 先于 CAS（#284 F1）
///
/// `rotate` 先 mint access JWT，**成功后才**执行唯一 security lifecycle producer transaction。
/// 顺序的关键在于**失败语义可恢复**：mint 是可失败步骤（signer 瞬时故障），CAS 提交是不可回滚的副作用。
/// 若先提交 CAS 再 mint，mint 失败时旧 refresh 已被消费、而新 refresh secret 在错误路径被丢弃——客户端
/// 既无可用旧 token 也拿不到新 token，被瞬时 mint 故障**永久锁死**。先 mint：mint 失败 ⇒ 旧 refresh 未消费、
/// 仍 Active，客户端原样重试即可（无锁死、无重放窗口——失败的 mint 未签发任何 access token）。
/// producer transaction 在 mint 之后，故「旧 refresh 一次性」仍由事务内 CAS + reuse containment 保证；
/// mint 结果只保存在 pending secrets 中，commit receipt 确认前无法释放给 HTTP 层。
/// ref: ory/fosite handler/oauth2/flow_refresh.go@master（先生成 token 再事务内 Rotate/Create）。
pub struct RefreshService<S> {
    store: Box<crate::ports::DynRefreshTokenStore<'static>>,
    lifecycle: Arc<DynAuthGrantLifecycle<'static>>,
    security: Arc<DynIdentitySecurityLifecycle<'static>>,
    accounts: Box<DynAccountSecurityReadRepo<'static>>,
    issuer: std::sync::Arc<authn::JwtIssuer<diport::RssAccessProfile, S>>,
    clock: Box<dyn diport::Clock>,
    refresh_ttl: Duration,
}

impl<S: diport::Signer + Send + Sync + 'static> RefreshService<S> {
    /// 组合根构造：account-security reader is mandatory and has no fallback.
    fn new(
        store: Box<crate::ports::DynRefreshTokenStore<'static>>,
        lifecycle: Arc<DynAuthGrantLifecycle<'static>>,
        security: Arc<DynIdentitySecurityLifecycle<'static>>,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        issuer: std::sync::Arc<authn::JwtIssuer<diport::RssAccessProfile, S>>,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> Self {
        Self {
            store,
            lifecycle,
            security,
            accounts,
            issuer,
            clock,
            refresh_ttl,
        }
    }

    /// 登录首发：铸 access JWT（注入的 vault `Signer` 经 [`authn::JwtIssuer`] 签）+ 签发并落库首个 refresh
    /// token，组成 [`RefreshBundle`]。供 [`LoginService`] 登录成功后调用——令 minted JWT 有生产消费方（#1252）。
    ///
    /// 顺序同 `rotate` 的「mint 先于持久副作用」：先 mint access（失败 ⇒ 无 refresh 记录残留、客户端重登即可），
    /// 成功后 `issue` 落库 refresh token。Only an active account receipt can reach this method.
    ///
    /// `skip_all`：subject 不入 span（零信任；可含 PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_prepare_initial", tenant_id = %grant.tenant()),
        err
    )]
    async fn prepare_initial(
        &self,
        grant: &AuthGrant,
    ) -> Result<PreparedInitialRefresh, RefreshError> {
        if grant.status() != AuthGrantStatus::Active {
            return Err(RefreshError::Invalid);
        }
        let current = self
            .accounts
            .find(tenant_repo_scope(grant.tenant()), grant.user_id())
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::Invalid)?
            .try_into_active()
            .ok_or(RefreshError::Invalid)?;
        if current.tenant() != grant.tenant()
            || current.user_id() != grant.user_id()
            || current.authn_epoch() != grant.authn_epoch_at_issue()
        {
            return Err(RefreshError::Invalid);
        }
        // mint 先于落库：access mint 失败 ⇒ 未写任何 refresh 记录、客户端重登即可（无悬挂 token）。
        let access = self
            .issuer
            .issue_access(
                grant
                    .access_issue_input()
                    .map_err(|_| RefreshError::Invalid)?,
            )
            .await
            .map_err(RefreshError::Mint)?;
        let secret = secure::OpaqueToken::generate();
        let now = self.clock.now();
        let refresh_expires_at = now
            .checked_add(self.refresh_ttl)
            .ok_or(RefreshError::Invalid)?
            .min(grant.expires_at());
        let record = RefreshTokenRecord::new_initial(
            grant,
            RefreshTokenId::generate(),
            RefreshTokenHash::new(secure::digest(secret.expose())),
            now,
            refresh_expires_at,
        )
        .ok_or(RefreshError::Invalid)?;
        Ok(PreparedInitialRefresh {
            record,
            pending: PendingLoginSecrets {
                bundle: RefreshBundle {
                    access,
                    refresh: authn::RefreshToken::new(secret.expose()),
                },
            },
        })
    }

    /// 轮换 refresh token（reuse-detection + 新 access JWT + 新 refresh token）。
    ///
    /// ## 步骤顺序（参见 struct 级 rustdoc 关于「mint 先于事务提交」的说明）
    ///
    /// 1. 重算呈递串摘要 → `find_by_hash`（查无 → Invalid）
    /// 2. 若 status != Active → sealed reuse command 经唯一 security lifecycle 原子 compromise root、
    ///    revoke grant-bound refresh family，并在状态转换 winner 时写一条安全事件
    /// 3. 若 is_expired → Expired
    /// 4. 由源 record `begin_rotation` 派生 sealed [`RefreshRotation`]（tenant/parent/lineage 类型层 Hard 派生）
    /// 5. mint access JWT（先于事务——失败则旧 refresh 未消费、客户端可重试，#284 F1）
    /// 6. sealed command 进入 producer transaction；CAS loser 在同一事务内 containment
    /// 7. 仅 `Applied(PersistedRefreshRotationReceipt)` 可释放 pending bearer 并返回 `RefreshBundle`
    ///
    /// `skip_all`：presented bearer secret 不入 span（PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_rotate", tenant_id = %tenant),
        err
    )]
    pub async fn rotate(
        &self,
        receipt: RefreshProducerReceipt,
        tenant: vocab::TenantId,
        presented: &authn::RefreshToken,
    ) -> Result<RefreshBundle, RefreshError> {
        let tenant_scope = tenant_repo_scope(tenant);
        // 1. 查找
        let hash = RefreshTokenHash::new(secure::digest(presented.as_str()));
        let rec = self
            .store
            .find_by_hash(tenant_scope, hash)
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::Invalid)?;

        if rec.tenant() != tenant {
            return Err(RefreshError::Invalid);
        }
        let user_id = rec.user_id();

        // 2. User-record 重放检测：status != Active ⇒ 原子 compromise 根 + 撤销全 family。
        if rec.status() != RefreshStatus::Active {
            let now = self.clock.now();
            let command =
                RefreshExecutionCommand::contain_reuse(rec, now).ok_or(RefreshError::Invalid)?;
            let outcome = self
                .security
                .execute_refresh(receipt, tenant_scope, command)
                .await
                .map_err(RefreshError::Store)?;
            if matches!(outcome, RefreshExecutionOutcome::Applied(_)) {
                return Err(RefreshError::Invalid);
            }
            tracing::warn!(
                tenant_id = %tenant,
                operation = "refresh_replay_detected",
                "refresh token replay detected; authentication grant compromised"
            );
            return Err(RefreshError::Replayed);
        }
        if rec.auth_grant_status() != AuthGrantStatus::Active {
            return Err(RefreshError::Invalid);
        }

        // 3. 过期检测
        let now = self.clock.now();
        if rec.is_expired(now) {
            return Err(RefreshError::Expired);
        }

        let grant = self
            .lifecycle
            .find_active(tenant_scope, rec.auth_grant_id().clone(), now)
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::Invalid)?;
        if grant.id() != rec.auth_grant_id()
            || grant.tenant() != tenant
            || grant.user_id() != user_id
            || grant.authn_epoch_at_issue() != rec.issuance_epoch()
        {
            return Err(RefreshError::Invalid);
        }

        let active = self
            .accounts
            .find(tenant_scope, user_id)
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::Invalid)?
            .try_into_active()
            .ok_or(RefreshError::Invalid)?;
        if active.tenant() != tenant
            || active.user_id() != user_id
            || active.authn_epoch() != rec.issuance_epoch()
        {
            return Err(RefreshError::Invalid);
        }
        let access_input = grant
            .access_issue_input()
            .map_err(|_| RefreshError::Invalid)?;
        // 4. 由源 record 派生 sealed 轮换命令（tenant/parent/lineage 从源派生，错位类型层不可表达，#284 F2）
        let new_secret = secure::OpaqueToken::generate();
        let new_hash = RefreshTokenHash::new(secure::digest(new_secret.expose()));
        let rotation = rec
            .begin_rotation(RefreshTokenId::generate(), new_hash, now)
            .ok_or(RefreshError::Invalid)?;
        // 5. mint access JWT（先于 CAS，#284 F1）：mint 失败 ⇒ 旧 refresh 未消费、客户端可重试、无锁死。
        //    claim source is the current Active account receipt, not caller-selected input.
        let access = self
            .issuer
            .issue_access(access_input)
            .await
            .map_err(RefreshError::Mint)?;
        let command = RefreshExecutionCommand::rotate(rec, grant, active, rotation, now)
            .ok_or(RefreshError::Invalid)?;
        let pending = PendingRotatedSecrets {
            bundle: RefreshBundle {
                access,
                refresh: authn::RefreshToken::new(new_secret.expose()),
            },
        };

        // 6. 原子 CAS/containment：只有 commit receipt 可以释放前面 mint 的 bearer。
        let outcome = self
            .security
            .execute_refresh(receipt, tenant_scope, command)
            .await
            .map_err(RefreshError::Store)?;
        match outcome {
            RefreshExecutionOutcome::Applied(persisted) => return Ok(pending.release(persisted)),
            RefreshExecutionOutcome::Stale => return Err(RefreshError::Invalid),
            RefreshExecutionOutcome::Expired => return Err(RefreshError::Expired),
            RefreshExecutionOutcome::ReuseContained | RefreshExecutionOutcome::AlreadyContained => {
                tracing::warn!(
                    tenant_id = %tenant,
                    operation = "refresh_replay_detected",
                    "refresh token replay detected; authentication grant compromised"
                );
                return Err(RefreshError::Replayed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Seed/journey 首发 token 装配（seed-login / test 门控；生产经组合根注入 vault Signer）
// ---------------------------------------------------------------------------

/// Demo/journey 用确定性 stub `Signer`（固定字节签名；**非生产**——生产经组合根注入 vault `Signer`）。
/// 仅 `seed-login`/test 构建编译（生产依赖图无此符号，同 `with_seed_credential` 门控，PR #186 F1）。
#[cfg(any(test, feature = "seed-login"))]
#[derive(Clone, Debug)]
pub struct SeedSigner;

#[cfg(any(test, feature = "seed-login"))]
#[allow(unknown_lints, rss_diport_impl_allowlist)] // reason: test/seed-login 确定性 stub；仅 seed-login feature / #[cfg(test)] 构建编译，生产依赖图无此符号；非可互换 production provider（#1252）。unknown_lints 消除 clippy 对 dylint-only lint 的告警。
impl diport::Signer for SeedSigner {
    async fn sign(
        &self,
        _req: diport::SignRequest,
    ) -> Result<diport::Signature, diport::SignerError> {
        // reason: 确定性占位签名——seed/journey 不验 crypto，只需 `issue()` 成功落库首发 token（#1252）。
        Ok(diport::Signature::new(
            b"seed-signer-deterministic-bytes".to_vec(),
        ))
    }
    async fn shutdown(&self) -> Result<(), diport::SignerError> {
        Ok(())
    }
}

/// 装配 demo/journey 用 in-mem [`RefreshService`]（[`SeedSigner`] + in-mem store + 默认 ES256 config）。
/// 供 journey 把首发 token 签发装进 [`LoginService::with_seed_credential`] / [`IdentityDomain`]（#1252）。
/// `mk_clock` 产两个时钟（issuer + service 各一）——seed 路径无系统时钟读（journey 注入 FixedClock）。
#[cfg(any(test, feature = "seed-login"))]
#[allow(clippy::expect_used)]
fn seed_issuer(
    clock: Box<dyn diport::Clock>,
) -> Arc<authn::JwtIssuer<diport::RssAccessProfile, SeedSigner>> {
    Arc::new(
        authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            Arc::new(SeedSigner),
            clock,
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("seed-jwt-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://seed.local",
                "rss-seed",
                Duration::from_secs(900),
            ),
        )
        // reason: const config（非空 iss/aud/key、ttl>0）⇒ JwtIssuer::new 不可能失败。
        .expect("seed jwt issuer config is valid"),
    )
}

/// Assemble login and refresh from one test/demo provider owner.
#[cfg(any(test, feature = "seed-login"))]
pub fn seed_auth_grant_services<P>(
    provider: P,
    accounts: Box<DynAccountSecurityReadRepo<'static>>,
    mk_clock: impl Fn() -> Box<dyn diport::Clock>,
    refresh_ttl: Duration,
) -> AuthGrantServices<SeedSigner>
where
    P: AuthGrantProvider,
{
    AuthGrantServices::from_provider(
        provider,
        accounts,
        seed_issuer(mk_clock()),
        mk_clock(),
        refresh_ttl,
    )
}

const MAX_LOGIN_BODY_BYTES: usize = 64 * 1024;

fn request_id_from(req: &Request<Body>) -> String {
    httpserve::request_id_str(req.extensions())
        .unwrap_or("unknown")
        .to_string()
}

fn tenant_header_name(spec: &HttpSpec) -> Result<&'static str, KernelError> {
    spec.headers
        .iter()
        .find(|h| h.mode == HttpHeaderMode::PopulateOnly)
        .map(|h| h.name)
        .ok_or(KernelError::Invariant)
}

/// 从 `req` 解析 `X-Tenant-ID`（pre-auth tenant 来源）+ 读 body bytes，二者任一失败回 4xx/5xx。
/// login/refresh handler 共用——同 public + populate-only header 形态。
async fn parse_tenant_and_body(
    req: Request<Body>,
    spec: &HttpSpec,
    request_id: &str,
) -> Result<(TenantId, Bytes), Response> {
    let tenant_header =
        tenant_header_name(spec).map_err(|_| httpserve::error::internal_error(request_id))?;
    let tenant = httpserve::exact_tenant_header(req.headers(), tenant_header)
        .map_err(|_| httpserve::error::validation_bad_request(request_id))?;
    let (_, body) = req.into_parts();
    let body = to_bytes(body, MAX_LOGIN_BODY_BYTES)
        .await
        .map_err(|_| httpserve::error::validation_bad_request(request_id))?;
    Ok((tenant, body))
}

async fn login_handler<S: diport::Signer + Send + Sync + 'static>(
    marker: ProducerMarker<::generated::http::identity_v1::login::RouteMarker>,
    State(service): State<Arc<LoginService<S>>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, body) = match parse_tenant_and_body(req, &LOGIN_HTTP_SPEC, &request_id).await {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };
    login_handler_bytes(service, marker.into_receipt(), tenant, body, &request_id).await
}

#[cfg(test)]
#[derive(Clone)]
struct PublicRouteTestAuthorizer;

#[cfg(test)]
impl RouteAuthorizer for PublicRouteTestAuthorizer {
    fn authorize<'a>(
        &'a self,
        _request: RouteAuthorizationRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RouteAuthorizationDecision> + Send + 'a>>
    {
        Box::pin(async { RouteAuthorizationDecision::Deny })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn login_router_for_test<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<LoginService<S>>,
) -> axum::Router {
    let routes = httpserve::UnfinalizedRoutes::empty()
        .nest_group::<Primary, KernelError>(LOGIN_ROUTE_PREFIX, |router| {
            Ok(router.mount(
                GeneratedPrimaryEndpoint::new_producer(LOGIN_PRODUCER, login_handler::<S>)?
                    .with_state(service),
            )?)
        })
        .expect("login test route uses generated production mount");
    let plan = primitives::AuthPlan::new(
        ListenerKind::Primary,
        primitives::AuthScheme::RssAccessToken,
    )
    .expect("valid Primary access-token plan");
    httpserve::finalize_primary_auth(routes, plan, Arc::new(PublicRouteTestAuthorizer))
        .expect("public login test route finalizes")
        .into_router_for_test()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) fn refresh_router_for_test<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<RefreshService<S>>,
) -> axum::Router {
    let routes = httpserve::UnfinalizedRoutes::empty()
        .nest_group::<Primary, KernelError>(LOGIN_ROUTE_PREFIX, |router| {
            Ok(router.mount(
                GeneratedPrimaryEndpoint::new_producer(REFRESH_PRODUCER, refresh_handler::<S>)?
                    .with_state(service),
            )?)
        })
        .expect("refresh test route uses generated producer mount");
    let plan = primitives::AuthPlan::new(
        ListenerKind::Primary,
        primitives::AuthScheme::RssAccessToken,
    )
    .expect("valid Primary access-token plan");
    httpserve::finalize_primary_auth(routes, plan, Arc::new(PublicRouteTestAuthorizer))
        .expect("public refresh route finalizes")
        .into_router_for_test()
}

async fn login_handler_bytes<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<LoginService<S>>,
    receipt: LoginProducerReceipt,
    tenant: TenantId,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: IdentityLoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    let tenant_log = tenant.to_string();
    match service.login(receipt, tenant, request).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(LoginError::InvalidCredentials) => httpserve::error::unauthenticated(request_id),
        Err(LoginError::AuthGrantWrite(err)) if err.kind() == OutboxEmitErrorKind::FactConflict => {
            fact_conflict_response(request_id)
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %tenant_log,
                contract_id = LOGIN_HTTP_SPEC.route.contract_id(),
                operation = "login",
                "identity login failed"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

async fn refresh_handler<S: diport::Signer + Send + Sync + 'static>(
    marker: ProducerMarker<::generated::http::identity_v1::refresh::RouteMarker>,
    State(service): State<Arc<RefreshService<S>>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, body) = match parse_tenant_and_body(req, &REFRESH_HTTP_SPEC, &request_id).await {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };
    refresh_handler_bytes(service, marker.into_receipt(), tenant, body, &request_id).await
}

async fn refresh_handler_bytes<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<RefreshService<S>>,
    receipt: RefreshProducerReceipt,
    tenant: TenantId,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: IdentityRefreshRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    let tenant_log = tenant.to_string();
    let presented = authn::RefreshToken::new(request.refresh_token);
    match service.rotate(receipt, tenant, &presented).await {
        Ok(bundle) => {
            let response = IdentityRefreshResponse {
                data: IdentityRefreshData {
                    access_token: bundle.access.as_str().to_string(),
                    refresh_token: bundle.refresh.as_str().to_string(),
                    access_expires_at: bundle.access.expires_at(),
                },
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        // refresh token 是凭据：未知/重放/过期一律 401（不区分以免 token 探测）；重放已原子
        // Compromised grant root 并撤销其 grant-bound refresh family。
        Err(RefreshError::Invalid | RefreshError::Replayed | RefreshError::Expired) => {
            httpserve::error::unauthenticated(request_id)
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %tenant_log,
                contract_id = REFRESH_HTTP_SPEC.route.contract_id(),
                operation = "refresh",
                "identity refresh failed"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

struct AuthSubjectContext {
    tenant: TenantId,
    subject: String,
    kind: vocab::PrincipalKind,
    projection: ResourceProjection,
}

struct AuthUserContext {
    tenant: TenantId,
    user_id: ids::UserId,
    kind: vocab::PrincipalKind,
}

#[derive(Clone)]
struct ContractAuthorizer {
    roles: Arc<DynRoleReadRepo<'static>>,
    binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
    policies: Arc<DynPolicyRepo<'static>>,
    resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
    clock: Arc<dyn Clock>,
}

enum ContractAuthPolicy {
    SelfScoped,
    RolePermission(RoutePermissionId),
}

fn permission_from_request(
    request: &RouteAuthorizationRequest,
    spec: &HttpSpec,
) -> Result<RoutePermissionId, AuthReject> {
    let HttpRouteAuth::Permission(expected) = spec.route.auth() else {
        return Err(AuthReject::Forbidden);
    };
    if request.permission == expected {
        Ok(request.permission)
    } else {
        Err(AuthReject::Forbidden)
    }
}

fn builtin_admin_permission(contract_id: &'static str, permission: RoutePermissionId) -> bool {
    [
        SETTINGS_CONFIG_HTTP_SPEC,
        SETTINGS_SECRET_HTTP_SPEC,
        SETTINGS_CONFIG_GET_HTTP_SPEC,
        SETTINGS_CONFIG_DELETE_HTTP_SPEC,
        SETTINGS_CONFIG_ROLLBACK_HTTP_SPEC,
    ]
    .iter()
    .any(|spec| {
        spec.route.contract_id() == contract_id
            && spec.route.auth() == HttpRouteAuth::Permission(permission)
    })
}

fn policy_management_permission_for(target_permission: RoutePermissionId) -> GrantPermission {
    GrantPermission::policy_manage(target_permission)
}

fn policy_management_permission(scope: &PolicyRouteScope) -> GrantPermission {
    policy_management_permission_for(scope.permission())
}

fn contract_auth_policy(
    request: &RouteAuthorizationRequest,
) -> Result<ContractAuthPolicy, AuthReject> {
    for spec in [PROFILE_HTTP_SPEC, PASSWORD_CHANGE_HTTP_SPEC] {
        if request.contract_id == spec.route.contract_id() {
            permission_from_request(request, &spec)?;
            return Ok(ContractAuthPolicy::SelfScoped);
        }
    }
    for spec in [
        ACCOUNT_STATUS_SET_HTTP_SPEC,
        ACCOUNT_STATUS_GET_HTTP_SPEC,
        LOGOUT_HTTP_SPEC,
        LOGOUT_ALL_HTTP_SPEC,
        ROLES_ASSIGN_HTTP_SPEC,
        ROLES_LIST_HTTP_SPEC,
        ROLES_REVOKE_HTTP_SPEC,
        POLICIES_CREATE_HTTP_SPEC,
        POLICIES_UPDATE_HTTP_SPEC,
        POLICIES_DEACTIVATE_HTTP_SPEC,
        POLICIES_GET_HTTP_SPEC,
        POLICIES_LIST_HTTP_SPEC,
        RUNTIME_INVENTORY_HTTP_SPEC,
    ] {
        if request.contract_id == spec.route.contract_id() {
            return permission_from_request(request, &spec).map(ContractAuthPolicy::RolePermission);
        }
    }
    Ok(ContractAuthPolicy::RolePermission(request.permission))
}

impl ContractAuthorizer {
    fn new(
        roles: Arc<DynRoleReadRepo<'static>>,
        binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
        policies: Arc<DynPolicyRepo<'static>>,
        resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
            clock,
        }
    }

    async fn authorize_request(
        &self,
        request: &RouteAuthorizationRequest,
    ) -> Result<RouteAuthorizationDecision, AuthReject> {
        let ctx = AuthSubjectContext {
            tenant: request.tenant_id.ok_or(AuthReject::Forbidden)?,
            subject: request.principal_id.clone(),
            kind: request.principal_kind,
            projection: ResourceProjection::default_masked(),
        };
        let policy = contract_auth_policy(request)?;
        match self.authorize_durable_policy(&ctx, request).await? {
            PolicyEvaluation::Deny => return Err(AuthReject::Forbidden),
            PolicyEvaluation::Allow(obligations) => {
                return projection_decision_from_obligations(request, &obligations);
            }
            PolicyEvaluation::NoMatch => {}
        }
        match policy {
            ContractAuthPolicy::SelfScoped => {
                if matches!(
                    ctx.kind,
                    vocab::PrincipalKind::User | vocab::PrincipalKind::Admin
                ) && request
                    .resource
                    .as_ref()
                    .is_some_and(|resource| resource.id() == ctx.subject)
                {
                    let fields = self
                        .projection_fields_for_subject(
                            &ctx,
                            request.contract_id,
                            request.permission,
                        )
                        .await?;
                    Ok(projection_decision_from_fields(&fields))
                } else {
                    Err(AuthReject::Forbidden)
                }
            }
            ContractAuthPolicy::RolePermission(permission) => {
                self.authorize_role_permission(&ctx, request.contract_id, permission)
                    .await
            }
        }
    }

    async fn role_grant_permissions_for_subject(
        &self,
        ctx: &AuthSubjectContext,
        contract_id: &'static str,
    ) -> Result<Vec<GrantPermission>, AuthReject> {
        let tenant_scope = tenant_repo_scope(ctx.tenant);
        let bindings = self
            .binding_reads
            .list_for_subject(tenant_scope, ctx.subject.clone())
            .await
            .map_err(|err| {
                tracing::warn!(
                    error = %err,
                    error_chain = %secure::redact_error(&err),
                    tenant_id = %ctx.tenant,
                    contract_id,
                    "identity contract authorizer binding lookup failed"
                );
                AuthReject::Forbidden
            })?;

        let role_ids = bindings
            .into_iter()
            .filter(|binding| binding.tenant() == ctx.tenant && binding.subject() == ctx.subject)
            .map(|binding| binding.role_id().clone())
            .collect::<Vec<_>>();

        let mut permissions = Vec::new();
        for role_id in role_ids {
            let role = self
                .roles
                .find(tenant_scope, role_id)
                .await
                .map_err(|err| {
                    tracing::warn!(
                        error = %err,
                        error_chain = %secure::redact_error(&err),
                        tenant_id = %ctx.tenant,
                        contract_id,
                        "identity contract authorizer role lookup failed"
                    );
                    AuthReject::Forbidden
                })?;
            if let Some(role) = role {
                permissions.extend(role.grant_permissions().iter().copied());
            }
        }
        Ok(permissions)
    }

    async fn projection_fields_for_subject(
        &self,
        ctx: &AuthSubjectContext,
        contract_id: &'static str,
        permission: RoutePermissionId,
    ) -> Result<Vec<ProjectionField>, AuthReject> {
        let role_permissions = self
            .role_grant_permissions_for_subject(ctx, contract_id)
            .await?;
        Ok(projection_fields_from_permissions(
            contract_id,
            permission,
            &role_permissions,
        ))
    }

    async fn authorize_durable_policy(
        &self,
        ctx: &AuthSubjectContext,
        request: &RouteAuthorizationRequest,
    ) -> Result<PolicyEvaluation, AuthReject> {
        let scope = PolicyRouteScope::parse(request.contract_id, request.permission.as_str())
            .map_err(|_| AuthReject::Forbidden)?;
        let tenant_scope = tenant_repo_scope(ctx.tenant);
        let now = self.clock.now();
        let policies = self
            .policies
            .list_effective(tenant_scope, scope.clone(), now)
            .await
            .map_err(|err| {
                tracing::warn!(
                    error = %err,
                    error_chain = %secure::redact_error(&err),
                    tenant_id = %ctx.tenant,
                    contract_id = request.contract_id,
                    "identity contract authorizer policy lookup failed"
                );
                AuthReject::Forbidden
            })?;
        let mut attrs = route_policy_attributes(ctx, request)?;
        let required_keys = required_resource_attribute_keys(&policies)?;
        if !required_keys.is_empty() {
            attrs.extend(
                self.resolve_resource_policy_attributes(ctx, request, scope, required_keys, now)
                    .await?,
            );
        }
        Ok(evaluate_policies_for_tenant(
            Some(ctx.tenant),
            &attrs,
            &policies,
        ))
    }

    async fn resolve_resource_policy_attributes(
        &self,
        ctx: &AuthSubjectContext,
        request: &RouteAuthorizationRequest,
        scope: PolicyRouteScope,
        required_keys: Vec<ResourceAttributeKey>,
        now: SystemTime,
    ) -> Result<Vec<AbacAttribute>, AuthReject> {
        let resource_id = request_resource_attribute_id(ctx, request)?;
        let tenant_scope = tenant_repo_scope(ctx.tenant);
        let resolved = self
            .resource_attribute_reads
            .resolve_effective(
                tenant_scope,
                scope.clone(),
                resource_id.clone(),
                required_keys.clone(),
                now,
            )
            .await
            .map_err(|err| {
                tracing::warn!(
                    error = %err,
                    error_chain = %secure::redact_error(&err),
                    tenant_id = %ctx.tenant,
                    contract_id = request.contract_id,
                    permission = %request.permission,
                    "identity contract authorizer resource attribute lookup failed"
                );
                AuthReject::Forbidden
            })?;
        match resolved {
            ResourceAttributeResolution::Known(attrs) => known_resource_attributes_to_abac(
                ctx,
                request,
                &scope,
                &resource_id,
                &required_keys,
                attrs,
            ),
            ResourceAttributeResolution::Missing(key) => {
                log_resource_attribute_resolution_failure(ctx, request, &key, "missing");
                Err(AuthReject::Forbidden)
            }
            ResourceAttributeResolution::Stale(key) => {
                log_resource_attribute_resolution_failure(ctx, request, &key, "stale");
                Err(AuthReject::Forbidden)
            }
        }
    }

    async fn authorize_role_permission(
        &self,
        ctx: &AuthSubjectContext,
        contract_id: &'static str,
        permission: RoutePermissionId,
    ) -> Result<RouteAuthorizationDecision, AuthReject> {
        if ctx.kind == vocab::PrincipalKind::SuperAdmin
            && projection_enabled_route(contract_id, permission)
        {
            return Ok(RouteAuthorizationDecision::Allow);
        }
        let runtime_inventory_rss_user = ctx.kind == vocab::PrincipalKind::User
            && contract_id == RUNTIME_INVENTORY_HTTP_SPEC.route.contract_id()
            && RUNTIME_INVENTORY_HTTP_SPEC.route.auth() == HttpRouteAuth::Permission(permission);
        let rss_user_session_logout = ctx.kind == vocab::PrincipalKind::User
            && matches!(
                (contract_id, permission),
                (
                    "identity.logout",
                    RoutePermissionId::IdentitySessionLogoutCurrent
                ) | (
                    "identity.logout-all",
                    RoutePermissionId::IdentitySessionLogoutAll
                )
            );
        let rss_user_account_status = ctx.kind == vocab::PrincipalKind::User
            && [ACCOUNT_STATUS_GET_HTTP_SPEC, ACCOUNT_STATUS_SET_HTTP_SPEC]
                .iter()
                .any(|spec| {
                    spec.route.contract_id() == contract_id
                        && spec.route.auth() == HttpRouteAuth::Permission(permission)
                });
        if ctx.kind != vocab::PrincipalKind::Admin
            && !runtime_inventory_rss_user
            && !rss_user_session_logout
            && !rss_user_account_status
        {
            return Err(AuthReject::Forbidden);
        }
        if builtin_admin_permission(contract_id, permission) {
            return Ok(RouteAuthorizationDecision::Allow);
        }
        let role_permissions = self
            .role_grant_permissions_for_subject(ctx, contract_id)
            .await?;
        let has_permission = role_permissions
            .iter()
            .any(|role_permission| role_permission.matches_route(permission));
        if has_permission {
            let fields =
                projection_fields_from_permissions(contract_id, permission, &role_permissions);
            Ok(projection_decision_from_fields(&fields))
        } else {
            Err(AuthReject::Forbidden)
        }
    }

    async fn authorize_policy_scope_management(
        &self,
        auth: &AuthUserContext,
        scope: &PolicyRouteScope,
    ) -> Result<(), AuthReject> {
        if auth.kind != vocab::PrincipalKind::Admin {
            return Err(AuthReject::Forbidden);
        }
        let required = policy_management_permission(scope);
        let subject = auth.user_id.as_uuid().hyphenated().to_string();
        let tenant_scope = tenant_repo_scope(auth.tenant);
        let bindings = self
            .binding_reads
            .list_for_subject(tenant_scope, subject.clone())
            .await
            .map_err(|err| {
                tracing::warn!(
                    error = %err,
                    error_chain = %secure::redact_error(&err),
                    tenant_id = %auth.tenant,
                    target_contract_id = scope.contract_id(),
                    target_permission = %scope.permission(),
                    "identity policy management binding lookup failed"
                );
                AuthReject::Forbidden
            })?;

        let role_ids = bindings
            .into_iter()
            .filter(|binding| binding.tenant() == auth.tenant && binding.subject() == subject)
            .map(|binding| binding.role_id().clone())
            .collect::<Vec<_>>();

        for role_id in role_ids {
            let role = self
                .roles
                .find(tenant_scope, role_id)
                .await
                .map_err(|err| {
                    tracing::warn!(
                        error = %err,
                        error_chain = %secure::redact_error(&err),
                        tenant_id = %auth.tenant,
                        target_contract_id = scope.contract_id(),
                        target_permission = %scope.permission(),
                        "identity policy management role lookup failed"
                    );
                    AuthReject::Forbidden
                })?;
            if role.is_some_and(|role| role.grant_permissions().contains(&required)) {
                return Ok(());
            }
        }
        Err(AuthReject::Forbidden)
    }
}

fn projection_spec(
    contract_id: &'static str,
    permission: RoutePermissionId,
) -> Option<&'static HttpSpec> {
    HTTP_SPECS.iter().find(|spec| {
        spec.route.contract_id() == contract_id
            && spec.route.auth() == HttpRouteAuth::Permission(permission)
            && !spec.projection_fields.is_empty()
    })
}

fn projection_enabled_route(contract_id: &'static str, permission: RoutePermissionId) -> bool {
    projection_spec(contract_id, permission).is_some()
}

fn projection_field_from_permission(
    contract_id: &'static str,
    permission: RoutePermissionId,
    grant: GrantPermission,
    fields: &mut Vec<ProjectionField>,
) {
    let Some(field_permission) = grant.as_route() else {
        return;
    };
    let Some(spec) = projection_spec(contract_id, permission) else {
        return;
    };
    let field = spec
        .projection_fields
        .iter()
        .find(|field| field.permission == field_permission)
        .map(|field| field.field);
    if let Some(field) = field
        && !fields.contains(&field)
    {
        fields.push(field);
    }
}

fn projection_fields_from_permissions(
    contract_id: &'static str,
    permission: RoutePermissionId,
    role_permissions: &[GrantPermission],
) -> Vec<ProjectionField> {
    let mut fields = Vec::new();
    if projection_enabled_route(contract_id, permission) {
        for role_permission in role_permissions {
            projection_field_from_permission(
                contract_id,
                permission,
                *role_permission,
                &mut fields,
            );
        }
    }
    fields
}

fn projection_decision_from_obligations(
    request: &RouteAuthorizationRequest,
    obligations: &PolicyObligations,
) -> Result<RouteAuthorizationDecision, AuthReject> {
    if obligations.row_scope().is_some() {
        return Err(AuthReject::Forbidden);
    }
    if !obligations.field_mask().is_empty()
        && !projection_enabled_route(request.contract_id, request.permission)
    {
        return Err(AuthReject::Forbidden);
    }
    let mut fields = Vec::new();
    for key in obligations.field_mask() {
        let Some(field) = projection_field_from_obligation_key(request, key.as_str()) else {
            return Err(AuthReject::Forbidden);
        };
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    Ok(projection_decision_from_fields(&fields))
}

fn projection_field_from_obligation_key(
    request: &RouteAuthorizationRequest,
    key: &str,
) -> Option<ProjectionField> {
    projection_spec(request.contract_id, request.permission)?
        .projection_fields
        .iter()
        .find(|field| field.obligation_key == key)
        .map(|field| field.field)
}

fn projection_decision_from_fields(fields: &[ProjectionField]) -> RouteAuthorizationDecision {
    if fields.is_empty() {
        RouteAuthorizationDecision::Allow
    } else {
        RouteAuthorizationDecision::allow_with_unmasked_fields(fields)
    }
}

fn route_policy_attributes(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
) -> Result<Vec<AbacAttribute>, AuthReject> {
    // fail-closed：任一 PIP 属性超长 → Forbidden（不注入半截 attrs，避免 Like/glob_match DoS）
    let mut attrs = vec![
        policy_attr(
            POLICY_ATTR_PRINCIPAL_KIND,
            ctx.kind.as_actor_metadata_label(),
        )?,
        policy_attr(POLICY_ATTR_PRINCIPAL_ID, &ctx.subject)?,
        policy_attr(POLICY_ATTR_TENANT_ID, &ctx.tenant.to_string())?,
        policy_attr(POLICY_ATTR_CONTRACT_ID, request.contract_id)?,
        policy_attr(POLICY_ATTR_PERMISSION, request.permission.as_str())?,
    ];
    if let Some(resource) = request.resource.as_ref() {
        attrs.push(policy_attr(POLICY_ATTR_RESOURCE_ID, resource.id())?);
    }
    Ok(attrs)
}

fn required_resource_attribute_keys(
    policies: &[Policy],
) -> Result<Vec<ResourceAttributeKey>, AuthReject> {
    let mut keys = Vec::new();
    for policy in policies {
        for rule in policy.rules() {
            collect_resource_attribute_key(rule.attribute_key(), &mut keys)?;
        }
    }
    Ok(keys)
}

fn collect_resource_attribute_key(
    key: &AttributeKey,
    keys: &mut Vec<ResourceAttributeKey>,
) -> Result<(), AuthReject> {
    let Some(parsed) = ResourcePolicyAttributeKey::classify(key)
        .map_err(|_| AuthReject::Forbidden)?
        .into_dynamic()
    else {
        return Ok(());
    };
    if !keys.iter().any(|existing| existing == &parsed) {
        keys.push(parsed);
    }
    Ok(())
}

fn request_resource_attribute_id(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
) -> Result<ResourceAttributeResourceId, AuthReject> {
    request_resource_attribute_id_in(ctx, request, HTTP_SPECS)
}

fn request_resource_attribute_id_in(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
    specs: &[HttpSpec],
) -> Result<ResourceAttributeResourceId, AuthReject> {
    if route_resource_sharing_is_global_in(request, specs) {
        tracing::warn!(
            tenant_id = %ctx.tenant,
            contract_id = request.contract_id,
            permission = %request.permission,
            "identity contract authorizer rejects dynamic resource attributes on global resource route"
        );
        return Err(AuthReject::Forbidden);
    }
    let Some(resource) = request.resource.as_ref() else {
        tracing::warn!(
            tenant_id = %ctx.tenant,
            contract_id = request.contract_id,
            permission = %request.permission,
            "identity contract authorizer resource attributes required without route resource"
        );
        return Err(AuthReject::Forbidden);
    };
    ResourceAttributeResourceId::parse(resource.id()).map_err(|_| AuthReject::Forbidden)
}

fn known_resource_attributes_to_abac(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
    scope: &PolicyRouteScope,
    resource_id: &ResourceAttributeResourceId,
    required_keys: &[ResourceAttributeKey],
    attrs: Vec<crate::domain::ResourceAttribute>,
) -> Result<Vec<AbacAttribute>, AuthReject> {
    let mut seen = Vec::with_capacity(attrs.len());
    let mut out = Vec::with_capacity(attrs.len());
    for attr in attrs {
        if attr.tenant() != ctx.tenant
            || attr.route_scope() != scope
            || attr.resource_id() != resource_id
        {
            log_resource_attribute_known_invalid(ctx, request, attr.key(), "scope-mismatch");
            return Err(AuthReject::Forbidden);
        }
        if !required_keys.iter().any(|required| required == attr.key()) {
            log_resource_attribute_known_invalid(ctx, request, attr.key(), "unexpected-key");
            return Err(AuthReject::Forbidden);
        }
        if seen.iter().any(|existing| existing == attr.key()) {
            log_resource_attribute_known_invalid(ctx, request, attr.key(), "duplicate-key");
            return Err(AuthReject::Forbidden);
        }
        seen.push(attr.key().clone());
        out.push(attr.to_abac_attribute());
    }
    for key in required_keys {
        if !seen.iter().any(|seen_key| seen_key == key) {
            log_resource_attribute_resolution_failure(ctx, request, key, "missing");
            return Err(AuthReject::Forbidden);
        }
    }
    Ok(out)
}

fn log_resource_attribute_resolution_failure(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
    key: &ResourceAttributeKey,
    reason: &'static str,
) {
    tracing::warn!(
        tenant_id = %ctx.tenant,
        contract_id = request.contract_id,
        permission = %request.permission,
        attribute_key = key.as_str(),
        reason,
        "identity contract authorizer resource attribute resolution failed"
    );
}

fn log_resource_attribute_known_invalid(
    ctx: &AuthSubjectContext,
    request: &RouteAuthorizationRequest,
    key: &ResourceAttributeKey,
    reason: &'static str,
) {
    tracing::warn!(
        tenant_id = %ctx.tenant,
        contract_id = request.contract_id,
        permission = %request.permission,
        attribute_key = key.as_str(),
        reason,
        "identity contract authorizer resource attribute repo returned invalid known set"
    );
}

fn route_resource_sharing_is_global_in(
    request: &RouteAuthorizationRequest,
    specs: &[HttpSpec],
) -> bool {
    specs.iter().any(|spec| {
        spec.route.contract_id() == request.contract_id
            && spec.route.auth() == HttpRouteAuth::Permission(request.permission)
            && spec.resource_sharing.mode == HttpResourceSharingMode::Global
    })
}

fn policy_attr(key: &str, value: &str) -> Result<AbacAttribute, AuthReject> {
    let value = AttributeValue::parse(value).map_err(|_| AuthReject::Forbidden)?;
    Ok(AbacAttribute::new(AttributeKey::new(key), value))
}

impl RouteAuthorizer for ContractAuthorizer {
    fn authorize<'a>(
        &'a self,
        request: RouteAuthorizationRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = RouteAuthorizationDecision> + Send + 'a>>
    {
        Box::pin(async move {
            match self.authorize_request(&request).await {
                Ok(decision) => decision,
                Err(_) => RouteAuthorizationDecision::Deny,
            }
        })
    }
}

#[derive(Clone)]
struct RbacHandlerState {
    service: Arc<RbacAdminService>,
}

#[derive(Clone)]
struct PolicyManageHandlerState {
    service: Arc<PolicyManageService>,
    authorizer: Arc<ContractAuthorizer>,
}

#[derive(Clone)]
struct CredentialSecurityHandlerState {
    service: Arc<CredentialSecurityService>,
}

#[derive(Clone)]
struct AccountStatusQueryHandlerState {
    query: AccountStatusQueryService,
}

impl httpserve::ClassifiedRouteState for AccountStatusQueryHandlerState {
    type Effect = diport::AuthEffect;
    type Privilege = diport::LocalPrivilege;
}

#[derive(Clone)]
struct RolesListHandlerState {
    roles: Arc<DynRoleReadRepo<'static>>,
}

impl httpserve::ClassifiedRouteState for RolesListHandlerState {
    type Effect = diport::ReadEffect;
    type Privilege = diport::LocalPrivilege;
}

/// 认证拒因（small；避免 `Result<_, Response>` 触 clippy `result_large_err`）。
enum AuthReject {
    Unauthenticated,
    Forbidden,
}

impl AuthReject {
    fn into_response(self, request_id: &str) -> Response {
        match self {
            Self::Unauthenticated => httpserve::error::unauthenticated(request_id),
            Self::Forbidden => httpserve::error::forbidden(request_id),
        }
    }
}

fn profile_kind_wire(kind: vocab::PrincipalKind) -> Result<IdentityProfileDataKind, AuthReject> {
    match kind {
        vocab::PrincipalKind::User => Ok(IdentityProfileDataKind::User),
        vocab::PrincipalKind::Device => Ok(IdentityProfileDataKind::Device),
        vocab::PrincipalKind::Admin => Ok(IdentityProfileDataKind::Admin),
        vocab::PrincipalKind::SuperAdmin => Ok(IdentityProfileDataKind::SuperAdmin),
        vocab::PrincipalKind::Service => Ok(IdentityProfileDataKind::Service),
        vocab::PrincipalKind::Anonymous => Ok(IdentityProfileDataKind::Anonymous),
        _ => Err(AuthReject::Forbidden),
    }
}

fn authenticated_subject_context(req: &Request<Body>) -> Result<AuthSubjectContext, AuthReject> {
    let auth = req
        .extensions()
        .get::<AuthorizedSubject>()
        .ok_or(AuthReject::Unauthenticated)?;
    Ok(AuthSubjectContext {
        tenant: auth.tenant_id(),
        subject: auth.principal_id().to_string(),
        kind: auth.principal_kind(),
        projection: auth.projection(),
    })
}

fn current_user_grant_context(req: &Request<Body>) -> Result<CurrentAuthGrant, AuthReject> {
    let subject = req
        .extensions()
        .get::<AuthorizedSubject>()
        .ok_or(AuthReject::Unauthenticated)?;
    if subject.principal_kind() != vocab::PrincipalKind::User {
        return Err(AuthReject::Forbidden);
    }
    let evidence = req
        .extensions()
        .get::<CurrentAuthGrant>()
        .cloned()
        .ok_or(AuthReject::Unauthenticated)?;
    if !evidence.binds_principal(subject.tenant_id(), subject.principal_id()) {
        return Err(AuthReject::Unauthenticated);
    }
    Ok(evidence)
}

fn logout_current_grant_context(
    _marker: &ProducerMarker<::generated::http::identity_v1::logout::RouteMarker>,
    req: &Request<Body>,
) -> Result<CurrentAuthGrant, AuthReject> {
    current_user_grant_context(req)
}

fn logout_all_grant_context(
    _marker: &ProducerMarker<::generated::http::identity_v1::logout_all::RouteMarker>,
    req: &Request<Body>,
) -> Result<CurrentAuthGrant, AuthReject> {
    current_user_grant_context(req)
}

fn authorized_user_context(ctx: AuthSubjectContext) -> Result<AuthUserContext, AuthReject> {
    let user_id = ids::UserId::parse(&ctx.subject).map_err(|_| AuthReject::Forbidden)?;
    Ok(AuthUserContext {
        tenant: ctx.tenant,
        user_id,
        kind: ctx.kind,
    })
}

async fn body_bytes(req: Request<Body>, request_id: &str) -> Result<Bytes, Response> {
    let (_, body) = req.into_parts();
    to_bytes(body, MAX_LOGIN_BODY_BYTES)
        .await
        .map_err(|_| httpserve::error::validation_bad_request(request_id))
}

fn core_response(kind: CoreErrorKind, request_id: &str) -> Response {
    httpserve::error::core_error_response(&CoreError::new(kind), request_id)
}

fn fact_conflict_response(request_id: &str) -> Response {
    core_response(CoreErrorKind::OutboxFactConflict, request_id)
}

fn role_id_from_wire(raw: &str) -> Result<RoleId, ()> {
    RoleId::parse(raw).map_err(|_| ())
}

fn decode_role_cursor(raw: &str) -> Result<RoleId, ()> {
    let cursor = vocab::Cursor::parse(raw).map_err(|_| ())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| ())?;
    let decoded = std::str::from_utf8(&bytes).map_err(|_| ())?;
    role_id_from_wire(decoded)
}

fn encode_role_cursor(role_id: &RoleId) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(role_id.as_str().as_bytes())
}

fn policy_id_from_wire(raw: &str) -> Result<PolicyId, ()> {
    policy_manage::policy_id_from_wire(raw).map_err(|_| ())
}

fn decode_policy_cursor(raw: &str) -> Result<PolicyId, ()> {
    let cursor = vocab::Cursor::parse(raw).map_err(|_| ())?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.as_str())
        .map_err(|_| ())?;
    let decoded = std::str::from_utf8(&bytes).map_err(|_| ())?;
    policy_id_from_wire(decoded)
}

fn encode_policy_cursor(policy_id: &PolicyId) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy_id.as_str().as_bytes())
}

async fn roles_assign_handler(
    marker: ProducerMarker<::generated::http::identity_v1::roles_assign::RouteMarker>,
    State(state): State<RbacHandlerState>,
    Path(role_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let request: IdentityRolesAssignRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let role_id = match role_id_from_wire(&role_id_raw) {
        Ok(role_id) => role_id,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    if request.subject.is_empty() {
        return httpserve::error::validation_bad_request(&request_id);
    }
    match state
        .service
        .assign_role(
            marker.into_receipt(),
            auth.tenant,
            auth.user_id,
            auth.kind,
            request.subject,
            role_id,
        )
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(IdentityRolesAssignResponse {
                data: IdentityRolesAssignData { assigned: true },
            }),
        )
            .into_response(),
        Err(err) => rbac_error_response(&err, auth.tenant, &request_id, &ROLES_ASSIGN_HTTP_SPEC),
    }
}

async fn roles_revoke_handler(
    marker: ProducerMarker<::generated::http::identity_v1::roles_revoke::RouteMarker>,
    State(state): State<RbacHandlerState>,
    Path((role_id_raw, subject_raw)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let role_id = match role_id_from_wire(&role_id_raw) {
        Ok(role_id) => role_id,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    if subject_raw.is_empty() {
        return httpserve::error::validation_bad_request(&request_id);
    }
    match state
        .service
        .revoke_role(
            marker.into_receipt(),
            auth.tenant,
            auth.user_id,
            auth.kind,
            role_id,
            subject_raw,
        )
        .await
    {
        Ok(revoked) => (
            StatusCode::OK,
            Json(IdentityRolesRevokeResponse {
                data: IdentityRolesRevokeData { revoked },
            }),
        )
            .into_response(),
        Err(err) => rbac_error_response(&err, auth.tenant, &request_id, &ROLES_REVOKE_HTTP_SPEC),
    }
}

async fn roles_list_handler(
    _: ContractMarker<::generated::http::identity_v1::roles_list::RouteMarker>,
    State(state): State<RolesListHandlerState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = subject;
    let request = match Query::<IdentityRolesListRequest>::try_from_uri(req.uri()) {
        Ok(Query(request)) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let limit = match u16::try_from(request.limit.get())
        .ok()
        .and_then(|limit| vocab::Limit::new(limit).ok())
    {
        Some(limit) => limit,
        None => return httpserve::error::validation_bad_request(&request_id),
    };
    let after = match request
        .cursor
        .as_deref()
        .map(decode_role_cursor)
        .transpose()
    {
        Ok(after) => after,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    let tenant_scope = tenant_repo_scope(auth.tenant);
    let result = match state
        .roles
        .list(tenant_scope, RolePage { limit, after })
        .await
    {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %auth.tenant,
                contract_id = ROLES_LIST_HTTP_SPEC.route.contract_id(),
                operation = "roles_list",
                "identity roles list failed"
            );
            return core_response(CoreErrorKind::Internal, &request_id);
        }
    };
    let next_cursor = if result.has_more {
        result
            .roles
            .last()
            .map(|role| encode_role_cursor(role.id()))
    } else {
        None
    };
    let data = result
        .roles
        .into_iter()
        .map(|role| IdentityRoleView {
            role_id: role.id().as_str().to_string(),
            name: role.name().to_string(),
            permissions: role.permission_ids().collect(),
        })
        .collect();
    (
        StatusCode::OK,
        Json(IdentityRolesListResponse {
            data,
            next_cursor,
            has_more: result.has_more,
        }),
    )
        .into_response()
}

async fn policies_create_handler(
    marker: ProducerMarker<::generated::http::identity_v1::policies_create::RouteMarker>,
    State(state): State<PolicyManageHandlerState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let request: IdentityPoliciesCreateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let draft = match policy_manage::PolicyCreateDraft::try_from(request) {
        Ok(draft) => draft,
        Err(err) => {
            return policy_error_response(
                &err,
                auth.tenant,
                &request_id,
                &POLICIES_CREATE_HTTP_SPEC,
            );
        }
    };
    if let Err(reject) = state
        .authorizer
        .authorize_policy_scope_management(&auth, draft.target_scope())
        .await
    {
        return reject.into_response(&request_id);
    }
    match state
        .service
        .create_policy(
            marker.into_receipt(),
            auth.tenant,
            auth.user_id,
            auth.kind,
            draft,
        )
        .await
        .and_then(|policy| policy_manage::create_response(&policy))
    {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(err) => {
            policy_error_response(&err, auth.tenant, &request_id, &POLICIES_CREATE_HTTP_SPEC)
        }
    }
}

async fn policies_update_handler(
    marker: ProducerMarker<::generated::http::identity_v1::policies_update::RouteMarker>,
    State(state): State<PolicyManageHandlerState>,
    Path(policy_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let policy_id = match policy_id_from_wire(&policy_id_raw) {
        Ok(policy_id) => policy_id,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let request: IdentityPoliciesUpdateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let draft = match policy_manage::PolicyUpdateDraft::try_from_wire(policy_id, request) {
        Ok(draft) => draft,
        Err(err) => {
            return policy_error_response(
                &err,
                auth.tenant,
                &request_id,
                &POLICIES_UPDATE_HTTP_SPEC,
            );
        }
    };
    let current = match state
        .service
        .find_policy_for_management(auth.tenant, draft.policy_id().clone())
        .await
    {
        Ok(policy) => policy,
        Err(err) => {
            return policy_error_response(
                &err,
                auth.tenant,
                &request_id,
                &POLICIES_UPDATE_HTTP_SPEC,
            );
        }
    };
    for scope in [current.route_scope(), draft.target_scope()] {
        if let Err(reject) = state
            .authorizer
            .authorize_policy_scope_management(&auth, scope)
            .await
        {
            return reject.into_response(&request_id);
        }
    }
    match state
        .service
        .update_policy(
            marker.into_receipt(),
            auth.tenant,
            auth.user_id,
            auth.kind,
            draft,
        )
        .await
        .and_then(|policy| policy_manage::update_response(&policy))
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            policy_error_response(&err, auth.tenant, &request_id, &POLICIES_UPDATE_HTTP_SPEC)
        }
    }
}

async fn policies_deactivate_handler(
    marker: ProducerMarker<::generated::http::identity_v1::policies_deactivate::RouteMarker>,
    State(state): State<PolicyManageHandlerState>,
    Path(policy_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let policy_id = match policy_id_from_wire(&policy_id_raw) {
        Ok(policy_id) => policy_id,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let request: IdentityPoliciesDeactivateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let draft = match policy_manage::PolicyDeactivateDraft::try_from_wire(policy_id, request) {
        Ok(draft) => draft,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let current = match state
        .service
        .find_policy_for_management(auth.tenant, draft.policy_id().clone())
        .await
    {
        Ok(policy) => policy,
        Err(err) => {
            return policy_error_response(
                &err,
                auth.tenant,
                &request_id,
                &POLICIES_DEACTIVATE_HTTP_SPEC,
            );
        }
    };
    if let Err(reject) = state
        .authorizer
        .authorize_policy_scope_management(&auth, current.route_scope())
        .await
    {
        return reject.into_response(&request_id);
    }
    match state
        .service
        .deactivate_policy(
            marker.into_receipt(),
            auth.tenant,
            auth.user_id,
            auth.kind,
            draft,
        )
        .await
        .and_then(policy_manage::deactivate_response)
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => policy_error_response(
            &err,
            auth.tenant,
            &request_id,
            &POLICIES_DEACTIVATE_HTTP_SPEC,
        ),
    }
}

async fn policies_get_handler(
    _: ContractMarker<::generated::http::identity_v1::policies_get::RouteMarker>,
    State(query): State<PolicyQueryService>,
    Path(policy_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let policy_id = match policy_id_from_wire(&policy_id_raw) {
        Ok(policy_id) => policy_id,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    match query
        .get_policy(subject.tenant, policy_id)
        .await
        .and_then(|policy| policy_manage::get_response(&policy))
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            policy_error_response(&err, subject.tenant, &request_id, &POLICIES_GET_HTTP_SPEC)
        }
    }
}

async fn policies_list_handler(
    _: ContractMarker<::generated::http::identity_v1::policies_list::RouteMarker>,
    State(query): State<PolicyQueryService>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let request = match Query::<IdentityPoliciesListRequest>::try_from_uri(req.uri()) {
        Ok(Query(request)) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let limit = match u16::try_from(request.limit.get())
        .ok()
        .and_then(|limit| vocab::Limit::new(limit).ok())
    {
        Some(limit) => limit,
        None => return httpserve::error::validation_bad_request(&request_id),
    };
    let after = match request
        .cursor
        .as_deref()
        .map(decode_policy_cursor)
        .transpose()
    {
        Ok(after) => after,
        Err(()) => return httpserve::error::validation_bad_request(&request_id),
    };
    let result = match query
        .list_policies(subject.tenant, PolicyPage { limit, after })
        .await
    {
        Ok(result) => result,
        Err(err) => {
            return policy_error_response(
                &err,
                subject.tenant,
                &request_id,
                &POLICIES_LIST_HTTP_SPEC,
            );
        }
    };
    let next_cursor = if result.has_more {
        result
            .policies
            .last()
            .map(|policy| encode_policy_cursor(policy.id()))
    } else {
        None
    };
    match policy_manage::list_response(result.policies, result.has_more, next_cursor) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            policy_error_response(&err, subject.tenant, &request_id, &POLICIES_LIST_HTTP_SPEC)
        }
    }
}

async fn profile_handler(
    _: ContractMarker<::generated::http::identity_v1::profile::RouteMarker>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = subject;
    let kind = match profile_kind_wire(auth.kind) {
        Ok(kind) => kind,
        Err(reject) => return reject.into_response(&request_id),
    };
    (
        StatusCode::OK,
        Json(IdentityProfileResponse {
            data: IdentityProfileData {
                subject: auth.projection.render(
                    vocab::ProjectionField::IdentityProfileSubject,
                    &auth.subject,
                ),
                tenant_id: auth.projection.render(
                    vocab::ProjectionField::IdentityProfileTenantId,
                    &auth.tenant.to_string(),
                ),
                kind,
            },
        }),
    )
        .into_response()
}

async fn password_change_handler(
    marker: ProducerMarker<::generated::http::identity_v1::password_change::RouteMarker>,
    State(state): State<CredentialSecurityHandlerState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = match authorized_user_context(subject) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let request: IdentityPasswordChangeRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let prepared = match state
        .service
        .reauthenticate_password_change(
            auth.tenant,
            auth.user_id,
            secure::RawPassword::new(request.current_password),
        )
        .await
    {
        Ok(prepared) => prepared,
        Err(error) => return password_error_response(&error, auth.tenant, &request_id),
    };
    let validated = match state
        .service
        .validate_new_password(secure::RawPassword::new(request.new_password.into()))
    {
        Ok(validated) => validated,
        Err(error) => return password_error_response(&error, auth.tenant, &request_id),
    };
    match state
        .service
        .change_password(marker.into_receipt(), prepared, validated)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(IdentityPasswordChangeResponse {
                data: IdentityPasswordChangeData { changed: true },
            }),
        )
            .into_response(),
        Err(err) => password_error_response(&err, auth.tenant, &request_id),
    }
}

async fn account_status_get_handler(
    _: ContractMarker<::generated::http::identity_v1::account_status_get::RouteMarker>,
    State(state): State<AccountStatusQueryHandlerState>,
    Path(user_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let auth = match authenticated_subject_context(&req) {
        Ok(auth) => auth,
        Err(reject) => return reject.into_response(&request_id),
    };
    let user_id = match ids::UserId::parse(&user_id_raw) {
        Ok(user_id) => user_id,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    match state.query.account_status(auth.tenant, user_id).await {
        Ok(status) => {
            let status = match status {
                crate::domain::AccountStatus::Active => IdentityAccountStatusGetDataStatus::Active,
                crate::domain::AccountStatus::Suspended => {
                    IdentityAccountStatusGetDataStatus::Suspended
                }
                crate::domain::AccountStatus::Locked => IdentityAccountStatusGetDataStatus::Locked,
                crate::domain::AccountStatus::Deactivated => {
                    IdentityAccountStatusGetDataStatus::Deactivated
                }
            };
            (
                StatusCode::OK,
                Json(IdentityAccountStatusGetResponse {
                    data: IdentityAccountStatusGetData { status },
                }),
            )
                .into_response()
        }
        Err(error) => account_status_error_response(&error, auth.tenant, &request_id),
    }
}

async fn account_status_set_handler(
    marker: ProducerMarker<::generated::http::identity_v1::account_status_set::RouteMarker>,
    State(state): State<CredentialSecurityHandlerState>,
    Path(user_id_raw): Path<String>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let subject = match authenticated_subject_context(&req) {
        Ok(ctx) => ctx,
        Err(reject) => return reject.into_response(&request_id),
    };
    let auth = subject;
    let user_id = match ids::UserId::parse(&user_id_raw) {
        Ok(user_id) => user_id,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: IdentityAccountStatusSetRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    let (target, status) = match request.target_status {
        IdentityAccountStatusSetRequestTargetStatus::Active => (
            crate::domain::AccountStatus::Active,
            IdentityAccountStatusSetDataStatus::Active,
        ),
        IdentityAccountStatusSetRequestTargetStatus::Suspended => (
            crate::domain::AccountStatus::Suspended,
            IdentityAccountStatusSetDataStatus::Suspended,
        ),
        IdentityAccountStatusSetRequestTargetStatus::Locked => (
            crate::domain::AccountStatus::Locked,
            IdentityAccountStatusSetDataStatus::Locked,
        ),
        IdentityAccountStatusSetRequestTargetStatus::Deactivated => (
            crate::domain::AccountStatus::Deactivated,
            IdentityAccountStatusSetDataStatus::Deactivated,
        ),
    };
    match state
        .service
        .set_account_status(
            marker.into_receipt(),
            auth.tenant,
            user_id,
            target,
            crate::domain::CredentialSecurityInitiator::authenticated(
                auth.tenant,
                auth.kind,
                auth.subject,
            ),
        )
        .await
    {
        Ok(changed) => (
            StatusCode::OK,
            Json(IdentityAccountStatusSetResponse {
                data: IdentityAccountStatusSetData { changed, status },
            }),
        )
            .into_response(),
        Err(error) => account_status_error_response(&error, auth.tenant, &request_id),
    }
}

async fn logout_handler(
    marker: ProducerMarker<::generated::http::identity_v1::logout::RouteMarker>,
    State(state): State<CredentialSecurityHandlerState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let evidence = match logout_current_grant_context(&marker, &req) {
        Ok(evidence) => evidence,
        Err(reject) => return reject.into_response(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let _request: IdentityLogoutRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    match state
        .service
        .logout_current(marker.into_receipt(), &evidence)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(IdentityLogoutResponse {
                data: IdentityLogoutData { logged_out: true },
            }),
        )
            .into_response(),
        Err(IdentityError::VersionConflict) => {
            core_response(CoreErrorKind::VersionConflict, &request_id)
        }
        Err(IdentityError::OutboxFactConflict(_)) => fact_conflict_response(&request_id),
        Err(IdentityError::ProviderUnavailable(_)) => {
            core_response(CoreErrorKind::ProviderUnavailable, &request_id)
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %evidence.tenant_id(),
                contract_id = LOGOUT_HTTP_SPEC.route.contract_id(),
                operation = "logout",
                "identity logout failed"
            );
            core_response(CoreErrorKind::Internal, &request_id)
        }
    }
}

async fn logout_all_handler(
    marker: ProducerMarker<::generated::http::identity_v1::logout_all::RouteMarker>,
    State(state): State<CredentialSecurityHandlerState>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let evidence = match logout_all_grant_context(&marker, &req) {
        Ok(evidence) => evidence,
        Err(reject) => return reject.into_response(&request_id),
    };
    let body = match body_bytes(req, &request_id).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let _: IdentityLogoutAllRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    match state
        .service
        .logout_all(marker.into_receipt(), &evidence)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(IdentityLogoutAllResponse {
                data: IdentityLogoutAllData { logged_out: true },
            }),
        )
            .into_response(),
        Err(IdentityError::VersionConflict) => {
            core_response(CoreErrorKind::VersionConflict, &request_id)
        }
        Err(IdentityError::OutboxFactConflict(_)) => fact_conflict_response(&request_id),
        Err(IdentityError::ProviderUnavailable(_)) => {
            core_response(CoreErrorKind::ProviderUnavailable, &request_id)
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                error_chain = %secure::redact_error(&error),
                request_id,
                tenant_id = %evidence.tenant_id(),
                contract_id = LOGOUT_ALL_HTTP_SPEC.route.contract_id(),
                operation = "logout_all",
                "identity logout-all failed"
            );
            core_response(CoreErrorKind::Internal, &request_id)
        }
    }
}

/// Test-support mount for driving the production logout handler with an injected lifecycle.
///
/// This is deliberately feature-gated: adapter integration tests need the real decode/auth/service
/// path, while production composition continues to mount the handler only through `IdentityDomain`.
#[cfg(feature = "test-support")]
pub(crate) fn logout_router_for_test(
    service: Arc<CredentialSecurityService>,
    evidence: CurrentAuthGrant,
) -> axum::Router {
    axum::Router::new()
        .route(
            LOGOUT_HTTP_SPEC.route.path(),
            axum::routing::post(logout_handler)
                .with_state(CredentialSecurityHandlerState { service }),
        )
        .layer(axum::Extension(AuthorizedSubject::for_test(
            evidence.tenant_id(),
            vocab::PrincipalKind::User,
            evidence.user_id().as_uuid().hyphenated().to_string(),
            None,
        )))
        .layer(axum::Extension(evidence))
}

fn rbac_error_response(
    err: &RbacAdminError,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) -> Response {
    if matches!(
        err,
        RbacAdminError::BindingWrite(error)
            if error.kind() == OutboxEmitErrorKind::FactConflict
    ) {
        return fact_conflict_response(request_id);
    }
    let kind = match err {
        RbacAdminError::RoleNotFound => CoreErrorKind::NotFound,
        RbacAdminError::RoleLookup(_)
        | RbacAdminError::PayloadEncode(_)
        | RbacAdminError::EnvelopeIdentity(_)
        | RbacAdminError::IdempotencyKey(_)
        | RbacAdminError::WireProjection(_)
        | RbacAdminError::BindingWrite(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            error_chain = %secure::redact_error(&err),
            request_id,
            tenant_id = %tenant,
            contract_id = spec.route.contract_id(),
            "identity rbac handler failed"
        );
    }
    core_response(kind, request_id)
}

fn policy_error_response(
    err: &PolicyManageError,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) -> Response {
    if matches!(err, PolicyManageError::OutboxFactConflict(_)) {
        return fact_conflict_response(request_id);
    }
    if matches!(err, PolicyManageError::AttributeValueTooLong) {
        return attribute_value_too_long_response(request_id);
    }
    let kind = policy_manage_error_kind(err);
    log_policy_manage_error(err, kind, tenant, request_id, spec);
    core_response(kind, request_id)
}

fn attribute_value_too_long_response(request_id: &str) -> Response {
    httpserve::error::core_error_response(
        &CoreError::new(CoreErrorKind::Validation)
            .with_details(PublicDetail::Str(
                "reason",
                "attributeValueTooLong".to_string(),
            ))
            .with_details(PublicDetail::Int(
                "maxBytes",
                crate::ATTR_VALUE_MAX_LEN as i64,
            )),
        request_id,
    )
}

fn policy_manage_error_kind(err: &PolicyManageError) -> CoreErrorKind {
    match err {
        PolicyManageError::AttributeValueTooLong | PolicyManageError::InvalidPolicy => {
            CoreErrorKind::Validation
        }
        PolicyManageError::PolicyNotFound => CoreErrorKind::NotFound,
        PolicyManageError::PolicyAlreadyExists => CoreErrorKind::Conflict,
        PolicyManageError::VersionConflict => CoreErrorKind::VersionConflict,
        PolicyManageError::PayloadEncode(_)
        | PolicyManageError::EventEncode(_)
        | PolicyManageError::EnvelopeIdentity(_)
        | PolicyManageError::IdempotencyKey(_)
        | PolicyManageError::WireProjection(_)
        | PolicyManageError::Store(_)
        | PolicyManageError::OutboxFactConflict(_) => CoreErrorKind::Internal,
    }
}

fn log_policy_manage_error(
    err: &PolicyManageError,
    kind: CoreErrorKind,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) {
    if store_invalid_policy(err) {
        warn_invalid_stored_policy(err, tenant, request_id, spec);
        return;
    }
    if matches!(kind, CoreErrorKind::Internal) {
        error_policy_handler_failed(err, tenant, request_id, spec);
    }
}

fn store_invalid_policy(err: &PolicyManageError) -> bool {
    matches!(err, PolicyManageError::Store(IdentityError::InvalidPolicy))
}

fn warn_invalid_stored_policy(
    err: &PolicyManageError,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) {
    tracing::warn!(
        error = %err,
        error_chain = %secure::redact_error(err),
        request_id,
        tenant_id = %tenant,
        contract_id = spec.route.contract_id(),
        "identity policy hydrate/store rejected invalid stored policy"
    );
}

fn error_policy_handler_failed(
    err: &PolicyManageError,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) {
    tracing::error!(
        error = %err,
        error_chain = %secure::redact_error(err),
        request_id,
        tenant_id = %tenant,
        contract_id = spec.route.contract_id(),
        "identity policy handler failed"
    );
}

fn password_error_response(
    err: &ChangePasswordError,
    tenant: TenantId,
    request_id: &str,
) -> Response {
    let kind = match err {
        ChangePasswordError::InvalidCredentials => CoreErrorKind::Forbidden,
        ChangePasswordError::NotFound => CoreErrorKind::NotFound,
        ChangePasswordError::VersionConflict => CoreErrorKind::VersionConflict,
        ChangePasswordError::Policy(_) => CoreErrorKind::Validation,
        ChangePasswordError::Hash | ChangePasswordError::Store(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            error_chain = %secure::redact_error(&err),
            request_id,
            tenant_id = %tenant,
            contract_id = PASSWORD_CHANGE_HTTP_SPEC.route.contract_id(),
            operation = "password_change",
            "identity password change failed"
        );
    }
    if let ChangePasswordError::Policy(policy) = err {
        return httpserve::error::core_error_response(
            &CoreError::new(kind)
                .with_details(PublicDetail::Str("reason", policy.reason().to_string())),
            request_id,
        );
    }
    core_response(kind, request_id)
}

fn account_status_error_response(
    error: &AccountStatusChangeError,
    tenant: TenantId,
    request_id: &str,
) -> Response {
    let kind = match error {
        AccountStatusChangeError::NotFound => CoreErrorKind::NotFound,
        AccountStatusChangeError::InvalidTransition => CoreErrorKind::Conflict,
        AccountStatusChangeError::VersionConflict => CoreErrorKind::VersionConflict,
        AccountStatusChangeError::Store(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %error,
            error_chain = %secure::redact_error(error),
            request_id,
            tenant_id = %tenant,
            contract_id = ACCOUNT_STATUS_SET_HTTP_SPEC.route.contract_id(),
            operation = "account_status_set",
            "identity account status set failed"
        );
    }
    core_response(kind, request_id)
}

/// identity 域 bootstrap 生命周期：声明 identity HTTP 路由组（Primary listener，同 `/api/v1/identity` 前缀）。
/// 泛型 `S: Signer` 随 login/refresh 服务穿透，组合根单态化 `S = vault::VaultSigner`。
pub struct IdentityDomainDeps<S> {
    pub login: Arc<LoginService<S>>,
    pub refresh: Arc<RefreshService<S>>,
    pub credential_security: Arc<CredentialSecurityService>,
    pub rbac_admin: Arc<RbacAdminService>,
    pub policy_manage: Arc<PolicyManageService>,
    pub roles: Arc<DynRoleReadRepo<'static>>,
    pub binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
    pub policies: Arc<DynPolicyRepo<'static>>,
    pub resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
    pub clock: Arc<dyn Clock>,
}

/// Identity dependencies that remain valid when the Primary listener trusts only federated access
/// tokens and therefore cannot expose RSS-local login, AuthGrant, or refresh mutation routes.
pub struct FederatedIdentityDomainDeps {
    pub rbac_admin: Arc<RbacAdminService>,
    pub policy_manage: Arc<PolicyManageService>,
    pub roles: Arc<DynRoleReadRepo<'static>>,
    pub binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
    pub policies: Arc<DynPolicyRepo<'static>>,
    pub resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
    pub clock: Arc<dyn Clock>,
}

struct IdentityCommonDomain {
    rbac_admin: Arc<RbacAdminService>,
    policy_manage: Arc<PolicyManageService>,
    roles: Arc<DynRoleReadRepo<'static>>,
    policies: Arc<DynPolicyRepo<'static>>,
    authorizer: Arc<ContractAuthorizer>,
}

impl IdentityCommonDomain {
    fn new(
        rbac_admin: Arc<RbacAdminService>,
        policy_manage: Arc<PolicyManageService>,
        roles: Arc<DynRoleReadRepo<'static>>,
        binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
        policies: Arc<DynPolicyRepo<'static>>,
        resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let authorizer = Arc::new(ContractAuthorizer::new(
            Arc::clone(&roles),
            binding_reads,
            Arc::clone(&policies),
            resource_attribute_reads,
            clock,
        ));
        Self {
            rbac_admin,
            policy_manage,
            roles,
            policies,
            authorizer,
        }
    }

    fn register_authorizer(&self, registry: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
        let authorizer: Arc<dyn RouteAuthorizer> = self.authorizer.clone();
        registry.register_primary_authorizer(authorizer)
    }

    fn route_state(&self) -> CommonIdentityRouteState {
        CommonIdentityRouteState {
            rbac_assign: RbacHandlerState {
                service: Arc::clone(&self.rbac_admin),
            },
            policies_create: PolicyManageHandlerState {
                service: Arc::clone(&self.policy_manage),
                authorizer: Arc::clone(&self.authorizer),
            },
            policies_get: PolicyQueryService {
                policies: Arc::clone(&self.policies),
            },
            roles_list: RolesListHandlerState {
                roles: Arc::clone(&self.roles),
            },
        }
    }
}

struct CommonIdentityRouteState {
    rbac_assign: RbacHandlerState,
    policies_create: PolicyManageHandlerState,
    policies_get: PolicyQueryService,
    roles_list: RolesListHandlerState,
}

pub struct IdentityDomain<S> {
    login: Arc<LoginService<S>>,
    refresh: Arc<RefreshService<S>>,
    credential_security: Arc<CredentialSecurityService>,
    common: IdentityCommonDomain,
}

/// Identity domain surface for a Primary listener fixed to `FederatedAccessToken`.
///
/// The type has no signer, issuer, refresh store, or login service field, making RSS-local login,
/// AuthGrant issuance, and refresh mutation routes structurally unavailable in this profile.
pub struct FederatedIdentityDomain {
    common: IdentityCommonDomain,
}

impl<S: diport::Signer + Send + Sync + 'static> IdentityDomain<S> {
    pub fn new(deps: IdentityDomainDeps<S>) -> Self {
        let IdentityDomainDeps {
            login,
            refresh,
            credential_security,
            rbac_admin,
            policy_manage,
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
            clock,
        } = deps;
        Self {
            login,
            refresh,
            credential_security,
            common: IdentityCommonDomain::new(
                rbac_admin,
                policy_manage,
                roles,
                binding_reads,
                policies,
                resource_attribute_reads,
                clock,
            ),
        }
    }
}

impl FederatedIdentityDomain {
    pub fn new(deps: FederatedIdentityDomainDeps) -> Self {
        let FederatedIdentityDomainDeps {
            rbac_admin,
            policy_manage,
            roles,
            binding_reads,
            policies,
            resource_attribute_reads,
            clock,
        } = deps;
        Self {
            common: IdentityCommonDomain::new(
                rbac_admin,
                policy_manage,
                roles,
                binding_reads,
                policies,
                resource_attribute_reads,
                clock,
            ),
        }
    }
}

fn mount_common_identity_routes(
    rb: ListenerRouter<Primary>,
    state: CommonIdentityRouteState,
) -> Result<ListenerRouter<Primary>, KernelError> {
    let rbac_revoke = state.rbac_assign.clone();
    let policies_update = state.policies_create.clone();
    let policies_deactivate = state.policies_create.clone();
    let policies_get = state.policies_get;
    let policies_list = policies_get.clone();
    let roles_list = state.roles_list;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new_producer(ROLES_ASSIGN_PRODUCER, roles_assign_handler)?
            .with_state(state.rbac_assign),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new_producer(ROLES_REVOKE_PRODUCER, roles_revoke_handler)?
            .with_state(rbac_revoke),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new(ROLES_LIST_HTTP_ROUTE, roles_list_handler)?
            .with_classified_state(roles_list),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new_producer(POLICIES_CREATE_PRODUCER, policies_create_handler)?
            .with_state(state.policies_create),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new_producer(POLICIES_UPDATE_PRODUCER, policies_update_handler)?
            .with_state(policies_update),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new_producer(
            POLICIES_DEACTIVATE_PRODUCER,
            policies_deactivate_handler,
        )?
        .with_state(policies_deactivate),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new(POLICIES_GET_HTTP_ROUTE, policies_get_handler)?
            .with_classified_state(policies_get),
    )?;
    let rb = rb.mount(
        GeneratedPrimaryEndpoint::new(POLICIES_LIST_HTTP_ROUTE, policies_list_handler)?
            .with_classified_state(policies_list),
    )?;
    rb.mount(GeneratedPrimaryEndpoint::new(
        PROFILE_HTTP_ROUTE,
        profile_handler,
    )?)
    .map_err(Into::into)
}

impl<S: diport::Signer + Send + Sync + 'static> ::bootstrap::Domain for IdentityDomain<S> {
    fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
        self.common.register_authorizer(reg)?;
        let login = Arc::clone(&self.login);
        let refresh = Arc::clone(&self.refresh);
        let common = self.common.route_state();
        let account_status_get = AccountStatusQueryHandlerState {
            query: AccountStatusQueryService {
                accounts: Arc::clone(&self.credential_security.accounts),
            },
        };
        let credential_security = CredentialSecurityHandlerState {
            service: Arc::clone(&self.credential_security),
        };
        let password = credential_security.clone();
        let account_status = credential_security.clone();
        let logout_all = credential_security.clone();
        reg.route_group::<Primary>(LOGIN_ROUTE_PREFIX, move |rb| {
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(LOGIN_PRODUCER, login_handler::<S>)?
                    .with_state(login),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(REFRESH_PRODUCER, refresh_handler::<S>)?
                    .with_state(refresh),
            )?;
            let rb = mount_common_identity_routes(rb, common)?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(
                    PASSWORD_CHANGE_PRODUCER,
                    password_change_handler,
                )?
                .with_state(password),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(
                    ACCOUNT_STATUS_SET_PRODUCER,
                    account_status_set_handler,
                )?
                .with_state(account_status),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new(
                    ACCOUNT_STATUS_GET_HTTP_ROUTE,
                    account_status_get_handler,
                )?
                .with_classified_state(account_status_get),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(LOGOUT_PRODUCER, logout_handler)?
                    .with_state(credential_security),
            )?;
            let rb = rb.mount(
                GeneratedPrimaryEndpoint::new_producer(LOGOUT_ALL_PRODUCER, logout_all_handler)?
                    .with_state(logout_all),
            )?;
            Ok(rb)
        })?;
        Ok(())
    }
}

impl ::bootstrap::Domain for FederatedIdentityDomain {
    fn init(&self, reg: &mut ::bootstrap::Registry) -> Result<(), KernelError> {
        self.common.register_authorizer(reg)?;
        let common = self.common.route_state();
        reg.route_group::<Primary>(LOGIN_ROUTE_PREFIX, move |rb| {
            mount_common_identity_routes(rb, common)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::ports::{
        AccountSecurityReadRepo, AccountSecurityState, Credential, DynPolicyLifecycle, Operator,
        PipAttributeKey, Policy, PolicyCondition, PolicyEffect, PolicyObligations, PolicyRule,
        Role,
    };
    use authn::CredentialSecurityEventKind;
    use diport::OutboxEmitError;
    use testkit::ContractRequest;

    // canonical UUID 种子租户（TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000abc";
    // canonical user id（audit actor 形态；与登录标识 "alice" 解耦，#1277 F1）。
    const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
    // 未种子化的 canonical user id（change_password 未知主体 → NotFound，#1277 F2）。
    const GHOST_USER: &str = "99999999-8888-4777-8666-555544443333";
    const RESOURCE_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn account_transition_errors_only_classify_illegal_edges_as_validation() {
        use crate::domain::AccountSecurityTransitionError::{
            EpochOverflow, Illegal, TimeRegression, VersionOverflow,
        };

        assert!(matches!(
            map_account_transition_error(Illegal),
            AccountStatusChangeError::InvalidTransition
        ));
        for error in [EpochOverflow, VersionOverflow, TimeRegression] {
            assert!(matches!(
                map_account_transition_error(error),
                AccountStatusChangeError::Store(IdentityError::Storage(_))
            ));
        }
    }

    fn login_receipt() -> LoginProducerReceipt {
        ProducerMarker::for_test(LOGIN_PRODUCER).into_receipt()
    }

    fn refresh_receipt() -> RefreshProducerReceipt {
        ProducerMarker::for_test(REFRESH_PRODUCER).into_receipt()
    }

    #[derive(Clone, Default)]
    struct EmptyAccountSecurityRead {
        find_calls: Arc<AtomicUsize>,
    }

    impl AccountSecurityReadRepo for EmptyAccountSecurityRead {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _user_id: ids::UserId,
        ) -> Result<Option<AccountSecurityState>, IdentityError> {
            self.find_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
    }

    struct ConfirmingIdentitySecurityLifecycle;

    impl IdentitySecurityLifecycle for ConfirmingIdentitySecurityLifecycle {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            let (_, _, command) = command.into_parts();
            let (_, _, pending) = command.into_parts();
            Ok(pending.confirm())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            let crate::domain::CredentialSecurityCommand::Account(command) =
                command.into_security_command()
            else {
                unreachable!("account status set is account-wide")
            };
            let (_, _, pending) = command.into_parts();
            Ok(pending.confirm())
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            let crate::domain::CredentialSecurityCommand::Grant(command) =
                command.into_security_command()
            else {
                unreachable!("logout-current wrapper is grant-local")
            };
            let (_, _, pending) = command.into_parts();
            Ok(pending.confirm())
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            let crate::domain::CredentialSecurityCommand::Account(command) =
                command.into_security_command()
            else {
                unreachable!("logout-all wrapper is account-wide")
            };
            let (_, _, pending) = command.into_parts();
            Ok(pending.confirm())
        }
    }

    impl AccountReactivationLifecycle for ConfirmingIdentitySecurityLifecycle {
        async fn execute_reactivation(
            &self,
            _scope: TenantRepoScope,
            command: crate::domain::ReactivateAccountCommand,
        ) -> Result<AccountSecurityState, IdentityError> {
            let (_, next) = command.into_mutation().into_parts();
            Ok(next)
        }
    }

    #[derive(Clone, Default)]
    struct CapturingStatusSetLifecycle {
        observed: Arc<Mutex<Vec<(CredentialSecurityEventKind, vocab::PrincipalKind)>>>,
    }

    impl CapturingStatusSetLifecycle {
        fn observed(&self) -> Vec<(CredentialSecurityEventKind, vocab::PrincipalKind)> {
            self.observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    impl IdentitySecurityLifecycle for CapturingStatusSetLifecycle {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            self.observed
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push((command.event().kind(), command.event().initiator().kind()));
            let crate::domain::CredentialSecurityCommand::Account(command) =
                command.into_security_command()
            else {
                unreachable!("account status set is account-wide")
            };
            let (_, _, pending) = command.into_parts();
            Ok(pending.confirm())
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }
    }

    #[derive(Clone)]
    struct ConcurrentWinnerStatusSetLifecycle {
        accounts: crate::internal::mem::InMemCredentialRepo,
        winner_status: crate::AccountStatus,
        calls: Arc<AtomicUsize>,
    }

    #[allow(clippy::expect_used)]
    impl IdentitySecurityLifecycle for ConcurrentWinnerStatusSetLifecycle {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let crate::domain::CredentialSecurityCommand::Account(command) =
                command.into_security_command()
            else {
                unreachable!("account status set is account-wide")
            };
            let (mutation, _, _) = command.into_parts();
            let (expected, requested) = mutation.into_parts();
            let persisted = if requested.status() == self.winner_status {
                requested
            } else {
                expected
                    .transition(
                        self.winner_status,
                        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
                    )
                    .expect("simulated concurrent winner transition")
                    .into_parts()
                    .1
            };
            self.accounts.set_account_security_for_test(persisted);
            Err(IdentityError::VersionConflict)
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }
    }

    fn provider_unavailable() -> IdentityError {
        IdentityError::ProviderUnavailable(Box::new(std::io::Error::other("database unavailable")))
    }

    struct UnavailableIdentitySecurityLifecycle;

    impl IdentitySecurityLifecycle for UnavailableIdentitySecurityLifecycle {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::ProviderUnavailable(Box::new(
                std::io::Error::other("database unavailable"),
            )))
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::ProviderUnavailable(Box::new(
                std::io::Error::other("database unavailable"),
            )))
        }
    }

    impl AccountReactivationLifecycle for UnavailableIdentitySecurityLifecycle {
        async fn execute_reactivation(
            &self,
            _scope: TenantRepoScope,
            _command: crate::domain::ReactivateAccountCommand,
        ) -> Result<AccountSecurityState, IdentityError> {
            Err(provider_unavailable())
        }
    }

    struct ConflictingIdentitySecurityLifecycle;

    impl IdentitySecurityLifecycle for ConflictingIdentitySecurityLifecycle {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            Err(IdentityError::VersionConflict)
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::VersionConflict)
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::VersionConflict)
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::VersionConflict)
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(IdentityError::VersionConflict)
        }
    }

    impl AccountReactivationLifecycle for ConflictingIdentitySecurityLifecycle {
        async fn execute_reactivation(
            &self,
            _scope: TenantRepoScope,
            _command: crate::domain::ReactivateAccountCommand,
        ) -> Result<AccountSecurityState, IdentityError> {
            Err(IdentityError::VersionConflict)
        }
    }

    fn test_credential_security<S: diport::Signer + Send + Sync + 'static>(
        login: &Arc<LoginService<S>>,
    ) -> Arc<CredentialSecurityService> {
        Arc::new(CredentialSecurityService::new(
            Arc::clone(&login.credentials),
            Arc::clone(&login.lifecycle),
            DynAccountSecurityReadRepo::new_box(EmptyAccountSecurityRead::default()),
            ConfirmingIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        ))
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn credential_security_reactivation_preserves_epoch_and_advances_version() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let active = accounts
            .find(tenant_repo_scope(tenant), user)
            .await
            .expect("read account")
            .expect("seed account");
        let (_, suspended) = active
            .transition(
                crate::AccountStatus::Suspended,
                SystemTime::UNIX_EPOCH + Duration::from_secs(999),
            )
            .expect("active can suspend")
            .into_parts();
        accounts.set_account_security_for_test(suspended.clone());

        let grants = crate::internal::mem::InMemAuthGrantStore::new();
        let service = CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(accounts.clone())),
            test_lifecycle(grants),
            DynAccountSecurityReadRepo::new_box(accounts),
            ConfirmingIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        );

        let restored = service
            .reactivate_account(tenant_repo_scope(tenant), user)
            .await
            .expect("suspended account can reactivate");
        assert_eq!(restored.status(), crate::AccountStatus::Active);
        assert_eq!(restored.authn_epoch(), suspended.authn_epoch());
        assert_eq!(restored.version().get(), suspended.version().get() + 1);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn account_status_set_handler_maps_success_and_cross_tenant_not_found() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let service = Arc::new(CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(accounts.clone())),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            DynAccountSecurityReadRepo::new_box(accounts),
            ConfirmingIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        ));
        let state = State(CredentialSecurityHandlerState { service });

        let mut opaque_admin = Request::builder()
            .body(Body::from(r#"{"targetStatus":"suspended"}"#))
            .expect("request");
        opaque_admin
            .extensions_mut()
            .insert(AuthorizedSubject::for_test(
                tenant,
                vocab::PrincipalKind::Admin,
                "admin-subj",
                Some(httpserve::RouteResource::new(CANON_USER).expect("canonical route resource")),
            ));
        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            state.clone(),
            Path(CANON_USER.to_string()),
            opaque_admin,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an already-authorized opaque admin subject must not be reparsed as a user UUID"
        );

        let mut request = Request::builder()
            .body(Body::from(r#"{"targetStatus":"locked"}"#))
            .expect("request");
        request.extensions_mut().insert(AuthorizedSubject::for_test(
            tenant,
            vocab::PrincipalKind::User,
            CANON_USER,
            Some(httpserve::RouteResource::new(CANON_USER).expect("canonical route resource")),
        ));
        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            state.clone(),
            Path(CANON_USER.to_string()),
            request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let mut cross_tenant = Request::builder()
            .body(Body::from(r#"{"targetStatus":"suspended"}"#))
            .expect("request");
        cross_tenant
            .extensions_mut()
            .insert(AuthorizedSubject::for_test(
                tid(OTHER_TENANT),
                vocab::PrincipalKind::User,
                CANON_USER,
                Some(httpserve::RouteResource::new(CANON_USER).expect("canonical route resource")),
            ));
        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            state,
            Path(CANON_USER.to_string()),
            cross_tenant,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn account_status_get_and_same_state_put_are_readable_and_effect_free() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let service = Arc::new(CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(accounts.clone())),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            DynAccountSecurityReadRepo::new_box(accounts.clone()),
            UnavailableIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        ));
        let mut set_request = Request::builder()
            .body(Body::from(r#"{"targetStatus":"active"}"#))
            .expect("set request");
        set_request
            .extensions_mut()
            .insert(AuthorizedSubject::for_test(
                tenant,
                vocab::PrincipalKind::Admin,
                "opaque-admin",
                None,
            ));
        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            State(CredentialSecurityHandlerState { service }),
            Path(CANON_USER.to_string()),
            set_request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(body["data"]["status"], "active");
        assert_eq!(body["data"]["changed"], false);

        let mut get_request = Request::builder().body(Body::empty()).expect("get request");
        get_request
            .extensions_mut()
            .insert(AuthorizedSubject::for_test(
                tenant,
                vocab::PrincipalKind::Admin,
                "opaque-admin",
                None,
            ));
        let response = account_status_get_handler(
            ContractMarker::for_test(),
            State(AccountStatusQueryHandlerState {
                query: AccountStatusQueryService {
                    accounts: Arc::from(DynAccountSecurityReadRepo::new_box(accounts)),
                },
            }),
            Path(CANON_USER.to_string()),
            get_request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("response json");
        assert_eq!(body["data"]["status"], "active");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn account_status_restore_emits_reactivated_with_real_admin_initiator() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let active = accounts
            .find(tenant_repo_scope(tenant), user)
            .await
            .expect("read")
            .expect("account");
        let (_, suspended) = active
            .transition(
                crate::AccountStatus::Suspended,
                SystemTime::UNIX_EPOCH + Duration::from_secs(999),
            )
            .expect("suspend")
            .into_parts();
        accounts.set_account_security_for_test(suspended);
        let lifecycle = CapturingStatusSetLifecycle::default();
        let service = Arc::new(CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(accounts.clone())),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            DynAccountSecurityReadRepo::new_box(accounts),
            lifecycle.clone(),
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        ));
        let mut request = Request::builder()
            .body(Body::from(r#"{"targetStatus":"active"}"#))
            .expect("request");
        request.extensions_mut().insert(AuthorizedSubject::for_test(
            tenant,
            vocab::PrincipalKind::Admin,
            "opaque-admin",
            None,
        ));
        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            State(CredentialSecurityHandlerState { service }),
            Path(CANON_USER.to_string()),
            request,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            lifecycle.observed(),
            vec![(
                CredentialSecurityEventKind::Account(
                    authn::AccountSecurityEventKind::AccountReactivated,
                ),
                vocab::PrincipalKind::Admin,
            )]
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn concurrent_desired_status_put_converges_only_when_winner_matches_target() {
        async fn run(
            requested: crate::AccountStatus,
            winner: crate::AccountStatus,
        ) -> (Result<bool, AccountStatusChangeError>, usize) {
            let tenant = tid(CANON_TENANT);
            let user = uid(CANON_USER);
            let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
                "alice",
                user,
                "correct-horse",
                tenant,
            )
            .expect("seed credential and account");
            let calls = Arc::new(AtomicUsize::new(0));
            let lifecycle = ConcurrentWinnerStatusSetLifecycle {
                accounts: accounts.clone(),
                winner_status: winner,
                calls: Arc::clone(&calls),
            };
            let service = CredentialSecurityService::new(
                Arc::from(DynCredentialRepo::new_box(accounts.clone())),
                test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
                DynAccountSecurityReadRepo::new_box(accounts),
                lifecycle,
                ConfirmingIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_000),
            );
            let result = service
                .set_account_status(
                    ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER).into_receipt(),
                    tenant,
                    user,
                    requested,
                    crate::domain::CredentialSecurityInitiator::authenticated(
                        tenant,
                        vocab::PrincipalKind::Admin,
                        "opaque-admin",
                    ),
                )
                .await;
            (result, calls.load(Ordering::SeqCst))
        }

        let (same, same_calls) = run(
            crate::AccountStatus::Suspended,
            crate::AccountStatus::Suspended,
        )
        .await;
        assert!(!same.expect("same desired status converges"));
        assert_eq!(same_calls, 1, "conflict reconciliation must not emit/retry");

        let (different, different_calls) = run(
            crate::AccountStatus::Suspended,
            crate::AccountStatus::Locked,
        )
        .await;
        assert!(matches!(
            different,
            Err(AccountStatusChangeError::VersionConflict)
        ));
        assert_eq!(different_calls, 1, "different target must not be retried");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn account_status_set_handler_fails_closed_across_input_and_provider_errors() {
        fn authorized_request(tenant: TenantId, body: &'static str) -> Request<Body> {
            let mut request = Request::builder().body(Body::from(body)).expect("request");
            request.extensions_mut().insert(AuthorizedSubject::for_test(
                tenant,
                vocab::PrincipalKind::Admin,
                "opaque-admin",
                None,
            ));
            request
        }

        let tenant = tid(CANON_TENANT);
        let empty = EmptyAccountSecurityRead::default();
        let empty_state = State(CredentialSecurityHandlerState {
            service: Arc::new(CredentialSecurityService::new(
                Arc::from(DynCredentialRepo::new_box(
                    crate::internal::mem::InMemCredentialRepo::new(),
                )),
                test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
                DynAccountSecurityReadRepo::new_box(empty.clone()),
                ConfirmingIdentitySecurityLifecycle,
                ConfirmingIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_000),
            )),
        });

        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            empty_state.clone(),
            Path(CANON_USER.to_string()),
            Request::builder()
                .body(Body::from(r#"{"targetStatus":"suspended"}"#))
                .expect("request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            empty_state.clone(),
            Path("not-a-user-id".to_string()),
            authorized_request(tenant, r#"{"targetStatus":"suspended"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            empty_state.clone(),
            Path(CANON_USER.to_string()),
            authorized_request(tenant, r#"{"targetStatus":"unsupported"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(empty.find_calls.load(Ordering::SeqCst), 0);

        let response = account_status_set_handler(
            ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
            empty_state,
            Path(CANON_USER.to_string()),
            authorized_request(tenant, r#"{"targetStatus":"suspended"}"#),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        for (unavailable, expected) in [
            (true, StatusCode::INTERNAL_SERVER_ERROR),
            (false, StatusCode::CONFLICT),
        ] {
            let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
                "alice",
                uid(CANON_USER),
                "correct-horse",
                tenant,
            )
            .expect("seed credential and account");
            let lifecycle: Box<DynIdentitySecurityLifecycle<'static>> = if unavailable {
                DynIdentitySecurityLifecycle::new_box(UnavailableIdentitySecurityLifecycle)
            } else {
                DynIdentitySecurityLifecycle::new_box(ConflictingIdentitySecurityLifecycle)
            };
            let service = CredentialSecurityService {
                credentials: Arc::from(DynCredentialRepo::new_box(accounts.clone())),
                grants: test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
                accounts: Arc::from(DynAccountSecurityReadRepo::new_box(accounts)),
                lifecycle: Arc::from(lifecycle),
                reactivation: DynAccountReactivationLifecycle::new_box(
                    ConfirmingIdentitySecurityLifecycle,
                ),
                password_policy: seed_password_policy(),
                clock: make_clock(1_000),
            };
            let response = account_status_set_handler(
                ProducerMarker::for_test(ACCOUNT_STATUS_SET_PRODUCER),
                State(CredentialSecurityHandlerState {
                    service: Arc::new(service),
                }),
                Path(CANON_USER.to_string()),
                authorized_request(tenant, r#"{"targetStatus":"suspended"}"#),
            )
            .await;
            assert_eq!(response.status(), expected);
        }
    }

    #[test]
    fn account_status_invalid_transition_is_an_http_conflict() {
        let response = account_status_error_response(
            &AccountStatusChangeError::InvalidTransition,
            tid(CANON_TENANT),
            "request-invalid-transition",
        );

        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn password_reauthentication_failures_share_the_login_lockout_funnel() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let service = CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(credentials.clone())),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            DynAccountSecurityReadRepo::new_box(credentials.clone()),
            ConfirmingIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        );

        for _attempt in 1..=5 {
            let error = service
                .reauthenticate_password_change(
                    tenant,
                    user,
                    secure::RawPassword::new("wrong-current".to_owned()),
                )
                .await
                .expect_err("wrong current password must reject");
            assert!(matches!(error, ChangePasswordError::InvalidCredentials));
        }

        let outcome = credentials
            .authenticate(
                tenant_repo_scope(tenant),
                LoginIdentifier::new("alice"),
                secure::RawPassword::new("correct-horse".to_owned()),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_001),
            )
            .await
            .expect("lockout observation");
        assert_eq!(
            outcome,
            AuthOutcome::RejectedKnown,
            "password-change failures must atomically advance the same lockout used by login"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn password_change_reauthentication_wins_over_new_password_policy() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed credential and account");
        let state = State(CredentialSecurityHandlerState {
            service: Arc::new(CredentialSecurityService::new(
                Arc::from(DynCredentialRepo::new_box(credentials.clone())),
                test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
                DynAccountSecurityReadRepo::new_box(credentials),
                UnavailableIdentitySecurityLifecycle,
                ConfirmingIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_000),
            )),
        });
        let mut request = Request::builder()
            .body(Body::from(
                r#"{"currentPassword":"wrong-current","newPassword":"weak"}"#,
            ))
            .expect("request");
        request.extensions_mut().insert(AuthorizedSubject::for_test(
            tenant,
            vocab::PrincipalKind::User,
            CANON_USER,
            None,
        ));

        let response = password_change_handler(
            ProducerMarker::for_test(PASSWORD_CHANGE_PRODUCER),
            state,
            request,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "wrong current password must fail before replacement-password policy is observable"
        );
    }

    fn attach_current_grant(req: &mut Request<Body>, evidence: CurrentAuthGrant) {
        req.extensions_mut().insert(AuthorizedSubject::for_test(
            evidence.tenant_id(),
            vocab::PrincipalKind::User,
            evidence.user_id().as_uuid().hyphenated().to_string(),
            None,
        ));
        req.extensions_mut().insert(evidence);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handlers_require_grant_evidence_and_reject_target_body() {
        let capture = CapturingAuthGrantLifecycle::default();
        let login = Arc::new(seed_service(&capture, 1_000, 3_600));
        let account_reader = EmptyAccountSecurityRead::default();
        let state = State(CredentialSecurityHandlerState {
            service: Arc::new(CredentialSecurityService::new(
                Arc::clone(&login.credentials),
                Arc::clone(&login.lifecycle),
                DynAccountSecurityReadRepo::new_box(account_reader.clone()),
                ConfirmingIdentitySecurityLifecycle,
                ConfirmingIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_000),
            )),
        });
        let missing = Request::builder().body(Body::from("{}")).expect("request");
        let response = logout_handler(
            ProducerMarker::for_test(LOGOUT_PRODUCER),
            state.clone(),
            missing,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let missing_all = Request::builder().body(Body::from("{}")).expect("request");
        let response = logout_all_handler(
            ProducerMarker::for_test(LOGOUT_ALL_PRODUCER),
            state.clone(),
            missing_all,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            capture.find_calls.load(Ordering::SeqCst),
            0,
            "missing route evidence must not reach the grant provider"
        );
        assert_eq!(
            account_reader.find_calls.load(Ordering::SeqCst),
            0,
            "missing route evidence must not reach the account provider"
        );

        let evidence = CurrentAuthGrant::for_test(
            ids::CanonicalUuidV4::parse("550e8400-e29b-41d4-a716-446655440000").expect("grant"),
            uid(CANON_USER),
            tid(CANON_TENANT),
            0,
        );
        let mut targeted = Request::builder()
            .body(Body::from(
                r#"{"sessionId":"550e8400-e29b-41d4-a716-446655440000"}"#,
            ))
            .expect("request");
        attach_current_grant(&mut targeted, evidence.clone());
        let response = logout_handler(
            ProducerMarker::for_test(LOGOUT_PRODUCER),
            state.clone(),
            targeted,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut targeted_all = Request::builder()
            .body(Body::from(r#"{"target":"forbidden"}"#))
            .expect("request");
        attach_current_grant(&mut targeted_all, evidence);
        let response = logout_all_handler(
            ProducerMarker::for_test(LOGOUT_ALL_PRODUCER),
            state,
            targeted_all,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handler_maps_explicit_provider_unavailability_to_503() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let refresh = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let bundle = issue_test_user_bundle(&refresh, &store).await;
        let claims = decode_access_claims(&bundle.access);
        let evidence = CurrentAuthGrant::for_test(
            ids::CanonicalUuidV4::parse(claims["sid"].as_str().expect("sid")).expect("grant"),
            uid(CANON_USER),
            tid(CANON_TENANT),
            claims["authn_epoch"].as_u64().expect("epoch"),
        );
        let state = State(CredentialSecurityHandlerState {
            service: Arc::new(CredentialSecurityService::new(
                seeded_credential_reader(),
                test_lifecycle(store),
                seeded_account_reader(),
                UnavailableIdentitySecurityLifecycle,
                UnavailableIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_700_000_001),
            )),
        });
        let mut request = Request::builder().body(Body::from("{}")).expect("request");
        attach_current_grant(&mut request, evidence.clone());

        let response = logout_handler(
            ProducerMarker::for_test(LOGOUT_PRODUCER),
            state.clone(),
            request,
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let mut request_all = Request::builder().body(Body::from("{}")).expect("request");
        attach_current_grant(&mut request_all, evidence);
        let response = logout_all_handler(
            ProducerMarker::for_test(LOGOUT_ALL_PRODUCER),
            state,
            request_all,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handlers_map_stale_validated_commands_to_409() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let refresh = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let bundle = issue_test_user_bundle(&refresh, &store).await;
        let claims = decode_access_claims(&bundle.access);
        let evidence = CurrentAuthGrant::for_test(
            ids::CanonicalUuidV4::parse(claims["sid"].as_str().expect("sid")).expect("grant"),
            uid(CANON_USER),
            tid(CANON_TENANT),
            claims["authn_epoch"].as_u64().expect("epoch"),
        );
        let state = State(CredentialSecurityHandlerState {
            service: Arc::new(CredentialSecurityService::new(
                seeded_credential_reader(),
                test_lifecycle(store),
                seeded_account_reader(),
                ConflictingIdentitySecurityLifecycle,
                ConflictingIdentitySecurityLifecycle,
                seed_password_policy(),
                make_clock(1_700_000_001),
            )),
        });
        let mut current = Request::builder().body(Body::from("{}")).expect("request");
        attach_current_grant(&mut current, evidence.clone());
        let current = logout_handler(
            ProducerMarker::for_test(LOGOUT_PRODUCER),
            state.clone(),
            current,
        )
        .await;
        assert_eq!(current.status(), StatusCode::CONFLICT);

        let mut all = Request::builder().body(Body::from("{}")).expect("request");
        attach_current_grant(&mut all, evidence);
        let all =
            logout_all_handler(ProducerMarker::for_test(LOGOUT_ALL_PRODUCER), state, all).await;
        assert_eq!(all.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn fact_conflict_mappers_use_one_terminal_wire_contract() {
        let conflict = consistency::OutboxFactConflict;
        let responses = [
            fact_conflict_response("rid"),
            rbac_error_response(
                &RbacAdminError::BindingWrite(OutboxEmitError::fact_conflict(conflict)),
                tid(CANON_TENANT),
                "rid",
                &ROLES_ASSIGN_HTTP_SPEC,
            ),
            policy_error_response(
                &PolicyManageError::OutboxFactConflict(conflict),
                tid(CANON_TENANT),
                "rid",
                &POLICIES_CREATE_HTTP_SPEC,
            ),
        ];
        for response in responses {
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("collect error body");
            let json: serde_json::Value = serde_json::from_slice(&body).expect("parse error body");
            assert_eq!(json["error"]["code"], "ERR_CORE_OUTBOX_FACT_CONFLICT");
            assert_eq!(json["error"]["retryable"], false);
            let rendered = String::from_utf8_lossy(&body);
            assert!(!rendered.contains("payload"));
            assert!(!rendered.contains("fingerprint"));
        }

        let cas = policy_error_response(
            &PolicyManageError::VersionConflict,
            tid(CANON_TENANT),
            "rid",
            &POLICIES_UPDATE_HTTP_SPEC,
        );
        let body = axum::body::to_bytes(cas.into_body(), usize::MAX)
            .await
            .expect("collect CAS error body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse CAS error body");
        assert_eq!(json["error"]["code"], "ERR_CORE_VERSION_CONFLICT");
        assert_eq!(json["error"]["retryable"], true);
    }

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：AuthGrantLifecycle / Clock 替身在此手写。
    // CapturingAuthGrantLifecycle 捕获原子 login mutation，并将 grant/refresh 一起委托给共享
    // `InMemAuthGrantStore`；同一 store 也注入 RefreshService，避免测试出现双存储漂移。
    #[derive(Clone, Default)]
    struct CapturingAuthGrantLifecycle {
        writes: Arc<Mutex<Vec<(AuthGrant, ReviewedEvent)>>>,
        inner: crate::internal::mem::InMemAuthGrantStore,
        find_calls: Arc<AtomicUsize>,
    }
    impl AuthGrantLifecycle for CapturingAuthGrantLifecycle {
        async fn persist_login_grant(
            &self,
            receipt: LoginProducerReceipt,
            scope: TenantRepoScope,
            mutation: LoginGrantMutation,
            event: ReviewedEvent,
        ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError> {
            let grant = mutation.grant().clone();
            let persisted = self
                .inner
                .persist_login_grant(receipt, scope, mutation, event.clone())
                .await?;
            self.writes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((grant, event));
            Ok(persisted)
        }
        async fn find_active(
            &self,
            scope: TenantRepoScope,
            grant_id: AuthGrantId,
            observed_at: SystemTime,
        ) -> Result<Option<AuthGrant>, IdentityError> {
            self.find_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.find_active(scope, grant_id, observed_at).await
        }
    }

    impl RefreshTokenStore for CapturingAuthGrantLifecycle {
        async fn find_by_hash(
            &self,
            scope: TenantRepoScope,
            hash: RefreshTokenHash,
        ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
            self.inner.find_by_hash(scope, hash).await
        }
    }

    impl IdentitySecurityLifecycle for CapturingAuthGrantLifecycle {
        async fn execute_refresh(
            &self,
            receipt: RefreshProducerReceipt,
            scope: TenantRepoScope,
            command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            self.inner.execute_refresh(receipt, scope, command).await
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }
    }

    impl CapturingAuthGrantLifecycle {
        fn count(&self) -> usize {
            self.writes.lock().unwrap_or_else(|e| e.into_inner()).len()
        }
    }

    #[derive(Clone, Default)]
    struct RecordingAuthAuditSink {
        events: Arc<Mutex<Vec<diport::AuditEvent>>>,
    }

    impl RecordingAuthAuditSink {
        fn events(&self) -> Vec<diport::AuditEvent> {
            self.events
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    }

    fn assert_profile_auth_event(
        sink: &RecordingAuthAuditSink,
        principal_kind: vocab::PrincipalKind,
        outcome: diport::AuditOutcome,
    ) {
        assert_route_auth_event(
            sink,
            PROFILE_HTTP_SPEC.route.contract_id(),
            principal_kind,
            outcome,
        );
    }

    fn assert_route_auth_event(
        sink: &RecordingAuthAuditSink,
        contract_id: &'static str,
        principal_kind: vocab::PrincipalKind,
        outcome: diport::AuditOutcome,
    ) {
        let events = sink.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.principal_id, CANON_USER);
        assert_eq!(event.principal_kind, principal_kind);
        assert_eq!(event.tenant_id, Some(tid(CANON_TENANT)));
        assert_eq!(event.resource_kind, "http_route");
        assert_eq!(event.resource_id, contract_id);
        assert_eq!(event.action, "httpserve:authz");
        assert_eq!(event.outcome, outcome);
    }

    impl diport::AuditSink for RecordingAuthAuditSink {
        async fn record(&self, event: diport::AuditEvent) -> Result<(), diport::AuditSinkError> {
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

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn make_clock(now_secs: u64) -> Box<dyn Clock> {
        Box::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(now_secs),
        ))
    }

    fn make_shared_clock(now_secs: u64) -> Arc<dyn Clock> {
        Arc::new(FixedClock(
            SystemTime::UNIX_EPOCH + Duration::from_secs(now_secs),
        ))
    }

    fn tid(raw: &str) -> TenantId {
        #[allow(clippy::expect_used)]
        TenantId::parse(raw).expect("canonical tenant")
    }

    fn uid(raw: &str) -> ids::UserId {
        #[allow(clippy::expect_used)]
        ids::UserId::parse(raw).expect("canonical user id")
    }

    #[allow(clippy::expect_used)]
    fn grant_id(raw: impl AsRef<str>) -> AuthGrantId {
        let raw = raw.as_ref();
        if let Ok(id) = AuthGrantId::hydrate(raw) {
            return id;
        }
        let digest = secure::digest(raw);
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        AuthGrantId::hydrate(uuid::Uuid::from_bytes(bytes).hyphenated().to_string())
            .expect("derived test grant id is canonical UUIDv4")
    }

    /// 构造用 with_seed_credential 的 LoginService（默认 CANON_TENANT + 登录标识 alice / canonical
    /// CANON_USER / correct-horse）。lifecycle 与 refresh 复用同一个 in-memory AuthGrant store。
    fn seed_service(
        capture: &CapturingAuthGrantLifecycle,
        now_secs: u64,
        ttl_secs: u64,
    ) -> LoginService<TestSigner> {
        let provider = capture.clone();
        #[allow(clippy::expect_used)]
        LoginService::with_seed_credential(
            move |accounts| {
                make_auth_grant_services(
                    provider,
                    accounts,
                    make_clock(now_secs),
                    Duration::from_secs(2_592_000),
                )
            },
            make_clock(now_secs),
            Duration::from_secs(ttl_secs),
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed_service ok")
    }

    /// 构造 IdentityDomain<TestSigner>（shared RefreshService）供路由声明测试使用。
    fn seed_domain(
        capture: CapturingAuthGrantLifecycle,
        now_secs: u64,
        ttl_secs: u64,
    ) -> IdentityDomain<TestSigner> {
        seed_domain_with_profile_permissions(capture, now_secs, ttl_secs, &[])
    }

    #[allow(clippy::expect_used)]
    fn seed_domain_with_profile_permissions(
        capture: CapturingAuthGrantLifecycle,
        now_secs: u64,
        ttl_secs: u64,
        profile_permissions: &[&str],
    ) -> IdentityDomain<TestSigner> {
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed domain credential");
        let auth_grants = make_auth_grant_services(
            capture,
            DynAccountSecurityReadRepo::new_box(credentials.clone()),
            make_clock(now_secs),
            Duration::from_secs(2_592_000),
        );
        let refresh = auth_grants.refresh_service();
        let login = Arc::new(LoginService::new(
            Arc::from(DynCredentialRepo::new_box(credentials)),
            auth_grants,
            make_clock(now_secs),
            Duration::from_secs(ttl_secs),
        ));
        let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let (roles_for_list, binding_provider): (
            Arc<DynRoleReadRepo<'static>>,
            crate::internal::mem::InMemRoleBindingLifecycle,
        ) = if profile_permissions.is_empty() {
            (
                Arc::from(DynRoleReadRepo::new_box(
                    crate::internal::mem::InMemRoleRepo::new(),
                )),
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            )
        } else {
            let profile_role = role(
                "role-profile-local-only",
                "Profile LocalOnly",
                profile_permissions,
            );
            let profile_role_id = profile_role.id().clone();
            (
                Arc::from(DynRoleReadRepo::new_box(
                    crate::internal::mem::InMemRoleRepo::new()
                        .with_role_entity(tid(CANON_TENANT), profile_role),
                )),
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &profile_role_id,
                    CANON_USER,
                ),
            )
        };
        let rbac_admin = Arc::new(RbacAdminService::new(
            roles_for_admin,
            Arc::from(DynRoleBindingLifecycle::new_box(binding_provider.clone())),
            make_clock(now_secs),
        ));
        let (policy_manage, policies) = empty_policy_manage(now_secs);
        IdentityDomain::new(IdentityDomainDeps {
            credential_security: test_credential_security(&login),
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles: roles_for_list,
            binding_reads: Arc::from(DynRoleBindingReadRepo::new_box(binding_provider)),
            policies,
            resource_attribute_reads: empty_resource_attribute_repo(),
            clock: make_shared_clock(now_secs),
        })
    }

    fn seed_federated_domain(now_secs: u64) -> FederatedIdentityDomain {
        let roles_for_admin = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let roles_for_list = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let binding_provider = crate::internal::mem::InMemRoleBindingLifecycle::new();
        let rbac_admin = Arc::new(RbacAdminService::new(
            roles_for_admin,
            Arc::from(DynRoleBindingLifecycle::new_box(binding_provider.clone())),
            make_clock(now_secs),
        ));
        let (policy_manage, policies) = empty_policy_manage(now_secs);
        FederatedIdentityDomain::new(FederatedIdentityDomainDeps {
            rbac_admin,
            policy_manage,
            roles: roles_for_list,
            binding_reads: Arc::from(DynRoleBindingReadRepo::new_box(binding_provider)),
            policies,
            resource_attribute_reads: empty_resource_attribute_repo(),
            clock: make_shared_clock(now_secs),
        })
    }

    #[allow(clippy::expect_used)]
    fn finalized_profile_router(
        capture: CapturingAuthGrantLifecycle,
        profile_permissions: &[&str],
        auth_sink: RecordingAuthAuditSink,
    ) -> (
        axum::Router,
        ::httpserve::StatelessLocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::profile::RouteMarker,
        >,
    ) {
        let domain =
            seed_domain_with_profile_permissions(capture, 1_000, 3_600, profile_permissions);
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        assert_eq!(finalized.len(), 1, "identity owns one Primary listener");
        let (listener, routes) = finalized.pop().expect("identity Primary routes");
        assert_eq!(listener, ListenerKind::Primary);
        let proof = ::httpserve::prove_stateless_local_only_mounted_route(
            &routes,
            &::generated::http::identity_v1::profile::ROUTE,
        )
        .expect("identity profile route is mounted in finalized routes");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            make_shared_clock(1_000),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    fn profile_local_only_parts(
        router: axum::Router,
        proof: ::httpserve::StatelessLocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::profile::RouteMarker,
        >,
        authenticated: Option<(vocab::PrincipalKind, &str)>,
    ) -> (axum::Router, ::testkit::local_only::LocalOnlyObservers) {
        let router = if let Some((kind, subject)) = authenticated {
            router.layer(axum::Extension(httpserve::Authenticated::new(
                primitives::RequiredScheme::FederatedAccessToken,
                kind,
                subject,
                Some(tid(CANON_TENANT)),
            )))
        } else {
            router
        };

        // Profile is mounted stateless by the typed LocalOnly funnel. It has no runtime provider
        // seam to observe, so all three forbidden dimensions are explicit static exclusions rather
        // than interchangeable closures over an unrelated domain capture.
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::BusinessWrite>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        (router, observers)
    }

    #[allow(clippy::expect_used)]
    async fn profile_local_only_call(
        router: axum::Router,
        proof: ::httpserve::StatelessLocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::profile::RouteMarker,
        >,
        authenticated: Option<(vocab::PrincipalKind, &str)>,
    ) -> testkit::ContractResponse {
        let (router, observers) = profile_local_only_parts(router, proof, authenticated);
        ::testkit::local_only::assert_local_only(observers, || {
            testkit::call(router, ContractRequest::get(PROFILE_HTTP_SPEC.route.path()))
        })
        .await
        .expect("profile remains LocalOnly")
        .expect("call finalized profile route")
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum IdentityLocalOnlyRead {
        RoleFind,
        RoleList,
        PolicyFind,
        PolicyList,
        PolicyEffective,
        BindingList,
        ResourceAttributes,
    }

    impl IdentityLocalOnlyRead {
        const ALL: [Self; 7] = [
            Self::RoleFind,
            Self::RoleList,
            Self::PolicyFind,
            Self::PolicyList,
            Self::PolicyEffective,
            Self::BindingList,
            Self::ResourceAttributes,
        ];
    }

    #[derive(Clone)]
    struct IdentityLocalOnlyReadProbe {
        roles: crate::internal::mem::InMemRoleRepo,
        policies: crate::internal::mem::InMemPolicyRepo,
        bindings: crate::internal::mem::InMemRoleBindingLifecycle,
        resource_attributes: crate::internal::mem::InMemResourceAttributeRepo,
        calls: Arc<std::sync::Mutex<Vec<(IdentityLocalOnlyRead, vocab::TenantId)>>>,
        business_write_effects:
            ::testkit::local_only::ProviderCounter<::testkit::local_only::BusinessWrite>,
        fail_on: Option<IdentityLocalOnlyRead>,
        forbidden_write_on: Option<IdentityLocalOnlyRead>,
    }

    impl Default for IdentityLocalOnlyReadProbe {
        fn default() -> Self {
            let other_tenant = tid("00000000-0000-4000-8000-000000000abc");
            let read_role = role(
                "role-a",
                "Identity reader",
                &[
                    "identity:role:read",
                    "identity:policy:read",
                    "identity:account-security:read",
                    "identity:account-security:write",
                ],
            );
            let read_role_id = read_role.id().clone();
            Self {
                roles: crate::internal::mem::InMemRoleRepo::new()
                    .with_role_entity(tid(CANON_TENANT), read_role)
                    .with_role_entity(
                        tid(CANON_TENANT),
                        role("role-b", "Secondary role", &["identity:profile:read"]),
                    )
                    .with_role_entity(
                        other_tenant,
                        role("role-z", "Other tenant role", &["identity:role:read"]),
                    ),
                policies: crate::internal::mem::InMemPolicyRepo::new()
                    .with_policy(owner_policy("policy-a"))
                    .with_policy(owner_policy("policy-b"))
                    .with_policy(identity_local_only_policy_for_tenant(
                        "policy-z",
                        other_tenant,
                    )),
                bindings: crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &read_role_id,
                    CANON_USER,
                ),
                resource_attributes: crate::internal::mem::InMemResourceAttributeRepo::new(),
                calls: Arc::new(std::sync::Mutex::new(Vec::new())),
                business_write_effects: ::testkit::local_only::ProviderCounter::business_write(),
                fail_on: None,
                forbidden_write_on: None,
            }
        }
    }

    #[allow(clippy::expect_used)]
    fn identity_local_only_policy_for_tenant(id: &str, tenant: TenantId) -> Policy {
        Policy::build(
            id,
            tenant,
            PolicyRouteScope::parse("other.contract", "identity:policy:read")
                .expect("identity LocalOnly policy scope"),
            SystemTime::UNIX_EPOCH,
            None,
            vec![PolicyRule::with_obligations(
                PolicyCondition::new(
                    AttributeKey::new(POLICY_ATTR_PRINCIPAL_KIND),
                    Operator::Eq(AttributeValue::new("admin")),
                ),
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            )],
        )
        .expect("identity LocalOnly policy")
    }

    impl IdentityLocalOnlyReadProbe {
        fn failing(read: IdentityLocalOnlyRead) -> Self {
            Self {
                fail_on: Some(read),
                ..Self::default()
            }
        }

        fn with_forbidden_write(read: IdentityLocalOnlyRead) -> Self {
            let mut probe = Self {
                forbidden_write_on: Some(read),
                ..Self::default()
            };
            if read == IdentityLocalOnlyRead::ResourceAttributes {
                probe.resource_attributes = crate::internal::mem::InMemResourceAttributeRepo::new()
                    .with_attribute(owner_resource_attribute(0, None));
            }
            probe
        }

        fn without_grant() -> Self {
            Self {
                bindings: crate::internal::mem::InMemRoleBindingLifecycle::new(),
                ..Self::default()
            }
        }

        fn test_repo(&self) -> TestRepo {
            TestRepo::from_provider(Arc::new(self.clone()))
        }

        fn record(&self, read: IdentityLocalOnlyRead, scope: TenantRepoScope) {
            self.calls
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push((read, scope.tenant()));
        }

        fn call_count(&self, read: IdentityLocalOnlyRead) -> usize {
            self.calls
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter(|(actual, _)| *actual == read)
                .count()
        }

        fn scopes_for(&self, read: IdentityLocalOnlyRead) -> Vec<vocab::TenantId> {
            self.calls
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .iter()
                .filter_map(|(actual, tenant)| (*actual == read).then_some(*tenant))
                .collect()
        }

        fn read_failure() -> IdentityError {
            IdentityError::Storage(Box::new(std::io::Error::other(
                "identity-local-only-probe-read-failure",
            )))
        }
    }

    impl RoleReadRepo for IdentityLocalOnlyReadProbe {
        async fn find(
            &self,
            scope: TenantRepoScope,
            id: RoleId,
        ) -> Result<Option<Role>, IdentityError> {
            self.record(IdentityLocalOnlyRead::RoleFind, scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::RoleFind) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::RoleFind) {
                return Err(Self::read_failure());
            }
            self.roles.find(scope, id).await
        }

        async fn list(
            &self,
            scope: TenantRepoScope,
            page: RolePage,
        ) -> Result<crate::ports::RoleListResult, IdentityError> {
            self.record(IdentityLocalOnlyRead::RoleList, scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::RoleList) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::RoleList) {
                return Err(Self::read_failure());
            }
            self.roles.list(scope, page).await
        }
    }

    impl PolicyRepo for IdentityLocalOnlyReadProbe {
        async fn find(
            &self,
            scope: TenantRepoScope,
            id: PolicyId,
        ) -> Result<Option<Policy>, IdentityError> {
            self.record(IdentityLocalOnlyRead::PolicyFind, scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::PolicyFind) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::PolicyFind) {
                return Err(Self::read_failure());
            }
            self.policies.find(scope, id).await
        }

        async fn list_active(
            &self,
            scope: TenantRepoScope,
            page: PolicyPage,
        ) -> Result<crate::ports::PolicyListResult, IdentityError> {
            self.record(IdentityLocalOnlyRead::PolicyList, scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::PolicyList) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::PolicyList) {
                return Err(Self::read_failure());
            }
            self.policies.list_active(scope, page).await
        }

        async fn list_effective(
            &self,
            tenant_scope: TenantRepoScope,
            scope: PolicyRouteScope,
            at: SystemTime,
        ) -> Result<Vec<Policy>, IdentityError> {
            self.record(IdentityLocalOnlyRead::PolicyEffective, tenant_scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::PolicyEffective) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::PolicyEffective) {
                return Err(Self::read_failure());
            }
            self.policies.list_effective(tenant_scope, scope, at).await
        }
    }

    impl RoleBindingReadRepo for IdentityLocalOnlyReadProbe {
        async fn list_for_subject(
            &self,
            scope: TenantRepoScope,
            subject: String,
        ) -> Result<Vec<crate::domain::RoleBinding>, IdentityError> {
            self.record(IdentityLocalOnlyRead::BindingList, scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::BindingList) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::BindingList) {
                return Err(Self::read_failure());
            }
            self.bindings.list_for_subject(scope, subject).await
        }
    }

    impl ResourceAttributeReadRepo for IdentityLocalOnlyReadProbe {
        async fn resolve_effective(
            &self,
            tenant_scope: TenantRepoScope,
            scope: PolicyRouteScope,
            resource_id: ResourceAttributeResourceId,
            required_keys: Vec<ResourceAttributeKey>,
            at: SystemTime,
        ) -> Result<ResourceAttributeResolution, IdentityError> {
            self.record(IdentityLocalOnlyRead::ResourceAttributes, tenant_scope);
            if self.forbidden_write_on == Some(IdentityLocalOnlyRead::ResourceAttributes) {
                self.business_write_effects.record();
            }
            if self.fail_on == Some(IdentityLocalOnlyRead::ResourceAttributes) {
                return Err(Self::read_failure());
            }
            self.resource_attributes
                .resolve_effective(tenant_scope, scope, resource_id, required_keys, at)
                .await
        }
    }

    struct TestRepo {
        roles: Arc<DynRoleReadRepo<'static>>,
        policies: Arc<DynPolicyRepo<'static>>,
        binding_reads: Arc<DynRoleBindingReadRepo<'static>>,
        resource_attribute_reads: Arc<DynResourceAttributeReadRepo<'static>>,
    }

    impl TestRepo {
        fn from_provider<T>(provider: Arc<T>) -> Self
        where
            T: RoleReadRepo
                + PolicyRepo
                + RoleBindingReadRepo
                + ResourceAttributeReadRepo
                + 'static,
        {
            Self {
                roles: Arc::from(DynRoleReadRepo::new_box(Arc::clone(&provider))),
                policies: Arc::from(DynPolicyRepo::new_box(Arc::clone(&provider))),
                binding_reads: Arc::from(DynRoleBindingReadRepo::new_box(Arc::clone(&provider))),
                resource_attribute_reads: Arc::from(DynResourceAttributeReadRepo::new_box(
                    provider,
                )),
            }
        }
    }

    struct IdentityLocalOnlyAncillaryServices {
        login: Arc<LoginService<TestSigner>>,
        refresh: Arc<RefreshService<TestSigner>>,
        rbac_admin: Arc<RbacAdminService>,
        policy_manage: Arc<PolicyManageService>,
    }

    #[allow(clippy::expect_used)]
    fn identity_local_only_ancillary_services() -> IdentityLocalOnlyAncillaryServices {
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed ancillary credential");
        let auth_grants = make_auth_grant_services(
            CapturingAuthGrantLifecycle::default(),
            DynAccountSecurityReadRepo::new_box(credentials.clone()),
            make_clock(1_000),
            Duration::from_secs(2_592_000),
        );
        let refresh = auth_grants.refresh_service();
        let login = Arc::new(LoginService::new(
            Arc::from(DynCredentialRepo::new_box(credentials)),
            auth_grants,
            make_clock(1_000),
            Duration::from_secs(3_600),
        ));
        let rbac_admin = Arc::new(RbacAdminService::new(
            Arc::from(DynRoleReadRepo::new_box(
                crate::internal::mem::InMemRoleRepo::new(),
            )),
            Arc::from(DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            )),
            make_clock(1_000),
        ));
        let (policy_manage, _) = empty_policy_manage(1_000);
        IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        }
    }

    #[allow(clippy::expect_used)]
    fn finalized_identity_v1_roles_list_router(
        repo: TestRepo,
        auth_sink: RecordingAuthAuditSink,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::roles_list::RouteMarker,
            RolesListHandlerState,
        >,
    ) {
        let IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        } = identity_local_only_ancillary_services();
        let domain = super::IdentityDomain::new(super::IdentityDomainDeps {
            credential_security: test_credential_security(&login),
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles: repo.roles,
            binding_reads: repo.binding_reads,
            policies: repo.policies,
            resource_attribute_reads: repo.resource_attribute_reads,
            clock: make_shared_clock(1_000),
        });
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        let (_, routes) = finalized.pop().expect("identity Primary routes");
        let proof = ::httpserve::prove_local_only_mounted_route_state::<RolesListHandlerState, _>(
            &routes,
            &::generated::http::identity_v1::roles_list::ROUTE,
        )
        .expect("identity roles-list LocalOnly state is mounted");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            make_shared_clock(1_000),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    #[allow(clippy::expect_used)]
    fn finalized_identity_v1_account_status_get_router(
        repo: TestRepo,
        auth_sink: RecordingAuthAuditSink,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::account_status_get::RouteMarker,
            AccountStatusQueryHandlerState,
        >,
    ) {
        let IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        } = identity_local_only_ancillary_services();
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed account-status query credential");
        let credential_security = Arc::new(CredentialSecurityService::new(
            Arc::from(DynCredentialRepo::new_box(accounts.clone())),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            DynAccountSecurityReadRepo::new_box(accounts),
            ConfirmingIdentitySecurityLifecycle,
            ConfirmingIdentitySecurityLifecycle,
            seed_password_policy(),
            make_clock(1_000),
        ));
        let domain = super::IdentityDomain::new(super::IdentityDomainDeps {
            login,
            refresh,
            credential_security,
            rbac_admin,
            policy_manage,
            roles: repo.roles,
            binding_reads: repo.binding_reads,
            policies: repo.policies,
            resource_attribute_reads: repo.resource_attribute_reads,
            clock: make_shared_clock(1_000),
        });
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        let (_, routes) = finalized.pop().expect("identity Primary routes");
        let proof =
            ::httpserve::prove_local_only_mounted_route_state::<AccountStatusQueryHandlerState, _>(
                &routes,
                &::generated::http::identity_v1::account_status_get::ROUTE,
            )
            .expect("identity account-status-get LocalOnly state is mounted");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            make_shared_clock(1_000),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    #[allow(clippy::expect_used)]
    fn finalized_identity_v1_policies_get_router(
        repo: TestRepo,
        auth_sink: RecordingAuthAuditSink,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::policies_get::RouteMarker,
            PolicyQueryService,
        >,
    ) {
        let IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        } = identity_local_only_ancillary_services();
        let domain = super::IdentityDomain::new(super::IdentityDomainDeps {
            credential_security: test_credential_security(&login),
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles: repo.roles,
            binding_reads: repo.binding_reads,
            policies: repo.policies,
            resource_attribute_reads: repo.resource_attribute_reads,
            clock: make_shared_clock(1_000),
        });
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        let (_, routes) = finalized.pop().expect("identity Primary routes");
        let proof = ::httpserve::prove_local_only_mounted_route_state::<PolicyQueryService, _>(
            &routes,
            &::generated::http::identity_v1::policies_get::ROUTE,
        )
        .expect("identity policies-get LocalOnly state is mounted");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            make_shared_clock(1_000),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    #[allow(clippy::expect_used)]
    fn finalized_identity_v1_policies_list_router(
        repo: TestRepo,
        auth_sink: RecordingAuthAuditSink,
    ) -> (
        axum::Router,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::policies_list::RouteMarker,
            PolicyQueryService,
        >,
    ) {
        let IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        } = identity_local_only_ancillary_services();
        let domain = super::IdentityDomain::new(super::IdentityDomainDeps {
            credential_security: test_credential_security(&login),
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles: repo.roles,
            binding_reads: repo.binding_reads,
            policies: repo.policies,
            resource_attribute_reads: repo.resource_attribute_reads,
            clock: make_shared_clock(1_000),
        });
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        let (_, routes) = finalized.pop().expect("identity Primary routes");
        let proof = ::httpserve::prove_local_only_mounted_route_state::<PolicyQueryService, _>(
            &routes,
            &::generated::http::identity_v1::policies_list::ROUTE,
        )
        .expect("identity policies-list LocalOnly state is mounted");
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::FederatedAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = ::httpserve::finalize_primary_auth_with_audit(
            routes,
            plan,
            httpserve::AuditSinkHandle::new(auth_sink),
            make_shared_clock(1_000),
            authorizer,
        )
        .expect("finalize Primary auth")
        .into_router_for_test();
        (router, proof)
    }

    #[allow(clippy::expect_used)]
    fn mounted_identity_resource_authorizer(
        repo: TestRepo,
    ) -> (
        Arc<ContractAuthorizer>,
        ::httpserve::LocalOnlyMountedRouteProof<
            ::generated::http::identity_v1::roles_list::RouteMarker,
            RolesListHandlerState,
        >,
    ) {
        let IdentityLocalOnlyAncillaryServices {
            login,
            refresh,
            rbac_admin,
            policy_manage,
        } = identity_local_only_ancillary_services();
        let domain = super::IdentityDomain::new(super::IdentityDomainDeps {
            credential_security: test_credential_security(&login),
            login,
            refresh,
            rbac_admin,
            policy_manage,
            roles: repo.roles,
            binding_reads: repo.binding_reads,
            policies: repo.policies,
            resource_attribute_reads: repo.resource_attribute_reads,
            clock: make_shared_clock(1_000),
        });
        let authorizer = Arc::clone(&domain.common.authorizer);
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        let (_, routes) = finalized.pop().expect("identity Primary routes");
        let proof = ::httpserve::prove_local_only_mounted_route_state::<RolesListHandlerState, _>(
            &routes,
            &::generated::http::identity_v1::roles_list::ROUTE,
        )
        .expect("identity roles-list LocalOnly state is mounted");
        (authorizer, proof)
    }

    fn user_evidence(subject: &str) -> AuthorizedSubject {
        AuthorizedSubject::for_test(tid(CANON_TENANT), vocab::PrincipalKind::User, subject, None)
    }

    fn admin_evidence(subject: &str) -> AuthorizedSubject {
        AuthorizedSubject::for_test(
            tid(CANON_TENANT),
            vocab::PrincipalKind::Admin,
            subject,
            None,
        )
    }

    fn projection_for(fields: &[ProjectionField]) -> Option<ResourceProjection> {
        match RouteAuthorizationDecision::allow_with_unmasked_fields(fields) {
            RouteAuthorizationDecision::AllowWithProjection(projection) => Some(projection),
            _ => None,
        }
    }

    fn with_auth(router: axum::Router, auth: AuthorizedSubject) -> axum::Router {
        router.layer(axum::Extension(auth))
    }

    #[allow(clippy::expect_used)]
    fn role(id: &str, name: &str, permissions: &[&str]) -> Role {
        Role::hydrate(
            id,
            name,
            &permissions
                .iter()
                .map(|permission| (*permission).to_string())
                .collect::<Vec<_>>(),
        )
        .expect("valid role")
    }

    fn empty_policy_repo() -> Arc<DynPolicyRepo<'static>> {
        Arc::from(DynPolicyRepo::new_box(
            crate::internal::mem::InMemPolicyRepo::new(),
        ))
    }

    fn empty_resource_attribute_repo() -> Arc<DynResourceAttributeReadRepo<'static>> {
        resource_attribute_repo(crate::internal::mem::InMemResourceAttributeRepo::new())
    }

    fn resource_attribute_repo(
        repo: crate::internal::mem::InMemResourceAttributeRepo,
    ) -> Arc<DynResourceAttributeReadRepo<'static>> {
        Arc::from(DynResourceAttributeReadRepo::new_box(repo))
    }

    struct IncompleteKnownResourceAttributeRepo;

    impl ResourceAttributeReadRepo for IncompleteKnownResourceAttributeRepo {
        async fn resolve_effective(
            &self,
            _tenant_scope: TenantRepoScope,
            _scope: PolicyRouteScope,
            _resource_id: ResourceAttributeResourceId,
            _required_keys: Vec<ResourceAttributeKey>,
            _at: SystemTime,
        ) -> Result<ResourceAttributeResolution, IdentityError> {
            Ok(ResourceAttributeResolution::Known(Vec::new()))
        }
    }

    fn incomplete_known_resource_attribute_repo() -> Arc<DynResourceAttributeReadRepo<'static>> {
        Arc::from(DynResourceAttributeReadRepo::new_box(
            IncompleteKnownResourceAttributeRepo,
        ))
    }

    fn empty_policy_manage(
        now_secs: u64,
    ) -> (Arc<PolicyManageService>, Arc<DynPolicyRepo<'static>>) {
        policy_manage_from_repo(crate::internal::mem::InMemPolicyRepo::new(), now_secs)
    }

    fn policy_manage_from_repo(
        repo: crate::internal::mem::InMemPolicyRepo,
        now_secs: u64,
    ) -> (Arc<PolicyManageService>, Arc<DynPolicyRepo<'static>>) {
        let policies: Arc<DynPolicyRepo<'static>> = Arc::from(DynPolicyRepo::new_box(repo.clone()));
        let lifecycle: Arc<DynPolicyLifecycle<'static>> =
            Arc::from(DynPolicyLifecycle::new_box(repo));
        (
            Arc::new(PolicyManageService::new(
                Arc::clone(&policies),
                lifecycle,
                make_clock(now_secs),
            )),
            policies,
        )
    }

    fn policy_manage_state_from_repo(
        repo: crate::internal::mem::InMemPolicyRepo,
        now_secs: u64,
    ) -> (
        PolicyManageHandlerState,
        crate::internal::mem::InMemPolicyRepo,
    ) {
        policy_manage_state_from_repo_with_permissions(
            repo,
            now_secs,
            &["identity:policy:manage:identity:policy:read"],
        )
    }

    fn policy_manage_state_from_repo_with_permissions(
        repo: crate::internal::mem::InMemPolicyRepo,
        now_secs: u64,
        management_permissions: &[&str],
    ) -> (
        PolicyManageHandlerState,
        crate::internal::mem::InMemPolicyRepo,
    ) {
        let (service, _) = policy_manage_from_repo(repo.clone(), now_secs);
        let manager_role = role(
            "role-policy-manager",
            "Policy Manager",
            management_permissions,
        );
        let manager_role_id = manager_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), manager_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &manager_role_id,
                    CANON_USER,
                ),
            ));
        let policies: Arc<DynPolicyRepo<'static>> = Arc::from(DynPolicyRepo::new_box(repo.clone()));
        let authorizer = Arc::new(ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(now_secs),
        ));
        (
            PolicyManageHandlerState {
                service,
                authorizer,
            },
            repo,
        )
    }

    fn policy_manage_router(state: PolicyManageHandlerState) -> axum::Router {
        let read = PolicyQueryService {
            policies: Arc::clone(&state.authorizer.policies),
        };
        axum::Router::new()
            .route(
                "/policies",
                httpserve::with_producer_witness_for_test(
                    post(policies_create_handler).with_state(state.clone()),
                    POLICIES_CREATE_PRODUCER,
                ),
            )
            .route(
                "/policies",
                get(policies_list_handler).with_state(read.clone()),
            )
            .route(
                "/policies/{policyId}",
                httpserve::with_producer_witness_for_test(
                    put(policies_update_handler).with_state(state.clone()),
                    POLICIES_UPDATE_PRODUCER,
                ),
            )
            .route(
                "/policies/{policyId}",
                get(policies_get_handler).with_state(read),
            )
            .route(
                "/policies/{policyId}/deactivate",
                httpserve::with_producer_witness_for_test(
                    post(policies_deactivate_handler).with_state(state),
                    POLICIES_DEACTIVATE_PRODUCER,
                ),
            )
    }

    fn policy_repo(repo: crate::internal::mem::InMemPolicyRepo) -> Arc<DynPolicyRepo<'static>> {
        Arc::from(DynPolicyRepo::new_box(repo))
    }

    fn policy_create_body(policy_id: &str) -> serde_json::Value {
        policy_create_body_for(
            policy_id,
            POLICIES_GET_HTTP_SPEC.route.contract_id(),
            "identity:policy:read",
        )
    }

    fn policy_create_body_for(
        policy_id: &str,
        contract_id: &'static str,
        permission: &'static str,
    ) -> serde_json::Value {
        serde_json::json!({
            "policyId": policy_id,
            "contractId": contract_id,
            "permission": permission,
            "effectiveFrom": 1_700_000_000,
            "rules": [{
                "condition": {
                    "attribute": POLICY_ATTR_PRINCIPAL_KIND,
                    "operator": { "kind": "eq", "value": "admin" }
                },
                "effect": "allow"
            }]
        })
    }

    fn policy_update_body(expected_version: u32) -> serde_json::Value {
        policy_update_body_for(
            expected_version,
            POLICIES_GET_HTTP_SPEC.route.contract_id(),
            "identity:policy:read",
        )
    }

    fn policy_update_body_for(
        expected_version: u32,
        contract_id: &'static str,
        permission: &'static str,
    ) -> serde_json::Value {
        serde_json::json!({
            "expectedVersion": expected_version,
            "contractId": contract_id,
            "permission": permission,
            "effectiveFrom": 1_700_000_010,
            "rules": [{
                "condition": {
                    "attribute": POLICY_ATTR_PRINCIPAL_KIND,
                    "operator": { "kind": "eq", "value": "admin" }
                },
                "effect": "deny"
            }]
        })
    }

    fn policy_deactivate_body(expected_version: u32) -> serde_json::Value {
        serde_json::json!({ "expectedVersion": expected_version })
    }

    #[allow(clippy::expect_used)]
    fn route_policy(
        id: &str,
        contract_id: &'static str,
        permission: RoutePermissionId,
        effect: PolicyEffect,
        obligations: PolicyObligations,
    ) -> Policy {
        route_policy_with_condition(
            id,
            contract_id,
            permission,
            PolicyCondition::new(
                AttributeKey::new(POLICY_ATTR_PRINCIPAL_KIND),
                Operator::Eq(AttributeValue::new("admin")),
            ),
            effect,
            obligations,
        )
    }

    #[allow(clippy::expect_used)]
    fn route_policy_with_condition(
        id: &str,
        contract_id: &'static str,
        permission: RoutePermissionId,
        condition: PolicyCondition,
        effect: PolicyEffect,
        obligations: PolicyObligations,
    ) -> Policy {
        let rule = PolicyRule::with_obligations(condition, effect, obligations);
        Policy::build(
            id,
            tid(CANON_TENANT),
            PolicyRouteScope::parse(contract_id, permission.as_str()).expect("valid route scope"),
            SystemTime::UNIX_EPOCH,
            None,
            vec![rule],
        )
        .expect("valid policy")
    }

    #[allow(clippy::expect_used)]
    fn resource_id() -> ResourceAttributeResourceId {
        ResourceAttributeResourceId::parse(RESOURCE_ID).expect("resource id")
    }

    #[allow(clippy::expect_used)]
    fn route_resource() -> httpserve::RouteResource {
        httpserve::RouteResource::new(RESOURCE_ID).expect("route resource")
    }

    #[allow(clippy::expect_used)]
    fn owner_resource_attribute(
        effective_from_secs: u64,
        effective_until_secs: Option<u64>,
    ) -> crate::domain::ResourceAttribute {
        crate::domain::ResourceAttribute::build(
            tid(CANON_TENANT),
            PolicyRouteScope::parse("other.contract", "identity:policy:read").expect("scope"),
            resource_id(),
            ResourceAttributeKey::parse("resource.owner").expect("key"),
            AttributeValue::new(CANON_USER),
            SystemTime::UNIX_EPOCH + Duration::from_secs(effective_from_secs),
            effective_until_secs.map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
        )
        .expect("resource attribute")
    }

    fn owner_policy(id: &str) -> Policy {
        route_policy_with_condition(
            id,
            "other.contract",
            vocab::RoutePermissionId::IdentityPolicyRead,
            PolicyCondition::new(
                AttributeKey::new("resource.owner"),
                Operator::EqAttr(PipAttributeKey::principal_id()),
            ),
            PolicyEffect::Allow,
            PolicyObligations::empty(),
        )
    }

    fn synthetic_global_spec() -> HttpSpec {
        HttpSpec {
            mount_key: "other_v1::contract",
            route: vocab::HttpRouteEvidence::from_static(
                vocab::HttpContractOwner::domain("other"),
                vocab::ContractBinding::from_static(
                    "other",
                    "other.contract",
                    "v1",
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                ),
                "/api/v1/other/{resourceId}",
                "GET",
                vocab::HttpSuccessStatus::new(200),
                vocab::HttpIdempotency::Idempotent,
                vocab::HttpRouteAuth::Permission(vocab::RoutePermissionId::IdentityPolicyRead),
                Some("resourceId"),
                false,
                vocab::http::HttpResourceSharing::Global,
                vocab::HttpConsistencyLevel::LocalOnly,
                vocab::HttpEffectProfile::new(&[
                    vocab::HttpEffectKind::Auth,
                    vocab::HttpEffectKind::Read,
                ]),
            ),
            local_tx: None,
            resource_sharing: ::generated::http::HttpResourceSharingSpec {
                mode: HttpResourceSharingMode::Global,
                reason: Some("shared synthetic test route"),
            },
            projection_fields: &[],
            headers: &[],
        }
    }

    #[allow(clippy::expect_used)]
    async fn rbac_state_with_role(
        role: Role,
    ) -> (
        RbacHandlerState,
        crate::internal::mem::InMemRoleBindingLifecycle,
    ) {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(tenant_repo_scope(tid(CANON_TENANT)), role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
            tid(CANON_TENANT),
            role.id(),
            CANON_USER,
        );
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let binding_lifecycle: Arc<DynRoleBindingLifecycle<'static>> = Arc::from(
            crate::ports::DynRoleBindingLifecycle::new_box(bindings.clone()),
        );
        let service = Arc::new(RbacAdminService::new(
            roles,
            binding_lifecycle,
            make_clock(1_000),
        ));
        (RbacHandlerState { service }, bindings)
    }

    #[test]
    fn login_service_and_login_future_are_send_sync() {
        fn assert_send<T: Send>(_: T) {}
        fn assert_send_sync<T: Send + Sync>(_: &T) {}

        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);
        assert_send_sync(&svc);
        assert_send(svc.login(
            login_receipt(),
            tid(CANON_TENANT),
            IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            },
        ));
    }

    #[test]
    fn identity_handler_states_are_clone_send_sync_static() {
        fn assert_state<T: Clone + Send + Sync + 'static>() {}
        assert_state::<Arc<ContractAuthorizer>>();
        assert_state::<RbacHandlerState>();
        assert_state::<CredentialSecurityHandlerState>();
        assert_state::<RolesListHandlerState>();
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn identity_rbac_handler_futures_are_send() {
        fn assert_send<T: Send>(_: T) {}

        let (rbac, _) =
            rbac_state_with_role(role("role-admin", "Admin", &["identity:role:assign"])).await;
        let assign_req = Request::builder()
            .body(Body::empty())
            .expect("assign request");
        assert_send(roles_assign_handler(
            ProducerMarker::for_test(ROLES_ASSIGN_PRODUCER),
            State(rbac),
            Path("role-admin".to_string()),
            assign_req,
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_service_can_back_axum_handler_state() -> Result<(), Box<dyn std::error::Error>> {
        use axum::response::IntoResponse;
        use testkit::ContractRequest;

        let capture = CapturingAuthGrantLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let router = axum::Router::new().route(
            "/login",
            axum::routing::post({
                let svc = svc.clone();
                move |body: axum::body::Bytes| {
                    let svc = svc.clone();
                    async move {
                        let request: IdentityLoginRequest =
                            serde_json::from_slice(&body).expect("valid login request");
                        let response = svc
                            .login(login_receipt(), tid(CANON_TENANT), request)
                            .await
                            .expect("login ok");
                        (axum::http::StatusCode::OK, axum::Json(response)).into_response()
                    }
                }
            }),
        );

        let resp = testkit::call(
            router,
            ContractRequest::post("/login").json(&IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            }),
        )
        .await?;

        resp.ensure_status(axum::http::StatusCode::OK)?;
        let decoded: IdentityLoginResponse = resp.json()?;
        assert!(!decoded.data.session_id.is_empty());
        assert_eq!(decoded.data.expires_at, 4_600);
        assert_eq!(capture.count(), 1, "handler login 应写入一次 co-tx");
        Ok(())
    }

    // ── 测试 1：login 成功 ────────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_success_persists_once_and_response_correct() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let resp = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");

        assert!(!resp.data.session_id.is_empty());
        assert_eq!(resp.data.expires_at, 1_000 + 3_600);

        // UoW 写恰一次。
        assert_eq!(capture.count(), 1, "co-tx 写应恰一次");
        let writes = capture.writes.lock().unwrap_or_else(|e| e.into_inner());
        let (grant, event) = &writes[0];
        let entry = event.entry();
        let envelope = event.envelope();

        // AuthGrant 字段正确。user_id = canonical user id（**非** 登录标识 "alice"）。
        assert_eq!(grant.id().as_str(), resp.data.session_id);
        assert_eq!(
            grant.user_id(),
            uid(CANON_USER),
            "grant user_id = canonical user id，非登录标识"
        );
        assert_eq!(grant.tenant(), tid(CANON_TENANT));
        assert_eq!(
            grant.created_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert_eq!(
            grant.expires_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 + 3_600)
        );

        // EventId ≠ session_id（敏感标识不得进 broker metadata）。
        assert_eq!(entry.topic().as_str(), SESSION_CREATED_SPEC.topic());
        assert!(!entry.idem_key().as_str().is_empty(), "EventId 不应为空");
        assert_ne!(
            entry.idem_key().as_str(),
            resp.data.session_id,
            "EventId 不应等于 session_id（F1）"
        );

        // payload 字段。subject 是 typed `uuid::Uuid`（generated `format:uuid`，#1277 F1）= canonical user id，
        // **非**登录标识——旧实现写 username 会让 wire decode 失败（非 UUID 不可表达）。
        let payload: IdentitySessionCreatedPayload =
            serde_json::from_slice(entry.payload()).expect("decode payload");
        assert_eq!(
            payload.subject,
            uid(CANON_USER).as_uuid(),
            "payload.subject = canonical user id（typed uuid::Uuid），非登录标识 \"alice\""
        );
        assert_eq!(payload.tenant_id, CANON_TENANT);
        assert_eq!(payload.session_id, resp.data.session_id);
        assert_eq!(payload.occurred_at, 1_000);

        // envelope 携带 generated `CONTRACT` 绑定（domain + contract_id + version + schema_hash 同源，#1193/#1618）；
        // subject_id = canonical user id（登录标识不进 broker metadata）。
        assert_eq!(*envelope.contract(), SESSION_CREATED_SPEC.contract());
        assert_eq!(envelope.subject_id().as_str(), CANON_USER);
        assert_eq!(envelope.actor().kind(), vocab::PrincipalKind::User);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_auth_grant_expiration_overflow_fails_before_write() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1, u64::MAX);

        let err = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("expiration overflow must fail");

        assert!(matches!(err, LoginError::AuthGrantTimeOverflow));
        assert_eq!(capture.count(), 0, "expiration overflow → 零 co-tx 写");
    }

    // ── 测试 2：login 密码错 ──────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_wrong_password_returns_invalid_credentials_zero_writes() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "wrong".to_string(),
                },
            )
            .await
            .expect_err("must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(capture.count(), 0, "密码错 → 零 co-tx 写");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_second_account_gate_rejection_is_unauthenticated_not_internal_error() {
        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed login credential");
        let second_gate = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed second gate");
        let current = second_gate
            .find(tenant_repo_scope(tenant), user)
            .await
            .expect("read second gate")
            .expect("second gate state");
        let (_, suspended) = current
            .transition(
                crate::AccountStatus::Suspended,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_001),
            )
            .expect("suspend second gate")
            .into_parts();
        second_gate.set_account_security_for_test(suspended);

        let capture = CapturingAuthGrantLifecycle::default();
        let auth_grants = make_auth_grant_services(
            capture.clone(),
            DynAccountSecurityReadRepo::new_box(second_gate),
            make_clock(1_000),
            Duration::from_secs(3_600),
        );
        let service = Arc::new(LoginService::new(
            Arc::from(DynCredentialRepo::new_box(credentials)),
            auth_grants,
            make_clock(1_000),
            Duration::from_secs(3_600),
        ));
        let body = Bytes::from(
            serde_json::to_vec(&IdentityLoginRequest {
                username: "alice".to_owned(),
                password: "correct-horse".to_owned(),
            })
            .expect("encode login"),
        );

        let response =
            login_handler_bytes(service, login_receipt(), tenant, body, "rid-second-gate").await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(capture.count(), 0, "second gate rejection has zero effects");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_all_non_active_states_and_password_results_have_zero_downstream_effects() {
        #[derive(Clone)]
        struct CountingSigner(Arc<AtomicUsize>);
        impl diport::Signer for CountingSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(diport::Signature::new(b"unexpected-signature".to_vec()))
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let tenant = tid(CANON_TENANT);
        for status in [
            crate::AccountStatus::Suspended,
            crate::AccountStatus::Locked,
            crate::AccountStatus::Deactivated,
        ] {
            for password in ["correct-horse", "wrong"] {
                let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
                    "alice",
                    uid(CANON_USER),
                    "correct-horse",
                    tenant,
                )
                .expect("seed");
                let state = credentials
                    .find(tenant_repo_scope(tenant), uid(CANON_USER))
                    .await
                    .expect("read")
                    .expect("state");
                let (_, blocked) = state
                    .transition(status, SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                    .expect("enter non-active state")
                    .into_parts();
                credentials.set_account_security_for_test(blocked);

                let sign_calls = Arc::new(AtomicUsize::new(0));
                let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                    Arc::new(CountingSigner(Arc::clone(&sign_calls))),
                    make_clock(1_000),
                    authn::JwtIssuerConfig::rss_access(
                        authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                            .expect("non-empty signing key id"),
                        diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                        "https://test.example",
                        "test-audience",
                        Duration::from_secs(900),
                    ),
                )
                .expect("issuer");
                let capture = CapturingAuthGrantLifecycle::default();
                let auth_grants = AuthGrantServices::from_provider(
                    capture.clone(),
                    DynAccountSecurityReadRepo::new_box(credentials.clone()),
                    Arc::new(issuer),
                    make_clock(1_000),
                    Duration::from_secs(3_600),
                );
                let service = LoginService::new(
                    Arc::from(DynCredentialRepo::new_box(credentials)),
                    auth_grants,
                    make_clock(1_000),
                    Duration::from_secs(3_600),
                );

                let result = service
                    .login(
                        login_receipt(),
                        tenant,
                        IdentityLoginRequest {
                            username: "alice".to_owned(),
                            password: password.to_owned(),
                        },
                    )
                    .await;
                assert!(
                    matches!(result, Err(LoginError::InvalidCredentials)),
                    "{status:?}/{password}"
                );
                assert_eq!(
                    sign_calls.load(Ordering::SeqCst),
                    0,
                    "{status:?}/{password}"
                );
                assert_eq!(capture.inner.refresh_len(), 0, "{status:?}/{password}");
                assert_eq!(
                    capture.count(),
                    0,
                    "{status:?}/{password} creates no session or outbox"
                );
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn login_rejects_authenticated_state_tenant_mismatch_before_downstream_effects() {
        struct TenantMismatchCredentialRepo(AccountSecurityState);
        impl CredentialRepo for TenantMismatchCredentialRepo {
            async fn find_by_user_id(
                &self,
                _scope: TenantRepoScope,
                _user_id: ids::UserId,
            ) -> Result<Option<Credential>, IdentityError> {
                unreachable!("login does not split credential reads")
            }

            async fn authenticate(
                &self,
                _scope: TenantRepoScope,
                _login: LoginIdentifier,
                _candidate: secure::RawPassword,
                _now: SystemTime,
            ) -> Result<AuthOutcome, IdentityError> {
                Ok(AuthOutcome::Authenticated(self.0.clone()))
            }

            async fn insert(
                &self,
                _scope: TenantRepoScope,
                _credential: Credential,
            ) -> Result<(), IdentityError> {
                unreachable!("login does not insert credentials")
            }
        }

        struct PanicSigner;
        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("tenant mismatch must precede token signing")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let mismatched = AccountSecurityState::try_from(crate::AccountSecuritySnapshot {
            tenant: tid(OTHER_TENANT),
            user_id: uid(CANON_USER),
            status: crate::AccountStatus::Active,
            authn_epoch: 0,
            version: 1,
            status_changed_at: SystemTime::UNIX_EPOCH,
            updated_at: SystemTime::UNIX_EPOCH,
        })
        .expect("mismatched state");
        let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            Arc::new(PanicSigner),
            make_clock(1_000),
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://test.example",
                "test-audience",
                Duration::from_secs(900),
            ),
        )
        .expect("issuer");
        let capture = CapturingAuthGrantLifecycle::default();
        let auth_grants = AuthGrantServices::from_provider(
            capture.clone(),
            seeded_account_reader(),
            Arc::new(issuer),
            make_clock(1_000),
            Duration::from_secs(3_600),
        );
        let service = LoginService::new(
            Arc::from(DynCredentialRepo::new_box(TenantMismatchCredentialRepo(
                mismatched,
            ))),
            auth_grants,
            make_clock(1_000),
            Duration::from_secs(3_600),
        );

        assert!(matches!(
            service
                .login(
                    login_receipt(),
                    tid(CANON_TENANT),
                    IdentityLoginRequest {
                        username: "alice".to_owned(),
                        password: "correct-horse".to_owned(),
                    },
                )
                .await,
            Err(LoginError::InvalidCredentials)
        ));
        assert_eq!(capture.inner.refresh_len(), 0);
        assert_eq!(capture.count(), 0, "no session or outbox write");
    }

    // ── 测试 3：login 未知用户 ────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_unknown_subject_returns_invalid_credentials_zero_writes() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "mallory".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("must reject unknown");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(capture.count(), 0);
    }

    // ── 测试 4：login 账户已锁（lockout 门控在验签前） ────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_locked_account_rejected_before_verify_zero_writes() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        // 连续 5 次错密码触发锁定（窗口内 FixedClock 固定在 now_secs=1_000）。
        for _ in 0..5 {
            let _ = svc
                .login(
                    login_receipt(),
                    tid(CANON_TENANT),
                    IdentityLoginRequest {
                        username: "alice".to_string(),
                        password: "bad-pw".to_string(),
                    },
                )
                .await;
        }
        // 此时账户已锁，UoW 写仍为 0（5 次都是密码错 → 零写）。
        assert_eq!(capture.count(), 0);

        // 第 6 次用**正确**密码，被 lockout 门控拒（InvalidCredentials，且零 UoW 写）。
        let err = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("locked account must reject even correct pw");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(capture.count(), 0, "lockout 门控 → 零 UoW 写");
    }

    // ── 测试 5：login 跨租（凭据在 CANON_TENANT，用 OTHER_TENANT 登录）────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_cross_tenant_returns_invalid_credentials_zero_writes() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
                login_receipt(),
                tid(OTHER_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("cross-tenant must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(capture.count(), 0);
    }

    // ── 测试 12：login route group 声明（保留既有测试）────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_domain_declares_login_route_group() {
        let domain = seed_domain(CapturingAuthGrantLifecycle::default(), 1_000, 3_600);
        let reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, LOGIN_ROUTE_PREFIX);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn federated_identity_domain_excludes_all_local_session_routes() {
        let domain = seed_federated_domain(1_000);
        let mut registry = bootstrap::compose(&[&domain]).expect("compose federated identity");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize federated identity routes");
        let (listener, routes) = finalized.pop().expect("federated Primary routes");
        assert_eq!(listener, ListenerKind::Primary);
        let evidence = routes.route_evidence();

        for local_session_contract in [
            LOGIN_HTTP_SPEC.route.contract_id(),
            REFRESH_HTTP_SPEC.route.contract_id(),
            PASSWORD_CHANGE_HTTP_SPEC.route.contract_id(),
            LOGOUT_HTTP_SPEC.route.contract_id(),
        ] {
            assert!(
                evidence
                    .iter()
                    .all(|route| route.contract_id() != local_session_contract),
                "{local_session_contract} must be structurally absent for federated Primary"
            );
        }
        assert!(
            evidence
                .iter()
                .any(|route| route.contract_id() == PROFILE_HTTP_SPEC.route.contract_id()),
            "non-session identity routes remain mounted"
        );
    }

    #[test]
    fn login_service_and_erased_deps_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<LoginService<TestSigner>>();
        assert_send_sync::<Box<DynCredentialRepo<'static>>>();
        assert_send_sync::<Box<DynAuthGrantLifecycle<'static>>>();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_login_route_mount_consumes_generated_spec() {
        let domain = seed_domain(CapturingAuthGrantLifecycle::default(), 1_000, 3_600);
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routes = reg.finalize_routes().expect("finalize routes");
        // identity domain 在 1 个 Primary listener 上挂载多条 identity HTTP 路由，
        // finalize_routes 按 listener 分组 → len() 仍 1（计组/listener，非 route 数）。
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, ListenerKind::Primary);
        assert_eq!(
            LOGIN_HTTP_SPEC
                .route
                .path()
                .strip_prefix(LOGIN_ROUTE_PREFIX)
                .expect("generated path has identity prefix"),
            ::generated::http::identity_v1::login::PATH
                .strip_prefix(LOGIN_ROUTE_PREFIX)
                .expect("generated path has prefix")
        );
        assert_eq!(
            LOGIN_HTTP_SPEC.route.contract_id(),
            ::generated::http::identity_v1::login::CONTRACT_ID
        );
        assert_eq!(LOGIN_HTTP_SPEC.route.method(), "POST");
        assert_eq!(LOGIN_HTTP_SPEC.route.auth(), HttpRouteAuth::Public);
        assert_eq!(
            ROLES_ASSIGN_HTTP_SPEC.route.auth(),
            HttpRouteAuth::Permission(vocab::RoutePermissionId::IdentityRoleAssign),
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_domain_registers_primary_authorizer_once() {
        let domain = seed_domain(CapturingAuthGrantLifecycle::default(), 1_000, 3_600);
        let mut registry = bootstrap::Registry::new();

        domain.init(&mut registry).expect("first init succeeds");
        assert!(registry.take_primary_authorizer().is_ok());

        domain
            .init(&mut registry)
            .expect("init after authorizer take succeeds once");
        assert!(matches!(
            domain.init(&mut registry),
            Err(KernelError::Invariant)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn identity_http_route_specs_match_nested_v1_contracts_and_mounted_router() {
        let domain = seed_domain(CapturingAuthGrantLifecycle::default(), 1_000, 3_600);
        let mut registry = bootstrap::compose(&[&domain]).expect("compose identity domain");
        let authorizer = registry
            .take_primary_authorizer()
            .expect("identity registers Primary authorizer");
        let mut finalized = registry
            .finalize_routes()
            .expect("finalize identity routes");
        assert_eq!(finalized.len(), 1, "identity owns one Primary listener");
        let (listener, routes) = finalized.pop().expect("identity Primary routes");
        assert_eq!(listener, ListenerKind::Primary);
        let plan = primitives::AuthPlan::new(
            ListenerKind::Primary,
            primitives::AuthScheme::RssAccessToken,
        )
        .expect("Primary JWT auth plan");
        let router = httpserve::finalize_primary_auth(routes, plan, authorizer)
            .expect("finalize Primary auth")
            .into_router_for_test();
        let cases = [
            (&LOGIN_HTTP_SPEC, "POST", "/login", None),
            (&REFRESH_HTTP_SPEC, "POST", "/refresh", None),
            (
                &ROLES_ASSIGN_HTTP_SPEC,
                "POST",
                "/roles/{roleId}/bindings",
                Some(vocab::RoutePermissionId::IdentityRoleAssign),
            ),
            (
                &ROLES_REVOKE_HTTP_SPEC,
                "DELETE",
                "/roles/{roleId}/bindings/{subject}",
                Some(vocab::RoutePermissionId::IdentityRoleRevoke),
            ),
            (
                &ROLES_LIST_HTTP_SPEC,
                "GET",
                "/roles",
                Some(vocab::RoutePermissionId::IdentityRoleRead),
            ),
            (
                &POLICIES_CREATE_HTTP_SPEC,
                "POST",
                "/policies",
                Some(vocab::RoutePermissionId::IdentityPolicyCreate),
            ),
            (
                &POLICIES_UPDATE_HTTP_SPEC,
                "PUT",
                "/policies/{policyId}",
                Some(vocab::RoutePermissionId::IdentityPolicyUpdate),
            ),
            (
                &POLICIES_DEACTIVATE_HTTP_SPEC,
                "POST",
                "/policies/{policyId}/deactivate",
                Some(vocab::RoutePermissionId::IdentityPolicyDeactivate),
            ),
            (
                &POLICIES_GET_HTTP_SPEC,
                "GET",
                "/policies/{policyId}",
                Some(vocab::RoutePermissionId::IdentityPolicyRead),
            ),
            (
                &POLICIES_LIST_HTTP_SPEC,
                "GET",
                "/policies",
                Some(vocab::RoutePermissionId::IdentityPolicyRead),
            ),
            (
                &PROFILE_HTTP_SPEC,
                "GET",
                "/profile",
                Some(vocab::RoutePermissionId::IdentityProfileRead),
            ),
            (
                &PASSWORD_CHANGE_HTTP_SPEC,
                "POST",
                "/password/change",
                Some(vocab::RoutePermissionId::IdentityProfileWrite),
            ),
            (
                &LOGOUT_HTTP_SPEC,
                "POST",
                "/logout",
                Some(vocab::RoutePermissionId::IdentitySessionLogoutCurrent),
            ),
        ];

        for (spec, method, path, permission) in cases {
            assert_eq!(spec.route.method(), method);
            assert_eq!(
                spec.route
                    .path()
                    .strip_prefix(LOGIN_ROUTE_PREFIX)
                    .expect("generated path has identity prefix"),
                path
            );
            let expected_auth = permission.map_or(HttpRouteAuth::Public, HttpRouteAuth::Permission);
            assert_eq!(spec.route.auth(), expected_auth);

            let request_path = spec
                .route
                .path()
                .replace("{roleId}", "role-test")
                .replace("{subject}", "subject-test")
                .replace("{policyId}", "policy-test");
            let request_method = axum::http::Method::from_bytes(method.as_bytes())
                .expect("generated method is valid HTTP");
            let response = testkit::call(
                router.clone(),
                ContractRequest::method(request_method, request_path),
            )
            .await
            .expect("mounted route request");
            assert_ne!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{} {} must be mounted on the finalized router",
                method,
                spec.route.path()
            );
            assert_ne!(
                response.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{} {} must accept its generated method",
                method,
                spec.route.path()
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_assign_handler_authed_returns_201_and_emits() {
        let (service, bindings) =
            rbac_state_with_role(role("role-admin", "Admin", &["identity:role:assign"])).await;
        let router = with_auth(
            axum::Router::new().route(
                "/roles/{roleId}/bindings",
                httpserve::with_producer_witness_for_test(
                    post(roles_assign_handler).with_state(service),
                    ROLES_ASSIGN_PRODUCER,
                ),
            ),
            admin_evidence(CANON_USER),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/roles/role-admin/bindings").json(&IdentityRolesAssignRequest {
                subject: "target-user".to_string(),
            }),
        )
        .await
        .expect("call");

        resp.ensure_status(StatusCode::CREATED).expect("201");
        let decoded: IdentityRolesAssignResponse = resp.json().expect("json");
        assert!(decoded.data.assigned);
        assert!(
            bindings.has_binding(
                tid(CANON_TENANT),
                role("role-admin", "Admin", &[]).id(),
                "target-user"
            ),
            "assign 应写 binding"
        );
        assert_eq!(bindings.emitted().len(), 1, "assign 应发 role-assigned");
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn contract_authorizer_limits_rss_user_grants_to_explicitly_supported_routes() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role(
                "role-admin",
                "Admin",
                &[
                    "identity:role:assign",
                    "identity:account-security:read",
                    "identity:account-security:write",
                ],
            ),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    role("role-admin", "Admin", &[]).id(),
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );
        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: ROLES_ASSIGN_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::IdentityRoleAssign,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: ACCOUNT_STATUS_SET_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::IdentityAccountSecurityWrite,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(httpserve::RouteResource::new(CANON_USER).expect("route resource")),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);

        let HttpRouteAuth::Permission(get_permission) = ACCOUNT_STATUS_GET_HTTP_SPEC.route.auth()
        else {
            panic!("account-status GET must require a typed permission")
        };
        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: ACCOUNT_STATUS_GET_HTTP_SPEC.route.contract_id(),
                permission: get_permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(httpserve::RouteResource::new(CANON_USER).expect("route resource")),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[test]
    #[allow(clippy::panic)]
    fn account_status_get_uses_a_distinct_read_permission() {
        let HttpRouteAuth::Permission(permission) = ACCOUNT_STATUS_GET_HTTP_SPEC.route.auth()
        else {
            panic!("account-status GET must require a typed permission")
        };

        assert_eq!(permission.as_str(), "identity:account-security:read");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_allows_builtin_admin_settings_permissions_without_role_binding() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        for spec in [
            SETTINGS_CONFIG_HTTP_SPEC,
            SETTINGS_SECRET_HTTP_SPEC,
            SETTINGS_CONFIG_GET_HTTP_SPEC,
            SETTINGS_CONFIG_DELETE_HTTP_SPEC,
            SETTINGS_CONFIG_ROLLBACK_HTTP_SPEC,
        ] {
            let auth = spec.route.auth();
            assert!(matches!(auth, HttpRouteAuth::Permission(_)));
            let HttpRouteAuth::Permission(permission) = auth else {
                continue;
            };
            let decision = authorizer
                .authorize(RouteAuthorizationRequest {
                    contract_id: spec.route.contract_id(),
                    permission,
                    tenant_id: Some(tid(CANON_TENANT)),
                    principal_kind: vocab::PrincipalKind::Admin,
                    principal_id: CANON_USER.to_string(),
                    federated_permissions: None,
                    resource: None,
                })
                .await;
            assert_eq!(
                decision,
                RouteAuthorizationDecision::Allow,
                "trusted Admin gets built-in settings permission for {}",
                spec.route.contract_id()
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_denies_unbound_user_settings_permissions() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        for spec in [
            SETTINGS_CONFIG_HTTP_SPEC,
            SETTINGS_SECRET_HTTP_SPEC,
            SETTINGS_CONFIG_GET_HTTP_SPEC,
            SETTINGS_CONFIG_DELETE_HTTP_SPEC,
            SETTINGS_CONFIG_ROLLBACK_HTTP_SPEC,
        ] {
            let auth = spec.route.auth();
            assert!(matches!(auth, HttpRouteAuth::Permission(_)));
            let HttpRouteAuth::Permission(permission) = auth else {
                continue;
            };
            let decision = authorizer
                .authorize(RouteAuthorizationRequest {
                    contract_id: spec.route.contract_id(),
                    permission,
                    tenant_id: Some(tid(CANON_TENANT)),
                    principal_kind: vocab::PrincipalKind::User,
                    principal_id: CANON_USER.to_string(),
                    federated_permissions: None,
                    resource: None,
                })
                .await;
            assert_eq!(
                decision,
                RouteAuthorizationDecision::Deny,
                "unbound user is denied {}",
                spec.route.contract_id()
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_allows_rss_user_runtime_inventory_only_with_durable_grant() {
        let inventory_role = role(
            "role-runtime-inventory-reader",
            "Runtime inventory reader",
            &[vocab::RoutePermissionId::RuntimeInventoryRead.as_str()],
        );
        let inventory_role_id = inventory_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), inventory_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &inventory_role_id,
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: RUNTIME_INVENTORY_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::RuntimeInventoryRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);

        for request in [
            RouteAuthorizationRequest {
                contract_id: RUNTIME_INVENTORY_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::RuntimeInventoryRead,
                tenant_id: None,
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            },
            RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::RuntimeInventoryRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            },
            RouteAuthorizationRequest {
                contract_id: RUNTIME_INVENTORY_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            },
        ] {
            assert_eq!(
                authorizer.authorize(request).await,
                RouteAuthorizationDecision::Deny
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_denies_rss_user_runtime_inventory_without_durable_grant() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: RUNTIME_INVENTORY_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::RuntimeInventoryRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_empty_durable_store_grants_nothing_without_baseline() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_durable_allow_permits_without_rbac_binding() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-allow",
                "other.contract",
                vocab::RoutePermissionId::IdentityPolicyRead,
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[test]
    fn policy_attr_rejects_overlong_value_fail_closed() {
        assert!(matches!(
            policy_attr(POLICY_ATTR_PRINCIPAL_ID, &"a".repeat(257)),
            Err(AuthReject::Forbidden)
        ));
        assert!(
            matches!(
                policy_attr(POLICY_ATTR_PRINCIPAL_ID, &"a".repeat(256)),
                Ok(attr) if attr.value().as_str().len() == 256
            ),
            "exact-256 principal id must parse"
        );
    }

    #[test]
    fn route_policy_attributes_rejects_overlong_principal_id() {
        let ctx = AuthSubjectContext {
            tenant: tid(CANON_TENANT),
            subject: "a".repeat(257),
            kind: vocab::PrincipalKind::Admin,
            projection: ResourceProjection::default_masked(),
        };
        let request = RouteAuthorizationRequest {
            contract_id: "other.contract",
            permission: vocab::RoutePermissionId::IdentityPolicyRead,
            tenant_id: Some(tid(CANON_TENANT)),
            principal_kind: vocab::PrincipalKind::Admin,
            principal_id: ctx.subject.clone(),
            federated_permissions: None,
            resource: None,
        };
        assert!(matches!(
            route_policy_attributes(&ctx, &request),
            Err(AuthReject::Forbidden)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_denies_overlong_principal_id_before_like_eval() {
        // Allow 策略用 Like("*") 匹配 principal.id；超长 subject 必须在 PIP 注入阶段 fail-closed Deny，
        // 不得把超长 value 送进 glob_match。
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy_with_condition(
                "policy-like-allow",
                "other.contract",
                vocab::RoutePermissionId::IdentityPolicyRead,
                PolicyCondition::new(
                    AttributeKey::new(POLICY_ATTR_PRINCIPAL_ID),
                    Operator::Like(crate::domain::GlobPattern::parse("*").expect("glob")),
                ),
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: "a".repeat(257),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_resource_attr_allow_permits_owner_policy_without_rbac_binding() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(
            crate::internal::mem::InMemPolicyRepo::new().with_policy(owner_policy("policy-owner")),
        );
        let resource_attrs = resource_attribute_repo(
            crate::internal::mem::InMemResourceAttributeRepo::new()
                .with_attribute(owner_resource_attribute(0, None)),
        );
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            resource_attrs,
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(route_resource()),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_missing_resource_attr_denies_before_rbac_baseline() {
        let baseline_role = role(
            "role-resource-admin",
            "Resource Admin",
            &["identity:policy:read"],
        );
        let baseline_role_id = baseline_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), baseline_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &baseline_role_id,
                    CANON_USER,
                ),
            ));
        let policies = policy_repo(
            crate::internal::mem::InMemPolicyRepo::new()
                .with_policy(owner_policy("policy-missing-resource-attr")),
        );
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(route_resource()),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_stale_resource_attr_denies_before_rbac_baseline() {
        let baseline_role = role(
            "role-resource-admin",
            "Resource Admin",
            &["identity:policy:read"],
        );
        let baseline_role_id = baseline_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), baseline_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &baseline_role_id,
                    CANON_USER,
                ),
            ));
        let policies = policy_repo(
            crate::internal::mem::InMemPolicyRepo::new()
                .with_policy(owner_policy("policy-stale-resource-attr")),
        );
        let resource_attrs = resource_attribute_repo(
            crate::internal::mem::InMemResourceAttributeRepo::new()
                .with_attribute(owner_resource_attribute(0, Some(500))),
        );
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            resource_attrs,
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(route_resource()),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_resource_attr_store_error_denies_before_rbac_baseline() {
        let baseline_role = role(
            "role-resource-admin",
            "Resource Admin",
            &["identity:policy:read"],
        );
        let baseline_role_id = baseline_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), baseline_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &baseline_role_id,
                    CANON_USER,
                ),
            ));
        let policies = policy_repo(
            crate::internal::mem::InMemPolicyRepo::new()
                .with_policy(owner_policy("policy-resource-attr-store-error")),
        );
        let resource_attrs = resource_attribute_repo(
            crate::internal::mem::InMemResourceAttributeRepo::failing_reads(),
        );
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            resource_attrs,
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(route_resource()),
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_incomplete_known_resource_attrs_denies_before_rbac_baseline() {
        let baseline_role = role(
            "role-resource-admin",
            "Resource Admin",
            &["identity:policy:read"],
        );
        let baseline_role_id = baseline_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), baseline_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &baseline_role_id,
                    CANON_USER,
                ),
            ));
        let policies = policy_repo(
            crate::internal::mem::InMemPolicyRepo::new()
                .with_policy(owner_policy("policy-incomplete-known-resource-attr")),
        );
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            incomplete_known_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(route_resource()),
            })
            .await;
        assert_eq!(
            decision,
            RouteAuthorizationDecision::Deny,
            "repo Known payloads must still cover every required resource attr before baseline"
        );
    }

    #[test]
    fn resource_attribute_global_route_spec_denies_dynamic_attr_resolution() {
        let ctx = AuthSubjectContext {
            tenant: tid(CANON_TENANT),
            subject: CANON_USER.to_string(),
            kind: vocab::PrincipalKind::User,
            projection: ResourceProjection::default_masked(),
        };
        let request = RouteAuthorizationRequest {
            contract_id: "other.contract",
            permission: vocab::RoutePermissionId::IdentityPolicyRead,
            tenant_id: Some(tid(CANON_TENANT)),
            principal_kind: vocab::PrincipalKind::User,
            principal_id: CANON_USER.to_string(),
            federated_permissions: None,
            resource: Some(route_resource()),
        };
        let specs = [synthetic_global_spec()];

        assert!(route_resource_sharing_is_global_in(&request, &specs));
        assert!(matches!(
            request_resource_attribute_id_in(&ctx, &request, &specs),
            Err(AuthReject::Forbidden)
        ));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_durable_deny_overrides_builtin_baseline() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let auth = SETTINGS_CONFIG_HTTP_SPEC.route.auth();
        assert!(matches!(auth, HttpRouteAuth::Permission(_)));
        let HttpRouteAuth::Permission(permission) = auth else {
            return;
        };
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-deny",
                SETTINGS_CONFIG_HTTP_SPEC.route.contract_id(),
                permission,
                PolicyEffect::Deny,
                PolicyObligations::empty(),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.route.contract_id(),
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_non_empty_obligation_denies_at_route_gate() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let auth = SETTINGS_CONFIG_HTTP_SPEC.route.auth();
        assert!(matches!(auth, HttpRouteAuth::Permission(_)));
        let HttpRouteAuth::Permission(permission) = auth else {
            return;
        };
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-obligation",
                SETTINGS_CONFIG_HTTP_SPEC.route.contract_id(),
                permission,
                PolicyEffect::Allow,
                PolicyObligations::new(Some(vocab::ScopedTenant::Tenant), vec![]),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.route.contract_id(),
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_role_field_permissions_become_projection()
    -> Result<(), String> {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role(
                "role-audit",
                "Audit",
                &[
                    vocab::AUDIT_READ_PERMISSION.as_str(),
                    vocab::AUDIT_FIELD_ACTOR_PERMISSION.as_str(),
                    vocab::AUDIT_FIELD_TENANT_ID_PERMISSION.as_str(),
                ],
            ),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    role("role-audit", "Audit", &[]).id(),
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(vocab::ProjectionField::AuditActor));
        assert!(projection.allows(vocab::ProjectionField::AuditTenantId));
        assert!(!projection.allows(vocab::ProjectionField::AuditResourceId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_read_without_field_permission_stays_masked() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role(
                "role-audit",
                "Audit",
                &[vocab::AUDIT_READ_PERMISSION.as_str()],
            ),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    role("role-audit", "Audit", &[]).id(),
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_super_admin_audit_read_defaults_masked() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::SuperAdmin,
                principal_id: "super-admin".to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[test]
    fn audit_projection_field_registry_is_generated_from_contract() {
        let fields = AUDIT_LIST_HTTP_SPEC.projection_fields;
        assert_eq!(fields.len(), 3);
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::AuditTenantId
                && field.permission == vocab::AUDIT_FIELD_TENANT_ID_PERMISSION
                && field.obligation_key == vocab::AUDIT_TENANT_ID_FIELD_OBLIGATION
                && field.response_path == "data[].tenantId"
        }));
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::AuditActor
                && field.permission == vocab::AUDIT_FIELD_ACTOR_PERMISSION
                && field.obligation_key == vocab::AUDIT_ACTOR_FIELD_OBLIGATION
                && field.response_path == "data[].actor"
        }));
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::AuditResourceId
                && field.permission == vocab::AUDIT_FIELD_RESOURCE_ID_PERMISSION
                && field.obligation_key == vocab::AUDIT_RESOURCE_ID_FIELD_OBLIGATION
                && field.response_path == "data[].resourceId"
        }));
    }

    #[test]
    fn profile_projection_field_registry_is_generated_from_contract() {
        let fields = PROFILE_HTTP_SPEC.projection_fields;
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::IdentityProfileSubject
                && field.permission == vocab::IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION
                && field.obligation_key == vocab::IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION
                && field.response_path == "data.subject"
        }));
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::IdentityProfileTenantId
                && field.permission == vocab::IDENTITY_PROFILE_FIELD_TENANT_ID_PERMISSION
                && field.obligation_key == vocab::IDENTITY_PROFILE_TENANT_ID_FIELD_OBLIGATION
                && field.response_path == "data.tenantId"
        }));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_policy_field_mask_becomes_projection()
    -> Result<(), String> {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-audit-field",
                AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                vocab::AUDIT_READ_PERMISSION,
                PolicyEffect::Allow,
                PolicyObligations::new(
                    None,
                    vec![AttributeKey::new(vocab::AUDIT_TENANT_ID_FIELD_OBLIGATION)],
                ),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(!projection.allows(vocab::ProjectionField::AuditActor));
        assert!(projection.allows(vocab::ProjectionField::AuditTenantId));
        assert!(!projection.allows(vocab::ProjectionField::AuditResourceId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_profile_projection_policy_field_mask_becomes_projection()
    -> Result<(), String> {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-profile-field",
                PROFILE_HTTP_SPEC.route.contract_id(),
                vocab::RoutePermissionId::IdentityProfileRead,
                PolicyEffect::Allow,
                PolicyObligations::new(
                    None,
                    vec![AttributeKey::new(
                        vocab::IDENTITY_PROFILE_SUBJECT_FIELD_OBLIGATION,
                    )],
                ),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: PROFILE_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::IdentityProfileRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(vocab::ProjectionField::IdentityProfileSubject));
        assert!(!projection.allows(vocab::ProjectionField::IdentityProfileTenantId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_profile_self_scoped_role_field_permission_becomes_projection()
    -> Result<(), String> {
        let profile_role = role(
            "role-profile-fields",
            "Profile Fields",
            &[vocab::IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION.as_str()],
        );
        let profile_role_id = profile_role.id().clone();
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new()
                .with_role_entity(tid(CANON_TENANT), profile_role),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    &profile_role_id,
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: PROFILE_HTTP_SPEC.route.contract_id(),
                permission: vocab::RoutePermissionId::IdentityProfileRead,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: Some(httpserve::RouteResource::new(CANON_USER).expect("self resource")),
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(vocab::ProjectionField::IdentityProfileSubject));
        assert!(!projection.allows(vocab::ProjectionField::IdentityProfileTenantId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_unknown_field_mask_obligation_denies() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-unknown-field",
                AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                vocab::AUDIT_READ_PERMISSION,
                PolicyEffect::Allow,
                PolicyObligations::new(None, vec![AttributeKey::new("audit.email")]),
            ),
        ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.route.contract_id(),
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_policy_store_error_denies_before_baseline() {
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::failing_reads());
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            policies,
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );
        let auth = SETTINGS_CONFIG_HTTP_SPEC.route.auth();
        assert!(matches!(auth, HttpRouteAuth::Permission(_)));
        let HttpRouteAuth::Permission(permission) = auth else {
            return;
        };

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.route.contract_id(),
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_allows_non_identity_permission_route_by_rbac() {
        let external_permission = vocab::RoutePermissionId::SettingsConfigPublish;
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role("role-admin", "Admin", &[external_permission.as_str()]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingReadRepo<'static>> =
            Arc::from(crate::ports::DynRoleBindingReadRepo::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
                    tid(CANON_TENANT),
                    role("role-admin", "Admin", &[]).id(),
                    CANON_USER,
                ),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            empty_resource_attribute_repo(),
            make_shared_clock(1_000),
        );
        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: external_permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                federated_permissions: None,
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_assign_handler_malformed_json_and_missing_role_fail_cleanly() {
        let (service, bindings) =
            rbac_state_with_role(role("role-admin", "Admin", &["identity:role:assign"])).await;
        let router = with_auth(
            axum::Router::new().route(
                "/roles/{roleId}/bindings",
                httpserve::with_producer_witness_for_test(
                    post(roles_assign_handler).with_state(service),
                    ROLES_ASSIGN_PRODUCER,
                ),
            ),
            admin_evidence(CANON_USER),
        );

        let bad_json = testkit::call(
            router.clone(),
            ContractRequest::post("/roles/role-admin/bindings")
                .raw_json(br#"{"subject":"target-user""#.to_vec()),
        )
        .await
        .expect("call malformed json");
        bad_json
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("malformed json -> 400");

        let missing_role = testkit::call(
            router,
            ContractRequest::post("/roles/role-missing/bindings").json(
                &IdentityRolesAssignRequest {
                    subject: "target-user".to_string(),
                },
            ),
        )
        .await
        .expect("call missing role");
        missing_role
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("missing role -> 404");
        assert_eq!(bindings.emitted().len(), 0, "失败路径零事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_assign_handler_missing_auth_returns_401_and_zero_writes() {
        let (service, bindings) =
            rbac_state_with_role(role("role-admin", "Admin", &["identity:role:assign"])).await;
        let router = axum::Router::new().route(
            "/roles/{roleId}/bindings",
            httpserve::with_producer_witness_for_test(
                post(roles_assign_handler).with_state(service),
                ROLES_ASSIGN_PRODUCER,
            ),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/roles/role-admin/bindings").json(&IdentityRolesAssignRequest {
                subject: "target-user".to_string(),
            }),
        )
        .await
        .expect("call");

        resp.ensure_status(StatusCode::UNAUTHORIZED)
            .expect("missing auth -> 401");
        assert_eq!(bindings.emitted().len(), 0, "未认证零事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_revoke_handler_returns_typed_revoked_flag() {
        let seeded_role = role("role-admin", "Admin", &["identity:role:revoke"]);
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(tenant_repo_scope(tid(CANON_TENANT)), seeded_role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new()
            .with_binding(tid(CANON_TENANT), seeded_role.id(), CANON_USER)
            .with_binding(tid(CANON_TENANT), seeded_role.id(), "target-user");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let binding_lifecycle: Arc<DynRoleBindingLifecycle<'static>> = Arc::from(
            crate::ports::DynRoleBindingLifecycle::new_box(bindings.clone()),
        );
        let service = Arc::new(RbacAdminService::new(
            Arc::clone(&roles),
            Arc::clone(&binding_lifecycle),
            make_clock(1_000),
        ));
        let state = RbacHandlerState { service };
        let router = with_auth(
            axum::Router::new().route(
                "/roles/{roleId}/bindings/{subject}",
                httpserve::with_producer_witness_for_test(
                    delete(roles_revoke_handler).with_state(state),
                    ROLES_REVOKE_PRODUCER,
                ),
            ),
            admin_evidence(CANON_USER),
        );

        let resp = testkit::call(
            router.clone(),
            ContractRequest::delete("/roles/role-admin/bindings/target-user"),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityRolesRevokeResponse = resp.json().expect("json");
        assert!(decoded.data.revoked);
        assert_eq!(bindings.emitted().len(), 1, "命中 revoke 应发事件");

        let resp2 = testkit::call(
            router,
            ContractRequest::delete("/roles/role-admin/bindings/target-user"),
        )
        .await
        .expect("call");
        resp2.ensure_status(StatusCode::OK).expect("200");
        let decoded2: IdentityRolesRevokeResponse = resp2.json().expect("json");
        assert!(!decoded2.data.revoked, "重复 revoke 幂等 false");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_revoke_handler_rejects_auth_json_subject_and_role_id_errors() {
        let seeded_role = role("role-admin", "Admin", &["identity:role:revoke"]);
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(tenant_repo_scope(tid(CANON_TENANT)), seeded_role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new()
            .with_binding(tid(CANON_TENANT), seeded_role.id(), CANON_USER)
            .with_binding(tid(CANON_TENANT), seeded_role.id(), "target-user");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let binding_lifecycle: Arc<DynRoleBindingLifecycle<'static>> = Arc::from(
            crate::ports::DynRoleBindingLifecycle::new_box(bindings.clone()),
        );
        let service = Arc::new(RbacAdminService::new(
            Arc::clone(&roles),
            Arc::clone(&binding_lifecycle),
            make_clock(1_000),
        ));
        let state = RbacHandlerState { service };
        let router = axum::Router::new().route(
            "/roles/{roleId}/bindings/{subject}",
            httpserve::with_producer_witness_for_test(
                delete(roles_revoke_handler).with_state(state),
                ROLES_REVOKE_PRODUCER,
            ),
        );

        let missing_auth = testkit::call(
            router.clone(),
            ContractRequest::delete("/roles/role-admin/bindings/target-user"),
        )
        .await
        .expect("call missing auth");
        missing_auth
            .ensure_status(StatusCode::UNAUTHORIZED)
            .expect("missing auth -> 401");

        let authed = with_auth(router, admin_evidence(CANON_USER));
        let invalid_role_id = testkit::call(
            authed,
            ContractRequest::delete("/roles/bad%20role/bindings/target-user"),
        )
        .await
        .expect("call invalid role id");
        invalid_role_id
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("invalid roleId path param -> 400");

        assert_eq!(
            bindings.emitted().len(),
            0,
            "revoke negative paths must not emit events"
        );
        assert!(
            bindings.has_binding(tid(CANON_TENANT), seeded_role.id(), "target-user"),
            "revoke negative paths must keep existing binding"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_list_handler_pages_and_rejects_bad_cursor() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role("role-a", "A", &["identity:role:read"]),
        )
        .await
        .expect("save a");
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role("role-b", "B", &["identity:policy:update"]),
        )
        .await
        .expect("save b");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let state = RolesListHandlerState {
            roles: Arc::clone(&roles),
        };
        let router = with_auth(
            axum::Router::new().route("/roles", get(roles_list_handler).with_state(state)),
            admin_evidence(CANON_USER),
        );

        let resp = testkit::call(router.clone(), ContractRequest::get("/roles?limit=1"))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityRolesListResponse = resp.json().expect("json");
        assert_eq!(decoded.data.len(), 1);
        assert_eq!(decoded.data[0].role_id, "role-a");
        assert!(decoded.has_more);
        assert!(decoded.next_cursor.is_some());

        let resp_bad = testkit::call(router, ContractRequest::get("/roles?cursor=not-base64"))
            .await
            .expect("call");
        resp_bad
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("bad cursor -> 400");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_list_handler_rejects_invalid_limit() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tenant_repo_scope(tid(CANON_TENANT)),
            role("role-a", "A", &["identity:role:read"]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleReadRepo<'static>> = Arc::from(DynRoleReadRepo::new_box(repo));
        let state = RolesListHandlerState {
            roles: Arc::clone(&roles),
        };
        let router = axum::Router::new().route("/roles", get(roles_list_handler).with_state(state));

        let invalid_limit = testkit::call(
            with_auth(router, admin_evidence(CANON_USER)),
            ContractRequest::get("/roles?limit=0"),
        )
        .await
        .expect("call invalid limit");
        invalid_limit
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("limit=0 -> 400");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_create_handler_returns_201_and_emits_policy_updated() {
        let (state, repo) =
            policy_manage_state_from_repo(crate::internal::mem::InMemPolicyRepo::new(), 1_000);
        let router = with_auth(policy_manage_router(state), admin_evidence(CANON_USER));

        let resp = testkit::call(
            router,
            ContractRequest::post("/policies").json(&policy_create_body("policy-http-a")),
        )
        .await
        .expect("call create");

        resp.ensure_status(StatusCode::CREATED).expect("201");
        let decoded: serde_json::Value = resp.json().expect("json");
        assert_eq!(decoded["data"]["policyId"], "policy-http-a");
        assert_eq!(repo.emitted().len(), 1, "create 应发 policy-updated");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_create_handler_requires_target_scope_management_permission() {
        let (state, repo) =
            policy_manage_state_from_repo(crate::internal::mem::InMemPolicyRepo::new(), 1_000);
        let router = with_auth(policy_manage_router(state), admin_evidence(CANON_USER));

        let resp = testkit::call(
            router,
            ContractRequest::post("/policies").json(&policy_create_body_for(
                "policy-target-scope",
                ROLES_ASSIGN_HTTP_SPEC.route.contract_id(),
                "identity:role:assign",
            )),
        )
        .await
        .expect("call create without target management permission");

        resp.ensure_status(StatusCode::FORBIDDEN)
            .expect("missing target management permission -> 403");
        assert_eq!(repo.emitted().len(), 0, "forbidden create must not emit");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_update_and_deactivate_require_current_and_new_scope_management_permissions() {
        let repo = crate::internal::mem::InMemPolicyRepo::new();
        let (state, repo) = policy_manage_state_from_repo(repo, 1_000);
        let router = with_auth(policy_manage_router(state), admin_evidence(CANON_USER));
        testkit::call(
            router.clone(),
            ContractRequest::post("/policies").json(&policy_create_body("policy-scope-change")),
        )
        .await
        .expect("create")
        .ensure_status(StatusCode::CREATED)
        .expect("create read policy");

        let update_to_role_assign =
            ContractRequest::put("/policies/policy-scope-change").json(&policy_update_body_for(
                1,
                ROLES_ASSIGN_HTTP_SPEC.route.contract_id(),
                "identity:role:assign",
            ));
        let denied_update = testkit::call(router.clone(), update_to_role_assign)
            .await
            .expect("update without new target management permission");
        denied_update
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("missing new target management permission -> 403");
        assert_eq!(repo.emitted().len(), 1, "forbidden update must not emit");

        let (broad_state, repo) = policy_manage_state_from_repo_with_permissions(
            repo,
            1_000,
            &[
                "identity:policy:manage:identity:policy:read",
                "identity:policy:manage:identity:role:assign",
            ],
        );
        let broad_router = with_auth(
            policy_manage_router(broad_state),
            admin_evidence(CANON_USER),
        );
        testkit::call(
            broad_router.clone(),
            ContractRequest::put("/policies/policy-scope-change").json(&policy_update_body_for(
                1,
                ROLES_ASSIGN_HTTP_SPEC.route.contract_id(),
                "identity:role:assign",
            )),
        )
        .await
        .expect("update with both management permissions")
        .ensure_status(StatusCode::OK)
        .expect("update succeeds");
        assert_eq!(repo.emitted().len(), 2, "successful update emits");

        let (read_only_state, repo) = policy_manage_state_from_repo(repo, 1_000);
        let read_only_router = with_auth(
            policy_manage_router(read_only_state),
            admin_evidence(CANON_USER),
        );
        let denied_current_scope = testkit::call(
            read_only_router.clone(),
            ContractRequest::put("/policies/policy-scope-change").json(&policy_update_body(2)),
        )
        .await
        .expect("update without current target management permission");
        denied_current_scope
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("missing current target management permission -> 403");
        assert_eq!(
            repo.emitted().len(),
            2,
            "forbidden update from unmanaged current scope must not emit"
        );

        let denied_deactivate = testkit::call(
            read_only_router,
            ContractRequest::post("/policies/policy-scope-change/deactivate")
                .json(&policy_deactivate_body(2)),
        )
        .await
        .expect("deactivate without current target management permission");
        denied_deactivate
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("missing current target management permission -> 403");
        assert_eq!(
            repo.emitted().len(),
            2,
            "forbidden deactivate must not emit"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_get_and_list_handlers_do_not_emit_policy_updated() {
        let (state, repo) =
            policy_manage_state_from_repo(crate::internal::mem::InMemPolicyRepo::new(), 1_000);
        let router = with_auth(policy_manage_router(state), admin_evidence(CANON_USER));
        testkit::call(
            router.clone(),
            ContractRequest::post("/policies").json(&policy_create_body("policy-http-read")),
        )
        .await
        .expect("create")
        .ensure_status(StatusCode::CREATED)
        .expect("create 201");
        assert_eq!(repo.emitted().len(), 1);

        let get_resp = testkit::call(
            router.clone(),
            ContractRequest::get("/policies/policy-http-read"),
        )
        .await
        .expect("get");
        get_resp.ensure_status(StatusCode::OK).expect("get 200");
        let get_json: serde_json::Value = get_resp.json().expect("get json");
        assert_eq!(get_json["data"]["policyId"], "policy-http-read");

        let list_resp = testkit::call(router, ContractRequest::get("/policies?limit=1"))
            .await
            .expect("list");
        list_resp.ensure_status(StatusCode::OK).expect("list 200");
        let list_json: serde_json::Value = list_resp.json().expect("list json");
        assert_eq!(list_json["data"][0]["policyId"], "policy-http-read");
        assert_eq!(repo.emitted().len(), 1, "get/list 不应发事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_handlers_map_bad_wire_and_auth_to_400_401_403() {
        let (state, repo) =
            policy_manage_state_from_repo(crate::internal::mem::InMemPolicyRepo::new(), 1_000);
        let router = policy_manage_router(state);

        let missing_auth = testkit::call(
            router.clone(),
            ContractRequest::post("/policies").json(&policy_create_body("policy-missing-auth")),
        )
        .await
        .expect("missing auth");
        missing_auth
            .ensure_status(StatusCode::UNAUTHORIZED)
            .expect("missing auth -> 401");

        let bad_actor = testkit::call(
            with_auth(router.clone(), admin_evidence("not-a-uuid")),
            ContractRequest::post("/policies").json(&policy_create_body("policy-bad-actor")),
        )
        .await
        .expect("bad actor");
        bad_actor
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("non uuid admin actor -> 403");

        let malformed_body = testkit::call(
            with_auth(router.clone(), admin_evidence(CANON_USER)),
            ContractRequest::post("/policies").raw_json(br#"{"policyId":"policy-bad""#.to_vec()),
        )
        .await
        .expect("malformed body");
        malformed_body
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("malformed body -> 400");

        let empty_rules = testkit::call(
            with_auth(router.clone(), admin_evidence(CANON_USER)),
            ContractRequest::post("/policies").json(&serde_json::json!({
                "policyId": "policy-empty-rules",
                "contractId": POLICIES_GET_HTTP_SPEC.route.contract_id(),
                "permission": "identity:policy:read",
                "effectiveFrom": 1_700_000_000,
                "rules": []
            })),
        )
        .await
        .expect("empty rules");
        empty_rules
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("empty rules -> 400");

        let bad_path = testkit::call(
            with_auth(router, admin_evidence(CANON_USER)),
            ContractRequest::put("/policies/bad%20policy").json(&policy_update_body(1)),
        )
        .await
        .expect("bad path");
        bad_path
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("bad policyId path -> 400");

        assert_eq!(repo.emitted().len(), 0, "失败路径零事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_handlers_map_not_found_and_version_conflict() {
        let (state, repo) =
            policy_manage_state_from_repo(crate::internal::mem::InMemPolicyRepo::new(), 1_000);
        let router = with_auth(policy_manage_router(state), admin_evidence(CANON_USER));

        let missing = testkit::call(
            router.clone(),
            ContractRequest::get("/policies/policy-missing"),
        )
        .await
        .expect("missing get");
        missing
            .ensure_status(StatusCode::NOT_FOUND)
            .expect("missing policy -> 404");

        testkit::call(
            router.clone(),
            ContractRequest::post("/policies").json(&policy_create_body("policy-conflict")),
        )
        .await
        .expect("create")
        .ensure_status(StatusCode::CREATED)
        .expect("create 201");

        let conflict = testkit::call(
            router.clone(),
            ContractRequest::put("/policies/policy-conflict").json(&policy_update_body(2)),
        )
        .await
        .expect("conflict update");
        conflict
            .ensure_status(StatusCode::CONFLICT)
            .expect("stale update -> 409");
        assert_eq!(repo.emitted().len(), 1, "conflict 不应发新事件");

        let deactivate = testkit::call(
            router,
            ContractRequest::post("/policies/policy-conflict/deactivate")
                .json(&policy_deactivate_body(1)),
        )
        .await
        .expect("deactivate");
        deactivate
            .ensure_status(StatusCode::OK)
            .expect("deactivate 200");
        let deactivated: serde_json::Value = deactivate.json().expect("deactivate json");
        assert_eq!(deactivated["data"]["deactivated"], true);
        assert_eq!(deactivated["data"]["version"], 2);
        assert_eq!(repo.emitted().len(), 2, "deactivate 应发事件");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn roles_list_local_only_finalized_route_has_canonical_receipt() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = self::finalized_identity_v1_roles_list_router(
            repo_probe.test_repo(),
            auth_sink.clone(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            repo_probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::roles_list::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::roles_list::SPEC
                .route
                .contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::identity_v1::roles_list::SPEC
                            .route
                            .path(),
                    ),
                )
            },
        )
        .await
        .expect("roles-list remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::identity_v1::roles_list::SPEC
                .route
                .contract_id()
        );
        response
            .expect("call finalized roles-list")
            .ensure_status(StatusCode::OK)
            .expect("roles-list 200");
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::RoleList), 1);
        assert_eq!(
            repo_probe.scopes_for(IdentityLocalOnlyRead::RoleList),
            vec![tid(CANON_TENANT)]
        );
        assert_route_auth_event(
            &auth_sink,
            ROLES_LIST_HTTP_SPEC.route.contract_id(),
            vocab::PrincipalKind::Admin,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn account_status_get_local_only_finalized_route_has_canonical_receipt() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = self::finalized_identity_v1_account_status_get_router(
            repo_probe.test_repo(),
            auth_sink.clone(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
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
            ::generated::http::identity_v1::account_status_get::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::account_status_get::SPEC
                .route
                .contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::identity_v1::account_status_get::SPEC
                            .route
                            .path()
                            .replace("{userId}", "11111111-2222-4333-8444-555555555555"),
                    ),
                )
            },
        )
        .await
        .expect("account-status-get remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::identity_v1::account_status_get::SPEC
                .route
                .contract_id()
        );
        let response = response.expect("call finalized account-status-get");
        response
            .ensure_status(StatusCode::OK)
            .expect("account-status-get 200");
        let body: IdentityAccountStatusGetResponse =
            response.json().expect("account-status-get json");
        assert_eq!(body.data.status, IdentityAccountStatusGetDataStatus::Active);
        assert_route_auth_event(
            &auth_sink,
            ACCOUNT_STATUS_GET_HTTP_SPEC.route.contract_id(),
            vocab::PrincipalKind::Admin,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_get_local_only_finalized_route_has_canonical_receipt() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = self::finalized_identity_v1_policies_get_router(
            repo_probe.test_repo(),
            auth_sink.clone(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            repo_probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::policies_get::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::policies_get::SPEC
                .route
                .contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::identity_v1::policies_get::SPEC
                            .route
                            .path()
                            .replace("{policyId}", "policy-a"),
                    ),
                )
            },
        )
        .await
        .expect("policies-get remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::identity_v1::policies_get::SPEC
                .route
                .contract_id()
        );
        response
            .expect("call finalized policies-get")
            .ensure_status(StatusCode::OK)
            .expect("policies-get 200");
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::PolicyFind), 1);
        assert_route_auth_event(
            &auth_sink,
            POLICIES_GET_HTTP_SPEC.route.contract_id(),
            vocab::PrincipalKind::Admin,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn policies_list_local_only_finalized_route_has_canonical_receipt() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = self::finalized_identity_v1_policies_list_router(
            repo_probe.test_repo(),
            auth_sink.clone(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            repo_probe.business_write_effects.handle(),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::policies_list::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::policies_list::SPEC
                .route
                .contract_id(),
            observers,
            move || {
                ::testkit::call(
                    router,
                    ::testkit::ContractRequest::get(
                        ::generated::http::identity_v1::policies_list::SPEC
                            .route
                            .path(),
                    ),
                )
            },
        )
        .await
        .expect("policies-list remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::identity_v1::policies_list::SPEC
                .route
                .contract_id()
        );
        response
            .expect("call finalized policies-list")
            .ensure_status(StatusCode::OK)
            .expect("policies-list 200");
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::PolicyList), 1);
        assert_eq!(
            repo_probe.scopes_for(IdentityLocalOnlyRead::PolicyList),
            vec![tid(CANON_TENANT)]
        );
        assert_route_auth_event(
            &auth_sink,
            POLICIES_LIST_HTTP_SPEC.route.contract_id(),
            vocab::PrincipalKind::Admin,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_roles_list_pages_and_validates_limit_and_cursor() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let (router, proof) = self::finalized_identity_v1_roles_list_router(
            repo_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let base = ::generated::http::identity_v1::roles_list::SPEC
            .route
            .path();
        let first = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                repo_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
            ),
            || ::testkit::call(
                router.clone(),
                ContractRequest::get(format!("{base}?limit=1")),
            ),
        )
        .await
        .expect("roles first page remains LocalOnly")
        .expect("roles first page");
        first.ensure_status(StatusCode::OK).expect("first page 200");
        let first: IdentityRolesListResponse = first.json().expect("first page json");
        assert_eq!(first.data.len(), 1);
        assert_eq!(first.data[0].role_id, "role-a");
        assert!(first.has_more);
        let cursor = first.next_cursor.expect("first page cursor");
        let second = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                repo_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
            ),
            || ::testkit::call(
                router.clone(),
                ContractRequest::get(format!("{base}?limit=1&cursor={cursor}")),
            ),
        )
        .await
        .expect("roles second page remains LocalOnly")
        .expect("roles second page");
        let second: IdentityRolesListResponse = second.json().expect("second page json");
        assert_eq!(second.data.len(), 1);
        assert_eq!(second.data[0].role_id, "role-b");
        assert!(!second.has_more);
        for bad_query in ["limit=0", "limit=501", "cursor=not-base64"] {
            ::testkit::local_only::assert_local_only(
                ::testkit::local_only::LocalOnlyObservers::new(
                    repo_probe.business_write_effects.handle(),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
                ),
                || ::testkit::call(
                    router.clone(),
                    ContractRequest::get(format!("{base}?{bad_query}")),
                ),
            )
            .await
            .expect("invalid roles query remains LocalOnly")
            .expect("invalid roles query")
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("invalid roles query -> 400");
        }
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::RoleList), 2);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_policies_list_pages_and_validates_limit_and_cursor() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let (router, proof) = self::finalized_identity_v1_policies_list_router(
            repo_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let base = ::generated::http::identity_v1::policies_list::SPEC
            .route
            .path();
        let first = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                repo_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
            ),
            || ::testkit::call(
                router.clone(),
                ContractRequest::get(format!("{base}?limit=1")),
            ),
        )
        .await
        .expect("policies first page remains LocalOnly")
        .expect("policies first page");
        first.ensure_status(StatusCode::OK).expect("first page 200");
        let first: serde_json::Value = first.json().expect("first page json");
        assert_eq!(first["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(first["data"][0]["policyId"], "policy-a");
        assert_eq!(first["hasMore"], true);
        let cursor = first["nextCursor"].as_str().expect("first page cursor");
        let second = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                repo_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
            ),
            || ::testkit::call(
                router.clone(),
                ContractRequest::get(format!("{base}?limit=1&cursor={cursor}")),
            ),
        )
        .await
        .expect("policies second page remains LocalOnly")
        .expect("policies second page");
        let second: serde_json::Value = second.json().expect("second page json");
        assert_eq!(second["data"].as_array().map(Vec::len), Some(1));
        assert_eq!(second["data"][0]["policyId"], "policy-b");
        assert_eq!(second["hasMore"], false);
        for bad_query in ["limit=0", "limit=501", "cursor=not-base64"] {
            ::testkit::local_only::assert_local_only(
                ::testkit::local_only::LocalOnlyObservers::new(
                    repo_probe.business_write_effects.handle(),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
                ),
                || ::testkit::call(
                    router.clone(),
                    ContractRequest::get(format!("{base}?{bad_query}")),
                ),
            )
            .await
            .expect("invalid policies query remains LocalOnly")
            .expect("invalid policies query")
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("invalid policies query -> 400");
        }
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::PolicyList), 2);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_policies_get_maps_success_invalid_id_and_not_found() {
        let repo_probe = IdentityLocalOnlyReadProbe::default();
        let (router, proof) = self::finalized_identity_v1_policies_get_router(
            repo_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let template = ::generated::http::identity_v1::policies_get::SPEC
            .route
            .path();
        for (policy_id, expected) in [
            ("policy-a", StatusCode::OK),
            ("bad%20policy", StatusCode::BAD_REQUEST),
            ("policy-z", StatusCode::NOT_FOUND),
        ] {
            ::testkit::local_only::assert_local_only(
                ::testkit::local_only::LocalOnlyObservers::new(
                    repo_probe.business_write_effects.handle(),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&proof),
                    ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&proof),
                ),
                || ::testkit::call(
                    router.clone(),
                    ContractRequest::get(template.replace("{policyId}", policy_id)),
                ),
            )
            .await
            .expect("policies-get remains LocalOnly")
            .expect("policies-get call")
            .ensure_status(expected)
            .expect("policies-get status");
        }
        assert_eq!(repo_probe.call_count(IdentityLocalOnlyRead::PolicyFind), 2);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_identity_reads_reject_missing_auth_missing_permission_and_cross_tenant() {
        let missing_auth_probe = IdentityLocalOnlyReadProbe::default();
        let missing_auth_sink = RecordingAuthAuditSink::default();
        let (missing_auth_router, missing_auth_proof) =
            self::finalized_identity_v1_roles_list_router(
                missing_auth_probe.test_repo(),
                missing_auth_sink.clone(),
            );
        ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                missing_auth_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&missing_auth_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&missing_auth_proof),
            ),
            move || ::testkit::call(
                missing_auth_router,
                ContractRequest::get(
                    ::generated::http::identity_v1::roles_list::SPEC
                        .route
                        .path(),
                ),
            ),
        )
        .await
        .expect("missing auth remains LocalOnly")
        .expect("missing auth call")
        .ensure_status(StatusCode::UNAUTHORIZED)
        .expect("missing auth -> 401");
        assert!(missing_auth_sink.events().is_empty());

        let missing_permission_probe = IdentityLocalOnlyReadProbe::without_grant();
        let missing_permission_sink = RecordingAuthAuditSink::default();
        let (missing_permission_router, missing_permission_proof) =
            self::finalized_identity_v1_policies_list_router(
                missing_permission_probe.test_repo(),
                missing_permission_sink.clone(),
            );
        let missing_permission_router =
            missing_permission_router.layer(::axum::Extension(httpserve::Authenticated::new(
                primitives::RequiredScheme::FederatedAccessToken,
                vocab::PrincipalKind::Admin,
                CANON_USER,
                Some(tid(CANON_TENANT)),
            )));
        ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                missing_permission_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&missing_permission_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&missing_permission_proof),
            ),
            move || ::testkit::call(
                missing_permission_router,
                ContractRequest::get(
                    ::generated::http::identity_v1::policies_list::SPEC
                        .route
                        .path(),
                ),
            ),
        )
        .await
        .expect("missing permission remains LocalOnly")
        .expect("missing permission call")
        .ensure_status(StatusCode::FORBIDDEN)
        .expect("missing permission -> 403");
        assert_eq!(
            missing_permission_probe.call_count(IdentityLocalOnlyRead::PolicyList),
            0
        );
        assert_route_auth_event(
            &missing_permission_sink,
            POLICIES_LIST_HTTP_SPEC.route.contract_id(),
            vocab::PrincipalKind::Admin,
            diport::AuditOutcome::Failure {
                reason: "forbidden",
            },
        );

        let cross_tenant_probe = IdentityLocalOnlyReadProbe::default();
        let cross_tenant_sink = RecordingAuthAuditSink::default();
        let (cross_tenant_router, cross_tenant_proof) =
            self::finalized_identity_v1_policies_get_router(
                cross_tenant_probe.test_repo(),
                cross_tenant_sink.clone(),
            );
        let other_tenant = tid("00000000-0000-4000-8000-000000000abc");
        let cross_tenant_router =
            cross_tenant_router.layer(::axum::Extension(httpserve::Authenticated::new(
                primitives::RequiredScheme::FederatedAccessToken,
                vocab::PrincipalKind::Admin,
                CANON_USER,
                Some(other_tenant),
            )));
        ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                cross_tenant_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&cross_tenant_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&cross_tenant_proof),
            ),
            move || ::testkit::call(
                cross_tenant_router,
                ContractRequest::get(
                    ::generated::http::identity_v1::policies_get::SPEC
                        .route
                        .path()
                        .replace("{policyId}", "policy-a"),
                ),
            ),
        )
        .await
        .expect("cross tenant remains LocalOnly")
        .expect("cross tenant call")
        .ensure_status(StatusCode::FORBIDDEN)
        .expect("cross tenant -> 403");
        assert_eq!(
            cross_tenant_probe.scopes_for(IdentityLocalOnlyRead::BindingList),
            vec![other_tenant]
        );
        assert_eq!(
            cross_tenant_probe.call_count(IdentityLocalOnlyRead::PolicyFind),
            0
        );
        let events = cross_tenant_sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tenant_id, Some(other_tenant));
        assert_eq!(
            events[0].outcome,
            diport::AuditOutcome::Failure {
                reason: "forbidden",
            }
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_identity_target_read_failures_are_internal_errors_without_writes() {
        let roles_probe = IdentityLocalOnlyReadProbe::failing(IdentityLocalOnlyRead::RoleList);
        let (roles_router, roles_proof) = self::finalized_identity_v1_roles_list_router(
            roles_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let roles_router = roles_router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let response = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                roles_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&roles_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&roles_proof),
            ),
            move || ::testkit::call(roles_router, ContractRequest::get(ROLES_LIST_HTTP_SPEC.route.path())),
        )
        .await
        .expect("roles failure remains side-effect free")
        .expect("roles failure response");
        response
            .ensure_status(StatusCode::INTERNAL_SERVER_ERROR)
            .expect("roles read failure -> 500");

        let get_probe = IdentityLocalOnlyReadProbe::failing(IdentityLocalOnlyRead::PolicyFind);
        let (get_router, get_proof) = self::finalized_identity_v1_policies_get_router(
            get_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let get_router = get_router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let response = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                get_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&get_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&get_proof),
            ),
            move || ::testkit::call(get_router, ContractRequest::get(POLICIES_GET_HTTP_SPEC.route.path().replace("{policyId}", "policy-a"))),
        )
        .await
        .expect("policy get failure remains side-effect free")
        .expect("policy get failure response");
        response
            .ensure_status(StatusCode::INTERNAL_SERVER_ERROR)
            .expect("policy get failure -> 500");

        let list_probe = IdentityLocalOnlyReadProbe::failing(IdentityLocalOnlyRead::PolicyList);
        let (list_router, list_proof) = self::finalized_identity_v1_policies_list_router(
            list_probe.test_repo(),
            RecordingAuthAuditSink::default(),
        );
        let list_router = list_router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::Admin,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let response = ::testkit::local_only::assert_local_only(
            ::testkit::local_only::LocalOnlyObservers::new(
                list_probe.business_write_effects.handle(),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(&list_proof),
                ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(&list_proof),
            ),
            move || ::testkit::call(list_router, ContractRequest::get(POLICIES_LIST_HTTP_SPEC.route.path())),
        )
        .await
        .expect("policy list failure remains side-effect free")
        .expect("policy list failure response");
        response
            .ensure_status(StatusCode::INTERNAL_SERVER_ERROR)
            .expect("policy list failure -> 500");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn finalized_identity_synthetic_business_writes_trip_each_local_only_guard() {
        #[derive(Clone, Copy)]
        enum RouteCase {
            RolesList,
            PoliciesGet(&'static str),
            PoliciesList,
            ResourceAuthorizer,
        }

        let cases = [
            (IdentityLocalOnlyRead::RoleFind, RouteCase::RolesList),
            (IdentityLocalOnlyRead::RoleList, RouteCase::RolesList),
            (
                IdentityLocalOnlyRead::PolicyFind,
                RouteCase::PoliciesGet("policy-a"),
            ),
            (IdentityLocalOnlyRead::PolicyList, RouteCase::PoliciesList),
            (IdentityLocalOnlyRead::PolicyEffective, RouteCase::RolesList),
            (IdentityLocalOnlyRead::BindingList, RouteCase::RolesList),
            (
                IdentityLocalOnlyRead::ResourceAttributes,
                RouteCase::ResourceAuthorizer,
            ),
        ];
        assert_eq!(
            cases.map(|(read, _)| read),
            IdentityLocalOnlyRead::ALL,
            "synthetic write matrix must cover every Identity read seam",
        );
        for (read, route_case) in cases {
            let probe = IdentityLocalOnlyReadProbe::with_forbidden_write(read);
            let result = match route_case {
                RouteCase::RolesList => {
                    let (router, proof) = self::finalized_identity_v1_roles_list_router(
                        probe.test_repo(),
                        RecordingAuthAuditSink::default(),
                    );
                    let observers = ::testkit::local_only::LocalOnlyObservers::new(
                        probe.business_write_effects.handle(),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Outbox,
                        >::from_governed(&proof),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Publish,
                        >::from_governed(&proof),
                    );
                    let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
                        primitives::RequiredScheme::FederatedAccessToken,
                        vocab::PrincipalKind::Admin,
                        CANON_USER,
                        Some(tid(CANON_TENANT)),
                    )));
                    ::testkit::local_only::assert_local_only(observers, move || async move {
                        let _response = ::testkit::call(
                            router,
                            ContractRequest::get(ROLES_LIST_HTTP_SPEC.route.path()),
                        )
                        .await;
                    })
                    .await
                }
                RouteCase::PoliciesGet(policy_id) => {
                    let (router, proof) = self::finalized_identity_v1_policies_get_router(
                        probe.test_repo(),
                        RecordingAuthAuditSink::default(),
                    );
                    let observers = ::testkit::local_only::LocalOnlyObservers::new(
                        probe.business_write_effects.handle(),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Outbox,
                        >::from_governed(&proof),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Publish,
                        >::from_governed(&proof),
                    );
                    let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
                        primitives::RequiredScheme::FederatedAccessToken,
                        vocab::PrincipalKind::Admin,
                        CANON_USER,
                        Some(tid(CANON_TENANT)),
                    )));
                    let path = POLICIES_GET_HTTP_SPEC
                        .route
                        .path()
                        .replace("{policyId}", policy_id);
                    ::testkit::local_only::assert_local_only(observers, move || async move {
                        let _response = ::testkit::call(router, ContractRequest::get(path)).await;
                    })
                    .await
                }
                RouteCase::PoliciesList => {
                    let (router, proof) = self::finalized_identity_v1_policies_list_router(
                        probe.test_repo(),
                        RecordingAuthAuditSink::default(),
                    );
                    let observers = ::testkit::local_only::LocalOnlyObservers::new(
                        probe.business_write_effects.handle(),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Outbox,
                        >::from_governed(&proof),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Publish,
                        >::from_governed(&proof),
                    );
                    let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
                        primitives::RequiredScheme::FederatedAccessToken,
                        vocab::PrincipalKind::Admin,
                        CANON_USER,
                        Some(tid(CANON_TENANT)),
                    )));
                    ::testkit::local_only::assert_local_only(observers, move || async move {
                        let _response = ::testkit::call(
                            router,
                            ContractRequest::get(POLICIES_LIST_HTTP_SPEC.route.path()),
                        )
                        .await;
                    })
                    .await
                }
                RouteCase::ResourceAuthorizer => {
                    let (authorizer, proof) =
                        self::mounted_identity_resource_authorizer(probe.test_repo());
                    let observers = ::testkit::local_only::LocalOnlyObservers::new(
                        probe.business_write_effects.handle(),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Outbox,
                        >::from_governed(&proof),
                        ::testkit::local_only::StaticExclusion::<
                            ::testkit::local_only::Publish,
                        >::from_governed(&proof),
                    );
                    ::testkit::local_only::assert_local_only(observers, move || async move {
                        let _decision = authorizer
                            .authorize(RouteAuthorizationRequest {
                                contract_id: "other.contract",
                                permission: vocab::RoutePermissionId::IdentityPolicyRead,
                                tenant_id: Some(tid(CANON_TENANT)),
                                principal_kind: vocab::PrincipalKind::Admin,
                                principal_id: CANON_USER.to_string(),
                                federated_permissions: None,
                                resource: Some(route_resource()),
                            })
                            .await;
                    })
                    .await
                }
            };
            let error = result.expect_err("read seam must trip LocalOnly conformance");
            assert_eq!(
                error,
                ::testkit::local_only::LocalOnlyConformanceError::ForbiddenEffects {
                    business_writes: 1,
                    outbox: 0,
                    publishes: 0,
                },
                "{read:?} must expose its forbidden write",
            );
            assert_eq!(probe.call_count(read), 1, "{read:?} must be exercised once");
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_returns_authenticated_self() {
        let router = with_auth(
            axum::Router::new().route("/profile", get(profile_handler)),
            user_evidence(CANON_USER),
        );
        let resp = testkit::call(router, ContractRequest::get("/profile"))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityProfileResponse = resp.json().expect("json");
        assert_eq!(decoded.data.subject, "<redacted>");
        assert_eq!(decoded.data.tenant_id, "<redacted>");
        assert_eq!(decoded.data.kind, IdentityProfileDataKind::User);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_unmasks_only_explicit_profile_fields() {
        let auth = AuthorizedSubject::for_test_with_projection(
            tid(CANON_TENANT),
            vocab::PrincipalKind::User,
            CANON_USER,
            None,
            projection_for(&[vocab::ProjectionField::IdentityProfileSubject]).expect("projection"),
        );
        let router = with_auth(
            axum::Router::new().route("/profile", get(profile_handler)),
            auth,
        );
        let resp = testkit::call(router, ContractRequest::get("/profile"))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityProfileResponse = resp.json().expect("json");
        assert_eq!(decoded.data.subject, CANON_USER);
        assert_eq!(decoded.data.tenant_id, "<redacted>");
        assert_eq!(decoded.data.kind, IdentityProfileDataKind::User);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_uses_generated_path_and_allows_non_uuid_subject() {
        let subject = "opaque-user-subject";
        let router = with_auth(
            axum::Router::new().route(PROFILE_HTTP_SPEC.route.path(), get(profile_handler)),
            user_evidence(subject),
        );
        let resp = testkit::call(router, ContractRequest::get(PROFILE_HTTP_SPEC.route.path()))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityProfileResponse = resp.json().expect("json");
        assert_eq!(decoded.data.subject, "<redacted>");
        assert_eq!(decoded.data.kind.to_string(), "user");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_missing_auth_returns_401() {
        let router =
            axum::Router::new().route(PROFILE_HTTP_SPEC.route.path(), get(profile_handler));
        let resp = testkit::call(router, ContractRequest::get(PROFILE_HTTP_SPEC.route.path()))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::UNAUTHORIZED)
            .expect("profile missing auth -> 401");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_local_only_finalized_route_keeps_default_projection_masked() {
        let capture = CapturingAuthGrantLifecycle::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = self::finalized_profile_router(capture, &[], auth_sink.clone());
        let router = router.layer(::axum::Extension(httpserve::Authenticated::new(
            primitives::RequiredScheme::FederatedAccessToken,
            vocab::PrincipalKind::User,
            CANON_USER,
            Some(tid(CANON_TENANT)),
        )));
        let observers = ::testkit::local_only::LocalOnlyObservers::new(
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::BusinessWrite>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Outbox>::from_governed(
                &proof,
            ),
            ::testkit::local_only::StaticExclusion::<::testkit::local_only::Publish>::from_governed(
                &proof,
            ),
        );
        #[rustfmt::skip]
        let (response, receipt) = ::testkit::local_only::assert_local_only_with_receipt::<
            ::generated::http::identity_v1::profile::LocalOnlyConformanceMarker,
            _,
            _,
            _,
        >(
            ::generated::http::identity_v1::profile::SPEC
                .route
                .contract_id(),
            observers,
            move || ::testkit::call(router, ::testkit::ContractRequest::get(::generated::http::identity_v1::profile::SPEC.route.path())),
        )
        .await
        .expect("profile remains LocalOnly");
        ::core::assert_eq!(
            receipt.contract_id(),
            ::generated::http::identity_v1::profile::SPEC
                .route
                .contract_id()
        );
        let response = response.expect("call finalized profile route");

        response.ensure_status(StatusCode::OK).expect("profile 200");
        let decoded: IdentityProfileResponse = response.json().expect("profile json");
        assert_eq!(decoded.data.subject, "<redacted>");
        assert_eq!(decoded.data.tenant_id, "<redacted>");
        assert_eq!(decoded.data.kind, IdentityProfileDataKind::User);
        assert_profile_auth_event(
            &auth_sink,
            vocab::PrincipalKind::User,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_local_only_finalized_route_applies_explicit_projection() {
        let capture = CapturingAuthGrantLifecycle::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = finalized_profile_router(
            capture,
            &[vocab::IDENTITY_PROFILE_FIELD_SUBJECT_PERMISSION.as_str()],
            auth_sink.clone(),
        );
        let response = profile_local_only_call(
            router,
            proof,
            Some((vocab::PrincipalKind::User, CANON_USER)),
        )
        .await;

        response.ensure_status(StatusCode::OK).expect("profile 200");
        let decoded: IdentityProfileResponse = response.json().expect("profile json");
        assert_eq!(decoded.data.subject, CANON_USER);
        assert_eq!(decoded.data.tenant_id, "<redacted>");
        assert_eq!(decoded.data.kind, IdentityProfileDataKind::User);
        assert_profile_auth_event(
            &auth_sink,
            vocab::PrincipalKind::User,
            diport::AuditOutcome::Success,
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_local_only_finalized_route_rejects_missing_authentication() {
        let capture = CapturingAuthGrantLifecycle::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = finalized_profile_router(capture, &[], auth_sink.clone());
        let response = profile_local_only_call(router, proof, None).await;

        response
            .ensure_status(StatusCode::UNAUTHORIZED)
            .expect("profile without authentication -> 401");
        assert!(auth_sink.events().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_local_only_finalized_route_rejects_unauthorized_principal() {
        let capture = CapturingAuthGrantLifecycle::default();
        let auth_sink = RecordingAuthAuditSink::default();
        let (router, proof) = finalized_profile_router(capture, &[], auth_sink.clone());
        let response = profile_local_only_call(
            router,
            proof,
            Some((vocab::PrincipalKind::Device, CANON_USER)),
        )
        .await;

        response
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("non-self-service principal -> 403");
        assert_profile_auth_event(
            &auth_sink,
            vocab::PrincipalKind::Device,
            diport::AuditOutcome::Failure {
                reason: "forbidden",
            },
        );
    }

    // ── RefreshService 集成测试 ────────────────────────────────────────────────
    //
    // TestSigner：`diport::Signer` 的最小替身（固定字节签名；shutdown Ok）。
    // 不依赖 adapter crate（rust-standards.md §命名：域 crate 单测不依赖平台 adapter）。

    #[derive(Clone)]
    struct TestSigner;
    impl diport::Signer for TestSigner {
        async fn sign(
            &self,
            _req: diport::SignRequest,
        ) -> Result<diport::Signature, diport::SignerError> {
            Ok(diport::Signature::new(
                b"test-sig-bytes-for-refresh".to_vec(),
            ))
        }
        async fn shutdown(&self) -> Result<(), diport::SignerError> {
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptedRefreshSettlement {
        ReuseContained,
        AlreadyContained,
        Internal,
        Outbox,
        CommitUnknown,
    }

    #[derive(Clone)]
    struct ScriptedRefreshBackend {
        record: Option<RefreshTokenRecord>,
        grant: Option<AuthGrant>,
        account: Option<AccountSecurityState>,
        settlement: ScriptedRefreshSettlement,
    }

    impl RefreshTokenStore for ScriptedRefreshBackend {
        async fn find_by_hash(
            &self,
            _scope: TenantRepoScope,
            _hash: RefreshTokenHash,
        ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
            Ok(self.record.clone())
        }
    }

    impl AuthGrantLifecycle for ScriptedRefreshBackend {
        async fn persist_login_grant(
            &self,
            _receipt: LoginProducerReceipt,
            _scope: TenantRepoScope,
            _mutation: LoginGrantMutation,
            _event: ReviewedEvent,
        ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError> {
            Err(OutboxEmitError::new(std::io::Error::other(
                "refresh response fixture does not persist login grants",
            )))
        }

        async fn find_active(
            &self,
            _scope: TenantRepoScope,
            _grant_id: AuthGrantId,
            _observed_at: SystemTime,
        ) -> Result<Option<AuthGrant>, IdentityError> {
            Ok(self.grant.clone())
        }
    }

    impl AccountSecurityReadRepo for ScriptedRefreshBackend {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _user_id: ids::UserId,
        ) -> Result<Option<AccountSecurityState>, IdentityError> {
            Ok(self.account.clone())
        }
    }

    impl IdentitySecurityLifecycle for ScriptedRefreshBackend {
        async fn execute_refresh(
            &self,
            _receipt: RefreshProducerReceipt,
            _scope: TenantRepoScope,
            _command: RefreshExecutionCommand,
        ) -> Result<RefreshExecutionOutcome, IdentityError> {
            match self.settlement {
                ScriptedRefreshSettlement::ReuseContained => {
                    Ok(RefreshExecutionOutcome::ReuseContained)
                }
                ScriptedRefreshSettlement::AlreadyContained => {
                    Ok(RefreshExecutionOutcome::AlreadyContained)
                }
                ScriptedRefreshSettlement::Internal => Err(IdentityError::ProviderUnavailable(
                    Box::new(std::io::Error::other("internal refresh provider state")),
                )),
                ScriptedRefreshSettlement::Outbox => Err(IdentityError::OutboxFactConflict(
                    consistency::OutboxFactConflict,
                )),
                ScriptedRefreshSettlement::CommitUnknown => Err(IdentityError::Storage(Box::new(
                    std::io::Error::other("commit acknowledgement unknown"),
                ))),
            }
        }

        async fn execute_password_change(
            &self,
            _receipt: PasswordChangeProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::PasswordChangeCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_account_status_set(
            &self,
            _receipt: AccountStatusSetProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::AccountStatusSetCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_current(
            &self,
            _receipt: LogoutCurrentProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutCurrentCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }

        async fn execute_logout_all(
            &self,
            _receipt: LogoutAllProducerReceipt,
            _scope: TenantRepoScope,
            _command: crate::domain::LogoutAllCommand,
        ) -> Result<crate::domain::CredentialSecurityReceipt, IdentityError> {
            Err(provider_unavailable())
        }
    }

    #[allow(clippy::expect_used)]
    fn scripted_refresh_backend(
        record_status: Option<(RefreshStatus, AuthGrantStatus)>,
        account_epoch: u64,
        expired: bool,
        settlement: ScriptedRefreshSettlement,
    ) -> ScriptedRefreshBackend {
        let tenant = tid(CANON_TENANT);
        let user_id = uid(CANON_USER);
        let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_699_999_900);
        let grant_expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_003_600);
        let epoch = authn::AuthnEpoch::hydrate(5).expect("refresh fixture epoch");
        let grant = AuthGrant::new_active(
            tenant,
            user_id,
            issued_at,
            epoch,
            grant_expires_at,
            issued_at,
        )
        .expect("active refresh fixture grant");
        let record = record_status.map(|(status, auth_grant_status)| {
            let id = RefreshTokenId::hydrate("aaaaaaaa-0001-4000-8000-000000000001");
            RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                id: id.clone(),
                tenant,
                auth_grant_id: grant.id().clone(),
                user_id,
                authn_epoch_at_issue: epoch,
                auth_grant_status,
                token_hash: RefreshTokenHash::hydrate(secure::digest("presented-refresh")),
                parent_id: None,
                lineage_id: id,
                status,
                issued_at,
                expires_at: SystemTime::UNIX_EPOCH
                    + Duration::from_secs(if expired {
                        1_699_999_999
                    } else {
                        1_700_003_600
                    }),
            })
            .expect("valid scripted refresh record")
        });
        let account = AccountSecurityState::try_from(crate::ports::AccountSecuritySnapshot {
            tenant,
            user_id,
            status: crate::ports::AccountStatus::Active,
            authn_epoch: account_epoch,
            version: 1,
            status_changed_at: issued_at,
            updated_at: issued_at,
        })
        .expect("valid scripted account state");
        ScriptedRefreshBackend::scripted_refresh_backend_parts(record, grant, account, settlement)
    }

    impl ScriptedRefreshBackend {
        fn scripted_refresh_backend_parts(
            record: Option<RefreshTokenRecord>,
            grant: AuthGrant,
            account: AccountSecurityState,
            settlement: ScriptedRefreshSettlement,
        ) -> Self {
            Self {
                record,
                grant: Some(grant),
                account: Some(account),
                settlement,
            }
        }
    }

    fn scripted_refresh_service(
        backend: ScriptedRefreshBackend,
    ) -> Arc<RefreshService<TestSigner>> {
        Arc::new(RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(backend.clone()),
            Arc::from(DynAuthGrantLifecycle::new_box(backend.clone())),
            Arc::from(DynIdentitySecurityLifecycle::new_box(backend.clone())),
            DynAccountSecurityReadRepo::new_box(backend),
            Arc::new(make_jwt_issuer(make_clock(1_700_000_000))),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ))
    }

    /// 构造用于 RefreshService 测试的 JwtIssuer（ES256，User kind）。
    #[allow(clippy::expect_used)]
    fn make_jwt_issuer(
        clock: Box<dyn diport::Clock>,
    ) -> authn::JwtIssuer<diport::RssAccessProfile, TestSigner> {
        authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            std::sync::Arc::new(TestSigner),
            clock,
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://test.example",
                "test-audience",
                Duration::from_secs(900),
            ),
        )
        .expect("valid jwt issuer config")
    }

    /// 构造 RefreshService（共享 in-mem store；clock 由调用方注入）。
    fn make_refresh_svc(
        store: crate::internal::mem::InMemAuthGrantStore,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> RefreshService<TestSigner> {
        make_refresh_svc_with_accounts(store, seeded_account_reader(), clock, refresh_ttl)
    }

    fn make_refresh_svc_with_accounts(
        store: crate::internal::mem::InMemAuthGrantStore,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> RefreshService<TestSigner> {
        let issuer = make_jwt_issuer(Box::new(FixedClock(clock.now())));
        RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(store.clone()),
            test_lifecycle(store.clone()),
            test_security_lifecycle(store),
            accounts,
            std::sync::Arc::new(issuer),
            clock,
            refresh_ttl,
        )
    }

    fn test_lifecycle(
        store: crate::internal::mem::InMemAuthGrantStore,
    ) -> Arc<DynAuthGrantLifecycle<'static>> {
        Arc::from(DynAuthGrantLifecycle::new_box(store))
    }

    fn test_security_lifecycle(
        store: crate::internal::mem::InMemAuthGrantStore,
    ) -> Arc<DynIdentitySecurityLifecycle<'static>> {
        Arc::from(DynIdentitySecurityLifecycle::new_box(store))
    }

    fn unavailable_security_lifecycle() -> Arc<DynIdentitySecurityLifecycle<'static>> {
        Arc::from(DynIdentitySecurityLifecycle::new_box(
            UnavailableIdentitySecurityLifecycle,
        ))
    }

    #[allow(clippy::expect_used)]
    fn lifecycle_for_record(record: &RefreshTokenRecord) -> Arc<DynAuthGrantLifecycle<'static>> {
        test_lifecycle(lifecycle_store_for_record(record))
    }

    #[allow(clippy::expect_used)]
    fn lifecycle_store_for_record(
        record: &RefreshTokenRecord,
    ) -> crate::internal::mem::InMemAuthGrantStore {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let grant = AuthGrant::hydrate(AuthGrantSnapshot {
            id: record.auth_grant_id().clone(),
            tenant: record.tenant(),
            user_id: record.user_id(),
            auth_time: record.issued_at(),
            authn_epoch_at_issue: record.issuance_epoch(),
            status: AuthGrantStatus::Active,
            expires_at: record.expires_at(),
            created_at: record.issued_at(),
            closed_at: None,
            close_reason: None,
        })
        .expect("refresh fixture grant");
        store
            .seed_login_pair(grant, record.clone())
            .expect("seed grant and refresh fixture");
        store
    }

    fn make_auth_grant_services<P>(
        provider: P,
        accounts: Box<DynAccountSecurityReadRepo<'static>>,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> AuthGrantServices<TestSigner>
    where
        P: AuthGrantProvider,
    {
        let issuer_clock: Box<dyn diport::Clock> = Box::new(FixedClock(clock.now()));
        AuthGrantServices::from_provider(
            provider,
            accounts,
            Arc::new(make_jwt_issuer(issuer_clock)),
            clock,
            refresh_ttl,
        )
    }

    #[allow(clippy::expect_used)]
    fn seeded_account_reader() -> Box<DynAccountSecurityReadRepo<'static>> {
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed refresh account");
        DynAccountSecurityReadRepo::new_box(accounts)
    }

    #[allow(clippy::expect_used)]
    fn seeded_credential_reader() -> Arc<DynCredentialRepo<'static>> {
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed credential reader");
        Arc::from(DynCredentialRepo::new_box(credentials))
    }

    #[allow(clippy::expect_used)]
    async fn issue_test_user<S: diport::Signer + Send + Sync + 'static>(
        svc: &RefreshService<S>,
        store: &crate::internal::mem::InMemAuthGrantStore,
    ) -> authn::RefreshToken {
        issue_test_user_bundle(svc, store).await.refresh
    }

    #[allow(clippy::expect_used)]
    async fn issue_test_user_bundle<S: diport::Signer + Send + Sync + 'static>(
        svc: &RefreshService<S>,
        store: &crate::internal::mem::InMemAuthGrantStore,
    ) -> RefreshBundle {
        let tenant = tid(CANON_TENANT);
        let state = svc
            .accounts
            .find(tenant_repo_scope(tenant), uid(CANON_USER))
            .await
            .expect("read account")
            .expect("seed account");
        let active = state.try_into_active().expect("active account");
        let now = svc.clock.now();
        let grant = AuthGrant::new_active(
            active.tenant(),
            active.user_id(),
            now,
            active.authn_epoch(),
            now + Duration::from_secs(3_600),
            now,
        )
        .expect("test auth grant");
        let (record, pending) = svc
            .prepare_initial(&grant)
            .await
            .expect("prepare initial refresh")
            .into_parts();
        let persistence = LoginGrantMutation::new(grant.clone(), record.clone())
            .into_parts()
            .2;
        store
            .seed_login_pair(grant, record)
            .expect("persist test login pair");
        pending.release(persistence.confirm())
    }

    #[allow(clippy::expect_used)]
    fn decode_access_claims(token: &authn::MintedJwt) -> serde_json::Value {
        use base64::Engine as _;

        let encoded = token
            .as_str()
            .split('.')
            .nth(1)
            .expect("access token payload segment");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .expect("base64url payload");
        serde_json::from_slice(&bytes).expect("access claims json")
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn refresh_initial_rechecks_active_receipt_before_sign_or_insert() {
        struct PanicSigner;

        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("signer must not be called after account state changes")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            user,
            "correct-horse",
            tenant,
        )
        .expect("seed account");
        let state = accounts
            .find(tenant_repo_scope(tenant), user)
            .await
            .expect("read account")
            .expect("account");
        let receipt = state.clone().try_into_active().expect("active receipt");
        let (_, suspended) = state
            .transition(
                crate::AccountStatus::Suspended,
                SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            )
            .expect("suspend")
            .into_parts();
        accounts.set_account_security_for_test(suspended.clone());
        let (_, restored) = suspended
            .transition(
                crate::AccountStatus::Active,
                SystemTime::UNIX_EPOCH + Duration::from_secs(2),
            )
            .expect("restore")
            .into_parts();
        accounts.set_account_security_for_test(restored.clone());
        assert_eq!(restored.status(), crate::AccountStatus::Active);
        assert_ne!(
            restored.clone().try_into_active(),
            Some(receipt.clone()),
            "suspend/restore must leave an Active state with a newer epoch"
        );

        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            Arc::new(PanicSigner),
            make_clock(1_700_000_000),
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://test.example",
                "test-audience",
                Duration::from_secs(900),
            ),
        )
        .expect("issuer");
        let service = RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(store.clone()),
            test_lifecycle(store.clone()),
            test_security_lifecycle(store.clone()),
            DynAccountSecurityReadRepo::new_box(accounts),
            Arc::new(issuer),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let stale_grant = AuthGrant::new_active(
            receipt.tenant(),
            receipt.user_id(),
            now,
            receipt.authn_epoch(),
            now + Duration::from_secs(3_600),
            now,
        )
        .expect("stale test grant");

        assert!(matches!(
            service.prepare_initial(&stale_grant).await,
            Err(RefreshError::Invalid)
        ));
        assert_eq!(
            store.refresh_len(),
            0,
            "rejected receipt writes no refresh record"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn refresh_rotate_rejects_family_issued_before_suspend_or_lock_restore() {
        struct PanicSigner;

        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("stale refresh family must be rejected before mint")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        for blocked_status in [
            crate::AccountStatus::Suspended,
            crate::AccountStatus::Locked,
        ] {
            let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
                "alice",
                user,
                "correct-horse",
                tenant,
            )
            .expect("seed account");
            let initial = accounts
                .find(tenant_repo_scope(tenant), user)
                .await
                .expect("read account")
                .expect("account");
            let initial_active = initial.clone().try_into_active().expect("active");
            let store = crate::internal::mem::InMemAuthGrantStore::new();
            let issuing_service = make_refresh_svc_with_accounts(
                store.clone(),
                DynAccountSecurityReadRepo::new_box(accounts.clone()),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );
            let refresh = issue_test_user(&issuing_service, &store).await;

            let (_, blocked) = initial
                .transition(
                    blocked_status,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                )
                .expect("block account")
                .into_parts();
            accounts.set_account_security_for_test(blocked.clone());
            let (_, restored) = blocked
                .transition(
                    crate::AccountStatus::Active,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(2),
                )
                .expect("restore")
                .into_parts();
            accounts.set_account_security_for_test(restored.clone());
            assert_ne!(
                restored.authn_epoch(),
                initial_active.authn_epoch(),
                "{blocked_status:?}/restore must advance the issuance epoch"
            );

            let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                Arc::new(PanicSigner),
                make_clock(1_700_000_000),
                authn::JwtIssuerConfig::rss_access(
                    authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                        .expect("non-empty signing key id"),
                    diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                    "https://test.example",
                    "test-audience",
                    Duration::from_secs(900),
                ),
            )
            .expect("issuer");
            let service = RefreshService::new(
                crate::ports::DynRefreshTokenStore::new_box(store.clone()),
                test_lifecycle(store.clone()),
                test_security_lifecycle(store.clone()),
                DynAccountSecurityReadRepo::new_box(accounts),
                Arc::new(issuer),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );
            assert!(matches!(
                service.rotate(refresh_receipt(), tenant, &refresh).await,
                Err(RefreshError::Invalid)
            ));
            assert_eq!(
                store.refresh_len(),
                1,
                "epoch-stale family is rejected without CAS consumption or child insert"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn refresh_initial_missing_or_failed_reader_rejects_before_sign_or_insert() {
        #[derive(Clone, Copy)]
        enum ReadResult {
            Missing,
            Failed,
        }

        struct ScriptedReader(ReadResult);
        impl AccountSecurityReadRepo for ScriptedReader {
            async fn find(
                &self,
                _scope: TenantRepoScope,
                _user_id: ids::UserId,
            ) -> Result<Option<AccountSecurityState>, IdentityError> {
                match self.0 {
                    ReadResult::Missing => Ok(None),
                    ReadResult::Failed => Err(IdentityError::Storage(Box::new(
                        std::io::Error::other("scripted account read failure"),
                    ))),
                }
            }
        }

        struct PanicSigner;
        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("reader rejection must precede signing")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let tenant = tid(CANON_TENANT);
        let receipt = AccountSecurityState::try_from(crate::AccountSecuritySnapshot {
            tenant,
            user_id: uid(CANON_USER),
            status: crate::AccountStatus::Active,
            authn_epoch: 0,
            version: 1,
            status_changed_at: SystemTime::UNIX_EPOCH,
            updated_at: SystemTime::UNIX_EPOCH,
        })
        .expect("state")
        .try_into_active()
        .expect("active receipt");

        for scripted in [ReadResult::Missing, ReadResult::Failed] {
            let store = crate::internal::mem::InMemAuthGrantStore::new();
            let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                Arc::new(PanicSigner),
                make_clock(1_700_000_000),
                authn::JwtIssuerConfig::rss_access(
                    authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                        .expect("non-empty signing key id"),
                    diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                    "https://test.example",
                    "test-audience",
                    Duration::from_secs(900),
                ),
            )
            .expect("issuer");
            let service = RefreshService::new(
                crate::ports::DynRefreshTokenStore::new_box(store.clone()),
                test_lifecycle(store.clone()),
                test_security_lifecycle(store.clone()),
                DynAccountSecurityReadRepo::new_box(ScriptedReader(scripted)),
                Arc::new(issuer),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );

            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            let grant = AuthGrant::new_active(
                receipt.tenant(),
                receipt.user_id(),
                now,
                receipt.authn_epoch(),
                now + Duration::from_secs(3_600),
                now,
            )
            .expect("test grant");
            let result = service.prepare_initial(&grant).await;
            match scripted {
                ReadResult::Missing => assert!(matches!(result, Err(RefreshError::Invalid))),
                ReadResult::Failed => assert!(matches!(result, Err(RefreshError::Store(_)))),
            }
            assert_eq!(
                store.refresh_len(),
                0,
                "reader rejection writes no refresh record"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn refresh_rotate_rejects_non_active_users_before_sign_or_cas() {
        struct PanicSigner;

        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("signer must not be called for a rejected refresh record")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        mockall::mock! {
            GateStore {}
            impl RefreshTokenStore for GateStore {
                async fn find_by_hash(
                    &self,
                    scope: TenantRepoScope,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            }
        }

        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        for status in [
            crate::AccountStatus::Suspended,
            crate::AccountStatus::Locked,
            crate::AccountStatus::Deactivated,
        ] {
            let accounts = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
                "alice",
                user,
                "correct-horse",
                tenant,
            )
            .expect("seed account");
            let state = accounts
                .find(tenant_repo_scope(tenant), user)
                .await
                .expect("read account")
                .expect("account");
            let (_, blocked) = state
                .transition(status, SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .expect("valid transition")
                .into_parts();
            accounts.set_account_security_for_test(blocked);

            let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            let record = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                id: RefreshTokenId::new("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
                tenant,
                auth_grant_id: grant_id("grant-non-active-account"),
                user_id: user,
                authn_epoch_at_issue: authn::AuthnEpoch::ZERO,
                auth_grant_status: AuthGrantStatus::Active,
                token_hash: RefreshTokenHash::new([0xAA; 32]),
                parent_id: None,
                lineage_id: RefreshTokenId::new("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
                status: RefreshStatus::Active,
                issued_at: issued,
                expires_at: issued + Duration::from_secs(3_600),
            })
            .expect("valid refresh fixture");
            let lifecycle = lifecycle_for_record(&record);
            let mut store = MockGateStore::new();
            store
                .expect_find_by_hash()
                .times(1)
                .returning(move |_scope, _hash| Ok(Some(record.clone())));
            let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                Arc::new(PanicSigner),
                make_clock(1_700_000_000),
                authn::JwtIssuerConfig::rss_access(
                    authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                        .expect("non-empty signing key id"),
                    diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                    "https://test.example",
                    "test-audience",
                    Duration::from_secs(900),
                ),
            )
            .expect("issuer");
            let service = RefreshService::new(
                crate::ports::DynRefreshTokenStore::new_box(store),
                lifecycle,
                unavailable_security_lifecycle(),
                DynAccountSecurityReadRepo::new_box(accounts),
                Arc::new(issuer),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );

            assert!(matches!(
                service
                    .rotate(
                        refresh_receipt(),
                        tenant,
                        &authn::RefreshToken::new("presented"),
                    )
                    .await,
                Err(RefreshError::Invalid)
            ));
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used, clippy::panic)]
    async fn refresh_rotate_rejects_missing_outage_and_mismatched_account_before_sign_or_cas() {
        #[derive(Clone)]
        enum ScriptedRead {
            Missing,
            Failed,
            State(AccountSecurityState),
        }

        struct ScriptedReader(ScriptedRead);
        impl AccountSecurityReadRepo for ScriptedReader {
            async fn find(
                &self,
                _scope: TenantRepoScope,
                _user_id: ids::UserId,
            ) -> Result<Option<AccountSecurityState>, IdentityError> {
                match &self.0 {
                    ScriptedRead::Missing => Ok(None),
                    ScriptedRead::Failed => Err(IdentityError::Storage(Box::new(
                        std::io::Error::other("scripted account reader outage"),
                    ))),
                    ScriptedRead::State(state) => Ok(Some(state.clone())),
                }
            }
        }

        struct PanicSigner;
        impl diport::Signer for PanicSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                panic!("account reader rejection must precede signing")
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        mockall::mock! {
            AccountGateStore {}
            impl RefreshTokenStore for AccountGateStore {
                async fn find_by_hash(
                    &self,
                    scope: TenantRepoScope,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            }
        }

        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let other_tenant_state = AccountSecurityState::try_from(crate::AccountSecuritySnapshot {
            tenant: tid(OTHER_TENANT),
            user_id: user,
            status: crate::AccountStatus::Active,
            authn_epoch: 0,
            version: 1,
            status_changed_at: SystemTime::UNIX_EPOCH,
            updated_at: SystemTime::UNIX_EPOCH,
        })
        .expect("other tenant state");
        let other_user_state = AccountSecurityState::try_from(crate::AccountSecuritySnapshot {
            tenant,
            user_id: uid(GHOST_USER),
            status: crate::AccountStatus::Active,
            authn_epoch: 0,
            version: 1,
            status_changed_at: SystemTime::UNIX_EPOCH,
            updated_at: SystemTime::UNIX_EPOCH,
        })
        .expect("other user state");

        for scripted in [
            ScriptedRead::Missing,
            ScriptedRead::Failed,
            ScriptedRead::State(other_tenant_state),
            ScriptedRead::State(other_user_state),
        ] {
            let record = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                id: RefreshTokenId::new("eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
                tenant,
                auth_grant_id: grant_id("grant-account-mismatch"),
                user_id: user,
                authn_epoch_at_issue: authn::AuthnEpoch::ZERO,
                auth_grant_status: AuthGrantStatus::Active,
                token_hash: RefreshTokenHash::new([0xEE; 32]),
                parent_id: None,
                lineage_id: RefreshTokenId::new("eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
                status: RefreshStatus::Active,
                issued_at: now,
                expires_at: now + Duration::from_secs(3_600),
            })
            .expect("valid refresh fixture");
            let lifecycle = lifecycle_for_record(&record);
            let mut store = MockAccountGateStore::new();
            store
                .expect_find_by_hash()
                .times(1)
                .returning(move |_scope, _hash| Ok(Some(record.clone())));

            let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                Arc::new(PanicSigner),
                make_clock(1_700_000_000),
                authn::JwtIssuerConfig::rss_access(
                    authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                        .expect("non-empty signing key id"),
                    diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                    "https://test.example",
                    "test-audience",
                    Duration::from_secs(900),
                ),
            )
            .expect("issuer");
            let service = RefreshService::new(
                crate::ports::DynRefreshTokenStore::new_box(store),
                lifecycle,
                unavailable_security_lifecycle(),
                DynAccountSecurityReadRepo::new_box(ScriptedReader(scripted.clone())),
                Arc::new(issuer),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );

            let result = service
                .rotate(
                    refresh_receipt(),
                    tenant,
                    &authn::RefreshToken::new("presented"),
                )
                .await;
            if matches!(scripted, ScriptedRead::Failed) {
                assert!(matches!(result, Err(RefreshError::Store(_))));
            } else {
                assert!(matches!(result, Err(RefreshError::Invalid)));
            }
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_rotate_rejects_invalid_grant_before_sign_or_cas() {
        #[derive(Clone)]
        enum GrantRead {
            Missing,
            Failed,
            Grant(AuthGrant),
        }

        struct ScriptedLifecycle(GrantRead);
        impl AuthGrantLifecycle for ScriptedLifecycle {
            async fn persist_login_grant(
                &self,
                _receipt: LoginProducerReceipt,
                _scope: TenantRepoScope,
                _mutation: LoginGrantMutation,
                _event: ReviewedEvent,
            ) -> Result<PersistedLoginGrantReceipt, OutboxEmitError> {
                unreachable!("grant read fixture never persists")
            }

            async fn find_active(
                &self,
                _scope: TenantRepoScope,
                _grant_id: AuthGrantId,
                _observed_at: SystemTime,
            ) -> Result<Option<AuthGrant>, IdentityError> {
                match &self.0 {
                    GrantRead::Missing => Ok(None),
                    GrantRead::Failed => Err(IdentityError::Storage(Box::new(
                        std::io::Error::other("scripted grant store outage"),
                    ))),
                    GrantRead::Grant(grant) => Ok(Some(grant.clone())),
                }
            }
        }

        struct GateStore {
            record: RefreshTokenRecord,
        }
        impl RefreshTokenStore for GateStore {
            async fn find_by_hash(
                &self,
                _scope: TenantRepoScope,
                _hash: RefreshTokenHash,
            ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
                Ok(Some(self.record.clone()))
            }
        }

        #[derive(Clone)]
        struct CountingSigner(Arc<AtomicUsize>);
        impl diport::Signer for CountingSigner {
            async fn sign(
                &self,
                _request: diport::SignRequest,
            ) -> Result<diport::Signature, diport::SignerError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(diport::Signature::new(b"must-not-be-used".to_vec()))
            }

            async fn shutdown(&self) -> Result<(), diport::SignerError> {
                Ok(())
            }
        }

        let tenant = tid(CANON_TENANT);
        let user = uid(CANON_USER);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let active = AuthGrant::new_active(
            tenant,
            user,
            now,
            authn::AuthnEpoch::ZERO,
            now + Duration::from_secs(3_600),
            now,
        )
        .expect("active grant");
        let revoked = active
            .clone()
            .close(GrantSecurityEventKind::LogoutCurrent, now)
            .expect("revoke grant")
            .next()
            .clone();
        let expired = AuthGrant::new_active(
            tenant,
            user,
            now - Duration::from_secs(3_600),
            authn::AuthnEpoch::ZERO,
            now,
            now - Duration::from_secs(3_600),
        )
        .expect("expired active snapshot");
        let mismatched = AuthGrant::new_active(
            tenant,
            uid(GHOST_USER),
            now,
            authn::AuthnEpoch::ZERO,
            now + Duration::from_secs(3_600),
            now,
        )
        .expect("mismatched grant");

        for (case, read) in [
            ("missing", GrantRead::Missing),
            ("provider failure", GrantRead::Failed),
            ("revoked", GrantRead::Grant(revoked.clone())),
            ("expired", GrantRead::Grant(expired.clone())),
            ("binding mismatch", GrantRead::Grant(mismatched.clone())),
        ] {
            let record = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
                id: RefreshTokenId::new(format!("refresh-{case}")),
                tenant,
                auth_grant_id: active.id().clone(),
                user_id: user,
                authn_epoch_at_issue: authn::AuthnEpoch::ZERO,
                auth_grant_status: AuthGrantStatus::Active,
                token_hash: RefreshTokenHash::new([0xA5; 32]),
                parent_id: None,
                lineage_id: RefreshTokenId::new(format!("refresh-{case}")),
                status: RefreshStatus::Active,
                issued_at: now,
                expires_at: now + Duration::from_secs(3_600),
            })
            .expect("valid refresh fixture");
            let sign_calls = Arc::new(AtomicUsize::new(0));
            let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
                Arc::new(CountingSigner(Arc::clone(&sign_calls))),
                make_clock(1_700_000_000),
                authn::JwtIssuerConfig::rss_access(
                    authn::SigningKeyRing::single(diport::KeyId::new("test-key")).expect("key id"),
                    diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                    "https://test.example",
                    "test-audience",
                    Duration::from_secs(900),
                ),
            )
            .expect("issuer");
            let service = RefreshService::new(
                crate::ports::DynRefreshTokenStore::new_box(GateStore { record }),
                Arc::from(DynAuthGrantLifecycle::new_box(ScriptedLifecycle(read))),
                unavailable_security_lifecycle(),
                seeded_account_reader(),
                Arc::new(issuer),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            );

            assert!(
                service
                    .rotate(
                        refresh_receipt(),
                        tenant,
                        &authn::RefreshToken::new("presented"),
                    )
                    .await
                    .is_err(),
                "case={case}"
            );
            assert_eq!(sign_calls.load(Ordering::SeqCst), 0, "case={case}");
        }
    }

    // ── 测试 R1：happy rotation — issue → rotate 成功（返回 access JWT 非空 + 新 refresh ≠ 旧）
    //             旧 refresh 再 rotate ⇒ Replayed 且原 lineage 全部不再可用 ─────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_happy_rotation_and_replay_detection() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let svc = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let ta = tid(CANON_TENANT);

        // issue → rotate 成功
        let initial = issue_test_user_bundle(&svc, &store).await;
        let initial_claims = decode_access_claims(&initial.access);
        let old_rf = initial.refresh;
        let bundle = svc
            .rotate(refresh_receipt(), ta, &old_rf)
            .await
            .expect("rotate ok");
        let rotated_claims = decode_access_claims(&bundle.access);
        assert!(
            !bundle.access.as_str().is_empty(),
            "access JWT must be non-empty"
        );
        assert_ne!(
            bundle.refresh.as_str(),
            old_rf.as_str(),
            "新 refresh ≠ 旧 refresh"
        );
        for stable in ["sid", "auth_time", "authn_epoch"] {
            assert_eq!(initial_claims[stable], rotated_claims[stable], "{stable}");
        }
        assert_ne!(initial_claims["jti"], rotated_claims["jti"]);

        // 旧 refresh 再 rotate ⇒ Replayed（重放检测）
        let err = svc
            .rotate(refresh_receipt(), ta, &old_rf)
            .await
            .expect_err("旧 refresh 已消费，应 Replayed");
        assert!(matches!(err, RefreshError::Replayed), "old rotate: {err:?}");

        let session_id = grant_id(
            initial_claims["sid"]
                .as_str()
                .expect("access token sid claim is a string"),
        );
        assert!(
            store
                .find_active(
                    tenant_repo_scope(ta),
                    session_id.clone(),
                    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                )
                .await
                .expect("grant lookup succeeds")
                .is_none(),
            "replay must terminalize the access-token grant root"
        );
        let root = store
            .grant_snapshot(&session_id)
            .expect("grant root remains durably inspectable");
        assert_eq!(root.status(), AuthGrantStatus::Compromised);
        assert_eq!(
            root.close_reason(),
            Some(CredentialSecurityEventKind::Grant(
                GrantSecurityEventKind::RefreshReuseDetected
            ))
        );
        let family = store.refresh_family_snapshot(&session_id);
        assert_eq!(
            family.len(),
            2,
            "both refresh generations remain observable"
        );
        assert!(family.iter().all(|record| {
            record.status() == RefreshStatus::Revoked
                && record.auth_grant_status() == AuthGrantStatus::Compromised
        }));

        // grant-bound family 原子撤销后，新 refresh 也不可用。
        let err2 = svc
            .rotate(refresh_receipt(), ta, &bundle.refresh)
            .await
            .expect_err("grant-bound family 撤销后新 refresh 也应 Replayed");
        assert!(
            matches!(err2, RefreshError::Replayed),
            "cascaded new: {err2:?}"
        );
    }

    // ── 测试 R2：重放关闭 grant + family — A→B，再用 A ⇒ Replayed，且 B 也 ⇒ Replayed ──

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_replay_compromises_grant_and_revokes_family() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let svc = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let ta = tid(CANON_TENANT);

        let token_a = issue_test_user(&svc, &store).await;
        let bundle_b = svc
            .rotate(refresh_receipt(), ta, &token_a)
            .await
            .expect("A→B ok");

        // 用 A 重放 ⇒ Replayed（A 已 Consumed）+ 原子 Compromised root/revoke family。
        let err = svc
            .rotate(refresh_receipt(), ta, &token_a)
            .await
            .expect_err("replayed A");
        assert!(matches!(err, RefreshError::Replayed));

        // B 也已被级联撤销 ⇒ Replayed
        let err2 = svc
            .rotate(refresh_receipt(), ta, &bundle_b.refresh)
            .await
            .expect_err("cascaded B");
        assert!(matches!(err2, RefreshError::Replayed));
    }

    // ── 测试 R3：旧 refresh 一次性 — rotate 后旧 token 不可再用 ────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_old_token_is_one_shot_after_rotate() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let svc = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let ta = tid(CANON_TENANT);

        let old_rf = issue_test_user(&svc, &store).await;
        let _bundle = svc
            .rotate(refresh_receipt(), ta, &old_rf)
            .await
            .expect("rotate ok");

        // 旧 refresh 已 Consumed，不可再轮换
        let err = svc
            .rotate(refresh_receipt(), ta, &old_rf)
            .await
            .expect_err("old one-shot");
        assert!(matches!(err, RefreshError::Replayed));
    }

    // ── 测试 R5：过期边界 — refresh_ttl 很短 + clock 推进 → rotate ⇒ Expired ──

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_expired_token_returns_expired() {
        // 共享 in-mem store：issue_svc 签发（now=T），expire_svc 用 T+ttl+1 的 clock rotate。
        let store = crate::internal::mem::InMemAuthGrantStore::new();

        // 签发服务：clock = T=1000，ttl = 1s（token 于 T+1 过期）
        let issue_svc = make_refresh_svc(store.clone(), make_clock(1_000), Duration::from_secs(1));
        let ta = tid(CANON_TENANT);
        let rf = issue_test_user(&issue_svc, &store).await;

        // 轮换服务：clock = T+10（token 已过期），ttl 无关（不会到达写新 record 步骤）
        let expire_svc = make_refresh_svc(store, make_clock(1_010), Duration::from_secs(3_600));
        let err = expire_svc
            .rotate(refresh_receipt(), ta, &rf)
            .await
            .expect_err("expired");
        assert!(matches!(err, RefreshError::Expired), "{err:?}");
    }

    // ── 测试 R6：跨租 fail-closed — tenant B 用 tenant A 的 token rotate ⇒ Invalid ─

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_cross_tenant_fail_closed() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let svc = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let ta = tid(CANON_TENANT);
        let tb = tid(OTHER_TENANT);

        let rf = issue_test_user(&svc, &store).await;

        // tenant B 用 tenant A 的 token ⇒ find_by_hash 跨租 → None → Invalid
        let err = svc
            .rotate(refresh_receipt(), tb, &rf)
            .await
            .expect_err("cross-tenant");
        assert!(matches!(err, RefreshError::Invalid), "{err:?}");

        // tenant A 的 token 未被影响（仍可 rotate）
        svc.rotate(refresh_receipt(), ta, &rf)
            .await
            .expect("tenant A token intact");
    }

    // ── 测试 R7：Invalid — 未知 token rotate ⇒ Invalid ──────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_unknown_token_is_invalid() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let unknown = authn::RefreshToken::new("this-token-was-never-issued");
        let err = svc
            .rotate(refresh_receipt(), ta, &unknown)
            .await
            .expect_err("unknown token");
        assert!(matches!(err, RefreshError::Invalid), "{err:?}");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_rotation_uses_security_lifecycle_not_reader_store() {
        use crate::ports::DynRefreshTokenStore;

        mockall::mock! {
            CasMissStore {}
            impl RefreshTokenStore for CasMissStore {
                async fn find_by_hash(
                    &self,
                    scope: TenantRepoScope,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            }
        }

        let ta = tid(CANON_TENANT);
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 根 token：id == lineage_id（固定 UUID 串便于 withf 捕获）。
        let lineage_str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

        let active_rec = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
            id: RefreshTokenId::new(lineage_str),
            tenant: ta,
            auth_grant_id: grant_id("grant-cas-miss"),
            user_id: uid(CANON_USER),
            authn_epoch_at_issue: authn::AuthnEpoch::ZERO,
            auth_grant_status: AuthGrantStatus::Active,
            token_hash: RefreshTokenHash::new([0xAA; 32]),
            parent_id: None,
            lineage_id: RefreshTokenId::new(lineage_str),
            status: RefreshStatus::Active,
            issued_at: issued,
            expires_at: issued + Duration::from_secs(3_600),
        })
        .expect("valid refresh fixture");
        let lifecycle_store = lifecycle_store_for_record(&active_rec);
        let lifecycle = test_lifecycle(lifecycle_store.clone());

        let mut mock = MockCasMissStore::new();

        // find_by_hash → Active 记录（步骤 1）
        mock.expect_find_by_hash()
            .returning(move |_t, _h| Ok(Some(active_rec.clone())));

        let svc = RefreshService::new(
            DynRefreshTokenStore::new_box(mock),
            lifecycle,
            test_security_lifecycle(lifecycle_store.clone()),
            seeded_account_reader(),
            std::sync::Arc::new(make_jwt_issuer(make_clock(1_700_000_000))),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );

        let fake_token = authn::RefreshToken::new("this-causes-cas-miss");
        let bundle = svc
            .rotate(refresh_receipt(), ta, &fake_token)
            .await
            .expect("security lifecycle commits rotation");
        assert!(!bundle.refresh.as_str().is_empty());
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_rotate_rejects_record_tenant_mismatch_before_mint() {
        use crate::ports::DynRefreshTokenStore;

        mockall::mock! {
            TenantMismatchStore {}
            impl RefreshTokenStore for TenantMismatchStore {
                async fn find_by_hash(
                    &self,
                    scope: TenantRepoScope,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            }
        }

        let request_tenant = tid(CANON_TENANT);
        let record_tenant = tid(OTHER_TENANT);
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let lineage_str = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let active_rec = RefreshTokenRecord::hydrate(RefreshTokenSnapshot {
            id: RefreshTokenId::new(lineage_str),
            tenant: record_tenant,
            auth_grant_id: grant_id("grant-tenant-mismatch"),
            user_id: uid(CANON_USER),
            authn_epoch_at_issue: authn::AuthnEpoch::ZERO,
            auth_grant_status: AuthGrantStatus::Active,
            token_hash: RefreshTokenHash::new([0xBB; 32]),
            parent_id: None,
            lineage_id: RefreshTokenId::new(lineage_str),
            status: RefreshStatus::Active,
            issued_at: issued,
            expires_at: issued + Duration::from_secs(3_600),
        })
        .expect("valid refresh fixture");

        let mut mock = MockTenantMismatchStore::new();
        mock.expect_find_by_hash()
            .withf(move |scope, _hash| scope.tenant() == request_tenant)
            .returning(move |_tenant, _hash| Ok(Some(active_rec.clone())));

        let svc = RefreshService::new(
            DynRefreshTokenStore::new_box(mock),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            unavailable_security_lifecycle(),
            seeded_account_reader(),
            std::sync::Arc::new(make_jwt_issuer(make_clock(1_700_000_000))),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );

        let fake_token = authn::RefreshToken::new("this-store-returns-wrong-tenant");
        let err = svc
            .rotate(refresh_receipt(), request_tenant, &fake_token)
            .await
            .expect_err("tenant-mismatched refresh record must fail closed");
        assert!(
            matches!(err, RefreshError::Invalid),
            "tenant mismatch must be Invalid before mint/CAS: {err:?}"
        );
    }

    // ── 测试 R10：mint 先于 CAS（#284 F1）— signer 失败时旧 refresh 未被消费、仍 Active ──
    //
    // 验证 rotate 步骤 5（mint）先于步骤 6（CAS 提交）：mint 失败 ⇒ 返回 Mint 错误、CAS 从未执行 ⇒
    // 旧 refresh 仍 Active（客户端可重试，无锁死）。反证「CAS 先于 mint」的锁死缺陷。

    /// 永远签名失败的 Signer（diport::SignerError 已脱敏 source）。
    struct FailingSigner;
    impl diport::Signer for FailingSigner {
        async fn sign(
            &self,
            _req: diport::SignRequest,
        ) -> Result<diport::Signature, diport::SignerError> {
            Err(diport::SignerError::new(std::io::Error::other(
                "test-mint-fail",
            )))
        }
        async fn shutdown(&self) -> Result<(), diport::SignerError> {
            Ok(())
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_rotate_mint_failure_does_not_consume_old() {
        let store = crate::internal::mem::InMemAuthGrantStore::new();
        let probe = store.clone(); // Arc 共享视图：rotate 后查旧 token 状态
        let ta = tid(CANON_TENANT);

        let issuing_service = make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let old_rf = issue_test_user(&issuing_service, &store).await;

        let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            std::sync::Arc::new(FailingSigner),
            make_clock(1_700_000_000),
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://test.example",
                "test-audience",
                Duration::from_secs(900),
            ),
        )
        .expect("valid jwt issuer config");
        let svc = RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(store.clone()),
            test_lifecycle(store.clone()),
            unavailable_security_lifecycle(),
            seeded_account_reader(),
            std::sync::Arc::new(issuer),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );

        // rotate ⇒ mint 失败（FailingSigner）⇒ Err(Mint)，CAS 从未执行
        let err = svc
            .rotate(refresh_receipt(), ta, &old_rf)
            .await
            .expect_err("mint 失败应返回 Mint 错误");
        assert!(
            matches!(err, RefreshError::Mint(_)),
            "应为 Mint 错误: {err:?}"
        );

        // 关键断言：旧 refresh 未被消费、仍 Active（CAS 先于 mint 会让此处 Consumed → 锁死）
        let old_hash = crate::domain::RefreshTokenHash::new(secure::digest(old_rf.as_str()));
        let found = probe
            .find_by_hash(tenant_repo_scope(ta), old_hash)
            .await
            .expect("find ok")
            .expect("旧 refresh 仍在 store");
        assert_eq!(
            found.status(),
            RefreshStatus::Active,
            "mint 失败不得消费旧 refresh（#284 F1：mint 先于 CAS）"
        );
    }

    // ── 测试 L1252-a：login 首发 token bundle（#1252）────────────────────────────
    // login 成功后响应包含 access JWT + refresh token bundle（首发，#1252）。
    // TestSigner 返回固定字节 → JWT 非空；refresh token 经 CSPRNG 签发。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_issues_initial_token_bundle() {
        let capture = CapturingAuthGrantLifecycle::default();
        let svc = seed_service(&capture, 1_700_000_000, 3_600);

        let resp = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");

        assert!(
            !resp.data.access_token.is_empty(),
            "access_token 非空（#1252 首发）"
        );
        assert!(
            !resp.data.refresh_token.is_empty(),
            "refresh_token 非空（#1252 首发）"
        );
        assert!(
            resp.data.access_expires_at > 0,
            "access_expires_at > 0（JWT 含有效期）"
        );

        let mut segments = resp.data.access_token.split('.');
        let header = segments.next().expect("JWT header");
        let payload = segments.next().expect("JWT payload");
        assert!(segments.next().is_some(), "JWT signature");
        assert!(segments.next().is_none(), "exact compact JWT segments");
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header)
                .expect("decode JWT header"),
        )
        .expect("parse JWT header");
        let payload: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .expect("decode JWT payload"),
        )
        .expect("parse JWT payload");
        assert_eq!(header["typ"], "at+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(payload["token_use"], "access");
        assert_eq!(payload["kind"], "user");
        assert_eq!(payload["tenant_id"], CANON_TENANT);
    }

    // ── 测试 H-Login-1：login_handler HTTP 级契约测试（F3）─────────────────────────
    // 经 login_router_for_test（真实 login_handler）验证：201 + token bundle 字段非空。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_handler_returns_201_with_token_bundle() -> Result<(), Box<dyn std::error::Error>>
    {
        use testkit::ContractRequest;

        let capture = CapturingAuthGrantLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_700_000_000, 3_600));
        let router = login_router_for_test(svc);

        let resp = testkit::call(
            router,
            ContractRequest::post(LOGIN_HTTP_SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .json(&IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                }),
        )
        .await?;

        resp.ensure_status(axum::http::StatusCode::CREATED)?;
        let decoded: IdentityLoginResponse = resp.json()?;
        assert!(!decoded.data.session_id.is_empty(), "session_id 非空");
        assert!(
            !decoded.data.access_token.is_empty(),
            "access_token 非空（#1252）"
        );
        assert!(
            !decoded.data.refresh_token.is_empty(),
            "refresh_token 非空（#1252）"
        );
        assert!(
            decoded.data.access_expires_at > 0,
            "access_expires_at > 0（JWT 含有效期）"
        );
        assert_eq!(capture.count(), 1, "co-tx 写应恰一次");
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_handler_duplicate_tenant_headers_reject_before_service_write()
    -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let capture = CapturingAuthGrantLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_700_000_000, 3_600));
        let router = login_router_for_test(svc);
        let resp = testkit::call(
            router,
            ContractRequest::post(LOGIN_HTTP_SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .header("X-Tenant-ID", CANON_TENANT)
                .json(&IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                }),
        )
        .await?;

        resp.ensure_error(axum::http::StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
        assert_eq!(capture.count(), 0, "login service write must not run");
        Ok(())
    }

    // ── 测试 H-Refresh-1..4：refresh_handler HTTP 级契约测试（F2）──────────────────
    // 四维断言：happy(201) / 缺租户头(400) / 坏 body(400) / 未知 token(401)。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_happy_path_returns_201_with_token_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        {
            const _: ::vocab::HttpRouteBinding<
                ::generated::http::identity_v1::refresh::RouteMarker,
                ::vocab::http::OutboxFact,
            > = ::generated::http::identity_v1::refresh::ROUTE;
        }

        {
            use testkit::ContractRequest;

            let store = crate::internal::mem::InMemAuthGrantStore::new();
            let svc = Arc::new(make_refresh_svc(
                store.clone(),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            ));
            // 先签发一个 refresh token 落库，供 handler 轮换。
            let rf = issue_test_user(&svc, &store).await;

            let router = refresh_router_for_test(Arc::clone(&svc));

            let resp = testkit::call(
                router,
                ContractRequest::post(REFRESH_HTTP_SPEC.route.path())
                    .header("X-Tenant-ID", CANON_TENANT)
                    .json(&IdentityRefreshRequest {
                        refresh_token: rf.as_str().to_string(),
                    }),
            )
            .await?;

            resp.ensure_status(axum::http::StatusCode::CREATED)?;
            let decoded: IdentityRefreshResponse = resp.json()?;
            assert!(!decoded.data.access_token.is_empty(), "access_token 非空");
            assert!(!decoded.data.refresh_token.is_empty(), "refresh_token 非空");
            assert!(decoded.data.access_expires_at > 0, "access_expires_at > 0");
            Ok(())
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_missing_tenant_header_returns_400()
    -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let svc = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemAuthGrantStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 不带 X-Tenant-ID header → parse_tenant_and_body → 400
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.route.path()).json(&IdentityRefreshRequest {
                refresh_token: "any-token".to_string(),
            }),
        )
        .await?;

        // F5.1：断言 HTTP 状态码 + error envelope 格式（code / message / requestId）。
        // wire 格式：{"error":{"code":"ERR_...","message":"...","details":[],"requestId":"..."}}
        resp.ensure_status(axum::http::StatusCode::BAD_REQUEST)?;
        let env: serde_json::Value = resp.json()?;
        assert_eq!(
            env["error"]["code"].as_str().unwrap_or(""),
            "ERR_CORE_VALIDATION",
            "缺 tenant header → ERR_CORE_VALIDATION"
        );
        assert!(
            !env["error"]["message"].as_str().unwrap_or("").is_empty(),
            "error.message 应非空"
        );
        assert!(
            !env["error"]["requestId"].as_str().unwrap_or("").is_empty(),
            "error.requestId 应存在"
        );
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_duplicate_tenant_headers_return_400()
    -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        for second in [CANON_TENANT, "11111111-1111-4111-8111-111111111111"] {
            let svc = Arc::new(make_refresh_svc(
                crate::internal::mem::InMemAuthGrantStore::new(),
                make_clock(1_700_000_000),
                Duration::from_secs(3_600),
            ));
            let router = refresh_router_for_test(svc);
            let resp = testkit::call(
                router,
                ContractRequest::post(REFRESH_HTTP_SPEC.route.path())
                    .header("X-Tenant-ID", CANON_TENANT)
                    .header("X-Tenant-ID", second)
                    .json(&IdentityRefreshRequest {
                        refresh_token: "not-reached".to_owned(),
                    }),
            )
            .await?;
            resp.ensure_error(axum::http::StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
        }
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_duplicate_tenant_header_rejects_before_store_lookup()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::ports::DynRefreshTokenStore;
        use testkit::ContractRequest;

        mockall::mock! {
            HeaderBoundaryStore {}
            impl RefreshTokenStore for HeaderBoundaryStore {
                async fn find_by_hash(
                    &self,
                    scope: TenantRepoScope,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            }
        }

        let mut store = MockHeaderBoundaryStore::new();
        store.expect_find_by_hash().times(0);
        let svc = Arc::new(RefreshService::new(
            DynRefreshTokenStore::new_box(store),
            test_lifecycle(crate::internal::mem::InMemAuthGrantStore::new()),
            unavailable_security_lifecycle(),
            seeded_account_reader(),
            Arc::new(make_jwt_issuer(make_clock(1_700_000_000))),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .header("X-Tenant-ID", CANON_TENANT)
                .json(&IdentityRefreshRequest {
                    refresh_token: "not-reached".to_owned(),
                }),
        )
        .await?;
        resp.ensure_error(axum::http::StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_bad_body_returns_400() -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let svc = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemAuthGrantStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 发送非 JSON body → serde_json::from_slice 失败 → 400
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .raw_json(b"not-valid-json"),
        )
        .await?;

        // F5.1：断言 HTTP 状态码 + error envelope 格式（code / message / requestId）。
        resp.ensure_status(axum::http::StatusCode::BAD_REQUEST)?;
        let env: serde_json::Value = resp.json()?;
        assert_eq!(
            env["error"]["code"].as_str().unwrap_or(""),
            "ERR_CORE_VALIDATION",
            "坏 body → ERR_CORE_VALIDATION"
        );
        assert!(
            !env["error"]["message"].as_str().unwrap_or("").is_empty(),
            "error.message 应非空"
        );
        assert!(
            !env["error"]["requestId"].as_str().unwrap_or("").is_empty(),
            "error.requestId 应存在"
        );
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_unknown_token_returns_401() -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let svc = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemAuthGrantStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 未知 token → RefreshError::Invalid → 401
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.route.path())
                .header("X-Tenant-ID", CANON_TENANT)
                .json(&IdentityRefreshRequest {
                    refresh_token: "this-token-was-never-issued".to_string(),
                }),
        )
        .await?;

        // F5.1：断言 HTTP 状态码 + error envelope 格式（code / message / requestId）。
        resp.ensure_status(axum::http::StatusCode::UNAUTHORIZED)?;
        let env: serde_json::Value = resp.json()?;
        assert_eq!(
            env["error"]["code"].as_str().unwrap_or(""),
            "ERR_CORE_UNAUTHENTICATED",
            "未知 token → ERR_CORE_UNAUTHENTICATED"
        );
        assert!(
            !env["error"]["message"].as_str().unwrap_or("").is_empty(),
            "error.message 应非空"
        );
        assert!(
            !env["error"]["requestId"].as_str().unwrap_or("").is_empty(),
            "error.requestId 应存在"
        );
        Ok(())
    }

    async fn scripted_refresh_http_response(
        backend: ScriptedRefreshBackend,
        request_id: &str,
    ) -> Result<(StatusCode, serde_json::Value, String), Box<dyn std::error::Error>> {
        let response = refresh_handler_bytes(
            scripted_refresh_service(backend),
            refresh_receipt(),
            tid(CANON_TENANT),
            Bytes::from(serde_json::json!({ "refreshToken": "presented-refresh" }).to_string()),
            request_id,
        )
        .await;
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        let text = String::from_utf8(body.to_vec())?;
        Ok((status, serde_json::from_str(&text)?, text))
    }

    fn normalize_error_request_id(body: &mut serde_json::Value) {
        body["error"]["requestId"] = serde_json::Value::String("<request-id>".to_owned());
    }

    #[tokio::test]
    async fn refresh_credential_rejections_have_one_indistinguishable_401_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                "unknown",
                scripted_refresh_backend(None, 5, false, ScriptedRefreshSettlement::ReuseContained),
            ),
            (
                "expired",
                scripted_refresh_backend(
                    Some((RefreshStatus::Active, AuthGrantStatus::Active)),
                    5,
                    true,
                    ScriptedRefreshSettlement::ReuseContained,
                ),
            ),
            (
                "consumed",
                scripted_refresh_backend(
                    Some((RefreshStatus::Consumed, AuthGrantStatus::Active)),
                    5,
                    false,
                    ScriptedRefreshSettlement::ReuseContained,
                ),
            ),
            (
                "revoked",
                scripted_refresh_backend(
                    Some((RefreshStatus::Revoked, AuthGrantStatus::Active)),
                    5,
                    false,
                    ScriptedRefreshSettlement::ReuseContained,
                ),
            ),
            (
                "epoch-stale",
                scripted_refresh_backend(
                    Some((RefreshStatus::Active, AuthGrantStatus::Active)),
                    6,
                    false,
                    ScriptedRefreshSettlement::Internal,
                ),
            ),
            (
                "already-compromised",
                scripted_refresh_backend(
                    Some((RefreshStatus::Revoked, AuthGrantStatus::Compromised)),
                    5,
                    false,
                    ScriptedRefreshSettlement::AlreadyContained,
                ),
            ),
        ];
        let mut canonical = None;
        for (index, (label, backend)) in cases.into_iter().enumerate() {
            let request_id = format!("refresh-reject-{index}");
            let (status, mut body, text) =
                scripted_refresh_http_response(backend, &request_id).await?;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "case={label}: {text}");
            assert_eq!(
                body["error"]["code"], "ERR_CORE_UNAUTHENTICATED",
                "case={label}: {text}"
            );
            assert_eq!(body["error"]["requestId"], request_id, "case={label}");
            normalize_error_request_id(&mut body);
            if let Some(expected) = &canonical {
                assert_eq!(
                    &body, expected,
                    "case={label} must not disclose token state"
                );
            } else {
                canonical = Some(body);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn refresh_internal_settlements_have_one_generic_500_without_bearers()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            ("internal", ScriptedRefreshSettlement::Internal),
            ("outbox", ScriptedRefreshSettlement::Outbox),
            ("commit-unknown", ScriptedRefreshSettlement::CommitUnknown),
        ];
        let mut canonical = None;
        for (index, (label, settlement)) in cases.into_iter().enumerate() {
            let backend = scripted_refresh_backend(
                Some((RefreshStatus::Active, AuthGrantStatus::Active)),
                5,
                false,
                settlement,
            );
            let request_id = format!("refresh-internal-{index}");
            let (status, mut body, text) =
                scripted_refresh_http_response(backend, &request_id).await?;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "case={label}: {text}"
            );
            assert_eq!(body["error"]["code"], "ERR_CORE_INTERNAL", "case={label}");
            assert_eq!(body["error"]["requestId"], request_id, "case={label}");
            for forbidden in [
                "accessToken",
                "refreshToken",
                "presented-refresh",
                "provider",
                "outbox",
                "commit",
                "compromised",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "case={label} leaked `{forbidden}` in {text}"
                );
            }
            normalize_error_request_id(&mut body);
            if let Some(expected) = &canonical {
                assert_eq!(
                    &body, expected,
                    "case={label} must have the generic 500 body"
                );
            } else {
                canonical = Some(body);
            }
        }
        Ok(())
    }

    // ── FailingSigner ⇒ TokenIssue + 零 AuthGrant/refresh/outbox ──
    //
    // 回归验证（anti-vacuity）：`FailingSigner.sign()` 永远失败，`prepare_initial` 返回
    // `RefreshError::Mint` → `LoginError::TokenIssue`。生命周期端口从未执行，故零持久化。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_failing_signer_no_session_on_token_issue_failure() {
        // 构造 RefreshService<FailingSigner>（prepare_initial 必然失败）。
        let issuer = authn::JwtIssuer::<diport::RssAccessProfile, _>::new(
            std::sync::Arc::new(FailingSigner),
            make_clock(1_700_000_000),
            authn::JwtIssuerConfig::rss_access(
                authn::SigningKeyRing::single(diport::KeyId::new("test-key"))
                    .expect("non-empty signing key id"),
                diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                "https://test.example",
                "test-audience",
                Duration::from_secs(900),
            ),
        )
        .expect("valid jwt issuer config");

        let capture = CapturingAuthGrantLifecycle::default();
        let provider = capture.clone();
        let svc = LoginService::with_seed_credential(
            move |accounts| {
                AuthGrantServices::from_provider(
                    provider,
                    accounts,
                    std::sync::Arc::new(issuer),
                    make_clock(1_700_000_000),
                    Duration::from_secs(2_592_000),
                )
            },
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed ok");

        let err = svc
            .login(
                login_receipt(),
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("failing signer must error");

        // mint-first（F4 reorder）：mint 失败 ⇒ TokenIssue，零 AuthGrant co-tx 写、零 outbox 事件。
        assert!(
            matches!(err, LoginError::TokenIssue(_)),
            "expected TokenIssue, got {err:?}"
        );
        assert_eq!(
            capture.count(),
            0,
            "mint-first reorder：mint 失败 ⇒ 零 AuthGrant co-tx 写（F4 回归）"
        );
    }

    // ── 测试 L1252-b：login 首发 refresh token 可轮换（store 已落库，#1252）─────────
    // 通过共享 in-mem store 的 RefreshService 轮换，证明 login 签发的 refresh token 已落库
    // （若 login 未落库，rotate 必返回 Invalid）。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_initial_refresh_token_is_seeded_in_store() {
        let capture = CapturingAuthGrantLifecycle::default();
        let credentials = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed credential");
        let auth_grants = make_auth_grant_services(
            capture,
            DynAccountSecurityReadRepo::new_box(credentials.clone()),
            make_clock(1_700_000_000),
            Duration::from_secs(2_592_000),
        );
        let refresh_svc = auth_grants.refresh_service();
        let login_svc = LoginService::new(
            Arc::from(DynCredentialRepo::new_box(credentials)),
            auth_grants,
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );
        let ta = tid(CANON_TENANT);

        let resp = login_svc
            .login(
                login_receipt(),
                ta,
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");

        assert!(
            !resp.data.refresh_token.is_empty(),
            "login refresh_token 非空"
        );

        // 用 login 回带的 refresh token 轮换 → Ok 证明 login 已落库 store（#1252）
        let rt = authn::RefreshToken::new(resp.data.refresh_token.as_str());
        let bundle = refresh_svc
            .rotate(refresh_receipt(), ta, &rt)
            .await
            .expect("rotate ok after login（token 已在 store）");
        assert!(!bundle.access.as_str().is_empty(), "rotated access 非空");
        assert_ne!(
            bundle.refresh.as_str(),
            resp.data.refresh_token.as_str(),
            "轮换后 refresh ≠ 旧 refresh（一次性）"
        );
    }

    #[test]
    fn application_error_chain_logs_use_redaction_funnel() {
        let source = include_str!("mod.rs");
        let forbidden = ["error_chain = ", "format!", "(\"{err:#}\")"].concat();
        assert!(
            !source.contains(&forbidden),
            "identity application handlers must not log raw error source chains"
        );
        assert!(
            source.contains("secure::redact_error(&err)"),
            "identity application handlers should keep error_chain behind the secure redaction funnel"
        );
    }
}
