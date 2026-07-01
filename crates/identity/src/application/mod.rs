//! identity 应用层：登录编排（哈希凭据 + lockout + L2 co-tx）/ 密码变更（CAS）/ logout（软撤销），#1189。
//!
//! 登录路径（PR4 + #1277，F4 reorder）：lockout 门控 → 恒定成本验签 + 原子锁定记账（`authenticate` →
//! `AuthOutcome` 分流：已知+错推进 lockout、未知不建锁、成功清零）→ mint 会话数据（session_id/payload/
//! entry/envelope，local，no I/O）→ **首发 token mint**（`issue_initial`，先于 co-tx，F4）→ **co-tx**
//! （[`Session`] 持久化 + `identity.session-created` outbox append 同一事务，经
//! `ports::SessionLifecycle::persist_session_and_emit`）→ 返回 `IdentityLoginResponse`。
//! mint-first 语义：mint 失败 ⇒ clean failure（无 session/outbox）；co-tx 失败 ⇒ orphan refresh token
//! （无 session/outbox，随 TTL 自然过期）——全面消除 co-tx 先/mint 失败的半成功窗口（F4 reorder）。
//! logout 经同一 `ports::SessionLifecycle::revoke` 软撤销（create / find / revoke 同源，#1278）。
//!
//! 下游 audit 订阅消费该事件。co-tx 接缝由 postgres adapter `PgSessionLifecycle`
//! （INVARIANT OUTBOX-COTX-SESSION-01）落地。
//!
//! ref: uber-go/fx lifecycle.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（Domain::init push 声明）

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use base64::Engine as _;
use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, OutboxPayload, Topic};
use diport::{
    Clock, EnvelopeSubjectId, OpaqueActorId, OutboxActor, OutboxEmitError, OutboxEnvelopeParts,
};
use generated::event::identity_v1::session_created::{
    CONTRACT, IdentitySessionCreatedPayload, TOPIC,
};
use generated::http::identity_v1::{
    login::{
        IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse, SPEC as LOGIN_HTTP_SPEC,
    },
    logout::{
        IdentityLogoutData, IdentityLogoutRequest, IdentityLogoutResponse, SPEC as LOGOUT_HTTP_SPEC,
    },
    password_change::{
        IdentityPasswordChangeData, IdentityPasswordChangeRequest, IdentityPasswordChangeResponse,
        SPEC as PASSWORD_CHANGE_HTTP_SPEC,
    },
    profile::{
        IdentityProfileData, IdentityProfileDataKind, IdentityProfileResponse,
        SPEC as PROFILE_HTTP_SPEC,
    },
    refresh::{
        IdentityRefreshData, IdentityRefreshRequest, IdentityRefreshResponse,
        SPEC as REFRESH_HTTP_SPEC,
    },
    roles_assign::{
        IdentityRolesAssignData, IdentityRolesAssignRequest, IdentityRolesAssignResponse,
        SPEC as ROLES_ASSIGN_HTTP_SPEC,
    },
    roles_list::{
        IdentityRoleView, IdentityRolesListRequest, IdentityRolesListResponse,
        SPEC as ROLES_LIST_HTTP_SPEC,
    },
    roles_revoke::{
        IdentityRolesRevokeData, IdentityRolesRevokeResponse, SPEC as ROLES_REVOKE_HTTP_SPEC,
    },
};
use generated::http::{
    HttpAuthMode, HttpHeaderMode, HttpSpec, audit_v1::SPEC as AUDIT_LIST_HTTP_SPEC,
    settings_v1::SPEC as SETTINGS_CONFIG_HTTP_SPEC, settings_v2::SPEC as SETTINGS_SECRET_HTTP_SPEC,
};
use httpserve::{
    AuthorizedSubject, Primary, PrimaryRoute, RouteAuthorizationDecision,
    RouteAuthorizationRequest, RouteAuthorizer, RoutePermission, RouteResourceScope,
};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use primitives::RouteAuthOptOut;
use uuid::Uuid;
use vocab::{CoreError, CoreErrorKind, ProjectionField, TenantId};

use crate::domain::{
    AbacAttribute, AttributeKey, AttributeValue, AuthOutcome, IdentityError, LoginIdentifier,
    POLICY_ATTR_CONTRACT_ID, POLICY_ATTR_PERMISSION, POLICY_ATTR_PRINCIPAL_ID,
    POLICY_ATTR_PRINCIPAL_KIND, POLICY_ATTR_RESOURCE_ID, POLICY_ATTR_TENANT_ID, PolicyEvaluation,
    PolicyObligations, PolicyRouteScope, RefreshStatus, RefreshTokenHash, RefreshTokenId,
    RefreshTokenRecord, RoleId, Session, SessionId, evaluate_policies_for_tenant,
};
use crate::ports::{
    CredentialRepo, DynCredentialRepo, DynPolicyRepo, DynRoleBindingLifecycle, DynRoleRepo,
    DynSessionLifecycle, PolicyRepo, RefreshTokenStore, RoleBindingLifecycle, RolePage, RoleRepo,
    SessionLifecycle,
};

/// RBAC 角色管理子域（角色分配 / 撤销 + L2 角色事件发布，#1190 US5）。私有——只经 facade re-export 暴露。
mod rbac_admin;
pub use rbac_admin::{RbacAdminError, RbacAdminService};

/// 发布域（tracing span 标签）。从契约绑定 `CONTRACT` 单源派生（= contract.toml `domain`，#1193），
/// 不再手写字面量——envelope `domain` 由 `OutboxEnvelopeParts::new(CONTRACT, ..)` 同源承载。
const SESSION_DOMAIN: &str = CONTRACT.domain();
/// 登录路由组前缀（Primary listener，业务 API）。
pub const LOGIN_ROUTE_PREFIX: &str = "/api/v1/identity";

/// JWT 署名用途字面量（seed-login / test 路径；≥ 3 处使用，rust-standards §工程护栏抽 const）。
#[cfg(any(test, feature = "seed-login"))]
pub(crate) const SEED_JWT_PURPOSE: &str = "auth.jwt.access";

/// 登录失败。库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射，error-handling.md）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// 用户不存在或密码不匹配（fail-closed：不区分以免用户枚举）。已锁账户亦返回此 variant（lockout 门控）。
    #[error("invalid credentials")]
    InvalidCredentials,
    /// session-created payload 编码失败（原始错误进 source，不进 Display）。
    #[error("session-created payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// outbox entry 构造失败（topic / event-id 非法——系统生成值，理论不可达，fail-closed）。
    #[error("session-created outbox entry build failed")]
    EntryBuild,
    /// 会话过期时间计算溢出（组合根 ttl/clock 误配，fail-closed）。
    #[error("session expiration time overflow")]
    SessionTimeOverflow,
    /// session 持久化 + outbox append 的 **co-tx** 写失败（session INSERT / append / commit 任一步；
    /// 原始错误进 source，已 PII-redacted，不进 Display）。
    #[error("session-created co-tx write failed")]
    SessionWrite(#[source] OutboxEmitError),
    /// 凭据仓储操作失败（CredentialRepo 方法错误通道；in-mem 不触发，postgres 接线 W）。
    #[error("credential store error")]
    Credential(#[source] IdentityError),
    /// 首发 token 签发失败（access JWT 铸造或 refresh token 落库失败，如 vault `Signer` 不可用，#1252）。
    /// mint 先于 co-tx（F4 reorder）：签发失败 ⇒ **clean failure**——无 session 创建、无 outbox 事件。
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
    /// 凭据仓储操作失败。
    #[error("credential store error")]
    Store(#[source] IdentityError),
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
/// 会话生命周期由**单一** [`DynSessionLifecycle`] provider 承载（合并原 `sessions` + `session_uow`，#1278）：
/// login 经 `persist_session_and_emit` co-tx 创建、logout 经 `revoke` 软撤销、查询经 `find`——**同源**，
/// 「创建写 与 撤销/查询落不同 store」从类型层不可表达（PR #255 F3 接缝闭合）。
///
/// 注入形态为 `Arc<DynCredentialRepo>` + `Arc<DynSessionLifecycle>`：域形端口基 trait 为 `Send + Sync`，
/// 使 `LoginService` 可作为 axum handler 共享 state，且 `login().await` future 为 `Send`（#1234）。
///
/// 泛型 `S: Signer`（#1252）：登录成功后经注入的 [`RefreshService<S>`] 首发 access JWT + refresh token bundle
/// （回带至响应）——令组合根注入的 vault `Signer` 有生产消费方。`S` 静态分发（`DynSigner` 非 Sync，见
/// [`authn::JwtIssuer`] DIPORT-ASYNC-ARC-SEND-01），组合根单态化 `S = vault::VaultSigner`。
pub struct LoginService<S> {
    credentials: Arc<DynCredentialRepo<'static>>,
    lifecycle: Arc<DynSessionLifecycle<'static>>,
    refresh: Arc<RefreshService<S>>,
    clock: Box<dyn Clock>,
    session_ttl: Duration,
}

impl<S: diport::Signer + Send + Sync + 'static> LoginService<S> {
    /// 组合根构造：4 必填依赖位置参（缺失即编译错误）+ 会话 ttl。`lifecycle` 是单一会话生命周期 provider
    /// （create/find/revoke 同源，#1278）；`refresh` 承载首发 token 签发（#1252）。
    pub fn new(
        credentials: Arc<DynCredentialRepo<'static>>,
        lifecycle: Arc<DynSessionLifecycle<'static>>,
        refresh: Arc<RefreshService<S>>,
        clock: Box<dyn Clock>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            credentials,
            lifecycle,
            refresh,
            clock,
            session_ttl,
        }
    }

    /// 种子构造（test/seed-login 门控）：哈希凭据种子 + 注入的会话生命周期 provider。
    /// 明文 `password` 仅入参，经 argon2 哈希入库，不存明文。
    #[cfg(any(test, feature = "seed-login"))]
    // reason: seed-login 构造器含 8 个必填位置参（lifecycle/refresh/clock/ttl/login/user_id/password/tenant），
    // 每个均为不可省略的域依赖，不拆 builder（YAGNI；test-only / seed-login feature-gated，非业务 public API）。
    #[allow(clippy::too_many_arguments)]
    pub fn with_seed_credential(
        lifecycle: Arc<DynSessionLifecycle<'static>>,
        refresh: Arc<RefreshService<S>>,
        clock: Box<dyn Clock>,
        session_ttl: Duration,
        login: impl Into<String>,
        user_id: ids::UserId,
        password: &str,
        tenant: TenantId,
    ) -> Result<Self, secure::PasswordError> {
        let creds = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            login, user_id, password, tenant,
        )?;
        // 会话生命周期 provider 由组合根注入（journeys 注 MemSessionLifecycle / PgSessionLifecycle；单测注
        // CapturingSessionLifecycle）——不再自建独立空 session store（原 InMemSessionRepo 与注入 UoW 异 store
        // 即 #1278 F3 接缝根因）；单一 lifecycle ⇒ create/find/revoke 同源。
        Ok(Self::new(
            Arc::from(crate::ports::DynCredentialRepo::new_box(creds)),
            lifecycle,
            refresh,
            clock,
            session_ttl,
        ))
    }

    /// 登录：lockout 门控 → 恒定成本验签 + 原子锁定记账（`authenticate`）→ 据 [`AuthOutcome`] 分流 →
    /// mint 会话数据 → **首发 token mint**（`issue_initial`，先于 co-tx，F4 reorder）→ co-tx（session + outbox）→ 返回响应。
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
        tenant: TenantId,
        request: IdentityLoginRequest,
    ) -> Result<IdentityLoginResponse, LoginError> {
        let login = LoginIdentifier::new(request.username);
        let now = self.clock.now();

        // 1. lockout 门控（验签前；已锁 → fail-closed InvalidCredentials，不验密码/零 UoW 写）
        if self
            .credentials
            .lockout_status(tenant, login.clone(), now)
            .await
            .map_err(LoginError::Credential)?
        {
            return Err(LoginError::InvalidCredentials);
        }

        // 2. 恒定成本验签 + 原子锁定记账（F1+F2）：provider 据 outcome 分流——已知+错已推进 lockout、
        //    未知不建锁、成功清零并返回 canonical actor subject；对外一律 InvalidCredentials（防枚举）。
        let user_id = match self
            .credentials
            .authenticate(tenant, login, request.password, now)
            .await
            .map_err(LoginError::Credential)?
        {
            AuthOutcome::Authenticated(user_id) => user_id,
            AuthOutcome::InvalidKnownUser | AuthOutcome::InvalidUnknown => {
                return Err(LoginError::InvalidCredentials);
            }
        };

        // 3. canonical subject（F1）：来自 credential 的 ids::UserId。payload.subject 是 typed `uuid::Uuid`
        //    （下方直接 `user_id.as_uuid()`，schema `format:uuid`）；此 hyphenated 串供 envelope.subject_id /
        //    Session.subject（仍 opaque String）。登录标识（准 PII）永不进 payload / outbox / broker metadata。
        let subject = user_id.as_uuid().hyphenated().to_string();

        // 4. mint 会话
        let expires_at = now
            .checked_add(self.session_ttl)
            .ok_or(LoginError::SessionTimeOverflow)?;
        let session_id = SessionId::new(authn::SessionId::generate().as_str());

        let payload = IdentitySessionCreatedPayload {
            session_id: session_id.as_str().to_string(),
            // typed canonical actor subject（generated `subject: uuid::Uuid`，#1277 F1：schema `format:uuid`
            // 收紧后非 UUID subject 在 wire decode 即不可表达，consumer 无需 parse）。
            subject: user_id.as_uuid(),
            tenant_id: tenant.to_string(), // canonical hyphenated
            occurred_at: unix_secs(now),
        };
        let bytes = serde_json::to_vec(&payload).map_err(LoginError::PayloadEncode)?;

        // EventId 是独立 opaque 标识（非 session_id；session_id 敏感，不得进 broker metadata/日志）。
        let event_id = Uuid::new_v4().to_string();
        let entry = Entry::new(
            Topic::parse(TOPIC).map_err(|_| LoginError::EntryBuild)?,
            IdemKey::parse(&event_id).map_err(|_| LoginError::EntryBuild)?,
            OutboxPayload::from_reviewed_event_bytes(bytes),
        );
        // 契约归属经 generated `CONTRACT`（domain + contract_id 同源绑定，#1193）；business 只给 opaque subject。
        let subject_id =
            EnvelopeSubjectId::from_opaque(subject.clone()).map_err(|_| LoginError::EntryBuild)?;
        let actor_id =
            OpaqueActorId::from_opaque(subject.clone()).map_err(|_| LoginError::EntryBuild)?;
        let actor = OutboxActor::scoped(
            vocab::PrincipalKind::User,
            actor_id,
            tenant,
            vocab::ScopedTenant::SelfOnly,
        );
        let envelope = OutboxEnvelopeParts::new(CONTRACT, tenant, subject_id, actor);

        // 5. 首发 token bundle（#1252，F4 reorder：mint 先于 co-tx）。
        //    铸 access JWT（注入的 vault `Signer`）+ 签发首个 refresh token——令组合根注入的 `Signer`
        //    有生产消费方。先于 co-tx 执行：mint 失败 ⇒ clean failure（无 session/outbox）。
        //    residual window：mint 成功但步骤 6 co-tx 失败 ⇒ orphan refresh token（无 session/outbox；
        //    随 TTL 自然过期）——完全消除「co-tx 先、mint 失败 ⇒ session 已建但无 token」的半成功窗口。
        //    `subject` = canonical user uuid（JWT `sub`），kind = User（ES256 路径，alg↔kind 一致）。
        let bundle = self
            .refresh
            .issue_initial(tenant, &subject, vocab::PrincipalKind::User)
            .await
            .map_err(LoginError::TokenIssue)?;

        // 6. L2 co-tx（session 行 + outbox 行同一事务原子写入，FR-003）
        let session = Session::new(session_id.clone(), subject.clone(), tenant, expires_at, now);
        self.lifecycle
            .persist_session_and_emit(session, entry, envelope)
            .await
            .map_err(LoginError::SessionWrite)?;

        Ok(IdentityLoginResponse {
            data: IdentityLoginData {
                session_id: session_id.as_str().to_string(),
                expires_at: unix_secs(expires_at),
                access_token: bundle.access.as_str().to_string(),
                refresh_token: bundle.refresh.as_str().to_string(),
                access_expires_at: bundle.access.expires_at(),
            },
        })
    }

    /// 密码变更（校验当前密码 + CAS）。
    ///
    /// `user_id` = 认证主体的 canonical [`ids::UserId`]（self-scoped 锚点，#1277 F2）——身份来自认证上下文，
    /// **非**请求体可选择的登录标识；调用方无法传 login 串定位他人凭据（类型层杜绝越权改他人密码）。
    ///
    /// `skip_all`：不记 current_password / new_password（凭据，zero-trust）；失败经 `err` 记
    /// [`ChangePasswordError`] Display（const literal，无 PII）。低基数定位字段 `domain` / `operation` /
    /// `tenant_id` 显式记入（observability.md §日志，F5）；密码仍 skip（user_id 是 canonical actor、非凭据）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "change_password", tenant_id = %tenant),
        err
    )]
    pub async fn change_password(
        &self,
        tenant: TenantId,
        user_id: ids::UserId,
        current_password: String,
        new_password: String,
    ) -> Result<(), ChangePasswordError> {
        let Some(credential) = self
            .credentials
            .find_by_user_id(tenant, user_id)
            .await
            .map_err(ChangePasswordError::Store)?
        else {
            // F3 等价成本盲化：查无凭据仍跑等价 argon2，消除 NotFound 与 InvalidCredentials 的账户枚举
            // 时序差（与 login 路径 `verify_password_constant_time` 同源防御；身份锚点 = 认证主体 user_id，请求不可选目标账号）。
            let _ = secure::verify_password_constant_time(&current_password, None);
            return Err(ChangePasswordError::NotFound);
        };
        if !credential.verify_password(&current_password) {
            return Err(ChangePasswordError::InvalidCredentials);
        }
        let new_hash =
            secure::hash_password(&new_password).map_err(|_| ChangePasswordError::Hash)?;
        let next = credential.rotate(new_hash);
        self.credentials
            .bump_version(credential.version(), next)
            .await
            .map_err(|e| match e {
                IdentityError::VersionConflict => ChangePasswordError::VersionConflict,
                IdentityError::CredentialNotFound => ChangePasswordError::NotFound,
                // reason: IdentityError #[non_exhaustive]——postgres adapter 接线可能携其它持久化错误，兜底进 Store 通道。
                other => ChangePasswordError::Store(other),
            })
    }

    /// logout（软撤销，直接冒泡 `IdentityError`，不新增错误枚举）。
    /// 幂等——重复/未知/跨租均 Ok 且 no-op；同租户命中但 owner 不匹配则 403，避免撤销他人 session。
    ///
    /// `skip_all`：不记 session_id / actor（凭据级 bearer 标识 / 主体标识）；失败经 `err` 记 `IdentityError`
    /// Display（const literal）。低基数定位字段 `domain` / `operation` / `tenant_id` 显式记入（observability.md
    /// §日志，F5）；session_id / actor 仍 skip。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "logout", tenant_id = %tenant),
        err
    )]
    pub async fn logout(
        &self,
        tenant: TenantId,
        actor: ids::UserId,
        session_id: SessionId,
    ) -> Result<(), IdentityError> {
        let Some(session) = self.lifecycle.find(tenant, session_id.clone()).await? else {
            return Ok(());
        };
        let actor_subject = actor.as_uuid().hyphenated().to_string();
        if session.subject() != actor_subject {
            return Err(IdentityError::PermissionDenied);
        }
        self.lifecycle.revoke(tenant, session_id).await
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
    /// refresh token 已被消费过（重放检测触发级联撤销）。
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

/// Refresh token 应用服务：签发 / 轮换 / 撤销。必填依赖走构造器位置参（缺失即编译错误）。
///
/// ## rotate 设计决策：mint 先于 CAS（#284 F1）
///
/// `rotate` 先 mint access JWT，**成功后才**执行 `store.rotate`（CAS 原子消费旧 token + 写新 token）。
/// 顺序的关键在于**失败语义可恢复**：mint 是可失败步骤（signer 瞬时故障），CAS 提交是不可回滚的副作用。
/// 若先提交 CAS 再 mint，mint 失败时旧 refresh 已被消费、而新 refresh secret 在错误路径被丢弃——客户端
/// 既无可用旧 token 也拿不到新 token，被瞬时 mint 故障**永久锁死**。先 mint：mint 失败 ⇒ 旧 refresh 未消费、
/// 仍 Active，客户端原样重试即可（无锁死、无重放窗口——失败的 mint 未签发任何 access token）。
/// CAS 在 mint 之后，故「旧 refresh 一次性」仍由 CAS 原子性 + 重放级联撤销保证。
/// ref: ory/fosite handler/oauth2/flow_refresh.go@master（先生成 token 再事务内 Rotate/Create）。
pub struct RefreshService<S> {
    store: Box<crate::ports::DynRefreshTokenStore<'static>>,
    issuer: std::sync::Arc<authn::JwtIssuer<S>>,
    clock: Box<dyn diport::Clock>,
    refresh_ttl: Duration,
}

impl<S: diport::Signer + Send + Sync + 'static> RefreshService<S> {
    /// 组合根构造：4 必填依赖位置参（缺失即编译错误）。
    pub fn new(
        store: Box<crate::ports::DynRefreshTokenStore<'static>>,
        issuer: std::sync::Arc<authn::JwtIssuer<S>>,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> Self {
        Self {
            store,
            issuer,
            clock,
            refresh_ttl,
        }
    }

    /// 签发新 refresh token（CSPRNG secret，存摘要）。返回 bearer secret（仅此时暴露一次）。
    ///
    /// `tenant` / `subject` / `kind` 作为 rotation 重签 access JWT 的 claim 源持久化至 store。
    /// `skip_all`：secret / subject 不入 span（零信任；subject 可含 PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_issue", tenant_id = %tenant),
        err
    )]
    pub async fn issue(
        &self,
        tenant: vocab::TenantId,
        subject: &str,
        kind: vocab::PrincipalKind,
    ) -> Result<authn::RefreshToken, RefreshError> {
        let secret = secure::OpaqueToken::generate();
        let hash = RefreshTokenHash::new(secure::digest(secret.expose()));
        let now = self.clock.now();
        let id = RefreshTokenId::generate();
        let record = RefreshTokenRecord::new(
            id.clone(),
            tenant,
            subject,
            kind,
            hash,
            None,
            id,
            RefreshStatus::Active,
            now,
            now + self.refresh_ttl,
        );
        self.store
            .insert(record)
            .await
            .map_err(RefreshError::Store)?;
        Ok(authn::RefreshToken::new(secret.expose()))
    }

    /// 登录首发：铸 access JWT（注入的 vault `Signer` 经 [`authn::JwtIssuer`] 签）+ 签发并落库首个 refresh
    /// token，组成 [`RefreshBundle`]。供 [`LoginService`] 登录成功后调用——令 minted JWT 有生产消费方（#1252）。
    ///
    /// 顺序同 `rotate` 的「mint 先于持久副作用」：先 mint access（失败 ⇒ 无 refresh 记录残留、客户端重登即可），
    /// 成功后 `issue` 落库 refresh token。`subject` / `kind` 是 access JWT 与 refresh 记录的同源 claim。
    ///
    /// `skip_all`：subject 不入 span（零信任；可含 PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_issue_initial", tenant_id = %tenant),
        err
    )]
    pub async fn issue_initial(
        &self,
        tenant: vocab::TenantId,
        subject: &str,
        kind: vocab::PrincipalKind,
    ) -> Result<RefreshBundle, RefreshError> {
        // mint 先于落库：access mint 失败 ⇒ 未写任何 refresh 记录、客户端重登即可（无悬挂 token）。
        let access = self
            .issuer
            .issue(subject, Some(tenant), kind)
            .await
            .map_err(RefreshError::Mint)?;
        let refresh = self.issue(tenant, subject, kind).await?;
        Ok(RefreshBundle { access, refresh })
    }

    /// 轮换 refresh token（reuse-detection + 新 access JWT + 新 refresh token）。
    ///
    /// ## 步骤顺序（参见 struct 级 rustdoc 关于「mint 先于 CAS」的说明）
    ///
    /// 1. 重算呈递串摘要 → `find_by_hash`（查无 → Invalid）
    /// 2. 若 status != Active → 重放检测：级联撤销整条谱系 → Replayed
    /// 3. 若 is_expired → Expired
    /// 4. 由源 record `begin_rotation` 派生 sealed [`RefreshRotation`]（tenant/parent/lineage 类型层 Hard 派生）
    /// 5. mint access JWT（先于 CAS——失败则旧 refresh 未消费、客户端可重试，#284 F1）
    /// 6. 原子 CAS（store.rotate(rotation)）：若未命中 → 并发双换 / 重放：级联撤销 → Replayed
    /// 7. 返回 RefreshBundle
    ///
    /// `skip_all`：presented bearer secret 不入 span（PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_rotate", tenant_id = %tenant),
        err
    )]
    pub async fn rotate(
        &self,
        tenant: vocab::TenantId,
        presented: &authn::RefreshToken,
    ) -> Result<RefreshBundle, RefreshError> {
        // 1. 查找
        let hash = RefreshTokenHash::new(secure::digest(presented.as_str()));
        let rec = self
            .store
            .find_by_hash(tenant, hash)
            .await
            .map_err(RefreshError::Store)?
            .ok_or(RefreshError::Invalid)?;

        // 2. 重放检测：status != Active ⇒ 级联撤销 + Replayed
        if rec.status() != RefreshStatus::Active {
            self.store
                .revoke_lineage(tenant, rec.lineage_id().clone())
                .await
                .map_err(RefreshError::Store)?;
            tracing::warn!(
                tenant_id = %tenant,
                lineage_id = %rec.lineage_id().as_str(),
                operation = "refresh_replay_detected",
                "refresh token replay detected; lineage revoked"
            );
            return Err(RefreshError::Replayed);
        }

        // 3. 过期检测
        let now = self.clock.now();
        if rec.is_expired(now) {
            return Err(RefreshError::Expired);
        }

        // 4. 由源 record 派生 sealed 轮换命令（tenant/parent/lineage 从源派生，错位类型层不可表达，#284 F2）
        let new_secret = secure::OpaqueToken::generate();
        let new_hash = RefreshTokenHash::new(secure::digest(new_secret.expose()));
        let rotation = rec.begin_rotation(
            RefreshTokenId::generate(),
            new_hash,
            now,
            now + self.refresh_ttl,
        );

        // 5. mint access JWT（先于 CAS，#284 F1）：mint 失败 ⇒ 旧 refresh 未消费、客户端可重试、无锁死
        let access = self
            .issuer
            .issue(rec.subject(), Some(tenant), rec.kind())
            .await
            .map_err(RefreshError::Mint)?;

        // 6. 原子 CAS：旧 token 一次性失效（mint 成功后才提交不可回滚的消费）
        let applied = self
            .store
            .rotate(rotation)
            .await
            .map_err(RefreshError::Store)?;
        if !applied {
            // 并发双换 / CAS miss ⇒ 重放处理：级联撤销 + Replayed（已 mint 的 access 丢弃，无害——未交付客户端）
            self.store
                .revoke_lineage(tenant, rec.lineage_id().clone())
                .await
                .map_err(RefreshError::Store)?;
            tracing::warn!(
                tenant_id = %tenant,
                lineage_id = %rec.lineage_id().as_str(),
                operation = "refresh_replay_detected",
                "refresh token replay detected; lineage revoked"
            );
            return Err(RefreshError::Replayed);
        }

        Ok(RefreshBundle {
            access,
            refresh: authn::RefreshToken::new(new_secret.expose()),
        })
    }

    /// 撤销（logout）：撤销整条谱系。查无 token 时幂等 Ok（防止信息泄露）。
    ///
    /// `skip_all`：presented bearer secret 不入 span（PII，observability.md §redaction）。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "refresh_revoke", tenant_id = %tenant),
        err
    )]
    pub async fn revoke(
        &self,
        tenant: vocab::TenantId,
        presented: &authn::RefreshToken,
    ) -> Result<(), RefreshError> {
        let hash = RefreshTokenHash::new(secure::digest(presented.as_str()));
        if let Some(rec) = self
            .store
            .find_by_hash(tenant, hash)
            .await
            .map_err(RefreshError::Store)?
        {
            self.store
                .revoke_lineage(tenant, rec.lineage_id().clone())
                .await
                .map_err(RefreshError::Store)?;
        }
        // reason: 查无 token 时幂等 Ok（logout 不泄露 token 存在性，同 SessionLifecycle::revoke）。
        Ok(())
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
pub fn seed_refresh_service(
    mk_clock: impl Fn() -> Box<dyn diport::Clock>,
    refresh_ttl: Duration,
) -> Arc<RefreshService<SeedSigner>> {
    let issuer = authn::JwtIssuer::new(
        Arc::new(SeedSigner),
        mk_clock(),
        authn::JwtIssuerConfig {
            key: diport::KeyId::new("seed-jwt-key"),
            alg: authn::JwtAlg::Es256,
            purpose: diport::SigningPurpose::new(SEED_JWT_PURPOSE),
            issuer: "https://seed.local".to_string(),
            audience: "rss-seed".to_string(),
            ttl: Duration::from_secs(900),
        },
    )
    // reason: const config（非空 iss/aud/key、ttl>0）⇒ JwtIssuer::new 不可能失败。
    .expect("seed jwt issuer config is valid");
    Arc::new(RefreshService::new(
        crate::ports::DynRefreshTokenStore::new_box(
            crate::internal::mem::InMemRefreshTokenStore::new(),
        ),
        Arc::new(issuer),
        mk_clock(),
        refresh_ttl,
    ))
}

const MAX_LOGIN_BODY_BYTES: usize = 64 * 1024;

fn request_id_from(req: &Request<Body>) -> String {
    httpserve::request_id_str(req.extensions())
        .unwrap_or("unknown")
        .to_string()
}

/// 业务相对 path（去掉 [`LOGIN_ROUTE_PREFIX`]，供 route_group 相对挂载）。login/refresh 共用同一前缀。
fn spec_relative_path(spec: &HttpSpec) -> Result<&'static str, KernelError> {
    let rel = spec
        .path
        .strip_prefix(LOGIN_ROUTE_PREFIX)
        .ok_or(KernelError::RouteGroup)?;
    if rel.starts_with('/') && rel.len() > 1 {
        Ok(rel)
    } else {
        Err(KernelError::RouteGroup)
    }
}

fn spec_method(spec: &HttpSpec) -> Result<Method, KernelError> {
    Method::from_bytes(spec.method.as_bytes()).map_err(|_| KernelError::RouteGroup)
}

fn spec_opt_out(spec: &HttpSpec) -> Result<RouteAuthOptOut, KernelError> {
    match spec.auth.mode {
        HttpAuthMode::Public => Ok(RouteAuthOptOut::Public),
        HttpAuthMode::Bootstrap | HttpAuthMode::ClientsOnly | HttpAuthMode::ServiceOwned => {
            Err(KernelError::RouteGroup)
        }
        HttpAuthMode::Permission => Err(KernelError::RouteGroup),
    }
}

fn primary_route_from_spec(spec: &HttpSpec) -> Result<PrimaryRoute, KernelError> {
    let method = spec_method(spec)?;
    let path = spec_relative_path(spec)?;
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
                path,
                spec.contract_id,
                RoutePermission { permission, scope },
            ))
        }
        HttpAuthMode::Public => Ok(PrimaryRoute::opt_out(
            method,
            path,
            spec.contract_id,
            spec_opt_out(spec)?,
        )),
        HttpAuthMode::Bootstrap | HttpAuthMode::ClientsOnly | HttpAuthMode::ServiceOwned => {
            Err(KernelError::RouteGroup)
        }
    }
}

fn tenant_header_name(spec: &HttpSpec) -> Result<&'static str, KernelError> {
    spec.headers
        .iter()
        .find(|h| h.mode == HttpHeaderMode::PopulateOnly)
        .map(|h| h.name)
        .ok_or(KernelError::RouteGroup)
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
    let tenant = req
        .headers()
        .get(tenant_header)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| TenantId::parse(s).ok())
        .ok_or_else(|| httpserve::error::validation_bad_request(request_id))?;
    let (_, body) = req.into_parts();
    let body = to_bytes(body, MAX_LOGIN_BODY_BYTES)
        .await
        .map_err(|_| httpserve::error::validation_bad_request(request_id))?;
    Ok((tenant, body))
}

async fn login_handler<S: diport::Signer + Send + Sync + 'static>(
    State(service): State<Arc<LoginService<S>>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, body) = match parse_tenant_and_body(req, &LOGIN_HTTP_SPEC, &request_id).await {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };
    login_handler_bytes(service, tenant, body, &request_id).await
}

#[cfg(test)]
pub(crate) fn login_router_for_test<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<LoginService<S>>,
) -> axum::Router {
    axum::Router::new().route(
        LOGIN_HTTP_SPEC.path,
        post(login_handler::<S>).with_state(service),
    )
}

#[cfg(test)]
pub(crate) fn refresh_router_for_test<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<RefreshService<S>>,
) -> axum::Router {
    axum::Router::new().route(
        REFRESH_HTTP_SPEC.path,
        post(refresh_handler::<S>).with_state(service),
    )
}

#[allow(clippy::cognitive_complexity)] // reason: match 臂 + SessionWrite orphan-refresh warn 分支（F4 reorder，#1252）；拆散 handler 反降低可读性
async fn login_handler_bytes<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<LoginService<S>>,
    tenant: TenantId,
    body: Bytes,
    request_id: &str,
) -> Response {
    let request: IdentityLoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(request_id),
    };
    let tenant_log = tenant.to_string();
    match service.login(tenant, request).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(LoginError::InvalidCredentials) => httpserve::error::unauthenticated(request_id),
        Err(err) => {
            if matches!(&err, LoginError::SessionWrite(_)) {
                // F4 reorder 残留窗口：mint 成功后 co-tx 失败 ⇒ refresh token 已落库但无 session/outbox；
                // 随 TTL 自然过期，无 session/outbox 副作用。
                tracing::warn!(
                    request_id,
                    tenant_id = %tenant_log,
                    operation = "login",
                    "session persist failed after token mint; refresh token orphaned (TTL-expiring)"
                );
            }
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %tenant_log,
                contract_id = LOGIN_HTTP_SPEC.contract_id,
                operation = "login",
                "identity login failed"
            );
            httpserve::error::internal_error(request_id)
        }
    }
}

async fn refresh_handler<S: diport::Signer + Send + Sync + 'static>(
    State(service): State<Arc<RefreshService<S>>>,
    req: Request<Body>,
) -> Response {
    let request_id = request_id_from(&req);
    let (tenant, body) = match parse_tenant_and_body(req, &REFRESH_HTTP_SPEC, &request_id).await {
        Ok(parts) => parts,
        Err(resp) => return resp,
    };
    refresh_handler_bytes(service, tenant, body, &request_id).await
}

async fn refresh_handler_bytes<S: diport::Signer + Send + Sync + 'static>(
    service: Arc<RefreshService<S>>,
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
    match service.rotate(tenant, &presented).await {
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
        // refresh token 是凭据：未知/重放/过期一律 401（不区分以免 token 探测），重放已触发级联撤销。
        Err(RefreshError::Invalid | RefreshError::Replayed | RefreshError::Expired) => {
            httpserve::error::unauthenticated(request_id)
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %tenant_log,
                contract_id = REFRESH_HTTP_SPEC.contract_id,
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
}

struct AuthUserContext {
    tenant: TenantId,
    user_id: ids::UserId,
    kind: vocab::PrincipalKind,
}

#[derive(Clone)]
struct ContractAuthorizer {
    roles: Arc<DynRoleRepo<'static>>,
    bindings: Arc<DynRoleBindingLifecycle<'static>>,
    policies: Arc<DynPolicyRepo<'static>>,
    clock: Arc<dyn Clock>,
}

enum ContractAuthPolicy {
    SelfScoped,
    RolePermission(&'static str),
}

fn permission_from_request(
    request: &RouteAuthorizationRequest,
    spec: &HttpSpec,
) -> Result<&'static str, AuthReject> {
    let expected = spec.auth.permission.ok_or(AuthReject::Forbidden)?;
    if request.permission == expected {
        Ok(request.permission)
    } else {
        Err(AuthReject::Forbidden)
    }
}

fn builtin_admin_permission(contract_id: &'static str, permission: &str) -> bool {
    [SETTINGS_CONFIG_HTTP_SPEC, SETTINGS_SECRET_HTTP_SPEC]
        .iter()
        .any(|spec| spec.contract_id == contract_id && spec.auth.permission == Some(permission))
}

fn contract_auth_policy(
    request: &RouteAuthorizationRequest,
) -> Result<ContractAuthPolicy, AuthReject> {
    match request.contract_id {
        id if id == PROFILE_HTTP_SPEC.contract_id => {
            permission_from_request(request, &PROFILE_HTTP_SPEC)?;
            Ok(ContractAuthPolicy::SelfScoped)
        }
        id if id == PASSWORD_CHANGE_HTTP_SPEC.contract_id => {
            permission_from_request(request, &PASSWORD_CHANGE_HTTP_SPEC)?;
            Ok(ContractAuthPolicy::SelfScoped)
        }
        id if id == LOGOUT_HTTP_SPEC.contract_id => {
            permission_from_request(request, &LOGOUT_HTTP_SPEC)?;
            Ok(ContractAuthPolicy::SelfScoped)
        }
        id if id == ROLES_ASSIGN_HTTP_SPEC.contract_id => {
            permission_from_request(request, &ROLES_ASSIGN_HTTP_SPEC)
                .map(ContractAuthPolicy::RolePermission)
        }
        id if id == ROLES_LIST_HTTP_SPEC.contract_id => {
            permission_from_request(request, &ROLES_LIST_HTTP_SPEC)
                .map(ContractAuthPolicy::RolePermission)
        }
        id if id == ROLES_REVOKE_HTTP_SPEC.contract_id => {
            permission_from_request(request, &ROLES_REVOKE_HTTP_SPEC)
                .map(ContractAuthPolicy::RolePermission)
        }
        _ if request.resource.is_none() => {
            Ok(ContractAuthPolicy::RolePermission(request.permission))
        }
        _ => Err(AuthReject::Forbidden),
    }
}

impl ContractAuthorizer {
    fn new(
        roles: Arc<DynRoleRepo<'static>>,
        bindings: Arc<DynRoleBindingLifecycle<'static>>,
        policies: Arc<DynPolicyRepo<'static>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            roles,
            bindings,
            policies,
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
                    Ok(RouteAuthorizationDecision::Allow)
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

    async fn authorize_durable_policy(
        &self,
        ctx: &AuthSubjectContext,
        request: &RouteAuthorizationRequest,
    ) -> Result<PolicyEvaluation, AuthReject> {
        let scope = PolicyRouteScope::parse(request.contract_id, request.permission)
            .map_err(|_| AuthReject::Forbidden)?;
        let policies = self
            .policies
            .list_effective(ctx.tenant, scope, self.clock.now())
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
        Ok(evaluate_policies_for_tenant(
            Some(ctx.tenant),
            &route_policy_attributes(ctx, request),
            &policies,
        ))
    }

    async fn authorize_role_permission(
        &self,
        ctx: &AuthSubjectContext,
        contract_id: &'static str,
        permission: &str,
    ) -> Result<RouteAuthorizationDecision, AuthReject> {
        if ctx.kind == vocab::PrincipalKind::SuperAdmin
            && audit_projection_route(contract_id, permission)
        {
            return Ok(RouteAuthorizationDecision::Allow);
        }
        if ctx.kind != vocab::PrincipalKind::Admin {
            return Err(AuthReject::Forbidden);
        }
        if builtin_admin_permission(contract_id, permission) {
            return Ok(RouteAuthorizationDecision::Allow);
        }
        let bindings = self
            .bindings
            .list_for_subject(ctx.tenant, ctx.subject.clone())
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

        let mut has_permission = false;
        let mut fields = Vec::new();
        for role_id in role_ids {
            let role = self.roles.find(ctx.tenant, role_id).await.map_err(|err| {
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
                for role_permission in role.permission_ids() {
                    if role_permission == permission {
                        has_permission = true;
                    }
                    if audit_projection_route(contract_id, permission) {
                        projection_field_from_permission(role_permission, &mut fields);
                    }
                }
            }
        }
        if has_permission {
            Ok(projection_decision_from_fields(&fields))
        } else {
            Err(AuthReject::Forbidden)
        }
    }
}

fn audit_projection_route(contract_id: &'static str, permission: &str) -> bool {
    contract_id == AUDIT_LIST_HTTP_SPEC.contract_id
        && AUDIT_LIST_HTTP_SPEC.auth.permission == Some(permission)
}

fn projection_field_from_permission(permission: &str, fields: &mut Vec<ProjectionField>) {
    let field = AUDIT_LIST_HTTP_SPEC
        .projection_fields
        .iter()
        .find(|field| field.permission == permission)
        .map(|field| field.field);
    if let Some(field) = field
        && !fields.contains(&field)
    {
        fields.push(field);
    }
}

fn projection_decision_from_obligations(
    request: &RouteAuthorizationRequest,
    obligations: &PolicyObligations,
) -> Result<RouteAuthorizationDecision, AuthReject> {
    if obligations.row_scope().is_some() {
        return Err(AuthReject::Forbidden);
    }
    if !obligations.field_mask().is_empty()
        && !audit_projection_route(request.contract_id, request.permission)
    {
        return Err(AuthReject::Forbidden);
    }
    let mut fields = Vec::new();
    for key in obligations.field_mask() {
        let Some(field) = projection_field_from_obligation_key(key.as_str()) else {
            return Err(AuthReject::Forbidden);
        };
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    Ok(projection_decision_from_fields(&fields))
}

fn projection_field_from_obligation_key(key: &str) -> Option<ProjectionField> {
    AUDIT_LIST_HTTP_SPEC
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
) -> Vec<AbacAttribute> {
    let mut attrs = vec![
        policy_attr(
            POLICY_ATTR_PRINCIPAL_KIND,
            ctx.kind.as_actor_metadata_label(),
        ),
        policy_attr(POLICY_ATTR_PRINCIPAL_ID, &ctx.subject),
        policy_attr(POLICY_ATTR_TENANT_ID, &ctx.tenant.to_string()),
        policy_attr(POLICY_ATTR_CONTRACT_ID, request.contract_id),
        policy_attr(POLICY_ATTR_PERMISSION, request.permission),
    ];
    if let Some(resource) = request.resource.as_ref() {
        attrs.push(policy_attr(POLICY_ATTR_RESOURCE_ID, resource.id()));
    }
    attrs
}

fn policy_attr(key: &str, value: &str) -> AbacAttribute {
    AbacAttribute::new(AttributeKey::new(key), AttributeValue::new(value))
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

struct SelfServiceHandlerState<S> {
    service: Arc<LoginService<S>>,
}

impl<S> Clone for SelfServiceHandlerState<S> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

#[derive(Clone)]
struct RolesListHandlerState {
    roles: Arc<DynRoleRepo<'static>>,
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
    })
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

async fn roles_assign_handler(
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
        .revoke_role(auth.tenant, auth.user_id, auth.kind, role_id, subject_raw)
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
    let result = match state
        .roles
        .list(auth.tenant, RolePage { limit, after })
        .await
    {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %auth.tenant,
                contract_id = ROLES_LIST_HTTP_SPEC.contract_id,
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
            permissions: role.permission_ids().map(str::to_owned).collect(),
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

async fn profile_handler(req: Request<Body>) -> Response {
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
                subject: auth.subject,
                tenant_id: auth.tenant.to_string(),
                kind,
            },
        }),
    )
        .into_response()
}

async fn password_change_handler<S: diport::Signer + Send + Sync + 'static>(
    State(state): State<SelfServiceHandlerState<S>>,
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
    match state
        .service
        .change_password(
            auth.tenant,
            auth.user_id,
            request.current_password,
            request.new_password,
        )
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

async fn logout_handler<S: diport::Signer + Send + Sync + 'static>(
    State(state): State<SelfServiceHandlerState<S>>,
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
    let request: IdentityLogoutRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    match state
        .service
        .logout(
            auth.tenant,
            auth.user_id,
            SessionId::new(request.session_id),
        )
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(IdentityLogoutResponse {
                data: IdentityLogoutData { logged_out: true },
            }),
        )
            .into_response(),
        Err(IdentityError::PermissionDenied) => {
            core_response(CoreErrorKind::Forbidden, &request_id)
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                error_chain = %secure::redact_error(&err),
                request_id,
                tenant_id = %auth.tenant,
                contract_id = LOGOUT_HTTP_SPEC.contract_id,
                operation = "logout",
                "identity logout failed"
            );
            core_response(CoreErrorKind::Internal, &request_id)
        }
    }
}

fn rbac_error_response(
    err: &RbacAdminError,
    tenant: TenantId,
    request_id: &str,
    spec: &HttpSpec,
) -> Response {
    let kind = match err {
        RbacAdminError::RoleNotFound => CoreErrorKind::NotFound,
        RbacAdminError::RoleLookup(_)
        | RbacAdminError::PayloadEncode(_)
        | RbacAdminError::EntryBuild
        | RbacAdminError::BindingWrite(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            error_chain = %secure::redact_error(&err),
            request_id,
            tenant_id = %tenant,
            contract_id = spec.contract_id,
            "identity rbac handler failed"
        );
    }
    core_response(kind, request_id)
}

fn password_error_response(
    err: &ChangePasswordError,
    tenant: TenantId,
    request_id: &str,
) -> Response {
    let kind = match err {
        ChangePasswordError::InvalidCredentials => CoreErrorKind::Forbidden,
        ChangePasswordError::NotFound => CoreErrorKind::NotFound,
        ChangePasswordError::VersionConflict => CoreErrorKind::Conflict,
        ChangePasswordError::Hash | ChangePasswordError::Store(_) => CoreErrorKind::Internal,
    };
    if matches!(kind, CoreErrorKind::Internal) {
        tracing::error!(
            error = %err,
            error_chain = %secure::redact_error(&err),
            request_id,
            tenant_id = %tenant,
            contract_id = PASSWORD_CHANGE_HTTP_SPEC.contract_id,
            operation = "password_change",
            "identity password change failed"
        );
    }
    core_response(kind, request_id)
}

/// identity 域 bootstrap 生命周期：声明 identity HTTP 路由组（Primary listener，同 `/api/v1/identity` 前缀）。
/// 泛型 `S: Signer` 随 login/refresh 服务穿透，组合根单态化 `S = vault::VaultSigner`。
pub struct IdentityDomain<S> {
    login: Arc<LoginService<S>>,
    refresh: Arc<RefreshService<S>>,
    rbac_admin: Arc<RbacAdminService>,
    roles: Arc<DynRoleRepo<'static>>,
    authorizer: Arc<ContractAuthorizer>,
}

impl<S: diport::Signer + Send + Sync + 'static> IdentityDomain<S> {
    pub fn new(
        login: Arc<LoginService<S>>,
        refresh: Arc<RefreshService<S>>,
        rbac_admin: Arc<RbacAdminService>,
        roles: Arc<DynRoleRepo<'static>>,
        bindings: Arc<DynRoleBindingLifecycle<'static>>,
        policies: Arc<DynPolicyRepo<'static>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let authorizer = Arc::new(ContractAuthorizer::new(
            Arc::clone(&roles),
            bindings,
            policies,
            clock,
        ));
        Self {
            login,
            refresh,
            rbac_admin,
            roles,
            authorizer,
        }
    }

    pub fn primary_authorizer(&self) -> Arc<dyn RouteAuthorizer> {
        self.authorizer.clone()
    }
}

impl<S: diport::Signer + Send + Sync + 'static> Domain for IdentityDomain<S> {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        let login = Arc::clone(&self.login);
        let refresh = Arc::clone(&self.refresh);
        let rbac_assign = RbacHandlerState {
            service: Arc::clone(&self.rbac_admin),
        };
        let rbac_revoke = rbac_assign.clone();
        let roles = RolesListHandlerState {
            roles: Arc::clone(&self.roles),
        };
        let password = SelfServiceHandlerState {
            service: Arc::clone(&self.login),
        };
        let logout = password.clone();
        reg.route_group::<Primary>(LOGIN_ROUTE_PREFIX, move |rb| {
            let rb = rb.mount_primary(
                primary_route_from_spec(&LOGIN_HTTP_SPEC)?,
                post(login_handler::<S>).with_state(login),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&REFRESH_HTTP_SPEC)?,
                post(refresh_handler::<S>).with_state(refresh),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&ROLES_ASSIGN_HTTP_SPEC)?,
                post(roles_assign_handler).with_state(rbac_assign),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&ROLES_REVOKE_HTTP_SPEC)?,
                delete(roles_revoke_handler).with_state(rbac_revoke),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&ROLES_LIST_HTTP_SPEC)?,
                get(roles_list_handler).with_state(roles),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&PROFILE_HTTP_SPEC)?,
                get(profile_handler),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&PASSWORD_CHANGE_HTTP_SPEC)?,
                post(password_change_handler::<S>).with_state(password),
            );
            let rb = rb.mount_primary(
                primary_route_from_spec(&LOGOUT_HTTP_SPEC)?,
                post(logout_handler::<S>).with_state(logout),
            );
            Ok(rb)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::ports::{
        Operator, Policy, PolicyCondition, PolicyEffect, PolicyObligations, PolicyRule, Role,
    };
    use diport::OutboxEmitError;
    use testkit::ContractRequest;

    // canonical UUID 种子租户（TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000abc";
    // canonical user id（audit actor 形态；与登录标识 "alice" 解耦，#1277 F1）。
    const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
    // 未种子化的 canonical user id（change_password 未知主体 → NotFound，#1277 F2）。
    const GHOST_USER: &str = "99999999-8888-4777-8666-555544443333";

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：SessionLifecycle / Clock 替身在此手写。
    // CapturingSessionLifecycle 双职能：① 捕获 co-tx 写入（Session + Entry + envelope）供 outbox 断言（test 1-5）；
    // ② 复用 `InMemSessionLifecycle` 承载 session store（create 即写 → find/revoke 同源，不重写 HashMap/租户/
    // 幂等逻辑）——证明 login→logout 经**同一 store** 闭合（#1278）。`Arc` 共享：clone 与 service 持有方共享
    // `writes` + `inner` 两 store。
    #[derive(Clone, Default)]
    struct CapturingSessionLifecycle {
        writes: Arc<Mutex<Vec<(Session, Entry, OutboxEnvelopeParts)>>>,
        inner: crate::internal::mem::InMemSessionLifecycle,
    }
    impl SessionLifecycle for CapturingSessionLifecycle {
        async fn persist_session_and_emit(
            &self,
            session: Session,
            entry: Entry,
            envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            // 委托 inner 承载 store（创建即写 → 同源 find/revoke）；同时捕获写入供 outbox 断言。
            self.inner
                .persist_session_and_emit(session.clone(), entry.clone(), envelope.clone())
                .await?;
            self.writes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((session, entry, envelope));
            Ok(())
        }
        async fn find(
            &self,
            tenant: TenantId,
            session_id: SessionId,
        ) -> Result<Option<Session>, IdentityError> {
            self.inner.find(tenant, session_id).await
        }
        async fn revoke(
            &self,
            tenant: TenantId,
            session_id: SessionId,
        ) -> Result<(), IdentityError> {
            self.inner.revoke(tenant, session_id).await
        }
    }

    impl CapturingSessionLifecycle {
        fn count(&self) -> usize {
            self.writes.lock().unwrap_or_else(|e| e.into_inner()).len()
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

    /// 构造用 with_seed_credential 的 LoginService（默认 CANON_TENANT + 登录标识 alice / canonical
    /// CANON_USER / correct-horse）。内置独立 in-mem RefreshService（#1252 新 2nd arg）。
    fn seed_service(
        capture: &CapturingSessionLifecycle,
        now_secs: u64,
        ttl_secs: u64,
    ) -> LoginService<TestSigner> {
        let refresh = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemRefreshTokenStore::new(),
            make_clock(now_secs),
            Duration::from_secs(2_592_000),
        ));
        #[allow(clippy::expect_used)]
        LoginService::with_seed_credential(
            Arc::from(DynSessionLifecycle::new_box(capture.clone())),
            refresh,
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
        capture: CapturingSessionLifecycle,
        now_secs: u64,
        ttl_secs: u64,
    ) -> IdentityDomain<TestSigner> {
        let refresh = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemRefreshTokenStore::new(),
            make_clock(now_secs),
            Duration::from_secs(2_592_000),
        ));
        #[allow(clippy::expect_used)]
        let login = Arc::new(
            LoginService::with_seed_credential(
                Arc::from(DynSessionLifecycle::new_box(capture)),
                Arc::clone(&refresh),
                make_clock(now_secs),
                Duration::from_secs(ttl_secs),
                "alice",
                uid(CANON_USER),
                "correct-horse",
                tid(CANON_TENANT),
            )
            .expect("seed_domain login ok"),
        );
        let roles_for_admin = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let roles_for_list = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings = Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
            crate::internal::mem::InMemRoleBindingLifecycle::new(),
        ));
        let rbac_admin = Arc::new(RbacAdminService::new(
            roles_for_admin,
            Arc::clone(&bindings),
            make_clock(now_secs),
        ));
        IdentityDomain::new(
            login,
            refresh,
            rbac_admin,
            roles_for_list,
            bindings,
            empty_policy_repo(),
            make_shared_clock(now_secs),
        )
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

    fn with_auth(router: axum::Router, auth: AuthorizedSubject) -> axum::Router {
        router.layer(axum::Extension(auth))
    }

    fn self_service_state(
        service: Arc<LoginService<TestSigner>>,
    ) -> SelfServiceHandlerState<TestSigner> {
        SelfServiceHandlerState { service }
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

    fn policy_repo(repo: crate::internal::mem::InMemPolicyRepo) -> Arc<DynPolicyRepo<'static>> {
        Arc::from(DynPolicyRepo::new_box(repo))
    }

    #[allow(clippy::expect_used)]
    fn route_policy(
        id: &str,
        contract_id: &'static str,
        permission: &str,
        effect: PolicyEffect,
        obligations: PolicyObligations,
    ) -> Policy {
        let rule = PolicyRule::with_obligations(
            PolicyCondition::new(
                AttributeKey::new(POLICY_ATTR_PRINCIPAL_KIND),
                Operator::Eq(AttributeValue::new("admin")),
            ),
            effect,
            obligations,
        );
        Policy::build(
            id,
            tid(CANON_TENANT),
            PolicyRouteScope::parse(contract_id, permission).expect("valid route scope"),
            SystemTime::UNIX_EPOCH,
            None,
            vec![rule],
        )
        .expect("valid policy")
    }

    #[allow(clippy::expect_used)]
    async fn rbac_state_with_role(
        role: Role,
    ) -> (
        RbacHandlerState,
        crate::internal::mem::InMemRoleBindingLifecycle,
    ) {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(tid(CANON_TENANT), role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new().with_binding(
            tid(CANON_TENANT),
            role.id(),
            CANON_USER,
        );
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
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

        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);
        assert_send_sync(&svc);
        assert_send(svc.login(
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
        assert_state::<SelfServiceHandlerState<TestSigner>>();
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

        let capture = CapturingSessionLifecycle::default();
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
                            .login(tid(CANON_TENANT), request)
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
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let resp = svc
            .login(
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
        let (session, entry, envelope) = &writes[0];

        // Session 字段正确。subject = canonical user id（**非** 登录标识 "alice"，#1277 F1）。
        assert_eq!(session.id().as_str(), resp.data.session_id);
        assert_eq!(
            session.subject(),
            CANON_USER,
            "session subject = canonical user id，非登录标识"
        );
        assert_eq!(session.tenant(), tid(CANON_TENANT));
        assert_eq!(
            session.created_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert_eq!(
            session.expires_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 + 3_600)
        );

        // EventId ≠ session_id（敏感标识不得进 broker metadata）。
        assert_eq!(entry.topic().as_str(), TOPIC);
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

        // envelope 携带 generated `CONTRACT` 绑定（domain + contract_id 同源，#1193）；
        // subject_id = canonical user id（登录标识不进 broker metadata）。
        assert_eq!(*envelope.contract(), CONTRACT);
        assert_eq!(envelope.subject_id().as_str(), CANON_USER);
        assert_eq!(envelope.actor().kind(), vocab::PrincipalKind::User);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_session_expiration_overflow_fails_before_write() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1, u64::MAX);

        let err = svc
            .login(
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("expiration overflow must fail");

        assert!(matches!(err, LoginError::SessionTimeOverflow));
        assert_eq!(capture.count(), 0, "expiration overflow → 零 co-tx 写");
    }

    // ── 测试 2：login 密码错 ──────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_wrong_password_returns_invalid_credentials_zero_writes() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
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

    // ── 测试 3：login 未知用户 ────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_unknown_subject_returns_invalid_credentials_zero_writes() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
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
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        // 连续 5 次错密码触发锁定（窗口内 FixedClock 固定在 now_secs=1_000）。
        for _ in 0..5 {
            let _ = svc
                .login(
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
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .login(
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

    // ── 测试 6：change_password 成功（轮换生效） ──────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_success_rotates_credential() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        svc.change_password(
            tid(CANON_TENANT),
            uid(CANON_USER),
            "correct-horse".to_string(),
            "new-pw".to_string(),
        )
        .await
        .expect("change_password ok");

        // 用新密码 login 成功。
        let resp = svc
            .login(
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "new-pw".to_string(),
                },
            )
            .await
            .expect("login with new-pw ok");
        assert!(!resp.data.session_id.is_empty());

        // 用旧密码 login 失败（先把 service 清 lockout，用额外 svc 测）。
        // 旧密码在 change 后应失效：
        let err = svc
            .login(
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("old pw must be rejected");
        assert!(matches!(err, LoginError::InvalidCredentials));
    }

    // ── 测试 7：change_password 旧密码错 ─────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_wrong_current_password_rejected() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .change_password(
                tid(CANON_TENANT),
                uid(CANON_USER),
                "wrong-current".to_string(),
                "new-pw".to_string(),
            )
            .await
            .expect_err("wrong current pw must reject");

        assert!(matches!(err, ChangePasswordError::InvalidCredentials));

        // 旧密码仍可用（change 失败后不影响原凭据）。
        svc.login(
            tid(CANON_TENANT),
            IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            },
        )
        .await
        .expect("original pw still works");
    }

    // ── 测试 8：change_password 凭据不存在 ───────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_unknown_subject_returns_not_found() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        let err = svc
            .change_password(
                tid(CANON_TENANT),
                uid(GHOST_USER),
                "any-pw".to_string(),
                "new-pw".to_string(),
            )
            .await
            .expect_err("unknown subject must be not found");

        assert!(matches!(err, ChangePasswordError::NotFound));
    }

    // ── 测试 8b：change_password 跨租 → NotFound（与 login 跨租对称，fail-closed）────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_cross_tenant_returns_not_found() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600); // 凭据在 CANON_TENANT

        let err = svc
            .change_password(
                tid(OTHER_TENANT),
                uid(CANON_USER),
                "correct-horse".to_string(),
                "new-pw".to_string(),
            )
            .await
            .expect_err("cross-tenant change must be not found");

        assert!(matches!(err, ChangePasswordError::NotFound));

        // 原租户凭据未被改动：旧密码仍可登录。
        svc.login(
            tid(CANON_TENANT),
            IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            },
        )
        .await
        .expect("original tenant credential intact");
    }

    // ── 测试 8c：change_password 以 canonical user_id 定位（login≠user_id，self-scoped 锚点，#1277 F2）──
    // 种子登录标识 "alice" 与 canonical user_id CANON_USER 解耦（不同值）。证明改密锚点是认证主体 user_id、
    // 非请求可选的登录标识：① 用本人 user_id 改密成功（即便它≠login）；② 用他人 user_id 无法定位本凭据
    // （type 层只能传 ids::UserId，无法用 login 串越权改他人密码）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_anchors_on_user_id_not_login() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);

        // ① 本人 canonical user_id（≠ 登录标识 "alice"）改密成功。
        svc.change_password(
            tid(CANON_TENANT),
            uid(CANON_USER),
            "correct-horse".to_string(),
            "new-pw".to_string(),
        )
        .await
        .expect("change by canonical user_id ok");

        // ② 他人 user_id 无法定位本凭据 → NotFound（认证主体锚点，请求不可选目标账号）。
        let err = svc
            .change_password(
                tid(CANON_TENANT),
                uid(GHOST_USER),
                "new-pw".to_string(),
                "x".to_string(),
            )
            .await
            .expect_err("other user_id must not locate this credential");
        assert!(matches!(err, ChangePasswordError::NotFound));

        // 新密码生效（login 路径仍以登录标识 "alice" 认证）。
        svc.login(
            tid(CANON_TENANT),
            IdentityLoginRequest {
                username: "alice".to_string(),
                password: "new-pw".to_string(),
            },
        )
        .await
        .expect("login with new pw via login identifier");
    }

    // ── 测试 9：change_password CAS 冲突（用 mockall 注入） ──────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn change_password_version_conflict_propagated() {
        use crate::ports::DynCredentialRepo;

        // mockall mock for CredentialRepo。
        mockall::mock! {
            CasCreds {}
            impl CredentialRepo for CasCreds {
                async fn find_by_user_id(
                    &self,
                    tenant: TenantId,
                    user_id: ids::UserId,
                ) -> Result<Option<crate::domain::Credential>, IdentityError>;
                async fn authenticate(
                    &self,
                    tenant: TenantId,
                    login: LoginIdentifier,
                    candidate: String,
                    now: SystemTime,
                ) -> Result<AuthOutcome, IdentityError>;
                async fn save(
                    &self,
                    credential: crate::domain::Credential,
                ) -> Result<(), IdentityError>;
                async fn bump_version(
                    &self,
                    expected: u32,
                    next: crate::domain::Credential,
                ) -> Result<(), IdentityError>;
                async fn lockout_status(
                    &self,
                    tenant: TenantId,
                    login: LoginIdentifier,
                    now: SystemTime,
                ) -> Result<bool, IdentityError>;
            }
        }

        let capture = CapturingSessionLifecycle::default();

        // 构造一个种子凭据（通过 InMemCredentialRepo 得到一个有效的 Credential）。
        let cred_repo = crate::internal::mem::InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed");
        let alice_cred = cred_repo
            .find_by_user_id(tid(CANON_TENANT), uid(CANON_USER))
            .await
            .expect("find")
            .expect("some");

        // Mock：find_by_user_id 返回 alice_cred，bump_version 返回 VersionConflict。
        let mut mock = MockCasCreds::new();
        mock.expect_find_by_user_id().returning(move |_t, _u| {
            let c = alice_cred.clone();
            Ok(Some(c))
        });
        mock.expect_bump_version()
            .returning(|_expected, _next| Err(IdentityError::VersionConflict));

        let svc = LoginService::new(
            Arc::from(DynCredentialRepo::new_box(mock)),
            Arc::from(DynSessionLifecycle::new_box(capture)),
            Arc::new(make_refresh_svc(
                crate::internal::mem::InMemRefreshTokenStore::new(),
                make_clock(1_000),
                Duration::from_secs(2_592_000),
            )),
            make_clock(1_000),
            Duration::from_secs(3_600),
        );

        let err = svc
            .change_password(
                tid(CANON_TENANT),
                uid(CANON_USER),
                "correct-horse".to_string(),
                "new-pw".to_string(),
            )
            .await
            .expect_err("version conflict must propagate");

        assert!(matches!(err, ChangePasswordError::VersionConflict));
    }

    // ── 测试 10：login → logout 全链回归（#1278 接缝闭合）─────────────────────────
    // 经**单一** lifecycle：login 写入会话 → 同一 store find=Some → svc.logout 软撤销 → find=None。
    // anti-vacuity：login 写入的会话**真实可读**（非两独立 store；合并前 login 写 UoW、logout 查 SessionRepo
    // 异 store ⇒ find 永远 None，回归不可表达该 bug）——证明合并后 create / revoke / find 同源。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_then_logout_revokes_via_shared_lifecycle() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);
        let ta = tid(CANON_TENANT);

        // login：经 lifecycle.persist_session_and_emit 创建会话（co-tx 写恰一次）。
        let resp = svc
            .login(
                ta,
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");
        let sid = SessionId::new(&resp.data.session_id);
        assert_eq!(capture.count(), 1, "co-tx 写应恰一次");

        // login 写入的会话经同一 lifecycle 可查回（anti-vacuity：非空 store、非两独立面）。
        assert!(
            capture
                .find(ta, sid.clone())
                .await
                .expect("find before")
                .is_some(),
            "login 后应能经同一 lifecycle 找到会话"
        );

        // logout：软撤销反映在同一 store → find=None（接缝闭合）。
        svc.logout(ta, uid(CANON_USER), sid.clone())
            .await
            .expect("logout ok");
        assert!(
            capture.find(ta, sid).await.expect("find after").is_none(),
            "经 service logout 后 find 应返回 None（软撤销，同源 store）"
        );
    }

    // ── 测试 11：logout 跨租 no-op + 幂等（login 写入 + 同源 lifecycle 观测）──────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_cross_tenant_noop_and_idempotent() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);
        let ta = tid(CANON_TENANT);
        let tb = tid(OTHER_TENANT);

        // login（CANON_TENANT，凭据所在租户）写入会话。
        let resp = svc
            .login(
                ta,
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");
        let sid = SessionId::new(&resp.data.session_id);

        // 跨租 logout（tenant B）：no-op，tenant A 会话仍在。
        svc.logout(tb, uid(CANON_USER), sid.clone())
            .await
            .expect("cross-tenant logout ok");
        assert!(
            capture.find(ta, sid.clone()).await.expect("find").is_some(),
            "跨租 logout 不应撤销 TENANT_A 的会话"
        );

        // tenant A logout：首次撤销，第二次幂等仍 Ok。
        svc.logout(ta, uid(CANON_USER), sid.clone())
            .await
            .expect("logout 1 ok");
        assert!(
            capture.find(ta, sid.clone()).await.expect("find").is_none(),
            "TENANT_A logout 后会话应被撤销"
        );
        svc.logout(ta, uid(CANON_USER), sid)
            .await
            .expect("logout 2 idempotent");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_same_tenant_other_actor_forbidden_and_keeps_session() {
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_000, 3_600);
        let ta = tid(CANON_TENANT);
        let resp = svc
            .login(
                ta,
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");
        let sid = SessionId::new(&resp.data.session_id);

        let err = svc
            .logout(ta, uid(GHOST_USER), sid.clone())
            .await
            .expect_err("other actor must not revoke session");

        assert!(matches!(err, IdentityError::PermissionDenied));
        assert!(
            capture.find(ta, sid).await.expect("find").is_some(),
            "他人 logout 失败后原 session 必须仍 active"
        );
    }

    // ── 测试 12：login route group 声明（保留既有测试）────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_domain_declares_login_route_group() {
        let domain = seed_domain(CapturingSessionLifecycle::default(), 1_000, 3_600);
        let reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, LOGIN_ROUTE_PREFIX);
    }

    #[test]
    fn login_service_and_erased_deps_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<LoginService<TestSigner>>();
        assert_send_sync::<Box<DynCredentialRepo<'static>>>();
        assert_send_sync::<Box<DynSessionLifecycle<'static>>>();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_login_route_mount_consumes_generated_spec() {
        let domain = seed_domain(CapturingSessionLifecycle::default(), 1_000, 3_600);
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routes = reg.finalize_routes().expect("finalize routes");
        // identity domain 在 1 个 Primary listener 上挂载多条 identity HTTP 路由，
        // finalize_routes 按 listener 分组 → len() 仍 1（计组/listener，非 route 数）。
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, ListenerKind::Primary);
        assert_eq!(
            spec_relative_path(&LOGIN_HTTP_SPEC).expect("relative path"),
            generated::http::identity_v1::login::PATH
                .strip_prefix(LOGIN_ROUTE_PREFIX)
                .expect("generated path has prefix")
        );
        assert_eq!(
            LOGIN_HTTP_SPEC.contract_id,
            generated::http::identity_v1::login::CONTRACT_ID
        );
        assert_eq!(LOGIN_HTTP_SPEC.method, "POST");
        assert_eq!(
            spec_opt_out(&LOGIN_HTTP_SPEC).expect("opt out"),
            RouteAuthOptOut::Public
        );
        assert!(
            spec_opt_out(&ROLES_ASSIGN_HTTP_SPEC).is_err(),
            "permission endpoint 不 opt-out"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_http_route_specs_match_nested_v1_contracts() {
        let cases = [
            (&LOGIN_HTTP_SPEC, "POST", "/login", None),
            (&REFRESH_HTTP_SPEC, "POST", "/refresh", None),
            (
                &ROLES_ASSIGN_HTTP_SPEC,
                "POST",
                "/roles/{roleId}/bindings",
                Some("identity:role:assign"),
            ),
            (
                &ROLES_REVOKE_HTTP_SPEC,
                "DELETE",
                "/roles/{roleId}/bindings/{subject}",
                Some("identity:role:revoke"),
            ),
            (
                &ROLES_LIST_HTTP_SPEC,
                "GET",
                "/roles",
                Some("identity:role:read"),
            ),
            (
                &PROFILE_HTTP_SPEC,
                "GET",
                "/profile",
                Some("identity:profile:read"),
            ),
            (
                &PASSWORD_CHANGE_HTTP_SPEC,
                "POST",
                "/password/change",
                Some("identity:profile:write"),
            ),
            (
                &LOGOUT_HTTP_SPEC,
                "POST",
                "/logout",
                Some("identity:session:write"),
            ),
        ];

        for (spec, method, path, permission) in cases {
            assert_eq!(spec.method, method);
            assert_eq!(spec_relative_path(spec).expect("relative path"), path);
            assert_eq!(spec.auth.permission, permission);
            if permission.is_some() {
                assert_eq!(spec.auth.mode, HttpAuthMode::Permission);
                assert!(spec_opt_out(spec).is_err());
            } else {
                assert_eq!(spec.auth.mode, HttpAuthMode::Public);
                assert_eq!(
                    spec_opt_out(spec).expect("public opt-out"),
                    RouteAuthOptOut::Public
                );
            }
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
                post(roles_assign_handler).with_state(service),
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
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_denies_user_role_assign_permission() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tid(CANON_TENANT),
            role("role-admin", "Admin", &["identity:role:assign"]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
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
            make_shared_clock(1_000),
        );
        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: ROLES_ASSIGN_HTTP_SPEC.contract_id,
                permission: "identity:role:assign",
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::User,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_allows_builtin_admin_settings_permissions_without_role_binding() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            make_shared_clock(1_000),
        );

        for spec in [SETTINGS_CONFIG_HTTP_SPEC, SETTINGS_SECRET_HTTP_SPEC] {
            let decision = authorizer
                .authorize(RouteAuthorizationRequest {
                    contract_id: spec.contract_id,
                    permission: spec.auth.permission.expect("settings permission"),
                    tenant_id: Some(tid(CANON_TENANT)),
                    principal_kind: vocab::PrincipalKind::Admin,
                    principal_id: CANON_USER.to_string(),
                    resource: None,
                })
                .await;
            assert_eq!(
                decision,
                RouteAuthorizationDecision::Allow,
                "trusted Admin gets built-in settings permission for {}",
                spec.contract_id
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_empty_durable_store_grants_nothing_without_baseline() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: "other:read",
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_durable_allow_permits_without_rbac_binding() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-allow",
                "other.contract",
                "other:read",
                PolicyEffect::Allow,
                PolicyObligations::empty(),
            ),
        ));
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: "other:read",
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_durable_deny_overrides_builtin_baseline() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let permission = SETTINGS_CONFIG_HTTP_SPEC
            .auth
            .permission
            .expect("settings permission");
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-deny",
                SETTINGS_CONFIG_HTTP_SPEC.contract_id,
                permission,
                PolicyEffect::Deny,
                PolicyObligations::empty(),
            ),
        ));
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.contract_id,
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_non_empty_obligation_denies_at_route_gate() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let permission = SETTINGS_CONFIG_HTTP_SPEC
            .auth
            .permission
            .expect("settings permission");
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-obligation",
                SETTINGS_CONFIG_HTTP_SPEC.contract_id,
                permission,
                PolicyEffect::Allow,
                PolicyObligations::new(Some(vocab::ScopedTenant::Tenant), vec![]),
            ),
        ));
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.contract_id,
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
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
            tid(CANON_TENANT),
            role(
                "role-audit",
                "Audit",
                &[
                    vocab::AUDIT_READ_PERMISSION,
                    vocab::AUDIT_FIELD_ACTOR_PERMISSION,
                ],
            ),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
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
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(vocab::ProjectionField::AuditActor));
        assert!(!projection.allows(vocab::ProjectionField::AuditResourceId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_read_without_field_permission_stays_masked() {
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tid(CANON_TENANT),
            role("role-audit", "Audit", &[vocab::AUDIT_READ_PERMISSION]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
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
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_super_admin_audit_read_defaults_masked() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let authorizer = ContractAuthorizer::new(
            roles,
            bindings,
            empty_policy_repo(),
            make_shared_clock(1_000),
        );

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::SuperAdmin,
                principal_id: "super-admin".to_string(),
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Allow);
    }

    #[test]
    fn audit_projection_field_registry_is_generated_from_contract() {
        let fields = AUDIT_LIST_HTTP_SPEC.projection_fields;
        assert_eq!(fields.len(), 2);
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::AuditActor
                && field.permission == vocab::AUDIT_FIELD_ACTOR_PERMISSION
                && field.obligation_key == vocab::AUDIT_ACTOR_FIELD_OBLIGATION
        }));
        assert!(fields.iter().any(|field| {
            field.field == vocab::ProjectionField::AuditResourceId
                && field.permission == vocab::AUDIT_FIELD_RESOURCE_ID_PERMISSION
                && field.obligation_key == vocab::AUDIT_RESOURCE_ID_FIELD_OBLIGATION
        }));
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_policy_field_mask_becomes_projection()
    -> Result<(), String> {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-audit-field",
                AUDIT_LIST_HTTP_SPEC.contract_id,
                vocab::AUDIT_READ_PERMISSION,
                PolicyEffect::Allow,
                PolicyObligations::new(
                    None,
                    vec![AttributeKey::new(vocab::AUDIT_ACTOR_FIELD_OBLIGATION)],
                ),
            ),
        ));
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;

        let projection = match decision {
            RouteAuthorizationDecision::AllowWithProjection(projection) => projection,
            other => return Err(format!("expected projection allow, got {other:?}")),
        };
        assert!(projection.allows(vocab::ProjectionField::AuditActor));
        assert!(!projection.allows(vocab::ProjectionField::AuditResourceId));
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_audit_projection_unknown_field_mask_obligation_denies() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::new().with_policy(
            route_policy(
                "policy-unknown-field",
                AUDIT_LIST_HTTP_SPEC.contract_id,
                vocab::AUDIT_READ_PERMISSION,
                PolicyEffect::Allow,
                PolicyObligations::new(None, vec![AttributeKey::new("audit.email")]),
            ),
        ));
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: AUDIT_LIST_HTTP_SPEC.contract_id,
                permission: vocab::AUDIT_READ_PERMISSION,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;

        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_policy_store_error_denies_before_baseline() {
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(
            crate::internal::mem::InMemRoleRepo::new(),
        ));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
                crate::internal::mem::InMemRoleBindingLifecycle::new(),
            ));
        let policies = policy_repo(crate::internal::mem::InMemPolicyRepo::failing_reads());
        let authorizer =
            ContractAuthorizer::new(roles, bindings, policies, make_shared_clock(1_000));
        let permission = SETTINGS_CONFIG_HTTP_SPEC
            .auth
            .permission
            .expect("settings permission");

        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: SETTINGS_CONFIG_HTTP_SPEC.contract_id,
                permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
                resource: None,
            })
            .await;
        assert_eq!(decision, RouteAuthorizationDecision::Deny);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn contract_authorizer_allows_non_identity_permission_route_by_rbac() {
        let external_permission = "other:read";
        let repo = crate::internal::mem::InMemRoleRepo::new();
        repo.save(
            tid(CANON_TENANT),
            role("role-admin", "Admin", &[external_permission]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
        let bindings: Arc<DynRoleBindingLifecycle<'static>> =
            Arc::from(crate::ports::DynRoleBindingLifecycle::new_box(
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
            make_shared_clock(1_000),
        );
        let decision = authorizer
            .authorize(RouteAuthorizationRequest {
                contract_id: "other.contract",
                permission: external_permission,
                tenant_id: Some(tid(CANON_TENANT)),
                principal_kind: vocab::PrincipalKind::Admin,
                principal_id: CANON_USER.to_string(),
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
                post(roles_assign_handler).with_state(service),
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
            post(roles_assign_handler).with_state(service),
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
        repo.save(tid(CANON_TENANT), seeded_role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new()
            .with_binding(tid(CANON_TENANT), seeded_role.id(), CANON_USER)
            .with_binding(tid(CANON_TENANT), seeded_role.id(), "target-user");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
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
                delete(roles_revoke_handler).with_state(state),
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
        repo.save(tid(CANON_TENANT), seeded_role.clone())
            .await
            .expect("save role");
        let bindings = crate::internal::mem::InMemRoleBindingLifecycle::new()
            .with_binding(tid(CANON_TENANT), seeded_role.id(), CANON_USER)
            .with_binding(tid(CANON_TENANT), seeded_role.id(), "target-user");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
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
            delete(roles_revoke_handler).with_state(state),
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
            tid(CANON_TENANT),
            role("role-a", "A", &["identity:role:read"]),
        )
        .await
        .expect("save a");
        repo.save(tid(CANON_TENANT), role("role-b", "B", &["docs:write"]))
            .await
            .expect("save b");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
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
            tid(CANON_TENANT),
            role("role-a", "A", &["identity:role:read"]),
        )
        .await
        .expect("save role");
        let roles: Arc<DynRoleRepo<'static>> = Arc::from(DynRoleRepo::new_box(repo));
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
        assert_eq!(decoded.data.subject, CANON_USER);
        assert_eq!(decoded.data.tenant_id, CANON_TENANT);
        assert_eq!(decoded.data.kind, IdentityProfileDataKind::User);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_uses_generated_path_and_allows_non_uuid_subject() {
        let subject = "opaque-user-subject";
        let router = with_auth(
            axum::Router::new().route(PROFILE_HTTP_SPEC.path, get(profile_handler)),
            user_evidence(subject),
        );
        let resp = testkit::call(router, ContractRequest::get(PROFILE_HTTP_SPEC.path))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityProfileResponse = resp.json().expect("json");
        assert_eq!(decoded.data.subject, subject);
        assert_eq!(decoded.data.kind.to_string(), "user");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn profile_handler_missing_auth_returns_401() {
        let router = axum::Router::new().route(PROFILE_HTTP_SPEC.path, get(profile_handler));
        let resp = testkit::call(router, ContractRequest::get(PROFILE_HTTP_SPEC.path))
            .await
            .expect("call");
        resp.ensure_status(StatusCode::UNAUTHORIZED)
            .expect("profile missing auth -> 401");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn password_change_handler_uses_authenticated_subject() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let router = with_auth(
            axum::Router::new().route(
                "/password/change",
                post(password_change_handler::<TestSigner>).with_state(self_service_state(svc)),
            ),
            user_evidence(CANON_USER),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/password/change").json(&IdentityPasswordChangeRequest {
                current_password: "correct-horse".to_string(),
                new_password: "new-correct-horse".to_string(),
            }),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityPasswordChangeResponse = resp.json().expect("json");
        assert!(decoded.data.changed);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn password_change_handler_wrong_current_password_returns_403() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let router = with_auth(
            axum::Router::new().route(
                "/password/change",
                post(password_change_handler::<TestSigner>).with_state(self_service_state(svc)),
            ),
            user_evidence(CANON_USER),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/password/change").json(&IdentityPasswordChangeRequest {
                current_password: "wrong-current".to_string(),
                new_password: "new-correct-horse".to_string(),
            }),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::FORBIDDEN)
            .expect("wrong current password -> 403");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn password_change_handler_rejects_missing_auth_malformed_json_and_bad_subject() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let router = axum::Router::new().route(
            PASSWORD_CHANGE_HTTP_SPEC.path,
            post(password_change_handler::<TestSigner>).with_state(self_service_state(svc)),
        );

        let missing_auth = testkit::call(
            router.clone(),
            ContractRequest::post(PASSWORD_CHANGE_HTTP_SPEC.path).json(
                &IdentityPasswordChangeRequest {
                    current_password: "correct-horse".to_string(),
                    new_password: "new-correct-horse".to_string(),
                },
            ),
        )
        .await
        .expect("call missing auth");
        missing_auth
            .ensure_status(StatusCode::UNAUTHORIZED)
            .expect("password change missing auth -> 401");

        let authed = with_auth(router.clone(), user_evidence(CANON_USER));
        let malformed = testkit::call(
            authed,
            ContractRequest::post(PASSWORD_CHANGE_HTTP_SPEC.path)
                .raw_json(br#"{"currentPassword":"correct-horse""#.to_vec()),
        )
        .await
        .expect("call malformed");
        malformed
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("password change malformed json -> 400");

        let bad_subject = testkit::call(
            with_auth(router, user_evidence("not-a-user-uuid")),
            ContractRequest::post(PASSWORD_CHANGE_HTTP_SPEC.path).json(
                &IdentityPasswordChangeRequest {
                    current_password: "correct-horse".to_string(),
                    new_password: "new-correct-horse".to_string(),
                },
            ),
        )
        .await
        .expect("call bad subject");
        bad_subject
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("password change bad principal id -> 403");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handler_soft_revokes_session() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let login_resp = svc
            .login(
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");
        let router = with_auth(
            axum::Router::new().route(
                "/logout",
                post(logout_handler::<TestSigner>).with_state(self_service_state(svc)),
            ),
            user_evidence(CANON_USER),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/logout").json(&IdentityLogoutRequest {
                session_id: login_resp.data.session_id.clone(),
            }),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::OK).expect("200");
        let decoded: IdentityLogoutResponse = resp.json().expect("json");
        assert!(decoded.data.logged_out);
        assert!(
            capture
                .find(
                    tid(CANON_TENANT),
                    SessionId::new(login_resp.data.session_id)
                )
                .await
                .expect("find revoked")
                .is_none(),
            "logout 后 session find 应不可见"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handler_rejects_other_actor_and_keeps_session() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let login_resp = svc
            .login(
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect("login ok");
        let router = with_auth(
            axum::Router::new().route(
                "/logout",
                post(logout_handler::<TestSigner>).with_state(self_service_state(Arc::clone(&svc))),
            ),
            user_evidence(GHOST_USER),
        );
        let resp = testkit::call(
            router,
            ContractRequest::post("/logout").json(&IdentityLogoutRequest {
                session_id: login_resp.data.session_id.clone(),
            }),
        )
        .await
        .expect("call");
        resp.ensure_status(StatusCode::FORBIDDEN)
            .expect("other actor logout -> 403");
        assert!(
            capture
                .find(
                    tid(CANON_TENANT),
                    SessionId::new(login_resp.data.session_id)
                )
                .await
                .expect("find active")
                .is_some(),
            "other actor logout 不应撤销 session"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_handler_rejects_missing_auth_malformed_json_and_bad_subject() {
        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_000, 3_600));
        let router = axum::Router::new().route(
            LOGOUT_HTTP_SPEC.path,
            post(logout_handler::<TestSigner>).with_state(self_service_state(Arc::clone(&svc))),
        );

        let missing_auth = testkit::call(
            router.clone(),
            ContractRequest::post(LOGOUT_HTTP_SPEC.path).json(&IdentityLogoutRequest {
                session_id: "session-1".to_string(),
            }),
        )
        .await
        .expect("call missing auth");
        missing_auth
            .ensure_status(StatusCode::UNAUTHORIZED)
            .expect("logout missing auth -> 401");

        let malformed = testkit::call(
            with_auth(router.clone(), user_evidence(CANON_USER)),
            ContractRequest::post(LOGOUT_HTTP_SPEC.path)
                .raw_json(br#"{"sessionId":"session-1""#.to_vec()),
        )
        .await
        .expect("call malformed");
        malformed
            .ensure_status(StatusCode::BAD_REQUEST)
            .expect("logout malformed json -> 400");

        let bad_subject = testkit::call(
            with_auth(router, user_evidence("not-a-user-uuid")),
            ContractRequest::post(LOGOUT_HTTP_SPEC.path).json(&IdentityLogoutRequest {
                session_id: "session-1".to_string(),
            }),
        )
        .await
        .expect("call bad subject");
        bad_subject
            .ensure_status(StatusCode::FORBIDDEN)
            .expect("logout bad principal id -> 403");
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

    /// 构造用于 RefreshService 测试的 JwtIssuer（ES256，User kind）。
    #[allow(clippy::expect_used)]
    fn make_jwt_issuer(clock: Box<dyn diport::Clock>) -> authn::JwtIssuer<TestSigner> {
        authn::JwtIssuer::new(
            std::sync::Arc::new(TestSigner),
            clock,
            authn::JwtIssuerConfig {
                key: diport::KeyId::new("test-key"),
                alg: authn::JwtAlg::Es256,
                purpose: diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                issuer: "https://test.example".to_string(),
                audience: "test-audience".to_string(),
                ttl: Duration::from_secs(900),
            },
        )
        .expect("valid jwt issuer config")
    }

    /// 构造 RefreshService（共享 in-mem store；clock 由调用方注入）。
    fn make_refresh_svc(
        store: crate::internal::mem::InMemRefreshTokenStore,
        clock: Box<dyn diport::Clock>,
        refresh_ttl: Duration,
    ) -> RefreshService<TestSigner> {
        let issuer = make_jwt_issuer(make_clock(1_700_000_000));
        RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(store),
            std::sync::Arc::new(issuer),
            clock,
            refresh_ttl,
        )
    }

    // ── 测试 R1：happy rotation — issue → rotate 成功（返回 access JWT 非空 + 新 refresh ≠ 旧）
    //             旧 refresh 再 rotate ⇒ Replayed 且原 lineage 全部不再可用 ─────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_happy_rotation_and_replay_detection() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        // issue → rotate 成功
        let old_rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");
        let bundle = svc.rotate(ta, &old_rf).await.expect("rotate ok");
        assert!(
            !bundle.access.as_str().is_empty(),
            "access JWT must be non-empty"
        );
        assert_ne!(
            bundle.refresh.as_str(),
            old_rf.as_str(),
            "新 refresh ≠ 旧 refresh"
        );

        // 旧 refresh 再 rotate ⇒ Replayed（重放检测）
        let err = svc
            .rotate(ta, &old_rf)
            .await
            .expect_err("旧 refresh 已消费，应 Replayed");
        assert!(matches!(err, RefreshError::Replayed), "old rotate: {err:?}");

        // 级联撤销后新 refresh 也不可用
        let err2 = svc
            .rotate(ta, &bundle.refresh)
            .await
            .expect_err("级联撤销后新 refresh 也应 Replayed");
        assert!(
            matches!(err2, RefreshError::Replayed),
            "cascaded new: {err2:?}"
        );
    }

    // ── 测试 R2：重放拒绝 + 级联撤销 — A→B rotate，再用 A ⇒ Replayed，且 B 也 ⇒ Replayed ──

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_replay_triggers_cascade_revoke() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let token_a = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");
        let bundle_b = svc.rotate(ta, &token_a).await.expect("A→B ok");

        // 用 A 重放 ⇒ Replayed（A 已 Consumed）+ 级联 Revoke 整条 lineage
        let err = svc.rotate(ta, &token_a).await.expect_err("replayed A");
        assert!(matches!(err, RefreshError::Replayed));

        // B 也已被级联撤销 ⇒ Replayed
        let err2 = svc
            .rotate(ta, &bundle_b.refresh)
            .await
            .expect_err("cascaded B");
        assert!(matches!(err2, RefreshError::Replayed));
    }

    // ── 测试 R3：旧 refresh 一次性 — rotate 后旧 token 不可再用 ────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_old_token_is_one_shot_after_rotate() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let old_rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");
        let _bundle = svc.rotate(ta, &old_rf).await.expect("rotate ok");

        // 旧 refresh 已 Consumed，不可再轮换
        let err = svc.rotate(ta, &old_rf).await.expect_err("old one-shot");
        assert!(matches!(err, RefreshError::Replayed));
    }

    // ── 测试 R4：撤销幂等 — revoke 两次均 Ok；revoke 后 rotate ⇒ Replayed ──────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_revoke_idempotent_and_blocks_rotate() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");

        // 第一次 revoke Ok
        svc.revoke(ta, &rf).await.expect("revoke 1 ok");
        // 第二次 revoke 幂等 Ok
        svc.revoke(ta, &rf).await.expect("revoke 2 idempotent");

        // revoke 后 rotate ⇒ Replayed（token 已 Revoked）
        let err = svc.rotate(ta, &rf).await.expect_err("revoked rotate");
        assert!(matches!(err, RefreshError::Replayed));
    }

    // ── 测试 R5：过期边界 — refresh_ttl 很短 + clock 推进 → rotate ⇒ Expired ──

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_expired_token_returns_expired() {
        // 共享 in-mem store：issue_svc 签发（now=T），expire_svc 用 T+ttl+1 的 clock rotate。
        let store = crate::internal::mem::InMemRefreshTokenStore::new();

        // 签发服务：clock = T=1000，ttl = 1s（token 于 T+1 过期）
        let issue_svc = make_refresh_svc(store.clone(), make_clock(1_000), Duration::from_secs(1));
        let ta = tid(CANON_TENANT);
        let rf = issue_svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");

        // 轮换服务：clock = T+10（token 已过期），ttl 无关（不会到达写新 record 步骤）
        let expire_svc = make_refresh_svc(store, make_clock(1_010), Duration::from_secs(3_600));
        let err = expire_svc.rotate(ta, &rf).await.expect_err("expired");
        assert!(matches!(err, RefreshError::Expired), "{err:?}");
    }

    // ── 测试 R6：跨租 fail-closed — tenant B 用 tenant A 的 token rotate ⇒ Invalid ─

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_cross_tenant_fail_closed() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);
        let tb = tid(OTHER_TENANT);

        let rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");

        // tenant B 用 tenant A 的 token ⇒ find_by_hash 跨租 → None → Invalid
        let err = svc.rotate(tb, &rf).await.expect_err("cross-tenant");
        assert!(matches!(err, RefreshError::Invalid), "{err:?}");

        // tenant A 的 token 未被影响（仍可 rotate）
        svc.rotate(ta, &rf).await.expect("tenant A token intact");
    }

    // ── 测试 R7：Invalid — 未知 token rotate ⇒ Invalid ──────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_unknown_token_is_invalid() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let unknown = authn::RefreshToken::new("this-token-was-never-issued");
        let err = svc.rotate(ta, &unknown).await.expect_err("unknown token");
        assert!(matches!(err, RefreshError::Invalid), "{err:?}");
    }

    // ── 测试 R8：revoke 未知 token 幂等 Ok ───────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_revoke_unknown_token_is_idempotent() {
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = make_refresh_svc(store, make_clock(1_700_000_000), Duration::from_secs(3_600));
        let ta = tid(CANON_TENANT);

        let unknown = authn::RefreshToken::new("this-token-was-never-issued");
        svc.revoke(ta, &unknown)
            .await
            .expect("revoke unknown is idempotent");
    }

    // ── 测试 R9：CAS-miss 分支 — store.rotate 返回 Ok(false) → revoke_lineage 被调用一次 + Replayed ──
    //
    // 验证 `rotate` 的步骤 5 if !applied 分支：
    // ①  `revoke_lineage` 以正确 lineage_id 被调用恰一次；
    // ②  rotate 返回 `Err(RefreshError::Replayed)`。
    // 用 mockall 控制 store 行为（`find_by_hash` 返回 Active 记录，`rotate` 返回 Ok(false)）。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_rotate_cas_miss_revokes_lineage_and_returns_replayed() {
        use crate::ports::DynRefreshTokenStore;

        mockall::mock! {
            CasMissStore {}
            impl RefreshTokenStore for CasMissStore {
                async fn insert(&self, record: RefreshTokenRecord) -> Result<(), IdentityError>;
                async fn find_by_hash(
                    &self,
                    tenant: TenantId,
                    hash: RefreshTokenHash,
                ) -> Result<Option<RefreshTokenRecord>, IdentityError>;
                async fn rotate(
                    &self,
                    rotation: crate::ports::RefreshRotation,
                ) -> Result<bool, IdentityError>;
                async fn revoke_lineage(
                    &self,
                    tenant: TenantId,
                    lineage_id: RefreshTokenId,
                ) -> Result<(), IdentityError>;
            }
        }

        let ta = tid(CANON_TENANT);
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // 根 token：id == lineage_id（固定 UUID 串便于 withf 捕获）。
        let lineage_str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

        let active_rec = RefreshTokenRecord::hydrate(
            lineage_str, // id
            ta,
            "alice-subj",
            vocab::PrincipalKind::User,
            [0xAA; 32],
            None,        // parent_id = None（根 token）
            lineage_str, // lineage_id = id（根 token）
            RefreshStatus::Active,
            issued,
            issued + Duration::from_secs(3_600),
        );

        let mut mock = MockCasMissStore::new();

        // find_by_hash → Active 记录（步骤 1）
        mock.expect_find_by_hash()
            .returning(move |_t, _h| Ok(Some(active_rec.clone())));

        // rotate → Ok(false)（CAS miss，步骤 6）
        mock.expect_rotate().returning(|_rotation| Ok(false));

        // revoke_lineage 须以正确 lineage_id 被调用恰一次（步骤 5 if !applied 分支）
        mock.expect_revoke_lineage()
            .withf(move |_t, lid| lid.as_str() == lineage_str)
            .times(1)
            .returning(|_t, _lid| Ok(()));

        let svc = RefreshService::new(
            DynRefreshTokenStore::new_box(mock),
            std::sync::Arc::new(make_jwt_issuer(make_clock(1_700_000_000))),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );

        let fake_token = authn::RefreshToken::new("this-causes-cas-miss");
        let err = svc
            .rotate(ta, &fake_token)
            .await
            .expect_err("CAS miss 应返回 Replayed");
        assert!(matches!(err, RefreshError::Replayed), "CAS miss: {err:?}");
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
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let probe = store.clone(); // Arc 共享视图：rotate 后查旧 token 状态
        let ta = tid(CANON_TENANT);

        let issuer = authn::JwtIssuer::new(
            std::sync::Arc::new(FailingSigner),
            make_clock(1_700_000_000),
            authn::JwtIssuerConfig {
                key: diport::KeyId::new("test-key"),
                alg: authn::JwtAlg::Es256,
                purpose: diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                issuer: "https://test.example".to_string(),
                audience: "test-audience".to_string(),
                ttl: Duration::from_secs(900),
            },
        )
        .expect("valid jwt issuer config");
        let svc = RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(store),
            std::sync::Arc::new(issuer),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        );

        // issue 不 mint（仅 insert）⇒ 成功签发旧 refresh
        let old_rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");

        // rotate ⇒ mint 失败（FailingSigner）⇒ Err(Mint)，CAS 从未执行
        let err = svc
            .rotate(ta, &old_rf)
            .await
            .expect_err("mint 失败应返回 Mint 错误");
        assert!(
            matches!(err, RefreshError::Mint(_)),
            "应为 Mint 错误: {err:?}"
        );

        // 关键断言：旧 refresh 未被消费、仍 Active（CAS 先于 mint 会让此处 Consumed → 锁死）
        let old_hash = crate::domain::RefreshTokenHash::new(secure::digest(old_rf.as_str()));
        let found = probe
            .find_by_hash(ta, old_hash)
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
        let capture = CapturingSessionLifecycle::default();
        let svc = seed_service(&capture, 1_700_000_000, 3_600);

        let resp = svc
            .login(
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
    }

    // ── 测试 H-Login-1：login_handler HTTP 级契约测试（F3）─────────────────────────
    // 经 login_router_for_test（真实 login_handler）验证：201 + token bundle 字段非空。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_handler_returns_201_with_token_bundle() -> Result<(), Box<dyn std::error::Error>>
    {
        use testkit::ContractRequest;

        let capture = CapturingSessionLifecycle::default();
        let svc = Arc::new(seed_service(&capture, 1_700_000_000, 3_600));
        let router = login_router_for_test(svc);

        let resp = testkit::call(
            router,
            ContractRequest::post(LOGIN_HTTP_SPEC.path)
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

    // ── 测试 H-Refresh-1..4：refresh_handler HTTP 级契约测试（F2）──────────────────
    // 四维断言：happy(201) / 缺租户头(400) / 坏 body(400) / 未知 token(401)。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_happy_path_returns_201_with_token_bundle()
    -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let svc = Arc::new(make_refresh_svc(
            store,
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let ta = tid(CANON_TENANT);

        // 先签发一个 refresh token 落库，供 handler 轮换。
        let rf = svc
            .issue(ta, "alice-subject", vocab::PrincipalKind::User)
            .await
            .expect("issue ok");

        let router = refresh_router_for_test(Arc::clone(&svc));

        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.path)
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

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn refresh_handler_missing_tenant_header_returns_400()
    -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let svc = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemRefreshTokenStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 不带 X-Tenant-ID header → parse_tenant_and_body → 400
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.path).json(&IdentityRefreshRequest {
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
    async fn refresh_handler_bad_body_returns_400() -> Result<(), Box<dyn std::error::Error>> {
        use testkit::ContractRequest;

        let svc = Arc::new(make_refresh_svc(
            crate::internal::mem::InMemRefreshTokenStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 发送非 JSON body → serde_json::from_slice 失败 → 400
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.path)
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
            crate::internal::mem::InMemRefreshTokenStore::new(),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
        ));
        let router = refresh_router_for_test(svc);

        // 未知 token → RefreshError::Invalid → 401
        let resp = testkit::call(
            router,
            ContractRequest::post(REFRESH_HTTP_SPEC.path)
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

    // ── 测试 L1252-c：login mint 先于 co-tx（F4 reorder）— FailingSigner ⇒ TokenIssue + 零 session ──
    //
    // 回归验证（anti-vacuity）：`FailingSigner.sign()` 永远失败，`issue_initial` 必然返回
    // `RefreshError::Mint` → `LoginError::TokenIssue`。由于 mint 先于 co-tx（F4 reorder），
    // `persist_session_and_emit` 从未执行，故 `capture.count() == 0`（零 session / 零 outbox 事件）。
    // 若顺序仍是「co-tx 先、mint 后」，则 capture.count() 会 == 1，断言会暴露回退。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_failing_signer_no_session_on_token_issue_failure() {
        // 构造 RefreshService<FailingSigner>（issue_initial 必然失败）。
        let issuer = authn::JwtIssuer::new(
            std::sync::Arc::new(FailingSigner),
            make_clock(1_700_000_000),
            authn::JwtIssuerConfig {
                key: diport::KeyId::new("test-key"),
                alg: authn::JwtAlg::Es256,
                purpose: diport::SigningPurpose::new(SEED_JWT_PURPOSE),
                issuer: "https://test.example".to_string(),
                audience: "test-audience".to_string(),
                ttl: Duration::from_secs(900),
            },
        )
        .expect("valid jwt issuer config");

        let refresh_svc = Arc::new(RefreshService::new(
            crate::ports::DynRefreshTokenStore::new_box(
                crate::internal::mem::InMemRefreshTokenStore::new(),
            ),
            std::sync::Arc::new(issuer),
            make_clock(1_700_000_000),
            Duration::from_secs(2_592_000),
        ));

        let capture = CapturingSessionLifecycle::default();
        let svc = LoginService::with_seed_credential(
            Arc::from(DynSessionLifecycle::new_box(capture.clone())),
            refresh_svc,
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
                tid(CANON_TENANT),
                IdentityLoginRequest {
                    username: "alice".to_string(),
                    password: "correct-horse".to_string(),
                },
            )
            .await
            .expect_err("failing signer must error");

        // mint-first（F4 reorder）：mint 失败 ⇒ TokenIssue，零 session co-tx 写、零 outbox 事件。
        assert!(
            matches!(err, LoginError::TokenIssue(_)),
            "expected TokenIssue, got {err:?}"
        );
        assert_eq!(
            capture.count(),
            0,
            "mint-first reorder：mint 失败 ⇒ 零 session co-tx 写（F4 回归）"
        );
    }

    // ── 测试 L1252-b：login 首发 refresh token 可轮换（store 已落库，#1252）─────────
    // 通过共享 in-mem store 的 RefreshService 轮换，证明 login 签发的 refresh token 已落库
    // （若 login 未落库，rotate 必返回 Invalid）。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_initial_refresh_token_is_seeded_in_store() {
        let capture = CapturingSessionLifecycle::default();
        let store = crate::internal::mem::InMemRefreshTokenStore::new();
        let refresh_svc = Arc::new(make_refresh_svc(
            store.clone(),
            make_clock(1_700_000_000),
            Duration::from_secs(2_592_000),
        ));
        let login_svc = LoginService::with_seed_credential(
            Arc::from(DynSessionLifecycle::new_box(capture)),
            Arc::clone(&refresh_svc),
            make_clock(1_700_000_000),
            Duration::from_secs(3_600),
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed ok");
        let ta = tid(CANON_TENANT);

        let resp = login_svc
            .login(
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
            .rotate(ta, &rt)
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
