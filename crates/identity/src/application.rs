//! identity 应用层：登录编排（哈希凭据 + lockout + L2 co-tx）/ 密码变更（CAS）/ logout（软撤销），#1189。
//!
//! 登录路径（PR4 + #1277）：lockout 门控 → 恒定成本验签 + 原子锁定记账（`authenticate` → `AuthOutcome` 分流：
//! 已知+错推进 lockout、未知不建锁、成功清零）→ mint 会话（subject = credential 携带的 canonical
//! `ids::UserId`，**非** 登录标识，F1）→ **co-tx**（[`Session`] 持久化 + `identity.session-created` outbox
//! append 同一事务，经 `ports::SessionLifecycle::persist_session_and_emit`）→ 返回 `IdentityLoginResponse`。
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
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, Topic};
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use generated::event::identity_v1::{CONTRACT, IdentitySessionCreatedPayload, TOPIC};
use generated::http::identity_v1::{
    IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse, SPEC as LOGIN_HTTP_SPEC,
};
use generated::http::{HttpAuthMode, HttpHeaderMode};
use httpserve::{Primary, PrimaryRoute};
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use primitives::RouteAuthOptOut;
use uuid::Uuid;
use vocab::TenantId;

use crate::domain::{
    AuthOutcome, IdentityError, LoginIdentifier, RefreshStatus, RefreshTokenHash, RefreshTokenId,
    RefreshTokenRecord, Session, SessionId,
};
use crate::ports::{
    CredentialRepo, DynCredentialRepo, DynSessionLifecycle, RefreshTokenStore, SessionLifecycle,
};

/// 发布域（tracing span 标签）。从契约绑定 `CONTRACT` 单源派生（= contract.toml `domain`，#1193），
/// 不再手写字面量——envelope `domain` 由 `OutboxEnvelopeParts::new(CONTRACT, ..)` 同源承载。
const SESSION_DOMAIN: &str = CONTRACT.domain();
/// 登录路由组前缀（Primary listener，业务 API）。
pub const LOGIN_ROUTE_PREFIX: &str = "/api/v1/identity";

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
pub struct LoginService {
    credentials: Arc<DynCredentialRepo<'static>>,
    lifecycle: Arc<DynSessionLifecycle<'static>>,
    clock: Box<dyn Clock>,
    session_ttl: Duration,
}

impl LoginService {
    /// 组合根构造：3 必填依赖位置参（缺失即编译错误）+ 会话 ttl。`lifecycle` 是单一会话生命周期 provider
    /// （create/find/revoke 同源，#1278）。
    pub fn new(
        credentials: Arc<DynCredentialRepo<'static>>,
        lifecycle: Arc<DynSessionLifecycle<'static>>,
        clock: Box<dyn Clock>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            credentials,
            lifecycle,
            clock,
            session_ttl,
        }
    }

    /// 种子构造（test/seed-login 门控）：哈希凭据种子 + 注入的会话生命周期 provider。
    /// 明文 `password` 仅入参，经 argon2 哈希入库，不存明文。
    #[cfg(any(test, feature = "seed-login"))]
    pub fn with_seed_credential(
        lifecycle: Arc<DynSessionLifecycle<'static>>,
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
            clock,
            session_ttl,
        ))
    }

    /// 登录：lockout 门控 → 恒定成本验签 + 原子锁定记账（`authenticate`）→ 据 [`AuthOutcome`] 分流 →
    /// mint 会话 → co-tx（session + outbox）→ 返回响应。
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
            bytes,
        );
        // 契约归属经 generated `CONTRACT`（domain + contract_id 同源绑定，#1193）；business 只给 opaque subject。
        let envelope = OutboxEnvelopeParts::new(CONTRACT, tenant, subject.clone());

        // 5. L2 co-tx（session 行 + outbox 行同一事务原子写入，FR-003）
        let session = Session::new(session_id.clone(), subject, tenant, expires_at, now);
        self.lifecycle
            .persist_session_and_emit(session, entry, envelope)
            .await
            .map_err(LoginError::SessionWrite)?;

        Ok(IdentityLoginResponse {
            data: IdentityLoginData {
                session_id: session_id.as_str().to_string(),
                expires_at: unix_secs(expires_at),
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
    /// 幂等——重复/未知/跨租均 Ok 且 no-op。
    ///
    /// `skip_all`：不记 session_id（凭据级 bearer 标识）；失败经 `err` 记 `IdentityError` Display（const literal）。
    /// 低基数定位字段 `domain` / `operation` / `tenant_id` 显式记入（observability.md §日志，F5）；session_id 仍 skip。
    #[tracing::instrument(
        skip_all,
        fields(domain = SESSION_DOMAIN, operation = "logout", tenant_id = %tenant),
        err
    )]
    pub async fn logout(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<(), IdentityError> {
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

const MAX_LOGIN_BODY_BYTES: usize = 64 * 1024;

fn request_id_from(req: &Request<Body>) -> String {
    httpserve::request_id_str(req.extensions())
        .unwrap_or("unknown")
        .to_string()
}

fn login_relative_path() -> Result<&'static str, KernelError> {
    let rel = LOGIN_HTTP_SPEC
        .path
        .strip_prefix(LOGIN_ROUTE_PREFIX)
        .ok_or(KernelError::RouteGroup)?;
    if rel.starts_with('/') && rel.len() > 1 {
        Ok(rel)
    } else {
        Err(KernelError::RouteGroup)
    }
}

fn login_method() -> Result<Method, KernelError> {
    Method::from_bytes(LOGIN_HTTP_SPEC.method.as_bytes()).map_err(|_| KernelError::RouteGroup)
}

fn login_opt_out() -> Result<Option<RouteAuthOptOut>, KernelError> {
    match LOGIN_HTTP_SPEC.auth.mode {
        HttpAuthMode::Public => Ok(Some(RouteAuthOptOut::Public)),
        HttpAuthMode::Permission
        | HttpAuthMode::Bootstrap
        | HttpAuthMode::ClientsOnly
        | HttpAuthMode::ServiceOwned => Err(KernelError::RouteGroup),
    }
}

fn tenant_header_name() -> Result<&'static str, KernelError> {
    LOGIN_HTTP_SPEC
        .headers
        .iter()
        .find(|h| h.mode == HttpHeaderMode::PopulateOnly)
        .map(|h| h.name)
        .ok_or(KernelError::RouteGroup)
}

async fn login_handler(State(service): State<Arc<LoginService>>, req: Request<Body>) -> Response {
    let request_id = request_id_from(&req);
    let tenant_header = match tenant_header_name() {
        Ok(name) => name,
        Err(_) => return httpserve::error::internal_error(&request_id),
    };
    let tenant = match req
        .headers()
        .get(tenant_header)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| TenantId::parse(s).ok())
    {
        Some(tenant) => tenant,
        None => return httpserve::error::validation_bad_request(&request_id),
    };
    let (_, body) = req.into_parts();
    let body = match to_bytes(body, MAX_LOGIN_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return httpserve::error::validation_bad_request(&request_id),
    };
    login_handler_bytes(service, tenant, body, &request_id).await
}

#[cfg(test)]
pub(crate) fn login_router_for_test(service: Arc<LoginService>) -> axum::Router {
    axum::Router::new().route(
        LOGIN_HTTP_SPEC.path,
        post(login_handler).with_state(service),
    )
}

async fn login_handler_bytes(
    service: Arc<LoginService>,
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
            tracing::error!(
                error = %err,
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

/// identity 域 bootstrap 生命周期：声明登录路由组。
pub struct IdentityDomain {
    login: Arc<LoginService>,
}

impl IdentityDomain {
    pub fn new(login: Arc<LoginService>) -> Self {
        Self { login }
    }
}

impl Domain for IdentityDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        let service = Arc::clone(&self.login);
        reg.route_group::<Primary>(LOGIN_ROUTE_PREFIX, move |rb| {
            Ok(rb.mount_primary(
                PrimaryRoute {
                    method: login_method()?,
                    path: login_relative_path()?,
                    contract_id: LOGIN_HTTP_SPEC.contract_id,
                    opt_out: login_opt_out()?,
                },
                post(login_handler).with_state(service),
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use diport::OutboxEmitError;

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

    fn tid(raw: &str) -> TenantId {
        #[allow(clippy::expect_used)]
        TenantId::parse(raw).expect("canonical tenant")
    }

    fn uid(raw: &str) -> ids::UserId {
        #[allow(clippy::expect_used)]
        ids::UserId::parse(raw).expect("canonical user id")
    }

    /// 构造用 with_seed_credential 的 LoginService（默认 CANON_TENANT + 登录标识 alice / canonical
    /// CANON_USER / correct-horse）。
    fn seed_service(
        capture: &CapturingSessionLifecycle,
        now_secs: u64,
        ttl_secs: u64,
    ) -> LoginService {
        #[allow(clippy::expect_used)]
        LoginService::with_seed_credential(
            Arc::from(DynSessionLifecycle::new_box(capture.clone())),
            make_clock(now_secs),
            Duration::from_secs(ttl_secs),
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed_service ok")
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
        assert_eq!(envelope.subject_id(), CANON_USER);
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
        svc.logout(ta, sid.clone()).await.expect("logout ok");
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
        svc.logout(tb, sid.clone())
            .await
            .expect("cross-tenant logout ok");
        assert!(
            capture.find(ta, sid.clone()).await.expect("find").is_some(),
            "跨租 logout 不应撤销 TENANT_A 的会话"
        );

        // tenant A logout：首次撤销，第二次幂等仍 Ok。
        svc.logout(ta, sid.clone()).await.expect("logout 1 ok");
        assert!(
            capture.find(ta, sid.clone()).await.expect("find").is_none(),
            "TENANT_A logout 后会话应被撤销"
        );
        svc.logout(ta, sid).await.expect("logout 2 idempotent");
    }

    // ── 测试 12：login route group 声明（保留既有测试）────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_domain_declares_login_route_group() {
        let capture = CapturingSessionLifecycle::default();
        let domain = IdentityDomain::new(Arc::new(seed_service(&capture, 1_000, 3_600)));
        let reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, LOGIN_ROUTE_PREFIX);
    }

    #[test]
    fn login_service_and_erased_deps_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<LoginService>();
        assert_send_sync::<Box<DynCredentialRepo<'static>>>();
        assert_send_sync::<Box<DynSessionLifecycle<'static>>>();
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_login_route_mount_consumes_generated_spec() {
        let capture = CapturingSessionLifecycle::default();
        let domain = IdentityDomain::new(Arc::new(seed_service(&capture, 1_000, 3_600)));
        let mut reg = bootstrap::compose(&[&domain]).expect("compose ok");
        let routes = reg.finalize_routes().expect("finalize routes");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, ListenerKind::Primary);
        assert_eq!(
            login_relative_path().expect("relative path"),
            generated::http::identity_v1::PATH
                .strip_prefix(LOGIN_ROUTE_PREFIX)
                .expect("generated path has prefix")
        );
        assert_eq!(
            LOGIN_HTTP_SPEC.contract_id,
            generated::http::identity_v1::CONTRACT_ID
        );
        assert_eq!(LOGIN_HTTP_SPEC.method, "POST");
        assert_eq!(
            login_opt_out().expect("opt out"),
            Some(RouteAuthOptOut::Public)
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

    /// 构造用于 RefreshService 测试的 JwtIssuer（ES256，User kind）。
    #[allow(clippy::expect_used)]
    fn make_jwt_issuer(clock: Box<dyn diport::Clock>) -> authn::JwtIssuer<TestSigner> {
        authn::JwtIssuer::new(
            std::sync::Arc::new(TestSigner),
            clock,
            authn::JwtIssuerConfig {
                key: diport::KeyId::new("test-key"),
                alg: authn::JwtAlg::Es256,
                purpose: diport::SigningPurpose::new("auth.jwt.access"),
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
                purpose: diport::SigningPurpose::new("auth.jwt.access"),
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
}
