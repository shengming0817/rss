//! identity 应用层：登录编排（哈希凭据 + lockout + L2 co-tx）/ 密码变更（CAS）/ logout（软撤销），#1189。
//!
//! 登录路径（PR4 + #1277）：lockout 门控 → 恒定成本验签 + 原子锁定记账（`authenticate` → `AuthOutcome` 分流：
//! 已知+错推进 lockout、未知不建锁、成功清零）→ mint 会话（subject = credential 携带的 canonical
//! `ids::UserId`，**非** 登录标识，F1）→ **co-tx**（[`Session`] 持久化 + `identity.session-created` outbox
//! append 同一事务，经 `ports::SessionUnitOfWork`）→ 返回 `IdentityLoginResponse`。
//!
//! 下游 audit 订阅消费该事件。co-tx 接缝由 postgres adapter `PgSessionUnitOfWork`
//! （INVARIANT OUTBOX-COTX-SESSION-01）落地。
//!
//! ref: uber-go/fx lifecycle.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（Domain::init push 声明）

use std::time::{Duration, SystemTime};

use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, Topic};
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use generated::event::identity_v1::{CONTRACT, IdentitySessionCreatedPayload, TOPIC};
use generated::http::identity_v1::{
    IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse,
};
use httpserve::Primary;
// ListenerKind 仅测试断言用（lib 经 typed `route_group::<Primary>` 不再传运行期 ListenerKind 值）。
#[cfg(test)]
use primitives::ListenerKind;
use uuid::Uuid;
use vocab::TenantId;

use crate::domain::{AuthOutcome, IdentityError, LoginIdentifier, Session, SessionId};
use crate::ports::{
    CredentialRepo, DynCredentialRepo, DynSessionRepo, DynSessionUnitOfWork, SessionRepo,
    SessionUnitOfWork,
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
pub struct LoginService {
    credentials: Box<DynCredentialRepo<'static>>,
    sessions: Box<DynSessionRepo<'static>>,
    session_uow: Box<DynSessionUnitOfWork<'static>>,
    clock: Box<dyn Clock>,
    session_ttl: Duration,
}

impl LoginService {
    /// 组合根构造：4 必填依赖位置参（缺失即编译错误）+ 会话 ttl。
    pub fn new(
        credentials: Box<DynCredentialRepo<'static>>,
        sessions: Box<DynSessionRepo<'static>>,
        session_uow: Box<DynSessionUnitOfWork<'static>>,
        clock: Box<dyn Clock>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            credentials,
            sessions,
            session_uow,
            clock,
            session_ttl,
        }
    }

    /// 种子构造（test/seed-login 门控）：哈希凭据种子 + in-mem 会话仓储。
    /// 明文 `password` 仅入参，经 argon2 哈希入库，不存明文。
    #[cfg(any(test, feature = "seed-login"))]
    pub fn with_seed_credential(
        session_uow: Box<DynSessionUnitOfWork<'static>>,
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
        let sessions = crate::internal::mem::InMemSessionRepo::new();
        Ok(Self::new(
            crate::ports::DynCredentialRepo::new_box(creds),
            crate::ports::DynSessionRepo::new_box(sessions),
            session_uow,
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
        let expires_at = now + self.session_ttl;
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
        let envelope = OutboxEnvelopeParts::new(CONTRACT, subject.clone());

        // 5. L2 co-tx（session 行 + outbox 行同一事务原子写入，FR-003）
        let session = Session::new(session_id.clone(), subject, tenant, expires_at, now);
        self.session_uow
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
        self.sessions.revoke(tenant, session_id).await
    }
}

/// identity 域 bootstrap 生命周期：声明登录路由组。
pub struct IdentityDomain;

impl Domain for IdentityDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        // 登录路由组（Primary listener，typed marker）。register 闭包追踪弹不执行：W 阶段经
        //   rb.mount_primary(PrimaryRoute { method: POST, path: "/login",
        //     contract_id: "identity.login", opt_out: Some(RouteAuthOptOut::Public) }, handler)
        // 挂真实 axum 路由（登录 Public opt-out 仅 Primary listener 可降级，AUTH-OPTOUT-PRIMARYONLY-01）。
        reg.route_group::<Primary>(LOGIN_ROUTE_PREFIX, Ok)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use diport::OutboxEmitError;

    // canonical UUID 种子租户（TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const OTHER_TENANT: &str = "00000000-0000-4000-8000-000000000abc";
    // canonical user id（audit actor 形态；与登录标识 "alice" 解耦，#1277 F1）。
    const CANON_USER: &str = "11111111-2222-4333-8444-555555555555";
    // 未种子化的 canonical user id（change_password 未知主体 → NotFound，#1277 F2）。
    const GHOST_USER: &str = "99999999-8888-4777-8666-555544443333";

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：SessionUnitOfWork / Clock 替身在此手写。
    // 捕获 co-tx 写入（Session 业务实体 + Entry + envelope），断言登录恰调一次、参数正确。
    #[derive(Clone, Default)]
    struct CapturingSessionUoW {
        writes: Arc<Mutex<Vec<(Session, Entry, OutboxEnvelopeParts)>>>,
    }
    impl SessionUnitOfWork for CapturingSessionUoW {
        async fn persist_session_and_emit(
            &self,
            session: Session,
            entry: Entry,
            envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            self.writes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((session, entry, envelope));
            Ok(())
        }
    }

    impl CapturingSessionUoW {
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
    fn seed_service(capture: &CapturingSessionUoW, now_secs: u64, ttl_secs: u64) -> LoginService {
        #[allow(clippy::expect_used)]
        LoginService::with_seed_credential(
            DynSessionUnitOfWork::new_box(capture.clone()),
            make_clock(now_secs),
            Duration::from_secs(ttl_secs),
            "alice",
            uid(CANON_USER),
            "correct-horse",
            tid(CANON_TENANT),
        )
        .expect("seed_service ok")
    }

    // ── 测试 1：login 成功 ────────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_success_persists_once_and_response_correct() {
        let capture = CapturingSessionUoW::default();
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

    // ── 测试 2：login 密码错 ──────────────────────────────────────────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_wrong_password_returns_invalid_credentials_zero_writes() {
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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
        let capture = CapturingSessionUoW::default();
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

        let capture = CapturingSessionUoW::default();

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

        let sessions = crate::internal::mem::InMemSessionRepo::new();
        let svc = LoginService::new(
            DynCredentialRepo::new_box(mock),
            crate::ports::DynSessionRepo::new_box(sessions),
            DynSessionUnitOfWork::new_box(capture),
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

    // ── 测试 10：logout 撤销（经 service 观测共享存储效果）────────────────────
    // sessions 经 Arc 共享：一个克隆注入 service、一个留作断言侧——验证 svc.logout 的软撤销
    // **真实反映在存储上**（不退化成直测 InMemSessionRepo::revoke）。

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_revokes_session() {
        use crate::internal::mem::{InMemCredentialRepo, InMemSessionRepo};
        use crate::ports::DynSessionRepo;

        let ta = tid(CANON_TENANT);
        let sid = SessionId::new("test-sid-logout");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let sessions = InMemSessionRepo::new();
        sessions.insert(Session::new(
            sid.clone(),
            CANON_USER, // canonical user id（与 F1 一致：session.subject 非登录标识）
            ta,
            now + Duration::from_secs(3_600),
            now,
        ));
        // logout 前可查到。
        assert!(
            sessions
                .find(ta, sid.clone())
                .await
                .expect("find before")
                .is_some(),
            "logout 前应能找到会话"
        );

        let creds = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            ta,
        )
        .expect("seed creds");
        let svc = LoginService::new(
            DynCredentialRepo::new_box(creds),
            DynSessionRepo::new_box(sessions.clone()), // service 持共享克隆
            DynSessionUnitOfWork::new_box(CapturingSessionUoW::default()),
            make_clock(1_000),
            Duration::from_secs(3_600),
        );

        // 经 service logout，效果反映在共享 sessions 上：find → None。
        svc.logout(ta, sid.clone()).await.expect("logout ok");
        assert!(
            sessions.find(ta, sid).await.expect("find after").is_none(),
            "经 service logout 后 find 应返回 None（软撤销）"
        );
    }

    // ── 测试 11：logout 跨租 no-op + 幂等（经 service 观测共享存储）──────────────

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn logout_cross_tenant_noop_and_idempotent() {
        use crate::internal::mem::{InMemCredentialRepo, InMemSessionRepo};
        use crate::ports::DynSessionRepo;

        let ta = tid(CANON_TENANT);
        let tb = tid(OTHER_TENANT);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let sid = SessionId::new("test-sid-cross");
        let sessions = InMemSessionRepo::new();
        sessions.insert(Session::new(
            sid.clone(),
            CANON_USER, // canonical user id（与 F1 一致：session.subject 非登录标识）
            ta,
            now + Duration::from_secs(3_600),
            now,
        ));

        let creds = InMemCredentialRepo::with_seed_credential(
            "alice",
            uid(CANON_USER),
            "correct-horse",
            ta,
        )
        .expect("seed");
        let svc = LoginService::new(
            DynCredentialRepo::new_box(creds),
            DynSessionRepo::new_box(sessions.clone()),
            DynSessionUnitOfWork::new_box(CapturingSessionUoW::default()),
            make_clock(1_000),
            Duration::from_secs(3_600),
        );

        // 跨租 logout（tenant B）：no-op，tenant A 会话仍在。
        svc.logout(tb, sid.clone())
            .await
            .expect("cross-tenant logout ok");
        assert!(
            sessions
                .find(ta, sid.clone())
                .await
                .expect("find")
                .is_some(),
            "跨租 logout 不应撤销 TENANT_A 的会话"
        );

        // tenant A logout：首次撤销，第二次幂等仍 Ok。
        svc.logout(ta, sid.clone()).await.expect("logout 1 ok");
        assert!(
            sessions
                .find(ta, sid.clone())
                .await
                .expect("find")
                .is_none(),
            "TENANT_A logout 后会话应被撤销"
        );
        svc.logout(ta, sid).await.expect("logout 2 idempotent");
    }

    // ── 测试 12：login route group 声明（保留既有测试）────────────────────────

    #[test]
    #[allow(clippy::expect_used)]
    fn identity_domain_declares_login_route_group() {
        let reg = bootstrap::compose(&[&IdentityDomain]).expect("compose ok");
        let groups = reg.route_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, ListenerKind::Primary);
        assert_eq!(groups[0].1, LOGIN_ROUTE_PREFIX);
    }
}
