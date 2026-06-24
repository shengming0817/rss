//! identity 应用层：登录编排（RW-G1 追踪弹 + L2 co-tx，#1083/#1192）。
//!
//! 登录路径证明接缝闭环的起点：校验凭据 → mint 会话 → **co-tx**（[`Session`] 持久化 + `identity.session-created`
//! outbox append 同一事务，经 `ports::SessionUnitOfWork`）→ 返回 `IdentityLoginResponse`。下游 audit 订阅消费
//! 该事件。co-tx 接缝由 postgres adapter `PgSessionUnitOfWork`（INVARIANT OUTBOX-COTX-SESSION-01）落地。
//!
//! 追踪弹边界（服务层闭环，见 #999 计划）：登录服务由组合根（journeys）直接调用，**不逐字节跑 axum**；
//! [`IdentityDomain`] 只经 bootstrap [`Registry`] **声明**登录路由组（register 闭包收集、不执行），
//! 证明 bootstrap 组装了 identity 的路由。真实 JWT 签发 / 密码哈希 / 会话鉴权聚合（`authn::Session`）+ axum
//! 挂载（`httpserve::mount_primary`）留 W。
//!
//! ref: uber-go/fx lifecycle.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（Domain::init push 声明）

use std::time::{Duration, SystemTime};

use bootstrap::{Domain, KernelError, Registry};
use consistency::{Entry, IdemKey, Topic};
use diport::{Clock, OutboxEnvelopeParts};
use generated::event::identity_v1::{CONTRACT_ID, IdentitySessionCreatedPayload, TOPIC};
use generated::http::identity_v1::{
    IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse,
};
use primitives::ListenerKind;
use uuid::Uuid;
use vocab::TenantId;

use crate::domain::{Session, SessionId};
#[cfg(any(test, feature = "seed-login"))]
use crate::internal::mem::InMemUserRepo;
use crate::internal::ports::UserRepo;
use crate::ports::{DynSessionUnitOfWork, SessionUnitOfWork};

/// 发布域（outbox envelope `domain` 字段；= contract.toml `domain`）。
const SESSION_DOMAIN: &str = "identity";
/// 登录路由组前缀（Primary listener，业务 API）。
pub const LOGIN_ROUTE_PREFIX: &str = "/api/v1/identity";

/// 登录失败。库错误枚举（const-literal message，不返回 HTTP 状态码——handler 层映射，error-handling.md）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// 用户不存在或密码不匹配（fail-closed：不区分以免用户枚举）。
    #[error("invalid credentials")]
    InvalidCredentials,
    /// session-created payload 编码失败（原始错误进 source，不进 Display）。
    #[error("session-created payload encode failed")]
    PayloadEncode(#[source] serde_json::Error),
    /// outbox entry 构造失败（topic / event-id 非法——系统生成值，理论不可达，fail-closed）。
    #[error("session-created outbox entry build failed")]
    EntryBuild,
    /// 账号租户标识非 canonical UUID（数据 / 配置错误，fail-closed；不进 session / outbox）。
    #[error("session tenant id invalid")]
    TenantInvalid,
    /// session 持久化 + outbox append 的 **co-tx** 写失败（session INSERT / append / commit 任一步；
    /// 原始错误进 source，已 PII-redacted，不进 Display）。
    #[error("session-created co-tx write failed")]
    SessionWrite(#[source] diport::OutboxEmitError),
}

/// `SystemTime` → UNIX epoch 秒（i64）。负偏移（早于 epoch）收口为 0；溢出收口为 `i64::MAX`。
/// 不取系统时钟（`now` 经注入 [`Clock`]）；`SystemTime::duration_since` 不在 clippy disallowed-methods。
fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// 登录应用服务。必填依赖走构造器位置参（缺失即编译错误，rust-standards §工程护栏）。
pub struct LoginService {
    users: Box<dyn UserRepo>,
    /// co-tx Unit-of-Work：session 持久化 + outbox append 同一事务（取代旧 emit-only `OutboxEmitter`，
    /// 因登录现有业务写（session）⇒ 走 L2 完整 co-tx，FR-003）。
    session_uow: Box<DynSessionUnitOfWork<'static>>,
    clock: Box<dyn Clock>,
    session_ttl: Duration,
}

impl LoginService {
    /// 组合根构造：注入 publisher + clock + 会话 ttl，并以单个种子用户初始化内存 user 库（追踪弹）。
    ///
    /// 仓储留域内（in-mem，[`crate::internal`]）；生产持久化（postgres adapter）留 W。
    ///
    /// **WARNING / TRACER-ONLY**：种子用户密码为明文、登录比对用 `==`（见 [`crate::internal`]）。
    /// 这是追踪弹打通接缝的桩，**W 域作者勿照抄此构造形态**——真实登录走哈希凭据 + 常时比对 + 凭据存储。
    ///
    /// 门控于 `test` / `seed-login` feature（编译期边界，PR #186 F1）：生产组合根不启用即无此构造器，
    /// 杜绝明文凭据路径进生产。组合根（journeys）经 `identity = { features = ["seed-login"] }` 启用。
    #[cfg(any(test, feature = "seed-login"))]
    pub fn with_seed_user(
        session_uow: Box<DynSessionUnitOfWork<'static>>,
        clock: Box<dyn Clock>,
        session_ttl: Duration,
        username: impl Into<String>,
        password: impl Into<String>,
        subject: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            users: Box::new(InMemUserRepo::with_user(
                username, password, subject, tenant_id,
            )),
            session_uow,
            clock,
            session_ttl,
        }
    }

    /// 登录：校验凭据 → mint 会话 → 构造 `outbox::Entry` → 经 `SessionUnitOfWork` **co-tx** 写
    /// （session 持久化 + outbox append 同一事务）→ 返回响应。
    ///
    /// L2 OutboxFact 完整语义（FR-003）：会话**业务写**（[`Session`] 行）与 outbox 发射（`identity.session-created`）
    /// 经 [`SessionUnitOfWork::persist_session_and_emit`] 落同一本地事务（both-or-neither；provider 经 topology
    /// 选型：demo in-mem / prod postgres）。EventId（outbox `event_id` / 幂等锚点）为**独立 opaque UUID**（非
    /// session_id；session_id 敏感，不得进 broker metadata/日志）；EventId 经 relay 盖章 broker message_id、流回
    /// 消费侧 `run_consumer` 的 `IdemKey`，实现「至少一次 + 幂等 = 有效一次」。co-tx 写失败冒泡
    /// [`LoginError::SessionWrite`]。
    ///
    /// `skip_all`：**不记 password / username**（zero-trust：username 可能是 email/UPN，按 PII 处理）；
    /// 失败经 `err` 记 [`LoginError`] Display（const literal，无 PII）。请求关联走 ambient request span。
    #[tracing::instrument(skip_all, err)]
    pub async fn login(
        &self,
        request: IdentityLoginRequest,
    ) -> Result<IdentityLoginResponse, LoginError> {
        let account = self
            .users
            .find(&request.username)
            .filter(|a| a.password == request.password)
            .ok_or(LoginError::InvalidCredentials)?;

        let now = self.clock.now();
        let expires_at = now + self.session_ttl;
        let subject = account.subject;
        let tenant_raw = account.tenant_id;
        // typed tenant（fail-closed）：账号 tenant 非 canonical UUID 属数据/配置错误，不进 session/outbox。
        // 经 co-tx adapter 的 SET LOCAL tenant scope（RLS）+ session 行 `tenant_id` 列写入。
        let tenant = TenantId::parse(&tenant_raw).map_err(|_| LoginError::TenantInvalid)?;

        // 会话 id：authn 生成 UUID v4，桥接到域 newtype（域形 port 只引域内 `SessionId`，ADR-005）。
        let session_id = SessionId::new(authn::SessionId::generate().as_str());

        let payload = IdentitySessionCreatedPayload {
            session_id: session_id.as_str().to_string(),
            subject: subject.clone(),
            tenant_id: tenant_raw, // wire payload 仍用 canonical String 原值（schema 不变）
            occurred_at: unix_secs(now),
        };
        let bytes = serde_json::to_vec(&payload).map_err(LoginError::PayloadEncode)?;

        // EventId 是独立 opaque 标识（非 session_id；session_id 敏感，不得进 broker metadata/日志）。
        // session_id 仅在 payload 内流转（audit 合法消费为 resource_id）。topic/contract_id 自 generated 单源。
        let event_id = Uuid::new_v4().to_string();
        let entry = Entry::new(
            Topic::parse(TOPIC).map_err(|_| LoginError::EntryBuild)?,
            IdemKey::parse(&event_id).map_err(|_| LoginError::EntryBuild)?,
            bytes,
        );
        let envelope = OutboxEnvelopeParts {
            domain: SESSION_DOMAIN.to_string(),
            contract_id: CONTRACT_ID.to_string(),
            // subject = 契约级 **opaque** subject id（FR-020：envelope 仅容 opaque 标识，不容完整 Principal /
            // email / UPN）。当前裸 `String` 无类型层 opacity 保证 ⇒ Session 实体的 Debug 防御性脱敏（按潜在
            // 敏感处理）；W 阶段经 OpaqueSubjectId newtype 类型强制（见 follow-up issue，本 PR OOS）。
            subject_id: subject.clone(),
        };

        // co-tx：session 行 + outbox 行同一事务原子写入（FR-003；adapter 侧 OUTBOX-COTX-SESSION-01）。
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
}

/// identity 域 bootstrap 生命周期：声明登录路由组。
///
/// 追踪弹只**声明**（register 闭包收集、不执行）——证明 bootstrap 组装了 identity 的 Primary 登录路由。
pub struct IdentityDomain;

impl Domain for IdentityDomain {
    fn init(&self, reg: &mut Registry) -> Result<(), KernelError> {
        // 登录路由组（Primary listener）。register 闭包追踪弹不执行：W 阶段经
        //   httpserve::mount_primary(router, PrimaryRoute { method: POST, path: "/login",
        //     contract_id: "identity.login", opt_out: Some(RouteAuthOptOut::Public) }, handler)
        // 挂真实 axum 路由（登录 Public opt-out 仅 Primary listener 可降级，AUTH-OPTOUT-PRIMARYONLY-01）。
        reg.route_group(ListenerKind::Primary, LOGIN_ROUTE_PREFIX, Ok)?;
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

    fn service_with(capture: &CapturingSessionUoW, now_secs: u64, ttl_secs: u64) -> LoginService {
        service_with_tenant(capture, now_secs, ttl_secs, CANON_TENANT)
    }

    fn service_with_tenant(
        capture: &CapturingSessionUoW,
        now_secs: u64,
        ttl_secs: u64,
        tenant_id: &str,
    ) -> LoginService {
        LoginService::with_seed_user(
            DynSessionUnitOfWork::new_box(capture.clone()),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(now_secs),
            )),
            Duration::from_secs(ttl_secs),
            "alice",
            "correct-horse",
            "alice-subject",
            tenant_id,
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_persists_session_and_emits_via_uow_once() {
        let capture = CapturingSessionUoW::default();
        let svc = service_with(&capture, 1_000, 3_600);

        let resp = svc
            .login(IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            })
            .await
            .expect("login ok");

        assert!(!resp.data.session_id.is_empty());
        assert_eq!(resp.data.expires_at, 1_000 + 3_600);

        let writes = capture.writes.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(writes.len(), 1, "co-tx 写应恰一次");
        let (session, entry, envelope) = &writes[0];

        // 业务写实体（Session）：id == 响应 session_id，subject / tenant / 时刻正确。
        assert_eq!(session.id().as_str(), resp.data.session_id);
        assert_eq!(session.subject(), "alice-subject");
        let expected_tenant = TenantId::parse(CANON_TENANT).expect("canonical");
        assert_eq!(session.tenant(), expected_tenant);
        assert_eq!(
            session.created_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
        );
        assert_eq!(
            session.expires_at(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000 + 3_600)
        );

        // F1：EventId（idem_key）是独立 opaque UUID，不等于 session_id（敏感，不得进 broker metadata）。
        assert_eq!(entry.topic().as_str(), TOPIC);
        assert!(!entry.idem_key().as_str().is_empty(), "EventId 不应为空");
        assert_ne!(
            entry.idem_key().as_str(),
            resp.data.session_id,
            "EventId 不应等于 session_id（F1: 避免敏感 session_id 进 broker metadata）"
        );
        let payload: IdentitySessionCreatedPayload =
            serde_json::from_slice(entry.payload()).expect("decode payload");
        assert_eq!(payload.subject, "alice-subject");
        assert_eq!(payload.tenant_id, CANON_TENANT);
        // payload.session_id 仍携 session_id（audit 合法消费为 resource_id）。
        assert_eq!(payload.session_id, resp.data.session_id);
        assert_eq!(payload.occurred_at, 1_000);
        // envelope：domain/contract_id 自单源，subject_id 为 opaque subject（FR-020）。
        assert_eq!(envelope.domain, SESSION_DOMAIN);
        assert_eq!(envelope.contract_id, CONTRACT_ID);
        assert_eq!(envelope.subject_id, "alice-subject");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_rejects_wrong_password_without_persisting_or_emitting() {
        let capture = CapturingSessionUoW::default();
        let svc = service_with(&capture, 1_000, 3_600);

        let err = svc
            .login(IdentityLoginRequest {
                username: "alice".to_string(),
                password: "wrong".to_string(),
            })
            .await
            .expect_err("must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        // 凭据失败 ⇒ 零 co-tx 写（无半写：既不持久化 session 也不 append outbox）。
        assert_eq!(capture.count(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_rejects_unknown_user_without_persisting_or_emitting() {
        let capture = CapturingSessionUoW::default();
        let svc = service_with(&capture, 1_000, 3_600);

        let err = svc
            .login(IdentityLoginRequest {
                username: "mallory".to_string(),
                password: "correct-horse".to_string(),
            })
            .await
            .expect_err("must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(capture.count(), 0);
    }

    // fail-closed：账号 tenant 非 canonical UUID → TenantInvalid，零 co-tx 写（不进 session / outbox）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_rejects_invalid_account_tenant_without_persisting_or_emitting() {
        let capture = CapturingSessionUoW::default();
        let svc = service_with_tenant(&capture, 1_000, 3_600, "not-a-uuid");

        let err = svc
            .login(IdentityLoginRequest {
                username: "alice".to_string(),
                password: "correct-horse".to_string(),
            })
            .await
            .expect_err("must reject invalid tenant");

        assert!(matches!(err, LoginError::TenantInvalid));
        assert_eq!(capture.count(), 0);
    }

    // 测试断言用 expect：item-level carve-out（error-handling.md §Carve-out 要求 item-level）。
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
