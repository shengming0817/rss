//! identity 应用层：登录编排（RW-G1 追踪弹）。
//!
//! 登录路径证明接缝闭环的起点：校验凭据 → mint 会话 id（authn）→ 发布 `identity.session-created`
//! outbox fact（diport::Publisher，in-mem）→ 返回 `IdentityLoginResponse`。下游 audit 订阅消费该事件。
//!
//! 追踪弹边界（服务层闭环，见 #999 计划）：登录服务由组合根（journeys）直接调用，**不逐字节跑 axum**；
//! [`IdentityDomain`] 只经 bootstrap [`Registry`] **声明**登录路由组（register 闭包收集、不执行），
//! 证明 bootstrap 组装了 identity 的路由。真实 JWT 签发 / 密码哈希 / 会话聚合（`authn::Session`）+ axum
//! 挂载（`httpserve::mount_primary`）留 W。
//!
//! ref: uber-go/fx lifecycle.go@6fab1b2d3a549a67dfcf50b96161a887181c2afa（Domain::init push 声明）

use std::time::{Duration, SystemTime};

use bootstrap::{Domain, KernelError, Registry};
use diport::{Clock, DynPublisher, PublishRequest, Publisher, Topic};
use generated::event::identity_v1::IdentitySessionCreatedPayload;
use generated::http::identity_v1::{
    IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse,
};
use primitives::ListenerKind;

#[cfg(any(test, feature = "seed-login"))]
use crate::internal::mem::InMemUserRepo;
use crate::internal::ports::UserRepo;

/// session-created event 契约 topic（contracts/event/identity/v1）。
pub const SESSION_CREATED_TOPIC: &str = "identity.session-created";
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
    /// session-created 发布失败（原始错误进 source）。
    #[error("session-created publish failed")]
    Publish(#[source] diport::PublisherError),
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
    publisher: Box<DynPublisher<'static>>,
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
        publisher: Box<DynPublisher<'static>>,
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
            publisher,
            clock,
            session_ttl,
        }
    }

    /// 登录：校验凭据 → mint 会话 id → 发布 session-created → 返回响应。
    ///
    /// L2 OutboxFact：本地（mint 会话）+ outbox 发布（in-mem）。发布失败冒泡 [`LoginError::Publish`]。
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

        let session_id = authn::SessionId::generate();
        let now = self.clock.now();
        let expires_at = now + self.session_ttl;

        let payload = IdentitySessionCreatedPayload {
            session_id: session_id.as_str().to_string(),
            subject: account.subject,
            tenant_id: account.tenant_id,
            occurred_at: unix_secs(now),
        };
        let bytes = serde_json::to_vec(&payload).map_err(LoginError::PayloadEncode)?;
        self.publisher
            .publish(PublishRequest {
                topic: Topic::new(SESSION_CREATED_TOPIC),
                payload: bytes,
            })
            .await
            .map_err(LoginError::Publish)?;

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

    use diport::PublisherError;

    // canonical UUID 种子租户（TenantId::parse 接受形态）。
    const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // 域单测不依赖 adapter crate（rust-standards.md §命名）：Publisher / Clock 替身在此手写。
    #[derive(Clone, Default)]
    struct CapturingPublisher {
        published: Arc<Mutex<Vec<PublishRequest>>>,
    }
    impl Publisher for CapturingPublisher {
        async fn publish(&self, request: PublishRequest) -> Result<(), PublisherError> {
            self.published
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(request);
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), PublisherError> {
            Ok(())
        }
    }

    struct FixedClock(SystemTime);
    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn service_with(capture: &CapturingPublisher, now_secs: u64, ttl_secs: u64) -> LoginService {
        LoginService::with_seed_user(
            DynPublisher::new_box(capture.clone()),
            Box::new(FixedClock(
                SystemTime::UNIX_EPOCH + Duration::from_secs(now_secs),
            )),
            Duration::from_secs(ttl_secs),
            "alice",
            "correct-horse",
            "alice-subject",
            CANON_TENANT,
        )
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_publishes_session_created_and_returns_session() {
        let capture = CapturingPublisher::default();
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

        let published = capture.published.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].topic.as_str(), SESSION_CREATED_TOPIC);
        let payload: IdentitySessionCreatedPayload =
            serde_json::from_slice(&published[0].payload).expect("decode payload");
        assert_eq!(payload.subject, "alice-subject");
        assert_eq!(payload.tenant_id, CANON_TENANT);
        assert_eq!(payload.session_id, resp.data.session_id);
        assert_eq!(payload.occurred_at, 1_000);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_rejects_wrong_password_without_publishing() {
        let capture = CapturingPublisher::default();
        let svc = service_with(&capture, 1_000, 3_600);

        let err = svc
            .login(IdentityLoginRequest {
                username: "alice".to_string(),
                password: "wrong".to_string(),
            })
            .await
            .expect_err("must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(
            capture
                .published
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn login_rejects_unknown_user() {
        let capture = CapturingPublisher::default();
        let svc = service_with(&capture, 1_000, 3_600);

        let err = svc
            .login(IdentityLoginRequest {
                username: "mallory".to_string(),
                password: "correct-horse".to_string(),
            })
            .await
            .expect_err("must reject");

        assert!(matches!(err, LoginError::InvalidCredentials));
        assert_eq!(
            capture
                .published
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            0
        );
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
