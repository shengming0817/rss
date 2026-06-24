//! `identity.login` 契约测试样板（#1136）——演示用 `testkit` harness 给 served HTTP 契约写
//! per-contract 测试的模板；W 域作者照此形态给自己的 served 契约补契约回归。
//!
//! # 覆盖（handler 行为维度，域内可测、零 adapter 依赖）
//!
//! - **正常响应 schema**：POST 合法凭据 → 200，body 反序列化进 generated [`IdentityLoginResponse`]
//!   （`resp.json::<IdentityLoginResponse>()` 往返成立 = schema 与契约派生类型对齐，#1136 验收）。
//! - **参数错误 + 错误码**：畸形 body → 400 + wire error envelope（`ERR_CORE_VALIDATION`）。
//! - 负路径：错误凭据 → 401 + `ERR_CORE_UNAUTHENTICATED`。
//!
//! # 四维按层分裂（#1136 计划）
//!
//! **鉴权边界（401/403 运行期闸）+ path 参数 newtype 校验**是框架 / 组合根关注点，不在本域样板：
//! - 域 crate **禁止构造 `AuthPlan`**（`runtime-api.md`），运行期 auth 闸（`finalize_auth` + plan）的
//!   端到端断言由 `httpserve/tests/runtime.rs` 穷举；
//! - `identity.login` **无 path 参数**；path newtype 校验维度由 `testkit` 自测（`crates/testkit/tests/harness.rs`，
//!   合成 router）通用验证。
//!
//! 故本样板用 **plain axum 挂载** handler（绕过 auth enforce 层，直验 handler 行为）。
//!
//! # 桩边界（重要）
//!
//! `identity.login` 仍 `lifecycle = draft`、生产未挂载（axum mount + graduate active 留 W）。**当前
//! [`LoginService`](crate::LoginService) 不可直接挂 axum handler**：它持 `Box<DynSessionUnitOfWork>`
//! （dynosaur Send-only dyn）⇒ `LoginService: !Sync` ⇒ `&self.login(..).await` 使 handler future `!Send`，
//! 而 axum handler future 须 `Send`。故本样板 handler **内联凭据判定 + 构造 generated [`IdentityLoginResponse`]**
//! 验 testkit 维度（凭据/会话逻辑的服务层覆盖见 `application.rs` 单测 + journey）。W 真实挂载前须先使
//! service `Sync`——即 session_uow 的 dyn 类型须 `Send + Sync`（提供 `DynSessionUnitOfWork` 的 Send+Sync
//! 变体，或组合根注入 `Arc<dyn SessionUnitOfWork + Send + Sync>`），与 axum mount 一并解决。本样板把该约束显式暴露。
//! 错误 envelope 为 tracer-grade（W 改用 generated typed response envelope，`domain-patterns.md §Typed response envelope`）。
//!
//! ref: tokio-rs/axum examples/testing/src/main.rs@3f8956dcd007070be5449dd23102b7ee7f2e1b05（fn app()->Router + oneshot）

use axum::Json;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use generated::http::identity_v1::{
    IdentityLoginData, IdentityLoginRequest, IdentityLoginResponse,
};
use testkit::ContractRequest;

use crate::application::LOGIN_ROUTE_PREFIX;

const SEED_USER: &str = "alice";
const SEED_PASSWORD: &str = "correct-horse";
/// 固定会话有效期（秒）——**仅样板确定性断言用，非生产 TTL 来源**。样板直接把它当 `expires_at` 返回
/// （相对 TTL 秒），而生产 `LoginService::login` 返回 **UNIX epoch 秒** `unix_secs(clock.now() + ttl)`
/// （见 application.rs）；W 真实 handler 须用 epoch 语义，勿照抄样板的 TTL 直填。
const SESSION_TTL_SECS: i64 = 3_600;

/// 登录契约路径——单源自 [`LOGIN_ROUTE_PREFIX`]，避免与 router 挂载路径漂移（前缀变更时测试路径同步，B9）。
fn login_path() -> String {
    format!("{LOGIN_ROUTE_PREFIX}/login")
}

/// 样板 login handler：读 body → 反序列化 generated [`IdentityLoginRequest`] → 凭据判定 →
/// 成功 typed `Json(IdentityLoginResponse)`；body 解析失败 / 凭据失败经 [`testkit::wire_error_response`]
/// 映射为 wire envelope 错误码。
///
/// 会话 id 经 `authn::SessionId::generate`（与真实登录同 mint 路径）。
async fn login_handler(body: Bytes) -> Response {
    let request: IdentityLoginRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return testkit::wire_error_response(
                StatusCode::BAD_REQUEST,
                "ERR_CORE_VALIDATION",
                "invalid request body",
            );
        }
    };
    // TRACER-ONLY：下方明文凭据判定是打通 testkit 维度的桩，**禁止照抄进生产 handler**——真实登录走
    // LoginService（哈希凭据 + 常时比对 + outbox），见模块 rustdoc §桩边界 + application.rs。
    if request.username != SEED_USER || request.password != SEED_PASSWORD {
        return testkit::wire_error_response(
            StatusCode::UNAUTHORIZED,
            "ERR_CORE_UNAUTHENTICATED",
            "invalid credentials",
        );
    }
    let response = IdentityLoginResponse {
        data: IdentityLoginData {
            session_id: authn::SessionId::generate().as_str().to_string(),
            // 样板简化：直接用 TTL 秒。生产须改为 UNIX epoch 秒 unix_secs(clock.now() + ttl)（application.rs）。
            expires_at: SESSION_TTL_SECS,
        },
    };
    (StatusCode::OK, Json(response)).into_response()
}

/// 构建仅挂 login 路由的测试 router（plain axum，不经 httpserve auth enforce 层）。
fn login_router() -> axum::Router {
    axum::Router::new().route(&login_path(), post(login_handler))
}

#[tokio::test]
async fn login_ok_returns_session_matching_generated_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(login_path()).json(&IdentityLoginRequest {
            username: SEED_USER.to_string(),
            password: SEED_PASSWORD.to_string(),
        }),
    )
    .await?;

    resp.ensure_status(StatusCode::OK)?;
    // schema 对齐：body 反序列化进 generated wire 类型（往返成立 = 形状匹配契约派生类型）。
    let decoded: IdentityLoginResponse = resp.json()?;
    assert!(!decoded.data.session_id.is_empty(), "返回会话 id");
    assert_eq!(decoded.data.expires_at, SESSION_TTL_SECS, "会话有效期");
    Ok(())
}

#[tokio::test]
async fn login_malformed_body_is_validation_error() -> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(login_path()).raw_json("{ not json"),
    )
    .await?;
    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    Ok(())
}

#[tokio::test]
async fn login_wrong_credentials_is_unauthenticated() -> Result<(), Box<dyn std::error::Error>> {
    let resp = testkit::call(
        login_router(),
        ContractRequest::post(login_path()).json(&IdentityLoginRequest {
            username: SEED_USER.to_string(),
            password: "wrong".to_string(),
        }),
    )
    .await?;
    resp.ensure_error(StatusCode::UNAUTHORIZED, "ERR_CORE_UNAUTHENTICATED")?;
    Ok(())
}
