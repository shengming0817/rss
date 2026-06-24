//! testkit harness 自测：在**合成 axum router**（handler 完全受控）上验证四个断言 helper 的语义，
//! 即 `domain-patterns.md §Contract test` 的四维模板——正常响应 schema / 参数错误 + 错误码 /
//! 鉴权边界 / path 参数 newtype 校验。
//!
//! 合成 router 不依赖 httpserve / primitives（合成 401 + envelope 即可验证 helper 行为）——本文件
//! 证明 harness 工具本身正确；真实契约样板见 `crates/identity/src/login_contract.rs`，运行期 auth 闸
//! 穷举见 `httpserve/tests/runtime.rs`。
//!
//! 全程 in-process（oneshot，确定性、毫秒级），**不** feature-gate（同 httpserve/tests/runtime.rs、journeys）。

use axum::Json;
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use testkit::ContractRequest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

// 合成 wire 类型：模拟 generated 契约派生类型，作 schema 对齐断言（json 往返）的目标。
#[derive(Debug, Serialize, Deserialize)]
struct Greeting {
    data: GreetingData,
}
#[derive(Debug, Serialize, Deserialize)]
struct GreetingData {
    greeting: String,
}

#[derive(Debug, Deserialize)]
struct HelloRequest {
    name: String,
}

fn ok_greeting(greeting: impl Into<String>) -> Response {
    (
        StatusCode::OK,
        Json(Greeting {
            data: GreetingData {
                greeting: greeting.into(),
            },
        }),
    )
        .into_response()
}

// 正常 + 参数错误维度：JSON body 解析成功 → 200 typed；解析失败 → 400 validation envelope。
async fn hello(body: Bytes) -> Response {
    match serde_json::from_slice::<HelloRequest>(&body) {
        Ok(req) => ok_greeting(format!("hi {}", req.name)),
        Err(_) => testkit::wire_error_response(
            StatusCode::BAD_REQUEST,
            "ERR_CORE_VALIDATION",
            "invalid body",
        ),
    }
}

// 鉴权边界维度：有 Authorization → 200；无 → 401 unauthenticated envelope。
async fn guarded(headers: HeaderMap) -> Response {
    if headers.contains_key(header::AUTHORIZATION) {
        ok_greeting("authed")
    } else {
        testkit::wire_error_response(
            StatusCode::UNAUTHORIZED,
            "ERR_CORE_UNAUTHENTICATED",
            "missing credentials",
        )
    }
}

// path 参数 newtype 校验维度：id 须是合法 UUID（强类型标识不裸 String），否则 400 validation。
async fn item(Path(id): Path<String>) -> Response {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => ok_greeting(format!("item {uuid}")),
        Err(_) => testkit::wire_error_response(
            StatusCode::BAD_REQUEST,
            "ERR_CORE_VALIDATION",
            "invalid id",
        ),
    }
}

// F1 anti-vacuity：故意不完整 / 多余字段的 envelope，验严格镜像（required + deny_unknown_fields）拒收。
async fn incomplete_error() -> Response {
    // 缺 message/details/requestId（只有 code）。
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": { "code": "ERR_X" } })),
    )
        .into_response()
}
async fn extra_field_error() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": { "code": "ERR_X", "message": "m", "details": [], "requestId": "r", "extra": 1 }
        })),
    )
        .into_response()
}
// F2：成功响应含敏感 sessionId，验 mismatch 摘要脱敏。
async fn session_ok() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "data": { "sessionId": "super-secret-sid", "expiresAt": 1 } })),
    )
        .into_response()
}

fn app() -> axum::Router {
    axum::Router::new()
        .route("/hello", post(hello))
        .route("/guarded", get(guarded))
        .route("/items/{id}", get(item))
        .route("/incomplete-error", get(incomplete_error))
        .route("/extra-error", get(extra_field_error))
        .route("/session", get(session_ok))
}

#[tokio::test]
async fn ok_response_deserializes_into_typed_schema() -> TestResult {
    // 正常响应 schema：200 + body 反序列化进 typed wire 类型（schema 对齐）。
    let resp = testkit::call(
        app(),
        ContractRequest::post("/hello").json(&serde_json::json!({ "name": "alice" })),
    )
    .await?;

    resp.ensure_status(StatusCode::OK)?;
    let greeting: Greeting = resp.json()?;
    assert_eq!(greeting.data.greeting, "hi alice");
    Ok(())
}

#[tokio::test]
async fn malformed_body_is_validation_error() -> TestResult {
    // 参数错误 + 错误码：畸形 JSON body → 400 + ERR_CORE_VALIDATION。
    let resp = testkit::call(
        app(),
        ContractRequest::post("/hello").raw_json("{ not valid json"),
    )
    .await?;

    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    // envelope 形状字段可访问（camelCase requestId 解析）。此处 "test-rid" 是合成 router 的固定哨兵
    // （由 testkit::wire_error_response 写入）——真实 requestId 由框架注入，见 httpserve/tests/runtime.rs。
    assert_eq!(resp.wire_error()?.request_id, "test-rid");
    Ok(())
}

#[tokio::test]
async fn missing_credentials_is_unauthenticated() -> TestResult {
    // 鉴权边界：无 Authorization → 401 + ERR_CORE_UNAUTHENTICATED。
    let resp = testkit::call(app(), ContractRequest::get("/guarded")).await?;
    resp.ensure_error(StatusCode::UNAUTHORIZED, "ERR_CORE_UNAUTHENTICATED")?;
    Ok(())
}

#[tokio::test]
async fn bearer_credentials_pass_guard() -> TestResult {
    // 鉴权边界正路径：带 bearer → 200。
    let resp = testkit::call(app(), ContractRequest::get("/guarded").bearer("test-token")).await?;
    resp.ensure_status(StatusCode::OK)?;
    Ok(())
}

#[tokio::test]
async fn bad_path_param_is_validation_error() -> TestResult {
    // path 参数 newtype 校验：非 UUID path 段 → 400 + ERR_CORE_VALIDATION。
    let resp = testkit::call(app(), ContractRequest::get("/items/not-a-uuid")).await?;
    resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_CORE_VALIDATION")?;
    Ok(())
}

#[tokio::test]
async fn valid_path_param_reaches_handler() -> TestResult {
    // path 参数正路径：合法 UUID → 200。
    let resp = testkit::call(
        app(),
        ContractRequest::get("/items/f47ac10b-58cc-4372-a567-0e02b2c3d479"),
    )
    .await?;
    resp.ensure_status(StatusCode::OK)?;
    Ok(())
}

#[tokio::test]
async fn ensure_status_mismatch_is_error_not_panic() -> TestResult {
    // harness 不 panic：断言不匹配返回 Err（anti-vacuity：ensure_* 不恒真）。
    let resp = testkit::call(app(), ContractRequest::get("/guarded")).await?;
    assert!(
        resp.ensure_status(StatusCode::OK).is_err(),
        "401 != 200 必须返回 Err"
    );
    Ok(())
}

#[tokio::test]
async fn ensure_error_wrong_code_is_error_not_panic() -> TestResult {
    // anti-vacuity（与 ensure_status 对称）：error code 不匹配返回 Err，不恒真。
    let resp = testkit::call(app(), ContractRequest::get("/guarded")).await?;
    assert!(
        resp.ensure_error(StatusCode::UNAUTHORIZED, "ERR_WRONG_CODE")
            .is_err(),
        "code 不匹配必须返回 Err"
    );
    Ok(())
}

#[tokio::test]
async fn strict_envelope_rejects_missing_required_field() -> TestResult {
    // F1 anti-vacuity：缺 message/details/requestId 的 envelope → wire_error/ensure_error 返回 Err，
    // 不漏测 envelope 形状（严格镜像：required，无 serde(default)）。
    let resp = testkit::call(app(), ContractRequest::get("/incomplete-error")).await?;
    assert!(resp.wire_error().is_err(), "缺必填字段须 decode 失败");
    assert!(
        resp.ensure_error(StatusCode::BAD_REQUEST, "ERR_X").is_err(),
        "ensure_error 不得在 envelope 缺字段时误绿"
    );
    Ok(())
}

#[tokio::test]
async fn strict_envelope_rejects_unknown_field() -> TestResult {
    // F1 anti-vacuity：多余字段 → deny_unknown_fields 拒收。
    let resp = testkit::call(app(), ContractRequest::get("/extra-error")).await?;
    assert!(resp.wire_error().is_err(), "多余字段须 decode 失败");
    Ok(())
}

#[tokio::test]
async fn mismatch_excerpt_redacts_sensitive_values() -> TestResult {
    // F2：断言失败摘要脱敏 sessionId，不把敏感值写进测试失败日志。
    let resp = testkit::call(app(), ContractRequest::get("/session")).await?;
    let err = match resp.ensure_status(StatusCode::BAD_REQUEST) {
        Ok(_) => return Err("期望 status mismatch".into()),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("<redacted>"), "sessionId 应脱敏: {msg}");
    assert!(
        !msg.contains("super-secret-sid"),
        "不得回显 sessionId 原文: {msg}"
    );
    Ok(())
}
