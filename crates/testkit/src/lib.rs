//! testkit — RSS HTTP 契约测试脚手架（`tower::ServiceExt::oneshot` 薄封装）+ L2 provider
//! conformance catalog 宏入口。
//!
//! 给 per-contract 契约测试（`domain-patterns.md §Contract test`）提供可复用 harness：声明式构造请求、
//! oneshot 驱动**已构建好的** axum [`Router`](axum::Router)、收集完整响应，并断言状态码 / 反序列化进
//! generated wire 类型（schema 对齐）/ 解析统一 wire error envelope（`error-handling.md §Wire 格式`）。
//!
//! ## L2 provider conformance catalog
//!
//! Adapter owners enroll exact capability wrappers with [`provider_conformance_catalog!`]
//! (`eventing_conformance` 模块)。Macro token 为 snake_case，wire/matrix 为 kebab-case；compile-fail
//! 负例见 `tests/ui/provider_catalog_*.rs`（经 `tests/provider_catalog_trybuild.rs`）。受控矩阵入口：
//! `./hack/cargo.sh xtask provider-capabilities` / `--check`（语义见 `docs/rules/eventbus.md`）。
//!
//! 边界（按层职责切分）：
//! - **不依赖任何 adapter crate**——域 crate 经 `[dev-dependencies]` 消费本 crate 写契约测试，不拉
//!   adapter（`rust-standards.md §命名`）。本 crate 出边全是外部 crate（axum/tower/serde…）。
//! - **不构造 `AuthPlan` / 不挂 `finalize_auth`**——auth 装配是组合根关注点；harness 只驱动调用方已
//!   组装好的 `Router`。运行期鉴权闸（401/403）的端到端断言见 `httpserve/tests/runtime.rs`。
//!
//! 用法见 `crates/testkit/tests/harness.rs`（合成 router 演示四维断言）与 `crates/identity/src/login_contract.rs`
//! （`identity.login` 真实契约样板）。
//!
//! ref: tokio-rs/axum examples/testing/src/main.rs@3f8956dcd007070be5449dd23102b7ee7f2e1b05
//!   （`fn app() -> Router` + oneshot + JSON body + body 收集 + 反序列化断言的官方惯用形态。
//!    偏离：自封 ~薄 helper、不引入 `axum-test`（避免外部测试框架 + 两套断言习惯）；官方 `.unwrap()`
//!    在 RSS 改为透明 `Result`（workspace `unwrap_used`/`panic` deny），与 `httpserve/tests/runtime.rs` 一致。）

#![forbid(unsafe_code)]

mod request;
mod response;

pub mod crash_matrix;
pub mod local_only;
pub mod revocation;

pub use request::ContractRequest;
pub use response::{ContractResponse, WireError};

/// Closed, low-cardinality provider error category shared by conformance helpers.
///
/// The category is safe to render in diagnostics. Provider messages, tenant identifiers, keys,
/// credentials, and payloads must remain in the opaque provider error value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConformanceErrorCategory {
    Storage,
    Transient,
    Conflict,
    Permanent,
    OwnershipLost,
    Validation,
    Authorization,
    CommitUnknown,
    RollbackFailed,
    Other,
}

impl ConformanceErrorCategory {
    /// Returns the stable, low-cardinality diagnostic label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Transient => "transient",
            Self::Conflict => "conflict",
            Self::Permanent => "permanent",
            Self::OwnershipLost => "ownership-lost",
            Self::Validation => "validation",
            Self::Authorization => "authorization",
            Self::CommitUnknown => "commit-unknown",
            Self::RollbackFailed => "rollback-failed",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for ConformanceErrorCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod conformance_error_category_tests {
    use super::ConformanceErrorCategory;

    #[test]
    fn labels_are_closed_and_display_uses_the_same_source() {
        let cases = [
            (ConformanceErrorCategory::Storage, "storage"),
            (ConformanceErrorCategory::Transient, "transient"),
            (ConformanceErrorCategory::Conflict, "conflict"),
            (ConformanceErrorCategory::Permanent, "permanent"),
            (ConformanceErrorCategory::OwnershipLost, "ownership-lost"),
            (ConformanceErrorCategory::Validation, "validation"),
            (ConformanceErrorCategory::Authorization, "authorization"),
            (ConformanceErrorCategory::CommitUnknown, "commit-unknown"),
            (ConformanceErrorCategory::RollbackFailed, "rollback-failed"),
            (ConformanceErrorCategory::Other, "other"),
        ];

        for (category, expected) in cases {
            assert_eq!(category.as_str(), expected);
            assert_eq!(category.to_string(), expected);
        }
    }
}

// 容器 fixture（#1137，仅 `containers` feature）：testcontainers self-provision postgres/redis/rabbitmq，
// 供 adapter 集成测试 + journeys durable journey 经 [dev-dependencies] 消费。零内部 workspace 依赖（只回
// 连接坐标，不构造 adapter 类型）。default 构建 / 契约 harness 消费方不拉 testcontainers 树。
#[cfg(feature = "containers")]
mod containers;
#[cfg(feature = "containers")]
pub use containers::{
    FixtureError, MinioConnParams, MinioFixture, MqttFixture, PgConnParams, PgFixture,
    PostgresTestLogin, RabbitFixture, RedisFixture, env_or_minio, env_or_mosquitto,
    env_or_postgres, env_or_rabbitmq, env_or_redis, provision_postgres_test_logins,
};

// Provider-neutral eventing taxonomy/assertions are dependency-free and intentionally available
// without the container feature. Real provider runners remain integration-gated in each adapter.
pub mod eventing_conformance;

// tenant-scope repository conformance 骨架（#1437 PERSIST-016 种子；#1426 在此扩展全套 repo conformance）。
// 仅 `containers` feature（其唯一消费方是启用 containers 的 adapter 集成测试）；不增 default public-api 面。
#[cfg(feature = "containers")]
pub mod localtx;
#[cfg(feature = "containers")]
pub mod policy_conformance;
#[cfg(feature = "containers")]
pub mod repo_conformance;
#[cfg(feature = "containers")]
pub mod tenant_conformance;

/// testkit harness 错误。harness 自身不 panic（workspace `panic`/`unwrap_used` deny）——
/// 失败一律走 `Result`，调用方在测试侧 `?` / `expect`（item-level carve-out）暴露。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TestkitError {
    /// 请求 body 序列化失败（[`ContractRequest::json`] 的自定义 `Serialize` 报错，罕见）。
    #[error("encode request body failed: {0}")]
    Encode(#[source] serde_json::Error),
    /// `http::Request` 组装失败（非法 uri / header 名值等，在 [`ContractRequest`] 入口收集、此处冒泡）。
    #[error("build http request failed: {0}")]
    Build(String),
    /// 被测 router 的 `Service` 调用失败（axum `Router` 错误类型为 `Infallible`，理论不可达）。
    #[error("router service error: {0}")]
    Service(String),
    /// 读取响应 body 字节失败。
    #[error("read response body failed: {0}")]
    Body(String),
    /// 响应 body 反序列化失败（schema 不对齐 / 非 JSON）。
    #[error("decode response body failed: {0}")]
    Decode(#[source] serde_json::Error),
    /// 断言不匹配（[`ContractResponse::ensure_status`] / [`ContractResponse::ensure_error`]）。
    #[error("contract assertion failed: {0}")]
    Mismatch(String),
}

/// 用 [`ContractRequest`] 经 `tower::ServiceExt::oneshot` 驱动**已构建好的** axum [`Router`](axum::Router)
/// （含 state / layer），收集完整响应（状态码 + body 字节）为 [`ContractResponse`]。
///
/// 全程 in-process（无 TCP，确定性、毫秒级）——与 `httpserve/tests/runtime.rs` / journeys 同范式。
pub async fn call(
    router: axum::Router,
    request: ContractRequest,
) -> Result<ContractResponse, TestkitError> {
    use tower::ServiceExt as _;

    let http_request = request.into_http()?;
    let response = router
        .oneshot(http_request)
        .await
        .map_err(|e| TestkitError::Service(format!("{e}")))?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), MAX_RESPONSE_BODY)
        .await
        .map_err(|e| TestkitError::Body(format!("{e}")))?;
    Ok(ContractResponse::new(status, bytes.to_vec()))
}

/// 响应 body 读取上限（16 MiB）。契约测试响应远小于此；超限（如被测 handler bug 产生超大 body）
/// 返回 [`TestkitError::Body`] 而非 `usize::MAX` 下的 OOM——与 harness「不 panic、全走 Result」一致。
const MAX_RESPONSE_BODY: usize = 16 * 1024 * 1024;

/// 构造统一 wire error envelope 响应（`{"error":{"code","message","retryable","details","requestId"}}`，
/// `error-handling.md §Wire 格式`）——**test fixture**：供契约测试的样板 handler 产出错误响应，单源化
/// envelope 形状（与 [`WireError`] 解析侧对称，防 drift）。生产 handler 用 generated typed response
/// envelope（`domain-patterns.md §Typed response envelope`），非本 helper。`requestId` 用固定哨兵
/// `"test-rid"`（真实 requestId 由框架注入，见 `httpserve/tests/runtime.rs`）。
pub fn wire_error_response(
    status: axum::http::StatusCode,
    code: &str,
    message: &str,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let body = serde_json::json!({
        "error": {
            "code": code,
            "message": message,
            "retryable": false,
            "details": [],
            "requestId": "test-rid"
        }
    });
    (status, axum::Json(body)).into_response()
}
