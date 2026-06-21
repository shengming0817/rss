//! runctx — 请求级 context 控制流值（tenant / principal）的传播接缝。
//!
//! # 可观测性边界（ADR-001 §D1，Hard）
//!
//! 本 crate **只**承载控制流值（授权用的 tenant / principal）。trace / correlation /
//! request / cell 等**可观测 ID 是诊断信号**，必须由 consumer（httpserve middleware /
//! observ）写成 `tracing` span 字段，**不**进 [`RequestCtx`]。runctx 刻意**不依赖 `tracing`**，
//! 让「把 tenant/principal 塞进 span」在依赖图上不可表达——诊断载体可被采样丢弃 / 任意层
//! 改写，不配做 row-scope 授权闸门（见 `docs/rules/tenancy.md`「tracing span 仅作关联信号、
//! 不替代持久审计」）。
//!
//! # 范式（ADR-001 §D2）
//!
//! [`RequestCtx`] 是显式 sealed struct，经 `tokio::task_local!` 传播：框架信任边界
//! （httpserve / authn）用 [`scope`] 绑定一次，深层代码用 [`try_current`] / [`try_with`] 取用。
//! ctx 缺失 = fail-closed（返回 [`MissingCtx`]，绝不伪造 anonymous / default-tenant；ADR-001 §D6）。
//!
//! 构造只允许发生在已认证通道（JWT claim / service-token-MAC 的 `X-Tenant-ID`）；
//! [`RequestCtx`] 私有字段 + 无 `Deserialize` ⇒ 从 request body 构造不可表达（ADR-001 §D5）。
//!
//! `tokio::spawn` / `spawn_blocking` / `std::thread` **不继承** task_local：跨任务须显式
//! 「spawn 前 [`try_current`] 捕获 → 子任务 [`scope`] 重绑」，否则子任务 fail-closed（ADR-001 §后果 R2）。
//!
//! # consumer 接线示例（仅示意，runctx 不依赖 axum / tracing）
//!
//! ```ignore
//! // httpserve middleware：认证后边界绑定一次，并把可观测 ID 写进 tracing span（D1：ID 入 span，不入 ctx）。
//! async fn ctx_layer(req: Request, next: Next) -> Response {
//!     let ctx = runctx::RequestCtx::new(tenant, principal); // tenant/principal 来自已认证通道
//!     let span = tracing::info_span!("request", trace_id = %trace, correlation = %corr); // 可观测 ID 走 span
//!     runctx::scope(ctx, next.run(req).instrument(span)).await
//! }
//! // 深层 handler：fail-closed 取用。
//! let tenant = runctx::try_with(|c| c.tenant().clone()).map_err(|_| Error::Unauthenticated)?;
//! ```
//!
//! 对标：`ref: tokio tokio/src/task/task_local.rs`（`LocalKey::scope` / `try_with`）。

pub mod ctx;
pub mod local;

pub use ctx::{AppCtx, PrincipalSlot, RequestCtx, TenantSlot};
pub use local::{MissingCtx, scope, try_current, try_with};
