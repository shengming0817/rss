//! diagctx — 请求级**诊断** context（correlation 等可观测 ID）的可读传播信道。
//!
//! # 为何独立 crate（ADR-002 §D1-bis，Hard 载体 = crate 图隔离）
//!
//! ADR-002 §D1 把可观测 ID（trace / correlation）与授权控制流值（tenant / principal）二分：前者写入
//! `tracing` span 喂日志 / otel，后者经 [`runctx::RequestCtx`] 传播。但 `tracing` **无 span 字段读回 API**，
//! 而 outbox metadata 需在 emit 点**读回** correlation 盖章——故需一条与 span 平行的**可读诊断信道**。
//!
//! 本 crate 即该信道。它与 `runctx` **物理隔离**（不同 crate / 不同类型 / 不同 task_local）：授权码
//! `use runctx`、诊断码 `use diagctx`，「诊断信道被误读为授权源」即一处可被 review 一眼抓的跨 import。
//! 失败语义也刻意相反——[`correlation`] 缺失返回 `None`（**fail-open** 省略），而 `runctx` 缺失 fail-closed
//! deny。诊断信号可采样丢弃 / 任意层改写，**不被任何授权闸门读取**，丢失只损可观测关联、不损正确性 / 安全。
//!
//! diagctx 刻意**不依赖** `tracing`（不给 runctx↛tracing 的 Hard 边界开口）、不依赖 `vocab` / `serde`
//! （`DiagnosticCtx` 不可从 body 反序列化构造）。
//!
//! # 接线
//!
//! - **写**（信任边界）：httpserve correlation middleware 解析 `X-Correlation-ID`（经
//!   [`CorrelationId::parse`] 校验、注入防护）→ [`scope`] 每请求绑定一次。
//! - **读**（深层）：outbox emit adapter 经 [`correlation`] 读回，「有则盖 `outbox.metadata`、无则省略」。
//!
//! 对标：`ref: tokio tokio/src/task/task_local.rs`（`LocalKey::scope` / `try_with`）；W3C Trace Context /
//! OpenTelemetry baggage 的可读诊断 context 传播思想（本 crate 是其最小 ambient 变体，不引 OTel 依赖）。

pub mod ctx;
pub mod local;

pub use ctx::{CorrelationId, CorrelationIdError, DiagnosticCtx, MAX_CORRELATION_ID_LEN};
pub use local::{correlation, current, scope};
