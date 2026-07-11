//! audit::internal — 域内 in-mem 仓储实现（domain-patterns.md §internal 模块）。
//!
//! 审计 read/write 域形 ports + 其 I/O 类型已升 `pub mod ports`（ADR-005 Option 2，#1230）——postgres adapter
//! 跨 crate impl 本 port，故 port 与签名实体须 `pub`（字段私有 + 受控 funnel，外部不可伪造）。本 module 只留
//! in-mem provider（[`mem::InMemAuditRepo`]，单进程占位 / 测试自洽）；postgres provider 在 `adapters/postgres`。

pub(crate) mod mem;
