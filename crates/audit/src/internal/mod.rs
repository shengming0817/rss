//! audit::internal — 域内审计仓储端口 + in-mem 实现（domain-patterns.md §internal 模块）。
//!
//! 本轮 `AuditRepo` 端口在 `internal/ports`（`pub(crate)`）：唯一实现是 in-crate in-mem，无外部 adapter
//! 消费端口 ⇒ 不 premature 升 `pub mod ports` / 扩 public-api（优雅简洁 + 保 `pub(crate)` Hard 封装边界）。
//! 升 `pub mod ports`（ADR-005）+ 端口实体集升 pub + 外部 adapter 从存储 rehydrate `AuditEntry` 的
//! 构造器可见性，统一在 postgres adapter follow-up 解决（那是这些决策被 forced 的地方）。

pub(crate) mod mem;
pub(crate) mod ports;
