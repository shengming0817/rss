//! bootstrap — RSS 进程组合根（composition / config / shutdown / worker）。
//!
//! 当前提供 [`shutdown`] 关闭逆序编排范式（无 async Drop）：进程关闭时由 bootstrap
//! 显式按注册逆序（LIFO）await 每个 `diport::ManagedResource` 关干净，替代 Rust
//! 缺失的 async `Drop`（port trait 归 `diport`，编排归本 crate）。设计决策与不变式见
//! `docs/architecture/202606212024-001-shutdown-reverse-order-orchestration.md`。

pub mod shutdown;
