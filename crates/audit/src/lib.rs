//! audit — RSS 审计哈希链域（keyed HMAC 链 + 事件消费 + 跨租户 admin 读）。
//!
//! 本 crate 承载审计域的核心值类型、keyed HMAC 链逻辑（[`domain`]）、域内仓储端口与应用层
//! （session→链 append 订阅 handler + 跨租户 admin 读 handler，
//! [`application`]）。所有域类型字段私有，只经显式构造 funnel——外部不可伪造，fail-closed。域类型均在
//! `mod domain` 内，由 dylint `rss_domain_no_serialize` 守护（禁止 Serialize/Deserialize derive）。
//!
//! # 对标
//!
//! ref: sigstore/sigstore-rs src/rekor/models/log_entry.rs@main
//! 采纳：`log_index` 单调序（→ `seq`）、`verify_inclusion` 纯验证（→ `AuditChainHasher::verify`）。
//! 偏离：Merkle 树 → 线性 keyed HMAC 哈希链；hex String → `EntryHash([u8;32])` newtype；
//!        rekor 字段全 pub → RSS 私有字段 + funnel。
//!
//! # 持久化边界（#1014）
//!
//! 链逻辑泛型于 [`primitives::MacVerifier`]；生产 postgres provider 承载每租户子链持久化
//! （advisory-lock / FORCE RLS / optional `rss_audit_admin` 只读池）。in-mem provider 与确定性
//! verifier 只存在于 `test-support` feature，不进入生产默认 feature graph。

#![forbid(unsafe_code)]

/// 应用层：session→链 append 订阅 handler + 跨租户 admin 读 handler + bootstrap 生命周期。私有——只经
/// facade re-export 暴露（domain-patterns.md §封装）。
mod application;
pub(crate) mod domain;
/// 域内 in-mem 仓储 provider（仅测试 feature 编译；read/write ports 已升 `pub mod ports`）。
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod internal;
/// 审计仓储**域形** repo DI port（ADR-005 Option 2）+ I/O 类型 / 签名实体 façade（postgres adapter 跨 crate impl）。
pub mod ports;
pub use application::AuditDomain;

/// Explicit test-only surface. Production-default consumers cannot name these providers/helpers.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    pub use crate::domain::test_support::{TestKeyedHasher, keyed_hasher};
    pub use crate::internal::mem::InMemAuditRepo;
}
