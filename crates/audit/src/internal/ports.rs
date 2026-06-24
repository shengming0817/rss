//! audit::internal::ports — 审计仓储 I/O 类型（`AuditRecord` / `AuditPage` / `AuditListResult`，`pub(crate)`）。
//!
//! 本轮仓储唯一实现是 in-crate [`crate::internal::mem::InMemAuditRepo`]（**inherent** async 方法，无 port
//! trait）：单 provider 不需要 trait 抽象，handler 经构造器注入 `Arc<InMemAuditRepo<M>>` static-dispatch。
//! **provider 抽象 port trait（ADR-005 域形 repo port，`pub mod ports` + dynosaur/trait-variant Send 变体）
//! 随 postgres adapter follow-up 引入**——那是第二 provider 真正需要互换的地方（YAGNI：不为单 provider 预建抽象）。
//! 本文件持仓储 I/O 类型，跨 in-mem / 未来 postgres 共用。

use std::time::SystemTime;

use crate::domain::{AuditEntry, AuditOutcome, ResourceRef};

/// 未封链的审计内容（handler 构造 → `InMemAuditRepo::append` 时原子封链：分配 seq、链接 prev、算 entry_hash）。
///
/// 内部 plumbing 类型：字段 `pub(crate)`——各字段已 typed 自校验（`TenantId`/`Action`/`UserId` 经各自 funnel），
/// 无需二次构造 funnel；append impl 直接 move 出字段封链。
pub(crate) struct AuditRecord {
    /// 租户标识（行级多租隔离；决定子链）。
    pub(crate) tenant: vocab::TenantId,
    /// 操作者标识。
    pub(crate) actor: ids::UserId,
    /// 操作者类别。
    pub(crate) actor_kind: authn::PrincipalKind,
    /// 授权动作。
    pub(crate) action: vocab::Action,
    /// 被操作资源引用。
    pub(crate) resource: ResourceRef,
    /// 操作结果。
    pub(crate) outcome: AuditOutcome,
    /// 记录时间（由注入时钟产生，不在 repo 取系统时钟）。
    pub(crate) recorded_at: SystemTime,
}

/// 分页请求。`limit` 用 [`vocab::Limit`]（构造即 ≤500，上限在类型层成立）；`cursor` 是不透明 token。
pub(crate) struct AuditPage {
    /// 单页上限（≤500，funnel 保证）。
    pub(crate) limit: vocab::Limit,
    /// 续页游标（首页 `None`）。
    pub(crate) cursor: Option<vocab::Cursor>,
}

/// 分页结果（对应 wire `data` / `nextCursor` / `hasMore`）。
pub(crate) struct AuditListResult {
    /// 本页条目。
    pub(crate) entries: Vec<AuditEntry>,
    /// 下一页游标（`has_more` 为 false 时 `None`）。
    pub(crate) next_cursor: Option<vocab::Cursor>,
    /// 是否还有更多页。
    pub(crate) has_more: bool,
}
