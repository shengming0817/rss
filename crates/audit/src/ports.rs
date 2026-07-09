//! audit::ports — 审计仓储**域形** repo DI port（ADR-005 Option 2）+ 端口 I/O 类型 / 签名实体 façade。
//!
//! 归属（ADR-005 category line）：本 port 签名引用域内实体（[`AuditRecord`] / [`AuditEntry`] / [`AuditError`]），
//! 是**域形** repo port——无法收敛 `diport`（否则 diport→域 反向依赖、层序倒置），故归本域 crate `pub mod ports`。
//! adapter（如 `postgres` 的 `PgAuditRepo`）依赖 `audit`、以 native AFIT impl 本 port（DIP 内向边，`adapters→域`
//! 单向）。派发与 `identity` / `settings` 域形 port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 +
//! `#[dynosaur(...)]` `DynX`。
//!
//! **注入用 `Arc<DynAuditRepo>`（非 `Box`）**：订阅 handler（session→链 append）与 admin 读路由 clone 共享**同一
//! 链 store**（in-mem 同一 `Mutex<State>` / postgres 同一池），故基 trait 带 `Send + Sync` 超 trait ⇒ erased
//! `DynAuditRepo` 须 `Send + Sync` 以使 `Arc<DynAuditRepo>` 可被 spawn 的订阅 future / axum handler 闭包持有。
//! 跨租户 admin read 使用独立 [`AuditAdminRepo`] port，只暴露 target-tenant 读能力，不复用 append-capable
//! [`AuditRepo`]，避免把 SuperAdmin 读路径误接到可写 provider。
//!
//! 跨 crate 可见性：port 须 `pub`（独立 adapter crate impl）；签名实体（[`AuditEntry`] / [`EntryHash`] /
//! [`ResourceRef`] / [`AuditOutcome`] / [`AuditError`] / [`AuditChainHasher`] + DB funnel）经下方 `pub use`
//! 暴露——字段私有 + 构造经受控 funnel（[`AuditEntry::hydrate`] / [`EntryHash::new`]），外部可命名/收发但**不可
//! 伪造**（fail-closed）。
//!
//! ref: oxidecomputer/omicron（域 trait + 组合根注入范本，framework-comparison §域运行时/DI）
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）

use std::time::SystemTime;

use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造仍经受控 funnel）。
pub use crate::application::{
    AuditEventKind, AuditEventRecordError, audit_record_from_event_message,
};
pub use crate::domain::{
    AuditChainHasher, AuditEntry, AuditError, AuditOutcome, EntryHash, ResourceRef,
    actor_kind_from_db, actor_kind_to_db,
};
pub use vocab::TenantId;

/// Tenant-scoped repo capability for ordinary audit storage ports.
///
/// Audit admin operations intentionally keep their own target-tenant entry points; this handle is
/// for non-admin tenant-scoped repository calls only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TenantRepoScope {
    tenant: TenantId,
    _seal: (),
}

impl TenantRepoScope {
    /// Domain-internal constructor from an already authenticated or authorized tenant claim.
    pub(crate) fn from_authenticated_tenant(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }

    /// Read the tenant carried by this repo capability.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// Test/dev-only constructor for downstream adapter conformance tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }
}

/// Non-cross-tenant row-scoped repo capability for audit rows.
pub struct RowRepoScope {
    visibility: vocab::RowVisibility,
    _seal: (),
}

impl RowRepoScope {
    #[allow(dead_code)]
    pub(crate) fn from_scoped_visibility(
        scope: vocab::ScopedTenant,
        tenant: TenantRepoScope,
    ) -> Self {
        Self {
            visibility: vocab::RowVisibility::new(scope, tenant.tenant()),
            _seal: (),
        }
    }

    pub fn visibility(&self) -> &vocab::RowVisibility {
        &self.visibility
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(scope: vocab::ScopedTenant, tenant: TenantRepoScope) -> Self {
        Self::from_scoped_visibility(scope, tenant)
    }
}

// ---------------------------------------------------------------------------
// 仓储 I/O 类型（跨 in-mem / postgres provider 共用；字段已 typed 自校验 ⇒ pub 字段无需二次 funnel）
// ---------------------------------------------------------------------------

/// 未封链的审计内容（handler 构造 → [`AuditRepo::append`] 时原子封链：分配 seq、链接 prev、算 entry_hash）。
///
/// 字段 `pub`——各字段已 typed 自校验（`TenantId`/`Action`/`UserId` 经各自 funnel），无 raw `String` 需二次
/// 构造 funnel；append impl 直接读字段封链。
pub struct AuditRecord {
    /// 租户标识（行级多租隔离；决定子链）。
    pub tenant: vocab::TenantId,
    /// 操作者标识。
    pub actor: ids::UserId,
    /// 操作者类别。
    pub actor_kind: vocab::PrincipalKind,
    /// 授权动作。
    pub action: vocab::Action,
    /// 被操作资源引用。
    pub resource: ResourceRef,
    /// 操作结果。
    pub outcome: AuditOutcome,
    /// 记录时间（由注入时钟产生，不在 repo 取系统时钟）。
    pub recorded_at: SystemTime,
}

/// 分页请求。`limit` 用 [`vocab::Limit`]（构造即 ≤500，上限在类型层成立）；`cursor` 是不透明 token。
pub struct AuditPage {
    /// 单页上限（≤500，funnel 保证）。
    pub limit: vocab::Limit,
    /// 续页游标（首页 `None`）。
    pub cursor: Option<vocab::Cursor>,
}

/// 分页结果（对应 wire `data` / `nextCursor` / `hasMore`）。adapter `list` 构造、handler 读出转 wire。
pub struct AuditListResult {
    /// 本页条目。
    pub entries: Vec<AuditEntry>,
    /// 下一页游标（`has_more` 为 false 时 `None`）。
    pub next_cursor: Option<vocab::Cursor>,
    /// 是否还有更多页。
    pub has_more: bool,
}

/// 单租户审计链全链验证报告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditLedgerVerifyReport {
    /// 已验证租户。
    pub tenant: TenantId,
    /// 已验证条目数。
    pub checked_entries: u64,
}

// ---------------------------------------------------------------------------
// AuditRepo —— 域形 repo DI port（trait_variant Send 变体 + dynosaur DynAuditRepo）
// ---------------------------------------------------------------------------

/// 审计仓储域形 DI port（async；provider 可换：prod `postgres` / test in-mem）。
///
/// 公开 [`AuditRepo`] 是 **Send 变体**（adapter `impl AuditRepo for ...`），[`DynAuditRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Arc<DynAuditRepo>` 注入——订阅 handler + admin 读路由 clone 共享同一链
/// store）。基 trait [`AuditRepoLocal`] 带 `Send + Sync` 超 trait：erased `DynAuditRepo` 须 `Send + Sync`，使
/// `Arc<DynAuditRepo>` 可被 spawn 的订阅 future / axum handler 闭包持有（[`crate::AuditDomain`] 注入即此形）。
///
/// **租户隔离由签名承载（fail-closed）**：[`list`](AuditRepoLocal::list) / [`verify_tail`](AuditRepoLocal::verify_tail)
/// 接 [`TenantRepoScope`] 作 store scope（postgres 经 `SET LOCAL` + FORCE RLS）。**读路径完整性 fail-closed**：
/// `list` 内增量 [`verify_window`](AuditChainHasher::verify_window)（窗口 + 1 前驱，非全扫），篡改 → `Err`
/// （handler 映 500，不下发脏数据）。
///
/// dyn-safe（ADR-003 §4.6）：方法 `&self`、参数/返回为具体类型、supertrait `Send + Sync`。归属为域形 port
/// （签名引用 [`AuditRecord`] / [`AuditEntry`]）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
///
/// ⚠ **方法集 = 本轮生产接缝**（append 订阅写 / list admin 读 / verify_tail bootstrap 自检）。点查
/// `get_by_id`（per-entry 可寻址 id）随框架 manifest 多端点扩展 + get-by-id 端点 follow-up 落地（YAGNI：本轮
/// 无 handler 消费方）。
#[trait_variant::make(AuditRepo: Send)]
#[dynosaur(pub DynAuditRepo = dyn(box) AuditRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `AuditRepo` 变体 + dynosaur
// `DynAuditRepo` 承载（DI 注入走 Send wrapper）。`Send + Sync` 超 trait 使 `Arc<DynAuditRepo>` 可共享
// （订阅 + 路由），与 identity/settings 域形 port 同范式（ADR-003/ADR-005）。
pub trait AuditRepoLocal: Send + Sync {
    /// **原子封链 append**：分配 seq、链接 prev、算 entry_hash、持久化（provider 内串行——in-mem `Mutex` /
    /// postgres advisory-lock + `(tenant, seq)` 唯一兜底）。
    async fn append(&self, scope: TenantRepoScope, record: AuditRecord) -> Result<(), AuditError>;

    /// 按租户分页列出审计条目（读路径**增量验证**返回窗口 + 1 前驱，篡改 fail-closed → `Err`）。
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError>;

    /// **尾部增量验证**（bootstrap 启动自检 + 运维巡检）：验末 `limit` 条 + 其前驱链接，非全扫整链。
    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError>;
}

// ---------------------------------------------------------------------------
// AuditAdminRepo —— 跨租户指定租户只读 port
// ---------------------------------------------------------------------------

/// 跨租户 admin audit read 的只读 provider。
///
/// 与 [`AuditRepo`] 分开是刻意的 capability 收窄：SuperAdmin target-tenant HTTP read 只需要读取指定租户
/// 审计链并做完整性校验；operator ledger verify 需要全链验证；二者都不需要 append / write 能力。
/// postgres provider 使用专用 `rss_audit_admin` pool，经 `SET LOCAL rss.tenant_id = targetTenant` 复用现有
/// FORCE RLS policy。
#[trait_variant::make(AuditAdminRepo: Send)]
#[dynosaur(pub DynAuditAdminRepo = dyn(box) AuditAdminRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AuditAdminRepoLocal: Send + Sync {
    /// 按目标租户分页列出审计条目；provider 负责在读取窗口上做链完整性校验，失败即 Err。
    async fn list_tenant(
        &self,
        tenant: TenantId,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError>;

    /// 按目标租户验证整条审计链；provider 负责分页扫描并对任何 seq gap / 链接 / 哈希 / 混租户异常 fail-closed。
    async fn verify_tenant(
        &self,
        tenant: TenantId,
        batch: vocab::Limit,
    ) -> Result<AuditLedgerVerifyReport, AuditError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl，经 `Arc<DynAuditRepo>` 装入且 wrapper
    //! **`Send + Sync`**（订阅 future / axum handler 闭包跨线程共享所必需，PORT-SHAPE 同 identity）。
    use std::sync::Arc;

    use super::{
        AuditAdminRepo, AuditError, AuditLedgerVerifyReport, AuditListResult, AuditPage,
        AuditRecord, AuditRepo, DynAuditAdminRepo, DynAuditRepo, TenantId, TenantRepoScope,
    };

    struct NoopAuditRepo;
    impl AuditRepo for NoopAuditRepo {
        async fn append(
            &self,
            _scope: TenantRepoScope,
            _record: AuditRecord,
        ) -> Result<(), AuditError> {
            todo!()
        }
        async fn list(
            &self,
            _scope: TenantRepoScope,
            _page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            todo!()
        }
        async fn verify_tail(
            &self,
            _scope: TenantRepoScope,
            _limit: u32,
        ) -> Result<(), AuditError> {
            todo!()
        }
    }

    struct NoopAuditAdminRepo;
    impl AuditAdminRepo for NoopAuditAdminRepo {
        async fn list_tenant(
            &self,
            _tenant: TenantId,
            _page: AuditPage,
        ) -> Result<AuditListResult, AuditError> {
            todo!()
        }

        async fn verify_tenant(
            &self,
            _tenant: TenantId,
            _batch: vocab::Limit,
        ) -> Result<AuditLedgerVerifyReport, AuditError> {
            todo!()
        }
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE：native-AFIT impl 经 `new_box` → `Arc<DynAuditRepo>`，wrapper `Send + Sync`（不调方法 → 不触 `todo!()`）。
    #[test]
    fn audit_repo_impl_loads_into_arc_dyn_send_sync() {
        let repo: Arc<DynAuditRepo<'static>> = Arc::from(DynAuditRepo::new_box(NoopAuditRepo));
        assert_send_sync(&repo);
    }

    #[test]
    fn audit_admin_repo_impl_loads_into_arc_dyn_send_sync() {
        let repo: Arc<DynAuditAdminRepo<'static>> =
            Arc::from(DynAuditAdminRepo::new_box(NoopAuditAdminRepo));
        assert_send_sync(&repo);
    }
}
