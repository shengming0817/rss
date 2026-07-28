//! audit::ports — 审计仓储**域形** repo DI port（ADR-005 Option 2）+ 端口 I/O 类型 / 签名实体 façade。
//!
//! 归属（ADR-005 category line）：本 port 签名引用域内实体（[`AuditRecord`] / [`AuditEntry`] / [`AuditError`]），
//! 是**域形** repo port——无法收敛 `diport`（否则 diport→域 反向依赖、层序倒置），故归本域 crate `pub mod ports`。
//! adapter（如 `postgres` 的 `PgAuditRepo`）依赖 `audit`、以 native AFIT impl 本 port（DIP 内向边，`adapters→域`
//! 单向）。派发与 `identity` / `settings` 域形 port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 +
//! `#[dynosaur(...)]` `DynX`。
//!
//! **注入用独立 `Arc<DynAuditWriteRepo>` / `Arc<DynAuditReadRepo>`**：组合根从同一 `Arc<Provider>` 构造
//! wrapper，共享链 store，同时静态收窄订阅与路由能力。
//! 跨租户 admin read 使用独立 [`AuditAdminRepo`] port，只暴露 target-tenant 读能力，不复用 append-capable
//! tenant-scoped ports，避免把 SuperAdmin 读路径误接到普通 provider。
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
use generated::http::audit_v1::list_tenant_entries::{
    LOCAL_TX as AUDIT_LIST_TENANT_LOCAL_TX, ROUTE as AUDIT_LIST_TENANT_ROUTE,
};

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造仍经受控 funnel）。
pub use crate::application::{
    AuditEventKind, AuditEventRecordError, SecurityAuditCommand, audit_record_from_event_message,
    security_audit_command_from_message,
};
pub use crate::domain::{
    AuditChainHasher, AuditEntry, AuditError, AuditOutcome, EntryHash, ResourceRef,
    actor_kind_from_db, actor_kind_to_db,
};
pub use vocab::TenantId;

/// Generated route marker retained by the target-tenant audit append command.
pub type AuditListTenantRouteMarker = generated::http::audit_v1::list_tenant_entries::RouteMarker;

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

/// Audited cross-tenant read capability for the admin repository.
///
/// The crate-private constructor requires the application module's unforgeable durable append
/// receipt. A bare target, authn grant, or independently obtained row visibility is insufficient.
pub struct CrossTenantReadScope {
    visibility: vocab::RowVisibility,
    target: TenantId,
    _seal: (),
}

impl CrossTenantReadScope {
    pub(crate) fn from_durable_append(
        receipt: crate::application::AuditListTenantAppendReceipt,
    ) -> Self {
        let capability = vocab::tenant::CrossTenantCapability::issue_for_verified_super_admin();
        let visibility = vocab::RowVisibility::new_cross_tenant(
            vocab::CrossTenantVisibility::authorize(capability),
        );
        Self {
            visibility,
            target: receipt.target(),
            _seal: (),
        }
    }

    /// Explicit target tenant authorized by this audited capability.
    pub fn target(&self) -> TenantId {
        self.target
    }

    /// Audited row visibility proof retained by this capability.
    pub fn visibility(&self) -> &vocab::RowVisibility {
        &self.visibility
    }
}

/// Unforgeable durable audit append for the target-tenant list route.
///
/// The target-derived tenant scope, normalized audit event, and generated LocalTx observation are
/// minted together inside this crate. Postgres adapters can consume the command but cannot pair a
/// target with evidence from another route.
pub struct AuditListTenantAppend {
    scope: TenantRepoScope,
    event: diport::AuditEvent,
    observation: observ::LocalTxObservation<AuditListTenantRouteMarker>,
}

impl AuditListTenantAppend {
    pub(crate) fn new(target: TenantId, mut event: diport::AuditEvent) -> Self {
        event.tenant_id = Some(target);
        Self {
            scope: TenantRepoScope::from_authenticated_tenant(target),
            event,
            observation: observ::LocalTxObservation::new(
                AUDIT_LIST_TENANT_ROUTE,
                AUDIT_LIST_TENANT_LOCAL_TX.boundary,
            ),
        }
    }

    /// Test-support factory that preserves the production target-to-scope and typed observation
    /// minting funnel. External fixtures may supply an event, but cannot replace either proof.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_test(target: TenantId, event: diport::AuditEvent) -> Self {
        Self::new(target, event)
    }

    /// Adapter lowering funnel for the target-bound scope, event, and exact LocalTx evidence.
    pub fn into_parts(
        self,
    ) -> (
        TenantRepoScope,
        diport::AuditEvent,
        observ::LocalTxObservation<AuditListTenantRouteMarker>,
    ) {
        (self.scope, self.event, self.observation)
    }
}

/// Route-specific append capability for audited target-tenant reads.
#[trait_variant::make(AuditListTenantAppender: Send)]
#[dynosaur(pub DynAuditListTenantAppender = dyn(box) AuditListTenantAppender, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AuditListTenantAppenderLocal: Send + Sync {
    async fn append(&self, command: AuditListTenantAppend) -> Result<(), diport::AuditSinkError>;
}

impl<T> AuditListTenantAppender for std::sync::Arc<T>
where
    T: AuditListTenantAppender + ?Sized,
{
    async fn append(&self, command: AuditListTenantAppend) -> Result<(), diport::AuditSinkError> {
        T::append(self, command).await
    }
}

// ---------------------------------------------------------------------------
// 仓储 I/O 类型（跨 in-mem / postgres provider 共用；字段已 typed 自校验 ⇒ pub 字段无需二次 funnel）
// ---------------------------------------------------------------------------

/// 未封链的审计内容（handler 构造 → [`AuditWriteRepo::append`] 时原子封链：分配 seq、链接 prev、算 entry_hash）。
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
// AuditWriteRepo / AuditReadRepo —— 最小能力域形 DI ports
// ---------------------------------------------------------------------------

/// 审计追加能力。订阅路径只接收该 capability，不能读取链内容。
#[trait_variant::make(AuditWriteRepo: Send)]
#[dynosaur(pub DynAuditWriteRepo = dyn(box) AuditWriteRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AuditWriteRepoLocal: Send + Sync {
    /// **原子封链 append**：分配 seq、链接 prev、算 entry_hash、持久化（provider 内串行——in-mem `Mutex` /
    /// postgres advisory-lock + `(tenant, seq)` 唯一兜底）。
    async fn append(&self, scope: TenantRepoScope, record: AuditRecord) -> Result<(), AuditError>;
}

/// 审计读取能力。LocalOnly ambient 路由只接收该 capability，不能追加记录。
#[trait_variant::make(AuditReadRepo: Send)]
#[dynosaur(pub DynAuditReadRepo = dyn(box) AuditReadRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait AuditReadRepoLocal: Send + Sync {
    /// 按租户分页列出审计条目（读路径**增量验证**返回窗口 + 1 前驱，篡改 fail-closed → `Err`）。
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError>;

    /// **尾部增量验证**（bootstrap 启动自检 + 运维巡检）：验末 `limit` 条 + 其前驱链接，非全扫整链。
    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError>;
}

impl<T> AuditWriteRepo for std::sync::Arc<T>
where
    T: AuditWriteRepo + ?Sized,
{
    async fn append(&self, scope: TenantRepoScope, record: AuditRecord) -> Result<(), AuditError> {
        T::append(self, scope, record).await
    }
}

impl<T> AuditReadRepo for std::sync::Arc<T>
where
    T: AuditReadRepo + ?Sized,
{
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: AuditPage,
    ) -> Result<AuditListResult, AuditError> {
        T::list(self, scope, page).await
    }

    async fn verify_tail(&self, scope: TenantRepoScope, limit: u32) -> Result<(), AuditError> {
        T::verify_tail(self, scope, limit).await
    }
}

mod effect_sealed {
    pub trait Sealed {}
}

/// Canonical audit port effect classification. Implementations are owner-sealed.
pub trait AuditPortEffect: effect_sealed::Sealed {
    /// Strongest capability exposed by this injected port.
    type Effect: diport::PortEffectClass;
    /// Whether the injected port can cross a tenant boundary.
    type Privilege: diport::PortPrivilegeClass;
}

macro_rules! classify_audit_port {
    ($port:ty => $effect:ty, $privilege:ty) => {
        impl effect_sealed::Sealed for $port {}
        impl AuditPortEffect for $port {
            type Effect = $effect;
            type Privilege = $privilege;
        }

        const _: fn() = || {
            fn assert_effect<T, E, P>()
            where
                T: AuditPortEffect<Effect = E, Privilege = P> + ?Sized,
                E: diport::PortEffectClass,
                P: diport::PortPrivilegeClass,
            {
            }

            assert_effect::<$port, $effect, $privilege>();
        };
    };
}

classify_audit_port!(DynAuditReadRepo<'_> => diport::ReadEffect, diport::LocalPrivilege);
classify_audit_port!(DynAuditWriteRepo<'_> => diport::BusinessWriteEffect, diport::LocalPrivilege);
classify_audit_port!(DynAuditAdminRepo<'_> => diport::ReadEffect, diport::CrossTenantPrivilege);

impl<T: AuditPortEffect + ?Sized> effect_sealed::Sealed for std::sync::Arc<T> {}
impl<T: AuditPortEffect + ?Sized> AuditPortEffect for std::sync::Arc<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

impl<T: AuditPortEffect + ?Sized> effect_sealed::Sealed for Box<T> {}
impl<T: AuditPortEffect + ?Sized> AuditPortEffect for Box<T> {
    type Effect = T::Effect;
    type Privilege = T::Privilege;
}

// ---------------------------------------------------------------------------
// AuditAdminRepo —— 跨租户指定租户只读 port
// ---------------------------------------------------------------------------

/// 跨租户 admin audit read 的只读 provider。
///
/// 与 tenant-scoped read/write ports 分开是刻意的 capability 收窄：SuperAdmin target-tenant HTTP read 只需要读取指定租户
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
        scope: CrossTenantReadScope,
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
    //! build smoke：域形 async repo port 可 native-AFIT impl，经独立 read/write wrapper 装入且
    //! **`Send + Sync`**（订阅 future / axum handler 闭包跨线程共享所必需，PORT-SHAPE 同 identity）。
    use std::sync::Arc;

    use super::{
        AuditAdminRepo, AuditError, AuditLedgerVerifyReport, AuditListResult, AuditPage,
        AuditReadRepo, AuditRecord, AuditWriteRepo, CrossTenantReadScope, DynAuditAdminRepo,
        DynAuditReadRepo, DynAuditWriteRepo, TenantId, TenantRepoScope,
    };

    struct NoopAuditRepo;
    impl AuditWriteRepo for NoopAuditRepo {
        async fn append(
            &self,
            _scope: TenantRepoScope,
            _record: AuditRecord,
        ) -> Result<(), AuditError> {
            todo!()
        }
    }
    impl AuditReadRepo for NoopAuditRepo {
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
            _scope: CrossTenantReadScope,
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

    // PORT-SHAPE：native-AFIT impl 经 `new_box` 装入两个最小能力 wrapper。
    #[test]
    fn audit_repo_impl_loads_into_arc_dyn_send_sync() {
        let write: Arc<DynAuditWriteRepo<'static>> =
            Arc::from(DynAuditWriteRepo::new_box(NoopAuditRepo));
        let read: Arc<DynAuditReadRepo<'static>> =
            Arc::from(DynAuditReadRepo::new_box(NoopAuditRepo));
        assert_send_sync(&write);
        assert_send_sync(&read);
    }

    #[test]
    fn audit_admin_repo_impl_loads_into_arc_dyn_send_sync() {
        let repo: Arc<DynAuditAdminRepo<'static>> =
            Arc::from(DynAuditAdminRepo::new_box(NoopAuditAdminRepo));
        assert_send_sync(&repo);
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: fixed canonical UUID fixtures must parse.
    fn audit_list_tenant_append_binds_scope_and_event_to_target() {
        let target = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
            .expect("canonical target tenant");
        let other = TenantId::parse("00000000-0000-4000-8000-000000000abc")
            .expect("canonical other tenant");
        let command = super::AuditListTenantAppend::new(
            target,
            diport::AuditEvent {
                occurred_at: std::time::UNIX_EPOCH,
                principal_id: "principal".to_string(),
                principal_kind: vocab::PrincipalKind::SuperAdmin,
                tenant_id: Some(other),
                resource_kind: "audit_entries",
                resource_id: target.to_string(),
                action: "audit:list-cross-tenant",
                outcome: diport::AuditOutcome::Success,
                request_id: Some("request".to_string()),
                correlation_id: Some("correlation".to_string()),
            },
        );

        let (scope, event, _observation) = command.into_parts();
        assert_eq!(scope.tenant(), target);
        assert_eq!(event.tenant_id, Some(target));
    }
}
