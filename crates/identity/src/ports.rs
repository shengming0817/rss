//! identity::ports — 身份域**专属** repo / 领域服务 DI port（Option 2 / ADR-005）。
//!
//! 归属（ADR-005 category line）：provider-agnostic 基建 port（`Clock`/`Signer`/`Publisher`/`AuditSink`…）
//! 在 `diport`；**域形** repo port——签名引用域内实体（`Role`/`RoleId`，域 crate `pub(crate)`/`pub` 类型）——
//! **无法**收敛 `diport`（否则 diport→域 反向依赖、层序倒置、deny 红），故归本域 crate `ports` 模块。
//! adapter（如 `postgres`）依赖 `identity`、以 native AFIT impl 本 port（DIP 内向边，`adapters→域` 单向）。
//! 派发与 diport DI port 同范式：`#[trait_variant::make(X: Send)]` Send 变体 + `#[dynosaur(...)]` `DynX`。
//! 需要跨 axum handler / subscriber future 共享的端口在基 trait 加 `Send + Sync`，经 `Arc<DynX>` 注入；
//! 单 owner 端口仍可用 `Box<DynX>`。
//!
//! 跨 crate 可见性：repo port 须 `pub`（独立 adapter crate impl）；签名实体 `Role`/`RoleId`/`IdentityError`
//! 经下方 `pub use` 暴露——字段私有 + 构造经 `pub(crate)` funnel，外部可命名/收发但**不可伪造**（fail-closed）。
//!
//! ref: oxidecomputer/omicron Cargo.toml@main（域 trait + 组合根注入范本，framework-comparison §域运行时/DI）
//! ref: Cockburn Hexagonal Ports&Adapters / Evans DDD Repository（repo 接口归域核心、adapter 经 DIP 实现）

use std::time::SystemTime;

use consistency::Entry;
use diport::{OutboxEmitError, OutboxEnvelopeParts};
use dynosaur::dynosaur;

// 域形 port 的签名实体经本模块 façade 暴露（types `pub`，构造器仍 `pub(crate)` funnel）。
// reason: AccountStatus 自 #1277 起不再是任一 port 方法的入/出参（lockout 推进折叠进 `authenticate`，
// 返回 AuthOutcome）；保留 `pub` 导出是为后续账户门控 handler（PR5/W）跨 crate 消费的账户状态闭值集，
// 当前作 `AccountLockout::record_failure` 的域内推进结果类型。AccountLockout 亦非 port 方法入/出参，但 #1316
// PgCredentialRepo 须在事务内对其 from_parts 重建 / record_failure 推进 / 访问器回写锁定三列 ⇒ 经本 facade
// 跨 crate 暴露（策略阈值仍域内单源、字段私有不可伪造）。其余符号均为现役 port 签名实体。
pub use crate::domain::{
    AbacAttribute, AccountLockout, AccountStatus, AttributeKey, AttributeValue, AuthOutcome,
    Credential, GlobPattern, IdentityError, LoginIdentifier, Operator, POLICY_ATTR_CONTRACT_ID,
    POLICY_ATTR_PERMISSION, POLICY_ATTR_PRINCIPAL_ID, POLICY_ATTR_PRINCIPAL_KIND,
    POLICY_ATTR_RESOURCE_ID, POLICY_ATTR_TENANT_ID, Policy, PolicyCondition, PolicyEffect,
    PolicyId, PolicyObligations, PolicyRouteScope, PolicyRule, PolicyVersion, RefreshRotation,
    RefreshStatus, RefreshTokenHash, RefreshTokenId, RefreshTokenRecord, ResourceAttribute,
    ResourceAttributeKey, ResourceAttributeKeyError, ResourceAttributeResolution,
    ResourceAttributeResourceId, ResourceAttributeVersion, Role, RoleBinding, RoleId, Session,
    SessionId, kind_from_db, kind_to_db,
};
pub use vocab::TenantId;

/// Tenant-scoped repo capability for identity storage ports.
///
/// It is an opaque handle: external crates can read the tenant for adapter lowering, but cannot
/// construct it from a bare [`TenantId`] in production builds.
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

/// Non-cross-tenant row-scoped repo capability for identity rows.
///
/// It only accepts [`vocab::ScopedTenant`]-derived visibility, which keeps `RowScope::All` out of
/// ordinary row-scoped repositories at the type boundary.
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

/// durable ABAC policy read repository DI port（tenant-scoped，domain-shaped）。
///
/// 本 port 只暴露读侧能力。管理写侧必须经 [`PolicyLifecycle`] 的 combined co-tx API，以类型边界避免
/// “先写 policy 再发事件”的两步调用。`list_effective` 是授权热路径读口：provider 必须按
/// `(tenant, route scope, effective window)` 收敛，任何存储 / decode / validation 错误由 caller fail-closed
/// 映射为 deny。
#[trait_variant::make(PolicyRepo: Send)]
#[dynosaur(pub DynPolicyRepo = dyn(box) PolicyRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait PolicyRepoLocal: Send + Sync {
    async fn find(
        &self,
        scope: TenantRepoScope,
        id: PolicyId,
    ) -> Result<Option<Policy>, IdentityError>;

    async fn list_active(
        &self,
        scope: TenantRepoScope,
        page: PolicyPage,
    ) -> Result<PolicyListResult, IdentityError>;

    async fn list_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        at: SystemTime,
    ) -> Result<Vec<Policy>, IdentityError>;
}

/// 策略列表分页参数（handler 已完成 query/cursor 校验，repo 只接收 typed page）。
#[derive(Debug, Clone)]
pub struct PolicyPage {
    pub limit: vocab::Limit,
    pub after: Option<PolicyId>,
}

/// 策略列表分页结果（`has_more` 由 repo over-fetch 判定；`nextCursor` 由 handler 用末项 policy id 派生）。
#[derive(Debug)]
pub struct PolicyListResult {
    pub policies: Vec<Policy>,
    pub has_more: bool,
}

/// Tenant-scoped resource attribute store / resolver for route ABAC.
///
/// This is the only durable PIP port used by `ContractAuthorizer`. Resolution failures are
/// explicit (`Missing` / `Stale`) so callers cannot accidentally treat an unavailable attribute as
/// an empty attribute bag and fall back to baseline RBAC.
#[trait_variant::make(ResourceAttributeRepo: Send)]
#[dynosaur(pub DynResourceAttributeRepo = dyn(box) ResourceAttributeRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait ResourceAttributeRepoLocal: Send + Sync {
    async fn resolve_effective(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        required_keys: Vec<ResourceAttributeKey>,
        at: SystemTime,
    ) -> Result<ResourceAttributeResolution, IdentityError>;

    async fn upsert(
        &self,
        scope: TenantRepoScope,
        attribute: ResourceAttribute,
        expected: Option<ResourceAttributeVersion>,
    ) -> Result<ResourceAttribute, IdentityError>;

    async fn expire(
        &self,
        tenant_scope: TenantRepoScope,
        scope: PolicyRouteScope,
        resource_id: ResourceAttributeResourceId,
        key: ResourceAttributeKey,
        expected: ResourceAttributeVersion,
    ) -> Result<bool, IdentityError>;
}

/// ABAC policy lifecycle DI port（domain-shaped）——policy mutation + `identity.policy-updated` outbox 的唯一写口。
#[trait_variant::make(PolicyLifecycle: Send)]
#[dynosaur(pub DynPolicyLifecycle = dyn(box) PolicyLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
pub trait PolicyLifecycleLocal: Send + Sync {
    async fn create_and_emit(
        &self,
        scope: TenantRepoScope,
        policy: Policy,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError>;

    async fn update_and_emit(
        &self,
        scope: TenantRepoScope,
        policy: Policy,
        expected: PolicyVersion,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<Policy, IdentityError>;

    async fn deactivate_and_emit(
        &self,
        scope: TenantRepoScope,
        id: PolicyId,
        expected: PolicyVersion,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, IdentityError>;
}

/// 角色仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`RoleRepo`] 是 **Send 变体**（adapter `impl RoleRepo for ...`），[`DynRoleRepo`] 是其
/// dyn-compatible wrapper（组合根经 `Box<DynRoleRepo>` 注入）。非 Send 基 trait [`RoleRepoLocal`] 仅供
/// 静态分发窄场景，不在 crate 根 re-export（同 diport `XLocal` 约定）。
///
/// dyn-safe（ADR-003 §4.6）：方法 `&self`、参数/返回为具体类型、supertrait 仅 Send。归属为域形 port
/// （签名引用 `Role`/`RoleId`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
///
/// **当前方法集 = PR5b 最小生产接缝（find / save / tenant-scoped list），非完整 repo 设计范式（勿照抄查询集）**。
/// 安全 scope 由签名承载：`Role` 按租户内角色建模，repo 方法必须接收 [`TenantRepoScope`] 做 store scope
/// （pre-GA：显式 `WHERE tenant_id` + 写路径 `SET LOCAL`；DB 层 FORCE RLS 属**仓库范围 RLS infra 后续**，跨
/// roles/sessions/config 统一落地，见 `docs/rules/tenancy.md` §RLS）；若后续需要全局角色定义，须拆独立
/// `GlobalRoleRepo`，不得复用本租户内 repo 签名。
/// **生产 postgres impl 已由 postgres `PgRoleRepo` 承载**（roles 表 + tenant scope + `Role::hydrate` 受控重建，
/// #1250；PR5b 补齐 `list` 分页查询）——签名实体 accessor（`RoleId::as_str` / `Role::id|name|permission_ids`
/// / `Role::hydrate`）已按需升 `pub`（字段私有 + 构造经 funnel，外部可读不可伪造）。
/// **查询形态后续**：按业务补 `find_by_name` / `exists` 等惯用方法；列表查询继续强制分页（`limit≤500`）。
#[trait_variant::make(RoleRepo: Send)]
#[dynosaur(pub DynRoleRepo = dyn(box) RoleRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RoleRepo` 变体 + dynosaur
// `DynRoleRepo` 承载（DI 注入走 Send wrapper）。与 diport DI port 同范式（ADR-003/ADR-004 C1）。body=todo!()
// （签名冻结，ADR-004 C8）。
pub trait RoleRepoLocal: Send + Sync {
    /// 按 ID 查角色（不存在返回 `Ok(None)`）。
    async fn find(&self, scope: TenantRepoScope, id: RoleId)
    -> Result<Option<Role>, IdentityError>;

    /// 持久化角色（upsert）。
    async fn save(&self, scope: TenantRepoScope, role: Role) -> Result<(), IdentityError>;

    /// 租户内分页列出角色（按 role id 升序稳定排序）。
    async fn list(
        &self,
        scope: TenantRepoScope,
        page: RolePage,
    ) -> Result<RoleListResult, IdentityError>;
}

/// 角色列表分页参数（handler 已完成 query/cursor 校验，repo 只接收 typed page）。
#[derive(Debug, Clone)]
pub struct RolePage {
    pub limit: vocab::Limit,
    pub after: Option<RoleId>,
}

/// 角色列表分页结果（`has_more` 由 repo over-fetch 判定；`nextCursor` 由 handler 用末项 role id 派生）。
#[derive(Debug)]
pub struct RoleListResult {
    pub roles: Vec<Role>,
    pub has_more: bool,
}

/// 角色绑定生命周期 DI port（域形；provider 可换：prod postgres / test in-mem）——RBAC 角色分配 / 撤销的
/// **L2 OutboxFact co-tx** 写口（#1190 US5）。
///
/// 公开 [`RoleBindingLifecycle`] 是 **Send 变体**（adapter `impl RoleBindingLifecycle for ...`），
/// [`DynRoleBindingLifecycle`] 是其 dyn-compatible wrapper（组合根经 `Arc<DynRoleBindingLifecycle>` 注入，
/// 供 [`crate::RbacAdminService`] 作 axum handler state 间接共享）。归属为域形 port（签名引用 [`RoleBinding`]
/// / [`RoleId`]）→ 本域 crate `ports`，非 diport（ADR-005 category line，同 [`SessionLifecycle`]）。
///
/// **co-tx（L2，both-or-neither）**：binding 行写 / 删与 outbox(`identity.role-{assigned,revoked}`) 行须
/// **同一本地事务**原子落地——域构造 `entry`（事件语义归域：topic + opaque-UUID EventId + 编码 payload）
/// 与 `envelope`，adapter 在单事务内先注入 tenant scope（SET LOCAL）、写/删 binding、`append_outbox`，单
/// commit；任一步失败整体 rollback。**唯一 binding-写 API**（域无 `save`/`emit` 分调、无半开事务句柄；co-tx
/// 不可拆解在类型层成立，同 [`SessionLifecycle`] 的 OUTBOX-COTX-SESSION-01）。
///
/// INVARIANT: OUTBOX-COTX-BINDING-API-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }— 域只暴露
/// combined-method funnel，调用方无法把 binding 行写/删与 role-event outbox append 拆成两个 port 调用。
/// INVARIANT: OUTBOX-COTX-BINDING-PG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }—
/// 生产 postgres `PgRoleBindingLifecycle` 在 PR5b 落地 same-tx 接线与集成 anti-vacuity（commit 两行皆在 ↔
/// rollback 两行皆无），同 OUTBOX-COTX-SESSION-01。
///
/// **租户隔离由签名承载（fail-closed）**：`assign_and_emit` 的 tenant 来自 `binding.tenant()`；
/// `revoke_and_emit` 接 [`TenantRepoScope`] 做 store scope——跨租 revoke → 幂等 `Ok(false)`（不撤、不发
/// 事件、不泄露存在性，IDENTITY-AUTHZ-TENANT-01）。失败通道经 [`OutboxEmitError`]（infra 错误，source 已
/// PII-redacted）冒泡。
///
/// **PR5b 状态**：port + `#[cfg(test)]` in-mem 替身 + 生产 `PgRoleBindingLifecycle` 已闭合 assign/revoke
/// 发布侧；role assigned/revoked event contract 仍为 draft，生产 audit consumer 延后（#1017）。
///
/// ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable）
/// ref: Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(RoleBindingLifecycle: Send)]
#[dynosaur(pub DynRoleBindingLifecycle = dyn(box) RoleBindingLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RoleBindingLifecycle` 变体 +
// dynosaur `DynRoleBindingLifecycle` 承载。`Send + Sync` supertrait 使 `Arc<DynRoleBindingLifecycle>` 可
// 被 RbacAdminService 跨 await 持有 / 作 handler state 共享（同 SessionLifecycle）。
pub trait RoleBindingLifecycleLocal: Send + Sync {
    /// **分配（co-tx，L2）**：把 [`RoleBinding`] 行（upsert）与 outbox(`identity.role-assigned`) 行同一本地
    /// 事务原子写入。tenant scope 来自 `binding.tenant()`（无独立 tenant 入参可错位）。
    async fn assign_and_emit(
        &self,
        scope: TenantRepoScope,
        binding: RoleBinding,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;

    /// **撤销（co-tx，L2）**：仅撤目标 binding（`(tenant, role_id, subject)` 键），命中则同事务删 binding +
    /// 写 outbox(`identity.role-revoked`) 行、返回 `Ok(true)`；未命中（不存在 / 跨租）→ **不删、不写 outbox**、
    /// 返回 `Ok(false)`（幂等 + 跨租隐藏存在性）。`entry`/`envelope` 在未命中时被丢弃（其 EventId 独立 opaque）。
    async fn revoke_and_emit(
        &self,
        scope: TenantRepoScope,
        role_id: RoleId,
        subject: String,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<bool, OutboxEmitError>;

    /// **授权读（L1）**：按 `(tenant, subject)` 列出该主体的 role bindings。仅供 contract-derived
    /// authorizer 求值；不存在返回空集，跨租经 tenant scope 天然不可见。失败由调用方 fail-closed 映射 403。
    async fn list_for_subject(
        &self,
        scope: TenantRepoScope,
        subject: String,
    ) -> Result<Vec<RoleBinding>, IdentityError>;
}

/// 凭据仓储 DI port（async；provider 可换：prod postgres / test in-mem / mockall）。
///
/// 公开 [`CredentialRepo`] 是 **Send 变体**（adapter `impl CredentialRepo for ...`），[`DynCredentialRepo`]
/// 是其 dyn-compatible wrapper（组合根经 `Arc<DynCredentialRepo>` 注入，ADR-004 C1/C5）。归属为域形 port
/// （签名引用 `Credential`/`LoginIdentifier`/`AuthOutcome`）→ 本域 crate `ports`，非 diport（ADR-005 category line）。
/// 基 trait 带 `Send + Sync` supertrait：登录 handler 需 clone 共享同一 credential store，且
/// `LoginService::login().await` future 必须为 `Send`（axum handler 要求）。
///
/// **租户隔离由签名承载（fail-closed）**：所有方法接收 [`TenantRepoScope`] 做 RLS / store scope；跨租
/// 经 tenant-keyed 查找天然失败——`find(t ≠ cred.tenant)` → `None`，`authenticate` → `InvalidUnknown`，
/// 不创建会话、不推进锁定计数（spec 003 US3 跨租红用例）。
///
/// **与 `RoleRepo` 差异**：本 port 在 PR3 已有写实 in-mem 替身（[`crate::internal`]），非纯签名冻结——
/// 锁定态推进是多实例暴破防御的硬需求（内存态多实例不共享则失效），由**原子 port 方法**承载（见下）。
/// 生产 postgres adapter impl 仍留 W（随 #1116 postgres adapter 落地）；届时 `Credential` / `AccountLockout`
/// 的跨 crate 重建 + 只读 accessor 公开化与 `RoleRepo` 同步走 W（accessor 升 `pub` / `from_persisted` funnel，
/// 见 #1258）——本 PR 编译证明阶段无独立 adapter，替身在同 crate 用 `pub(crate)`。
///
/// **租户/主体一致性 = 类型层 Hard（F2）**：携带完整 `Credential` 的写方法（`save` / `bump_version`）**不收**
/// 独立 `tenant`/`login` 参，store key 直接派生自 `credential.tenant()` / `.login()`——错位组合不可表达
/// （零信任租户隔离不靠调用方约定 / debug_assert）。只持标识的方法：`authenticate` / `lockout_status` 收
/// [`TenantRepoScope`] + [`LoginIdentifier`]（登录路径，攻击者可控查找键）；`find_by_user_id` 收 [`TenantRepoScope`] +
/// `ids::UserId`（self-scoped 改密路径，认证主体锚点，#1277 F2）——二者皆经 tenant-keyed 查找天然 fail-closed。
///
/// **验签 + 锁定推进原子化（F1+F2，#1277）**：失败计数 = 安全关键状态，**禁**外部「读-改-写」（并发丢更新）。
/// `authenticate` 在 provider 内单次原子完成「恒定成本验签 + 据已知/未知主体分流推进 lockout」，返回
/// [`AuthOutcome`]——已知+正确清零、已知+错推进、未知不动；登录枚举防御（constant-time KDF）与真实账号
/// lockout 推进收进**单一原子结果**，「对未知主体建锁」从此无 API 可表达（F2 Hard：未知主体不可预置锁定、
/// 不撑大 lockout 表）。`lockout_status` 仅做验签前预门控的原子 lazy-unlock 查询。in-mem = 锁内、
/// postgres = 事务/行锁/条件 upsert。
/// ref: kubernetes client-go RetryOnConflict（并发更新显式版本化）。
/// ref: keycloak DefaultBruteForceProtector.java@main（`failedLogin` 入参为已解析 `UserModel` +
/// `permanentUserLockOut` 的 `getUserById != null` guard：brute-force 计数仅对已知主体推进；RSS 以
/// `AuthOutcome` typed 分流强化为类型层 Hard——`InvalidUnknown` 变体在类型层即与计数路径隔离）。
///
/// **owned 参数**：与既有 DI port（diport / `RoleRepo`）一致——async dyn port 用 owned 参规避借用生命周期、简化
/// dynosaur `bridge(dyn)` 装配；消费方调用即弃，代价仅一次 `LoginIdentifier::new`。
#[trait_variant::make(CredentialRepo: Send)]
#[dynosaur(pub DynCredentialRepo = dyn(box) CredentialRepo, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: 同 RoleRepo——base trait 非 Send native AFIT，Send 由 trait_variant `CredentialRepo` 变体 +
// dynosaur `DynCredentialRepo` 承载（ADR-003/ADR-004 C1）。`Send + Sync` supertrait 使
// `Arc<DynCredentialRepo>` 可被 axum handler state 间接共享。
pub trait CredentialRepoLocal: Send + Sync {
    /// 按 canonical user id 查凭据（tenant-scoped；不存在返回 `Ok(None)`）。self-scoped 操作（改密）的身份
    /// 锚点是**认证主体**的 `ids::UserId`，**非**请求可选择的登录标识——调用方不能传 login 串定位他人凭据
    /// （#1277 F2：self-scoped 端点身份锚点 = authenticated subject，类型层杜绝越权改他人密码）。
    async fn find_by_user_id(
        &self,
        scope: TenantRepoScope,
        user_id: ids::UserId,
    ) -> Result<Option<Credential>, IdentityError>;

    /// **恒定成本验签 + 原子锁定记账**（F1+F2+F3，#1277）：无论凭据是否存在，候选明文总跑一次 argon2 KDF
    /// （经 `secure::verify_password_constant_time`）——消除「无此主体（跳 KDF 快返回）」与「密码错（跑 KDF）」
    /// 的登录枚举时序差。provider 内据 `(tenant, login)` 查得凭据与否，**原子**分流返回 [`AuthOutcome`]：
    /// - 已知 + 密码正确 → `Authenticated(user_id)`（canonical actor subject，写 wire/audit）+ 清零失败计数；
    /// - 已知 + 密码错 → `InvalidKnownUser` + 原子推进 lockout（达阈值即锁）；
    /// - 查无凭据 → `InvalidUnknown`，**不建/不动 lockout 态**（F2：未知主体不可被预置锁定、不撑大 lockout 表）。
    ///
    /// `now` 由调用方注入 `Clock` 读出（禁 `SystemTime::now()`，clippy 静态守）。消费方（`LoginService`）对
    /// `InvalidKnownUser` / `InvalidUnknown` 一律对外 `InvalidCredentials`（不向客户端区分以防枚举）。
    ///
    /// **provider 实现要求（postgres adapter W，#1258）**：① 验签 + lockout 推进须在**单次原子**（事务/行锁/
    /// 条件 upsert）内完成；② `InvalidKnownUser` 与 `InvalidUnknown` 的 RTT 差异 SHOULD 不超过 argon2 KDF 噪音
    /// 量级——即 lockout 写（仅已知主体路径有）不得引入主体枚举可观测时序差（必要时未知主体路径补等价空写
    /// 或已知主体路径异步推进）。in-mem 替身经 Mutex 内 KDF 主导，天然满足。
    async fn authenticate(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        candidate: String,
        now: SystemTime,
    ) -> Result<AuthOutcome, IdentityError>;

    /// 持久化凭据（upsert）。store key 派生自 `credential`（F2：tenant/login 错位不可表达）。
    async fn save(
        &self,
        scope: TenantRepoScope,
        credential: Credential,
    ) -> Result<(), IdentityError>;

    /// 密码变更 CAS：仅当存储版本 == `expected` 时以 `next` 替换；版本不匹配 → `Err(VersionConflict)`，
    /// 查无凭据 → `Err(CredentialNotFound)`（并发密码变更安全）。store key 派生自 `next`（F2）；消费方经
    /// `Credential::rotate`（保持 login/user_id/tenant、version + 1）构造 `next`。
    async fn bump_version(
        &self,
        scope: TenantRepoScope,
        expected: u32,
        next: Credential,
    ) -> Result<(), IdentityError>;

    /// **原子**锁定态查询（F1，验签前门控）：provider 内 RMW 完成「读 → `try_lazy_unlock(now)`（TTL 过则解锁
    /// 并持久化）→ 返回 `is_locked(now)`」。无锁定态（查无）→ `Ok(false)`。`now` 经注入 `Clock`。
    async fn lockout_status(
        &self,
        scope: TenantRepoScope,
        login: LoginIdentifier,
        now: SystemTime,
    ) -> Result<bool, IdentityError>;
}

/// 会话**生命周期** DI port（域形；provider 可换：prod postgres / demo in-mem）——会话**创建（co-tx，L2）**、
/// **查询（L1）**、**软撤销（L1）**收敛为**单一 provider**，create / find / revoke 同源。
///
/// 公开 [`SessionLifecycle`] 是 **Send 变体**（adapter `impl SessionLifecycle for ...`），
/// [`DynSessionLifecycle`] 是其 dyn-compatible wrapper（组合根经 `Arc<DynSessionLifecycle>` 注入）。
/// 基 trait 带 `Send + Sync` supertrait：登录 handler 需 clone 共享同一 lifecycle store，且
/// `LoginService::login().await` future 必须为 `Send`（axum handler 要求）。
///
/// **为何单一 provider（合并原 `SessionUnitOfWork` + `SessionRepo`，#1278）**：会话「创建写」与「查询/撤销」
/// 分属**两个未绑定的存储端口**时，组合根可注入分属不同底座的实例（persist 写 store A、find/revoke 查 store B）
/// ——login 写入的会话无法被同一 service 的 logout 撤销，且类型系统无法阻止该 bug（PR #255 F3）。收敛为单一
/// `SessionLifecycle` 后，**「两个未绑定 store」从类型层不可表达**：单一必填注入端口 ⇒ create / find / revoke 必
/// 同源（AI-robust **Hard**：构造器必填参数 + typed function choice）。工业 Rust 一致采用单一会话存储接口
/// （tower-sessions `SessionStore`：create+save+load+delete 同 trait；omicron `DataStore` console_session：
/// session_create / lookup / hard_delete 同 impl）。
/// ref: maxcountryman/tower-sessions tower-sessions-core/src/session_store.rs@main
/// ref: oxidecomputer/omicron nexus/db-queries/src/db/datastore/console_session.rs@main
///
/// **co-tx 原子性 INVARIANT OUTBOX-COTX-SESSION-01 不受合并影响**（L2 OutboxFact，FR-003）：原子性来自
/// [`persist_session_and_emit`](SessionLifecycleLocal::persist_session_and_emit) 的**方法签名形状**
/// （combined 单方法、域无半开事务句柄），**非** trait 边界——它与 `find` / `revoke` 并列于同一 trait 后仍是
/// 唯一 session-写 API（无 `save` / `emit` 分调）。adapter 在其 impl body 内独占事务边界（begin → 写 session →
/// append_outbox → 单 commit）；拆成 `SessionRepo::save` + `OutboxEmitter::emit` 两 provider-agnostic 调用，域
/// 无法绑同一事务（端口签名不容 `&mut PgConnection`，否则 `ports`→adapter 反向耦合），closure-UoW 把事务句柄
/// 回传给域同样泄漏 provider 类型并**重开 split-tx 洞**——故保留 combined 方法（co-tx 不可拆解在类型层成立，
/// Hard）。adapter same-tx 接线由 postgres `PgSessionLifecycle` 的 **INVARIANT: OUTBOX-COTX-SESSION-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }** +
/// 集成测试 anti-vacuity（commit 两行皆在 ↔ rollback 两行皆无）守。
///
/// 租户隔离由签名承载（fail-closed，同 `CredentialRepo`）：`find` / `revoke` 接收 [`TenantRepoScope`]，跨租
/// find→None（不泄露存在性）/ revoke→幂等 no-op。失败通道：`persist_session_and_emit` 经 [`OutboxEmitError`]
/// （diport infra 错误，source 已 PII-redacted）冒泡（co-tx 写失败任一步均不暴露原始错误明文，zero-trust；
/// 复用 infra 错误因签名已桥接 [`Entry`] / [`OutboxEnvelopeParts`]、失败本质是持久化层错误）；`find` / `revoke`
/// 经 [`IdentityError`] 冒泡。
///
/// 归属：域形 port（签名引用域内实体 [`Session`]）→ 本 crate `ports`，非 diport（ADR-005 category line，同
/// [`RoleRepo`]）。durable `find` / `revoke` 由 postgres `PgSessionLifecycle` 实写（tenant-scope SELECT/UPDATE +
/// `sessions.revoked` 列，#1278——补齐原 #1116 session durable 闭合，provider 无 `todo!()` 半实现）。
///
/// ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable）
/// ref: MassTransit Bus Outbox（一应用方法 co-persist 实体 + outbox 经共享事务/scoped DbContext）
/// ref: Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(SessionLifecycle: Send)]
#[dynosaur(pub DynSessionLifecycle = dyn(box) SessionLifecycle, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `SessionLifecycle` 变体 +
// dynosaur `DynSessionLifecycle` 承载（DI 注入走 Send wrapper）。`Send + Sync` supertrait 使
// `Arc<DynSessionLifecycle>` 可被 axum handler state 间接共享。
pub trait SessionLifecycleLocal: Send + Sync {
    /// **创建（co-tx，L2）**：把 [`Session`] 行与 outbox(`identity.session-created`) 行**同一本地事务**原子
    /// 写入（FR-003）。域构造 `entry`（事件语义归域：topic + opaque-UUID EventId + 编码 payload）与 `envelope`
    /// （opaque envelope 字段），并提供 `session` 业务实体；adapter 在单事务内先注入 tenant scope（SET LOCAL）、
    /// 写 session、`append_outbox`，单 commit。任一步失败 → 整体 rollback（both-or-neither）。**唯一 session-写
    /// API**（OUTBOX-COTX-SESSION-01：域无 `save`/`emit` 分调、无半开事务句柄）。
    async fn persist_session_and_emit(
        &self,
        scope: TenantRepoScope,
        session: Session,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError>;

    /// **查询（L1）**：按 id 查会话（不存在 / 已撤销 / 跨租 → `Ok(None)`，不泄露存在性）。
    async fn find(
        &self,
        scope: TenantRepoScope,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError>;

    /// **软撤销（L1，logout）**：域侧软撤销会话（幂等——重复 / 未知 / 跨租均 `Ok` 且 no-op）。已颁 JWT 在 TTL
    /// 内仍有效（硬吊销延 #1003）。
    async fn revoke(
        &self,
        scope: TenantRepoScope,
        session_id: SessionId,
    ) -> Result<(), IdentityError>;
}

/// refresh token 持久化 store DI port（域形；provider 可换：prod postgres / test in-mem）——#1325。
///
/// 公开 [`RefreshTokenStore`] 是 **Send 变体**（adapter `impl RefreshTokenStore for ...`），
/// [`DynRefreshTokenStore`] 是其 dyn-compatible wrapper（组合根经 `Box<DynRefreshTokenStore>` 注入，ADR-004 C1/C5）。
/// 归属为域形 port（签名引用 [`RefreshTokenRecord`]/[`RefreshTokenId`]/[`RefreshTokenHash`]）→ 本域 crate
/// `ports`，非 diport（ADR-005 category line，同 [`SessionLifecycle`]）。
///
/// 基 trait 带 `Send + Sync` supertrait（同 `CredentialRepo`/`SessionLifecycle`）：refresh / login handler 经
/// `Arc<RefreshService<S>>` 共享同一 store 作 axum handler state，且 `rotate().await` future 须为 `Send`
/// （axum handler 要求）——故 `Box<DynRefreshTokenStore>` 须 `Sync`（#1252 接线 refresh/login 端点）。
///
/// **哈希存储（不存明文）**：store 只持 secret 的 SHA-256 摘要（[`RefreshTokenHash`]）——攻陷 store 不泄露可用
/// refresh token（摘要不可逆）。secret 生成 / 摘要计算在 `secure::refresh`（base 层 crypto），编排在
/// `application::RefreshService`（域 / store 不做 crypto）。
///
/// **租户隔离由签名承载（fail-closed，同 `CredentialRepo`/`SessionLifecycle`）**：所有方法接
/// [`TenantRepoScope`] 做 store scope；跨租 `find_by_hash`→`None`（不泄露存在性）、`rotate`→CAS miss、
/// `revoke`/`revoke_lineage`→幂等 no-op。
///
/// **reuse-detection（旧 refresh 一次性 + 失窃检测）**：rotation 经 [`rotate`](RefreshTokenStoreLocal::rotate)
/// 的**原子 CAS** 保证旧 token 一次性消费；命中已消费 / 已撤销 token（重放）由 application 经
/// [`revoke_lineage`](RefreshTokenStoreLocal::revoke_lineage) 级联撤销整条谱系（OAuth refresh rotation 标准）。
///
/// ref: ory/fosite handler/oauth2/flow_refresh.go@master（refresh rotation + graceful reuse-detection，概念谱系）
/// ref: Cockburn Hexagonal Ports&Adapters（repo 归域核心，adapter DIP 实现）
#[trait_variant::make(RefreshTokenStore: Send)]
#[dynosaur(pub DynRefreshTokenStore = dyn(box) RefreshTokenStore, bridge(dyn))]
#[allow(async_fn_in_trait)]
// reason: base trait 为非 Send native AFIT；Send 由 trait_variant 生成的 `RefreshTokenStore` 变体 +
// dynosaur `DynRefreshTokenStore` 承载（DI 注入走 Send wrapper）。`Send + Sync` supertrait 使
// `Box<DynRefreshTokenStore>` 为 `Sync`、`RefreshService<S>` 可作共享 handler state（同 SessionLifecycle，#1252）。
pub trait RefreshTokenStoreLocal: Send + Sync {
    /// 持久化新签发记录（`status = Active`；签发链根 `lineage_id == id`）。
    async fn insert(
        &self,
        scope: TenantRepoScope,
        record: RefreshTokenRecord,
    ) -> Result<(), IdentityError>;

    /// 按 secret 摘要查找（不存在 / 跨租 → `Ok(None)`，不泄露存在性）。返回的记录含 status——application 据此
    /// 判活跃 / 重放（命中非 Active = 重放）。
    async fn find_by_hash(
        &self,
        scope: TenantRepoScope,
        hash: RefreshTokenHash,
    ) -> Result<Option<RefreshTokenRecord>, IdentityError>;

    /// **原子 CAS 轮换**：仅当 `rotation.old_id()` 当前 `status == Active` 时，**同一事务**内标其 `Consumed`
    /// + 插入 `rotation.new_record()`。
    ///
    /// 入参是 sealed [`RefreshRotation`] 命令（由源 record `begin_rotation` 派生）——tenant / parent / lineage
    /// 已从源 record 派生，错位组合类型层不可表达（REFRESH-ROTATE-LINEAGE-01，#284 F2）。store 据
    /// `rotation.new_record().tenant()` 注入 scope（无独立 `tenant` 入参可错位）。
    ///
    /// 返回 `Ok(true)` = CAS 命中（old 当时仍 Active，已消费 + 写入 new）；`Ok(false)` = old 已非 Active
    /// （并发轮换 / 重放胜出者已消费它）——**不写 new**，由 application 据此触发 reuse-detection 级联撤销。
    /// 旧 refresh 一次性失效在类型层 + 事务 CAS 双重保证（杜绝 TOCTOU 双换）。
    async fn rotate(
        &self,
        scope: TenantRepoScope,
        rotation: RefreshRotation,
    ) -> Result<bool, IdentityError>;

    /// **级联撤销整条谱系**（reuse-detection + logout）：把 `lineage_id` 家族全部记录置 `Revoked`。幂等
    /// （未知 / 跨租 / 已撤销均 `Ok` 且 no-op）。
    ///
    /// logout 与 reuse-detection 共用谱系级撤销——logout 须使活跃 token 及其整条轮换链失效（否则已轮换出的
    /// 子 token 仍可用），故无独立单条 `revoke(id)`（YAGNI：单条撤销无消费方）。
    async fn revoke_lineage(
        &self,
        scope: TenantRepoScope,
        lineage_id: RefreshTokenId,
    ) -> Result<(), IdentityError>;
}

#[cfg(test)]
mod smoke {
    //! build smoke：域形 async repo port 可 native-AFIT impl + mockall mock（非 `#[async_trait]`）均经
    //! `Box<DynRoleRepo>` 装入（PORT-SHAPE-01/02）。
    //!
    //! 与 diport `signer.rs` smoke 的差异：identity 域类型（`RoleId`/`Role`）构造器 **PR1 已写实**，但本 port
    //! 的 repo impl（`NoopRoleRepo` / mock）方法 body 仍 `todo!()`（真实 repo 接缝待 W，issue #1083），故本
    //! smoke **只构造 Dyn wrapper + 断言 `Send`，不 `.await`**（不触 repo `todo!()`）。async future 的 Send + 跨
    //! `tokio::spawn` 调度由 diport `signer.rs` `mockall_mock_loads_into_dyn_signer` 同范式已证（dynosaur Send 变体保证）。
    use super::{
        DynRoleRepo, DynSessionLifecycle, Entry, IdentityError, OutboxEmitError,
        OutboxEnvelopeParts, Role, RoleId, RoleRepo, Session, SessionId, SessionLifecycle,
        TenantRepoScope,
    };
    use std::sync::Arc;

    struct NoopRoleRepo;
    impl RoleRepo for NoopRoleRepo {
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _id: RoleId,
        ) -> Result<Option<Role>, IdentityError> {
            todo!()
        }
        async fn save(&self, _scope: TenantRepoScope, _role: Role) -> Result<(), IdentityError> {
            todo!()
        }
        async fn list(
            &self,
            _scope: TenantRepoScope,
            _page: super::RolePage,
        ) -> Result<super::RoleListResult, IdentityError> {
            todo!()
        }
    }

    fn assert_send<T: Send>(_: &T) {}
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send 变体
    // `DynRoleRepo` 且 wrapper `Send`（可跨 spawn 注入）。不调用方法 → 不触 `todo!()`。
    #[test]
    fn role_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynRoleRepo> = DynRoleRepo::new_box(NoopRoleRepo);
        assert_send(&from_impl);
        let from_mock: Box<DynRoleRepo> = DynRoleRepo::new_box(MockTestRoleRepo::new());
        assert_send(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——test-only service 把 `Box<DynRoleRepo>` 作必填
    // 位置参（非 Option），缺失即编译错误（ADR-004 C5）。impl/mock 各注入一次，证明域形 repo port 与
    // 既有 DI port 一致经 `Box<DynX>` 注入（不调用方法 → 不触 `todo!()`）。
    struct RoleService {
        _repo: Box<DynRoleRepo<'static>>,
    }
    impl RoleService {
        fn new(repo: Box<DynRoleRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn role_repo_is_required_ctor_injectable() {
        let from_impl = RoleService::new(DynRoleRepo::new_box(NoopRoleRepo));
        assert_send(&from_impl._repo);
        let from_mock = RoleService::new(DynRoleRepo::new_box(MockTestRoleRepo::new()));
        assert_send(&from_mock._repo);
    }

    // mock 是 native trait impl（`async fn` 直接声明，非 `#[async_trait]`），经 `new_box` 进 `DynRoleRepo`。
    mockall::mock! {
        TestRoleRepo {}
        impl RoleRepo for TestRoleRepo {
            async fn find(
                &self,
                scope: TenantRepoScope,
                id: RoleId,
            ) -> Result<Option<Role>, IdentityError>;
            async fn save(&self, scope: TenantRepoScope, role: Role) -> Result<(), IdentityError>;
            async fn list(
                &self,
                scope: TenantRepoScope,
                page: super::RolePage,
            ) -> Result<super::RoleListResult, IdentityError>;
        }
    }

    // ── SessionLifecycle（co-tx 创建 + 查询 + 软撤销，单一域形 port，#1278）PORT-SHAPE ────────────
    // 与 RoleRepo 不同：本 port 在 postgres adapter 有**真实 impl**（PgSessionLifecycle 的 co-tx 创建；
    // find/revoke 冻结 #1116），但本 smoke 仍只构造 Dyn wrapper + 断言 `Send`（不 `.await` → 不触 Noop
    // `todo!()`）；co-tx 行为由 adapter 集成测试守。三方法（create/find/revoke）同一 trait，证明合并后仍
    // 经单一 `Arc<DynSessionLifecycle>` 注入。
    struct NoopSessionLifecycle;
    impl SessionLifecycle for NoopSessionLifecycle {
        async fn persist_session_and_emit(
            &self,
            _scope: TenantRepoScope,
            _session: Session,
            _entry: Entry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), OutboxEmitError> {
            todo!()
        }
        async fn find(
            &self,
            _scope: TenantRepoScope,
            _session_id: SessionId,
        ) -> Result<Option<Session>, IdentityError> {
            todo!()
        }
        async fn revoke(
            &self,
            _scope: TenantRepoScope,
            _session_id: SessionId,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send+Sync 变体，
    // 可经 `Arc<DynSessionLifecycle>` 共享给 axum handler。
    #[test]
    fn session_lifecycle_impls_load_into_dyn_wrapper() {
        let from_impl: Arc<DynSessionLifecycle> =
            Arc::from(DynSessionLifecycle::new_box(NoopSessionLifecycle));
        assert_send_sync(&from_impl);
        let from_mock: Arc<DynSessionLifecycle> =
            Arc::from(DynSessionLifecycle::new_box(MockTestSessionLifecycle::new()));
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消费侧**构造器必填位置参注入**——`Arc<DynSessionLifecycle>` 作必填位置参（非 Option），
    // 缺失即编译错误（ADR-004 C5；LoginService 即如此持有单一 lifecycle，见 application.rs）。
    struct SessionService {
        _lifecycle: Arc<DynSessionLifecycle<'static>>,
    }
    impl SessionService {
        fn new(lifecycle: Arc<DynSessionLifecycle<'static>>) -> Self {
            Self {
                _lifecycle: lifecycle,
            }
        }
    }

    #[test]
    fn session_lifecycle_is_required_ctor_injectable() {
        let from_impl = SessionService::new(Arc::from(DynSessionLifecycle::new_box(
            NoopSessionLifecycle,
        )));
        assert_send_sync(&from_impl._lifecycle);
        let from_mock = SessionService::new(Arc::from(DynSessionLifecycle::new_box(
            MockTestSessionLifecycle::new(),
        )));
        assert_send_sync(&from_mock._lifecycle);
    }

    mockall::mock! {
        TestSessionLifecycle {}
        impl SessionLifecycle for TestSessionLifecycle {
            async fn persist_session_and_emit(
                &self,
                scope: TenantRepoScope,
                session: Session,
                entry: Entry,
                envelope: OutboxEnvelopeParts,
            ) -> Result<(), OutboxEmitError>;
            async fn find(
                &self,
                scope: TenantRepoScope,
                session_id: SessionId,
            ) -> Result<Option<Session>, IdentityError>;
            async fn revoke(
                &self,
                scope: TenantRepoScope,
                session_id: SessionId,
            ) -> Result<(), IdentityError>;
        }
    }
}

#[cfg(test)]
mod smoke_credential {
    //! build smoke：`CredentialRepo` 域形 async port 同范式（PORT-SHAPE-01/02）——native-AFIT impl +
    //! mockall mock 均经 `Arc<DynCredentialRepo>` 装入 + `Send + Sync`。`NoopCredentialRepo` body `todo!()`，
    //! 故只构造 Dyn wrapper + 断言 `Send`，**不 `.await`**（真实行为由 `internal::mem::InMemCredentialRepo`
    //! round-trip 测试覆盖）。
    use super::{
        AuthOutcome, Credential, CredentialRepo, DynCredentialRepo, IdentityError, LoginIdentifier,
        SystemTime, TenantRepoScope,
    };
    use std::sync::Arc;

    struct NoopCredentialRepo;
    impl CredentialRepo for NoopCredentialRepo {
        async fn find_by_user_id(
            &self,
            _scope: TenantRepoScope,
            _user_id: ids::UserId,
        ) -> Result<Option<Credential>, IdentityError> {
            todo!()
        }
        async fn authenticate(
            &self,
            _scope: TenantRepoScope,
            _login: LoginIdentifier,
            _candidate: String,
            _now: SystemTime,
        ) -> Result<AuthOutcome, IdentityError> {
            todo!()
        }
        async fn save(
            &self,
            _scope: TenantRepoScope,
            _credential: Credential,
        ) -> Result<(), IdentityError> {
            todo!()
        }
        async fn bump_version(
            &self,
            _scope: TenantRepoScope,
            _expected: u32,
            _next: Credential,
        ) -> Result<(), IdentityError> {
            todo!()
        }
        async fn lockout_status(
            &self,
            _scope: TenantRepoScope,
            _login: LoginIdentifier,
            _now: SystemTime,
        ) -> Result<bool, IdentityError> {
            todo!()
        }
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：impl + mock 均经 `new_box` 装入 dynosaur Send+Sync 变体，可经
    // `Arc<DynCredentialRepo>` 共享给 axum handler。
    #[test]
    fn credential_repo_impls_load_into_dyn_wrapper() {
        let from_impl: Arc<DynCredentialRepo> =
            Arc::from(DynCredentialRepo::new_box(NoopCredentialRepo));
        assert_send_sync(&from_impl);
        let from_mock: Arc<DynCredentialRepo> =
            Arc::from(DynCredentialRepo::new_box(MockTestCredentialRepo::new()));
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消费侧构造器必填位置参注入（`Arc<DynCredentialRepo>` 非 Option，缺失即编译错误）。
    struct CredentialService {
        _repo: Arc<DynCredentialRepo<'static>>,
    }
    impl CredentialService {
        fn new(repo: Arc<DynCredentialRepo<'static>>) -> Self {
            Self { _repo: repo }
        }
    }

    #[test]
    fn credential_repo_is_required_ctor_injectable() {
        let from_impl =
            CredentialService::new(Arc::from(DynCredentialRepo::new_box(NoopCredentialRepo)));
        assert_send_sync(&from_impl._repo);
        let from_mock = CredentialService::new(Arc::from(DynCredentialRepo::new_box(
            MockTestCredentialRepo::new(),
        )));
        assert_send_sync(&from_mock._repo);
    }

    mockall::mock! {
        TestCredentialRepo {}
        impl CredentialRepo for TestCredentialRepo {
            async fn find_by_user_id(&self, scope: TenantRepoScope, user_id: ids::UserId) -> Result<Option<Credential>, IdentityError>;
            async fn authenticate(&self, scope: TenantRepoScope, login: LoginIdentifier, candidate: String, now: SystemTime) -> Result<AuthOutcome, IdentityError>;
            async fn save(&self, scope: TenantRepoScope, credential: Credential) -> Result<(), IdentityError>;
            async fn bump_version(&self, scope: TenantRepoScope, expected: u32, next: Credential) -> Result<(), IdentityError>;
            async fn lockout_status(&self, scope: TenantRepoScope, login: LoginIdentifier, now: SystemTime) -> Result<bool, IdentityError>;
        }
    }
}

#[cfg(test)]
mod smoke_refresh {
    //! build smoke：`RefreshTokenStore` 域形 async port 同范式（PORT-SHAPE-01/02，#1325）——native-AFIT impl +
    //! mockall mock 均经 `Box<DynRefreshTokenStore>` 装入 + `Send + Sync`。`RefreshTokenStoreLocal` supertrait
    //! 为 `Send + Sync`（#1252 接线 refresh/login handler 共享 state 要求），故 `DynRefreshTokenStore` 亦
    //! `Send + Sync`；烟测断言升级为 `assert_send_sync`。`NoopRefreshTokenStore` body `todo!()`，
    //! 故只构造 Dyn wrapper + 断言 `Send + Sync`，**不 `.await`**（真实行为由 `internal::mem::InMemRefreshTokenStore`
    //! + `application::RefreshService` 集成测试覆盖）。
    use super::{
        DynRefreshTokenStore, IdentityError, RefreshRotation, RefreshTokenHash, RefreshTokenId,
        RefreshTokenRecord, RefreshTokenStore, TenantRepoScope,
    };

    struct NoopRefreshTokenStore;
    impl RefreshTokenStore for NoopRefreshTokenStore {
        async fn insert(
            &self,
            _scope: TenantRepoScope,
            _record: RefreshTokenRecord,
        ) -> Result<(), IdentityError> {
            todo!()
        }
        async fn find_by_hash(
            &self,
            _scope: TenantRepoScope,
            _hash: RefreshTokenHash,
        ) -> Result<Option<RefreshTokenRecord>, IdentityError> {
            todo!()
        }
        async fn rotate(
            &self,
            _scope: TenantRepoScope,
            _rotation: RefreshRotation,
        ) -> Result<bool, IdentityError> {
            todo!()
        }
        async fn revoke_lineage(
            &self,
            _scope: TenantRepoScope,
            _lineage_id: RefreshTokenId,
        ) -> Result<(), IdentityError> {
            todo!()
        }
    }

    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    // PORT-SHAPE-01：native-AFIT impl 与 mockall mock 均经 `new_box` 装入 dynosaur Send+Sync 变体（#1252）。
    #[test]
    fn refresh_store_impls_load_into_dyn_wrapper() {
        let from_impl: Box<DynRefreshTokenStore> =
            DynRefreshTokenStore::new_box(NoopRefreshTokenStore);
        assert_send_sync(&from_impl);
        let from_mock: Box<DynRefreshTokenStore> =
            DynRefreshTokenStore::new_box(MockTestRefreshTokenStore::new());
        assert_send_sync(&from_mock);
    }

    // PORT-SHAPE-02：消費侧构造器必填位置参注入（`Box<DynRefreshTokenStore>` 非 Option，缺失即编译错误）。
    struct RefreshStoreService {
        _store: Box<DynRefreshTokenStore<'static>>,
    }
    impl RefreshStoreService {
        fn new(store: Box<DynRefreshTokenStore<'static>>) -> Self {
            Self { _store: store }
        }
    }

    #[test]
    fn refresh_store_is_required_ctor_injectable() {
        let from_impl =
            RefreshStoreService::new(DynRefreshTokenStore::new_box(NoopRefreshTokenStore));
        assert_send_sync(&from_impl._store);
        let from_mock = RefreshStoreService::new(DynRefreshTokenStore::new_box(
            MockTestRefreshTokenStore::new(),
        ));
        assert_send_sync(&from_mock._store);
    }

    mockall::mock! {
        TestRefreshTokenStore {}
        impl RefreshTokenStore for TestRefreshTokenStore {
            async fn insert(&self, scope: TenantRepoScope, record: RefreshTokenRecord) -> Result<(), IdentityError>;
            async fn find_by_hash(&self, scope: TenantRepoScope, hash: RefreshTokenHash) -> Result<Option<RefreshTokenRecord>, IdentityError>;
            async fn rotate(&self, scope: TenantRepoScope, rotation: RefreshRotation) -> Result<bool, IdentityError>;
            async fn revoke_lineage(&self, scope: TenantRepoScope, lineage_id: RefreshTokenId) -> Result<(), IdentityError>;
        }
    }
}
