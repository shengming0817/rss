//! [`RequestCtx`]：请求级控制流值快照（tenant / principal）。
//!
//! 不可变快照，经 [`crate::local`] 的 `task_local!` 传播。私有字段 + 无 `Deserialize`
//! ⇒ sealed 构造，从 request body 反序列化构造**不可表达**（ADR-001 §D5）。

/// 请求级授权快照——**只**装控制流值（tenant / principal），不装可观测 ID（见 crate 级文档）。
///
/// 泛型 `T`（tenant）/ `P`（principal）使 runctx 保持零内部依赖：
/// - `P` 必须 trait/泛型擦除——`Principal` 归 `authn`（service 层），而 `authn` 已依赖 runctx，
///   故 `runctx → authn` 是 cargo 拒绝的闭环，principal 永不可被 runctx 按具体类型持有（ADR-001 §D3）。
/// - `T` 暂同样泛型；目标态（ADR-001 §D3「intra-base sub-DAG」）下收敛为具体
///   `vocab::tenant::TenantId`，届时只改 [`AppCtx`] 别名一处。
///
/// 字段私有 = sealed 构造：唯一入口 [`RequestCtx::new`]，调用点须在已认证通道（ADR-001 §D5）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestCtx<T, P> {
    tenant: T,
    principal: P,
}

impl<T, P> RequestCtx<T, P> {
    /// 唯一构造入口。调用方须处于已认证通道（JWT claim / service-token-MAC 的 `X-Tenant-ID`）；
    /// body 派生的 tenant 在 codegen 处被拒（`docs/rules/tenancy.md`）。
    pub fn new(tenant: T, principal: P) -> Self {
        Self { tenant, principal }
    }

    /// 借用 tenant 控制流值。
    pub fn tenant(&self) -> &T {
        &self.tenant
    }

    /// 借用 principal 控制流值。
    pub fn principal(&self) -> &P {
        &self.principal
    }
}

/// 进程级实例化别名：`task_local!` 不能泛型，须钉死一组具体 payload 类型。
///
/// spike 用 [`TenantSlot`] / [`PrincipalSlot`] 占位；W 阶段把本别名换成
/// `RequestCtx<vocab::tenant::TenantId, _PrincipalFacet>`（ADR-001 §D3，单点迁移）。
pub type AppCtx = RequestCtx<TenantSlot, PrincipalSlot>;

/// spike tenant 占位 newtype。
// reason: 接缝冻结期的最小可测 payload；W 阶段由 `vocab::tenant::TenantId` 取代。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantSlot(String);

impl TenantSlot {
    /// 构造占位 tenant（仅 spike）。
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// spike principal 占位 newtype。
// reason: 同上；W 阶段由 authn 的 principal facet（trait 擦除）取代，runctx 不直接持有具体 Principal。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalSlot(String);

impl PrincipalSlot {
    /// 构造占位 principal（仅 spike）。
    pub fn new(subject: impl Into<String>) -> Self {
        Self(subject.into())
    }
}
