//! [`RequestCtx`]：请求级控制流值快照（tenant / principal）。
//!
//! 不可变快照，经 [`crate::local`] 的 `task_local!` 传播。私有字段 + 无 `Deserialize`
//! ⇒ sealed 构造，从 request body 反序列化构造**不可表达**（ADR-001 §D5）。

use std::fmt;

/// 请求级授权快照——**只**装控制流值（tenant / principal），不装可观测 ID（见 crate 级文档）。
///
/// 泛型 `T`（tenant）/ `P`（principal）使 runctx 保持零内部依赖：
/// - `P` 必须 trait/泛型擦除——`Principal` 归 `authn`（service 层），而 `authn` 已依赖 runctx，
///   故 `runctx → authn` 是 cargo 拒绝的闭环，principal 永不可被 runctx 按具体类型持有（ADR-001 §D3）。
/// - `T` 暂同样泛型；目标态（ADR-001 §D3「intra-base sub-DAG」）下收敛为具体
///   `vocab::tenant::TenantId`，届时只改 [`AppCtx`] 别名一处。
///
/// 字段私有 = sealed 构造：唯一入口 [`RequestCtx::new`]。具体 [`AppCtx`] 的 payload（slot）构造器
/// 是 `pub(crate)`，外部 crate 无法伪造 `AppCtx`（ADR-001 §D5，Hard / crate 可见性）。
///
/// **不 derive `Debug`**：tenant/principal 是授权 PII，手写 redacted `Debug` 只出占位，绝不打印
/// payload（ADR-001 §D1 / §威胁矩阵），杜绝 `?ctx` / 断言失败 / 临时日志泄露原值。
#[derive(Clone, PartialEq, Eq)]
pub struct RequestCtx<T, P> {
    tenant: T,
    principal: P,
}

impl<T, P> RequestCtx<T, P> {
    /// 唯一构造入口。调用方须处于已认证通道（JWT claim / service-token-MAC 的 `X-Tenant-ID`）；
    /// body 派生的 tenant 在 codegen 处被拒（`docs/rules/tenancy.md`）。
    ///
    /// trusted-caller 收口：具体 [`AppCtx`] 因 slot 构造器 `pub(crate)` 而外部不可伪造；泛型
    /// `RequestCtx::new` 的能力门（sealed capability，由 authn 持有）随 authn 落 W 阶段（ADR-001 §D5）。
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

// reason: 手写 redacted Debug，不打印 tenant/principal payload（授权 PII，ADR-001 §D1）；
// 不要求 T/P: Debug，故 payload 在 Debug 通道上不可达。
impl<T, P> fmt::Debug for RequestCtx<T, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestCtx")
            .field("tenant", &"<redacted>")
            .field("principal", &"<redacted>")
            .finish()
    }
}

/// 进程级实例化别名：`task_local!` 不能泛型，须钉死一组具体 payload 类型。
///
/// spike 用 [`TenantSlot`] / [`PrincipalSlot`] 占位；W 阶段把本别名换成
/// `RequestCtx<vocab::tenant::TenantId, _PrincipalFacet>`（ADR-001 §D3，单点迁移）。
pub type AppCtx = RequestCtx<TenantSlot, PrincipalSlot>;

/// spike tenant 占位 newtype。**非 consumer API**（`#[doc(hidden)]` + `pub(crate)` 构造）：
/// W 阶段由 `vocab::tenant::TenantId`（带「空值 / nil 非法」校验，见 `docs/rules/tenancy.md`）取代。
/// 构造器 `pub(crate)` ⇒ 外部 crate 无法 mint，故 `AppCtx` 不可被下游伪造（ADR-001 §D5）；
/// 占位期校验留待真类型，因为外部已无构造路径、无未受信输入到达此处。
// reason: 接缝冻结期的最小可测 payload；构造 pub(crate) 收 forgeability，doc(hidden) 防误用。
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct TenantSlot(String);

impl TenantSlot {
    /// 构造占位 tenant（仅测试；非 test 构建无构造路径 ⇒ `AppCtx` 彻底不可在 crate 外伪造）。
    #[cfg(test)]
    pub(crate) fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

// reason: redacted Debug —— assert_eq! 失败消息需要 Debug，但占位/真 payload 都不该裸打印。
impl fmt::Debug for TenantSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TenantSlot(<redacted>)")
    }
}

/// spike principal 占位 newtype。**非 consumer API**（`#[doc(hidden)]` + `pub(crate)` 构造）：
/// W 阶段由 authn 的 principal facet（trait 擦除）取代，runctx 不直接持有具体 `Principal`。
// reason: 同上；构造 pub(crate) 收 forgeability，doc(hidden) 防误用。
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct PrincipalSlot(String);

impl PrincipalSlot {
    /// 构造占位 principal（仅测试；非 test 构建无构造路径 ⇒ `AppCtx` 彻底不可在 crate 外伪造）。
    #[cfg(test)]
    pub(crate) fn new(subject: impl Into<String>) -> Self {
        Self(subject.into())
    }
}

// reason: redacted Debug，同 TenantSlot。
impl fmt::Debug for PrincipalSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrincipalSlot(<redacted>)")
    }
}
