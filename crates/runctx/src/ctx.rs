//! [`RequestCtx`]：请求级控制流值快照（tenant / principal）。
//!
//! 不可变快照，经 [`crate::local`] 的 `task_local!` 传播。私有字段 + 无 `Deserialize`
//! ⇒ sealed 构造，从 request body 反序列化构造**不可表达**（ADR-002 §D5）。

/// 请求级授权快照——**只**装控制流值（tenant / principal），不装可观测 ID（见 crate 级文档）。
///
/// 泛型 `T`（tenant）/ `P`（principal）把 runctx 对具体 payload 的耦合收敛到单一别名点：
/// - `P` 必须 trait/泛型擦除——`Principal` 归 `authn`（service 层），而 `authn` 已依赖 runctx，
///   故 `runctx → authn` 是 cargo 拒绝的闭环，principal 永不可被 runctx 按具体类型持有（ADR-002 §D3）。
/// - `T` 在 [`AppCtx`] 收敛为具体 `vocab::tenant::TenantId`（ADR-002 §D3「intra-base sub-DAG」
///   已落地：sanctioned `runctx → vocab` 边）；泛型 `T` 仍保留，切换 tenant 类型只改别名一处。
///
/// 字段私有 = sealed 构造：唯一入口 [`RequestCtx::new`]。具体 [`AppCtx`] 的 principal payload
/// （[`PrincipalSlot`]）构造器为 `pub(crate)`，外部 crate 无法 mint principal ⇒ `AppCtx` 不可被下游伪造
/// （ADR-002 §D5，Hard / crate 可见性；tenant 已是公有可解析的 `TenantId`，伪造门收敛到 principal 接缝）。
///
/// **Debug 经 `secure::Redact` 字段级脱敏**：tenant/principal 是授权 PII，`Debug` 只出占位，绝不打印
/// payload（ADR-002 §D1 / §威胁矩阵），杜绝 `?ctx` / 断言失败 / 临时日志泄露原值。
#[derive(Clone, PartialEq, Eq, secure::Redact)]
pub struct RequestCtx<T, P> {
    #[redact(internal)]
    tenant: T,
    #[redact(internal)]
    principal: P,
}

impl<T, P> RequestCtx<T, P> {
    /// 唯一构造入口。调用方须处于已认证通道（JWT claim / service-token-MAC 的 `X-Tenant-ID`）；
    /// body 派生的 tenant 在 codegen 处被拒（`docs/rules/tenancy.md`）。
    ///
    /// trusted-caller 收口：具体 [`AppCtx`] 因 [`PrincipalSlot`] 构造器 `pub(crate)` 而外部不可伪造；泛型
    /// `RequestCtx::new` 的能力门（sealed capability，由 authn 持有）随 authn 落 W 阶段（ADR-002 §D5）。
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
/// tenant 已收敛为具体 [`vocab::tenant::TenantId`]（ADR-002 §D3 intra-base sub-DAG：sanctioned
/// `runctx → vocab` 边）。principal 仍 [`PrincipalSlot`] 占位——W 阶段由 authn 的 principal facet
/// （trait 擦除）取代；`runctx → authn` 是 cargo 拒绝的闭环，principal 永不可被 runctx 按具体类型持有。
pub type AppCtx = RequestCtx<vocab::tenant::TenantId, PrincipalSlot>;

/// spike principal 占位 newtype。**非 consumer API**（`#[doc(hidden)]` + `pub(crate)` 构造）：
/// W 阶段由 authn 的 principal facet（trait 擦除）取代，runctx 不直接持有具体 `Principal`。
// reason: 同上；构造 pub(crate) 收 forgeability，doc(hidden) 防误用。
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, secure::Redact)]
pub struct PrincipalSlot(#[redact(secret)] String);

impl PrincipalSlot {
    /// 构造占位 principal（仅测试 / `test-support` feature；生产构建无构造路径 ⇒ `AppCtx`
    /// 在生产下不可在 crate 外伪造）。`test-support` 仅经下游 `[dev-dependencies]` 开启，
    /// 不进生产构建，故生产伪造门不变（principal 生产接缝替换仍属 W，见 crate 文档）。
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn new(subject: impl Into<String>) -> Self {
        Self(subject.into())
    }
}

/// 测试支撑：仅 `test-support` feature 下编译，供下游 crate（如 authn）单测构造 [`AppCtx`]。
///
/// 生产构建不启用此 feature（消费方仅经 `[dev-dependencies]` 开启）⇒ `PrincipalSlot` 生产不可
/// 伪造的保证不变；`AppCtx` 的 principal 生产接缝（`PrincipalSlot` → authn principal facet）替换仍属 W。
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::{AppCtx, PrincipalSlot, RequestCtx};
    use vocab::tenant::TenantId;

    /// 构造一个绑定 `tenant` 的 [`AppCtx`]，principal 槽填占位 `subject`（仅测试用）。
    pub fn app_ctx(tenant: TenantId, subject: impl Into<String>) -> AppCtx {
        RequestCtx::new(tenant, PrincipalSlot::new(subject))
    }
}
