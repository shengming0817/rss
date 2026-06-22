//! 租户词汇。TenantId 归 vocab（ADR-002 D3）。

// ---------------------------------------------------------------------------
// ScopedTenant — 排除 All 的受限行级可见域（Finding#13，tenancy.md 类型层约束）
// ---------------------------------------------------------------------------

/// 受限行级可见域（排除 All；All 只能经 new_cross_tenant 进入）。
///
/// 类型层杜绝「把 All 传给 RowVisibility::new」（tenancy.md）。
/// `RowVisibility::new` 接受此类型而非 `RowScope`，使错误在编译期不可表达（Hard）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedTenant {
    /// 仅可见自身（user/device 级隔离）。
    SelfOnly,
    /// 可见同设备下的行。
    Device,
    /// 可见同租户下的行。
    Tenant,
}

impl ScopedTenant {
    /// 提升为完整 RowScope（不含 All 方向）。
    pub fn as_row_scope(self) -> RowScope {
        todo!()
    }
}

/// `TenantId` 解析错误。空值 / nil UUID / 非 canonical UUID 均非法（`docs/rules/tenancy.md` fail-closed）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TenantIdError {
    #[error("tenant id is empty")]
    Empty,
    #[error("tenant id is nil uuid")]
    Nil,
    #[error("tenant id is not a canonical uuid")]
    Format,
}

/// 租户标识 newtype（私有字段，canonical UUID 背书；构造经 fallible funnel）。
///
/// 隔离域边界类型——空值与 nil UUID 非法、非空必须 canonical UUID（`docs/rules/tenancy.md`）。
/// 用 UUID 内部表示让「非 canonical 租户」从类型层不可表达；不提供 infallible 构造入口。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(uuid::Uuid);

impl TenantId {
    /// 解析 canonical UUID 字符串；拒绝 empty / nil / 非 canonical（fail-closed）。
    pub fn parse(_raw: &str) -> Result<Self, TenantIdError> {
        todo!()
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// 行级数据权限词汇（tenancy.md §RowScope / §RowVisibility / §CrossTenantVisibility）
// ---------------------------------------------------------------------------

/// 行级数据可见域（闭值集；无 `Default`——必须显式指定，fail-closed）。
///
/// 驱动 RLS / PG scope 与 ABAC filter 派生；见 `docs/rules/tenancy.md`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowScope {
    /// 仅可见自身（user/device 级隔离）。
    SelfOnly,
    /// 可见同设备下的行。
    Device,
    /// 可见同租户下的行。
    Tenant,
    /// 跨租户全局可见（需经 [`CrossTenantVisibility`] 显式 marker）。
    All,
}

/// 行级可见性义务（sealed obligation：私有字段，只能经构造 funnel 构造）。
///
/// 持有者保证 scope + 可选租户约束已经过认证通道派生；外部无法绕过 funnel 自造。
// ADR-004 C8 签名冻结：字段私有、体为 todo!()；函数体落地前 dead_code 预期（carve-out item-level）。
// reason: ADR-004 C8 签名冻结——私有字段待行为 PR 读取
#[allow(dead_code)]
pub struct RowVisibility {
    scope: RowScope,
    /// `Some` 时约束于特定租户（`ScopedTenant` scope 下由 Principal 派生）。
    tenant: Option<TenantId>,
}

impl RowVisibility {
    /// 构造单租户/自身可见性。`tenant` 来自已认证 principal 的 tenant claim。
    ///
    /// 接受 [`ScopedTenant`] 而非 [`RowScope`]，类型层排除 `RowScope::All`
    /// 进入此路径（Finding#13，tenancy.md，Hard）。
    pub fn new(_scope: ScopedTenant, _tenant: TenantId) -> Self {
        todo!()
    }

    /// 构造跨租户可见性。调用方须持有 [`CrossTenantVisibility`] marker（显式位置参）。
    pub fn new_cross_tenant(_marker: CrossTenantVisibility) -> Self {
        todo!()
    }

    /// 返回当前可见域。
    pub fn scope(&self) -> RowScope {
        todo!()
    }

    /// 返回租户约束（跨租户 `All` scope 时为 `None`）。
    pub fn tenant(&self) -> Option<TenantId> {
        todo!()
    }
}

/// 跨租户授权 capability（构造受控：仅 authn 已校验 super-admin 派生路径应签发）。
///
/// INVARIANT: TENANCY-CROSSTENANT-CAP-01 —— 跨 crate 真 seal 不可达（domain-patterns.md：sealed-trait
/// 仅定义-crate 内封闭，vocab 无法对 authn sealing）。本类型为 **Medium 漏斗**：私有字段强制经 funnel，
/// 显式且 greppable；「只 authn verified super-admin 路径可调用」由 callsite-allowlist governance lint 强制
/// （lint 跟踪见 #1074）。
pub struct CrossTenantCapability {
    _seal: (),
}

impl CrossTenantCapability {
    /// 由 authn 已校验 super-admin 派生路径签发（governance lint 限定 callsite）。
    pub fn issue_for_verified_super_admin() -> Self {
        todo!()
    }
}

/// 跨租户可见性 sealed 位置参（私有构造，跨租户 API 必须显式传入此 marker）。
///
/// 持有此值代表调用方已经过平台授权验证（`SuperAdmin` / framework-internal）；
/// 非特权代码路径无构造入口，从类型层杜绝意外跨租户访问（ADR-002）。
// ADR-004 C8 签名冻结：字段私有、体为 todo!()；函数体落地前 dead_code 预期（carve-out item-level）。
// reason: ADR-004 C8 签名冻结——私有字段待行为 PR 读取
#[allow(dead_code)]
pub struct CrossTenantVisibility {
    // 私有 unit 字段，阻止 struct literal 构造
    _priv: (),
}

impl CrossTenantVisibility {
    /// 经 [`CrossTenantCapability`] capability 授权构造跨租户可见性 marker。
    ///
    /// 调用方须持有已签发的 `CrossTenantCapability`（由 authn 校验 super-admin 路径签发）。
    pub fn authorize(_cap: CrossTenantCapability) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 RowScope / ScopedTenant Copy enum 可构造、funnel 签名可引用（不调用 todo!() body）。
    use super::{
        CrossTenantCapability, CrossTenantVisibility, RowScope, RowVisibility, ScopedTenant,
        TenantId,
    };

    #[test]
    fn row_scope_and_visibility_signatures_are_consumable() {
        // RowScope Copy enum 构造（不触发 todo!()）
        let _scope: RowScope = RowScope::Tenant;
        let _self_only = RowScope::SelfOnly;
        let _device = RowScope::Device;
        let _all = RowScope::All;

        // 穷尽 match 证明 #[non_exhaustive] 不阻止 crate-内部穷举
        match _scope {
            RowScope::SelfOnly => {}
            RowScope::Device => {}
            RowScope::Tenant => {}
            RowScope::All => {} // non_exhaustive variant 由编译器在 crate 外强制 `_` 分支，crate 内穷举合法
        }

        // ScopedTenant Copy enum 构造（Finding#13：类型层排除 All）
        let _st: ScopedTenant = ScopedTenant::Tenant;
        let _st_self = ScopedTenant::SelfOnly;
        let _st_dev = ScopedTenant::Device;

        // 穷尽 match ScopedTenant（crate 内合法；无 All 变体——类型层约束）
        match _st {
            ScopedTenant::SelfOnly => {}
            ScopedTenant::Device => {}
            ScopedTenant::Tenant => {}
        }

        // 绑定函数指针证明签名形状（不调用 → 不触 todo!()）
        // Finding#13：new 接受 ScopedTenant 而非 RowScope，All 路径从类型层排除
        let _new: fn(ScopedTenant, TenantId) -> RowVisibility = RowVisibility::new;
        let _cross: fn(CrossTenantVisibility) -> RowVisibility = RowVisibility::new_cross_tenant;

        // as_row_scope 签名可绑定（不调用）
        let _as_scope: fn(ScopedTenant) -> RowScope = ScopedTenant::as_row_scope;

        // F3：CrossTenantCapability funnel 签名可绑定（不调用 → 不触 todo!()）
        // issue_for_verified_super_admin 是受控入口；authorize 消费 capability 构造 marker
        let _issue: fn() -> CrossTenantCapability =
            CrossTenantCapability::issue_for_verified_super_admin;
        let _authorize: fn(CrossTenantCapability) -> CrossTenantVisibility =
            CrossTenantVisibility::authorize;
    }
}
