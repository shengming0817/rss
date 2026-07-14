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
        match self {
            ScopedTenant::SelfOnly => RowScope::SelfOnly,
            ScopedTenant::Device => RowScope::Device,
            ScopedTenant::Tenant => RowScope::Tenant,
        }
    }
}

/// `TenantId` 解析错误。空值 / nil UUID / 非 canonical UUID 均非法（`docs/rules/tenancy.md` fail-closed）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
///
/// **可观测标识、非凭据**：`Debug` / `Display` 有意输出 canonical UUID 原值——tenant id 是 audit /
/// tracing span 的合法字段（对比 principal subject 等凭据级 PII 须脱敏，ADR-002 §威胁矩阵）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(uuid::Uuid);

impl TenantId {
    /// 解析 canonical UUID 字符串；拒绝 empty / nil / 非 canonical（fail-closed）。
    ///
    /// canonical = lowercase-hyphenated（RFC 9562 §4）。`Uuid::try_parse` 宽松（接受
    /// simple / braced / urn / 大写），故 round-trip 比对拒绝非 canonical 表示——隔离域边界
    /// 只认单一字符串形态，杜绝同一 UUID 多形态在 RLS predicate / cache key 上歧义。
    /// 错误优先级：空→`Empty`；非 canonical 形态（含**非 canonical 的 nil**，如 simple `00…0`）→`Format`
    /// （round-trip 先于 nil 检查拒绝）；仅 canonical nil 串→`Nil`。
    pub fn parse(raw: &str) -> Result<Self, TenantIdError> {
        if raw.is_empty() {
            return Err(TenantIdError::Empty);
        }
        let uuid = uuid::Uuid::try_parse(raw).map_err(|_| TenantIdError::Format)?;
        if uuid.hyphenated().to_string() != raw {
            return Err(TenantIdError::Format);
        }
        if uuid.is_nil() {
            return Err(TenantIdError::Nil);
        }
        Ok(Self(uuid))
    }

    /// 取底层 uuid。
    pub fn as_uuid(&self) -> uuid::Uuid {
        self.0
    }
}

// 可观测标识：Display 输出 canonical lowercase-hyphenated（同 parse 接受形态），便于 span / audit 结构化字段，
// 免消费方退回 `as_uuid().to_string()` 或 `{:?}`（后者带 `TenantId(..)` 前缀）。
impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.hyphenated())
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

impl RowScope {
    /// 稳定 metadata label（小写 kebab-free 标量）。
    pub fn as_label(self) -> &'static str {
        match self {
            RowScope::SelfOnly => "self-only",
            RowScope::Device => "device",
            RowScope::Tenant => "tenant",
            RowScope::All => "all",
        }
    }
}

/// 行级可见性义务（sealed obligation：私有字段，只能经构造 funnel 构造）。
///
/// 持有者保证 scope + 可选租户约束已经过认证通道派生；外部无法绕过 funnel 自造。
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
    pub fn new(scope: ScopedTenant, tenant: TenantId) -> Self {
        Self {
            scope: scope.as_row_scope(),
            tenant: Some(tenant),
        }
    }

    /// 构造跨租户可见性。调用方须持有 [`CrossTenantVisibility`] marker（显式位置参）。
    pub fn new_cross_tenant(_marker: CrossTenantVisibility) -> Self {
        Self {
            scope: RowScope::All,
            tenant: None,
        }
    }

    /// 返回当前可见域。
    pub fn scope(&self) -> RowScope {
        self.scope
    }

    /// 返回租户约束（跨租户 `All` scope 时为 `None`）。
    pub fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }
}

/// 跨租户授权 capability（构造受控：仅 audit durable append receipt 消费点应签发）。
///
/// INVARIANT: TENANCY-CROSSTENANT-CAP-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 跨 crate 真 seal 不可达（domain-patterns.md：sealed-trait
/// 仅定义-crate 内封闭，vocab 无法对 authn sealing）。本类型为 **Medium 漏斗**：私有字段强制经 funnel（上游
/// Hard），显式且 greppable；「只 authn verified super-admin 路径可调用」（下游）由 callsite-allowlist dylint
/// `rss_crosstenant_callsite`（`lints/`，精确放行 audit receipt 消费函数）强制。
pub struct CrossTenantCapability {
    _seal: (),
}

impl CrossTenantCapability {
    /// 由 authn 已校验 super-admin 派生路径签发（governance lint 限定 callsite）。
    pub fn issue_for_verified_super_admin() -> Self {
        Self { _seal: () }
    }
}

/// 跨租户可见性 sealed 位置参（私有构造，跨租户 API 必须显式传入此 marker）。
///
/// 持有此值代表调用方已经过平台授权验证（`SuperAdmin` / framework-internal）；
/// 非特权代码路径无构造入口，从类型层杜绝意外跨租户访问（ADR-002）。
pub struct CrossTenantVisibility {
    // 私有 unit 字段，阻止 struct literal 构造
    _priv: (),
}

impl CrossTenantVisibility {
    /// 经 [`CrossTenantCapability`] capability 授权构造跨租户可见性 marker。
    ///
    /// 调用方须持有已签发的 `CrossTenantCapability`（由 authn 校验 super-admin 路径签发）。
    pub fn authorize(_cap: CrossTenantCapability) -> Self {
        // reason: cap 消费即授权——持有 CrossTenantCapability 代表 authn 已校验 super-admin
        Self { _priv: () }
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 RowScope / ScopedTenant Copy enum 可构造、funnel 签名可引用。
    use super::{
        CrossTenantCapability, CrossTenantVisibility, RowScope, RowVisibility, ScopedTenant,
        TenantId,
    };

    #[test]
    fn row_scope_and_visibility_signatures_are_consumable() {
        // RowScope Copy enum 构造
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

        // Finding#13：new 接受 ScopedTenant 而非 RowScope，All 路径从类型层排除
        let _new: fn(ScopedTenant, TenantId) -> RowVisibility = RowVisibility::new;
        let _cross: fn(CrossTenantVisibility) -> RowVisibility = RowVisibility::new_cross_tenant;

        // as_row_scope 签名可绑定
        let _as_scope: fn(ScopedTenant) -> RowScope = ScopedTenant::as_row_scope;

        // F3：CrossTenantCapability funnel 签名可绑定
        // issue_for_verified_super_admin 是受控入口；authorize 消费 capability 构造 marker
        let _issue: fn() -> CrossTenantCapability =
            CrossTenantCapability::issue_for_verified_super_admin;
        let _authorize: fn(CrossTenantCapability) -> CrossTenantVisibility =
            CrossTenantVisibility::authorize;
    }
}

#[cfg(test)]
mod row_visibility_tests {
    use super::{
        CrossTenantCapability, CrossTenantVisibility, RowScope, RowVisibility, ScopedTenant,
        TenantId,
    };

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[allow(clippy::unwrap_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON).unwrap()
    }

    #[test]
    fn scoped_tenant_as_row_scope_all_variants() {
        let cases: &[(ScopedTenant, RowScope)] = &[
            (ScopedTenant::SelfOnly, RowScope::SelfOnly),
            (ScopedTenant::Device, RowScope::Device),
            (ScopedTenant::Tenant, RowScope::Tenant),
        ];
        for (scoped, expected) in cases {
            assert_eq!(scoped.as_row_scope(), *expected, "scoped={scoped:?}");
        }
    }

    #[test]
    fn row_scope_labels_are_stable() {
        let cases: &[(RowScope, &str)] = &[
            (RowScope::SelfOnly, "self-only"),
            (RowScope::Device, "device"),
            (RowScope::Tenant, "tenant"),
            (RowScope::All, "all"),
        ];
        for &(scope, expected) in cases {
            assert_eq!(scope.as_label(), expected, "scope={scope:?}");
        }
    }

    #[test]
    fn row_visibility_new_sets_scope_and_tenant() {
        let tid = tenant();
        let cases: &[ScopedTenant] = &[
            ScopedTenant::SelfOnly,
            ScopedTenant::Device,
            ScopedTenant::Tenant,
        ];
        for scoped in cases {
            let vis = RowVisibility::new(*scoped, tid);
            assert_eq!(vis.scope(), scoped.as_row_scope(), "scoped={scoped:?}");
            assert_eq!(vis.tenant(), Some(tid), "scoped={scoped:?}");
        }
    }

    #[test]
    fn row_visibility_new_cross_tenant_is_all_with_no_tenant() {
        let cap = CrossTenantCapability::issue_for_verified_super_admin();
        let marker = CrossTenantVisibility::authorize(cap);
        let vis = RowVisibility::new_cross_tenant(marker);
        assert_eq!(vis.scope(), RowScope::All);
        assert_eq!(vis.tenant(), None);
    }

    #[test]
    fn cross_tenant_capability_and_visibility_are_constructible() {
        let cap = CrossTenantCapability::issue_for_verified_super_admin();
        let _vis = CrossTenantVisibility::authorize(cap);
        // 消费后能构造 RowVisibility（通过 new_cross_tenant 路径）
        let cap2 = CrossTenantCapability::issue_for_verified_super_admin();
        let marker2 = CrossTenantVisibility::authorize(cap2);
        let vis2 = RowVisibility::new_cross_tenant(marker2);
        assert_eq!(vis2.scope(), RowScope::All);
    }
}

#[cfg(test)]
mod tenant_id {
    //! `TenantId::parse` 表驱动：canonical lowercase-hyphenated 唯一合法形态；
    //! 空 / nil / 非 canonical（大写·simple·braced·urn·含空白）一律 fail-closed（tenancy.md）。
    use super::{TenantId, TenantIdError};

    // 合法 canonical lowercase-hyphenated 基准（RFC 9562 §4）。
    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[test]
    fn parse_rejects_invalid_and_accepts_canonical() {
        // (输入, 期望)；用 `.map(|_| ())` 抹掉 Ok 载荷以表比对（不 unwrap/expect/panic）。
        let cases: &[(&str, Result<(), TenantIdError>)] = &[
            (CANON, Ok(())),
            ("", Err(TenantIdError::Empty)),
            (
                "00000000-0000-0000-0000-000000000000",
                Err(TenantIdError::Nil),
            ),
            ("not-a-uuid", Err(TenantIdError::Format)),
            ("123", Err(TenantIdError::Format)),
            // 非 canonical 表示（大写 / simple / braced / urn / 前导空白）一律 Format——
            // 单一字符串形态杜绝同一 UUID 在 RLS predicate / cache key 上歧义。
            (
                "F47AC10B-58CC-4372-A567-0E02B2C3D479",
                Err(TenantIdError::Format),
            ),
            (
                "f47ac10b58cc4372a5670e02b2c3d479",
                Err(TenantIdError::Format),
            ),
            (
                "{f47ac10b-58cc-4372-a567-0e02b2c3d479}",
                Err(TenantIdError::Format),
            ),
            (
                "urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479",
                Err(TenantIdError::Format),
            ),
            (
                " f47ac10b-58cc-4372-a567-0e02b2c3d479",
                Err(TenantIdError::Format),
            ),
            // 结尾空白 + 混合大小写：同样非 canonical → Format。
            (
                "f47ac10b-58cc-4372-a567-0e02b2c3d479 ",
                Err(TenantIdError::Format),
            ),
            (
                "F47ac10b-58cc-4372-a567-0e02b2c3d479",
                Err(TenantIdError::Format),
            ),
            // 非 canonical 的 nil（simple 全 0）：round-trip 先拒为 Format，非 Nil（见 parse rustdoc 错误优先级）。
            (
                "00000000000000000000000000000000",
                Err(TenantIdError::Format),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                TenantId::parse(input).map(|_| ()),
                *expected,
                "input={input:?}"
            );
        }
    }

    #[test]
    fn as_uuid_round_trips_canonical() {
        // as_uuid 还原的 uuid 重新 canonical 化必须等于输入（无信息丢失）。
        let got = TenantId::parse(CANON).map(|id| id.as_uuid().hyphenated().to_string());
        assert_eq!(got, Ok(CANON.to_string()));
    }

    #[test]
    fn display_outputs_canonical() {
        // Display 输出 canonical lowercase-hyphenated，回灌 parse 仍成功（往返一致）。
        let shown = TenantId::parse(CANON).map(|id| id.to_string());
        assert_eq!(shown, Ok(CANON.to_string()));
    }
}
