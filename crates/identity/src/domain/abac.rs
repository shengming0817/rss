//! identity::domain::abac — ABAC 属性 / 策略值类型与策略求值（dylint rss_domain_no_serialize 守护区）。
//!
//! `AbacAttribute` / `PolicyRule` / `Policy` + `evaluate_abac`（L0 纯计算，fail-closed）。
//! 共享 newtype（`AttributeKey` / `AttributeValue` / `PolicyId`）定义在 `super`（`domain/mod.rs`）。
//!
//! # 实现状态
//!
//! 本模块（ABAC 求值）仍**签名冻结**（函数体 = `todo!()`），行为实现留 PR2（spec 003 US2）。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/core_api.rs@master（enforce 元组求值，全部满足才 Allow）

use super::{AttributeKey, AttributeValue, PolicyId};

// ---------------------------------------------------------------------------
// ABAC 属性
// ---------------------------------------------------------------------------

/// ABAC 属性（key-value 对；不 derive Serialize——域类型）。
// reason: 签名冻结期所有方法尚无调用方，dead_code 来自冻结期（ADR-004 C8）；行为实现待 PR2。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct AbacAttribute {
    key: AttributeKey,
    value: AttributeValue,
}

// reason: 同上（ADR-004 C8；PR2 实现）。
#[allow(dead_code)]
impl AbacAttribute {
    /// 构造 ABAC 属性。
    pub(crate) fn new(_key: AttributeKey, _value: AttributeValue) -> Self {
        todo!()
    }

    /// 取属性键引用。
    pub(crate) fn key(&self) -> &AttributeKey {
        todo!()
    }

    /// 取属性值引用。
    pub(crate) fn value(&self) -> &AttributeValue {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// Policy / PolicyRule — ABAC 策略
// ---------------------------------------------------------------------------

/// 策略规则（条件表达式；不 derive Serialize——域类型）。
///
/// 单条规则：属性键 + 期望值 → 匹配则贡献 Allow；
/// 缺失属性 fail-closed（贡献 Deny）。
// reason: 同上（ADR-004 C8；PR2 实现）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct PolicyRule {
    attribute_key: AttributeKey,
    expected_value: AttributeValue,
}

// reason: 同上（ADR-004 C8；PR2 实现）。
#[allow(dead_code)]
impl PolicyRule {
    /// 构造策略规则（期望值匹配时允许）。
    pub(crate) fn new(_attribute_key: AttributeKey, _expected_value: AttributeValue) -> Self {
        todo!()
    }

    /// 取属性键引用。
    pub(crate) fn attribute_key(&self) -> &AttributeKey {
        todo!()
    }

    /// 取期望值引用。
    pub(crate) fn expected_value(&self) -> &AttributeValue {
        todo!()
    }
}

/// ABAC 策略（规则集；全部规则满足才 Allow，否则 Deny；不 derive Serialize——域类型）。
///
/// fail-closed 语义：空规则集或规则缺失属性均返回 `Decision::Deny`。
/// 多租隔离：策略必须归属租户（对标 `RoleBinding.tenant`）。
// reason: 同上（ADR-004 C8；PR2 实现）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Policy {
    id: PolicyId,
    tenant: vocab::TenantId,
    rules: Vec<PolicyRule>,
}

// reason: 同上（ADR-004 C8；PR2 实现）。
#[allow(dead_code)]
impl Policy {
    /// 构造策略（id + tenant + 规则集，必填）。
    pub(crate) fn new(_id: PolicyId, _tenant: vocab::TenantId, _rules: Vec<PolicyRule>) -> Self {
        todo!()
    }

    /// 取策略 ID 引用。
    pub(crate) fn id(&self) -> &PolicyId {
        todo!()
    }

    /// 取绑定租户。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        todo!()
    }

    /// 取规则列表引用。
    pub(crate) fn rules(&self) -> &[PolicyRule] {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// 非 DI 纯逻辑自由函数（L0 纯计算；body = todo!()，PR2 实现）
// ---------------------------------------------------------------------------

/// ABAC 策略求值（纯函数，L0；fail-closed 语义）。
///
/// INVARIANT: IDENTITY-AUTHZ-TENANT-01 — 实现仅对 `_policy.tenant() == _principal.tenant()`
/// 的策略求值；`_principal.tenant()` 为 `None`（Service/SuperAdmin 跨租场景）时返回
/// `Decision::Deny`（通用 ABAC 路径不放行跨租，跨租走独立管理面）。
///
/// 与 `rbac::authorize_rbac` **共用同一 INVARIANT ID**（有意）：两者是「仅同租记录参与求值 +
/// `principal.tenant()==None` → Deny」的两个实例——RBAC 按 `binding.tenant`、ABAC 按 `policy.tenant`，
/// 租户隔离语义等价，故同 ID 而非另起 -02。
///
/// 签名与 `rbac::authorize_rbac` 对称：`_principal` 位参使「跨租 mismatch fail-closed」由签名承载
/// （Hard），而非依赖调用方约定（Soft）。
///
/// fail-closed：空策略、缺失属性、规则不匹配、`_principal.tenant()` 为 `None` 时均返回
/// `Decision::Deny`。全部规则满足才返回 `Decision::Allow`
/// （ref: casbin/casbin-rs core_api.rs enforce 元组求值）。
///
/// 函数体 = `todo!()` 直至行为 PR（PR2，spec 003 US2）。
// reason: 签名冻结期函数尚无调用方，dead_code 来自冻结期（ADR-004 C8）；行为实现待 PR2。
#[allow(dead_code)]
pub(crate) fn evaluate_abac(
    _principal: &authn::Principal,
    _attrs: &[AbacAttribute],
    _policy: &Policy,
) -> vocab::Decision {
    todo!()
}
