//! identity — RSS 身份/RBAC/ABAC 域（值类型与纯逻辑签名冻结）。
//!
//! 本 crate 承载身份域的核心值类型、RBAC/ABAC 纯计算接缝与错误枚举。
//! DI port（repo / store）归 `diport`（ADR-003）。
//! 所有域类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! # 实现状态（部分写实）
//!
//! `domain`（RBAC/ABAC 值类型与纯逻辑）仍**签名冻结**（函数体 = `todo!()`，smoke 只绑函数指针）；
//! `application`（登录接缝：[`LoginService`] / [`IdentityDomain`]）**RW-G1 已写实**——打通 identity
//! 登录 → outbox。余下（authz 纯逻辑、真实 JWT/密码哈希）留 W。`application` 模块私有，只 re-export facade。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/core_api.rs@master（enforce 元组求值）
//! ref: casbin/casbin-rs src/rbac/default_role_manager.rs@master（domain 多租隔离）
//! ref: eclipse-biscuit/biscuit-rust biscuit-auth/src/token/mod.rs@main（pub(crate) 字段 + funnel）

#![forbid(unsafe_code)]

/// 应用层：登录编排 + bootstrap 生命周期（RW-G1 追踪弹）。私有——只经 facade re-export 暴露，
/// 不外泄 tracer 常量 / 内部实现（domain-patterns.md §序列化边界 / 封装）。
mod application;
pub(crate) mod domain;
mod internal;

pub use application::{IdentityDomain, LoginError, LoginService};

// ---------------------------------------------------------------------------
// smoke test（ADR-004 C8 豁免：只绑函数指针 / 构造 Copy enum，不触 todo!() body）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! build smoke：证明签名可被引用消费 + 闭值集 enum 可构造 + Send 约束。
    //! **不调用** `todo!()` body。

    use crate::domain::{
        AbacAttribute, AccountStatus, AttributeKey, AttributeValue, IdentityError, Permission,
        PermissionId, Policy, PolicyId, PolicyRule, ResourcePattern, Role, RoleBinding, RoleId,
        authorize_rbac, evaluate_abac,
    };

    // 证明主要类型是 Send（跨 await 点传播）。
    fn _assert_send<T: Send>() {}

    #[test]
    fn domain_types_are_send() {
        _assert_send::<RoleId>();
        _assert_send::<PermissionId>();
        _assert_send::<PolicyId>();
        _assert_send::<Role>();
        _assert_send::<Permission>();
        _assert_send::<ResourcePattern>();
        _assert_send::<RoleBinding>();
        _assert_send::<AbacAttribute>();
        _assert_send::<AttributeKey>();
        _assert_send::<AttributeValue>();
        _assert_send::<Policy>();
        _assert_send::<PolicyRule>();
    }

    #[test]
    fn account_status_enum_is_constructable_and_exhaustive() {
        let _status: AccountStatus = AccountStatus::Active;

        // 穷尽 match（non_exhaustive crate 内合法穷举）
        match _status {
            AccountStatus::Active => {}
            AccountStatus::Suspended => {}
            AccountStatus::Locked => {}
            AccountStatus::Deactivated => {}
        }
    }

    #[test]
    fn identity_error_enum_is_exhaustive() {
        // 穷尽 match 证明 IdentityError variant 完整（crate 内）
        let e = IdentityError::RoleNotFound;
        match e {
            IdentityError::RoleNotFound => {}
            IdentityError::PermissionDenied => {}
            IdentityError::InvalidPolicy => {}
        }
    }

    #[test]
    fn newtype_fn_signatures_are_consumable() {
        // parse funnel：显式类型标注锁签名（不调用 → 不触 todo!()）
        let _: fn(&str) -> Result<RoleId, crate::domain::IdParseError> = RoleId::parse;
        let _: fn(&str) -> Result<PermissionId, crate::domain::IdParseError> = PermissionId::parse;
        let _: fn(&str) -> Result<PolicyId, crate::domain::IdParseError> = PolicyId::parse;
        let _: fn(&str) -> Result<AttributeKey, crate::domain::AttributeKeyError> =
            AttributeKey::parse;
        let _: fn(&str) -> Result<ResourcePattern, crate::domain::PatternError> =
            ResourcePattern::parse;

        // as_str accessor：显式类型标注锁签名（不调用）
        let _: fn(&RoleId) -> &str = RoleId::as_str;
        let _: fn(&PermissionId) -> &str = PermissionId::as_str;
        let _: fn(&PolicyId) -> &str = PolicyId::as_str;
        let _: fn(&ResourcePattern) -> &str = ResourcePattern::as_str;
        let _: fn(&AttributeKey) -> &str = AttributeKey::as_str;
        let _: fn(&AttributeValue) -> &str = AttributeValue::as_str;

        // Role accessor：显式类型标注锁签名
        let _: fn(&Role) -> &RoleId = Role::id;
        let _: fn(&Role) -> &str = Role::name;
        let _: fn(&Role) -> &[PermissionId] = Role::permissions;

        // Permission accessor
        let _: fn(&Permission) -> &PermissionId = Permission::id;
        let _: fn(&Permission) -> &vocab::Action = Permission::action;
        let _: fn(&Permission) -> &ResourcePattern = Permission::resource_pattern;

        // RoleBinding accessor
        let _: fn(&RoleBinding) -> &str = RoleBinding::subject;
        let _: fn(&RoleBinding) -> &RoleId = RoleBinding::role_id;
        let _: fn(&RoleBinding) -> vocab::TenantId = RoleBinding::tenant;

        // Policy accessor
        let _: fn(&Policy) -> &PolicyId = Policy::id;
        let _: fn(&Policy) -> vocab::TenantId = Policy::tenant;
        let _: fn(&Policy) -> &[PolicyRule] = Policy::rules;

        // PolicyRule accessor
        let _: fn(&PolicyRule) -> &AttributeKey = PolicyRule::attribute_key;
        let _: fn(&PolicyRule) -> &AttributeValue = PolicyRule::expected_value;

        // AbacAttribute accessor
        let _: fn(&AbacAttribute) -> &AttributeKey = AbacAttribute::key;
        let _: fn(&AbacAttribute) -> &AttributeValue = AbacAttribute::value;
    }

    #[test]
    fn pure_logic_fn_signatures_are_consumable() {
        // 绑定自由函数指针（不调用 → 不触 todo!()）
        let _: fn(&authn::Principal, &[RoleBinding], &[Role], &Permission) -> vocab::Decision =
            authorize_rbac;

        // evaluate_abac 新签名：_principal 位参使租户隔离由签名承载（Hard）
        let _: fn(&authn::Principal, &[AbacAttribute], &Policy) -> vocab::Decision = evaluate_abac;
    }

    #[test]
    fn constructor_signatures_are_consumable() {
        // Role / Permission / RoleBinding / Policy 构造器签名可绑定（impl Into<String> 泛型用 String 实例化）
        let _: fn(RoleId, String, Vec<PermissionId>) -> Role = Role::new;
        let _: fn(PermissionId, vocab::Action, ResourcePattern) -> Permission = Permission::new;
        let _: fn(String, RoleId, vocab::TenantId) -> RoleBinding = RoleBinding::new;
        let _: fn(AttributeKey, AttributeValue) -> AbacAttribute = AbacAttribute::new;
        let _: fn(PolicyId, vocab::TenantId, Vec<PolicyRule>) -> Policy = Policy::new;
        let _: fn(AttributeKey, AttributeValue) -> PolicyRule = PolicyRule::new;
        // AttributeValue::new：impl Into<String> 用 String 实例化
        let _: fn(String) -> AttributeValue = AttributeValue::new;
        // RoleId::new / PermissionId::new
        let _: fn(String) -> RoleId = RoleId::new;
        let _: fn(String) -> PermissionId = PermissionId::new;
    }
}
