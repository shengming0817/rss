//! identity::domain::rbac — RBAC 值类型与授权纯逻辑（dylint rss_domain_no_serialize 守护区）。
//!
//! `Permission` / `Role` / `RoleBinding` + `authorize_rbac`（L0 纯计算，fail-closed）。
//! 共享 newtype（`PermissionId` / `RoleId` / `ResourcePattern`）定义在 `super`（`domain/mod.rs`）。
//!
//! # 对标
//!
//! ref: casbin/casbin-rs src/core_api.rs@master（enforce 元组求值，闭值集 Decision，fail-closed）
//! ref: casbin/casbin-rs src/rbac/default_role_manager.rs@master（多租隔离，域 Role 绑定）

use super::{PermissionId, ResourcePattern, RoleId};

// ---------------------------------------------------------------------------
// Permission — action + resource_pattern
// ---------------------------------------------------------------------------

/// 权限定义：action（`vocab::Action`）+ 资源模式（`ResourcePattern`）。
///
/// 不 derive Serialize——域类型。
// reason: 实现已落地，但生产调用方（handler / authz 接线）待 W 阶段（PR4/PR5）；当前仅测试消费，
// 非 test 构建无调用方 ⇒ 仍 dead，保留 allow 以过 `-D warnings`（ADR-004 C8 遗留期 carve-out）。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Permission {
    id: PermissionId,
    action: vocab::Action,
    resource_pattern: ResourcePattern,
}

// reason: 同 Permission（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl Permission {
    /// 构造权限（位置参，必填；缺失即编译错误）。
    pub(crate) fn new(
        id: PermissionId,
        action: vocab::Action,
        resource_pattern: ResourcePattern,
    ) -> Self {
        Self {
            id,
            action,
            resource_pattern,
        }
    }

    /// 取权限 ID 引用。
    pub(crate) fn id(&self) -> &PermissionId {
        &self.id
    }

    /// 取授权动作引用。
    pub(crate) fn action(&self) -> &vocab::Action {
        &self.action
    }

    /// 取资源模式引用。
    pub(crate) fn resource_pattern(&self) -> &ResourcePattern {
        &self.resource_pattern
    }
}

// ---------------------------------------------------------------------------
// Role — 角色（含权限集）
// ---------------------------------------------------------------------------

/// 角色实体（含权限集；私有字段；不 derive Serialize——域类型）。
///
/// `pub`（ADR-005 Option 2）：作 `ports::RoleRepo` 返回聚合被 adapter 跨 crate 命名；字段私有、构造经
/// `Role::new`（`pub(crate)` funnel）——adapter 可接收/返回 `Role` 但**不可伪造其不变式**。`permissions`
/// 等字段类型仍 `pub(crate)`（`pub struct` + 私有字段不外泄字段类型）。
// reason: 同 Permission（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
#[derive(Debug)]
pub struct Role {
    id: RoleId,
    name: String,
    permissions: Vec<PermissionId>,
}

// reason: 同 Permission（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl Role {
    /// 构造角色（位置参，必填）。
    pub(crate) fn new(id: RoleId, name: impl Into<String>, permissions: Vec<PermissionId>) -> Self {
        Self {
            id,
            name: name.into(),
            permissions,
        }
    }

    /// 取角色 ID 引用。
    pub(crate) fn id(&self) -> &RoleId {
        &self.id
    }

    /// 取角色名引用。
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// 取权限 ID 列表引用。
    pub(crate) fn permissions(&self) -> &[PermissionId] {
        &self.permissions
    }
}

// ---------------------------------------------------------------------------
// RoleBinding — principal <-> role 绑定（含租户）
// ---------------------------------------------------------------------------

/// 角色绑定（principal subject + role + tenant 三元组；私有字段；不 derive Serialize——域类型）。
///
/// 多租隔离：binding 必须带 tenant（对应 casbin domain-aware RBAC）。
///
/// Debug 手写 redacted：subject 可能是 email / username 等 PII，不得原文打印到日志；
/// role_id 和 tenant 非敏感，正常打印。
// reason: 同 Permission（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
pub(crate) struct RoleBinding {
    subject: String,
    role_id: RoleId,
    tenant: vocab::TenantId,
}

impl std::fmt::Debug for RoleBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleBinding")
            .field("subject", &"<redacted>")
            .field("role_id", &self.role_id)
            .field("tenant", &self.tenant)
            .finish()
    }
}

// reason: 同 Permission（生产调用方待 W；当前仅测试消费）。
#[allow(dead_code)]
impl RoleBinding {
    /// 构造角色绑定（subject / role / tenant 必填）。
    pub(crate) fn new(
        subject: impl Into<String>,
        role_id: RoleId,
        tenant: vocab::TenantId,
    ) -> Self {
        Self {
            subject: subject.into(),
            role_id,
            tenant,
        }
    }

    /// 取 subject 引用。
    pub(crate) fn subject(&self) -> &str {
        &self.subject
    }

    /// 取角色 ID 引用。
    pub(crate) fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    /// 取绑定租户。
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tenant
    }
}

// ---------------------------------------------------------------------------
// 非 DI 纯逻辑自由函数（L0 纯计算）
// ---------------------------------------------------------------------------

/// RBAC 授权求值（纯函数，L0；fail-closed 语义）。
///
/// **binding 适用性 = subject 匹配 ∧ tenant 匹配**——一条 `RoleBinding` 只在「属于本 principal
/// （`principal.matches_subject(binding.subject())`）**且**同租（`binding.tenant() == principal.tenant()`）」
/// 时参与求值。subject 维度防同租**横向越权**（同租不同 subject 不得借他人 binding 获权，casbin RBAC-with-domains
/// 的 `g(r.sub, p.sub, r.dom)` 同时匹配 subject + domain，本函数对齐）；tenant 维度防跨租。两者均在函数体内**无条件**
/// 强制——不依赖调用方预过滤 bindings（约定为 Soft，此处上移为 Hard 求值）。
///
/// INVARIANT: IDENTITY-AUTHZ-TENANT-01 — tenant 隔离：实现仅对 `binding.tenant() == principal.tenant()` 的
/// `RoleBinding` 求值；`principal.tenant()` 为 `None`（Service/SuperAdmin 跨租场景）时返回 `Decision::Deny`
/// （通用 RBAC 路径不放行跨租，跨租走独立管理面）。
///
/// fail-closed：principal 无绑定、subject 不匹配、跨租、角色不存在、权限未声明、`principal.tenant()` 为 `None`
/// 时均返回 `Decision::Deny`。
/// （ref: casbin/casbin-rs rbac/default_role_manager.rs 域感知 RBAC + core_api enforce 元组 sub+dom 匹配）
///
/// 权限匹配按 **permission-id 归属**：适用 binding 的角色（`Role.permissions`）含目标 `perm.id()` 即 `Allow`。
/// `perm` 的 `action` / `resource_pattern` 是该权限的身份元数据；签名无独立 resource 入参、`Role` 不持有
/// 完整 `Permission`，故本函数不做资源级 glob 匹配（资源级匹配属后续行为 PR）。
// reason: 实现已落地，但生产调用方（handler / authz 接线）待 W 阶段（PR4/PR5）；当前仅测试消费，
// 非 test 构建无调用方 ⇒ 仍 dead，保留 allow 以过 `-D warnings`（ADR-004 C8 遗留期 carve-out）。
#[allow(dead_code)]
pub(crate) fn authorize_rbac(
    principal: &authn::Principal,
    bindings: &[RoleBinding],
    roles: &[Role],
    perm: &Permission,
) -> vocab::Decision {
    // 无租户主体（Service / SuperAdmin 跨租场景）：通用 RBAC 路径不放行（INVARIANT IDENTITY-AUTHZ-TENANT-01）。
    let Some(tenant) = principal.tenant() else {
        return vocab::Decision::Deny;
    };
    for binding in bindings {
        // binding 适用性：必须既属于本 principal（subject 匹配）又同租；任一不符即跳过
        // （fail-closed，不泄漏存在性）。subject 防同租横向越权、tenant 防跨租。
        if !principal.matches_subject(binding.subject()) || binding.tenant() != tenant {
            continue;
        }
        // 适用 binding：解析其角色，角色权限集含目标权限 id → Allow。
        if let Some(role) = roles.iter().find(|r| r.id() == binding.role_id())
            && role.permissions().contains(perm.id())
        {
            return vocab::Decision::Allow;
        }
    }
    // 无匹配 / 空集 → 默认拒绝。
    vocab::Decision::Deny
}

// ---------------------------------------------------------------------------
// 测试（实体构造 / 访问器 / Debug 脱敏 + authorize_rbac 表驱动 fail-closed）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Permission, Role, RoleBinding, authorize_rbac};
    use crate::domain::{PermissionId, ResourcePattern, RoleId};
    use authn::{Principal, PrincipalKind};
    use rstest::rstest;
    use vocab::Decision;
    use vocab::tenant::TenantId;

    // 两个 canonical UUID：tenant A（principal 所属）/ tenant B（跨租）。
    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[allow(clippy::expect_used)]
    fn tid(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant uuid")
    }

    #[allow(clippy::expect_used)]
    fn action() -> vocab::Action {
        // Action 格式 = `domain:verb`（vocab::Action::parse 约束）。
        vocab::Action::parse("docs:read").expect("valid action")
    }

    #[allow(clippy::expect_used)]
    fn perm(id: &str) -> Permission {
        Permission::new(
            PermissionId::new(id),
            action(),
            ResourcePattern::parse("docs:*").expect("pattern"),
        )
    }

    fn role(id: &str, perms: &[&str]) -> Role {
        Role::new(
            RoleId::new(id),
            "display name",
            perms.iter().map(|p| PermissionId::new(*p)).collect(),
        )
    }

    #[test]
    fn entity_accessors_echo() {
        let p = perm("docs:read");
        assert_eq!(p.id().as_str(), "docs:read");
        assert_eq!(p.resource_pattern().as_str(), "docs:*");
        assert_eq!(p.action(), &action());

        let r = role("admin", &["docs:read", "docs:write"]);
        assert_eq!(r.id().as_str(), "admin");
        assert_eq!(r.name(), "display name");
        assert_eq!(r.permissions().len(), 2);

        let b = RoleBinding::new("alice@corp", RoleId::new("admin"), tid(TENANT_A));
        assert_eq!(b.subject(), "alice@corp");
        assert_eq!(b.role_id().as_str(), "admin");
        assert_eq!(b.tenant(), tid(TENANT_A));
    }

    // RoleBinding Debug 脱敏：subject（PII）隐藏，role_id / tenant 正常打印。
    #[test]
    fn role_binding_debug_redacts_subject() {
        let b = RoleBinding::new("alice@corp", RoleId::new("admin"), tid(TENANT_A));
        let dbg = format!("{b:?}");
        assert!(dbg.contains("<redacted>"), "subject 必须脱敏: {dbg}");
        assert!(!dbg.contains("alice@corp"), "Debug 不得泄露 subject 明文");
        assert!(dbg.contains("admin"), "role_id 非敏感，正常打印");
    }

    /// authorize_rbac 场景（表驱动）。
    enum Scenario {
        /// 同租 binding + 角色含目标权限 → Allow。
        SameTenantGranted,
        /// 跨租 binding（tenant B）与同租 granting binding（tenant A）并存 → Allow：
        /// 验证跨租 binding 被 `continue` 跳过而**不阻断**同租放行（INVARIANT 核心路径）。
        MixedTenantGranted,
        /// 仅跨租 binding（tenant B），principal 在 tenant A → Deny（INVARIANT）。
        CrossTenantOnly,
        /// 空 binding 集 → Deny。
        EmptyBindings,
        /// 同租 binding 但角色不含该权限 → Deny。
        RoleLacksPerm,
        /// 同租 binding 的 role_id 不在 roles 集 → Deny。
        BindingRoleNotFound,
        /// 同租**不同 subject** 的 binding（subject=bob，principal=alice，同 tenant A）→ Deny：
        /// 防同租横向越权——binding 必须属于本 principal（subject 匹配），不止 tenant 匹配。
        DifferentSubjectSameTenant,
        /// principal 无 tenant（SuperAdmin 跨租主体）→ Deny。
        SuperAdminNoTenant,
        /// principal 无 tenant（Service 服务账号）→ Deny：INVARIANT 覆盖**全部** None 主体，
        /// 不止 SuperAdmin。
        ServiceNoTenant,
    }

    fn build(scn: &Scenario) -> (Principal, Vec<RoleBinding>, Vec<Role>, Permission) {
        let target = perm("docs:read");
        let granting_role = role("admin", &["docs:read"]);
        let bind_a = || RoleBinding::new("alice", RoleId::new("admin"), tid(TENANT_A));
        let bind_b = || RoleBinding::new("alice", RoleId::new("admin"), tid(TENANT_B));
        let user = |t: Option<&str>| {
            authn::test_support::principal(PrincipalKind::User, "alice", t.map(tid))
        };
        // 无租户主体（tenant=None）构造器：kind 可换（SuperAdmin / Service），均应 Deny。
        let no_tenant = |kind| authn::test_support::principal(kind, "subj", None);
        match scn {
            Scenario::SameTenantGranted => (
                user(Some(TENANT_A)),
                vec![bind_a()],
                vec![granting_role],
                target,
            ),
            // 跨租 binding 在前、同租 granting binding 在后：跨租被 continue 跳过，同租放行。
            Scenario::MixedTenantGranted => (
                user(Some(TENANT_A)),
                vec![bind_b(), bind_a()],
                vec![granting_role],
                target,
            ),
            Scenario::CrossTenantOnly => (
                user(Some(TENANT_A)),
                vec![bind_b()],
                vec![granting_role],
                target,
            ),
            Scenario::EmptyBindings => (user(Some(TENANT_A)), vec![], vec![granting_role], target),
            Scenario::RoleLacksPerm => (
                user(Some(TENANT_A)),
                vec![bind_a()],
                vec![role("admin", &["docs:write"])], // 不含 docs:read
                target,
            ),
            Scenario::BindingRoleNotFound => (
                user(Some(TENANT_A)),
                vec![bind_a()],
                vec![role("other", &["docs:read"])], // role_id 不匹配 binding
                target,
            ),
            // 同 tenant A、但 binding.subject="bob" ≠ principal.subject="alice"：subject 不匹配 → Deny。
            Scenario::DifferentSubjectSameTenant => (
                user(Some(TENANT_A)),
                vec![RoleBinding::new("bob", RoleId::new("admin"), tid(TENANT_A))],
                vec![granting_role],
                target,
            ),
            // tenant=None 主体（SuperAdmin / Service）：通用 RBAC 路径不放行（INVARIANT）。
            Scenario::SuperAdminNoTenant => (
                no_tenant(PrincipalKind::SuperAdmin),
                vec![bind_a()],
                vec![granting_role],
                target,
            ),
            Scenario::ServiceNoTenant => (
                no_tenant(PrincipalKind::Service),
                vec![bind_a()],
                vec![granting_role],
                target,
            ),
        }
    }

    #[rstest]
    #[case::same_tenant_allow(Scenario::SameTenantGranted, Decision::Allow)]
    #[case::mixed_tenant_allow(Scenario::MixedTenantGranted, Decision::Allow)]
    #[case::cross_tenant_deny(Scenario::CrossTenantOnly, Decision::Deny)]
    #[case::empty_bindings_deny(Scenario::EmptyBindings, Decision::Deny)]
    #[case::role_lacks_perm_deny(Scenario::RoleLacksPerm, Decision::Deny)]
    #[case::binding_role_not_found_deny(Scenario::BindingRoleNotFound, Decision::Deny)]
    #[case::different_subject_same_tenant_deny(
        Scenario::DifferentSubjectSameTenant,
        Decision::Deny
    )]
    #[case::super_admin_no_tenant_deny(Scenario::SuperAdminNoTenant, Decision::Deny)]
    #[case::service_no_tenant_deny(Scenario::ServiceNoTenant, Decision::Deny)]
    fn authorize_rbac_cases(#[case] scn: Scenario, #[case] want: Decision) {
        let (principal, bindings, roles, target) = build(&scn);
        assert_eq!(authorize_rbac(&principal, &bindings, &roles, &target), want);
    }
}
