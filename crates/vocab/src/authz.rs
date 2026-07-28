//! 基础授权词汇。`Action` 保留旧纯逻辑动作 newtype；生产 route/grant 授权走闭值集。

/// `Action` 解析错误。空值 / 非法字符等非法。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ActionError {
    #[error("action is empty")]
    Empty,
    #[error("action has invalid format")]
    Format,
}

/// 授权动作 newtype（私有字段，构造经 fallible funnel）。
///
/// 冻结为可失败构造：未知 / 非法 action 在边界即拒。行为 PR 可在此基础上加 `perm_*()`
/// 闭值集 accessor（additive，非破坏式），故此处不预冻 sealed `Permission` 枚举。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action(String);

impl Action {
    /// 解析授权动作；格式 `domain:verb`（恰一个冒号，两段非空，每段 crate-name 形）。
    ///
    /// 空串 → `Empty`；格式不符 → `Format`。
    pub fn parse(raw: &str) -> Result<Self, ActionError> {
        if raw.is_empty() {
            return Err(ActionError::Empty);
        }
        let (domain, verb) = raw.split_once(':').ok_or(ActionError::Format)?;
        // 确保只有一个冒号：verb 段不得再含 ':'
        if verb.contains(':') {
            return Err(ActionError::Format);
        }
        if !crate::is_crate_name(domain) || !crate::is_crate_name(verb) {
            return Err(ActionError::Format);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Route/grant permission 解析错误。未知 permission 一律 fail-closed。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PermissionParseError {
    #[error("permission is unknown")]
    Unknown,
}

/// durable role grant 中 policy-management grant 的存储前缀。
pub const POLICY_MANAGE_PERMISSION_PREFIX: &str = "identity:policy:manage:";

/// 生产 HTTP route permission 与 audit projection permission 的闭值集。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoutePermissionId {
    AuditRead,
    AuditFieldActor,
    AuditFieldTenantId,
    AuditFieldResourceId,
    IdentityProfileFieldSubject,
    IdentityProfileFieldTenantId,
    IdentityProfileRead,
    IdentityProfileWrite,
    IdentitySessionLogoutCurrent,
    IdentitySessionLogoutAll,
    IdentityRoleAssign,
    IdentityRoleRead,
    IdentityRoleRevoke,
    IdentityPolicyCreate,
    IdentityPolicyRead,
    IdentityPolicyUpdate,
    IdentityPolicyDeactivate,
    RuntimeInventoryRead,
    SettingsConfigPublish,
    SettingsConfigGet,
    SettingsConfigDelete,
    SettingsConfigRollback,
    SettingsSecretPublish,
    SettingsSecretResolve,
    MtlsInvoke,
}

impl RoutePermissionId {
    /// All route permissions in the closed catalog.
    pub const ALL: &'static [Self] = &[
        Self::AuditRead,
        Self::AuditFieldActor,
        Self::AuditFieldTenantId,
        Self::AuditFieldResourceId,
        Self::IdentityProfileFieldSubject,
        Self::IdentityProfileFieldTenantId,
        Self::IdentityProfileRead,
        Self::IdentityProfileWrite,
        Self::IdentitySessionLogoutCurrent,
        Self::IdentitySessionLogoutAll,
        Self::IdentityRoleAssign,
        Self::IdentityRoleRead,
        Self::IdentityRoleRevoke,
        Self::IdentityPolicyCreate,
        Self::IdentityPolicyRead,
        Self::IdentityPolicyUpdate,
        Self::IdentityPolicyDeactivate,
        Self::RuntimeInventoryRead,
        Self::SettingsConfigPublish,
        Self::SettingsConfigGet,
        Self::SettingsConfigDelete,
        Self::SettingsConfigRollback,
        Self::SettingsSecretPublish,
        Self::SettingsSecretResolve,
        Self::MtlsInvoke,
    ];

    /// 解析 wire/storage permission；未知值拒绝。
    pub fn parse(raw: &str) -> Result<Self, PermissionParseError> {
        match raw {
            "audit:read" => Ok(Self::AuditRead),
            "audit:field:actor" => Ok(Self::AuditFieldActor),
            "audit:field:tenant_id" => Ok(Self::AuditFieldTenantId),
            "audit:field:resource_id" => Ok(Self::AuditFieldResourceId),
            "identity:profile:field:subject" => Ok(Self::IdentityProfileFieldSubject),
            "identity:profile:field:tenant_id" => Ok(Self::IdentityProfileFieldTenantId),
            "identity:profile:read" => Ok(Self::IdentityProfileRead),
            "identity:profile:write" => Ok(Self::IdentityProfileWrite),
            "identity:session:logout-current" => Ok(Self::IdentitySessionLogoutCurrent),
            "identity:session:logout-all" => Ok(Self::IdentitySessionLogoutAll),
            "identity:role:assign" => Ok(Self::IdentityRoleAssign),
            "identity:role:read" => Ok(Self::IdentityRoleRead),
            "identity:role:revoke" => Ok(Self::IdentityRoleRevoke),
            "identity:policy:create" => Ok(Self::IdentityPolicyCreate),
            "identity:policy:read" => Ok(Self::IdentityPolicyRead),
            "identity:policy:update" => Ok(Self::IdentityPolicyUpdate),
            "identity:policy:deactivate" => Ok(Self::IdentityPolicyDeactivate),
            "runtime:inventory:read" => Ok(Self::RuntimeInventoryRead),
            "settings.config-publish" => Ok(Self::SettingsConfigPublish),
            "settings.config-get" => Ok(Self::SettingsConfigGet),
            "settings.config-delete" => Ok(Self::SettingsConfigDelete),
            "settings.config-rollback" => Ok(Self::SettingsConfigRollback),
            "settings.secret-publish" => Ok(Self::SettingsSecretPublish),
            "settings.secret-resolve" => Ok(Self::SettingsSecretResolve),
            "mtls:invoke" => Ok(Self::MtlsInvoke),
            _ => Err(PermissionParseError::Unknown),
        }
    }

    /// 稳定 wire/storage 字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuditRead => "audit:read",
            Self::AuditFieldActor => "audit:field:actor",
            Self::AuditFieldTenantId => "audit:field:tenant_id",
            Self::AuditFieldResourceId => "audit:field:resource_id",
            Self::IdentityProfileFieldSubject => "identity:profile:field:subject",
            Self::IdentityProfileFieldTenantId => "identity:profile:field:tenant_id",
            Self::IdentityProfileRead => "identity:profile:read",
            Self::IdentityProfileWrite => "identity:profile:write",
            Self::IdentitySessionLogoutCurrent => "identity:session:logout-current",
            Self::IdentitySessionLogoutAll => "identity:session:logout-all",
            Self::IdentityRoleAssign => "identity:role:assign",
            Self::IdentityRoleRead => "identity:role:read",
            Self::IdentityRoleRevoke => "identity:role:revoke",
            Self::IdentityPolicyCreate => "identity:policy:create",
            Self::IdentityPolicyRead => "identity:policy:read",
            Self::IdentityPolicyUpdate => "identity:policy:update",
            Self::IdentityPolicyDeactivate => "identity:policy:deactivate",
            Self::RuntimeInventoryRead => "runtime:inventory:read",
            Self::SettingsConfigPublish => "settings.config-publish",
            Self::SettingsConfigGet => "settings.config-get",
            Self::SettingsConfigDelete => "settings.config-delete",
            Self::SettingsConfigRollback => "settings.config-rollback",
            Self::SettingsSecretPublish => "settings.secret-publish",
            Self::SettingsSecretResolve => "settings.secret-resolve",
            Self::MtlsInvoke => "mtls:invoke",
        }
    }

    /// Rust path fragment used by code generators.
    pub const fn variant_name(self) -> &'static str {
        match self {
            Self::AuditRead => "AuditRead",
            Self::AuditFieldActor => "AuditFieldActor",
            Self::AuditFieldTenantId => "AuditFieldTenantId",
            Self::AuditFieldResourceId => "AuditFieldResourceId",
            Self::IdentityProfileFieldSubject => "IdentityProfileFieldSubject",
            Self::IdentityProfileFieldTenantId => "IdentityProfileFieldTenantId",
            Self::IdentityProfileRead => "IdentityProfileRead",
            Self::IdentityProfileWrite => "IdentityProfileWrite",
            Self::IdentitySessionLogoutCurrent => "IdentitySessionLogoutCurrent",
            Self::IdentitySessionLogoutAll => "IdentitySessionLogoutAll",
            Self::IdentityRoleAssign => "IdentityRoleAssign",
            Self::IdentityRoleRead => "IdentityRoleRead",
            Self::IdentityRoleRevoke => "IdentityRoleRevoke",
            Self::IdentityPolicyCreate => "IdentityPolicyCreate",
            Self::IdentityPolicyRead => "IdentityPolicyRead",
            Self::IdentityPolicyUpdate => "IdentityPolicyUpdate",
            Self::IdentityPolicyDeactivate => "IdentityPolicyDeactivate",
            Self::RuntimeInventoryRead => "RuntimeInventoryRead",
            Self::SettingsConfigPublish => "SettingsConfigPublish",
            Self::SettingsConfigGet => "SettingsConfigGet",
            Self::SettingsConfigDelete => "SettingsConfigDelete",
            Self::SettingsConfigRollback => "SettingsConfigRollback",
            Self::SettingsSecretPublish => "SettingsSecretPublish",
            Self::SettingsSecretResolve => "SettingsSecretResolve",
            Self::MtlsInvoke => "MtlsInvoke",
        }
    }
}

impl std::fmt::Display for RoutePermissionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// durable role grant permission. Role names are display data; allow/deny compares this typed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantPermission {
    Route(RoutePermissionId),
    PolicyManage(RoutePermissionId),
}

impl GrantPermission {
    /// 解析持久化 role grant；未知 route 或 nested policy-management grant 拒绝。
    pub fn parse(raw: &str) -> Result<Self, PermissionParseError> {
        if let Some(target) = raw.strip_prefix(POLICY_MANAGE_PERMISSION_PREFIX) {
            if target.starts_with(POLICY_MANAGE_PERMISSION_PREFIX) {
                return Err(PermissionParseError::Unknown);
            }
            return RoutePermissionId::parse(target).map(Self::PolicyManage);
        }
        RoutePermissionId::parse(raw).map(Self::Route)
    }

    pub const fn route(permission: RoutePermissionId) -> Self {
        Self::Route(permission)
    }

    pub const fn policy_manage(permission: RoutePermissionId) -> Self {
        Self::PolicyManage(permission)
    }

    pub const fn as_route(self) -> Option<RoutePermissionId> {
        match self {
            Self::Route(permission) => Some(permission),
            Self::PolicyManage(_) => None,
        }
    }

    pub const fn policy_manage_target(self) -> Option<RoutePermissionId> {
        match self {
            Self::Route(_) => None,
            Self::PolicyManage(permission) => Some(permission),
        }
    }

    pub const fn matches_route(self, permission: RoutePermissionId) -> bool {
        match self {
            Self::Route(granted) => granted as u8 == permission as u8,
            Self::PolicyManage(_) => false,
        }
    }

    pub const fn matches_policy_manage(self, permission: RoutePermissionId) -> bool {
        match self {
            Self::Route(_) => false,
            Self::PolicyManage(granted) => granted as u8 == permission as u8,
        }
    }

    /// 持久化/response 输出 helper。内部授权不得反向解析此字符串再比较。
    pub fn to_storage_string(self) -> String {
        match self {
            Self::Route(permission) => permission.as_str().to_string(),
            Self::PolicyManage(permission) => {
                format!("{POLICY_MANAGE_PERMISSION_PREFIX}{}", permission.as_str())
            }
        }
    }
}

impl std::fmt::Display for GrantPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route(permission) => f.write_str(permission.as_str()),
            Self::PolicyManage(permission) => {
                f.write_str(POLICY_MANAGE_PERMISSION_PREFIX)?;
                f.write_str(permission.as_str())
            }
        }
    }
}

/// 授权裁决。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Allow,
    Deny,
}

#[cfg(test)]
mod tests {
    use super::{
        Action, GrantPermission, POLICY_MANAGE_PERMISSION_PREFIX, PermissionParseError,
        RoutePermissionId,
    };

    #[test]
    fn action_accepts_valid_format() {
        let cases: &[&str] = &[
            "foo:bar",
            "identity:read",
            "settings:write",
            "my_domain:my_verb",
            "a:b",
            "abc123:xyz_op",
        ];
        for &raw in cases {
            let result = Action::parse(raw);
            assert!(result.is_ok(), "expected Ok for raw={raw:?}");
            #[allow(clippy::unwrap_used)]
            let action = result.unwrap();
            assert_eq!(action.as_str(), raw);
        }
    }

    #[test]
    fn action_rejects_empty() {
        assert!(
            matches!(Action::parse(""), Err(super::ActionError::Empty)),
            "expected Empty variant"
        );
    }

    #[test]
    fn action_rejects_format_errors() {
        let cases: &[&str] = &[
            "nodomain",    // 无冒号
            "foo:bar:baz", // 两个冒号
            ":verb",       // 空 domain
            "domain:",     // 空 verb
            ":",           // 两段都空
            "Foo:bar",     // domain 首字母大写
            "foo:Bar",     // verb 首字母大写
            "1foo:bar",    // domain 首字母数字
            "foo:1bar",    // verb 首字母数字
            "_foo:bar",    // domain 首字母下划线
            "FOO:BAR",     // 全大写
            "foo bar:baz", // 含空格
            "foo-bar:baz", // 含连字符
        ];
        for &raw in cases {
            assert!(
                matches!(Action::parse(raw), Err(super::ActionError::Format)),
                "expected Format for raw={raw:?}"
            );
        }
    }

    #[test]
    fn route_permission_accepts_catalog_values() {
        let cases = [
            ("audit:read", RoutePermissionId::AuditRead),
            ("audit:field:actor", RoutePermissionId::AuditFieldActor),
            (
                "audit:field:resource_id",
                RoutePermissionId::AuditFieldResourceId,
            ),
            (
                "identity:profile:read",
                RoutePermissionId::IdentityProfileRead,
            ),
            (
                "identity:profile:write",
                RoutePermissionId::IdentityProfileWrite,
            ),
            (
                "identity:session:logout-current",
                RoutePermissionId::IdentitySessionLogoutCurrent,
            ),
            (
                "identity:session:logout-all",
                RoutePermissionId::IdentitySessionLogoutAll,
            ),
            (
                "identity:role:assign",
                RoutePermissionId::IdentityRoleAssign,
            ),
            ("identity:role:read", RoutePermissionId::IdentityRoleRead),
            (
                "identity:role:revoke",
                RoutePermissionId::IdentityRoleRevoke,
            ),
            (
                "identity:policy:create",
                RoutePermissionId::IdentityPolicyCreate,
            ),
            (
                "identity:policy:read",
                RoutePermissionId::IdentityPolicyRead,
            ),
            (
                "identity:policy:update",
                RoutePermissionId::IdentityPolicyUpdate,
            ),
            (
                "identity:policy:deactivate",
                RoutePermissionId::IdentityPolicyDeactivate,
            ),
            (
                "runtime:inventory:read",
                RoutePermissionId::RuntimeInventoryRead,
            ),
            (
                "settings.config-publish",
                RoutePermissionId::SettingsConfigPublish,
            ),
            ("settings.config-get", RoutePermissionId::SettingsConfigGet),
            (
                "settings.config-delete",
                RoutePermissionId::SettingsConfigDelete,
            ),
            (
                "settings.config-rollback",
                RoutePermissionId::SettingsConfigRollback,
            ),
            (
                "settings.secret-publish",
                RoutePermissionId::SettingsSecretPublish,
            ),
            (
                "settings.secret-resolve",
                RoutePermissionId::SettingsSecretResolve,
            ),
            ("mtls:invoke", RoutePermissionId::MtlsInvoke),
        ];
        for (raw, expected) in cases {
            assert_eq!(RoutePermissionId::parse(raw), Ok(expected));
            assert_eq!(expected.as_str(), raw);
        }
        assert!(
            RoutePermissionId::ALL.contains(&RoutePermissionId::RuntimeInventoryRead),
            "runtime inventory permission must remain in the closed catalog"
        );
        assert_eq!(
            RoutePermissionId::RuntimeInventoryRead.variant_name(),
            "RuntimeInventoryRead"
        );
    }

    #[test]
    fn route_permission_rejects_unknown_values() {
        for raw in [
            "",
            "docs:read",
            "other:read",
            "identity:policy:manage:identity:policy:read",
            "audit:field:email",
        ] {
            assert_eq!(
                RoutePermissionId::parse(raw),
                Err(PermissionParseError::Unknown)
            );
        }
    }

    #[test]
    fn grant_permission_accepts_route_and_policy_manage_catalog_values() {
        let target = RoutePermissionId::IdentityPolicyRead;
        assert_eq!(
            GrantPermission::parse(target.as_str()),
            Ok(GrantPermission::Route(target))
        );
        let manage = format!("{POLICY_MANAGE_PERMISSION_PREFIX}{}", target.as_str());
        let grant = GrantPermission::PolicyManage(target);
        assert_eq!(GrantPermission::parse(&manage), Ok(grant));
        assert!(grant.matches_policy_manage(target));
        assert_eq!(grant.to_storage_string(), manage);
    }

    #[test]
    fn grant_permission_rejects_unknown_and_nested_policy_manage() {
        for raw in [
            "docs:read",
            "identity:policy:manage:docs:read",
            "identity:policy:manage:identity:policy:manage:identity:policy:read",
        ] {
            assert_eq!(
                GrantPermission::parse(raw),
                Err(PermissionParseError::Unknown)
            );
        }
    }
}
