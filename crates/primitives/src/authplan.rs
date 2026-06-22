//! Auth plan 纯值类型 / scheme 闭值集（`runtime-api.md` §Listener / §Auth plan 优先级）。
//!
//! 仅纯数据 + 纯决策计算。PDP / 会话 / Principal / jwt 在 `authn`（service 层）。
//! 下游 `authn`（PR-3）引 `primitives::authplan`。域 crate 禁构造 `AuthPlan`——组合根经 bootstrap option 注入。

/// listener 认证方案（闭值集；Copy）。
///
/// `NoAuth` variant = 显式无认证（`AuthNone`）；与「未配置」从类型层区分——listener 构造器必填 plan，
/// 缺省（Rust `Option::None`）是配置错误（runtime-api.md §Listener）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthScheme {
    /// 显式无认证（`AuthNone`；与「未配置」从类型层区分）。
    NoAuth,
    Jwt,
    Mtls,
    ServiceToken,
    /// 从组合根装配注入的 JWT 校验器。
    JwtFromAssembly,
}

/// 标准 listener 种类（闭值集；决定 route-level opt-out 是否可降级）。runtime-api.md §Listener。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListenerKind {
    Primary,
    Internal,
    Health,
    Admin,
}

/// route-level 认证 opt-out（优先级 1；仅对外面 listener 生效，runtime-api.md §Auth plan 优先级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteAuthOptOut {
    /// 公开 route（无需认证）。
    Public,
    /// 免密码重置门槛。
    PasswordResetExempt,
}

/// `AuthPlan` 构造错误（fail-closed）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthPlanError {
    #[error("control-plane listener (internal/admin) cannot use no-auth")]
    NoAuthOnControlPlane,
}

/// listener 的 auth plan（纯值；单 listener 单 scheme，runtime-api.md §Listener）。
///
/// invariant：plan 必有显式 scheme（`AuthScheme::NoAuth` 表「显式无认证」，非缺省）。
/// 构造经 funnel——域 crate 不应直接 mint（runtime-api.md：组合根注入）。
/// Internal / Admin listener 上禁用 NoAuth（fail-closed，runtime-api.md §Auth plan 优先级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPlan {
    listener: ListenerKind,
    scheme: AuthScheme,
}

/// 判断 listener 是否为控制面（Internal / Admin）。
fn is_control_plane(listener: ListenerKind) -> bool {
    matches!(listener, ListenerKind::Internal | ListenerKind::Admin)
}

/// 将 `AuthScheme` 映射到 `RequiredScheme`；`NoAuth` 返回 `None`（无认证要求）。
fn require_scheme(scheme: AuthScheme) -> Option<RequiredScheme> {
    match scheme {
        AuthScheme::Jwt => Some(RequiredScheme::Jwt),
        AuthScheme::Mtls => Some(RequiredScheme::Mtls),
        AuthScheme::ServiceToken => Some(RequiredScheme::ServiceToken),
        AuthScheme::JwtFromAssembly => Some(RequiredScheme::JwtFromAssembly),
        AuthScheme::NoAuth => None,
    }
}

impl AuthPlan {
    /// 由 listener 种类 + 显式 scheme 构造；拒 Internal/Admin 上的 NoAuth（fail-closed，runtime-api.md）。
    pub fn new(listener: ListenerKind, scheme: AuthScheme) -> Result<Self, AuthPlanError> {
        if is_control_plane(listener) && scheme == AuthScheme::NoAuth {
            return Err(AuthPlanError::NoAuthOnControlPlane);
        }
        Ok(Self { listener, scheme })
    }

    /// 显式无认证 plan（`AuthNone`）；仅对外面 listener 合法，Internal/Admin 拒（fail-closed）。
    pub fn none(listener: ListenerKind) -> Result<Self, AuthPlanError> {
        Self::new(listener, AuthScheme::NoAuth)
    }

    /// 所属 listener 种类。
    pub fn listener(self) -> ListenerKind {
        self.listener
    }

    /// 认证方案。
    pub fn scheme(self) -> AuthScheme {
        self.scheme
    }
}

/// 需认证的方案（`AuthScheme` 排除 `NoAuth` 的子集；类型层杜绝「要求无认证」自相矛盾）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequiredScheme {
    Jwt,
    Mtls,
    ServiceToken,
    JwtFromAssembly,
}

/// 最终认证裁决（纯值；优先级求值结果）。runtime-api.md §Auth plan 优先级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthRequirement {
    /// 放行（route 显式 opt-out 命中且 listener 允许降级）。
    Allow,
    /// 需按方案认证（不含 NoAuth，类型层杜绝「要求无认证」自相矛盾）。
    Require(RequiredScheme),
    /// fail-fast 默认拒（无 plan、或 internal/admin 上的非法 opt-out）。
    Deny,
}

/// 纯决策：按优先级（route opt-out → listener plan → fail-fast deny）算最终认证要求。
///
/// fail-closed（runtime-api.md）：`Internal` / `Admin` listener 上的 route opt-out 必须被拒
/// ——返回 [`AuthRequirement::Deny`]（非法配置，直接拒整条路由，绝不 Allow 或 Require 降级）；
/// opt-out 仅对 `Primary` 等对外 listener 生效，产生 [`AuthRequirement::Allow`]。
/// 无 opt-out 时：`NoAuth` scheme → `Allow`；其余 scheme → `Require`。纯函数、无 I/O。
///
/// INVARIANT: AUTH-FAILCLOSED-01 —— Internal/Admin listener 上 route opt-out 必须返回 `Deny`（绝不 Allow）；Medium governance test 随 authn W 行为 PR 落地。
pub fn resolve_requirement(plan: AuthPlan, opt_out: Option<RouteAuthOptOut>) -> AuthRequirement {
    match opt_out {
        Some(_) => {
            if is_control_plane(plan.listener) {
                // 红线：控制面 listener 上的 opt-out 是非法配置，fail-fast 拒整条路由（绝不降级）。
                AuthRequirement::Deny
            } else {
                // 对外面 listener（Primary / Health）允许 opt-out 降级。
                AuthRequirement::Allow
            }
        }
        None => match require_scheme(plan.scheme) {
            Some(s) => AuthRequirement::Require(s),
            None => AuthRequirement::Allow, // NoAuth scheme：无需认证
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AuthPlan::new ─────────────────────────────────────────────────────────
    #[test]
    fn auth_plan_new_primary_no_auth_ok() {
        #[allow(clippy::unwrap_used)]
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::NoAuth).unwrap();
        assert_eq!(plan.listener(), ListenerKind::Primary);
        assert_eq!(plan.scheme(), AuthScheme::NoAuth);
    }

    #[test]
    fn auth_plan_new_health_no_auth_ok() {
        assert!(AuthPlan::new(ListenerKind::Health, AuthScheme::NoAuth).is_ok());
    }

    #[test]
    fn auth_plan_new_internal_no_auth_err() {
        assert!(matches!(
            AuthPlan::new(ListenerKind::Internal, AuthScheme::NoAuth),
            Err(AuthPlanError::NoAuthOnControlPlane)
        ));
    }

    #[test]
    fn auth_plan_new_admin_no_auth_err() {
        assert!(matches!(
            AuthPlan::new(ListenerKind::Admin, AuthScheme::NoAuth),
            Err(AuthPlanError::NoAuthOnControlPlane)
        ));
    }

    #[test]
    fn auth_plan_new_internal_jwt_ok() {
        assert!(AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).is_ok());
    }

    #[test]
    fn auth_plan_none_primary_ok() {
        assert!(AuthPlan::none(ListenerKind::Primary).is_ok());
    }

    #[test]
    fn auth_plan_none_internal_err() {
        assert!(matches!(
            AuthPlan::none(ListenerKind::Internal),
            Err(AuthPlanError::NoAuthOnControlPlane)
        ));
    }

    // ── resolve_requirement ───────────────────────────────────────────────────

    fn primary_jwt_plan() -> AuthPlan {
        #[allow(clippy::unwrap_used)]
        AuthPlan::new(ListenerKind::Primary, AuthScheme::Jwt).unwrap()
    }

    fn primary_no_auth_plan() -> AuthPlan {
        #[allow(clippy::unwrap_used)]
        AuthPlan::new(ListenerKind::Primary, AuthScheme::NoAuth).unwrap()
    }

    fn internal_service_token_plan() -> AuthPlan {
        #[allow(clippy::unwrap_used)]
        AuthPlan::new(ListenerKind::Internal, AuthScheme::ServiceToken).unwrap()
    }

    fn admin_jwt_plan() -> AuthPlan {
        #[allow(clippy::unwrap_used)]
        AuthPlan::new(ListenerKind::Admin, AuthScheme::Jwt).unwrap()
    }

    // Primary + Public opt-out → Allow
    #[test]
    fn resolve_primary_public_opt_out_allows() {
        let req = resolve_requirement(primary_jwt_plan(), Some(RouteAuthOptOut::Public));
        assert_eq!(req, AuthRequirement::Allow);
    }

    // Primary + PasswordResetExempt opt-out → Allow
    #[test]
    fn resolve_primary_password_reset_exempt_allows() {
        let req = resolve_requirement(
            primary_jwt_plan(),
            Some(RouteAuthOptOut::PasswordResetExempt),
        );
        assert_eq!(req, AuthRequirement::Allow);
    }

    // Internal + opt-out → Deny（控制面 opt-out 是非法配置，fail-fast 拒整条路由）
    #[test]
    fn resolve_internal_opt_out_is_deny() {
        let req = resolve_requirement(internal_service_token_plan(), Some(RouteAuthOptOut::Public));
        assert_eq!(req, AuthRequirement::Deny);
    }

    // Admin + opt-out → Deny（控制面 opt-out 是非法配置，fail-fast 拒整条路由）
    #[test]
    fn resolve_admin_opt_out_is_deny() {
        let req = resolve_requirement(admin_jwt_plan(), Some(RouteAuthOptOut::Public));
        assert_eq!(req, AuthRequirement::Deny);
    }

    // No opt-out + NoAuth scheme → Allow
    #[test]
    fn resolve_no_opt_out_no_auth_scheme_allows() {
        let req = resolve_requirement(primary_no_auth_plan(), None);
        assert_eq!(req, AuthRequirement::Allow);
    }

    // No opt-out + JWT scheme → Require(Jwt)
    #[test]
    fn resolve_no_opt_out_jwt_scheme_requires() {
        let req = resolve_requirement(primary_jwt_plan(), None);
        assert_eq!(req, AuthRequirement::Require(RequiredScheme::Jwt));
    }

    // No opt-out + ServiceToken → Require(ServiceToken)
    #[test]
    fn resolve_no_opt_out_service_token_requires() {
        let req = resolve_requirement(internal_service_token_plan(), None);
        assert_eq!(req, AuthRequirement::Require(RequiredScheme::ServiceToken));
    }

    // No opt-out + Mtls → Require(Mtls)
    #[test]
    fn resolve_no_opt_out_mtls_requires() {
        #[allow(clippy::unwrap_used)]
        let plan = AuthPlan::new(ListenerKind::Internal, AuthScheme::Mtls).unwrap();
        let req = resolve_requirement(plan, None);
        assert_eq!(req, AuthRequirement::Require(RequiredScheme::Mtls));
    }

    // No opt-out + JwtFromAssembly → Require(JwtFromAssembly)
    #[test]
    fn resolve_no_opt_out_jwt_from_assembly_requires() {
        #[allow(clippy::unwrap_used)]
        let plan = AuthPlan::new(ListenerKind::Primary, AuthScheme::JwtFromAssembly).unwrap();
        let req = resolve_requirement(plan, None);
        assert_eq!(
            req,
            AuthRequirement::Require(RequiredScheme::JwtFromAssembly)
        );
    }

    // Health listener + opt-out → Allow (not control plane)
    #[test]
    fn resolve_health_opt_out_allows() {
        #[allow(clippy::unwrap_used)]
        let plan = AuthPlan::new(ListenerKind::Health, AuthScheme::NoAuth).unwrap();
        let req = resolve_requirement(plan, Some(RouteAuthOptOut::Public));
        assert_eq!(req, AuthRequirement::Allow);
    }
}
