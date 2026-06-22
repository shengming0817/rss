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

impl AuthPlan {
    /// 由 listener 种类 + 显式 scheme 构造；拒 Internal/Admin 上的 NoAuth（fail-closed，runtime-api.md）。
    pub fn new(_listener: ListenerKind, _scheme: AuthScheme) -> Result<Self, AuthPlanError> {
        todo!()
    }

    /// 显式无认证 plan（`AuthNone`）；仅对外面 listener 合法，Internal/Admin 拒（fail-closed）。
    pub fn none(_listener: ListenerKind) -> Result<Self, AuthPlanError> {
        todo!()
    }

    /// 所属 listener 种类。
    pub fn listener(self) -> ListenerKind {
        todo!()
    }

    /// 认证方案。
    pub fn scheme(self) -> AuthScheme {
        todo!()
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
/// （返回 [`AuthRequirement::Require`] 或 `Deny`，绝不 `Allow`）；opt-out 仅对 `Primary` 等对外
/// listener 生效。纯函数、无 I/O。
///
/// INVARIANT: AUTH-FAILCLOSED-01 —— Internal/Admin listener 上 route opt-out 必须被拒（绝不 Allow）；Medium governance test 随 authn W 行为 PR 落地。
pub fn resolve_requirement(_plan: AuthPlan, _opt_out: Option<RouteAuthOptOut>) -> AuthRequirement {
    todo!()
}
