//! authn — RSS 认证主体词汇（Principal / Session / JWT / token 值类型）。
//!
//! 本 crate 承载认证侧的核心值类型与错误枚举；DI port（PDP / session store）归 `diport`（ADR-003）。
//! 所有类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 本 crate 当前只冻结签名（函数体 = `todo!()`）；smoke test 只绑函数指针 / 构造 Copy enum，
//! 不执行任何 `todo!()` body。

#![forbid(unsafe_code)]

use primitives::authplan::{AuthPlan, AuthRequirement, RouteAuthOptOut, resolve_requirement};

// reason: 确保 authplan 符号被引用，防止 cargo-udeps 误报未使用依赖（ADR-004 C8）。
#[allow(dead_code)]
const _: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;

// ---------------------------------------------------------------------------
// 主体类别
// ---------------------------------------------------------------------------

/// 认证主体类别（驱动 [`vocab::RowScope`] 派生；闭值集，fail-closed）。
///
/// `Service` / `Anonymous` 派生为受限 RowScope（见 `docs/rules/tenancy.md`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrincipalKind {
    /// 普通终端用户。
    User,
    /// 设备主体（MDM 管理设备，L4 场景）。
    Device,
    /// 管理员（域级）。
    Admin,
    /// 超管（跨租户，仅平台授权层可造）。
    SuperAdmin,
    /// 服务账号（内部服务间 token）。
    Service,
    /// 匿名访客（fail-closed：RowScope 受限，不得升级权限）。
    Anonymous,
}

// ---------------------------------------------------------------------------
// 认证主体
// ---------------------------------------------------------------------------

/// 认证主体（私有字段；经构造 funnel；不 derive `Serialize`——非 wire 类型）。
///
/// `row_visibility` 从已认证 principal + ctx 派生行级可见域（ADR-002）。
// reason: 签名冻结期字段已声明但 body 全为 todo!()，dead_code 来自冻结期，非 API 漂移（ADR-004 C8）。
#[allow(dead_code)]
pub struct Principal {
    kind: PrincipalKind,
    /// subject 标识（内部，不入 wire）。
    subject: String,
    /// 所属租户（`None` 仅限 `Service` / `SuperAdmin` 跨租户场景）。
    tenant: Option<vocab::TenantId>,
}

impl Principal {
    /// 由已校验 JWT 派生（认证边界唯一入口）。
    ///
    /// `kind` / `tenant` 从已验证 claims 派生；外部 crate 无法构造特权主体（ADR-001）。
    pub fn from_verified_jwt(_jwt: &Jwt) -> Result<Self, AuthnError> {
        todo!()
    }

    /// 由已校验 service-token 派生（service caller 入口）。
    ///
    /// 仅限服务间内部调用路径；caller 必须持有已校验 `AccessToken`（ADR-001）。
    pub fn from_verified_service_token(_token: &AccessToken) -> Result<Self, AuthnError> {
        todo!()
    }

    /// 测试专用构造（不进生产/wire 路径）。
    #[cfg(test)]
    pub(crate) fn for_test(
        _kind: PrincipalKind,
        _subject: impl Into<String>,
        _tenant: Option<vocab::TenantId>,
    ) -> Self {
        todo!()
    }

    /// 返回主体类别。
    pub fn kind(&self) -> PrincipalKind {
        todo!()
    }

    /// 返回所属租户（跨租户 principal 为 `None`）。
    pub fn tenant(&self) -> Option<vocab::TenantId> {
        todo!()
    }

    /// 从 principal + 请求 ctx 派生行级可见性义务（ADR-002）。
    ///
    /// `ctx` 类型为 `runctx::AppCtx`，即 `runctx::RequestCtx<vocab::tenant::TenantId, PrincipalSlot>`
    /// 别名，遵循 ADR-002 显式传 `&RequestCtx` 而非隐式线程局部的原则。
    /// ctx 缺失 fail-closed（返回 [`runctx::MissingCtx`]，绝不伪造 RowScope）。
    pub fn row_visibility(
        &self,
        _ctx: &runctx::AppCtx,
    ) -> Result<vocab::RowVisibility, runctx::MissingCtx> {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// JWT / token / session 值类型
// ---------------------------------------------------------------------------

/// JWT 原始令牌（私有字段；不 derive `Serialize`；构造经 fallible funnel）。
// reason: 签名冻结期 newtype 内容未读，todo!() body 不写读操作（ADR-004 C8）。
#[allow(dead_code)]
pub struct Jwt(String);

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jwt(<redacted>)")
    }
}

impl Jwt {
    /// 解析并做基础结构验证（签名验证由 PDP 负责）。
    pub fn parse(_raw: &str) -> Result<Self, AuthnError> {
        todo!()
    }

    /// 取令牌字符串引用（只读，不 clone）。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 访问令牌 newtype（私有内容；构造经 funnel；不 derive `Serialize`）。
// reason: 同 Jwt（ADR-004 C8 签名冻结期）。
#[allow(dead_code)]
pub struct AccessToken(String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessToken(<redacted>)")
    }
}

impl AccessToken {
    /// 构造访问令牌（来自认证流程输出，非直接 parse）。
    pub fn new(_raw: impl Into<String>) -> Self {
        todo!()
    }

    /// 取令牌字符串引用。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 刷新令牌 newtype（私有内容；不 derive `Serialize`）。
// reason: 同 Jwt（ADR-004 C8 签名冻结期）。
#[allow(dead_code)]
pub struct RefreshToken(String);

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshToken(<redacted>)")
    }
}

impl RefreshToken {
    /// 构造刷新令牌。
    pub fn new(_raw: impl Into<String>) -> Self {
        todo!()
    }

    /// 取令牌字符串引用。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 会话 ID newtype（私有内容；不 derive `Serialize`）。
// reason: 同 Jwt（ADR-004 C8 签名冻结期）。
#[allow(dead_code)]
pub struct SessionId(String);

impl SessionId {
    /// 生成新会话 ID（实现时使用 `ids` / `secure` crate 生成随机值）。
    pub fn generate() -> Self {
        todo!()
    }

    /// 取 ID 字符串引用。
    pub fn as_str(&self) -> &str {
        todo!()
    }
}

/// 会话快照（私有字段；不 derive `Serialize`；构造经位置参 funnel）。
// reason: 签名冻结期字段已声明但 body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub struct Session {
    id: SessionId,
    principal: Principal,
    /// 会话到期时间（与 deviceloop CertLifecycleState 的 SystemTime 类型一致）。
    expires_at: std::time::SystemTime,
}

impl Session {
    /// 构造会话（`expires_at` 来自时钟注入，不在此取系统时间）。
    pub fn new(_id: SessionId, _principal: Principal, _expires_at: std::time::SystemTime) -> Self {
        todo!()
    }

    /// 取会话 ID 引用。
    pub fn id(&self) -> &SessionId {
        todo!()
    }

    /// 取 principal 引用。
    pub fn principal(&self) -> &Principal {
        todo!()
    }

    /// 取到期时间。
    pub fn expires_at(&self) -> std::time::SystemTime {
        todo!()
    }
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// 认证层错误（库枚举；用 `thiserror`；message 为 const 静态字面量）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthnError {
    #[error("token is invalid")]
    TokenInvalid,
    #[error("token is expired")]
    TokenExpired,
    #[error("session not found")]
    SessionNotFound,
    #[error("principal not permitted")]
    Forbidden,
}

// ---------------------------------------------------------------------------
// smoke test（ADR-004 C8 豁免：只绑函数指针 / 构造 Copy enum，不触 todo!() body）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod smoke {
    //! build smoke：证明签名可被引用消费 + 闭值集 enum 可构造 + Send 约束。
    //! **不调用** `todo!()` body。

    use super::{
        AccessToken, AuthnError, Jwt, Principal, PrincipalKind, RefreshToken, Session, SessionId,
    };
    use vocab::TenantId;

    // 证明 Principal / Session 是 Send（跨 await 点传播）。
    fn _assert_send<T: Send>() {}

    #[test]
    fn principal_and_session_are_send() {
        _assert_send::<Principal>();
        _assert_send::<Session>();
    }

    #[test]
    fn principal_kind_enum_is_constructable_and_exhaustive() {
        let _kind: PrincipalKind = PrincipalKind::Device;

        // 穷尽 match（non_exhaustive crate 内合法穷举）
        match _kind {
            PrincipalKind::User => {}
            PrincipalKind::Device => {}
            PrincipalKind::Admin => {}
            PrincipalKind::SuperAdmin => {}
            PrincipalKind::Service => {}
            PrincipalKind::Anonymous => {}
        }
    }

    #[test]
    fn authn_error_enum_is_exhaustive() {
        // 穷尽 match 证明 AuthnError variant 完整（crate 内）
        let e = AuthnError::TokenInvalid;
        match e {
            AuthnError::TokenInvalid => {}
            AuthnError::TokenExpired => {}
            AuthnError::SessionNotFound => {}
            AuthnError::Forbidden => {}
        }
    }

    #[test]
    fn value_type_fn_signatures_are_consumable() {
        // 绑定函数指针（不调用 → 不触 todo!()）
        let _parse: fn(&str) -> Result<Jwt, super::AuthnError> = Jwt::parse;
        let _gen: fn() -> SessionId = SessionId::generate;

        // row_visibility 签名：绑定 fn item（方法指针需指定类型）
        let _row_vis = Principal::row_visibility;
        let _ = _row_vis; // 使用绑定，避免 unused 警告
    }

    #[test]
    fn constructor_signatures_are_consumable() {
        // 绑定构造器方法 item（不调用 → 不触 todo!()；编译期锁签名）。
        // impl Into<String> 参数用 String 实例化，避免 fn 指针生命周期问题。

        // verified funnel — 认证边界入口（ADR-001 F1 收口）
        let _: fn(&Jwt) -> Result<Principal, super::AuthnError> = Principal::from_verified_jwt;
        let _: fn(&AccessToken) -> Result<Principal, super::AuthnError> =
            Principal::from_verified_service_token;

        // 测试专用构造（for_test 仅 cfg(test) 可见）
        let _: fn(PrincipalKind, String, Option<TenantId>) -> Principal = Principal::for_test;

        let _: fn(String) -> AccessToken = AccessToken::new;
        let _: fn(String) -> RefreshToken = RefreshToken::new;
        let _: fn(SessionId, Principal, std::time::SystemTime) -> Session = Session::new;
    }
}
