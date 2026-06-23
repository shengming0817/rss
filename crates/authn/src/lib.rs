//! authn — RSS 认证主体词汇（Principal / Session / JWT / token 值类型）。
//!
//! 本 crate 承载认证侧的核心值类型与错误枚举；DI port（PDP / session store）归 `diport`（ADR-003）。
//! 所有类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! ## 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
//!
//! `Jwt::parse` 做结构化解码 + claims 映射，**不验签、不校验 exp**（签名/MAC/过期校验延后给上游
//! verifier DI port `diport::Pdp`，W 后续）。派生 `Principal` 的 funnel 收紧为只收**已验证 newtype**：
//! `from_verified_jwt(&VerifiedJwt)` / `from_verified_service_token(&VerifiedServiceToken)`。
//! `VerifiedJwt` / `VerifiedServiceToken` 私有内层 + `pub(crate)` `seal`——外部 crate 无法 mint，故
//! 「未经验签派生 Principal」**从类型层不可表达（Hard）**：拿 `Jwt::parse(raw)` 的产物已无法直接派生主体。
//! 实际验签 body + Pdp port + 生产接线（mint 收口到验签路径）留 W，见 #1109。
//!
//! ## fail-closed
//!
//! `Principal::row_visibility` 的 `Service` / `Anonymous` 分支返回 `Err(runctx::MissingCtx)`，
//! 强制调用方 deny；字段私有，外部无法绕过 funnel 伪造特权主体。

#![forbid(unsafe_code)]

use base64::Engine;
use vocab::tenant::{
    CrossTenantCapability, CrossTenantVisibility, RowVisibility, ScopedTenant, TenantId,
};

use primitives::authplan::{AuthPlan, AuthRequirement, RouteAuthOptOut, resolve_requirement};

// reason: 确保 authplan 符号被引用，防止 cargo-udeps 误报未使用依赖（ADR-004 C8）。
#[allow(dead_code)]
const _: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;

// kind claim 字符串常量（同义字面量 ≥3 次，抽 const）。
const KIND_USER: &str = "user";
const KIND_DEVICE: &str = "device";
const KIND_ADMIN: &str = "admin";
const KIND_SUPER_ADMIN: &str = "superAdmin";

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
// JWT claims 解码 DTO（私有，不 Serialize）
// ---------------------------------------------------------------------------

/// JWT payload 解码 DTO（仅内部使用；只 Deserialize，不 Serialize）。
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    kind: Option<String>,
}

/// 共享 JWT payload 解码器（不验签）。
///
/// 信任边界：只做结构解析，签名/exp 校验由上游 verifier 负责。
fn decode_claims(raw: &str) -> Result<Claims, AuthnError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthnError::TokenInvalid);
    }
    let payload_b64 = parts[1];
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AuthnError::TokenInvalid)?;
    let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| AuthnError::TokenInvalid)?;
    if claims.sub.is_empty() {
        return Err(AuthnError::TokenInvalid);
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// 认证主体
// ---------------------------------------------------------------------------

/// 认证主体（私有字段；经构造 funnel；不 derive `Serialize`——非 wire 类型）。
///
/// `row_visibility` 从已认证 principal + ctx 派生行级可见域（ADR-002）。
pub struct Principal {
    kind: PrincipalKind,
    /// subject 标识（内部，不入 wire）；供 session store / audit 读取，外部消费待后续 W 接缝落地。
    // reason: subject 是 Principal 核心标识字段，生产读路径在 session store / audit（W 阶段），
    // 当前 crate 内暂无消费方；保留 allow 避免误删（ADR-004 C8 遗留期 carve-out）。
    #[allow(dead_code)]
    subject: String,
    /// 所属租户（`None` 仅限 `Service` / `SuperAdmin` 跨租户场景）。
    tenant: Option<TenantId>,
}

impl Principal {
    /// 由已验证 JWT 派生 [`Principal`]（认证边界唯一入口）。
    ///
    /// `kind` / `tenant` 从已验证 claims 派生；外部 crate 无法构造特权主体（ADR-001）。
    ///
    /// # 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
    ///
    /// 入参收紧为 [`VerifiedJwt`]——其私有内层 + `pub(crate)` [`VerifiedJwt::seal`] 使外部 crate 无法
    /// mint，故「未经验签派生 Principal」**类型层不可表达（Hard）**：裸 `Jwt::parse(raw)` 的产物已无法
    /// 直接派生主体。本函数仍只做 claims 映射、**不验签**；签名/exp 校验由未来 verifier（`diport::Pdp`）
    /// 在 mint `VerifiedJwt` 前完成（W 后续）。当前无生产调用方（httpserve 挂载留 W），见 #1109。
    pub fn from_verified_jwt(verified: &VerifiedJwt) -> Result<Self, AuthnError> {
        // VerifiedJwt(Jwt) tuple newtype：`.0` = 已验证内层 `Jwt`（同 crate 可读私有字段）。
        let claims = &verified.0.claims;
        // 单点决策 kind + 是否需 tenant，避免二级 match-on-PrincipalKind 的不可达 `_` 臂
        // （新增 PrincipalKind 时须在此加 KIND_* 串臂并定其 tenant 要求，无静默兜底）。
        let (kind, needs_tenant) = match claims.kind.as_deref() {
            Some(KIND_USER) => (PrincipalKind::User, true),
            Some(KIND_DEVICE) => (PrincipalKind::Device, true),
            Some(KIND_ADMIN) => (PrincipalKind::Admin, true),
            // 跨租户超管：无 tenant（忽略任何 tenant claim）。
            Some(KIND_SUPER_ADMIN) => (PrincipalKind::SuperAdmin, false),
            // service/anonymous 不经 jwt funnel；未知/缺失 kind → TokenInvalid。
            _ => return Err(AuthnError::TokenInvalid),
        };
        // scoped 主体（user/device/admin）的 tenant claim 必填：缺失 / 非 canonical UUID → TokenInvalid。
        let tenant = if needs_tenant {
            let raw = claims.tenant.as_deref().ok_or(AuthnError::TokenInvalid)?;
            Some(TenantId::parse(raw).map_err(|_| AuthnError::TokenInvalid)?)
        } else {
            None
        };
        Ok(Self {
            kind,
            subject: claims.sub.clone(),
            tenant,
        })
    }

    /// 由已验证 service-token 派生（service caller 入口）。
    ///
    /// funnel 固定 `kind=Service`，忽略 token 内的 kind/tenant claim。入参收紧为 [`VerifiedServiceToken`]
    /// （私有内层 + `pub(crate)` [`VerifiedServiceToken::seal`]，外部不可 mint）——与 [`Self::from_verified_jwt`]
    /// 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）；本函数不验签，验签由未来 verifier 在 mint 前完成（W）。
    pub fn from_verified_service_token(token: &VerifiedServiceToken) -> Result<Self, AuthnError> {
        let claims = decode_claims(token.0.as_str())?;
        Ok(Self {
            kind: PrincipalKind::Service,
            subject: claims.sub,
            tenant: None,
        })
    }

    /// 测试专用构造（不进生产/wire 路径）。
    #[cfg(test)]
    pub(crate) fn for_test(
        _kind: PrincipalKind,
        _subject: impl Into<String>,
        _tenant: Option<TenantId>,
    ) -> Self {
        Self {
            kind: _kind,
            subject: _subject.into(),
            tenant: _tenant,
        }
    }

    /// 返回主体类别。
    pub fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// 返回所属租户（跨租户 principal 为 `None`）。
    pub fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }

    /// 从 principal + 请求 ctx 派生行级可见性义务（ADR-002）。
    ///
    /// `ctx` 类型为 `runctx::AppCtx`，即 `runctx::RequestCtx<vocab::tenant::TenantId, PrincipalSlot>`
    /// 别名，遵循 ADR-002 显式传 `&RequestCtx` 而非隐式线程局部的原则。
    /// ctx 缺失 fail-closed（返回 [`runctx::MissingCtx`]，绝不伪造 RowScope）。
    ///
    /// scoped 主体（user/device/admin）的行级隔离以**已认证 ctx tenant** 为准，且 fail-closed 要求
    /// principal 自带 tenant claim 与 `*ctx.tenant()` **一致**——不一致（如 tenant-A 令牌在 ctx-B 下）
    /// 返回 `Err`，杜绝越租户派生可见域（tenancy.md §Principal claim source）。
    ///
    /// `Service` / `Anonymous` 及未来未知 kind 的 `_` 分支返回 `Err(runctx::MissingCtx)`：
    /// fail-closed，无可派生行级可见域。`MissingCtx` 是冻结签名唯一 error 通道——消费方须将此 `Err`
    /// **一律按 deny 处理**，不区分「ctx 真缺失」与「主体不可派生 scope」成因（专用错误变体待签名破冻）。
    pub fn row_visibility(
        &self,
        ctx: &runctx::AppCtx,
    ) -> Result<RowVisibility, runctx::MissingCtx> {
        let ctx_tenant = *ctx.tenant();
        // scoped 主体：principal tenant claim 必须与已认证 ctx tenant 一致，否则 fail-closed
        // （防 tenant-A 令牌在 ctx-B 下越权派生可见域，codex review F3）。
        let scoped = |scope: ScopedTenant| match self.tenant {
            Some(t) if t == ctx_tenant => Ok(RowVisibility::new(scope, ctx_tenant)),
            _ => Err(runctx::MissingCtx),
        };
        match self.kind {
            PrincipalKind::User => scoped(ScopedTenant::SelfOnly),
            PrincipalKind::Device => scoped(ScopedTenant::Device),
            PrincipalKind::Admin => scoped(ScopedTenant::Tenant),
            PrincipalKind::SuperAdmin => {
                // INVARIANT: TENANCY-CROSSTENANT-CAP-01 —— authn super-admin 派生是唯一 sanctioned
                // crosstenant capability 签发点（dylint rss_crosstenant_callsite allowlist=authn 守）。
                // REQUIREMENT: tenancy.md §RowScope —— 调用方须在 super-admin All-scope 派生「同址」写
                // 持久 audit ledger（tenant/principal/resource/action/request/correlation）。frozen 同步
                // 签名无 AuditSink，本 PR 无法在此闭环；强制审计待 W httpserve/audit 接线，见 issue #1110。
                let cap = CrossTenantCapability::issue_for_verified_super_admin();
                let marker = CrossTenantVisibility::authorize(cap);
                Ok(RowVisibility::new_cross_tenant(marker))
            }
            // Service / Anonymous 及 #[non_exhaustive] 未来 kind：fail-closed，无可派生行级可见域。
            _ => Err(runctx::MissingCtx),
        }
    }
}

// ---------------------------------------------------------------------------
// JWT / token / session 值类型
// ---------------------------------------------------------------------------

/// JWT 原始令牌（私有字段；不 derive `Serialize`；构造经 fallible funnel）。
pub struct Jwt {
    raw: String,
    claims: Claims,
}

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jwt(<redacted>)")
    }
}

impl Jwt {
    /// 解析并做基础结构验证（签名验证由上游 verifier DI port 负责，不验签、不校验 exp）。
    pub fn parse(raw: &str) -> Result<Self, AuthnError> {
        let claims = decode_claims(raw)?;
        Ok(Self {
            raw: raw.to_string(),
            claims,
        })
    }

    /// 取令牌字符串引用（只读，不 clone）。
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// 已验证 JWT 标记（私有内层 [`Jwt`]；外部 crate 无法 mint；不 derive `Serialize`）。
///
/// # 类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
///
/// 把「未经验签派生 Principal」收口到类型层（Hard，newtype funnel）：[`Principal::from_verified_jwt`]
/// 只收 `&VerifiedJwt`，而 `VerifiedJwt` 仅经 `pub(crate)` [`Self::seal`] 装箱——外部 crate 既不能命名
/// 私有内层、也不能调 `pub(crate)` 构造，故无法用裸 `Jwt::parse(raw)` 的产物伪造已验证主体。`Debug` 脱敏。
///
/// ⚠ `seal` 的 `pub(crate)` 可见性是本不变式锚点：改为 `pub` 会让外部可 mint，Hard 静默退化为 Soft
/// （anti-vacuity smoke 不覆盖可见性漂移）。改 `pub` 须经 ADR amendment；机器守（`cargo public-api`
/// golden）跟踪见 #1151。不 derive `Clone`（内层 `Jwt` 非 `Clone`）；W httpserve 接线若需共享，wrap `Arc<_>`。
///
/// **funnel 上下游强度（已知中间态，#1109 Option A）**：本 PR 只锁**消费端**（Hard）；**生产端**当前仅
/// `pub(crate)` `seal`（test 行使），跨 crate 无受控生产入口。闭环 producer 桥接留 W——届时**不**把 `seal`
/// 改 `pub` 让外部 verifier 直接 mint（会退化 Hard），而由 authn 暴露 **authn-owned** `verify→mint` bridge
/// （内部经 `diport::Pdp` 验签成功后调 `seal`，`seal` 保持 `pub(crate)`）。Blocked-by diport::Pdp，见 #1158。
/// `seal` 本身**不验签**，只做受控装箱。当前无生产调用方（httpserve 挂载留 W）。见 #1109。
pub struct VerifiedJwt(Jwt);

impl std::fmt::Debug for VerifiedJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedJwt(<redacted>)")
    }
}

impl VerifiedJwt {
    /// 受控装箱：把已验签 [`Jwt`] 标记为 [`VerifiedJwt`]（`pub(crate)` funnel，**不验签**）。
    ///
    /// 调用方须已对 `jwt` 完成验签（签名/exp/MAC）——本函数只做类型层标记，不做 crypto。
    // reason: 生产 mint 接线（验签后 verifier 调用）留 W，当前 crate 内仅 test 行使；
    // 保留 allow 避免误删（ADR-004 C8 遗留期 carve-out），见 #1109。
    #[allow(dead_code)]
    pub(crate) fn seal(jwt: Jwt) -> Self {
        Self(jwt)
    }
}

/// 访问令牌 newtype（私有内容；构造经 funnel；不 derive `Serialize`）。
pub struct AccessToken(String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessToken(<redacted>)")
    }
}

impl AccessToken {
    /// 构造访问令牌（来自认证流程输出，非直接 parse）。
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取令牌字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 已验证 service-token 标记（私有内层 [`AccessToken`]；外部 crate 无法 mint；不 derive `Serialize`）。
///
/// 与 [`VerifiedJwt`] 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）：
/// [`Principal::from_verified_service_token`] 只收 `&VerifiedServiceToken`，仅经 `pub(crate)` [`Self::seal`]
/// 装箱。`Debug` 脱敏。`seal` 须保持 `pub(crate)`（同 [`VerifiedJwt`] 锚点，机器守见 #1151）。
/// 生产 mint 由验签后的 verifier 调用（W 后续），当前 crate 内仅 test 行使。见 #1109。
pub struct VerifiedServiceToken(AccessToken);

impl std::fmt::Debug for VerifiedServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedServiceToken(<redacted>)")
    }
}

impl VerifiedServiceToken {
    /// 受控装箱：把已验签 [`AccessToken`] 标记为 [`VerifiedServiceToken`]（`pub(crate)`，**不验签**）。
    // reason: 生产 mint 接线（验签后 verifier 调用）留 W，当前 crate 内仅 test 行使；
    // 保留 allow 避免误删（ADR-004 C8 遗留期 carve-out），见 #1109。
    #[allow(dead_code)]
    pub(crate) fn seal(token: AccessToken) -> Self {
        Self(token)
    }
}

/// 刷新令牌 newtype（私有内容；不 derive `Serialize`）。
pub struct RefreshToken(String);

impl std::fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RefreshToken(<redacted>)")
    }
}

impl RefreshToken {
    /// 构造刷新令牌。
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// 取令牌字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 会话 ID newtype（私有内容；不 derive `Serialize`）。
pub struct SessionId(String);

impl SessionId {
    /// 生成新会话 ID（UUID v4 随机值）。
    ///
    /// 不取系统时钟（满足 clippy clock 纪律）；RW-G1 追踪弹经此 mint 登录会话 id。
    /// 完整会话生命周期（`Session` / `Principal` 聚合经已校验 JWT / token 派生）留 W。
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// 取 ID 字符串引用。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 会话快照（私有字段；不 derive `Serialize`；构造经位置参 funnel）。
pub struct Session {
    id: SessionId,
    principal: Principal,
    /// 会话到期时间（与 deviceloop CertLifecycleState 的 SystemTime 类型一致）。
    expires_at: std::time::SystemTime,
}

impl Session {
    /// 构造会话（`expires_at` 来自时钟注入，不在此取系统时间）。
    pub fn new(id: SessionId, principal: Principal, expires_at: std::time::SystemTime) -> Self {
        Self {
            id,
            principal,
            expires_at,
        }
    }

    /// 取会话 ID 引用。
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// 取 principal 引用。
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// 取到期时间。
    pub fn expires_at(&self) -> std::time::SystemTime {
        self.expires_at
    }
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// 认证层错误（库枚举；用 `thiserror`；message 为 const 静态字面量）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// 结构化解码 / claims 映射失败（坏 base64url / 坏 JSON / 缺 sub / 未知 kind / 坏 tenant）。
    #[error("token is invalid")]
    TokenInvalid,
    /// 令牌过期。**本 crate 当前不可达**——exp 校验需 `Clock`，由 W verifier DI port（`diport::Pdp`）产生。
    #[error("token is expired")]
    TokenExpired,
    /// 会话不存在。**本 crate 当前不可达**——由 W session store（`diport` 仓储 port）产生。
    #[error("session not found")]
    SessionNotFound,
    /// 主体无权。预留给授权失败路径（PDP 决策，W 后续）。
    #[error("principal not permitted")]
    Forbidden,
}

// ---------------------------------------------------------------------------
// 行为测试（解冻：真实调用 body；表驱动 rstest，服务档覆盖 ≥80%）
// ---------------------------------------------------------------------------

/// 测试用合法 canonical 租户（`TenantId::parse` 接受形态）。
#[cfg(test)]
const CANON_TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

/// 测试用 JWT 构造：3 段（header.payload.sig），payload 为给定 JSON；header/sig 为占位（不验签）。
#[cfg(test)]
fn test_jwt(payload_json: &str) -> String {
    use base64::Engine;
    let eng = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        eng.encode(br#"{"alg":"none"}"#),
        eng.encode(payload_json.as_bytes()),
        eng.encode(b"sig"),
    )
}

#[cfg(test)]
mod row_visibility_tests {
    //! 核心：`Principal::row_visibility` 身份→行级可见域派生（tenancy.md §Principal claim source）。
    //! user→self / device→device / admin→tenant / super-admin→all / service·anonymous→fail-closed。
    use super::{CANON_TENANT, Principal, PrincipalKind};
    use rstest::rstest;
    use vocab::tenant::{RowScope, TenantId};

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    /// 期望形态：scoped（Ok + 单租户）/ all（Ok + 跨租户无租户）/ fail-closed（Err）。
    enum Expect {
        Scoped(RowScope),
        All,
        FailClosed,
    }

    #[rstest]
    #[case(PrincipalKind::User, Expect::Scoped(RowScope::SelfOnly))]
    #[case(PrincipalKind::Device, Expect::Scoped(RowScope::Device))]
    #[case(PrincipalKind::Admin, Expect::Scoped(RowScope::Tenant))]
    #[case(PrincipalKind::SuperAdmin, Expect::All)]
    #[case(PrincipalKind::Service, Expect::FailClosed)]
    #[case(PrincipalKind::Anonymous, Expect::FailClosed)]
    fn row_visibility_maps_kind_to_scope(
        #[case] kind: PrincipalKind,
        #[case] expect: Expect,
    ) -> Result<(), runctx::MissingCtx> {
        let tid = tenant();
        // scoped kind 自带与 ctx 一致的 tenant（row_visibility 校验 self.tenant == ctx.tenant）；特权/匿名为 None。
        let self_tenant = match kind {
            PrincipalKind::User | PrincipalKind::Device | PrincipalKind::Admin => Some(tid),
            _ => None,
        };
        let principal = Principal::for_test(kind, "subject-x", self_tenant);
        let ctx = runctx::test_support::app_ctx(tid, "subject-x");

        match expect {
            Expect::Scoped(scope) => {
                let vis = principal.row_visibility(&ctx)?;
                assert_eq!(vis.scope(), scope, "kind={kind:?}");
                assert_eq!(vis.tenant(), Some(tid), "kind={kind:?}");
            }
            Expect::All => {
                // super-admin → 跨租户 All，经 authn 唯一 sanctioned crosstenant callsite 派生。
                let vis = principal.row_visibility(&ctx)?;
                assert_eq!(vis.scope(), RowScope::All);
                assert_eq!(vis.tenant(), None);
            }
            Expect::FailClosed => {
                assert!(
                    principal.row_visibility(&ctx).is_err(),
                    "kind={kind:?} 必须 fail-closed（无可派生行级可见域）"
                );
            }
        }
        Ok(())
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn row_visibility_fails_closed_on_tenant_mismatch() {
        // codex review F3：scoped principal 的 tenant claim 与已认证 ctx tenant 不一致 → fail-closed
        // （防 tenant-A 令牌在 ctx-B 下越权派生可见域）。
        let tid_a = tenant();
        let tid_b = TenantId::parse("11111111-2222-4333-8444-555555555555").expect("tenant b");
        assert_ne!(tid_a, tid_b);
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
        ] {
            let principal = Principal::for_test(kind, "subject-x", Some(tid_a));
            let ctx = runctx::test_support::app_ctx(tid_b, "subject-x");
            assert!(
                principal.row_visibility(&ctx).is_err(),
                "kind={kind:?} tenant 不一致须 fail-closed"
            );
        }
    }
}

#[cfg(test)]
mod jwt_parse_tests {
    //! `Jwt::parse`：结构化解码（3 段 + base64url payload + JSON + 必填 sub），不验签。
    use super::{AuthnError, Jwt, test_jwt};

    #[test]
    #[allow(clippy::expect_used)]
    fn parse_accepts_valid_token_and_as_str_round_trips() {
        let raw = test_jwt(
            r#"{"sub":"alice","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let parsed = Jwt::parse(&raw).expect("valid token parses");
        assert_eq!(parsed.as_str(), raw, "as_str 必须回放原始 token");
    }

    #[test]
    fn parse_rejects_malformed_structures() {
        let cases: Vec<String> = vec![
            "only.two".to_string(),                      // 非 3 段（2 段）
            "a.b.c.d".to_string(),                       // 非 3 段（4 段）
            "###.###.###".to_string(),                   // payload 非 base64url
            test_jwt("not-json"),                        // payload 非 JSON
            test_jwt(r#"{"tenant":"x","kind":"user"}"#), // 缺 sub
            test_jwt(r#"{"sub":"","kind":"user"}"#),     // sub 空
        ];
        for raw in &cases {
            assert!(
                matches!(Jwt::parse(raw), Err(AuthnError::TokenInvalid)),
                "必须 TokenInvalid: {raw}"
            );
        }
    }
}

#[cfg(test)]
mod principal_derive_tests {
    //! `from_verified_jwt`（claims→Principal 映射）+ `from_verified_service_token`（funnel 固定 Service）。
    //! 信任边界：函数信任入参已被上游 verifier 验签（本轮不做 crypto 验签）。
    use super::{
        AccessToken, AuthnError, Jwt, Principal, PrincipalKind, VerifiedJwt, VerifiedServiceToken,
        test_jwt,
    };
    use vocab::tenant::TenantId;

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    #[allow(clippy::expect_used)]
    fn parsed(payload_json: &str) -> Jwt {
        Jwt::parse(&test_jwt(payload_json)).expect("payload parses")
    }

    /// 已验签 JWT 测试装箱：模拟未来 verifier 验签后经 `pub(crate)` funnel mint（本轮不做 crypto）。
    fn verified(payload_json: &str) -> VerifiedJwt {
        VerifiedJwt::seal(parsed(payload_json))
    }

    /// 已验签 service-token 测试装箱（同上）。
    fn verified_service(raw: impl Into<String>) -> VerifiedServiceToken {
        VerifiedServiceToken::seal(AccessToken::new(raw))
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn maps_scoped_kinds_with_tenant() {
        let tid = TenantId::parse(CANON).expect("tenant");
        let cases = [
            (
                r#"{"sub":"u","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
                PrincipalKind::User,
            ),
            (
                r#"{"sub":"d","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"device"}"#,
                PrincipalKind::Device,
            ),
            (
                r#"{"sub":"a","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"admin"}"#,
                PrincipalKind::Admin,
            ),
        ];
        for (payload, kind) in cases {
            let p = Principal::from_verified_jwt(&verified(payload)).expect("derive ok");
            assert_eq!(p.kind(), kind, "{payload}");
            assert_eq!(p.tenant(), Some(tid), "{payload}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn maps_super_admin_to_cross_tenant_none() {
        let p = Principal::from_verified_jwt(&verified(r#"{"sub":"root","kind":"superAdmin"}"#))
            .expect("super-admin derive ok");
        assert_eq!(p.kind(), PrincipalKind::SuperAdmin);
        assert_eq!(p.tenant(), None, "super-admin 跨租户，tenant 必须 None");
    }

    #[test]
    fn rejects_scoped_kind_without_tenant() {
        for payload in [
            r#"{"sub":"u","kind":"user"}"#,
            r#"{"sub":"d","kind":"device"}"#,
            r#"{"sub":"a","kind":"admin"}"#,
        ] {
            assert!(
                matches!(
                    Principal::from_verified_jwt(&verified(payload)),
                    Err(AuthnError::TokenInvalid)
                ),
                "scoped kind 缺 tenant 必须 TokenInvalid: {payload}"
            );
        }
    }

    #[test]
    fn rejects_unknown_kind_wrong_funnel_and_bad_tenant() {
        for payload in [
            r#"{"sub":"x","kind":"service"}"#, // service 走 service-token funnel，非 jwt 派生
            r#"{"sub":"x","kind":"anonymous"}"#, // anonymous 不经 jwt 派生
            r#"{"sub":"x","kind":"root"}"#,    // 未知 kind
            r#"{"sub":"x"}"#,                  // 缺 kind
            r#"{"sub":"u","tenant":"not-a-uuid","kind":"user"}"#, // 坏 tenant
        ] {
            assert!(
                matches!(
                    Principal::from_verified_jwt(&verified(payload)),
                    Err(AuthnError::TokenInvalid)
                ),
                "必须 TokenInvalid: {payload}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn service_token_funnel_fixes_service_kind_no_tenant() {
        let token = test_jwt(
            r#"{"sub":"svc-a","kind":"ignored","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479"}"#,
        );
        let p = Principal::from_verified_service_token(&verified_service(token))
            .expect("service derive ok");
        // funnel 自身确定 kind=Service，忽略 token 的 kind/tenant claim。
        assert_eq!(p.kind(), PrincipalKind::Service);
        assert_eq!(p.tenant(), None);
    }

    #[test]
    fn service_token_rejects_malformed() {
        assert!(matches!(
            Principal::from_verified_service_token(&verified_service("garbage")),
            Err(AuthnError::TokenInvalid)
        ));
    }
}

#[cfg(test)]
mod verified_token_seal {
    //! INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 —— 「未验签派生 Principal」类型层不可表达。
    //!
    //! `VerifiedJwt` / `VerifiedServiceToken` 私有内层 + `pub(crate)` `seal`：外部 crate 无法 mint，
    //! 故收紧后的 `from_verified_jwt(&VerifiedJwt)` / `from_verified_service_token(&VerifiedServiceToken)`
    //! 只能消费已验证 newtype（编译期 Hard，绕过不可表达）。
    //! anti-vacuity：受控入口 + funnel 签名绑为函数指针——去掉任一即编译失败（守卫非恒真）。
    use super::{
        AccessToken, AuthnError, Jwt, Principal, VerifiedJwt, VerifiedServiceToken, test_jwt,
    };

    #[test]
    fn seal_entries_and_funnels_carry_verified_newtype_signatures() {
        // 受控 mint 入口（`pub(crate)`，外部 crate 不可达——Hard）。
        let _seal_jwt: fn(Jwt) -> VerifiedJwt = VerifiedJwt::seal;
        let _seal_svc: fn(AccessToken) -> VerifiedServiceToken = VerifiedServiceToken::seal;
        // funnel 只收已验证 newtype（裸 `&Jwt` / `&AccessToken` 不再可派生 Principal）。
        let _from_jwt: fn(&VerifiedJwt) -> Result<Principal, AuthnError> =
            Principal::from_verified_jwt;
        let _from_svc: fn(&VerifiedServiceToken) -> Result<Principal, AuthnError> =
            Principal::from_verified_service_token;
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn verified_jwt_redacts_debug() {
        let raw = test_jwt(
            r#"{"sub":"alice-secret","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let vj = VerifiedJwt::seal(Jwt::parse(&raw).expect("payload parses"));
        let dbg = format!("{vj:?}");
        assert!(!dbg.contains(&raw), "VerifiedJwt Debug 不得泄露原始 token");
        // 显式断言 claim 明文不泄（防 Debug 委托内层格式化器打印 sub 值）。
        assert!(
            !dbg.contains("alice-secret"),
            "VerifiedJwt Debug 不得泄露 sub claim 明文"
        );
        assert!(
            dbg.contains("redacted"),
            "VerifiedJwt Debug 应标记 redacted"
        );
    }

    #[test]
    fn verified_service_token_redacts_debug() {
        let vs = VerifiedServiceToken::seal(AccessToken::new("svc-secret-xyz"));
        let dbg = format!("{vs:?}");
        assert!(
            !dbg.contains("svc-secret-xyz"),
            "VerifiedServiceToken Debug 不得泄露原始 token"
        );
        assert!(
            dbg.contains("redacted"),
            "VerifiedServiceToken Debug 应标记 redacted"
        );
    }
}

#[cfg(test)]
mod value_type_tests {
    //! token newtype / `Session` 聚合 / `Principal` 访问器 / Send / Debug 脱敏。
    use super::{
        AccessToken, CANON_TENANT, Principal, PrincipalKind, RefreshToken, Session, SessionId,
    };
    use std::time::{Duration, SystemTime};
    use vocab::tenant::TenantId;

    fn _assert_send<T: Send>() {}

    #[test]
    fn principal_and_session_are_send() {
        _assert_send::<Principal>();
        _assert_send::<Session>();
    }

    #[test]
    fn tokens_round_trip_and_debug_is_redacted() {
        let at = AccessToken::new("access-secret");
        assert_eq!(at.as_str(), "access-secret");
        assert!(
            !format!("{at:?}").contains("access-secret"),
            "AccessToken Debug 不得泄露内容"
        );

        let rt = RefreshToken::new("refresh-secret");
        assert_eq!(rt.as_str(), "refresh-secret");
        assert!(
            !format!("{rt:?}").contains("refresh-secret"),
            "RefreshToken Debug 不得泄露内容"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn session_aggregates_id_principal_and_expiry() {
        let tid = TenantId::parse(CANON_TENANT).expect("tenant");
        let principal = Principal::for_test(PrincipalKind::User, "alice", Some(tid));
        let id = SessionId::generate();
        let id_str = id.as_str().to_string();
        let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);

        let session = Session::new(id, principal, expires_at);
        assert_eq!(session.id().as_str(), id_str);
        assert_eq!(session.principal().kind(), PrincipalKind::User);
        assert_eq!(session.expires_at(), expires_at);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn principal_accessors_reflect_construction() {
        let tid = TenantId::parse(CANON_TENANT).expect("tenant");
        let p = Principal::for_test(PrincipalKind::Admin, "bob", Some(tid));
        assert_eq!(p.kind(), PrincipalKind::Admin);
        assert_eq!(p.tenant(), Some(tid));
    }
}

#[cfg(test)]
mod enum_exhaustiveness {
    //! 闭值集完整性 + 错误 Display 非空（crate 内穷举 non_exhaustive）。
    use super::{AuthnError, PrincipalKind};

    #[test]
    fn principal_kind_is_exhaustive() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::SuperAdmin,
            PrincipalKind::Service,
            PrincipalKind::Anonymous,
        ] {
            match kind {
                PrincipalKind::User
                | PrincipalKind::Device
                | PrincipalKind::Admin
                | PrincipalKind::SuperAdmin
                | PrincipalKind::Service
                | PrincipalKind::Anonymous => {}
            }
        }
    }

    #[test]
    fn authn_error_is_exhaustive_and_displays() {
        for e in [
            AuthnError::TokenInvalid,
            AuthnError::TokenExpired,
            AuthnError::SessionNotFound,
            AuthnError::Forbidden,
        ] {
            assert!(!e.to_string().is_empty(), "错误 message 非空");
            match e {
                AuthnError::TokenInvalid
                | AuthnError::TokenExpired
                | AuthnError::SessionNotFound
                | AuthnError::Forbidden => {}
            }
        }
    }
}

#[cfg(test)]
mod session_id {
    //! `SessionId::generate`（RW-G1 已写实）：UUID v4，唯一 + 非空。
    use super::SessionId;

    #[test]
    fn generate_is_unique_and_canonical_uuid() {
        let a = SessionId::generate();
        let b = SessionId::generate();
        assert!(!a.as_str().is_empty());
        assert_ne!(a.as_str(), b.as_str());
        // 锁定格式契约：session id 是 canonical UUID（贯穿到 audit resource_id，不可退化为递增整数）。
        assert!(
            uuid::Uuid::parse_str(a.as_str()).is_ok(),
            "session id must be a parseable uuid"
        );
    }
}
