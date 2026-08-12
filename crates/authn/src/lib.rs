//! authn — RSS 认证主体词汇与 profile-typed token funnel。
//!
//! 本 crate 承载认证侧的核心值类型与错误枚举；认证 DI port（PDP 等）归 `diport`（ADR-003）。
//! 所有类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//! [`JwtIssuer`] / [`JwtIssuerConfig`] 以 sealed profile marker 固定算法、`typ`、`token_use` 与最大
//! TTL：RSS access 只暴露 access mint，service-token 只暴露 service mint，federated access
//! 没有本地 issuer 构造入口。
//!
//! ## 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）
//!
//! 验签（签名/MAC、profile、时间窗、issuer/audience 与身份 claims）由 verifier DI port
//! `diport::Pdp` 负责；`Jwt::parse` 仅作 token
//! **结构闸**（3 段 / base64url / JSON / 非空 sub），不验签、不提取身份。派生 `Principal` 的 funnel 收紧为
//! 只收**已验证 newtype**：`from_verified_jwt(&VerifiedJwt)` / `from_verified_service_token(&VerifiedServiceToken)`。
//! `VerifiedJwt` / `VerifiedServiceToken` 私有字段 + `pub(crate)` `seal`——外部 crate 无法 mint，故
//! 「未经验签派生 Principal」**从类型层不可表达（Hard）**。载体内携**单一 canonical 身份源**
//! `diport::VerifiedClaims`（验签产物）：一个载体只导出一个 principal，无第二（raw 重解析）身份源（#1158 F1）。
//! 生产 mint 路径 = authn-owned `verify_rss_access` / `verify_federated_access` /
//! `verify_service_token`（经 `Pdp` 验签后 seal）。生产 runtime 的 exhaustive profile binding
//! 从同一 variant 派生 provider、所需 auth scheme 与这三个 funnel 之一，避免 scheme/provider 分参错配。
//!
//! ## fail-closed
//!
//! `Principal::row_visibility` 的 `SuperAdmin`（裸同步路径）/ `Service` / `Anonymous` 分支返回
//! `Err(runctx::MissingCtx)`，强制调用方 deny；字段私有，外部无法绕过 funnel 伪造特权主体。
//! 跨租户路径只经 [`Principal::cross_tenant_audit_grant`] 派生不含 All-scope 的 target-bound grant；
//! audit 域完成 typed durable append 后才铸造 read scope。
//! 无审计无 All-scope，audit 写失败 fail-closed。

#![forbid(unsafe_code)]

use base64::Engine;
use rss_request_context::PrincipalKind;
use rss_request_context::RowScope;
use rss_request_context::TenantId;
use vocab::tenant::RowVisibility;

use primitives::authplan::{AuthPlan, AuthRequirement, RouteAuthOptOut, resolve_requirement};

// verify→mint bridge 经 `DynPdp` 调验签：`verify` 是 `Pdp` trait 方法，须 trait 在 scope（`as _`
// 只引入方法、不污染 `Pdp` 名——bridge 全程用 `diport::DynPdp` / `diport::RawCredential` 全限定）。
use diport::Pdp as _;

// reason: 确保 authplan 符号被引用，防止 cargo-udeps 误报未使用依赖（ADR-004 C8）。
#[allow(dead_code)]
const _: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;

// JWT 签发（mint/sign）：组装 claims + 紧凑 JWS，签名委托注入的 `diport::Signer`（#1314）。验签侧对称物在
// 本 crate 顶部 verify→mint bridge；mint 子模块复用下方 `KIND_*` claim 串单源（杜绝 round-trip 漂移）。
mod keyring;
pub use keyring::{KeyRingError, RotationMode, RotationOverlapPolicy, SigningKeyRing};
mod grant;
pub use grant::{
    AccountSecurityEventKind, AuthGrant, AuthGrantCloseMutation, AuthGrantId, AuthGrantIdError,
    AuthGrantIssueError, AuthGrantSnapshot, AuthGrantStateError, AuthGrantStatus, AuthnEpoch,
    AuthnEpochError, CredentialSecurityEventKind, GrantSecurityEventKind, RssAccessIssueInput,
};
mod mint;
pub use mint::{JwtIssueError, JwtIssuer, JwtIssuerConfig, MintedJwt};
mod mtls;
pub use mtls::{
    MtlsAllowSet, MtlsIdentityError, MtlsTrustDomain, MtlsTrustDomainAllowSet, OutboundMtlsPolicy,
    SpiffeId, VerifiedMtlsPeer, verify_mtls_peer,
};

// Locally minted profile claim strings. Federated claim parsing is owned by the verifier.
const KIND_USER: &str = "user";
// reason: service 主体（HS256 service-token）的 kind 串——本轮仅 mint 侧 `kind_claim` 用；与上列同址，
// 保 kind claim 名单源（验签 service-token 路径经 `from_verified_service_token` 固定 Service、不读本串）。
const KIND_SERVICE: &str = "service";

/// Closed projection maintenance action set used by grants and sealed receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionMaintenanceAction {
    /// Read projection pointer and replay status.
    Status,
    /// Replay one generated projection target.
    Replay,
    /// Promote one generated projection version.
    Swap,
}

/// One configured service-principal grant for an exact projection maintenance target.
#[derive(Debug, PartialEq, Eq)]
pub struct ProjectionMaintenanceGrant {
    caller: vocab::ServiceCallerDomain,
    action: ProjectionMaintenanceAction,
    tenant: TenantId,
    projection: Box<str>,
}

impl ProjectionMaintenanceGrant {
    /// Build an exact typed-caller grant. Empty projection identifiers fail closed.
    pub fn new(
        caller: vocab::ServiceCallerDomain,
        action: ProjectionMaintenanceAction,
        tenant: TenantId,
        projection: impl Into<String>,
    ) -> Result<Self, ProjectionMaintenanceGrantError> {
        let projection = projection.into();
        if projection.trim().is_empty() {
            return Err(ProjectionMaintenanceGrantError::EmptyProjection);
        }
        Ok(Self {
            caller,
            action,
            tenant,
            projection: projection.into_boxed_str(),
        })
    }
}

/// Configured projection maintenance grants. This is the sole public receipt mint funnel.
pub struct ProjectionMaintenanceGrantSet {
    grants: Vec<ProjectionMaintenanceGrant>,
}

impl ProjectionMaintenanceGrantSet {
    /// Build a non-empty grant set.
    pub fn new(
        grants: Vec<ProjectionMaintenanceGrant>,
    ) -> Result<Self, ProjectionMaintenanceGrantError> {
        if grants.is_empty() {
            return Err(ProjectionMaintenanceGrantError::EmptySet);
        }
        Ok(Self { grants })
    }

    /// Authorize an already verified service principal for one exact action and target.
    pub fn authorize(
        &self,
        principal: &Principal,
        action: ProjectionMaintenanceAction,
        tenant: TenantId,
        projection: &str,
    ) -> Result<ProjectionMaintenanceReceipt, ProjectionMaintenanceGrantError> {
        let caller = principal
            .service_caller
            .ok_or(ProjectionMaintenanceGrantError::Forbidden)?;
        let allowed = self.grants.iter().any(|grant| {
            caller == grant.caller
                && grant.action == action
                && grant.tenant == tenant
                && grant.projection.as_ref() == projection
        });
        if !allowed {
            return Err(ProjectionMaintenanceGrantError::Forbidden);
        }
        Ok(ProjectionMaintenanceReceipt::seal(
            caller, action, tenant, projection,
        ))
    }
}

/// Authn-owned, target-bound proof for one authorized projection maintenance operation.
///
/// Private fields and a private mint make forgery impossible outside authn. The type deliberately
/// does not implement `Clone`, so a receipt cannot be widened into an ambient reusable capability.
/// INVARIANT: AUTHN-PROJECTION-RECEIPT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "private target-bound receipt and sealed mint funnel", facet = "sealed-receipt" }.
pub struct ProjectionMaintenanceReceipt {
    operator_caller: vocab::ServiceCallerDomain,
    action: ProjectionMaintenanceAction,
    tenant: TenantId,
    projection: Box<str>,
    _seal: (),
}

impl ProjectionMaintenanceReceipt {
    fn seal(
        operator_caller: vocab::ServiceCallerDomain,
        action: ProjectionMaintenanceAction,
        tenant: TenantId,
        projection: &str,
    ) -> Self {
        Self {
            operator_caller,
            action,
            tenant,
            projection: projection.into(),
            _seal: (),
        }
    }

    /// Typed caller domain of the verified service principal that received this proof.
    pub const fn operator_caller(&self) -> vocab::ServiceCallerDomain {
        self.operator_caller
    }

    /// Return whether this receipt authorizes exactly the supplied action and target.
    pub fn authorizes(
        &self,
        action: ProjectionMaintenanceAction,
        tenant: TenantId,
        projection: &str,
    ) -> bool {
        self.action == action && self.tenant == tenant && self.projection.as_ref() == projection
    }
}

impl std::fmt::Debug for ProjectionMaintenanceReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectionMaintenanceReceipt")
            .field("operator_caller", &self.operator_caller)
            .field("action", &self.action)
            .field("tenant", &self.tenant)
            .field("projection", &self.projection)
            .finish_non_exhaustive()
    }
}

/// Projection grant validation and authorization failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionMaintenanceGrantError {
    /// A grant projection identifier was empty.
    #[error("projection maintenance grant projection must be non-empty")]
    EmptyProjection,
    /// At least one explicit grant is required.
    #[error("projection maintenance grant set must be non-empty")]
    EmptySet,
    /// The verified principal did not match the exact action and target.
    #[error("projection maintenance operation is not authorized")]
    Forbidden,
}

// 主体类别 `PrincipalKind` 单一源已上移基础层 `vocab`（crates/vocab/src/principal.rs）：authn `Principal.kind` /
// httpserve `Authenticated` 证据 / audit `actor_kind` 共用同一枚举，杜绝双源漂移。本 crate 经顶部
// `use rss_request_context::PrincipalKind` 消费；KIND_* claim 串 → `PrincipalKind` 的映射策略仍归本 crate（`from_verified_jwt`）。

// ---------------------------------------------------------------------------
// JWT claims 解码 DTO（私有，不 Serialize）
// ---------------------------------------------------------------------------

/// JWT payload 结构校验 DTO（仅内部；只 Deserialize）。身份 claims 由 verifier 经 [`diport::VerifiedClaims`]
/// 提供，本结构只承载结构闸所需的 `sub`（非空校验）；serde 忽略其余 payload 字段。
#[derive(serde::Deserialize)]
struct Claims {
    sub: String,
}

/// JWT 结构闸（不验签）：校验 3 段 + base64url payload + JSON + 非空 `sub`。
///
/// 信任边界：只做**结构**校验，签名/exp 与身份 claims 由上游 verifier（`diport::Pdp`）负责。本闸在 access
/// 中**验签通过后**运行（防 lenient adapter 误判畸形 token ok），故失败归 [`AuthnError::PrincipalInvalid`]
/// （验签后失败），**非** `TokenInvalid`（专指 verifier 报告的签名失败，#1275 review F1）。
fn decode_claims(raw: &str) -> Result<Claims, AuthnError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthnError::PrincipalInvalid);
    }
    let payload_b64 = parts[1];
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AuthnError::PrincipalInvalid)?;
    let claims: Claims =
        serde_json::from_slice(&bytes).map_err(|_| AuthnError::PrincipalInvalid)?;
    if claims.sub.is_empty() {
        return Err(AuthnError::PrincipalInvalid);
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
    /// subject 标识（内部，不入 wire）；经 [`Principal::matches_subject`] 受控比较（不泄露明文）。
    subject: String,
    /// 所属租户（`None` 仅限 `Service` / `SuperAdmin` 跨租户场景）。
    tenant: Option<TenantId>,
    service_caller: Option<vocab::ServiceCallerDomain>,
}

impl Principal {
    /// 由已验证 JWT 派生 [`Principal`]（认证边界唯一入口）。
    ///
    /// `kind` / `tenant` 从**验签产物 [`diport::VerifiedClaims`]**（verifier = 信任原点）派生；外部 crate
    /// 无法构造特权主体（ADR-001）。
    ///
    /// # 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）
    ///
    /// 入参收紧为 [`VerifiedJwt`]——其私有内层 + `pub(crate)` [`VerifiedJwt::seal`] 使外部 crate 无法 mint，
    /// 故「未经验签派生 Principal」**类型层不可表达（Hard）**。`VerifiedJwt` 内携**单一 canonical 身份源**
    /// `VerifiedClaims`（F1）：一个 verified 载体只导出一个 principal——本函数与 verify→mint bridge
    /// access verification funnels read the **same** `VerifiedClaims`, with no second raw identity source.
    pub fn from_verified_jwt(verified: &VerifiedJwt) -> Result<Self, AuthnError> {
        match verified.claims.view() {
            diport::VerifiedClaimsView::RssUser {
                user_id, tenant, ..
            } => Ok(Self {
                kind: PrincipalKind::User,
                subject: user_id.as_uuid().hyphenated().to_string(),
                tenant: Some(tenant),
                service_caller: None,
            }),
            diport::VerifiedClaimsView::FederatedAccess {
                subject,
                tenant,
                kind,
                ..
            } => Ok(Self {
                kind,
                subject: subject.to_owned(),
                tenant,
                service_caller: None,
            }),
            diport::VerifiedClaimsView::ServiceToken { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => {
                Err(AuthnError::PrincipalInvalid)
            }
        }
    }

    /// 由已验证 service-token subject 派生（funnel 固定 `kind=Service`，跨租户 `tenant=None`）。
    ///
    /// fail-closed 与 typed [`vocab::ServiceCallerDomain`] 对齐：空 `sub` 在 OIDC claims 闸以
    /// `EmptySubject` 拒绝，不进入本函数；本函数只经 [`vocab::ServiceCallerDomain::from_subject`]
    /// 做 closed-set 映射——miss（未知 / 非闭集 caller）→ [`AuthnError::PrincipalInvalid`]。
    /// wrong-shape claims（非 `ServiceToken` 视图）由 [`Self::from_verified_service_token`] 同款拒为
    /// `PrincipalInvalid`。信任原点 = verifier：subject 取自验签产物
    /// [`diport::VerifiedClaimsView::ServiceToken`]，service token 的 kind / tenant claim 不参与
    /// （service 主体恒跨租户）。
    fn service_from_subject(subject: &str) -> Result<Self, AuthnError> {
        let service_caller = vocab::ServiceCallerDomain::from_subject(subject)
            .ok_or(AuthnError::PrincipalInvalid)?;
        Ok(Self {
            kind: PrincipalKind::Service,
            subject: subject.to_string(),
            tenant: None,
            service_caller: Some(service_caller),
        })
    }

    /// 由已验证 service-token 派生（funnel 固定 `kind=Service`）。
    ///
    /// 入参收紧为 [`VerifiedServiceToken`]（私有内层 + `pub(crate)` [`VerifiedServiceToken::seal`]，外部
    /// 不可 mint）——与 [`Self::from_verified_jwt`] 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）。
    /// caller 取自载体内**单一 canonical 身份源** [`diport::VerifiedClaims`]（verifier = 信任原点，与
    /// verify→mint bridge [`verify_service_token`] 同源，无分歧）；service shape 恒跨租户。
    pub fn from_verified_service_token(token: &VerifiedServiceToken) -> Result<Self, AuthnError> {
        match token.claims.view() {
            diport::VerifiedClaimsView::ServiceToken { caller, .. } => {
                Self::service_from_subject(caller.as_str())
            }
            diport::VerifiedClaimsView::RssUser { .. }
            | diport::VerifiedClaimsView::FederatedAccess { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => {
                Err(AuthnError::PrincipalInvalid)
            }
        }
    }

    /// Derive the tenant-scoped maintenance service principal from a verifier-only Projection
    /// operator token. Both caller and tenant come from the same signed claims object.
    pub fn from_verified_projection_operator_token(
        token: &VerifiedProjectionOperatorToken,
    ) -> Result<Self, AuthnError> {
        match token.claims.view() {
            diport::VerifiedClaimsView::ProjectionOperator { caller, tenant } => Ok(Self {
                kind: PrincipalKind::Service,
                subject: caller.as_str().to_owned(),
                tenant: Some(tenant),
                service_caller: Some(caller),
            }),
            diport::VerifiedClaimsView::RssUser { .. }
            | diport::VerifiedClaimsView::FederatedAccess { .. }
            | diport::VerifiedClaimsView::ServiceToken { .. } => Err(AuthnError::PrincipalInvalid),
        }
    }

    /// 测试专用构造（不进生产/wire 路径）。
    ///
    /// `#[cfg(any(test, feature = "test-support"))]`：authn 自测 + 下游域 crate（经 `test-support`
    /// feature → `test_support::principal`）共用。生产构建不编译——seal 不变。
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test(
        _kind: PrincipalKind,
        _subject: impl Into<String>,
        _tenant: Option<TenantId>,
    ) -> Self {
        Self {
            kind: _kind,
            subject: _subject.into(),
            tenant: _tenant,
            service_caller: None,
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

    /// Closed caller domain carried only by a verified service-token principal.
    pub fn service_caller_domain(&self) -> Option<vocab::ServiceCallerDomain> {
        self.service_caller
    }

    /// 返回审计用途的已验证 subject。
    ///
    /// 这是唯一暴露 subject 明文的生产 accessor，仅供组合根把已验签主体降维为 `diport::AuditEvent`
    /// / `httpserve::Authenticated` 审计快照。调用方不得把该值写入 tracing / Debug / metrics label；callsite
    /// 由 `rss_authenticated_callsite` dylint 限定在组合根。
    pub fn audit_subject(&self) -> &str {
        &self.subject
    }

    /// 本主体 subject 是否等于 `subject`（**受控比较，不泄露明文 subject**）。
    ///
    /// 授权路径用此判定某条绑定（如 `RoleBinding.subject`）是否归属本 principal——把「绑定属于本主体」
    /// 从调用方预过滤约定（Soft）上移为类型层受控入口：消费方只能问「是否匹配」、拿不到 subject 明文
    /// （PII 不出 authn 边界）。
    pub fn matches_subject(&self, subject: &str) -> bool {
        self.subject == subject
    }

    /// 从 principal + 请求 ctx 派生行级可见性义务（ADR-002）。
    ///
    /// `ctx` 类型为 `runctx::AppCtx`，即 `runctx::RequestCtx<rss_request_context::TenantId, Arc<dyn PrincipalFacet>>`
    /// 别名，遵循 ADR-002 显式传 `&RequestCtx` 而非隐式线程局部的原则（本函数只读 `ctx.tenant()`；
    /// principal payload 供 diport / 审计等其它 ambient 消费者）。
    /// ctx 缺失 fail-closed（返回 [`runctx::MissingCtx`]，绝不伪造 RowScope）。
    ///
    /// scoped 主体（user/device/admin）的行级隔离以**已认证 ctx tenant** 为准，且 fail-closed 要求
    /// principal 自带 tenant claim 与 `*ctx.tenant()` **一致**——不一致（如 tenant-A 令牌在 ctx-B 下）
    /// 返回 `Err`，杜绝越租户派生可见域（tenancy.md §Principal claim source）。
    ///
    /// `SuperAdmin`（跨租户读须经 [`Principal::cross_tenant_audit_grant`] + audit durable receipt）、
    /// `Service` / `Anonymous` 及未来未知 kind 的 `_` 分支返回 `Err(runctx::MissingCtx)`：经此 sync 路径
    /// fail-closed，无可派生行级可见域。`MissingCtx` 是冻结签名唯一 error 通道——消费方须将此 `Err`
    /// **一律按 deny 处理**，不区分「ctx 真缺失」与「主体不可派生 scope」成因（专用错误变体待签名破冻）。
    pub fn row_visibility(
        &self,
        ctx: &runctx::AppCtx,
    ) -> Result<RowVisibility, runctx::MissingCtx> {
        let ctx_tenant = *ctx.tenant();
        // scoped 主体：principal tenant claim 必须与已认证 ctx tenant 一致，否则 fail-closed
        // （防 tenant-A 令牌在 ctx-B 下越权派生可见域，codex review F3）。
        let scoped = |scope: RowScope| match self.tenant {
            Some(t) if t == ctx_tenant => Ok(RowVisibility::new(scope, ctx_tenant)),
            _ => Err(runctx::MissingCtx),
        };
        match self.kind {
            PrincipalKind::User => scoped(RowScope::SelfOnly),
            PrincipalKind::Device => scoped(RowScope::Device),
            PrincipalKind::Admin => scoped(RowScope::Tenant),
            // super-admin 的普通同步 scope 永不签发 All-scope；跨租户读只能经 target-bound grant、
            // route-specific durable append 和 audit-owned receipt 链闭合。
            PrincipalKind::SuperAdmin => Err(runctx::MissingCtx),
            // Service / Anonymous 及 #[non_exhaustive] 未来 kind：fail-closed，无可派生行级可见域。
            _ => Err(runctx::MissingCtx),
        }
    }
}

// ---------------------------------------------------------------------------
// runctx 接缝：Principal → AppCtx（ADR-002 §D5 principal facet 落地）
// ---------------------------------------------------------------------------

/// `Principal` 经 [`runctx::PrincipalFacet`] 擦除注入 [`runctx::AppCtx`] 的 principal payload。
///
/// 生产唯一 impl-er = authn（INVARIANT: PRINCIPAL-FACET-IMPL-AUTHN-01， { level = "Medium", exec = "manual/opt-in", source = "code" }dylint
/// `rss_principal_facet_impl_allowlist` 守，Medium——跨 crate sealed-trait 不可行，ADR-003 §4.2 / ADR-002
/// §D5）。只暴露 vetted **非-PII** facet：`kind`（分类标量）+ `matches_subject`（受控比较，不泄露明文
/// subject）——与 [`Principal::kind`] / [`Principal::matches_subject`] 同语义，subject 明文不出 authn 边界。
impl runctx::PrincipalFacet for Principal {
    fn kind(&self) -> PrincipalKind {
        self.kind
    }

    fn matches_subject(&self, subject: &str) -> bool {
        self.subject == subject
    }
}

/// 由已验证 [`Principal`] 构造 [`runctx::AppCtx`]——**tenant 从 Principal 自身的已验证 claim 派生**，
/// 调用方无法把合法 Principal 与另一个 tenant 错配（#1105 review F1：tenant 与 principal 不可分割，
/// 错配类型层不可表达 / AI-HARD）。
///
/// - scoped 主体（User/Device/Admin，`principal.tenant()==Some(t)`）⇒ `Some(AppCtx)`（绑定该 tenant）。
/// - 跨租户主体（Service/SuperAdmin，`tenant==None`）⇒ `None`：无单一 ambient tenant，不建 scope
///   （消费方 fail-closed `MissingCtx`；跨租户读经显式 grant→append→receipt 路径）。
///
/// `Principal` 经 authn 验签 funnel mint（外部不可伪造）；`Arc<Principal>` 经 unsized 强转为
/// `Arc<dyn PrincipalFacet>`（trait object 廉价共享，满足 `AppCtx: Clone`）。伪造门：外部 crate impl 不了
/// [`runctx::PrincipalFacet`]（dylint 限 authn）、mint 不了 [`Principal`]（验签 seal），故造不出合法 `AppCtx`。
pub fn app_ctx(principal: std::sync::Arc<Principal>) -> Option<runctx::AppCtx> {
    let tenant = principal.tenant()?;
    let facet: std::sync::Arc<dyn runctx::PrincipalFacet> = principal;
    Some(runctx::RequestCtx::new(tenant, facet))
}

// ---------------------------------------------------------------------------
// 跨租户 target-bound 审计 grant（All-scope 仅由 audit durable receipt 消费点铸造）
// ---------------------------------------------------------------------------

pub use crosstenant::{
    CrossTenantAuditContext, CrossTenantAuditError, CrossTenantAuditGrant, CrossTenantGrantError,
};

/// 跨租户主体资格与规范化审计事件 grant。
///
/// # 类型层强制（INVARIANT: TENANCY-CROSSTENANT-AUDIT-01 { level = "Hard", exec = "native-compile", source = "code", native = "private target-bound receipt and sealed mint funnel", facet = "sealed-receipt" }）
///
/// authn 只签发无 visibility 的 [`CrossTenantAuditGrant`]；裸 callback 与 audit sink 不再属于本 API。
/// All-scope 三步唯一在 audit durable receipt 消费点执行，并由 `rss_crosstenant_callsite` 精确函数门守护。
///
/// # Deny / ledger 边界（#1288）
///
/// grant API **仅**在 Success 路径规范化审计事件（`AuditOutcome::Success`）；deny 侧 ledger
/// （谁被拒、为何被拒）是调用方（audit 域）责任，不经本 API 回写，也不再注入 `AuditSink`。
/// [`CrossTenantGrantError::NotSuperAdmin`] 是 defense-in-depth 资格不变式（非 super-admin 绝不 mint
/// grant），**不是**「未审计的 403」语义——调用方须自行记录 deny 后再对外映射 HTTP 状态。
mod crosstenant {
    use super::Principal;
    use rss_request_context::PrincipalKind;

    /// 跨租户审计 grant 派生失败（fail-closed）：非 super-admin 不签发 grant。
    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum CrossTenantGrantError {
        /// 主体非 super-admin——无跨租户派生资格（不静默降级）。
        #[error("principal is not a super-admin")]
        NotSuperAdmin,
    }

    /// 跨租户审计上下文构造失败（fail-closed）：任一字段空 ⇒ 不得构造，杜绝不完整 ledger 签发 All-scope。
    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum CrossTenantAuditError {
        /// 审计字段为空——跨租户 All-scope 派生要求字段完整（tenancy.md §RowScope：
        /// tenant/principal/resource/action/request/correlation）。
        #[error("cross-tenant audit context field must be non-empty")]
        EmptyField,
    }

    /// super-admin 跨租户派生的审计上下文（funnel 入参）。
    ///
    /// `request_id` / `correlation_id` 是诊断信号、**不**在 `AppCtx`（runctx 边界约定），由 httpserve W
    /// middleware 注入。私有字段 + [`Self::new`] **fail-closed** 构造 funnel（input-struct-field-exclusion +
    /// 非空校验）：持有一个 `CrossTenantAuditContext` ⇒ 全字段非空（tenancy.md §RowScope 完整性，bundle 级
    /// Hard），funnel 据此签发 All-scope 时审计字段不缺。不 derive `Serialize`；Debug 脱敏
    /// `resource_id` / `request_id` / `correlation_id`（零信任，对齐 `diport::AuditEvent`，
    /// DIPORT-DTO-PII-DEBUG-REDACT-01 同范式）。
    pub struct CrossTenantAuditContext {
        resource_kind: &'static str,
        resource_id: String,
        action: &'static str,
        request_id: String,
        correlation_id: String,
    }

    impl CrossTenantAuditContext {
        /// 构造审计上下文（**fail-closed**：任一字段空 → `Err(CrossTenantAuditError::EmptyField)`，杜绝
        /// 不完整 ledger 签发 All-scope，tenancy.md §RowScope）。
        ///
        /// # Arguments
        /// - `resource_kind`：资源类别 const literal（如 `"cross_tenant_visibility"`）——与 `action` **同为
        ///   `&'static str`，勿混淆顺序**（类型相同、误置编译器不报错）；非空。
        /// - `resource_id`：资源标识（非空；裸 `String`，typed-id 待 diport W 阶段，对齐 `AuditEvent.resource_id`）。
        /// - `action`：操作动作 const literal（如 `"derive_all_scope"`）；非空。
        /// - `request_id` / `correlation_id`：**必填非空**——httpserve W middleware 注入；跨租户审计要求完整
        ///   请求 / 关联上下文（tenancy.md §RowScope），空即拒绝构造（不再接受缺失）。
        pub fn new(
            resource_kind: &'static str,
            resource_id: impl Into<String>,
            action: &'static str,
            request_id: impl Into<String>,
            correlation_id: impl Into<String>,
        ) -> Result<Self, CrossTenantAuditError> {
            let resource_id = resource_id.into();
            let request_id = request_id.into();
            let correlation_id = correlation_id.into();
            // fail-closed：跨租户 All-scope 审计字段须完整（tenancy.md §RowScope），任一空即拒绝。
            if resource_kind.is_empty()
                || resource_id.is_empty()
                || action.is_empty()
                || request_id.is_empty()
                || correlation_id.is_empty()
            {
                return Err(CrossTenantAuditError::EmptyField);
            }
            Ok(Self {
                resource_kind,
                resource_id,
                action,
                request_id,
                correlation_id,
            })
        }
    }

    // PII 边界（对齐 diport::AuditEvent）：resource_id / request_id / correlation_id 脱敏（必填非空、无 None
    // 形态）；resource_kind / action 为 const literal 可观测。
    impl std::fmt::Debug for CrossTenantAuditContext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CrossTenantAuditContext")
                .field("resource_kind", &self.resource_kind)
                .field("resource_id", &"<redacted>")
                .field("action", &self.action)
                .field("request_id", &"<redacted>")
                .field("correlation_id", &"<redacted>")
                .finish()
        }
    }

    /// authn-owned target-bound grant：证明已验证主体可为该目标发起跨租户审计请求。
    ///
    /// grant **不含** All-scope visibility，也不声称持久审计已经完成；audit 域必须消费其中的规范化事件，
    /// 成功写入 typed durable appender 后才能铸造 read scope。私有字段与非 Clone 语义禁止调用方重组
    /// target/event，且彻底删除了“任意成功 callback 即视为 durable”的旁路。
    pub struct CrossTenantAuditGrant {
        target: rss_request_context::TenantId,
        event: diport::AuditEvent,
        _seal: (),
    }

    impl CrossTenantAuditGrant {
        /// 该授权 grant 绑定的目标租户。
        pub fn target(&self) -> rss_request_context::TenantId {
            self.target
        }

        /// 消费 grant，取得必须由 audit 域持久化的规范化事件。
        pub fn into_event(self) -> diport::AuditEvent {
            self.event
        }
    }

    impl Principal {
        /// 从已验证 super-admin 派生 target-bound 审计 grant。
        ///
        /// 此入口只证明主体资格并规范化事件，绝不签发 All-scope。audit 域消费 grant、完成
        /// route-specific typed durable append 后才可铸造 read scope。
        /// `clock` 取注入 [`diport::Clock`]（`occurred_at` 非系统时钟，rust-standards Clock 纪律）；`audit` 承载
        /// caller 提供的审计字段（super-admin 自身 `tenant=None`，`tenant_id` 取 ctx 行使 All-scope 的租户上下文）。
        pub fn cross_tenant_audit_grant(
            &self,
            ctx: &runctx::AppCtx,
            clock: &dyn diport::Clock,
            audit: &CrossTenantAuditContext,
        ) -> Result<CrossTenantAuditGrant, CrossTenantGrantError> {
            if self.kind != PrincipalKind::SuperAdmin {
                return Err(CrossTenantGrantError::NotSuperAdmin);
            }
            let event = diport::AuditEvent {
                occurred_at: clock.now(),
                principal_id: self.subject.clone(),
                principal_kind: self.kind,
                // reason: super-admin 自身 tenant=None；审计记录「行使 All-scope 的目标租户」= ctx.tenant，非自身 tenant。
                tenant_id: Some(*ctx.tenant()),
                resource_kind: audit.resource_kind,
                resource_id: audit.resource_id.clone(),
                action: audit.action,
                outcome: diport::AuditOutcome::Success,
                // CrossTenantAuditContext 已 fail-closed 保证非空（tenancy.md §RowScope 完整性）。
                request_id: Some(audit.request_id.clone()),
                correlation_id: Some(audit.correlation_id.clone()),
            };
            Ok(CrossTenantAuditGrant {
                target: *ctx.tenant(),
                event,
                _seal: (),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 测试支撑（`test-support` feature）：下游域 crate 单测构造 Principal
// ---------------------------------------------------------------------------

/// 测试支撑——仅 `test-support` feature（test/dev 构建）启用，生产不编译。
///
/// 下游域 crate（如 `identity`）的 authz 纯逻辑单测（`authorize_rbac(&Principal, …)`）需带特定
/// `tenant` 的 [`Principal`]，但生产派生入口收紧为已验签 newtype（`VerifiedJwt` 等，`pub(crate)` seal，
/// 外部 crate 不可 mint，INVARIANT AUTHN-VERIFIEDJWT-SEAL-01）。本模块经 feature 门控暴露受控测试构造器，
/// **不削弱生产 seal**（生产构建 feature off ⇒ 本模块及 [`Principal::for_test`] 均不编译）。与既有
/// `runctx::test_support` 同信任模型。
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::{
        AccessToken, Principal, PrincipalKind, VerifiedMaintenanceServiceOperator,
        VerifiedServiceToken,
    };
    use rss_request_context::TenantId;

    /// 构造测试 [`Principal`]（kind / subject / tenant 任意；不进生产 / wire 路径）。
    pub fn principal(
        kind: PrincipalKind,
        subject: impl Into<String>,
        tenant: Option<TenantId>,
    ) -> Principal {
        Principal::for_test(kind, subject, tenant)
    }

    /// Construct a test service principal from the same closed caller domain used in production.
    pub fn service_principal(caller: vocab::ServiceCallerDomain) -> Principal {
        Principal {
            kind: PrincipalKind::Service,
            subject: caller.as_str().to_owned(),
            tenant: None,
            service_caller: Some(caller),
        }
    }

    /// Construct a sealed maintenance service-operator proof for adapter capability mint tests.
    pub fn maintenance_service_operator_proof() -> VerifiedMaintenanceServiceOperator {
        VerifiedMaintenanceServiceOperator::try_from_verified_service_token(
            &VerifiedServiceToken::seal(
                AccessToken::new("opaque"),
                diport::VerifiedClaims::service_token(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                        .expect("canonical tenant"),
                ),
            ),
        )
        .unwrap_or_else(|_| {
            unreachable!("MaintenanceOperator service-token claims must mint the sealed proof")
        })
    }
}

// ---------------------------------------------------------------------------
// verify→mint bridge（authn-owned 验签 → 受控 mint，#1158）
// ---------------------------------------------------------------------------
//
// INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }（生产端闭环）。`seal` 是 `pub(crate)`——外部 crate 无法 mint
// `VerifiedJwt` / `VerifiedServiceToken`（Hard，消费端见 `verified_token_seal` + `tests/ui/`）。本 bridge
// 是 authn 内**唯一生产 mint 路径**：经注入的 [`diport::Pdp`] 验签（profile、签名/MAC、时间与
// profile claims）成功后，才在 crate 内
// 调 `seal` 装箱、并据**验签产物** [`diport::VerifiedClaims`] 派生 `Principal`（验签 = 信任原点，非旁路
// re-parse）。验签**先于** seal 由 `?`-链顺序保证：`pdp.verify(...).await?` 失败即返回，绝不 seal。
// 生产 runtime 以 exhaustive profile binding 把 listener、provider 与对应 funnel 同批绑定；HTTP 边界
// 在调用本 bridge 前完成 exact-one header 提取。决策 telemetry 位于该 runtime bridge，且不记录凭据值。

/// 验签并 mint RSS access token：profile 在进入 provider 前由本 funnel 固定。
///
/// `pdp` 取 dynosaur wrapper `&DynPdp`（caller 可持 `Box<DynPdp>` / `Arc<DynPdp>` 或静态 impl）。返回的
/// `VerifiedJwt` 内携**单一 canonical 身份源** `VerifiedClaims`——`Principal` 与该载体经 `from_verified_jwt`
/// 同源派生，一个载体只导出一个 principal（F1）。`Principal` 刻意不 derive `Debug`（含 PII）——消费 / 测试
/// 经 `.kind()` / `.tenant()` 访问器断言，不 debug 格式化整个元组。
pub async fn verify_rss_access(
    raw: &str,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedJwt, Principal), AuthnError> {
    verify_access(raw, diport::RawCredential::rss_access(raw), pdp).await
}

/// 验签并 mint federated access token：与 RSS access 共用私有 seal core，但构造不同 profile
/// credential，因此 listener/provider 错配在任何 token 解析前即可拒绝。
pub async fn verify_federated_access(
    raw: &str,
    pdp: &diport::DynPdp<'_>,
) -> Result<VerifiedFederatedAccess, AuthnError> {
    let (verified_jwt, principal) =
        verify_access(raw, diport::RawCredential::federated_access(raw), pdp).await?;
    Ok(VerifiedFederatedAccess {
        verified_jwt,
        principal: std::sync::Arc::new(principal),
    })
}

async fn verify_access(
    raw: &str,
    credential: diport::RawCredential,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedJwt, Principal), AuthnError> {
    // ① 验签（信任原点）：失败即 fail-closed，下方 seal / 派生均不可达。
    let claims = pdp.verify(&credential).await?;
    let profile_matches = matches!(
        (claims.view(), credential.profile()),
        (
            diport::VerifiedClaimsView::RssUser { .. },
            diport::TokenProfile::RssAccess
        ) | (
            diport::VerifiedClaimsView::FederatedAccess { .. },
            diport::TokenProfile::FederatedAccess
        )
    );
    if !profile_matches {
        return Err(AuthnError::PrincipalInvalid);
    }
    // ② 结构防御闸（defense-in-depth）：raw 须 well-formed JWT（3 段 + base64url），否则 TokenInvalid——
    //    防 lenient adapter 对畸形 token 误判 ok。解析产物丢弃，仅校验结构（身份在 ④ 取自 VerifiedClaims）。
    Jwt::parse(raw)?;
    // ③ 受控 mint：载体携 raw（供下游 token relay）+ **单一 canonical 身份源** claims。
    let verified = VerifiedJwt::seal(raw.to_string(), claims);
    // ④ 据载体单一身份源派生主体（与 from_verified_jwt 同 funnel，无第二（raw 重解析）身份源、无分歧）。
    let principal = Principal::from_verified_jwt(&verified)?;
    Ok((verified, principal))
}

/// 验签并 mint service-token：funnel 固定 `kind=Service`、`subject` 取自验签产物。
///
/// service token 结构由 verifier（[`diport::Pdp`]）负责，authn 不 re-parse——故 `raw` 对 authn 不透明，
/// 受控 seal 进 [`VerifiedServiceToken`]（携 raw + 单一 canonical 身份源 `VerifiedClaims`）。
pub async fn verify_service_token(
    raw: &str,
    binding: diport::ServiceTokenTenantBinding,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedServiceToken, Principal), AuthnError> {
    let claims = pdp
        .verify(&diport::RawCredential::service_token(raw, binding))
        .await?;
    if !matches!(
        claims.view(),
        diport::VerifiedClaimsView::ServiceToken { .. }
    ) {
        return Err(AuthnError::PrincipalInvalid);
    }
    let verified = VerifiedServiceToken::seal(AccessToken::new(raw), claims);
    let principal = Principal::from_verified_service_token(&verified)?;
    Ok((verified, principal))
}

/// Verify and seal a verifier-only Projection maintenance operator token.
///
/// Unlike the general service-token funnel, tenant authority is an ES256-signed claim and no
/// ambient tenant header participates in verification.
pub async fn verify_projection_operator_token(
    raw: &str,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedProjectionOperatorToken, Principal), AuthnError> {
    let claims = pdp
        .verify(&diport::RawCredential::projection_operator(raw))
        .await?;
    if !matches!(
        claims.view(),
        diport::VerifiedClaimsView::ProjectionOperator { .. }
    ) {
        return Err(AuthnError::PrincipalInvalid);
    }
    let verified = VerifiedProjectionOperatorToken::seal(AccessToken::new(raw), claims);
    let principal = Principal::from_verified_projection_operator_token(&verified)?;
    Ok((verified, principal))
}

// ---------------------------------------------------------------------------
// JWT / token 值类型
// ---------------------------------------------------------------------------

/// A single, non-forgeable federated authentication result.
///
/// Identity and route grants are derived from the same verifier-owned [`diport::VerifiedClaims`]
/// carried by `verified_jwt`. Private fields prevent callers from pairing one verified identity
/// with another token's permissions.
pub struct VerifiedFederatedAccess {
    verified_jwt: VerifiedJwt,
    principal: std::sync::Arc<Principal>,
}

impl std::fmt::Debug for VerifiedFederatedAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedFederatedAccess(<redacted>)")
    }
}

impl VerifiedFederatedAccess {
    pub fn principal(&self) -> &Principal {
        self.principal.as_ref()
    }

    pub fn principal_arc(&self) -> std::sync::Arc<Principal> {
        std::sync::Arc::clone(&self.principal)
    }

    pub fn allows_route(&self, permission: vocab::RoutePermissionId) -> bool {
        match self.verified_jwt.claims.view() {
            diport::VerifiedClaimsView::FederatedAccess { permissions, .. } => {
                permissions.allows_route(permission)
            }
            diport::VerifiedClaimsView::RssUser { .. }
            | diport::VerifiedClaimsView::ServiceToken { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => false,
        }
    }

    pub fn permissions(&self) -> &diport::VerifiedFederatedPermissions {
        match self.verified_jwt.claims.view() {
            diport::VerifiedClaimsView::FederatedAccess { permissions, .. } => permissions,
            diport::VerifiedClaimsView::RssUser { .. }
            | diport::VerifiedClaimsView::ServiceToken { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => {
                unreachable!("federated access carrier always holds federated claims")
            }
        }
    }
}

/// JWT 原始令牌（私有字段；不 derive `Serialize`；构造经结构闸 funnel）。
///
/// `Jwt` 是 **结构载体**——`parse` 校验 token 结构（3 段 / base64url / JSON / 非空 sub）但**不**承载身份。
/// 身份 claims 由 verifier 经 [`diport::VerifiedClaims`] 提供（verify→mint bridge 用 `Jwt::parse` 作结构闸）。
pub struct Jwt {
    raw: String,
}

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Jwt(<redacted>)")
    }
}

impl Jwt {
    /// 结构校验并装箱（不验签、不校验 exp、不提取身份 claims——签名/身份归 verifier）。
    pub fn parse(raw: &str) -> Result<Self, AuthnError> {
        decode_claims(raw)?; // 结构闸：3 段 + base64url + JSON + 非空 sub（产物丢弃，仅校验副作用）。
        Ok(Self {
            raw: raw.to_string(),
        })
    }

    /// 取令牌字符串引用（只读，不 clone）。
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// 已验证 JWT 载体（私有字段；外部 crate 无法 mint；不 derive `Serialize`）。
///
/// # 类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）
///
/// 把「未经验签派生 Principal」收口到类型层（Hard，newtype funnel）：[`Principal::from_verified_jwt`]
/// 只收 `&VerifiedJwt`，而 `VerifiedJwt` 仅经 `pub(crate)` [`Self::seal`] 装箱——外部 crate 既不能命名
/// 私有字段、也不能调 `pub(crate)` 构造，故无法伪造已验证主体。`Debug` 脱敏。
///
/// **单一 canonical 身份源（F1）**：载体内 `claims`（验签产物 [`diport::VerifiedClaims`]，verifier =
/// 信任原点）是**唯一**身份源；`raw` 仅是原始 token 串（供下游 token relay），**不派生身份**。
/// 故一个 `VerifiedJwt` 只能经 `from_verified_jwt` 导出**一个** principal——无第二（raw 重解析）身份源、
/// 无分歧。access bridge 与 `from_verified_jwt` 读同一 `claims`。
///
/// ⚠ `seal` 的 `pub(crate)` 可见性是本不变式锚点：改为 `pub` 会让外部可 mint，Hard 静默退化为 Soft。
/// 改 `pub` 须经 ADR amendment；机器守（`cargo public-api` golden）跟踪见 #1151。**生产端**经 authn-owned
/// access verification funnels 闭环；外部 crate 不可达（`tests/ui/` compile-fail 锁）。
pub struct VerifiedJwt {
    /// 原始已验证 token 串（供下游 token relay；**不派生身份**——身份用 [`Principal::from_verified_jwt`]）。
    raw: String,
    /// 验签产物 = 单一 canonical 身份源。
    claims: diport::VerifiedClaims,
}

impl std::fmt::Debug for VerifiedJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedJwt(<redacted>)")
    }
}

impl VerifiedJwt {
    /// 受控装箱：把已验签 token（`raw`）+ 验签产物 `claims` 标记为 [`VerifiedJwt`]（`pub(crate)`，**不验签**）。
    ///
    /// 调用方须已经 verifier 完成验签（签名/exp/MAC）——本函数只做类型层标记。生产唯一调用方是
    /// authn-owned access verification funnels，`seal` 保持 `pub(crate)`。
    pub(crate) fn seal(raw: String, claims: diport::VerifiedClaims) -> Self {
        Self { raw, claims }
    }

    /// 原始已验证 token 串（供下游 token relay；不派生身份）。
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Borrow the durable grant facts carried only by an RSS User access token.
    pub fn grant_receipt(&self) -> Option<VerifiedGrantReceipt<'_>> {
        match self.claims.view() {
            diport::VerifiedClaimsView::RssUser {
                user_id,
                tenant,
                grant,
            } => Some(VerifiedGrantReceipt {
                user_id,
                tenant,
                grant,
            }),
            diport::VerifiedClaimsView::FederatedAccess { .. }
            | diport::VerifiedClaimsView::ServiceToken { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => None,
        }
    }
}

/// Read-only borrowed receipt for one verified local access-token grant binding.
pub struct VerifiedGrantReceipt<'a> {
    user_id: ids::UserId,
    tenant: TenantId,
    grant: &'a diport::VerifiedAccessGrantFacts,
}

impl std::fmt::Debug for VerifiedGrantReceipt<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedGrantReceipt(<redacted>)")
    }
}

impl VerifiedGrantReceipt<'_> {
    pub fn grant_id(&self) -> AuthGrantId {
        AuthGrantId::from_verified(self.grant.session_id())
    }

    pub fn token_id(&self) -> ids::CanonicalUuidV4 {
        self.grant.token_id()
    }

    pub fn auth_time_unix_secs(&self) -> u64 {
        self.grant.auth_time_unix_secs()
    }

    pub fn authn_epoch(&self) -> u64 {
        self.grant.authn_epoch()
    }

    /// Consume the borrowed receipt into the only owned request accepted by the durable grant
    /// validator. Callers cannot select or replace any binding field.
    pub fn into_validation_input(self) -> AccessGrantValidationInput {
        AccessGrantValidationInput {
            grant_id: AuthGrantId::from_verified(self.grant.session_id()),
            user_id: self.user_id,
            tenant: self.tenant,
            auth_time_unix_secs: self.grant.auth_time_unix_secs(),
            authn_epoch: AuthnEpoch::from_verified(self.grant.authn_epoch()),
        }
    }
}

/// Owned, source-bound input for one durable access-request grant validation.
///
/// Fields are private and the only constructor consumes [`VerifiedGrantReceipt`], so tenant,
/// subject, grant id, authentication time and epoch cannot be supplied independently.
pub struct AccessGrantValidationInput {
    grant_id: AuthGrantId,
    user_id: ids::UserId,
    tenant: TenantId,
    auth_time_unix_secs: u64,
    authn_epoch: AuthnEpoch,
}

impl std::fmt::Debug for AccessGrantValidationInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AccessGrantValidationInput(<redacted>)")
    }
}

impl AccessGrantValidationInput {
    pub fn grant_id(&self) -> &AuthGrantId {
        &self.grant_id
    }

    pub fn user_id(&self) -> ids::UserId {
        self.user_id
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    pub fn auth_time_unix_secs(&self) -> u64 {
        self.auth_time_unix_secs
    }

    pub fn authn_epoch(&self) -> AuthnEpoch {
        self.authn_epoch
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

/// 已验证 service-token 载体（私有字段；外部 crate 无法 mint；不 derive `Serialize`）。
///
/// 与 [`VerifiedJwt`] 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }）+ **单一 canonical 身份源**
/// （F1）：[`Principal::from_verified_service_token`] 只收 `&VerifiedServiceToken`，从载体内 `claims`
/// （验签产物 [`diport::VerifiedClaims`]）派生身份；`token` 仅是原始串（relay 用，不派生身份）。仅经
/// `pub(crate)` [`Self::seal`] 装箱（同 [`VerifiedJwt`] 锚点，机器守见 #1151）。生产 mint 仅由
/// [`verify_service_token`] 调用。
pub struct VerifiedServiceToken {
    /// 原始已验证 service token（relay 用，不派生身份）。
    token: AccessToken,
    /// 验签产物 = 单一 canonical 身份源。
    claims: diport::VerifiedClaims,
}

impl std::fmt::Debug for VerifiedServiceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedServiceToken(<redacted>)")
    }
}

impl VerifiedServiceToken {
    /// 受控装箱：把已验签 [`AccessToken`] + 验签产物 `claims` 标记为 [`VerifiedServiceToken`]
    /// （`pub(crate)`，**不验签**）。生产唯一调用方是 authn-owned [`verify_service_token`]。
    pub(crate) fn seal(token: AccessToken, claims: diport::VerifiedClaims) -> Self {
        Self { token, claims }
    }

    /// 原始已验证 service token 串（供下游 relay；不派生身份）。
    pub fn raw(&self) -> &str {
        self.token.as_str()
    }

    /// Signed canonical tenant carried by the verified service-token claims.
    ///
    /// This is the sole ambient tenant authority for service-token routes; header challengers never
    /// become a second source.
    pub fn tenant(&self) -> Result<rss_request_context::TenantId, AuthnError> {
        match self.claims.view() {
            diport::VerifiedClaimsView::ServiceToken { tenant, .. } => Ok(tenant),
            _ => Err(AuthnError::PrincipalInvalid),
        }
    }
}

/// Sealed proof that a verified **service-token** profile carries the maintenance operator caller.
///
/// Hard boundary for config-value maintenance capability mint: only
/// [`Self::try_from_verified_service_token`] constructs this type, and that funnel rejects every
/// non-`ServiceToken` claims view (including ProjectionOperator) and every non-maintenance caller.
/// There is no constructor from [`Principal`] or [`VerifiedProjectionOperatorToken`].
pub struct VerifiedMaintenanceServiceOperator {
    principal: Principal,
}

impl std::fmt::Debug for VerifiedMaintenanceServiceOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedMaintenanceServiceOperator(<redacted>)")
    }
}

impl VerifiedMaintenanceServiceOperator {
    /// Narrow a verified service-token carrier to the maintenance-operator service proof.
    pub fn try_from_verified_service_token(
        token: &VerifiedServiceToken,
    ) -> Result<Self, AuthnError> {
        match token.claims.view() {
            diport::VerifiedClaimsView::ServiceToken {
                caller: vocab::ServiceCallerDomain::MaintenanceOperator,
                ..
            } => Ok(Self {
                principal: Principal::from_verified_service_token(token)?,
            }),
            // Non-service-token shapes (incl. ProjectionOperator) never mint this proof.
            // New ServiceCallerDomain variants make this match non-exhaustive → compile fail.
            diport::VerifiedClaimsView::RssUser { .. }
            | diport::VerifiedClaimsView::FederatedAccess { .. }
            | diport::VerifiedClaimsView::ProjectionOperator { .. } => {
                Err(AuthnError::PrincipalInvalid)
            }
        }
    }

    /// Borrow the sealed principal derived with this proof (not a capability mint input).
    ///
    /// Durable audit subject downshift must go through the combination-root allowlisted wrapper
    /// (`service_maintenance_operator_audit_subject`), not a parallel public string accessor.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
}

/// Non-forgeable result of Projection operator JWKS verification.
pub struct VerifiedProjectionOperatorToken {
    token: AccessToken,
    claims: diport::VerifiedClaims,
}

impl std::fmt::Debug for VerifiedProjectionOperatorToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProjectionOperatorToken(<redacted>)")
    }
}

impl VerifiedProjectionOperatorToken {
    pub(crate) fn seal(token: AccessToken, claims: diport::VerifiedClaims) -> Self {
        Self { token, claims }
    }

    /// Signed canonical tenant carried by the verified token.
    pub fn tenant(&self) -> Result<rss_request_context::TenantId, AuthnError> {
        match self.claims.view() {
            diport::VerifiedClaimsView::ProjectionOperator { tenant, .. } => Ok(tenant),
            _ => Err(AuthnError::PrincipalInvalid),
        }
    }

    pub fn raw(&self) -> &str {
        self.token.as_str()
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

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// 认证层错误（库枚举；用 `thiserror`；message 为 const 静态字面量）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthnError {
    /// 凭据**签名 / MAC / 结构完整性**校验失败（verifier 报 [`diport::PdpError::InvalidSignature`]：签名 / MAC
    /// 校验失败、token 段数畸形、alg 不白名单、payload JSON 坏）。verify 层只做认证（非授权），故凭据无效一律
    /// 401 invalid_token（RFC 6750 §3.1），403 留给 authz 层「已认证但无权」。
    ///
    /// **本变体专指 verifier 报告的凭据签名失败**——验签**通过后**的 claims 结构闸 / principal 派生失败归
    /// [`AuthnError::PrincipalInvalid`]，**不复用本变体**（#1275 review F1：避免 deny 路把良性 claims 失败误报成
    /// `signature_invalid` 攻击信号）。
    #[error("token is invalid")]
    TokenInvalid,
    /// 凭据经 verifier 验签**通过**（签名 / iss / aud / exp 均 OK），但 authn 无法据其 claims 派生有效
    /// [`Principal`]：claims 结构畸形（防 lenient adapter 的结构闸）、未知 / 缺失 kind、scoped 主体缺 tenant /
    /// tenant 非 canonical UUID、空 subject。
    ///
    /// **wire 语义与 [`AuthnError::TokenInvalid`] 相同**——同为 401 invalid_token（RFC 6750 §3.1，**非** 403）；
    /// 独立变体使 deny 路 `authz.deny_reason` 区分**疑似攻击的签名失败**（`TokenInvalid`）vs **良性的 claims /
    /// principal 派生失败**（本变体），不把后者误报成 `signature_invalid`（#1275 review F1）。
    #[error("principal cannot be derived")]
    PrincipalInvalid,
    /// 凭据来源 / 路径不受信（verifier 报 [`diport::PdpError::Untrusted`]：iss / aud / key-path 不受信 / 未知 scheme）。
    /// **wire 语义与 [`AuthnError::TokenInvalid`] 相同**——同为 401 invalid_token（RFC 6750 §3.1，**非** 403）；
    /// 独立变体仅为 deny 路 tracing 告警分级（区分疑似配置错 `Untrusted` vs 疑似攻击 `InvalidSignature`，#1275 /
    /// spec SC-006），不改 HTTP 状态。
    #[error("token is untrusted")]
    TokenUntrusted,
    /// 令牌过期（verifier 报 [`diport::PdpError::Expired`]，经 verify→mint bridge 的 `From<PdpError>` 产生）。
    #[error("token is expired")]
    TokenExpired,
    /// 凭据验证所依赖的安全关键 provider 暂不可用。该状态仍 fail-closed，但必须与无效凭据分离，
    /// 以便 runtime 返回可重试的 503，而不是把基础设施故障伪装成调用方 401。
    #[error("authentication provider is unavailable")]
    ProviderUnavailable,
    /// 主体已认证但无权（403 insufficient permission）。**本 crate 当前不可达**——由后续 authz / ABAC 层
    /// 产生；verify→mint bridge **不**产此态（凭据不可信 / 无效归 401 拒绝态 `TokenInvalid` / `TokenUntrusted` /
    /// `PrincipalInvalid` / `TokenExpired`，RFC 6750 §3.1）。
    #[error("principal not permitted")]
    Forbidden,
}

/// 验签 port 错误 → 认证错误映射（verify→mint bridge 经 `?` 使用，#1158）。fail-closed：所有 `PdpError`
/// 变体均映射到**拒绝**态，绝不静默成功；`PdpError` 是 `#[non_exhaustive]`，未来变体默认落 `TokenInvalid`。
///
/// 四变体一一保真：三种凭据失败保持 401 `invalid_token` 语义；`ProviderUnavailable` 单列
/// [`AuthnError::ProviderUnavailable`]，使 runtime 能返回可重试 503，且不会误记为签名攻击。
impl From<diport::PdpError> for AuthnError {
    fn from(e: diport::PdpError) -> Self {
        match e {
            diport::PdpError::InvalidSignature => AuthnError::TokenInvalid,
            diport::PdpError::Expired => AuthnError::TokenExpired,
            // verify 层纯认证：Untrusted（iss / key / aud 不受信 / 未知 alg / kid 无匹配）= 凭据无效 →
            // 401 invalid_token（RFC 6750 §3.1），非 403 Forbidden（后者留给 authz 层「已认证但无权」）。
            diport::PdpError::Untrusted => AuthnError::TokenUntrusted,
            diport::PdpError::ProviderUnavailable => AuthnError::ProviderUnavailable,
            // PdpError #[non_exhaustive]：未来变体 fail-closed 落 TokenInvalid（默认拒绝，无静默成功）。
            _ => AuthnError::TokenInvalid,
        }
    }
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
mod principal_facet_tests {
    //! `Principal` → `runctx::PrincipalFacet` 擦除 + [`super::app_ctx`] mint（ADR-002 §D5，#1105）。
    //! facet 只暴露 vetted 非-PII（kind / 受控 subject 比较）；`app_ctx` 把已验证 Principal + 已认证
    //! tenant 装进 `runctx::AppCtx`，供验签桥经 `runctx::scope` 绑定 ambient。
    use super::{CANON_TENANT, Principal, PrincipalKind, app_ctx};
    use rss_request_context::TenantId;
    use runctx::PrincipalFacet;
    use std::sync::Arc;

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    // facet 暴露 kind + 受控 subject 比较（不泄露明文）。
    #[test]
    fn facet_exposes_kind_and_controlled_subject_match() {
        let p = Principal::for_test(PrincipalKind::User, "alice", Some(tenant()));
        assert_eq!(PrincipalFacet::kind(&p), PrincipalKind::User);
        assert!(PrincipalFacet::matches_subject(&p, "alice"));
        assert!(!PrincipalFacet::matches_subject(&p, "bob"));
    }

    // app_ctx 从 Principal 自身 tenant 派生 AppCtx（scoped 主体 → Some）；ambient 消费者经访问器取回 vetted facet。
    #[test]
    #[allow(clippy::expect_used)]
    fn app_ctx_derives_tenant_for_scoped_principal() {
        let tid = tenant();
        let p = Arc::new(Principal::for_test(
            PrincipalKind::Admin,
            "admin1",
            Some(tid),
        ));
        let ctx = app_ctx(p).expect("scoped principal (有 tenant) 应 mint AppCtx");
        // tenant 来自 principal 自身 claim，调用方无从错配（F1）。
        assert_eq!(ctx.tenant(), &tid);
        assert_eq!(ctx.principal().kind(), PrincipalKind::Admin);
        assert!(ctx.principal().matches_subject("admin1"));
        assert!(!ctx.principal().matches_subject("intruder"));
    }

    // 跨租户主体（Service/SuperAdmin，tenant=None）→ app_ctx 返回 None（不建 ambient scope）。
    #[test]
    fn app_ctx_none_for_cross_tenant_principal() {
        let service = Arc::new(Principal::for_test(PrincipalKind::Service, "svc", None));
        assert!(
            app_ctx(service).is_none(),
            "service 主体无单一 tenant ⇒ app_ctx None"
        );
        let super_admin = Arc::new(Principal::for_test(PrincipalKind::SuperAdmin, "root", None));
        assert!(
            app_ctx(super_admin).is_none(),
            "superAdmin 跨租户 ⇒ app_ctx None"
        );
    }
}

#[cfg(test)]
mod projection_maintenance_receipt_tests {
    use super::*;

    fn tenant(raw: &str) -> TenantId {
        TenantId::parse(raw).unwrap_or_else(|_| unreachable!("static tenant fixture is valid"))
    }

    fn service() -> Principal {
        Principal::service_from_subject(vocab::ServiceCallerDomain::MaintenanceOperator.as_str())
            .unwrap_or_else(|_| unreachable!("closed caller is valid"))
    }

    #[test]
    fn receipt_requires_exact_verified_service_action_tenant_and_projection() {
        let target_tenant = tenant("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        let other_tenant = tenant("f47ac10b-58cc-4372-a567-0e02b2c3d480");
        let grants = ProjectionMaintenanceGrantSet::new(vec![
            ProjectionMaintenanceGrant::new(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                ProjectionMaintenanceAction::Replay,
                target_tenant,
                "audit.session-projection",
            )
            .unwrap_or_else(|_| unreachable!("static grant fixture is valid")),
        ])
        .unwrap_or_else(|_| unreachable!("static grant set is non-empty"));

        let receipt = grants
            .authorize(
                &service(),
                ProjectionMaintenanceAction::Replay,
                target_tenant,
                "audit.session-projection",
            )
            .unwrap_or_else(|_| unreachable!("exact grant must authorize"));
        assert!(receipt.authorizes(
            ProjectionMaintenanceAction::Replay,
            target_tenant,
            "audit.session-projection"
        ));
        assert!(!receipt.authorizes(
            ProjectionMaintenanceAction::Status,
            target_tenant,
            "audit.session-projection"
        ));
        assert!(!receipt.authorizes(
            ProjectionMaintenanceAction::Replay,
            other_tenant,
            "audit.session-projection"
        ));
        assert!(matches!(
            grants.authorize(
                &Principal::for_test(PrincipalKind::Service, "another-service", None),
                ProjectionMaintenanceAction::Replay,
                target_tenant,
                "audit.session-projection"
            ),
            Err(ProjectionMaintenanceGrantError::Forbidden)
        ));
    }

    #[test]
    fn grant_inputs_fail_closed_and_receipt_debug_uses_typed_caller() {
        let target_tenant = tenant("f47ac10b-58cc-4372-a567-0e02b2c3d479");
        assert!(matches!(
            ProjectionMaintenanceGrantSet::new(Vec::new()),
            Err(ProjectionMaintenanceGrantError::EmptySet)
        ));

        let grants = ProjectionMaintenanceGrantSet::new(vec![
            ProjectionMaintenanceGrant::new(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                ProjectionMaintenanceAction::Status,
                target_tenant,
                "audit.session-projection",
            )
            .unwrap_or_else(|_| unreachable!("static grant fixture is valid")),
        ])
        .unwrap_or_else(|_| unreachable!("static grant set is non-empty"));
        let receipt = grants
            .authorize(
                &service(),
                ProjectionMaintenanceAction::Status,
                target_tenant,
                "audit.session-projection",
            )
            .unwrap_or_else(|_| unreachable!("exact grant must authorize"));
        assert_eq!(
            receipt.operator_caller(),
            vocab::ServiceCallerDomain::MaintenanceOperator
        );
    }
}

#[cfg(test)]
mod row_visibility_tests {
    //! 核心：`Principal::row_visibility` 身份→行级可见域派生（tenancy.md §Principal claim source）。
    //! user→self / device→device / admin→tenant / super-admin→**fail-closed**（All 须经 audited funnel，
    //! 见 `cross_tenant_audit_grant_tests`）/ service·anonymous→fail-closed。
    use super::{CANON_TENANT, Principal, PrincipalKind};
    use rss_request_context::RowScope;
    use rss_request_context::TenantId;
    use rstest::rstest;

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_TENANT).expect("canonical tenant")
    }

    /// 期望形态：scoped（Ok + 单租户）/ fail-closed（Err）。
    /// super-admin 经裸同步 `row_visibility` 归 fail-closed——All-scope 唯一经 audited funnel 派生。
    enum Expect {
        Scoped(RowScope),
        FailClosed,
    }

    #[rstest]
    #[case(PrincipalKind::User, Expect::Scoped(RowScope::SelfOnly))]
    #[case(PrincipalKind::Device, Expect::Scoped(RowScope::Device))]
    #[case(PrincipalKind::Admin, Expect::Scoped(RowScope::Tenant))]
    // super-admin 经 sync 路径 fail-closed（无 AuditSink 无法同址审计）；All 经 audited funnel。
    #[case(PrincipalKind::SuperAdmin, Expect::FailClosed)]
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
mod cross_tenant_audit_grant_tests {
    use super::{
        CrossTenantAuditContext, CrossTenantAuditError, CrossTenantGrantError, Principal,
        PrincipalKind,
    };
    use diport::{AuditOutcome, Clock};
    use rss_request_context::TenantId;
    use std::time::SystemTime;

    const CANON_T: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    struct TestClock(SystemTime);
    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON_T).expect("canonical tenant")
    }

    #[allow(clippy::expect_used)]
    fn audit_ctx() -> CrossTenantAuditContext {
        CrossTenantAuditContext::new(
            "cross_tenant_visibility",
            "res-7",
            "derive_all_scope",
            "req-1",
            "corr-9",
        )
        .expect("完整字段构造应成功")
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn super_admin_grant_binds_target_and_normalized_event() {
        let tid = tenant();
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let principal = Principal::for_test(PrincipalKind::SuperAdmin, "root-subject", None);
        let ctx = runctx::test_support::app_ctx(tid, "root-subject");

        let grant = principal
            .cross_tenant_audit_grant(&ctx, &TestClock(t0), &audit_ctx())
            .expect("super-admin grant should be minted");
        assert_eq!(grant.target(), tid);
        let event = grant.into_event();
        assert_eq!(event.occurred_at, t0);
        assert_eq!(event.principal_id, "root-subject");
        assert_eq!(event.principal_kind, PrincipalKind::SuperAdmin);
        assert_eq!(event.tenant_id, Some(tid));
        assert_eq!(event.resource_kind, "cross_tenant_visibility");
        assert_eq!(event.resource_id, "res-7");
        assert_eq!(event.action, "derive_all_scope");
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
        assert_eq!(event.correlation_id.as_deref(), Some("corr-9"));
    }

    /// INVARIANT (#1288): non-super-admin → `Err(NotSuperAdmin)` and **no** grant/event is produced.
    /// Defense-in-depth 资格闸；deny ledger 由调用方（audit 域）负责，本 API 不回写 deny 事件。
    #[test]
    fn grant_denied_when_not_super_admin_tripwire() {
        let tid = tenant();
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::Service,
            PrincipalKind::Anonymous,
        ] {
            let principal = Principal::for_test(kind, "subject-x", Some(tid));
            let ctx = runctx::test_support::app_ctx(tid, "subject-x");
            // 保留完整 Result：Ok 即意味着 mint 了 CrossTenantAuditGrant（含规范化 Success 事件）。
            let result = principal.cross_tenant_audit_grant(
                &ctx,
                &TestClock(SystemTime::UNIX_EPOCH),
                &audit_ctx(),
            );
            assert!(
                matches!(&result, Err(CrossTenantGrantError::NotSuperAdmin)),
                "INVARIANT: kind={kind:?} → NotSuperAdmin；Err 路径 ⇒ 无 grant/event 可消费（Ok 即 mint）"
            );
        }
    }

    /// `CrossTenantAuditContext` Debug 脱敏：不泄 resource_id / request_id / correlation_id。
    #[test]
    fn audit_context_debug_redacts() {
        let dbg = format!("{:?}", audit_ctx());
        assert!(!dbg.contains("res-7"), "resource_id 泄漏: {dbg}");
        assert!(!dbg.contains("req-1"), "request_id 泄漏: {dbg}");
        assert!(!dbg.contains("corr-9"), "correlation_id 泄漏: {dbg}");
        assert!(dbg.contains("<redacted>"), "缺 <redacted> 占位: {dbg}");
    }

    /// fail-closed 构造：任一审计字段空 → `Err(EmptyField)`，杜绝不完整 ledger 签发 All-scope
    /// （tenancy.md §RowScope 完整性，codex review F1）。表驱动覆盖每个字段。
    #[test]
    fn audit_context_rejects_empty_fields() {
        // (resource_kind, resource_id, action, request_id, correlation_id)
        let empties = [
            ("", "res", "act", "req", "corr"),
            ("rk", "", "act", "req", "corr"),
            ("rk", "res", "", "req", "corr"),
            ("rk", "res", "act", "", "corr"),
            ("rk", "res", "act", "req", ""),
        ];
        for (rk, rid, act, req, corr) in empties {
            let r = CrossTenantAuditContext::new(rk, rid, act, req, corr);
            assert!(
                matches!(r.as_ref(), Err(CrossTenantAuditError::EmptyField)),
                "空字段须 fail-closed 拒绝：({rk:?},{rid:?},{act:?},{req:?},{corr:?}) → {:?}",
                r.map(|_| ())
            );
        }
        // 完整字段成功（anti-vacuity：校验非恒拒绝）。
        assert!(
            CrossTenantAuditContext::new("rk", "res", "act", "req", "corr").is_ok(),
            "完整字段须构造成功"
        );
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
                matches!(Jwt::parse(raw), Err(AuthnError::PrincipalInvalid)),
                "结构闸（验签后）失败必须 PrincipalInvalid: {raw}"
            );
        }
    }
}

#[cfg(test)]
mod principal_derive_tests {
    //! `from_verified_jwt`（claims→Principal 映射）+ `from_verified_service_token`（funnel 固定 Service）。
    //! 信任边界：函数信任入参已被上游 verifier 验签（本轮不做 crypto 验签）。
    //! Service fail-closed tripwire（#1306）：federated 空 subject 在 claims factory 即拒；
    //! typed `ServiceCallerDomain` 无法 stub 空 ServiceToken subject，wrong-claims-shape →
    //! `PrincipalInvalid` 作 untrusted-kind 代理。
    use super::{
        AccessToken, AuthnError, Principal, PrincipalKind, VerifiedJwt,
        VerifiedMaintenanceServiceOperator, VerifiedServiceToken,
    };
    use diport::{VerifiedClaims, VerifiedFederatedPermissions};
    use rss_request_context::TenantId;

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    fn permissions() -> VerifiedFederatedPermissions {
        VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
            vocab::RoutePermissionId::SettingsConfigPublish,
        )])
        .unwrap_or_else(|_| unreachable!("literal permission set is valid"))
    }

    /// 已验签 JWT 测试装箱：载体携 raw + verifier-canonical [`VerifiedClaims`]（单一身份源，直接构造，
    /// 模拟 verifier 验签产物）。
    fn vjwt(sub: &str, tenant: Option<&str>, kind: Option<&str>) -> VerifiedJwt {
        let parsed_tenant = tenant.and_then(|raw| TenantId::parse(raw).ok());
        let parsed_kind = match kind {
            Some("user") => Some(PrincipalKind::User),
            Some("device") => Some(PrincipalKind::Device),
            Some("admin") => Some(PrincipalKind::Admin),
            Some("superAdmin") => Some(PrincipalKind::SuperAdmin),
            _ => None,
        };
        let claims = parsed_kind
            .and_then(|kind| {
                VerifiedClaims::federated_access(sub, parsed_tenant, kind, permissions()).ok()
            })
            .unwrap_or_else(|| {
                VerifiedClaims::service_token(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    TenantId::parse(CANON).expect("canonical tenant"),
                )
            });
        VerifiedJwt::seal("h.e.s".to_string(), claims)
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn maps_scoped_kinds_with_tenant() {
        let tid = TenantId::parse(CANON).expect("tenant");
        for (kind_claim, kind) in [
            ("user", PrincipalKind::User),
            ("device", PrincipalKind::Device),
            ("admin", PrincipalKind::Admin),
        ] {
            let p = Principal::from_verified_jwt(&vjwt("sub-x", Some(CANON), Some(kind_claim)))
                .expect("derive ok");
            assert_eq!(p.kind(), kind, "kind={kind_claim}");
            assert_eq!(p.tenant(), Some(tid), "kind={kind_claim}");
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn maps_super_admin_to_cross_tenant_none() {
        let p = Principal::from_verified_jwt(&vjwt("root", None, Some("superAdmin")))
            .expect("super-admin derive ok");
        assert_eq!(p.kind(), PrincipalKind::SuperAdmin);
        assert_eq!(p.tenant(), None, "super-admin 跨租户，tenant 必须 None");
    }

    #[test]
    fn rejects_scoped_kind_without_tenant() {
        for kind in ["user", "device", "admin"] {
            assert!(
                matches!(
                    Principal::from_verified_jwt(&vjwt("u", None, Some(kind))),
                    Err(AuthnError::PrincipalInvalid)
                ),
                "scoped kind 缺 tenant 必须 PrincipalInvalid（验签后派生失败）: {kind}"
            );
        }
    }

    #[test]
    fn rejects_unknown_kind_wrong_funnel_and_bad_tenant() {
        let cases: [(Option<&str>, Option<&str>); 5] = [
            (None, Some("service")),   // service 走 service-token funnel，非 jwt 派生
            (None, Some("anonymous")), // anonymous 不经 jwt 派生
            (None, Some("root")),      // 未知 kind
            (None, None),              // 缺 kind
            (Some("not-a-uuid"), Some("user")), // 坏 tenant
        ];
        for (tenant, kind) in cases {
            assert!(
                matches!(
                    Principal::from_verified_jwt(&vjwt("x", tenant, kind)),
                    Err(AuthnError::PrincipalInvalid)
                ),
                "必须 PrincipalInvalid（验签后派生失败）: tenant={tenant:?} kind={kind:?}"
            );
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn service_token_funnel_fixes_service_kind_no_tenant() {
        // funnel 固定 kind=Service：即便验签产物携 kind=admin / tenant，也忽略，恒 Service + 跨租户 None。
        let vs = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::service_token(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                TenantId::parse(CANON).expect("canonical tenant"),
            ),
        );
        let p = Principal::from_verified_service_token(&vs).expect("service derive ok");
        assert_eq!(p.kind(), PrincipalKind::Service);
        assert_eq!(p.tenant(), None);
        assert_eq!(
            p.service_caller_domain(),
            Some(vocab::ServiceCallerDomain::MaintenanceOperator)
        );
    }

    /// Tripwire (#1306)：federated 空 subject 在 claims factory 即拒；service-token funnel 对
    /// wrong-shape（federated 塞进 service 载体）→ `PrincipalInvalid`——绝不 mint。
    ///
    /// `VerifiedClaims::service_token` 以 `ServiceCallerDomain` 类型化，无法 stub「开放 / 空 subject
    /// 的 Ok(ServiceToken)」；wrong-shape 是唯一可表达的 untrusted-kind 代理（勿与空 subject 守卫重复）。
    #[test]
    #[allow(clippy::expect_used)]
    fn federated_empty_subject_and_service_wrong_shape_tripwire() {
        assert!(
            VerifiedClaims::federated_access("", None, PrincipalKind::SuperAdmin, permissions(),)
                .is_err(),
            "federated empty subject must fail closed at claims factory"
        );
        let wrong_shape = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::federated_access(
                "not-service",
                None,
                PrincipalKind::SuperAdmin,
                permissions(),
            )
            .expect("federated"),
        );
        assert!(
            matches!(
                Principal::from_verified_service_token(&wrong_shape),
                Err(AuthnError::PrincipalInvalid)
            ),
            "service funnel wrong-shape must never mint Service principal"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn maintenance_service_operator_proof_accepts_service_token_rejects_projection_shape() {
        let tenant = TenantId::parse(CANON).expect("tenant");
        let ok = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::service_token(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                TenantId::parse(CANON).expect("canonical tenant"),
            ),
        );
        let proof = VerifiedMaintenanceServiceOperator::try_from_verified_service_token(&ok)
            .expect("maintenance service-token proof");
        assert!(
            proof
                .principal()
                .matches_subject(vocab::ServiceCallerDomain::MaintenanceOperator.as_str())
        );
        assert_eq!(proof.principal().kind(), PrincipalKind::Service);

        let projection_shape = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::projection_operator(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                tenant,
            ),
        );
        assert!(
            matches!(
                VerifiedMaintenanceServiceOperator::try_from_verified_service_token(
                    &projection_shape
                ),
                Err(AuthnError::PrincipalInvalid)
            ),
            "projection claims must never mint maintenance service-operator proof"
        );

        let wrong_shape = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::federated_access(
                "not-service",
                None,
                PrincipalKind::SuperAdmin,
                permissions(),
            )
            .expect("federated"),
        );
        assert!(
            matches!(
                VerifiedMaintenanceServiceOperator::try_from_verified_service_token(&wrong_shape),
                Err(AuthnError::PrincipalInvalid)
            ),
            "wrong-shape claims must never mint maintenance service-operator proof"
        );
    }
}

#[cfg(test)]
mod verified_token_seal {
    //! INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— 「未验签派生 Principal」类型层不可表达。
    //!
    //! `VerifiedJwt` / `VerifiedServiceToken` 私有内层 + `pub(crate)` `seal`：外部 crate 无法 mint，
    //! 故收紧后的 `from_verified_jwt(&VerifiedJwt)` / `from_verified_service_token(&VerifiedServiceToken)`
    //! 只能消费已验证 newtype（编译期 Hard，绕过不可表达）。
    //! anti-vacuity：受控入口 + funnel 签名绑为函数指针——去掉任一即编译失败（守卫非恒真）。
    use super::{
        AccessToken, AuthnError, Principal, PrincipalKind, VerifiedJwt,
        VerifiedProjectionOperatorToken, VerifiedServiceToken,
    };
    use diport::{VerifiedClaims, VerifiedFederatedPermissions};
    use rss_request_context::TenantId;

    fn permissions() -> VerifiedFederatedPermissions {
        VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
            vocab::RoutePermissionId::SettingsConfigPublish,
        )])
        .unwrap_or_else(|_| unreachable!("literal permission set is valid"))
    }

    #[allow(clippy::expect_used)]
    fn federated_claims(subject: &str) -> VerifiedClaims {
        VerifiedClaims::federated_access(
            subject,
            Some(TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("tenant")),
            PrincipalKind::Admin,
            permissions(),
        )
        .expect("federated claims")
    }

    #[test]
    fn seal_entries_and_funnels_carry_verified_newtype_signatures() {
        // 受控 mint 入口（`pub(crate)`，外部 crate 不可达——Hard）；载体携 raw + canonical claims。
        let _seal_jwt: fn(String, VerifiedClaims) -> VerifiedJwt = VerifiedJwt::seal;
        let _seal_svc: fn(AccessToken, VerifiedClaims) -> VerifiedServiceToken =
            VerifiedServiceToken::seal;
        let _seal_projection: fn(AccessToken, VerifiedClaims) -> VerifiedProjectionOperatorToken =
            VerifiedProjectionOperatorToken::seal;
        // funnel 只收已验证 newtype（裸 token / claims 不可直接派生 Principal）。
        let _from_jwt: fn(&VerifiedJwt) -> Result<Principal, AuthnError> =
            Principal::from_verified_jwt;
        let _from_svc: fn(&VerifiedServiceToken) -> Result<Principal, AuthnError> =
            Principal::from_verified_service_token;
        let _from_projection: fn(
            &VerifiedProjectionOperatorToken,
        ) -> Result<Principal, AuthnError> = Principal::from_verified_projection_operator_token;
    }

    #[test]
    fn verified_jwt_redacts_debug() {
        // 载体携 raw token + canonical claims（subject）——Debug 二者均不得泄露。
        let vj = VerifiedJwt::seal(
            "secret-raw-token".to_string(),
            federated_claims("alice-secret"),
        );
        let dbg = format!("{vj:?}");
        assert!(
            !dbg.contains("secret-raw-token"),
            "VerifiedJwt Debug 不得泄露原始 token"
        );
        assert!(
            !dbg.contains("alice-secret"),
            "VerifiedJwt Debug 不得泄露 subject 明文"
        );
        assert!(
            dbg.contains("redacted"),
            "VerifiedJwt Debug 应标记 redacted"
        );
    }

    #[test]
    fn verified_service_token_redacts_debug() {
        let vs = VerifiedServiceToken::seal(
            AccessToken::new("svc-secret-xyz"),
            VerifiedClaims::service_token(
                vocab::ServiceCallerDomain::MaintenanceOperator,
                TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479").expect("canonical tenant"),
            ),
        );
        let dbg = format!("{vs:?}");
        assert!(
            !dbg.contains("svc-secret-xyz"),
            "VerifiedServiceToken Debug 不得泄露原始 token"
        );
        assert!(!dbg.contains("rss-maintenance-operator"));
        assert!(
            dbg.contains("redacted"),
            "VerifiedServiceToken Debug 应标记 redacted"
        );
    }
}

#[cfg(test)]
mod verify_bridge_tests {
    //! authn-owned verify→mint bridge（#1158）：`Pdp` 验签 ok → seal `VerifiedJwt` / `VerifiedServiceToken`
    //! 并从**验签产物 `VerifiedClaims`** 派生 `Principal`（验签 = 信任原点）；验签 fail → `AuthnError`，
    //! 绝不 seal / 派生（fail-closed，verify 先于 seal 的顺序由 `?`-链保证）。
    //! Service-token tripwires（#1306）：PDP Err 映射 never-mint；non-ServiceToken claims →
    //! `PrincipalInvalid`（wrong-profile 代理不可 stub 的空 ServiceToken subject）。
    use super::{
        AuthnError, PrincipalKind, test_jwt, verify_federated_access,
        verify_projection_operator_token, verify_rss_access, verify_service_token,
    };
    use diport::{
        DynPdp, Pdp, PdpError, RawCredential, TokenProfile, VerifiedAccessGrantFacts,
        VerifiedClaims, VerifiedFederatedPermissions,
    };
    use ids::UserId;
    use rss_request_context::TenantId;

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const USER: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[allow(clippy::expect_used)]
    fn tenant() -> TenantId {
        TenantId::parse(CANON).expect("tenant")
    }

    #[allow(clippy::expect_used)]
    fn rss_claims() -> VerifiedClaims {
        VerifiedClaims::rss_user(
            UserId::parse(USER).expect("user"),
            tenant(),
            VerifiedAccessGrantFacts::try_new(
                "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8",
                "d8dbe849-1d7e-49aa-b68a-a7b41ed252df",
                1_700_000_000,
                7,
            )
            .expect("grant facts"),
        )
    }

    #[allow(clippy::expect_used)]
    fn federated_claims(subject: &str, kind: PrincipalKind) -> VerifiedClaims {
        let tenant = match kind {
            PrincipalKind::SuperAdmin => None,
            _ => Some(tenant()),
        };
        let permissions = VerifiedFederatedPermissions::new([vocab::GrantPermission::route(
            vocab::RoutePermissionId::SettingsConfigPublish,
        )])
        .unwrap_or_else(|_| unreachable!("literal permission set is valid"));
        VerifiedClaims::federated_access(subject, tenant, kind, permissions)
            .expect("federated claims")
    }

    /// 桩 `Pdp`：先主动 yield，再按预置结果应答（native-AFIT impl → 经 `DynPdp` 注入）。
    struct StubPdp {
        result: Result<VerifiedClaims, PdpError>,
    }
    impl Pdp for StubPdp {
        async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
            tokio::task::yield_now().await;
            self.result.clone()
        }
    }
    fn boxed(result: Result<VerifiedClaims, PdpError>) -> Box<DynPdp<'static>> {
        DynPdp::new_box(StubPdp { result })
    }

    struct ProfilePdp {
        expected: TokenProfile,
    }

    impl Pdp for ProfilePdp {
        async fn verify(&self, raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
            assert_eq!(raw.profile(), self.expected);
            Ok(match self.expected {
                TokenProfile::RssAccess => rss_claims(),
                TokenProfile::FederatedAccess => federated_claims("subject", PrincipalKind::User),
                TokenProfile::ServiceToken => VerifiedClaims::service_token(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    TenantId::parse(CANON).expect("canonical tenant"),
                ),
                TokenProfile::ProjectionOperator => VerifiedClaims::projection_operator(
                    vocab::ServiceCallerDomain::MaintenanceOperator,
                    tenant(),
                ),
            })
        }
    }

    #[allow(clippy::expect_used)]
    fn service_binding() -> diport::ServiceTokenTenantBinding {
        diport::ServiceTokenTenantBinding::new(TenantId::parse(CANON).expect("canonical tenant"))
    }

    #[test]
    fn verify_futures_are_send_across_yielding_dyn_pdp() {
        fn assert_send<T: Send>(_: T) {}

        let raw = test_jwt(r#"{"sub":"u"}"#);
        let jwt_pdp = boxed(Err(PdpError::InvalidSignature));
        assert_send(verify_rss_access(&raw, &jwt_pdp));

        let service_pdp = boxed(Err(PdpError::InvalidSignature));
        assert_send(verify_service_token(
            "opaque",
            service_binding(),
            &service_pdp,
        ));
        let projection_pdp = boxed(Err(PdpError::InvalidSignature));
        assert_send(verify_projection_operator_token("opaque", &projection_pdp));
    }

    #[tokio::test]
    async fn access_funnels_fix_the_trusted_profile_before_provider_entry() {
        let raw = test_jwt(r#"{"sub":"user"}"#);
        let rss = DynPdp::new_box(ProfilePdp {
            expected: TokenProfile::RssAccess,
        });
        let federated = DynPdp::new_box(ProfilePdp {
            expected: TokenProfile::FederatedAccess,
        });

        assert!(verify_rss_access(&raw, &rss).await.is_ok());
        assert!(verify_federated_access(&raw, &federated).await.is_ok());

        let service = DynPdp::new_box(ProfilePdp {
            expected: TokenProfile::ServiceToken,
        });
        assert!(
            verify_service_token("opaque", service_binding(), &service)
                .await
                .is_ok()
        );

        let projection = DynPdp::new_box(ProfilePdp {
            expected: TokenProfile::ProjectionOperator,
        });
        assert!(
            verify_projection_operator_token("opaque", &projection)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn projection_operator_funnel_preserves_signed_tenant_and_closed_caller() {
        let pdp = boxed(Ok(VerifiedClaims::projection_operator(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            tenant(),
        )));
        let (verified, principal) = verify_projection_operator_token("opaque", &pdp)
            .await
            .expect("verified Projection operator token");
        assert_eq!(verified.tenant().expect("signed tenant"), tenant());
        assert_eq!(principal.tenant(), Some(tenant()));
        assert_eq!(
            principal.service_caller_domain(),
            Some(vocab::ServiceCallerDomain::MaintenanceOperator)
        );
        assert!(format!("{verified:?}").contains("redacted"));
    }

    /// happy：验签 ok → `(VerifiedJwt, Principal)`；身份反映**验签产物**而非 raw 重解析。
    /// raw payload 故意 `kind=user`，`VerifiedClaims.kind=admin` → `Principal=Admin`，证明信任原点是 verifier。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_federated_access_derives_principal_from_verified_claims_not_raw() {
        let raw = test_jwt(
            r#"{"sub":"raw-ignored","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(federated_claims("admin-subj", PrincipalKind::Admin)));
        let access = verify_federated_access(&raw, &pdp)
            .await
            .expect("verify ok mints");
        let principal = access.principal();
        assert_eq!(
            principal.kind(),
            PrincipalKind::Admin,
            "身份须源自 VerifiedClaims（admin），非 raw（user）"
        );
        assert!(
            format!("{access:?}").contains("redacted"),
            "VerifiedFederatedAccess Debug 脱敏"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn rss_principal_and_grant_receipt_come_only_from_verified_evidence() {
        let raw = test_jwt(
            r#"{"sub":"raw-ignored","tenant_id":"00000000-0000-4000-8000-000000000abc","kind":"admin","sid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","jti":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","auth_time":1,"authn_epoch":999}"#,
        );
        let pdp = boxed(Ok(rss_claims()));
        let (verified, principal) = verify_rss_access(&raw, &pdp)
            .await
            .expect("verified RSS evidence");

        assert_eq!(principal.kind(), PrincipalKind::User);
        assert_eq!(principal.audit_subject(), USER);
        assert_eq!(principal.tenant(), Some(tenant()));
        let receipt = verified.grant_receipt().expect("RSS grant receipt");
        assert_eq!(
            receipt.grant_id().to_wire(),
            "7d65e5f2-e716-4c4e-8e4c-6f7ab1754ef8".to_owned()
        );
        assert_eq!(
            receipt.token_id().to_string(),
            "d8dbe849-1d7e-49aa-b68a-a7b41ed252df"
        );
        assert_eq!(receipt.auth_time_unix_secs(), 1_700_000_000);
        assert_eq!(receipt.authn_epoch(), 7);
        assert_eq!(format!("{receipt:?}"), "VerifiedGrantReceipt(<redacted>)");
        let input = receipt.into_validation_input();
        assert_eq!(
            format!("{input:?}"),
            "AccessGrantValidationInput(<redacted>)"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_federated_access_super_admin_is_cross_tenant_none() {
        let raw = test_jwt(
            r#"{"sub":"x","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(federated_claims("root", PrincipalKind::SuperAdmin)));
        let access = verify_federated_access(&raw, &pdp)
            .await
            .expect("super-admin ok");
        let principal = access.principal();
        assert_eq!(principal.kind(), PrincipalKind::SuperAdmin);
        assert_eq!(principal.tenant(), None, "super-admin 跨租户 tenant=None");
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn every_federated_principal_kind_has_no_local_grant_receipt() {
        let raw = test_jwt(r#"{"sub":"federated"}"#);
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::SuperAdmin,
        ] {
            let pdp = boxed(Ok(federated_claims("federated", kind)));
            let access = verify_federated_access(&raw, &pdp)
                .await
                .expect("federated access");
            let principal = access.principal();
            assert_eq!(principal.kind(), kind);
            assert!(!access.permissions().as_slice().is_empty(), "kind={kind:?}");
        }
    }

    /// fail-closed：四个 `PdpError` 变体均 never `Ok` / seal；三种凭据失败保持 401 taxonomy，
    /// provider outage 则保持独立可重试语义。
    #[tokio::test]
    async fn verify_rss_access_pdp_failure_maps_error_and_never_mints() {
        let raw = test_jwt(
            r#"{"sub":"u","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenUntrusted),
            (
                PdpError::ProviderUnavailable,
                AuthnError::ProviderUnavailable,
            ),
        ] {
            let pdp = boxed(Err(perr.clone()));
            // matches! + discriminant 守卫：既断言是 Err（绝不 mint），又锁定映射变体。
            // 不用 expect_err（`Principal` 无 Debug，含 PII 刻意不 derive）、不用 panic（clippy::panic 禁）。
            let result = verify_rss_access(&raw, &pdp).await;
            assert!(
                matches!(&result, Err(e) if std::mem::discriminant(e) == std::mem::discriminant(&want)),
                "PdpError::{perr:?} 须映射到 {want:?}（且绝不 Ok）"
            );
        }
    }

    /// verify 先于 seal：`Pdp` ok 但 raw 结构坏 → `Jwt::parse` 报 `PrincipalInvalid`（验签后结构闸失败，非
    /// 签名失败、非 seal），无产物。#1275 review F1：此路不得记 `signature_invalid`。
    #[tokio::test]
    async fn verify_rss_access_ok_but_malformed_raw_fails_at_parse() {
        let pdp = boxed(Ok(rss_claims()));
        assert!(matches!(
            verify_rss_access("only.two", &pdp).await,
            Err(AuthnError::PrincipalInvalid)
        ));
    }

    /// service-token happy / anti-vacuity：验签 ok + ServiceToken claims → mint `kind=Service`。
    /// 与下方 fail-closed tripwire 成对，防止「永远 Err」的空洞守卫。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_service_token_ok_fixes_service_kind() {
        let canonical = TenantId::parse(CANON).expect("canonical tenant");
        let pdp = boxed(Ok(VerifiedClaims::service_token(
            vocab::ServiceCallerDomain::MaintenanceOperator,
            canonical,
        )));
        let (vs, principal) = verify_service_token("opaque-service-token", service_binding(), &pdp)
            .await
            .expect("service verify ok");
        assert_eq!(principal.kind(), PrincipalKind::Service);
        assert_eq!(principal.tenant(), None);
        assert_eq!(
            vs.tenant().expect("sealed service claims project tenant"),
            canonical
        );
        assert!(format!("{vs:?}").contains("redacted"));
    }

    /// Tripwire (#1306)：四个 `PdpError` 变体均 never `Ok` / seal，并与 access 路径一一对齐。
    #[tokio::test]
    async fn verify_service_token_pdp_err_mapping_never_mints_tripwire() {
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenUntrusted),
            (
                PdpError::ProviderUnavailable,
                AuthnError::ProviderUnavailable,
            ),
        ] {
            let pdp = boxed(Err(perr.clone()));
            let result = verify_service_token("opaque-token", service_binding(), &pdp).await;
            assert!(
                matches!(&result, Err(e) if std::mem::discriminant(e) == std::mem::discriminant(&want)),
                "PdpError::{perr:?} 须映射到 {want:?}（且绝不 mint）"
            );
        }
    }

    /// Tripwire (#1306)：PDP 验签「ok」但返回非 ServiceToken claims → `PrincipalInvalid`，绝不 mint。
    ///
    /// `VerifiedClaims::service_token` typed on `ServiceCallerDomain`——无法 stub 空 subject 的
    /// `Ok(ServiceToken)`；wrong-profile（RssUser / FederatedAccess）是 bridge 端 untrusted-kind 代理。
    #[tokio::test]
    async fn verify_service_token_denied_when_non_service_claims_tripwire() {
        let pdp_rss = boxed(Ok(rss_claims()));
        assert!(
            matches!(
                verify_service_token("opaque", service_binding(), &pdp_rss).await,
                Err(AuthnError::PrincipalInvalid)
            ),
            "RssUser claims on service funnel must never mint"
        );
        let pdp_fed = boxed(Ok(federated_claims("user", PrincipalKind::User)));
        assert!(
            matches!(
                verify_service_token("opaque", service_binding(), &pdp_fed).await,
                Err(AuthnError::PrincipalInvalid)
            ),
            "FederatedAccess claims on service funnel must never mint"
        );
    }

    /// Tripwire：access funnel 拒绝 wrong-profile claims（PDP ok 但形态不匹配 → `PrincipalInvalid`）。
    #[tokio::test]
    async fn verify_rss_access_denied_when_wrong_profile_shape_tripwire() {
        let raw = test_jwt(
            r#"{"sub":"x","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(federated_claims("user", PrincipalKind::User)));
        assert!(matches!(
            verify_rss_access(&raw, &pdp).await,
            Err(AuthnError::PrincipalInvalid)
        ));
    }
}

#[cfg(test)]
mod value_type_tests {
    //! token newtype / `Principal` 访问器 / Send / Debug 脱敏。
    use super::{AccessToken, CANON_TENANT, Principal, PrincipalKind, RefreshToken};
    use rss_request_context::TenantId;

    fn _assert_send<T: Send>() {}

    #[test]
    fn principal_is_send() {
        _assert_send::<Principal>();
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
    fn principal_accessors_reflect_construction() {
        let tid = TenantId::parse(CANON_TENANT).expect("tenant");
        let p = Principal::for_test(PrincipalKind::Admin, "bob", Some(tid));
        assert_eq!(p.kind(), PrincipalKind::Admin);
        assert_eq!(p.tenant(), Some(tid));
    }
}

#[cfg(test)]
mod enum_exhaustiveness {
    //! AuthnError 闭值集完整性 + Display 非空（crate 内穷举 non_exhaustive）。
    //! PrincipalKind 穷举守卫随类型上移 vocab（crates/vocab/src/principal.rs 的 tests）。
    use super::AuthnError;

    #[test]
    fn authn_error_is_exhaustive_and_displays() {
        for e in [
            AuthnError::TokenInvalid,
            AuthnError::TokenUntrusted,
            AuthnError::PrincipalInvalid,
            AuthnError::TokenExpired,
            AuthnError::ProviderUnavailable,
            AuthnError::Forbidden,
        ] {
            assert!(!e.to_string().is_empty(), "错误 message 非空");
            match e {
                AuthnError::TokenInvalid
                | AuthnError::TokenUntrusted
                | AuthnError::PrincipalInvalid
                | AuthnError::TokenExpired
                | AuthnError::ProviderUnavailable
                | AuthnError::Forbidden => {}
            }
        }
    }

    /// deny 分级：五个 deny / unavailable 变体 Debug 互不相同（bridge 据变体记不同 `authz.deny_reason`
    /// 闭值），Display 为 const literal，且 Debug/Display 均不含任何 runtime 数据（taxonomy 不携 PII）。
    /// 重点：`PrincipalInvalid`（验签后良性失败）须与 `TokenInvalid`（签名失败）Debug 可区分，否则 bridge 无法
    /// 避免把良性失败误报成 `signature_invalid`。
    #[test]
    fn deny_variants_are_distinct_and_pii_free() {
        let debugs: Vec<String> = [
            AuthnError::TokenInvalid,
            AuthnError::TokenUntrusted,
            AuthnError::PrincipalInvalid,
            AuthnError::TokenExpired,
            AuthnError::ProviderUnavailable,
        ]
        .iter()
        .map(|e| format!("{e:?}"))
        .collect();
        assert_eq!(
            debugs,
            [
                "TokenInvalid",
                "TokenUntrusted",
                "PrincipalInvalid",
                "TokenExpired",
                "ProviderUnavailable"
            ],
            "Debug 为变体名"
        );
        let unique: std::collections::HashSet<&String> = debugs.iter().collect();
        assert_eq!(unique.len(), debugs.len(), "deny 变体 Debug 须互不相同");
        assert_eq!(
            AuthnError::PrincipalInvalid.to_string(),
            "principal cannot be derived",
            "Display 为 const literal（无 runtime 数据 / PII）"
        );
    }

    /// `CrossTenantGrantError` 闭值集 + 非空、无 PII Display。
    #[test]
    fn cross_tenant_grant_error_is_closed() {
        use super::CrossTenantGrantError;
        let error = CrossTenantGrantError::NotSuperAdmin;
        assert!(!error.to_string().is_empty(), "错误 message 非空");
        match error {
            CrossTenantGrantError::NotSuperAdmin => {}
        }
    }
}
