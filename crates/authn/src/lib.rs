//! authn — RSS 认证主体词汇（Principal / Session / JWT / token 值类型）。
//!
//! 本 crate 承载认证侧的核心值类型与错误枚举；DI port（PDP / session store）归 `diport`（ADR-003）。
//! 所有类型字段私有，只经显式构造 funnel 创建——外部不可伪造，fail-closed（ADR-001）。
//!
//! ## 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
//!
//! 验签（签名/MAC/exp）与身份 claims 由 verifier DI port `diport::Pdp` 负责；`Jwt::parse` 仅作 token
//! **结构闸**（3 段 / base64url / JSON / 非空 sub），不验签、不提取身份。派生 `Principal` 的 funnel 收紧为
//! 只收**已验证 newtype**：`from_verified_jwt(&VerifiedJwt)` / `from_verified_service_token(&VerifiedServiceToken)`。
//! `VerifiedJwt` / `VerifiedServiceToken` 私有字段 + `pub(crate)` `seal`——外部 crate 无法 mint，故
//! 「未经验签派生 Principal」**从类型层不可表达（Hard）**。载体内携**单一 canonical 身份源**
//! `diport::VerifiedClaims`（验签产物）：一个载体只导出一个 principal，无第二（raw 重解析）身份源（#1158 F1）。
//! 生产 mint 路径 = authn-owned `verify_jwt` / `verify_service_token`（经 `Pdp` 验签后 seal）；真实 crypto
//! verifier adapter + httpserve 接线留 W，见 #1109。
//!
//! ## fail-closed
//!
//! `Principal::row_visibility` 的 `SuperAdmin`（裸同步路径）/ `Service` / `Anonymous` 分支返回
//! `Err(runctx::MissingCtx)`，强制调用方 deny；字段私有，外部无法绕过 funnel 伪造特权主体。
//! 跨租户 All-scope 唯一经 [`Principal::audited_cross_tenant_visibility`] 派生——派生与持久 audit ledger
//! INVARIANT: TENANCY-CROSSTENANT-AUDIT-01 —— All-scope 派生与持久 audit ledger 写入同址；
//! 无审计无 All-scope，audit 写失败 fail-closed。

#![forbid(unsafe_code)]

use base64::Engine;
use vocab::PrincipalKind;
use vocab::tenant::{RowVisibility, ScopedTenant, TenantId};

use primitives::authplan::{AuthPlan, AuthRequirement, RouteAuthOptOut, resolve_requirement};

// verify→mint bridge 经 `DynPdp` 调验签：`verify` 是 `Pdp` trait 方法，须 trait 在 scope（`as _`
// 只引入方法、不污染 `Pdp` 名——bridge 全程用 `diport::DynPdp` / `diport::RawCredential` 全限定）。
use diport::Pdp as _;

// reason: 确保 authplan 符号被引用，防止 cargo-udeps 误报未使用依赖（ADR-004 C8）。
#[allow(dead_code)]
const _: fn(AuthPlan, Option<RouteAuthOptOut>) -> AuthRequirement = resolve_requirement;

// JWT 签发（mint/sign）：组装 claims + 紧凑 JWS，签名委托注入的 `diport::Signer`（#1314）。验签侧对称物在
// 本 crate 顶部 verify→mint bridge；mint 子模块复用下方 `KIND_*` claim 串单源（杜绝 round-trip 漂移）。
mod mint;
pub use mint::{JwtAlg, JwtIssueError, JwtIssuer, JwtIssuerConfig, MintedJwt};

// kind claim 字符串常量（单源：验签侧 `derive_from_claims` 读、mint 侧 `kind_claim` 写，同一组常量防漂移）。
const KIND_USER: &str = "user";
const KIND_DEVICE: &str = "device";
const KIND_ADMIN: &str = "admin";
const KIND_SUPER_ADMIN: &str = "superAdmin";
// reason: service 主体（HS256 service-token）的 kind 串——本轮仅 mint 侧 `kind_claim` 用；与上列同址，
// 保 kind claim 名单源（验签 service-token 路径经 `from_verified_service_token` 固定 Service、不读本串）。
const KIND_SERVICE: &str = "service";

// 主体类别 `PrincipalKind` 单一源已上移基础层 `vocab`（crates/vocab/src/principal.rs）：authn `Principal.kind` /
// httpserve `Authenticated` 证据 / audit `actor_kind` 共用同一枚举，杜绝双源漂移。本 crate 经顶部
// `use vocab::PrincipalKind` 消费；KIND_* claim 串 → `PrincipalKind` 的映射策略仍归本 crate（`from_verified_jwt`）。

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
/// 信任边界：只做**结构**校验，签名/exp 与身份 claims 由上游 verifier（`diport::Pdp`）负责。本闸在 `verify_jwt`
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
    /// subject 标识（内部，不入 wire）；经 [`Principal::matches_subject`] 受控比较（不泄露明文）；
    /// session store / audit 读路径待 W 阶段接缝落地。
    subject: String,
    /// 所属租户（`None` 仅限 `Service` / `SuperAdmin` 跨租户场景）。
    tenant: Option<TenantId>,
}

impl Principal {
    /// 由已验证 JWT 派生 [`Principal`]（认证边界唯一入口）。
    ///
    /// `kind` / `tenant` 从**验签产物 [`diport::VerifiedClaims`]**（verifier = 信任原点）派生；外部 crate
    /// 无法构造特权主体（ADR-001）。
    ///
    /// # 信任边界（类型层强制，INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
    ///
    /// 入参收紧为 [`VerifiedJwt`]——其私有内层 + `pub(crate)` [`VerifiedJwt::seal`] 使外部 crate 无法 mint，
    /// 故「未经验签派生 Principal」**类型层不可表达（Hard）**。`VerifiedJwt` 内携**单一 canonical 身份源**
    /// `VerifiedClaims`（F1）：一个 verified 载体只导出一个 principal——本函数与 verify→mint bridge
    /// [`verify_jwt`] 读**同一** `VerifiedClaims`，无第二（raw 重解析）身份源、无分歧。
    pub fn from_verified_jwt(verified: &VerifiedJwt) -> Result<Self, AuthnError> {
        // VerifiedJwt.claims = 验签产物 = 单一身份源（载体的 raw 仅供下游转发，不派生身份）。
        let c = &verified.claims;
        Self::derive_from_claims(c.subject(), c.tenant(), c.kind())
    }

    /// 由已验证 claims 三元组（subject / tenant / kind）派生 scoped / super-admin [`Principal`]。
    ///
    /// `kind`→[`PrincipalKind`] 策略 + subject 非空不变式**单源**：消费侧两条已验证入口共用本函数，杜绝
    /// 双份映射 / 双份校验漂移——[`Self::from_verified_jwt`] 与 verify→mint bridge [`verify_jwt`] 均读载体
    /// 内 [`diport::VerifiedClaims`]。service / anonymous 不经本 funnel；未知 / 缺失 kind、空 subject、
    /// scoped 主体缺 tenant / tenant 非 canonical UUID → 一律 [`AuthnError::PrincipalInvalid`]（验签**通过后**的
    /// principal 派生失败，fail-closed；**非** `TokenInvalid`——后者专指签名失败，#1275 review F1）。
    fn derive_from_claims(
        subject: &str,
        tenant: Option<&str>,
        kind: Option<&str>,
    ) -> Result<Self, AuthnError> {
        // 空 subject fail-closed（F2）：verifier 产物即便绕过旧 decode_claims 的非空检查，也不得 mint
        // 空主体 Principal。此为 Principal 派生单一漏斗，覆盖 from_verified_jwt + bridge 两路。
        if subject.is_empty() {
            return Err(AuthnError::PrincipalInvalid);
        }
        // 单点决策 kind + 是否需 tenant，避免二级 match-on-PrincipalKind 的不可达 `_` 臂
        // （新增 PrincipalKind 时须在此加 KIND_* 串臂并定其 tenant 要求，无静默兜底）。
        let (kind, needs_tenant) = match kind {
            Some(KIND_USER) => (PrincipalKind::User, true),
            Some(KIND_DEVICE) => (PrincipalKind::Device, true),
            Some(KIND_ADMIN) => (PrincipalKind::Admin, true),
            // 跨租户超管：无 tenant（忽略任何 tenant claim）。
            Some(KIND_SUPER_ADMIN) => (PrincipalKind::SuperAdmin, false),
            // service/anonymous 不经 jwt funnel；未知/缺失 kind → PrincipalInvalid（验签后派生失败）。
            _ => return Err(AuthnError::PrincipalInvalid),
        };
        let tenant = if needs_tenant {
            let raw = tenant.ok_or(AuthnError::PrincipalInvalid)?;
            Some(TenantId::parse(raw).map_err(|_| AuthnError::PrincipalInvalid)?)
        } else {
            None
        };
        Ok(Self {
            kind,
            subject: subject.to_string(),
            tenant,
        })
    }

    /// 由已验证 service-token subject 派生（funnel 固定 `kind=Service`，跨租户 `tenant=None`）。
    ///
    /// fail-closed：空 subject → [`AuthnError::PrincipalInvalid`]（验签后派生失败，F2 / #1275 review F1，与
    /// [`Self::derive_from_claims`] 同款非空不变式）。信任原点 = verifier：subject 取自验签产物
    /// [`diport::VerifiedClaims::subject`]，service token 的 kind / tenant claim 不参与（service 主体恒跨租户）。
    fn service_from_subject(subject: &str) -> Result<Self, AuthnError> {
        if subject.is_empty() {
            return Err(AuthnError::PrincipalInvalid);
        }
        Ok(Self {
            kind: PrincipalKind::Service,
            subject: subject.to_string(),
            tenant: None,
        })
    }

    /// 由已验证 service-token 派生（funnel 固定 `kind=Service`）。
    ///
    /// 入参收紧为 [`VerifiedServiceToken`]（私有内层 + `pub(crate)` [`VerifiedServiceToken::seal`]，外部
    /// 不可 mint）——与 [`Self::from_verified_jwt`] 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）。
    /// subject 取自载体内**单一 canonical 身份源** [`diport::VerifiedClaims`]（verifier = 信任原点，与
    /// verify→mint bridge [`verify_service_token`] 同源，无分歧）；忽略 kind / tenant（service 恒跨租户）。
    pub fn from_verified_service_token(token: &VerifiedServiceToken) -> Result<Self, AuthnError> {
        Self::service_from_subject(token.claims.subject())
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
    /// `ctx` 类型为 `runctx::AppCtx`，即 `runctx::RequestCtx<vocab::tenant::TenantId, PrincipalSlot>`
    /// 别名，遵循 ADR-002 显式传 `&RequestCtx` 而非隐式线程局部的原则。
    /// ctx 缺失 fail-closed（返回 [`runctx::MissingCtx`]，绝不伪造 RowScope）。
    ///
    /// scoped 主体（user/device/admin）的行级隔离以**已认证 ctx tenant** 为准，且 fail-closed 要求
    /// principal 自带 tenant claim 与 `*ctx.tenant()` **一致**——不一致（如 tenant-A 令牌在 ctx-B 下）
    /// 返回 `Err`，杜绝越租户派生可见域（tenancy.md §Principal claim source）。
    ///
    /// `SuperAdmin`（跨租户 All-scope 须经 [`Principal::audited_cross_tenant_visibility`] 同址审计派生）、
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
        let scoped = |scope: ScopedTenant| match self.tenant {
            Some(t) if t == ctx_tenant => Ok(RowVisibility::new(scope, ctx_tenant)),
            _ => Err(runctx::MissingCtx),
        };
        match self.kind {
            PrincipalKind::User => scoped(ScopedTenant::SelfOnly),
            PrincipalKind::Device => scoped(ScopedTenant::Device),
            PrincipalKind::Admin => scoped(ScopedTenant::Tenant),
            // super-admin All-scope 只能经 `audited_cross_tenant_visibility`（async）派生——派生与持久
            // audit ledger「同址」（tenancy.md §RowScope，INVARIANT TENANCY-CROSSTENANT-AUDIT-01）。本 sync
            // 签名无 `AuditSink`、无法闭环审计 ⇒ fail-closed 拒绝，杜绝「无审计 All-scope」后门。
            PrincipalKind::SuperAdmin => Err(runctx::MissingCtx),
            // Service / Anonymous 及 #[non_exhaustive] 未来 kind：fail-closed，无可派生行级可见域。
            _ => Err(runctx::MissingCtx),
        }
    }
}

// ---------------------------------------------------------------------------
// 跨租户 All-scope 审计漏斗（同址强制审计，INVARIANT: TENANCY-CROSSTENANT-AUDIT-01）
// ---------------------------------------------------------------------------

pub use crosstenant::{CrossTenantAuditContext, CrossTenantAuditError, CrossTenantError};

/// 跨租户 All-scope 派生与持久审计「同址」漏斗。
///
/// # 类型层强制（INVARIANT: TENANCY-CROSSTENANT-AUDIT-01）
///
/// All-scope `RowVisibility` 只能由本模块 `AuditedCrossTenant` receipt 经 `into_all_scope` 产出；receipt 的
/// `seal` / `into_all_scope` 均**模块私有**，唯一 mint 点是 [`Principal::audited_cross_tenant_visibility`]
/// ——它在 `sink.record(..).await?` 成功**之后**才 `seal`（`?`-链先审计后签发，同 verify→mint bridge 范式）。
/// 故「无审计产 All-scope」在 authn 内**类型层不可表达**（模块封装 + 必填 receipt + 控制流顺序三重 Hard）。
/// vocab 跨租户三步（issue→authorize→new_cross_tenant）的唯一 callsite 收敛到 `into_all_scope`（仍在 authn
/// crate，dylint `rss_crosstenant_callsite` allowlist=authn 不变）。
mod crosstenant {
    use super::Principal;
    // `record` 是 `AuditSink` trait 方法，须 trait 在 scope（`as _` 只引入方法、不污染名——funnel 全程
    // 用 `diport::DynAuditSink` / `diport::AuditEvent` 全限定，同 row_visibility bridge 的 `Pdp as _`）。
    use diport::AuditSink as _;
    use vocab::PrincipalKind;
    use vocab::tenant::{CrossTenantCapability, CrossTenantVisibility, RowVisibility};

    /// 跨租户派生失败（fail-closed）：非 super-admin 或 audit 写失败均不签发 All-scope。
    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum CrossTenantError {
        /// 主体非 super-admin——无跨租户派生资格（不静默降级）。
        #[error("principal is not a super-admin")]
        NotSuperAdmin,
        /// 同址持久 audit 写失败 ⇒ fail-closed，绝不签发 All-scope（source 经 diport 脱敏）。
        #[error("cross-tenant audit write failed")]
        Audit(#[source] diport::AuditSinkError),
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

    /// authn-owned receipt：持有它 == 已对本次跨租户派生写入持久 audit（fail-closed 后才 mint）。
    ///
    /// 私有 struct + **模块私有** `seal` / `into_all_scope`：外部 crate / authn 模块外均不可 mint，唯一
    /// mint 点是本模块 [`Principal::audited_cross_tenant_visibility`]（record 成功后）。不 derive `Clone`
    /// （一次性证据）。INVARIANT: TENANCY-CROSSTENANT-AUDIT-01
    struct AuditedCrossTenant {
        _seal: (),
    }

    impl AuditedCrossTenant {
        /// 唯一 mint（模块私有）：仅本模块 audited funnel 在 audit `record` 成功后调用。
        fn seal() -> Self {
            Self { _seal: () }
        }

        /// 消费 receipt 产 All-scope（消费 `self` ⇒ 一审计→一 All-scope）。
        ///
        /// 这是 authn 内对 vocab 跨租户三步（issue→authorize→new_cross_tenant）的**唯一** callsite；
        /// dylint `rss_crosstenant_callsite` 命中点从 `row_visibility` 收敛到此（crate=authn allowlist 不变）。
        fn into_all_scope(self) -> RowVisibility {
            let cap = CrossTenantCapability::issue_for_verified_super_admin();
            RowVisibility::new_cross_tenant(CrossTenantVisibility::authorize(cap))
        }
    }

    impl Principal {
        /// super-admin 跨租户 All-scope 派生的【唯一】sanctioned 入口：先同址写持久 audit，record 成功
        /// 才签发 All-scope（无审计无 All-scope）。INVARIANT: TENANCY-CROSSTENANT-AUDIT-01
        ///
        /// fail-closed：`record` 失败 → `Err(CrossTenantError::Audit)`，`?` 短路在 `seal` 之前，绝不签发；
        /// 非 super-admin → `Err(CrossTenantError::NotSuperAdmin)`（不静默降级）。审计「先于」签发由 `?`-链
        /// 顺序保证（同 verify→mint bridge `verify_jwt` 范式）。
        ///
        /// `sink` 取 dynosaur wrapper `&DynAuditSink`（caller 可持 `Box`/`Arc`，同 `verify_jwt` 的 `&DynPdp`）；
        /// `clock` 取注入 [`diport::Clock`]（`occurred_at` 非系统时钟，rust-standards Clock 纪律）；`audit` 承载
        /// caller 提供的审计字段（super-admin 自身 `tenant=None`，`tenant_id` 取 ctx 行使 All-scope 的租户上下文）。
        ///
        /// # 安全模型 / 可观测（NOTE）
        ///
        /// - 仅 super-admin **成功派生**写 audit（`outcome: Success`）；非 super-admin 提前 `NotSuperAdmin`
        ///   return、**不**在此写审计——本 funnel 只审计「授予 All-scope」事件；越权拒绝的安全审计
        ///   （`AuditOutcome::Failure`）归 httpserve authz 层（真实鉴权门，本检查是 defense-in-depth），
        ///   不在此 defense-in-depth 处重复记录拒绝（follow-up issue 跟踪）。
        /// - `tracing` span 留 httpserve W 接线（同 `verify_jwt` 的 NOTE #1109）：当前无生产调用方，不引
        ///   `tracing` 依赖、不埋空转 span；W 注入时补「`authz.decision=allow` + `principal.kind`（无 PII）」。
        pub async fn audited_cross_tenant_visibility(
            &self,
            ctx: &runctx::AppCtx,
            sink: &diport::DynAuditSink<'_>,
            clock: &dyn diport::Clock,
            audit: &CrossTenantAuditContext,
        ) -> Result<RowVisibility, CrossTenantError> {
            if self.kind != PrincipalKind::SuperAdmin {
                return Err(CrossTenantError::NotSuperAdmin);
            }
            // 同址持久 audit（先于签发）。
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
            sink.record(event).await.map_err(CrossTenantError::Audit)?;
            // record 成功 → seal receipt → 经 receipt 签发 All-scope（唯一 mint 点）。
            Ok(AuditedCrossTenant::seal().into_all_scope())
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
    use super::{Principal, PrincipalKind};
    use vocab::tenant::TenantId;

    /// 构造测试 [`Principal`]（kind / subject / tenant 任意；不进生产 / wire 路径）。
    pub fn principal(
        kind: PrincipalKind,
        subject: impl Into<String>,
        tenant: Option<TenantId>,
    ) -> Principal {
        Principal::for_test(kind, subject, tenant)
    }
}

// ---------------------------------------------------------------------------
// verify→mint bridge（authn-owned 验签 → 受控 mint，#1158）
// ---------------------------------------------------------------------------
//
// INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01（生产端闭环）。`seal` 是 `pub(crate)`——外部 crate 无法 mint
// `VerifiedJwt` / `VerifiedServiceToken`（Hard，消费端见 `verified_token_seal` + `tests/ui/`）。本 bridge
// 是 authn 内**唯一生产 mint 路径**：经注入的 [`diport::Pdp`] 验签（签名/exp/MAC）成功后，才在 crate 内
// 调 `seal` 装箱、并据**验签产物** [`diport::VerifiedClaims`] 派生 `Principal`（验签 = 信任原点，非旁路
// re-parse）。验签**先于** seal 由 `?`-链顺序保证：`pdp.verify(...).await?` 失败即返回，绝不 seal。
// 真实 crypto verifier adapter + httpserve 生产接线留 #1109 W（ADR-006 §3/§5 验签空窗）。
//
// NOTE(#1109)：本 bridge 是认证决策关键路径，httpserve 接线时须补 `tracing` span（ADR-006 §4 承诺
// 与 #1109 同批交付）：verify ok → `authz.decision=allow` + `principal.kind`（不含 PII）；verify fail →
// `authz.decision=deny` + 区分 `PdpError` 变体（InvalidSignature / Expired / Untrusted 告警级别不同）。
// 当前 slice 无生产接线，故不引 `tracing` 依赖、不在此埋点（避免空转 span）。

/// 验签并 mint JWT：经注入的 [`diport::Pdp`] 校验签名 / exp / MAC，成功后受控 seal 出 [`VerifiedJwt`]
/// 并据验签产物派生 [`Principal`]。验签失败 fail-closed（[`AuthnError`]），绝不 seal。
///
/// `pdp` 取 dynosaur wrapper `&DynPdp`（caller 可持 `Box<DynPdp>` / `Arc<DynPdp>` 或静态 impl）。返回的
/// `VerifiedJwt` 内携**单一 canonical 身份源** `VerifiedClaims`——`Principal` 与该载体经 `from_verified_jwt`
/// 同源派生，一个载体只导出一个 principal（F1）。`Principal` 刻意不 derive `Debug`（含 PII）——消费 / 测试
/// 经 `.kind()` / `.tenant()` 访问器断言，不 debug 格式化整个元组。
pub async fn verify_jwt(
    raw: &str,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedJwt, Principal), AuthnError> {
    // ① 验签（信任原点）：失败即 fail-closed，下方 seal / 派生均不可达。
    let claims = pdp.verify(&diport::RawCredential::jwt(raw)).await?;
    // ② 结构防御闸（defense-in-depth）：raw 须 well-formed JWT（3 段 + base64url），否则 TokenInvalid——
    //    防 lenient adapter 对畸形 token 误判 ok。解析产物丢弃，仅校验结构（身份在 ④ 取自 VerifiedClaims）。
    Jwt::parse(raw)?;
    // ③ 受控 mint：载体携 raw（供下游 token relay）+ **单一 canonical 身份源** claims。
    let verified = VerifiedJwt::seal(raw.to_string(), claims);
    // ④ 据载体单一身份源派生主体（与 from_verified_jwt 同 funnel，无第二（raw 重解析）身份源、无分歧）。
    let principal = Principal::from_verified_jwt(&verified)?;
    Ok((verified, principal))
}

/// 验签并 mint service-token：同 [`verify_jwt`]，funnel 固定 `kind=Service`、`subject` 取自验签产物。
///
/// service token 结构由 verifier（[`diport::Pdp`]）负责，authn 不 re-parse——故 `raw` 对 authn 不透明，
/// 受控 seal 进 [`VerifiedServiceToken`]（携 raw + 单一 canonical 身份源 `VerifiedClaims`）。
pub async fn verify_service_token(
    raw: &str,
    pdp: &diport::DynPdp<'_>,
) -> Result<(VerifiedServiceToken, Principal), AuthnError> {
    let claims = pdp
        .verify(&diport::RawCredential::service_token(raw))
        .await?;
    let verified = VerifiedServiceToken::seal(AccessToken::new(raw), claims);
    let principal = Principal::from_verified_service_token(&verified)?;
    Ok((verified, principal))
}

// ---------------------------------------------------------------------------
// JWT / token / session 值类型
// ---------------------------------------------------------------------------

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
/// # 类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）
///
/// 把「未经验签派生 Principal」收口到类型层（Hard，newtype funnel）：[`Principal::from_verified_jwt`]
/// 只收 `&VerifiedJwt`，而 `VerifiedJwt` 仅经 `pub(crate)` [`Self::seal`] 装箱——外部 crate 既不能命名
/// 私有字段、也不能调 `pub(crate)` 构造，故无法伪造已验证主体。`Debug` 脱敏。
///
/// **单一 canonical 身份源（F1）**：载体内 `claims`（验签产物 [`diport::VerifiedClaims`]，verifier =
/// 信任原点）是**唯一**身份源；`raw` 仅是原始 token 串（供下游 token relay / session），**不派生身份**。
/// 故一个 `VerifiedJwt` 只能经 `from_verified_jwt` 导出**一个** principal——无第二（raw 重解析）身份源、
/// 无分歧。bridge [`verify_jwt`] 与 `from_verified_jwt` 读同一 `claims`。
///
/// ⚠ `seal` 的 `pub(crate)` 可见性是本不变式锚点：改为 `pub` 会让外部可 mint，Hard 静默退化为 Soft。
/// 改 `pub` 须经 ADR amendment；机器守（`cargo public-api` golden）跟踪见 #1151。**生产端**经 authn-owned
/// [`verify_jwt`] 闭环；外部 crate 不可达（`tests/ui/` compile-fail 锁）。httpserve 生产挂载留 #1109 W。
pub struct VerifiedJwt {
    /// 原始已验证 token 串（供下游 token relay / session；**不派生身份**——身份用 [`Principal::from_verified_jwt`]）。
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
    /// authn-owned [`verify_jwt`]，`seal` 保持 `pub(crate)`。
    pub(crate) fn seal(raw: String, claims: diport::VerifiedClaims) -> Self {
        Self { raw, claims }
    }

    /// 原始已验证 token 串（供下游 token relay；不派生身份）。
    pub fn raw(&self) -> &str {
        &self.raw
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
/// 与 [`VerifiedJwt`] 同款类型层强制（INVARIANT: AUTHN-VERIFIEDJWT-SEAL-01）+ **单一 canonical 身份源**
/// （F1）：[`Principal::from_verified_service_token`] 只收 `&VerifiedServiceToken`，从载体内 `claims`
/// （验签产物 [`diport::VerifiedClaims`]）派生身份；`token` 仅是原始串（relay 用，不派生身份）。仅经
/// `pub(crate)` [`Self::seal`] 装箱（同 [`VerifiedJwt`] 锚点，机器守见 #1151）。生产 mint 由
/// [`verify_service_token`] 调用。见 #1109。
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
    /// 会话不存在。**本 crate 当前不可达**——由 W session store（`diport` 仓储 port）产生。
    #[error("session not found")]
    SessionNotFound,
    /// 主体已认证但无权（403 insufficient permission）。**本 crate 当前不可达**——由后续 authz / ABAC 层
    /// 产生；verify→mint bridge **不**产此态（凭据不可信 / 无效归 401 拒绝态 `TokenInvalid` / `TokenUntrusted` /
    /// `PrincipalInvalid` / `TokenExpired`，RFC 6750 §3.1）。
    #[error("principal not permitted")]
    Forbidden,
}

/// 验签 port 错误 → 认证错误映射（verify→mint bridge 经 `?` 使用，#1158）。fail-closed：所有 `PdpError`
/// 变体均映射到**拒绝**态，绝不静默成功；`PdpError` 是 `#[non_exhaustive]`，未来变体默认落 `TokenInvalid`。
///
/// 三变体一一保真（#1275，spec SC-006/FR-009）：`Untrusted` 单列 [`AuthnError::TokenUntrusted`]、不与
/// `InvalidSignature` 折叠成同一 `TokenInvalid`，使 deny 路告警可区分疑似配置错 vs 疑似攻击。三者 wire 语义不变
/// （`TokenInvalid` / `TokenUntrusted` 同为 401 invalid_token，`TokenExpired` 亦 401），仅观测粒度提升。
impl From<diport::PdpError> for AuthnError {
    fn from(e: diport::PdpError) -> Self {
        match e {
            diport::PdpError::InvalidSignature => AuthnError::TokenInvalid,
            diport::PdpError::Expired => AuthnError::TokenExpired,
            // verify 层纯认证：Untrusted（iss / key / aud 不受信 / 未知 alg / kid 无匹配）= 凭据无效 →
            // 401 invalid_token（RFC 6750 §3.1），非 403 Forbidden（后者留给 authz 层「已认证但无权」）。
            diport::PdpError::Untrusted => AuthnError::TokenUntrusted,
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
mod row_visibility_tests {
    //! 核心：`Principal::row_visibility` 身份→行级可见域派生（tenancy.md §Principal claim source）。
    //! user→self / device→device / admin→tenant / super-admin→**fail-closed**（All 须经 audited funnel，
    //! 见 `audited_cross_tenant_tests`，INVARIANT TENANCY-CROSSTENANT-AUDIT-01）/ service·anonymous→fail-closed。
    use super::{CANON_TENANT, Principal, PrincipalKind};
    use rstest::rstest;
    use vocab::tenant::{RowScope, TenantId};

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
mod audited_cross_tenant_tests {
    //! `Principal::audited_cross_tenant_visibility`：super-admin 跨租户 All-scope 派生**同址强制审计**
    //! （tenancy.md §RowScope，INVARIANT TENANCY-CROSSTENANT-AUDIT-01）。先写持久 audit → record 成功才
    //! 签发 All-scope（无审计无 All-scope）；audit 失败 fail-closed、非 super-admin 拒绝、均不签发。
    use super::{
        CrossTenantAuditContext, CrossTenantAuditError, CrossTenantError, Principal, PrincipalKind,
    };
    use diport::{AuditEvent, AuditOutcome, AuditSink, AuditSinkError, Clock, DynAuditSink};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;
    use vocab::tenant::{RowScope, TenantId};

    const CANON_T: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    // ── 自包含测试替身（CLAUDE.md：单测不依赖 adapter crate） ────────────────────
    /// 记录型 audit sink（可配置 `fail`）：克隆共享句柄供注入后断言已记录事件 / 调用次数。
    #[derive(Clone)]
    struct RecordingAuditSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
        calls: Arc<AtomicUsize>,
        fail: bool,
    }
    impl RecordingAuditSink {
        fn ok() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::ok()
            }
        }
        fn events(&self) -> Vec<AuditEvent> {
            // reason: test-only stub——poison 代表 test-internal panic，取 inner 比再 panic 更利诊断。
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl AuditSink for RecordingAuditSink {
        async fn record(&self, event: AuditEvent) -> Result<(), AuditSinkError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                // reason: 模拟持久 sink 写失败 → funnel 须 fail-closed、绝不签发 All-scope。
                return Err(AuditSinkError::new(std::io::Error::other("test-sink-fail")));
            }
            self.events
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), AuditSinkError> {
            Ok(())
        }
    }

    /// 确定性测试时钟（impl `diport::Clock`，不取系统时钟）。
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

    /// 正常路径：super-admin + sink(ok) → 先写恰 1 条 audit（全字段断言）→ 签发 All-scope。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn audited_ok_writes_audit_then_mints_all_scope() {
        let tid = tenant();
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let sink = RecordingAuditSink::ok();
        let boxed = DynAuditSink::new_box(sink.clone());
        let clock = TestClock(t0);
        let principal = Principal::for_test(PrincipalKind::SuperAdmin, "root-subject", None);
        let ctx = runctx::test_support::app_ctx(tid, "root-subject");

        let vis = principal
            .audited_cross_tenant_visibility(&ctx, &boxed, &clock, &audit_ctx())
            .await
            .expect("super-admin audited 派生应成功");

        // 签发 All-scope（跨租户无租户约束）。
        assert_eq!(vis.scope(), RowScope::All);
        assert_eq!(vis.tenant(), None);

        // 恰 1 条 audit，全字段同址。
        let evs = sink.events();
        assert_eq!(evs.len(), 1, "须恰写 1 条持久 audit");
        let ev = &evs[0];
        assert_eq!(ev.occurred_at, t0, "occurred_at 取注入 Clock");
        assert_eq!(ev.principal_id, "root-subject");
        assert_eq!(ev.principal_kind, PrincipalKind::SuperAdmin);
        assert_eq!(
            ev.tenant_id,
            Some(tid),
            "tenant_id 取 ctx 行使 All-scope 的租户上下文"
        );
        assert_eq!(ev.resource_kind, "cross_tenant_visibility");
        assert_eq!(ev.resource_id, "res-7");
        assert_eq!(ev.action, "derive_all_scope");
        assert_eq!(ev.outcome, AuditOutcome::Success);
        assert_eq!(ev.request_id.as_deref(), Some("req-1"));
        assert_eq!(ev.correlation_id.as_deref(), Some("corr-9"));
    }

    /// 核心 fail-closed：audit 写失败 → Err(Audit)，**绝不**签发 All-scope；
    /// anti-vacuity：sink 确被调用 1 次（证明「先审计」非恒真、失败短路在签发前）。
    #[tokio::test]
    async fn audited_fail_closed_when_audit_fails() {
        let tid = tenant();
        let sink = RecordingAuditSink::failing();
        let boxed = DynAuditSink::new_box(sink.clone());
        let clock = TestClock(SystemTime::UNIX_EPOCH);
        let principal = Principal::for_test(PrincipalKind::SuperAdmin, "root-subject", None);
        let ctx = runctx::test_support::app_ctx(tid, "root-subject");

        // RowVisibility 无 Debug（非 wire 类型）；map 到 () 以便诊断格式化。
        let r = principal
            .audited_cross_tenant_visibility(&ctx, &boxed, &clock, &audit_ctx())
            .await
            .map(|_| ());

        assert!(
            matches!(r, Err(CrossTenantError::Audit(_))),
            "audit 写失败须 fail-closed，得 {r:?}"
        );
        assert!(r.is_err(), "绝不签发 All-scope");
        assert_eq!(sink.calls(), 1, "anti-vacuity：sink 确被调用过（先审计）");
        assert_eq!(
            sink.events().len(),
            0,
            "audit 写失败不应持久化事件（fail-closed 完整性）"
        );
    }

    /// 非 super-admin（含 service/anonymous/scoped）→ NotSuperAdmin，**零** audit（不写无谓审计）。
    #[tokio::test]
    async fn audited_rejects_non_super_admin() {
        let tid = tenant();
        for kind in [
            PrincipalKind::User,
            PrincipalKind::Device,
            PrincipalKind::Admin,
            PrincipalKind::Service,
            PrincipalKind::Anonymous,
        ] {
            let sink = RecordingAuditSink::ok();
            let boxed = DynAuditSink::new_box(sink.clone());
            let clock = TestClock(SystemTime::UNIX_EPOCH);
            let principal = Principal::for_test(kind, "subject-x", Some(tid));
            let ctx = runctx::test_support::app_ctx(tid, "subject-x");

            let r = principal
                .audited_cross_tenant_visibility(&ctx, &boxed, &clock, &audit_ctx())
                .await
                .map(|_| ());

            assert!(
                matches!(r, Err(CrossTenantError::NotSuperAdmin)),
                "kind={kind:?} 非 super-admin 须拒绝，得 {r:?}"
            );
            assert_eq!(sink.calls(), 0, "kind={kind:?} 非 super-admin 不写审计");
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
    use super::{
        AccessToken, AuthnError, Principal, PrincipalKind, VerifiedJwt, VerifiedServiceToken,
    };
    use diport::VerifiedClaims;
    use vocab::tenant::TenantId;

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    /// 已验签 JWT 测试装箱：载体携 raw + verifier-canonical [`VerifiedClaims`]（单一身份源，直接构造，
    /// 模拟 verifier 验签产物）。
    fn vjwt(sub: &str, tenant: Option<&str>, kind: Option<&str>) -> VerifiedJwt {
        VerifiedJwt::seal(
            "h.e.s".to_string(),
            VerifiedClaims::new(sub, tenant.map(str::to_string), kind.map(str::to_string)),
        )
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
            VerifiedClaims::new("svc-a", Some(CANON.to_string()), Some("admin".to_string())),
        );
        let p = Principal::from_verified_service_token(&vs).expect("service derive ok");
        assert_eq!(p.kind(), PrincipalKind::Service);
        assert_eq!(p.tenant(), None);
    }

    #[test]
    fn rejects_empty_subject_both_funnels() {
        // F2：验签产物即便 subject 为空（adapter 绕过旧 decode_claims 非空检查），也绝不 mint 空主体。
        let empty_jwt = VerifiedJwt::seal(
            "raw.tok.en".to_string(),
            VerifiedClaims::new("", None, Some("user".to_string())),
        );
        assert!(matches!(
            Principal::from_verified_jwt(&empty_jwt),
            Err(AuthnError::PrincipalInvalid)
        ));
        let empty_svc = VerifiedServiceToken::seal(
            AccessToken::new("opaque"),
            VerifiedClaims::new("", None, None),
        );
        assert!(matches!(
            Principal::from_verified_service_token(&empty_svc),
            Err(AuthnError::PrincipalInvalid)
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
    use super::{AccessToken, AuthnError, Principal, VerifiedJwt, VerifiedServiceToken};
    use diport::VerifiedClaims;

    #[test]
    fn seal_entries_and_funnels_carry_verified_newtype_signatures() {
        // 受控 mint 入口（`pub(crate)`，外部 crate 不可达——Hard）；载体携 raw + canonical claims。
        let _seal_jwt: fn(String, VerifiedClaims) -> VerifiedJwt = VerifiedJwt::seal;
        let _seal_svc: fn(AccessToken, VerifiedClaims) -> VerifiedServiceToken =
            VerifiedServiceToken::seal;
        // funnel 只收已验证 newtype（裸 token / claims 不可直接派生 Principal）。
        let _from_jwt: fn(&VerifiedJwt) -> Result<Principal, AuthnError> =
            Principal::from_verified_jwt;
        let _from_svc: fn(&VerifiedServiceToken) -> Result<Principal, AuthnError> =
            Principal::from_verified_service_token;
    }

    #[test]
    fn verified_jwt_redacts_debug() {
        // 载体携 raw token + canonical claims（subject）——Debug 二者均不得泄露。
        let vj = VerifiedJwt::seal(
            "secret-raw-token".to_string(),
            VerifiedClaims::new("alice-secret", Some("tenant-secret".to_string()), None),
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
            VerifiedClaims::new("svc-subject-secret", None, None),
        );
        let dbg = format!("{vs:?}");
        assert!(
            !dbg.contains("svc-secret-xyz"),
            "VerifiedServiceToken Debug 不得泄露原始 token"
        );
        assert!(
            !dbg.contains("svc-subject-secret"),
            "VerifiedServiceToken Debug 不得泄露 subject"
        );
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
    use super::{AuthnError, PrincipalKind, test_jwt, verify_jwt, verify_service_token};
    use diport::{DynPdp, Pdp, PdpError, RawCredential, VerifiedClaims};

    const CANON: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    /// 桩 `Pdp`：按预置结果应答 `verify`（native-AFIT impl → 经 `DynPdp` 注入）。
    struct StubPdp {
        result: Result<VerifiedClaims, PdpError>,
    }
    impl Pdp for StubPdp {
        async fn verify(&self, _raw: &RawCredential) -> Result<VerifiedClaims, PdpError> {
            self.result.clone()
        }
    }
    fn boxed(result: Result<VerifiedClaims, PdpError>) -> Box<DynPdp<'static>> {
        DynPdp::new_box(StubPdp { result })
    }

    /// happy：验签 ok → `(VerifiedJwt, Principal)`；身份反映**验签产物**而非 raw 重解析。
    /// raw payload 故意 `kind=user`，`VerifiedClaims.kind=admin` → `Principal=Admin`，证明信任原点是 verifier。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_jwt_ok_derives_principal_from_verified_claims_not_raw() {
        let raw = test_jwt(
            r#"{"sub":"raw-ignored","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(VerifiedClaims::new(
            "admin-subj",
            Some(CANON.to_string()),
            Some("admin".to_string()),
        )));
        let (vj, principal) = verify_jwt(&raw, &pdp).await.expect("verify ok mints");
        assert_eq!(
            principal.kind(),
            PrincipalKind::Admin,
            "身份须源自 VerifiedClaims（admin），非 raw（user）"
        );
        assert!(
            format!("{vj:?}").contains("redacted"),
            "VerifiedJwt Debug 脱敏"
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_jwt_super_admin_is_cross_tenant_none() {
        let raw = test_jwt(
            r#"{"sub":"x","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(VerifiedClaims::new(
            "root",
            None,
            Some("superAdmin".to_string()),
        )));
        let (_vj, principal) = verify_jwt(&raw, &pdp).await.expect("super-admin ok");
        assert_eq!(principal.kind(), PrincipalKind::SuperAdmin);
        assert_eq!(principal.tenant(), None, "super-admin 跨租户 tenant=None");
    }

    /// fail-closed：三 `PdpError` 变体均映射到**拒绝**态，never `Ok`，never seal（verify 层纯认证）。
    /// 三路一一保真（#1275，spec SC-006/FR-009）：`Untrusted` 单列 `TokenUntrusted`（与 `TokenInvalid` 同为
    /// 401 invalid_token wire 语义，独立变体仅供 deny 路告警分级），不再与 `InvalidSignature` 折叠。
    #[tokio::test]
    async fn verify_jwt_pdp_failure_maps_error_and_never_mints() {
        let raw = test_jwt(
            r#"{"sub":"u","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenUntrusted),
        ] {
            let pdp = boxed(Err(perr.clone()));
            // matches! + discriminant 守卫：既断言是 Err（绝不 mint），又锁定映射变体。
            // 不用 expect_err（`Principal` 无 Debug，含 PII 刻意不 derive）、不用 panic（clippy::panic 禁）。
            let result = verify_jwt(&raw, &pdp).await;
            assert!(
                matches!(&result, Err(e) if std::mem::discriminant(e) == std::mem::discriminant(&want)),
                "PdpError::{perr:?} 须映射到 {want:?}（且绝不 Ok）"
            );
        }
    }

    /// verify 先于 seal：`Pdp` ok 但 raw 结构坏 → `Jwt::parse` 报 `PrincipalInvalid`（验签后结构闸失败，非
    /// 签名失败、非 seal），无产物。#1275 review F1：此路不得记 `signature_invalid`。
    #[tokio::test]
    async fn verify_jwt_ok_but_malformed_raw_fails_at_parse() {
        let pdp = boxed(Ok(VerifiedClaims::new(
            "u",
            Some(CANON.to_string()),
            Some("user".to_string()),
        )));
        assert!(matches!(
            verify_jwt("only.two", &pdp).await,
            Err(AuthnError::PrincipalInvalid)
        ));
    }

    /// service-token：funnel 固定 `kind=Service`，`subject` 取自 `VerifiedClaims`（raw 可不透明）。
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn verify_service_token_ok_fixes_service_kind() {
        let pdp = boxed(Ok(VerifiedClaims::new(
            "svc-a",
            None,
            Some("ignored".to_string()),
        )));
        let (vs, principal) = verify_service_token("opaque-service-token", &pdp)
            .await
            .expect("service verify ok");
        assert_eq!(principal.kind(), PrincipalKind::Service);
        assert_eq!(principal.tenant(), None);
        assert!(format!("{vs:?}").contains("redacted"));
    }

    /// fail-closed：三 `PdpError` 变体均映射到**拒绝**态，never `Ok` / seal（与 verify_jwt 路径对齐；
    /// 三路一一保真，`Untrusted`→`TokenUntrusted`，#1275）。
    #[tokio::test]
    async fn verify_service_token_pdp_failure_maps_error_and_never_mints() {
        for (perr, want) in [
            (PdpError::InvalidSignature, AuthnError::TokenInvalid),
            (PdpError::Expired, AuthnError::TokenExpired),
            (PdpError::Untrusted, AuthnError::TokenUntrusted),
        ] {
            let pdp = boxed(Err(perr.clone()));
            let result = verify_service_token("opaque-token", &pdp).await;
            assert!(
                matches!(&result, Err(e) if std::mem::discriminant(e) == std::mem::discriminant(&want)),
                "PdpError::{perr:?} 须映射到 {want:?}（且绝不 mint）"
            );
        }
    }

    /// F2（bridge 端到端）：verifier 验签 ok 但返回**空 subject** → fail-closed `PrincipalInvalid`（验签后派生
    /// 失败，非签名失败），绝不 mint。#1275 review F1：此路不得记 `signature_invalid`。
    #[tokio::test]
    async fn verify_rejects_empty_subject_from_verifier() {
        let raw = test_jwt(
            r#"{"sub":"x","tenant":"f47ac10b-58cc-4372-a567-0e02b2c3d479","kind":"user"}"#,
        );
        let pdp = boxed(Ok(VerifiedClaims::new(
            "",
            Some(CANON.to_string()),
            Some("user".to_string()),
        )));
        assert!(matches!(
            verify_jwt(&raw, &pdp).await,
            Err(AuthnError::PrincipalInvalid)
        ));
        let pdp_svc = boxed(Ok(VerifiedClaims::new("", None, None)));
        assert!(matches!(
            verify_service_token("opaque", &pdp_svc).await,
            Err(AuthnError::PrincipalInvalid)
        ));
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
            AuthnError::SessionNotFound,
            AuthnError::Forbidden,
        ] {
            assert!(!e.to_string().is_empty(), "错误 message 非空");
            match e {
                AuthnError::TokenInvalid
                | AuthnError::TokenUntrusted
                | AuthnError::PrincipalInvalid
                | AuthnError::TokenExpired
                | AuthnError::SessionNotFound
                | AuthnError::Forbidden => {}
            }
        }
    }

    /// deny 分级（#1275 + review F1）：四个 deny 变体 Debug 互不相同（bridge 据变体记不同 `authz.deny_reason`
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
                "TokenExpired"
            ],
            "Debug 为变体名"
        );
        let unique: std::collections::HashSet<&String> = debugs.iter().collect();
        assert_eq!(unique.len(), debugs.len(), "四 deny 变体 Debug 须互不相同");
        assert_eq!(
            AuthnError::PrincipalInvalid.to_string(),
            "principal cannot be derived",
            "Display 为 const literal（无 runtime 数据 / PII）"
        );
    }

    /// `CrossTenantError` 闭值集 + Display 非空 + Audit source 脱敏（消费方据 Display 映射状态码 / 日志）。
    #[test]
    fn cross_tenant_error_is_exhaustive_and_redacts_source() {
        use super::CrossTenantError;
        let leak = "leak-marker-crosstenant";
        for e in [
            CrossTenantError::NotSuperAdmin,
            CrossTenantError::Audit(diport::AuditSinkError::new(std::io::Error::other(leak))),
        ] {
            assert!(!e.to_string().is_empty(), "错误 message 非空");
            match e {
                CrossTenantError::NotSuperAdmin | CrossTenantError::Audit(_) => {}
            }
        }
        // 安全 + anti-vacuity：Audit 的 Display/Debug 均不泄漏底层 source（DIPORT-ERR-SOURCE-REDACT-01）。
        let audit =
            CrossTenantError::Audit(diport::AuditSinkError::new(std::io::Error::other(leak)));
        assert!(
            format!("{:?}", std::io::Error::other(leak)).contains(leak),
            "前提失效：内层 Debug 未携 marker"
        );
        assert!(
            !audit.to_string().contains(leak),
            "Display 泄漏 source: {audit}"
        );
        assert!(
            !format!("{audit:?}").contains(leak),
            "Debug 泄漏 source: {audit:?}"
        );
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
